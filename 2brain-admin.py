#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""2brain-admin.py — local admin CLI for the 2brain M1a backend.

    python3 2brain-admin.py init
    python3 2brain-admin.py invite --name <user> --ttl 24h
    python3 2brain-admin.py list-users
    python3 2brain-admin.py list-devices --name <user>
    python3 2brain-admin.py revoke-device --id <device-id>

The invite code is printed once and only its SHA-256 is stored.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import re
import secrets
import sys
from pathlib import Path
from typing import Any, Optional


def load_backend() -> Any:
    path = Path(__file__).resolve().with_name("2brain-app.py")
    spec = importlib.util.spec_from_file_location("brainapp", str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load 2brain-app.py")
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves annotations through sys.modules; register first.
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(spec.name, None)
        raise
    return module


app = load_backend()


def default_db() -> str:
    return str(Path(__file__).resolve().parent / "var" / "2brain.db")


def parse_ttl(text: str) -> int:
    match = re.fullmatch(r"\s*(\d+)\s*([smhd])\s*", text.lower())
    if not match:
        raise SystemExit("ttl must look like 30m, 24h or 7d")
    value = int(match.group(1))
    unit = match.group(2)
    return value * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


def open_db(path: str) -> Any:
    if not os.path.isabs(path):
        path = os.path.abspath(path)
    return app.DB(path)


def cmd_init(args: argparse.Namespace) -> int:
    db = open_db(args.db)
    try:
        print(f"initialized: {db.path}")
        print(f"schema: {app.SCHEMA_VERSION}")
    finally:
        db.close()
    return 0


def cmd_invite(args: argparse.Namespace) -> int:
    name = app.norm_name(args.name)
    try:
        app.validate_name(name)
    except app.ApiError as exc:
        print(f"error: {exc.message}", file=sys.stderr)
        return 2
    db = open_db(args.db)
    try:
        if db.user_by_name(name) is not None:
            print(f"error: user already exists: {name}", file=sys.stderr)
            return 2
        code = app.crockford_encode(secrets.token_bytes(16))
        code_hash = app.sha256_hex(app.crockford_norm(code))
        ttl = parse_ttl(args.ttl)
        created = app.now_iso()
        exp = app.iso_after(ttl)
        db.run(
            "INSERT INTO invites(code_hash,name,created,exp,used_by,used_at) "
            "VALUES(?,?,?,?,NULL,NULL)",
            (code_hash, name, created, exp),
        )
        print(f"name: {name}")
        print(f"expires: {exp}")
        print(f"invite: {app.group_code(code)}")
        print("The invite is shown once. Only its SHA-256 is stored.")
    finally:
        db.close()
    return 0


def cmd_list_users(args: argparse.Namespace) -> int:
    db = open_db(args.db)
    try:
        rows = db.all(
            "SELECT u.id,u.name,u.role,u.created,u.kdf_iter,b.rev,b.size,"
            "b.updated_at,(SELECT COUNT(*) FROM sessions s WHERE s.uid=u.id) "
            "AS sessions FROM users u LEFT JOIN brains b ON b.uid=u.id "
            "ORDER BY u.id"
        )
        if not rows:
            print("no users")
            return 0
        print("uid\tname\trole\tcreated\tkdf_iter\trev\tsize\tsessions")
        for row in rows:
            print("\t".join(str(value if value is not None else "") for value in (
                row["id"], row["name"], row["role"], row["created"],
                row["kdf_iter"], row["rev"], row["size"], row["sessions"],
            )))
    finally:
        db.close()
    return 0


def cmd_list_devices(args: argparse.Namespace) -> int:
    name = app.norm_name(args.name)
    db = open_db(args.db)
    try:
        user = db.user_by_name(name)
        if user is None:
            print(f"error: user not found: {name}", file=sys.stderr)
            return 2
        rows = db.all(
            "SELECT id,name,scope,created,last_seen,revoked FROM devices "
            "WHERE uid=? ORDER BY created",
            (user["id"],),
        )
        if not rows:
            print("no devices")
            return 0
        print("id\tname\tscope\tcreated\tlast_seen\trevoked")
        for row in rows:
            print("\t".join(str(value if value is not None else "") for value in (
                row["id"], row["name"], row["scope"], row["created"],
                row["last_seen"], row["revoked"],
            )))
    finally:
        db.close()
    return 0


def cmd_revoke_device(args: argparse.Namespace) -> int:
    db = open_db(args.db)
    try:
        cur = db.run("UPDATE devices SET revoked=1 WHERE id=?", (args.id,))
        if cur.rowcount == 0:
            print(f"error: device not found: {args.id}", file=sys.stderr)
            return 2
        print(f"revoked: {args.id}")
    finally:
        db.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="2brain admin CLI")
    parser.add_argument("--db", default=default_db())
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="create the database")
    p_init.set_defaults(func=cmd_init)

    p_invite = sub.add_parser("invite", help="create a one-time invite")
    p_invite.add_argument("--name", required=True)
    p_invite.add_argument("--ttl", default="24h")
    p_invite.set_defaults(func=cmd_invite)

    p_users = sub.add_parser("list-users", help="list users")
    p_users.set_defaults(func=cmd_list_users)

    p_devices = sub.add_parser("list-devices", help="list devices for a user")
    p_devices.add_argument("--name", required=True)
    p_devices.set_defaults(func=cmd_list_devices)

    p_revoke = sub.add_parser("revoke-device", help="revoke one device token")
    p_revoke.add_argument("--id", required=True)
    p_revoke.set_defaults(func=cmd_revoke_device)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
