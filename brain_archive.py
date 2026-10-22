#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""2brain permanent archives. Python standard library only.

A permanent archive is a read-only copy of the whole SQLite database made just
before a sync reset. It is written to the NAS archive root and to a second
location (the mounted U disk), verified by SHA256, then the reset transaction
is allowed to run. The server never sees note plaintext; archives contain the
same E2EE ciphertext as the live database.

Layout:
    <archive-root>/permanent/<pre-reset-YYYYmmddTHHMMSSZ>/
        2brain.db        SQLite online-backup copy (journal_mode=DELETE)
        manifest.json    rev / etag / epoch / DB hash of the archived snapshot
        SHA256SUMS       "<sha256>  2brain.db"
        NOTICE.txt       restore notes (ciphertext only)
    <udisk-dir>/archive-permanent/<same-name>/  identical copy

Nothing here is imported by the browser; restore is a manual ops procedure.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone
from typing import Optional

FORMAT = "2brain-permanent-archive/1"
KIND = "pre-reset"
NAME_RE = re.compile(r"^pre-reset-\d{8}T\d{6}Z(?:-\d{1,3})?$")
ACK_PHRASE = "同步重置"


class ArchiveError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fsync(path: str) -> None:
    try:
        flags = os.O_RDWR if os.name == "nt" else os.O_RDONLY
        fd = os.open(path, flags)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _write_file(path: str, data: bytes) -> None:
    with open(path, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


def _chmod_tree(path: str, dir_mode: int = 0o555, file_mode: int = 0o444) -> None:
    for root, dirs, files in os.walk(path):
        for name in files:
            try:
                os.chmod(os.path.join(root, name), file_mode)
            except OSError:
                pass
        for name in dirs:
            try:
                os.chmod(os.path.join(root, name), dir_mode)
            except OSError:
                pass
    try:
        os.chmod(path, dir_mode)
    except OSError:
        pass


def archive_path(root: str, name: str) -> str:
    if not NAME_RE.fullmatch(name or ""):
        raise ArchiveError("bad_name", "invalid archive name")
    path = os.path.join(os.path.abspath(root), "permanent", name)
    if os.path.dirname(path) != os.path.join(os.path.abspath(root), "permanent"):
        raise ArchiveError("bad_name", "invalid archive path")
    return path


def _copy_db(db_path: str, dest: str, uid: int,
             rev: int, etag: str, epoch: int) -> tuple[int, str]:
    if not os.path.isfile(db_path):
        raise ArchiveError("no_db", "database file not found")
    src = sqlite3.connect(db_path, timeout=15)
    try:
        src.execute("PRAGMA busy_timeout=15000")
        dst = sqlite3.connect(dest)
        try:
            src.backup(dst)
            dst.execute("PRAGMA journal_mode=DELETE")
            check = dst.execute("PRAGMA integrity_check").fetchone()
            if not check or check[0] != "ok":
                raise ArchiveError("integrity", "database integrity_check failed")
            cols = {r[1] for r in dst.execute("PRAGMA table_info(brains)")}
            if not {"rev", "etag", "epoch", "blob"} <= cols:
                raise ArchiveError("schema", "brains table lacks epoch columns")
            row = dst.execute(
                "SELECT rev, etag, epoch, blob IS NOT NULL FROM brains WHERE uid=?",
                (uid,),
            ).fetchone()
            if row is None or not int(row[3]):
                raise ArchiveError("empty", "brain is empty; nothing to archive")
            archived_etag = row[1]
            if int(row[0]) != int(rev) or int(row[2]) != int(epoch):
                raise ArchiveError(
                    "stale_snapshot",
                    "database snapshot does not match the requested revision",
                )
            if archived_etag and archived_etag != etag:
                raise ArchiveError(
                    "stale_snapshot",
                    "database snapshot does not match the requested etag",
                )
            size = int(dst.execute("PRAGMA page_count").fetchone()[0]) * int(
                dst.execute("PRAGMA page_size").fetchone()[0])
        finally:
            dst.close()
    finally:
        src.close()
    return size, _sha256_file(dest)


def _manifest_bytes(manifest: dict) -> tuple[bytes, str]:
    raw = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
    return raw, hashlib.sha256(raw).hexdigest()


NOTICE = """2brain permanent archive (pre-reset)
=====================================

This directory is a read-only snapshot of the 2brain SQLite database taken
immediately before a sync reset. It contains E2EE ciphertext only: notes can
only be read after restoring the database and logging in with the account
password, or with the recovery code.

Contents:
  2brain.db      SQLite database copy (journal_mode=DELETE, integrity checked)
  manifest.json  revision / etag / epoch / database SHA256
  SHA256SUMS     checksum of 2brain.db

Do not edit or delete this directory. To restore, follow ops/README.md
("permanent pre-reset archives").

"""


def create_permanent_archive(
    *,
    db_path: str,
    archive_root: str,
    udisk_dir: str,
    uid: int,
    rev: int,
    etag: str,
    epoch: int,
    app_version: str,
    schema_version: int,
    now: Optional[datetime] = None,
) -> dict:
    """Create a verified archive in both locations. Fails closed."""
    if not archive_root:
        raise ArchiveError("not_configured", "archive root is not configured")
    if not udisk_dir:
        raise ArchiveError("udisk_not_configured", "U disk archive dir is not configured")
    if not os.path.isdir(udisk_dir):
        raise ArchiveError("udisk_missing", "U disk archive dir is not mounted")
    if rev <= 0 or not etag:
        raise ArchiveError("empty", "brain is empty; nothing to archive")

    stamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    base = f"{KIND}-{stamp}"
    permanent = os.path.join(os.path.abspath(archive_root), "permanent")
    os.makedirs(permanent, exist_ok=True)
    os.chmod(permanent, 0o755)

    name = base
    n = 2
    while os.path.exists(os.path.join(permanent, name)):
        name = f"{base}-{n}"
        n += 1
        if n > 100:
            raise ArchiveError("collision", "could not allocate an archive name")

    staging = tempfile.mkdtemp(prefix=f".staging-{name}-", dir=permanent)
    udisk_staging = ""
    try:
        db_copy = os.path.join(staging, "2brain.db")
        db_size, db_sha = _copy_db(db_path, db_copy, uid, rev, etag, epoch)
        manifest = {
            "format": FORMAT,
            "kind": KIND,
            "name": name,
            "createdAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "appVersion": app_version,
            "schemaVersion": int(schema_version),
            "uid": int(uid),
            "brain": {
                "rev": int(rev),
                "etag": etag,
                "epoch": int(epoch),
            },
            "db": {
                "file": "2brain.db",
                "sha256": db_sha,
                "bytes": db_size,
                "integrity": "ok",
            },
        }
        raw, manifest_sha = _manifest_bytes(manifest)
        manifest_path = os.path.join(staging, "manifest.json")
        sums_path = os.path.join(staging, "SHA256SUMS")
        notice_path = os.path.join(staging, "NOTICE.txt")
        _write_file(manifest_path, raw)
        _write_file(sums_path, f"{db_sha}  2brain.db\n".encode("ascii"))
        _write_file(notice_path, NOTICE.encode("utf-8"))
        for path in (db_copy, manifest_path, sums_path, notice_path):
            _fsync(path)

        final = os.path.join(permanent, name)
        _chmod_tree(staging)
        os.replace(staging, final)
        staging = ""

        udisk_root = os.path.join(os.path.abspath(udisk_dir),
                                  "archive-permanent")
        os.makedirs(udisk_root, exist_ok=True)
        udisk_staging = tempfile.mkdtemp(prefix=f".staging-{name}-", dir=udisk_root)
        udisk_final = os.path.join(udisk_root, name)
        for item in os.listdir(final):
            shutil.copy2(os.path.join(final, item),
                         os.path.join(udisk_staging, item))
        copied_db = os.path.join(udisk_staging, "2brain.db")
        if _sha256_file(copied_db) != db_sha:
            raise ArchiveError("udisk_checksum", "U disk copy checksum mismatch")
        copied_manifest = os.path.join(udisk_staging, "manifest.json")
        with open(copied_manifest, "rb") as fh:
            if hashlib.sha256(fh.read()).hexdigest() != manifest_sha:
                raise ArchiveError("udisk_checksum", "U disk manifest mismatch")
        _fsync(copied_db)
        _fsync(copied_manifest)
        _chmod_tree(udisk_staging)
        os.replace(udisk_staging, udisk_final)
        udisk_staging = ""
    except ArchiveError:
        raise
    except Exception as exc:
        raise ArchiveError("io", f"archive failed: {exc}") from exc
    finally:
        if staging:
            shutil.rmtree(staging, ignore_errors=True)
        if udisk_staging:
            shutil.rmtree(udisk_staging, ignore_errors=True)

    return {
        "name": name,
        "createdAt": manifest["createdAt"],
        "dbSha256": db_sha,
        "dbBytes": db_size,
        "manifestSha256": manifest_sha,
        "archiveDir": final,
        "udiskDir": udisk_final,
    }


def load_and_verify_archive(archive_root: str, name: str) -> dict:
    """Re-verify an archive before the reset transaction. Fails closed."""
    path = archive_path(archive_root, name)
    manifest_path = os.path.join(path, "manifest.json")
    db_path = os.path.join(path, "2brain.db")
    if not os.path.isdir(path) or not os.path.isfile(manifest_path) \
            or not os.path.isfile(db_path):
        raise ArchiveError("missing", "archive not found")
    try:
        with open(manifest_path, "rb") as fh:
            raw = fh.read()
        manifest = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ArchiveError("manifest", f"manifest unreadable: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("format") != FORMAT \
            or manifest.get("kind") != KIND or manifest.get("name") != name:
        raise ArchiveError("manifest", "unsupported archive manifest")
    db = manifest.get("db") or {}
    if _sha256_file(db_path) != db.get("sha256"):
        raise ArchiveError("checksum", "archive database checksum mismatch")
    con = sqlite3.connect(db_path, timeout=10)
    try:
        con.execute("PRAGMA query_only=ON")
        check = con.execute("PRAGMA integrity_check").fetchone()
        if not check or check[0] != "ok":
            raise ArchiveError("integrity", "archive integrity_check failed")
        row = con.execute(
            "SELECT rev, etag, epoch FROM brains WHERE uid=?",
            (int(manifest.get("uid") or 0),),
        ).fetchone()
    finally:
        con.close()
    brain = manifest.get("brain") or {}
    if row is None or int(row[0]) != int(brain.get("rev")) \
            or int(row[2]) != int(brain.get("epoch")) \
            or (row[1] and row[1] != brain.get("etag")):
        raise ArchiveError("manifest", "archive manifest does not match its database")
    return manifest
