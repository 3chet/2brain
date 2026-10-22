#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""2brain-app.py — 2brain M1a backend. Python standard library only.

The server stores E2EE ciphertext only. It never sees the password, KEK, DEK,
recovery code, or note plaintext. All crypto happens in the browser.

Run:
    python3 2brain-app.py --db var/2brain.db --port 8090 \
        --origin https://notes.example.com
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import socket
import sqlite3
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from html import unescape as html_unescape
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Iterator, Optional
from urllib.parse import urlparse

from brain_archive import (ACK_PHRASE, ArchiveError,
                           create_permanent_archive, load_and_verify_archive)

APP_VERSION = "m1e-2026-10-22"
SCHEMA_VERSION = 2
DEFAULT_KDF_ITER = 600_000
MIN_KDF_ITER = 310_000
MAX_KDF_ITER = 2_000_000
KDF_VER = 1
SERVER_PBKDF2_ITERS = 10_000
SESSION_TTL = 30 * 86400
TICKET_TTL = 300
MAX_BODY = 25 * 1024 * 1024
AI_PROXY_MAX_RESPONSE = 2 * 1024 * 1024
FETCH_TIMEOUT = 15.0
FETCH_MAX_BYTES = 2 * 1024 * 1024
FETCH_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/126 Safari/537.36 2brain-app")
MAX_BLOB = 18 * 1024 * 1024
MAX_REVISIONS = 50
MAX_REVISION_BYTES = 256 * 1024 * 1024
NAME_RE = re.compile(r"^[a-z0-9_-]{3,32}$")
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  name                 TEXT NOT NULL COLLATE NOCASE UNIQUE,
  created              TEXT NOT NULL,
  role                 TEXT NOT NULL DEFAULT 'owner',
  kdf_salt             BLOB NOT NULL,
  kdf_iter             INTEGER NOT NULL,
  kdf_ver              INTEGER NOT NULL DEFAULT 1,
  auth_salt            BLOB NOT NULL,
  auth_verifier        BLOB NOT NULL,
  wrapped_dek          BLOB NOT NULL,
  dek_iv               BLOB NOT NULL,
  recovery_verifier    BLOB NOT NULL,
  wrapped_dek_recovery BLOB NOT NULL,
  rec_iv               BLOB NOT NULL,
  failed               INTEGER NOT NULL DEFAULT 0,
  locked_until         TEXT,
  password_changed     TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  uid        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  exp        TEXT NOT NULL,
  ip         TEXT NOT NULL DEFAULT '',
  ua         TEXT NOT NULL DEFAULT '',
  created    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS brains (
  uid        INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  rev        INTEGER NOT NULL DEFAULT 0,
  etag       TEXT,
  blob       BLOB,
  size       INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT,
  epoch      INTEGER NOT NULL DEFAULT 0,
  reset_at   TEXT,
  reset_archive TEXT
);

CREATE TABLE IF NOT EXISTS revisions (
  uid  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  rev  INTEGER NOT NULL,
  blob BLOB NOT NULL,
  size INTEGER NOT NULL,
  ts   TEXT NOT NULL,
  by   TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (uid, rev)
);

CREATE TABLE IF NOT EXISTS devices (
  id         TEXT PRIMARY KEY,
  uid        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  name       TEXT NOT NULL DEFAULT '',
  scope      TEXT NOT NULL DEFAULT 'read',
  created    TEXT NOT NULL,
  last_seen  TEXT,
  revoked    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS invites (
  code_hash TEXT PRIMARY KEY,
  name      TEXT NOT NULL,
  created   TEXT NOT NULL,
  exp       TEXT NOT NULL,
  used_by   INTEGER,
  used_at   TEXT
);

CREATE TABLE IF NOT EXISTS recover_tickets (
  token_hash TEXT PRIMARY KEY,
  uid        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  exp        TEXT NOT NULL,
  used       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit (
  id     INTEGER PRIMARY KEY AUTOINCREMENT,
  ts     TEXT NOT NULL,
  uid    INTEGER,
  ip     TEXT,
  action TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_sessions_uid ON sessions(uid);
CREATE INDEX IF NOT EXISTS idx_revisions_uid_ts ON revisions(uid, ts);
CREATE INDEX IF NOT EXISTS idx_devices_uid ON devices(uid);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
"""


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str,
                 extra: Optional[dict] = None):
        super().__init__(message)
        self.status = int(status)
        self.code = code
        self.message = message
        self.extra = extra or {}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return utc_now().isoformat(timespec="seconds")


def iso_after(seconds: float) -> str:
    return (utc_now() + timedelta(seconds=seconds)).isoformat(
        timespec="milliseconds")


def parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        d = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d
    except (TypeError, ValueError):
        return None


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(value: Any, expected_len: Optional[int] = None,
         max_len: Optional[int] = None, field: str = "value") -> bytes:
    if not isinstance(value, str) or not value:
        raise ApiError(400, "bad_field", f"{field} must be base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:
        raise ApiError(400, "bad_field", f"{field} must be base64")
    if expected_len is not None and len(raw) != expected_len:
        raise ApiError(400, "bad_field", f"{field} must decode to {expected_len} bytes")
    if max_len is not None and len(raw) > max_len:
        raise ApiError(400, "bad_field", f"{field} is too large")
    return raw


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def crockford_encode(raw: bytes) -> str:
    value = 0
    bits = 0
    out = []
    for byte in raw:
        value = (value << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(CROCKFORD[(value >> bits) & 31])
    if bits:
        out.append(CROCKFORD[(value << (5 - bits)) & 31])
    return "".join(out)


def crockford_norm(code: Any) -> str:
    if not isinstance(code, str):
        return ""
    text = code.strip().upper().replace("-", "").replace(" ", "")
    return text.replace("I", "1").replace("L", "1").replace("O", "0")


def group_code(code: str) -> str:
    return "-".join(code[i:i + 4] for i in range(0, len(code), 4))


def norm_name(name: Any) -> str:
    return str(name or "").strip().lower()


def validate_name(name: str) -> None:
    if not NAME_RE.fullmatch(name):
        raise ApiError(400, "bad_name", "name must be 3-32 chars: a-z 0-9 _ -")


def field_str(body: dict, key: str, max_len: int = 256) -> str:
    value = body.get(key)
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise ApiError(400, "bad_field", f"{key} is required")
    return value


def field_int(body: dict, key: str, default: Optional[int] = None) -> int:
    value = body.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ApiError(400, "bad_field", f"{key} must be an integer")
    return value


def field_b64(body: dict, key: str, expected: Optional[int] = None,
              max_len: Optional[int] = None) -> bytes:
    return b64d(body.get(key), expected_len=expected, max_len=max_len, field=key)


def server_verifier(auth_hash: bytes, auth_salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", auth_hash, auth_salt,
                               SERVER_PBKDF2_ITERS, 32)


def parse_etag(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    text = value.strip()
    if text == "*":
        return "*"
    if text.startswith("W/"):
        text = text[2:].strip()
    if text.startswith('"') and text.endswith('"') and len(text) >= 2:
        text = text[1:-1]
    return text or None


def etag_of_blob(blob: bytes) -> str:
    try:
        obj = json.loads(blob.decode("utf-8"))
        ct = b64d(obj.get("ct"), max_len=MAX_BLOB, field="ct")
    except ApiError:
        raise
    except Exception:
        raise ApiError(500, "corrupt_blob", "stored blob is corrupt")
    return sha256_hex(ct)[:16]


def harden_path(path: str, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        pass


class DB:
    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        parent = os.path.dirname(self.path) or "."
        os.makedirs(parent, exist_ok=True)
        harden_path(parent, 0o700)
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(
            self.path, timeout=5, check_same_thread=False, isolation_level=None
        )
        self.conn.row_factory = sqlite3.Row
        with self.lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA foreign_keys=ON")
            self.conn.execute("PRAGMA busy_timeout=5000")
            self.conn.executescript(SCHEMA_SQL)
            row = self.conn.execute(
                "SELECT value FROM meta WHERE key='schema_version'"
            ).fetchone()
            if row is None:
                self.conn.execute(
                    "INSERT INTO meta(key,value) VALUES('schema_version',?)",
                    (str(SCHEMA_VERSION),),
                )
            else:
                found = int(row["value"])
                if found < SCHEMA_VERSION:
                    self._migrate(found)
                elif found > SCHEMA_VERSION:
                    raise RuntimeError(
                        f"unsupported schema_version={row['value']} "
                        f"(expected {SCHEMA_VERSION})"
                    )
            row = self.conn.execute(
                "SELECT value FROM meta WHERE key='instance_secret'"
            ).fetchone()
            if row is None:
                self.conn.execute(
                    "INSERT INTO meta(key,value) VALUES('instance_secret',?)",
                    (b64e(secrets.token_bytes(32)),),
                )
        harden_path(self.path, 0o600)
        self._secret = self._read_secret()

    def _migrate(self, found: int) -> None:
        with self.lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                if found == 1:
                    cols = {r["name"] for r in self.conn.execute(
                        "PRAGMA table_info(brains)").fetchall()}
                    for name, decl in (
                        ("epoch", "INTEGER NOT NULL DEFAULT 0"),
                        ("reset_at", "TEXT"),
                        ("reset_archive", "TEXT"),
                    ):
                        if name not in cols:
                            self.conn.execute(
                                f"ALTER TABLE brains ADD COLUMN {name} {decl}")
                    self.conn.execute(
                        "UPDATE meta SET value=? WHERE key='schema_version'",
                        (str(SCHEMA_VERSION),),
                    )
                else:
                    raise RuntimeError(
                        f"no migration path from schema_version={found}")
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise

    def _read_secret(self) -> bytes:
        row = self.one("SELECT value FROM meta WHERE key='instance_secret'")
        return b64d(row["value"], expected_len=32, field="instance_secret")

    @property
    def instance_secret(self) -> bytes:
        return self._secret

    def one(self, sql: str, args: tuple = ()) -> Optional[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(sql, args).fetchone()

    def all(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(sql, args).fetchall()

    def run(self, sql: str, args: tuple = ()) -> sqlite3.Cursor:
        with self.lock:
            return self.conn.execute(sql, args)

    @contextlib.contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        with self.lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                yield self.conn
            except Exception:
                self.conn.execute("ROLLBACK")
                raise
            else:
                self.conn.execute("COMMIT")

    def close(self) -> None:
        with self.lock:
            self.conn.close()

    # users
    def user_by_name(self, name: str) -> Optional[sqlite3.Row]:
        return self.one("SELECT * FROM users WHERE name=?", (name,))

    def user_by_id(self, uid: int) -> Optional[sqlite3.Row]:
        return self.one("SELECT * FROM users WHERE id=?", (uid,))

    # sessions
    def session_create(self, uid: int, ip: str, ua: str) -> str:
        token = secrets.token_urlsafe(32)
        self.run(
            "INSERT INTO sessions(token_hash,uid,exp,ip,ua,created) "
            "VALUES(?,?,?,?,?,?)",
            (sha256_hex(token), uid, iso_after(SESSION_TTL), ip, ua, now_iso()),
        )
        return token

    def session_by_token(self, token: str) -> Optional[sqlite3.Row]:
        token_hash = sha256_hex(token)
        row = self.one("SELECT * FROM sessions WHERE token_hash=?", (token_hash,))
        if row is None:
            return None
        exp = parse_iso(row["exp"])
        if exp is None or exp <= utc_now():
            self.run("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
            return None
        return row

    # devices
    def device_create(self, uid: int, name: str, scope: str) -> tuple[str, str]:
        device_id = secrets.token_hex(8)
        token = secrets.token_urlsafe(32)
        self.run(
            "INSERT INTO devices(id,uid,token_hash,name,scope,created) "
            "VALUES(?,?,?,?,?,?)",
            (device_id, uid, sha256_hex(token), name, scope, now_iso()),
        )
        return device_id, token

    def device_by_token(self, token: str) -> Optional[sqlite3.Row]:
        return self.one("SELECT * FROM devices WHERE token_hash=?",
                        (sha256_hex(token),))

    def touch_device(self, device_id: str) -> None:
        self.run("UPDATE devices SET last_seen=? WHERE id=?",
                 (now_iso(), device_id))

    # brain
    def brain_row(self, uid: int) -> Optional[sqlite3.Row]:
        return self.one("SELECT * FROM brains WHERE uid=?", (uid,))

    # audit
    def audit(self, uid: Optional[int], ip: str, action: str,
              detail: str = "") -> None:
        self.run(
            "INSERT INTO audit(ts,uid,ip,action,detail) VALUES(?,?,?,?,?)",
            (now_iso(), uid, ip, action, detail[:500]),
        )


def prune_revisions(conn: sqlite3.Connection, uid: int) -> None:
    conn.execute(
        "DELETE FROM revisions WHERE uid=? AND rev <= "
        "(SELECT MAX(rev) FROM revisions WHERE uid=?) - ?",
        (uid, uid, MAX_REVISIONS),
    )
    rows = conn.execute(
        "SELECT rev,size FROM revisions WHERE uid=? ORDER BY rev ASC", (uid,)
    ).fetchall()
    total = sum(int(r["size"]) for r in rows)
    for row in rows:
        if total <= MAX_REVISION_BYTES:
            break
        conn.execute("DELETE FROM revisions WHERE uid=? AND rev=?",
                     (uid, row["rev"]))
        total -= int(row["size"])


class RateLimiter:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.events: dict[str, list[float]] = {}

    def hit(self, key: str, limit: int, window: float) -> tuple[bool, int]:
        now = time.time()
        with self.lock:
            arr = self.events.setdefault(key, [])
            arr[:] = [t for t in arr if now - t < window]
            if len(arr) >= limit:
                retry = max(1, int(math.ceil(window - (now - arr[0]))))
                return False, retry
            arr.append(now)
            return True, 0


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        return None


# 不走环境代理，避免内网模型地址被 HTTP_PROXY 截走
_NO_REDIRECT_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), _NoRedirect)
CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")
_URL_SAFE = ":/?#[]@!$&'()*+,;=%"


class FetchError(Exception):
    """AI 转发 / 文章抓取的可读失败原因。"""


def _host_blocked(host: str, allow_private: bool) -> bool:
    host = (host or "").strip().lower().strip("[]")
    if not host:
        return True
    if (host == "localhost" or host.endswith(".localhost")
            or host.endswith(".local") or host.endswith(".internal")):
        return True
    if re.fullmatch(r"(0x[0-9a-f]+|\d+)", host):
        return True                     # 十进制/十六进制 IP 变体
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
        return True
    if ip.is_reserved or getattr(ip, "is_site_local", False):
        return True
    if not allow_private and (ip.is_private or ip in CGNAT_NET):
        return True
    return False


def _check_host(host: str, allow_private: bool) -> None:
    if _host_blocked(host, allow_private):
        raise FetchError("只允许抓取公网页面（内网/本机地址已拒绝）"
                         if not allow_private else "目标地址不允许（本机/链路本地地址已拒绝）")
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError):
        raise FetchError("域名解析失败：" + host)
    addrs = {info[4][0] for info in infos}
    if not addrs:
        raise FetchError("域名没有解析结果")
    for addr in addrs:
        if _host_blocked(addr, allow_private):
            raise FetchError("域名解析到内网地址，已拒绝" if not allow_private
                             else "域名解析到本机地址，已拒绝")


def _target_url(raw: str, allow_private: bool) -> urllib.parse.SplitResult:
    text = str(raw or "").strip()
    if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in text):
        raise FetchError("url 含非法控制字符")
    u = urllib.parse.urlsplit(text)
    if u.scheme not in ("http", "https"):
        raise FetchError("仅允许 http/https 链接")
    if u.username or u.password:
        raise FetchError("链接不能带用户名或密码")
    if not u.hostname:
        raise FetchError("url 非法")
    _check_host(u.hostname, allow_private)
    return u


def _request_url(u: urllib.parse.SplitResult) -> str:
    return urllib.parse.quote(u.geturl(), safe=_URL_SAFE)


def _read_limited(resp: Any, max_bytes: int, label: str) -> bytes:
    chunks = []
    total = 0
    while True:
        chunk = resp.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise FetchError(label + "超过 2MB，已停止抓取")
        chunks.append(chunk)
    return b"".join(chunks)


def _decode_html(raw: bytes, ctype: str) -> str:
    charset = ""
    m = re.search(r"charset=([\w-]+)", ctype or "", re.I)
    if m:
        charset = m.group(1)
    if not charset:
        head = raw[:4096].decode("ascii", "ignore")
        m = re.search(r"<meta[^>]+charset=[\"']?([\w-]+)", head, re.I)
        if m:
            charset = m.group(1)
    for enc in (charset, "utf-8", "gb18030", "big5"):
        if not enc:
            continue
        try:
            return raw.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue
    return raw.decode("utf-8", "replace")


def _extract_article(html: str) -> tuple[str, str]:
    title = ""
    for pat in (
        r'<meta[^>]+property=["\']og:title["\'][^>]*content=["\']([^"\']*)["\']',
        r'<meta[^>]+content=["\']([^"\']*)["\'][^>]*property=["\']og:title["\']',
    ):
        m = re.search(pat, html, re.I)
        if m:
            title = html_unescape(m.group(1))
            break
    if not title:
        m = re.search(r"<title[^>]*>([\s\S]*?)</title>", html, re.I)
        if m:
            title = html_unescape(m.group(1))
    title = re.sub(r"\s+", " ", title).strip()[:200]

    body = re.sub(r"<!--[\s\S]*?-->", " ", html)
    body = re.sub(r"<(script|style|noscript|svg|canvas|iframe|template)[^>]*>[\s\S]*?</\1>",
                  " ", body, flags=re.I)
    body = re.sub(r"<(nav|header|footer|aside|form|button|select|textarea)[^>]*>[\s\S]*?</\1>",
                  " ", body, flags=re.I)
    main = (re.search(r"<article[^>]*>([\s\S]*?)</article>", body, re.I)
            or re.search(r"<main[^>]*>([\s\S]*?)</main>", body, re.I))
    if main:
        body = main.group(1)
    body = re.sub(r"<br\s*/?>", "\n", body, flags=re.I)
    body = re.sub(r"</(p|div|li|h[1-6]|tr|blockquote|section|article)>", "\n",
                  body, flags=re.I)
    body = re.sub(r"<[^>]+>", " ", body)
    text = html_unescape(body).replace("\r", "").replace("\xa0", " ")
    lines = [re.sub(r"[ \t\f\v]+", " ", line).strip() for line in text.split("\n")]
    text = "\n".join(line for line in lines if line)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return title, text[:30000]


@dataclass
class Auth:
    kind: str
    uid: int
    name: str
    role: str
    scope: str
    session_hash: str = ""
    device_id: str = ""


@dataclass
class App:
    db: DB
    origin: str
    max_body: int
    lock_scale: float
    limiter: RateLimiter
    secure_cookie: bool
    archive_root: str = ""
    udisk_archive_dir: str = ""

    @property
    def archive_ready(self) -> bool:
        if not (self.archive_root and self.udisk_archive_dir):
            return False
        if not os.path.isdir(self.archive_root):
            return False
        if not os.path.isdir(self.udisk_archive_dir):
            return False
        if os.name == "posix":
            # The U disk is a FUSE mountpoint: an empty mountpoint directory
            # must never be mistaken for a writable second archive target.
            return os.path.ismount(self.udisk_archive_dir)
        return True

    def fake_kdf(self, name: str) -> tuple[bytes, int, int]:
        salt = hmac.new(self.db.instance_secret,
                        b"kdf|" + name.encode("utf-8"),
                        hashlib.sha256).digest()[:16]
        return salt, DEFAULT_KDF_ITER, KDF_VER


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "2brain-app/" + APP_VERSION
    sys_version = ""
    timeout = 30  # drop idle keep-alive sockets instead of leaking threads

    @property
    def app(self) -> App:
        return self.server.app  # type: ignore[attr-defined]

    # ---------- HTTP plumbing ----------
    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("%s %s %s\n" % (
            now_iso(), self.client_address[0], fmt % args))
        sys.stderr.flush()

    def _send(self, status: int, obj: Optional[dict] = None,
              headers: Optional[dict] = None) -> None:
        body = b"" if obj is None else json.dumps(
            obj, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        self.send_response(status)
        if obj is not None:
            self.send_header("Content-Type", "application/json; charset=utf-8")
        if status not in (204, 304):
            self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if self.close_connection:
            self.send_header("Connection", "close")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def _error(self, status: int, code: str, message: str,
               extra: Optional[dict] = None) -> None:
        payload = {"error": {"code": code, "message": message}}
        payload.update(extra or {})
        headers = {}
        if status == 429:
            retry = payload.get("retryAfter")
            if isinstance(retry, int) and retry > 0:
                headers["Retry-After"] = str(retry)
        self._send(status, payload, headers)

    def _read_json(self) -> dict:
        ctype = self.headers.get("Content-Type", "")
        if not ctype.lower().startswith("application/json"):
            raise ApiError(400, "bad_content_type",
                           "Content-Type must be application/json")
        length = self.headers.get("Content-Length")
        if length is None:
            raise ApiError(411, "length_required", "Content-Length required")
        try:
            size = int(length)
        except ValueError:
            raise ApiError(400, "bad_length", "invalid Content-Length")
        if size < 0:
            raise ApiError(400, "bad_length", "invalid Content-Length")
        if size > self.app.max_body:
            self.close_connection = True
            raise ApiError(413, "too_large", "request body too large")
        raw = self.rfile.read(size)
        self._body_consumed = True
        try:
            obj = json.loads(raw.decode("utf-8"))
        except Exception:
            raise ApiError(400, "bad_json", "invalid JSON")
        if not isinstance(obj, dict):
            raise ApiError(400, "bad_json", "JSON object required")
        return obj

    def _cookie(self, name: str) -> Optional[str]:
        raw = self.headers.get("Cookie", "")
        if not raw:
            return None
        try:
            jar = SimpleCookie()
            jar.load(raw)
            item = jar.get(name)
            return item.value if item else None
        except Exception:
            return None

    def _cookie_header(self, token: str, max_age: int = SESSION_TTL) -> str:
        parts = [f"sb_sid={token}", "Path=/", "HttpOnly",
                 "SameSite=Lax", f"Max-Age={max_age}"]
        if self.app.secure_cookie:
            parts.append("Secure")
        return "; ".join(parts)

    def _client_ip(self) -> str:
        peer = self.client_address[0]
        if peer in ("127.0.0.1", "::1"):
            cf = self.headers.get("CF-Connecting-IP")
            if cf:
                return cf.strip()
            xff = self.headers.get("X-Forwarded-For")
            if xff:
                return xff.split(",")[0].strip()
        return peer

    def _check_csrf(self) -> None:
        origin = self.headers.get("Origin")
        if origin and origin.rstrip("/") != self.app.origin.rstrip("/"):
            raise ApiError(403, "bad_origin", "origin not allowed")
        site = self.headers.get("Sec-Fetch-Site")
        if site and site not in ("same-origin", "none"):
            raise ApiError(403, "bad_fetch_site", "cross-site request rejected")

    def _auth(self, allow_device: bool = True, write: bool = False) -> Auth:
        authz = self.headers.get("Authorization", "")
        if authz.lower().startswith("bearer "):
            if not allow_device:
                raise ApiError(401, "session_required", "session required")
            token = authz[7:].strip()
            if not token:
                raise ApiError(401, "unauthorized", "invalid device token")
            row = self.app.db.device_by_token(token)
            if row is None or row["revoked"]:
                raise ApiError(401, "unauthorized", "invalid device token")
            if write and row["scope"] != "readwrite":
                raise ApiError(403, "readonly_device", "device token is read-only")
            user = self.app.db.user_by_id(row["uid"])
            if user is None:
                raise ApiError(401, "unauthorized", "unknown user")
            self.app.db.touch_device(row["id"])
            return Auth("device", user["id"], user["name"], user["role"],
                        row["scope"], device_id=row["id"])
        sid = self._cookie("sb_sid")
        if not sid:
            raise ApiError(401, "unauthorized", "login required")
        row = self.app.db.session_by_token(sid)
        if row is None:
            raise ApiError(401, "unauthorized", "session expired")
        user = self.app.db.user_by_id(row["uid"])
        if user is None:
            raise ApiError(401, "unauthorized", "unknown user")
        return Auth("session", user["id"], user["name"], user["role"],
                    "readwrite", session_hash=sha256_hex(sid))

    def _conflict(self, rev: int, etag: Optional[str],
                  epoch: int = 0) -> ApiError:
        return ApiError(412, "conflict", "etag mismatch",
                        {"rev": rev, "etag": etag, "epoch": epoch})

    def _epoch_mismatch(self, rev: int, etag: Optional[str],
                        epoch: int) -> ApiError:
        return ApiError(409, "epoch_mismatch",
                        "sync epoch changed; pull before pushing",
                        {"rev": rev, "etag": etag, "epoch": epoch})

    def _epoch_header(self) -> Optional[int]:
        raw = self.headers.get("X-2brain-Epoch")
        if raw is None or raw.strip() == "":
            return None
        try:
            value = int(raw.strip())
        except ValueError:
            raise ApiError(400, "bad_epoch",
                           "X-2brain-Epoch must be an integer")
        if value < 0:
            raise ApiError(400, "bad_epoch",
                           "X-2brain-Epoch must be non-negative")
        return value

    # ---------- dispatch ----------
    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_PUT(self) -> None:
        self._dispatch("PUT")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")

    def do_OPTIONS(self) -> None:
        self._send(405, {"error": {"code": "method_not_allowed",
                                  "message": "OPTIONS not supported"}},
                   {"Allow": "GET, POST, PUT, DELETE"})

    def _dispatch(self, method: str) -> None:
        try:
            try:
                declared = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                declared = 1
            self._body_consumed = declared <= 0
            path = urlparse(self.path).path
            if method in ("POST", "PUT", "DELETE"):
                self._check_csrf()
            if method == "GET":
                handler = {
                    "/api/health": self._h_health,
                    "/api/me": self._h_me,
                    "/api/brain": self._h_brain_get,
                    "/api/brain/revisions": self._h_brain_revisions,
                    "/api/export": self._h_export,
                    "/api/devices": self._h_devices_list,
                }.get(path)
            elif method == "POST":
                handler = {
                    "/api/kdf": self._h_kdf,
                    "/api/setup": self._h_setup,
                    "/api/login": self._h_login,
                    "/api/logout": self._h_logout,
                    "/api/logout_all": self._h_logout_all,
                    "/api/password": self._h_password,
                    "/api/recover/verify": self._h_recover_verify,
                    "/api/recover/commit": self._h_recover_commit,
                    "/api/recovery/rotate": self._h_recovery_rotate,
                    "/api/brain/restore": self._h_brain_restore,
                    "/api/brain/archive": self._h_brain_archive,
                    "/api/brain/reset": self._h_brain_reset,
                    "/api/devices": self._h_devices_create,
                    "/api/ai/proxy": self._h_ai_proxy,
                    "/api/fetch/url": self._h_fetch_url,
                }.get(path)
            elif method == "PUT":
                handler = {"/api/brain": self._h_brain_put}.get(path)
            else:
                handler = None
                if path.startswith("/api/devices/"):
                    handler = self._h_devices_revoke
            if handler is None:
                raise ApiError(404, "not_found", "not found")
            handler()
        except ApiError as exc:
            if not getattr(self, "_body_consumed", True):
                self.close_connection = True
            self._error(exc.status, exc.code, exc.message, exc.extra)
        except sqlite3.IntegrityError:
            if not getattr(self, "_body_consumed", True):
                self.close_connection = True
            self._error(409, "conflict", "duplicate or constraint violation")
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            traceback.print_exc()
            if not getattr(self, "_body_consumed", True):
                self.close_connection = True
            try:
                self._error(500, "internal", "internal error")
            except Exception:
                pass

    # ---------- health / me ----------
    def _h_health(self) -> None:
        self._send(200, {"ok": True, "version": APP_VERSION,
                         "schema": SCHEMA_VERSION,
                         "archive": self.app.archive_ready})

    def _h_me(self) -> None:
        auth = self._auth(allow_device=True)
        user = self.app.db.user_by_id(auth.uid)
        self._send(200, {"uid": auth.uid, "name": auth.name,
                         "role": auth.role, "created": user["created"],
                         "kind": auth.kind, "scope": auth.scope})

    # ---------- AI 同源转发 / 文章抓取 ----------
    def _h_ai_proxy(self) -> None:
        auth = self._auth(allow_device=False)
        ok, retry = self.app.limiter.hit("ai:%d" % auth.uid, 30, 60)
        if not ok:
            raise ApiError(429, "rate_limited", "too many AI requests",
                           {"retryAfter": retry})
        try:
            declared = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            declared = 0
        if declared > 2 * 1024 * 1024:
            raise ApiError(413, "too_large", "AI request body too large")
        body = self._read_json()
        try:
            target = _target_url(str(body.get("url") or ""), allow_private=True)
        except FetchError as exc:
            raise ApiError(400, "bad_url", str(exc))
        method = "POST" if str(body.get("method") or "GET").upper() == "POST" else "GET"
        api_key = str(body.get("apiKey") or "")
        if len(api_key) > 8192 or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in api_key):
            raise ApiError(400, "bad_key", "invalid API key header")
        payload = body.get("payload")
        if payload is None:
            payload = {}
        if not isinstance(payload, dict):
            raise ApiError(400, "bad_payload", "payload must be an object")
        try:
            timeout = float(body.get("timeoutMs") or 25000) / 1000.0
        except (TypeError, ValueError):
            timeout = 25.0
        timeout = min(120.0, max(2.0, timeout))
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json",
                   "User-Agent": "2brain-app/" + APP_VERSION}
        if api_key:
            headers["Authorization"] = "Bearer " + api_key
        data = None
        if method == "POST":
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            if len(data) > 2 * 1024 * 1024:
                raise ApiError(413, "too_large", "AI payload too large")
        req = urllib.request.Request(_request_url(target), data=data,
                                     headers=headers, method=method)
        try:
            resp = _NO_REDIRECT_OPENER.open(req, timeout=timeout)
            try:
                status = int(getattr(resp, "status", 200))
                raw = _read_limited(resp, AI_PROXY_MAX_RESPONSE, "模型响应")
            finally:
                resp.close()
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            try:
                raw = _read_limited(exc, AI_PROXY_MAX_RESPONSE, "模型响应")
            except Exception:
                raw = b""
            finally:
                exc.close()
        except (socket.timeout, TimeoutError):
            raise ApiError(504, "upstream_timeout", "模型服务响应超时")
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, (socket.timeout, TimeoutError)):
                raise ApiError(504, "upstream_timeout", "模型服务响应超时")
            raise ApiError(502, "upstream_unreachable",
                           "无法连接模型服务：" + str(reason))
        text = raw.decode("utf-8", "replace")
        self._send(200, {"ok": True, "status": status, "bodyText": text})

    def _h_fetch_url(self) -> None:
        auth = self._auth(allow_device=False)
        ok, retry = self.app.limiter.hit("fetch:%d" % auth.uid, 10, 60)
        if not ok:
            raise ApiError(429, "rate_limited", "too many fetch requests",
                           {"retryAfter": retry})
        body = self._read_json()
        try:
            current = _target_url(str(body.get("url") or ""), allow_private=False)
        except FetchError as exc:
            raise ApiError(400, "bad_url", str(exc))
        headers = {
            "User-Agent": FETCH_UA,
            "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.1",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.6",
        }
        for _hop in range(4):
            req = urllib.request.Request(_request_url(current), headers=headers,
                                         method="GET")
            try:
                resp = _NO_REDIRECT_OPENER.open(req, timeout=FETCH_TIMEOUT)
                try:
                    status = int(getattr(resp, "status", 200))
                    if 300 <= status < 400:
                        loc = resp.headers.get("Location")
                        resp.close()
                        if not loc:
                            raise ApiError(502, "fetch_failed", "页面跳转缺少 Location")
                        current = _target_url(urllib.parse.urljoin(
                            current.geturl(), loc), allow_private=False)
                        continue
                    if status != 200:
                        raise ApiError(502, "fetch_failed",
                                       "页面返回 HTTP %d" % status)
                    ctype = str(resp.headers.get("Content-Type") or "").lower()
                    if ctype and not re.search(r"text/html|application/xhtml|text/plain", ctype):
                        raise ApiError(502, "fetch_failed",
                                       "不是网页内容（" + ctype.split(";")[0] + "）")
                    raw = _read_limited(resp, FETCH_MAX_BYTES, "页面")
                finally:
                    resp.close()
            except urllib.error.HTTPError as exc:
                if 300 <= exc.code < 400:
                    loc = exc.headers.get("Location")
                    exc.close()
                    if not loc:
                        raise ApiError(502, "fetch_failed", "页面跳转缺少 Location")
                    current = _target_url(urllib.parse.urljoin(
                        current.geturl(), loc), allow_private=False)
                    continue
                exc.close()
                raise ApiError(502, "fetch_failed", "页面返回 HTTP %d" % exc.code)
            except (socket.timeout, TimeoutError):
                raise ApiError(504, "fetch_timeout", "抓取超时（15 秒）")
            except urllib.error.URLError as exc:
                reason = exc.reason
                if isinstance(reason, (socket.timeout, TimeoutError)):
                    raise ApiError(504, "fetch_timeout", "抓取超时（15 秒）")
                raise ApiError(502, "fetch_failed", "抓取失败：" + str(reason))
            except FetchError as exc:
                raise ApiError(502, "fetch_failed", str(exc))
            html = _decode_html(raw, ctype)
            title, text = _extract_article(html)
            if not text:
                raise ApiError(422, "no_content",
                               "没抽到正文（页面可能需要登录，或内容由脚本动态渲染）")
            self._send(200, {"ok": True, "url": current.geturl(),
                             "title": title, "text": text, "chars": len(text)})
            return
        raise ApiError(502, "fetch_failed", "页面跳转次数过多")

    # ---------- account ----------
    def _h_kdf(self) -> None:
        ok, retry = self.app.limiter.hit("kdf|" + self._client_ip(), 30, 60)
        if not ok:
            raise ApiError(429, "rate_limited", "too many requests",
                           {"retryAfter": retry})
        body = self._read_json()
        name = norm_name(body.get("name"))
        user = self.app.db.user_by_name(name) if name else None
        if user is not None:
            salt = bytes(user["kdf_salt"])
            iterator = int(user["kdf_iter"])
            ver = int(user["kdf_ver"])
        else:
            salt, iterator, ver = self.app.fake_kdf(name)
        self._send(200, {"salt": b64e(salt), "iter": iterator, "ver": ver})

    def _h_setup(self) -> None:
        ok, retry = self.app.limiter.hit("setup|" + self._client_ip(), 10, 3600)
        if not ok:
            raise ApiError(429, "rate_limited", "too many requests",
                           {"retryAfter": retry})
        body = self._read_json()
        name = norm_name(body.get("name"))
        validate_name(name)
        invite = crockford_norm(body.get("invite"))
        if len(invite) < 16:
            raise ApiError(403, "bad_invite", "invalid invite")
        kdf_salt = field_b64(body, "kdfSalt", expected=16)
        kdf_iter = field_int(body, "kdfIter")
        kdf_ver = field_int(body, "kdfVer", KDF_VER)
        if not (MIN_KDF_ITER <= kdf_iter <= MAX_KDF_ITER):
            raise ApiError(400, "bad_kdf_iter", "kdfIter out of range")
        if kdf_ver != KDF_VER:
            raise ApiError(400, "bad_kdf_ver", "unsupported kdf version")
        auth_hash = field_b64(body, "authHash", expected=32)
        wrapped_dek = field_b64(body, "wrappedDEK", expected=48)
        dek_iv = field_b64(body, "dekIv", expected=12)
        recovery_verifier = field_b64(body, "recoveryVerifier", expected=32)
        wrapped_rec = field_b64(body, "wrappedDEKRecovery", expected=48)
        rec_iv = field_b64(body, "recIv", expected=12)

        invite_hash = sha256_hex(invite)
        auth_salt = secrets.token_bytes(16)
        verifier = server_verifier(auth_hash, auth_salt)
        created = now_iso()
        with self.app.db.tx() as conn:
            inv = conn.execute(
                "SELECT * FROM invites WHERE code_hash=?", (invite_hash,)
            ).fetchone()
            if inv is None or inv["used_by"] is not None:
                raise ApiError(403, "bad_invite", "invalid or used invite")
            exp = parse_iso(inv["exp"])
            if exp is None or exp <= utc_now():
                raise ApiError(403, "bad_invite", "expired invite")
            if norm_name(inv["name"]) != name:
                raise ApiError(403, "bad_invite", "invite name mismatch")
            exists = conn.execute(
                "SELECT 1 FROM users WHERE name=?", (name,)
            ).fetchone()
            if exists is not None:
                raise ApiError(409, "name_taken", "name already exists")
            cur = conn.execute(
                "INSERT INTO users(name,created,role,kdf_salt,kdf_iter,kdf_ver,"
                "auth_salt,auth_verifier,wrapped_dek,dek_iv,recovery_verifier,"
                "wrapped_dek_recovery,rec_iv,password_changed) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (name, created, "owner", kdf_salt, kdf_iter, kdf_ver,
                 auth_salt, verifier, wrapped_dek, dek_iv, recovery_verifier,
                 wrapped_rec, rec_iv, created),
            )
            uid = int(cur.lastrowid)
            conn.execute(
                "INSERT INTO brains(uid,rev,size) VALUES(?,0,0)", (uid,)
            )
            conn.execute(
                "UPDATE invites SET used_by=?, used_at=? WHERE code_hash=?",
                (uid, created, invite_hash),
            )
        token = self.app.db.session_create(uid, self._client_ip(),
                                           self.headers.get("User-Agent", ""))
        self.app.db.audit(uid, self._client_ip(), "setup", name)
        self._send(200, {"uid": uid, "name": name},
                   {"Set-Cookie": self._cookie_header(token)})

    def _h_login(self) -> None:
        ok, retry = self.app.limiter.hit("login|" + self._client_ip(), 60, 60)
        if not ok:
            raise ApiError(429, "rate_limited", "too many requests",
                           {"retryAfter": retry})
        body = self._read_json()
        name = norm_name(body.get("name"))
        auth_hash = field_b64(body, "authHash", expected=32)
        iterator = field_int(body, "iter")
        kdf_ver = field_int(body, "kdfVer", KDF_VER)

        user = self.app.db.user_by_name(name) if name else None
        if user is None:
            fake_salt, fake_iter, fake_ver = self.app.fake_kdf(name)
            if iterator != fake_iter or kdf_ver != fake_ver:
                # Keep the response shape identical to a real iter mismatch so
                # a wrong iter cannot be used as a reliable existence oracle.
                raise ApiError(409, "kdf_changed", "kdf parameters changed",
                               {"kdf": {"salt": b64e(fake_salt),
                                        "iter": fake_iter, "ver": fake_ver}})
            # Equalize the dominant cost with a dummy verifier.
            hashlib.pbkdf2_hmac("sha256", auth_hash, b"\x00" * 16,
                                SERVER_PBKDF2_ITERS, 32)
            self.app.db.audit(None, self._client_ip(), "login", "unknown")
            raise ApiError(401, "bad_credentials", "invalid name or password")

        locked = parse_iso(user["locked_until"])
        if locked is not None and locked > utc_now():
            retry = max(1, int(math.ceil((locked - utc_now()).total_seconds())))
            raise ApiError(429, "locked", "too many failures",
                           {"retryAfter": retry})
        if iterator != int(user["kdf_iter"]) or kdf_ver != int(user["kdf_ver"]):
            raise ApiError(409, "kdf_changed", "kdf parameters changed",
                           {"kdf": {"salt": b64e(bytes(user["kdf_salt"])),
                                    "iter": int(user["kdf_iter"]),
                                    "ver": int(user["kdf_ver"])}})

        expected = bytes(user["auth_verifier"])
        actual = server_verifier(auth_hash, bytes(user["auth_salt"]))
        if not hmac.compare_digest(actual, expected):
            failed = int(user["failed"]) + 1
            lock_seconds = 0.0
            if failed >= 20:
                lock_seconds = 3600.0
            elif failed >= 10:
                lock_seconds = 300.0
            elif failed >= 5:
                lock_seconds = 30.0
            lock_until = iso_after(lock_seconds * self.app.lock_scale) \
                if lock_seconds else None
            self.app.db.run(
                "UPDATE users SET failed=?, locked_until=? WHERE id=?",
                (failed, lock_until, user["id"]),
            )
            self.app.db.audit(user["id"], self._client_ip(), "login", "bad")
            if lock_seconds:
                raise ApiError(429, "locked", "too many failures",
                               {"retryAfter": max(
                                   1, int(math.ceil(
                                       lock_seconds * self.app.lock_scale)))})
            raise ApiError(401, "bad_credentials", "invalid name or password")

        self.app.db.run(
            "UPDATE users SET failed=0, locked_until=NULL WHERE id=?",
            (user["id"],),
        )
        token = self.app.db.session_create(
            user["id"], self._client_ip(), self.headers.get("User-Agent", ""))
        self.app.db.audit(user["id"], self._client_ip(), "login", "ok")
        self._send(200, {
            "uid": user["id"],
            "name": user["name"],
            "wrappedDEK": b64e(bytes(user["wrapped_dek"])),
            "dekIv": b64e(bytes(user["dek_iv"])),
            "kdf": {"salt": b64e(bytes(user["kdf_salt"])),
                    "iter": int(user["kdf_iter"]),
                    "ver": int(user["kdf_ver"])},
        }, {"Set-Cookie": self._cookie_header(token)})

    def _h_logout(self) -> None:
        auth = self._auth(allow_device=False)
        self.app.db.run("DELETE FROM sessions WHERE token_hash=?",
                        (auth.session_hash,))
        self.app.db.audit(auth.uid, self._client_ip(), "logout", "")
        self._send(200, {"ok": True},
                   {"Set-Cookie": self._cookie_header("", max_age=0)})

    def _h_logout_all(self) -> None:
        auth = self._auth(allow_device=False)
        self.app.db.run("DELETE FROM sessions WHERE uid=?", (auth.uid,))
        self.app.db.audit(auth.uid, self._client_ip(), "logout_all", "")
        self._send(200, {"ok": True},
                   {"Set-Cookie": self._cookie_header("", max_age=0)})

    def _h_password(self) -> None:
        auth = self._auth(allow_device=False)
        body = self._read_json()
        old_hash = field_b64(body, "oldAuthHash", expected=32)
        new_hash = field_b64(body, "newAuthHash", expected=32)
        wrapped_dek = field_b64(body, "wrappedDEK", expected=48)
        dek_iv = field_b64(body, "dekIv", expected=12)
        user = self.app.db.user_by_id(auth.uid)
        actual = server_verifier(old_hash, bytes(user["auth_salt"]))
        if not hmac.compare_digest(actual, bytes(user["auth_verifier"])):
            self.app.db.audit(auth.uid, self._client_ip(), "password", "bad")
            raise ApiError(401, "bad_credentials", "old password incorrect")
        auth_salt = secrets.token_bytes(16)
        verifier = server_verifier(new_hash, auth_salt)
        changed = now_iso()
        with self.app.db.tx() as conn:
            conn.execute(
                "UPDATE users SET auth_salt=?, auth_verifier=?, wrapped_dek=?, "
                "dek_iv=?, password_changed=?, failed=0, locked_until=NULL "
                "WHERE id=?",
                (auth_salt, verifier, wrapped_dek, dek_iv, changed, auth.uid),
            )
            conn.execute(
                "DELETE FROM sessions WHERE uid=? AND token_hash<>?",
                (auth.uid, auth.session_hash),
            )
            conn.execute("DELETE FROM recover_tickets WHERE uid=?", (auth.uid,))
        self.app.db.audit(auth.uid, self._client_ip(), "password", "ok")
        self._send(200, {"ok": True})

    # ---------- recovery ----------
    def _h_recover_verify(self) -> None:
        ok, retry = self.app.limiter.hit(
            "recover|" + self._client_ip(), 10, 60)
        if not ok:
            raise ApiError(429, "rate_limited", "too many requests",
                           {"retryAfter": retry})
        body = self._read_json()
        name = norm_name(body.get("name"))
        verifier = field_b64(body, "verifier", expected=32)
        user = self.app.db.user_by_name(name) if name else None
        if user is None:
            hmac.compare_digest(verifier, b"\x00" * 32)
            raise ApiError(403, "bad_recovery", "invalid name or recovery code")
        if not hmac.compare_digest(verifier, bytes(user["recovery_verifier"])):
            self.app.db.audit(user["id"], self._client_ip(),
                              "recover_verify", "bad")
            raise ApiError(403, "bad_recovery", "invalid name or recovery code")
        ticket = secrets.token_urlsafe(32)
        with self.app.db.tx() as conn:
            conn.execute("DELETE FROM recover_tickets WHERE uid=?", (user["id"],))
            conn.execute(
                "INSERT INTO recover_tickets(token_hash,uid,exp,used) "
                "VALUES(?,?,?,0)",
                (sha256_hex(ticket), user["id"], iso_after(TICKET_TTL)),
            )
        self.app.db.audit(user["id"], self._client_ip(),
                          "recover_verify", "ok")
        self._send(200, {
            "wrappedDEKRecovery": b64e(bytes(user["wrapped_dek_recovery"])),
            "recIv": b64e(bytes(user["rec_iv"])),
            "ticket": ticket,
        })

    def _h_recover_commit(self) -> None:
        body = self._read_json()
        ticket = field_str(body, "ticket", 256)
        new_hash = field_b64(body, "newAuthHash", expected=32)
        wrapped_dek = field_b64(body, "wrappedDEK", expected=48)
        dek_iv = field_b64(body, "dekIv", expected=12)
        new_rec_verifier = field_b64(body, "newRecoveryVerifier", expected=32)
        wrapped_rec = field_b64(body, "wrappedDEKRecovery", expected=48)
        rec_iv = field_b64(body, "recIv", expected=12)
        ticket_hash = sha256_hex(ticket)
        auth_salt = secrets.token_bytes(16)
        verifier = server_verifier(new_hash, auth_salt)
        changed = now_iso()
        with self.app.db.tx() as conn:
            row = conn.execute(
                "SELECT * FROM recover_tickets WHERE token_hash=?",
                (ticket_hash,),
            ).fetchone()
            if row is None or row["used"]:
                raise ApiError(403, "bad_ticket", "invalid or used ticket")
            exp = parse_iso(row["exp"])
            if exp is None or exp <= utc_now():
                raise ApiError(403, "bad_ticket", "expired ticket")
            uid = int(row["uid"])
            conn.execute(
                "UPDATE users SET auth_salt=?, auth_verifier=?, wrapped_dek=?, "
                "dek_iv=?, recovery_verifier=?, wrapped_dek_recovery=?, "
                "rec_iv=?, password_changed=?, failed=0, locked_until=NULL "
                "WHERE id=?",
                (auth_salt, verifier, wrapped_dek, dek_iv, new_rec_verifier,
                 wrapped_rec, rec_iv, changed, uid),
            )
            conn.execute("UPDATE recover_tickets SET used=1 WHERE token_hash=?",
                         (ticket_hash,))
            conn.execute("DELETE FROM sessions WHERE uid=?", (uid,))
            conn.execute("DELETE FROM recover_tickets WHERE uid=?", (uid,))
        user = self.app.db.user_by_id(uid)
        self.app.db.audit(uid, self._client_ip(), "recover_commit", "ok")
        self._send(200, {"uid": uid, "name": user["name"]})

    def _h_recovery_rotate(self) -> None:
        auth = self._auth(allow_device=False)
        body = self._read_json()
        auth_hash = field_b64(body, "authHash", expected=32)
        new_rec_verifier = field_b64(body, "recoveryVerifier", expected=32)
        wrapped_rec = field_b64(body, "wrappedDEKRecovery", expected=48)
        rec_iv = field_b64(body, "recIv", expected=12)
        user = self.app.db.user_by_id(auth.uid)
        actual = server_verifier(auth_hash, bytes(user["auth_salt"]))
        if not hmac.compare_digest(actual, bytes(user["auth_verifier"])):
            self.app.db.audit(auth.uid, self._client_ip(),
                              "recovery_rotate", "bad")
            raise ApiError(401, "bad_credentials", "password incorrect")
        with self.app.db.tx() as conn:
            conn.execute(
                "UPDATE users SET recovery_verifier=?, wrapped_dek_recovery=?, "
                "rec_iv=? WHERE id=?",
                (new_rec_verifier, wrapped_rec, rec_iv, auth.uid),
            )
            conn.execute("DELETE FROM recover_tickets WHERE uid=?", (auth.uid,))
        self.app.db.audit(auth.uid, self._client_ip(),
                          "recovery_rotate", "ok")
        self._send(200, {"ok": True})

    # ---------- brain ----------
    def _h_brain_get(self) -> None:
        auth = self._auth(allow_device=True)
        row = self.app.db.brain_row(auth.uid)
        if row is None:
            self._send(200, {"rev": 0, "etag": None, "blob": None,
                             "updatedAt": None, "epoch": 0,
                             "resetAt": None, "resetArchive": None})
            return
        reset = {"epoch": int(row["epoch"]), "resetAt": row["reset_at"],
                 "resetArchive": row["reset_archive"]}
        if row["blob"] is None:
            self._send(200, {"rev": int(row["rev"]), "etag": None, "blob": None,
                             "updatedAt": row["updated_at"], **reset})
            return
        etag = row["etag"] or etag_of_blob(bytes(row["blob"]))
        inm = self.headers.get("If-None-Match")
        if inm:
            tags = [parse_etag(part) for part in inm.split(",")]
            if "*" in tags or etag in tags:
                self._send(304, None, {"ETag": f'"{etag}"'})
                return
        try:
            blob = json.loads(bytes(row["blob"]).decode("utf-8"))
        except Exception:
            raise ApiError(500, "corrupt_blob", "stored blob is corrupt")
        self._send(200, {"rev": int(row["rev"]), "etag": etag, "blob": blob,
                         "updatedAt": row["updated_at"], **reset},
                   {"ETag": f'"{etag}"'})

    def _h_brain_put(self) -> None:
        auth = self._auth(allow_device=True, write=True)
        provided_epoch = self._epoch_header()
        row_now = self.app.db.brain_row(auth.uid)
        cur_rev = int(row_now["rev"]) if row_now is not None else 0
        cur_epoch = int(row_now["epoch"]) if row_now is not None else 0
        cur_etag = None
        if row_now is not None and row_now["blob"] is not None:
            cur_etag = (row_now["etag"]
                        or etag_of_blob(bytes(row_now["blob"])))
        if provided_epoch is None:
            if cur_epoch > 0:
                raise self._epoch_mismatch(cur_rev, cur_etag, cur_epoch)
        elif provided_epoch != cur_epoch:
            raise self._epoch_mismatch(cur_rev, cur_etag, cur_epoch)
        body = self._read_json()
        if set(body.keys()) != {"v", "iv", "ct"}:
            raise ApiError(400, "bad_blob", "blob must contain v, iv, ct only")
        version = body.get("v")
        if isinstance(version, bool) or version != 1:
            raise ApiError(400, "bad_blob", "unsupported blob version")
        iv = field_b64(body, "iv", expected=12)
        ct = field_b64(body, "ct", max_len=MAX_BLOB)
        if not ct:
            raise ApiError(400, "bad_blob", "ct must not be empty")
        blob = json.dumps({"v": 1, "iv": b64e(iv), "ct": b64e(ct)},
                          separators=(",", ":")).encode("utf-8")
        etag = sha256_hex(ct)[:16]
        if_match = parse_etag(self.headers.get("If-Match"))
        if_none = parse_etag(self.headers.get("If-None-Match"))
        by = auth.kind + (":" + auth.device_id if auth.device_id else "")
        with self.app.db.tx() as conn:
            row = conn.execute(
                "SELECT * FROM brains WHERE uid=?", (auth.uid,)
            ).fetchone()
            epoch = int(row["epoch"]) if row is not None else 0
            if epoch != cur_epoch:
                raise self._epoch_mismatch(
                    int(row["rev"]) if row is not None else 0,
                    (row["etag"] if row is not None
                     and row["blob"] is not None else None),
                    epoch,
                )
            current = (row["etag"] if row is not None and row["blob"] is not None
                       else None)
            current_rev = int(row["rev"]) if row is not None else 0
            if if_none == "*":
                if current is not None:
                    raise self._conflict(current_rev, current, epoch)
            elif if_match is not None:
                if if_match == "*":
                    if current is None:
                        raise self._conflict(current_rev, current, epoch)
                elif current is None or if_match != current:
                    raise self._conflict(current_rev, current, epoch)
            else:
                if current is not None:
                    raise self._conflict(current_rev, current, epoch)
            if row is not None and row["blob"] is not None:
                conn.execute(
                    "INSERT OR REPLACE INTO revisions(uid,rev,blob,size,ts,by) "
                    "VALUES(?,?,?,?,?,?)",
                    (auth.uid, current_rev, row["blob"], int(row["size"]),
                     now_iso(), by),
                )
            new_rev = current_rev + 1
            conn.execute(
                "INSERT INTO brains(uid,rev,etag,blob,size,updated_at) "
                "VALUES(?,?,?,?,?,?) ON CONFLICT(uid) DO UPDATE SET "
                "rev=excluded.rev, etag=excluded.etag, blob=excluded.blob, "
                "size=excluded.size, updated_at=excluded.updated_at",
                (auth.uid, new_rev, etag, blob, len(blob), now_iso()),
            )
            prune_revisions(conn, auth.uid)
        self.app.db.audit(auth.uid, self._client_ip(), "brain_put",
                          f"rev={new_rev} size={len(blob)} epoch={epoch}")
        self._send(200, {"rev": new_rev, "etag": etag, "epoch": epoch},
                   {"ETag": f'"{etag}"'})

    def _h_brain_revisions(self) -> None:
        auth = self._auth(allow_device=False)
        rows = self.app.db.all(
            "SELECT rev,size,ts,by FROM revisions WHERE uid=? "
            "ORDER BY rev DESC LIMIT 50",
            (auth.uid,),
        )
        self._send(200, {"revisions": [
            {"rev": int(r["rev"]), "size": int(r["size"]),
             "ts": r["ts"], "by": r["by"]} for r in rows
        ]})

    def _h_brain_restore(self) -> None:
        auth = self._auth(allow_device=False)
        body = self._read_json()
        rev = field_int(body, "rev")
        if rev <= 0:
            raise ApiError(400, "bad_rev", "rev must be positive")
        with self.app.db.tx() as conn:
            old = conn.execute(
                "SELECT * FROM revisions WHERE uid=? AND rev=?",
                (auth.uid, rev),
            ).fetchone()
            if old is None:
                raise ApiError(404, "not_found", "revision not found")
            row = conn.execute(
                "SELECT * FROM brains WHERE uid=?", (auth.uid,)
            ).fetchone()
            current_rev = int(row["rev"]) if row is not None else 0
            if row is not None and row["blob"] is not None:
                conn.execute(
                    "INSERT OR REPLACE INTO revisions(uid,rev,blob,size,ts,by) "
                    "VALUES(?,?,?,?,?,?)",
                    (auth.uid, current_rev, row["blob"], int(row["size"]),
                     now_iso(), "restore"),
                )
            new_rev = current_rev + 1
            blob = bytes(old["blob"])
            etag = etag_of_blob(blob)
            conn.execute(
                "INSERT INTO brains(uid,rev,etag,blob,size,updated_at) "
                "VALUES(?,?,?,?,?,?) ON CONFLICT(uid) DO UPDATE SET "
                "rev=excluded.rev, etag=excluded.etag, blob=excluded.blob, "
                "size=excluded.size, updated_at=excluded.updated_at",
                (auth.uid, new_rev, etag, blob, len(blob), now_iso()),
            )
            prune_revisions(conn, auth.uid)
        self.app.db.audit(auth.uid, self._client_ip(), "brain_restore",
                          f"from={rev} rev={new_rev}")
        self._send(200, {"rev": new_rev, "etag": etag},
                   {"ETag": f'"{etag}"'})

    # ---------- permanent archive / sync reset ----------
    def _h_brain_archive(self) -> None:
        auth = self._auth(allow_device=False)
        ok, retry = self.app.limiter.hit("archive|" + str(auth.uid), 6, 3600)
        if not ok:
            raise ApiError(429, "rate_limited", "too many requests",
                           {"retryAfter": retry})
        if not self.app.archive_ready:
            raise ApiError(503, "archive_not_configured",
                           "permanent archive is not configured")
        row = self.app.db.brain_row(auth.uid)
        if row is None or row["blob"] is None:
            raise ApiError(409, "nothing_to_archive",
                           "server brain is already empty")
        blob = bytes(row["blob"])
        rev = int(row["rev"])
        epoch = int(row["epoch"])
        etag = row["etag"] or etag_of_blob(blob)
        try:
            result = create_permanent_archive(
                db_path=self.app.db.path,
                archive_root=self.app.archive_root,
                udisk_dir=self.app.udisk_archive_dir,
                uid=auth.uid, rev=rev, etag=etag, epoch=epoch,
                app_version=APP_VERSION, schema_version=SCHEMA_VERSION,
            )
        except ArchiveError as exc:
            self.app.db.audit(auth.uid, self._client_ip(), "brain_archive",
                              f"fail {exc.code}")
            raise ApiError(503, "archive_failed", str(exc),
                           {"reason": exc.code})
        self.app.db.audit(auth.uid, self._client_ip(), "brain_archive",
                          f"{result['name']} rev={rev} epoch={epoch}")
        self._send(200, {
            "ok": True,
            "archive": result["name"],
            "rev": rev,
            "etag": etag,
            "epoch": epoch,
            "bytes": int(result["dbBytes"]),
            "dbSha256": result["dbSha256"],
            "createdAt": result["createdAt"],
            "udisk": True,
        })

    def _h_brain_reset(self) -> None:
        auth = self._auth(allow_device=False)
        ok, retry = self.app.limiter.hit("reset|" + str(auth.uid), 5, 3600)
        if not ok:
            raise ApiError(429, "rate_limited", "too many requests",
                           {"retryAfter": retry})
        body = self._read_json()
        if body.get("confirm") != ACK_PHRASE:
            raise ApiError(400, "confirm_required",
                           f'confirm must be "{ACK_PHRASE}"')
        auth_hash = field_b64(body, "authHash", expected=32)
        name = field_str(body, "archive", 64)
        expect_rev = field_int(body, "expectRev")
        expect_epoch = field_int(body, "expectEpoch")
        expect_etag = body.get("expectEtag")
        if not isinstance(expect_etag, str) \
                or not re.fullmatch(r"[0-9a-f]{16}", expect_etag):
            raise ApiError(400, "bad_field", "expectEtag is required")
        if not self.app.archive_ready:
            raise ApiError(503, "archive_not_configured",
                           "permanent archive is not configured")
        user = self.app.db.user_by_id(auth.uid)
        actual = server_verifier(auth_hash, bytes(user["auth_salt"]))
        if not hmac.compare_digest(actual, bytes(user["auth_verifier"])):
            self.app.db.audit(auth.uid, self._client_ip(),
                              "brain_reset", "bad_password")
            raise ApiError(401, "bad_credentials", "password incorrect")
        try:
            manifest = load_and_verify_archive(self.app.archive_root, name)
        except ArchiveError as exc:
            self.app.db.audit(auth.uid, self._client_ip(),
                              "brain_reset", f"archive {exc.code}")
            raise ApiError(409, "archive_invalid", str(exc),
                           {"reason": exc.code})
        m_brain = manifest.get("brain") or {}
        m_rev, m_epoch = m_brain.get("rev"), m_brain.get("epoch")
        if manifest.get("uid") != auth.uid \
                or m_rev != expect_rev or m_epoch != expect_epoch \
                or m_brain.get("etag") != expect_etag:
            raise ApiError(409, "stale_archive",
                           "archive does not match the requested revision",
                           {"reason": "manifest_mismatch"})
        with self.app.db.tx() as conn:
            row = conn.execute(
                "SELECT * FROM brains WHERE uid=?", (auth.uid,)
            ).fetchone()
            if row is None or row["blob"] is None:
                raise ApiError(409, "nothing_to_reset",
                               "server brain is already empty")
            cur_rev = int(row["rev"])
            cur_epoch = int(row["epoch"])
            cur_etag = row["etag"] or etag_of_blob(bytes(row["blob"]))
            if cur_rev != expect_rev or cur_epoch != expect_epoch \
                    or cur_etag != expect_etag:
                raise ApiError(409, "stale_archive",
                               "server changed since the archive was made",
                               {"rev": cur_rev, "etag": cur_etag,
                                "epoch": cur_epoch})
            new_rev = cur_rev + 1
            new_epoch = cur_epoch + 1
            ts = now_iso()
            conn.execute(
                "UPDATE brains SET rev=?, etag=NULL, blob=NULL, size=0, "
                "updated_at=?, epoch=?, reset_at=?, reset_archive=? "
                "WHERE uid=?",
                (new_rev, ts, new_epoch, ts, name, auth.uid),
            )
            conn.execute("DELETE FROM revisions WHERE uid=?", (auth.uid,))
        self.app.db.audit(auth.uid, self._client_ip(), "brain_reset",
                          f"rev={new_rev} epoch={new_epoch} archive={name}")
        self._send(200, {"ok": True, "rev": new_rev, "epoch": new_epoch,
                         "resetAt": ts, "archive": name})

    def _h_export(self) -> None:
        auth = self._auth(allow_device=False)
        user = self.app.db.user_by_id(auth.uid)
        row = self.app.db.brain_row(auth.uid)
        reset = {"epoch": 0, "resetAt": None, "resetArchive": None}
        brain = {"rev": 0, "etag": None, "blob": None, "updatedAt": None,
                 **reset}
        if row is not None:
            reset = {"epoch": int(row["epoch"]),
                     "resetAt": row["reset_at"],
                     "resetArchive": row["reset_archive"]}
            if row["blob"] is None:
                brain = {"rev": int(row["rev"]), "etag": None, "blob": None,
                         "updatedAt": row["updated_at"], **reset}
            else:
                brain = {
                    "rev": int(row["rev"]),
                    "etag": row["etag"] or etag_of_blob(bytes(row["blob"])),
                    "blob": json.loads(bytes(row["blob"]).decode("utf-8")),
                    "updatedAt": row["updated_at"],
                    **reset,
                }
        self._send(200, {
            "app": "2brain",
            "schema": 1,
            "exportedAt": now_iso(),
            "account": {
                "uid": user["id"],
                "name": user["name"],
                "kdfSalt": b64e(bytes(user["kdf_salt"])),
                "kdfIter": int(user["kdf_iter"]),
                "kdfVer": int(user["kdf_ver"]),
                "wrappedDEK": b64e(bytes(user["wrapped_dek"])),
                "dekIv": b64e(bytes(user["dek_iv"])),
                "wrappedDEKRecovery": b64e(bytes(user["wrapped_dek_recovery"])),
                "recIv": b64e(bytes(user["rec_iv"])),
            },
            "brain": brain,
        })

    # ---------- devices ----------
    def _h_devices_list(self) -> None:
        auth = self._auth(allow_device=False)
        rows = self.app.db.all(
            "SELECT id,name,scope,created,last_seen,revoked FROM devices "
            "WHERE uid=? ORDER BY created ASC",
            (auth.uid,),
        )
        self._send(200, {"devices": [
            {"id": r["id"], "name": r["name"], "scope": r["scope"],
             "created": r["created"], "lastSeen": r["last_seen"],
             "revoked": bool(r["revoked"])} for r in rows
        ]})

    def _h_devices_create(self) -> None:
        auth = self._auth(allow_device=False)
        body = self._read_json()
        name = field_str(body, "name", 64)
        scope = body.get("scope", "read")
        if scope not in ("read", "readwrite"):
            raise ApiError(400, "bad_scope", "scope must be read or readwrite")
        device_id, token = self.app.db.device_create(
            auth.uid, name, scope)
        self.app.db.audit(auth.uid, self._client_ip(), "device_create",
                          f"{device_id} scope={scope}")
        self._send(200, {"id": device_id, "token": token, "name": name,
                         "scope": scope})

    def _h_devices_revoke(self) -> None:
        auth = self._auth(allow_device=False)
        path = urlparse(self.path).path
        device_id = path[len("/api/devices/"):]
        if not device_id or "/" in device_id:
            raise ApiError(404, "not_found", "not found")
        cur = self.app.db.run(
            "UPDATE devices SET revoked=1 WHERE id=? AND uid=?",
            (device_id, auth.uid),
        )
        if cur.rowcount == 0:
            raise ApiError(404, "not_found", "device not found")
        self.app.db.audit(auth.uid, self._client_ip(), "device_revoke",
                          device_id)
        self._send(200, {"ok": True})


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="2brain M1a backend")
    parser.add_argument("--db", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "var", "2brain.db"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--origin", default="https://notes.example.com")
    parser.add_argument("--max-body-mb", type=int, default=25)
    parser.add_argument("--lock-scale", type=float, default=1.0,
                        help="scale login lockout seconds (tests use <1)")
    parser.add_argument("--archive-root", default="",
                        help="permanent archive root (e.g. /srv/2brain/archive)")
    parser.add_argument("--udisk-archive-dir", default="",
                        help="mounted U disk archive dir; reset requires it")
    args = parser.parse_args(argv)

    db = DB(args.db)
    app = App(
        db=db,
        origin=args.origin.rstrip("/"),
        max_body=max(1024, args.max_body_mb * 1024 * 1024),
        lock_scale=max(0.0, args.lock_scale),
        limiter=RateLimiter(),
        secure_cookie=args.origin.lower().startswith("https://"),
        archive_root=os.path.abspath(args.archive_root) if args.archive_root else "",
        udisk_archive_dir=(os.path.abspath(args.udisk_archive_dir)
                           if args.udisk_archive_dir else ""),
    )

    class BoundHandler(Handler):
        @property
        def app(self) -> App:
            return app

    httpd = ThreadingHTTPServer((args.host, args.port), BoundHandler)
    httpd.daemon_threads = True
    print(f"2brain-app {APP_VERSION} listening on http://{args.host}:{args.port} "
          f"origin={app.origin} db={db.path} "
          f"archive={'on' if app.archive_ready else 'off'}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
