#!/usr/bin/env python3
"""2brain 在线模式回归用的本地 API 桩。

不是生产后端：只实现前端 M1b 会用到的端点，外加 /api/__* 测试钩子。
真实后端仍是 2brain-app.py；本桩**不落盘、不记日志到文件**，进程退出即清空。

跑法：
    python tests/api_stub.py --port 7799
    # 然后打开 http://127.0.0.1:7799/tests/online_smoke.html

端点与 2brain-app.py 对齐：/api/kdf /api/setup /api/login /api/me
/api/brain(GET/PUT, etag/412) /api/logout /api/logout_all
测试钩子：/api/__reset /api/__state /api/__put /api/__expire /api/__offline
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import sys
import threading
import time
import traceback
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

MIN_KDF_ITER = 310_000
MAX_KDF_ITER = 2_000_000
KDF_VER = 1
SERVER_PBKDF2_ITERS = 10_000
MAX_BLOB = 18 * 1024 * 1024
INVITE = "ONLINESMOKEINVITE0001"
NAME_RE = re.compile(r"^[a-z0-9_-]{3,32}$")
VID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
MAX_VAULTS = 20
GID_RE = re.compile(r"^s[a-f0-9]{16}$")
MAX_SHARED_VAULTS = 20
MAX_SHARED_MEMBERS = 20
COOKIE = "sb_sid"

MIME = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text, expected=None):
    if not isinstance(text, str) or not text:
        return None
    try:
        raw = base64.b64decode(text, validate=True)
    except Exception:
        return None
    if expected is not None and len(raw) != expected:
        return None
    return raw


def norm_name(name) -> str:
    return str(name or "").strip().lower()


def norm_pub(value):
    if not isinstance(value, str) or not (2 <= len(value) <= 1024):
        return None
    try:
        obj = json.loads(value)
    except Exception:
        return None
    if not isinstance(obj, dict) or obj.get("kty") != "EC" \
            or obj.get("crv") != "P-256":
        return None
    for name in ("x", "y"):
        coord = obj.get(name)
        if not isinstance(coord, str) or not (40 <= len(coord) <= 64):
            return None
    return json.dumps({"kty": "EC", "crv": "P-256",
                       "x": obj["x"], "y": obj["y"]},
                      separators=(",", ":"))


def norm_wrapped(value):
    if not isinstance(value, str) or not (2 <= len(value) <= 4096):
        return None
    try:
        obj = json.loads(value)
    except Exception:
        return None
    if not isinstance(obj, dict) or obj.get("v") != 1:
        return None
    epk = obj.get("epk")
    if not isinstance(epk, dict) or epk.get("kty") != "EC" \
            or epk.get("crv") != "P-256":
        return None
    for name in ("x", "y"):
        coord = epk.get(name)
        if not isinstance(coord, str) or not (40 <= len(coord) <= 64):
            return None
    if b64d(obj.get("iv"), 12) is None:
        return None
    if not b64d(obj.get("ct")):
        return None
    return json.dumps(obj, separators=(",", ":"))


def crockford_norm(code) -> str:
    if not isinstance(code, str):
        return ""
    text = code.strip().upper().replace("-", "").replace(" ", "")
    return text.replace("I", "1").replace("L", "1").replace("O", "0")


def fake_kdf(name: str):
    salt = hashlib.sha256(b"2brain|fake-kdf|" + name.encode("utf-8")).digest()[:16]
    return salt, 600_000, KDF_VER


def verifier(auth_hash: bytes, auth_salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", auth_hash, auth_salt, SERVER_PBKDF2_ITERS, 32
    )


class State:
    def __init__(self):
        self.lock = threading.RLock()
        self.reset()

    def reset(self):
        with self.lock:
            self.users = {}          # uid -> dict
            self.by_name = {}        # name -> uid
            self.sessions = {}       # token -> uid
            self.brains = {}         # uid -> dict(rev, etag, blob, updated_at, epoch, reset_*)
            self.vaults = {}         # (uid, vid) -> 同上（schema 3 附加库；默认库仍是 brains）
            self.keys = {}           # uid -> ECDH P-256 公钥 JWK 字符串
            self.shared = {}         # gid -> dict(owner_uid, name, rev, etag, blob, key_epoch...)
            self.shared_members = {} # (gid, uid) -> dict(role, wrapped, key_epoch, added, updated)
            self.archives = {}       # name -> dict(uid, rev, etag, epoch)
            self.next_uid = 1
            self.offline = False
            self.log = []            # [{at, method, path, status, uid}]

    def audit(self, method, path, status, uid=0):
        with self.lock:
            self.log.append({"at": now_iso(), "method": method,
                             "path": path, "status": status, "uid": uid})
            if len(self.log) > 400:
                del self.log[:100]


STATE = State()


class Handler(BaseHTTPRequestHandler):
    server_version = "2brain-test-stub/1"
    protocol_version = "HTTP/1.1"

    # ---------- plumbing ----------
    def log_message(self, fmt, *args):
        pass

    def _send(self, status, obj=None, headers=None):
        body = b"" if obj is None else json.dumps(
            obj, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        self.send_response(status)
        if obj is not None:
            self.send_header("Content-Type", "application/json; charset=utf-8")
        if status not in (204, 304):
            self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def _error(self, status, code, message, extra=None):
        payload = {"error": {"code": code, "message": message}}
        payload.update(extra or {})
        self._send(status, payload)

    def _read_json(self):
        raw = self._raw_body or b""
        if not raw:
            return {}
        try:
            value = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise ValueError("bad json") from exc
        if not isinstance(value, dict):
            raise ValueError("body must be an object")
        return value

    def _cookie_uid(self, write=False):
        raw = self.headers.get("Cookie") or ""
        token = ""
        for part in raw.split(";"):
            key, _, value = part.strip().partition("=")
            if key == COOKIE:
                token = value
                break
        if not token:
            return None, ""
        with STATE.lock:
            uid = STATE.sessions.get(token)
            if uid is None or uid not in STATE.users:
                return None, token
        return uid, token

    def _require(self, write=False):
        uid, token = self._cookie_uid(write)
        if uid is None:
            self._error(401, "unauthorized", "login required")
            return None, token
        return uid, token

    def _set_cookie(self, token):
        if token:
            return {"Set-Cookie": f"{COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax"}
        return {"Set-Cookie": f"{COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"}

    def _offline_cut(self, path):
        if path.startswith("/api/__"):
            return False
        if not STATE.offline:
            return False
        self.close_connection = True
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.connection.close()
        except OSError:
            pass
        STATE.audit(self.command, path, 0)
        return True

    # ---------- dispatch ----------
    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._dispatch("PUT")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def _dispatch(self, method):
        path = urlsplit(self.path).path
        if self._offline_cut(path):
            return
        self._raw_body = b""
        if method in ("POST", "PUT"):
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length > MAX_BLOB + 1_000_000:
                self._error(413, "too_large", "body too large")
                return
            if length > 0:
                self._raw_body = self.rfile.read(length)
        try:
            if path.startswith("/api/"):
                self._api(method, path)
            elif method == "GET":
                self._static(path)
            else:
                self._error(404, "not_found", "not found")
        except ValueError as exc:
            self._error(400, "bad_request", str(exc))
        except BrokenPipeError:
            pass
        except Exception as exc:  # 桩自身出错时给测试页一个可读信号
            traceback.print_exc()
            try:
                self._error(500, "stub_error", str(exc))
            except Exception:
                pass

    # ---------- static ----------
    def _static(self, path):
        if path in ("/", "/index.html"):
            self._send(302, None, {"Location": "/tests/online_smoke.html"})
            return
        root = self.server.root
        rel = path.lstrip("/")
        if rel.startswith("tests/"):
            target = os.path.abspath(os.path.join(root, rel))
        elif rel == "2brain.html":
            target = os.path.abspath(os.path.join(root, "2brain.html"))
        else:
            self._error(404, "not_found", "not found")
            return
        if not target.startswith(os.path.abspath(root) + os.sep) and \
                target != os.path.abspath(root):
            self._error(403, "forbidden", "forbidden")
            return
        if not os.path.isfile(target):
            self._error(404, "not_found", "not found")
            return
        ext = os.path.splitext(target)[1].lower()
        try:
            with open(target, "rb") as fh:
                data = fh.read()
        except OSError:
            self._error(500, "read_failed", "read failed")
            return
        self.send_response(200)
        self.send_header("Content-Type", MIME.get(ext, "application/octet-stream"))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    # ---------- api ----------
    def _vault_row(self, uid):
        vid = getattr(self, "_vid", "main")
        if vid == "main":
            return STATE.brains.get(uid)
        return STATE.vaults.get((uid, vid))

    def _api(self, method, path):
        self._vid = "main"
        self._shared = ""
        self._shared_brain = False
        self._shared_action = ""
        self._shared_member = 0
        m = re.fullmatch(r"/api/v/([A-Za-z0-9_-]{1,32})(/.*)?", path)
        if m:
            self._vid = m.group(1).lower()
            path = "/api" + (m.group(2) or "")
        m = re.fullmatch(r"/api/s/([A-Za-z0-9_-]{1,32})(/.*)?", path)
        if m:
            self._shared = m.group(1).lower()
            self._shared_brain = True
            path = "/api" + (m.group(2) or "")
        m = re.fullmatch(r"/api/shared/([A-Za-z0-9_-]{1,32})(/.*)?", path)
        if m:
            self._shared = m.group(1).lower()
            rest = m.group(2) or ""
            mm = re.fullmatch(r"/members/(\d{1,10})", rest)
            if mm:
                self._shared_action = "member"
                self._shared_member = int(mm.group(1))
            elif rest in ("/invite", "/rotate", "/transfer"):
                self._shared_action = rest[1:]
            elif rest == "":
                self._shared_action = "meta"
            else:
                self._shared_action = "unknown"
            path = "/api/shared"
        if path == "/api/__reset" and method == "POST":
            STATE.reset()
            self._send(200, {"ok": True})
            return
        if path == "/api/__state" and method == "GET":
            with STATE.lock:
                current = None
                uid, _ = self._cookie_uid()
                if uid is None:
                    uid = next(iter(STATE.brains), None)
                if uid is not None:
                    current = dict(STATE.brains.get(uid) or {})
                    current["uid"] = uid
                users = [{"uid": u["uid"], "name": u["name"]}
                         for u in STATE.users.values()]
                shared_out = []
                for sgid, sr in sorted(STATE.shared.items()):
                    shared_out.append({
                        "gid": sgid, "name": sr["name"],
                        "owner_uid": sr["owner_uid"], "rev": sr["rev"],
                        "etag": sr.get("etag"), "blob": sr.get("blob"),
                        "size": sr.get("size") or 0,
                        "key_epoch": sr["key_epoch"],
                        "members": [{"uid": muid, "role": m["role"],
                                     "key_epoch": m["key_epoch"],
                                     "wrapped": m["wrapped"]}
                                    for (g, muid), m in sorted(STATE.shared_members.items())
                                    if g == sgid],
                    })
                payload = {
                    "ok": True, "users": users,
                    "sessions": len(STATE.sessions),
                    "brain": current,
                    "shared": shared_out,
                    "archives": sorted(STATE.archives),
                    "offline": STATE.offline,
                    "log": STATE.log[-120:],
                }
            self._send(200, payload)
            return
        if path == "/api/__put" and method == "POST":
            # 模拟另一台设备直接上传（不走 cookie），body 同 PUT /api/brain
            body = self._read_json()
            uid = int(body.get("uid") or 0)
            with STATE.lock:
                if uid not in STATE.users:
                    self._error(400, "bad_uid", "unknown uid")
                    return
                result = self._store_blob(uid, body, bypass=True)
            self._send(*result)
            return
        if path == "/api/__expire" and method == "POST":
            with STATE.lock:
                STATE.sessions.clear()
            self._send(200, {"ok": True})
            return
        if path == "/api/__offline" and method == "POST":
            body = self._read_json()
            STATE.offline = bool(body.get("on"))
            self._send(200, {"ok": True, "offline": STATE.offline})
            return
        if path == "/api/__rewind" and method == "POST":
            with STATE.lock:
                uid, _ = self._cookie_uid()
                if uid is None:
                    uid = next(iter(STATE.brains), None)
                row = STATE.brains.get(uid) if uid is not None else None
                if row is not None and row.get("blob") is not None and row["rev"] > 0:
                    row["rev"] -= 1
                    # 模拟恢复旧快照：内容/etag 一起回退，否则条件 GET 只会返回 304
                    row["etag"] = hashlib.sha256(
                        ("rewind|" + str(row["rev"]) + "|" + row["etag"]).encode()
                    ).hexdigest()[:16]
                payload = {"ok": True,
                           "rev": row["rev"] if row is not None else 0}
            self._send(200, payload)
            return
        if path == "/api/__server_reset" and method == "POST":
            # 模拟"另一台设备完成同步重置"：直接清空、rev+1、epoch+1
            body = self._read_json()
            with STATE.lock:
                uid, _ = self._cookie_uid()
                if uid is None:
                    uid = next(iter(STATE.brains), None)
                row = STATE.brains.get(uid) if uid is not None else None
                if row is None:
                    self._error(400, "bad_uid", "unknown uid")
                    return
                name = str(body.get("archive") or "pre-reset-test")
                STATE.archives[name] = {"uid": uid, "rev": row["rev"],
                                        "etag": row.get("etag"),
                                        "epoch": int(row.get("epoch") or 0)}
                row["rev"] = int(row["rev"]) + 1
                row["etag"] = None
                row["blob"] = None
                row["updated_at"] = now_iso()
                row["epoch"] = int(row.get("epoch") or 0) + 1
                row["reset_at"] = now_iso()
                row["reset_archive"] = name
                payload = {"ok": True, "rev": row["rev"], "epoch": row["epoch"],
                           "resetAt": row["reset_at"], "archive": name}
            self._send(200, payload)
            return
        if path == "/api/__seed_recovery" and method == "POST":
            self._error(404, "not_needed", "not needed")
            return

        if path == "/api/kdf" and method == "POST":
            self._h_kdf()
        elif path == "/api/setup" and method == "POST":
            self._h_setup()
        elif path == "/api/login" and method == "POST":
            self._h_login()
        elif path == "/api/me" and method == "GET":
            self._h_me()
        elif path == "/api/logout" and method == "POST":
            self._h_logout(False)
        elif path == "/api/logout_all" and method == "POST":
            self._h_logout(True)
        elif path == "/api/brain" and method == "GET":
            if self._shared_brain:
                self._h_shared_brain_get()
            else:
                self._h_brain_get()
        elif path == "/api/brain" and method == "PUT":
            if self._shared_brain:
                self._h_shared_brain_put()
            else:
                self._h_brain_put()
        elif path == "/api/vaults" and method == "GET":
            self._h_vaults_list()
        elif path == "/api/vaults" and method == "POST":
            self._h_vaults_create()
        elif path.startswith("/api/vaults/") and method == "DELETE":
            self._h_vaults_delete(path[len("/api/vaults/"):])
        elif path == "/api/keys" and method == "GET":
            self._h_keys_get()
        elif path == "/api/keys" and method == "PUT":
            self._h_keys_put()
        elif path == "/api/shared" and method == "GET":
            if self._shared_action == "meta":
                self._h_shared_meta()
            else:
                self._h_shared_list()
        elif path == "/api/shared" and method == "POST":
            if self._shared:
                self._h_shared_post()
            else:
                self._h_shared_create()
        elif path == "/api/shared" and method == "PUT":
            self._h_shared_member_put()
        elif path == "/api/shared" and method == "DELETE":
            if self._shared_action == "member":
                self._h_shared_member_delete()
            else:
                self._h_shared_delete()
        elif path == "/api/brain/archive" and method == "POST":
            self._h_brain_archive()
        elif path == "/api/brain/reset" and method == "POST":
            self._h_brain_reset()
        else:
            self._error(404, "not_found", "not found")

    def _h_kdf(self):
        body = self._read_json()
        name = norm_name(body.get("name"))
        with STATE.lock:
            user = STATE.users.get(STATE.by_name.get(name)) if name else None
            if user is not None:
                salt = b64d(user["kdf_salt"])
                iterator, ver = user["kdf_iter"], user["kdf_ver"]
            else:
                salt, iterator, ver = fake_kdf(name)
        STATE.audit("POST", "/api/kdf", 200)
        self._send(200, {"salt": b64e(salt), "iter": iterator, "ver": ver})

    def _h_setup(self):
        body = self._read_json()
        name = norm_name(body.get("name"))
        if not NAME_RE.fullmatch(name):
            self._error(400, "bad_name", "name must be 3-32 chars")
            return
        if crockford_norm(body.get("invite")) != crockford_norm(INVITE):
            self._error(403, "bad_invite", "invalid invite")
            return
        kdf_salt = b64d(body.get("kdfSalt"), 16)
        auth_hash = b64d(body.get("authHash"), 32)
        wrapped = b64d(body.get("wrappedDEK"), 48)
        dek_iv = b64d(body.get("dekIv"), 12)
        rec_ver = b64d(body.get("recoveryVerifier"), 32)
        wrapped_rec = b64d(body.get("wrappedDEKRecovery"), 48)
        rec_iv = b64d(body.get("recIv"), 12)
        if not all((kdf_salt, auth_hash, wrapped, dek_iv, rec_ver,
                    wrapped_rec, rec_iv)):
            self._error(400, "bad_field", "missing or bad setup field")
            return
        try:
            kdf_iter = int(body.get("kdfIter"))
            kdf_ver = int(body.get("kdfVer"))
        except (TypeError, ValueError):
            self._error(400, "bad_field", "bad kdf fields")
            return
        if not (MIN_KDF_ITER <= kdf_iter <= MAX_KDF_ITER) or kdf_ver != KDF_VER:
            self._error(400, "bad_kdf", "unsupported kdf")
            return
        with STATE.lock:
            if name in STATE.by_name:
                self._error(409, "name_taken", "name already exists")
                return
            auth_salt = secrets.token_bytes(16)
            uid = STATE.next_uid
            STATE.next_uid += 1
            STATE.users[uid] = {
                "uid": uid, "name": name, "created": now_iso(),
                "kdf_salt": b64e(kdf_salt), "kdf_iter": kdf_iter,
                "kdf_ver": kdf_ver,
                "auth_salt": b64e(auth_salt),
                "auth_verifier": b64e(verifier(auth_hash, auth_salt)),
                "wrapped_dek": b64e(wrapped), "dek_iv": b64e(dek_iv),
                "recovery_verifier": b64e(rec_ver),
                "wrapped_dek_recovery": b64e(wrapped_rec),
                "rec_iv": b64e(rec_iv),
            }
            STATE.by_name[name] = uid
            STATE.brains[uid] = {"rev": 0, "etag": None, "blob": None,
                                 "updated_at": None, "epoch": 0,
                                 "reset_at": None, "reset_archive": None}
            token = secrets.token_urlsafe(24)
            STATE.sessions[token] = uid
        STATE.audit("POST", "/api/setup", 200, uid)
        self._send(200, {"uid": uid, "name": name}, self._set_cookie(token))

    def _h_login(self):
        body = self._read_json()
        name = norm_name(body.get("name"))
        auth_hash = b64d(body.get("authHash"), 32)
        if auth_hash is None:
            self._error(400, "bad_field", "missing authHash")
            return
        with STATE.lock:
            uid = STATE.by_name.get(name)
            user = STATE.users.get(uid) if uid else None
            try:
                iterator = int(body.get("iter"))
                kdf_ver = int(body.get("kdfVer"))
            except (TypeError, ValueError):
                iterator, kdf_ver = 0, 0
            if user is None:
                salt, fake_iter, fake_ver = fake_kdf(name)
                if iterator != fake_iter or kdf_ver != fake_ver:
                    self._error(409, "kdf_changed", "kdf parameters changed",
                                {"kdf": {"salt": b64e(salt),
                                         "iter": fake_iter, "ver": fake_ver}})
                    return
                hashlib.pbkdf2_hmac("sha256", auth_hash, b"\x00" * 16,
                                    SERVER_PBKDF2_ITERS, 32)
                STATE.audit("POST", "/api/login", 401)
                self._error(401, "bad_credentials", "invalid name or password")
                return
            if iterator != user["kdf_iter"] or kdf_ver != user["kdf_ver"]:
                kdf = {"salt": user["kdf_salt"], "iter": user["kdf_iter"],
                       "ver": user["kdf_ver"]}
                self._error(409, "kdf_changed", "kdf parameters changed",
                            {"kdf": kdf})
                return
            expected = b64d(user["auth_verifier"])
            actual = verifier(auth_hash, b64d(user["auth_salt"]))
            if not hmac.compare_digest(actual, expected):
                STATE.audit("POST", "/api/login", 401)
                self._error(401, "bad_credentials", "invalid name or password")
                return
            token = secrets.token_urlsafe(24)
            STATE.sessions[token] = uid
            payload = {
                "uid": uid, "name": user["name"],
                "wrappedDEK": user["wrapped_dek"], "dekIv": user["dek_iv"],
                "kdf": {"salt": user["kdf_salt"], "iter": user["kdf_iter"],
                        "ver": user["kdf_ver"]},
            }
        STATE.audit("POST", "/api/login", 200, uid)
        self._send(200, payload, self._set_cookie(token))

    def _h_me(self):
        uid, _ = self._require()
        if uid is None:
            return
        with STATE.lock:
            user = STATE.users[uid]
            payload = {"uid": uid, "name": user["name"], "role": "owner",
                       "created": user["created"], "kind": "session",
                       "scope": "write"}
        STATE.audit("GET", "/api/me", 200, uid)
        self._send(200, payload)

    def _h_logout(self, all_sessions):
        uid, token = self._require()
        if uid is None:
            return
        with STATE.lock:
            if all_sessions:
                for key in [k for k, value in STATE.sessions.items()
                            if value == uid]:
                    STATE.sessions.pop(key, None)
            else:
                STATE.sessions.pop(token, None)
        STATE.audit("POST", "/api/logout_all" if all_sessions else "/api/logout",
                    200, uid)
        self._send(200, {"ok": True}, self._set_cookie(""))

    def _epoch_of(self, row):
        return int((row or {}).get("epoch") or 0)

    def _epoch_mismatch_error(self, row):
        self._error(409, "epoch_mismatch",
                    "sync epoch changed; pull before pushing",
                    {"rev": int(row["rev"]), "etag": row.get("etag"),
                     "epoch": self._epoch_of(row)})

    def _brain_payload(self, row, uid):
        if row is None or not row.get("blob"):
            return {"rev": int((row or {}).get("rev") or 0),
                    "etag": None, "blob": None,
                    "updatedAt": (row or {}).get("updated_at"),
                    "epoch": self._epoch_of(row),
                    "resetAt": (row or {}).get("reset_at"),
                    "resetArchive": (row or {}).get("reset_archive")}
        return {"rev": row["rev"], "etag": row["etag"], "blob": row["blob"],
                "updatedAt": row["updated_at"], "epoch": self._epoch_of(row),
                "resetAt": row.get("reset_at"),
                "resetArchive": row.get("reset_archive")}

    def _h_brain_get(self):
        uid, _ = self._require()
        if uid is None:
            return
        vid = getattr(self, "_vid", "main")
        with STATE.lock:
            row = dict(self._vault_row(uid) or {})
        if vid != "main" and not row:
            self._error(404, "not_found", "vault not found")
            return
        if not row or row.get("blob") is None:
            STATE.audit("GET", "/api/brain", 200, uid)
            self._send(200, self._brain_payload(row, uid))
            return
        inm = self.headers.get("If-None-Match") or ""
        tags = [part.strip().strip('"') for part in inm.split(",")]
        if inm.strip() == "*" or row["etag"] in tags:
            STATE.audit("GET", "/api/brain", 304, uid)
            self._send(304, None, {"ETag": f'"{row["etag"]}"'})
            return
        STATE.audit("GET", "/api/brain", 200, uid)
        self._send(200, self._brain_payload(row, uid),
                   {"ETag": f'"{row["etag"]}"'})

    def _h_brain_put(self):
        uid, _ = self._require(write=True)
        if uid is None:
            return
        body = self._read_json()
        if set(body.keys()) != {"v", "iv", "ct"}:
            self._error(400, "bad_blob", "blob must contain v, iv, ct only")
            return
        if body.get("v") != 1:
            self._error(400, "bad_blob", "unsupported blob version")
            return
        iv = b64d(body.get("iv"), 12)
        ct = b64d(body.get("ct"))
        if iv is None or not ct:
            self._error(400, "bad_blob", "bad iv/ct")
            return
        if len(ct) > MAX_BLOB:
            self._error(400, "bad_blob", "ct too large")
            return
        vid = getattr(self, "_vid", "main")
        with STATE.lock:
            row = self._vault_row(uid)
            if vid != "main" and row is None:
                self._error(404, "not_found", "vault not found")
                return
            row = row or {"rev": 0, "etag": None,
                          "blob": None, "updated_at": None,
                          "epoch": 0, "reset_at": None,
                          "reset_archive": None}
            cur_epoch = self._epoch_of(row)
            provided = (self.headers.get("X-2brain-Epoch") or "").strip()
            if provided == "":
                if cur_epoch > 0:
                    self._epoch_mismatch_error(row)
                    STATE.audit("PUT", "/api/brain", 409, uid)
                    return
            else:
                try:
                    provided_epoch = int(provided)
                except ValueError:
                    self._error(400, "bad_epoch", "invalid X-2brain-Epoch")
                    return
                if provided_epoch != cur_epoch:
                    self._epoch_mismatch_error(row)
                    STATE.audit("PUT", "/api/brain", 409, uid)
                    return
            current = row["etag"] if row["blob"] is not None else None
            if_match = (self.headers.get("If-Match") or "").strip()
            if_none = (self.headers.get("If-None-Match") or "").strip()
            if if_none == "*":
                if current is not None:
                    self._error(412, "conflict", "etag mismatch",
                                {"rev": row["rev"], "etag": current})
                    STATE.audit("PUT", "/api/brain", 412, uid)
                    return
            elif if_match:
                want = if_match.strip('"')
                if want == "*":
                    if current is None:
                        self._error(412, "conflict", "etag mismatch",
                                    {"rev": row["rev"], "etag": current})
                        STATE.audit("PUT", "/api/brain", 412, uid)
                        return
                elif current is None or want != current:
                    self._error(412, "conflict", "etag mismatch",
                                {"rev": row["rev"], "etag": current})
                    STATE.audit("PUT", "/api/brain", 412, uid)
                    return
            else:
                if current is not None:
                    self._error(412, "conflict", "etag mismatch",
                                {"rev": row["rev"], "etag": current})
                    STATE.audit("PUT", "/api/brain", 412, uid)
                    return
            result = self._store_blob_locked(uid, body, vid)
        STATE.audit("PUT", "/api/brain", 200, uid)
        self._send(*result)

    def _h_vaults_list(self):
        uid, _ = self._require()
        if uid is None:
            return
        with STATE.lock:
            main = STATE.brains.get(uid)
            out = [self._vault_meta("main", "默认库", main, main=True)]
            for (vuid, vid), row in sorted(STATE.vaults.items()):
                if vuid != uid:
                    continue
                out.append(self._vault_meta(
                    vid, row.get("name") or vid, row, main=False))
        STATE.audit("GET", "/api/vaults", 200, uid)
        self._send(200, {"vaults": out, "max": MAX_VAULTS})

    def _vault_meta(self, vid, name, row, main):
        row = row or {}
        blob = row.get("blob") or {}
        return {"vid": vid, "name": name, "rev": int(row.get("rev") or 0),
                "etag": row.get("etag"),
                "size": int(row.get("size") or 0),
                "updatedAt": row.get("updated_at"),
                "epoch": self._epoch_of(row) if row else 0,
                "created": row.get("created"), "main": bool(main)}

    def _h_vaults_create(self):
        uid, _ = self._require(write=True)
        if uid is None:
            return
        body = self._read_json()
        name = str(body.get("name") or "").strip()[:64] or "新库"
        vid = str(body.get("vid") or "").strip().lower()
        if vid == "main":
            self._error(409, "conflict", "main vault always exists")
            return
        if vid and not VID_RE.fullmatch(vid):
            self._error(400, "bad_vid", "invalid vault id")
            return
        if not vid:
            vid = "v" + secrets.token_hex(6)
        with STATE.lock:
            mine = [k for k in STATE.vaults if k[0] == uid]
            if len(mine) >= MAX_VAULTS:
                self._error(429, "too_many_vaults", "vault limit reached",
                            {"max": MAX_VAULTS})
                return
            if (uid, vid) in STATE.vaults:
                self._error(409, "conflict", "vault already exists")
                return
            STATE.vaults[(uid, vid)] = {
                "name": name, "rev": 0, "etag": None, "blob": None,
                "size": 0, "updated_at": None, "epoch": 0,
                "reset_at": None, "reset_archive": None,
                "created": now_iso()}
        STATE.audit("POST", "/api/vaults", 200, uid)
        self._send(200, {"vid": vid, "name": name, "rev": 0})

    def _h_vaults_delete(self, vid):
        uid, _ = self._require(write=True)
        if uid is None:
            return
        vid = str(vid or "").split("?")[0].strip().lower()
        if not VID_RE.fullmatch(vid):
            self._error(400, "bad_vid", "invalid vault id")
            return
        if vid == "main":
            self._error(403, "main_vault",
                        "the default vault cannot be deleted")
            return
        with STATE.lock:
            if STATE.vaults.pop((uid, vid), None) is None:
                self._error(404, "not_found", "vault not found")
                return
        STATE.audit("DELETE", "/api/vaults/" + vid, 200, uid)
        self._send(200, {"ok": True, "vid": vid})

    def _h_brain_archive(self):
        uid, _ = self._require()
        if uid is None:
            return
        with STATE.lock:
            row = STATE.brains.get(uid)
            if row is None or row.get("blob") is None:
                self._error(409, "nothing_to_archive",
                            "server brain is already empty")
                return
            etag = row.get("etag") or hashlib.sha256(
                json.dumps(row["blob"], sort_keys=True).encode()).hexdigest()[:16]
            name = "pre-reset-" + datetime.now(timezone.utc).strftime(
                "%Y%m%dT%H%M%SZ")
            base, n = name, 1
            while name in STATE.archives:
                n += 1
                name = f"{base}-{n}"
            STATE.archives[name] = {"uid": uid, "rev": int(row["rev"]),
                                    "etag": etag, "epoch": self._epoch_of(row)}
            blob_bytes = json.dumps(row["blob"]).encode("utf-8")
            payload = {"ok": True, "archive": name, "rev": int(row["rev"]),
                       "etag": etag, "epoch": self._epoch_of(row),
                       "bytes": len(blob_bytes),
                       "dbSha256": hashlib.sha256(blob_bytes).hexdigest(),
                       "createdAt": now_iso(), "udisk": True}
        STATE.audit("POST", "/api/brain/archive", 200, uid)
        self._send(200, payload)

    def _h_brain_reset(self):
        uid, _ = self._require()
        if uid is None:
            return
        body = self._read_json()
        if body.get("confirm") != "同步重置":
            self._error(400, "confirm_required",
                        'confirm must be "同步重置"')
            return
        auth_hash = b64d(body.get("authHash"), 32)
        if auth_hash is None:
            self._error(400, "bad_field", "missing authHash")
            return
        with STATE.lock:
            user = STATE.users[uid]
            if not hmac.compare_digest(
                    verifier(auth_hash, b64d(user["auth_salt"])),
                    b64d(user["auth_verifier"])):
                self._error(401, "bad_credentials", "password incorrect")
                return
            name = str(body.get("archive") or "")
            arc = STATE.archives.get(name)
            row = STATE.brains.get(uid)
            if arc is None:
                self._error(409, "archive_invalid", "archive not found",
                            {"reason": "not_found"})
                return
            try:
                expect_rev = int(body.get("expectRev"))
                expect_epoch = int(body.get("expectEpoch"))
            except (TypeError, ValueError):
                self._error(400, "bad_field", "bad expect fields")
                return
            expect_etag = str(body.get("expectEtag") or "")
            if arc["uid"] != uid or arc["rev"] != expect_rev \
                    or arc["epoch"] != expect_epoch \
                    or arc["etag"] != expect_etag:
                self._error(409, "stale_archive",
                            "archive does not match the requested revision",
                            {"reason": "manifest_mismatch"})
                return
            if row is None or row.get("blob") is None:
                self._error(409, "nothing_to_reset",
                            "server brain is already empty")
                return
            cur_etag = row.get("etag") or hashlib.sha256(
                json.dumps(row["blob"], sort_keys=True).encode()).hexdigest()[:16]
            if int(row["rev"]) != expect_rev or self._epoch_of(row) != expect_epoch \
                    or cur_etag != expect_etag:
                self._error(409, "stale_archive",
                            "server changed since the archive was made",
                            {"rev": int(row["rev"]), "etag": cur_etag,
                             "epoch": self._epoch_of(row)})
                return
            row["rev"] = int(row["rev"]) + 1
            row["etag"] = None
            row["blob"] = None
            row["updated_at"] = now_iso()
            row["epoch"] = self._epoch_of(row) + 1
            row["reset_at"] = now_iso()
            row["reset_archive"] = name
            payload = {"ok": True, "rev": row["rev"], "epoch": row["epoch"],
                       "resetAt": row["reset_at"], "archive": name}
        STATE.audit("POST", "/api/brain/reset", 200, uid)
        self._send(200, payload)

    # ---------- 共享库（schema 4 镜像） ----------
    def _shared_scope(self, gid, uid, write=False):
        with STATE.lock:
            row = STATE.shared.get(gid)
            member = STATE.shared_members.get((gid, uid))
        if row is None or member is None:
            self._error(404, "not_found", "shared vault not found")
            return None, None
        if write:
            if member["role"] == "reader":
                self._error(403, "read_only", "reader members cannot write")
                return None, None
            if int(member["key_epoch"]) != int(row["key_epoch"]):
                self._error(409, "key_epoch_stale",
                            "member key is stale; refresh this vault",
                            {"keyEpoch": int(row["key_epoch"])})
                return None, None
        return row, member

    def _h_keys_get(self):
        uid, _ = self._require()
        if uid is None:
            return
        with STATE.lock:
            pub = STATE.keys.get(uid)
        self._send(200, {"pubJwk": pub, "updatedAt": None if pub is None
                         else now_iso()})

    def _h_keys_put(self):
        uid, _ = self._require()
        if uid is None:
            return
        body = self._read_json()
        pub = norm_pub(body.get("pubJwk"))
        if pub is None:
            self._error(400, "bad_pubkey", "pubJwk must be an EC P-256 key")
            return
        with STATE.lock:
            existing = STATE.keys.get(uid)
            active = [k for k in STATE.shared_members
                      if k[1] == uid and STATE.shared.get(k[0]) is not None]
            if existing is not None and existing != pub and active:
                self._error(409, "key_in_use",
                            "account key is used by active shared vaults",
                            {"pubJwk": existing})
                return
            STATE.keys[uid] = pub
        STATE.audit("PUT", "/api/keys", 200, uid)
        self._send(200, {"ok": True, "pubJwk": pub})

    def _shared_meta_payload(self, gid, row, member):
        is_owner = member["role"] == "owner"
        with STATE.lock:
            owner = STATE.users.get(row["owner_uid"]) or {}
            members = []
            for (g, u), m in sorted(STATE.shared_members.items()):
                if g != gid:
                    continue
                item = {"uid": u,
                        "name": (STATE.users.get(u) or {}).get("name", ""),
                        "role": m["role"], "added": m["added"],
                        "updated": m["updated"], "keyEpoch": m["key_epoch"]}
                if is_owner and STATE.keys.get(u):
                    item["pubJwk"] = STATE.keys[u]
                members.append(item)
        return {
            "gid": gid, "name": row["name"], "role": member["role"],
            "ownerUid": row["owner_uid"], "ownerName": owner.get("name", ""),
            "keyEpoch": int(row["key_epoch"]),
            "myKeyEpoch": int(member["key_epoch"]),
            "wrapped": member["wrapped"], "rev": int(row["rev"]),
            "etag": row.get("etag"), "size": int(row.get("size") or 0),
            "updatedAt": row.get("updated_at"), "created": row["created"],
            "members": members,
        }

    def _h_shared_list(self):
        uid, _ = self._require()
        if uid is None:
            return
        with STATE.lock:
            out = []
            for (gid, muid), member in sorted(STATE.shared_members.items()):
                row = STATE.shared.get(gid)
                if muid != uid or row is None:
                    continue
                owner = STATE.users.get(row["owner_uid"]) or {}
                out.append({
                    "gid": gid, "name": row["name"], "role": member["role"],
                    "ownerUid": row["owner_uid"],
                    "ownerName": owner.get("name", ""),
                    "keyEpoch": int(row["key_epoch"]),
                    "myKeyEpoch": int(member["key_epoch"]),
                    "wrapped": member["wrapped"], "rev": int(row["rev"]),
                    "etag": row.get("etag"), "size": int(row.get("size") or 0),
                    "updatedAt": row.get("updated_at"),
                    "created": row["created"],
                    "members": sum(1 for k in STATE.shared_members if k[0] == gid),
                })
        STATE.audit("GET", "/api/shared", 200, uid)
        self._send(200, {"vaults": out})

    def _h_shared_meta(self):
        uid, _ = self._require()
        if uid is None:
            return
        gid = self._shared
        row, member = self._shared_scope(gid, uid)
        if row is None:
            return
        STATE.audit("GET", "/api/shared/" + gid, 200, uid)
        self._send(200, self._shared_meta_payload(gid, row, member))

    def _h_shared_create(self):
        uid, _ = self._require()
        if uid is None:
            return
        body = self._read_json()
        name = str(body.get("name") or "").strip()[:64] or "共享库"
        wrapped = norm_wrapped(body.get("wrapped"))
        if wrapped is None:
            self._error(400, "bad_wrapped", "wrapped key is required")
            return
        with STATE.lock:
            owned = sum(1 for r in STATE.shared.values()
                        if r["owner_uid"] == uid)
            if owned >= MAX_SHARED_VAULTS:
                self._error(429, "too_many_shared", "shared vault limit reached",
                            {"max": MAX_SHARED_VAULTS})
                return
            raw_gid = body.get("gid")
            if raw_gid is None:
                gid = "s" + secrets.token_hex(8)
            else:
                gid = str(raw_gid).lower()
                if not GID_RE.match(gid):
                    self._error(400, "bad_gid",
                                "gid must be `s` + 16 hex characters")
                    return
                if gid in STATE.shared:
                    self._error(409, "gid_taken", "gid already exists")
                    return
            ts = now_iso()
            STATE.shared[gid] = {"owner_uid": uid, "name": name, "rev": 0,
                                 "etag": None, "blob": None, "size": 0,
                                 "updated_at": None, "key_epoch": 1,
                                 "created": ts}
            STATE.shared_members[(gid, uid)] = {
                "role": "owner", "wrapped": wrapped, "key_epoch": 1,
                "added": ts, "updated": ts}
        STATE.audit("POST", "/api/shared", 200, uid)
        self._send(200, {"gid": gid, "name": name, "keyEpoch": 1})

    def _h_shared_delete(self):
        uid, _ = self._require()
        if uid is None:
            return
        gid = self._shared
        row, member = self._shared_scope(gid, uid)
        if row is None:
            return
        if member["role"] != "owner":
            self._error(403, "owner_only", "only the owner can do this")
            return
        with STATE.lock:
            STATE.shared.pop(gid, None)
            for key in [k for k in STATE.shared_members if k[0] == gid]:
                STATE.shared_members.pop(key, None)
        STATE.audit("DELETE", "/api/shared/" + gid, 200, uid)
        self._send(200, {"ok": True, "gid": gid})

    def _h_shared_post(self):
        action = self._shared_action
        if action == "invite":
            self._shared_invite()
        elif action == "rotate":
            self._shared_rotate()
        elif action == "transfer":
            self._shared_transfer()
        else:
            self._error(404, "not_found", "not found")

    def _shared_invite(self):
        uid, _ = self._require()
        if uid is None:
            return
        gid = self._shared
        row, member = self._shared_scope(gid, uid)
        if row is None:
            return
        if member["role"] != "owner":
            self._error(403, "owner_only", "only the owner can do this")
            return
        body = self._read_json()
        name = norm_name(body.get("name"))
        role = str(body.get("role") or "writer").lower()
        if role not in ("writer", "reader"):
            self._error(400, "bad_role", "role must be writer or reader")
            return
        with STATE.lock:
            target = STATE.by_name.get(name)
            if target is None:
                self._error(404, "user_not_found", "no such user")
                return
            if target == uid:
                self._error(400, "self_invite", "cannot invite yourself")
                return
            if (gid, target) in STATE.shared_members:
                self._error(409, "already_member", "already a member")
                return
            if sum(1 for k in STATE.shared_members if k[0] == gid) >= MAX_SHARED_MEMBERS:
                self._error(429, "too_many_members", "member limit reached",
                            {"max": MAX_SHARED_MEMBERS})
                return
            pub = STATE.keys.get(target)
            if pub is None:
                self._error(409, "no_pubkey",
                            "this user has not set up a sharing key yet")
                return
            tname = STATE.users[target]["name"]
        self._send(200, {"uid": target, "name": tname, "role": role,
                         "pubJwk": pub})

    def _h_shared_member_put(self):
        uid, _ = self._require()
        if uid is None:
            return
        gid = self._shared
        if self._shared_action != "member":
            self._error(404, "not_found", "not found")
            return
        row, member = self._shared_scope(gid, uid)
        if row is None:
            return
        if member["role"] != "owner":
            self._error(403, "owner_only", "only the owner can do this")
            return
        target = int(self._shared_member)
        if target == uid:
            self._error(400, "self_member", "owner is already a member")
            return
        body = self._read_json()
        role = str(body.get("role") or "").lower()
        if role not in ("writer", "reader"):
            self._error(400, "bad_role", "role must be writer or reader")
            return
        wrapped = norm_wrapped(body.get("wrapped"))
        if wrapped is None:
            self._error(400, "bad_wrapped", "wrapped key is required")
            return
        epoch = int(row["key_epoch"])
        provided = body.get("keyEpoch")
        if provided is not None and provided != epoch:
            self._error(409, "epoch_mismatch",
                        "key epoch changed; refresh this vault",
                        {"keyEpoch": epoch})
            return
        with STATE.lock:
            if target not in STATE.users:
                self._error(404, "user_not_found", "no such user")
                return
            if (gid, target) not in STATE.shared_members and \
                    sum(1 for k in STATE.shared_members if k[0] == gid) >= MAX_SHARED_MEMBERS:
                self._error(429, "too_many_members", "member limit reached",
                            {"max": MAX_SHARED_MEMBERS})
                return
            STATE.shared_members[(gid, target)] = {
                "role": role, "wrapped": wrapped, "key_epoch": epoch,
                "added": now_iso(), "updated": now_iso()}
            tname = STATE.users[target]["name"]
        STATE.audit("PUT", f"/api/shared/{gid}/members/{target}", 200, uid)
        self._send(200, {"ok": True, "uid": target, "name": tname,
                         "role": role, "keyEpoch": epoch})

    def _h_shared_member_delete(self):
        uid, _ = self._require()
        if uid is None:
            return
        gid = self._shared
        if self._shared_action != "member":
            self._error(404, "not_found", "not found")
            return
        row, member = self._shared_scope(gid, uid)
        if row is None:
            return
        target = int(self._shared_member)
        with STATE.lock:
            trow = STATE.shared_members.get((gid, target))
        if trow is None:
            self._error(404, "member_not_found", "member not found")
            return
        if target == uid:
            if member["role"] == "owner":
                self._error(409, "owner_transfer_required",
                            "transfer ownership before leaving")
                return
        elif member["role"] != "owner":
            self._error(403, "owner_only", "only the owner can do this")
            return
        if target != uid and int(trow["key_epoch"]) >= int(row["key_epoch"]):
            self._error(409, "rotate_required",
                        "rotate the vault key before removing this member",
                        {"keyEpoch": int(row["key_epoch"])})
            return
        with STATE.lock:
            STATE.shared_members.pop((gid, target), None)
        STATE.audit("DELETE", f"/api/shared/{gid}/members/{target}", 200, uid)
        self._send(200, {"ok": True, "uid": target})

    def _shared_transfer(self):
        uid, _ = self._require()
        if uid is None:
            return
        gid = self._shared
        row, member = self._shared_scope(gid, uid)
        if row is None:
            return
        if member["role"] != "owner":
            self._error(403, "owner_only", "only the owner can do this")
            return
        body = self._read_json()
        name = norm_name(body.get("name"))
        with STATE.lock:
            target = STATE.by_name.get(name)
            if target is None:
                self._error(404, "user_not_found", "no such user")
                return
            trow = STATE.shared_members.get((gid, target))
            if trow is None:
                self._error(404, "member_not_found",
                            "target must be an active member")
                return
            STATE.shared[gid]["owner_uid"] = target
            STATE.shared_members[(gid, uid)]["role"] = "writer"
            trow["role"] = "owner"
        self._send(200, {"ok": True, "ownerUid": target})

    def _shared_rotate(self):
        uid, _ = self._require()
        if uid is None:
            return
        gid = self._shared
        row, member = self._shared_scope(gid, uid)
        if row is None:
            return
        if member["role"] != "owner":
            self._error(403, "owner_only", "only the owner can do this")
            return
        body = self._read_json()
        cur = int(row["key_epoch"])
        try:
            new_epoch = int(body.get("keyEpoch"))
        except (TypeError, ValueError):
            self._error(400, "bad_field", "keyEpoch must be an integer")
            return
        if new_epoch != cur + 1:
            self._error(409, "epoch_mismatch",
                        "rotation must advance the key epoch by one",
                        {"keyEpoch": cur})
            return
        remove_raw = body.get("remove") or []
        if not isinstance(remove_raw, list):
            self._error(400, "bad_field", "remove must be a list")
            return
        remove = set()
        for item in remove_raw:
            if isinstance(item, bool) or not isinstance(item, int):
                self._error(400, "bad_field", "remove must contain uids")
                return
            remove.add(int(item))
        if row["owner_uid"] in remove or uid in remove:
            self._error(400, "bad_field", "cannot remove the owner")
            return
        wraps_raw = body.get("members")
        if not isinstance(wraps_raw, list) or not wraps_raw:
            self._error(400, "bad_field", "members is required")
            return
        wraps = {}
        for item in wraps_raw:
            if not isinstance(item, dict):
                self._error(400, "bad_field", "bad member entry")
                return
            muid = item.get("uid")
            if isinstance(muid, bool) or not isinstance(muid, int):
                self._error(400, "bad_field", "member uid must be an integer")
                return
            wrapped = norm_wrapped(item.get("wrapped"))
            if wrapped is None:
                self._error(400, "bad_wrapped", "wrapped key is required")
                return
            wraps[int(muid)] = wrapped
        blob_raw = body.get("blob")
        if not isinstance(blob_raw, dict) or \
                set(blob_raw.keys()) != {"v", "iv", "ct"} or blob_raw.get("v") != 1:
            self._error(400, "bad_blob", "blob must contain v, iv, ct only")
            return
        iv = b64d(blob_raw.get("iv"), 12)
        ct = b64d(blob_raw.get("ct"))
        if iv is None or not ct:
            self._error(400, "bad_blob", "bad iv/ct")
            return
        with STATE.lock:
            active = {u for (g, u) in STATE.shared_members if g == gid}
            if set(wraps) - active:
                self._error(400, "bad_field", "wraps for non-members")
                return
            if (active - remove) - set(wraps):
                self._error(400, "wraps_incomplete",
                            "every remaining member needs a wrapped key")
                return
            cur_etag = row.get("etag") if row.get("blob") is not None else None
            if cur_etag is not None:
                if (self.headers.get("If-Match") or "").strip('"') != cur_etag:
                    self._error(412, "conflict", "etag mismatch",
                                {"rev": int(row["rev"]), "etag": cur_etag})
                    return
            if int(STATE.shared[gid]["key_epoch"]) != cur:
                self._error(409, "epoch_mismatch",
                            "key epoch changed; refresh this vault",
                            {"keyEpoch": int(STATE.shared[gid]["key_epoch"])})
                return
            new_rev = int(row["rev"]) + 1
            row.update({"rev": new_rev, "etag": hashlib.sha256(ct).hexdigest()[:16],
                        "blob": {"v": 1, "iv": b64e(iv), "ct": b64e(ct)},
                        "size": len(ct), "updated_at": now_iso(),
                        "key_epoch": new_epoch})
            for muid, wrapped in wraps.items():
                STATE.shared_members[(gid, muid)]["wrapped"] = wrapped
                STATE.shared_members[(gid, muid)]["key_epoch"] = new_epoch
                STATE.shared_members[(gid, muid)]["updated"] = now_iso()
            for muid in remove:
                STATE.shared_members.pop((gid, muid), None)
        self._send(200, {"rev": new_rev, "etag": row["etag"],
                         "keyEpoch": new_epoch},
                   {"ETag": f'"{row["etag"]}"'})

    def _h_shared_brain_get(self):
        uid, _ = self._require()
        if uid is None:
            return
        gid = self._shared
        row, member = self._shared_scope(gid, uid)
        if row is None:
            return
        base = {"gid": gid, "name": row["name"], "role": member["role"],
                "keyEpoch": int(row["key_epoch"]),
                "myKeyEpoch": int(member["key_epoch"]),
                "wrapped": member["wrapped"],
                "ownerUid": row["owner_uid"]}
        if row.get("blob") is None:
            self._send(200, {"rev": int(row["rev"]), "etag": None,
                             "blob": None, "updatedAt": row.get("updated_at"),
                             **base})
            return
        inm = (self.headers.get("If-None-Match") or "").strip()
        tags = [part.strip().strip('"') for part in inm.split(",")]
        if inm == "*" or row["etag"] in tags:
            self._send(304, None, {"ETag": f'"{row["etag"]}"'})
            return
        self._send(200, {"rev": int(row["rev"]), "etag": row["etag"],
                         "blob": row["blob"],
                         "updatedAt": row.get("updated_at"), **base},
                   {"ETag": f'"{row["etag"]}"'})

    def _h_shared_brain_put(self):
        uid, _ = self._require(write=True)
        if uid is None:
            return
        gid = self._shared
        row, member = self._shared_scope(gid, uid, write=True)
        if row is None:
            return
        cur = int(row["key_epoch"])
        provided = (self.headers.get("X-2brain-KeyEpoch") or "").strip()
        try:
            provided_epoch = int(provided)
        except ValueError:
            self._error(409, "epoch_mismatch",
                        "key epoch changed; pull before pushing",
                        {"keyEpoch": cur})
            return
        if provided_epoch != cur:
            self._error(409, "epoch_mismatch",
                        "key epoch changed; pull before pushing",
                        {"rev": int(row["rev"]), "etag": row.get("etag"),
                         "keyEpoch": cur})
            return
        body = self._read_json()
        if set(body.keys()) != {"v", "iv", "ct"} or body.get("v") != 1:
            self._error(400, "bad_blob", "blob must contain v, iv, ct only")
            return
        iv = b64d(body.get("iv"), 12)
        ct = b64d(body.get("ct"))
        if iv is None or not ct:
            self._error(400, "bad_blob", "bad iv/ct")
            return
        if len(ct) > MAX_BLOB:
            self._error(400, "bad_blob", "ct too large")
            return
        with STATE.lock:
            row = STATE.shared.get(gid)
            if row is None:
                self._error(404, "not_found", "shared vault not found")
                return
            current = row["etag"] if row.get("blob") is not None else None
            if_match = (self.headers.get("If-Match") or "").strip()
            if_none = (self.headers.get("If-None-Match") or "").strip()
            if if_none == "*":
                if current is not None:
                    self._error(412, "conflict", "etag mismatch",
                                {"rev": int(row["rev"]), "etag": current})
                    return
            elif if_match:
                if if_match.strip('"') != current:
                    self._error(412, "conflict", "etag mismatch",
                                {"rev": int(row["rev"]), "etag": current})
                    return
            elif current is not None:
                self._error(412, "conflict", "etag mismatch",
                            {"rev": int(row["rev"]), "etag": current})
                return
            new_rev = int(row["rev"]) + 1
            etag = hashlib.sha256(ct).hexdigest()[:16]
            row.update({"rev": new_rev, "etag": etag,
                        "blob": {"v": 1, "iv": b64e(iv), "ct": b64e(ct)},
                        "size": len(ct), "updated_at": now_iso()})
        STATE.audit("PUT", f"/api/s/{gid}/brain", 200, uid)
        self._send(200, {"rev": new_rev, "etag": etag, "keyEpoch": cur},
                   {"ETag": f'"{etag}"'})

    def _store_blob(self, uid, body, bypass=False):
        with STATE.lock:
            return self._store_blob_locked(uid, body, "main")

    def _store_blob_locked(self, uid, body, vid="main"):
        iv = b64d(body.get("iv"), 12)
        ct = b64d(body.get("ct"))
        if iv is None or not ct:
            return (400, {"error": {"code": "bad_blob",
                                    "message": "bad iv/ct"}})
        blob = {"v": 1, "iv": b64e(iv), "ct": b64e(ct)}
        etag = hashlib.sha256(ct).hexdigest()[:16]
        if vid == "main":
            row = STATE.brains.get(uid)
        else:
            row = STATE.vaults.get((uid, vid))
        row = dict(row or {"rev": 0, "etag": None,
                           "blob": None, "updated_at": None,
                           "epoch": 0, "reset_at": None,
                           "reset_archive": None})
        rev = int(row["rev"]) + 1
        row.update({"rev": rev, "etag": etag, "blob": blob,
                    "updated_at": now_iso(), "size": len(ct)})
        if vid == "main":
            STATE.brains[uid] = row
        else:
            STATE.vaults[(uid, vid)] = row
        return (200, {"rev": rev, "etag": etag,
                      "epoch": self._epoch_of(row)})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=7799)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--root", default=os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")))
    args = ap.parse_args()
    httpd = ThreadingHTTPServer((args.bind, args.port), Handler)
    httpd.daemon_threads = True
    httpd.root = args.root
    print(f"2brain stub on http://{args.bind}:{args.port}/ "
          f"(root={args.root}, invite={INVITE})", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
