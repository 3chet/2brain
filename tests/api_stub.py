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
            self.brains = {}         # uid -> dict(rev, etag, blob, updated_at)
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
    def _api(self, method, path):
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
                payload = {
                    "ok": True, "users": users,
                    "sessions": len(STATE.sessions),
                    "brain": current,
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
            self._h_brain_get()
        elif path == "/api/brain" and method == "PUT":
            self._h_brain_put()
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
                                 "updated_at": None}
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

    def _h_brain_get(self):
        uid, _ = self._require()
        if uid is None:
            return
        with STATE.lock:
            row = dict(STATE.brains.get(uid) or {})
        if not row or row.get("blob") is None:
            STATE.audit("GET", "/api/brain", 200, uid)
            self._send(200, {"rev": 0, "etag": None, "blob": None,
                             "updatedAt": None})
            return
        inm = self.headers.get("If-None-Match") or ""
        tags = [part.strip().strip('"') for part in inm.split(",")]
        if inm.strip() == "*" or row["etag"] in tags:
            STATE.audit("GET", "/api/brain", 304, uid)
            self._send(304, None, {"ETag": f'"{row["etag"]}"'})
            return
        STATE.audit("GET", "/api/brain", 200, uid)
        self._send(200, {"rev": row["rev"], "etag": row["etag"],
                         "blob": row["blob"], "updatedAt": row["updated_at"]},
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
        with STATE.lock:
            row = STATE.brains.get(uid) or {"rev": 0, "etag": None,
                                            "blob": None, "updated_at": None}
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
            result = self._store_blob_locked(uid, body)
        STATE.audit("PUT", "/api/brain", 200, uid)
        self._send(*result)

    def _store_blob(self, uid, body, bypass=False):
        with STATE.lock:
            return self._store_blob_locked(uid, body)

    def _store_blob_locked(self, uid, body):
        iv = b64d(body.get("iv"), 12)
        ct = b64d(body.get("ct"))
        if iv is None or not ct:
            return (400, {"error": {"code": "bad_blob",
                                    "message": "bad iv/ct"}})
        blob = {"v": 1, "iv": b64e(iv), "ct": b64e(ct)}
        etag = hashlib.sha256(ct).hexdigest()[:16]
        row = STATE.brains.get(uid) or {"rev": 0, "etag": None,
                                        "blob": None, "updated_at": None}
        rev = int(row["rev"]) + 1
        STATE.brains[uid] = {"rev": rev, "etag": etag, "blob": blob,
                            "updated_at": now_iso()}
        return (200, {"rev": rev, "etag": etag})


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
