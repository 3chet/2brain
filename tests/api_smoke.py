#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""API smoke test for 2brain-app.py (M1a).

Runs against a throwaway SQLite database under the OS temp directory, on
127.0.0.1, never touching the real data directory or ~/.mnemon.

    python tests/api_smoke.py
    python tests/api_smoke.py --keep

Exit code 0 only when every check passes.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "2brain-app.py"
ADMIN = ROOT / "2brain-admin.py"

PASS = 0
FAIL = 0
FAILURES: list[str] = []


def check(name: str, cond: bool, detail="") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print("PASS " + name)
    else:
        FAIL += 1
        FAILURES.append(name)
        print("FAIL " + name + (" :: " + str(detail) if detail else ""))


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def material(label: str, size: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(f"{label}|{counter}".encode("ascii")).digest()
        counter += 1
    return out[:size]


def sha_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def rmtree_force(path) -> None:
    def retry(func, target, exc):
        try:
            os.chmod(target, 0o700)
            func(target)
        except OSError:
            pass
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=retry)
    else:
        shutil.rmtree(path, onerror=retry)


def blob_for(tag: str) -> dict:
    ct = material("ct|" + tag, 128)
    iv = material("iv|" + tag, 12)
    return {"v": 1, "iv": b64(iv), "ct": b64(ct)}


def etag_for(blob: dict) -> str:
    return sha_hex(base64.b64decode(blob["ct"]))[:16]


class Resp:
    def __init__(self, status: int, headers: dict, obj, raw: bytes):
        self.status = status
        self.headers = headers
        self.obj = obj
        self.raw = raw


class Api:
    def __init__(self, port: int):
        self.port = port
        self.origin = f"http://127.0.0.1:{port}"

    def connection(self) -> http.client.HTTPConnection:
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)


class Session:
    def __init__(self, api: Api):
        self.api = api
        self.cookie = None

    def req(self, method: str, path: str, body=None, headers=None,
            token: str | None = None, content_type: str = "application/json",
            omit_content_type: bool = False) -> Resp:
        hdrs = {"Origin": self.api.origin}
        if headers:
            hdrs.update(headers)
        data = None
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(
                body, separators=(",", ":")).encode("utf-8")
            if not omit_content_type:
                hdrs["Content-Type"] = content_type
        if self.cookie:
            hdrs["Cookie"] = "sb_sid=" + self.cookie
        if token:
            hdrs["Authorization"] = "Bearer " + token
        conn = self.api.connection()
        try:
            conn.request(method, path, body=data, headers=hdrs)
            raw_resp = conn.getresponse()
            raw = raw_resp.read()
            headers_out = {k.lower(): v for k, v in raw_resp.getheaders()}
            status = raw_resp.status
            set_cookie = raw_resp.getheader("Set-Cookie")
        finally:
            conn.close()
        if set_cookie and "sb_sid=" in set_cookie:
            value = set_cookie.split("sb_sid=", 1)[1].split(";", 1)[0]
            self.cookie = value or None
        obj = None
        if raw:
            try:
                obj = json.loads(raw.decode("utf-8"))
            except ValueError:
                obj = None
        return Resp(status, headers_out, obj, raw)


class Server:
    def __init__(self, db_path: str, log_path: str, port: int | None = None,
                 lock_scale: str = "0.02", max_body_mb: int = 2,
                 archive_root: str | None = None,
                 udisk_dir: str | None = None):
        self.port = port or free_port()
        self.origin = f"http://127.0.0.1:{self.port}"
        self.api = Api(self.port)
        self.log_path = log_path
        base = Path(db_path).parent
        self.archive_root = str(archive_root if archive_root is not None
                                else base / "archive")
        self.udisk_dir = str(udisk_dir if udisk_dir is not None
                             else base / "udisk")
        self.log = open(log_path, "ab")
        self.proc = subprocess.Popen(
            [sys.executable, str(APP), "--db", db_path,
             "--port", str(self.port), "--origin", self.origin,
             "--lock-scale", lock_scale, "--max-body-mb", str(max_body_mb),
             "--archive-root", self.archive_root,
             "--udisk-archive-dir", self.udisk_dir],
            stdin=subprocess.DEVNULL, stdout=self.log,
            stderr=subprocess.STDOUT,
        )

    def wait_ready(self, timeout: float = 15.0) -> bool:
        deadline = time.time() + timeout
        probe = Session(self.api)
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return False
            try:
                resp = probe.req("GET", "/api/health")
                if resp.status == 200:
                    return True
            except OSError:
                pass
            time.sleep(0.1)
        return False

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        self.log.close()


def run_admin(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(ADMIN), *args],
                          capture_output=True, text=True, timeout=60)


def invite_from_admin(db_path: str, name: str) -> str:
    proc = run_admin("--db", db_path, "invite", "--name", name, "--ttl", "1h")
    if proc.returncode != 0:
        raise RuntimeError(f"admin invite failed: {proc.stderr}")
    match = re.search(r"^invite:\s*(\S+)\s*$", proc.stdout, re.MULTILINE)
    if not match:
        raise RuntimeError(f"no invite in output: {proc.stdout!r}")
    return match.group(1)


def pub_jwk(tag: str) -> str:
    x = b64(material("pubx|" + tag, 32))
    y = b64(material("puby|" + tag, 32))
    return json.dumps({"kty": "EC", "crv": "P-256", "x": x, "y": y},
                      separators=(",", ":"))


def wrapped_key(tag: str) -> str:
    epk = {"kty": "EC", "crv": "P-256",
           "x": b64(material("epkx|" + tag, 32)),
           "y": b64(material("epky|" + tag, 32))}
    return json.dumps(
        {"v": 1, "epk": epk, "iv": b64(material("wiv|" + tag, 12)),
         "ct": b64(material("wct|" + tag, 48))},
        separators=(",", ":"))


def wrapped_equals(a: str, b: str) -> bool:
    try:
        return json.loads(a) == json.loads(b)
    except (TypeError, ValueError):
        return False


def insert_expired_invite(db_path: str, name: str, code: str) -> None:
    conn = sqlite3.connect(db_path, timeout=5)
    try:
        exp = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat(
            timespec="milliseconds")
        conn.execute(
            "INSERT INTO invites(code_hash,name,created,exp,used_by,used_at) "
            "VALUES(?,?,?,?,NULL,NULL)",
            (sha_hex(code.encode("ascii")), name,
             datetime.now(timezone.utc).isoformat(timespec="seconds"), exp),
        )
        conn.commit()
    finally:
        conn.close()


def insert_note_lock(db_path: str, gid: str, note_id: str, uid: int,
                     seconds_from_now: float) -> None:
    """直接写一行租约；负数即「已过期」，用来测服务端的过期处理。"""
    conn = sqlite3.connect(db_path, timeout=5)
    try:
        moment = (datetime.now(timezone.utc)
                  + timedelta(seconds=seconds_from_now))
        iso = moment.isoformat(timespec="milliseconds")
        conn.execute(
            "INSERT OR REPLACE INTO note_locks"
            "(gid,note_id,uid,device_id,expires_at,updated_at) "
            "VALUES(?,?,?,?,?,?)",
            (gid, note_id, uid, f"dev-{note_id}", iso,
             datetime.now(timezone.utc).isoformat(timespec="seconds")))
        conn.commit()
    finally:
        conn.close()


def count_note_locks(db_path: str, gid: str) -> int:
    conn = sqlite3.connect(db_path, timeout=5)
    try:
        return int(conn.execute(
            "SELECT COUNT(*) FROM note_locks WHERE gid=?", (gid,)).fetchone()[0])
    finally:
        conn.close()


def read_auth_salt(db_path: str) -> bytes:
    conn = sqlite3.connect(db_path, timeout=5)
    try:
        row = conn.execute(
            "SELECT auth_salt FROM users WHERE name='tester'").fetchone()
        return bytes(row[0])
    finally:
        conn.close()


def setup_body(name: str, invite: str, auth_hash: bytes, kdf_salt: bytes,
               kdf_iter: int = 600_000, kdf_ver: int = 1,
               wrapped_dek: bytes | None = None, dek_iv: bytes | None = None,
               rec_verifier: bytes | None = None,
               wrapped_rec: bytes | None = None,
               rec_iv: bytes | None = None) -> dict:
    return {
        "name": name,
        "invite": invite,
        "kdfSalt": b64(kdf_salt),
        "kdfIter": kdf_iter,
        "kdfVer": kdf_ver,
        "authHash": b64(auth_hash),
        "wrappedDEK": b64(wrapped_dek or material("wrapped", 48)),
        "dekIv": b64(dek_iv or material("dekiv", 12)),
        "recoveryVerifier": b64(rec_verifier or material("recver", 32)),
        "wrappedDEKRecovery": b64(wrapped_rec or material("wrappedrec", 48)),
        "recIv": b64(rec_iv or material("reciv", 12)),
    }


def login_body(name: str, auth_hash: bytes, kdf_iter: int = 600_000,
               kdf_ver: int = 1) -> dict:
    return {"name": name, "authHash": b64(auth_hash),
            "iter": kdf_iter, "kdfVer": kdf_ver}


class MockUpstream(BaseHTTPRequestHandler):
    """本机起的假模型服务：验证 /api/ai/proxy 的私网转发往返。"""

    seen: list[dict] = []

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = None
        type(self).seen.append({"path": self.path,
                                "auth": self.headers.get("Authorization") or "",
                                "payload": payload})
        out = json.dumps({"ok": True, "model": "mock", "echo": payload},
                         ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *_args) -> None:
        pass


def lan_ip() -> str:
    """拿本机非回环 IPv4（UDP connect 不发包，只选路由）。没有则返回空串。"""
    for target in ("192.0.2.1", "8.8.8.8"):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.connect((target, 80))
                ip = sock.getsockname()[0]
            finally:
                sock.close()
            if ip and not ip.startswith("127."):
                return ip
        except OSError:
            pass
    try:
        ip = socket.gethostbyname(socket.gethostname())
        return "" if ip.startswith("127.") else ip
    except OSError:
        return ""


def main(argv: list[str]) -> int:
    keep = "--keep" in argv
    tmp = Path(tempfile.mkdtemp(prefix="2brain-m1a-"))
    db_path = str(tmp / "test.db")
    log_path = str(tmp / "server.log")
    archive_root = tmp / "archive"
    udisk_dir = tmp / "udisk"
    archive_root.mkdir()
    udisk_dir.mkdir()
    server: Server | None = None

    H1 = material("authH1", 32)
    H2 = material("authH2", 32)
    H3 = material("authH3", 32)
    KDF_SALT = material("kdfsalt", 16)
    PW1 = material("pw1", 48)
    IV1 = material("iv1", 12)
    RECOVERY_CODE = "A1B2C3D4E5F6G7H8J9K0M1N2"
    R1 = hashlib.sha256(
        ("2brain|recovery-verifier|v1|tester|" + RECOVERY_CODE).encode("utf-8")
    ).digest()
    WR1 = material("wr1", 48)
    RIV1 = material("riv1", 12)
    PW2 = material("pw2", 48)
    IV2 = material("iv2", 12)
    PW3 = material("pw3", 48)
    IV3 = material("iv3", 12)
    R2 = material("r2", 32)
    WR2 = material("wr2", 48)
    RIV2 = material("riv2", 12)
    R3 = material("r3", 32)
    WR3 = material("wr3", 48)
    RIV3 = material("riv3", 12)

    print(f"temp dir: {tmp}")
    print(f"db:       {db_path}")

    try:
        proc = run_admin("--db", db_path, "init")
        check("admin init", proc.returncode == 0 and "initialized" in proc.stdout,
              proc.stderr.strip())
        proc = run_admin("--db", db_path, "init")
        check("admin init is idempotent", proc.returncode == 0, proc.stderr.strip())

        tester_invite = invite_from_admin(db_path, "tester")
        check("admin invite format", bool(re.fullmatch(
            r"(?:[0-9A-Z]{4}-){6}[0-9A-Z]{2}", tester_invite)),
            tester_invite)
        alice_invite = invite_from_admin(db_path, "alice")
        insert_expired_invite(db_path, "expired", "0" * 26)
        proc = run_admin("--db", db_path, "invite", "--name", "BAD NAME")
        check("admin rejects bad name", proc.returncode == 2 and "name" in proc.stderr,
              proc.stderr.strip())

        server = Server(db_path, log_path)
        if not server.wait_ready():
            print(Path(log_path).read_text(errors="replace")[-4000:])
            check("server starts", False, "health never became ready")
            return 1
        check("server starts", True)
        api = server.api

        anon = Session(api)
        resp = anon.req("GET", "/api/health")
        check("health 200", resp.status == 200, resp.raw[:200])
        check("health version",
              isinstance(resp.obj, dict) and resp.obj.get("version") == "m1h-2026-10-26",
              str(resp.obj))
        check("health schema", resp.obj.get("schema") == 5, str(resp.obj))
        check("health archive flag", resp.obj.get("archive") is True,
              str(resp.obj))

        # ---------- fake KDF salt ----------
        resp = anon.req("POST", "/api/kdf", {"name": "nobody"})
        fake_salt_1 = resp.obj.get("salt") if isinstance(resp.obj, dict) else None
        check("kdf unknown 200", resp.status == 200, resp.raw[:200])
        check("kdf unknown defaults", resp.obj.get("iter") == 600_000
              and resp.obj.get("ver") == 1, str(resp.obj))
        check("kdf fake salt is 16 bytes",
              fake_salt_1 is not None and len(base64.b64decode(fake_salt_1)) == 16,
              str(resp.obj))
        resp = anon.req("POST", "/api/kdf", {"name": "nobody"})
        check("kdf fake salt is stable", resp.obj.get("salt") == fake_salt_1,
              str(resp.obj))
        resp = anon.req("POST", "/api/kdf", {"name": "other"})
        check("kdf fake salt is name-specific", resp.obj.get("salt") != fake_salt_1,
              str(resp.obj))

        # ---------- setup failures + success ----------
        bad = setup_body("nobody", "A" * 26, H1, KDF_SALT)
        resp = anon.req("POST", "/api/setup", bad)
        check("setup rejects unknown invite", resp.status == 403
              and resp.obj["error"]["code"] == "bad_invite", resp.raw[:200])

        resp = anon.req("POST", "/api/setup",
                        setup_body("bob", alice_invite, H1, KDF_SALT))
        check("setup rejects invite/name mismatch", resp.status == 403, resp.raw[:200])

        resp = anon.req("POST", "/api/setup",
                        setup_body("expired", "0" * 26, H1, KDF_SALT))
        check("setup rejects expired invite", resp.status == 403, resp.raw[:200])

        resp = anon.req("POST", "/api/setup",
                        setup_body("tester", tester_invite, H1, KDF_SALT,
                                   kdf_iter=1000))
        check("setup rejects weak kdf iter", resp.status == 400
              and resp.obj["error"]["code"] == "bad_kdf_iter", resp.raw[:200])

        resp = anon.req("POST", "/api/setup",
                        setup_body("tester", tester_invite, b"short", KDF_SALT))
        check("setup rejects short authHash", resp.status == 400, resp.raw[:200])

        resp = anon.req("POST", "/api/setup",
                        setup_body("tester", tester_invite, H1, KDF_SALT,
                                   wrapped_dek=PW1, dek_iv=IV1,
                                   rec_verifier=R1, wrapped_rec=WR1,
                                   rec_iv=RIV1))
        ok_setup = resp.status == 200 and isinstance(resp.obj, dict)
        check("setup succeeds", ok_setup and resp.obj.get("name") == "tester",
              resp.raw[:200])
        check("setup returns only uid+name", ok_setup and set(resp.obj) == {"uid", "name"},
              str(resp.obj))
        uid = resp.obj.get("uid") if ok_setup else None
        cookie_header = resp.headers.get("set-cookie", "")
        check("setup sets session cookie", "sb_sid=" in cookie_header
              and "HttpOnly" in cookie_header and "SameSite=Lax" in cookie_header,
              cookie_header)
        check("setup cookie not Secure over http", "Secure" not in cookie_header,
              cookie_header)
        S1 = anon
        check("setup session works", S1.cookie is not None
              and S1.req("GET", "/api/me").status == 200, "")

        resp = anon.req("POST", "/api/setup",
                        setup_body("tester", tester_invite, H1, KDF_SALT))
        check("setup rejects reused invite", resp.status == 403, resp.raw[:200])
        proc = run_admin("--db", db_path, "invite", "--name", "tester")
        check("admin rejects existing user",
              proc.returncode == 2 and "already exists" in proc.stderr,
              proc.stderr.strip())

        # ---------- kdf for real user ----------
        resp = anon.req("POST", "/api/kdf", {"name": "tester"})
        check("kdf real salt", resp.obj.get("salt") == b64(KDF_SALT)
              and resp.obj.get("iter") == 600_000, str(resp.obj))

        # ---------- me ----------
        resp = S1.req("GET", "/api/me")
        check("me session", resp.status == 200 and resp.obj.get("uid") == uid
              and resp.obj.get("kind") == "session"
              and resp.obj.get("role") == "owner", str(resp.obj))

        # ---------- login ----------
        S2 = Session(api)
        statuses = []
        for _ in range(5):
            statuses.append(S2.req("POST", "/api/login",
                                   login_body("tester", material("wrong", 32))).status)
        check("login wrong password then lock", statuses[:4] == [401, 401, 401, 401]
              and statuses[4] == 429, str(statuses))
        resp = S2.req("POST", "/api/login", login_body("tester", H1))
        check("login while locked is 429", resp.status == 429
              and resp.obj.get("retryAfter", 0) >= 1
              and resp.headers.get("retry-after", "").isdigit(), resp.raw[:200])
        time.sleep(0.8)
        resp = S2.req("POST", "/api/login", login_body("tester", H1))
        check("login after lock expires", resp.status == 200, resp.raw[:200])
        check("login returns wrapped DEK", resp.obj.get("wrappedDEK") == b64(PW1)
              and resp.obj.get("dekIv") == b64(IV1), str(resp.obj))
        check("login returns kdf params", resp.obj.get("kdf", {}).get("salt") == b64(KDF_SALT)
              and resp.obj["kdf"].get("iter") == 600_000, str(resp.obj))
        check("login sets cookie", "sb_sid=" in resp.headers.get("set-cookie", ""),
              resp.headers.get("set-cookie", ""))

        resp = S2.req("POST", "/api/login",
                      login_body("tester", H1, kdf_iter=600_001))
        check("login stale iter is 409", resp.status == 409
              and resp.obj.get("kdf", {}).get("salt") == b64(KDF_SALT),
              resp.raw[:200])

        resp = anon.req("POST", "/api/login", login_body("ghost", H1))
        check("login unknown user is 401", resp.status == 401, resp.raw[:200])
        resp = anon.req("POST", "/api/kdf", {"name": "ghost"})
        ghost_salt = resp.obj.get("salt")
        resp = anon.req("POST", "/api/login", login_body("ghost", H1, kdf_iter=123))
        check("login unknown user stale iter is fake 409", resp.status == 409
              and resp.obj.get("kdf", {}).get("salt") == ghost_salt,
              resp.raw[:200])
        resp = anon.req("POST", "/api/login", login_body("tester", H1),
                        content_type="text/plain")
        check("login rejects non-json content type", resp.status == 400,
              resp.raw[:200])

        # ---------- AI 同源转发 / 文章抓取：鉴权 + SSRF 防线 ----------
        anon2 = Session(api)
        resp = anon2.req("POST", "/api/ai/proxy",
                         {"url": "http://model-host.example:18201/v1/models"})
        check("ai proxy requires session", resp.status == 401, resp.raw[:200])
        resp = anon2.req("POST", "/api/fetch/url", {"url": "https://example.com/"})
        check("fetch url requires session", resp.status == 401, resp.raw[:200])

        for path, target in (
                ("/api/ai/proxy", "file:///etc/passwd"),
                ("/api/ai/proxy", "http://127.0.0.1:9/v1/chat/completions"),
                ("/api/ai/proxy", "http://169.254.169.254/latest/meta-data/"),
                ("/api/fetch/url", "http://127.0.0.1/"),
                ("/api/fetch/url", "http://10.0.0.5/"),
                ("/api/fetch/url", "http://169.254.169.254/")):
            resp = S2.req("POST", path, {"url": target})
            err = resp.obj.get("error") if isinstance(resp.obj, dict) else None
            check("reject unsafe target " + target,
                  resp.status == 400 and isinstance(err, dict)
                  and err.get("code") == "bad_url", resp.raw[:200])

        resp = S2.req("POST", "/api/ai/proxy",
                      {"url": "http://192.0.2.1/v1/chat/completions",
                       "payload": []})
        err = resp.obj.get("error") if isinstance(resp.obj, dict) else None
        check("ai proxy rejects non-object payload",
              resp.status == 400 and isinstance(err, dict)
              and err.get("code") == "bad_payload", resp.raw[:200])
        resp = S2.req("POST", "/api/ai/proxy",
                      {"url": "http://192.0.2.1/v1/chat/completions",
                       "apiKey": "bad\nkey", "timeoutMs": 2000})
        err = resp.obj.get("error") if isinstance(resp.obj, dict) else None
        check("ai proxy rejects control chars in key",
              resp.status == 400 and isinstance(err, dict)
              and err.get("code") == "bad_key", resp.raw[:200])

        # 私网模型服务必须可转发：用本机 LAN 地址起假上游验证
        ip = lan_ip()
        if ip:
            upstream = ThreadingHTTPServer(("0.0.0.0", 0), MockUpstream)
            thread = threading.Thread(target=upstream.serve_forever, daemon=True)
            thread.start()
            try:
                target = ("http://%s:%d/v1/chat/completions"
                          % (ip, upstream.server_address[1]))
                resp = S2.req("POST", "/api/ai/proxy", {
                    "url": target, "method": "POST",
                    "apiKey": "smoke-not-a-real-key",
                    "payload": {"model": "mock", "messages": [{"role": "user",
                                                               "content": "ping"}]},
                    "timeoutMs": 5000,
                })
                ok = (resp.status == 200 and isinstance(resp.obj, dict)
                      and resp.obj.get("ok") is True and resp.obj.get("status") == 200)
                check("ai proxy forwards to private LAN model", ok, resp.raw[:300])
                body_text = resp.obj.get("bodyText", "") if ok else ""
                check("ai proxy returns upstream body",
                      '"model": "mock"' in body_text, body_text[:200])
                seen = MockUpstream.seen[-1] if MockUpstream.seen else {}
                check("ai proxy forwards bearer key + POST payload",
                      seen.get("auth") == "Bearer smoke-not-a-real-key"
                      and isinstance(seen.get("payload"), dict)
                      and seen["payload"].get("model") == "mock",
                      str(seen)[:300])
                check("ai proxy does not echo api key in response",
                      "smoke-not-a-real-key" not in resp.raw.decode("utf-8", "replace"),
                      resp.raw[:200])
            finally:
                upstream.shutdown()
                upstream.server_close()
        else:
            check("ai proxy LAN forward test (skipped: no LAN IPv4)", True)

        # keep-alive poisoning: rejected body must close the connection
        conn = api.connection()
        try:
            conn.request("POST", "/api/login", body=b'{"name":"x"}',
                         headers={"Origin": api.origin,
                                  "Content-Type": "text/plain"})
            first = conn.getresponse()
            first.read()
            check("rejected body closes connection",
                  first.status == 400
                  and (first.getheader("Connection") or "").lower() == "close",
                  str(first.status))
            conn.request("GET", "/api/health")
            second = conn.getresponse()
            second.read()
            check("connection reusable after close",
                  second.status == 200, str(second.status))
        finally:
            conn.close()

        # ---------- brain ----------
        resp = S2.req("GET", "/api/brain")
        check("brain starts empty", resp.status == 200
              and resp.obj.get("rev") == 0 and resp.obj.get("etag") is None
              and resp.obj.get("blob") is None, str(resp.obj))
        resp = S2.req("GET", "/api/brain/revisions")
        check("revisions start empty", resp.status == 200
              and resp.obj.get("revisions") == [], str(resp.obj))

        A = blob_for("A")
        B = blob_for("B")
        D = blob_for("D")
        E1, E2, E4 = (etag_for(A), etag_for(B), etag_for(D))

        resp = S2.req("PUT", "/api/brain", A, headers={"If-None-Match": "*"})
        check("first PUT with If-None-Match:*", resp.status == 200
              and resp.obj.get("rev") == 1 and resp.obj.get("etag") == E1,
              resp.raw[:200])
        resp = S2.req("PUT", "/api/brain", A, headers={"If-None-Match": "*"})
        check("second create conflicts", resp.status == 412
              and resp.obj.get("rev") == 1 and resp.obj.get("etag") == E1,
              resp.raw[:200])

        resp = S2.req("GET", "/api/brain")
        check("brain returns blob", resp.status == 200 and resp.obj.get("rev") == 1
              and resp.obj.get("blob") == A, str(resp.obj))
        check("brain returns ETag header", resp.headers.get("etag") == f'"{E1}"',
              resp.headers.get("etag", ""))

        resp = S2.req("GET", "/api/brain",
                      headers={"If-None-Match": f'"{E1}"'})
        check("If-None-Match 304", resp.status == 304 and resp.raw == b"",
              resp.raw[:100])
        check("304 has no Content-Length", "content-length" not in resp.headers,
              str(resp.headers))

        resp = S2.req("PUT", "/api/brain", B)
        check("PUT without If-Match on existing is 412", resp.status == 412,
              resp.raw[:200])
        resp = S2.req("PUT", "/api/brain", B, headers={"If-Match": '"deadbeef"'})
        check("PUT with stale If-Match is 412", resp.status == 412, resp.raw[:200])
        resp = S2.req("PUT", "/api/brain", B, headers={"If-Match": "*"})
        check("PUT with If-Match:*", resp.status == 200
              and resp.obj.get("rev") == 2 and resp.obj.get("etag") == E2,
              resp.raw[:200])

        bad_blob = dict(A)
        bad_blob["extra"] = 1
        resp = S2.req("PUT", "/api/brain", bad_blob,
                      headers={"If-Match": f'"{E2}"'})
        check("PUT rejects extra keys", resp.status == 400, resp.raw[:200])
        resp = S2.req("PUT", "/api/brain", {"v": 2, "iv": A["iv"], "ct": A["ct"]},
                      headers={"If-Match": f'"{E2}"'})
        check("PUT rejects blob version", resp.status == 400, resp.raw[:200])
        resp = S2.req("PUT", "/api/brain",
                      {"v": 1, "iv": b64(b"x" * 11), "ct": A["ct"]},
                      headers={"If-Match": f'"{E2}"'})
        check("PUT rejects short iv", resp.status == 400, resp.raw[:200])
        resp = S2.req("PUT", "/api/brain", {"v": 1, "iv": A["iv"], "ct": ""},
                      headers={"If-Match": f'"{E2}"'})
        check("PUT rejects empty ct", resp.status == 400, resp.raw[:200])

        resp = S2.req("PUT", "/api/brain", A,
                      headers={"If-Match": f'"{E2}"', "Origin": "https://evil.example"})
        check("PUT rejects cross origin", resp.status == 403
              and resp.obj["error"]["code"] == "bad_origin", resp.raw[:200])
        resp = S2.req("PUT", "/api/brain", A,
                      headers={"If-Match": f'"{E2}"',
                               "Sec-Fetch-Site": "cross-site"})
        check("PUT rejects cross-site fetch", resp.status == 403
              and resp.obj["error"]["code"] == "bad_fetch_site", resp.raw[:200])
        resp = S2.req("PUT", "/api/brain", A, headers={"If-Match": f'"{E2}"'},
                      content_type="text/plain")
        check("PUT rejects non-json content type", resp.status == 400,
              resp.raw[:200])

        # oversized body: headers only, server must answer 413 and close
        conn = api.connection()
        try:
            conn.putrequest("PUT", "/api/brain")
            conn.putheader("Origin", api.origin)
            conn.putheader("Cookie", "sb_sid=" + (S2.cookie or ""))
            conn.putheader("Content-Type", "application/json")
            conn.putheader("Content-Length", str(2 * 1024 * 1024 + 1))
            conn.endheaders()
            resp_raw = conn.getresponse()
            payload = resp_raw.read()
            check("oversized body is 413", resp_raw.status == 413,
                  payload[:200].decode("utf-8", "replace"))
            check("413 closes connection",
                  (resp_raw.getheader("Connection") or "").lower() == "close",
                  str(resp_raw.getheader("Connection")))
        finally:
            conn.close()

        resp = S2.req("GET", "/api/brain/revisions")
        revs = [r["rev"] for r in resp.obj.get("revisions", [])]
        check("revisions archive rev1", revs == [1] and resp.obj["revisions"][0]["size"] > 0,
              str(resp.obj))
        resp = S2.req("POST", "/api/brain/restore", {"rev": 1})
        check("restore rev1", resp.status == 200 and resp.obj.get("rev") == 3
              and resp.obj.get("etag") == E1, resp.raw[:200])
        resp = S2.req("GET", "/api/brain")
        check("restore returns old blob", resp.obj.get("rev") == 3
              and resp.obj.get("blob") == A, str(resp.obj))
        resp = S2.req("GET", "/api/brain/revisions")
        revs = sorted(r["rev"] for r in resp.obj.get("revisions", []))
        check("revisions keep rev1+rev2", revs == [1, 2], str(revs))
        resp = S2.req("POST", "/api/brain/restore", {"rev": 999})
        check("restore missing revision is 404", resp.status == 404, resp.raw[:200])
        resp = S2.req("POST", "/api/brain/restore", {"rev": 0})
        check("restore rev0 is 400", resp.status == 400, resp.raw[:200])

        # ---------- devices ----------
        resp = S2.req("POST", "/api/devices", {"name": "agent-read", "scope": "read"})
        check("create read device", resp.status == 200 and resp.obj.get("scope") == "read"
              and resp.obj.get("token"), resp.raw[:200])
        read_token = resp.obj.get("token")
        read_id = resp.obj.get("id")
        resp = S2.req("POST", "/api/devices", {"name": "agent-rw", "scope": "readwrite"})
        check("create readwrite device", resp.status == 200
              and resp.obj.get("scope") == "readwrite", resp.raw[:200])
        rw_token = resp.obj.get("token")
        rw_id = resp.obj.get("id")
        resp = S2.req("POST", "/api/devices", {"name": "survivor", "scope": "read"})
        survivor_token = resp.obj.get("token")
        survivor_id = resp.obj.get("id")
        resp = S2.req("POST", "/api/devices", {"name": "x", "scope": "root"})
        check("create device rejects bad scope", resp.status == 400, resp.raw[:200])
        resp = S2.req("POST", "/api/devices", {"name": "x"}, token=read_token)
        check("device cannot create device", resp.status == 401, resp.raw[:200])

        resp = S2.req("GET", "/api/brain", token=read_token)
        check("read device can read", resp.status == 200
              and resp.obj.get("rev") == 3, resp.raw[:200])
        resp = S2.req("PUT", "/api/brain", D,
                      headers={"If-Match": f'"{E1}"'}, token=read_token)
        check("read device cannot write", resp.status == 403
              and resp.obj["error"]["code"] == "readonly_device", resp.raw[:200])
        resp = S2.req("PUT", "/api/brain", D,
                      headers={"If-Match": f'"{E1}"'}, token=rw_token)
        check("readwrite device writes", resp.status == 200
              and resp.obj.get("rev") == 4 and resp.obj.get("etag") == E4,
              resp.raw[:200])
        resp = S2.req("GET", "/api/brain/revisions", token=read_token)
        check("device cannot list revisions", resp.status == 401, resp.raw[:200])
        resp = S2.req("GET", "/api/export", token=read_token)
        check("device cannot export", resp.status == 401, resp.raw[:200])

        resp = S2.req("GET", "/api/devices")
        ids = {d["id"]: d for d in resp.obj.get("devices", [])}
        check("device list", resp.status == 200 and {read_id, rw_id, survivor_id}
              <= set(ids) and all(not d["revoked"] for d in ids.values()),
              str(resp.obj))
        resp = S2.req("DELETE", "/api/devices/" + read_id)
        check("revoke device", resp.status == 200, resp.raw[:200])
        resp = S2.req("GET", "/api/brain", token=read_token)
        check("revoked device is 401", resp.status == 401, resp.raw[:200])
        resp = S2.req("DELETE", "/api/devices/nope")
        check("revoke unknown device is 404", resp.status == 404, resp.raw[:200])

        proc = run_admin("--db", db_path, "list-devices", "--name", "tester")
        check("admin lists devices", proc.returncode == 0
              and "agent-rw" in proc.stdout and "survivor" in proc.stdout,
              proc.stdout + proc.stderr)

        # ---------- password change ----------
        salt_before_pw = read_auth_salt(db_path)
        S3 = Session(api)
        check("second login for revocation test",
              S3.req("POST", "/api/login", login_body("tester", H1)).status == 200)
        resp = S2.req("POST", "/api/password", {
            "oldAuthHash": b64(material("wrong", 32)),
            "newAuthHash": b64(H2),
            "wrappedDEK": b64(PW2),
            "dekIv": b64(IV2),
        })
        check("password change rejects wrong old hash", resp.status == 401,
              resp.raw[:200])
        resp = S2.req("POST", "/api/password", {
            "oldAuthHash": b64(H1),
            "newAuthHash": b64(H2),
            "wrappedDEK": b64(PW2),
            "dekIv": b64(IV2),
        })
        check("password change succeeds", resp.status == 200, resp.raw[:200])
        check("password change rotates auth salt",
              read_auth_salt(db_path) != salt_before_pw, "")
        check("password change revokes other sessions",
              S3.req("GET", "/api/me").status == 401
              and S1.req("GET", "/api/me").status == 401, "")
        check("password change keeps current session",
              S2.req("GET", "/api/me").status == 200, "")
        check("password change keeps device tokens",
              S2.req("GET", "/api/brain", token=survivor_token).status == 200, "")

        S4 = Session(api)
        resp = S4.req("POST", "/api/login", login_body("tester", H1))
        check("old password is dead", resp.status == 401, resp.raw[:200])
        resp = S4.req("POST", "/api/login", login_body("tester", H2))
        check("new password works", resp.status == 200
              and resp.obj.get("wrappedDEK") == b64(PW2), resp.raw[:200])
        resp = S4.req("POST", "/api/login", login_body("tester", H2, kdf_iter=600_001))
        check("new password with stale iter is 409", resp.status == 409, resp.raw[:200])

        # ---------- recovery ----------
        resp = anon.req("POST", "/api/recover/verify",
                        {"name": "tester", "verifier": b64(material("nope", 32))})
        check("recovery rejects wrong verifier", resp.status == 403, resp.raw[:200])
        resp = anon.req("POST", "/api/recover/verify",
                        {"name": "tester", "verifier": b64(R1)})
        check("recovery verify returns wrapped DEK", resp.status == 200
              and resp.obj.get("wrappedDEKRecovery") == b64(WR1)
              and resp.obj.get("recIv") == b64(RIV1)
              and resp.obj.get("ticket"), resp.raw[:200])
        ticket = resp.obj.get("ticket")
        salt_before_rec = read_auth_salt(db_path)

        resp = anon.req("POST", "/api/recover/commit", {
            "ticket": ticket,
            "newAuthHash": b64(H3),
            "wrappedDEK": b64(PW3),
            "dekIv": b64(IV3),
            "newRecoveryVerifier": b64(R2),
            "wrappedDEKRecovery": b64(WR2),
            "recIv": b64(RIV2),
        })
        check("recovery commit succeeds", resp.status == 200
              and resp.obj.get("uid") == uid and resp.obj.get("name") == "tester",
              resp.raw[:200])
        check("recovery commit rotates auth salt",
              read_auth_salt(db_path) != salt_before_rec, "")
        check("recovery commit revokes all sessions",
              S2.req("GET", "/api/me").status == 401
              and S4.req("GET", "/api/me").status == 401, "")
        resp = anon.req("POST", "/api/recover/commit", {
            "ticket": ticket,
            "newAuthHash": b64(H3),
            "wrappedDEK": b64(PW3),
            "dekIv": b64(IV3),
            "newRecoveryVerifier": b64(R2),
            "wrappedDEKRecovery": b64(WR2),
            "recIv": b64(RIV2),
        })
        check("recovery ticket is one-shot", resp.status == 403, resp.raw[:200])

        S5 = Session(api)
        resp = S5.req("POST", "/api/login", login_body("tester", H2))
        check("pre-recovery password is dead", resp.status == 401, resp.raw[:200])
        resp = S5.req("POST", "/api/login", login_body("tester", H3))
        check("recovered account logs in", resp.status == 200
              and resp.obj.get("wrappedDEK") == b64(PW3), resp.raw[:200])

        resp = anon.req("POST", "/api/recover/verify",
                        {"name": "tester", "verifier": b64(R1)})
        check("old recovery code is dead", resp.status == 403, resp.raw[:200])
        resp = anon.req("POST", "/api/recover/verify",
                        {"name": "tester", "verifier": b64(R2)})
        check("new recovery code verifies", resp.status == 200, resp.raw[:200])

        resp = S5.req("POST", "/api/recovery/rotate", {
            "authHash": b64(H2),
            "recoveryVerifier": b64(R3),
            "wrappedDEKRecovery": b64(WR3),
            "recIv": b64(RIV3),
        })
        check("recovery rotate rejects wrong password", resp.status == 401,
              resp.raw[:200])
        resp = S5.req("POST", "/api/recovery/rotate", {
            "authHash": b64(H3),
            "recoveryVerifier": b64(R3),
            "wrappedDEKRecovery": b64(WR3),
            "recIv": b64(RIV3),
        })
        check("recovery rotate succeeds", resp.status == 200, resp.raw[:200])
        resp = anon.req("POST", "/api/recover/verify",
                        {"name": "tester", "verifier": b64(R2)})
        check("rotated-out recovery code is dead", resp.status == 403,
              resp.raw[:200])
        resp = anon.req("POST", "/api/recover/verify",
                        {"name": "tester", "verifier": b64(R3)})
        check("rotated-in recovery code verifies", resp.status == 200, resp.raw[:200])

        # ---------- export ----------
        resp = S5.req("GET", "/api/export")
        exported = resp.obj or {}
        text = json.dumps(exported)
        account = exported.get("account", {})
        check("export 200", resp.status == 200 and exported.get("app") == "2brain",
              resp.raw[:200])
        check("export has current wrapping",
              account.get("wrappedDEK") == b64(PW3)
              and account.get("dekIv") == b64(IV3)
              and account.get("wrappedDEKRecovery") == b64(WR3)
              and account.get("recIv") == b64(RIV3),
              str(account))
        check("export has no auth material",
              "authHash" not in text and "authVerifier" not in text
              and "recoveryVerifier" not in text and "password" not in text,
              text[:300])
        check("export has brain blob", exported.get("brain", {}).get("rev") == 4
              and exported["brain"].get("blob") == D,
              str(exported.get("brain", {}).get("rev")))

        # ---------- logout ----------
        resp = S5.req("POST", "/api/logout", {},
                      headers={"Origin": "https://evil.example"})
        check("logout rejects cross origin", resp.status == 403, resp.raw[:200])
        S6 = Session(api)
        S6.req("POST", "/api/login", login_body("tester", H3))
        resp = S6.req("POST", "/api/logout", {})
        check("logout clears cookie", resp.status == 200
              and "Max-Age=0" in resp.headers.get("set-cookie", ""),
              resp.headers.get("set-cookie", ""))
        check("logout kills session", S6.req("GET", "/api/me").status == 401, "")

        S7 = Session(api)
        S8 = Session(api)
        S7.req("POST", "/api/login", login_body("tester", H3))
        S8.req("POST", "/api/login", login_body("tester", H3))
        resp = S7.req("POST", "/api/logout_all", {})
        check("logout_all succeeds", resp.status == 200, resp.raw[:200])
        check("logout_all kills all sessions",
              S7.req("GET", "/api/me").status == 401
              and S8.req("GET", "/api/me").status == 401, "")

        S9 = Session(api)
        resp = S9.req("POST", "/api/login", login_body("tester", H3))
        check("login after logout_all", resp.status == 200, resp.raw[:200])
        admin_sid = S9.cookie

        proc = run_admin("--db", db_path, "list-users")
        check("admin lists user", proc.returncode == 0
              and "tester" in proc.stdout and "600000" in proc.stdout,
              proc.stdout + proc.stderr)
        proc = run_admin("--db", db_path, "revoke-device", "--id", rw_id)
        check("admin revokes device", proc.returncode == 0
              and rw_id in proc.stdout, proc.stderr.strip())
        resp = S9.req("GET", "/api/brain", token=rw_token)
        check("admin-revoked device is 401", resp.status == 401, resp.raw[:200])

        # ---------- database contents ----------
        conn = sqlite3.connect(db_path, timeout=5)
        conn.row_factory = sqlite3.Row
        try:
            cols = [r["name"] for r in conn.execute("PRAGMA table_info(users)")]
            row = conn.execute("SELECT * FROM users WHERE name='tester'").fetchone()
            schema = conn.execute(
                "SELECT value FROM meta WHERE key='schema_version'").fetchone()[0]
            check("db schema version", schema == "5", schema)
            check("db has no password-like column",
                  not any(c in cols for c in ("password", "auth_hash", "recovery_code")),
                  str(cols))
            check("db stores kdf salt", bytes(row["kdf_salt"]) == KDF_SALT, "")
            check("db stores server verifier, not authHash",
                  bytes(row["auth_verifier"]) != H3
                  and len(bytes(row["auth_verifier"])) == 32, "")
            check("db stores current wrapped DEK",
                  bytes(row["wrapped_dek"]) == PW3
                  and bytes(row["dek_iv"]) == IV3, "")
            check("db stores recovery verifier", bytes(row["recovery_verifier"]) == R3,
                  "")
            sess = conn.execute("SELECT COUNT(*) FROM sessions WHERE token_hash=?",
                                (sha_hex((admin_sid or "").encode("utf-8")),)).fetchone()[0]
            raw_sess = conn.execute("SELECT COUNT(*) FROM sessions WHERE token_hash=?",
                                    (admin_sid or "",)).fetchone()[0]
            check("db stores hashed session token", sess == 1 and raw_sess == 0,
                  f"{sess}/{raw_sess}")
            revs = conn.execute("SELECT COUNT(*) FROM revisions").fetchone()[0]
            check("db has revision history", revs >= 3, str(revs))
            audit_count = conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
            actions = {r["action"] for r in conn.execute("SELECT action FROM audit")}
            check("db audit trail",
                  audit_count >= 15 and {"setup", "login", "password",
                                         "recover_commit", "brain_put"}
                  <= actions, str(sorted(actions)))
            invites = conn.execute(
                "SELECT COUNT(*) FROM invites WHERE name='alice'").fetchone()[0]
            check("unused invite survives", invites == 1, str(invites))
        finally:
            conn.close()

        raw_db = b"".join(
            p.read_bytes() for p in Path(db_path).parent.glob("test.db*")
            if p.is_file())
        canaries = {
            "recovery code": RECOVERY_CODE.encode("ascii"),
            "recovery code base64": b64(RECOVERY_CODE.encode("ascii")).encode("ascii"),
            "authHash 1": H1,
            "authHash 2": H2,
            "authHash 3": H3,
            "authHash base64": b64(H1).encode("ascii"),
            "note plaintext": b"CANARY-NOTE-TEXT",
        }
        leaked = [name for name, value in canaries.items() if value in raw_db]
        check("db/wal contain no secret canaries", not leaked,
              "leaked: " + ", ".join(leaked))

        # ---------- restart persistence ----------
        server.stop()
        check("server stops", True)
        server = Server(db_path, log_path)
        if not server.wait_ready():
            print(Path(log_path).read_text(errors="replace")[-4000:])
            check("server restarts", False, "health never became ready")
            return 1
        check("server restarts", True)
        api2 = server.api

        # reattach the cookie from S9 (host-scoped, but port changed)
        S10 = Session(api2)
        S10.cookie = admin_sid
        resp = S10.req("GET", "/api/me")
        check("session persists across restart", resp.status == 200
              and resp.obj.get("name") == "tester", resp.raw[:200])
        resp = S10.req("GET", "/api/brain")
        check("brain persists across restart", resp.status == 200
              and resp.obj.get("rev") == 4 and resp.obj.get("blob") == D,
              resp.raw[:200])
        resp = S10.req("GET", "/api/brain/revisions")
        revs = sorted(r["rev"] for r in resp.obj.get("revisions", []))
        check("revisions persist across restart", revs == [1, 2, 3], str(revs))
        resp = Session(api2).req("POST", "/api/login", login_body("tester", H3))
        check("login works after restart", resp.status == 200, resp.raw[:200])
        resp = Session(api2).req("POST", "/api/kdf", {"name": "tester"})
        check("kdf salt persists", resp.obj.get("salt") == b64(KDF_SALT),
              str(resp.obj))
        resp = Session(api2).req("GET", "/api/brain", token=survivor_token)
        check("device survives restart", resp.status == 200, resp.raw[:200])
        resp = Session(api2).req("GET", "/api/brain", token=read_token)
        check("revoked device stays revoked", resp.status == 401, resp.raw[:200])

        # ---------- permanent archive / sync reset ----------
        resp = S10.req("GET", "/api/brain")
        pret = resp.obj or {}
        pre_rev = int(pret.get("rev") or 0)
        pre_etag = pret.get("etag")
        check("pre-reset epoch fields", pret.get("epoch") == 0
              and pret.get("resetAt") is None
              and pret.get("resetArchive") is None, str(pret))
        check("pre-reset brain state", pre_rev == 4 and pre_etag == E4
              and pret.get("blob") == D, str(pret))
        resp = S10.req("GET", "/api/health")
        check("health reports archive ready", resp.obj.get("archive") is True,
              str(resp.obj))
        resp = S10.req("POST", "/api/brain/archive", {}, token=rw_token)
        check("device cannot archive", resp.status == 401, resp.raw[:200])

        resp = S10.req("POST", "/api/brain/archive", {})
        check("archive succeeds", resp.status == 200
              and str(resp.obj.get("archive", "")).startswith("pre-reset-")
              and resp.obj.get("rev") == pre_rev
              and resp.obj.get("etag") == pre_etag
              and resp.obj.get("epoch") == 0
              and resp.obj.get("udisk") is True, resp.raw[:200])
        archive_name = resp.obj.get("archive", "")
        arch_dir = archive_root / "permanent" / archive_name
        udisk_copy = udisk_dir / "archive-permanent" / archive_name
        check("archive files exist",
              (arch_dir / "2brain.db").is_file()
              and (arch_dir / "manifest.json").is_file()
              and (arch_dir / "SHA256SUMS").is_file()
              and (arch_dir / "NOTICE.txt").is_file(), str(arch_dir))
        arch_db = (arch_dir / "2brain.db").read_bytes()
        manifest = json.loads((arch_dir / "manifest.json").read_text("utf-8"))
        sums = (arch_dir / "SHA256SUMS").read_text("ascii")
        check("archive manifest matches snapshot",
              manifest.get("kind") == "pre-reset"
              and manifest.get("uid") == uid
              and manifest.get("brain", {}).get("rev") == pre_rev
              and manifest.get("brain", {}).get("etag") == pre_etag
              and manifest.get("brain", {}).get("epoch") == 0
              and manifest.get("db", {}).get("sha256") == sha_hex(arch_db),
              str(manifest)[:400])
        check("archive SHA256SUMS matches", sums.split()[0] == sha_hex(arch_db),
              sums[:100])
        check("archive copied to U disk",
              (udisk_copy / "2brain.db").read_bytes() == arch_db
              and (udisk_copy / "manifest.json").read_bytes()
              == (arch_dir / "manifest.json").read_bytes(), str(udisk_copy))
        check("archive carries no secret canaries",
              not [n for n, v in canaries.items() if v in arch_db], "")

        reset_body = {
            "confirm": "同步重置",
            "archive": archive_name,
            "authHash": b64(H3),
            "expectRev": pre_rev,
            "expectEtag": pre_etag,
            "expectEpoch": 0,
        }
        resp = S10.req("POST", "/api/brain/reset",
                       {**reset_body, "confirm": "reset"})
        check("reset requires the exact phrase", resp.status == 400
              and resp.obj["error"]["code"] == "confirm_required",
              resp.raw[:200])
        resp = S10.req("POST", "/api/brain/reset",
                       {**reset_body, "authHash": b64(H2)})
        check("reset rejects a wrong password", resp.status == 401
              and resp.obj["error"]["code"] == "bad_credentials",
              resp.raw[:200])
        resp = S10.req("POST", "/api/brain/reset",
                       {**reset_body, "expectRev": pre_rev - 1})
        check("reset rejects stale expectations", resp.status == 409
              and resp.obj["error"]["code"] == "stale_archive",
              resp.raw[:200])
        resp = S10.req("POST", "/api/brain/reset",
                       {**reset_body, "archive": "../evil"})
        check("reset rejects a bad archive name", resp.status == 409
              and resp.obj["error"]["code"] == "archive_invalid",
              resp.raw[:200])
        resp = S10.req("POST", "/api/brain/reset", reset_body, token=rw_token)
        check("device cannot reset", resp.status == 401, resp.raw[:200])

        resp = S10.req("POST", "/api/brain/reset", reset_body)
        check("reset succeeds", resp.status == 200
              and resp.obj.get("rev") == pre_rev + 1
              and resp.obj.get("epoch") == 1
              and resp.obj.get("archive") == archive_name
              and resp.obj.get("resetAt"), resp.raw[:200])
        resp = S10.req("GET", "/api/brain")
        reset_obj = resp.obj or {}
        check("reset leaves empty brain at next rev",
              reset_obj.get("rev") == pre_rev + 1
              and reset_obj.get("etag") is None
              and reset_obj.get("blob") is None
              and reset_obj.get("epoch") == 1
              and reset_obj.get("resetArchive") == archive_name
              and reset_obj.get("resetAt"), str(reset_obj))
        resp = S10.req("GET", "/api/brain/revisions")
        check("reset clears revisions",
              resp.obj.get("revisions") == [], resp.raw[:200])
        resp = S10.req("POST", "/api/brain/restore", {"rev": 1})
        check("reset makes old revisions unrestorable", resp.status == 404,
              resp.raw[:200])
        resp = S10.req("GET", "/api/export")
        check("export exposes reset marker",
              resp.obj["brain"].get("epoch") == 1
              and resp.obj["brain"].get("resetArchive") == archive_name,
              str(resp.obj.get("brain"))[:300])
        resp = S10.req("POST", "/api/brain/archive", {})
        check("archive refuses an empty brain", resp.status == 409
              and resp.obj["error"]["code"] == "nothing_to_archive",
              resp.raw[:200])

        F = blob_for("F")
        EF = etag_for(F)
        resp = S10.req("PUT", "/api/brain", F,
                       headers={"If-None-Match": "*"})
        check("old client PUT is blocked after reset", resp.status == 409
              and resp.obj["error"]["code"] == "epoch_mismatch"
              and resp.obj.get("epoch") == 1, resp.raw[:200])
        resp = S10.req("PUT", "/api/brain", F,
                       headers={"If-None-Match": "*",
                                "X-2brain-Epoch": "0"})
        check("stale epoch PUT is blocked", resp.status == 409
              and resp.obj["error"]["code"] == "epoch_mismatch",
              resp.raw[:200])
        resp = S10.req("PUT", "/api/brain", F,
                       headers={"If-None-Match": "*",
                                "X-2brain-Epoch": "1"})
        check("post-reset PUT with epoch", resp.status == 200
              and resp.obj.get("rev") == pre_rev + 2
              and resp.obj.get("etag") == EF
              and resp.obj.get("epoch") == 1, resp.raw[:200])
        resp = S10.req("PUT", "/api/brain", D,
                       headers={"If-Match": f'"{EF}"',
                                "X-2brain-Epoch": "1"})
        check("epoch survives normal writes", resp.status == 200
              and resp.obj.get("epoch") == 1
              and resp.obj.get("rev") == pre_rev + 3, resp.raw[:200])

        # fail closed when the U disk is not mounted
        server.stop()
        server = Server(db_path, log_path,
                        udisk_dir=str(tmp / "no-such-udisk"))
        if not server.wait_ready():
            check("server starts without U disk", False, "health never ready")
            return 1
        S12 = Session(server.api)
        S12.cookie = admin_sid
        resp = S12.req("GET", "/api/health")
        check("health reports archive off without U disk",
              resp.obj.get("archive") is False, str(resp.obj))
        resp = S12.req("POST", "/api/brain/archive", {})
        check("archive fails closed without U disk", resp.status == 503
              and resp.obj["error"]["code"] == "archive_not_configured",
              resp.raw[:200])

        # ---------- schema 3: per-account extra vaults ----------
        resp = Session(server.api).req("GET", "/api/vaults")
        check("vault list requires login", resp.status == 401, resp.raw[:200])
        resp = S12.req("GET", "/api/vaults")
        vaults = resp.obj.get("vaults") if isinstance(resp.obj, dict) else None
        check("vault list starts with the main vault",
              resp.status == 200 and isinstance(vaults, list)
              and len(vaults) == 1 and vaults[0]["vid"] == "main"
              and vaults[0]["main"] is True
              and resp.obj.get("max") == 20, resp.raw[:300])
        main_before = S12.req("GET", "/api/brain").obj or {}
        resp = S12.req("POST", "/api/vaults", {"vid": "work", "name": "工作"})
        check("vault create", resp.status == 200
              and resp.obj.get("vid") == "work"
              and resp.obj.get("rev") == 0, resp.raw[:200])
        resp = S12.req("POST", "/api/vaults", {"vid": "work"})
        check("vault create rejects duplicates", resp.status == 409,
              resp.raw[:200])
        resp = S12.req("POST", "/api/vaults", {"vid": "main"})
        check("vault create rejects main", resp.status == 409, resp.raw[:200])
        resp = S12.req("POST", "/api/vaults", {"vid": "BAD ID"})
        check("vault create rejects a bad id", resp.status == 400,
              resp.raw[:200])
        resp = S12.req("GET", "/api/vaults")
        check("vault list shows the extra vault",
              [v["vid"] for v in resp.obj["vaults"]] == ["main", "work"],
              resp.raw[:300])
        resp = S12.req("GET", "/api/v/work/brain")
        check("empty extra vault", resp.status == 200
              and resp.obj.get("rev") == 0
              and resp.obj.get("blob") is None, resp.raw[:200])
        resp = S12.req("GET", "/api/v/WORK/brain")
        check("vault id is case-insensitive", resp.status == 200,
              resp.raw[:200])
        V1 = blob_for("vault-1")
        EV1 = etag_for(V1)
        resp = S12.req("PUT", "/api/v/work/brain", V1,
                       headers={"If-None-Match": "*"})
        check("extra vault accepts the first write", resp.status == 200
              and resp.obj.get("rev") == 1
              and resp.obj.get("etag") == EV1, resp.raw[:200])
        resp = S12.req("GET", "/api/brain")
        check("main vault is untouched by extra vault writes",
              resp.obj.get("rev") == main_before.get("rev")
              and resp.obj.get("etag") == main_before.get("etag"),
              resp.raw[:300])
        resp = S12.req("GET", "/api/v/work/brain")
        check("extra vault returns its own blob",
              resp.obj.get("rev") == 1 and resp.obj.get("blob") == V1,
              resp.raw[:300])
        resp = S12.req("GET", "/api/v/work/brain",
                       headers={"If-None-Match": f'"{EV1}"'})
        check("extra vault honours etag", resp.status == 304, resp.raw[:200])
        resp = S12.req("PUT", "/api/v/work/brain", blob_for("vault-2"))
        check("extra vault requires If-Match", resp.status == 412
              and resp.obj["error"]["code"] == "conflict", resp.raw[:200])
        resp = S12.req("PUT", "/api/v/nope/brain", blob_for("nope"),
                       headers={"If-None-Match": "*"})
        check("unknown vault rejects writes", resp.status == 404,
              resp.raw[:200])
        resp = S12.req("GET", "/api/v/nope/brain")
        check("unknown vault rejects reads", resp.status == 404,
              resp.raw[:200])
        resp = S12.req("DELETE", "/api/vaults/main")
        check("main vault cannot be deleted", resp.status == 403
              and resp.obj["error"]["code"] == "main_vault", resp.raw[:200])
        resp = S12.req("DELETE", "/api/vaults/nope")
        check("deleting an unknown vault is 404", resp.status == 404,
              resp.raw[:200])
        resp = S12.req("DELETE", "/api/vaults/work")
        check("vault delete", resp.status == 200
              and resp.obj.get("ok") is True, resp.raw[:200])
        resp = S12.req("GET", "/api/v/work/brain")
        check("deleted vault is gone", resp.status == 404, resp.raw[:200])
        for i in range(20):
            S12.req("POST", "/api/vaults", {"vid": f"v{i}"})
        resp = S12.req("GET", "/api/vaults")
        check("vault limit allows twenty extras",
              len(resp.obj.get("vaults") or []) == 21, resp.raw[:200])
        resp = S12.req("POST", "/api/vaults", {"vid": "overflow"})
        check("vault limit rejects the twenty-first", resp.status == 429
              and resp.obj["error"]["code"] == "too_many_vaults",
              resp.raw[:200])

        # ---------- schema 4: shared vaults (ECDH keys + roles + rotation) ----------
        resp = Session(server.api).req("GET", "/api/shared")
        check("shared list requires login", resp.status == 401,
              resp.raw[:200])
        resp = S12.req("GET", "/api/keys")
        check("account key is empty before registration",
              resp.status == 200 and resp.obj.get("pubJwk") is None,
              resp.raw[:200])
        resp = S12.req("PUT", "/api/keys", {"pubJwk": "not json"})
        check("account key rejects garbage", resp.status == 400
              and resp.obj["error"]["code"] == "bad_pubkey", resp.raw[:200])
        owner_pub = pub_jwk("owner")
        resp = S12.req("PUT", "/api/keys", {"pubJwk": owner_pub})
        check("account key registered", resp.status == 200
              and resp.obj.get("pubJwk") == owner_pub, resp.raw[:200])
        resp = S12.req("GET", "/api/keys")
        check("account key read back",
              resp.obj.get("pubJwk") == owner_pub, resp.raw[:200])

        owner_wrap = wrapped_key("owner-1")
        resp = S12.req("POST", "/api/shared",
                       {"name": "家庭", "wrapped": owner_wrap})
        gid = resp.obj.get("gid") if isinstance(resp.obj, dict) else ""
        check("shared vault create", resp.status == 200
              and bool(re.fullmatch(r"s[0-9a-f]{16}", gid or ""))
              and resp.obj.get("keyEpoch") == 1
              and resp.obj.get("name") == "家庭", resp.raw[:200])
        check("shared vault rejects a missing wrap",
              S12.req("POST", "/api/shared", {"name": "x"}).status == 400, "")
        resp = S12.req("GET", "/api/shared")
        mine = resp.obj.get("vaults") if isinstance(resp.obj, dict) else []
        check("shared list shows the owned vault",
              resp.status == 200 and len(mine) == 1
              and mine[0]["gid"] == gid and mine[0]["role"] == "owner"
              and mine[0]["ownerName"] == "tester"
              and mine[0]["members"] == 1, resp.raw[:300])
        resp = S12.req("GET", "/api/shared/" + gid)
        check("shared meta lists the owner",
              resp.status == 200 and resp.obj.get("role") == "owner"
              and [m["role"] for m in resp.obj.get("members", [])] == ["owner"],
              resp.raw[:300])
        resp = Session(server.api).req("GET", "/api/shared/" + gid)
        check("shared meta requires login", resp.status == 401,
              resp.raw[:200])

        alice_invite2 = invite_from_admin(db_path, "alice")
        S13 = Session(server.api)
        resp = S13.req("POST", "/api/setup",
                       setup_body("alice", alice_invite2, H2,
                                  material("kdfsa", 16)))
        check("alice account created", resp.status == 200, resp.raw[:200])
        alice_uid = resp.obj.get("uid")
        resp = S13.req("GET", "/api/shared")
        check("alice has no shared vaults yet",
              resp.status == 200 and resp.obj.get("vaults") == [],
              resp.raw[:200])
        resp = S12.req("POST", "/api/shared/" + gid + "/invite",
                       {"name": "alice", "role": "writer"})
        check("invite needs the target public key", resp.status == 409
              and resp.obj["error"]["code"] == "no_pubkey", resp.raw[:200])
        alice_pub = pub_jwk("alice")
        S13.req("PUT", "/api/keys", {"pubJwk": alice_pub})
        resp = S12.req("POST", "/api/shared/" + gid + "/invite",
                       {"name": "alice", "role": "writer"})
        check("invite returns the target public key",
              resp.status == 200 and resp.obj.get("uid") == alice_uid
              and resp.obj.get("pubJwk") == alice_pub
              and resp.obj.get("role") == "writer", resp.raw[:200])
        resp = S13.req("GET", "/api/shared")
        check("invite alone does not add a member",
              resp.obj.get("vaults") == [], resp.raw[:200])
        alice_wrap = wrapped_key("alice-1")
        resp = S12.req("PUT", f"/api/shared/{gid}/members/{alice_uid}",
                       {"role": "writer", "wrapped": alice_wrap,
                        "keyEpoch": 1})
        check("owner stores the wrapped key", resp.status == 200
              and resp.obj.get("role") == "writer", resp.raw[:200])
        resp = S13.req("GET", "/api/shared")
        got = (resp.obj.get("vaults") or [{}])[0]
        check("alice sees the shared vault",
              len(resp.obj.get("vaults") or []) == 1
              and got.get("gid") == gid and got.get("role") == "writer"
              and got.get("keyEpoch") == 1
              and wrapped_equals(got.get("wrapped"), alice_wrap),
              resp.raw[:300])
        resp = S13.req("GET", f"/api/s/{gid}/brain")
        check("empty shared vault",
              resp.status == 200 and resp.obj.get("rev") == 0
              and resp.obj.get("blob") is None
              and resp.obj.get("keyEpoch") == 1
              and resp.obj.get("role") == "writer", resp.raw[:300])

        A1 = blob_for("shared-1")
        EA1 = etag_for(A1)
        resp = S13.req("PUT", f"/api/s/{gid}/brain", A1,
                       headers={"If-None-Match": "*",
                                "X-2brain-KeyEpoch": "1"})
        check("writer can push to the shared vault", resp.status == 200
              and resp.obj.get("rev") == 1
              and resp.obj.get("etag") == EA1
              and resp.obj.get("keyEpoch") == 1, resp.raw[:200])
        resp = S12.req("GET", f"/api/s/{gid}/brain")
        check("owner sees the writer blob",
              resp.obj.get("blob") == A1 and resp.obj.get("rev") == 1,
              resp.raw[:200])
        resp = S13.req("PUT", f"/api/s/{gid}/brain", blob_for("shared-2"),
                       headers={"If-None-Match": "*",
                                "X-2brain-KeyEpoch": "1"})
        check("shared push requires If-Match", resp.status == 412,
              resp.raw[:200])
        resp = S13.req("PUT", f"/api/s/{gid}/brain", blob_for("shared-2"),
                       headers={"If-Match": f'"{EA1}"'})
        check("shared push requires the key epoch", resp.status == 409
              and resp.obj["error"]["code"] == "epoch_mismatch",
              resp.raw[:200])

        bob_invite = invite_from_admin(db_path, "bob")
        S14 = Session(server.api)
        resp = S14.req("POST", "/api/setup",
                       setup_body("bob", bob_invite, H3,
                                  material("kdfsb", 16)))
        check("bob account created", resp.status == 200, resp.raw[:200])
        bob_uid = resp.obj.get("uid")
        resp = S14.req("GET", f"/api/s/{gid}/brain")
        check("outsiders get a 404 on shared reads", resp.status == 404,
              resp.raw[:200])
        resp = S14.req("GET", "/api/shared/" + gid)
        check("shared meta hides itself from outsiders", resp.status == 404,
              resp.raw[:200])
        S14.req("PUT", "/api/keys", {"pubJwk": pub_jwk("bob")})
        resp = S12.req("POST", f"/api/shared/{gid}/invite",
                       {"name": "bob", "role": "reader"})
        bob_uid = resp.obj.get("uid") or bob_uid
        bob_wrap = wrapped_key("bob-1")
        resp = S12.req("PUT", f"/api/shared/{gid}/members/{bob_uid}",
                       {"role": "reader", "wrapped": bob_wrap})
        check("owner adds a reader", resp.status == 200
              and resp.obj.get("role") == "reader", resp.raw[:200])
        resp = S14.req("GET", f"/api/s/{gid}/brain")
        check("reader can read and decrypt", resp.status == 200
              and resp.obj.get("blob") == A1
              and resp.obj.get("role") == "reader", resp.raw[:200])
        resp = S14.req("PUT", f"/api/s/{gid}/brain", blob_for("bob-write"),
                       headers={"If-Match": f'"{EA1}"',
                                "X-2brain-KeyEpoch": "1"})
        check("reader cannot write even holding the DEK", resp.status == 403
              and resp.obj["error"]["code"] == "read_only", resp.raw[:200])
        resp = S14.req("POST", f"/api/shared/{gid}/rotate",
                       {"keyEpoch": 2, "members": [], "remove": [],
                        "blob": blob_for("nope")})
        check("non-owner cannot rotate", resp.status == 403, resp.raw[:200])
        resp = S14.req("PUT", f"/api/shared/{gid}/members/{bob_uid}",
                       {"role": "writer", "wrapped": bob_wrap})
        check("non-owner cannot change roles", resp.status == 403,
              resp.raw[:200])

        resp = S12.req("PUT", f"/api/shared/{gid}/members/{alice_uid}",
                       {"role": "reader", "wrapped": alice_wrap})
        check("demoting to reader keeps the key epoch",
              resp.status == 200 and resp.obj.get("keyEpoch") == 1,
              resp.raw[:200])
        resp = S13.req("PUT", f"/api/s/{gid}/brain", blob_for("demoted"),
                       headers={"If-Match": f'"{EA1}"',
                                "X-2brain-KeyEpoch": "1"})
        check("demoted member is rejected by the server", resp.status == 403,
              resp.raw[:200])
        resp = S12.req("PUT", f"/api/shared/{gid}/members/{alice_uid}",
                       {"role": "writer", "wrapped": alice_wrap})
        check("restoring writer needs no re-encryption",
              resp.status == 200 and resp.obj.get("keyEpoch") == 1,
              resp.raw[:200])
        A2 = blob_for("shared-2")
        EA2 = etag_for(A2)
        resp = S13.req("PUT", f"/api/s/{gid}/brain", A2,
                       headers={"If-Match": f'"{EA1}"',
                                "X-2brain-KeyEpoch": "1"})
        check("restored writer can push", resp.status == 200
              and resp.obj.get("rev") == 2
              and resp.obj.get("etag") == EA2, resp.raw[:200])

        # ---------- schema 5: 共享笔记编辑租约 ----------
        DEV_O, DEV_A, DEV_B = "dev-owner-1", "dev-alice-1", "dev-bob-1"
        LK1 = f"/api/s/{gid}/locks/n-lock-1"
        resp = S12.req("POST", LK1, headers={"X-2brain-Device": DEV_O})
        check("a writer acquires the edit lock", resp.status == 200
              and resp.obj.get("held") is True
              and resp.obj.get("ttl") == 120, resp.raw[:200])
        resp = S13.req("POST", LK1, headers={"X-2brain-Device": DEV_A})
        check("a second member is refused with 409 locked", resp.status == 409
              and resp.obj["error"]["code"] == "locked"
              and resp.obj.get("holder") == "tester"
              and int(resp.obj.get("expiresIn") or 0) > 100, resp.raw[:200])
        resp = S12.req("POST", LK1, headers={"X-2brain-Device": DEV_O})
        check("the holder renews by acquiring again", resp.status == 200
              and resp.obj.get("held") is True, resp.raw[:200])
        resp = S14.req("POST", LK1, headers={"X-2brain-Device": DEV_B})
        check("a reader cannot take an edit lock", resp.status == 403
              and resp.obj["error"]["code"] == "read_only", resp.raw[:200])
        insert_note_lock(db_path, gid, "n-dead-1", uid, -60)
        insert_note_lock(db_path, gid, "n-dead-2", alice_uid, -1)
        resp = S13.req("GET", f"/api/s/{gid}/locks")
        check("the lock list hides expired leases", resp.status == 200
              and [x["noteId"] for x in resp.obj.get("locks") or []]
              == ["n-lock-1"]
              and resp.obj["locks"][0]["holder"] == "tester", resp.raw[:300])
        check("listing prunes the expired rows",
              count_note_locks(db_path, gid) == 1, "")
        insert_note_lock(db_path, gid, "n-lock-1", uid, -5)
        resp = S13.req("POST", LK1, headers={"X-2brain-Device": DEV_A})
        check("an expired lease can be taken over", resp.status == 200
              and resp.obj.get("uid") == alice_uid, resp.raw[:200])
        resp = S13.req("DELETE", LK1, headers={"X-2brain-Device": DEV_O})
        check("releasing someone else's lease is refused", resp.status == 409
              and resp.obj["error"]["code"] == "not_holder", resp.raw[:200])
        resp = S13.req("DELETE", LK1, headers={"X-2brain-Device": DEV_A})
        check("the holder releases the lock", resp.status == 200
              and resp.obj.get("released") is True
              and count_note_locks(db_path, gid) == 0, resp.raw[:200])

        resp = S12.req("DELETE", f"/api/shared/{gid}/members/{bob_uid}")
        check("removal requires rotation first", resp.status == 409
              and resp.obj["error"]["code"] == "rotate_required",
              resp.raw[:200])
        resp = S12.req("POST", f"/api/shared/{gid}/rotate",
                       {"keyEpoch": 3,
                        "members": [{"uid": uid,
                                     "wrapped": wrapped_key("owner-2")}],
                        "remove": [bob_uid], "blob": blob_for("rot-2")},
                       headers={"If-Match": f'"{EA2}"'})
        check("rotation rejects a skipped epoch", resp.status == 409,
              resp.raw[:200])
        resp = S12.req("POST", f"/api/shared/{gid}/rotate",
                       {"keyEpoch": 2,
                        "members": [{"uid": uid,
                                     "wrapped": wrapped_key("owner-2")}],
                        "remove": [bob_uid], "blob": blob_for("rot-1")},
                       headers={"If-Match": f'"{EA2}"'})
        check("rotation needs a wrap for every remaining member",
              resp.status == 400
              and resp.obj["error"]["code"] == "wraps_incomplete",
              resp.raw[:200])
        ROT = blob_for("shared-rot")
        EROT = etag_for(ROT)
        owner_wrap2 = wrapped_key("owner-2")
        alice_wrap2 = wrapped_key("alice-2")
        resp = S12.req("POST", f"/api/shared/{gid}/rotate",
                       {"keyEpoch": 2,
                        "members": [
                            {"uid": uid, "wrapped": owner_wrap2},
                            {"uid": alice_uid, "wrapped": alice_wrap2}],
                        "remove": [bob_uid], "blob": ROT},
                       headers={"If-Match": f'"{EA2}"'})
        check("owner rotates the shared key atomically",
              resp.status == 200 and resp.obj.get("rev") == 3
              and resp.obj.get("etag") == EROT
              and resp.obj.get("keyEpoch") == 2, resp.raw[:200])
        resp = S14.req("GET", f"/api/s/{gid}/brain")
        check("removed member loses access", resp.status == 404,
              resp.raw[:200])
        resp = S13.req("GET", f"/api/s/{gid}/brain")
        check("remaining member gets the new epoch and wrap",
              resp.status == 200 and resp.obj.get("keyEpoch") == 2
              and resp.obj.get("blob") == ROT
              and wrapped_equals(resp.obj.get("wrapped"), alice_wrap2),
              resp.raw[:300])
        resp = S13.req("PUT", f"/api/s/{gid}/brain", blob_for("old-epoch"),
                       headers={"If-Match": f'"{EROT}"',
                                "X-2brain-KeyEpoch": "1"})
        check("old epoch writes are refused after rotation",
              resp.status == 409
              and resp.obj["error"]["code"] == "epoch_mismatch",
              resp.raw[:200])
        A3 = blob_for("shared-3")
        resp = S13.req("PUT", f"/api/s/{gid}/brain", A3,
                       headers={"If-Match": f'"{EROT}"',
                                "X-2brain-KeyEpoch": "2"})
        check("writer continues on the new epoch", resp.status == 200
              and resp.obj.get("rev") == 4
              and resp.obj.get("keyEpoch") == 2, resp.raw[:200])
        resp = S13.req("PUT", "/api/keys", {"pubJwk": pub_jwk("alice-new")})
        check("a key in use cannot be replaced", resp.status == 409
              and resp.obj["error"]["code"] == "key_in_use", resp.raw[:200])
        resp = S12.req("POST", f"/api/shared/{gid}/transfer",
                       {"name": "alice"})
        check("ownership transfer", resp.status == 200
              and resp.obj.get("ownerUid") == alice_uid, resp.raw[:200])
        resp = S12.req("POST", f"/api/shared/{gid}/rotate",
                       {"keyEpoch": 3, "members": [], "remove": [],
                        "blob": blob_for("x")})
        check("former owner loses owner powers", resp.status == 403,
              resp.raw[:200])
        resp = S13.req("GET", "/api/shared")
        check("new owner is reflected in the list",
              (resp.obj.get("vaults") or [{}])[0].get("role") == "owner",
              resp.raw[:200])
        resp = S13.req("DELETE", "/api/shared/" + gid)
        check("owner deletes the shared vault", resp.status == 200,
              resp.raw[:200])
        resp = S12.req("GET", f"/api/s/{gid}/brain")
        check("deleted shared vault is gone", resp.status == 404,
              resp.raw[:200])

        # schema 1 -> 2 migration on an existing database
        server.stop()
        mig_db = str(tmp / "migrate-v1.db")
        conn = sqlite3.connect(mig_db)
        try:
            conn.executescript(
                "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
                "INSERT INTO meta VALUES('schema_version','1');"
                "CREATE TABLE brains ("
                " uid INTEGER PRIMARY KEY, rev INTEGER NOT NULL DEFAULT 0,"
                " etag TEXT, blob BLOB,"
                " size INTEGER NOT NULL DEFAULT 0, updated_at TEXT);"
            )
            conn.commit()
        finally:
            conn.close()
        server = Server(mig_db, str(tmp / "migrate.log"))
        if not server.wait_ready():
            check("v1 database starts after migration", False,
                  "health never ready")
            return 1
        resp = Session(server.api).req("GET", "/api/health")
        check("v1 database migrates to schema 5",
              resp.status == 200 and resp.obj.get("schema") == 5,
              str(resp.obj))
        conn = sqlite3.connect(mig_db)
        try:
            ver = conn.execute(
                "SELECT value FROM meta WHERE key='schema_version'"
            ).fetchone()[0]
            cols = {r[1] for r in conn.execute("PRAGMA table_info(brains)")}
            tables = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        finally:
            conn.close()
        check("migration adds epoch columns", ver == "5"
              and {"epoch", "reset_at", "reset_archive"} <= cols,
              f"ver={ver} cols={sorted(cols)}")
        check("migration adds the vault tables",
              {"vaults", "vault_revisions"} <= tables, sorted(tables))
        check("migration adds the shared tables",
              {"account_keys", "shared_vaults", "shared_revisions",
               "shared_members", "note_locks"} <= tables, sorted(tables))

    finally:
        if server is not None:
            server.stop()
        if FAIL:
            print("\n--- server log tail ---")
            try:
                lines = Path(log_path).read_text(errors="replace").splitlines()
                print("\n".join(lines[-80:]))
            except OSError:
                pass
            print(f"temp dir kept for inspection: {tmp}")
        elif keep:
            print(f"temp dir kept: {tmp}")
        else:
            rmtree_force(tmp)

    print(f"\n{PASS} passed, {FAIL} failed")
    if FAILURES:
        print("failed: " + ", ".join(FAILURES))
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
