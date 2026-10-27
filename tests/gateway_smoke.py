#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gateway smoke: 私有头能不能活着穿过 sharect-webd。

起两个真实进程——2brain-app.py（应用）+ 网关——然后把每一个请求都发给网关端口，
由网关转发。断言刻意做成「头被吞了就红」：

  X-2brain-Epoch      空库上带错值 → 409；网关若丢掉这个头，应用会当成"没带"，直接 200
  X-2brain-KeyEpoch   带正确值 1 → 200；丢掉 → None != 1 → 409 epoch_mismatch
  X-2brain-Device     带合法值 → 200 且回显 deviceId；丢掉 → 400 bad_device

用法：python tests/gateway_smoke.py [--keep]
只在本机 127.0.0.1 上跑，临时库在系统临时目录，不碰生产数据、不碰 ~/.mnemon。
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import api_smoke as A  # noqa: E402

ROOT = HERE.parent
# 工作副本里网关是 docs/方案/sharect-webd-v6.1.py；开源仓库里是根目录的脱敏版。
# SHARECT_GATEWAY 只为"反向对照"服务：指一份删掉私有头的副本，本测试必须变红。
_GW_CANDIDATES = [ROOT / "sharect-webd.py",
                  ROOT / "docs" / "方案" / "sharect-webd-v6.2.py",
                  ROOT / "docs" / "方案" / "sharect-webd-v6.1.py"]
_ENV_GW = os.environ.get("SHARECT_GATEWAY")
GATEWAY = (Path(_ENV_GW) if _ENV_GW
           else next((p for p in _GW_CANDIDATES if p.is_file()),
                     _GW_CANDIDATES[0]))
PING = "<!DOCTYPE html><html><body>gateway-smoke-ping</body></html>"


def err_code(resp) -> str | None:
    body = resp.obj if isinstance(resp.obj, dict) else {}
    err = body.get("error")
    return err.get("code") if isinstance(err, dict) else None


class Gateway:
    def __init__(self, root: Path, gatefile: Path, upstream: str,
                 app_origin: str, log_path: str):
        self.port = A.free_port()
        self.app_origin = app_origin
        env = dict(os.environ,
                   SHARECT_API_UPSTREAM=upstream,
                   SHARECT_SYNC_UPSTREAM="",
                   SHARECT_BIND="127.0.0.1")
        self.log = open(log_path, "ab")
        self.proc = subprocess.Popen(
            [sys.executable, str(GATEWAY), str(root), str(self.port),
             str(gatefile)],
            stdin=subprocess.DEVNULL, stdout=self.log,
            stderr=subprocess.STDOUT, env=env,
        )

    def api(self) -> A.Api:
        api = A.Api(self.port)
        api.origin = self.app_origin   # 浏览器在网关这侧，Origin 仍须是应用认可的
        return api

    def wait_ready(self, timeout: float = 15.0) -> bool:
        deadline = time.time() + timeout
        probe = A.Session(self.api())
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return False
            try:
                if probe.req("GET", "/api/health").status == 200:
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


def main(argv: list[str]) -> int:
    keep = "--keep" in argv
    if not GATEWAY.is_file():
        print(f"missing gateway: {GATEWAY}")
        return 2

    tmp = Path(tempfile.mkdtemp(prefix="2brain-gw-"))
    db_path = str(tmp / "test.db")
    log_path = str(tmp / "server.log")
    gw_log_path = str(tmp / "gateway.log")
    (tmp / "archive").mkdir()
    (tmp / "udisk").mkdir()
    static = tmp / "static"
    static.mkdir()
    (static / "ping.html").write_text(PING, encoding="utf-8")
    (static / "2brain.html").write_text(PING, encoding="utf-8")
    (static / "secret.txt").write_text("nope", encoding="utf-8")
    gatefile = tmp / "webgate.json"
    gatefile.write_text(json.dumps({"@public": ["ping.html", "2brain.html"]}),
                        encoding="utf-8")

    print(f"temp dir: {tmp}")
    server: A.Server | None = None
    gateway: Gateway | None = None
    try:
        proc = A.run_admin("--db", db_path, "init")
        A.check("admin init", proc.returncode == 0, proc.stderr.strip())
        invite = A.invite_from_admin(db_path, "tester")

        server = A.Server(db_path, log_path)
        if not server.wait_ready():
            print(Path(log_path).read_text(errors="replace")[-3000:])
            A.check("app starts", False, "health never became ready")
            return 1

        gateway = Gateway(static, gatefile, server.origin, server.origin,
                          gw_log_path)
        if not gateway.wait_ready():
            print(Path(gw_log_path).read_text(errors="replace")[-3000:])
            A.check("gateway starts", False, "health never became ready")
            return 1
        A.check("gateway starts", True)

        anon = A.Session(gateway.api())

        # ---------- 静态面：白名单与登录入口 ----------
        resp = anon.req("GET", "/ping.html")
        A.check("whitelisted static file is served",
                resp.status == 200 and b"gateway-smoke-ping" in resp.raw,
                resp.status)
        resp = anon.req("GET", "/2brain.html")
        A.check("whitelisted app file is served",
                resp.status == 200 and b"gateway-smoke-ping" in resp.raw,
                resp.status)
        resp = anon.req("GET", "/secret.txt")
        A.check("non-whitelisted file is 404", resp.status == 404, resp.status)
        resp = anon.req("GET", "/")
        A.check("root serves the app file directly (no redirect)",
                resp.status == 200 and b"gateway-smoke-ping" in resp.raw
                and "location" not in resp.headers,
                f'{resp.status} loc={resp.headers.get("location")}')
        resp = anon.req("GET", "/login.html")
        A.check("login alias jumps to root", resp.status == 302
                and resp.headers.get("location") == "/",
                resp.headers.get("location"))
        resp = anon.req("GET", "/brain/health")
        A.check("sync prefix is off here (404, not a hang)",
                resp.status == 404, resp.status)

        # ---------- /api 转发 ----------
        resp = anon.req("GET", "/api/health")
        A.check("api reaches the app through the gateway",
                resp.status == 200
                and isinstance(resp.obj, dict)
                and isinstance(resp.obj.get("schema"), int),
                resp.raw[:200])
        resp = anon.req("GET", "/api/brain")
        A.check("anon brain is 401 behind the gateway", resp.status == 401,
                resp.raw[:200])
        resp = anon.req("POST", "/api/kdf", {"name": "tester"})
        A.check("POST body crosses the gateway",
                resp.status == 200
                and isinstance(resp.obj, dict)
                and resp.obj.get("iter") == 600_000, resp.raw[:200])

        # ---------- Cookie 双向 ----------
        resp = anon.req("POST", "/api/setup",
                        A.setup_body("tester", invite, A.material("authH1", 32),
                                     A.material("kdfsalt", 16)))
        A.check("setup through the gateway", resp.status == 200, resp.raw[:200])
        A.check("Set-Cookie crosses the gateway", bool(anon.cookie), "")
        resp = anon.req("GET", "/api/me")
        A.check("Cookie crosses the gateway back",
                resp.status == 200
                and isinstance(resp.obj, dict)
                and resp.obj.get("name") == "tester", resp.raw[:200])

        # ---------- 判别器 A：X-2brain-Epoch ----------
        B1 = A.blob_for("gw-1")
        resp = anon.req("PUT", "/api/brain", B1,
                        headers={"X-2brain-Epoch": "3"})
        A.check("X-2brain-Epoch survives (wrong epoch -> 409)",
                resp.status == 409 and err_code(resp) == "epoch_mismatch",
                resp.raw[:200])
        resp = anon.req("PUT", "/api/brain", B1,
                        headers={"X-2brain-Epoch": "0"})
        A.check("PUT with the live epoch lands",
                resp.status == 200
                and isinstance(resp.obj, dict)
                and resp.obj.get("etag") == A.etag_for(B1), resp.raw[:200])
        resp = anon.req("GET", "/api/brain",
                        headers={"If-None-Match": f'"{A.etag_for(B1)}"'})
        A.check("ETag round-trips (If-None-Match -> 304)",
                resp.status == 304, resp.raw[:200])

        # ---------- 共享库：身份密钥 + 判别器 B/C ----------
        pub = A.pub_jwk("owner")
        resp = anon.req("PUT", "/api/keys", {"pubJwk": pub})
        A.check("account key registered through the gateway",
                resp.status == 200
                and isinstance(resp.obj, dict)
                and resp.obj.get("pubJwk") == pub, resp.raw[:200])
        resp = anon.req("POST", "/api/shared",
                        {"name": "家庭", "wrapped": A.wrapped_key("owner-1")})
        gid = resp.obj.get("gid") if isinstance(resp.obj, dict) else ""
        A.check("shared vault created through the gateway",
                resp.status == 200 and bool(re.fullmatch(r"s[0-9a-f]{16}",
                                                         gid or ""))
                and resp.obj.get("keyEpoch") == 1, resp.raw[:200])

        SH = A.blob_for("gw-shared")
        resp = anon.req("PUT", f"/api/s/{gid}/brain", SH,
                        headers={"X-2brain-KeyEpoch": "99"})
        A.check("X-2brain-KeyEpoch survives (stale epoch -> 409)",
                resp.status == 409 and err_code(resp) == "epoch_mismatch"
                and isinstance(resp.obj, dict)
                and resp.obj.get("keyEpoch") == 1, resp.raw[:200])
        resp = anon.req("PUT", f"/api/s/{gid}/brain", SH,
                        headers={"X-2brain-KeyEpoch": "1"})
        A.check("X-2brain-KeyEpoch survives (live epoch -> 200)",
                resp.status == 200
                and isinstance(resp.obj, dict)
                and resp.obj.get("etag") == A.etag_for(SH), resp.raw[:200])

        lock_path = f"/api/s/{gid}/locks/gw-note-1"
        resp = anon.req("POST", lock_path)
        A.check("lock gate is real (no device header -> 400 bad_device)",
                resp.status == 400 and err_code(resp) == "bad_device",
                resp.raw[:200])
        resp = anon.req("POST", lock_path,
                        headers={"X-2brain-Device": "gw-dev-A"})
        A.check("X-2brain-Device survives (acquire echoes deviceId)",
                resp.status == 200
                and isinstance(resp.obj, dict)
                and resp.obj.get("held") is True
                and resp.obj.get("deviceId") == "gw-dev-A", resp.raw[:200])
        resp = anon.req("DELETE", lock_path,
                        headers={"X-2brain-Device": "gw-dev-A"})
        A.check("release through the gateway",
                resp.status == 200
                and isinstance(resp.obj, dict)
                and resp.obj.get("released") is True, resp.raw[:200])
    finally:
        if gateway is not None:
            gateway.stop()
        if server is not None:
            server.stop()
        if A.FAIL and not keep:
            try:
                lines = Path(gw_log_path).read_text(errors="replace").splitlines()
                print("\n".join(lines[-40:]))
            except OSError:
                pass
        if keep:
            print(f"temp dir kept: {tmp}")
        else:
            A.rmtree_force(tmp)

    print(f"\n{A.PASS} passed, {A.FAIL} failed")
    if A.FAILURES:
        print("failed: " + ", ".join(A.FAILURES))
    return 0 if A.FAIL == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
