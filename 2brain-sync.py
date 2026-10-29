#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
2brain 同步中枢（零依赖，只用 Python 3 标准库）
=================================================
把「一个 JSON 文件」变成一个多端同步端点，页面里的「同步方式 = HTTP 备份端点」直接对接：

    GET  /brain   Authorization: Bearer <同步 Key>   →  取回整包 bundle（无数据时 404）
    PUT  /brain   Authorization: Bearer <同步 Key>   →  写回整包（原子写 + 轮转备份）
                  If-Match: "<版本>"                →  版本不一致返回 409，避免互相覆盖
    GET  /brain/health                               →  版本 / 条数 / 大小 / 备份数
    GET  /                                           →  一句说明的小页面
    OPTIONS *                                        →  CORS 预检（页面可能来自别的源）

版本号 = 内容指纹（notes + nodes + tombstones 的 sha256 前 16 位，忽略 exportedAt 之类易变字段）：
内容没变时 PUT 不写盘、不产生备份，直接回同一个版本 —— 多台设备互相轮询不会互相"踩"出写放大。

用法示例：
    python3 2brain-sync.py --file "/home/aict/sharect/2 brain/2brain-data.json" \
        --port 8089 --token-file ~/.2brain-sync.token --backup-dir ~/.2brain/backups --keep 30

安全：
    * 必须提供 Key（--token / --token-file / 环境变量 IIIBRAIN_SYNC_TOKEN），否则拒绝启动；
      确实想裸奔再加 --no-auth（不建议，尤其是走公网隧道时）。
    * 默认只监听 127.0.0.1；要给局域网别的机器直连就 --host 0.0.0.0（Key 别太弱）。
"""

import argparse
import hashlib
import hmac
import json
import os
import shutil
import sys
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 32 * 1024 * 1024          # 32 MB 上限，防呆
LOCK = threading.Lock()              # 写盘串行化（多设备同时 PUT）

STATE = {
    "raw": None,                     # 当前 bundle 的原始字节
    "version": None,                 # 内容指纹
    "notes": 0,
    "nodes": 0,
    "updated": "",                   # 最后写入时间（本地时区）
}

CFG = {}


# ---------------------------------------------------------------- 工具函数
def log(msg):
    sys.stdout.write("[%s] %s\n" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg))
    sys.stdout.flush()


def fingerprint(raw):
    """内容指纹：只投影真正的内容字段，忽略 exportedAt / 顺序无关的元信息。"""
    try:
        j = json.loads(raw)
    except Exception:
        return None
    proj = {
        "n": j.get("nodes") or [],
        "c": j.get("notes") or [],
        "t": j.get("tombstones") or {},
    }
    blob = json.dumps(proj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def load_from_disk():
    p = CFG["file"]
    if not os.path.exists(p):
        log("数据文件还不存在，等第一次 PUT：%s" % p)
        return
    with open(p, "rb") as f:
        raw = f.read()
    STATE["raw"] = raw
    STATE["version"] = fingerprint(raw)
    try:
        j = json.loads(raw)
        STATE["notes"] = len(j.get("notes") or [])
        STATE["nodes"] = len(j.get("nodes") or [])
    except Exception:
        pass
    STATE["updated"] = datetime.fromtimestamp(os.path.getmtime(p)).strftime("%Y-%m-%d %H:%M:%S")
    log("已载入 %s（版本 %s · %d 条笔记 · %d 个节点）"
        % (p, STATE["version"], STATE["notes"], STATE["nodes"]))


def backup_current():
    """写入前把上一版复制到备份目录，保留最近 N 份。"""
    src = CFG["file"]
    if not os.path.exists(src):
        return None
    bdir = CFG["backup_dir"]
    os.makedirs(bdir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    dst = os.path.join(bdir, "2brain-data-%s.json" % stamp)
    n = 1
    while os.path.exists(dst):                       # 同一秒内多次写：加序号
        dst = os.path.join(bdir, "2brain-data-%s-%d.json" % (stamp, n))
        n += 1
    shutil.copy2(src, dst)
    os.chmod(dst, 0o600)
    keep = CFG["keep"]
    if keep > 0:
        files = sorted(f for f in os.listdir(bdir) if f.startswith("2brain-data-"))
        for old in files[:-keep]:
            try:
                os.remove(os.path.join(bdir, old))
            except OSError:
                pass
    return os.path.basename(dst)


def atomic_write(raw):
    """原子写：临时文件 + fsync + replace，掉电也不会留下半个 JSON。
    临时文件名带随机后缀：数据文件落在公网静态目录里时，猜不到、也来不及抓。"""
    path = CFG["file"]
    d = os.path.dirname(os.path.abspath(path))
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    tmp = os.path.join(d, ".2brain-%s.tmp" % os.urandom(6).hex())
    try:
        with open(tmp, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def read_body(handler):
    """读请求体：优先 Content-Length，兼容 chunked（隧道/代理可能改写）。"""
    te = (handler.headers.get("Transfer-Encoding") or "").lower()
    if "chunked" in te:
        chunks = []
        while True:
            line = handler.rfile.readline(64).strip()
            if not line:
                break
            try:
                size = int(line.split(b";")[0], 16)
            except ValueError:
                return None
            if size == 0:
                handler.rfile.readline(64)               # 收尾 CRLF
                break
            chunks.append(handler.rfile.read(size))
            handler.rfile.read(2)                        # 每个 chunk 后面的 CRLF
            if sum(len(c) for c in chunks) > MAX_BODY:
                return None
        return b"".join(chunks)
    try:
        n = int(handler.headers.get("Content-Length") or 0)
    except ValueError:
        return None
    if n < 0 or n > MAX_BODY:
        return None
    return handler.rfile.read(n) if n else b""


# ---------------------------------------------------------------- HTTP 处理
class Handler(BaseHTTPRequestHandler):
    server_version = "2brain-sync/1.0"
    protocol_version = "HTTP/1.1"

    # ---- 基础响应 ----
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, PUT, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, If-Match, X-2brain-Version")
        self.send_header("Access-Control-Expose-Headers", "ETag, X-2brain-Version, X-2brain-Notes")
        self.send_header("Access-Control-Max-Age", "600")

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}):
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code, obj, extra=None):
        self._send(code, json.dumps(obj, ensure_ascii=False), extra=extra)

    # ---- 鉴权 ----
    def _authed(self):
        if CFG["no_auth"]:
            return True
        want = CFG["token"]
        got = self.headers.get("Authorization") or ""
        if got.lower().startswith("bearer "):
            got = got[7:].strip()
        return bool(want) and hmac.compare_digest(got, want)

    def _unauthorized(self):
        accept = (self.headers.get("Accept") or "")
        if "text/html" in accept:
            self._send(401, u"""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>2brain 同步端点</title><style>body{font:15px/1.7 -apple-system,"Microsoft YaHei",sans-serif;
max-width:640px;margin:60px auto;padding:0 18px;color:#26282c}h1{font-size:19px}code{background:#f2f3f5;padding:1px 5px;border-radius:4px}
.tip{color:#7b828a;font-size:13px}</style></head><body>
<h1>这里是 2brain 的同步端点</h1>
<p>它不提供网页界面，只认 <code>GET</code> / <code>PUT</code> 一个 JSON，且需要同步 Key：</p>
<p><code>Authorization: Bearer &lt;你的同步 Key&gt;</code></p>
<p class="tip">在 2brain 页面里：设置 → 同步与 Agent → 同步方式选「HTTP 备份端点」，
地址填本页地址，Key 填同一个值。</p></body></html>""", ctype="text/html; charset=utf-8")
        else:
            self._json(401, {"error": "unauthorized", "hint": "需要 Authorization: Bearer <同步 Key>"})

    # ---- 路由 ----
    def _path(self):
        return (self.path or "").split("?", 1)[0].rstrip("/") or "/"

    def _is_brain(self):
        return self._path() in (CFG["prefix"], CFG["prefix"] + "/health")

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        p = self._path()
        if p == "/" or p == "":
            self._send(200, u"""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>2brain 同步中枢</title><style>body{font:15px/1.7 -apple-system,"Microsoft YaHei",sans-serif;
max-width:640px;margin:60px auto;padding:0 18px;color:#26282c}code{background:#f2f3f5;padding:1px 5px;border-radius:4px}</style>
</head><body><h1>2brain 同步中枢 · 运行中</h1>
<p>端点：<code>%(prefix)s</code>（GET 取回 / PUT 写回，需要 <code>Authorization: Bearer &lt;Key&gt;</code>）</p>
<p>健康检查：<code>%(prefix)s/health</code></p>
<p>数据文件：<code>%(file)s</code></p></body></html>""" % {"prefix": CFG["prefix"], "file": CFG["file"]},
                       ctype="text/html; charset=utf-8")
            return
        if p == "/health" or p == CFG["prefix"] + "/health":
            if not self._authed():
                return self._unauthorized()
            return self._json(200, self._health())
        if p == CFG["prefix"]:
            if not self._authed():
                return self._unauthorized()
            if STATE["raw"] is None:
                return self._json(404, {"error": "empty", "hint": "远端还没有数据，第一次 PUT 会自动创建"})
            return self._send(200, STATE["raw"], extra=[
                ("ETag", '"%s"' % STATE["version"]),
                ("X-2brain-Version", STATE["version"]),
                ("X-2brain-Notes", str(STATE["notes"])),
            ])
        return self._json(404, {"error": "not-found", "path": p})

    def do_PUT(self):
        if self._path() != CFG["prefix"]:
            return self._json(404, {"error": "not-found", "path": self._path()})
        if not self._authed():
            return self._unauthorized()
        raw = read_body(self)
        if raw is None:
            return self._json(413, {"error": "body-too-large-or-unreadable"})
        try:
            j = json.loads(raw.decode("utf-8"))
        except Exception as e:
            return self._json(400, {"error": "bad-json", "detail": str(e)[:200]})
        if not isinstance(j.get("nodes"), list) or not isinstance(j.get("notes"), list):
            return self._json(400, {"error": "bad-bundle", "hint": "需要 nodes / notes 两个数组"})
        new_ver = fingerprint(raw)
        want = (self.headers.get("If-Match") or self.headers.get("X-2brain-Version") or "").strip().strip('"')
        with LOCK:
            cur = STATE["version"]
            if want and cur and want != cur:
                log("版本冲突：对方带 %s，当前 %s" % (want, cur))
                return self._json(409, {"error": "version-conflict", "version": cur})
            if new_ver and new_ver == cur:
                log("内容没变，跳过写盘（版本 %s）" % cur)
                return self._json(200, {"ok": True, "unchanged": True, "version": cur,
                                        "notes": STATE["notes"], "nodes": STATE["nodes"]})
            bak = backup_current()
            atomic_write(raw)
            STATE["raw"] = raw
            STATE["version"] = new_ver
            STATE["notes"] = len(j.get("notes") or [])
            STATE["nodes"] = len(j.get("nodes") or [])
            STATE["updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log("已写入：%d 条笔记 · %d 个节点 · %d 字节 · 版本 %s%s"
            % (STATE["notes"], STATE["nodes"], len(raw), STATE["version"],
               ("（备份 %s）" % bak) if bak else ""))
        return self._json(200, {"ok": True, "version": STATE["version"], "notes": STATE["notes"],
                                "nodes": STATE["nodes"], "bytes": len(raw), "updated": STATE["updated"]})

    def do_POST(self):
        self.do_PUT()

    def _health(self):
        bdir = CFG["backup_dir"]
        try:
            nbak = len([f for f in os.listdir(bdir) if f.startswith("2brain-data-")])
        except OSError:
            nbak = 0
        return {"ok": True, "version": STATE["version"], "notes": STATE["notes"], "nodes": STATE["nodes"],
                "bytes": len(STATE["raw"] or b""), "updated": STATE["updated"],
                "file": CFG["file"], "backups": nbak, "auth": not CFG["no_auth"]}

    def log_message(self, fmt, *args):              # 默认日志带一堆颜色/格式，重写成一行
        log("%s %s" % (self.address_string(), fmt % args))


def main():
    ap = argparse.ArgumentParser(description="2brain 同步中枢：一个 JSON 文件的 GET/PUT 端点")
    ap.add_argument("--file", required=True, help="数据文件路径（放共享文件夹里也行）")
    ap.add_argument("--port", type=int, default=8089)
    ap.add_argument("--host", default="127.0.0.1", help="默认只监听本机；给局域网直连用 0.0.0.0")
    ap.add_argument("--path", default="/brain", help="端点路径（要和隧道里的路径路由一致）")
    ap.add_argument("--token", default="", help="同步 Key（也可用 --token-file 或环境变量）")
    ap.add_argument("--token-file", default="", help="从文件读 Key（建议 chmod 600）")
    ap.add_argument("--no-auth", action="store_true", help="不要 Key（危险，仅限完全可信环境）")
    ap.add_argument("--backup-dir", default="", help="备份目录（默认 <数据文件目录>/.2brain-backups）")
    ap.add_argument("--keep", type=int, default=30, help="备份保留份数")
    a = ap.parse_args()

    token = a.token or os.environ.get("IIIBRAIN_SYNC_TOKEN", "")
    if not token and a.token_file:
        try:
            with open(os.path.expanduser(a.token_file), encoding="utf-8") as f:
                token = f.read().strip()
        except OSError as e:
            log("读不到 Key 文件 %s：%s" % (a.token_file, e))
    if not token and not a.no_auth:
        log("没有配置同步 Key：请用 --token / --token-file / 环境变量 IIIBRAIN_SYNC_TOKEN，"
            "或明确加 --no-auth（不建议）")
        sys.exit(2)

    CFG.update({
        "file": os.path.abspath(os.path.expanduser(a.file)),
        "prefix": "/" + a.path.strip("/"),
        "token": token,
        "no_auth": bool(a.no_auth),
        "keep": max(0, a.keep),
        "backup_dir": os.path.abspath(os.path.expanduser(
            a.backup_dir or os.path.join(os.path.dirname(os.path.abspath(os.path.expanduser(a.file))),
                                         ".2brain-backups"))),
    })
    load_from_disk()
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    log("监听 http://%s:%d%s（鉴权：%s）" % (a.host, a.port, CFG["prefix"],
                                            "关闭" if CFG["no_auth"] else "Bearer Key"))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        log("收到 Ctrl+C，退出")
        srv.server_close()


if __name__ == "__main__":
    main()
