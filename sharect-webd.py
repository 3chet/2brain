#!/usr/bin/env python3
# sharect-webd v6.1: v6 + 按路径放宽超时（/api/ai/proxy 95s、/api/fetch/url 60s）
#                   其余逻辑与 v6 完全一致；部署时放在应用目录即可
# sharect-webd v6: live static server with per-path password gate + recovery reset
#                   + 公开白名单（只暴露列出的文件，其余一律 404，不再列目录）
#                   + /brain 转发到本机同步服务（页面同域，免 CORS、免再动 CF）
#                   + /api 转发到本机 2brain-app（Cookie / Origin / ETag / 304 透传）
# argv: <root> <port> <gatefile.json {"path|dir/": {"pw":"sha256hex","rc":"sha256hex"},
#                                     "@public": ["2brain.html", ...]}>
import functools, hashlib, hmac, html, http.server, json, os, sys, time, urllib.parse
import urllib.request, urllib.error

root, port, gatefile = sys.argv[1], int(sys.argv[2]), sys.argv[3]

# ---- v5 配置：只有白名单里的文件能被浏览器读取；@public 键可覆盖下面这份默认值 ----
DEFAULT_PUBLIC = ["2brain.html", "bridge_conn_check.html", "2brain-data.json"]
INDEX_TO = "2brain.html"            # 访问 / 时跳到这里（不在白名单里则 404）
LOGIN_ALIAS = "login.html"          # 短入口：/login.html → 在线模式（不新建文件、不改数据桶路径）
LOGIN_TO = "/2brain.html?online=1"  # M1c 切换后可改成 "/2brain.html"
SYNC_UPSTREAM = os.environ.get("SHARECT_SYNC_UPSTREAM", "http://127.0.0.1:8089")  # 上游；置 "" 关闭 /brain 转发
SYNC_PREFIX = "brain"               # /brain、/brain/health… 全部转发
API_UPSTREAM = os.environ.get("SHARECT_API_UPSTREAM", "http://127.0.0.1:8090")    # v6；置 "" 关闭 /api 转发
API_PREFIX = "api"                  # /api、/api/health… 全部转发
# 入站请求体上限：与两个上游各自的限制对齐，绝不让网关先把整包吞进内存
MAX_API_BODY = 25 * 1024 * 1024     # 2brain-app.py: MAX_BODY（--max-body-mb 默认 25）
MAX_SYNC_BODY = 32 * 1024 * 1024    # 2brain-sync.py: MAX_BODY
# 普通 API 30s；AI 转发/公网抓文章更慢，按路径放宽（CF 公网对源站约 100s 上限）
API_TIMEOUT = 30
API_SLOW_TIMEOUTS = {"/api/ai/proxy": 95, "/api/fetch/url": 60}
PASS_HEADERS = ("Content-Type", "ETag", "Cache-Control", "Last-Modified",
                "Access-Control-Allow-Origin", "Access-Control-Allow-Headers",
                "Access-Control-Allow-Methods", "Vary")
API_PASS_HEADERS = ("Content-Type", "ETag", "Retry-After", "Allow",
                    "X-Content-Type-Options", "Referrer-Policy", "Vary")
API_REQ_HEADERS = ("Authorization", "Content-Type", "If-Match", "If-None-Match",
                   "X-2brain-Epoch", "X-2brain-KeyEpoch", "X-2brain-Device", "Accept", "Origin", "Cookie",
                   "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest",
                   "CF-Connecting-IP", "CF-IPCountry", "User-Agent")


class BodyTooLarge(Exception):
    pass

def load_rules():
    try:
        with open(gatefile, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}

def save_rules(d):
    tmp = gatefile + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=1)
    os.replace(tmp, gatefile)
    os.chmod(gatefile, 0o600)

def norm(p):
    return urllib.parse.unquote(p.split("?", 1)[0].split("#", 1)[0]).lstrip("/")

def match_scope(rules, rel):
    best, blen = None, -1
    for k in rules:
        kk = k.lstrip("/")
        if kk.endswith("/") and rel.startswith(kk):
            cand, sc = kk, len(kk)
        elif rel == kk or rel == kk + "/":
            cand, sc = kk, len(kk)
        else:
            continue
        if sc > blen:
            best, blen = cand, sc
    return best

def sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def public_set(rules):
    """公开白名单：网关文件里的 "@public": [...] 优先；缺失/非法则用默认值。"""
    lst = rules.get("@public")
    if not isinstance(lst, list) or not lst:
        lst = DEFAULT_PUBLIC
    return {str(x).lstrip("/") for x in lst if str(x).strip()}

def tok(scope, h):
    return hmac.new(hashlib.sha256(("gate|" + scope + "|" + h).encode()).digest(), b"granted", hashlib.sha256).hexdigest()

def ckname(scope):
    return "ba_" + hashlib.sha256(scope.encode()).hexdigest()[:12]

CSS = """
:root{--g:#0f7a4a;--gm:#14915a;--gl:#e8f6ee;--bd:#d8e8de;--tx:#1c1c1c;--mut:#66756c;--bad:#c0392b}
*{box-sizing:border-box;margin:0;padding:0}
body{background:#fff;color:var(--tx);font-family:"Segoe UI","Microsoft YaHei",system-ui,sans-serif;
min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
.card{width:100%;max-width:420px;background:#f7faf8;border:1px solid var(--bd);border-radius:16px;
padding:40px 36px;box-shadow:0 12px 40px rgba(15,122,74,.08);position:relative;overflow:hidden}
.card:before{content:"";position:absolute;top:0;left:0;right:0;height:5px;
background:linear-gradient(90deg,var(--g),var(--gm),#7cc9a3)}
.lock{width:64px;height:64px;margin:0 auto 18px;border-radius:50%;background:var(--gl);
display:flex;align-items:center;justify-content:center}
.lock svg{width:30px;height:30px;stroke:var(--g);fill:none;stroke-width:2}
h1{font-size:20px;text-align:center}
.namewrap{text-align:center}.name{color:var(--g);font-weight:600;font-size:14px;margin:10px 0 4px;
padding:6px 12px;background:var(--gl);border-radius:8px;display:inline-block;max-width:100%;overflow-wrap:anywhere}
.sub{text-align:center;color:var(--mut);font-size:12.5px;margin:10px 0 24px}
input{width:100%;padding:12px 15px;font-size:15px;border:1.5px solid var(--bd);border-radius:10px;
background:#fff;color:var(--tx);outline:none;margin-top:10px;transition:border-color .2s,box-shadow .2s}
input:focus{border-color:var(--gm);box-shadow:0 0 0 3px rgba(20,145,90,.14)}
button{width:100%;margin-top:16px;padding:13px;font-size:15px;font-weight:600;letter-spacing:2px;
color:#fff;background:linear-gradient(135deg,var(--g),var(--gm));border:none;border-radius:10px;
cursor:pointer;transition:transform .1s,box-shadow .2s}
button:hover{box-shadow:0 6px 18px rgba(15,122,74,.28)}
button:active{transform:scale(.98)}button:disabled{opacity:.6;cursor:wait}
.err{color:var(--bad);font-size:13px;text-align:center;margin-top:14px;padding:9px 12px;
background:#fdeeec;border-left:3px solid var(--bad);border-radius:6px;animation:shake .3s}
.lk{display:block;text-align:center;margin-top:16px;color:var(--gm);font-size:13px;text-decoration:none}
.lk:hover{text-decoration:underline}
.foot{margin-top:22px;text-align:center;color:var(--mut);font-size:11.5px;line-height:1.7}.foot b{color:var(--g)}
@keyframes shake{0%,100%{transform:translateX(0)}25%{transform:translateX(-5px)}75%{transform:translateX(5px)}}"""

GATE = """<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>__NAME__ · 受保护文档</title>
<style>__CSS__</style></head><body>
<div class="card">
 <div class="lock"><svg viewBox="0 0 24 24"><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/><circle cx="12" cy="15.5" r="1.6" fill="var(--g)" stroke="none"/></svg></div>
 <h1>此文档受密码保护</h1>
 <div class="namewrap"><span class="name">__NAME__</span></div>
 <div class="sub">输入密码后阅读<b style="color:var(--g)">实时最新</b>内容（24 小时内免重复输入）</div>
 <form method="POST" action="/unlock" onsubmit="var b=this.querySelector('button');b.disabled=true;b.textContent='验证中…';return true;">
  <input type="password" name="pw" placeholder="文档密码" autofocus autocomplete="off">
  <input type="hidden" name="path" value="__PATH__">
  <button type="submit">阅 读 文 档</button>
 </form>
 __ERR__
 <a class="lk" href="/recover?path=__PATH__">忘记密码？使用恢复码重设</a>
 <div class="foot">powered by <b>sharect · 2 brain</b></div>
</div></body></html>"""

RECV = """<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>__NAME__ · 重设密码</title>
<style>__CSS__</style></head><body>
<div class="card">
 <div class="lock"><svg viewBox="0 0 24 24"><path d="M12 3l7 4v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V7z"/><path d="M9.5 12.5l2 2 4-4.5"/></svg></div>
 <h1>重设文档密码</h1>
 <div class="namewrap"><span class="name">__NAME__</span></div>
 <div class="sub">输入<b>恢复码</b>和新密码即可重设；原密码及所有已登录会话立即失效</div>
 <form method="POST" action="/recover" onsubmit="var b=this.querySelector('button');b.disabled=true;b.textContent='验证中…';return true;">
  <input type="password" name="rc" placeholder="恢复码" autofocus autocomplete="off">
  <input type="password" name="npw" placeholder="新密码（至少 4 位）" autocomplete="new-password">
  <input type="password" name="npw2" placeholder="确认新密码" autocomplete="new-password">
  <input type="hidden" name="path" value="__PATH__">
  <button type="submit">重 设 密 码</button>
 </form>
 __ERR__
 <a class="lk" href="__PATH__">返回登录</a>
 <div class="foot">powered by <b>sharect · 2 brain</b></div>
</div></body></html>"""

def _doc(tpl, rel, err):
    name = os.path.basename(urllib.parse.unquote(rel).rstrip("/")) or "目录"
    path = "/" + rel
    out = tpl.replace("__CSS__", CSS)
    out = out.replace("__NAME__", html.escape(name)).replace("__PATH__", html.escape(path, quote=True))
    out = out.replace("__ERR__", '<div class="err">' + html.escape(err) + "</div>" if err else "")
    return out.encode("utf-8")

class Handler(http.server.SimpleHTTPRequestHandler):
    timeout = 30  # 慢连接/半截 chunked 请求最多占用线程 30 秒（SimpleHTTPRequestHandler 默认无超时）

    def _rule(self, rel):
        rules = load_rules()
        scope = match_scope(rules, rel)
        if scope is None:
            return None, None, rules
        entry = rules[scope]
        if not isinstance(entry, dict):  # legacy format from v3
            entry = {"pw": str(entry), "rc": ""}
        return entry, scope, rules

    def _authed(self, scope, entry):
        want = tok(scope, entry.get("pw", ""))
        nm = ckname(scope)
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == nm and hmac.compare_digest(v, want):
                return True
        return False

    def _page(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, rel, cookie=None):
        self.send_response(302)
        self.send_header("Location", "/" + urllib.parse.quote(rel))
        if cookie:
            self.send_header("Set-Cookie", cookie + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400")
        self.end_headers()

    def _form(self):
        n = int(self.headers.get("Content-Length") or 0)
        return urllib.parse.parse_qs(self.rfile.read(n).decode("utf-8", "replace"))

    # ---- v5: 公开白名单 ----------------------------------------------------
    def _allowed(self, rel):
        """只放行白名单里的文件；目录/其它文件一律 404（不再列目录）。"""
        _, _, rules = self._rule(rel)
        pub = public_set(rules)
        if rel == "":
            if INDEX_TO in pub:
                self._redirect(INDEX_TO)
            else:
                self.send_error(404)
            return False
        if rel not in pub:
            self.send_error(404)
            return False
        return True

    # ---- v6: 在线登录入口（根路径与 /login.html 都跳到这里）------------------
    def _login_alias_hit(self, rel):
        """跳给同一个应用文件，不复制 HTML —— Firefox 按完整路径存 localStorage，
        真做一个 login.html 副本等于换一个空白数据桶。
        根路径 `https://…/` 也走这里：用户无论从哪个地址进来都要看到登录界面。"""
        if rel not in ("", LOGIN_ALIAS):
            return False
        self.send_response(302)
        self.send_header("Location", LOGIN_TO)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()
        return True

    # ---- v5: /brain 转发到同步服务 -----------------------------------------
    def _sync_target(self):
        if not SYNC_UPSTREAM:
            return None
        raw = self.path.split("#", 1)[0]
        rel = urllib.parse.unquote(raw.split("?", 1)[0]).lstrip("/")
        if rel == SYNC_PREFIX or rel.startswith(SYNC_PREFIX + "/"):
            return raw
        return None

    # ---- v6: /api 转发到 2brain-app ----------------------------------------
    def _api_target(self):
        if not API_UPSTREAM:
            return None
        raw = self.path.split("#", 1)[0]
        rel = urllib.parse.unquote(raw.split("?", 1)[0]).lstrip("/")
        if rel == API_PREFIX or rel.startswith(API_PREFIX + "/"):
            return raw
        return None

    def _read_chunked(self, limit):
        buf = bytearray()
        total = 0
        while True:
            line = self.rfile.readline(65536).strip()
            if not line:
                break
            try:
                size = int(line.split(b";", 1)[0], 16)
            except ValueError:
                break
            if size == 0:
                self.rfile.readline(65536)
                break
            total += size
            if total > limit:
                raise BodyTooLarge()
            buf += self.rfile.read(size)
            self.rfile.readline(65536)
        return bytes(buf)

    def _read_request_body(self, limit):
        if self.command not in ("PUT", "POST", "PATCH"):
            return None
        te = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in te:
            return self._read_chunked(limit)
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n > limit:
            raise BodyTooLarge()
        return self.rfile.read(n) if n > 0 else b""

    def _proxy(self, raw_path):
        try:
            body = self._read_request_body(MAX_SYNC_BODY)
        except BodyTooLarge:
            self.close_connection = True
            self.send_error(413, "request body too large")
            return
        hdrs = {}
        for k in ("Authorization", "Content-Type", "If-Match", "Accept", "Origin"):
            v = self.headers.get(k)
            if v:
                hdrs[k] = v
        req = urllib.request.Request(SYNC_UPSTREAM + raw_path, data=body, headers=hdrs,
                                     method=self.command)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                code, data, h = r.status, r.read(), r.headers
        except urllib.error.HTTPError as e:
            code, data, h = e.code, e.read(), e.headers
        except Exception:
            self.send_error(502, "sync upstream unreachable")
            return
        self.send_response(code)
        for k in PASS_HEADERS:
            v = h.get(k)
            if v:
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _proxy_api(self, raw_path):
        try:
            body = self._read_request_body(MAX_API_BODY)
        except BodyTooLarge:
            self.close_connection = True
            self._api_error(413, "request body too large", "request_too_large")
            return
        hdrs = {}
        for k in API_REQ_HEADERS:
            v = self.headers.get(k)
            if v:
                hdrs[k] = v
        # XFF 只填 Cloudflare 给的真实客户端 IP；拿不到就不填，别写 127.0.0.1 这种假值
        cfip = (self.headers.get("CF-Connecting-IP") or "").strip()
        if cfip:
            hdrs["X-Forwarded-For"] = cfip
        else:
            hdrs.pop("X-Forwarded-For", None)
        # X-Forwarded-Proto 不信任入站头（客户端可伪造），只按 CF-Visitor 判定
        cf = (self.headers.get("CF-Visitor") or "").replace(" ", "")
        hdrs["X-Forwarded-Proto"] = "https" if '"scheme":"https"' in cf else "http"
        req = urllib.request.Request(API_UPSTREAM + raw_path, data=body, headers=hdrs,
                                     method=self.command)
        wait = API_SLOW_TIMEOUTS.get(raw_path.split("?", 1)[0], API_TIMEOUT)
        try:
            with urllib.request.urlopen(req, timeout=wait) as r:
                code, data, h = r.status, r.read(), r.headers
        except urllib.error.HTTPError as e:
            code, data, h = e.code, e.read(), e.headers
        except Exception:
            self._api_error(502, "api upstream unreachable")
            return
        self.send_response(code)
        for k in API_PASS_HEADERS:
            v = h.get(k)
            if v:
                self.send_header(k, v)
        for sc in (h.get_all("Set-Cookie") or []):
            self.send_header("Set-Cookie", sc)
        self.send_header("Cache-Control", "no-store")
        if code in (204, 304):
            pass
        elif self.command == "HEAD" and h.get("Content-Length"):
            self.send_header("Content-Length", h.get("Content-Length"))
        else:
            self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if code not in (204, 304) and self.command != "HEAD":
            self.wfile.write(data)

    def _api_error(self, code, message, err="bad_gateway"):
        data = json.dumps({"error": {"code": err, "message": message}},
                          separators=(",", ":")).encode("utf-8")
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception:
            pass

    def _forward_or_none(self):
        tgt = self._api_target()
        if tgt is not None:
            self._proxy_api(tgt)
            return True
        tgt = self._sync_target()
        if tgt is not None:
            self._proxy(tgt)
            return True
        return False

    def do_GET(self):
        if self.path.split("?", 1)[0] == "/recover":
            q = urllib.parse.parse_qs(self.path.partition("?")[2])
            rel = norm((q.get("path") or ["/"])[0])
            entry, scope, _ = self._rule(rel)
            if entry is None:
                self._redirect(rel)
                return
            self._page(_doc(RECV, rel, ""))
            return
        if self._forward_or_none():
            return
        rel = norm(self.path)
        if self._login_alias_hit(rel):
            return
        if not self._allowed(rel):
            return
        entry, scope, _ = self._rule(rel)
        if entry is None or self._authed(scope, entry):
            super().do_GET()
        else:
            self._page(_doc(GATE, rel, ""))

    def do_HEAD(self):
        if self._forward_or_none():
            return
        rel = norm(self.path)
        if self._login_alias_hit(rel):
            return
        if not self._allowed(rel):
            return
        entry, scope, _ = self._rule(rel)
        if entry is None or self._authed(scope, entry):
            super().do_HEAD()
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_PUT(self):
        if not self._forward_or_none():
            self.send_error(404)

    def do_PATCH(self):
        if not self._forward_or_none():
            self.send_error(404)

    def do_DELETE(self):
        if not self._forward_or_none():
            self.send_error(404)

    def do_OPTIONS(self):
        if not self._forward_or_none():
            self.send_error(404)

    def do_POST(self):
        p = self.path.split("?", 1)[0]
        if self._forward_or_none():
            return
        try:
            if p == "/unlock":
                form = self._form()
                rel = norm((form.get("path") or ["/"])[0])
                pw = (form.get("pw") or [""])[0]
                time.sleep(0.4)
                entry, scope, _ = self._rule(rel)
                if entry is None:
                    self._redirect(rel)
                elif hmac.compare_digest(sha(pw), entry.get("pw", "")):
                    self._redirect(rel, ckname(scope) + "=" + tok(scope, entry.get("pw", "")))
                else:
                    self._page(_doc(GATE, rel, "密码错误，请再试一次"))
            elif p == "/recover":
                form = self._form()
                rel = norm((form.get("path") or ["/"])[0])
                rc = (form.get("rc") or [""])[0]
                npw = (form.get("npw") or [""])[0]
                npw2 = (form.get("npw2") or [""])[0]
                time.sleep(0.4)
                entry, scope, rules = self._rule(rel)
                if entry is None:
                    self._redirect(rel)
                elif not hmac.compare_digest(sha(rc), entry.get("rc", "")):
                    self._page(_doc(RECV, rel, "恢复码错误，请核对后再试"))
                elif len(npw) < 4 or npw != npw2:
                    self._page(_doc(RECV, rel, "新密码至少 4 位且两次输入需一致"))
                else:
                    rules[scope]["pw"] = sha(npw)
                    save_rules(rules)
                    self._redirect(rel, ckname(scope) + "=" + tok(scope, sha(npw)))
            else:
                self.send_error(404)
        except Exception:
            self.send_error(400)

BIND = os.environ.get("SHARECT_BIND", "127.0.0.1")
httpd = http.server.ThreadingHTTPServer((BIND, port), functools.partial(Handler, directory=root))
httpd.serve_forever()
