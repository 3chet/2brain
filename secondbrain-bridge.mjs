#!/usr/bin/env node
/* ============================================================================
   secondbrain-bridge.mjs  ——  2brain ⇄ mnemon 本地桥
   ----------------------------------------------------------------------------
   作用：2brain 是单文件 HTML，在 file:// 下无法 spawn 子进程。
         这座桥是它的可选附属进程，把浏览器的 HTTP 请求翻译成 mnemon CLI 调用，
         让 2brain 写进去的笔记能被 DSH（dsh-mnemon / provider: mnemon-native）直接召回。

   特点：零依赖、只监听 127.0.0.1、端点白名单、不接受客户端传来的任意 CLI 参数。

   启动：
     node secondbrain-bridge.mjs
     node secondbrain-bridge.mjs --port 7723 --data-dir "D:\agent AI\Ⅱ brain\.mnemon"

   环境变量：
     IIIBRAIN_MNEMON_BIN    mnemon 可执行文件全路径（默认自动探测）
     IIIBRAIN_MNEMON_DIR    记忆库数据目录（留空 = mnemon 默认 ~/.mnemon，即与 DSH 共用）
     IIIBRAIN_MNEMON_STORE  命名库（可选，对应 mnemon --store）
     IIIBRAIN_BRIDGE_PORT   端口，默认 7723
     IIIBRAIN_BRIDGE_TOKEN  若设置，则请求需带 Authorization: Bearer <token>

   端点：
     GET  /health              桥 + CLI + 库状态探测
     GET  /status              mnemon status（JSON）
     GET  /search?q=..&limit=  token 检索（JSON，--brief）
     POST /search              { q, limit }
     POST /import              memory draft JSON（schema_version "1"）→ mnemon import
                               ?dry=1 走 --dry-run 只校验不落库
     POST /remember            { content, category, importance, tags[], entities[] }
     GET  /related?id=..&depth=  图遍历（需要 mnemon id）
     POST /ai/proxy            { url, method, apiKey?, payload?, timeoutMs? }
                                → 转发模型服务（模型服务不带跨域头时借桥出面，绕开浏览器限制）
     POST /fetch/url           { url } → 抓公网文章正文（SSRF 防护，上限 2MB）
   ============================================================================ */

import { createServer } from 'node:http';
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { lookup } from 'node:dns/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

/* ---------- 参数与环境 ---------- */
function argVal(name, def) {
  const i = process.argv.indexOf(name);
  if (i >= 0 && process.argv[i + 1]) return process.argv[i + 1];
  const hit = process.argv.find(a => a.startsWith(name + '='));
  return hit ? hit.slice(name.length + 1) : def;
}

const PORT      = Number(argVal('--port', process.env.IIIBRAIN_BRIDGE_PORT || 7723));
const DATA_DIR  = argVal('--data-dir', process.env.IIIBRAIN_MNEMON_DIR || '');
const STORE     = argVal('--store',    process.env.IIIBRAIN_MNEMON_STORE || '');
const TOKEN     = process.env.IIIBRAIN_BRIDGE_TOKEN || '';
const HOST      = '127.0.0.1';
const MAX_BODY  = 32 * 1024 * 1024;   // 全库 draft 也放得下
const RUN_TIMEOUT = 15 * 60 * 1000;   // 大批量 import + embedding 可能很慢

/* ---------- 定位 mnemon 可执行文件 ----------
   坑 1：Node ≥18.20 / 20.12 / 22 在 Windows 上直接 spawn .cmd / .bat 会 EINVAL
         （CVE-2024-27980 的修复），所以优先用原生 .exe 或 node + bin/mnemon.js。
   坑 2：PowerShell 执行策略禁止 mnemon.ps1，绕开它。                        */
function resolveMnemon() {
  const APPDATA = process.env.APPDATA || '';
  const GLOBAL  = path.join(APPDATA, 'npm', 'node_modules', '@mnemon-dev', 'mnemon');
  const binName = process.platform === 'win32' ? 'mnemon.exe' : 'mnemon';
  const candidates = [
    // 1) 显式指定
    process.env.IIIBRAIN_MNEMON_BIN,
    // 2) 平台原生二进制（最快，且不受 .cmd 限制）
    path.join(GLOBAL, 'node_modules', '@mnemon-dev', `mnemon-${process.platform}-${process.arch}`, 'bin', binName),
    // 3) npm 全局 shim 同目录下的 node 脚本
    path.join(GLOBAL, 'bin', 'mnemon.js'),
  ].filter(Boolean);

  for (const c of candidates) {
    if (existsSync(c)) {
      if (c.endsWith('.js')) return { cmd: process.execPath, pre: [c], how: 'node-script' };
      return { cmd: c, pre: [], how: 'native-binary' };
    }
  }
  // 4) 交给 PATH（需要 shell 才能跑 .cmd）
  return { cmd: process.platform === 'win32' ? 'mnemon.cmd' : 'mnemon', pre: [], how: 'path-shim', shell: true };
}

const MNEMON = resolveMnemon();

/* ---------- 调 CLI ---------- */
function mnemon(args, { readonly = false, bare = false } = {}) {
  const argv = [...MNEMON.pre, ...args];
  if (!bare) {
    if (DATA_DIR) argv.push('--data-dir', DATA_DIR);
    if (STORE) argv.push('--store', STORE);
    if (readonly) argv.push('--readonly');
  }

  return new Promise((resolve) => {
    execFile(MNEMON.cmd, argv, {
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
      windowsHide: true,
      timeout: RUN_TIMEOUT,
      shell: !!MNEMON.shell,
    }, (err, stdout, stderr) => {
      if (err) return resolve({ ok: false, code: err.code ?? err.errno ?? 'ERR',
                                error: String(stderr || err.message || err).trim(),
                                out: String(stdout || ''), err: String(stderr || '') });
      resolve({ ok: true, out: String(stdout || ''), err: String(stderr || '') });
    });
  });
}

/* 读操作返回 JSON；解析失败就把原文回传，方便排查。
   注意：--dry-run 的提示信息走 stderr，所以两条流都要带上。 */
async function mnemonJSON(args, opts) {
  const r = await mnemon(args, opts);
  if (!r.ok) return r;
  const text = (r.out + r.err).trim();
  try { return { ok: true, data: JSON.parse(r.out || '{}'), text: r.err.trim() }; }
  catch { return { ok: true, raw: text }; }
}

/* ---------- HTTP 工具 ---------- */
function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');           // file:// 的 Origin 是 null
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Private-Network', 'true');   // Chrome 本地网络访问预检
  res.setHeader('Cache-Control', 'no-store');
}
function sendJSON(res, code, obj) {
  cors(res);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let n = 0; const chunks = [];
    req.on('data', (c) => {
      n += c.length;
      if (n > MAX_BODY) { reject(new Error('请求体过大（上限 32MB）')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}
function authorized(req) {
  if (!TOKEN) return true;
  return (req.headers['authorization'] || '') === 'Bearer ' + TOKEN;
}
const clampLimit = (v) => Math.min(50, Math.max(1, Number(v) || 10));

/* /ai/proxy 的目标地址防护：桥没设 token 时仅允许内网/回环目标；
   要转发公网 API，请设 IIIBRAIN_BRIDGE_TOKEN（页面端填同一个 token 到「同步 Key」）。 */
function isPrivateHost(h) {
  h = String(h || '').toLowerCase();
  if (h === 'localhost' || h.endsWith('.local')) return true;
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (m) {
    const a = +m[1], b = +m[2];
    if (a === 10 || a === 127 || a === 169 && b === 254) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
  }
  return h === '::1' || h.startsWith('fc') || h.startsWith('fd');
}

/* ---------- /fetch/url：公网文章抓取 ----------
   桥是本机进程，绝不能变成打内网的跳板：私网 / 回环 / 链路本地 / 元数据地址
   以及解析到这些地址的域名一律拒绝；跳转逐跳复核，响应上限 2MB。 */
const FETCH_TIMEOUT = 15000;
const FETCH_MAX_BYTES = 2 * 1024 * 1024;

function isBlockedFetchHost(h) {
  h = String(h || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (!h) return true;
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal')) return true;
  if (h === '::1' || h === '::' || h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80')) return true;
  if (h.startsWith('::ffff:')) return isBlockedFetchHost(h.slice(7));
  if (/^(0x[0-9a-f]+|\d+)$/i.test(h)) return true;          // 十进制/十六进制 IP 变体
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (m) {
    const a = +m[1], b = +m[2];
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;                // 含云元数据 169.254.169.254
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;      // CGNAT
    if (a === 198 && (b === 18 || b === 19)) return true;
  }
  return false;
}

async function assertPublicUrl(u) {
  if (!/^https?:$/.test(u.protocol)) throw new Error('仅允许 http/https 链接');
  if (u.username || u.password) throw new Error('链接不能带用户名或密码');
  if (isBlockedFetchHost(u.hostname)) throw new Error('只允许抓取公网页面（内网/本机地址已拒绝）');
  let addrs;
  try { addrs = await lookup(u.hostname, { all: true, verbatim: true }); }
  catch { throw new Error('域名解析失败：' + u.hostname); }
  if (!addrs.length) throw new Error('域名没有解析结果');
  for (const a of addrs) {
    if (isBlockedFetchHost(a.address)) throw new Error('域名解析到内网地址，已拒绝');
  }
}

async function readLimited(r, max) {
  if (!r.body) return '';
  const reader = r.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      try { await reader.cancel(); } catch {}
      throw new Error('页面超过 2MB，已停止抓取');
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks).toString('utf8');
}

function decodeEntities(s) {
  return String(s)
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => { try { return String.fromCodePoint(parseInt(h, 16)); } catch { return ''; } })
    .replace(/&#(\d+);/g, (_, d) => { try { return String.fromCodePoint(+d); } catch { return ''; } })
    .replace(/&nbsp;/gi, ' ').replace(/&amp;/gi, '&').replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>').replace(/&quot;/gi, '"').replace(/&#39;|&apos;/gi, "'");
}

function extractArticle(html) {
  let title = '';
  const og = /<meta[^>]+property=["']og:title["'][^>]*content=["']([^"']*)["']/i.exec(html)
          || /<meta[^>]+content=["']([^"']*)["'][^>]*property=["']og:title["']/i.exec(html);
  if (og) title = decodeEntities(og[1]);
  if (!title) {
    const tm = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html);
    if (tm) title = decodeEntities(tm[1]);
  }
  title = title.replace(/\s+/g, ' ').trim().slice(0, 200);

  let body = html
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<(script|style|noscript|svg|canvas|iframe|template)[^>]*>[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<(nav|header|footer|aside|form|button|select|textarea)[^>]*>[\s\S]*?<\/\1>/gi, ' ');
  const main = /<article[^>]*>([\s\S]*?)<\/article>/i.exec(body)
            || /<main[^>]*>([\s\S]*?)<\/main>/i.exec(body);
  if (main) body = main[1];
  body = body
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(p|div|li|h[1-6]|tr|blockquote|section|article)>/gi, '\n')
    .replace(/<[^>]+>/g, ' ');
  let text = decodeEntities(body)
    .replace(/\r/g, '')
    .split('\n')
    .map(l => l.replace(/[ \t\f\v]+/g, ' ').trim())
    .filter(Boolean)
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
  if (text.length > 30000) text = text.slice(0, 30000);
  return { title, text };
}

async function fetchPublicPage(rawUrl) {
  let current;
  try { current = new URL(String(rawUrl || '')); }
  catch { throw new Error('url 非法'); }
  for (let hop = 0; hop < 4; hop++) {
    await assertPublicUrl(current);
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT);
    try {
      const r = await fetch(current, {
        redirect: 'manual',
        signal: ctrl.signal,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126 Safari/537.36 2brain-bridge',
          'Accept': 'text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.1',
          'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.6',
        },
      });
      if (r.status >= 300 && r.status < 400) {
        const loc = r.headers.get('location');
        if (!loc) throw new Error('页面跳转缺少 Location');
        current = new URL(loc, current);
        continue;
      }
      if (!r.ok) throw new Error('页面返回 HTTP ' + r.status);
      const ct = String(r.headers.get('content-type') || '').toLowerCase();
      if (ct && !/text\/html|application\/xhtml|text\/plain/.test(ct))
        throw new Error('不是网页内容（' + ct.split(';')[0] + '）');
      const html = await readLimited(r, FETCH_MAX_BYTES);
      return { finalUrl: current.href, html };
    } catch (e) {
      if (e && e.name === 'AbortError') throw new Error('抓取超时（15 秒）');
      throw e;
    } finally {
      clearTimeout(timer);
    }
  }
  throw new Error('页面跳转次数过多');
}

/* ---------- 路由 ---------- */
const server = createServer(async (req, res) => {
  if (req.method === 'OPTIONS') { cors(res); res.writeHead(204); res.end(); return; }
  if (!authorized(req)) return sendJSON(res, 401, { ok: false, error: '未授权：需要 Bearer token' });

  const url = new URL(req.url, `http://${HOST}:${PORT}`);
  const p = url.pathname.replace(/\/+$/, '') || '/';

  try {
    /* --- 健康探测：monaco 页面用它决定是否启用 --- */
    if (p === '/health' && req.method === 'GET') {
      const ver = await mnemon(['--version'], { bare: true });
      const st  = await mnemonJSON(['status'], { readonly: true });
      return sendJSON(res, 200, {
        ok: true,
        bridge: 'secondbrain-bridge',
        resolvedBy: MNEMON.how,
        cli: MNEMON.cmd,
        dataDir: DATA_DIR || '(mnemon 默认: ~/.mnemon)',
        store: STORE || '(默认 default)',
        version: (ver.out || ver.error || '').trim(),
        memory: st.ok ? (st.data || {}) : { error: st.error || 'status 读取失败' },
      });
    }

    if (p === '/status' && req.method === 'GET') {
      const r = await mnemonJSON(['status'], { readonly: true });
      return sendJSON(res, r.ok ? 200 : 502, r.ok ? r.data : { ok: false, error: r.error });
    }

    /* --- AI 转发：模型服务（gptload/中转等）不带跨域头，页面 file:// 下无法直连，
           借桥出面（桥自带 CORS 头，页面本来就能调桥）。
           POST { url, method: GET|POST, apiKey?, payload?, timeoutMs? }
           → 服务端 fetch 目标地址，原文回传 { ok, status, bodyText }（Key 不写日志）。 --- */
    if (p === '/ai/proxy' && req.method === 'POST') {
      const b = JSON.parse(await readBody(req) || '{}');
      let u;
      try { u = new URL(String(b.url || '')); }
      catch { return sendJSON(res, 400, { ok: false, error: 'url 非法' }); }
      if (!/^https?:$/.test(u.protocol)) return sendJSON(res, 400, { ok: false, error: '仅允许 http/https' });
      if (!TOKEN && !isPrivateHost(u.hostname))
        return sendJSON(res, 403, { ok: false, error: '转发公网目标需要先给桥设 token（IIIBRAIN_BRIDGE_TOKEN=xxx 启动，页面「同步 Key」填同一个）' });
      const method = String(b.method || 'GET').toUpperCase() === 'POST' ? 'POST' : 'GET';
      const headers = { 'Content-Type': 'application/json' };
      if (b.apiKey) headers['Authorization'] = 'Bearer ' + String(b.apiKey);
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(),
        Math.min(120000, Math.max(2000, Number(b.timeoutMs) || 25000)));
      try {
        const r2 = await fetch(u, {
          method,
          headers,
          signal: ctrl.signal,
          body: method === 'POST' ? JSON.stringify(b.payload || {}) : undefined,
        });
        const text = await r2.text();
        return sendJSON(res, 200, { ok: true, status: r2.status, bodyText: text.slice(0, 60000) });
      } catch (e) {
        return sendJSON(res, 502, { ok: false, error: e.name === 'AbortError' ? '转发超时' : String(e && e.message || e) });
      } finally {
        clearTimeout(timer);
      }
    }

    /* --- 抓文章正文：给编辑器的 AI 摘要用。只抓公网 http(s)，不做登录态转发。 --- */
    if (p === '/fetch/url' && req.method === 'POST') {
      let b;
      try { b = JSON.parse(await readBody(req) || '{}'); }
      catch { return sendJSON(res, 400, { ok: false, error: '请求体不是合法 JSON' }); }
      try {
        const page = await fetchPublicPage(b.url);
        const art = extractArticle(page.html);
        if (!art.text) return sendJSON(res, 422, { ok: false, error: '没抽到正文（页面可能需要登录，或内容由脚本动态渲染）' });
        return sendJSON(res, 200, {
          ok: true, url: page.finalUrl, title: art.title,
          text: art.text, chars: art.text.length,
        });
      } catch (e) {
        return sendJSON(res, 502, { ok: false, error: String((e && e.message) || e) });
      }
    }

    if (p === '/search') {
      let q = '', limit = 10;
      if (req.method === 'GET') { q = url.searchParams.get('q') || ''; limit = url.searchParams.get('limit'); }
      else if (req.method === 'POST') {
        const body = JSON.parse(await readBody(req) || '{}');
        q = body.q || ''; limit = body.limit;
      } else return sendJSON(res, 405, { ok: false, error: 'method not allowed' });

      if (!q.trim()) return sendJSON(res, 400, { ok: false, error: '缺少 q 参数' });
      const r = await mnemonJSON(['search', q, '--brief', '--limit', String(clampLimit(limit))], { readonly: true });
      return sendJSON(res, r.ok ? 200 : 502, r.ok ? r.data : { ok: false, error: r.error });
    }

    if (p === '/related' && req.method === 'GET') {
      const id = url.searchParams.get('id');
      if (!id) return sendJSON(res, 400, { ok: false, error: '缺少 id 参数' });
      const depth = Math.min(4, Math.max(1, Number(url.searchParams.get('depth')) || 2));
      const args = ['related', id, '--depth', String(depth)];
      const edge = url.searchParams.get('edge');
      if (edge && /^(causal|entity|semantic|supersedes|temporal)$/.test(edge)) args.push('--edge', edge);
      const r = await mnemonJSON(args, { readonly: true });
      return sendJSON(res, r.ok ? 200 : 502, r.ok ? r.data : { ok: false, error: r.error });
    }

    /* --- 批量导入：2brain 的 draft --- */
    if (p === '/import' && req.method === 'POST') {
      const body = await readBody(req);
      let draft;
      try { draft = JSON.parse(body); }
      catch { return sendJSON(res, 400, { ok: false, error: '请求体不是合法 JSON' }); }
      if (draft.schema_version !== '1' || !Array.isArray(draft.insights)) {
        return sendJSON(res, 400, { ok: false, error: 'draft 缺少 schema_version:"1" 或 insights 数组' });
      }
      const dir = await mkdtemp(path.join(tmpdir(), 'iibrain-'));
      const file = path.join(dir, 'memory_draft.json');
      // 关键：UTF-8 且不带 BOM，否则 mnemon 的 JSON 解码会失败
      await writeFile(file, body, 'utf8');
      const args = ['import', file];
      if (url.searchParams.get('dry')) args.push('--dry-run');
      const r = await mnemonJSON(args);
      await rm(dir, { recursive: true, force: true }).catch(() => {});
      if (!r.ok) return sendJSON(res, 502, { ok: false, error: r.error });
      // dry-run 的校验结论走 stderr（note 字段带回给页面）
      if (r.data) return sendJSON(res, 200, r.text ? Object.assign({}, r.data, { note: r.text }) : r.data);
      return sendJSON(res, 200, { ok: true, output: r.raw || '' });
    }

    /* --- 删除（软删，对应 2brain 里的删除笔记；未经 2brain 自动调用，仅暴露能力） --- */
    if (p === '/forget' && req.method === 'POST') {
      let id = '';
      try { id = String(JSON.parse(await readBody(req) || '{}').id || '').trim(); } catch {}
      if (!id) return sendJSON(res, 400, { ok: false, error: '缺少 id' });
      const r = await mnemonJSON(['forget', id]);
      return sendJSON(res, r.ok ? 200 : 502,
        r.ok ? (r.data || { ok: true, output: (r.out + r.err).trim() }) : { ok: false, error: r.error });
    }

    /* --- 单条写入 --- */
    if (p === '/remember' && req.method === 'POST') {
      const b = JSON.parse(await readBody(req) || '{}');
      if (!b.content || !String(b.content).trim()) return sendJSON(res, 400, { ok: false, error: '缺少 content' });
      const args = ['remember', String(b.content)];
      if (b.category) args.push('--cat', String(b.category));
      if (b.importance) args.push('--imp', String(Math.min(5, Math.max(1, Number(b.importance) || 3))));
      if (Array.isArray(b.tags) && b.tags.length) args.push('--tags', b.tags.slice(0, 20).join(','));
      if (Array.isArray(b.entities) && b.entities.length) args.push('--entities', b.entities.slice(0, 50).join(','));
      const r = await mnemonJSON(args);
      return sendJSON(res, r.ok ? 200 : 502, r.ok ? r.data : { ok: false, error: r.error });
    }

    return sendJSON(res, 404, { ok: false, error: '未知端点: ' + p });
  } catch (e) {
    return sendJSON(res, 500, { ok: false, error: String(e && e.message || e) });
  }
});

server.listen(PORT, HOST, () => {
  console.log('2brain ⇄ mnemon bridge 已启动');
  console.log('  监听      http://' + HOST + ':' + PORT);
  console.log('  mnemon    ' + MNEMON.cmd + '  (' + MNEMON.how + ')');
  console.log('  数据目录  ' + (DATA_DIR || '(mnemon 默认 ~/.mnemon —— 与 DSH 共用)'));
  console.log('  命名库    ' + (STORE || '(default)'));
  console.log('  鉴权      ' + (TOKEN ? 'Bearer token 已启用' : '未启用（仅本机可访问）'));
  console.log('  停止      Ctrl+C');
});
