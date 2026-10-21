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
   ============================================================================ */

import { createServer } from 'node:http';
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
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
