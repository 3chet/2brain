#!/usr/bin/env node
/*
 * 2brain-mcp.mjs — 2brain 只读 MCP server（stdio JSON-RPC 2.0，零依赖）
 *
 * 从 <index>/index.jsonl 读取离线索引，提供 5 个只读工具：
 *   brain_search  brain_recent  brain_get  brain_stats  brain_tags
 *
 * 启动：
 *   node tools/2brain-mcp.mjs
 *   TWOBRAIN_INDEX=D:\path\to\index node tools/2brain-mcp.mjs
 *   node tools/2brain-mcp.mjs --index D:\path\to\index
 *
 * 默认索引目录：~/.2brain/index（由 tools/2brain-index.mjs 生成）。
 * 只返回元数据 + 摘要，不返回正文全文；不提供任何写工具。
 * 日志一律写 stderr，stdout 只用于 JSON-RPC。
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { pathToFileURL } from 'node:url';

const SERVER_INFO = { name: '2brain-mcp', version: '0.1.0' };
const PROTOCOL_VERSION = '2024-11-05';
const MAX_LIMIT = 100;
const DEFAULT_LIMIT = 20;
const MAX_RESPONSE_BYTES = 64 * 1024;

function parseCli(argv){
  let dir = process.env.TWOBRAIN_INDEX || path.join(os.homedir(), '.2brain', 'index');
  for(let i = 0; i < argv.length; i++){
    if(argv[i] === '--index'){
      const v = argv[++i];
      if(!v){ console.error('missing value for --index'); process.exit(2); }
      dir = v;
    }else if(argv[i] === '--help' || argv[i] === '-h'){
      console.log('Usage: node tools/2brain-mcp.mjs [--index <dir>]\n' +
                  'Env: TWOBRAIN_INDEX (default ~/.2brain/index)');
      process.exit(0);
    }else{
      console.error('unknown option: ' + argv[i]);
      process.exit(2);
    }
  }
  return path.resolve(dir);
}

const INDEX_DIR = parseCli(process.argv.slice(2));

let cache = {
  metaMtime: -1,
  jsonlMtime: -1,
  meta: null,
  rows: [],
  error: 'not_loaded'
};

function loadIndex(force){
  const metaPath = path.join(INDEX_DIR, 'index.meta.json');
  const jsonlPath = path.join(INDEX_DIR, 'index.jsonl');
  let metaStat;
  let jsonlStat;
  try{
    metaStat = fs.statSync(metaPath);
    jsonlStat = fs.statSync(jsonlPath);
  }catch(e){
    cache = { metaMtime: -1, jsonlMtime: -1, meta: null, rows: [], error: 'index_not_found' };
    return cache;
  }
  if(!force && cache.metaMtime === metaStat.mtimeMs && cache.jsonlMtime === jsonlStat.mtimeMs){
    return cache;
  }
  try{
    const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
    const lines = fs.readFileSync(jsonlPath, 'utf8').split(/\r?\n/).filter(Boolean);
    const rows = [];
    let badLines = 0;
    for(const line of lines){
      try{
        const row = JSON.parse(line);
        if(row && typeof row.id === 'string') rows.push(row);
        else badLines += 1;
      }catch(e){ badLines += 1; }
    }
    cache = {
      metaMtime: metaStat.mtimeMs,
      jsonlMtime: jsonlStat.mtimeMs,
      meta: { ...meta, badLines },
      rows,
      error: null
    };
  }catch(e){
    cache = { metaMtime: -1, jsonlMtime: -1, meta: null, rows: [], error: 'index_unreadable: ' + e.message };
  }
  return cache;
}

function pickNote(row){
  return {
    id: row.id,
    short: row.short || '',
    title: row.title || '',
    excerpt: row.excerpt || '',
    tags: Array.isArray(row.tags) ? row.tags : [],
    status: row.status || '',
    nodeId: row.nodeId || '',
    path: row.path || '',
    links: Array.isArray(row.links) ? row.links : [],
    visibility: row.visibility || 'meta',
    createdAt: Number(row.createdAt) || 0,
    updatedAt: Number(row.updatedAt) || 0,
    truncated: !!row.truncated
  };
}

function byRecent(a, b){
  return (Number(b.updatedAt) || 0) - (Number(a.updatedAt) || 0) ||
         (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
}

function toLimit(v){
  const n = Number(v);
  if(!Number.isFinite(n)) return DEFAULT_LIMIT;
  return Math.max(1, Math.min(MAX_LIMIT, Math.floor(n)));
}

function toTime(v){
  if(v === undefined || v === null || v === '') return 0;
  if(typeof v === 'number' && Number.isFinite(v)) return v;
  const n = Number(v);
  if(Number.isFinite(n)) return n;
  const t = Date.parse(String(v));
  return Number.isFinite(t) ? t : 0;
}

function lowerList(v){
  return (Array.isArray(v) ? v : []).map(x => String(x).toLowerCase());
}

function searchNotes(rows, args){
  const q = String(args.q || '').trim().toLowerCase();
  const tokens = q ? q.split(/\s+/).filter(Boolean) : [];
  const tag = String(args.tag || '').trim().toLowerCase();
  const nodeId = String(args.nodeId || '').trim();
  const status = String(args.status || '').trim();
  const hits = rows.filter(r => {
    if(tag && !lowerList(r.tags).includes(tag)) return false;
    if(nodeId && r.nodeId !== nodeId) return false;
    if(status && r.status !== status) return false;
    if(tokens.length){
      const hay = [r.title, r.excerpt, (r.tags || []).join(' '), r.path, r.status]
        .join(' ').toLowerCase();
      if(!tokens.every(t => hay.includes(t))) return false;
    }
    return true;
  });
  hits.sort(byRecent);
  const limit = toLimit(args.limit);
  return { total: hits.length, returned: Math.min(limit, hits.length), notes: hits.slice(0, limit).map(pickNote) };
}

function recentNotes(rows, args){
  const since = toTime(args.since);
  const hits = rows.filter(r => (Number(r.updatedAt) || 0) >= since);
  hits.sort(byRecent);
  const limit = toLimit(args.limit);
  return { total: hits.length, returned: Math.min(limit, hits.length), since, notes: hits.slice(0, limit).map(pickNote) };
}

function resolveNote(rows, raw){
  const q = String(raw || '').trim().replace(/^#/, '');
  if(!q) return { found: false, reason: 'empty' };
  const exact = rows.filter(r => r.id === q);
  if(exact.length === 1) return { found: true, note: pickNote(exact[0]) };
  const lower = q.toLowerCase();
  const byShort = rows.filter(r => r.short && r.short.toLowerCase() === lower);
  if(byShort.length === 1) return { found: true, note: pickNote(byShort[0]) };
  if(q.length < 3) return { found: false, reason: 'prefix_too_short', hint: 'Use at least 3 characters, or the full id.' };
  const hits = rows.filter(r =>
    r.id.toLowerCase().startsWith(lower) ||
    (r.short && r.short.toLowerCase().startsWith(lower)));
  if(hits.length === 1) return { found: true, note: pickNote(hits[0]) };
  if(hits.length > 1){
    return {
      found: false,
      reason: 'ambiguous',
      count: hits.length,
      candidates: hits.slice(0, 10).map(r => ({
        id: r.id, short: r.short, title: r.title, updatedAt: r.updatedAt
      }))
    };
  }
  return { found: false, reason: 'not_found', hint: 'Try brain_search first.' };
}

function stats(){
  const byVisibility = { off: 0, meta: 0, full: 0 };
  for(const r of cache.rows){
    const v = r.visibility === 'full' ? 'full' : 'meta';
    byVisibility[v] += 1;
  }
  return {
    count: cache.rows.length,
    byVisibility,
    format: cache.meta ? cache.meta.format : null,
    generatedAt: cache.meta ? cache.meta.generatedAt : null,
    encrypted: cache.meta ? !!cache.meta.encrypted : false,
    source: cache.meta ? cache.meta.source : null,
    skipped: cache.meta ? cache.meta.skipped : null,
    truncated: cache.meta ? cache.meta.truncated : null,
    badLines: cache.meta ? cache.meta.badLines : 0,
    indexDir: INDEX_DIR,
    stale: null,
    staleReason: 'offline bundle index; no server revision'
  };
}

function tagCounts(rows){
  const counts = new Map();
  for(const r of rows){
    for(const t of Array.isArray(r.tags) ? r.tags : []){
      const tag = String(t);
      counts.set(tag, (counts.get(tag) || 0) + 1);
    }
  }
  const tags = [...counts.entries()]
    .map(([tag, count]) => ({ tag, count }))
    .sort((a, b) => b.count - a.count || (a.tag < b.tag ? -1 : 1));
  return { total: tags.length, tags };
}

function requireIndex(){
  loadIndex(false);
  if(cache.error){
    const msg = cache.error === 'index_not_found'
      ? 'No index found at ' + INDEX_DIR + '. Generate it with: node tools/2brain-index.mjs --bundle <export.json>'
      : cache.error;
    throw new Error(msg);
  }
}

const TOOLS = [
  {
    name: 'brain_search',
    description: 'Search 2brain notes by keywords, tag, category (nodeId) or status. ' +
      'Returns note metadata and a short excerpt, NOT the full text; full text is visible only in the 2brain web app. ' +
      'Space-separated q terms are ANDed. Sort: updatedAt desc.',
    inputSchema: {
      type: 'object',
      properties: {
        q: { type: 'string', description: 'Keywords matched against title/excerpt/tags/path. Space-separated = AND.' },
        tag: { type: 'string', description: 'Exact tag (case-insensitive).' },
        nodeId: { type: 'string', description: 'Exact category id, e.g. life_home.' },
        status: { type: 'string', description: 'Exact status string, e.g. 待处理.' },
        limit: { type: 'integer', minimum: 1, maximum: MAX_LIMIT, default: DEFAULT_LIMIT }
      },
      additionalProperties: false
    }
  },
  {
    name: 'brain_recent',
    description: 'List recently updated 2brain notes. Returns metadata + excerpt, not full text.',
    inputSchema: {
      type: 'object',
      properties: {
        since: { type: 'integer', description: 'Unix epoch milliseconds; only notes with updatedAt >= since.' },
        limit: { type: 'integer', minimum: 1, maximum: MAX_LIMIT, default: DEFAULT_LIMIT }
      },
      additionalProperties: false
    }
  },
  {
    name: 'brain_get',
    description: 'Get one 2brain note by full id, 5-character short code, or unique id prefix (>= 3 chars). ' +
      'Returns metadata + excerpt, NOT full text. Use brain_search first if the id is unknown.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Full id (n_...), short code (e.g. b7c9x), #short, or unique prefix.' }
      },
      required: ['id'],
      additionalProperties: false
    }
  },
  {
    name: 'brain_stats',
    description: 'Show 2brain index statistics: note count, visibility breakdown, source bundle, generation time. ' +
      'Call this before querying to confirm the index is present and how fresh it is.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false }
  },
  {
    name: 'brain_tags',
    description: 'List all tags in the 2brain index with counts, sorted by count desc.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false }
  }
];

function callTool(name, args){
  if(name === 'brain_search'){ requireIndex(); return searchNotes(cache.rows, args); }
  if(name === 'brain_recent'){ requireIndex(); return recentNotes(cache.rows, args); }
  if(name === 'brain_get'){
    requireIndex();
    if(!args.id) throw new Error('id is required');
    return resolveNote(cache.rows, args.id);
  }
  if(name === 'brain_stats'){ requireIndex(); return stats(); }
  if(name === 'brain_tags'){ requireIndex(); return tagCounts(cache.rows); }
  throw new Error('unknown tool: ' + name);
}

function sizeLimited(result){
  let text = JSON.stringify(result);
  if(Buffer.byteLength(text, 'utf8') <= MAX_RESPONSE_BYTES) return { result, text };
  if(!Array.isArray(result.notes)) return { result, text };
  const notes = result.notes.slice();
  while(notes.length){
    notes.pop();
    const next = { ...result, notes, truncatedBySize: true };
    text = JSON.stringify(next);
    if(Buffer.byteLength(text, 'utf8') <= MAX_RESPONSE_BYTES) return { result: next, text };
  }
  const next = { ...result, notes: [], truncatedBySize: true };
  return { result: next, text: JSON.stringify(next) };
}

function toolResult(id, payload, isError){
  loadIndex(false);
  const limited = sizeLimited(payload);
  return {
    jsonrpc: '2.0',
    id,
    result: {
      content: [{ type: 'text', text: limited.text }],
      structuredContent: limited.result,
      isError: !!isError
    }
  };
}

function handle(msg){
  if(!msg || typeof msg !== 'object' || Array.isArray(msg)){
    return { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } };
  }
  const { id, method, params } = msg;
  const isNotification = id === undefined || id === null;

  if(method === 'initialize'){
    return {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: (params && typeof params.protocolVersion === 'string')
          ? params.protocolVersion : PROTOCOL_VERSION,
        capabilities: { tools: { listChanged: false } },
        serverInfo: SERVER_INFO,
        instructions: 'Read-only access to a 2brain index: metadata + excerpts only, never full note text. ' +
          'Call brain_stats first. No write tools are exposed.'
      }
    };
  }
  if(method === 'ping') return { jsonrpc: '2.0', id, result: {} };
  if(method === 'tools/list') return { jsonrpc: '2.0', id, result: { tools: TOOLS } };

  if(method === 'tools/call'){
    if(isNotification) return null;
    const name = params && params.name;
    const args = (params && params.arguments && typeof params.arguments === 'object') ? params.arguments : {};
    if(typeof name !== 'string' || !TOOLS.some(t => t.name === name)){
      return { jsonrpc: '2.0', id, error: { code: -32602, message: 'Unknown tool: ' + name } };
    }
    try{
      return toolResult(id, callTool(name, args), false);
    }catch(e){
      return toolResult(id, { error: e.message }, true);
    }
  }

  if(isNotification) return null;
  return { jsonrpc: '2.0', id, error: { code: -32601, message: 'Method not found: ' + method } };
}

function send(obj){
  if(obj) process.stdout.write(JSON.stringify(obj) + '\n');
}

function main(){
  const loaded = loadIndex(false);
  const state = loaded.error ? loaded.error : (loaded.rows.length + ' notes');
  console.error('[2brain-mcp] index=' + INDEX_DIR + ' status=' + state);

  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  rl.on('line', line => {
    const trimmed = line.trim();
    if(!trimmed) return;
    let msg;
    try{ msg = JSON.parse(trimmed); }
    catch(e){
      send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
      return;
    }
    if(Array.isArray(msg)){
      const out = msg.map(handle).filter(Boolean);
      if(out.length) send(out);
      return;
    }
    send(handle(msg));
  });
  rl.on('close', () => process.exit(0));
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if(isMain) main();

export { searchNotes, recentNotes, resolveNote, stats, tagCounts, callTool, TOOLS };
