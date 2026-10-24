#!/usr/bin/env node
/*
 * 2brain-index.mjs — 从「导出 JSON」生成 agent 只读索引（零服务端改动）
 *
 * 用法：
 *   node tools/2brain-index.mjs --bundle 2brain-backup-YYYY-MM-DD.json
 *   node tools/2brain-index.mjs --bundle export.json --out ./index
 *   node tools/2brain-index.mjs --bundle - --out ./index          # 从 stdin 读
 *
 * 增量（P5）：导出文件带 `oplog`（每库单调 seq）时，工具用 <out>/state.json
 * 记住上次的 seq 与每条笔记的内容指纹；日志连续且指纹对得上就只重算变化的条目，
 * 否则自动回退整表重建。选筛选参数（--only/--tag/--node）时总是整表重建。
 *   --state <file>   状态文件路径，默认 <out>/state.json
 *   --full           忽略状态文件，强制整表重建
 *
 * 可选筛选（同时给出时取交集）：
 *   --only n_abc123,b7c9x  只导出指定笔记（完整 id / 短号 / 唯一前缀）
 *   --tag 装修,收藏        标签必须全部命中
 *   --node life_home       只导出该分类（精确 nodeId）
 *
 * 输出：<out>/index.meta.json + <out>/index.jsonl（+ state.json）
 * 默认 out = ~/.2brain/index（明文索引，不要放进仓库或第三方同步盘）。
 *
 * 退出码：0 成功；2 输入不合法。
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { pathToFileURL } from 'node:url';

const FORMAT = '2brain-index/1';
const STATE_FORMAT = '2brain-index-state/1';
const EXCERPT_META = 300;
const EXCERPT_FULL = 4000;
const TITLE_MAX = 120;
const SHORT_LEN = 5;
const VISIBILITIES = new Set(['off', 'meta', 'full']);

function usage(){
  return [
    'Usage: node tools/2brain-index.mjs --bundle <export.json|-> [options]',
    '',
    'Options:',
    '  --bundle <file>             buildBundle() 导出的 JSON（- 表示 stdin）',
    '  --out <dir>                 输出目录，默认 ~/.2brain/index',
    '  --visibility-default <v>    缺省可见性 meta|off，默认 meta',
    '  --only <ids>                逗号分隔：完整 id / 短号 / 唯一前缀',
    '  --tag <tags>                逗号分隔，标签全部命中',
    '  --node <nodeId>             精确分类 id',
    '  --state <file>              增量状态文件，默认 <out>/state.json',
    '  --full                      强制整表重建（忽略状态文件）',
    '  --quiet                     不打印统计 JSON',
    '  --help                      显示本帮助'
  ].join('\n');
}

function parseArgs(argv){
  const opts = {
    bundle: '',
    out: path.join(os.homedir(), '.2brain', 'index'),
    visibilityDefault: 'meta',
    only: [],
    tags: [],
    node: '',
    state: '',
    full: false,
    quiet: false,
    help: false
  };
  for(let i = 0; i < argv.length; i++){
    const a = argv[i];
    const val = () => {
      const v = argv[++i];
      if(v === undefined) throw new Error('missing value for ' + a);
      return v;
    };
    if(a === '--bundle') opts.bundle = val();
    else if(a === '--out') opts.out = val();
    else if(a === '--visibility-default') opts.visibilityDefault = val();
    else if(a === '--only') opts.only.push(...splitList(val()));
    else if(a === '--tag') opts.tags.push(...splitList(val()));
    else if(a === '--node') opts.node = val();
    else if(a === '--state') opts.state = val();
    else if(a === '--full') opts.full = true;
    else if(a === '--quiet') opts.quiet = true;
    else if(a === '--help' || a === '-h') opts.help = true;
    else throw new Error('unknown option: ' + a);
  }
  if(!opts.help && !opts.bundle) throw new Error('--bundle is required');
  if(!VISIBILITIES.has(opts.visibilityDefault)){
    throw new Error('--visibility-default must be meta or off');
  }
  return opts;
}

function splitList(s){
  return String(s || '').split(',').map(x => x.trim()).filter(Boolean);
}

/* 与 2brain.html 的 stripRich 对齐：去掉自定义标记与防御性 HTML 标签 */
function plainText(s){
  return String(s == null ? '' : s)
    .replace(/\r\n?/g, '\n')
    .replace(/\[(?:red|blue|black)\]/g, '')
    .replace(/\[\/(?:red|blue|black)\]/g, '')
    .replace(/\*\*/g, '')
    .replace(/~~/g, '')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/g, ' ')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, '&');
}

function firstLineTitle(content){
  const lines = plainText(content).split('\n');
  for(const line of lines){
    const t = line.replace(/\s+/g, ' ').trim();
    if(!t) continue;
    return t.length > TITLE_MAX ? t.slice(0, TITLE_MAX) + '…' : t;
  }
  return '(无标题)';
}

function makeExcerpt(content, max){
  const t = plainText(content).replace(/\s+/g, ' ').trim();
  if(t.length <= max) return { excerpt: t, truncated: false };
  return { excerpt: t.slice(0, max) + '…', truncated: true };
}

function normalizeList(v){
  if(!Array.isArray(v)) return [];
  const out = [];
  const seen = new Set();
  for(const x of v){
    if(typeof x !== 'string') continue;
    const t = x.trim();
    if(!t || seen.has(t)) continue;
    seen.add(t);
    out.push(t);
  }
  return out;
}

function visibilityOf(note, fallback){
  const v = note && note.agentVisibility;
  return VISIBILITIES.has(v) ? v : fallback;
}

function buildNodePaths(nodes){
  const byId = new Map();
  for(const n of Array.isArray(nodes) ? nodes : []){
    if(n && typeof n.id === 'string') byId.set(n.id, n);
  }
  const cache = new Map();
  function walk(id, seen){
    if(cache.has(id)) return cache.get(id);
    const n = byId.get(id);
    if(!n || seen.has(id)) return '';
    seen.add(id);
    const name = String(n.name || '').trim();
    let p = name;
    if(n.parentId && byId.has(n.parentId)){
      const parent = walk(n.parentId, seen);
      if(parent) p = parent + '/' + name;
    }
    cache.set(id, p);
    return p;
  }
  const out = new Map();
  for(const id of byId.keys()) out.set(id, walk(id, new Set()));
  return out;
}

function assignShorts(rows){
  rows.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const used = new Set();
  let collisions = 0;
  for(const row of rows){
    const id = row.id;
    let len = SHORT_LEN;
    let short = id.length > len ? id.slice(-len) : id;
    while(used.has(short) && len < id.length){
      len += 1;
      short = id.slice(-len);
      collisions += 1;
    }
    if(used.has(short)){ short = id; collisions += 1; }
    row.short = short;
    used.add(short);
  }
  return collisions;
}

function readBundle(file){
  const raw = file === '-'
    ? fs.readFileSync(0, 'utf8')
    : fs.readFileSync(file, 'utf8');
  let data;
  try{ data = JSON.parse(raw); }
  catch(e){ throw new Error('bundle is not valid JSON: ' + e.message); }
  if(!data || data.app !== '2brain') throw new Error('not a 2brain bundle (app !== "2brain")');
  if(!Array.isArray(data.notes)) throw new Error('bundle.notes is not an array');
  const sha256 = crypto.createHash('sha256').update(raw, 'utf8').digest('hex');
  return { data, sha256 };
}

/* 只读寻址：完整 id / 短号 / 前缀，供 --only 使用 */
function resolveId(rows, raw){
  const q = String(raw || '').trim().replace(/^#/, '');
  if(!q) return { found: false, reason: 'empty' };
  const lower = q.toLowerCase();
  const exact = rows.filter(r => r.id === q);
  if(exact.length === 1) return { found: true, row: exact[0] };
  const byShort = rows.filter(r => r.short && r.short.toLowerCase() === lower);
  if(byShort.length === 1) return { found: true, row: byShort[0] };
  if(q.length < 3) return { found: false, reason: 'prefix_too_short' };
  const hits = rows.filter(r =>
    r.id.toLowerCase().startsWith(lower) ||
    (r.short && r.short.toLowerCase().startsWith(lower)));
  if(hits.length === 1) return { found: true, row: hits[0] };
  return { found: false, reason: hits.length ? 'ambiguous' : 'not_found', hits };
}

/* 稳定序列化 + 内容指纹：用于判断「这条笔记自上次索引后有没有变」 */
function stableStringify(v){
  if(v === null || typeof v !== 'object') return JSON.stringify(v);
  if(Array.isArray(v)) return '[' + v.map(stableStringify).join(',') + ']';
  const keys = Object.keys(v).sort();
  const parts = [];
  for(const k of keys){
    const sv = stableStringify(v[k]);
    if(sv !== undefined) parts.push(JSON.stringify(k) + ':' + sv);
  }
  return '{' + parts.join(',') + '}';
}
function sigOf(v){
  const s = stableStringify(v);
  return crypto.createHash('sha256').update(s == null ? 'null' : s, 'utf8').digest('hex').slice(0, 16);
}
function noteSig(note){ return sigOf(note); }

function noteMapOf(bundle){
  const byId = new Map();
  let invalid = 0;
  for(const note of Array.isArray(bundle.notes) ? bundle.notes : []){
    if(!note || typeof note.id !== 'string' || !note.id){ invalid += 1; continue; }
    byId.set(note.id, note);
  }
  return { byId, invalid };
}

function buildRow(note, nodes, visibilityDefault){
  const visibility = visibilityOf(note, visibilityDefault);
  if(visibility === 'off') return null;
  const max = visibility === 'full' ? EXCERPT_FULL : EXCERPT_META;
  const ex = makeExcerpt(note.content, max);
  return {
    id: note.id,
    short: '',
    title: firstLineTitle(note.content),
    excerpt: ex.excerpt,
    tags: normalizeList(note.tags),
    status: String(note.status || ''),
    nodeId: String(note.nodeId || ''),
    path: nodes.get(note.nodeId) || '',
    links: normalizeList(note.links),
    visibility,
    createdAt: Number(note.createdAt) || 0,
    updatedAt: Number(note.updatedAt) || 0,
    truncated: ex.truncated
  };
}

function applySelectors(rows, opts){
  const collisions = assignShorts(rows);
  const unresolved = [];
  let selected = rows;
  if(opts.only.length){
    const wanted = new Set();
    for(const sel of opts.only){
      const hit = resolveId(rows, sel);
      if(hit.found) wanted.add(hit.row.id);
      else unresolved.push(sel);
    }
    selected = selected.filter(r => wanted.has(r.id));
  }
  if(opts.tags.length){
    const tags = opts.tags.map(t => t.toLowerCase());
    selected = selected.filter(r => {
      const own = r.tags.map(t => t.toLowerCase());
      return tags.every(t => own.includes(t));
    });
  }
  if(opts.node){
    selected = selected.filter(r => r.nodeId === opts.node);
  }
  const filtered = rows.length - selected.length;
  selected.sort((a, b) => (a.createdAt - b.createdAt) || (a.id < b.id ? -1 : 1));
  return { selected, filtered, unresolved, collisions };
}

function makeMeta(bundle, opts, selected, extra){
  const byVisibility = { off: extra.skippedOff || 0, meta: 0, full: 0 };
  for(const r of selected) byVisibility[r.visibility] += 1;
  return {
    format: FORMAT,
    generatedAt: Date.now(),
    source: {
      kind: 'bundle',
      bundleSha256: opts.bundleSha256 || '',
      exportedAt: bundle.exportedAt || '',
      appSchema: Number.isFinite(bundle.schema) ? bundle.schema : null,
      seq: Number(bundle.oplog && bundle.oplog.seq) || null
    },
    mode: 'full',
    count: selected.length,
    visibility: byVisibility,
    skipped: { invalid: extra.invalid || 0, off: extra.skippedOff || 0, filtered: extra.filtered || 0 },
    truncated: selected.filter(r => r.truncated).length,
    maxLineBytes: 0,
    shortCollisions: extra.collisions || 0,
    excerptMax: { meta: EXCERPT_META, full: EXCERPT_FULL },
    selectors: {
      only: opts.only,
      tags: opts.tags,
      node: opts.node,
      unresolved: extra.unresolved || []
    },
    incremental: { used:false, since:null, applied:0, ops:0, fallback: extra.fallback || '' },
    encrypted: false
  };
}

function stateOf(bundle, opts){
  const { byId } = noteMapOf(bundle);
  const notes = {};
  for(const [id, note] of byId) notes[id] = noteSig(note);
  return {
    format: STATE_FORMAT,
    seq: Number(bundle.oplog && bundle.oplog.seq) || 0,
    vaultId: (bundle.vault && bundle.vault.id) || '',
    visibilityDefault: opts.visibilityDefault,
    nodesSig: sigOf(Array.isArray(bundle.nodes) ? bundle.nodes : []),
    selectors: { only: opts.only, tags: opts.tags, node: opts.node },
    updatedAt: Date.now(),
    notes
  };
}

function buildIndex(bundle, opts){
  const nodes = buildNodePaths(bundle.nodes);
  const { byId, invalid } = noteMapOf(bundle);
  const rows = [];
  let skippedOff = 0;
  for(const note of byId.values()){
    const row = buildRow(note, nodes, opts.visibilityDefault);
    if(row) rows.push(row); else skippedOff += 1;
  }
  const { selected, filtered, unresolved, collisions } = applySelectors(rows, opts);
  const lines = selected.map(r => JSON.stringify(r));
  const meta = makeMeta(bundle, opts, selected, { invalid, skippedOff, filtered, unresolved, collisions });
  meta.maxLineBytes = lines.reduce((m, l) => Math.max(m, Buffer.byteLength(l, 'utf8')), 0);
  return { meta, rows: selected, lines, state: stateOf(bundle, opts) };
}

/* 增量：只接受「笔记级、日志连续、其余笔记指纹未变」的导出；否则返回 { fallback } 由调用方整表重建 */
function buildIndexIncremental(bundle, opts, prevState, prevRows){
  if(!prevState || prevState.format !== STATE_FORMAT) return { fallback:'no_state' };
  if(!Array.isArray(prevRows)) return { fallback:'no_prev_rows' };
  if(opts.only.length || opts.tags.length || opts.node) return { fallback:'selectors' };
  const ps = prevState.selectors || {};
  if((ps.only && ps.only.length) || (ps.tags && ps.tags.length) || ps.node) return { fallback:'prev_selectors' };
  if(prevState.visibilityDefault !== opts.visibilityDefault) return { fallback:'visibility_changed' };
  const bundleSeq = Number(bundle.oplog && bundle.oplog.seq) || 0;
  if(!bundleSeq) return { fallback:'bundle_without_seq' };
  if(!prevState.seq) return { fallback:'state_without_seq' };
  if(bundleSeq < prevState.seq) return { fallback:'seq_regressed' };
  const bundleVault = (bundle.vault && bundle.vault.id) || '';
  if(prevState.vaultId && bundleVault && prevState.vaultId !== bundleVault) return { fallback:'vault_changed' };
  const nodesSig = sigOf(Array.isArray(bundle.nodes) ? bundle.nodes : []);
  if(prevState.nodesSig && prevState.nodesSig !== nodesSig) return { fallback:'nodes_changed' };

  const ops = (Array.isArray(bundle.oplog.entries) ? bundle.oplog.entries : [])
    .filter(e => e && Number(e.seq) > prevState.seq)
    .sort((a, b) => a.seq - b.seq);
  let expect = prevState.seq;
  const touched = new Map();
  for(const e of ops){
    if(Number(e.seq) !== expect + 1) return { fallback:'oplog_gap' };
    expect = Number(e.seq);
    if(e.kind !== 'note') return { fallback:'oplog_kind_' + String(e.kind) };
    if(e.op !== 'add' && e.op !== 'upd' && e.op !== 'del') return { fallback:'oplog_op_' + String(e.op) };
    const id = String(e.id || '');
    if(!id) return { fallback:'oplog_bad_id' };
    if(touched.has(id)) return { fallback:'oplog_dup' };
    touched.set(id, e.op);
  }
  if(expect !== bundleSeq) return { fallback:'oplog_incomplete' };

  const { byId, invalid } = noteMapOf(bundle);
  for(const [id, note] of byId){
    if(touched.has(id)) continue;
    if(prevState.notes[id] !== noteSig(note)) return { fallback:'drift' };
  }
  for(const [id, op] of touched){
    const known = prevState.notes[id] !== undefined;
    const alive = byId.has(id);
    if(op === 'del' && (!known || alive)) return { fallback:'op_delete_mismatch' };
    if(op === 'add' && (known || !alive)) return { fallback:'op_add_mismatch' };
    if(op === 'upd' && (!known || !alive)) return { fallback:'op_update_mismatch' };
  }

  const rowsById = new Map();
  for(const r of prevRows){
    if(!r || typeof r.id !== 'string') continue;
    if(prevState.notes[r.id] === undefined) return { fallback:'row_not_in_state' };
    rowsById.set(r.id, r);
  }
  const nodes = buildNodePaths(bundle.nodes);
  let skippedOff = 0;
  for(const note of byId.values()){
    if(visibilityOf(note, opts.visibilityDefault) === 'off') skippedOff += 1;
  }
  for(const [id, op] of touched){
    if(op === 'del'){ rowsById.delete(id); continue; }
    const row = buildRow(byId.get(id), nodes, opts.visibilityDefault);
    if(row) rowsById.set(id, row); else rowsById.delete(id);
  }
  const expected = byId.size - skippedOff;
  if(rowsById.size !== expected) return { fallback:'row_count' };

  const rows = Array.from(rowsById.values());
  const { selected, collisions } = applySelectors(rows, opts);
  const lines = selected.map(r => JSON.stringify(r));
  const meta = makeMeta(bundle, opts, selected, { invalid, skippedOff, collisions });
  meta.mode = 'incremental';
  meta.incremental = { used:true, since:prevState.seq, applied:touched.size, ops:ops.length, fallback:'' };
  meta.maxLineBytes = lines.reduce((m, l) => Math.max(m, Buffer.byteLength(l, 'utf8')), 0);
  return { meta, rows: selected, lines, state: stateOf(bundle, opts) };
}

function writeIndex(outDir, result, statePath){
  fs.mkdirSync(outDir, { recursive: true, mode: 0o700 });
  const jsonlPath = path.join(outDir, 'index.jsonl');
  const metaPath = path.join(outDir, 'index.meta.json');
  const jsonlTmp = jsonlPath + '.tmp';
  const metaTmp = metaPath + '.tmp';
  const body = result.lines.join('\n') + (result.lines.length ? '\n' : '');
  fs.writeFileSync(jsonlTmp, body, { encoding: 'utf8', mode: 0o600 });
  fs.writeFileSync(metaTmp, JSON.stringify(result.meta, null, 2) + '\n', { encoding: 'utf8', mode: 0o600 });
  fs.renameSync(jsonlTmp, jsonlPath);
  fs.renameSync(metaTmp, metaPath);
  if(result.state && statePath){
    fs.mkdirSync(path.dirname(statePath), { recursive: true, mode: 0o700 });
    const stTmp = statePath + '.tmp';
    fs.writeFileSync(stTmp, JSON.stringify(result.state) + '\n', { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(stTmp, statePath);
  }
}

/* 上次的索引 + 状态；任何一份缺失/损坏都按「没有历史」处理，走整表重建 */
function loadPrev(outDir, statePath){
  let state;
  try{ state = JSON.parse(fs.readFileSync(statePath, 'utf8')); }catch(e){ return null; }
  if(!state || state.format !== STATE_FORMAT) return null;
  try{
    const body = fs.readFileSync(path.join(outDir, 'index.jsonl'), 'utf8');
    const rows = body.split(/\r?\n/).filter(Boolean).map(l => JSON.parse(l));
    return { state, rows };
  }catch(e){ return null; }
}

function main(){
  let opts;
  try{ opts = parseArgs(process.argv.slice(2)); }
  catch(e){ console.error(e.message + '\n\n' + usage()); process.exitCode = 2; return; }
  if(opts.help){ console.log(usage()); return; }

  try{
    const bundle = readBundle(opts.bundle);
    const baseOpts = { ...opts, bundleSha256: bundle.sha256 };
    const statePath = opts.state || path.join(opts.out, 'state.json');
    let result = null;
    let fallback = '';
    if(opts.full){
      fallback = 'forced';
    }else{
      const prev = loadPrev(opts.out, statePath);
      if(prev){
        result = buildIndexIncremental(bundle.data, baseOpts, prev.state, prev.rows);
        if(result.fallback){ fallback = result.fallback; result = null; }
      }else{
        fallback = 'no_state';
      }
    }
    if(!result){
      result = buildIndex(bundle.data, baseOpts);
      result.meta.incremental.fallback = fallback;
    }
    writeIndex(opts.out, result, statePath);
    if(!opts.quiet){
      console.log(JSON.stringify({
        ok: true,
        out: opts.out,
        mode: result.meta.mode,
        seq: result.meta.source.seq,
        applied: result.meta.incremental.applied,
        fallback: result.meta.incremental.fallback,
        count: result.meta.count,
        skipped: result.meta.skipped,
        truncated: result.meta.truncated,
        maxLineBytes: result.meta.maxLineBytes,
        shortCollisions: result.meta.shortCollisions
      }));
    }
  }catch(e){
    console.error('[2brain-index] ' + e.message);
    process.exitCode = 2;
  }
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if(isMain) main();

export { buildIndex, buildIndexIncremental, noteSig, writeIndex, loadPrev, readBundle, resolveId, plainText, firstLineTitle, parseArgs };
