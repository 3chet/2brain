#!/usr/bin/env node
/*
 * 2brain-index.mjs — 从「导出 JSON」生成 agent 只读索引（零服务端改动）
 *
 * 用法：
 *   node tools/2brain-index.mjs --bundle 2brain-backup-YYYY-MM-DD.json
 *   node tools/2brain-index.mjs --bundle export.json --out ./index
 *   node tools/2brain-index.mjs --bundle - --out ./index          # 从 stdin 读
 *
 * 可选筛选（同时给出时取交集）：
 *   --only n_abc123,b7c9x  只导出指定笔记（完整 id / 短号 / 唯一前缀）
 *   --tag 装修,收藏        标签必须全部命中
 *   --node life_home       只导出该分类（精确 nodeId）
 *
 * 输出：<out>/index.meta.json + <out>/index.jsonl
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

function buildIndex(bundle, opts){
  const nodes = buildNodePaths(bundle.nodes);
  const rows = [];
  let skippedOff = 0;
  let invalid = 0;

  for(const note of bundle.notes){
    if(!note || typeof note.id !== 'string' || !note.id){
      invalid += 1;
      continue;
    }
    const visibility = visibilityOf(note, opts.visibilityDefault);
    if(visibility === 'off'){ skippedOff += 1; continue; }
    const max = visibility === 'full' ? EXCERPT_FULL : EXCERPT_META;
    const ex = makeExcerpt(note.content, max);
    rows.push({
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
    });
  }

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

  const byVisibility = { off: skippedOff, meta: 0, full: 0 };
  for(const r of selected) byVisibility[r.visibility] += 1;
  const lines = selected.map(r => JSON.stringify(r));
  const maxLineBytes = lines.reduce((m, l) => Math.max(m, Buffer.byteLength(l, 'utf8')), 0);

  const meta = {
    format: FORMAT,
    generatedAt: Date.now(),
    source: {
      kind: 'bundle',
      bundleSha256: opts.bundleSha256 || '',
      exportedAt: bundle.exportedAt || '',
      appSchema: Number.isFinite(bundle.schema) ? bundle.schema : null
    },
    count: selected.length,
    visibility: byVisibility,
    skipped: { invalid, off: skippedOff, filtered },
    truncated: selected.filter(r => r.truncated).length,
    maxLineBytes,
    shortCollisions: collisions,
    excerptMax: { meta: EXCERPT_META, full: EXCERPT_FULL },
    selectors: {
      only: opts.only,
      tags: opts.tags,
      node: opts.node,
      unresolved
    },
    encrypted: false
  };
  return { meta, rows: selected, lines };
}

function writeIndex(outDir, result){
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
}

function main(){
  let opts;
  try{ opts = parseArgs(process.argv.slice(2)); }
  catch(e){ console.error(e.message + '\n\n' + usage()); process.exitCode = 2; return; }
  if(opts.help){ console.log(usage()); return; }

  try{
    const bundle = readBundle(opts.bundle);
    const result = buildIndex(bundle.data, { ...opts, bundleSha256: bundle.sha256 });
    writeIndex(opts.out, result);
    if(!opts.quiet){
      console.log(JSON.stringify({
        ok: true,
        out: opts.out,
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

export { buildIndex, writeIndex, readBundle, resolveId, plainText, firstLineTitle, parseArgs };
