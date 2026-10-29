/*
 * P-1 回归：离线索引 + 只读 MCP
 * 运行：node --test tests/agent_index_test.mjs
 * 全部使用临时目录与合成 bundle，不碰真实笔记 / NAS。
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const INDEXER = path.join(ROOT, 'tools', '2brain-index.mjs');
const MCP = path.join(ROOT, 'tools', '2brain-mcp.mjs');

let tmp;
let bundlePath;
let indexDir;

const LONG_META = '装修：阳台改书房的 7 个尺寸坑\n' + '进深至少 1.4 米，否则转身会撞到椅子。'.repeat(30);
const LONG_FULL = '长期：每天跑步三公里\n' + '坚持比强度更重要。'.repeat(45);

function makeBundle(){
  return {
    app: '2brain',
    schema: 1,
    exportedAt: '2026-10-22T05:00:00.000Z',
    nodes: [
      { id: 'life', name: '生活', parentId: null },
      { id: 'life_home', name: '家里', parentId: 'life' },
      { id: 'work', name: '工作', parentId: null },
      { id: 'work_meet', name: '会议', parentId: 'work' }
    ],
    notes: [
      {
        id: 'n_m3k2j1a4b7c9x', content: LONG_META, nodeId: 'life_home',
        tags: ['装修', '收藏'], status: '待处理',
        links: ['https://example.com/a'], createdAt: 1000, updatedAt: 5000
      },
      {
        id: 'n_m3k2j1a4b7c9y', content: '周三下午三点和后端过接口字段', nodeId: 'work_meet',
        tags: ['会议'], status: '待处理', createdAt: 2000, updatedAt: 4000,
        agentVisibility: 'off'
      },
      {
        id: 'n_m3k2j2b8d0e1f', content: LONG_FULL, nodeId: 'life',
        tags: ['运动'], status: '长期', createdAt: 3000, updatedAt: 6000,
        agentVisibility: 'full'
      },
      {
        id: 'n_m3k2j3c9f1g2h', content: '[red]紧急[/red]：厨房漏水，先关总阀', nodeId: 'life_home',
        tags: ['装修', '紧急'], status: '待处理', createdAt: 4000, updatedAt: 7000
      },
      {
        id: 'n_m3k2j4d0h2i3j', content: '书单：今年读过的 12 本书', nodeId: 'life_home',
        tags: ['书'], status: '长期', createdAt: 5000, updatedAt: 8000
      },
      { content: '缺少 id 的脏数据', tags: [] }
    ],
    favorites: []
  };
}

function runIndex(extra, outDir){
  const out = outDir || path.join(tmp, 'out-' + Math.random().toString(36).slice(2));
  const r = spawnSync(process.execPath, [INDEXER, '--bundle', bundlePath, '--out', out, ...extra], {
    cwd: ROOT, encoding: 'utf8'
  });
  return { ...r, out };
}

function readRows(dir){
  return fs.readFileSync(path.join(dir, 'index.jsonl'), 'utf8')
    .split(/\r?\n/).filter(Boolean).map(l => JSON.parse(l));
}

function readMeta(dir){
  return JSON.parse(fs.readFileSync(path.join(dir, 'index.meta.json'), 'utf8'));
}

function startMcp(indexPath){
  const child = spawn(process.execPath, [MCP, '--index', indexPath], { stdio: ['pipe', 'pipe', 'pipe'] });
  const queue = [];
  const waiters = [];
  const rl = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
  rl.on('line', line => {
    const msg = JSON.parse(line);
    const waiter = waiters.shift();
    if(waiter) waiter(msg);
    else queue.push(msg);
  });
  let nextId = 1;
  function request(method, params){
    const id = nextId++;
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('timeout: ' + method)), 5000);
      const take = msg => { clearTimeout(timer); resolve(msg); };
      if(queue.length) take(queue.shift());
      else waiters.push(take);
    });
  }
  return { request, close: () => child.kill() };
}

async function tool(mcp, name, args){
  const res = await mcp.request('tools/call', { name, arguments: args || {} });
  assert.ok(res.result, JSON.stringify(res));
  return res.result;
}

before(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), '2brain-index-test-'));
  bundlePath = path.join(tmp, 'bundle.json');
  fs.writeFileSync(bundlePath, JSON.stringify(makeBundle(), null, 2), 'utf8');
  indexDir = path.join(tmp, 'index');
  const r = runIndex([], indexDir);
  assert.equal(r.status, 0, r.stderr);
});

after(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('索引格式、过滤与截断', () => {
  const meta = readMeta(indexDir);
  const rows = readRows(indexDir);

  assert.equal(meta.format, '2brain-index/1');
  assert.equal(meta.count, 4);
  assert.equal(meta.visibility.off, 1);
  assert.equal(meta.visibility.meta, 3);
  assert.equal(meta.visibility.full, 1);
  assert.equal(meta.skipped.off, 1);
  assert.equal(meta.skipped.invalid, 1);
  assert.equal(meta.source.bundleSha256.length, 64);
  assert.equal(meta.encrypted, false);

  assert.equal(rows.length, 4);
  assert.deepEqual(rows.map(r => r.id), [
    'n_m3k2j1a4b7c9x', 'n_m3k2j2b8d0e1f', 'n_m3k2j3c9f1g2h', 'n_m3k2j4d0h2i3j'
  ]);
  for(const row of rows) assert.equal('content' in row, false);

  const first = rows[0];
  assert.equal(first.title, '装修：阳台改书房的 7 个尺寸坑');
  assert.equal(first.path, '生活/家里');
  assert.equal(first.excerpt.length, 301);
  assert.equal(first.truncated, true);
  assert.equal(first.short.length, 5);
  assert.deepEqual(first.tags, ['装修', '收藏']);
  assert.deepEqual(first.links, ['https://example.com/a']);

  const full = rows[1];
  assert.equal(full.visibility, 'full');
  assert.ok(full.excerpt.length > 301);
  assert.equal(full.truncated, false);

  const marked = rows[2];
  assert.equal(marked.title, '紧急：厨房漏水，先关总阀');
  assert.equal(marked.short, 'f1g2h');
});

test('--visibility-default off 只保留显式 full', () => {
  const r = runIndex(['--visibility-default', 'off']);
  assert.equal(r.status, 0, r.stderr);
  const rows = readRows(r.out);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].visibility, 'full');
});

test('--tag / --node / --only 筛选', () => {
  const byTag = runIndex(['--tag', '装修']);
  assert.equal(byTag.status, 0, byTag.stderr);
  assert.equal(readRows(byTag.out).length, 2);

  const byTwoTags = runIndex(['--tag', '装修,收藏']);
  assert.equal(readRows(byTwoTags.out).length, 1);

  const byNode = runIndex(['--node', 'life_home']);
  assert.equal(readRows(byNode.out).length, 3);

  const byShort = runIndex(['--only', 'b7c9x']);
  assert.equal(readRows(byShort.out).length, 1);
  assert.equal(readRows(byShort.out)[0].id, 'n_m3k2j1a4b7c9x');

  const byPrefix = runIndex(['--only', 'n_m3k2j2']);
  assert.equal(readRows(byPrefix.out).length, 1);

  const ambiguous = runIndex(['--only', 'n_m3k2j']);
  assert.equal(readRows(ambiguous.out).length, 0);
  assert.deepEqual(readMeta(ambiguous.out).selectors.unresolved, ['n_m3k2j']);

  const andFilter = runIndex(['--only', 'b7c9x', '--tag', '运动']);
  assert.equal(readRows(andFilter.out).length, 0);
});

test('非法输入退出码为 2', () => {
  const badApp = path.join(tmp, 'bad-app.json');
  fs.writeFileSync(badApp, JSON.stringify({ app: 'other', notes: [] }), 'utf8');
  const r1 = spawnSync(process.execPath, [INDEXER, '--bundle', badApp, '--out', path.join(tmp, 'x')], {
    cwd: ROOT, encoding: 'utf8'
  });
  assert.equal(r1.status, 2);

  const badJson = path.join(tmp, 'bad.json');
  fs.writeFileSync(badJson, '{not json', 'utf8');
  const r2 = spawnSync(process.execPath, [INDEXER, '--bundle', badJson, '--out', path.join(tmp, 'y')], {
    cwd: ROOT, encoding: 'utf8'
  });
  assert.equal(r2.status, 2);
});

test('MCP：initialize / tools/list', async () => {
  const mcp = startMcp(indexDir);
  try{
    const init = await mcp.request('initialize', { protocolVersion: '2024-11-05', capabilities: {} });
    assert.equal(init.result.serverInfo.name, '2brain-mcp');
    assert.equal(init.result.capabilities.tools.listChanged, false);

    const list = await mcp.request('tools/list', {});
    assert.deepEqual(list.result.tools.map(t => t.name).sort(), [
      'brain_get', 'brain_recent', 'brain_search', 'brain_stats', 'brain_tags'
    ]);
    for(const t of list.result.tools){
      if(['brain_search', 'brain_recent', 'brain_get'].includes(t.name)){
        assert.match(t.description, /not the full text|not full text|NOT the full text/i);
      }
    }
  }finally{ mcp.close(); }
});

test('MCP：搜索 / 最近 / 统计 / 标签', async () => {
  const mcp = startMcp(indexDir);
  try{
    const stats = await tool(mcp, 'brain_stats');
    assert.equal(stats.isError, false);
    assert.equal(stats.structuredContent.count, 4);
    assert.deepEqual(stats.structuredContent.byVisibility, { off: 0, meta: 3, full: 1 });

    const search = await tool(mcp, 'brain_search', { q: '装修' });
    assert.equal(search.structuredContent.total, 2);
    assert.equal(search.structuredContent.notes[0].id, 'n_m3k2j3c9f1g2h');

    const andSearch = await tool(mcp, 'brain_search', { q: '阳台 尺寸' });
    assert.equal(andSearch.structuredContent.total, 1);

    const tag = await tool(mcp, 'brain_search', { tag: '装修' });
    assert.equal(tag.structuredContent.total, 2);

    const node = await tool(mcp, 'brain_search', { nodeId: 'work_meet' });
    assert.equal(node.structuredContent.total, 0);

    const status = await tool(mcp, 'brain_search', { status: '长期' });
    assert.equal(status.structuredContent.total, 2);

    const limited = await tool(mcp, 'brain_search', { q: '装修', limit: 1 });
    assert.equal(limited.structuredContent.total, 2);
    assert.equal(limited.structuredContent.returned, 1);
    assert.equal(limited.structuredContent.notes.length, 1);

    const recent = await tool(mcp, 'brain_recent', { since: 6000 });
    assert.equal(recent.structuredContent.total, 3);
    assert.equal(recent.structuredContent.notes[0].id, 'n_m3k2j4d0h2i3j');

    const tags = await tool(mcp, 'brain_tags');
    const map = Object.fromEntries(tags.structuredContent.tags.map(t => [t.tag, t.count]));
    assert.equal(map['装修'], 2);
    assert.equal(map['收藏'], 1);
  }finally{ mcp.close(); }
});

test('MCP：id / 短号 / 前缀寻址', async () => {
  const mcp = startMcp(indexDir);
  try{
    const full = await tool(mcp, 'brain_get', { id: 'n_m3k2j1a4b7c9x' });
    assert.equal(full.structuredContent.found, true);
    assert.equal(full.structuredContent.note.path, '生活/家里');
    assert.equal('content' in full.structuredContent.note, false);

    const short = await tool(mcp, 'brain_get', { id: 'b7c9x' });
    assert.equal(short.structuredContent.note.id, 'n_m3k2j1a4b7c9x');

    const hashShort = await tool(mcp, 'brain_get', { id: '#b7c9x' });
    assert.equal(hashShort.structuredContent.note.id, 'n_m3k2j1a4b7c9x');

    const ambiguous = await tool(mcp, 'brain_get', { id: 'n_m3k2j' });
    assert.equal(ambiguous.structuredContent.found, false);
    assert.equal(ambiguous.structuredContent.reason, 'ambiguous');
    assert.equal(ambiguous.structuredContent.count, 4);
    assert.equal(ambiguous.structuredContent.candidates.length, 4);

    const missing = await tool(mcp, 'brain_get', { id: 'zzzzz' });
    assert.equal(missing.structuredContent.found, false);
    assert.equal(missing.structuredContent.reason, 'not_found');

    const noArg = await tool(mcp, 'brain_get', {});
    assert.equal(noArg.isError, true);
  }finally{ mcp.close(); }
});

test('MCP：未知工具与缺失索引', async () => {
  const mcp = startMcp(indexDir);
  try{
    const unknown = await mcp.request('tools/call', { name: 'brain_delete', arguments: {} });
    assert.equal(unknown.error.code, -32602);
  }finally{ mcp.close(); }

  const empty = path.join(tmp, 'empty-index');
  fs.mkdirSync(empty);
  const mcp2 = startMcp(empty);
  try{
    const init = await mcp2.request('initialize', { protocolVersion: '2024-11-05' });
    assert.equal(init.result.serverInfo.name, '2brain-mcp');
    const stats = await tool(mcp2, 'brain_stats');
    assert.equal(stats.isError, true);
    assert.match(stats.content[0].text, /No index yet/);
  }finally{ mcp2.close(); }
});

/* ===================== P5：oplog 增量重建 ===================== */

function incNote(id, text, extra){
  return Object.assign({
    id, content: text, nodeId: 'life', tags: ['t'], status: '待处理',
    createdAt: 1000, updatedAt: 1000
  }, extra || {});
}
function incBundle(seq, entries){
  return {
    app: '2brain', schema: 1, exportedAt: '2026-10-25T00:00:00.000Z',
    vault: { id: 'vtest', kind: 'local', name: '增量测试库' },
    nodes: [
      { id: 'life', name: '生活', parentId: null },
      { id: 'life_home', name: '家里', parentId: 'life' }
    ],
    notes: [
      incNote('n_a', '笔记 A'),
      incNote('n_b', '笔记 B'),
      incNote('n_c', '笔记 C', { nodeId: 'life_home' })
    ],
    favorites: [],
    oplog: { seq, entries }
  };
}
function writeInc(name, obj){
  const p = path.join(tmp, name);
  fs.writeFileSync(p, JSON.stringify(obj, null, 2), 'utf8');
  return p;
}
function runOn(bundleFile, outDir, extra){
  return spawnSync(process.execPath,
    [INDEXER, '--bundle', bundleFile, '--out', outDir, ...(extra || [])],
    { cwd: ROOT, encoding: 'utf8' });
}
function readState(dir){
  return JSON.parse(fs.readFileSync(path.join(dir, 'state.json'), 'utf8'));
}

test('增量：首次建表写状态，第二次只应用变化条目', () => {
  const incDir = path.join(tmp, 'inc-index');
  const b1 = writeInc('inc1.json', incBundle(5, []));
  let r = runOn(b1, incDir);
  assert.equal(r.status, 0, r.stderr);
  let meta = readMeta(incDir);
  assert.equal(meta.mode, 'full');
  assert.equal(meta.source.seq, 5);
  assert.equal(meta.count, 3);
  assert.equal(meta.incremental.used, false);
  assert.equal(meta.incremental.fallback, 'no_state');
  const st = readState(incDir);
  assert.equal(st.format, '2brain-index-state/1');
  assert.equal(st.seq, 5);
  assert.deepEqual(Object.keys(st.notes).sort(), ['n_a', 'n_b', 'n_c']);

  const b2 = incBundle(8, [
    { seq: 6, at: 1, kind: 'note', op: 'upd', id: 'n_a', label: '笔记 A 改' },
    { seq: 7, at: 2, kind: 'note', op: 'add', id: 'n_d', label: '笔记 D' },
    { seq: 8, at: 3, kind: 'note', op: 'del', id: 'n_b', label: '' }
  ]);
  b2.notes = [
    incNote('n_a', '笔记 A 改', { updatedAt: 2000 }),
    incNote('n_c', '笔记 C', { nodeId: 'life_home' }),
    incNote('n_d', '笔记 D', { createdAt: 3000, updatedAt: 3000 })
  ];
  const b2p = writeInc('inc2.json', b2);
  r = runOn(b2p, incDir);
  assert.equal(r.status, 0, r.stderr);
  meta = readMeta(incDir);
  assert.equal(meta.mode, 'incremental');
  assert.equal(meta.incremental.used, true);
  assert.equal(meta.incremental.since, 5);
  assert.equal(meta.incremental.ops, 3);
  assert.equal(meta.incremental.applied, 3);
  assert.equal(meta.incremental.fallback, '');
  assert.equal(meta.count, 3);
  const rows = readRows(incDir);
  assert.deepEqual(rows.map(x => x.id), ['n_a', 'n_c', 'n_d']);
  assert.equal(rows[0].title, '笔记 A 改');
  assert.equal(rows[1].path, '生活/家里');
  assert.equal(readState(incDir).seq, 8);

  /* 和整表重建逐字节一致（含短号分配） */
  const fullDir = path.join(tmp, 'inc-full');
  r = runOn(b2p, fullDir, ['--full']);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(readMeta(fullDir).mode, 'full');
  assert.deepEqual(readRows(fullDir), rows);
});

test('增量：日志不连续 / 分类变更 / 指纹漂移都回退整表', () => {
  const incDir = path.join(tmp, 'inc-index');

  /* 分类变更（kind 不是 note）→ 全量 */
  const b3 = incBundle(9, [
    { seq: 9, at: 4, kind: 'node', op: 'upd', id: 'life', label: '生活' }
  ]);
  b3.nodes = b3.nodes.map(n => n.id === 'life' ? Object.assign({}, n, { name: '生活改名' }) : n);
  let r = runOn(writeInc('inc3.json', b3), incDir);
  assert.equal(r.status, 0, r.stderr);
  let meta = readMeta(incDir);
  assert.equal(meta.mode, 'full');
  assert.equal(meta.incremental.fallback, 'nodes_changed');
  assert.equal(readRows(incDir)[0].path, '生活改名');

  /* seq 跳号（缺 10）→ 全量 */
  const b4 = incBundle(11, [
    { seq: 11, at: 5, kind: 'note', op: 'upd', id: 'n_a', label: '笔记 A 再改' }
  ]);
  b4.nodes = b3.nodes;
  r = runOn(writeInc('inc4.json', b4), incDir);
  meta = readMeta(incDir);
  assert.equal(meta.mode, 'full');
  assert.equal(meta.incremental.fallback, 'oplog_gap');

  /* 未记日志的内容变化（指纹对不上）→ 全量 */
  const b5 = incBundle(11, []);
  b5.nodes = b3.nodes;
  b5.notes = b5.notes.map(n => n.id === 'n_c'
    ? Object.assign({}, n, { content: '偷偷改过的 C', updatedAt: 4000 }) : n);
  r = runOn(writeInc('inc5.json', b5), incDir);
  meta = readMeta(incDir);
  assert.equal(meta.mode, 'full');
  assert.equal(meta.incremental.fallback, 'drift');
  assert.equal(readRows(incDir).find(x => x.id === 'n_c').title, '偷偷改过的 C');

  /* 导出来自另一个库 → 全量 */
  const b6 = incBundle(12, []);
  b6.nodes = b3.nodes;
  b6.vault = { id: 'vother', kind: 'local', name: '别的库' };
  r = runOn(writeInc('inc6.json', b6), incDir);
  meta = readMeta(incDir);
  assert.equal(meta.mode, 'full');
  assert.equal(meta.incremental.fallback, 'vault_changed');
});

test('增量：筛选 / --full / 无 oplog 导出都走整表', () => {
  const incDir = path.join(tmp, 'inc-index');
  const selDir = path.join(tmp, 'inc-sel');
  fs.cpSync(incDir, selDir, { recursive: true });
  let r = runOn(path.join(tmp, 'inc6.json'), selDir, ['--tag', 't']);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(readMeta(selDir).incremental.fallback, 'selectors');

  r = runOn(path.join(tmp, 'inc6.json'), incDir, ['--full']);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(readMeta(incDir).mode, 'full');
  assert.equal(readMeta(incDir).incremental.fallback, 'forced');

  r = runOn(bundlePath, incDir);   // 旧格式导出：没有 oplog
  assert.equal(r.status, 0, r.stderr);
  const meta = readMeta(incDir);
  assert.equal(meta.mode, 'full');
  assert.equal(meta.incremental.fallback, 'bundle_without_seq');
  assert.equal(meta.count, 4);
});
