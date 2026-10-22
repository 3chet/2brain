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
    assert.match(stats.content[0].text, /No index found/);
  }finally{ mcp2.close(); }
});
