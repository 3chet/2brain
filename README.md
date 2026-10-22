# 2brain

单文件、零依赖、可离线使用的「第二大脑」笔记应用。

打开 `2brain.html` 就能用，不需要服务器、构建步骤或第三方库；需要多设备时，可选地自建一套账号登录 + 端到端加密（E2EE）的在线模式。

## 快速开始

1. 下载或克隆本仓库。
2. 用浏览器打开 `2brain.html`（`file://` 也可以）。
3. 数据保存在浏览器 localStorage（键前缀 `sb_*`）。请定期用应用内的「导出」做备份。

> 不要把 `2brain.html` 改名或移动后再打开：浏览器按完整路径隔离 localStorage，改名等于换了一个空白数据区。

## 功能

- 树形分类（顶部「全部」入口）、笔记编辑、搜索、收藏、置顶
- 所见即所得编辑：加粗、删除线、红/蓝/黑标记直接显示；存储仍为兼容导出格式的轻量标记
- 列表筛选：时间范围 / 完成状态（待处理、进行中、已完成、长期）/ 按月筛选
- 快照 / 回收站 / 导入导出（JSON / Markdown / JSONL）
- 可选本地 mnemon 桥（Node，Windows 双击脚本），把笔记写入本机记忆库供 agent 召回；设置页有总开关（默认关闭）
- 可选 AI 分类与 AI 摘要（OpenAI 兼容接口 / Ollama；在线模式经同源后端转发）
- 可选在线模式：账号登录、E2EE 多设备同步、离线可用
- 本地提醒（不参与同步）
- 手机端输入框聚焦后自动放大（约 3 倍），便于单手输入
- 「重置全部数据」三步确认：先归档、再验证密码、可选只清本机
- `tools/` 下提供只读索引器与 MCP 服务，把导出的数据交给本机 agent（不写入、不上传）

## 在线模式（可选，自建）

浏览器端完成密钥派生与加解密：

```
密码 → NFKC → PBKDF2-SHA256(600,000) → authHash / KEK
随机 32B DEK → 用 KEK 包裹 → 服务器只存 wrappedDEK
笔记 JSON → AES-GCM(DEK) → 服务器只存密文
```

服务器组件：

| 组件 | 默认端口 | 作用 |
|---|---:|---|
| `2brain-app.py` | 8090 | 账号、登录、E2EE bundle 的 GET/PUT（ETag / If-Match 并发控制）、归档/重置、AI 同源转发 |
| `2brain-sync.py` | 8089 | 旧版 JSON 同步面（`/brain`，可选用；也可以只用在线模式） |
| `sharect-webd.py` | 8088 | 静态页、口令门、`/api` 与 `/brain` 反向代理 |

部署要点：

1. 安装 Python 3.11+，后端只用标准库，无需 pip。
2. 把 `2brain.html` 和后端放在同一目录；把 `sharect-webd.py` 的目录参数指向该目录。
3. 把 `2brain-app.py --origin` 和 `2brain.html` 里的 `notes.example.com` 占位符替换成你的站点域名。
4. 初始化账号：`python3 2brain-admin.py --help`（邀请码只显示一次，不要写进仓库）。
5. 用 systemd / 进程管理器启动；默认只监听 `127.0.0.1`，外层用 HTTPS 反向代理或 Cloudflare Tunnel。
6. **公网必须 HTTPS**：`crypto.subtle` 只在安全上下文可用；纯局域网 `http://192.0.2.10` 会提示“需要 HTTPS”。
7. 需要 AI 分类/摘要时，在应用设置里填 OpenAI 兼容接口；在线页面会把请求发给同源 `/api/ai/proxy`，Key 不进日志、不落服务器。

安全模型与限制：

- 服务器不接触密码、KEK、DEK 或明文笔记；但能看到账号名、时间、密文大小等元数据。
- 忘记密码只能靠恢复码；恢复码只显示一次，请离线保存。
- 口令下限 6 位是产品限制，不是安全建议；请使用更长的口令。
- 同步重置会先把旧库归档到指定目录（只读 + SHA256 + integrity_check），再换新代次；归档不在自动清理范围内。
- 本地 mnemon 桥与 `tools/` 索引会在**本机明文**保存笔记正文；这是本机能力，不是云端同步，请自行保护磁盘与备份。
- 单文件应用没有第三方脚本；如果你 fork 后引入外部资源，需要自行评估 XSS 风险。

## Agent 只读接入（可选）

`tools/` 提供零依赖的本地索引器与只读 MCP 服务，数据来自应用导出的 JSON，不连接服务器、不写入笔记：

```bash
# 1. 在应用里「导出」得到 JSON，然后生成明文索引（默认 ~/.2brain/index）
node tools/2brain-index.mjs --bundle export.json

# 2. 以 stdio 方式启动 MCP server，交给你的 agent 客户端
node tools/2brain-mcp.mjs
```

索引包含标题、分类路径、摘要、状态与标签；默认摘要 300 字、全文模式 4000 字，不含附件。索引是**本机明文**，请勿放进仓库或第三方同步盘。

## 测试

页面型测试（浏览器打开）：

- `tests/ui_smoke.html` — 主界面回归
- `tests/ui_mobile.html` — 手机断点（390×844 iframe）
- `tests/io_roundtrip.html` — 导出 → 覆盖导入 → 再导出，逐字段一致（**改导入/导出/Schema 必跑**）
- `tests/online_smoke.html` — 在线模式桩测试（先启动 `python3 tests/api_stub.py --port 7799`，用真实 Chrome 打开）
- `tests/mnemon_smoke.html` — 本地桥连通性（用 `--data-dir` 指向临时目录，勿写真实记忆库）

命令行测试：

```bash
python3 tests/api_smoke.py      # 临时库，不碰真实数据
node tests/agent_index_test.mjs # 只读索引与 MCP 单元测试
```

`tests/online_smoke.html` 不要用 Chrome `--dump-dom` 跑：PBKDF2 与多轮 iframe 启动会耗尽虚拟时间预算。详细约定见 `CONTRIBUTING.md`。

## 目录

```
2brain.html              主应用（单文件，IIFE，无构建）
2brain-app.py            在线模式后端（账号 / E2EE bundle / 归档）
brain_archive.py         永久归档（校验 / 只读落盘）
2brain-admin.py          账号与邀请码管理 CLI
2brain-sync.py           旧版 JSON 同步中枢（可选）
sharect-webd.py          静态页 + 口令门 + 反向代理（可选）
secondbrain-bridge.mjs   本地 mnemon 桥
bridge_conn_check.html   桥连通性自检页
启动桥.bat / 停止桥.bat   Windows 启动/停止脚本（GBK + CRLF）
tools/                   只读索引导出器 + MCP 服务
ops/                     备份、巡检脚本与 systemd 模板
tests/                   冒烟与回归测试
```

## 开发状态

2026-10-22：在线模式、记忆桥与只读 agent 接入已上线。

- 已完成：M1a 后端、M1b 在线前端（E2EE）、M1c 真实数据覆盖导入与同步、NAS 部署与切流、
  SQLite 备份 + btrfs 只读快照 + U 盘异地副本 + 巡检、同步重置与永久归档、本地记忆桥、
  只读索引器 / MCP、AI 分类与摘要、所见即所得编辑器。
- 页面版本 `v2026-10-22.4`；回归基线 api 180 / ui 145 / mobile 28 / online 98 / io_roundtrip 16 / agent_index 8 / mnemon 18。
- 后续计划：静态审查 P2、学习报告、M1.5 写侧 Agent 网关（需先有审计与撤销机制）。
- 部署脚本中的域名/主机/密钥路径均为占位符，请按自己的环境修改。

## 许可

MIT，版权署名 3chet。见 `LICENSE`。
