# Contributing

## 基本约束

- `2brain.html` 必须保持**单文件、零依赖、无构建步骤**；使用 IIFE，变量风格向周边代码看齐。
- 不引入外部 CDN、字体、脚本或样式表。
- 每次改 `2brain.html`，把 `APP_VERSION` 末位 +1（例如 `v2026-10-21.1` → `v2026-10-21.2`），
  并同步更新 `tests/ui_smoke.html` 里的版本断言。
- `*.bat` 必须是 **ANSI/GBK + CRLF**；不要用编辑器把它存成 UTF-8。
- 不要在代码、测试、文档里写真实笔记、密码、恢复码、邀请码、Key、内网域名/IP。
- 不提交 `2brain-data.json`、`var/`、`*.db`、备份、日志。

## 修改前

- 先读 `2brain.html` 顶部的版本与模式说明，确认改动落在离线模式还是在线模式。
- 涉及导出/导入/Schema 的改动，必须同时改 `tests/io_roundtrip.html` 并通过。
- 涉及加密、bundle 字段白名单、`If-Match`/ETag 的改动，先说明兼容性，再动代码。

## 验证

```bash
# Python 语法 / 冒烟（临时库，不碰真实数据）
python3 -m py_compile 2brain-app.py 2brain-admin.py 2brain-sync.py sharect-webd.py
python3 tests/api_smoke.py

# JS 语法（把 2brain.html 的 <script> 抽出来后）
node --check /tmp/2brain-app.js
node --check secondbrain-bridge.mjs
```

页面测试用真实 Chrome 打开 `tests/*.html`；`tests/online_smoke.html` 需先启动
`python3 tests/api_stub.py --port 7799`。`--dump-dom` 不适合该页（PBKDF2 + 多轮 iframe 会耗尽虚拟时间预算）。

## 提交

- 一个提交只做一类修改，提交信息写清“为什么”和验证方式。
- 不提交生成的临时文件、`__pycache__`、编辑器配置。
- 首次贡献请先开 Issue 说明目标，避免大改后才发现方向不一致。
