# Security Policy

## Supported versions

只维护 `main` 分支上的最新版本。旧版本不单独发安全补丁。

## Reporting a vulnerability

请通过 GitHub 的 **Security → Report a vulnerability**（私有安全公告）报告，不要在公开 Issue 里贴利用细节、真实笔记或密钥。

报告时请尽量提供：

- 受影响版本（页面底部 / `window.brain.pageVersion`）
- 复现步骤与影响范围（例如：XSS、越权读取、同步覆盖、密钥泄露）
- 是否涉及真实数据；**不要附带真实笔记内容、密码、恢复码、邀请码或 AI Key**

## Threat model（简要）

- 在线模式的目标是：服务器只保存密文与 `wrappedDEK`，不持有密码、KEK、DEK 或明文笔记。
- 服务器仍可见元数据：账号名、登录时间、请求大小、修订次数、IP 等。
- 端到端加密不能防御：设备被入侵、浏览器扩展读取页面、弱口令被离线暴力破解、用户把恢复码/密码交给第三方。
- 前端是单文件应用，任何引入第三方脚本的改动都会扩大 XSS 面；提交前请说明。
- 本地桥会把选中笔记写入本机 mnemon 记忆库；这是本机能力，不是云端同步。

## 不要提交到仓库

- 真实 `2brain-data.json`、`var/2brain.db`、备份、日志
- 密码、恢复码、邀请码、同步 Key、AI Key、Tunnel 凭据
- 内网域名、内网 IP、主机名、个人路径

如果误提交了密钥，请立即在对应服务轮换，并清理 Git 历史后再公开。
