# 2brain 备份、巡检与 btrfs 快照

本目录是在线库的备份/巡检工具。**只备份加密库 `var/2brain.db` 与整目录快照，不复制密码、同步 Key、AI Key、邀请码或明文笔记到仓库。**

## 时间表（示例，可按需修改）

| 时间 | 任务 | 内容 |
|---|---|---|
| 每 30 分钟 | `snapshot live` | SQLite 在线备份，保留 48 小时 |
| 每天 00:20 | `snapshot daily` | 当日快照，保留 30 天 |
| 每周日 00:25 | `snapshot weekly` | 周快照，保留 12 周 |
| 每天 00:30 | `btrfs snapshot` | 数据子卷只读快照，保留 14 天 |
| 每天 00:40 | `pull` | 把 daily/weekly 增量复制到远端并校验 SHA256 |
| 每天 01:00 | `check` | 快照新鲜度、integrity_check、SHA256、服务/HTTP、磁盘、远端副本、btrfs 快照 |

`Persistent=true` 表示关机错过的任务会在下次开机补跑；请把时间安排在主机计划关机之前（若主机会关机）。

## 路径与保留

- 应用：`/srv/2brain/app`（示例值，按实际部署改）。
- 在线库：`/srv/2brain/var/2brain.db`。
- 备份：`/srv/2brain/backups/{live,daily,weekly,logs,state}`，目录 700、文件 600。
- btrfs 快照：`/srv/.2brain-snapshots/2brain-snap-YYYYmmdd-HHMMSS`，只读，保留 14 天。
- 远端：默认 `/mnt/2brain-backup/2brain/{daily,weekly}`（可用 `TWOBRAIN_REMOTE_DIR` 覆盖）。
- 保留：live 48h / daily 30d / weekly 12w / btrfs 14d；远端同 daily/weekly 规则。

快照目录必须放在被快照子卷**之外**，否则会把快照自己拍进快照。

## 脚本

- `2brain-backup.sh snapshot {live|daily|weekly} | pull | status`
- `2brain-snapshot.sh snapshot | list`：`btrfs subvolume snapshot -r <src> <dir>`，按 14 天清理。
- `2brain-check.py`：0 = 无失败（可有警告），1 = 有失败。
  结果先写 `state/check-latest.json` 与 `logs/backup.log`（脚本按行首日期裁到最近 90 天），
  然后按「钉钉优先、邮件可选」投递 —— 钉钉只在新失败 / 恢复时发，邮件默认关闭。

可用环境变量覆盖：

| 变量 | 默认值 |
|---|---|
| `TWOBRAIN_APP_DIR` | `/srv/2brain` |
| `TWOBRAIN_DB` | `$TWOBRAIN_APP_DIR/var/2brain.db` |
| `TWOBRAIN_BACKUP_ROOT` | `/srv/2brain/backups` |
| `TWOBRAIN_REMOTE` | `root@backup-host`（**必须改成你的备份主机**） |
| `TWOBRAIN_REMOTE_DIR` | `/mnt/2brain-backup/2brain` |
| `TWOBRAIN_SSH_KEY` | `/etc/2brain/keys/backup_ed25519` |
| `TWOBRAIN_KNOWN_HOSTS` | `/etc/2brain/keys/known_hosts` |
| `TWOBRAIN_SNAPSHOT_SRC` | `/srv`（含 2brain 的 btrfs 子卷） |
| `TWOBRAIN_SNAPSHOT_DIR` | `/srv/.2brain-snapshots` |
| `TWOBRAIN_SNAPSHOT_KEEP_DAYS` | `14` |
| `TWOBRAIN_DINGTALK_ENV` | `/etc/2brain/keys/dingtalk.env` |
| `TWOBRAIN_MAIL_ENABLED` | 非 `1`（或未设）= 不发邮件 |
| `TWOBRAIN_MAIL_TO` | 空 = 不发邮件，只写文件；逗号分隔可填多个收件人 |
| `TWOBRAIN_MAIL_USER` | 空 = 取第一个收件人作为发信账号 |
| `TWOBRAIN_MAIL_PASS_FILE` | `/etc/2brain/keys/mail.pass` |
| `TWOBRAIN_MAIL_SMTP` | `smtp.example.com`（换成你的邮箱服务商） |
| `TWOBRAIN_MAIL_PORT` | `465`（SMTP SSL） |

## 钉钉推送（默认通道）

巡检最怕的是"结果没人看"，所以结果会主动推一条钉钉。用的是自定义机器人（webhook + 加签）：

- 配置：`/etc/2brain/keys/dingtalk.env`（600），两行 `DINGTALK_WEBHOOK=` / `DINGTALK_SECRET=`；
  路径可用 `TWOBRAIN_DINGTALK_ENV` 覆盖。**文件不存在或字段缺失 = 通道自动关闭，只写日志**，不影响巡检本身。
- 发送口径：**只在两个时刻响** —— 出现新失败发一条 `FAIL`（列出非 ok 的检查项），恢复正常发一条 `RECOVERED`；
  同一故障持续时最多每 20 小时提醒一次；**全部正常时完全静默**（刻意没有心跳）。
  `warn` 不算失败（磁盘将满、WAL 偏大这类只进文件）。
- 去重水位：`state/dingtalk-last.json`，**只有发送成功才更新**，所以网络抖动会在下一轮重试。
- 签名：`timestamp + "\n" + secret` 的 HMAC-SHA256 → base64 → URL-encode，`errcode == 0` 才算发出，超时 10 秒。
- 手动验证：`python3 /srv/2brain/app/ops/2brain-check.py --dingtalk-test --no-mail; echo rc=$?`
  （`rc=0` 才是真发出去了）。临时静音：传 `--no-dingtalk`。
- 边界：巡检只在主机活着时才会发，整机断电不会有消息 —— 这类"看门狗自己死了"只能靠别处发现。

## 邮件告警（可选，默认关闭）

`TWOBRAIN_MAIL_ENABLED=1` 才发信；不设 = 只写 `check-latest.json` 与 `backup.log`。
巡检结果除了写文件，还会投递一封邮件，避免"日志没人看"：

- 失败 → 立刻一封；同一故障持续 → 每 20 小时最多一封；恢复 → 补一封 `RECOVERED`；
  全部正常 → 每 168 小时（一周）一封 `OK` 心跳，用于证明巡检任务和邮件通道都还活着。
- 去重水位在 `state/notify-last.json`，**只有发送成功才更新**，所以发送失败会在下一轮重试。
- 发送账号与收件人放在 `EnvironmentFile=-/etc/2brain/keys/mail.env`（600）：`TWOBRAIN_MAIL_TO=<your-mailbox@example.com>`。
- **SMTP 授权码单独放在 `/etc/2brain/keys/mail.pass`（600，只有一行）**，脚本只在发送那一刻读进内存；
  不要提交到仓库、不要写进文档/日志/巡检输出。多数邮箱要求用"授权码"而不是登录密码，且要求发件人 = 登录账号。
- 手动验证：`set -a; . /etc/2brain/keys/mail.env; set +a; python3 /srv/2brain/app/ops/2brain-check.py --notify-test; echo rc=$?`
  （`rc=0` 才是真发出去了；`mail error auth code file missing` = 授权码还没放）。临时停发：传 `--no-mail`。
- 边界：巡检只在主机活着时才会发，整机断电不会有邮件——这类"看门狗自己死了"只能靠每周心跳的**缺席**发现。

SQLite 备份使用 `sqlite3.Connection.backup()`，可安全用于运行中的 WAL 库；备份文件会转为 `journal_mode=DELETE` 并跑 `integrity_check`。
U 盘/远端拉取按 **SHA256 比较** 决定是否覆盖：远端同名文件内容不同也会被替换。

## 安装（systemd 系统级示例）

单元模板在 `ops/systemd/`，默认 `User=2brain` / `Group=2brain`、路径 `/srv/2brain`，请按实际用户与路径修改后再安装：

```bash
sudo install -m 644 ops/systemd/2brain-*.service ops/systemd/2brain-*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now 2brain-backup-{live,daily,weekly,pull,check}.timer 2brain-snapshot.timer
systemctl list-timers --all '2brain-*'
```

若用普通用户运行，也可以改成 `systemctl --user` 单元；此时需要 `loginctl enable-linger "$USER"`，否则注销后定时器不跑。

## 远端拉取的前置条件

- 本机有可登录远端的专用 SSH 密钥（建议只给它备份目录的写权限），放在 `/etc/2brain/keys/`，权限 600。
- `known_hosts` 同目录；SSH 一律带 `-F /dev/null`，不读系统 ssh 配置。
- 远端目录存在且为 700；脚本会 `mkdir -p` 并 `chmod 700`。
- 远端若是 Dropbear/busybox，可能没有 `rsync`：脚本用 `scp -O`（legacy SCP 协议），
  远端清理由 `find ... -exec rm -f {} +` 完成。

## 验收 / 日常查看

```bash
/srv/2brain/app/ops/2brain-backup.sh status
cat /srv/2brain/backups/state/check-latest.json
systemctl --no-pager status 2brain-backup-check.service
journalctl -u 2brain-backup-check.service -n 30 --no-pager
/srv/2brain/app/ops/2brain-snapshot.sh list
btrfs property get /srv/.2brain-snapshots/<name> ro
```

## 恢复

1. 停止写入（停掉 2brain-app 等在线服务；恢复期间不要开网页写数据）。
2. 选一份 daily/weekly，先 `sha256sum -c <file>.sha256`，再 `PRAGMA integrity_check;`。
3. 备份当前库：把 `var/2brain.db` 复制到临时位置；**同时移走 `-wal`/`-shm`**，避免旧 WAL 覆盖恢复结果。
4. 把选中的备份复制为 `var/2brain.db`，属主改为运行服务的用户、权限 600。
5. 启动服务，检查 `/api/health`、登录、笔记条数；首次打开网页会按客户端缓存合并，不要用旧设备的离线缓存覆盖。

整机级回滚可直接用 btrfs 只读快照：停服务 → 把快照里的应用目录复制回数据目录（或另建子卷切换挂载），再启动服务。快照是只读的，不能直接当写入目录用。

## 安全边界

- 备份库包含登录校验材料、wrapped DEK 与加密笔记 blob；**不要**放进 OneDrive/坚果云/Syncthing 等第三方同步盘，不要提交到 Git。
- btrfs 快照可能包含旧版明文 JSON、同步 token 等敏感文件，按敏感介质对待，不要对外共享快照目录。
- 远端只保存同一份加密库的副本；丢失介质不会直接泄露明文，但仍应视为敏感介质。
