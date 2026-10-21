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
