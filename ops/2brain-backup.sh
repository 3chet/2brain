#!/usr/bin/env bash
# 2brain backup: SQLite online snapshots (live/daily/weekly) + U-disk pull.
# Usage: 2brain-backup.sh snapshot {live|daily|weekly} | pull | status
set -Eeuo pipefail
umask 077

APP_DIR="${TWOBRAIN_APP_DIR:-/srv/2brain/app}"
DB="${TWOBRAIN_DB:-/srv/2brain/var/2brain.db}"
ROOT="${TWOBRAIN_BACKUP_ROOT:-/srv/2brain/backups}"
REMOTE="${TWOBRAIN_REMOTE:-root@backup-host}"
REMOTE_DIR="${TWOBRAIN_REMOTE_DIR:-/mnt/2brain-backup/2brain}"
SSH_KEY="${TWOBRAIN_SSH_KEY:-/etc/2brain/keys/openwrt_ed25519}"
KNOWN_HOSTS="${TWOBRAIN_KNOWN_HOSTS:-/etc/2brain/keys/known_hosts}"

LIVE_KEEP_H=48
DAILY_KEEP_D=30
WEEKLY_KEEP_D=84

mkdir -p "$ROOT/live" "$ROOT/daily" "$ROOT/weekly" "$ROOT/logs" "$ROOT/state"
chmod 700 "$ROOT" "$ROOT/live" "$ROOT/daily" "$ROOT/weekly" "$ROOT/logs" "$ROOT/state" 2>/dev/null || true
exec 9>"$ROOT/.lock"
flock -n 9 || { echo "another 2brain-backup run is active"; exit 0; }

log() {
  local m="$*"
  printf '%s %s\n' "$(date '+%F %T')" "$m" >>"$ROOT/logs/backup.log"
  logger -t 2brain-backup -- "$m" 2>/dev/null || true
}
die() { log "ERROR: $*"; echo "ERROR: $*" >&2; exit 1; }

snapshot() {
  local kind="${1:-}" out tmp base
  [[ "$kind" == live || "$kind" == daily || "$kind" == weekly ]] || die "usage: snapshot live|daily|weekly"
  [[ -f "$DB" ]] || die "db not found: $DB"
  case "$kind" in
    live)   out="$ROOT/live/2brain-live-$(date +%Y%m%d-%H%M%S).db" ;;
    daily)  out="$ROOT/daily/2brain-daily-$(date +%Y%m%d).db" ;;
    weekly) out="$ROOT/weekly/2brain-weekly-$(date +%G-W%V).db" ;;
  esac
  tmp="$out.tmp.$$"
  python3 - "$DB" "$tmp" <<'PY'
import sqlite3, sys
src = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True, timeout=30)
dst = sqlite3.connect(sys.argv[2])
try:
    src.backup(dst)
    dst.commit()
    dst.execute("PRAGMA journal_mode=DELETE").fetchone()
    dst.commit()
    row = dst.execute("PRAGMA integrity_check").fetchone()
    if not row or row[0] != "ok":
        raise SystemExit("integrity_check failed: %r" % (row,))
finally:
    dst.close(); src.close()
PY
  chmod 600 "$tmp"
  mv -f "$tmp" "$out"
  base="$(basename "$out")"
  (cd "$(dirname "$out")" && sha256sum "$base" >"$base.sha256")
  log "snapshot $kind ok $base $(stat -c%s "$out") bytes"
  prune "$kind"
  printf '%s\n' "$out"
}

prune() {
  case "${1:-}" in
    live)   find "$ROOT/live"   -maxdepth 1 -type f -name '2brain-live-*.db*'   -mmin +$((LIVE_KEEP_H * 60)) -delete 2>/dev/null || true ;;
    daily)  find "$ROOT/daily"  -maxdepth 1 -type f -name '2brain-daily-*.db*'  -mtime +"$DAILY_KEEP_D"      -delete 2>/dev/null || true ;;
    weekly) find "$ROOT/weekly" -maxdepth 1 -type f -name '2brain-weekly-*.db*' -mtime +"$WEEKLY_KEEP_D"     -delete 2>/dev/null || true ;;
  esac
}

SSH_OPTS=(-F /dev/null -i "$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=10
          -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$KNOWN_HOSTS")

remote() {
  ssh "${SSH_OPTS[@]}" "$REMOTE" "$@"
}
remote_scp() {
  scp -q -O "${SSH_OPTS[@]}" "$@"
}

pull() {
  local kind f base latest sum rsum list lsum
  remote "mkdir -p '$REMOTE_DIR/daily' '$REMOTE_DIR/weekly'; chmod 700 '$REMOTE_DIR' '$REMOTE_DIR/daily' '$REMOTE_DIR/weekly'" || die "remote mkdir failed"
  shopt -s nullglob
  for f in "$ROOT"/daily/*.db "$ROOT"/weekly/*.db; do
    base="$(basename "$f")"
    kind="$(basename "$(dirname "$f")")"
    lsum="$(sha256sum "$f" | awk '{print $1}')"
    rsum="$(remote "sha256sum '$REMOTE_DIR/$kind/$base' 2>/dev/null" | awk '{print $1}' || true)"
    if [[ "$lsum" != "$rsum" ]]; then
      remote_scp "$f" "$REMOTE:$REMOTE_DIR/$kind/" || die "scp failed: $kind/$base"
      if [[ -f "$f.sha256" ]]; then
        remote_scp "$f.sha256" "$REMOTE:$REMOTE_DIR/$kind/" || die "scp failed: $kind/$base.sha256"
      fi
    fi
  done
  shopt -u nullglob
  for kind in daily weekly; do
    latest="$(ls -1t "$ROOT/$kind"/*.db 2>/dev/null | head -n1 || true)"
    [[ -n "$latest" ]] || continue
    sum="$(sha256sum "$latest" | awk '{print $1}')"
    rsum="$(remote "sha256sum '$REMOTE_DIR/$kind/$(basename "$latest")' 2>/dev/null" | awk '{print $1}' || true)"
    [[ "$sum" == "$rsum" ]] || die "remote checksum mismatch: $kind/$(basename "$latest")"
  done
  remote "find '$REMOTE_DIR/daily' -type f -mtime +$DAILY_KEEP_D -exec rm -f {} +; find '$REMOTE_DIR/weekly' -type f -mtime +$WEEKLY_KEEP_D -exec rm -f {} +" >/dev/null || true
  date +%s >"$ROOT/state/last-pull"
  log "pull ok"
}

status() {
  echo "root=$ROOT"
  echo "db=$DB"
  local k latest
  for k in live daily weekly; do
    latest="$(ls -1t "$ROOT/$k"/*.db 2>/dev/null | head -n1 || true)"
    printf '%-7s %s\n' "$k" "${latest:-none}"
  done
  if [[ -f "$ROOT/state/last-pull" ]]; then
    echo "last-pull=$(date -d "@$(cat "$ROOT/state/last-pull")" '+%F %T')"
  fi
  if [[ -f "$ROOT/state/check-latest.json" ]]; then
    cat "$ROOT/state/check-latest.json"
  fi
}

case "${1:-}" in
  snapshot) snapshot "${2:-}" ;;
  pull) pull ;;
  status) status ;;
  *) echo "usage: $0 snapshot {live|daily|weekly} | pull | status" >&2; exit 2 ;;
esac
