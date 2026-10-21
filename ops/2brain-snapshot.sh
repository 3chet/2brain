#!/usr/bin/env bash
# Read-only btrfs snapshot of the fnOS user subvolume that contains 2brain.
# Usage: 2brain-snapshot.sh snapshot | list
set -Eeuo pipefail
umask 077

SRC="${TWOBRAIN_SNAPSHOT_SRC:-/srv}"
DIR="${TWOBRAIN_SNAPSHOT_DIR:-/srv/.2brain-snapshots}"
PREFIX="${TWOBRAIN_SNAPSHOT_PREFIX:-2brain-snap-}"
KEEP_D="${TWOBRAIN_SNAPSHOT_KEEP_DAYS:-14}"

log() { logger -t 2brain-snapshot -- "$*" 2>/dev/null || true; }
die() { echo "ERROR: $*" >&2; log "ERROR: $*"; exit 1; }

[[ -d "$SRC" ]] || die "snapshot source not found: $SRC"
command -v btrfs >/dev/null || die "btrfs not found"

case "${1:-}" in
  snapshot)
    mkdir -p "$DIR"
    chgrp 2brain "$DIR" 2>/dev/null || true
    chmod 750 "$DIR"
    name="$PREFIX$(date +%Y%m%d-%H%M%S)"
    btrfs subvolume snapshot -r "$SRC" "$DIR/$name"
    sync
    find "$DIR" -mindepth 1 -maxdepth 1 -type d -name "${PREFIX}*" -mtime +"$KEEP_D" -print0 \
      | while IFS= read -r -d '' old; do
          btrfs subvolume delete "$old" >/dev/null
          log "pruned $old"
        done
    log "snapshot ok $DIR/$name"
    printf '%s\n' "$DIR/$name"
    ;;
  list)
    find "$DIR" -mindepth 1 -maxdepth 1 -type d -name "${PREFIX}*" -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort
    ;;
  *)
    echo "usage: $0 snapshot | list" >&2
    exit 2
    ;;
esac
