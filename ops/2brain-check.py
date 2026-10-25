#!/usr/bin/env python3
"""2brain backup & service health check.

Exit 0 when only "ok"/"warn" checks exist, 1 when any check fails.
Writes state/check-latest.json and appends one line to logs/backup.log.
No secret material is read or printed.
"""
import hashlib
import json
import os
import shlex
import sqlite3
import subprocess
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path

ROOT = Path(os.environ.get("TWOBRAIN_BACKUP_ROOT", "/srv/2brain/backups"))
DB = Path(os.environ.get("TWOBRAIN_DB", "/srv/2brain/var/2brain.db"))
REMOTE = os.environ.get("TWOBRAIN_REMOTE", "root@backup-host")
REMOTE_DIR = os.environ.get("TWOBRAIN_REMOTE_DIR", "/mnt/2brain-backup/2brain")
SSH_KEY = os.environ.get("TWOBRAIN_SSH_KEY", "/etc/2brain/keys/openwrt_ed25519")
KNOWN_HOSTS = os.environ.get("TWOBRAIN_KNOWN_HOSTS", "/etc/2brain/keys/known_hosts")
SNAPSHOT_DIR = Path(os.environ.get("TWOBRAIN_SNAPSHOT_DIR", "/srv/.2brain-snapshots"))
SERVICES = ("2brain-app.service", "sharect-web.service", "2brain-sync.service")

checks = []


def add(name, status, detail):
    checks.append({"name": name, "status": status, "detail": detail})


def newest(kind):
    files = sorted((ROOT / kind).glob("*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None


def age_h(path):
    return (time.time() - path.stat().st_mtime) / 3600


def sha_ok(path):
    side = path.with_name(path.name + ".sha256")
    if not side.exists():
        return False, "sidecar missing"
    want = side.read_text(encoding="utf-8").split()[0].strip()
    got = hashlib.sha256(path.read_bytes()).hexdigest()
    return (want == got), ("ok" if want == got else "mismatch")


def integrity(path):
    try:
        con = sqlite3.connect("file:%s?mode=ro" % path, uri=True, timeout=10)
        try:
            row = con.execute("PRAGMA quick_check").fetchone()
        finally:
            con.close()
        return bool(row and row[0] == "ok"), (row[0] if row else "no result")
    except Exception as exc:
        return False, str(exc)


def systemctl_active(unit):
    try:
        rc = subprocess.run(["systemctl", "is-active", "--quiet", unit], timeout=10).returncode
        return rc == 0
    except Exception:
        return False


def http_ok(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            body = resp.read(4096)
            return resp.status == 200, body
    except Exception as exc:
        return False, str(exc)


def remote(cmd):
    return subprocess.run(
        ["ssh", "-F", "/dev/null", "-i", SSH_KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
         "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=" + KNOWN_HOSTS, REMOTE, cmd],
        capture_output=True, text=True, timeout=40,
    )


def last_pull_age_h():
    p = ROOT / "state/last-pull"
    if not p.exists():
        return None
    try:
        return (time.time() - int(p.read_text().strip())) / 3600
    except Exception:
        return None


def main():
    now = datetime.now().astimezone()

    # local snapshot freshness
    live = newest("live")
    daily = newest("daily")
    weekly = newest("weekly")

    if live is None:
        add("live_snapshot", "fail", "no live snapshot")
    else:
        h = age_h(live)
        add("live_snapshot", "ok" if h <= 0.75 else ("warn" if h <= 1.5 else "fail"),
            "%s age %.1fh" % (live.name, h))

    if daily is None:
        add("daily_snapshot", "fail", "no daily snapshot")
    else:
        h = age_h(daily)
        add("daily_snapshot", "ok" if h <= 26 else "fail", "%s age %.1fh" % (daily.name, h))

    if weekly is None:
        add("weekly_snapshot", "fail", "no weekly snapshot")
    else:
        h = age_h(weekly)
        add("weekly_snapshot", "ok" if h <= 168 else ("warn" if h <= 192 else "fail"),
            "%s age %.1fh" % (weekly.name, h))

    # integrity + checksum of daily/weekly
    for kind, path in (("daily", daily), ("weekly", weekly)):
        if path is None:
            continue
        ok, detail = integrity(path)
        add("%s_integrity" % kind, "ok" if ok else "fail", "%s: %s" % (path.name, detail))
        if ok:
            ok2, detail2 = sha_ok(path)
            add("%s_sha256" % kind, "ok" if ok2 else "fail", "%s: %s" % (path.name, detail2))

    # database + WAL
    if not DB.exists():
        add("database", "fail", "db missing: %s" % DB)
    else:
        wal = Path(str(DB) + "-wal")
        add("database", "ok", "%s %.1f MB" % (DB.name, DB.stat().st_size / 1048576))
        if wal.exists():
            mb = wal.stat().st_size / 1048576
            add("wal_size", "ok" if mb < 64 else ("warn" if mb < 256 else "fail"), "%.1f MB" % mb)

    # services
    for unit in SERVICES:
        add("service_%s" % unit.replace(".service", ""), "ok" if systemctl_active(unit) else "fail",
            "active" if systemctl_active(unit) else "inactive")

    # HTTP health
    ok, body = http_ok("http://127.0.0.1:8090/api/health")
    health = {}
    if ok:
        try:
            health = json.loads(body.decode("utf-8"))
            ok = bool(health.get("ok"))
        except Exception:
            ok = False
    add("api_health", "ok" if ok else "fail", "127.0.0.1:8090/api/health")

    # archive readiness: false means permanent archive and the reset flow both 503
    if "archive" in health:
        add("archive_ready", "ok" if health.get("archive") else "fail",
            "ok" if health.get("archive") else "archive:false; /api/brain/archive and reset would 503")
    else:
        add("archive_ready", "warn", "health response has no archive field")
    ok, _ = http_ok("http://127.0.0.1:8088/2brain.html")
    add("web_page", "ok" if ok else "fail", "127.0.0.1:8088/2brain.html")

    # local disk
    st = os.statvfs(str(ROOT))
    free_gb = st.f_bavail * st.f_frsize / 1073741824
    add("disk_free", "ok" if free_gb >= 5 else ("warn" if free_gb >= 1 else "fail"), "%.1f GB" % free_gb)

    # permissions
    mode = (ROOT.stat().st_mode & 0o777)
    add("backup_dir_mode", "ok" if mode & 0o077 == 0 else "warn", oct(mode))

    # btrfs read-only snapshots; snapshot dirs keep the source mtime, so use the name timestamp
    snaps = sorted(p for p in SNAPSHOT_DIR.glob("2brain-snap-*") if p.is_dir()) if SNAPSHOT_DIR.exists() else []
    if not snaps:
        add("btrfs_snapshot", "warn", "none in %s" % SNAPSHOT_DIR)
    else:
        import re
        m = re.search(r"(\d{8})-(\d{6})$", snaps[-1].name)
        if m:
            made = datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S").astimezone()
            h = (now - made).total_seconds() / 3600
        else:
            h = age_h(snaps[-1])
        add("btrfs_snapshot", "ok" if h <= 26 else ("warn" if h <= 36 else "fail"),
            "%s age %.1fh, %d kept" % (snaps[-1].name, h, len(snaps)))

    # remote U disk
    pull_age = last_pull_age_h()
    add("last_pull", "ok" if (pull_age is not None and pull_age <= 26) else
        ("warn" if pull_age is not None and pull_age <= 36 else "fail"),
        "never" if pull_age is None else "%.1fh ago" % pull_age)
    remote_ok = True
    try:
        r = remote("echo ok")
        remote_ok = r.returncode == 0 and "ok" in r.stdout
        if not remote_ok:
            add("remote_u_disk", "warn" if (pull_age is not None and pull_age <= 26) else "fail",
                "ssh failed: %s" % (r.stderr.strip()[:120] or "unknown"))
        else:
            for kind, path in (("daily", daily), ("weekly", weekly)):
                if path is None:
                    continue
                local_sum = hashlib.sha256(path.read_bytes()).hexdigest()
                rp = "%s/%s/%s" % (REMOTE_DIR, kind, path.name)
                rr = remote("sha256sum %s 2>/dev/null" % shlex.quote(rp))
                rsum = rr.stdout.split()[0] if rr.returncode == 0 and rr.stdout.split() else ""
                if not rsum:
                    status = "fail" if (pull_age is None or pull_age > 26) else "warn"
                    add("remote_%s" % kind, status, "missing %s" % path.name)
                elif rsum != local_sum:
                    add("remote_%s" % kind, "fail", "checksum mismatch %s" % path.name)
                else:
                    add("remote_%s" % kind, "ok", path.name)
            rr = remote("df -Pk %s | tail -1" % shlex.quote(REMOTE_DIR))
            try:
                avail = int(rr.stdout.split()[3])
                gb = avail / 1048576
                add("remote_disk_free", "ok" if gb >= 1 else "fail", "%.1f GB" % gb)
            except Exception:
                add("remote_disk_free", "warn", "could not parse df")
    except Exception as exc:
        add("remote_u_disk", "warn" if (pull_age is not None and pull_age <= 26) else "fail", "ssh error: %s" % exc)

    failures = sum(1 for c in checks if c["status"] == "fail")
    warnings = sum(1 for c in checks if c["status"] == "warn")
    out = {
        "at": now.isoformat(timespec="seconds"),
        "ok": failures == 0,
        "failures": failures,
        "warnings": warnings,
        "checks": checks,
    }
    state = ROOT / "state/check-latest.json"
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    line = "%s check %s failures=%d warnings=%d\n" % (now.strftime("%F %T"), "OK" if failures == 0 else "FAIL", failures, warnings)
    with open(ROOT / "logs/backup.log", "a", encoding="utf-8") as fh:
        fh.write(line)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
