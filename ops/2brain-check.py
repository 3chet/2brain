#!/usr/bin/env python3
"""2brain backup & service health check.

Exit 0 when only "ok"/"warn" checks exist, 1 when any check fails.
Writes state/check-latest.json and appends lines to logs/backup.log
(the log is trimmed to the last 90 days on every run).
Push channel is DingTalk: one message when a failure appears, one when it recovers,
at most one per 20h while still failing, and nothing at all when everything is ok.
Mail is OFF unless TWOBRAIN_MAIL_ENABLED=1 (2026-10-26: the mail channel is on hold;
everything is recorded in check-latest.json + backup.log instead). When enabled it
alerts on failure (at most one per day while still failing), on recovery, as a weekly
all-green heartbeat, or with --notify-test.
No secret material is read into the output, printed, or logged.

Mail is configured only through the environment / an EnvironmentFile:
  TWOBRAIN_MAIL_ENABLED    "1" turns automatic mail on; anything else (or unset) = off
  TWOBRAIN_MAIL_TO         recipient list, comma separated (empty = mail disabled)
  TWOBRAIN_MAIL_USER       sending mailbox (defaults to the first recipient)
  TWOBRAIN_MAIL_PASS_FILE  path holding only the SMTP auth code (never stored in the repo)
  TWOBRAIN_MAIL_SMTP       host, default smtp.example.com
  TWOBRAIN_MAIL_PORT       port, default 465 (SMTP SSL)
DingTalk is configured by TWOBRAIN_DINGTALK_ENV (default /etc/2brain/keys/dingtalk.env,
mode 600, keys DINGTALK_WEBHOOK / DINGTALK_SECRET); missing file just disables the channel.
Flags: --notify-test sends one test mail regardless of the enabled flag and status;
--dingtalk-test sends one test DingTalk message; --no-mail / --no-dingtalk disable
that channel for this run.
"""
import base64
import hashlib
import hmac
import json
import os
import shlex
import smtplib
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(os.environ.get("TWOBRAIN_BACKUP_ROOT", "/srv/2brain/backups"))
DB = Path(os.environ.get("TWOBRAIN_DB", "/srv/2brain/var/2brain.db"))
REMOTE = os.environ.get("TWOBRAIN_REMOTE", "root@backup-host")
REMOTE_DIR = os.environ.get("TWOBRAIN_REMOTE_DIR", "/mnt/2brain-backup/2brain")
SSH_KEY = os.environ.get("TWOBRAIN_SSH_KEY", "/etc/2brain/keys/openwrt_ed25519")
KNOWN_HOSTS = os.environ.get("TWOBRAIN_KNOWN_HOSTS", "/etc/2brain/keys/known_hosts")
SNAPSHOT_DIR = Path(os.environ.get("TWOBRAIN_SNAPSHOT_DIR", "/srv/.2brain-snapshots"))
SERVICES = ("2brain-app.service", "sharect-web.service", "2brain-sync.service")

MAIL_TO = os.environ.get("TWOBRAIN_MAIL_TO", "").strip()
MAIL_ENABLED = os.environ.get("TWOBRAIN_MAIL_ENABLED", "0").strip() == "1"
MAIL_SMTP_HOST = os.environ.get("TWOBRAIN_MAIL_SMTP", "smtp.example.com").strip()
MAIL_SMTP_PORT = int(os.environ.get("TWOBRAIN_MAIL_PORT", "465"))
MAIL_USER = os.environ.get("TWOBRAIN_MAIL_USER", "").strip()
MAIL_PASS_FILE = os.environ.get("TWOBRAIN_MAIL_PASS_FILE", "/etc/2brain/keys/mail.pass")
NOTIFY_STATE = ROOT / "state/notify-last.json"
DINGTALK_ENV = os.environ.get("TWOBRAIN_DINGTALK_ENV", "/etc/2brain/keys/dingtalk.env")
DINGTALK_STATE = ROOT / "state/dingtalk-last.json"
DINGTALK_TIMEOUT = 10
LOG_RETENTION_DAYS = 90
RE_ALERT_H = 20.0
HEARTBEAT_H = 168.0

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


def mail_recipients():
    return [a.strip() for a in MAIL_TO.split(",") if a.strip()]


def mail_sender():
    return MAIL_USER or (mail_recipients() or [""])[0]


def mail_auth_code():
    try:
        lines = [x.strip() for x in Path(MAIL_PASS_FILE).read_text(encoding="utf-8").splitlines()]
        return next((x for x in lines if x), None)
    except Exception:
        return None


def send_mail(subject, body):
    sender = mail_sender()
    to = mail_recipients()
    code = mail_auth_code()
    if not sender or not to:
        return False, "TWOBRAIN_MAIL_TO / TWOBRAIN_MAIL_USER not set"
    if code is None:
        return False, "auth code file missing"
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = ", ".join(to)
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        with smtplib.SMTP_SSL(MAIL_SMTP_HOST, MAIL_SMTP_PORT, timeout=25) as srv:
            srv.ehlo()
            srv.login(sender, code)
            srv.send_message(msg)
        return True, "sent to %d address(es)" % len(to)
    except Exception as exc:
        return False, "%s: %s" % (type(exc).__name__, str(exc)[:150])


def last_notify():
    try:
        return json.loads(NOTIFY_STATE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def need_notify(out, now):
    prev = last_notify()
    if out["failures"] > 0:
        if prev.get("status") != "fail":
            return True, "new failure"
        try:
            gap = (now - datetime.fromisoformat(prev["at"])).total_seconds() / 3600
        except Exception:
            return True, "no previous timestamp"
        return gap >= RE_ALERT_H, "still failing" if gap >= RE_ALERT_H else "reminded %.1fh ago" % gap
    if prev.get("status") == "fail":
        return True, "recovered"
    try:
        gap = (now - datetime.fromisoformat(prev["at"])).total_seconds() / 3600
    except Exception:
        return True, "never notified"
    return gap >= HEARTBEAT_H, "weekly heartbeat" if gap >= HEARTBEAT_H else "quiet %.1fh" % gap


def notify(out, now, force=False):
    if not force and not MAIL_ENABLED:
        return {"status": "disabled", "detail": "TWOBRAIN_MAIL_ENABLED != 1 (mail on hold)"}
    if not mail_recipients():
        return {"status": "disabled", "detail": "TWOBRAIN_MAIL_TO not set"}
    if force:
        do, why = True, "manual test"
    else:
        do, why = need_notify(out, now)
    if not do:
        return {"status": "silent", "detail": why}
    bad = [c for c in out["checks"] if c["status"] != "ok"]
    if force:
        tag = "TEST"
    elif out["failures"]:
        tag = "FAIL"
    elif why == "recovered":
        tag = "RECOVERED"
    else:
        tag = "OK"
    subject = "[2brain] backup check %s %d fail / %d warn %s" % (
        tag, out["failures"], out["warnings"], now.strftime("%F %R"))
    lines = []
    if force:
        lines.append("这是一封测试邮件：2brain 备份巡检的邮件通道已经打通。")
        lines.append("")
    elif tag == "RECOVERED":
        lines.append("巡检已恢复正常：%d 项检查全部通过（上次告警 %s）。" % (
            len(out["checks"]), last_notify().get("at", "?")))
        lines.append("")
    elif tag == "OK":
        lines.append("巡检正常：%d 项检查全部通过。这是每周心跳，说明巡检和邮件通道都活着。" % len(out["checks"]))
        lines.append("")
    else:
        lines.append("巡检发现 %d 项失败 / %d 项警告（共 %d 项）：" % (
            out["failures"], out["warnings"], len(out["checks"])))
        lines.append("")
        for c in bad:
            lines.append("- %s [%s] %s" % (c["name"], c["status"], c["detail"]))
        lines.append("")
    lines.append("主机：%s" % socket.gethostname())
    lines.append("明细：%s" % (ROOT / "state/check-latest.json"))
    lines.append("巡检每天 01:00 自动运行；同一故障最多每天提醒一次，全部正常时每周发一封心跳。")
    ok, detail = send_mail(subject, "\n".join(lines) + "\n")
    if ok and not force:
        try:
            NOTIFY_STATE.parent.mkdir(parents=True, exist_ok=True)
            NOTIFY_STATE.write_text(json.dumps({
                "at": now.isoformat(timespec="seconds"),
                "status": "fail" if out["failures"] else "ok",
                "failures": out["failures"],
                "warnings": out["warnings"],
            }, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass
    return {"status": "sent" if ok else "error", "detail": detail, "reason": why, "tag": tag}


def dingtalk_creds():
    try:
        vals = {}
        for ln in Path(DINGTALK_ENV).read_text(encoding="utf-8").splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#") or "=" not in ln:
                continue
            k, v = ln.split("=", 1)
            vals[k.strip()] = v.strip().strip('"').strip("'")
        hook = vals.get("DINGTALK_WEBHOOK", "").rstrip("&")
        secret = vals.get("DINGTALK_SECRET", "")
        return (hook, secret) if hook and secret else (None, None)
    except Exception:
        return None, None


def send_dingtalk(text):
    hook, secret = dingtalk_creds()
    if not hook:
        return False, "dingtalk.env missing or incomplete"
    ts = str(int(time.time() * 1000))
    sign = base64.b64encode(hmac.new(secret.encode("utf-8"), ("%s\n%s" % (ts, secret)).encode("utf-8"),
                                     hashlib.sha256).digest()).decode("ascii")
    sep = "&" if "?" in hook else "?"
    url = "%s%stimestamp=%s&sign=%s" % (hook, sep, ts, urllib.parse.quote_plus(sign))
    body = json.dumps({"msgtype": "text", "text": {"content": text}}, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json; charset=utf-8"})
    try:
        with urllib.request.urlopen(req, timeout=DINGTALK_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if data.get("errcode") == 0:
            return True, "sent"
        return False, "errcode %s: %s" % (data.get("errcode"), str(data.get("errmsg"))[:120])
    except Exception as exc:
        return False, "%s: %s" % (type(exc).__name__, str(exc)[:150])


def last_dingtalk():
    try:
        return json.loads(DINGTALK_STATE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def dingtalk_need(out, now):
    """Push only when a failure appears and when it clears. No heartbeat, no reminders on a fixed
    cadence until the same failure has persisted for RE_ALERT_H, then one nudge per RE_ALERT_H."""
    prev = last_dingtalk()
    if out["failures"] > 0:
        if prev.get("status") != "fail":
            return True, "new failure"
        try:
            gap = (now - datetime.fromisoformat(prev["at"])).total_seconds() / 3600
        except Exception:
            return True, "no previous timestamp"
        return gap >= RE_ALERT_H, "still failing" if gap >= RE_ALERT_H else "reminded %.1fh ago" % gap
    if prev.get("status") == "fail":
        return True, "recovered"
    return False, "all ok"


def dingtalk_notify(out, now, force=False):
    if force:
        do, why = True, "manual test"
    else:
        do, why = dingtalk_need(out, now)
    if not do:
        return {"status": "silent", "detail": why}
    bad = [c for c in out["checks"] if c["status"] != "ok"]
    lines = []
    if force:
        lines.append("这是测试消息：2brain 备份巡检的钉钉通道已打通。")
        lines.append("当前状态：%d 项失败 / %d 项警告（共 %d 项）。" % (out["failures"], out["warnings"], len(out["checks"])))
    elif out["failures"]:
        lines.append("2brain 备份巡检失败：%d 项失败 / %d 项警告（共 %d 项）" % (
            out["failures"], out["warnings"], len(out["checks"])))
        lines.append("")
        for c in bad:
            lines.append("- %s [%s] %s" % (c["name"], c["status"], c["detail"]))
    else:
        lines.append("2brain 备份巡检已恢复：%d 项检查全部通过。" % len(out["checks"]))
        lines.append("上次失败告警：%s" % last_dingtalk().get("at", "?"))
    lines.append("")
    lines.append("主机 %s  时间 %s" % (socket.gethostname(), now.strftime("%F %R")))
    lines.append("明细 %s" % (ROOT / "state/check-latest.json"))
    lines.append("只在出现新失败和恢复时推送；全部正常时完全静默。")
    tag = "TEST" if force else ("FAIL" if out["failures"] else "RECOVERED")
    ok, detail = send_dingtalk("\n".join(lines))
    if ok and not force:
        try:
            DINGTALK_STATE.parent.mkdir(parents=True, exist_ok=True)
            DINGTALK_STATE.write_text(json.dumps({
                "at": now.isoformat(timespec="seconds"),
                "status": "fail" if out["failures"] else "ok",
                "failures": out["failures"],
                "warnings": out["warnings"],
            }, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass
    return {"status": "sent" if ok else "error", "detail": detail, "reason": why, "tag": tag}


def trim_log(path, days=LOG_RETENTION_DAYS):
    """Drop log lines older than `days`. Lines start with 'YYYY-MM-DD HH:MM:SS'."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    kept = [ln for ln in lines if not (len(ln) >= 10 and ln[4] == "-" and ln[7] == "-" and ln[:10] < cutoff)]
    if len(kept) == len(lines):
        return
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
    tmp.replace(path)


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
    snaps = sorted(p for p in SNAPSHOT_DIR.glob("2brain-1004-*") if p.is_dir()) if SNAPSHOT_DIR.exists() else []
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
    result = None
    if "--no-mail" not in sys.argv:
        result = notify(out, now, force=("--notify-test" in sys.argv))
        out["notify"] = result
        with open(ROOT / "logs/backup.log", "a", encoding="utf-8") as fh:
            fh.write("%s mail %s %s\n" % (now.strftime("%F %T"), (result or {}).get("status", "?"),
                                          (result or {}).get("detail", "")))
    dt = None
    if "--no-dingtalk" not in sys.argv:
        dt = dingtalk_notify(out, now, force=("--dingtalk-test" in sys.argv))
        out["dingtalk"] = dt
        with open(ROOT / "logs/backup.log", "a", encoding="utf-8") as fh:
            fh.write("%s dingtalk %s %s\n" % (now.strftime("%F %T"), (dt or {}).get("status", "?"),
                                              (dt or {}).get("detail", "")))
    trim_log(ROOT / "logs/backup.log")
    print(json.dumps(out, ensure_ascii=False, indent=2))
    if "--dingtalk-test" in sys.argv:
        return 0 if (dt or {}).get("status") == "sent" else 1
    if "--notify-test" in sys.argv:
        return 0 if (result or {}).get("status") == "sent" else 1
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
