#!/usr/bin/env python3
"""Synthetic demo events for SUNavigator walkthroughs. Standard library only.

Environment: SPLUNK_MGMT_URL, SPLUNK_ADMIN_USER, SPLUNK_ADMIN_PASSWORD (never on the command line).
Usage:  sun_demo_generator.py base     # 24 h of baseline events (os + sun_demo)
        sun_demo_generator.py burst    # 30 failed SSH logins from one source in the last few minutes
Indexes used: os, sun_demo (create them first). Hosts and addresses are invented (RFC 5737 documentation range).
"""
import base64, os, random, ssl, sys, urllib.parse, urllib.request
from datetime import datetime, timedelta

random.seed(11)
CTX = ssl._create_unverified_context()
BASE = os.environ["SPLUNK_MGMT_URL"]
AUTH = base64.b64encode(f'{os.environ["SPLUNK_ADMIN_USER"]}:{os.environ["SPLUNK_ADMIN_PASSWORD"]}'.encode()).decode()
NOW = datetime.now().astimezone()

def send(index, sourcetype, host, source, lines):
    q = urllib.parse.urlencode({"index": index, "sourcetype": sourcetype, "host": host, "source": source})
    req = urllib.request.Request(f"{BASE}/services/receivers/simple?{q}", data="\n".join(lines).encode(), method="POST",
                                 headers={"Authorization": "Basic " + AUTH})
    with urllib.request.urlopen(req, context=CTX, timeout=120) as r:
        r.read()
    print(f"{index}/{sourcetype}: {len(lines)} events")

def syslog(t, host, msg): return f"{t.strftime('%b %e %H:%M:%S')} {host} {msg}"
def iso(t): return t.strftime("%Y-%m-%d %H:%M:%S")
def spread(hours_back, n): return sorted(NOW - timedelta(minutes=random.uniform(2, hours_back * 60)) for _ in range(n))

def base():
    users = ["alice", "bob", "carol", "dave"]
    ok = [syslog(t, "demo-linux-01", f"sshd[{random.randint(1000,9999)}]: Accepted publickey for {random.choice(users)} from 198.51.100.{random.randint(10,40)} port {random.randint(40000,60000)} ssh2") for t in spread(24, 80)]
    bad = [syslog(t, "demo-linux-01", f"sshd[{random.randint(1000,9999)}]: Failed password for {random.choice(users)} from 198.51.100.{random.randint(10,40)} port {random.randint(40000,60000)} ssh2") for t in spread(24, 12)]
    sudo = [syslog(t, "demo-linux-01", f"sudo: {random.choice(users)} : command not allowed ; TTY=pts/0 ; PWD=/home/u ; USER=root ; COMMAND=/bin/cat /etc/shadow") for t in spread(24, 6)]
    send("os", "linux_secure", "demo-linux-01", "/var/log/secure", sorted(ok + bad + sudo))
    send("os", "cpu", "demo-linux-01", "cpu", [f"{iso(t)} cpu=all pctUser={random.uniform(5,40):.2f} pctSystem={random.uniform(1,10):.2f} pctIdle={random.uniform(50,90):.2f}" for t in spread(24, 96)])
    send("os", "vmstat", "demo-linux-01", "vmstat", [f"{iso(t)} memTotalMB=16000 memFreeMB={random.randint(2000,9000)} swapUsedMB=0" for t in spread(24, 96)])
    # stale sourcetype: newest event is about 30 hours old
    stale = sorted(NOW - timedelta(hours=random.uniform(30, 60)) for _ in range(40))
    send("os", "df", "demo-linux-01", "df", [f"{iso(t)} Filesystem=/dev/sda1 MountedOn=/ UsePct={random.randint(40,70)} TotalMB=100000" for t in stale])
    # sun_demo: a Windows-style authentication sourcetype in a differently named index, plus auditd and syslog
    win = []
    for t in spread(24, 90):
        code = random.choice([4624] * 7 + [4625] * 2 + [4740])
        win.append(f"{iso(t)} EventCode={code} Account_Name={random.choice(['alice','bob','carol','dave'])} Source_Network_Address=198.51.100.{random.randint(10,40)} Logon_Type=3")
    send("sun_demo", "WinEventLog:Security", "demo-win-01", "demo:winsec", win)
    send("sun_demo", "auditd", "demo-linux-01", "/var/log/audit/audit.log", [f"{iso(t)} type=SYSCALL syscall=59 success=yes uid={random.choice([0,1000,1001])} comm=\"bash\"" for t in spread(24, 60)])
    send("sun_demo", "syslog", "demo-linux-01", "/var/log/messages", [syslog(t, "demo-linux-01", f"systemd[1]: Started Session {random.randint(1,999)} of user alice.") for t in spread(24, 60)])

def burst():
    t0 = NOW - timedelta(minutes=2)
    lines = [syslog(t0 - timedelta(seconds=45 - i), "demo-linux-01", f"sshd[{4000+i}]: Failed password for invalid user admin from 203.0.113.50 port {50000+i} ssh2") for i in range(30)]
    send("os", "linux_secure", "demo-linux-01", "/var/log/secure", lines)

if __name__ == "__main__":
    {"base": base, "burst": burst}[sys.argv[1]]()
