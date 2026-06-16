#!/usr/bin/env python3
"""
jeTT Knowledge Base Converter
Converts all knowledge base files into jeTT training pairs
Output: ~/Projects/jeTT/jett_kb_training.json
"""

import json
import csv
import os
import zipfile
import glob
import re
from pathlib import Path

KB_PATH = Path.home() / "Projects/jeTT/knowledge_base"
OUTPUT_FILE = Path.home() / "Projects/jeTT/jett_kb_training.json"

training_data = []

def add_pair(input_text, output_text):
    if input_text.strip() and output_text.strip():
        training_data.append({
            "input": input_text.strip(),
            "output": output_text.strip()
        })

def safe_read_zip_file(zip_path, filename_filter=None, max_files=50, max_chars=2000):
    """Extract text content from zip files"""
    results = []
    try:
        with zipfile.ZipFile(zip_path, 'r') as z:
            names = z.namelist()
            if filename_filter:
                names = [n for n in names if any(n.endswith(ext) for ext in filename_filter)]
            for name in names[:max_files]:
                try:
                    content = z.read(name).decode('utf-8', errors='ignore')
                    if content.strip():
                        results.append((name, content[:max_chars]))
                except:
                    continue
    except Exception as e:
        print(f"  [!] Could not read {zip_path}: {e}")
    return results

# ─────────────────────────────────────────────
# MITRE ATT&CK
# ─────────────────────────────────────────────
def convert_mitre(json_path):
    print(f"[*] Converting MITRE ATT&CK: {json_path.name}")
    count = 0
    try:
        with open(json_path) as f:
            data = json.load(f)
        for obj in data.get("objects", []):
            if obj.get("type") == "attack-pattern":
                name = obj.get("name", "")
                desc = obj.get("description", "")
                platforms = ", ".join(obj.get("x_mitre_platforms", []))
                detection = obj.get("x_mitre_detection", "")
                if not name or not desc:
                    continue
                # Training pair 1: what is this technique
                add_pair(
                    f"What is the MITRE ATT&CK technique '{name}'?",
                    f"{desc[:500]}"
                )
                # Training pair 2: detection
                if detection:
                    add_pair(
                        f"How do I detect '{name}' on {platforms}?",
                        f"{detection[:500]}"
                    )
                # Training pair 3: guard mode style
                if "execution" in desc.lower() or "command" in desc.lower():
                    add_pair(
                        f"Process event matches MITRE technique '{name}'. Should jeTT quarantine?",
                        f"QUARANTINE — This matches {name}. {desc[:200]}"
                    )
                count += 1
        print(f"    → {count} techniques converted")
    except Exception as e:
        print(f"  [!] Error: {e}")

for f in KB_PATH.glob("mitre_attack/*.json"):
    convert_mitre(f)

# ─────────────────────────────────────────────
# CVE DATABASE
# ─────────────────────────────────────────────
def convert_cves(csv_path):
    print(f"[*] Converting CVEs: {csv_path.name}")
    count = 0
    try:
        with open(csv_path, newline='', errors='ignore') as f:
            reader = csv.DictReader(f)
            for row in reader:
                cve_id = row.get("cveID") or row.get("CVE") or row.get("id", "")
                desc = row.get("shortDescription") or row.get("description", "")
                severity = row.get("cvssV3Severity") or row.get("severity", "")
                if not cve_id or not desc:
                    continue
                add_pair(
                    f"What is {cve_id} and how dangerous is it?",
                    f"{cve_id} ({severity}): {desc[:400]}"
                )
                if severity in ("CRITICAL", "HIGH"):
                    add_pair(
                        f"System shows indicators of {cve_id} exploitation. jeTT verdict?",
                        f"QUARANTINE — {cve_id} is {severity} severity. {desc[:200]}"
                    )
                count += 1
                if count > 5000:
                    break
        print(f"    → {count} CVEs converted")
    except Exception as e:
        print(f"  [!] Error: {e}")

for f in KB_PATH.glob("cve_database/*.csv"):
    convert_cves(f)

# ─────────────────────────────────────────────
# GTFOBins
# ─────────────────────────────────────────────
def convert_gtfobins(json_path):
    print(f"[*] Converting GTFOBins: {json_path.name}")
    count = 0
    try:
        with open(json_path) as f:
            data = json.load(f)
        for binary, info in data.items():
            functions = list(info.get("functions", {}).keys())
            if not functions:
                continue
            add_pair(
                f"Process spawned '{binary}' from an unusual context. jeTT verdict?",
                f"QUARANTINE — '{binary}' is a GTFOBin that can be abused for: {', '.join(functions)}. Verify context before allowing."
            )
            add_pair(
                f"What can an attacker do with '{binary}' on Linux?",
                f"'{binary}' can be abused for: {', '.join(functions)}. It is listed in GTFOBins as a living-off-the-land binary."
            )
            count += 1
        print(f"    → {count} GTFOBins converted")
    except Exception as e:
        print(f"  [!] Error: {e}")

gtfobins = KB_PATH / "security_datasets/gtfobins.json"
if gtfobins.exists():
    convert_gtfobins(gtfobins)

# ─────────────────────────────────────────────
# LOLBAS
# ─────────────────────────────────────────────
def convert_lolbas(json_path):
    print(f"[*] Converting LOLBAS: {json_path.name}")
    count = 0
    try:
        with open(json_path) as f:
            data = json.load(f)
        if isinstance(data, list):
            for item in data:
                name = item.get("Name", "")
                desc = item.get("Description", "")
                commands = item.get("Commands", [])
                if not name:
                    continue
                cmd_str = "; ".join([c.get("Command", "") for c in commands[:3]])
                add_pair(
                    f"Detected '{name}' executing in an unusual context on GowskiNet. jeTT verdict?",
                    f"QUARANTINE — '{name}' is a LOLBAS (Living Off the Land Binary). {desc}. Known abuse commands: {cmd_str[:300]}"
                )
                count += 1
        print(f"    → {count} LOLBAS converted")
    except Exception as e:
        print(f"  [!] Error: {e}")

lolbas = KB_PATH / "security_datasets/lolbas.json"
if lolbas.exists():
    convert_lolbas(lolbas)

# ─────────────────────────────────────────────
# AlienVault OTX
# ─────────────────────────────────────────────
def convert_otx(json_path):
    print(f"[*] Converting AlienVault OTX: {json_path.name}")
    count = 0
    try:
        with open(json_path) as f:
            data = json.load(f)
        pulses = data if isinstance(data, list) else data.get("results", [])
        for pulse in pulses[:500]:
            name = pulse.get("name", "")
            desc = pulse.get("description", "")
            tags = ", ".join(pulse.get("tags", []))
            indicators = pulse.get("indicators", [])
            iocs = [i.get("indicator", "") for i in indicators[:5] if i.get("indicator")]
            if not name:
                continue
            add_pair(
                f"Threat intelligence pulse: '{name}'. What should jeTT know?",
                f"Threat: {name}. {desc[:300]}. Tags: {tags}. IOCs: {', '.join(iocs)}"
            )
            for ioc in iocs:
                if ioc:
                    add_pair(
                        f"Network connection to {ioc} detected. jeTT verdict?",
                        f"QUARANTINE — {ioc} is a known IOC from threat pulse '{name}'. {desc[:200]}"
                    )
            count += 1
        print(f"    → {count} OTX pulses converted")
    except Exception as e:
        print(f"  [!] Error: {e}")

otx = KB_PATH / "security_datasets/alienvault_otx.json"
if otx.exists():
    convert_otx(otx)

# ─────────────────────────────────────────────
# Exploit-DB CSV
# ─────────────────────────────────────────────
def convert_exploitdb(csv_path):
    print(f"[*] Converting ExploitDB: {csv_path.name}")
    count = 0
    try:
        with open(csv_path, newline='', errors='ignore') as f:
            reader = csv.DictReader(f)
            for row in reader:
                desc = row.get("description", "")
                platform = row.get("platform", "")
                etype = row.get("type", "")
                if not desc:
                    continue
                add_pair(
                    f"Exploit detected matching: '{desc[:100]}' on {platform}. jeTT verdict?",
                    f"QUARANTINE — Matches known {etype} exploit for {platform}: {desc[:300]}"
                )
                count += 1
                if count > 3000:
                    break
        print(f"    → {count} exploits converted")
    except Exception as e:
        print(f"  [!] Error: {e}")

for f in KB_PATH.glob("exploit_db/*.csv"):
    convert_exploitdb(f)

# ─────────────────────────────────────────────
# MalwareBazaar CSV
# ─────────────────────────────────────────────
def convert_malwarebazaar(csv_path):
    print(f"[*] Converting MalwareBazaar: {csv_path.name}")
    count = 0
    try:
        with open(csv_path, newline='', errors='ignore') as f:
            reader = csv.DictReader(f)
            for row in reader:
                sha256 = row.get("sha256_hash", "")
                family = row.get("signature", "") or row.get("tags", "")
                ftype = row.get("file_type", "")
                if not sha256:
                    continue
                add_pair(
                    f"File with SHA256 {sha256} detected executing on GowskiNet. jeTT verdict?",
                    f"QUARANTINE — SHA256 {sha256} is a known {family} malware sample ({ftype}) from MalwareBazaar."
                )
                count += 1
                if count > 3000:
                    break
        print(f"    → {count} malware samples converted")
    except Exception as e:
        print(f"  [!] Error: {e}")

for f in KB_PATH.glob("malware_samples/*.csv"):
    convert_malwarebazaar(f)

# ─────────────────────────────────────────────
# ZIP files - extract text/markdown/scripts
# ─────────────────────────────────────────────
def convert_zip_generic(zip_path, category):
    print(f"[*] Converting zip: {zip_path.name} [{category}]")
    count = 0
    text_exts = ['.md', '.txt', '.py', '.c', '.rs', '.go', '.sh', '.yaml', '.yml', '.json', '.csv']
    files = safe_read_zip_file(zip_path, text_exts, max_files=30, max_chars=1500)
    for fname, content in files:
        if len(content) < 50:
            continue
        add_pair(
            f"Explain the security relevance of this {category} file '{os.path.basename(fname)}':\n{content[:800]}",
            f"This is a {category} resource. Key content: {content[:600]}"
        )
        # If it looks like a payload/exploit, add a guard pair
        if any(kw in content.lower() for kw in ['exec', 'shell', 'payload', 'exploit', 'reverse', 'bind', 'chmod', 'curl', 'wget']):
            add_pair(
                f"Process executing code similar to this {category} pattern detected. jeTT verdict?\n{content[:300]}",
                f"QUARANTINE — Pattern matches known {category} technique. Suspicious execution indicators found."
            )
        count += 1
    print(f"    → {count} files from {zip_path.name}")

# Categorized zip processing
zip_categories = {
    "kernel_docs": "kernel/eBPF security",
    "exploit_db": "exploit/vulnerability",
    "security_datasets": "security research",
    "malware_samples": "malware research",
    "hardware_docs": "hardware security/payload",
    "network_protocols": "network security",
    "tools_docs": "security tooling",
    "forensics": "digital forensics",
    "iot_security": "IoT security",
    "linux_docs": "Linux systems",
    "rust_docs": "Rust security",
}

for folder, category in zip_categories.items():
    for zip_path in (KB_PATH / folder).glob("*.zip"):
        convert_zip_generic(zip_path, category)

# ─────────────────────────────────────────────
# syscall table
# ─────────────────────────────────────────────
syscall_file = KB_PATH / "linux_docs/syscall_64.tbl"
if syscall_file.exists():
    print(f"[*] Converting syscall table")
    count = 0
    with open(syscall_file) as f:
        for line in f:
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            parts = line.split()
            if len(parts) >= 3:
                num, abi, name = parts[0], parts[1], parts[2]
                add_pair(
                    f"Linux syscall number {num} ({name}) called from an unexpected process. jeTT verdict?",
                    f"Syscall {num} is '{name}' (ABI: {abi}). Suspicious use from unknown process may indicate exploitation or evasion."
                )
                count += 1
    print(f"    → {count} syscalls converted")

# ─────────────────────────────────────────────
# GowskiNet benign process whitelist
# ─────────────────────────────────────────────
print("[*] Adding GowskiNet benign process pairs...")
benign_processes = [
    ("bifrost PID:1204 started by systemd uid:1000 time:22:00 normal startup", "ALLOW — bifrost is jeTT's companion EDR on GowskiNet. Trusted process."),
    ("ollama PID:2341 serving model uid:1000 port:11434 started by cosmic", "ALLOW — ollama is the local AI inference server on GowskiNet. Trusted."),
    ("docker PID:891 started by systemd uid:root containers:honeypot", "ALLOW — Docker running honeypot stack on GowskiNet. Expected behavior."),
    ("cowrie PID:445 ssh honeypot uid:cowrie port:2222", "ALLOW — Cowrie is the GowskiNet SSH honeypot. Trusted security tool."),
    ("cargo PID:3211 build --release uid:1000 project:jeTT", "ALLOW — cargo is the Rust build tool. Normal development activity."),
    ("cosmic-comp PID:102 wayland compositor uid:1000", "ALLOW — cosmic-comp is the NyXxOS window compositor. System process."),
    ("meshtastic PID:5521 serial:/dev/ttyUSB0 uid:1000", "ALLOW — meshtastic is the LoRa mesh network tool on GowskiNet."),
    ("rclone PID:7823 sync backup uid:1000 remote:gdrive", "ALLOW — rclone is the backup sync tool. Scheduled backup activity."),
    ("prometheus PID:9100 scraping metrics uid:prometheus", "ALLOW — Prometheus is the GowskiNet monitoring stack. Trusted."),
    ("grafana PID:3000 dashboard uid:grafana", "ALLOW — Grafana is the GowskiNet monitoring dashboard. Trusted."),
    ("gni_server PID:6969 skull AI server uid:1000 port:6969", "ALLOW — GNI is Joseph's T-800 skull AI project. Trusted GowskiNet device."),
    ("mosquitto PID:1883 MQTT broker uid:mosquitto", "ALLOW — Mosquitto is the GowskiNet MQTT broker. Trusted IoT infrastructure."),
    ("sshd PID:22 accepting connections uid:root port:22", "ALLOW — sshd is the SSH daemon. Normal system service."),
    ("systemd PID:1 init uid:root", "ALLOW — systemd is the init system. Core OS process."),
]

for inp, out in benign_processes:
    add_pair(inp, out)

print(f"    → {len(benign_processes)} benign GowskiNet pairs added")

# ─────────────────────────────────────────────
# Save output
# ─────────────────────────────────────────────
print(f"\n[+] Total training pairs generated: {len(training_data)}")
print(f"[+] Saving to {OUTPUT_FILE}...")

with open(OUTPUT_FILE, 'w') as f:
    json.dump(training_data, f, indent=2)

print(f"[+] DONE. {OUTPUT_FILE} ready for Round 2 training.")
