#!/usr/bin/env python3
"""
jeTT Intelligence Downloader
Downloads real security intelligence into ~/Projects/jeTT/intelligence/
Run this before Round 2 training to maximize jeTT's knowledge.
"""

import os
import subprocess
import json
from pathlib import Path

BASE = Path.home() / "Projects/jeTT/intelligence"

def run(cmd, cwd=None):
    print(f"  $ {cmd}")
    result = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0 and result.stderr:
        print(f"  [!] {result.stderr[:200]}")
    return result.returncode == 0

def clone(url, dest):
    if dest.exists():
        print(f"  [skip] {dest.name} already exists")
        return True
    return run(f"git clone --depth=1 {url} {dest}")

def download(url, dest):
    if dest.exists():
        print(f"  [skip] {dest.name} already exists")
        return True
    return run(f"wget -q -O {dest} '{url}'")

print("=" * 60)
print("jeTT Intelligence Downloader")
print("=" * 60)

# ─────────────────────────────────────────────
# RED TEAM
# ─────────────────────────────────────────────
print("\n[🔴 RED TEAM]")
rt = BASE / "raw_redteam"
rt.mkdir(exist_ok=True)

clone("https://github.com/swisskyrepo/PayloadsAllTheThings", rt / "payloads-all-the-things")
clone("https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet", rt / "ad-exploitation")
clone("https://github.com/cube0x0/CVE-2021-1675", rt / "printspooler-exploit")
clone("https://github.com/carlospolop/PEASS-ng", rt / "peass-privilege-escalation")
clone("https://github.com/mthbernardes/GTRS", rt / "gtrs-c2")
clone("https://github.com/danielmiessler/SecLists", rt / "seclists")
clone("https://github.com/Porchetta-Industries/CrackMapExec", rt / "crackmapexec")
clone("https://github.com/bettercap/bettercap", rt / "bettercap")
clone("https://github.com/BloodHoundAD/BloodHound", rt / "bloodhound")
clone("https://github.com/gentilkiwi/mimikatz", rt / "mimikatz")
clone("https://github.com/samratashok/nishang", rt / "nishang-powershell")
clone("https://github.com/PowerShellMafia/PowerSploit", rt / "powersploit")

# ─────────────────────────────────────────────
# BLUE TEAM
# ─────────────────────────────────────────────
print("\n[🔵 BLUE TEAM]")
bt = BASE / "raw_blueteam"
bt.mkdir(exist_ok=True)

clone("https://github.com/SigmaHQ/sigma", bt / "sigma-rules")
clone("https://github.com/elastic/detection-rules", bt / "elastic-detection-rules")
clone("https://github.com/Neo23x0/sigma", bt / "sigma-neo23x0")
clone("https://github.com/cisagov/CHIRP", bt / "chirp-ioc-scanner")
clone("https://github.com/Yara-Rules/rules", bt / "yara-rules")
clone("https://github.com/Neo23x0/god-mode-rules", bt / "godmode-yara")
clone("https://github.com/google/osdfir-infrastructure", bt / "google-dfir")
clone("https://github.com/redhuntlabs/Awesome-Asset-Discovery", bt / "asset-discovery")
clone("https://github.com/infosecn1nja/AD-Attack-Defense", bt / "ad-attack-defense")
clone("https://github.com/jatrost/awesome-kubernetes-threat-detection", bt / "k8s-threat-detection")
clone("https://github.com/0x4D31/awesome-threat-detection", bt / "threat-detection-awesome")

# ─────────────────────────────────────────────
# KALI / PENTEST TOOLS
# ─────────────────────────────────────────────
print("\n[🐉 KALI TOOLS]")
kali = BASE / "raw_kali"
kali.mkdir(exist_ok=True)

clone("https://github.com/sqlmapproject/sqlmap", kali / "sqlmap")
clone("https://github.com/vanhauser-thc/thc-hydra", kali / "hydra")
clone("https://github.com/threat9/routersploit", kali / "routersploit")
clone("https://github.com/offensive-security/exploit-database", kali / "exploit-database")
clone("https://github.com/rapid7/metasploit-framework", kali / "metasploit")
clone("https://github.com/nmap/nmap", kali / "nmap")
clone("https://github.com/sullo/nikto", kali / "nikto")
clone("https://github.com/wifiphisher/wifiphisher", kali / "wifiphisher")
clone("https://github.com/lgandx/Responder", kali / "responder")
clone("https://github.com/byt3bl33d3r/CrackMapExec", kali / "crackmapexec2")
clone("https://github.com/Tib3rius/AutoRecon", kali / "autorecon")

# ─────────────────────────────────────────────
# EXPLOIT DEV
# ─────────────────────────────────────────────
print("\n[💥 EXPLOIT DEV]")
ed = BASE / "raw_exploitdev"
ed.mkdir(exist_ok=True)

clone("https://github.com/shellphish/how2heap", ed / "how2heap")
clone("https://github.com/Gallopsled/pwntools", ed / "pwntools")
clone("https://github.com/hugsy/gef", ed / "gef-debugger")
clone("https://github.com/pwndbg/pwndbg", ed / "pwndbg")
clone("https://github.com/sashs/Ropper", ed / "ropper-rop-gadgets")
clone("https://github.com/JonathanSalwan/ROPgadget", ed / "ropgadget")
clone("https://github.com/longld/peda", ed / "peda-gdb")
clone("https://github.com/niklasb/libc-database", ed / "libc-database")
clone("https://github.com/radareorg/radare2", ed / "radare2")
clone("https://github.com/AFLplusplus/AFLplusplus", ed / "aflplusplus")

# ─────────────────────────────────────────────
# EXPLOIT DB / VULN DATA
# ─────────────────────────────────────────────
print("\n[🗄️ EXPLOIT DB]")
edb = BASE / "raw_exploitdb"
edb.mkdir(exist_ok=True)

clone("https://github.com/nomi-sec/PoC-in-GitHub", edb / "poc-in-github")
clone("https://github.com/trickest/cve", edb / "trickest-cves")
clone("https://github.com/vulnerable-code/vulhub", edb / "vulhub")
clone("https://github.com/projectdiscovery/nuclei-templates", edb / "nuclei-templates")
clone("https://github.com/shadawck/awesome-anti-forensic", edb / "anti-forensics")
clone("https://github.com/rmusser01/Infosec_Reference", edb / "infosec-reference")

# ─────────────────────────────────────────────
# HAK5 / HARDWARE
# ─────────────────────────────────────────────
print("\n[🔧 HAK5 / HARDWARE]")
hak5 = BASE / "raw_hak5"
hak5.mkdir(exist_ok=True)

clone("https://github.com/hak5/usbrubberducky-payloads", hak5 / "rubber-ducky")
clone("https://github.com/hak5/bashbunny-payloads", hak5 / "bash-bunny")
clone("https://github.com/hak5/omg-payloads", hak5 / "omg-cable")
clone("https://github.com/hak5/pineapple-modules", hak5 / "wifi-pineapple")
clone("https://github.com/hak5/sharkjack-payloads", hak5 / "shark-jack")
clone("https://github.com/hak5/keycroc-payloads", hak5 / "key-croc")
clone("https://github.com/RoganDawes/P4wnP1_aloa", hak5 / "p4wnp1")
clone("https://github.com/dbisu/pico-ducky", hak5 / "pico-ducky")
clone("https://github.com/SpacehuhnTech/esp8266_deauther", hak5 / "esp-deauther")
clone("https://github.com/FlipperZero/flipperzero-firmware", hak5 / "flipper-firmware")

# ─────────────────────────────────────────────
# MITRE RAW
# ─────────────────────────────────────────────
print("\n[🎯 MITRE]")
mitre = BASE / "raw_mitre"
mitre.mkdir(exist_ok=True)

clone("https://github.com/center-for-threat-informed-defense/attack-flow", mitre / "attack-flow")
clone("https://github.com/mitre-attack/attack-navigator", mitre / "attack-navigator")
clone("https://github.com/mitre/caldera", mitre / "caldera-adversary-emulation")
clone("https://github.com/redcanaryco/atomic-red-team", mitre / "atomic-red-team")
clone("https://github.com/center-for-threat-informed-defense/mappings-explorer", mitre / "mappings-explorer")

print("\n" + "=" * 60)
print("[+] Download complete!")
print("[*] Now run the converter to turn this into training data.")
print("=" * 60)
