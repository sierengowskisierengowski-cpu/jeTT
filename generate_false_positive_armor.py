#!/usr/bin/env python3
"""
generate_false_positive_armor.py — Bucket B generator for jeTT Round 4.

Produces "legit-but-scary" training records: processes that throw the SAME
alarming signals as malware — reading /etc/shadow, outbound connections, root
uid, execution from /tmp, spawning many children — but are legitimate, so the
verdict is ALLOW.

This is the false-positive armor. It is the category where EDRs actually die:
the day jeTT kills your backup tool or your own bifrost daemon is the day you
turn it off. The model must learn the rule that makes it elite instead of a
glorified blocklist:

    scary signals + legitimate context  ==>  ALLOW
    behavior breaks ties, not the name or path alone.

OUTPUT: JSONL, one canonical jeTT training record per line. The `input` field
is a byte-for-byte match of what the daemon's format_event_for_ai() +
collect_behavior() produce at runtime (see src/bin/daemon.rs).

RUN:
    python3 generate_false_positive_armor.py --count 1200 \
            --out data/bucket_b_scary_legit.jsonl

Then merge via stratified_merge.py (next file). train_core_weights.py drops
`reasoning` and trains only input -> output for the one-word guard path.
"""

import argparse
import hashlib
import json
import random
from pathlib import Path

# ---------------------------------------------------------------------------
# DAEMON-EXACT FORMATTER  (mirrors src/bin/daemon.rs)
#
#   format_event_for_ai():  "{name} PID:{pid} uid:{uid} exe:{exe} cmd:{cmd} time:{ts}"
#   collect_behavior() suffix, each appended ONLY if non-empty, lists SORTED:
#       " outbound_connections:[ip:port,ip:port]"
#       " sensitive_files:[/path,/path]"
#       " spawned_children:[name,name]"
#   if all three empty:  " behavior:none_observed"
#
# NOTE on `time`: the daemon emits epoch seconds. Epoch is opaque to the model,
# so "3am vs 2pm" is NOT a signal the model can read from this field today. That
# only matters for Bucket C (time-based ambiguous pairs); we settle it there. For
# Bucket B it's just a rotated value, so we leave it as epoch to stay daemon-exact.
# ---------------------------------------------------------------------------

# Plausible "recent" epoch window (matches the daemon log prefixes seen on-box).
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
    """The one true dialect. Use this in ALL bucket generators so the model
    only ever sees one input shape — the one the daemon actually emits."""
    base = f"{name} PID:{pid} uid:{uid} exe:{exe} cmd:{cmd} time:{ts}"
    return base + behavior_suffix(conns, files, kids)


# ---------------------------------------------------------------------------
# IP POOLS — real events carry IPs, not hostnames. These are realistic
# "benign-destination" ranges so the scary outbound signal is present without
# being an actual indicator of compromise.
# ---------------------------------------------------------------------------
BENIGN_IPS = [
    "104.18.32.47", "104.18.38.10", "104.16.85.20",      # Cloudflare (Anthropic/Govee front)
    "140.82.112.25", "140.82.121.4",                       # GitHub
    "151.101.0.223", "151.101.54.132",                     # Fastly (PyPI/crates)
    "34.107.221.82", "35.190.247.13",                       # GCP
    "13.107.42.14", "20.205.243.166",                       # Azure/MS
    "162.159.135.234",                                       # Cloudflare DNS-over-HTTPS
]
LAN_IPS = [
    "192.168.0.1", "192.168.0.32", "192.168.0.80",
    "192.168.0.125", "192.168.0.144", "192.168.0.172",
]


def rip(pool):
    return f"{random.choice(pool)}:{random.choice([443, 443, 443, 8443, 9090, 80, 22])}"


# ---------------------------------------------------------------------------
# BUCKET B TEMPLATES — legit processes wearing malware's clothes.
#
# Each template is a family. The generator rotates pid/uid/time and the
# behavioral payload to produce many variants, but the verdict is always ALLOW
# and the SCARY SIGNAL is always present (that's the whole point — clean
# examples teach nothing here).
#
# Fields:
#   name, exe, cmds[]      — identity
#   uid                    — 0 (root) or 1000 (cosmic) or a callable
#   conns / files / kids   — generators returning the scary-but-benign payload
#   mitre, tags, category, reasoning
# ---------------------------------------------------------------------------

def _conns(pool, lo=1, hi=3):
    return lambda: [rip(pool) for _ in range(random.randint(lo, hi))]


TEMPLATES = [
    # --- Backup / integrity / AV : reads credential files, phones home -------
    dict(
        name="system_backup_tool", exe="/usr/local/bin/system_backup_tool",
        cmds=["--full-scan", "--incremental --verify", "--integrity-hash /etc"],
        uid=0, category="backup_integrity",
        files=lambda: ["/etc/passwd", "/etc/shadow", "/etc/group"][: random.randint(2, 3)],
        conns=_conns(BENIGN_IPS, 1, 1),
        mitre=["T1003.008", "T1082"],
        tags=["reads_shadow", "outbound", "root_uid"],
        reasoning="Scheduled backup hashing credential files for integrity; known path, outbound to configured store.",
    ),
    dict(
        name="rclone", exe="/usr/bin/rclone",
        cmds=["sync /home/cosmic/Backups remote:gowski", "copy ~/Documents remote:codex --progress"],
        uid=1000, category="backup_integrity",
        files=lambda: ["/home/cosmic/.config/rclone/rclone.conf"],
        conns=_conns(BENIGN_IPS, 1, 3),
        mitre=["T1567.002"],
        tags=["outbound", "bulk_upload", "reads_config"],
        reasoning="User-driven cloud sync; outbound + bulk read is normal rclone behavior.",
    ),
    dict(
        name="restic", exe="/usr/bin/restic",
        cmds=["backup /etc /home --tag nightly", "prune --repo remote"],
        uid=0, category="backup_integrity",
        files=lambda: ["/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config"][: random.randint(1, 3)],
        conns=_conns(BENIGN_IPS, 1, 2),
        mitre=["T1003", "T1082"],
        tags=["reads_shadow", "outbound", "root_uid"],
        reasoning="restic snapshotting system + reading config for backup; benign root backup job.",
    ),

    # --- Dev toolchain : execs from /tmp & target/, spawns compilers ---------
    dict(
        name="cargo", exe="/home/cosmic/.cargo/bin/cargo",
        cmds=["build --release", "test --release", "run --release"],
        uid=1000, category="dev_toolchain",
        kids=lambda: random.sample(["rustc", "cc", "ld", "build-script-build", "ar"], k=random.randint(2, 4)),
        conns=lambda: ([rip(BENIGN_IPS)] if random.random() < 0.4 else None),  # crates.io fetch
        mitre=["T1059.004"],
        tags=["spawns_compilers", "tmp_artifacts", "outbound_optional"],
        reasoning="Rust build spawning rustc/cc and fetching crates; core dev workflow.",
    ),
    dict(
        name=".tmpXXXX", exe="/tmp/cargo-installXXXXXX/release/jett-test",
        cmds=["--selftest", ""], uid=1000, category="dev_toolchain",
        kids=lambda: ["sh"] if random.random() < 0.3 else None,
        mitre=["T1059"],
        tags=["exec_from_tmp", "dev_artifact"],
        reasoning="Freshly compiled test binary running from a cargo temp dir; /tmp exec is benign here.",
    ),
    dict(
        name="rustc", exe="/home/cosmic/.rustup/toolchains/stable/bin/rustc",
        cmds=["--edition 2021 src/main.rs -o /tmp/.build-out"], uid=1000,
        category="dev_toolchain",
        files=lambda: None, kids=lambda: ["cc", "ld"][: random.randint(1, 2)],
        mitre=["T1027"],
        tags=["writes_tmp", "spawns_linker"],
        reasoning="Compiler emitting an artifact to /tmp and invoking the linker; normal.",
    ),

    # --- Package managers : touch system dirs, spawn children, fetch ---------
    dict(
        name="pacman", exe="/usr/bin/pacman",
        cmds=["-Syu --noconfirm", "-S base-devel"], uid=0, category="package_manager",
        kids=lambda: random.sample(["gpg", "tar", "ldconfig", "systemd-hwdb", "install"], k=random.randint(2, 4)),
        conns=_conns(BENIGN_IPS, 1, 3),
        files=lambda: ["/etc/pacman.d/mirrorlist"] if random.random() < 0.5 else None,
        mitre=["T1072"],
        tags=["root_uid", "many_children", "outbound", "writes_system"],
        reasoning="System update fetching packages and running install hooks as root; expected.",
    ),
    dict(
        name="pip", exe="/usr/bin/python3",
        cmds=["-m pip install --break-system-packages unsloth", "-m pip install -r requirements.txt"],
        uid=1000, category="package_manager",
        conns=_conns(BENIGN_IPS, 1, 2),
        kids=lambda: ["gcc", "cc"] if random.random() < 0.4 else None,
        mitre=["T1059.006"],
        tags=["outbound", "writes_site_packages", "spawns_compiler"],
        reasoning="pip resolving wheels from PyPI, occasionally building native ext; benign.",
    ),

    # --- Monitoring : reads /proc, binds ports, outbound metrics -------------
    dict(
        name="node_exporter", exe="/usr/bin/node_exporter",
        cmds=["--web.listen-address=:9100"], uid=1000, category="monitoring",
        conns=lambda: [f"{random.choice(LAN_IPS)}:9090"],
        files=lambda: ["/proc/stat", "/proc/meminfo", "/proc/net/dev"][: random.randint(2, 3)],
        mitre=["T1082"],
        tags=["reads_proc", "binds_port", "outbound_lan"],
        reasoning="Prometheus exporter reading /proc and serving metrics on the LAN; monitoring, not recon.",
    ),
    dict(
        name="prometheus", exe="/usr/bin/prometheus",
        cmds=["--config.file=/etc/prometheus/prometheus.yml"], uid=1000, category="monitoring",
        conns=lambda: [f"{random.choice(LAN_IPS)}:9100", f"{random.choice(LAN_IPS)}:8080"][: random.randint(1, 2)],
        mitre=["T1082"],
        tags=["scrapes_targets", "binds_port", "outbound_lan"],
        reasoning="Prometheus scraping LAN exporters; fan-out connections are its normal behavior.",
    ),

    # --- Joseph's own stack : looks like C2 if you only read the name --------
    dict(
        name="bifrost", exe="/home/cosmic/Projects/bifrost/app/bifrost-desktop/src-tauri/target/release/bifrost",
        cmds=["--guardian", ""], uid=1000, category="own_stack",
        conns=lambda: [f"{random.choice(LAN_IPS)}:11434", rip(BENIGN_IPS)][: random.randint(1, 2)],
        files=lambda: ["/proc/self/status"] if random.random() < 0.3 else None,
        mitre=["T1071"],
        tags=["outbound", "looks_like_c2", "reads_proc"],
        reasoning="Joseph's own EDR platform talking to its guardian/Ollama; trusted GowskiNet process.",
    ),
    dict(
        name="ghost-relay", exe="/home/cosmic/Projects/c2/teamserver/ghost-relay",
        cmds=["--listen 0.0.0.0:8443", "--lab-mode"], uid=1000, category="own_stack",
        conns=lambda: [f"{random.choice(LAN_IPS)}:8443"],
        mitre=["T1071", "T1571"],
        tags=["outbound", "name_looks_evil", "binds_port"],
        reasoning="Joseph's own C2 research framework running in his lab; named like malware but explicitly trusted.",
    ),
    dict(
        name="ollama", exe="/usr/local/bin/ollama",
        cmds=["serve", "run qwen2.5:7b-instruct"], uid=1000, category="own_stack",
        conns=lambda: ([rip(BENIGN_IPS)] if random.random() < 0.5 else [f"{random.choice(LAN_IPS)}:11434"]),
        mitre=["T1071"],
        tags=["outbound", "model_pull", "high_mem"],
        reasoning="Ollama pulling/serving a model; large outbound + memory is expected.",
    ),
    dict(
        name="gni_server.py", exe="/home/cosmic/Projects/GNI/gni_server.py",
        cmds=["--port 6969"], uid=1000, category="own_stack",
        conns=lambda: [rip(BENIGN_IPS)],  # Anthropic API
        files=lambda: ["/home/cosmic/.gni_config"] if random.random() < 0.4 else None,
        mitre=["T1071.001"],
        tags=["outbound", "reads_config", "api_call"],
        reasoning="GNI animatronic brain calling the Claude API; reads its own config; trusted.",
    ),
    dict(
        name="cowrie", exe="/home/cosmic/Projects/honeypot/cowrie/bin/cowrie",
        cmds=["start", ""], uid=1000, category="own_stack",
        conns=lambda: [f"{random.choice(LAN_IPS)}:2222", f"{random.choice(LAN_IPS)}:23"][: random.randint(1, 2)],
        mitre=["T1071"],
        tags=["binds_low_ports", "sees_attack_traffic", "looks_malicious"],
        reasoning="Cowrie honeypot listening on trap ports and logging attackers; the scary traffic is INBOUND to a trap.",
    ),

    # --- Containers : many execs, weird caps, network bridges ----------------
    dict(
        name="dockerd", exe="/usr/bin/dockerd", cmds=["", "--containerd=/run/containerd/containerd.sock"],
        uid=0, category="containers",
        kids=lambda: random.sample(["containerd-shim", "runc", "docker-proxy", "containerd"], k=random.randint(2, 4)),
        conns=lambda: [f"{random.choice(LAN_IPS)}:2375"] if random.random() < 0.2 else None,
        mitre=["T1610"],
        tags=["root_uid", "many_children", "net_bridge"],
        reasoning="Docker daemon spawning container runtimes and wiring bridges; benign as root.",
    ),
    dict(
        name="runc", exe="/usr/bin/runc", cmds=["init", "--root /run/containerd ..."],
        uid=0, category="containers",
        kids=lambda: ["sh", "bash"][: random.randint(1, 2)] if random.random() < 0.5 else None,
        mitre=["T1610"],
        tags=["root_uid", "spawns_shell", "container_init"],
        reasoning="Container init spawning the entrypoint shell; root + shell here is expected.",
    ),

    # --- Smart-home / scripts : python3 + curl to external API ---------------
    dict(
        name="python3", exe="/home/cosmic/Scripts/utilities/govee-art.sh",
        cmds=["--scene sunset", "--sync-clock"], uid=1000, category="smarthome",
        conns=lambda: [rip(BENIGN_IPS)],  # api.govee.com behind Cloudflare
        mitre=["T1071.001"],
        tags=["outbound", "python_interpreter", "api_call"],
        reasoning="Govee lighting script hitting the Govee API; python3 + outbound is its whole job.",
    ),
    dict(
        name="gps-logger", exe="/home/cosmic/Scripts/deployed/gps-logger.py",
        cmds=["--interval 30"], uid=1000, category="smarthome",
        files=lambda: ["/home/cosmic/Docs/Notes/gps-track.log"] if random.random() < 0.3 else None,
        conns=lambda: [rip(BENIGN_IPS)] if random.random() < 0.4 else None,
        mitre=["T1082"],
        tags=["writes_log", "outbound_optional"],
        reasoning="GPS logger writing a track file and optionally syncing; benign personal script.",
    ),

    # --- Admin maintenance : root, late, edits configs -----------------------
    dict(
        name="sshd", exe="/usr/bin/sshd", cmds=["-D", "session opened for cosmic"],
        uid=0, category="admin_maintenance",
        kids=lambda: ["bash", "zsh"][: 1] if random.random() < 0.6 else None,
        conns=lambda: [f"{random.choice(LAN_IPS)}:22"],
        mitre=["T1021.004"],
        tags=["root_uid", "spawns_shell", "inbound_ssh"],
        reasoning="Legitimate SSH login from the LAN spawning the user's shell; the parent is sshd but the session is authorized.",
    ),
    dict(
        name="sudo", exe="/usr/bin/sudo", cmds=["systemctl restart jett-daemon", "pacman -Syu"],
        uid=0, category="admin_maintenance",
        kids=lambda: random.sample(["systemctl", "pacman", "nano", "cp"], k=1),
        mitre=["T1548.003"],
        tags=["root_uid", "privilege_use", "interactive"],
        reasoning="Interactive sudo running a maintenance command; authorized escalation, not exploitation.",
    ),
    dict(
        name="systemctl", exe="/usr/bin/systemctl", cmds=["restart docker", "enable nyx-honeypot.service"],
        uid=0, category="admin_maintenance",
        files=lambda: ["/etc/systemd/system/jett-daemon.service"] if random.random() < 0.3 else None,
        mitre=["T1543.002"],
        tags=["root_uid", "edits_units"],
        reasoning="Admin managing systemd units; touching unit files as root is normal maintenance.",
    ),
    dict(
        name="nvidia-smi", exe="/usr/bin/nvidia-smi", cmds=["", "-q -d MEMORY"],
        uid=1000, category="monitoring",
        files=lambda: ["/proc/driver/nvidia/gpus"] if random.random() < 0.3 else None,
        mitre=["T1082"],
        tags=["reads_proc", "hardware_query"],
        reasoning="GPU status query; reads driver/proc info, no network, fully benign.",
    ),
]


# ---------------------------------------------------------------------------
# GENERATION
# ---------------------------------------------------------------------------

def rand_pid():
    return random.randint(800, 199999)


def resolve(v):
    """Templates store payloads as callables (so each variant differs) or plain
    values. Resolve to a concrete value for this record."""
    return v() if callable(v) else v


def make_record(t):
    uid = resolve(t.get("uid", 1000))
    name = t["name"]
    exe = t["exe"]
    # de-templatize placeholder XXXX names/paths so each looks distinct
    if "XXXX" in name:
        name = name.replace("XXXX", str(random.randint(1000, 9999)))
    if "XXXX" in exe:
        exe = exe.replace("XXXXXX", str(random.randint(100000, 999999)))
    cmd = random.choice(t["cmds"]) if t.get("cmds") else ""
    ts = random.randint(TS_MIN, TS_MAX)

    conns = resolve(t.get("conns")) if "conns" in t else None
    files = resolve(t.get("files")) if "files" in t else None
    kids = resolve(t.get("kids")) if "kids" in t else None

    inp = format_guard_event(name, rand_pid(), uid, exe, cmd, ts,
                             conns=conns, files=files, kids=kids)

    return {
        "bucket": "legit_scary",
        "category": t["category"],
        "mitre": t.get("mitre", []),
        "tags": t.get("tags", []),
        "input": inp,
        "output": "ALLOW",
        "reasoning": t.get("reasoning", ""),
    }


def main():
    ap = argparse.ArgumentParser(description="jeTT Round 4 — Bucket B (legit-but-scary) generator")
    ap.add_argument("--count", type=int, default=1200, help="number of records to emit")
    ap.add_argument("--out", default="data/bucket_b_scary_legit.jsonl")
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    seen = set()
    written = 0
    attempts = 0
    max_attempts = args.count * 40  # generous headroom for dedup

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
    print("category distribution:")
    for c, n in sorted(by_cat.items(), key=lambda x: -x[1]):
        print(f"  {n:5d}  {c}")


if __name__ == "__main__":
    main()
