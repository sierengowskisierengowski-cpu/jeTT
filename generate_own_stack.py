#!/usr/bin/env python3
"""Round 6 — jeTT / Cerberus / Bifrost own-stack ALLOW anchors."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path

TS_MIN, TS_MAX = 1749000000, 1781300000
LAN = ["192.168.0.1:8443", "127.0.0.1:6969", "192.168.0.1:9090"]


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


TEMPLATES = [
    dict(name="jett-daemon", exe="/home/cosmic/Projects/jeTT/target/release/jett-daemon",
         cmd="", uid=0, category="own_stack",
         conns=LAN[:1], kids=["jeTT"],
         mitre=["T1082"], reasoning="jeTT daemon loading Granite guard model; expected stack."),
    dict(name="jeTT", exe="/home/cosmic/Projects/jeTT/target/release/jeTT",
         cmd="--guard", uid=1000, category="own_stack",
         mitre=["T1059"], reasoning="jeTT CLI guard inference; core product path."),
    dict(name="bifrost", exe="/home/cosmic/Projects/bifrost/target/release/bifrost",
         cmd="--api", uid=1000, category="own_stack",
         conns=LAN[:2], mitre=["T1071.001"],
         reasoning="Bifrost dashboard API on LAN; authorized security UI."),
    dict(name="cerberus", exe="/usr/local/bin/cerberus-guardian",
         cmd="--honeypot", uid=0, category="own_stack",
         conns=LAN[2:3], files=["/var/log/cerberus/events.log"],
         mitre=["T1082"], reasoning="Cerberus honeypot listener; defensive component."),
    dict(name="python3", exe="/usr/bin/python3",
         cmd="/home/cosmic/Projects/jeTT/generate_threats.py --count 100",
         uid=1000, category="own_stack",
         mitre=["T1059.006"], reasoning="jeTT training data generator; dev workflow."),
    dict(name="jett-control.sh", exe="/bin/bash",
         cmd="/home/cosmic/Projects/jeTT/jett-control.sh", uid=1000, category="own_stack",
         mitre=["T1059.004"], reasoning="jeTT control menu script; operator tool."),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=350)
    ap.add_argument("--out", default="data/bucket_g_own_stack.jsonl")
    ap.add_argument("--seed", type=int, default=63)
    args = ap.parse_args()
    random.seed(args.seed)
    out = Path(args.out)
    seen, n = set(), 0
    with out.open("w") as f:
        while n < args.count:
            t = random.choice(TEMPLATES)
            rec = {
                "bucket": "legit_scary",
                "category": t["category"],
                "mitre": t["mitre"],
                "tags": ["own_stack", "round6"],
                "input": fmt(t["name"], random.randint(100, 9999), t["uid"], t["exe"],
                             t["cmd"], random.randint(TS_MIN, TS_MAX),
                             t.get("conns"), t.get("files"), t.get("kids")),
                "output": "ALLOW",
                "reasoning": t["reasoning"],
            }
            h = hashlib.sha1(rec["input"].encode()).hexdigest()
            if h in seen:
                continue
            seen.add(h)
            f.write(json.dumps(rec) + "\n")
            n += 1
    print(f"[+] {n} own-stack records -> {out}")


if __name__ == "__main__":
    main()
