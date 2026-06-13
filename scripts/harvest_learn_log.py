#!/usr/bin/env python3
"""Harvest learn-mode WOULD-quarantine lines from jett.log → eval failure jsonl.

False positives (model WOULD/QUARANTINE, human wants ALLOW) become training rows.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

LOG_LINE = re.compile(
    r"^\[(?P<ts>[^\]]+)\]\s+(?P<name>\S+)\s+PID:(?P<pid>\d+)\s+→\s+"
    r"(?:🟡\s+)?WOULD-QUARANTINE\s+\((?P<reason>[^)]+)\)"
)

# Known false-positive patterns after plumbing fixes (per-PID behavior, ART noise).
FP_RULES: list[tuple[str, str]] = [
    (r"spawned child.*journalctl", "art_log_review"),
    (r"spawned child.*\[journalctl,rg,tail\]", "art_log_review"),
    (r"spawned child.*\[head,journalctl,rg\]", "art_log_review"),
    (r"spawned child.*\[python3,tail\]", "art_log_review"),
    (r"\bmoke\.sh\b|art_jett|art-smoke", "art_harness"),
    (r"194\.68\.245\.\d+.*spawned child.*\[(scp|rsync)", "runpod_admin"),
    (r"spawned child.*\[(scp|rsync)\].*194\.68\.245", "runpod_admin"),
    (r"spawned child.*\[bash,rg,tail\]", "dev_shell_rg"),
]


def classify_fp(name: str, reason: str) -> str | None:
    hay = f"{name} {reason}".lower()
    for pattern, tag in FP_RULES:
        if re.search(pattern, hay, re.I):
            return tag
    if name == "bash" and re.search(r"spawned child.*\brg\b", hay) and "journalctl" not in hay:
        if "194.68.245" not in hay:
            return "dev_shell_rg_only"
    return None


def reason_to_behavior(reason: str) -> str:
    """Turn logged reason fragments into behavior suffix."""
    parts = []
    if "spawned child" in reason.lower():
        m = re.search(r"spawned child[^[]*\[([^\]]+)\]", reason, re.I)
        if m:
            parts.append(f"spawned_children:[{m.group(1)}]")
    if "outbound connection" in reason.lower():
        m = re.search(r"outbound connections to \[([^\]]+)\]", reason, re.I)
        if m:
            parts.append(f"outbound_connections:[{m.group(1)}]")
    if "sensitive files" in reason.lower():
        m = re.search(r"sensitive files \[([^\]]+)\]", reason, re.I)
        if m:
            parts.append(f"sensitive_files:[{m.group(1)}]")
    if not parts:
        return " behavior:none_observed"
    return " " + "; ".join(parts)


def build_input(name: str, pid: str, ts: str, reason: str) -> str:
    exe = f"/usr/bin/{name}" if name in ("bash", "sh", "curl", "wget", "python3", "ssh") else f"/proc/{pid}/exe"
    if name == "moke.sh":
        exe = "/home/cosmic/Projects/jeTT/scripts/art_jett_smoke.sh"
    behavior = reason_to_behavior(reason)
    return f"{name} PID:{pid} uid:1000 exe:{exe} cmd: time:{ts}{behavior}"


def harvest_log(path: Path) -> list[dict]:
    rows: list[dict] = []
    seen: set[str] = set()
    if not path.exists():
        print(f"[!] missing log: {path}")
        return rows

    for line in path.read_text(errors="replace").splitlines():
        m = LOG_LINE.search(line.strip())
        if not m:
            continue
        tag = classify_fp(m.group("name"), m.group("reason"))
        if not tag:
            continue
        inp = build_input(m.group("name"), m.group("pid"), m.group("ts"), m.group("reason"))
        key = f"{tag}:{inp[:120]}"
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "bucket": "legit_scary",
                "category": f"live_harvest_{tag}",
                "mitre": ["T1059.004"],
                "tags": ["live_harvest", "learn_mode", "round9"],
                "input": inp,
                "output": "ALLOW",
                "reasoning": f"Live learn-mode false positive ({tag}); benign admin/dev/ART pattern.",
                "eval_got": "QUARANTINE",
                "eval_want": "ALLOW",
            }
        )
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default="/var/log/jett/jett.log")
    ap.add_argument("--out", default="data/eval_failures_live_r9.jsonl")
    ap.add_argument("--merge-r8", default="data/eval_failures_r8.jsonl")
    ap.add_argument("--merged-out", default="data/eval_failures_r9_merged.jsonl")
    args = ap.parse_args()

    live = harvest_log(Path(args.log))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as f:
        for row in live:
            f.write(json.dumps(row) + "\n")
    print(f"[+] live harvest: {len(live)} FP rows -> {out}")

    merged: list[dict] = []
    seen_inp: set[str] = set()
    for src in (out, Path(args.merge_r8)):
        if not src.exists():
            continue
        for line in src.read_text().splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            h = row.get("input", "")[:200]
            if h in seen_inp:
                continue
            seen_inp.add(h)
            merged.append(row)

    mout = Path(args.merged_out)
    with mout.open("w") as f:
        for row in merged:
            f.write(json.dumps(row) + "\n")
    print(f"[+] merged failures: {len(merged)} rows -> {mout}")


if __name__ == "__main__":
    main()
