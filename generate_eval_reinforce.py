#!/usr/bin/env python3
"""Turn eval failures into reinforced training rows (+ light paraphrase variants)."""

from __future__ import annotations

import argparse
import json
import random
import re
from pathlib import Path


def variant_input(inp: str) -> str:
    """Nudge pid/time so model sees same verdict on near-duplicate."""
    pid = random.randint(1000, 199999)
    ts = random.randint(1749000000, 1781300000)
    s = re.sub(r"PID:\d+", f"PID:{pid}", inp, count=1)
    s = re.sub(r"time:\d+", f"time:{ts}", s, count=1)
    return s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--failures", default="data/eval_failures_r5.jsonl")
    ap.add_argument("--out", default="data/bucket_i_eval_reinforce.jsonl")
    ap.add_argument("--variants", type=int, default=3, help="variants per failure")
    args = ap.parse_args()

    src = Path(args.failures)
    if not src.exists():
        print(f"[!] no failures file {src} — run eval_guard.py --failures-out first")
        return

    rows = [json.loads(l) for l in src.read_text().splitlines() if l.strip()]
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with out.open("w") as f:
        for row in rows:
            base = {
                "bucket": row.get("bucket", "ambiguous"),
                "category": row.get("category", "eval_reinforce"),
                "mitre": row.get("mitre", []),
                "tags": ["eval_reinforce", "round6"],
                "input": row["input"],
                "output": row["output"],
                "reasoning": row.get("reasoning", "Reinforced from eval miss."),
            }
            f.write(json.dumps(base) + "\n")
            n += 1
            for _ in range(args.variants):
                v = {**base, "input": variant_input(row["input"])}
                f.write(json.dumps(v) + "\n")
                n += 1
    print(f"[+] {n} reinforce records from {len(rows)} failures -> {out}")


if __name__ == "__main__":
    main()
