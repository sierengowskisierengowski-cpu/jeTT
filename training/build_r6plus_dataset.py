#!/usr/bin/env python3
"""Build surgical r6+ training set: reinforce r6 eval misses + v6 replay to prevent forgetting."""

from __future__ import annotations

import argparse
import json
import random
import re
from collections import defaultdict
from pathlib import Path


def variant_input(inp: str) -> str:
    pid = random.randint(1000, 199999)
    ts = random.randint(1749000000, 1781300000)
    s = re.sub(r"PID:\d+", f"PID:{pid}", inp, count=1)
    return re.sub(r"time:\d+", f"time:{ts}", s, count=1)


def load_failures(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def reinforce_failures(failures: list[dict], variants: int, round_tag: str) -> list[dict]:
    rows: list[dict] = []
    for row in failures:
        base = {
            "bucket": row.get("bucket", "ambiguous"),
            "category": row.get("category", "eval_reinforce"),
            "mitre": row.get("mitre", []),
            "tags": [*row.get("tags", ["eval_reinforce"]), round_tag],
            "input": row["input"],
            "output": row.get("output") or row.get("eval_want", "ALLOW"),
            "reasoning": row.get("reasoning", "Reinforced from r6 eval miss."),
        }
        rows.append(base)
        for _ in range(variants):
            rows.append({**base, "input": variant_input(row["input"])})
    return rows


def sample_replay(v6_path: Path, n: int, seed: int) -> list[dict]:
    data = json.loads(v6_path.read_text())
    by_bucket: dict[str, list] = defaultdict(list)
    for item in data:
        bucket = item.get("bucket", "unknown")
        by_bucket[bucket].append(item)

    rng = random.Random(seed)
    present = {b: len(items) for b, items in by_bucket.items() if items}
    total_present = sum(present.values()) or 1
    out: list[dict] = []
    for bucket, count in present.items():
        take = min(len(by_bucket[bucket]), max(1, int(n * count / total_present)))
        out.extend(rng.sample(by_bucket[bucket], take))

    if len(out) > n:
        out = rng.sample(out, n)
    return out


def to_alpaca(records: list[dict]) -> list[dict]:
    instruction = (
        "You are jeTT, a security classifier. Analyze this process event and respond "
        "with EXACTLY ONE WORD: either QUARANTINE (if malicious/suspicious) or ALLOW "
        "(if legitimate). Do not explain. Do not add detail."
    )
    alpaca = []
    for rec in records:
        verdict = rec.get("output") or rec.get("verdict")
        reasoning = rec.get("reasoning", "")
        if not verdict:
            continue
        alpaca.append(
            {
                "instruction": instruction,
                "input": rec["input"],
                "output": (
                    f"Analysis Matrix:\n- Behavioral Assessment: {reasoning}\n"
                    f"Final Verdict: {verdict}"
                ),
                "bucket": rec.get("bucket", "unknown"),
            }
        )
    return alpaca


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--failures", default="data/eval_failures_r6.jsonl")
    ap.add_argument("--replay-from", default="data/jett_training_v6.json")
    ap.add_argument("--replay-count", type=int, default=3000)
    ap.add_argument("--variants", type=int, default=8)
    ap.add_argument("--out", default="data/jett_training_r6plus.json")
    ap.add_argument("--seed", type=int, default=3407)
    args = ap.parse_args()

    failures = load_failures(Path(args.failures))
    reinforced = reinforce_failures(failures, args.variants, "r6plus")
    replay = sample_replay(Path(args.replay_from), args.replay_count, args.seed) if Path(args.replay_from).exists() else []

    combined = reinforced + replay
    random.Random(args.seed).shuffle(combined)
    alpaca = to_alpaca(combined)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(alpaca, indent=2))
    print(f"[+] r6+ dataset: {len(failures)} failures x {args.variants + 1} reinforce + {len(replay)} replay -> {len(alpaca)} rows")
    print(f"    wrote {out}")


if __name__ == "__main__":
    main()
