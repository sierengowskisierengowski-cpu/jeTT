#!/usr/bin/env python3
"""Measure guard latency p50/p99 on fixed sample events."""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import time
from pathlib import Path


SAMPLES = [
    "python3 PID:4821 uid:1000 exe:/tmp/.hidden cmd:curl evil time:1749000001 behavior:none_observed",
    "bifrost PID:1204 uid:1000 exe:/home/cosmic/Projects/bifrost/target/release/bifrost cmd:--api time:1749000002 behavior:none_observed",
    "jett-daemon PID:900 uid:0 exe:/home/cosmic/Projects/jeTT/target/release/jett-daemon cmd: time:1749000003 behavior:none_observed",
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jett", default="target/release/jeTT")
    ap.add_argument("--model", default=os.environ.get("JETT_MODEL", ""))
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--samples-file", default="")
    args = ap.parse_args()

    jett = Path(args.jett)
    if not jett.exists():
        print(f"[!] build first: {jett}")
        return 1

    samples = SAMPLES
    if args.samples_file:
        samples = [
            json.loads(line)["input"]
            for line in Path(args.samples_file).read_text().splitlines()
            if line.strip()
        ][:20]

    env = os.environ.copy()
    if args.model:
        env["JETT_MODEL"] = args.model
    env.setdefault("JETT_N_CTX", "512")
    env.setdefault("JETT_GUARD_MAX_TOKENS", "2")
    env.setdefault("JETT_BEHAVIOR_MODE", "snapshot")

    times_ms: list[float] = []
    for r in range(args.rounds):
        for sample in samples:
            t0 = time.perf_counter()
            subprocess.run(
                [str(jett), "--guard", sample],
                env=env,
                capture_output=True,
                check=False,
            )
            times_ms.append((time.perf_counter() - t0) * 1000)

    times_ms.sort()
    n = len(times_ms)
    p50 = statistics.median(times_ms)
    p99 = times_ms[int(0.99 * (n - 1))] if n > 1 else times_ms[0]
    print(f"samples={len(samples)} rounds={args.rounds} total_calls={n}")
    print(f"p50={p50:.0f}ms p99={p99:.0f}ms min={times_ms[0]:.0f}ms max={times_ms[-1]:.0f}ms")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
