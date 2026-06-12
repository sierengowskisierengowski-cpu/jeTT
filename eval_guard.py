#!/usr/bin/env python3
"""Score jeTT guard output against held-out guard_eval.jsonl (substring match on verdict)."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

EVAL_END_MARKER = "__JETT_EVAL_END__"
EVAL_QUIT = "__JETT_EVAL_QUIT__"


def extract_verdict(text: str) -> str:
    up = text.upper()
    if "QUARANTINE" in up:
        return "QUARANTINE"
    if "ALLOW" in up:
        return "ALLOW"
    if "REVIEW" in up:
        return "REVIEW"
    return "UNKNOWN"


class WarmGuard:
    """One jeTT process: model loaded once, many --guard-batch inferences."""

    def __init__(self, jett: Path, timeout: float = 120.0) -> None:
        self._timeout = timeout
        env = os.environ.copy()
        self._proc = subprocess.Popen(
            [str(jett), "--guard-batch"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
        )
        if self._proc.stdin is None or self._proc.stdout is None:
            raise RuntimeError("failed to open pipes to jeTT --guard-batch")

    def guard(self, event: str) -> str:
        assert self._proc.stdin is not None
        assert self._proc.stdout is not None
        if self._proc.poll() is not None:
            raise RuntimeError("jeTT --guard-batch exited unexpectedly")

        self._proc.stdin.write(event + "\n")
        self._proc.stdin.flush()

        chunks: list[str] = []
        deadline = time.monotonic() + self._timeout
        while True:
            if time.monotonic() > deadline:
                self.close()
                raise TimeoutError(f"jeTT guard timed out after {self._timeout}s")
            line = self._proc.stdout.readline()
            if line == "":
                self.close()
                raise RuntimeError("jeTT --guard-batch closed stdout")
            chunks.append(line)
            if line.strip() == EVAL_END_MARKER:
                break
        return "".join(chunks)

    def close(self) -> None:
        if self._proc.poll() is not None:
            return
        try:
            if self._proc.stdin:
                self._proc.stdin.write(EVAL_QUIT + "\n")
                self._proc.stdin.flush()
        except OSError:
            pass
        try:
            self._proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._proc.kill()


def guard_cold(jett: Path, event: str, timeout: float = 120.0) -> str:
    proc = subprocess.run(
        [str(jett), "--guard", event],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return (proc.stdout or "") + (proc.stderr or "")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--eval", default="tests/guard_eval.jsonl")
    ap.add_argument("--jett", default="target/release/jeTT")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--failures-out", default="", help="write missed eval rows to jsonl")
    ap.add_argument(
        "--cold",
        action="store_true",
        help="spawn a new jeTT per row (slow; for A/B vs warm batch)",
    )
    ap.add_argument("--progress-every", type=int, default=25, help="0 to disable")
    args = ap.parse_args()

    jett = Path(args.jett)
    if not jett.exists():
        print(f"[!] build jeTT first: {jett}", file=sys.stderr)
        return 1

    rows = []
    with Path(args.eval).open() as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    if args.limit:
        rows = rows[: args.limit]

    correct = 0
    by_bucket = defaultdict(lambda: [0, 0])
    failures = []
    failure_rows = []

    mode = "cold" if args.cold else "warm"
    print(f"[eval] {len(rows)} rows  mode={mode}  jett={jett}", flush=True)
    t0 = time.monotonic()

    warm: WarmGuard | None = None
    try:
        if not args.cold:
            print("[eval] loading model (warm batch)...", flush=True)
            warm = WarmGuard(jett)
            print("[eval] model ready", flush=True)

        for i, row in enumerate(rows):
            inp = row["input"]
            want = row["output"].upper()
            if warm is not None:
                raw = warm.guard(inp)
            else:
                raw = guard_cold(jett, inp)

            got = extract_verdict(raw)
            ok = got == want
            correct += int(ok)
            b = row.get("bucket", "?")
            by_bucket[b][1] += 1
            by_bucket[b][0] += int(ok)
            if not ok:
                failures.append((i, row.get("category"), want, got, inp[:120]))
                failure_rows.append({**row, "eval_got": got, "eval_want": want})

            if args.progress_every and (i + 1) % args.progress_every == 0:
                elapsed = time.monotonic() - t0
                rate = (i + 1) / elapsed if elapsed > 0 else 0.0
                print(
                    f"  [{i + 1}/{len(rows)}] {100.0 * correct / (i + 1):.1f}%  "
                    f"{rate:.1f} rows/s",
                    flush=True,
                )
    finally:
        if warm is not None:
            warm.close()

    if args.failures_out and failure_rows:
        out = Path(args.failures_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w") as f:
            for r in failure_rows:
                f.write(json.dumps(r) + "\n")
        print(f"  failures written: {len(failure_rows)} -> {out}")

    total = len(rows)
    elapsed = time.monotonic() - t0
    pct = 100.0 * correct / total if total else 0
    print(f"=== guard eval: {correct}/{total} ({pct:.1f}%) in {elapsed:.1f}s ===")
    for b, (c, t) in sorted(by_bucket.items()):
        print(f"  {b:14s} {c}/{t} ({100*c/t:.1f}%)")
    if failures:
        print(f"\n=== first {min(10, len(failures))} failures ===")
        for item in failures[:10]:
            i, cat, want, got, snippet = item
            print(f"  [{i}] {cat} want={want} got={got}")
            print(f"       {snippet}...")
    return 0 if pct >= 80.0 else 1


if __name__ == "__main__":
    sys.exit(main())
