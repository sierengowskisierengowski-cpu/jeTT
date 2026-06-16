#!/usr/bin/env python3
"""
stratified_merge.py — Round 4 dataset assembler for jeTT.

Takes the per-bucket .jsonl files and produces ONE curated training set, the
right way:

  1. Load every bucket file (threat / legit_scary / ambiguous)
  2. Global dedup on input hash (a record can't appear twice)
  3. Stratify by SCENARIO bucket to target proportions (NOT raw 50/50 labels)
  4. Carve off a held-out eval set (never seen in training) — the honesty check
  5. Convert to the exact Alpaca shape train_core_weights.py expects, with the
     instruction matching the runtime guard prompt and output = one word
  6. Emit a MITRE coverage report so you can see blind spots before you train

PROPORTIONS: defaults to 30% threat / 47% legit_scary / 20% ambiguous. If a
bucket is missing (e.g. no Bucket C yet), the remaining buckets are
renormalized automatically — so A+B alone become ~39%/61%.

RUN (uses everything available, holds out 5% for eval):
    python3 stratified_merge.py

RUN (cap size + custom eval fraction):
    python3 stratified_merge.py --total 50000 --eval-frac 0.05

OUTPUTS:
    data/jett_training_v4.json   (Alpaca array → train_core_weights.py)  [gitignored]
    tests/guard_eval.jsonl       (held-out eval, full records w/ reasoning)
    data/mitre_coverage.json     (technique counts + zero-coverage list)
"""

import argparse
import glob
import hashlib
import json
import random
from collections import defaultdict
from pathlib import Path

# Instruction must match the runtime guard prompt in src/engine.rs so training
# and inference speak the same dialect.
GUARD_INSTRUCTION = (
    "You are jeTT, a security classifier. Analyze this process event and respond "
    "with EXACTLY ONE WORD: either QUARANTINE (if malicious/suspicious) or ALLOW "
    "(if legitimate). Do not explain. Do not add detail."
)

# Round 5 bumps ambiguous slightly (context pairs teach tie-breaking).
DEFAULT_PROPORTIONS = {"threat": 0.30, "legit_scary": 0.45, "ambiguous": 0.25}


def load_buckets(patterns):
    """Load all records, keyed by their self-declared bucket. Global dedup."""
    seen = set()
    by_bucket = defaultdict(list)
    files_loaded = []
    for pattern in patterns:
        for path in glob.glob(pattern):
            n = 0
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    rec = json.loads(line)
                    h = hashlib.sha1(rec["input"].encode()).hexdigest()
                    if h in seen:
                        continue
                    seen.add(h)
                    by_bucket[rec.get("bucket", "unknown")].append(rec)
                    n += 1
            files_loaded.append((path, n))
    return by_bucket, files_loaded


def target_counts(by_bucket, total):
    """Renormalize default proportions over the buckets actually present, then
    compute per-bucket target counts. Caps at what's available per bucket."""
    present = {b: DEFAULT_PROPORTIONS.get(b, 0.0) for b in by_bucket}
    s = sum(present.values()) or 1.0
    norm = {b: p / s for b, p in present.items()}

    if total is None:
        # Use everything; proportions are whatever the data gives.
        return {b: len(recs) for b, recs in by_bucket.items()}, norm

    targets = {}
    for b in by_bucket:
        want = round(norm[b] * total)
        have = len(by_bucket[b])
        targets[b] = min(want, have)
    return targets, norm


def stratified_holdout(records, frac, seed):
    """Split a bucket's records into (train, eval), stratified by category so
    the eval set mirrors the bucket's category mix."""
    rng = random.Random(seed)
    by_cat = defaultdict(list)
    for r in records:
        by_cat[r.get("category", "_")].append(r)
    train, ev = [], []
    for cat, recs in by_cat.items():
        rng.shuffle(recs)
        k = max(1, round(len(recs) * frac)) if len(recs) > 1 else 0
        ev.extend(recs[:k])
        train.extend(recs[k:])
    return train, ev


def to_alpaca(rec):
    return {"instruction": GUARD_INSTRUCTION, "input": rec["input"], "output": rec["output"]}


def coverage_report(records):
    counts = defaultdict(int)
    for r in records:
        for m in r.get("mitre", []):
            counts[m] += 1
    return dict(sorted(counts.items(), key=lambda x: -x[1]))


def main():
    ap = argparse.ArgumentParser(description="jeTT Round 4 stratified merge")
    ap.add_argument("--buckets", nargs="+", default=["data/bucket_*.jsonl"],
                    help="glob(s) for bucket jsonl files")
    ap.add_argument("--total", type=int, default=None,
                    help="target training size (default: use all available)")
    ap.add_argument("--eval-frac", type=float, default=0.05)
    ap.add_argument("--out", default="data/jett_training_v4.json")
    ap.add_argument("--eval-out", default="tests/guard_eval.jsonl")
    ap.add_argument("--coverage-out", default="data/mitre_coverage.json")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    by_bucket, files_loaded = load_buckets(args.buckets)
    if not by_bucket:
        print("No bucket files matched. Run the generators first.")
        return

    print("=== loaded (after global dedup) ===")
    for path, n in files_loaded:
        print(f"  {n:6d}  {path}")
    print()

    targets, norm = target_counts(by_bucket, args.total)
    rng = random.Random(args.seed)

    selected = []
    for b, recs in by_bucket.items():
        rng.shuffle(recs)
        selected.extend(recs[: targets[b]])

    # coverage computed on the SELECTED set (before stripping reasoning)
    coverage = coverage_report(selected)

    # hold out eval, stratified within each bucket
    train_recs, eval_recs = [], []
    for b in by_bucket:
        chunk = [r for r in selected if r.get("bucket") == b]
        tr, ev = stratified_holdout(chunk, args.eval_frac, args.seed)
        train_recs.extend(tr)
        eval_recs.extend(ev)

    rng.shuffle(train_recs)
    rng.shuffle(eval_recs)

    # write training set (Alpaca array, reasoning stripped)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as f:
        json.dump([to_alpaca(r) for r in train_recs], f, indent=1)

    # write held-out eval (full records, reasoning kept for audit)
    ev_out = Path(args.eval_out)
    ev_out.parent.mkdir(parents=True, exist_ok=True)
    with ev_out.open("w") as f:
        for r in eval_recs:
            f.write(json.dumps(r) + "\n")

    # write coverage report
    cov_out = Path(args.coverage_out)
    cov_out.parent.mkdir(parents=True, exist_ok=True)
    with cov_out.open("w") as f:
        json.dump(coverage, f, indent=2)

    # ---- summary ----
    total_sel = len(selected)
    print("=== bucket mix (selected) ===")
    for b in by_bucket:
        n = sum(1 for r in selected if r.get("bucket") == b)
        pct = 100 * n / total_sel if total_sel else 0
        print(f"  {b:14s} {n:6d}  ({pct:4.1f}%)   target ~{100*norm[b]:.0f}%")
    print()
    label = defaultdict(int)
    for r in selected:
        label[r["output"]] += 1
    print("=== label balance ===")
    for k, v in label.items():
        print(f"  {k:12s} {v:6d}  ({100*v/total_sel:.1f}%)")
    print()
    print(f"=== outputs ===")
    print(f"  train : {len(train_recs):6d}  -> {args.out}")
    print(f"  eval  : {len(eval_recs):6d}  -> {args.eval_out}  (NEVER trained on)")
    print(f"  mitre : {len(coverage):6d} techniques covered -> {args.coverage_out}")
    print()
    print("=== MITRE coverage (top 12) ===")
    for i, (tech, n) in enumerate(coverage.items()):
        if i >= 12:
            break
        print(f"  {tech:14s} {n}")


if __name__ == "__main__":
    main()
