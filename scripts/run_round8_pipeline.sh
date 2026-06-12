#!/usr/bin/env bash
# jeTT Round 8 — surgical: r6 eval misses + lolbin behavior-over-path.
set -euo pipefail
cd "$(dirname "$0")/.."

TOTAL="${JETT_TRAIN_TOTAL:-70000}"
FAIL_R6="${JETT_FAIL_R6:-data/eval_failures_r6.jsonl}"
[[ -f "$FAIL_R6" ]] || FAIL_R6="/tmp/jett_eval/eval_failures_r6_fixed.jsonl"

echo "[1/4] Reinforce r6 eval misses ($FAIL_R6)"
if [[ -f "$FAIL_R6" ]]; then
  python3 generate_eval_reinforce.py --failures "$FAIL_R6" \
    --out data/bucket_j_eval_reinforce_r8.jsonl --variants 4 --round round8
else
  echo "[skip] no failures file — run eval_guard.py --failures-out first"
fi

echo "[2/4] Lolbin behavior-over-path top-up"
python3 generate_lolbins.py --count 150 --out data/bucket_f_lolbins_r8.jsonl
python3 generate_stretch_threats.py --count 150 --out data/bucket_d3_stretch_r8.jsonl

echo "[3/4] Merge v8"
python3 stratified_merge.py --total "$TOTAL" --eval-frac 0.05 \
  --out data/jett_training_v8.json \
  --eval-out tests/guard_eval_v8.jsonl \
  --coverage-out data/mitre_coverage_v8.json \
  --buckets data/bucket_*.jsonl

echo "[4/4] Coverage gate"
python3 coverage/zero_gate.py --coverage data/mitre_coverage_v8.json

echo "[+] Round 8 ready: data/jett_training_v8.json"
