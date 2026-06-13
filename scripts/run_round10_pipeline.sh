#!/usr/bin/env bash
# jeTT Round 10 — surgical: r9 eval misses + lolbin/behavior reinforce.
set -euo pipefail
cd "$(dirname "$0")/.."

TOTAL="${JETT_TRAIN_TOTAL:-70000}"
FAIL_R9="${JETT_FAIL_R9:-data/eval_failures_r9.jsonl}"

echo "[1/4] Reinforce r9 eval misses ($FAIL_R9)"
if [[ -f "$FAIL_R9" ]]; then
  python3 generate_eval_reinforce.py --failures "$FAIL_R9" \
    --out data/bucket_j_eval_reinforce_r10.jsonl --variants 4 --round round10
else
  echo "[!] missing $FAIL_R9 — run after r9 pull:"
  echo "    JETT_MODEL=models/jett-r9-q4_k_m.gguf python3 eval_guard.py \\"
  echo "      --eval tests/guard_eval_v9.jsonl --jett target/release/jeTT \\"
  echo "      --failures-out data/eval_failures_r9.jsonl"
  echo "    bash scripts/run_round10_pipeline.sh"
  exit 1
fi

echo "[2/4] Lolbin + stretch top-up"
python3 generate_lolbins.py --count 150 --out data/bucket_f_lolbins_r10.jsonl
python3 generate_stretch_threats.py --count 150 --out data/bucket_d3_stretch_r10.jsonl

echo "[3/4] Merge v10"
python3 stratified_merge.py --total "$TOTAL" --eval-frac 0.05 \
  --out data/jett_training_v10.json \
  --eval-out tests/guard_eval_v10.jsonl \
  --coverage-out data/mitre_coverage_v10.json \
  --buckets data/bucket_*.jsonl

echo "[4/4] Coverage gate"
python3 coverage/zero_gate.py --coverage data/mitre_coverage_v10.json

echo "[+] Round 10 ready: data/jett_training_v10.json"
