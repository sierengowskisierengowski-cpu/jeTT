#!/usr/bin/env bash
# jeTT Round 8 — eval-driven reinforce + log-shaped events (scaffold).
set -euo pipefail
cd "$(dirname "$0")/.."

TOTAL="${JETT_TRAIN_TOTAL:-70000}"

echo "[1/4] Reinforce r6/r7 eval misses (if failures exist)"
for f in data/eval_failures_r6.jsonl data/eval_failures_r7.jsonl; do
  if [[ -f "$f" ]]; then
  base=$(basename "$f" .jsonl)
  python3 generate_eval_reinforce.py --failures "$f" \
    --out "data/bucket_j_${base}.jsonl" --variants 3 --round round8
  fi
done

echo "[2/4] Threat + stretch top-up"
python3 generate_threats.py --count 400 --out data/bucket_a3_threats_r8.jsonl
python3 generate_stretch_threats.py --count 250 --out data/bucket_d3_stretch_r8.jsonl

echo "[3/4] Merge v8"
python3 stratified_merge.py --total "$TOTAL" --eval-frac 0.05 \
  --out data/jett_training_v8.json \
  --eval-out tests/guard_eval_v8.jsonl \
  --coverage-out data/mitre_coverage_v8.json \
  --buckets data/bucket_*.jsonl

echo "[4/4] Coverage gate"
python3 coverage/zero_gate.py --coverage data/mitre_coverage_v8.json

echo "[+] Round 8 ready: data/jett_training_v8.json"
