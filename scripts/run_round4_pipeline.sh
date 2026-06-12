#!/usr/bin/env bash
# jeTT Round 4 — generate buckets, merge, coverage gate, optional train.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

TOTAL="${JETT_TRAIN_TOTAL:-50000}"
A_COUNT="${JETT_BUCKET_A:-1800}"
B_COUNT="${JETT_BUCKET_B:-2500}"
C_PAIRS="${JETT_BUCKET_C:-800}"

echo "[1/5] Bucket A — threats"
python3 training/generators/generate_threats.py --count "$A_COUNT" --out data/bucket_a_threats.jsonl

echo "[2/5] Bucket B — legit scary"
python3 training/generators/generate_false_positive_armor.py --count "$B_COUNT" --out data/bucket_b_scary_legit.jsonl

echo "[3/5] Bucket C — ambiguous pairs"
python3 training/generators/generate_ambiguous_pairs.py --pairs "$C_PAIRS" --out data/bucket_c_ambiguous.jsonl

echo "[4/5] Stratified merge"
python3 training/merge/stratified_merge.py --total "$TOTAL" --eval-frac 0.05 \
  --buckets data/bucket_*.jsonl

echo "[5/5] Coverage gate"
if python3 training/coverage/zero_gate.py --coverage data/mitre_coverage.json; then
  echo "[+] coverage gate PASS"
else
  echo "[!] coverage gate FAIL — re-run with JETT_GATE_WARN=1 to train anyway"
  if [[ "${JETT_GATE_WARN:-}" != "1" ]]; then
    exit 1
  fi
fi

echo ""
echo "[+] Ready: data/jett_training_v4.json ($(python3 -c 'import json;print(len(json.load(open("data/jett_training_v4.json"))))') records)"
echo "    Train: JETT_TRAINING_DATA=data/jett_training_v4.json python3 training/train_core_weights.py"
echo "    Or:    bash scripts/runpod_train.sh"
