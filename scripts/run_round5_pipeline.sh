#!/usr/bin/env bash
# jeTT Round 5 — widen coverage (new MITRE + ambiguous + legit-scary), merge v5.
set -euo pipefail
cd "$(dirname "$0")/.."

TOTAL="${JETT_TRAIN_TOTAL:-55000}"
A_COUNT="${JETT_BUCKET_A:-1400}"
D_COUNT="${JETT_BUCKET_D:-600}"
B_COUNT="${JETT_BUCKET_B:-2800}"
C_PAIRS="${JETT_BUCKET_C:-1200}"

echo "[1/6] Bucket A — core threats"
python3 training/generators/generate_threats.py --count "$A_COUNT" --out data/bucket_a_threats.jsonl

echo "[2/6] Bucket D — stretch MITRE (lateral, ransomware, impair, webshell)"
python3 training/generators/generate_stretch_threats.py --count "$D_COUNT" --out data/bucket_d_stretch.jsonl

echo "[3/6] Bucket B — legit scary (widened)"
python3 training/generators/generate_false_positive_armor.py --count "$B_COUNT" --out data/bucket_b_scary_legit.jsonl

echo "[4/6] Bucket C — ambiguous pairs (widened)"
python3 training/generators/generate_ambiguous_pairs.py --pairs "$C_PAIRS" --out data/bucket_c_ambiguous.jsonl

echo "[5/6] Stratified merge → v5"
python3 training/merge/stratified_merge.py --total "$TOTAL" --eval-frac 0.05 \
  --out data/jett_training_v5.json \
  --eval-out tests/guard_eval_v5.jsonl \
  --coverage-out data/mitre_coverage_v5.json \
  --buckets data/bucket_*.jsonl

echo "[6/6] Coverage gate"
python3 training/coverage/zero_gate.py --coverage data/mitre_coverage_v5.json --matrix training/coverage/matrix.yaml

echo ""
echo "[+] Round 5 ready: data/jett_training_v5.json"
echo "    Train: JETT_TRAINING_DATA=data/jett_training_v5.json bash scripts/runpod_train.sh"
