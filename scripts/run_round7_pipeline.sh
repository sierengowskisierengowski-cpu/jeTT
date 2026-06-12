#!/usr/bin/env bash
# jeTT Round 7 — eval reinforce + own-stack + threat depth → v7
set -euo pipefail
cd "$(dirname "$0")/.."

TOTAL="${JETT_TRAIN_TOTAL:-65000}"
JETT_MODEL="${JETT_MODEL:-$HOME/Projects/jeTT/models/jett-r5-q4_k_m.gguf}"
JETT_BIN="${JETT_BIN:-target/release/jeTT}"

echo "[1/6] Optional eval → failures (skip by default; set JETT_RUN_EVAL=1 to score)"
if [[ "${JETT_RUN_EVAL:-0}" == "1" && -x "$JETT_BIN" && -f "$JETT_MODEL" ]]; then
  python3 eval_guard.py --eval tests/guard_eval_v6.jsonl --jett "$JETT_BIN" \
    --failures-out data/eval_failures_r6.jsonl || true
else
  echo "    skip eval (fast path — r5 failures already in data/eval_failures_r5.jsonl)"
fi

echo "[2/6] Reinforce eval misses (r5 required, r6 optional)"
python3 generate_eval_reinforce.py --failures data/eval_failures_r5.jsonl \
  --out data/bucket_j_eval_reinforce_r7.jsonl --variants 4 --round round7
if [[ -f data/eval_failures_r6.jsonl ]]; then
  python3 generate_eval_reinforce.py --failures data/eval_failures_r6.jsonl \
    --out data/bucket_j2_eval_reinforce_r7.jsonl --variants 3 --round round7
fi

echo "[3/6] Own stack (cowrie, GNI, bifrost, Steam, Govee, jeTT)"
python3 generate_own_stack.py --count 450 --seed 71 --out data/bucket_g2_own_stack_r7.jsonl

echo "[4/6] Threat depth"
python3 generate_threats.py --count 500 --out data/bucket_a2_threats_r7.jsonl
python3 generate_stretch_threats.py --count 300 --out data/bucket_d2_stretch_r7.jsonl

echo "[5/6] Stratified merge -> v7"
python3 stratified_merge.py --total "$TOTAL" --eval-frac 0.05 \
  --out data/jett_training_v7.json \
  --eval-out tests/guard_eval_v7.jsonl \
  --coverage-out data/mitre_coverage_v7.json \
  --buckets data/bucket_*.jsonl

echo "[6/6] Coverage gate"
python3 coverage/zero_gate.py --coverage data/mitre_coverage_v7.json

echo ""
echo "[+] Round 7 ready: data/jett_training_v7.json"
echo "    One-shot pod: bash scripts/runpod_launch_all.sh"
