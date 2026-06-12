#!/usr/bin/env bash
# jeTT Round 6 — eval-driven widen + supply chain + LOLbins + own-stack + C2 variety
set -euo pipefail
cd "$(dirname "$0")/.."

JETT_MODEL="${JETT_MODEL:-$HOME/Projects/jeTT/models/jett-r5-q4_k_m.gguf}"
JETT_BIN="${JETT_BIN:-target/release/jeTT}"

echo "[1/8] Eval r5 model (failures -> reinforce bucket)"
if [[ -x "$JETT_BIN" ]]; then
  python3 eval_guard.py --eval tests/guard_eval_v5.jsonl --jett "$JETT_BIN" \
    --failures-out data/eval_failures_r5.jsonl || true
else
  echo "    skip eval (build jeTT first)"
fi

echo "[2/8] Reinforce eval misses"
python3 generate_eval_reinforce.py --failures data/eval_failures_r5.jsonl \
  --out data/bucket_i_eval_reinforce.jsonl 2>/dev/null || \
  echo "    no failures file yet — empty reinforce bucket skipped"

echo "[3/8] Supply chain"
python3 generate_supply_chain.py --count 400 --out data/bucket_e_supply_chain.jsonl

echo "[4/8] LOLbins"
python3 generate_lolbins.py --count 400 --out data/bucket_f_lolbins.jsonl

echo "[5/8] Own stack (jeTT/Cerberus/Bifrost)"
python3 generate_own_stack.py --count 350 --out data/bucket_g_own_stack.jsonl

echo "[6/8] C2 variety"
python3 generate_c2_variety.py --count 400 --out data/bucket_h_c2_variety.jsonl

echo "[7/8] Stratified merge -> v6"
TOTAL="${JETT_TRAIN_TOTAL:-60000}"
python3 stratified_merge.py --total "$TOTAL" --eval-frac 0.05 \
  --out data/jett_training_v6.json \
  --eval-out tests/guard_eval_v6.jsonl \
  --coverage-out data/mitre_coverage_v6.json \
  --buckets data/bucket_*.jsonl

echo "[8/8] Coverage gate"
python3 coverage/zero_gate.py --coverage data/mitre_coverage_v6.json

echo ""
echo "[+] Round 6 ready: data/jett_training_v6.json"
echo "    Pod: JETT_TRAINING_DATA=data/jett_training_v6.json JETT_TRAIN_MAX_STEPS=250 bash scripts/runpod_remote_train.sh"
