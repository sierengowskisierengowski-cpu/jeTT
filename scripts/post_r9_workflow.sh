#!/usr/bin/env bash
# After r9 RunPod export: pull → eval r6/r8/r9 → prep r10 data if failures exist.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${RUNPOD_HOST:-194.68.245.118}"
PORT="${RUNPOD_PORT:-22097}"
JETT_BIN="${JETT_BIN:-target/release/jeTT}"

echo "=============================================="
echo " jeTT post-r9 workflow"
echo "=============================================="

echo "[1/4] Pull r9 GGUF from RunPod..."
RUNPOD_HOST="$HOST" RUNPOD_PORT="$PORT" JETT_PULL_ROUNDS=r9 bash scripts/runpod_pull_models.sh

if [[ ! -f models/jett-r9-q4_k_m.gguf ]]; then
  echo "[!] pull failed — is train_r9.log finished on the pod?"
  exit 1
fi

echo ""
echo "[2/4] Eval r6 / r8 / r9 on held-out sets..."
JETT_BIN="$JETT_BIN" bash scripts/run_eval_models.sh

echo ""
echo "[3/4] Score r9 on v9 eval (failures → r10 input)..."
JETT_MODEL=models/jett-r9-q4_k_m.gguf JETT_BIN="$JETT_BIN" \
  python3 eval_guard.py --eval tests/guard_eval_v9.jsonl --jett "$JETT_BIN" \
  --failures-out data/eval_failures_r9.jsonl

echo ""
echo "[4/4] Build r10 training merge (if failures exist)..."
if [[ -f data/eval_failures_r9.jsonl ]] && [[ -s data/eval_failures_r9.jsonl ]]; then
  bash scripts/run_round10_pipeline.sh
  echo ""
  echo "[+] r10 ready. Launch when you want:"
  echo "    RUNPOD_HOST=$HOST RUNPOD_PORT=$PORT bash scripts/runpod_launch_r10.sh"
else
  echo "[skip] no r9 eval failures — r10 not needed yet"
fi

echo ""
echo "[+] Done. Compare accuracy above; deploy winner via JETT_MODEL + systemctl restart jett-daemon"
