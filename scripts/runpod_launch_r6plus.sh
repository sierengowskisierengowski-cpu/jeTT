#!/usr/bin/env bash
# r6+ on RunPod: ensure r6 LoRA exists, then surgical refine (NOT retrain from scratch).
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${RUNPOD_HOST:-194.68.245.3}"
PORT="${RUNPOD_PORT:-22043}"
USER="${RUNPOD_USER:-root}"
REMOTE="${RUNPOD_DIR:-/workspace/jett}"
SSH="ssh -o StrictHostKeyChecking=no -p $PORT $USER@$HOST"
RSYNC_SSH="ssh -o StrictHostKeyChecking=no -p $PORT"

R6_STEPS="${JETT_R6_SEED_STEPS:-250}"
R6PLUS_STEPS="${JETT_R6PLUS_STEPS:-100}"
LR="${JETT_LEARNING_RATE:-5e-5}"

for f in data/jett_training_r6plus.json data/jett_training_v6.json; do
  if [[ ! -f "$f" ]]; then
    echo "[!] missing $f — run: bash scripts/run_r6plus_pipeline.sh"
    exit 1
  fi
done

echo "=============================================="
echo " jeTT RunPod r6+ (surgical refine FROM r6 LoRA)"
echo " Host: $USER@$HOST:$PORT"
echo " r6 seed: ${R6_STEPS} steps (if checkpoint missing)"
echo " r6+ refine: ${R6PLUS_STEPS} steps @ lr=${LR}"
echo "=============================================="

echo "[1/4] Sync scripts + data..."
$SSH "mkdir -p $REMOTE/data $REMOTE/models/r6plus $REMOTE/outputs/r6 $REMOTE/outputs/r6plus $REMOTE/scripts"
rsync -az -e "$RSYNC_SSH" --no-owner --no-group scripts/ "$USER@$HOST:$REMOTE/scripts/"
rsync -az -e "$RSYNC_SSH" --no-owner --no-group \
  train_core_weights.py build_r6plus_dataset.py \
  "$USER@$HOST:$REMOTE/"
rsync -az -e "$RSYNC_SSH" --no-owner --no-group \
  data/jett_training_v6.json data/jett_training_r6plus.json \
  "$USER@$HOST:$REMOTE/data/"

echo "[2/4] Launch r6+ pipeline (nohup)..."
$SSH "cd $REMOTE && chmod +x scripts/*.sh && \
  export HF_HOME=/workspace/jett/.cache/hf && \
  export JETT_R6_SEED_STEPS=${R6_STEPS} && \
  export JETT_R6PLUS_STEPS=${R6PLUS_STEPS} && \
  export JETT_LEARNING_RATE=${LR} && \
  export JETT_FORCE=${JETT_FORCE:-1} && \
  nohup bash scripts/runpod_r6plus_pipeline.sh > train_r6plus.log 2>&1 & echo started"

echo "[3/4] Monitor:"
echo "  $SSH 'tail -f $REMOTE/train_r6plus.log'"
echo ""
echo "[4/4] When done — pull + eval vs r6 bar:"
echo "  RUNPOD_HOST=$HOST RUNPOD_PORT=$PORT JETT_PULL_ROUNDS=r6plus bash scripts/runpod_pull_models.sh"
echo "  JETT_BIN=target/release/jeTT bash scripts/run_eval_models.sh"
