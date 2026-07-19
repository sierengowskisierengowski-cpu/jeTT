#!/usr/bin/env bash
# Sync r4 runtime-format training data + scripts to RunPod and start train+export.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${RUNPOD_HOST:-213.173.105.4}"
PORT="${RUNPOD_PORT:-30077}"
USER="${RUNPOD_USER:-root}"
REMOTE="${RUNPOD_DIR:-/workspace/jett}"
SSH="ssh -o StrictHostKeyChecking=accept-new -p $PORT $USER@$HOST"
RSYNC_SSH="ssh -o StrictHostKeyChecking=accept-new -p $PORT"

DATA="${JETT_TRAINING_DATA:-data/jett_training_v4.json}"
if [[ ! -f "$DATA" ]]; then
  echo "[!] missing $DATA — run: python3 generate_round4.py"
  exit 1
fi

echo "=============================================="
echo " jeTT RunPod r4 (runtime behavioral profiles)"
echo " Host: $USER@$HOST:$PORT"
echo " Data: $DATA"
echo "=============================================="

echo "[1/3] Sync scripts + training data..."
$SSH "mkdir -p $REMOTE/data $REMOTE/models/r4 $REMOTE/outputs/r4 $REMOTE/scripts $REMOTE/src"
rsync -az --progress -e "$RSYNC_SSH" --no-owner --no-group scripts/ "$USER@$HOST:$REMOTE/scripts/"
rsync -az --progress -e "$RSYNC_SSH" --no-owner --no-group src/ "$USER@$HOST:$REMOTE/src/"
rsync -az -e "$RSYNC_SSH" --no-owner --no-group \
  train_core_weights.py eval_guard.py stratified_merge.py \
  "$USER@$HOST:$REMOTE/"
rsync -az --progress -e "$RSYNC_SSH" --no-owner --no-group "$DATA" "$USER@$HOST:$REMOTE/data/jett_training_v4.json"

echo "[2/3] Launch r4 pipeline (nohup)..."
$SSH "cd $REMOTE && chmod +x scripts/*.sh && \
  export HF_HOME=/workspace/jett/.cache/hf && \
  export JETT_TRAIN_MAX_STEPS=${JETT_TRAIN_MAX_STEPS:-300} && \
  export JETT_ROUNDS=r4 && \
  export JETT_FORCE=${JETT_FORCE:-0} && \
  nohup bash scripts/runpod_full_pipeline.sh > train_r4.log 2>&1 & echo started pid=\$!"

echo "[3/3] Monitor:"
echo "  $SSH 'tail -f $REMOTE/train_r4.log'"
echo ""
echo "When done:"
echo "  RUNPOD_HOST=$HOST RUNPOD_PORT=$PORT JETT_PULL_ROUNDS=r4 bash scripts/runpod_pull_models.sh"
