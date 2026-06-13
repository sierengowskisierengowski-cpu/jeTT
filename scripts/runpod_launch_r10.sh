#!/usr/bin/env bash
# Sync r10 training data + scripts to RunPod and start r10 train+export.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${RUNPOD_HOST:-194.68.245.125}"
PORT="${RUNPOD_PORT:-22146}"
USER="${RUNPOD_USER:-root}"
REMOTE="${RUNPOD_DIR:-/workspace/jett}"
SSH="ssh -o StrictHostKeyChecking=no -p $PORT $USER@$HOST"
RSYNC_SSH="ssh -o StrictHostKeyChecking=no -p $PORT"

if [[ ! -f data/jett_training_v10.json ]]; then
  echo "[!] missing data/jett_training_v10.json — run: bash scripts/run_round10_pipeline.sh"
  exit 1
fi

echo "=============================================="
echo " jeTT RunPod r10 (r9 eval miss reinforce)"
echo " Host: $USER@$HOST:$PORT"
echo "=============================================="

echo "[1/3] Sync scripts + training data..."
$SSH "mkdir -p $REMOTE/data $REMOTE/models/r10 $REMOTE/outputs/r10 $REMOTE/scripts $REMOTE/src $REMOTE/coverage $REMOTE/tests"
rsync -az --progress -e "$RSYNC_SSH" --no-owner --no-group scripts/ "$USER@$HOST:$REMOTE/scripts/"
rsync -az --progress -e "$RSYNC_SSH" --no-owner --no-group src/ "$USER@$HOST:$REMOTE/src/"
rsync -az --progress -e "$RSYNC_SSH" --no-owner --no-group coverage/ "$USER@$HOST:$REMOTE/coverage/"
rsync -az -e "$RSYNC_SSH" --no-owner --no-group tests/guard_eval_v10.jsonl "$USER@$HOST:$REMOTE/tests/"
rsync -az -e "$RSYNC_SSH" --no-owner --no-group \
  train_core_weights.py eval_guard.py stratified_merge.py generate_*.py \
  "$USER@$HOST:$REMOTE/"
rsync -az -e "$RSYNC_SSH" --no-owner --no-group data/jett_training_v10.json "$USER@$HOST:$REMOTE/data/"

echo "[2/3] Launch r10 pipeline (nohup)..."
$SSH "cd $REMOTE && chmod +x scripts/*.sh && \
  export HF_HOME=/workspace/jett/.cache/hf && \
  export JETT_TRAIN_MAX_STEPS=${JETT_TRAIN_MAX_STEPS:-250} && \
  export JETT_ROUNDS=r10 && \
  export JETT_FORCE=${JETT_FORCE:-0} && \
  nohup bash scripts/runpod_full_pipeline.sh > train_r10.log 2>&1 & echo started"

echo "[3/3] Monitor:"
echo "  $SSH 'tail -f $REMOTE/train_r10.log'"
echo ""
echo "When done:"
echo "  JETT_PULL_ROUNDS=r10 bash scripts/runpod_pull_models.sh"
