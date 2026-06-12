#!/usr/bin/env bash
# Local one-command: build v7 data, sync to RunPod, start full train+export pipeline.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${RUNPOD_HOST:-194.68.245.125}"
PORT="${RUNPOD_PORT:-22146}"
USER="${RUNPOD_USER:-root}"
REMOTE="${RUNPOD_DIR:-/workspace/jett}"
SSH="ssh -o StrictHostKeyChecking=no -p $PORT $USER@$HOST"
RSYNC_SSH="ssh -o StrictHostKeyChecking=no -p $PORT"

echo "=============================================="
echo " jeTT RunPod one-shot (r6+r7 train + GGUF)"
echo " Host: $USER@$HOST:$PORT"
echo " Remote: $REMOTE"
echo "=============================================="

echo ""
echo "[1/4] Local Round 7 data pipeline..."
bash scripts/run_round7_pipeline.sh

echo ""
echo "[2/4] Sync repo + datasets to pod (excludes large GGUFs)..."
$SSH "mkdir -p $REMOTE/data $REMOTE/models $REMOTE/outputs $REMOTE/scripts $REMOTE/coverage $REMOTE/tests"
rsync -az --progress \
  -e "$RSYNC_SSH" \
  --exclude '.git/' \
  --exclude 'target/' \
  --exclude 'models/*.gguf' \
  --exclude 'models/**/' \
  --exclude '.venv/' \
  --exclude '__pycache__/' \
  --exclude 'outputs/' \
  --exclude 'data/bucket_*.jsonl' \
  ./ "$USER@$HOST:$REMOTE/"

# Training JSON + eval (small, required)
for f in data/jett_training_v6.json data/jett_training_v7.json \
  data/eval_failures_r5.jsonl data/eval_failures_r6.jsonl; do
  if [[ -f "$f" ]]; then
    rsync -az -e "$RSYNC_SSH" "$f" "$USER@$HOST:$REMOTE/$f"
  fi
done

echo ""
echo "[3/4] Launch remote full pipeline (nohup)..."
$SSH "cd $REMOTE && chmod +x scripts/*.sh && \
  export JETT_TRAIN_MAX_STEPS=${JETT_TRAIN_MAX_STEPS:-250} && \
  export JETT_ROUNDS='${JETT_ROUNDS:-r6 r7}' && \
  export JETT_FORCE='${JETT_FORCE:-0}' && \
  nohup bash scripts/runpod_full_pipeline.sh > setup_full_pipeline.log 2>&1 & echo PID=\$!"

echo ""
echo "[4/4] Monitor on pod:"
echo "  $SSH 'tail -f $REMOTE/full_pipeline.log'"
echo ""
echo "When finished, pull GGUFs locally:"
echo "  bash scripts/runpod_pull_models.sh"
echo ""
echo "Optional — r7 only (if r6 already done on pod):"
echo "  JETT_ROUNDS=r7 bash scripts/runpod_launch_all.sh"
