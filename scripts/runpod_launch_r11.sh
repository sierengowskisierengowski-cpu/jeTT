#!/usr/bin/env bash
# Push r11 training data + scripts to RunPod and start the training run.
# r11 targets jeTT's benchmark weak spots: supply_chain, lolbin_abuse,
# dropper, priv_esc, c2_doh, exfiltration, defense_impairment.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${RUNPOD_HOST:-203.57.40.101}"
PORT="${RUNPOD_PORT:-10074}"
USER="${RUNPOD_USER:-root}"
REMOTE="${RUNPOD_DIR:-/workspace/jett}"
KEY="${RUNPOD_KEY:-$HOME/.ssh/id_rsa}"
SSH="ssh -o StrictHostKeyChecking=no -p $PORT -i $KEY $USER@$HOST"
RSYNC_SSH="ssh -o StrictHostKeyChecking=no -p $PORT -i $KEY"
STEPS="${JETT_TRAIN_MAX_STEPS:-300}"

if [[ ! -f "data/jett_training_v11.json" ]]; then
    echo "[!] missing data/jett_training_v11.json — run: python3 generate_r11_dataset.py"
    exit 1
fi

echo "=============================================="
echo " jeTT RunPod r11 — targeted threat reinforcement"
echo " Host: $USER@$HOST:$PORT"
echo " Dataset: data/jett_training_v11.json ($(du -sh data/jett_training_v11.json | cut -f1))"
echo " Steps: $STEPS"
echo "=============================================="

echo "[1/4] creating remote directories..."
$SSH "mkdir -p $REMOTE/data $REMOTE/models/r11 $REMOTE/outputs/r11 $REMOTE/scripts $REMOTE/tests"

echo "[2/4] syncing scripts, train code, eval sets..."
rsync -az --progress -e "$RSYNC_SSH" --no-owner --no-group \
    scripts/ "$USER@$HOST:$REMOTE/scripts/"
rsync -az -e "$RSYNC_SSH" --no-owner --no-group \
    train_core_weights.py eval_guard.py stratified_merge.py \
    "$USER@$HOST:$REMOTE/"
rsync -az -e "$RSYNC_SSH" --no-owner --no-group \
    tests/guard_eval_v10.jsonl tests/guard_eval_v6.jsonl \
    "$USER@$HOST:$REMOTE/tests/"

echo "[3/4] uploading r11 dataset (75MB)..."
rsync -az --progress -e "$RSYNC_SSH" --no-owner --no-group \
    data/jett_training_v11.json "$USER@$HOST:$REMOTE/data/"

echo "[4/4] launching r11 pipeline (nohup — runs in background on pod)..."
$SSH "cd $REMOTE && chmod +x scripts/*.sh && \
    export HF_HOME=/workspace/jett/.cache/hf && \
    export JETT_TRAIN_MAX_STEPS=${STEPS} && \
    export JETT_ROUNDS=r11 && \
    export JETT_FORCE=1 && \
    export JETT_TRAIN_BATCH=4 && \
    export JETT_TRAIN_GRAD_ACCUM=4 && \
    export JETT_TRAIN_MAX_SEQ=512 && \
    export PYTORCH_ALLOC_CONF=expandable_segments:True && \
    export UNSLOTH_DISABLE_VERSION_CHECK=1 && \
    nohup bash scripts/runpod_full_pipeline.sh > train_r11.log 2>&1 & \
    echo 'started PID '\$!"

echo ""
echo "Training launched. Monitor with:"
echo "  $SSH 'tail -f $REMOTE/train_r11.log'"
echo ""
echo "When done, pull the model with:"
echo "  RUNPOD_HOST=$HOST RUNPOD_PORT=$PORT bash scripts/runpod_pull_models.sh"
echo ""
echo "Then benchmark vs r6:"
echo "  JETT_MODEL=models/jett-r11-q4_k_m.gguf python3 eval_guard.py --eval tests/guard_eval_v10.jsonl --jett /usr/lib/jett/jeTT"
