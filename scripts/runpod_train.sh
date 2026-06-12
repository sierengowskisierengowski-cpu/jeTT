#!/usr/bin/env bash
# Upload v4 dataset + train on RunPod (or any CUDA host with unsloth).
set -euo pipefail
cd "$(dirname "$0")/.."

DATA="${JETT_TRAINING_DATA:-data/jett_training_v4.json}"
STEPS="${JETT_TRAIN_STEPS:-120}"

if [[ ! -f "$DATA" ]]; then
  echo "[!] missing $DATA — run scripts/run_round4_pipeline.sh first"
  exit 1
fi

export JETT_TRAINING_DATA="$DATA"
export JETT_TRAIN_MAX_STEPS="$STEPS"

# jett-daemon loads the GGUF on GPU (~2GB). Stop it before training on a 6GB card.
if nvidia-smi --query-compute-apps=pid,process_name --format=csv 2>/dev/null | grep -q jett-daemon; then
  echo "[!] jett-daemon is using GPU VRAM. Stop it first:"
  echo "    sudo systemctl stop jett-daemon"
  exit 1
fi

export PYTORCH_ALLOC_CONF="${PYTORCH_ALLOC_CONF:-expandable_segments:True}"
export JETT_TRAIN_BATCH="${JETT_TRAIN_BATCH:-1}"
export JETT_TRAIN_GRAD_ACCUM="${JETT_TRAIN_GRAD_ACCUM:-16}"
export JETT_TRAIN_MAX_SEQ="${JETT_TRAIN_MAX_SEQ:-512}"

echo "[*] Training from $DATA (max_steps=$STEPS, batch=$JETT_TRAIN_BATCH, seq=$JETT_TRAIN_MAX_SEQ)"
python3 train_core_weights.py

echo "[+] Done. GGUF under models/ — set JETT_MODEL and restart jett-daemon"
