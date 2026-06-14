#!/usr/bin/env bash
# On RunPod: seed r6 LoRA if missing, then refine r6+ from that adapter.
set -euo pipefail
cd /workspace/jett

export UNSLOTH_DISABLE_VERSION_CHECK=1
export PYTORCH_ALLOC_CONF=expandable_segments:True

R6_STEPS="${JETT_R6_SEED_STEPS:-250}"
R6PLUS_STEPS="${JETT_R6PLUS_STEPS:-100}"
LR="${JETT_LEARNING_RATE:-5e-5}"
R6_CKPT="outputs/r6/checkpoint-${R6_STEPS}"
LOG="${JETT_MAIN_LOG:-train_r6plus.log}"

log() { echo "[$(date -Is)] $*" | tee -a "$LOG"; }

log "r6+ pipeline start (seed=${R6_STEPS} refine=${R6PLUS_STEPS} lr=${LR})"

source .venv/bin/activate 2>/dev/null || {
  bash scripts/runpod_setup_venv.sh 2>&1 | tee -a "$LOG"
  source .venv/bin/activate
}

pip uninstall -y torchao 2>/dev/null || true
pip install -q --no-deps --force-reinstall "bitsandbytes==0.49.2" 2>/dev/null || true
pip install -q "torch==2.6.0+cu124" "torchvision==0.21.0+cu124" "torchaudio==2.6.0+cu124" \
  --index-url https://download.pytorch.org/whl/cu124 2>/dev/null || true
bash scripts/runpod_preflight.sh 2>&1 | tee -a "$LOG"

if [[ ! -d "$R6_CKPT" ]]; then
  log "=== seed r6 LoRA (checkpoint missing) steps=${R6_STEPS} ==="
  export JETT_SKIP_GGUF=1
  python train_core_weights.py \
    --data data/jett_training_v6.json \
    --max-steps "$R6_STEPS" \
    --batch-size "${JETT_TRAIN_BATCH:-4}" \
    --grad-accum "${JETT_TRAIN_GRAD_ACCUM:-4}" \
    --output-dir outputs/r6 \
    --gguf-dir models/r6 \
    --skip-gguf \
    2>&1 | tee -a "$LOG"
fi

if [[ ! -d "$R6_CKPT" ]]; then
  log "FATAL: r6 checkpoint not found at $R6_CKPT"
  exit 1
fi

log "=== r6+ refine from $R6_CKPT steps=${R6PLUS_STEPS} lr=${LR} ==="
export JETT_LORA_ADAPTER="$R6_CKPT"
export JETT_LEARNING_RATE="$LR"
export JETT_SKIP_GGUF=1
export JETT_OUTPUT_DIR=outputs/r6plus
export JETT_GGUF_DIR=models/r6plus

python train_core_weights.py \
  --data data/jett_training_r6plus.json \
  --max-steps "$R6PLUS_STEPS" \
  --batch-size "${JETT_TRAIN_BATCH:-4}" \
  --grad-accum "${JETT_TRAIN_GRAD_ACCUM:-4}" \
  --output-dir outputs/r6plus \
  --gguf-dir models/r6plus \
  --lora-adapter "$R6_CKPT" \
  --learning-rate "$LR" \
  --skip-gguf \
  2>&1 | tee -a "$LOG"

R6PLUS_CKPT="outputs/r6plus/checkpoint-${R6PLUS_STEPS}"
export JETT_CHECKPOINT="$R6PLUS_CKPT"
export JETT_CLEAN="models/r6plus/clean"
export JETT_GGUF_OUT="models/r6plus/jett-r6plus-q4_k_m.gguf"

log "=== export r6+ GGUF ==="
bash scripts/export_gguf_pod.sh 2>&1 | tee -a "$LOG"

if [[ -f "models/r6plus/jett-r6plus-q4_k_m.gguf" ]]; then
  ls -lh models/r6plus/jett-r6plus-q4_k_m.gguf | tee -a "$LOG"
  log "r6+ complete"
else
  log "FATAL: GGUF export failed"
  exit 1
fi
