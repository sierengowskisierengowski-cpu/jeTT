#!/usr/bin/env bash
# Run ON the RunPod pod — /workspace/jett
set -euo pipefail
cd /workspace/jett

export UNSLOTH_DISABLE_VERSION_CHECK=1
export PYTORCH_ALLOC_CONF=expandable_segments:True
export JETT_TRAINING_DATA="${JETT_TRAINING_DATA:-data/jett_training_v6.json}"
export JETT_TRAIN_MAX_STEPS="${JETT_TRAIN_MAX_STEPS:-250}"
export JETT_TRAIN_BATCH="${JETT_TRAIN_BATCH:-4}"
export JETT_TRAIN_GRAD_ACCUM="${JETT_TRAIN_GRAD_ACCUM:-4}"
export JETT_TRAIN_MAX_SEQ="${JETT_TRAIN_MAX_SEQ:-512}"
export JETT_OUTPUT_DIR="${JETT_OUTPUT_DIR:-outputs/r6}"
export JETT_GGUF_DIR="${JETT_GGUF_DIR:-models/r6}"

LOG="${JETT_LOG:-train_r6.log}"

# shellcheck disable=SC1091
source .venv/bin/activate

echo "[train] $(date -Is) data=$JETT_TRAINING_DATA steps=$JETT_TRAIN_MAX_STEPS"
python train_core_weights.py \
  --data "$JETT_TRAINING_DATA" \
  --max-steps "$JETT_TRAIN_MAX_STEPS" \
  --batch-size "$JETT_TRAIN_BATCH" \
  --grad-accum "$JETT_TRAIN_GRAD_ACCUM" \
  --output-dir "$JETT_OUTPUT_DIR" \
  --gguf-dir "$JETT_GGUF_DIR" \
  2>&1 | tee -a "$LOG"

echo "[export] post-train GGUF (pickle-safe path)"
export JETT_CHECKPOINT="${JETT_OUTPUT_DIR}/checkpoint-${JETT_TRAIN_MAX_STEPS}"
bash export_gguf_pod.sh 2>&1 | tee -a "${LOG%.log}_export.log"

echo "[done] $(date -Is)"
find models/r6 -name '*.gguf' -exec ls -lh {} \; 2>/dev/null || true
