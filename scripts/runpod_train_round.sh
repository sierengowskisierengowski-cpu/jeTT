#!/usr/bin/env bash
# Train one round on RunPod: LoRA checkpoint + reliable GGUF export.
# Run from /workspace/jett with venv active (called by runpod_full_pipeline.sh).
set -euo pipefail

ROUND="${1:?usage: runpod_train_round.sh ROUND DATA_JSON STEPS [GGUF_OUT]}"
DATA="${2:?}"
STEPS="${3:?}"
GGUF_OUT="${4:-models/${ROUND}/jett-${ROUND}-q4_k_m.gguf}"

export JETT_TRAINING_DATA="$DATA"
export JETT_TRAIN_MAX_STEPS="$STEPS"
export JETT_TRAIN_BATCH="${JETT_TRAIN_BATCH:-4}"
export JETT_TRAIN_GRAD_ACCUM="${JETT_TRAIN_GRAD_ACCUM:-4}"
export JETT_TRAIN_MAX_SEQ="${JETT_TRAIN_MAX_SEQ:-512}"
export JETT_OUTPUT_DIR="${JETT_OUTPUT_DIR:-outputs/${ROUND}}"
export JETT_GGUF_DIR="${JETT_GGUF_DIR:-models/${ROUND}}"
export JETT_SKIP_GGUF=1

LOG="${JETT_LOG:-train_${ROUND}.log}"
CKPT="${JETT_OUTPUT_DIR}/checkpoint-${STEPS}"

if [[ ! -f "$DATA" ]]; then
  echo "[!] missing training data: $DATA"
  exit 1
fi

echo ""
echo "========== jeTT train round=${ROUND} steps=${STEPS} =========="

if [[ -d "$CKPT" && "${JETT_FORCE:-0}" != "1" ]]; then
  echo "[skip-train] $(date -Is) checkpoint exists: $CKPT (set JETT_FORCE=1 to retrain)"
else
  echo "[train] $(date -Is) data=$DATA -> $CKPT"
  python train_core_weights.py \
    --data "$JETT_TRAINING_DATA" \
    --max-steps "$JETT_TRAIN_MAX_STEPS" \
    --batch-size "$JETT_TRAIN_BATCH" \
    --grad-accum "$JETT_TRAIN_GRAD_ACCUM" \
    --output-dir "$JETT_OUTPUT_DIR" \
    --gguf-dir "$JETT_GGUF_DIR" \
    --skip-gguf \
    2>&1 | tee -a "$LOG"
fi

export JETT_CHECKPOINT="$CKPT"
export JETT_CLEAN="${JETT_GGUF_DIR}/clean"
export JETT_GGUF_BF16="${JETT_GGUF_DIR}/jett-${ROUND}.BF16.gguf"
export JETT_GGUF_OUT="$GGUF_OUT"

echo "[export] $(date -Is) $CKPT -> $GGUF_OUT"
bash scripts/export_gguf_pod.sh 2>&1 | tee -a "${LOG%.log}_export.log"

if [[ ! -f "$GGUF_OUT" ]]; then
  echo "[!] GGUF not found after export: $GGUF_OUT"
  exit 1
fi
ls -lh "$GGUF_OUT"
echo "[+] round ${ROUND} complete"
