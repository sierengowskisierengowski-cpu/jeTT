#!/usr/bin/env bash
# One RunPod job: train + export r6 and r7 (skip rounds that already have GGUF).
# Run ON the pod from /workspace/jett (started by runpod_launch_all.sh).
set -euo pipefail
cd /workspace/jett

export UNSLOTH_DISABLE_VERSION_CHECK=1
export PYTORCH_ALLOC_CONF=expandable_segments:True

MAIN_LOG="${JETT_MAIN_LOG:-full_pipeline.log}"
STEPS="${JETT_TRAIN_MAX_STEPS:-250}"

# round|data_json|gguf_path
DEFAULT_ROUNDS=(
  "r6|data/jett_training_v6.json|models/r6/jett-r6-q4_k_m.gguf"
  "r7|data/jett_training_v7.json|models/r7/jett-r7-q4_k_m.gguf"
)

if [[ -n "${JETT_ROUNDS:-}" ]]; then
  # Space-separated: r6 r7 or r7 only
  mapfile -t ROUND_SPECS < <(
    for r in $JETT_ROUNDS; do
      case "$r" in
        r6) echo "r6|data/jett_training_v6.json|models/r6/jett-r6-q4_k_m.gguf" ;;
        r7) echo "r7|data/jett_training_v7.json|models/r7/jett-r7-q4_k_m.gguf" ;;
        r8) echo "r8|data/jett_training_v8.json|models/r8/jett-r8-q4_k_m.gguf" ;;
        *) echo "[!] unknown round $r" >&2; exit 1 ;;
      esac
    done
  )
else
  ROUND_SPECS=("${DEFAULT_ROUNDS[@]}")
fi

log() { echo "[$(date -Is)] $*" | tee -a "$MAIN_LOG"; }

log "jeTT full pipeline start (steps=$STEPS force=${JETT_FORCE:-0})"

if [[ ! -d .venv ]]; then
  log "creating venv..."
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

if ! python -c "import unsloth" 2>/dev/null; then
  log "installing unsloth + deps (5-15 min)..."
  pip install -q --upgrade pip
  pip install -q "unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git" \
    trl transformers datasets accelerate bitsandbytes pyyaml
fi

for spec in "${ROUND_SPECS[@]}"; do
  IFS='|' read -r round data gguf <<<"$spec"
  if [[ -f "$gguf" && "${JETT_FORCE:-0}" != "1" ]]; then
    log "skip $round — GGUF exists: $gguf"
    continue
  fi
  if [[ ! -f "$data" ]]; then
    log "skip $round — missing $data (run round pipeline locally first)"
    continue
  fi
  log "=== training $round ==="
  bash scripts/runpod_train_round.sh "$round" "$data" "$STEPS" "$gguf" \
    2>&1 | tee -a "$MAIN_LOG"
done

log "full pipeline done"
find models -name 'jett-r*-q4_k_m.gguf' -exec ls -lh {} \; 2>/dev/null | tee -a "$MAIN_LOG" || true
