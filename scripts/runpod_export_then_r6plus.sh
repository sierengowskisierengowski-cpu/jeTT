#!/usr/bin/env bash
# On RunPod: export r10 GGUF from existing checkpoint, then run r6+ pipeline.
set -euo pipefail
cd /workspace/jett
source .venv/bin/activate

export HF_HOME="${HF_HOME:-/workspace/jett/.cache/hf}"
LOG="${JETT_CHAIN_LOG:-export_then_r6plus.log}"

log() { echo "[$(date -Is)] $*" | tee -a "$LOG"; }

log "=== phase 1: export r10 from checkpoint-300 ==="
if [[ -f models/r10/jett-r10-q4_k_m.gguf ]]; then
  log "r10 GGUF already exists — skip export"
else
  bash scripts/runpod_train_round.sh r10 data/jett_training_v10.json 300 models/r10/jett-r10-q4_k_m.gguf \
    2>&1 | tee -a "$LOG"
fi

log "=== phase 2: r6+ pipeline ==="
bash scripts/runpod_r6plus_pipeline.sh 2>&1 | tee -a "$LOG"

log "=== chain complete ==="
ls -lh models/r10/jett-r10-q4_k_m.gguf models/r6plus/jett-r6plus-q4_k_m.gguf 2>&1 | tee -a "$LOG"
