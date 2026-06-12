#!/usr/bin/env bash
# Run ON the RunPod pod — /workspace/jett (single round; see runpod_full_pipeline.sh)
set -euo pipefail
cd /workspace/jett

export UNSLOTH_DISABLE_VERSION_CHECK=1
export PYTORCH_ALLOC_CONF=expandable_segments:True

DATA="${JETT_TRAINING_DATA:-data/jett_training_v6.json}"
STEPS="${JETT_TRAIN_MAX_STEPS:-250}"
ROUND="${JETT_ROUND:-r6}"
GGUF="${JETT_GGUF_OUT:-models/${ROUND}/jett-${ROUND}-q4_k_m.gguf}"

if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

bash scripts/runpod_train_round.sh "$ROUND" "$DATA" "$STEPS" "$GGUF"
