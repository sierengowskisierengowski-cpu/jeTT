#!/usr/bin/env bash
# jeTT RunPod venv — torch cu124 for driver 12.8; no torchao (not used by our train path).
set -euo pipefail
cd /workspace/jett

log() { echo "[$(date -Is)] $*"; }

if [[ "${JETT_VENV_REBUILD:-1}" == "1" ]]; then
  log "removing old .venv"
  rm -rf .venv
fi

python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q --upgrade pip wheel

log "torch 2.6.0+cu124"
pip install -q "torch==2.6.0" "torchvision" "torchaudio" \
  --index-url https://download.pytorch.org/whl/cu124

python - <<'PY'
import torch
assert torch.cuda.is_available()
print(f"[ok] torch {torch.__version__} cuda={torch.version.cuda} gpu={torch.cuda.get_device_name(0)}")
PY

log "training deps (transformers<4.49 avoids broken torchao import on torch 2.6)"
pip install -q \
  "transformers==4.48.3" \
  "trl==0.15.2" \
  "peft==0.14.0" \
  "accelerate==1.4.0" \
  "bitsandbytes==0.45.3" \
  "datasets" "pyyaml" "sentencepiece" "protobuf" "hf_transfer" "tyro" "ninja"

log "unsloth (no-deps — we already pinned torch/transformers)"
pip install -q "unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git" --no-deps
pip install -q "unsloth_zoo"

# torchao optional; breaks on torch 2.6 — jeTT uses bitsandbytes only.
pip uninstall -y torchao 2>/dev/null || true
pip install -q "pydantic"  # unsloth warns if missing

# torchao is optional for HF quantizers; jeTT uses bitsandbytes + unsloth only.
pip uninstall -y torchao 2>/dev/null || true

python - <<'PY'
import torch
from unsloth import FastLanguageModel
print(f"[ok] unsloth ready; torch {torch.__version__} cuda={torch.cuda.is_available()}")
PY

log "venv ready"
