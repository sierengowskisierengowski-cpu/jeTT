#!/usr/bin/env bash
# jeTT RunPod venv — strict pins; no torchao; no accidental torch upgrades.
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

log "torch 2.6.0+cu124 (pinned index)"
pip install -q "torch==2.6.0+cu124" "torchvision==0.21.0+cu124" "torchaudio==2.6.0+cu124" \
  --index-url https://download.pytorch.org/whl/cu124

python - <<'PY'
import torch
assert torch.cuda.is_available(), "CUDA required"
print(f"[ok] torch {torch.__version__} gpu={torch.cuda.get_device_name(0)}")
PY

log "core training deps (--no-deps where needed to avoid torch bump)"
pip install -q \
  "transformers==4.51.3" \
  "trl==0.15.2" \
  "peft==0.14.0" \
  "accelerate==1.4.0" \
  "datasets" "pyyaml" "sentencepiece" "protobuf" "hf_transfer" "tyro" "ninja" \
  "nest-asyncio" "typer" "pydantic" "fsspec<=2025.9.0"

pip install -q --no-deps "bitsandbytes==0.49.2"
pip install -q --no-deps "unsloth==2026.6.7" "unsloth_zoo==2026.6.5"

pip uninstall -y torchao 2>/dev/null || true

# Re-assert torch pin if anything drifted
pip install -q "torch==2.6.0+cu124" "torchvision==0.21.0+cu124" "torchaudio==2.6.0+cu124" \
  --index-url https://download.pytorch.org/whl/cu124

chmod +x scripts/runpod_preflight.sh
bash scripts/runpod_preflight.sh
log "venv ready"
