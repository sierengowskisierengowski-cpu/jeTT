#!/usr/bin/env bash
# Quick venv sanity check before GPU train — fail fast with clear errors.
set -euo pipefail
cd /workspace/jett
source .venv/bin/activate
pip uninstall -y torchao 2>/dev/null || true

python - <<'PY'
import sys
import torch
print(f"python={sys.executable}")
print(f"torch={torch.__version__} cuda={torch.cuda.is_available()}")
if not torch.cuda.is_available():
    raise SystemExit("CUDA not available")

import bitsandbytes as bnb
print(f"bitsandbytes={bnb.__version__}")

from transformers.utils import is_bitsandbytes_available
if not is_bitsandbytes_available():
    raise SystemExit("transformers reports bitsandbytes unavailable — reinstall bitsandbytes")

import transformers
print(f"transformers={transformers.__version__}")

import unsloth  # noqa: F401
from unsloth import FastLanguageModel
print("unsloth import ok")
PY

echo "[preflight] ok"
