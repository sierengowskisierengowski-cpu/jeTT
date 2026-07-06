#!/usr/bin/env bash
# jeTT RunPod preflight — sanity checks before training starts.
set -euo pipefail
cd "$(dirname "$0")/.."

log() { echo "[preflight] $*"; }

FAIL=0
check() {
    local label="$1"; shift
    if "$@" >/dev/null 2>&1; then
        log "✓ $label"
    else
        log "✗ $label FAILED"
        FAIL=$((FAIL + 1))
    fi
}

log "running preflight checks..."

# Python + CUDA
check "python3 available" python3 --version
check "torch importable" python3 -c "import torch"
check "CUDA available" python3 -c "import torch; assert torch.cuda.is_available()"
check "unsloth importable" python3 -c "from unsloth import FastLanguageModel"

# GPU VRAM — need at least 12GB for 2B + LoRA
VRAM=$(python3 -c "import torch; print(torch.cuda.get_device_properties(0).total_memory // 1024**3)" 2>/dev/null || echo 0)
log "  GPU: $(python3 -c "import torch; print(torch.cuda.get_device_name(0))" 2>/dev/null || echo unknown)  VRAM: ${VRAM}GB"
if (( VRAM < 12 )); then
    log "✗ insufficient VRAM: need ≥12GB, have ${VRAM}GB"
    FAIL=$((FAIL + 1))
else
    log "✓ VRAM ${VRAM}GB sufficient"
fi

# training data
DATA="${JETT_TRAINING_DATA:-data/jett_training_v11.json}"
if [ -f "$DATA" ]; then
    SIZE=$(du -sh "$DATA" | cut -f1)
    log "✓ training data found: $DATA ($SIZE)"
else
    log "✗ training data MISSING: $DATA"
    FAIL=$((FAIL + 1))
fi

if (( FAIL > 0 )); then
    log "preflight FAILED ($FAIL check(s)) — aborting training"
    exit 1
fi

log "preflight passed — ready to train"
