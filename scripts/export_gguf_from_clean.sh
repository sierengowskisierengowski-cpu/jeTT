#!/usr/bin/env bash
# Export GGUF from an existing merged HF dir (no HuggingFace re-download).
# Use when train finished but export_gguf_pod.sh failed (disk quota, etc.).
set -euo pipefail
cd /workspace/jett
source .venv/bin/activate

ROUND="${1:-r6}"
CLEAN="${JETT_CLEAN:-models/${ROUND}/clean}"
# Write BF16 to /tmp first — network FS on RunPod can stall mid-write on workspace.
BF16="${JETT_GGUF_BF16:-/tmp/jett-${ROUND}.BF16.gguf}"
OUT="${JETT_GGUF_OUT:-models/${ROUND}/jett-${ROUND}-q4_k_m.gguf}"

if [[ ! -f "${CLEAN}/model.safetensors" && ! -f "${CLEAN}/pytorch_model.bin" ]]; then
  echo "[!] missing merged weights in $CLEAN"
  exit 1
fi

echo "[export-clean] $CLEAN -> $OUT"
python /root/.unsloth/llama.cpp/unsloth_convert_hf_to_gguf.py \
  "$CLEAN" --outfile "$BF16" --outtype bf16
/root/.unsloth/llama.cpp/llama-quantize "$BF16" "$OUT" q4_k_m
ls -lh "$OUT"
echo "[+] done: $OUT"
