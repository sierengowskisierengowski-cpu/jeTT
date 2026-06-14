#!/usr/bin/env bash
# Export GGUF from merged HF dir via unsloth (no hardcoded llama.cpp path).
set -euo pipefail
cd /workspace/jett
source .venv/bin/activate

ROUND="${1:-r10}"
CLEAN="${JETT_CLEAN:-models/${ROUND}/clean}"
OUT="${JETT_GGUF_OUT:-models/${ROUND}/jett-${ROUND}-q4_k_m.gguf}"
OUT_DIR="$(dirname "$OUT")"

if [[ ! -f "${CLEAN}/model.safetensors" && ! -f "${CLEAN}/pytorch_model.bin" && -z "$(ls "${CLEAN}"/model-*.safetensors 2>/dev/null)" ]]; then
  echo "[!] missing merged weights in $CLEAN"
  exit 1
fi

echo "[export-unsloth] $CLEAN -> $OUT"
python - <<PY
import os, glob, shutil
os.environ["UNSLOTH_DISABLE_VERSION_CHECK"] = "1"
from unsloth import FastLanguageModel
clean, out_dir, out_path = "$CLEAN", "$OUT_DIR", "$OUT"
model, tokenizer = FastLanguageModel.from_pretrained(
    clean, max_seq_length=512, dtype=None, load_in_4bit=False)
model.save_pretrained_gguf(out_dir, tokenizer, quantization_method="q4_k_m")
ggufs = glob.glob(f"{out_dir}/**/*.gguf", recursive=True) + glob.glob(f"{out_dir}/*.gguf")
q4 = [g for g in ggufs if "Q4_K_M" in g.upper() or "q4_k_m" in g]
src = q4[0] if q4 else (ggufs[0] if ggufs else None)
if not src:
    raise SystemExit("no GGUF produced")
shutil.copy2(src, out_path)
print(f"[+] {out_path}")
PY
ls -lh "$OUT"
