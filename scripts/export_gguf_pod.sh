#!/usr/bin/env bash
# Run ON RunPod after train — merge LoRA to fp16 clean weights, then GGUF via unsloth.
set -euo pipefail
cd /workspace/jett
source .venv/bin/activate
export HF_HOME="${HF_HOME:-/workspace/jett/.cache/hf}"

CKPT="${JETT_CHECKPOINT:-outputs/r6/checkpoint-250}"
CLEAN="${JETT_CLEAN:-models/r6/clean}"
GGUF_OUT="${JETT_GGUF_OUT:-models/r6/jett-r6-q4_k_m.gguf}"
ROUND="${JETT_ROUND:-r6}"
MODEL="ibm-granite/granite-3.3-2b-instruct"

if [[ ! -f "${CLEAN}/model.safetensors" && ! -f "${CLEAN}/model-00001-of-00002.safetensors" ]]; then
  echo "[merge] $CKPT -> $CLEAN"
  python3 << PYEOF
import os, json, shutil
os.environ["UNSLOTH_DISABLE_VERSION_CHECK"] = "1"
from unsloth import FastLanguageModel
from peft import PeftModel

CKPT, CLEAN, MODEL = "$CKPT", "$CLEAN", "$MODEL"

model, tokenizer = FastLanguageModel.from_pretrained(
    MODEL, max_seq_length=512, dtype=None, load_in_4bit=False)
model = PeftModel.from_pretrained(model, CKPT)
model = model.merge_and_unload()
if os.path.isdir(CLEAN):
    shutil.rmtree(CLEAN)
model.save_pretrained(CLEAN, safe_serialization=True)
tokenizer.save_pretrained(CLEAN)
c = json.load(open(f"{CLEAN}/config.json"))
c.pop("quantization_config", None)
json.dump(c, open(f"{CLEAN}/config.json", "w"), indent=2)
print("[+] merged ->", CLEAN)
PYEOF
else
  echo "[merge] skip — clean weights already in $CLEAN"
fi

export JETT_CLEAN="$CLEAN"
export JETT_GGUF_OUT="$GGUF_OUT"
bash scripts/runpod_export_gguf_unsloth.sh "$ROUND"
