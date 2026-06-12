#!/usr/bin/env bash
# Run ON RunPod after train — fp16 merge + bf16 GGUF + q4_k_m (reliable path)
set -euo pipefail
cd /workspace/jett
source .venv/bin/activate

CKPT="${JETT_CHECKPOINT:-outputs/r6/checkpoint-250}"
CLEAN="${JETT_CLEAN:-models/r6/clean}"
GGUF_BF16="${JETT_GGUF_BF16:-models/r6/jett-r6.BF16.gguf}"
GGUF_OUT="${JETT_GGUF_OUT:-models/r6/jett-r6-q4_k_m.gguf}"
MODEL="ibm-granite/granite-3.3-2b-instruct"

python3 << PYEOF
import os, json, shutil, subprocess
os.environ["UNSLOTH_DISABLE_VERSION_CHECK"] = "1"
from unsloth import FastLanguageModel
from peft import PeftModel

CKPT, CLEAN = "$CKPT", "$CLEAN"
GGUF_BF16, GGUF_OUT = "$GGUF_BF16", "$GGUF_OUT"
MODEL = "$MODEL"

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
subprocess.check_call([
    "python", "/root/.unsloth/llama.cpp/unsloth_convert_hf_to_gguf.py",
    CLEAN, "--outfile", GGUF_BF16, "--outtype", "bf16"])
subprocess.check_call([
    "/root/.unsloth/llama.cpp/llama-quantize", GGUF_BF16, GGUF_OUT, "q4_k_m"])
print("[+] GGUF:", GGUF_OUT)
PYEOF
