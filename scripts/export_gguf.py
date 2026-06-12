#!/usr/bin/env python3
"""Export jeTT LoRA checkpoint to GGUF (standalone, post-train)."""
import os
import sys

os.environ["UNSLOTH_DISABLE_VERSION_CHECK"] = "1"

CHECKPOINT = os.getenv("JETT_CHECKPOINT", "outputs/checkpoint-200")
GGUF_DIR = os.getenv("JETT_GGUF_DIR", "models")
MODEL = os.getenv("JETT_TRAINING_MODEL", "ibm-granite/granite-3.3-2b-instruct")
MAX_SEQ = int(os.getenv("JETT_TRAIN_MAX_SEQ", "512"))

from unsloth import FastLanguageModel

print(f"[+] loading base {MODEL} + adapter {CHECKPOINT}")
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name=MODEL,
    max_seq_length=MAX_SEQ,
    dtype=None,
    load_in_4bit=True,
)
model.load_adapter(CHECKPOINT)
print(f"[+] merging and exporting q4_k_m -> {GGUF_DIR}/")
model.save_pretrained_merged(f"{GGUF_DIR}/merged", tokenizer, save_method="merged_16bit")
model.save_pretrained_gguf(GGUF_DIR, tokenizer, quantization_method="q4_k_m")
print("[+] COMPILATION COMPLETE")
