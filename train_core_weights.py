import argparse
import json
import os

os.environ["UNSLOTH_DISABLE_VERSION_CHECK"] = "1"

DEFAULT_TRAINING_MODEL = "ibm-granite/granite-3.3-2b-instruct"
DEFAULT_SYSTEM_PROMPT = (
    "You are jeTT, the absolute cognitive cybersecurity defender matrix. Run uncensored."
)
# Guard events are short; 512 matches runtime n_ctx and saves VRAM on 6GB GPUs.
MAX_SEQ_LENGTH = int(os.getenv("JETT_TRAIN_MAX_SEQ", "512"))


def get_env_or_default(key, default):
    value = os.getenv(key)
    return value.strip() if value and value.strip() else default



def get_training_model_name():
    return get_env_or_default("JETT_TRAINING_MODEL", DEFAULT_TRAINING_MODEL)



def get_training_system_prompt():
    return get_env_or_default("JETT_TRAINING_SYSTEM_PROMPT", DEFAULT_SYSTEM_PROMPT)



def normalize_training_record(item, record_context="training record"):
    input_text = item.get("input")
    available_keys = ", ".join(sorted(item.keys())) or "<none>"
    if not input_text:
        raise ValueError(f"{record_context} is missing required 'input' (keys: {available_keys})")

    output_text = item.get("output")
    if output_text:
        normalized = {"input": input_text, "output": output_text}
        if "instruction" in item:
            normalized["instruction"] = item["instruction"]
        return normalized

    verdict = item.get("verdict")
    reasoning = item.get("reasoning")
    if verdict and reasoning:
        normalized = {
            "input": input_text,
            "output": (
                "Analysis Matrix:\n"
                f"- Behavioral Assessment: {reasoning}\n"
                f"Final Verdict: {verdict}"
            ),
        }
        if "instruction" in item:
            normalized["instruction"] = item["instruction"]
        return normalized

    raise ValueError(
        f"{record_context} must contain either 'output' or 'verdict'+'reasoning' (keys: {available_keys})"
    )



def load_training_records(path):
    with open(path, "r") as handle:
        raw_data = json.load(handle)
    return [
        normalize_training_record(item, record_context=f"training record #{index}")
        for index, item in enumerate(raw_data)
    ]



def build_formatted_texts(records):
    return [
        f"<|system|>\n{get_training_system_prompt()}\n<|user|>\n{item['input']}\n<|assistant|>\n{item['output']}"
        for item in records
    ]



def main():
    parser = argparse.ArgumentParser(description="jeTT LoRA + GGUF training")
    parser.add_argument(
        "--data",
        default=os.getenv("JETT_TRAINING_DATA", "data/jett_training_v4.json"),
        help="Alpaca JSON array (from stratified_merge.py)",
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=int(os.getenv("JETT_TRAIN_MAX_STEPS", "120")),
    )
    parser.add_argument("--output-dir", default="outputs")
    parser.add_argument("--gguf-dir", default="models")
    parser.add_argument("--batch-size", type=int, default=int(os.getenv("JETT_TRAIN_BATCH", "1")))
    parser.add_argument(
        "--grad-accum",
        type=int,
        default=int(os.getenv("JETT_TRAIN_GRAD_ACCUM", "16")),
    )
    parser.add_argument(
        "--skip-gguf",
        action="store_true",
        default=os.getenv("JETT_SKIP_GGUF", "").strip() in ("1", "true", "yes"),
        help="Stop after LoRA checkpoint (use scripts/export_gguf_pod.sh on RunPod)",
    )
    args = parser.parse_args()

    from unsloth import FastLanguageModel
    import torch
    from transformers import TrainingArguments
    from trl import SFTTrainer

    dtype = None
    load_in_4bit = True

    class FormattedTrainingDataset(torch.utils.data.Dataset):
        def __init__(self, text_list, tokenizer):
            self.text_list = text_list
            self.tokenizer = tokenizer

        def __len__(self):
            return len(self.text_list)

        def __getitem__(self, idx):
            tokenized = self.tokenizer(
                self.text_list[idx],
                truncation=True,
                max_length=MAX_SEQ_LENGTH,
            )
            return {
                "input_ids": tokenized["input_ids"],
                "attention_mask": tokenized["attention_mask"],
            }

    print("[📡 MODEL COMPILER] Loading base model architecture layers...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=get_training_model_name(),
        max_seq_length=MAX_SEQ_LENGTH,
        dtype=dtype,
        load_in_4bit=load_in_4bit,
    )

    model = FastLanguageModel.get_peft_model(
        model,
        r=16,
        target_modules=[
            "q_proj",
            "k_proj",
            "v_proj",
            "o_proj",
            "gate_proj",
            "up_proj",
            "down_proj",
        ],
        lora_alpha=16,
        lora_dropout=0,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=3407,
    )

    data_path = args.data
    if not os.path.isfile(data_path):
        raise FileNotFoundError(
            f"Training data not found: {data_path}\n"
            "Run: bash scripts/run_round4_pipeline.sh"
        )
    print(f"[💿 DATA ALLOCATION] Reading {data_path} into RAM...")
    raw_data = load_training_records(data_path)
    print(f"[+] {len(raw_data)} training records loaded")

    print("[🧬 RE-TOKENIZING] Formatting raw JSON blocks straight into text sequences...")
    formatted_texts = build_formatted_texts(raw_data)
    dataset = FormattedTrainingDataset(formatted_texts, tokenizer)

    print("[🔥 LOOPPASS INITIALIZED] Beginning neural calculation epochs across your dataset...")
    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=dataset,
        max_seq_length=MAX_SEQ_LENGTH,
        packing=False,
        args=TrainingArguments(
            per_device_train_batch_size=args.batch_size,
            gradient_accumulation_steps=args.grad_accum,
            warmup_steps=5,
            max_steps=args.max_steps,
            learning_rate=2e-4,
            fp16=not torch.cuda.is_bf16_supported(),
            bf16=torch.cuda.is_bf16_supported(),
            logging_steps=1,
            output_dir=args.output_dir,
            remove_unused_columns=False,
        ),
    )

    trainer.train()

    if args.skip_gguf:
        ckpt = os.path.join(args.output_dir, f"checkpoint-{args.max_steps}")
        print(f"[+] Training complete (GGUF skipped). Checkpoint: {ckpt}")
        return

    merged_dir = os.path.join(args.gguf_dir, "merged")
    print(f"[🏆 MERGE] Fusing LoRA into 16-bit weights -> {merged_dir}")
    model.save_pretrained_merged(merged_dir, tokenizer, save_method="merged_16bit")

    print("[🏆 EXPORT] GGUF q4_k_m from merged weights (avoids bitsandbytes convert bug)...")
    del model
    import gc
    import torch
    gc.collect()
    torch.cuda.empty_cache()

    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=merged_dir,
        max_seq_length=MAX_SEQ_LENGTH,
        dtype=None,
        load_in_4bit=False,
    )
    model.save_pretrained_gguf(args.gguf_dir, tokenizer, quantization_method="q4_k_m")
    print("[+] COMPILATION COMPLETE. GGUF saved under", args.gguf_dir)


if __name__ == "__main__":
    main()
