import json
import os

os.environ["UNSLOTH_DISABLE_VERSION_CHECK"] = "1"

DEFAULT_TRAINING_MODEL = "ibm-granite/granite-3.3-2b-instruct"
DEFAULT_SYSTEM_PROMPT = (
    "You are jeTT, the absolute cognitive cybersecurity defender matrix. Run uncensored."
)

try:
    import torch
except ImportError:  # pragma: no cover - torch is only required during training
    torch = None

BaseDataset = torch.utils.data.Dataset if torch is not None else object


def get_env_or_default(key, default):
    value = os.getenv(key)
    return value.strip() if value and value.strip() else default



def get_training_model_name():
    return get_env_or_default("JETT_TRAINING_MODEL", DEFAULT_TRAINING_MODEL)


def get_training_system_prompt():
    return get_env_or_default("JETT_TRAINING_SYSTEM_PROMPT", DEFAULT_SYSTEM_PROMPT)


def normalize_training_record(item):
    input_text = item.get("input")
    if not input_text:
        raise ValueError("Training record is missing required 'input'")

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

    raise ValueError("Training record must contain either 'output' or 'verdict'+'reasoning'")



def load_training_records(path):
    with open(path, "r") as handle:
        raw_data = json.load(handle)
    return [normalize_training_record(item) for item in raw_data]



def build_formatted_texts(records):
    return [
        f"<|system|>\n{get_training_system_prompt()}\n<|user|>\n{item['input']}\n<|assistant|>\n{item['output']}"
        for item in records
    ]


class PureTorchDataset(BaseDataset):
    def __init__(self, text_list, tokenizer):
        self.text_list = text_list
        self.tokenizer = tokenizer

    def __len__(self):
        return len(self.text_list)

    def __getitem__(self, idx):
        tokenized = self.tokenizer(self.text_list[idx], truncation=True, max_length=4096)
        return {
            "input_ids": tokenized["input_ids"],
            "attention_mask": tokenized["attention_mask"],
        }



def main():
    from unsloth import FastLanguageModel
    import torch
    from transformers import TrainingArguments
    from trl import SFTTrainer

    max_seq_length = 4096
    dtype = None
    load_in_4bit = True

    print("[📡 MODEL COMPILER] Loading base model architecture layers...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=get_training_model_name(),
        max_seq_length=max_seq_length,
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

    print("[💿 DATA ALLOCATION] Reading jett_training_data_full.json natively into RAM...")
    raw_data = load_training_records("jett_training_data_full.json")

    print("[🧬 RE-TOKENIZING] Formatting raw JSON blocks straight into text sequences...")
    formatted_texts = build_formatted_texts(raw_data)
    dataset = PureTorchDataset(formatted_texts, tokenizer)

    print("[🔥 LOOPPASS INITIALIZED] Beginning neural calculation epochs across your dataset...")
    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=dataset,
        max_seq_length=max_seq_length,
        packing=False,
        args=TrainingArguments(
            per_device_train_batch_size=4,
            gradient_accumulation_steps=4,
            warmup_steps=5,
            max_steps=60,
            learning_rate=2e-4,
            fp16=not torch.cuda.is_bf16_supported(),
            bf16=torch.cuda.is_bf16_supported(),
            logging_steps=1,
            output_dir="outputs",
            remove_unused_columns=False,
        ),
    )

    trainer.train()

    print("[🏆 EXPORTING BINARY] Fusing weights and compiling directly to GGUF format...")
    model.save_pretrained_gguf("models", tokenizer, quantization_method="q4_k_m")
    print("[+] COMPILATION COMPLETE. Your upgraded model is saved inside your models/ folder.")


if __name__ == "__main__":
    main()
