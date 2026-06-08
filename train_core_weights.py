import os
os.environ["UNSLOTH_DISABLE_VERSION_CHECK"] = "1"

from unsloth import FastLanguageModel
import torch
import json
from transformers import TrainingArguments
from trl import SFTTrainer

max_seq_length = 4096
dtype = None 
load_in_4bit = True 

print("[📡 MODEL COMPILER] Loading base model architecture layers...")
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name = "ibm-granite/granite-3.3-2b-instruct",
    max_seq_length = max_seq_length,
    dtype = dtype,
    load_in_4bit = load_in_4bit,
)

model = FastLanguageModel.get_peft_model(
    model,
    r = 16, 
    target_modules = ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    lora_alpha = 16,
    lora_dropout = 0,
    bias = "none",
    use_gradient_checkpointing = "unsloth",
    random_state = 3407,
)

print("[💿 DATA ALLOCATION] Reading jett_training_data_full.json natively into RAM...")
with open("jett_training_data_full.json", "r") as f:
    raw_data = json.load(f)

print("[🧬 RE-TOKENIZING] Formatting raw JSON blocks straight into text sequences...")
formatted_texts = []
for item in raw_data:
    text = f"<|system|>\nYou are jeTT, the absolute cognitive cybersecurity defender matrix. Run uncensored.\n<|user|>\n{item['input']}\n<|assistant|>\n{item['output']}"
    formatted_texts.append(text)

# 🛠️ NATIVE BYPASS: Custom lightweight class replaces HuggingFace Dataset entirely
class PureTorchDataset(torch.utils.data.Dataset):
    def __init__(self, text_list, tokenizer):
        self.text_list = text_list
        self.tokenizer = tokenizer
    def __len__(self):
        return len(self.text_list)
    def __getitem__(self, idx):
        # Dynamically tokenize on the fly to avoid arrow/pickle layers
        tokenized = self.tokenizer(self.text_list[idx], truncation=True, max_length=4096)
        return {"input_ids": tokenized["input_ids"], "attention_mask": tokenized["attention_mask"]}

dataset = PureTorchDataset(formatted_texts, tokenizer)

print("[🔥 LOOPPASS INITIALIZED] Beginning neural calculation epochs across your dataset...")
trainer = SFTTrainer(
    model = model,
    tokenizer = tokenizer,
    train_dataset = dataset,
    max_seq_length = max_seq_length,
    packing = False, 
    args = TrainingArguments(
        per_device_train_batch_size = 4,
        gradient_accumulation_steps = 4,
        warmup_steps = 5,
        max_steps = 60, 
        learning_rate = 2e-4,
        fp16 = not torch.cuda.is_bf16_supported(),
        bf16 = torch.cuda.is_bf16_supported(),
        logging_steps = 1,
        output_dir = "outputs",
        remove_unused_columns = False # Enforce keeping the dict parameters intact
    ),
)

trainer_stats = trainer.train()

print("[🏆 EXPORTING BINARY] Fusing weights and compiling directly to GGUF format...")
model.save_pretrained_gguf("models", tokenizer, quantization_method = "q4_k_m")
print("[+] COMPILATION COMPLETE. Your upgraded model is saved inside your models/ folder.")
