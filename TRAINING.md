# Training & Fine-Tuning Pipeline for jeTT

This document outlines the end-to-end dataset generation, conversion, and fine-tuning workflow for jeTT. The pipeline trains IBM Granite 3.3 2B Instruct on advanced cybersecurity signatures and exports the resulting adapters into an optimized quantized GGUF format.

## Prerequisites

    pip install torch transformers trl accelerate peft bitsandbytes

GPU with CUDA required for practical training performance.

## Step 1: Generate Base Dataset

    python generate_training_data.py

Produces jett_training_data.json with baseline attack/benign scenarios.

## Step 2: Download & Convert Intelligence

    python download_intelligence.py
    python convert_intelligence.py
    python convert_knowledge_base.py

Downloads red/blue team repos, MITRE ATT&CK, CVEs, GTFOBins, LOLBAS, Sigma rules, YARA rules, Hak5 payloads and converts them to training pairs.

## Step 3: Consolidate Dataset

    python jett_extended_training.py

Merges all sources into jett_training_data_full.json.

## Step 4: Inject Evasion Mutations

    python mutate_matrix.py

Adds polymorphic evasion variants to improve detection of bypass techniques.

## Step 5: Balance ALLOW/QUARANTINE

    python generate_allow_dataset.py

Generates balanced ALLOW training pairs for trusted GowskiNet processes to reduce false positives.

## Step 6: Final Merge

    python merge_final.py

Produces the final training dataset.

## Step 7: Train

    python train_core_weights.py

Trains IBM Granite 3.3 2B with LoRA adapters via SFTTrainer. Recommended: RunPod A40 GPU, 120-180 steps.

## Step 8: Convert to GGUF

    # Merge LoRA adapter
    python merge_lora.py

    # Convert to f16
    python convert_hf_to_gguf.py models/jeTT-merged --outfile models/jeTT-f16.gguf --outtype f16

    # Quantize to Q4_K_M
    llama-quantize models/jeTT-f16.gguf models/jeTT-q4.gguf Q4_K_M

## Output

Final model: models/jeTT-q4.gguf (~1.4GB)
Set JETT_MODEL=/path/to/jeTT-q4.gguf before running jeTT.

## Dataset Stats (Round 3)

- Total pairs: 1,578,207
- ALLOW pairs: ~533,000
- QUARANTINE pairs: ~533,000
- Sources: MITRE ATT&CK, CVEs, GTFOBins, LOLBAS, OTX, ExploitDB, MalwareBazaar, Sigma, YARA, red team tools, Hak5 payloads
