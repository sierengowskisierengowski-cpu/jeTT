# Training & Fine-Tuning Pipeline

This document describes the end-to-end workflow for generating training data, fine-tuning IBM Granite 3.3 2B Instruct, and exporting the resulting model to an optimized GGUF format.

All training scripts live under `training/`. Dataset generation pipelines are fully automated via the `scripts/run_round*_pipeline.sh` scripts.

---

## Prerequisites

```bash
pip install torch transformers trl accelerate peft bitsandbytes unsloth
```

A CUDA GPU is required for practical training. Recommended: NVIDIA A40 or RTX 3090 with at least 24 GB VRAM. RunPod cloud training scripts are provided under `scripts/runpod_*.sh`.

---

## Pipeline overview

The current production pipeline is **Round 7**. Each round adds new threat categories and widens MITRE ATT&CK coverage:

| Round | Script | Key additions |
|---|---|---|
| 4 | `scripts/run_round4_pipeline.sh` | Core threat / legit-scary / ambiguous buckets |
| 5 | `scripts/run_round5_pipeline.sh` | Stretch MITRE (lateral, ransomware, impair, webshell) |
| 6 | `scripts/run_round6_pipeline.sh` | Supply chain, LOLbins, own-stack, C2 variety |
| 7 | `scripts/run_round7_pipeline.sh` | Eval-driven reinforcement, threat depth |

To run the full Round 7 pipeline:

```bash
bash scripts/run_round7_pipeline.sh
```

This generates `data/jett_training_v7.json` (≈65 k pairs) and `tests/guard_eval_v7.jsonl`.

---

## Step-by-step (manual)

### Step 1 — Download & convert threat intelligence

```bash
python3 training/intel/download_intelligence.py
python3 training/intel/convert_intelligence.py
python3 training/intel/convert_knowledge_base.py
```

Downloads MITRE ATT&CK, CVEs, GTFOBins, LOLBAS, Sigma rules, YARA rules, Hak5 payloads, and converts them to training pairs.

### Step 2 — Generate data buckets

```bash
# Bucket A — core threats
python3 training/generators/generate_threats.py --count 1800 --out data/bucket_a_threats.jsonl

# Bucket B — legitimate-but-scary (false positive reduction)
python3 training/generators/generate_false_positive_armor.py --count 2500 --out data/bucket_b_scary_legit.jsonl

# Bucket C — ambiguous pairs (contextual reasoning)
python3 training/generators/generate_ambiguous_pairs.py --pairs 800 --out data/bucket_c_ambiguous.jsonl

# Bucket D — stretch MITRE (lateral movement, ransomware, defence impairment)
python3 training/generators/generate_stretch_threats.py --count 600 --out data/bucket_d_stretch.jsonl

# Optional additional buckets (supply chain, LOLbins, C2, own-stack)
python3 training/generators/generate_supply_chain.py --count 400 --out data/bucket_e_supply_chain.jsonl
python3 training/generators/generate_lolbins.py --count 400 --out data/bucket_f_lolbins.jsonl
python3 training/generators/generate_own_stack.py --count 350 --out data/bucket_g_own_stack.jsonl
python3 training/generators/generate_c2_variety.py --count 400 --out data/bucket_h_c2_variety.jsonl
```

### Step 3 — Stratified merge

```bash
python3 training/merge/stratified_merge.py \
  --total 65000 --eval-frac 0.05 \
  --out data/jett_training_v7.json \
  --eval-out tests/guard_eval_v7.jsonl \
  --coverage-out data/mitre_coverage_v7.json \
  --buckets data/bucket_*.jsonl
```

The merge script:
- Deduplicates on input hash
- Stratifies by scenario bucket (not raw label)
- Carves off a held-out eval set
- Converts to the Alpaca shape expected by `train_core_weights.py`
- Emits a MITRE technique coverage report

### Step 4 — MITRE coverage gate

```bash
python3 training/coverage/zero_gate.py \
  --coverage data/mitre_coverage_v7.json \
  --matrix training/coverage/matrix.yaml
```

Fails (exit 1) if any required MITRE technique falls below the minimum count defined in `training/coverage/matrix.yaml`. Set `JETT_GATE_WARN=1` to warn-only.

### Step 5 — Inject evasion mutations (optional)

```bash
python3 training/generators/mutate_matrix.py
```

Adds polymorphic evasion variants to improve detection of bypass techniques.

### Step 6 — Train

```bash
JETT_TRAINING_DATA=data/jett_training_v7.json python3 training/train_core_weights.py
```

Trains IBM Granite 3.3 2B with LoRA adapters via Unsloth/SFTTrainer.
Recommended: RunPod A40 GPU, 200–250 training steps.

### Step 7 — Eval

```bash
python3 training/eval_guard.py \
  --eval tests/guard_eval_v7.jsonl \
  --jett target/release/jeTT \
  --failures-out data/eval_failures_r7.jsonl
```

### Step 8 — Export to GGUF

```bash
# Merge LoRA adapter into base model
python3 scripts/export_gguf.py

# Or on RunPod
bash scripts/export_gguf_pod.sh
```

The resulting GGUF (`models/jeTT-q4.gguf`, ~1.4 GB) is set via `JETT_MODEL` at runtime.

---

## RunPod one-shot pipeline

To generate Round 7 data locally and then launch training + export on RunPod in one command:

```bash
# Configure your pod connection
export RUNPOD_HOST=<your-pod-ip>
export RUNPOD_PORT=<ssh-port>
bash scripts/runpod_launch_all.sh
```

Monitor progress:
```bash
ssh root@<pod>:<port> 'tail -f /workspace/jett/full_pipeline.log'
```

Pull the finished GGUF:
```bash
bash scripts/runpod_pull_models.sh
```

---

## Training data layout

| Path | Contents | Committed? |
|---|---|---|
| `data/bucket_*.jsonl` | Per-bucket generator output | No (gitignored) |
| `data/jett_training_v*.json` | Final training sets | No (gitignored) |
| `data/mitre_coverage_v*.json` | Coverage reports | No (gitignored) |
| `tests/guard_eval_v*.jsonl` | Held-out eval sets | **Yes** |
| `training/coverage/matrix.yaml` | Required MITRE techniques | **Yes** |

---

## Dataset stats (Round 7)

- Total pairs: ~65,000
- ALLOW pairs: ~30%
- QUARANTINE/KILL pairs: ~47%
- Ambiguous pairs: ~23%
- MITRE ATT&CK techniques covered: 20+ required, tracked via coverage gate
- Sources: MITRE ATT&CK, CVEs, GTFOBins, LOLBAS, OTX, ExploitDB, MalwareBazaar, Sigma, YARA, red-team tools, Hak5 payloads, supply-chain scenarios

