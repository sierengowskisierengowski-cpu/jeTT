#!/usr/bin/env bash
# jeTT Round 9 — live learn-mode FPs + r8 eval misses → v9 training set.
set -euo pipefail
cd "$(dirname "$0")/.."

TOTAL="${JETT_TRAIN_TOTAL:-70000}"
LOG="${JETT_HARVEST_LOG:-/var/log/jett/jett.log}"
FAIL_MERGED="${JETT_FAIL_MERGED:-data/eval_failures_r9_merged.jsonl}"

echo "[0/5] Harvest live learn-mode false positives"
python3 scripts/harvest_learn_log.py \
  --log "$LOG" \
  --out data/eval_failures_live_r9.jsonl \
  --merge-r8 data/eval_failures_r8.jsonl \
  --merged-out "$FAIL_MERGED"

echo "[1/5] Reinforce merged eval misses ($FAIL_MERGED)"
python3 generate_eval_reinforce.py --failures "$FAIL_MERGED" \
  --out data/bucket_j_eval_reinforce_r9.jsonl --variants 4 --round round9

echo "[2/5] Lolbin + stretch top-up (r9-only buckets)"
python3 generate_lolbins.py --count 100 --out data/bucket_f_lolbins_r9.jsonl
python3 generate_stretch_threats.py --count 100 --out data/bucket_d3_stretch_r9.jsonl

echo "[3/5] Merge v9 (explicit buckets — no silent glob churn)"
python3 stratified_merge.py --total "$TOTAL" --eval-frac 0.05 \
  --out data/jett_training_v9.json \
  --eval-out tests/guard_eval_v9.jsonl \
  --coverage-out data/mitre_coverage_v9.json \
  --buckets \
    data/bucket_a_threats.jsonl \
    data/bucket_b_scary_legit.jsonl \
    data/bucket_c_ambiguous.jsonl \
    data/bucket_e_supply_chain.jsonl \
    data/bucket_f_lolbins.jsonl \
    data/bucket_g_own_stack.jsonl \
    data/bucket_h_c2_variety.jsonl \
    data/bucket_j_eval_reinforce_r9.jsonl \
    data/bucket_f_lolbins_r9.jsonl \
    data/bucket_d3_stretch_r9.jsonl

echo "[4/5] Coverage gate"
python3 coverage/zero_gate.py --coverage data/mitre_coverage_v9.json

echo "[5/5] Summary"
python3 - <<'PY'
import json
from pathlib import Path
live = sum(1 for _ in open("data/eval_failures_live_r9.jsonl") if _.strip())
merged = sum(1 for _ in open("data/eval_failures_r9_merged.jsonl") if _.strip())
train = len(json.load(open("data/jett_training_v9.json")))
print(f"  live FP harvest: {live}")
print(f"  merged failures: {merged}")
print(f"  training rows:   {train}")
PY

echo "[+] Round 9 ready: data/jett_training_v9.json"
