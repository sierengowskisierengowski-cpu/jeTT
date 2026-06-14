#!/usr/bin/env bash
# jeTT r6+ — surgical refine FROM r6 LoRA: only r6 eval misses + v6 replay (no full retrain).
set -euo pipefail
cd "$(dirname "$0")/.."

FAIL_R6="${JETT_FAIL_R6:-data/eval_failures_r6.jsonl}"
REPLAY="${JETT_REPLAY:-data/jett_training_v6.json}"

if [[ ! -f "$FAIL_R6" ]]; then
  echo "[!] missing $FAIL_R6 — run eval on r6 first:"
  echo "    JETT_BIN=target/release/jeTT python3 eval_guard.py --eval tests/guard_eval_v6.jsonl --failures-out $FAIL_R6"
  exit 1
fi

if [[ ! -f "$REPLAY" ]]; then
  echo "[!] missing $REPLAY — run scripts/run_round6_pipeline.sh first"
  exit 1
fi

echo "[1/3] Re-eval r6 to refresh failure file (optional sanity)"
JETT_BIN="${JETT_BIN:-target/release/jeTT}"
if [[ -x "$JETT_BIN" ]]; then
  python3 eval_guard.py --eval tests/guard_eval_v6.jsonl --jett "$JETT_BIN" \
    --failures-out "$FAIL_R6" || true
  FAIL_N=$(wc -l < "$FAIL_R6")
  echo "    r6 failures: $FAIL_N (ship bar gaps to fix)"
else
  echo "    skip live eval (no jeTT binary)"
fi

echo "[2/3] Build surgical r6+ dataset (failures + v6 replay)"
python3 build_r6plus_dataset.py \
  --failures "$FAIL_R6" \
  --replay-from "$REPLAY" \
  --replay-count "${JETT_R6PLUS_REPLAY:-3000}" \
  --variants "${JETT_R6PLUS_VARIANTS:-8}" \
  --out data/jett_training_r6plus.json

echo "[3/3] Summary"
python3 - <<'PY'
import json
train = len(json.load(open("data/jett_training_r6plus.json")))
fail_n = sum(1 for _ in open("data/eval_failures_r6.jsonl") if _.strip())
print(f"  r6 eval misses:  {fail_n}")
print(f"  r6+ train rows:  {train}")
print(f"  eval holdout:    guard_eval_v6.jsonl (same bar — must beat 92.1%)")
PY

echo "[+] r6+ ready: data/jett_training_r6plus.json"
echo "    Pod: needs outputs/r6/checkpoint-250 first, then refine with JETT_LORA_ADAPTER"
