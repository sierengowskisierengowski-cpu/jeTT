#!/usr/bin/env bash
# Score r6–r9 GGUFs against held-out eval sets (substring verdict match).
set -euo pipefail
cd "$(dirname "$0")/.."

JETT_BIN="${JETT_BIN:-target/release/jeTT}"
export RUSTFLAGS="${RUSTFLAGS:--L /usr/lib -l nccl}"

if [[ ! -x "$JETT_BIN" ]]; then
  echo "[build] jeTT release binary..."
  cargo build --release
fi

run_one() {
  local model="$1" eval="$2" tag="$3"
  if [[ ! -f "$model" ]]; then
    echo "[skip] $tag — missing $model"
    return 0
  fi
  echo ""
  echo "========== $tag =========="
  echo "model: $model"
  echo "eval:  $eval"
  JETT_MODEL="$model" python3 eval_guard.py --eval "$eval" --jett "$JETT_BIN" \
    --failures-out "data/eval_failures_${tag}.jsonl"
}

run_one "${JETT_MODEL_R6:-models/jett-r6-q4_k_m.gguf}" tests/guard_eval_v6.jsonl r6
run_one "${JETT_MODEL_R6PLUS:-models/jett-r6plus-q4_k_m.gguf}" tests/guard_eval_v6.jsonl r6plus
run_one "${JETT_MODEL_R7:-models/jett-r7-q4_k_m.gguf}" tests/guard_eval_v7.jsonl r7
run_one "${JETT_MODEL_R8:-models/jett-r8-q4_k_m.gguf}" tests/guard_eval_v8.jsonl r8
run_one "${JETT_MODEL_R9:-models/jett-r9-q4_k_m.gguf}" tests/guard_eval_v9.jsonl r9

echo ""
echo "[+] eval complete — failures in data/eval_failures_r*.jsonl"
