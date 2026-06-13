#!/usr/bin/env bash
# Poll RunPod train log until GGUF export completes or job errors.
set -euo pipefail

HOST="${RUNPOD_HOST:-194.68.245.118}"
PORT="${RUNPOD_PORT:-22097}"
ROUND="${JETT_WATCH_ROUND:-r9}"
REMOTE="${RUNPOD_DIR:-/workspace/jett}"
LOG="${REMOTE}/train_${ROUND}.log"
SSH="ssh -o StrictHostKeyChecking=no -p $PORT root@$HOST"
INTERVAL="${JETT_WATCH_INTERVAL:-60}"

echo "Watching $LOG on $HOST:$PORT (every ${INTERVAL}s)"
echo "Ctrl+C to stop watching (training continues on pod)"

while true; do
  snippet="$($SSH "tail -8 '$LOG' 2>/dev/null" || echo "[no log yet]")"
  gpu="$($SSH "nvidia-smi --query-gpu=utilization.gpu,memory.used --format=csv,noheader 2>/dev/null" || true)"
  echo ""
  echo "=== $(date -Is) gpu: ${gpu:-n/a} ==="
  echo "$snippet"

  if echo "$snippet" | rg -q 'COMPILATION COMPLETE|full pipeline done'; then
    echo ""
    echo "[+] Training/export complete for $ROUND"
    echo "    RUNPOD_HOST=$HOST RUNPOD_PORT=$PORT bash scripts/post_r9_workflow.sh"
    exit 0
  fi
  if echo "$snippet" | rg -qi 'traceback|error:|failed'; then
    echo ""
    echo "[!] Possible error in log — check: $SSH 'tail -50 $LOG'"
    exit 1
  fi
  sleep "$INTERVAL"
done
