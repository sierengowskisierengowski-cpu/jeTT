#!/usr/bin/env bash
# Weekly learn-mode false-positive harvest → candidate v7 eval rows.
#
# Run manually or via cron (Sundays 03:00 example):
#   0 3 * * 0 /home/cosmic/Projects/jeTT/scripts/weekly_harvest.sh >> /var/log/jett/harvest.log 2>&1
#
# Requires: jett-daemon in learn mode, log at /var/log/jett/jett.log
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DATE="$(date +%Y%m%d)"
LOG="${JETT_LOG:-/var/log/jett/jett.log}"
OUT="${JETT_HARVEST_OUT:-$ROOT/data/learn_harvest_${DATE}.jsonl}"
MERGED="${JETT_HARVEST_MERGED:-$ROOT/data/eval_failures_merged.jsonl}"

echo "[weekly_harvest] $(date -Is) log=$LOG"

if [[ ! -f "$LOG" ]]; then
  echo "[!] missing log: $LOG (is jett-daemon running in learn mode?)" >&2
  exit 1
fi

python3 "$ROOT/scripts/harvest_learn_log.py" \
  --log "$LOG" \
  --out "$OUT" \
  --merged-out "$MERGED"

echo "[weekly_harvest] done → $OUT (merged: $MERGED)"
