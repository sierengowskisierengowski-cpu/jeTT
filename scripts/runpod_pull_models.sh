#!/usr/bin/env bash
# Pull trained GGUFs from RunPod to local models/
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${RUNPOD_HOST:-194.68.245.125}"
PORT="${RUNPOD_PORT:-22146}"
USER="${RUNPOD_USER:-root}"
REMOTE="${RUNPOD_DIR:-/workspace/jett}"
SSH_OPTS=(-o StrictHostKeyChecking=no -p "$PORT")

mkdir -p models

for round in ${JETT_PULL_ROUNDS:-r6 r7}; do
  remote="models/${round}/jett-${round}-q4_k_m.gguf"
  local="models/jett-${round}-q4_k_m.gguf"
  echo "[pull] $USER@$HOST:$REMOTE/$remote -> $local"
  if scp "${SSH_OPTS[@]}" "$USER@$HOST:$REMOTE/$remote" "$local"; then
    ls -lh "$local"
  else
    echo "[!] missing on pod: $remote"
  fi
done

echo "[+] Pull complete. Deploy: export JETT_MODEL=$PWD/models/jett-r7-q4_k_m.gguf"
