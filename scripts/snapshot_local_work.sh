#!/usr/bin/env bash
# Snapshot all local jeTT work (including gitignored data/) into backups/
set -euo pipefail
cd "$(dirname "$0")/.."

STAMP="$(date +%Y%m%d-%H%M%S)"
DEST="backups/jett-snapshot-${STAMP}"
mkdir -p "$DEST"

echo "[1/4] git tracked changes list"
git status -sb > "$DEST/git-status.txt"
git diff > "$DEST/git-diff.patch" || true
git ls-files --others --exclude-standard > "$DEST/git-untracked.txt"

echo "[2/4] copy data artifacts (gitignored but required for r9/r10)"
if [[ -d data ]]; then
  mkdir -p "$DEST/data"
  for f in data/eval_failures_*.jsonl data/jett_training_v*.json data/mitre_coverage_v*.json \
    data/bucket_j_eval_reinforce_r9.jsonl data/bucket_f_lolbins_r9.jsonl \
    data/bucket_d3_stretch_r9.jsonl; do
    [[ -f "$f" ]] && cp -a "$f" "$DEST/data/"
  done
fi

echo "[3/4] copy tests eval holdouts"
mkdir -p "$DEST/tests"
cp -a tests/guard_eval_v9.jsonl "$DEST/tests/" 2>/dev/null || true

echo "[4/4] manifest"
{
  echo "jeTT snapshot $STAMP"
  echo "repo: $(pwd)"
  echo "branch: $(git branch --show-current)"
  echo "head: $(git rev-parse --short HEAD)"
  echo ""
  echo "=== modified tracked ==="
  git diff --name-only
  echo ""
  echo "=== untracked ==="
  cat "$DEST/git-untracked.txt"
  echo ""
  echo "=== data copied ==="
  ls -la "$DEST/data" 2>/dev/null || true
  echo ""
  echo "=== release binaries (not copied — rebuild with cargo) ==="
  ls -lh target/release/jeTT target/release/jett-daemon 2>/dev/null || echo "  (not built)"
  echo ""
  echo "=== models on disk (not copied — large GGUFs) ==="
  ls -lh models/jett-r*.gguf 2>/dev/null || echo "  (none)"
} > "$DEST/MANIFEST.txt"

tar -czf "backups/jett-snapshot-${STAMP}.tar.gz" -C backups "jett-snapshot-${STAMP}"
echo "[+] $DEST"
echo "[+] backups/jett-snapshot-${STAMP}.tar.gz"
