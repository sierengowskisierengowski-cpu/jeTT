#!/bin/bash
# deploy_maze.sh — OPTIONAL/EXPERIMENTAL deception layer.
#
# This script is NOT part of the core jeTT runtime.  It sets up a volatile
# tmpfs-backed honeypot directory tree.  Use only in controlled environments.
#
# Usage:
#   sudo MAZE_REPO_ROOT=/path/to/jeTT ./internal/deception/deploy_maze.sh
#
# MAZE_REPO_ROOT defaults to the directory two levels above this script.

set -euo pipefail

# Ensure root access to manipulate the kernel namespace matrix
if [ "$EUID" -ne 0 ]; then
  echo "[!] Hades requires sudo privileges to initialize the illusion matrix."
  exit 1
fi

# Resolve the repository root relative to this script's location.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${MAZE_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"

MAZE_DIR="$REPO_ROOT/internal/deception/shadow_layer"
mkdir -p "$MAZE_DIR"

echo "[🛡️ STAGE 1] Spawning memory-backed Shadow Honeynet..."

# Mount a high-velocity, volatile RAM disk directly to the honeypot layer
mount -t tmpfs -o size=64M tmpfs "$MAZE_DIR"

# Populate the maze with deceptive mirror targets
echo "Initializing core illusion file nodes..."
mkdir -p "$MAZE_DIR/Documents" "$MAZE_DIR/Downloads" "$MAZE_DIR/System_Configs"
echo "CONFIDENTIAL_PASSPHRASES_2026.txt" > "$MAZE_DIR/Documents/secrets.txt"

# THE REFLECTION LOGIC: Loop any automated writing actions back to the sender
# NOTE: This creates a symlink to /proc/self/fd/1 (stdout) intentionally.
ln -sf /proc/self/fd/1 "$MAZE_DIR/System_Configs/output_loop"

echo "[+] SATELLITE DEFENSE ACTIVE: Volatile RAM maze locked and loaded."
