#!/bin/bash
# Ensure root access to manipulate the kernel namespace matrix
if [ "$EUID" -ne 0 ]; then
  echo "[!] Hades requires sudo privileges to initialize the illusion matrix."
  exit 1
fi

MAZE_DIR="/home/cosmic/cerberus/internal/deception/shadow_layer"
mkdir -p "$MAZE_DIR"

echo "[🛡️ STAGE 1] Spawning memory-backed Shadow Honeynet..."

# Mount a high-velocity, volatile RAM disk directly to the honeypot layer
mount -t tmpfs -o size=64M tmpfs "$MAZE_DIR"

# Populate the maze with deceptive mirror targets
echo "Initializing core illusion file nodes..."
mkdir -p "$MAZE_DIR/Documents" "$MAZE_DIR/Downloads" "$MAZE_DIR/System_Configs"
echo "CONFIDENTIAL_PASSPHRASES_2026.txt" > "$MAZE_DIR/Documents/secrets.txt"

# THE REFLECTION LOGIC: Loop any automated writing actions back to the sender
ln -sf /proc/self/fd/1 "$MAZE_DIR/System_Configs/output_loop"

echo "[+] SATELLITE DEFENSE ACTIVE: Volatile RAM maze locked and loaded."
