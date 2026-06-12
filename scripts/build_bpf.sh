#!/usr/bin/env bash
# Compile jeTT eBPF object (requires clang, libbpf headers, internal/kernel/vmlinux.h)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VMLINUX_DIR="${VMLINUX_DIR:-$ROOT/internal/kernel}"
OUT="${JETT_BPF_OUT:-$ROOT/bpf/jett_sensor.bpf.o}"
ARCH="${BPF_ARCH:-x86}"

case "$ARCH" in
  x86)   TARGET_ARCH_FLAG=-D__TARGET_ARCH_x86 ;;
  arm64) TARGET_ARCH_FLAG=-D__TARGET_ARCH_arm64 ;;
  *)     echo "[!] unsupported BPF_ARCH=$ARCH"; exit 1 ;;
esac

echo "[bpf] compiling bpf/jett_sensor.bpf.c -> $OUT"
clang -g -O2 -target bpf $TARGET_ARCH_FLAG \
  -I"$VMLINUX_DIR" -I/usr/include \
  -c "$ROOT/bpf/jett_sensor.bpf.c" -o "$OUT"
ls -lh "$OUT"
echo "[+] BPF object ready"
