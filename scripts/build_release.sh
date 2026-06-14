#!/usr/bin/env bash
# Build jeTT + jett-daemon release tarballs and SHA-256 sidecars.
#
# Local production (CUDA + NCCL):
#   bash scripts/build_release.sh
#
# CI / smoke (CPU-only, no GPU):
#   JETT_CPU_ONLY=1 bash scripts/build_release.sh
#
# Output: dist/jett-linux-x86_64.tar.gz, dist/jett-daemon-linux-x86_64.tar.gz (+ .sha256)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="$(grep '^version' Cargo.toml | head -1 | sed -E 's/.*"([^"]+)".*/\1/')"
OUT_DIR="${JETT_RELEASE_DIR:-$ROOT/dist}"
CPU_ONLY="${JETT_CPU_ONLY:-0}"
BUILD_EBPF="${JETT_BUILD_EBPF:-0}"
ARCH="$(uname -m)"
ARCH_LABEL="${ARCH}"
[[ "$ARCH" == "x86_64" ]] && ARCH_LABEL="x86_64"

log() {
  printf '[build_release] %s\n' "$*"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    printf '[build_release] ERROR: missing command: %s\n' "$1" >&2
    exit 1
  }
}

require_cmd cargo
require_cmd tar
require_cmd sha256sum

mkdir -p "$OUT_DIR"

FEATURES=()
CARGO_ARGS=(build --release --bin jeTT --bin jett-daemon)

if [[ "$CPU_ONLY" == "1" ]]; then
  log "CPU-only build (--no-default-features)"
  CARGO_ARGS+=(--no-default-features)
else
  log "CUDA build (default features + NCCL link flags)"
  require_cmd cmake
  export RUSTFLAGS="${RUSTFLAGS:--L /usr/lib -l nccl}"
fi

if [[ "$BUILD_EBPF" == "1" ]]; then
  log "Including ebpf feature"
  FEATURES+=(ebpf)
  if [[ -x scripts/build_bpf.sh ]]; then
    bash scripts/build_bpf.sh
  fi
fi

if ((${#FEATURES[@]})); then
  CARGO_ARGS+=(--features "$(IFS=,; echo "${FEATURES[*]}")")
fi

log "cargo ${CARGO_ARGS[*]}"
cargo "${CARGO_ARGS[@]}"

ENGINE_BIN="$ROOT/target/release/jeTT"
DAEMON_BIN="$ROOT/target/release/jett-daemon"
[[ -x "$ENGINE_BIN" ]] || { log "missing $ENGINE_BIN"; exit 1; }
[[ -x "$DAEMON_BIN" ]] || { log "missing $DAEMON_BIN"; exit 1; }

STAGING="$OUT_DIR/staging-$$"
ENGINE_STAGE="$STAGING/jett-engine"
DAEMON_STAGE="$STAGING/jett-daemon"
mkdir -p "$ENGINE_STAGE" "$DAEMON_STAGE"

install -Dm755 "$ENGINE_BIN" "$ENGINE_STAGE/jeTT"
install -Dm755 "$DAEMON_BIN" "$DAEMON_STAGE/jett-daemon"
install -Dm755 "$ROOT/jett" "$ENGINE_STAGE/jett-wrapper"
install -Dm644 "$ROOT/jett-daemon.service" "$DAEMON_STAGE/jett-daemon.service"

ENGINE_TAR="$OUT_DIR/jett-linux-${ARCH_LABEL}.tar.gz"
DAEMON_TAR="$OUT_DIR/jett-daemon-linux-${ARCH_LABEL}.tar.gz"

tar -C "$ENGINE_STAGE" -czf "$ENGINE_TAR" jeTT jett-wrapper
tar -C "$DAEMON_STAGE" -czf "$DAEMON_TAR" jett-daemon jett-daemon.service

sha256sum "$ENGINE_TAR" | awk '{print $1}' >"${ENGINE_TAR}.sha256"
sha256sum "$DAEMON_TAR" | awk '{print $1}' >"${DAEMON_TAR}.sha256"

BUILD_NOTES="$OUT_DIR/BUILD-NOTES.txt"
{
  echo "jeTT release build notes"
  echo "version: ${VERSION}"
  echo "arch: ${ARCH_LABEL}"
  echo "cpu_only: ${CPU_ONLY}"
  echo "ebpf: ${BUILD_EBPF}"
  echo "built: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo ""
  echo "engine: $(basename "$ENGINE_TAR")"
  echo "daemon: $(basename "$DAEMON_TAR")"
  echo ""
  if [[ "$CPU_ONLY" == "1" ]]; then
    echo "This is a CPU-only build suitable for CI and smoke testing."
    echo "For production GPU inference, rebuild without JETT_CPU_ONLY=1 on a CUDA host."
  else
    echo "CUDA build — verify NCCL and NVIDIA driver on target host."
  fi
} >"$BUILD_NOTES"

rm -rf "$STAGING"

log "wrote $ENGINE_TAR"
log "wrote ${ENGINE_TAR}.sha256"
log "wrote $DAEMON_TAR"
log "wrote ${DAEMON_TAR}.sha256"
log "wrote $BUILD_NOTES"
