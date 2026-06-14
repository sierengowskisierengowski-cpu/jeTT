#!/usr/bin/env bash
# Create a GitHub release from dist/ tarballs (optional — needs gh auth).
#
# Usage:
#   bash scripts/build_release.sh          # or JETT_CPU_ONLY=1 for CI-like assets
#   bash scripts/create_github_release.sh v0.1.0
#
# Options via env:
#   JETT_RELEASE_DRAFT=1     create draft release
#   JETT_RELEASE_NOTES=file  append notes from file
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TAG="${1:-}"
DIST="${JETT_RELEASE_DIR:-$ROOT/dist}"

if [[ -z "$TAG" ]]; then
  VERSION="$(grep '^version' Cargo.toml | head -1 | sed -E 's/.*"([^"]+)".*/\1/')"
  TAG="v${VERSION}"
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "[!] gh cli not found — install from https://cli.github.com/ or upload dist/ manually" >&2
  exit 1
fi

shopt -s nullglob
ASSETS=( "$DIST"/*.tar.gz "$DIST"/*.sha256 "$DIST"/BUILD-NOTES.txt )
if ((${#ASSETS[@]} == 0)); then
  echo "[!] no assets in $DIST — run scripts/build_release.sh first" >&2
  exit 1
fi

NOTES="jeTT release ${TAG}

Built from $(git rev-parse --short HEAD 2>/dev/null || echo unknown).

Model GGUF is not bundled. See INSTALL.md and scripts/deploy_walkthrough.sh."

if [[ -n "${JETT_RELEASE_NOTES:-}" && -f "$JETT_RELEASE_NOTES" ]]; then
  NOTES="${NOTES}

$(cat "$JETT_RELEASE_NOTES")"
fi

DRAFT_FLAG=()
if [[ "${JETT_RELEASE_DRAFT:-0}" == "1" ]]; then
  DRAFT_FLAG=(--draft)
fi

echo "[+] creating release ${TAG} with ${#ASSETS[@]} asset(s)"
gh release create "$TAG" "${ASSETS[@]}" \
  --title "jeTT ${TAG}" \
  --notes "$NOTES" \
  "${DRAFT_FLAG[@]}"

echo "[+] https://github.com/$(gh repo view --json nameWithOwner -q .nameWithOwner)/releases/tag/${TAG}"
