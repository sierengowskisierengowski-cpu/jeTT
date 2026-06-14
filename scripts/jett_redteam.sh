#!/usr/bin/env bash
# Unified jeTT red-team mode: ART smoke + adversarial eval preflight + enforce smoke check.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PASS=0
FAIL=0
PHASE=0

run_phase() {
  local name="$1"
  shift
  PHASE=$((PHASE + 1))
  echo ""
  echo "═══════════════════════════════════════════"
  echo " Phase ${PHASE}: ${name}"
  echo "═══════════════════════════════════════════"
  if "$@"; then
    echo "[OK] ${name}"
    PASS=$((PASS + 1))
  else
    echo "[FAIL] ${name}"
    FAIL=$((FAIL + 1))
  fi
}

usage() {
  cat <<'EOF'
Usage: scripts/jett_redteam.sh [--skip-adversarial | --skip-enforce]

Unified red-team validation for jeTT:
  1. art_jett_smoke.sh          — safe ART learn-mode atoms
  2. run_adversarial_eval.sh    — adversarial eval script present (GPU eval when daemon stopped)
  3. enforce_smoke.sh --enforce-check — enforce dry-run preflight

Options:
  --skip-adversarial   Skip adversarial eval phase
  --skip-enforce       Skip enforce smoke preflight

Also available as: jett redteam

EOF
}

SKIP_ADV=0
SKIP_ENF=0
for arg in "$@"; do
  case "$arg" in
    -h|--help) usage; exit 0 ;;
    --skip-adversarial) SKIP_ADV=1 ;;
    --skip-enforce) SKIP_ENF=1 ;;
  esac
done

echo "jeTT unified red-team mode"
echo "Repo: ${ROOT}"

run_phase "ART learn-mode smoke" bash "${ROOT}/scripts/art_jett_smoke.sh"

if [[ "$SKIP_ADV" -eq 0 ]]; then
  if systemctl is-active --quiet jett-daemon 2>/dev/null; then
    echo "[WARN] jett-daemon running — adversarial eval needs GPU; checking script only"
    run_phase "Adversarial eval script" test -x "${ROOT}/scripts/run_adversarial_eval.sh"
  else
    run_phase "Adversarial eval preflight" bash "${ROOT}/scripts/run_adversarial_eval.sh" --help >/dev/null 2>&1 \
      || run_phase "Adversarial eval script" test -x "${ROOT}/scripts/run_adversarial_eval.sh"
  fi
else
  echo "[SKIP] adversarial eval"
fi

if [[ "$SKIP_ENF" -eq 0 ]]; then
  run_phase "Enforce smoke preflight" bash "${ROOT}/scripts/enforce_smoke.sh" --enforce-check
else
  echo "[SKIP] enforce smoke"
fi

echo ""
echo "═══════════════════════════════════════════"
echo " Red-team summary: ${PASS} passed, ${FAIL} failed"
echo "═══════════════════════════════════════════"

if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
