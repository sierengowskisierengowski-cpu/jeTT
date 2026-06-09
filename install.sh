#!/usr/bin/env bash
set -euo pipefail

REPO="sierengowskisierengowski-cpu/jeTT"
INSTALL_BIN_DIR="/usr/local/bin"
INSTALL_LIB_DIR="/usr/local/lib/jett"
SERVICE_PATH="/etc/systemd/system/jett-daemon.service"

log() {
  printf '[jett-install] %s\n' "$*"
}

die() {
  printf '[jett-install] ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

if [[ "${EUID}" -ne 0 ]]; then
  die "Run as root (for example: sudo bash install.sh)"
fi

require_cmd curl
require_cmd python3
require_cmd install
require_cmd systemctl

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

RELEASE_JSON="${TMP_DIR}/release.json"
log "Fetching latest release metadata from ${REPO}"
curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" -o "${RELEASE_JSON}" || die "Unable to query latest release metadata"

TAG="$(python3 - <<'PY' "${RELEASE_JSON}"
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as fh:
    data = json.load(fh)
print(data.get('tag_name', ''))
PY
)"

[[ -n "${TAG}" ]] || die "No release tag found in latest release metadata"
log "Using release ${TAG}"

find_asset_url() {
  local kind="$1"
  python3 - <<'PY' "${RELEASE_JSON}" "${kind}"
import json, sys
release_json_path, kind = sys.argv[1], sys.argv[2]
with open(release_json_path, 'r', encoding='utf-8') as fh:
    data = json.load(fh)
assets = data.get('assets', [])

def score(name: str, target: str) -> int:
    n = name.lower()
    if n.endswith(('.sha256', '.sig', '.asc', '.txt')):
        return -1
    if 'linux' not in n:
        return -1
    if target == 'daemon':
        if 'daemon' not in n or 'jett' not in n:
            return -1
    else:
        if 'jett' not in n or 'daemon' in n:
            return -1
    s = 10
    if 'x86_64' in n or 'amd64' in n:
        s += 5
    if n.endswith(('.tar.gz', '.tgz', '.tar')):
        s += 2
    if n.endswith('.zip'):
        s += 1
    return s

best = None
for asset in assets:
    name = asset.get('name', '')
    s = score(name, kind)
    if s < 0:
        continue
    if best is None or s > best[0]:
        best = (s, asset.get('browser_download_url', ''), name)

if best:
    print(best[1])
PY
}

ENGINE_URL="$(find_asset_url engine)"
DAEMON_URL="$(find_asset_url daemon)"

[[ -n "${ENGINE_URL}" ]] || die "Could not find a Linux jeTT inference engine asset in release ${TAG}"
[[ -n "${DAEMON_URL}" ]] || die "Could not find a Linux jett-daemon asset in release ${TAG}"

extract_binary() {
  local downloaded_file="$1"
  local match_pattern="$2"
  local out_path="$3"

  if tar -tf "${downloaded_file}" >/dev/null 2>&1; then
    local unpack_dir="${TMP_DIR}/unpack-$(basename "${out_path}")"
    mkdir -p "${unpack_dir}"
    tar -xf "${downloaded_file}" -C "${unpack_dir}"
    local found
    found="$(find "${unpack_dir}" -type f -perm -111 | grep -Ei "${match_pattern}" | head -n 1 || true)"
    [[ -n "${found}" ]] || die "Could not find expected binary in archive ${downloaded_file}"
    install -Dm755 "${found}" "${out_path}"
    return
  fi

  if python3 - <<'PY' "${downloaded_file}"
import sys, zipfile
try:
    with zipfile.ZipFile(sys.argv[1], "r"):
        pass
except zipfile.BadZipFile:
    raise SystemExit(1)
PY
  then
    local unpack_dir="${TMP_DIR}/unpack-$(basename "${out_path}")"
    mkdir -p "${unpack_dir}"
    python3 - <<'PY' "${downloaded_file}" "${unpack_dir}"
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "r") as zf:
    zf.extractall(sys.argv[2])
PY
    local found
    found="$(find "${unpack_dir}" -type f -perm -111 | grep -Ei "${match_pattern}" | head -n 1 || true)"
    [[ -n "${found}" ]] || die "Could not find expected binary in zip asset ${downloaded_file}"
    install -Dm755 "${found}" "${out_path}"
    return
  fi

  install -Dm755 "${downloaded_file}" "${out_path}"
}

log "Downloading inference engine"
ENGINE_FILE="${TMP_DIR}/engine-asset"
curl -fL "${ENGINE_URL}" -o "${ENGINE_FILE}"

log "Downloading daemon"
DAEMON_FILE="${TMP_DIR}/daemon-asset"
curl -fL "${DAEMON_URL}" -o "${DAEMON_FILE}"

install -d "${INSTALL_BIN_DIR}" "${INSTALL_LIB_DIR}" "/var/log/jett" "/var/jett/quarantine"
extract_binary "${ENGINE_FILE}" '(^|/)jett$|(^|/)jett-.*|(^|/)jeTT$' "${INSTALL_LIB_DIR}/jeTT"
extract_binary "${DAEMON_FILE}" '(^|/)jett-daemon$|(^|/)jett-daemon-.*' "${INSTALL_BIN_DIR}/jett-daemon"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WRAPPER_SOURCE="${SCRIPT_DIR}/jett"
SERVICE_SOURCE="${SCRIPT_DIR}/jett-daemon.service"

if [[ ! -f "${WRAPPER_SOURCE}" ]]; then
  WRAPPER_SOURCE="${TMP_DIR}/jett"
  curl -fsSL "https://raw.githubusercontent.com/${REPO}/${TAG}/jett" -o "${WRAPPER_SOURCE}" || die "Unable to fetch jett wrapper script"
fi

if [[ ! -f "${SERVICE_SOURCE}" ]]; then
  SERVICE_SOURCE="${TMP_DIR}/jett-daemon.service"
  curl -fsSL "https://raw.githubusercontent.com/${REPO}/${TAG}/jett-daemon.service" -o "${SERVICE_SOURCE}" || die "Unable to fetch jett-daemon.service"
fi

install -Dm755 "${WRAPPER_SOURCE}" "${INSTALL_BIN_DIR}/jett"
install -Dm644 "${SERVICE_SOURCE}" "${SERVICE_PATH}"

log "Reloading systemd and enabling jett-daemon service"
systemctl daemon-reload
systemctl enable --now jett-daemon.service

log "Install complete"
log "Run 'jett' for control panel mode, or 'jett --guard|--alert|--query <payload>' for CLI mode"
