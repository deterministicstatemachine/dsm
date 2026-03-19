#!/usr/bin/env bash
set -euo pipefail

# Directories to exclude from forbidden-symbol scans (non-code paths)
EXCLUDE_DIRS=(scripts docs .claude .github node_modules target build ci)

# Fail CI if the forbidden symbol name appears anywhere in the repo
if command -v rg >/dev/null 2>&1; then
  _rg_excludes=()
  for d in "${EXCLUDE_DIRS[@]}"; do _rg_excludes+=(--glob "!**/${d}/**"); done
  _bt_hits=$(rg -n --hidden --no-ignore-vcs -S '\bBluetoothMessage\b' \
    "${_rg_excludes[@]}" . || true)
else
  _grep_excludes=()
  for d in "${EXCLUDE_DIRS[@]}"; do _grep_excludes+=(--exclude-dir="$d"); done
  _bt_hits=$(grep -rn --include='*.rs' --include='*.kt' --include='*.java' --include='*.ts' --include='*.tsx' \
    "${_grep_excludes[@]}" 'BluetoothMessage' . || true)
fi
if [[ -n "$_bt_hits" ]]; then
  echo "$_bt_hits"
  echo "Forbidden symbol 'BluetoothMessage' found. Remove or rename (use BleBridgeEvent for local events)."
  exit 1
fi

echo "No forbidden symbol 'BluetoothMessage' found."

# Fail on any forbidden artifacts that would reintroduce blocked paths
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
cd "$ROOT_DIR"

fail() {
  echo "[FORBIDDEN-GUARD] $1" >&2
  exit 1
}

# Patterns to block (fixed-string mode — no regex metacharacters)
BLOCK_PATTERNS=(
  "dsm.bridge.proto"
  "vaulthunter.proto"
  "GameFaucetBridge"
  "ProtobufBridge"
  "JSON.stringify(envelope)"
)

FOUND=()
for pat in "${BLOCK_PATTERNS[@]}"; do
  if command -v rg >/dev/null 2>&1; then
    _rg_excludes=()
    for d in "${EXCLUDE_DIRS[@]}"; do _rg_excludes+=(--glob "!**/${d}/**"); done
    hits=$(rg -n --hidden -F "${_rg_excludes[@]}" --glob '!*.sh' --glob '!*.md' "${pat}" . || true)
  else
    _grep_excludes=()
    for d in "${EXCLUDE_DIRS[@]}"; do _grep_excludes+=(--exclude-dir="$d"); done
    hits=$(grep -RInF "${_grep_excludes[@]}" --exclude='*.sh' --exclude='*.md' -- "${pat}" . || true)
  fi
  if [[ -n "$hits" ]]; then
    FOUND+=("Pattern: ${pat}")
    FOUND+=($'-----')
    FOUND+=("${hits}")
    FOUND+=($'')
  fi
done

if (( ${#FOUND[@]} > 0 )); then
  echo "Forbidden identifiers detected:" >&2
  printf '%s\n' "${FOUND[@]}" >&2
  fail "Please remove blocked references above (forbidden patterns)."
else
  echo "[FORBIDDEN-GUARD] OK: No blocked identifiers found."
fi
