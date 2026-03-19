#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")"/.. && pwd)"
cd "$ROOT_DIR"

MANIFEST="scripts/flow_mappings.manifest"

red()  { printf "\033[31m%s\033[0m\n" "$*"; }
green(){ printf "\033[32m%s\033[0m\n" "$*"; }

if [[ ! -f "$MANIFEST" ]]; then
  red "[FLOW-MAP] FAIL: missing manifest: $MANIFEST"
  exit 1
fi

fails=0

while IFS='|' read -r rel_file pattern desc; do
  # Skip empty/comment lines
  [[ -z "${rel_file// }" ]] && continue
  [[ "${rel_file:0:1}" == "#" ]] && continue

  if [[ -z "${pattern// }" ]]; then
    red "[FLOW-MAP] FAIL: empty pattern for manifest row: $rel_file"
    fails=$((fails + 1))
    continue
  fi

  if [[ ! -f "$rel_file" ]]; then
    red "[FLOW-MAP] FAIL: file missing: $rel_file"
    fails=$((fails + 1))
    continue
  fi

  if ! grep -Fq "$pattern" "$rel_file"; then
    red "[FLOW-MAP] FAIL: ${desc:-mapping check failed}"
    red "  file: $rel_file"
    red "  pattern: $pattern"
    fails=$((fails + 1))
  fi
done < "$MANIFEST"

if [[ "$fails" -ne 0 ]]; then
  red "[FLOW-MAP] FAIL: $fails mapping assertion(s) failed"
  exit 1
fi

green "[FLOW-MAP] PASS: exact flow mappings verified from manifest"
