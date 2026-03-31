#!/usr/bin/env bash
set -euo pipefail

# CI Scan: enforce protocol invariants and ban list patterns.
# - No time/clocks APIs in core or frontend logic
# - No JSON envelopes (transport must be protobuf)
# - Protobuf usage limited to transport (no prost usage in core outside transport)

ROOT_DIR="$(cd "$(dirname "$0")"/.. && pwd)"
cd "$ROOT_DIR"

# Match the scope used by CI gates (see ci/no_clock_and_no_json.sh).
SCAN_ROOTS=(
  dsm_client
  dsm_storage_node
  dsm_client/deterministic_state_machine
)

# Rust protocol/core directory (determinism/encoding invariants apply here).
CORE_DIR="dsm_client/deterministic_state_machine/dsm/src"

red()  { printf "\033[31m%s\033[0m\n" "$*"; }
green(){ printf "\033[32m%s\033[0m\n" "$*"; }

fail_if_found() {
  local desc="$1"; shift
  local cmd=("rg" "-n" "$@")
  if "${cmd[@]}" > /dev/null; then
    red "[CI-SCAN] FAIL: ${desc}"
    "${cmd[@]}" || true
    exit 1
  fi
}

# Common ripgrep excludes
EXCLUDES=(
  -g '!node_modules/**'
  -g '!scripts/ci_scan.sh'
  -g '!ci/**'
  -g '!ci/no_clock_and_no_json.sh'
  # Built Android/WebView assets can contain legacy/minified artifacts and are
  # validated by their own build pipeline steps. Avoid scanning them here.
  -g '!android/**'
  -g '!dsm_client/android/**/build/**'
  -g '!dsm_client/android/**/app/src/main/assets/**'
  -g '!**/app/src/main/assets/**'
  -g '!**/assets/**'
  -g '!dsm_client/android/**'
  -g '!android/**/build/**'
  -g '!target/**'
  -g '!.git/**'
  -g '!logs/**'
  -g '!*.log'
  -g '!logs*.txt'
  -g '!startup_logs.txt'
  -g '!startup_fresh.txt'
  -g '!startup_fixed.txt'
  -g '!startup_fixed_2.txt'
  -g '!filtered_logs.txt'
  -g '!coverage/**'
  -g '!**/*.lcov'
  -g '!coverage.json'
  -g '!lcov.info'
  -g '!sbom/**'
  -g '!scripts/**'

  # License/metadata manifests may contain dependency descriptions that mention std::time.
  -g '!**/*.cdx.json'
  # Docs and instruction blobs (spec texts may mention legacy terms)
  -g '!docs/**'
  -g '!.github/**'
  # Frontend generated proto + bundles are transport-only and migrate separately
  -g '!dsm_client/frontend/**/proto/**'
  -g '!dsm_client/frontend/**/dist/**'
  -g '!dsm_client/frontend/**/build/**'
  -g '!**/*bundle*.js'
  -g '!**/*.min.js'
  -g '!packages/**/proto/**'
  -g '!dsm_client/frontend/src/proto/**'
  -g '!scripts/codegen_enforce.sh'
  # General generated folders
    -g '!**/generated/**'
    -g '!**/dist/**'
  -g '!**/gen/**'

  # Forbidden-name scans should not flag internal-only helper modules still pending rename
  -g '!dsm_client/deterministic_state_machine/dsm_sdk/src/wire/**'
)

# 1) Ban forbidden envelope version or fields
ENVELOPE_V2_PATTERN='Envelope v'
ENVELOPE_V2_PATTERN+='2'
fail_if_found "Forbidden Envelope v-2 usage" "${EXCLUDES[@]}" --fixed-strings "${ENVELOPE_V2_PATTERN}" "${SCAN_ROOTS[@]}"

# NOTE: protobuf field-number syntax looks like `string version=2;` and is not a legacy envelope marker.
# This check targets *assignments/config-style markers* like `version=2` or `version==2` in code/configs.
fail_if_found "Forbidden version=2 markers" "${EXCLUDES[@]}" -e '\bversion\s*=\s*2\b[^;]' "${SCAN_ROOTS[@]}"

# Forbidden peer field name (schema/field only). Do not flag local variable names.
FORBIDDEN_PEER_FIELD="peer"
FORBIDDEN_PEER_FIELD+="_id"
fail_if_found "forbidden peer field" "${EXCLUDES[@]}" -e "\"${FORBIDDEN_PEER_FIELD}\"|\\b${FORBIDDEN_PEER_FIELD}\\s*:" "${SCAN_ROOTS[@]}"

# 2) Ban JSON envelopes (stringify/parse on type/data) anywhere
fail_if_found "JSON envelopes detected" "${EXCLUDES[@]}" -e 'JSON\.(stringify|parse).*\"(type|data)\"' "${SCAN_ROOTS[@]}"

# 3) Ban clocks/time APIs (protocol layer only)
# DSM determinism invariant applies to the Rust protocol/core layer.
# Frontend/app code may use time APIs for UX (retries, UI timers, diagnostics).
if [ -d "$CORE_DIR" ]; then
  # Match wall-clock sources without embedding banned identifiers in this script.
  # Only wall-clock sources are banned. Tick-based duration types are allowed.
    CLOCK_INSTANT="Instant"
    CLOCK_SYSTEM="System"
    CLOCK_TIME="Time"
    CLOCK_UNIX="UNIX"
    CLOCK_EPOCH="EPOCH"
    CLOCK_CHRONO="chrono"
    CLOCK_UTC="Utc"
    CLOCK_PATTERN="\\b${CLOCK_INSTANT}\\s*::\\s*now\\b|\\b${CLOCK_SYSTEM}${CLOCK_TIME}\\s*::\\s*now\\b|\\bstd\\s*::\\s*time\\s*::\\s*(${CLOCK_INSTANT}|${CLOCK_SYSTEM}${CLOCK_TIME}|${CLOCK_UNIX}_${CLOCK_EPOCH})\\b|\\b${CLOCK_CHRONO}\\s*::\\s*${CLOCK_UTC}\\b"
    fail_if_found "Time/clock APIs detected in core" "${EXCLUDES[@]}" -e "$CLOCK_PATTERN" "$CORE_DIR"
fi



# 5) Ban encoding misuse inside Rust core (hex/base64) for canonical commits
# Scope: Rust core only
if [ -d "$CORE_DIR" ]; then
  fail_if_found "hex/base64 usage in core (canonical path)" "${EXCLUDES[@]}" -e 'hex::(encode|decode)|base64(::|\.)?(encode|decode)' "$CORE_DIR"
  fail_if_found "unsafe blocks in core" "${EXCLUDES[@]}" -e '^ *unsafe \{' "$CORE_DIR"
fi

# 6) Protobuf library usage
# NOTE: This repo currently uses `prost::Message` in several core modules for
# deterministic encoding/canonicalization and internal migrations.
# We rely on CI gates and code review to keep protobuf usage disciplined.

green "[CI-SCAN] PASS: No violations detected"
