#!/usr/bin/env bash
set -euo pipefail

# Ensure ripgrep (rg) is available — CI runners may not have it pre-installed
if ! command -v rg &>/dev/null; then
  if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq && sudo apt-get install -y -qq ripgrep 2>/dev/null || true
  fi
  if ! command -v rg &>/dev/null; then
    echo "WARN: ripgrep (rg) not available; skipping protocol purity checks" >&2
    echo "Clockless + protobuf-only gate: SKIPPED (no rg)"
    exit 0
  fi
fi

# CI pre-merge gate: prohibit reintroduction of banned patterns (wall-clock, JSON, forbidden versions)

roots=(
  dsm_client
  dsm_storage_node
  dsm_client/deterministic_state_machine
)

# Custom type: source languages on the protocol path.
# Using --type-add + --type instead of --glob '**/*.{rs,kt,...}' so that
# negative --glob exclusions take proper precedence.
src_type=(--type-add 'srclang:*.{rs,kt,kts,java}' --type srclang)

# Some paths in the repo are expected to contain JSON (lockfiles, SBOMs, vendored build
# artifacts, and build scripts). They are not on the protocol/bridge acceptance path.
json_allow_globs=(
  --glob '!**/Cargo.lock'
  --glob '!**/*.cdx.json'
  --glob '!**/*.map'
  --glob '!**/app/src/main/assets/**'
  --glob '!**/public/**'
  --glob '!**/scripts/**'
  --glob '!**/*.js'
  --glob '!**/*.ts'
  --glob '!**/*.tsx'
)


# Allowlist for non-clock exceptions (feature-gated, test-only, or external-boundary files).
# Note: avoid globs that may be treated as literal paths by some ripgrep versions.
common_allow_globs=(
  --glob '!**/sdk/blockchain_transport.rs'        # web3 JSON (feature-gated)
  --glob '!**/sdk/blockchain_transport_stub.rs'   # stub (no JSON)
  --glob '!**/integration_tests.rs'               # integration tests
  --glob '!**/*tests*'                            # unit/integration tests
  --glob '!**/testdata/**'                        # fixtures
  --glob '!**/*.md'                               # docs
  --glob '!**/target/**'                          # build outputs
  --glob '!**/cpta/migrations/**'                 # offline migrations may reference deprecated encodings
  --glob '!**/Cargo.lock'                         # dependency lockfiles may mention banned libs
  --glob '!**/handlers/app_router_impl.rs'        # Bitcoin Core JSON-RPC boundary (external API)
  --glob '!**/handlers/mempool_api.rs'             # mempool.space REST API boundary (external JSON API)
  --glob '!**/chaos_testing.rs'                   # testing/benchmarks
  --glob '!**/security/wal_transaction_queue.rs'   # WAL encrypted transaction (bincode at-rest, not protocol)
)

# Additional allowlist for wall-clock use in operational transport/runtime code only.
# These paths may use real elapsed time, but only for BLE transport behavior or
# other operational controls. They remain subject to the JSON/encoding/version gates.
clock_allow_globs=(
  "${common_allow_globs[@]}"
  --glob '!**/api/rate_limit.rs'                                           # transport-layer DoS rate limiting (permitted)
  --glob '!**/api/unilateral_api.rs'                                       # transport-layer rate limiting (permitted)
  --glob '!**/handlers/storage_routes.rs'                                  # transport-layer performance timing (latency measurement)
  --glob '!**/jni/ble_events.rs'                                           # BLE event buffering / runtime wakeups
  --glob '!**/deterministic_state_machine/dsm_sdk/src/sdk/bluetooth_transport.rs'  # BLE retries / ACK timeouts / reconnect backoff
  --glob '!**/deterministic_state_machine/dsm_sdk/src/bluetooth/pairing_orchestrator.rs' # BLE handshake freshness / retry windows
  --glob '!**/deterministic_state_machine/dsm_sdk/src/bluetooth/android_ble_bridge.rs'    # BLE bridge runtime transport control
  --glob '!**/deterministic_state_machine/dsm_sdk/src/bluetooth/ble_frame_coordinator.rs' # BLE chunk reassembly / transport expiry
  --glob '!**/deterministic_state_machine/dsm_sdk/src/bluetooth/bilateral_session.rs'      # BLE session freshness / expiry bookkeeping
  --glob '!**/deterministic_state_machine/dsm_sdk/src/bluetooth/bilateral_ble_handler.rs'   # BLE runtime retry / stale-session handling
  --glob '!**/android/app/src/main/java/com/dsm/wallet/bridge/ble/BleCoordinator.kt'      # Android BLE scan throttling / connect readiness
)

json_patterns='\bserde_json::|\bJSON\.parse\b|\bJSON\.stringify\b|\.toJSON\(|\bfrom_json\b|\bto_json\b'
SYS_MARKER="System"
CURRENT_MARKER="current"
TIME_MARKER="Time"
MILLIS_MARKER="Millis"
DATE_MARKER="Date"
NOW_MARKER="now"
INSTANT_MARKER="Instant"
CHRONO_MARKER="chrono"
UTC_MARKER="Utc"
UNIX_MARKER="UNIX"
EPOCH_MARKER="EPOCH"
clock_patterns="${SYS_MARKER}\\.${CURRENT_MARKER}${TIME_MARKER}${MILLIS_MARKER}|${DATE_MARKER}\\.${NOW_MARKER}|${CHRONO_MARKER}::${UTC_MARKER}|${SYS_MARKER}${TIME_MARKER}(::|\\.)?now|${UNIX_MARKER}_${EPOCH_MARKER}|${INSTANT_MARKER}(::|\\.)?now"
version_patterns='Envelope v'
version_patterns+='2'
encoding_patterns='\bhex::(encode|decode)\b|\bbase64(::|\.)?(encode|decode)\b|\bbincode::\b'
cborg_patterns='\bciborium\b'
indefinite_cbor_patterns='\b0x9f\b|\b0xbf\b|\b0xdf\b'  # indefinite arrays/maps/text/bytes (restricted to CBOR encoder modules)
protobuf_patterns='protobuf::'

echo "Running protobuf-only + clockless gates..."

# Bridge/string-transport (bytes-only boundary)
if [ -x "ci/bridge_contracts_gate.sh" ]; then
  ci/bridge_contracts_gate.sh
fi

# JSON (only meaningful for Rust/Kotlin/Java source on protocol path; ignore comment-only matches)
_json_hits="$(rg -n --hidden --ignore-case \
  "${src_type[@]}" \
  ${common_allow_globs[@]} \
  ${json_allow_globs[@]} \
  -e "\bserde_json::|\bserde_json\s*!" \
  -e "\bJSON\.(parse|stringify)\b" \
  -e "\.toJSON\(" \
  -e "\bfrom_json\b" \
  -e "\bto_json\b" \
  "${roots[@]}" | rg -v -n ":\s*(//|/\*|\*)" || true)"
if [ -n "${_json_hits}" ]; then
  echo "${_json_hits}"
  echo "[FAIL] JSON usage found outside allowlisted paths"; exit 2;
fi

# Wall clocks (protocol path only; frontend and bundled assets may use UI timers)
_clock_hits="$(rg -n --hidden --ignore-case \
  "${src_type[@]}" \
  ${clock_allow_globs[@]} \
  --glob '!**/app/src/main/assets/**' \
  --glob '!**/public/**' \
  -e "$clock_patterns" "${roots[@]}" \
  | rg -v -n "://|:/\*|:\s*\*" || true)"
if [ -n "${_clock_hits}" ]; then
  echo "${_clock_hits}"
  echo "[FAIL] Wall-clock APIs found"; exit 2;
fi

# Forbidden schema/version ghosts
if rg -n --hidden --ignore-case ${common_allow_globs[@]} -e "$version_patterns" "${roots[@]}"; then
  echo "[FAIL] Forbidden envelope/version artifacts found"; exit 2;
fi

# Encoding misuse in core (allow at boundaries/tests only)
if rg -n --hidden --ignore-case ${common_allow_globs[@]} -e "$encoding_patterns" "${roots[@]}"; then
  echo "[FAIL] Encoding helpers used in core paths"; exit 2;
fi

# CBOR libraries must not be used in transport or core paths (we use minimal deterministic CBOR locally only)
# With `set -o pipefail`, a pipeline that produces no output will still return non-zero
# due to intermediate filters; use a temp capture to avoid false failures.
_cbor_hits="$(rg -n --hidden --ignore-case ${common_allow_globs[@]} -e "$cborg_patterns" "${roots[@]}" \
  | rg -v -n ":\s*(//|/\*|\*)" || true)"
if [ -n "${_cbor_hits}" ]; then
  echo "${_cbor_hits}"
  echo "[FAIL] External CBOR libraries found; use deterministic in-core encoder only"; exit 2;
fi

# Indefinite-length CBOR must not appear in canonical commit encodings.
# Restrict this scan to the CBOR encoder modules to avoid false positives from arbitrary
# hex constants in unrelated code.
_indef_hits="$(rg -n --hidden --ignore-case \
  ${allow_globs[@]} \
  --glob '**/cbor*.rs' \
  --glob '**/canonical_encoding.rs' \
  ${common_allow_globs[@]} \
  -e "$indefinite_cbor_patterns" "${roots[@]}" \
  | rg -v -n ":\s*(//|/\*|\*)" || true)"
if [ -n "${_indef_hits}" ]; then
  echo "${_indef_hits}"
  echo "[FAIL] Indefinite-length CBOR found; enforce definite-length canonical form"; exit 2;
fi

# Protobuf libraries: allow `prost` (protobuf-only wire v3) as it is the standard transport
# layer across the workspace; continue to ban `protobuf::` usage.
if rg -n --hidden --ignore-case ${common_allow_globs[@]} -e "$protobuf_patterns" "${roots[@]}"; then
  echo "[FAIL] Forbidden protobuf::* usage found; use prost/protobuf-only v3"; exit 2;
fi

echo "Clockless + protobuf-only gate: OK"
