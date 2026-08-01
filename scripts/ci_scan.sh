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

# 1b) Ban envelope-version lenient-acceptance variants (seam (a) structural
# enforcement). The strict-fail in dsm/src/envelope.rs::require_envelope_v3
# already rejects version != 3, but a contributor could regress that by
# adding accept paths under different identifiers. Catch the obvious shapes:
#   - "envelope" + "version < 3" (or ≤) on the same line   → accept-old paths
#   - EnvelopeV2 / EnvelopeV1                              → re-introducing
#     legacy type names
#   - accept_v2 / accept_legacy / legacy_envelope          → semantic flags
# Anchored on `envelope` keyword for the numeric inequality so that
# non-envelope schema bumps (soft_vault, recovery capsule) don't trigger.
fail_if_found "envelope-version lenient acceptance (seam a)" "${EXCLUDES[@]}" \
  -e '\bEnvelopeV[12]\b|\benvelope\b.*\bversion\s*[<≤]\s*3\b|\baccept_v2\b|\baccept_legacy\b|\blegacy_envelope\b' \
  "${SCAN_ROOTS[@]}"

# Forbidden peer field name (schema/field only). Do not flag local variable names.
FORBIDDEN_PEER_FIELD="peer"
FORBIDDEN_PEER_FIELD+="_id"
fail_if_found "forbidden peer field" "${EXCLUDES[@]}" -e "\"${FORBIDDEN_PEER_FIELD}\"|\\b${FORBIDDEN_PEER_FIELD}\\s*:" "${SCAN_ROOTS[@]}"

# 2) Ban JSON envelopes (stringify/parse on type/data) anywhere
fail_if_found "JSON envelopes detected" "${EXCLUDES[@]}" -e 'JSON\.(stringify|parse).*\"(type|data)\"' "${SCAN_ROOTS[@]}"

# 2b) Ban serde_json reaching into Core/SDK protocol paths (seam (b)
# structural enforcement). DSM wire format is protobuf-only; serde_json on
# the protocol layer would silently widen the accepted-input surface.
# Legitimate boundary uses: external HTTP API clients (e.g. mempool.space).
# Each such file MUST be exempted here with a comment naming the rationale.
fail_if_found "serde_json reaches into Core/SDK protocol path (seam b)" \
  -g '!**/tests/**' \
  -g '!**/*_test.rs' \
  -g '!**/test_*.rs' \
  -g '!**/mempool_api.rs' `# external mempool.space REST API — see file header` \
  -e 'serde_json::(Value|from_str|to_string|to_value|from_value|from_slice|to_vec)\b' \
  dsm_client/deterministic_state_machine/dsm/src \
  dsm_client/deterministic_state_machine/dsm_sdk/src

# 2c) Lock transfer_hooks.rs to token-only imports (seam (c) structural
# enforcement). dBTC transfers must NOT carry vault anchors, preimages,
# or vault-specific execution material. The file currently has zero vault
# imports; this scan freezes that property.
fail_if_found "transfer_hooks must stay token-only — no vault/anchor imports (seam c)" \
  -e '(crate::|dsm::|super::)?vault::|::vault\b|LimboVault|LimboVaultProto|DlvManager|AnchorEnforcement|VaultStateAnchor|dlv_routes::|dlv_sdk::|dsm::dlv::' \
  dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/transfer_hooks.rs

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

# 3b) Ban blocking entropy sources in production code. Android must use the
# platform-backed nonblocking OS RNG path exposed through rand/getrandom, not
# direct reads from /dev/random.
ENTROPY_SCAN_ROOTS=(
  dsm_client/deterministic_state_machine/dsm/src
  dsm_client/deterministic_state_machine/dsm_sdk/src
  dsm_client/android/app/src/main
)
fail_if_found "blocking /dev/random entropy source" \
  "${EXCLUDES[@]}" \
  --fixed-strings "/dev/random" \
  "${ENTROPY_SCAN_ROOTS[@]}"



# 5) Ban encoding misuse inside Rust core (hex/base64) for canonical commits
# Scope: Rust core only
if [ -d "$CORE_DIR" ]; then
  fail_if_found "hex/base64 usage in core (canonical path)" "${EXCLUDES[@]}" -e 'hex::(encode|decode)|base64(::|\.)?(encode|decode)' "$CORE_DIR"
  fail_if_found "unsafe blocks in core" "${EXCLUDES[@]}" -e '^ *unsafe \{' "$CORE_DIR"
fi

# 6) Ban Pedersen commitments (Issue #184 F2 + Brandon's reintroduction-prevention gate).
#
# A `crypto/pedersen` module previously lived in this repo, mislabeled
# "Quantum-Resistant Pedersen Commitments" but implementing a classical
# Z_p* construction whose security reduces to discrete-log — broken in
# polynomial time by Shor. It was excised entirely; DSM uses salted
# BLAKE3 commitments (`vault::limbo_vault::dlv_content_commitment`)
# which provide identical hiding + binding under post-quantum-secure
# assumptions.
#
# This gate prevents the module / re-exports / dead constants from
# creeping back in. The legitimate keyword `pedersen` does not appear
# anywhere in the canonical DSM stack, so a string match here is
# unambiguous.
PEDERSEN_BAN_SCOPES=(
  "dsm_client/deterministic_state_machine/dsm/src"
  "dsm_client/deterministic_state_machine/dsm_sdk/src"
)
PEDERSEN_PATTERN='\bpedersen\b|\bPedersen\b|\bPEDERSEN\b|\bPedersenCommitment\b|\bPedersenParams\b'
for scope in "${PEDERSEN_BAN_SCOPES[@]}"; do
  if [ -d "$scope" ]; then
    fail_if_found \
      "Pedersen reintroduction in ${scope} (use salted BLAKE3 commitment instead — Issue #184 F2)" \
      "${EXCLUDES[@]}" \
      -e "$PEDERSEN_PATTERN" \
      "$scope"
  fi
done

# Also ban num-bigint / num-primes / num-traits / num-integer
# dependencies — they were Pedersen-only. Dropping them keeps the
# build minimal and prevents Pedersen reintroduction by way of
# big-int infrastructure.
NUMBIG_BAN_PATTERN='^\s*num-(bigint|primes|traits|integer)\s*='
for cargo in \
  "dsm_client/deterministic_state_machine/dsm/Cargo.toml" \
  "dsm_client/deterministic_state_machine/dsm_sdk/Cargo.toml"
do
  if [ -f "$cargo" ]; then
    fail_if_found \
      "Pedersen-era num-* dependency reintroduced in $cargo" \
      -e "$NUMBIG_BAN_PATTERN" \
      "$cargo"
  fi
done

# 7) Ban dead-code-by-default modules that have crept back before.
# `crypto_verification` (Issue #185, all 4 findings) was a 600-line
# module exposing `QuantumResistantBinding` + `MpcIdentityFactory`
# with zero production callers; its audit findings were all on a
# never-executed path. Removed entirely. Reintroduction without an
# explicit production caller and CI gate update is flagged here.
QRB_BAN_PATTERN='\bcrypto_verification\b|\bQuantumResistantBinding\b|\bMpcIdentityFactory\b'
for scope in "${PEDERSEN_BAN_SCOPES[@]}"; do
  if [ -d "$scope" ]; then
    fail_if_found \
      "crypto_verification reintroduction in ${scope} (use crypto::cdbrw_binding for hardware-bound attestation — Issue #185)" \
      "${EXCLUDES[@]}" \
      -e "$QRB_BAN_PATTERN" \
      "$scope"
  fi
done

# 6) Protobuf library usage
# NOTE: This repo currently uses `prost::Message` in several core modules for
# deterministic encoding/canonicalization and internal migrations.
# We rely on CI gates and code review to keep protobuf usage disciplined.


# ─────────────────────────────────────────────────────────────────────────────
# STATIC ARCHITECTURAL RULES — migrated from dsm_sdk/tests/dlv_regression_guards.rs
#
# These are the rules from that suite that are GENUINELY STATIC: they say
# "this code shape must not exist", which no behavioural test can express — a
# test can only prove the code that DOES exist behaves correctly, never that a
# forbidden construct is absent.
#
# Everything else in that suite asserted `src.contains(...)` about behaviour,
# and has been replaced by tests that execute the real routes. Those greps were
# the reason a value path rejected by the conservation chokepoint stayed green
# for months: they matched the text of code that never ran.
#
# Labelled static so nobody mistakes them for coverage.
# ─────────────────────────────────────────────────────────────────────────────

SDK_SRC="dsm_client/deterministic_state_machine/dsm_sdk/src"
CORE_SRC="dsm_client/deterministic_state_machine/dsm/src"
FE_SRC="dsm_client/frontend"

# Protocol state is canonical state, never a preferences blob. A handler that
# mirrored vault or token state into app-state prefs would create a second copy
# that drifts from the chain.
fail_if_found "static: token/dlv/sofi state written to app-state prefs" \
  -e 'app_state_set\(&format!\("dsm\.(token|dlv|sofi)\.' \
  "$SDK_SRC/handlers/"

# A policy commit is derived from the canonical policy, never lifted out of a
# display metadata cache. The cache is populated FROM the commit; reversing that
# lets a stale or attacker-supplied cache entry decide asset identity.
fail_if_found "static: policy_commit derived from a metadata cache" \
  -e 'policy_commit = metadata\.policy_anchor' \
  -e 'from_policy_anchor\(&metadata\.policy_anchor' \
  "$SDK_SRC/"

# Path search is pure route arithmetic. If it could build RouteCommits or drive
# the state machine, quote-time code would be able to move value.
fail_if_found "static: routing_path_sdk reaches into RouteCommit or settlement" \
  -e 'RouteCommitV1|execute_on_relationship|Operation::Dlv' \
  "$SDK_SRC/sdk/routing_path_sdk.rs"

# RouteCommit construction is likewise pure: it binds a quote, it does not
# settle one. Emitting operations here would put value movement outside the
# handler that gates it.
fail_if_found "static: route_commit_sdk emits state-machine operations" \
  -e 'execute_on_relationship|Operation::DlvUnlock|Operation::DlvClaim|Operation::DlvCreate' \
  "$SDK_SRC/sdk/route_commit_sdk.rs"

# Business logic stays in Rust: a frontend that can hash can derive identity,
# and then two implementations decide what an asset is.
if [ -f "$FE_SRC/package.json" ]; then
  fail_if_found "static: frontend carries a hashing library" \
    -e '@noble/hashes|blake3' \
    "$FE_SRC/package.json"
fi

# Deleted paths stay deleted. Each of these was removed because it was wrong,
# not because it was unused, so a reintroduction is a regression rather than a
# style question.
fail_if_found "static: the token-policy placeholder hash was reintroduced" \
  -e 'domain_hash_bytes\("DSM/token-policy' \
  "$CORE_SRC/core/token/token_state_manager.rs"

fail_if_found "static: DlvCreateV3 was reintroduced" \
  -e 'DlvCreateV3' \
  "$CORE_SRC/" "$SDK_SRC/" proto/

green "[CI-SCAN] PASS: No violations detected"
