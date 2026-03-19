#!/usr/bin/env bash
set -euo pipefail

# CI pre-merge gate: prohibit bridge/string-transport patterns.
# Goal: enforce a "Uniform Byte Pipe" at boundaries.

roots=(
  dsm_client/new_frontend/src/dsm
  dsm_client/android/app/src/main/java
)

android_roots=(
  dsm_client/android/app/src/main/java
)

# Subroots that must remain strictly bytes-only and never use Base32/JSON fallbacks.
# These are the protocol/bridge-facing surfaces.
frontend_strict_roots=(
  # NOTE: `index.ts` is a UI/client facade and may format identifiers for display.
  # The strict bytes-only contract applies to the actual bridge plumbing only.
  dsm_client/new_frontend/src/dsm/WebViewBridge.ts
  dsm_client/new_frontend/src/dsm/BridgeGate.ts
)

# Allowlist some files that are explicitly UI/display/recovery and not transport acceptance.
# IMPORTANT: keep this list small and intentional.
allow_paths=(
  dsm_client/new_frontend/src/dsm/EventBridge.ts
  dsm_client/android/app/src/main/java/com/dsm/wallet/ui/MainActivity.kt
  dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BleEventRelay.kt
  dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/SinglePathWebViewBridge.kt
  dsm_client/android/app/src/main/java/com/dsm/wallet/security/AntiCloneGate.kt
  dsm_client/android/app/src/main/java/com/dsm/wallet/recovery/NfcRecoveryActivity.kt
  dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/DsmBluetoothService.kt
)

rg_allow=(
  --glob '!**/__tests__/**'
  --glob '!**/*.test.ts'
  --glob '!**/*.spec.ts'
  --glob '!**/*.md'
)

# 1) Frontend bridge transport: PROHIBIT Base32 encode/decode.
#
# IMPORTANT:
# - The DSM protocol boundary must be bytes-only (MessagePort / __callBin) and MUST NOT
#   accept or produce Base32/JSON shims.
# - UI-only helpers may use Base32, but those must live outside the strict bridge entrypoints
#   listed in `frontend_strict_roots`.
frontend_transport_encoding='base32CrockfordEncode\(|base32CrockfordDecode\('

# 2) Frontend: prohibit bridge globals/aliases.
# NOTE: window.DsmBridge is the canonical global and is allowed.
frontend_bridge_globals='window\.DSMBridge|window\.Android|window\.dsmBridge|\bDSMBridge\b|\bdsmBridge\b'

# 3) Frontend: prohibit binary-string or hex adapters on bridge payloads.
frontend_binary_string_adapters='String\.fromCharCode\(|\.charCodeAt\(|atob\(|btoa\(|toString\(\x27hex\x27\)|from\([^\n]*\x27hex\x27\)'

# 3b) Frontend: prohibit JSON parsing in the DSM protocol/bridge layer.
# Serialization for logging is allowed (it's not a transport boundary), but parsing indicates
# a JSON-based protocol path or shim.
frontend_json_parse='JSON\.parse\('

# 3c) Frontend: prohibit JSON message bridge fallback.
# The DSM boundary must use protobuf bytes (MessagePort / __callBin) and never JSON messages.
frontend_send_message='\.sendMessage\(|\bsendMessage\s*\('

# 4) Android/Kotlin: prohibit reintroduction of @JavascriptInterface bridge methods.
android_jsi='@JavascriptInterface'

# 5) Android/Kotlin: prohibit Base32-on-transport comments that drift back into contracts.
# (We want bytes-only through MessagePort; Base32 is UI-only.)
# Only match Android-side contract/comment remnants, not incidental JS field names.
android_transport_base32='Payload MUST be a Base32|payloadBase32\b'

# Helper to run ripgrep and fail with message.
fail_if_rg() {
  local label="$1"; shift
  local pattern="$1"; shift
  local rg_exclude_files=()
  for p in "${allow_paths[@]}"; do
    rg_exclude_files+=(--glob "!$p")
  done
  if rg -n --hidden --ignore-case "${rg_allow[@]}" "${rg_exclude_files[@]}" -e "$pattern" "${roots[@]}"; then
    echo "[FAIL] ${label}" >&2
    exit 2
  fi
}

# Same as fail_if_rg, but searches only the strict frontend bridge/client entrypoints.
fail_if_rg_frontend_strict() {
  local label="$1"; shift
  local pattern="$1"; shift
  # No allowlist exclusions here; the whole point is "no exceptions" on these files.
  if rg -n --hidden --ignore-case "${rg_allow[@]}" -e "$pattern" "${frontend_strict_roots[@]}"; then
    echo "[FAIL] ${label}" >&2
    exit 2
  fi
}

fail_if_rg_frontend_strict_case_sensitive() {
  local label="$1"; shift
  local pattern="$1"; shift
  if rg -n --hidden "${rg_allow[@]}" -e "$pattern" "${frontend_strict_roots[@]}"; then
    echo "[FAIL] ${label}" >&2
    exit 2
  fi
}

fail_if_rg_case_sensitive() {
  local label="$1"; shift
  local pattern="$1"; shift
  local rg_exclude_files=()
  for p in "${allow_paths[@]}"; do
    rg_exclude_files+=(--glob "!$p")
  done
  if rg -n --hidden "${rg_allow[@]}" "${rg_exclude_files[@]}" -e "$pattern" "${roots[@]}"; then
    echo "[FAIL] ${label}" >&2
    exit 2
  fi
}

fail_if_rg_android() {
  local label="$1"; shift
  local pattern="$1"; shift
  local rg_exclude_files=()
  for p in "${allow_paths[@]}"; do
    rg_exclude_files+=(--glob "!$p")
  done
  if rg -n --hidden --ignore-case "${rg_allow[@]}" "${rg_exclude_files[@]}" -e "$pattern" "${android_roots[@]}"; then
    echo "[FAIL] ${label}" >&2
    exit 2
  fi
}

echo "Running bridge contract gate..."

# Strict bytes-only enforcement for the bridge plumbing entrypoints.
fail_if_rg_frontend_strict "Frontend bridge (strict): Base32 transport encode/decode found" "$frontend_transport_encoding"
fail_if_rg_frontend_strict_case_sensitive "Frontend bridge (strict): bridge globals/aliases found" "$frontend_bridge_globals"
fail_if_rg_frontend_strict "Frontend bridge (strict): binary-string/hex adapters found" "$frontend_binary_string_adapters"
fail_if_rg_frontend_strict_case_sensitive "Frontend bridge (strict): JSON.parse usage found" "$frontend_json_parse"
fail_if_rg_frontend_strict_case_sensitive "Frontend bridge (strict): sendMessage usage found" "$frontend_send_message"
fail_if_rg_android "Android: @JavascriptInterface reintroduced" "$android_jsi"
fail_if_rg_android "Android: Base32 transport contract remnants found" "$android_transport_base32"

echo "Bridge contract gate: OK"
