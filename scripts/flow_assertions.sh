#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")"/.. && pwd)"
cd "$ROOT_DIR"

red()  { printf "\033[31m%s\033[0m\n" "$*"; }
green(){ printf "\033[32m%s\033[0m\n" "$*"; }

assert_file() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    red "[FLOW-ASSERT] FAIL: missing file: $file"
    exit 1
  fi
}

assert_pattern() {
  local file="$1"
  local pattern="$2"
  local desc="$3"
  if ! grep -Fq "$pattern" "$file"; then
    red "[FLOW-ASSERT] FAIL: $desc"
    red "  expected pattern: $pattern"
    red "  file: $file"
    exit 1
  fi
}

FRONT_TX="dsm_client/new_frontend/src/dsm/transactions.ts"
FRONT_BRIDGE="dsm_client/new_frontend/src/dsm/WebViewBridge.ts"
FRONT_EVENT="dsm_client/new_frontend/src/dsm/EventBridge.ts"
FRONT_PORT="dsm_client/new_frontend/public/index.html"
JNI_BRIDGE="dsm_client/deterministic_state_machine/dsm_sdk/src/jni/unified_protobuf_bridge.rs"
SDK_ROUTER="dsm_client/deterministic_state_machine/dsm_sdk/src/handlers/app_router_impl.rs"

assert_file "$FRONT_TX"
assert_file "$FRONT_BRIDGE"
assert_file "$FRONT_EVENT"
assert_file "$FRONT_PORT"
assert_file "$JNI_BRIDGE"
assert_file "$SDK_ROUTER"

# Online transfer path
assert_pattern "$FRONT_TX" "sendOnlineTransfer(" "frontend online transfer entrypoint missing"
assert_pattern "$FRONT_TX" "appRouterInvokeBin('wallet.sendSmart'" "frontend online transfer must route via wallet.sendSmart"
assert_pattern "$SDK_ROUTER" "process_online_transfer_logic" "sdk online transfer processing logic missing"

# Offline bilateral prepare path
assert_pattern "$FRONT_TX" "offlineSend(" "frontend offline send entrypoint missing"
assert_pattern "$FRONT_TX" "appRouterInvokeBin('wallet.sendOffline'" "frontend offline send must route via wallet.sendOffline"
assert_pattern "$FRONT_BRIDGE" "methodName: 'bilateralOfflineSend'" "bridge must route bilateral offline send method"
assert_pattern "$JNI_BRIDGE" "Java_com_dsm_wallet_bridge_UnifiedNativeApi_bilateralOfflineSend" "jni bilateral offline entrypoint missing"

# App router framed boundaries
assert_pattern "$FRONT_BRIDGE" "method: 'appRouterInvoke'" "frontend must construct appRouterInvoke bridge request"
assert_pattern "$FRONT_BRIDGE" "method: 'appRouterQuery'" "frontend must construct appRouterQuery bridge request"
assert_pattern "$JNI_BRIDGE" "Java_com_dsm_wallet_bridge_UnifiedNativeApi_appRouterInvokeFramed" "jni invoke framed entrypoint missing"
assert_pattern "$JNI_BRIDGE" "Java_com_dsm_wallet_bridge_UnifiedNativeApi_appRouterQueryFramed" "jni query framed entrypoint missing"

# Async event propagation chain
assert_pattern "$FRONT_PORT" "dispatchEventPayload(bytes)" "message-port async event dispatcher missing"
assert_pattern "$FRONT_PORT" "'dsm-event-bin'" "message-port dispatcher must emit dsm-event-bin"
assert_pattern "$FRONT_EVENT" "window.addEventListener('dsm-event-bin'" "event bridge listener missing"
assert_pattern "$FRONT_EVENT" "topic === 'bilateral.event'" "bilateral event fanout missing"
assert_pattern "$FRONT_EVENT" "topic === 'ble.envelope.bin'" "ble envelope fanout missing"

# QR/contact onboarding and storage/inbox anchors
assert_pattern "$SDK_ROUTER" "\"contacts.handle_contact_qr_v3\"" "sdk contact qr handler missing"
assert_pattern "$SDK_ROUTER" "\"inbox.pull\"" "sdk inbox pull query handler missing"
assert_pattern "$SDK_ROUTER" "\"bilateral.pending_list\"" "sdk bilateral pending query handler missing"

green "[FLOW-ASSERT] PASS: critical stack flow anchors verified"
