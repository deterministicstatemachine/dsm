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

FRONT_TX="dsm_client/frontend/src/dsm/transactions.ts"
FRONT_BRIDGE="dsm_client/frontend/src/dsm/WebViewBridge/transportCore.ts"
FRONT_NBB="dsm_client/frontend/src/dsm/NativeBoundaryBridge.ts"
FRONT_EVENT="dsm_client/frontend/src/dsm/EventBridge.ts"
FRONT_PORT="dsm_client/frontend/public/index.html"
JNI_BRIDGE="dsm_client/deterministic_state_machine/dsm_sdk/src/jni/unified_protobuf_bridge.rs"
SDK_ROUTER="dsm_client/deterministic_state_machine/dsm_sdk/src/handlers/app_router_impl.rs"

assert_file "$FRONT_TX"
assert_file "$FRONT_BRIDGE"
assert_file "$FRONT_NBB"
assert_file "$FRONT_EVENT"
assert_file "$FRONT_PORT"
assert_file "$JNI_BRIDGE"
assert_file "$SDK_ROUTER"

# Online transfer path — routes via unified ingress (routerInvokeBin → IngressRequest)
assert_pattern "$FRONT_TX" "sendOnlineTransfer(" "frontend online transfer entrypoint missing"
assert_pattern "$FRONT_TX" "routerInvokeBin('wallet.send'" "frontend online transfer must route via wallet.send"
assert_pattern "$FRONT_TX" "routerInvokeBin('wallet.sendSmart'" "frontend smart online transfer must route via wallet.sendSmart"
assert_pattern "$SDK_ROUTER" "process_online_transfer_logic" "sdk online transfer processing logic missing"

# Offline bilateral prepare path
assert_pattern "$FRONT_TX" "offlineSend(" "frontend offline send entrypoint missing"
assert_pattern "$FRONT_TX" "routerInvokeBin('wallet.sendOffline'" "frontend offline send must route via wallet.sendOffline"
assert_pattern "$JNI_BRIDGE" "Java_com_dsm_wallet_bridge_UnifiedNativeApi_bilateralOfflineSend" "jni bilateral offline entrypoint missing"

# Unified ingress boundary (replaced legacy appRouterInvokeFramed/appRouterQueryFramed post-16f0763)
assert_pattern "$FRONT_NBB" "case: 'routerInvoke'" "ingress routerInvoke case missing in NativeBoundaryBridge"
assert_pattern "$FRONT_NBB" "case: 'routerQuery'" "ingress routerQuery case missing in NativeBoundaryBridge"
assert_pattern "$FRONT_NBB" "nativeBoundaryIngress" "native boundary ingress dispatch method missing"
assert_pattern "$FRONT_BRIDGE" "buildRouterInvokeIngressRequest" "frontend must build routerInvoke via ingress helper"
assert_pattern "$FRONT_BRIDGE" "buildRouterQueryIngressRequest" "frontend must build routerQuery via ingress helper"
assert_pattern "$JNI_BRIDGE" "Java_com_dsm_wallet_bridge_UnifiedNativeApi_dispatchIngress" "jni dispatchIngress entrypoint missing"
assert_pattern "$JNI_BRIDGE" "Java_com_dsm_wallet_bridge_UnifiedNativeApi_dispatchStartup" "jni dispatchStartup entrypoint missing"

# Async event propagation chain
assert_pattern "$FRONT_PORT" "dispatchLegacyTopicEvent(bytes)" "legacy-topic event dispatcher missing"
assert_pattern "$FRONT_PORT" "'dsm-event-bin'" "message-port dispatcher must emit dsm-event-bin"
assert_pattern "$FRONT_EVENT" "window.addEventListener('dsm-event-bin'" "event bridge listener missing"
assert_pattern "$FRONT_EVENT" "topic === 'bilateral.event'" "bilateral event fanout missing"
assert_pattern "$FRONT_EVENT" "topic === 'ble.envelope.bin'" "ble envelope fanout missing"

# QR/contact onboarding and storage/inbox anchors
assert_pattern "$SDK_ROUTER" "\"contacts.handle_contact_qr_v3\"" "sdk contact qr handler missing"
assert_pattern "$SDK_ROUTER" "\"inbox.pull\"" "sdk inbox pull query handler missing"
assert_pattern "$SDK_ROUTER" "\"bilateral.pending_list\"" "sdk bilateral pending query handler missing"

green "[FLOW-ASSERT] PASS: critical stack flow anchors verified"
