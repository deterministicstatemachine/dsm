#!/bin/bash
# DSM Guardrails Enforcement Script
#
# Fork architecture invariants:
#   - "Rust is the brain, frontend is dumb view layer"
#   - Frontend imports WebViewBridge directly (protobuf envelope binary RPC)
#   - Envelope v3 framing (single 0x03 prefix byte) on all responses
#   - Size/version limits enforced Rust-side (MAX_ENVELOPE_BYTES, MAX_OP_BYTES_LEN)
#   - Single Android bridge class: SinglePathWebViewBridge
#   - No JSON communication in frontend services (protobuf only)
#   - No legacy ProtobufBridge file, no onBleEvent JSON fallback, no 'dsm-ble' CustomEvent shim

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "🔒 DSM Guardrails Enforcement"
echo "============================="

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

report_violation() {
    echo -e "${RED}❌ VIOLATION: $1${NC}"
    echo "   $2"
    VIOLATIONS=$((VIOLATIONS + 1))
}

report_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

VIOLATIONS=0

CODE_DIRS=(
    "$REPO_ROOT/dsm_client/frontend/src"
    "$REPO_ROOT/dsm_client/android/app/src"
    "$REPO_ROOT/dsm_client/deterministic_state_machine"
    "$REPO_ROOT/dsm_storage_node"
)

# Portable find + grep helper; excludes build outputs + bundled JS artifacts
search_in_code_dirs() {
    local pattern="$1"
    local print_matches="$2"
    local found=1
    for d in "${CODE_DIRS[@]}"; do
        [ -d "$d" ] || continue
        local matches
        matches=$(find "$d" \
            -type d \( -name target -o -name node_modules -o -name dist -o -name build -o -name .gradle -o -name .git -o -name out \) -prune \
            -o -type f -print \
            | xargs grep -I -nE "$pattern" 2>/dev/null || true)
        matches=$(echo "$matches" | grep -v "/dsm_client/android/app/src/main/assets/js/" | grep -v "^$")
        if [ -n "$matches" ]; then
            found=0
            if [ -n "$print_matches" ]; then
                echo "$matches" | head -n 5
            fi
            break
        fi
    done
    return $found
}

echo "Checking fork architecture invariants..."

# Check 1: JNI interfaces limited to DsmBridge + Voice
echo "1. Checking JNI bridge methods..."
if grep -RIn "addJavascriptInterface(" --include="*.java" --include="*.kt" "$REPO_ROOT/dsm_client/android/app/src/main/java/" 2>/dev/null | \
     grep -v "DsmBridge" | grep -v "Voice" >/dev/null; then
    report_violation "FORBIDDEN JNI METHOD" "Found addJavascriptInterface other than allowed aliases (DsmBridge, Voice)."
else
    report_success "JNI methods compliant - only DsmBridge + Voice aliases allowed"
fi

# Check 2: No JSON communication in frontend services (protobuf only)
echo "2. Checking for JSON communication patterns (frontend services)..."
if [ -d "$REPO_ROOT/dsm_client/frontend/src/services" ] && \
   grep -RInE '\.stringify\(|\.parse\(' --include="*.ts" --include="*.tsx" "$REPO_ROOT/dsm_client/frontend/src/services/" 2>/dev/null | grep -v "temporary\|TODO" | grep -q .; then
    report_violation "FORBIDDEN JSON COMMUNICATION" "Found JSON serialization in frontend services. Must use protobuf envelopes only."
else
    report_success "No JSON communication patterns in frontend services"
fi

# Check 3: Envelope v3 framing (0x03 prefix) present in TS bridge
echo "3. Checking envelope v3 framing in TS bridge..."
BRIDGE_TS="$REPO_ROOT/dsm_client/frontend/src/dsm/WebViewBridge.ts"
if [ -f "$BRIDGE_TS" ]; then
    if grep -qE "0x03" "$BRIDGE_TS"; then
        report_success "Envelope v3 framing (0x03 prefix) documented/used in WebViewBridge.ts"
    else
        report_violation "MISSING ENVELOPE V3 FRAMING" "WebViewBridge.ts must reference 0x03 framing byte (envelope v3)."
    fi
else
    report_success "Skipped TS bridge framing check (WebViewBridge.ts not present)"
fi

# Check 4: Rust-side envelope size limit constant present
echo "4. Checking Rust-side envelope size limits..."
if grep -RInE "MAX_ENVELOPE_BYTES|MAX_OP_BYTES_LEN" --include="*.rs" "$REPO_ROOT/dsm_client/deterministic_state_machine" 2>/dev/null | grep -q "const "; then
    report_success "Rust-side envelope size limit constants enforced"
else
    report_violation "MISSING RUST SIZE LIMIT" "Expected MAX_ENVELOPE_BYTES or MAX_OP_BYTES_LEN const in Rust side."
fi

# Check 5: Exactly one Android WebView bridge class (SinglePathWebViewBridge)
echo "5. Checking for single Android bridge class..."
BRIDGE_CLASS_COUNT=$(grep -RIn "class .*WebViewBridge" --include="*.kt" "$REPO_ROOT/dsm_client/android/app/src/main/java/" 2>/dev/null | wc -l | awk '{print $1}')
if [ "$BRIDGE_CLASS_COUNT" -ne 1 ] || ! grep -RInE "class[[:space:]]+SinglePathWebViewBridge" "$REPO_ROOT/dsm_client/android/app/src/main/java/" >/dev/null 2>&1; then
    report_violation "MULTIPLE BRIDGE INSTANCES" "Expected exactly one production WebView bridge class named SinglePathWebViewBridge."
else
    report_success "Single SinglePathWebViewBridge class enforced"
fi

# Check 6: No BLE CustomEvent shim in frontend
echo "6. Checking for BLE CustomEvent shim..."
if [ -d "$REPO_ROOT/dsm_client/frontend/src" ] && \
   grep -RInE "addEventListener\('dsm-ble'|dispatchEvent\(new CustomEvent\('dsm-ble'" "$REPO_ROOT/dsm_client/frontend/src/" 2>/dev/null | grep -q .; then
    report_violation "BLE CUSTOMEVENT SHIM" "Remove 'dsm-ble' CustomEvent usage; rely on protobuf envelope push."
else
    report_success "No BLE CustomEvent shim usage in frontend"
fi

# Check 7: No Android onBleEvent JSON fallback
echo "7. Checking for Android onBleEvent fallback..."
if grep -RInF "onBleEvent(" "$REPO_ROOT/dsm_client/android/app/src/main/java/" 2>/dev/null | grep -q .; then
    report_violation "ANDROID JSON BLE FALLBACK" "Found onBleEvent(String). Remove JSON BLE path."
else
    report_success "Android JSON BLE fallback not present"
fi

# Check 8: No 'dsm-ble' string usage in code paths
echo "8. Checking for 'dsm-ble' usage across code paths..."
if search_in_code_dirs "dsm-ble" ""; then
    report_violation "FORBIDDEN 'dsm-ble' USAGE" "Remove BLE CustomEvent name from code paths."
else
    report_success "No 'dsm-ble' usage in code paths"
fi

# Check 9: No legacy bridge references in code paths
echo "9. Checking for legacy bridge references (code paths only)..."
if search_in_code_dirs "ProtobufBridge|ProtobufJsBridge|bridge\\.proto|DSM_BRIDGE_PORT" "print"; then
    report_violation "FORBIDDEN BRIDGE REFERENCES" "Remove or update legacy bridge references in code paths."
else
    report_success "No legacy bridge references in code paths"
fi

# Check 10: No legacy ProtobufBridge.ts file
echo "10. Checking for ProtobufBridge file..."
if [ -f "$REPO_ROOT/dsm_client/frontend/src/bridge/ProtobufBridge.ts" ]; then
    report_violation "FORBIDDEN FILE PRESENT" "dsm_client/frontend/src/bridge/ProtobufBridge.ts should be removed."
else
    report_success "ProtobufBridge file not present"
fi

# Check 11: No stale Android WebViewBridgeTest.kt
echo "11. Checking for legacy Android WebViewBridgeTest..."
if [ -f "$REPO_ROOT/dsm_client/android/app/src/androidTest/java/com/dsm/wallet/WebViewBridgeTest.kt" ]; then
    report_violation "FORBIDDEN TEST PRESENT" "dsm_client/android/app/src/androidTest/java/com/dsm/wallet/WebViewBridgeTest.kt should be removed."
else
    report_success "Legacy Android WebViewBridgeTest not present"
fi

# Informational: non-fatal docs scan
echo "12. Info: scanning docs for legacy bridge mentions (non-fatal)..."
if grep -RInE "ProtobufBridge|bridge\.proto|DSM_BRIDGE_PORT" "$REPO_ROOT/docs" "$REPO_ROOT/README.md" "$REPO_ROOT"/*.md 2>/dev/null | head -n 5 | grep -q .; then
    echo -e "${YELLOW}Note:${NC} Legacy bridge terms referenced in docs—safe to clean up later."
fi

echo ""
echo "============================="
if [ $VIOLATIONS -eq 0 ]; then
    echo -e "${GREEN}🎉 ALL GUARDRAILS PASSED${NC}"
    echo "Fork architecture invariants enforced."
    exit 0
else
    echo -e "${RED}💥 $VIOLATIONS GUARDRAILS VIOLATIONS FOUND${NC}"
    echo "Fix violations before proceeding."
    exit 1
fi
