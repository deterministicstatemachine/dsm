#!/bin/bash
# DSM Guardrails Enforcement Script
# Enforces single execution path and forbids alternative communication methods

set -e

# Resolve repo root so the script can be run from any working directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "🔒 DSM Guardrails Enforcement"
echo "============================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to report violations
report_violation() {
    echo -e "${RED}❌ VIOLATION: $1${NC}"
    echo "   $2"
    VIOLATIONS=$((VIOLATIONS + 1))
}

# Function to report success
report_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

VIOLATIONS=0

# Code directories to scan (sources only). Keep this definition BEFORE any checks that use it.
CODE_DIRS=(
    "$REPO_ROOT/dsm_client/new_frontend/src"
    "$REPO_ROOT/dsm_client/android/app/src"
    "$REPO_ROOT/dsm_client/deterministic_state_machine"
    "$REPO_ROOT/dsm_storage_node"
)

# Portable find + grep helper: search pattern in CODE_DIRS while excluding common build/output dirs
search_in_code_dirs() {
    local pattern="$1"
    local print_matches="$2" # if non-empty, print first few matches
    local found=1
    for d in "${CODE_DIRS[@]}"; do
        [ -d "$d" ] || continue
        # Exclude build outputs: target, node_modules, dist, build, .gradle, .git, out
        # BSD find (macOS) syntax compatible
        local matches
        matches=$(find "$d" \
            -type d \( -name target -o -name node_modules -o -name dist -o -name build -o -name .gradle -o -name .git -o -name out \) -prune \
            -o -type f -print \
            | xargs grep -I -nE "$pattern" 2>/dev/null || true)
        # Exclude Android assets JS bundles (bundled build output)
        matches=$(echo "$matches" | grep -v "/dsm_client/android/app/src/main/assets/js/")
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

echo "Checking for forbidden communication methods..."

# Check 1: Forbid alternative JS interface injections (allow only DsmBridge and Voice)
echo "1. Checking JNI bridge methods..."
if grep -RIn "addJavascriptInterface(" --include="*.java" --include="*.kt" "$REPO_ROOT/dsm_client/android/app/src/main/java/" 2>/dev/null | \
     grep -v "DsmBridge" | grep -v "Voice" >/dev/null; then
    report_violation "FORBIDDEN JNI METHOD" "Found addJavascriptInterface other than allowed aliases (DsmBridge, Voice)."
else
    report_success "JNI methods compliant - only single path allowed"
fi

# Check 2: Forbid direct WebView bridge calls in TypeScript
echo "2. Checking TypeScript WebView bridge usage..."
# macOS grep doesn't support PCRE lookaheads; use a simpler include/exclude pipeline.
if [ -d "$REPO_ROOT/dsm_client/new_frontend/src" ] && \
   grep -RIn "window\\.DsmBridge\\." --include="*.ts" --include="*.tsx" "$REPO_ROOT/dsm_client/new_frontend/src" 2>/dev/null | \
   grep -v -F 'sendMessage("dsm.send")' | \
   grep -v "/setupTests.ts" >/dev/null; then
    report_violation "FORBIDDEN DIRECT BRIDGE CALL" "Found direct WebView bridge calls. Must use MCP browser adapter."
else
    report_success "TypeScript bridge usage compliant"
fi

# Check 3: Ensure MCP browser adapter is the only bridge interface
echo "3. Checking MCP browser adapter usage..."
# Only enforce if DsmClient.ts exists in expected location
if [ -f "$REPO_ROOT/dsm_client/new_frontend/src/services/DsmClient.ts" ]; then
    if ! grep -qE "dsm-mcp.*browser|packages/dsm-mcp/src/browser/index" "$REPO_ROOT/dsm_client/new_frontend/src/services/DsmClient.ts"; then
      report_violation "MISSING MCP ADAPTER" "DsmClient must import and use MCP browser adapter"
  else
      report_success "MCP browser adapter properly integrated"
  fi
else
  report_success "Skipped MCP adapter check (frontend services file not present)"
fi

# Check 4: Forbid JSON-based communication
echo "4. Checking for JSON communication patterns (frontend services)..."
if [ -d "$REPO_ROOT/dsm_client/new_frontend/src/services" ] && \
   grep -RInE '\\.stringify\(|\\.parse\(' --include="*.ts" --include="*.tsx" "$REPO_ROOT/dsm_client/new_frontend/src/services/" 2>/dev/null | grep -v "temporary\|TODO"; then
    report_violation "FORBIDDEN JSON COMMUNICATION" "Found JSON serialization. Must use protobuf envelopes only."
else
    report_success "No JSON communication patterns found"
fi

# Check 5: Ensure protobuf envelope size limits
echo "5. Checking protobuf envelope size enforcement..."
BRIDGE_FILE=$(find "$REPO_ROOT/dsm_client/android/app/src" -name "SinglePathWebViewBridge.kt" -print -quit 2>/dev/null || true)
if [ -n "$BRIDGE_FILE" ]; then
  if ! grep -qE "256.*KiB|256.*KB" "$BRIDGE_FILE"; then
      report_violation "MISSING SIZE LIMIT" "Protobuf envelope size limit (256 KiB) not enforced"
  else
      report_success "Envelope size limits enforced"
  fi
else
  report_success "Skipped size limit check (bridge file not found)"
fi

# Check 6: Ensure envelope version validation
echo "6. Checking envelope version validation..."
if [ -n "$BRIDGE_FILE" ]; then
    if grep -qE "ENVELOPE_VERSION\s*=\s*2" "$BRIDGE_FILE" && grep -q "version != ENVELOPE_VERSION" "$BRIDGE_FILE"; then
        report_success "Envelope version validation enforced"
    else
        report_violation "MISSING VERSION VALIDATION" "Envelope version validation (must be 2) not enforced"
    fi
else
  report_success "Skipped version validation check (bridge file not found)"
fi

# Check 7: Forbid multiple WebView bridge instances
echo "7. Checking for multiple bridge instances..."
BRIDGE_CLASS_COUNT=$(grep -RIn "class .*WebViewBridge" --include="*.kt" "$REPO_ROOT/dsm_client/android/app/src/main/java/" 2>/dev/null | wc -l | awk '{print $1}')
if [ "$BRIDGE_CLASS_COUNT" -ne 1 ] || ! grep -RIn "class\s\+SinglePathWebViewBridge" "$REPO_ROOT/dsm_client/android/app/src/main/java/" >/dev/null 2>&1; then
    report_violation "MULTIPLE BRIDGE INSTANCES" "Expected exactly one WebView bridge class named SinglePathWebViewBridge."
else
    report_success "Single bridge instance enforced"
fi

# Check 8: Ensure no forbidden bridge imports
echo "8. Checking for forbidden bridge imports..."
if [ -d "$REPO_ROOT/dsm_client/new_frontend/src" ] && \
   grep -RInE "import.*DsmBridge|import.*WebViewBridge" --include="*.ts" --include="*.tsx" "$REPO_ROOT/dsm_client/new_frontend/src/" 2>/dev/null | grep -v "dsm-mcp"; then
    report_violation "FORBIDDEN BRIDGE IMPORTS" "Found forbidden bridge imports. Must use MCP browser adapter only."
else
    report_success "No forbidden bridge imports found"
fi

# 9: Forbid BLE CustomEvent shim usage in frontend (must use subscription)
echo "9. Checking for BLE CustomEvent shim and JNI fallback names..."
if [ -d "$REPO_ROOT/dsm_client/new_frontend/src" ] && \
   grep -RInE "addEventListener\('dsm-ble'|dispatchEvent\(new CustomEvent\('dsm-ble'" "$REPO_ROOT/dsm_client/new_frontend/src/" 2>/dev/null; then
    report_violation "BLE CUSTOMEVENT SHIM" "Remove 'dsm-ble' CustomEvent usage; rely on protobuf envelope push."
else
    report_success "No BLE CustomEvent shim usage detected in frontend."
fi

# 11: Forbid Android JSON BLE fallback method name
echo "11. Checking for Android onBleEvent fallback..."
if grep -RInF "onBleEvent(" "$REPO_ROOT/dsm_client/android/app/src/main/java/" 2>/dev/null; then
    report_violation "ANDROID JSON BLE FALLBACK" "Found onBleEvent(String). Remove JSON BLE path."
else
    report_success "Android JSON BLE fallback not present."
fi

# 12: Forbid 'dsm-ble' usage in code paths (ignore built artifacts)
echo "12. Checking for 'dsm-ble' usage across code paths..."
if search_in_code_dirs "dsm-ble" ""; then
    # search_in_code_dirs returns 0 when found
    report_violation "FORBIDDEN 'dsm-ble' USAGE" "Remove BLE CustomEvent name from code paths."
else
    report_success "No 'dsm-ble' usage detected in code paths."
fi

# 13: Flag bridge references
echo "13. Checking for bridge references (code paths only)..."
# Only scan code directories to avoid flagging historical docs/assets; also exclude build outputs
if search_in_code_dirs "ProtobufBridge|ProtobufJsBridge|bridge\\.proto|DSM_BRIDGE_PORT" "print"; then
    report_violation "FORBIDDEN BRIDGE REFERENCES" "Remove or update bridge references in code paths. (See matches above)"
else
    report_success "No forbidden bridge references in code paths."
fi

# Optional: Informational scan over docs/scripts (non-fatal)
echo "13b. Info: scanning docs/scripts for bridge mentions (non-fatal)..."
if grep -RInE "ProtobufBridge|bridge\.proto|DSM_BRIDGE_PORT" "$REPO_ROOT/docs" "$REPO_ROOT/README.md" "$REPO_ROOT"/*.md "$REPO_ROOT/dsm_client/android"/*.md "$REPO_ROOT/dsm_client/android/app"/*.md 2>/dev/null | head -n 5; then
    echo -e "${YELLOW}Note:${NC} Bridge terms referenced in docs—safe to clean up later."
fi

# 10: Flag presence of ProtobufBridge file if still in tree
echo "10. Checking for ProtobufBridge file..."
if [ -f "$REPO_ROOT/dsm_client/new_frontend/src/bridge/ProtobufBridge.ts" ]; then
    report_violation "FORBIDDEN FILE PRESENT" "dsm_client/new_frontend/src/bridge/ProtobufBridge.ts should be removed."
else
    report_success "ProtobufBridge file not present."
fi

# 10b: Flag presence of Android WebViewBridge test
echo "10b. Checking for Android WebViewBridge test..."
if [ -f "$REPO_ROOT/dsm_client/android/app/src/androidTest/java/com/dsm/wallet/WebViewBridgeTest.kt" ]; then
    report_violation "FORBIDDEN TEST PRESENT" "dsm_client/android/app/src/androidTest/java/com/dsm/wallet/WebViewBridgeTest.kt should be removed."
else
    report_success "Android WebViewBridge test not present."
fi

echo ""
echo "============================="
if [ $VIOLATIONS -eq 0 ]; then
    echo -e "${GREEN}🎉 ALL GUARDRAILS PASSED${NC}"
    echo "Single execution path properly enforced."
    exit 0
else
    echo -e "${RED}💥 $VIOLATIONS GUARDRAILS VIOLATIONS FOUND${NC}"
    echo "Fix violations before proceeding."
    exit 1
fi
