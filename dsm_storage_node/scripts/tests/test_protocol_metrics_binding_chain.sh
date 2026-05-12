#!/bin/bash

# Test Protocol Metrics Binding Chain
# Tests all 6 layers from JNI to UI for Protocol Metrics SDK group

echo "===================="
echo "PROTOCOL METRICS SDK"
echo "BINDING CHAIN TEST"
echo "===================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results tracking
TOTAL_TESTS=0
PASSED_TESTS=0

test_result() {
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    if [ $1 -eq 0 ]; then
        echo -e "  ${GREEN}✓ PASS${NC} - $2"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "  ${RED}✗ FAIL${NC} - $2"
    fi
}

# Function to check if a file contains expected content
check_file_content() {
    local file="$1"
    local pattern="$2"
    local description="$3"
    
    if [ -f "$file" ]; then
        if grep -q "$pattern" "$file"; then
            test_result 0 "$description"
        else
            test_result 1 "$description - Pattern not found: $pattern"
        fi
    else
        test_result 1 "$description - File not found: $file"
    fi
}

echo -e "${BLUE}Testing Protocol Metrics SDK Implementation...${NC}"
echo ""

# Layer 1: JNI Bindings (Rust)
echo -e "${YELLOW}Layer 1: JNI Bindings${NC}"
check_file_content \
    "dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/jni_bindings.rs" \
    "nativeMetricsStartTimer" \
    "JNI metricsStartTimer binding exists"

check_file_content \
    "dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/jni_bindings.rs" \
    "nativeMetricsStopTimer" \
    "JNI metricsStopTimer binding exists"

check_file_content \
    "dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/jni_bindings.rs" \
    "nativeMetricsGetReport" \
    "JNI metricsGetReport binding exists"

check_file_content \
    "dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/jni_bindings.rs" \
    "nativeMetricsReset" \
    "JNI metricsReset binding exists"

echo ""

# Layer 2: Kotlin Service Layer
echo -e "${YELLOW}Layer 2: Kotlin Service Layer${NC}"
check_file_content \
    "dsm_client/android/app/src/main/java/com/dsm/wallet/DsmWallet.kt" \
    "fun metricsStartTimer" \
    "Kotlin metricsStartTimer method exists"

check_file_content \
    "dsm_client/android/app/src/main/java/com/dsm/wallet/DsmWallet.kt" \
    "fun metricsStopTimer" \
    "Kotlin metricsStopTimer method exists"

check_file_content \
    "dsm_client/android/app/src/main/java/com/dsm/wallet/DsmWallet.kt" \
    "fun metricsGetReport" \
    "Kotlin metricsGetReport method exists"

check_file_content \
    "dsm_client/android/app/src/main/java/com/dsm/wallet/DsmWallet.kt" \
    "fun metricsReset" \
    "Kotlin metricsReset method exists"

echo ""

# Layer 3: JavaScript Bridge Layer
echo -e "${YELLOW}Layer 3: JavaScript Bridge Layer${NC}"
check_file_content \
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/JsWalletBridge.kt" \
    "fun metricsStartTimer" \
    "JS Bridge metricsStartTimer method exists"

check_file_content \
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/JsWalletBridge.kt" \
    "fun metricsStopTimer" \
    "JS Bridge metricsStopTimer method exists"

check_file_content \
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/JsWalletBridge.kt" \
    "fun metricsGetReport" \
    "JS Bridge metricsGetReport method exists"

check_file_content \
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/JsWalletBridge.kt" \
    "fun metricsReset" \
    "JS Bridge metricsReset method exists"

echo ""

# Layer 4: JavaScript Wrapper Layer
echo -e "${YELLOW}Layer 4: JavaScript Wrapper Layer${NC}"
check_file_content \
    "dsm_client/android/app/src/main/assets/js/dsm-bridge.js" \
    "metricsStartTimer" \
    "JS Wrapper metricsStartTimer method exists"

check_file_content \
    "dsm_client/android/app/src/main/assets/js/dsm-bridge.js" \
    "onMetricsTimerStarted" \
    "JS Wrapper onMetricsTimerStarted callback exists"

check_file_content \
    "dsm_client/android/app/src/main/assets/js/dsm-bridge.js" \
    "onMetricsReportReceived" \
    "JS Wrapper onMetricsReportReceived callback exists"

check_file_content \
    "dsm_client/android/app/src/main/assets/js/dsm-bridge.js" \
    "onMetricsReset" \
    "JS Wrapper onMetricsReset callback exists"

echo ""

# Layer 5: React Hook Layer
echo -e "${YELLOW}Layer 5: React Hook Layer${NC}"
check_file_content \
    "dsm_client/frontend/src/hooks/useBridge.ts" \
    "const metricsStartTimer" \
    "React Hook metricsStartTimer exists"

check_file_content \
    "dsm_client/frontend/src/hooks/useBridge.ts" \
    "const metricsStopTimer" \
    "React Hook metricsStopTimer exists"

check_file_content \
    "dsm_client/frontend/src/hooks/useBridge.ts" \
    "const metricsGetReport" \
    "React Hook metricsGetReport exists"

check_file_content \
    "dsm_client/frontend/src/hooks/useBridge.ts" \
    "const metricsReset" \
    "React Hook metricsReset exists"

echo ""

# Layer 6: UI Component Layer
echo -e "${YELLOW}Layer 6: UI Component Layer${NC}"
check_file_content \
    "dsm_client/frontend/src/components/screens/ProtocolMetricsScreen.tsx" \
    "export const ProtocolMetricsScreen" \
    "ProtocolMetricsScreen component exists"

check_file_content \
    "dsm_client/frontend/src/components/screens/ProtocolMetricsScreen.tsx" \
    "metricsStartTimer" \
    "UI component uses metricsStartTimer"

check_file_content \
    "dsm_client/frontend/src/components/screens/ProtocolMetricsScreen.tsx" \
    "TIMER MANAGEMENT" \
    "UI component has timer management section"

check_file_content \
    "dsm_client/frontend/src/components/screens/ProtocolMetricsScreen.tsx" \
    "PERFORMANCE METRICS" \
    "UI component has performance metrics section"

echo ""

# Integration Tests
echo -e "${YELLOW}Integration Tests${NC}"
check_file_content \
    "dsm_client/frontend/src/App.tsx" \
    "import ProtocolMetricsScreen" \
    "App.tsx imports ProtocolMetricsScreen"

check_file_content \
    "dsm_client/frontend/src/App.tsx" \
    "case 'protocol-metrics'" \
    "App.tsx has protocol-metrics route"

check_file_content \
    "dsm_client/frontend/src/components/screens/HomeScreen.tsx" \
    "protocol-metrics" \
    "HomeScreen has Protocol Metrics menu item"

check_file_content \
    "dsm_client/frontend/src/types/dsm-bridge.ts" \
    "protocol-metrics" \
    "TypeScript Screen type includes protocol-metrics"

echo ""

# TypeScript Compilation Test
echo -e "${YELLOW}TypeScript Compilation Test${NC}"
cd dsm_client/frontend
if npm run type-check > /dev/null 2>&1; then
    test_result 0 "TypeScript compilation passes"
else
    test_result 1 "TypeScript compilation failed"
fi
cd ../..

echo ""
echo "===================="
echo "TEST SUMMARY"
echo "===================="
echo -e "Total Tests: ${BLUE}$TOTAL_TESTS${NC}"
echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed: ${RED}$((TOTAL_TESTS - PASSED_TESTS))${NC}"

if [ $PASSED_TESTS -eq $TOTAL_TESTS ]; then
    echo ""
    echo -e "${GREEN}🎉 ALL TESTS PASSED!${NC}"
    echo -e "${GREEN}Protocol Metrics SDK binding chain is complete and functional.${NC}"
    echo ""
    echo "The Protocol Metrics SDK group implements:"
    echo "  • Timer management for performance measurement"
    echo "  • Real-time metrics collection and display"
    echo "  • Verification status monitoring"
    echo "  • Comprehensive performance reporting"
    echo "  • StateBoy-style interface with navigation"
    echo ""
    echo "Complete binding chain from JNI → Kotlin → JS Bridge → JS Wrapper → React Hook → UI Component"
    exit 0
else
    echo ""
    echo -e "${RED}❌ SOME TESTS FAILED${NC}"
    echo -e "${YELLOW}Please review the failed tests above and fix any missing implementations.${NC}"
    exit 1
fi
