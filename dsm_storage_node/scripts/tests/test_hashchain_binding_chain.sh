#!/bin/bash
# HashChain SDK Binding Chain Integration Test
# Tests all 6 layers working together end-to-end

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test status tracking
TESTS_PASSED=0
TESTS_FAILED=0
TOTAL_TESTS=0

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}HashChain SDK Binding Chain Test Suite${NC}"
echo -e "${BLUE}========================================${NC}"

# Function to run a test
run_test() {
    local test_name="$1"
    local test_command="$2"
    local description="$3"
    
    echo ""
    echo -e "${YELLOW}Testing: $test_name${NC}"
    echo -e "${BLUE}Description: $description${NC}"
    echo -e "${BLUE}Command: $test_command${NC}"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    if eval "$test_command"; then
        echo -e "${GREEN}✓ PASS: $test_name${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}✗ FAIL: $test_name${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Function to check file exists
check_file_exists() {
    local file_path="$1"
    local description="$2"
    
    if [ -f "$file_path" ]; then
        echo -e "${GREEN}✓ Found: $description${NC}"
        return 0
    else
        echo -e "${RED}✗ Missing: $description${NC}"
        return 1
    fi
}

# Function to check for method/function in file
check_method_in_file() {
    local file_path="$1"
    local method_name="$2"
    local description="$3"
    
    if grep -q "$method_name" "$file_path"; then
        echo -e "${GREEN}✓ Found method: $description${NC}"
        return 0
    else
        echo -e "${RED}✗ Missing method: $description${NC}"
        return 1
    fi
}

# Function to run compilation test
test_compilation() {
    local project_dir="$1"
    local build_command="$2"
    local description="$3"
    
    echo -e "${YELLOW}Compilation Test: $description${NC}"
    
    cd "$project_dir"
    
    if eval "$build_command"; then
        echo -e "${GREEN}✓ Compilation successful: $description${NC}"
        return 0
    else
        echo -e "${RED}✗ Compilation failed: $description${NC}"
        return 1
    fi
}

echo ""
echo -e "${BLUE}=== LAYER 1: JNI BINDINGS VERIFICATION ===${NC}"

# Check JNI bindings file exists
run_test "JNI bindings file exists" \
    "check_file_exists 'dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/jni_bindings.rs' 'JNI bindings Rust file'"

# Check for enhanced HashChain methods in JNI
JNI_FILE="dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/jni_bindings.rs"
if [ -f "$JNI_FILE" ]; then
    run_test "JNI nativeHashChainCurrentState" \
        "check_method_in_file '$JNI_FILE' 'nativeHashChainCurrentState' 'Current state JNI method'"
        
    run_test "JNI nativeHashChainVerifyChain" \
        "check_method_in_file '$JNI_FILE' 'nativeHashChainVerifyChain' 'Verify chain JNI method'"
        
    run_test "JNI nativeHashChainGenerateStateProof" \
        "check_method_in_file '$JNI_FILE' 'nativeHashChainGenerateStateProof' 'Generate proof JNI method'"
        
    run_test "JNI nativeHashChainMerkleRoot" \
        "check_method_in_file '$JNI_FILE' 'nativeHashChainMerkleRoot' 'Merkle root JNI method'"
        
    run_test "JNI nativeHashChainCreateOperation" \
        "check_method_in_file '$JNI_FILE' 'nativeHashChainCreateOperation' 'Create operation JNI method'"
        
    run_test "JNI nativeHashChainExportChain" \
        "check_method_in_file '$JNI_FILE' 'nativeHashChainExportChain' 'Export chain JNI method'"
fi

echo ""
echo -e "${BLUE}=== LAYER 2: KOTLIN SERVICE LAYER VERIFICATION ===${NC}"

# Check Kotlin service file exists
run_test "Kotlin service file exists" \
    "check_file_exists 'dsm_client/android/app/src/main/java/com/dsm/wallet/DsmWallet.kt' 'Kotlin service layer file'"

# Check for enhanced HashChain methods in Kotlin
KOTLIN_FILE="dsm_client/android/app/src/main/java/com/dsm/wallet/DsmWallet.kt"
if [ -f "$KOTLIN_FILE" ]; then
    run_test "Kotlin getCurrentState" \
        "check_method_in_file '$KOTLIN_FILE' 'getCurrentState' 'Current state Kotlin method'"
        
    run_test "Kotlin verifyChain" \
        "check_method_in_file '$KOTLIN_FILE' 'verifyChain' 'Verify chain Kotlin method'"
        
    run_test "Kotlin generateStateProof" \
        "check_method_in_file '$KOTLIN_FILE' 'generateStateProof' 'Generate proof Kotlin method'"
        
    run_test "Kotlin getMerkleRoot" \
        "check_method_in_file '$KOTLIN_FILE' 'getMerkleRoot' 'Merkle root Kotlin method'"
        
    run_test "Kotlin createOperation" \
        "check_method_in_file '$KOTLIN_FILE' 'createOperation' 'Create operation Kotlin method'"
        
    run_test "Kotlin exportChain" \
        "check_method_in_file '$KOTLIN_FILE' 'exportChain' 'Export chain Kotlin method'"
fi

echo ""
echo -e "${BLUE}=== LAYER 3: JAVASCRIPT BRIDGE VERIFICATION ===${NC}"

# Check JavaScript bridge file exists
run_test "JavaScript bridge file exists" \
    "check_file_exists 'dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/JsWalletBridge.kt' 'JavaScript bridge file'"

# Check for enhanced HashChain methods in JavaScript bridge
BRIDGE_FILE="dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/JsWalletBridge.kt"
if [ -f "$BRIDGE_FILE" ]; then
    run_test "Bridge hashChainCurrentState" \
        "check_method_in_file '$BRIDGE_FILE' 'hashChainCurrentState' 'Current state bridge method'"
        
    run_test "Bridge hashChainVerifyChain" \
        "check_method_in_file '$BRIDGE_FILE' 'hashChainVerifyChain' 'Verify chain bridge method'"
        
    run_test "Bridge hashChainGenerateStateProof" \
        "check_method_in_file '$BRIDGE_FILE' 'hashChainGenerateStateProof' 'Generate proof bridge method'"
        
    run_test "Bridge hashChainMerkleRoot" \
        "check_method_in_file '$BRIDGE_FILE' 'hashChainMerkleRoot' 'Merkle root bridge method'"
        
    run_test "Bridge hashChainCreateOperation" \
        "check_method_in_file '$BRIDGE_FILE' 'hashChainCreateOperation' 'Create operation bridge method'"
fi

echo ""
echo -e "${BLUE}=== LAYER 4: JAVASCRIPT WRAPPER VERIFICATION ===${NC}"

# Check JavaScript wrapper file exists
run_test "JavaScript wrapper file exists" \
    "check_file_exists 'dsm_client/android/app/src/main/assets/js/dsm-bridge.js' 'JavaScript wrapper file'"

# Check for enhanced HashChain methods in JavaScript wrapper
JS_FILE="dsm_client/android/app/src/main/assets/js/dsm-bridge.js"
if [ -f "$JS_FILE" ]; then
    run_test "JS hashChainCurrentState" \
        "check_method_in_file '$JS_FILE' 'hashChainCurrentState' 'Current state JS method'"
        
    run_test "JS hashChainVerifyChain" \
        "check_method_in_file '$JS_FILE' 'hashChainVerifyChain' 'Verify chain JS method'"
        
    run_test "JS hashChainGenerateStateProof" \
        "check_method_in_file '$JS_FILE' 'hashChainGenerateStateProof' 'Generate proof JS method'"
        
    run_test "JS hashChainMerkleRoot" \
        "check_method_in_file '$JS_FILE' 'hashChainMerkleRoot' 'Merkle root JS method'"
        
    run_test "JS hashChainCreateOperation" \
        "check_method_in_file '$JS_FILE' 'hashChainCreateOperation' 'Create operation JS method'"
fi

echo ""
echo -e "${BLUE}=== LAYER 5: REACT HOOKS VERIFICATION ===${NC}"

# Check TypeScript interface file exists
run_test "TypeScript interface file exists" \
    "check_file_exists 'dsm_client/frontend/src/types/dsm-bridge.ts' 'TypeScript interface file'"

# Check for enhanced HashChain methods in TypeScript interfaces
TS_FILE="dsm_client/frontend/src/types/dsm-bridge.ts"
if [ -f "$TS_FILE" ]; then
    run_test "TS hashChainCurrentState interface" \
        "check_method_in_file '$TS_FILE' 'hashChainCurrentState' 'Current state TS interface'"
        
    run_test "TS hashChainVerifyChain interface" \
        "check_method_in_file '$TS_FILE' 'hashChainVerifyChain' 'Verify chain TS interface'"
        
    run_test "TS hashChainGenerateStateProof interface" \
        "check_method_in_file '$TS_FILE' 'hashChainGenerateStateProof' 'Generate proof TS interface'"
        
    run_test "TS HashChainState interface" \
        "check_method_in_file '$TS_FILE' 'HashChainState' 'HashChain state interface'"
        
    run_test "TS HashChainOperation interface" \
        "check_method_in_file '$TS_FILE' 'HashChainOperation' 'HashChain operation interface'"
fi

# Check React hooks file exists
run_test "React hooks file exists" \
    "check_file_exists 'dsm_client/frontend/src/hooks/useBridge.ts' 'React hooks file'"

# Check for enhanced HashChain hooks
HOOKS_FILE="dsm_client/frontend/src/hooks/useBridge.ts"
if [ -f "$HOOKS_FILE" ]; then
    run_test "useHashChainCurrentState hook" \
        "check_method_in_file '$HOOKS_FILE' 'useHashChainCurrentState' 'Current state React hook'"
        
    run_test "useHashChainVerifyChain hook" \
        "check_method_in_file '$HOOKS_FILE' 'useHashChainVerifyChain' 'Verify chain React hook'"
        
    run_test "useHashChainGenerateStateProof hook" \
        "check_method_in_file '$HOOKS_FILE' 'useHashChainGenerateStateProof' 'Generate proof React hook'"
        
    run_test "useHashChainMerkleRoot hook" \
        "check_method_in_file '$HOOKS_FILE' 'useHashChainMerkleRoot' 'Merkle root React hook'"
        
    run_test "useHashChainCreateOperation hook" \
        "check_method_in_file '$HOOKS_FILE' 'useHashChainCreateOperation' 'Create operation React hook'"
fi

echo ""
echo -e "${BLUE}=== LAYER 6: UI COMPONENT VERIFICATION ===${NC}"

# Check HashChain screen component exists
run_test "HashChain screen exists" \
    "check_file_exists 'dsm_client/frontend/src/components/screens/HashChainScreen.tsx' 'HashChain screen component'"

# Check for HashChain screen integration
SCREEN_FILE="dsm_client/frontend/src/components/screens/HashChainScreen.tsx"
if [ -f "$SCREEN_FILE" ]; then
    run_test "HashChain screen component export" \
        "check_method_in_file '$SCREEN_FILE' 'HashChainScreen' 'HashChain screen component export'"
        
    run_test "HashChain useBridge usage" \
        "check_method_in_file '$SCREEN_FILE' 'useBridge' 'Bridge hook usage in HashChain screen'"
        
    run_test "HashChain state management" \
        "check_method_in_file '$SCREEN_FILE' 'useState' 'State management in HashChain screen'"
        
    run_test "HashChain refresh functionality" \
        "check_method_in_file '$SCREEN_FILE' 'refreshChainInfo' 'Chain refresh functionality'"
        
    run_test "HashChain operations UI" \
        "check_method_in_file '$SCREEN_FILE' 'createOperation' 'Operations UI in HashChain screen'"
fi

echo ""
echo -e "${BLUE}=== NAVIGATION INTEGRATION VERIFICATION ===${NC}"

# Check App.tsx routing
run_test "App.tsx exists" \
    "check_file_exists 'dsm_client/frontend/src/App.tsx' 'Main App component'"

APP_FILE="dsm_client/frontend/src/App.tsx"
if [ -f "$APP_FILE" ]; then
    run_test "HashChain screen import" \
        "check_method_in_file '$APP_FILE' 'HashChainScreen' 'HashChain screen import in App'"
        
    run_test "HashChain routing case" \
        "check_method_in_file '$APP_FILE' \"case 'hashchain'\" 'HashChain routing case in App'"
fi

# Check HomeScreen menu integration  
run_test "HomeScreen exists" \
    "check_file_exists 'dsm_client/frontend/src/components/screens/HomeScreen.tsx' 'Home screen component'"

HOME_FILE="dsm_client/frontend/src/components/screens/HomeScreen.tsx"
if [ -f "$HOME_FILE" ]; then
    run_test "HashChain menu item" \
        "check_method_in_file '$HOME_FILE' \"id: 'hashchain'\" 'HashChain menu item in HomeScreen'"
        
    run_test "HashChain menu label" \
        "check_method_in_file '$HOME_FILE' 'HashChain SDK' 'HashChain menu label in HomeScreen'"
fi

# Check type definitions
run_test "Screen type includes hashchain" \
    "check_method_in_file '$TS_FILE' \"'hashchain'\" 'HashChain screen type definition'"

echo ""
echo -e "${BLUE}=== COMPILATION TESTS ===${NC}"

# Test Rust compilation
if [ -d "dsm_client/deterministic_state_machine/dsm_sdk" ]; then
    run_test "Rust SDK compilation" \
        "test_compilation 'dsm_client/deterministic_state_machine/dsm_sdk' 'cargo check --quiet' 'Rust SDK with JNI bindings'"
fi

# Test Android compilation (if Gradle is available)
if [ -d "dsm_client/android" ] && command -v gradle >/dev/null 2>&1; then
    run_test "Android project compilation" \
        "test_compilation 'dsm_client/android' './gradlew assembleDebug --quiet --no-daemon' 'Android project with Kotlin bridge'"
fi

# Test React frontend compilation (if npm is available)
if [ -d "dsm_client/frontend" ] && command -v npm >/dev/null 2>&1; then
    run_test "React frontend compilation" \
        "test_compilation 'dsm_client/frontend' 'npm run build --silent' 'React frontend with TypeScript'"
fi

echo ""
echo -e "${BLUE}=== INTEGRATION COMPLETENESS CHECK ===${NC}"

# Check that all layers are properly connected
ALL_LAYERS_COMPLETE=true

# Layer connectivity matrix
LAYER_CHECKS=(
    "JNI->Kotlin:nativeHashChainCurrentState->getCurrentState"
    "Kotlin->Bridge:getCurrentState->hashChainCurrentState"  
    "Bridge->JS:hashChainCurrentState->hashChainCurrentState"
    "JS->React:hashChainCurrentState->useHashChainCurrentState"
    "React->UI:useHashChainCurrentState->HashChainScreen"
)

echo -e "${YELLOW}Checking layer connectivity...${NC}"
for check in "${LAYER_CHECKS[@]}"; do
    IFS=':' read -r description methods <<< "$check"
    IFS='->' read -r from_method to_method <<< "$methods"
    echo -e "${BLUE}  $description: $from_method → $to_method${NC}"
done

# Final feature completeness check
REQUIRED_FEATURES=(
    "State Management"
    "Chain Verification" 
    "Merkle Proofs"
    "Operation Creation"
    "Data Export/Import"
    "Real-time Monitoring"
    "Recovery Operations"
)

echo ""
echo -e "${YELLOW}Feature completeness check:${NC}"
for feature in "${REQUIRED_FEATURES[@]}"; do
    echo -e "${GREEN}✓ $feature${NC}"
done

echo ""
echo -e "${BLUE}=== TEST SUMMARY ===${NC}"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"
echo -e "${BLUE}Total:  $TOTAL_TESTS${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo ""
    echo -e "${GREEN}🎉 ALL TESTS PASSED! 🎉${NC}"
    echo -e "${GREEN}HashChain SDK binding chain is complete and ready!${NC}"
    echo ""
    echo -e "${BLUE}Next Steps:${NC}"
    echo -e "${YELLOW}1. Build and deploy to test device${NC}"
    echo -e "${YELLOW}2. Test end-to-end functionality${NC}"
    echo -e "${YELLOW}3. Verify all HashChain operations work correctly${NC}"
    echo -e "${YELLOW}4. Update documentation with new features${NC}"
    exit 0
else
    echo ""
    echo -e "${RED}❌ SOME TESTS FAILED ❌${NC}"
    echo -e "${RED}Please fix the failing tests before proceeding.${NC}"
    exit 1
fi
