#!/bin/bash

# DSM Logcat Filters - Predefined filters for monitoring DSM on Android devices

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

show_usage() {
    echo "DSM Logcat Filters - Monitor DSM logs on Android devices"
    echo ""
    echo "Usage: $0 [filter]"
    echo ""
    echo "Available filters:"
    echo "  all          - All DSM-related logs"
    echo "  main         - MainActivity and app lifecycle"
    echo "  bridge       - JavaScript-Kotlin bridge interactions"
    echo "  jni          - JNI method calls and native interactions"
    echo "  rust         - Rust native library logs"
    echo "  webview      - WebView events and console messages"
    echo "  network      - Network operations and HTTP requests"
    echo "  performance  - Performance metrics and timing"
    echo "  errors       - Error messages and exceptions only"
    echo "  so-loading   - Native library (.so) loading events"
    echo "  crypto       - Cryptographic operations"
    echo "  bluetooth    - Bluetooth connectivity"
    echo "  custom       - Show custom filter examples"
    echo ""
    echo "Examples:"
    echo "  $0 all          # Monitor all DSM logs"
    echo "  $0 errors       # Show only errors"
    echo "  $0 bridge       # Monitor bridge interactions"
}

# Filter functions
filter_all() {
    log_info "Monitoring ALL DSM logs..."
    adb logcat -v threadtime | grep -E "(DSM_|DsmBridge|MainActivity|UnifiedDsmBridge|libdsm_sdk)"
}

filter_main() {
    log_info "Monitoring MainActivity and app lifecycle..."
    adb logcat -v threadtime | grep -E "(DSM_MAIN|MainActivity)"
}

filter_bridge() {
    log_info "Monitoring JavaScript-Kotlin bridge interactions..."
    adb logcat -v threadtime | grep -E "(DSM_BRIDGE|DsmBridge|UnifiedDsmBridge)"
}

filter_jni() {
    log_info "Monitoring JNI method calls and native interactions..."
    adb logcat -v threadtime | grep -E "(DSM_JNI|JNI)"
}

filter_rust() {
    log_info "Monitoring Rust native library logs..."
    adb logcat -v threadtime | grep -E "(DSM_RUST)"
}

filter_webview() {
    log_info "Monitoring WebView events and console messages..."
    adb logcat -v threadtime | grep -E "(DSM_WEBVIEW|chromium|CrWebView)"
}

filter_network() {
    log_info "Monitoring network operations and HTTP requests..."
    adb logcat -v threadtime | grep -E "(DSM_NETWORK|HTTP|IOException|ConnectException)"
}

filter_performance() {
    log_info "Monitoring performance metrics and timing..."
    adb logcat -v threadtime | grep -E "(DSM_PERF|Performance)"
}

filter_errors() {
    log_info "Monitoring ERROR messages and exceptions only..."
    adb logcat -v threadtime | grep -E "(DSM_ERROR|ERROR|FATAL|Exception|Error)"
}

filter_so_loading() {
    log_info "Monitoring native library (.so) loading events..."
    adb logcat -v threadtime | grep -E "(DSM_SO_LOADING|libdsm_sdk|UnsatisfiedLinkError|\.so)"
}

filter_crypto() {
    log_info "Monitoring cryptographic operations..."
    adb logcat -v threadtime | grep -E "(DSM_CRYPTO|crypto|encryption|key)"
}

filter_bluetooth() {
    log_info "Monitoring Bluetooth connectivity..."
    adb logcat -v threadtime | grep -E "(DSM_BLUETOOTH|Bluetooth|BLE)"
}

show_custom_examples() {
    echo -e "${CYAN}Custom Filter Examples:${NC}"
    echo ""
    echo "1. Monitor specific log levels:"
    echo "   adb logcat -v threadtime '*:E'  # Errors only"
    echo "   adb logcat -v threadtime '*:W'  # Warnings and above"
    echo "   adb logcat -v threadtime '*:I'  # Info and above"
    echo ""
    echo "2. Multiple tag filtering:"
    echo "   adb logcat -v threadtime | grep -E '(DSM_MAIN|DSM_BRIDGE)'"
    echo ""
    echo "3. Exclude unwanted logs:"
    echo "   adb logcat -v threadtime | grep DSM_ | grep -v DEBUG"
    echo ""
    echo "4. Time-based filtering:"
    echo "   adb logcat -v threadtime -T '01-01 12:00:00.000'"
    echo ""
    echo "5. Save to file while monitoring:"
    echo "   adb logcat -v threadtime | tee dsm_logs.txt | grep DSM_"
    echo ""
    echo "6. Monitor specific process:"
    echo "   adb logcat -v threadtime --pid=\$(adb shell pidof com.dsm.wallet)"
    echo ""
    echo "7. Real-time filtering with colors:"
    echo "   adb logcat -v threadtime | grep --color=always -E '(ERROR|WARN|INFO)'"
    echo ""
    echo "8. Buffer-specific logs:"
    echo "   adb logcat -b main -b system -b crash"
}

# Check if adb is available
check_adb() {
    if ! command -v adb &> /dev/null; then
        log_info "${RED}ERROR: adb not found. Please install Android SDK platform-tools${NC}"
        exit 1
    fi
    
    # Check for connected devices
    local devices=$(adb devices | grep -E "device$" | wc -l)
    if [ "$devices" -eq 0 ]; then
        log_info "${RED}ERROR: No Android devices connected. Please connect a device and enable USB debugging${NC}"
        exit 1
    fi
    
    log_info "Found $devices connected Android device(s)"
}

# Main execution
main() {
    local filter="${1:-help}"
    
    if [ "$filter" == "help" ] || [ "$filter" == "--help" ] || [ "$filter" == "-h" ]; then
        show_usage
        exit 0
    fi
    
    check_adb
    
    echo -e "${CYAN}DSM Logcat Filter - $filter${NC}"
    echo -e "${YELLOW}Press Ctrl+C to stop monitoring${NC}"
    echo ""
    
    case "$filter" in
        "all")
            filter_all
            ;;
        "main")
            filter_main
            ;;
        "bridge")
            filter_bridge
            ;;
        "jni")
            filter_jni
            ;;
        "rust")
            filter_rust
            ;;
        "webview")
            filter_webview
            ;;
        "network")
            filter_network
            ;;
        "performance")
            filter_performance
            ;;
        "errors")
            filter_errors
            ;;
        "so-loading")
            filter_so_loading
            ;;
        "crypto")
            filter_crypto
            ;;
        "bluetooth")
            filter_bluetooth
            ;;
        "custom")
            show_custom_examples
            ;;
        *)
            echo -e "${RED}Unknown filter: $filter${NC}"
            echo ""
            show_usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
