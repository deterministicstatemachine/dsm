#!/bin/bash

# DSM Android Device Testing Script with Comprehensive Logging
# This script sets up, builds, deploys, and monitors DSM on real Android devices

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR/.."
ANDROID_DIR="$PROJECT_ROOT/dsm_client/android"
FRONTEND_DIR="$PROJECT_ROOT/dsm_client/frontend"
RUST_DIR="$PROJECT_ROOT/dsm_client/deterministic_state_machine"
RUN_ID="run_$$"

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${CYAN}[STEP]${NC} $1"
}

log_rust() {
    echo -e "${YELLOW}🦀${NC} $1"
}

log_android() {
    echo -e "${GREEN}📱${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_step "Checking prerequisites for Android device testing..."
    
    # Check if adb is available
    if ! command -v adb &> /dev/null; then
        log_error "adb not found. Please install Android SDK platform-tools"
        exit 1
    fi
    
    # Check for connected devices
    local devices=$(adb devices | grep -E "device$" | wc -l)
    if [ "$devices" -eq 0 ]; then
        log_error "No Android devices connected. Please connect a device and enable USB debugging"
        exit 1
    fi
    
    log_info "Found $devices connected Android device(s)"
    
    # List connected devices with details
    log_info "Connected devices:"
    adb devices -l | grep -E "device" | while read line; do
        log_info "  $line"
    done
    
    # Check if Rust is available
    if ! command -v cargo &> /dev/null; then
        log_error "Cargo not found. Please install Rust"
        exit 1
    fi
    
    # Check if Node.js is available
    if ! command -v node &> /dev/null; then
        log_error "Node.js not found. Please install Node.js"
        exit 1
    fi
    
    # Check Android NDK
    if [ -z "$ANDROID_NDK_ROOT" ] && [ -z "$NDK_HOME" ]; then
        log_warn "ANDROID_NDK_ROOT or NDK_HOME not set. This may cause build issues."
    fi
    
    log_info "✅ All prerequisites check passed"
}

# Setup logging directories on device
setup_device_logging() {
    log_step "Setting up logging directories on Android device..."
    
    local device_id=$(adb devices | grep -E "device$" | head -1 | awk '{print $1}')
    log_android "Setting up logging on device: $device_id"
    
    # Create logging directories
    adb shell "mkdir -p /sdcard/Android/data/com.dsm.wallet/files/logs"
    adb shell "mkdir -p /sdcard/dsm_logs"
    
    # Clear previous logs
    adb shell "rm -f /sdcard/dsm_logs/*"
    adb shell "rm -f /sdcard/Android/data/com.dsm.wallet/files/*log*"
    
    # Set up logcat filtering
    adb logcat -c  # Clear logcat buffer
    
    log_info "✅ Device logging setup complete"
}

# Build the project with comprehensive logging
build_project() {
    log_step "Building DSM project with comprehensive logging..."
    
    cd "$FRONTEND_DIR"
    
    # Run the nuclear build script
    log_info "Running nuclear build and deploy script..."
    node scripts/build-and-deploy-nuclear.js
    
    log_info "✅ Project build complete"
}

# Build and install Android APK
build_and_install_apk() {
    log_step "Building and installing Android APK..."
    
    cd "$ANDROID_DIR"
    
    # Clean previous builds
    log_android "Cleaning previous builds..."
    ./gradlew clean
    
    # Build debug APK with full logging
    log_android "Building debug APK with comprehensive logging..."
    ./gradlew assembleDebug
    
    # Install APK
    log_android "Installing APK on device..."
    ./gradlew installDebug
    
    log_info "✅ APK build and installation complete"
}

# Setup real-time log monitoring
setup_log_monitoring() {
    log_step "Setting up real-time log monitoring..."
    
    local log_dir="$PROJECT_ROOT/device_logs"
    mkdir -p "$log_dir"
    
    local logcat_file="$log_dir/logcat_${RUN_ID}.log"
    local dsm_log_file="$log_dir/dsm_device_${RUN_ID}.log"
    
    log_info "Log files will be saved to:"
    log_info "  Logcat: $logcat_file"
    log_info "  DSM Device Log: $dsm_log_file"
    
    # Start logcat monitoring in background
    log_android "Starting logcat monitoring..."
    adb logcat -v threadtime | tee "$logcat_file" &
    local logcat_pid=$!
    
    # Start DSM-specific log monitoring
    log_android "Starting DSM-specific log monitoring..."
    adb logcat -v threadtime | grep -E "(DSM_|DsmBridge|MainActivity|UnifiedDsmBridge)" | tee "$dsm_log_file" &
    local dsm_log_pid=$!
    
    # Save PIDs for cleanup
    echo "$logcat_pid" > "$log_dir/logcat.pid"
    echo "$dsm_log_pid" > "$log_dir/dsm_log.pid"
    
    log_info "✅ Log monitoring started (PIDs: logcat=$logcat_pid, dsm=$dsm_log_pid)"
}

# Monitor .so file loading
monitor_so_files() {
    log_step "Monitoring native library (.so) loading..."
    
    log_rust "Checking .so files in APK..."
    local apk_path=$(find "$ANDROID_DIR/app/build/outputs/apk/debug" -name "*.apk" | head -1)
    
    if [ -f "$apk_path" ]; then
        log_info "APK found: $apk_path"
        
        # Extract and list .so files
        local temp_dir=$(mktemp -d)
        unzip -q "$apk_path" -d "$temp_dir"
        
        log_rust "Native libraries in APK:"
        find "$temp_dir" -name "*.so" | while read so_file; do
            local rel_path=$(echo "$so_file" | sed "s|$temp_dir/||")
            local size=$(ls -lh "$so_file" | awk '{print $5}')
            log_rust "  📄 $rel_path ($size)"
            
            # Check if it's a DSM library
            if [[ "$so_file" == *"dsm"* ]]; then
                log_rust "     ✅ DSM Library"
            fi
        done
        
        rm -rf "$temp_dir"
    else
        log_warn "APK not found for .so file inspection"
    fi
}

# Launch app and start testing
launch_app() {
    log_step "Launching DSM Wallet on device..."
    
    # Clear app data first
    log_android "Clearing app data..."
    adb shell pm clear com.dsm.wallet
    
    # Launch the app
    log_android "Launching DSM Wallet..."
    adb shell am start -n com.dsm.wallet/.ui.MainActivity
    
    # Wait for app to start
    sleep 3
    
    # Check if app is running
    local running=$(adb shell "ps | grep com.dsm.wallet" | wc -l)
    if [ "$running" -gt 0 ]; then
        log_info "✅ DSM Wallet is running on device"
    else
        log_error "❌ DSM Wallet failed to start"
        return 1
    fi
}

# Monitor app performance
monitor_performance() {
    log_step "Monitoring app performance..."
    
    local monitor_duration=30
    log_info "Monitoring performance for $monitor_duration seconds..."
    
    for i in $(seq 1 $monitor_duration); do
        # Get memory usage
        local mem_info=$(adb shell "dumpsys meminfo com.dsm.wallet | grep 'TOTAL'" | head -1)
        
        # Get CPU usage
        local cpu_info=$(adb shell "top -n 1 | grep com.dsm.wallet" | head -1)
        
        if [ ! -z "$mem_info" ]; then
            log_info "[$i/${monitor_duration}] Memory: $mem_info"
        fi
        
        if [ ! -z "$cpu_info" ]; then
            log_info "[$i/${monitor_duration}] CPU: $cpu_info"
        fi
        
        sleep 1
    done
    
    log_info "✅ Performance monitoring complete"
}

# Pull device logs
pull_device_logs() {
    log_step "Pulling logs from device..."
    
    local log_dir="$PROJECT_ROOT/device_logs"
    # Pull DSM device logs
    log_android "Pulling DSM device logs..."
    adb pull /sdcard/Android/data/com.dsm.wallet/files/ "$log_dir/device_files_${RUN_ID}/" 2>/dev/null || log_warn "No device files found"
    
    # Pull any additional logs
    adb pull /sdcard/dsm_logs/ "$log_dir/dsm_logs_${RUN_ID}/" 2>/dev/null || log_warn "No DSM logs found"
    
    # Get system logs
    log_android "Saving system information..."
    adb shell "getprop" > "$log_dir/device_properties_${RUN_ID}.txt"
    adb shell "cat /proc/cpuinfo" > "$log_dir/device_cpuinfo_${RUN_ID}.txt"
    adb shell "cat /proc/meminfo" > "$log_dir/device_meminfo_${RUN_ID}.txt"
    
    log_info "✅ Device logs pulled to $log_dir"
}

# Cleanup function
cleanup() {
    log_step "Cleaning up..."
    
    local log_dir="$PROJECT_ROOT/device_logs"
    
    # Stop log monitoring processes
    if [ -f "$log_dir/logcat.pid" ]; then
        local logcat_pid=$(cat "$log_dir/logcat.pid")
        kill $logcat_pid 2>/dev/null || true
        rm -f "$log_dir/logcat.pid"
        log_info "Stopped logcat monitoring (PID: $logcat_pid)"
    fi
    
    if [ -f "$log_dir/dsm_log.pid" ]; then
        local dsm_log_pid=$(cat "$log_dir/dsm_log.pid")
        kill $dsm_log_pid 2>/dev/null || true
        rm -f "$log_dir/dsm_log.pid"
        log_info "Stopped DSM log monitoring (PID: $dsm_log_pid)"
    fi
    
    log_info "✅ Cleanup complete"
}

# Main execution
main() {
    echo -e "${MAGENTA}☢️  DSM Android Device Testing with Comprehensive Logging${NC}"
    echo -e "${BLUE}=========================================================${NC}"
    
    # Set up cleanup trap
    trap cleanup EXIT
    
    check_prerequisites
    setup_device_logging
    build_project
    build_and_install_apk
    monitor_so_files
    setup_log_monitoring
    launch_app
    
    # Give user option to monitor performance
    echo ""
    read -p "Do you want to monitor app performance? (y/n): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        monitor_performance
    fi
    
    # Keep monitoring until user decides to stop
    echo ""
    log_info "App is running with full logging. Press Enter to stop monitoring and pull logs..."
    read
    
    pull_device_logs
    
    echo ""
    log_info "🚀 DSM Android device testing complete!"
    log_info "Check the device_logs directory for all collected logs"
}

# Run main function
main "$@"
