#!/bin/bash
# Create and launch a 16 KB page size Android emulator for testing

set -e

AVD_NAME="DSM_Test_16KB"
SYSTEM_IMAGE="system-images;android-35;google_apis;x86_64"
DEVICE_TYPE="pixel_8"

echo "=== Setting up 16 KB Page Size Test Emulator ==="
echo

# Check if Android SDK is available
if ! command -v sdkmanager &> /dev/null; then
    echo "Error: sdkmanager not found. Please install Android SDK."
    echo "Expected path: $ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager"
    exit 1
fi

# Check if system image is installed
echo "1. Checking for Android 15 (API 35) system image..."
if sdkmanager --list_installed | grep -q "$SYSTEM_IMAGE"; then
    echo "   ✓ System image already installed"
else
    echo "   Installing system image (this may take a few minutes)..."
    yes | sdkmanager "$SYSTEM_IMAGE"
fi

# Check if AVD already exists
if avdmanager list avd | grep -q "Name: $AVD_NAME"; then
    echo
    echo "2. AVD '$AVD_NAME' already exists. Delete and recreate? (y/N)"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        avdmanager delete avd -n "$AVD_NAME"
    else
        echo "   Skipping AVD creation, using existing AVD"
        SKIP_CREATE=1
    fi
fi

if [ -z "$SKIP_CREATE" ]; then
    echo
    echo "2. Creating AVD '$AVD_NAME' with 16 KB page size support..."
    echo "no" | avdmanager create avd \
        -n "$AVD_NAME" \
        -k "$SYSTEM_IMAGE" \
        -d "$DEVICE_TYPE" \
        -c 6144M
    
    # Configure AVD for optimal performance
    AVD_CONFIG="$HOME/.android/avd/${AVD_NAME}.avd/config.ini"
    if [ -f "$AVD_CONFIG" ]; then
        echo "   Configuring AVD settings..."
        # Increase RAM to 4GB (required for 16 KB page size)
        sed -i.bak 's/hw.ramSize=.*/hw.ramSize=4096/' "$AVD_CONFIG" || \
            echo "hw.ramSize=4096" >> "$AVD_CONFIG"
        
        # Set VM heap
        sed -i.bak 's/vm.heapSize=.*/vm.heapSize=512/' "$AVD_CONFIG" || \
            echo "vm.heapSize=512" >> "$AVD_CONFIG"
    fi
fi

echo
echo "3. AVD '$AVD_NAME' ready for testing"
echo

# Offer to launch emulator
echo "Launch emulator now? (y/N)"
read -r response
if [[ "$response" =~ ^[Yy]$ ]]; then
    echo
    echo "Starting emulator (this may take a minute)..."
    echo "Press Ctrl+C to stop"
    echo
    
    # Launch emulator
    emulator -avd "$AVD_NAME" \
        -no-snapshot-save \
        -wipe-data \
        -gpu host &
    
    EMULATOR_PID=$!
    
    # Wait for device to boot
    echo "Waiting for emulator to boot..."
    adb wait-for-device
    
    # Wait for boot to complete
    while [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" != "1" ]; do
        sleep 1
    done
    
    echo
    echo "✓ Emulator booted successfully"
    echo
    
    # Verify page size
    PAGE_SIZE=$(adb shell getconf PAGE_SIZE 2>/dev/null | tr -d '\r')
    echo "Verification:"
    echo "  Page size: $PAGE_SIZE bytes"
    
    if [ "$PAGE_SIZE" = "16384" ]; then
        echo "  ✓ 16 KB page size confirmed"
    else
        echo "  ⚠ Warning: Expected 16384, got $PAGE_SIZE"
        echo "  This system image may not support 16 KB page sizes"
    fi
    
    echo
    echo "Emulator is ready for testing!"
    echo "  Device: $DEVICE_TYPE"
    echo "  AVD Name: $AVD_NAME"
    echo "  Page Size: $PAGE_SIZE bytes"
    echo
    echo "Next steps:"
    echo "  1. Build and install DSM APK:"
    echo "     cd dsm_client/android"
    echo "     ./gradlew installDebug"
    echo
    echo "  2. Reverse storage ports:"
    echo "     adb reverse tcp:8080 tcp:8080"
    echo "     adb reverse tcp:8081 tcp:8081"
    echo "     adb reverse tcp:8082 tcp:8082"
    echo "     adb reverse tcp:8083 tcp:8083"
    echo "     adb reverse tcp:8084 tcp:8084"
    echo
    echo "  3. Launch app:"
    echo "     adb shell am start -n com.dsm.wallet/.ui.MainActivity"
    echo
    echo "Emulator running in background (PID: $EMULATOR_PID)"
    echo "To stop: kill $EMULATOR_PID"
    
else
    echo
    echo "Emulator not launched. To start manually:"
    echo "  emulator -avd $AVD_NAME"
    echo
    echo "Or use Android Studio Device Manager"
fi
