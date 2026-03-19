#!/bin/bash
# Verify 16 KB page size support is properly configured

set -e

echo "=== DSM 16 KB Page Size Support Verification ==="
echo

# Check AndroidManifest.xml
echo "1. Checking AndroidManifest.xml for 16 KB property..."
if grep -q 'android.supports_16kb_page_size.*true' dsm_client/android/app/src/main/AndroidManifest.xml; then
    echo "   ✓ Manifest property found"
else
    echo "   ✗ Manifest property NOT found"
    exit 1
fi

# Check Rust cargo config
echo "2. Checking Rust linker flags..."
CONFIG_FILE="dsm_client/deterministic_state_machine/dsm_sdk/.cargo/config.toml"

if grep -q 'max-page-size=16384' "$CONFIG_FILE"; then
    echo "   ✓ 16 KB page size linker flag found"
    
    # Count occurrences (should be 3: arm64, armv7, x86_64)
    COUNT=$(grep -c 'max-page-size=16384' "$CONFIG_FILE" || true)
    echo "   ✓ Found in $COUNT target configurations"
    
    if [ "$COUNT" -eq 3 ]; then
        echo "   ✓ All 3 Android targets configured (arm64-v8a, armeabi-v7a, x86_64)"
    else
        echo "   ⚠ Expected 3 targets, found $COUNT"
    fi
else
    echo "   ✗ 16 KB linker flag NOT found"
    exit 1
fi

echo
echo "3. Verifying build configuration..."
if grep -q '16 KB page size support' dsm_client/android/app/build.gradle.kts; then
    echo "   ✓ Build documentation updated"
else
    echo "   ⚠ Build documentation not updated (optional)"
fi

echo
echo "=== Verification Complete ==="
echo
echo "Next steps:"
echo "  1. Rebuild native libraries:"
echo "     cd dsm_client/deterministic_state_machine"
echo "     cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 \\"
echo "       -o ../android/app/src/main/jniLibs \\"
echo "       build --release --features jni,bluetooth"
echo
echo "  2. Build APK:"
echo "     cd ../android"
echo "     ./gradlew assembleDebug"
echo
echo "  3. Test on 16 KB emulator (see docs/16KB_PAGE_SIZE_SUPPORT.md)"
echo
