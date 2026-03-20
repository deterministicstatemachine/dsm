---
name: device-status
description: Check test device connectivity, installed APK version, and BLE readiness
disable-model-invocation: true
---

# Device Status Check

Quick health check for both DSM test devices. Run before BLE testing or APK deployment to catch disconnections early.

## Devices

| Role | Serial | Model |
|------|--------|-------|
| Device A (Sender) | R5CW620MQVL | Galaxy A54 (SM_A546W) |
| Device B (Receiver) | RF8Y90PX5GN | Galaxy A16 (SM_A165M) |

**Note**: Device B has a flaky USB connection. If it shows as offline/unauthorized, advise re-plugging the cable.

## Steps

### 1. Check device connectivity

```bash
echo "=== Connected Devices ==="
adb devices -l

DEVICE_A="R5CW620MQVL"
DEVICE_B="RF8Y90PX5GN"

for DEV in $DEVICE_A $DEVICE_B; do
  if adb devices | grep -q "$DEV.*device$"; then
    MODEL=$(adb -s "$DEV" shell getprop ro.product.model 2>/dev/null | tr -d '\r')
    ANDROID=$(adb -s "$DEV" shell getprop ro.build.version.release 2>/dev/null | tr -d '\r')
    echo "CONNECTED: $DEV ($MODEL, Android $ANDROID)"
  else
    echo "DISCONNECTED: $DEV — check USB cable"
  fi
done
```

### 2. Check installed APK version

```bash
DEVICE_A="R5CW620MQVL"
DEVICE_B="RF8Y90PX5GN"

for DEV in $DEVICE_A $DEVICE_B; do
  if adb devices | grep -q "$DEV.*device$"; then
    VERSION=$(adb -s "$DEV" shell dumpsys package com.dsm.wallet 2>/dev/null | grep versionName | head -1 | awk -F= '{print $2}' | tr -d '\r')
    VERSION_CODE=$(adb -s "$DEV" shell dumpsys package com.dsm.wallet 2>/dev/null | grep versionCode | head -1 | awk '{print $1}' | awk -F= '{print $2}' | tr -d '\r')
    if [ -n "$VERSION" ]; then
      echo "$DEV: DSM Wallet v$VERSION (code $VERSION_CODE)"
    else
      echo "$DEV: DSM Wallet NOT INSTALLED"
    fi
  fi
done
```

### 3. Check BLE permissions and state

```bash
DEVICE_A="R5CW620MQVL"
DEVICE_B="RF8Y90PX5GN"

for DEV in $DEVICE_A $DEVICE_B; do
  if adb devices | grep -q "$DEV.*device$"; then
    echo "--- $DEV BLE Status ---"
    # Check Bluetooth enabled
    BT=$(adb -s "$DEV" shell settings get global bluetooth_on 2>/dev/null | tr -d '\r')
    echo "  Bluetooth: $([ "$BT" = "1" ] && echo "ON" || echo "OFF")"

    # Check Location enabled (required for BLE scanning)
    LOC=$(adb -s "$DEV" shell settings get secure location_mode 2>/dev/null | tr -d '\r')
    echo "  Location: $([ "$LOC" != "0" ] && echo "ON (mode=$LOC)" || echo "OFF — BLE scan will fail")"

    # Check granted permissions
    PERMS=$(adb -s "$DEV" shell dumpsys package com.dsm.wallet 2>/dev/null | grep -E "BLUETOOTH|LOCATION" | grep "granted=true" | wc -l | tr -d ' ')
    echo "  BLE/Location permissions granted: $PERMS"
  fi
done
```

### 4. Check ADB port forwarding

```bash
DEVICE_A="R5CW620MQVL"
DEVICE_B="RF8Y90PX5GN"

for DEV in $DEVICE_A $DEVICE_B; do
  if adb devices | grep -q "$DEV.*device$"; then
    REVERSED=$(adb -s "$DEV" reverse --list 2>/dev/null | wc -l | tr -d ' ')
    echo "$DEV: $REVERSED reverse port mappings"
    adb -s "$DEV" reverse --list 2>/dev/null
  fi
done
```

### 5. Report summary

Print a summary table with:
- Device connectivity (connected/disconnected)
- Installed APK version
- Bluetooth ON/OFF
- Location ON/OFF
- BLE permissions count
- Port forwarding status
- Any issues that need attention (Device B USB, missing permissions, etc.)
