---
name: ble-test
description: Deploy APK and launch BLE transfer test on both test devices (A=R5CW620MQVL sender, B=RF8Y90PX5GN receiver)
disable-model-invocation: true
---

# BLE Transfer Test

Deploy the APK to both test devices and launch the BLE transfer test.

## Test Devices

| Role | Serial | Model |
|------|--------|-------|
| Device A (Sender) | R5CW620MQVL | Samsung Galaxy A54 |
| Device B (Receiver) | RF8Y90PX5GN | Samsung Galaxy A16 |

**Note**: Device B has a flaky USB connection. If it drops, re-plug and retry.

## Steps

### 1. Verify both devices are connected

```bash
adb devices
```

Check that both `R5CW620MQVL` and `RF8Y90PX5GN` appear with status `device`. If either is missing, report which device is not connected and stop.

### 2. Install APK on both devices

```bash
APK="/Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/android/app/build/outputs/apk/debug/app-debug.apk"
adb -s R5CW620MQVL install -r "$APK"
adb -s RF8Y90PX5GN install -r "$APK"
```

If the APK doesn't exist, tell the user to run `/ndk-build` first.

### 3. Set up ADB reverse port forwarding

```bash
for DEVICE in R5CW620MQVL RF8Y90PX5GN; do
  for PORT in 8080 8081 8082 8083 8084; do
    adb -s "$DEVICE" reverse tcp:$PORT tcp:$PORT
  done
done
```

### 4. Clear logcat on both devices

```bash
adb -s R5CW620MQVL logcat -c
adb -s RF8Y90PX5GN logcat -c
```

### 5. Launch BLE test on both devices

Launch with the `auto_ble` intent extra to go directly to the BLE transfer test screen:

```bash
adb -s R5CW620MQVL shell am start -n com.dsm.wallet/.ui.MainActivity --ez auto_ble true
adb -s RF8Y90PX5GN shell am start -n com.dsm.wallet/.ui.MainActivity --ez auto_ble true
```

### 6. Wait and capture logcat

Wait 5 seconds for BLE discovery and connection, then capture logs:

```bash
sleep 5

echo "=== Device A (Sender) Logs ==="
adb -s R5CW620MQVL logcat -d -s "Unified:V" "DsmBle:V" "BleCoordinator:V" "DsmBridge:V" "GattServerHost:V" "PairingMachine:V" 2>&1 | tail -50

echo ""
echo "=== Device B (Receiver) Logs ==="
adb -s RF8Y90PX5GN logcat -d -s "Unified:V" "DsmBle:V" "BleCoordinator:V" "DsmBridge:V" "GattServerHost:V" "PairingMachine:V" 2>&1 | tail -50
```

### 7. Report results

Summarize:
- Whether both devices discovered each other
- BLE connection status (GATT connected / failed)
- Transfer outcome (success / failure / timeout)
- Any errors or exceptions in the logs
