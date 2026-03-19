# DSM Test Automation Tools

Python scripts for automated end-to-end testing on physical Android devices.

## Prerequisites

- Two Android devices connected via ADB
- DSM Wallet APK installed on both devices
- Python 3.9+ with standard library
- Storage nodes running locally (ports 8080-8084)
- ADB reverse port forwarding configured

## Scripts

### adb_utils.py

Core utilities for ADB operations:
- Device detection and command execution
- UI automation via `uiautomator dump` XML parsing
- Tap/swipe/keyevent simulation
- SQLite database pulling via `run-as` (no root required)
- Activity launching and log monitoring

### ble_pairing_e2e.py

Automates BLE pairing between two devices:

```bash
python3 tools/ble_pairing_e2e.py --device1 <serial1> --device2 <serial2> [--apk <path>]
```

**Flow:**
1. Clear app data on both devices
2. Launch DSM Wallet app
3. Navigate to Bluetooth screen
4. Start advertising on device 1
5. Start scanning on device 2
6. Wait for device discovery
7. Tap discovered device to initiate pairing
8. Verify pairing success via logs

**Success criteria:** Log patterns show "contact added", "paired", or "success"

### verify_persistence.py

Verifies on-device SQLite persistence:

```bash
python3 tools/verify_persistence.py --device1 <serial1> --device2 <serial2>
```

**Checks:**
- Pulls `dsm_client.db` via `run-as com.dsm.wallet`
- Counts rows in:
  - `contacts` table (verified contacts)
  - `bilateral_transactions` table (offline transactions)
  - `bilateral_receipts` table (transaction receipts)
- Reports warnings if tables are empty

**Database paths tried** (in order):
1. `files/dsm_client.db`
2. `databases/dsm_client.db`
3. `databases/dsm.db`

### offline_send_e2e.py

**NEW:** Full offline bilateral transaction automation:

```bash
python3 tools/offline_send_e2e.py --device1 <sender> --device2 <receiver> \
  [--amount 1000000000] [--timeout 60]
```

**Flow:**
1. Launch apps on both devices
2. Add device 2 as verified contact on device 1 (via QR simulation/broadcast)
3. Enable Bluetooth on both devices
4. Navigate to Wallet → Send screen on device 1
5. Toggle offline mode
6. Select recipient (device 2)
7. Enter amount
8. Tap Send
9. Monitor logs for bilateral flow:
   - Sender: prepare → (BLE send) → commit
   - Receiver: (BLE receive) → accept → commit
10. Report success if all phases detected

**Success criteria:**
- Prepare phase detected on sender
- Accept phase detected on receiver
- Commit phase detected on both devices
- All within timeout period

### live_smoke_orchestrator.py

High-level orchestrator for complete smoke test:

```bash
python3 tools/live_smoke_orchestrator.py --device1 <serial1> --device2 <serial2> [--apk <path>]
```

**Flow:**
1. Configure ADB reverse (ports 8080-8084)
2. Launch DSM Wallet on both devices
3. Run BLE pairing automation
4. Run persistence verification

**Note:** This script runs pairing + verification but does NOT execute an actual transaction. Use `offline_send_e2e.py` for that.

## Usage Examples

### Complete E2E test sequence

```bash
# 1. Build and install latest APK
cd dsm_client/android
./gradlew assembleDebug
APK=app/build/outputs/apk/debug/app-debug.apk

# 2. Run orchestrator (pairing + persistence check)
cd ../..
python3 tools/live_smoke_orchestrator.py \
  --device1 <DEVICE1_SERIAL> \
  --device2 <DEVICE2_SERIAL> \
  --apk dsm_client/android/$APK

# 3. Run offline transaction test
python3 tools/offline_send_e2e.py \
  --device1 <DEVICE1_SERIAL> \
  --device2 <DEVICE2_SERIAL> \
  --amount 1000000000 \
  --timeout 60

# 4. Verify persistence after transaction
python3 tools/verify_persistence.py \
  --device1 <DEVICE1_SERIAL> \
  --device2 <DEVICE2_SERIAL>
```

### Manual device discovery

If you don't know device serials:

```bash
adb devices
# List of devices attached
# <DEVICE1_SERIAL>        device
# <DEVICE2_SERIAL>        device
```

Then use the serials in the scripts above.

### Capture logs during test

```bash
# Terminal 1: Device 1 logs
adb -s <DEVICE1_SERIAL> logcat -s DSM:* DsmNative:* | tee device1.log

# Terminal 2: Device 2 logs
adb -s <DEVICE2_SERIAL> logcat -s DSM:* DsmNative:* | tee device2.log

# Terminal 3: Run test
python3 tools/offline_send_e2e.py --device1 <DEVICE1_SERIAL> --device2 <DEVICE2_SERIAL>
```

## Troubleshooting

### "Device not found"

```bash
adb devices
# If device shows "unauthorized", unlock device and accept RSA key prompt
# If device shows "offline", reconnect USB cable
```

### "run-as: Package 'com.dsm.wallet' is not debuggable"

The app must be a debug build. Release builds are not debuggable and `run-as` will fail.

### UI automation failures

The scripts use uiautomator to find UI elements by text and fallback to approximate coordinates. If layout changes:

1. Run `adb -s <device> shell uiautomator dump` and `adb shell cat /sdcard/window_dump.xml` to inspect UI hierarchy
2. Adjust text patterns or coordinates in the scripts
3. Common patterns to search: "Send", "Bluetooth", "Contacts", "Add", "Offline"

### BLE pairing doesn't complete

- Ensure both devices have Bluetooth enabled: `adb shell svc bluetooth enable`
- Check Bluetooth permissions in app settings
- Clear app data and retry: `adb shell pm clear com.dsm.wallet`
- Check logs for discovery: `adb logcat -s BluetoothAdapter:* BtGatt.GattService:*`

### Bilateral flow timeout

- Verify storage nodes are running: `curl http://localhost:8080/health`
- Verify ADB reverse is configured: `adb reverse --list`
- Check if devices are on same network (though BLE should work offline)
- Increase timeout: `--timeout 120`

### No contacts/transactions in DB

This is expected if:
- Pairing was attempted but contact verification didn't complete (requires online storage node connection)
- No actual transaction was sent (use `offline_send_e2e.py` to test this)

To fix:
1. Ensure storage nodes are running
2. Configure ADB reverse on both devices
3. Complete pairing (online verification required)
4. Run offline send test
5. Verify persistence shows non-zero counts

## Development

### Adding new UI automation

1. Inspect UI hierarchy: `adb shell uiautomator dump && adb shell cat /sdcard/window_dump.xml`
2. Find element by `text`, `resource-id`, or `content-desc`
3. Use `find_node_bounds()` from `adb_utils.py`
4. Add fallback coordinates for robustness
5. Test on multiple screen sizes/layouts

### Extending log patterns

The scripts wait for specific log patterns to detect success. Common patterns:

- Pairing: `"contact"`, `"paired"`, `"success"`, `"added"`
- Bilateral: `"prepare"`, `"accept"`, `"commit"`, `"bilateral"`
- Errors: `"error"`, `"fail"`, `"exception"`

Add new patterns in the `wait_for_log()` calls as needed.

## CI Integration

These scripts can run in CI if you have Android devices or emulators connected:

```yaml
# .github/workflows/e2e-test.yml
- name: Start emulators
  run: |
    emulator -avd test_device_1 -no-window -no-audio &
    emulator -avd test_device_2 -no-window -no-audio &
    adb wait-for-device

- name: Run E2E tests
  run: |
    python3 tools/live_smoke_orchestrator.py
    python3 tools/offline_send_e2e.py --device1 emulator-5554 --device2 emulator-5556
    python3 tools/verify_persistence.py --device1 emulator-5554 --device2 emulator-5556
```

## License

MIT OR Apache-2.0 (matches DSM project license)
