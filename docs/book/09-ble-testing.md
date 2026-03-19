# Chapter 9 — BLE Testing

Bluetooth Low Energy pairing, bilateral transfers, device setup, and debugging.

---

## Overview

DSM supports fully offline bilateral transfers over Bluetooth LE. Two devices can exchange tokens with no internet connectivity using a three-phase commit protocol (Prepare → Accept → Commit) transported over BLE GATT.

### BLE Stack

```
Frontend (BleContext.tsx)
    │  bridge RPC: bleCommand
    ▼
Kotlin (BleCoordinator.kt)
    │  actor pattern, Channel-serialized
    │  GattServerHost.kt — GATT server with identity characteristic
    │  PairingMachine.kt — pairing state machine
    ▼
Rust SDK (bluetooth/)
    │  bilateral_ble_handler.rs — 3-phase bilateral protocol
    │  ble_frame_coordinator.rs — MTU-aware chunking/reassembly
    │  pairing_orchestrator.rs — Rust-driven pairing flow
    ▼
Core (dsm)
    │  bilateral_transaction_manager.rs — state transition validation
    │  state_machine.rs — hash chain evolution
```

---

## Device Setup

### Prerequisites

- Two Android devices (Android 8.0+) with Bluetooth LE support
- Both devices connected via USB (or wireless adb)
- DSM Wallet app installed on both (debug build)
- Local storage nodes running
- Port forwarding configured on both devices

### Port Forwarding

```bash
# Get device serials
adb devices

# Forward storage ports on both devices
for serial in <SERIAL_A> <SERIAL_B>; do
  for port in 8080 8081 8082 8083 8084; do
    adb -s $serial reverse tcp:$port tcp:$port
  done
done
```

### Enable Bluetooth

```bash
adb -s <SERIAL> shell svc bluetooth enable
```

Ensure Location is enabled on both devices (Android requires location for BLE scanning).

---

## Entering BLE Test Mode

### Method 1: In-app Offline Mode

1. Open DSM Wallet app
2. Go to **Settings**
3. Enable **OFFLINE MODE**
4. Repeat on the second device

This is the active in-app path for preparing devices for manual BLE transfer testing.
For the full hidden developer menu flow, see [Chapter 18 — In-App Developer Walkthroughs](18-in-app-developer-walkthroughs.md).

### Method 2: Intent Extra (adb)

```bash
adb -s <SERIAL> shell am start -n com.dsm.wallet/.ui.MainActivity --ez auto_ble true
```

### Method 3: Automation Script

```bash
bash scripts/android_auto_ble.sh
```

### Legacy note

Older comments and components still reference a `BLE TRANSFER TEST` screen behind developer mode.
That screen is not part of the active routed app flow and should not be treated as the primary BLE
testing path.

---

## BLE Pairing Flow

Before a bilateral transfer, devices must be paired. The pairing flow establishes mutual identity verification.

```
Device A (Initiator)             Device B (Responder)
      │                                │
      │── HELLO(pubkey, nonce) ───────►│
      │                                │  verify identity
      │◄── CHALLENGE(nonce2) ──────────│
      │                                │
      │  sign(nonce2)                  │
      │── RESPONSE(sig) ──────────────►│
      │                                │  verify sig
      │◄── READY ─────────────────────│
      │                                │
      │   Pairing complete             │
```

---

## BLE Bilateral Transfer Flow

After pairing, a bilateral transfer proceeds:

```
Sender (Initiator)               Receiver (Responder)
      │                                │
      │── TRANSFER(state_delta) ──────►│
      │                                │  validate transition
      │                                │  check token conservation
      │                                │  apply + commit
      │◄── ACK(new_state_hash) ────────│
      │                                │
      │  verify ACK                    │
      │── COMPLETE ───────────────────►│
      │                                │
      │   Both hash chains advanced    │
```

Both devices independently commit the new state. When connectivity returns, each device syncs to storage nodes.

---

## MTU and Chunking

BLE has MTU limitations (typically 20–512 bytes per packet). The `ble_frame_coordinator.rs` handles:

1. **Segmentation** — large protobuf messages split into MTU-sized frames
2. **Reassembly** — frames collected and reassembled on receiving end
3. **Sequence numbers** — ensure correct ordering
4. **Retransmission** — lost frames can be retransmitted

### Radio Timing

A **500ms gap** is required between scan/advertise switches to avoid BLE radio state conflicts. The `BleCoordinator` in Kotlin enforces this using an actor pattern with Channel-serialized operations. Do not attempt rapid scan/advertise toggling.

---

## Automated E2E Testing

### BLE Pairing Test

```bash
python3 tools/ble_pairing_e2e.py \
  --device1 <SERIAL_A> \
  --device2 <SERIAL_B> \
  [--apk path/to/app-debug.apk]
```

This:
1. Clears app data on both devices
2. Launches DSM Wallet
3. Navigates to Bluetooth screen
4. Starts advertising on device 1
5. Starts scanning on device 2
6. Waits for discovery and initiates pairing
7. Verifies success via log patterns

### Offline Transfer Test

```bash
python3 tools/offline_send_e2e.py \
  --device1 <SENDER_SERIAL> \
  --device2 <RECEIVER_SERIAL> \
  --amount 1000000000 \
  --timeout 60
```

This:
1. Launches apps on both devices
2. Enables Bluetooth
3. Navigates to Send screen, toggles offline mode
4. Enters amount and sends
5. Monitors logs for bilateral flow phases
6. Reports success when all phases complete

### Full Smoke Test

```bash
python3 tools/live_smoke_orchestrator.py \
  --device1 <SERIAL_A> \
  --device2 <SERIAL_B> \
  --apk dsm_client/android/app/build/outputs/apk/debug/app-debug.apk
```

Runs pairing + persistence verification.

### Persistence Verification

```bash
python3 tools/verify_persistence.py \
  --device1 <SERIAL_A> \
  --device2 <SERIAL_B>
```

Pulls `dsm_client.db` via `run-as` and checks:
- `contacts` table (verified contacts)
- `bilateral_transactions` table
- `bilateral_receipts` table

---

## Log Capture During BLE Tests

### Live monitoring (recommended)

Open three terminals:

```bash
# Terminal 1: Device A logs
adb -s <SERIAL_A> logcat -s DSM:* DsmNative:* | tee device_a.log

# Terminal 2: Device B logs
adb -s <SERIAL_B> logcat -s DSM:* DsmNative:* | tee device_b.log

# Terminal 3: Run test
python3 tools/offline_send_e2e.py --device1 <SERIAL_A> --device2 <SERIAL_B>
```

### BLE-specific logs

```bash
adb -s <SERIAL> logcat -s BluetoothAdapter:* BtGatt.GattService:*
```

### Log Patterns to Watch

| Pattern | Meaning |
|---------|---------|
| `"contact"`, `"paired"`, `"added"` | Pairing success |
| `"prepare"` | Bilateral prepare phase |
| `"accept"` | Bilateral accept phase |
| `"commit"` | Bilateral commit phase |
| `"bilateral"` | General bilateral activity |
| `"error"`, `"fail"`, `"exception"` | Errors |

---

## Common BLE Issues

### Pairing doesn't complete

1. Both devices have Bluetooth enabled? `adb shell svc bluetooth enable`
2. Location enabled? (Required for BLE scanning on Android)
3. App has Bluetooth permissions? (Settings → Apps → DSM Wallet → Permissions)
4. Clear app data and retry: `adb shell pm clear com.dsm.wallet`

### Devices not discovering each other

1. Toggle Bluetooth off/on on both devices
2. Ensure devices are within range (< 10 meters)
3. Restart the app on both devices
4. Try swapping roles (advertiser ↔ scanner)

### Transfer times out

- Storage nodes running? `curl http://localhost:8080/api/v2/health`
- ADB reverse configured? `adb reverse --list`
- Increase timeout: `--timeout 120`
- Check for radio timing issues in logs

### No contacts/transactions in database

Expected if:
- Pairing didn't complete (requires online storage node connection for verification)
- No actual transaction was sent
- Solution: ensure storage nodes running, complete pairing, then run transfer test

---

Next: [Chapter 10 — Testing and CI](10-testing-and-ci.md)
