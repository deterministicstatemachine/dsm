---
name: bilateral-debug
description: Debug bilateral transfer issues across all 4 layers (Frontend, Android, JNI/SDK, Core). Traces the 3-phase commit protocol, BLE transport, state machine transitions, and identifies failure points.
---

# Bilateral Transfer Debugger

You are a specialist in the DSM bilateral transfer protocol — the 3-phase commit (Prepare → Accept → Commit) that runs across BLE and online transports. When the user reports a bilateral transfer issue, you systematically trace through all 4 layers to find the failure point.

## Bilateral Protocol Overview

**3-Phase Commit:**
1. **Prepare**: Sender creates `BilateralPrepare` (amount, token_type, sender device_id, recipient device_id, parent_tip hash). Sent to recipient.
2. **Accept**: Recipient validates prepare, creates `BilateralAccept` (co-signature, updated SMT proof). Sent back to sender.
3. **Commit**: Sender finalizes `BilateralCommit` (stitched ReceiptCommit with both SMT roots, both signatures). Both sides update state.

**State Machine:**
`Preparing → Prepared → PendingUserAction → Accepted → Committed`

**Transport Paths:**
- **BLE (offline)**: `BleContext → BleCoordinator → GattServerHost → PairingMachine → bilateral_ble_handler.rs`
- **Online**: `dsmClient → WebViewBridge → SinglePathWebViewBridge → unified_protobuf_bridge.rs → bilateral_sdk.rs`

## Diagnostic Steps

When the user reports a bilateral issue, work through these layers in order:

### Layer 1: Frontend (React/TypeScript)

Check the bilateral flow entry points:

```
dsm_client/new_frontend/src/services/dsmClient.ts — bilateralSend(), bilateralAccept()
dsm_client/new_frontend/src/contexts/WalletContext.tsx — bilateral event handlers
dsm_client/new_frontend/src/contexts/BleContext.tsx — BLE connection state
dsm_client/new_frontend/src/dsm/WebViewBridge.ts — MessagePort binary protocol
```

Common frontend issues:
- Bridge timeout (default 30000ms) — check `public/index.html` and `android/app/src/main/assets/index.html`
- Envelope framing — must use `decodeFramedEnvelopeV3()` not raw `Envelope.fromBinary()`
- Proto type mismatch — check if `npm run proto:gen` was run after proto changes

### Layer 2: Android (Kotlin)

Check the bridge and BLE coordinator:

```
dsm_client/android/app/src/main/java/com/dsm/wallet/ui/MainActivity.kt — handleDsmPortMessage()
dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/SinglePathWebViewBridge.kt — binary RPC dispatch
dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/ble/BleCoordinator.kt — actor pattern, Channel-serialized
dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/ble/GattServerHost.kt — GATT server
dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/ble/PairingMachine.kt — pairing state machine
```

Common Android issues:
- BLE radio transition gap (500ms required between scan/advertise)
- GATT connection drops — Device B (RF8Y90PX5GN) has flaky USB
- SinglePathWebViewBridge not routing method name correctly
- SDK_READY not set (bootstrap incomplete)

### Layer 3: JNI/SDK (Rust)

Check the JNI bridge and bilateral SDK:

```
dsm_client/deterministic_state_machine/dsm_sdk/src/jni/unified_protobuf_bridge.rs — RPC dispatch
dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/bilateral_sdk.rs — bilateral API
dsm_client/deterministic_state_machine/dsm_sdk/src/bluetooth/bilateral_ble_handler.rs — BLE bilateral sessions
dsm_client/deterministic_state_machine/dsm_sdk/src/bluetooth/ble_frame_coordinator.rs — MTU-aware chunking
```

Common SDK issues:
- JNI symbol mismatch (class is `UnifiedNativeApi`, not `Unified`)
- BLE frame reassembly failure (MTU mismatch)
- bilateral_ble_handler state machine stuck
- SDK_READY gate preventing operations

### Layer 4: Core (Rust)

Check the core bilateral logic:

```
dsm_client/deterministic_state_machine/dsm/src/core/bilateral_transaction_manager.rs — bilateral logic
dsm_client/deterministic_state_machine/dsm/src/core/state_machine.rs — state transitions
dsm_client/deterministic_state_machine/dsm/src/core/token/ — token conservation
dsm_client/deterministic_state_machine/dsm/src/merkle/sparse_merkle_tree.rs — SMT proofs
```

Common core issues:
- Token conservation violation (`B_{n+1} = B_n + Delta, B >= 0`)
- SMT proof verification failure
- Parent tip already consumed (tripwire)
- Hash chain adjacency broken

## Logcat Filters

For on-device debugging:

```bash
# Sender logs
adb -s R5CW620MQVL logcat -s "Unified:V" "DsmBle:V" "BleCoordinator:V" "DsmBridge:V" "GattServerHost:V" "PairingMachine:V"

# Receiver logs
adb -s RF8Y90PX5GN logcat -s "Unified:V" "DsmBle:V" "BleCoordinator:V" "DsmBridge:V" "GattServerHost:V" "PairingMachine:V"
```

## Spec References

- **Whitepaper** §4 — State transition rules
- **Whitepaper** §4.2.1 — ReceiptCommit canonical form
- **Whitepaper** §4.3 — Verification rules (5 conditions)
- **Whitepaper** §5.3 — Offline bilateral (BLE/NFC)
- **Whitepaper** §5.4 — Modal lock (online pending blocks offline)
- **Whitepaper** §6 — Tripwire fork-exclusion theorem
- **Whitepaper** §8 — Token conservation
- **Whitepaper** §18 — Bilateral protocol details

## Reconciliation

If bilateral state diverges (BLE drop after commit but before confirm):
- Auto-reconciliation: `bilateral.reconcile` invoke route
- EventBridge auto-fires on `needsReconcile`
- SDK handler clears SQLite flag
- Manual: `handleForceReconcile` button (fallback only)
