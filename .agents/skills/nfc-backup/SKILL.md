---
name: nfc-backup
description: NFC ring backup domain — architecture, data flow, layer boundaries, and implementation guide for writing/reading encrypted recovery capsules to NTAG216 NFC rings. Use when working on NFC backup, recovery capsules, or the NFC write/read flow.
---

# NFC Ring Backup Domain

You provide architectural orientation and implementation guidance for the DSM NFC ring backup system.

## Overview

NFC backup writes an encrypted recovery capsule from the DSM Rust core onto an NTAG216 NFC ring. The user holds their phone to the ring; if the write commits, the phone vibrates. No vibration = no write. The user taps again.

## Three-Layer Architecture

```
┌─────────────────────────────────────────────────────┐
│  TypeScript (WebView)                               │
│  src/dsm/nfc.ts — domain module                     │
│  Triggers write flow, subscribes to events           │
│  startNfcWrite() → bridge RPC "nfcStartWrite"       │
│  onBackupWritten() → bridgeEvents "nfc.backupWritten"│
│  onCapsuleReceived() → EventBridge "nfc-recovery-*" │
├─────────────────────────────────────────────────────┤
│  Kotlin (Android) — TRANSPORT ONLY                  │
│  SinglePathWebViewBridge routes:                     │
│    nfcIsBackupEnabled → JNI → Rust                  │
│    nfcHasPendingCapsule → JNI → Rust                │
│    nfcStartWrite → launches NfcWriteActivity        │
│  NfcWriteActivity:                                   │
│    enableReaderMode → onTagDiscovered                │
│    Gets capsule from Rust (getPendingRecoveryCapsule)│
│    Gets NDEF from Rust (prepareNfcWritePayload)      │
│    Writes bytes to tag (hardware op)                 │
│    On success: vibrate + dispatch event + finish()   │
│    On failure: silent. No vibration.                 │
│  NfcRecoveryActivity:                                │
│    Handles NDEF_DISCOVERED intent (tag read)         │
│    Sends raw bytes to Rust via JNI                   │
├─────────────────────────────────────────────────────┤
│  Rust (Core + SDK)                                   │
│  Owns ALL capsule creation, NDEF formatting, crypto  │
│  JNI exports in unified_protobuf_bridge.rs:          │
│    getPendingRecoveryCapsule()                        │
│    prepareNfcWritePayload(capsuleBytes)              │
│    isNfcBackupEnabled()                              │
│    clearPendingRecoveryCapsule()                     │
│    createNfcRecoveryCapsuleEnvelope(payload)         │
│  NDEF MIME type: application/vnd.dsm.recovery        │
│  RecoverySDK manages capsule lifecycle               │
└─────────────────────────────────────────────────────┘
```

## Key Files

| Layer | File | Purpose |
|-------|------|---------|
| TS | `new_frontend/src/dsm/nfc.ts` | Domain module: startNfcWrite, isNfcBackupEnabled, event subscriptions |
| TS | `new_frontend/src/dsm/EventBridge.ts` | Handles `nfc.backup_written` topic → `bridgeEvents.emit('nfc.backupWritten')` |
| TS | `new_frontend/src/bridge/bridgeEvents.ts` | Event types: `nfc.backupWritten`, `nfc.writeStarted` |
| Kotlin | `bridge/SinglePathWebViewBridge.kt` | RPC routes: `nfcIsBackupEnabled`, `nfcHasPendingCapsule`, `nfcStartWrite` |
| Kotlin | `recovery/NfcWriteActivity.kt` | Hardware write: enableReaderMode, onTagDiscovered, vibrate-on-commit |
| Kotlin | `recovery/NfcRecoveryActivity.kt` | Hardware read: NDEF_DISCOVERED intent handler |
| Kotlin | `bridge/UnifiedNativeApi.kt` | JNI declarations for NFC symbols |
| Kotlin | `bridge/BleEventRelay.kt` | `dispatchEventEmpty("nfc.backup_written")` pushes to WebView |
| Rust | `jni/unified_protobuf_bridge.rs` | JNI exports for capsule get/prepare/clear/enabled |
| Rust | `sdk/recovery_sdk.rs` | Capsule lifecycle (create, store, prune) |
| XML | `AndroidManifest.xml` | NFC permission, feature flag, NDEF intent filters |

## UX Contract

- **Vibration = state committed.** The tag write succeeded. The motor fires as a side effect of the state transition completing.
- **No vibration = it didn't write.** Tag moved, not compatible, capacity exceeded, or no pending capsule. User taps again.
- **No error UI.** No text, no progress bars, no timers. The absence of the event is the signal.
- **No timers.** The vibration is an event, not a duration. The 50ms in `VibrationEffect.createOneShot(50, ...)` is an Android API minimum to actuate the motor, not a design choice.

## Write Flow (Step by Step)

1. User enables NFC backup in settings → Rust creates capsule via `recovery.createCapsule`, stores in SQLite as "pending"
2. User taps "Write to Ring" in WebView → TS calls `startNfcWrite()` → bridge RPC `nfcStartWrite`
3. Kotlin bridge launches `NfcWriteActivity`
4. Activity calls `enableReaderMode()` in `onResume()` — Android NFC hardware starts listening
5. User holds phone to NTAG216 ring → `onTagDiscovered(tag)` fires
6. Activity gets capsule bytes from Rust: `UnifiedNativeApi.getPendingRecoveryCapsule()`
7. Activity gets NDEF message from Rust: `UnifiedNativeApi.prepareNfcWritePayload(capsuleBytes)`
8. Activity writes NDEF to tag: `Ndef.get(tag).writeNdefMessage(ndefMessage)` (or `NdefFormatable.format()`)
9. On success:
   - `UnifiedNativeApi.clearPendingRecoveryCapsule()` — tells Rust write committed
   - `vibrate()` — haptic confirmation event
   - `BleEventRelay.dispatchEventEmpty("nfc.backup_written")` — notifies WebView
   - `finish()` — returns to WebView
10. On `IOException` (tag moved): nothing. No vibration. Activity stays open for re-tap.

## Read Flow (Recovery Import)

1. Android NFC dispatch detects tag with MIME `application/vnd.dsm.recovery`
2. `NfcRecoveryActivity.onCreate()` handles `NDEF_DISCOVERED` intent
3. Extracts capsule bytes from NDEF record
4. Sends to Rust: `UnifiedNativeApi.createNfcRecoveryCapsuleEnvelope(payload)`
5. Rust decrypts, dispatches envelope via `BleEventRelay.dispatchEnvelope()`
6. EventBridge receives on topic `ble.envelope.bin`, parses `nfcRecoveryCapsule` payload case
7. Re-emits as `nfc-recovery-capsule` on the EventBridge pub/sub
8. TS `onCapsuleReceived()` subscribers receive decrypted payload

## NTAG216 Constraints

- **888 bytes** total user memory
- **~868 bytes** usable after NDEF overhead
- NDEF record uses short-record format when payload ≤ 255 bytes, long-record otherwise
- Rust's `prepareNfcWritePayload` handles all NDEF framing — Kotlin writes raw bytes

## Invariants

1. **Kotlin is transport-only.** It operates the NFC radio and moves bytes. No protocol decisions.
2. **Rust owns NDEF formatting.** The MIME type, record structure, and capsule content are all decided in `prepareNfcWritePayload`. Kotlin does not construct NDEF records.
3. **No business logic in Kotlin.** The `if/when` in `NfcWriteActivity` gates on hardware state (tag writable, capacity sufficient), not protocol outcomes.
4. **Vibration is an event, not a timer.** It fires on the discrete state transition of "write committed."
5. **Silent failure.** No error patterns, no error UI. Absence of vibration is the signal.
6. **Binary bridge only.** NFC routes use the same `handleBinaryRpc` MessagePort path as everything else. No `@JavascriptInterface`, no JSON, no hex.

## Adding a New NFC Feature

Follow the same pattern as BLE or QR additions:

1. Add JNI export in `unified_protobuf_bridge.rs` (Rust)
2. Add `external fun` in `UnifiedNativeApi.kt` (Kotlin)
3. Add `when` case in `handleBinaryRpcInternal` in `SinglePathWebViewBridge.kt` (Kotlin)
4. Add function in `src/dsm/nfc.ts` (TypeScript)
5. If it produces events: add topic handler in `EventBridge.ts`, add type to `bridgeEvents.ts`

## Test Devices

| Role | Serial | Model | NFC |
|------|--------|-------|-----|
| Primary | R5CW620MQVL | Samsung Galaxy A54 | Yes |
| Secondary | RF8Y90PX5GN | Samsung Galaxy A16 | Yes |

Both Samsung devices have optimized WebViews. The A54 NFC antenna is located near the camera on the back.
