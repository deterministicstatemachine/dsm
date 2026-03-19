# DSM SDK

## Architecture Overview

The DSM SDK provides the core logic for the Deterministic State Machine, including cryptographic primitives, transaction handling, and bilateral (offline) protocols.

### JNI & Offline Transactions

For Android, the SDK exposes JNI bindings in `src/jni`. 

**Critical Architecture Note:**
The `bilateralOfflineSend` flow has a specific architectural divergence to ensure state consistency:

1.  **Direct BluetoothManager Access**: The JNI implementation of `bilateralOfflineSend` (in `src/jni/unified_protobuf_bridge.rs`) does **not** use the standard `CoreBridge` -> `UnilateralHandler` path. Instead, it interacts directly with the global `BluetoothManager` singleton.
2.  **Single Source of Truth**: This bypass is intentional. It ensures that the offline transaction uses the *same* `ContactManager` instance that the QR code scanner writes to. Using the core bridge path could instantiate a parallel `ContactManager` with empty state, causing "Unknown Contact" errors during transfers.
3.  **Event-Driven**: The frontend (TypeScript) calls `bilateralOfflineSend` but does **not** receive the transaction result in the return value. The return value only indicates "Transmission Started". The actual success/failure/progress is communicated via `BilateralEventNotification` protobufs emitted to the `bilateral.event` event bridge channel.
4.  **Timeouts**: The frontend enforces a 60s hard timeout (`BLE_COMPLETION_TIMEOUT_MS`). The Rust layer must ensure it emits terminal events (`COMPLETED`, `REJECTED`, `FAILED`) before this timeout, or the UI will assume failure.

### Testing

*   **Unit Tests**: `cargo test` covers core logic.
*   **Integration Tests**: `tests/` contains e2e flows matching `dsm_client` behavior.
*   **Bilateral Event Guarantee**: `tests/bilateral_event_guarantee.rs` simulates the full offline flow (mocking only the raw BLE packets) to prove that the correct `BilateralEventNotification`s are emitted to the frontend.
