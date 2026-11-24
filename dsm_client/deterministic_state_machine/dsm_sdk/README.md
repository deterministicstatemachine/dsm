# DSM SDK

The wallet's engine behind one ingress: the router's routes (`src/handlers`), the storage-node
clients and sync, SoFi and escrow, DSM Connect, and offline steps between contacts over BLE with
each side's anchor board. It drives the pure core crate (`../dsm`), which does no I/O.

## One ingress

Every platform reaches the SDK through `ingress::dispatch_ingress` with an `IngressRequest`
(`proto/dsm_app.proto`): Android through the JNI shim (`src/jni`), iOS through the C ABI of the
`ffi` feature (`src/ffi`). The shims marshal bytes and decide nothing.

## Offline sends

An offline send is the router's `wallet.sendOffline` invoke. The BLE stack (`src/bluetooth`) runs
the step between the two contacts over an authenticated link session (DSM Amendment A27); the
payer's board signs the release and the receiver's board checks and commits the receive. Progress
reaches the frontend as `BilateralEventNotification` messages on the `bilateral.event` topic.

## Tests

- Unit tests sit beside the code (`cargo test -p dsm_sdk`).
- Node-backed tests start their own storage nodes on PostgreSQL and need `DSM_TEST_DATABASE_URL`.
- `tests/` holds the integration suites, among them `ble_pairing_and_offline_e2e.rs` and
  `bilateral_reject_tests.rs`.
