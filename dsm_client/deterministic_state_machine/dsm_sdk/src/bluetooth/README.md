# Canonical Android BLE Bridge (Offline Bilateral Path)

## Status: ACTIVE – Single, enforced path

This directory contains the ONLY permitted Bluetooth Low Energy (BLE) integration for DSM. All previous multi-module / exploratory stacks (discovery, connection managers, messaging layers, bluetooth_impl, retry schedulers) have been permanently removed and are CI‑guarded against resurrection.

## Scope

Minimal responsibility: move serialized Envelope v3 byte frames between two Android devices so the bilateral transaction state machine can progress offline. No discovery logic, no generalized messaging layer, no background maintenance loops, no multi-hop routing, no JSON framing.

## Components

```
Kotlin GATT service
    │  (JNI protobuf bytes)
    ▼
android_ble_bridge.rs        // JNI ingress/egress, converts to Vec<u8>
    │
    ▼
ble_frame_coordinator.rs     // Chunking / reassembly of Envelope v3 frames
    │
    ▼
bilateral_ble_handler.rs     // Prepares + commits bilateral transactions (returns envelope bytes + commitment hash)
    │
    ▼
core bilateral manager       // Forward-only state updates
```

## Deterministic Invariants

- Envelope version: v3 only
- Forward-only chain progression; no rollback / fork semantics
- No wall‑clock driven maintenance (no `tokio::time::sleep/interval/timeout` in this stack)
- No JSON / Base64 / hex application framing – raw protobuf bytes only
- No deprecated modules or symbols (`BluetoothConnectionManager`, `BluetoothMessaging`, `BluetoothDiscovery`, etc.)
- Commitment hash produced directly at preparation step (BLAKE3 precommitment) – no heuristic session scans

## CI Enforcement

`ci_gates.sh` contains BLE guards that will fail the build if:

1. Any deleted deprecated file (`connection.rs`, `messaging.rs`, `bluetooth_impl.rs`, `discovery.rs`) reappears.
2. Any banned deprecated symbol is referenced anywhere in Rust sources.
3. Runtime `tokio::time::{sleep,interval,timeout}` is introduced into this directory.

These gates run early for fail‑fast feedback. To extend enforcement add new patterns to the BLE section at the top of `ci_gates.sh`.

## Interaction Pattern

Android (Kotlin) pushes a prepared transaction by invoking JNI → bytes enter `android_ble_bridge.rs` → coordinator frames them → handler validates / commits when counterpart responds → resulting committed state is exposed back up through existing SDK flows.

## Non-Goals (Deliberate Exclusions)

- General device discovery / scanning orchestration
- Connection retry backoff schedulers
- Multi-hop / mesh routing
- Arbitrary message bus or chat semantics
- Cross-platform desktop BLE (Android only for now)

## Adding New Offline Features

Extend only via the handler or coordinator with protobuf-compatible frame types. Preserve invariants above and update CI gates if a new risk vector appears.

## Security & Integrity Notes

- All cryptographic commitments must originate from the bilateral transaction manager – do not recompute externally.
- Do not introduce alternative hashing or envelope versions without updating global contracts.

## Maintenance

If this path changes, update: `ci_gates.sh`, this README, and any frontend bridge utilities expecting frame semantics.

## Summary

This is a lean, deterministic transport conduit. Its correctness is enforced by design and by CI. Any expansion must retain determinism and avoid resurrecting deprecated abstractions.
