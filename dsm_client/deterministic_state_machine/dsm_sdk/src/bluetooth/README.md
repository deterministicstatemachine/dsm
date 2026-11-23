# BLE: offline steps between contacts

## Scope

Moves bilateral frames between two contacts' devices so an offline step can progress. Every byte
on a link is a fragment of the link handshake or a sealed record of the link's session (DSM
Amendment A27): a post-quantum handshake over the ML-KEM keys each contact pinned from the other's
directory entry, then fixed-length XChaCha20-Poly1305 records. The host (Android over JNI, iOS over
the C ABI) moves bytes and interprets none. No JSON framing, no generalized message bus, no
multi-hop routing, and no wall-clock influence on protocol semantics. Operational BLE timers are
allowed only for transport behavior such as retries, ACK timeouts, reconnect backoff, pacing, and
idle expiry.

## Components

```
host GATT (Kotlin BleCoordinator / Swift)
    │  radio bytes
    ▼
radio_link.rs                 // one link per peer address, for any host
    │
    ▼
link_session.rs               // the A27 handshake and sealed records
    │
    ▼
radio_ingress.rs              // opened records into frames
    │
    ▼
ble_frame_coordinator.rs      // chunking / reassembly of Envelope v3 frames
    │
    ▼
bilateral_transport_adapter.rs
    │
    ▼
bilateral_ble_handler.rs      // the offline step (below)

beside them: pairing_orchestrator.rs (scan and advertising), owed_frame_driver.rs (re-sends owed frames)
```

## The offline step

The payer proposes; the receiver accepts; the payer's board signs the release and the payer
confirms with it; the receiver's board checks the payment (the payer's stamp included, DSM
Amendment A38) and commits the receive; the receiver's acknowledgement commits the payer's side.
Every step of an offline account is its board's, and each is final at its origin cell on the
storage nodes (DSM Amendment A39).

## Deterministic Invariants

- Envelope version: v3 only
- Forward-only chain progression; no rollback / fork semantics
- Protocol semantics are clockless: wall-clock must never affect envelope contents, commitment bytes, chain ordering, or acceptance.
- BLE transport/runtime may use wall-clock timers for handshake freshness, ACK timeout, reconnect backoff, pacing, reassembly expiry, and idle session cleanup.
- No JSON / Base64 / hex application framing - raw protobuf bytes only
- No deprecated modules or symbols (`BluetoothConnectionManager`, `BluetoothMessaging`, `BluetoothDiscovery`, etc.)
- Commitment hash produced directly at preparation step (BLAKE3 precommitment) - no heuristic session scans

## CI Enforcement

`scripts/check_forbidden_symbols.sh` fails the build if the retired
Bluetooth message type (the one symbol it names) or one of the blocked
artifacts it lists reappears. Nothing in CI
checks that a transport timer stays out of protocol semantics:
`ci/no_clock_and_no_json.sh` allowlists the BLE transport files, so that
invariant is held by review. There is no `ci_gates.sh`.

## Non-Goals (Deliberate Exclusions)

- Protocol-semantic schedulers or background loops that advance DSM state by elapsed time
- Multi-hop / mesh routing
- Arbitrary message bus or chat semantics
- Desktop BLE

## Adding New Offline Features

Extend only via the handler or coordinator with protobuf-compatible frame types. Preserve invariants above and update CI gates if a new risk vector appears.

## Security & Integrity Notes

- All cryptographic commitments must originate from the bilateral transaction manager - do not recompute externally.
- Do not introduce alternative hashing or envelope versions without updating global contracts.

## Maintenance

If this path changes, update `scripts/check_forbidden_symbols.sh`, this README, and any frontend bridge utilities expecting frame semantics.

## Summary

This is a lean, deterministic transport conduit. Its correctness is enforced by design and by CI. BLE runtime timers are allowed for transport control only; any expansion must keep protocol semantics clockless and avoid resurrecting deprecated abstractions.
