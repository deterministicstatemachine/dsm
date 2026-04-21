# Bilateral Hardening, Race-Condition Audit & Test Coverage

Date: 2026-04-21
Status: design approved (checkpointed execution)
Author: Claude (Opus 4.7) for Brandon

## Goal

Produce a "trust it" bilateral surface by:
1. Auditing bilateral code for race conditions, concurrency hazards, and
   performance bottlenecks across the BLE offline path, core protocol logic,
   and SDK handlers/settlement.
2. Fixing high-confidence findings in place.
3. Building a deterministic test harness that lets us exercise the full
   3-phase commit protocol (Prepare → Accept → Commit) without live Android
   devices, with fault injection and adversarial peer scenarios.
4. Covering the harness surface with unit, property-based, and concurrency
   tests so future regressions get caught in CI.

## Non-goals

- New bilateral features.
- Changes to the wire format (envelope v3, protobuf v2.4.0 stay).
- Online bilateral path (TLS/HTTP) beyond interaction hazards with the BLE
  path.
- Live device testing. Everything must run in CI.
- Storage node changes (that surface has its own domain).

## Scope

**Primary target** — BLE offline path:
- `dsm_sdk/src/bluetooth/bilateral_ble_handler.rs` (5,355 lines)
- `dsm_sdk/src/bluetooth/bilateral_session.rs` (699 lines)
- `dsm_sdk/src/bluetooth/bilateral_transport_adapter.rs` (516 lines)
- `dsm_sdk/src/bluetooth/bilateral_envelope.rs` (387 lines)
- `dsm_sdk/src/bluetooth/ble_frame_coordinator.rs`

**Secondary audit** (interaction hazards only):
- Core: `dsm/src/core/bilateral_transaction_manager.rs` (1,882 lines),
  `bilateral_relationship_manager.rs` (1,153 lines),
  `state_machine/bilateral.rs`
- SDK handlers: `bilateral_impl.rs`, `bilateral_settlement.rs`,
  `bilateral_routes.rs`
- Storage: `storage/bilateral.rs` (2,430 lines),
  `client_db/bilateral_sessions.rs`, `client_db/bilateral_tip_sync.rs`
- JNI polling: `jni/bilateral_poll.rs`

Total: ~15,800 lines of bilateral code.

## Hard invariants (must hold across all changes)

From `CLAUDE.md` and the 12 hard invariants:
- BLAKE3 domain-separated, SPHINCS+ signatures, Base32 Crockford externally.
- No JSON in protocol paths. Protobuf only.
- No wall-clock time in protocol consensus.
- No TODO/FIXME/HACK markers.
- 4-layer architecture respected; no layer skipping.
- Token conservation: `B_{n+1} = B_n + Δ_{n+1}, B ≥ 0`.
- Tripwire: no double-spend of a parent tip.
- Single authoritative path (no legacy re-adds).

From the Per-Relationship Chain Model (spec §2.1, §2.2, §18):
- Each relationship (A↔B) has its own chain with its own state index n.
- The Per-Device SMT is a switchboard, not a history table.
- No global bilateral state_number per device.
- Balances are per-chain: `B_{n+1} = B_n + Δ`.

## Architecture of the test harness

### Deterministic two-peer BLE harness

Build `bilateral_test_harness` (new module under `dsm_sdk/src/bluetooth/`
guarded with `#[cfg(test)]` — or a dedicated `tests/common/` module) that
provides:

```
PeerPair {
  peer_a: TestPeer,
  peer_b: TestPeer,
  network: FakeNetwork,
}
```

- `TestPeer` wraps a `BilateralBleHandler` + in-memory client DB +
  deterministic clock + deterministic RNG.
- `FakeNetwork` is an in-process transport: every
  `TransportOutbound` from peer X is converted into a
  `TransportInboundMessage` for peer Y, subject to fault-injection rules.
- Fault injection:
  - `drop_every_nth(n)` / `drop_matching(predicate)` — simulate packet loss.
  - `delay_frames(Duration)` / `random_delay(Range)` — latency.
  - `reorder_window(n)` — out-of-order chunk delivery within a window.
  - `disconnect_at(event)` — hang up after a specific frame.
  - `corrupt_at(event)` — flip bits in a specific payload.
  - `partition()` / `heal()` — full network partition.
- `NetworkTap` — observe every frame on the wire for assertion.
- MTU clamp: force chunking behavior by capping frame size.

### Why not reuse `offline_real_protocol_ble_mock.rs` directly

That harness exercises the happy path well but does not expose structured
fault injection, does not support concurrent sessions on one peer, and is
not wired for proptest-style property checking. We will extract what's
reusable and extend.

## Phase plan (checkpointed — Brandon reviews at each ✋ )

### Phase 1 — Deterministic BLE harness ✋

Deliverable: harness module + 5–8 smoke tests proving it can drive a happy-
path 3-phase commit end-to-end without Android, and 2–3 fault-injection
tests proving the fault API works.

Gate: Brandon reviews harness API before Phase 2.

### Phase 2 — Race & hazard audit ✋

Walk `bilateral_ble_handler.rs` + `bilateral_session.rs` +
`bilateral_settlement.rs` with a concurrency lens. Audit targets:

1. Session state transitions under concurrent events (Preparing → Prepared
   → PendingUserAction → Accepted → Committed).
2. Concurrent prepare from same peer, different counterparty.
3. Commit-during-abort, reject-during-commit, expiry-during-handshake.
4. Chunk reassembly race: reorder, duplicate, drop.
5. Session GC vs fresh session on same counterparty.
6. Balance projection vs canonical state write ordering.
7. Event emission ordering (commit event before DB write, or vice versa).
8. `is_already_settled` scan + its replacement with O(1) lookup.
9. Reconciliation flag lifecycle.
10. `bilateral_tip_sync` updates during active session.

Deliverable: `docs/audits/2026-04-21-bilateral-findings.md` ranking
findings by (confidence × severity). Each finding pins file:line and notes
whether it's a bug, hardening opportunity, or perf issue.

Gate: Brandon picks which findings to fix, which to defer.

### Phase 3 — Fix + concurrency test suite ✋

For each picked finding:
1. Write a test in the harness that reproduces the hazard.
2. Fix the code.
3. Verify the test now passes and no regressions.

Plus: general concurrency test coverage independent of specific findings,
using tokio multi-threaded runtime and `loom` where appropriate for
lock-free claims.

Deliverable: per-finding commits, growing test suite.

Gate: Brandon reviews the diff per commit.

### Phase 4 — Property tests

Use the already-present `proptest` dep. Properties to verify:
- **Token conservation**: random sequence of prepare/accept/commit/abort
  preserves total tokens on both sides.
- **Idempotent commit**: applying the same commit twice produces the same
  state.
- **Chain adjacency**: every committed transition has `parent_tip`
  matching the relationship's prior head.
- **Balance projection consistency**: `balance_projections` always agrees
  with the canonical state post-settlement.
- **Protobuf round-trip**: prepare/accept/commit messages survive encode →
  decode → equal.
- **Replay rejection**: a second prepare with the same commitment hash is
  rejected.
- **Settlement idempotency**: `build_canonical_settled_state` is a pure
  function of the relationship chain + delta.

Deliverable: `tests/bilateral_properties.rs` + `tests/bilateral_concurrency.rs`.

### Phase 5 — Performance micro-benches (optional, informed by Phase 2)

Using `criterion` on hot paths:
- SMT leaf update on bilateral advance.
- Chunk reassembly.
- Settlement read path (known O(500) scan on `is_already_settled`).
- Proto encode/decode for commit envelope.

Only optimize where the bench shows meaningful improvement. Pre/post
numbers in the commit message.

### Phase 6 — Audit close-out

- Findings doc updated with "fixed" / "deferred" / "wontfix".
- CI runs the full new suite plus any existing bilateral tests.
- `memory.md` updated with trace notes (via the Stop hook lifecycle,
  automatic).

## Risks & mitigations

| Risk | Mitigation |
|------|-----------|
| Harness is too synthetic and misses real-world bugs | Pair harness tests with at least one live-device smoke run at Phase 6 if Brandon wants; harness must mirror real BLE frame shapes exactly |
| Fixing one race introduces another | proptest + concurrency tests run on every commit |
| Perf changes violate an invariant | Invariant-check skill runs after every Phase 3+ commit |
| Refactor bloat | Explicitly forbid: no API changes beyond what a finding requires, no speculative abstraction |
| Phase 2 finds 30 findings and Phase 3 drags | Brandon rank-orders at the Phase 2 gate; we fix the top N only |

## What "done" looks like

- Harness module merged and used for a growing test suite.
- `docs/audits/2026-04-21-bilateral-findings.md` lists every finding with
  status.
- ≥15 new bilateral tests (unit + proptest + concurrency) landing in CI.
- All existing bilateral tests still pass.
- Every high-confidence finding either fixed or explicitly deferred with
  rationale.
- No invariant regressions. No TODO/FIXME. No Co-Authored-By trailers.
  No push.

## Out-of-scope rails (restate for the avoidance of drift)

- Not touching: online path, storage nodes, DLV, emissions, frontend,
  Kotlin, wire format, CLAUDE.md, settings.
- Not adding: new bilateral features, new SDK APIs outside test scaffolding,
  new proto fields.

## Execution mode

Checkpointed. Brandon reviews at gates: after Phase 1 (harness),
after Phase 2 (findings doc), per-commit in Phase 3, and at
Phase 6 (close-out).
