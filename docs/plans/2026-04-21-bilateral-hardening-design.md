# Bilateral Hardening, Race-Condition Audit & Test Coverage

Date: 2026-04-21
Status: approved with pre-Phase-1 amendments (see "Amendments" section below)
Author: Claude (Opus 4.7) for Brandon

## Amendments (2026-04-21 pm, per Brandon review)

The initial plan slightly assumed a test-control surface that does not
yet exist and under-weighted several first-class audit targets. The
following amendments apply:

1. **Manual-accept is a process flag, not an in-harness convenience.**
   The harness does **not** rely on the adapter's auto-reply path. It
   toggles `set_manual_accept_enabled(true)` and drives accept/reject
   by calling `BilateralBleHandler` directly on the receiver side.
   Any "adversarial user-decision timing" is simulated by the harness
   itself (delay between receiving prepare and issuing accept), not by
   a nonexistent production control point.

2. **Restart / recovery semantics become a first-class audit lane.**
   `BilateralBleHandler::restore_sessions_from_storage` already exists
   and auto-recovers accepted sessions that carry the counterparty
   signature. Phase 2 audit and Phase 3 tests must cover: restore of
   persisted Prepared; restore of persisted PendingUserAction; restore
   of persisted Accepted with and without counterparty signature;
   duplicate replay after restore. Harness must expose a "simulate
   restart" shim.

3. **Chain-tip lifecycle is elevated above generic perf work.**
   The documented failure mode — clearing reconcile state incorrectly
   zeros the sender chain tip and the next BLE prepare fails with
   TipMismatch — makes tip persistence / reconcile / refresh ordering
   a top-tier invariant to pin with deterministic tests. Moved above
   Phase 5 perf work in the audit lane ordering.

4. **Same-counterparty exclusion + shared-SMT online/offline lock is
   a primary audit target.** The process-wide shared SMT and the modal
   synchronization lock (prevents concurrent online/offline transfers
   for the same relationship) get their own audit lane. Tests must
   verify: same-pair exclusion actually blocks; different-pair
   concurrency still proceeds; online reconcile flag transitions
   during a live BLE flow behave correctly.

5. **Event ordering guarantees become a first-class audit lane.**
   Audit must verify: DB write precedes event emission; no committed
   event is emitted if canonical settle failed; no duplicate committed
   event on retry / recovery.

6. **`loom` is demoted.** Most of this surface is async orchestration,
   protobuf framing, SQLite-backed persistence, and process-global
   state. `loom` is not the right tool. Replace with:
   - normal multi-threaded tokio tests for handler/session/settlement
     races,
   - `proptest` for protocol invariants,
   - `loom` only if a small pure synchronization unit (e.g. in-memory
     session map, frame reassembly bookkeeping) is cleanly extracted
     in its own crate-private module with no async dependencies.

7. **Harness owns logical ticks, not just RNG.** The BLE runtime uses
   monotonic activity ticks, and restored sessions carry an in-memory
   wall-clock placeholder. The harness must own both the logical
   transport tick stream and the restart-restore timing shim so that
   no test silently depends on `Instant::now()`.

8. **Phase 5 (perf) is hard-gated.** No perf work unless a failing
   benchmark is paired with either a correctness regression test or
   a measured hotspot surfaced by Phase 2. The known candidate is
   settlement-side duplicate detection / scanning; defer until
   correctness tests exist.

These amendments rewrite the audit lane ordering below. The phase
structure (1–6) and checkpoint gates remain unchanged.

---


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
  - `delay_ticks(n)` — logical-tick-based latency (no wall-clock).
  - `reorder_window(n)` — out-of-order chunk delivery within a window.
  - `disconnect_at(event)` — hang up after a specific frame.
  - `corrupt_at(event)` — flip bits in a specific payload.
  - `partition()` / `heal()` — full network partition.
- `NetworkTap` — observe every frame on the wire for assertion.
- MTU clamp: force chunking behavior by capping frame size.

**Control surfaces the harness owns (per amendment #1, #2, #7):**
- `set_manual_accept_enabled(true)` toggle — harness always drives
  accept/reject by calling the receiver handler directly, never relies
  on the adapter's auto-reply path.
- `TestPeer::simulate_restart()` — persist current sessions, drop the
  handler, rebuild from storage via `restore_sessions_from_storage`,
  verify auto-recovery where applicable.
- `TestPeer::tick()` / `advance_tick(n)` — override the logical
  transport tick stream. Restored sessions get a test-controlled
  placeholder instead of `Instant::now()`.
- Modal SMT exclusion mock — ability to simulate "online path currently
  holds the lock for pair (A↔B)" and assert BLE path blocks
  accordingly; conversely, pair (A↔C) proceeds.

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
`bilateral_settlement.rs` + `bilateral_tip_sync.rs` with a concurrency
lens. Audit lanes, in priority order:

**Lane A — Chain-tip lifecycle (top priority)**
- Reconcile state clear vs sender chain tip (known TipMismatch mode)
- Tip persistence across restart / restore
- Tip refresh ordering vs in-flight prepare/accept/commit
- `bilateral_tip_sync` updates during active session

**Lane B — Restart / restore / recovery semantics**
- Restore of persisted Prepared session
- Restore of persisted PendingUserAction session
- Restore of persisted Accepted session *with* counterparty signature
  (auto-recovery path)
- Restore of persisted Accepted session *without* counterparty signature
- Duplicate replay after restore
- In-memory wall-clock placeholder on restored sessions — ensure no
  production path depends on it

**Lane C — Same-counterparty exclusion + shared-SMT online/offline**
- Same pair, same parent tip, concurrent prepares
- Same pair, stale restored session vs fresh new session
- Online reconcile flag transitions during BLE flow
- Shared-SMT modal lock blocks same-relationship concurrency
- Shared-SMT modal lock permits different-relationship concurrency

**Lane D — Event ordering guarantees**
- DB write precedes event emission
- No `committed` event if canonical settle failed
- No duplicate `committed` event on retry / recovery
- No out-of-order event delivery across BilateralPhase transitions

**Lane E — Session state transitions under concurrent events**
- Preparing → Prepared → PendingUserAction → Accepted → Committed
- Commit-during-abort, reject-during-commit, expiry-during-handshake
- Session GC vs fresh session on same counterparty
- Concurrent prepare from same peer to different counterparty

**Lane F — Chunk reassembly & transport hazards**
- Reorder, duplicate, drop
- Corrupt chunk vs reassembly checksum
- MTU variation across chunk counts

**Lane G — Balance projection vs canonical state**
- Ordering of `balance_projections` write vs canonical state write
- `is_already_settled` replay guard (correctness before perf)

Deliverable: `docs/audits/2026-04-21-bilateral-findings.md` ranking
findings by (confidence × severity) *within* each lane. Each finding
pins file:line and notes whether it's a bug, hardening opportunity, or
perf issue.

Gate: Brandon picks which findings to fix, which to defer.

### Phase 3 — Fix + concurrency test suite ✋

For each picked finding:
1. Write a test in the harness that reproduces the hazard.
2. Fix the code.
3. Verify the test now passes and no regressions.

Plus: general concurrency test coverage independent of specific findings,
organized by the Lane A–G audit targets, using tokio multi-threaded
runtime. `loom` is **not** applied to the orchestration/storage/global-
state surface (wrong tool). It is only applied to a small extracted
synchronization unit if one is cleanly isolated in its own module with
no async dependencies (e.g. in-memory session map, frame reassembly
bookkeeping).

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

### Phase 5 — Performance micro-benches (hard-gated, optional)

**Gate:** No perf work lands unless a failing `criterion` benchmark is
paired with (a) a correctness regression test covering the same path,
or (b) a measured hotspot surfaced by Phase 2 with concrete evidence.

Candidate paths (only if gate passes):
- Settlement-side duplicate detection / scanning
  (`is_already_settled` O(500) scan — known smell, correctness first).
- SMT leaf update on bilateral advance.
- Chunk reassembly.
- Proto encode/decode for commit envelope.

Pre/post numbers in the commit message. No optimization where the bench
does not show meaningful improvement.

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
