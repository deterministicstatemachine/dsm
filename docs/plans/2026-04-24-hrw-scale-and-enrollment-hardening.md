# DSM Mainnet Readiness Plan: HRW Migration, Scale Mechanism Wiring, Multi-Device Enrollment Hardening

> **For Claude:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task.

---

## Context

**Why this plan exists.** Three problems surfaced during architectural review:

1. **§6/§17 placement primitive is unfit for scale.** The spec specifies classical Fisher-Yates over the active registry. The implementation at `dsm_storage_node/src/api/hardening.rs:95-116` faithfully matches the spec. But classical Fisher-Yates has the avalanche property: adding or removing a single node from the registry reshuffles the placement for ~100% of addresses. This makes replica re-placement (and therefore scale-out / eviction) bandwidth-catastrophic at any meaningful network size. **§11's repair semantics ("clients extend Permute(·) to restore N replicas") already presuppose bounded-churn behavior that Fisher-Yates does not provide — the spec is internally inconsistent.**

2. **Storage-node scale mechanism is skeleton-only.** Signal handlers, applicant ranking, eviction ranking, grace cycles, and PaidK receipts are all individually implemented and tested in `dsm_storage_node/src/api/registry_scaling.rs` and `paidk.rs`. The orchestration layer that turns capacity signals into actual topology change does not exist. No node emits its own UpSignal/DownSignal. No automatic registry-update trigger. No replica re-placement on registry change. PaidK receipts are recorded but never consulted during applicant acceptance. Grace cycles protect new nodes from eviction but don't gate quorum inclusion.

3. **Multi-device enrollment exists but is unauthenticated.** `dsm_client/.../sdk/storage_node_sdk.rs:1791-1910` (`add_secondary_device`) lets anyone with knowledge of `G` derive a new device ID and PUT it into the device tree at `/api/v2/identity/{genesis}/devtree/root`. The storage node accepts any bytes. There is no pre-enrollment verification of `G`, no root-device authorization, no bounded validator on the storage-node side, no MPC signature verification chain. The happy path works; the security guarantees do not exist.

**What this plan does.** Three sequenced phases that close all three gaps and bring DSM to mainnet readiness for storage-node scale dynamics and multi-device enrollment.

**What it does not do.** No work on DLV, emissions, NFC backup, bilateral transfer, BLE-direct enrollment optimization, or anything outside the three areas above. Those are tracked separately.

---

## Goal

Migrate placement to HRW (bounded-churn), wire the scale-mechanism orchestration (signal emission, auto-trigger, replica re-placement, PaidK gate, quorum grace), and harden multi-device enrollment with three-checkpoint attestation (network verification, root authorization, storage-node validation).

## Architecture

Three independent-but-sequenced phases. Phase 1 (spec amendment + primitive replacement) unblocks Phase 2 task 2.7 (replica re-placement requires bounded churn). Phases 1 and 3 can run in parallel. Phase 2 tasks 2.1-2.6 can begin in parallel with Phase 1; only 2.7 has the hard dependency. All phases preserve Invariant #12 (storage nodes index-only): the storage-node validator added in Phase 3 is a closed set of four checks (signature verify, hash derivation, version compare, RootBindingRecord presence) — no business logic, no policy interpretation, no unlock authority.

## Tech Stack

Rust (storage node, SDK, core), TypeScript/React (frontend), Kotlin/Android (mobile), JNI bridge, Protobuf v3 (DSM-CPE deterministic encoding), BLAKE3-256 (with domain separation tags), SPHINCS+ (post-quantum signatures), ML-KEM-768 (key exchange).

## Dependency Graph

```
Phase 1 (HRW)  ──────────────────────────► Phase 2 task 2.7 (replica re-placement)
                                            ▲
Phase 2 tasks 2.1-2.6 ──────────────────────┘
                                            │
Phase 3 (multi-device enrollment) ──────────┴── independent of Phase 1/2
```

**Recommended sequencing for one developer:** Phase 1 → Phase 2.1-2.5 → Phase 3 → Phase 2.6 → Phase 2.7. **For two developers in parallel:** Dev A takes Phase 1 + Phase 2; Dev B takes Phase 3.

---

# Phase 1 — HRW Placement Migration

**Phase 1 summary.** Replace classical Fisher-Yates over the active registry with Highest Random Weight (HRW / rendezvous) hashing. Spec amendment first, then code migration at all call sites of `permute_unbiased` used for placement, then test updates to verify the bounded-churn property. After this phase, registry membership change affects an expected fraction `1/|N|` of addresses rather than ~100%.

**Phase 1 prerequisite verification.** Audit confirmed BUCKET_C (full-permutation-uniformity dependencies) is empty across spec and code. HRW is structurally safe to substitute. See conversation history for the full audit; no re-verification required before starting.

---

### Task 1.1 — Spec amendment: §1 Purpose and Philosophy bullet

**File:** `.github/instructions/storagenodes.instructions.md`

**Step 1.** Open the file. Locate line 50 (in the "Purpose and Philosophy" section).

**Step 2.** Replace:
> • Deterministic placement and repair by keyed permutation over the active registry.

With:
> • Deterministic placement and repair by keyed HRW (Highest-Random-Weight / rendezvous) scoring over the active registry; bounded churn under membership change.

**Step 3.** No other edits in §1. Save.

**Acceptance:** line 50 contains the new wording. No other lines in the file modified by this task.

**Commit:** `spec(storagenodes): amend §1 to reflect HRW placement primitive`

---

### Task 1.2 — Spec amendment: §6 Replica set definition

**File:** `.github/instructions/storagenodes.instructions.md` (lines 91-98)

**Step 1.** Locate the §6 "Replica set" subsection (around lines 94-95).

**Step 2.** Replace:
> Replica set. Given active registry vector N (Section 9), redundancy (N,K):
> replicas(addr) = first N entries of Permute(H(DSM/place\0∥addr), N).

With:
> **Replica set (HRW / Rendezvous).** Given active registry vector 𝒩 = [node_id₀, …, node_id_{|𝒩|−1}] (§9), redundancy (N, K):
>
> &nbsp;&nbsp;s(addr, n) = H(DSM/place\0 ∥ addr ∥ n)   for each n ∈ 𝒩
> &nbsp;&nbsp;replicas(addr) = top N entries of 𝒩 ordered by (s descending, node_id ascending)
>
> **Property (bounded churn, informative).** Adding or removing a single node n* from 𝒩 changes replicas(addr) only for addresses where n* would have scored in the top N+1 — an expected fraction 1/|𝒩| of all addresses. §11 mid-cycle replacement requires this property.

**Step 3.** Leave the "PUT enforcement" paragraph after this (lines 96-98) unchanged.

**Acceptance:** §6 Replica set subsection reads as above. PUT enforcement text unchanged.

**Commit:** `spec(storagenodes): amend §6 to use HRW placement with bounded-churn property`

---

### Task 1.3 — Spec amendment: §11 Repair, Mid-Cycle Replacement, Continuity

**File:** `.github/instructions/storagenodes.instructions.md` (lines 183-186)

**Step 1.** Locate §11. Replace the body (lines 184-186) with:

> Reads succeed with any K replies; clients always verify addr from bytes.
>
> **On prune or voluntary exit of node n\*,** the affected address set is A(n\*) = {addr : n\* ∈ replicas(addr) under prior 𝒩}. For each addr ∈ A(n\*), the replacement replica is the (N+1)ᵗʰ-ranked node under prior 𝒩 by the §6 score function — equivalently, the Nᵗʰ-ranked node under 𝒩 ∖ {n\*}. The remaining N−1 replicas are unchanged.
>
> **Migration (push-based, client-driven).** Surviving replicas push content for addr to the replacement replica. Content is address-verified on receipt. The exiting node MAY relinquish storage on exit; no coordination with the replacement is required. A surviving replica MAY delete its `migrating_out` copy after receiving ≥ K−1 other-replica acknowledgments that the replacement holds the address; acknowledgments are raw bytes, not signatures.
>
> **Non-cascading.** Because only addresses in A(n\*) are affected, repair is bounded to an expected fraction 1/|𝒩| of the global address space per membership change. Addresses outside A(n\*) are untouched.
>
> Batching writes is recommended; acceptance is hash-only so client-written repairs are equivalent to operator-written.

**Acceptance:** §11 body matches above. Heading "11 Repair, Mid-Cycle Replacement, Continuity" unchanged.

**Commit:** `spec(storagenodes): amend §11 to specify push-based migration and ACK-gated deletion`

---

### Task 1.4 — Spec amendment: §17 Placement Determinism

**File:** `.github/instructions/storagenodes.instructions.md` (lines 312-316)

**Step 1.** Change the heading from `17 Permutation Determinism` to `17 Placement Determinism (HRW)`.

**Step 2.** Replace the §17 body with:

> Replica selection uses Highest-Random-Weight (HRW / rendezvous) hashing over the active registry. For each address x and each node n ∈ 𝒩:
>
> &nbsp;&nbsp;s(x, n) = H(DSM/place\0 ∥ x ∥ n)
>
> The replica set is the top N nodes ordered by score descending with bytewise-ascending node_id as tiebreak. Honest clients with identical 𝒩 MUST compute identical replica sets.
>
> **Rationale (informative).** This replaces classical Fisher-Yates over the full registry. HRW preserves deterministic unbiased top-N selection per address while bounding the effect of membership change to an expected fraction 1/|𝒩| of all addresses — the property §11 mid-cycle replacement presupposes. Classical full-shuffle permutation exhibits avalanche under membership change (~100% of addresses reshuffle on single add/remove) and is therefore incompatible with §11; it is removed in this revision.
>
> **Implementation note (informative).** Top-N selection can be computed with a bounded-size max-heap in O(|𝒩| log N) per address lookup; no full sort is required.

**Acceptance:** §17 heading and body match above. §18 (Acceptance Rules) immediately following is unchanged.

**Commit:** `spec(storagenodes): amend §17 to specify HRW algorithm; remove Fisher-Yates`

---

### Task 1.5 — Add HRW utility function

**File to create:** `dsm_storage_node/src/api/placement.rs`

**Step 1.** Create the file with module declaration. Add to `dsm_storage_node/src/api/mod.rs`: `pub mod placement;`.

**Step 2.** Implement (full code; do not paraphrase):

```rust
// SPDX-License-Identifier: Apache-2.0
//! HRW (Highest-Random-Weight / Rendezvous) placement primitive per spec §6/§17.
//! Deterministic top-N node selection per address, with bounded churn under
//! registry membership change.

use super::hardening::blake3_tagged;

/// Compute the HRW score for (addr, node_id).
/// s(addr, node) = BLAKE3("DSM/place\0" || addr || node_id) interpreted as big-endian u256.
/// Returns the 32-byte digest; callers compare lexicographically (descending = larger digest first).
pub fn hrw_score(addr: &[u8], node_id: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(addr.len() + node_id.len());
    buf.extend_from_slice(addr);
    buf.extend_from_slice(node_id);
    blake3_tagged("DSM/place", &buf)
}

/// Select the top-N nodes for a given address, ordered by HRW score descending,
/// with node_id ascending as tiebreak. Returns up to N entries (fewer if registry < N).
pub fn hrw_top_n<T: Clone>(addr: &[u8], nodes: &[T], n: usize, node_id_of: impl Fn(&T) -> &[u8]) -> Vec<T> {
    if nodes.is_empty() || n == 0 {
        return Vec::new();
    }
    let mut scored: Vec<([u8; 32], &T)> = nodes
        .iter()
        .map(|node| (hrw_score(addr, node_id_of(node)), node))
        .collect();
    // Sort by score descending, then node_id ascending for tiebreak
    scored.sort_by(|a, b| {
        b.0.cmp(&a.0).then_with(|| node_id_of(a.1).cmp(node_id_of(b.1)))
    });
    scored.into_iter().take(n).map(|(_, node)| node.clone()).collect()
}
```

**Step 3.** Write tests in the same file under `#[cfg(test)] mod tests`. Required test cases:
- `hrw_score_is_deterministic`: same inputs → same output.
- `hrw_score_differs_for_different_node`: same addr, different node_id → different score.
- `hrw_top_n_is_deterministic`: same inputs → same ordered output.
- `hrw_top_n_returns_n_entries_when_registry_larger`: 10 nodes, n=3 → 3 entries.
- `hrw_top_n_returns_all_when_registry_smaller`: 2 nodes, n=6 → 2 entries.
- `hrw_top_n_handles_empty`: empty nodes → empty result.
- `hrw_top_n_tiebreak_uses_node_id`: synthetic case where two nodes produce equal scores (use a controlled mock by directly constructing entries with crafted inputs); verify node_id ascending wins.
- **Bounded churn property** (the key property): 1000 random addresses, registry of 100 nodes; remove one node; assert that the set of addresses whose top-N changed is in [5, 30] (expected ~10 = 100 addresses × 1/N where N=10 not relevant here — recompute: with 100 nodes and N=6 replicas, removing one node should change top-6 for addrs where it was in top 7 — expected fraction 6/100 = 6% → ~60 of 1000). Adjust bounds to a generous interval [30, 90] to allow for variance.

**Step 4.** Run `cargo test -p dsm_storage_node placement::tests` — all pass.

**Acceptance:** module compiles, all tests pass, bounded-churn test confirms HRW property.

**Commit:** `feat(storage-node): add HRW placement primitive with bounded-churn tests`

---

### Task 1.6 — Migrate `get_replication_targets` to HRW

**File to modify:** `dsm_storage_node/src/replication.rs` (around lines 183-204)

**Step 1.** Update the doc comment on `get_replication_targets` to reference HRW (not Fisher-Yates) and §6/§17 as amended.

**Step 2.** Replace the body of `get_replication_targets`:

```rust
pub async fn get_replication_targets(&self, object_key: &str) -> Vec<pb::StorageNodeInfoV1> {
    let alive_nodes = self.get_alive_nodes();
    if alive_nodes.is_empty() {
        return Vec::new();
    }
    crate::api::placement::hrw_top_n(
        object_key.as_bytes(),
        &alive_nodes,
        self.config.replication_factor,
        |node| node.node_id.as_bytes(),
    )
}
```

(Adjust the closure to the correct field for `node_id` on `StorageNodeInfoV1` — verify by reading `pb::StorageNodeInfoV1` definition.)

**Step 3.** Remove the `permute_unbiased` import from this file if no longer used. Run `cargo check -p dsm_storage_node` to verify.

**Step 4.** Update the existing tests at `dsm_storage_node/src/replication.rs:590-655` (`get_replication_targets_deterministic` and similar): assertions on determinism stay valid; remove any assertions on full-permutation properties if present.

**Step 5.** Add one new test: `get_replication_targets_bounded_churn`: build registry of 50 nodes, compute targets for 200 distinct keys, remove one node from the alive set, recompute, assert the affected key set is in [5, 50] entries (expected ~12 = 200 × 6/50 ≈ 24, generous bounds for variance).

**Step 6.** Run `cargo test -p dsm_storage_node replication::tests` — all pass.

**Acceptance:** `get_replication_targets` uses HRW; existing determinism tests pass; new bounded-churn test passes.

**Commit:** `refactor(storage-node): migrate get_replication_targets to HRW per amended §6`

---

### Task 1.7 — Migrate `mirror_set_w` to HRW

**File to modify:** `dsm_storage_node/src/api/hardening.rs` (around lines 137-157)

**Step 1.** Read the current `mirror_set_w` implementation. Confirm it currently uses `permute_unbiased` to select first MMIRROR entries.

**Step 2.** Replace the body to use `crate::api::placement::hrw_top_n` instead. The seed becomes `node_id || sw` (window seed) used as the "address" for HRW; the input list is `ActivePositions ∖ exclude`; pick top MMIRROR entries.

**Step 3.** Update tests at `dsm_storage_node/src/api/hardening.rs:227-305`. Existing tests that assert determinism stay valid. Remove assertions that depend on full-permutation distribution. Add a `mirror_set_bounded_churn` test analogous to Task 1.6 step 5.

**Step 4.** Run `cargo test -p dsm_storage_node api::hardening::tests` — all pass.

**Acceptance:** `mirror_set_w` uses HRW; tests pass.

**Commit:** `refactor(storage-node): migrate mirror_set_w to HRW per amended §6`

---

### Task 1.8 — Verify no remaining placement call sites use `permute_unbiased`

**Step 1.** Run `Grep -n "permute_unbiased"` across the entire repo.

**Step 2.** For each remaining usage, classify: (a) test code that intentionally tests `permute_unbiased` itself — leave alone, the function may be retained as a utility; (b) production code path for placement — migrate to HRW; (c) production code path for some non-placement randomization — leave alone.

**Step 3.** Document findings in commit message.

**Step 4.** If `permute_unbiased` has no remaining production callers, leave the function definition in place (no rush to delete; future cleanup task).

**Acceptance:** `permute_unbiased` has no remaining placement call sites in production code.

**Commit:** `chore(storage-node): document remaining permute_unbiased usages post-HRW migration`

---

### Task 1.9 — Run invariant-check on Phase 1

**Step 1.** Invoke the `invariant-check` skill to verify no DSM hard invariants were violated by the spec edits or code changes.

**Step 2.** Run full storage-node test suite: `cargo test -p dsm_storage_node`.

**Step 3.** Run any cross-crate tests that exercise placement: `cargo test --workspace -- placement` (if any tagged).

**Acceptance:** invariant-check passes; all storage-node tests pass.

**Commit:** none (verification only).

---

# Phase 2 — Storage Node Scale Mechanism Wiring

**Phase 2 summary.** Wire the orchestration that turns capacity signals into actual topology change. Five missing pieces in dependency order. Tasks 2.1-2.5 do not depend on Phase 1. Task 2.6 (replica re-placement) requires Phase 1 complete because push-based bounded migration is only viable under HRW.

**Reusable infrastructure (from audit).** Use these existing primitives — do not duplicate:
- Signal handlers: `dsm_storage_node/src/api/registry_scaling.rs:54-160` (`submit_up_signal`, `submit_down_signal`)
- ΔP computation: `registry_scaling.rs:284-298` (`trigger_registry_update`)
- Eviction ranking and grace exclusion: `registry_scaling.rs:351-374`, `pg.rs:1379-1403`
- Applicant ranking: `registry_scaling.rs:320-335`
- Registry insertion/deletion: `pg.rs:1245-1257` (`upsert_registry_node`), `pg.rs:1294-1302` (`deactivate_registry_node`)
- PaidK status: `paidk.rs:39-143`
- Constants: `hardening.rs:41-42` (`U_UP=0.85`, `U_DOWN=0.35`)
- Replication push (for re-placement): `replication.rs:206-261` (`replicate_object`), outbox pattern with idempotency keys
- Maintenance hook: `replication.rs:420-456` (`maintenance_cycle`) — needs a tick driver

---

### Task 2.1 — Per-node utilization measurement

**File to create:** `dsm_storage_node/src/capacity.rs`

**Step 1.** Create module. Add `pub mod capacity;` to `dsm_storage_node/src/lib.rs` (or main.rs as appropriate).

**Step 2.** Implement:

```rust
// SPDX-License-Identifier: Apache-2.0
//! Per-node utilization measurement. bytes_used is the sum of stored object lengths
//! in the node's primary partition; capacity is configured at startup.

use crate::AppState;

pub struct UtilizationSnapshot {
    pub bytes_used: u64,
    pub capacity: u64,
    /// 0.0 to (potentially) >1.0 if over capacity.
    pub utilization: f64,
}

pub async fn measure_utilization(state: &AppState, capacity: u64) -> UtilizationSnapshot {
    let bytes_used = crate::db::sum_object_bytes(&state.db_pool).await.unwrap_or(0) as u64;
    let utilization = if capacity == 0 { 0.0 } else { bytes_used as f64 / capacity as f64 };
    UtilizationSnapshot { bytes_used, capacity, utilization }
}
```

**Step 3.** Add `sum_object_bytes(pool) -> Result<i64>` to `dsm_storage_node/src/db/pg.rs` and `sqlite.rs`. Implementation: `SELECT COALESCE(SUM(byte_len), 0) FROM objects` (verify the actual column name by reading the existing `upsert_object` calls).

**Step 4.** Tests in `capacity.rs`:
- `measure_utilization_zero_capacity_returns_zero`: capacity=0 → utilization=0.0
- `measure_utilization_basic`: insert 3 objects of 100 bytes each, capacity=1000 → utilization=0.3
- `measure_utilization_over_capacity_allowed`: insert 600 bytes into 500-byte capacity → utilization=1.2 (no error)

**Step 5.** `cargo test -p dsm_storage_node capacity::tests`.

**Acceptance:** utilization measurement works against test DB.

**Commit:** `feat(storage-node): add per-node utilization measurement`

---

### Task 2.2 — Cycle tick driver in `main.rs`

**File to modify:** `dsm_storage_node/src/main.rs`

**Step 1.** Locate where the server starts (after `db_pool` initialization, around line 358).

**Step 2.** Add a `tokio::spawn` after server start that runs an async loop:

```rust
let tick_state = state.clone();
let tick_capacity = server_config.capacity_bytes;  // add this to ServerConfig if not present
let tick_interval = std::time::Duration::from_secs(server_config.cycle_interval_secs.unwrap_or(60));
tokio::spawn(async move {
    let mut now_tick: i64 = 0;
    let mut interval = tokio::time::interval(tick_interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        now_tick += 1;
        // Drive replication maintenance
        if let Some(rep) = tick_state.replication.as_ref() {
            rep.maintenance_cycle(tick_state.clone(), now_tick);
        }
        // Drive capacity signaling (Task 2.3 wires this in)
        crate::scale::cycle_step(&tick_state, tick_capacity, now_tick).await;
    }
});
```

**Step 3.** If `ServerConfig` doesn't already have `capacity_bytes` and `cycle_interval_secs`, add them to the config struct and parsing logic. Sensible defaults: capacity from disk available space estimate or operator-set; cycle interval 60s.

**Step 4.** Add stub `pub mod scale;` and stub `cycle_step` returning immediately — Tasks 2.3-2.6 fill in.

**Step 5.** Verify the binary compiles and starts: `cargo build -p dsm_storage_node`. Smoke test: start the binary in test mode, observe cycle tick log lines.

**Acceptance:** tick loop runs at configured interval. `maintenance_cycle` is called each tick. `scale::cycle_step` is called each tick (currently a no-op).

**Commit:** `feat(storage-node): add cycle tick driver in main.rs`

---

### Task 2.3 — Signal emission task

**File to create:** `dsm_storage_node/src/scale.rs`

**Step 1.** Implement the signal-emission step within `cycle_step`. Decision logic with hysteresis:
- If `utilization >= U_UP (0.85)` → emit UpSignalV3 to peer storage nodes (POST to each peer's `/api/v2/scaling/up`)
- Else if `utilization <= U_DOWN (0.35)` → emit DownSignalV3 to peer storage nodes (POST to each peer's `/api/v2/scaling/down`)
- Else: silent

**Step 2.** Build the signal proto using the existing `UpSignalV3` / `DownSignalV3` types. Required fields:
- `node_id`: this node's ID
- `capacity`: configured capacity
- `anchors`: per spec, the recent ByteCommit hashes for the window. Pull from the node's own ByteCommit history (last `w` cycles where `w` is from `paidk.rs::DEFAULT_FLAT_RATE` neighbors — confirm window param from spec §19 default `w=3`).

**Step 3.** Discover peers from `RegistryV3` via the existing peer-listing path (look for `get_alive_nodes` or similar in `replication.rs`). Reuse this list; do not build a new discovery mechanism.

**Step 4.** Submit the signal via the existing handlers' POST endpoints. Use the same HTTP client used by replication.

**Step 5.** Tests:
- `signal_emission_above_u_up_emits_up`: utilization=0.9 → up signal posted (mock HTTP client)
- `signal_emission_below_u_down_emits_down`: utilization=0.2 → down signal posted
- `signal_emission_in_band_silent`: utilization=0.5 → no signal
- `signal_emission_at_thresholds`: utilization=0.85 → up; utilization=0.35 → down (boundary inclusive per spec §8)

**Step 6.** Run tests, verify, commit.

**Acceptance:** signal emission fires correctly per hysteresis. Verified in tests with mock HTTP client.

**Commit:** `feat(storage-node): wire UpSignal/DownSignal emission with U_up/U_down hysteresis`

---

### Task 2.4 — Auto registry-update trigger

**File to modify:** `dsm_storage_node/src/scale.rs` (extend Task 2.3's `cycle_step`)

**Step 1.** After signal emission, query the discovery window (DISCOVERY_WINDOW=4 from `registry_scaling.rs:33`). Count valid Up and Down signals received in the window. If `|up_count − down_count| > 0` AND the window is fully populated:
- Call `crate::api::registry_scaling::trigger_registry_update(state).await`. Reuse the existing function — do not reimplement.

**Step 2.** Add a guard to prevent re-triggering within the same window: track `last_trigger_cycle` in state; require `now_tick - last_trigger_cycle >= DISCOVERY_WINDOW`.

**Step 3.** Tests:
- `trigger_fires_when_window_full_and_delta_nonzero`: populate signals to make ΔP=2 → trigger called
- `trigger_silent_when_delta_zero`: equal up and down → no trigger
- `trigger_silent_when_window_not_full`: fewer than 4 cycles of signals → no trigger
- `trigger_respects_cooldown`: triggered, then triggered again within window → second is suppressed

**Step 4.** Run tests, verify, commit.

**Acceptance:** auto-trigger fires correctly. Cooldown prevents thrashing.

**Commit:** `feat(storage-node): auto-trigger registry-update on ΔP threshold within discovery window`

---

### Task 2.5 — Wire PaidK gate into applicant acceptance

**File to modify:** `dsm_storage_node/src/api/registry_scaling.rs` (lines 320-350, the applicant ranking and admission section)

**Step 1.** Locate the applicant admission loop (around lines 337-350 where `upsert_registry_node` is called).

**Step 2.** Before the `upsert_registry_node` call, add a PaidK check:

```rust
let paidk_satisfied = crate::api::paidk::is_paidk_satisfied_for_applicant(
    &state.db_pool,
    &applicant.seed_app,
).await.unwrap_or(false);
if !paidk_satisfied {
    log::info!("Rejecting applicant: PaidK not satisfied for seed_app {}", ...);
    continue;
}
```

**Step 3.** Add `is_paidk_satisfied_for_applicant(pool, seed_app) -> Result<bool>` to `paidk.rs`. Implementation: query receipts for the device identified by `seed_app`'s associated device_id, count distinct paid operators, return `count >= K`.

**Step 4.** Test:
- `applicant_with_paidk_satisfied_admitted`: seed receipts to satisfy K=3 → applicant admitted
- `applicant_without_paidk_rejected`: no receipts → applicant rejected, registry unchanged
- `applicant_with_partial_paidk_rejected`: 2 receipts when K=3 → rejected

**Step 5.** Run tests, verify, commit.

**Acceptance:** PaidK acts as a gate, not just a tracked metric.

**Commit:** `feat(storage-node): gate applicant acceptance on PaidK satisfaction (§16 enforcement)`

---

### Task 2.6 — Quorum-inclusion grace for new nodes (reader layer)

**File to modify:** `dsm_storage_node/src/replication.rs` (or wherever the read-path quorum decision happens — verify by grep for "K=3" or "quorum" or `replication_factor / 2 + 1`)

**Step 1.** Locate the read-path quorum logic. Identify where N candidate replicas are filtered to determine quorum-eligible replicas.

**Step 2.** Add a filter step: for each candidate replica, check whether it's currently within `G_new` cycles since admission. If yes, exclude from the quorum calculation but include in the request fanout (its response is informative but not decisive).

**Step 3.** Add `is_within_grace(pool, node_id, current_cycle, g_new) -> Result<bool>` to `pg.rs` (mirror the existing `count_down_signals_excluding_grace` pattern). Returns true if `first_cycle + g_new > current_cycle`.

**Step 4.** Tests:
- `grace_node_excluded_from_quorum_count`: 6 replicas, 1 is in grace → effective quorum is K=3 of 5
- `grace_node_response_does_not_decide_quorum`: grace node returns "got it", 2 others return data → does NOT count as K=3 (need a third non-grace response)
- `post_grace_node_counts_normally`: grace expired → counts toward quorum

**Step 5.** Run tests, verify, commit.

**Acceptance:** new nodes don't influence reads until G_new cycles have elapsed.

**Commit:** `feat(storage-node): exclude grace-period nodes from read quorum (§10 G_new enforcement)`

---

### Task 2.7 — HRW-based replica re-placement on registry change

**Hard prerequisite:** Phase 1 complete.

**File to create:** `dsm_storage_node/src/migration.rs`

**Step 1.** Add module. Implement push-based migration logic per amended §11:

```rust
pub async fn run_migration_for_registry_change(
    state: &AppState,
    prior_registry: &[NodeId],
    current_registry: &[NodeId],
    self_node_id: &[u8],
) -> Result<MigrationStats>
```

**What it does:**
1. Determine self's role: was self in prior_registry? In current_registry?
2. Iterate self's held addresses (use existing `crate::db::list_object_keys` or equivalent — confirm by grep; if no listing endpoint exists, add one with paginated cursor).
3. For each held address `addr`:
   - Compute `prior_replicas = hrw_top_n(addr, prior_registry, N)` and `current_replicas = hrw_top_n(addr, current_registry, N)`.
   - Compare:
     - If self ∈ prior_replicas AND self ∉ current_replicas → mark `migrating_out`, push to all new replicas in `current_replicas \ prior_replicas` via existing `replicate_object` outbox pattern (Task 1.6 already migrated this to HRW).
     - If self ∈ current_replicas AND self ∉ prior_replicas → no action (other surviving replicas push to us).
     - Else → no action for this address.

**Step 2.** ACK-gated deletion:
- Add `migration_ack` table with columns `(addr, recipient_node_id, ack_received_at_cycle)`.
- After push is queued, listen for `recipient_node_id` to fetch+verify the address (use existing replication outbox response or add a lightweight `/api/v2/migration/ack` endpoint; ACKs are bytes, not signatures).
- Delete `migrating_out` only after K-1 ACKs received from new replicas (where K=3, so 2 ACKs sufficient if K=3).

**Step 3.** Crash-safety: on storage-node restart, re-derive migration plan from current registry diff. Idempotent because:
- Pushes use existing idempotency keys (replication outbox already does this).
- Deletes are gated on ACK count, not on event order.

**Step 4.** Hook into `cycle_step` (Task 2.2): when `trigger_registry_update` (Task 2.4) observes a registry change, schedule `run_migration_for_registry_change` for the affected node IDs (self).

**Step 5.** Tests (use a mocked multi-node setup):
- `migration_self_evicted_pushes_to_new_replicas`: 6-node registry, self evicted → self pushes its addresses to the (N+1)th-ranked nodes.
- `migration_new_node_receives_pushes`: 6-node registry → 7-node registry; addresses where new node is in top-N get pushed to it by existing replicas.
- `migration_unaffected_addresses_skipped`: addresses where neither prior nor current top-N changed → no migration calls.
- `migration_ack_gated_deletion`: push without ACK → migrating_out NOT deleted; with K-1 ACKs → deleted.
- `migration_idempotent_on_restart`: simulate crash mid-migration; restart; verify plan re-derived and pushes resumed.
- `migration_bounded_per_change`: 1000 addresses on self, registry of 100 nodes, remove 1 node; assert affected address count is in expected range (≈60 = 1000 × 6/100).

**Step 6.** Run tests, verify, commit.

**Acceptance:** migration runs on registry change, push is bounded to affected addresses, ACK-gated deletion is safe.

**Commit:** `feat(storage-node): implement HRW-based push migration with ACK-gated deletion (§11)`

---

### Task 2.8 — Run invariant-check on Phase 2

**Step 1.** Invoke the `invariant-check` skill.

**Step 2.** Run `cargo test --workspace`.

**Step 3.** Manual integration check: bring up 6 storage nodes locally, observe one cycle of operation, verify utilization signals propagate, registry updates trigger, and migration runs without data loss when one node is shut down (eviction).

**Acceptance:** all invariants hold; integration check passes; no data loss observed.

**Commit:** none.

---

# Phase 3 — Multi-Device Enrollment Hardening

**Phase 3 summary.** The happy path of secondary device enrollment exists (`add_secondary_device` in storage_node_sdk.rs:1791-1910) but is unauthenticated — anyone with knowledge of `G` can write to the device tree. This phase adds the three-checkpoint attestation reviewed adversarially earlier, with the nine specific gap closures identified.

**Reusable infrastructure (from audit).** Use these — do not duplicate:
- Genesis QR generation: `dsm_client/frontend/src/components/qr/GenesisQrPanel.tsx`
- Base32 encode/decode: `dsm_client/frontend/src/utils/textId.ts` and `dsm_sdk/src/util/text_id.rs`
- Identity devtree endpoints: `dsm_storage_node/src/api/identity_devtree.rs` (GET/PUT root and proof)
- Add-secondary-device flow scaffolding: `add_secondary_device` (SDK), `Java_com_dsm_native_DsmNative_addSecondaryDevice` (JNI), `addSecondaryDevice` (frontend)
- Inbox spool table for mailbox: `dsm_storage_node/migrations/20250928_create_inbox_spool.sql`
- Inbox poller (client-side): `dsm_sdk/src/sdk/inbox_poller.rs`
- CDBRW responder: `dsm_sdk/src/security/cdbrw_responder.rs`

**What's missing (this phase builds):** RootBindingRecord type and storage; pre-enrollment verification of G against the network; bounded validator on identity-devtree PUT; root device authorization message and signing; storage-node validator on devtree writes; inbox push endpoint (currently pull-only); registry bootstrap (signed node-list in QR); R_G version binding to authorization; 12-char DevID fingerprint display; concurrent-enrollment serialization.

---

### Task 3.1 — Define `RootBindingRecord` proto

**File to modify:** `proto/dsm_app.proto`

**Step 1.** Add the message definition:

```proto
message MpcContributionV1 {
  // domain: "DSM/genesis-mpc-binding\0"
  bytes contributor_id = 1;       // storage node ID (32 bytes)
  bytes entropy = 2;              // 32 bytes
  bytes node_signature = 3;       // SPHINCS+ signature
}

message RootBindingRecordV1 {
  // domain: "DSM/identity/rootbinding\0"
  // Stored at storage-node key: blake3_tagged("DSM/identity/rootbinding", G)
  bytes genesis_hash = 1;                       // G (32 bytes)
  repeated MpcContributionV1 contributions = 2; // ≥ threshold (3) distinct contributors
  bytes pk_1 = 3;                               // SPHINCS+ public key of root device
  bytes cdbrw_1 = 4;                            // CDBRW digest of root device (32 bytes)
  bytes device_commitment = 5;                  // BLAKE3("DSM/device-commit\0" || pk_1 || cdbrw_1)
  uint64 schema_version = 6;
  // Storage-node bootstrap pointer (Phase 3 gap #5):
  // signed list of storage-node public keys this G's identity is anchored to.
  // Sig is by pk_1 over the canonical serialization of node_pubkeys.
  repeated bytes anchored_node_pubkeys = 7;
  bytes anchored_nodes_sig = 8;                 // SPHINCS+ sig by pk_1
}

message SecondaryDeviceAuthV1 {
  // domain: "DSM/secondary-auth\0"
  bytes genesis_hash = 1;        // G
  bytes new_device_id = 2;       // DevID_N (32 bytes)
  bytes new_device_pk = 3;       // pk_N (SPHINCS+ public key)
  bytes new_device_cdbrw = 4;    // CDBRW digest
  uint64 prior_rg_version = 5;   // Gap #2: bind to current R_G version
  bytes request_id = 6;          // Gap #9: nonce to prevent concurrent-enrollment ambiguity
  bytes root_signature = 7;      // SPHINCS+ sig by pk_1 over fields 1-6
}
```

**Step 2.** Run protobuf code generation: `cargo build -p dsm_proto` (or whatever the proto-gen target is — verify by reading `proto/build.rs` or similar).

**Step 3.** Commit.

**Acceptance:** types compile across Rust + frontend (TypeScript proto bindings auto-generated).

**Commit:** `feat(proto): add RootBindingRecordV1 and SecondaryDeviceAuthV1 (multi-device enrollment)`

---

### Task 3.2 — Storage-node endpoint for RootBindingRecord

**File to modify:** `dsm_storage_node/src/api/identity_devtree.rs` (add new routes alongside existing devtree routes)

**Step 1.** Add `GET/PUT /api/v2/identity/{genesis}/root-binding` endpoints. Mirror the pattern of `get_root` / `put_root` (lines 46-81 of identity_devtree.rs).

**Step 2.** Key derivation: `key_root_binding(genesis_b) = blake3_tagged("DSM/identity/rootbinding", genesis_b)` then base32. Add this helper alongside the existing `key_root` and `key_proof`.

**Step 3.** PUT validation (this is part of the bounded validator — see Task 3.4 for the devtree PUT validator; for root-binding PUT the rule is simpler):
- Body must parse as `RootBindingRecordV1`
- `record.genesis_hash` must equal the path `genesis` parameter
- `record.contributions.len() >= 3`
- All contribution signatures verify (SPHINCS+ check over `"DSM/genesis-mpc-binding\0" || session_id || device_commitment || entropy_i`)
- `record.anchored_nodes_sig` verifies under `record.pk_1`

**Step 4.** Constants: `MAX_ROOT_BINDING_BYTES = 16 * 1024` (16 KiB cap, generous for a few-contributor record).

**Step 5.** Tests:
- `key_root_binding_is_deterministic`
- `put_root_binding_rejects_oversized_body`
- `put_root_binding_rejects_genesis_mismatch`
- `put_root_binding_rejects_insufficient_contributions`
- `put_root_binding_rejects_invalid_mpc_sig`
- `put_root_binding_rejects_invalid_anchored_nodes_sig`
- `put_root_binding_accepts_valid_record`
- `get_root_binding_returns_stored_bytes`

**Step 6.** Run tests, verify, commit.

**Acceptance:** endpoint accepts valid records, rejects invalid; storage-node validator stays inside the closed list of checks.

**Commit:** `feat(storage-node): add RootBindingRecord endpoints with bounded validation`

---

### Task 3.3 — Publish RootBindingRecord on root-genesis creation

**File to modify:** `dsm_client/.../sdk/storage_node_sdk.rs` — locate the existing `create_root_genesis` function (search for "create_root_genesis" or "createRootGenesis" or similar). Add publishing step.

**Step 1.** After successful root genesis creation (real MPC, not the legacy single-node path), build a `RootBindingRecordV1`:
- `genesis_hash`: G
- `contributions`: collected from the MPC session (each contributor's id, entropy, sig)
- `pk_1`: this device's SPHINCS+ public key
- `cdbrw_1`: this device's CDBRW digest (via existing `fetch_dbrw_binding_key`)
- `device_commitment`: `BLAKE3("DSM/device-commit\0" || pk_1 || cdbrw_1)` — add this to the canonical formula and verify the same formula is used on the receiver side
- `anchored_node_pubkeys`: the public keys of the storage nodes that participated in MPC (these are the nodes the new device will trust at bootstrap — gap #5 fix)
- `anchored_nodes_sig`: SPHINCS+ signature by `sk_1` over the canonical serialization of `anchored_node_pubkeys`

**Step 2.** Publish the record to all storage nodes that participated in the MPC. Failure handling: if publish to majority fails, the genesis creation is considered failed and the user is notified to retry.

**Step 3.** **Gap #6 (atomicity):** add a check in the storage-node `put_root` (devtree root) handler — see Task 3.4 — that refuses devtree writes when no RootBindingRecord exists for the same G.

**Step 4.** Tests (integration-level with mocked storage nodes):
- `root_genesis_publishes_root_binding_record`
- `root_genesis_fails_if_majority_publish_fails`

**Step 5.** Commit.

**Acceptance:** root device publishes a valid RootBindingRecord on every successful genesis creation.

**Commit:** `feat(sdk): publish RootBindingRecord on root genesis creation`

---

### Task 3.4 — Bounded validator on `PUT /devtree/root`

**File to modify:** `dsm_storage_node/src/api/identity_devtree.rs`, specifically `put_root` (lines 65-81).

**Step 1.** Replace the body of `put_root`. The validator is a CLOSED list of FOUR checks — the spec section that documents this should reflect that no further checks may be added without amendment:

```rust
async fn put_root(
    Extension(state): Extension<Arc<AppState>>,
    Path(genesis): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    if body.is_empty() || body.len() > MAX_ROOT_BYTES {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let genesis_b = decode_base32_crockford(&genesis).ok_or(StatusCode::BAD_REQUEST)?;

    // CHECK 1: RootBindingRecord must be present for this G (Gap #6 atomicity).
    let rbr_key = key_root_binding(&genesis_b);
    let rbr_bytes = crate::db::get_object_by_key(&state.db_pool, &rbr_key)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::FAILED_DEPENDENCY)?; // 424
    let rbr: RootBindingRecordV1 = decode_proto(&rbr_bytes).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Body is expected to be a DevTreeRootUpdateV1 envelope: { proposed_root: bytes, prior_version: u64, new_version: u64, authorization: SecondaryDeviceAuthV1 (optional, only for additions) }
    let update: DevTreeRootUpdateV1 = decode_proto(body.as_ref()).map_err(|_| StatusCode::BAD_REQUEST)?;

    // CHECK 2: version monotonic. Compare against currently-stored version.
    let key = key_root(&genesis_b);
    let prior_stored = crate::db::get_object_by_key(&state.db_pool, &key).await.ok().flatten();
    let prior_version = prior_stored.as_ref()
        .and_then(|b| decode_proto::<DevTreeRootUpdateV1>(b).ok())
        .map(|u| u.new_version)
        .unwrap_or(0);
    if update.new_version != prior_version + 1 {
        return Err(StatusCode::CONFLICT); // 409
    }

    // CHECK 3: SPHINCS+ authorization signature verifies under rbr.pk_1
    //         over canonical("DSM/secondary-auth\0" || G || DevID_N || pk_N || CDBRW_N || prior_version || request_id)
    if let Some(auth) = update.authorization.as_ref() {
        verify_sphincs_plus(&rbr.pk_1, &canonical_auth_signing_input(auth), &auth.root_signature)
            .map_err(|_| StatusCode::FORBIDDEN)?;

        // CHECK 4: DevID derivation correctness. DevID_N == BLAKE3("DSM/devid\0" || pk_N || CDBRW_N || G).
        let derived = derive_devid(&auth.new_device_pk, &auth.new_device_cdbrw, &genesis_b);
        if derived != auth.new_device_id.as_slice() {
            return Err(StatusCode::FORBIDDEN);
        }
    }
    // (If authorization is absent — e.g. a primary-device-only update — only checks 1 and 2 apply.)

    // All checks passed. Store.
    let pool = &*state.db_pool;
    crate::db::upsert_object(pool, &key, body.as_ref(), b"identity", body.len() as i64)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::OK)
}
```

**Step 2.** Add a comment block above the function:

```rust
/// BOUNDED VALIDATOR — closed list of 4 checks per spec §X (multi-device enrollment).
/// No additional checks may be added without spec amendment.
///   1. RootBindingRecord present for G
///   2. Version monotonic (current+1)
///   3. SPHINCS+ authorization signature verifies under rbr.pk_1 (when present)
///   4. DevID derivation correct (when authorization present)
```

**Step 3.** Add helper functions: `decode_proto`, `canonical_auth_signing_input`, `derive_devid`, `verify_sphincs_plus`. Most likely already exist in `dsm_sdk` or `dsm/src/crypto` — search and reuse, do not duplicate.

**Step 4.** Tests covering each rejection path and the success path. Reuse the existing `identity_devtree.rs` test pattern.

**Step 5.** Commit.

**Acceptance:** PUT /devtree/root rejects unauthorized writes; accepts valid root-signed updates; the validator stays bounded to 4 checks.

**Commit:** `feat(storage-node): bounded validator on identity devtree root PUT (closed 4-check list)`

---

### Task 3.5 — SDK function: `verify_genesis_on_network`

**File to create:** `dsm_client/.../sdk/genesis_verify.rs`

**Step 1.** Implement:

```rust
pub struct VerifiedGenesis {
    pub genesis_hash: [u8; 32],
    pub pk_1: Vec<u8>,
    pub current_rg: Vec<u8>,
    pub current_rg_version: u64,
    pub anchored_node_pubkeys: Vec<Vec<u8>>,
}

pub async fn verify_genesis_on_network(
    g: [u8; 32],
    nodes: &[NodeUrl],
) -> Result<VerifiedGenesis, DsmError> {
    // 1. Quorum-read RootBindingRecord from at least 3 nodes; majority must agree on bytes.
    let rbr_bytes = quorum_get(nodes, &format!("/api/v2/identity/{}/root-binding", encode_base32_crockford(&g)), 3).await?;
    let rbr = decode_proto::<RootBindingRecordV1>(&rbr_bytes)?;

    // 2. Recompute G from binding inputs; abort if mismatch.
    let device_commitment = blake3_tagged("DSM/device-commit", &concat(&rbr.pk_1, &rbr.cdbrw_1));
    if device_commitment != rbr.device_commitment.as_slice() {
        return Err(DsmError::verification_failed("device_commitment mismatch"));
    }
    let recomputed_g = compute_g_from_binding(&rbr); // canonical formula — must match root-genesis creation
    if recomputed_g != g {
        return Err(DsmError::verification_failed("G recomputation mismatch"));
    }

    // 3. Verify each MPC contribution signature; require at least threshold (3) distinct contributors.
    let mut valid_contribs = 0;
    let mut seen_contributors = std::collections::HashSet::new();
    for contrib in &rbr.contributions {
        let signing_input = canonical_mpc_signing_input(&contrib.contributor_id, &contrib.entropy, &rbr.device_commitment);
        if verify_sphincs_plus(&lookup_node_pubkey(&contrib.contributor_id, &rbr.anchored_node_pubkeys)?, &signing_input, &contrib.node_signature).is_ok()
            && seen_contributors.insert(contrib.contributor_id.clone()) {
            valid_contribs += 1;
        }
    }
    if valid_contribs < 3 {
        return Err(DsmError::verification_failed("insufficient valid MPC contributions"));
    }

    // 4. Verify anchored_nodes_sig (registry bootstrap, gap #5).
    verify_sphincs_plus(&rbr.pk_1, &canonical_anchored_nodes_input(&rbr.anchored_node_pubkeys), &rbr.anchored_nodes_sig)
        .map_err(|_| DsmError::verification_failed("anchored_nodes_sig invalid"))?;

    // 5. Quorum-read current devtree root for G; verify root signature.
    let root_bytes = quorum_get(nodes, &format!("/api/v2/identity/{}/devtree/root", encode_base32_crockford(&g)), 3).await?;
    let update = decode_proto::<DevTreeRootUpdateV1>(&root_bytes)?;
    // Verify the auth-attached signature if present (otherwise it's a primary-only state — accept as-is).

    Ok(VerifiedGenesis {
        genesis_hash: g,
        pk_1: rbr.pk_1.clone(),
        current_rg: update.proposed_root.clone(),
        current_rg_version: update.new_version,
        anchored_node_pubkeys: rbr.anchored_node_pubkeys.clone(),
    })
}
```

**Step 2.** Implement helpers: `quorum_get` (queries N nodes, returns the byte string a majority agree on); `compute_g_from_binding`; `canonical_mpc_signing_input`; `canonical_anchored_nodes_input`; `lookup_node_pubkey`. Reuse existing crypto utilities where present.

**Step 3.** Tests (with mocked storage-node responses):
- `verify_succeeds_with_valid_record`
- `verify_fails_on_g_mismatch`
- `verify_fails_on_insufficient_contributions`
- `verify_fails_on_invalid_mpc_sig`
- `verify_fails_on_invalid_anchored_nodes_sig`
- `verify_fails_on_quorum_disagreement`

**Step 4.** Add to `dsm_sdk/src/lib.rs`: `pub mod genesis_verify;`.

**Step 5.** Commit.

**Acceptance:** function correctly verifies genuine records, rejects each tampering vector.

**Commit:** `feat(sdk): add verify_genesis_on_network with full MPC + anchored-nodes-sig verification`

---

### Task 3.6 — JNI binding for `verify_genesis_on_network`

**File to modify:** `dsm_client/android/app/src/main/jni/...` and `dsm_client/.../sdk/jni/secondary_device.rs`

**Step 1.** Add a JNI function `Java_com_dsm_native_DsmNative_verifyGenesisOnNetwork(env, class, genesis_hash_bytes, nodes_json_or_proto)` returning a serialized `VerifiedGenesis` envelope (or an error envelope).

**Step 2.** Add corresponding Kotlin binding in `DsmNative.kt`: `external fun verifyGenesisOnNetwork(genesisHash: ByteArray, nodes: ByteArray): ByteArray`.

**Step 3.** Smoke test from Android: invoke with synthetic genesis + mock node list; verify response envelope decodes.

**Step 4.** Commit.

**Acceptance:** JNI bridge calls SDK function; envelope decoding works on Kotlin side.

**Commit:** `feat(jni): expose verify_genesis_on_network across JNI bridge`

---

### Task 3.7 — Frontend genesis verification service

**File to create:** `dsm_client/frontend/src/services/genesis/genesisVerificationService.ts`

**Step 1.** Implement a service that calls the JNI verifier and surfaces per-step progress to the UI:

```typescript
export interface GenesisVerificationProgress {
  step: 'quorum_read' | 'recompute_g' | 'verify_mpc_sigs' | 'verify_anchored_sig' | 'fetch_rg' | 'verify_rg_sig' | 'done';
  status: 'in_progress' | 'success' | 'failed';
  errorMessage?: string;
}

export interface VerifiedGenesisResult {
  genesisHashBase32: string;
  pk1: Uint8Array;
  currentRgVersion: number;
  anchoredNodePubkeys: Uint8Array[];
}

export async function verifyGenesisOnNetwork(
  genesisHashBase32: string,
  onProgress?: (p: GenesisVerificationProgress) => void
): Promise<VerifiedGenesisResult> { ... }
```

**Step 2.** Use the existing JNI bridge pattern (mirror `addSecondaryDevice` in `frontend/src/services/genesis.ts`).

**Step 3.** Tests with mocked WebViewBridge: success path, each failure-mode error message renders correctly.

**Step 4.** Commit.

**Acceptance:** frontend can call genesis verification and receive structured progress + final verification result.

**Commit:** `feat(frontend): add genesisVerificationService backed by JNI`

---

### Task 3.8 — Update enrollment screen to require pre-verification

**File to modify:** `dsm_client/frontend/src/components/screens/` — locate the existing enrollment screen (search for `ScanRootQrScreen`, `SecondaryDeviceSetup`, or any screen using `addSecondaryDevice`).

**File to create:** `dsm_client/frontend/src/components/screens/EnterGenesisHashScreen.tsx` (replaces or supersedes the QR-only scan screen)

**Step 1.** Build a screen with two input modes (toggle): QR scan and text paste. Both feed the same downstream flow.

**Step 2.** On input received:
- Validate format (52 Crockford chars, decodes to 32 bytes). Show specific format errors.
- Parse and decode to bytes.
- Show "Verifying..." with per-step progress UI driven by `genesisVerificationService.verifyGenesisOnNetwork`.
- On success, navigate to root-device-approval-pending screen.
- On failure, surface the specific failure step with actionable message.

**Step 3.** Update `addSecondaryDevice` callers to require a `VerifiedGenesisResult` before proceeding. Add a runtime guard in the SDK function so that callers cannot bypass verification (defense-in-depth).

**Step 4.** Tests (frontend unit tests with mocked services).

**Step 5.** Commit.

**Acceptance:** the user cannot enroll a secondary device without successful pre-verification; failure modes are surfaced specifically.

**Commit:** `feat(frontend): require pre-enrollment genesis verification before add_secondary_device`

---

### Task 3.9 — Inbox push endpoint (storage-node-side)

**File to modify:** `dsm_storage_node/src/api/` — add a new file `inbox_push.rs` or extend the existing inbox-related routes.

**Step 1.** Add `POST /api/v2/inbox/{recipient_device_id}` that accepts a binary envelope and inserts into `inbox_spool`. Required fields in the request body: envelope bytes, sender_device_id, message_id (for idempotency).

**Step 2.** Validation (kept light — storage node still dumb):
- recipient_device_id is well-formed (32-byte base32)
- envelope is non-empty and within size cap (e.g., 32 KiB)
- message_id is unique (UNIQUE constraint already exists on inbox_spool)

**Step 3.** Tests for accept/reject paths.

**Step 4.** Commit.

**Acceptance:** any device can push an envelope into another device's inbox; the existing `inbox_poller.rs` will deliver it.

**Commit:** `feat(storage-node): add /api/v2/inbox/{recipient} POST endpoint for mailbox push`

---

### Task 3.10 — Root-device approval flow (mailbox handshake)

**Files to modify:** root-device frontend screen (new), SDK functions (new), inbox handlers (extend).

**Step 1.** New device side: after successful pre-verification, build a `SecondaryEnrollmentRequestV1` envelope (define this proto type if not present; fields: G, pk_N, CDBRW_N proof, request_id nonce, requesting_device_id) and push to root device's inbox via Task 3.9 endpoint. The root device's inbox address is derivable from `pk_1` in the verified record.

**Step 2.** Root device side: existing inbox poller picks up the envelope. New handler `handle_secondary_enrollment_request` decodes and:
- Verifies the request structure (CDBRW proof internal consistency, DevID derivation correctness — same checks the storage node will do; defense in depth)
- Surfaces an approval prompt to the user with:
  - The new device's CDBRW_1 fingerprint (last 12 Crockford chars, **displayed as 4+4+4 groups for human verification — Gap #8 fix**)
  - "Approve" and "Reject" actions

**Step 3.** On approval: build `SecondaryDeviceAuthV1` (Task 3.1), sign with `sk_1`, including:
- `prior_rg_version`: current R_G version (Gap #2 fix)
- `request_id`: copy from request envelope (Gap #9 fix)
- `root_signature`: SPHINCS+ over canonical input

Push the auth envelope back to the requesting device via the inbox push endpoint.

**Step 4.** **Concurrent enrollment serialization (Gap #9 part 2):** root device handler maintains a per-G in-flight set. If a second enrollment request arrives while the first is pending user approval, the second is queued behind the first; the user is shown a list and can approve/reject each individually. Each `request_id` binds the approval to that specific request.

**Step 5.** New device side: poller picks up the auth envelope. New handler verifies the authorization, then issues `PUT /api/v2/identity/{G}/devtree/root` with the new tree (existing `add_secondary_device` flow extended with the authorization payload).

**Step 6.** Tests covering: happy path; approval rejection; concurrent enrollments; replay attack on auth (reused request_id rejected).

**Step 7.** Commit.

**Acceptance:** the three-checkpoint attestation is operational — verification, approval with 12-char fingerprint and version binding, storage-node validation.

**Commit:** `feat(enrollment): root-device mailbox approval flow with 12-char fingerprint and request-id binding`

---

### Task 3.11 — Update QR encoder to include anchored node list

**File to modify:** `dsm_client/frontend/src/services/qr/genesisQrService.ts` and `GenesisQrPanel.tsx`.

**Step 1.** Extend `encodeGenesisQrDataFromBase32` to embed a signed pointer to the anchored storage-node list. Two options:
- (a) Embed the full `anchored_node_pubkeys` list in the QR (may push QR size into V8+).
- (b) Embed only `G + first 6 anchored_node_pubkeys` (enough for the new device to bootstrap and discover the rest from the RootBindingRecord). Recommended.

**Step 2.** Update the receiver-side decoder in the new device to extract both `G` and the anchored node list, and pass the latter as the `nodes: &[NodeUrl]` argument to `verify_genesis_on_network`.

**Step 3.** Document the QR format change in a comment block in `genesisQrService.ts`.

**Step 4.** Tests for round-trip encode/decode.

**Step 5.** Commit.

**Acceptance:** QR contains G + bootstrap node list; decoder produces both. Registry bootstrap (Gap #5) is closed.

**Commit:** `feat(qr): embed bootstrap node list in genesis QR for fresh-device trust chain`

---

### Task 3.12 — Mailbox rate-limiting (Gap #3)

**File to modify:** `dsm_storage_node/src/api/` — likely the inbox push endpoint added in Task 3.9.

**Step 1.** Add per-recipient rate limit: max N inserts per cycle window per `recipient_device_id`. Implementation: small in-memory counter with the cycle index (no signatures, no protocol — just spam protection at the HTTP layer). Reasonable values: 30 messages per cycle.

**Step 2.** On exceeded: return `429 Too Many Requests`.

**Step 3.** Tests: rapid inserts hit the limit; counter resets on cycle change.

**Step 4.** Commit.

**Acceptance:** mailbox cannot be flooded for any specific recipient.

**Commit:** `feat(storage-node): per-recipient rate limiting on inbox push`

---

### Task 3.13 — CDBRW proof semantics pin-down (Gap #4)

**Step 1.** Read `dsm_sdk/src/security/cdbrw_responder.rs:1-100` and surrounding files. Document in a NEW `dsm_sdk/src/security/cdbrw_proof_semantics.md` what the CDBRW "proof" actually proves and what verifiers can rely on.

**Step 2.** Specifically address: what exactly is `auth.new_device_cdbrw` in `SecondaryDeviceAuthV1`? Options:
- (a) Public commitment derived deterministically from device's PUF — the "proof" is the commitment value itself, and CDBRW security comes from the device's hardware uniqueness; the receiver cannot remotely verify the binding to hardware, only that the commitment is well-formed and consistent with later device-signed attestations.
- (b) A challenge-response from the responder code that requires the device's actual PUF inputs at proof time.

**Step 3.** Pick (a) or (b) based on what the existing responder actually produces. Update the `SecondaryDeviceAuthV1` proto comment block in Task 3.1 to reflect this. Update the storage-node validator (Task 3.4 check #4) to verify only what's actually verifiable.

**Step 4.** This is documentation + minor proto comment update — not a new code path. But the next dev MUST resolve this question before Phase 3 ships, otherwise the "CDBRW proof" check is theater.

**Step 5.** Commit.

**Acceptance:** there is a documented, defensible answer to "what does the CDBRW field in the auth envelope actually attest to."

**Commit:** `docs(crypto): document CDBRW proof semantics for multi-device enrollment`

---

### Task 3.14 — End-to-end enrollment integration test

**File to create:** `dsm/tests/integration/multi_device_enrollment.rs`

**Step 1.** Build a test that:
1. Spins up 6 storage nodes locally
2. Creates a real-MPC root genesis on device A; verifies RootBindingRecord published
3. Generates QR on device A
4. Decodes QR on device B; runs `verify_genesis_on_network`; verifies success
5. Pushes enrollment request via inbox; root device A receives, displays mock-approves
6. Root device A signs SecondaryDeviceAuthV1; pushes back via inbox
7. Device B picks up auth; PUTs new devtree root; storage-node validator accepts
8. Verifies new R_G is fetchable and contains both device IDs

**Step 2.** Add adversarial sub-tests:
- Tamper with G in QR → verification fails at step 4
- Tamper with RootBindingRecord on storage node → verification fails at step 4
- Replay old auth envelope → storage-node validator rejects (request_id binding)
- Concurrent enrollment from device C while B is mid-flow → both serialized correctly

**Step 3.** Commit.

**Acceptance:** end-to-end happy path works; all adversarial sub-cases fail safely.

**Commit:** `test(integration): end-to-end multi-device enrollment with attestation checkpoints`

---

### Task 3.15 — Run security-reviewer + invariant-check on Phase 3

**Step 1.** Invoke the `security-reviewer` skill with focus on the enrollment path: storage-node validator boundary, replay protection, rate limiting, CDBRW semantics.

**Step 2.** Invoke the `invariant-check` skill.

**Step 3.** Address findings; commit fixes if any.

**Acceptance:** clean reviews from both skills.

**Commit:** none (verification only).

---

# Cross-Phase Concerns

## Verification Strategy

For each task that touches code:
1. **Unit tests** for the new function/module (specified in the task).
2. **Integration tests** at the phase boundary (Tasks 1.9, 2.8, 3.14, 3.15).
3. **Skill-driven reviews:**
   - `invariant-check` after each phase
   - `security-reviewer` after Phase 3
   - `pbt-auditor` after Phase 1 to ensure HRW has property-based test coverage
4. **Manual smoke tests:** Phase 2.8 includes a 6-node local cluster check; Phase 3.14 includes end-to-end enrollment.

## Migration Safety / Rollback

- Phase 1 (HRW) is a one-way primitive change. There is no on-disk format change — placement is computed, not stored. Rollback is reverting the spec amendment + reverting the HRW commits; this is safe at any point before mainnet.
- Phase 2 (scale wiring) adds new functionality; nothing to roll back beyond reverting commits.
- Phase 3 (enrollment hardening) tightens existing behavior. Existing devices already enrolled under the old (unauthenticated) flow continue to work — the validator only checks new PUTs going forward. If migration of legacy device trees is needed (signing pre-existing trees with current `pk_1`), that is an additional task not in this plan; flag for follow-up if required.

## Skills to Invoke During Execution

- `superpowers:executing-plans` (overall execution discipline)
- `invariant-check` (after each phase)
- `security-reviewer` (Phase 3)
- `pbt-auditor` (Phase 1 HRW)
- `crypto-guide` (consultation during Phase 3 CDBRW work — Task 3.13)
- `wire-format` (consultation during Phase 3 proto additions — Task 3.1)
- `storage-guide` (consultation throughout — confirms invariant compliance)

## Pre-Flight for the Executing Developer

Before starting:
1. Read `.github/instructions/storagenodes.instructions.md` end-to-end.
2. Read `dsm_storage_node/src/api/registry_scaling.rs` (full file) and `dsm_storage_node/src/replication.rs` (full file).
3. Read `dsm_storage_node/src/api/identity_devtree.rs` (full file).
4. Read `dsm_client/.../sdk/storage_node_sdk.rs` lines 1791-1910 (existing `add_secondary_device`).
5. Familiarize with the conversation history that led to this plan (in particular: the §6 Fisher-Yates avalanche finding, the bounded-validator decision for Phase 3, and the nine gap closures).

## Critical Files Reference

| File | Phase | Purpose |
|------|-------|---------|
| `.github/instructions/storagenodes.instructions.md` | 1 | Spec amendments |
| `dsm_storage_node/src/api/hardening.rs` | 1 | `permute_unbiased` (legacy), `mirror_set_w` |
| `dsm_storage_node/src/api/placement.rs` | 1 | New HRW module |
| `dsm_storage_node/src/replication.rs` | 1, 2 | `get_replication_targets`, `replicate_object`, `maintenance_cycle` |
| `dsm_storage_node/src/main.rs` | 2 | Cycle tick driver |
| `dsm_storage_node/src/scale.rs` | 2 | New: signal emission + auto-trigger |
| `dsm_storage_node/src/capacity.rs` | 2 | New: per-node utilization |
| `dsm_storage_node/src/migration.rs` | 2 | New: HRW push migration |
| `dsm_storage_node/src/api/registry_scaling.rs` | 2 | PaidK gate wiring |
| `dsm_storage_node/src/api/paidk.rs` | 2 | `is_paidk_satisfied_for_applicant` |
| `dsm_storage_node/src/api/identity_devtree.rs` | 3 | Bounded validator on PUT, root-binding endpoints |
| `dsm_storage_node/src/api/inbox_push.rs` | 3 | New: mailbox push endpoint |
| `proto/dsm_app.proto` | 3 | RootBindingRecordV1, SecondaryDeviceAuthV1, etc. |
| `dsm_client/.../sdk/storage_node_sdk.rs` | 3 | `add_secondary_device` flow update, RootBindingRecord publishing |
| `dsm_client/.../sdk/genesis_verify.rs` | 3 | New: `verify_genesis_on_network` |
| `dsm_client/android/.../jni/...` | 3 | JNI binding for verification |
| `dsm_client/frontend/src/services/genesis/genesisVerificationService.ts` | 3 | New: frontend verification service |
| `dsm_client/frontend/src/components/screens/EnterGenesisHashScreen.tsx` | 3 | New: dual-input enrollment screen |
| `dsm_client/frontend/src/services/qr/genesisQrService.ts` | 3 | QR encoder update for bootstrap nodes |

## Out of Scope

- DLV / DeTFi work
- Emissions / DJTE / token policy
- NFC ring backup
- Bilateral transfer
- BLE-direct enrollment optimization (mailbox-only this round)
- Migration of legacy unauthenticated devtree entries to authenticated form (flag if needed)
- Storage-node validator extensions beyond the closed 4-check list (any extension is a spec amendment)

---

**End of plan.**
