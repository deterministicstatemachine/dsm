# State-Number Removal Refactor — Checkpoint

**Date:** 2026-04-15
**Branch:** `cryptskii/vigorous-gould`
**Plan file:** `~/.claude/plans/rustling-frolicking-swan.md` (approved)
**Status:** `dsm` crate builds clean (0 errors). `dsm_sdk` has 33 errors remaining.

**Completed:**
- `device_state.rs` with `DeviceState`, `RelationshipChainState`, `AdvanceOutcome`, `BalanceDelta` (new canonical types per §2.2, §4, §8)
- `state_number` removed from `State` struct, `StateParams`, `StateContext`, `RelationshipContext`, `Balance::from_state`, `Balance::last_updated_tick`
- `state_number` removed from all hash/entropy paths: `compute_hash`, `pre_finalization_hash`, `to_bytes`, all entropy derivation
- All acceptance-predicate counter checks deleted (§4.3 compliance)
- `hashchain.rs` rewritten to hash-based indexing (no counter)
- `checkpoint.rs` `state_number` removed from struct + signing payload
- BCR archive schema refactored: `state_number` column dropped, `ORDER BY rowid ASC`
- `SparseIndexVerifier` rewritten to hash-adjacency only
- `hierarchical_device_management.rs` counter-based traversal replaced with hash adjacency

**Remaining (dsm_sdk, 33 errors):**
- `hashchain_sdk.rs` (10): calls removed `HashChain::get_state_by_number`. Need to migrate to `get_state_by_hash` or hash-based walk.
- `token_sdk.rs` (8): mostly `Balance::from_state` 3-arg calls that my regex missed (multiline).
- `wallet_sdk.rs` (6): state.state_number reads on actual `State` objects.
- `bitcoin_tap_sdk.rs` (4): state.state_number reads.
- `token_state.rs` (3): Balance::from_state calls.
- Various handlers (7 total): mixed state_number reads on State vs SDK types.
- `token_types.rs` (6 from dsm crate): These are test compilation errors, not lib errors.
- **CAUTION**: My bulk sed incorrectly replaced `.state_number` on non-State types (BilateralChainTip, ChainTipInfo, BilateralState). Those types have their own legitimate `state_number` fields. Need to revert `hash[0] as u64` → `state_number` in those files.

---

## Why this refactor exists

DSM's code has two parallel, disconnected state models:

1. **Monolithic `State`** in `dsm/src/types/state_types.rs` — a device-level god object with `state_number: u64`, `token_balances: HashMap<String, Balance>`, and `prev_state_hash`. `state_number` was baked into the canonical hash (`compute_hash`, `pre_finalization_hash`, `to_bytes`), making it cryptographically load-bearing. This directly violates whitepaper §4.3: *"There are no timestamps, heights, or counters in acceptance predicates."*

2. **Bilateral SMT** in `dsm/src/merkle/sparse_merkle_tree.rs` — a real Per-Device SMT per §2.2, keyed by relationship, with leaves as chain tips `h_{A↔B}`. Already correct. Used only by `BilateralTransactionManager`. **Never wired into `apply_transition`.**

`apply_transition` never touches the SMT. The SMT sits unused as device head. Every operation (faucet, bilateral, mint, DJTE) bumps `state_number` and mutates the shared `token_balances` hashmap, which is why concurrent operations cascade into balance loss.

The correct model, per whitepaper §2.2, §4, §6.1, §8:

- Device state = `(G_A, DevID_A, r_A, {RelChain_{A↔B}}, {B^T}, R_G-proof)` where `r_A` is the Per-Device SMT root.
- Each transition advances one relationship chain, replaces one SMT leaf, produces `r_A → r'_A`.
- Token balances are device-level fungible scalars keyed by CPTA `policy_commit` (32B), witnessed on each state but not sourced from the chain state.
- **No counters** in acceptance predicates or canonical hashes.
- Concurrency safety comes from: (1) single-writer device lock, (2) DBRW anti-cloning, (3) per-relationship Tripwire. First-commit-wins at the head pointer.

See `~/.claude/plans/rustling-frolicking-swan.md` for the full plan and the Gemini adversarial-review response.

---

## Progress so far

### Completed (sound, compiles cleanly for the new code)

#### New file: `dsm/src/types/device_state.rs`

Defines the canonical post-refactor types. Additively created; not yet wired into `apply_transition` or callers.

- `DeviceState` — per-device head holder. Fields:
  - `genesis: [u8; 32]`, `devid: [u8; 32]`, `public_key: Vec<u8>`
  - `smt: SparseMerkleTree` — the actual head via `smt.root()`
  - `balances: BTreeMap<[u8; 32], u64>` — **keyed by 32-byte CPTA `policy_commit`** per §9 and adversarial-review Issue 5 (eliminates hash-time policy resolution dependency)
  - `tips: BTreeMap<[u8; 32], RelChainTip>` — tip-only cache, no full history (full history lives in BCR)
- `RelationshipChainState` — per-chain state object. Carries `rel_key`, `embedded_parent`, `counterparty_devid`, `operation`, `entropy`, `encapsulated_entropy`, `balance_witness`, sigs, optional `dbrw_summary_hash`. **No `state_number`, no `sparse_index`.** Canonical hash via `compute_chain_tip()` with explicit length-prefixed field ordering.
- `AdvanceOutcome` — result of `DeviceState::advance()`, contains `new_device_state`, `new_chain_state`, `smt_proofs: SmtReplaceResult`, `parent_r_a`, `child_r_a` for caller-level CAS.
- `BalanceDelta { policy_commit, direction: BalanceDirection, amount }` — credit/debit with overflow/underflow checking per §8 eq. 10.
- `DeviceState::advance(rel_key, counterparty_devid, op, entropy, enc_entropy, deltas, initial_chain_tip, dbrw_summary_hash) -> Result<AdvanceOutcome>` — pure function, does not mutate `self`. Wires `smt_replace()` atomically.

Registered in `dsm/src/types/mod.rs` as `pub mod device_state;`.

**This file builds clean. It is not used anywhere yet.** It's the landing pad for the rest of the refactor.

#### Surgery on `dsm/src/types/state_types.rs`

- **`State` struct** (line 313 area): removed `state_number: u64` field. `id` field repurposed from `format!("state_{}", state_number)` to `String::new()` in `State::new` and `"genesis".to_string()` in `new_genesis`.
- **`StateParams` struct** (line 68 area): removed `state_number: u64` field. `StateParams::new()` is now a 3-arg function `(entropy, operation, device_info)`, was 4-arg.
- **`State::compute_hash()`** (line 610 area): removed `hasher.update(&self.state_number.to_le_bytes())` — the direct §4.3 violation. The hash now: domain tag "DSM/state-hash" → `prev_state_hash` → `entropy` → `encapsulated_entropy?` → `operation.to_bytes()` → `device_info.device_id` → `device_info.public_key` → `forward_commitment?` → sorted token_balances. **Note: balance sorting is still by `String` token_id key, not by 32-byte `policy_commit`. That's axis 2 of the plan, still pending.**
- **`State::pre_finalization_hash()`**: removed `state_number.to_le_bytes()`.
- **`State::to_bytes()`**: removed `put_u64(&mut out, self.state_number)` and the `put_u64` import that became unused.
- **`State::value()`**: deleted entirely. Was computing a u64 from `sparse_index` + `state_number` for non-normative purposes.
- **`State::validate_for_state_number()`**: deleted entirely.
- **`State::calculate_sparse_indices()`**: deleted entirely.
- **`State::calculate_basic_sparse_indices()`**: deleted entirely.
- **`State::transition_count()`**: deleted entirely.
- **`State::with_relationship_context()`**: removed `counterparty_state_number` parameter. Signature is now `(counterparty_id, counterparty_public_key)`, was 3-arg.
- **`State::with_relationship_context_and_chain_tip()`**: removed `counterparty_state_number` parameter.
- **`State::get_counterparty_state()`**: deleted (returned `counterparty_state_number`).
- **`RelationshipContext` struct** (line ~2480 area): removed `entity_state_number: u64` and `counterparty_state_number: u64` fields. `RelationshipContext::new()` and `new_with_chain_tip()` constructors no longer take or set these.

#### Approved plan and adversarial review

Plan at `~/.claude/plans/rustling-frolicking-swan.md` was submitted to Gemini 2.5 Flash for adversarial critique. Gemini raised 6 issues, 2 dismissed with explicit reasoning (Issue 1: straight-hash-chain prevents idempotency collapse; Issue 6: §4.3 predicates check hash content, so counters in the hash ARE acceptance checks), 4 drove plan revisions. See the plan file's "Adversarial review" section for engagement detail.

---

## Current broken state

`cargo build -p dsm` fails with **190 errors across 16 files**. Every error is a direct consequence of the struct surgery above. No semantic errors, no logic bugs introduced — purely field-removal cascade.

### Error kinds

```
error[E0061]: this function takes 3 arguments but 4 arguments were supplied
error[E0560]: struct `RelationshipContext` has no field named `counterparty_state_number`
error[E0560]: struct `RelationshipContext` has no field named `entity_state_number`
error[E0609]: no field `counterparty_state_number` on type `&RelationshipContext`
error[E0609]: no field `entity_state_number` on type `&RelationshipContext`
error[E0609]: no field `state_number` on type `&&state_types::State`
error[E0609]: no field `state_number` on type `&state_types::State`
error[E0609]: no field `state_number` on type `StateParams`
error[E0609]: no field `state_number` on type `state_types::State`
```

Two `E0061` (wrong arg count to `StateParams::new`). The rest are field reads on `State` or `RelationshipContext` that no longer exist.

### Files with errors (priority order for fixup)

| Priority | File | Notes |
|----------|------|-------|
| P1 | `dsm/src/types/state_builder.rs` | Thin builder over `State` + `StateParams`. Needs `state_number` parameter removed. |
| P1 | `dsm/src/core/state_machine/transition.rs` | The core transition path. `apply_transition → create_next_state` bumps `state_number` at line ~1020 and checks `state_number != prev + 1` at line ~519. Both must go. **This file also needs the eventual `advance(&DeviceState, ...)` rewrite** for Phase 2, but for Phase 1 just remove counter references. |
| P1 | `dsm/src/core/state_machine/state.rs` | Re-exports / wrappers. |
| P1 | `dsm/src/core/state_machine/mod.rs` | 19 refs. Module glue. |
| P1 | `dsm/src/core/state_machine/hashchain.rs` | 22 refs. Hash-chain walk logic. Almost certainly reads `state.state_number` for sparse navigation. Can delete or replace with chain_tip-based navigation. |
| P1 | `dsm/src/core/state_machine/relationship.rs` | 19 refs. Bilateral relationship tracking. |
| P2 | `dsm/src/core/token/token_state_manager.rs` | 15 refs, mostly `current_state.state_number + 1` in `create_token_state_transition`. Just remove. |
| P2 | `dsm/src/core/identity/mod.rs` | 5 refs. Identity construction. |
| P2 | `dsm/src/core/identity/hierarchical_device_management.rs` | **41 refs** — the biggest concentration. Likely tree-structural tracking that uses `state_number` as a serial. Needs careful audit — may have some intentional counters for device tree versioning (§3) that are OK to keep as Device Tree index numbers, NOT state counters. Double-check before deletion. |
| P2 | `dsm/src/core/bilateral_transaction_manager.rs` | 3 refs. Already uses `BilateralRelationshipAnchor { chain_tip }` correctly; just needs stragglers removed. |
| P3 | `dsm/src/core/security/bilateral_control.rs` | 16 refs. Security checks on bilateral flow. |
| P3 | `dsm/src/core/security/manipulation_resistance.rs` | 7 refs. Replay/tamper checks. |
| P3 | `dsm/src/core/verification/dual_mode_verifier.rs` | 3 refs. |
| P3 | `dsm/src/core/state_machine/random_walk.rs` | 3 refs. Position generation; may use `state_number` as an entropy input — replace with chain tip. |
| P3 | `dsm/src/vault/limbo_vault.rs` | 9 refs. DLV lifecycle. |

Plus `state_types.rs` internal tests (`#[cfg(test)] mod tests`) — several tests construct `State::new(StateParams::new(7, ...))` and assert `state.state_number == N`. These need updating to drop the counter arg and delete counter assertions.

### What the `dsm_sdk` crate probably needs

Not measured yet. `dsm_sdk` depends on `dsm::types::state_types::State` extensively (I audited the imports earlier — 18 files in `dsm_sdk` import `State` or `state_types`). When `dsm` compiles clean, `dsm_sdk` will surface its own wave of errors. Likely patterns:
- `state.state_number` reads in wallet/handler code
- `Balance::from_state(value, hash, state_number)` calls (the `Balance` API still takes a `state_number` for `last_updated_tick` — this is axis 2 / Phase 1 partial work)
- Counter-based checks in bilateral settlement handlers

---

## Resume instructions

### Step 1: Rebuild to confirm baseline error count

```bash
cd /Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/deterministic_state_machine
DSM_PROTO_ROOT=/Users/cryptskii/Desktop/claude_workspace/dsm/proto \
  cargo build -p dsm 2>&1 | grep -E "^error\[" | wc -l
# Expect: 190 (or similar; may drift slightly between fixes)
```

### Step 2: Fix P1 files first (the build won't progress until transition.rs is clean)

For each P1 file, the pattern is:

1. `grep -n "state_number\|entity_state_number\|counterparty_state_number" <file>`
2. For each hit:
   - `state.state_number` reads → delete the expression, replace with `0u64` if the value is fed into another API, or delete the surrounding logic if it's a counter-based check like `if a.state_number == b.state_number + 1`.
   - `next_state.state_number += 1` / `state_number: N` in struct init → delete the line.
   - `StateParams::new(N, entropy, op, dev)` → `StateParams::new(entropy, op, dev)`.
   - `with_relationship_context(id, counter, pk)` → `with_relationship_context(id, pk)`.
   - `ctx.counterparty_state_number` / `ctx.entity_state_number` → delete the expression or replace with `0u64` if a number is needed.
3. Build after each file. Track the error count shrinking.

### Step 3: Fix the `state_number != prev_state.state_number + 1` acceptance check in `transition.rs`

Around line 519 in the pre-refactor file. This is the **core §4.3 violation** in the predicate path — a counter comparison used as an acceptance check. Delete it entirely. Adjacency is enforced by `prev_state_hash` embedding, not by counter arithmetic.

### Step 4: Fix the `next_state.state_number += 1` line in `create_next_state`

Around line 1020 in the pre-refactor file. Delete the line. The new state's identity comes from `entropy` + `prev_state_hash` + op content per the canonical hash.

### Step 5: Delete sparse_index construction that uses state_number

In `create_next_state` there's a `calculate_sparse_indices(next_state.state_number)` call. The function doesn't exist anymore. Just delete the block that computes and assigns `next_state.sparse_index`. Leave `sparse_index` as its `SparseIndex::default()` value; per §2.2 it's advisory only and not in the canonical hash.

### Step 6: Work through P2 files

`hierarchical_device_management.rs` is the biggest risk. Before mass-deletion, `grep -n "state_number" dsm/src/core/identity/hierarchical_device_management.rs` and read the context. Some of these may be Device Tree indices (§3) — which are legitimate ordering for device add/remove events. The heuristic:

- If it's `state.state_number` on a `State` object → definitely a counter read, delete.
- If it's a standalone `u64` named "state_number" that's tracking device-tree version/index → might be legitimate, leave if it's not hashed.
- If it's fed into a BLAKE3 hash or a signature payload → delete (spec violation).

### Step 7: Work through P3 files

Mostly mechanical. Same patterns.

### Step 8: Fix `state_types.rs` internal tests

```bash
grep -n "state_number" dsm/src/types/state_types.rs
```

Find the `#[cfg(test)] mod tests` block (around line 1100+) and fix test cases:
- `StateParams::new(7, ...)` → `StateParams::new(...)`
- `assert_eq!(s.state_number, 42)` → delete
- `assert_eq!(ctx.counterparty_state_number, 5)` → delete
- `assert_eq!(pc.min_state_number, 10)` → special case (see "Known gotchas")

### Step 9: Build the `dsm` crate clean

```bash
cd /Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/deterministic_state_machine
DSM_PROTO_ROOT=/Users/cryptskii/Desktop/claude_workspace/dsm/proto cargo build -p dsm 2>&1 | tail -20
```

No errors. Warnings OK.

### Step 10: Fix `dsm_sdk`

```bash
DSM_PROTO_ROOT=/Users/cryptskii/Desktop/claude_workspace/dsm/proto cargo build -p dsm_sdk 2>&1 | grep -E "^error\[" | wc -l
```

Same patterns. Fix file by file.

### Step 11: Run the dsm test suite

```bash
DSM_PROTO_ROOT=/Users/cryptskii/Desktop/claude_workspace/dsm/proto cargo test -p dsm --lib 2>&1 | tail -30
```

Expect many hash-comparison test failures. State hashes all changed because `state_number` is no longer in them. Fix assertion-based tests by recomputing the expected values at test time, or remove hash-value assertions that were hardcoded to specific digests.

### Step 12: Axis 2 — balance keying migration

Once axis 1 (counter removal) is clean, begin axis 2:

- Change `State.token_balances: HashMap<String, Balance>` → `HashMap<[u8; 32], u64>` keyed by `policy_commit`.
- Update `compute_hash` to iterate by 32-byte key directly (BTreeMap preferred for determinism).
- Fix `Balance::from_state(value, hash, state_number)` — remove the `state_number` parameter (currently stored as `last_updated_tick`, which reaches the hash via `Balance::to_le_bytes()`).
- Update every caller that constructs or reads `token_balances`.

Same rustc-driven approach.

### Step 13: Axis 3 — DeviceState wiring

- Rewrite `apply_transition` → `advance(&DeviceState, RelKey, Operation, entropy) -> Result<AdvanceOutcome>`.
- Wire `smt_replace` into every advance.
- Update faucet, bilateral, mint/burn, DJTE callers to use the new API with explicit `rel_key`:
  - Faucet: `k_{A↔source_dlv}` (DLV unlock path per §9.5).
  - Bilateral: `k_{A↔B}` (already computed in bilateral managers).
  - Authority mint/burn: `k_{A↔CPTA-authority}`.
  - DJTE emission: `k_{winner↔source_dlv}` per §9.5.
- CAS head pointer at the runtime layer (write-lock on `DeviceState` holder).

### Step 14: Verification

- `cargo test -p dsm --lib` clean.
- `cargo test -p dsm_sdk --lib` clean.
- NDK rebuild (recipe in `~/.claude/projects/-Users-cryptskii-Desktop-claude-workspace-dsm/memory/MEMORY.md` under "NDK Build"):
  ```bash
  rm -f dsm_client/android/app/src/main/jniLibs/*/libdsm_sdk.so
  cd dsm_client/decentralized_state_machine && \
    DSM_PROTO_ROOT=/Users/cryptskii/Desktop/claude_workspace/dsm/proto \
    cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 \
      -o /Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/android/app/src/main/jniLibs \
      --platform 23 build --release --package dsm_sdk --features=jni,bluetooth
  ```
  Copy to repo-level AND `app/src/main/jniLibs/`. `./gradlew clean`. Verify 87+ JNI symbols.
- Install on Device A (R5CW620MQVL), verify restore from recovery capsule still works.
- BLE transfer test A → B.
- Concurrent ops test: faucet + bilateral in quick succession, confirm no balance loss.

---

## Known gotchas

### 1. `PreCommitment.min_state_number`

The `PreCommitment` struct (around line 2150 in `state_types.rs` pre-refactor) has a `min_state_number: u64` field meaning "this commitment is only valid after state number X." This is a spec violation (§4.3) but semantically distinct from `state_number` on `State`. **Left in place for axis 1 — do not touch yet.** Address it when rewriting forward commitments or when the test at line ~1262 (`assert_eq!(pc.min_state_number, 10)`) comes up. The semantic replacement is "valid after parent chain tip H" — a hash-based precondition, not a counter.

### 2. `Balance::last_updated_tick` and `from_state`

`Balance::from_state(value, hash, state_number)` stores `state_number` as `last_updated_tick: u64` and serializes it in `Balance::to_le_bytes()`. That means `state_number` IS STILL reaching `State::compute_hash()` indirectly through the balance serialization, even though the direct `state_number.to_le_bytes()` line was removed. **Axis 1 does not fully fix this.** Axis 2 must either:
- Change `Balance` to not track a tick, OR
- Change `compute_hash` to serialize only `balance.value()` (8 bytes, u64 LE) instead of the full `Balance::to_le_bytes()`.

The second option is cleaner and more surgical. Recommend that.

### 3. `StateTransition.tick`

In `transition.rs` line ~44, `StateTransition` has a `tick: u64` field populated from `deterministic_time::tick()`. Whitepaper §11 forbids time-based inputs. This is a separate violation, out of axis 1's scope. Flag for later (probably axis 3 when the whole transition struct is rewritten). If any callsite assumes `tick` is used for ordering, it's wrong.

### 4. Device Tree versioning

`hierarchical_device_management.rs` has 41 `state_number` refs. Some of these may legitimately be Device Tree index numbers per §3 (the "Device Tree is fully replicated ... adding a device is an online event"). The Device Tree CAN have an internal index for structural ordering — that's different from `State.state_number`. **Read context before deleting.** If you see something like `device_tree_version: u64` or `tree_epoch: u64`, that's fine. If you see `state.state_number`, that's the god-object read, delete.

### 5. Random walk entropy seeding

`state_machine/random_walk.rs` uses `state_number` in `generate_seed`. Per §11 the entropy must come from adjacency inputs (parent tip + DBRW + fresh entropy), not a counter. Replace `state_number` with `prev_state_hash` or chain tip in the seed derivation. This is a semantic change — the resulting positions will differ.

### 6. `#![deny(warnings)]` + `.clippy.toml`

The crate is `#![deny(warnings)]` in `dsm_sdk/src/lib.rs`. `.clippy.toml` at repo root disallows `.unwrap()`, `.expect()`, `.unwrap_err()` (becomes hard errors). When writing new code, use `?` and `.ok_or_else()`. In tests you may need `#[allow(clippy::disallowed_methods)]` or use `match` instead of `unwrap`.

### 7. Gradle JNI cache

After NDK rebuild, always `./gradlew clean` before reinstall. `mergeDebugNativeLibs UP-TO-DATE` is a liar and will use stale `.so` copies. See MEMORY.md "NDK Build".

### 8. Branch state

Current branch: `cryptskii/vigorous-gould`. Worktree: `.claude/worktrees/vigorous-gould`. Clean base (no uncommitted changes before this session). Committing progress would create a WIP checkpoint — recommend a commit after axis 1 completes clean, another after axis 2, another after axis 3.

---

## Success criteria

- [ ] `cargo build -p dsm` — clean
- [ ] `cargo build -p dsm_sdk` — clean
- [ ] `cargo clippy -p dsm --lib -- -D warnings` — clean (honors `.clippy.toml`)
- [ ] `grep -rn "state_number" dsm/src/` returns only: (a) `emission_index` in DJTE (distinct concept, §9.5); (b) `min_state_number` in `PreCommitment` (axis 1 leaves in place, flagged above); (c) no hits inside `compute_hash`, `to_bytes`, or any predicate path
- [ ] `cargo test -p dsm --lib` — passes or has only hash-value assertion failures that are fixed to use new canonical hashes
- [ ] NDK rebuild produces 87+ JNI symbols across all 3 arches
- [ ] Bilateral BLE transfer A → B works end-to-end
- [ ] Concurrent faucet + bilateral test shows no balance loss (the original symptom)

---

## What this fixes

- **Spec compliance §4.3:** No counter in any canonical hash or acceptance predicate.
- **Spec compliance §2.2:** Per-Device SMT is the actual device head (once Phase 2/axis 3 lands).
- **Spec compliance §8:** Balance witnesses are device-level fungible scalars, witnessed on each state.
- **Balance loss bug:** Root cause was the shared `token_balances` hashmap mutated through a single counter. Axis 3 (`advance(rel_key)` with SMT CAS) eliminates the shared-writer race structurally — concurrent cross-relationship advances can't produce conflicting heads because the SMT root IS the serialization primitive.

## What this doesn't fix (out of scope for this refactor)

- DJTE spend-gate edge cases — separate issue.
- NFC recovery capsule format version bump — may need later if capsule layout changes because of the removed `state_number` field.
- DLV manager's internal counters — separate audit needed.
- Wire format v3 envelope changes — not affected.
