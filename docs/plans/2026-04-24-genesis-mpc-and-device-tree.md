# DSM Genesis MPC + Device Tree Implementation Plan (Foundation for Multi-Device Enrollment)

> **For Claude:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task.

> **Companion plan:** `docs/plans/2026-04-24-hrw-scale-and-enrollment-hardening.md` covers HRW migration, storage-node scale wiring, and multi-device enrollment hardening. **That plan's Phase 3 (enrollment) sits on top of THIS plan.** Do not start Phase 3 of the companion plan until Phases A and B of this plan are complete.

---

## Context

**Why this plan exists.** The original architectural conversation was about multi-device enrollment — adding a secondary device to an existing identity rooted at Genesis hash `G` with device tree root `R_G` signed by the primary device's `pk_1`. Multi-device enrollment requires two foundations to be solid:

1. **Real threshold-MPC Genesis creation** per spec §5 — commit-reveal across distinct storage nodes, producing an unbiased `G` that no single party (root device or any subset of storage nodes) could have predicted or biased. Without this, an attacker who controls the root device or a minority of MPC contributors can grind `G` to a value of their choosing, defeating the entire identity model.

2. **A real device tree** — a content-addressable Merkle structure rooted at `R_G`, with verifiable inclusion proofs for each device, monotonic versioning, and unambiguous update semantics for add/remove. The current scaffolding (`compute_device_tree_root` in SDK; `/api/v2/identity/{genesis}/devtree/{root,proof}` endpoints) appears to encode the device list as `[count: u32][device_id: 32B]...` — a flat sorted list, not a Merkle tree. Inclusion proofs would not be meaningful against a flat list, and the validator the companion plan adds in Phase 3 cannot verify what it cannot parse.

The companion plan added a bounded validator on `PUT /devtree/root` and a `RootBindingRecord` mechanism — both correct in shape, but they assume Genesis MPC is real and the device tree is a real Merkle structure. **This plan makes those assumptions actually true.**

## Goal

Bring DSM's Genesis creation up to spec §5 (real threshold-MPC with commit-reveal) and replace the flat-list "device tree" with a proper Merkle structure with inclusion proofs and versioning.

## Architecture

Two phases, sequenced. Phase A (Genesis MPC) and Phase B (device tree) are nearly independent and can run in parallel by two developers, with the integration point being that Phase A's `RootBindingRecord` publishing references the initial `R_G` produced by Phase B's empty-tree-with-pk_1 construction. After both are complete, the companion plan's Phase 3 (multi-device enrollment hardening) can build on solid foundations.

## Tech Stack

Rust (storage node, SDK, core), TypeScript/React (frontend), Kotlin/Android (mobile), JNI bridge, Protobuf v3 (DSM-CPE deterministic encoding), BLAKE3-256 (with domain separation tags), SPHINCS+ (post-quantum signatures).

## Dependency Graph

```
Phase A (Genesis MPC) ──────┐
                            ├──► Companion Plan Phase 3 (enrollment hardening)
Phase B (Device Tree) ──────┘
```

---

## Pre-Flight: State Audit

Before starting either phase, the executing developer **must** read these files and produce a one-paragraph "current state" summary in the commit message of Task A.0 / B.0:

**Genesis stack:**
- `dsm_client/deterministic_state_machine/dsm/src/core/identity/genesis_mpc.rs`
- `dsm_storage_node/src/api/genesis.rs`
- `dsm_client/deterministic_state_machine/dsm_sdk/src/jni/create_genesis.rs`
- `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/genesis_publisher.rs`
- `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/counterparty_genesis_helpers.rs`
- `dsm_client/deterministic_state_machine/dsm/src/types/genesis_types.rs`

**Device tree stack:**
- `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/storage_node_sdk.rs:1791-1910` (`add_secondary_device`)
- `dsm_client/deterministic_state_machine/dsm/src/common/device_tree.rs` (if exists; search for `compute_device_tree_root`)
- `dsm_storage_node/src/api/identity_devtree.rs`
- `proto/dsm_app.proto` — search for any device-tree-related messages

For each file, classify each function as:
- **IMPLEMENTED + correct per spec** — keep as-is, document
- **IMPLEMENTED but spec-divergent** — note the divergence, plan reconciliation
- **STUB/PARTIAL** — note what's missing, plan completion
- **MISSING** — note required addition

**Reference spec sections** (read before starting):
- §5 Genesis Anchor (Commit-Reveal, Clockless) in `.github/instructions/storagenodes.instructions.md`
- §7 Node Storage SMT and ByteCommit Mirroring (for SMT patterns to mirror in device tree)
- Whitepaper §2 if applicable for device tree security argument

---

# Phase A — Real Threshold-MPC Genesis Creation

**Phase A summary.** Replace any single-node or simulated MPC path with real threshold MPC across N≥3 distinct storage nodes per §5, with commit-reveal entropy combination and per-contributor SPHINCS+ signatures. Publish a `RootBindingRecord` that the multi-device-enrollment flow can verify.

---

### Task A.0 — State audit and gap report

**Step 1.** Read the Genesis stack files listed in Pre-Flight.

**Step 2.** Write a one-page summary to `docs/plans/2026-04-24-genesis-state-audit.md` covering:
- Does the current `create_genesis` actually contact distinct storage nodes? Or does it generate entropy locally and call it "MPC"?
- Is there a session protocol (offer → join → contribute → commit → reveal → combine)?
- Does each contributor sign with SPHINCS+? Where is each storage node's MPC participation key stored?
- Is the commit-reveal mechanic from §5 implemented (D_commit before D_reveal, η_0 = H("DSM/anchor/eta\0" || D_commit || D_reveal))?
- What threshold is required? (Default per spec is unspecified but quorum-of-3 is reasonable for a 6-node N=6 deployment.)
- What's the failure-handling story (timeout, contributor drops out, network partition)?

**Step 3.** Commit the audit document. Reference it in subsequent task commits.

**Acceptance:** state audit document committed; subsequent task plans can be calibrated against actual current state.

**Commit:** `docs(plans): genesis MPC current-state audit`

---

### Task A.1 — Define genesis MPC session proto types

**File to modify:** `proto/dsm_app.proto`

**Step 1.** Add (or verify exist; reconcile if present with different shape):

```proto
message GenesisMpcSessionV1 {
  // domain: "DSM/genesis-mpc-session\0"
  bytes session_id = 1;             // 32 bytes — H(initiator_device_id || initiator_nonce || timestamp)
  bytes initiator_device_id = 2;    // root device's DevID (32 bytes)
  bytes initiator_pk = 3;           // root device's SPHINCS+ public key (pk_1)
  bytes initiator_cdbrw = 4;        // CDBRW digest of root device (32 bytes)
  uint32 threshold = 5;             // minimum contributors required (default 3)
  uint64 deadline_cycle = 6;        // cycle index by which session must complete
}

message GenesisMpcCommitV1 {
  // domain: "DSM/genesis-mpc-commit\0"
  bytes session_id = 1;
  bytes contributor_id = 2;         // storage node ID (32 bytes)
  bytes commit_digest = 3;          // H("DSM/genesis-commit\0" || session_id || contributor_id || entropy_i)
  bytes node_signature = 4;         // SPHINCS+ sig over fields 1-3 by storage node's MPC key
}

message GenesisMpcRevealV1 {
  // domain: "DSM/genesis-mpc-reveal\0"
  bytes session_id = 1;
  bytes contributor_id = 2;
  bytes entropy = 3;                // 32 bytes — must match the commit
  bytes node_signature = 4;         // SPHINCS+ sig over fields 1-3
}

message GenesisMpcCombinedV1 {
  // domain: "DSM/genesis-mpc-combined\0"
  bytes session_id = 1;
  repeated GenesisMpcRevealV1 reveals = 2;   // ≥ threshold valid reveals
  bytes initiator_device_commitment = 3;     // H("DSM/device-commit\0" || pk_1 || cdbrw_1)
  bytes computed_g = 4;                      // G = H("DSM/genesis\0" || ProtoDet(A_0))
  bytes computed_eta_0 = 5;                  // η_0 = H("DSM/anchor/eta\0" || D_commit || D_reveal)
}
```

Where `D_commit = H_concat(commit_digest_i for i sorted by contributor_id)` and `D_reveal = H_concat(entropy_i for i sorted by contributor_id)`. `A_0` per §5 is the canonical encoding of all contributors' identities + reveals + initiator binding — pin this format down explicitly in a comment block in the proto file.

**Step 2.** Run protobuf code generation. Verify generated types compile across Rust + frontend.

**Step 3.** Commit.

**Acceptance:** types compile; canonical encoding of `A_0` is unambiguous (one comment-block formula, no alternatives).

**Commit:** `feat(proto): add genesis MPC session protocol types per spec §5`

---

### Task A.2 — Storage-node MPC participation key

**Files to modify:** `dsm_storage_node/src/main.rs` and a new `dsm_storage_node/src/identity/mpc_key.rs`

**Step 1.** Each storage node needs a SPHINCS+ keypair specifically for signing MPC contributions. This key must be:
- Generated once at first startup, persisted to disk under restrictive permissions
- Loaded on every subsequent startup
- Used only for MPC participation signatures (not for any other signing role)
- Public key advertised via the registry (extend `RegistryV3` if needed, or via a separate node-info endpoint)

**Step 2.** Implement key generation + persistence:

```rust
pub struct StorageNodeMpcKey {
    pub public_key: Vec<u8>,
    pub secret_key: secrecy::Secret<Vec<u8>>,
}

pub fn load_or_generate_mpc_key(state_dir: &Path) -> Result<StorageNodeMpcKey>;
```

Persistence: write to `${state_dir}/mpc_key.bin` with mode 0600. Format: protobuf with public_key + encrypted_secret_key (encrypt with a key derived from a node-operator-provided passphrase OR from the node's config-bound DBRW if available; document the choice).

**Step 3.** Wire into `main.rs`: load on startup, attach to `AppState` as `Arc<StorageNodeMpcKey>`.

**Step 4.** Add `GET /api/v2/node/info` returning the node's MPC public key, node_id, and capacity. Used by clients to discover MPC participants. (If a similar endpoint exists, extend it; do not duplicate.)

**Step 5.** Tests:
- `mpc_key_persists_across_restart`: generate, save, reload, verify same public key
- `node_info_returns_mpc_pubkey`

**Step 6.** Commit.

**Acceptance:** each storage node has a stable MPC keypair; public key is discoverable.

**Commit:** `feat(storage-node): persistent MPC participation key with /api/v2/node/info endpoint`

---

### Task A.3 — Storage-node MPC handlers

**File to create:** `dsm_storage_node/src/api/genesis_mpc.rs` (new) — or extend the existing `dsm_storage_node/src/api/genesis.rs` if the audit shows it's appropriate to extend.

**Step 1.** Implement endpoints:

- `POST /api/v2/genesis/mpc/offer` — receive `GenesisMpcSessionV1` from a root device. Validate session_id derivation, threshold ≥ 3, deadline reasonable. If accepted, store session in a per-node session table; return 200 with this node's MPC public key + a "joined" acknowledgment. If rejected (e.g., session_id already used, deadline expired), return 409.
- `POST /api/v2/genesis/mpc/commit` — receive `GenesisMpcCommitV1` from this node's own contribution generator (or accept-and-store commits from other nodes for verification fanout). Generate a 32-byte entropy, compute commit_digest, sign, store, return the commit envelope.
  - **Note:** the commit phase is each contributor independently producing a commit; the storage node's commit is its OWN entropy, not someone else's. This endpoint is invoked internally during the offer-acceptance flow, not by the root device. It may be merged into the offer handler if simpler.
- `POST /api/v2/genesis/mpc/reveal` — receive a request to reveal this node's entropy (after the root device has confirmed all expected commits arrived). Returns `GenesisMpcRevealV1`.
- `GET /api/v2/genesis/mpc/session/{session_id}` — read endpoint for any party to see the session state and collected commits/reveals.

**Step 2.** Validation rules per endpoint:
- Sessions are uniquely identified by `session_id`. Refuse re-use.
- Commits are stored as-received; reveals are validated against their commits (`commit_digest == H("DSM/genesis-commit\0" || session_id || contributor_id || revealed_entropy)`).
- Bias-resistance: a node MUST NOT reveal until its commit has been published AND it has observed commits from at least `threshold-1` other contributors. This prevents withholding-the-reveal attacks (per §5).
- Session table is purged after deadline + grace period (e.g., 100 cycles) to prevent unbounded growth.

**Step 3.** Storage:
- New table `genesis_mpc_sessions` with columns: session_id, initiator_device_id, threshold, deadline_cycle, state (offered/committing/revealing/combined/expired), created_at_cycle.
- New table `genesis_mpc_contributions` with columns: session_id, contributor_id, commit_digest, commit_signature, revealed_entropy (NULL until reveal phase), reveal_signature.

**Step 4.** Tests:
- `session_offer_accepted_by_node`
- `session_offer_rejected_on_duplicate_session_id`
- `commit_stored_correctly`
- `reveal_rejected_if_commit_mismatch`
- `reveal_rejected_before_threshold_commits_observed` (bias resistance)
- `session_purged_after_deadline_plus_grace`

**Step 5.** Commit.

**Acceptance:** storage node can participate in genesis MPC sessions, with bias resistance enforced.

**Commit:** `feat(storage-node): genesis MPC participation handlers with commit-reveal bias resistance`

---

### Task A.4 — Root-device MPC orchestration in SDK

**File to modify:** `dsm_client/deterministic_state_machine/dsm/src/core/identity/genesis_mpc.rs` (extend existing) and `dsm_sdk/src/sdk/storage_node_sdk.rs` (extend `create_root_genesis` or equivalent).

**Step 1.** Implement `pub async fn create_root_genesis_mpc(...) -> Result<GenesisCreationResponse>`:

```
1. Generate session_id (random 32 bytes mixed with device_id and a high-entropy nonce).
2. Discover candidate storage nodes via the registry (use existing peer-listing code).
3. Build GenesisMpcSessionV1; POST /api/v2/genesis/mpc/offer to ≥ threshold + 1 candidate nodes (over-provision for failure tolerance).
4. Wait for at least `threshold` accepting responses, with their MPC public keys.
5. Wait for commits to be published by each accepting node (poll session endpoint or have nodes push back).
6. Once `threshold` commits are observed, signal each node to reveal.
7. Collect reveals; verify each (commit_digest matches H(session_id || contributor_id || revealed_entropy)).
8. Compute D_commit = H_concat(sorted commits), D_reveal = H_concat(sorted reveals), η_0 = H("DSM/anchor/eta\0" || D_commit || D_reveal).
9. Build A_0 (canonical: contributor list + reveals + initiator pk_1 + initiator cdbrw_1 + device_commitment); G = H("DSM/genesis\0" || ProtoDet(A_0)).
10. Build RootBindingRecordV1 (already specified in companion plan Task 3.1) populated from the actual MPC results.
11. Publish RootBindingRecordV1 to the SAME storage-node quorum (those that participated). Do NOT publish to nodes that did not participate — they have no basis to attest the record.
12. Return GenesisCreationResponse with G, pk_1, session metadata, list of participating storage nodes.
```

**Step 2.** Failure handling:
- If insufficient acceptances after timeout: abort, return error to user.
- If a contributor drops out between commit and reveal: continue with remaining contributors as long as `threshold` are present.
- If publish phase fails after MPC succeeds: retry to majority of participants; if still failing, return a "MPC succeeded but publish failed" error and surface a manual retry option. (G exists locally but is unverifiable — this is the atomicity concern from companion plan; storage nodes refuse devtree writes in this state per companion Task 3.4.)

**Step 3.** Remove or feature-gate any pre-existing single-node "MPC" path. Explicitly document in code comments that the legacy path is removed and why.

**Step 4.** Tests (with a mock storage-node cluster of 6 nodes):
- `mpc_genesis_succeeds_with_threshold_contributors`
- `mpc_genesis_fails_on_insufficient_acceptances`
- `mpc_genesis_handles_contributor_dropout_after_commit`
- `mpc_genesis_detects_invalid_reveal`
- `mpc_genesis_publishes_root_binding_record_to_participants_only`
- `mpc_genesis_g_is_deterministic_given_inputs`
- `mpc_genesis_g_differs_with_any_input_change`

**Step 5.** Commit.

**Acceptance:** real threshold-MPC genesis creation succeeds, fails-safe under each failure mode, publishes RootBindingRecord on success.

**Commit:** `feat(sdk): real threshold-MPC genesis creation per §5 with commit-reveal`

---

### Task A.5 — JNI bridge update

**File to modify:** `dsm_client/.../sdk/jni/create_genesis.rs` and `dsm_client/android/.../DsmNative.kt`

**Step 1.** Replace the existing `createGenesis` JNI function's internals to call the new `create_root_genesis_mpc`. The function signature stays compatible (same input args, same output envelope structure).

**Step 2.** If the existing function returns a "complete" envelope synchronously, restructure to either:
- (a) Block on the async MPC flow (acceptable for genesis since user is waiting)
- (b) Return a session token and add a polling endpoint for status updates (better UX with progress UI)

Recommend (b) — extend `DsmNative.kt` with `genesisMpcStatus(sessionId: ByteArray): ByteArray` returning a `GenesisMpcStatusV1` envelope with state + collected_commits_count + collected_reveals_count + error_message.

**Step 3.** Tests (Kotlin side):
- `createGenesis_returns_session_token`
- `genesisMpcStatus_progresses_through_phases`

**Step 4.** Commit.

**Acceptance:** Android can initiate real-MPC genesis; UI can render progress.

**Commit:** `feat(jni): expose real-MPC genesis with progress polling`

---

### Task A.6 — Frontend genesis-creation flow update

**File to modify:** `dsm_client/frontend/src/services/genesis.ts` and the genesis creation screen (search for `useGenesisFlow` and the UI screen that uses it).

**Step 1.** Replace any direct call to `createGenesis` with the new session-token-plus-polling flow.

**Step 2.** Add a per-phase progress UI:
- "Discovering storage nodes..."
- "Collecting commitments (X of Y)..."
- "Verifying reveals..."
- "Publishing identity binding..."
- "Done."

Each phase has a possible failure state with specific message.

**Step 3.** Tests with mocked WebViewBridge.

**Step 4.** Commit.

**Acceptance:** user sees real progress; failure modes are surfaced specifically.

**Commit:** `feat(frontend): real-MPC genesis creation flow with per-phase progress UI`

---

### Task A.7 — End-to-end MPC genesis integration test

**File to create:** `dsm/tests/integration/mpc_genesis.rs`

**Step 1.** Spin up 6 storage nodes locally. Initiate MPC genesis from a mock root device. Verify:
- Session is offered, accepted by ≥ threshold nodes
- Commits and reveals proceed
- G is deterministic given the same inputs (re-run with same nonce → same G)
- G is different given different inputs (different nonce → different G)
- RootBindingRecord is published to participants
- Subsequent `verify_genesis_on_network` (from companion plan Task 3.5) verifies the result

**Step 2.** Adversarial sub-tests:
- One contributor reveals invalid entropy → caught at reveal verification
- One contributor refuses to reveal after committing → MPC continues with remaining (if still ≥ threshold) or aborts cleanly
- Storage node tampers with stored commit between phases → detected
- Storage node tries to participate in two simultaneous sessions → first wins, second rejected (or both proceed if session_ids differ — verify expected behavior)

**Step 3.** Commit.

**Acceptance:** end-to-end MPC genesis works; adversarial cases fail safely.

**Commit:** `test(integration): end-to-end real-MPC genesis with adversarial cases`

---

### Task A.8 — Phase A verification

**Step 1.** Run `invariant-check`, `security-reviewer`, `crypto-guide` skill consultations on the MPC genesis path.

**Step 2.** Verify that ALL non-test calls to genesis-creation now route through the real-MPC path. Grep for legacy single-node creation; if any remain, either remove or document why.

**Acceptance:** clean reviews; no legacy path callers.

**Commit:** none.

---

# Phase B — Real Device Tree (Merkle Structure with Inclusion Proofs)

**Phase B summary.** Replace the flat-list device tree (`[count: u32][device_id: 32B]...`) with a proper Merkle structure. Add inclusion proofs, monotonic versioning, and a clear update protocol. Make the validator added in companion plan Task 3.4 actually meaningful by giving it real proof structures to verify.

---

### Task B.0 — State audit and gap report

**Step 1.** Read the device tree files listed in Pre-Flight.

**Step 2.** Write a one-page summary to `docs/plans/2026-04-24-device-tree-state-audit.md`:
- What does `compute_device_tree_root` actually compute? Real Merkle hash, or just `H(concatenated bytes)`?
- Does `dsm/src/common/device_tree.rs` exist? What's in it?
- What's the inclusion-proof format? Are there real proofs, or just empty stub bytes?
- Is the leaf encoding domain-separated?
- Is the tree sorted? Stable across permutations?
- Does the storage endpoint do any validation, or accept any bytes?

**Step 3.** Commit. Reference in subsequent tasks.

**Acceptance:** state audit documented; subsequent tasks calibrated to actual state.

**Commit:** `docs(plans): device tree current-state audit`

---

### Task B.1 — Define device tree types

**File to modify:** `proto/dsm_app.proto`

**Step 1.** Add (or reconcile if present in different shape):

```proto
message DeviceLeafV1 {
  // domain: "DSM/devtree-leaf\0"
  bytes device_id = 1;             // 32 bytes (DevID_N)
  bytes device_pk = 2;              // SPHINCS+ public key
  bytes cdbrw = 3;                  // CDBRW digest (32 bytes)
  uint64 admitted_at_version = 4;   // R_G version when this device was added
}

message DeviceTreeV1 {
  // canonical sorted list of leaves; root is computed from this
  repeated DeviceLeafV1 leaves = 1;  // sorted ascending by device_id
  uint64 version = 2;                // monotonic, increments per change
}

message DeviceTreeRootUpdateV1 {
  // domain: "DSM/devtree-root\0"
  // This is what's PUT to /api/v2/identity/{genesis}/devtree/root
  bytes genesis_hash = 1;
  bytes proposed_root = 2;           // 32 bytes — Merkle root of DeviceTreeV1
  uint64 prior_version = 3;
  uint64 new_version = 4;
  // Optional: only present for additions (not for primary-only updates)
  optional SecondaryDeviceAuthV1 authorization = 5;
  // The new tree itself (for storage-node validator to recompute and verify root)
  DeviceTreeV1 new_tree = 6;
}

message DeviceInclusionProofV1 {
  // domain: "DSM/devtree-proof\0"
  bytes genesis_hash = 1;
  bytes device_id = 2;
  uint64 tree_version = 3;
  bytes computed_root = 4;
  // Sibling hashes from leaf to root, MSB-first
  repeated bytes siblings = 5;
  // The leaf bytes being proven
  DeviceLeafV1 leaf = 6;
}
```

**Step 2.** Define the canonical Merkle tree construction in a comment block in the proto:
- Sort leaves ascending by `device_id`
- Each leaf hash: `H("DSM/devtree-leaf\0" || ProtoDet(DeviceLeafV1))`
- Internal node hash: `H("DSM/devtree-node\0" || left_hash || right_hash)`
- For odd leaf counts at any level, last leaf is duplicated (alternative: use empty-leaf sentinel — pick one and document)
- Root: top-level node hash; `empty_root = 32 × 0x00` for empty tree

**Step 3.** Run protobuf code generation. Verify compilation across Rust + frontend.

**Step 4.** Commit.

**Acceptance:** types compile; canonical Merkle construction is unambiguous.

**Commit:** `feat(proto): add device tree types with canonical Merkle construction`

---

### Task B.2 — Device tree library

**File to create:** `dsm_client/deterministic_state_machine/dsm/src/common/device_tree.rs` (or replace existing if it's stub)

**Step 1.** Implement (verify against existing `compute_device_tree_root` first; replace, don't duplicate):

```rust
use crate::types::{DeviceLeafV1, DeviceTreeV1, DeviceInclusionProofV1};
use blake3;

pub const EMPTY_ROOT: [u8; 32] = [0u8; 32];

pub fn hash_leaf(leaf: &DeviceLeafV1) -> [u8; 32] {
    let bytes = canonical_proto_encode(leaf);
    blake3_tagged("DSM/devtree-leaf", &bytes)
}

pub fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(left);
    buf.extend_from_slice(right);
    blake3_tagged("DSM/devtree-node", &buf)
}

pub fn compute_root(tree: &DeviceTreeV1) -> [u8; 32];

pub fn build_inclusion_proof(tree: &DeviceTreeV1, device_id: &[u8; 32]) -> Option<DeviceInclusionProofV1>;

pub fn verify_inclusion_proof(
    proof: &DeviceInclusionProofV1,
    expected_root: &[u8; 32],
) -> bool;

pub fn add_device(tree: &mut DeviceTreeV1, leaf: DeviceLeafV1) -> Result<()>;

pub fn remove_device(tree: &mut DeviceTreeV1, device_id: &[u8; 32]) -> Result<()>;
```

**Step 2.** Tests covering:
- `compute_root_empty_tree_is_zero`: empty leaves → EMPTY_ROOT
- `compute_root_single_leaf_is_leaf_hash` (or duplicated to a node hash, depending on chosen convention)
- `compute_root_is_deterministic`: same tree → same root, regardless of insertion order (sorting normalizes)
- `compute_root_changes_on_modification`: add a leaf → different root
- `inclusion_proof_verifies_for_present_device`
- `inclusion_proof_fails_for_absent_device` (build_inclusion_proof returns None)
- `verify_inclusion_proof_rejects_tampered_leaf`
- `verify_inclusion_proof_rejects_wrong_root`
- `add_device_increments_version`
- `add_device_idempotent`: adding a device that's already present is a no-op
- `remove_device_decrements_count_and_increments_version`
- `tree_remains_sorted_after_arbitrary_add_remove_sequence`

**Step 3.** Commit.

**Acceptance:** real Merkle device tree library; all tests pass.

**Commit:** `feat(common): real Merkle device tree library with inclusion proofs`

---

### Task B.3 — Update SDK `add_secondary_device` to use the real tree

**File to modify:** `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/storage_node_sdk.rs:1791-1910`

**Step 1.** Replace the flat-list construction (lines 1830-1882) with:
- Fetch the current `DeviceTreeRootUpdateV1` from storage (parse proto, not raw bytes)
- Extract `current_tree: DeviceTreeV1`
- Build new `DeviceLeafV1` with the new device's pk + cdbrw + admitted_at_version=current_tree.version+1
- Call `device_tree::add_device(&mut current_tree, new_leaf)?`
- Build a new `DeviceTreeRootUpdateV1` with proposed_root = `device_tree::compute_root(&current_tree)`, prior_version, new_version
- The `authorization` field is filled by the multi-device enrollment flow (companion plan Task 3.10) — at this point in the flow, that auth must already be obtained.
- PUT the new `DeviceTreeRootUpdateV1` (proto-encoded) to `/api/v2/identity/{genesis}/devtree/root`
- The storage-node validator (companion plan Task 3.4) verifies the auth + recomputes the root from `new_tree` to confirm it matches `proposed_root`.

**Step 2.** Add a `remove_secondary_device` SDK function with the analogous flow (uses `device_tree::remove_device`).

**Step 3.** Add `fetch_device_tree(genesis_hash) -> Result<DeviceTreeV1>` and `prove_device_membership(genesis_hash, device_id) -> Result<DeviceInclusionProofV1>` (latter calls the existing `/devtree/proof` endpoint).

**Step 4.** Tests:
- `add_secondary_device_produces_valid_tree_update`
- `add_secondary_device_with_existing_id_is_idempotent`
- `remove_secondary_device_produces_valid_tree_update`
- `fetch_device_tree_round_trips`

**Step 5.** Commit.

**Acceptance:** SDK uses the real Merkle tree; storage-node validator can verify it.

**Commit:** `refactor(sdk): use real Merkle device tree in add/remove_secondary_device`

---

### Task B.4 — Update storage-node validator to use real tree

**Note:** This task EXTENDS companion plan Task 3.4. If that task hasn't run yet, this task subsumes it. If it has run, this task amends it.

**File to modify:** `dsm_storage_node/src/api/identity_devtree.rs`

**Step 1.** Update the bounded validator's CHECK 4 to also verify that:
- The submitted `new_tree` (from the request body) when run through `device_tree::compute_root()` produces a hash equal to `proposed_root`.
- For an addition: `new_tree` contains the `auth.new_device_id` as a leaf with matching `pk` and `cdbrw`, AND `new_tree.version == prior_version + 1`.
- For a removal: `new_tree` is missing `auth.new_device_id` (or some other to-be-removed-id) AND `new_tree.version == prior_version + 1`. (Removal authorization semantics need to be specified — defer to a separate task if not covered here.)

**Step 2.** The validator's checks are now:
1. `RootBindingRecord` present for G
2. Version monotonic
3. SPHINCS+ authorization signature verifies under `rbr.pk_1` (when present)
4. DevID derivation correct (when authorization present)
5. **NEW:** Submitted tree's recomputed root matches `proposed_root`
6. **NEW:** Submitted tree contains/excludes the authorized device_id appropriately

The list is now SIX checks; this is still bounded and closed. Update the spec section comment.

**Step 3.** Tests covering each new check's rejection path.

**Step 4.** Commit.

**Acceptance:** validator now meaningfully verifies the tree, not just signature shape.

**Commit:** `feat(storage-node): extend devtree validator to verify Merkle root and tree consistency`

---

### Task B.5 — Storage-node serves real inclusion proofs

**File to modify:** `dsm_storage_node/src/api/identity_devtree.rs` — the `get_proof` handler.

**Step 1.** Currently `get_proof` returns whatever bytes were PUT. Change it to:
- Fetch the current `DeviceTreeRootUpdateV1` (which includes the full tree)
- Parse, find the device by `device_id` query param
- If found, build a `DeviceInclusionProofV1` via `device_tree::build_inclusion_proof()`
- Return the proof bytes

**Step 2.** Deprecate `PUT /devtree/proof` — proofs are derived from the tree, not stored separately. Remove the PUT handler.

**Step 3.** Tests:
- `get_proof_returns_valid_inclusion_proof_for_present_device`
- `get_proof_returns_404_for_absent_device`
- `get_proof_uses_current_tree_version`

**Step 4.** Commit.

**Acceptance:** inclusion proofs are derived from the tree, not stored separately; clients verify with `device_tree::verify_inclusion_proof`.

**Commit:** `refactor(storage-node): derive devtree inclusion proofs from tree on GET; remove proof PUT`

---

### Task B.6 — Initial empty tree at genesis time

**File to modify:** `dsm_sdk/src/sdk/storage_node_sdk.rs` (extend `create_root_genesis_mpc` from Task A.4)

**Step 1.** After successful MPC genesis but before publishing the RootBindingRecord, build the initial device tree:
- `tree = DeviceTreeV1 { leaves: [DeviceLeafV1 { device_id: pk_1's DevID, device_pk: pk_1, cdbrw: cdbrw_1, admitted_at_version: 1 }], version: 1 }`
- Compute `R_G = device_tree::compute_root(&tree)`
- Build `DeviceTreeRootUpdateV1 { genesis_hash: G, proposed_root: R_G, prior_version: 0, new_version: 1, authorization: None, new_tree: tree }`
- PUT to `/devtree/root` for each MPC participant. The validator must accept this initial state with no authorization (since pk_1 is itself the root authority being established) — handle this case explicitly: when prior_version=0 and the only leaf is the device deriving from `rbr.pk_1`, no separate auth is needed.

**Step 2.** Update validator (Task B.4) to handle the bootstrap case: if prior_version=0 AND the tree contains exactly one leaf whose pk == rbr.pk_1 AND that leaf's cdbrw == rbr.cdbrw_1, accept without auth.

**Step 3.** Tests:
- `genesis_creates_initial_devtree_with_single_leaf`
- `bootstrap_devtree_accepted_without_auth`
- `bootstrap_devtree_rejected_if_pk_does_not_match_rbr`
- `bootstrap_devtree_rejected_if_more_than_one_leaf`

**Step 4.** Commit.

**Acceptance:** every successful genesis produces an initial device tree with the root device as the sole leaf.

**Commit:** `feat(sdk): initialize device tree at genesis with primary device as sole leaf`

---

### Task B.7 — Frontend device-tree visualization (optional, recommended)

**Files to create:** new component in `dsm_client/frontend/src/components/identity/DeviceTreeViewer.tsx`

**Step 1.** Implement a UI that:
- Fetches the current device tree via the SDK
- Renders the device list with: device_id (truncated 12-char Crockford), pk fingerprint, admitted_at_version, "this device" indicator
- Shows the tree's version and root hash
- Provides a "verify inclusion" button per row that calls `prove_device_membership` and verifies locally

**Step 2.** Add a route + entry point from settings/identity screen.

**Step 3.** Tests with mocked services.

**Step 4.** Commit.

**Acceptance:** users can inspect their device tree and verify their own device's inclusion locally.

**Commit:** `feat(frontend): device tree viewer with local inclusion-proof verification`

---

### Task B.8 — Phase B verification

**Step 1.** Run `invariant-check` and `security-reviewer`.

**Step 2.** Run all device-tree-related tests across crates.

**Step 3.** Verify that the legacy flat-list encoding has no remaining production callers. Grep for `[count: u32][device_id_1: 32 bytes]`-style construction. Remove or migrate.

**Acceptance:** clean reviews; no legacy callers.

**Commit:** none.

---

# Cross-Phase Concerns

## Verification Strategy

- Per-task unit tests (specified inline)
- Integration tests at phase boundaries (Tasks A.7, A.8, B.8)
- Skill-driven reviews: `invariant-check`, `security-reviewer`, `crypto-guide`, `wire-format`
- Manual end-to-end test: bring up 6 storage nodes, create a genesis via real MPC, add a secondary device, verify all checkpoints pass.

## Migration / Compatibility

- Any existing test or dev identities created under the legacy single-node "MPC" or flat-list devtree are incompatible and must be regenerated. There is no in-place migration path — the legacy formats are unverifiable by the new validators.
- Document in release notes that mainnet launch requires fresh genesis creation; pre-mainnet test identities cannot carry over.

## Skills to Invoke

- `superpowers:executing-plans`
- `crypto-guide` — consult during Phase A MPC implementation
- `wire-format` — consult during proto type additions
- `invariant-check` — after each phase
- `security-reviewer` — after each phase
- `pbt-auditor` — Phase B device tree (property-based tests for tree invariants)
- `storage-guide` — confirm storage-node responsibilities stay bounded

## Critical Files Reference

| File | Phase | Purpose |
|------|-------|---------|
| `proto/dsm_app.proto` | A, B | New session/contribution/leaf/tree messages |
| `dsm_storage_node/src/identity/mpc_key.rs` | A | Per-node MPC key persistence (new) |
| `dsm_storage_node/src/api/genesis_mpc.rs` | A | MPC participation handlers (new or extends `genesis.rs`) |
| `dsm_client/.../dsm/src/core/identity/genesis_mpc.rs` | A | Core MPC orchestration (extend existing) |
| `dsm_client/.../sdk/storage_node_sdk.rs` | A, B | `create_root_genesis_mpc`, `add/remove_secondary_device` |
| `dsm_client/.../sdk/jni/create_genesis.rs` | A | JNI bridge (update) |
| `dsm_client/.../sdk/sdk/genesis_publisher.rs` | A | RootBindingRecord publishing (extend) |
| `dsm_client/.../dsm/src/common/device_tree.rs` | B | Real Merkle library (new or replace) |
| `dsm_storage_node/src/api/identity_devtree.rs` | B | Validator extensions, real proof derivation |
| `dsm_client/frontend/src/components/identity/DeviceTreeViewer.tsx` | B | UI (new, optional) |

## Out of Scope

- Anything in the companion plan: HRW migration, scale-mechanism wiring, multi-device enrollment hardening on top of the foundations built here.
- DLV / DeTFi / emissions / NFC backup / bilateral.
- Genesis backup / recovery via NFC ring (separate work tracked under `nfc-backup` skill).
- Network-bootstrap-genesis (the very first genesis at network launch) — assumed to be handled by an out-of-band ceremony with hand-coordinated participants; document but do not automate in this plan.

---

**End of plan.**
