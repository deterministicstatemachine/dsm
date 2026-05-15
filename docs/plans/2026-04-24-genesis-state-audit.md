# Genesis MPC State Audit (Pre-Plan-A Execution)

**Date:** 2026-05-15  
**Branch:** fix/genesis-mpc-and-device-tree (worktree from origin/main)  
**Plan reference:** docs/plans/2026-04-24-genesis-mpc-and-device-tree.md Task A.0

## Summary

The codebase has **real threshold-free (n-of-n) MPC entropy collection implemented in core**, with both a transport-free local derivation path (`create_mpc_genesis`) and a transport-integrated path (`create_mpc_genesis_with_transport`). However, **the storage-node-side MPC orchestration, RPC endpoints, and persist-to-network flow are entirely MISSING**. Genesis currently generates entropy locally in-process with no distinct storage node contact. Task A.0 must build the storage-node MPC handlers (offer/commit/reveal endpoints) and wire the SDK to actually contact nodes. The device tree is a real Merkle structure (Issue #182 Finding #4 fix with canonical padding), but has no integration with genesis creation yet.

---

## Per-File Findings

### dsm_client/.../dsm/src/core/identity/genesis_mpc.rs
**Status:** IMPLEMENTED + correct per spec §5 (commit-reveal, n-of-n n≥3)  
**Functions:**
- `GenesisSession::new()` — allocates session with random session_id
- `GenesisSession::initialize_mpc()` — validates ≥3 storage_nodes, stores them
- `GenesisSession::set_entropies()` — accepts device + MPC entropies (local; no network)
- `GenesisSession::compute_commitments()` — builds C_i = H("DSM/genesis-commit" ‖ session_id ‖ entropy_i)
- `GenesisSession::verify_commitments()` — checks each commit against its reveal
- `GenesisSession::compute_genesis_id()` — G = H("DSM/genesis" ‖ device_entropy ‖ mpc_i... ‖ A) where A is canonical device_id ‖ sorted participants ‖ metadata
- `GenesisSession::derive_silicon_bound_keypair()` — derives SPHINCS+ + Kyber from S_master per whitepaper §11.1, with K_DBRW folded into IKM
- `create_mpc_genesis()` — local n-of-n MPC: generates both device and MPC entropies in-process, computes commitments and genesis_id
- `create_mpc_genesis_with_transport()` — as above but calls GenesisMpcTransport::collect_node_entropy per storage node (STUB endpoint contract; no actual storage nodes implement it yet)

**Spec alignment:**
- ✓ n-of-n (all storage_nodes contribute, no threshold t<n)
- ✓ Domain-separated commitment hashing ("DSM/genesis-commit" distinct from "DSM/genesis")
- ✓ Canonical A ordering (lex-sorted by NodeId.as_bytes())
- ✓ K_DBRW silicon binding (folded into S_master IKM only, zeroised after keypair derivation)
- ✓ Participant count check (≥3 enforced; line 188, 296, 538)

**Gap:** The GenesisMpcTransport trait is defined but has no storage-node implementations. SDK must invoke `collect_node_entropy` per node; nodes must respond with their 32-byte entropy. Currently calls would fail or block indefinitely.

### dsm_storage_node/src/api/identity/genesis.rs (post-merge path)
**Status:** STUB (entropy endpoint only)  
**Functions:**
- `GET /api/v2/genesis/entropy` — returns 32 bytes from OS RNG, headers anti-cache. **This is the node's contribution to MPC.**
- `POST /api/v2/genesis/create` — forwarder to upstream DSM_GENESIS_UPSTREAM (external MPC service, not local participation)

**Spec gap:** §5 expects each node to:
- Store the session_id, commitments, and reveals locally
- Enforce reveal-before-commit bias protection (commit must be published before node reveals)
- Return HTTP 200 with "joined" ack + this node's MPC public key on offer acceptance

**Current state:** Genesis entropy is generated fresh per request but NOT correlated with any session protocol. There is no offer/join/commit/reveal state machine.

### dsm_client/.../dsm/src/core/identity/genesis.rs
**Status:** IMPLEMENTED (wrapper for genesis_mpc, conversion helper)  
**Functions:**
- `create_genesis_via_blind_mpc()` — calls genesis_mpc::create_mpc_genesis, converts GenesisSession → GenesisState, verifies
- `convert_session_to_genesis_state_compat()` — maps GenesisSession fields to GenesisState struct (note: field order change; metadata added to contribs for initial_entropy derivation)

**Spec alignment:** Correct; recomputes initial_entropy under distinct domain "DSM/genesis-initial-entropy" so it diverges from genesis_id.

### dsm_client/.../dsm/src/types/genesis_types.rs
**Status:** IMPLEMENTED (structural hashing + verification)  
**Key structures:**
- `GenesisState` — device_id, genesis_hash, mpc_contributions, dbrw_proof, public_keys, created_at (non-canonical)
- `MPCContribution` — contributor_id, contribution_hash, signature, tick
- `DBRWProof` — device_fingerprint, env_state_hash, proof_data, verification_hash (zeroised on drop)
- `GenesisPublicKeys` — SPHINCS+ + Kyber keys, key_hash (deterministic)

**Functions:**
- `recompute_genesis_hash()` — recomputes G from contributions (sorted by hash, then ID), DBRW, keys
- `verify_integrity()` — checks presence, DBRW env hash, key hash, and canonical G match (deterministic all-or-nothing)

**Spec gap:** This type is independent of the whitepaper §2.5 n-of-n commitment protocol. It exists but is not wired into genesis_mpc module. Note that contributions are sorted by `(contribution_hash, contributor_id)` here, not by session order as in genesis_mpc.

### dsm_client/.../dsm/src/common/device_tree.rs
**Status:** IMPLEMENTED + correct per spec §2.2, Issue #182 Finding #4 (padding fix)  
**Key structures:**
- `DeviceTree` — sorted deduplicated leaves (DevIDs), precomputed root R_G
- `DevTreeProof` — siblings, leaf_to_root flag, path_bits (per-level child position)

**Functions:**
- `hash_leaf(dev_id)` — H("DSM/dev-leaf" ‖ dev_id)
- `hash_node(left, right)` — H("DSM/dev-merkle" ‖ left ‖ right)
- `pad_leaf()` — H("DSM/dev-tree-pad") (distinct domain; prevents [A,B,C] ≡ [A,B,C,C] collision)
- `empty_root()` — H("DSM/dev-empty")
- `DeviceTree::new()` — builds sorted binary Merkle tree; odd-count levels pair with pad_leaf()
- `proof()` — generates inclusion proof for a device_id, returns None if absent

**Spec alignment:**
- ✓ Canonical lex-sorted leaves (dedupped)
- ✓ Balanced binary Merkle with canonical padding (not self-duplication; Issue #182 Finding #4)
- ✓ Domain-separated hashing at all levels
- ✓ Deterministic: same set → same root, regardless of input order

**Current limitation:** Device tree is built in-process from a list of DevIDs; integration with genesis creation happens in Task B.6 (create initial tree with only primary device). Device tree is **not yet referenced by genesis_mpc**.

### dsm_client/.../dsm_sdk/src/sdk/genesis_publisher.rs
**Status:** IMPLEMENTED (serialization + publish/retrieve contract)  
**Functions:**
- `SdkGenesisPublisher::new()` — holds reference to StorageNodeSDK
- `serialize_payload()` — flattens SanitizedGenesisPayload to bytes (genesis_hash ‖ device_id ‖ pk_len ‖ pk ‖ participants_count ‖ participants ‖ created_at_ticks)
- `deserialize_payload()` — inverse; validates lengths and UTF-8
- `publish()` — calls `storage_sdk.put("genesis/{b32}", bytes)` (currently just stores; no MPC session metadata)
- `retrieve()` — calls `storage_sdk.get()` and verifies genesis_hash matches

**Spec gap:** The plan's Task A.4 step 11 requires publishing a **RootBindingRecord** to MPC participants only, with signed metadata about the MPC session. Current code publishes a raw SanitizedGenesisPayload with no session binding or signature. RootBindingRecord doesn't exist in proto yet.

### proto/dsm_app.proto
**Status:** PARTIAL (genesis structures exist; MPC session types MISSING)  
**Present:**
- `SystemGenesisRequest` (input: device_entropy, DBRW params)
- `SystemGenesisResponse` (output: genesis_hash, public_key)
- `GenesisCreated` (event: device_id, genesis_hash, public_key, threshold=?, session_id=?, storage_nodes=[?])
- `CreateGenesisPayload` (JNI bridge: locale, network_id, entropy)

**Spec gap:** §5 + Plan A.1 require:
- ❌ `GenesisMpcSessionV1` — session_id, initiator_device_id, initiator_pk, threshold, deadline_cycle
- ❌ `GenesisMpcCommitV1` — session_id, contributor_id, commit_digest, node_signature
- ❌ `GenesisMpcRevealV1` — session_id, contributor_id, entropy, node_signature
- ❌ `GenesisMpcCombinedV1` — session_id, reveals, initiator_commitment, computed_g, computed_eta_0
- ❌ `RootBindingRecordV1` — genesis_hash, proposed_root (device tree root), participant list, signatures

---

## Question Matrix

| Question | Answer | Reference |
|---|---|---|
| a) Distinct storage nodes contacted? | **NO.** Entropy is generated locally in-process; `GenesisMpcTransport` is a trait stub with no impl. Must implement HTTP POST endpoints per node in Task A.3. | genesis_mpc.rs:564-574, storage_node_sdk call path missing |
| b) Session protocol phases? | **PARTIAL.** Commit phase exists (compute_commitments); reveal phase exists (verify_commitments). No offer/join/contribute phases; no network state machine. Must add storage-node handlers in Task A.3. | genesis_mpc.rs:207-256 (local only) |
| c) Per-node MPC sig key? | **MISSING.** No per-node MPC key generation, storage, or registration. Plan A.2 task: generate SPHINCS+ key at node startup, store, advertise via /api/v2/node/info. | storage_node/src/api/genesis.rs has no key material |
| d) Commit-reveal η_0 formula? | **STUB.** D_commit and D_reveal are not computed (plan says D_commit = H_concat(sorted commits)). Entropy is used directly; no two-phase encoding. Task A.4 step 8 must add: `η_0 = H("DSM/anchor/eta\0" ‖ D_commit ‖ D_reveal)`. | genesis_mpc.rs:212-238 (only C_i computed) |
| e) Threshold configured? | **n-of-n (no threshold).** Code enforces ≥3 nodes; all n must contribute (whitepaper §2.5 index notation). Task A.4 may later add threshold config as optional; current spec is n-of-n only. | genesis_mpc.rs:188, 295, 538 |
| f) Failure handling? | **LOCAL-ONLY.** Timeout, contributor dropout, network partition: not applicable until transport implemented. Once Task A.3 adds network, must implement retries, quorum detection, and graceful abort. | genesis_mpc.rs:593-656 awaits storage node integration |
| g) Existing proto types? | **YES, but incomplete.** GenesisCreated exists (line 1452-1463); has threshold and session_id fields but they are unused placeholders. MPC-specific messages (Commit, Reveal, Combined, RootBindingRecord) are **MISSING**. | proto/dsm_app.proto:1452-1463 vs. Plan A.1 |
| h) RootBindingRecordV1 in proto? | **NO.** Not found in proto. Must be added in Plan A.1 with fields per spec: genesis_hash, proposed_root, participant_list, combined_hash, signatures. | grep shows no match in dsm_app.proto |

---

## Reconciliation for Tasks A.1–A.8

**From-scratch needed:**
- Task A.1 (proto types): Add GenesisMpcSessionV1, GenesisMpcCommitV1, GenesisMpcRevealV1, GenesisMpcCombinedV1, RootBindingRecordV1 from scratch. Canonical A_0 encoding is pinned in genesis_mpc.rs:421-456 (`canonical_a` function).
- Task A.2 (storage-node MPC key): No existing per-node MPC key generation. Create new `dsm_storage_node/src/identity/mpc_key.rs`.
- Task A.3 (storage-node MPC handlers): No existing offer/commit/reveal endpoints. Create new `dsm_storage_node/src/api/genesis_mpc.rs` (or extend identity/genesis.rs).

**Extend existing:**
- Task A.4 (root-device MPC orchestration): Extend genesis_mpc.rs with real storage-node discovery + HTTP POST loop. Existing `create_mpc_genesis_with_transport` is the right hook; bind it to actual HTTP calls.
- Task A.5 (JNI bridge): Update create_genesis.rs (if exists) or create new JNI binding that calls Task A.4 entrypoint. No file exists yet; check if there's a Kotlin side.
- Task A.6 (frontend): New UI component for MPC progress. No existing genesis-creation flow found.
- Task A.7 (E2E test): New integration test with 6-node local cluster + real MPC.

**Note:** The plan's default threshold is 3 (quorum of 6); code currently has no per-node threshold awareness. Once n-of-n is working, Task A might add optional threshold_count config, but spec §5 is silent on it.

---

## Open Decisions for Phase A Implementation

From the plan's deferred decisions (carry forward):

1. **MPC-key encryption strategy** — Plan A.2 defers the choice: passphrase-derived OR config-bound DBRW. Recommend: passphrase-derived for user control (operator supplies at node startup), with option to rotate.

2. **A_0 canonical encoding** — Already pinned in code (canonical_a function, lines 435-456). Confirm format with plan stakeholders before Task A.1 proto freeze.

3. **Bias-resistance enforcement** — Plan A.3 requires nodes to reject reveal before ≥threshold-1 commits seen. Current plan doesn't specify recovery if a node's entropy is withheld (n-of-n means one dropout = failure). Clarify: continue with remaining contributors or strict n-of-n?

4. **RootBindingRecord signing** — Who signs RootBindingRecord? Plan suggests "initiator device signs" (pk_1), but nodes must also validate it before publishing. Clarify signature scheme and validation predicate.

5. **Genesis bootstrap (out of scope but relevant)** — Very first network genesis (G_0) requires hand-coordinated ceremony; not automated. Document out-of-band process.

---

## Summary Table: From-Scratch vs. Extend

| Task | Component | Approach | Notes |
|------|-----------|----------|-------|
| A.1 | Proto types | **FROM SCRATCH** | Add 5 new message types; pin A_0 encoding |
| A.2 | Storage-node key | **FROM SCRATCH** | New mpc_key.rs; load/persist SPHINCS+ pair |
| A.3 | Storage-node handlers | **FROM SCRATCH** | New genesis_mpc.rs with 4 endpoints |
| A.4 | Root-device orchestration | **EXTEND** | Enhance create_mpc_genesis_with_transport with real HTTP calls |
| A.5 | JNI bridge | **BUILD OR EXTEND** | Likely new create_genesis.rs JNI binding |
| A.6 | Frontend | **FROM SCRATCH** | New React component for MPC progress UI |
| A.7 | E2E test | **FROM SCRATCH** | 6-node integration test harness |
| A.8 | Phase review | **REVIEW GATE** | No coding; invariant & security checks |

