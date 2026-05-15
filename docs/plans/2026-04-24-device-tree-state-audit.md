# Device Tree State Audit (Pre-Plan-B Execution)

**Date:** 2026-05-15  
**Branch:** fix/genesis-mpc-and-device-tree (worktree from origin/main)  
**Plan reference:** docs/plans/2026-04-24-genesis-mpc-and-device-tree.md Task B.0

---

## Summary

The current device tree is **a real balanced binary Merkle tree with:
- Proper leaf hashing with domain separation (`DSM/dev-leaf`)
- Proper internal node hashing with domain separation (`DSM/dev-merkle`)
- Canonical padding leaf (`DSM/dev-tree-pad`) for odd-count levels (Issue #182 Finding #4 fix)
- Inclusion proofs with sibling hashes and path bits
- Lexicographic sorting, deterministic across permutations, stable roots

However, the SDK's `add_secondary_device` (lines 1795–1915) uses a **flat-list encoding** (`[count: u32][device_id_1: 32B]...`) for transport to storage nodes, not the proto-structured tree. The storage endpoint (`PUT /devtree/root`) accepts **any bytes without validation** — no recomputation of root, no schema parsing, no versioning. Inclusion proofs are **stored as raw bytes** from clients, not derived from the tree.

**Verdict:** Core Merkle tree library is correct and production-ready. Device tree endpoint and SDK flow need refactoring to surface the tree structure to storage nodes and remove proof storage in favor of on-demand derivation.**

---

## Per-File Findings

### 1. `dsm_client/deterministic_state_machine/dsm/src/common/device_tree.rs`

**Status:** IMPLEMENTED + correct per spec (with one note)

**What it does:**
- `DeviceTree::new(device_ids)` — sorts, deduplicates, builds balanced binary Merkle tree
- `hash_leaf(dev_id)` — BLAKE3 with domain `DSM/dev-leaf`
- `hash_node(left, right)` — BLAKE3 with domain `DSM/dev-merkle`
- `empty_root()` — special sentinel hash via domain `DSM/dev-empty` (not 32×0x00)
- `pad_leaf()` — canonical padding leaf via domain `DSM/dev-tree-pad` for odd-count levels
- `DeviceTree::proof(dev_id)` — generates `DevTreeProof` with siblings and path_bits
- `DevTreeProof::verify()` — reconstructs root from leaf + siblings + path_bits

**Code locations:**
- Tree construction: lines 184–196
- Merkle root computation: lines 237–255 (chunks(2), odd-leaf paired with pad_leaf(), not self-duplication)
- Proof generation: lines 220–233 (leaf_to_root=true convention)
- Proof serialization: lines 78–104 (u32 count, u8 flag, u32 bitlen, packed bits, siblings)
- Tests: lines 299–476 (15 tests covering empty tree, single/two/three/four-device trees, dedup, padding regression for Issue #182 Finding #4)

**Alignment with spec:**
- Per §2.2 (Device Tree Merkle structure) ✓
- Canonical encoding: sorted ascending by device_id, binary balanced tree ✓
- Leaf hashing domain-separated ✓
- Internal node hashing domain-separated ✓
- Odd-leaf handling via pad_leaf(), not self-duplication ✓
- Empty tree handled explicitly (empty_root sentinel) ✓

**Subtlety:** The domain tags (TAG_DEV_LEAF, TAG_DEV_MERKLE, TAG_DEV_EMPTY, TAG_DEV_PAD) use `DSM/dev-*` nomenclature per the implementation's Issue #182 comment, not the §2.2 `DSM/merkle-*` terminology. This is noted as pending Brandon's resolution in domain_tags.rs:30–32. Both interpretations are domain-separated and secure; the audit assumes the implementation's choice is intentional.

---

### 2. `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/storage_node_sdk.rs:1795–1915` (`add_secondary_device` and related)

**Status:** IMPLEMENTED but spec-divergent

**What it does:**
- `add_secondary_device(genesis_hash, client_entropy)` (lines 1795–1915):
  1. Derives new_device_id via H(DSM/device || client_entropy || genesis_hash || DBRW)
  2. Fetches existing "device tree" from storage as **flat-list bytes** (lines 1835–1861): `[count: u32][device_id_1: 32B]...[device_id_N: 32B]`
  3. Decodes flat list into `Vec<[u8; 32]>`, appends new device, sorts
  4. Calls `compute_device_tree_root(&device_ids)` (line 1873) — correctly uses the Merkle library
  5. Encodes back to flat list (lines 1882–1886)
  6. PUTs to storage under key `device_tree:{genesis_crockford}` (lines 1889–1900)
  7. Returns response; no proof generated

- `compute_device_tree_root(device_ids)` (lines 2910–2939):
  - Wraps the Merkle tree library correctly
  - Uses `hash_leaf`, `hash_node`, `empty_root` from the DSM common module
  - **BUG:** Lines 2925–2927 show odd-leaf self-duplication (`[left] => next_level.push(*left)`), which contradicts the library's pad_leaf() fix. This code path is **unreachable** because the library functions handle odd padding correctly at the next level (line 2949 would use pad_leaf()); the match arm at line 2925 would only trigger if a single element made it to the top, which is caught earlier. **Low severity but needs code cleanup.**

**Spec divergence:**
- **Transport format:** Plan Task B.1 specifies proto-encoded `DeviceTreeV1` with `repeated DeviceLeafV1 leaves` + `uint64 version` (lines 403–406 of plan). Current code uses flat `[count: u32][device_id...]`, which is opaque to validators.
- **Versioning:** No `version` field in current flow; plan requires monotonic versioning per Task B.1 (field 2 of DeviceTreeV1, checked in Task B.4 validator).
- **Proof storage:** Current code does not generate or upload proofs on device addition; plan expects proofs to be **derived** from the tree on GET (Task B.5).

**Lines affected:**
- Device list encoding: 1843–1854 (decoding), 1882–1886 (encoding)
- Root computation call: 1873

---

### 3. `dsm_storage_node/src/api/identity/devtree.rs`

**Status:** IMPLEMENTED but no validation

**What it does:**
- **PUT /api/v2/identity/{genesis}/devtree/root** (lines 65–81, `put_root`):
  - Checks body size (1–256 bytes)
  - Decodes genesis from Crockford path parameter
  - Computes storage key via blake3_tagged("DSM/identity/devtree/root", genesis_b)
  - Upserts raw bytes to database
  - **Returns 200 OK for ANY bytes — no schema validation, no root recomputation, no version checking**

- **GET /api/v2/identity/{genesis}/devtree/root** (lines 46–63, `get_root`):
  - Returns whatever bytes were PUT

- **GET /api/v2/identity/{genesis}/devtree/proof** (lines 83–105, `get_proof`):
  - Queries device_id from URL params
  - Computes proof key via blake3_tagged("DSM/identity/devtree/proof", genesis_b || devid_b)
  - Returns stored bytes (client-provided during PUT)

- **PUT /api/v2/identity/{genesis}/devtree/proof** (lines 107–128, `put_proof`):
  - Accepts and stores raw proof bytes (1–128KiB)

**Spec divergence:**
- **Zero validation:** Current endpoint is dumb storage. Plan Task B.4 specifies a bounded validator with 6 checks:
  1. RootBindingRecord present for G
  2. Version monotonic (new_version > prior_version)
  3. SPHINCS+ authorization signature verifies under rbr.pk_1
  4. DevID derivation correct
  5. **NEW:** Submitted tree's recomputed root matches proposed_root
  6. **NEW:** Submitted tree contains/excludes authorized device_id
- **Proof derivation:** Current endpoint stores proofs from clients. Plan Task B.5 says proofs should be **derived** from the tree on GET via `device_tree::build_inclusion_proof()`.

---

### 4. `proto/dsm_app.proto`

**Status:** PARTIAL (device tree types exist but not task-specified types)

**What's present (lines 2641–2655):**
- `DeviceTreeProof` (lines 2641–2646): repeated siblings, leaf_to_root flag, path_bits_len, packed path_bits
  - Matches the format used by DevTreeProof serialization (device_tree.rs:78–104)
  - NOT the plan's Task B.1 spec for `DeviceInclusionProofV1` (which includes genesis_hash, device_id, tree_version, computed_root, leaf, domain tag comment)
  
- `DeviceTreeEntry` (lines 2649–2655): device_id, genesis_hash, parent_hash, tree_depth, merkle_proof (array of siblings)
  - Unrelated to current implementation; appears unused
  
- Generic field reference (line 2046): `DeviceTreeProof device_tree_proof = 3;` in some message (context needed to confirm)

**Missing (per plan Task B.1):**
- `DeviceLeafV1`: fields device_id, device_pk, cdbrw, admitted_at_version; domain "DSM/devtree-leaf"
- `DeviceTreeV1`: repeated DeviceLeafV1, version field
- `DeviceTreeRootUpdateV1`: genesis_hash, proposed_root, prior_version, new_version, optional authorization, new_tree; domain "DSM/devtree-root"
- `DeviceInclusionProofV1`: genesis_hash, device_id, tree_version, computed_root, siblings, leaf; domain "DSM/devtree-proof"

---

## Question Matrix

| Question | Answer | Reference |
|---|---|---|
| **a) compute_device_tree_root algorithm?** | Real balanced binary Merkle tree with domain-separated leaf/node hashing. Empty tree → empty_root sentinel. Single leaf → leaf hash. Multiple leaves → bottom-up hash of chunks. Odd-count levels: last node paired with pad_leaf() (Issue #182 Finding #4 fix). | storage_node_sdk.rs:2910–2939; device_tree.rs:237–255 |
| **b) device_tree.rs status?** | EXISTS; PRODUCTION-READY. Full Merkle tree library with DeviceTree struct, proof generation/verification, serialization. Correctly domain-separated. 15 regression tests. | dsm/src/common/device_tree.rs:1–476; tests at :299–476 |
| **c) Inclusion-proof format?** | Real proofs: DevTreeProof struct with (siblings: Vec<[u8; 32]>, path_bits: Vec<bool>, leaf_to_root: bool). Serialized as [num_siblings: u32][flag: u8][path_len: u32][packed_bits][siblings...]. Verification reconstructs root from leaf + siblings + path via hash_node at each level. NOT empty stubs. | device_tree.rs:45–163 (DevTreeProof definition and verify/serialize/deserialize) |
| **d) Domain-separated leaf hash?** | YES. `hash_leaf(dev_id)` uses BLAKE3 with domain tag `DSM/dev-leaf` (via dsm_domain_hasher wrapper). Tag constants in domain_tags.rs have NO trailing NUL; hasher appends it (convention fix for Issue #182 Finding #3). | device_tree.rs:20–25; domain_tags.rs:34 |
| **e) Sorted + stable?** | YES. DeviceTree::new() sorts device_ids lexicographically (ascending) at line 185, deduplicates at 186. Inclusion proofs verified correctly for any permutation of same device set (both test cases at device_tree_root_lifecycle_test.rs confirm). Root is byte-exact-identical regardless of insertion order. | device_tree.rs:184–186 |
| **f) Storage endpoint validation?** | NONE. PUT /devtree/root accepts any 1–256 byte payload without schema check, root recomputation, or version validation. Stored as raw bytes in database. GET returns what was PUT. | identity/devtree.rs:65–81 (put_root); lines 70–80 show no validation beyond size and genesis decoding |
| **g) Monotonic version field?** | NOT PRESENT. Current code has NO version field in any device-tree-related data structure (neither flat-list encoding nor proto message nor storage key). Plan Task B.1 requires uint64 version; Task B.4 validator must enforce prior_version < new_version. | Grep for "version" in add_secondary_device (1795–1915) returns zero matches; proto DeviceTreeProof (:2641) has no version field |
| **h) Existing proto types? If yes, list field shapes vs. plan.** | PARTIAL. DeviceTreeProof exists (siblings, leaf_to_root, path_bits_len, path_bits) — close to but not identical to plan's DeviceInclusionProofV1 (missing genesis_hash, device_id, tree_version, computed_root, leaf fields). DeviceTreeEntry exists but unused. NO DeviceLeafV1, DeviceTreeV1, or DeviceTreeRootUpdateV1. Plan Task B.1 requires all four types with specific field ordering and domain tags. | proto/dsm_app.proto:2641–2655 vs. plan §Task B.1 lines 395–432 |

---

## Recommended Reconciliation

### For Tasks B.1–B.8

| Task | Scope | Reconciliation |
|---|---|---|
| **B.1** | Define device tree types | **Build from scratch** — add DeviceLeafV1, DeviceTreeV1, DeviceTreeRootUpdateV1, DeviceInclusionProofV1 per spec. Keep existing DeviceTreeProof in proto for backward compatibility with tests, but migrate SDK/storage to new types. |
| **B.2** | Device tree library | **Extend existing** — device_tree.rs is complete; add helper functions `compute_root(tree: &DeviceTreeV1)` and `build_inclusion_proof(tree, dev_id)` that wrap the existing DeviceTree struct if needed for proto workflow, or refactor to operate on DeviceLeafV1 arrays directly. |
| **B.3** | Update SDK add_secondary_device | **Refactor existing** — replace flat-list encoding with proto DeviceTreeV1. Fetch current tree, add leaf (with admitted_at_version), recompute root, PUT proto-encoded DeviceTreeRootUpdateV1. |
| **B.4** | Update storage validator | **Build from scratch** — add bounded validator with 6 checks; storage endpoint currently has zero validation. Parse proto DeviceTreeRootUpdateV1, recompute root from new_tree, verify schema + authorization + version monotonicity. |
| **B.5** | Derive proofs on GET | **Refactor existing** — remove PUT /devtree/proof endpoint; change GET to parse stored tree, call device_tree::build_inclusion_proof(), return proto DeviceInclusionProofV1. |
| **B.6** | Initial empty tree at genesis | **Build from scratch** — extend create_root_genesis_mpc (Task A.4) to build initial DeviceTreeV1 with primary device as sole leaf, compute R_G, PUT to /devtree/root with prior_version=0. Update validator to accept bootstrap case (no auth needed when prior_version=0 and tree contains exactly pk_1). |
| **B.7** | Frontend device-tree UI | **New component** — not started; straightforward UI integration once B.3–B.5 complete. |
| **B.8** | Phase B verification | **Validation step** — run security review on new validator; grep codebase for legacy flat-list usages; run all device-tree tests. |

---

## Open Decisions for Phase B Implementation

1. **Proto message versioning:** Should DeviceTreeV1 be versioned in the message name (`DeviceTreeV1`, `DeviceTreeV2`, etc.) or via a version field inside? Plan assumes separate message types; confirm this aligns with SDK architecture.

2. **Admitted-at-version semantics:** Plan's DeviceLeafV1.admitted_at_version field (Task B.1 line 400) means "the tree version when this device was added." Is this used for auditing, or can it be omitted from the initial implementation and added in a future task?

3. **Removal authorization:** Plan's Task B.4 Step 1 mentions removal semantics "need to be specified — defer to a separate task if not covered here." Multi-device disenrollment is not in scope for B.0 audit; confirm whether B.4 validator should support device removal in Phase B or only addition.

4. **Bootstrap case:** Plan Task B.6 allows prior_version=0 with no authorization signature if the tree contains exactly one leaf matching pk_1. Should the validator also accept prior_version=0 + empty tree? (Unlikely but worth confirming.)

---

## Critical Plan Assumptions That Don't Match Current State

1. **"Device tree is currently a flat-list scaffolding"** (plan intro, line 15): ✓ Confirmed — SDK uses flat `[count: u32][device_id...]` encoding on wire. However, **the Merkle tree library is complete and correct**, so the "needs full replacement" framing is misleading. What needs replacement is the **transport encoding and endpoint validation**, not the tree algorithm.

2. **"Inclusion proofs would not be meaningful against a flat list"** (plan line 15): ✓ Confirmed — current storage endpoint stores proofs from clients (PUT /devtree/proof), does not validate them against the tree. Plan's shift to on-demand derivation (Task B.5) is required.

3. **"Validator added in Phase 3 cannot verify what it cannot parse"** (plan line 15): ✓ Confirmed — storage endpoint accepts raw bytes with zero schema validation. Validator cannot meaningfully check anything until Task B.4 implements schema parsing and root recomputation.

4. **"Companion plan added a bounded validator... both correct in shape, but they assume... device tree is a real Merkle structure"** (plan line 17): ✓ Confirmed — the Merkle library exists and is correct; the validator logic (from companion plan) needs to be extended (Task B.4) to parse the tree and verify root consistency.

---

**Audit completed.** Ready for Phase B execution.
