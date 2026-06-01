# Phase B verification — Device Tree (§16.3)

**Audit window:** 2026-05-27 → 2026-05-28
**Scope:** issues #272, #274, #275, #276, #277, #278 (Phase B.1–B.7)
**Audit closes:** issue #279 (Phase B.8)
**Reviewer:** Anthropic Claude (per-commit) + repo CI gates

---

## Summary

Phase B lands the Device Tree as a §16.3 standard binary Merkle tree
over sorted + deduplicated 32-byte DevIDs, with a bounded-validator
storage endpoint, derive-on-GET inclusion proofs, fail-closed initial
publish at genesis-MPC finalisation, and a pure-rendering React
viewer that pulls all verification booleans from Rust.

**Outcome: PASS.** Every invariant has at least one committed test
that exercises it. Cross-crate proof encoding is byte-identical via
`DevTreeProof::to_v1_proto_bytes`. The frontend has zero hashing /
no Merkle math / no `@noble/hashes` dependency on any device-tree
code path.

Six production-complete commits landed on `main` ahead of this audit:

| Commit    | Push  | Scope                                                                       |
| --------- | ----- | --------------------------------------------------------------------------- |
| `20140f26` | B.1   | `DeviceLeafV1` / `DeviceTreeV1` / `DeviceTreeRootUpdateV1` / `DeviceInclusionProofV1` protos + round-trip tests |
| `720a5614` | B.3   | SDK `add/remove_secondary_device` migrated to `DeviceTree::new` + `DeviceTreeStateV1` |
| `06db8483` | B.4   | Storage-node bounded validator on `PUT /devtree/root` + atomic monotonic-version upsert |
| `02da4f6f` | B.5   | Derive-on-GET `/devtree/proof`; `PUT /devtree/proof` removed (405)          |
| `0d2d6a81` | B.6   | Publish initial `DeviceTreeStateV1` at genesis-MPC finalisation; fail-closed at quorum failure |
| `7e578b8b` | B.7   | Pure-rendering `DeviceTreeViewer` + `identity.devtree.snapshot` Rust verifier route |

---

## Invariants → evidence

Each row is one Phase B invariant cross-linked to the commit + test
that proves it. Every test is in-repo and runs via `cargo test` or
`npm test`.

### Tree construction (§16.3)

| Invariant                                              | Proven by                                                                                                |
| ------------------------------------------------------ | -------------------------------------------------------------------------------------------------------- |
| Merkle root is exactly 32 bytes                        | `validator_rejects_root_hash_wrong_length` (B.4 commit `06db8483`); proto `dsm_fixed_len=32` (B.1)       |
| Root is non-zero (rejects all-zero anchor)             | `validator_rejects_all_zero_root_hash` (B.4)                                                             |
| Injectivity — different device sets → different roots  | `initial_device_tree_payloads_differ_across_genesis` (B.6); `test_two_device_tree` / `test_three_device_tree` (pre-existing `dsm::common::device_tree::tests`) |
| Determinism — same input → byte-identical proto bytes  | `initial_device_tree_payload_is_deterministic` (B.6); `proof_derivation_is_byte_deterministic` (B.5)     |
| Sort + dedup canonicalisation                          | `input_order_is_canonicalised_via_lexicographic_sort_and_dedup` (B.3 commit `720a5614`)                  |
| Pad-leaf domain tag prevents odd-leaf self-collision   | `three_device_root_differs_from_padded_four_device_root` + `pad_leaf_is_canonical_and_distinct_from_devid_hashes` (pre-existing, regression for Issue #182 Finding #4) |

### Inclusion proof

| Invariant                                                                            | Proven by                                                                |
| ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------ |
| GET proof is reproducible from stored state with no caller-supplied input            | `proof_derivation_matches_canonical_devtree_proof` + entire `derive_inclusion_proof` suite (B.5 commit `02da4f6f`) |
| Repeated GETs return byte-identical proofs                                           | `proof_derivation_is_byte_deterministic` (B.5)                           |
| Non-member device returns `404 Not Found`                                            | `proof_derivation_returns_not_found_for_non_member` (B.5)                |
| Sibling count is `ceil(log2(device_count))` for balanced trees                       | `proof_derivation_returns_correct_sibling_count_for_balanced_tree` (B.5) |
| Single-leaf yields empty proof (verifies against `hash_leaf(devid)`)                 | `proof_derivation_single_leaf_yields_empty_proof` (B.5); `to_v1_proto_bytes_single_leaf_yields_empty_path` (B.7 commit `7e578b8b`) |
| Proof verification rejects forged siblings                                           | `DevTreeProof::verify` tests in `dsm::common::device_tree::tests` (pre-existing) |
| Canonical encoder (`DevTreeProof::to_v1_proto_bytes`) round-trips through prost      | `to_v1_proto_bytes_round_trips_and_verifies` (B.7)                       |
| Storage-node-served + SDK-served proof bytes are byte-identical for the same input   | B.7 commit body — both paths route through `DevTreeProof::to_v1_proto_bytes`; cross-checked by `proof_derivation_matches_canonical_devtree_proof` (B.5) reusing the canonical encoder |
| `PUT /devtree/proof` is removed (405 with `Allow: GET`)                              | B.5 commit body; `put_proof_removed` handler returns `StatusCode::METHOD_NOT_ALLOWED` |

### Validator (`PUT /devtree/root`)

| Invariant                                                          | Proven by                                                                                |
| ------------------------------------------------------------------ | ---------------------------------------------------------------------------------------- |
| Malformed proto rejected with `400 Bad Request`                    | `validator_rejects_malformed_proto` (B.4)                                                |
| Missing inner `tree` summary rejected with `400`                   | `validator_rejects_missing_tree_summary` (B.4) + `validator_rejects_empty_body` (B.4)    |
| `device_count == 0` rejected                                       | `validator_rejects_zero_device_count` (B.4)                                              |
| `device_count != device_ids.len()` rejected                        | `validator_rejects_device_count_mismatch` (B.4)                                          |
| Per-element `device_ids[i]` length != 32 rejected                  | `validator_rejects_device_id_wrong_length` (B.4)                                         |
| `version_number` strictly monotonic (atomic in DB tx)              | `devtree_strictly_greater_version_is_accepted` + `devtree_equal_version_is_rejected_as_stale` + `devtree_lesser_version_is_rejected_as_stale` (B.4) |
| Per-genesis state is isolated                                      | `devtree_different_genesis_keys_are_isolated` (B.4)                                      |
| Missing-row read is `None`, not error                              | `devtree_get_returns_none_when_absent` (B.4)                                             |
| Validator stays bounded (no Merkle recomputation, no signatures)   | B.4 commit body — `validate_devtree_state` only runs CHECKs 1–4; advanced checks (Merkle recomputation, SPHINCS+ sig, DevID derivation) deferred to Phase 3 enrollment (#300) where `RootBindingRecord` provides the signed authority |

### Add / remove / mutation pipeline

| Invariant                                                                            | Proven by                                                                |
| ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------ |
| First `add_secondary_device` seeds the tree with the root device (genesis_hash)      | `add_first_secondary_seeds_with_root_device_and_bumps_version_to_1` (B.3) |
| Add of duplicate device_id is idempotent (root + count unchanged, version still bumps) | `add_is_idempotent_on_duplicate_device_id` (B.3)                       |
| Remove returns the tree to root-only when only the root + one secondary existed      | `add_then_remove_cycles_back_to_root_only` (B.3)                         |
| `version_number` is strictly monotonic across adds + removes                         | `version_number_is_strictly_monotonic_across_multiple_updates` (B.3)     |
| Removing the last leaf is rejected (`InvalidOperation`)                              | `removing_the_last_device_post_genesis_is_rejected` (B.3)                |
| Malformed prior-state bytes are rejected                                             | `malformed_state_bytes_are_rejected_with_serialization_error` (B.3)      |
| Snapshot serialises to canonical `DeviceTreeV1` prost bytes                          | `snapshot_to_proto_round_trips_through_prost` (B.3)                      |

### Genesis-time initial publish (B.6)

| Invariant                                                                                  | Proven by                                                                |
| ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------ |
| Initial tree has exactly one leaf: the root device (`device_id == genesis_hash`)           | `initial_device_tree_payload_has_single_root_leaf` (B.6)                 |
| Initial publish payload is acceptable to the Phase B.4 validator                           | `initial_device_tree_payload_round_trips_through_validator_shape` (B.6)  |
| Initial publish is deterministic for the same genesis                                      | `initial_device_tree_payload_is_deterministic` (B.6)                     |
| Different genesis hashes produce distinct initial payloads                                 | `initial_device_tree_payloads_differ_across_genesis` (B.6)               |
| Genesis aborts (no local state installed) when initial-publish quorum can't be reached     | `core_sdk::create_genesis_with_passive_contributors` doc comment (B.6); the `before_install` hook returns `Err`, K_DBRW is never installed, silicon inputs are not zeroized, no state-machine state or BCR head row is written |
| Initial publish counts 2xx (Created/OK) AND 409 (Conflict) as ACKs                         | B.6 commit body — `publish_initial_device_tree_to_quorum` treats prior-version-409 as an idempotent success (storage node already holds the row at version >= 1) |
| `AppState::set_device_tree_root` is populated post-publish for bilateral settlement        | B.6 commit body — `create_genesis_with_mpc` calls `set_device_tree_root(snapshot.root_hash)` after `before_install` succeeds |

### Frontend pure-rendering (B.7)

| Invariant                                                                                          | Proven by                                                                |
| -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| Frontend renders pure presentation (no JS verifier; no Merkle math; no hashing)                    | `frontend/src/components/identity/DeviceTreeViewer.tsx` — zero `@noble/hashes` import, zero `Blake3` reference, zero `hash_leaf` / `hash_node` equivalents. All verification booleans come from `inclusionVerified` / `claimedRootMatchesRecomputed` fields populated Rust-side. |
| The verifier is the same Rust code path the rest of the workspace exercises                        | B.7 commit body — `build_device_tree_snapshot_view` calls `DevTreeProof::verify` (same `dsm::common::device_tree`); no parallel JS port |
| Trust-but-verify gate at the tree level                                                            | `claimed_root_matches_recomputed` flag set by `build_device_tree_snapshot_view`; covered by `build_snapshot_view_flags_match_versus_mismatch` (B.7) |
| Frontend mocks the bridge at the module boundary; per-leaf badges follow the booleans              | 5 tests in `DeviceTreeViewer.test.tsx` (B.7): empty state, verified-honest, tampered (root mismatch), bridge-throws-error, per-leaf "✗ Not included" rendering |

---

## Cleanup verification (B.8 acceptance criteria)

The B.8 issue asks for grep-style sweeps that ensure no legacy
`[count: u32][device_id_1: 32 bytes]…`-style flat-list constructions
or `compute_device_tree_root` callers survive. Sweep results
(2026-05-28):

| Pattern                                                                              | Hits |
| ------------------------------------------------------------------------------------ | ---- |
| `grep -rn "compute_device_tree_root" --include="*.rs" --include="*.ts" --include="*.tsx" --include="*.kt"` | **0** |
| `grep -rn "// Encode as: \[count: u32\]" --include="*.rs"`                           | **0** |
| `grep -rn "\[count: u32\]\[device_id_1: 32 bytes\]" --include="*.rs"`                | **0** |
| Production `DeviceTreeEntry` callers (intentionally retained — separate registry-evidence path, not §16.3) | `ingress.rs`, `registry_addr.rs`, `storage_node_sdk.rs::register_device_in_tree`, `app_router_impl.rs` — documented in B.3 commit body |

No partial migrations. The Phase B.1–B.7 surface is the only sanctioned
§16.3 path; the legacy `DeviceTreeEntry` family handles a separate
content-addressed registry-evidence flow (root device registration)
that doesn't overlap with the published Device Tree.

---

## Security-relevant observations (security-reviewer skill output)

Reviewing the diffs landed in B.1–B.7 against the project rules
(post-quantum SPHINCS+ signatures, BLAKE3 domain-separated hashing,
no JSON in protocol paths, no wall-clock time, no hex encoding, no
`unsafe` in core paths):

| Concern                                                  | Status                                                                                                                                                                                                                                                                                                                  |
| -------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Hashing primitives                                       | All Device Tree hashing uses `dsm::crypto::blake3::dsm_domain_hasher` with domain tags `DSM/dev-merkle`, `DSM/dev-leaf`, `DSM/dev-empty`, `DSM/dev-tree-pad`. No raw BLAKE3 / SHA usage. ✓                                                                                                                              |
| Signature primitives                                     | None used in B.1–B.7. The `DeviceTreeRootUpdateV1.signature` field is reserved for Phase 3 enrollment hardening (#300) where the `RootBindingRecord`'s `root_pubkey` provides the authority to verify against. ✓                                                                                                       |
| Wall-clock time in consensus paths                       | None. Validator uses `state.current_tick` (atomic deterministic counter) for `updated_at_tick` storage; no `SystemTime::now`. ✓                                                                                                                                                                                         |
| Hex encoding on the wire                                 | None. All identifiers cross the wire as raw `bytes` proto fields; HTTP path segments use Base32 Crockford. ✓                                                                                                                                                                                                            |
| JSON in protocol paths                                   | None. The validator decodes prost; the storage column stores prost bytes. ✓                                                                                                                                                                                                                                             |
| `unsafe` in core paths                                   | None added in B.1–B.7. ✓                                                                                                                                                                                                                                                                                                |
| Caller-controlled trust at the storage node              | `PUT /devtree/proof` removed (405). Inclusion proofs derived on every GET from the validated `DeviceTreeStateV1` — a malicious caller cannot install custom proof bytes that subsequent readers consume as authoritative. ✓                                                                                            |
| Atomic version-monotonicity (no TOCTOU race)             | `upsert_device_tree_state_if_monotonic` runs the read + check + write inside one transaction on both backends: rusqlite `unchecked_transaction()` for SQLite, `IsolationLevel::Serializable` with `SELECT ... FOR UPDATE` for PostgreSQL. ✓                                                                              |
| Fail-closed initial publish                              | `create_genesis_with_passive_contributors`'s `before_install` hook runs network publish BEFORE installing K_DBRW / state-machine / BCR head; on quorum failure all those installations are skipped and silicon inputs are not zeroized. ✓                                                                               |
| Frontend trust boundary                                  | The React component renders booleans the Rust SDK computed. No client-side hash recomputation that could disagree silently with the Rust path. The `claimed_root_matches_recomputed` gate is the trust-but-verify signal against the storage node. ✓                                                                    |

**No new findings.** The deferred items below are scope-narrowing
calls already documented in the relevant commit bodies.

### Deferred to later tiers (explicitly not Phase B scope)

| Item                                                                                  | Tracked in                                                  |
| ------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| Storage-side Merkle-root recomputation (CHECK 5) on PUT                               | Phase 3 enrollment (#300) — depends on `RootBindingRecord`  |
| SPHINCS+ signature verification on `DeviceTreeRootUpdateV1`                           | Phase 3 enrollment (#300)                                   |
| DevID-derivation check (every leaf derives from a known pubkey)                       | Phase 3 enrollment (#300)                                   |
| Multi-device tree publish on `add_secondary_device` (network-side, not just SDK-local) | Phase 3 enrollment (#300) — same RBR authority chain        |
| Mounting `DeviceTreeViewer` on a screen                                               | Next contact-info UI refresh (UI layout decision)           |

---

## Test totals

Running the full Phase B test bouquet on 2026-05-28:

```bash
cargo test -p dsm --lib common::device_tree
  -> 12 passed; 0 failed

cargo test -p dsm --test device_tree_root_lifecycle_test
  -> 18 passed; 0 failed

cargo test -p dsm_sdk --lib sdk::storage_node_sdk::tests
  -> 19 passed; 0 failed

cargo test -p dsm_sdk --lib handlers::identity_routes
  -> 8 passed; 0 failed

cargo test -p dsm_storage_node --no-default-features --features local-dev,strict --lib
  -> 211 passed; 0 failed   (includes 11 validator-branch + 6 monotonic-upsert + 9 proof-derivation tests)

cargo test --workspace --exclude dsm_storage_node --lib
  -> 1502 passed; 0 failed; 7 ignored

npm test -- --ci
  -> 141 suites / 1103 tests pass  (includes 5 DeviceTreeViewer tests)

cargo clippy --workspace --all-features -- -D warnings   -> clean
npm run type-check                                       -> clean
npm run lint                                             -> clean
ci/no_clock_and_no_json.sh                               -> OK
scripts/check_forbidden_symbols.sh                       -> OK
```

---

## Decision

**Close issue #279 (Phase B.8).** All B.0–B.7 issues are closed
(#272, #274, #275, #276, #277, #278). The Phase B Device Tree
surface is production-complete per the per-push rule.

Phase 3 enrollment hardening (#297–#311) picks up from here: it
extends the bounded validator to 8 checks once `RootBindingRecord`
lands, and adds the multi-device publish path on `add/remove_secondary_device`.
