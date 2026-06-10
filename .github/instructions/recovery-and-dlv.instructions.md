---
applyTo: '**'
---

# DSM Recovery and Deterministic Limbo Vault Specification

Brandon "Cryptskii" Ramsay — Inventor of DSM (Deterministic State Machine)

June 5, 2026 — Revision 1.0 (reconciled spec ↔ code)

## Abstract

This document specifies DSM recovery and Deterministic Limbo Vault (DLV) behavior.
It distinguishes live device recovery from DLV controller recovery. Live device
recovery requires mnemonic-authorized tombstone publication followed by automatic
synchronization across the device's complete committed contact set before recovered
funds become spendable. Completeness of that set is guaranteed structurally: the
device continuity capsule advances with every accepted state transition, a
counterparty cannot carry value until it has been sealed into the capsule's contact
set, and the capsule tip is an anti-rollback floor that a counterparty may only
confirm or extend forward. As a result, the no-double-spend guarantee reduces to
capsule currency plus all-contact acknowledgement and depends on no external
availability source. DLV recovery is different: it does not recover balances or roll
back vault state. It only rotates controller or recovery access against the latest
verifiable DLV state. The DLV remains a sovereign deterministic vault: value is
suspended under committed protocol math, not controlled by a middleman, validator,
creator backdoor, or discretionary signer. Token policies remain independent objects.
A DLV only operates over existing token policies explicitly referenced when the DLV
is created.

> **This is a reconciled specification.** Every normative section carries a status
> tag describing its relationship to the shipped implementation. Where the spec and
> the code diverge, **the shipped code is authoritative** unless this document names
> an explicit required migration. This revision adds no code; it classifies the
> design surface and flags implementation gaps (see §0).

---

## Status Legend

Each section/clause is tagged with one of:

- **[A — shipped]** — Code-backed today. The cited file (and, where useful, line) or
  proto message implements it.
- **[B — planned]** — Spec-only. Not present in code or proto yet. Listed in the
  Implementation Gap Register (§0.2).
- **[Divergent — shipped authoritative]** — The code does this, but differently from
  the way this document describes. The **shipped form governs**; the document's
  alternative is recorded for reference and is **not** adopted unless a migration is
  explicitly named.

Code anchors are relative to `dsm_client/deterministic_state_machine/` unless noted.
Proto anchors are in `proto/dsm_app.proto`.

---

## 0. Reconciliation Summary

### 0.1 What is shipped vs planned, at a glance

| Area | Status | Anchor |
| --- | --- | --- |
| Recovery mnemonic — 256-bit / 24-word generation | **A** | `dsm_sdk/src/sdk/recovery_sdk.rs:259` (`generate_mnemonic`, `bip39::from_entropy`, 32-byte entropy) |
| Recovery mnemonic — reject 12-word as primary mainnet authority | **A** | 24-word (256-bit) floor at `recovery.enable` + `recovery.cacheMnemonic` (`recovery_routes.rs`) |
| Recovery key derivation (Argon2id → BLAKE3) | **Divergent** | `capsule.rs:244` uses salt `DSM/recovery-ring\0` + BLAKE3 `derive_key("DSM/recovery-aead\0")`, not Argon2id+HKDF over `DSM/recovery-mnemonic\0` |
| Recovery authority seed (SPHINCS+) | **A** | `capsule.rs:265` (`derive_recovery_authority_seed`, ctx `DSM/recovery-authority\0`) |
| Device Continuity Capsule — owner's own sealed frontier | **A** | `RecoveryCapsule` (`capsule.rs:55`): `smt_root`, `counterparty_tips`, `rollup_hash`, `cert_chain_heads`, `last_certs` |
| Capsule wire framing (hand-rolled `RCV3`, not protobuf) | **Divergent** | `capsule.rs:22` magic `RCV3`; spec's `DeviceContinuityCapsulePlaintextV3` is a protobuf shape |
| Capsule `contact_set_commit` (v6) | **A** | v6 trailing field, domain-separated, validated on open (`capsule.rs`); unified with seal via `contact_set_commit_from_device_ids` |
| Capsule `*_root_hint` discovery hints | **B** | absent from `RecoveryCapsule` |
| Capsule encryption AAD / nonce / challenge | **Divergent** | `capsule.rs:117/496/505` (see §4.3); shipped binds `smt_root`+`counter`, not `G‖X‖R‖c` |
| Capsule currency — re-seal on every accepted transition | **A** | atomic `accepted_state_index` bump in the commit tx (`core_sdk::dual_write_advance_outcome`); re-seal + self-heal on egress |
| Capsule dirty/current tracking | **A** | `accepted_state_index` / `capsule_state_index` / `is_capsule_dirty`; surfaced on `recovery.status` |
| Mandatory contact sealing (Invariant 1) | **A** (as currency) / **B** (per-contact establishment seal) | R2′ blocks egress while dirty; establishment-seal + non-shrinkable set pending (P2 T2.2/T2.3) |
| Tombstone + succession receipts (SPHINCS+) | **A** | `dsm/src/recovery/tombstone.rs:31/50`; proto `RecoveryTombstoneRequest/Response`, `RecoverySuccessionRequest/Response`, `TombstoneReceiptProto` |
| Recovery lifecycle (typed `RecoveryState`) | **A** | `RecoveryState` enum in `client_db/recovery.rs` (drop-in for the prior string phases) |
| Cross-relationship succession + `RecoveryActivationSeal` validation | **A** (logic) / **B** (proto wire + flow) | `recovery/succession_binding.rs` (`CrossRelationshipSuccessionEvidence`), `recovery/activation.rs` (`validate_recovery_activation`, `compute_evidence_root`); proto/transport not wired |
| Genesis-anchored recovery authority | **A** (logic) / **B** (bind-once + transport) | `recovery/authority_anchor.rs` (`RecoveryAuthorityAnchor`); chokepoint binds candidate pubkey before verify; storage bind-once not wired |
| All-contact gate-set + relationship-freshness enforcement | **A** (seal logic) / **B** (flow) | seal enforces set-equality + forward-ancestry floor; online-posted evidence collection + non-shrinkable union not wired |
| Recovered-successor spend-freeze + unlock chokepoint | **A** | freeze in `value_egress_block_reason`; sole unlock `RecoverySDK::verify_and_record_activation` (T4.4) |
| Fail-closed value-egress gate (exhaustive `Operation::is_value_egress`) | **A** | `core_sdk::execute_on_relationship` + `validate_transfer_request`; under-lock, fail-closed on DB error |
| DLV object, "not a smart contract", storage=availability | **A** | `vault/limbo_vault.rs`, `vault/dlv_manager.rs` |
| DLV references **existing** token policies (CPTA) | **A (concept) / Divergent (shape)** | `LimboVaultProto.policy_digest` (field 15) anchors a CPTA; spec's `DLVCreateV3.token_policies` / `TokenPolicyRefV3` is a different shape |
| Token policies independent (DLV never creates/modifies) | **A** | CPTA: `TokenPolicyV3`, `PolicyAnchorV3`; `token-policy-readiness.instructions.md` |
| DLV swap + output routing | **A (function) / Divergent (shape)** | SoFi `RouteCommitV1` pipeline + `AmmConstantProduct` (`sdk/route_commit_sdk.rs`, `routing_path_sdk.rs`); not `DLVSwapTransitionV3` / `DLVRouteKind` |
| DLV value/controller state split (`DLVStateV3`) | **B** | absent |
| DLV controller rotation (`DLVControllerRotationV3`, rotation capsule) | **B** | absent |
| No public fanout into owner recovery gate-set | **A (design) / B (formal link)** | holds once the gate-set (§6) is enforced |

### 0.2 Implementation Gap Register (status)

Status as of the recovery double-spend hardening work. The entire double-spend
*safety logic* (P0–P4 + P3) is implemented and unit-tested; what remains is
transport/flow plumbing and the DLV subsystem. Legend: **✅ implemented +
unit-tested** · **◑ partial (safety logic done; flow/plumbing remains)** · **☐ open**.

1. ✅ **Capsule currency on every accepted transition.** The `accepted_state_index`
   bump is folded ATOMICALLY into the state-commit transaction
   (`core_sdk::dual_write_advance_outcome`, `recovery::bump_accepted_state_index_with_conn`),
   so a frontier-changing transition can never persist without the capsule being
   marked dirty; best-effort re-seal + self-heal on egress. Refinement ☐:
   durable-write confirmation (NFC tag / storage-node publish ack → `durable_capsule_index`).

2. ✅ **Capsule dirty/current surfacing.** `accepted_state_index` / `capsule_state_index`
   / `is_capsule_dirty` (`client_db/recovery.rs`); surfaced on `recovery.status`.

3. ◑ **Mandatory contact sealing (Invariant 1).** Enforced as *currency*: R2′
   blocks value egress while the capsule is dirty (`value_egress_block_reason`,
   fail-closed). The per-contact establishment-seal + the non-shrinkable gate-set
   (public anchors) is ☐ (P2 T2.2/T2.3).

4. ◑ **`contact_set_commit` / gate-set.** ✅ capsule v6 `contact_set_commit`
   (domain-separated, validated on open), unified with the seal's byte-id commit
   (`capsule::contact_set_commit_from_device_ids`). ☐ the non-shrinkable union
   (public anchors + storage enumeration).

5. ✅ **Anti-rollback floor enforcement.** Seal acks: confirm-floor-or-forward,
   below-floor rejected (`activation::validate_recovery_activation`). Resume path:
   `resume_tip_diverges_from_floor` (fail-closed) + `restore_finalized_bilateral_chain_tip`
   refuse-to-overwrite. ◑ full co-signed forward-chain proof for tips above the floor.

6. ✅ **Typed `RecoveryState` enum.** `client_db/recovery.rs` — drop-in for the
   string phases (same on-disk representation).

7. ◑ **Cross-relationship succession + activation seal (§0.5 model, supersedes
   the signed-ack model).** ✅ pure validation logic + types:
   `CrossRelationshipSuccessionEvidence` (`recovery/succession_binding.rs`),
   `RecoveryActivationSeal` + `validate_recovery_activation` + `compute_evidence_root`
   (`recovery/activation.rs`) — set-equality over the gate-set (no
   omission/substitution/duplicate) + per-C device-binding + carry-forward + old-chain
   hash forward-ancestry + both-tip inclusion. ✅ **recovery-authority trust-anchoring**
   via the genesis-chained declaration `RecoveryAuthorityAnchor`
   (`recovery/authority_anchor.rs`) — the activation chokepoint binds the candidate
   authority pubkey to the anchor (genesis-key + possession signatures) before any
   verification; no contacts-DB pubkey path remains. ✅ **value-capable** gate-set
   criterion (`Operation::is_value_bearing`). ✅ **bilateral re-establish transport**
   (the interactive successor-channel side): A_new conveys the capsule floor `h_cap` in the
   recovery-establish op's `proof` (`build_recovery_establishment_op` /
   `recovery_establishment_floor`); the pre-co-sign authorization is posted as a
   `RecoverySuccessionProof` (`recovery/succession_proof.rs`) and fetched by C; A_new initiates
   via `RecoverySDK::begin_recovery_reestablish` (carry-forward over C's REAL `(A_old,C)`
   frontier, `t_old_current` from C's posted leaf) and C gates co-signing on
   `verify_incoming_recovery_reestablish` → the pure `verify_recovery_reestablish_request`.
   Both sides are wired into the bilateral BLE handler — `initiate_recovery_reestablish`
   (A_new) and an automatic accept-guard in `handle_prepare_request` (C), selected by the
   canonical `is_recovery_establish_op` marker — reusing the ordinary 3-phase commit (**no new
   BLE message types**). ☐ on-device two-device prepare→confirm integration test (requires a
   live BLE link). ◑ unlock chokepoint
   `RecoverySDK::verify_and_record_activation` exists, performs the anchor binding +
   seal validation, but is **fail-closed (disabled)** pending live trust inputs; the
   recovered-successor freeze (`is_recovered_successor`/`is_recovery_activated`) is
   wired into the gate but intentionally inert. ☐ **remaining before go-live:**
   gate-set must be the online-posted, non-shrinkable, value-capable set (R4, gap #4)
   fetched via the device-tree quorum path (storage = availability); proto wire
   messages; posted-evidence collection over sync; **bind-once enforcement** for the
   authority anchor at the storage/device-tree layer; capsule-index freshness check;
   `set_recovered_successor(true)` at succession; per-contact bind-once (R1). **Do NOT
   wire the freeze/unlock live until the online-posted gate-set + anchor bind-once
   enforcement land.**

8. ☐ **DLV value/controller split + controller rotation.** ✅ pure validator
   `dlv::controller_rotation::validate_controller_rotation` — parent==current tip,
   value_state_commit preserved, controller change, recovery-authority signature
   (9 tests). ☐ wiring: `controller_devid` on the actual vault state, proto
   `DLVStateV3`/`DLVControllerRotationV3`, rotation capsule, `dlv_sdk` apply against
   the latest verified DLV-chain state (P6). NOTE: rotation-nonce replay is bounded
   by the parent==current-tip check (a verifier holding the newer tip rejects a
   replay); an explicit nonce set would harden against storage-rewind.

9. ✅ **Reject-12-word for mainnet.** 24-word (256-bit) floor at `recovery.enable`
   and `recovery.cacheMnemonic` (`recovery_routes.rs`).

Added during hardening (beyond the original register):

10. ✅ **Fail-closed value-egress gate** at the canonical chokepoint via the
    exhaustive `Operation::is_value_egress` classifier (`core_sdk::execute_on_relationship`)
    + `validate_transfer_request`. The gate fails CLOSED on a DB read error and
    decides UNDER the state-machine lock (no check-before-lock TOCTOU), atomic with
    the commit + bump.

11. ✅/☐ **Bearer-asset `LOCKED_RECOVERY` + per-asset spend-open chokepoint** (P5) —
    the capsule is a continuity hint, never a balance oracle.
    ✅ Generic safety layer: `BearerAssetLockState{LockedRecovery, Spendable, Reduced,
    InFlight, Finalized, RefundPending}` (`dsm::recovery::bearer_lock`, fail-closed wire
    codec) + `Operation::egress_asset` (exhaustive asset-id companion to `is_value_egress`)
    + the `recovery_locked_assets` registry + `asset_egress_block_reason` wired into the
    `execute_on_relationship` chokepoint (checked AFTER the identity gate, persists per-asset
    past activation) + recovery-time locking in `execute_recovery_pipeline`
    (`lock_all_restored_bearer_assets`, fail-closed) + generic token reconciliation
    (`reconcile_token_asset`: `verified≥hint→Spendable`, `verified<hint→Reduced` capped).
    ✅/☐ **dBTC bearer-state reconciliation.** ✅ Posted-advertisement classifier +
    deterministic aggregator + fail-closed reconcile: `dsm::recovery::dbtc_reconcile`
    (`DbtcVaultCondition`, `DbtcVaultOutcome`, `aggregate_dbtc_frontier` — checked arithmetic,
    `{Spendable|Reduced|InFlight|Finalized|RefundPending|LockedRecovery}`) +
    `BitcoinTapSdk::classify_dbtc_lifecycle` (posted `DbtcVaultAdvertisementV1.lifecycle_state`
    → condition; unknown → fail-closed) + `BitcoinTapSdk::reconcile_dbtc_asset` (fetch+verify
    each posted ad, aggregate, `set_asset_lock("dBTC", …, is_dbtc=true)`; any missing/malformed/
    unverifiable/unknown ad keeps dBTC `LockedRecovery`) + `recovery.reconcileDbtc` route. The
    generic path still REFUSES dBTC (`MissingDbtcFrontierReplay`); dBTC unlocks only through
    this dedicated path, only for vaults whose Bitcoin backing proves it, never from capsule
    data. ✅ **Bitcoin SPV/UTXO gate** (`dsm::recovery::dbtc_backing` + `BitcoinTapSdk::
    gather_dbtc_backing_facts`/`dbtc_preimage_matches`): the unsigned ad is trusted only to
    BLOCK; a vault becomes `Spendable` ONLY when live Bitcoin confirms the HTLC UTXO is unspent
    + confirmed AND the bearer can re-derive the claim preimage (`SHA256(preimage)==hash_lock`).
    Bitcoin unreachable → fail-closed (no unlock). ✅ **Authenticated vault enumeration**
    (`dsm::recovery::PostedDbtcVaultIndex`, K_A-signed; `RecoverySDK::publish_dbtc_vault_index`/
    `fetch_dbtc_vault_index`/`auto_dbtc_vault_candidates`; `recovery.reconcileDbtc` auto-sources
    it; empty → `MissingDbtcVaultEnumeration`, dBTC stays `LockedRecovery`). Unit-tested;
    live Bitcoin UTXO/confirmation is integration-tested on Bitcoin infra.

12. ✅/☐ **Recovery-authority anchor lifecycle (§0.5 step 7).** ✅ create
    (`RecoverySDK::build_authority_anchor`, device key re-derived via
    `init::derive_device_signing_keypair`) → publish to the dedicated bind-once
    endpoint (`storage_io::put_to_all_nodes_path`, offline-first trigger on
    `recovery.enable`) → **server bind-once per genesis** (`dsm_storage_node`
    `recovery_authority_anchors` table + `/api/v2/recovery/authority-anchor/{genesis}`,
    first-write-wins / idempotent-identical / 409-on-conflict, both sqlite+pg) →
    **quorum-authenticated fetch+verify** (`RecoverySDK::fetch_and_verify_authority_anchor`
    composing the device-tree quorum signing pubkey + `anchor.verify`). All
    fail-closed; consuming side still inert. ☐ go-live wiring.

13. ☐ **Gate-set discovery — BLOCKED on a PDSMT posting prerequisite (R4-critical).**
    The R4 rule (CONFIRMED): the recovery gate-set is **A_old's online-posted,
    genesis-authenticated, enumerable, value-capable Per-Device SMT leaf set at the
    recovery snapshot** — NOT the capsule hints, NOT the contacts DB, NOT the
    responder set, NOT a per-counterparty scan (those are *evidence* authority per
    member, never *enumeration* authority), and NOT a separate relationship-set
    object. The posted PDSMT today (`dsm_storage_node/.../identity/tips.rs`) cannot
    satisfy this: the head is an unsigned root, leaves are individually hash-keyed +
    encrypted (**not enumerable**), a leaf carries only a tip hash (**not
    classifiable** — `operation` lives in unposted `RelationshipChainState`), and the
    root is **not genesis-authenticated**. **Prerequisite (next-session design/build) —
    Authenticated Enumerable PDSMT Posting** (extend the existing tips/PDSMT layer,
    do NOT add a parallel object).

    **Dual keying (MANDATORY) — device for state location, genesis for authority.**
    The Per-Device SMT belongs to a specific device and `rel_key` is device-pair-derived
    (`H("DSM/smt-key\0" || min(DevID_A,DevID_C) || max(DevID_A,DevID_C))`), so the
    endpoint and records are **addressed/enumerated by `owner_device_id = A_old`** —
    NOT by genesis alone (genesis-only blurs multiple devices under one user and breaks
    the SMT-key model). But every signed head/leaf record MUST ALSO carry
    `genesis_id = G_A`, because recovery authority and anti-shrink trust are
    genesis-scoped: a device/PDSMT is only trusted once proven to belong to the
    recovering identity domain. Rule: **device ID selects the PDSMT; genesis ID
    authenticates that the device/PDSMT belongs to G_A; the signature authority must
    chain back to `genesis_id`.** Do NOT replace `device_id` with `genesis_id`, and do
    NOT omit `genesis_id`.

    - **Posted head** (`PostedPDSMTHead`): `{ genesis_id: G_A, device_id: A_old,
      pd_smt_root: r_A_old, leaf_index_root: R_index, snapshot_id,
      authority_pubkey_commit_or_id, signature }`. The signature is valid iff it
      verifies under a recovery/genesis authority that is itself anchored to G_A
      (§0.5 step 5 anchor) **AND** `A_old` is proven included under G_A's Device Tree
      (device-tree quorum / inclusion).
    - **Posted leaf/index records** (`PostedPDSMTLeafRecord`): `{ genesis_id: G_A,
      owner_device_id: A_old, rel_key, counterparty_device_id: C,
      counterparty_genesis_id (optional but recommended if known/proven), current_tip,
      value_capable, value_capable_reason, inclusion_proof_to_pd_smt_root,
      inclusion_proof_to_leaf_index_root }`. The `value_capable` flag MUST be part of
      the signed/committed record — server metadata is NOT authoritative. Minimum
      identity fields: `genesis_id = G_A`, `owner_device_id = A_old`,
      `counterparty_device_id = C`. (Counterparty genesis alone cannot compute `rel_key`
      — it is device-pair based — but is useful authenticated context once C's device
      membership under its own genesis is verified.)
    - **Enumeration endpoint**: `GET /tips/{owner_device_id}/leaves` returns all posted
      leaf/index records for the snapshot (availability only; client verifies every
      record against the signed head: inclusion to `pd_smt_root`/`leaf_index_root`,
      and head signature chaining to G_A).
    - **Gate-set construction**: fetch the signed head for `owner_device_id = A_old` →
      verify head signature chains to G_A AND A_old ∈ G_A Device Tree → enumerate
      leaves → verify each leaf's inclusion/root consistency → filter
      `value_capable=true` → freeze into `gate_set_commit`/`contact_set_commit` →
      require `CrossRelationshipSuccessionEvidence` for every member (extra responders
      not in the frozen leaf set do not expand the gate). Also still needed: the
      **recovery bundle** format (carries `K_A_pub` + tombstone + succession + per-C
      evidence) the activation flow consumes.

    **✅ Built (wire foundation):** `PostedPdsmtHeadV1` / `PostedPdsmtLeafRecordV1`
    protos + `recovery::pdsmt_posting` (`PostedPdsmtHead` / `PostedPdsmtLeafRecord`
    codec, head signing digest + `PostedPdsmtHead::verify` binding the signature to the
    committed authority pubkey, per-leaf `committed_digest` binding the authoritative
    `value_capable` flag/reason; 6 tests). The head is signed by the genesis-anchored
    recovery authority `K_A` (commit reused from the §0.5 step-5 anchor).

    **R4 anti-shrink (CONFIRMED design — double-spend-critical).** A `K_A`-signed head
    proves *authenticity* but NOT *completeness*: the R4 adversary IS the spender (holds
    `A_old`/`K_A`), so it can sign a head whose value-capable leaf set OMITS a
    counterparty `C` — then `C` keeps accepting `A_old` while `A_new` activates without
    `C` (the recovery double-spend window). The SMT root is sparse, so "the index covers
    ALL value-capable leaves" is unprovable from `pd_smt_root` alone, and completeness
    only proves the index matches the *signed head*, not that the *signer* was honest.
    Therefore R4 is enforced by a COMBINATION of three layers, with the counterparty-union
    as the adversarial backstop:

    > **R4 INVARIANT.** *A recovery activation MUST NOT exclude any counterparty that can
    > prove, from its OWN genesis-authenticated posted state, that it had a value-capable
    > relationship with `A_old` at or before the recovery snapshot.*

    - **Authority split (unchanged):** `A_old`'s posted PDSMT = primary enumeration source;
      `C`'s posted state = anti-shrink witness; capsule = floor/hint only; contacts DB =
      no authority; responder set = no authority.
    - **Layer 1 — pre-tombstone freeze / append-once head chain.** `PostedPdsmtHead` is
      part of a monotonic append-only chain: each head commits `parent_head_hash`; storage
      enforces append-only (a new head's parent MUST equal the current head's hash) — no
      overwrite, no fork. The recovery snapshot uses the latest valid head **at or before**
      the tombstone/recovery-intent; a recovery head cannot silently replace the prior head.
    - **Layer 2 — completeness commitment.** The head commits BOTH `pd_smt_root` AND
      `leaf_index_root`; `leaf_index_root` commits the enumerable set of leaf records; each
      record commits `{rel_key, counterparty_device_id, current_tip, value_capable,
      value_capable_reason}` (via `committed_digest`). The verifier REJECTS if the
      enumerable index does not verify against the signed head. `value_capable` is
      committed/signed — NEVER server metadata.
    - **Layer 3 — counterparty-union cross-check (backstop).** Any independently
      genesis-authenticated counterparty state proving an active value-capable `(C,A_old)`
      relationship forces `C` into the gate-set even if `A_old`'s head omitted it. Concrete
      witness: `C`'s OWN `PostedPdsmtLeafRecord` for the SAME (symmetric, device-pair)
      `rel_key` with `owner=C, counterparty=A_old, value_capable=true`, included under
      `C`'s OWN signed PDSMT head (authenticated via `C`'s `RecoveryAuthorityAnchor` +
      `C ∈ G_C`'s Device Tree). `value_capable` is symmetric — bilateral states are
      co-signed, so both endpoints attest it truthfully.

    **Final gate-set rule.** `GateSet =` value-capable leaves from `A_old`'s latest valid
    append-only PDSMT head `∪` independently genesis-authenticated counterparty claims
    proving a value-capable relationship with `A_old` (at/before the snapshot). Activation
    **fails closed** if any member of that union lacks valid
    `CrossRelationshipSuccessionEvidence`.

    **Proof-system caveat (implementation).** `pd_smt_root` is a `SparseMerkleTree`
    (`device_state.rs`); local inclusion uses `SparseMerkleTree::get_inclusion_proof` /
    `verify_proof_against_root`. A SECOND, non-interchangeable proof format exists —
    `verify_smt_inclusion_proof_bytes` (protobuf `SmtProof`, used by `succession_binding`
    against `counterparty_root`). Before building leaf-inclusion, confirm which format the
    *posted* `pd_smt_root` proofs use and use it consistently; build the NEW
    `leaf_index_root` as a `SparseMerkleTree`.

    **Test plan (each layer, pass + fail):**
    - *Append-only chain (storage, local-dev):* first head inserts; valid child
      (parent==current) appends + increments `head_number`; fork/overwrite (wrong parent) →
      409; replay of current head idempotent-or-409 per convention; distinct device
      independent.
    - *Completeness (unit):* `verify_inclusion` passes against a real
      `SparseMerkleTree`-built `leaf_index_root` + `pd_smt_root`; fails on tampered tip,
      tampered `committed_digest`, wrong root, or a leaf omitted from the index.
    - *Head auth (unit, extend existing 6):* signature/authority binding holds with
      `parent_head_hash`/`head_number` folded into the digest.
    - *Union (unit):* an `A_old` head OMITTING `C` + a valid `C`-witness (C's own
      value-capable leaf, shared symmetric `rel_key`, under C's genesis-auth head) ⇒ `C` is
      FORCED into the gate-set; a forged / non-genesis-authenticated `C`-witness is
      rejected; a `value_capable=false` witness does not add `C`.
    - *Gate-set construction (unit):* union freeze → `gate_set_commit`; activation fails
      closed if any union member lacks valid `CrossRelationshipSuccessionEvidence`.

    **✅ Built (all three layers, pure cores + storage + transport, tested):**
    - Wire foundation: `PostedPdsmtHeadV1`/`PostedPdsmtLeafRecordV1` + `recovery::pdsmt_posting`.
    - Layer 1 (append-once chain): head `parent_head_hash`/`head_number` (signed);
      `dsm_storage_node` `pdsmt_head_chain` table (sqlite+pg) + `insert_pdsmt_head_if_chained`
      (genesis/child append, idempotent replay, 409 on fork/gap/stale); endpoint
      `PUT/GET /api/v2/tips/{device}/head-chain[/{n}]`; SDK `publish_pdsmt_head` /
      `fetch_pdsmt_head_latest` / `fetch_pdsmt_head_at`.
    - Layer 2 (completeness): `PostedPdsmtLeafRecord::verify_inclusion` (rel_key→tip under
      `pd_smt_root`, rel_key→`committed_digest` under `leaf_index_root`, both via
      `SparseMerkleTree::verify_proof_against_root`) + `verify_head_with_leaves`.
    - Layer 3 (union + final rule): `recovery::gate_set::build_gate_set` —
      `A_old` value-capable leaves ∪ `CounterpartyValueWitness` (C's own value-capable leaf
      for the shared symmetric rel_key) → frozen `gate_set_commit`; the omitted-counterparty
      anti-shrink path is unit-proven.

    **☐ Remaining (this plan):** SDK orchestration (fetch A_old's latest valid head ≤
    snapshot + leaves, fetch candidate counterparty witnesses, verify each via
    `fetch_and_verify_authority_anchor` + device-tree quorum, call `build_gate_set`, freeze
    into the activation seal); the **publish-side head builder** (enumerate THIS device's
    PDSMT leaves, classify `value_capable` by walking each relationship's history with
    `is_value_bearing`, build the `leaf_index` SparseMerkleTree, generate proofs, sign +
    `publish_pdsmt_head`); the **recovery bundle** format. Gate-set CONSTRUCTION + the
    unlock stay fail-closed until all land + adversarial review (go-live is a separate
    audited step).

### 0.3 Sibling-spec overlap (cross-reference, not rewritten here)

- `whitepaper.instructions.md` — recovery ring, capsule AAD (§13/§16.10), cert chains (§11.1).
- `nfcringbackup.instructions.md` — NFC capsule transport / recovery overlap.
- `sofi.instructions.md`, `sofispecs.instructions.md` — DLV, swap, routing, storage-as-availability.
- `token-policy-readiness.instructions.md` — token-policy independence (CPTA).

Contradictions found during reconciliation are recorded as gap-register entries above;
sibling specs are **not** rewritten in this pass.

### 0.4 Hardened double-spend doctrine (authoritative)

The recovery design rests on a **two-gate model**. Conflating these two gates is
the historical source of double-spend risk:

1. **Identity recovery** answers "is `A_new` the valid successor to `A_old`?" —
   the mnemonic-authorized tombstone + all-contact activation seal (§6).
2. **Bearer-asset reconciliation** answers, per asset, "what value is still
   spendable under the latest verified asset frontier?" (§5 LOCKED_RECOVERY).

> **A recovery capsule is NOT a balance oracle.** It is a continuity object that
> helps the successor *locate* relationships, contacts, policy commitments, and
> asset-frontier hints. Spend authority is restored only by (1) identity
> succession succeeding AND (2) the specific asset frontier reconciling. There is
> no path from "capsule says balance X" to "X is spendable" — which is what kills
> the stale-capsule attack.

**Mandatory hardening conditions (all required):**

- **R1 — per-contact bind-once.** Each contact binds to the first valid tombstone
  proposal for an `old_device_id` and rejects later competing proposals; combined
  with all-contact set-equality, competing recoveries can only deadlock, never
  both activate.
- **R2′ — durable-persist-before-value (on the spending device).** A value-bearing
  transition is refused until the capsule committing the relevant contact is
  durably persisted; fail-closed on persistence failure. (Enforced today as
  capsule-seal currency; durable-write confirmation is the remaining strengthening.)
- **R3 — total value-egress coverage.** Every egress path (bilateral, token,
  DLV, dBTC transfer/withdraw/burn/refund/finalize, token-MPC, emissions) routes
  through the fail-closed gate; proven by the exhaustive `Operation::is_value_egress`
  classifier at the canonical chokepoint.
- **R4 — non-shrinkable gate-set.** `gate_set = capsule.contact_set_commit ∪
  publicly-discoverable contact anchors ∪ externally-relevant value frontiers`.
  The spender cannot unilaterally shrink the set by omitting a contact.
- **STRICT-GATE — never weaken for liveness.** The all-contact gate MUST NOT be
  relaxed by timeout, quorum, majority, set-reduction, or "best-effort". Liveness
  is handled only by liquidity placement (value in DLVs, thin hot balances). A
  malicious mnemonic holder may deadlock recovery but MUST NOT create two
  spend-authoritative successors.

**Acknowledgement = posted state, not a signed ack object (§0.5).** A counterparty's
recognition of the tombstone/successor binding is its own online-posted,
genesis-authenticated relationship state — not a standalone `ContactTombstoneAck`
object (that model is superseded). The anti-rollback floor is enforced as
**cryptographic forward ancestry** (`h^cap ⟶* T_old_current`, hash adjacency /
parent consumption) — there is **no numeric height** in the predicate. The successor
must restore at or above the floor in the forward-ancestry sense.

**dBTC crucial rule (bearer-asset instance).** Recovered dBTC is never restored
as spendable from capsule balance. It is restored as a pending bearer-asset claim
under policy `P`, then resolved by replaying and verifying the latest dBTC
bearer-state frontier — transfers, in-flight withdrawals, burns, refunds, and
bridge finalization — keeping the capsule from becoming a private ledger. (Bearer
asset states: `LOCKED_RECOVERY → reconciled{Spendable | Reduced | InFlight |
Finalized | RefundPending}`; egress refused while locked or below frontier. P5.)

### 0.5 Recovery authority = counterparties' posted, genesis-authenticated state (CONFIRMED — supersedes the signed-ack model)

Recovery authority is **NOT** the stolen device, **NOT** the capsule, and **NOT**
the local contacts DB. Recovery authority is the set of counterparties whose own
**online-posted, genesis-authenticated state** proves they recognized the tombstone
and advanced to the successor binding. This fits DSM: storage nodes are dumb mirrors
(store / mirror / enforce object invariants, never attest); verification is
**client-side** via BLAKE3 over deterministic protobuf + device-side signatures and
inclusion proofs.

**Safety argument:**
1. **No invisible value contact.** A value-capable relationship must have an
   online-posted contact/anchor path. Never anchored ⇒ cannot be in the gate;
   anchored ⇒ recovery discovers it from the posted record.
2. **The ack is not a standalone signed object.** It is the counterparty's own
   posted tree/root showing the tombstone + successor binding, verified against the
   counterparty's genesis/device authority — not trusted because storage served it.
3. **Offline spends can't be hidden from a counterparty that counts.** If C accepted
   an offline spend from A_old before processing the tombstone, then when C comes
   online to process the tombstone it posts its current tree — which includes BOTH
   the spend AND the successor binding. A_new cannot observe the binding without also
   observing C's full current relationship state.
4. **If C never comes online, C does not count.** The relationship stalls (liveness),
   but there is no double-spend (safety). This is the only failure mode.

**Per-counterparty validity (build rule).** For each value-capable counterparty C in
A's online-posted, genesis-authenticated relationship set, C's recovery evidence is
valid iff:
1. C's posted object is fetched from storage by content/address;
2. it verifies under DSM canonical bytes + domain-separated hash rules;
3. C's device identity verifies under C's genesis / device tree;
4. C's posted per-device tree/root contains the relationship edge to A;
5. that edge shows C processed A_old's tombstone and bound A_new as successor;
6. C's relationship tip is a valid **forward descendant (hash ancestry)** of the
   floor known from A_new's capsule / recovery seed;
7. any transition C accepted **before** the tombstone is already reflected in the
   same posted tree/root;
8. missing / stale / unverifiable / non-posting C produces **no** authority.

**Drop:** signed recovery acks as separate authority objects; contacts-DB pubkey
lookup as authority; the local capsule as the contact-set source; shrinkable local
gate-set logic from A_old's local records.
**Keep:** capsule as hint/floor/recovery seed; storage as availability; counterparty
posted trees as authority; genesis/device-tree verification as the trust root;
forward-tip comparison against the capsule floor.

**Forward-ancestry nuance (MANDATORY).** "tip ≥ floor" means **cryptographic forward
ancestry** (hash adjacency / parent consumption), **NOT numeric greater-than**. DSM
acceptance uses hash adjacency, inclusion proofs, and signatures — **no timestamps,
heights, or counters** in acceptance predicates. (This corrects the interim
`recovery/activation.rs` floor check, which used a numeric `height`; that is
superseded by hash forward-ancestry.)

**Doctrine.** A recovery contact counts only when its own genesis-authenticated,
online-posted tree proves both (1) it bound the tombstone/successor transition and
(2) its current relationship tip includes every transition it accepted before that
binding. Therefore recovery cannot skip a thief's prior spend to that counterparty:
either the spend is in the posted state, or the counterparty has not posted and
cannot count. **The complete gate-set IS the online-posted, value-capable
relationship set; the authority for each gate is the counterparty's own posted,
genesis-authenticated state.**

### 0.5.1 Implemented building blocks (pure cores; transport/go-live pending)

The §0.5 doctrine is realized by these unit-tested pure cores. Wiring to live
posted data, storage, and the go-live unlock remains (see gap register #7).

1. ✅ **Cross-relationship succession, not in-place migration.** `rel_key` is
   device-pair-derived (`compute_smt_key`, §18.1), so `(A_old,C)` and `(A_new,C)`
   are distinct SMT leaves — in-place same-`rel_key` migration is impossible by
   construction. Recovery **retires** `(A_old,C)` and **establishes** a new
   bilateral `(A_new,C)` whose first accepted state carries forward the old
   relationship's verified frontier. `succession_binding.rs`
   (`CrossRelationshipSuccessionEvidence`) verifies, per C: device-pair `rel_key`
   derivation; the tombstone/succession successor proof under the genesis-anchored
   authority; old-chain forward-ancestry `h^cap ⟶* T_old_current` (hash adjacency,
   no heights); the carry-forward commitment binding `(rel_keys, h_cap,
   T_old_current, tombstone, succession, A_old, A_new, C)`; the first-state
   constraint (the successor channel must be *born* as such); and inclusion of BOTH
   old and new tips in C's posted, genesis-authenticated root. The new `(A_new,C)`
   relationship is a normal bilateral stitched receipt, so `verify_stitched_receipt`
   authenticates it at the integration layer.

2. ✅ **Genesis-anchored recovery-authority declaration — NOT a genesis field.**
   The recovery-authority SPHINCS+ pubkey `K_A_pub` (derived from the mnemonic via
   `derive_recovery_authority_seed`) authenticates each C's tombstone/succession.
   It **cannot** be a genesis field: the recovery mnemonic is generated only when
   the user enables NFC backup (`recovery_sdk::derive_and_cache_key`, via the
   `recovery.enable` route), which runs AFTER genesis creation — the mnemonic is not
   in scope when `create_genesis_via_blind_mpc*` runs. So the authority is anchored
   by a **declaration chained off genesis** (`authority_anchor.rs`,
   `RecoveryAuthorityAnchor`): it commits `H(K_A_pub)` and is signed twice — by the
   device's **genesis signing key** (genesis binding; verified against the
   genesis-authenticated device pubkey fetched via the device-tree quorum path) and
   by `K_A` itself (possession proof). Forgery resistance is **bind-once per
   genesis** (first declaration wins, immutable thereafter — mirrors R1): a
   device-holding thief cannot override a legitimately-enrolled authority; a
   never-enrolled user has no recovery path regardless, and bearer assets stay
   `LOCKED_RECOVERY` (P5). The activation chokepoint binds the candidate authority
   pubkey to this anchor BEFORE any verification — there is **no** raw
   runtime-pubkey path. (Bind-once *enforcement* is a storage/device-tree property,
   step 7.)

3. ✅ **Value-capable = `Operation::is_value_bearing`.** Gate-set membership is
   protocol-defined: a relationship is value-capable iff its posted state accepted
   ≥1 value-bearing operation (value in ANY direction — egress ∪ ingress
   `Mint`/`Receive`/`CreateToken`), OR its policy marks it value-bearing (policy
   branch applied at the discovery layer). Pure contact/social relationships are
   excluded. The freeze/snapshot of this set is the seal's `contact_set_commit`
   (R4 anti-shrink + anti-drift); the discovery scan (`list_objects`) is step 7.

### 0.5.2 R4 anti-shrink — gate-set completeness (see §0.2 gap 13 for the full rule)

A `K_A`-signed PDSMT head proves authenticity, not completeness; the R4 adversary IS
the spender. The gate-set is therefore made non-shrinkable by THREE combined layers
(detailed, with the invariant + final gate-set rule + test plan, in §0.2 gap 13):
**(1)** an append-once PDSMT head chain (`parent_head_hash`, pre-tombstone freeze),
**(2)** a completeness commitment (head commits `pd_smt_root` + `leaf_index_root`;
`value_capable` is committed, never server metadata), and **(3)** a counterparty-union
backstop — `C`'s OWN genesis-authenticated value-capable leaf for the shared symmetric
`rel_key` forces `C` into the gate-set even if `A_old`'s head omitted it.

> **R4 invariant.** A recovery activation MUST NOT exclude any counterparty that can
> prove, from its OWN genesis-authenticated posted state, a value-capable relationship
> with `A_old` at/before the recovery snapshot. Activation fails closed if any union
> member lacks valid `CrossRelationshipSuccessionEvidence`.

---

## 1. Purpose

DSM supports two distinct recovery modes. **[A — concept; both modules exist and are
already distinct]**

1. **Device continuity recovery.** Recovers a lost, stolen, destroyed, or retired
   live device. A live device is a relationship endpoint with contacts, bilateral
   state, pending transitions, hot spend authority, and relationship-local tips;
   recovering it migrates the relationship graph.
2. **DLV controller recovery.** Recovers or rotates access to control a Deterministic
   Limbo Vault. A DLV is not a normal live contact device; it is a deterministic
   policy-bound vault object. DLV recovery does not restore a historical balance and
   does not roll back vault state — it only rotates controller or recovery access.

The two modes are not interchangeable:

```
DeviceRecovery ≠ DLVControllerRecovery
```

A device is recovered by contact migration. A DLV is recovered by controller rotation.

---

## 2. Core Terminology

- **Genesis (`G`).** Root identity domain binding devices, contacts, policies, and
  recovery authority. **[A]** (`genesis_hash` carried in the capsule, `capsule.rs:71`).
- **Device Identifier (`DevID`).** Stable cryptographic identifier derived from a
  device's post-quantum public key + device binding material. **[A]**
  (`source_device_id`, `capsule.rs:68`).
- **Old Device (`DevID_old`).** The device being recovered from / tombstoned. **[A]**.
- **Successor Device (`DevID_new`).** Fresh device identifier with new silicon binding
  and a fresh SPHINCS+ keypair; bound via the succession receipt
  (`tombstone.rs:50`, `new_device_commitment`). **[A]**.
- **Value-Bearing Transition.** Any accepted relationship transition that creates,
  moves, reserves, or releases token value (or otherwise changes a balance/reserve
  attributable to the device). Metadata/discovery/recovery-context updates are
  non-value-bearing. **[A — concept]**.
- **Device Continuity Capsule.** The device's own encrypted, self-sealed checkpoint of
  its post-transition frontier: relationship tips, contact-set commitment, Per-Device
  SMT root, and receipt-roll accumulator current as of the latest accepted transition.
  **[A — storage]** for the owner's own frontier (`RecoveryCapsule`, `capsule.rs:55`);
  **[B]** for the explicit `contact_set_commit` field (see §4.1).
- **Anti-Rollback Floor.** For relationship `A↔B`, the capsule-committed tip
  `h^cap_{A↔B}` is the minimum tip the recovering device accepts. **[A — stored]** (the
  floor material is `counterparty_tips`); **[B — enforced]** (the confirm-or-extend-forward
  check at recovery time is not yet wired).
- **Gate-Set.** The exact set of counterparties whose Contact Tombstone Acknowledgements
  are required before the successor may spend; defined by the latest sealed capsule's
  `contact_set_commit` and nothing else. **[B]**.
- **Deterministic Limbo Vault (DLV).** A deterministic policy-bound vault object; value
  is suspended under committed protocol math until a proof-carrying transition satisfies
  the DLV's policy. **[A]** (`vault/limbo_vault.rs`, `vault/dlv_manager.rs`).
- **Token Policy.** An independent CPTA / token-policy object that exists separately from
  any DLV. A DLV does not create, modify, rename, or replace token policies. **[A]**
  (`TokenPolicyV3`, `PolicyAnchorV3`; core `cpta/`).

> **Naming discipline (per project direction).** This document uses **DLV** throughout
> and treats **token policy** as the pre-existing, independent CPTA object that DLV
> flows **reference/import**. It does not introduce a renamed or parallel vault or
> token-policy system.

---

## 3. Recovery Mnemonic

### 3.1 Entropy and Representation Requirement

DSM recovery mnemonics MUST encode at least 256 bits of entropy. The canonical
representation is a 24-word BIP39-style phrase, and a 24-word phrase is REQUIRED as the
primary recovery authority for mainnet.

- 256-bit / 24-word generation: **[A]** — `recovery_sdk.rs:259` `generate_mnemonic()`
  draws 32 bytes from `OsRng` and calls `bip39::Mnemonic::from_entropy`.
- "A 12-word mnemonic MUST NOT be used as the primary mainnet recovery authority":
  **[B]** — `derive_recovery_key` (`capsule.rs:244`) hashes the mnemonic string with no
  word-count gate; a 12-word phrase is not rejected. (Gap §0.2.9.)

The recovery mnemonic derives recovery authority and capsule decryption material. It
MUST NOT directly derive the old device's live signing key, DBRW/C-DBRW binding
material, the old device identifier, vault balances, contact approvals, storage-node
authority, or any ECDSA/Ed25519/RSA/secp256k1 authority. **[A]** — the mnemonic feeds
only the AEAD key and the (separate) SPHINCS+ recovery-authority seed; SPHINCS+ is the
only signature scheme (no Ed25519/secp256k1).

### 3.2 Recovery Key Derivation — **[Divergent — shipped authoritative]**

Spec form:

```
S_mn = Argon2id(M, "DSM/recovery-mnemonic\0", params)
K_R  = HKDF-BLAKE3("DSM/recovery-aead\0", S_mn)        # 32 bytes
```

Shipped form (`capsule.rs:244`, authoritative):

```
seed = Argon2id(mnemonic, salt = "DSM/recovery-ring\0")           # Argon2::default()
K_R  = BLAKE3::new_derive_key("DSM/recovery-aead\0").update(seed) # 32 bytes
```

Differences: the Argon2id salt/domain is `DSM/recovery-ring\0` (not
`DSM/recovery-mnemonic\0`), and the second stage is BLAKE3 `derive_key` (not HKDF-BLAKE3).
The AEAD context string `DSM/recovery-aead\0` matches. The shipped derivation governs.
A separate authority seed is derived under `DSM/recovery-authority\0`
(`capsule.rs:265`) and feeds the deterministic SPHINCS+ recovery-authority keypair —
this is **[A]** and is the root of trust for tombstone/succession signing.

> No migration is adopted here. If the project later chooses the `recovery-mnemonic` +
> HKDF construction, it MUST be a versioned capsule format change (it would invalidate
> existing capsules) and must be named explicitly as a required migration.

---

## 4. Recovery Artifacts

DSM defines two recovery capsule classes:

1. `DeviceContinuityCapsule` — **[A]** (shipped as the `RCV3` binary capsule).
2. `DLVControllerRotationCapsule` — **[B]** (not present).

They are different objects and MUST NOT be treated as interchangeable.

### 4.1 Device Continuity Capsule

An encrypted checkpoint for a live device. It provides continuity context for recovery;
it does not activate recovery and does not unlock funds.

**Shipped plaintext** (`RecoveryCapsule`, `capsule.rs:55`) — **[A]**:

```
RecoveryCapsule {
    smt_root: [32]                 # Per-Device SMT root  (owner's own)
    counterparty_tips: map<id, (height, head_hash[32])>   # owner's sealed per-relationship tips
    rollup_hash: [32]              # receipt-roll accumulator
    challenge: [32]
    metadata { version, flags, logical_time, counter }    # counter == capsule index
    source_device_id: [32]         # v4
    genesis_hash: [32]             # v4
    cert_chain_heads: map<id, EK_pk>   # v5 (whitepaper §11.1)
    last_certs: map<id, cert>          # v5
}
```

**Spec-proposed plaintext** `DeviceContinuityCapsulePlaintextV3` (protobuf) — for
comparison only:

```
version, genesis_id, old_device_id, capsule_index, per_device_smt_root,
receipt_roll, contact_set_commit, storage_contact_root_hint,
latest_device_tree_root_hint, challenge, metadata
```

Reconciliation:

| Spec field | Shipped equivalent | Status |
| --- | --- | --- |
| `genesis_id` | `genesis_hash` | **A** |
| `old_device_id` | `source_device_id` | **A** |
| `capsule_index` | `metadata.counter` | **A** |
| `per_device_smt_root` | `smt_root` | **A** |
| `receipt_roll` | `rollup_hash` | **A** |
| `challenge` | `challenge` | **A (present) / Divergent (derivation, §4.3)** |
| `metadata` | `metadata` | **A** |
| `contact_set_commit` | — | **B** |
| `storage_contact_root_hint` | — | **B** |
| `latest_device_tree_root_hint` | partially via `genesis_hash`+`smt_root` | **B** |
| — | `counterparty_tips`, `cert_chain_heads`, `last_certs` | **A (shipped, not in spec msg)** |

> **Important — self-tip invariant (per direction).** The shipped capsule already seals
> the **owner's own** frontier (`smt_root` + `counterparty_tips` + `rollup_hash` +
> `cert_chain_heads`). This is stronger than the spec's `DeviceContinuityCapsulePlaintextV3`,
> which folds per-relationship tips into commitments and omits the explicit tips map.
> Any future `V3` protobuf migration MUST preserve `counterparty_tips`/`cert_chain_heads`/
> `last_certs` (do not drop them in favor of `per_device_smt_root` + `contact_set_commit`
> alone). See §5.4.

The capsule's committed relationship tips are the anti-rollback floor. During recovery
a counterparty MAY only (a) confirm the capsule-committed tip, or (b) prove a valid
forward receipt-adjacent chain from the capsule tip to a newer tip; it MUST NOT move a
relationship below the floor. **Floor storage: [A]. Floor enforcement at recovery time: [B].**

### 4.2 DLV Controller Rotation Capsule — **[B]**

An encrypted artifact to recover/rotate controller access for a DLV. It MUST NOT define
the DLV balance, restore historical DLV state, or roll back a DLV; it only identifies
recovery context for rotating controller access against the latest verifiable DLV state.
Spec shape (`DLVControllerRotationCapsulePlaintextV3`): `version, genesis_id, vault_id,
old_controller_devid, recovery_authority_commit, storage_vault_root_hint,
controller_rotation_nonce, challenge`. **Not present in code.**

```
DLVControllerRotationCapsule ⇏ VaultBalance
```

### 4.3 Capsule Encryption — **[Divergent — shipped authoritative]**

Both capsule types use a 256-bit AEAD (XChaCha20-Poly1305). The shipped device capsule
binds the AAD/nonce/challenge as follows (authoritative):

```
# capsule.rs:117  build_capsule_aad
AD = "DSM/recovery-capsule-v3\0" || smt_root || u64le(counter)

# capsule.rs:496  derive_nonce
N  = BLAKE3("DSM/recovery-nonce" || u64le(counter) || rollup_hash)[0..24]

# capsule.rs:505  derive_challenge
challenge = BLAKE3("DSM/recovery-challenge" || rollup_hash || smt_root || u64le(counter))
```

Spec form (recorded, not adopted): `AD = "DSM/recovery-capsule-v3\0" || G || X || R ||
u64le(c)`, `N = BLAKE3("DSM/recovery-nonce\0" || u64le(c) || R)[0..24]`, `challenge =
BLAKE3("DSM/recovery-challenge\0" || G || X || R || u64le(c))`, where `X = DevID_old`
(device capsule) or `vault_id` (rotation capsule) and `R` is a per-capsule binding value.

Nonce-uniqueness: the shipped construction binds `counter` (the strictly increasing
capsule index) and `rollup_hash` (per-capsule), so `N` is never reused under a given
`K_R` — the mandatory stream-cipher property holds today. The shipped challenge binds
the capsule to `(rollup_hash, smt_root, counter)` rather than `(G, X, R, c)`; it serves
the same self-binding purpose. AEAD tamper, counter tamper, and `smt_root` (AAD) tamper
are all tested (`capsule.rs` tests `test_*_tamper_fails`). **[A — these protections ship.]**

> No migration to the `G‖X‖R‖c` form is adopted here.

---

## 5. Capsule Currency

### 5.1 Capsule Advances With Accepted State — **[B]**

A Device Continuity Capsule is a post-state recovery checkpoint, not a periodic backup.
The requirement is:

```
∀n: Accept(S_{n-1} → S_n) ⇒ ∃C_n: CapsuleCommitsTo(C_n, S_n)
```

with `C_n` committing the post-transition frontier (updated relationship tip, Per-Device
SMT root, receipt-roll accumulator, contact-set commitment, capsule index, latest receipt
digest, and all known relationship tips), and a strictly increasing capsule index.

**Shipped reality:** the capsule is sealed only via `recovery.enable` and the manual
`recovery.createCapsule` route (`recovery_routes.rs:194`); the `counter`/`logical_time`
index is supplied by the caller, not driven by accepted-state count. There is **no
accept-time re-seal hook**. (Gap §0.2.1.)

### 5.2 Capsule Dirty State — **[B]**

```
CapsuleCurrent ⟺ capsule_index == accepted_state_index
CapsuleDirty   = ¬CapsuleCurrent
```

A dirty capsule means the exported artifact does not represent the latest accepted
frontier, and the wallet MUST surface this. **Not tracked today.** (Gap §0.2.2.)

### 5.3 Mandatory Sealing of Contact Establishment — **[B]**

> **Invariant 1 (Mandatory Contact Sealing).** No relationship may carry a value-bearing
> transition until the transition that established the contact has been sealed into the
> device continuity capsule. The capsule contact set therefore contains every
> counterparty with which the device can conduct value-bearing transitions.

```
FirstValueTransition(A↔B) ⇒ B ∈ contact_set_commit(C_latest_sealed)
```

This is the load-bearing guarantee that the recovery gate-set is complete. **Not enforced
today** (capsule sealing is decoupled from contact establishment; there is no
`contact_set_commit`). (Gaps §0.2.3, §0.2.4.)

### 5.4 Capsule as Recovery Anchor — **[A storage / B enforcement]**

The capsule tip is the recovering device's **own** sealed view of each relationship.
For `A↔B` the capsule stores the anti-rollback floor `h^cap_{A↔B}`. During recovery,
counterparty `B` must either report the same tip or supply a valid forward adjacent
receipt chain from the floor to `B`'s latest accepted tip.

> **Self-tip invariant (explicit, per direction).** Recovery anchors on the **owner's
> own** sealed floor — `per_device_smt_root` + per-relationship `counterparty_tips` +
> `rollup_hash` (+ cert heads) — **not** on the counterparty's reported tip. "The other
> party has the latest tip" is **insufficient**: a counterparty could under-report
> (rollback) or the owner could be presented stale relationship state. The owner's
> sealed self-tip is the rollback floor; a counterparty's report may only **confirm** it
> or **extend forward** from it with a valid co-signed receipt-adjacent chain. Storage
> of this floor is **[A]**; the recovery-time enforcement check is **[B]** (Gap §0.2.5).
> Because the floor is only trustworthy if it is fresh, capsules MUST advance on **every
> accepted state transition** (§5.1, Gap §0.2.1) — otherwise recovery could restore from
> stale, gameable relationship state.

### 5.5 High-Value Synchronous Sealing — **[B]**

Beyond mandatory contact-establishment sealing, high-value/treasury-linked devices SHOULD
enforce full synchronous sealing: a new value-bearing transition MUST NOT begin while
`CapsuleDirty = true`. This is a recoverability strengthening on top of Invariant 1, not
a precondition of the no-double-spend guarantee (which depends only on contact-establishment
sealing + capsule currency).

> **Capsule currency ⇒ complete gate-set.** The latest sealed capsule commits to every
> relationship that may carry value; the recovery activation seal is computed over exactly
> that committed contact set. The no-double-spend guarantee reduces to capsule currency +
> all-contact acknowledgement, with no external availability source. **This reduction is
> only as strong as §5.1/§5.3, which are Layer B today.**

---

## 6. Device Continuity Recovery

### 6.1 Device Recovery Is Contact Migration — **[A concept / B completion gate]**

A live device is a bilateral relationship endpoint. Decrypting a capsule does not
complete recovery:

```
Mnemonic + DeviceContinuityCapsule ≠ RecoveredDevice
ActiveDeviceRecovery = AllContactTombstoneSync
```

Recovery completes only after every gate-set counterparty has automatically synchronized
the tombstone and rebound its relationship to the successor. **The all-contact gate as a
hard spend precondition is [B].**

### 6.2 No Manual Permission — **[A — design]**

Recovery is not a permission process. A contact device automatically processes a valid
mnemonic-authorized tombstone during normal sync; it synchronizes to a valid protocol
state rather than granting permission.

### 6.3 Recovery State Machine — **[Divergent — shipped authoritative]**

Spec enum: `NONE, CAPSULE_DECRYPTED, RECOVERY_INTENT_CREATED, TOMBSTONE_PROPOSAL_PUBLISHED,
AWAITING_CONTACT_SYNC, FULLY_SYNCED, ACTIVATED, FAILED`.

Shipped: untyped string phases `tombstoning → succession → propagating → polling →
resuming → complete` (`recovery_impl.rs:480,515,564,594,617,650`; read via
`recovery.phase`, `recovery_routes.rs:86`). Same lifecycle, no typed enum. (Gap §0.2.6.)

While awaiting contact sync, the successor MAY fetch storage mirrors, discover contacts,
publish recovery intent, receive acks, verify missing receipts, and update its candidate
frontier; it MUST NOT perform value-bearing transitions, spend recovered funds, accept
new token-affecting transitions as active successor, finalize succession, or claim final
recovery. **(Spend lock during recovery is the intended gate; the strict all-contact form
is [B].)**

### 6.4 Contact Discovery — **[A locate / B gate-set definition]**

The successor discovers the old device's contact set from the decrypted capsule,
storage-mirrored contact anchors and b0x/contact routing surfaces, content-addressed
contact objects under the old genesis, and recovered local contact roots. **Discovery
locates counterparties; it does not define the gate-set.** The authoritative gate-set is
the latest sealed capsule's `contact_set_commit` (**[B]**). A discovered-but-uncommitted
counterparty is never added to the gate-set; a committed-but-unlocated counterparty keeps
the gate closed until located and synchronized.

### 6.5 Recovery Intent — **[B]**

`RecoveryIntentV3 { genesis_id, old_device_id, candidate_new_device_id, capsule_index,
capsule_digest, contact_set_commit, recovery_nonce, new_device_signature }`. Its
`contact_set_commit` MUST equal the referenced capsule's. Announces a candidate
replacement; does not tombstone or activate. **Not present in code.**

### 6.6 Mnemonic-Authorized Tombstone Proposal — **[B message / A underlying receipt]**

Spec `RecoveryTombstoneProposalV3 { genesis_id, old_device_id, new_device_id,
recovery_intent_digest, contact_set_commit, recovery_authority_proof,
new_device_signature }`, valid iff: recovery-authority proof verifies; `old_device_id`
active under `G`; `new_device_id` fresh; references a valid Recovery Intent;
`contact_set_commit` matches the capsule; new-device signature verifies; deterministic
encoding + domain-separated hashing hold.

Shipped: the **tombstone receipt itself** is **[A]** (`tombstone.rs:31` `TombstoneReceipt
{ device_id, old_smt_root, old_counter, old_rollup_hash, tick, signature, tombstone_hash }`;
proto `RecoveryTombstoneRequest/Response`, `TombstoneReceiptProto`), and so is succession
(`tombstone.rs:50` `SuccessionReceipt`, proto `RecoverySuccession*`). The **proposal
wrapper with intent + `contact_set_commit`** is **[B]**.

### 6.7 Automatic Contact Tombstone Processing & Posted Evidence — **[A logic / B flow]**

During sync each contact checks for recovery tombstone proposals for known contacts,
verifies the tombstone/succession pair under the **genesis-anchored** recovery
authority (§0.5.1.2), marks the old device tombstoned for the relationship, and
**establishes a new bilateral `(A_new,C)` relationship** whose first accepted state
carries forward the old frontier (§0.5.1.1). There is **no standalone signed-ack
object** (the `ContactTombstoneAckV3` model is superseded): C's recognition IS its own
online-posted, genesis-authenticated relationship state, which a verifier fetches and
checks client-side. Automatic; no user approval. The cross-relationship evidence
verifier (`CrossRelationshipSuccessionEvidence`) is **[A]**; the posting/sync flow and
the string-phase `propagating`/`polling` stand-in (`recovery_impl.rs`) are **[B]**.

**Relationship freshness.** C's evidence is valid only if its current `(A_old,C)` tip is
a valid **forward descendant** of the capsule floor — `h^cap ⟶* T_old_current` (hash
adjacency / parent consumption, **no numeric height**); the new `(A_new,C)` receipt is a
normal bilateral stitched receipt co-signed by both endpoints. Any tip not a forward
descendant of the floor is rejected. **[A] (`verify_forward_ancestry`).**

### 6.8 Recovery Activation Seal — **[A logic / B flow]**

`RecoveryActivationSeal { genesis_id, old_device_id, new_device_id,
recovery_intent_digest, tombstone_proposal_digest, contact_set_commit, evidence_root,
synced_contact_count, final_per_device_smt_root, final_receipt_roll }`
(`recovery/activation.rs`), valid iff: `synced_contact_count` equals the gate-set size;
`contact_set_commit` equals the gate-set commitment; the per-counterparty evidence set
equals the gate-set EXACTLY (no omission/substitution/duplicate); each evidence binds
the old→new device under recovery and verifies the cross-relationship succession
(§0.5.1.1) under the genesis-anchored authority (§0.5.1.2); and `evidence_root` commits
exactly the verified outcomes. **Seal validation logic is [A] (`validate_recovery_activation`,
unit-tested); the online-posted gate-set, evidence collection, and proto wire are [B].**

### 6.9 Activation Rule — **[A intent / B mechanism]**

```
ValidSuccession ⇒ ValidRecoveryActivationSeal
¬SpendAuthority(DevID_new)   until the seal exists
```

The successor becomes active only after a valid activation seal exists. The **spend lock
until recovery completes** is the shipped intent (string-phase gating); the **activation
seal as the precise unlock condition** is **[B]**.

### 6.10 No Double-Spend Window — **[B — depends on §5/§6 Layer-B mechanisms]**

The successor cannot spend while any gate-set member still accepts the old device,
preventing split acceptance.

> **Theorem (All-Contact Tombstone Sync Prevents Recovery Double Spend).** Assuming
> BLAKE3-256 collision resistance and SPHINCS+ unforgeability, **and** Invariant 1 +
> capsule currency: if the successor cannot perform value-bearing transitions until every
> gate-set member's own posted, genesis-authenticated state proves the cross-relationship
> succession (§0.5.1.1) under the genesis-anchored authority (§0.5.1.2), recovery cannot
> create a double-spend window between old and new devices. *Status: conditional — the
> seal/evidence/authority verifiers are [A] (§0.5.1); the online-posted gate-set and
> evidence-collection flow it rests on (§5.1, §5.3, §6.7, §6.8) are Layer B. The
> cryptographic premises (BLAKE3, SPHINCS+) are [A].*

---

## 7. Deterministic Limbo Vaults

### 7.1 DLV Meaning — **[A]**

Value is suspended under protocol math, not controlled by a middleman, validator,
sequencer, creator backdoor, or storage node:

```
DLVAuthority = CommittedCondition
ValidRelease ⟺ PolicyPredicateSatisfied
```

A DLV can express swap, escrow, AMM, treasury, release, and recovery behavior, but it is
not a global-VM smart contract. (`vault/limbo_vault.rs`, `vault/dlv_manager.rs`.)

### 7.2 DLV Is Not a Smart Contract — **[A — design]**

Unlike a blockchain smart contract (global address, shared VM execution, validators/
sequencers, gas, global ordering, mempool exposure, admin/upgrade access, reentrancy/
loop bugs), a DLV is precommitted, deterministic, bounded, policy-anchored, proof-carrying,
locally verifiable, middleman-free, and signer-free after creation unless a signer is
explicitly part of the committed policy.

### 7.3 No Middleman / Storage Is Not Authority — **[A]**

A DLV has no discretionary operator, no creator backdoor (unless the policy explicitly
commits one — SHOULD NOT for sovereign vaults), no storage-node authority, no validator
executor, no sequencer. DLV state may be mirrored through storage for availability; a
verifier accepts DLV state only if the vault id matches, the referenced existing token
policies match, the DLV policy commitment matches, the state extends the accepted parent
tip, the transition satisfies the policy, all proofs verify, and deterministic encoding
holds. (`dlv/vault_state_anchor.rs`, `dlv/vault_smt_leaf.rs`.)

```
Storage = Availability     Verification = Authority
```

Storage withholding is a liveness effect (delay), never a safety effect (rollback). **[A]**.

---

## 8. DLV Use of Existing Token Policies

### 8.1 Token Policies Exist Separately — **[A]**

Token policies exist independently of DLVs. A DLV does not create, modify, rename,
replace, or define a new token universe; it only commits to which **already-existing**
token policies it may interact with. (`TokenPolicyV3`, `PolicyAnchorV3`; core `cpta/`;
`token-policy-readiness.instructions.md`.)

### 8.2 Token Policies Referenced by the DLV — **[A concept / Divergent shape]**

At DLV creation, every token policy the DLV may accept/hold/reserve/route/release/refund/
burn/swap MUST already exist as an anchored token-policy object, and the DLV creation
object MUST reference them.

- **Shipped:** `LimboVaultProto.policy_digest` (field 15) anchors a CPTA policy to the
  vault; vault creation flows through `DlvSpecV1` / `DlvInstantiateV1` / `DlvCreate`.
- **Spec shape (recorded):** `DLVCreateV3 { vault_id, creator_device_id, dlv_policy_digest,
  repeated TokenPolicyRefV3 token_policies, route_table_commit, predicate_commit,
  recovery_commit }` and `TokenPolicyRefV3 { token_genesis, policy_anchor_digest,
  policy_commit, policy_bytes_digest }`.

Reconciliation: the **principle** (DLV references existing token policies, validity
requires the canonical policy bytes to hash to the committed digest) is **[A]**. The
**multi-policy `repeated TokenPolicyRefV3` set + `route_table_commit`/`predicate_commit`/
`recovery_commit` envelope** is **[B / Divergent]**: today a vault anchors a single CPTA
via `policy_digest`. **Any implementation MUST map onto the existing CPTA objects
(`TokenPolicyV3`/`PolicyAnchorV3`) — it MUST NOT introduce a parallel token-policy
type.**

### 8.3 No Token Policy Creation by DLV — **[A]**

```
TokenPolicy(T) ∉ DLVCreate.token_policies ⇒ T cannot be used by that DLV
```

A DLV MUST NOT create/modify token policies, and MUST NOT accept a token policy not
referenced at creation.

> **Hard token-policy invariant.** Token policies are independent objects. A DLV only
> operates over existing token policies explicitly referenced at creation; it does not
> create, import-later, modify, or replace them.

---

## 9. DLV Controller Recovery — **[B]**

### 9.1 DLV Recovery Is Not Balance Recovery

```
DLVRecovery = ControllerRotation ≠ BalanceRestore
```

A DLV recovery MUST NOT restore a historical balance or roll back vault state; it MAY only
rotate the recovery/controller access path. The current balance is whatever the latest
verifiable DLV state says. **No controller-rotation path exists in code today.**

### 9.2 DLV State Split — **[B]**

Spec `DLVStateV3 { vault_id, dlv_policy_digest, parent_tip, value_state_commit,
controller_devid, recovery_commit, transition_digest }` separates value state from
controller authority. Shipped vault state (`VaultStateProto`, `VaultStateAnchorV1`) tracks
value/reserves but has **no `controller_devid`**. (Gap §0.2.8.)

### 9.3 Controller Rotation — **[B]**

`DLVControllerRotationV3 { vault_id, dlv_policy_digest, parent_vault_tip, child_vault_tip,
old_controller_devid, new_controller_devid, recovery_authority_proof,
latest_value_state_commit, rotation_nonce }`, valid iff: latest DLV state fetched + verified
by hash adjacency and policy; it extends the accepted parent tip and is the longest
verifiable forward chain known; `old_controller_devid` matches the active controller;
recovery-authority proof verifies; `new_controller_devid` fresh + silicon-bound;
`latest_value_state_commit` equals the latest verified value commitment; the child
preserves the value commitment (unless policy authorizes otherwise); child tip derived from
canonical child state; deterministic encoding holds. A storage node serving stale-but-valid
earlier state cannot cause rollback (a verifier holding a newer tip rejects a rotation whose
parent is not current). **Not present in code.**

> **Theorem (DLV Recovery Does Not Restore Balance).** If a controller rotation preserves
> the latest verified value commitment, controller recovery cannot roll back or alter the
> balance. *Status: [B] — depends on §9.2/§9.3.*

---

## 10. DLV Interaction and Swap Semantics

### 10.1 The DLV Is the Counterparty of Record — **[A]**

```
Trader ↔ DLV        (not  Trader ↔ OwnerDevice)
```

Traders interact with the DLV policy surface, not the owner's personal device, so they do
not become recovery-blocking contacts and do not enter the owner device's capsule contact
set. (SoFi vaults are addressed/discovered independently of the owner's device contacts.)

### 10.2 Owner Control vs Public Interaction Surface — **[A design / B formal link]**

A DLV has a public interaction surface (vault id, DLV policy commitment, referenced token
policies, transition rules) and a narrow owner control surface (controller/recovery
authority). The public surface may have many users; the owner surface SHOULD remain narrow.
The guarantee that public users never enter the owner recovery gate-set is formal once the
gate-set (§6) is enforced (**[B]**).

### 10.3 DLV Swap Transition & Output Routing — **[A function / Divergent shape]**

Spec `DLVSwapTransitionV3` (input/output token genesis + policy commit + amounts, trader
signature, policy proof, proceeds route) and `DLVRouteKind { ROUTE_COUNTERPARTY,
ROUTE_OWNER_RECEIVE_TARGET, ROUTE_DLV_RESERVE, ROUTE_TREASURY_DLV, ROUTE_BURN,
ROUTE_REFUND_SOURCE, ROUTE_POLICY_COMMITTED_TARGET }` and `OwnerReceiveTargetV3` describe
swap + routing.

Shipped: equivalent **function** exists via the SoFi pipeline — `RouteCommitV1` /
`RouteCommitHopV1` (signed by the trader, verified by the unlock gate), constant-product
`AmmConstantProduct` fulfillment, external commitments, `DlvUnlockRoutedV1`
(`sdk/route_commit_sdk.rs`, `sdk/routing_path_sdk.rs`, `sdk/amm_demo.rs`,
`handlers/route_routes.rs`). A swap is well-formed only if both token policies are
existing policies referenced by the vault. The **explicit `DLVSwapTransitionV3` message +
`DLVRouteKind` enum + `OwnerReceiveTargetV3`** are a **different shape** over already-shipped
functionality; routing kinds like treasury/owner-receive/burn are **[B]** as first-class
enumerated routes. The route is part of policy + transition proof, never chosen by storage
or improvised by the owner at execution time. **[A — principle.]**

Sale/limit-order, AMM/reserve, and custody/redundancy DLV patterns (§ of the source doc)
are expressible today via SoFi vault configurations; the owner need not be online for a
swap and later ingests/verifies the receipt. **[A].**

### 10.4 No Public Fanout Into Owner Recovery — **[A design / B formal link]**

```
Trader ∈ DLVInteractionSet ⇏ Trader ∈ OwnerRecoveryContactSet
```

DLV interaction fanout does not expand the owner recovery gate-set; formal once §6 lands.

---

## 11. High-Liquidity Operational Guidance — **[A — advisory]**

- Keep high-contact devices low on hot liquidity; place substantial liquidity into DLVs.
- Public users interact directly with DLV policy surfaces; proceeds route per policy.
- Recover DLVs by controller rotation (§9), not hot-wallet balance recovery.
- Unsafe profile: one device, many contacts, large hot balance, direct spend authority over
  all funds — large recovery synchronization surface.

```
High-contact devices should carry low hot liquidity.
High-liquidity DLVs should have narrow controller recovery surfaces.
```

The strict all-contact gate (§6) guarantees no double-spend; keeping value in DLVs bounds
the gate's liveness cost (a stranded gate-set member can only hold up the thin hot balance).

---

## 12. Security Theorems — status summary

| Theorem | Premises | Status |
| --- | --- | --- |
| Capsule-Anchored Gate Completeness | Invariant 1 + capsule currency | **B** (premises §5.1/§5.3 not enforced) |
| Device Recovery Requires Graph Migration | spend-lock until all-contact ack | **B** (strict gate not enforced) |
| No Split-Recovery Double Spend | SPHINCS+ + BLAKE3 + Invariant 1 + currency | **B** (crypto premises [A]; gate [B]) |
| DLV Controller Recovery Does Not Restore Balance | controller rotation preserves value commit | **B** (no rotation yet) |
| DLV Users Do Not Become Owner Recovery Contacts | counterparty-of-record is the DLV | **A design / B formal** |

---

## 13. Cross-Reference Appendix — spec message ↔ shipped artifact

| Spec object | Shipped artifact (proto / code) | Status |
| --- | --- | --- |
| `DeviceContinuityCapsulePlaintextV3` | `RecoveryCapsule` (`capsule.rs:55`, `RCV3` binary) | A (binary) / Divergent (framing) + B (new fields) |
| `DLVControllerRotationCapsulePlaintextV3` | — | B |
| `RecoveryIntentV3` | — | B |
| `RecoveryTombstoneProposalV3` | `RecoveryTombstoneRequest/Response`, `TombstoneReceiptProto`, `tombstone.rs:31` | B (proposal) / A (receipt) |
| `ContactTombstoneAckV3` | superseded by §0.5 posted-state model — `CrossRelationshipSuccessionEvidence` (`succession_binding.rs`) | A (logic) / B (flow) |
| Cross-relationship succession evidence | `CrossRelationshipSuccessionEvidence` (`succession_binding.rs`) | A (logic) / B (transport) |
| Genesis-anchored recovery authority | `RecoveryAuthorityAnchor` (`authority_anchor.rs`) | A (logic) / B (bind-once + transport) |
| `RecoveryActivationSealV3` | `RecoveryActivationSeal` (`activation.rs`, `evidence_root`) | A (logic) / B (proto wire) |
| `RecoveryState` enum | string phases (`recovery_impl.rs`) | Divergent |
| Succession | `RecoverySuccession*`, `SuccessionReceipt` (`tombstone.rs:50`) | A |
| `DLVCreateV3` / `TokenPolicyRefV3` | `DlvCreate`, `DlvSpecV1`, `DlvInstantiateV1`, `LimboVaultProto.policy_digest`, `TokenPolicyV3`, `PolicyAnchorV3` | A (concept) / Divergent (shape) |
| `DLVStateV3` | `VaultStateProto`, `VaultStateAnchorV1` (no controller field) | B (controller split) |
| `DLVControllerRotationV3` | — | B |
| `DLVSwapTransitionV3` / `DLVRouteKind` / `OwnerReceiveTargetV3` | `RouteCommitV1`/`RouteCommitHopV1`, `AmmConstantProduct`, `DlvUnlockRoutedV1` | A (function) / Divergent (shape) |

---

## 14. Summary

```
DeviceRecovery = Mnemonic_24 + CurrentCapsule + AutomaticContactTombstoneSync + RecoveryActivationSeal
DLVRecovery    = Mnemonic_24 + DLVControllerRotationCapsule + LatestVerifiedDLVState + ControllerRotationTransition
```

Device recovery migrates a relationship endpoint; DLV recovery rotates a controller. The
device continuity capsule advances with every accepted state (so its contact set is always
complete for value-bearing relationships); the activation seal is computed over exactly that
committed gate-set; every member must acknowledge before the successor can spend; each ack
may only confirm or extend forward from the capsule's anti-rollback floor. The no-double-spend
guarantee then holds structurally with no external availability source.

**Shipped today:** the capsule already seals the owner's own frontier (SMT root +
per-relationship tips + rollup + cert heads), tombstone/succession receipts, the recovery
lifecycle (as string phases), and the full DLV + SoFi swap/routing + CPTA token-policy
stack. **Planned (Layer B):** capsule currency on every accepted transition + dirty-state
surfacing, mandatory contact sealing, `contact_set_commit`/gate-set, anti-rollback-floor
enforcement, the typed `RecoveryState` enum, the intent/proposal/ack/activation-seal
messages, and the DLV value/controller split + controller rotation. See §0.2.

A DLV-mediated swap is performed against the DLV, not the owner device, and never expands
the owner's recovery gate-set. A DLV does not create token policies; it only operates over
existing token policies explicitly referenced at creation. DLV outputs route per committed
policy. Storage provides availability, not authority. A DLV remains sovereign because value
is suspended under deterministic protocol math.
