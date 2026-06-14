---
applyTo: '**'
---

# DSM Recovery, NFC Ring Backup, and Deterministic Limbo Vault Specification

Brandon "Cryptskii" Ramsay — Inventor of DSM (Deterministic State Machine)

June 10, 2026 — Revision 2.0 (reconciled spec ↔ code; honest-status taxonomy)

## Abstract

This document specifies DSM recovery, the NFC ring backup transport for the device
continuity capsule, and Deterministic Limbo Vault (DLV) behavior. It distinguishes
live device recovery from DLV controller recovery. Live device recovery requires
mnemonic-authorized tombstone publication followed by automatic synchronization across
the device's complete committed contact set before recovered funds become spendable.
Completeness of that set is guaranteed structurally: the device continuity capsule
advances with every accepted state transition, a counterparty cannot carry value until
it has been sealed into the capsule's contact set, and the capsule tip is an
anti-rollback floor that a counterparty may only confirm or extend forward. As a result,
the no-double-spend guarantee reduces to capsule currency plus all-contact
acknowledgement and depends on no external availability source. DLV recovery is
different: it does not recover balances or roll back vault state. It only rotates
controller or recovery access against the latest verifiable DLV state. The DLV remains a
sovereign deterministic vault: value is suspended under committed protocol math, not
controlled by a middleman, validator, creator backdoor, or discretionary signer. Token
policies remain independent objects. A DLV only operates over existing token policies
explicitly referenced when the DLV is created.

> **This is a reconciled specification.** Every normative section carries a status tag
> describing its relationship to the shipped implementation. Where the spec and the code
> diverge, **the shipped code is authoritative** unless this document names an explicit
> required migration. This revision adds no code; it classifies the design surface and
> flags implementation status honestly (see §0).

---

## Status Legend

Every normative clause carries one status. The vocabulary is deliberate: **"done" /
"shipped" is never used loosely.** A feature is only **Shipped & Enforced** when it is
implemented in code, reachable through the intended production path, tested against its
invariants, documented to match the code, **and** not merely fail-closed behind an
activation gate.

- **[S1 — Shipped & Enforced]** — Implemented, reachable in production, tested, and
  actively enforced live. The cited file/line or proto implements it and a production
  path exercises it.
- **[S2 — Implemented, Activation-Gated]** — The code, types, proto, storage, and safety
  logic exist and are unit-tested, but the final unlock / controller / activation path is
  **intentionally fail-closed** and NOT reachable in production. Inert by design, pending
  an audited go-live. *This is correct, not a defect — but it MUST NOT be described as
  live.*
- **[S3 — Partially Implemented]** — Some pieces exist (often a tested pure core), but the
  production path is incomplete: orchestration, wiring, SDK apply, or a transport message
  is still missing.
- **[S4 — Specified, Not Implemented]** — Exists only in this document. No code or proto.
- **(shipped-divergent)** — an orthogonal note on an S1 item: the code is live and
  enforced, but its **shape** differs from how this document's alternative form describes
  it. The **shipped form governs**; the alternative is recorded for reference and is not
  adopted unless a migration is explicitly named.

> **Anti-overclaim rule (MANDATORY for this and sibling specs).** Never collapse
> "implemented but gated" into "done." If the structures exist but the final unlock /
> controller path is intentionally fail-closed, write **S2 — implemented,
> activation-gated**, never S1. If a pure core exists but its production path is missing,
> write **S3 — partially implemented**. If it lives only in the spec, write **S4 —
> specified, not implemented**. The specs MUST NOT imply activation-gated behavior is
> live.

Code anchors are relative to `dsm_client/deterministic_state_machine/` unless noted.
Core Rust is under `dsm/src/`, the SDK under `dsm_sdk/src/`, the storage node under
`dsm_storage_node/src/`. Proto anchors are in `proto/dsm_app.proto`. Android/Kotlin and
frontend/TypeScript anchors are under `dsm_client/android/` and `dsm_client/frontend/`.

---

## 0. Reconciliation Summary

### 0.1 What is shipped, gated, partial, or planned — at a glance

| Area | Status | Anchor |
| --- | --- | --- |
| Recovery mnemonic — 256-bit / 24-word generation | **S1** | `recovery_sdk.rs:259` (`generate_mnemonic`, `bip39::from_entropy`, 32-byte entropy) |
| Recovery mnemonic — reject < 24-word as mainnet authority | **S1** | 24-word floor at `recovery.enable` (`recovery_routes.rs:117`) and `recovery.cacheMnemonic` (`:225`) |
| Recovery key derivation (Argon2id → BLAKE3) | **S1 (shipped-divergent)** | `capsule.rs:295` uses salt `DSM/recovery-ring\0` + BLAKE3 `derive_key("DSM/recovery-aead\0")`, not the whitepaper's Argon2id+HKDF over `DSM/recovery-mnemonic\0` |
| Recovery authority seed (SPHINCS+) | **S1** | `capsule.rs:316` (`derive_recovery_authority_seed`, ctx `DSM/recovery-authority\0`) |
| Device Continuity Capsule — owner's own sealed frontier | **S1** | `RecoveryCapsule` (`capsule.rs:55`): `smt_root`, `counterparty_tips`, `rollup_hash`, `cert_chain_heads`, `last_certs` |
| Capsule wire framing (hand-rolled `RCV3`, not protobuf) | **S1 (shipped-divergent)** | `capsule.rs:22` magic `RCV3`; the whitepaper's `DeviceContinuityCapsulePlaintextV3` is a protobuf shape |
| Capsule `contact_set_commit` (v6 feature field) | **S1** | `capsule.rs:95`, domain-separated, validated on open (`capsule.rs:598`); unified with seal via `contact_set_commit_from_device_ids` (`capsule.rs:127`) |
| Capsule `*_root_hint` discovery hints | **S4** | absent from `RecoveryCapsule` |
| Capsule encryption AAD / nonce / challenge | **S1 (shipped-divergent)** | `capsule.rs:163/551/560` (see §4.3); shipped binds `smt_root`+`counter`/`rollup_hash`, not `G‖X‖R‖c` |
| Capsule currency — re-seal on every accepted transition | **S1** | atomic `accepted_state_index` bump in the commit tx (`core_sdk.rs:185/234`, `recovery::bump_accepted_state_index_with_conn`); re-seal + self-heal on egress |
| Capsule dirty/current tracking | **S1** | `accepted_state_index` / `capsule_state_index` / `is_capsule_dirty` (`client_db/recovery.rs:541/587/604`); surfaced on `recovery.status` (`recovery_routes.rs:27`) |
| NFC ring backup — capsule transport (write + read) | **S1** | Rust JNI (`jni/unified_protobuf_bridge.rs`, `jni/ble_events.rs`) + SDK (`recovery_sdk.rs`) + Kotlin (`ui/MainActivity.kt`) + TS (`dsm/nfc.ts`); routes `nfc.ring.write`/`nfc.ring.read` (§4.4) |
| Mandatory contact sealing (Invariant 1) | **S1 (as currency) / S3 (per-contact establishment seal)** | R2′ blocks egress while dirty; per-contact establishment-seal + non-shrinkable set pending |
| Tombstone + succession receipts (SPHINCS+) | **S1** | `recovery/tombstone.rs:31/50`; proto `RecoveryTombstoneRequest/Response`, `RecoverySuccessionRequest/Response`, `TombstoneReceiptProto`, `SuccessionReceiptProto` |
| Recovery lifecycle (typed `RecoveryState`) | **S1** | typed enum in `client_db/recovery.rs:345` (same on-disk strings as the prior phases) |
| Cross-relationship succession evidence + activation-seal **validation** | **S1** | `recovery/succession_binding.rs` (`CrossRelationshipSuccessionEvidence`), `recovery/activation.rs` (`validate_recovery_activation`, `compute_evidence_root`); proto `RecoveryActivationSealProto` |
| Recovery activation **unlock chokepoint** (the live freeze release) | **S2** | `RecoverySDK::verify_and_record_activation` (`recovery_sdk.rs:1704`) runs anchor-binding + seal validation, then **unconditionally returns a disabled error** (`:1751`); `set_recovered_successor(true)` only under `#[cfg(test)]` |
| Genesis-anchored recovery authority — anchor + storage bind-once | **S1** | `recovery/authority_anchor.rs` (`RecoveryAuthorityAnchor`); storage `recovery_authority_anchors` table + `PUT/GET /api/v2/recovery/authority-anchor/{genesis}` (first-write-wins / 409-on-conflict, sqlite+pg) |
| Recovery-authority **consumption** in activation | **S2** | binding runs at the chokepoint but the chokepoint is fail-closed (above) |
| Recovery floor check — hash forward-ancestry (not numeric height) | **S1** | `verify_forward_ancestry` (`succession_binding.rs:138`); acceptance uses hash adjacency / parent consumption, no heights |
| Recovery re-establish transport (bilateral BLE) | **S1 (wired) / S3 (on-device 2-device integration test)** | `begin_recovery_reestablish` / `verify_incoming_recovery_reestablish` (`recovery_sdk.rs:1384/1445`) wired into `bilateral_ble_handler.rs:1778/1925` via `is_recovery_establish_op`, reusing the 3-phase commit (no new BLE message types) |
| All-contact gate-set construction (R4 anti-shrink) | **S1 (building blocks) / S3 (live orchestration)** | core `gate_set::build_gate_set`, `pdsmt_posting`, storage `pdsmt_head_chain` + endpoints, SDK fetch/publish all exist; live fetch→verify→freeze→activation orchestration + publish-side head builder remain |
| Recovered-successor spend-freeze | **S1 (gate wiring) / S2 (live release)** | freeze reason in `value_egress_block_reason` is wired; release is gated behind the S2 unlock chokepoint |
| Fail-closed value-egress gate (exhaustive `Operation::is_value_egress`) | **S1** | `operations.rs:552`; wired at `core_sdk::execute_on_relationship` (`:848`) + `validate_transfer_request` (`:1545`); fail-closed on DB error, under-lock |
| Bearer-asset `LOCKED_RECOVERY` lock-state + per-asset egress block | **S1** | `recovery/bearer_lock.rs` (6 states), `recovery_locked_assets` registry, `asset_egress_block_reason` wired into the chokepoint |
| dBTC bearer-state reconciliation (posted ad → condition → SPV gate) | **S1 (logic + route + unit tests) / S3 (live Bitcoin UTXO/confirmation is integration-tested)** | `recovery/dbtc_reconcile.rs`, `dbtc_backing.rs`, `dbtc_vault_index.rs`; `BitcoinTapSdk::classify_dbtc_lifecycle/reconcile_dbtc_asset`; route `recovery.reconcileDbtc` |
| DLV object, "not a smart contract", storage = availability | **S1** | `vault/limbo_vault.rs`, `vault/dlv_manager.rs` |
| DLV references **existing** token policies (CPTA) — single `policy_digest` | **S1** | `LimboVaultProto.policy_digest` (field 15, `proto:754`) anchors a CPTA; `DlvSpecV1`/`DlvInstantiateV1`/`DlvCreate` |
| DLV multi-policy `repeated TokenPolicyRefV3` + route/predicate/recovery envelope | **S4** | absent; shipped DLV anchors a single CPTA digest |
| Token policies independent (DLV never creates/modifies) | **S1** | CPTA: `TokenPolicyV3`, `PolicyAnchorV3`; `cpta/`; `token-policy-readiness.instructions.md` |
| DLV swap + output routing (SoFi) | **S1 (shipped-divergent shape)** | `RouteCommitV1`/`RouteCommitHopV1` + `AmmConstantProduct` + `DlvUnlockRoutedV1` (`sdk/route_commit_sdk.rs`, `routing_path_sdk.rs`, `handlers/dlv_routes.rs`, `route.*` routes) |
| `DLVSwapTransitionV3` / `DLVRouteKind` / `OwnerReceiveTargetV3` message shapes | **S4** | absent; the function ships via the RouteCommit pipeline above |
| DLV value/controller state split (`DLVStateV3`, `controller_devid` on vault state) | **S4** | absent from persisted state (`VaultStateProto`, `VaultStateAnchorV1` have no controller field) |
| DLV controller rotation | **S3** | pure validator `dlv::controller_rotation::validate_controller_rotation` + 9 tests; **no proto, no SDK apply, no rotation capsule, no route** (zero external references) |
| No public fanout into owner recovery gate-set | **S1 (design) / S3 (formal link)** | holds once the live gate-set orchestration (§6) is enforced |

### 0.2 Status detail (honest taxonomy)

This register tracks the recovery double-spend hardening work and the DLV subsystem.
Statuses use the legend above. The headline distinctions this revision corrects:

1. Most items the previous revision marked "planned" are now **S1 — shipped & enforced**:
   the typed `RecoveryState` enum, `contact_set_commit`, capsule currency, the proto wire
   messages, storage-side bind-once + PDSMT head-chain + HTTP endpoints, and the bilateral
   BLE recovery re-establish path.
2. The **one** genuinely-inert piece is the **activation unlock chokepoint** (item 7),
   which is **S2 — implemented, activation-gated**: the anchor binding + seal validation
   run, then the chokepoint returns a disabled error by design. This is correct
   (fail-closed), not a defect — but it is **NOT live** and must never be described as such.
3. The **gate-set live orchestration** (item 13) is **S3 — partially implemented**: the
   wire/storage/core building blocks ship and are enforced server-side, but the live
   fetch→verify→freeze flow that feeds activation, plus the publish-side head builder and
   the recovery-bundle format, remain.

---

1. **S1 — Capsule currency on every accepted transition.** The `accepted_state_index`
   bump is folded ATOMICALLY into the state-commit transaction (`core_sdk.rs:185/234`,
   `recovery::bump_accepted_state_index_with_conn`, `client_db/recovery.rs:562`), so a
   frontier-changing transition can never persist without the capsule being marked dirty;
   best-effort re-seal + self-heal on egress. Refinement (S3): durable-write confirmation
   (NFC tag write-ack / storage-node publish ack → a `durable_capsule_index`).

2. **S1 — Capsule dirty/current surfacing.** `accepted_state_index` / `capsule_state_index`
   / `is_capsule_dirty` (`client_db/recovery.rs:541/587/604`); surfaced on `recovery.status`
   (`recovery_routes.rs:27`).

3. **S1 (currency) / S3 (per-contact establishment seal) — Mandatory contact sealing
   (Invariant 1).** Enforced as *currency*: R2′ blocks value egress while the capsule is
   dirty (`value_egress_block_reason`, `client_db/recovery.rs:435`, fail-closed). The
   per-contact establishment-seal + the non-shrinkable gate-set (public anchors) is S3
   (the building blocks ship; live wiring remains).

4. **S1 (capsule field) / S3 (non-shrinkable union) — `contact_set_commit` / gate-set.**
   Capsule v6 `contact_set_commit` is domain-separated and validated on open
   (`capsule.rs:95/598`), unified with the seal's byte-id commit
   (`contact_set_commit_from_device_ids`, `capsule.rs:127`). The non-shrinkable union
   (public anchors + storage enumeration, R4) is the gate-set orchestration in item 13.

5. **S1 — Anti-rollback floor enforcement.** Seal acks: confirm-floor-or-forward; below-floor
   rejected (`activation::validate_recovery_activation`). The floor predicate is **hash
   forward-ancestry** (`verify_forward_ancestry`, `succession_binding.rs:138`,
   `h^cap ⟶* T_old_current`), **not** a numeric height. Resume path:
   `resume_tip_diverges_from_floor` (fail-closed) + refuse-to-overwrite on chain-tip
   restore. (Full co-signed forward-chain proof for tips above the floor: S3.)

6. **S1 — Typed `RecoveryState` enum.** `client_db/recovery.rs:345` — variants `None,
   Tombstoning, Succession, Propagating, Polling, Resuming, Complete, Failed`; `as_str`/
   `from_bytes` keep the same on-disk lowercase strings (drop-in, no migration).

7. **S1 (validation + proto + transport) / S2 (live activation unlock) — Cross-relationship
   succession + activation seal.** *Validation logic and wire are shipped:*
   `CrossRelationshipSuccessionEvidence` (`succession_binding.rs:285`), `RecoveryActivationSeal`
   + `validate_recovery_activation` + `compute_evidence_root` (`activation.rs:49/64/166`) —
   set-equality over the gate-set (no omission/substitution/duplicate) + per-C
   device-binding + carry-forward + old-chain hash forward-ancestry + both-tip inclusion;
   proto `RecoveryActivationSealProto` (`proto:2773`) with `to_bytes`/`from_bytes`.
   *Recovery-authority trust-anchoring is shipped:* the genesis-chained declaration
   `RecoveryAuthorityAnchor` (`authority_anchor.rs`) commits `H(K_A_pub)`, is signed by the
   device genesis key and by `K_A`, and the activation chokepoint binds the candidate
   authority pubkey to the anchor BEFORE any verification (`recovery_sdk.rs:1721`) — no
   contacts-DB pubkey path remains. *Value-capable* gate-set criterion is shipped
   (`Operation::is_value_bearing`, `operations.rs:603`). *Bilateral re-establish transport
   is shipped and wired into BLE* (item 10). **The live activation unlock is S2:**
   `RecoverySDK::verify_and_record_activation` (`recovery_sdk.rs:1704`) performs the anchor
   binding + seal validation, then **unconditionally returns `Err(InvalidState("recovery
   activation recording disabled…"))`** (`:1751`); the recovered-successor freeze is wired
   into the egress gate but intentionally inert (`set_recovered_successor(true)` exists only
   under `#[cfg(test)]`). **Do NOT wire the freeze/unlock live until the online-posted
   gate-set orchestration (item 13) + anchor bind-once enforcement are complete and
   audited.**

8. **S3 — DLV value/controller split + controller rotation.** Pure validator
   `dlv::controller_rotation::validate_controller_rotation` (`dlv/controller_rotation.rs:162`)
   — parent==current tip, `value_state_commit` preserved, controller change,
   recovery-authority signature, canonical child tip (9 tests). **Not wired anywhere**:
   `controller_devid` is NOT a field on the persisted vault state (`LimboVaultProto`,
   `VaultStateProto`, `VaultStateAnchorV1`) — it exists only on the in-memory `DlvStateView`
   inside the validator; there is **no** `DLVControllerRotationV3` proto, no `dlv_sdk` apply
   path, no rotation capsule, no route. NOTE: rotation-nonce replay is bounded by the
   parent==current-tip check (a verifier holding the newer tip rejects a replay); an explicit
   nonce set would harden against storage-rewind.

9. **S1 — Reject < 24-word for mainnet.** 24-word (256-bit) floor at `recovery.enable`
   (`recovery_routes.rs:117`) and `recovery.cacheMnemonic` (`:225`), via
   `mnemonic.split_whitespace().count() < 24`.

10. **S1 (wired) / S3 (on-device two-device integration test) — Bilateral recovery
    re-establish transport.** A_new conveys the capsule floor `h_cap` in the
    recovery-establish op's `proof` (`build_recovery_establishment_op` /
    `recovery_establishment_floor`, `succession_binding.rs:74/114`); the pre-co-sign
    authorization is posted as a `RecoverySuccessionProof` (`recovery/succession_proof.rs:29`,
    proto `RecoverySuccessionProofV1`) and fetched by C; A_new initiates via
    `RecoverySDK::begin_recovery_reestablish` (`recovery_sdk.rs:1384`, carry-forward over
    C's REAL `(A_old,C)` frontier) and C gates co-signing on
    `verify_incoming_recovery_reestablish` (`:1445`) → the pure
    `verify_recovery_reestablish_request` (`succession_binding.rs:193`). Both sides are
    wired into the bilateral BLE handler — `initiate_recovery_reestablish` (A_new,
    `bilateral_ble_handler.rs:1778`) and an automatic accept-guard in `handle_prepare_request`
    (C, `:1925`), selected by the canonical `is_recovery_establish_op` marker — reusing the
    ordinary 3-phase commit (**no new BLE message types**). S3 remaining: the live two-device
    prepare→confirm integration test (requires a live BLE link).

11. **S1 — Fail-closed value-egress gate.** The canonical chokepoint via the exhaustive
    `Operation::is_value_egress` classifier (`operations.rs:552`, every variant classified)
    at `core_sdk::execute_on_relationship` (`:848`) + `validate_transfer_request` (`:1545`).
    The gate fails CLOSED on a DB read error and decides UNDER the state-machine lock (no
    check-before-lock TOCTOU), atomic with the commit + bump.

12. **S1 — Bearer-asset `LOCKED_RECOVERY` + per-asset spend-open chokepoint.** The capsule
    is a continuity hint, never a balance oracle. Generic safety layer:
    `BearerAssetLockState { LockedRecovery, Spendable, Reduced, InFlight, Finalized,
    RefundPending }` (`recovery/bearer_lock.rs:26`, fail-closed wire codec, `permits_egress`
    only on `Spendable`/`Reduced`) + `Operation::egress_asset` (exhaustive asset-id companion
    to `is_value_egress`, `operations.rs:621`) + the `recovery_locked_assets` registry
    (`client_db/recovery.rs:56`) + `asset_egress_block_reason` (`:1284`) wired into the
    `execute_on_relationship` chokepoint (checked AFTER the identity gate, persists per-asset
    past activation) + recovery-time locking in `lock_all_restored_bearer_assets` (`:1353`,
    fail-closed) + generic token reconciliation (`reconcile_token_asset`: `verified≥hint →
    Spendable`, `verified<hint → Reduced` capped).

    **dBTC bearer-state reconciliation — S1 (logic + route + unit tests) / S3 (live Bitcoin
    UTXO/confirmation, integration-tested on Bitcoin infra).** Posted-advertisement classifier
    + deterministic aggregator + fail-closed reconcile: `recovery/dbtc_reconcile.rs`
    (`DbtcVaultCondition`, `DbtcVaultOutcome`, `aggregate_dbtc_frontier` — checked arithmetic)
    + `BitcoinTapSdk::classify_dbtc_lifecycle` (posted `DbtcVaultAdvertisementV1.lifecycle_state`
    → condition; unknown → fail-closed) + `BitcoinTapSdk::reconcile_dbtc_asset` (fetch+verify
    each posted ad, aggregate, `set_asset_lock("dBTC", …, is_dbtc=true)`; any
    missing/malformed/unverifiable/unknown ad keeps dBTC `LockedRecovery`) + route
    `recovery.reconcileDbtc` (`recovery_routes.rs:984`). The generic path REFUSES dBTC
    (`MissingDbtcFrontierReplay`); dBTC unlocks only through this dedicated path, only for
    vaults whose Bitcoin backing proves it, never from capsule data. **Bitcoin SPV/UTXO gate**
    (`recovery/dbtc_backing.rs`, `BitcoinTapSdk::gather_dbtc_backing_facts`): the unsigned ad
    is trusted only to BLOCK; a vault becomes `Spendable` ONLY when live Bitcoin confirms the
    HTLC UTXO is unspent + confirmed AND the bearer can re-derive the claim preimage. Bitcoin
    unreachable → fail-closed (no unlock). **Authenticated vault enumeration**
    (`recovery/dbtc_vault_index.rs`, `PostedDbtcVaultIndex`, K_A-signed; proto
    `PostedDbtcVaultIndexV1`; empty → `MissingDbtcVaultEnumeration`, dBTC stays
    `LockedRecovery`).

13. **S1 (building blocks) / S3 (live orchestration) — Gate-set discovery (R4-critical).**
    The R4 rule (CONFIRMED): the recovery gate-set is **A_old's online-posted,
    genesis-authenticated, enumerable, value-capable Per-Device SMT leaf set at the recovery
    snapshot** — NOT the capsule hints, NOT the contacts DB, NOT the responder set, NOT a
    per-counterparty scan (those are *evidence* authority per member, never *enumeration*
    authority), and NOT a separate relationship-set object.

    **Dual keying (MANDATORY) — device for state location, genesis for authority.** The
    Per-Device SMT belongs to a specific device and `rel_key` is device-pair-derived
    (`H("DSM/smt-key\0" || min(DevID_A,DevID_C) || max(DevID_A,DevID_C))`), so the endpoint and
    records are **addressed/enumerated by `owner_device_id = A_old`** — NOT by genesis alone.
    But every signed head/leaf record MUST ALSO carry `genesis_id = G_A`, because recovery
    authority and anti-shrink trust are genesis-scoped. Rule: **device ID selects the PDSMT;
    genesis ID authenticates that the device/PDSMT belongs to G_A; the signature authority
    must chain back to `genesis_id`.** Do NOT replace `device_id` with `genesis_id`, and do
    NOT omit `genesis_id`.

    **R4 anti-shrink (CONFIRMED design — double-spend-critical).** A `K_A`-signed head proves
    *authenticity* but NOT *completeness*: the R4 adversary IS the spender (holds
    `A_old`/`K_A`), so it can sign a head whose value-capable leaf set OMITS a counterparty
    `C` — the recovery double-spend window. R4 is enforced by THREE combined layers:

    > **R4 INVARIANT.** *A recovery activation MUST NOT exclude any counterparty that can
    > prove, from its OWN genesis-authenticated posted state, that it had a value-capable
    > relationship with `A_old` at or before the recovery snapshot.*

    - **Layer 1 — append-once head chain.** `PostedPdsmtHead` commits `parent_head_hash` +
      `head_number`; storage enforces append-only (a new head's parent MUST equal the current
      head's hash) — no overwrite, no fork. The recovery snapshot uses the latest valid head
      at/before the tombstone.
    - **Layer 2 — completeness commitment.** The head commits BOTH `pd_smt_root` AND
      `leaf_index_root`; each leaf record commits `{rel_key, counterparty_device_id,
      current_tip, value_capable, value_capable_reason}` (via `committed_digest`).
      `value_capable` is committed/signed — NEVER server metadata.
    - **Layer 3 — counterparty-union backstop.** Any independently genesis-authenticated
      counterparty state proving an active value-capable `(C,A_old)` relationship forces `C`
      into the gate-set even if `A_old`'s head omitted it (C's OWN value-capable leaf for the
      shared symmetric `rel_key`, under C's OWN signed head).

    **Final gate-set rule.** `GateSet =` value-capable leaves from `A_old`'s latest valid
    append-only PDSMT head `∪` independently genesis-authenticated counterparty claims proving
    a value-capable relationship with `A_old`. Activation **fails closed** if any member of
    that union lacks valid `CrossRelationshipSuccessionEvidence`.

    **S1 — building blocks shipped + storage-enforced:**
    - Wire: protos `PostedPdsmtHeadV1` (`proto:2705`, with `parent_head_hash`/`head_number`,
      `ValueCapabilityV1` enum), `PostedPdsmtLeafRecordV1` (`proto:2741`), `PostedPdsmtLeafSetV1`
      (`proto:2756`).
    - Core: `recovery/pdsmt_posting.rs` — `PostedPdsmtHead` (signing digest + `verify` binding
      the signature to the committed authority pubkey, `is_genesis_head`), `PostedPdsmtLeafRecord`
      + per-leaf `committed_digest` + `verify_inclusion` (rel_key→tip under `pd_smt_root`,
      rel_key→`committed_digest` under `leaf_index_root`, both via
      `SparseMerkleTree::verify_proof_against_root`); 13 tests.
    - Layer 3: `recovery/gate_set.rs` — `build_gate_set` (A_old value-capable leaves ∪
      `CounterpartyValueWitness`) → frozen `gate_set_commit`; the omitted-counterparty
      anti-shrink path is unit-proven; 9 tests.
    - Storage (enforced server-side): `pdsmt_head_chain` table (sqlite+pg) +
      `insert_pdsmt_head_if_chained` (genesis/child append, idempotent replay, 409 on
      fork/gap/stale) + endpoints `PUT/GET /api/v2/tips/{device}/head-chain[/{n}]`.
    - SDK: `publish_pdsmt_head` / `fetch_pdsmt_head_latest` / `fetch_pdsmt_head_at`
      (`recovery_sdk.rs:561/588/598`).

    **S3 — remaining live orchestration:** the SDK orchestration that fetches A_old's latest
    valid head ≤ snapshot + leaves, fetches candidate counterparty witnesses, verifies each via
    `fetch_and_verify_authority_anchor` + device-tree quorum, calls `build_gate_set`, and freezes
    the result into the activation seal; the **publish-side head builder** (enumerate THIS
    device's PDSMT leaves, classify `value_capable` by walking each relationship's history with
    `is_value_bearing`, build the `leaf_index` SparseMerkleTree, generate proofs, sign +
    `publish_pdsmt_head`); the **recovery bundle** format (carries `K_A_pub` + tombstone +
    succession + per-C evidence). Gate-set construction + the unlock (item 7) stay fail-closed
    until these land + adversarial review (go-live is a separate audited step).

14. **S1 — Recovery-authority anchor lifecycle.** Create (`RecoverySDK::build_authority_anchor`,
    `recovery_sdk.rs:385`, device key re-derived via `init::derive_device_signing_keypair`) →
    publish to the dedicated bind-once endpoint (`publish_authority_anchor`, `:457`,
    offline-first trigger on `recovery.enable`) → **server bind-once per genesis**
    (`recovery_authority_anchors` table + `PUT/GET /api/v2/recovery/authority-anchor/{genesis}`,
    first-write-wins / idempotent-identical / 409-on-conflict, both sqlite+pg, Postgres
    `FOR UPDATE` row-lock) → **quorum-authenticated fetch+verify** (`fetch_and_verify_authority_anchor`,
    `:507`, composing the device-tree quorum signing pubkey + `anchor.verify`). All fail-closed.
    The *consuming* side (the activation chokepoint) is the S2 item 7.

### 0.3 Sibling-spec overlap (cross-reference, not rewritten here)

- `whitepaper.instructions.md` — recovery ring, capsule AAD (§13/§16.10), cert chains (§11.1).
- `sofi.instructions.md`, `sofispecs.instructions.md` — DLV, swap, routing, storage-as-availability (SoFi paper + implementation blueprint).
- `token-policy-readiness.instructions.md` — token-policy independence (CPTA).

> **Consolidation note (this revision).** The NFC ring backup transport — previously a
> mis-pasted duplicate of the SoFi paper under the filename `nfcringbackup.instructions.md`
> — is now specified here in **§4.4** (NFC transports the device continuity capsule defined
> in §4.1). The duplicated SoFi text was dropped (the canonical copy remains in
> `sofi.instructions.md`), and `nfcringbackup.instructions.md` was removed.

Contradictions found during reconciliation are recorded as status-detail entries above;
sibling specs are **not** rewritten in this pass.

### 0.4 Hardened double-spend doctrine (authoritative)

The recovery design rests on a **two-gate model**. Conflating these two gates is the
historical source of double-spend risk:

1. **Identity recovery** answers "is `A_new` the valid successor to `A_old`?" — the
   mnemonic-authorized tombstone + all-contact activation seal (§6).
2. **Bearer-asset reconciliation** answers, per asset, "what value is still spendable under
   the latest verified asset frontier?" (§5 LOCKED_RECOVERY).

> **A recovery capsule is NOT a balance oracle.** It is a continuity object that helps the
> successor *locate* relationships, contacts, policy commitments, and asset-frontier hints.
> Spend authority is restored only by (1) identity succession succeeding AND (2) the specific
> asset frontier reconciling. There is no path from "capsule says balance X" to "X is
> spendable" — which is what kills the stale-capsule attack.

**Mandatory hardening conditions (all required):**

- **R1 — per-contact bind-once.** Each contact binds to the first valid tombstone proposal
  for an `old_device_id` and rejects later competing proposals; combined with all-contact
  set-equality, competing recoveries can only deadlock, never both activate.
- **R2′ — durable-persist-before-value (on the spending device).** A value-bearing
  transition is refused until the capsule committing the relevant contact is durably
  persisted; fail-closed on persistence failure. (Enforced today as capsule-seal currency,
  **S1**; durable-write confirmation — NFC tag write-ack / storage publish-ack — is the
  remaining **S3** strengthening.)
- **R3 — total value-egress coverage.** Every egress path (bilateral, token, DLV, dBTC
  transfer/withdraw/burn/refund/finalize, token-MPC, emissions) routes through the
  fail-closed gate; proven by the exhaustive `Operation::is_value_egress` classifier at the
  canonical chokepoint (**S1**).
- **R4 — non-shrinkable gate-set.** `gate_set = capsule.contact_set_commit ∪
  publicly-discoverable contact anchors ∪ externally-relevant value frontiers`. The spender
  cannot unilaterally shrink the set by omitting a contact. (Building blocks **S1**; live
  orchestration **S3** — §0.2 item 13.)
- **STRICT-GATE — never weaken for liveness.** The all-contact gate MUST NOT be relaxed by
  timeout, quorum, majority, set-reduction, or "best-effort". Liveness is handled only by
  liquidity placement (value in DLVs, thin hot balances). A malicious mnemonic holder may
  deadlock recovery but MUST NOT create two spend-authoritative successors.

**Acknowledgement = posted state, not a signed ack object (§0.5).** A counterparty's
recognition of the tombstone/successor binding is its own online-posted, genesis-authenticated
relationship state — not a standalone `ContactTombstoneAck` object (that model is superseded).
The anti-rollback floor is enforced as **cryptographic forward ancestry** (`h^cap ⟶*
T_old_current`, hash adjacency / parent consumption) — there is **no numeric height** in the
predicate. The successor must restore at or above the floor in the forward-ancestry sense.

**dBTC crucial rule (bearer-asset instance).** Recovered dBTC is never restored as spendable
from capsule balance. It is restored as a pending bearer-asset claim under policy `P`, then
resolved by replaying and verifying the latest dBTC bearer-state frontier — transfers,
in-flight withdrawals, burns, refunds, and bridge finalization — keeping the capsule from
becoming a private ledger. (Bearer asset states: `LOCKED_RECOVERY → reconciled{Spendable |
Reduced | InFlight | Finalized | RefundPending}`; egress refused while locked or below
frontier. §0.2 item 12.)

### 0.5 Recovery authority = counterparties' posted, genesis-authenticated state (supersedes the signed-ack model)

Recovery authority is **NOT** the stolen device, **NOT** the capsule, and **NOT** the local
contacts DB. Recovery authority is the set of counterparties whose own **online-posted,
genesis-authenticated state** proves they recognized the tombstone and advanced to the
successor binding. This fits DSM: storage nodes are dumb mirrors (store / mirror / enforce
object invariants, never attest); verification is **client-side** via BLAKE3 over deterministic
protobuf + device-side signatures and inclusion proofs.

**Safety argument:**
1. **No invisible value contact.** A value-capable relationship must have an online-posted
   contact/anchor path. Never anchored ⇒ cannot be in the gate; anchored ⇒ recovery discovers
   it from the posted record.
2. **The ack is not a standalone signed object.** It is the counterparty's own posted
   tree/root showing the tombstone + successor binding, verified against the counterparty's
   genesis/device authority — not trusted because storage served it.
3. **Offline spends can't be hidden from a counterparty that counts.** If C accepted an offline
   spend from A_old before processing the tombstone, then when C comes online to process the
   tombstone it posts its current tree — which includes BOTH the spend AND the successor
   binding. A_new cannot observe the binding without also observing C's full current
   relationship state.
4. **If C never comes online, C does not count.** The relationship stalls (liveness), but there
   is no double-spend (safety). This is the only failure mode.

**Per-counterparty validity (build rule).** For each value-capable counterparty C in A's
online-posted, genesis-authenticated relationship set, C's recovery evidence is valid iff:
1. C's posted object is fetched from storage by content/address;
2. it verifies under DSM canonical bytes + domain-separated hash rules;
3. C's device identity verifies under C's genesis / device tree;
4. C's posted per-device tree/root contains the relationship edge to A;
5. that edge shows C processed A_old's tombstone and bound A_new as successor;
6. C's relationship tip is a valid **forward descendant (hash ancestry)** of the floor known
   from A_new's capsule / recovery seed;
7. any transition C accepted **before** the tombstone is already reflected in the same posted
   tree/root;
8. missing / stale / unverifiable / non-posting C produces **no** authority.

**Drop:** signed recovery acks as separate authority objects; contacts-DB pubkey lookup as
authority; the local capsule as the contact-set source; shrinkable local gate-set logic from
A_old's local records.
**Keep:** capsule as hint/floor/recovery seed; storage as availability; counterparty posted
trees as authority; genesis/device-tree verification as the trust root; forward-tip comparison
against the capsule floor.

**Forward-ancestry nuance (MANDATORY).** "tip ≥ floor" means **cryptographic forward ancestry**
(hash adjacency / parent consumption), **NOT numeric greater-than**. DSM acceptance uses hash
adjacency, inclusion proofs, and signatures — **no timestamps, heights, or counters** in
acceptance predicates. This is the shipped behavior: `verify_forward_ancestry`
(`succession_binding.rs:138`, module header `:26`) walks `embedded_parent` adjacency from
`h_cap` to `t_old_current`; there is no numeric `height` floor in the current code.

**Doctrine.** A recovery contact counts only when its own genesis-authenticated, online-posted
tree proves both (1) it bound the tombstone/successor transition and (2) its current
relationship tip includes every transition it accepted before that binding. Therefore recovery
cannot skip a thief's prior spend to that counterparty: either the spend is in the posted state,
or the counterparty has not posted and cannot count. **The complete gate-set IS the
online-posted, value-capable relationship set; the authority for each gate is the
counterparty's own posted, genesis-authenticated state.**

### 0.5.1 Implemented building blocks (pure cores + transport; live activation gated)

The §0.5 doctrine is realized by these cores. Per the anti-overclaim rule, statuses are
explicit: the cores and transport are **S1**; the live activation that consumes them is **S2**
(item 7), and the live gate-set orchestration that feeds it is **S3** (item 13).

1. **S1 — Cross-relationship succession, not in-place migration.** `rel_key` is
   device-pair-derived (`compute_smt_key`), so `(A_old,C)` and `(A_new,C)` are distinct SMT
   leaves — in-place same-`rel_key` migration is impossible by construction. Recovery
   **retires** `(A_old,C)` and **establishes** a new bilateral `(A_new,C)` whose first accepted
   state carries forward the old relationship's verified frontier. `succession_binding.rs`
   (`CrossRelationshipSuccessionEvidence`) verifies, per C: device-pair `rel_key` derivation;
   the tombstone/succession successor proof under the genesis-anchored authority; old-chain
   forward-ancestry `h^cap ⟶* T_old_current` (hash adjacency, no heights); the carry-forward
   commitment binding `(rel_keys, h_cap, T_old_current, tombstone, succession, A_old, A_new, C)`;
   the first-state constraint (the successor channel must be *born* as such); and inclusion of
   BOTH old and new tips in C's posted, genesis-authenticated root. The new `(A_new,C)`
   relationship is a normal bilateral stitched receipt, so `verify_stitched_receipt`
   authenticates it at the integration layer.

2. **S1 — Genesis-anchored recovery-authority declaration — NOT a genesis field.** The
   recovery-authority SPHINCS+ pubkey `K_A_pub` (derived from the mnemonic via
   `derive_recovery_authority_seed`) authenticates each C's tombstone/succession. It **cannot**
   be a genesis field: the recovery mnemonic is generated only when the user enables NFC backup
   (via `recovery.enable`), which runs AFTER genesis creation — the mnemonic is not in scope
   when genesis is created. So the authority is anchored by a **declaration chained off genesis**
   (`authority_anchor.rs`, `RecoveryAuthorityAnchor`): it commits `H(K_A_pub)` and is signed
   twice — by the device's **genesis signing key** (genesis binding; verified against the
   genesis-authenticated device pubkey fetched via the device-tree quorum path) and by `K_A`
   itself (possession proof). Forgery resistance is **bind-once per genesis** (first declaration
   wins, immutable thereafter — mirrors R1; enforced storage-side, §0.2 item 14). The activation
   chokepoint binds the candidate authority pubkey to this anchor BEFORE any verification — there
   is **no** raw runtime-pubkey path.

3. **S1 — Value-capable = `Operation::is_value_bearing`.** Gate-set membership is
   protocol-defined: a relationship is value-capable iff its posted state accepted ≥1
   value-bearing operation (value in ANY direction — egress ∪ ingress `Mint`/`Receive`/
   `CreateToken`), OR its policy marks it value-bearing. Pure contact/social relationships are
   excluded. The freeze/snapshot of this set is the seal's `contact_set_commit` (R4 anti-shrink
   + anti-drift); the live discovery scan that produces it is the S3 orchestration (§0.2 item 13).

### 0.5.2 R4 anti-shrink — gate-set completeness (see §0.2 item 13 for the full rule)

A `K_A`-signed PDSMT head proves authenticity, not completeness; the R4 adversary IS the
spender. The gate-set is therefore made non-shrinkable by THREE combined layers (detailed,
with the invariant + final gate-set rule + test plan, in §0.2 item 13): **(1)** an append-once
PDSMT head chain (`parent_head_hash`, pre-tombstone freeze), **(2)** a completeness commitment
(head commits `pd_smt_root` + `leaf_index_root`; `value_capable` is committed, never server
metadata), and **(3)** a counterparty-union backstop — `C`'s OWN genesis-authenticated
value-capable leaf for the shared symmetric `rel_key` forces `C` into the gate-set even if
`A_old`'s head omitted it.

> **R4 invariant.** A recovery activation MUST NOT exclude any counterparty that can prove,
> from its OWN genesis-authenticated posted state, a value-capable relationship with `A_old`
> at/before the recovery snapshot. Activation fails closed if any union member lacks valid
> `CrossRelationshipSuccessionEvidence`.

---

## 1. Purpose

DSM supports two distinct recovery modes. **[S1 — both modules exist and are already
distinct]**

1. **Device continuity recovery.** Recovers a lost, stolen, destroyed, or retired live device.
   A live device is a relationship endpoint with contacts, bilateral state, pending transitions,
   hot spend authority, and relationship-local tips; recovering it migrates the relationship
   graph.
2. **DLV controller recovery.** Recovers or rotates access to control a Deterministic Limbo
   Vault. A DLV is not a normal live contact device; it is a deterministic policy-bound vault
   object. DLV recovery does not restore a historical balance and does not roll back vault state
   — it only rotates controller or recovery access.

The two modes are not interchangeable:

```
DeviceRecovery ≠ DLVControllerRecovery
```

A device is recovered by contact migration. A DLV is recovered by controller rotation.

---

## 2. Core Terminology

- **Genesis (`G`).** Root identity domain binding devices, contacts, policies, and recovery
  authority. **[S1]** (`genesis_hash` carried in the capsule, `capsule.rs`).
- **Device Identifier (`DevID`).** Stable cryptographic identifier derived from a device's
  post-quantum public key + device binding material. **[S1]** (`source_device_id`, `capsule.rs`).
- **Old Device (`DevID_old`).** The device being recovered from / tombstoned. **[S1]**.
- **Successor Device (`DevID_new`).** Fresh device identifier with new silicon binding and a
  fresh SPHINCS+ keypair; bound via the succession receipt (`tombstone.rs:50`,
  `new_device_commitment`). **[S1]**.
- **Value-Bearing Transition.** Any accepted relationship transition that creates, moves,
  reserves, or releases token value (or otherwise changes a balance/reserve attributable to the
  device). Metadata/discovery/recovery-context updates are non-value-bearing. **[S1]**
  (`Operation::is_value_bearing`, `operations.rs:603`).
- **Device Continuity Capsule.** The device's own encrypted, self-sealed checkpoint of its
  post-transition frontier: relationship tips, contact-set commitment, Per-Device SMT root, and
  receipt-roll accumulator current as of the latest accepted transition. **[S1]** (`RecoveryCapsule`,
  `capsule.rs:55`, including the v6 `contact_set_commit` field).
- **NFC Ring Backup.** The physical transport that writes the encrypted device continuity
  capsule onto an NTAG216 NFC ring and reads it back during recovery. **[S1]** (§4.4).
- **Anti-Rollback Floor.** For relationship `A↔B`, the capsule-committed tip `h^cap_{A↔B}` is
  the minimum tip the recovering device accepts. **[S1 — stored]** (`counterparty_tips`); the
  recovery-time confirm-or-extend-forward check is part of the S2/S3 activation flow (§6).
- **Gate-Set.** The exact set of counterparties whose recovery evidence is required before the
  successor may spend; defined by the latest sealed capsule's `contact_set_commit` ∪ the
  non-shrinkable counterparty-union (R4). **[S1 — capsule commit + core build_gate_set] / [S3 —
  live orchestration]**.
- **Deterministic Limbo Vault (DLV).** A deterministic policy-bound vault object; value is
  suspended under committed protocol math until a proof-carrying transition satisfies the DLV's
  policy. **[S1]** (`vault/limbo_vault.rs`, `vault/dlv_manager.rs`).
- **Token Policy.** An independent CPTA / token-policy object that exists separately from any
  DLV. A DLV does not create, modify, rename, or replace token policies. **[S1]**
  (`TokenPolicyV3`, `PolicyAnchorV3`; core `cpta/`).

> **Naming discipline (per project direction).** This document uses **DLV** throughout and
> treats **token policy** as the pre-existing, independent CPTA object that DLV flows
> **reference/import**. It does not introduce a renamed or parallel vault or token-policy
> system.

---

## 3. Recovery Mnemonic

### 3.1 Entropy and Representation Requirement — **[S1]**

DSM recovery mnemonics MUST encode at least 256 bits of entropy. The canonical representation
is a 24-word BIP39-style phrase, and a 24-word phrase is REQUIRED as the primary recovery
authority for mainnet.

- 256-bit / 24-word generation: `recovery_sdk.rs:259` `generate_mnemonic()` draws 32 bytes from
  `OsRng` and calls `bip39::Mnemonic::from_entropy`.
- "A phrase shorter than 24 words MUST NOT be used as the primary mainnet recovery authority":
  enforced at `recovery.enable` (`recovery_routes.rs:117`) and `recovery.cacheMnemonic` (`:225`)
  via `mnemonic.split_whitespace().count() < 24`. (Previous revisions marked this planned; it is
  now shipped.)

The recovery mnemonic derives recovery authority and capsule decryption material. It MUST NOT
directly derive the old device's live signing key, DBRW/C-DBRW binding material, the old device
identifier, vault balances, contact approvals, storage-node authority, or any ECDSA/Ed25519/RSA/
secp256k1 authority. **[S1]** — the mnemonic feeds only the AEAD key and the (separate) SPHINCS+
recovery-authority seed; SPHINCS+ is the only signature scheme (no Ed25519/secp256k1).

### 3.2 Recovery Key Derivation — **[S1 (shipped-divergent)]**

Whitepaper form (recorded, not adopted):

```
S_mn = Argon2id(M, "DSM/recovery-mnemonic\0", params)
K_R  = HKDF-BLAKE3("DSM/recovery-aead\0", S_mn)        # 32 bytes
```

Shipped form (`capsule.rs:295`, authoritative):

```
seed = Argon2id(mnemonic, salt = "DSM/recovery-ring\0")           # Argon2::default()
K_R  = BLAKE3::new_derive_key("DSM/recovery-aead\0").update(seed) # 32 bytes
```

Differences: the Argon2id salt/domain is `DSM/recovery-ring\0` (not `DSM/recovery-mnemonic\0`),
and the second stage is BLAKE3 `derive_key` (not HKDF-BLAKE3). The AEAD context string
`DSM/recovery-aead\0` matches. The shipped derivation governs. A separate authority seed is
derived under `DSM/recovery-authority\0` (`capsule.rs:316`) and feeds the deterministic SPHINCS+
recovery-authority keypair — this is the root of trust for tombstone/succession signing.

> No migration is adopted here. If the project later chooses the `recovery-mnemonic` + HKDF
> construction, it MUST be a versioned capsule format change (it would invalidate existing
> capsules) and must be named explicitly as a required migration.

---

## 4. Recovery Artifacts

DSM defines two recovery capsule classes:

1. `DeviceContinuityCapsule` — **[S1]** (shipped as the `RCV3` binary capsule).
2. `DLVControllerRotationCapsule` — **[S4]** (not present).

They are different objects and MUST NOT be treated as interchangeable.

### 4.1 Device Continuity Capsule — **[S1]**

An encrypted checkpoint for a live device. It provides continuity context for recovery; it does
not activate recovery and does not unlock funds.

**Shipped plaintext** (`RecoveryCapsule`, `capsule.rs:55`):

```
RecoveryCapsule {
    smt_root: [32]                 # Per-Device SMT root  (owner's own)
    counterparty_tips: map<id, (height, head_hash[32])>   # owner's sealed per-relationship tips
    rollup_hash: [32]              # receipt-roll accumulator
    challenge: [32]
    metadata { version, flags, logical_time, counter }    # counter == capsule index
    source_device_id: [32]         # v4 feature
    genesis_hash: [32]             # v4 feature
    cert_chain_heads: map<id, EK_pk>   # v5 feature (whitepaper §11.1)
    last_certs: map<id, cert>          # v5 feature
    contact_set_commit: [32]           # v6 feature (validated on open)
}
```

> **Capsule versioning (precise).** The wire magic is `RCV3` (`capsule.rs:22`) and
> `metadata.version` is hard-coded to **3** (validated `!= 3` rejects). "v4/v5/v6" are
> *backward-compatible trailing-field feature generations* on the same `RCV3`/version-3 wire
> format, not wire-version bumps: v4 = `source_device_id` + `genesis_hash`; v5 =
> `cert_chain_heads` + `last_certs`; **v6 = `contact_set_commit`**. The current latest capsule
> is **wire `RCV3` / version 3 carrying the v6 feature set**. Do NOT describe this as "capsule
> version 6".

**Whitepaper-proposed plaintext** `DeviceContinuityCapsulePlaintextV3` (protobuf) — for
comparison only:

```
version, genesis_id, old_device_id, capsule_index, per_device_smt_root,
receipt_roll, contact_set_commit, storage_contact_root_hint,
latest_device_tree_root_hint, challenge, metadata
```

Reconciliation:

| Whitepaper field | Shipped equivalent | Status |
| --- | --- | --- |
| `genesis_id` | `genesis_hash` | **S1** |
| `old_device_id` | `source_device_id` | **S1** |
| `capsule_index` | `metadata.counter` | **S1** |
| `per_device_smt_root` | `smt_root` | **S1** |
| `receipt_roll` | `rollup_hash` | **S1** |
| `challenge` | `challenge` | **S1 (present) / shipped-divergent (derivation, §4.3)** |
| `metadata` | `metadata` | **S1** |
| `contact_set_commit` | `contact_set_commit` | **S1** (was planned; now shipped, v6) |
| `storage_contact_root_hint` | — | **S4** |
| `latest_device_tree_root_hint` | partially via `genesis_hash`+`smt_root` | **S4** (explicit hint absent) |
| — | `counterparty_tips`, `cert_chain_heads`, `last_certs` | **S1 (shipped, not in whitepaper msg)** |

> **Important — self-tip invariant (per direction).** The shipped capsule already seals the
> **owner's own** frontier (`smt_root` + `counterparty_tips` + `rollup_hash` + `cert_chain_heads`).
> This is stronger than the whitepaper's `DeviceContinuityCapsulePlaintextV3`, which folds
> per-relationship tips into commitments and omits the explicit tips map. Any future protobuf
> migration MUST preserve `counterparty_tips`/`cert_chain_heads`/`last_certs` (do not drop them in
> favor of `per_device_smt_root` + `contact_set_commit` alone). See §5.4.

The capsule's committed relationship tips are the anti-rollback floor. During recovery a
counterparty MAY only (a) confirm the capsule-committed tip, or (b) prove a valid forward
receipt-adjacent chain from the capsule tip to a newer tip; it MUST NOT move a relationship below
the floor. **Floor storage: S1. Floor enforcement predicate (forward-ancestry): S1
(`verify_forward_ancestry`). Live recovery-time application: part of the S2/S3 activation flow
(§6).**

### 4.2 DLV Controller Rotation Capsule — **[S4]**

An encrypted artifact to recover/rotate controller access for a DLV. It MUST NOT define the DLV
balance, restore historical DLV state, or roll back a DLV; it only identifies recovery context
for rotating controller access against the latest verifiable DLV state. Whitepaper shape
(`DLVControllerRotationCapsulePlaintextV3`): `version, genesis_id, vault_id, old_controller_devid,
recovery_authority_commit, storage_vault_root_hint, controller_rotation_nonce, challenge`.
**Not present in code.**

```
DLVControllerRotationCapsule ⇏ VaultBalance
```

### 4.3 Capsule Encryption — **[S1 (shipped-divergent)]**

Both capsule types use a 256-bit AEAD (XChaCha20-Poly1305). The shipped device capsule binds
the AAD/nonce/challenge as follows (authoritative):

```
# capsule.rs:163  build_capsule_aad
AD = "DSM/recovery-capsule-v3\0" || smt_root || u64le(counter)

# capsule.rs:551  derive_nonce
N  = BLAKE3("DSM/recovery-nonce" || u64le(counter) || rollup_hash)[0..24]

# capsule.rs:560  derive_challenge
challenge = BLAKE3("DSM/recovery-challenge" || rollup_hash || smt_root || u64le(counter))
```

Whitepaper form (recorded, not adopted): `AD = "DSM/recovery-capsule-v3\0" || G || X || R ||
u64le(c)`, `N = BLAKE3("DSM/recovery-nonce\0" || u64le(c) || R)[0..24]`, `challenge =
BLAKE3("DSM/recovery-challenge\0" || G || X || R || u64le(c))`, where `X = DevID_old` (device
capsule) or `vault_id` (rotation capsule) and `R` is a per-capsule binding value.

Nonce-uniqueness: the shipped construction binds `counter` (the strictly increasing capsule
index) and `rollup_hash` (per-capsule), so `N` is never reused under a given `K_R` — the
mandatory stream-cipher property holds today. The shipped challenge binds the capsule to
`(rollup_hash, smt_root, counter)` rather than `(G, X, R, c)`; it serves the same self-binding
purpose. AEAD tamper, counter tamper, and `smt_root` (AAD) tamper are all tested (`capsule.rs`
tests `test_*_tamper_fails`, 16 tests total). **[S1 — these protections ship.]**

> No migration to the `G‖X‖R‖c` form is adopted here.

### 4.4 NFC Ring Backup — Capsule Transport — **[S1]**

NFC ring backup is the physical transport for the device continuity capsule (§4.1): it writes
the encrypted capsule onto an NTAG216 NFC ring and reads it back during recovery import. It is a
4-layer flow (Frontend React/TS → Android Kotlin transport → Rust JNI/SDK → Rust core) and
respects the DSM layer doctrine: **Rust owns all capsule creation, NDEF formatting, and crypto;
Kotlin is transport-only (operates the NFC radio and moves bytes); the frontend triggers and
renders.** (Consolidated here from the former `nfcringbackup.instructions.md`; see also the
`nfc-backup` skill — note the skill text predates a refactor and is partly stale; the anchors
below are authoritative.)

#### 4.4.1 Layer map and control plane

```
Frontend (TS / WebView)            dsm_client/frontend/src/
  dsm/nfc.ts                       startNfcWrite / isNfcBackupEnabled / hasPendingCapsule
                                   / onBackupWritten / onCapsuleReceived
  dsm/nfcRecoveryService.ts        writeToNfcRing(): invokes Rust route nfc.ring.write,
                                   then writeNfcTagPayloadHost() (NativeHost)
  dsm/EventBridge.ts               topic ble.envelope.bin → re-emit nfc.backupWritten and
                                   nfc-recovery-capsule
  bridge/bridgeEvents.ts           event types nfc.backupWritten (nfc.writeStarted declared,
                                   currently unused)
  bridge/NativeHostBridge.ts       writeNfcTagPayloadHost (mime defaults
                                   application/vnd.dsm.recovery)
────────────────────────────────────────────────────────────────────────────
Android (Kotlin) — TRANSPORT ONLY  dsm_client/android/
  ui/MainActivity.kt               implements NfcAdapter.ReaderCallback; NfcHostMode enum
                                   {DISABLED, SUPPRESSED, READ, WRITE}; enableReaderMode for
                                   BOTH read and write (no separate Activities).
                                   handleNfcWrite(): get capsule → prepare NDEF → prepareNfcTag
                                   (auto-formats blank NTAG216) → writeNdefToTag →
                                   clearPendingRecoveryCapsule → maybeRefreshNfcCapsule →
                                   vibrateNfcCommit → dispatch backup-written envelope.
                                   onTagDiscovered → handleNfcRead(): read NDEF,
                                   extractCapsuleRecord (MIME match) → createNfcRecoveryCapsule-
                                   Envelope → BleEventRelay.dispatchEnvelope.
  bridge/NativeHostBridge.kt       HOST_CONTROL_NFC_READER_START/STOP,
                                   PLATFORM_PRIMITIVE_NFC_TAG_READ_PAYLOAD/_WRITE_PAYLOAD →
                                   MainActivity.startNfcReader()/startNfcWriter()
  bridge/UnifiedNativeApi.kt       JNI external fun declarations (see 4.4.2)
  bridge/BleEventRelay.kt          dispatchEnvelope() (used for both read and write-complete)
  AndroidManifest.xml              android.permission.NFC + VIBRATE; feature
                                   android.hardware.nfc required="false";
                                   NO NDEF intent filter (foreground reader mode only)
────────────────────────────────────────────────────────────────────────────
Rust (Core + SDK)                  Owns capsule lifecycle, NDEF framing, crypto.
  jni/unified_protobuf_bridge.rs   getPendingRecoveryCapsule, prepareNfcWritePayload,
                                   clearPendingRecoveryCapsule, maybeRefreshNfcCapsule;
                                   NDEF framing + MIME application/vnd.dsm.recovery
  jni/ble_events.rs                createNfcRecoveryCapsuleEnvelope,
                                   createNfcBackupWrittenEnvelope
  sdk/recovery_sdk.rs              get_pending_capsule, build_capsule_state,
                                   create_capsule_from_current_state_with_key, persist_capsule
                                   (→ prune_old_capsules(5))
  storage/client_db/recovery.rs    mark/clear/get pending recovery capsule, is_nfc_backup_enabled
  handlers/recovery_routes.rs      authorization routes nfc.ring.write / nfc.ring.read
```

**Control plane (corrects the stale skill doc).** There are **no** `nfc*` named Kotlin bridge
RPCs and **no** `isNfcBackupEnabled` JNI export. Control flows as **NativeHost protobuf request
kinds** (`HOST_CONTROL_NFC_READER_START/STOP`, `PLATFORM_PRIMITIVE_NFC_TAG_READ_PAYLOAD/
_WRITE_PAYLOAD`) and is **authorized by the Rust app-router routes `nfc.ring.write` /
`nfc.ring.read`** (`recovery_routes.rs:542/554`, `app_router_impl.rs:2778`). Backup-enabled
status is read via the `recovery.status` route, not a dedicated RPC.

#### 4.4.2 Rust JNI exports (authoritative)

Class prefix `Java_com_dsm_wallet_bridge_UnifiedNativeApi_`. Exports live in **two** files:

| Export | File:line | Returns |
| --- | --- | --- |
| `getPendingRecoveryCapsule()` | `jni/unified_protobuf_bridge.rs:5612` | `jbyteArray` (encrypted capsule) |
| `prepareNfcWritePayload(capsuleBytes)` | `unified_protobuf_bridge.rs:5642` | `jbyteArray` (NDEF) |
| `clearPendingRecoveryCapsule()` | `unified_protobuf_bridge.rs:5707` | void |
| `maybeRefreshNfcCapsule()` | `unified_protobuf_bridge.rs:5723` | void (re-arms next capsule) |
| `createNfcRecoveryCapsuleEnvelope(payload)` | `jni/ble_events.rs:1487` | `jbyteArray` (Envelope) |
| `createNfcBackupWrittenEnvelope()` | `jni/ble_events.rs:1532` | `jbyteArray` (write-committed event) |

The MIME type `application/vnd.dsm.recovery` is set in Rust (`unified_protobuf_bridge.rs:5673`).
NDEF framing is **in the JNI layer** (`unified_protobuf_bridge.rs:5666`), not in `recovery_sdk.rs`:
short-record (`0xD2`) when payload ≤ 255 bytes, else long-record (`0xC2`) with a 4-byte length.

#### 4.4.3 Capsule lifecycle for the ring

- `RecoverySDK::build_capsule_state` (`recovery_sdk.rs:1887`) reuses the capsule index while a
  capsule is pending and advances it after the ring consumes one (`:1923`);
  `create_capsule_from_current_state_with_key` (`:1843`) seals via
  `create_recovery_capsule_with_binding` (binds `source_device_id` + `genesis_hash`, §4.1/§4.3);
  `persist_capsule` (`:2021`) marks pending and prunes to the latest 5 (`prune_old_capsules(5)`,
  `client_db/recovery.rs:726`).
- Pending-capsule SQLite management: `mark_pending_recovery_capsule` (`recovery.rs:124`),
  `clear_pending_recovery_capsule` (`:147`), `get_pending_recovery_capsule` (`:160`),
  `is_nfc_backup_enabled` (`:676`).
- The capsule advances on every accepted state transition (§5.1) and `maybeRefreshNfcCapsule`
  re-arms the next capsule after each successful write.

#### 4.4.4 NTAG216 capacity — **[S1 (Kotlin write-time check) / S3 (no Rust pre-clamp)]**

NTAG216 has 888 bytes total user memory (~868 usable after NDEF overhead). The byte budget is
**not** clamped in Rust; the only capacity gate is at write time on the Kotlin side
(`MainActivity.kt:543`, `ndef.maxSize < messageSize → IOException`). A capsule that exceeds the
tag simply fails to write (silent — see UX contract). A Rust-side pre-clamp / pre-flight size
check is a possible S3 hardening.

#### 4.4.5 Write flow (step by step)

1. User enables NFC backup → Rust creates a capsule (`recovery.enable` → capsule sealed, stored
   "pending" in SQLite).
2. User taps "Write to Ring" → TS `startNfcWrite()` → `nfcRecoveryService.writeToNfcRing()` →
   Rust route `nfc.ring.write` (authorization) → `writeNfcTagPayloadHost()` arms the host radio
   in WRITE mode.
3. `MainActivity` enters `NfcHostMode.WRITE`, `enableReaderMode` listening.
4. User holds phone to NTAG216 ring → `onTagDiscovered` → `handleNfcWrite()` (`:431`).
5. `getPendingRecoveryCapsule()` → capsule bytes; `prepareNfcWritePayload(capsule)` → NDEF bytes.
6. `prepareNfcTag` auto-formats a blank NTAG216; `writeNdefToTag` writes (`Ndef.writeNdefMessage`
   or `NdefFormatable.format`).
7. On success: `clearPendingRecoveryCapsule()` (tells Rust the write committed) →
   `maybeRefreshNfcCapsule()` → `vibrateNfcCommit()` → `createNfcBackupWrittenEnvelope()` +
   `BleEventRelay.dispatchEnvelope(...)` (the write-committed event reaches the WebView as a
   Rust-authored Envelope, **not** `dispatchEventEmpty`).
8. On `IOException` (tag moved / incompatible / capacity exceeded): silent (debug log only). No
   vibration. Activity stays in reader mode for re-tap.

#### 4.4.6 Read flow (recovery import)

1. Reader is in `NfcHostMode.READ` (foreground `enableReaderMode`; there is **no** `NDEF_DISCOVERED`
   manifest intent filter — the app must be open).
2. `onTagDiscovered` (`:376`) → `handleNfcRead()` (`:385`) reads the NDEF message.
3. `extractCapsuleRecord` matches MIME `application/vnd.dsm.recovery` (`:601`) and extracts the
   encrypted capsule bytes.
4. `createNfcRecoveryCapsuleEnvelope(payload)` (`ble_events.rs:1487`) → Rust wraps it as an
   Envelope → `BleEventRelay.dispatchEnvelope(envelope)`.
5. `EventBridge.ts` receives on topic `ble.envelope.bin`, detects the `nfcRecoveryCapsule`
   payload case, and re-emits `nfc-recovery-capsule` to TS subscribers (`onCapsuleReceived`).
   Decryption requires the recovery mnemonic (§3.2); the ring carries ciphertext only.

#### 4.4.7 NFC UX and layer invariants — **[S1]**

- **Vibration = state committed.** The tag write succeeded; the motor fires as a side effect of
  the write completing. **No vibration = it didn't write** (tag moved, incompatible, capacity
  exceeded, or no pending capsule) — user taps again. **No error UI, no timers.** The `50ms` in
  `VibrationEffect.createOneShot(50, …)` is the Android minimum to actuate the motor, not a
  duration design choice.
- **Kotlin is transport-only.** It operates the NFC radio and moves bytes; it makes no protocol
  decisions. The hardware-state branches (`tag writable`, `capacity sufficient`) gate on hardware,
  not protocol outcomes.
- **Rust owns NDEF + crypto.** MIME type, record structure, and capsule content are decided in
  Rust (`prepareNfcWritePayload`). Kotlin does not construct NDEF records.
- **Binary bridge only.** NFC uses the same binary host-control / MessagePort path as everything
  else; no `@JavascriptInterface`, no JSON, no hex.

> **R2′ link.** A durable NFC write-ack (vibration ⇒ committed) is the user-facing form of the
> durable-persist-before-value condition (§0.4 R2′). Wiring the write-ack into a
> `durable_capsule_index` is the remaining **S3** strengthening (§0.2 item 1).

---

## 5. Capsule Currency

### 5.1 Capsule Advances With Accepted State — **[S1]**

A Device Continuity Capsule is a post-state recovery checkpoint, not a periodic backup. The
requirement is:

```
∀n: Accept(S_{n-1} → S_n) ⇒ ∃C_n: CapsuleCommitsTo(C_n, S_n)
```

with `C_n` committing the post-transition frontier (updated relationship tip, Per-Device SMT
root, receipt-roll accumulator, contact-set commitment, capsule index, and all known relationship
tips), and a strictly increasing capsule index.

**Shipped reality:** the `accepted_state_index` bump is folded ATOMICALLY into the state-commit
transaction (`core_sdk::dual_write_advance_outcome`, `core_sdk.rs:185/234`;
`recovery::bump_accepted_state_index_with_conn`, `client_db/recovery.rs:562`), so a
frontier-changing transition can never persist without the capsule being marked dirty. The
capsule is best-effort re-sealed and self-healed on egress (`execute_on_relationship` calls
`maybe_refresh_nfc_capsule` when dirty). (Previous revisions marked this planned; it is now
shipped.)

### 5.2 Capsule Dirty State — **[S1]**

```
CapsuleCurrent ⟺ capsule_state_index == accepted_state_index
CapsuleDirty   = capsule_state_index < accepted_state_index
```

A dirty capsule means the exported artifact does not represent the latest accepted frontier, and
the wallet surfaces this. Tracked via `accepted_state_index` / `capsule_state_index` /
`is_capsule_dirty` (`client_db/recovery.rs:541/587/604`) and surfaced on `recovery.status`
(`recovery_routes.rs:27`).

### 5.3 Mandatory Sealing of Contact Establishment — **[S1 (as currency) / S3 (per-contact establishment seal)]**

> **Invariant 1 (Mandatory Contact Sealing).** No relationship may carry a value-bearing
> transition until the transition that established the contact has been sealed into the device
> continuity capsule. The capsule contact set therefore contains every counterparty with which
> the device can conduct value-bearing transitions.

```
FirstValueTransition(A↔B) ⇒ B ∈ contact_set_commit(C_latest_sealed)
```

This is the load-bearing guarantee that the recovery gate-set is complete. **Shipped as
currency** (R2′ blocks value egress while the capsule is dirty, fail-closed —
`value_egress_block_reason`), and the capsule carries `contact_set_commit` (v6). The
**per-contact establishment-seal** (binding the first value transition to the specific
contact-establishment seal) + the non-shrinkable public-anchor union (R4) is the **S3**
orchestration in §0.2 items 3, 4, 13.

### 5.4 Capsule as Recovery Anchor — **[S1 storage + predicate / S2-S3 live application]**

The capsule tip is the recovering device's **own** sealed view of each relationship. For `A↔B`
the capsule stores the anti-rollback floor `h^cap_{A↔B}`. During recovery, counterparty `B` must
either report the same tip or supply a valid forward adjacent receipt chain from the floor to
`B`'s latest accepted tip.

> **Self-tip invariant (explicit, per direction).** Recovery anchors on the **owner's own**
> sealed floor — `per_device_smt_root` + per-relationship `counterparty_tips` + `rollup_hash`
> (+ cert heads) — **not** on the counterparty's reported tip. "The other party has the latest
> tip" is **insufficient**: a counterparty could under-report (rollback) or the owner could be
> presented stale relationship state. The owner's sealed self-tip is the rollback floor; a
> counterparty's report may only **confirm** it or **extend forward** from it with a valid
> co-signed receipt-adjacent chain. Storage of this floor is **S1**; the forward-ancestry
> predicate is **S1** (`verify_forward_ancestry`); the live recovery-time application that
> consumes it is part of the activation flow (**S2** unlock / **S3** orchestration). Because the
> floor is only trustworthy if it is fresh, capsules advance on **every accepted state
> transition** (§5.1, **S1**) — otherwise recovery could restore from stale, gameable
> relationship state.

### 5.5 High-Value Synchronous Sealing — **[S3]**

Beyond mandatory contact-establishment sealing, high-value/treasury-linked devices SHOULD enforce
full synchronous sealing: a new value-bearing transition MUST NOT begin while `CapsuleDirty =
true`. This is a recoverability strengthening on top of Invariant 1, not a precondition of the
no-double-spend guarantee (which depends only on contact-establishment sealing + capsule
currency). Today egress is refused while dirty (R2′, S1); the synchronous *block-before-begin*
strengthening is S3.

> **Capsule currency ⇒ complete gate-set.** The latest sealed capsule commits to every
> relationship that may carry value; the recovery activation seal is computed over exactly that
> committed contact set ∪ the R4 union. The no-double-spend guarantee reduces to capsule currency
> + all-contact acknowledgement, with no external availability source. **The reduction is S1 for
> capsule currency (§5.1) and the egress gate (§0.2 item 11), and S3 for the live all-contact
> orchestration it consumes (§0.2 item 13).**

---

## 6. Device Continuity Recovery

### 6.1 Device Recovery Is Contact Migration — **[S1 concept / S2 completion gate]**

A live device is a bilateral relationship endpoint. Decrypting a capsule does not complete
recovery:

```
Mnemonic + DeviceContinuityCapsule ≠ RecoveredDevice
ActiveDeviceRecovery = AllContactTombstoneSync
```

Recovery completes only after every gate-set counterparty has automatically synchronized the
tombstone and rebound its relationship to the successor. The all-contact gate as a **live** hard
spend precondition is gated behind the S2 activation unlock (§6.8/§6.9) and the S3 gate-set
orchestration (§0.2 item 13).

### 6.2 No Manual Permission — **[S1 — design]**

Recovery is not a permission process. A contact device automatically processes a valid
mnemonic-authorized tombstone during normal sync; it synchronizes to a valid protocol state
rather than granting permission.

### 6.3 Recovery State Machine — **[S1]**

Typed `RecoveryState` enum (`client_db/recovery.rs:345`): `None, Tombstoning, Succession,
Propagating, Polling, Resuming, Complete, Failed`. `as_str`/`from_bytes` keep the same on-disk
lowercase strings as the prior string phases (drop-in, no migration);
`is_identity_recovery_in_progress()` covers the five in-flight states. (Previous revisions marked
this divergent string-phases; it is now a typed enum.) Phases are read via `recovery.phase`
(`recovery_routes.rs`).

While awaiting contact sync, the successor MAY fetch storage mirrors, discover contacts, publish
recovery intent, receive evidence, verify missing receipts, and update its candidate frontier; it
MUST NOT perform value-bearing transitions, spend recovered funds, accept new token-affecting
transitions as active successor, finalize succession, or claim final recovery. The spend-lock
during recovery is enforced by the value-egress gate (**S1**, `value_egress_block_reason` blocks
during in-progress recovery); the precise all-contact unlock condition is the **S2** activation
chokepoint.

### 6.4 Contact Discovery — **[S1 locate / S3 gate-set definition]**

The successor discovers the old device's contact set from the decrypted capsule, storage-mirrored
contact anchors and contact-routing surfaces, content-addressed contact objects under the old
genesis, and recovered local contact roots. **Discovery locates counterparties; it does not
define the gate-set.** The authoritative gate-set is `A_old`'s online-posted, genesis-authenticated
value-capable PDSMT leaf set ∪ the R4 counterparty-union, frozen into `contact_set_commit`
(building blocks **S1**, live orchestration **S3** — §0.2 item 13). A discovered-but-uncommitted
counterparty is never added to the gate-set; a committed-but-unlocated counterparty keeps the gate
closed until located and synchronized.

### 6.5 Recovery Intent — **[S4 (explicit message)]**

`RecoveryIntentV3 { genesis_id, old_device_id, candidate_new_device_id, capsule_index,
capsule_digest, contact_set_commit, recovery_nonce, new_device_signature }`. Its
`contact_set_commit` MUST equal the referenced capsule's. Announces a candidate replacement; does
not tombstone or activate. The shipped flow expresses recovery intent through the string-phase
state machine + the recovery routes (`recovery.tombstone`, `recovery.succession`,
`recovery.propagateTombstone`, `recovery.pollAcks`, `recovery.activate`); the discrete
`RecoveryIntentV3` message is **not** a separate object in code.

### 6.6 Mnemonic-Authorized Tombstone Proposal — **[S4 (proposal wrapper) / S1 (underlying receipt)]**

Whitepaper `RecoveryTombstoneProposalV3 { genesis_id, old_device_id, new_device_id,
recovery_intent_digest, contact_set_commit, recovery_authority_proof, new_device_signature }`,
valid iff: recovery-authority proof verifies; `old_device_id` active under `G`; `new_device_id`
fresh; references a valid Recovery Intent; `contact_set_commit` matches the capsule; new-device
signature verifies; deterministic encoding + domain-separated hashing hold.

Shipped: the **tombstone receipt itself** is **S1** (`tombstone.rs:31` `TombstoneReceipt {
device_id, old_smt_root, old_counter, old_rollup_hash, tick, signature, tombstone_hash }`; proto
`RecoveryTombstoneRequest/Response`, `TombstoneReceiptProto`), and so is succession
(`tombstone.rs:50` `SuccessionReceipt`, proto `RecoverySuccession*`). The **proposal wrapper with
intent + `contact_set_commit`** as a discrete message is **S4**.

### 6.7 Automatic Contact Tombstone Processing & Posted Evidence — **[S1 logic+transport / S2-S3 live flow]**

During sync each contact checks for recovery tombstone proposals for known contacts, verifies the
tombstone/succession pair under the **genesis-anchored** recovery authority (§0.5.1.2), marks the
old device tombstoned for the relationship, and **establishes a new bilateral `(A_new,C)`
relationship** whose first accepted state carries forward the old frontier (§0.5.1.1). There is
**no standalone signed-ack object** (the `ContactTombstoneAckV3` model is superseded): C's
recognition IS its own online-posted, genesis-authenticated relationship state, which a verifier
fetches and checks client-side. Automatic; no user approval.

The cross-relationship evidence verifier (`CrossRelationshipSuccessionEvidence`,
`succession_binding.rs`) is **S1**, and the bilateral re-establish transport is **S1** and wired
into BLE (§0.2 item 10). The live posting/collection flow that drives this end-to-end during
recovery (the `propagating`/`polling` orchestration feeding activation) is **S3**, and the
activation it culminates in is **S2**.

**Relationship freshness.** C's evidence is valid only if its current `(A_old,C)` tip is a valid
**forward descendant** of the capsule floor — `h^cap ⟶* T_old_current` (hash adjacency / parent
consumption, **no numeric height**); the new `(A_new,C)` receipt is a normal bilateral stitched
receipt co-signed by both endpoints. Any tip not a forward descendant of the floor is rejected.
**[S1]** (`verify_forward_ancestry`, `succession_binding.rs:138`).

### 6.8 Recovery Activation Seal — **[S1 validation+wire / S2 live unlock]**

`RecoveryActivationSeal { genesis_id, old_device_id, new_device_id, recovery_intent_digest,
tombstone_proposal_digest, contact_set_commit, evidence_root, synced_contact_count,
final_per_device_smt_root, final_receipt_roll }` (`recovery/activation.rs:64`), valid iff:
`synced_contact_count` equals the gate-set size; `contact_set_commit` equals the gate-set
commitment; the per-counterparty evidence set equals the gate-set EXACTLY (no
omission/substitution/duplicate); each evidence binds the old→new device under recovery and
verifies the cross-relationship succession (§0.5.1.1) under the genesis-anchored authority
(§0.5.1.2); and `evidence_root` commits exactly the verified outcomes. **Seal validation logic +
proto are S1** (`validate_recovery_activation`, `activation.rs:166`; `compute_evidence_root`,
`:49`; proto `RecoveryActivationSealProto`, `proto:2773`, with `to_bytes`/`from_bytes`,
unit-tested — 8 tests). **The live unlock that records activation is S2:**
`RecoverySDK::verify_and_record_activation` (`recovery_sdk.rs:1704`) runs the anchor binding +
seal validation, then **unconditionally returns a disabled error** (`:1751`) pending the
online-posted gate-set orchestration (§0.2 item 13) + anchor bind-once + adversarial review.

### 6.9 Activation Rule — **[S1 intent / S2 live mechanism]**

```
ValidSuccession ⇒ ValidRecoveryActivationSeal
¬SpendAuthority(DevID_new)   until the seal exists AND the unlock is enabled
```

The successor becomes active only after a valid activation seal exists **and** the activation
chokepoint is enabled. The spend-lock until recovery completes is enforced today (the egress gate
+ the disabled unlock chokepoint keep the successor frozen). The **live release** is the S2 item:
it stays fail-closed until go-live.

### 6.10 No Double-Spend Window — **[S1 premises (crypto + egress gate + capsule currency) / S2-S3 live mechanism]**

The successor cannot spend while any gate-set member still accepts the old device, preventing
split acceptance.

> **Theorem (All-Contact Tombstone Sync Prevents Recovery Double Spend).** Assuming BLAKE3-256
> collision resistance and SPHINCS+ unforgeability, **and** Invariant 1 + capsule currency: if the
> successor cannot perform value-bearing transitions until every gate-set member's own posted,
> genesis-authenticated state proves the cross-relationship succession (§0.5.1.1) under the
> genesis-anchored authority (§0.5.1.2), recovery cannot create a double-spend window between old
> and new devices. *Status: the cryptographic premises (BLAKE3, SPHINCS+) are S1; the egress gate
> (§0.2 item 11), capsule currency (§5.1), seal/evidence/authority verifiers (§0.5.1), and BLE
> re-establish transport (§0.2 item 10) are S1; the live all-contact gate-set orchestration (§0.2
> item 13) is S3; the activation unlock (§6.8) is S2. The safety argument holds; the live
> end-to-end path is intentionally fail-closed until go-live.*

---

## 7. Deterministic Limbo Vaults

### 7.1 DLV Meaning — **[S1]**

Value is suspended under protocol math, not controlled by a middleman, validator, sequencer,
creator backdoor, or storage node:

```
DLVAuthority = CommittedCondition
ValidRelease ⟺ PolicyPredicateSatisfied
```

A DLV can express swap, escrow, AMM, treasury, release, and recovery behavior, but it is not a
global-VM smart contract. (`vault/limbo_vault.rs`, `vault/dlv_manager.rs`.)

### 7.2 DLV Is Not a Smart Contract — **[S1 — design]**

Unlike a blockchain smart contract (global address, shared VM execution, validators/sequencers,
gas, global ordering, mempool exposure, admin/upgrade access, reentrancy/loop bugs), a DLV is
precommitted, deterministic, bounded, policy-anchored, proof-carrying, locally verifiable,
middleman-free, and signer-free after creation unless a signer is explicitly part of the committed
policy.

### 7.3 No Middleman / Storage Is Not Authority — **[S1]**

A DLV has no discretionary operator, no creator backdoor (unless the policy explicitly commits one
— SHOULD NOT for sovereign vaults), no storage-node authority, no validator executor, no
sequencer. DLV state may be mirrored through storage for availability; a verifier accepts DLV
state only if the vault id matches, the referenced existing token policies match, the DLV policy
commitment matches, the state extends the accepted parent tip, the transition satisfies the
policy, all proofs verify, and deterministic encoding holds. (`dlv/vault_state_anchor.rs`,
`dlv/vault_smt_leaf.rs`; client-side composition verifier `sdk/vault_state_composition.rs::compose_vault_state`.)

```
Storage = Availability     Verification = Authority
```

Storage withholding is a liveness effect (delay), never a safety effect (rollback). **[S1]**.

---

## 8. DLV Use of Existing Token Policies

### 8.1 Token Policies Exist Separately — **[S1]**

Token policies exist independently of DLVs. A DLV does not create, modify, rename, replace, or
define a new token universe; it only commits to which **already-existing** token policies it may
interact with. (`TokenPolicyV3`, `PolicyAnchorV3`; core `cpta/`; `token-policy-readiness.instructions.md`.)

### 8.2 Token Policies Referenced by the DLV — **[S1 single-policy / S4 multi-policy envelope]**

At DLV creation, every token policy the DLV may accept/hold/reserve/route/release/refund/burn/swap
MUST already exist as an anchored token-policy object, and the DLV creation object MUST reference
it.

- **Shipped (S1):** `LimboVaultProto.policy_digest` (field 15, `proto:754`) anchors a single CPTA
  policy to the vault; vault creation flows through `DlvSpecV1` / `DlvInstantiateV1` / `DlvCreate`
  (`handlers/dlv_routes.rs`, route `dlv.create`). `dlv.create` validates `spec.policy_digest` is
  32 bytes, stamps it onto the vault after finalize, and for a locked token reads an
  already-registered policy via `resolve_policy_commit_strict` (fail-closed on unregistered) — it
  never authors a policy.
- **Whitepaper shape (S4):** `DLVCreateV3 { vault_id, creator_device_id, dlv_policy_digest,
  repeated TokenPolicyRefV3 token_policies, route_table_commit, predicate_commit, recovery_commit }`
  and `TokenPolicyRefV3 { token_genesis, policy_anchor_digest, policy_commit, policy_bytes_digest }`.

Reconciliation: the **principle** (DLV references existing token policies; validity requires the
canonical policy bytes to hash to the committed digest) is **S1**. The **multi-policy `repeated
TokenPolicyRefV3` set + `route_table_commit`/`predicate_commit`/`recovery_commit` envelope** is
**S4**: today a vault anchors a single CPTA via `policy_digest`. **Any implementation MUST map onto
the existing CPTA objects (`TokenPolicyV3`/`PolicyAnchorV3`) — it MUST NOT introduce a parallel
token-policy type.**

### 8.3 No Token Policy Creation by DLV — **[S1]**

```
TokenPolicy(T) ∉ DLVCreate.token_policies ⇒ T cannot be used by that DLV
```

A DLV MUST NOT create/modify token policies, and MUST NOT accept a token policy not referenced at
creation.

> **Hard token-policy invariant.** Token policies are independent objects. A DLV only operates
> over existing token policies explicitly referenced at creation; it does not create, import-later,
> modify, or replace them.

---

## 9. DLV Controller Recovery

### 9.1 DLV Recovery Is Not Balance Recovery — **[S1 principle / S3-S4 mechanism]**

```
DLVRecovery = ControllerRotation ≠ BalanceRestore
```

A DLV recovery MUST NOT restore a historical balance or roll back vault state; it MAY only rotate
the recovery/controller access path. The current balance is whatever the latest verifiable DLV
state says. The **principle** is enforced by construction (there is no balance-restore path); the
**controller-rotation mechanism** is S3 (validator only) / S4 (state split, capsule).

### 9.2 DLV State Split — **[S4]**

Whitepaper `DLVStateV3 { vault_id, dlv_policy_digest, parent_tip, value_state_commit,
controller_devid, recovery_commit, transition_digest }` separates value state from controller
authority. Shipped vault state (`VaultStateProto`, `VaultStateAnchorV1`) tracks value/reserves but
has **no `controller_devid`** — that field exists only on the in-memory `DlvStateView` inside the
rotation validator, not on any persisted vault object. The value/controller split is **not present
in persisted state.**

### 9.3 Controller Rotation — **[S3]**

`DLVControllerRotationV3 { vault_id, dlv_policy_digest, parent_vault_tip, child_vault_tip,
old_controller_devid, new_controller_devid, recovery_authority_proof, latest_value_state_commit,
rotation_nonce }`, valid iff: latest DLV state fetched + verified by hash adjacency and policy; it
extends the accepted parent tip and is the longest verifiable forward chain known;
`old_controller_devid` matches the active controller; recovery-authority proof verifies;
`new_controller_devid` fresh + silicon-bound; `latest_value_state_commit` equals the latest verified
value commitment; the child preserves the value commitment (unless policy authorizes otherwise);
child tip derived from canonical child state; deterministic encoding holds. A storage node serving
stale-but-valid earlier state cannot cause rollback (a verifier holding a newer tip rejects a
rotation whose parent is not current).

**Shipped (S3 — pure validator, not wired):** `dlv::controller_rotation::validate_controller_rotation`
(`dlv/controller_rotation.rs:162`) checks, in order: `vault_id` match, `dlv_policy_digest` match,
`parent_vault_tip == latest.current_tip` (no-rollback), `old_controller_devid == latest.controller_devid`,
`latest_value_state_commit == latest.value_state_commit` (value preserved), `new != old`,
recovery-authority commit match, SPHINCS+ signature over the rotation payload, and a canonical
value-preserving `child_vault_tip` (9 tests). **Not wired anywhere:** there is no `DLVControllerRotationV3`
proto (the name appears only in a doc comment), no `dlv_sdk` apply path, no rotation capsule, and no
route. NOTE: rotation-nonce replay is bounded by the parent==current-tip check; an explicit nonce set
would harden against storage-rewind.

> **Theorem (DLV Recovery Does Not Restore Balance).** If a controller rotation preserves the latest
> verified value commitment, controller recovery cannot roll back or alter the balance. *Status: the
> validator enforces value preservation (S3); the surrounding state-split + apply path + capsule are
> S4. Not live.*

---

## 10. DLV Interaction and Swap Semantics

### 10.1 The DLV Is the Counterparty of Record — **[S1]**

```
Trader ↔ DLV        (not  Trader ↔ OwnerDevice)
```

Traders interact with the DLV policy surface, not the owner's personal device, so they do not
become recovery-blocking contacts and do not enter the owner device's capsule contact set. (SoFi
vaults are addressed/discovered independently of the owner's device contacts.)

### 10.2 Owner Control vs Public Interaction Surface — **[S1 design / S3 formal link]**

A DLV has a public interaction surface (vault id, DLV policy commitment, referenced token policies,
transition rules) and a narrow owner control surface (controller/recovery authority). The public
surface may have many users; the owner surface SHOULD remain narrow. The guarantee that public users
never enter the owner recovery gate-set is formal once the live gate-set orchestration (§6, §0.2 item
13) is enforced.

### 10.3 DLV Swap Transition & Output Routing — **[S1 (shipped-divergent shape) / S4 (V3 message shapes)]**

Whitepaper `DLVSwapTransitionV3` (input/output token genesis + policy commit + amounts, trader
signature, policy proof, proceeds route) and `DLVRouteKind { ROUTE_COUNTERPARTY,
ROUTE_OWNER_RECEIVE_TARGET, ROUTE_DLV_RESERVE, ROUTE_TREASURY_DLV, ROUTE_BURN, ROUTE_REFUND_SOURCE,
ROUTE_POLICY_COMMITTED_TARGET }` and `OwnerReceiveTargetV3` describe swap + routing.

Shipped (S1): the equivalent **function** ships via the SoFi pipeline — `RouteCommitV1` /
`RouteCommitHopV1` (signed by the trader, verified by the unlock gate), the external commitment
`X = BLAKE3("DSM/ext\0" || canonical(RouteCommit))`, constant-product `AmmConstantProduct`
fulfillment, and `DlvUnlockRoutedV1` (`sdk/route_commit_sdk.rs`, `sdk/routing_path_sdk.rs`,
`handlers/dlv_routes.rs` route `dlv.unlockRouted`, `route.*` routes). A swap is well-formed only if
both token policies are existing policies referenced by the vault; the unlock gate
(`verify_route_commit_unlock_eligibility`) verifies the trader signature, recomputes `X`, and checks
its visibility; the AMM re-simulation (`verify_amm_swap_against_reserves`) checks the constant-product
invariant against the vault's current reserves. The **explicit `DLVSwapTransitionV3` message +
`DLVRouteKind` enum + `OwnerReceiveTargetV3`** are **S4** — a different shape over already-shipped
functionality; first-class enumerated routes like treasury/owner-receive/burn are not present. The
route is part of policy + transition proof, never chosen by storage or improvised by the owner at
execution time. **[S1 — principle; shipped-divergent shape.]**

Sale/limit-order, AMM/reserve, and custody/redundancy DLV patterns are expressible today via SoFi
vault configurations; the owner need not be online for a swap and later ingests/verifies the receipt.
**[S1].**

### 10.4 No Public Fanout Into Owner Recovery — **[S1 design / S3 formal link]**

```
Trader ∈ DLVInteractionSet ⇏ Trader ∈ OwnerRecoveryContactSet
```

DLV interaction fanout does not expand the owner recovery gate-set; formal once the live gate-set
orchestration (§6, §0.2 item 13) lands.

---

## 11. High-Liquidity Operational Guidance — **[S1 — advisory]**

- Keep high-contact devices low on hot liquidity; place substantial liquidity into DLVs.
- Public users interact directly with DLV policy surfaces; proceeds route per policy.
- Recover DLVs by controller rotation (§9), not hot-wallet balance recovery.
- Unsafe profile: one device, many contacts, large hot balance, direct spend authority over all
  funds — large recovery synchronization surface.

```
High-contact devices should carry low hot liquidity.
High-liquidity DLVs should have narrow controller recovery surfaces.
```

The strict all-contact gate (§6) guarantees no double-spend; keeping value in DLVs bounds the gate's
liveness cost (a stranded gate-set member can only hold up the thin hot balance).

---

## 12. Security Theorems — status summary

| Theorem | Premises | Status |
| --- | --- | --- |
| Capsule-Anchored Gate Completeness | Invariant 1 + capsule currency | **S1 (capsule currency, egress gate, contact_set_commit) / S3 (live all-contact orchestration)** |
| Device Recovery Requires Graph Migration | spend-lock until all-contact ack | **S1 (spend-lock + cross-rel evidence + BLE re-establish) / S2 (live activation unlock)** |
| No Split-Recovery Double Spend | SPHINCS+ + BLAKE3 + Invariant 1 + currency | **S1 (crypto + egress gate + verifiers + currency) / S2 (live unlock) / S3 (gate-set orchestration)** |
| DLV Controller Recovery Does Not Restore Balance | controller rotation preserves value commit | **S3 (validator enforces value preservation; no apply path) / S4 (state split, capsule)** |
| DLV Users Do Not Become Owner Recovery Contacts | counterparty-of-record is the DLV | **S1 design / S3 formal link** |

---

## 13. Cross-Reference Appendix — spec message ↔ shipped artifact

| Spec object | Shipped artifact (proto / code) | Status |
| --- | --- | --- |
| `DeviceContinuityCapsulePlaintextV3` | `RecoveryCapsule` (`capsule.rs:55`, `RCV3` binary, v6 `contact_set_commit`) | S1 (binary, shipped-divergent framing); `*_root_hint` fields S4 |
| `DLVControllerRotationCapsulePlaintextV3` | — | S4 |
| `RecoveryIntentV3` | string-phase state machine + recovery routes | S4 (discrete message) |
| `RecoveryTombstoneProposalV3` | `RecoveryTombstoneRequest/Response`, `TombstoneReceiptProto`, `tombstone.rs:31` | S1 (receipt) / S4 (proposal wrapper) |
| `ContactTombstoneAckV3` | superseded by §0.5 posted-state model — `CrossRelationshipSuccessionEvidence` (`succession_binding.rs`) | S1 (logic) / S3 (live flow) |
| Cross-relationship succession evidence | `CrossRelationshipSuccessionEvidence` (`succession_binding.rs`) | S1 (logic + BLE transport) / S3 (live orchestration) |
| Genesis-anchored recovery authority | `RecoveryAuthorityAnchor` (`authority_anchor.rs`) + storage bind-once | S1 (logic + storage bind-once + fetch/verify) / S2 (consumption in activation) |
| `RecoveryActivationSealV3` | `RecoveryActivationSeal` (`activation.rs`) + `RecoveryActivationSealProto` (`proto:2773`) | S1 (validation + wire) / S2 (live unlock) |
| `RecoveryState` enum | typed enum (`client_db/recovery.rs:345`) | S1 |
| Succession | `RecoverySuccession*`, `SuccessionReceipt` (`tombstone.rs:50`) | S1 |
| PDSMT posting / gate-set | `PostedPdsmtHeadV1`/`PostedPdsmtLeafRecordV1` + `pdsmt_posting.rs` + `gate_set.rs` + storage `pdsmt_head_chain` + SDK fetch/publish | S1 (building blocks) / S3 (live orchestration) |
| NFC ring backup | `recovery_sdk.rs` + JNI (`unified_protobuf_bridge.rs`, `ble_events.rs`) + `MainActivity.kt` + `nfc.ts`; routes `nfc.ring.write`/`read` | S1 |
| `DLVCreateV3` / `TokenPolicyRefV3` | `DlvCreate`, `DlvSpecV1`, `DlvInstantiateV1`, `LimboVaultProto.policy_digest`, `TokenPolicyV3`, `PolicyAnchorV3` | S1 (single-policy concept) / S4 (multi-policy envelope) |
| `DLVStateV3` | `VaultStateProto`, `VaultStateAnchorV1` (no controller field) | S4 (controller split) |
| `DLVControllerRotationV3` | `validate_controller_rotation` (`dlv/controller_rotation.rs`, validator only) | S3 (validator) / S4 (proto + apply + capsule) |
| `DLVSwapTransitionV3` / `DLVRouteKind` / `OwnerReceiveTargetV3` | `RouteCommitV1`/`RouteCommitHopV1`, `AmmConstantProduct`, `DlvUnlockRoutedV1` | S1 (function, shipped-divergent shape) / S4 (V3 messages) |

---

## 14. Summary

```
DeviceRecovery = Mnemonic_24 + CurrentCapsule + AutomaticContactTombstoneSync + RecoveryActivationSeal
DLVRecovery    = Mnemonic_24 + DLVControllerRotationCapsule + LatestVerifiedDLVState + ControllerRotationTransition
```

Device recovery migrates a relationship endpoint; DLV recovery rotates a controller. The device
continuity capsule advances with every accepted state (so its contact set is always complete for
value-bearing relationships), is durably backed up to an NFC ring (§4.4), and the activation seal is
computed over exactly that committed gate-set ∪ the R4 union; every member must acknowledge before
the successor can spend; each ack may only confirm or extend forward from the capsule's anti-rollback
floor. The no-double-spend guarantee then holds structurally with no external availability source.

**Shipped & enforced today (S1):** capsule sealing of the owner's own frontier (SMT root +
per-relationship tips + rollup + cert heads + `contact_set_commit` v6), NFC ring backup write/read,
capsule currency on every accepted transition + dirty-state surfacing, the fail-closed value-egress
gate + bearer-asset `LOCKED_RECOVERY` lock-state, tombstone/succession receipts + protos, the typed
`RecoveryState` enum, the cross-relationship succession + activation-seal **validation** logic + proto,
the genesis-anchored recovery authority + storage bind-once, the bilateral BLE recovery re-establish
transport, the R4 gate-set **building blocks** (PDSMT head-chain + leaf records + `build_gate_set` +
storage endpoints), and the full DLV + SoFi swap/routing + CPTA token-policy stack.

**Implemented but activation-gated / fail-closed (S2 — NOT live):** the recovery activation **unlock
chokepoint** (`verify_and_record_activation` returns a disabled error by design) and the
recovered-successor freeze **release**. These exist and are tested, but the final go-live path is
intentionally inert pending the S3 orchestration below + an audited go-live.

**Partially implemented (S3):** the live all-contact gate-set orchestration (fetch → verify →
freeze → activation) + the publish-side PDSMT head builder + the recovery-bundle format; the
per-contact establishment seal; durable-write confirmation for R2′; the on-device two-device BLE
recovery integration test; the DLV controller-rotation apply path (the validator is S3-complete).

**Specified, not implemented (S4):** the DLV value/controller state split (`DLVStateV3`,
`controller_devid` on vault state), the DLV controller-rotation capsule + proto, the discrete
`RecoveryIntentV3`/`RecoveryTombstoneProposalV3` messages, the multi-policy `DLVCreateV3` /
`TokenPolicyRefV3` envelope, the `DLVSwapTransitionV3`/`DLVRouteKind`/`OwnerReceiveTargetV3` shapes,
and the capsule `*_root_hint` discovery fields.

A DLV-mediated swap is performed against the DLV, not the owner device, and never expands the owner's
recovery gate-set. A DLV does not create token policies; it only operates over existing token policies
explicitly referenced at creation. DLV outputs route per committed policy. Storage provides
availability, not authority. A DLV remains sovereign because value is suspended under deterministic
protocol math.
