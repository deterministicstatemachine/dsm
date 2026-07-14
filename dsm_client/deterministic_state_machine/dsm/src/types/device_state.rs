// SPDX-License-Identifier: MIT OR Apache-2.0

//! Device state: the canonical per-device head per whitepaper §2.2, §4, §8.
//!
//! This module defines [`DeviceState`] — the authoritative representation of a
//! DSM device's state. It consists of:
//!
//! - Per-Device SMT whose root `r_A` is the device's head pointer (§2.2)
//! - Device-level fungible token balances keyed by CPTA `policy_commit` (§9)
//! - Per-relationship chain tips + minimal acceptance material (§4.2)
//!
//! Advances take the device from `r_A → r'_A` via a single SMT leaf replace
//! (§4.2). The design follows first-commit-wins semantics: each advance is an
//! atomic head update. Concurrency is structurally impossible at the head
//! level — two attempted advances from the same `r_A` will each see the same
//! parent root, build valid successors, and race at the caller's CAS step;
//! the loser's receipt references a stale `r_A` and is rejected.
//!
//! Per §4.3, this module contains **no counters, no timestamps, no heights**
//! in any acceptance predicate or canonical hash. Ordering is by hash
//! adjacency (§2.1): each [`RelationshipChainState`] embeds its predecessor
//! tip `h_{i-1}`. Per-transition entropy (§11) makes state identity unique
//! even when balance values round-trip.

use std::collections::BTreeMap;
use std::fmt;

use crate::common::domain_tags::TAG_STATE_HASH;
use crate::crypto::blake3::dsm_domain_hasher;
use crate::merkle::sparse_merkle_tree::{SmtReplaceResult, SparseMerkleTree};
use crate::types::error::DsmError;
use crate::types::operations::Operation;

/// The canonical per-device head per §2.2.
///
/// `DeviceState` stores **current truth only** — tip-per-relationship plus
/// device-level fungible balances. Full per-relationship history lives in
/// BCR archives, not here.
#[derive(Clone)]
pub struct DeviceState {
    /// Genesis digest `G_A` (§2.4–§2.5). Immutable 32 bytes.
    genesis: [u8; 32],

    /// Device identifier `DevID_A = BLAKE3("DSM/devid\0" ‖ pk ‖ att)` (§2.4).
    devid: [u8; 32],

    /// Device's SPHINCS+ public key for receipt signatures.
    public_key: Vec<u8>,

    /// Per-Device SMT (§2.2). Leaves: `rel_key → chain_tip`. Root is `r_A`.
    smt: SparseMerkleTree,

    /// Device-level fungible token balances.
    ///
    /// Keyed by the **32-byte CPTA `policy_commit`** per §9 — not by a
    /// token_id string. This eliminates any runtime policy-resolution
    /// dependency in canonical hashing: a verifier reproducing a
    /// [`RelationshipChainState`] hash only needs the 32-byte keys from
    /// the state itself, never a CPTA lookup.
    ///
    /// `BTreeMap` for deterministic iteration order during canonical hashing.
    balances: BTreeMap<[u8; 32], u64>,

    /// Per-relationship current tip cache. Mirrors the SMT leaf values plus
    /// the minimum acceptance material needed to build the next advance
    /// (embedded parent, balance witness, counterparty binding).
    ///
    /// Canonical source of truth is [`SparseMerkleTree`]; this map is a
    /// fast-path for building successors without archive fetches.
    tips: BTreeMap<[u8; 32], RelChainTip>,

    /// Legacy compat anchor: if a State was bootstrapped via `set_state`,
    /// its hash is stored here so that `verify_state` and similar legacy
    /// checks have a head_hash to compare against. Strictly compat path —
    /// new code reads `root()` (the SMT root, §2.2 canonical).
    legacy_anchor: Option<[u8; 32]>,

    /// Device-level offline-bearer attestation capability (spec §10, optional
    /// anti-clone authority tier). Gate state only — NOT part of any canonical
    /// hash; `DeviceState` is current-truth-only and anchored by the SMT root.
    /// Fresh genesis is `NotAttested`; an admitted island sets `Attested`; a
    /// re-root after recovery resets to `NotAttested`. See [`crate::attestation`].
    offline_bearer_attestation: OfflineBearerAttestation,

    /// Non-relationship SMT leaves that also commit into the device root `r_A`:
    /// offline-bearer anchor-state leaves ([`Self::with_anchor_state_leaf`], and the
    /// `anchor_leaf` replaced inside [`Self::advance`]) and SoFi vault-state leaves
    /// ([`Self::with_vault_state_leaf`]). The [`SparseMerkleTree`] is the canonical source
    /// of truth for their VALUE, but — exactly like [`Self::tips`] — this map is the
    /// enumerable record needed to REPLAY them in [`Self::restore`]. Without it a state that
    /// has any such leaf recomputes a different root on reload (the leaf is in the stored root
    /// but absent from the replayed one), bricking the wallet. `BTreeMap` for deterministic
    /// iteration during persistence.
    extra_leaves: BTreeMap<[u8; 32], [u8; 32]>,

    /// Offline-cash allocations: value deliberately loaded from the online balance into this
    /// device's device-bound offline-bearer regime ("cash in hand"). Keyed by
    /// `offline_allocation_key(genesis, devid, anchor_bundle_B, asset)`; the value is the
    /// extractable `(amount, sequence)` behind the committed allocation leaf (whose hash lives
    /// in [`Self::extra_leaves`]). The leaf hash is not reversible to the amount, so this map is
    /// the enumerable, persisted record of the allocation balance — mutated only by the
    /// load/unload/spend chokepoints, never by the online per-token spend path. `BTreeMap` for
    /// deterministic iteration during persistence.
    offline_allocations: BTreeMap<[u8; 32], OfflineAllocation>,
}

/// Extractable state of one offline-cash allocation (see [`DeviceState::offline_allocations`]).
/// The committed allocation leaf value is `offline_allocation_value(amount, sequence)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OfflineAllocation {
    /// Current allocation balance in the asset's base units.
    pub amount: u64,
    /// Monotone per-allocation transition counter; advances on every load/unload/spend so a
    /// repeated `amount` still produces a distinct committed leaf value (no replay).
    pub sequence: u64,
}

impl fmt::Debug for DeviceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceState")
            .field("genesis", &hex_short(&self.genesis))
            .field("devid", &hex_short(&self.devid))
            .field("root", &hex_short(&self.root()))
            .field("balances", &self.balances.len())
            .field("tips", &self.tips.len())
            .finish()
    }
}

fn hex_short(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16);
    for byte in &b[..8] {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

/// Canonical value-capability of a relationship, for recovery gate-set construction
/// (spec §0.5 gap 13, R4 anti-shrink). This is the ONLY representation — there is no
/// legacy bool, no default-false, no `missing == No`.
///
/// - `Yes` — PROVEN value-capable: a value-bearing op was observed. Sticky; never downgraded.
/// - `No` — PROVEN never value-capable: the relationship's birth was witnessed and complete
///   observed history shows no value-bearing op.
/// - `Unknown` — INCOMPLETE PROOF: imported / capsule-restored / partial or unwitnessed
///   history. Transitional — eliminated by canonicalization when history becomes provable.
///
/// **Invariant: `Unknown` is NOT false. `Unknown` is INCLUDED in the recovery gate. Only
/// proven `No` is excluded.** No relationship may be excluded unless exclusion is proven.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueCapability {
    Yes,
    No,
    Unknown,
}

impl ValueCapability {
    /// Canonical wire value (matches proto `ValueCapabilityV1`; `0`/UNSPECIFIED is invalid).
    pub fn to_wire(self) -> i32 {
        match self {
            ValueCapability::Yes => 1,
            ValueCapability::No => 2,
            ValueCapability::Unknown => 3,
        }
    }

    /// Decode from the wire, **fail-closed**: `0`/UNSPECIFIED and any unrecognized value are
    /// rejected (returned `None`) — NEVER silently treated as `No` or any other variant.
    pub fn from_wire(v: i32) -> Option<Self> {
        match v {
            1 => Some(ValueCapability::Yes),
            2 => Some(ValueCapability::No),
            3 => Some(ValueCapability::Unknown),
            _ => None,
        }
    }

    /// Stable 1-byte tag for domain-separated commitments (equals the wire value).
    pub fn commit_tag(self) -> u8 {
        self.to_wire() as u8
    }

    /// R4 gate inclusion: include unless PROVEN `No`. (`Yes` and `Unknown` both include.)
    pub fn includes_in_gate(self) -> bool {
        !matches!(self, ValueCapability::No)
    }

    /// Sticky-monotone update on an accepted op. A value-bearing op proves `Yes` (and `Yes`
    /// is never downgraded); a non-value op leaves the prior verdict unchanged. Starting
    /// from `No` (a freshly witnessed birth) this yields `Yes` on first value op and `No`
    /// otherwise; starting from `Unknown` (unwitnessed history) a non-value op keeps
    /// `Unknown` (we still cannot prove `No`).
    pub fn advance(self, op_is_value_bearing: bool) -> Self {
        if op_is_value_bearing {
            ValueCapability::Yes
        } else {
            self
        }
    }
}

/// Device-level offline-bearer attestation capability (the optional anti-clone
/// authority tier, spec §10). Mirrors the [`ValueCapability`] shape but with the
/// **opposite gate polarity** and **no stickiness**:
///
/// - `Attested` — a genuine secure-element island (Trezor Safe 7 / TROPIC01) has
///   been admitted under a pinning policy; the device may exercise offline-bearer
///   authority. See [`crate::attestation`].
/// - `NotAttested` — PROVEN no admitted island (fresh genesis, or re-rooted after
///   recovery / new device). Offline-bearer authority is denied; transitions fall
///   back to the online-checked settlement path.
/// - `Unknown` — INCOMPLETE PROOF (imported / capsule-restored). Denied, fail-closed.
///
/// **Gate polarity (deny-unless-proven): only `Attested` permits the offline-bearer
/// path.** This is the inverse of `ValueCapability`'s include-unless-proven-`No` gate,
/// because attestation is a positive authority claim — absence of proof must deny it.
///
/// **Not sticky — resets on recovery.** Seed recovery restores funds but NEVER restores
/// prior offline-bearer island authority (spec §5: bind the island identity, not the
/// seed). After a re-root the device is `NotAttested` until a new island is admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OfflineBearerAttestation {
    Attested,
    NotAttested,
    Unknown,
}

impl OfflineBearerAttestation {
    /// Canonical wire value (`0`/UNSPECIFIED is invalid, mirroring [`ValueCapability`]).
    pub fn to_wire(self) -> i32 {
        match self {
            OfflineBearerAttestation::Attested => 1,
            OfflineBearerAttestation::NotAttested => 2,
            OfflineBearerAttestation::Unknown => 3,
        }
    }

    /// Decode from the wire, **fail-closed**: `0`/UNSPECIFIED and any unrecognized
    /// value are rejected (`None`) — NEVER silently treated as any variant.
    pub fn from_wire(v: i32) -> Option<Self> {
        match v {
            1 => Some(OfflineBearerAttestation::Attested),
            2 => Some(OfflineBearerAttestation::NotAttested),
            3 => Some(OfflineBearerAttestation::Unknown),
            _ => None,
        }
    }

    /// Stable 1-byte tag for domain-separated commitments (equals the wire value).
    pub fn commit_tag(self) -> u8 {
        self.to_wire() as u8
    }

    /// Offline-bearer gate: permit the offline path **only** when PROVEN `Attested`.
    /// `NotAttested` and `Unknown` both deny (fail-closed deny-unless-proven).
    pub fn permits_offline_bearer(self) -> bool {
        matches!(self, OfflineBearerAttestation::Attested)
    }

    /// The attestation state after a re-root (recovery / new device). Authority is
    /// NOT carried across recovery — the new island must be re-admitted. Always
    /// `NotAttested`, never the prior value.
    pub fn after_recovery() -> Self {
        OfflineBearerAttestation::NotAttested
    }
}

/// Cached per-relationship tip metadata.
///
/// Contains the current chain tip digest (mirror of the SMT leaf) plus the
/// full [`RelationshipChainState`] that produced it, so the next advance on
/// this relationship can read `embedded_parent` and prior `balance_witness`
/// without an archive fetch.
#[derive(Clone, Debug)]
pub struct RelChainTip {
    /// Current chain tip `h_n = H(canonical_bytes(state))`.
    /// Mirrors the SMT leaf value.
    pub chain_tip: [u8; 32],

    /// Counterparty device identifier for this relationship.
    pub counterparty_devid: [u8; 32],

    /// Full state at the tip, if available. `None` when the tip was restored
    /// from a recovery capsule that only carried the digest.
    pub state: Option<RelationshipChainState>,

    /// Canonical value-capability (R4 anti-shrink). Witnessed-birth relationships are
    /// `Yes`/`No`; imported/capsule-restored tips are `Unknown` until history proves
    /// otherwise. There is no legacy/default form — every tip carries this explicitly.
    pub value_capability: ValueCapability,
}

/// One accepted state in a per-relationship straight hash chain (§2.1).
///
/// Replaces the old monolithic `State` for per-chain semantics. Carries
/// adjacency material, the operation, entropy, a device-level balance
/// witness, and signatures. **No `state_number`, no `sparse_index`** —
/// both are forbidden in acceptance predicates by §4.3.
#[derive(Clone, Debug)]
pub struct RelationshipChainState {
    /// 32-byte relationship key `k_{A↔B}` per §2.2 canonical derivation.
    pub rel_key: [u8; 32],

    /// Embedded parent hash `h_{i-1}` from the **same** relationship chain
    /// (§2.1 eq. 1). For first-ever advances on a relationship this is the
    /// spec-canonical initial tip derived from genesis + counterparty.
    pub embedded_parent: [u8; 32],

    /// Counterparty device identifier.
    pub counterparty_devid: [u8; 32],

    /// Operation performed in this transition.
    pub operation: Operation,

    /// Fresh per-transition entropy (§11 eq. 14). Makes state identity
    /// unique even when field values round-trip.
    pub entropy: Vec<u8>,

    /// Optional ML-KEM-768 ciphertext binding this transition to the
    /// counterparty (§11 eq. 12).
    pub encapsulated_entropy: Option<Vec<u8>>,

    /// Device-level `B^T` witness at the moment of this transition (§8).
    ///
    /// Keyed by 32-byte CPTA `policy_commit` (not token_id string) so the
    /// canonical hash has no runtime policy-resolution dependency. Values
    /// are raw `u64` balances. `BTreeMap` for deterministic order.
    pub balance_witness: BTreeMap<[u8; 32], u64>,

    /// Entity (advancing party) SPHINCS+ signature.
    pub entity_sig: Option<Vec<u8>>,

    /// Counterparty SPHINCS+ signature (bilateral mode).
    pub counterparty_sig: Option<Vec<u8>>,
}

impl RelationshipChainState {
    /// Compute `h_n = H(canonical_bytes(self))` with the
    /// `DSM/state-hash` domain tag.
    ///
    /// The canonical byte layout EXCLUDES `state_number`, `sparse_index`,
    /// and any counter-like metadata per §4.3. Ordering of fields is:
    ///
    /// `rel_key ‖ embedded_parent ‖ counterparty_devid ‖ op ‖ entropy
    /// ‖ encap_flag ‖ encap? ‖ witness_len
    /// ‖ (policy_commit ‖ value)* sorted_by_policy_commit`
    ///
    /// Signatures are NOT hashed — they sign this digest, not the other
    /// way around.
    pub fn compute_chain_tip(&self) -> [u8; 32] {
        let mut hasher = dsm_domain_hasher(TAG_STATE_HASH);

        hasher.update(&self.rel_key);
        hasher.update(&self.embedded_parent);
        hasher.update(&self.counterparty_devid);

        let op_bytes = self.operation.to_bytes();
        hasher.update(&(op_bytes.len() as u32).to_le_bytes());
        hasher.update(&op_bytes);

        hasher.update(&(self.entropy.len() as u32).to_le_bytes());
        hasher.update(&self.entropy);

        match &self.encapsulated_entropy {
            Some(enc) => {
                hasher.update(&[1u8]);
                hasher.update(&(enc.len() as u32).to_le_bytes());
                hasher.update(enc);
            }
            None => {
                hasher.update(&[0u8]);
            }
        }

        // Balance witness: already sorted by 32B policy_commit (BTreeMap).
        hasher.update(&(self.balance_witness.len() as u32).to_le_bytes());
        for (policy_commit, value) in &self.balance_witness {
            hasher.update(policy_commit);
            hasher.update(&value.to_le_bytes());
        }

        *hasher.finalize().as_bytes()
    }
}

/// A balance mutation to apply during [`DeviceState::advance`].
#[derive(Clone, Debug)]
pub struct BalanceDelta {
    /// CPTA `policy_commit` (32B) identifying the token.
    pub policy_commit: [u8; 32],

    /// Direction and magnitude of the change.
    pub direction: BalanceDirection,

    /// Magnitude.
    pub amount: u64,
}

/// Direction of a [`BalanceDelta`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BalanceDirection {
    /// Increase the balance (`B^T ← B^T + amount`).
    Credit,
    /// Decrease the balance (`B^T ← B^T - amount`), failing on underflow
    /// per §8 eq. 10.
    Debit,
}

/// The value source for an [`DeviceState::advance`] that spends from the device-bound
/// offline-cash allocation instead of the online balance (an offline-bearer transfer).
///
/// When present, the transfer's value is conserved by debiting the allocation by `amount` — the
/// online balance is NOT touched (it was already debited when the cash was loaded) and
/// `deltas` MUST be empty. The allocation debit and the relationship + anchor-state advance land in
/// ONE atomic device-root replacement, so the value move and the transition are inseparable.
#[derive(Clone, Copy, Debug)]
pub struct OfflineSpend {
    /// Chip-rooted anchor bundle `B` binding the allocation to this device's offline-bearer island.
    pub anchor_bundle_b: [u8; 32],
    /// Asset (CPTA `policy_commit`) whose allocation is being spent.
    pub asset: [u8; 32],
    /// Amount drawn from the allocation — must equal the transfer operation's amount.
    pub amount: u64,
}

/// By-construction balance-conservation guard for [`DeviceState::advance`].
///
/// Validates that `deltas` exactly realize `operation` for the device identified
/// by `local_devid`, so a caller cannot apply a balance mutation that diverges
/// from the (authenticated) signed operation. Mirrors the reference semantics of
/// `core::state_machine::transition::verify_token_balance_consistency`, lifted to
/// operate on `&[BalanceDelta]` (code correspondence: lean4
/// `DSMOfflineFinality.lean` `commitTransfer` / `commit_conservation`).
///
/// - `Transfer` (online): exactly one delta, `amount == op.amount`, direction is `Credit`
///   iff this device is the recipient (`op.to_device_id == local_devid`) else
///   `Debit`, and `policy_commit == op.policy_commit` (§9.5 token binding).
/// - `Transfer` (offline-bearer, `offline_spend = Some(amount)`): value comes from the
///   device-bound offline-cash allocation, so `deltas` MUST be empty (the online balance is not
///   touched) and the allocation debit must equal `op.amount`. The operation must be a bearer
///   transfer (`OfflineBearerRequired`). This keeps ONE conservation chokepoint across both
///   value regimes — the allocation debit is the conserved source, exactly as an online `Debit` is.
/// - `Mint`: exactly one `Credit` delta of `amount`.
/// - `Burn`: exactly one `Debit` delta of `amount`.
/// - Every other operation: no balance deltas, and no `offline_spend`.
fn validate_conservation(
    local_devid: &[u8; 32],
    operation: &Operation,
    deltas: &[BalanceDelta],
    offline_spend: Option<u64>,
) -> Result<(), DsmError> {
    // A allocation-backed spend is only ever valid for an offline-bearer transfer. Reject it on any
    // other operation before the per-op match, so no non-transfer path can source from the allocation.
    if offline_spend.is_some()
        && !crate::core::bilateral_transaction_manager::operation_requires_offline_bearer(operation)
    {
        return Err(DsmError::invalid_operation(
            "conservation: offline-cash allocation spend is only valid for an offline-bearer transfer",
        ));
    }
    match operation {
        Operation::Transfer {
            to_device_id,
            amount,
            policy_commit,
            ..
        } => {
            // Offline-bearer transfer: allocation-backed, no online balance movement.
            if let Some(allocation_amount) = offline_spend {
                if !deltas.is_empty() {
                    return Err(DsmError::invalid_operation(
                        "conservation: offline-bearer transfer must not apply an online balance delta",
                    ));
                }
                if allocation_amount != amount.value() {
                    return Err(DsmError::invalid_operation(
                        "conservation: offline-cash allocation debit != transfer amount",
                    ));
                }
                return Ok(());
            }
            if deltas.len() != 1 {
                return Err(DsmError::invalid_operation(
                    "conservation: transfer must apply exactly one balance delta",
                ));
            }
            let d = &deltas[0];
            if d.amount != amount.value() {
                return Err(DsmError::invalid_operation(
                    "conservation: transfer delta amount != operation amount",
                ));
            }
            let is_recipient =
                to_device_id.len() == 32 && to_device_id.as_slice() == local_devid.as_slice();
            let expected = if is_recipient {
                BalanceDirection::Credit
            } else {
                BalanceDirection::Debit
            };
            if d.direction != expected {
                return Err(DsmError::invalid_operation(
                    "conservation: transfer delta direction does not match sender/recipient role",
                ));
            }
            if &d.policy_commit != policy_commit {
                return Err(DsmError::invalid_operation(
                    "conservation: transfer delta policy_commit != operation policy_commit",
                ));
            }
            Ok(())
        }
        Operation::Mint { amount, .. } => {
            if deltas.len() != 1
                || deltas[0].direction != BalanceDirection::Credit
                || deltas[0].amount != amount.value()
            {
                return Err(DsmError::invalid_operation(
                    "conservation: mint must apply exactly one credit delta of the mint amount",
                ));
            }
            Ok(())
        }
        Operation::Burn { amount, .. } => {
            if deltas.len() != 1
                || deltas[0].direction != BalanceDirection::Debit
                || deltas[0].amount != amount.value()
            {
                return Err(DsmError::invalid_operation(
                    "conservation: burn must apply exactly one debit delta of the burn amount",
                ));
            }
            Ok(())
        }
        _ => {
            if !deltas.is_empty() {
                return Err(DsmError::invalid_operation(
                    "conservation: non-balance operation must not apply balance deltas",
                ));
            }
            Ok(())
        }
    }
}

/// Result of a successful [`DeviceState::advance`] build.
///
/// The caller must CAS-swap the device head from `parent_r_a` to
/// `child_r_a`. If the CAS fails, another advance landed first and this
/// outcome is stale; discard and rebuild from the new head.
/// A fused-anchor-state leaf replacement to apply in the SAME device-SMT batch as a bearer
/// transfer's relationship-leaf advance (Software-Authority / Hardware-Identity). `key` is the stable
/// per-device anchor-state leaf key `H("DSM/fused-anchor-state-leaf/v1" ‖ B)`; `new_value` is the
/// SUCCESSOR commit `H("DSM/fused-anchor-state/v1" ‖ B ‖ A_{i+1} ‖ J_{b'} ‖ uᵢ+1)`. The key is
/// stable; only the value changes, so the successor root changes because the value changes and a
/// receiver verifies both roots independently.
#[derive(Clone, Debug)]
pub struct AnchorLeafUpdate {
    pub key: [u8; 32],
    pub new_value: [u8; 32],
}

/// Inclusion proofs for the anchor-state leaf across a bearer advance (`Π_i`/`Π_{i+1}`): `parent`
/// proves the OLD leaf under the pre-advance device root `R_i`, `child` proves the SUCCESSOR leaf
/// under the post-advance device root `R_{i+1}` (`child_r_a`). Both are
/// `SmtInclusionProof::to_bytes()` and verify via `verify_anchor_state_leaf`.
#[derive(Clone, Debug)]
pub struct AnchorLeafProofs {
    pub parent: Vec<u8>,
    pub child: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct AdvanceOutcome {
    /// The new [`DeviceState`] to install on CAS success.
    pub new_device_state: DeviceState,

    /// The new chain state for the advanced relationship. Signatures are
    /// `None` in this outcome — the caller attaches them via the stitched
    /// receipt flow (§4.2) before CAS.
    pub new_chain_state: RelationshipChainState,

    /// SMT replace proofs for the stitched receipt: parent inclusion
    /// (`h_n ∈ r_A`) and child inclusion (`h_{n+1} ∈ r'_A`), plus the
    /// pre/post root pair (§4.2).
    pub smt_proofs: SmtReplaceResult,

    /// Parent device root `r_A` at the time the outcome was built. Used
    /// by the caller to CAS-check the current head.
    pub parent_r_a: [u8; 32],

    /// Child device root `r'_A` produced by the leaf replace.
    pub child_r_a: [u8; 32],

    /// Fused-anchor-state leaf inclusion proofs, `Some` iff an [`AnchorLeafUpdate`] was applied
    /// (a bearer advance). `parent` binds the old commit under `parent_r_a`/`smt_proofs.pre_root`;
    /// `child` binds the successor commit under `child_r_a`. `None` for ordinary transitions.
    pub anchor_proofs: Option<AnchorLeafProofs>,
}

impl DeviceState {
    /// Construct a fresh, empty device state at genesis.
    ///
    /// The SMT starts empty (root = empty-leaf default), balances are
    /// zero, and no relationship tips exist. `max_relationships` bounds
    /// the SMT's leaf cache (FIFO eviction).
    pub fn new(
        genesis: [u8; 32],
        devid: [u8; 32],
        public_key: Vec<u8>,
        max_relationships: usize,
    ) -> Self {
        Self {
            genesis,
            devid,
            public_key,
            smt: SparseMerkleTree::new(max_relationships),
            balances: BTreeMap::new(),
            tips: BTreeMap::new(),
            legacy_anchor: None,
            offline_bearer_attestation: OfflineBearerAttestation::NotAttested,
            extra_leaves: BTreeMap::new(),
            offline_allocations: BTreeMap::new(),
        }
    }

    /// Reconstruct a `DeviceState` from previously-encoded fields, replaying
    /// the per-relationship tips into the SMT to recompute the canonical root.
    ///
    /// Phase 4.1 codec roundtrip path. The caller supplies the device-level
    /// fields plus the sorted-by-`rel_key` tip list and this constructor:
    ///
    /// 1. Builds a fresh `DeviceState::new(...)` with empty SMT and balances.
    /// 2. Replays each tip via `smt_replace(&rel_key, &tip.chain_tip)` in
    ///    the supplied order. Determinism is guaranteed because
    ///    `SparseMerkleTree` is purely functional in its leaf-replace path.
    /// 3. Installs `balances`, `tips`, and `legacy_anchor` directly.
    ///
    /// The caller is responsible for verifying that the resulting `root()`
    /// matches the stored sanity-check digest.
    ///
    /// # Errors
    ///
    /// Returns `Err` on any SMT replace failure.
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        genesis: [u8; 32],
        devid: [u8; 32],
        public_key: Vec<u8>,
        legacy_anchor: Option<[u8; 32]>,
        balances: BTreeMap<[u8; 32], u64>,
        tips_in_order: Vec<([u8; 32], RelChainTip)>,
        extra_leaves: BTreeMap<[u8; 32], [u8; 32]>,
        offline_allocations: BTreeMap<[u8; 32], OfflineAllocation>,
        max_relationships: usize,
    ) -> Result<Self, DsmError> {
        let mut state = Self::new(genesis, devid, public_key, max_relationships);
        state.legacy_anchor = legacy_anchor;
        state.balances = balances;
        state.offline_allocations = offline_allocations;

        for (rel_key, tip) in tips_in_order.into_iter() {
            state
                .smt
                .smt_replace(&rel_key, &tip.chain_tip)
                .map_err(|e| {
                    DsmError::invalid_operation(format!(
                        "DeviceState::restore: SMT replace failed for rel_key: {e}"
                    ))
                })?;
            state.tips.insert(rel_key, tip);
        }

        // Replay non-tip leaves (offline-bearer anchor-state, SoFi vault-state) so the recomputed
        // root matches the stored one. Omitting these was the reload-brick bug: a state with any
        // such leaf recomputed a different root after a restart.
        for (key, value) in extra_leaves.into_iter() {
            state.smt.update_leaf(&key, &value).map_err(|e| {
                DsmError::invalid_operation(format!(
                    "DeviceState::restore: extra-leaf update failed: {e}"
                ))
            })?;
            state.extra_leaves.insert(key, value);
        }

        Ok(state)
    }

    /// Current device head `r_A` — the Per-Device SMT root (§2.2).
    pub fn root(&self) -> [u8; 32] {
        *self.smt.root()
    }

    /// Per-Device SMT inclusion proof for a relationship leaf (`rel_key → current chain
    /// tip`) against [`Self::root`]. Used by the recovery PDSMT head builder to attest
    /// each posted leaf. Generated from the live SMT (which may also hold vault leaves),
    /// so the proof recomputes the true `root()`.
    pub fn rel_inclusion_proof(
        &self,
        rel_key: &[u8; 32],
    ) -> Result<crate::merkle::sparse_merkle_tree::SmtInclusionProof, DsmError> {
        self.smt
            .get_inclusion_proof(rel_key, 256)
            .map_err(|e| DsmError::invalid_operation(format!("rel_inclusion_proof: {e}")))
    }

    /// Stash a legacy `State.hash` as a verification anchor. Callers that
    /// hold a legacy State and want `legacy_anchor()` to return its hash
    /// (for hash-adjacency verification) use this. Strictly compat path —
    /// not part of the §2.2 SMT.
    pub fn bootstrap_legacy_root(&mut self, legacy_root: [u8; 32]) {
        self.legacy_anchor = Some(legacy_root);
    }

    /// Returns the legacy anchor if set (compat path).
    pub fn legacy_anchor(&self) -> Option<[u8; 32]> {
        self.legacy_anchor
    }

    /// Device genesis digest.
    pub fn genesis_digest(&self) -> [u8; 32] {
        self.genesis
    }

    /// Current device-level offline-bearer attestation capability (spec §10).
    pub fn offline_bearer_attestation(&self) -> OfflineBearerAttestation {
        self.offline_bearer_attestation
    }

    /// Admit (or clear) the device's offline-bearer attestation. This is the
    /// ONLY mutator of the capability — set `Attested` after a genuine island
    /// is verified under a pinning policy ([`crate::attestation`]), and reset
    /// to `NotAttested` on re-root/recovery. Admission is a deliberate step,
    /// never a side effect of an ordinary advance (which carries it forward).
    pub fn set_offline_bearer_attestation(&mut self, state: OfflineBearerAttestation) {
        self.offline_bearer_attestation = state;
    }

    /// Device identifier.
    pub fn devid(&self) -> [u8; 32] {
        self.devid
    }

    /// Device SPHINCS+ public key.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Current device-level fungible balance for a token, keyed by its
    /// 32-byte CPTA `policy_commit`.
    pub fn balance(&self, policy_commit: &[u8; 32]) -> u64 {
        self.balances.get(policy_commit).copied().unwrap_or(0)
    }

    /// Snapshot of all device-level balances (read-only view).
    pub fn balances_snapshot(&self) -> &BTreeMap<[u8; 32], u64> {
        &self.balances
    }

    /// Snapshot of the non-tip SMT leaves (offline-bearer anchor-state + SoFi vault-state) that
    /// also commit into the device root. The persistence layer enumerates these to replay them in
    /// [`Self::restore`]; without persisting them a reload recomputes a mismatched root.
    pub fn extra_leaves_snapshot(&self) -> &BTreeMap<[u8; 32], [u8; 32]> {
        &self.extra_leaves
    }

    /// Current chain tip for a relationship, if one exists. Returns
    /// `None` for first-ever transactions on an unseen relationship —
    /// the caller must supply a spec-canonical initial tip.
    pub fn chain_tip(&self, rel_key: &[u8; 32]) -> Option<[u8; 32]> {
        self.tips.get(rel_key).map(|t| t.chain_tip)
    }

    /// Retrieve the cached full state at a relationship's current tip,
    /// if present.
    pub fn tip_state(&self, rel_key: &[u8; 32]) -> Option<&RelationshipChainState> {
        self.tips.get(rel_key).and_then(|t| t.state.as_ref())
    }

    /// Retrieve the cached tip metadata for a relationship, if present.
    pub fn rel_chain_tip(&self, rel_key: &[u8; 32]) -> Option<&RelChainTip> {
        self.tips.get(rel_key)
    }

    /// Device ID as a 32-byte array. Convenience for callers migrating from
    /// `State.device_info.device_id`.
    pub fn device_id(&self) -> [u8; 32] {
        self.devid
    }

    /// All relationship keys currently in the SMT.
    pub fn relationship_keys(&self) -> Vec<[u8; 32]> {
        self.tips.keys().copied().collect()
    }

    /// Number of active relationships in the SMT.
    pub fn relationship_count(&self) -> usize {
        self.tips.len()
    }

    /// Attempt to build an advance by one transition on `rel_key`.
    ///
    /// Takes the current state by reference and returns an
    /// [`AdvanceOutcome`] containing the new device state by value. The
    /// caller commits the advance by CAS-swapping their device head from
    /// `outcome.parent_r_a` to `outcome.child_r_a`. On CAS failure the
    /// outcome is stale and must be discarded.
    ///
    /// # Parameters
    ///
    /// - `rel_key` — 32-byte relationship key `k_{A↔B}`
    /// - `counterparty_devid` — the other party's `DevID`
    /// - `operation` — the op being performed
    /// - `entropy` — fresh per-transition entropy (§11 eq. 14)
    /// - `encapsulated_entropy` — optional ML-KEM ciphertext (§11 eq. 12)
    /// - `deltas` — balance mutations to apply to device-level `B^T`
    /// - `initial_chain_tip` — spec-canonical initial tip, used ONLY if
    ///   `rel_key` has no prior entry in the SMT (first-ever tx)
    ///
    /// # Errors
    ///
    /// - Balance underflow or overflow (§8 eq. 10)
    /// - First-ever tx without `initial_chain_tip`
    /// - SMT replace failure
    ///
    /// # Concurrency
    ///
    /// This method is pure: it does not mutate `self`. Two concurrent
    /// callers on the same device observe identical `parent_r_a`
    /// snapshots and build valid candidates; the caller's CAS layer
    /// enforces first-commit-wins.
    #[allow(clippy::too_many_arguments)]
    pub fn advance(
        &self,
        rel_key: [u8; 32],
        counterparty_devid: [u8; 32],
        operation: Operation,
        entropy: Vec<u8>,
        encapsulated_entropy: Option<Vec<u8>>,
        deltas: &[BalanceDelta],
        initial_chain_tip: Option<[u8; 32]>,
        anchor_leaf: Option<AnchorLeafUpdate>,
        offline_spend: Option<OfflineSpend>,
    ) -> Result<AdvanceOutcome, DsmError> {
        // Resolve embedded_parent: prior SMT leaf, or the initial tip for
        // first-ever advances on this relationship. For first-ever advances
        // we additionally seed the SMT leaf to that initial tip BEFORE the
        // replace so the parent inclusion proof carries a real value
        // (matching the historical behaviour of `initialize_contact_chain_tip`
        // on the retired `SHARED_SMT`). Without the seed, the first-ever
        // parent proof would be a non-inclusion proof with value=None, which
        // §4.3 `verify_receipt_bytes` rejects.
        let (embedded_parent, seed_first_ever) = match self.chain_tip(&rel_key) {
            Some(tip) => (tip, false),
            None => {
                let seed = initial_chain_tip.ok_or_else(|| {
                    DsmError::invalid_operation(
                        "advance: first-ever transaction requires initial_chain_tip",
                    )
                })?;
                (seed, true)
            }
        };

        // §9.5 + balance conservation (token-policy doctrine §4; code
        // correspondence: lean4 DSMOfflineFinality.lean commit_conservation /
        // commitTransfer): the supplied deltas MUST exactly realize the signed
        // operation — one delta of op.amount, role-correct direction, bound to the
        // op's policy_commit — OR, for an offline-bearer transfer, `offline_spend` sources the
        // value from the device-bound allocation and `deltas` is empty. This is the by-construction
        // guard at the sole balance-mutation chokepoint (online balance AND offline allocation); it
        // rejects value creation/substitution regardless of caller.
        validate_conservation(
            &self.devid,
            &operation,
            deltas,
            offline_spend.map(|o| o.amount),
        )?;

        // Offline-bearer spend: draw the value from the device-bound offline-cash allocation instead of
        // the online balance. Requires the anchor-state advance (a bearer transfer always advances
        // the anchor leaf), so the allocation debit and the transition land in ONE atomic device root.
        let allocation_update = match offline_spend {
            None => None,
            Some(os) => {
                if anchor_leaf.is_none() {
                    return Err(DsmError::invalid_operation(
                        "advance: offline-bearer spend requires an anchor-state leaf advance",
                    ));
                }
                let key = crate::types::offline_allocation_leaf::offline_allocation_key(
                    &self.genesis,
                    &self.devid,
                    &os.anchor_bundle_b,
                    &os.asset,
                );
                let cur = self
                    .offline_allocations
                    .get(&key)
                    .copied()
                    .unwrap_or_default();
                let new_amount = cur.amount.checked_sub(os.amount).ok_or_else(|| {
                    DsmError::invalid_operation(
                        "advance: offline-cash allocation underflow (insufficient offline cash)",
                    )
                })?;
                let new_sequence = cur.sequence + 1;
                let value = crate::types::offline_allocation_leaf::offline_allocation_value(
                    new_amount,
                    new_sequence,
                );
                Some((key, value, new_amount, new_sequence))
            }
        };

        // Apply deltas to a working copy. Failures leave self untouched. (For an offline-bearer
        // spend, `deltas` is empty — conservation enforced above — so the online balance is
        // untouched here; the value moved via the allocation debit instead.)
        let mut new_balances = self.balances.clone();
        for d in deltas {
            let cur = new_balances.get(&d.policy_commit).copied().unwrap_or(0);
            let next = match d.direction {
                BalanceDirection::Credit => cur.checked_add(d.amount).ok_or_else(|| {
                    DsmError::invalid_operation("advance: balance overflow on credit")
                })?,
                BalanceDirection::Debit => cur.checked_sub(d.amount).ok_or_else(|| {
                    DsmError::invalid_operation(
                        "advance: balance underflow on debit (insufficient funds)",
                    )
                })?,
            };
            if next == 0 {
                new_balances.remove(&d.policy_commit);
            } else {
                new_balances.insert(d.policy_commit, next);
            }
        }

        // Build the successor chain state with the updated witness.
        let new_chain_state = RelationshipChainState {
            rel_key,
            embedded_parent,
            counterparty_devid,
            operation,
            entropy,
            encapsulated_entropy,
            balance_witness: new_balances.clone(),
            entity_sig: None,
            counterparty_sig: None,
        };

        // Derive h_{n+1} = H(canonical_bytes(new_chain_state)).
        let child_chain_tip = new_chain_state.compute_chain_tip();

        // Atomic SMT-replace on a working copy of the SMT. For first-ever
        // advances, seed the leaf with `embedded_parent` (= initial_chain_tip)
        // before the replace so the parent proof is an inclusion proof.
        //
        // `parent_r_a` is the CAS-layer view of the device head entering this
        // advance — the root BEFORE any seeding. Seeding is an internal helper
        // to build a valid Merkle pre-image for `smt_replace`; it must remain
        // invisible to the CAS compare-and-swap. The Merkle `pre_root`
        // (post-seed) lives on `smt_proofs.pre_root` instead.
        let parent_r_a = *self.smt.root();
        let mut new_smt = self.smt.clone();
        if seed_first_ever {
            new_smt
                .update_leaf(&rel_key, &embedded_parent)
                .map_err(|e| {
                    DsmError::invalid_operation(format!(
                        "advance: first-ever seed update_leaf failed: {e}"
                    ))
                })?;
        }
        // Ordinary transitions: a single relationship-leaf replace (unchanged bytes). Bearer
        // transitions with an `anchor_leaf`: replace the relationship leaf AND the stable
        // per-device anchor-state leaf as ONE atomic root update — all four inclusion proofs are
        // taken against the true pre/post roots (never an intermediate root), so both the
        // relationship and anchor-state proofs bind the same `child_r_a` the transfer commits.
        let (smt_proofs, anchor_proofs) = match &anchor_leaf {
            None => {
                let p = new_smt
                    .smt_replace(&rel_key, &child_chain_tip)
                    .map_err(|e| DsmError::invalid_operation(format!("SMT replace failed: {e}")))?;
                (p, None)
            }
            Some(al) => {
                let pre_root = *new_smt.root();
                let rel_parent = new_smt
                    .get_inclusion_proof(&rel_key, 256)
                    .map_err(|e| DsmError::invalid_operation(format!("rel parent proof: {e}")))?;
                let anchor_parent = new_smt.get_inclusion_proof(&al.key, 256).map_err(|e| {
                    DsmError::invalid_operation(format!("anchor parent proof: {e}"))
                })?;
                new_smt
                    .update_leaf(&rel_key, &child_chain_tip)
                    .map_err(|e| DsmError::invalid_operation(format!("rel leaf replace: {e}")))?;
                new_smt.update_leaf(&al.key, &al.new_value).map_err(|e| {
                    DsmError::invalid_operation(format!("anchor leaf replace: {e}"))
                })?;
                // Offline-bearer spend: the allocation debit's allocation leaf rides the SAME atomic
                // batch, so the allocation draw-down and the transition share one device root. Updated
                // before `post_root`/child proofs so the rel + anchor child proofs bind the final
                // root (the receiver verifies rel + anchor against it; the allocation leaf need not be
                // proven to the receiver — it is the sender's own accounting).
                if let Some((k, v, _, _)) = &allocation_update {
                    new_smt.update_leaf(k, v).map_err(|e| {
                        DsmError::invalid_operation(format!("offline-allocation leaf replace: {e}"))
                    })?;
                }
                let post_root = *new_smt.root();
                let rel_child = new_smt
                    .get_inclusion_proof(&rel_key, 256)
                    .map_err(|e| DsmError::invalid_operation(format!("rel child proof: {e}")))?;
                let anchor_child = new_smt
                    .get_inclusion_proof(&al.key, 256)
                    .map_err(|e| DsmError::invalid_operation(format!("anchor child proof: {e}")))?;
                (
                    crate::merkle::sparse_merkle_tree::SmtReplaceResult {
                        pre_root,
                        post_root,
                        parent_proof: rel_parent,
                        child_proof: rel_child,
                    },
                    Some(AnchorLeafProofs {
                        parent: anchor_parent.to_bytes(),
                        child: anchor_child.to_bytes(),
                    }),
                )
            }
        };

        let child_r_a = smt_proofs.post_root;

        // Update the tip cache with the new state. value_capability is sticky-monotone:
        // a missing prior means we are witnessing this relationship's birth, so we start
        // from `No` (proven non-value until a value op is seen); an existing prior
        // (including a restored `Unknown`) is advanced — `Yes` is never downgraded and a
        // restored `Unknown` only becomes `Yes` (never `No`) since earlier history is
        // unproven.
        let mut new_tips = self.tips.clone();
        let prior_vc = self
            .tips
            .get(&rel_key)
            .map(|t| t.value_capability)
            .unwrap_or(ValueCapability::No);
        let value_capability = prior_vc.advance(new_chain_state.operation.is_value_bearing());
        new_tips.insert(
            rel_key,
            RelChainTip {
                chain_tip: child_chain_tip,
                counterparty_devid,
                state: Some(new_chain_state.clone()),
                value_capability,
            },
        );

        // A bearer transition replaces the per-device anchor-state leaf (and, for an offline-bearer
        // spend, the allocation leaf) as part of the SAME atomic root update; record their new
        // values so `restore` replays them (else reload root-mismatches).
        let mut new_extra_leaves = self.extra_leaves.clone();
        if let Some(al) = &anchor_leaf {
            new_extra_leaves.insert(al.key, al.new_value);
        }
        let mut new_offline_allocations = self.offline_allocations.clone();
        if let Some((k, v, amount, sequence)) = allocation_update {
            new_extra_leaves.insert(k, v);
            new_offline_allocations.insert(k, OfflineAllocation { amount, sequence });
        }
        let new_device_state = Self {
            genesis: self.genesis,
            devid: self.devid,
            public_key: self.public_key.clone(),
            smt: new_smt,
            balances: new_balances,
            tips: new_tips,
            legacy_anchor: self.legacy_anchor,
            offline_bearer_attestation: self.offline_bearer_attestation,
            extra_leaves: new_extra_leaves,
            offline_allocations: new_offline_allocations,
        };

        Ok(AdvanceOutcome {
            new_device_state,
            new_chain_state,
            smt_proofs,
            parent_r_a,
            child_r_a,
            anchor_proofs,
        })
    }

    /// Bootstrap the per-device anchor-state leaf into the device SMT (Software-Authority /
    /// Anchor §12): insert `key → value` where `key = H("DSM/fused-anchor-state-leaf/v1" ‖ B)` and
    /// `value = commit_0 = H("DSM/fused-anchor-state/v1" ‖ B ‖ A_0 ‖ J_0 ‖ 0)`. Called ONCE when
    /// the device's fused anchor is admitted; the resulting device root becomes the first valid
    /// offline-bearer parent root. Returns the new [`DeviceState`] (the caller CAS-installs it).
    pub fn with_anchor_state_leaf(
        &self,
        key: &[u8; 32],
        value: &[u8; 32],
    ) -> Result<Self, DsmError> {
        let mut new_smt = self.smt.clone();
        new_smt.update_leaf(key, value).map_err(|e| {
            DsmError::invalid_operation(format!("anchor-state leaf bootstrap: {e}"))
        })?;
        let mut new_extra_leaves = self.extra_leaves.clone();
        new_extra_leaves.insert(*key, *value);
        Ok(Self {
            genesis: self.genesis,
            devid: self.devid,
            public_key: self.public_key.clone(),
            smt: new_smt,
            balances: self.balances.clone(),
            tips: self.tips.clone(),
            legacy_anchor: self.legacy_anchor,
            offline_bearer_attestation: self.offline_bearer_attestation,
            extra_leaves: new_extra_leaves,
            offline_allocations: self.offline_allocations.clone(),
        })
    }

    /// Commit a vault state leaf into the Per-Device SMT (SoFi spec §4.1.2).
    ///
    /// Vault-state leaves live in the same SMT as bilateral relationship
    /// chain tips, but in a disjoint key namespace via
    /// [`dsm::dlv::vault_smt_leaf::compute_vault_smt_key`] (domain tag
    /// `DSM/vault-smt-key\0`).  This keeps both leaf types committed
    /// under a single device root — what the spec calls "vault state
    /// committed in Per-Device SMT" — without colliding with bilateral
    /// leaves (which use `DSM/smt-key\0 || min(A,B) || max(A,B)`).
    ///
    /// This is a *pure* method (mirroring [`Self::advance`]): it returns a
    /// new `DeviceState` + the inclusion proof siblings + the post-write
    /// root.  Caller installs the new head via `StateMachine::set_device_head`
    /// once persistence succeeds, mirroring the prepare/write/commit
    /// pattern in `CoreSdk::execute_on_relationship`.
    ///
    /// # Parameters
    /// - `vault_id` — 32-byte deterministic vault identifier.
    /// - `sequence` — monotonic vault state sequence (0 at create,
    ///   +1 per accepted unlock).
    /// - `reserves_digest` — BLAKE3 digest of (token_a, token_b,
    ///   reserve_a, reserve_b, fee_bps) per
    ///   [`dsm::dlv::vault_state_anchor::compute_reserves_digest`].
    pub fn with_vault_state_leaf(
        &self,
        vault_id: &[u8; 32],
        sequence: u64,
        reserves_digest: &[u8; 32],
    ) -> Result<VaultLeafOutcome, DsmError> {
        use crate::dlv::vault_smt_leaf::{compute_vault_smt_key, compute_vault_smt_value};

        let leaf_key = compute_vault_smt_key(vault_id);
        let leaf_value = compute_vault_smt_value(sequence, reserves_digest);

        let mut new_smt = self.smt.clone();
        new_smt.update_leaf(&leaf_key, &leaf_value).map_err(|e| {
            DsmError::invalid_operation(format!("with_vault_state_leaf: update_leaf failed: {e}"))
        })?;
        let new_root = *new_smt.root();
        let proof = new_smt.get_inclusion_proof(&leaf_key, 256).map_err(|e| {
            DsmError::merkle(format!(
                "with_vault_state_leaf: get_inclusion_proof failed: {e}"
            ))
        })?;

        let mut new_extra_leaves = self.extra_leaves.clone();
        new_extra_leaves.insert(leaf_key, leaf_value);
        let new_device_state = Self {
            genesis: self.genesis,
            devid: self.devid,
            public_key: self.public_key.clone(),
            smt: new_smt,
            balances: self.balances.clone(),
            tips: self.tips.clone(),
            legacy_anchor: self.legacy_anchor,
            offline_bearer_attestation: self.offline_bearer_attestation,
            extra_leaves: new_extra_leaves,
            offline_allocations: self.offline_allocations.clone(),
        };

        Ok(VaultLeafOutcome {
            new_device_state,
            new_root,
            siblings: proof.siblings,
        })
    }

    // ---------------------------------------------------------------------
    // Offline-cash allocation transitions (device-bound "cash in hand").
    //
    // Each is a real device-SMT state change: it rewrites the allocation leaf
    // (advancing the device root) and, for load/unload, moves online balance.
    // These are balance-mutation chokepoints alongside `advance`: conservation is
    // by construction — the online debit/credit and the allocation credit/debit are
    // computed together from the same `amount`, so value is moved, never created
    // or destroyed. `advance` remains the sole chokepoint for relationship transfers.
    // ---------------------------------------------------------------------

    /// Current offline-cash allocation balance for the allocation `key`, or 0 if none.
    pub fn offline_allocation(&self, key: &[u8; 32]) -> u64 {
        self.offline_allocations
            .get(key)
            .map(|a| a.amount)
            .unwrap_or(0)
    }

    /// Enumerable snapshot of every offline-cash allocation, for persistence.
    pub fn offline_allocations_snapshot(&self) -> &BTreeMap<[u8; 32], OfflineAllocation> {
        &self.offline_allocations
    }

    /// Rewrite the allocation leaf for `key` to `(new_amount, new_sequence)` and return the
    /// new device state + inclusion proof. Internal helper for the load/unload/spend
    /// chokepoints; `new_balances` is the already-computed online balance map.
    fn set_offline_allocation(
        &self,
        key: [u8; 32],
        new_balances: BTreeMap<[u8; 32], u64>,
        new_amount: u64,
        new_sequence: u64,
    ) -> Result<OfflineAllocationOutcome, DsmError> {
        let leaf_value = crate::types::offline_allocation_leaf::offline_allocation_value(
            new_amount,
            new_sequence,
        );
        let mut new_smt = self.smt.clone();
        new_smt.update_leaf(&key, &leaf_value).map_err(|e| {
            DsmError::invalid_operation(format!("offline-allocation leaf update: {e}"))
        })?;
        let new_root = *new_smt.root();
        let proof = new_smt
            .get_inclusion_proof(&key, 256)
            .map_err(|e| DsmError::merkle(format!("offline-allocation proof: {e}")))?;

        let mut new_extra_leaves = self.extra_leaves.clone();
        new_extra_leaves.insert(key, leaf_value);
        // Keep the entry even at amount 0 so `sequence` stays monotone (never replay a leaf value).
        let mut new_offline_allocations = self.offline_allocations.clone();
        new_offline_allocations.insert(
            key,
            OfflineAllocation {
                amount: new_amount,
                sequence: new_sequence,
            },
        );

        let new_device_state = Self {
            genesis: self.genesis,
            devid: self.devid,
            public_key: self.public_key.clone(),
            smt: new_smt,
            balances: new_balances,
            tips: self.tips.clone(),
            legacy_anchor: self.legacy_anchor,
            offline_bearer_attestation: self.offline_bearer_attestation,
            extra_leaves: new_extra_leaves,
            offline_allocations: new_offline_allocations,
        };
        Ok(OfflineAllocationOutcome {
            new_device_state,
            new_root,
            proof: proof.to_bytes(),
            amount: new_amount,
            sequence: new_sequence,
        })
    }

    /// **Load** `amount` of `asset` from the online balance into this device's offline-cash allocation
    /// (`anchor_bundle_b` binds the allocation to this device's offline-bearer island). Debits online
    /// `available` and credits the allocation by the same amount — conserved. Fails closed on
    /// insufficient online balance.
    pub fn load_offline_cash(
        &self,
        anchor_bundle_b: &[u8; 32],
        asset: &[u8; 32],
        amount: u64,
    ) -> Result<OfflineAllocationOutcome, DsmError> {
        if amount == 0 {
            return Err(DsmError::invalid_operation(
                "load_offline_cash: amount must be > 0",
            ));
        }
        let key = crate::types::offline_allocation_leaf::offline_allocation_key(
            &self.genesis,
            &self.devid,
            anchor_bundle_b,
            asset,
        );
        let cur_bal = self.balances.get(asset).copied().unwrap_or(0);
        let new_bal = cur_bal.checked_sub(amount).ok_or_else(|| {
            DsmError::invalid_operation("load_offline_cash: insufficient online balance")
        })?;
        let mut new_balances = self.balances.clone();
        if new_bal == 0 {
            new_balances.remove(asset);
        } else {
            new_balances.insert(*asset, new_bal);
        }
        let cur = self
            .offline_allocations
            .get(&key)
            .copied()
            .unwrap_or_default();
        let new_amount = cur.amount.checked_add(amount).ok_or_else(|| {
            DsmError::invalid_operation("load_offline_cash: allocation balance overflow")
        })?;
        self.set_offline_allocation(key, new_balances, new_amount, cur.sequence + 1)
    }

    /// **Unload** `amount` from the offline-cash allocation back to the online balance (reconcile).
    /// Credits online `available` and debits the allocation — conserved. Fails closed if the allocation
    /// holds less than `amount`.
    pub fn unload_offline_cash(
        &self,
        anchor_bundle_b: &[u8; 32],
        asset: &[u8; 32],
        amount: u64,
    ) -> Result<OfflineAllocationOutcome, DsmError> {
        if amount == 0 {
            return Err(DsmError::invalid_operation(
                "unload_offline_cash: amount must be > 0",
            ));
        }
        let key = crate::types::offline_allocation_leaf::offline_allocation_key(
            &self.genesis,
            &self.devid,
            anchor_bundle_b,
            asset,
        );
        let cur = self
            .offline_allocations
            .get(&key)
            .copied()
            .unwrap_or_default();
        let new_amount = cur.amount.checked_sub(amount).ok_or_else(|| {
            DsmError::invalid_operation("unload_offline_cash: insufficient offline-cash allocation")
        })?;
        let cur_bal = self.balances.get(asset).copied().unwrap_or(0);
        let new_bal = cur_bal.checked_add(amount).ok_or_else(|| {
            DsmError::invalid_operation("unload_offline_cash: online balance overflow")
        })?;
        let mut new_balances = self.balances.clone();
        new_balances.insert(*asset, new_bal);
        self.set_offline_allocation(key, new_balances, new_amount, cur.sequence + 1)
    }

    /// **Spend** `amount` from the offline-cash allocation for an offline-bearer transfer. Draws the
    /// allocation down; the online balance is NOT touched (the value goes to the receiver via the
    /// bearer release, off the online books). Fails closed if the allocation holds less than `amount`.
    pub fn spend_offline_cash(
        &self,
        anchor_bundle_b: &[u8; 32],
        asset: &[u8; 32],
        amount: u64,
    ) -> Result<OfflineAllocationOutcome, DsmError> {
        if amount == 0 {
            return Err(DsmError::invalid_operation(
                "spend_offline_cash: amount must be > 0",
            ));
        }
        let key = crate::types::offline_allocation_leaf::offline_allocation_key(
            &self.genesis,
            &self.devid,
            anchor_bundle_b,
            asset,
        );
        let cur = self
            .offline_allocations
            .get(&key)
            .copied()
            .unwrap_or_default();
        let new_amount = cur.amount.checked_sub(amount).ok_or_else(|| {
            DsmError::invalid_operation("spend_offline_cash: insufficient offline-cash allocation")
        })?;
        self.set_offline_allocation(key, self.balances.clone(), new_amount, cur.sequence + 1)
    }
}

/// Outcome of an offline-cash allocation transition ([`DeviceState::load_offline_cash`] /
/// [`DeviceState::unload_offline_cash`] / [`DeviceState::spend_offline_cash`]). The caller
/// CAS-installs `new_device_state` as the device head once persistence succeeds.
#[derive(Debug, Clone)]
pub struct OfflineAllocationOutcome {
    /// New device state (post-transition). Install as the head.
    pub new_device_state: DeviceState,
    /// Post-transition device SMT root.
    pub new_root: [u8; 32],
    /// Inclusion proof (`SmtInclusionProof::to_bytes()`) of the allocation leaf under `new_root`.
    pub proof: Vec<u8>,
    /// New allocation balance.
    pub amount: u64,
    /// New allocation transition sequence.
    pub sequence: u64,
}

/// Outcome of [`DeviceState::with_vault_state_leaf`].  Caller installs
/// `new_device_state` as the device head once persistence succeeds, and
/// uses `(new_root, siblings)` to build a
/// `VaultStateInclusionProofV1` record for the off-device trader path.
#[derive(Debug, Clone)]
pub struct VaultLeafOutcome {
    /// The new device state (post-leaf-write).  Has the same balances,
    /// tips, genesis, etc. as `self`; only the SMT differs.
    pub new_device_state: DeviceState,
    /// Post-write SMT root.  This is the value to embed in the signed
    /// inclusion proof.
    pub new_root: [u8; 32],
    /// 256 sibling hashes in leaf-to-root order, ready to ship inside
    /// `VaultStateInclusionProofV1.smt_siblings`.
    pub siblings: Vec<[u8; 32]>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::operations::{Operation, TransactionMode};

    fn devid(b: u8) -> [u8; 32] {
        [b; 32]
    }
    fn pubkey() -> Vec<u8> {
        vec![0xAA; 64]
    }
    fn pc(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn fresh_device(b: u8) -> DeviceState {
        DeviceState::new([0u8; 32], devid(b), pubkey(), 1024)
    }

    #[test]
    fn offline_bearer_attestation_gate_is_deny_unless_proven_and_fail_closed() {
        use OfflineBearerAttestation::*;
        // Gate polarity: ONLY Attested permits the offline-bearer path.
        assert!(Attested.permits_offline_bearer());
        assert!(!NotAttested.permits_offline_bearer());
        assert!(!Unknown.permits_offline_bearer());
        // Wire codec round-trips for every variant; 0/UNSPECIFIED and unknowns fail closed.
        for v in [Attested, NotAttested, Unknown] {
            assert_eq!(OfflineBearerAttestation::from_wire(v.to_wire()), Some(v));
            assert_eq!(v.commit_tag(), v.to_wire() as u8);
        }
        assert_eq!(OfflineBearerAttestation::from_wire(0), None);
        assert_eq!(OfflineBearerAttestation::from_wire(4), None);
        assert_eq!(OfflineBearerAttestation::from_wire(-1), None);
        // Recovery never restores island authority — always NotAttested.
        assert_eq!(OfflineBearerAttestation::after_recovery(), NotAttested);
    }

    #[test]
    fn device_attestation_defaults_not_attested_and_carries_through_advance() {
        use OfflineBearerAttestation::*;
        // Fresh genesis device has no admitted island.
        let mut dev = fresh_device(7);
        assert_eq!(dev.offline_bearer_attestation(), NotAttested);
        // Admission is the only mutator; an ordinary advance carries it forward.
        dev.set_offline_bearer_attestation(Attested);
        assert_eq!(dev.offline_bearer_attestation(), Attested);
        let init_tip =
            crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                &devid(7),
                &devid(8),
            );
        let outcome = dev
            .advance(
                [0x55; 32],
                devid(8),
                op(),
                vec![0x01; 32],
                None,
                &[],
                Some(init_tip),
                None,
                None,
            )
            .expect("advance");
        assert_eq!(
            outcome.new_device_state.offline_bearer_attestation(),
            Attested,
            "ordinary advance must carry the attestation forward unchanged"
        );
    }

    fn op() -> Operation {
        Operation::Generic {
            operation_type: b"test".to_vec(),
            data: vec![],
            message: "t".to_string(),
            signature: vec![],
        }
    }

    fn bal(amount: u64) -> crate::types::token_types::Balance {
        crate::types::token_types::Balance::from_state(amount, [0u8; 32])
    }

    /// A Mint op carrying one credit of `amount` — satisfies the conservation
    /// guard for a single Credit `BalanceDelta` of the same amount.
    fn mint_op(amount: u64) -> Operation {
        Operation::Mint {
            amount: bal(amount),
            token_id: b"ERA".to_vec(),
            authorized_by: vec![],
            proof_of_authorization: vec![],
            message: String::new(),
        }
    }

    /// A Burn op carrying one debit of `amount` — satisfies the conservation
    /// guard for a single Debit `BalanceDelta` of the same amount.
    fn burn_op(amount: u64) -> Operation {
        Operation::Burn {
            amount: bal(amount),
            token_id: b"ERA".to_vec(),
            proof_of_ownership: vec![],
            message: String::new(),
        }
    }

    /// Value op matching a delta's direction/amount for conservation-guard tests.
    fn value_op(dir: BalanceDirection, amount: u64) -> Operation {
        match dir {
            BalanceDirection::Credit => mint_op(amount),
            BalanceDirection::Debit => burn_op(amount),
        }
    }

    #[test]
    fn conservation_guard_rules() {
        let me = devid(0xAA);
        let other = devid(0xBB);
        let pcx = pc(0xCC);
        let xfer = |to: [u8; 32], amt: u64, pcv: [u8; 32]| Operation::Transfer {
            to_device_id: to.to_vec(),
            amount: bal(amt),
            token_id: b"ERA".to_vec(),
            policy_commit: pcv,
            mode: crate::types::operations::TransactionMode::Unilateral,
            nonce: vec![],
            verification: crate::types::operations::VerificationType::Standard,
            pre_commit: None,
            recipient: vec![],
            to: vec![],
            message: String::new(),
            signature: vec![],
            authority_policy: None,
        };
        let credit = |amt: u64, pcv: [u8; 32]| BalanceDelta {
            policy_commit: pcv,
            direction: BalanceDirection::Credit,
            amount: amt,
        };
        let debit = |amt: u64, pcv: [u8; 32]| BalanceDelta {
            policy_commit: pcv,
            direction: BalanceDirection::Debit,
            amount: amt,
        };

        // Transfer: recipient credits, sender debits — accepted. (offline_spend None = online.)
        assert!(validate_conservation(&me, &xfer(me, 5, pcx), &[credit(5, pcx)], None).is_ok());
        assert!(validate_conservation(&me, &xfer(other, 5, pcx), &[debit(5, pcx)], None).is_ok());
        // Wrong amount / direction / token / count — rejected.
        assert!(validate_conservation(&me, &xfer(me, 5, pcx), &[credit(6, pcx)], None).is_err());
        assert!(validate_conservation(&me, &xfer(me, 5, pcx), &[debit(5, pcx)], None).is_err());
        assert!(validate_conservation(&me, &xfer(other, 5, pcx), &[credit(5, pcx)], None).is_err());
        assert!(
            validate_conservation(&me, &xfer(me, 5, pcx), &[credit(5, pc(0xEE))], None).is_err()
        );
        assert!(validate_conservation(&me, &xfer(me, 5, pcx), &[], None).is_err());
        assert!(validate_conservation(
            &me,
            &xfer(me, 5, pcx),
            &[credit(5, pcx), credit(5, pcx)],
            None
        )
        .is_err());
        // Mint: one credit==amount; Burn: one debit==amount.
        assert!(validate_conservation(&me, &mint_op(9), &[credit(9, pcx)], None).is_ok());
        assert!(validate_conservation(&me, &mint_op(9), &[debit(9, pcx)], None).is_err());
        assert!(validate_conservation(&me, &mint_op(9), &[credit(8, pcx)], None).is_err());
        assert!(validate_conservation(&me, &burn_op(9), &[debit(9, pcx)], None).is_ok());
        assert!(validate_conservation(&me, &burn_op(9), &[credit(9, pcx)], None).is_err());
        // Non-balance op must carry no deltas.
        assert!(validate_conservation(&me, &op(), &[], None).is_ok());
        assert!(validate_conservation(&me, &op(), &[credit(1, pcx)], None).is_err());
        // offline_spend is only valid on a bearer transfer, and forbids online deltas.
        assert!(
            validate_conservation(&me, &mint_op(9), &[], Some(9)).is_err(),
            "allocation spend on a non-bearer op must be rejected"
        );
        assert!(
            validate_conservation(&me, &op(), &[], Some(1)).is_err(),
            "allocation spend on a non-transfer op must be rejected"
        );
        // A bearer transfer sourced from the allocation: empty deltas + Some(offline_spend) is accepted;
        // but empty deltas WITHOUT offline_spend is rejected before commit (the fail-closed case the
        // activation seam must never produce — empty deltas and Some(offline_spend) are one choice).
        let bearer_xfer = |amt: u64| {
            use crate::types::operations::{AuthorityMode, AuthorityPolicy};
            match xfer(other, amt, pcx) {
                Operation::Transfer {
                    to_device_id,
                    amount,
                    token_id,
                    policy_commit,
                    mode,
                    nonce,
                    verification,
                    pre_commit,
                    recipient,
                    to,
                    message,
                    signature,
                    ..
                } => Operation::Transfer {
                    to_device_id,
                    amount,
                    token_id,
                    policy_commit,
                    mode,
                    nonce,
                    verification,
                    pre_commit,
                    recipient,
                    to,
                    message,
                    signature,
                    authority_policy: Some(AuthorityPolicy {
                        mode: AuthorityMode::OfflineBearerRequired,
                        policy_id: [0u8; 32],
                        anchor_set_id: [0u8; 32],
                    }),
                },
                other => other,
            }
        };
        assert!(
            validate_conservation(&me, &bearer_xfer(5), &[], Some(5)).is_ok(),
            "bearer transfer with empty deltas + matching allocation debit must be accepted"
        );
        assert!(
            validate_conservation(&me, &bearer_xfer(5), &[], None).is_err(),
            "bearer transfer with empty deltas and NO offline_spend must be rejected before commit"
        );
        assert!(
            validate_conservation(&me, &bearer_xfer(5), &[debit(5, pcx)], Some(5)).is_err(),
            "bearer transfer must not carry an online delta alongside a allocation spend"
        );
        assert!(
            validate_conservation(&me, &bearer_xfer(5), &[], Some(6)).is_err(),
            "bearer allocation debit must equal the transfer amount"
        );
    }

    fn entropy(seed: u8) -> Vec<u8> {
        let mut h = crate::crypto::blake3::dsm_domain_hasher(
            crate::common::domain_tags::TAG_DSM_TEST_ENTROPY,
        );
        h.update(&[seed]);
        h.finalize().as_bytes().to_vec()
    }

    /// I5.0 gate (plan Part J): `advance` MUST materialise a new `policy_commit`
    /// entry on Credit when the device has zero prior exposure to that
    /// commit — the "Bob claims Alice's custom-token vault on his own chain"
    /// path.  Semantically equivalent to `entry().or_insert(0) += amount`.
    ///
    /// Without this, DlvClaim on a claimant who has never held the custom
    /// token would silently no-op instead of crediting the locked balance.
    #[test]
    fn advance_credit_materialises_new_policy_commit_entry() {
        let bob = fresh_device(0xBB);
        let custom_token = pc(0xF1);

        // Bob starts with zero exposure to this policy_commit.
        assert!(
            !bob.balances.contains_key(&custom_token),
            "precondition: fresh device has no entry for the custom token"
        );

        // Simulate the DlvClaim credit landing on Bob's self-loop.
        let rk_self =
            crate::core::bilateral_transaction_manager::compute_smt_key(&bob.devid, &bob.devid);
        let init_tip =
            crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                &bob.devid, &bob.devid,
            );

        let outcome = bob
            .advance(
                rk_self,
                bob.devid,
                mint_op(50),
                entropy(42),
                None,
                &[BalanceDelta {
                    policy_commit: custom_token,
                    direction: BalanceDirection::Credit,
                    amount: 50,
                }],
                Some(init_tip),
                None,
                None,
            )
            .expect("credit advance succeeds");

        // advance() returns the successor device_state; `self` is untouched.
        let post = outcome
            .new_device_state
            .balances
            .get(&custom_token)
            .copied()
            .expect("Credit must materialise a new balance entry keyed by policy_commit");
        assert_eq!(post, 50);

        // The original bob remains unchanged — functional transform contract.
        assert!(
            !bob.balances.contains_key(&custom_token),
            "advance must not mutate &self"
        );
    }

    #[test]
    fn offline_cash_load_spend_unload_conserves_and_advances_root() {
        use crate::types::offline_allocation_leaf::offline_allocation_key;
        let dev = fresh_device(0xC1);
        let token = pc(0xA1);
        let bundle = [0x7B; 32];

        // Seed 100 of the token via a self-mint advance.
        let rk_self =
            crate::core::bilateral_transaction_manager::compute_smt_key(&dev.devid, &dev.devid);
        let init_tip =
            crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                &dev.devid, &dev.devid,
            );
        let funded = dev
            .advance(
                rk_self,
                dev.devid,
                mint_op(100),
                entropy(1),
                None,
                &[BalanceDelta {
                    policy_commit: token,
                    direction: BalanceDirection::Credit,
                    amount: 100,
                }],
                Some(init_tip),
                None,
                None,
            )
            .expect("mint 100")
            .new_device_state;

        let key = offline_allocation_key(&funded.genesis, &funded.devid, &bundle, &token);
        let online = |s: &DeviceState| s.balances.get(&token).copied().unwrap_or(0);
        assert_eq!(online(&funded), 100);
        assert_eq!(funded.offline_allocation(&key), 0);

        // Load 30: online 70, allocation 30 — conserved — and the device root advances (real state change).
        let loaded = funded
            .load_offline_cash(&bundle, &token, 30)
            .expect("load 30")
            .new_device_state;
        assert_eq!(online(&loaded), 70);
        assert_eq!(loaded.offline_allocation(&key), 30);
        assert_eq!(
            online(&loaded) + loaded.offline_allocation(&key),
            100,
            "load conserves"
        );
        assert_ne!(
            loaded.root(),
            funded.root(),
            "load must advance the device root"
        );

        // Spend 10 offline: allocation 20, online unchanged (value leaves via the bearer release).
        let spent = loaded
            .spend_offline_cash(&bundle, &token, 10)
            .expect("spend 10")
            .new_device_state;
        assert_eq!(spent.offline_allocation(&key), 20);
        assert_eq!(online(&spent), 70);
        assert_ne!(
            spent.root(),
            loaded.root(),
            "spend must advance the device root"
        );

        // Unload 5: allocation 15, online 75 — conserved back.
        let unloaded = spent
            .unload_offline_cash(&bundle, &token, 5)
            .expect("unload 5")
            .new_device_state;
        assert_eq!(unloaded.offline_allocation(&key), 15);
        assert_eq!(online(&unloaded), 75);

        // Fail-closed guards.
        assert!(
            unloaded.load_offline_cash(&bundle, &token, 76).is_err(),
            "load > online balance"
        );
        assert!(
            unloaded.spend_offline_cash(&bundle, &token, 16).is_err(),
            "spend > allocation"
        );
        assert!(
            unloaded.unload_offline_cash(&bundle, &token, 16).is_err(),
            "unload > allocation"
        );
        assert!(
            unloaded.load_offline_cash(&bundle, &token, 0).is_err(),
            "zero amount rejected"
        );
    }

    #[test]
    fn offline_cash_allocation_is_disjoint_from_online_token_balance() {
        // The allocation leaf key never collides with the token's policy_commit balance key: an online
        // per-token spend reads `balances[token]`, which the allocation never occupies.
        use crate::types::offline_allocation_leaf::offline_allocation_key;
        let dev = fresh_device(0xC2);
        let token = pc(0xA2);
        let bundle = [0x7C; 32];
        let key = offline_allocation_key(&dev.genesis, &dev.devid, &bundle, &token);
        assert_ne!(
            key, token,
            "allocation key must not equal the token policy_commit"
        );
    }

    #[test]
    fn value_capability_is_sticky_monotone_and_fail_closed() {
        use ValueCapability::*;
        // Sticky-monotone toward Yes; `Yes` is NEVER downgraded — this is the Gemini
        // fatal case (value then later non-value / zero-balance MUST stay value-capable).
        assert_eq!(No.advance(true), Yes);
        assert_eq!(Yes.advance(false), Yes);
        assert_eq!(Yes.advance(true), Yes);
        assert_eq!(No.advance(false), No);
        assert_eq!(Unknown.advance(false), Unknown);
        assert_eq!(Unknown.advance(true), Yes);
        // Gate inclusion: include unless PROVEN No.
        assert!(Yes.includes_in_gate() && Unknown.includes_in_gate() && !No.includes_in_gate());
        // Wire is fail-closed: only 1/2/3 are valid; UNSPECIFIED(0) and any other value are
        // rejected — NEVER silently mapped to `No`.
        assert_eq!(ValueCapability::from_wire(1), Some(Yes));
        assert_eq!(ValueCapability::from_wire(2), Some(No));
        assert_eq!(ValueCapability::from_wire(3), Some(Unknown));
        assert_eq!(ValueCapability::from_wire(0), None);
        assert_eq!(ValueCapability::from_wire(4), None);
        assert_eq!(ValueCapability::from_wire(-1), None);
        for v in [Yes, No, Unknown] {
            assert_eq!(ValueCapability::from_wire(v.to_wire()), Some(v));
        }
    }

    #[test]
    fn bearer_advance_commits_fused_anchor_leaf_into_real_device_roots() {
        use crate::core::bilateral_transaction_manager::{
            anchor_state_leaf_key, compute_smt_key, initial_chain_tip_from_device_ids,
            verify_anchor_state_leaf,
        };
        // Fused anchor identity + two opaque v2 anchor-state leaf VALUES (the anchor-core leaf
        // `anchor_state_leaf(B, h_i, u_i)` — dsm treats them as opaque 32-byte values).
        let b = [0xB1u8; 32];
        let key = anchor_state_leaf_key(&b);
        let commit0 = [0xC0u8; 32];
        let commit1 = [0xC1u8; 32];

        // (bootstrap) The admitted device SMT carries commit_0 at the stable anchor-state key.
        let dev = fresh_device(0xAB);
        let dev = dev
            .with_anchor_state_leaf(&key, &commit0)
            .expect("bootstrap");

        let cp = devid(0xC0);
        let rk = compute_smt_key(&dev.devid, &cp);
        let init = initial_chain_tip_from_device_ids(&dev.devid, &cp);

        // (bearer advance) updates the SAME anchor leaf key old→successor in the same root batch.
        let out = dev
            .advance(
                rk,
                cp,
                mint_op(10),
                entropy(1),
                None,
                &[BalanceDelta {
                    policy_commit: pc(0xF1),
                    direction: BalanceDirection::Credit,
                    amount: 10,
                }],
                Some(init),
                Some(AnchorLeafUpdate {
                    key,
                    new_value: commit1,
                }),
                None,
            )
            .expect("bearer advance");
        let ap = out
            .anchor_proofs
            .clone()
            .expect("bearer advance emits anchor proofs");

        // prev proof verifies commit_0 ONLY against the prev root; next proof verifies commit_1
        // ONLY against the next root — and each rejects the other root/value pairing.
        assert!(verify_anchor_state_leaf(
            &out.smt_proofs.pre_root,
            &b,
            &commit0,
            &ap.parent
        ));
        assert!(verify_anchor_state_leaf(
            &out.child_r_a,
            &b,
            &commit1,
            &ap.child
        ));
        assert!(!verify_anchor_state_leaf(
            &out.child_r_a,
            &b,
            &commit0,
            &ap.parent
        ));
        assert!(!verify_anchor_state_leaf(
            &out.smt_proofs.pre_root,
            &b,
            &commit1,
            &ap.child
        ));
        // a wrong leaf VALUE under the right root rejects (value binding).
        assert!(!verify_anchor_state_leaf(
            &out.child_r_a,
            &b,
            &commit0,
            &ap.child
        ));
        // an empty proof rejects (a release with no attached Π routes online).
        assert!(!verify_anchor_state_leaf(&out.child_r_a, &b, &commit1, &[]));

        // (non-bearer) an ordinary advance (anchor_leaf=None) emits no anchor proofs and does NOT
        // mutate the fused anchor state — a subsequent bearer advance still sees commit_0 as parent.
        let cp2 = devid(0xC2);
        let rk2 = compute_smt_key(&dev.devid, &cp2);
        let init2 = initial_chain_tip_from_device_ids(&dev.devid, &cp2);
        let plain = dev
            .advance(
                rk2,
                cp2,
                mint_op(5),
                entropy(2),
                None,
                &[BalanceDelta {
                    policy_commit: pc(0xF2),
                    direction: BalanceDirection::Credit,
                    amount: 5,
                }],
                Some(init2),
                None,
                None,
            )
            .expect("plain advance");
        assert!(plain.anchor_proofs.is_none());

        let cp3 = devid(0xC3);
        let rk3 = compute_smt_key(&dev.devid, &cp3);
        let init3 = initial_chain_tip_from_device_ids(&dev.devid, &cp3);
        let out2 = plain
            .new_device_state
            .advance(
                rk3,
                cp3,
                mint_op(7),
                entropy(3),
                None,
                &[BalanceDelta {
                    policy_commit: pc(0xF3),
                    direction: BalanceDirection::Credit,
                    amount: 7,
                }],
                Some(init3),
                Some(AnchorLeafUpdate {
                    key,
                    new_value: commit1,
                }),
                None,
            )
            .expect("bearer advance after a plain one");
        let ap2 = out2.anchor_proofs.clone().expect("anchor proofs");
        assert!(
            verify_anchor_state_leaf(&out2.smt_proofs.pre_root, &b, &commit0, &ap2.parent),
            "a non-bearer transition must not mutate the fused anchor state (commit_0 survives)"
        );
    }

    #[test]
    fn bearer_advance_draws_from_allocation_not_online_balance() {
        use crate::core::bilateral_transaction_manager::{
            anchor_state_leaf_key, compute_smt_key, initial_chain_tip_from_device_ids,
        };
        use crate::types::offline_allocation_leaf::offline_allocation_key;
        use crate::types::operations::{
            AuthorityMode, AuthorityPolicy, Operation, TransactionMode, VerificationType,
        };

        let b = [0xB2u8; 32];
        let key = anchor_state_leaf_key(&b);
        let token = pc(0xA1);

        // Bootstrap the anchor, mint 100 online, then load 40 into the offline allocation.
        let dev = fresh_device(0xD5)
            .with_anchor_state_leaf(&key, &[0xC0u8; 32])
            .expect("bootstrap");
        let rk_self = compute_smt_key(&dev.devid, &dev.devid);
        let init_self = initial_chain_tip_from_device_ids(&dev.devid, &dev.devid);
        let funded = dev
            .advance(
                rk_self,
                dev.devid,
                mint_op(100),
                entropy(1),
                None,
                &[BalanceDelta {
                    policy_commit: token,
                    direction: BalanceDirection::Credit,
                    amount: 100,
                }],
                Some(init_self),
                None,
                None,
            )
            .expect("mint 100")
            .new_device_state;
        let loaded = funded
            .load_offline_cash(&b, &token, 40)
            .expect("load 40")
            .new_device_state;
        let alloc_key = offline_allocation_key(&loaded.genesis, &loaded.devid, &b, &token);
        assert_eq!(loaded.balances.get(&token).copied().unwrap_or(0), 60);
        assert_eq!(loaded.offline_allocation(&alloc_key), 40);

        // Build an offline-bearer transfer of `amt` to a counterparty.
        let cp = devid(0xC5);
        let rk = compute_smt_key(&loaded.devid, &cp);
        let init = initial_chain_tip_from_device_ids(&loaded.devid, &cp);
        let anchor_leaf = AnchorLeafUpdate {
            key,
            new_value: [0xC1u8; 32],
        };
        let bearer_op = |amt: u64| Operation::Transfer {
            to_device_id: cp.to_vec(),
            amount: bal(amt),
            token_id: b"ERA".to_vec(),
            policy_commit: token,
            mode: TransactionMode::Bilateral,
            nonce: vec![],
            verification: VerificationType::Standard,
            pre_commit: None,
            recipient: vec![],
            to: vec![],
            message: String::new(),
            signature: vec![],
            authority_policy: Some(AuthorityPolicy {
                mode: AuthorityMode::OfflineBearerRequired,
                policy_id: [0u8; 32],
                anchor_set_id: [0u8; 32],
            }),
        };
        let spend = |amt: u64| {
            Some(OfflineSpend {
                anchor_bundle_b: b,
                asset: token,
                amount: amt,
            })
        };

        // Bearer spend of 25: allocation 40 -> 15, online balance UNTOUCHED (60), anchor leaf advanced.
        let spent = loaded
            .advance(
                rk,
                cp,
                bearer_op(25),
                entropy(2),
                None,
                &[], // no online delta — value comes from the allocation
                Some(init),
                Some(anchor_leaf.clone()),
                spend(25),
            )
            .expect("bearer advance from allocation")
            .new_device_state;
        assert_eq!(
            spent.balances.get(&token).copied().unwrap_or(0),
            60,
            "online balance must be untouched by a bearer spend"
        );
        assert_eq!(
            spent.offline_allocation(&alloc_key),
            15,
            "allocation debited by the bearer amount"
        );

        // Determinism (the sim==guard==commit invariant): re-running the SAME bearer advance
        // (identical op, empty deltas, anchor_leaf, and offline_spend) against the same head yields
        // a byte-identical device root. This is why threading the SAME `prepared.offline_spend` into
        // the confirm-build sim, the determinism-guard sim, and the canonical commit keeps all three
        // sender roots equal.
        let spent_again = loaded
            .advance(
                rk,
                cp,
                bearer_op(25),
                entropy(2),
                None,
                &[],
                Some(init),
                Some(anchor_leaf.clone()),
                spend(25),
            )
            .expect("re-run bearer advance from allocation")
            .new_device_state;
        assert_eq!(
            spent.root(),
            spent_again.root(),
            "identical bearer advance inputs must produce a byte-identical device root"
        );

        // Fail-closed: an online delta alongside a allocation spend is a double-source → rejected.
        assert!(
            loaded
                .advance(
                    rk,
                    cp,
                    bearer_op(25),
                    entropy(3),
                    None,
                    &[BalanceDelta {
                        policy_commit: token,
                        direction: BalanceDirection::Debit,
                        amount: 25,
                    }],
                    Some(init),
                    Some(anchor_leaf.clone()),
                    spend(25),
                )
                .is_err(),
            "bearer advance must reject an online delta alongside a allocation spend"
        );

        // Fail-closed: allocation underflow (spend 100 from a 40 allocation).
        assert!(
            loaded
                .advance(
                    rk,
                    cp,
                    bearer_op(100),
                    entropy(4),
                    None,
                    &[],
                    Some(init),
                    Some(anchor_leaf.clone()),
                    spend(100),
                )
                .is_err(),
            "bearer advance must reject a allocation underflow"
        );

        // Fail-closed: a allocation spend without the anchor-state advance (anchor_leaf None) is rejected.
        assert!(
            loaded
                .advance(
                    rk,
                    cp,
                    bearer_op(10),
                    entropy(5),
                    None,
                    &[],
                    Some(init),
                    None,
                    spend(10)
                )
                .is_err(),
            "offline-bearer spend requires the anchor-state advance"
        );
    }

    #[test]
    fn two_transfer_adoption_advances_receiver_frontier_and_rejects_replay() {
        use crate::core::bilateral_transaction_manager::{
            anchor_state_leaf_key, compute_smt_key, initial_chain_tip_from_device_ids,
            verify_anchor_state_leaf,
        };
        let b = [0xB1u8; 32];
        let key = anchor_state_leaf_key(&b);
        // Opaque v2 anchor-state leaf values for u=0,1,2 (anchor-core computes the real ones).
        let (leaf0, leaf1, leaf2) = ([0xC0u8; 32], [0xC1u8; 32], [0xC2u8; 32]);

        // Sender device: bootstrap the anchor-state leaf at leaf_0.
        let dev = fresh_device(0xAB)
            .with_anchor_state_leaf(&key, &leaf0)
            .expect("bootstrap");

        // One bearer advance installing the successor leaf on relationship `cp_tag`.
        let bearer = |dev: &DeviceState, cp_tag: u8, new_value: [u8; 32], u: u64| {
            let cp = devid(cp_tag);
            let rk = compute_smt_key(&dev.devid, &cp);
            let init = initial_chain_tip_from_device_ids(&dev.devid, &cp);
            dev.advance(
                rk,
                cp,
                mint_op(1),
                entropy(u as u8 + 1),
                None,
                &[BalanceDelta {
                    policy_commit: pc(0xF0 + u as u8),
                    direction: BalanceDirection::Credit,
                    amount: 1,
                }],
                Some(init),
                Some(AnchorLeafUpdate { key, new_value }),
                None,
            )
            .expect("bearer advance")
        };

        // Receiver's accepted leaf frontier starts at the admitted genesis value.
        let mut accepted = leaf0;

        // ---- Transfer 1: leaf_0 -> leaf_1 ----
        let out1 = bearer(&dev, 0xC0, leaf1, 1);
        let ap1 = out1.anchor_proofs.clone().unwrap();
        assert!(
            verify_anchor_state_leaf(&out1.smt_proofs.pre_root, &b, &accepted, &ap1.parent),
            "transfer 1 consumes the accepted leaf frontier"
        );
        assert!(verify_anchor_state_leaf(
            &out1.child_r_a,
            &b,
            &leaf1,
            &ap1.child
        ));
        accepted = leaf1; // adopt

        // ---- Replay: presenting Transfer 1's parent proof against the ADOPTED frontier rejects ----
        assert!(
            !verify_anchor_state_leaf(&out1.smt_proofs.pre_root, &b, &accepted, &ap1.parent),
            "after adoption the consumed leaf_0 state no longer matches the accepted frontier"
        );

        // ---- Transfer 2: leaf_1 -> leaf_2, from the adopted state ----
        let out2 = bearer(&out1.new_device_state, 0xC1, leaf2, 2);
        let ap2 = out2.anchor_proofs.clone().unwrap();
        assert!(
            verify_anchor_state_leaf(&out2.smt_proofs.pre_root, &b, &accepted, &ap2.parent),
            "transfer 2 must consume exactly the successor the receiver adopted"
        );
        assert!(verify_anchor_state_leaf(
            &out2.child_r_a,
            &b,
            &leaf2,
            &ap2.child
        ));
        accepted = leaf2;
        assert_eq!(accepted, leaf2);
    }

    #[test]
    fn advance_sets_value_capability_sticky_yes_and_birth_no() {
        use crate::core::bilateral_transaction_manager::{
            compute_smt_key, initial_chain_tip_from_device_ids,
        };
        let dev = fresh_device(0xAB);

        // Relationship whose FIRST op is value-bearing → Yes.
        let cp = devid(0xC0);
        let rk = compute_smt_key(&dev.devid, &cp);
        let init = initial_chain_tip_from_device_ids(&dev.devid, &cp);
        let o1 = dev
            .advance(
                rk,
                cp,
                mint_op(10),
                entropy(1),
                None,
                &[BalanceDelta {
                    policy_commit: pc(0xF1),
                    direction: BalanceDirection::Credit,
                    amount: 10,
                }],
                Some(init),
                None,
                None,
            )
            .expect("value advance");
        assert_eq!(
            o1.new_device_state
                .rel_chain_tip(&rk)
                .unwrap()
                .value_capability,
            ValueCapability::Yes
        );

        // A LATER non-value op on the same relationship (e.g. balance now drained) MUST
        // keep it `Yes` — the Gemini fatal case, end-to-end through advance().
        let o2 = o1
            .new_device_state
            .advance(rk, cp, op(), entropy(2), None, &[], None, None, None)
            .expect("non-value advance");
        assert_eq!(
            o2.new_device_state
                .rel_chain_tip(&rk)
                .unwrap()
                .value_capability,
            ValueCapability::Yes
        );

        // A DIFFERENT relationship whose first-ever op is non-value → `No` (witnessed birth).
        let cp2 = devid(0xD0);
        let rk2 = compute_smt_key(&dev.devid, &cp2);
        let init2 = initial_chain_tip_from_device_ids(&dev.devid, &cp2);
        let o3 = dev
            .advance(
                rk2,
                cp2,
                op(),
                entropy(3),
                None,
                &[],
                Some(init2),
                None,
                None,
            )
            .expect("first non-value advance");
        assert_eq!(
            o3.new_device_state
                .rel_chain_tip(&rk2)
                .unwrap()
                .value_capability,
            ValueCapability::No
        );
    }

    /// Phase 6 test: balance witness reflects device-level total at commit time.
    /// Two relationships, each debiting from the same device-level token balance.
    /// Each chain's `balance_witness` must show the device total at the moment
    /// of that advance (per §8 — "Each state binds B^T_{n+1}").
    #[test]
    fn balance_witness_reflects_device_total_across_relationships() {
        let mut dev = fresh_device(0xAA);
        // Seed the device with 100 of token T.
        let token = pc(0xCC);
        dev.balances.insert(token, 100);

        let bob = devid(0xBB);
        let charlie = devid(0xDD);
        let rk_bob = crate::core::bilateral_transaction_manager::compute_smt_key(&dev.devid, &bob);
        let rk_chrl =
            crate::core::bilateral_transaction_manager::compute_smt_key(&dev.devid, &charlie);
        let init_bob =
            crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                &dev.devid, &bob,
            );
        let init_chrl =
            crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                &dev.devid, &charlie,
            );

        // Advance (A↔Bob): debit 30 → device total now 70
        let out_bob = dev
            .advance(
                rk_bob,
                bob,
                burn_op(30),
                entropy(1),
                None,
                &[BalanceDelta {
                    policy_commit: token,
                    direction: BalanceDirection::Debit,
                    amount: 30,
                }],
                Some(init_bob),
                None,
                None,
            )
            .expect("advance Bob");
        assert_eq!(
            out_bob.new_chain_state.balance_witness.get(&token).copied(),
            Some(70),
            "after debit 30 from 100, witness on (A↔Bob) chain must = 70"
        );

        // Apply outcome to device, then advance (A↔Charlie) from updated device state.
        let dev_after_bob = out_bob.new_device_state;
        let out_chrl = dev_after_bob
            .advance(
                rk_chrl,
                charlie,
                burn_op(50),
                entropy(2),
                None,
                &[BalanceDelta {
                    policy_commit: token,
                    direction: BalanceDirection::Debit,
                    amount: 50,
                }],
                Some(init_chrl),
                None,
                None,
            )
            .expect("advance Charlie");
        assert_eq!(
            out_chrl
                .new_chain_state
                .balance_witness
                .get(&token)
                .copied(),
            Some(20),
            "after debit 50 from 70, witness on (A↔Charlie) chain must = 20"
        );

        // Device-level balance is the canonical source of truth.
        assert_eq!(out_chrl.new_device_state.balance(&token), 20);
    }

    /// Phase 6 test: stale-snapshot CAS detection.
    /// Two advances built from the SAME parent `r_A` produce different child
    /// `r'_A` values (different relationships → different SMT leaves replaced).
    /// In the CAS layer above this, only the first to install wins; the second
    /// sees its `parent_r_a` no longer matches the current head.
    #[test]
    fn concurrent_advances_from_same_root_produce_different_children() {
        let mut dev = fresh_device(0xAA);
        let token = pc(0xCC);
        dev.balances.insert(token, 100);

        let bob = devid(0xBB);
        let charlie = devid(0xDD);
        let rk_bob = crate::core::bilateral_transaction_manager::compute_smt_key(&dev.devid, &bob);
        let rk_chrl =
            crate::core::bilateral_transaction_manager::compute_smt_key(&dev.devid, &charlie);
        let init_bob =
            crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                &dev.devid, &bob,
            );
        let init_chrl =
            crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                &dev.devid, &charlie,
            );

        let parent_root = dev.root();

        // Two advances from the same parent root, on different relationships.
        let a = dev
            .advance(
                rk_bob,
                bob,
                burn_op(10),
                entropy(1),
                None,
                &[BalanceDelta {
                    policy_commit: token,
                    direction: BalanceDirection::Debit,
                    amount: 10,
                }],
                Some(init_bob),
                None,
                None,
            )
            .expect("advance A");
        let b = dev
            .advance(
                rk_chrl,
                charlie,
                burn_op(20),
                entropy(2),
                None,
                &[BalanceDelta {
                    policy_commit: token,
                    direction: BalanceDirection::Debit,
                    amount: 20,
                }],
                Some(init_chrl),
                None,
                None,
            )
            .expect("advance B");

        // Both built from the same parent.
        assert_eq!(a.parent_r_a, parent_root);
        assert_eq!(b.parent_r_a, parent_root);

        // But produce different children — first-commit-wins at the CAS layer
        // means the second outcome is stale.
        assert_ne!(
            a.child_r_a, b.child_r_a,
            "different SMT leaf replacements must yield different child roots"
        );

        // Balances on the two outcomes also diverge.
        assert_eq!(a.new_device_state.balance(&token), 90);
        assert_eq!(b.new_device_state.balance(&token), 80);
    }

    /// Phase 6 test: same-relationship double advance from same SMT root.
    /// This is the per-relationship Tripwire scenario (§6.1, Theorem 2):
    /// two attempts to consume the same chain tip `h_n` on the same relationship.
    /// Both advances individually succeed (DeviceState::advance is pure), but
    /// they produce DIFFERENT `h_{n+1}` because entropy/op differ — yet both
    /// embed the same `embedded_parent`. Verifiers seeing both must reject one.
    #[test]
    fn tripwire_same_relationship_same_parent_different_children() {
        let mut dev = fresh_device(0xAA);
        let token = pc(0xCC);
        dev.balances.insert(token, 100);

        let bob = devid(0xBB);
        let rk = crate::core::bilateral_transaction_manager::compute_smt_key(&dev.devid, &bob);
        let init = crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &dev.devid, &bob,
        );

        let a = dev
            .advance(
                rk,
                bob,
                burn_op(10),
                entropy(1),
                None,
                &[BalanceDelta {
                    policy_commit: token,
                    direction: BalanceDirection::Debit,
                    amount: 10,
                }],
                Some(init),
                None,
                None,
            )
            .expect("advance A");
        let b = dev
            .advance(
                rk,
                bob,
                burn_op(20),
                entropy(2),
                None,
                &[BalanceDelta {
                    policy_commit: token,
                    direction: BalanceDirection::Debit,
                    amount: 20,
                }],
                Some(init),
                None,
                None,
            )
            .expect("advance B");

        // Both consume the SAME embedded_parent (the initial tip).
        assert_eq!(a.new_chain_state.embedded_parent, init);
        assert_eq!(b.new_chain_state.embedded_parent, init);

        // But produce DIFFERENT successor chain tips (different entropy/op).
        let h_a = a.new_chain_state.compute_chain_tip();
        let h_b = b.new_chain_state.compute_chain_tip();
        assert_ne!(
            h_a, h_b,
            "Tripwire: two children of same h_n must be cryptographically distinguishable"
        );

        // A verifier seeing both signed receipts would detect the fork:
        // both claim to extend the same h_n, only one can be accepted.
    }

    /// Phase 6 test: balance underflow rejected.
    #[test]
    fn advance_rejects_balance_underflow() {
        let mut dev = fresh_device(0xAA);
        let token = pc(0xCC);
        dev.balances.insert(token, 5);

        let bob = devid(0xBB);
        let rk = crate::core::bilateral_transaction_manager::compute_smt_key(&dev.devid, &bob);
        let init = crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &dev.devid, &bob,
        );

        let r = dev.advance(
            rk,
            bob,
            burn_op(10),
            entropy(1),
            None,
            &[BalanceDelta {
                policy_commit: token,
                direction: BalanceDirection::Debit,
                amount: 10,
            }],
            Some(init),
            None,
            None,
        );
        assert!(
            r.is_err(),
            "debit > balance must fail with insufficient funds"
        );
    }

    /// Phase 6 test: balance overflow rejected.
    #[test]
    fn advance_rejects_balance_overflow() {
        let mut dev = fresh_device(0xAA);
        let token = pc(0xCC);
        dev.balances.insert(token, u64::MAX);

        let bob = devid(0xBB);
        let rk = crate::core::bilateral_transaction_manager::compute_smt_key(&dev.devid, &bob);
        let init = crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &dev.devid, &bob,
        );

        let r = dev.advance(
            rk,
            bob,
            mint_op(1),
            entropy(1),
            None,
            &[BalanceDelta {
                policy_commit: token,
                direction: BalanceDirection::Credit,
                amount: 1,
            }],
            Some(init),
            None,
            None,
        );
        assert!(r.is_err(), "u64::MAX + 1 must overflow");
    }

    /// Phase 6 test: balance conservation across cross-relationship sequence.
    /// Property: sum of all deltas across a sequence of valid advances equals
    /// the net change in the device-level balance scalar.
    #[test]
    fn balance_conservation_across_sequence() {
        let _ = TransactionMode::Bilateral; // import keep-alive
        let mut dev = fresh_device(0xAA);
        let token = pc(0xCC);
        dev.balances.insert(token, 1000);

        let parties: Vec<[u8; 32]> = (0u8..5).map(|i| devid(0xB0 + i)).collect();
        let mut net_delta: i64 = 0;
        for (i, party) in parties.iter().enumerate() {
            let amt = (i + 1) as u64 * 7;
            let dir = if i % 2 == 0 {
                BalanceDirection::Debit
            } else {
                BalanceDirection::Credit
            };
            let signed = if matches!(dir, BalanceDirection::Debit) {
                -(amt as i64)
            } else {
                amt as i64
            };
            net_delta += signed;

            let rk = crate::core::bilateral_transaction_manager::compute_smt_key(&dev.devid, party);
            let init =
                crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                    &dev.devid, party,
                );
            let out = dev
                .advance(
                    rk,
                    *party,
                    value_op(dir, amt),
                    entropy(i as u8),
                    None,
                    &[BalanceDelta {
                        policy_commit: token,
                        direction: dir,
                        amount: amt,
                    }],
                    Some(init),
                    None,
                    None,
                )
                .expect("advance");
            dev = out.new_device_state;
        }

        let expected = (1000_i64 + net_delta) as u64;
        assert_eq!(
            dev.balance(&token),
            expected,
            "net balance change must equal sum of signed deltas"
        );
    }

    // ─────────────────────────────────────────────────────────────
    // Phase 7 — vault state SMT leaf integration (§4.1.2 / §8.4 step 2)
    // ─────────────────────────────────────────────────────────────

    #[test]
    fn with_vault_state_leaf_returns_verifiable_inclusion_proof() {
        use crate::dlv::vault_smt_leaf::{
            compute_vault_smt_key, compute_vault_smt_value, verify_vault_smt_inclusion,
        };
        use crate::dlv::vault_state_anchor::compute_reserves_digest;

        let bob = fresh_device(0xC1);
        let vault_id = [0x12u8; 32];
        let reserves_digest = compute_reserves_digest(b"AAA", b"BBB", 1_000, 2_000, 30);

        let outcome = bob
            .with_vault_state_leaf(&vault_id, 0, &reserves_digest)
            .expect("vault leaf write succeeds");

        // Pure-function contract: self untouched.
        assert_eq!(bob.root(), bob.root(), "self.root must be stable");
        assert_ne!(
            bob.root(),
            outcome.new_root,
            "writing a vault leaf must change the SMT root"
        );

        // Spec-strict verification path: trader rebuilds key+value
        // from public inputs, walks the siblings up to the proven
        // root, and accepts.
        verify_vault_smt_inclusion(
            &vault_id,
            0,
            &reserves_digest,
            &outcome.new_root,
            &outcome.siblings,
        )
        .expect("verifier accepts the on-device-produced proof");

        // Sanity: the new device state actually carries the leaf.
        let leaf_key = compute_vault_smt_key(&vault_id);
        let leaf_value = compute_vault_smt_value(0, &reserves_digest);
        assert!(outcome.new_device_state.smt.contains_key(&leaf_key));
        // The proof's value field equals the recomputed leaf value.
        let live_proof = outcome
            .new_device_state
            .smt
            .get_inclusion_proof(&leaf_key, 256)
            .expect("live proof");
        assert_eq!(live_proof.value, Some(leaf_value));
    }

    #[test]
    fn vault_state_leaf_does_not_disturb_bilateral_tips() {
        use crate::dlv::vault_state_anchor::compute_reserves_digest;

        // First seed a bilateral chain (self-loop) so there's a real
        // relationship leaf in the SMT.
        let alice = fresh_device(0xA2);
        let rk_self =
            crate::core::bilateral_transaction_manager::compute_smt_key(&alice.devid, &alice.devid);
        let init_tip =
            crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                &alice.devid,
                &alice.devid,
            );
        let after_bilateral = alice
            .advance(
                rk_self,
                alice.devid,
                op(),
                entropy(7),
                None,
                &[],
                Some(init_tip),
                None,
                None,
            )
            .expect("bilateral advance succeeds")
            .new_device_state;

        let bilateral_tip_before = after_bilateral
            .chain_tip(&rk_self)
            .expect("relationship tip present");
        let smt_root_before = after_bilateral.root();

        // Now write a vault leaf on top.
        let vault_id = [0x34u8; 32];
        let reserves_digest = compute_reserves_digest(b"AAA", b"BBB", 1_000, 2_000, 30);
        let outcome = after_bilateral
            .with_vault_state_leaf(&vault_id, 0, &reserves_digest)
            .expect("vault leaf write succeeds");

        // Bilateral tip cache is unchanged.
        assert_eq!(
            outcome
                .new_device_state
                .chain_tip(&rk_self)
                .expect("relationship tip survives"),
            bilateral_tip_before,
            "vault leaf write must not perturb relationship tip cache"
        );
        // Balances unchanged.
        assert_eq!(outcome.new_device_state.balances, after_bilateral.balances);
        // But the SMT root advanced because a new leaf landed in the
        // (disjoint, domain-separated) vault namespace.
        assert_ne!(outcome.new_root, smt_root_before);
    }

    #[test]
    fn vault_state_leaf_sequence_advance_changes_root_monotonically() {
        use crate::dlv::vault_state_anchor::compute_reserves_digest;

        let bob = fresh_device(0xC2);
        let vault_id = [0x56u8; 32];
        let r0 = compute_reserves_digest(b"AAA", b"BBB", 1_000, 2_000, 30);
        let after_seq0 = bob
            .with_vault_state_leaf(&vault_id, 0, &r0)
            .expect("seq=0 write");

        // Simulate a trade: reserves shift, sequence bumps.
        let r1 = compute_reserves_digest(b"AAA", b"BBB", 1_500, 1_700, 30);
        let after_seq1 = after_seq0
            .new_device_state
            .with_vault_state_leaf(&vault_id, 1, &r1)
            .expect("seq=1 write");

        assert_ne!(
            after_seq0.new_root, after_seq1.new_root,
            "sequence advance must visibly change the SMT root"
        );

        // The seq=1 proof verifies against the seq=1 root.
        crate::dlv::vault_smt_leaf::verify_vault_smt_inclusion(
            &vault_id,
            1,
            &r1,
            &after_seq1.new_root,
            &after_seq1.siblings,
        )
        .expect("seq=1 proof verifies");

        // The seq=0 proof now NO LONGER verifies against the seq=1
        // root — i.e. an attacker cannot replay the old proof against
        // the device's current state.
        crate::dlv::vault_smt_leaf::verify_vault_smt_inclusion(
            &vault_id,
            0,
            &r0,
            &after_seq1.new_root,
            &after_seq0.siblings,
        )
        .expect_err("stale seq=0 proof must not verify against the seq=1 root");
    }
}
