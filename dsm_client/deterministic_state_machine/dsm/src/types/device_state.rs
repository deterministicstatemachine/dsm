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

    /// Non-relationship SMT leaves that also commit into the device root `r_A`:
    /// offline-bearer anchor-state leaves ([`Self::with_anchor_state_leaf`], and the
    /// `anchor_leaf` replaced inside [`Self::advance`]) and the token adoption leaves
    /// [`Self::advance`] writes. The [`SparseMerkleTree`] is the canonical source
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

    /// The economic admission in flight, if any — the authoritative fence
    /// state for [`Self::advance`].
    ///
    /// Deliberately **not** a parameter of `advance`. A caller-supplied
    /// `pending: bool` would move the bypass one argument inward: any caller
    /// wanting to spend fenced value would simply pass `false`. It rides on
    /// the head instead, so the gate reads state the persistence layer put
    /// there and no call site can choose otherwise.
    ///
    /// Also deliberately **not** part of `encode_device_state`. Serializing it
    /// would require a `DEVICE_STATE_VERSION` bump, which under the beta
    /// no-legacy rule means wiping every existing head. It is durably held in
    /// its own table and re-attached on load; [`Self::restore`] requires it as
    /// an argument so every rebuild path must supply it or fail to compile.
    pending_economic_admission: Option<crate::economic::admission::PendingEconomicAdmission>,
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

/// Cached per-relationship tip metadata.
///
/// This is a **bounded accumulator entry**: a fixed-size commitment to the
/// relationship's position, not a copy of the state that produced it.
///
/// The head previously retained the whole [`RelationshipChainState`] per tip.
/// That cost ~50 KB per relationship — the operation embeds a 49,856-byte
/// SPHINCS+ signature — while only two values were ever read back out:
/// `entropy`, and a chain-tip recomputation that the codec already forced to
/// equal `chain_tip`. Heads therefore grew ~50 KB per counterparty and
/// overran the storage node's 128 KiB `MAX_ENVELOPE_BYTES`, which the
/// envelope inherits because it carries the head.
///
/// So the tip keeps the digest and the entropy and nothing else. `root()` is
/// unaffected: the SMT leaf has always been `rel_key -> chain_tip`, never the
/// state. The operation being transacted still travels in full in its own
/// envelope field — it is only the *retained history* that is now a
/// commitment.
#[derive(Clone, Debug)]
pub struct RelChainTip {
    /// Current chain tip `h_n = H(canonical_bytes(state))`.
    /// Mirrors the SMT leaf value.
    pub chain_tip: [u8; 32],

    /// Counterparty device identifier for this relationship.
    pub counterparty_devid: [u8; 32],

    /// Entropy of the state at this tip — the `prior_entropy` input to the
    /// next advance's hash-adjacency derivation (§11 eq. 14).
    ///
    /// This is the ONLY part of the tip state that later operations consume,
    /// which is why it is retained explicitly instead of being recovered from
    /// a 50 KB state copy. Empty ONLY for a digest-only tip restored from a
    /// recovery capsule that never carried one; an advance on such a tip
    /// falls back to the SMT-root derivation, exactly as a fresh chain does.
    pub tip_entropy: Vec<u8>,

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

    /// Entity (advancing party) SPHINCS+ signature.
    pub entity_sig: Option<Vec<u8>>,

    /// Counterparty SPHINCS+ signature (bilateral mode).
    pub counterparty_sig: Option<Vec<u8>>,
}

/// THE canonical relationship-successor commitment — `h_n = C_dsm+` — as ONE
/// preimage helper. `compute_chain_tip` and the foreign successor-evidence
/// verifier both call this; there are never two encodings of the preimage.
///
/// `DSM/relationship-chain-tip/v2`: succession facts ONLY. The `/v1`-era
/// relationship use of `DSM/state-hash` folded the whole balance map into
/// every tip and is burned — `R_econ` is the sole authenticated online
/// balance representation. The layout still EXCLUDES `state_number`,
/// `sparse_index`, and any counter-like metadata per §4.3; signatures are
/// not hashed — they sign this digest, not the other way around.
pub fn relationship_chain_tip_v2(
    rel_key: &[u8; 32],
    embedded_parent: &[u8; 32],
    counterparty_devid: &[u8; 32],
    operation_bytes: &[u8],
    entropy: &[u8],
    encapsulated_entropy: Option<&[u8]>,
) -> [u8; 32] {
    let mut hasher =
        dsm_domain_hasher(crate::common::domain_tags::TAG_DSM_RELATIONSHIP_CHAIN_TIP_V2);
    hasher.update(rel_key);
    hasher.update(embedded_parent);
    hasher.update(counterparty_devid);
    hasher.update(&(operation_bytes.len() as u32).to_le_bytes());
    hasher.update(operation_bytes);
    hasher.update(&(entropy.len() as u32).to_le_bytes());
    hasher.update(entropy);
    match encapsulated_entropy {
        Some(enc) => {
            hasher.update(&[1u8]);
            hasher.update(&(enc.len() as u32).to_le_bytes());
            hasher.update(enc);
        }
        None => {
            hasher.update(&[0u8]);
        }
    }
    *hasher.finalize().as_bytes()
}

impl RelationshipChainState {
    /// Compute `h_n` via [`relationship_chain_tip_v2`] — the one canonical
    /// preimage.
    pub fn compute_chain_tip(&self) -> [u8; 32] {
        relationship_chain_tip_v2(
            &self.rel_key,
            &self.embedded_parent,
            &self.counterparty_devid,
            &self.operation.to_bytes(),
            &self.entropy,
            self.encapsulated_entropy.as_deref(),
        )
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
        Operation::FaucetClaim { .. } => {
            // The economics are DERIVED, never carried: exactly one credit of
            // exactly the fixed payout of exactly builtin ERA. The operation
            // has no amount/asset fields to lie with, and this arm is what
            // stops a delta smuggling a different quantity in beside it.
            let era = crate::core::token::token_state_manager::era_policy_commit();
            if deltas.len() != 1
                || deltas[0].direction != BalanceDirection::Credit
                || deltas[0].amount != crate::economic::faucet::ERA_FAUCET_PAYOUT
                || deltas[0].policy_commit != era
            {
                return Err(DsmError::invalid_operation(
                    "conservation: a faucet claim applies exactly one credit of exactly the \
                     derived payout of builtin ERA — nothing about it is caller-chosen",
                ));
            }
            Ok(())
        }
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
        Operation::Mint {
            amount,
            policy_commit,
            ..
        } => {
            if deltas.len() != 1
                || deltas[0].direction != BalanceDirection::Credit
                || deltas[0].amount != amount.value()
            {
                return Err(DsmError::invalid_operation(
                    "conservation: mint must apply exactly one credit delta of the mint amount",
                ));
            }
            // Bind the credited ASSET to the one the signed operation names.
            // Without this the guard checks only count/direction/amount, so a
            // mint for token X could credit a different asset entirely (e.g.
            // ERA) — the delta's policy_commit was unconstrained.
            if &deltas[0].policy_commit != policy_commit {
                return Err(DsmError::invalid_operation(
                    "conservation: mint delta policy_commit != operation policy_commit",
                ));
            }
            Ok(())
        }
        Operation::Burn {
            amount,
            policy_commit,
            ..
        } => {
            if deltas.len() != 1
                || deltas[0].direction != BalanceDirection::Debit
                || deltas[0].amount != amount.value()
            {
                return Err(DsmError::invalid_operation(
                    "conservation: burn must apply exactly one debit delta of the burn amount",
                ));
            }
            if &deltas[0].policy_commit != policy_commit {
                return Err(DsmError::invalid_operation(
                    "conservation: burn delta policy_commit != operation policy_commit",
                ));
            }
            Ok(())
        }
        // Token creation is the ONLY multi-asset operation. It destroys ERA to
        // pay the creation fee and issues the new asset, in ONE advance — so
        // either the token exists and the fee was paid, or neither happened.
        //
        // The rule is POSITIONAL and exact rather than set-membership: with a
        // fixed order, a reordered or duplicated delta cannot satisfy it, and
        // the whole rule stays a total function of the operation.
        //
        // Conservation holds per-asset. ERA: a strict destruction of
        // `fee_amount` with no counterparty credit — the same semantics as
        // `Burn`. New asset: genesis issuance of `initial_supply` against a
        // commit proven distinct from every existing asset. It is the `Mint`
        // rule generalized to two legs over two provably different assets.
        Operation::CreateToken {
            initial_supply,
            policy_commit,
            fee_amount,
            ..
        } => {
            // A create may NEVER issue an existing asset. This is a second,
            // independent barrier against a colliding anchor: even if one
            // reached the guard, it could not mint a builtin here.
            if crate::core::token::builtin_token_id_for_policy_commit(policy_commit).is_some() {
                return Err(DsmError::invalid_operation(
                    "conservation: create-token policy_commit collides with a builtin asset",
                ));
            }

            let era_commit = crate::core::token::builtin_policy_commit_for_token("ERA")
                .ok_or_else(|| DsmError::invalid_operation("conservation: ERA commit missing"))?;

            let mut i = 0usize;
            if *fee_amount > 0 {
                let d = deltas.get(i).ok_or_else(|| {
                    DsmError::invalid_operation("conservation: create-token fee delta missing")
                })?;
                // The fee is always ERA. The caller has no field with which to
                // point it at another asset.
                if d.policy_commit != era_commit
                    || d.direction != BalanceDirection::Debit
                    || d.amount != *fee_amount
                {
                    return Err(DsmError::invalid_operation(
                        "conservation: create-token fee must be exactly one ERA debit of fee_amount",
                    ));
                }
                i += 1;
            }
            if initial_supply.value() > 0 {
                let d = deltas.get(i).ok_or_else(|| {
                    DsmError::invalid_operation("conservation: create-token issuance delta missing")
                })?;
                if &d.policy_commit != policy_commit
                    || d.direction != BalanceDirection::Credit
                    || d.amount != initial_supply.value()
                {
                    return Err(DsmError::invalid_operation(
                        "conservation: create-token issuance must be exactly one credit of \
                         initial_supply under the token's own policy_commit",
                    ));
                }
                i += 1;
            }
            if deltas.len() != i {
                return Err(DsmError::invalid_operation(
                    "conservation: create-token carries unexpected extra balance deltas",
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

impl AdvanceOutcome {
    /// This device's canonical relationship pair for the advanced step: the
    /// lineage head it consumed (`embedded_parent` — the prior SMT leaf, or the
    /// shared initial tip on a first-ever advance) and the head it produced
    /// (`compute_chain_tip()`, the new SMT leaf). Per-device values: the same
    /// pair the device will sign under as its parent when it next originates on
    /// this relationship, and the pair a recipient authenticates to its peer.
    pub fn relationship_pair(&self) -> ([u8; 32], [u8; 32]) {
        (
            self.new_chain_state.embedded_parent,
            self.new_chain_state.compute_chain_tip(),
        )
    }
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
            extra_leaves: BTreeMap::new(),
            offline_allocations: BTreeMap::new(),
            pending_economic_admission: None,
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
    /// The admission in flight, if any. Read by [`Self::advance`]'s fence.
    pub fn pending_economic_admission(
        &self,
    ) -> Option<&crate::economic::admission::PendingEconomicAdmission> {
        self.pending_economic_admission.as_ref()
    }

    /// Attach or clear the pending admission, returning the updated head.
    ///
    /// The persistence layer calls this inside the same transaction that
    /// writes the pending row, so the head and the fence state can never
    /// disagree about whether an admission is in flight.
    pub fn with_pending_economic_admission(
        &self,
        pending: Option<crate::economic::admission::PendingEconomicAdmission>,
    ) -> Self {
        let mut next = self.clone();
        next.pending_economic_admission = pending;
        next
    }

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
        // The admission in flight, from its own durable table. REQUIRED, not
        // defaulted: every rebuild path must state it or fail to compile. A
        // defaulted `None` here would be a silent fence-open on any path that
        // forgot — a gate precondition with no mandatory producer.
        pending_economic_admission: Option<crate::economic::admission::PendingEconomicAdmission>,
        max_relationships: usize,
    ) -> Result<Self, DsmError> {
        let mut state = Self::new(genesis, devid, public_key, max_relationships);
        state.legacy_anchor = legacy_anchor;
        state.balances = balances;
        state.offline_allocations = offline_allocations;
        // The reserve LEAVES replay through `extra_leaves` below, which is what
        // rebuilds the root; this map carries the amounts behind them, which the
        // leaf hash cannot yield. A funded vault that reloaded without it would
        // recompute a root that does not match the stored one.
        state.pending_economic_admission = pending_economic_admission;

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

    /// Install the canonical genesis authority root `G` on an ALREADY
    /// CONSTRUCTED head.
    ///
    /// Only the constructor used to write `genesis`, which made
    /// `CoreSDK::write_genesis_device_head` silently unable to honour its own
    /// contract: it takes the existing head when one is present, so on that
    /// branch `genesis` kept whatever the head was built with. Genesis install
    /// always hits that branch — `StateMachine::set_state` materialises a head
    /// first — so every freshly created wallet ended up with a head whose
    /// `genesis` was the `[0u8; 32]` that `set_state` invented. Every consumer
    /// reading `genesis_digest()` as the authority root then compared against
    /// zeros: the ERA faucet's authority evidence re-derived the real seed-rooted
    /// `v3.g` and fail-closed on every device, correctly.
    ///
    /// This is the narrow repair for that: a head that HAS the canonical root
    /// can be told it. It does not make the root optional and does not add a
    /// second notion of `G` — there is one, the seed-derived `v3.g`.
    pub fn set_genesis_digest(&mut self, genesis: [u8; 32]) {
        self.genesis = genesis;
    }

    /// Device identifier.
    pub fn devid(&self) -> [u8; 32] {
        self.devid
    }

    /// Genesis identifier. A key-derivation input for every device-scoped leaf,
    /// so a verifier that must recompute a leaf position needs it alongside
    /// [`Self::devid`].
    pub fn genesis(&self) -> [u8; 32] {
        self.genesis
    }

    /// Sibling path for any leaf in this device's SMT.
    ///
    /// Needed to sign a settlement receipt: the receipt leaf is written by the
    /// settling advance, and proving it to a third party means carrying its path
    /// against the post-advance root.
    pub fn inclusion_siblings(&self, key: &[u8; 32]) -> Result<Vec<[u8; 32]>, DsmError> {
        Ok(self
            .smt
            .get_inclusion_proof(key, 256)
            .map_err(|e| DsmError::merkle(format!("inclusion path: {e}")))?
            .siblings)
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

    /// SMT key of the leaf committing this device's adoption of `policy_commit`.
    pub fn token_adoption_leaf_key(policy_commit: &[u8; 32]) -> [u8; 32] {
        crate::crypto::blake3::domain_hash_bytes(
            crate::common::domain_tags::TAG_DSM_TOKEN_ADOPTION,
            policy_commit,
        )
    }

    /// Whether this device's committed state carries the adoption of
    /// `policy_commit`. Builtin ERA and dBTC are pre-adopted: every device
    /// holds their policies by construction.
    pub fn has_adopted(&self, policy_commit: &[u8; 32]) -> bool {
        if crate::core::token::token_state_manager::builtin_token_id_for_policy_commit(
            policy_commit,
        )
        .is_some()
        {
            return true;
        }
        self.extra_leaves
            .get(&Self::token_adoption_leaf_key(policy_commit))
            .is_some_and(|v| v == policy_commit)
    }

    /// Current chain tip for a relationship, if one exists. Returns
    /// `None` for first-ever transactions on an unseen relationship —
    /// the caller must supply a spec-canonical initial tip.
    pub fn chain_tip(&self, rel_key: &[u8; 32]) -> Option<[u8; 32]> {
        self.tips.get(rel_key).map(|t| t.chain_tip)
    }

    /// Entropy of the state at a relationship's current tip — the
    /// `prior_entropy` input to the next advance (§11 eq. 14).
    ///
    /// `None` when the relationship is unknown, or when its tip carries no
    /// entropy (a digest-only tip restored from a recovery capsule). Both
    /// cases mean the caller must fall back to the SMT-root derivation.
    pub fn tip_entropy(&self, rel_key: &[u8; 32]) -> Option<&[u8]> {
        self.tips
            .get(rel_key)
            .map(|t| t.tip_entropy.as_slice())
            .filter(|e| !e.is_empty())
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

    /// The FULL accepting-gate discipline (3.5b, owner correction 11b): an
    /// economically-gated operation requires an admission ALREADY attached to
    /// this head that is (1) `DsmBacked`, (2) still `Prepared` (attached for
    /// exactly this advance — a fencing state means it belongs to an earlier
    /// acceptance), and (3) bound to exactly this operation's digest. Never
    /// "some pending record": each miss is its own named refusal.
    fn require_attached_dsm_admission(
        &self,
        operation: &Operation,
        what: &str,
    ) -> Result<(), DsmError> {
        let pending = self.pending_economic_admission.as_ref().ok_or_else(|| {
            DsmError::invalid_operation(format!(
                "advance: refusing {what} with no pending economic admission — installing \
                 balance without the admission fence would be a raw local credit, spendable \
                 before any foreign verifier could refuse it",
            ))
        })?;
        if pending.kind != crate::economic::admission::PendingAdmissionKind::DsmBacked {
            return Err(DsmError::invalid_operation(format!(
                "advance: refusing {what} — the pending admission is not DSM-backed",
            )));
        }
        if pending.state != crate::economic::admission::EconomicAdmissionState::Prepared {
            return Err(DsmError::invalid_operation(format!(
                "advance: refusing {what} — the pending admission is not Prepared; a \
                 fencing admission belongs to an earlier acceptance and authorizes nothing \
                 new",
            )));
        }
        let op_digest = crate::economic::faucet::dsm_operation_digest(&operation.to_bytes());
        if pending.operation_digest != op_digest {
            return Err(DsmError::invalid_operation(format!(
                "advance: refusing {what} whose digest does not match the pending economic \
                 admission — the admission authorizes exactly one operation",
            )));
        }
        Ok(())
    }

    /// The SoFi counterpart: a `TraderFulfillment` requires its OWN pending
    /// admission, of the kind that fences a position.
    ///
    /// `require_attached_dsm_admission` cannot serve here — it demands
    /// `DsmBacked`, and a fulfillment's admission is
    /// [`PendingAdmissionKind::SofiFulfillment`], which fences the lineage
    /// rather than an asset. Before this existed, a `SofiFulfill` reached the
    /// head with NO accepting gate at all: `classify` calls it a
    /// `ClosedWriteSet` (it moves value), every other value-moving operation
    /// has a `require_attached_*` call site, and this one had none.
    ///
    /// The digest binding is the same and is the point: an admission
    /// authorizes exactly one operation, so a fulfillment cannot ride the
    /// admission staged for a different one.
    fn require_attached_sofi_admission(
        &self,
        operation: &Operation,
        what: &str,
    ) -> Result<(), DsmError> {
        let pending = self.pending_economic_admission.as_ref().ok_or_else(|| {
            DsmError::invalid_operation(format!(
                "advance: refusing {what} with no pending economic admission — a \
                 fulfillment installs a CONDITIONAL claim at its position, and without the \
                 admission fence the lineage would advance past a position that has \
                 selected no root",
            ))
        })?;
        let crate::economic::admission::PendingAdmissionKind::SofiFulfillment { fulfillment_id } =
            pending.kind
        else {
            return Err(DsmError::invalid_operation(format!(
                "advance: refusing {what} — the pending admission is not a SoFi \
                 fulfillment admission; a fulfillment fences a position, and an \
                 asset-fencing admission does not authorize it",
            )));
        };
        if pending.state != crate::economic::admission::EconomicAdmissionState::Prepared {
            return Err(DsmError::invalid_operation(format!(
                "advance: refusing {what} — the pending admission is not Prepared; a \
                 fencing admission belongs to an earlier acceptance and authorizes \
                 nothing new",
            )));
        }
        let op_digest = crate::economic::faucet::dsm_operation_digest(&operation.to_bytes());
        if pending.operation_digest != op_digest {
            return Err(DsmError::invalid_operation(format!(
                "advance: refusing {what} whose digest does not match the pending \
                 economic admission — the admission authorizes exactly one operation",
            )));
        }
        // THE ID MUST BE THIS F'S. The admission's `fulfillment_id` is not
        // decoration: it is the durable identity the resume path and the
        // route's resolution are keyed to, so an admission carrying another
        // F's id would fence this position under a name nothing can resolve.
        // The digest above binds the BYTES; this binds the identity those
        // bytes derive, and they are not the same claim.
        let Operation::SofiFulfill {
            fulfillment_body, ..
        } = operation
        else {
            return Err(DsmError::invalid_operation(format!(
                "advance: refusing {what} — not a fulfillment",
            )));
        };
        let body =
            crate::sofi::wire::TraderFulfillmentBody::decode(fulfillment_body).map_err(|_| {
                DsmError::invalid_operation(format!(
                    "advance: refusing {what} — its body is not a canonical \
                     TraderFulfillmentBody",
                ))
            })?;
        if fulfillment_id != crate::sofi::derive::fulfillment_id(&body) {
            return Err(DsmError::invalid_operation(format!(
                "advance: refusing {what} — the pending admission names a different \
                 fulfillment; the id is this position's durable identity, not a label",
            )));
        }
        Ok(())
    }

    /// TEST-ONLY: advance with the Prepared economic admission that the
    /// accepting fences require for an economically-originating operation.
    ///
    /// This is the INPUT SHAPE production hands `advance`: the admission
    /// producer (`stage_admission` -> `AdmissionPlan`) attaches a Prepared
    /// DSM-backed admission bound to exactly this operation's digest, then
    /// advances. Whether the admission is TRUE — whether a register accepted
    /// the position, whether the evidence verifies — is established one layer
    /// up, by the producer and the economic verifier, and is proven there.
    /// At this layer there is no other way a credit enters the head, which is
    /// what makes this the legitimate origin for a core test rather than a
    /// bypass: every gate `advance` owns still runs. It is not asserting that
    /// an unadmitted origin is acceptable;
    /// `a_funded_create_is_refused_without_its_own_attached_admission` pins
    /// that it is not.
    #[cfg(any(test, feature = "testing"))]
    #[allow(clippy::too_many_arguments)]
    pub fn advance_admitted(
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
        let mut staged = self.clone();
        staged.pending_economic_admission = Some(
            crate::economic::admission::PendingEconomicAdmission::prepared(
                crate::economic::admission::PendingAdmissionKind::DsmBacked,
                1,
                [0u8; 32],
                crate::economic::faucet::dsm_operation_digest(&operation.to_bytes()),
            ),
        );
        staged.advance(
            rel_key,
            counterparty_devid,
            operation,
            entropy,
            encapsulated_entropy,
            deltas,
            initial_chain_tip,
            anchor_leaf,
            offline_spend,
        )
    }

    /// TEST-ONLY. ERA through the faucet, at the core layer: one admitted
    /// `FaucetClaim` on this device's self-loop, crediting exactly the
    /// protocol payout (`ERA_FAUCET_PAYOUT`) of builtin ERA. A test that
    /// needs more claims more tickets — there is no amount to ask for,
    /// because the faucet has none.
    #[cfg(any(test, feature = "testing"))]
    pub fn admitted_faucet_claim(
        &self,
        ticket_index: u64,
        entropy_seed: u8,
    ) -> Result<Self, DsmError> {
        let (rel_key, initial_tip) = self.self_loop_coordinates();
        self.advance_admitted(
            rel_key,
            self.devid,
            Operation::FaucetClaim {
                faucet_id: crate::economic::faucet::era_faucet_id(b"dsm-testnet"),
                ticket_index,
            },
            vec![entropy_seed; 32],
            None,
            &[BalanceDelta {
                policy_commit: crate::core::token::token_state_manager::era_policy_commit(),
                direction: BalanceDirection::Credit,
                amount: crate::economic::faucet::ERA_FAUCET_PAYOUT,
            }],
            Some(initial_tip),
            None,
            None,
        )
        .map(|o| o.new_device_state)
    }

    /// TEST-ONLY. A user asset through authorized issuance, at the core
    /// layer: one admitted `Mint` of `amount` units of `policy_commit` on the
    /// self-loop. A builtin commit is refused exactly as in production — ERA
    /// comes only from [`Self::admitted_faucet_claim`].
    /// TEST-ONLY. Adopt `policy_commit` on this device: the authenticated
    /// transition behind ADD TOKEN, as a no-delta self-loop advance. Idempotent.
    #[cfg(any(test, feature = "testing"))]
    pub fn adopt_token(&self, policy_commit: [u8; 32], entropy_seed: u8) -> Result<Self, DsmError> {
        let (rel_key, initial_tip) = self.self_loop_coordinates();
        self.clone()
            .advance(
                rel_key,
                self.devid,
                Operation::AdoptToken {
                    policy_commit,
                    signature: vec![0xAD; 64],
                },
                vec![entropy_seed; 32],
                None,
                &[],
                Some(initial_tip),
                None,
                None,
            )
            .map(|o| o.new_device_state)
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn admitted_mint(
        &self,
        policy_commit: [u8; 32],
        amount: u64,
        entropy_seed: u8,
    ) -> Result<Self, DsmError> {
        // A minter is the token's issuer, and production issuers adopt in the
        // creation advance (`CreateToken` writes the leaf). The fixture has no
        // creation step, so adopt here: an un-adopted device cannot be
        // credited, by design, and a fixture must not bypass that.
        let head = if self.has_adopted(&policy_commit) {
            self.clone()
        } else {
            self.adopt_token(policy_commit, entropy_seed ^ 0x80)?
        };
        let (rel_key, initial_tip) = head.self_loop_coordinates();
        head.advance_admitted(
            rel_key,
            self.devid,
            Operation::Mint {
                amount: crate::types::token_types::Balance::from_state(amount, [0u8; 32]),
                token_id: b"TEST".to_vec(),
                policy_commit,
                message: String::new(),
            },
            vec![entropy_seed; 32],
            None,
            &[BalanceDelta {
                policy_commit,
                direction: BalanceDirection::Credit,
                amount,
            }],
            Some(initial_tip),
            None,
            None,
        )
        .map(|o| o.new_device_state)
    }

    /// The device's self-loop relationship key and its spec-canonical initial
    /// tip — where every self-authored economic origin lands.
    #[cfg(any(test, feature = "testing"))]
    fn self_loop_coordinates(&self) -> ([u8; 32], [u8; 32]) {
        (
            crate::core::bilateral_transaction_manager::compute_smt_key(&self.devid, &self.devid),
            crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                &self.devid,
                &self.devid,
            ),
        )
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

        // SOFI v8 SIGNS ITS PROTOCOL OBJECTS, NOT A SECOND COPY OF THEM.
        //
        // A setup signs `m_setup` and a fulfillment signs `m_F` — the digests
        // of the objects themselves, which is what a storage member checks
        // when the same object arrives with no operation wrapped around it.
        // Verifying an additional generic operation signature here would
        // demand a second signature nobody else can check, over bytes that
        // exist only on this path.
        //
        // A vault creation has no object digest of its own and signs the
        // operation, so `sofi::signature::verify_operation` is the one place
        // that knows which rule each of the three follows. Every one of them
        // is fail-closed and BEFORE the chain tip is computed: the signature
        // is part of the committed operation bytes.
        if matches!(
            operation,
            Operation::SofiSetup { .. }
                | Operation::SofiVaultCreate { .. }
                | Operation::SofiFulfill { .. }
        ) {
            crate::sofi::signature::verify_operation(&operation, &self.public_key)?;
        }

        // A FULFILLMENT NEEDS ITS ADMISSION, like every other value-moving
        // operation. `classify` calls it a `ClosedWriteSet`; every other
        // operation in that class has a `require_attached_*` call site, and
        // this one had none — so a `SofiFulfill` advanced the head with a
        // valid signature and no accepting gate whatsoever.
        if matches!(operation, Operation::SofiFulfill { .. }) {
            self.require_attached_sofi_admission(&operation, "a SoFi fulfillment")?;
        }

        // BUILTIN ISSUANCE IS NOT SELF-AUTHORIZABLE.
        //
        // A `Mint` naming a builtin policy commit (ERA, dBTC) creates units of a
        // supply nobody may unilaterally expand. Every check that used to stand
        // between a caller and that credit was satisfiable by the caller alone:
        // the route builds its own authorization and stamps `authorized_by` with
        // the caller's own device id; ERA's preloaded policy carries zero
        // conditions and zero roles, so the enforcer iterates nothing and
        // returns "allowed"; dBTC has no registered policy at all and takes the
        // builtin escape hatch; and `validate_conservation` only checks that the
        // single credit delta matches the amount and asset the same caller
        // signed. Nothing anywhere established a right to issue.
        //
        // The gate lives HERE, at the accepting transition, and not on the route,
        // because a route guard binds only the callers that go through it: any
        // future route, or any direct `advance` caller, would silently reopen the
        // hole. This is the chokepoint every mint must cross.
        //
        // Fail-closed with no exemption for BUILTINS: class 0x0029 exists and
        // authorizes user-token issuance, but a builtin's issuance is not
        // self-authorizable under any policy signature — ERA enters through
        // the faucet's bootstrap tickets, dBTC through the Bitcoin tap. A
        // `SupplyCap` condition would NOT be an issuance predicate either: it
        // reads `circulating_le` from caller-supplied enforcement context, and
        // no canonical producer authenticates that number.
        // Keyed on `policy_commit`, which is the identity that actually moves
        // value: `validate_conservation` binds the credit delta to it, `balances`
        // is keyed by it, and the compat projection resolves a ticker FROM it.
        // The `token_id` string is metadata — a mint carrying the ticker "ERA"
        // with a non-builtin commit credits that non-builtin asset and can never
        // project as ERA, so rejecting on the string would refuse honest mints
        // without closing anything.
        // THE PENDING-ADMISSION FENCE.
        //
        // Reads `self`, not an argument. A caller-supplied `pending: bool`
        // would move the bypass one argument inward — anyone wanting to spend
        // fenced value would pass `false`. The state rides on the head, so
        // every route AND every direct internal caller crosses this same gate,
        // which is the invariant that matters (the builtin-mint incident found
        // three suites calling `advance` directly, bypassing the route).
        //
        // The predicate is the exhaustive economic classifier, NOT
        // `Operation::is_value_bearing`: that gate exists for recovery and is
        // too coarse here — `DlvUnlock` is value-egress by its measure while
        // producing no `R_econ` mutation at all.
        if let Some(pending) = &self.pending_economic_admission {
            let effect = crate::economic::classifier::classify(&operation);
            crate::economic::admission::fence_allows(pending, effect, &operation)
                .map_err(|blocked| DsmError::invalid_operation(format!("advance: {blocked}")))?;
        }

        // THE FAUCET-CLAIM ACCEPTING GATE. A faucet claim must not be a raw
        // local-balance mint: it is refused unless a matching economic
        // admission is ALREADY attached to this head (attached in `Prepared`,
        // which does not fence), binding this exact operation's digest. The
        // only way core installs the +100 is with the fence already riding
        // the head, and the commit seam makes head+row atomic. A modified
        // client that skips the attach gets this refusal; one that fakes and
        // locally clears it holds value NO FOREIGN VERIFIER accepts — which
        // is the economic-root guarantee doing its job.
        //
        // Range is enforced here too; the CANONICAL faucet_id is enforced
        // where the authenticated network_id exists (the provenance verifier,
        // and the register node) — this layer has only the genesis DIGEST and
        // cannot recompute era_faucet_id(network_id) without un-hashing it.
        if let Operation::FaucetClaim { ticket_index, .. } = &operation {
            if *ticket_index >= crate::economic::faucet::ERA_FAUCET_TICKET_COUNT {
                return Err(DsmError::invalid_operation(format!(
                    "advance: faucet ticket_index {ticket_index} is not a coordinate that \
                     exists — the allocation is exactly {} tickets",
                    crate::economic::faucet::ERA_FAUCET_TICKET_COUNT
                )));
            }
            self.require_attached_dsm_admission(&operation, "a faucet claim")?;
        }

        // THE CREDIT-DIRECTION TRANSFER ACCEPTING GATE (3.5b PR4). An online
        // credit-direction Transfer — `authority_policy: None`, addressed to
        // THIS device — installs a positive balance the recipient never held;
        // without an attached economic admission it would be a raw local
        // credit, spendable before any foreign verifier could refuse it. Same
        // discipline as the faucet gate, same reason, TOTAL: the BLE/USB
        // bilateral receiver crosses this exact seam with an
        // indistinguishable operation and is refused fail-closed until its
        // own admission wiring lands (owner ruling 2026-08-27 — no transport
        // exemption; bearer-tier transfers carry `authority_policy: Some` and
        // are untouched). Debit-direction stays un-gated in core: a raw local
        // debit is self-harm, and a skipped debit admission strands only the
        // skipper's own lineage.
        if let Operation::Transfer {
            to_device_id,
            authority_policy: Option::None,
            ..
        } = &operation
        {
            if to_device_id.len() == 32 && to_device_id.as_slice() == self.devid.as_slice() {
                self.require_attached_dsm_admission(
                    &operation,
                    "an online credit-direction transfer",
                )?;
            }
        }

        // THE MINT GATE. A positive mint CREATES units — the one operation
        // whose whole effect is a credit with no prior holder — so it may
        // enter canonical device state only through the economic-admission
        // fence, exactly like a faucet claim or an online credit-direction
        // transfer. This layer does NOT parse the 0x0029 evidence; its job is
        // narrower and load-bearing: no raw local positive credit without an
        // attached admission. The economic verifier proves the admission's
        // 0x0023 AuthorizedIssuance source during validation.
        //
        // The builtin arm stays UNCONDITIONAL and is keyed on the COMMIT, not
        // the ticker: builtin issuance is not self-authorizable under any
        // admission — ERA enters through the faucet's bootstrap tickets, and
        // dBTC arrives with the Bitcoin tap integration.
        if let Operation::Mint {
            policy_commit,
            amount,
            ..
        } = &operation
        {
            if let Some(name) =
                crate::core::token::token_state_manager::builtin_token_id_for_policy_commit(
                    policy_commit,
                )
            {
                return Err(DsmError::invalid_operation(format!(
                    "advance: refusing to mint the builtin token {name} — builtin issuance is not \
                     self-authorizable; ERA is distributed by the faucet's bootstrap tickets and \
                     dBTC issuance arrives with the Bitcoin tap integration"
                )));
            }
            if amount.value() > 0 {
                self.require_attached_dsm_admission(&operation, "an authorized issuance mint")?;
            }
        }

        // THE SECOND ISSUANCE OPERATION. `CreateToken` carries an issuance leg,
        // and `validate_conservation` deliberately PERMITS it (the arm requires
        // exactly one credit of `initial_supply` under the new token's own
        // commit). Refusing it only in the route and only in the write-set
        // builder leaves the chokepoint itself open — precisely the shape that
        // made `Mint` a live defect, since a route guard binds one caller and
        // the write-set rule binds only paths that build one.
        //
        // No production caller can reach it today: `Operation::CreateToken` has
        // a single constructor, which passes only the ERA fee debit, so
        // conservation would refuse a supply leg for want of the delta. That is
        // an argument for fencing it now rather than later — the gap is
        // currently free to close, and it is exactly the kind that a future
        // caller closes by accident in the wrong direction.
        if let Operation::CreateToken { initial_supply, .. } = &operation {
            if initial_supply.value() > 0 {
                return Err(DsmError::invalid_operation(
                    "advance: refusing to create a token with initial supply — supply at \
                     creation has no issuance source. Create the token with zero supply and \
                     issue through token.mint, whose credit is funded by a 0x0029 issuance \
                     authorization the verifier reruns",
                ));
            }
        }

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

        // ADOPTION GATE. A credit of a non-builtin token is accepted only if
        // this device's PRE-state already commits the token's adoption leaf —
        // the authenticated fact that its public policy was installed here
        // before any value under it arrived. This is what keeps receipt
        // verifiable offline: nothing about the token is fetched at acceptance
        // time. The creator adopts in the same advance that creates (the leaf
        // is written below, from the signed operation); every other device
        // adopts through `AdoptToken` first. A settlement path that roots the
        // token on the receiver's behalf does not satisfy this, by design.
        for d in deltas {
            if d.direction == BalanceDirection::Credit
                && !self.has_adopted(&d.policy_commit)
                && !matches!(
                    &operation,
                    Operation::CreateToken { policy_commit, .. } if *policy_commit == d.policy_commit
                )
            {
                return Err(DsmError::invalid_operation(format!(
                    "advance: refusing to credit token {} — this device has not adopted its \
                     policy; adoption (ADD TOKEN) must precede receipt so the policy is \
                     verifiable from local state",
                    crate::types::identifiers::encode_crockford(&d.policy_commit)
                )));
            }
        }

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

        // Every non-relationship leaf this advance writes. ONE vector, consumed
        // by every batch arm and by the `extra_leaves` replay, so no arm can
        // forget a leaf.
        let mut batch_leaves: Vec<([u8; 32], [u8; 32])> = Vec::new();
        // ADOPTION LEAF. Written from the signed operation, never from a
        // caller-supplied leaf: `AdoptToken` adopts the named policy, and
        // `CreateToken` adopts the token it issues (the creator must be able
        // to receive its own token back). Idempotent — re-adopting rewrites
        // the same value.
        match &operation {
            Operation::AdoptToken { policy_commit, .. }
            | Operation::CreateToken { policy_commit, .. } => {
                batch_leaves.push((Self::token_adoption_leaf_key(policy_commit), *policy_commit));
            }
            _ => {}
        }

        // Build the successor chain state with the updated witness.
        let new_chain_state = RelationshipChainState {
            rel_key,
            embedded_parent,
            counterparty_devid,
            operation,
            entropy,
            encapsulated_entropy,
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
            // The ordinary path, and the only one that keeps `smt_replace`: no
            // anchor leaf, no receipt leaf, no reserve/vault-state leaves. Every
            // transfer.
            None if batch_leaves.is_empty() => {
                let p = new_smt
                    .smt_replace(&rel_key, &child_chain_tip)
                    .map_err(|e| DsmError::invalid_operation(format!("SMT replace failed: {e}")))?;
                (p, None)
            }
            // A reserve-moving advance (funding or owner-apply): the reserve
            // leaves AND the derived vault-state leaf ride the SAME batch as the
            // relationship leaf, so the encumbrance/settlement, the vault state
            // and the transition share one device root. `smt_replace` cannot
            // express this — its child proof binds a root taken before the extra
            // leaves land — and two roots would put the reserve proof and the
            // vault-state proof out of agreement, which `compose_vault_state`
            // requires to be equal.
            None => {
                let pre_root = *new_smt.root();
                let rel_parent = new_smt
                    .get_inclusion_proof(&rel_key, 256)
                    .map_err(|e| DsmError::invalid_operation(format!("rel parent proof: {e}")))?;
                new_smt
                    .update_leaf(&rel_key, &child_chain_tip)
                    .map_err(|e| DsmError::invalid_operation(format!("rel leaf replace: {e}")))?;
                for (k, v) in &batch_leaves {
                    new_smt
                        .update_leaf(k, v)
                        .map_err(|e| DsmError::invalid_operation(format!("adoption leaf: {e}")))?;
                }
                let post_root = *new_smt.root();
                let rel_child = new_smt
                    .get_inclusion_proof(&rel_key, 256)
                    .map_err(|e| DsmError::invalid_operation(format!("rel child proof: {e}")))?;
                (
                    crate::merkle::sparse_merkle_tree::SmtReplaceResult {
                        pre_root,
                        post_root,
                        parent_proof: rel_parent,
                        child_proof: rel_child,
                    },
                    None,
                )
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
                for (k, v) in &batch_leaves {
                    new_smt
                        .update_leaf(k, v)
                        .map_err(|e| DsmError::invalid_operation(format!("adoption leaf: {e}")))?;
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
                // Retain only the entropy: the next advance's sole input from
                // this tip. The state that produced it is not kept — its
                // digest is `child_chain_tip`, already committed to the SMT.
                tip_entropy: new_chain_state.entropy.clone(),
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
        // Adoption leaves replay through `extra_leaves` too, or a reloaded
        // device recomputes a root missing them and refuses to start.
        for (k, v) in &batch_leaves {
            new_extra_leaves.insert(*k, *v);
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
            extra_leaves: new_extra_leaves,
            offline_allocations: new_offline_allocations,
            pending_economic_admission: self.pending_economic_admission.clone(),
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
            extra_leaves: new_extra_leaves,
            offline_allocations: self.offline_allocations.clone(),
            pending_economic_admission: self.pending_economic_admission.clone(),
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
            extra_leaves: new_extra_leaves,
            offline_allocations: new_offline_allocations,
            pending_economic_admission: self.pending_economic_admission.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::operations::{Operation, TransactionMode};

    fn devid(b: u8) -> [u8; 32] {
        [b; 32]
    }
    /// The test device's ACTUAL signing keypair, cached — SPHINCS+ keygen is slow.
    ///
    /// `pubkey()` used to be `vec![0xAA; 64]`, which was fine while nothing verified
    /// anything. `advance` verifies the signed SoFi operations against the advancing
    /// device's own key, so a head whose public key is not a real SPX256f key cannot
    /// authorize its own transitions — and a test that cannot sign is a test that
    /// cannot exercise the gate. Same 64-byte length (SPX256f pk = 2n), so every other
    /// fixture is unaffected.
    fn test_keypair() -> &'static crate::crypto::signatures::SignatureKeyPair {
        static KP: std::sync::OnceLock<crate::crypto::signatures::SignatureKeyPair> =
            std::sync::OnceLock::new();
        KP.get_or_init(|| {
            crate::crypto::signatures::SignatureKeyPair::generate_from_entropy(&[0xAA; 32])
                .expect("test keypair")
        })
    }

    fn pubkey() -> Vec<u8> {
        test_keypair().public_key.clone()
    }

    fn pc(b: u8) -> [u8; 32] {
        [b; 32]
    }

    // ── vault reserves ─────────────────────────────────────────────────────
    //
    // A SoFi vault's advertised liquidity was a number inside its fulfillment
    // condition: the owner asserted it, nothing held it, and a settled swap
    // moved no value. These pin the accounting that makes the claim real.

    /// BUILTIN ISSUANCE IS REFUSED AT THE ACCEPTING TRANSITION.
    ///
    /// Not at the route — at `advance`, the chokepoint every mint must cross.
    /// Before this gate, `token.mint {token_id: "ERA", amount: <any>}` was a live
    /// production route that credited the caller: the handler signs its own
    /// authorization and stamps `authorized_by` with the caller's own device id;
    /// ERA's preloaded policy has zero conditions and zero roles, so enforcement
    /// returns "allowed"; dBTC has no policy at all and takes the builtin escape
    /// hatch; and conservation only checks that the single credit matches the
    /// amount and asset the same caller signed.
    ///
    /// MUTATION CONTROL: delete the builtin-issuance block in `advance` and this
    /// test goes green by minting ERA from air — which is precisely the defect.
    #[test]
    fn a_builtin_token_cannot_be_minted_from_air_at_the_accepting_transition() {
        for ticker in ["ERA", "dBTC"] {
            let pc = crate::core::token::builtin_policy_commit_for_token(ticker)
                .expect("builtin commit");
            let dev = DeviceState::new(devid(0xA1), devid(0xA1), vec![0x01; 32], 64);
            let rk =
                crate::core::bilateral_transaction_manager::compute_smt_key(&dev.devid, &dev.devid);
            let tip = crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                &dev.devid, &dev.devid,
            );
            let outcome = dev.advance(
                rk,
                dev.devid,
                mint_op_for(u64::MAX, pc),
                entropy(7),
                None,
                &[BalanceDelta {
                    policy_commit: pc,
                    direction: BalanceDirection::Credit,
                    amount: u64::MAX,
                }],
                Some(tip),
                None,
                None,
            );
            // Fail for the RIGHT reason — an `is_err()` assertion would pass just
            // as happily on an unrelated error.
            let err = format!(
                "{}",
                outcome.expect_err("minting a builtin token from air must be refused")
            );
            assert!(
                err.contains("builtin issuance is not self-authorizable") && err.contains(ticker),
                "must fail as unauthorized builtin issuance naming {ticker}, got: {err}"
            );
        }
    }

    /// NO ASSET MINTS FROM AIR — and the two refusals stay distinguishable.
    ///
    /// This used to pin the opposite: a builtin ticker carrying a NON-builtin
    /// `policy_commit` credited that asset, on the reasoning that refusing it
    /// would reject honest issuance. That reasoning assumed honest issuance was
    /// expressible. It is not: `R_econ` funds a credit only through a
    /// `CreditSource`, and AT THE TIME the issuance arm (`0x0023`) failed
    /// closed with class `0x0029` unwritten (it exists now; the builtin
    /// refusal here is unconditional regardless). So the units were not
    /// honest issuance — they were
    /// unadmittable, they became DLV vault reserves through the head-gated
    /// funding path, and holding them permanently blocked `activate`.
    ///
    /// The gate is still keyed on the ASSET rather than the ticker: both assets
    /// refuse, but for different reasons, and this pins that they do not
    /// collapse into one blanket refusal. Since the 0x0029 producer cut, the
    /// non-builtin reason is the ADMISSION FENCE: a positive mint may enter
    /// only with an attached DsmBacked admission whose digest names exactly
    /// this operation — a raw local credit is refused before any balance
    /// changes, and the economic verifier proves the admission's issuance
    /// source separately.
    ///
    /// THE MUTATION CONTROL for the issuance gate: replace the
    /// `require_attached_dsm_admission` call in the Mint arm of `advance` with
    /// `Ok(())` and this test goes red by actually crediting 1_000 units of a
    /// non-builtin asset into the head.
    #[test]
    fn no_asset_mints_from_air_and_the_two_refusals_stay_distinct() {
        let pc = [0x5Au8; 32];
        assert!(
            crate::core::token::token_state_manager::builtin_token_id_for_policy_commit(&pc)
                .is_none(),
            "fixture must not accidentally name a builtin"
        );
        let dev = DeviceState::new(devid(0xA2), devid(0xA2), vec![0x02; 32], 64);
        let rk =
            crate::core::bilateral_transaction_manager::compute_smt_key(&dev.devid, &dev.devid);
        let tip = crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &dev.devid, &dev.devid,
        );
        // `mint_op_for` hard-codes the ticker "ERA" while naming this commit.
        let err = format!(
            "{}",
            dev.advance(
                rk,
                dev.devid,
                mint_op_for(1_000, pc),
                entropy(8),
                None,
                &[BalanceDelta {
                    policy_commit: pc,
                    direction: BalanceDirection::Credit,
                    amount: 1_000,
                }],
                Some(tip),
                None,
                None,
            )
            .expect_err("an unadmitted mint must be refused at the accepting layer")
        );
        assert!(
            err.contains("no pending economic admission"),
            "the non-builtin refusal is the ADMISSION FENCE, got: {err}"
        );
        assert!(
            !err.contains("builtin issuance is not self-authorizable"),
            "…and is NOT the builtin refusal — the two reasons stay distinct: {err}"
        );
        // Nothing was credited. This is the half a deleted gate would break.
        assert_eq!(
            dev.balance(&pc),
            0,
            "a refused mint credits nothing, so the device can still activate"
        );
    }

    /// THE SECOND ISSUANCE OPERATION IS FENCED AT THE CHOKEPOINT TOO.
    ///
    /// `validate_conservation` deliberately PERMITS `CreateToken`'s issuance
    /// leg, and until this gate existed the only refusals were a route guard
    /// and the write-set builder — both outside `advance`, i.e. exactly the
    /// shape that made `Mint` a live defect. No production caller can reach it
    /// (the single constructor passes only the fee debit), which is why it was
    /// free to close now.
    ///
    /// MUTATION CONTROL: delete the `CreateToken` block in `advance` and this
    /// goes red by creating 500 units of a brand-new asset from air.
    #[test]
    fn creating_a_token_with_initial_supply_is_refused_at_the_accepting_layer() {
        let pc_new = [0x7Cu8; 32];
        assert!(
            crate::core::token::token_state_manager::builtin_token_id_for_policy_commit(&pc_new)
                .is_none(),
            "the new asset must not collide with a builtin"
        );
        let era = crate::core::token::token_state_manager::era_policy_commit();
        // ERA from the faucet: one admitted claim, the protocol payout — enough
        // for the creation fee, which is all this refusal needs to get past.
        let dev = DeviceState::new(devid(0xA4), devid(0xA4), vec![0x04; 32], 64)
            .admitted_faucet_claim(0, 0xA4)
            .expect("faucet claim");
        let rk =
            crate::core::bilateral_transaction_manager::compute_smt_key(&dev.devid, &dev.devid);
        let tip = crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &dev.devid, &dev.devid,
        );
        let op = Operation::CreateToken {
            token_id: b"NEWCOIN".to_vec(),
            initial_supply: bal(500),
            policy_commit: pc_new,
            fee_amount: 100,
            name: "New Coin".to_string(),
            symbol: "NEW".to_string(),
            decimals: 0,
            metadata_uri: None,
            signature: Vec::new(),
        };
        let err = format!(
            "{}",
            dev.advance(
                rk,
                dev.devid,
                op,
                entropy(11),
                None,
                &[
                    BalanceDelta {
                        policy_commit: era,
                        direction: BalanceDirection::Debit,
                        amount: 100,
                    },
                    BalanceDelta {
                        policy_commit: pc_new,
                        direction: BalanceDirection::Credit,
                        amount: 500,
                    },
                ],
                Some(tip),
                None,
                None,
            )
            .expect_err("issuance at creation has no predicate either")
        );
        assert!(
            err.contains("0x0029"),
            "the refusal names the missing issuance predicate, got: {err}"
        );
        // The half a deleted gate would break: no units of the new asset exist.
        assert_eq!(dev.balance(&pc_new), 0, "a refused creation issues nothing");
    }

    /// Zero-supply creation is NOT issuance and stays available — the fee debit
    /// is an ordinary spend. This is what keeps the refusal narrow.
    #[test]
    fn creating_a_token_with_zero_supply_is_still_allowed() {
        let pc_new = [0x7Du8; 32];
        let era = crate::core::token::token_state_manager::era_policy_commit();
        // ERA from the faucet: one admitted claim, exactly the creation fee.
        let dev = DeviceState::new(devid(0xA5), devid(0xA5), vec![0x05; 32], 64)
            .admitted_faucet_claim(0, 0xA5)
            .expect("faucet claim");
        let rk =
            crate::core::bilateral_transaction_manager::compute_smt_key(&dev.devid, &dev.devid);
        let tip = crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &dev.devid, &dev.devid,
        );
        let op = Operation::CreateToken {
            token_id: b"NEWCOIN".to_vec(),
            initial_supply: bal(0),
            policy_commit: pc_new,
            fee_amount: 100,
            name: "New Coin".to_string(),
            symbol: "NEW".to_string(),
            decimals: 0,
            metadata_uri: None,
            signature: Vec::new(),
        };
        let out = dev
            .advance(
                rk,
                dev.devid,
                op,
                entropy(12),
                None,
                &[BalanceDelta {
                    policy_commit: era,
                    direction: BalanceDirection::Debit,
                    amount: 100,
                }],
                Some(tip),
                None,
                None,
            )
            .expect("a zero-supply creation is an ordinary fee spend");
        assert_eq!(
            out.new_device_state.balance(&era),
            crate::economic::faucet::ERA_FAUCET_PAYOUT - 100,
            "the fee is an ordinary debit of the claimed ERA"
        );
        assert_eq!(out.new_device_state.balance(&pc_new), 0);
    }

    /// A zero-amount mint is not issuance, so the issuance refusal does not
    /// claim it — the gate is on units created, not on the operation's name.
    #[test]
    fn a_zero_amount_mint_is_not_refused_as_issuance() {
        let pc = [0x5Au8; 32];
        let dev = DeviceState::new(devid(0xA3), devid(0xA3), vec![0x03; 32], 64);
        let rk =
            crate::core::bilateral_transaction_manager::compute_smt_key(&dev.devid, &dev.devid);
        let tip = crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &dev.devid, &dev.devid,
        );
        let outcome = dev.advance(
            rk,
            dev.devid,
            mint_op_for(0, pc),
            entropy(9),
            None,
            &[BalanceDelta {
                policy_commit: pc,
                direction: BalanceDirection::Credit,
                amount: 0,
            }],
            Some(tip),
            None,
            None,
        );
        if let Err(e) = &outcome {
            let msg = format!("{e}");
            assert!(
                !msg.contains("0x0029"),
                "a zero mint creates no units, so the issuance refusal must not be the reason: \
                 {msg}"
            );
        }
    }

    // ── settlement: positional movement ────────────────────────────────────

    // ── amendment 2c-H: a route settle's movement and its receipt leaves ────

    fn fresh_device(b: u8) -> DeviceState {
        DeviceState::new([0u8; 32], devid(b), pubkey(), 1024)
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
    /// Mint of ERA — the common fixture. Use `mint_op_for` when the test needs
    /// the operation to name a specific asset.
    fn mint_op(amount: u64) -> Operation {
        mint_op_for(
            amount,
            crate::core::token::builtin_policy_commit_for_token("ERA").unwrap(),
        )
    }

    fn mint_op_for(amount: u64, policy_commit: [u8; 32]) -> Operation {
        Operation::Mint {
            amount: bal(amount),
            token_id: b"ERA".to_vec(),
            policy_commit,
            message: String::new(),
        }
    }

    /// A Burn op carrying one debit of `amount` — satisfies the conservation
    /// guard for a single Debit `BalanceDelta` of the same amount.
    fn burn_op_for(amount: u64, policy_commit: [u8; 32]) -> Operation {
        Operation::Burn {
            amount: bal(amount),
            token_id: b"ERA".to_vec(),
            policy_commit,
            proof_of_ownership: vec![],
            message: String::new(),
        }
    }

    /// Value op matching a delta's direction, amount AND asset — the guard now
    /// binds all three, so a fixture must name the asset its delta moves.
    ///
    /// The credit arm is a credit-direction `Transfer`, not a mint: a mint
    /// requires an attached admission carrying `0x0029` issuance evidence,
    /// and this fixture's subject is delta/asset binding, not issuance.
    /// Callers driving the credit direction through `advance` must attach the
    /// matching Prepared admission — see `prepared_for`.
    fn value_op(dir: BalanceDirection, amount: u64, policy_commit: [u8; 32]) -> Operation {
        match dir {
            BalanceDirection::Credit => credit_transfer_op(amount, policy_commit),
            BalanceDirection::Debit => burn_op_for(amount, policy_commit),
        }
    }

    /// A credit-direction `Transfer` addressed to `to` — the only online credit
    /// the accepting layer takes, and only with its admission attached.
    fn credit_transfer_op(amount: u64, policy_commit: [u8; 32]) -> Operation {
        Operation::Transfer {
            to_device_id: devid(0xAA).to_vec(),
            amount: bal(amount),
            token_id: b"ERA".to_vec(),
            policy_commit,
            mode: crate::types::operations::TransactionMode::Bilateral,
            nonce: vec![0x11; 32],
            verification: crate::types::operations::VerificationType::Standard,
            pre_commit: None,
            recipient: devid(0xAA).to_vec(),
            to: Vec::new(),
            message: String::new(),
            signature: Vec::new(),
            authority_policy: None,
        }
    }

    /// The Prepared admission `advance` demands for a credit-direction transfer.
    fn prepared_for(op: &Operation) -> crate::economic::admission::PendingEconomicAdmission {
        crate::economic::admission::PendingEconomicAdmission::prepared(
            crate::economic::admission::PendingAdmissionKind::DsmBacked,
            1,
            [0u8; 32],
            crate::economic::faucet::dsm_operation_digest(&op.to_bytes()),
        )
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
        assert!(validate_conservation(&me, &mint_op_for(9, pcx), &[credit(9, pcx)], None).is_ok());
        assert!(validate_conservation(&me, &mint_op_for(9, pcx), &[debit(9, pcx)], None).is_err());
        assert!(validate_conservation(&me, &mint_op_for(9, pcx), &[credit(8, pcx)], None).is_err());
        assert!(validate_conservation(&me, &burn_op_for(9, pcx), &[debit(9, pcx)], None).is_ok());
        assert!(validate_conservation(&me, &burn_op_for(9, pcx), &[credit(9, pcx)], None).is_err());
        // ASSET BINDING: a mint/burn may not move an asset other than the one
        // the signed operation names. Without this the guard checked only
        // count/direction/amount, so a mint for token X could credit ERA.
        assert!(
            validate_conservation(&me, &mint_op_for(9, pcx), &[credit(9, pc(0xEE))], None).is_err(),
            "mint delta must be bound to the operation's policy_commit"
        );
        assert!(
            validate_conservation(&me, &burn_op_for(9, pcx), &[debit(9, pc(0xEE))], None).is_err(),
            "burn delta must be bound to the operation's policy_commit"
        );
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
    /// The credit shape the recipient path builds for a custom token: a
    /// credit-direction Transfer with its DSM-backed admission attached.
    fn admitted_custom_credit(
        dev: DeviceState,
        policy_commit: [u8; 32],
        amount: u64,
    ) -> (DeviceState, Operation) {
        let credit_op = Operation::Transfer {
            to_device_id: dev.devid.to_vec(),
            amount: bal(amount),
            token_id: b"CUSTOM".to_vec(),
            policy_commit,
            mode: TransactionMode::Bilateral,
            nonce: vec![0x5C; 32],
            verification: crate::types::operations::VerificationType::Standard,
            pre_commit: None,
            recipient: dev.devid.to_vec(),
            to: Vec::new(),
            message: String::new(),
            signature: Vec::new(),
            authority_policy: None,
        };
        let dev = dev.with_pending_economic_admission(Some(
            crate::economic::admission::PendingEconomicAdmission::prepared(
                crate::economic::admission::PendingAdmissionKind::DsmBacked,
                1,
                [0u8; 32],
                crate::economic::faucet::dsm_operation_digest(&credit_op.to_bytes()),
            ),
        ));
        (dev, credit_op)
    }

    /// THE OFFLINE-RECEIPT INVARIANT (owner ruling 2026-09-13). A receiver
    /// must already hold the token's public policy in its OWN authenticated
    /// state before any value under it arrives — it cannot fetch the policy
    /// later, and no online path may root it on the receiver's behalf. Proven
    /// on hardware the other way round: a device that never adopted SOFI was
    /// credited 44.56 SOFI by a routed settlement and could neither see nor
    /// spend it.
    #[test]
    fn a_credit_of_an_unadopted_token_is_refused_at_advance() {
        let bob = fresh_device(0xBB);
        let custom_token = pc(0xF1);
        assert!(!bob.has_adopted(&custom_token));
        let rk_self =
            crate::core::bilateral_transaction_manager::compute_smt_key(&bob.devid, &bob.devid);
        let init_tip =
            crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                &bob.devid, &bob.devid,
            );
        let (bob, credit_op) = admitted_custom_credit(bob, custom_token, 50);
        let err = bob
            .advance(
                rk_self,
                bob.devid,
                credit_op,
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
            .expect_err("a credit of a token this device never adopted must be refused");
        assert!(
            format!("{err}").contains("has not adopted"),
            "the refusal names adoption, got: {err}"
        );
        // Nothing moved: the working copy was discarded with the error.
        assert!(!bob.balances.contains_key(&custom_token));
    }

    /// Positive control for the gate above: adoption first, then the SAME
    /// credit lands. The adoption is a committed leaf, so a reloaded device
    /// recomputes the same root with it.
    #[test]
    fn adoption_precedes_receipt_and_is_committed() {
        let bob = fresh_device(0xBB);
        let custom_token = pc(0xF1);
        let bob = bob.adopt_token(custom_token, 7).expect("adopt");
        assert!(bob.has_adopted(&custom_token));
        assert_eq!(
            bob.extra_leaves
                .get(&DeviceState::token_adoption_leaf_key(&custom_token)),
            Some(&custom_token),
            "adoption is a committed extra leaf, replayed on restore"
        );
        // Builtins are pre-adopted; an unrelated commit is not.
        assert!(
            bob.has_adopted(&crate::core::token::builtin_policy_commit_for_token("ERA").unwrap())
        );
        assert!(!bob.has_adopted(&pc(0xF2)));

        let rk_self =
            crate::core::bilateral_transaction_manager::compute_smt_key(&bob.devid, &bob.devid);
        let (bob, credit_op) = admitted_custom_credit(bob, custom_token, 50);
        let outcome = bob
            .advance(
                rk_self,
                bob.devid,
                credit_op,
                entropy(43),
                None,
                &[BalanceDelta {
                    policy_commit: custom_token,
                    direction: BalanceDirection::Credit,
                    amount: 50,
                }],
                None,
                None,
                None,
            )
            .expect("after adoption the same credit is accepted");
        assert_eq!(
            outcome
                .new_device_state
                .balances
                .get(&custom_token)
                .copied(),
            Some(50)
        );
        // Re-adopting is idempotent: same leaf, same value, no refusal.
        let again = outcome
            .new_device_state
            .adopt_token(custom_token, 8)
            .expect("adopt");
        assert!(again.has_adopted(&custom_token));
    }

    /// The creator adopts in the creation advance itself: a token's issuer
    /// must be able to receive its own token back without a second step.
    #[test]
    fn create_token_adopts_the_token_it_issues() {
        let bob = fresh_device(0xBB);
        let new_token = pc(0xF3);
        let rk_self =
            crate::core::bilateral_transaction_manager::compute_smt_key(&bob.devid, &bob.devid);
        let init_tip =
            crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                &bob.devid, &bob.devid,
            );
        let create = Operation::CreateToken {
            token_id: b"NEWT".to_vec(),
            initial_supply: bal(0),
            policy_commit: new_token,
            fee_amount: 0,
            name: "New".into(),
            symbol: "NEWT".into(),
            decimals: 2,
            metadata_uri: None,
            signature: vec![0xC7; 64],
        };
        let outcome = bob
            .advance(
                rk_self,
                bob.devid,
                create,
                entropy(9),
                None,
                &[],
                Some(init_tip),
                None,
                None,
            )
            .expect("a zero-fee, zero-supply creation advances");
        assert!(outcome.new_device_state.has_adopted(&new_token));
    }

    #[test]
    fn advance_credit_materialises_new_policy_commit_entry() {
        let bob = fresh_device(0xBB);
        let custom_token = pc(0xF1);
        // Adoption is the precondition of receipt (see the tests above); this
        // test is about the balance entry, so adopt first.
        let bob = bob.adopt_token(custom_token, 1).expect("adopt");

        // Bob starts with zero exposure to this policy_commit.
        assert!(
            !bob.balances.contains_key(&custom_token),
            "precondition: fresh device has no entry for the custom token"
        );

        // Simulate the DlvClaim credit landing on Bob's self-loop.
        let rk_self =
            crate::core::bilateral_transaction_manager::compute_smt_key(&bob.devid, &bob.devid);

        // THE CREDIT SHAPE PRODUCTION ACTUALLY USES. A mint is no longer a
        // credit vehicle — issuance is refused at this layer until class
        // 0x0029 exists — so this drives the only online credit that reaches
        // `advance`: a credit-direction Transfer with its DSM-backed admission
        // already attached, exactly as the recipient path builds it.
        let credit_op = Operation::Transfer {
            to_device_id: bob.devid.to_vec(),
            amount: bal(50),
            token_id: b"CUSTOM".to_vec(),
            policy_commit: custom_token,
            mode: TransactionMode::Bilateral,
            nonce: vec![0x5C; 32],
            verification: crate::types::operations::VerificationType::Standard,
            pre_commit: None,
            recipient: bob.devid.to_vec(),
            to: Vec::new(),
            message: String::new(),
            signature: Vec::new(),
            authority_policy: None,
        };
        let bob = bob.with_pending_economic_admission(Some(
            crate::economic::admission::PendingEconomicAdmission::prepared(
                crate::economic::admission::PendingAdmissionKind::DsmBacked,
                1,
                [0u8; 32],
                crate::economic::faucet::dsm_operation_digest(&credit_op.to_bytes()),
            ),
        ));
        let outcome = bob
            .advance(
                rk_self,
                bob.devid,
                credit_op,
                entropy(42),
                None,
                &[BalanceDelta {
                    policy_commit: custom_token,
                    direction: BalanceDirection::Credit,
                    amount: 50,
                }],
                None,
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

        // 100 of the token from an admitted issuance; the subject is what
        // happens to the funds afterwards.
        let funded = dev.admitted_mint(token, 100, 0xC1).expect("admitted mint");

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
        // Three admitted issuances to burn from: a burn is value-bearing without
        // being issuance, so it exercises the same advance path this test is about.
        let dev = fresh_device(0xAB)
            .admitted_mint(pc(0xF1), 1_000, 0xF1)
            .expect("admitted mint")
            .admitted_mint(pc(0xF2), 1_000, 0xF2)
            .expect("admitted mint")
            .admitted_mint(pc(0xF3), 1_000, 0xF3)
            .expect("admitted mint");
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
                burn_op_for(10, pc(0xF1)),
                entropy(1),
                None,
                &[BalanceDelta {
                    policy_commit: pc(0xF1),
                    direction: BalanceDirection::Debit,
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
                burn_op_for(5, pc(0xF2)),
                entropy(2),
                None,
                &[BalanceDelta {
                    policy_commit: pc(0xF2),
                    direction: BalanceDirection::Debit,
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
                burn_op_for(7, pc(0xF3)),
                entropy(3),
                None,
                &[BalanceDelta {
                    policy_commit: pc(0xF3),
                    direction: BalanceDirection::Debit,
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

        // Bootstrap the anchor, hold 100 online from an admitted issuance, then
        // load 40 into the offline allocation.
        let dev = fresh_device(0xD5)
            .with_anchor_state_leaf(&key, &[0xC0u8; 32])
            .expect("bootstrap");
        let funded = dev.admitted_mint(token, 100, 0xD5).expect("admitted mint");
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
                    spend(10),
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
        let dev = (0u8..8)
            .fold(fresh_device(0xAB), |d, u| {
                d.admitted_mint(pc(0xF0 + u), 1_000, 0xF0 + u)
                    .expect("admitted mint")
            })
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
                burn_op_for(1, pc(0xF0 + u as u8)),
                entropy(u as u8 + 1),
                None,
                &[BalanceDelta {
                    policy_commit: pc(0xF0 + u as u8),
                    direction: BalanceDirection::Debit,
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
        // Three admitted issuances to burn from: a burn is value-bearing exactly
        // as a mint is, and a debit needs no credit source of its own.
        let dev = fresh_device(0xAB)
            .admitted_mint(pc(0xF1), 1_000, 0xF1)
            .expect("admitted mint")
            .admitted_mint(pc(0xF2), 1_000, 0xF2)
            .expect("admitted mint")
            .admitted_mint(pc(0xF3), 1_000, 0xF3)
            .expect("admitted mint");

        // Relationship whose FIRST op is value-bearing → Yes.
        let cp = devid(0xC0);
        let rk = compute_smt_key(&dev.devid, &cp);
        let init = initial_chain_tip_from_device_ids(&dev.devid, &cp);
        let o1 = dev
            .advance(
                rk,
                cp,
                burn_op_for(10, pc(0xF1)),
                entropy(1),
                None,
                &[BalanceDelta {
                    policy_commit: pc(0xF1),
                    direction: BalanceDirection::Debit,
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

    /// The burn control for the v2 chain-tip domain: the successor commitment
    /// must be a pure function of succession facts. Two devices in DIFFERENT
    /// balance states performing the identical advance (same parent, same
    /// operation, same entropy) must derive the IDENTICAL chain tip — the
    /// balance map is no longer an input, `R_econ` is the sole authenticated
    /// online balance representation, and a counterparty learns nothing about
    /// the balance portfolio from a tip.
    #[test]
    fn the_chain_tip_commits_succession_facts_and_no_balances() {
        let token = pc(0xCC);
        let bob = devid(0xBB);

        let tip_with_balances = |seed: u64| {
            // differing balance state, each reached through an admitted issuance
            let dev = fresh_device(0xAA)
                .admitted_mint(token, 100 + seed, 0xA0 + seed as u8)
                .expect("admitted issuance")
                .with_pending_economic_admission(None);
            let rk = crate::core::bilateral_transaction_manager::compute_smt_key(&dev.devid, &bob);
            let init =
                crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                    &dev.devid, &bob,
                );
            let out = dev
                .advance(
                    rk,
                    bob,
                    burn_op_for(30, token),
                    entropy(1),
                    None,
                    &[BalanceDelta {
                        policy_commit: token,
                        direction: BalanceDirection::Debit,
                        amount: 30,
                    }],
                    Some(init),
                    None,
                    None,
                )
                .expect("advance");
            out.new_chain_state.compute_chain_tip()
        };

        assert_eq!(
            tip_with_balances(0),
            tip_with_balances(7),
            "identical succession facts must derive identical tips regardless of the \
             device balance state — a difference means balances leaked back into the \
             commitment"
        );

        // And the helper IS the commitment — one preimage, two entry points.
        let dev = fresh_device(0xAA)
            .admitted_mint(token, 100, 0xA8)
            .expect("admitted issuance")
            .with_pending_economic_admission(None);
        let rk = crate::core::bilateral_transaction_manager::compute_smt_key(&dev.devid, &bob);
        let init = crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &dev.devid, &bob,
        );
        let out = dev
            .advance(
                rk,
                bob,
                burn_op_for(30, token),
                entropy(1),
                None,
                &[BalanceDelta {
                    policy_commit: token,
                    direction: BalanceDirection::Debit,
                    amount: 30,
                }],
                Some(init),
                None,
                None,
            )
            .expect("advance");
        let cs = &out.new_chain_state;
        assert_eq!(
            cs.compute_chain_tip(),
            relationship_chain_tip_v2(
                &cs.rel_key,
                &cs.embedded_parent,
                &cs.counterparty_devid,
                &cs.operation.to_bytes(),
                &cs.entropy,
                cs.encapsulated_entropy.as_deref(),
            )
        );
    }

    /// Phase 6 test: stale-snapshot CAS detection.
    /// Two advances built from the SAME parent `r_A` produce different child
    /// `r'_A` values (different relationships → different SMT leaves replaced).
    /// In the CAS layer above this, only the first to install wins; the second
    /// sees its `parent_r_a` no longer matches the current head.
    #[test]
    fn concurrent_advances_from_same_root_produce_different_children() {
        let token = pc(0xCC);
        let dev = fresh_device(0xAA)
            .admitted_mint(token, 100, 0xA0)
            .expect("admitted issuance")
            .with_pending_economic_admission(None);

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
                burn_op_for(10, token),
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
                burn_op_for(20, token),
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
        let token = pc(0xCC);
        let dev = fresh_device(0xAA)
            .admitted_mint(token, 100, 0xA0)
            .expect("admitted issuance")
            .with_pending_economic_admission(None);

        let bob = devid(0xBB);
        let rk = crate::core::bilateral_transaction_manager::compute_smt_key(&dev.devid, &bob);
        let init = crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &dev.devid, &bob,
        );

        let a = dev
            .advance(
                rk,
                bob,
                burn_op_for(10, token),
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
                burn_op_for(20, token),
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
        let token = pc(0xCC);
        let dev = fresh_device(0xAA)
            .admitted_mint(token, 5, 0xA0)
            .expect("admitted issuance")
            .with_pending_economic_admission(None);

        let bob = devid(0xBB);
        let rk = crate::core::bilateral_transaction_manager::compute_smt_key(&dev.devid, &bob);
        let init = crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &dev.devid, &bob,
        );

        let r = dev.advance(
            rk,
            bob,
            burn_op_for(10, token),
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
    ///
    /// The credit MUST be one the accepting layer would otherwise take, or this
    /// stops testing overflow. It used to mint, and the issuance refusal now
    /// fires before the delta loop's `checked_add` is ever reached — the test
    /// would still have been green while proving nothing. So it drives the
    /// credit shape production actually admits, and asserts the failure is the
    /// OVERFLOW rather than any earlier gate.
    #[test]
    fn advance_rejects_balance_overflow() {
        let token = pc(0xCC);
        let dev = fresh_device(0xAA)
            .admitted_mint(token, u64::MAX, 0xA0)
            .expect("admitted issuance")
            .with_pending_economic_admission(None);

        let bob = devid(0xBB);
        let rk = crate::core::bilateral_transaction_manager::compute_smt_key(&dev.devid, &bob);
        let init = crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &dev.devid, &bob,
        );

        let credit_op = credit_transfer_op(1, token);
        let dev = dev.with_pending_economic_admission(Some(prepared_for(&credit_op)));
        let err = format!(
            "{}",
            dev.advance(
                rk,
                bob,
                credit_op,
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
            )
            .expect_err("u64::MAX + 1 must overflow")
        );
        assert!(
            err.contains("overflow"),
            "the refusal must be the overflow itself, not an earlier gate: {err}"
        );
    }

    /// Phase 6 test: balance conservation across cross-relationship sequence.
    /// Property: sum of all deltas across a sequence of valid advances equals
    /// the net change in the device-level balance scalar.
    #[test]
    fn balance_conservation_across_sequence() {
        let _ = TransactionMode::Bilateral; // import keep-alive
        let token = pc(0xCC);
        let mut dev = fresh_device(0xAA)
            .admitted_mint(token, 1000, 0xA0)
            .expect("admitted issuance")
            .with_pending_economic_admission(None);

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
            let op = value_op(dir, amt, token);
            // A credit needs its admission attached; a debit is self-harm and
            // needs none. Both still move the same balance map, which is what
            // this test conserves across.
            let stepped = if matches!(dir, BalanceDirection::Credit) {
                dev.clone()
                    .with_pending_economic_admission(Some(prepared_for(&op)))
            } else {
                dev.clone()
            };
            let out = stepped
                .advance(
                    rk,
                    *party,
                    op,
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
            dev = out.new_device_state.with_pending_economic_admission(None);
        }

        let expected = (1000_i64 + net_delta) as u64;
        assert_eq!(
            dev.balance(&token),
            expected,
            "net balance change must equal sum of signed deltas"
        );
    }

    // ─────────────────────────────────────────────────────────────
    // The vault-state leaf rides the staged advance (one canonical root)
    // ─────────────────────────────────────────────────────────────

    // ─────────────────────────────────────────────────────────────
    // Closing a vault: the complete reserve set returns, exactly once
    // ─────────────────────────────────────────────────────────────

    /// A credit-direction online Transfer addressed to self, exactly the
    /// shape both the online recipient apply AND the BLE/USB bilateral
    /// receiver hand to `advance`.
    fn incoming_online_transfer(to: [u8; 32], amount: u64, asset: [u8; 32]) -> Operation {
        Operation::Transfer {
            to_device_id: to.to_vec(),
            amount: crate::types::token_types::Balance::from_state(amount, [0u8; 32]),
            token_id: b"ERA".to_vec(),
            policy_commit: asset,
            mode: crate::types::operations::TransactionMode::Bilateral,
            nonce: vec![0x4E; 32],
            verification: crate::types::operations::VerificationType::Standard,
            pre_commit: None,
            recipient: to.to_vec(),
            to: Vec::new(),
            message: String::new(),
            signature: Vec::new(),
            authority_policy: None,
        }
    }

    /// THE CREDIT-DIRECTION TRANSFER ACCEPTING GATE (3.5b PR4), full
    /// discipline: `None`, wrong kind, wrong state, and digest mismatch each
    /// get their own named refusal, and the SAME advance succeeds with a
    /// matching `Prepared`/`DsmBacked` admission attached. MUTATION CONTROL:
    /// delete the gate block in `advance` and the first arm here credits a
    /// A FULFILLMENT CANNOT ADVANCE WITHOUT ITS OWN ADMISSION.
    ///
    /// `classify` calls a `SofiFulfill` a `ClosedWriteSet` — it moves value —
    /// and every other operation in that class has a `require_attached_*`
    /// call site in `advance`. This one had none: a valid signature was the
    /// whole gate, so a fulfillment installed its conditional claim with
    /// nothing having accepted the position.
    ///
    /// The admission it needs is `SofiFulfillment`, which fences the LINEAGE.
    /// A `DsmBacked` admission does not authorize it, and neither does an
    /// admission staged for some other operation.
    #[test]
    fn a_sofi_fulfillment_cannot_advance_without_its_own_admission() {
        use crate::crypto::sphincs::{generate_sphincs_keypair, sphincs_sign};
        use crate::economic::admission::{PendingAdmissionKind, PendingEconomicAdmission};
        use crate::economic::faucet::dsm_operation_digest;
        use crate::sofi::derive;
        use crate::sofi::wire::{AttemptEntry, TraderFulfillmentBody};

        let (pk, sk) = generate_sphincs_keypair().unwrap();
        let genesis = [0xAA; 32];
        let devid = [0xBB; 32];
        let head = DeviceState::new(genesis, devid, pk.clone(), 64);

        let body = TraderFulfillmentBody::new(
            [0x0A; 32],
            vec![[0x71; 32]],
            vec![AttemptEntry {
                vault_id: [0xC1; 32],
                attempt: 0,
            }],
            6,
            0x0001,
            &pk,
        )
        .unwrap();
        let operation = Operation::SofiFulfill {
            fulfillment_body: body.encode(),
            precommit_id: [0x0A; 32].to_vec(),
            // Signed correctly: the signature is NOT what is under test.
            signature: sphincs_sign(&sk, &derive::fulfillment_signing_digest(&body)).unwrap(),
        };
        let digest = dsm_operation_digest(&operation.to_bytes());

        let run = |h: &DeviceState| {
            h.advance(
                [0x3A; 32],
                devid,
                operation.clone(),
                entropy(11),
                None,
                &[],
                Some([0x11; 32]),
                None,
                None,
            )
        };

        // 1. No admission at all — the gate that did not exist.
        let msg = run(&head)
            .expect_err("a fulfillment with no admission must be refused")
            .to_string();
        assert!(
            msg.contains("no pending economic admission"),
            "named refusal, got: {msg}"
        );

        // 2. A DSM-backed admission does not authorize a fulfillment.
        let wrong_kind =
            head.with_pending_economic_admission(Some(PendingEconomicAdmission::prepared(
                PendingAdmissionKind::DsmBacked,
                6,
                [0x11; 32],
                digest,
            )));
        let msg = run(&wrong_kind)
            .expect_err("the wrong admission kind must be refused")
            .to_string();
        assert!(
            msg.contains("not a SoFi fulfillment admission"),
            "named refusal, got: {msg}"
        );

        // 3. The right kind, bound to a DIFFERENT operation.
        let wrong_digest =
            head.with_pending_economic_admission(Some(PendingEconomicAdmission::prepared(
                PendingAdmissionKind::SofiFulfillment {
                    fulfillment_id: derive::fulfillment_id(&body),
                },
                6,
                [0x11; 32],
                [0xFF; 32],
            )));
        let msg = run(&wrong_digest)
            .expect_err("an admission authorizes exactly one operation")
            .to_string();
        assert!(msg.contains("does not match"), "named refusal, got: {msg}");

        // 4. Its own Prepared SoFi admission: it advances.
        let correct =
            head.with_pending_economic_admission(Some(PendingEconomicAdmission::prepared(
                PendingAdmissionKind::SofiFulfillment {
                    fulfillment_id: derive::fulfillment_id(&body),
                },
                6,
                [0x11; 32],
                digest,
            )));
        assert!(
            run(&correct).is_ok(),
            "a fulfillment with its own Prepared admission must advance"
        );
    }

    /// THE ADMISSION'S FULFILLMENT ID IS BOUND TO THE ACTUAL F.
    ///
    /// The digest check binds the operation's BYTES; this binds the identity
    /// those bytes derive, and they are different claims. An admission
    /// carrying another F's id would fence this position under a name the
    /// resume path and the route's resolution cannot resolve — the id is the
    /// durable identity, not a label beside it.
    #[test]
    fn the_sofi_admission_must_name_this_fulfillment() {
        use crate::crypto::sphincs::{generate_sphincs_keypair, sphincs_sign};
        use crate::economic::admission::{PendingAdmissionKind, PendingEconomicAdmission};
        use crate::economic::faucet::dsm_operation_digest;
        use crate::sofi::derive;
        use crate::sofi::wire::{AttemptEntry, TraderFulfillmentBody};

        let (pk, sk) = generate_sphincs_keypair().unwrap();
        let genesis = [0xAC; 32];
        let devid = [0xBC; 32];
        let head = DeviceState::new(genesis, devid, pk.clone(), 64);
        let body = TraderFulfillmentBody::new(
            [0x0A; 32],
            vec![[0x71; 32]],
            vec![AttemptEntry {
                vault_id: [0xC1; 32],
                attempt: 0,
            }],
            6,
            0x0001,
            &pk,
        )
        .unwrap();
        let operation = Operation::SofiFulfill {
            fulfillment_body: body.encode(),
            precommit_id: [0x0A; 32].to_vec(),
            signature: sphincs_sign(&sk, &derive::fulfillment_signing_digest(&body)).unwrap(),
        };
        let digest = dsm_operation_digest(&operation.to_bytes());

        let with_id = |fulfillment_id: [u8; 32]| {
            head.with_pending_economic_admission(Some(PendingEconomicAdmission::prepared(
                PendingAdmissionKind::SofiFulfillment { fulfillment_id },
                6,
                [0x11; 32],
                digest,
            )))
        };
        let run = |h: &DeviceState| {
            h.advance(
                [0x3C; 32],
                devid,
                operation.clone(),
                entropy(12),
                None,
                &[],
                Some([0x11; 32]),
                None,
                None,
            )
        };

        // The right kind, the right state, the RIGHT operation digest — and
        // another fulfillment's id. Everything the check looked at before
        // passes; only the identity is wrong.
        let msg = run(&with_id([0xEE; 32]))
            .expect_err("the admission names a different fulfillment")
            .to_string();
        assert!(
            msg.contains("names a different fulfillment"),
            "named refusal, got: {msg}"
        );

        // Its own id: it advances.
        assert!(run(&with_id(derive::fulfillment_id(&body))).is_ok());
    }

    /// THE DEVICE PATH VERIFIES A SOFI SIGNATURE, over the rule that
    /// operation's object actually uses.
    ///
    /// Every other SoFi signature test checks the verifier directly. This one
    /// drives `advance`, because that is the path a real transition takes —
    /// and removing the check there left every one of those tests green.
    #[test]
    fn a_sofi_setup_advances_only_with_a_signature_over_its_own_digest() {
        use crate::crypto::sphincs::{generate_sphincs_keypair, sphincs_sign};
        use crate::sofi::derive;
        use crate::sofi::wire::SofiSetupBody;

        let (pk, sk) = generate_sphincs_keypair().unwrap();
        let genesis = [0xA9u8; 32];
        let devid = [0xB9u8; 32];
        let head = DeviceState::new(genesis, devid, pk.clone(), 64);
        let body = SofiSetupBody::new(
            genesis, devid, 5, [0xC1; 32], [0x66; 32], [0x67; 32], 0x0001, &pk,
        )
        .unwrap();
        let run = |signature: Vec<u8>| {
            head.advance(
                [0x39u8; 32],
                devid,
                Operation::SofiSetup {
                    setup_body: body.encode(),
                    signature,
                },
                entropy(9),
                None,
                &[],
                Some([0x11u8; 32]),
                None,
                None,
            )
        };

        // Unsigned, and signed over the wrong message: the operation's own
        // canonical bytes, which is the generic rule a setup does NOT use.
        let over_the_operation = sphincs_sign(
            &sk,
            &crate::core::state_machine::transition::operation_signing_bytes(
                &Operation::SofiSetup {
                    setup_body: body.encode(),
                    signature: Vec::new(),
                },
            ),
        )
        .unwrap();
        for (signature, case) in [
            (Vec::new(), "unsigned"),
            (vec![0xAB; 49_856], "garbage"),
            (over_the_operation, "signed over the operation, not m_setup"),
        ] {
            assert!(
                run(signature).is_err(),
                "{case}: the device path must refuse it"
            );
        }

        // And `m_setup` — the object's own digest — advances the head.
        let signed = sphincs_sign(&sk, &derive::setup_signing_digest(&body)).unwrap();
        assert!(
            run(signed).is_ok(),
            "a setup signed over m_setup must advance"
        );
    }

    /// transfer with no admission — this test goes red.
    #[test]
    fn a_credit_transfer_requires_the_full_admission_discipline() {
        use crate::economic::admission::{
            AcceptedAdmissionCoords, PendingAdmissionKind, PendingEconomicAdmission,
        };

        let era = pc(0xE7);
        let devid = [0xB7u8; 32];
        let head = DeviceState::new([0xA7; 32], devid, vec![0xC7; 32], 64);
        // Receipt presupposes adoption (owner ruling 2026-09-13): the head must
        // already commit this token's policy before any credit under it.
        let head = head
            .adopt_token(era, 0x11)
            .expect("adopt the incoming token");
        let sender = [0x99u8; 32];
        let rk = [0x33u8; 32];
        let tip = [0x11u8; 32];
        let op = incoming_online_transfer(devid, 10, era);
        let credit = [BalanceDelta {
            policy_commit: era,
            direction: BalanceDirection::Credit,
            amount: 10,
        }];
        let run = |h: &DeviceState| {
            h.advance(
                rk,
                sender,
                op.clone(),
                entropy(4),
                None,
                &credit,
                Some(tip),
                None,
                None,
            )
        };

        // 1. No admission at all.
        let msg = run(&head)
            .expect_err("no admission must refuse")
            .to_string();
        assert!(
            msg.contains("no pending economic admission"),
            "named refusal for the absent admission, got: {msg}"
        );

        // 2. Wrong operation digest.
        let wrong_digest =
            head.clone()
                .with_pending_economic_admission(Some(PendingEconomicAdmission::prepared(
                    PendingAdmissionKind::DsmBacked,
                    1,
                    [0u8; 32],
                    [0xDD; 32],
                )));
        let msg = run(&wrong_digest)
            .expect_err("wrong digest must refuse")
            .to_string();
        assert!(
            msg.contains("does not match the pending"),
            "named refusal for the digest mismatch, got: {msg}"
        );

        // 3. Wrong kind: an offline-boundary admission authorizes no online
        // credit.
        let op_digest = crate::economic::faucet::dsm_operation_digest(&op.to_bytes());
        let wrong_kind =
            head.clone()
                .with_pending_economic_admission(Some(PendingEconomicAdmission::prepared(
                    PendingAdmissionKind::OfflineLoad {
                        asset_policy_commit: era,
                    },
                    1,
                    [0u8; 32],
                    op_digest,
                )));
        let msg = run(&wrong_kind)
            .expect_err("wrong kind must refuse")
            .to_string();
        assert!(
            msg.contains("not DSM-backed"),
            "named refusal for the wrong kind, got: {msg}"
        );

        // 4. Wrong state: a post-acceptance admission belongs to an EARLIER
        // acceptance and authorizes nothing new. (`Admitted` does not fence,
        // so this reaches the gate rather than the fence.)
        let mut stale = PendingEconomicAdmission::prepared(
            PendingAdmissionKind::DsmBacked,
            1,
            [0u8; 32],
            op_digest,
        )
        .into_locally_accepted(AcceptedAdmissionCoords {
            post_economic_root: [2u8; 32],
            accepted_substrate_addr: [4u8; 32],
            admission_manifest_addr: [5u8; 32],
            c_dsm_plus: [6u8; 32],
            embedded_parent: [7u8; 32],
        })
        .expect("prepared -> accepted");
        stale.state = crate::economic::admission::EconomicAdmissionState::Admitted;
        let wrong_state = head.clone().with_pending_economic_admission(Some(stale));
        let msg = run(&wrong_state)
            .expect_err("wrong state must refuse")
            .to_string();
        assert!(
            msg.contains("not Prepared"),
            "named refusal for the wrong state, got: {msg}"
        );

        // 5. Full discipline satisfied: the SAME advance succeeds — the
        // refusals above are the gate, not an unrelated precondition.
        let ok =
            head.clone()
                .with_pending_economic_admission(Some(PendingEconomicAdmission::prepared(
                    PendingAdmissionKind::DsmBacked,
                    1,
                    [0u8; 32],
                    op_digest,
                )));
        let outcome = run(&ok).expect("a matching Prepared DsmBacked admission admits the credit");
        assert_eq!(outcome.new_device_state.balance(&era), 10);
    }

    /// Owner ruling (2026-08-27): NO transport exemption. The BLE/USB
    /// bilateral receiver's online-credit op is byte-indistinguishable at
    /// this seam and is refused fail-closed until its own admission wiring
    /// lands; the bearer tier (`authority_policy: Some`) never crosses this
    /// gate. MUTATION CONTROL: exempting the BLE shape (e.g. keying the gate
    /// on anything transport-flavored) turns this red.
    #[test]
    fn a_ble_shaped_online_credit_is_refused_without_an_admission() {
        let era = pc(0xE8);
        let devid = [0xB8u8; 32];
        let head = DeviceState::new([0xA8; 32], devid, vec![0xC8; 32], 64);
        // Exactly what bilateral_ble_handler builds for the receiver commit:
        // Bilateral mode, authority_policy None, one credit delta.
        let op = incoming_online_transfer(devid, 5, era);
        let msg = head
            .advance(
                [0x34u8; 32],
                [0x9Au8; 32],
                op,
                entropy(5),
                None,
                &[BalanceDelta {
                    policy_commit: era,
                    direction: BalanceDirection::Credit,
                    amount: 5,
                }],
                Some([0x12u8; 32]),
                None,
                None,
            )
            .expect_err("the gate is total across transports")
            .to_string();
        assert!(
            msg.contains("online credit-direction transfer"),
            "the refusal names the gated shape, got: {msg}"
        );
    }
}
