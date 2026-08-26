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

    /// Non-relationship SMT leaves that also commit into the device root `r_A`:
    /// offline-bearer anchor-state leaves ([`Self::with_anchor_state_leaf`], and the
    /// `anchor_leaf` replaced inside [`Self::advance`]), SoFi vault reserve leaves and the
    /// derived vault-state leaf (both written by [`Self::advance`] when a
    /// [`VaultReserveMutation`] rides it). The [`SparseMerkleTree`] is the canonical source
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

    /// Vault reserves: value the owner has ENCUMBERED into a specific SoFi vault. Keyed by
    /// `vault_reserve_key(genesis, devid, vault_id, policy_commit)`; the value is the
    /// extractable `(amount, sequence)` behind the committed reserve leaf (whose hash lives
    /// in [`Self::extra_leaves`]). The leaf hash is not reversible to the amount, so this map
    /// is the enumerable, persisted record.
    ///
    /// Deliberately NOT an entry in [`Self::balances`]. That map is folded whole into
    /// `balance_witness` by [`RelationshipChainState::compute_chain_tip`], so a vault-scoped
    /// key there would change the chain tip a counterparty derives on every unrelated
    /// transfer. Keeping reserves out of it is also what makes the encumbrance real:
    /// `BalanceDelta` can only reach `balances`, so no transfer, mint or burn can spend a
    /// reserve — only the vault chokepoints can. `BTreeMap` for deterministic iteration.
    vault_reserves: BTreeMap<[u8; 32], VaultReserve>,
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

/// Extractable state of one vault reserve leg (see [`DeviceState::vault_reserves`]).
/// The committed leaf value is `vault_reserve_value(amount, sequence)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VaultReserve {
    /// Encumbered balance for this `(vault, asset)`, in the asset's base units.
    pub amount: u64,
    /// The VAULT's sequence at the point this reserve was written — not a per-leaf counter.
    /// Sharing the vault's sequence lets a verifier cross-check this leaf against the
    /// vault-state leaf at the same root.
    pub sequence: u64,
}

/// Result of a vault funding or withdrawal: the advanced state, its root, and one inclusion
/// proof per leg in the order the legs were supplied.
#[derive(Clone, Debug)]
pub struct VaultReserveOutcome {
    pub new_device_state: DeviceState,
    pub new_root: [u8; 32],
    pub proofs: Vec<Vec<u8>>,
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
        // SETTLEMENT: two POSITIONAL deltas, each cross-checked against the
        // signed authorization.
        //
        // Positional and exact, in the shape `CreateToken` already uses — never
        // set-membership. A rule that merely required "a debit of x and a credit
        // of y somewhere in the vector" would accept them reordered, duplicated,
        // or accompanied by a third delta; this accepts exactly one arrangement.
        //
        // And they are checked against the AUTHORIZATION, not merely against
        // each other. Generic zero-sum arithmetic would let a caller move a
        // different pair, or different amounts, as long as the two sides
        // balanced — the deltas must realize the trade that was actually
        // authorized, not merely *a* trade.
        Operation::DlvSettle {
            input_policy_commit,
            output_policy_commit,
            input_amount,
            output_amount,
            ..
        } => {
            if input_policy_commit == output_policy_commit {
                return Err(DsmError::invalid_operation(
                    "conservation: DlvSettle input and output name the same asset",
                ));
            }
            if *input_amount == 0 || *output_amount == 0 {
                return Err(DsmError::invalid_operation(
                    "conservation: DlvSettle amounts must both be non-zero",
                ));
            }
            if deltas.len() != 2 {
                return Err(DsmError::invalid_operation(format!(
                    "conservation: DlvSettle must carry exactly 2 deltas, got {}",
                    deltas.len()
                )));
            }
            let d_in = &deltas[0];
            let d_out = &deltas[1];
            if d_in.policy_commit != *input_policy_commit
                || d_in.direction != BalanceDirection::Debit
                || d_in.amount != *input_amount
            {
                return Err(DsmError::invalid_operation(
                    "conservation: DlvSettle delta[0] must debit the authorized input exactly",
                ));
            }
            if d_out.policy_commit != *output_policy_commit
                || d_out.direction != BalanceDirection::Credit
                || d_out.amount != *output_amount
            {
                return Err(DsmError::invalid_operation(
                    "conservation: DlvSettle delta[1] must credit the authorized output exactly",
                ));
            }
            Ok(())
        }

        // The owner RECORDS a settlement it has already verified. It authorizes
        // no value movement of its own: the trader's credit was final at the
        // trader's advance, and the fee accrues inside the reserves as LP yield,
        // so the owner's spendable balance is untouched. Only reserve leaves
        // move, and those are checked by `validate_vault_reserve_conservation`.
        Operation::DlvOwnerApply { .. } => {
            if !deltas.is_empty() {
                return Err(DsmError::invalid_operation(
                    "conservation: DlvOwnerApply records a verified receipt and must not move balances",
                ));
            }
            Ok(())
        }

        // Closing a vault is a RESERVE move back to `balances`: the release and
        // the credit are computed together from the same leg amounts inside the
        // `Withdraw` arm of `advance`, so a delta riding along would be a second,
        // unconserved movement.
        Operation::DlvClose { .. } => {
            if !deltas.is_empty() {
                return Err(DsmError::invalid_operation(
                    "conservation: DlvClose releases reserves through the Withdraw mutation, not \
                     balance deltas",
                ));
            }
            Ok(())
        }

        // Funding a vault is a RESERVE move, not a balance delta. The value leaves
        // `balances` and lands in a vault-reserve leaf, and both halves are computed from
        // one amount inside `fund_vault_reserves` — so a delta accompanying this operation
        // would be a second, unconserved movement riding along with it.
        //
        // Stated explicitly rather than left to the catch-all because this operation used
        // to build a Debit delta and be rejected by that catch-all: the value-bearing DLV
        // path has never worked, for any vault type, and nothing noticed because the DLV
        // suite asserted on the text of the handler rather than its behaviour.
        Operation::DlvCreate { .. } => {
            if !deltas.is_empty() {
                return Err(DsmError::invalid_operation(
                    "conservation: DlvCreate funds a vault through reserve leaves, not balance deltas",
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

/// Assets to ENCUMBER into a vault as part of a `DlvCreate` transition.
///
/// Rides the same [`DeviceState::advance`] as the transition, so the debit, the
/// reserve leaves and the state transition share one device root. A separate
/// advance would leave a window in which the vault exists, is discoverable and
/// holds nothing — and would give the reserve proof and the vault-state proof
/// two different roots, which `compose_vault_state` requires to be equal, so
/// every quote against that vault would fail closed forever.
///
/// Carries AMOUNTS, never leaf values. The caller is spending its own balance so
/// the amounts are its to state, but each leaf value is derived here from
/// `(amount, vault_sequence)`. Accepting a precomputed leaf would be the same
/// "magnitudes supplied rather than proven" shape that was removed from reserve
/// composition.
/// The vault-state leaf `advance` derived for this batch: what it will prove
/// after `post_root` is taken.
struct DerivedVaultStateLeaf {
    vault_id: [u8; 32],
    sequence: u64,
    reserves_digest: [u8; 32],
    key: [u8; 32],
}

/// Borrowed view of the `Fund` variant, so the encumbrance body reads the same
/// as it did before the mutation type grew a second case.
struct FundingView<'a> {
    vault_id: [u8; 32],
    legs: &'a [([u8; 32], u64)],
    vault_sequence: u64,
}

/// The AMM vault's asset pair and fee, carried on every reserve mutation so
/// [`DeviceState::advance`] can DERIVE the vault-state leaf
/// (`compute_vault_smt_value(sequence, reserves_digest)`) from the reserves it
/// has just moved, in the SAME SMT batch. A vault-state leaf therefore never
/// exists without the reserve move it describes, and its digest is computed
/// from the post-mutation leaves — never accepted from a caller.
///
/// The two sides are 32-byte POLICY COMMITMENTS — the keys the reserve legs are
/// stored under — in canonical (lex-ascending) order, exactly what
/// [`crate::dlv::pair_identity::CanonicalPair`] produces. They are not token
/// labels. The reserves digest is always computed over this canonical order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultStatePair {
    policy_commit_a: [u8; 32],
    policy_commit_b: [u8; 32],
    fee_bps: u32,
}

impl VaultStatePair {
    /// Build from an already-canonical pair (the only production source).
    pub fn from_pair(pair: &crate::dlv::pair_identity::CanonicalPair, fee_bps: u32) -> Self {
        Self {
            policy_commit_a: pair.a(),
            policy_commit_b: pair.b(),
            fee_bps,
        }
    }

    /// Build from two raw policy commits. Refuses a non-canonical or degenerate
    /// pair so a caller cannot smuggle an unordered or single-asset "pair" into
    /// the digest.
    pub fn new(
        policy_commit_a: [u8; 32],
        policy_commit_b: [u8; 32],
        fee_bps: u32,
    ) -> Result<Self, DsmError> {
        if policy_commit_a >= policy_commit_b {
            return Err(DsmError::invalid_operation(
                "vault-state pair: policy commits must be distinct and lex-ascending (a < b)",
            ));
        }
        Ok(Self {
            policy_commit_a,
            policy_commit_b,
            fee_bps,
        })
    }

    /// The lex-lower asset's policy commit.
    pub fn a(&self) -> [u8; 32] {
        self.policy_commit_a
    }

    /// The lex-higher asset's policy commit.
    pub fn b(&self) -> [u8; 32] {
        self.policy_commit_b
    }

    pub fn fee_bps(&self) -> u32 {
        self.fee_bps
    }

    /// The reserves digest for `(reserve_a, reserve_b)` over this pair — the one
    /// definition every anchor, inclusion proof and quote agree on.
    pub fn reserves_digest(&self, reserve_a: u64, reserve_b: u64) -> [u8; 32] {
        crate::dlv::vault_smt_leaf::compute_reserves_digest(
            &self.policy_commit_a,
            &self.policy_commit_b,
            reserve_a,
            reserve_b,
            self.fee_bps,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VaultReserveMutation {
    /// `DlvCreate`: value leaves `balances` and enters the vault's reserve
    /// leaves.
    Fund {
        vault_id: [u8; 32],
        /// `(policy_commit, amount)` — exactly the vault's pair, in canonical
        /// order, every amount non-zero. Checked here rather than trusted.
        legs: Vec<([u8; 32], u64)>,
        /// The vault's sequence at creation. `0` is a real genesis sequence, not
        /// an absence.
        vault_sequence: u64,
        /// The vault's pair + fee; the vault-state leaf is derived from it.
        pair: VaultStatePair,
    },
    /// `DlvOwnerApply`: the owner records a settlement it has verified. The
    /// input the trader paid arrives, the output it took leaves, and `balances`
    /// is untouched — the fee accrues inside the reserves as LP yield, so the
    /// owner's spendable balance is not part of a settlement.
    ApplySettlement {
        vault_id: [u8; 32],
        input_policy_commit: [u8; 32],
        input_amount: u64,
        output_policy_commit: [u8; 32],
        output_amount: u64,
        /// The vault generation this settlement consumes. The output reserve leg
        /// MUST currently sit at exactly this sequence or the advance is refused:
        /// two settlements racing one parent both name `parent_sequence = N`, the
        /// first moves the vault to `N + 1`, and the second now finds a generation
        /// it cannot consume. This is the hard parent-consumption claim — exactly
        /// one settlement succeeds a given generation, whatever a receipt claims.
        parent_sequence: u64,
        /// `parent_sequence + 1`. Every reserve write stamps it, so a stale proof
        /// cannot be replayed against the new state.
        new_sequence: u64,
        /// The vault's pair + fee; `{input, output}` must BE this pair, and the
        /// vault-state leaf at `new_sequence` is derived from it.
        pair: VaultStatePair,
    },
    /// `DlvClose`: the COMPLETE remaining reserve set — both legs of the pair,
    /// exactly, at exactly `parent_sequence` — returns to `balances` atomically,
    /// exactly once; the leaves become `0 @ new_sequence` (terminal, never
    /// deleted, so the vault id can never be re-funded or re-withdrawn). Must
    /// equal the signed `DlvClose` operation field-for-field: the signature
    /// binds the whole transition, unsigned mutation metadata decides nothing.
    Withdraw {
        vault_id: [u8; 32],
        /// `(policy_commit, amount)` — exactly `[pair.a, pair.b]`, in canonical
        /// order, each amount equal to the leaf it drains.
        legs: Vec<([u8; 32], u64)>,
        /// The generation consumed (both leaves must sit at exactly this) and
        /// the terminal generation produced (`parent + 1`).
        parent_sequence: u64,
        new_sequence: u64,
        /// The vault's pair + fee; the terminal vault-state leaf derives
        /// `digest(a, b, 0, 0, fee)` at `new_sequence`.
        pair: VaultStatePair,
    },
}

impl VaultReserveMutation {
    /// The vault this mutation moves reserves for.
    pub fn vault_id(&self) -> [u8; 32] {
        match self {
            VaultReserveMutation::Fund { vault_id, .. }
            | VaultReserveMutation::ApplySettlement { vault_id, .. }
            | VaultReserveMutation::Withdraw { vault_id, .. } => *vault_id,
        }
    }

    /// The vault's pair + fee.
    pub fn pair(&self) -> VaultStatePair {
        match self {
            VaultReserveMutation::Fund { pair, .. }
            | VaultReserveMutation::ApplySettlement { pair, .. }
            | VaultReserveMutation::Withdraw { pair, .. } => *pair,
        }
    }

    /// The vault generation the reserves sit at AFTER this mutation.
    pub fn resulting_sequence(&self) -> u64 {
        match self {
            VaultReserveMutation::Fund { vault_sequence, .. } => *vault_sequence,
            VaultReserveMutation::ApplySettlement { new_sequence, .. }
            | VaultReserveMutation::Withdraw { new_sequence, .. } => *new_sequence,
        }
    }
}

/// The vault-state leaf witness an advance produced, `Some` iff a
/// [`VaultReserveMutation`] rode it. `siblings` (exactly 256) bind the leaf
/// under `AdvanceOutcome::child_r_a`; `sequence` and `reserves_digest` are the
/// values that actually LANDED (derived inside `advance`), so a caller signs
/// what the root commits rather than what it hoped for. Feed straight into
/// [`crate::dlv::vault_smt_leaf::sign_vault_state_inclusion_proof`].
#[derive(Clone, Debug)]
pub struct VaultStateLeafProof {
    pub vault_id: [u8; 32],
    pub sequence: u64,
    pub reserves_digest: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
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

    /// Vault-state leaf witness, `Some` iff a [`VaultReserveMutation`] rode this
    /// advance. Its siblings bind the (derived) leaf under `child_r_a` — the same
    /// root the reserve leaves and the relationship leaf landed under — so an
    /// owner-published inclusion proof and reserve proof share one root by
    /// construction.
    pub vault_state_proof: Option<VaultStateLeafProof>,
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
            vault_reserves: BTreeMap::new(),
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
        vault_reserves: BTreeMap<[u8; 32], VaultReserve>,
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
        state.vault_reserves = vault_reserves;
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

    /// Build the per-leg inclusion proofs that let a third party VERIFY this
    /// vault's encumbered reserves, rather than take the owner's word for them.
    ///
    /// The amounts come out of the leaves, never from an argument. A caller that
    /// could pass the magnitudes in would be signing its own claim — which is
    /// exactly the self-declared-reserve shape the vault-reserve leaf replaced.
    ///
    /// Legs come back lex-sorted by `policy_commit`, the canonical order the
    /// proof's signature payload is built over.
    ///
    /// Fails closed on an asset this vault does not hold: an absent leg would
    /// otherwise be indistinguishable from a proven zero.
    pub fn vault_reserve_leg_proofs(
        &self,
        vault_id: &[u8; 32],
        policy_commits: &[[u8; 32]],
    ) -> Result<Vec<crate::dlv::vault_reserve_inclusion::ReserveLegProof>, DsmError> {
        let mut legs = Vec::with_capacity(policy_commits.len());
        for policy_commit in policy_commits {
            let key = crate::dlv::vault_reserve_leaf::vault_reserve_key(
                &self.genesis,
                &self.devid,
                vault_id,
                policy_commit,
            );
            let entry = self.vault_reserves.get(&key).ok_or_else(|| {
                DsmError::invalid_operation(
                    "vault_reserve_leg_proofs: this vault holds no reserve for that asset",
                )
            })?;
            let proof = self
                .smt
                .get_inclusion_proof(&key, 256)
                .map_err(|e| DsmError::merkle(format!("vault-reserve leg proof: {e}")))?;
            legs.push(crate::dlv::vault_reserve_inclusion::ReserveLegProof {
                policy_commit: *policy_commit,
                amount: entry.amount,
                smt_siblings: proof.siblings,
            });
        }
        legs.sort_by_key(|l| l.policy_commit);
        Ok(legs)
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
    /// Install a fixture balance. TEST-ONLY: compiled under `cfg(test)` or the
    /// non-default `testing` feature; a production build never sees it.
    ///
    /// This is FIXTURE CONSTRUCTION, not issuance. Builtin issuance is refused at
    /// `advance`, and that refusal is total — it applies in tests exactly as in
    /// production, which is what makes it worth anything. A fixture therefore
    /// cannot obtain ERA by minting and MUST NOT try: not via `faucet.claim`, not
    /// via `wallet.mint_for_self`, not via `Operation::Mint`. Those are issuance
    /// ROUTES, and re-opening one for tests re-opens it for everyone.
    ///
    /// What this does instead is install the state a device would already be in —
    /// the same thing `restore` does for a reloaded device — asserting nothing
    /// about whether any issuance was authorized. Balances live outside the SMT,
    /// so `root()` is unchanged, exactly as in `restore`.
    ///
    /// The amount installed has NO provenance and must never be read as though it
    /// had. This is for tests whose subject is something else and that merely need
    /// a funded starting point.
    #[cfg(any(test, feature = "testing"))]
    pub fn with_balance_for_testing(&self, policy_commit: [u8; 32], amount: u64) -> Self {
        let mut next = self.clone();
        if amount == 0 {
            next.balances.remove(&policy_commit);
        } else {
            next.balances.insert(policy_commit, amount);
        }
        next
    }

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
        // Assets to encumber into a vault as part of THIS transition. `Some`
        // only for `DlvCreate`; every other advance passes `None`.
        reserve_mutation: Option<VaultReserveMutation>,
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

        // AUTHORIZATION ON THE REAL PATH (§ canonical rule, transition.rs).
        //
        // `DlvSettle` and `DlvOwnerApply` are value-moving egress (`EgressAsset::Asset`)
        // and are not among the rule's no-signature exemptions (`Genesis`, `Noop`,
        // `Receive`). They used to reach this point unverified: the rule's own helper,
        // `enforce_operation_authorization`, is only wired into the legacy
        // `create_transition` / `execute_relationship_transition` paths, and neither is
        // on the device-head advance every DLV route actually takes. The signature was
        // therefore hashed into `compute_chain_tip()` — into the SMT leaf and the device
        // root `r_A` — whether or not anyone had produced it.
        //
        // Both are SELF-LOOP transitions (`rel_key = compute_smt_key(actor, actor)`), so
        // the authorizing key is this device's own AK. It is deliberately NOT read out of
        // the operation (`DlvSettle` carries a `settler_public_key`): a key travelling
        // inside the material it authorizes proves nothing, and a caller could name any
        // key it liked. Verifying against `self.public_key()` is what makes the signature
        // bind to the actor whose head is advancing.
        //
        // Fail-closed and BEFORE the chain tip is computed: the signature is part of the
        // committed operation bytes, so an unsigned transition cannot be repaired later
        // without rewriting this tip and every descendant.
        if matches!(
            operation,
            Operation::DlvSettle { .. }
                | Operation::DlvOwnerApply { .. }
                | Operation::DlvClose { .. }
        ) {
            let op_name = operation.get_operation_type();
            crate::core::state_machine::transition::verify_operation_signature(
                &operation,
                &self.public_key,
                op_name,
            )?;
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
        // Fail-closed with no exemption: `EXCEPT through an explicit issuance
        // predicate whose evidence THIS verifier validates` is the intended
        // shape, and no such predicate exists yet — so there is no admissible
        // builtin issuance today rather than a placeholder one. A `SupplyCap`
        // condition would NOT be that predicate: it reads `circulating_le` from
        // caller-supplied enforcement context, and no canonical producer
        // authenticates that number.
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
            let op_digest = crate::economic::faucet::dsm_operation_digest(&operation.to_bytes());
            match &self.pending_economic_admission {
                Some(pending) if pending.operation_digest == op_digest => {}
                Some(_) => {
                    return Err(DsmError::invalid_operation(
                        "advance: refusing a faucet claim whose digest does not match the \
                         pending economic admission — the admission authorizes exactly one \
                         operation",
                    ));
                }
                None => {
                    return Err(DsmError::invalid_operation(
                        "advance: refusing a faucet claim with no pending economic admission \
                         — a claim that installed balance without the admission fence would \
                         be a raw local mint, spendable before any foreign verifier could \
                         refuse it",
                    ));
                }
            }
        }

        if let Operation::Mint { policy_commit, .. } = &operation {
            if let Some(name) =
                crate::core::token::token_state_manager::builtin_token_id_for_policy_commit(
                    policy_commit,
                )
            {
                return Err(DsmError::invalid_operation(format!(
                    "advance: refusing to mint the builtin token {name} — builtin issuance is not \
                     self-authorizable, and no authenticated issuance predicate is defined for it"
                )));
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

        // FUNDING: value leaves `balances` and enters this vault's reserve
        // leaves, in the SAME advance as the transition that creates the vault.
        //
        // Only `DlvCreate` may fund. Every other operation carrying funding is a
        // caller mistake serious enough to refuse rather than ignore: an advance
        // that silently dropped the legs would report success on a vault holding
        // nothing, which is the exact failure this whole path exists to end.
        //
        // Not expressed as `BalanceDelta`s, deliberately. A delta can only reach
        // `balances`, and that is what makes an encumbered reserve unspendable by
        // any transfer, mint or burn — only the vault chokepoints can move it.
        // Routing funding through deltas would give it back.
        let mut new_vault_reserves = self.vault_reserves.clone();
        // Every non-relationship leaf this advance writes: reserve leaves and the
        // vault-state leaf. ONE vector, consumed by every batch arm and by the
        // `extra_leaves` replay, so no arm can forget a leaf.
        let mut batch_leaves: Vec<([u8; 32], [u8; 32])> = Vec::new();
        if let Some(VaultReserveMutation::Fund {
            vault_id: funding_vault,
            legs: funding_legs_in,
            vault_sequence,
            pair,
        }) = &reserve_mutation
        {
            let funding = FundingView {
                vault_id: *funding_vault,
                legs: funding_legs_in,
                vault_sequence: *vault_sequence,
            };
            if !matches!(operation, Operation::DlvCreate { .. }) {
                return Err(DsmError::invalid_operation(
                    "advance: only DlvCreate may encumber reserves",
                ));
            }
            // PAIR COMPLETENESS. An AMM vault's legs ARE its pair — exactly the
            // two assets the vault-state digest is derived over. A third asset,
            // a single leg, or an asset outside the pair would be silently
            // omitted from `digest(a, b, ra, rb, fee)`, giving a signed vault
            // state that describes different reserves than the leaves hold.
            let expected_legs = [pair.a(), pair.b()];
            let actual_legs: Vec<[u8; 32]> = funding.legs.iter().map(|(pc, _)| *pc).collect();
            if actual_legs.as_slice() != expected_legs {
                return Err(DsmError::invalid_operation(
                    "advance: funding legs must be exactly the vault's pair, in canonical order",
                ));
            }
            for (i, (policy_commit, amount)) in funding.legs.iter().enumerate() {
                if *amount == 0 {
                    return Err(DsmError::invalid_operation(
                        "advance: a funding leg must carry a non-zero amount",
                    ));
                }
                // Canonical order and distinctness, checked rather than trusted:
                // a repeated asset would debit twice into one leaf, and an
                // unordered pair would disagree with the order the reserve proof
                // and the advertisement are built in.
                if i > 0 && funding.legs[i - 1].0 >= *policy_commit {
                    return Err(DsmError::invalid_operation(
                        "advance: funding legs must be lex-ascending by policy_commit and distinct",
                    ));
                }

                let key = crate::dlv::vault_reserve_leaf::vault_reserve_key(
                    &self.genesis,
                    &self.devid,
                    &funding.vault_id,
                    policy_commit,
                );
                // ORPHANED ENCUMBRANCE. A leaf already here means a prior
                // creation for this vault got as far as encumbering. Refuse:
                // completing someone else's half-finished creation from inside a
                // value-moving constructor would be a repair, and a repair
                // belongs in an explicit recovery operation where it can be
                // audited.
                if self.vault_reserves.contains_key(&key) {
                    return Err(DsmError::invalid_operation(
                        "advance: this vault already holds a reserve for that asset — \
                         refusing to encumber again",
                    ));
                }

                // The debit. `checked_sub` is the structural guarantee; a
                // handler-side balance check is only there to name the shortfall
                // more readably.
                let cur = new_balances.get(policy_commit).copied().unwrap_or(0);
                let next = cur.checked_sub(*amount).ok_or_else(|| {
                    DsmError::invalid_operation(
                        "advance: insufficient balance to encumber (funding leg exceeds holdings)",
                    )
                })?;
                if next == 0 {
                    new_balances.remove(policy_commit);
                } else {
                    new_balances.insert(*policy_commit, next);
                }

                let leaf_value = crate::dlv::vault_reserve_leaf::vault_reserve_value(
                    *amount,
                    funding.vault_sequence,
                );
                batch_leaves.push((key, leaf_value));
                new_vault_reserves.insert(
                    key,
                    VaultReserve {
                        amount: *amount,
                        sequence: funding.vault_sequence,
                    },
                );
            }
        }

        // THE OWNER RECORDS A SETTLEMENT it has already verified. The input the
        // trader paid arrives, the output it took leaves, and `balances` is
        // untouched: the trader's credit was final at the trader's own advance,
        // and the fee accrues inside the reserves as LP yield.
        //
        // Rides the same batch as the `DlvOwnerApply` transition, for the same
        // reason funding does — a reserve move in a separate advance would leave
        // a root in which the vault's state and its reserves disagree.
        if let Some(VaultReserveMutation::ApplySettlement {
            vault_id: apply_vault,
            input_policy_commit,
            input_amount,
            output_policy_commit,
            output_amount,
            parent_sequence,
            new_sequence,
            pair,
        }) = &reserve_mutation
        {
            if !matches!(operation, Operation::DlvOwnerApply { .. }) {
                return Err(DsmError::invalid_operation(
                    "advance: only DlvOwnerApply may apply a settlement to reserves",
                ));
            }
            if input_policy_commit == output_policy_commit {
                return Err(DsmError::invalid_operation(
                    "advance: a settlement cannot name one asset on both legs",
                ));
            }
            // PAIR COMPLETENESS. `{input, output}` must BE the vault's pair: a
            // settlement introducing a third asset would move a leg the vault-
            // state digest never sees, so the signed state and the leaves would
            // silently disagree.
            {
                let (lo, hi) = if input_policy_commit < output_policy_commit {
                    (*input_policy_commit, *output_policy_commit)
                } else {
                    (*output_policy_commit, *input_policy_commit)
                };
                if [lo, hi] != [pair.a(), pair.b()] {
                    return Err(DsmError::invalid_operation(
                        "advance: a settlement's input and output must be exactly the vault's pair",
                    ));
                }
            }
            if *input_amount == 0 || *output_amount == 0 {
                return Err(DsmError::invalid_operation(
                    "advance: settlement amounts must both be non-zero",
                ));
            }
            // THE HARD PARENT-CONSUMPTION CLAIM. `new_sequence` is a strict unit
            // step, and the vault must currently sit at exactly the generation
            // this settlement names. Two individually-valid settlements racing one
            // parent both carry `parent_sequence = N`; whichever advances first
            // moves every touched leg to `N + 1`, and the second now finds the
            // vault a generation ahead and is refused HERE, in the canonical state
            // transition. Exactly one settlement consumes a generation — a stale or
            // already-consumed parent cannot be folded again, whatever a receipt
            // says. This is the reserve analog of the relationship layer's
            // `UNIQUE(relationship_key, parent_tip)` consume-once tripwire, enforced
            // where the vault's generation actually lives: the device root.
            if *new_sequence
                != parent_sequence.checked_add(1).ok_or_else(|| {
                    DsmError::invalid_operation("advance: settlement sequence overflow")
                })?
            {
                return Err(DsmError::invalid_operation(
                    "advance: a settlement must advance the vault by exactly one generation \
                     (new_sequence must be parent_sequence + 1)",
                ));
            }

            let key_in = crate::dlv::vault_reserve_leaf::vault_reserve_key(
                &self.genesis,
                &self.devid,
                apply_vault,
                input_policy_commit,
            );
            let key_out = crate::dlv::vault_reserve_leaf::vault_reserve_key(
                &self.genesis,
                &self.devid,
                apply_vault,
                output_policy_commit,
            );
            // The output leg is the vault's liquidity being paid out: it must exist
            // AND sit at exactly the parent generation. This is the consume-once
            // check — a leg already at `parent + 1` (or beyond) means the generation
            // was consumed by an earlier settlement.
            match self.vault_reserves.get(&key_out) {
                Some(e) if e.sequence == *parent_sequence => {}
                Some(_) => {
                    return Err(DsmError::invalid_operation(
                        "advance: this settlement targets a vault generation that is not \
                         current — the parent has already been consumed (a second settlement \
                         racing the same parent) or the proof is stale",
                    ))
                }
                None => {
                    return Err(DsmError::invalid_operation(
                        "advance: the vault holds no output reserve for that settlement",
                    ))
                }
            }
            // The input leg may be a first-time asset (created at `new_sequence`);
            // but if it already exists it shares the vault's generation — two legs of
            // one vault are never at different generations.
            if let Some(e) = self.vault_reserves.get(&key_in) {
                if e.sequence != *parent_sequence {
                    return Err(DsmError::invalid_operation(
                        "advance: the settlement input reserve is at a different vault \
                         generation than the parent it names",
                    ));
                }
            }
            let cur_in = self
                .vault_reserves
                .get(&key_in)
                .copied()
                .unwrap_or_default();
            let cur_out = self
                .vault_reserves
                .get(&key_out)
                .copied()
                .unwrap_or_default();

            let next_in = cur_in.amount.checked_add(*input_amount).ok_or_else(|| {
                DsmError::invalid_operation("advance: settlement overflows the input reserve")
            })?;
            // Fails closed rather than wrapping: a vault that cannot pay the
            // output has not settled this trade, whatever a receipt says.
            let next_out = cur_out.amount.checked_sub(*output_amount).ok_or_else(|| {
                DsmError::invalid_operation("advance: the vault cannot pay that settlement output")
            })?;

            for (key, amount) in [(key_in, next_in), (key_out, next_out)] {
                let leaf_value =
                    crate::dlv::vault_reserve_leaf::vault_reserve_value(amount, *new_sequence);
                batch_leaves.push((key, leaf_value));
                new_vault_reserves.insert(
                    key,
                    VaultReserve {
                        amount,
                        sequence: *new_sequence,
                    },
                );
            }
        }

        // THE OWNER CLOSES THE VAULT: the complete remaining reserve set moves
        // back to `balances` atomically, exactly once, and the leaves become
        // `0 @ parent + 1` — a terminal generation that can neither be funded
        // (the leaves exist) nor withdrawn (both are already zero) again.
        //
        // The signed `DlvClose` operation binds the WHOLE transition; the
        // mutation is checked against it FIELD FOR FIELD before anything moves.
        // (`ApplySettlement` never cross-checked op vs mutation — this arm does
        // not repeat that.)
        if let Some(VaultReserveMutation::Withdraw {
            vault_id: close_vault,
            legs: close_legs,
            parent_sequence: close_parent,
            new_sequence: close_new,
            pair: close_pair,
        }) = &reserve_mutation
        {
            let Operation::DlvClose {
                vault_id: op_vault,
                leg_a_policy_commit,
                leg_a_amount,
                leg_b_policy_commit,
                leg_b_amount,
                parent_sequence: op_parent,
                new_sequence: op_new,
                fee_bps: op_fee,
                ..
            } = &operation
            else {
                return Err(DsmError::invalid_operation(
                    "advance: only DlvClose may withdraw reserves",
                ));
            };
            // WITHDRAW == OP, field for field.
            if op_vault.as_slice() != close_vault.as_slice()
                || *op_parent != *close_parent
                || *op_new != *close_new
                || *op_fee != close_pair.fee_bps()
                || close_legs.as_slice()
                    != [
                        (*leg_a_policy_commit, *leg_a_amount),
                        (*leg_b_policy_commit, *leg_b_amount),
                    ]
            {
                return Err(DsmError::invalid_operation(
                    "advance: the Withdraw mutation does not equal the signed DlvClose \
                     (vault, legs, generation or pair) — refusing",
                ));
            }
            // PAIR COMPLETENESS: the legs are exactly the vault's pair, canonical
            // order, no duplicates, nothing else. A one-leg or foreign-leg close
            // would leave the other asset encumbered forever while the vault
            // reads as closed.
            let close_expected = [close_pair.a(), close_pair.b()];
            let close_actual: Vec<[u8; 32]> = close_legs.iter().map(|(pc, _)| *pc).collect();
            if close_actual.as_slice() != close_expected {
                return Err(DsmError::invalid_operation(
                    "advance: a close must drain exactly the vault's pair, in canonical order",
                ));
            }
            if *close_new
                != close_parent.checked_add(1).ok_or_else(|| {
                    DsmError::invalid_operation("advance: close sequence overflow")
                })?
            {
                return Err(DsmError::invalid_operation(
                    "advance: a close must advance the vault by exactly one generation",
                ));
            }
            // Every named leaf must EXIST at exactly the parent generation, and
            // its amount must EQUAL the leg — a partial or over-withdraw is
            // refused; a leaf at another generation is a stale or already-
            // consumed parent.
            let mut all_zero = true;
            let mut keys = Vec::with_capacity(2);
            for (pc, amount) in close_legs.iter() {
                let key = crate::dlv::vault_reserve_leaf::vault_reserve_key(
                    &self.genesis,
                    &self.devid,
                    close_vault,
                    pc,
                );
                let entry = self.vault_reserves.get(&key).ok_or_else(|| {
                    DsmError::invalid_operation(
                        "advance: the vault holds no reserve leaf for a leg named by the close",
                    )
                })?;
                if entry.sequence != *close_parent {
                    return Err(DsmError::invalid_operation(
                        "advance: this close targets a vault generation that is not current — \
                         the parent was consumed by a settlement, or the close is stale",
                    ));
                }
                if entry.amount != *amount {
                    return Err(DsmError::invalid_operation(
                        "advance: a close must withdraw exactly the leaf's amount (no partial \
                         or over-withdraw)",
                    ));
                }
                if entry.amount != 0 {
                    all_zero = false;
                }
                keys.push((key, *pc, *amount));
            }
            // A vault whose complete reserve set is already zero is already
            // closed: refuse rather than mint a second terminal generation.
            if all_zero {
                return Err(DsmError::invalid_operation(
                    "advance: this vault is already closed (both reserves are zero)",
                ));
            }
            // THE RELEASE: credit `balances` by exactly the leg amounts (checked),
            // and leave the leaves at `0 @ new_sequence` — never deleted, so a
            // future `Fund` for this vault id refuses ("already holds a reserve")
            // and a future close refuses ("already closed").
            for (key, pc, amount) in keys {
                let cur = new_balances.get(&pc).copied().unwrap_or(0);
                let next = cur.checked_add(amount).ok_or_else(|| {
                    DsmError::invalid_operation("advance: close credit overflows the balance")
                })?;
                new_balances.insert(pc, next);
                let leaf_value = crate::dlv::vault_reserve_leaf::vault_reserve_value(0, *close_new);
                batch_leaves.push((key, leaf_value));
                new_vault_reserves.insert(
                    key,
                    VaultReserve {
                        amount: 0,
                        sequence: *close_new,
                    },
                );
            }
        }

        // THE VAULT-STATE LEAF, DERIVED — never accepted. Every reserve mutation
        // updates the vault's state leaf in the SAME batch as the reserve leaves,
        // and its value is computed HERE from the post-mutation reserves: the
        // sequence the mutation produced and the digest of the amounts the leaves
        // now hold. So the vault-state proof an owner publishes and the reserve
        // proof it publishes bind ONE root by construction, and no caller can
        // commit a vault-state leaf that disagrees with the leaves (which is
        // worse than two roots: it would be signed and self-consistent).
        //
        // Domain-disjoint from relationship and reserve leaves
        // (`DSM/vault-smt-key\0`), so it shares the tree without colliding.
        let vault_state_leaf: Option<DerivedVaultStateLeaf> = match &reserve_mutation {
            None => None,
            Some(m) => {
                let vault_id = m.vault_id();
                let pair = m.pair();
                let sequence = m.resulting_sequence();
                let reserve_at = |pc: &[u8; 32]| -> Result<u64, DsmError> {
                    let key = crate::dlv::vault_reserve_leaf::vault_reserve_key(
                        &self.genesis,
                        &self.devid,
                        &vault_id,
                        pc,
                    );
                    match new_vault_reserves.get(&key) {
                        Some(e) if e.sequence == sequence => Ok(e.amount),
                        // Both pair legs are written by the arms above at exactly
                        // `sequence`; anything else is an internal contradiction,
                        // refused rather than papered over with a zero.
                        _ => Err(DsmError::invalid_operation(
                            "advance: vault-state leaf cannot be derived — a pair leg is missing \
                             or at a different generation than the mutation produced",
                        )),
                    }
                };
                let ra = reserve_at(&pair.a())?;
                let rb = reserve_at(&pair.b())?;
                let reserves_digest = pair.reserves_digest(ra, rb);
                let key = crate::dlv::vault_smt_leaf::compute_vault_smt_key(&vault_id);
                let value =
                    crate::dlv::vault_smt_leaf::compute_vault_smt_value(sequence, &reserves_digest);
                batch_leaves.push((key, value));
                Some(DerivedVaultStateLeaf {
                    vault_id,
                    sequence,
                    reserves_digest,
                    key,
                })
            }
        };

        // A settling advance WRITES ITS OWN RECEIPT, derived from the operation's
        // fields rather than from anything the caller passes alongside.
        //
        // That derivation is the security property. If recording a receipt were
        // a separate entry point, a trader could write a receipt leaf for a
        // settlement it never paid for, and the leaf would verify — which is the
        // forgery the receipt exists to make impossible. Deriving it here means
        // a receipt can only come into existence through an advance that already
        // satisfied the positional conservation arm, so the leaf cannot describe
        // a different trade than the deltas that moved.
        let settlement_leaf: Option<([u8; 32], [u8; 32])> = match &operation {
            Operation::DlvSettle {
                vault_id,
                settlement_receipt_id,
                external_commitment_x,
                parent_sequence,
                input_policy_commit,
                output_policy_commit,
                input_amount,
                output_amount,
                ..
            } => {
                let vid: [u8; 32] = vault_id.as_slice().try_into().map_err(|_| {
                    DsmError::invalid_operation("DlvSettle: vault_id must be 32 bytes")
                })?;
                let new_sequence = parent_sequence.checked_add(1).ok_or_else(|| {
                    DsmError::invalid_operation("DlvSettle: parent sequence cannot advance")
                })?;
                let trade = crate::dlv::settlement_receipt_leaf::SettledTrade {
                    x: *external_commitment_x,
                    parent_sequence: *parent_sequence,
                    new_sequence,
                    input_policy_commit: *input_policy_commit,
                    input_amount: *input_amount,
                    output_policy_commit: *output_policy_commit,
                    output_amount: *output_amount,
                };
                Some((
                    crate::dlv::settlement_receipt_leaf::settlement_receipt_key(
                        &self.genesis,
                        &self.devid,
                        &vid,
                        settlement_receipt_id,
                    ),
                    crate::dlv::settlement_receipt_leaf::settlement_receipt_value(&trade),
                ))
            }
            _ => None,
        };

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
        let (smt_proofs, anchor_proofs) = match (&anchor_leaf, &settlement_leaf) {
            // The ordinary path, and the only one that keeps `smt_replace`: no
            // anchor leaf, no receipt leaf, no reserve/vault-state leaves. Every
            // transfer.
            (None, None) if batch_leaves.is_empty() => {
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
            (None, None) => {
                let pre_root = *new_smt.root();
                let rel_parent = new_smt
                    .get_inclusion_proof(&rel_key, 256)
                    .map_err(|e| DsmError::invalid_operation(format!("rel parent proof: {e}")))?;
                new_smt
                    .update_leaf(&rel_key, &child_chain_tip)
                    .map_err(|e| DsmError::invalid_operation(format!("rel leaf replace: {e}")))?;
                for (k, v) in &batch_leaves {
                    new_smt.update_leaf(k, v).map_err(|e| {
                        DsmError::invalid_operation(format!("vault reserve/state leaf: {e}"))
                    })?;
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
            // A settling advance with no anchor leaf: the receipt leaf rides the
            // SAME batch as the relationship leaf, so the settlement and its
            // witness share one device root. `smt_replace` cannot express this —
            // its child proof binds a root taken before the receipt leaf lands —
            // so the pre/post roots and both proofs are taken by hand, exactly as
            // the anchor-leaf branch below does.
            (None, Some((rk, rv))) => {
                let pre_root = *new_smt.root();
                let rel_parent = new_smt
                    .get_inclusion_proof(&rel_key, 256)
                    .map_err(|e| DsmError::invalid_operation(format!("rel parent proof: {e}")))?;
                new_smt
                    .update_leaf(&rel_key, &child_chain_tip)
                    .map_err(|e| DsmError::invalid_operation(format!("rel leaf replace: {e}")))?;
                new_smt.update_leaf(rk, rv).map_err(|e| {
                    DsmError::invalid_operation(format!("settlement receipt leaf: {e}"))
                })?;
                for (k, v) in &batch_leaves {
                    new_smt.update_leaf(k, v).map_err(|e| {
                        DsmError::invalid_operation(format!("vault reserve/state leaf: {e}"))
                    })?;
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
            (Some(al), _) => {
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
                if let Some((rk, rv)) = &settlement_leaf {
                    new_smt.update_leaf(rk, rv).map_err(|e| {
                        DsmError::invalid_operation(format!("settlement receipt leaf: {e}"))
                    })?;
                }
                for (k, v) in &batch_leaves {
                    new_smt.update_leaf(k, v).map_err(|e| {
                        DsmError::invalid_operation(format!("vault reserve/state leaf: {e}"))
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

        // The vault-state witness is taken off the FINAL tree, after every arm
        // has landed all its leaves, so its siblings bind exactly `child_r_a`.
        let vault_state_proof = match vault_state_leaf {
            None => None,
            Some(DerivedVaultStateLeaf {
                vault_id,
                sequence,
                reserves_digest,
                key,
            }) => {
                let proof = new_smt.get_inclusion_proof(&key, 256).map_err(|e| {
                    DsmError::invalid_operation(format!("vault-state leaf proof: {e}"))
                })?;
                Some(VaultStateLeafProof {
                    vault_id,
                    sequence,
                    reserves_digest,
                    siblings: proof.siblings,
                })
            }
        };

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
        if let Some((rk, rv)) = settlement_leaf {
            new_extra_leaves.insert(rk, rv);
        }
        // Reserve and vault-state leaves replay through `extra_leaves` too, or a
        // reloaded device recomputes a root missing them and refuses to start.
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
            vault_reserves: new_vault_reserves,
            pending_economic_admission: self.pending_economic_admission.clone(),
        };

        Ok(AdvanceOutcome {
            new_device_state,
            new_chain_state,
            smt_proofs,
            parent_r_a,
            child_r_a,
            anchor_proofs,
            vault_state_proof,
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
            vault_reserves: self.vault_reserves.clone(),
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
            vault_reserves: self.vault_reserves.clone(),
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

    /// Move value between the online balance and a vault's encumbered reserves.
    ///
    /// THE SOLE CHOKEPOINT for reserve movement, and the reason a vault's advertised
    /// liquidity means anything. Funding debits `balances` and credits the per-`(vault,
    /// asset)` reserve leaf by the same amount; withdrawal is the exact inverse. Both legs
    /// of an AMM vault move in ONE call, so a two-asset vault is funded in one advance
    /// against one root rather than two states where the vault is half-funded.
    ///
    /// `vault_sequence` is supplied by the caller because the VAULT owns it, not this leaf:
    /// funding writes at the vault's genesis sequence 0, and a later withdrawal writes at
    /// whatever sequence the vault has reached. Sharing that number with the vault-state
    /// leaf is what lets a verifier tie reserves to a specific vault state.
    ///
    /// Pure: on `Err` nothing is mutated and the caller's state is untouched.
    fn move_vault_reserves(
        &self,
        vault_id: &[u8; 32],
        legs: &[([u8; 32], u64)],
        vault_sequence: u64,
        fund: bool,
    ) -> Result<VaultReserveOutcome, DsmError> {
        let op = if fund { "fund" } else { "withdraw" };
        if legs.is_empty() {
            return Err(DsmError::invalid_operation(format!(
                "{op}_vault_reserves: at least one leg is required"
            )));
        }
        // Two legs naming the same asset would let one silently overwrite the other's
        // leaf, so the pair would be funded with less than the caller asked for.
        for (i, (pc, _)) in legs.iter().enumerate() {
            if legs[..i].iter().any(|(prev, _)| prev == pc) {
                return Err(DsmError::invalid_operation(format!(
                    "{op}_vault_reserves: the same asset appears twice"
                )));
            }
        }

        let mut new_balances = self.balances.clone();
        let mut new_smt = self.smt.clone();
        let mut new_extra_leaves = self.extra_leaves.clone();
        let mut new_vault_reserves = self.vault_reserves.clone();
        let mut keys = Vec::with_capacity(legs.len());

        for (policy_commit, amount) in legs {
            if *amount == 0 {
                return Err(DsmError::invalid_operation(format!(
                    "{op}_vault_reserves: amount must be > 0"
                )));
            }
            let key = crate::dlv::vault_reserve_leaf::vault_reserve_key(
                &self.genesis,
                &self.devid,
                vault_id,
                policy_commit,
            );
            let cur = new_vault_reserves.get(&key).copied().unwrap_or_default();
            let cur_bal = new_balances.get(policy_commit).copied().unwrap_or(0);

            let (new_bal, new_amount) = if fund {
                (
                    cur_bal.checked_sub(*amount).ok_or_else(|| {
                        DsmError::invalid_operation(
                            "fund_vault_reserves: insufficient balance to encumber",
                        )
                    })?,
                    cur.amount.checked_add(*amount).ok_or_else(|| {
                        DsmError::invalid_operation("fund_vault_reserves: reserve overflow")
                    })?,
                )
            } else {
                (
                    cur_bal.checked_add(*amount).ok_or_else(|| {
                        DsmError::invalid_operation("withdraw_vault_reserves: balance overflow")
                    })?,
                    cur.amount.checked_sub(*amount).ok_or_else(|| {
                        DsmError::invalid_operation(
                            "withdraw_vault_reserves: the vault does not hold that much",
                        )
                    })?,
                )
            };

            if new_bal == 0 {
                new_balances.remove(policy_commit);
            } else {
                new_balances.insert(*policy_commit, new_bal);
            }

            let leaf_value =
                crate::dlv::vault_reserve_leaf::vault_reserve_value(new_amount, vault_sequence);
            new_smt.update_leaf(&key, &leaf_value).map_err(|e| {
                DsmError::invalid_operation(format!("vault-reserve leaf update: {e}"))
            })?;
            new_extra_leaves.insert(key, leaf_value);
            // Kept even at amount 0 so the sequence stays monotone and an emptied
            // reserve cannot be replayed from an older leaf.
            new_vault_reserves.insert(
                key,
                VaultReserve {
                    amount: new_amount,
                    sequence: vault_sequence,
                },
            );
            keys.push(key);
        }

        // Every proof is taken against the FINAL root, after all legs are written, so no
        // proof binds an intermediate state in which the vault was half-funded.
        let new_root = *new_smt.root();
        let mut proofs = Vec::with_capacity(keys.len());
        for key in &keys {
            let proof = new_smt
                .get_inclusion_proof(key, 256)
                .map_err(|e| DsmError::merkle(format!("vault-reserve proof: {e}")))?;
            proofs.push(proof.to_bytes());
        }

        Ok(VaultReserveOutcome {
            new_device_state: Self {
                genesis: self.genesis,
                devid: self.devid,
                public_key: self.public_key.clone(),
                smt: new_smt,
                balances: new_balances,
                tips: self.tips.clone(),
                legacy_anchor: self.legacy_anchor,
                extra_leaves: new_extra_leaves,
                offline_allocations: self.offline_allocations.clone(),
                vault_reserves: new_vault_reserves,
                pending_economic_admission: self.pending_economic_admission.clone(),
            },
            new_root,
            proofs,
        })
    }

    /// Apply a settlement to a vault's reserves: input leg in, output leg out.
    ///
    /// The THIRD reserve chokepoint, and deliberately distinct from the other
    /// two. Funding moves value from `balances` into a vault; withdrawal moves
    /// it back. This moves value only WITHIN the vault — the input the trader
    /// paid arrives, the output it took leaves — and touches `balances` not at
    /// all, because the fee accrues inside the reserves as LP yield and the
    /// owner's spendable balance is not part of a settlement.
    ///
    /// That is why it exists rather than being expressed as a fund+withdraw
    /// pair: those would each move the owner's spendable balance through an
    /// intermediate state that never actually occurs.
    ///
    /// Pure: on `Err` nothing is mutated. Fails closed when the vault cannot pay
    /// the output.
    pub fn apply_settlement_to_reserves(
        &self,
        vault_id: &[u8; 32],
        input_policy_commit: &[u8; 32],
        input_amount: u64,
        output_policy_commit: &[u8; 32],
        output_amount: u64,
        new_sequence: u64,
    ) -> Result<VaultReserveOutcome, DsmError> {
        if input_policy_commit == output_policy_commit {
            return Err(DsmError::invalid_operation(
                "apply_settlement_to_reserves: input and output name the same asset",
            ));
        }
        if input_amount == 0 || output_amount == 0 {
            return Err(DsmError::invalid_operation(
                "apply_settlement_to_reserves: amounts must both be > 0",
            ));
        }

        let key_in = crate::dlv::vault_reserve_leaf::vault_reserve_key(
            &self.genesis,
            &self.devid,
            vault_id,
            input_policy_commit,
        );
        let key_out = crate::dlv::vault_reserve_leaf::vault_reserve_key(
            &self.genesis,
            &self.devid,
            vault_id,
            output_policy_commit,
        );

        let cur_in = self
            .vault_reserves
            .get(&key_in)
            .copied()
            .unwrap_or_default();
        let cur_out = self
            .vault_reserves
            .get(&key_out)
            .copied()
            .unwrap_or_default();

        let new_in = cur_in.amount.checked_add(input_amount).ok_or_else(|| {
            DsmError::invalid_operation("apply_settlement_to_reserves: input reserve overflow")
        })?;
        let new_out = cur_out.amount.checked_sub(output_amount).ok_or_else(|| {
            DsmError::invalid_operation(
                "apply_settlement_to_reserves: the vault cannot pay that output",
            )
        })?;

        let mut new_smt = self.smt.clone();
        let mut new_extra_leaves = self.extra_leaves.clone();
        let mut new_vault_reserves = self.vault_reserves.clone();

        for (key, amount) in [(key_in, new_in), (key_out, new_out)] {
            let leaf_value =
                crate::dlv::vault_reserve_leaf::vault_reserve_value(amount, new_sequence);
            new_smt.update_leaf(&key, &leaf_value).map_err(|e| {
                DsmError::invalid_operation(format!("vault-reserve leaf update: {e}"))
            })?;
            new_extra_leaves.insert(key, leaf_value);
            new_vault_reserves.insert(
                key,
                VaultReserve {
                    amount,
                    sequence: new_sequence,
                },
            );
        }

        // Proofs against the FINAL root, so neither binds a state in which only
        // one side of the swap had landed.
        let new_root = *new_smt.root();
        let mut proofs = Vec::with_capacity(2);
        for key in [key_in, key_out] {
            let proof = new_smt
                .get_inclusion_proof(&key, 256)
                .map_err(|e| DsmError::merkle(format!("vault-reserve proof: {e}")))?;
            proofs.push(proof.to_bytes());
        }

        Ok(VaultReserveOutcome {
            new_device_state: Self {
                genesis: self.genesis,
                devid: self.devid,
                public_key: self.public_key.clone(),
                smt: new_smt,
                // Untouched: a settlement moves nothing spendable.
                balances: self.balances.clone(),
                tips: self.tips.clone(),
                legacy_anchor: self.legacy_anchor,
                extra_leaves: new_extra_leaves,
                offline_allocations: self.offline_allocations.clone(),
                vault_reserves: new_vault_reserves,
                pending_economic_admission: self.pending_economic_admission.clone(),
            },
            new_root,
            proofs,
        })
    }

    /// Encumber `legs` into `vault_id`, debiting the online balance. Fails closed on
    /// insufficient funds, leaving this state untouched.
    pub fn fund_vault_reserves(
        &self,
        vault_id: &[u8; 32],
        legs: &[([u8; 32], u64)],
        vault_sequence: u64,
    ) -> Result<VaultReserveOutcome, DsmError> {
        self.move_vault_reserves(vault_id, legs, vault_sequence, true)
    }

    /// Release `legs` from `vault_id` back to the online balance. TEST-ONLY: the
    /// one production door for un-encumbering is the signed `DlvClose` transition
    /// (a `Withdraw` reserve mutation riding `advance`); an unsigned withdrawal
    /// path must not exist in a production build.
    #[cfg(test)]
    pub fn withdraw_vault_reserves(
        &self,
        vault_id: &[u8; 32],
        legs: &[([u8; 32], u64)],
        vault_sequence: u64,
    ) -> Result<VaultReserveOutcome, DsmError> {
        self.move_vault_reserves(vault_id, legs, vault_sequence, false)
    }

    /// Encumbered balance for one `(vault, asset)`, in base units.
    pub fn vault_reserve(&self, vault_id: &[u8; 32], policy_commit: &[u8; 32]) -> u64 {
        let key = crate::dlv::vault_reserve_leaf::vault_reserve_key(
            &self.genesis,
            &self.devid,
            vault_id,
            policy_commit,
        );
        self.vault_reserves.get(&key).map(|r| r.amount).unwrap_or(0)
    }

    /// The full reserve record for one `(vault, asset)`, including its sequence.
    pub fn vault_reserve_entry(
        &self,
        vault_id: &[u8; 32],
        policy_commit: &[u8; 32],
    ) -> Option<VaultReserve> {
        let key = crate::dlv::vault_reserve_leaf::vault_reserve_key(
            &self.genesis,
            &self.devid,
            vault_id,
            policy_commit,
        );
        self.vault_reserves.get(&key).copied()
    }

    /// Every reserve leaf this device holds, for persistence.
    pub fn vault_reserves_snapshot(&self) -> BTreeMap<[u8; 32], VaultReserve> {
        self.vault_reserves.clone()
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
    /// anything. Now that `advance` verifies `DlvSettle` / `DlvOwnerApply` against the
    /// advancing device's own key, a head whose public key is not a real SPX256f key
    /// cannot authorize its own transitions — and a test that cannot sign is a test that
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

    /// Sign `op` with the test device's key over the canonical preimage
    /// (`with_cleared_signature().to_bytes()`), exactly as production does.
    fn sign_op(op: Operation) -> Operation {
        let payload = op.with_cleared_signature().to_bytes();
        let sig = crate::crypto::sphincs::sphincs_sign(&test_keypair().secret_key, &payload)
            .expect("sign test operation");
        op.with_signature(sig)
    }
    fn pc(b: u8) -> [u8; 32] {
        [b; 32]
    }

    // ── vault reserves ─────────────────────────────────────────────────────
    //
    // A SoFi vault's advertised liquidity was a number inside its fulfillment
    // condition: the owner asserted it, nothing held it, and a settled swap
    // moved no value. These pin the accounting that makes the claim real.

    /// THE REPRODUCTION: funding moves value OUT of `balances` and into the
    /// vault's reserve leaves, conserved per asset, in one advance.
    #[test]
    fn funding_a_vault_conserves_value_per_asset() {
        let mut dev = fresh_device(0xA1);
        let (era, rigb) = (pc(0xE0), pc(0xF0));
        dev.balances.insert(era, 50_000);
        dev.balances.insert(rigb, 20_000);
        let vault = [0x77u8; 32];

        let out = dev
            .fund_vault_reserves(&vault, &[(era, 10_000), (rigb, 5_000)], 0)
            .expect("funding");
        let after = &out.new_device_state;

        assert_eq!(
            after.balance(&era),
            40_000,
            "spendable ERA falls by the leg"
        );
        assert_eq!(after.balance(&rigb), 15_000);
        assert_eq!(
            after.vault_reserve(&vault, &era),
            10_000,
            "and lands in the vault"
        );
        assert_eq!(after.vault_reserve(&vault, &rigb), 5_000);

        // Per asset: spendable + encumbered is unchanged.
        assert_eq!(
            after.balance(&era) + after.vault_reserve(&vault, &era),
            50_000
        );
        assert_eq!(
            after.balance(&rigb) + after.vault_reserve(&vault, &rigb),
            20_000
        );
        assert_eq!(out.proofs.len(), 2, "one proof per leg");
    }

    /// Both legs land under ONE root. A half-funded intermediate state must not
    /// be observable, or a trader could quote against a vault holding one side.
    #[test]
    fn both_legs_are_committed_under_one_root() {
        let mut dev = fresh_device(0xA2);
        let (era, rigb) = (pc(0xE0), pc(0xF0));
        dev.balances.insert(era, 50_000);
        dev.balances.insert(rigb, 20_000);
        let vault = [0x77u8; 32];

        let out = dev
            .fund_vault_reserves(&vault, &[(era, 10_000), (rigb, 5_000)], 0)
            .expect("funding");

        // Every proof verifies against the SAME final root — none was taken
        // part-way through the batch.
        for (i, (asset, amount)) in [(era, 10_000u64), (rigb, 5_000u64)].iter().enumerate() {
            assert!(
                crate::dlv::vault_reserve_leaf::verify_vault_reserve_leaf(
                    &out.new_root,
                    &out.new_device_state.genesis,
                    &out.new_device_state.devid,
                    &vault,
                    asset,
                    *amount,
                    0,
                    &out.proofs[i],
                ),
                "leg {i} must verify against the final root"
            );
        }
        assert_eq!(out.new_root, *out.new_device_state.smt.root());
    }

    /// Insufficient funds reject BEFORE anything moves, and the caller's state
    /// is byte-identical afterwards.
    #[test]
    fn insufficient_balance_at_funding_leaves_the_head_untouched() {
        let mut dev = fresh_device(0xA3);
        let (era, rigb) = (pc(0xE0), pc(0xF0));
        dev.balances.insert(era, 50_000);
        dev.balances.insert(rigb, 1_000);
        let vault = [0x77u8; 32];
        let root_before = *dev.smt.root();

        // The SECOND leg is short: the first must not have moved either.
        let err = dev
            .fund_vault_reserves(&vault, &[(era, 10_000), (rigb, 5_000)], 0)
            .expect_err("must refuse");
        assert!(format!("{err}").contains("insufficient"), "got: {err}");

        assert_eq!(*dev.smt.root(), root_before, "root unchanged");
        assert_eq!(dev.balance(&era), 50_000, "the affordable leg did not move");
        assert_eq!(dev.balance(&rigb), 1_000);
        assert_eq!(dev.vault_reserve(&vault, &era), 0);
    }

    /// THE ENCUMBRANCE. Once funded, the value is unreachable through the
    /// ordinary spend path — `BalanceDelta` can only reach `balances`.
    #[test]
    fn funded_reserves_are_unspendable_by_transfer() {
        let mut dev = fresh_device(0xA4);
        let era = pc(0xE0);
        dev.balances.insert(era, 10_000);
        let vault = [0x77u8; 32];

        let funded = dev
            .fund_vault_reserves(&vault, &[(era, 10_000)], 0)
            .expect("funding")
            .new_device_state;
        assert_eq!(funded.balance(&era), 0, "all of it is encumbered");
        assert_eq!(funded.vault_reserve(&vault, &era), 10_000);

        // Spending even one base unit must now fail: the reserve is not spendable.
        let rk = crate::core::bilateral_transaction_manager::compute_smt_key(
            &funded.devid,
            &funded.devid,
        );
        let tip = crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &funded.devid,
            &funded.devid,
        );
        let outcome = funded.advance(
            rk,
            funded.devid,
            Operation::Transfer {
                to_device_id: devid(0xBB).to_vec(),
                amount: crate::types::token_types::Balance::from_state(1, [0u8; 32]),
                token_id: b"ERA".to_vec(),
                policy_commit: era,
                mode: crate::types::operations::TransactionMode::Unilateral,
                nonce: vec![],
                verification: crate::types::operations::VerificationType::Standard,
                pre_commit: None,
                recipient: vec![],
                to: vec![],
                message: String::new(),
                signature: vec![],
                authority_policy: None,
            },
            entropy(9),
            None,
            &[BalanceDelta {
                policy_commit: era,
                direction: BalanceDirection::Debit,
                amount: 1,
            }],
            Some(tip),
            None,
            None,
            None,
        );
        // Fail for the RIGHT reason. A test that merely asserts `is_err()` passes
        // just as happily on an unrelated error, which is how a guard gets
        // credited for work it is not doing.
        let err = format!(
            "{}",
            outcome.expect_err("an encumbered reserve must not be spendable")
        );
        assert!(
            err.contains("underflow") || err.to_lowercase().contains("insufficient"),
            "must fail as a balance shortfall, got: {err}"
        );
    }

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

    /// The gate is keyed on the ASSET, not the ticker string. A mint carrying a
    /// builtin ticker with a non-builtin `policy_commit` credits that non-builtin
    /// asset and can never project as ERA, so refusing it would reject honest
    /// issuance without closing anything. This pins that the gate stays narrow.
    #[test]
    fn a_non_builtin_asset_still_mints_even_under_a_builtin_ticker() {
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
        let out = dev
            .advance(
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
                None,
            )
            .expect("a non-builtin asset is unaffected by the builtin-issuance gate");
        assert_eq!(out.new_device_state.balance(&pc), 1_000);
    }

    // ── reserve authority: the PRODUCTION funding path ─────────────────────
    //
    // The tests above fund through `fund_vault_reserves`, a test-only shim that
    // writes the reserve leaves directly. Production funding never takes that
    // door: it rides a signed `DlvCreate` transition through `advance`, and the
    // value is debited from `balances` inside that same advance, under one root,
    // with the operation's signature committed to the tip. These pin the model
    // — "value cannot be both free wallet balance and delegated vault liquidity"
    // — on that real path.

    /// The self-loop relationship key and genesis tip for a device's own vault
    /// transitions (funding is a `Unilateral` self-loop: the owner encumbers its
    /// own holdings).
    fn self_loop(dev: &DeviceState) -> ([u8; 32], [u8; 32]) {
        (
            crate::core::bilateral_transaction_manager::compute_smt_key(&dev.devid, &dev.devid),
            crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                &dev.devid, &dev.devid,
            ),
        )
    }

    /// A signed `DlvCreate` for `vault`. Funding legs are NOT carried here — they
    /// ride the `Fund` reserve mutation — because a `BalanceDelta` can only reach
    /// `balances`, and routing funding through deltas would hand the value back.
    fn dlv_create(vault: [u8; 32]) -> Operation {
        sign_op(Operation::DlvCreate {
            vault_id: vault.to_vec(),
            creator_public_key: pubkey(),
            parameters_hash: vec![0u8; 32],
            fulfillment_condition: vec![],
            intended_recipient: None,
            token_id: None,
            locked_amount: None,
            signature: vec![],
            mode: TransactionMode::Unilateral,
        })
    }

    /// The vault's canonical pair + a 30 bps fee, the way production builds it
    /// from `CanonicalPair`. `a` must be lex-lower than `b`.
    fn vault_pair(a: [u8; 32], b: [u8; 32]) -> VaultStatePair {
        VaultStatePair::new(a, b, 30).expect("canonical test pair")
    }

    /// A `Unilateral` transfer of `amount` of `asset`, with the matching debit
    /// delta the conservation guard requires.
    fn transfer_op(asset: [u8; 32], amount: u64) -> Operation {
        Operation::Transfer {
            to_device_id: devid(0xBB).to_vec(),
            amount: crate::types::token_types::Balance::from_state(amount, [0u8; 32]),
            token_id: b"ERA".to_vec(),
            policy_commit: asset,
            mode: crate::types::operations::TransactionMode::Unilateral,
            nonce: vec![],
            verification: crate::types::operations::VerificationType::Standard,
            pre_commit: None,
            recipient: vec![],
            to: vec![],
            message: String::new(),
            signature: vec![],
            authority_policy: None,
        }
    }

    /// USER MODEL, TEST 1 — `100 ERA -> lock 60 into a DLV -> spendable is 40,
    /// not 100`, driven through the production `advance(DlvCreate, Fund)` path.
    ///
    /// "Spendable" is proven two ways so the number is not just a reader's
    /// opinion: `balance()` reports 40, AND the ordinary transfer ceiling is
    /// exactly 40 — a 41-unit transfer underflows while a 40-unit transfer
    /// clears and leaves the 60 still encumbered.
    #[test]
    fn funding_via_production_dlvcreate_advance_reduces_spendable_to_the_remainder() {
        let mut dev = fresh_device(0xC1);
        let (era, rigb) = (pc(0xE0), pc(0xF0));
        dev.balances.insert(era, 100);
        dev.balances.insert(rigb, 10);
        let vault = [0x71u8; 32];
        let (rk, tip) = self_loop(&dev);

        // Lock 60 through the real funding transition (empty deltas; legs in Fund).
        // An AMM vault is funded with exactly its pair, so the other side rides
        // along; the claim under test is about the ERA remainder.
        let funded = dev
            .advance(
                rk,
                dev.devid,
                dlv_create(vault),
                entropy(1),
                None,
                &[],
                Some(tip),
                None,
                None,
                Some(VaultReserveMutation::Fund {
                    vault_id: vault,
                    legs: vec![(era, 60), (rigb, 10)],
                    vault_sequence: 0,
                    pair: vault_pair(era, rigb),
                }),
            )
            .expect("production funding must succeed")
            .new_device_state;

        assert_eq!(
            funded.balance(&era),
            40,
            "free balance is the remainder, not 100"
        );
        assert_eq!(
            funded.vault_reserve(&vault, &era),
            60,
            "the 60 is encumbered"
        );

        // The transfer ceiling IS the spendable: 41 must underflow.
        let over = funded.advance(
            rk,
            funded.devid,
            transfer_op(era, 41),
            entropy(2),
            None,
            &[BalanceDelta {
                policy_commit: era,
                direction: BalanceDirection::Debit,
                amount: 41,
            }],
            Some(tip),
            None,
            None,
            None,
        );
        let err = format!("{}", over.expect_err("41 exceeds the 40 free units"));
        assert!(
            err.contains("underflow") || err.to_lowercase().contains("insufficient"),
            "must fail as a shortfall, got: {err}"
        );

        // 40 clears, and the reserve is untouched by draining every free unit.
        let after = funded
            .advance(
                rk,
                funded.devid,
                transfer_op(era, 40),
                entropy(3),
                None,
                &[BalanceDelta {
                    policy_commit: era,
                    direction: BalanceDirection::Debit,
                    amount: 40,
                }],
                Some(tip),
                None,
                None,
                None,
            )
            .expect("spending exactly the free remainder must clear")
            .new_device_state;
        assert_eq!(after.balance(&era), 0, "every free unit is spent");
        assert_eq!(
            after.vault_reserve(&vault, &era),
            60,
            "draining free balance does not reach the reserve"
        );
    }

    /// USER MODEL, TEST 2 (the inverse) — `spend 50 first -> attempt to fund 60
    /// -> reject`. With 50 already gone the vault cannot be over-funded, and the
    /// refusal leaves the head byte-identical: no half-encumbrance.
    #[test]
    fn spending_first_then_funding_beyond_the_remainder_is_refused() {
        let mut dev = fresh_device(0xC2);
        let era = pc(0xE0);
        dev.balances.insert(era, 100);
        let (rk, tip) = self_loop(&dev);

        let spent = dev
            .advance(
                rk,
                dev.devid,
                transfer_op(era, 50),
                entropy(1),
                None,
                &[BalanceDelta {
                    policy_commit: era,
                    direction: BalanceDirection::Debit,
                    amount: 50,
                }],
                Some(tip),
                None,
                None,
                None,
            )
            .expect("spend 50 first")
            .new_device_state;
        assert_eq!(spent.balance(&era), 50);

        let vault = [0x72u8; 32];
        let rigb = pc(0xF0);
        let root_before = *spent.smt.root();
        let err = spent.advance(
            rk,
            spent.devid,
            dlv_create(vault),
            entropy(2),
            None,
            &[],
            Some(tip),
            None,
            None,
            Some(VaultReserveMutation::Fund {
                vault_id: vault,
                legs: vec![(era, 60), (rigb, 10)],
                vault_sequence: 0,
                pair: vault_pair(era, rigb),
            }),
        );
        let err = format!("{}", err.expect_err("cannot encumber 60 out of 50"));
        assert!(
            err.to_lowercase().contains("insufficient"),
            "must name the shortfall, got: {err}"
        );
        assert_eq!(
            *spent.smt.root(),
            root_before,
            "a refused funding moves nothing"
        );
        assert_eq!(spent.balance(&era), 50, "balance intact");
        assert_eq!(spent.vault_reserve(&vault, &era), 0, "no leaf was written");
    }

    /// STALE-STATE GUARD, funding side — an already-encumbered vault asset cannot
    /// be re-encumbered through the production path. This is the device-level
    /// analog of "reject a move made against stale vault state": completing a
    /// second encumbrance for a vault that already holds one would be a silent
    /// repair inside a value-moving constructor. Refused (device_state.rs
    /// "already holds a reserve"), head untouched.
    ///
    /// NOTE — this is NOT the user's test 3 ("owner withdraws from stale v40
    /// while the market advanced to v42"). That scenario has no production
    /// operation to drive: there is no withdraw / unencumber / close (only
    /// `Fund` and `ApplySettlement`), so encumbered liquidity has no path back
    /// to free `balances` at all — stale or fresh. The succession stale-guard
    /// (parent-consumption / reconcile-first) lives at the SDK layer, not here.
    #[test]
    fn refunding_an_already_encumbered_vault_asset_is_refused() {
        let mut dev = fresh_device(0xC3);
        let (era, rigb) = (pc(0xE0), pc(0xF0));
        dev.balances.insert(era, 100);
        dev.balances.insert(rigb, 100);
        let vault = [0x73u8; 32];
        let (rk, tip) = self_loop(&dev);

        let funded = dev
            .advance(
                rk,
                dev.devid,
                dlv_create(vault),
                entropy(1),
                None,
                &[],
                Some(tip),
                None,
                None,
                Some(VaultReserveMutation::Fund {
                    vault_id: vault,
                    legs: vec![(era, 60), (rigb, 10)],
                    vault_sequence: 0,
                    pair: vault_pair(era, rigb),
                }),
            )
            .expect("first funding")
            .new_device_state;
        let root_before = *funded.smt.root();

        // A second funding of the same assets for the same vault — refused.
        let err = funded.advance(
            rk,
            funded.devid,
            dlv_create(vault),
            entropy(2),
            None,
            &[],
            Some(tip),
            None,
            None,
            Some(VaultReserveMutation::Fund {
                vault_id: vault,
                legs: vec![(era, 10), (rigb, 5)],
                vault_sequence: 1,
                pair: vault_pair(era, rigb),
            }),
        );
        let err = format!("{}", err.expect_err("must refuse a second encumbrance"));
        assert!(
            err.contains("already holds a reserve"),
            "must refuse re-encumbrance, got: {err}"
        );
        assert_eq!(*funded.smt.root(), root_before, "the refusal moved nothing");
        assert_eq!(funded.balance(&era), 40, "balance unchanged by the refusal");
        assert_eq!(funded.vault_reserve(&vault, &era), 60, "reserve unchanged");
    }

    /// END TO END: a really-funded vault produces a proof a stranger can check,
    /// and the amounts come OUT of the leaves rather than from an argument.
    ///
    /// This is the join the primitive's own unit tests cannot make — they build
    /// their tree by hand. If `fund_vault_reserves` and the proof format ever
    /// drift, this is what fails.
    #[test]
    fn a_funded_vault_proves_its_reserves_to_a_stranger() {
        use crate::dlv::vault_reserve_inclusion::{
            proven_amount, sign_vault_reserve_inclusion_proof, verify_vault_reserve_inclusion_proof,
        };

        let mut owner = fresh_device(0xA9);
        let (era, rigb) = (pc(0xE0), pc(0xF0));
        owner.balances.insert(era, 50_000);
        owner.balances.insert(rigb, 20_000);
        let vault = [0x77u8; 32];
        let owner = owner
            .fund_vault_reserves(&vault, &[(era, 10_000), (rigb, 5_000)], 3)
            .expect("funding")
            .new_device_state;

        let legs = owner
            .vault_reserve_leg_proofs(&vault, &[era, rigb])
            .expect("the owner can prove what it encumbered");
        let (pk, sk) = crate::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
        let proof = sign_vault_reserve_inclusion_proof(
            &vault,
            3,
            owner.smt.root(),
            &owner.genesis(),
            &owner.devid(),
            legs,
            &pk,
            &sk,
        )
        .expect("sign");

        verify_vault_reserve_inclusion_proof(&proof)
            .expect("a stranger must be able to verify real encumbrance");
        assert_eq!(proven_amount(&proof, &era), Some(10_000));
        assert_eq!(proven_amount(&proof, &rigb), Some(5_000));

        // The owner cannot prove an asset this vault does not hold — an absent
        // leg would otherwise be indistinguishable from a proven zero.
        let err = owner
            .vault_reserve_leg_proofs(&vault, &[era, pc(0xD0)])
            .expect_err("an unheld asset must not yield a leg");
        assert!(format!("{err}").contains("no reserve for that asset"));
    }

    /// After a settlement the proof tracks the NEW amounts at the NEW sequence,
    /// so a trader cannot be shown pre-trade reserves against a post-trade state.
    #[test]
    fn a_settled_vault_proves_its_new_reserves_and_not_the_old_ones() {
        use crate::dlv::vault_reserve_inclusion::{
            proven_amount, sign_vault_reserve_inclusion_proof, verify_vault_reserve_inclusion_proof,
        };

        let mut owner = fresh_device(0xAA);
        let (era, rigb) = (pc(0xE0), pc(0xF0));
        owner.balances.insert(era, 50_000);
        owner.balances.insert(rigb, 20_000);
        let vault = [0x77u8; 32];
        let owner = owner
            .fund_vault_reserves(&vault, &[(era, 10_000), (rigb, 5_000)], 3)
            .expect("funding")
            .new_device_state;
        let owner = owner
            .apply_settlement_to_reserves(&vault, &era, 1_000, &rigb, 970, 4)
            .expect("settle")
            .new_device_state;

        let (pk, sk) = crate::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
        let legs = owner
            .vault_reserve_leg_proofs(&vault, &[era, rigb])
            .expect("legs");
        let proof = sign_vault_reserve_inclusion_proof(
            &vault,
            4,
            owner.smt.root(),
            &owner.genesis(),
            &owner.devid(),
            legs,
            &pk,
            &sk,
        )
        .expect("sign");
        verify_vault_reserve_inclusion_proof(&proof).expect("post-settlement proof verifies");
        assert_eq!(proven_amount(&proof, &era), Some(11_000));
        assert_eq!(proven_amount(&proof, &rigb), Some(4_030));

        // The same legs cannot be presented at the pre-settlement sequence.
        let stale_legs = owner
            .vault_reserve_leg_proofs(&vault, &[era, rigb])
            .expect("legs");
        let stale = sign_vault_reserve_inclusion_proof(
            &vault,
            3,
            owner.smt.root(),
            &owner.genesis(),
            &owner.devid(),
            stale_legs,
            &pk,
            &sk,
        )
        .expect("sign");
        assert!(
            verify_vault_reserve_inclusion_proof(&stale).is_err(),
            "reserves at sequence 4 must not verify as sequence 3"
        );
    }

    // ── settlement: positional movement ────────────────────────────────────

    /// A settlement authorization naming `x` of `in` for `y` of `out`.
    fn settle_op(
        vault: [u8; 32],
        input_pc: [u8; 32],
        input_amount: u64,
        output_pc: [u8; 32],
        output_amount: u64,
    ) -> Operation {
        sign_op(Operation::DlvSettle {
            vault_id: vault.to_vec(),
            owner_public_key: vec![0xAA; 64],
            owner_devid: devid(0xA1),
            owner_genesis: [0u8; 32],
            input_policy_commit: input_pc,
            output_policy_commit: output_pc,
            parent_sequence: 0,
            parent_binding: [0x11; 32],
            route_commit_bytes: vec![0x44; 8],
            external_commitment_x: [0x55; 32],
            input_amount,
            output_amount,
            fee_bps: 30,
            sigma: [0x66; 32],
            settler_public_key: vec![0xBB; 64],
            settler_devid: devid(0xB1),
            settlement_receipt_id: [0x77; 32],
            signature: Vec::new(),
            mode: TransactionMode::Bilateral,
        })
    }

    fn delta(policy_commit: [u8; 32], direction: BalanceDirection, amount: u64) -> BalanceDelta {
        BalanceDelta {
            policy_commit,
            direction,
            amount,
        }
    }

    /// The deltas must realize THE TRADE THAT WAS AUTHORIZED — not merely a
    /// balanced pair of moves.
    ///
    /// Generic zero-sum arithmetic ("something out, something in, the books
    /// balance") is satisfied by a completely different trade: another asset,
    /// another amount, the two sides swapped. Each case below balances in that
    /// weaker sense and must still reject, because it does not match the signed
    /// authorization sitting in the same operation.
    #[test]
    fn dlv_settle_deltas_must_match_the_authorization_positionally() {
        let (era, rigb, dbtc) = (pc(0xE0), pc(0xF0), pc(0xD0));
        let vault = [0x77u8; 32];
        let op = settle_op(vault, era, 1_000, rigb, 970);

        // The one arrangement that is accepted.
        let ok = [
            delta(era, BalanceDirection::Debit, 1_000),
            delta(rigb, BalanceDirection::Credit, 970),
        ];
        validate_conservation(&devid(0xB1), &op, &ok, None)
            .expect("the authorized trade must pass");

        for (why, deltas) in [
            ("no deltas at all", vec![]),
            (
                "only the credit — the output without paying the input",
                vec![delta(rigb, BalanceDirection::Credit, 970)],
            ),
            (
                "only the debit",
                vec![delta(era, BalanceDirection::Debit, 1_000)],
            ),
            (
                "a third delta riding along",
                vec![
                    delta(era, BalanceDirection::Debit, 1_000),
                    delta(rigb, BalanceDirection::Credit, 970),
                    delta(dbtc, BalanceDirection::Credit, 1),
                ],
            ),
            (
                "REORDERED — set-membership would accept this",
                vec![
                    delta(rigb, BalanceDirection::Credit, 970),
                    delta(era, BalanceDirection::Debit, 1_000),
                ],
            ),
            (
                "directions inverted: paid in the output, took the input",
                vec![
                    delta(era, BalanceDirection::Credit, 1_000),
                    delta(rigb, BalanceDirection::Debit, 970),
                ],
            ),
            (
                "a different asset credited than the one authorized",
                vec![
                    delta(era, BalanceDirection::Debit, 1_000),
                    delta(dbtc, BalanceDirection::Credit, 970),
                ],
            ),
            (
                "a different asset debited",
                vec![
                    delta(dbtc, BalanceDirection::Debit, 1_000),
                    delta(rigb, BalanceDirection::Credit, 970),
                ],
            ),
            (
                "paying LESS than the authorized input",
                vec![
                    delta(era, BalanceDirection::Debit, 999),
                    delta(rigb, BalanceDirection::Credit, 970),
                ],
            ),
            (
                "taking MORE than the authorized output",
                vec![
                    delta(era, BalanceDirection::Debit, 1_000),
                    delta(rigb, BalanceDirection::Credit, 971),
                ],
            ),
            (
                "both sides scaled up — still zero-sum in the weak sense",
                vec![
                    delta(era, BalanceDirection::Debit, 10_000),
                    delta(rigb, BalanceDirection::Credit, 9_700),
                ],
            ),
            (
                "duplicated debit",
                vec![
                    delta(era, BalanceDirection::Debit, 1_000),
                    delta(era, BalanceDirection::Debit, 1_000),
                ],
            ),
        ] {
            assert!(
                validate_conservation(&devid(0xB1), &op, &deltas, None).is_err(),
                "must reject: {why}"
            );
        }
    }

    /// An authorization that names one asset on both legs, or a zero amount, is
    /// rejected on its own terms — before any delta is considered.
    #[test]
    fn dlv_settle_authorization_must_name_two_assets_and_non_zero_amounts() {
        let (era, rigb) = (pc(0xE0), pc(0xF0));
        let vault = [0x77u8; 32];

        let same_asset = settle_op(vault, era, 1_000, era, 970);
        assert!(validate_conservation(
            &devid(0xB1),
            &same_asset,
            &[
                delta(era, BalanceDirection::Debit, 1_000),
                delta(era, BalanceDirection::Credit, 970),
            ],
            None,
        )
        .is_err());

        for (x, y) in [(0u64, 970u64), (1_000, 0), (0, 0)] {
            let op = settle_op(vault, era, x, rigb, y);
            assert!(
                validate_conservation(
                    &devid(0xB1),
                    &op,
                    &[
                        delta(era, BalanceDirection::Debit, x),
                        delta(rigb, BalanceDirection::Credit, y),
                    ],
                    None,
                )
                .is_err(),
                "zero-amount authorization ({x}, {y}) must reject"
            );
        }
    }

    /// AT THE ADVANCE, not just at the guard: exactly two balances move, by
    /// exactly the authorized amounts, and every unrelated balance and reserve
    /// leaf is byte-identical afterwards.
    ///
    /// `validate_conservation` sees only the delta vector — it cannot observe
    /// what the advance did to the rest of the map. This is the assertion the
    /// user's conservation rule actually asks for, and it needs a real advance.
    #[test]
    fn dlv_settle_advance_moves_two_balances_and_leaves_everything_else_identical() {
        let mut trader = fresh_device(0xB1);
        let (era, rigb, dbtc) = (pc(0xE0), pc(0xF0), pc(0xD0));
        trader.balances.insert(era, 50_000);
        trader.balances.insert(rigb, 2_000);
        trader.balances.insert(dbtc, 7_777);

        // The trader also runs a vault of its own. A settlement it performs as a
        // TRADER must not touch reserves it holds as an OWNER.
        let own_vault = [0x99u8; 32];
        let trader = trader
            .fund_vault_reserves(&own_vault, &[(era, 10_000), (dbtc, 1_000)], 0)
            .expect("trader funds its own vault")
            .new_device_state;

        let before_dbtc = trader.balance(&dbtc);
        let before_reserves = trader.vault_reserves_snapshot();

        let rk = crate::core::bilateral_transaction_manager::compute_smt_key(
            &trader.devid,
            &trader.devid,
        );
        let tip = crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &trader.devid,
            &trader.devid,
        );
        let vault = [0x77u8; 32];
        let out = trader
            .advance(
                rk,
                trader.devid,
                settle_op(vault, era, 1_000, rigb, 970),
                entropy(11),
                None,
                &[
                    delta(era, BalanceDirection::Debit, 1_000),
                    delta(rigb, BalanceDirection::Credit, 970),
                ],
                Some(tip),
                None,
                None,
                None,
            )
            .expect("the authorized settlement must advance");
        let after = &out.new_device_state;

        // 50_000 held, 10_000 already encumbered in the trader's own vault.
        assert_eq!(after.balance(&era), 39_000, "input debited exactly");
        assert_eq!(after.balance(&rigb), 2_970, "output credited exactly");
        assert_eq!(
            after.balance(&dbtc),
            before_dbtc,
            "an unrelated balance must not move"
        );
        assert_eq!(
            after.vault_reserves_snapshot(),
            before_reserves,
            "a trader-side settlement must not touch the trader's own reserve leaves"
        );
    }

    /// END TO END: a settling advance writes its own receipt leaf, and a
    /// receipt built from that advance's post-root verifies for a third party.
    ///
    /// This is the join between the two halves. The conservation arm proves the
    /// right balances moved; the receipt is what lets the VAULT OWNER — who
    /// never saw this advance — know that they did. Without the leaf landing in
    /// the same root, the owner would be back to trusting a published claim.
    #[test]
    fn a_settling_advance_emits_a_verifiable_receipt() {
        use crate::dlv::settlement_receipt_leaf::{
            settlement_receipt_key, sign_trader_settlement_receipt,
            verify_trader_settlement_receipt, SettledTrade,
        };

        let mut trader = fresh_device(0xB7);
        let (era, rigb) = (pc(0xE0), pc(0xF0));
        trader.balances.insert(era, 50_000);
        trader.balances.insert(rigb, 0);

        let vault = [0x77u8; 32];
        let rk = crate::core::bilateral_transaction_manager::compute_smt_key(
            &trader.devid,
            &trader.devid,
        );
        let tip = crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &trader.devid,
            &trader.devid,
        );
        let op = settle_op(vault, era, 1_000, rigb, 970);
        let (receipt_id, x, parent_seq) = match &op {
            Operation::DlvSettle {
                settlement_receipt_id,
                external_commitment_x,
                parent_sequence,
                ..
            } => (
                *settlement_receipt_id,
                *external_commitment_x,
                *parent_sequence,
            ),
            _ => unreachable!(),
        };

        let out = trader
            .advance(
                rk,
                trader.devid,
                op,
                entropy(21),
                None,
                &[
                    delta(era, BalanceDirection::Debit, 1_000),
                    delta(rigb, BalanceDirection::Credit, 970),
                ],
                Some(tip),
                None,
                None,
                None,
            )
            .expect("settlement advances");
        let after = &out.new_device_state;

        // The receipt leaf is in the post-advance root, under the SAME root the
        // relationship leaf binds — one batch, not two.
        let trade = SettledTrade {
            x,
            parent_sequence: parent_seq,
            new_sequence: parent_seq + 1,
            input_policy_commit: era,
            input_amount: 1_000,
            output_policy_commit: rigb,
            output_amount: 970,
        };
        let key = settlement_receipt_key(&after.genesis, &after.devid, &vault, &receipt_id);
        let post_root = *after.smt.root();
        let siblings = after
            .smt
            .get_inclusion_proof(&key, 256)
            .expect("receipt proof")
            .siblings;

        let (tpk, tsk) = crate::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
        let receipt = sign_trader_settlement_receipt(
            &vault,
            &receipt_id,
            trade,
            &after.genesis,
            &after.devid,
            &post_root,
            siblings,
            &tpk,
            &tsk,
        )
        .expect("sign the receipt");

        verify_trader_settlement_receipt(&receipt)
            .expect("a third party must be able to verify a settlement that really happened");

        // And the leaf replays on restore, or a reloaded device would root-mismatch.
        assert_eq!(
            after.extra_leaves_snapshot().get(&key).copied(),
            Some(crate::dlv::settlement_receipt_leaf::settlement_receipt_value(&trade)),
            "the receipt leaf must replay through extra_leaves"
        );
    }

    /// A settlement the trader never made has no leaf, so no receipt over it can
    /// be produced from that device's root. This is what stops a published
    /// pointer from consuming liquidity for free.
    #[test]
    fn a_device_that_did_not_settle_has_no_receipt_leaf_to_prove() {
        use crate::dlv::settlement_receipt_leaf::{
            settlement_receipt_key, settlement_receipt_value, SettledTrade,
        };

        let mut griefer = fresh_device(0xB8);
        let (era, rigb) = (pc(0xE0), pc(0xF0));
        griefer.balances.insert(era, 50_000);
        let vault = [0x77u8; 32];
        let receipt_id = [0x77u8; 32];

        // No settling advance — just a device holding funds.
        let key = settlement_receipt_key(&griefer.genesis, &griefer.devid, &vault, &receipt_id);
        let trade = SettledTrade {
            x: [0x55; 32],
            parent_sequence: 0,
            new_sequence: 1,
            input_policy_commit: era,
            input_amount: 1_000,
            output_policy_commit: rigb,
            output_amount: 970,
        };
        let proof = griefer
            .smt
            .get_inclusion_proof(&key, 256)
            .expect("a proof is always producible");
        assert_ne!(
            proof.value,
            Some(settlement_receipt_value(&trade)),
            "an unsettled device cannot present the settled value at that slot"
        );
    }

    /// The owner RECORDS a settlement it verified. It authorizes no value
    /// movement of its own, so any balance delta rejects.
    #[test]
    fn dlv_owner_apply_authorizes_no_balance_movement() {
        let (era, rigb) = (pc(0xE0), pc(0xF0));
        let op = Operation::DlvOwnerApply {
            vault_id: vec![0x77; 32],
            settlement_receipt_id: [0x77; 32],
            pending_pointer_x: [0x55; 32],
            parent_sequence: 0,
            new_sequence: 1,
            input_policy_commit: era,
            output_policy_commit: rigb,
            input_amount: 1_000,
            output_amount: 970,
            signature: vec![0xCC; 64],
            mode: TransactionMode::Bilateral,
        };

        validate_conservation(&devid(0xB1), &op, &[], None)
            .expect("empty deltas are the only accepted shape");

        for deltas in [
            vec![delta(era, BalanceDirection::Credit, 1_000)],
            vec![delta(rigb, BalanceDirection::Debit, 970)],
            vec![
                delta(era, BalanceDirection::Credit, 1_000),
                delta(rigb, BalanceDirection::Debit, 970),
            ],
            // Even a self-cancelling pair: the owner's spendable balance is not
            // part of a settlement at all.
            vec![
                delta(era, BalanceDirection::Credit, 1),
                delta(era, BalanceDirection::Debit, 1),
            ],
        ] {
            assert!(
                validate_conservation(&devid(0xB1), &op, &deltas, None).is_err(),
                "owner-apply must not carry balance deltas"
            );
        }
    }

    /// The owner's reserve legs move positionally: the input the trader paid
    /// arrives, the output it took leaves, and NOTHING else changes — not the
    /// owner's spendable balances, not another vault's leaves, not the other
    /// assets in the same vault.
    #[test]
    fn owner_apply_moves_two_reserve_legs_and_leaves_everything_else_identical() {
        let mut owner = fresh_device(0xA1);
        let (era, rigb, dbtc) = (pc(0xE0), pc(0xF0), pc(0xD0));
        owner.balances.insert(era, 50_000);
        owner.balances.insert(rigb, 20_000);
        owner.balances.insert(dbtc, 9_000);

        let vault = [0x77u8; 32];
        let other_vault = [0x88u8; 32];
        let owner = owner
            .fund_vault_reserves(&vault, &[(era, 10_000), (rigb, 5_000)], 0)
            .expect("fund the traded vault")
            .new_device_state;
        let owner = owner
            .fund_vault_reserves(&other_vault, &[(era, 1_000), (dbtc, 500)], 0)
            .expect("fund an unrelated vault")
            .new_device_state;

        let balances_before = owner.balances.clone();

        let after = owner
            .apply_settlement_to_reserves(&vault, &era, 1_000, &rigb, 970, 1)
            .expect("apply the settlement")
            .new_device_state;

        assert_eq!(
            after.vault_reserve(&vault, &era),
            11_000,
            "the input the trader paid arrives in the reserve"
        );
        assert_eq!(
            after.vault_reserve(&vault, &rigb),
            4_030,
            "the output the trader took leaves the reserve"
        );
        assert_eq!(
            after.balances, balances_before,
            "the owner's SPENDABLE balances are untouched — the fee accrues as LP yield inside the reserves"
        );
        assert_eq!(
            after.vault_reserve(&other_vault, &era),
            1_000,
            "an unrelated vault over the same asset is untouched"
        );
        assert_eq!(after.vault_reserve(&other_vault, &dbtc), 500);

        // The sequence steps on BOTH moved legs, so a proof of either at the old
        // sequence no longer verifies.
        assert_eq!(after.vault_reserve_entry(&vault, &era).unwrap().sequence, 1);
        assert_eq!(
            after.vault_reserve_entry(&vault, &rigb).unwrap().sequence,
            1
        );
        assert_eq!(
            after
                .vault_reserve_entry(&other_vault, &era)
                .unwrap()
                .sequence,
            0,
            "the untraded vault keeps its own sequence"
        );
    }

    /// A vault that cannot pay the output fails closed with ZERO mutation —
    /// the alternative is a reserve that wraps to a near-u64::MAX balance.
    #[test]
    fn a_vault_that_cannot_pay_the_output_rejects_with_zero_mutation() {
        let mut owner = fresh_device(0xA6);
        let (era, rigb) = (pc(0xE0), pc(0xF0));
        owner.balances.insert(era, 50_000);
        owner.balances.insert(rigb, 1_000);
        let vault = [0x77u8; 32];
        let owner = owner
            .fund_vault_reserves(&vault, &[(era, 10_000), (rigb, 1_000)], 0)
            .expect("funding")
            .new_device_state;

        let root_before = *owner.smt.root();
        let reserves_before = owner.vault_reserves_snapshot();

        let err = owner
            .apply_settlement_to_reserves(&vault, &era, 1_000, &rigb, 1_001, 1)
            .expect_err("the vault holds 1_000 RIGB and cannot pay 1_001");
        assert!(
            format!("{err}").contains("cannot pay"),
            "must fail as an unpayable output, got: {err}"
        );

        assert_eq!(*owner.smt.root(), root_before, "zero mutation on the root");
        assert_eq!(owner.vault_reserves_snapshot(), reserves_before);

        // Exactly the reserve is payable — the boundary is not off by one.
        owner
            .apply_settlement_to_reserves(&vault, &era, 1_000, &rigb, 1_000, 1)
            .expect("draining the leg to zero is legitimate");
    }

    /// The settlement move refuses degenerate authorizations at the chokepoint
    /// itself, not only at the guard above it.
    #[test]
    fn settlement_reserve_move_refuses_same_asset_and_zero_amounts() {
        let mut owner = fresh_device(0xA7);
        let (era, rigb) = (pc(0xE0), pc(0xF0));
        owner.balances.insert(era, 50_000);
        owner.balances.insert(rigb, 50_000);
        let vault = [0x77u8; 32];
        let owner = owner
            .fund_vault_reserves(&vault, &[(era, 10_000), (rigb, 10_000)], 0)
            .expect("funding")
            .new_device_state;

        assert!(
            owner
                .apply_settlement_to_reserves(&vault, &era, 1_000, &era, 970, 1)
                .is_err(),
            "one asset on both legs is not a trade"
        );
        assert!(owner
            .apply_settlement_to_reserves(&vault, &era, 0, &rigb, 970, 1)
            .is_err());
        assert!(owner
            .apply_settlement_to_reserves(&vault, &era, 1_000, &rigb, 0, 1)
            .is_err());
    }

    /// Encumbrance is reversible, or funding a vault is a one-way door.
    #[test]
    fn withdrawal_returns_the_exact_reserve_to_spendable() {
        let mut dev = fresh_device(0xA5);
        let era = pc(0xE0);
        dev.balances.insert(era, 10_000);
        let vault = [0x77u8; 32];

        let funded = dev
            .fund_vault_reserves(&vault, &[(era, 10_000)], 0)
            .expect("fund")
            .new_device_state;
        let back = funded
            .withdraw_vault_reserves(&vault, &[(era, 10_000)], 7)
            .expect("withdraw")
            .new_device_state;

        assert_eq!(back.balance(&era), 10_000, "exactly what went in comes out");
        assert_eq!(back.vault_reserve(&vault, &era), 0);
        // The emptied leaf keeps its entry so the sequence stays monotone and an
        // older proof cannot be replayed against it.
        assert_eq!(
            back.vault_reserve_entry(&vault, &era).map(|r| r.sequence),
            Some(7)
        );
    }

    /// Withdrawing more than the vault holds is refused rather than clamped.
    #[test]
    fn over_withdrawal_is_refused() {
        let mut dev = fresh_device(0xA6);
        let era = pc(0xE0);
        dev.balances.insert(era, 10_000);
        let vault = [0x77u8; 32];
        let funded = dev
            .fund_vault_reserves(&vault, &[(era, 4_000)], 0)
            .expect("fund")
            .new_device_state;

        assert!(funded
            .withdraw_vault_reserves(&vault, &[(era, 4_001)], 1)
            .is_err());
        assert_eq!(funded.vault_reserve(&vault, &era), 4_000, "unchanged");
    }

    /// Two vaults over the same asset keep separate reserves — otherwise an
    /// owner could not attribute a settlement to the vault that produced it.
    #[test]
    fn two_vaults_over_one_asset_do_not_share_a_reserve() {
        let mut dev = fresh_device(0xA7);
        let era = pc(0xE0);
        dev.balances.insert(era, 10_000);
        let (v1, v2) = ([0x11u8; 32], [0x22u8; 32]);

        let s = dev
            .fund_vault_reserves(&v1, &[(era, 3_000)], 0)
            .expect("v1")
            .new_device_state;
        let s = s
            .fund_vault_reserves(&v2, &[(era, 2_000)], 0)
            .expect("v2")
            .new_device_state;

        assert_eq!(s.vault_reserve(&v1, &era), 3_000);
        assert_eq!(s.vault_reserve(&v2, &era), 2_000);
        assert_eq!(s.balance(&era), 5_000);
    }

    /// A leg list naming one asset twice would let the second write clobber the
    /// first, funding the vault with less than the caller asked for.
    #[test]
    fn a_duplicated_asset_in_the_legs_is_refused() {
        let mut dev = fresh_device(0xA8);
        let era = pc(0xE0);
        dev.balances.insert(era, 10_000);
        assert!(dev
            .fund_vault_reserves(&[0x77u8; 32], &[(era, 1_000), (era, 2_000)], 0)
            .is_err());
    }

    /// Zero-amount and empty leg lists are refused rather than producing a
    /// no-op advance that looks like a funded vault.
    #[test]
    fn degenerate_leg_lists_are_refused() {
        let mut dev = fresh_device(0xA9);
        let era = pc(0xE0);
        dev.balances.insert(era, 10_000);
        let vault = [0x77u8; 32];
        assert!(dev.fund_vault_reserves(&vault, &[], 0).is_err());
        assert!(dev.fund_vault_reserves(&vault, &[(era, 0)], 0).is_err());
    }

    /// Funding is a RESERVE move, so `DlvCreate` must carry no balance delta.
    ///
    /// This arm exists because the operation previously fell to the catch-all,
    /// which rejects ANY delta — so the single-asset lock the handler built
    /// could never commit. The value-bearing DLV path has never worked, for any
    /// vault type, and the DLV suite did not notice because it asserted on the
    /// text of the handler rather than its behaviour.
    #[test]
    fn dlv_create_rejects_any_balance_delta() {
        let me = devid(0xC1);
        let era = pc(0xE0);
        let op = Operation::DlvCreate {
            vault_id: vec![0x77; 32],
            creator_public_key: vec![0xAA; 32],
            parameters_hash: vec![0x11; 32],
            fulfillment_condition: Vec::new(),
            intended_recipient: None,
            token_id: None,
            locked_amount: None,
            signature: Vec::new(),
            mode: crate::types::operations::TransactionMode::Unilateral,
        };
        assert!(
            validate_conservation(&me, &op, &[], None).is_ok(),
            "no deltas is the shape funding uses"
        );
        for d in [BalanceDirection::Credit, BalanceDirection::Debit] {
            let err = validate_conservation(
                &me,
                &op,
                &[BalanceDelta {
                    policy_commit: era,
                    direction: d,
                    amount: 1,
                }],
                None,
            )
            .expect_err("a delta riding along with DlvCreate must be refused");
            assert!(
                format!("{err}").contains("reserve leaves"),
                "the refusal should say where funding actually goes, got: {err}"
            );
        }
    }

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
            authorized_by: vec![],
            proof_of_authorization: vec![],
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
    fn value_op(dir: BalanceDirection, amount: u64, policy_commit: [u8; 32]) -> Operation {
        match dir {
            BalanceDirection::Credit => mint_op_for(amount, policy_commit),
            BalanceDirection::Debit => burn_op_for(amount, policy_commit),
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
                mint_op_for(50, custom_token),
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
                mint_op_for(100, token),
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
                mint_op_for(10, pc(0xF1)),
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
                mint_op_for(5, pc(0xF2)),
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
                mint_op_for(7, pc(0xF3)),
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
                mint_op_for(100, token),
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
                None,
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
                None,
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
                    None,
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
                    None,
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
                    None,
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
                mint_op_for(1, pc(0xF0 + u as u8)),
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
                mint_op_for(10, pc(0xF1)),
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
            .advance(rk, cp, op(), entropy(2), None, &[], None, None, None, None)
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
                burn_op_for(30, token),
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
                burn_op_for(50, token),
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
            mint_op_for(1, token),
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
                    value_op(dir, amt, token),
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
    // The vault-state leaf rides the staged advance (one canonical root)
    // ─────────────────────────────────────────────────────────────

    /// A funding advance writes the vault-state leaf in the SAME SMT batch as
    /// the reserve leaves and the relationship leaf, so `outcome.vault_state_proof`
    /// verifies against `child_r_a` == `new_device_state.root()`, and its digest
    /// is DERIVED from the leaves that landed (canonical pair order), not
    /// supplied.
    #[test]
    fn a_funding_advance_writes_the_vault_state_leaf_under_the_same_root() {
        use crate::dlv::vault_smt_leaf::{compute_vault_smt_key, verify_vault_smt_inclusion};

        let mut dev = fresh_device(0xC5);
        let (era, rigb) = (pc(0xE0), pc(0xF0));
        dev.balances.insert(era, 50_000);
        dev.balances.insert(rigb, 20_000);
        let vault = [0x75u8; 32];
        let (rk, tip) = self_loop(&dev);

        let out = dev
            .advance(
                rk,
                dev.devid,
                dlv_create(vault),
                entropy(1),
                None,
                &[],
                Some(tip),
                None,
                None,
                Some(VaultReserveMutation::Fund {
                    vault_id: vault,
                    legs: vec![(era, 10_000), (rigb, 5_000)],
                    vault_sequence: 0,
                    pair: vault_pair(era, rigb),
                }),
            )
            .expect("funding advance");

        let proof = out
            .vault_state_proof
            .as_ref()
            .expect("a reserve mutation must yield a vault-state witness");
        assert_eq!(proof.vault_id, vault);
        assert_eq!(proof.sequence, 0);
        assert_eq!(
            proof.reserves_digest,
            vault_pair(era, rigb).reserves_digest(10_000, 5_000),
            "the digest is derived from the amounts the leaves hold"
        );
        assert_eq!(proof.siblings.len(), 256);

        // ONE root: the outcome's child root IS the new head's root, and the
        // vault-state proof verifies against it — the same root the reserve
        // leaves and the relationship leaf landed under.
        assert_eq!(out.child_r_a, out.new_device_state.root());
        verify_vault_smt_inclusion(
            &vault,
            0,
            &proof.reserves_digest,
            &out.child_r_a,
            &proof.siblings,
        )
        .expect("vault-state proof binds child_r_a");
        // ...and so does a reserve-leg proof taken off the SAME head.
        let legs = out
            .new_device_state
            .vault_reserve_leg_proofs(&vault, &[era, rigb])
            .expect("reserve legs provable");
        assert_eq!(legs.len(), 2);
        assert!(out
            .new_device_state
            .smt
            .contains_key(&compute_vault_smt_key(&vault)));

        // The leaf is in the replay record: a restored device recomputes the
        // SAME root (the reload-brick guard).
        let live = &out.new_device_state;
        let restored = DeviceState::restore(
            live.genesis,
            live.devid,
            live.public_key.clone(),
            live.legacy_anchor,
            live.balances.clone(),
            live.tips.iter().map(|(k, v)| (*k, v.clone())).collect(),
            live.extra_leaves.clone(),
            live.offline_allocations.clone(),
            live.vault_reserves.clone(),
            None, // no admission pending in this fixture
            1024,
        )
        .expect("restore");
        assert_eq!(
            restored.root(),
            live.root(),
            "restore replays the vault-state leaf"
        );

        // No mutation, no witness.
        let plain = out
            .new_device_state
            .advance(
                rk,
                out.new_device_state.devid,
                transfer_op(era, 1),
                entropy(2),
                None,
                &[BalanceDelta {
                    policy_commit: era,
                    direction: BalanceDirection::Debit,
                    amount: 1,
                }],
                Some(tip),
                None,
                None,
                None,
            )
            .expect("ordinary transfer");
        assert!(plain.vault_state_proof.is_none());
    }

    /// PAIR COMPLETENESS on funding: legs must be exactly the vault's pair, in
    /// canonical order. One leg, three legs, or an asset outside the pair is
    /// refused — a leg the digest never sees would let a signed vault state
    /// describe different reserves than the leaves hold.
    #[test]
    fn funding_legs_that_are_not_exactly_the_pair_are_refused() {
        let mut dev = fresh_device(0xC6);
        let (era, rigb, dbtc) = (pc(0xE0), pc(0xF0), pc(0xD0));
        dev.balances.insert(era, 50_000);
        dev.balances.insert(rigb, 20_000);
        dev.balances.insert(dbtc, 9_000);
        let vault = [0x76u8; 32];
        let (rk, tip) = self_loop(&dev);
        let root_before = dev.root();

        for (name, legs) in [
            ("one leg", vec![(era, 10_000)]),
            ("three legs", vec![(dbtc, 1), (era, 10_000), (rigb, 5_000)]),
            (
                "an asset outside the pair",
                vec![(dbtc, 1_000), (era, 10_000)],
            ),
            ("the pair out of order", vec![(rigb, 5_000), (era, 10_000)]),
        ] {
            let err = dev.advance(
                rk,
                dev.devid,
                dlv_create(vault),
                entropy(1),
                None,
                &[],
                Some(tip),
                None,
                None,
                Some(VaultReserveMutation::Fund {
                    vault_id: vault,
                    legs,
                    vault_sequence: 0,
                    pair: vault_pair(era, rigb),
                }),
            );
            let err = format!("{}", err.expect_err(name));
            assert!(
                err.contains("exactly the vault's pair"),
                "{name}: must refuse on pair completeness, got: {err}"
            );
        }
        assert_eq!(dev.root(), root_before, "refusals move nothing");
        assert_eq!(dev.balance(&era), 50_000);
    }

    /// The owner-apply advance keeps the vault-state leaf in LOCKSTEP with the
    /// reserve legs: after folding a settlement the leaf sits at `new_sequence`
    /// carrying the digest of the folded amounts, under the same root as the
    /// moved legs. And a settlement naming a third asset is refused.
    #[test]
    fn owner_apply_advance_keeps_the_vault_state_leaf_in_lockstep_and_refuses_a_third_asset() {
        use crate::dlv::vault_smt_leaf::verify_vault_smt_inclusion;

        let mut owner = fresh_device(0xC7);
        let (era, rigb, dbtc) = (pc(0xE0), pc(0xF0), pc(0xD0));
        owner.balances.insert(era, 50_000);
        owner.balances.insert(rigb, 20_000);
        let vault = [0x77u8; 32];
        let (rk, tip) = self_loop(&owner);
        let pair = vault_pair(era, rigb);

        let funded = owner
            .advance(
                rk,
                owner.devid,
                dlv_create(vault),
                entropy(1),
                None,
                &[],
                Some(tip),
                None,
                None,
                Some(VaultReserveMutation::Fund {
                    vault_id: vault,
                    legs: vec![(era, 10_000), (rigb, 5_000)],
                    vault_sequence: 0,
                    pair,
                }),
            )
            .expect("fund")
            .new_device_state;

        let apply_op = |input: [u8; 32], output: [u8; 32], out_amt: u64| {
            sign_op(Operation::DlvOwnerApply {
                vault_id: vault.to_vec(),
                settlement_receipt_id: [0x77; 32],
                pending_pointer_x: [0x55; 32],
                parent_sequence: 0,
                new_sequence: 1,
                input_policy_commit: input,
                output_policy_commit: output,
                input_amount: 1_000,
                output_amount: out_amt,
                signature: vec![],
                mode: TransactionMode::Bilateral,
            })
        };

        // A third asset on the input side: refused, nothing moves.
        let root_before = funded.root();
        let err = funded.advance(
            rk,
            funded.devid,
            apply_op(dbtc, rigb, 970),
            entropy(2),
            None,
            &[],
            Some(tip),
            None,
            None,
            Some(VaultReserveMutation::ApplySettlement {
                vault_id: vault,
                input_policy_commit: dbtc,
                input_amount: 1_000,
                output_policy_commit: rigb,
                output_amount: 970,
                parent_sequence: 0,
                new_sequence: 1,
                pair,
            }),
        );
        let err = format!("{}", err.expect_err("third asset"));
        assert!(
            err.contains("exactly the vault's pair"),
            "must refuse a settlement outside the pair, got: {err}"
        );
        assert_eq!(funded.root(), root_before);

        // The real settlement: legs move AND the vault-state leaf follows.
        let out = funded
            .advance(
                rk,
                funded.devid,
                apply_op(era, rigb, 970),
                entropy(3),
                None,
                &[],
                Some(tip),
                None,
                None,
                Some(VaultReserveMutation::ApplySettlement {
                    vault_id: vault,
                    input_policy_commit: era,
                    input_amount: 1_000,
                    output_policy_commit: rigb,
                    output_amount: 970,
                    parent_sequence: 0,
                    new_sequence: 1,
                    pair,
                }),
            )
            .expect("owner apply");
        let after = &out.new_device_state;
        assert_eq!(after.vault_reserve(&vault, &era), 11_000);
        assert_eq!(after.vault_reserve(&vault, &rigb), 4_030);
        let proof = out.vault_state_proof.as_ref().expect("witness");
        assert_eq!(proof.sequence, 1, "the leaf advanced with the legs");
        assert_eq!(
            proof.reserves_digest,
            pair.reserves_digest(11_000, 4_030),
            "the leaf's digest is the folded amounts, in canonical pair order"
        );
        verify_vault_smt_inclusion(
            &vault,
            1,
            &proof.reserves_digest,
            &out.child_r_a,
            &proof.siblings,
        )
        .expect("lockstep leaf binds the post-settlement root");
        // The stale seq-0 witness no longer verifies against the new root.
        verify_vault_smt_inclusion(
            &vault,
            0,
            &pair.reserves_digest(10_000, 5_000),
            &out.child_r_a,
            &proof.siblings,
        )
        .expect_err("stale generation must not verify against the new root");
    }

    // ─────────────────────────────────────────────────────────────
    // Closing a vault: the complete reserve set returns, exactly once
    // ─────────────────────────────────────────────────────────────

    /// A funded vault at generation 0, with `era`/`rigb` reserves.
    fn funded_for_close(
        b: u8,
        era: [u8; 32],
        rigb: [u8; 32],
        ra: u64,
        rb: u64,
    ) -> (DeviceState, [u8; 32], [u8; 32], [u8; 32]) {
        let mut dev = fresh_device(b);
        dev.balances.insert(era, ra + 1_000);
        dev.balances.insert(rigb, rb + 500);
        let vault = [b ^ 0x5A; 32];
        let (rk, tip) = self_loop(&dev);
        let funded = dev
            .advance(
                rk,
                dev.devid,
                dlv_create(vault),
                entropy(1),
                None,
                &[],
                Some(tip),
                None,
                None,
                Some(VaultReserveMutation::Fund {
                    vault_id: vault,
                    legs: vec![(era, ra), (rigb, rb)],
                    vault_sequence: 0,
                    pair: vault_pair(era, rigb),
                }),
            )
            .expect("fund")
            .new_device_state;
        (funded, vault, rk, tip)
    }

    /// A signed `DlvClose` for the full reserve set at `parent`.
    fn dlv_close_op(
        vault: [u8; 32],
        a: [u8; 32],
        amt_a: u64,
        b: [u8; 32],
        amt_b: u64,
        parent: u64,
        new: u64,
    ) -> Operation {
        sign_op(Operation::DlvClose {
            vault_id: vault.to_vec(),
            leg_a_policy_commit: a,
            leg_a_amount: amt_a,
            leg_b_policy_commit: b,
            leg_b_amount: amt_b,
            parent_sequence: parent,
            new_sequence: new,
            fee_bps: 30,
            signature: Vec::new(),
            mode: TransactionMode::Unilateral,
        })
    }

    fn withdraw_mutation(
        vault: [u8; 32],
        a: [u8; 32],
        amt_a: u64,
        b: [u8; 32],
        amt_b: u64,
        parent: u64,
        new: u64,
    ) -> VaultReserveMutation {
        VaultReserveMutation::Withdraw {
            vault_id: vault,
            legs: vec![(a, amt_a), (b, amt_b)],
            parent_sequence: parent,
            new_sequence: new,
            pair: vault_pair(a, b),
        }
    }

    /// THE CLOSE: the complete remaining reserve set returns to spendable
    /// balance, exactly once; both leaves sit at `0 @ parent+1`; the vault-state
    /// leaf follows with `digest(a, b, 0, 0, fee)`; and the vault id is
    /// single-use afterwards — neither re-fundable nor re-closable.
    #[test]
    fn a_close_returns_the_whole_reserve_set_exactly_once_and_the_vault_id_is_single_use() {
        use crate::dlv::vault_smt_leaf::verify_vault_smt_inclusion;
        let (era, rigb) = (pc(0xE0), pc(0xF0));
        let (funded, vault, rk, tip) = funded_for_close(0xD1, era, rigb, 10_000, 5_000);
        let pair = vault_pair(era, rigb);
        let (free_a_before, free_b_before) = (funded.balance(&era), funded.balance(&rigb));

        let out = funded
            .advance(
                rk,
                funded.devid,
                dlv_close_op(vault, era, 10_000, rigb, 5_000, 0, 1),
                entropy(2),
                None,
                &[],
                Some(tip),
                None,
                None,
                Some(withdraw_mutation(vault, era, 10_000, rigb, 5_000, 0, 1)),
            )
            .expect("close");
        let after = &out.new_device_state;

        // POST-TRADE ORACLE: the wallet grows by exactly the reserves at K.
        assert_eq!(after.balance(&era), free_a_before + 10_000);
        assert_eq!(after.balance(&rigb), free_b_before + 5_000);
        // Leaves are zero at the terminal generation — present, not deleted.
        assert_eq!(after.vault_reserve(&vault, &era), 0);
        assert_eq!(after.vault_reserve(&vault, &rigb), 0);
        assert_eq!(after.vault_reserve_entry(&vault, &era).unwrap().sequence, 1);
        assert_eq!(
            after.vault_reserve_entry(&vault, &rigb).unwrap().sequence,
            1
        );
        // The vault-state leaf is the terminal one, under the SAME root.
        let w = out.vault_state_proof.as_ref().expect("witness");
        assert_eq!(w.sequence, 1);
        assert_eq!(w.reserves_digest, pair.reserves_digest(0, 0));
        verify_vault_smt_inclusion(&vault, 1, &w.reserves_digest, &out.child_r_a, &w.siblings)
            .expect("terminal leaf binds the close's root");

        // SINGLE USE. A second close is refused (already zero), and re-funding
        // is refused because the leaves EXIST — not because an amount is
        // non-zero.
        let second = after.advance(
            rk,
            after.devid,
            dlv_close_op(vault, era, 0, rigb, 0, 1, 2),
            entropy(3),
            None,
            &[],
            Some(tip),
            None,
            None,
            Some(withdraw_mutation(vault, era, 0, rigb, 0, 1, 2)),
        );
        let e = format!("{}", second.expect_err("a closed vault cannot close again"));
        assert!(e.contains("already closed"), "got: {e}");

        let refund = after.advance(
            rk,
            after.devid,
            dlv_create(vault),
            entropy(4),
            None,
            &[],
            Some(tip),
            None,
            None,
            Some(VaultReserveMutation::Fund {
                vault_id: vault,
                legs: vec![(era, 10), (rigb, 5)],
                vault_sequence: 2,
                pair,
            }),
        );
        let e = format!("{}", refund.expect_err("a closed vault id is single use"));
        assert!(
            e.contains("already holds a reserve"),
            "the refusal must be existence-based, got: {e}"
        );
    }

    /// A close after a settlement withdraws the POST-TRADE reserves at the
    /// current generation — never the funding-time amounts.
    #[test]
    fn a_close_after_a_settlement_withdraws_the_post_trade_reserves() {
        let (era, rigb) = (pc(0xE0), pc(0xF0));
        let (funded, vault, rk, tip) = funded_for_close(0xD2, era, rigb, 10_000, 5_000);
        let pair = vault_pair(era, rigb);
        let apply = sign_op(Operation::DlvOwnerApply {
            vault_id: vault.to_vec(),
            settlement_receipt_id: [0x77; 32],
            pending_pointer_x: [0x55; 32],
            parent_sequence: 0,
            new_sequence: 1,
            input_policy_commit: era,
            output_policy_commit: rigb,
            input_amount: 1_000,
            output_amount: 970,
            signature: Vec::new(),
            mode: TransactionMode::Bilateral,
        });
        let traded = funded
            .advance(
                rk,
                funded.devid,
                apply,
                entropy(2),
                None,
                &[],
                Some(tip),
                None,
                None,
                Some(VaultReserveMutation::ApplySettlement {
                    vault_id: vault,
                    input_policy_commit: era,
                    input_amount: 1_000,
                    output_policy_commit: rigb,
                    output_amount: 970,
                    parent_sequence: 0,
                    new_sequence: 1,
                    pair,
                }),
            )
            .expect("settle")
            .new_device_state;
        let (free_a, free_b) = (traded.balance(&era), traded.balance(&rigb));

        // Closing at the FUNDING amounts is refused: they are not the leaves.
        let stale = traded.advance(
            rk,
            traded.devid,
            dlv_close_op(vault, era, 10_000, rigb, 5_000, 1, 2),
            entropy(3),
            None,
            &[],
            Some(tip),
            None,
            None,
            Some(withdraw_mutation(vault, era, 10_000, rigb, 5_000, 1, 2)),
        );
        let e = format!("{}", stale.expect_err("funding-time amounts are stale"));
        assert!(e.contains("exactly the leaf's amount"), "got: {e}");

        let after = traded
            .advance(
                rk,
                traded.devid,
                dlv_close_op(vault, era, 11_000, rigb, 4_030, 1, 2),
                entropy(4),
                None,
                &[],
                Some(tip),
                None,
                None,
                Some(withdraw_mutation(vault, era, 11_000, rigb, 4_030, 1, 2)),
            )
            .expect("close at the post-trade generation")
            .new_device_state;
        assert_eq!(after.balance(&era), free_a + 11_000);
        assert_eq!(after.balance(&rigb), free_b + 4_030);
        assert_eq!(after.vault_reserve_entry(&vault, &era).unwrap().sequence, 2);
    }

    /// Structural refusals, every one with ZERO mutation: a stale generation, a
    /// one-leg or foreign-leg drain, unordered legs, a non-unit step, an
    /// unsigned operation, balance deltas, and a mutation that disagrees with
    /// the signed operation.
    #[test]
    fn every_malformed_close_is_refused_with_zero_mutation() {
        let (era, rigb, dbtc) = (pc(0xE0), pc(0xF0), pc(0xD0));
        let (funded, vault, rk, tip) = funded_for_close(0xD3, era, rigb, 10_000, 5_000);
        let root_before = funded.root();
        let bal_before = funded.balances.clone();
        let pair = vault_pair(era, rigb);

        /// One refusal case: what it is, the phrase the refusal must name, and
        /// the shape that must be refused.
        struct BadClose {
            name: &'static str,
            needle: &'static str,
            op: Operation,
            mutation: Option<VaultReserveMutation>,
            deltas: Vec<BalanceDelta>,
        }
        let bad = |name, needle, op, mutation, deltas| BadClose {
            name,
            needle,
            op,
            mutation,
            deltas,
        };
        let attempts: Vec<BadClose> = vec![
            bad(
                "stale generation",
                "not current",
                dlv_close_op(vault, era, 10_000, rigb, 5_000, 1, 2),
                Some(withdraw_mutation(vault, era, 10_000, rigb, 5_000, 1, 2)),
                vec![],
            ),
            bad(
                // A one-leg mutation cannot equal a signed op that names both,
                // so the op-equality gate — the tighter one — refuses first.
                "one leg only",
                "does not equal the signed DlvClose",
                dlv_close_op(vault, era, 10_000, rigb, 5_000, 0, 1),
                Some(VaultReserveMutation::Withdraw {
                    vault_id: vault,
                    legs: vec![(era, 10_000)],
                    parent_sequence: 0,
                    new_sequence: 1,
                    pair,
                }),
                vec![],
            ),
            bad(
                // Op and mutation AGREE, and both name an asset the vault's
                // pair does not contain: pair completeness is what catches it.
                // Without that check the drain would leave the real second leg
                // encumbered forever while the vault read as closed.
                "op and mutation agree on legs that are not the pair",
                "exactly the vault's pair",
                dlv_close_op(vault, era, 10_000, dbtc, 5_000, 0, 1),
                Some(VaultReserveMutation::Withdraw {
                    vault_id: vault,
                    legs: vec![(era, 10_000), (dbtc, 5_000)],
                    parent_sequence: 0,
                    new_sequence: 1,
                    pair,
                }),
                vec![],
            ),
            bad(
                "a leg outside the pair",
                "does not equal the signed DlvClose",
                dlv_close_op(vault, era, 10_000, rigb, 5_000, 0, 1),
                Some(VaultReserveMutation::Withdraw {
                    vault_id: vault,
                    legs: vec![(dbtc, 1), (era, 10_000)],
                    parent_sequence: 0,
                    new_sequence: 1,
                    pair,
                }),
                vec![],
            ),
            bad(
                "legs out of canonical order",
                "does not equal the signed DlvClose",
                dlv_close_op(vault, era, 10_000, rigb, 5_000, 0, 1),
                Some(VaultReserveMutation::Withdraw {
                    vault_id: vault,
                    legs: vec![(rigb, 5_000), (era, 10_000)],
                    parent_sequence: 0,
                    new_sequence: 1,
                    pair,
                }),
                vec![],
            ),
            bad(
                "a non-unit generation step",
                "exactly one generation",
                dlv_close_op(vault, era, 10_000, rigb, 5_000, 0, 2),
                Some(withdraw_mutation(vault, era, 10_000, rigb, 5_000, 0, 2)),
                vec![],
            ),
            bad(
                "partial withdraw",
                "exactly the leaf's amount",
                dlv_close_op(vault, era, 9_000, rigb, 5_000, 0, 1),
                Some(withdraw_mutation(vault, era, 9_000, rigb, 5_000, 0, 1)),
                vec![],
            ),
            bad(
                "over withdraw",
                "exactly the leaf's amount",
                dlv_close_op(vault, era, 10_001, rigb, 5_000, 0, 1),
                Some(withdraw_mutation(vault, era, 10_001, rigb, 5_000, 0, 1)),
                vec![],
            ),
            bad(
                "mutation disagrees with the signed op",
                "does not equal the signed DlvClose",
                dlv_close_op(vault, era, 10_000, rigb, 5_000, 0, 1),
                Some(withdraw_mutation(vault, era, 10_000, rigb, 4_999, 0, 1)),
                vec![],
            ),
            bad(
                "balance deltas riding along",
                "not balance deltas",
                dlv_close_op(vault, era, 10_000, rigb, 5_000, 0, 1),
                Some(withdraw_mutation(vault, era, 10_000, rigb, 5_000, 0, 1)),
                vec![BalanceDelta {
                    policy_commit: era,
                    direction: BalanceDirection::Credit,
                    amount: 10_000,
                }],
            ),
            bad(
                "a withdraw under another operation",
                "only DlvClose may withdraw",
                dlv_create(vault),
                Some(withdraw_mutation(vault, era, 10_000, rigb, 5_000, 0, 1)),
                vec![],
            ),
        ];

        for case in attempts {
            let res = funded.advance(
                rk,
                funded.devid,
                case.op,
                entropy(9),
                None,
                &case.deltas,
                Some(tip),
                None,
                None,
                case.mutation,
            );
            let e = format!("{}", res.expect_err(case.name));
            assert!(
                e.contains(case.needle),
                "{}: expected {:?}, got: {e}",
                case.name,
                case.needle
            );
        }

        // An UNSIGNED close is refused by the signature gate.
        let unsigned = funded.advance(
            rk,
            funded.devid,
            Operation::DlvClose {
                vault_id: vault.to_vec(),
                leg_a_policy_commit: era,
                leg_a_amount: 10_000,
                leg_b_policy_commit: rigb,
                leg_b_amount: 5_000,
                parent_sequence: 0,
                new_sequence: 1,
                fee_bps: 30,
                signature: Vec::new(),
                mode: TransactionMode::Unilateral,
            },
            entropy(10),
            None,
            &[],
            Some(tip),
            None,
            None,
            Some(withdraw_mutation(vault, era, 10_000, rigb, 5_000, 0, 1)),
        );
        assert!(unsigned.is_err(), "an unsigned close must be refused");

        assert_eq!(funded.root(), root_before, "every refusal moved nothing");
        assert_eq!(funded.balances, bal_before);
        assert_eq!(funded.vault_reserve(&vault, &era), 10_000);
        assert_eq!(funded.vault_reserve(&vault, &rigb), 5_000);
    }

    /// THE WIRING TEST for the pending-admission fence.
    ///
    /// The fence predicate has its own suite, but a correct predicate that
    /// `advance` never calls protects nothing. This drives the real
    /// `advance()` on a head carrying a pending admission and asserts the
    /// refusal comes from the gate — and that the SAME head advances fine once
    /// the admission is cleared, so the refusal is the fence and not some
    /// unrelated precondition.
    #[test]
    fn advance_refuses_an_economic_write_while_an_admission_is_pending() {
        use crate::economic::admission::{
            EconomicAdmissionState, PendingAdmissionKind, PendingEconomicAdmission,
        };

        let (era, rigb) = (pc(0xE0), pc(0xF0));
        let (funded, vault, rk, tip) = funded_for_close(0xD5, era, rigb, 7_000, 3_000);

        let pending = PendingEconomicAdmission {
            kind: PendingAdmissionKind::DsmBacked,
            state: EconomicAdmissionState::LocalAcceptedPendingEcon,
            economic_position: 9,
            pre_economic_root: [1u8; 32],
            post_economic_root: [2u8; 32],
            operation_digest: [3u8; 32],
            accepted_substrate_addr: [4u8; 32],
            admission_manifest_addr: [5u8; 32],
        };
        let fenced = funded.with_pending_economic_admission(Some(pending));

        // DlvClose is a ClosedWriteSet operation: it moves reserves back to
        // balances, which is exactly the kind of economic write that must not
        // happen while the ancestry of earlier value is unregistered.
        let err = fenced
            .advance(
                rk,
                fenced.devid,
                dlv_close_op(vault, era, 7_000, rigb, 3_000, 0, 1),
                entropy(2),
                None,
                &[],
                Some(tip),
                None,
                None,
                Some(withdraw_mutation(vault, era, 7_000, rigb, 3_000, 0, 1)),
            )
            .expect_err("the fence must refuse an economic write while pending");
        let msg = err.to_string();
        assert!(
            msg.contains("economic admission at position 9 is pending"),
            "refusal must come from the FENCE, not an unrelated precondition: {msg}"
        );

        // Same head, same operation, no pending admission: it succeeds. This
        // is what makes the assertion above about the fence specifically.
        funded
            .advance(
                rk,
                funded.devid,
                dlv_close_op(vault, era, 7_000, rigb, 3_000, 0, 1),
                entropy(2),
                None,
                &[],
                Some(tip),
                None,
                None,
                Some(withdraw_mutation(vault, era, 7_000, rigb, 3_000, 0, 1)),
            )
            .expect("the identical advance succeeds once nothing is pending");
    }

    /// The fence SURVIVES a state derivation. If `advance` dropped it while
    /// building the successor head, the very next operation would be unfenced
    /// — a one-transition escape hatch.
    #[test]
    fn the_fence_is_carried_forward_by_advance() {
        use crate::economic::admission::{
            EconomicAdmissionState, PendingAdmissionKind, PendingEconomicAdmission,
        };

        let (era, rigb) = (pc(0xE1), pc(0xF1));
        let (funded, _vault, rk, tip) = funded_for_close(0xD6, era, rigb, 7_000, 3_000);
        let pending = PendingEconomicAdmission {
            kind: PendingAdmissionKind::DsmBacked,
            state: EconomicAdmissionState::LocalAcceptedPendingEcon,
            economic_position: 11,
            pre_economic_root: [1u8; 32],
            post_economic_root: [2u8; 32],
            operation_digest: [3u8; 32],
            accepted_substrate_addr: [4u8; 32],
            admission_manifest_addr: [5u8; 32],
        };
        let fenced = funded.with_pending_economic_admission(Some(pending.clone()));

        // A Noop classifies as EconomicEffect::None, so the fence allows it.
        let next = fenced
            .advance(
                rk,
                fenced.devid,
                Operation::Noop,
                entropy(3),
                None,
                &[],
                Some(tip),
                None,
                None,
                None,
            )
            .expect("non-economic activity continues during the fence")
            .new_device_state;

        assert_eq!(
            next.pending_economic_admission(),
            Some(&pending),
            "the successor head must still be fenced"
        );
    }

    /// The close's terminal state SURVIVES a reload: `restore` replays the zero
    /// leaves and the terminal vault-state leaf and recomputes the same root.
    #[test]
    fn a_closed_vaults_terminal_state_survives_restore() {
        let (era, rigb) = (pc(0xE0), pc(0xF0));
        let (funded, vault, rk, tip) = funded_for_close(0xD4, era, rigb, 7_000, 3_000);
        let closed = funded
            .advance(
                rk,
                funded.devid,
                dlv_close_op(vault, era, 7_000, rigb, 3_000, 0, 1),
                entropy(2),
                None,
                &[],
                Some(tip),
                None,
                None,
                Some(withdraw_mutation(vault, era, 7_000, rigb, 3_000, 0, 1)),
            )
            .expect("close")
            .new_device_state;
        let restored = DeviceState::restore(
            closed.genesis,
            closed.devid,
            closed.public_key.clone(),
            closed.legacy_anchor,
            closed.balances.clone(),
            closed.tips.iter().map(|(k, v)| (*k, v.clone())).collect(),
            closed.extra_leaves.clone(),
            closed.offline_allocations.clone(),
            closed.vault_reserves.clone(),
            None, // no admission pending in this fixture
            1024,
        )
        .expect("restore");
        assert_eq!(restored.root(), closed.root(), "terminal state reloads");
        assert_eq!(restored.vault_reserve(&vault, &era), 0);
        assert_eq!(
            restored
                .vault_reserve_entry(&vault, &rigb)
                .unwrap()
                .sequence,
            1
        );
    }

    /// `VaultStatePair` refuses a non-canonical or degenerate pair.
    #[test]
    fn vault_state_pair_must_be_canonical_and_distinct() {
        let (lo, hi) = (pc(0x10), pc(0x20));
        assert!(VaultStatePair::new(lo, hi, 30).is_ok());
        assert!(VaultStatePair::new(hi, lo, 30).is_err(), "unordered");
        assert!(VaultStatePair::new(lo, lo, 30).is_err(), "single asset");
    }
}
