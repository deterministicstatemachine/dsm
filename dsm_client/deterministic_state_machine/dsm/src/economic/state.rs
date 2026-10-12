// SPDX-License-Identifier: Apache-2.0

//! The `R_econ` leaf states and the derivation of the position each one
//! occupies.
//!
//! ## The key is derived from the state, never supplied
//!
//! [`EconomicLeafState::leaf_key`] takes the identity `(G, DevID)` and the
//! state itself, and nothing else. A mutation therefore cannot name a position
//! that disagrees with its own contents: a balance state cannot be filed at a
//! reserve key, and a reserve for vault A cannot be filed at vault B's key,
//! because the key is a function of exactly those fields. A supplied key would
//! reintroduce the whole class of "valid object at the wrong address" defects
//! that this tree exists to make unrepresentable.
//!
//! ## Zero is not one thing
//!
//! ```text
//! balance amount == 0          => the leaf is ABSENT
//! reserve amount == 0          => the leaf is PRESENT as { amount: 0, vault_sequence: n }
//! ```
//!
//! The asymmetry is deliberate and load-bearing. A balance of zero carries no
//! information beyond its own absence, so admitting a zero-valued balance leaf
//! would give one economic state two encodings and therefore two roots. A
//! **reserve** of zero is different: `vault_sequence` is still meaning. A
//! drained vault at sequence 7 and a drained vault at sequence 8 are different
//! states, and a close that zeroes both legs has to be able to say which
//! generation it zeroed them at.

use crate::ccb::{class, push_digest32, push_envelope, push_u64, CcbError, CcbObject};
use crate::common::domain_tags::TAG_DSM_ECONOMIC_LEAF_STATE;
use crate::crypto::blake3::dsm_domain_hasher;
use crate::economic::keys;

/// `0x001F` schema 1 — one asset's online spendable balance.
///
/// `amount` is always strictly positive; see the module note on zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomicBalanceState {
    pub policy_commit: [u8; 32],
    pub amount: u64,
}

impl CcbObject for EconomicBalanceState {
    const CLASS: u16 = class::ECONOMIC_BALANCE_STATE;
    const SCHEMA: u16 = 1;
}

impl EconomicBalanceState {
    /// Refuses `amount == 0` rather than normalizing it away, because the
    /// caller that reached zero has to *remove* the leaf, and silently
    /// encoding a zero would leave it believing it had written one.
    pub fn new(policy_commit: [u8; 32], amount: u64) -> Result<Self, CcbError> {
        if amount == 0 {
            return Err(CcbError::ZeroBalanceLeafMustBeAbsent);
        }
        Ok(Self {
            policy_commit,
            amount,
        })
    }

    fn encode(&self) -> Result<Vec<u8>, CcbError> {
        if self.amount == 0 {
            return Err(CcbError::ZeroBalanceLeafMustBeAbsent);
        }
        let mut out = Vec::new();
        push_envelope::<Self>(&mut out);
        push_digest32(&mut out, &self.policy_commit); // 1
        push_u64(&mut out, self.amount); // 2
        Ok(out)
    }
}

/// `0x0022` schema 1 — the write-once record that one credit source has been
/// spent, and by which operation.
///
/// Presence is the whole meaning. The consuming transition proves the leaf was
/// ZERO before it wrote, so a second consumer of the same `source_id` cannot
/// produce a valid pre-state. `consumer_economic_operation_id` is what turns a
/// bare "spent" flag into an attributable one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomicConsumedSourceState {
    pub source_id: [u8; 32],
    pub consumer_economic_operation_id: [u8; 32],
}

impl CcbObject for EconomicConsumedSourceState {
    const CLASS: u16 = class::ECONOMIC_CONSUMED_SOURCE_STATE;
    const SCHEMA: u16 = 1;
}

impl EconomicConsumedSourceState {
    fn encode(&self) -> Result<Vec<u8>, CcbError> {
        let mut out = Vec::new();
        push_envelope::<Self>(&mut out);
        push_digest32(&mut out, &self.source_id); // 1
        push_digest32(&mut out, &self.consumer_economic_operation_id); // 2
        Ok(out)
    }
}

/// `0x0060` schema 1 — the creator's record that the native token under
/// `policy_commit` was created on this lineage (SoFi Amendment S8).
///
/// Insert-only: presence is the whole meaning. The creating transition proves
/// the leaf was ZERO before it wrote, so a second creation of the same commit
/// on this lineage cannot produce a valid pre-state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomicTokenCreationState {
    pub policy_commit: [u8; 32],
}

impl CcbObject for EconomicTokenCreationState {
    const CLASS: u16 = class::ECONOMIC_TOKEN_CREATION_STATE;
    const SCHEMA: u16 = 1;
}

impl EconomicTokenCreationState {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_envelope::<Self>(&mut out);
        push_digest32(&mut out, &self.policy_commit); // 1
        out
    }
}

/// Any leaf of `R_econ`.
///
/// The offline device-bound allocation is deliberately **not** a variant. It
/// is a separate accounting regime that evolves outside this tree entirely;
/// only its boundaries (load and unload) touch `R_econ`, and they touch it
/// through the `balance` and `consumed_source` leaves like anything else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EconomicLeafState {
    Balance(EconomicBalanceState),
    ConsumedSource(EconomicConsumedSourceState),
    /// A SoFi relationship leaf `hʲ` for one vault (P15-6).
    ///
    /// It holds no amount: it is the trader's side of a relationship, and its
    /// only movement is the chain `hʲ⁺¹ = H(rel-leaf ‖ hʲ ‖ E)` that BindExt
    /// writes. The bytes are `sofi::wire`'s, so there is ONE encoding of this
    /// object and a second one cannot drift from it.
    Relationship(crate::sofi::wire::TraderRelationshipLeaf),
    /// The owner's vault-CREATION record (P15-12), insert-only.
    ///
    /// It IS the wire object — one encoding, as with the relationship leaf —
    /// so the record committed in `R_econ` and the record the operation
    /// carries cannot drift. Insert-only: a vault is created once, and the
    /// leaf is never rewritten, which is what makes its presence under a
    /// validated root a proof that the creation happened on that lineage.
    VaultCreation(crate::sofi::wire::VaultCreation),
    /// The creator's token-creation record, insert-only (SoFi Amendment S8).
    TokenCreation(EconomicTokenCreationState),
}

impl EconomicLeafState {
    /// The CCB class of this leaf. Selects the key derivation, which is why a
    /// mutation whose pre- and post-states disagree on class is rejected.
    pub fn class(&self) -> u16 {
        match self {
            Self::Balance(_) => EconomicBalanceState::CLASS,
            Self::ConsumedSource(_) => EconomicConsumedSourceState::CLASS,
            Self::Relationship(_) => crate::ccb::class::SOFI_TRADER_RELATIONSHIP_LEAF,
            Self::VaultCreation(_) => crate::ccb::class::SOFI_VAULT_CREATION,
            Self::TokenCreation(_) => EconomicTokenCreationState::CLASS,
        }
    }

    /// Canonical commit bytes for the leaf's own state object.
    pub fn encode(&self) -> Result<Vec<u8>, CcbError> {
        match self {
            Self::Balance(s) => s.encode(),
            Self::ConsumedSource(s) => s.encode(),
            Self::Relationship(s) => Ok(s.encode()),
            Self::VaultCreation(s) => Ok(s.encode()),
            Self::TokenCreation(s) => Ok(s.encode()),
        }
    }

    /// `economic_leaf_value(S) = H_dom(DSM/economic-leaf-state/v1, CCB(S))`.
    pub fn leaf_value(&self) -> Result<[u8; 32], CcbError> {
        let ccb = self.encode()?;
        let mut h = dsm_domain_hasher(TAG_DSM_ECONOMIC_LEAF_STATE);
        h.update(&ccb);
        Ok(*h.finalize().as_bytes())
    }

    /// The amount this leaf holds, for leaf classes where "more than before"
    /// means a credit. `None` for classes where presence is the meaning and
    /// there is no quantity to increase.
    ///
    /// A consumed-source marker is an INSERTION, not a credit: it records that
    /// something happened, it does not add spendable units. Treating it as a
    /// credit would demand a funding source for a bookkeeping entry.
    pub fn credit_amount(&self) -> Option<u64> {
        match self {
            Self::Balance(s) => Some(s.amount),
            Self::ConsumedSource(_)
            // A relationship leaf is a CHAIN, not a quantity: advancing it
            // adds nothing spendable, so it needs no funding source.
            | Self::Relationship(_)
            // A creation record is a RECORD: the funding it names was debited
            // by the same write set, so the record itself credits nothing.
            | Self::VaultCreation(_)
            // A token-creation record credits nothing either: the supply is
            // the release credit beside it.
            | Self::TokenCreation(_) => None,
        }
    }

    /// The class and identifying fields that together fix this state's
    /// position, without needing an identity to hash against.
    ///
    /// Exists so a mutation can check that its pre-state and post-state
    /// describe the SAME leaf at encode time, when `(G, DevID)` is not in
    /// hand. Two states share a position exactly when they agree here.
    pub fn position_material(&self) -> (u16, Vec<[u8; 32]>) {
        match self {
            Self::Balance(s) => (self.class(), vec![s.policy_commit]),
            Self::ConsumedSource(s) => (self.class(), vec![s.source_id]),
            Self::Relationship(s) => (self.class(), vec![s.vault_id]),
            Self::VaultCreation(s) => (self.class(), vec![s.vault_id]),
            Self::TokenCreation(s) => (self.class(), vec![s.policy_commit]),
        }
    }

    /// The position this state occupies, derived from `(G, DevID)` and the
    /// state's own identifying fields — never supplied by a caller.
    pub fn leaf_key(&self, genesis: &[u8; 32], device_id: &[u8; 32]) -> [u8; 32] {
        match self {
            Self::Balance(s) => keys::balance_key(genesis, device_id, &s.policy_commit),
            Self::ConsumedSource(s) => keys::consumed_source_key(genesis, device_id, &s.source_id),
            // `k_{T,v}` — the SoFi relationship key, which is the ONE
            // derivation for this leaf in both trees (F1). It is not restated
            // here in another form.
            Self::Relationship(s) => {
                crate::sofi::derive::relationship_key(genesis, device_id, &s.vault_id)
            }
            // The owner's own tree, scoped to the owner — `vault_id` already
            // derives from `(G_o, DevID_o, p_create)`, and the key says so
            // anyway because every economic key names the tree it lives in.
            Self::VaultCreation(s) => {
                crate::sofi::derive::vault_creation_key(genesis, device_id, &s.vault_id)
            }
            Self::TokenCreation(s) => {
                keys::token_creation_key(genesis, device_id, &s.policy_commit)
            }
        }
    }
}
