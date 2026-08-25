// SPDX-License-Identifier: Apache-2.0

//! The four `R_econ` leaf states — CCB classes `0x001F`–`0x0022` — and the
//! derivation of the position each one occupies.
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
use crate::dlv::settlement_receipt_leaf::derive_receipt_id;
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

/// `0x0020` schema 1 — one leg of one DLV's reserves, at a stated generation.
///
/// `vault_sequence` is a member of the state and not merely context: it is
/// what makes a zero reserve a distinguishable state rather than an absence,
/// and what stops a settlement being replayed against a generation it has
/// already consumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomicVaultReserveState {
    pub vault_id: [u8; 32],
    pub policy_commit: [u8; 32],
    pub amount: u64,
    pub vault_sequence: u64,
}

impl CcbObject for EconomicVaultReserveState {
    const CLASS: u16 = class::ECONOMIC_VAULT_RESERVE_STATE;
    const SCHEMA: u16 = 1;
}

impl EconomicVaultReserveState {
    fn encode(&self) -> Result<Vec<u8>, CcbError> {
        let mut out = Vec::new();
        push_envelope::<Self>(&mut out);
        push_digest32(&mut out, &self.vault_id); // 1
        push_digest32(&mut out, &self.policy_commit); // 2
        push_u64(&mut out, self.amount); // 3
        push_u64(&mut out, self.vault_sequence); // 4
        Ok(out)
    }
}

/// `0x0021` schema 1 — the record that one settlement happened against one
/// vault generation.
///
/// Its presence is what makes a `DlvReserveConsumption` credit non-reusable:
/// the settlement writes this leaf from ZERO, so a second settlement claiming
/// the same `(vault_id, receipt_id)` fails its own Merkle precondition. No
/// separate consumed-source leaf is needed for the DLV path because this leaf
/// already is one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomicSettlementReceiptState {
    pub vault_id: [u8; 32],
    pub receipt_id: [u8; 32],
    pub x: [u8; 32],
    pub parent_sequence: u64,
    pub new_sequence: u64,
    pub input_policy_commit: [u8; 32],
    pub input_amount: u64,
    pub output_policy_commit: [u8; 32],
    pub output_amount: u64,
}

impl CcbObject for EconomicSettlementReceiptState {
    const CLASS: u16 = class::ECONOMIC_SETTLEMENT_RECEIPT_STATE;
    const SCHEMA: u16 = 1;
}

impl EconomicSettlementReceiptState {
    /// The receipt's own consistency conditions, checked at construction so
    /// that an inconsistent receipt has no canonical bytes at all.
    ///
    /// `receipt_id` is **recomputed** from `(vault_id, x)` rather than trusted:
    /// it is a derived name, and a state carrying a name that does not derive
    /// from its own contents is exactly the self-rooting shape this tree is
    /// meant to remove.
    // The arity is the registry's field table, not a factoring choice.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vault_id: [u8; 32],
        x: [u8; 32],
        parent_sequence: u64,
        new_sequence: u64,
        input_policy_commit: [u8; 32],
        input_amount: u64,
        output_policy_commit: [u8; 32],
        output_amount: u64,
    ) -> Result<Self, CcbError> {
        if new_sequence != parent_sequence.saturating_add(1) {
            return Err(CcbError::ReceiptSequenceNotSuccessor {
                parent: parent_sequence,
                new: new_sequence,
            });
        }
        if input_amount == 0 || output_amount == 0 {
            return Err(CcbError::ReceiptZeroAmount);
        }
        if input_policy_commit == output_policy_commit {
            return Err(CcbError::ReceiptAssetsNotDistinct);
        }
        Ok(Self {
            vault_id,
            receipt_id: derive_receipt_id(&vault_id, &x),
            x,
            parent_sequence,
            new_sequence,
            input_policy_commit,
            input_amount,
            output_policy_commit,
            output_amount,
        })
    }

    fn encode(&self) -> Result<Vec<u8>, CcbError> {
        if self.new_sequence != self.parent_sequence.saturating_add(1) {
            return Err(CcbError::ReceiptSequenceNotSuccessor {
                parent: self.parent_sequence,
                new: self.new_sequence,
            });
        }
        if self.input_amount == 0 || self.output_amount == 0 {
            return Err(CcbError::ReceiptZeroAmount);
        }
        if self.input_policy_commit == self.output_policy_commit {
            return Err(CcbError::ReceiptAssetsNotDistinct);
        }
        let mut out = Vec::new();
        push_envelope::<Self>(&mut out);
        push_digest32(&mut out, &self.vault_id); // 1
        push_digest32(&mut out, &self.receipt_id); // 2
        push_digest32(&mut out, &self.x); // 3
        push_u64(&mut out, self.parent_sequence); // 4
        push_u64(&mut out, self.new_sequence); // 5
        push_digest32(&mut out, &self.input_policy_commit); // 6
        push_u64(&mut out, self.input_amount); // 7
        push_digest32(&mut out, &self.output_policy_commit); // 8
        push_u64(&mut out, self.output_amount); // 9
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

/// Any leaf of `R_econ`.
///
/// The offline device-bound allocation is deliberately **not** a variant. It
/// is a separate accounting regime that evolves outside this tree entirely;
/// only its boundaries (load and unload) touch `R_econ`, and they touch it
/// through the `balance` and `consumed_source` leaves like anything else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EconomicLeafState {
    Balance(EconomicBalanceState),
    VaultReserve(EconomicVaultReserveState),
    SettlementReceipt(EconomicSettlementReceiptState),
    ConsumedSource(EconomicConsumedSourceState),
}

impl EconomicLeafState {
    /// The CCB class of this leaf. Selects the key derivation, which is why a
    /// mutation whose pre- and post-states disagree on class is rejected.
    pub fn class(&self) -> u16 {
        match self {
            Self::Balance(_) => EconomicBalanceState::CLASS,
            Self::VaultReserve(_) => EconomicVaultReserveState::CLASS,
            Self::SettlementReceipt(_) => EconomicSettlementReceiptState::CLASS,
            Self::ConsumedSource(_) => EconomicConsumedSourceState::CLASS,
        }
    }

    /// Canonical commit bytes for the leaf's own state object.
    pub fn encode(&self) -> Result<Vec<u8>, CcbError> {
        match self {
            Self::Balance(s) => s.encode(),
            Self::VaultReserve(s) => s.encode(),
            Self::SettlementReceipt(s) => s.encode(),
            Self::ConsumedSource(s) => s.encode(),
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
    /// A settlement receipt and a consumed-source marker are INSERTIONS, not
    /// credits: they record that something happened, they do not add spendable
    /// units. Treating them as credits would demand a funding source for a
    /// bookkeeping entry.
    pub fn credit_amount(&self) -> Option<u64> {
        match self {
            Self::Balance(s) => Some(s.amount),
            Self::VaultReserve(s) => Some(s.amount),
            Self::SettlementReceipt(_) | Self::ConsumedSource(_) => None,
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
            Self::VaultReserve(s) => (self.class(), vec![s.vault_id, s.policy_commit]),
            Self::SettlementReceipt(s) => (self.class(), vec![s.vault_id, s.receipt_id]),
            Self::ConsumedSource(s) => (self.class(), vec![s.source_id]),
        }
    }

    /// The position this state occupies, derived from `(G, DevID)` and the
    /// state's own identifying fields — never supplied by a caller.
    pub fn leaf_key(&self, genesis: &[u8; 32], device_id: &[u8; 32]) -> [u8; 32] {
        match self {
            Self::Balance(s) => keys::balance_key(genesis, device_id, &s.policy_commit),
            Self::VaultReserve(s) => {
                keys::vault_reserve_key(genesis, device_id, &s.vault_id, &s.policy_commit)
            }
            Self::SettlementReceipt(s) => {
                keys::settlement_receipt_key(genesis, device_id, &s.vault_id, &s.receipt_id)
            }
            Self::ConsumedSource(s) => keys::consumed_source_key(genesis, device_id, &s.source_id),
        }
    }
}
