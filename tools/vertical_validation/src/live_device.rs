// SPDX-License-Identifier: MIT OR Apache-2.0

//! Devices for the validation harnesses, on the path production runs.
//!
//! A device is a `DeviceState` head — the canonical Per-Device SMT (§2.2) —
//! advanced only by `DeviceState::advance`, with every operation signed by the
//! device's SPHINCS+ key over `Operation::signing_bytes`. A transfer is two
//! advances, the sender's debit and the recipient's credit, each on that
//! device's own chain for the relationship.
//!
//! A step decided by the offline bilateral protocol's receiver is not built
//! here: the offline door carries only the offline-bearer transfer, and Core's
//! `decide_confirm` takes the sender's anchor-state leaves and the receiver's
//! record of the sender's offline account, which only a walk of the sender's
//! history produces. Those steps run on real bearer pairs in the SDK's
//! offline step tests (§6.103).
//!
//! ERA enters a device through the faucet-claim advance, one protocol payout
//! per claim. In production an economic admission precedes that advance; the
//! harnesses exercise the transition, not the admission.

use dsm::common::domain_tags::{TAG_DSM_TRACE_DEVICE, TAG_DSM_TRACE_GENESIS};
use dsm::core::bilateral_transaction_manager::compute_smt_key;
use dsm::core::token::token_state_manager::era_policy_commit;
use dsm::crypto::blake3::domain_hash_bytes;
use dsm::crypto::signatures::SignatureKeyPair;
use dsm::economic::native_reserve::{era_reserve_id, ERA_FAUCET_PAYOUT};
use dsm::types::device_state::{
    AdvanceOutcome, BalanceDelta, BalanceDirection, DeviceState, RealizedHead,
};
use dsm::types::error::DsmError;
use dsm::types::operations::{Operation, TransactionMode};
use dsm::types::token_types::Balance;

/// One device: its identity, its AK and its canonical head.
pub struct LiveDevice {
    pub devid: [u8; 32],
    pub keypair: SignatureKeyPair,
    pub head: RealizedHead,
}

impl LiveDevice {
    /// A device whose identity and keys derive from `label`, so a harness run
    /// is reproducible.
    pub fn new(label: &str) -> Result<Self, DsmError> {
        let keypair =
            SignatureKeyPair::generate_from_entropy(format!("vv/device/{label}").as_bytes())?;
        let devid = domain_hash_bytes(TAG_DSM_TRACE_DEVICE, label.as_bytes());
        let genesis = domain_hash_bytes(TAG_DSM_TRACE_GENESIS, label.as_bytes());
        let head = DeviceState::genesis_head(genesis, devid, keypair.public_key.clone());
        Ok(Self {
            devid,
            keypair,
            head,
        })
    }

    pub fn era_balance(&self) -> u64 {
        self.head.balance(&era_policy_commit())
    }

    /// One faucet claim; see [`faucet_claim`].
    pub fn claim_faucet(&mut self, generation: u64) -> Result<(), DsmError> {
        self.head = faucet_claim(&self.head, generation)?;
        Ok(())
    }

    /// The relationship's SMT key, the same on both devices.
    pub fn rel_key(&self, other: &LiveDevice) -> [u8; 32] {
        compute_smt_key(&self.devid, &other.devid)
    }

    /// Establish the relationship with `other` on this device, as adding a
    /// contact does: its leaf enters the tree at `h_0`. A relationship already
    /// established stays as it is.
    pub fn establish(&mut self, other: &LiveDevice) -> Result<(), DsmError> {
        self.establish_with(other.devid)
    }

    /// [`Self::establish`] with the device whose id is `other`.
    pub fn establish_with(&mut self, other: [u8; 32]) -> Result<(), DsmError> {
        if self
            .head
            .chain_tip(&compute_smt_key(&self.devid, &other))
            .is_none()
        {
            self.head = self.head.establish_relationship(other)?;
        }
        Ok(())
    }

    /// This device's tip for the relationship with `other`, once established.
    pub fn tip_with(&self, other: &LiveDevice) -> Option<[u8; 32]> {
        self.head.chain_tip(&self.rel_key(other))
    }

    /// A transfer of `amount` ERA to `to`, signed by this device over its
    /// signing bytes, as `wallet.send` signs one.
    pub fn transfer(
        &self,
        to: &LiveDevice,
        amount: u64,
        nonce: &[u8],
    ) -> Result<Operation, DsmError> {
        let op = Operation::Transfer {
            to_device_id: to.devid.to_vec(),
            amount: Balance::amount(amount),
            policy_commit: era_policy_commit(),
            token_policy: dsm::core::token::era_policy::era_policy_bytes().to_vec(),
            terms_commitment: dsm::types::operations::TransferTerms {
                token_id: b"ERA".to_vec(),
                nonce: nonce.to_vec(),
                mode: TransactionMode::Unilateral,
                memo: String::new(),
                salt: vec![0x5A; 32],
            }
            .commitment(),
            signature: Vec::new(),
            authority_policy: None,
        };
        let signature = self.keypair.sign(&op.signing_bytes())?;
        Ok(op.with_signature(signature))
    }

    /// The sender's advance for `op` on the relationship with `to`: a
    /// transfer debits its amount, any other operation moves no value. Not
    /// installed.
    pub fn send(&self, to: &LiveDevice, op: &Operation) -> Result<AdvanceOutcome, DsmError> {
        self.head.advance(
            self.rel_key(to),
            to.devid,
            op.clone(),
            value_moved(op, BalanceDirection::Debit)?.as_slice(),
            None,
        )
    }

    /// The recipient's advance for `op` on the relationship with `from`: a
    /// transfer credits its amount, any other operation moves no value. Not
    /// installed.
    pub fn receive(&self, from: &LiveDevice, op: &Operation) -> Result<AdvanceOutcome, DsmError> {
        self.head.advance(
            self.rel_key(from),
            from.devid,
            op.clone(),
            value_moved(op, BalanceDirection::Credit)?.as_slice(),
            None,
        )
    }

    /// Install an advance this device computed.
    pub fn install(&mut self, outcome: AdvanceOutcome) {
        self.head = outcome.new_device_state;
    }
}

/// Establish the relationship between `a` and `b` on both devices.
pub fn connect(a: &mut LiveDevice, b: &mut LiveDevice) -> Result<(), DsmError> {
    a.establish(b)?;
    b.establish(a)
}

/// The balance a step's operation moves: a transfer's amount in `direction`;
/// any other operation moves none.
fn value_moved(
    op: &Operation,
    direction: BalanceDirection,
) -> Result<Option<BalanceDelta>, DsmError> {
    match op {
        Operation::Transfer { .. } => Ok(Some(BalanceDelta {
            policy_commit: era_policy_commit(),
            direction,
            amount: transfer_amount(op)?,
        })),
        _ => Ok(None),
    }
}

/// One faucet claim on `head`'s self-loop: the protocol payout of ERA, as the
/// release at `generation` (never 0, the reserve's genesis) of the network's
/// reserve. Advanced as the wallet advances it, carrying its own `Prepared`
/// economic admission; the head returned carries the admission `head` had.
pub fn faucet_claim(head: &RealizedHead, generation: u64) -> Result<RealizedHead, DsmError> {
    use dsm::economic::admission::{
        dsm_operation_digest, PendingAdmissionKind, PendingEconomicAdmission,
    };
    let devid = head.devid();
    let claim = Operation::FaucetClaim {
        reserve_id: era_reserve_id(b"dsm-testnet"),
        generation,
    };
    let prepared = PendingEconomicAdmission::prepared(
        PendingAdmissionKind::DsmBacked,
        1,
        dsm::economic::tree::empty_economic_root(),
        dsm_operation_digest(&claim.to_bytes()),
    );
    head.with_pending_economic_admission(Some(prepared))
        .advance(
            compute_smt_key(&devid, &devid),
            devid,
            claim,
            &[BalanceDelta {
                policy_commit: era_policy_commit(),
                direction: BalanceDirection::Credit,
                amount: ERA_FAUCET_PAYOUT,
            }],
            None,
        )
        .map(|outcome| {
            outcome
                .new_device_state
                .with_pending_economic_admission(head.pending_economic_admission().cloned())
        })
}

/// The amount a transfer operation carries.
pub fn transfer_amount(op: &Operation) -> Result<u64, DsmError> {
    match op {
        Operation::Transfer { amount, .. } => Ok(amount.value()),
        other => Err(DsmError::invalid_operation(format!(
            "{} is not a transfer",
            other.get_operation_type()
        ))),
    }
}
