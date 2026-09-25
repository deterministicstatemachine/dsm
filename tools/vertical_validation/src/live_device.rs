// SPDX-License-Identifier: MIT OR Apache-2.0

//! Devices for the validation harnesses, on the path production runs.
//!
//! A device is a `DeviceState` head — the canonical Per-Device SMT (§2.2) —
//! advanced only by `DeviceState::advance`, with every operation signed by the
//! device's SPHINCS+ key over `Operation::signing_bytes`. A transfer is two
//! advances, the sender's debit and the recipient's credit, each on that
//! device's own chain for the relationship. Its stitched receipt is built from
//! the sender's outcome — the relationship path, both roots, the transition
//! entropy Core derived — and is checked by Core's receipt verifier. A harness
//! that disagrees with this module disagrees with production.
//!
//! ERA enters a device through the faucet-claim advance, one protocol payout
//! per claim. In production an economic admission precedes that advance; the
//! harnesses exercise the transition, not the admission.

use dsm::common::device_tree::DeviceTree;
use dsm::common::domain_tags::{TAG_DSM_TRACE_DEVICE, TAG_DSM_TRACE_GENESIS};
use dsm::core::bilateral_transaction_manager::compute_smt_key;
use dsm::core::token::token_state_manager::era_policy_commit;
use dsm::crypto::blake3::domain_hash_bytes;
use dsm::crypto::ephemeral_key::{generate_ephemeral_keypair, sign_ek_cert};
use dsm::crypto::signatures::SignatureKeyPair;
use dsm::economic::native_reserve::{era_reserve_id, ERA_FAUCET_PAYOUT};
use dsm::types::device_state::{AdvanceOutcome, BalanceDelta, BalanceDirection, DeviceState};
use dsm::types::error::DsmError;
use dsm::types::operations::{Operation, TransactionMode};
use dsm::types::receipt_types::{
    DeviceTreeAcceptanceCommitment, ReceiptVerificationContext, StitchedReceiptV2,
};
use dsm::types::token_types::Balance;

/// One device: identity, signing key, the chain head its per-step keys
/// certify back to (§11.1), and its canonical head.
pub struct LiveDevice {
    pub label: String,
    pub devid: [u8; 32],
    pub genesis: [u8; 32],
    pub keypair: SignatureKeyPair,
    chain_head_pk: Vec<u8>,
    chain_head_sk: Vec<u8>,
    pub head: DeviceState,
}

impl LiveDevice {
    /// A device whose identity and keys derive from `label`, so a harness run
    /// is reproducible.
    pub fn new(label: &str) -> Result<Self, DsmError> {
        let keypair =
            SignatureKeyPair::generate_from_entropy(format!("vv/device/{label}").as_bytes())?;
        let devid = domain_hash_bytes(TAG_DSM_TRACE_DEVICE, label.as_bytes());
        let genesis = domain_hash_bytes(TAG_DSM_TRACE_GENESIS, label.as_bytes());
        let (chain_head_pk, chain_head_sk) = generate_ephemeral_keypair(&domain_hash_bytes(
            TAG_DSM_TRACE_DEVICE,
            format!("{label}/chain-head").as_bytes(),
        ))?;
        let head = DeviceState::new(genesis, devid, keypair.public_key.clone());
        Ok(Self {
            label: label.to_string(),
            devid,
            genesis,
            keypair,
            chain_head_pk,
            chain_head_sk,
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
    /// contact does: its leaf enters the tree at `h_0`. A relationship
    /// already established stays as it is.
    pub fn establish(&mut self, other: &LiveDevice) -> Result<(), DsmError> {
        if self.tip_with(other).is_none() {
            self.head = self.head.establish_relationship(other.devid)?;
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
            token_id: b"ERA".to_vec(),
            policy_commit: era_policy_commit(),
            mode: TransactionMode::Unilateral,
            nonce: nonce.to_vec(),
            recipient: to.devid.to_vec(),
            to: to.label.as_bytes().to_vec(),
            message: String::new(),
            signature: Vec::new(),
            authority_policy: None,
        };
        let signature = self.keypair.sign(&op.signing_bytes())?;
        Ok(op.with_signature(signature))
    }

    /// The sender's advance for `op`: one debit of its amount on the
    /// relationship with `to`. Not installed.
    pub fn send(&self, to: &LiveDevice, op: &Operation) -> Result<AdvanceOutcome, DsmError> {
        self.head.advance(
            self.rel_key(to),
            to.devid,
            op.clone(),
            &[BalanceDelta {
                policy_commit: era_policy_commit(),
                direction: BalanceDirection::Debit,
                amount: transfer_amount(op)?,
            }],
            None,
            None,
        )
    }

    /// The recipient's advance for `op`: one credit of its amount on the
    /// relationship with `from`. Not installed.
    pub fn receive(&self, from: &LiveDevice, op: &Operation) -> Result<AdvanceOutcome, DsmError> {
        self.head.advance(
            self.rel_key(from),
            from.devid,
            op.clone(),
            &[BalanceDelta {
                policy_commit: era_policy_commit(),
                direction: BalanceDirection::Credit,
                amount: transfer_amount(op)?,
            }],
            None,
            None,
        )
    }

    /// Install an advance this device computed.
    pub fn install(&mut self, outcome: AdvanceOutcome) {
        self.head = outcome.new_device_state;
    }

    /// The authenticated Device Tree commitment a counterparty holds for this
    /// device: a tree of this one device.
    pub fn device_tree_commitment(&self) -> DeviceTreeAcceptanceCommitment {
        DeviceTreeAcceptanceCommitment::from_root(DeviceTree::single(self.devid).root())
    }
}

/// Establish the relationship between `a` and `b` on both devices.
pub fn connect(a: &mut LiveDevice, b: &mut LiveDevice) -> Result<(), DsmError> {
    a.establish(b)?;
    b.establish(a)
}

/// One faucet claim on `head`'s self-loop: the protocol payout of ERA, as the
/// release at `generation` (never 0, the reserve's genesis) of the network's
/// reserve.
pub fn faucet_claim(head: &DeviceState, generation: u64) -> Result<DeviceState, DsmError> {
    let devid = head.devid();
    head.advance(
        compute_smt_key(&devid, &devid),
        devid,
        Operation::FaucetClaim {
            reserve_id: era_reserve_id(b"dsm-testnet"),
            generation,
        },
        &[BalanceDelta {
            policy_commit: era_policy_commit(),
            direction: BalanceDirection::Credit,
            amount: ERA_FAUCET_PAYOUT,
        }],
        None,
        None,
    )
    .map(|outcome| outcome.new_device_state)
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

/// The stitched receipt of the step `outcome` records on `sender`'s device,
/// countersigned by `receiver`, each signature under a key certified back to
/// its signer's chain head over the parent tip.
pub fn stitched_receipt(
    sender: &LiveDevice,
    receiver: &LiveDevice,
    outcome: &AdvanceOutcome,
) -> Result<StitchedReceiptV2, DsmError> {
    let proofs = &outcome.smt_proofs;
    let parent_tip = proofs
        .parent_proof
        .value
        .ok_or_else(|| DsmError::invalid_operation("the parent path authenticates no tip"))?;
    let child_tip = proofs
        .child_proof
        .value
        .ok_or_else(|| DsmError::invalid_operation("the child path authenticates no tip"))?;
    let dev_proof = DeviceTree::single(sender.devid)
        .proof(&sender.devid)
        .ok_or_else(|| DsmError::invalid_operation("the sender is not in its own Device Tree"))?
        .to_bytes();
    let mut receipt = StitchedReceiptV2::new(
        sender.genesis,
        sender.devid,
        receiver.devid,
        parent_tip,
        child_tip,
        proofs.pre_root,
        proofs.post_root,
        proofs.parent_proof.to_bytes(),
        dev_proof,
    );
    receipt.set_transition_entropy(outcome.transition_entropy());
    receipt.set_ek_cert_a(sign_ek_cert(
        &sender.chain_head_sk,
        &sender.keypair.public_key,
        &parent_tip,
    )?);
    receipt.set_ek_cert_b(sign_ek_cert(
        &receiver.chain_head_sk,
        &receiver.keypair.public_key,
        &parent_tip,
    )?);
    let commitment = receipt.compute_commitment()?;
    receipt.add_sig_a(sender.keypair.sign(&commitment)?);
    receipt.add_sig_b(receiver.keypair.sign(&commitment)?);
    Ok(receipt)
}

/// What a verifier expecting `sender`'s step from `parent_root` holds: the
/// sender's authenticated Device Tree commitment and both chain heads.
pub fn verification_context(
    sender: &LiveDevice,
    receiver: &LiveDevice,
    parent_root: [u8; 32],
) -> ReceiptVerificationContext {
    ReceiptVerificationContext::new(
        sender.device_tree_commitment(),
        parent_root,
        sender.keypair.public_key.clone(),
        receiver.keypair.public_key.clone(),
    )
    .with_chain_head_a(sender.chain_head_pk.clone())
    .with_chain_head_b(receiver.chain_head_pk.clone())
}
