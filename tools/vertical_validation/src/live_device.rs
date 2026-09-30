// SPDX-License-Identifier: MIT OR Apache-2.0

//! Devices for the validation harnesses, on the path production runs.
//!
//! A device is a `DeviceState` head — the canonical Per-Device SMT (§2.2) —
//! advanced only by `DeviceState::advance`, with every operation signed by the
//! device's SPHINCS+ key over `Operation::signing_bytes`. A transfer is two
//! advances, the sender's debit and the recipient's credit, each on that
//! device's own chain for the relationship.
//!
//! A step between two devices is the offline bilateral protocol's step, as
//! production's sender builds it and production's receiver decides it
//! (`dsm::bilateral::offline`): the sender proposes the operation on the
//! relationship tip it holds, signed over the step's commitment; its stitched
//! receipt carries a per-step EK certified back to the sender's chain head;
//! the receiver decides with `decide_prepare` and `decide_confirm` against the
//! tip it holds and the keys its contact pins; and both commit, moving the
//! shared tip to the successor. A harness that disagrees with this module
//! disagrees with production.
//!
//! ERA enters a device through the faucet-claim advance, one protocol payout
//! per claim. In production an economic admission precedes that advance; the
//! harnesses exercise the transition, not the admission.

use std::collections::BTreeMap;

use dsm::bilateral::identity_binding::binding_digest;
use dsm::bilateral::offline::{
    decide_confirm, decide_prepare, AcceptedStep, ConfirmClaims, PeerCredentials, PinnedPeer,
    PrepareClaims, PrepareDecision, VerifiedConfirm,
};
use dsm::common::device_tree::DeviceTree;
use dsm::common::domain_tags::{TAG_DSM_TRACE_DEVICE, TAG_DSM_TRACE_GENESIS};
use dsm::core::bilateral_transaction_manager::{
    bilateral_sign_message, compute_precommit, compute_smt_key, compute_successor_tip,
    initial_chain_tip_from_device_ids, BilateralPreCommitment,
};
use dsm::core::token::token_state_manager::era_policy_commit;
use dsm::crypto::blake3::domain_hash_bytes;
use dsm::crypto::ephemeral_key::{generate_ephemeral_keypair, sign_ek_cert};
use dsm::crypto::kyber::generate_kyber_keypair_from_entropy;
use dsm::crypto::signatures::SignatureKeyPair;
use dsm::crypto::sphincs::sphincs_sign;
use dsm::economic::native_reserve::{era_reserve_id, ERA_FAUCET_PAYOUT};
use dsm::types::device_state::{AdvanceOutcome, BalanceDelta, BalanceDirection, DeviceState};
use dsm::types::error::DsmError;
use dsm::types::operations::{Operation, TransactionMode};
use dsm::types::receipt_types::{
    compute_receipt_challenge_response_target, DeviceTreeAcceptanceCommitment, StitchedReceiptV2,
};
use dsm::types::token_types::Balance;

/// One device: identity, its AK and the Kyber key bound to it, its canonical
/// head, and, per relationship, what production keeps durably beside the
/// head: the shared tip it holds, its own per-step EK chain head, and the
/// counterparty's.
pub struct LiveDevice {
    pub label: String,
    pub devid: [u8; 32],
    pub genesis: [u8; 32],
    pub keypair: SignatureKeyPair,
    /// The device's Kyber keypair, `(pk, sk)`, and its AK's binding of the
    /// public key to the device's identity.
    kyber: (Vec<u8>, Vec<u8>),
    kyber_binding_sig: Vec<u8>,
    pub head: DeviceState,
    /// Counterparty -> the relationship tip this device holds.
    shared_tips: BTreeMap<[u8; 32], [u8; 32]>,
    /// Counterparty -> this device's newest EK on the relationship, `(pk, sk)`.
    own_ek_heads: BTreeMap<[u8; 32], (Vec<u8>, Vec<u8>)>,
    /// Counterparty -> the counterparty's newest EK on the relationship.
    peer_ek_heads: BTreeMap<[u8; 32], Vec<u8>>,
    /// Steps this device has proposed, so each per-step EK is its own.
    proposals: u64,
}

/// One step of the offline bilateral protocol as its sender built it: the
/// proposal and the confirm, and the sender's advance, not installed.
#[derive(Clone)]
pub struct Step {
    pub operation: Operation,
    pub sender_outcome: AdvanceOutcome,
    /// The relationship tip the proposal extends.
    pub expected_tip: [u8; 32],
    pub commitment_hash: [u8; 32],
    /// σ_A: the sender's AK over the step's commitment.
    pub sender_signature: Vec<u8>,
    pub receipt: StitchedReceiptV2,
    pub pre_entropy: [u8; 32],
    pub successor_tip: [u8; 32],
    /// The per-step EK the receipt is signed with, `(pk, sk)`.
    ek: (Vec<u8>, Vec<u8>),
}

impl Step {
    /// This step with its receipt signed by a fresh EK that `certifier`'s AK
    /// certifies over the parent tip: an EK the sender's own chain never
    /// certified, every other artifact of the receipt genuine.
    pub fn with_ek_certified_by(mut self, certifier: &LiveDevice) -> Result<Self, DsmError> {
        let ek = generate_ephemeral_keypair(&domain_hash_bytes(
            TAG_DSM_TRACE_DEVICE,
            format!("{}/foreign-ek", certifier.label).as_bytes(),
        ))?;
        let parent_tip = self.receipt.parent_tip;
        self.receipt.set_ek_pk_a(ek.0.clone());
        self.receipt.set_ek_cert_a(sign_ek_cert(
            certifier.keypair.secret_key(),
            &ek.0,
            &parent_tip,
        )?);
        self.ek = ek;
        self.resigned()
    }

    /// This step with its receipt re-signed by the step's own per-step EK
    /// over its current bytes: what a sender that alters its own receipt can
    /// sign.
    pub fn resigned(mut self) -> Result<Self, DsmError> {
        self.receipt.sig_a.clear();
        let target = compute_receipt_challenge_response_target(
            &self.receipt.compute_commitment()?,
            &self.commitment_hash,
        );
        self.receipt.add_sig_a(sphincs_sign(&self.ek.1, &target)?);
        Ok(self)
    }
}

/// The receiver's decision on a step, as Core makes it.
#[derive(Debug)]
pub enum Decision {
    /// Both `decide_prepare` and `decide_confirm` accept the step.
    Accepted(VerifiedConfirm),
    /// `decide_prepare`: the proposal does not extend the tip the receiver
    /// holds.
    StaleTip,
    /// `decide_prepare` answered neither `Consider` nor `StaleTip`.
    Unconsidered(PrepareDecision),
    /// `decide_prepare` refused the proposal.
    PrepareRefused(DsmError),
    /// The receipt could not be encoded for the confirm.
    Unencodable(DsmError),
    /// `decide_confirm` refused the confirm.
    ConfirmRefused(DsmError),
    /// The sender is not this device's contact.
    NotAContact,
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Decision::Accepted(verified) => write!(
                f,
                "accepted, successor {}",
                dsm::utils::text_id::encode_base32_crockford(&verified.successor_tip)
            ),
            Decision::StaleTip => write!(f, "refused: a stale tip"),
            Decision::Unconsidered(answer) => write!(f, "prepare answered {answer:?}"),
            Decision::PrepareRefused(e) => write!(f, "prepare refused: {e}"),
            Decision::Unencodable(e) => write!(f, "the receipt does not encode: {e}"),
            Decision::ConfirmRefused(e) => write!(f, "confirm refused: {e}"),
            Decision::NotAContact => write!(f, "the sender is not a contact"),
        }
    }
}

/// The two decisions the receiver makes on a step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Prepare,
    Confirm,
}

impl Decision {
    /// The error `stage` refused the step with, when this is that stage's
    /// refusal.
    pub fn refusal_at(&self, stage: Stage) -> Option<&DsmError> {
        match (self, stage) {
            (Decision::PrepareRefused(e), Stage::Prepare)
            | (Decision::ConfirmRefused(e), Stage::Confirm) => Some(e),
            _ => None,
        }
    }
}

impl LiveDevice {
    /// A device whose identity and keys derive from `label`, so a harness run
    /// is reproducible.
    pub fn new(label: &str) -> Result<Self, DsmError> {
        let keypair =
            SignatureKeyPair::generate_from_entropy(format!("vv/device/{label}").as_bytes())?;
        let devid = domain_hash_bytes(TAG_DSM_TRACE_DEVICE, label.as_bytes());
        let genesis = domain_hash_bytes(TAG_DSM_TRACE_GENESIS, label.as_bytes());
        let kyber = generate_kyber_keypair_from_entropy(
            &domain_hash_bytes(TAG_DSM_TRACE_DEVICE, format!("{label}/kyber").as_bytes()),
            "vv/device/kyber",
        )?;
        let kyber_binding_sig = keypair.sign(&binding_digest(&devid, &genesis, &kyber.0))?;
        let head = DeviceState::new(genesis, devid, keypair.public_key.clone());
        Ok(Self {
            label: label.to_string(),
            devid,
            genesis,
            keypair,
            kyber,
            kyber_binding_sig,
            head,
            shared_tips: BTreeMap::new(),
            own_ek_heads: BTreeMap::new(),
            peer_ek_heads: BTreeMap::new(),
            proposals: 0,
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
    /// contact does: its leaf enters the tree at `h_0`, and the contact holds
    /// the shared tip `h_0`. A relationship already established stays as it
    /// is.
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
            self.shared_tips.insert(
                other,
                initial_chain_tip_from_device_ids(&self.devid, &other),
            );
        }
        Ok(())
    }

    /// The shared relationship tip this device holds for `other`, as its
    /// contact record keeps it.
    pub fn shared_tip_with(&self, other: &LiveDevice) -> Option<[u8; 32]> {
        self.shared_tips.get(&other.devid).copied()
    }

    /// This device as a counterparty's contact record pins it.
    pub fn pinned(&self) -> PinnedPeer<'_> {
        PinnedPeer {
            device_id: self.devid,
            genesis: self.genesis,
            signing_key: &self.keypair.public_key,
            kyber_public_key: &self.kyber.0,
        }
    }

    /// The keys this device sends with a proposal.
    pub fn credentials(&self) -> PeerCredentials<'_> {
        PeerCredentials {
            signing_key: &self.keypair.public_key,
            kyber_public_key: &self.kyber.0,
            kyber_binding_sig: &self.kyber_binding_sig,
        }
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
            None,
        )
    }

    /// The step this device proposes to `to`: `operation` on the shared tip
    /// it holds, as production's sender builds the proposal and the confirm.
    /// The commitment binds the tip and the operation; σ_A is the AK's
    /// signature over it; the receipt is the sender's stitched receipt of its
    /// advance, signed by a fresh per-step EK that the sender's newest EK on
    /// the relationship (its AK at the first step) certifies over the parent
    /// tip; and the successor tip is reproduced from the tip, the operation
    /// and the entropy the advance derived.
    pub fn propose(&mut self, to: &LiveDevice, operation: Operation) -> Result<Step, DsmError> {
        let expected_tip = self
            .shared_tip_with(to)
            .ok_or_else(|| DsmError::relationship("the counterparty is not a contact"))?;
        let commitment_hash =
            BilateralPreCommitment::new(expected_tip, operation.clone()).bilateral_commitment_hash;
        let sender_signature = self
            .keypair
            .sign(&bilateral_sign_message(&commitment_hash))?;
        let sender_outcome = self.send(to, &operation)?;

        self.proposals += 1;
        let ek = generate_ephemeral_keypair(&domain_hash_bytes(
            TAG_DSM_TRACE_DEVICE,
            format!("{}/ek/{}", self.label, self.proposals).as_bytes(),
        ))?;
        let mut receipt = StitchedReceiptV2::of_step(
            self.genesis,
            self.devid,
            to.devid,
            &sender_outcome,
            None,
            &self.device_tree_commitment(),
        )?;
        let parent_tip = receipt.parent_tip;
        let certifier = match self.own_ek_heads.get(&to.devid) {
            Some((_, sk)) => sk.clone(),
            None => self.keypair.secret_key().to_vec(),
        };
        receipt.set_ek_pk_a(ek.0.clone());
        receipt.set_ek_cert_a(sign_ek_cert(&certifier, &ek.0, &parent_tip)?);
        let target = compute_receipt_challenge_response_target(
            &receipt.compute_commitment()?,
            &commitment_hash,
        );
        receipt.add_sig_a(sphincs_sign(&ek.1, &target)?);

        let pre_entropy = sender_outcome.transition_entropy();
        let op_bytes = operation.to_bytes();
        let c_pre = compute_precommit(&expected_tip, &op_bytes, &pre_entropy);
        let successor_tip = compute_successor_tip(&expected_tip, &op_bytes, &pre_entropy, &c_pre);
        Ok(Step {
            operation,
            sender_outcome,
            expected_tip,
            commitment_hash,
            sender_signature,
            receipt,
            pre_entropy,
            successor_tip,
            ek,
        })
    }

    /// This device's decision, as receiver, on `step` from `from`: Core's
    /// `decide_prepare` against the shared tip it holds and the keys its
    /// contact pins, then `decide_confirm` against the sender's Device Tree
    /// commitment and the sender's EK chain head it keeps.
    pub fn decide(&self, from: &LiveDevice, step: &Step) -> Decision {
        let Some(held_tip) = self.shared_tip_with(from) else {
            return Decision::NotAContact;
        };
        let prepare = decide_prepare(
            step.commitment_hash,
            &step.operation,
            PrepareClaims {
                addressed_to: &self.devid,
                expected_tip: Some(step.expected_tip),
                credentials: from.credentials(),
                signature: &step.sender_signature,
            },
            &from.pinned(),
            &self.devid,
            held_tip,
            None,
        );
        match prepare {
            Ok(PrepareDecision::Consider { .. }) => {}
            Ok(PrepareDecision::StaleTip { .. }) => return Decision::StaleTip,
            Ok(other) => return Decision::Unconsidered(other),
            Err(e) => return Decision::PrepareRefused(e),
        }
        // The confirm carries the signed receipt: its full wire bytes.
        let receipt = match step.receipt.to_full_protobuf() {
            Ok(bytes) => bytes,
            Err(e) => return Decision::Unencodable(e),
        };
        match decide_confirm(
            ConfirmClaims {
                signature: &step.sender_signature,
                receipt: &receipt,
                pre_entropy: &step.pre_entropy,
                successor_tip: Some(step.successor_tip),
            },
            AcceptedStep {
                commitment_hash: step.commitment_hash,
                operation: &step.operation,
                held_tip,
                receiver_device_id: self.devid,
                sender_device_tree_root: DeviceTree::single(from.devid).root(),
                sender_chain_head: self.peer_ek_heads.get(&from.devid).map(Vec::as_slice),
                bearer: None,
            },
            &from.pinned(),
        ) {
            Ok(verified) => Decision::Accepted(verified),
            Err(e) => Decision::ConfirmRefused(e),
        }
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

/// Commit a step the receiver accepted, on both devices, as production does:
/// the receiver's advance and the sender's are installed, both hold the
/// verified successor as the relationship's tip, and each keeps the step's EK
/// as the sender's chain head on the relationship.
pub fn commit(
    sender: &mut LiveDevice,
    receiver: &mut LiveDevice,
    step: Step,
    verified: &VerifiedConfirm,
) -> Result<(), DsmError> {
    let received = receiver.receive(sender, &step.operation)?;
    receiver.install(received);
    receiver
        .shared_tips
        .insert(sender.devid, verified.successor_tip);
    receiver
        .peer_ek_heads
        .insert(sender.devid, step.ek.0.clone());
    sender.install(step.sender_outcome);
    sender
        .shared_tips
        .insert(receiver.devid, verified.successor_tip);
    sender.own_ek_heads.insert(receiver.devid, step.ek);
    Ok(())
}

/// A non-value operation the offline protocol carries, marked `mark`, as
/// production's offline step tests carry one.
pub fn marked(mark: u8) -> Operation {
    Operation::Generic {
        operation_type: b"vertical-validation-step".to_vec(),
        data: vec![mark],
        message: String::new(),
        signature: Vec::new(),
    }
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
