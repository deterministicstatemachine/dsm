// SPDX-License-Identifier: MIT OR Apache-2.0

//! The offline bilateral protocol's decisions: transport-agnostic and pure.
//! Every input is passed in and nothing is read or written. The SDK runner
//! loads what a decision needs (the pinned contact, the relationship tip it
//! holds durably, the session), applies the outcome, and hands the frames it
//! answers with to a carrier. A carrier moves bytes and decides nothing.
//!
//! A message is authenticated only by what it proves against the pinned
//! contact: its signatures verify under the pinned AK, and the keys it carries
//! are the pinned keys. Who delivered it, and over which carrier, proves
//! nothing.

use crate::core::bilateral_transaction_manager::{
    bilateral_accept_sign_message, bilateral_sign_message, compute_precommit,
    compute_successor_tip, operation_requires_offline_bearer, BilateralPreCommitment,
};
use crate::types::receipt_types::{DeviceTreeAcceptanceCommitment, ReceiptLeaf, StitchedReceiptV2};
use crate::verification::receipt_verification::{
    per_step_ek_predecessor, verify_per_step_ek_signing, verify_receipt_state, BearerLeaves,
    BilateralSide, ReceiptStateContext,
};
use crate::crypto::signatures::SignatureKeyPair;
use crate::types::error::DsmError;
use crate::types::operations::Operation;

use super::identity_binding::verify_kyber_identity_binding;

/// A counterparty as its contact record pins it, from its self-proving
/// directory entry.
#[derive(Clone, Copy, Debug)]
pub struct PinnedPeer<'a> {
    pub device_id: [u8; 32],
    pub genesis: [u8; 32],
    pub signing_key: &'a [u8],
    pub kyber_public_key: &'a [u8],
}

/// The operation a proposal carries, if the offline protocol may carry it at
/// all ([`offline_door`]).
pub fn offline_operation(operation_bytes: &[u8]) -> Result<Operation, DsmError> {
    let operation = Operation::from_bytes(operation_bytes)
        .map_err(|_| DsmError::invalid_operation("invalid operation payload"))?;
    offline_door(&operation)?;
    Ok(operation)
}

/// The offline door, at the sender's and the receiver's alike (MR-DSM-0219;
/// §6.105 C1, decided 2026-10-27). The offline protocol carries exactly what
/// the offline rulings name: the offline-bearer transfer. Every other
/// operation is refused here, before anything is written or signed — SoFi
/// and vault operations because SoFi is online and does not inherit the
/// offline-bearer path (Explainer §63, SoFi §4), an online-tier transfer
/// because it has the network transport, and the rest because offline nothing
/// but the bearer transfer moves. A load, an unload and a settlement are not
/// operations on this door: they are the device's own admitted transitions
/// online. The match has no wildcard arm, so a variant added to `Operation`
/// does not compile until it is classified here.
pub fn offline_door(operation: &Operation) -> Result<(), DsmError> {
    let refused = |what: &str, why: &str| {
        Err(DsmError::invalid_operation(format!(
            "the offline door carries only the offline-bearer transfer: {what} is refused — {why}"
        )))
    };
    const SOFI_IS_ONLINE: &str =
        "SoFi is online and does not inherit the offline-bearer path (Explainer §63, SoFi §4)";
    const NOT_OFFLINE: &str =
        "offline, value moves only as the offline-bearer transfer the offline rulings name";
    match operation {
        Operation::Transfer { .. } if operation_requires_offline_bearer(operation) => Ok(()),
        Operation::Transfer { .. } => refused(
            "an online-tier transfer",
            "BLE/USB carries offline-bearer transfers only; an online-tier transfer uses the \
             network transport",
        ),
        Operation::SofiSetup { .. }
        | Operation::SofiVaultCreate { .. }
        | Operation::SofiFulfill { .. } => refused("a SoFi operation", SOFI_IS_ONLINE),
        Operation::DlvCreate { .. }
        | Operation::DlvUnlock { .. }
        | Operation::DlvClaim { .. }
        | Operation::DlvInvalidate { .. }
        | Operation::EscrowVaultCreate { .. } => refused("a vault operation", SOFI_IS_ONLINE),
        Operation::FaucetClaim { .. }
        | Operation::AdoptToken { .. }
        | Operation::CreateToken { .. }
        | Operation::Burn { .. }
        | Operation::LockToken { .. }
        | Operation::UnlockToken { .. }
        | Operation::Lock { .. }
        | Operation::Unlock { .. }
        | Operation::Receive { .. } => refused("a token operation", NOT_OFFLINE),
        Operation::Genesis
        | Operation::Create { .. }
        | Operation::Update { .. }
        | Operation::AddRelationship { .. }
        | Operation::CreateRelationship { .. }
        | Operation::RemoveRelationship { .. }
        | Operation::Recovery { .. }
        | Operation::Delete { .. }
        | Operation::Link { .. }
        | Operation::Unlink { .. }
        | Operation::Invalidate { .. } => {
            refused("an identity or relationship operation", NOT_OFFLINE)
        }
        Operation::Generic { .. } | Operation::Noop => {
            refused("a step that moves no value", NOT_OFFLINE)
        }
    }
}

/// An offline-bearer transfer moves only a token its committed policy lets
/// move between holders (owner question 9, 2026-10-27: "Core must be the
/// authoritative enforcement boundary ... Any policy supplied to Core must be
/// authenticated against the committed token policy"). The transfer carries
/// the token's committed `TokenPolicyV3` bytes; they must re-hash to its
/// `policy_commit` (`economic::write_set::moved_token_policy`, the one check
/// the write set runs online), and the policy must be `transferable`. An
/// offline step has no economic write set, so its sender's and its receiver's
/// Core hold it to this here, before anything is written.
pub fn bearer_token_moves(operation: &Operation) -> Result<(), DsmError> {
    let Operation::Transfer {
        policy_commit,
        token_policy,
        ..
    } = operation
    else {
        return Err(DsmError::invalid_operation(
            "an offline-bearer token policy is the policy of a transfer",
        ));
    };
    let policy = crate::economic::write_set::moved_token_policy(policy_commit, token_policy)
        .map_err(|e| DsmError::invalid_operation(format!("offline-bearer transfer: {e}")))?;
    if !policy.transferable {
        return Err(DsmError::invalid_operation(
            "offline-bearer transfer: the token's committed policy makes it non-transferable",
        ));
    }
    Ok(())
}

/// The keys a message carries for its sender: its AK, its Kyber key and the
/// binding of the one to the other.
#[derive(Clone, Copy, Debug)]
pub struct PeerCredentials<'a> {
    pub signing_key: &'a [u8],
    pub kyber_public_key: &'a [u8],
    pub kyber_binding_sig: &'a [u8],
}

/// The keys a peer sent are the keys its contact pins, and its Kyber key is
/// bound to its identity under its pinned AK. Nothing sent replaces a pinned
/// key.
pub fn verify_pinned_peer_keys(
    peer: &PinnedPeer<'_>,
    sent: PeerCredentials<'_>,
) -> Result<(), DsmError> {
    let (wire_signing_key, wire_kyber_public_key, wire_binding_sig) = (
        sent.signing_key,
        sent.kyber_public_key,
        sent.kyber_binding_sig,
    );
    if wire_signing_key != peer.signing_key {
        return Err(DsmError::invalid_operation(
            "the signing key sent is not the contact's pinned AK",
        ));
    }
    if wire_kyber_public_key != peer.kyber_public_key {
        return Err(DsmError::invalid_operation(
            "the Kyber key sent is not the contact's pinned Kyber key",
        ));
    }
    verify_kyber_identity_binding(
        &peer.device_id,
        &peer.genesis,
        wire_kyber_public_key,
        wire_binding_sig,
        peer.signing_key,
    )
    .map_err(|e| {
        DsmError::invalid_operation(format!(
            "the Kyber identity binding does not verify under the pinned AK: {e}"
        ))
    })
}

/// `signature` is `peer`'s signature over the step `commitment_hash`, under
/// its pinned AK.
fn verify_step_signature(
    peer: &PinnedPeer<'_>,
    commitment_hash: &[u8; 32],
    signature: &[u8],
    what: &str,
) -> Result<(), DsmError> {
    verify_signature_over(
        peer,
        &bilateral_sign_message(commitment_hash),
        signature,
        what,
    )
}

/// `signature` is `peer`'s signature over `message`, under its pinned AK.
fn verify_signature_over(
    peer: &PinnedPeer<'_>,
    message: &[u8],
    signature: &[u8],
    what: &str,
) -> Result<(), DsmError> {
    if signature.is_empty() {
        return Err(DsmError::invalid_operation(format!(
            "the {what} carries no signature over its commitment"
        )));
    }
    let valid = SignatureKeyPair::verify_raw(message, signature, peer.signing_key)
        .map_err(|e| DsmError::invalid_operation(format!("{what} signature: {e}")))?;
    if !valid {
        return Err(DsmError::invalid_operation(format!(
            "the {what} is not signed over its commitment by the pinned AK"
        )));
    }
    Ok(())
}

/// The receiver's decision on a proposal it has authenticated.
#[derive(Debug)]
pub enum PrepareDecision {
    /// The proposal extends the relationship tip this device holds: it is
    /// put to the user.
    Consider { commitment_hash: [u8; 32] },
    /// The relationship holds another step in flight on this device. It
    /// takes one step at a time, at the receiver's door as at the
    /// proposer's: the proposal is answered with a signed rejection, which is
    /// kept as the answer to the proposal delivered again. Two proposals that
    /// cross are each refused this way; were either taken, each could commit
    /// on its receiver, and the relationship would hold two successors of one
    /// tip.
    StepInFlight { in_flight: [u8; 32] },
    /// The proposal does not extend the tip this device holds: it is answered
    /// with a signed rejection, and the relationship is reconciled online.
    /// `expected_recomputes` when the proposal's commitment is its operation's
    /// commitment on the tip it claims — only then is that claim evidence of
    /// the sender's tip.
    StaleTip {
        expected: Option<[u8; 32]>,
        held: [u8; 32],
        expected_recomputes: bool,
    },
    /// The prepare is addressed to another device. Here it is meaningless
    /// bytes: nothing this device holds is read for it, nothing is written,
    /// and nothing answers it.
    NotAddressed,
}

/// What a prepare claims: the device it is addressed to, the tip it expects
/// the relationship to hold, its sender's keys, and its sender's signature
/// (σ_A) over its commitment.
#[derive(Clone, Copy, Debug)]
pub struct PrepareClaims<'a> {
    pub addressed_to: &'a [u8],
    pub expected_tip: Option<[u8; 32]>,
    pub credentials: PeerCredentials<'a>,
    pub signature: &'a [u8],
}

/// The receiver's decision on a prepare. `operation` is what
/// [`offline_operation`] admitted from the request, `commitment_hash` the
/// commitment the proposal names, `local_device_id` this device, `held_tip`
/// the relationship tip this device holds durably, and `in_flight` the step
/// this device holds in flight on the relationship, if any. A prepare
/// addressed to another device — by the request, or by the transfer it
/// commits — is not addressed here, and is decided so before anything else.
/// The proposal must come from the pinned sender (its keys, and its
/// signature over the commitment); it is refused while another step is in
/// flight; and its commitment must be its operation's commitment on the held
/// tip — the receiver never signs a commitment it did not recompute. A
/// bearer transfer moves only a token its committed policy lets move; the
/// allocation it spends is proven to be its sender's at the confirm, from the
/// account this device recorded ([`spend_starts_at_the_record`]).
pub fn decide_prepare(
    commitment_hash: [u8; 32],
    operation: &Operation,
    claims: PrepareClaims<'_>,
    sender: &PinnedPeer<'_>,
    local_device_id: &[u8; 32],
    held_tip: [u8; 32],
    in_flight: Option<[u8; 32]>,
) -> Result<PrepareDecision, DsmError> {
    let transfer_addressed_elsewhere = matches!(
        operation,
        Operation::Transfer { to_device_id, .. } if to_device_id.as_slice() != local_device_id.as_slice()
    );
    if claims.addressed_to != local_device_id.as_slice() || transfer_addressed_elsewhere {
        return Ok(PrepareDecision::NotAddressed);
    }
    // Owner question 9: no economic write set checks a bearer transfer offline,
    // so its token's committed policy is checked here, before anything else.
    if operation_requires_offline_bearer(operation) {
        bearer_token_moves(operation)?;
    }
    verify_pinned_peer_keys(sender, claims.credentials)?;
    verify_step_signature(sender, &commitment_hash, claims.signature, "proposal")?;

    // Before the tip: a device behind its peer is behind because a step of
    // its own is in flight, and that refusal is the one it keeps.
    if let Some(in_flight) = in_flight.filter(|held| *held != commitment_hash) {
        return Ok(PrepareDecision::StepInFlight { in_flight });
    }
    if claims.expected_tip != Some(held_tip) {
        let expected_recomputes = claims
            .expected_tip
            .map(|tip| BilateralPreCommitment::new(tip, operation.clone()))
            .transpose()?
            .is_some_and(|pre| pre.bilateral_commitment_hash == commitment_hash);
        return Ok(PrepareDecision::StaleTip {
            expected: claims.expected_tip,
            held: held_tip,
            expected_recomputes,
        });
    }
    let own = BilateralPreCommitment::new(held_tip, operation.clone())?.bilateral_commitment_hash;
    if own != commitment_hash {
        return Err(DsmError::invalid_operation(
            "the proposal's commitment is not its operation's commitment on this relationship",
        ));
    }
    Ok(PrepareDecision::Consider { commitment_hash })
}

/// The receiver's acceptance, as the proposer takes it from a verified
/// prepare response.
#[derive(Debug, PartialEq, Eq)]
pub struct Acceptance {
    /// σ_B over the step's commitment and `receiver_challenge`.
    pub signature: Vec<u8>,
    /// The receiver's challenge `r_R` a bearer release answers, as σ_B
    /// signs it.
    pub receiver_challenge: [u8; 32],
}

/// What a prepare response claims: the commitment it answers, its
/// receiver's keys, its receiver's signature (σ_B) over that commitment and
/// its challenge, and the challenge.
#[derive(Clone, Copy, Debug)]
pub struct ResponseClaims<'a> {
    pub commitment_hash: Option<[u8; 32]>,
    pub credentials: PeerCredentials<'a>,
    pub signature: &'a [u8],
    pub receiver_challenge: &'a [u8],
}

/// The proposer's decision on a prepare response for the step
/// `commitment_hash` it proposed to `receiver`: the response carries the
/// receiver's pinned keys and its signature over that commitment and the
/// challenge it issues ([`bilateral_accept_sign_message`]). Nothing in a
/// response is taken before it verifies: a challenge the receiver did not
/// sign is refused, so the proposer never stages a release toward it.
pub fn decide_prepare_response(
    commitment_hash: [u8; 32],
    claims: ResponseClaims<'_>,
    receiver: &PinnedPeer<'_>,
) -> Result<Acceptance, DsmError> {
    if claims.commitment_hash != Some(commitment_hash) {
        return Err(DsmError::invalid_operation(
            "the response names another commitment",
        ));
    }
    verify_pinned_peer_keys(receiver, claims.credentials)?;
    let receiver_challenge = <[u8; 32]>::try_from(claims.receiver_challenge).map_err(|e| {
        DsmError::invalid_operation(format!("the receiver challenge is not 32 bytes: {e}"))
    })?;
    verify_signature_over(
        receiver,
        &bilateral_accept_sign_message(&commitment_hash, &receiver_challenge),
        claims.signature,
        "acceptance",
    )?;
    Ok(Acceptance {
        signature: claims.signature.to_vec(),
        receiver_challenge,
    })
}

/// The largest stitched receipt a confirm may carry (§11.1 strict-fail).
pub const MAX_STITCHED_RECEIPT_BYTES: usize = 131_072;

/// What a confirm claims: its sender's σ_A over the commitment, the step's
/// stitched receipt, the entropy the sender derived the step with, and the
/// successor tip h_{n+1} it computed.
#[derive(Clone, Copy, Debug)]
pub struct ConfirmClaims<'a> {
    pub signature: &'a [u8],
    pub receipt: &'a [u8],
    pub pre_entropy: &'a [u8],
    pub successor_tip: Option<[u8; 32]>,
}

/// What the receiver holds for a step it accepted.
#[derive(Clone, Debug)]
pub struct AcceptedStep<'a> {
    pub commitment_hash: [u8; 32],
    pub operation: &'a Operation,
    /// The relationship tip h_n this device holds durably.
    pub held_tip: [u8; 32],
    pub receiver_device_id: [u8; 32],
    /// The Device Tree commitment `R_G` kept for the sender.
    pub sender_device_tree_root: [u8; 32],
    /// The sender's EK chain head on this relationship, once a step has been
    /// received; before that, its pinned AK signs the first EK.
    pub sender_chain_head: Option<&'a [u8]>,
    /// The sender's anchor-state leaves as this device derived them from the
    /// step's release under the sender's pinned bundle. Every step the
    /// offline door admits is an offline-bearer transfer ([`offline_door`]),
    /// so a confirm carries them, always.
    pub bearer: BearerLeaves,
    /// Where this device holds the sender's offline account from
    /// ([`BearerOrigin`]).
    pub bearer_origin: &'a BearerOrigin<'a>,
}

/// What a receiver holds of a sender's offline account, independently of the
/// confirm, and what the confirm carries to bring it forward.
#[derive(Clone, Debug)]
pub struct BearerOrigin<'a> {
    /// The sender's offline account under the release's bundle as this device
    /// last validated it from the sender's online history
    /// (`economic_lineage::latest_offline_account`); `None` when this device
    /// has validated none of it — a real state (it has not walked the
    /// sender's load), and Core refuses the spend for it.
    pub recorded: Option<crate::economic::peer_lineage::PeerOfflineAccount>,
    /// The sender's anchor: its bundle and the keys it commits, as this device
    /// pins it, or admits it from a disclosure whose bundle recomputes.
    pub anchor: crate::types::offline_chain::ChainAnchor,
    /// The sender's spends since the recorded account, as the confirm carries
    /// them (SA-116).
    pub chain: &'a [crate::types::offline_chain::SpendHop],
    /// Where this device last accepted a spend from the sender to leave its
    /// account — the frontier and the counter — if it ever has.
    pub accepted: Option<([u8; 32], u64)>,
}

/// A confirm the receiver may commit. Only [`decide_confirm`] makes one,
/// so holding one is proof that its receipt verified: what needs that
/// proof takes this type, not a receipt or roots its caller supplies.
#[derive(Debug)]
pub struct VerifiedConfirm {
    receipt: StitchedReceiptV2,
    successor_tip: [u8; 32],
    bearer: BearerLeaves,
    bearer_start: crate::types::offline_chain::AccountPoint,
}

impl VerifiedConfirm {
    /// The sender's stitched receipt of the step, verified.
    pub fn receipt(&self) -> &StitchedReceiptV2 {
        &self.receipt
    }

    /// The relationship's successor tip h_{n+1}, reproduced from the held
    /// tip, the operation and the entropy the signed receipt commits.
    pub fn successor_tip(&self) -> [u8; 32] {
        self.successor_tip
    }

    /// The sender's anchor-state leaves the verified receipt proves its step
    /// moved, before and after.
    pub fn bearer(&self) -> &BearerLeaves {
        &self.bearer
    }

    /// For an offline-bearer step, the account its spend starts from as this
    /// device established it: its recorded account carried forward by the
    /// sender's verified chain of spends, at the counter and frontier the
    /// release starts from.
    pub fn bearer_start(&self) -> &crate::types::offline_chain::AccountPoint {
        &self.bearer_start
    }
}

/// The owner's receive rule (2026-10-22): an offline-bearer spend is taken
/// only from the offline account its receiver validated itself, from the
/// sender's online history — carried forward, when the sender has paid offline
/// since, by the sender's chain of spends (SA-116).
///
/// The recorded account must be the sender's, under the spend's bundle, and
/// the anchor the chain is verified under must be that bundle's. The chain is
/// verified hop by hop from the recorded account
/// ([`crate::types::offline_chain::verify_spend_chain`]); the receipt's
/// offline-account write names the account the spend started from (its
/// pre-root, which `verify_receipt_state` folds under the sender's device
/// root), and that must be the account the chain leaves, at the counter and
/// frontier the release starts from. A spend from another sender's or another
/// bundle's account, or from any other state of this one, is refused.
///
/// Forward only: once this device accepted a spend from the sender, the next
/// one must pass through the point that spend left the account at — unless
/// the recorded account is newer, validated online since. A spend that starts
/// before it, or beside it, is refused.
///
/// Answers the account the spend starts from.
pub fn spend_starts_at_the_record(
    receipt: &StitchedReceiptV2,
    leaves: &BearerLeaves,
    sender_genesis: &[u8; 32],
    origin: &BearerOrigin<'_>,
) -> Result<crate::types::offline_chain::AccountPoint, DsmError> {
    use crate::types::offline_chain::{chain_end, verify_spend_chain, AccountPoint};
    let recorded = origin.recorded.as_ref().ok_or_else(|| {
        DsmError::invalid_operation(
            "offline-bearer confirm: this device has validated none of the sender's offline \
             account online, so no offline payment from it is taken",
        )
    })?;
    if recorded.device_id() != &receipt.devid_a
        || recorded.genesis() != sender_genesis
        || recorded.bundle() != &leaves.bundle
        || origin.anchor.bundle != leaves.bundle
    {
        return Err(DsmError::invalid_operation(
            "offline-bearer spend: the recorded offline account is not the sender's under this \
             spend's anchor bundle",
        ));
    }
    let payments = verify_spend_chain(recorded.account_root(), &origin.anchor, origin.chain)?;
    let carried = chain_end(recorded.account_root(), &payments);
    let started_from = receipt
        .step_writes
        .iter()
        .find_map(|write| match &write.leaf {
            ReceiptLeaf::OfflineAccount(witness) => Some(witness.pre_account_root),
            ReceiptLeaf::Relationship => None,
        })
        .ok_or_else(|| {
            DsmError::invalid_operation(
                "offline-bearer spend: the receipt writes no offline account",
            )
        })?;
    if started_from != carried {
        return Err(DsmError::invalid_operation(
            "offline-bearer spend: it does not start from the offline account this device \
             validated online for the sender, carried forward by the sender's chain of spends",
        ));
    }
    if let Some((frontier, counter)) = origin.accepted {
        let recorded_counter = match payments.first() {
            Some(first) => first.before.counter,
            None => leaves.counter,
        };
        let passes_through = payments
            .iter()
            .map(|p| (p.before.counter, p.before.frontier))
            .chain([(leaves.counter, leaves.frontier)])
            .any(|point| point == (counter, frontier));
        if counter >= recorded_counter && !passes_through {
            return Err(DsmError::invalid_operation(
                "offline-bearer spend: it does not extend the spend this device last accepted \
                 from the sender",
            ));
        }
    }
    Ok(AccountPoint {
        root: carried,
        counter: leaves.counter,
        frontier: leaves.frontier,
    })
}

/// The receiver's decision on a confirm for a step it accepted: σ_A under
/// the sender's pinned AK; the stitched receipt from this sender to this
/// device, holding its state rules against the sender's Device Tree
/// commitment and its A-side EK chaining from the sender's chain head; and
/// the successor tip reproduced from the held tip, the operation and the
/// entropy the signed receipt commits. The confirm's own entropy is unsigned:
/// it is taken only when it is the receipt's. The receipt's tips are the
/// sender's own (per-device) lineage and are bound by its EK chain, never
/// compared with the relationship tip.
pub fn decide_confirm(
    claims: ConfirmClaims<'_>,
    step: AcceptedStep<'_>,
    sender: &PinnedPeer<'_>,
) -> Result<VerifiedConfirm, DsmError> {
    if claims.receipt.len() > MAX_STITCHED_RECEIPT_BYTES {
        return Err(DsmError::invalid_operation(format!(
            "stitched_receipt exceeds 128 KiB strict-fail limit (§11.1): {} bytes",
            claims.receipt.len()
        )));
    }
    verify_step_signature(sender, &step.commitment_hash, claims.signature, "confirm")?;
    if claims.receipt.is_empty() {
        return Err(DsmError::invalid_operation(
            "incoming bilateral confirm omits stitched_receipt; rejecting",
        ));
    }
    let receipt = StitchedReceiptV2::from_canonical_protobuf(claims.receipt).map_err(|e| {
        DsmError::invalid_operation(format!(
            "bilateral confirm: the stitched receipt does not decode: {e}"
        ))
    })?;
    if receipt.devid_a != sender.device_id || receipt.devid_b != step.receiver_device_id {
        return Err(DsmError::invalid_operation(
            "bilateral confirm: the receipt is not from this session's sender to this device",
        ));
    }
    verify_receipt_state(
        &receipt,
        &ReceiptStateContext {
            device_tree_commitment: &DeviceTreeAcceptanceCommitment::from_root(
                step.sender_device_tree_root,
            ),
            author_genesis: sender.genesis,
            operation: step.operation,
            bearer: Some(step.bearer),
        },
    )?;
    verify_per_step_ek_signing(
        &receipt,
        BilateralSide::A,
        per_step_ek_predecessor(step.sender_chain_head, sender.signing_key).key(),
        &receipt.parent_tip,
        &step.commitment_hash,
    )?;
    let bearer_start =
        spend_starts_at_the_record(&receipt, &step.bearer, &sender.genesis, step.bearer_origin)?;

    let pre_entropy = <[u8; 32]>::try_from(claims.pre_entropy).map_err(|_| {
        DsmError::invalid_operation("pre_entropy must be present and 32 bytes in confirm")
    })?;
    // The entropy rides the confirm unsigned; σ_A's EK signs the receipt,
    // whose canonical form commits the step's one entropy. A confirm whose
    // entropy is not that one would move this device to a successor tip its
    // sender never derived.
    if pre_entropy != receipt.transition_entropy {
        return Err(DsmError::invalid_operation(
            "the confirm's pre_entropy is not the transition entropy its signed receipt commits",
        ));
    }
    let successor_tip = claims
        .successor_tip
        .ok_or_else(|| DsmError::invalid_operation("missing shared_chain_tip_new in confirm"))?;
    let op_bytes = step.operation.to_bytes();
    let sigma = compute_precommit(&step.held_tip, &op_bytes, &pre_entropy)?;
    if compute_successor_tip(&step.held_tip, &op_bytes, &pre_entropy, &sigma) != successor_tip {
        return Err(DsmError::invalid_operation(
            "h_{n+1} mismatch: pre_entropy cannot reproduce shared_chain_tip_new (§4.1)",
        ));
    }
    Ok(VerifiedConfirm {
        receipt,
        successor_tip,
        bearer: step.bearer,
        bearer_start,
    })
}

/// The receiver's decision on a confirm for a step it has already committed
/// (its session ended in that commit): the confirm is delivered again because
/// its ack was lost, and the ack the step committed is the answer again — only
/// for a confirm the step's pinned sender signed over the step's commitment.
pub fn decide_committed_confirm(
    signature: &[u8],
    commitment_hash: &[u8; 32],
    sender: &PinnedPeer<'_>,
) -> Result<(), DsmError> {
    verify_step_signature(sender, commitment_hash, signature, "confirm")
}

/// What the sender holds for a step it confirmed and awaits the ack of.
#[derive(Clone, Copy, Debug)]
pub struct ConfirmedStep<'a> {
    pub commitment_hash: [u8; 32],
    pub sender_device_id: [u8; 32],
    /// The Device Tree commitment `R_G` kept for the receiver.
    pub receiver_device_tree_root: [u8; 32],
    /// The receiver's EK chain head on this relationship, once a step has
    /// been acknowledged; before that, its pinned AK signs the first EK.
    pub receiver_chain_head: Option<&'a [u8]>,
    /// The step's operation: the receiver's own receipt of it writes only its
    /// relationship leaf, and its child tip is recomputed from it.
    pub operation: &'a Operation,
}

/// The sender's decision on an acknowledgment: it is the receiver's
/// counter-signed receipt of the step — its own copy, from the receiver to
/// this device, holding its state rules against the receiver's Device Tree
/// commitment, and answering the step's commitment with the receiver's
/// B-side EK chained from its head. Nothing else in an ack is authority.
pub fn decide_commit_ack(
    named_commitment: Option<[u8; 32]>,
    counter_signed_receipt: &[u8],
    step: ConfirmedStep<'_>,
    receiver: &PinnedPeer<'_>,
) -> Result<StitchedReceiptV2, DsmError> {
    if named_commitment != Some(step.commitment_hash) {
        return Err(DsmError::invalid_operation(
            "the acknowledgment names another commitment",
        ));
    }
    if counter_signed_receipt.is_empty() {
        return Err(DsmError::invalid_operation(
            "BilateralCommitResponse omits counter_signed_receipt; rejecting",
        ));
    }
    if counter_signed_receipt.len() > MAX_STITCHED_RECEIPT_BYTES {
        return Err(DsmError::invalid_operation(format!(
            "counter_signed_receipt exceeds 128 KiB strict-fail limit (§11.1): {} bytes",
            counter_signed_receipt.len()
        )));
    }
    let receipt =
        StitchedReceiptV2::from_canonical_protobuf(counter_signed_receipt).map_err(|e| {
            DsmError::invalid_operation(format!(
                "sender per-step EK verify: failed to decode counter_signed_receipt: {e}"
            ))
        })?;
    if receipt.devid_a != receiver.device_id || receipt.devid_b != step.sender_device_id {
        return Err(DsmError::invalid_operation(
            "counter_signed_receipt: not the receiver's receipt of a step toward this device — \
             possible substitution",
        ));
    }
    verify_receipt_state(
        &receipt,
        &ReceiptStateContext {
            device_tree_commitment: &DeviceTreeAcceptanceCommitment::from_root(
                step.receiver_device_tree_root,
            ),
            author_genesis: receiver.genesis,
            operation: step.operation,
            bearer: None,
        },
    )?;
    verify_per_step_ek_signing(
        &receipt,
        BilateralSide::B,
        per_step_ek_predecessor(step.receiver_chain_head, receiver.signing_key).key(),
        &receipt.parent_tip,
        &step.commitment_hash,
    )?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bilateral::identity_binding::binding_digest;
    use crate::types::operations::TransactionMode;
    use crate::types::step_fixture::{credit_step, transfer_step, Party, Step};
    use crate::types::token_types::Balance;

    /// A peer: the identity a wallet derives from its seed, and the binding
    /// of its ML-KEM key its AK signs.
    struct Peer {
        party: Party,
        device_id: [u8; 32],
        genesis: [u8; 32],
        kyber_public_key: Vec<u8>,
        binding_sig: Vec<u8>,
    }

    impl Peer {
        /// The peer a wallet with seed `[seed; 32]` is.
        fn new(seed: u8) -> Self {
            let party = Party::from_seed(&[seed; 32]);
            let (device_id, genesis) = (party.device_id(), party.genesis());
            let kyber_public_key = party.kyber_public_key().to_vec();
            let binding_sig = crate::crypto::sphincs::sphincs_sign(
                party.signing_secret_key(),
                &binding_digest(&device_id, &genesis, &kyber_public_key),
            )
            .expect("binding");
            Self {
                party,
                device_id,
                genesis,
                kyber_public_key,
                binding_sig,
            }
        }

        /// The AK's public half.
        fn public_key(&self) -> &[u8] {
            self.party.signing_public_key()
        }

        /// The AK's signature over `message`.
        fn sign(&self, message: &[u8]) -> Vec<u8> {
            crate::crypto::sphincs::sphincs_sign(self.party.signing_secret_key(), message)
                .expect("sign")
        }

        fn pinned(&self) -> PinnedPeer<'_> {
            PinnedPeer {
                device_id: self.device_id,
                genesis: self.genesis,
                signing_key: self.public_key(),
                kyber_public_key: &self.kyber_public_key,
            }
        }

        fn sign_step(&self, commitment_hash: &[u8; 32]) -> Vec<u8> {
            self.sign(&bilateral_sign_message(commitment_hash))
        }

        fn sign_acceptance(&self, commitment_hash: &[u8; 32], challenge: &[u8; 32]) -> Vec<u8> {
            self.sign(&bilateral_accept_sign_message(commitment_hash, challenge))
        }
    }

    fn refused<T: std::fmt::Debug>(r: Result<T, DsmError>, why: &str) {
        let e = r.expect_err(why).to_string();
        assert!(e.contains(why), "refused for another reason: {e}");
    }

    /// The keys a peer sends are refused unless they are the keys its contact
    /// pins: the AK equal, the Kyber key equal, and its binding verifying
    /// under the pinned AK. Every refusal says why.
    #[test]
    fn a_peer_is_held_to_the_keys_its_contact_pins() {
        let peer = Peer::new(0x7C);
        let other = Peer::new(0x7D);
        let pinned = peer.pinned();
        let check = |ak: &[u8], kyber_pk: &[u8], sig: &[u8]| {
            verify_pinned_peer_keys(
                &pinned,
                PeerCredentials {
                    signing_key: ak,
                    kyber_public_key: kyber_pk,
                    kyber_binding_sig: sig,
                },
            )
        };

        check(peer.public_key(), &peer.kyber_public_key, &peer.binding_sig)
            .expect("the pinned keys and their binding");
        refused(
            check(
                other.public_key(),
                &peer.kyber_public_key,
                &peer.binding_sig,
            ),
            "not the contact's pinned AK",
        );
        refused(
            check(&[], &peer.kyber_public_key, &peer.binding_sig),
            "not the contact's pinned AK",
        );
        refused(
            check(
                peer.public_key(),
                &other.kyber_public_key,
                &peer.binding_sig,
            ),
            "not the contact's pinned Kyber key",
        );
        refused(
            check(peer.public_key(), &[], &peer.binding_sig),
            "not the contact's pinned Kyber key",
        );
        refused(
            check(peer.public_key(), &peer.kyber_public_key, &[]),
            "does not verify under the pinned AK",
        );
        let wrong_signer = other.sign(&binding_digest(
            &peer.device_id,
            &peer.genesis,
            &peer.kyber_public_key,
        ));
        refused(
            check(peer.public_key(), &peer.kyber_public_key, &wrong_signer),
            "does not verify under the pinned AK",
        );
    }

    /// A bearer transfer to `to` of a token whose committed policy lets it
    /// move.
    fn bearer_transfer(to: [u8; 32]) -> Operation {
        bearer_transfer_of(
            to,
            crate::sofi::validation::fixtures::committed(
                crate::sofi::validation::fixtures::token_policy_bytes_with(
                    0x0F,
                    crate::economic::token_policy::POLICY_FLAG_TRANSFERABLE,
                ),
            ),
        )
    }

    /// A bearer transfer to `to` of the token `(policy_commit, token_policy)`.
    fn bearer_transfer_of(
        to: [u8; 32],
        (policy_commit, token_policy): ([u8; 32], Vec<u8>),
    ) -> Operation {
        Operation::Transfer {
            policy_commit,
            token_policy,
            terms_commitment: crate::types::operations::TransferTerms {
                token_id: b"TOK".to_vec(),
                nonce: vec![1; 8],
                mode: TransactionMode::Bilateral,
                memo: String::new(),
                salt: vec![0x5A; 32],
            }
            .commitment(),
            to_device_id: to.to_vec(),
            amount: Balance::amount(3),
            signature: Vec::new(),
            authority_policy: Some(crate::types::operations::canonical_offline_bearer_policy()),
        }
    }

    /// A step that moves no value, marked so two of them on one tip differ.
    fn step(mark: u8) -> Operation {
        Operation::Generic {
            operation_type: b"offline-step-test".to_vec(),
            data: vec![mark],
            message: String::new(),
            signature: Vec::new(),
        }
    }

    fn credentials(peer: &Peer) -> PeerCredentials<'_> {
        PeerCredentials {
            signing_key: peer.public_key(),
            kyber_public_key: &peer.kyber_public_key,
            kyber_binding_sig: &peer.binding_sig,
        }
    }

    /// The receiver considers only a proposal its pinned sender signed, whose
    /// commitment it recomputes from the operation on the tip it holds; a
    /// proposal on another tip is answered as stale. MUTATION CONTROLS:
    /// dropping the signature check, or the commitment recompute, lets a
    /// refused proposal be considered and turns this red.
    #[test]
    fn a_proposal_is_considered_only_as_its_sender_signed_it_on_the_held_tip() {
        let sender = Peer::new(0x41);
        let other = Peer::new(0x42);
        let receiver = [0x43u8; 32];
        let held = [0x70u8; 32];
        let operation = step(0x01);
        let commitment = BilateralPreCommitment::new(held, operation.clone())
            .expect("the step's precommitment")
            .bilateral_commitment_hash;
        let decide = |commitment: [u8; 32], expected_tip: Option<[u8; 32]>, signature: &[u8]| {
            decide_prepare(
                commitment,
                &operation,
                PrepareClaims {
                    addressed_to: &receiver,
                    expected_tip,
                    credentials: credentials(&sender),
                    signature,
                },
                &sender.pinned(),
                &receiver,
                held,
                None,
            )
        };

        match decide(commitment, Some(held), &sender.sign_step(&commitment))
            .expect("the sender's own proposal on the held tip")
        {
            PrepareDecision::Consider {
                commitment_hash, ..
            } => assert_eq!(commitment_hash, commitment),
            other => panic!("expected Consider, got {other:?}"),
        }

        refused(decide(commitment, Some(held), &[]), "carries no signature");
        refused(
            decide(commitment, Some(held), &other.sign_step(&commitment)),
            "not signed over its commitment by the pinned AK",
        );

        // A commitment the sender signed that is not its operation's
        // commitment on the held tip: the receiver never signs it.
        let foreign = BilateralPreCommitment::new(held, step(0x02))
            .expect("the foreign step's precommitment")
            .bilateral_commitment_hash;
        refused(
            decide(foreign, Some(held), &sender.sign_step(&foreign)),
            "not its operation's commitment on this relationship",
        );

        for expected in [None, Some([0x71u8; 32])] {
            match decide(commitment, expected, &sender.sign_step(&commitment))
                .expect("an authenticated proposal on another tip is answered")
            {
                PrepareDecision::StaleTip {
                    expected: e,
                    held: h,
                    expected_recomputes,
                } => {
                    assert_eq!((e, h), (expected, held));
                    // The commitment was made on the held tip, not the one claimed.
                    assert!(!expected_recomputes);
                }
                other => panic!("expected StaleTip, got {other:?}"),
            }
        }
    }

    /// The relationship takes one step at a time at the receiver's door: an
    /// authenticated proposal is refused while this device holds another step
    /// in flight — even one that would be stale, since the device is behind
    /// because of that step — and the step in flight is not refused as its own
    /// neighbour. An unauthenticated proposal is refused before any of it.
    /// MUTATION CONTROL: dropping the in-flight arm lets the proposal be
    /// considered and turns this red.
    #[test]
    fn a_proposal_is_refused_while_another_step_is_in_flight() {
        let sender = Peer::new(0x46);
        let receiver = [0x47u8; 32];
        let held = [0x72u8; 32];
        let operation = step(0x03);
        let commitment = BilateralPreCommitment::new(held, operation.clone())
            .expect("the step's precommitment")
            .bilateral_commitment_hash;
        let own_step = [0x73u8; 32];
        let decide = |expected_tip: Option<[u8; 32]>, signature: &[u8], in_flight| {
            decide_prepare(
                commitment,
                &operation,
                PrepareClaims {
                    addressed_to: &receiver,
                    expected_tip,
                    credentials: credentials(&sender),
                    signature,
                },
                &sender.pinned(),
                &receiver,
                held,
                in_flight,
            )
        };
        let signature = sender.sign_step(&commitment);

        for expected_tip in [Some(held), Some([0x74u8; 32])] {
            match decide(expected_tip, &signature, Some(own_step))
                .expect("an authenticated proposal is answered")
            {
                PrepareDecision::StepInFlight { in_flight } => assert_eq!(in_flight, own_step),
                other => panic!("expected StepInFlight, got {other:?}"),
            }
        }
        match decide(Some(held), &signature, Some(commitment))
            .expect("the step in flight is this proposal")
        {
            PrepareDecision::Consider { commitment_hash } => {
                assert_eq!(commitment_hash, commitment)
            }
            other => panic!("expected Consider, got {other:?}"),
        }
        refused(
            decide(Some(held), &[], Some(own_step)),
            "carries no signature",
        );
    }

    /// A prepare addressed to another device is meaningless bytes to this
    /// one: it is not addressed here whether the request names another device
    /// or the transfer it commits pays another, and that is decided before
    /// the signature, the step in flight or the tip — so nothing is answered
    /// and nothing held is consulted. MUTATION CONTROL: dropping either
    /// address check lets a misaddressed prepare reach the step and tip
    /// checks and turns this red.
    #[test]
    fn a_prepare_addressed_to_another_device_is_not_addressed_here() {
        let sender = Peer::new(0x48);
        let receiver = [0x49u8; 32];
        let third = [0x4Au8; 32];
        let held = [0x75u8; 32];
        let decide = |operation: &Operation, addressed_to: &[u8], in_flight| {
            let commitment =
                BilateralPreCommitment::new(held, operation.clone())?.bilateral_commitment_hash;
            decide_prepare(
                commitment,
                operation,
                PrepareClaims {
                    addressed_to,
                    expected_tip: Some([0x76u8; 32]),
                    credentials: credentials(&sender),
                    signature: &[],
                },
                &sender.pinned(),
                &receiver,
                held,
                in_flight,
            )
        };

        // The request names a third device.
        match decide(&bearer_transfer(receiver), &third, Some([0x77u8; 32]))
            .expect("a misaddressed prepare is decided, not refused")
        {
            PrepareDecision::NotAddressed => {}
            other => panic!("expected NotAddressed, got {other:?}"),
        }
        // The request names this device, but the transfer it commits pays a third.
        match decide(&bearer_transfer(third), &receiver, None)
            .expect("a misaddressed transfer is decided, not refused")
        {
            PrepareDecision::NotAddressed => {}
            other => panic!("expected NotAddressed, got {other:?}"),
        }
        // Addressed here, an unsigned prepare reaches the signature check.
        refused(decide(&step(0x04), &receiver, None), "carries no signature");
    }

    /// SA-61, opened in phase 4: the allocation a bearer transfer spends is
    /// proven at the confirm, from the account the receiver recorded
    /// (`spend_starts_at_the_record`), so its prepare is decided as any step's
    /// is — put to the user when its pinned sender signed it on the held tip,
    /// refused unsigned, and answered as in flight while another step is.
    #[test]
    fn a_bearer_transfer_addressed_here_is_decided_as_any_step() {
        let sender = Peer::new(0x4D);
        let receiver = [0x4Eu8; 32];
        let held = [0x7Bu8; 32];
        let operation = bearer_transfer(receiver);
        let commitment = BilateralPreCommitment::new(held, operation.clone())
            .expect("the bearer transfer's precommitment")
            .bilateral_commitment_hash;
        let decide = |signature: &[u8], in_flight| {
            decide_prepare(
                commitment,
                &operation,
                PrepareClaims {
                    addressed_to: &receiver,
                    expected_tip: Some(held),
                    credentials: credentials(&sender),
                    signature,
                },
                &sender.pinned(),
                &receiver,
                held,
                in_flight,
            )
        };
        match decide(&sender.sign_step(&commitment), None)
            .expect("a signed bearer transfer on the held tip is decided")
        {
            PrepareDecision::Consider { commitment_hash } => {
                assert_eq!(commitment_hash, commitment, "the proposal put to the user")
            }
            other => panic!("expected Consider, got {other:?}"),
        }
        refused(decide(&[], None), "carries no signature");
        match decide(&sender.sign_step(&commitment), Some([0x7Cu8; 32]))
            .expect("a bearer transfer while another step is in flight is decided")
        {
            PrepareDecision::StepInFlight { in_flight } => assert_eq!(in_flight, [0x7Cu8; 32]),
            other => panic!("expected StepInFlight, got {other:?}"),
        }
    }

    /// Owner question 9, offline: the receiver's Core refuses, at the
    /// prepare and before anything is verified or written, a bearer transfer
    /// of a token whose committed policy does not let it move, or whose
    /// carried policy bytes are not the token's.
    /// MUTATION CONTROL: dropping `bearer_token_moves` from `decide_prepare`
    /// lets both proposals on to the next refusal and turns this red.
    #[test]
    fn a_bearer_transfer_of_a_token_that_may_not_move_is_refused_at_its_receivers_prepare() {
        use crate::sofi::validation::fixtures::{committed, token_policy_bytes_with};
        let sender = Peer::new(0x4F);
        let receiver = [0x50u8; 32];
        let held = [0x7Bu8; 32];
        let locked = committed(token_policy_bytes_with(0x10, 0));
        let (moving, _) = committed(token_policy_bytes_with(
            0x11,
            crate::economic::token_policy::POLICY_FLAG_TRANSFERABLE,
        ));
        let not_its_own = (moving, locked.1.clone());
        for (operation, reason) in [
            (bearer_transfer_of(receiver, locked), "non-transferable"),
            (
                bearer_transfer_of(receiver, not_its_own),
                "are not the committed policy",
            ),
        ] {
            let commitment = BilateralPreCommitment::new(held, operation.clone())
                .expect("the step's precommitment")
                .bilateral_commitment_hash;
            refused(
                decide_prepare(
                    commitment,
                    &operation,
                    PrepareClaims {
                        addressed_to: &receiver,
                        expected_tip: Some(held),
                        credentials: credentials(&sender),
                        signature: &sender.sign_step(&commitment),
                    },
                    &sender.pinned(),
                    &receiver,
                    held,
                    None,
                ),
                reason,
            );
        }
    }

    /// A stale proposal's claimed tip is evidence of the sender's tip only
    /// when the proposal's commitment is its operation's commitment on that
    /// claimed tip.
    #[test]
    fn a_stale_proposal_says_whether_its_claimed_tip_recomputes() {
        let sender = Peer::new(0x4B);
        let receiver = [0x4Cu8; 32];
        let held = [0x78u8; 32];
        let claimed = [0x79u8; 32];
        let operation = step(0x05);
        let on_claimed = BilateralPreCommitment::new(claimed, operation.clone())
            .expect("the step's precommitment on the claimed tip")
            .bilateral_commitment_hash;
        let decide = |commitment: [u8; 32]| {
            decide_prepare(
                commitment,
                &operation,
                PrepareClaims {
                    addressed_to: &receiver,
                    expected_tip: Some(claimed),
                    credentials: credentials(&sender),
                    signature: &sender.sign_step(&commitment),
                },
                &sender.pinned(),
                &receiver,
                held,
                None,
            )
        };

        match decide(on_claimed).expect("an authenticated stale proposal is answered") {
            PrepareDecision::StaleTip {
                expected_recomputes,
                ..
            } => assert!(expected_recomputes),
            other => panic!("expected StaleTip, got {other:?}"),
        }
        let unrelated = [0x7Au8; 32];
        match decide(unrelated).expect("an authenticated stale proposal is answered") {
            PrepareDecision::StaleTip {
                expected_recomputes,
                ..
            } => assert!(!expected_recomputes),
            other => panic!("expected StaleTip, got {other:?}"),
        }
    }

    /// Offline, only the bearer tier moves value: an online-tier transfer is
    /// refused at the door.
    #[test]
    fn an_online_tier_transfer_is_not_an_offline_operation() {
        refused(
            offline_operation(&online_tier_transfer().to_bytes()),
            "offline-bearer transfers only",
        );
        offline_operation(&bearer_transfer([0x45; 32]).to_bytes()).expect("a bearer transfer");
        refused(
            offline_operation(&[0xFF, 0x00]),
            "invalid operation payload",
        );
    }

    /// A bearer transfer with its authority policy taken off: the online tier.
    fn online_tier_transfer() -> Operation {
        let mut online = bearer_transfer([0x45; 32]);
        if let Operation::Transfer {
            authority_policy, ..
        } = &mut online
        {
            *authority_policy = None;
        }
        online
    }

    /// One operation of every variant, each by its class at the offline door.
    fn one_of_every_variant() -> Vec<(Operation, &'static str)> {
        use crate::types::operations::TransactionMode::{Bilateral, Unilateral};
        let b = |v: u8, n: usize| vec![v; n];
        let id = |v: u8| [v; 32];
        let amount = Balance::amount;
        const NONE: &str = "a step that moves no value";
        const TOKEN: &str = "a token operation";
        const IDENTITY: &str = "an identity or relationship operation";
        const VAULT: &str = "a vault operation";
        const SOFI: &str = "a SoFi operation";
        vec![
            (bearer_transfer([0x45; 32]), "admitted"),
            (online_tier_transfer(), "an online-tier transfer"),
            (Operation::Noop, NONE),
            (
                Operation::Generic {
                    operation_type: b(0x01, 4),
                    data: b(0x02, 5),
                    message: "generic".into(),
                    signature: b(0x03, 32),
                },
                NONE,
            ),
            (Operation::Genesis, IDENTITY),
            (
                Operation::Create {
                    message: "create".into(),
                    identity_data: b(0x01, 3),
                    public_key: b(0x02, 3),
                    metadata: b(0x03, 2),
                    commitment: b(0x04, 1),
                    proof: b(0x05, 2),
                    mode: Bilateral,
                },
                IDENTITY,
            ),
            (
                Operation::Update {
                    message: "update".into(),
                    identity_id: b(0xAA, 16),
                    updated_data: b(0xBB, 8),
                    proof: b(0xCC, 4),
                    forward_link: Some(b(0xDD, 32)),
                },
                IDENTITY,
            ),
            (
                Operation::AddRelationship {
                    from_id: id(0x01),
                    to_id: id(0x02),
                    relationship_type: b(0x03, 4),
                    metadata: b(0x04, 4),
                    proof: b(0x05, 64),
                    mode: Bilateral,
                    message: "add".into(),
                },
                IDENTITY,
            ),
            (
                Operation::CreateRelationship {
                    message: "create".into(),
                    counterparty_id: b(0x01, 32),
                    commitment: b(0x02, 16),
                    proof: b(0x03, 64),
                    mode: Unilateral,
                },
                IDENTITY,
            ),
            (
                Operation::RemoveRelationship {
                    from_id: id(0x0A),
                    to_id: id(0x0B),
                    relationship_type: b(0x0C, 4),
                    proof: b(0x0D, 64),
                    mode: Bilateral,
                    message: "remove".into(),
                },
                IDENTITY,
            ),
            (
                Operation::Recovery {
                    message: "recover".into(),
                    state_number: 42,
                    state_hash: b(0x11, 32),
                    state_entropy: b(0x22, 32),
                    invalidation_data: b(0x33, 16),
                    new_state_data: b(0x44, 64),
                    new_state_number: 43,
                    new_state_hash: b(0x55, 32),
                    new_state_entropy: b(0x66, 32),
                    compromise_proof: b(0x77, 128),
                    authority_sigs: vec![b(0x88, 64)],
                },
                IDENTITY,
            ),
            (
                Operation::Delete {
                    reason: "expired".into(),
                    proof: b(0xAA, 64),
                    mode: Unilateral,
                    id: b(0xBB, 16),
                },
                IDENTITY,
            ),
            (
                Operation::Link {
                    target_id: b(0x01, 32),
                    link_type: b(0x02, 7),
                    proof: b(0x03, 64),
                    mode: Bilateral,
                },
                IDENTITY,
            ),
            (
                Operation::Unlink {
                    target_id: b(0x01, 32),
                    proof: b(0x02, 64),
                    mode: Unilateral,
                },
                IDENTITY,
            ),
            (
                Operation::Invalidate {
                    reason: "clone".into(),
                    proof: b(0xDE, 64),
                    mode: Bilateral,
                },
                IDENTITY,
            ),
            (
                Operation::FaucetClaim {
                    reserve_id: id(0x52),
                    generation: 7,
                },
                TOKEN,
            ),
            (
                Operation::AdoptToken {
                    policy_commit: id(0x5A),
                    signature: b(0xCD, 64),
                },
                TOKEN,
            ),
            (
                Operation::CreateToken {
                    token_id: b(0x54, 3),
                    initial_supply: amount(21),
                    name: "Token".into(),
                    symbol: "TOK".into(),
                    decimals: 2,
                    metadata_uri: None,
                    policy_commit: id(0xAB),
                    fee_amount: 10,
                    signature: b(0xCD, 64),
                },
                TOKEN,
            ),
            (
                Operation::Burn {
                    amount: amount(200),
                    token_id: b(0x54, 3),
                    policy_commit: id(0xAC),
                    token_policy: b(0x0A, 40),
                    message: "burn".into(),
                },
                TOKEN,
            ),
            (
                Operation::LockToken {
                    token_id: b(0x54, 3),
                    amount: 500,
                    purpose: b(0x65, 6),
                    mode: Unilateral,
                    signature: b(0xDD, 32),
                },
                TOKEN,
            ),
            (
                Operation::UnlockToken {
                    token_id: b(0x54, 3),
                    amount: 250,
                    purpose: b(0x65, 6),
                    mode: Bilateral,
                    signature: b(0xEE, 32),
                },
                TOKEN,
            ),
            (
                Operation::Lock {
                    token_id: b(0x54, 3),
                    amount: amount(100),
                    purpose: b(0x63, 10),
                    owner: b(0x11, 32),
                    message: "lock".into(),
                    signature: b(0x22, 48),
                },
                TOKEN,
            ),
            (
                Operation::Unlock {
                    token_id: b(0x54, 3),
                    amount: amount(50),
                    purpose: b(0x63, 10),
                    owner: b(0x33, 32),
                    message: "unlock".into(),
                    signature: b(0x44, 48),
                },
                TOKEN,
            ),
            (
                Operation::Receive {
                    token_id: b(0x54, 3),
                    from_device_id: b(0x01, 32),
                    amount: amount(777),
                    recipient: b(0x02, 32),
                    message: "receive".into(),
                    mode: Bilateral,
                    nonce: b(0x03, 16),
                    sender_state_hash: None,
                },
                TOKEN,
            ),
            (
                Operation::DlvCreate {
                    vault_id: b(0x01, 32),
                    creator_public_key: b(0x02, 64),
                    parameters_hash: b(0x03, 32),
                    fulfillment_condition: b(0x04, 16),
                    intended_recipient: None,
                    signature: b(0x06, 48),
                    mode: Unilateral,
                },
                VAULT,
            ),
            (
                Operation::DlvUnlock {
                    vault_id: b(0x01, 32),
                    fulfillment_proof: b(0x02, 128),
                    requester_public_key: b(0x03, 64),
                    signature: b(0x04, 48),
                    mode: Unilateral,
                },
                VAULT,
            ),
            (
                Operation::DlvClaim {
                    vault_id: b(0x01, 32),
                    claim_proof: b(0x02, 64),
                    claimant_public_key: b(0x03, 64),
                    signature: b(0x04, 48),
                    mode: Bilateral,
                },
                VAULT,
            ),
            (
                Operation::DlvInvalidate {
                    vault_id: b(0x01, 32),
                    reason: "timeout".into(),
                    creator_public_key: b(0x02, 64),
                    signature: b(0x03, 48),
                    mode: Unilateral,
                },
                VAULT,
            ),
            (
                Operation::EscrowVaultCreate {
                    genesis_preimage: vec![0x5A, 0x01],
                    creation: vec![0x5B, 0x01],
                    terms: vec![0x01, 0x63, 0x01, 0x01],
                    funding_policies: vec![vec![0x40, 0x01]],
                    signature: b(0xA4, 64),
                },
                VAULT,
            ),
            (
                Operation::SofiSetup {
                    setup_body: vec![0x36, 0x01],
                    signature: b(0xA1, 64),
                },
                SOFI,
            ),
            (
                Operation::SofiVaultCreate {
                    genesis_preimage: vec![0x5A, 0x01],
                    creation: vec![0x5B, 0x01],
                    market_policy_preimage: vec![0x01, 0x07, 0x01, 0x01],
                    funding_a_policy_commit: id(0x5C),
                    funding_b_policy_commit: id(0x5D),
                    funding_policies: vec![vec![0x5C, 0x01], vec![0x5D, 0x01]],
                    signature: b(0xA2, 64),
                },
                SOFI,
            ),
            (
                Operation::SofiFulfill {
                    fulfillment_body: vec![0x39, 0x01],
                    precommit_id: b(0x11, 32),
                    signature: b(0xA3, 64),
                },
                SOFI,
            ),
        ]
    }

    /// MR-DSM-0219 (§6.105 C1): the offline door, from the bytes a proposal
    /// carries, admits the offline-bearer transfer and refuses every other
    /// variant by its class — SoFi and vault operations as online. Every
    /// variant has an operation here (the door's match has no wildcard, and
    /// this list is checked against the variant count).
    /// MUTATION CONTROL: a wildcard arm admitting what is not classified turns
    /// this red on the SoFi operations.
    #[test]
    fn the_offline_door_admits_the_bearer_transfer_and_refuses_every_other_variant() {
        // The variant an operation is. No wildcard: a variant added to
        // `Operation` does not compile here until it has an index, and then
        // fails this test until it has an operation in the list.
        fn index(op: &Operation) -> usize {
            match op {
                Operation::Genesis => 0,
                Operation::Create { .. } => 1,
                Operation::Update { .. } => 2,
                Operation::Transfer { .. } => 3,
                Operation::FaucetClaim { .. } => 4,
                Operation::AdoptToken { .. } => 5,
                Operation::Burn { .. } => 6,
                Operation::LockToken { .. } => 7,
                Operation::UnlockToken { .. } => 8,
                Operation::Lock { .. } => 9,
                Operation::Unlock { .. } => 10,
                Operation::AddRelationship { .. } => 11,
                Operation::CreateRelationship { .. } => 12,
                Operation::RemoveRelationship { .. } => 13,
                Operation::Recovery { .. } => 14,
                Operation::Delete { .. } => 15,
                Operation::Link { .. } => 16,
                Operation::Unlink { .. } => 17,
                Operation::Invalidate { .. } => 18,
                Operation::Generic { .. } => 19,
                Operation::Receive { .. } => 20,
                Operation::CreateToken { .. } => 21,
                Operation::Noop => 22,
                Operation::DlvCreate { .. } => 23,
                Operation::DlvUnlock { .. } => 24,
                Operation::DlvClaim { .. } => 25,
                Operation::SofiSetup { .. } => 26,
                Operation::SofiVaultCreate { .. } => 27,
                Operation::SofiFulfill { .. } => 28,
                Operation::EscrowVaultCreate { .. } => 29,
                Operation::DlvInvalidate { .. } => 30,
            }
        }
        const VARIANTS: usize = 31;
        let every = one_of_every_variant();
        let mut held = [0usize; VARIANTS];
        for (operation, _) in &every {
            held[index(operation)] += 1;
        }
        for (variant, count) in held.iter().enumerate() {
            assert_ne!(
                *count, 0,
                "operation variant {variant} has no operation here"
            );
        }
        for (operation, class) in every {
            let carried = offline_operation(&operation.to_bytes());
            match class {
                "admitted" => {
                    carried.expect("the offline-bearer transfer passes the door");
                }
                class => refused(carried, class),
            }
        }
    }

    /// The proposer takes an acceptance — its signature and its challenge —
    /// only from a response its pinned receiver signed over the proposed
    /// commitment. MUTATION CONTROL: dropping the signature check lets the
    /// forged responses through and turns this red.
    #[test]
    fn an_acceptance_is_taken_only_from_a_response_its_receiver_signed() {
        let receiver = Peer::new(0x51);
        let other = Peer::new(0x52);
        let commitment = [0x53u8; 32];
        let challenge = [0x54u8; 32];
        let decide = |named: [u8; 32], signature: &[u8], challenge: &[u8]| {
            decide_prepare_response(
                commitment,
                ResponseClaims {
                    commitment_hash: Some(named),
                    credentials: credentials(&receiver),
                    signature,
                    receiver_challenge: challenge,
                },
                &receiver.pinned(),
            )
        };

        let accepted = receiver.sign_acceptance(&commitment, &challenge);
        assert_eq!(
            decide(commitment, &accepted, &challenge).expect("the receiver's own acceptance"),
            Acceptance {
                signature: accepted.clone(),
                receiver_challenge: challenge,
            }
        );
        refused(decide(commitment, &[], &challenge), "carries no signature");
        refused(
            decide(
                commitment,
                &other.sign_acceptance(&commitment, &challenge),
                &challenge,
            ),
            "not signed over its commitment by the pinned AK",
        );
        refused(
            decide(
                [0x55; 32],
                &receiver.sign_acceptance(&[0x55; 32], &challenge),
                &challenge,
            ),
            "names another commitment",
        );
        refused(decide(commitment, &accepted, &[1, 2, 3]), "not 32 bytes");
        refused(decide(commitment, &accepted, &[]), "not 32 bytes");
    }

    /// SA-14. The challenge `r_R` a bearer release answers is under σ_B: a
    /// relay that replaces it in a genuine response is refused before the
    /// proposer stages anything toward it (and so before its anchor's COMMIT
    /// spends a counter step on a release the receiver will refuse). A σ_B
    /// over the commitment alone — what an acceptance signed before — no
    /// longer accepts.
    /// MUTATION CONTROL: verifying σ_B over the commitment alone (or not
    /// binding the challenge into the signed message) lets the substituted
    /// challenge through and turns this red.
    #[test]
    fn a_relayed_response_cannot_substitute_the_receivers_challenge() {
        let receiver = Peer::new(0x56);
        let commitment = [0x57u8; 32];
        let issued = [0x58u8; 32];
        let substituted = [0x59u8; 32];
        let decide = |signature: &[u8], challenge: &[u8]| {
            decide_prepare_response(
                commitment,
                ResponseClaims {
                    commitment_hash: Some(commitment),
                    credentials: credentials(&receiver),
                    signature,
                    receiver_challenge: challenge,
                },
                &receiver.pinned(),
            )
        };
        let sigma_b = receiver.sign_acceptance(&commitment, &issued);

        assert_eq!(
            decide(&sigma_b, &issued)
                .expect("the challenge the receiver signed")
                .receiver_challenge,
            issued
        );
        refused(
            decide(&sigma_b, &substituted),
            "not signed over its commitment by the pinned AK",
        );
        refused(
            decide(&receiver.sign_step(&commitment), &issued),
            "not signed over its commitment by the pinned AK",
        );
    }

    /// A confirm for a step, genuinely built: the sender's first transfer
    /// to the receiver from a real advance, its receipt answered on the A
    /// side by the sender's per-step EK certified by its AK over the
    /// session-bound target of the step's commitment on the tip the receiver
    /// holds, and the successor both derive from the sender's entropy.
    /// A sender's offline-bearer payment to a receiver, at the confirm: the
    /// sender's load and spend on its anchor, the spend's receipt answered by
    /// the sender's per-step EK, and the receiver's record of the account the
    /// load left.
    struct BuiltConfirm {
        sender: Peer,
        receiver: Peer,
        operation: Operation,
        bearer: BearerLeaves,
        recorded: crate::economic::peer_lineage::PeerOfflineAccount,
        anchor: crate::types::offline_chain::ChainAnchor,
        commitment_hash: [u8; 32],
        receipt: Vec<u8>,
        device_tree_root: [u8; 32],
        held_tip: [u8; 32],
        pre_entropy: [u8; 32],
        successor_tip: [u8; 32],
    }

    /// The step between `sender` and `receiver`: the sender's transfer and
    /// the receiver's credit of it, each with its receipt.
    fn steps(sender: &Peer, receiver: &Peer) -> (Step, Step) {
        let transfer = transfer_step(&sender.party, &receiver.party, 7);
        let credit = credit_step(&receiver.party, &sender.party, &transfer.operation);
        (transfer, credit)
    }

    /// The relationship tip `receiver` holds toward `sender` before their
    /// first step, and the step's commitment on it.
    fn held_tip_and_commitment(
        receiver: &Peer,
        sender: &Peer,
        operation: &Operation,
    ) -> ([u8; 32], [u8; 32]) {
        let held_tip = receiver
            .party
            .head()
            .establish_relationship(sender.device_id)
            .expect("the relationship is established")
            .chain_tip(
                &crate::core::bilateral_transaction_manager::compute_smt_key(
                    &receiver.device_id,
                    &sender.device_id,
                ),
            )
            .expect("the established relationship has a tip");
        let commitment = BilateralPreCommitment::new(held_tip, operation.clone())
            .expect("the step's precommitment on the held tip")
            .bilateral_commitment_hash;
        (held_tip, commitment)
    }

    /// `author`'s `receipt` toward `toward`, of the step precommitted as
    /// `c_pre`, answered on `side` by
    /// the author's per-step EK certified by its AK over the session-bound
    /// target of `commitment_hash`. Returns the receipt's wire bytes and the
    /// author's Device Tree root.
    fn signed_receipt(
        author: &Peer,
        toward: &Peer,
        receipt: &StitchedReceiptV2,
        c_pre: &[u8; 32],
        side: BilateralSide,
        commitment_hash: &[u8; 32],
    ) -> (Vec<u8>, [u8; 32]) {
        use crate::types::receipt_types::compute_receipt_challenge_response_target;

        let mut receipt = receipt.clone();
        let commitment = receipt.compute_commitment().expect("commitment");
        let answer = author.party.answer(
            &toward.party,
            &receipt.parent_tip,
            c_pre,
            &compute_receipt_challenge_response_target(&commitment, commitment_hash),
        );
        match side {
            BilateralSide::A => {
                receipt.set_ek_cert_a(answer.ek_cert);
                receipt.set_ek_pk_a(answer.ek_pk);
                receipt.add_sig_a(answer.sig);
                receipt.set_kyber_ct_a(answer.kyber_ct);
            }
            BilateralSide::B => {
                receipt.set_ek_cert_b(answer.ek_cert);
                receipt.set_ek_pk_b(answer.ek_pk);
                receipt.add_sig_b(answer.sig);
                receipt.set_kyber_ct_b(answer.kyber_ct);
            }
        }
        (
            receipt.to_full_protobuf().expect("encode"),
            crate::common::device_tree::DeviceTree::single(author.device_id).root(),
        )
    }

    impl BuiltConfirm {
        /// Where the receiver holds the sender's offline account from: its
        /// record of the load, with no spend between.
        fn origin(&self) -> BearerOrigin<'static> {
            BearerOrigin {
                recorded: Some(self.recorded),
                anchor: self.anchor.clone(),
                chain: &[],
                accepted: None,
            }
        }
    }

    fn built_confirm() -> BuiltConfirm {
        use crate::types::offline_chain::fixture::{bearer_op, Payer};

        let sender = Peer::new(0x61);
        let receiver = Peer::new(0x62);
        let mut payer = Payer::loaded_on(
            sender.party.head(),
            sender.genesis,
            0x61,
            40,
            crate::economic::token_policy::POLICY_FLAG_TRANSFERABLE,
        );
        let recorded = super::receive_rule_tests::record(&payer);
        let operation = bearer_op(receiver.device_id, payer.token, &payer.token_policy, 7);
        let (_, spent, bearer) = payer.spend(receiver.device_id, 7);
        let (held_tip, commitment_hash) = held_tip_and_commitment(&receiver, &sender, &operation);
        let pre_entropy = spent.transition_entropy;
        let c_pre = compute_precommit(
            &spent.parent_tip,
            &operation.with_cleared_signature().to_bytes(),
            &pre_entropy,
        )
        .expect("the step's C_pre");
        let (receipt, device_tree_root) = signed_receipt(
            &sender,
            &receiver,
            &spent,
            &c_pre,
            BilateralSide::A,
            &commitment_hash,
        );
        let op_bytes = operation.to_bytes();
        let successor_tip = compute_successor_tip(
            &held_tip,
            &op_bytes,
            &pre_entropy,
            &compute_precommit(&held_tip, &op_bytes, &pre_entropy).expect("the step's C_pre"),
        );
        BuiltConfirm {
            sender,
            receiver,
            operation,
            bearer,
            recorded,
            anchor: payer.pin,
            commitment_hash,
            receipt,
            device_tree_root,
            held_tip,
            pre_entropy,
            successor_tip,
        }
    }

    /// The receiver commits only a confirm its pinned sender signed, whose
    /// receipt is from that sender to this device and holds (state rules,
    /// A-side EK chaining from the sender's head), whose spend starts at the
    /// sender's offline account as this device validated it online, and
    /// whose successor tip the held tip, the operation and the sender's
    /// entropy reproduce.
    /// MUTATION CONTROLS: dropping the σ_A check, the receipt's device
    /// binding, or the successor recompute lets a refused confirm through and
    /// turns this red.
    #[test]
    fn a_confirm_is_committed_only_as_its_sender_signed_and_derived_it() {
        let c = built_confirm();
        let operation = c.operation.clone();
        let origin = c.origin();
        let other = Peer::new(0x65);
        let decide = |signature: &[u8],
                      receipt: &[u8],
                      pre_entropy: &[u8],
                      successor_tip: [u8; 32],
                      receiver_device_id: [u8; 32],
                      sender_chain_head: Option<&[u8]>| {
            decide_confirm(
                ConfirmClaims {
                    signature,
                    receipt,
                    pre_entropy,
                    successor_tip: Some(successor_tip),
                },
                AcceptedStep {
                    commitment_hash: c.commitment_hash,
                    operation: &operation,
                    held_tip: c.held_tip,
                    receiver_device_id,
                    sender_device_tree_root: c.device_tree_root,
                    sender_chain_head,
                    bearer: c.bearer,
                    bearer_origin: &origin,
                },
                &c.sender.pinned(),
            )
        };
        let sigma_a = c.sender.sign_step(&c.commitment_hash);

        let verified = decide(
            &sigma_a,
            &c.receipt,
            &c.pre_entropy,
            c.successor_tip,
            c.receiver.device_id,
            None,
        )
        .expect("the sender's own confirm");
        assert_eq!(verified.successor_tip(), c.successor_tip);

        refused(
            decide(
                &[],
                &c.receipt,
                &c.pre_entropy,
                c.successor_tip,
                c.receiver.device_id,
                None,
            ),
            "carries no signature",
        );
        refused(
            decide(
                &other.sign_step(&c.commitment_hash),
                &c.receipt,
                &c.pre_entropy,
                c.successor_tip,
                c.receiver.device_id,
                None,
            ),
            "not signed over its commitment by the pinned AK",
        );
        refused(
            decide(
                &sigma_a,
                &c.receipt,
                &c.pre_entropy,
                c.successor_tip,
                other.device_id,
                None,
            ),
            "not from this session's sender to this device",
        );
        refused(
            decide(
                &sigma_a,
                &c.receipt,
                &c.pre_entropy,
                c.successor_tip,
                c.receiver.device_id,
                Some(other.public_key()),
            ),
            "does NOT chain",
        );
        refused(
            decide(
                &sigma_a,
                &c.receipt,
                &c.pre_entropy,
                c.held_tip,
                c.receiver.device_id,
                None,
            ),
            "h_{n+1} mismatch",
        );
        refused(
            decide(
                &sigma_a,
                &vec![0u8; MAX_STITCHED_RECEIPT_BYTES + 1],
                &c.pre_entropy,
                c.successor_tip,
                c.receiver.device_id,
                None,
            ),
            "128 KiB",
        );

        // A device that has validated none of the sender's offline account
        // online takes no offline payment from it.
        refused(
            decide_confirm(
                ConfirmClaims {
                    signature: &sigma_a,
                    receipt: &c.receipt,
                    pre_entropy: &c.pre_entropy,
                    successor_tip: Some(c.successor_tip),
                },
                AcceptedStep {
                    commitment_hash: c.commitment_hash,
                    operation: &operation,
                    held_tip: c.held_tip,
                    receiver_device_id: c.receiver.device_id,
                    sender_device_tree_root: c.device_tree_root,
                    sender_chain_head: None,
                    bearer: c.bearer,
                    bearer_origin: &BearerOrigin {
                        recorded: None,
                        ..c.origin()
                    },
                },
                &c.sender.pinned(),
            ),
            "has validated none of the sender's offline account online",
        );
    }

    /// SA-11. The confirm's entropy and successor tip ride unsigned beside
    /// the signed receipt. A frame whose entropy is another value — with the
    /// successor tip recomputed from it, so the two agree with each other —
    /// would move this device to a tip its sender never derived, and the two
    /// sides would hold different tips. The receiver takes the step only
    /// with the entropy its signed receipt commits.
    /// MUTATION CONTROL: dropping the comparison of the confirm's entropy
    /// with the receipt's lets the tampered frame commit and turns this red.
    #[test]
    fn a_confirm_whose_entropy_is_not_its_receipts_moves_nothing() {
        let c = built_confirm();
        let operation = c.operation.clone();
        let origin = c.origin();
        let tampered_entropy = [0x6Bu8; 32];
        assert_ne!(tampered_entropy, c.pre_entropy);
        let op_bytes = operation.to_bytes();
        let tampered_successor = compute_successor_tip(
            &c.held_tip,
            &op_bytes,
            &tampered_entropy,
            &compute_precommit(&c.held_tip, &op_bytes, &tampered_entropy)
                .expect("the tampered step's C_pre"),
        );
        assert_ne!(tampered_successor, c.successor_tip);
        let decide = |entropy: &[u8], successor_tip: [u8; 32]| {
            decide_confirm(
                ConfirmClaims {
                    signature: &c.sender.sign_step(&c.commitment_hash),
                    receipt: &c.receipt,
                    pre_entropy: entropy,
                    successor_tip: Some(successor_tip),
                },
                AcceptedStep {
                    commitment_hash: c.commitment_hash,
                    operation: &operation,
                    held_tip: c.held_tip,
                    receiver_device_id: c.receiver.device_id,
                    sender_device_tree_root: c.device_tree_root,
                    sender_chain_head: None,
                    bearer: c.bearer,
                    bearer_origin: &origin,
                },
                &c.sender.pinned(),
            )
        };

        assert_eq!(
            decide(&c.pre_entropy, c.successor_tip)
                .expect("the sender's own confirm")
                .successor_tip(),
            c.successor_tip
        );
        refused(
            decide(&tampered_entropy, tampered_successor),
            "is not the transition entropy its signed receipt commits",
        );
    }

    /// The receiver takes a bearer confirm only with the anchor-state leaves
    /// its receipt's spend moved. The counter and both frontiers the
    /// receipt's offline account starts from and advances to must be the ones
    /// the release signed, and the account's leaf, under the release's bundle,
    /// must fold with the relationship leaf from the receipt's parent root to
    /// its child root.
    /// MUTATION CONTROL: dropping the comparison of the receipt's offline
    /// account with the release's leaves lets the counter and frontier cases
    /// through and turns this red.
    #[test]
    fn a_confirm_whose_bearer_leaves_are_not_its_receipts_spend_is_refused() {
        let c = built_confirm();
        let operation = c.operation.clone();
        let origin = c.origin();
        let sigma_a = c.sender.sign_step(&c.commitment_hash);
        let decide = |bearer: BearerLeaves| {
            decide_confirm(
                ConfirmClaims {
                    signature: &sigma_a,
                    receipt: &c.receipt,
                    pre_entropy: &c.pre_entropy,
                    successor_tip: Some(c.successor_tip),
                },
                AcceptedStep {
                    commitment_hash: c.commitment_hash,
                    operation: &operation,
                    held_tip: c.held_tip,
                    receiver_device_id: c.receiver.device_id,
                    sender_device_tree_root: c.device_tree_root,
                    sender_chain_head: None,
                    bearer,
                    bearer_origin: &origin,
                },
                &c.sender.pinned(),
            )
        };

        decide(c.bearer).expect("the confirm with its own spend's leaves");
        let other = [0x6Cu8; 32];
        for (leaves, why) in [
            (
                BearerLeaves {
                    counter: c.bearer.counter + 1,
                    ..c.bearer
                },
                "is not the one its release advances",
            ),
            (
                BearerLeaves {
                    frontier: other,
                    ..c.bearer
                },
                "is not the one its release advances",
            ),
            (
                BearerLeaves {
                    next_frontier: other,
                    ..c.bearer
                },
                "is not the one its release advances",
            ),
            (
                BearerLeaves {
                    bundle: other,
                    ..c.bearer
                },
                // The account's leaf under another bundle is another key: its
                // write's path is not the tree's.
                "the receipt's writes: ",
            ),
        ] {
            refused(decide(leaves), why);
        }
    }

    /// The sender takes as the step's acknowledgment only the receiver's
    /// counter-signed receipt: named for the step, from the pinned receiver
    /// toward this device, holding against the receiver's Device Tree
    /// commitment, with the B-side EK chained from the receiver's head.
    /// MUTATION CONTROLS: dropping the device binding or the B-side EK check
    /// lets a forged ack through and turns this red.
    /// A confirm for a committed step is answered again only as its pinned
    /// sender signed it over that step's commitment.
    #[test]
    fn a_committed_steps_confirm_is_answered_only_as_its_sender_signed_it() {
        let sender = Peer::new(0x76);
        let other = Peer::new(0x77);
        let commitment_hash = [0x78u8; 32];
        decide_committed_confirm(
            &sender.sign_step(&commitment_hash),
            &commitment_hash,
            &sender.pinned(),
        )
        .expect("the sender's own confirm");
        refused(
            decide_committed_confirm(
                &other.sign_step(&commitment_hash),
                &commitment_hash,
                &sender.pinned(),
            ),
            "not signed over its commitment by the pinned AK",
        );
        refused(
            decide_committed_confirm(
                &sender.sign_step(&[0x79u8; 32]),
                &commitment_hash,
                &sender.pinned(),
            ),
            "not signed over its commitment by the pinned AK",
        );
        refused(
            decide_committed_confirm(&[], &commitment_hash, &sender.pinned()),
            "carries no signature",
        );
    }

    #[test]
    fn an_ack_is_only_the_receivers_counter_signed_receipt() {
        let receiver = Peer::new(0x71);
        let sender = Peer::new(0x72);
        let sender_device_id = sender.device_id;
        let (transfer, credit) = steps(&sender, &receiver);
        let (held_tip, commitment_hash) =
            held_tip_and_commitment(&receiver, &sender, &transfer.operation);
        let (ack, root) = signed_receipt(
            &receiver,
            &sender,
            &credit.receipt,
            &credit.c_pre,
            BilateralSide::B,
            &commitment_hash,
        );
        let other = Peer::new(0x74);
        let step = |sender_device_id: [u8; 32]| ConfirmedStep {
            commitment_hash,
            sender_device_id,
            receiver_device_tree_root: root,
            receiver_chain_head: None,
            operation: &transfer.operation,
        };
        let decide = |named: [u8; 32], bytes: &[u8], step: ConfirmedStep<'_>| {
            decide_commit_ack(Some(named), bytes, step, &receiver.pinned())
        };

        decide(commitment_hash, &ack, step(sender_device_id))
            .expect("the receiver's own acknowledgment");
        refused(
            decide(held_tip, &ack, step(sender_device_id)),
            "names another commitment",
        );
        refused(
            decide(commitment_hash, &[], step(sender_device_id)),
            "omits counter_signed_receipt",
        );
        refused(
            decide(commitment_hash, &ack, step(other.device_id)),
            "possible substitution",
        );
        refused(
            decide(
                commitment_hash,
                &ack,
                ConfirmedStep {
                    receiver_chain_head: Some(other.public_key()),
                    ..step(sender_device_id)
                },
            ),
            "does NOT chain",
        );
        let (a_side, _) = signed_receipt(
            &receiver,
            &sender,
            &credit.receipt,
            &credit.c_pre,
            BilateralSide::A,
            &commitment_hash,
        );
        refused(
            decide(commitment_hash, &a_side, step(sender_device_id)),
            "B-side artifacts",
        );
    }
}

/// The receive rule against real spends: a payer's anchor-released spends,
/// built through its own `advance`, and the receiver's record of the account
/// the payer's load left.
#[cfg(test)]
mod receive_rule_tests {
    use super::*;
    use crate::economic::peer_lineage::PeerOfflineAccount;
    use crate::types::offline_chain::fixture::Payer;

    const RECEIVER: [u8; 32] = [0xB0; 32];
    const OTHER: [u8; 32] = [0xC0; 32];

    fn refused<T: core::fmt::Debug>(result: Result<T, DsmError>, reason: &str) {
        let error = result.expect_err(reason);
        assert!(error.to_string().contains(reason), "{error}");
    }

    pub(super) fn record(payer: &Payer) -> PeerOfflineAccount {
        let account = payer
            .head
            .offline_account(&payer.pin.bundle)
            .expect("the account is open");
        PeerOfflineAccount::rehydrate_recorded(
            payer.genesis,
            payer.head.devid(),
            1,
            payer.pin.bundle,
            account.root(),
            account.funding_chain().expect("a load funded it"),
        )
    }

    fn origin<'a>(
        recorded: &PeerOfflineAccount,
        payer: &Payer,
        chain: &'a [crate::types::offline_chain::SpendHop],
        accepted: Option<([u8; 32], u64)>,
    ) -> BearerOrigin<'a> {
        BearerOrigin {
            recorded: Some(*recorded),
            anchor: payer.pin.clone(),
            chain,
            accepted,
        }
    }

    /// SA-116. A payer that paid someone else offline since its load pays
    /// this receiver from the account its chain of spends leaves: taken with
    /// the chain, from the receiver's record of the load; refused without it.
    /// MUTATION CONTROL: taking the spend's start from the record alone,
    /// without the chain, turns this red.
    #[test]
    fn a_second_offline_spend_is_taken_with_the_chain_from_the_record() {
        let mut payer = Payer::loaded(0x41, 40);
        let recorded = record(&payer);
        let (first, first_receipt, first_leaves) = payer.spend(OTHER, 10);
        let (_, second_receipt, second_leaves) = payer.spend(RECEIVER, 5);
        let start = spend_starts_at_the_record(
            &second_receipt,
            &second_leaves,
            &payer.genesis,
            &origin(&recorded, &payer, std::slice::from_ref(&first), None),
        )
        .expect("the second spend is taken with the chain");
        assert_eq!((start.counter, start.frontier), (1, second_leaves.frontier));
        spend_starts_at_the_record(
            &first_receipt,
            &first_leaves,
            &payer.genesis,
            &origin(&recorded, &payer, &[], None),
        )
        .expect("the first spend starts at the record");
        refused(
            spend_starts_at_the_record(
                &second_receipt,
                &second_leaves,
                &payer.genesis,
                &origin(&recorded, &payer, &[], None),
            ),
            "carried forward by the sender's chain of spends",
        );
    }

    /// A chain that does not reach the release's start, or under another
    /// anchor, or a record of another sender, is refused.
    #[test]
    fn a_spend_whose_chain_does_not_carry_the_record_to_it_is_refused() {
        let mut payer = Payer::loaded(0x42, 40);
        let other = Payer::loaded(0x43, 40);
        let recorded = record(&payer);
        let (first, _, _) = payer.spend(OTHER, 10);
        let (second, _, _) = payer.spend(OTHER, 3);
        let (_, receipt, leaves) = payer.spend(RECEIVER, 5);
        refused(
            spend_starts_at_the_record(
                &receipt,
                &leaves,
                &payer.genesis,
                &origin(&recorded, &payer, std::slice::from_ref(&first), None),
            ),
            "carried forward by the sender's chain of spends",
        );
        let both = [first.clone(), second.clone()];
        let mut foreign = origin(&recorded, &payer, &both, None);
        foreign.anchor = other.pin.clone();
        refused(
            spend_starts_at_the_record(&receipt, &leaves, &payer.genesis, &foreign),
            "not the sender's under this spend's anchor bundle",
        );
        refused(
            spend_starts_at_the_record(
                &receipt,
                &leaves,
                &payer.genesis,
                &origin(&record(&other), &payer, &[first, second], None),
            ),
            "not the sender's under this spend's anchor bundle",
        );
    }

    /// Forward only: once a receiver accepted a spend from a payer, the next
    /// spend must pass through the point that spend left the account at. A
    /// spend replayed from before it, or a spend whose chain bypasses it, is
    /// refused.
    /// MUTATION CONTROL: dropping the forward-only check takes the replayed
    /// spend and turns this red.
    #[test]
    fn a_spend_before_the_one_last_accepted_is_refused() {
        let mut payer = Payer::loaded(0x44, 40);
        let recorded = record(&payer);
        let (first, first_receipt, first_leaves) = payer.spend(RECEIVER, 10);
        let (_, second_receipt, second_leaves) = payer.spend(RECEIVER, 5);
        let after_first = Some((first_leaves.next_frontier, first_leaves.counter + 1));
        spend_starts_at_the_record(
            &second_receipt,
            &second_leaves,
            &payer.genesis,
            &origin(&recorded, &payer, std::slice::from_ref(&first), after_first),
        )
        .expect("the next spend passes through the one accepted");
        let after_second = Some((second_leaves.next_frontier, second_leaves.counter + 1));
        refused(
            spend_starts_at_the_record(
                &first_receipt,
                &first_leaves,
                &payer.genesis,
                &origin(&recorded, &payer, &[], after_second),
            ),
            "does not extend the spend this device last accepted",
        );
        refused(
            spend_starts_at_the_record(
                &second_receipt,
                &second_leaves,
                &payer.genesis,
                &origin(&recorded, &payer, &[first], Some(([0x5C; 32], 1))),
            ),
            "does not extend the spend this device last accepted",
        );
    }
}
