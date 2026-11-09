//! The receiver's side of an offline payment (owner, 2026-11-07: an offline payment needs a board on
//! both sides). The receiver's appliance draws the challenge the payer's release must answer, checks
//! the payer's release itself, and commits the receive as a root advance of its own, whose
//! certificate is the acknowledgement the payer keeps.
//!
//! One challenge is open at a time. Drawing another discards it, a cancel keeps it, and the finalize
//! of a receive uses it up, so a release, which answers exactly one challenge, is received at most
//! once. Nothing is kept per payer.
//!
//! The appliance checks the payer's release before it signs anything:
//! - the disclosed enrollment recomputes the release's bundle `B_s`, under the receiver's own policy;
//! - the transition is the advance the certificate signs, and a transfer;
//! - `h_{i+1}` and `M` recompute, and `σ^chip` and `σ^host` verify under the disclosed keys;
//! - the release answers the open challenge, and pays the device this appliance was provisioned for.
//!
//! The receive it then prepares binds exactly the checked release: its action fields name `B_s`, the
//! payer's `M_s` and counter `u_s + 1`, and it carries the payer's payload hash, relationship,
//! object and policy. Its recipient is the payer, and its challenge is the one the payer answered.

extern crate alloc;
use alloc::vec::Vec;

use crate::accept::{verify_cert_frontier_and_sigs, AcceptError};
use crate::enrollment::anchor_bundle;
use crate::root_advance::{transition_digest, Certificate, OfflineRelease, Transition};
use crate::tropic::{ChipSig, HostSig, PartitionSig, Tropic};
use crate::util::{ct_eq_32, u64_le};

/// A transition that pays: the payer's release.
pub const ACTION_TRANSFER: u32 = 0;
/// A transition that receives a payment: the receiver's own advance.
pub const ACTION_RECEIVE: u32 = 4;

/// The action fields of a receive: the payer's bundle, the message its anchor signed, and the counter
/// its release moved to. `M_s` binds the rest of the payer's certificate.
pub fn receive_action_fields(
    payer_bundle: &[u8; 32],
    payer_message: &[u8; 32],
    payer_next_counter: u64,
) -> Vec<u8> {
    let mut v = Vec::with_capacity(72);
    v.extend_from_slice(payer_bundle);
    v.extend_from_slice(payer_message);
    v.extend_from_slice(&u64_le(payer_next_counter));
    v
}

/// What a payer discloses of its enrollment, for its bundle to recompute: every field `B` binds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayerDisclosure {
    pub online_id_pk: Vec<u8>,
    pub anchor_id: [u8; 32],
    pub chip_pk: Vec<u8>,
    pub partition_pk: Vec<u8>,
    pub enrolled_counter: u32,
    pub device_id: [u8; 32],
    pub policy_hash: [u8; 32],
    pub birth_commitment: [u8; 32],
}

impl PayerDisclosure {
    /// The bundle the disclosed fields commit.
    pub fn bundle(&self) -> [u8; 32] {
        anchor_bundle(
            &self.online_id_pk,
            &self.anchor_id,
            &self.chip_pk,
            &self.partition_pk,
            self.enrolled_counter,
            &self.device_id,
            &self.policy_hash,
            &self.birth_commitment,
        )
    }
}

/// The payer's certificate as the receiver's appliance reads it: its signatures borrowed from the
/// request that carried them, so the largest of them, `σ^host`, is held once.
pub struct PaymentCert<'a> {
    pub anchor_bundle: [u8; 32],
    pub sender_device_root_before: [u8; 32],
    pub sender_device_root_after: [u8; 32],
    pub prev_frontier: [u8; 32],
    pub next_frontier: [u8; 32],
    pub anchor_counter: u64,
    pub next_anchor_counter: u64,
    pub transition_digest: [u8; 32],
    pub root_advance_message: [u8; 32],
    pub anchor_id: [u8; 32],
    pub sigma_chip: &'a [u8],
    pub sigma_host: &'a [u8],
    pub receiver_challenge: [u8; 32],
    pub recipient: [u8; 32],
}

/// Why the receiver's appliance refused the payer's release.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PaymentRefusal {
    /// The disclosed enrollment does not recompute the release's bundle, or names another anchor.
    Bundle,
    /// The payer is enrolled under another policy than this appliance.
    Policy,
    /// The release's transition is not a transfer.
    Action,
    /// The transition is not the advance its certificate signs.
    Transition,
    /// The release moves its counter by other than one.
    Counter,
    /// The release was not made for the open challenge.
    Challenge,
    /// The release pays another device than this appliance's.
    Recipient,
    /// The transition is not the disclosed payer's.
    Payer,
    /// The successor frontier does not recompute.
    Frontier,
    /// The root-advance message does not recompute.
    Message,
    /// `σ^chip` does not verify under the disclosed chip key.
    ChipSignature,
    /// `σ^host` does not verify under the disclosed partition key.
    HostSignature,
}

/// What a receive of a checked payment must bind, as one digest: its action fields (the payer's bundle,
/// `M_s` and counter), the payer's payload, relationship, object and policy, the payer as its
/// recipient, the receiving device as its author, and the challenge the payment answered. The
/// appliance keeps this digest from its check to the receive that names it, and recomputes it from
/// the receive it is asked to prepare.
pub fn receive_binding(t: &Transition, challenge: &[u8; 32]) -> [u8; 32] {
    crate::hash::h(
        crate::domain::RECEIVE_BINDING_V1,
        &[
            &crate::util::u32_le(t.action_type),
            &crate::util::u32_le(t.action_fields.len() as u32),
            t.action_fields,
            t.payload_hash,
            t.relationship_id,
            t.object_id,
            t.authority_policy_hash,
            t.recipient_device_id,
            t.sender_device_id,
            challenge,
        ],
    )
}

/// Who the receiving appliance is, and the challenge it has open.
pub struct Receiver<'a> {
    pub device_id: &'a [u8; 32],
    pub policy_hash: &'a [u8; 32],
    pub open_challenge: &'a [u8; 32],
}

/// The receiver's appliance's check of the payer's release (see the module docs). `tropic` verifies
/// `σ^chip` (an Ed25519 verify under the given key; the chip's own key is not involved). Answers the
/// binding ([`receive_binding`]) of the one receive that may name the payment.
#[inline(never)]
pub fn check_payment<T: Tropic, P: PartitionSig>(
    tropic: &T,
    transition: &Transition,
    cert: &PaymentCert,
    payer: &PayerDisclosure,
    receiver: &Receiver,
) -> Result<[u8; 32], PaymentRefusal> {
    if !ct_eq_32(&payer.policy_hash, receiver.policy_hash) {
        return Err(PaymentRefusal::Policy);
    }
    if !ct_eq_32(&payer.bundle(), &cert.anchor_bundle)
        || !ct_eq_32(&payer.anchor_id, &cert.anchor_id)
    {
        return Err(PaymentRefusal::Bundle);
    }
    if transition.action_type != ACTION_TRANSFER {
        return Err(PaymentRefusal::Action);
    }
    if !ct_eq_32(transition.sender_device_id, &payer.device_id) {
        return Err(PaymentRefusal::Payer);
    }
    if !ct_eq_32(&cert.receiver_challenge, receiver.open_challenge) {
        return Err(PaymentRefusal::Challenge);
    }
    if !ct_eq_32(&cert.recipient, receiver.device_id)
        || !ct_eq_32(transition.recipient_device_id, receiver.device_id)
    {
        return Err(PaymentRefusal::Recipient);
    }
    if cert.anchor_counter.checked_add(1) != Some(cert.next_anchor_counter) {
        return Err(PaymentRefusal::Counter);
    }
    if !ct_eq_32(transition.prev_root, &cert.prev_frontier)
        || !ct_eq_32(transition.next_root, &cert.next_frontier)
        || transition.anchor_counter != cert.anchor_counter
        || transition.next_anchor_counter != cert.next_anchor_counter
        || !ct_eq_32(
            &transition_digest(transition, &cert.receiver_challenge),
            &cert.transition_digest,
        )
    {
        return Err(PaymentRefusal::Transition);
    }
    let next =
        crate::root_advance::anchor_root_advance(&cert.prev_frontier, &cert.transition_digest);
    if !ct_eq_32(&next, &cert.next_frontier) {
        return Err(PaymentRefusal::Frontier);
    }
    let m = crate::root_advance::root_advance_message(
        &cert.anchor_bundle,
        &cert.sender_device_root_before,
        &cert.sender_device_root_after,
        &cert.prev_frontier,
        &cert.next_frontier,
        cert.anchor_counter,
        cert.next_anchor_counter,
        &cert.transition_digest,
        &cert.recipient,
        &cert.receiver_challenge,
    );
    if !ct_eq_32(&m, &cert.root_advance_message) {
        return Err(PaymentRefusal::Message);
    }
    if !tropic.chip_signature_holds(&payer.chip_pk, &m, cert.sigma_chip) {
        return Err(PaymentRefusal::ChipSignature);
    }
    if !P::part_verify(&payer.partition_pk, &m, cert.sigma_host) {
        return Err(PaymentRefusal::HostSignature);
    }
    // The receive that names this payment: its fields, as the payer's release sets them.
    let fields = receive_action_fields(&cert.anchor_bundle, &m, cert.next_anchor_counter);
    let expected = Transition {
        action_type: ACTION_RECEIVE,
        action_fields: &fields,
        recipient_device_id: &payer.device_id,
        sender_device_id: receiver.device_id,
        ..*transition
    };
    Ok(receive_binding(&expected, &cert.receiver_challenge))
}

/// The receiver's anchor as the payer pinned it: its bundle and the keys the bundle commits.
pub struct ReceiverPin<'a> {
    pub bundle: &'a [u8; 32],
    pub anchor_id: &'a [u8; 32],
    pub pk_chip: &'a [u8],
    pub pk_host: &'a [u8],
}

/// What a verified acknowledgement says the receiver's anchor did: the advance its receive commit
/// made, between the two device roots it signed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Acknowledged {
    pub receiver_device_root_before: [u8; 32],
    pub receiver_device_root_after: [u8; 32],
    pub counter: u64,
    pub frontier: [u8; 32],
    pub next_frontier: [u8; 32],
    pub message: [u8; 32],
}

/// Why a payer refused an acknowledgement.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AckRefusal {
    /// The acknowledgement is under another anchor than the receiver's pinned one.
    Anchor,
    /// Its transition is not a receive.
    Action,
    /// Its transition is not the advance its certificate signs.
    Transition,
    /// It does not receive this payer's own release.
    NotThisRelease,
    /// It names another payer, receiver, challenge, payload, relationship, object or policy.
    Binding,
    /// Its counter moves by other than one.
    Counter,
    /// Its frontier, message or signatures do not verify.
    Certificate(AcceptError),
}

/// The payer's check of an acknowledgement (owner, 2026-11-07: the payer's phone checks it): the
/// receiver's receive commit, under the receiver's pinned anchor, of exactly the release `own` this
/// payer made to `receiver_device`.
pub fn verify_acknowledgement<C: ChipSig, H: HostSig>(
    ack: &OfflineRelease,
    receiver: &ReceiverPin,
    receiver_device: &[u8; 32],
    own: &OfflineRelease,
) -> Result<Acknowledged, AckRefusal> {
    let cert: &Certificate = &ack.cert;
    let t = &ack.transition;
    if !ct_eq_32(&cert.anchor_bundle, receiver.bundle)
        || !ct_eq_32(&cert.anchor_id, receiver.anchor_id)
    {
        return Err(AckRefusal::Anchor);
    }
    if t.action_type != ACTION_RECEIVE {
        return Err(AckRefusal::Action);
    }
    if cert.anchor_counter.checked_add(1) != Some(cert.next_anchor_counter) {
        return Err(AckRefusal::Counter);
    }
    if t.prev_root != cert.prev_frontier
        || t.next_root != cert.next_frontier
        || t.anchor_counter != cert.anchor_counter
        || t.next_anchor_counter != cert.next_anchor_counter
        || t.recipient_device_id != cert.recipient
        || transition_digest(&t.as_transition(), &cert.receiver_challenge) != cert.transition_digest
    {
        return Err(AckRefusal::Transition);
    }
    let paid = &own.cert;
    if t.action_fields
        != receive_action_fields(
            &paid.anchor_bundle,
            &paid.root_advance_message,
            paid.next_anchor_counter,
        )
    {
        return Err(AckRefusal::NotThisRelease);
    }
    let sent = &own.transition;
    if cert.receiver_challenge != paid.receiver_challenge
        || cert.recipient != sent.sender_device_id
        || t.sender_device_id != *receiver_device
        || t.payload_hash != sent.payload_hash
        || t.relationship_id != sent.relationship_id
        || t.object_id != sent.object_id
        || t.authority_policy_hash != sent.authority_policy_hash
    {
        return Err(AckRefusal::Binding);
    }
    verify_cert_frontier_and_sigs::<C, H>(cert, receiver.pk_chip, receiver.pk_host)
        .map_err(AckRefusal::Certificate)?;
    Ok(Acknowledged {
        receiver_device_root_before: cert.sender_device_root_before,
        receiver_device_root_after: cert.sender_device_root_after,
        counter: cert.anchor_counter,
        frontier: cert.prev_frontier,
        next_frontier: cert.next_frontier,
        message: cert.root_advance_message,
    })
}
