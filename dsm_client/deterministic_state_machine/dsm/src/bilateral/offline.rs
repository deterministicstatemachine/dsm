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
    bilateral_sign_message, operation_requires_offline_bearer, BilateralPreCommitment,
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
/// all. Offline, the only value that moves is the bearer tier; an online-tier
/// transfer has the network transport.
pub fn offline_operation(operation_bytes: &[u8]) -> Result<Operation, DsmError> {
    let operation = Operation::from_bytes(operation_bytes)
        .map_err(|_| DsmError::invalid_operation("invalid operation payload"))?;
    if matches!(operation, Operation::Transfer { .. })
        && !operation_requires_offline_bearer(&operation)
    {
        return Err(DsmError::invalid_operation(
            "bilateral prepare refused: BLE/USB carries offline-bearer transfers only — an \
             online-tier transfer uses the network transport",
        ));
    }
    Ok(operation)
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
    if signature.is_empty() {
        return Err(DsmError::invalid_operation(format!(
            "the {what} carries no signature over its commitment"
        )));
    }
    let valid = SignatureKeyPair::verify_raw(
        &bilateral_sign_message(commitment_hash),
        signature,
        peer.signing_key,
    )
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
    /// The proposal does not extend the tip this device holds: it is answered
    /// with a signed rejection, and the relationship is reconciled online.
    StaleTip {
        expected: Option<[u8; 32]>,
        held: [u8; 32],
    },
}

/// What a prepare claims: the tip it expects the relationship to hold, its
/// sender's keys, and its sender's signature (σ_A) over its commitment.
#[derive(Clone, Copy, Debug)]
pub struct PrepareClaims<'a> {
    pub expected_tip: Option<[u8; 32]>,
    pub credentials: PeerCredentials<'a>,
    pub signature: &'a [u8],
}

/// The receiver's decision on a prepare. `operation` is what
/// [`offline_operation`] admitted from the request, `commitment_hash` the
/// commitment the proposal names, and `held_tip` the relationship tip this
/// device holds durably. The proposal must come from the pinned sender (its
/// keys, and its signature over the commitment), and the commitment must be
/// its operation's commitment on the held tip — the receiver never signs a
/// commitment it did not recompute.
pub fn decide_prepare(
    commitment_hash: [u8; 32],
    operation: &Operation,
    claims: PrepareClaims<'_>,
    sender: &PinnedPeer<'_>,
    held_tip: [u8; 32],
) -> Result<PrepareDecision, DsmError> {
    verify_pinned_peer_keys(sender, claims.credentials)?;
    verify_step_signature(sender, &commitment_hash, claims.signature, "proposal")?;

    if claims.expected_tip != Some(held_tip) {
        return Ok(PrepareDecision::StaleTip {
            expected: claims.expected_tip,
            held: held_tip,
        });
    }
    let own = BilateralPreCommitment::new(held_tip, operation.clone()).bilateral_commitment_hash;
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
    /// σ_B over the step's commitment.
    pub signature: Vec<u8>,
    /// The receiver's challenge a bearer release answers.
    pub receiver_challenge: Option<[u8; 32]>,
}

/// What a prepare response claims: the commitment it answers, its
/// receiver's keys, its receiver's signature (σ_B) over that commitment, and
/// the receiver's challenge.
#[derive(Clone, Copy, Debug)]
pub struct ResponseClaims<'a> {
    pub commitment_hash: Option<[u8; 32]>,
    pub credentials: PeerCredentials<'a>,
    pub signature: &'a [u8],
    pub receiver_challenge: &'a [u8],
}

/// The proposer's decision on a prepare response for the step
/// `commitment_hash` it proposed to `receiver`: the response carries the
/// receiver's pinned keys and its signature over that commitment. Nothing in
/// a response is taken before it verifies.
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
    verify_step_signature(receiver, &commitment_hash, claims.signature, "acceptance")?;
    let receiver_challenge = match claims.receiver_challenge.len() {
        0 => None,
        _ => Some(
            <[u8; 32]>::try_from(claims.receiver_challenge).map_err(|_| {
                DsmError::invalid_operation("the receiver challenge is not 32 bytes")
            })?,
        ),
    };
    Ok(Acceptance {
        signature: claims.signature.to_vec(),
        receiver_challenge,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bilateral::identity_binding::binding_digest;
    use crate::crypto::kyber;
    use crate::types::operations::TransactionMode;
    use crate::types::token_types::Balance;

    struct Peer {
        device_id: [u8; 32],
        genesis: [u8; 32],
        keys: SignatureKeyPair,
        kyber_public_key: Vec<u8>,
        binding_sig: Vec<u8>,
    }

    impl Peer {
        fn new(seed: u8) -> Self {
            let device_id = [seed; 32];
            let genesis = [seed.wrapping_add(1); 32];
            let keys = SignatureKeyPair::generate_from_entropy(&[seed; 32]).expect("keys");
            let kyber_public_key = kyber::generate_kyber_keypair()
                .expect("kyber")
                .public_key
                .clone();
            let binding_sig = keys
                .sign(&binding_digest(&device_id, &genesis, &kyber_public_key))
                .expect("binding");
            Self {
                device_id,
                genesis,
                keys,
                kyber_public_key,
                binding_sig,
            }
        }

        fn pinned(&self) -> PinnedPeer<'_> {
            PinnedPeer {
                device_id: self.device_id,
                genesis: self.genesis,
                signing_key: self.keys.public_key(),
                kyber_public_key: &self.kyber_public_key,
            }
        }

        fn sign_step(&self, commitment_hash: &[u8; 32]) -> Vec<u8> {
            self.keys
                .sign(&bilateral_sign_message(commitment_hash))
                .expect("sign")
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

        check(
            peer.keys.public_key(),
            &peer.kyber_public_key,
            &peer.binding_sig,
        )
        .expect("the pinned keys and their binding");
        refused(
            check(
                other.keys.public_key(),
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
                peer.keys.public_key(),
                &other.kyber_public_key,
                &peer.binding_sig,
            ),
            "not the contact's pinned Kyber key",
        );
        refused(
            check(peer.keys.public_key(), &[], &peer.binding_sig),
            "not the contact's pinned Kyber key",
        );
        refused(
            check(peer.keys.public_key(), &peer.kyber_public_key, &[]),
            "does not verify under the pinned AK",
        );
        let wrong_signer = other
            .keys
            .sign(&binding_digest(
                &peer.device_id,
                &peer.genesis,
                &peer.kyber_public_key,
            ))
            .unwrap();
        refused(
            check(
                peer.keys.public_key(),
                &peer.kyber_public_key,
                &wrong_signer,
            ),
            "does not verify under the pinned AK",
        );
    }

    fn bearer_transfer(to: [u8; 32]) -> Operation {
        Operation::Transfer {
            policy_commit: [0x0F; 32],
            to_device_id: to.to_vec(),
            amount: Balance::amount(3),
            token_id: b"TOK".to_vec(),
            mode: TransactionMode::Bilateral,
            nonce: vec![1; 8],
            recipient: to.to_vec(),
            to: to.to_vec(),
            message: String::new(),
            signature: Vec::new(),
            authority_policy: Some(crate::types::operations::canonical_offline_bearer_policy()),
        }
    }

    fn credentials(peer: &Peer) -> PeerCredentials<'_> {
        PeerCredentials {
            signing_key: peer.keys.public_key(),
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
        let held = [0x70u8; 32];
        let operation = bearer_transfer([0x43; 32]);
        let commitment =
            BilateralPreCommitment::new(held, operation.clone()).bilateral_commitment_hash;
        let decide = |commitment: [u8; 32], expected_tip: Option<[u8; 32]>, signature: &[u8]| {
            decide_prepare(
                commitment,
                &operation,
                PrepareClaims {
                    expected_tip,
                    credentials: credentials(&sender),
                    signature,
                },
                &sender.pinned(),
                held,
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
        let foreign = BilateralPreCommitment::new(held, bearer_transfer([0x44; 32]))
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
                } => {
                    assert_eq!((e, h), (expected, held))
                }
                other => panic!("expected StaleTip, got {other:?}"),
            }
        }
    }

    /// Offline, only the bearer tier moves value: an online-tier transfer is
    /// refused at the door.
    #[test]
    fn an_online_tier_transfer_is_not_an_offline_operation() {
        let mut online = bearer_transfer([0x45; 32]);
        if let Operation::Transfer {
            authority_policy, ..
        } = &mut online
        {
            *authority_policy = None;
        }
        refused(
            offline_operation(&online.to_bytes()),
            "offline-bearer transfers only",
        );
        offline_operation(&bearer_transfer([0x45; 32]).to_bytes()).expect("a bearer transfer");
        refused(
            offline_operation(&[0xFF, 0x00]),
            "invalid operation payload",
        );
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

        assert_eq!(
            decide(commitment, &receiver.sign_step(&commitment), &challenge)
                .expect("the receiver's own acceptance"),
            Acceptance {
                signature: receiver.sign_step(&commitment),
                receiver_challenge: Some(challenge),
            }
        );
        refused(decide(commitment, &[], &challenge), "carries no signature");
        refused(
            decide(commitment, &other.sign_step(&commitment), &challenge),
            "not signed over its commitment by the pinned AK",
        );
        refused(
            decide([0x55; 32], &receiver.sign_step(&[0x55; 32]), &challenge),
            "names another commitment",
        );
        refused(
            decide(commitment, &receiver.sign_step(&commitment), &[1, 2, 3]),
            "not 32 bytes",
        );
    }
}
