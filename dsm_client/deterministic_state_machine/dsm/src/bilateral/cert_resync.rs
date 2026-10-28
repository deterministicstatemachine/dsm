// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cert resync: the jointly authorized restart of a relationship's per-step
//! EK cert chain after one side lost its chain state.
//!
//! Both devices compute one joint statement over the relationship, the
//! accepted tip both agree on, an epoch and the preserved acceptance
//! commitment. Each AK signs that statement bound to the key it asserts: the
//! initiator its fresh EK, the responder its unchanged Local head. This module
//! holds what both sides compute identically: the statement, the bytes an AK
//! signs, the cosignature check and the epoch rule. The head writes, the send
//! gate, the pending-obligation guard and the audit row are each device's own
//! state, and are the SDK's.

use crate::common::domain_tags::TAG_DSM_CERT_RESTART;
use crate::crypto::sphincs::{public_key_bytes, signature_bytes, sphincs_verify, SphincsVariant};
use crate::types::error::DsmError;

/// The joint restart statement both AKs sign:
/// `BLAKE3("DSM/cert-restart/v1" ‖ 0x00 ‖ relationship ‖ agreed tip ‖ epoch
/// (i64, little-endian) ‖ preserved acceptance commitment)`. It binds the
/// restart to the relationship, the agreed accepted tip, the epoch and the
/// preserved commitment, so a signature for one restart cannot be replayed
/// for another.
pub fn compute_joint_auth_hash(
    relationship_key: &[u8; 32],
    agreed_tip: &[u8; 32],
    epoch: i64,
    preserved_acceptance_commitment: &[u8; 32],
) -> [u8; 32] {
    let mut h = crate::crypto::blake3::dsm_domain_hasher(TAG_DSM_CERT_RESTART);
    h.update(relationship_key);
    h.update(agreed_tip);
    h.update(&epoch.to_le_bytes());
    h.update(preserved_acceptance_commitment);
    *h.finalize().as_bytes()
}

/// The bytes an AK signs: the joint statement followed by the key the signer
/// asserts, so a signature authorizes exactly that key.
pub fn cert_resync_signing_target(joint_auth_hash: &[u8; 32], asserted_key: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(32 + asserted_key.len());
    v.extend_from_slice(joint_auth_hash);
    v.extend_from_slice(asserted_key);
    v
}

/// Why a cert-resync cosignature is refused. Each is its own reason: a key
/// that is not a key is never reported as a signature that does not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CosignatureRefusal {
    /// The signer's AK is not an SPX256f public key.
    MalformedKey { len: usize },
    /// The cosignature is not an SPX256f signature.
    MalformedSignature { len: usize },
    /// A well-formed signature that does not verify under the signer's AK
    /// over the statement bound to the asserted key.
    DoesNotVerify,
    /// The verifier refused its inputs.
    VerifierError(String),
}

impl std::fmt::Display for CosignatureRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedKey { len } => write!(
                f,
                "the signer's AK is {len} bytes, not an SPX256f public key ({})",
                public_key_bytes(SphincsVariant::SPX256f)
            ),
            Self::MalformedSignature { len } => write!(
                f,
                "the cosignature is {len} bytes, not an SPX256f signature ({})",
                signature_bytes(SphincsVariant::SPX256f)
            ),
            Self::DoesNotVerify => write!(
                f,
                "the cosignature does not verify under the signer's AK over the joint \
                 statement bound to the asserted key"
            ),
            Self::VerifierError(e) => write!(f, "the cosignature could not be verified: {e}"),
        }
    }
}

/// A resync cosignature: `signer_ak` signed `joint_auth_hash` bound to
/// `asserted_key` — the initiator's AK over its fresh EK in a request, the
/// responder's AK over its Local head in an ack.
pub fn verify_cert_resync_cosignature(
    signer_ak: &[u8],
    joint_auth_hash: &[u8; 32],
    asserted_key: &[u8],
    signature: &[u8],
) -> Result<(), CosignatureRefusal> {
    if signer_ak.len() != public_key_bytes(SphincsVariant::SPX256f) {
        return Err(CosignatureRefusal::MalformedKey {
            len: signer_ak.len(),
        });
    }
    if signature.len() != signature_bytes(SphincsVariant::SPX256f) {
        return Err(CosignatureRefusal::MalformedSignature {
            len: signature.len(),
        });
    }
    let verified = sphincs_verify(
        signer_ak,
        &cert_resync_signing_target(joint_auth_hash, asserted_key),
        signature,
    )
    .map_err(|e| CosignatureRefusal::VerifierError(e.to_string()))?;
    if !verified {
        return Err(CosignatureRefusal::DoesNotVerify);
    }
    Ok(())
}

/// A resync's epoch is strictly greater than the last one the relationship
/// recorded, so a captured request cannot re-apply.
pub fn cert_resync_epoch_advances(epoch: i64, last_epoch: i64) -> Result<(), DsmError> {
    if epoch <= last_epoch {
        return Err(DsmError::invalid_operation(format!(
            "cert resync epoch {epoch} is not greater than the last, {last_epoch}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sphincs::{generate_keypair_from_seed, sphincs_sign, SphincsKeyPair};

    /// The joint statement and the bytes an AK signs, on fixed inputs, are the
    /// bytes `b3sum` gives for `"DSM/cert-restart/v1" ‖ 0x00 ‖ relationship ‖
    /// agreed tip ‖ epoch (i64, little-endian) ‖ preserved commitment`, and
    /// that digest followed by the asserted key.
    #[test]
    fn the_joint_statement_and_its_signing_target_are_the_pinned_bytes() {
        const JOINT: [u8; 32] = [
            0x14, 0x4C, 0x79, 0x70, 0x92, 0x33, 0x57, 0x62, 0x17, 0xAB, 0xD8, 0xA2, 0xB7, 0x9F,
            0x02, 0xA1, 0x28, 0x82, 0x9E, 0x3A, 0x43, 0xC6, 0x7A, 0x02, 0x27, 0x86, 0x45, 0x84,
            0x68, 0x60, 0x6A, 0x20,
        ];
        let joint = compute_joint_auth_hash(&[0x11u8; 32], &[0x22u8; 32], 7, &[0x33u8; 32]);
        assert_eq!(joint, JOINT);
        let key = [0x44u8; 64];
        let mut signed = JOINT.to_vec();
        signed.extend_from_slice(&key);
        assert_eq!(cert_resync_signing_target(&joint, &key), signed);
    }

    /// The joint auth hash binds all four fields — changing any one changes it.
    #[test]
    fn joint_auth_hash_binds_every_field() {
        let base = compute_joint_auth_hash(&[1u8; 32], &[2u8; 32], 3, &[4u8; 32]);
        assert_ne!(
            base,
            compute_joint_auth_hash(&[9u8; 32], &[2u8; 32], 3, &[4u8; 32])
        );
        assert_ne!(
            base,
            compute_joint_auth_hash(&[1u8; 32], &[9u8; 32], 3, &[4u8; 32])
        );
        assert_ne!(
            base,
            compute_joint_auth_hash(&[1u8; 32], &[2u8; 32], 9, &[4u8; 32])
        );
        assert_ne!(
            base,
            compute_joint_auth_hash(&[1u8; 32], &[2u8; 32], 3, &[9u8; 32])
        );
    }

    /// RULE-1 LAYER PROOF for B3: the statement is not the digest the
    /// doubled-NUL spelling produced, and it is the canonical encoding of the
    /// same inputs.
    #[test]
    fn b3_joint_auth_hash_is_frozen_across_the_delimiter_cut() {
        // The digest the doubled-NUL spelling produced. Every joint statement
        // signed before the cut derives from this construction.
        const B3_OLD_DOUBLE_NUL: [u8; 32] = [
            2, 162, 118, 237, 87, 134, 5, 64, 174, 142, 255, 231, 182, 55, 197, 122, 60, 88, 137,
            28, 18, 176, 28, 124, 173, 84, 137, 120, 1, 194, 66, 127,
        ];
        let h = compute_joint_auth_hash(&[1u8; 32], &[2u8; 32], 7, &[3u8; 32]);
        assert_ne!(
            h, B3_OLD_DOUBLE_NUL,
            "B3 still produces the doubled-NUL digest — the cut did not take, and \
             statements signed before it would still verify"
        );
        let mut canonical = crate::crypto::blake3::tagged_hasher(TAG_DSM_CERT_RESTART);
        canonical.update(&[1u8; 32]);
        canonical.update(&[2u8; 32]);
        canonical.update(&7i64.to_le_bytes());
        canonical.update(&[3u8; 32]);
        assert_eq!(
            h,
            *canonical.finalize().as_bytes(),
            "B3 did not land on the canonical digest"
        );
    }

    fn ak(seed: u8) -> SphincsKeyPair {
        generate_keypair_from_seed(SphincsVariant::SPX256f, &[seed; 32]).expect("an AK")
    }

    /// B3 old-artifact rejection, new-artifact acceptance, for both parties.
    /// The joint restart statement is signed by BOTH AKs, so two real AKs sign
    /// it: a statement signed before the delimiter cut is refused for either,
    /// and the regenerated one verifies for each, so the refusals are not a
    /// verifier that refuses everything.
    #[test]
    fn old_joint_statements_fail_and_regenerated_ones_verify_for_both_aks() {
        let (rel, tip, epoch, preserved) = ([0x31u8; 32], [0x32u8; 32], 9i64, [0x33u8; 32]);
        let ek = [0x34u8; 64];
        let (local, peer) = (ak(0x41), ak(0x42));

        // The PRE-CUT joint statement: the literal carried its own NUL and
        // the hasher appended another.
        let mut old = blake3::Hasher::new();
        old.update(b"DSM/cert-restart/v1\0");
        old.update(&[0x00]);
        old.update(&rel);
        old.update(&tip);
        old.update(&epoch.to_le_bytes());
        old.update(&preserved);
        let old_joint: [u8; 32] = *old.finalize().as_bytes();
        let joint = compute_joint_auth_hash(&rel, &tip, epoch, &preserved);
        assert_ne!(old_joint, joint);

        for (who, kp) in [("local", &local), ("peer", &peer)] {
            let stale = sphincs_sign(&kp.secret_key, &cert_resync_signing_target(&old_joint, &ek))
                .expect("sign the pre-cut statement");
            assert_eq!(
                verify_cert_resync_cosignature(&kp.public_key, &joint, &ek, &stale),
                Err(CosignatureRefusal::DoesNotVerify),
                "the {who} AK's pre-cut joint signature still verifies"
            );
            let fresh = sphincs_sign(&kp.secret_key, &cert_resync_signing_target(&joint, &ek))
                .expect("sign the statement");
            if let Err(e) = verify_cert_resync_cosignature(&kp.public_key, &joint, &ek, &fresh) {
                panic!("the {who} AK's regenerated signature: {e}");
            }
        }
    }

    /// A cosignature authorizes exactly its statement and its asserted key,
    /// under exactly its signer's AK. Another key asserted, another statement
    /// or another signer does not verify; a key that is not an SPX256f public
    /// key and a signature that is not an SPX256f signature are each refused
    /// as what they are, never as a signature that does not verify.
    #[test]
    fn a_cosignature_verifies_only_for_its_statement_key_and_signer() {
        let (initiator, other) = (ak(0x51), ak(0x52));
        let joint = compute_joint_auth_hash(&[0x61u8; 32], &[0x62u8; 32], 4, &[0x63u8; 32]);
        let fresh_ek = [0x64u8; 64];
        let sig = sphincs_sign(
            &initiator.secret_key,
            &cert_resync_signing_target(&joint, &fresh_ek),
        )
        .expect("the initiator's cosignature");
        verify_cert_resync_cosignature(&initiator.public_key, &joint, &fresh_ek, &sig)
            .expect("the cosignature over its own statement and key");

        let replayed = compute_joint_auth_hash(&[0x61u8; 32], &[0x62u8; 32], 5, &[0x63u8; 32]);
        for (label, signer, statement, key) in [
            (
                "another asserted key",
                &initiator.public_key,
                &joint,
                &[0x65u8; 64],
            ),
            (
                "another statement",
                &initiator.public_key,
                &replayed,
                &fresh_ek,
            ),
            ("another signer", &other.public_key, &joint, &fresh_ek),
        ] {
            assert_eq!(
                verify_cert_resync_cosignature(signer, statement, key, &sig),
                Err(CosignatureRefusal::DoesNotVerify),
                "{label}"
            );
        }

        let short_key = &initiator.public_key[1..];
        assert_eq!(
            verify_cert_resync_cosignature(short_key, &joint, &fresh_ek, &sig),
            Err(CosignatureRefusal::MalformedKey {
                len: short_key.len()
            })
        );
        let short_sig = &sig[1..];
        assert_eq!(
            verify_cert_resync_cosignature(&initiator.public_key, &joint, &fresh_ek, short_sig),
            Err(CosignatureRefusal::MalformedSignature {
                len: short_sig.len()
            })
        );
    }

    /// An epoch is taken only past the last one recorded: the last itself and
    /// anything below it are refused, and the next is taken.
    #[test]
    fn an_epoch_is_taken_only_past_the_last() {
        for stale in [i64::MIN, 4, 5] {
            let err = cert_resync_epoch_advances(stale, 5).expect_err("a stale epoch");
            assert!(err.to_string().contains("not greater"), "{stale}: {err}");
        }
        cert_resync_epoch_advances(6, 5).expect("the next epoch");
        cert_resync_epoch_advances(i64::MAX, 5).expect("any later epoch");
    }
}
