// SPDX-License-Identifier: Apache-2.0

//! AnchorV3 — the owner-signed baseline over the canonical state identity.
//!
//! Rev 15 Def 6.4a. The signed message is
//!
//! ```text
//! m_sig = H(DSM/vault-state-anchor/v3 ‖ 0x00 ‖ c_n)
//! σ     = SPHINCS+.Sign(sk, m_sig)
//! ```
//!
//! and the anchor's **authoritative content is `c_n` and nothing else**. There
//! is no CCB object class for it: one fixed-width digest has no field layout
//! to declare. Generation, reserves, the storage set and the authority
//! position are all fields of the `V_n` that `c_n` identifies — a consumer
//! re-derives every such value from the fetched, re-hashed state and refuses
//! on disagreement. Convenience metadata may travel beside the anchor in
//! transport; it is never a second source of truth.
//!
//! ## What verification here does and does not establish
//!
//! [`verify_anchor_v3_candidate`] performs the **cryptographic check only** —
//! stage 1 of the composition staging. A valid result establishes exactly
//! *"this candidate key signed this exact state commitment"*, and **nothing
//! about whose key it is**. The predecessor artifact's weakness is the
//! caution: an anchor's embedded key proves only that *someone* signed, and
//! anyone can generate a keypair and sign any commitment.
//!
//! Owner authority arrives only at stage 6 of the staging, after the P0–P6
//! identity predicate proves a key `K_proven` and the caller checks
//! `K_cand == K_proven` **byte for byte**. Nothing in this module may be
//! named, logged, or documented as "owner verified" — a verifier that
//! believes it checked the owner when it checked a key is the failure the
//! whole area exists to prevent.
//!
//! ## No V2 path
//!
//! This module has no fallback, no dual-read, and no knowledge of the burned
//! `/v2` tuple. The V2 artifact is deleted when its last consumer flips to
//! the composition staging; nothing here eases that migration, because there
//! is nothing to migrate — a reprovision means no old anchor is valid.

use crate::common::domain_tags::TAG_DSM_VAULT_STATE_ANCHOR_V3;
use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::sphincs::{sphincs_sign, sphincs_verify};
use crate::types::error::DsmError;

/// The signed 32-byte message: `H(DSM/vault-state-anchor/v3 ‖ 0x00 ‖ c_n)`.
///
/// Signing the domain-separated digest rather than a tagged concatenation is
/// the registry §2.9 construction, and matches the shipping idiom
/// (`RecoveryAuthorityAnchor` passes its digest straight to `sphincs_sign`).
pub fn anchor_v3_signing_digest(state_commitment: &[u8; 32]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_VAULT_STATE_ANCHOR_V3);
    h.update(state_commitment);
    *h.finalize().as_bytes()
}

/// An AnchorV3 as it travels: the commitment it binds, the key that claims to
/// have signed it, and the signature.
///
/// `candidate_public_key` is named for what it is at this layer. It is not an
/// owner key until the P0–P6 predicate proves it and the caller enforces the
/// byte-for-byte equality — see the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedVaultStateAnchorV3 {
    /// `c_n = H(DSM/vault-state ‖ CCB(V_n))` — the sole authoritative content.
    pub state_commitment: [u8; 32],
    /// The key presented as having signed. **Candidate, not authority.**
    pub candidate_public_key: Vec<u8>,
    /// SPHINCS+ signature over [`anchor_v3_signing_digest`].
    pub signature: Vec<u8>,
}

/// Sign the baseline for `state_commitment` with the owner's secret key.
pub fn sign_vault_state_anchor_v3(
    state_commitment: &[u8; 32],
    secret_key: &[u8],
    public_key: &[u8],
) -> Result<SignedVaultStateAnchorV3, DsmError> {
    let digest = anchor_v3_signing_digest(state_commitment);
    let signature = sphincs_sign(secret_key, &digest)?;
    Ok(SignedVaultStateAnchorV3 {
        state_commitment: *state_commitment,
        candidate_public_key: public_key.to_vec(),
        signature,
    })
}

/// Stage-1 cryptographic check: does the anchor's candidate key verify over
/// exactly this state commitment?
///
/// A success **integrity-binds the candidate key to `c_n`** and establishes
/// no authority whatsoever. The caller must go on to fetch and re-hash
/// `CCB(V_n)` against `c_n`, discharge P0–P6 at the state's bound authority
/// position, and require the proven key to equal this candidate byte for
/// byte, before reinterpreting this signature as owner-authenticated.
pub fn verify_anchor_v3_candidate(anchor: &SignedVaultStateAnchorV3) -> Result<(), DsmError> {
    let digest = anchor_v3_signing_digest(&anchor.state_commitment);
    let ok = sphincs_verify(&anchor.candidate_public_key, &digest, &anchor.signature)?;
    if !ok {
        return Err(DsmError::verification(
            "anchor v3: candidate signature does not verify over this state commitment",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signatures::SignatureKeyPair;

    fn keypair(seed: u8) -> SignatureKeyPair {
        SignatureKeyPair::generate_from_entropy(&[seed; 32]).expect("keypair")
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let kp = keypair(0x01);
        let c_n = [0xAB; 32];
        let anchor =
            sign_vault_state_anchor_v3(&c_n, &kp.secret_key, &kp.public_key).expect("signs");
        verify_anchor_v3_candidate(&anchor).expect("verifies");
    }

    #[test]
    fn a_tampered_commitment_is_refused() {
        let kp = keypair(0x02);
        let anchor =
            sign_vault_state_anchor_v3(&[0xAB; 32], &kp.secret_key, &kp.public_key).expect("signs");
        let mut tampered = anchor;
        tampered.state_commitment[0] ^= 0x01;
        assert!(verify_anchor_v3_candidate(&tampered).is_err());
    }

    #[test]
    fn a_substituted_key_is_refused() {
        let signer = keypair(0x03);
        let other = keypair(0x04);
        let anchor =
            sign_vault_state_anchor_v3(&[0xAB; 32], &signer.secret_key, &signer.public_key)
                .expect("signs");
        let mut swapped = anchor;
        swapped.candidate_public_key = other.public_key.clone();
        assert!(verify_anchor_v3_candidate(&swapped).is_err());
    }

    /// A valid verification proves possession, not authority: any freshly
    /// generated key can sign any commitment and pass. This test EXPECTS that
    /// to succeed, because the module's contract is the cryptographic check
    /// only — the failure would be a caller treating this as owner
    /// verification, which the composition staging forecloses at stage 6.
    #[test]
    fn any_key_can_produce_a_valid_candidate_anchor() {
        let stranger = keypair(0x05);
        let anchor =
            sign_vault_state_anchor_v3(&[0xCD; 32], &stranger.secret_key, &stranger.public_key)
                .expect("signs");
        verify_anchor_v3_candidate(&anchor)
            .expect("verifies — which is precisely why this alone is never authority");
    }

    /// The signing digest matches an independent recomputation whose domain
    /// tag is typed from the SPEC's domain table, not copied from the code —
    /// the provenance rule from the `DSM/storage-set/v1` miss.
    #[test]
    fn the_signing_digest_matches_the_spec_construction() {
        let c_n = [0x77; 32];
        let mut preimage = b"DSM/vault-state-anchor/v3".to_vec();
        preimage.push(0x00);
        preimage.extend_from_slice(&c_n);
        let expected: [u8; 32] = *blake3::hash(&preimage).as_bytes();
        assert_eq!(anchor_v3_signing_digest(&c_n), expected);
    }

    /// Cross-domain separation: the burned `/v2` domain over the same bytes
    /// yields a different digest, so no signature can be valid under both.
    #[test]
    fn the_burned_v2_domain_does_not_collide() {
        let c_n = [0x77; 32];
        let mut v2_style = b"DSM/vault-state-anchor/v2".to_vec();
        v2_style.push(0x00);
        v2_style.extend_from_slice(&c_n);
        let v2_digest: [u8; 32] = *blake3::hash(&v2_style).as_bytes();
        assert_ne!(anchor_v3_signing_digest(&c_n), v2_digest);
    }
}
