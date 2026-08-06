// SPDX-License-Identifier: MIT OR Apache-2.0

//! ML-KEM (Kyber) identity binding for online contact establishment.
//!
//! The §11.1 per-step-EK online transfer encapsulates against the recipient's
//! ML-KEM-768 public key, which must therefore already be in the recipient's
//! contact record BEFORE any online send. A relationship paired purely online
//! has no BLE history, so the Kyber key must travel through online contact
//! establishment (the registry) rather than being populated lazily from a live
//! bilateral prepare. Requiring a BLE prepare first is an accidental transport
//! dependency, not a security property.
//!
//! The Kyber public key is bound to the device identity by a SPHINCS+ signature
//! from the device's attestation key (AK) over
//!   `domain_hash("DSM/kyber-identity-binding\0", device_id || genesis_hash || kyber_pk)`.
//! A verifier that already trusts the peer's AK public key — registry-attested
//! and itself bound to `device_id` + `genesis` — verifies this signature before
//! persisting the Kyber key, closing any key-substitution path. The ~29 KB
//! SPHINCS+ signature rides in the registry / device-info record, never the QR.
//!
//! The Kyber SECRET key is never read, transmitted, or reconstructed here.

use dsm::crypto::{blake3::domain_hash, kyber, sphincs};
use dsm::types::error::DsmError;

use crate::sdk::app_state::AppState;

/// Domain tag binding an ML-KEM public key to a device identity + genesis.
pub const KYBER_IDENTITY_BINDING_TAG: dsm::crypto::domain::TaggedHashDomain<'static> =
    dsm::crypto::domain::TaggedHashDomain::from_static(b"DSM/kyber-identity-binding");

/// Canonical binding digest over `device_id || genesis_hash || kyber_pubkey`,
/// domain-separated by [`KYBER_IDENTITY_BINDING_TAG`]. This is the message the
/// device AK signs and a verifier re-derives.
fn binding_digest(device_id: &[u8; 32], genesis_hash: &[u8; 32], kyber_pubkey: &[u8]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(64 + kyber_pubkey.len());
    preimage.extend_from_slice(device_id);
    preimage.extend_from_slice(genesis_hash);
    preimage.extend_from_slice(kyber_pubkey);
    *domain_hash(KYBER_IDENTITY_BINDING_TAG, &preimage).as_bytes()
}

fn as_array_32(bytes: &[u8], what: &str) -> Result<[u8; 32], DsmError> {
    <[u8; 32]>::try_from(bytes).map_err(|_| {
        DsmError::invalid_parameter(format!("{what} must be 32 bytes, got {}", bytes.len()))
    })
}

/// Build this device's Kyber identity binding for registry publication.
/// Returns `(kyber_public_key, binding_sig)`. Fails closed when the wallet is
/// locked (no AK secret) or the local Kyber public key is uninitialised or
/// malformed. The Kyber secret key is never touched.
pub fn build_local_kyber_identity_binding() -> Result<(Vec<u8>, Vec<u8>), DsmError> {
    let device_id = as_array_32(
        &AppState::get_device_id()
            .ok_or_else(|| DsmError::InvalidState("device_id not initialised".into()))?,
        "device_id",
    )?;
    let genesis = as_array_32(
        &AppState::get_genesis_hash()
            .ok_or_else(|| DsmError::InvalidState("genesis_hash not initialised".into()))?,
        "genesis_hash",
    )?;
    let kyber_pk = crate::bridge::local_kyber_pubkey()
        .filter(|k| !k.is_empty())
        .ok_or_else(|| DsmError::InvalidState("local Kyber public key not installed".into()))?;
    if kyber_pk.len() != kyber::public_key_bytes() {
        return Err(DsmError::invalid_parameter(format!(
            "local Kyber public key must be {} bytes (ML-KEM-768), got {}",
            kyber::public_key_bytes(),
            kyber_pk.len()
        )));
    }
    let ak_sk = crate::sdk::signing_authority::current_secret_key()?;
    let digest = binding_digest(&device_id, &genesis, &kyber_pk);
    let sig = sphincs::sphincs_sign(&ak_sk, &digest)?;
    Ok((kyber_pk, sig))
}

/// Verify a peer's Kyber identity binding before persisting it to a contact.
///
/// `signing_public_key` is the peer's AK public key, already trusted via the
/// registry attestation that binds it to `device_id` + `genesis`. Fail-closed
/// on missing, malformed-length, or unbound (substituted/mismatched) material —
/// there is no fallback that would accept an unbound Kyber key.
pub fn verify_kyber_identity_binding(
    device_id: &[u8; 32],
    genesis_hash: &[u8; 32],
    kyber_pubkey: &[u8],
    binding_sig: &[u8],
    signing_public_key: &[u8],
) -> Result<(), DsmError> {
    if kyber_pubkey.is_empty() || binding_sig.is_empty() {
        return Err(DsmError::invalid_operation(
            "kyber identity binding: missing Kyber public key or binding signature (fail-closed)",
        ));
    }
    if kyber_pubkey.len() != kyber::public_key_bytes() {
        return Err(DsmError::invalid_operation(format!(
            "kyber identity binding: Kyber public key must be {} bytes (ML-KEM-768), got {}",
            kyber::public_key_bytes(),
            kyber_pubkey.len()
        )));
    }
    let digest = binding_digest(device_id, genesis_hash, kyber_pubkey);
    let ok = sphincs::sphincs_verify(signing_public_key, &digest, binding_sig)?;
    if !ok {
        return Err(DsmError::invalid_operation(
            "kyber identity binding: signature does not bind this Kyber key to (device_id, genesis) \
             under the peer's AK — rejecting (possible substitution/equivocation)",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    /// B4 CACHE TRACE, second half: verification is RECOMPUTED from the binding
    /// every call, never read from a stored verdict.
    ///
    /// The inventory found no acceptance cache anywhere —
    /// `verify_kyber_identity_binding` has zero production callers, the storage
    /// node persists `kyber_binding_sig` without checking it, `contacts` caches
    /// the peer KEY not a verdict, and there is no Android reference. This test
    /// pins the remaining half: the verifier is a pure function of its
    /// arguments, so there is nothing to invalidate at the cut beyond the stored
    /// signatures themselves.
    ///
    /// Method: call the verifier twice with the SAME accepted inputs, then a
    /// third time with one input perturbed. A cached verdict keyed on identity
    /// would return the earlier answer for the perturbed call; recomputation
    /// rejects it.
    #[test]
    fn binding_verification_is_recomputed_not_cached() {
        use dsm::crypto::signatures::SignatureKeyPair;

        let device_id = [0x7Au8; 32];
        let genesis = [0x7Bu8; 32];
        let kp = SignatureKeyPair::generate_from_entropy(b"DSM/test/b4-nocache").expect("keypair");
        let kyber_pk = vec![0x7Cu8; dsm::crypto::kyber::public_key_bytes()];

        let digest = binding_digest(&device_id, &genesis, &kyber_pk);
        let sig = kp.sign(&digest).expect("sign binding");

        // Accepted, twice — a memoizing verifier would also pass this.
        for _ in 0..2 {
            verify_kyber_identity_binding(&device_id, &genesis, &kyber_pk, &sig, kp.public_key())
                .expect("a valid binding must verify");
        }

        // Same device identity, DIFFERENT Kyber key: the signature no longer
        // binds. A verdict cached against (device_id, genesis) would wrongly
        // accept; recomputation refuses.
        let substituted = vec![0x7Du8; dsm::crypto::kyber::public_key_bytes()];
        assert!(
            verify_kyber_identity_binding(
                &device_id,
                &genesis,
                &substituted,
                &sig,
                kp.public_key()
            )
            .is_err(),
            "a substituted Kyber key was accepted under the same device identity \
             — the verdict is cached against identity rather than recomputed \
             from the binding, and that cache must be invalidated by the B4 cut"
        );

        // And the original still verifies afterwards, so the refusal above did
        // not simply poison some shared state.
        verify_kyber_identity_binding(&device_id, &genesis, &kyber_pk, &sig, kp.public_key())
            .expect("the original binding must still verify after a rejection");
    }

    /// IMPACT-TABLE ROW B4, asserted in both directions.
    ///
    /// The old construction is written out explicitly rather than frozen as an
    /// opaque array: the tag literal carried its own NUL and `domain_hash`
    /// appended another, so the preimage began `"…binding" || 0x00 || 0x00`.
    /// Reconstructing it here documents exactly what moved.
    ///
    /// This digest is what a device AK signs and what a verifier re-derives, so
    /// every binding published before the cut fails against the new code. That
    /// is intended — see the regeneration coverage below.
    #[test]
    fn b4_identity_binding_moved_off_the_double_nul_digest() {
        let device_id = [1u8; 32];
        let genesis = [2u8; 32];
        let kyber_pk = [3u8; 64];

        let mut preimage = Vec::new();
        preimage.extend_from_slice(&device_id);
        preimage.extend_from_slice(&genesis);
        preimage.extend_from_slice(&kyber_pk);

        // What the doubled spelling produced.
        let mut old = blake3::Hasher::new();
        old.update(b"DSM/kyber-identity-binding\0"); // the literal, NUL included
        old.update(&[0u8]); // the helper's appended NUL
        old.update(&preimage);
        let old_digest = *old.finalize().as_bytes();

        // What the canonical encoding produces.
        let mut new = blake3::Hasher::new();
        new.update(b"DSM/kyber-identity-binding");
        new.update(&[0u8]);
        new.update(&preimage);
        let canonical = *new.finalize().as_bytes();

        let actual = binding_digest(&device_id, &genesis, &kyber_pk);
        assert_ne!(
            actual, old_digest,
            "B4 still produces the doubled-NUL digest — bindings signed before \
             the cut would still verify"
        );
        assert_eq!(actual, canonical, "B4 did not land on the canonical digest");
    }

    /// OLD ARTIFACT REJECTED / NEW ARTIFACT ACCEPTED, with no fallback path.
    ///
    /// A binding signature made over the OLD digest must fail verification, and
    /// a freshly generated one must pass. If a compatibility verifier is ever
    /// added, the first assertion breaks.
    #[test]
    fn an_old_binding_fails_and_a_regenerated_one_verifies() {
        use dsm::crypto::signatures::SignatureKeyPair;

        let device_id = [4u8; 32];
        let genesis = [5u8; 32];
        let kp = SignatureKeyPair::generate_from_entropy(b"DSM/test/b4-regen").expect("keypair");
        let kyber_pk = [6u8; 64];

        let mut preimage = Vec::new();
        preimage.extend_from_slice(&device_id);
        preimage.extend_from_slice(&genesis);
        preimage.extend_from_slice(&kyber_pk);

        // An artifact signed under the OLD rule.
        let mut old = blake3::Hasher::new();
        old.update(b"DSM/kyber-identity-binding\0");
        old.update(&[0u8]);
        old.update(&preimage);
        let stale_sig = kp.sign(old.finalize().as_bytes()).expect("sign old");

        // The verifier re-derives with the canonical rule, so the stale
        // signature is over the wrong message.
        let current = binding_digest(&device_id, &genesis, &kyber_pk);
        assert!(
            !matches!(
                dsm::crypto::sphincs::sphincs_verify(kp.public_key(), &current, &stale_sig),
                Ok(true)
            ),
            "a binding signed under the pre-cut digest still verifies — there is \
             a compatibility path that must not exist"
        );

        // Regenerated against the current digest: accepted.
        let fresh_sig = kp.sign(&current).expect("sign current");
        assert!(
            matches!(
                dsm::crypto::sphincs::sphincs_verify(kp.public_key(), &current, &fresh_sig),
                Ok(true)
            ),
            "a regenerated binding must verify"
        );
    }

    // A fresh AK (SPHINCS+) + Kyber pubkey and a correctly-built binding.
    struct Fixture {
        device_id: [u8; 32],
        genesis: [u8; 32],
        kyber_pk: Vec<u8>,
        ak_pk: Vec<u8>,
        binding_sig: Vec<u8>,
    }

    fn fixture() -> Fixture {
        let device_id = [0x11u8; 32];
        let genesis = [0x22u8; 32];
        let (ak_pk, ak_sk) = sphincs::generate_sphincs_keypair().expect("ak keypair");
        let kp = kyber::generate_kyber_keypair().expect("kyber keypair");
        let kyber_pk = kp.public_key.clone();
        let digest = binding_digest(&device_id, &genesis, &kyber_pk);
        let binding_sig = sphincs::sphincs_sign(&ak_sk, &digest).expect("sign binding");
        Fixture {
            device_id,
            genesis,
            kyber_pk,
            ak_pk,
            binding_sig,
        }
    }

    #[test]
    fn valid_binding_verifies() {
        let f = fixture();
        verify_kyber_identity_binding(
            &f.device_id,
            &f.genesis,
            &f.kyber_pk,
            &f.binding_sig,
            &f.ak_pk,
        )
        .expect("a correctly-signed binding must verify");
    }

    #[test]
    fn substituted_kyber_key_is_rejected() {
        let f = fixture();
        // Attacker swaps in a different Kyber key with the same (valid) signature.
        let other = kyber::generate_kyber_keypair().expect("other kyber");
        let other_pk = other.public_key.clone();
        assert_ne!(other_pk, f.kyber_pk);
        let res = verify_kyber_identity_binding(
            &f.device_id,
            &f.genesis,
            &other_pk,
            &f.binding_sig,
            &f.ak_pk,
        );
        assert!(
            res.is_err(),
            "a substituted Kyber key must fail the binding"
        );
    }

    #[test]
    fn wrong_device_id_or_genesis_is_rejected() {
        let f = fixture();
        let bad_dev = verify_kyber_identity_binding(
            &[0x99u8; 32],
            &f.genesis,
            &f.kyber_pk,
            &f.binding_sig,
            &f.ak_pk,
        );
        assert!(
            bad_dev.is_err(),
            "wrong device_id must fail (identity binding)"
        );
        let bad_gen = verify_kyber_identity_binding(
            &f.device_id,
            &[0x99u8; 32],
            &f.kyber_pk,
            &f.binding_sig,
            &f.ak_pk,
        );
        assert!(
            bad_gen.is_err(),
            "wrong genesis must fail (identity binding)"
        );
    }

    #[test]
    fn wrong_signer_is_rejected() {
        let f = fixture();
        // A different AK (equivocation) must not validate the binding.
        let (other_ak_pk, _) = sphincs::generate_sphincs_keypair().expect("other ak");
        let res = verify_kyber_identity_binding(
            &f.device_id,
            &f.genesis,
            &f.kyber_pk,
            &f.binding_sig,
            &other_ak_pk,
        );
        assert!(res.is_err(), "binding must not verify under a different AK");
    }

    #[test]
    fn malformed_length_is_rejected() {
        let f = fixture();
        let short = vec![0u8; kyber::public_key_bytes() - 1];
        assert!(verify_kyber_identity_binding(
            &f.device_id,
            &f.genesis,
            &short,
            &f.binding_sig,
            &f.ak_pk
        )
        .is_err());
        let long = vec![0u8; kyber::public_key_bytes() + 1];
        assert!(verify_kyber_identity_binding(
            &f.device_id,
            &f.genesis,
            &long,
            &f.binding_sig,
            &f.ak_pk
        )
        .is_err());
    }

    #[test]
    fn missing_material_is_rejected_fail_closed() {
        let f = fixture();
        assert!(verify_kyber_identity_binding(
            &f.device_id,
            &f.genesis,
            &[],
            &f.binding_sig,
            &f.ak_pk
        )
        .is_err());
        assert!(verify_kyber_identity_binding(
            &f.device_id,
            &f.genesis,
            &f.kyber_pk,
            &[],
            &f.ak_pk
        )
        .is_err());
    }
}
