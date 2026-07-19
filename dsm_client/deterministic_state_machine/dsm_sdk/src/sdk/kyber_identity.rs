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
pub const KYBER_IDENTITY_BINDING_TAG: &str = "DSM/kyber-identity-binding\0";

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
