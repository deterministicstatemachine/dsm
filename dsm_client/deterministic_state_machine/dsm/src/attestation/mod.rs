// SPDX-License-Identifier: MIT OR Apache-2.0
//! Offline-bearer secure-element attestation (anti-clone island binding).
//!
//! Implements the verifier side of the attested-device-identity anti-clone
//! mechanism (`.github/instructions/dsm_anticlone.instructions.md`). An offline
//! bearer transition is bound to a hardware secure element ("island") the owner
//! cannot rewrite: the island signs the transition's canonical intent challenge,
//! and the verifier checks that signature against a pinned device identity and a
//! pinned vendor production root. A perfect bit copy on different silicon holds the
//! seed and keys but not the island's non-extractable key, so it cannot produce the
//! signature and cannot continue an offline-bearer lineage.
//!
//! The island uses classical signatures (the device's own keys); see
//! [`crate::crypto::classical_verify`] for the scoped classical exception. DSM's own
//! protocol crypto remains post-quantum (BLAKE3 / SPHINCS+ / ML-KEM).
//!
//! [`verify_island_attestation`] is the Rust port of the vendor's
//! `verify_authentication_response`, restricted to the Trezor Safe 7 production
//! roots so a development device is rejected by construction.

use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::classical_verify::{
    ed25519_pubkey_from_spki, verify_ecdsa_p256_sha256, verify_ecdsa_p256_sha256_sec1,
    verify_ed25519,
};
use crate::types::error::DsmError;
use sha2::{Digest, Sha256};
use x509_parser::certificate::X509Certificate;
use x509_parser::oid_registry::{
    OID_KEY_TYPE_EC_PUBLIC_KEY, OID_SIG_ECDSA_WITH_SHA256, OID_SIG_ED25519,
};
use x509_parser::prelude::FromDer;

/// The AuthenticateDevice framing header used by the device host protocol. The island
/// signs `len(header) || header || len(challenge) || challenge`.
pub const AUTHENTICATE_DEVICE_HEADER: &[u8] = b"AuthenticateDevice:";

/// Pinned Trezor Safe 7 (T3W1) production root public keys (from the vendor verifier's
/// ROOT_PUBLIC_KEYS). P-256 keys are SEC1 uncompressed points (65 bytes); Ed25519 keys
/// are raw (32 bytes). Only production roots are pinned, so a development or staging
/// device is rejected by construction.
const SAFE7_P256_ROOTS: [&[u8]; 2] = [
    include_bytes!("roots/safe7_p256_prod.bin"),
    include_bytes!("roots/safe7_p256_prod_backup.bin"),
];
const SAFE7_ED25519_ROOTS: [&[u8]; 2] = [
    include_bytes!("roots/safe7_ed25519_prod.bin"),
    include_bytes!("roots/safe7_ed25519_prod_backup.bin"),
];

/// Build the framed message the island signs for a given challenge. `challenge` is the
/// DSM canonical intent hash; the island wraps it with the fixed AuthenticateDevice
/// framing. Strict-fail if either part cannot be single-byte length-prefixed.
pub fn frame_authenticate_device(challenge: &[u8]) -> Result<Vec<u8>, DsmError> {
    if AUTHENTICATE_DEVICE_HEADER.len() > u8::MAX as usize || challenge.len() > u8::MAX as usize {
        return Err(DsmError::verification(
            "attestation: challenge or header too long to length-prefix",
        ));
    }
    let mut framed = Vec::with_capacity(2 + AUTHENTICATE_DEVICE_HEADER.len() + challenge.len());
    framed.push(AUTHENTICATE_DEVICE_HEADER.len() as u8);
    framed.extend_from_slice(AUTHENTICATE_DEVICE_HEADER);
    framed.push(challenge.len() as u8);
    framed.extend_from_slice(challenge);
    Ok(framed)
}

/// The stable per-device island identity: SHA-256 of the leaf SubjectPublicKeyInfo
/// DER. This matches the external vendor verifier and is the value DSM pins and folds
/// into the offline-bearer chain tip. (SHA-256 here is for external identity
/// compatibility; DSM's own canonical hashing uses domain-separated BLAKE3.)
pub fn id_island_from_spki(spki_der: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(spki_der);
    let digest = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&digest);
    id
}

/// Domain tag for the offline-bearer island attestation intent challenge.
pub const ISLAND_ATTESTATION_DOMAIN: &str = "DSM/offline-bearer/island-attestation/v1";

/// Build the canonical intent challenge the island signs for an offline-bearer transition.
///
/// Binding the full intent (not just `h_n`) is what prevents a hostile host reusing one
/// island approval across a different payload. The result is the 32-byte value handed to the
/// device's AuthenticateDevice operation as the challenge (the device then wraps it with
/// [`frame_authenticate_device`]). `expiry_tick` is a DETERMINISTIC tick / state-index bound,
/// never wall-clock: DSM is clockless and this value folds into a signed commitment.
#[allow(clippy::too_many_arguments)]
pub fn dsm_island_challenge(
    h_n: &[u8; 32],
    payload_hash: &[u8; 32],
    relationship_id: &[u8; 32],
    device_id: &[u8; 32],
    value_capability: u8,
    offline_bearer_mode: u8,
    nonce: &[u8],
    expiry_tick: u64,
) -> [u8; 32] {
    let mut hasher = dsm_domain_hasher(ISLAND_ATTESTATION_DOMAIN);
    hasher.update(h_n);
    hasher.update(payload_hash);
    hasher.update(relationship_id);
    hasher.update(device_id);
    hasher.update(&[value_capability, offline_bearer_mode]);
    hasher.update(&(nonce.len() as u32).to_le_bytes());
    hasher.update(nonce);
    hasher.update(&expiry_tick.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn parse_cert(der: &[u8]) -> Result<X509Certificate<'_>, DsmError> {
    X509Certificate::from_der(der)
        .map(|(_, cert)| cert)
        .map_err(|_| DsmError::verification("attestation: malformed certificate"))
}

fn ed25519_sig_array(sig: &[u8]) -> Result<[u8; 64], DsmError> {
    sig.try_into()
        .map_err(|_| DsmError::verification("attestation: Ed25519 signature is not 64 bytes"))
}

/// Verify a signature over `message` using a SubjectPublicKeyInfo and a signature
/// algorithm OID to select the scheme (Ed25519 raw, or ECDSA P-256 / SHA-256 DER).
fn verify_by_spki(
    spki_der: &[u8],
    sig_alg: &x509_parser::der_parser::Oid,
    message: &[u8],
    signature: &[u8],
) -> Result<(), DsmError> {
    if *sig_alg == OID_SIG_ED25519 {
        let pubkey = ed25519_pubkey_from_spki(spki_der)?;
        verify_ed25519(&pubkey, message, &ed25519_sig_array(signature)?)
    } else if *sig_alg == OID_SIG_ECDSA_WITH_SHA256 {
        verify_ecdsa_p256_sha256(spki_der, message, signature)
    } else {
        Err(DsmError::verification(
            "attestation: unsupported certificate signature algorithm",
        ))
    }
}

/// Check that `issuer` is a valid CA permitted to sign at the current path length:
/// keyUsage.keyCertSign set, basicConstraints.cA set, and pathLenConstraint present
/// and not exceeded.
fn check_ca(issuer: &X509Certificate, path_len: usize) -> Result<(), DsmError> {
    let key_cert_sign = issuer
        .key_usage()
        .ok()
        .flatten()
        .map(|ku| ku.value.key_cert_sign())
        .unwrap_or(false);
    if !key_cert_sign {
        return Err(DsmError::verification(
            "attestation: issuer certificate lacks keyCertSign",
        ));
    }
    let bc = issuer
        .basic_constraints()
        .ok()
        .flatten()
        .ok_or_else(|| DsmError::verification("attestation: issuer missing BasicConstraints"))?;
    if !bc.value.ca {
        return Err(DsmError::verification(
            "attestation: issuer is not a CA (cA flag unset)",
        ));
    }
    let plc = bc.value.path_len_constraint.ok_or_else(|| {
        DsmError::verification("attestation: issuer missing pathLenConstraint")
    })?;
    if (plc as usize) < path_len {
        return Err(DsmError::verification(
            "attestation: issuer pathLenConstraint exceeded",
        ));
    }
    Ok(())
}

/// Verify the top certificate is signed by a pinned Safe 7 production root.
fn verify_signed_by_pinned_root(top: &X509Certificate) -> Result<(), DsmError> {
    let tbs = top.tbs_certificate.as_ref();
    let sig = top.signature_value.as_ref();
    let alg = &top.signature_algorithm.algorithm;
    if *alg == OID_SIG_ED25519 {
        let sig_arr = ed25519_sig_array(sig)?;
        for root in SAFE7_ED25519_ROOTS {
            if let Ok(root_arr) = <[u8; 32]>::try_from(root) {
                if verify_ed25519(&root_arr, tbs, &sig_arr).is_ok() {
                    return Ok(());
                }
            }
        }
        Err(DsmError::verification(
            "attestation: top certificate not signed by a pinned Safe 7 Ed25519 production root",
        ))
    } else if *alg == OID_SIG_ECDSA_WITH_SHA256 {
        for root in SAFE7_P256_ROOTS {
            if verify_ecdsa_p256_sha256_sec1(root, tbs, sig).is_ok() {
                return Ok(());
            }
        }
        Err(DsmError::verification(
            "attestation: top certificate not signed by a pinned Safe 7 P-256 production root",
        ))
    } else {
        Err(DsmError::verification(
            "attestation: unsupported top certificate signature algorithm",
        ))
    }
}

/// Verify an offline-bearer island attestation. The leaf signs the framed challenge, the
/// certificate chain links leaf to issuer(s), and the top certificate is signed by a
/// pinned Trezor Safe 7 production root. Returns the pinned device identity
/// (`id_island`) on success. Development devices are rejected because only production
/// roots are pinned.
pub fn verify_island_attestation(
    challenge: &[u8],
    signature: &[u8],
    cert_chain: &[&[u8]],
) -> Result<[u8; 32], DsmError> {
    if cert_chain.is_empty() {
        return Err(DsmError::verification("attestation: empty certificate chain"));
    }
    let framed = frame_authenticate_device(challenge)?;

    let leaf = parse_cert(cert_chain[0])?;
    let leaf_spki = leaf.public_key().raw;
    let leaf_key_alg = &leaf.public_key().algorithm.algorithm;

    // 1) Challenge binding: the leaf's own key signs the framed challenge.
    if *leaf_key_alg == OID_SIG_ED25519 {
        let pubkey = ed25519_pubkey_from_spki(leaf_spki)?;
        verify_ed25519(&pubkey, &framed, &ed25519_sig_array(signature)?)?;
    } else if *leaf_key_alg == OID_KEY_TYPE_EC_PUBLIC_KEY {
        verify_ecdsa_p256_sha256(leaf_spki, &framed, signature)?;
    } else {
        return Err(DsmError::verification("attestation: unsupported leaf key type"));
    }

    let id_island = id_island_from_spki(leaf_spki);

    // 2) Walk the chain: each issuer must name the child, be a valid CA, and sign it.
    let mut child = leaf;
    for (path_len, issuer_der) in cert_chain[1..].iter().enumerate() {
        let issuer = parse_cert(issuer_der)?;
        if issuer.subject() != child.issuer() {
            return Err(DsmError::verification(
                "attestation: certificate issuer name mismatch",
            ));
        }
        check_ca(&issuer, path_len)?;
        verify_by_spki(
            issuer.public_key().raw,
            &child.signature_algorithm.algorithm,
            child.tbs_certificate.as_ref(),
            child.signature_value.as_ref(),
        )?;
        child = issuer;
    }

    // 3) The top certificate must be signed by a pinned Safe 7 production root.
    verify_signed_by_pinned_root(&child)?;

    Ok(id_island)
}

/// The full offline-bearer intent an island signs for one transition. These are exactly
/// the fields folded into [`dsm_island_challenge`]; bundling them keeps the per-transition
/// gate call honest (a hostile host cannot swap one approved field for another after the
/// island has signed).
#[derive(Clone, Copy, Debug)]
pub struct IslandIntent<'a> {
    /// Prior chain tip `h_n` the transition extends.
    pub h_n: &'a [u8; 32],
    /// Hash of the transition payload.
    pub payload_hash: &'a [u8; 32],
    /// Relationship identifier.
    pub relationship_id: &'a [u8; 32],
    /// Acting device identifier.
    pub device_id: &'a [u8; 32],
    /// Value-capability commit tag at this transition.
    pub value_capability: u8,
    /// Offline-bearer mode tag.
    pub offline_bearer_mode: u8,
    /// Per-transition nonce.
    pub nonce: &'a [u8],
    /// Deterministic expiry tick (clockless), never wall-clock.
    pub expiry_tick: u64,
}

impl IslandIntent<'_> {
    /// The 32-byte canonical challenge for this intent (see [`dsm_island_challenge`]).
    pub fn challenge(&self) -> [u8; 32] {
        dsm_island_challenge(
            self.h_n,
            self.payload_hash,
            self.relationship_id,
            self.device_id,
            self.value_capability,
            self.offline_bearer_mode,
            self.nonce,
            self.expiry_tick,
        )
    }
}

/// Verify an island's Ed25519 signature over one transition intent, given the island's
/// leaf SubjectPublicKeyInfo. Recomputes the canonical challenge from the bound intent,
/// frames it exactly as the device firmware does, and checks the signature. On success
/// returns the pinned island identity `id_island = SHA-256(leaf SPKI)` so the caller can
/// confirm it matches the admitted island. The binding element is TROPIC01 (Ed25519,
/// spec §10); the heavier certificate-chain-to-root proof is the admission-time
/// [`verify_island_attestation`], not repeated per transition.
pub fn verify_island_intent_signature(
    leaf_spki_der: &[u8],
    intent: &IslandIntent,
    signature: &[u8],
) -> Result<[u8; 32], DsmError> {
    let challenge = intent.challenge();
    let framed = frame_authenticate_device(&challenge)?;
    let pubkey = ed25519_pubkey_from_spki(leaf_spki_der)?;
    verify_ed25519(&pubkey, &framed, &ed25519_sig_array(signature)?)?;
    Ok(id_island_from_spki(leaf_spki_der))
}

/// Which settlement path an offline-bearer-eligible transition takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettlementPath {
    /// The optional offline-bearer authority path: a genuine admitted island signed this
    /// exact intent. Usable offline with no online check.
    OfflineBearer,
    /// The existing online-checked settlement path. Used whenever offline-bearer authority
    /// is not requested, not admitted, or its proof is absent or invalid. Fail-closed but
    /// never a hard reject: a failed attestation forecloses the offline path only — the
    /// transaction still settles online.
    OnlineFallback,
}

/// Decide the settlement path for a transition. Offline-bearer authority is granted ONLY
/// when it is requested, the device's island is PROVEN `Attested`, and the island's
/// signature over this exact intent verifies. Every other case falls back to the
/// online-checked path — deny-unless-proven, never a hard reject of the transaction.
pub fn decide_settlement_path(
    requesting_offline_bearer: bool,
    capability: crate::types::device_state::OfflineBearerAttestation,
    island_signature_ok: bool,
) -> SettlementPath {
    if requesting_offline_bearer && capability.permits_offline_bearer() && island_signature_ok {
        SettlementPath::OfflineBearer
    } else {
        SettlementPath::OnlineFallback
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real captured AuthenticateDevice vectors from a genuine Trezor Safe 7 (T3W1),
    // independently verified AUTHENTIC by trezorlib's own verifier against the Trezor
    // production root (devel = false, both legs, challenge bound).
    const CHALLENGE: &[u8] = include_bytes!("test_vectors/challenge.bin");
    const TROPIC_SIG: &[u8] = include_bytes!("test_vectors/tropic_sig.bin");
    const TROPIC_SPKI: &[u8] = include_bytes!("test_vectors/tropic_leaf_spki.der");
    const TROPIC_ID: &[u8] = include_bytes!("test_vectors/tropic_id.bin");
    const TROPIC_CERT0: &[u8] = include_bytes!("test_vectors/tropic_cert0.der");
    const TROPIC_CERT1: &[u8] = include_bytes!("test_vectors/tropic_cert1.der");
    const OPTIGA_SIG: &[u8] = include_bytes!("test_vectors/optiga_sig.bin");
    const OPTIGA_SPKI: &[u8] = include_bytes!("test_vectors/optiga_leaf_spki.der");
    const OPTIGA_ID: &[u8] = include_bytes!("test_vectors/optiga_id.bin");
    const OPTIGA_CERT0: &[u8] = include_bytes!("test_vectors/optiga_cert0.der");
    const OPTIGA_CERT1: &[u8] = include_bytes!("test_vectors/optiga_cert1.der");

    #[test]
    fn tropic_ed25519_challenge_binds_over_frame() {
        let framed = frame_authenticate_device(CHALLENGE).expect("frame");
        let pubkey = ed25519_pubkey_from_spki(TROPIC_SPKI).expect("ed25519 spki");
        let mut sig = [0u8; 64];
        sig.copy_from_slice(TROPIC_SIG);
        verify_ed25519(&pubkey, &framed, &sig).expect("TROPIC01 challenge signature must verify");
        assert_eq!(&id_island_from_spki(TROPIC_SPKI)[..], TROPIC_ID);
    }

    #[test]
    fn optiga_ecdsa_challenge_binds_over_frame() {
        let framed = frame_authenticate_device(CHALLENGE).expect("frame");
        verify_ecdsa_p256_sha256(OPTIGA_SPKI, &framed, OPTIGA_SIG)
            .expect("OPTIGA challenge signature must verify");
        assert_eq!(&id_island_from_spki(OPTIGA_SPKI)[..], OPTIGA_ID);
    }

    #[test]
    fn wrong_payload_challenge_is_rejected() {
        let mut tampered = CHALLENGE.to_vec();
        tampered[0] ^= 0xff;
        let framed = frame_authenticate_device(&tampered).expect("frame");
        let pubkey = ed25519_pubkey_from_spki(TROPIC_SPKI).expect("ed25519 spki");
        let mut sig = [0u8; 64];
        sig.copy_from_slice(TROPIC_SIG);
        assert!(verify_ed25519(&pubkey, &framed, &sig).is_err());
    }

    #[test]
    fn unframed_challenge_is_rejected() {
        let pubkey = ed25519_pubkey_from_spki(TROPIC_SPKI).expect("ed25519 spki");
        let mut sig = [0u8; 64];
        sig.copy_from_slice(TROPIC_SIG);
        assert!(verify_ed25519(&pubkey, CHALLENGE, &sig).is_err());
    }

    #[test]
    fn tropic_full_chain_verifies_to_pinned_root() {
        let id = verify_island_attestation(CHALLENGE, TROPIC_SIG, &[TROPIC_CERT0, TROPIC_CERT1])
            .expect("TROPIC01 chain must verify to pinned Safe 7 root");
        assert_eq!(&id[..], TROPIC_ID);
    }

    #[test]
    fn optiga_full_chain_verifies_to_pinned_root() {
        let id = verify_island_attestation(CHALLENGE, OPTIGA_SIG, &[OPTIGA_CERT0, OPTIGA_CERT1])
            .expect("OPTIGA chain must verify to pinned Safe 7 root");
        assert_eq!(&id[..], OPTIGA_ID);
    }

    #[test]
    fn tampered_challenge_fails_full_chain() {
        let mut bad = CHALLENGE.to_vec();
        bad[0] ^= 0xff;
        assert!(verify_island_attestation(&bad, TROPIC_SIG, &[TROPIC_CERT0, TROPIC_CERT1]).is_err());
    }

    #[test]
    fn wrong_leaf_signature_fails_full_chain() {
        // OPTIGA's signature with TROPIC01's chain: leaf challenge check must fail.
        assert!(
            verify_island_attestation(CHALLENGE, OPTIGA_SIG, &[TROPIC_CERT0, TROPIC_CERT1]).is_err()
        );
    }

    #[test]
    fn island_challenge_is_deterministic_and_binds_every_intent_field() {
        let h_n = [1u8; 32];
        let payload = [2u8; 32];
        let rel = [3u8; 32];
        let dev = [4u8; 32];
        let base = dsm_island_challenge(&h_n, &payload, &rel, &dev, 1, 1, b"nonce", 7);
        // Deterministic: identical inputs -> identical challenge.
        assert_eq!(base, dsm_island_challenge(&h_n, &payload, &rel, &dev, 1, 1, b"nonce", 7));
        // Every intent field is bound: flipping any one changes the challenge.
        assert_ne!(base, dsm_island_challenge(&[9u8; 32], &payload, &rel, &dev, 1, 1, b"nonce", 7));
        assert_ne!(base, dsm_island_challenge(&h_n, &[9u8; 32], &rel, &dev, 1, 1, b"nonce", 7));
        assert_ne!(base, dsm_island_challenge(&h_n, &payload, &[9u8; 32], &dev, 1, 1, b"nonce", 7));
        assert_ne!(base, dsm_island_challenge(&h_n, &payload, &rel, &[9u8; 32], 1, 1, b"nonce", 7));
        assert_ne!(base, dsm_island_challenge(&h_n, &payload, &rel, &dev, 2, 1, b"nonce", 7));
        assert_ne!(base, dsm_island_challenge(&h_n, &payload, &rel, &dev, 1, 2, b"nonce", 7));
        assert_ne!(base, dsm_island_challenge(&h_n, &payload, &rel, &dev, 1, 1, b"other", 7));
        assert_ne!(base, dsm_island_challenge(&h_n, &payload, &rel, &dev, 1, 1, b"nonce", 8));
    }

    /// Minimal Ed25519 SubjectPublicKeyInfo DER wrapping a raw 32-byte public key.
    fn ed25519_spki(raw_pubkey: &[u8; 32]) -> Vec<u8> {
        let mut spki = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        spki.extend_from_slice(raw_pubkey);
        spki
    }

    #[test]
    fn island_intent_signature_round_trips_and_rejects_tampering() {
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let spki = ed25519_spki(sk.verifying_key().as_bytes());

        let h_n = [1u8; 32];
        let payload = [2u8; 32];
        let rel = [3u8; 32];
        let dev = [4u8; 32];
        let intent = IslandIntent {
            h_n: &h_n,
            payload_hash: &payload,
            relationship_id: &rel,
            device_id: &dev,
            value_capability: 1,
            offline_bearer_mode: 1,
            nonce: b"n0",
            expiry_tick: 9,
        };
        let framed = frame_authenticate_device(&intent.challenge()).expect("frame");
        let sig = sk.sign(&framed).to_bytes();

        // Honest path: the island signed THIS exact intent; id pins to the leaf SPKI.
        let id = verify_island_intent_signature(&spki, &intent, &sig).expect("intent sig verifies");
        assert_eq!(id, id_island_from_spki(&spki));

        // Tampered intent (different nonce) -> recomputed challenge differs -> fails.
        let tampered = IslandIntent { nonce: b"n1", ..intent };
        assert!(verify_island_intent_signature(&spki, &tampered, &sig).is_err());

        // Wrong island key -> fails (a clone with a different key cannot reuse the sig).
        let other = SigningKey::from_bytes(&[8u8; 32]);
        let other_spki = ed25519_spki(other.verifying_key().as_bytes());
        assert!(verify_island_intent_signature(&other_spki, &intent, &sig).is_err());
    }

    #[test]
    fn settlement_path_grants_offline_only_when_attested_and_signed() {
        use crate::types::device_state::OfflineBearerAttestation::*;
        // The sole grant case: requested + Attested + valid island signature.
        assert_eq!(
            decide_settlement_path(true, Attested, true),
            SettlementPath::OfflineBearer
        );
        // Every other case falls back to the online-checked path (never a hard reject).
        assert_eq!(
            decide_settlement_path(false, Attested, true),
            SettlementPath::OnlineFallback
        );
        assert_eq!(
            decide_settlement_path(true, NotAttested, true),
            SettlementPath::OnlineFallback
        );
        assert_eq!(
            decide_settlement_path(true, Unknown, true),
            SettlementPath::OnlineFallback
        );
        assert_eq!(
            decide_settlement_path(true, Attested, false),
            SettlementPath::OnlineFallback
        );
    }
}
