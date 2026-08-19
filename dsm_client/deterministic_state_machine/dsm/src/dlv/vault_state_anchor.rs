// SPDX-License-Identifier: Apache-2.0

//! Vault state anchor primitive (Tier 2 Foundation).
//!
//! Owner-signed snapshot of a DLV's state at a specific sequence.
//! Published to storage at `sofi/vault-state/{vault_id_b32}/latest`
//! for off-device traders to read at quote time.  The local
//! `DLVManager` is the authoritative truth source for the chunks #7
//! gate — anchors are an *advertisement*, not a consensus mechanism.
//!
//! All cryptographic operations are domain-separated BLAKE3.
//! Signatures are SPHINCS+.  No JSON, no hex, no wall-clock.

use blake3::Hasher;

const DOMAIN_RESERVES: &[u8] = b"DSM/amm-reserves\0";
const DOMAIN_ANCHOR: &[u8] = b"DSM/vault-state-anchor\0";

/// Compute the canonical reserves digest for an AMM constant-product
/// vault.  Stable across endianness because all integer fields are
/// big-endian encoded.
pub fn compute_reserves_digest(
    token_a: &[u8],
    token_b: &[u8],
    reserve_a: u64,
    reserve_b: u64,
    fee_bps: u32,
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN_RESERVES);
    h.update(token_a);
    h.update(token_b);
    h.update(&reserve_a.to_be_bytes());
    h.update(&reserve_b.to_be_bytes());
    h.update(&fee_bps.to_be_bytes());
    *h.finalize().as_bytes()
}

/// Signed canonical form of a vault state anchor.  Wire-encoded as
/// `VaultStateAnchorV1` proto; this struct is the in-memory typed
/// view.
#[derive(Debug, Clone)]
pub struct SignedVaultStateAnchor {
    pub vault_id: [u8; 32],
    pub sequence: u64,
    pub reserves_digest: [u8; 32],
    /// The canonical storage set the vault was born under — inside the signed
    /// preimage, birth-fixed across the lineage (every generation of the
    /// anchor carries the same value; composition rejects a change).
    pub storage_set_id: [u8; 32],
    pub owner_public_key: Vec<u8>,
    pub owner_signature: Vec<u8>,
}

/// Errors raised by `sign_vault_state_anchor` /
/// `verify_vault_state_anchor`.  Avoids pulling `thiserror` for a
/// pure-crypto leaf module — manual `Display` + `std::error::Error`
/// keeps the dependency surface honest.
#[derive(Debug)]
pub enum AnchorError {
    /// Signature verification failed (bad signature, key mismatch,
    /// or tampered fields).
    SignatureInvalid,
    /// Underlying SPHINCS+ sign call failed.
    SignFailed(String),
}

impl core::fmt::Display for AnchorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AnchorError::SignatureInvalid => write!(f, "signature verification failed"),
            AnchorError::SignFailed(msg) => write!(f, "sphincs sign failed: {msg}"),
        }
    }
}

impl std::error::Error for AnchorError {}

/// The anchor-binding digest over the vault's attested state:
/// `BLAKE3(DOMAIN_ANCHOR || vault_id || sequence_be || reserves_digest)`.
fn anchor_state_digest(vault_id: &[u8; 32], sequence: u64, reserves_digest: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN_ANCHOR);
    h.update(vault_id);
    h.update(&sequence.to_be_bytes());
    h.update(reserves_digest);
    *h.finalize().as_bytes()
}

/// The owner's SIGNED preimage: the anchor-binding digest extended with the
/// canonical storage set the vault was born under —
/// `BLAKE3(DOMAIN_ANCHOR || vault_id || sequence_be || reserves_digest ||
/// storage_set_id)`. The set is inside the signature so a consumer resolving
/// "which storage set serves this vault" reads it from the vault's own
/// authenticated identity, never from local configuration.
fn anchor_sign_payload(
    vault_id: &[u8; 32],
    sequence: u64,
    reserves_digest: &[u8; 32],
    storage_set_id: &[u8; 32],
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN_ANCHOR);
    h.update(vault_id);
    h.update(&sequence.to_be_bytes());
    h.update(reserves_digest);
    h.update(storage_set_id);
    *h.finalize().as_bytes()
}

/// Canonical vault-state-anchor digest binding a vault to one attested
/// `(sequence, reserves_digest)` state — `BLAKE3(DOMAIN_ANCHOR || vault_id
/// || sequence_be || reserves_digest)`.  The RouteCommit hop's
/// `vault_state_anchor_digest` (stamped by the routing binder from the
/// composed vault state) and the vault-side unlock gate independently
/// recompute this value and compare — the third anchor-binding field,
/// alongside `vault_state_anchor_seq` and `vault_state_reserves_digest`.
/// (The owner-signed anchor covers these same fields plus the vault's
/// birth-fixed `storage_set_id`; see `sign_vault_state_anchor`.)
pub fn compute_anchor_digest(
    vault_id: &[u8; 32],
    sequence: u64,
    reserves_digest: &[u8; 32],
) -> [u8; 32] {
    anchor_state_digest(vault_id, sequence, reserves_digest)
}

/// Sign a vault state anchor with the owner's SPHINCS+ secret key.
///
/// The signed payload is the BLAKE3 digest of
/// `DOMAIN_ANCHOR || vault_id || sequence_be || reserves_digest || storage_set_id`.
pub fn sign_vault_state_anchor(
    vault_id: &[u8; 32],
    sequence: u64,
    reserves_digest: &[u8; 32],
    storage_set_id: &[u8; 32],
    owner_public_key: &[u8],
    owner_secret_key: &[u8],
) -> Result<SignedVaultStateAnchor, AnchorError> {
    let payload = anchor_sign_payload(vault_id, sequence, reserves_digest, storage_set_id);
    let signature = crate::crypto::sphincs::sphincs_sign(owner_secret_key, &payload)
        .map_err(|e| AnchorError::SignFailed(format!("{e:?}")))?;
    Ok(SignedVaultStateAnchor {
        vault_id: *vault_id,
        sequence,
        reserves_digest: *reserves_digest,
        storage_set_id: *storage_set_id,
        owner_public_key: owner_public_key.to_vec(),
        owner_signature: signature,
    })
}

/// Verify the owner's SPHINCS+ signature on a vault state anchor.
/// Returns `Ok(())` when the signature matches the canonical payload
/// derived from the anchor's public fields, `Err(SignatureInvalid)`
/// otherwise.
pub fn verify_vault_state_anchor(anchor: &SignedVaultStateAnchor) -> Result<(), AnchorError> {
    let payload = anchor_sign_payload(
        &anchor.vault_id,
        anchor.sequence,
        &anchor.reserves_digest,
        &anchor.storage_set_id,
    );
    let ok = crate::crypto::sphincs::sphincs_verify(
        &anchor.owner_public_key,
        &payload,
        &anchor.owner_signature,
    )
    .map_err(|_| AnchorError::SignatureInvalid)?;
    if ok {
        Ok(())
    } else {
        Err(AnchorError::SignatureInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserves_digest_is_deterministic() {
        let d1 = compute_reserves_digest(b"AAA", b"BBB", 1000, 2000, 30);
        let d2 = compute_reserves_digest(b"AAA", b"BBB", 1000, 2000, 30);
        assert_eq!(d1, d2);
    }

    #[test]
    fn anchor_digest_is_deterministic_and_binds_every_field() {
        let vault_id = [0x11u8; 32];
        let rd = compute_reserves_digest(b"AAA", b"BBB", 1000, 2000, 30);
        let base = compute_anchor_digest(&vault_id, 5, &rd);
        // Deterministic.
        assert_eq!(base, compute_anchor_digest(&vault_id, 5, &rd));
        // It is the STATE half of what an owner-signed anchor signs over: the
        // signed payload extends it with the vault's birth-fixed storage set, so
        // the two are distinct and neither is a prefix collision of the other.
        assert_eq!(base, anchor_state_digest(&vault_id, 5, &rd));
        assert_ne!(base, anchor_sign_payload(&vault_id, 5, &rd, &[0x6B; 32]));
        // Sensitive to vault_id, sequence, and reserves digest.
        assert_ne!(base, compute_anchor_digest(&[0x22u8; 32], 5, &rd));
        assert_ne!(base, compute_anchor_digest(&vault_id, 6, &rd));
        let rd2 = compute_reserves_digest(b"AAA", b"BBB", 1001, 2000, 30);
        assert_ne!(base, compute_anchor_digest(&vault_id, 5, &rd2));
    }

    #[test]
    fn reserves_digest_differs_on_any_field_change() {
        let base = compute_reserves_digest(b"AAA", b"BBB", 1000, 2000, 30);
        assert_ne!(
            base,
            compute_reserves_digest(b"AAB", b"BBB", 1000, 2000, 30)
        );
        assert_ne!(
            base,
            compute_reserves_digest(b"AAA", b"BBC", 1000, 2000, 30)
        );
        assert_ne!(
            base,
            compute_reserves_digest(b"AAA", b"BBB", 1001, 2000, 30)
        );
        assert_ne!(
            base,
            compute_reserves_digest(b"AAA", b"BBB", 1000, 2001, 30)
        );
        assert_ne!(
            base,
            compute_reserves_digest(b"AAA", b"BBB", 1000, 2000, 31)
        );
    }

    #[test]
    fn anchor_signing_round_trips() {
        let (pk, sk) = crate::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
        let vault_id = [0x11u8; 32];
        let reserves_digest = compute_reserves_digest(b"AAA", b"BBB", 100, 200, 30);

        let signed = sign_vault_state_anchor(&vault_id, 0, &reserves_digest, &[0x6B; 32], &pk, &sk)
            .expect("sign succeeds");

        verify_vault_state_anchor(&signed).expect("verify succeeds");
    }

    #[test]
    fn anchor_verification_rejects_tampered_sequence() {
        let (pk, sk) = crate::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
        let vault_id = [0x22u8; 32];
        let reserves_digest = compute_reserves_digest(b"AAA", b"BBB", 100, 200, 30);

        let mut signed =
            sign_vault_state_anchor(&vault_id, 5, &reserves_digest, &[0x6B; 32], &pk, &sk)
                .expect("sign succeeds");
        signed.sequence = 6;

        assert!(verify_vault_state_anchor(&signed).is_err());
    }

    #[test]
    fn anchor_verification_rejects_tampered_reserves_digest() {
        let (pk, sk) = crate::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
        let vault_id = [0x33u8; 32];
        let reserves_digest = compute_reserves_digest(b"AAA", b"BBB", 100, 200, 30);

        let mut signed =
            sign_vault_state_anchor(&vault_id, 0, &reserves_digest, &[0x6B; 32], &pk, &sk)
                .expect("sign succeeds");
        signed.reserves_digest[0] ^= 0xff;

        assert!(verify_vault_state_anchor(&signed).is_err());
    }

    /// The storage set is INSIDE the signed preimage: an anchor whose set id
    /// was altered after signing does not verify — a consumer cannot be
    /// steered to another set by a mutated field.
    #[test]
    fn anchor_verification_rejects_tampered_storage_set_id() {
        let (pk, sk) = crate::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
        let vault_id = [0x44u8; 32];
        let reserves_digest = compute_reserves_digest(b"AAA", b"BBB", 100, 200, 30);

        let mut signed =
            sign_vault_state_anchor(&vault_id, 0, &reserves_digest, &[0x6B; 32], &pk, &sk)
                .expect("sign succeeds");
        signed.storage_set_id[0] ^= 0xff;

        assert!(verify_vault_state_anchor(&signed).is_err());
    }
}
