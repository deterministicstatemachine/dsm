// SPDX-License-Identifier: Apache-2.0

//! Vault-keyed pending-state pointer primitive (SoFi spec §2.3, §4.1).
//!
//! Each `VaultPendingPointerV1` is a small, anyone-verifiable witness
//! that some trader has published a valid `ExternalCommitmentV1` (with
//! σ) advancing a specific vault's state by one sequence step. Pointers
//! are co-published with the ExtCommit at
//!
//!     defi/vault-pending/{vault_id_b32}/{new_sequence_be_pad16}/{x_b32}
//!
//! so that the *next* trader can list pending advances on a vault in
//! O(pending) — instead of scanning the global `sofi/extcommit/*`
//! prefix — and compose them into the canonical current state before
//! quoting.
//!
//! The pointer itself carries no liquidity-changing authority; it is a
//! discovery aid. Full settlement validity still flows through the
//! existing eligibility gate (`route_commit_sdk::verify_route_commit_unlock_eligibility`)
//! plus the chunks-#7 AMM re-simulation gate. The pointer's signature
//! only proves *this specific publisher* attested to *this specific*
//! (vault, parent_seq, new_seq, X, new_reserves_digest) tuple.
//!
//! All cryptographic operations are domain-separated BLAKE3. Signatures
//! are SPHINCS+. No JSON, no hex, no wall-clock.

use blake3::Hasher;

const DOMAIN_POINTER: &[u8] = b"DSM/vault-pending\0";

/// Signed canonical form of a vault-pending pointer. Wire-encoded as
/// `VaultPendingPointerV1` proto; this struct is the in-memory typed
/// view used by composition + tests.
#[derive(Debug, Clone)]
pub struct SignedVaultPendingPointer {
    pub vault_id: [u8; 32],
    pub parent_sequence: u64,
    pub new_sequence: u64,
    pub x: [u8; 32],
    pub new_reserves_digest: [u8; 32],
    /// Hash of the ONE settlement receipt that can activate this pointer.
    ///
    /// Until a receipt hashing to exactly this value is fetched and verified,
    /// the pointer is inert: it changes no one's effective reserves. Signed
    /// over, so it cannot be swapped for a cheaper trade's receipt after the
    /// fact.
    pub expected_receipt_hash: [u8; 32],
    pub publisher_public_key: Vec<u8>,
    pub publisher_signature: Vec<u8>,
}

/// Errors raised by `sign_vault_pending_pointer` /
/// `verify_vault_pending_pointer`.
#[derive(Debug)]
pub enum PointerError {
    /// Signature verification failed (bad signature, key mismatch, or
    /// tampered fields).
    SignatureInvalid,
    /// Underlying SPHINCS+ sign call failed.
    SignFailed(String),
    /// `new_sequence != parent_sequence + 1`.  Pointers MUST be unit
    /// steps; multi-step pointers would obscure verification.
    NonUnitStep {
        parent_sequence: u64,
        new_sequence: u64,
    },
    /// `parent_sequence == u64::MAX` cannot be advanced by one. This
    /// must fail closed instead of silently accepting a saturated
    /// pseudo-step.
    SequenceOverflow { parent_sequence: u64 },
}

impl core::fmt::Display for PointerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PointerError::SignatureInvalid => write!(f, "signature verification failed"),
            PointerError::SignFailed(msg) => write!(f, "sphincs sign failed: {msg}"),
            PointerError::NonUnitStep {
                parent_sequence,
                new_sequence,
            } => write!(
                f,
                "pointer must advance sequence by exactly 1 (parent={parent_sequence}, new={new_sequence})",
            ),
            PointerError::SequenceOverflow { parent_sequence } => write!(
                f,
                "pointer sequence overflow: parent={parent_sequence} cannot advance by 1",
            ),
        }
    }
}

impl std::error::Error for PointerError {}

fn expected_next_sequence(parent_sequence: u64) -> Result<u64, PointerError> {
    parent_sequence
        .checked_add(1)
        .ok_or(PointerError::SequenceOverflow { parent_sequence })
}

/// Canonical signing payload for a vault pending pointer.
///
/// `BLAKE3(DOMAIN_POINTER || vault_id || parent_sequence_be ||
///         new_sequence_be || x || new_reserves_digest ||
///         expected_receipt_hash)`
///
/// Stable across endianness because all integer fields are big-endian
/// encoded; stable across implementations because the order is fixed
/// and there are no length-prefixed dynamic fields.
fn pointer_sign_payload(
    vault_id: &[u8; 32],
    parent_sequence: u64,
    new_sequence: u64,
    x: &[u8; 32],
    new_reserves_digest: &[u8; 32],
    expected_receipt_hash: &[u8; 32],
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN_POINTER);
    h.update(vault_id);
    h.update(&parent_sequence.to_be_bytes());
    h.update(&new_sequence.to_be_bytes());
    h.update(x);
    h.update(new_reserves_digest);
    h.update(expected_receipt_hash);
    *h.finalize().as_bytes()
}

/// Sign a vault pending pointer with the publisher's SPHINCS+ secret
/// key.
///
/// Enforces `new_sequence == parent_sequence + 1`; multi-step pointers
/// are rejected to keep composition strictly chain-additive (each
/// pointer extends the cursor by exactly one sequence step).
#[allow(clippy::too_many_arguments)]
pub fn sign_vault_pending_pointer(
    vault_id: &[u8; 32],
    parent_sequence: u64,
    new_sequence: u64,
    x: &[u8; 32],
    new_reserves_digest: &[u8; 32],
    expected_receipt_hash: &[u8; 32],
    publisher_public_key: &[u8],
    publisher_secret_key: &[u8],
) -> Result<SignedVaultPendingPointer, PointerError> {
    let expected_new = expected_next_sequence(parent_sequence)?;
    if new_sequence != expected_new {
        return Err(PointerError::NonUnitStep {
            parent_sequence,
            new_sequence,
        });
    }
    let payload = pointer_sign_payload(
        vault_id,
        parent_sequence,
        new_sequence,
        x,
        new_reserves_digest,
        expected_receipt_hash,
    );
    let signature = crate::crypto::sphincs::sign(
        crate::crypto::sphincs::SphincsVariant::SPX256f,
        publisher_secret_key,
        payload.as_ref(),
    )
    .map_err(|e| PointerError::SignFailed(format!("{e:?}")))?;
    Ok(SignedVaultPendingPointer {
        vault_id: *vault_id,
        parent_sequence,
        new_sequence,
        x: *x,
        new_reserves_digest: *new_reserves_digest,
        expected_receipt_hash: *expected_receipt_hash,
        publisher_public_key: publisher_public_key.to_vec(),
        publisher_signature: signature,
    })
}

/// Verify the publisher's SPHINCS+ signature on a vault pending
/// pointer.  Anyone can verify; no privileged authority required.
///
/// Also enforces the `new_sequence == parent_sequence + 1` invariant
/// so a non-unit-step pointer fails closed even if it carries a valid
/// signature over an inconsistent payload.
pub fn verify_vault_pending_pointer(
    pointer: &SignedVaultPendingPointer,
) -> Result<(), PointerError> {
    let expected_new = expected_next_sequence(pointer.parent_sequence)?;
    if pointer.new_sequence != expected_new {
        return Err(PointerError::NonUnitStep {
            parent_sequence: pointer.parent_sequence,
            new_sequence: pointer.new_sequence,
        });
    }
    let payload = pointer_sign_payload(
        &pointer.vault_id,
        pointer.parent_sequence,
        pointer.new_sequence,
        &pointer.x,
        &pointer.new_reserves_digest,
        &pointer.expected_receipt_hash,
    );
    let ok = crate::crypto::sphincs::sphincs_verify(
        &pointer.publisher_public_key,
        &payload,
        &pointer.publisher_signature,
    )
    .map_err(|_| PointerError::SignatureInvalid)?;
    if ok {
        Ok(())
    } else {
        Err(PointerError::SignatureInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sphincs::{generate_keypair, SphincsVariant};

    fn sample_inputs() -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        let mut vault_id = [0u8; 32];
        vault_id[0] = 0xDE;
        vault_id[1] = 0x70;
        vault_id[31] = 0xA1;
        let mut x = [0u8; 32];
        x[0] = 0xEC;
        x[31] = 0x12;
        let mut digest = [0u8; 32];
        digest[0] = 0xD1;
        digest[31] = 0xFE;
        let mut receipt_hash = [0u8; 32];
        receipt_hash[0] = 0x7C;
        receipt_hash[31] = 0x9C;
        (vault_id, x, digest, receipt_hash)
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let (vault_id, x, digest, receipt_hash) = sample_inputs();
        let kp = generate_keypair(SphincsVariant::SPX256f).expect("keypair");
        let signed = sign_vault_pending_pointer(
            &vault_id,
            5,
            6,
            &x,
            &digest,
            &receipt_hash,
            &kp.public_key,
            &kp.secret_key,
        )
        .expect("sign succeeds");
        verify_vault_pending_pointer(&signed).expect("verify succeeds");
    }

    #[test]
    fn rejects_tampered_new_sequence() {
        let (vault_id, x, digest, receipt_hash) = sample_inputs();
        let kp = generate_keypair(SphincsVariant::SPX256f).expect("keypair");
        let mut signed = sign_vault_pending_pointer(
            &vault_id,
            5,
            6,
            &x,
            &digest,
            &receipt_hash,
            &kp.public_key,
            &kp.secret_key,
        )
        .expect("sign succeeds");
        // Tamper new_sequence to a different value that still passes
        // the unit-step invariant (parent+1) → signature must fail.
        signed.parent_sequence = 6;
        signed.new_sequence = 7;
        assert!(matches!(
            verify_vault_pending_pointer(&signed),
            Err(PointerError::SignatureInvalid),
        ));
    }

    #[test]
    fn rejects_non_unit_step_at_sign_time() {
        let (vault_id, x, digest, receipt_hash) = sample_inputs();
        let kp = generate_keypair(SphincsVariant::SPX256f).expect("keypair");
        let err = sign_vault_pending_pointer(
            &vault_id,
            5,
            7, // skips seq=6
            &x,
            &digest,
            &receipt_hash,
            &kp.public_key,
            &kp.secret_key,
        )
        .expect_err("non-unit step is rejected");
        assert!(matches!(err, PointerError::NonUnitStep { .. }));
    }

    #[test]
    fn rejects_non_unit_step_at_verify_time_even_with_valid_sphincs() {
        // Sign over the canonical (parent=5, new=6) payload, then mutate
        // the in-memory struct so new_sequence skips. Even though the
        // SPHINCS+ verification would happen against the wrong payload
        // and fail, the unit-step invariant check should fire first.
        let (vault_id, x, digest, receipt_hash) = sample_inputs();
        let kp = generate_keypair(SphincsVariant::SPX256f).expect("keypair");
        let mut signed = sign_vault_pending_pointer(
            &vault_id,
            5,
            6,
            &x,
            &digest,
            &receipt_hash,
            &kp.public_key,
            &kp.secret_key,
        )
        .expect("sign succeeds");
        signed.parent_sequence = 5;
        signed.new_sequence = 7;
        let err = verify_vault_pending_pointer(&signed).expect_err("non-unit step rejected");
        assert!(matches!(err, PointerError::NonUnitStep { .. }));
    }

    #[test]
    fn rejects_sequence_overflow_at_sign_time() {
        let (vault_id, x, digest, receipt_hash) = sample_inputs();
        let kp = generate_keypair(SphincsVariant::SPX256f).expect("keypair");
        let err = sign_vault_pending_pointer(
            &vault_id,
            u64::MAX,
            u64::MAX,
            &x,
            &digest,
            &receipt_hash,
            &kp.public_key,
            &kp.secret_key,
        )
        .expect_err("overflow parent must be rejected");
        assert!(matches!(err, PointerError::SequenceOverflow { .. }));
    }

    #[test]
    fn rejects_sequence_overflow_at_verify_time() {
        let (vault_id, x, digest, receipt_hash) = sample_inputs();
        let pointer = SignedVaultPendingPointer {
            vault_id,
            parent_sequence: u64::MAX,
            new_sequence: u64::MAX,
            x,
            new_reserves_digest: digest,
            expected_receipt_hash: receipt_hash,
            publisher_public_key: vec![],
            publisher_signature: vec![],
        };
        let err = verify_vault_pending_pointer(&pointer).expect_err("overflow parent rejected");
        assert!(matches!(err, PointerError::SequenceOverflow { .. }));
    }

    #[test]
    fn rejects_tampered_reserves_digest() {
        let (vault_id, x, digest, receipt_hash) = sample_inputs();
        let kp = generate_keypair(SphincsVariant::SPX256f).expect("keypair");
        let mut signed = sign_vault_pending_pointer(
            &vault_id,
            5,
            6,
            &x,
            &digest,
            &receipt_hash,
            &kp.public_key,
            &kp.secret_key,
        )
        .expect("sign succeeds");
        signed.new_reserves_digest[0] ^= 0xff;
        assert!(matches!(
            verify_vault_pending_pointer(&signed),
            Err(PointerError::SignatureInvalid),
        ));
    }

    /// The receipt commitment is signed over. If it were not, a trader could
    /// publish a pointer for a large trade and then swap in the hash of a tiny
    /// receipt it could actually produce — activating the pointer while paying
    /// almost nothing.
    #[test]
    fn rejects_tampered_receipt_commitment() {
        let (vault_id, x, digest, receipt_hash) = sample_inputs();
        let kp = generate_keypair(SphincsVariant::SPX256f).expect("keypair");
        let mut signed = sign_vault_pending_pointer(
            &vault_id,
            5,
            6,
            &x,
            &digest,
            &receipt_hash,
            &kp.public_key,
            &kp.secret_key,
        )
        .expect("sign succeeds");
        signed.expected_receipt_hash[0] ^= 0xff;
        assert!(matches!(
            verify_vault_pending_pointer(&signed),
            Err(PointerError::SignatureInvalid),
        ));
    }

    #[test]
    fn rejects_wrong_pk() {
        let (vault_id, x, digest, receipt_hash) = sample_inputs();
        let kp1 = generate_keypair(SphincsVariant::SPX256f).expect("kp1");
        let kp2 = generate_keypair(SphincsVariant::SPX256f).expect("kp2");
        let mut signed = sign_vault_pending_pointer(
            &vault_id,
            5,
            6,
            &x,
            &digest,
            &receipt_hash,
            &kp1.public_key,
            &kp1.secret_key,
        )
        .expect("sign succeeds");
        signed.publisher_public_key = kp2.public_key.clone();
        assert!(matches!(
            verify_vault_pending_pointer(&signed),
            Err(PointerError::SignatureInvalid),
        ));
    }
}
