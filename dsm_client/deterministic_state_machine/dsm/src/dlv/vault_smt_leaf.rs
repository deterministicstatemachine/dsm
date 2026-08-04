// SPDX-License-Identifier: Apache-2.0

//! Vault state SMT leaf primitive (Tier 2 Foundation).
//!
//! SoFi spec §4.1.2 / §8.4 step 2 require that every verifying party
//! check an *inclusion proof* of the vault's state against the owner's
//! Per-Device SMT root, not merely a free-floating owner signature.
//! This module is the pure-crypto layer for that obligation: it
//! defines the SMT key + value derivation used for vault-state leaves,
//! the SPHINCS+ signing payload that binds (vault_id, sequence,
//! reserves_digest, smt_root) together, and a stateless verifier that
//! recomputes the leaf and walks the supplied siblings up to the
//! expected root.
//!
//! Vault-state leaves are domain-separated from the existing bilateral
//! relationship-tip leaves (which use `DSM/smt-key\0` in
//! `dsm::merkle::sparse_merkle_tree::hash_smt_leaf`), so the two leaf
//! types share the same SparseMerkleTree without colliding.
//!
//! All cryptographic operations are domain-separated BLAKE3.
//! Signatures are SPHINCS+.  No JSON, no hex, no wall-clock.

use blake3::Hasher;

use crate::merkle::sparse_merkle_tree::{SmtInclusionProof, SparseMerkleTree};

/// Domain separator for the 256-bit SMT *key* of a vault state leaf.
/// Disjoint from `DSM/smt-key\0` (bilateral relationship leaves) so
/// the two namespaces can co-exist in one tree.
const DOMAIN_VAULT_SMT_KEY: &[u8] = b"DSM/vault-smt-key\0";

/// Domain separator for the 256-bit SMT *value* of a vault state
/// leaf.  Folds (sequence, reserves_digest) into one hash; both
/// fields collectively commit the vault's current AMM state.
const DOMAIN_VAULT_SMT_VALUE: &[u8] = b"DSM/vault-smt-value\0";

/// Domain separator for the SPHINCS+ signing payload of a
/// VaultStateInclusionProofV1 record.  Binds the inclusion proof to
/// the SMT root, so an owner cannot equivocate by signing the same
/// (vault_id, sequence, reserves_digest) tuple against two different
/// roots.
const DOMAIN_INCLUSION_PROOF: &[u8] = b"DSM/vault-state-inclusion\0";

/// 256-bit SMT key for a vault state leaf.
///
/// Computed as `BLAKE3(DOMAIN_VAULT_SMT_KEY || vault_id)`.  Pure
/// function of the vault id: the same vault occupies the same leaf
/// position for its entire lifetime, so sequential state advances are
/// successive updates of one leaf rather than insertions of new
/// leaves.
pub fn compute_vault_smt_key(vault_id: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN_VAULT_SMT_KEY);
    h.update(vault_id);
    *h.finalize().as_bytes()
}

/// 256-bit SMT leaf value committing the vault's `(sequence,
/// reserves_digest)` tuple.
///
/// Computed as `BLAKE3(DOMAIN_VAULT_SMT_VALUE || sequence_be ||
/// reserves_digest)`.  Sequence is big-endian for endianness
/// stability across heterogeneous devices.
pub fn compute_vault_smt_value(sequence: u64, reserves_digest: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN_VAULT_SMT_VALUE);
    h.update(&sequence.to_be_bytes());
    h.update(reserves_digest);
    *h.finalize().as_bytes()
}

/// Compute the SPHINCS+ signing payload for a vault state inclusion
/// proof.  Bound fields: vault_id, sequence, reserves_digest,
/// smt_root.  All four are committed in one hash so the signature
/// cannot be lifted from one (vault, root) to another.
pub fn inclusion_proof_sign_payload(
    vault_id: &[u8; 32],
    sequence: u64,
    reserves_digest: &[u8; 32],
    smt_root: &[u8; 32],
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN_INCLUSION_PROOF);
    h.update(vault_id);
    h.update(&sequence.to_be_bytes());
    h.update(reserves_digest);
    h.update(smt_root);
    *h.finalize().as_bytes()
}

/// Signed canonical form of a vault state inclusion proof.  Wire-
/// encoded as `VaultStateInclusionProofV1` proto.
#[derive(Debug, Clone)]
pub struct SignedVaultStateInclusionProof {
    pub vault_id: [u8; 32],
    pub sequence: u64,
    pub reserves_digest: [u8; 32],
    pub smt_root: [u8; 32],
    /// 256 sibling hashes in leaf-to-root order, as produced by
    /// `SparseMerkleTree::get_inclusion_proof` for the vault-state
    /// SMT leaf key.
    pub smt_siblings: Vec<[u8; 32]>,
    pub owner_public_key: Vec<u8>,
    pub owner_signature: Vec<u8>,
}

/// Errors from vault SMT leaf signing / verification.  Avoids
/// `thiserror` for the pure-crypto leaf module — manual `Display`
/// keeps the dependency surface honest.
#[derive(Debug)]
pub enum VaultSmtLeafError {
    /// SPHINCS+ signature verification failed (bad signature, key
    /// mismatch, or tampered fields).
    SignatureInvalid,
    /// Underlying SPHINCS+ sign call failed.
    SignFailed(String),
    /// SMT inclusion proof did not verify against the supplied root.
    /// Either the siblings are wrong, the leaf was reconstructed
    /// against a different (vault_id, sequence, reserves_digest), or
    /// the root is a mismatch.
    InclusionProofRejected,
    /// Sibling vector length is not exactly 256.  The SMT is a
    /// fixed-depth (256-level) Merkle structure; a shorter or longer
    /// path cannot be a valid inclusion proof.
    BadSiblingCount { expected: usize, actual: usize },
}

impl core::fmt::Display for VaultSmtLeafError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VaultSmtLeafError::SignatureInvalid => write!(f, "signature verification failed"),
            VaultSmtLeafError::SignFailed(msg) => write!(f, "sphincs sign failed: {msg}"),
            VaultSmtLeafError::InclusionProofRejected => {
                write!(f, "SMT inclusion proof rejected for vault-state leaf")
            }
            VaultSmtLeafError::BadSiblingCount { expected, actual } => {
                write!(f, "SMT siblings must have length {expected}, got {actual}")
            }
        }
    }
}

impl std::error::Error for VaultSmtLeafError {}

/// Sign a vault state inclusion proof with the owner's SPHINCS+
/// secret key.  Caller is responsible for having already pulled the
/// matching sibling path out of the owner's SMT — this function does
/// not consult any tree state.
pub fn sign_vault_state_inclusion_proof(
    vault_id: &[u8; 32],
    sequence: u64,
    reserves_digest: &[u8; 32],
    smt_root: &[u8; 32],
    smt_siblings: Vec<[u8; 32]>,
    owner_public_key: &[u8],
    owner_secret_key: &[u8],
) -> Result<SignedVaultStateInclusionProof, VaultSmtLeafError> {
    if smt_siblings.len() != 256 {
        return Err(VaultSmtLeafError::BadSiblingCount {
            expected: 256,
            actual: smt_siblings.len(),
        });
    }
    let payload = inclusion_proof_sign_payload(vault_id, sequence, reserves_digest, smt_root);
    let signature = crate::crypto::sphincs::sphincs_sign(owner_secret_key, &payload)
        .map_err(|e| VaultSmtLeafError::SignFailed(format!("{e:?}")))?;
    Ok(SignedVaultStateInclusionProof {
        vault_id: *vault_id,
        sequence,
        reserves_digest: *reserves_digest,
        smt_root: *smt_root,
        smt_siblings,
        owner_public_key: owner_public_key.to_vec(),
        owner_signature: signature,
    })
}

/// Recompute the SMT leaf key + value from `(vault_id, sequence,
/// reserves_digest)` and verify the supplied siblings produce
/// `expected_root` when hashed up from the recomputed leaf value.
///
/// This is a pure verifier — no I/O, no tree instance needed.  Used
/// by:
/// * Off-device traders at quote time (composition path).
/// * The chunks-#7 unlock gate, before emitting `Operation::DlvUnlock`.
/// * Storage-node-side spot checks of published inclusion proofs.
pub fn verify_vault_smt_inclusion(
    vault_id: &[u8; 32],
    sequence: u64,
    reserves_digest: &[u8; 32],
    expected_root: &[u8; 32],
    siblings: &[[u8; 32]],
) -> Result<(), VaultSmtLeafError> {
    if siblings.len() != 256 {
        return Err(VaultSmtLeafError::BadSiblingCount {
            expected: 256,
            actual: siblings.len(),
        });
    }
    let key = compute_vault_smt_key(vault_id);
    let value = compute_vault_smt_value(sequence, reserves_digest);
    let proof = SmtInclusionProof {
        key,
        value: Some(value),
        siblings: siblings.to_vec(),
    };
    if SparseMerkleTree::verify_proof_against_root(&proof, expected_root) {
        Ok(())
    } else {
        Err(VaultSmtLeafError::InclusionProofRejected)
    }
}

/// Verify a signed inclusion proof end-to-end: SPHINCS+ signature
/// check first, then SMT inclusion check.  Returns `Ok(())` when both
/// pass.
///
/// Order matters: signature first (cheap-ish), inclusion second.  A
/// caller that wants only the signature half can call
/// `verify_inclusion_proof_signature` directly, but production code
/// paths should always require both.
pub fn verify_vault_state_inclusion_proof(
    proof: &SignedVaultStateInclusionProof,
) -> Result<(), VaultSmtLeafError> {
    let payload = inclusion_proof_sign_payload(
        &proof.vault_id,
        proof.sequence,
        &proof.reserves_digest,
        &proof.smt_root,
    );
    let ok = crate::crypto::sphincs::sphincs_verify(
        &proof.owner_public_key,
        &payload,
        &proof.owner_signature,
    )
    .map_err(|_| VaultSmtLeafError::SignatureInvalid)?;
    if !ok {
        return Err(VaultSmtLeafError::SignatureInvalid);
    }
    verify_vault_smt_inclusion(
        &proof.vault_id,
        proof.sequence,
        &proof.reserves_digest,
        &proof.smt_root,
        &proof.smt_siblings,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dlv::vault_state_anchor::compute_reserves_digest;

    fn fixture_keys() -> (Vec<u8>, Vec<u8>) {
        crate::crypto::sphincs::generate_sphincs_keypair().expect("keypair")
    }

    /// Build a real 256-sibling inclusion proof against a fresh SMT
    /// holding the (vault_id, sequence, reserves_digest) leaf.
    fn fixture_proof(
        vault_id: &[u8; 32],
        sequence: u64,
        reserves_digest: &[u8; 32],
    ) -> ([u8; 32], Vec<[u8; 32]>) {
        let mut tree = SparseMerkleTree::new(64);
        let leaf_key = compute_vault_smt_key(vault_id);
        let leaf_value = compute_vault_smt_value(sequence, reserves_digest);
        tree.update_leaf(&leaf_key, &leaf_value)
            .expect("update_leaf");
        let proof = tree.get_inclusion_proof(&leaf_key, 256).expect("proof");
        (*tree.root(), proof.siblings)
    }

    #[test]
    fn leaf_key_is_deterministic_and_domain_separated() {
        let vault_id = [0x11u8; 32];
        let k1 = compute_vault_smt_key(&vault_id);
        let k2 = compute_vault_smt_key(&vault_id);
        assert_eq!(k1, k2);
        // The vault-state key cannot collide with a bilateral-tip key
        // for the same 32-byte input, because the two functions hash
        // disjoint domain tags before the input.
        let mut bilateral = crate::crypto::blake3::tagged_hasher(
            crate::crypto::domain::TaggedHashDomain::from_static(b"DSM/smt-key"),
        );
        // Bilateral keys hash min(A, B) || max(A, B) — feeding the
        // same `vault_id` twice replicates the worst-case-collision
        // input but the domain tag still makes them disjoint.
        bilateral.update(&vault_id);
        bilateral.update(&vault_id);
        let bilateral_key: [u8; 32] = *bilateral.finalize().as_bytes();
        assert_ne!(k1, bilateral_key);
    }

    #[test]
    fn leaf_value_is_deterministic_and_field_sensitive() {
        let reserves = compute_reserves_digest(b"AAA", b"BBB", 100, 200, 30);
        let v0 = compute_vault_smt_value(0, &reserves);
        let v0_again = compute_vault_smt_value(0, &reserves);
        assert_eq!(v0, v0_again);

        let v1 = compute_vault_smt_value(1, &reserves);
        assert_ne!(v0, v1, "sequence advance must change leaf value");

        let mut tampered = reserves;
        tampered[0] ^= 0xff;
        let v_t = compute_vault_smt_value(0, &tampered);
        assert_ne!(v0, v_t, "reserves change must change leaf value");
    }

    #[test]
    fn signed_inclusion_proof_round_trips() {
        let (pk, sk) = fixture_keys();
        let vault_id = [0x22u8; 32];
        let reserves_digest = compute_reserves_digest(b"AAA", b"BBB", 100, 200, 30);
        let (root, siblings) = fixture_proof(&vault_id, 0, &reserves_digest);

        let signed = sign_vault_state_inclusion_proof(
            &vault_id,
            0,
            &reserves_digest,
            &root,
            siblings,
            &pk,
            &sk,
        )
        .expect("sign succeeds");

        verify_vault_state_inclusion_proof(&signed).expect("end-to-end verify");
    }

    #[test]
    fn verification_rejects_tampered_vault_id() {
        let (pk, sk) = fixture_keys();
        let vault_id = [0x33u8; 32];
        let reserves_digest = compute_reserves_digest(b"AAA", b"BBB", 100, 200, 30);
        let (root, siblings) = fixture_proof(&vault_id, 0, &reserves_digest);

        let mut signed = sign_vault_state_inclusion_proof(
            &vault_id,
            0,
            &reserves_digest,
            &root,
            siblings,
            &pk,
            &sk,
        )
        .expect("sign succeeds");
        signed.vault_id[0] ^= 0xff;
        assert!(matches!(
            verify_vault_state_inclusion_proof(&signed),
            Err(VaultSmtLeafError::SignatureInvalid)
        ));
    }

    #[test]
    fn verification_rejects_tampered_sequence() {
        let (pk, sk) = fixture_keys();
        let vault_id = [0x44u8; 32];
        let reserves_digest = compute_reserves_digest(b"AAA", b"BBB", 100, 200, 30);
        let (root, siblings) = fixture_proof(&vault_id, 5, &reserves_digest);

        let mut signed = sign_vault_state_inclusion_proof(
            &vault_id,
            5,
            &reserves_digest,
            &root,
            siblings,
            &pk,
            &sk,
        )
        .expect("sign succeeds");
        signed.sequence = 6;
        assert!(matches!(
            verify_vault_state_inclusion_proof(&signed),
            Err(VaultSmtLeafError::SignatureInvalid)
        ));
    }

    #[test]
    fn verification_rejects_tampered_reserves_digest() {
        let (pk, sk) = fixture_keys();
        let vault_id = [0x55u8; 32];
        let reserves_digest = compute_reserves_digest(b"AAA", b"BBB", 100, 200, 30);
        let (root, siblings) = fixture_proof(&vault_id, 0, &reserves_digest);

        let mut signed = sign_vault_state_inclusion_proof(
            &vault_id,
            0,
            &reserves_digest,
            &root,
            siblings,
            &pk,
            &sk,
        )
        .expect("sign succeeds");
        signed.reserves_digest[0] ^= 0xff;
        assert!(matches!(
            verify_vault_state_inclusion_proof(&signed),
            Err(VaultSmtLeafError::SignatureInvalid)
        ));
    }

    #[test]
    fn verification_rejects_tampered_smt_root() {
        let (pk, sk) = fixture_keys();
        let vault_id = [0x66u8; 32];
        let reserves_digest = compute_reserves_digest(b"AAA", b"BBB", 100, 200, 30);
        let (root, siblings) = fixture_proof(&vault_id, 0, &reserves_digest);

        let mut signed = sign_vault_state_inclusion_proof(
            &vault_id,
            0,
            &reserves_digest,
            &root,
            siblings,
            &pk,
            &sk,
        )
        .expect("sign succeeds");
        signed.smt_root[0] ^= 0xff;
        assert!(matches!(
            verify_vault_state_inclusion_proof(&signed),
            Err(VaultSmtLeafError::SignatureInvalid)
        ));
    }

    #[test]
    fn verification_rejects_wrong_signer() {
        let (pk_a, sk_a) = fixture_keys();
        let (pk_b, _sk_b) = fixture_keys();
        let vault_id = [0x77u8; 32];
        let reserves_digest = compute_reserves_digest(b"AAA", b"BBB", 100, 200, 30);
        let (root, siblings) = fixture_proof(&vault_id, 0, &reserves_digest);

        let mut signed = sign_vault_state_inclusion_proof(
            &vault_id,
            0,
            &reserves_digest,
            &root,
            siblings,
            &pk_a,
            &sk_a,
        )
        .expect("sign succeeds");
        // Swap in a different public key — signature no longer
        // matches the embedded payload under that key.
        signed.owner_public_key = pk_b;
        assert!(matches!(
            verify_vault_state_inclusion_proof(&signed),
            Err(VaultSmtLeafError::SignatureInvalid)
        ));
    }

    #[test]
    fn verification_rejects_bad_sibling_count() {
        let (pk, sk) = fixture_keys();
        let vault_id = [0x88u8; 32];
        let reserves_digest = compute_reserves_digest(b"AAA", b"BBB", 100, 200, 30);
        let (root, siblings) = fixture_proof(&vault_id, 0, &reserves_digest);

        // Construct via the signing helper (correct length), then
        // truncate the siblings to simulate an on-wire corruption.
        let mut signed = sign_vault_state_inclusion_proof(
            &vault_id,
            0,
            &reserves_digest,
            &root,
            siblings,
            &pk,
            &sk,
        )
        .expect("sign succeeds");
        signed.smt_siblings.truncate(128);
        match verify_vault_state_inclusion_proof(&signed) {
            Err(VaultSmtLeafError::BadSiblingCount { expected, actual }) => {
                assert_eq!(expected, 256);
                assert_eq!(actual, 128);
            }
            other => panic!("expected BadSiblingCount, got {other:?}"),
        }
    }

    #[test]
    fn verification_rejects_tampered_sibling() {
        let (pk, sk) = fixture_keys();
        let vault_id = [0x99u8; 32];
        let reserves_digest = compute_reserves_digest(b"AAA", b"BBB", 100, 200, 30);
        let (root, siblings) = fixture_proof(&vault_id, 0, &reserves_digest);

        let mut signed = sign_vault_state_inclusion_proof(
            &vault_id,
            0,
            &reserves_digest,
            &root,
            siblings,
            &pk,
            &sk,
        )
        .expect("sign succeeds");
        // Flip one byte in the lowest sibling — signature still
        // matches (because siblings are not part of the signed
        // payload, by design — the *root* is), but the inclusion
        // proof must reject.
        signed.smt_siblings[0][0] ^= 0xff;
        assert!(matches!(
            verify_vault_state_inclusion_proof(&signed),
            Err(VaultSmtLeafError::InclusionProofRejected)
        ));
    }

    #[test]
    fn sign_rejects_bad_sibling_count_at_construction() {
        let (pk, sk) = fixture_keys();
        let vault_id = [0xAAu8; 32];
        let reserves_digest = compute_reserves_digest(b"AAA", b"BBB", 100, 200, 30);
        let bad_siblings = vec![[0u8; 32]; 255];
        match sign_vault_state_inclusion_proof(
            &vault_id,
            0,
            &reserves_digest,
            &[0u8; 32],
            bad_siblings,
            &pk,
            &sk,
        ) {
            Err(VaultSmtLeafError::BadSiblingCount { expected, actual }) => {
                assert_eq!(expected, 256);
                assert_eq!(actual, 255);
            }
            other => panic!("expected BadSiblingCount, got {other:?}"),
        }
    }
}
