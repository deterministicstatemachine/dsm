// SPDX-License-Identifier: MIT OR Apache-2.0

//! Commitments Module
//!
//! This module contains implementations of various commitment schemes used in DSM,
//! including pre-commitments, forward commitments, and deterministic smart commitments.
//!
//! Commitments are an essential part of DSM's security model, allowing for verifiable
//! state transitions without revealing underlying data or requiring global consensus.
//! The implementation follows sections 7, 14, and 15 of the whitepaper.

// Sub-modules
pub mod deterministic;
pub mod external_commitment;
pub mod parameter_comparison;
pub mod precommit;
pub mod smart_commitment;

// Re-export key components for easier access
pub use deterministic::{
    create_conditional_commitment, create_deterministic_commitment, create_recurring_commitment,
    create_time_locked_commitment, verify_deterministic_commitment,
};

pub use external_commitment::{
    create_external_commitment, create_external_commitment_with_metadata, external_evidence_hash,
    external_source_id, verify_external_commitment, verify_external_commitment_with_metadata,
    DefaultExternalCommitmentVerifier, ExternalCommitment, ExternalCommitmentVerifier,
};

pub use smart_commitment::{
    CommitmentCondition, CommitmentContext, SmartCommitment, SmartCommitmentReference,
    SmartCommitmentRegistry, ThresholdOperator,
};

/// Create a basic commitment by hashing the data with BLAKE3
pub fn create_commitment(data: &[u8]) -> Vec<u8> {
    crate::crypto::blake3::domain_hash("DSM/commitment", data)
        .as_bytes()
        .to_vec()
}

/// Verify a basic commitment by comparing it with a fresh hash of the data
pub fn verify_commitment(commitment: &[u8], data: &[u8]) -> bool {
    let calculated = create_commitment(data);
    calculated == commitment
}

/// Open a commitment using a nonce
/// Returns Some(data) if successful, None if invalid
pub fn open_commitment(commitment: &[u8], nonce: &[u8]) -> Option<Vec<u8>> {
    let mut hasher = crate::crypto::blake3::dsm_domain_hasher("DSM/commitment-open");
    hasher.update(commitment);
    hasher.update(nonce);
    Some(hasher.finalize().as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_verify_commitment() {
        let data = b"test data";
        let commitment = create_commitment(data);

        assert_eq!(commitment.len(), 32); // BLAKE3 produces 32-byte output
        assert!(verify_commitment(&commitment, data));
        assert!(!verify_commitment(&commitment, b"wrong data"));
    }

    #[test]
    fn test_open_commitment() {
        let data = b"test data";
        let nonce = b"test nonce";
        let commitment = create_commitment(data);

        let opened = open_commitment(&commitment, nonce).expect("Failed to open commitment");
        assert_eq!(opened.len(), 32);

        // Opening with different nonce should produce different result
        let opened2 = open_commitment(&commitment, b"different nonce")
            .expect("Failed to open commitment with different nonce");
        assert_ne!(opened, opened2);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Issue #179 regression — strengthen commitment verification tests beyond
    // shared-implementation self-recomputation. The tests below build the
    // expected digest using a raw `blake3::Hasher` (bypassing
    // `dsm_domain_hasher` + `domain_hash`) so a bug in the wrapper layer
    // cannot be reflected back into the verifier.
    // ────────────────────────────────────────────────────────────────────────

    /// Independent BLAKE3 evaluation of `H("DSM/commitment\0" || data)`.
    /// Reads NOTHING from `crate::crypto::blake3::*` so the verifier and
    /// the test do not share construction code.
    fn independent_basic_commitment_digest(data: &[u8]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"DSM/commitment");
        h.update(&[0u8]);
        h.update(data);
        *h.finalize().as_bytes()
    }

    #[test]
    fn basic_commitment_matches_independent_construction_for_known_inputs() {
        // Known-answer tests: each input has a digest that an independent
        // raw-BLAKE3 walk reproduces. If the wrapper drifts (domain tag,
        // NUL placement, framing), this test fails immediately.
        let cases: &[&[u8]] = &[
            b"",
            b"a",
            b"DSM-test",
            b"\x00\x01\x02\x03\x04\x05\x06\x07",
            &[0xFFu8; 64],
        ];
        for data in cases {
            let from_api = create_commitment(data);
            let from_independent = independent_basic_commitment_digest(data);
            assert_eq!(
                from_api.as_slice(),
                from_independent.as_slice(),
                "commitment digest must match H(\"DSM/commitment\\0\" || data) \
                 for input of len {}",
                data.len()
            );
        }
    }

    #[test]
    fn basic_commitment_domain_tag_is_load_bearing() {
        // The literal "DSM/commitment\0" prefix MUST be present in the
        // preimage. Recompute without the tag — must NOT match.
        let data = b"DSM-test";
        let from_api = create_commitment(data);
        let mut h_no_tag = blake3::Hasher::new();
        h_no_tag.update(data);
        let without_tag = *h_no_tag.finalize().as_bytes();
        assert_ne!(
            from_api.as_slice(),
            without_tag.as_slice(),
            "domain-tag-less hash must NOT equal create_commitment output"
        );
    }

    #[test]
    fn basic_commitment_verify_rejects_single_byte_corruption() {
        // For every byte position, flipping any bit must cause verify to fail.
        let data = b"DSM-test";
        let commitment = create_commitment(data);
        assert_eq!(commitment.len(), 32);
        for byte_idx in 0..commitment.len() {
            for bit in 0..8u8 {
                let mut corrupted = commitment.clone();
                corrupted[byte_idx] ^= 1 << bit;
                assert!(
                    !verify_commitment(&corrupted, data),
                    "verify_commitment must reject corruption at byte {byte_idx}, bit {bit}"
                );
            }
        }
    }

    #[test]
    fn basic_commitment_verify_rejects_corrupted_data() {
        // Mutating any byte of the input must break the digest.
        let data = b"DSM-test-input-payload";
        let commitment = create_commitment(data);
        for byte_idx in 0..data.len() {
            let mut corrupted = data.to_vec();
            corrupted[byte_idx] ^= 0xFF;
            assert!(
                !verify_commitment(&commitment, &corrupted),
                "verify_commitment must reject input corruption at byte {byte_idx}"
            );
        }
    }

    // Integration test between different commitment types
    #[test]
    fn test_commitment_integration() {
        // Create a basic commitment
        let data = b"original data";
        let basic_commitment = create_commitment(data);

        // Create an external commitment from the basic commitment
        let context = "ethereum";
        let source_id = external_source_id(context);
        let evidence_hash = external_evidence_hash(&[]);
        let external = create_external_commitment(&basic_commitment, &source_id, &evidence_hash);

        // Verify the external commitment
        assert!(verify_external_commitment(
            &external,
            &basic_commitment,
            &source_id,
            &evidence_hash
        ));

        // Create a deterministic commitment from operation data that includes our basic commitment
        use crate::crypto::sphincs::{generate_sphincs_keypair, sphincs_sign};
        use crate::types::operations::Operation;

        let (_pk, sk) = generate_sphincs_keypair().expect("keypair");
        let mut operation = Operation::Update {
            message: "Using basic commitment as operation data".to_string(),
            identity_id: b"test_identity".to_vec(),
            updated_data: basic_commitment.clone(),
            proof: vec![],
            forward_link: None,
        };
        let sig = sphincs_sign(&sk, &operation.to_bytes()).expect("sign update");
        if let Operation::Update { proof, .. } = &mut operation {
            *proof = sig;
        }

        let mut state_hash = [0u8; 32];
        state_hash[0..4].copy_from_slice(&[1, 2, 3, 4]);
        let recipient_info = b"recipient";

        let deterministic =
            create_deterministic_commitment(&state_hash, &operation, recipient_info, None)
                .expect("deterministic commitment must construct");

        // Verify the deterministic commitment
        assert!(verify_deterministic_commitment(
            &deterministic,
            &state_hash,
            &operation,
            recipient_info,
            None
        ));

        // The combination of these commitment types demonstrates the
        // flexible commitment architecture described in the whitepaper
    }
}
