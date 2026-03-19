//! External commitment functionality
//!
//! This module provides functions to create and verify external commitments,
//! which are commitments that are published to external systems.

use crate::crypto::blake3::dsm_domain_hasher;

/// External commitment structure for cross-chain publication
#[derive(Debug, Clone)]
pub struct ExternalCommitment {
    /// External payload bytes (original content being committed)
    pub payload: Vec<u8>,

    /// Canonical source identifier (hash of source string)
    pub source_id: [u8; 32],

    /// Optional evidence bytes
    pub evidence: Vec<u8>,

    /// External commitment hash (derived from source_id + payload + evidence_hash)
    pub commit_id: [u8; 32],
}

/// External commitment verification interface
pub trait ExternalCommitmentVerifier {
    /// Verify an external commitment against payload, source, and evidence
    fn verify_external_commitment(
        &self,
        external: &[u8],
        payload: &[u8],
        source: &str,
        evidence: &[u8],
    ) -> bool;

    /// Create a new external commitment from payload, source, and evidence
    fn create_external_commitment(&self, payload: &[u8], source: &str, evidence: &[u8])
        -> [u8; 32];
}

impl ExternalCommitment {
    /// Create a new external commitment
    pub fn new(payload: Vec<u8>, source_id: [u8; 32], evidence: Vec<u8>) -> Self {
        let evidence_hash = external_evidence_hash(&evidence);
        let commit_id = create_external_commitment(&payload, &source_id, &evidence_hash);

        Self {
            payload,
            source_id,
            evidence,
            commit_id,
        }
    }

    /// Create a new external commitment using a source string
    pub fn new_with_source(payload: Vec<u8>, source: &str, evidence: Vec<u8>) -> Self {
        let source_id = external_source_id(source);
        Self::new(payload, source_id, evidence)
    }

    /// Verify this external commitment
    pub fn verify(&self, original: &[u8]) -> bool {
        // Check that the stored payload matches the provided original
        if self.payload != original {
            return false;
        }

        // Recalculate the source id and commit id
        let evidence_hash = external_evidence_hash(&self.evidence);
        let calculated_hash = create_external_commitment(original, &self.source_id, &evidence_hash);

        // Verify the calculated hash matches the stored commit id
        calculated_hash == self.commit_id
    }
}

/// Default implementation of external commitment verification
pub struct DefaultExternalCommitmentVerifier;

impl ExternalCommitmentVerifier for DefaultExternalCommitmentVerifier {
    fn verify_external_commitment(
        &self,
        external: &[u8],
        payload: &[u8],
        source: &str,
        evidence: &[u8],
    ) -> bool {
        let expected = self.create_external_commitment(payload, source, evidence);
        expected == external
    }

    fn create_external_commitment(
        &self,
        payload: &[u8],
        source: &str,
        evidence: &[u8],
    ) -> [u8; 32] {
        let source_id = external_source_id(source);
        let evidence_hash = external_evidence_hash(evidence);
        create_external_commitment(payload, &source_id, &evidence_hash)
    }
}

/// Canonical source id for external commitments
pub fn external_source_id(source: &str) -> [u8; 32] {
    let mut hasher = dsm_domain_hasher("DSM/external-source-id");
    hasher.update(source.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Canonical evidence hash (zero if evidence is empty)
pub fn external_evidence_hash(evidence: &[u8]) -> [u8; 32] {
    if evidence.is_empty() {
        return [0u8; 32];
    }
    let mut hasher = dsm_domain_hasher("DSM/external-evidence");
    hasher.update(evidence);
    *hasher.finalize().as_bytes()
}

/// Create an external commitment by combining payload, source id, and evidence hash
///
/// # Parameters
/// - `commitment`: The internal commitment to externalize.
/// - `context`: The context string that identifies where this commitment is published.
///
/// # Returns
/// - A new commitment that includes both the original commitment and the context.
pub fn create_external_commitment(
    payload: &[u8],
    source_id: &[u8; 32],
    evidence_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = dsm_domain_hasher("DSM/external-commit-id");
    hasher.update(source_id);
    hasher.update(payload);
    hasher.update(evidence_hash);
    *hasher.finalize().as_bytes()
}

/// Verify an external commitment against payload, source id, and evidence hash
///
/// # Parameters
/// - `external`: The external commitment to verify.
/// - `original`: The original internal commitment.
/// - `source_id`: The canonical source id used for publication.
///
/// # Returns
/// - `true` if the external commitment was derived from the original commitment
///   and context, `false` otherwise.
pub fn verify_external_commitment(
    external: &[u8],
    payload: &[u8],
    source_id: &[u8; 32],
    evidence_hash: &[u8; 32],
) -> bool {
    let expected = create_external_commitment(payload, source_id, evidence_hash);
    expected == external
}

/// Create an external commitment from an internal commitment with metadata
///
/// # Parameters
/// - `commitment`: The internal commitment to externalize.
/// - `context`: The context string that identifies where this commitment is published.
/// - `metadata`: Additional metadata to include in the external commitment.
///
/// # Returns
/// - A new commitment that includes the original commitment, context, and metadata.
pub fn create_external_commitment_with_metadata(
    commitment: &[u8],
    context: &str,
    metadata: &[u8],
) -> Vec<u8> {
    let source_id = external_source_id(context);
    let evidence_hash = external_evidence_hash(metadata);
    create_external_commitment(commitment, &source_id, &evidence_hash).to_vec()
}

/// Verify an external commitment with metadata
pub fn verify_external_commitment_with_metadata(
    external: &[u8],
    original: &[u8],
    context: &str,
    metadata: &[u8],
) -> bool {
    let source_id = external_source_id(context);
    let evidence_hash = external_evidence_hash(metadata);
    let expected = create_external_commitment(original, &source_id, &evidence_hash);
    expected.as_slice() == external
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_external_commitment() {
        let internal = b"internal commitment";
        let context = "ethereum";

        let source_id = external_source_id(context);
        let evidence_hash = external_evidence_hash(&[]);
        let external = create_external_commitment(internal, &source_id, &evidence_hash);

        // Output should be a BLAKE3 hash (32 bytes)
        assert_eq!(external.len(), 32);

        // The same input should produce the same output
        let external2 = create_external_commitment(internal, &source_id, &evidence_hash);
        assert_eq!(external, external2);

        // Different context should produce different output
        let external3 = create_external_commitment(
            internal,
            &external_source_id("solana"),
            &external_evidence_hash(&[]),
        );
        assert_ne!(external, external3);
    }

    #[test]
    fn test_verify_external_commitment() {
        let internal = b"test commitment";
        let context = "ethereum";

        let external = create_external_commitment(
            internal,
            &external_source_id(context),
            &external_evidence_hash(&[]),
        );

        // Correct verification
        assert!(verify_external_commitment(
            &external,
            internal,
            &external_source_id(context),
            &external_evidence_hash(&[])
        ));

        // Incorrect context
        assert!(!verify_external_commitment(
            &external,
            internal,
            &external_source_id("wrong"),
            &external_evidence_hash(&[])
        ));

        // Incorrect original commitment
        assert!(!verify_external_commitment(
            &external,
            b"wrong",
            &external_source_id(context),
            &external_evidence_hash(&[])
        ));

        // Both incorrect
        assert!(!verify_external_commitment(
            &external,
            b"wrong",
            &external_source_id("wrong"),
            &external_evidence_hash(&[])
        ));
    }

    #[test]
    fn test_external_commitment_struct() {
        let internal = b"internal commitment".to_vec();
        let context = "ethereum".to_string();

        // Create external commitment
        let commitment = ExternalCommitment::new_with_source(internal.clone(), &context, vec![]);

        // Verify the commitment
        assert!(commitment.verify(&internal));

        // Verify with incorrect original
        let wrong_internal = b"wrong commitment".to_vec();
        assert!(!commitment.verify(&wrong_internal));
    }

    #[test]
    fn test_external_commitment_with_metadata() {
        let internal = b"internal commitment";
        let context = "ethereum";
        let metadata = b"tick=1234567890";

        let external = create_external_commitment_with_metadata(internal, context, metadata);

        // Correct verification
        assert!(verify_external_commitment_with_metadata(
            &external, internal, context, metadata
        ));

        // Incorrect metadata
        assert!(!verify_external_commitment_with_metadata(
            &external,
            internal,
            context,
            b"tick=0987654321"
        ));

        // Incorrect context and metadata
        assert!(!verify_external_commitment_with_metadata(
            &external,
            internal,
            "wrong",
            b"tick=0987654321"
        ));
    }

    #[test]
    fn test_default_verifier() {
        let verifier = DefaultExternalCommitmentVerifier;
        let internal = b"internal commitment";
        let context = "ethereum";

        let external = verifier.create_external_commitment(internal, context, &[]);

        // Correct verification
        assert!(verifier.verify_external_commitment(&external, internal, context, &[]));

        // Incorrect context
        assert!(!verifier.verify_external_commitment(&external, internal, "wrong", &[]));
    }
}
