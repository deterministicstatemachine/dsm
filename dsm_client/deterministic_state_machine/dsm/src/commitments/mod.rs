// SPDX-License-Identifier: MIT OR Apache-2.0

//! Commitments Module
//!
//! The branch commitment a bilateral precommit binds (`precommit`) and external
//! commitments (`external_commitment`). Smart commitments (DSM §59) are not
//! built: an unwired implementation of an older shape was removed.

// Sub-modules
pub mod external_commitment;
pub mod precommit;

// Re-export key components for easier access
pub use external_commitment::{
    create_external_commitment, create_external_commitment_with_metadata, external_evidence_hash,
    external_source_id, verify_external_commitment, verify_external_commitment_with_metadata,
    DefaultExternalCommitmentVerifier, ExternalCommitment, ExternalCommitmentVerifier,
};
