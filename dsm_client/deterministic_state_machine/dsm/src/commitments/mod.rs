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
pub mod external_commitment;
pub mod precommit;
pub mod smart_commitment;

// Re-export key components for easier access
pub use external_commitment::{
    create_external_commitment, create_external_commitment_with_metadata, external_evidence_hash,
    external_source_id, verify_external_commitment, verify_external_commitment_with_metadata,
    DefaultExternalCommitmentVerifier, ExternalCommitment, ExternalCommitmentVerifier,
};

pub use smart_commitment::{
    CommitmentCondition, CommitmentContext, SmartCommitment, SmartCommitmentReference,
    SmartCommitmentRegistry, ThresholdOperator,
};
