//! Protocol type definitions for the DSM core crate.
//!
//! This module organizes all data types used throughout the DSM protocol:
//!
//! - [`error`] — [`error::DsmError`] comprehensive error type with deterministic safety classifications
//! - [`state_types`] — [`State`] struct (the central protocol data type) and related parameters
//! - [`token_types`] — [`Token`], [`TokenStatus`], supply parameters, and state context
//! - [`identifiers`] — Type-safe wrappers: [`NodeId`], [`VaultId`], [`SessionId`], [`TransactionId`], etc.
//! - [`operations`] — Operation trait hierarchy: [`Ops`], [`TokenOps`], [`IdOps`], [`SmartCommitOps`]
//! - [`identity`] — [`IdentityAnchor`] and [`IdentityClaim`] for device identity
//! - [`genesis_types`] — Genesis state and MPC genesis artifacts
//! - [`policy_types`] — [`TokenPolicy`], [`PolicyAnchor`], [`PolicyFile`] for CPTA
//! - [`receipt_types`] — Stitched receipts and verification contexts
//! - [`contact_types`] — Verified contact information
//! - [`general`] — Shared types: [`Commitment`], [`KeyPair`], [`SecurityLevel`]
//! - [`state_builder`] — Fluent builder for constructing [`State`] instances
//! - [`crypto_error`] — Cryptographic operation errors
//! - [`serialization`] — Protobuf serialization helpers
//! - [`proto`] — Generated protobuf types (from `dsm_app.proto`)
//! - [`ui_error`] — UI-facing error mappings
//! - [`unified_error`] — Cross-layer error adaptation

pub mod contact_types;
pub mod crypto_error;
pub mod device_state; // §2.2, §4, §8: Per-Device SMT head + relationship chains
pub mod error;
pub mod general;
pub mod genesis_types;
pub mod identifiers; // New type-safe identifiers
pub mod identity;
pub mod operations;
pub mod policy_types;
pub mod proto; // generated OUT_DIR include (dsm.rs)
pub mod receipt_types; // Canonical receipt structures
pub mod serialization;
pub mod state_builder;
pub mod state_types;
pub mod token_types;
pub mod ui_error;
pub mod unified_error;
// Re-export correctly named types
pub use contact_types::DsmVerifiedContact;
pub use general::{Commitment, DirectoryEntry, KeyPair, SecurityLevel, VerificationResult};
pub use identity::{IdentityAnchor, IdentityClaim};
pub use identifiers::{Entropy, GenesisHash, NodeId, SessionId, Signature, TransactionId, VaultId}; // New type-safe identifiers
pub use operations::{GenericOps, IdOps, Ops, SmartCommitOps, TokenOps}; // Remove Operation as it doesn't exist
pub use policy_types::{PolicyAnchor, PolicyFile, TokenPolicy};
pub use receipt_types::{
    ParentConsumptionTracker, ReceiptAcceptance, ReceiptVerificationContext, StitchedReceiptV2,
};
pub use state_builder::StateBuilder;
pub use state_types::State;
pub use token_types::{Token, TokenStatus};
