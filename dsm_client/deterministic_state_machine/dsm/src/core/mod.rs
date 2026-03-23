//! Core module of the Deterministic State Machine (DSM).
//!
//! This module is the heart of the DSM protocol, providing the foundational components
//! for post-quantum, clockless, bilateral state management. It contains:
//!
//! - **State machine engine** ([`state_machine`]): Forward-only hash chain evolution,
//!   deterministic entropy derivation, pre-commitment verification, and batch processing.
//! - **Bridge traits** ([`bridge`]): Envelope routing and handler installation for
//!   dispatching protobuf-encoded operations to the appropriate subsystem (unilateral,
//!   bilateral, recovery, bootstrap, or application queries).
//! - **Bilateral management** ([`bilateral_relationship_manager`], [`bilateral_transaction_manager`]):
//!   Isolated bilateral state pairs with cross-chain continuity verification, forward-linked
//!   commitments, and chain-tip tracking as described in whitepaper Section 3.4.
//! - **Identity lifecycle** ([`identity`]): Genesis state creation via MPC, hierarchical
//!   device management, and device tree maintenance.
//! - **Token subsystem** ([`token`]): Token type definitions, conservation invariant
//!   enforcement (`B_{n+1} = B_n + Delta, B >= 0`), and policy validation via CPTA anchors.
//! - **Contact management** ([`contact_manager`]): Counterparty identity storage and
//!   lookup by device ID.
//! - **Security policies** ([`security`]): Access control, rate limiting, and protocol
//!   compliance enforcement.
//! - **Verification** ([`verification`]): Proof primitives for SMT inclusion proofs and
//!   device tree verification.
//! - **Chain tip store** ([`chain_tip_store`]): Per-relationship chain tip tracking for
//!   bilateral state synchronization.
//! - **Error types** ([`error`]): Structured error hierarchy for all core operations.

pub mod bilateral_relationship_manager;
pub mod bilateral_transaction_manager;
pub mod bridge;
pub mod chain_tip_store;
pub mod contact_manager;
pub mod debug_helpers;
pub mod error;
pub mod identity;
pub mod security;
pub mod state_machine;
pub mod token;
pub mod utility;
pub mod verification; // Expose core bridge interfaces for SDK integration

pub use error::DsmCoreError;

// Re-export bridge types for convenience
pub use bridge::{
    AppRouter, UnilateralHandler, BilateralHandler, BootstrapHandler, install_app_router,
    install_unilateral_handler, install_bilateral_handler, install_bootstrap_handler,
    handle_envelope_universal,
};
