// SPDX-License-Identifier: MIT OR Apache-2.0

//! Core module of the Deterministic State Machine (DSM).
//!
//! This module is the heart of the DSM protocol, providing the foundational components
//! for post-quantum, clockless, bilateral state management. It contains:
//!
//! - **State machine** ([`state_machine`]): the device head and the one transition path
//!   onto it, `DeviceState::advance`.
//! - **Bridge** ([`bridge`]): Envelope v3 routing of queries, invokes and faucet claims to
//!   the installed `AppRouter`.
//! - **Bilateral management** ([`bilateral_transaction_manager`]): relationship tips,
//!   precommitments, signing and the Tripwire prechecks of the steps between two contacts.
//! - **Relationship lifecycle** ([`relationship_lifecycle`]): the ESTABLISH and TERMINATE
//!   steps (DSM Amendment A33); **write grants** ([`relationship_write_grant`]): the inbox
//!   write locks and grants (DSM Amendments A34, A37).
//! - **Identity** ([`identity`]): mnemonic-rooted genesis (Genesis v2/v3), the
//!   device directory entry, and the P0–P6 device-authority resolver.
//! - **Token subsystem** ([`token`]): Token type definitions, conservation invariant
//!   enforcement (`B_{n+1} = B_n + Delta, B >= 0`), and policy validation via CPTA anchors.
//! - **Contact management** ([`contact_manager`]): Counterparty identity storage and
//!   lookup by device ID.
//! - **Chain tip store** ([`chain_tip_store`]): Per-relationship chain tip tracking for
//!   bilateral state synchronization.
//! - **Error types** ([`error`]): Structured error hierarchy for all core operations.

pub mod bilateral_transaction_manager;
pub mod bridge;
pub mod chain_tip_store;
pub mod contact_manager;
pub mod error;
pub mod identity;
pub mod relationship_lifecycle;
pub mod relationship_write_grant;
pub mod state_machine;
pub mod token;
pub mod utility;

pub use error::DsmCoreError;

// Re-export bridge types for convenience
pub use bridge::{AppRouter, install_app_router, handle_envelope_universal};
