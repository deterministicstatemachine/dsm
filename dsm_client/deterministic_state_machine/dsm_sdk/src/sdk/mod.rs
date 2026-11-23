// SPDX-License-Identifier: MIT OR Apache-2.0

//! # DSM SDK Core Module
//!
//! This module provides the foundation for the DSM Software Development Kit,
//! organizing functionality into logical components for building DSM applications.
//!
//! ## Module Organization
//!
//! The SDK is organized into several categories of modules:
//!
//! ### Core Foundational Modules
//!
//! * `core_sdk`: Central integration point for all DSM functionality
//! * `token_sdk`: Provides token operations and policy enforcement
//!
//! ### Application-Specific Implementations
//!
//! * `contact_sdk`: Manages peer relationships and communications
//! * `wallet_sdk`: Key management and secure storage capabilities
//!
pub mod app_cell_flow;
/// Objects an account publishes under a topic of its own, signed by its AK.
pub mod authored_objects;
/// Computed escrow vaults (SoFi §19.10): an outcome a pinned program decides.
pub mod computed_flow;
pub mod economic_admission_flow;
pub mod economic_registers;
/// Escrow vaults (SoFi §19.9): stakes released by a canonical verdict.
pub mod escrow_flow;
pub mod faucet_claim_flow;
pub mod native_reserve;
pub mod origin_cell_flow; // offline origin cells (DSM Amendment A39)
pub mod outcome_programs;
pub mod runtime_config;
pub mod sdk_context;
pub mod wallet_backup_flow; // a wallet's sealed backups (DSM Amendment A40)

// Re-export SdkContext for convenient access
pub use sdk_context::SdkContext;

// Core SDK modules - fundamental building blocks

pub mod anchor_enrollment_store;
pub mod app_lock; // The app lock: Rust enrolls and checks the PIN or pattern
pub mod app_state; // Shared application state management
pub mod apply_outcome; // §16.6 tri-state full-state apply outcome
pub mod b0x_sdk;
pub mod bounded_read; // every answer body read within its kind's limit or a local budget
pub mod chain_tip_store;
pub mod connect; // DSM Connect: a Web2 application connected to a wallet (DSM Amendment A11)
pub mod core_sdk;
pub mod identity_publication; // publication-quorum lifecycle for device identities
pub mod inbox_poller;
pub mod inbox_waiter; // long-poll on the storage nodes beside the poller
pub mod kyber_identity; // ML-KEM identity binding carried in offline messages
pub mod lineage_discovery;
pub mod realized_records;
pub mod session_manager; // Native-first session state projection
pub mod signing_authority;
pub mod sofi_advance;
pub mod sofi_exercise;
pub mod sofi_publish;
pub mod sofi_reads;
pub mod sofi_register;
pub mod sofi_relay;
/// SoFi v8 producers: setup, vault creation, trade, route and close.
pub mod sofi_sdk;
pub mod tls_transport_sdk;
pub mod token_sdk;
pub mod token_state;
pub mod vault_baseline;
pub mod vault_history;
// Storage-node clients
pub mod device_directory;
pub(crate) mod final_reads;
pub mod route_seats;
pub mod sofi_flow;
pub mod spool_write; // the write a device sends for each envelope it spools (DSM Amendment A34)
pub mod storage_io;
pub mod storage_node_sdk;
pub mod storage_set; // canonical storage-set identity + catalog (the anchor chooses the set; config resolves it)

// The Bitcoin tap (dBTC; not functional in this release) and identity presentation
pub mod bitcoin_key_store;
pub mod bitcoin_tap_sdk;
pub mod bitcoin_tx_builder;
pub mod identity_presentation;
pub mod transfer_hooks;

// Recovery system SDK
pub mod recovery_sdk;
pub mod recovery_store;

// Hardware-sealed wallet-seed vault (cold-start signer unlock without the mnemonic),
// on the builds whose platform holds a key to seal under.
#[cfg(any(all(target_os = "android", feature = "jni"), feature = "ffi"))]
pub mod seed_vault;

// Transport and communication modules

// Receipt primitives
pub mod receipts;

// Offline transaction modules

// Application-specific SDK implementations
pub mod contact_profile; // a person's details as the wallet shows them (DSM Amendment A17)
pub mod contact_sdk;
pub mod email_receipts; // a courtesy email receipt after a send (DSM Amendment A17)
pub mod money_waiting; // the count on the app icon of money received and not yet looked at

pub mod wallet_sdk;

// Re-export primary SDK components for easier access
pub use core_sdk::CoreSDK;
pub use wallet_sdk::WalletSDK;
// Note: BilateralContactManager and BilateralOfflineTransactionManager are not public types
pub use bitcoin_tap_sdk::BitcoinTapSdk;
pub use bitcoin_key_store::BitcoinKeyStore;
pub use recovery_sdk::RecoverySDK;
pub use token_sdk::TokenSDK;
pub use runtime_config::RuntimeConfig;
pub use b0x_sdk::B0xSDK;
