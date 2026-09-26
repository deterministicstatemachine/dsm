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
pub mod bootstrap;
pub mod economic_admission_flow;
pub mod economic_registers;
pub mod faucet_claim_flow;
pub mod kv;
pub mod native_reserve;
pub mod runtime_config;
pub mod sdk_context;

// Re-export SdkContext for convenient access
pub use sdk_context::SdkContext;
pub use bootstrap::SdkBootstrap;

// Core SDK modules - fundamental building blocks

pub mod anchor_enrollment_store;
pub mod app_state; // Shared application state management
pub mod apply_outcome; // §16.6 tri-state full-state apply outcome
pub mod b0x_sdk;
pub mod chain_tip_store;
pub mod core_sdk;
pub mod identity_publication; // publication-quorum lifecycle for device identities
pub mod inbox_poller;
pub mod kyber_identity; // ML-KEM identity binding for online contact establishment (§11.1)
pub mod session_manager; // Native-first session state projection
pub mod signing_authority;
pub mod sofi_advance;
/// SoFi v8 producers: setup, vault creation, trade, route and close.
pub mod sofi_exercise;
pub mod sofi_publish;
pub mod sofi_reads;
pub mod sofi_register;
pub mod sofi_relay;
pub mod sofi_sdk;
pub mod tls_transport_sdk;
pub mod token_sdk;
pub mod token_state;
// Storage-node client wrapper
pub mod device_directory;
pub mod route_seats;
pub mod sofi_flow;
pub mod storage_io;
pub mod storage_node_sdk;
pub mod storage_set; // canonical storage-set identity + catalog (the anchor chooses the set; config resolves it)

// Smart contract and commitment functionality
pub mod bitcoin_key_store;
pub mod bitcoin_tap_sdk;
pub mod bitcoin_tx_builder;
pub mod identity_presentation;
pub mod transfer_hooks;

// Recovery system SDK
pub mod recovery_sdk;
pub mod recovery_store;

// Hardware-sealed wallet-seed vault (cold-start signer unlock without the mnemonic)
pub mod seed_vault;

// Transport and communication modules

// Receipt primitives
pub mod receipts;

// Offline transaction modules

// Application-specific SDK implementations
pub mod contact_sdk;

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
