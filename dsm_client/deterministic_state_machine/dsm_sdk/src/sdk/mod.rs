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
//! * `hashchain_sdk` removed: superseded by DeviceState (§2.2) for current tip + BCR archive for history
//! * `identity_sdk`: Handles cryptographic identity creation and management
//! * `token_sdk`: Provides token operations and policy enforcement
//! * `token_mpc_sdk`: Implements secure token creation using MPC and manages bilateral transfers
//! * `policy_cache`: Provides efficient token policy caching and validation
//! * `counterparty_genesis_helpers`: Manages verification and caching of counterparty Genesis states
//!
//! ### Smart Contract Functionality
//!
//! * `smart_commitment_sdk`: Creates and verifies cryptographic commitments
//!
//! ### Transport and Communication
//!
//! * `bluetooth_transport`: Enables device-to-device communication via Bluetooth
//!
//! ### Application-Specific Implementations
//!
//! * `contact_sdk`: Manages peer relationships and communications
//! * `wallet_sdk`: Key management and secure storage capabilities
//!
pub mod bootstrap;
pub mod kv;
pub mod runtime_config;
pub mod sdk_context;

// Re-export SdkContext for convenient access
pub use sdk_context::SdkContext;
pub use bootstrap::SdkBootstrap;

// Core SDK modules - fundamental building blocks

pub mod app_state; // Shared application state management
pub mod b0x_sdk;
pub mod chain_tip_store;
pub mod core_sdk;
pub mod counterparty_genesis_helpers;
pub mod dlv_sdk;
pub mod external_commitment_sdk;
// pub mod hashchain_sdk; — deleted (superseded by DeviceState + BCR archive)
pub mod identity_sdk;
pub mod inbox_poller;
pub mod policy_cache;
#[cfg(test)]
mod qr; // QR code creation and parsing for contacts - enabled for tests only
pub mod session_manager; // Native-first session state projection
pub mod signing_authority;
pub mod tls_transport_sdk;
pub mod token_mpc_sdk;
pub mod token_sdk;
pub mod token_state;
pub mod unilateral_ops_sdk;
// Storage-node client wrapper and discovery (dev-only)
#[cfg(feature = "dev-discovery")]
pub mod discovery;
#[cfg(target_os = "android")]
pub mod preview;
pub mod storage_node_health;
pub mod storage_node_sdk;

// Chain tip synchronization and blockchain integration
// Blockchain transport is feature-gated: JSON (Web3) support is opt-in only.
// Default builds should not pull in serde_json or reqwest/json features.
// Blockchain transport removed: DSM is protobuf-only and does not include JSON/Web3 transports.
// If blockchain transport functionality is required, implement a protobuf-based transport
// that communicates using generated proto messages and prost encoding.
// pub mod blockchain_transport;  // removed by purge
// pub mod chain_tip_sync_sdk;  // deleted: 787-line module with zero external
// consumers. ChainTipSyncSDK was never instantiated outside its own tests; its
// internal UniversalTransport trait had no implementors beyond the tests' DummyTransport.
// Per-relationship chain-tip anchoring is now handled inline in
// bilateral_transaction_manager + contacts store.

// Smart contract and commitment functionality
pub mod bitcoin_key_store;
pub mod bitcoin_tap_sdk;
pub mod bitcoin_tx_builder;
pub mod dlv_pre_commitment_sdk;
pub mod dlv_receipt_sdk;
pub mod smart_commitment_sdk;
pub mod transfer_hooks;

// Recovery system SDK
pub mod recovery_sdk;

// Transport and communication modules
pub mod bluetooth_transport;
pub mod secure_ble_transport;

// Receipt primitives (local replacement for removed core module)
pub mod receipts;

// Offline transaction modules

// Application-specific SDK implementations
pub mod contact_sdk;

pub mod wallet_sdk;

// Network detection and auto-configuration (dev-only)
#[cfg(feature = "dev-discovery")]
pub mod network_detection;

// Re-export primary SDK components for easier access
pub use bluetooth_transport::{
    BluetoothMode, BluetoothTransport, BleBridgeEvent, BilateralBluetoothMessage,
};
pub use core_sdk::CoreSDK;
// pub use hashchain_sdk::HashChainSDK; — module deleted
pub use identity_sdk::IdentitySDK;
pub use wallet_sdk::WalletSDK;
pub use storage_node_sdk::StorageNodeSDK;
pub use storage_node_health::{
    StorageNodeHealthMonitor, StorageNodeDiscovery, StorageNodeConnectionPool, HealthMonitorConfig,
    PoolConfig, StorageNodeHealth,
};
pub use contact_sdk::ContactSDK;
pub use dlv_sdk::DlvSdk;
// Note: BilateralContactManager and BilateralOfflineTransactionManager are not public types
pub use smart_commitment_sdk::SmartCommitmentSDK;
pub use bitcoin_tap_sdk::BitcoinTapSdk;
pub use bitcoin_key_store::BitcoinKeyStore;
pub use dlv_pre_commitment_sdk::DlvPreCommitmentSdk;
pub use dlv_receipt_sdk::DlvReceiptSdk;
pub use recovery_sdk::RecoverySDK;
pub use token_sdk::TokenSDK;
pub use token_mpc_sdk::TokenMpcSDK;
// chain_tip_sync_sdk re-exports removed alongside the module deletion above.
// blockchain_transport removed as part of protobuf-only purge.
// If chain integration is required, implement a protobuf-native transport and reintroduce here.
pub use runtime_config::RuntimeConfig;
#[cfg(feature = "storage")]
pub use storage_sync_sdk::StorageSyncSdk;
#[cfg(feature = "storage")]
pub mod genesis_publisher;
#[cfg(feature = "storage")]
pub mod storage_sync_sdk;
pub use b0x_sdk::B0xSDK;
pub use unilateral_ops_sdk::UnilateralOpsSDK;
