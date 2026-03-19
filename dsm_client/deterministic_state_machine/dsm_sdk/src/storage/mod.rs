//! # DSM Client Storage Module
//!
//! Provides the persistent storage layer for the DSM client:
//! SQLite-based data persistence for contacts, chain tips, bilateral
//! state, DLV records, and transaction history. All data is stored as
//! raw binary (no JSON, no Base64).
// • Cryptographic verification of all stored data
// • Hash chain and SMT proof integration
// • No in-memory alternate paths per DSM protocol compliance
// • Bilateral storage interface for offline capability
pub mod bcr_storage;
pub mod bilateral;
pub mod client_db;
pub mod codecs;
pub mod policy_fs;
pub mod soft_vault;

// Re-export key types and functions for easy access
pub use client_db::{
    init_database, store_genesis_record_with_verification, get_verified_genesis_record,
    initialize_wallet_from_verified_genesis, verify_wallet_against_stored_genesis, store_contact,
    get_all_contacts, store_transaction, get_transaction_history, update_wallet_balance,
    get_wallet_state, upsert_token_balance, get_token_balances, get_token_balance, GenesisRecord,
    VerificationResult, WalletState, ContactRecord, TransactionRecord,
};

// Re-export bilateral storage interface
pub use bilateral::{
    BilateralStorageInterface, BilateralStorageSDK, BilateralStorageConfig, BilateralStorageStats,
    BilateralKey,
};

pub use bcr_storage::BcrStorage;
