// SPDX-License-Identifier: MIT OR Apache-2.0

//! # DSM Client Storage Module
//!
//! Provides the persistent storage layer for the DSM client:
//! SQLite-based data persistence for contacts, chain tips, bilateral
//! state, DLV records, and transaction history. All data is stored as
//! raw binary (no JSON, no Base64).
// • Cryptographic verification of all stored data
// • Hash chain and SMT proof integration
// • No in-memory alternate paths per DSM protocol compliance
// pub mod bcr_storage — deleted alongside core::security (heuristic detection
// layer removed). The bcr_states SQLite table and its codec in client_db::bcr
// stay as a durable state archive.
pub mod client_db;
pub mod codecs;

// Re-export key types and functions for easy access
pub use client_db::{
    init_database, store_genesis_record_with_verification, get_verified_genesis_record,
    store_contact, get_all_contacts, store_transaction, get_transaction_history, GenesisRecord,
    ContactRecord, TransactionRecord,
};
