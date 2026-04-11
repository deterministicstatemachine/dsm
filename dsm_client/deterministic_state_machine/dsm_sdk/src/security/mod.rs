//! # DSM Security Module
//!
//! Provides cryptographic security primitives that maintain offline capabilities.
//! All sensitive data is encrypted at rest while preserving full offline transaction
//! creation, validation, and queuing functionality.

pub mod cdbrw_access_gate;
pub mod cdbrw_enrollment_writer;
pub mod cdbrw_ffi;
pub mod cdbrw_responder;
pub mod cdbrw_verifier;
pub mod identity;
pub mod offline_security;
pub mod shared_smt;
pub mod wal_transaction_queue;

pub use offline_security::{
    DeviceMasterKey, EncryptedAppState, EncryptedTransaction, OfflineTransactionQueue,
    SecureAppState, SensitiveAppData,
};
pub use wal_transaction_queue::WalTransactionQueue;
