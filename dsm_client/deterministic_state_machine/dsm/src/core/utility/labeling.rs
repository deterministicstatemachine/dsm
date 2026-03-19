//! Non-canonical labeling utilities for human-readable output.
//!
//! # ARCHITECTURAL WARNING
//! This module is explicitly EXCLUDED from the cryptographic boundary.
//! Functions here produce non-canonical, non-deterministic string representations
//! (e.g. decimal IDs, short hashes) intended ONLY for logging, debugging, and UI.
//!
//! NEVER use output from this module in:
//! - Hash chains
//! - Signatures
//! - Merkle proofs
//! - State serialization
//!
//! Any import of this module within core consensus logic is an audit violation.

use crate::core::identity::Identity;

/// Convert an Identity to a human-readable string label (decimal-only).
/// Derived from first 16 bytes of genesis hash.
pub fn identity_to_string(identity: &Identity) -> String {
    let h = &identity.master_genesis.hash;
    let (a, b) = if h.len() >= 16 {
        let mut lo = [0u8; 8];
        let mut hi = [0u8; 8];
        lo.copy_from_slice(&h[0..8]);
        hi.copy_from_slice(&h[8..16]);
        (u64::from_le_bytes(lo), u64::from_le_bytes(hi))
    } else {
        (0, 0)
    };
    format!("{}-{}", a, b)
}

/// Convert an Identity to a short decimal label (first 8 bytes).
/// For logs/UI only.
pub fn identity_short_id(identity: &Identity) -> String {
    let h = &identity.master_genesis.hash;
    let num = if h.len() >= 8 {
        let mut lo = [0u8; 8];
        lo.copy_from_slice(&h[0..8]);
        u64::from_le_bytes(lo)
    } else {
        0u64
    };
    num.to_string()
}

/// Convert a raw 32-byte hash to a short decimal label.
pub fn hash_to_short_id(hash: &[u8]) -> String {
    let num = if hash.len() >= 8 {
        let mut lo = [0u8; 8];
        lo.copy_from_slice(&hash[0..8]);
        u64::from_le_bytes(lo)
    } else {
        0u64
    };
    num.to_string()
}
