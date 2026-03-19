//! Deterministic ID Generation (No UUID, No Wall-Clock)
//!
//! This module provides deterministic, reproducible ID generation for all DSM components.
//! All IDs are derived from cryptographic hashes and/or atomic counters, never random UUIDs.
//!
//! Constraints:
//! - No UUID::new_v4() or UUID::now_v7() (non-deterministic)
//! - No wall-clock timestamps
//! - All IDs are reproducible from inputs or monotonic counters

use crate::crypto::blake3::dsm_domain_hasher;
use std::sync::atomic::{AtomicU64, Ordering};

/// Global atomic counter for deterministic sequential IDs
static SEQUENTIAL_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generate a deterministic ID from domain-separated hash of inputs
///
/// # Arguments
/// * `domain` - Domain separator (e.g., "DSM/tx-id", "DSM/msg-id")
/// * `inputs` - Variable number of byte slices to hash
///
/// # Returns
/// Hex string of first 16 bytes of BLAKE3 hash (UUID-compatible format)
pub fn derive_id_from_hash(domain: &str, inputs: &[&[u8]]) -> String {
    let mut hasher = dsm_domain_hasher("DSM/deterministic-id");
    hasher.update(domain.as_bytes());

    for input in inputs {
        hasher.update(input);
    }

    let hash = hasher.finalize();
    let bytes = hash.as_bytes();

    // Take first 16 bytes and format as UUID-compatible string
    // Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

/// Generate a deterministic sequential ID
///
/// # Arguments
/// * `prefix` - Prefix for the ID (e.g., "tx", "msg", "batch")
///
/// # Returns
/// String in format "{prefix}_{counter}" where counter is monotonically increasing
pub fn generate_sequential_id(prefix: &str) -> String {
    let counter = SEQUENTIAL_COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("{}_{:016x}", prefix, counter)
}

/// Generate a deterministic transaction ID from sender, recipient, and operation hash
pub fn generate_tx_id(sender_id: &[u8], recipient_id: &[u8], op_hash: &[u8]) -> String {
    derive_id_from_hash("DSM/tx-id", &[sender_id, recipient_id, op_hash])
}

/// Generate a deterministic message ID from sender and sequence
pub fn generate_message_id(sender_id: &[u8], sequence: u64) -> String {
    let seq_bytes = sequence.to_le_bytes();
    derive_id_from_hash("DSM/msg-id", &[sender_id, &seq_bytes])
}

/// Generate a deterministic batch ID from batch contents hash
pub fn generate_batch_id(batch_hash: &[u8]) -> String {
    derive_id_from_hash("DSM/batch-id", &[batch_hash])
}

/// Generate a deterministic session ID from participants and timestamp-free context
pub fn generate_session_id(context: &[u8]) -> String {
    derive_id_from_hash("DSM/session-id", &[context])
}

/// Generate a deterministic entry ID from entry data hash
pub fn generate_entry_id(entry_hash: &[u8]) -> String {
    derive_id_from_hash("DSM/entry-id", &[entry_hash])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_hash_based_id() {
        let sender = b"sender123";
        let recipient = b"recipient456";
        let op_hash = b"op_hash_data";

        let id1 = generate_tx_id(sender, recipient, op_hash);
        let id2 = generate_tx_id(sender, recipient, op_hash);

        // Same inputs should produce same ID
        assert_eq!(id1, id2);

        // Different inputs should produce different ID
        let id3 = generate_tx_id(b"different", recipient, op_hash);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_sequential_id_monotonic() {
        let id1 = generate_sequential_id("test");
        let id2 = generate_sequential_id("test");

        // IDs should be different and monotonically increasing
        assert_ne!(id1, id2);
        assert!(id2 > id1);
    }

    #[test]
    fn test_message_id_deterministic() {
        let sender = b"device_abc";
        let seq1 = 42u64;
        let seq2 = 43u64;

        let msg1 = generate_message_id(sender, seq1);
        let msg2 = generate_message_id(sender, seq1);
        let msg3 = generate_message_id(sender, seq2);

        // Same inputs produce same ID
        assert_eq!(msg1, msg2);

        // Different sequence produces different ID
        assert_ne!(msg1, msg3);
    }

    #[test]
    fn test_id_format_uuid_compatible() {
        let sender = b"test";
        let recipient = b"test2";
        let op_hash = b"hash";

        let id = generate_tx_id(sender, recipient, op_hash);

        // Should match UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        assert_eq!(id.len(), 36);
        assert_eq!(&id[8..9], "-");
        assert_eq!(&id[13..14], "-");
        assert_eq!(&id[18..19], "-");
        assert_eq!(&id[23..24], "-");
    }

    #[test]
    fn test_domain_separation() {
        let data = b"same_data";

        let tx_id = derive_id_from_hash("DSM/tx-id", &[data]);
        let msg_id = derive_id_from_hash("DSM/msg-id", &[data]);

        // Different domains with same data should produce different IDs
        assert_ne!(tx_id, msg_id);
    }
}
