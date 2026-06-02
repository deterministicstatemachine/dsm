// SPDX-License-Identifier: MIT OR Apache-2.0

//! Deterministic ID Generation (No UUID, No Wall-Clock)
//!
//! This module provides deterministic, reproducible ID generation for all DSM components.
//! All IDs are derived from cryptographic hashes, never random UUIDs.
//!
//! Constraints:
//! - No UUID::new_v4() or UUID::now_v7() (non-deterministic)
//! - No wall-clock unix_tss
//! - All IDs are reproducible from explicit inputs

use crate::crypto::blake3::dsm_domain_hasher;

/// Generate a deterministic ID from domain-separated hash of inputs
///
/// # Arguments
/// * `domain` - Domain separator (e.g., "DSM/tx-id", "DSM/msg-id")
/// * `inputs` - Variable number of byte slices to hash
///
/// # Returns
/// Hex string of first 16 bytes of BLAKE3 hash (UUID-compatible format)
pub fn derive_id_from_hash(domain: &str, inputs: &[&[u8]]) -> String {
    let mut hasher = dsm_domain_hasher(crate::common::domain_tags::TAG_DSM_DETERMINISTIC_ID);
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

/// Generate a deterministic session ID from participants and unix_ts-free context
pub fn generate_session_id(context: &[u8]) -> String {
    derive_id_from_hash("DSM/session-id", &[context])
}
