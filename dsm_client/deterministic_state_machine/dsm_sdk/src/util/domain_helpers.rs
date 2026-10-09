// SPDX-License-Identifier: MIT OR Apache-2.0
//! Domain-separated hash helpers for common SDK patterns.
//!
//! These thin wrappers ensure Hard Invariant 9 compliance:
//! all hashing uses `BLAKE3-256("DSM/<domain>\0" || data)`.

use dsm::common::domain_tags::TAG_DEVICE_ID;
use dsm::crypto::blake3::domain_hash;

/// Derive a 32-byte device identifier from raw bytes.
#[inline]
pub fn device_id_hash_bytes(bytes: &[u8]) -> [u8; 32] {
    *domain_hash(TAG_DEVICE_ID, bytes).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_hash_bytes_deterministic() {
        let data = b"some raw device data";
        let a = device_id_hash_bytes(data);
        let b = device_id_hash_bytes(data);
        assert_eq!(a, b);
    }

    #[test]
    fn device_id_hash_bytes_different_inputs_differ() {
        let a = device_id_hash_bytes(b"input-one");
        let b = device_id_hash_bytes(b"input-two");
        assert_ne!(a, b);
    }

    #[test]
    fn device_id_hash_bytes_empty_input() {
        let h = device_id_hash_bytes(b"");
        assert_ne!(h, [0u8; 32]);
    }
}
