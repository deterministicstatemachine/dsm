// SPDX-License-Identifier: MIT OR Apache-2.0
//! Domain-separated hash helpers for common SDK patterns.
//!
//! These thin wrappers ensure Hard Invariant 9 compliance:
//! all hashing uses `BLAKE3-256("DSM/<domain>\0" || data)`.

use dsm::crypto::blake3::domain_hash;

/// Derive a 32-byte device identifier from a string label.
///
/// Replaces the pervasive `blake3::hash(label.as_bytes()).into()` pattern
/// with proper domain separation: `BLAKE3("DSM/device-id\0" || label)`.
#[inline]
pub fn device_id_hash(label: &str) -> [u8; 32] {
    *domain_hash("DSM/device-id", label.as_bytes()).as_bytes()
}

/// Derive a 32-byte device identifier from raw bytes.
#[inline]
pub fn device_id_hash_bytes(bytes: &[u8]) -> [u8; 32] {
    *domain_hash("DSM/device-id", bytes).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_hash_deterministic() {
        let a = device_id_hash("alice");
        let b = device_id_hash("alice");
        assert_eq!(a, b);
    }

    #[test]
    fn device_id_hash_different_labels_differ() {
        let a = device_id_hash("alice");
        let b = device_id_hash("bob");
        assert_ne!(a, b);
    }

    #[test]
    fn device_id_hash_is_32_bytes() {
        let h = device_id_hash("test");
        assert_eq!(h.len(), 32);
    }

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
    fn device_id_hash_string_vs_bytes_consistent() {
        let label = "test-device";
        let from_str = device_id_hash(label);
        let from_bytes = device_id_hash_bytes(label.as_bytes());
        assert_eq!(from_str, from_bytes);
    }

    #[test]
    fn device_id_hash_empty_label() {
        let h = device_id_hash("");
        assert_ne!(h, [0u8; 32], "even empty label should produce a non-zero hash");
    }

    #[test]
    fn device_id_hash_bytes_empty_input() {
        let h = device_id_hash_bytes(b"");
        assert_ne!(h, [0u8; 32]);
    }
}
