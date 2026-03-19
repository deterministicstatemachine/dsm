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
