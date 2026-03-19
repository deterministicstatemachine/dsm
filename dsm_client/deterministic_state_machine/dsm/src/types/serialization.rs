//! Canonical Serialization Helpers
//!
//! Centralized, auditable serialization primitives for DSM.
//! Enforces little-endian byte order and consistent format.

/// Append a u8 to the vector
#[inline]
pub fn put_u8(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}

/// Append a u32 to the vector (little-endian)
#[inline]
pub fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// Append a u64 to the vector (little-endian)
#[inline]
pub fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// Append a byte slice to the vector, prefixed with its length as u32
#[inline]
pub fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_u32(out, b.len() as u32);
    out.extend_from_slice(b);
}

/// Append a string to the vector, prefixed with its length as u32
#[inline]
pub fn put_str(out: &mut Vec<u8>, s: &str) {
    put_bytes(out, s.as_bytes());
}
