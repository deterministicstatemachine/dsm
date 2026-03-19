//! Canonical byte encoding helpers for DSM.
//!
//! Canon 2: centralize internal canonical serialization.
//! - No JSON/base64/hex.
//! - No map iteration nondeterminism.
//! - No wall-clock dependence.
//! - Explicit, frozen field order.
//!
//! This module intentionally does NOT implement Protobuf encoding.
//! Where canonical Protobuf commit messages exist, prefer deterministic `prost::Message`
//! encoding at the boundary (see `envelope/canonical.rs`).

use crate::types::error::DsmError;

/// A small helper for constructing deterministic bytes.
///
/// Encoding rules:
/// - u32/u64 are little-endian.
/// - variable-length byte/string fields are length-prefixed with u32.
/// - `None` is encoded as length = 0.
/// - fixed 32-byte fields are encoded as length-prefixed 32 bytes to avoid ambiguity.
#[derive(Debug, Default, Clone)]
pub struct CanonicalBytesWriter {
    buf: Vec<u8>,
}

impl CanonicalBytesWriter {
    #[inline]
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    #[inline]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    #[inline]
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    #[inline]
    pub fn push_u32_le(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    #[inline]
    pub fn push_u64_le(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    #[inline]
    pub fn push_len_prefixed(&mut self, bytes: &[u8]) {
        // Truncation is impossible with usize->u32 for realistic DSM payload sizes;
        // keep explicit cast to pin the format.
        self.push_u32_le(bytes.len() as u32);
        self.buf.extend_from_slice(bytes);
    }

    #[inline]
    pub fn push_opt_len_prefixed(&mut self, bytes: Option<&[u8]>) {
        match bytes {
            Some(b) => self.push_len_prefixed(b),
            None => self.push_u32_le(0),
        }
    }

    #[inline]
    pub fn push_str(&mut self, s: &str) {
        self.push_len_prefixed(s.as_bytes());
    }

    #[inline]
    pub fn push_bytes32(&mut self, b: &[u8; 32]) {
        self.push_len_prefixed(b);
    }

    #[inline]
    pub fn push_vec_of_bytes32(&mut self, items: &[[u8; 32]]) {
        self.push_u32_le(items.len() as u32);
        for it in items {
            self.push_bytes32(it);
        }
    }
}

/// Trait for producing canonical bytes suitable for hashing/signing.
///
/// Implementations MUST:
/// - specify a strict field order;
/// - sort any collections explicitly;
/// - avoid encoding debug strings;
/// - avoid encoding wall-clock markers.
pub trait ToCanonicalBytes {
    fn to_canonical_bytes(&self) -> Result<Vec<u8>, DsmError>;
}
