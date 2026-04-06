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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_empty_writer() {
        let w = CanonicalBytesWriter::new();
        assert!(w.as_slice().is_empty());
        assert_eq!(w.into_vec().len(), 0);
    }

    #[test]
    fn with_capacity_creates_empty_writer() {
        let w = CanonicalBytesWriter::with_capacity(1024);
        assert!(w.as_slice().is_empty());
        assert_eq!(w.into_vec().len(), 0);
    }

    #[test]
    fn default_creates_empty_writer() {
        let w = CanonicalBytesWriter::default();
        assert!(w.as_slice().is_empty());
    }

    #[test]
    fn push_u32_le_encodes_correctly() {
        let mut w = CanonicalBytesWriter::new();
        w.push_u32_le(0x04030201);
        assert_eq!(w.as_slice(), &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn push_u32_le_zero() {
        let mut w = CanonicalBytesWriter::new();
        w.push_u32_le(0);
        assert_eq!(w.as_slice(), &[0, 0, 0, 0]);
    }

    #[test]
    fn push_u32_le_max() {
        let mut w = CanonicalBytesWriter::new();
        w.push_u32_le(u32::MAX);
        assert_eq!(w.as_slice(), &[0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn push_u64_le_encodes_correctly() {
        let mut w = CanonicalBytesWriter::new();
        w.push_u64_le(0x0807060504030201);
        assert_eq!(
            w.as_slice(),
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn push_u64_le_zero() {
        let mut w = CanonicalBytesWriter::new();
        w.push_u64_le(0);
        assert_eq!(w.as_slice(), &[0; 8]);
    }

    #[test]
    fn push_len_prefixed_encodes_length_and_data() {
        let mut w = CanonicalBytesWriter::new();
        w.push_len_prefixed(b"abc");
        // length prefix: 3u32 LE = [3, 0, 0, 0], then payload
        assert_eq!(w.as_slice(), &[3, 0, 0, 0, b'a', b'b', b'c']);
    }

    #[test]
    fn push_len_prefixed_empty_data() {
        let mut w = CanonicalBytesWriter::new();
        w.push_len_prefixed(b"");
        assert_eq!(w.as_slice(), &[0, 0, 0, 0]);
    }

    #[test]
    fn push_opt_len_prefixed_some() {
        let mut w = CanonicalBytesWriter::new();
        w.push_opt_len_prefixed(Some(b"xy"));
        assert_eq!(w.as_slice(), &[2, 0, 0, 0, b'x', b'y']);
    }

    #[test]
    fn push_opt_len_prefixed_none() {
        let mut w = CanonicalBytesWriter::new();
        w.push_opt_len_prefixed(None);
        assert_eq!(w.as_slice(), &[0, 0, 0, 0]);
    }

    #[test]
    fn push_opt_none_same_as_empty_slice() {
        let mut w_none = CanonicalBytesWriter::new();
        w_none.push_opt_len_prefixed(None);

        let mut w_empty = CanonicalBytesWriter::new();
        w_empty.push_len_prefixed(b"");

        assert_eq!(w_none.as_slice(), w_empty.as_slice());
    }

    #[test]
    fn push_str_encodes_as_bytes() {
        let mut w = CanonicalBytesWriter::new();
        w.push_str("hi");
        assert_eq!(w.as_slice(), &[2, 0, 0, 0, b'h', b'i']);
    }

    #[test]
    fn push_str_empty() {
        let mut w = CanonicalBytesWriter::new();
        w.push_str("");
        assert_eq!(w.as_slice(), &[0, 0, 0, 0]);
    }

    #[test]
    fn push_bytes32_encodes_fixed_array() {
        let mut w = CanonicalBytesWriter::new();
        let arr = [0xAB_u8; 32];
        w.push_bytes32(&arr);
        // length prefix: 32u32 LE = [32, 0, 0, 0], then 32 bytes of 0xAB
        assert_eq!(w.as_slice().len(), 4 + 32);
        assert_eq!(&w.as_slice()[..4], &[32, 0, 0, 0]);
        assert_eq!(&w.as_slice()[4..], &[0xAB; 32]);
    }

    #[test]
    fn push_vec_of_bytes32_empty() {
        let mut w = CanonicalBytesWriter::new();
        let items: &[[u8; 32]] = &[];
        w.push_vec_of_bytes32(items);
        // count = 0 u32 LE
        assert_eq!(w.as_slice(), &[0, 0, 0, 0]);
    }

    #[test]
    fn push_vec_of_bytes32_two_items() {
        let mut w = CanonicalBytesWriter::new();
        let a = [0x11_u8; 32];
        let b = [0x22_u8; 32];
        w.push_vec_of_bytes32(&[a, b]);

        // count(2) + 2*(len_prefix(32) + 32 bytes)
        let expected_len = 4 + 2 * (4 + 32);
        assert_eq!(w.as_slice().len(), expected_len);
        // Count
        assert_eq!(&w.as_slice()[..4], &[2, 0, 0, 0]);
        // First item length prefix
        assert_eq!(&w.as_slice()[4..8], &[32, 0, 0, 0]);
        // First item data
        assert_eq!(&w.as_slice()[8..40], &[0x11; 32]);
        // Second item length prefix
        assert_eq!(&w.as_slice()[40..44], &[32, 0, 0, 0]);
        // Second item data
        assert_eq!(&w.as_slice()[44..76], &[0x22; 32]);
    }

    #[test]
    fn into_vec_returns_buffer() {
        let mut w = CanonicalBytesWriter::new();
        w.push_u32_le(42);
        let v = w.into_vec();
        assert_eq!(v, 42u32.to_le_bytes());
    }

    #[test]
    fn as_slice_returns_reference() {
        let mut w = CanonicalBytesWriter::new();
        w.push_u32_le(7);
        let s = w.as_slice();
        assert_eq!(s, &7u32.to_le_bytes());
        // Writer is still usable after as_slice
        w.push_u32_le(8);
        assert_eq!(w.as_slice().len(), 8);
    }

    #[test]
    fn multiple_pushes_concatenate() {
        let mut w = CanonicalBytesWriter::new();
        w.push_u32_le(1);
        w.push_u64_le(2);
        w.push_str("z");

        let mut expected = Vec::new();
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(&2u64.to_le_bytes());
        expected.extend_from_slice(&1u32.to_le_bytes()); // length prefix for "z"
        expected.push(b'z');
        assert_eq!(w.into_vec(), expected);
    }

    #[test]
    fn clone_produces_independent_copy() {
        let mut w = CanonicalBytesWriter::new();
        w.push_u32_le(99);
        let mut w2 = w.clone();
        w2.push_u32_le(100);
        assert_eq!(w.as_slice().len(), 4);
        assert_eq!(w2.as_slice().len(), 8);
    }
}
