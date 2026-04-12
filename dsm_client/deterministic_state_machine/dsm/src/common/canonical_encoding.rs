//! # Canonical Encoding Module
//!
//! Centralized, audited canonical encoding for cryptographic commitments.
//! All structures that contribute to state hashes must implement the CanonicalEncode trait.
//!
//! This module provides:
//! - Consistent byte ordering and field inclusion
//! - Standardized length prefixing
//! - Domain separation for cryptographic operations
//! - Single source of truth for all canonical encodings

use crate::DsmError;

/// Trait for structures that can be canonically encoded for cryptographic commitments.
/// All implementations must ensure deterministic, unambiguous byte representation.
pub trait CanonicalEncode {
    /// Encode this structure to canonical bytes for hashing/commitment.
    /// Must be deterministic and unambiguous.
    fn to_canonical_bytes(&self) -> Result<Vec<u8>, DsmError>;

    /// Return the domain tag for this type's canonical encoding.
    fn domain_tag(&self) -> &'static str;
}

/// Length-prefixed encoding helpers used by legacy binary helpers that remain
/// outside the protobuf-only canonical commitment path.
pub mod length_prefix {
    use crate::DsmError;

    /// Encode with 4-byte big-endian length prefix
    #[inline]
    pub fn encode_u32_prefix(buf: &mut Vec<u8>, data: &[u8]) -> Result<(), DsmError> {
        if data.len() > u32::MAX as usize {
            return Err(DsmError::InvalidOperation(
                "Data too large for u32 length prefix".to_string(),
            ));
        }
        buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
        buf.extend_from_slice(data);
        Ok(())
    }

    /// Encode with variable-length prefix (1, 2, or 4 bytes as needed)
    #[inline]
    pub fn encode_variable_prefix(buf: &mut Vec<u8>, data: &[u8]) -> Result<(), DsmError> {
        let len = data.len();
        if len <= 0xFF {
            buf.push(len as u8);
        } else if len <= 0xFFFF {
            buf.extend_from_slice(&(len as u16).to_be_bytes());
        } else if len <= 0xFFFF_FFFF {
            buf.extend_from_slice(&(len as u32).to_be_bytes());
        } else {
            return Err(DsmError::InvalidOperation(
                "Data too large for variable length prefix".to_string(),
            ));
        }
        buf.extend_from_slice(data);
        Ok(())
    }
}

/// Helper for domain-separated hashing
#[inline]
pub fn domain_separated_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let mut hasher = crate::crypto::blake3::dsm_domain_hasher(tag);
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_length_prefix_u32() {
        let mut buf = Vec::new();
        let data = b"hello";
        length_prefix::encode_u32_prefix(&mut buf, data).unwrap();

        assert_eq!(buf.len(), 9);
        assert_eq!(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]), 5);
        assert_eq!(&buf[4..], data);
    }

    #[test]
    fn test_length_prefix_u32_empty_data() {
        let mut buf = Vec::new();
        length_prefix::encode_u32_prefix(&mut buf, &[]).unwrap();
        assert_eq!(buf.len(), 4);
        assert_eq!(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]), 0);
    }

    #[test]
    fn test_length_prefix_variable_small() {
        let mut buf = Vec::new();
        let data = b"abc";
        length_prefix::encode_variable_prefix(&mut buf, data).unwrap();

        assert_eq!(buf[0], 3u8); // 1-byte length
        assert_eq!(&buf[1..], data.as_slice());
    }

    #[test]
    fn test_length_prefix_variable_medium() {
        let data = vec![0x42; 300];
        let mut buf = Vec::new();
        length_prefix::encode_variable_prefix(&mut buf, &data).unwrap();

        let len = u16::from_be_bytes([buf[0], buf[1]]);
        assert_eq!(len, 300);
        assert_eq!(&buf[2..], &data[..]);
    }

    #[test]
    fn test_domain_separated_hash_deterministic() {
        let h1 = domain_separated_hash("DSM/test-tag", b"payload");
        let h2 = domain_separated_hash("DSM/test-tag", b"payload");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_domain_separated_hash_different_tags_differ() {
        let h1 = domain_separated_hash("DSM/tag-a", b"payload");
        let h2 = domain_separated_hash("DSM/tag-b", b"payload");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_domain_separated_hash_different_data_differ() {
        let h1 = domain_separated_hash("DSM/tag", b"data-1");
        let h2 = domain_separated_hash("DSM/tag", b"data-2");
        assert_ne!(h1, h2);
    }
}
