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

/// Centralized CBOR encoding helpers for canonical byte streams.
/// These replace scattered manual CBOR construction throughout the codebase.
pub mod cbor {
    use crate::DsmError;

    /// Encode a 32-byte bstr with definite length (canonical form)
    #[inline]
    pub fn encode_bstr_32(buf: &mut Vec<u8>, data: &[u8; 32]) {
        // Major type 2 (bstr), additional info = 24 (1-byte length follows)
        buf.push(0x58); // 0b010_11000
        buf.push(32); // Length = 32
        buf.extend_from_slice(data);
    }

    /// Encode a variable-length bstr with definite length (canonical form)
    #[inline]
    pub fn encode_bstr_variable(buf: &mut Vec<u8>, data: &[u8]) -> Result<(), DsmError> {
        let len = data.len();

        if len <= 23 {
            // Major type 2, additional info = len (0-23 inline)
            buf.push(0x40 | (len as u8));
        } else if len <= 0xFF {
            // 1-byte length
            buf.push(0x58); // Major type 2, additional info 24
            buf.push(len as u8);
        } else if len <= 0xFFFF {
            // 2-byte length (big-endian)
            buf.push(0x59); // Major type 2, additional info 25
            buf.extend_from_slice(&(len as u16).to_be_bytes());
        } else if len <= 0xFFFF_FFFF {
            // 4-byte length (big-endian)
            buf.push(0x5a); // Major type 2, additional info 26
            buf.extend_from_slice(&(len as u32).to_be_bytes());
        } else {
            return Err(DsmError::InvalidOperation(format!(
                "Data too large for CBOR encoding: {} bytes",
                len
            )));
        }

        buf.extend_from_slice(data);
        Ok(())
    }

    /// Encode a CBOR array header with definite length
    #[inline]
    pub fn encode_array_header(buf: &mut Vec<u8>, len: usize) -> Result<(), DsmError> {
        if len <= 23 {
            // Major type 4, additional info = len (0-23 inline)
            buf.push(0x80 | (len as u8));
        } else if len <= 0xFF {
            // 1-byte length
            buf.push(0x98); // Major type 4, additional info 24
            buf.push(len as u8);
        } else if len <= 0xFFFF {
            // 2-byte length (big-endian)
            buf.push(0x99); // Major type 4, additional info 25
            buf.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            return Err(DsmError::InvalidOperation(format!(
                "Array too large for CBOR encoding: {} elements",
                len
            )));
        }
        Ok(())
    }
}

/// Length-prefixed encoding helpers (replaces scattered pushLP/writeLP/putU32 functions)
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
    fn test_cbor_bstr_32_encoding() {
        let mut buf = Vec::new();
        let data = [42u8; 32];
        cbor::encode_bstr_32(&mut buf, &data);

        assert_eq!(buf.len(), 34);
        assert_eq!(buf[0], 0x58);
        assert_eq!(buf[1], 32);
        assert_eq!(&buf[2..], &data[..]);
    }

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
    fn test_cbor_bstr_variable_empty() {
        let mut buf = Vec::new();
        cbor::encode_bstr_variable(&mut buf, &[]).unwrap();
        assert_eq!(buf, vec![0x40]); // major type 2, length 0 inline
    }

    #[test]
    fn test_cbor_bstr_variable_small() {
        let mut buf = Vec::new();
        let data = [0xAB; 5];
        cbor::encode_bstr_variable(&mut buf, &data).unwrap();

        assert_eq!(buf[0], 0x40 | 5); // major type 2, length 5 inline
        assert_eq!(&buf[1..], &data[..]);
    }

    #[test]
    fn test_cbor_bstr_variable_one_byte_length() {
        let data = vec![0xFF; 100];
        let mut buf = Vec::new();
        cbor::encode_bstr_variable(&mut buf, &data).unwrap();

        assert_eq!(buf[0], 0x58); // 1-byte length
        assert_eq!(buf[1], 100);
        assert_eq!(&buf[2..], &data[..]);
    }

    #[test]
    fn test_cbor_bstr_variable_two_byte_length() {
        let data = vec![0x01; 300];
        let mut buf = Vec::new();
        cbor::encode_bstr_variable(&mut buf, &data).unwrap();

        assert_eq!(buf[0], 0x59); // 2-byte length
        let len = u16::from_be_bytes([buf[1], buf[2]]);
        assert_eq!(len, 300);
        assert_eq!(buf.len(), 3 + 300);
    }

    #[test]
    fn test_cbor_array_header_inline() {
        let mut buf = Vec::new();
        cbor::encode_array_header(&mut buf, 3).unwrap();
        assert_eq!(buf, vec![0x80 | 3]);
    }

    #[test]
    fn test_cbor_array_header_one_byte_length() {
        let mut buf = Vec::new();
        cbor::encode_array_header(&mut buf, 200).unwrap();
        assert_eq!(buf[0], 0x98);
        assert_eq!(buf[1], 200);
    }

    #[test]
    fn test_cbor_array_header_two_byte_length() {
        let mut buf = Vec::new();
        cbor::encode_array_header(&mut buf, 1000).unwrap();
        assert_eq!(buf[0], 0x99);
        let len = u16::from_be_bytes([buf[1], buf[2]]);
        assert_eq!(len, 1000);
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

    #[test]
    fn test_cbor_bstr_variable_boundary_23_bytes() {
        let data = vec![0x01; 23];
        let mut buf = Vec::new();
        cbor::encode_bstr_variable(&mut buf, &data).unwrap();

        assert_eq!(buf[0], 0x40 | 23); // still inline
        assert_eq!(buf.len(), 1 + 23);
    }

    #[test]
    fn test_cbor_bstr_variable_boundary_24_bytes() {
        let data = vec![0x01; 24];
        let mut buf = Vec::new();
        cbor::encode_bstr_variable(&mut buf, &data).unwrap();

        assert_eq!(buf[0], 0x58); // switches to 1-byte length
        assert_eq!(buf[1], 24);
        assert_eq!(buf.len(), 2 + 24);
    }
}
