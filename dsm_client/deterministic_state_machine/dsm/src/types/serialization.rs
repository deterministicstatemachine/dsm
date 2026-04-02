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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_u8_appends_single_byte() {
        let mut buf = Vec::new();
        put_u8(&mut buf, 0x42);
        assert_eq!(buf, vec![0x42]);
    }

    #[test]
    fn put_u8_zero_and_max() {
        let mut buf = Vec::new();
        put_u8(&mut buf, 0);
        put_u8(&mut buf, 255);
        assert_eq!(buf, vec![0, 255]);
    }

    #[test]
    fn put_u32_little_endian() {
        let mut buf = Vec::new();
        put_u32(&mut buf, 0x0102_0304);
        assert_eq!(buf, vec![0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn put_u32_zero() {
        let mut buf = Vec::new();
        put_u32(&mut buf, 0);
        assert_eq!(buf, vec![0, 0, 0, 0]);
    }

    #[test]
    fn put_u32_max() {
        let mut buf = Vec::new();
        put_u32(&mut buf, u32::MAX);
        assert_eq!(buf, vec![0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn put_u64_little_endian() {
        let mut buf = Vec::new();
        put_u64(&mut buf, 0x0102_0304_0506_0708);
        assert_eq!(buf, vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn put_u64_zero() {
        let mut buf = Vec::new();
        put_u64(&mut buf, 0);
        assert_eq!(buf, vec![0; 8]);
    }

    #[test]
    fn put_u64_max() {
        let mut buf = Vec::new();
        put_u64(&mut buf, u64::MAX);
        assert_eq!(buf, vec![0xFF; 8]);
    }

    #[test]
    fn put_bytes_prefixes_length_then_data() {
        let mut buf = Vec::new();
        put_bytes(&mut buf, &[0xAA, 0xBB, 0xCC]);
        // length = 3 as u32 LE, then the bytes
        assert_eq!(buf, vec![3, 0, 0, 0, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn put_bytes_empty_slice() {
        let mut buf = Vec::new();
        put_bytes(&mut buf, &[]);
        assert_eq!(buf, vec![0, 0, 0, 0]);
    }

    #[test]
    fn put_str_encodes_as_utf8_with_length() {
        let mut buf = Vec::new();
        put_str(&mut buf, "hi");
        // length = 2 as u32 LE, then b"hi"
        assert_eq!(buf, vec![2, 0, 0, 0, b'h', b'i']);
    }

    #[test]
    fn put_str_empty() {
        let mut buf = Vec::new();
        put_str(&mut buf, "");
        assert_eq!(buf, vec![0, 0, 0, 0]);
    }

    #[test]
    fn put_str_multibyte_utf8() {
        let mut buf = Vec::new();
        put_str(&mut buf, "\u{00E9}"); // é = 2 bytes in UTF-8
        let bytes = "\u{00E9}".as_bytes();
        assert_eq!(buf.len(), 4 + bytes.len());
        assert_eq!(&buf[..4], &(bytes.len() as u32).to_le_bytes());
        assert_eq!(&buf[4..], bytes);
    }

    #[test]
    fn sequential_writes_concatenate() {
        let mut buf = Vec::new();
        put_u8(&mut buf, 1);
        put_u32(&mut buf, 2);
        put_u64(&mut buf, 3);
        assert_eq!(buf.len(), 1 + 4 + 8);
    }
}
