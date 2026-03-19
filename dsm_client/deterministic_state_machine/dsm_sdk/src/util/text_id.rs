// SPDX-License-Identifier: MIT OR Apache-2.0
//! Binary-safe textual identifiers (no base64/hex).
//!
//! These helpers produce human-inspectable strings without using forbidden
//! encodings. They are intended for logs/UI only; core logic must remain bytes-first.

/// Encode bytes as dotted-decimal (e.g. `1.2.3`).
pub fn encode(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let mut s = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push('.');
        }
        s.push_str(&b.to_string());
    }
    s
}

/// Render the first n bytes as dotted-decimal short id.
pub fn short_id(bytes: &[u8], n: usize) -> String {
    let take = core::cmp::min(n, bytes.len());
    encode(&bytes[..take])
}

/// Base32 **Crockford** encoding (0-9, A-Z excluding I,L,O,U, no padding).
///
/// This is the **only** base32 variant permitted for human-readable IDs/logs in this repo.
/// Returns an empty string when `bytes` is empty.
pub fn encode_base32_crockford(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    // Alphabet per Crockford Base32
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    let mut out = String::new();
    let mut buffer: u16 = 0; // use 16 bits to be safe while shifting
    let mut bits_left: u8 = 0;

    for &b in bytes {
        buffer = (buffer << 8) | b as u16;
        bits_left += 8;
        while bits_left >= 5 {
            let idx = ((buffer >> (bits_left - 5)) & 0b1_1111) as usize;
            out.push(ALPHABET[idx] as char);
            bits_left -= 5;
        }
    }

    if bits_left > 0 {
        let idx = ((buffer << (5 - bits_left)) & 0b1_1111) as usize;
        out.push(ALPHABET[idx] as char);
    }

    out
}

/// Base32 **Crockford** decoding.
/// Handles common substitutions (o/O -> 0, i/I/l/L -> 1).
/// Returns `Some<Vec<u8>>` on success, or `None` if invalid characters are present.
/// Ignores leftover bits that do not make a full byte (matching encode_base32 behavior).
pub fn decode_base32_crockford(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'A'..=b'H' => Some(c - b'A' + 10), // A=10..H=17
            b'J'..=b'K' => Some(c - b'J' + 18), // J=18, K=19
            b'M'..=b'N' => Some(c - b'M' + 20), // M=20, N=21
            b'P'..=b'T' => Some(c - b'P' + 22), // P=22..T=26
            b'V'..=b'Z' => Some(c - b'V' + 27), // V=27..Z=31
            // Substitutions
            b'O' | b'o' => Some(0),
            b'I' | b'i' | b'L' | b'l' => Some(1),
            b'a'..=b'z' => val(c - 32), // recursive for lowercase
            _ => None,
        }
    }

    let mut out: Vec<u8> = Vec::with_capacity((s.len() * 5) / 8);
    let mut buffer: u32 = 0;
    let mut bits_left: u8 = 0;

    for ch in s.bytes() {
        if ch == b'-' || ch == b' ' {
            continue;
        } // Crockford allows hyphens and spaces
        let v = val(ch)? as u32;
        buffer = (buffer << 5) | v;
        bits_left += 5;
        while bits_left >= 8 {
            let byte = ((buffer >> (bits_left - 8)) & 0xFF) as u8;
            out.push(byte);
            bits_left -= 8;
        }
    }
    // Ignore leftover bits (they are zero-padded in encode)
    Some(out)
}

/// Alias for decoding textual identifiers used for genesis hash.
/// Decodes Base32 Crockford (with substitutions for o/O, i/I/l/L).
pub fn decode(s: &str) -> Option<Vec<u8>> {
    decode_base32_crockford(s)
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    #[test]
    fn test_base32_roundtrip_small() {
        let data = b"hello world";
        let enc = encode_base32_crockford(data);
        let dec = decode_base32_crockford(&enc).expect("decode ok");
        assert_eq!(dec, data, "roundtrip must preserve bytes");
    }

    #[test]
    fn test_base32_empty() {
        let enc = encode_base32_crockford(&[]);
        assert_eq!(enc, "", "empty encode gives empty string");
        let dec = decode_base32_crockford(&enc).expect("decode empty ok");
        assert!(dec.is_empty(), "decoded empty vector");
    }

    #[test]
    fn test_base32_invalid_char() {
        // Include invalid symbol '@'
        assert!(
            decode_base32_crockford("ABC@EF").is_none(),
            "invalid character should fail"
        );
    }

    #[test]
    fn test_base32_full_block_alignment() {
        // 5 bytes becomes 8 chars; ensure decode matches.
        let data = [0x00u8, 0xFF, 0x10, 0x20, 0x30];
        let enc = encode_base32_crockford(&data);
        assert!(
            enc.len() >= 8,
            "encoded length expected >=8 (got {})",
            enc.len()
        );
        let dec = decode_base32_crockford(&enc).unwrap();
        assert_eq!(dec, data);
    }
    #[test]
    fn test_crockford_case_insensitive() {
        let data = [5u8; 10];
        let enc = encode_base32_crockford(&data); // Crockford encoding
        let lower = enc.to_ascii_lowercase();
        assert!(decode(&enc).is_some(), "uppercase must decode");
        assert!(
            decode(&lower).is_some(),
            "lowercase must also decode (Crockford)"
        );
    }
}
