//! Base32 Crockford encoding/decoding for compiled blob output.
//! Ported from dsm_sdk::util::text_id — canonical DSM encoding.

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub fn encode(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    let mut buffer: u16 = 0;
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

pub fn decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'A'..=b'H' => Some(c - b'A' + 10),
            b'J'..=b'K' => Some(c - b'J' + 18),
            b'M'..=b'N' => Some(c - b'M' + 20),
            b'P'..=b'T' => Some(c - b'P' + 22),
            b'V'..=b'Z' => Some(c - b'V' + 27),
            b'O' | b'o' => Some(0),
            b'I' | b'i' | b'L' | b'l' => Some(1),
            b'a'..=b'z' => val(c - 32),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let mut buffer: u16 = 0;
    let mut bits_left: u8 = 0;
    for &c in s.as_bytes() {
        let v = val(c)?;
        buffer = (buffer << 5) | v as u16;
        bits_left += 5;
        if bits_left >= 8 {
            out.push((buffer >> (bits_left - 8)) as u8);
            bits_left -= 8;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let data = vec![0u8; 32];
        let encoded = encode(&data);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }
    #[test]
    fn roundtrip_nonzero() {
        let data: Vec<u8> = (0..160).map(|i| i as u8).collect();
        let encoded = encode(&data);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }
}
