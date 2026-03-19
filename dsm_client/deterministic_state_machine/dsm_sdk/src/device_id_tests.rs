// SPDX-License-Identifier: MIT OR Apache-2.0

//! Regression tests: device ids used for online transport/auth must be
//! base32(32 bytes). Any dotted-decimal representation is UI/debug only.

use crate::util::text_id;

fn dotted32() -> String {
    (0u8..32u8)
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

#[test]
fn base32_roundtrip_32_bytes_ok() {
    let bytes: Vec<u8> = (0u8..32u8).collect();
    let b32 = text_id::encode_base32_crockford(&bytes);
    let decoded = match text_id::decode_base32_crockford(&b32) {
        Some(d) => d,
        None => panic!("decode failed"),
    };
    assert_eq!(decoded.len(), 32);
    assert_eq!(&decoded[..], &bytes[..]);
}

#[test]
fn dotted_decimal_is_not_base32() {
    let s = dotted32();
    assert!(text_id::decode_base32_crockford(&s).is_none());
}
