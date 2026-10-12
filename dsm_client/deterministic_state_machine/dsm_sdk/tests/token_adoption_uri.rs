// SPDX-License-Identifier: MIT OR Apache-2.0
//! Handing a token to a peer: one encoder, one decoder, checked claims.
//!
//! A device that CREATED a token could not see its CPTA anchor anywhere, so
//! getting it to a peer meant deriving it off-device. Doing that by hand is how
//! this session lost an hour: the canonical encoder pads the TRAILING group and
//! the hand-rolled one padded the leading group, so the anchor was a plausible
//! 52-character string that resolved to nothing, and the resulting
//! POLICY_NOT_FOUND looked exactly like a publish failure.
//!
//! So both directions live in Rust. The QR payload is versioned like the
//! contact payload, and the adopt field takes either form. The payload's ticker
//! and token id are CLAIMS: the anchor still has to hash the fetched policy, so
//! a claim cannot change which token is adopted — but a mismatch means the user
//! is being shown a different name than the policy carries, and that is
//! refused rather than silently corrected.

#![allow(clippy::disallowed_methods)]

use dsm_sdk::handlers::token_routes::{build_adoption_uri, parse_adoption_input};
use dsm_sdk::util::text_id::encode_base32_crockford;

const ANCHOR: [u8; 32] = [0x5Au8; 32];

/// THE REPRODUCTION: the round trip a creator and an adopter actually perform.
#[test]
fn an_adoption_uri_round_trips_to_the_exact_anchor() {
    let uri = build_adoption_uri(&ANCHOR, "RIGB", "QMK5SY91");
    assert!(
        uri.starts_with("dsm:token/v1:"),
        "versioned like the contact payload, got {uri}"
    );

    let parsed = parse_adoption_input(&uri).expect("parses");
    assert_eq!(parsed.anchor, ANCHOR, "the anchor survives byte for byte");
    assert_eq!(parsed.claimed_ticker.as_deref(), Some("RIGB"));
    assert_eq!(parsed.claimed_token_id.as_deref(), Some("QMK5SY91"));
}

/// The other form: what a person reads off a screen and types.
#[test]
fn a_bare_base32_anchor_is_accepted_and_claims_nothing() {
    let parsed = parse_adoption_input(&encode_base32_crockford(&ANCHOR)).expect("parses");
    assert_eq!(parsed.anchor, ANCHOR);
    assert!(
        parsed.claimed_ticker.is_none() && parsed.claimed_token_id.is_none(),
        "a bare anchor asserts nothing about what it resolves to"
    );
}

/// CASE IS THE DECODER'S PROBLEM, NOT THE FIELD'S.
///
/// The adopt input used to uppercase what the user typed, because Crockford
/// Base32 is canonically uppercase. That silently destroyed the lowercase
/// `dsm:token/v1:` prefix, so every scanned payload parsed as a bare anchor and
/// then failed as invalid Base32 — on device, with a message that pointed at
/// the wrong thing entirely.
#[test]
fn case_is_normalised_here_so_a_field_never_has_to() {
    let uri = build_adoption_uri(&ANCHOR, "RIGB", "ID");
    for variant in [uri.to_uppercase(), uri.to_lowercase(), uri.clone()] {
        let parsed = parse_adoption_input(&variant)
            .unwrap_or_else(|e| panic!("must parse {variant:?}: {e}"));
        assert_eq!(parsed.anchor, ANCHOR);
        assert_eq!(parsed.claimed_ticker.as_deref(), Some("RIGB"));
    }
    // And a bare anchor in either case.
    let b32 = encode_base32_crockford(&ANCHOR);
    assert_eq!(
        parse_adoption_input(&b32.to_lowercase())
            .expect("lower")
            .anchor,
        ANCHOR
    );
    assert_eq!(parse_adoption_input(&b32).expect("upper").anchor, ANCHOR);
}

/// Surrounding whitespace is what a paste actually contains.
#[test]
fn input_is_trimmed() {
    let b32 = encode_base32_crockford(&ANCHOR);
    assert_eq!(
        parse_adoption_input(&format!("  {b32}\n"))
            .expect("parses")
            .anchor,
        ANCHOR
    );
    let uri = build_adoption_uri(&ANCHOR, "RIGB", "ID");
    assert_eq!(
        parse_adoption_input(&format!(" {uri} "))
            .expect("parses")
            .anchor,
        ANCHOR
    );
}

/// Everything that is not a usable anchor fails closed with a reason, rather
/// than producing 32 bytes of something.
#[test]
fn unusable_input_is_refused() {
    for (input, why) in [
        ("", "empty"),
        ("   ", "whitespace only"),
        ("not base32 !!!", "invalid alphabet"),
        ("ABC", "decodes to too few bytes"),
        ("dsm:token/v1:", "versioned prefix with no payload"),
        ("dsm:token/v1:!!!", "versioned prefix, undecodable payload"),
        ("dsm:token/v2:AAAA", "an unknown version is not read as v1"),
    ] {
        assert!(
            parse_adoption_input(input).is_err(),
            "must refuse {why}: {input:?}"
        );
    }
}

/// A v1 prefix carrying bytes that are valid Base32 but not the payload proto
/// must not be coerced into one.
#[test]
fn a_versioned_prefix_over_non_payload_bytes_is_refused() {
    let junk = encode_base32_crockford(&[0xFFu8; 48]);
    assert!(parse_adoption_input(&format!("dsm:token/v1:{junk}")).is_err());
}

/// An anchor of the wrong length is refused rather than truncated or padded —
/// silently reshaping it would point adoption at a different token.
#[test]
fn a_wrong_length_anchor_is_refused() {
    for len in [16usize, 31, 33, 64] {
        let bytes = vec![0x11u8; len];
        let err = parse_adoption_input(&encode_base32_crockford(&bytes))
            .expect_err("must refuse a non-32-byte anchor");
        assert!(
            err.contains("32 bytes"),
            "the refusal should say what was wrong, got: {err}"
        );
    }
}
