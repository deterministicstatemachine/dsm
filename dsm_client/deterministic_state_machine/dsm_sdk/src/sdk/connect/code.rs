// SPDX-License-Identifier: MIT OR Apache-2.0

//! The connect code an application shows (DSM Amendment A11):
//! `dsm:connect/v1:` followed by the Base32 Crockford of a [`ConnectCodeV1`].
//! A pointer only: it names the endpoint, the pin of the endpoint's TLS leaf
//! certificate and the digest of the offer; the signed offer is fetched from
//! the endpoint. Parsing lives here, in Rust, so there is one decoder.

use dsm::types::proto as generated;
use prost::Message;

use super::d32;
use crate::util::text_id::{decode_base32_crockford, encode_base32_crockford};

/// The scheme prefix, versioned like `dsm:contact/v3:` and `dsm:token/v1:`.
pub const CONNECT_CODE_PREFIX: &str = "dsm:connect/v1:";

/// The longest endpoint a code may name.
pub const MAX_ENDPOINT_LEN: usize = 512;

/// A connect code, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectCode {
    pub endpoint: String,
    pub cert_pin: [u8; 32],
    pub offer_digest: [u8; 32],
}

/// An endpoint a code may name: an `https://` origin, nothing after it.
pub fn check_endpoint(endpoint: &str) -> Result<(), String> {
    if endpoint.len() > MAX_ENDPOINT_LEN {
        return Err(format!(
            "the endpoint is {} bytes; at most {MAX_ENDPOINT_LEN}",
            endpoint.len()
        ));
    }
    let rest = endpoint
        .strip_prefix("https://")
        .ok_or_else(|| "the endpoint is not an https:// origin".to_string())?;
    if rest.is_empty() || rest.contains('/') || rest.contains('?') || rest.contains('#') {
        return Err("the endpoint must be an origin (https://host:port), with no path".into());
    }
    Ok(())
}

/// The text a code's QR encodes.
pub fn encode(code: &ConnectCode) -> String {
    let wire = generated::ConnectCodeV1 {
        endpoint: code.endpoint.clone(),
        cert_pin: code.cert_pin.to_vec(),
        offer_digest: code.offer_digest.to_vec(),
    };
    format!(
        "{CONNECT_CODE_PREFIX}{}",
        encode_base32_crockford(&wire.encode_to_vec())
    )
}

/// The code a scanned or pasted text carries.
pub fn parse(text: &str) -> Result<ConnectCode, String> {
    let text = text.trim();
    let body = match text.get(..CONNECT_CODE_PREFIX.len()) {
        Some(prefix) if prefix.eq_ignore_ascii_case(CONNECT_CODE_PREFIX) => {
            &text[CONNECT_CODE_PREFIX.len()..]
        }
        _ => return Err(format!("a connect code starts with {CONNECT_CODE_PREFIX}")),
    };
    let bytes = decode_base32_crockford(&body.trim().to_ascii_uppercase())
        .ok_or_else(|| "the connect code is not Base32 Crockford".to_string())?;
    let wire = generated::ConnectCodeV1::decode(bytes.as_slice())
        .map_err(|e| format!("the connect code carries no code: {e}"))?;
    if wire.encode_to_vec() != bytes {
        return Err("the connect code is not in its canonical encoding".into());
    }
    check_endpoint(&wire.endpoint)?;
    Ok(ConnectCode {
        endpoint: wire.endpoint,
        cert_pin: d32(&wire.cert_pin, "the certificate pin")?,
        offer_digest: d32(&wire.offer_digest, "the offer digest")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code() -> ConnectCode {
        ConnectCode {
            endpoint: "https://192.168.1.20:8443".into(),
            cert_pin: [7; 32],
            offer_digest: [9; 32],
        }
    }

    #[test]
    fn a_code_reads_back_as_written() {
        let text = encode(&code());
        assert!(text.starts_with(CONNECT_CODE_PREFIX));
        assert_eq!(parse(&text), Ok(code()));
        assert_eq!(parse(&text.to_ascii_lowercase()), Ok(code()));
    }

    #[test]
    fn a_code_that_is_not_one_is_refused() {
        parse("dsm:contact/v3:ABC").expect_err("must be refused");
        parse("dsm:connect/v1:not-base32!").expect_err("must be refused");
        let mut short = code();
        short.endpoint = "http://192.168.1.20:8443".into();
        parse(&encode(&short)).expect_err("a cleartext endpoint");
        short.endpoint = "https://host/path".into();
        parse(&encode(&short)).expect_err("an endpoint with a path");
        let wire = generated::ConnectCodeV1 {
            endpoint: "https://host:1".into(),
            cert_pin: vec![1; 31],
            offer_digest: vec![2; 32],
        };
        let text = format!(
            "{CONNECT_CODE_PREFIX}{}",
            encode_base32_crockford(&wire.encode_to_vec())
        );
        parse(&text).expect_err("a 31-byte pin");
    }
}
