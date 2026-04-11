// SPDX-License-Identifier: Apache-2.0
//! Identity mirrors: Device Tree root and inclusion proofs (protobuf-only, raw bytes).
//! Storage node is dumb: deterministic keys, raw bytes; clients verify.

use axum::{
    body::Bytes,
    extract::{Extension, Path, RawQuery},
    http::{HeaderValue, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use std::sync::Arc;

use super::hardening::blake3_tagged;
use crate::AppState;

const MAX_ROOT_BYTES: usize = 256; // small protobuf
const MAX_PROOF_BYTES: usize = 128 * 1024; // 128 KiB cap

fn key_root(genesis_b: &[u8]) -> String {
    let k = blake3_tagged("DSM/identity/devtree/root", genesis_b);
    dsm_sdk::util::text_id::encode_base32_crockford(&k)
}
fn key_proof(genesis_b: &[u8], devid_b: &[u8]) -> String {
    let mut buf = Vec::with_capacity(genesis_b.len() + devid_b.len());
    buf.extend_from_slice(genesis_b);
    buf.extend_from_slice(devid_b);
    let k = blake3_tagged("DSM/identity/devtree/proof", &buf);
    dsm_sdk::util::text_id::encode_base32_crockford(&k)
}

pub fn create_router(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route(
            "/api/v2/identity/{genesis}/devtree/root",
            get(get_root).put(put_root),
        )
        .route(
            "/api/v2/identity/{genesis}/devtree/proof",
            get(get_proof).put(put_proof),
        )
        .layer(Extension(state))
}

async fn get_root(
    Extension(state): Extension<Arc<AppState>>,
    Path(genesis): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let genesis_b =
        dsm_sdk::util::text_id::decode_base32_crockford(&genesis).ok_or(StatusCode::BAD_REQUEST)?;
    let key = key_root(&genesis_b);
    let bytes = crate::db::get_object_by_key(&state.db_pool, &key)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok((StatusCode::OK, headers, bytes))
}

async fn put_root(
    Extension(state): Extension<Arc<AppState>>,
    Path(genesis): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    if body.is_empty() || body.len() > MAX_ROOT_BYTES {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let genesis_b =
        dsm_sdk::util::text_id::decode_base32_crockford(&genesis).ok_or(StatusCode::BAD_REQUEST)?;
    let key = key_root(&genesis_b);
    let pool = &*state.db_pool;
    crate::db::upsert_object(pool, &key, body.as_ref(), b"identity", body.len() as i64)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::OK)
}

async fn get_proof(
    Extension(state): Extension<Arc<AppState>>,
    Path(genesis): Path<String>,
    RawQuery(raw): RawQuery,
) -> Result<impl IntoResponse, StatusCode> {
    let genesis_b =
        dsm_sdk::util::text_id::decode_base32_crockford(&genesis).ok_or(StatusCode::BAD_REQUEST)?;
    let devid_b = parse_devid(raw.as_deref())?;
    if devid_b.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let key = key_proof(&genesis_b, &devid_b);
    let bytes = crate::db::get_object_by_key(&state.db_pool, &key)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok((StatusCode::OK, headers, bytes))
}

async fn put_proof(
    Extension(state): Extension<Arc<AppState>>,
    Path(genesis): Path<String>,
    RawQuery(raw): RawQuery,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    if body.is_empty() || body.len() > MAX_PROOF_BYTES {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let genesis_b =
        dsm_sdk::util::text_id::decode_base32_crockford(&genesis).ok_or(StatusCode::BAD_REQUEST)?;
    let devid_b = parse_devid(raw.as_deref())?;
    if devid_b.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let key = key_proof(&genesis_b, &devid_b);
    let pool = &*state.db_pool;
    crate::db::upsert_object(pool, &key, body.as_ref(), b"identity", body.len() as i64)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::OK)
}

fn parse_devid(raw: Option<&str>) -> Result<Vec<u8>, StatusCode> {
    let raw = raw.ok_or(StatusCode::BAD_REQUEST)?;
    for pair in raw.split('&') {
        let mut it = pair.splitn(2, '=');
        let key = it.next().unwrap_or("");
        let val = it.next().unwrap_or("");
        if key == "devid" {
            let val = decode_percent(val)?;
            return dsm_sdk::util::text_id::decode_base32_crockford(&val)
                .ok_or(StatusCode::BAD_REQUEST);
        }
    }
    Err(StatusCode::BAD_REQUEST)
}

fn decode_percent(input: &str) -> Result<String, StatusCode> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err(StatusCode::BAD_REQUEST);
                }
                let hi = from_hex(bytes[i + 1])?;
                let lo = from_hex(bytes[i + 2])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| StatusCode::BAD_REQUEST)
}

fn from_hex(b: u8) -> Result<u8, StatusCode> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_root_is_deterministic() {
        let genesis = [0xABu8; 32];
        let k1 = key_root(&genesis);
        let k2 = key_root(&genesis);
        assert_eq!(k1, k2, "same genesis must produce same root key");
    }

    #[test]
    fn key_root_differs_for_different_genesis() {
        let g1 = [0x01u8; 32];
        let g2 = [0x02u8; 32];
        assert_ne!(key_root(&g1), key_root(&g2));
    }

    #[test]
    fn key_proof_is_deterministic_and_order_sensitive() {
        let genesis = [0x01u8; 32];
        let devid = [0x02u8; 32];
        let k1 = key_proof(&genesis, &devid);
        let k2 = key_proof(&genesis, &devid);
        assert_eq!(k1, k2);

        // Swapping genesis/devid must produce different key
        let swapped = key_proof(&devid, &genesis);
        assert_ne!(k1, swapped, "key_proof must be order-sensitive");
    }

    #[test]
    fn key_proof_differs_for_different_devid() {
        let genesis = [0x01u8; 32];
        let d1 = [0x0Au8; 32];
        let d2 = [0x0Bu8; 32];
        assert_ne!(key_proof(&genesis, &d1), key_proof(&genesis, &d2));
    }

    #[test]
    fn parse_devid_extracts_value() {
        let b32 = dsm_sdk::util::text_id::encode_base32_crockford(&[0x42u8; 32]);
        let raw = format!("devid={b32}");
        assert_eq!(parse_devid(Some(&raw)), Ok(vec![0x42u8; 32]));
    }

    #[test]
    fn parse_devid_missing_param_is_error() {
        assert!(parse_devid(None).is_err());
        assert!(parse_devid(Some("other=abc")).is_err());
    }

    #[test]
    fn parse_devid_with_multiple_params() {
        let b32 = dsm_sdk::util::text_id::encode_base32_crockford(&[0x33u8; 32]);
        let raw = format!("foo=bar&devid={b32}&baz=qux");
        assert_eq!(parse_devid(Some(&raw)), Ok(vec![0x33u8; 32]));
    }

    #[test]
    fn decode_percent_passthrough() {
        assert_eq!(decode_percent("hello"), Ok("hello".to_string()));
    }

    #[test]
    fn decode_percent_hex_sequences() {
        assert_eq!(decode_percent("a%20b"), Ok("a b".to_string()));
        assert_eq!(decode_percent("%41%42%43"), Ok("ABC".to_string()));
    }

    #[test]
    fn decode_percent_plus_becomes_space() {
        assert_eq!(decode_percent("a+b"), Ok("a b".to_string()));
    }

    #[test]
    fn decode_percent_truncated_hex_is_error() {
        assert!(decode_percent("%2").is_err());
        assert!(decode_percent("%").is_err());
    }

    #[test]
    fn from_hex_digits() {
        assert_eq!(from_hex(b'0'), Ok(0));
        assert_eq!(from_hex(b'9'), Ok(9));
        assert_eq!(from_hex(b'a'), Ok(10));
        assert_eq!(from_hex(b'f'), Ok(15));
        assert_eq!(from_hex(b'A'), Ok(10));
        assert_eq!(from_hex(b'F'), Ok(15));
    }

    #[test]
    fn from_hex_invalid() {
        assert!(from_hex(b'g').is_err());
        assert!(from_hex(b'G').is_err());
        assert!(from_hex(b' ').is_err());
    }

    #[test]
    fn size_constants_are_reasonable() {
        assert_eq!(MAX_ROOT_BYTES, 256);
        assert_eq!(MAX_PROOF_BYTES, 128 * 1024);
    }
}
