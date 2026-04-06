// SPDX-License-Identifier: Apache-2.0
//! Per-Device Tip Mirror endpoints (public head, encrypted leaves).
//! Raw protobuf bytes; deterministic keys; clients verify.

use axum::{
    body::Bytes,
    extract::{Extension, Path},
    http::{HeaderValue, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use std::sync::Arc;

use super::hardening::blake3_tagged;
use crate::AppState;

const MAX_HEAD_BYTES: usize = 256; // small TipHeadV2
const MAX_LEAF_BYTES: usize = 2048; // TipLeafCipherV2 ciphertext cap

fn key_head(device_b: &[u8]) -> String {
    let k = blake3_tagged("DSM/identity/tips/head", device_b);
    dsm_sdk::util::text_id::encode_base32_crockford(&k)
}
fn key_leaf(device_b: &[u8], rel_b: &[u8]) -> String {
    let mut buf = Vec::with_capacity(device_b.len() + rel_b.len());
    buf.extend_from_slice(device_b);
    buf.extend_from_slice(rel_b);
    let k = blake3_tagged("DSM/identity/tips/leaf", &buf);
    dsm_sdk::util::text_id::encode_base32_crockford(&k)
}

pub fn create_router(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route("/api/v2/tips/{device}/head", get(get_head).put(put_head))
        .route(
            "/api/v2/tips/{device}/leaf/{rel}",
            get(get_leaf).put(put_leaf),
        )
        .layer(Extension(state))
}

async fn get_head(
    Extension(state): Extension<Arc<AppState>>,
    Path(device): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let device_b =
        dsm_sdk::util::text_id::decode_base32_crockford(&device).ok_or(StatusCode::BAD_REQUEST)?;
    if device_b.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let key = key_head(&device_b);
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

async fn put_head(
    Extension(state): Extension<Arc<AppState>>,
    Path(device): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    if body.is_empty() || body.len() > MAX_HEAD_BYTES {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let device_b =
        dsm_sdk::util::text_id::decode_base32_crockford(&device).ok_or(StatusCode::BAD_REQUEST)?;
    if device_b.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let key = key_head(&device_b);
    let pool = &*state.db_pool;
    crate::db::upsert_object(pool, &key, body.as_ref(), b"tips", body.len() as i64)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::OK)
}

async fn get_leaf(
    Extension(state): Extension<Arc<AppState>>,
    Path((device, rel)): Path<(String, String)>,
) -> Result<impl IntoResponse, StatusCode> {
    let device_b =
        dsm_sdk::util::text_id::decode_base32_crockford(&device).ok_or(StatusCode::BAD_REQUEST)?;
    let rel_b =
        dsm_sdk::util::text_id::decode_base32_crockford(&rel).ok_or(StatusCode::BAD_REQUEST)?;
    if device_b.len() != 32 || rel_b.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let key = key_leaf(&device_b, &rel_b);
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

async fn put_leaf(
    Extension(state): Extension<Arc<AppState>>,
    Path((device, rel)): Path<(String, String)>,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    if body.is_empty() || body.len() > MAX_LEAF_BYTES {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let device_b =
        dsm_sdk::util::text_id::decode_base32_crockford(&device).ok_or(StatusCode::BAD_REQUEST)?;
    let rel_b =
        dsm_sdk::util::text_id::decode_base32_crockford(&rel).ok_or(StatusCode::BAD_REQUEST)?;
    if device_b.len() != 32 || rel_b.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let key = key_leaf(&device_b, &rel_b);
    let pool = &*state.db_pool;
    crate::db::upsert_object(pool, &key, body.as_ref(), b"tips", body.len() as i64)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_head_is_deterministic() {
        let device = [0x01u8; 32];
        let k1 = key_head(&device);
        let k2 = key_head(&device);
        assert_eq!(k1, k2, "same device must produce same head key");
    }

    #[test]
    fn key_head_differs_for_different_devices() {
        let d1 = [0x01u8; 32];
        let d2 = [0x02u8; 32];
        assert_ne!(key_head(&d1), key_head(&d2));
    }

    #[test]
    fn key_leaf_is_deterministic() {
        let device = [0x0Au8; 32];
        let rel = [0x0Bu8; 32];
        let k1 = key_leaf(&device, &rel);
        let k2 = key_leaf(&device, &rel);
        assert_eq!(k1, k2);
    }

    #[test]
    fn key_leaf_differs_for_different_rel() {
        let device = [0x01u8; 32];
        let r1 = [0x0Au8; 32];
        let r2 = [0x0Bu8; 32];
        assert_ne!(key_leaf(&device, &r1), key_leaf(&device, &r2));
    }

    #[test]
    fn key_leaf_is_order_sensitive() {
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        assert_ne!(
            key_leaf(&a, &b),
            key_leaf(&b, &a),
            "swapping device/rel must produce different keys"
        );
    }

    #[test]
    fn key_head_and_key_leaf_use_different_domains() {
        let data = [0xFFu8; 32];
        let head = key_head(&data);
        let leaf = key_leaf(&data, &data);
        assert_ne!(
            head, leaf,
            "head and leaf keys must differ due to domain tags"
        );
    }

    #[test]
    fn size_constants_are_reasonable() {
        assert_eq!(MAX_HEAD_BYTES, 256);
        assert_eq!(MAX_LEAF_BYTES, 2048);
    }

    #[test]
    fn key_outputs_are_nonempty_base32() {
        let device = [0x42u8; 32];
        let head = key_head(&device);
        assert!(!head.is_empty());
        assert!(head.len() > 10);

        let rel = [0x43u8; 32];
        let leaf = key_leaf(&device, &rel);
        assert!(!leaf.is_empty());
        assert!(leaf.len() > 10);
    }
}
