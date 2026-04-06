//! Policy persistence endpoints (transport-only, deterministic, binary-only)
//! - POST /api/v2/policy        (body = canonical policy bytes) -> 200 + 32-byte anchor in body
//! - POST /api/v2/policy/get    (body = 32-byte anchor)         -> 200 + canonical bytes, or 404
//! - POST /api/v2/policy/mirror (body = TokenPolicyV3 bytes)     -> 204 (mirrored)
//! - POST /api/v2/policy/anchor (body = PolicyAnchorV3 bytes)    -> 204 (mirrored)
//!
//! Storage model: reuse `objects` with deterministic address:
//! `addr := hex(BLAKE3("DSM/policy\0" || body_bytes))`

use axum::{
    body::Bytes,
    extract::Extension,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use std::sync::Arc;

use super::hardening::blake3_tagged;
use crate::{db, AppState};

/// Internal-only: DB uses TEXT keys; we encode anchor bytes to ASCII for storage (hex).
///
/// This module is intentionally transport-only and may be wired into the main router later.
#[allow(dead_code)]
fn anchor_to_db_key(anchor: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for &b in anchor {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[allow(dead_code)]
pub fn create_router(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route("/api/v2/policy", post(put_policy))
        .route("/api/v2/policy/get", post(get_policy))
        .route("/api/v2/policy/mirror", post(mirror_token_policy))
        .route("/api/v2/policy/anchor", post(mirror_policy_anchor))
        .layer(Extension(state))
}

/// Store canonical policy bytes addressed by BLAKE3 tag.
/// Response body is the 32-byte anchor (binary).
pub async fn put_policy(
    Extension(state): Extension<Arc<AppState>>,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    if body.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Deterministic address: BLAKE3("DSM/policy\0" || body)
    let anchor = blake3_tagged("DSM/policy", body.as_ref());
    let anchor_key = anchor_to_db_key(&anchor);

    // Persist (namespace "policy" for attribution/debug)
    let pool = &*state.db_pool;
    db::upsert_object(
        pool,
        &anchor_key,
        body.as_ref(),
        b"policy",
        body.len() as i64,
    )
    .await
    .map_err(|e| {
        log::warn!("policy: put_policy upsert DB error: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Binary-only response: 32-byte anchor in body.
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(
        axum::http::header::CONTENT_LENGTH,
        HeaderValue::from_static("32"),
    );
    Ok((StatusCode::OK, headers, anchor.to_vec()))
}

/// Fetch canonical policy bytes by anchor (binary).
/// Request body MUST be exactly 32 bytes (anchor).
pub async fn get_policy(
    Extension(state): Extension<Arc<AppState>>,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    if body.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut anchor = [0u8; 32];
    anchor.copy_from_slice(&body);
    let db_key = anchor_to_db_key(&anchor);

    let bytes = db::get_object_by_key(&state.db_pool, &db_key)
        .await
        .map_err(|e| {
            log::warn!("policy: get_policy DB error: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok((StatusCode::OK, headers, bytes))
}

/// Normative mirroring logic for Token Policies (CTPA).
///
/// Mirroring is signature-free; nodes only store bytes under deterministic keys.
///
/// P1 rule (verifier-side): policy digest is recomputed from bytes.
pub async fn mirror_token_policy(
    Extension(state): Extension<Arc<AppState>>,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    if body.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // policy_digest := H("DSM/policy\0" || body_bytes)
    // NOTE: `blake3_tagged` appends "\0" internally.
    let policy_digest = blake3_tagged("DSM/policy", body.as_ref());
    let mirror_path = format!("policy/{}", anchor_to_db_key(&policy_digest));

    db::upsert_object(
        &state.db_pool,
        &mirror_path,
        body.as_ref(),
        b"ctpa_policy",
        body.len() as i64,
    )
    .await
    .map_err(|e| {
        log::warn!("policy: mirror_token_policy upsert DB error: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Mirror a PolicyAnchorV3 to bind a policy to an author's stream.
///
/// Nodes mirror the bytes but do not verify device signatures; verifiers enforce P2.
pub async fn mirror_policy_anchor(
    Extension(state): Extension<Arc<AppState>>,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    if body.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // anchor_digest := H("DSM/policy/anchor\0" || body_bytes)
    let anchor_digest = blake3_tagged("DSM/policy/anchor", body.as_ref());
    let mirror_path = format!("policy/anchor/{}", anchor_to_db_key(&anchor_digest));

    db::upsert_object(
        &state.db_pool,
        &mirror_path,
        body.as_ref(),
        b"ctpa_anchor",
        body.len() as i64,
    )
    .await
    .map_err(|e| {
        log::warn!("policy: mirror_policy_anchor upsert DB error: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_to_db_key_correct_length() {
        let anchor = [0u8; 32];
        let key = anchor_to_db_key(&anchor);
        assert_eq!(key.len(), 64);
    }

    #[test]
    fn anchor_to_db_key_all_zeros() {
        let anchor = [0u8; 32];
        let key = anchor_to_db_key(&anchor);
        assert_eq!(key, "0".repeat(64));
    }

    #[test]
    fn anchor_to_db_key_all_ff() {
        let anchor = [0xFFu8; 32];
        let key = anchor_to_db_key(&anchor);
        assert_eq!(key, "f".repeat(64));
    }

    #[test]
    fn anchor_to_db_key_mixed() {
        let mut anchor = [0u8; 32];
        anchor[0] = 0xAB;
        anchor[1] = 0xCD;
        let key = anchor_to_db_key(&anchor);
        assert!(key.starts_with("abcd"));
        assert_eq!(key.len(), 64);
    }

    #[test]
    fn anchor_to_db_key_lowercase_hex() {
        let anchor = [0xAB; 32];
        let key = anchor_to_db_key(&anchor);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(key.chars().all(|c| !c.is_ascii_uppercase()));
    }

    #[test]
    fn blake3_policy_tag_is_deterministic() {
        let body = b"some policy bytes";
        let d1 = blake3_tagged("DSM/policy", body);
        let d2 = blake3_tagged("DSM/policy", body);
        assert_eq!(d1, d2);
    }

    #[test]
    fn blake3_different_tags_differ() {
        let body = b"same body";
        let d1 = blake3_tagged("DSM/policy", body);
        let d2 = blake3_tagged("DSM/policy/anchor", body);
        assert_ne!(d1, d2);
    }

    #[test]
    fn mirror_path_format() {
        let body = b"token policy bytes";
        let digest = blake3_tagged("DSM/policy", body);
        let path = format!("policy/{}", anchor_to_db_key(&digest));
        assert!(path.starts_with("policy/"));
        assert_eq!(path.len(), "policy/".len() + 64);
    }

    #[test]
    fn anchor_mirror_path_format() {
        let body = b"anchor bytes";
        let digest = blake3_tagged("DSM/policy/anchor", body);
        let path = format!("policy/anchor/{}", anchor_to_db_key(&digest));
        assert!(path.starts_with("policy/anchor/"));
        assert_eq!(path.len(), "policy/anchor/".len() + 64);
    }
}
