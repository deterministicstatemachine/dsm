//! # Registry Evidence API
//!
//! Deterministic, clockless evidence submission gate. Accepts raw protobuf
//! bytes with `Content-Type: application/octet-stream` and returns the
//! domain-separated BLAKE3 object address in the `x-object-address` header.

// SPDX-License-Identifier: Apache-2.0

use axum::{
    body::Bytes,
    extract::{Extension, Path},
    http::{header::CONTENT_TYPE, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use std::sync::Arc;

use dsm_sdk::util::text_id;

/// Public headers used by callers/tests
#[allow(dead_code)]
pub const HDR_DLV_ID: &str = "x-dsm-dlv-id";
#[allow(dead_code)]
pub const HDR_KIND: &str = "x-dsm-kind";
#[allow(dead_code)]
pub const HDR_PATH: &str = "x-dsm-path";
#[allow(dead_code)]
pub const HDR_CAPACITY: &str = "x-dsm-capacity";
#[allow(dead_code)]
pub const HDR_STAKE_HASH: &str = "x-dsm-stake";
pub const HDR_ADDR: &str = "x-object-address";

pub fn create_router(state: Arc<crate::AppState>) -> Router<()> {
    Router::new()
        .route("/api/v2/registry/publish", post(publish_evidence))
        .route("/api/v2/registry/list/{kind}", get(list_by_kind))
        .route("/api/v2/registry/get/{addr}", get(get_object_by_addr))
        .layer(Extension(state))
}

#[inline]
fn parse_optional_dlv_id(headers: &HeaderMap) -> Vec<u8> {
    // Canon: Base32 Crockford only.
    let Some(raw) = headers.get("X-DSM-DLV-ID").and_then(|v| v.to_str().ok()) else {
        return Vec::new();
    };

    let s = raw.trim();
    if s.is_empty() {
        return Vec::new();
    }

    text_id::decode_base32_crockford(s).unwrap_or_default()
}

#[inline]
fn registry_metadata_plain(rows: &[(String, i16, i64)]) -> Bytes {
    // Text/plain, deterministic output; avoids JSON at trust boundary.
    // Format: one row per line: "{addr}\t{kind_code}\t{size_bytes}\n"
    let mut out = String::new();
    for (addr, kind, size) in rows {
        out.push_str(addr);
        out.push('\t');
        out.push_str(&kind.to_string());
        out.push('\t');
        out.push_str(&size.to_string());
        out.push('\n');
    }
    Bytes::from(out)
}

#[inline]
fn content_addr_b64url(body: &Bytes) -> String {
    // Domain-separated BLAKE3 for registry evidence (opaque bytes)
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"DSM/registry\0");
    hasher.update(body);
    let out = hasher.finalize();
    b64_url_no_pad(out.as_bytes())
}

/// POST /api/v2/registry/publish — strict gate per tests
pub async fn publish_evidence(
    Extension(state): Extension<Arc<crate::AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    // Strict Content-Type gate
    match headers.get(CONTENT_TYPE).and_then(|v| v.to_str().ok()) {
        Some(ct) if ct.eq_ignore_ascii_case("application/octet-stream") => {}
        _ => return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE),
    }
    if body.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let addr = content_addr_b64url(&body);

    // Persist to registry_evidence table. Accept optional headers:
    // - X-DSM-KIND: integer kind code
    // - X-DSM-DLV-ID: hex-encoded DLV id
    let kind_code: i16 = headers
        .get("X-DSM-KIND")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<i16>().ok())
        .unwrap_or(0);

    let mut dlv_id: Vec<u8> = parse_optional_dlv_id(&headers);
    if !dlv_id.is_empty() && dlv_id.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    if dlv_id.is_empty() {
        dlv_id = vec![0u8; 32];
    }

    let pool = &state.db_pool;

    log::info!(
        "registry.publish: storing evidence at addr={} kind_code={} size={}",
        &addr,
        kind_code,
        body.len()
    );

    if let Err(e) =
        crate::db::upsert_object(pool, &addr, body.as_ref(), &dlv_id, body.len() as i64).await
    {
        log::error!("registry.publish: object persist failed: {:?}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    if let Err(e) =
        crate::db::store_registry_evidence(pool, &addr, kind_code, &dlv_id, body.len() as i64).await
    {
        log::error!("registry.publish: DB persist failed: {:?}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    log::info!(
        "registry.publish: successfully stored evidence at addr={}",
        &addr
    );

    let mut out_headers = HeaderMap::new();
    let _ = out_headers.insert(
        HDR_ADDR,
        HeaderValue::from_str(&addr).unwrap_or_else(|_| HeaderValue::from_static("")),
    );

    Ok((StatusCode::OK, out_headers))
}

/// GET /api/v2/registry/list/{kind}
///
/// Returns deterministic metadata rows (text/plain) for a specific kind code.
pub async fn list_by_kind(
    Extension(_state): Extension<Arc<crate::AppState>>,
    Path(kind): Path<i16>,
) -> Result<impl IntoResponse, StatusCode> {
    let rows = crate::db::list_registry_evidence_by_kind(&_state.db_pool, kind)
        .await
        .map_err(|e| {
            log::error!("registry.list: DB query failed: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let mut out_headers = HeaderMap::new();
    let _ = out_headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    Ok((StatusCode::OK, out_headers, registry_metadata_plain(&rows)))
}

/// GET /api/v2/registry/get/{addr}
///
/// Returns the raw evidence bytes by deterministic address.
pub async fn get_object_by_addr(
    Extension(_state): Extension<Arc<crate::AppState>>,
    Path(addr): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    log::info!("registry.get: retrieving evidence at addr={}", &addr);

    let bytes_opt = crate::db::get_registry_object_by_addr(&_state.db_pool, &addr)
        .await
        .map_err(|e| {
            log::error!("registry.get: DB query failed: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let Some(bytes) = bytes_opt else {
        log::warn!("registry.get: no evidence found at addr={}", &addr);
        return Err(StatusCode::NOT_FOUND);
    };

    log::info!(
        "registry.get: found evidence at addr={} size={}",
        &addr,
        bytes.len()
    );

    let mut out_headers = HeaderMap::new();
    let _ = out_headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok((StatusCode::OK, out_headers, Bytes::from(bytes)))
}

/// Minimal base64url encoder (no padding) to avoid pulling deps.
/// Uses the URL-safe alphabet and omits '=' characters.
#[inline]
fn b64_url_no_pad(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let n = input.len();
    let mut out = String::with_capacity(n.div_ceil(3) * 4);

    let mut i = 0;
    while i + 3 <= n {
        let a = input[i];
        let b = input[i + 1];
        let c = input[i + 2];

        out.push(T[(a >> 2) as usize] as char);
        out.push(T[(((a & 0x03) << 4) | (b >> 4)) as usize] as char);
        out.push(T[(((b & 0x0f) << 2) | (c >> 6)) as usize] as char);
        out.push(T[(c & 0x3f) as usize] as char);

        i += 3;
    }

    match n - i {
        1 => {
            let a = input[i];
            out.push(T[(a >> 2) as usize] as char);
            out.push(T[((a & 0x03) << 4) as usize] as char);
            // (no padding) — normally we'd add "=="
        }
        2 => {
            let a = input[i];
            let b = input[i + 1];
            out.push(T[(a >> 2) as usize] as char);
            out.push(T[(((a & 0x03) << 4) | (b >> 4)) as usize] as char);
            out.push(T[((b & 0x0f) << 2) as usize] as char);
            // (no padding) — normally we'd add "="
        }
        _ => {}
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn b64_url_no_pad_empty_input() {
        assert_eq!(b64_url_no_pad(&[]), "");
    }

    #[test]
    fn b64_url_no_pad_one_byte() {
        let result = b64_url_no_pad(&[0xFF]);
        assert_eq!(result.len(), 2);
        // 0xFF = 11111111 -> sextets: 111111 (63='_'), 110000 (48='w')
        assert_eq!(result, "_w");
    }

    #[test]
    fn b64_url_no_pad_two_bytes() {
        let result = b64_url_no_pad(&[0x00, 0x00]);
        assert_eq!(result.len(), 3);
        assert_eq!(result, "AAA");
    }

    #[test]
    fn b64_url_no_pad_three_bytes() {
        let result = b64_url_no_pad(&[0x00, 0x00, 0x00]);
        assert_eq!(result.len(), 4);
        assert_eq!(result, "AAAA");
    }

    #[test]
    fn b64_url_no_pad_uses_url_safe_alphabet() {
        // Byte values that would produce '+' and '/' in standard base64
        // should instead produce '-' and '_'
        let result = b64_url_no_pad(&[0xFB, 0xFF, 0xFE]);
        assert!(!result.contains('+'));
        assert!(!result.contains('/'));
        assert!(!result.contains('='));
    }

    #[test]
    fn b64_url_no_pad_known_vector() {
        // "Hello" in standard base64 = "SGVsbG8=", url-safe no-pad = "SGVsbG8"
        let result = b64_url_no_pad(b"Hello");
        assert_eq!(result, "SGVsbG8");
    }

    #[test]
    fn content_addr_b64url_deterministic() {
        let body = Bytes::from_static(b"test-evidence-data");
        let addr1 = content_addr_b64url(&body);
        let addr2 = content_addr_b64url(&body);
        assert_eq!(addr1, addr2);
        assert!(!addr1.is_empty());
    }

    #[test]
    fn content_addr_b64url_different_bodies_differ() {
        let addr1 = content_addr_b64url(&Bytes::from_static(b"payload-a"));
        let addr2 = content_addr_b64url(&Bytes::from_static(b"payload-b"));
        assert_ne!(addr1, addr2);
    }

    #[test]
    fn content_addr_b64url_domain_separation() {
        // The hash is domain-separated with "DSM/registry\0", so even identical raw
        // bytes hashed without the domain tag would produce a different result.
        let body = Bytes::from_static(b"data");
        let addr = content_addr_b64url(&body);
        let raw = blake3::hash(b"data");
        let raw_b64 = b64_url_no_pad(raw.as_bytes());
        assert_ne!(addr, raw_b64);
    }

    #[test]
    fn registry_metadata_plain_formats_rows() {
        let rows = vec![
            ("abc123".to_string(), 1i16, 256i64),
            ("def456".to_string(), 2i16, 1024i64),
        ];
        let out = registry_metadata_plain(&rows);
        let text = std::str::from_utf8(&out).unwrap();
        assert_eq!(text, "abc123\t1\t256\ndef456\t2\t1024\n");
    }

    #[test]
    fn registry_metadata_plain_empty_rows() {
        let rows: Vec<(String, i16, i64)> = vec![];
        let out = registry_metadata_plain(&rows);
        assert!(out.is_empty());
    }

    #[test]
    fn parse_optional_dlv_id_missing_header() {
        let headers = HeaderMap::new();
        assert!(parse_optional_dlv_id(&headers).is_empty());
    }

    #[test]
    fn parse_optional_dlv_id_empty_value() {
        let mut headers = HeaderMap::new();
        headers.insert("X-DSM-DLV-ID", HeaderValue::from_static(""));
        assert!(parse_optional_dlv_id(&headers).is_empty());
    }

    #[test]
    fn parse_optional_dlv_id_whitespace_only() {
        let mut headers = HeaderMap::new();
        headers.insert("X-DSM-DLV-ID", HeaderValue::from_static("   "));
        assert!(parse_optional_dlv_id(&headers).is_empty());
    }
}
