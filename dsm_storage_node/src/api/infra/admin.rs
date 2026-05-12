// SPDX-License-Identifier: Apache-2.0
//! Admin endpoints for storage node operations

use crate::timing::ExponentialBackoffTiming;
use axum::{
    extract::{Extension, RawQuery},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::IntoResponse,
    routing::post,
    Router,
};
use dsm::types::proto as pb;
use log::info;
use prost::Message;
use std::env;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use subtle::ConstantTimeEq;

use crate::db;
use crate::AppState;

const ADMIN_TOKEN_HEADER: &str = "x-dsm-admin-token";
const ADMIN_TOKEN_ENV: &str = "DSM_ADMIN_TOKEN";

fn token_matches(provided: &str, expected: &str) -> bool {
    provided.as_bytes().ct_eq(expected.as_bytes()).into()
}

async fn require_admin_token(headers: HeaderMap) -> Result<(), StatusCode> {
    let expected = env::var(ADMIN_TOKEN_ENV).unwrap_or_default();
    if expected.trim().is_empty() {
        if cfg!(debug_assertions) {
            log::warn!(
                "admin auth disabled: {} not set (debug build)",
                ADMIN_TOKEN_ENV
            );
            return Ok(());
        }
        log::error!(
            "admin auth disabled in release: {} not set",
            ADMIN_TOKEN_ENV
        );
        return Err(StatusCode::UNAUTHORIZED);
    }

    let provided = headers
        .get(ADMIN_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if token_matches(provided, &expected) {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn admin_auth(
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
    require_admin_token(req.headers().clone()).await?;
    Ok(next.run(req).await)
}

#[derive(Debug, PartialEq)]
pub struct CleanupParams {
    /// Delete objects where iter_expires < before_iter
    before_iter: i64,
}

/// Admin endpoint to manually trigger cleanup of expired objects and spool entries.
/// POST /admin/cleanup?before_iter=12345
pub async fn cleanup_expired_handler(
    Extension(state): Extension<Arc<AppState>>,
    RawQuery(raw): RawQuery,
) -> Result<impl IntoResponse, StatusCode> {
    let params = parse_cleanup_query(raw.as_deref())?;
    let timing = ExponentialBackoffTiming::default();
    let (objects_deleted, spool_deleted) =
        db::cleanup_expired_objects_and_spool(&state.db_pool, &timing, params.before_iter)
            .await
            .map_err(|e| {
                log::error!("cleanup_expired failed: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

    info!(
        "cleanup_expired: deleted {} objects and {} spool entries with iter_expires < {}",
        objects_deleted, spool_deleted, params.before_iter
    );

    let resp = pb::AdminCleanupResponseV1 {
        objects_deleted,
        spool_deleted,
        before_iter: params.before_iter,
    };
    let mut buf = Vec::with_capacity(resp.encoded_len());
    resp.encode(&mut buf)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        buf,
    ))
}

/// Admin endpoint to run deterministic maintenance cycle.
/// POST /admin/maintenance?tick=12345
pub async fn maintenance_handler(
    Extension(state): Extension<Arc<AppState>>,
    RawQuery(raw): RawQuery,
) -> Result<impl IntoResponse, StatusCode> {
    let tick = parse_tick_query(raw.as_deref())?;
    state.current_tick.store(tick, Ordering::SeqCst);
    state
        .replication_manager
        .maintenance_cycle(state.clone(), tick)
        .map_err(|e| {
            log::error!("maintenance_cycle failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let resp = pb::AdminMaintenanceResponseV1 { tick, ok: true };
    let mut buf = Vec::with_capacity(resp.encoded_len());
    resp.encode(&mut buf)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        buf,
    ))
}

fn parse_cleanup_query(raw: Option<&str>) -> Result<CleanupParams, StatusCode> {
    let raw = raw.ok_or(StatusCode::BAD_REQUEST)?;
    let mut before_iter = None;
    for pair in raw.split('&') {
        let mut it = pair.splitn(2, '=');
        let key = it.next().unwrap_or("");
        let val = it.next().unwrap_or("");
        let val = decode_percent(val)?;
        if key == "before_iter" {
            before_iter = Some(val.parse::<i64>().map_err(|_| StatusCode::BAD_REQUEST)?);
        }
    }
    let before_iter = before_iter.ok_or(StatusCode::BAD_REQUEST)?;
    Ok(CleanupParams { before_iter })
}

fn parse_tick_query(raw: Option<&str>) -> Result<i64, StatusCode> {
    let raw = raw.ok_or(StatusCode::BAD_REQUEST)?;
    for pair in raw.split('&') {
        let mut it = pair.splitn(2, '=');
        let key = it.next().unwrap_or("");
        let val = it.next().unwrap_or("");
        if key == "tick" {
            let val = decode_percent(val)?;
            return val.parse::<i64>().map_err(|_| StatusCode::BAD_REQUEST);
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

pub fn router(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route("/cleanup", post(cleanup_expired_handler))
        .route("/maintenance", post(maintenance_handler))
        .layer(axum::middleware::from_fn(admin_auth))
        .layer(Extension(state))
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn token_matches_equal() {
        assert!(token_matches("secret123", "secret123"));
    }

    #[test]
    fn token_matches_not_equal() {
        assert!(!token_matches("secret123", "wrong"));
    }

    #[test]
    fn token_matches_empty() {
        assert!(token_matches("", ""));
        assert!(!token_matches("x", ""));
        assert!(!token_matches("", "x"));
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
        assert_eq!(from_hex(b'g'), Err(StatusCode::BAD_REQUEST));
        assert_eq!(from_hex(b'z'), Err(StatusCode::BAD_REQUEST));
        assert_eq!(from_hex(b' '), Err(StatusCode::BAD_REQUEST));
    }

    #[test]
    fn decode_percent_plain() {
        assert_eq!(decode_percent("hello"), Ok("hello".to_string()));
    }

    #[test]
    fn decode_percent_encoded_chars() {
        assert_eq!(
            decode_percent("hello%20world"),
            Ok("hello world".to_string())
        );
        assert_eq!(decode_percent("%41%42%43"), Ok("ABC".to_string()));
    }

    #[test]
    fn decode_percent_plus_is_space() {
        assert_eq!(decode_percent("a+b"), Ok("a b".to_string()));
    }

    #[test]
    fn decode_percent_truncated() {
        assert!(decode_percent("%2").is_err());
        assert!(decode_percent("%").is_err());
    }

    #[test]
    fn decode_percent_invalid_hex() {
        assert!(decode_percent("%GG").is_err());
    }

    #[test]
    fn parse_cleanup_query_valid() {
        match parse_cleanup_query(Some("before_iter=42")) {
            Ok(p) => assert_eq!(p.before_iter, 42),
            Err(err) => panic!("expected valid cleanup query, got {err:?}"),
        }
    }

    #[test]
    fn parse_cleanup_query_with_extra_params() {
        match parse_cleanup_query(Some("foo=bar&before_iter=100&baz=1")) {
            Ok(p) => assert_eq!(p.before_iter, 100),
            Err(err) => panic!("expected valid cleanup query with extras, got {err:?}"),
        }
    }

    #[test]
    fn parse_cleanup_query_missing_param() {
        assert_eq!(
            parse_cleanup_query(Some("foo=bar")),
            Err(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn parse_cleanup_query_none() {
        assert_eq!(parse_cleanup_query(None), Err(StatusCode::BAD_REQUEST));
    }

    #[test]
    fn parse_cleanup_query_non_numeric() {
        assert_eq!(
            parse_cleanup_query(Some("before_iter=abc")),
            Err(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn parse_tick_query_valid() {
        assert_eq!(parse_tick_query(Some("tick=999")), Ok(999));
    }

    #[test]
    fn parse_tick_query_missing() {
        assert_eq!(parse_tick_query(None), Err(StatusCode::BAD_REQUEST));
        assert_eq!(
            parse_tick_query(Some("foo=1")),
            Err(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn parse_tick_query_non_numeric() {
        assert_eq!(
            parse_tick_query(Some("tick=xyz")),
            Err(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn parse_tick_query_negative() {
        assert_eq!(parse_tick_query(Some("tick=-5")), Ok(-5));
    }

    #[test]
    fn parse_cleanup_query_percent_encoded_value() {
        match parse_cleanup_query(Some("before_iter=%33%37")) {
            Ok(p) => assert_eq!(p.before_iter, 37),
            Err(err) => panic!("expected valid percent-encoded cleanup query, got {err:?}"),
        }
    }
}
