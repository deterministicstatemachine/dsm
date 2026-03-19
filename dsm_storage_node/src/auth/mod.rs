//! # Storage Node Authentication Layer
//!
//! Strict, fail-closed, protobuf-only device authentication middleware.
//! Validates `Authorization: DSM <device_id>:<token>` headers and enforces
//! replay protection via `x-dsm-message-id` headers.

// SPDX-License-Identifier: Apache-2.0

use axum::{
    body::{to_bytes, Body, Bytes},
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use dsm_sdk::util::text_id;
use std::sync::Arc;
use subtle::ConstantTimeEq;

use crate::db;

// ---- Public context injected into request extensions ----
#[derive(Clone, Debug)]
pub struct DeviceContext {
    pub device_id: String, // transport id from Authorization header
}

#[derive(Clone)]
pub struct AuthState {
    pub db_pool: Arc<db::DBPool>,
}

// Header names (constants)
const AUTHZ: &str = "authorization";
const MSG_ID: &str = "x-dsm-message-id";
const CT: &str = "content-type";

// Expected Authorization: "DSM <device_id>:<token>"
fn parse_authz(h: &str) -> Option<(String, String)> {
    let trimmed = h.trim();
    if !trimmed.starts_with("DSM ") {
        return None;
    }
    let rest = &trimmed[4..];
    let mut parts = rest.splitn(2, ':');
    let device_id = parts.next()?.to_string();
    let token = parts.next()?.to_string();
    if device_id.is_empty() || token.is_empty() {
        return None;
    }
    Some((device_id, token))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

async fn lookup_device(
    pool: &db::DBPool,
    device_id: &str,
) -> Result<(Vec<u8>, Vec<u8>, bool), StatusCode> {
    // returns (pubkey, token_hash, revoked)
    db::lookup_device_auth(pool, device_id)
        .await
        .map_err(|e| {
            log::warn!("auth: lookup_device_auth DB error for device {device_id}: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::UNAUTHORIZED)
}

async fn check_replay(
    pool: &db::DBPool,
    device_id: &str,
    message_id: &str,
) -> Result<(), StatusCode> {
    // Clockless replay defense: unique(device_id, message_id)
    let inserted = db::insert_inbox_receipt(pool, device_id, message_id)
        .await
        .map_err(|e| {
            log::warn!("auth: insert_inbox_receipt DB error for device {device_id}: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if !inserted {
        return Err(StatusCode::CONFLICT);
    }

    // Bound growth: keep only the most recent receipts per device (deterministic by id).
    const MAX_RECEIPTS_PER_DEVICE: i64 = 2048;
    let _ = db::prune_inbox_receipts(pool, device_id, MAX_RECEIPTS_PER_DEVICE).await;
    Ok(())
}

fn require_protobuf(h: &HeaderMap) -> Result<(), StatusCode> {
    match h.get(CT).and_then(|v| v.to_str().ok()) {
        Some(ct) if ct.eq_ignore_ascii_case("application/protobuf") => Ok(()),
        // Allow octet-stream as a carrier; payload must still be protobuf bytes end-to-end.
        Some(ct) if ct.eq_ignore_ascii_case("application/octet-stream") => Ok(()),
        _ => Err(StatusCode::UNSUPPORTED_MEDIA_TYPE),
    }
}

async fn verify_token(token: &str, token_hash: &[u8]) -> Result<(), StatusCode> {
    // Canonical-only path: token on wire is Base32 text; DB stores BLAKE3(raw_token_bytes).
    let raw_token = text_id::decode_base32_crockford(token).ok_or(StatusCode::UNAUTHORIZED)?;
    let th = blake3::hash(&raw_token);
    if constant_time_eq(th.as_bytes(), token_hash) {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

/// Strict, fail-closed middleware:
/// - Enforces protobuf-only Content-Type (for requests with body)
/// - Auth via `DSM <device_id>:<token>` (BLAKE3(token) vs stored hash)
/// - Clockless replay guard via x-dsm-message-id uniqueness
/// - No base64, no JSON, no alternate decode paths
/// - Reads and re-injects body bytes losslessly
pub async fn device_auth(
    State(state): State<Arc<AuthState>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Content-Type must be protobuf or octet-stream (carrier only) for non-GET requests
    // GET requests (e.g., retrieve) typically have no body, so skip Content-Type check
    if req.method() != axum::http::Method::GET {
        if let Err(e) = require_protobuf(req.headers()) {
            log::warn!(
                "device_auth: rejecting {} {} due to unsupported Content-Type: {:?}",
                req.method(),
                req.uri().path(),
                req.headers().get(CT)
            );
            return Err(e);
        }
    }

    // Authorization header (deterministic parse)
    let authz = req
        .headers()
        .get(AUTHZ)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            log::warn!(
                "device_auth: missing Authorization header on {} {}",
                req.method(),
                req.uri().path()
            );
            StatusCode::UNAUTHORIZED
        })?;
    // Redacted logging: capture the device part (before ':') without the token
    if let Some(rest) = authz.strip_prefix("DSM ") {
        if let Some(dev_part) = rest.split(':').next() {
            let looks_base32 = !dev_part.is_empty()
                && dev_part.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7'));
            log::info!(
                "device_auth: raw_authorization_device_part='{}' looks_base32={}",
                dev_part,
                looks_base32
            );
        }
    }
    let (device_id, token) = parse_authz(authz).ok_or(StatusCode::UNAUTHORIZED)?;
    // Enforce canonical base32(32 bytes) device id in Authorization header to avoid
    // silent routing mismatches (fail-closed).
    if let Some(decoded) = text_id::decode_base32_crockford(&device_id) {
        if decoded.len() != 32 {
            log::warn!(
                "device_auth: Authorization device_id decoded to {} bytes (expected 32): {}",
                decoded.len(),
                device_id
            );
            return Err(StatusCode::UNAUTHORIZED);
        }
    } else {
        log::warn!(
            "device_auth: Authorization device_id is not valid base32: {}",
            device_id
        );
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Device lookup + token verify
    let (_pubkey, token_hash, revoked) = lookup_device(&state.db_pool, &device_id).await?;
    if revoked {
        return Err(StatusCode::FORBIDDEN);
    }
    verify_token(&token, &token_hash).await?;

    // Replay guard: require x-dsm-message-id
    let msg_id = req
        .headers()
        .get(MSG_ID)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            log::warn!(
                "device_auth: missing or invalid x-dsm-message-id header on {} {}",
                req.method(),
                req.uri().path()
            );
            StatusCode::BAD_REQUEST
        })?;
    if std::env::var("DSM_DISABLE_REPLAY_GUARD").is_err()
        && req.uri().path() != "/api/v2/b0x/submit"
    {
        check_replay(&state.db_pool, &device_id, msg_id).await?;
    }

    // Log authenticated device + message id for correlation (info level)
    log::info!(
        "device_auth: authenticated device={} msg_id={}",
        &device_id,
        &msg_id
    );

    // Consume body (bounded) and rebuild request with identical bytes
    let limit: usize = 512 * 1024; // 512 KiB cap (consistent with API caps)
    let (parts, body) = req.into_parts();
    let body_bytes: Bytes = to_bytes(body, limit)
        .await
        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
    let mut req = Request::from_parts(parts, Body::from(body_bytes));

    // Inject DeviceContext for downstream handlers
    let ctx = DeviceContext { device_id };
    req.extensions_mut().insert(ctx);

    Ok(next.run(req).await)
}

#[cfg(test)]
mod auth_format_tests {
    use super::parse_authz;

    fn looks_like_base32(s: &str) -> bool {
        !s.is_empty() && s.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7'))
    }

    #[test]
    fn parse_authz_extracts_device_and_token() {
        let h = "DSM T4IK43LWNESKAM7DEZK6TYUIO6AOVSGSK4KLJSU2B4X4JJMFSGOQ:tok123";
        let (dev, tok) = parse_authz(h).unwrap_or_else(|| panic!("parse_authz failed"));
        assert_eq!(tok, "tok123");
        assert!(looks_like_base32(&dev), "device_id must be base32-like");
    }

    #[test]
    fn dotted_decimal_is_not_base32_like() {
        let dotted = "DSM 1.2.3.4:tok";
        let (dev, _tok) = parse_authz(dotted).unwrap_or_else(|| panic!("parse_authz failed"));
        assert!(!looks_like_base32(&dev));
    }
}
