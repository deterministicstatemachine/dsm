// SPDX-License-Identifier: MIT OR Apache-2.0
// tests are appended at end to not break module-level inner doc comments
// SPDX-License-Identifier: Apache-2.0
//! DSM API v2: Protobuf-only b0x spool (deterministic, clockless)
//! - Envelope v3 only (strict-fail if != 3)
//! - Deterministic ordering (BIGSERIAL)
//! - Per-key ACK scoping
//! - No genesis_hash persistence in spool
//! - Protobuf-only; no JSON; no wall-clock markers.
//! - Admission: deterministic protobuf, auth, and routing-key gates only

#[cfg(test)]
use crate::replication::{ReplicationConfig, ReplicationManager};
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::Path,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Extension, Router,
};
use prost::Message;

use crate::AppState;
use dsm_sdk::util::text_id;

const MAX_ENVELOPE_BYTES: usize = 128 * 1024; // 128 KiB (normalized)
const MAX_BATCH_RETRIEVE: i64 = 64;

fn valid_spool_key(value: &str) -> bool {
    matches!(
        text_id::decode_base32_crockford(value),
        Some(bytes) if bytes.len() == 32
    )
}


/// The b0x spool: bytes in under a recipient's spool key, bytes out by that
/// key from a position on. No write authorization and no reader authorization
/// (storage spec §4, DSM Amendment A3): the node never checks who writes or
/// reads, and never branches on what an envelope carries. The spool is
/// append-only: nothing is marked read, hidden, expired or removed. Which
/// messages a device has consumed is the device's own state, kept on the
/// device (owner, 2026-09-23).
pub fn router(app: Arc<AppState>) -> Router<()> {
    Router::new()
        .route("/api/v2/b0x/submit", post(submit_b0x_envelope))
        .route(
            "/api/v2/b0x/retrieve/{from_seq}",
            get(retrieve_b0x_batch_from_seq),
        )
        .layer(Extension(app))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            MAX_ENVELOPE_BYTES,
        ))
}

fn require_protobuf(headers: &HeaderMap) -> Result<(), StatusCode> {
    match headers.get(axum::http::header::CONTENT_TYPE) {
        Some(v) if v == "application/octet-stream" => Ok(()),
        Some(v) if v == "application/protobuf" => Ok(()),
        _ => Err(StatusCode::UNSUPPORTED_MEDIA_TYPE),
    }
}

// ------------------- v2 (protobuf-only) -------------------

/// Submit a protobuf Envelope (v3) into the b0x spool under the recipient's inbox.
///
/// **Protocol contract:**
/// - Requires `content-type: application/protobuf` or `application/octet-stream`.
/// - Requires `x-dsm-recipient: <base32>` header specifying the recipient spool key.
///   This may be the canonical device_id or a rotated b0x routing key, but it must
///   always decode from Base32 Crockford to exactly 32 bytes.
/// - Body: prost-encoded Envelope v3 (version field MUST be 3; message_id MUST be 16 bytes).
/// - Returns `204 No Content` on success (idempotent).
///
/// The envelope is stored in the recipient's inbox spool (keyed by x-dsm-recipient).
/// Ordering is deterministic via BIGSERIAL. No wall-clock markers, no genesis_hash persistence.
async fn submit_b0x_envelope(
    Extension(app): Extension<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    log::info!("b0x submit: recv bytes={}", body.len());

    require_protobuf(&headers)?;

    // Extract the recipient spool key from the header. This may be the recipient
    // device_id or a rotated b0x routing key, but either way it must be base32(32).
    let recipient_spool_key = headers
        .get("x-dsm-recipient")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            log::warn!("Missing x-dsm-recipient header");
            StatusCode::BAD_REQUEST
        })?;

    if !valid_spool_key(&recipient_spool_key) {
        log::warn!(
            "Invalid x-dsm-recipient header (must be canonical base32(32)): {}",
            recipient_spool_key
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    let env = dsm::envelope::from_canonical_bytes(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    // NOTE: Storage nodes are dumb mirrors.
    // Do NOT validate SmartPolicy / protocol semantics here (clients verify).

    // Derive message id string (base32 text-id) for idempotency
    let msg_id_b32 = text_id::encode_base32_crockford(&env.message_id);

    // Store in the recipient inbox spool using the explicit routing key.
    let pool = &*app.db_pool;
    crate::db::spool_insert(pool, &recipient_spool_key, &msg_id_b32, &body)
        .await
        .map_err(|e| {
        log::error!(
            "spool_insert failed for recipient {}: {:?}",
            recipient_spool_key,
            e
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    log::info!(
        "📥 b0x envelope stored for recipient {} (msg_id={})",
        &recipient_spool_key[..8.min(recipient_spool_key.len())],
        &msg_id_b32[..16.min(msg_id_b32.len())]
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Retrieve a batch of Envelopes starting from a specific sequence number.
/// Returns SequencedBatchEnvelope (protobuf) with envelopes and their sequence numbers.
/// Supports idempotent retrieval - same envelopes can be retrieved multiple times safely.
async fn retrieve_b0x_batch_from_seq(
    axum::extract::Path(from_seq): axum::extract::Path<i64>,
    Extension(app): Extension<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<axum::response::Response, StatusCode> {
    // §16.4: the spool key names the inbox. There is no authenticated device
    // to fall back to: without the key there is nothing to read.
    let lookup_key = headers
        .get("x-dsm-b0x-address")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .ok_or(StatusCode::BAD_REQUEST)?;
    if !valid_spool_key(lookup_key) {
        log::warn!(
            "Invalid x-dsm-b0x-address header (must be canonical base32(32)): {}",
            lookup_key
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    log::info!(
        "📬 retrieve_b0x_batch_from_seq: GET /api/v2/b0x/retrieve/{} (lookup_key={})",
        from_seq,
        &lookup_key[..16.min(lookup_key.len())]
    );

    let pool = &*app.db_pool;
    let rows =
        crate::db::spool_list_from_seq(pool, lookup_key, from_seq, MAX_BATCH_RETRIEVE)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if rows.is_empty() {
        log::info!(
            "📭 retrieve_b0x_batch_from_seq: no envelopes >= seq {} for {}",
            from_seq,
            &lookup_key[..16.min(lookup_key.len())]
        );
        return Ok(StatusCode::NO_CONTENT.into_response());
    }

    // Build SequencedBatchEnvelope protobuf
    let mut batch = dsm::types::proto::SequencedBatchEnvelope::default();
    let mut next_seq = from_seq;
    for (envelope_bytes, seq_num) in rows {
        match dsm::envelope::from_canonical_bytes(envelope_bytes.as_slice()) {
            Ok(env) => {
                let sequenced = dsm::types::proto::SequencedEnvelope {
                    envelope: Some(env),
                    seq_num: seq_num as u64,
                };
                batch.envelopes.push(sequenced);
                next_seq = next_seq.max(seq_num + 1);
            }
            Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
        }
    }
    batch.next_seq = next_seq as u64;

    let mut bytes = Vec::with_capacity(batch.encoded_len());
    batch
        .encode(&mut bytes)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    log::info!(
        "📬 retrieve_b0x_batch_from_seq: returning {} envelopes (seq {}-{}, next={}) for {}",
        batch.envelopes.len(),
        from_seq,
        next_seq - 1,
        batch.next_seq,
        &lookup_key[..16.min(lookup_key.len())]
    );

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/octet-stream"),
    );
    Ok((StatusCode::OK, headers, bytes).into_response())
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use axum::http::{Request, StatusCode as HttpStatus};
    use prost::Message;
    use tower::ServiceExt; // oneshot

    #[test]
    fn valid_spool_key_accepts_canonical_base32_and_rejects_bracketed_paths() {
        let routed = text_id::encode_base32_crockford(&[0x55u8; 32]);
        assert!(valid_spool_key(&routed));
        assert!(!valid_spool_key("b0x[TEST][TEST][TEST]"));
    }

    async fn maybe_state_and_auth() -> Option<(Arc<AppState>, Arc<AuthState>, Router)> {
        if std::env::var("DSM_RUN_DB_TESTS").ok().as_deref() != Some("1") {
            return None;
        }
        let database_url = std::env::var("DSM_DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://localhost:5432/dsm_storage".to_string());

        let pool = match crate::db::create_pool(&database_url, false) {
            Ok(p) => p,
            Err(_) => return None,
        };
        if crate::db::init_db(&pool).await.is_err() {
            return None;
        }
        let db_pool = Arc::new(pool);

        // Insert device
        let default_dev = [1u8; 32];
        let device_id_str = dsm_sdk::util::text_id::encode_base32_crockford(&default_dev);
        let token = "test-token".to_string();
        let token_hash = blake3::hash(token.as_bytes());
        let token_hash_vec = token_hash.as_bytes().to_vec();
        let pubkey_vec = vec![9u8; 32];
        let genesis_hash = vec![7u8; 32];
        let _ = crate::db::register_device(
            &db_pool,
            &device_id_str,
            &genesis_hash,
            &pubkey_vec,
            &token_hash_vec,
            &vec![0u8; 1184],
            &[0u8; 64],
        )
        .await
        .ok()?;

        let replication_config = ReplicationConfig {
            replication_factor: 3,
            gossip_interval_ticks: 100,
            failure_timeout_ticks: 300,
            gossip_fanout: 3,
            max_concurrent_jobs: 10,
        };
        let replication_manager = Arc::new(
            ReplicationManager::new_for_tests(
                replication_config,
                "test-node".to_string(),
                "http://localhost:8080".to_string(),
            )
            .unwrap_or_else(|e| panic!("Failed to create replication manager: {e}")),
        );
        let app_state = Arc::new(AppState::new(
            "test-node".to_string(),
            "http://localhost:8080",
            None,
            db_pool.clone(),
            replication_manager,
        ));
        let auth_state = Arc::new(AuthState {
            db_pool: db_pool.clone(),
        });
        let app = super::router(app_state.clone(), auth_state.clone());
        Some((app_state, auth_state, app))
    }

    fn make_env(
        device_id: &[u8; 32],
        chain_tip: &[u8; 32],
        msg_id_len: usize,
    ) -> dsm::types::proto::Envelope {
        use dsm::types::proto::Headers;
        dsm::types::proto::Envelope {
            version: 3,
            message_id: vec![7u8; msg_id_len],
            headers: Some(Headers {
                device_id: device_id.to_vec(),
                chain_tip: chain_tip.to_vec(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn v2_b0x_submit_happy() {
        let Some((_app_state, _auth_state, app)) = maybe_state_and_auth().await else {
            return;
        };

        let dev = [1u8; 32];
        let tip = [2u8; 32];
        let env = make_env(&dev, &tip, 16);
        let mut body = Vec::with_capacity(env.encoded_len());
        env.encode(&mut body)
            .unwrap_or_else(|e| panic!("encode envelope failed: {e}"));

        let device_id_str = dsm_sdk::util::text_id::encode_base32_crockford(&dev);
        let token = "test-token";
        let authz = format!("DSM {}:{}", device_id_str, token);
        let msg_id_b32 = text_id::encode_base32_crockford(&[7u8; 16]);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v2/b0x/submit")
            .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
            .header("authorization", authz)
            .header("x-dsm-message-id", msg_id_b32)
            // route into recipient spool (recipient header must be base32 for device ids)
            .header("x-dsm-recipient", text_id::encode_base32_crockford(&dev))
            .body(axum::body::Body::from(body))
            .unwrap_or_else(|e| panic!("request build failed: {e}"));
        let resp = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("oneshot failed: {e}"));
        assert_eq!(resp.status(), HttpStatus::NO_CONTENT);
    }

    #[tokio::test]
    async fn v2_b0x_submit_rejects_bad_msg_id_len() {
        let Some((_app_state, _auth_state, app)) = maybe_state_and_auth().await else {
            return;
        };

        let dev = [1u8; 32];
        let tip = [2u8; 32];
        let env = make_env(&dev, &tip, 15);
        let mut body = Vec::with_capacity(env.encoded_len());
        env.encode(&mut body)
            .unwrap_or_else(|e| panic!("encode envelope failed: {e}"));

        let device_id_str = dsm_sdk::util::text_id::encode_base32_crockford(&dev);
        let token = "test-token";
        let authz = format!("DSM {}:{}", device_id_str, token);
        let msg_id_b32 = text_id::encode_base32_crockford(&[7u8; 16]);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v2/b0x/submit")
            .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
            .header("authorization", authz)
            .header("x-dsm-message-id", msg_id_b32)
            .header("x-dsm-recipient", text_id::encode_base32_crockford(&dev))
            .body(axum::body::Body::from(body))
            .unwrap_or_else(|e| panic!("request build failed: {e}"));
        let resp = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("oneshot failed: {e}"));
        assert_eq!(resp.status(), HttpStatus::BAD_REQUEST);
    }

    #[tokio::test]
    async fn v2_b0x_submit_rejects_wrong_content_type() {
        let Some((_app_state, _auth_state, app)) = maybe_state_and_auth().await else {
            return;
        };

        let dev = [1u8; 32];
        let tip = [2u8; 32];
        let env = make_env(&dev, &tip, 16);
        let mut body = Vec::with_capacity(env.encoded_len());
        env.encode(&mut body)
            .unwrap_or_else(|e| panic!("encode envelope failed: {e}"));

        let device_id_str = dsm_sdk::util::text_id::encode_base32_crockford(&dev);
        let token = "test-token";
        let authz = format!("DSM {}:{}", device_id_str, token);
        let msg_id_b32 = text_id::encode_base32_crockford(&[7u8; 16]);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v2/b0x/submit")
            .header(axum::http::header::CONTENT_TYPE, "text/plain")
            .header("authorization", authz)
            .header("x-dsm-message-id", msg_id_b32)
            .header("x-dsm-recipient", text_id::encode_base32_crockford(&dev))
            .body(axum::body::Body::from(body))
            .unwrap_or_else(|e| panic!("request build failed: {e}"));
        let resp = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("oneshot failed: {e}"));
        assert_eq!(resp.status(), HttpStatus::UNSUPPORTED_MEDIA_TYPE);
    }

}
