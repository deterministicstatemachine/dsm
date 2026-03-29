// tests are appended at end to not break module-level inner doc comments
// SPDX-License-Identifier: Apache-2.0
//! DSM API v2: Protobuf-only b0x spool (deterministic, clockless)
//! - Envelope v3 only (strict-fail if != 3)
//! - Deterministic ordering (BIGSERIAL)
//! - Per-key ACK scoping
//! - No genesis_hash persistence in spool
//! - Protobuf-only; no JSON; no wall-clock markers.
//! - Rate limiting: 100 requests per minute per device/IP

#[cfg(test)]
use crate::replication::{ReplicationConfig, ReplicationManager};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Extension, Router,
};
use prost::Message;

use crate::{
    auth::{device_auth, AuthState, DeviceContext},
    AppState,
};
use dsm_sdk::util::text_id;

const MAX_ENVELOPE_BYTES: usize = 128 * 1024; // 128 KiB (normalized)
const MAX_BATCH_RETRIEVE: i64 = 64;

// Rate limiting: 100 requests per minute per key
const RATE_LIMIT_REQUESTS: u32 = 100;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
struct RateLimitEntry {
    tokens: u32,
    last_refill: Instant,
}

impl RateLimitEntry {
    fn new() -> Self {
        Self {
            tokens: RATE_LIMIT_REQUESTS,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let windows_elapsed = elapsed.as_secs() / RATE_LIMIT_WINDOW.as_secs();

        if windows_elapsed > 0 {
            self.tokens = RATE_LIMIT_REQUESTS;
            self.last_refill = now;
        }
    }

    fn consume(&mut self) -> bool {
        self.refill();
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

type RateLimitMap = HashMap<String, RateLimitEntry>;

#[derive(Clone)]
struct RateLimiter {
    limits: Arc<RwLock<RateLimitMap>>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            limits: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn should_prune(entry: &RateLimitEntry, now: Instant) -> bool {
        let elapsed = now.duration_since(entry.last_refill);
        elapsed > RATE_LIMIT_WINDOW.saturating_mul(10)
    }

    async fn check_rate_limit(&self, key: &str) -> Result<(), StatusCode> {
        let mut limits = self.limits.write().await;
        let now = Instant::now();
        limits.retain(|_, entry| !Self::should_prune(entry, now));
        let entry = limits
            .entry(key.to_string())
            .or_insert_with(RateLimitEntry::new);

        if entry.consume() {
            Ok(())
        } else {
            Err(StatusCode::TOO_MANY_REQUESTS)
        }
    }
}

fn valid_spool_key(value: &str) -> bool {
    matches!(
        text_id::decode_base32_crockford(value),
        Some(bytes) if bytes.len() == 32
    )
}

pub fn router(app: Arc<AppState>, auth: Arc<AuthState>) -> Router<()> {
    let rate_limiter = Arc::new(RateLimiter::new());

    Router::new()
        .route("/api/v2/b0x/submit", post(submit_b0x_envelope))
        .route("/api/v2/b0x/retrieve", get(retrieve_b0x_batch))
        .route(
            "/api/v2/b0x/retrieve/{from_seq}",
            get(retrieve_b0x_batch_from_seq),
        )
        .route("/api/v2/b0x/ack", post(ack_b0x_batch))
        .route(
            "/api/v2/b0x/status/{message_id}",
            get(get_b0x_message_status),
        )
        .layer(axum::middleware::from_fn_with_state(
            auth.clone(),
            device_auth,
        ))
        .layer(Extension(app))
        .layer(Extension(auth))
        .layer(Extension(rate_limiter))
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
/// - Requires `authorization: DSM <device_id>:<token>` (enforced by device_auth middleware).
/// - Requires `x-dsm-message-id: <base32>` for replay protection (validated by middleware).
/// - Requires `x-dsm-recipient: <base32>` header specifying the recipient spool key.
///   This may be the canonical device_id or a rotated b0x routing key, but it must
///   always decode from Base32 Crockford to exactly 32 bytes.
/// - Body: prost-encoded Envelope v3 (version field MUST be 3; message_id MUST be 16 bytes).
/// - Returns `204 No Content` on success (idempotent).
///
/// The envelope is stored in the recipient's inbox spool (keyed by x-dsm-recipient).
/// Ordering is deterministic via BIGSERIAL. No wall-clock markers, no genesis_hash persistence.
async fn submit_b0x_envelope(
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Extension(app): Extension<Arc<AppState>>,
    Extension(_auth): Extension<Arc<AuthState>>,
    Extension(_ctx): Extension<DeviceContext>,
    Extension(rate_limiter): Extension<Arc<RateLimiter>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    log::info!("b0x submit: recv from={} bytes={}", addr.ip(), body.len());
    // Rate limiting: combine device_id and IP for key
    let rate_limit_key = format!("{}_{}", _ctx.device_id, addr.ip());
    rate_limiter.check_rate_limit(&rate_limit_key).await?;

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

    // Decode Envelope v3 strictly.
    let env = dsm::types::proto::Envelope::decode(&*body).map_err(|_| StatusCode::BAD_REQUEST)?;
    if env.version != 3 {
        return Err(StatusCode::BAD_REQUEST);
    }
    if env.message_id.len() != 16 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // NOTE: Storage nodes are dumb mirrors.
    // Do NOT validate SmartPolicy / protocol semantics here (clients verify).

    // Derive message id string (base32 text-id) for idempotency
    let msg_id_b32 = text_id::encode_base32_crockford(&env.message_id);

    // Check for optional expiration header (x-dsm-expires-at-iter)
    // Format: decimal-encoded iteration number (clockless expiration)
    let expires_at_iter = headers
        .get("x-dsm-expires-at-iter")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<i64>().ok());

    // Store in the recipient inbox spool using the explicit routing key.
    let pool = &*app.db_pool;
    if let Some(expires_at) = expires_at_iter {
        crate::db::spool_insert_with_expiration(
            pool,
            &recipient_spool_key,
            &msg_id_b32,
            &body,
            Some(expires_at),
        )
        .await
    } else {
        crate::db::spool_insert(pool, &recipient_spool_key, &msg_id_b32, &body).await
    }
    .map_err(|e| {
        log::error!(
            "spool_insert failed for recipient {}: {:?}",
            recipient_spool_key,
            e
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    log::info!(
        "📥 b0x envelope stored for recipient {} (msg_id={}, expires={:?})",
        &recipient_spool_key[..8.min(recipient_spool_key.len())],
        &msg_id_b32[..16.min(msg_id_b32.len())],
        expires_at_iter
    );

    // Replicate b0x envelope to peer nodes so the receiver can poll any node.
    {
        let rm = app.replication_manager.clone();
        let app_clone = app.clone();
        let repl_key = format!("b0x/{recipient_spool_key}/{msg_id_b32}");
        let repl_data = body.to_vec();
        tokio::spawn(async move {
            if let Err(e) = rm
                .replicate_object(app_clone, &repl_key, &repl_data, 0)
                .await
            {
                log::warn!(
                    "b0x replication failed for {}: {e}",
                    &repl_key[..repl_key.len().min(32)]
                );
            }
        });
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Retrieve a batch of Envelopes for the given b0x key, encoded as BatchEnvelope bytes.
/// Returns BatchEnvelope (protobuf), up to MAX_BATCH_RETRIEVE items in deterministic order.
/// Compatibility endpoint for older clients - does not return sequence numbers.
async fn retrieve_b0x_batch(
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Extension(app): Extension<Arc<AppState>>,
    Extension(_auth): Extension<Arc<AuthState>>,
    Extension(_ctx): Extension<DeviceContext>,
    Extension(rate_limiter): Extension<Arc<RateLimiter>>,
    headers: HeaderMap,
) -> Result<axum::response::Response, StatusCode> {
    // Rate limiting: combine device_id and IP for key
    let rate_limit_key = format!("{}_{}", _ctx.device_id, addr.ip());
    rate_limiter.check_rate_limit(&rate_limit_key).await?;

    // Fetch unacked envelopes for this device
    let device_id = _ctx.device_id.clone();

    // §16.4: If x-dsm-b0x-address header is present, use it as the inbox lookup key
    // instead of the auth device_id. This enables tip-scoped address rotation where
    // the sender submits to a rotated address and the recipient retrieves from it.
    let lookup_key = if let Some(key) = headers
        .get("x-dsm-b0x-address")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
    {
        if !valid_spool_key(key) {
            log::warn!(
                "Invalid x-dsm-b0x-address header (must be canonical base32(32)): {}",
                key
            );
            return Err(StatusCode::BAD_REQUEST);
        }
        key.to_string()
    } else {
        device_id.clone()
    };

    // Log full device_id to help correlate retrieves with stored recipients
    log::info!(
        "📬 retrieve_b0x_batch: incoming GET /api/v2/b0x/retrieve (device={}, lookup_key={})",
        &device_id,
        &lookup_key[..16.min(lookup_key.len())]
    );
    let include_acked = headers
        .get("x-dsm-include-acked")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let pool = &*app.db_pool;
    let rows = crate::db::spool_list(pool, &lookup_key, include_acked, MAX_BATCH_RETRIEVE)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if rows.is_empty() {
        log::info!(
            "📭 retrieve_from_b0x_v2: inbox empty for device {}",
            &device_id
        );
        return Ok(StatusCode::NO_CONTENT.into_response());
    }

    // Build BatchEnvelope protobuf
    let mut batch = dsm::types::proto::BatchEnvelope::default();
    for item in rows {
        match dsm::types::proto::Envelope::decode(item.as_slice()) {
            Ok(env) => batch.envelopes.push(env),
            Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
        }
    }
    let mut bytes = Vec::with_capacity(batch.encoded_len());
    batch
        .encode(&mut bytes)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    log::info!(
        "📬 retrieve_from_b0x_v2: returning {} envelopes for device {}",
        batch.envelopes.len(),
        &device_id
    );

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/octet-stream"),
    );
    Ok((StatusCode::OK, headers, bytes).into_response())
}

/// Retrieve a batch of Envelopes starting from a specific sequence number.
/// Returns SequencedBatchEnvelope (protobuf) with envelopes and their sequence numbers.
/// Supports idempotent retrieval - same envelopes can be retrieved multiple times safely.
async fn retrieve_b0x_batch_from_seq(
    axum::extract::Path(from_seq): axum::extract::Path<i64>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Extension(app): Extension<Arc<AppState>>,
    Extension(_auth): Extension<Arc<AuthState>>,
    Extension(_ctx): Extension<DeviceContext>,
    Extension(rate_limiter): Extension<Arc<RateLimiter>>,
    headers: HeaderMap,
) -> Result<axum::response::Response, StatusCode> {
    // Rate limiting: combine device_id and IP for key
    let rate_limit_key = format!("{}_{}", _ctx.device_id, addr.ip());
    rate_limiter.check_rate_limit(&rate_limit_key).await?;

    let device_id = _ctx.device_id.clone();

    // §16.4: If x-dsm-b0x-address header is present, use it as the inbox lookup key.
    let lookup_key = if let Some(key) = headers
        .get("x-dsm-b0x-address")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
    {
        if !valid_spool_key(key) {
            log::warn!(
                "Invalid x-dsm-b0x-address header (must be canonical base32(32)): {}",
                key
            );
            return Err(StatusCode::BAD_REQUEST);
        }
        key.to_string()
    } else {
        device_id.clone()
    };

    log::info!(
        "📬 retrieve_b0x_batch_from_seq: incoming GET /api/v2/b0x/retrieve/{} (device={}, lookup_key={})",
        from_seq,
        &device_id,
        &lookup_key[..16.min(lookup_key.len())]
    );

    let pool = &*app.db_pool;
    let rows =
        crate::db::spool_list_unacked_from_seq(pool, &lookup_key, from_seq, MAX_BATCH_RETRIEVE)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if rows.is_empty() {
        log::info!(
            "📭 retrieve_b0x_batch_from_seq: no envelopes >= seq {} for device {}",
            from_seq,
            &device_id
        );
        return Ok(StatusCode::NO_CONTENT.into_response());
    }

    // Build SequencedBatchEnvelope protobuf
    let mut batch = dsm::types::proto::SequencedBatchEnvelope::default();
    let mut next_seq = from_seq;
    for (envelope_bytes, seq_num) in rows {
        match dsm::types::proto::Envelope::decode(envelope_bytes.as_slice()) {
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
        "📬 retrieve_b0x_batch_from_seq: returning {} envelopes (seq {}-{}, next={}) for device {}",
        batch.envelopes.len(),
        from_seq,
        next_seq - 1,
        batch.next_seq,
        &device_id
    );

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/octet-stream"),
    );
    Ok((StatusCode::OK, headers, bytes).into_response())
}

/// Acknowledge a batch by message_id, scoped to the provided b0x key.
/// Body: BatchEnvelope (protobuf) with envelopes carrying their message_id.
///
/// Scoping rule (per-key ACK):
/// - If header `x-dsm-b0x-address` is present, it MUST be a canonical base32(32) spool key.
///   The ACK is applied to that explicit inbox key, independent of the Authorization device id.
/// - Otherwise, `x-dsm-recipient` may be used with the same base32(32) rule.
/// - Otherwise, the ACK is scoped to the Authorization device id extracted by the auth middleware.
///
/// This enables deterministic per-key acknowledgements while keeping authentication and replay
/// proofs enforced by the middleware.
async fn ack_b0x_batch(
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Extension(app): Extension<Arc<AppState>>,
    Extension(_auth): Extension<Arc<AuthState>>,
    Extension(_ctx): Extension<DeviceContext>,
    Extension(rate_limiter): Extension<Arc<RateLimiter>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    // Rate limiting: combine device_id and IP for key
    let rate_limit_key = format!("{}_{}", _ctx.device_id, addr.ip());
    rate_limiter.check_rate_limit(&rate_limit_key).await?;

    require_protobuf(&headers)?;
    let batch =
        dsm::types::proto::BatchEnvelope::decode(&*body).map_err(|_| StatusCode::BAD_REQUEST)?;
    // Determine ACK scope: prefer the explicit rotated routing key, else an explicit
    // recipient spool key, else the authenticated device id.
    let device_id = if let Some(spool_key) = headers
        .get("x-dsm-b0x-address")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
    {
        if !valid_spool_key(spool_key) {
            log::warn!(
                "Invalid x-dsm-b0x-address header (must be canonical base32(32)): {}",
                spool_key
            );
            return Err(StatusCode::BAD_REQUEST);
        }
        spool_key.to_string()
    } else if let Some(recipient_b32) = headers.get("x-dsm-recipient").and_then(|v| v.to_str().ok())
    {
        if !valid_spool_key(recipient_b32) {
            log::warn!(
                "Invalid x-dsm-recipient header (must be canonical base32(32)): {}",
                recipient_b32
            );
            return Err(StatusCode::BAD_REQUEST);
        }
        recipient_b32.to_string()
    } else {
        _ctx.device_id.clone()
    };
    let msg_ids: Vec<String> = batch
        .envelopes
        .iter()
        .map(|e| text_id::encode_base32_crockford(&e.message_id))
        .collect();
    let pool = &*app.db_pool;
    let _updated = crate::db::spool_ack(pool, &device_id, &msg_ids)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_b0x_message_status(
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Extension(app): Extension<Arc<AppState>>,
    Extension(_auth): Extension<Arc<AuthState>>,
    Extension(_ctx): Extension<DeviceContext>,
    Extension(rate_limiter): Extension<Arc<RateLimiter>>,
    Path(message_id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let rate_limit_key = format!("{}_{}", _ctx.device_id, addr.ip());
    rate_limiter.check_rate_limit(&rate_limit_key).await?;

    let msg_id_bytes = text_id::decode_base32_crockford(&message_id)
        .filter(|bytes| bytes.len() == 16)
        .ok_or(StatusCode::BAD_REQUEST)?;

    let sender_bytes = text_id::decode_base32_crockford(&_ctx.device_id)
        .filter(|bytes| bytes.len() == 32)
        .ok_or(StatusCode::FORBIDDEN)?;

    let pool = &*app.db_pool;
    let Some((envelope_bytes, acked)) = crate::db::spool_lookup_by_message_id(pool, &message_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    else {
        return Err(StatusCode::NOT_FOUND);
    };

    let env = dsm::types::proto::Envelope::decode(envelope_bytes.as_slice())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if env.message_id != msg_id_bytes {
        return Err(StatusCode::NOT_FOUND);
    }

    let envelope_sender = env
        .headers
        .as_ref()
        .map(|headers| headers.device_id.clone())
        .filter(|device_id| device_id.len() == 32)
        .ok_or(StatusCode::NOT_FOUND)?;

    if envelope_sender != sender_bytes {
        return Err(StatusCode::NOT_FOUND);
    }

    if acked {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Ok(StatusCode::CONFLICT)
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use axum::http::{Request, StatusCode as HttpStatus};
    use prost::Message;
    use tower::ServiceExt; // oneshot

    #[test]
    fn valid_spool_key_accepts_canonical_base32_and_rejects_legacy_brackets() {
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

    #[tokio::test]
    async fn v2_b0x_ack_and_retrieve_basic() {
        let Some((_app_state, _auth_state, app)) = maybe_state_and_auth().await else {
            return;
        };

        let dev = [1u8; 32];
        let device_id_str = dsm_sdk::util::text_id::encode_base32_crockford(&dev);
        let token = "test-token";
        let authz = format!("DSM {}:{}", device_id_str, token);
        let msg_id_b32_r = dsm_sdk::util::text_id::encode_base32_crockford(&[8u8; 16]);
        let msg_id_b32_a = dsm_sdk::util::text_id::encode_base32_crockford(&[9u8; 16]);

        // retrieve (expecting 204 No Content for empty inbox)
        let req_r = Request::builder()
            .method("GET")
            .uri("/api/v2/b0x/retrieve")
            .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
            .header("authorization", authz.clone())
            .header("x-dsm-message-id", msg_id_b32_r)
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("request build failed: {e}"));
        let resp_r = app
            .clone()
            .oneshot(req_r)
            .await
            .unwrap_or_else(|e| panic!("oneshot failed: {e}"));
        assert_eq!(resp_r.status(), HttpStatus::NO_CONTENT);

        // ack (expecting 204 No Content for empty/idempotent ack)
        let req_a = Request::builder()
            .method("POST")
            .uri("/api/v2/b0x/ack")
            .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
            .header("authorization", authz)
            .header("x-dsm-message-id", msg_id_b32_a)
            .body(axum::body::Body::from(Vec::<u8>::new()))
            .unwrap_or_else(|e| panic!("request build failed: {e}"));
        let resp_a = app
            .clone()
            .oneshot(req_a)
            .await
            .unwrap_or_else(|e| panic!("oneshot failed: {e}"));
        assert_eq!(resp_a.status(), HttpStatus::NO_CONTENT);
    }

    #[tokio::test]
    async fn v2_b0x_routing_and_ack_scope_end_to_end() {
        // DB-backed, opt-in.
        let Some((_app_state, auth_state, app)) = maybe_state_and_auth().await else {
            return;
        };

        let sender_dev = [1u8; 32];
        let receiver_dev = [3u8; 32];
        let sender_id_str = dsm_sdk::util::text_id::encode_base32_crockford(&sender_dev);
        let receiver_id_str = dsm_sdk::util::text_id::encode_base32_crockford(&receiver_dev);

        // Receiver uses the same token string "test-token"; auth hashes it.
        let token = "test-token";
        let token_hash = blake3::hash(token.as_bytes()).as_bytes().to_vec();
        let receiver_pubkey = vec![9u8; 32];
        let receiver_genesis_hash = vec![7u8; 32];
        crate::db::register_device(
            &auth_state.db_pool,
            &receiver_id_str,
            &receiver_genesis_hash,
            &receiver_pubkey,
            &token_hash,
        )
        .await
        .unwrap_or_else(|e| panic!("insert receiver device failed: {e}"));

        // Build valid envelope bytes, and a base32 message-id for middleware.
        let tip = [2u8; 32];
        let env = make_env(&sender_dev, &tip, 16);
        let mut body = Vec::with_capacity(env.encoded_len());
        env.encode(&mut body)
            .unwrap_or_else(|e| panic!("encode envelope failed: {e}"));

        let msg_id_b32_submit = dsm_sdk::util::text_id::encode_base32_crockford(&[1u8; 16]);
        let msg_id_b32_recv_a = dsm_sdk::util::text_id::encode_base32_crockford(&[2u8; 16]);
        let msg_id_b32_recv_r = dsm_sdk::util::text_id::encode_base32_crockford(&[3u8; 16]);
        let msg_id_b32_recv_r2 = dsm_sdk::util::text_id::encode_base32_crockford(&[4u8; 16]);

        // Submit as sender, route to receiver inbox via x-dsm-recipient.
        let auth_sender = format!("DSM {}:{}", sender_id_str, token);
        let receiver_id_b32 = dsm_sdk::util::text_id::encode_base32_crockford(&receiver_dev);
        let req_submit = Request::builder()
            .method("POST")
            .uri("/api/v2/b0x/submit")
            .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
            .header("authorization", auth_sender)
            .header("x-dsm-message-id", msg_id_b32_submit)
            .header("x-dsm-recipient", receiver_id_b32.clone())
            .body(axum::body::Body::from(body))
            .unwrap_or_else(|e| panic!("request build failed: {e}"));
        let resp_submit = app
            .clone()
            .oneshot(req_submit)
            .await
            .unwrap_or_else(|e| panic!("oneshot failed: {e}"));
        assert_eq!(resp_submit.status(), HttpStatus::NO_CONTENT);

        // Retrieve as SENDER should be empty even if we try to override x-dsm-recipient.
        let auth_sender = format!("DSM {}:{}", sender_id_str, token);
        let req_sender_retrieve = Request::builder()
            .method("GET")
            .uri("/api/v2/b0x/retrieve")
            .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
            .header("authorization", auth_sender)
            .header("x-dsm-message-id", msg_id_b32_recv_r)
            .header("x-dsm-recipient", receiver_id_b32.clone())
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("request build failed: {e}"));
        let resp_sender_retrieve = app
            .clone()
            .oneshot(req_sender_retrieve)
            .await
            .unwrap_or_else(|e| panic!("oneshot failed: {e}"));
        assert_eq!(resp_sender_retrieve.status(), HttpStatus::NO_CONTENT);

        // Retrieve as RECEIVER should return the envelope.
        let auth_receiver = format!("DSM {}:{}", receiver_id_str, token);
        let req_receiver_retrieve = Request::builder()
            .method("GET")
            .uri("/api/v2/b0x/retrieve")
            .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
            .header("authorization", auth_receiver.clone())
            .header("x-dsm-message-id", msg_id_b32_recv_r2)
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("request build failed: {e}"));
        let resp_receiver_retrieve = app
            .clone()
            .oneshot(req_receiver_retrieve)
            .await
            .unwrap_or_else(|e| panic!("oneshot failed: {e}"));
        assert_eq!(resp_receiver_retrieve.status(), HttpStatus::OK);
        let bytes = axum::body::to_bytes(resp_receiver_retrieve.into_body(), usize::MAX)
            .await
            .unwrap_or_else(|e| panic!("read body failed: {e}"));
        let batch = dsm::types::proto::BatchEnvelope::decode(bytes.as_ref())
            .unwrap_or_else(|e| panic!("decode batch failed: {e}"));
        assert_eq!(batch.envelopes.len(), 1);
        assert_eq!(batch.envelopes[0].message_id, vec![7u8; 16]);

        // Ack as receiver.
        let mut ack_batch = dsm::types::proto::BatchEnvelope::default();
        ack_batch.envelopes.push(dsm::types::proto::Envelope {
            message_id: vec![7u8; 16],
            ..Default::default()
        });
        let mut ack_body = Vec::with_capacity(ack_batch.encoded_len());
        ack_batch
            .encode(&mut ack_body)
            .unwrap_or_else(|e| panic!("encode ack batch failed: {e}"));

        let req_ack = Request::builder()
            .method("POST")
            .uri("/api/v2/b0x/ack")
            .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
            .header("authorization", auth_receiver)
            .header("x-dsm-message-id", msg_id_b32_recv_a)
            .body(axum::body::Body::from(ack_body))
            .unwrap_or_else(|e| panic!("request build failed: {e}"));
        let resp_ack = app
            .clone()
            .oneshot(req_ack)
            .await
            .unwrap_or_else(|e| panic!("oneshot failed: {e}"));
        assert_eq!(resp_ack.status(), HttpStatus::NO_CONTENT);

        // Now receiver retrieve should be empty.
        let auth_receiver = format!("DSM {}:{}", receiver_id_str, token);
        let req_receiver_retrieve2 = Request::builder()
            .method("GET")
            .uri("/api/v2/b0x/retrieve")
            .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
            .header("authorization", auth_receiver)
            .header(
                "x-dsm-message-id",
                dsm_sdk::util::text_id::encode_base32_crockford(&[5u8; 16]),
            )
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("request build failed: {e}"));
        let resp_receiver_retrieve2 = app
            .oneshot(req_receiver_retrieve2)
            .await
            .unwrap_or_else(|e| panic!("oneshot failed: {e}"));
        assert_eq!(resp_receiver_retrieve2.status(), HttpStatus::NO_CONTENT);
    }
}
