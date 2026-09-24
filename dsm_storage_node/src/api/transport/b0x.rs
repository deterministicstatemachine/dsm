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
    // Do NOT validate protocol semantics here (clients verify).

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
    let rows = crate::db::spool_list_from_seq(pool, lookup_key, from_seq, MAX_BATCH_RETRIEVE)
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

    /// The b0x router on the Postgres test database.
    async fn spool() -> Router {
        let pool = Arc::new(crate::db::test_store::fresh_pool().await);
        let replication_manager = Arc::new(
            ReplicationManager::new_for_tests(
                ReplicationConfig {
                    replication_factor: 3,
                    gossip_interval_ticks: 100,
                    failure_timeout_ticks: 300,
                    gossip_fanout: 3,
                    max_concurrent_jobs: 10,
                },
                "test-node".to_string(),
                "http://localhost:8080".to_string(),
            )
            .unwrap_or_else(|e| panic!("Failed to create replication manager: {e}")),
        );
        let app_state = Arc::new(AppState::new(
            "test-node".to_string(),
            "http://localhost:8080",
            None,
            pool,
            replication_manager,
        ));
        super::router(app_state)
    }

    /// What a device sends (DSM Amendment A7): an inner envelope sealed to a
    /// recipient's Kyber key, carried by an outer v3 envelope holding only the
    /// message id and the seal.
    struct Sent {
        outer: dsm::types::proto::Envelope,
        inner: Vec<u8>,
        recipient: dsm::crypto::kyber::KyberKeyPair,
    }

    fn sealed_envelope() -> Sent {
        use dsm::types::proto::{envelope::Payload, Envelope, Headers, SealedEnvelopeV1};
        let recipient = dsm::crypto::kyber::generate_kyber_keypair().expect("kyber keypair");
        let message_id: [u8; 16] = rand::random();
        let inner = Envelope {
            version: 3,
            headers: Some(Headers {
                device_id: rand::random::<[u8; 32]>().to_vec(),
                genesis_hash: rand::random::<[u8; 32]>().to_vec(),
            }),
            message_id: message_id.to_vec(),
            payload: None,
        }
        .encode_to_vec();
        let (shared_secret, kem_ciphertext) =
            dsm::crypto::kyber::kyber_encapsulate(&recipient.public_key).expect("encapsulate");
        let ciphertext =
            dsm::crypto::spool_seal::seal(&shared_secret, &message_id, &inner).expect("seal");
        let outer = Envelope {
            version: 3,
            headers: None,
            message_id: message_id.to_vec(),
            payload: Some(Payload::Sealed(SealedEnvelopeV1 {
                kem_ciphertext,
                ciphertext,
            })),
        };
        Sent {
            outer,
            inner,
            recipient,
        }
    }

    async fn submit(
        app: &Router,
        recipient: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> HttpStatus {
        let req = Request::builder()
            .method("POST")
            .uri("/api/v2/b0x/submit")
            .header(axum::http::header::CONTENT_TYPE, content_type)
            .header("x-dsm-recipient", recipient)
            .body(axum::body::Body::from(body))
            .unwrap_or_else(|e| panic!("request build failed: {e}"));
        app.clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("oneshot failed: {e}"))
            .status()
    }

    /// What the spool at `address` answers from position `from_seq`.
    async fn retrieve(app: &Router, address: &str, from_seq: i64) -> (HttpStatus, Vec<u8>) {
        let req = Request::builder()
            .method("GET")
            .uri(format!("/api/v2/b0x/retrieve/{from_seq}"))
            .header("x-dsm-b0x-address", address)
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("request build failed: {e}"));
        let resp = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("oneshot failed: {e}"));
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap_or_else(|e| panic!("read body failed: {e}"));
        (status, body.to_vec())
    }

    /// A sealed envelope submitted with no authorization is spooled under its
    /// recipient's key, read back from position 0 by that key byte for byte,
    /// and opens with the recipient's Kyber secret.
    #[tokio::test]
    async fn a_submitted_envelope_is_read_back_from_its_spool() {
        use dsm::types::proto::envelope::Payload;
        let app = spool().await;
        let spool_key = crate::db::test_store::unique_name(0x61);
        let sent = sealed_envelope();
        let body = sent.outer.encode_to_vec();
        assert_eq!(
            submit(&app, &spool_key, "application/octet-stream", body.clone()).await,
            HttpStatus::NO_CONTENT
        );

        let (status, bytes) = retrieve(&app, &spool_key, 0).await;
        assert_eq!(status, HttpStatus::OK);
        let batch =
            dsm::types::proto::SequencedBatchEnvelope::decode(bytes.as_slice()).expect("batch");
        assert_eq!(batch.envelopes.len(), 1);
        let held = batch.envelopes[0].envelope.as_ref().expect("envelope");
        assert_eq!(
            held.encode_to_vec(),
            body,
            "the spool returns the bytes it was sent"
        );
        let Some(Payload::Sealed(seal)) = &held.payload else {
            panic!("the held envelope is not sealed");
        };
        let shared_secret =
            dsm::crypto::kyber::kyber_decapsulate(&sent.recipient.secret_key, &seal.kem_ciphertext)
                .expect("decapsulate");
        let message_id: [u8; 16] = held.message_id.as_slice().try_into().expect("16-byte id");
        assert_eq!(
            dsm::crypto::spool_seal::open(&shared_secret, &message_id, &seal.ciphertext)
                .expect("the recipient opens it"),
            sent.inner
        );
        assert_eq!(batch.next_seq, batch.envelopes[0].seq_num + 1);

        let (status, bytes) = retrieve(&app, &spool_key, batch.next_seq as i64).await;
        assert_eq!(
            status,
            HttpStatus::NO_CONTENT,
            "nothing after the last position"
        );
        assert!(bytes.is_empty());
    }

    /// A spool nothing was sent to answers with no content.
    #[tokio::test]
    async fn an_empty_spool_answers_no_content() {
        let app = spool().await;
        let (status, bytes) = retrieve(&app, &crate::db::test_store::unique_name(0x62), 0).await;
        assert_eq!(status, HttpStatus::NO_CONTENT);
        assert!(bytes.is_empty());
    }

    #[tokio::test]
    async fn v2_b0x_submit_rejects_bad_msg_id_len() {
        let app = spool().await;
        let spool_key = crate::db::test_store::unique_name(0x63);
        let mut sent = sealed_envelope();
        sent.outer.message_id.truncate(15);
        assert_eq!(
            submit(
                &app,
                &spool_key,
                "application/octet-stream",
                sent.outer.encode_to_vec()
            )
            .await,
            HttpStatus::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn v2_b0x_submit_rejects_wrong_content_type() {
        let app = spool().await;
        let spool_key = crate::db::test_store::unique_name(0x64);
        assert_eq!(
            submit(
                &app,
                &spool_key,
                "text/plain",
                sealed_envelope().outer.encode_to_vec()
            )
            .await,
            HttpStatus::UNSUPPORTED_MEDIA_TYPE
        );
    }
}
