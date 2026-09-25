// SPDX-License-Identifier: MIT OR Apache-2.0
//! The b0x inbox spool (storage spec §8): bytes in under a recipient's spool
//! key, bytes out by that key from a position on. Protobuf-only, clockless.

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
use dsm::utils::text_id;

const MAX_ENVELOPE_BYTES: usize = 128 * 1024; // 128 KiB (normalized)
const MAX_BATCH_RETRIEVE: i64 = 64;

fn valid_spool_key(value: &str) -> bool {
    matches!(
        text_id::decode_base32_crockford(value),
        Some(bytes) if bytes.len() == 32
    )
}

/// The b0x spool. No write authorization and no reader authorization
/// (storage spec §4, DSM Amendment A3): the node never checks who writes or
/// reads, never opens an envelope and refuses none (storage spec §8). The
/// spool is append-only: nothing is marked read, hidden, expired, removed or
/// deduplicated. Canonical encoding, the replay-protected message id and the
/// recipient key are checked by the devices at both ends; which messages a
/// device has consumed is the device's own state.
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

/// Append the request body to the spool named by `x-dsm-recipient` (Base32
/// Crockford of 32 bytes: the recipient's device id or a b0x routing key).
/// Answers `204 No Content` once the bytes are durably appended.
async fn submit_b0x_envelope(
    Extension(app): Extension<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    require_protobuf(&headers)?;

    let recipient_spool_key = headers
        .get("x-dsm-recipient")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;
    if !valid_spool_key(recipient_spool_key) {
        return Err(StatusCode::BAD_REQUEST);
    }

    crate::db::spool_insert(&app.db_pool, recipient_spool_key, &body)
        .await
        .map_err(|e| {
            log::error!("b0x submit: spool_insert failed: {e:?}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(StatusCode::NO_CONTENT)
}

/// Up to [`MAX_BATCH_RETRIEVE`] entries of the spool named by
/// `x-dsm-b0x-address`, from position `from_seq` on, as a
/// `SequencedBatchEnvelope` of the bytes exactly as they were submitted.
/// `204 No Content` when nothing is held there.
async fn retrieve_b0x_batch_from_seq(
    axum::extract::Path(from_seq): axum::extract::Path<i64>,
    Extension(app): Extension<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<axum::response::Response, StatusCode> {
    let lookup_key = headers
        .get("x-dsm-b0x-address")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .ok_or(StatusCode::BAD_REQUEST)?;
    if !valid_spool_key(lookup_key) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let rows =
        crate::db::spool_list_from_seq(&app.db_pool, lookup_key, from_seq, MAX_BATCH_RETRIEVE)
            .await
            .map_err(|e| {
                log::error!("b0x retrieve: spool_list_from_seq failed: {e:?}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
    if rows.is_empty() {
        return Ok(StatusCode::NO_CONTENT.into_response());
    }

    let mut batch = dsm::types::proto::SequencedBatchEnvelope::default();
    let mut next_seq = from_seq;
    for (envelope, seq_num) in rows {
        next_seq = next_seq.max(seq_num + 1);
        batch.envelopes.push(dsm::types::proto::SequencedEnvelope {
            envelope,
            seq_num: u64::try_from(seq_num).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        });
    }
    batch.next_seq = u64::try_from(next_seq).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/octet-stream"),
    );
    Ok((StatusCode::OK, headers, batch.encode_to_vec()).into_response())
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
        let app_state = Arc::new(
            AppState::new(
                "test-node".to_string(),
                pool,
                crate::db::test_store::set_client(),
            )
            .unwrap_or_else(|e| panic!("app state: {e}")),
        );
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

    /// The entries the spool at `address` holds from position 0, as the node
    /// answers them.
    async fn spooled(app: &Router, address: &str) -> Vec<Vec<u8>> {
        let (status, bytes) = retrieve(app, address, 0).await;
        assert_eq!(status, HttpStatus::OK);
        dsm::types::proto::SequencedBatchEnvelope::decode(bytes.as_slice())
            .expect("batch")
            .envelopes
            .into_iter()
            .map(|e| e.envelope)
            .collect()
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
        assert_eq!(
            batch.envelopes[0].envelope, body,
            "the spool returns the bytes it was sent"
        );
        let held = dsm::envelope::from_canonical_bytes(&batch.envelopes[0].envelope)
            .expect("the reader decodes what it was sent");
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

    /// Storage spec §8: the node refuses nothing and deduplicates nothing. A
    /// second envelope carrying a message id already spooled — a different
    /// envelope under the same id, or the same bytes again — is appended and
    /// read back after the first; telling them apart is the recipient's
    /// replay check. The node used to keep only the first holder of an id,
    /// across every spool, and answer the second writer 204.
    #[tokio::test]
    async fn an_envelope_reusing_a_message_id_is_kept_after_the_first() {
        let app = spool().await;
        let spool_key = crate::db::test_store::unique_name(0x65);
        let first = sealed_envelope();
        let mut second = sealed_envelope();
        second.outer.message_id = first.outer.message_id.clone();
        let (first, second) = (first.outer.encode_to_vec(), second.outer.encode_to_vec());
        assert_ne!(first, second);
        for body in [&first, &second, &first] {
            assert_eq!(
                submit(&app, &spool_key, "application/octet-stream", body.clone()).await,
                HttpStatus::NO_CONTENT
            );
        }
        let other_key = crate::db::test_store::unique_name(0x66);
        assert_eq!(
            submit(&app, &other_key, "application/octet-stream", first.clone()).await,
            HttpStatus::NO_CONTENT
        );

        let held = spooled(&app, &spool_key).await;
        assert_eq!(held, vec![first.clone(), second, first.clone()]);
        let held_elsewhere = spooled(&app, &other_key).await;
        assert_eq!(held_elsewhere, vec![first]);
    }

    /// Storage spec §8: envelopes are never opened by the node. Bytes that are
    /// not an envelope at all — here a v3 envelope with a 15-byte message id,
    /// and plain junk — are kept and returned exactly; the recipient decides
    /// what they are. The node used to decode every envelope on the way in and
    /// again on the way out.
    #[tokio::test]
    async fn bytes_the_node_cannot_read_are_kept_and_returned_unopened() {
        let app = spool().await;
        let spool_key = crate::db::test_store::unique_name(0x63);
        let mut short_id = sealed_envelope();
        short_id.outer.message_id.truncate(15);
        let short_id = short_id.outer.encode_to_vec();
        let junk = vec![0xFF, 0x00, 0x13, 0x37];
        for body in [&short_id, &junk] {
            assert_eq!(
                submit(&app, &spool_key, "application/octet-stream", body.clone()).await,
                HttpStatus::NO_CONTENT
            );
        }
        let held = spooled(&app, &spool_key).await;
        assert_eq!(held, vec![short_id, junk]);
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
