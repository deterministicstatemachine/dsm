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

/// How long the deployed node holds a wait before answering that nothing
/// landed ([`crate::AppLimits::wait_bound`]): under the idle cut-off of
/// phones, carriers and NAT tables, so a held request is answered rather than
/// dropped on the way.
pub const MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(25);

/// Spools one wait may name: every inbox route of a device with a few hundred
/// contacts.
pub const MAX_WAIT_MARKS: usize = 512;

/// Waits the node holds at once. One more is answered `503` at once, and the
/// device falls back to reading on its own schedule.
pub const MAX_WAITERS: usize = 4096;

/// A wait request's body: [`MAX_WAIT_MARKS`] marks fit well inside it.
const MAX_WAIT_BODY_BYTES: usize = 64 * 1024;

/// Arrivals buffered for waits that have not yet looked at them. A wait that
/// falls further behind looks at its spools again instead.
const ARRIVALS_BUFFER: usize = 1024;

/// The spools that took an entry, announced to every wait (storage spec §8,
/// long-poll), and the slots waits are held in. In-process: a node's spool is
/// written by its own submit route alone.
#[derive(Clone)]
pub struct SpoolWaits {
    arrivals: tokio::sync::broadcast::Sender<String>,
    slots: Arc<tokio::sync::Semaphore>,
}

impl Default for SpoolWaits {
    fn default() -> Self {
        let (arrivals, _receiver) = tokio::sync::broadcast::channel(ARRIVALS_BUFFER);
        Self {
            arrivals,
            slots: Arc::new(tokio::sync::Semaphore::new(MAX_WAITERS)),
        }
    }
}

impl SpoolWaits {
    /// Wake every wait on `spool_key`. With no wait held there is no one to
    /// wake, and the send has nowhere to go.
    fn announce(&self, spool_key: &str) {
        if self.arrivals.receiver_count() > 0 {
            if let Err(e) = self.arrivals.send(spool_key.to_string()) {
                log::error!("b0x submit: the arrival on {spool_key} reached no wait: {e}");
            }
        }
    }
}

/// The spool key `value` names, in its one canonical spelling, or `None`
/// when it is not Base32 Crockford of 32 bytes. Base32 Crockford reads
/// several spellings as the same bytes (either case, `I` and `L` for `1`,
/// `O` for `0`), and the spool is kept under exactly one, so the spelling a
/// writer chooses cannot put a message where its recipient never reads.
fn canonical_spool_key(value: &str) -> Option<String> {
    match text_id::decode_base32_crockford(value) {
        Some(bytes) if bytes.len() == 32 => Some(text_id::encode_base32_crockford(&bytes)),
        _ => None,
    }
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

/// A device's wait on its spools (long-poll), held until something lands
/// or `bound` passes, when it is answered `204`: a transport bound like the
/// request timeout, so no protocol fact depends on it (storage spec §1 rule
/// 4), and the node reads no clock for it. Held on purpose, so it is served
/// outside the node's request timeout and concurrency limit
/// ([`crate::build_app`]): [`MAX_WAITERS`] bounds it instead, and a held wait
/// holds no database connection.
pub fn wait_router(app: Arc<AppState>, bound: std::time::Duration) -> Router<()> {
    Router::new()
        .route("/api/v2/b0x/wait", post(wait_for_spools))
        .layer(Extension(app))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            MAX_WAIT_BODY_BYTES,
        ))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::NO_CONTENT,
            bound,
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
        .and_then(canonical_spool_key)
        .ok_or(StatusCode::BAD_REQUEST)?;

    crate::db::spool_insert(&app.db_pool, &recipient_spool_key, &body)
        .await
        .map_err(|e| {
            log::error!("b0x submit: spool_insert failed: {e:?}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    app.spool_waits.announce(&recipient_spool_key);
    Ok(StatusCode::NO_CONTENT)
}

/// Answer once any spool a [`dsm::types::proto::B0xWaitRequest`] names holds
/// an entry at or after the position given for it: `200` with those spools
/// in a `B0xWaitResponse`. Until then the wait is held; the router answers
/// `204` once its bound passes ([`wait_router`]). `400` for a request that is
/// not one, `503` when [`MAX_WAITERS`] waits are already held. Nothing is
/// read out, marked or changed: the device reads its spools as it always
/// does.
async fn wait_for_spools(
    Extension(app): Extension<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<axum::response::Response, StatusCode> {
    use tokio::sync::broadcast::error::RecvError;

    require_protobuf(&headers)?;
    let request = dsm::types::proto::B0xWaitRequest::decode(body.as_ref()).map_err(|e| {
        log::info!("b0x wait: the request does not decode: {e}");
        StatusCode::BAD_REQUEST
    })?;
    if request.marks.is_empty() || request.marks.len() > MAX_WAIT_MARKS {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut marks = Vec::with_capacity(request.marks.len());
    for mark in &request.marks {
        let key = canonical_spool_key(&mark.address).ok_or(StatusCode::BAD_REQUEST)?;
        // Positions are the node's own sequence numbers; one past every one a
        // spool can hold was never handed out.
        let from = i64::try_from(mark.from_seq).map_err(|e| {
            log::info!(
                "b0x wait: position {} is not a spool position: {e}",
                mark.from_seq
            );
            StatusCode::BAD_REQUEST
        })?;
        marks.push((key, from));
    }
    let watched: std::collections::HashSet<String> =
        marks.iter().map(|(key, _from)| key.clone()).collect();

    let Ok(_slot) = app.spool_waits.slots.clone().try_acquire_owned() else {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    };
    // Subscribed before the first look, so an entry that lands between the
    // look and the wait still wakes it.
    let mut arrivals = app.spool_waits.arrivals.subscribe();
    loop {
        let ready = crate::db::spool_ready(&app.db_pool, &marks)
            .await
            .map_err(|e| {
                log::error!("b0x wait: spool_ready failed: {e:?}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        if !ready.is_empty() {
            return Ok(wait_answer(ready));
        }
        loop {
            match arrivals.recv().await {
                Ok(key) if watched.contains(&key) => break,
                Ok(_elsewhere) => continue,
                // Arrivals went by unseen: look at the spools again.
                Err(RecvError::Lagged(missed)) => {
                    log::debug!("b0x wait: {missed} arrival(s) went by unseen; looking again");
                    break;
                }
                // The node is shutting down: nothing more will land here.
                Err(RecvError::Closed) => return Ok(StatusCode::NO_CONTENT.into_response()),
            }
        }
    }
}

/// A wait's answer: the spools that hold an entry for it.
fn wait_answer(ready: Vec<String>) -> axum::response::Response {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/octet-stream"),
    );
    let answer = dsm::types::proto::B0xWaitResponse { ready };
    (StatusCode::OK, headers, answer.encode_to_vec()).into_response()
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
        .and_then(canonical_spool_key)
        .ok_or(StatusCode::BAD_REQUEST)?;

    let rows =
        crate::db::spool_list_from_seq(&app.db_pool, &lookup_key, from_seq, MAX_BATCH_RETRIEVE)
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
    fn a_spool_key_is_kept_in_its_one_canonical_spelling() {
        let routed = text_id::encode_base32_crockford(&[0x55u8; 32]);
        assert_eq!(canonical_spool_key(&routed), Some(routed.clone()));
        assert_eq!(
            canonical_spool_key(&routed.to_ascii_lowercase()),
            Some(routed),
            "another spelling of the same bytes names the same spool"
        );
        assert_eq!(canonical_spool_key("b0x[TEST][TEST][TEST]"), None);
        assert_eq!(
            canonical_spool_key(&text_id::encode_base32_crockford(&[0x55u8; 31])),
            None,
            "a key is 32 bytes"
        );
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

    /// The page the spool at `address` answers from position `from_seq`: its
    /// entries as `(position, bytes)`, and the position after them.
    async fn page(app: &Router, address: &str, from_seq: u64) -> (Vec<(u64, Vec<u8>)>, u64) {
        let from = i64::try_from(from_seq).expect("a position the route takes");
        let (status, bytes) = retrieve(app, address, from).await;
        assert_eq!(status, HttpStatus::OK, "a page from position {from_seq}");
        let batch =
            dsm::types::proto::SequencedBatchEnvelope::decode(bytes.as_slice()).expect("batch");
        let entries = batch
            .envelopes
            .into_iter()
            .map(|e| (e.seq_num, e.envelope))
            .collect();
        (entries, batch.next_seq)
    }

    /// Storage spec §8: a spool is read from a position, and reading it
    /// changes nothing. More envelopes than one page holds are read whole in
    /// two pages, in the order they were sent; the first page, read again
    /// after the second, is what it was; a read from a position in the middle
    /// is exactly the spool from there on. A spool that marked, hid or removed
    /// what had been read, or served from anywhere but the position asked,
    /// fails here.
    #[tokio::test]
    async fn a_spool_reads_the_same_from_any_position_however_often_it_is_read() {
        let app = spool().await;
        let spool_key = crate::db::test_store::unique_name(0x67);
        let page_len = usize::try_from(MAX_BATCH_RETRIEVE).expect("a page length");
        let sent: Vec<Vec<u8>> = (0..page_len + 3)
            .map(|_| sealed_envelope().outer.encode_to_vec())
            .collect();
        for body in &sent {
            assert_eq!(
                submit(&app, &spool_key, "application/octet-stream", body.clone()).await,
                HttpStatus::NO_CONTENT
            );
        }

        let (first, after_first) = page(&app, &spool_key, 0).await;
        assert_eq!(first.len(), page_len, "a page holds {page_len} entries");
        let (second, after_second) = page(&app, &spool_key, after_first).await;
        let whole: Vec<(u64, Vec<u8>)> = first.iter().chain(second.iter()).cloned().collect();
        assert_eq!(
            whole
                .iter()
                .map(|(_, bytes)| bytes.clone())
                .collect::<Vec<_>>(),
            sent,
            "every envelope, once, in the order it was sent"
        );
        assert!(
            whole.windows(2).all(|pair| pair[0].0 < pair[1].0),
            "positions rise in arrival order"
        );
        assert_eq!(after_second, whole[whole.len() - 1].0 + 1);

        assert_eq!(
            page(&app, &spool_key, 0).await,
            (first, after_first),
            "reading the spool marked, hid or removed something"
        );

        let middle = page_len / 2;
        let (from_middle, after_middle) = page(&app, &spool_key, whole[middle].0).await;
        assert_eq!(
            from_middle,
            whole[middle..].to_vec(),
            "a read from a position is the spool from that position on"
        );
        assert_eq!(after_middle, after_second);

        let end = i64::try_from(after_second).expect("a position the route takes");
        let (status, bytes) = retrieve(&app, &spool_key, end).await;
        assert_eq!(
            status,
            HttpStatus::NO_CONTENT,
            "nothing after the last position"
        );
        assert!(bytes.is_empty());
    }

    /// Storage spec §8: which messages a device has consumed is the device's
    /// own state, and a spool is served only from a position. The requests a
    /// device once made to acknowledge what it read, to ask a message's
    /// status and to read with no position are not served, and the spool
    /// reads the same after them.
    #[tokio::test]
    async fn a_device_acknowledging_what_it_read_changes_nothing() {
        let app = spool().await;
        let spool_key = crate::db::test_store::unique_name(0x68);
        let sent = sealed_envelope();
        let body = sent.outer.encode_to_vec();
        assert_eq!(
            submit(&app, &spool_key, "application/octet-stream", body.clone()).await,
            HttpStatus::NO_CONTENT
        );
        let (read, after_read) = page(&app, &spool_key, 0).await;
        let batch = dsm::types::proto::SequencedBatchEnvelope {
            envelopes: read
                .iter()
                .map(|(seq_num, envelope)| dsm::types::proto::SequencedEnvelope {
                    envelope: envelope.clone(),
                    seq_num: *seq_num,
                })
                .collect(),
            next_seq: after_read,
        };

        let message_id = text_id::encode_base32_crockford(&sent.outer.message_id);
        for (method, uri, request_body) in [
            ("POST", "/api/v2/b0x/ack".to_string(), batch.encode_to_vec()),
            (
                "GET",
                format!("/api/v2/b0x/status/{message_id}"),
                Vec::new(),
            ),
            ("GET", "/api/v2/b0x/retrieve".to_string(), Vec::new()),
        ] {
            let req = Request::builder()
                .method(method)
                .uri(uri.as_str())
                .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
                .header("x-dsm-recipient", spool_key.as_str())
                .header("x-dsm-b0x-address", spool_key.as_str())
                .body(axum::body::Body::from(request_body))
                .expect("a request");
            let status = app
                .clone()
                .oneshot(req)
                .await
                .expect("the router answers")
                .status();
            assert_eq!(status, HttpStatus::NOT_FOUND, "{method} {uri} is served");
        }

        assert_eq!(
            page(&app, &spool_key, 0).await,
            (read, after_read),
            "the spool changed after the device's requests"
        );
    }

    /// A spool nothing was sent to answers with no content.
    /// The spool a message lands in does not depend on how its writer spells
    /// the key. A submission under another spelling of the same 32 bytes is
    /// read back under the canonical spelling its recipient reads, and under
    /// the writer's spelling too: one spool, whatever the spelling.
    #[tokio::test]
    async fn a_message_sent_under_another_spelling_of_its_key_reaches_its_spool() {
        let app = spool().await;
        let spool_key = crate::db::test_store::unique_name(0x62);
        let spelled = spool_key.to_ascii_lowercase();
        assert_ne!(spelled, spool_key, "the key has letters to spell otherwise");
        let body = sealed_envelope().outer.encode_to_vec();
        assert_eq!(
            submit(&app, &spelled, "application/octet-stream", body.clone()).await,
            HttpStatus::NO_CONTENT
        );
        assert_eq!(spooled(&app, &spool_key).await, vec![body.clone()]);
        assert_eq!(spooled(&app, &spelled).await, vec![body]);
    }

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
