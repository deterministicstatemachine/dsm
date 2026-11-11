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
use dsm::spool::MAX_SPOOL_WRITE_BYTES;
use dsm::utils::text_id;

/// [`dsm::spool::MAX_BATCH_RETRIEVE`], as the query's integer.
const MAX_BATCH_RETRIEVE: i64 = dsm::spool::MAX_BATCH_RETRIEVE as i64;

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

/// Waits the node holds at once on any one spool. A spool is one
/// relationship's inbox at one step, read by one device, so a few waits
/// cover a device whose earlier wait is still held when it opens the next.
/// One more naming that spool is answered `503` at once, as one over
/// [`MAX_WAITERS`] is.
pub const MAX_WAITERS_PER_SPOOL: usize = 4;

/// Waits reading the store at once, out of the node's
/// [`crate::db::POOL_MAX_SIZE`] connections. A wait reads the store when it
/// starts and when arrivals went by it unseen, and [`MAX_WAITERS`] of them
/// can start or fall behind together; the rest wait their turn holding no
/// connection, so the wait route, which runs outside the node's concurrency
/// limit, never holds more than these of the connections every other route
/// shares.
pub const WAIT_LOOKS: usize = crate::db::POOL_MAX_SIZE / 4;

/// A wait request's body: [`MAX_WAIT_MARKS`] marks fit well inside it.
const MAX_WAIT_BODY_BYTES: usize = 64 * 1024;

/// Arrivals buffered for waits that have not yet looked at them. A wait that
/// falls further behind looks at its spools again instead.
const ARRIVALS_BUFFER: usize = 1024;

/// An entry a spool took: the spool and the position the entry holds there.
/// A wait is answered from this alone, so a submit wakes its waits without
/// any of them reading the store.
#[derive(Clone, Debug)]
struct Arrival {
    spool_key: String,
    seq_num: i64,
}

/// The spools that took an entry, announced to every wait (storage spec §8,
/// long-poll), the slots waits are held in, across the node and per spool,
/// and the turns waits take reading the store ([`WAIT_LOOKS`]). In-process:
/// a node's spool is written by its own submit route alone.
#[derive(Clone)]
pub struct SpoolWaits {
    arrivals: tokio::sync::broadcast::Sender<Arrival>,
    slots: Arc<tokio::sync::Semaphore>,
    per_spool: Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>>,
    looks: Arc<tokio::sync::Semaphore>,
}

impl Default for SpoolWaits {
    fn default() -> Self {
        let (arrivals, _receiver) = tokio::sync::broadcast::channel(ARRIVALS_BUFFER);
        Self {
            arrivals,
            slots: Arc::new(tokio::sync::Semaphore::new(MAX_WAITERS)),
            per_spool: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            looks: Arc::new(tokio::sync::Semaphore::new(WAIT_LOOKS)),
        }
    }
}

/// A wait held: its slot under [`MAX_WAITERS`] and its count on every spool
/// it watches, both given back when the wait ends.
struct HeldWait {
    per_spool: Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>>,
    watched: Vec<String>,
    _slot: tokio::sync::OwnedSemaphorePermit,
}

impl Drop for HeldWait {
    fn drop(&mut self) {
        let mut held = SpoolWaits::counts(&self.per_spool);
        for key in &self.watched {
            if let Some(count) = held.get_mut(key) {
                *count -= 1;
                if *count == 0 {
                    held.remove(key);
                }
            }
        }
    }
}

impl SpoolWaits {
    /// Wake every wait on the spool that took the entry at `seq_num`. With
    /// no wait held there is no one to wake, and the send has nowhere to go.
    fn announce(&self, spool_key: &str, seq_num: i64) {
        if self.arrivals.receiver_count() > 0 {
            let arrival = Arrival {
                spool_key: spool_key.to_string(),
                seq_num,
            };
            if let Err(e) = self.arrivals.send(arrival) {
                log::error!("b0x submit: the arrival on {spool_key} reached no wait: {e}");
            }
        }
    }

    /// The per-spool counts. A panic while they were held leaves every
    /// count whole (each is one integer written in place), so they are read
    /// as they stand.
    fn counts(
        per_spool: &std::sync::Mutex<std::collections::HashMap<String, usize>>,
    ) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, usize>> {
        match per_spool.lock() {
            Ok(counts) => counts,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Hold a wait on the `watched` spools, or `503` when the node already
    /// holds [`MAX_WAITERS`] waits, or [`MAX_WAITERS_PER_SPOOL`] on any one
    /// of them.
    fn hold(&self, watched: &std::collections::HashSet<String>) -> Result<HeldWait, StatusCode> {
        let Ok(slot) = self.slots.clone().try_acquire_owned() else {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        };
        let mut held = Self::counts(&self.per_spool);
        if watched
            .iter()
            .any(|key| held.get(key).is_some_and(|n| *n >= MAX_WAITERS_PER_SPOOL))
        {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        for key in watched {
            *held.entry(key.clone()).or_insert(0) += 1;
        }
        Ok(HeldWait {
            per_spool: self.per_spool.clone(),
            watched: watched.iter().cloned().collect(),
            _slot: slot,
        })
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

/// The b0x spool. A write is stored only when it carries its address's key,
/// fixed by the address's first write, a grant under that key and the
/// granted key's signature over the write (storage spec §8, DSM Amendment
/// A34): one check, the same on every node. No reader authorization. The node
/// never opens an envelope. The spool is append-only: nothing is marked read,
/// hidden, expired, removed or deduplicated. Canonical encoding, the replay-protected message id and the
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
            MAX_SPOOL_WRITE_BYTES,
        ))
}

/// A device's wait on its spools (long-poll), held until something lands
/// or `bound` passes, when it is answered `204`: a transport bound like the
/// request timeout, so no protocol fact depends on it (storage spec §1 rule
/// 4), and the node reads no clock for it. Held on purpose, so it is served
/// outside the node's request timeout and concurrency limit
/// ([`crate::build_app`]): [`MAX_WAITERS`] bounds it instead, a held wait
/// holds no database connection, and at most [`WAIT_LOOKS`] waits read the
/// store at once.
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

/// The 32 bytes a canonical spool key names.
fn spool_key_bytes(key: &str) -> Result<[u8; 32], StatusCode> {
    let bytes = text_id::decode_base32_crockford(key).ok_or(StatusCode::BAD_REQUEST)?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|e| {
        log::info!("b0x submit: the spool key is {} bytes: {e}", bytes.len());
        StatusCode::BAD_REQUEST
    })
}

/// The 16-byte message id `x-dsm-message-id` names (Base32 Crockford).
fn message_id_header(headers: &HeaderMap) -> Result<[u8; 16], StatusCode> {
    let value = headers
        .get("x-dsm-message-id")
        .ok_or(StatusCode::BAD_REQUEST)?;
    let text = value.to_str().map_err(|e| {
        log::info!("b0x submit: the message id is not text: {e}");
        StatusCode::BAD_REQUEST
    })?;
    let bytes = text_id::decode_base32_crockford(text).ok_or(StatusCode::BAD_REQUEST)?;
    <[u8; 16]>::try_from(bytes.as_slice()).map_err(|e| {
        log::info!("b0x submit: the message id is {} bytes: {e}", bytes.len());
        StatusCode::BAD_REQUEST
    })
}

fn require_protobuf(headers: &HeaderMap) -> Result<(), StatusCode> {
    match headers.get(axum::http::header::CONTENT_TYPE) {
        Some(v) if v == "application/octet-stream" => Ok(()),
        Some(v) if v == "application/protobuf" => Ok(()),
        _ => Err(StatusCode::UNSUPPORTED_MEDIA_TYPE),
    }
}

/// Append a write to the spool named by `x-dsm-recipient` (Base32 Crockford
/// of 32 bytes: an inbox address), under the message id `x-dsm-message-id`
/// (Base32 Crockford of 16 bytes). The body is a `SpoolWriteV1`: the sealed
/// envelope, the inbox's key, that key's grant of the writer's key, the
/// writer's signature over the address, the id and the envelope, and the
/// inbox's route digest (DSM Amendment A34). The address must be the route
/// bound to the key (a locked inbox: the key is its own) or the route's open
/// address (a relationship's first inbox: the key its first write fixed). The
/// node checks the signatures, never opens the envelope, and stores the
/// envelope alone. The check is the same on
/// every node and leaves it no choice: `204 No Content` once the envelope is
/// durably appended, `403 Forbidden` for a write that fails it.
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
    let address = spool_key_bytes(&recipient_spool_key)?;
    let message_id = message_id_header(&headers)?;

    let write =
        dsm::core::relationship_write_grant::verify_spool_write(&body, &address, &message_id)
            .map_err(|e| {
                log::info!("b0x submit: refused: {e}");
                StatusCode::FORBIDDEN
            })?;

    // A locked inbox's key is its own by derivation: the write proved the
    // address is its route bound to that key. An open inbox (a
    // relationship's first) takes the key its first write fixed.
    let appended = match write.inbox {
        dsm::core::relationship_write_grant::InboxKind::Locked => {
            crate::db::spool_append(&app.db_pool, &recipient_spool_key, &write.envelope).await
        }
        dsm::core::relationship_write_grant::InboxKind::Open => {
            crate::db::spool_insert_locked(
                &app.db_pool,
                &recipient_spool_key,
                &write.lock_public_key,
                &write.envelope,
            )
            .await
        }
    }
    .map_err(|e| {
        log::error!("b0x submit: the append failed: {e:?}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    match appended {
        crate::db::LockedAppend::Appended(seq_num) => {
            app.spool_waits.announce(&recipient_spool_key, seq_num);
            Ok(StatusCode::NO_CONTENT)
        }
        crate::db::LockedAppend::NotTheAddressKey => {
            log::info!("b0x submit: refused: not the address's key");
            Err(StatusCode::FORBIDDEN)
        }
    }
}

/// Answer once any spool a [`dsm::types::proto::B0xWaitRequest`] names holds
/// an entry at or after the position given for it: `200` with those spools
/// in a `B0xWaitResponse`. Until then the wait is held; the router answers
/// `204` once its bound passes ([`wait_router`]). `400` for a request that is
/// not one, `503` when [`MAX_WAITERS`] waits are already held, or
/// [`MAX_WAITERS_PER_SPOOL`] on a spool it names. A submit wakes a wait with
/// the position its entry took, and the wait answers from that alone; a wait
/// reads the store only when it starts and when arrivals went by it unseen.
/// Nothing is
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

    let _held = app.spool_waits.hold(&watched)?;
    // Subscribed before the first look, so an entry that lands between the
    // look and the wait still wakes it.
    let mut arrivals = app.spool_waits.arrivals.subscribe();
    let ready = ready_spools(&app, &marks).await?;
    if !ready.is_empty() {
        return Ok(wait_answer(ready));
    }
    loop {
        match arrivals.recv().await {
            // The arrival says where the entry landed, which is all a wait
            // asks: no wait reads the store to learn it.
            Ok(arrival)
                if marks
                    .iter()
                    .any(|(key, from)| *key == arrival.spool_key && arrival.seq_num >= *from) =>
            {
                return Ok(wait_answer(vec![arrival.spool_key]));
            }
            Ok(_elsewhere) => continue,
            // Arrivals went by unseen: look at the spools again.
            Err(RecvError::Lagged(missed)) => {
                log::debug!("b0x wait: {missed} arrival(s) went by unseen; looking again");
                let ready = ready_spools(&app, &marks).await?;
                if !ready.is_empty() {
                    return Ok(wait_answer(ready));
                }
            }
            // The node is shutting down: nothing more will land here.
            Err(RecvError::Closed) => return Ok(StatusCode::NO_CONTENT.into_response()),
        }
    }
}

/// The spools among `marks` that hold an entry at or after the position
/// given for each, read from the store once this wait's turn among
/// [`WAIT_LOOKS`] comes; until then it holds no connection.
async fn ready_spools(app: &AppState, marks: &[(String, i64)]) -> Result<Vec<String>, StatusCode> {
    let _turn = app.spool_waits.looks.acquire().await.map_err(|e| {
        log::error!("b0x wait: the store's turns are closed: {e}");
        StatusCode::SERVICE_UNAVAILABLE
    })?;
    crate::db::spool_ready(&app.db_pool, marks)
        .await
        .map_err(|e| {
            log::error!("b0x wait: spool_ready failed: {e:?}");
            StatusCode::INTERNAL_SERVER_ERROR
        })
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
            AppState::new("test-node".to_string(), pool)
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

    /// The key these tests write under: the first write at each test
    /// address fixes it there (DSM Amendment A34).
    fn test_key() -> &'static dsm::crypto::sphincs::SphincsKeyPair {
        static KEY: std::sync::OnceLock<dsm::crypto::sphincs::SphincsKeyPair> =
            std::sync::OnceLock::new();
        KEY.get_or_init(|| {
            dsm::crypto::sphincs::generate_keypair(dsm::crypto::sphincs::SphincsVariant::SPX256f)
                .expect("a test key")
        })
    }

    /// The route digest each test inbox address was derived from.
    fn routes() -> std::sync::MutexGuard<'static, std::collections::HashMap<String, [u8; 32]>> {
        static ROUTES: std::sync::OnceLock<
            std::sync::Mutex<std::collections::HashMap<String, [u8; 32]>>,
        > = std::sync::OnceLock::new();
        ROUTES
            .get_or_init(Default::default)
            .lock()
            .expect("the test routes")
    }

    /// A fresh locked inbox address: a unique route bound to the test key.
    fn test_inbox(tag: u8) -> String {
        let route = crate::db::test_store::unique_key(tag);
        let address =
            dsm::crypto::spool_address::locked_inbox_address(&route, &test_key().public_key);
        routes().insert(address.clone(), route);
        address
    }

    /// A fresh open inbox address: a relationship's first inbox.
    fn test_open_inbox(tag: u8) -> String {
        let route = crate::db::test_store::unique_key(tag);
        let address = dsm::crypto::spool_address::open_inbox_address(&route);
        routes().insert(address.clone(), route);
        address
    }

    /// `envelope` written to `recipient` (an address [`test_inbox`] or
    /// [`test_open_inbox`] made, in any spelling) under `key`, granting
    /// itself, with a fresh message id: the request body and the id.
    fn signed(
        recipient: &str,
        envelope: &[u8],
        key: &dsm::crypto::sphincs::SphincsKeyPair,
    ) -> (Vec<u8>, String) {
        let canonical = super::canonical_spool_key(recipient).expect("a test address");
        let route = *routes().get(&canonical).expect("a test address's route");
        let address = super::spool_key_bytes(&canonical).expect("a test address decodes");
        let message_id: [u8; 16] = rand::random();
        let body = dsm::core::relationship_write_grant::self_granted_spool_write(
            key,
            &[0x5A; 32],
            &route,
            &address,
            &message_id,
            envelope,
        )
        .expect("a signed write");
        (body, text_id::encode_base32_crockford(&message_id))
    }

    async fn submit_write(
        app: &Router,
        recipient: &str,
        content_type: &str,
        body: Vec<u8>,
        message_id: &str,
    ) -> HttpStatus {
        let req = Request::builder()
            .method("POST")
            .uri("/api/v2/b0x/submit")
            .header(axum::http::header::CONTENT_TYPE, content_type)
            .header("x-dsm-recipient", recipient)
            .header("x-dsm-message-id", message_id)
            .body(axum::body::Body::from(body))
            .unwrap_or_else(|e| panic!("request build failed: {e}"));
        app.clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("oneshot failed: {e}"))
            .status()
    }

    /// `envelope` submitted to `recipient` as a write under the test key.
    async fn submit(
        app: &Router,
        recipient: &str,
        content_type: &str,
        envelope: Vec<u8>,
    ) -> HttpStatus {
        let (body, message_id) = signed(recipient, &envelope, test_key());
        submit_write(app, recipient, content_type, body, &message_id).await
    }

    /// DSM Amendment A34: a locked inbox takes only its own lock, by
    /// derivation, whatever arrives first. A stranger's well-signed write
    /// under its own key is refused even as the first write there, and
    /// nothing is fixed: the inbox's own key is taken afterwards.
    #[tokio::test]
    async fn a_locked_inbox_takes_only_its_own_lock_even_from_the_first_write() {
        let app = spool().await;
        let spool_key = test_inbox(0x6D);
        let stranger =
            dsm::crypto::sphincs::generate_keypair(dsm::crypto::sphincs::SphincsVariant::SPX256f)
                .expect("a stranger's key");
        let (body, id) = signed(&spool_key, b"the stranger writes first", &stranger);
        assert_eq!(
            submit_write(&app, &spool_key, "application/octet-stream", body, &id).await,
            HttpStatus::FORBIDDEN
        );
        let own = sealed_envelope().outer.encode_to_vec();
        assert_eq!(
            submit(&app, &spool_key, "application/octet-stream", own.clone()).await,
            HttpStatus::NO_CONTENT
        );
        assert_eq!(spooled(&app, &spool_key).await, vec![own]);
    }

    /// DSM Amendment A34: the first write at a relationship's first inbox
    /// (an open address) fixes its key. A write there under another key is
    /// refused and stores nothing, however well it is signed; a write under
    /// the fixed key is taken.
    #[tokio::test]
    async fn the_first_write_fixes_an_addresss_key_and_another_key_is_refused() {
        let app = spool().await;
        let spool_key = test_open_inbox(0x6A);
        let first = sealed_envelope().outer.encode_to_vec();
        assert_eq!(
            submit(&app, &spool_key, "application/octet-stream", first.clone()).await,
            HttpStatus::NO_CONTENT
        );
        let stranger =
            dsm::crypto::sphincs::generate_keypair(dsm::crypto::sphincs::SphincsVariant::SPX256f)
                .expect("a stranger's key");
        let (body, id) = signed(&spool_key, b"junk from a stranger", &stranger);
        assert_eq!(
            submit_write(&app, &spool_key, "application/octet-stream", body, &id).await,
            HttpStatus::FORBIDDEN
        );
        let second = sealed_envelope().outer.encode_to_vec();
        assert_eq!(
            submit(&app, &spool_key, "application/octet-stream", second.clone()).await,
            HttpStatus::NO_CONTENT
        );
        assert_eq!(spooled(&app, &spool_key).await, vec![first, second]);
    }

    /// DSM Amendment A34: a write that is not one, a write signed for another
    /// address, and a write with no message id are each refused, and nothing
    /// is stored, not even an address's key.
    #[tokio::test]
    async fn a_write_that_does_not_verify_stores_nothing() {
        let app = spool().await;
        let spool_key = test_open_inbox(0x6B);
        let other_key = test_inbox(0x6C);
        let envelope = sealed_envelope().outer.encode_to_vec();
        let (_, id) = signed(&spool_key, &envelope, test_key());
        assert_eq!(
            submit_write(
                &app,
                &spool_key,
                "application/octet-stream",
                envelope.clone(),
                &id
            )
            .await,
            HttpStatus::FORBIDDEN,
            "bare envelope bytes"
        );
        let (for_other, other_id) = signed(&other_key, &envelope, test_key());
        assert_eq!(
            submit_write(
                &app,
                &spool_key,
                "application/octet-stream",
                for_other,
                &other_id
            )
            .await,
            HttpStatus::FORBIDDEN,
            "a write signed for another address"
        );
        let (body, _) = signed(&spool_key, &envelope, test_key());
        let req = Request::builder()
            .method("POST")
            .uri("/api/v2/b0x/submit")
            .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
            .header("x-dsm-recipient", spool_key.as_str())
            .body(axum::body::Body::from(body))
            .expect("request");
        assert_eq!(
            app.clone().oneshot(req).await.expect("oneshot").status(),
            HttpStatus::BAD_REQUEST,
            "no message id"
        );
        let (status, _) = retrieve(&app, &spool_key, 0).await;
        assert_eq!(status, HttpStatus::NO_CONTENT, "nothing stored");
        // Nothing fixed either: a stranger's write is still the first.
        let stranger =
            dsm::crypto::sphincs::generate_keypair(dsm::crypto::sphincs::SphincsVariant::SPX256f)
                .expect("a key");
        let (body, id) = signed(&spool_key, &envelope, &stranger);
        assert_eq!(
            submit_write(&app, &spool_key, "application/octet-stream", body, &id).await,
            HttpStatus::NO_CONTENT
        );
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
        let spool_key = test_inbox(0x61);
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
        let spool_key = test_inbox(0x65);
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
        let other_key = test_inbox(0x66);
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
        let spool_key = test_inbox(0x63);
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
        let spool_key = test_inbox(0x67);
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
        let spool_key = test_inbox(0x68);
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
        let spool_key = test_inbox(0x62);
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
        let (status, bytes) = retrieve(&app, &test_inbox(0x62), 0).await;
        assert_eq!(status, HttpStatus::NO_CONTENT);
        assert!(bytes.is_empty());
    }

    #[tokio::test]
    async fn v2_b0x_submit_rejects_wrong_content_type() {
        let app = spool().await;
        let spool_key = test_inbox(0x64);
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

    /// The wait router on `pool`, holding a wait for at most `bound`, and the
    /// node state behind it.
    fn waits_on(pool: crate::db::DBPool, bound: std::time::Duration) -> (Arc<AppState>, Router) {
        let app_state =
            Arc::new(AppState::new("test-node".to_string(), Arc::new(pool)).expect("app state"));
        let router = super::wait_router(app_state.clone(), bound);
        (app_state, router)
    }

    /// A wait on `spools`, each from position 1.
    fn wait_request(spools: &[&str]) -> Request<axum::body::Body> {
        let request = dsm::types::proto::B0xWaitRequest {
            marks: spools
                .iter()
                .map(|address| dsm::types::proto::B0xWaitMark {
                    address: address.to_string(),
                    from_seq: 1,
                })
                .collect(),
        };
        Request::builder()
            .method("POST")
            .uri("/api/v2/b0x/wait")
            .header("content-type", "application/octet-stream")
            .body(axum::body::Body::from(request.encode_to_vec()))
            .unwrap()
    }

    /// Yield until `done` holds, at most `rounds` times. These tests run no
    /// timer of their own (no node source does): what bounds a wait here is
    /// the node's own wait bound and the pool's own wait for a connection.
    async fn until(rounds: usize, mut done: impl FnMut() -> bool) -> bool {
        for _ in 0..rounds {
            if done() {
                return done();
            }
            tokio::task::yield_now().await;
        }
        done()
    }

    /// Until the node holds `n` waits, each subscribed to arrivals.
    async fn until_held(app_state: &AppState, n: usize) {
        let held = until(1_000_000, || {
            app_state.spool_waits.arrivals.receiver_count() == n
        })
        .await;
        assert!(
            held,
            "the node holds {} waits, not {n}",
            app_state.spool_waits.arrivals.receiver_count()
        );
    }

    /// A spool takes at most MAX_WAITERS_PER_SPOOL waits: one more naming it
    /// is answered 503 at once, where a held wait would be answered 204 only
    /// when the wait bound passes; a wait on another spool is still held.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_spool_holds_no_more_waits_than_its_bound() {
        let (app_state, router) = waits_on(
            crate::db::test_store::fresh_pool().await,
            std::time::Duration::from_secs(3),
        );
        let (crowded, other) = (
            crate::db::test_store::unique_name(0x65),
            crate::db::test_store::unique_name(0x65),
        );
        let held: Vec<_> = (0..MAX_WAITERS_PER_SPOOL)
            .map(|_| tokio::spawn(router.clone().oneshot(wait_request(&[crowded.as_str()]))))
            .collect();
        until_held(&app_state, MAX_WAITERS_PER_SPOOL).await;

        let one_more = router
            .clone()
            .oneshot(wait_request(&[other.as_str(), crowded.as_str()]))
            .await
            .expect("answer");
        assert_eq!(one_more.status(), HttpStatus::SERVICE_UNAVAILABLE);

        let elsewhere = tokio::spawn(router.clone().oneshot(wait_request(&[other.as_str()])));
        until_held(&app_state, MAX_WAITERS_PER_SPOOL + 1).await;
        assert!(!elsewhere.is_finished(), "a wait on another spool is held");
        for wait in held.into_iter().chain([elsewhere]) {
            wait.abort();
        }
    }

    /// A submit wakes its waits without any of them reading the store: once
    /// the waits have looked at their spool, the node's only database
    /// connection is taken, an entry lands (written over another connection),
    /// and the arrival the submit route announces for it answers every wait
    /// on that spool. A wait that read the store instead would wait on the
    /// pool until its wait for a connection ran out, and answer `500`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_submit_wakes_its_waits_without_any_reading_the_store() {
        let url = std::env::var("DSM_TEST_DATABASE_URL").expect("DSM_TEST_DATABASE_URL");
        let pool = crate::db::create_pool(&url, 1).expect("pool");
        crate::db::init_db(&pool).await.expect("init");
        let (app_state, router) = waits_on(pool, std::time::Duration::from_secs(30));
        let spool_key = crate::db::test_store::unique_name(0x66);
        let waits: Vec<_> = (0..3)
            .map(|_| tokio::spawn(router.clone().oneshot(wait_request(&[spool_key.as_str()]))))
            .collect();
        until_held(&app_state, 3).await;
        // Every wait's first look at its spool is done once the pool's one
        // connection is idle and nobody is waiting for it.
        let looked = until(10_000_000, || {
            let status = app_state.db_pool.status();
            status.size == 1 && status.available == 1 && status.waiting == 0
        })
        .await;
        assert!(looked, "the waits' first looks never finished");
        let taken = app_state.db_pool.get().await.expect("the only connection");

        // What the submit route does: the entry lands, then its arrival is
        // announced.
        let writer = crate::db::test_store::fresh_pool().await;
        let seq_num =
            match crate::db::spool_insert_locked(&writer, &spool_key, &[0x4B; 64], b"sealed")
                .await
                .expect("insert")
            {
                crate::db::LockedAppend::Appended(seq_num) => seq_num,
                other => panic!("the first write fixes the key: {other:?}"),
            };
        app_state.spool_waits.announce(&spool_key, seq_num);

        for wait in waits {
            let answer = wait.await.expect("task").expect("answer");
            assert_eq!(answer.status(), HttpStatus::OK);
            let body = axum::body::to_bytes(answer.into_body(), usize::MAX)
                .await
                .unwrap();
            let ready = dsm::types::proto::B0xWaitResponse::decode(body.as_ref()).unwrap();
            assert_eq!(ready.ready, vec![spool_key.clone()]);
        }
        drop(taken);
    }
}
