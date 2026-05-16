// SPDX-License-Identifier: Apache-2.0
//! Genesis MPC participation endpoints — spec §5 strict N-of-N
//! commit-reveal.
//!
//! Endpoints (protobuf-only, no JSON / hex / base64 in bodies):
//!
//! `POST /api/v2/genesis/mpc/offer`
//!   body: `GenesisMpcSessionV1` (the orchestrator's offer)
//!   resp: `GenesisMpcCommitV1`  (this node's own signed commit)
//!
//! Acceptance rules:
//!
//! - `participants.len() ≥ 3` (spec §5 minimum for "real" MPC).
//! - participants strictly sorted, 32 bytes each, no duplicates.
//! - this node's `StorageNodeId` must be in `participants`.
//! - `deadline_cycle` must be strictly greater than the current
//!   deterministic tick (no wall clock).
//! - `session_id` must not already exist (write-once).
//! - `initiator_device_id`, `initiator_cdbrw` must each be 32 bytes;
//!   `initiator_pk` must match SPHINCS+ SPX256f public-key length.
//!
//! On acceptance the node generates a fresh 32-byte entropy `e_self`,
//! computes
//!   `commit = H("DSM/genesis-commit\0" || session_id || self_node_id || e_self)`,
//! signs the canonical `GenesisMpcCommitV1` (with `node_signature`
//! cleared) with its persistent MPC participation key, and persists
//! the session row plus its own contribution row (`own_entropy =
//! Some(e_self)`, `revealed_entropy = None`).
//!
//! `POST /api/v2/genesis/mpc/commit/{session_id}`
//!   body: `GenesisMpcCommitV1` (a peer's signed commit, fanned out
//!         by the orchestrator so every participant can satisfy its
//!         bias-resistance gate)
//!   resp: `204 No Content`
//!
//! The storage node stores peer commits idempotently. It does NOT
//! cross-verify a peer's signature against any registry pubkey here
//! — that bridge is the orchestrator's responsibility at combine
//! time. Local checks: session must exist, body's `session_id` must
//! match the URL, peer's `contributor_id` must appear in the
//! session's declared participant set, and `contributor_id` MUST
//! NOT equal our own node id (that row is created by /offer).
//!
//! `POST /api/v2/genesis/mpc/reveal/{session_id}`
//!   body: empty (the orchestrator simply asks this node to reveal)
//!   resp: `GenesisMpcRevealV1`
//!
//! Bias-resistance gate (spec §5, strict N-of-N): the node MUST have
//! stored commits from ALL OTHER N-1 declared participants before
//! releasing its `e_self`. We check `contribution_count(session_id)
//! == N` (one row for this node + N-1 peer rows). If short, return
//! `412 Precondition Failed`. Once the gate passes, sign and return
//! the `GenesisMpcRevealV1`, mark the own row as revealed, and
//! transition the session state to `"revealed"`.
//!
//! Idempotency: a second /reveal call returns the same envelope.
//!
//! `GET /api/v2/genesis/mpc/session/{session_id}`
//!   resp: `GenesisMpcStatusV1`
//!
//! Returns the current state and counts. 404 if session unknown.
//!
//! `session_id` in URL paths is base32-Crockford of the 32-byte
//! session_id (the only place we encode it as text — matches the
//! existing `/api/v2/identity/{genesis}/devtree/*` convention).

use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use prost::Message;

use dsm::crypto::blake3::domain_hash_bytes;
use dsm::crypto::sphincs::{self, SphincsVariant};
use dsm::types::proto as pb;

use crate::db;
use crate::replication::StorageNodeId;
use crate::AppState;

const MPC_VARIANT: SphincsVariant = SphincsVariant::SPX256f;

/// Minimum participant count to call this MPC (spec §5: "≥3").
const MIN_PARTICIPANTS: usize = 3;

/// Generous upper bound to avoid pathological session-offer payloads.
/// A SPHINCS+ SPX256f public key is 64 bytes; combined with up to 64
/// 32-byte participant IDs and the four 32-byte identifying fields,
/// 16 KiB leaves plenty of headroom.
const MAX_OFFER_BODY: usize = 16 * 1024;

/// Upper bound on the /commit body. SPHINCS+ SPX256f signature is
/// 49_856 bytes; with the other commit fields, 64 KiB is comfortable.
const MAX_COMMIT_BODY: usize = 64 * 1024;

/// Domain tag for the commit digest (matches whitepaper §2.5 / spec §5).
const COMMIT_DOMAIN: &str = "DSM/genesis-commit";

pub fn create_router(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route("/api/v2/genesis/mpc/offer", post(offer))
        .route(
            "/api/v2/genesis/mpc/commit/{session_id}",
            post(observe_peer_commit),
        )
        .route("/api/v2/genesis/mpc/reveal/{session_id}", post(reveal))
        .route("/api/v2/genesis/mpc/session/{session_id}", get(get_session))
        .layer(Extension(state))
}

// -------------------- /offer --------------------

async fn offer(
    Extension(state): Extension<Arc<AppState>>,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    if body.len() > MAX_OFFER_BODY {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let session = pb::GenesisMpcSessionV1::decode(body.as_ref())
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Required field shape checks.
    if session.session_id.len() != 32
        || session.initiator_device_id.len() != 32
        || session.initiator_cdbrw.len() != 32
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let expected_pk_len = sphincs::public_key_bytes(MPC_VARIANT);
    if session.initiator_pk.len() != expected_pk_len {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Participant set validation.
    let participants = decode_participants(&session.participants)?;
    if participants.len() < MIN_PARTICIPANTS {
        return Err(StatusCode::BAD_REQUEST);
    }

    // The node must require its own MPC key to be loaded before
    // accepting any offer (test harnesses without a key get 503).
    let mpc_key = state.mpc_key.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let self_id = *state.node_id.as_bytes();

    // Must be in the declared participant set.
    if !participants.iter().any(|p| p == &self_id) {
        return Err(StatusCode::FORBIDDEN);
    }

    // Deadline must be in the future (strict greater than current
    // deterministic tick; no wall clock).
    let now_cycle = state.current_tick.load(Ordering::SeqCst);
    if (session.deadline_cycle as i64) <= now_cycle {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Fresh, secret entropy for this node's contribution.
    let mut e_self = [0u8; 32];
    use rand::rngs::OsRng;
    use rand::RngCore;
    OsRng
        .try_fill_bytes(&mut e_self)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // commit_digest = H("DSM/genesis-commit\0" || session_id || self_id || e_self)
    let mut input = Vec::with_capacity(32 + 32 + 32);
    input.extend_from_slice(&session.session_id);
    input.extend_from_slice(&self_id);
    input.extend_from_slice(&e_self);
    let commit_digest = domain_hash_bytes(COMMIT_DOMAIN, &input);

    // Sign the canonical commit envelope with `node_signature` cleared.
    let unsigned_commit = pb::GenesisMpcCommitV1 {
        session_id: session.session_id.clone(),
        contributor_id: self_id.to_vec(),
        commit_digest: commit_digest.to_vec(),
        node_signature: Vec::new(),
    };
    let signing_bytes = unsigned_commit.encode_to_vec();
    let commit_sig = sphincs::sign(MPC_VARIANT, mpc_key.secret_key_bytes(), &signing_bytes)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Persist session + own contribution. Insert-then-upsert under one
    // logical "accept" — if the session_id is already known we return
    // 409. The DB layer surfaces this as anyhow with a specific
    // "already exists" message.
    let row = db::GenesisMpcSessionRow {
        session_id: session.session_id.clone(),
        initiator_device_id: session.initiator_device_id.clone(),
        initiator_pk: session.initiator_pk.clone(),
        initiator_cdbrw: session.initiator_cdbrw.clone(),
        participants_blob: flatten_participants(&participants),
        deadline_cycle: session.deadline_cycle as i64,
        state: "offered".to_string(),
        created_at_cycle: now_cycle,
    };
    match db::genesis_mpc_session_insert(&state.db_pool, row).await {
        Ok(()) => {}
        Err(e) if format!("{e}").contains("already exists") => {
            return Err(StatusCode::CONFLICT);
        }
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    }

    db::genesis_mpc_contribution_upsert(
        &state.db_pool,
        db::GenesisMpcContributionRow {
            session_id: session.session_id.clone(),
            contributor_id: self_id.to_vec(),
            commit_digest: commit_digest.to_vec(),
            commit_signature: commit_sig.clone(),
            own_entropy: Some(e_self.to_vec()),
            revealed_entropy: None,
            reveal_signature: None,
        },
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let signed_commit = pb::GenesisMpcCommitV1 {
        session_id: session.session_id,
        contributor_id: self_id.to_vec(),
        commit_digest: commit_digest.to_vec(),
        node_signature: commit_sig,
    };
    Ok(proto_response(StatusCode::OK, &signed_commit))
}

// -------------------- /commit (peer fan-in) --------------------

async fn observe_peer_commit(
    Extension(state): Extension<Arc<AppState>>,
    Path(session_id_b32): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    if body.len() > MAX_COMMIT_BODY {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let session_id = decode_session_id_path(&session_id_b32)?;

    let commit = pb::GenesisMpcCommitV1::decode(body.as_ref())
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if commit.session_id != session_id {
        return Err(StatusCode::BAD_REQUEST);
    }
    if commit.contributor_id.len() != 32 || commit.commit_digest.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    if commit.node_signature.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let row = db::genesis_mpc_session_get(&state.db_pool, &session_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Reject peer commits past the deadline (the session is effectively
    // dead — purge will remove the row, but until it does we don't
    // accept new contributions).
    let now_cycle = state.current_tick.load(Ordering::SeqCst);
    if now_cycle >= row.deadline_cycle {
        return Err(StatusCode::GONE);
    }

    let participants = parse_participants_blob(&row.participants_blob)
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let contributor_id: [u8; 32] = commit
        .contributor_id
        .as_slice()
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if !participants.iter().any(|p| p == &contributor_id) {
        return Err(StatusCode::FORBIDDEN);
    }

    // Our own row is owned by /offer — refuse to overwrite it via the
    // fan-in path.
    if contributor_id == *state.node_id.as_bytes() {
        return Err(StatusCode::CONFLICT);
    }

    db::genesis_mpc_contribution_upsert(
        &state.db_pool,
        db::GenesisMpcContributionRow {
            session_id: session_id.to_vec(),
            contributor_id: contributor_id.to_vec(),
            commit_digest: commit.commit_digest,
            commit_signature: commit.node_signature,
            own_entropy: None,
            revealed_entropy: None,
            reveal_signature: None,
        },
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}

// -------------------- /reveal --------------------

async fn reveal(
    Extension(state): Extension<Arc<AppState>>,
    Path(session_id_b32): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let session_id = decode_session_id_path(&session_id_b32)?;

    let mpc_key = state.mpc_key.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    let session = db::genesis_mpc_session_get(&state.db_pool, &session_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Past deadline → reveal is no longer valid; the orchestrator must
    // start a new session with a fresh participant set.
    let now_cycle = state.current_tick.load(Ordering::SeqCst);
    if now_cycle >= session.deadline_cycle {
        return Err(StatusCode::GONE);
    }

    let participants = parse_participants_blob(&session.participants_blob)
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let n = participants.len();
    let self_id = *state.node_id.as_bytes();

    // Defence in depth: our id must still be in the set (it was at
    // /offer time, but the blob is the source of truth here).
    if !participants.iter().any(|p| p == &self_id) {
        return Err(StatusCode::FORBIDDEN);
    }

    // Load our own row — must have own_entropy set (the secret we
    // generated at /offer time).
    let own_row = db::genesis_mpc_contribution_get(&state.db_pool, &session_id, &self_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::CONFLICT)?;

    // Idempotent re-reveal: if we already published our reveal, return
    // the cached envelope so retries are safe.
    if let (Some(entropy), Some(sig)) = (
        own_row.revealed_entropy.as_ref(),
        own_row.reveal_signature.as_ref(),
    ) {
        let envelope = pb::GenesisMpcRevealV1 {
            session_id: session_id.to_vec(),
            contributor_id: self_id.to_vec(),
            entropy: entropy.clone(),
            node_signature: sig.clone(),
        };
        return Ok(proto_response(StatusCode::OK, &envelope));
    }

    let e_self = own_row
        .own_entropy
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    if e_self.len() != 32 {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // N-of-N bias-resistance gate: total stored commits must equal N,
    // i.e. own + (N-1) peer commits.
    let stored = db::genesis_mpc_contribution_count(&state.db_pool, &session_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if (stored as usize) < n {
        return Err(StatusCode::PRECONDITION_FAILED);
    }

    // Sign the canonical reveal envelope with `node_signature` cleared.
    let unsigned_reveal = pb::GenesisMpcRevealV1 {
        session_id: session_id.to_vec(),
        contributor_id: self_id.to_vec(),
        entropy: e_self.clone(),
        node_signature: Vec::new(),
    };
    let signing_bytes = unsigned_reveal.encode_to_vec();
    let reveal_sig = sphincs::sign(MPC_VARIANT, mpc_key.secret_key_bytes(), &signing_bytes)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Persist reveal in our own row + advance session state. Re-upsert
    // own_row preserves commit_digest/commit_signature/own_entropy via
    // COALESCE in the DB helper.
    db::genesis_mpc_contribution_upsert(
        &state.db_pool,
        db::GenesisMpcContributionRow {
            session_id: session_id.to_vec(),
            contributor_id: self_id.to_vec(),
            commit_digest: own_row.commit_digest,
            commit_signature: own_row.commit_signature,
            own_entropy: Some(e_self.clone()),
            revealed_entropy: Some(e_self.clone()),
            reveal_signature: Some(reveal_sig.clone()),
        },
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    db::genesis_mpc_session_set_state(&state.db_pool, &session_id, "revealed")
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let envelope = pb::GenesisMpcRevealV1 {
        session_id: session_id.to_vec(),
        contributor_id: self_id.to_vec(),
        entropy: e_self,
        node_signature: reveal_sig,
    };
    Ok(proto_response(StatusCode::OK, &envelope))
}

// -------------------- /session/{id} --------------------

async fn get_session(
    Extension(state): Extension<Arc<AppState>>,
    Path(session_id_b32): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let session_id = decode_session_id_path(&session_id_b32)?;

    let session = db::genesis_mpc_session_get(&state.db_pool, &session_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let contributions = db::genesis_mpc_contribution_list(&state.db_pool, &session_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let collected_commits_count: u32 = contributions
        .iter()
        .filter(|c| !c.commit_digest.is_empty())
        .count()
        .min(u32::MAX as usize) as u32;
    let collected_reveals_count: u32 = contributions
        .iter()
        .filter(|c| c.revealed_entropy.is_some())
        .count()
        .min(u32::MAX as usize) as u32;

    let envelope = pb::GenesisMpcStatusV1 {
        session_id: session_id.to_vec(),
        state: session.state,
        collected_commits_count,
        collected_reveals_count,
        error_message: String::new(),
    };
    Ok(proto_response(StatusCode::OK, &envelope))
}

// -------------------- helpers --------------------

fn proto_response<M: prost::Message>(status: StatusCode, msg: &M) -> impl IntoResponse {
    let mut buf = Vec::with_capacity(msg.encoded_len());
    // `encode` on a Vec<u8> only fails if the buffer cannot grow, which
    // it always can here. Treat the (unreachable) error as a 500 by
    // returning an empty body — the panic-on-impossible path is fine
    // for axum handler ergonomics.
    let _ = msg.encode(&mut buf);
    (
        status,
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        buf,
    )
}

fn decode_session_id_path(s: &str) -> Result<[u8; 32], StatusCode> {
    let bytes = dsm_sdk::util::text_id::decode_base32_crockford(s)
        .ok_or(StatusCode::BAD_REQUEST)?;
    bytes.try_into().map_err(|_| StatusCode::BAD_REQUEST)
}

/// Decode the proto's `repeated bytes participants` into `[u8;32]`
/// entries, validating shape and ordering. Rejects:
/// * any entry not exactly 32 bytes,
/// * duplicate IDs,
/// * out-of-order entries (must be strictly ascending lex).
fn decode_participants(raw: &[Vec<u8>]) -> Result<Vec<[u8; 32]>, StatusCode> {
    let mut out: Vec<[u8; 32]> = Vec::with_capacity(raw.len());
    for entry in raw {
        if entry.len() != 32 {
            return Err(StatusCode::BAD_REQUEST);
        }
        let arr: [u8; 32] = entry.as_slice().try_into().map_err(|_| StatusCode::BAD_REQUEST)?;
        if let Some(last) = out.last() {
            // strictly ascending: equal → duplicate, less → unsorted
            if &arr <= last {
                return Err(StatusCode::BAD_REQUEST);
            }
        }
        out.push(arr);
    }
    Ok(out)
}

fn flatten_participants(parts: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.len() * 32);
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

fn parse_participants_blob(blob: &[u8]) -> Option<Vec<[u8; 32]>> {
    if !blob.len().is_multiple_of(32) {
        return None;
    }
    let n = blob.len() / 32;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let mut a = [0u8; 32];
        a.copy_from_slice(&blob[i * 32..(i + 1) * 32]);
        out.push(a);
    }
    Some(out)
}

#[allow(dead_code)]
fn _self_id_for(state: &AppState) -> StorageNodeId {
    state.node_id
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::identity::load_or_generate_mpc_key;
    use crate::replication::{ReplicationConfig, ReplicationManager};
    use axum::body::Body;
    use axum::http::Request;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn test_replication_manager() -> Arc<ReplicationManager> {
        let cfg = ReplicationConfig {
            replication_factor: 1,
            gossip_interval_ticks: 1000,
            failure_timeout_ticks: 1000,
            gossip_fanout: 1,
            max_concurrent_jobs: 1,
        };
        Arc::new(
            ReplicationManager::new_for_tests(
                cfg,
                "test-node".to_string(),
                "http://localhost:8080".to_string(),
            )
            .expect("test replication manager"),
        )
    }

    /// Build a test AppState whose `node_id` is at a known position in
    /// a participant set sorted ascending. The MPC key is loaded from a
    /// tempdir so each test is hermetic.
    async fn test_state_for_node(
        node_seed: &str,
    ) -> (Arc<AppState>, tempfile::TempDir) {
        let pool = db::create_pool(":memory:", true).expect("test pool");
        db::init_db(&pool).await.expect("init_db");
        let dir = tempfile::tempdir().expect("tempdir");
        let key = load_or_generate_mpc_key(dir.path()).expect("mpc key");
        let state = AppState::new(
            node_seed.to_string(),
            &format!("http://{}.test", node_seed),
            None,
            Arc::new(pool),
            test_replication_manager(),
        )
        .with_mpc_key(Arc::new(key));
        (Arc::new(state), dir)
    }

    fn make_session_proto(
        session_id: &[u8; 32],
        deadline_cycle: u64,
        participants: &[[u8; 32]],
    ) -> Vec<u8> {
        // SPHINCS+ SPX256f pk size — we don't need a real key, just the
        // right length so the shape validation passes.
        let pk_len = sphincs::public_key_bytes(MPC_VARIANT);
        let session = pb::GenesisMpcSessionV1 {
            session_id: session_id.to_vec(),
            initiator_device_id: vec![0x11u8; 32],
            initiator_pk: vec![0u8; pk_len],
            initiator_cdbrw: vec![0x22u8; 32],
            participants: participants.iter().map(|p| p.to_vec()).collect(),
            deadline_cycle,
        };
        session.encode_to_vec()
    }

    /// Build a sorted-ascending participant set that includes the given
    /// AppState's `node_id`. Pads with synthetic IDs so the set size is
    /// `n`.
    fn participants_including(state: &AppState, n: usize) -> Vec<[u8; 32]> {
        let self_id = *state.node_id.as_bytes();
        let mut set: Vec<[u8; 32]> = Vec::with_capacity(n);
        set.push(self_id);
        let mut filler = 0u8;
        while set.len() < n {
            let mut id = [0u8; 32];
            id[0] = 0xF0 | (filler & 0x0F);
            id[1] = filler;
            // Avoid colliding with self_id.
            if id == self_id {
                filler = filler.wrapping_add(1);
                continue;
            }
            set.push(id);
            filler = filler.wrapping_add(1);
        }
        set.sort();
        set
    }

    #[tokio::test]
    async fn offer_accepted_returns_signed_commit() {
        let (state, _td) = test_state_for_node("offer-accepted").await;
        let participants = participants_including(&state, 3);
        let body = make_session_proto(&[7u8; 32], 1_000, &participants);

        let app = create_router(state.clone());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v2/genesis/mpc/offer")
                    .header("content-type", "application/octet-stream")
                    .body(Body::from(body))
                    .expect("build request"),
            )
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let resp_bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("read body");
        let commit = pb::GenesisMpcCommitV1::decode(resp_bytes.as_ref()).expect("decode");
        assert_eq!(commit.session_id.len(), 32);
        assert_eq!(commit.contributor_id, state.node_id.as_bytes().to_vec());
        assert_eq!(commit.commit_digest.len(), 32);
        assert_eq!(
            commit.node_signature.len(),
            sphincs::signature_bytes(MPC_VARIANT)
        );

        // Storage side-effect: a session row + an own contribution row
        // with `own_entropy` are persisted.
        let row = db::genesis_mpc_session_get(&state.db_pool, &commit.session_id)
            .await
            .expect("session get")
            .expect("session present");
        assert_eq!(row.state, "offered");
        assert_eq!(row.participants_blob.len(), 3 * 32);

        let own = db::genesis_mpc_contribution_get(
            &state.db_pool,
            &commit.session_id,
            state.node_id.as_bytes(),
        )
        .await
        .expect("get own")
        .expect("own row present");
        assert!(own.own_entropy.is_some());
        assert!(own.revealed_entropy.is_none());
    }

    #[tokio::test]
    async fn offer_rejected_when_node_not_in_participants() {
        let (state, _td) = test_state_for_node("offer-not-in-set").await;
        // Participants set that deliberately excludes our self_id.
        let participants: Vec<[u8; 32]> = (0u8..3u8)
            .map(|i| {
                let mut id = [0u8; 32];
                id[0] = 0x10 + i;
                id
            })
            .collect();
        assert!(!participants
            .iter()
            .any(|p| p == state.node_id.as_bytes()));
        let body = make_session_proto(&[8u8; 32], 1_000, &participants);

        let app = create_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v2/genesis/mpc/offer")
                    .body(Body::from(body))
                    .expect("req"),
            )
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn offer_rejected_on_duplicate_session_id() {
        let (state, _td) = test_state_for_node("offer-dup").await;
        let participants = participants_including(&state, 3);
        let session_id = [42u8; 32];
        let body = make_session_proto(&session_id, 1_000, &participants);

        let app = create_router(state.clone());

        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v2/genesis/mpc/offer")
                    .body(Body::from(body.clone()))
                    .expect("req1"),
            )
            .await
            .expect("oneshot1");
        assert_eq!(first.status(), StatusCode::OK);

        let second = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v2/genesis/mpc/offer")
                    .body(Body::from(body))
                    .expect("req2"),
            )
            .await
            .expect("oneshot2");
        assert_eq!(second.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn offer_rejected_below_minimum_participants() {
        let (state, _td) = test_state_for_node("offer-too-few").await;
        let participants = participants_including(&state, 2);
        let body = make_session_proto(&[9u8; 32], 1_000, &participants);

        let app = create_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v2/genesis/mpc/offer")
                    .body(Body::from(body))
                    .expect("req"),
            )
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn peer_commit_stored_and_appears_in_status() {
        let (state, _td) = test_state_for_node("peer-commit").await;
        let participants = participants_including(&state, 3);
        let session_id = [21u8; 32];
        let body = make_session_proto(&session_id, 1_000, &participants);

        let app = create_router(state.clone());
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v2/genesis/mpc/offer")
                    .body(Body::from(body))
                    .expect("req"),
            )
            .await
            .expect("offer");
        assert_eq!(resp.status(), StatusCode::OK);

        // Pick a peer id from the set (any entry that is not us).
        let self_id = *state.node_id.as_bytes();
        let peer_id = *participants
            .iter()
            .find(|p| *p != &self_id)
            .expect("at least one peer");

        // Build a peer commit. The signature contents don't need to
        // verify for this test — only shape rules are enforced
        // server-side at /commit; cross-verification is the
        // orchestrator's job at combine time.
        let peer_commit = pb::GenesisMpcCommitV1 {
            session_id: session_id.to_vec(),
            contributor_id: peer_id.to_vec(),
            commit_digest: vec![0x33u8; 32],
            node_signature: vec![0x44u8; 64],
        };
        let url = format!(
            "/api/v2/genesis/mpc/commit/{}",
            dsm_sdk::util::text_id::encode_base32_crockford(&session_id)
        );
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&url)
                    .body(Body::from(peer_commit.encode_to_vec()))
                    .expect("req"),
            )
            .await
            .expect("commit");
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Status now reports 2 commits (own + the peer we pushed).
        let status_url = format!(
            "/api/v2/genesis/mpc/session/{}",
            dsm_sdk::util::text_id::encode_base32_crockford(&session_id)
        );
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(&status_url)
                    .body(Body::empty())
                    .expect("req"),
            )
            .await
            .expect("status");
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("read");
        let status = pb::GenesisMpcStatusV1::decode(bytes.as_ref()).expect("decode");
        assert_eq!(status.collected_commits_count, 2);
        assert_eq!(status.collected_reveals_count, 0);
        assert_eq!(status.state, "offered");
    }

    #[tokio::test]
    async fn reveal_rejected_when_peer_commits_short() {
        let (state, _td) = test_state_for_node("reveal-gated").await;
        let participants = participants_including(&state, 3);
        let session_id = [55u8; 32];
        let body = make_session_proto(&session_id, 1_000, &participants);

        let app = create_router(state);
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v2/genesis/mpc/offer")
                    .body(Body::from(body))
                    .expect("req"),
            )
            .await
            .expect("offer");
        assert_eq!(resp.status(), StatusCode::OK);

        // No peer commits stored → reveal must refuse.
        let url = format!(
            "/api/v2/genesis/mpc/reveal/{}",
            dsm_sdk::util::text_id::encode_base32_crockford(&session_id)
        );
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&url)
                    .body(Body::empty())
                    .expect("req"),
            )
            .await
            .expect("reveal");
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    }

    #[tokio::test]
    async fn reveal_succeeds_after_all_peer_commits_observed_and_is_idempotent() {
        let (state, _td) = test_state_for_node("reveal-ok").await;
        let participants = participants_including(&state, 3);
        let session_id = [66u8; 32];
        let body = make_session_proto(&session_id, 1_000, &participants);

        let app = create_router(state.clone());
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v2/genesis/mpc/offer")
                    .body(Body::from(body))
                    .expect("req"),
            )
            .await
            .expect("offer");
        assert_eq!(resp.status(), StatusCode::OK);

        let self_id = *state.node_id.as_bytes();
        for p in participants.iter().filter(|p| **p != self_id) {
            let peer_commit = pb::GenesisMpcCommitV1 {
                session_id: session_id.to_vec(),
                contributor_id: p.to_vec(),
                commit_digest: vec![0x77u8; 32],
                node_signature: vec![0x88u8; 64],
            };
            let url = format!(
                "/api/v2/genesis/mpc/commit/{}",
                dsm_sdk::util::text_id::encode_base32_crockford(&session_id)
            );
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(&url)
                        .body(Body::from(peer_commit.encode_to_vec()))
                        .expect("req"),
                )
                .await
                .expect("commit");
            assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        }

        // All N-1 peer commits stored → reveal must now succeed.
        let url = format!(
            "/api/v2/genesis/mpc/reveal/{}",
            dsm_sdk::util::text_id::encode_base32_crockford(&session_id)
        );
        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&url)
                    .body(Body::empty())
                    .expect("req"),
            )
            .await
            .expect("reveal1");
        assert_eq!(first.status(), StatusCode::OK);
        let first_bytes = axum::body::to_bytes(first.into_body(), 1 << 20)
            .await
            .expect("read");
        let r1 = pb::GenesisMpcRevealV1::decode(first_bytes.as_ref()).expect("decode r1");
        assert_eq!(r1.session_id, session_id.to_vec());
        assert_eq!(r1.contributor_id, self_id.to_vec());
        assert_eq!(r1.entropy.len(), 32);
        assert_eq!(
            r1.node_signature.len(),
            sphincs::signature_bytes(MPC_VARIANT)
        );

        // Session row should now be "revealed".
        let row = db::genesis_mpc_session_get(&state.db_pool, &session_id)
            .await
            .expect("get session")
            .expect("session present");
        assert_eq!(row.state, "revealed");

        // Idempotent re-reveal returns the same envelope bytes.
        let second = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&url)
                    .body(Body::empty())
                    .expect("req"),
            )
            .await
            .expect("reveal2");
        assert_eq!(second.status(), StatusCode::OK);
        let second_bytes = axum::body::to_bytes(second.into_body(), 1 << 20)
            .await
            .expect("read");
        let r2 = pb::GenesisMpcRevealV1::decode(second_bytes.as_ref()).expect("decode r2");
        assert_eq!(r2.entropy, r1.entropy);
        assert_eq!(r2.node_signature, r1.node_signature);
    }

    #[tokio::test]
    async fn purge_removes_expired_session_and_contributions() {
        let (state, _td) = test_state_for_node("purge").await;
        let participants = participants_including(&state, 3);
        let session_id = [99u8; 32];
        let body = make_session_proto(&session_id, 50, &participants);

        let app = create_router(state.clone());
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v2/genesis/mpc/offer")
                    .body(Body::from(body))
                    .expect("req"),
            )
            .await
            .expect("offer");
        assert_eq!(resp.status(), StatusCode::OK);

        // Purge with cutoff_cycle > deadline.
        let purged = db::genesis_mpc_session_purge_expired(&state.db_pool, 1_000)
            .await
            .expect("purge");
        assert!(purged >= 1);
        let row = db::genesis_mpc_session_get(&state.db_pool, &session_id)
            .await
            .expect("get");
        assert!(row.is_none(), "session row should be purged");
        let contribs = db::genesis_mpc_contribution_list(&state.db_pool, &session_id)
            .await
            .expect("list");
        assert!(
            contribs.is_empty(),
            "contributions should cascade-purge with the session"
        );
    }

    #[tokio::test]
    async fn get_session_404_when_unknown() {
        let (state, _td) = test_state_for_node("get-404").await;
        let app = create_router(state);
        let url = format!(
            "/api/v2/genesis/mpc/session/{}",
            dsm_sdk::util::text_id::encode_base32_crockford(&[1u8; 32])
        );
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(&url)
                    .body(Body::empty())
                    .expect("req"),
            )
            .await
            .expect("status");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
