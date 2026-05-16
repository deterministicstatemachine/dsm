// SPDX-License-Identifier: Apache-2.0
//! Genesis MPC participation endpoints — spec §5 strict N-of-N
//! commit-reveal.
//!
//! Endpoints (protobuf-only, no JSON / hex / base64 in bodies):
//!
//! `POST /api/v2/genesis/mpc/offer`
//!   body: `GenesisMpcSessionV1` (the orchestrator's signed offer)
//!   resp: `GenesisMpcCommitV1`  (this node's own commit)
//!
//! Acceptance rules:
//!
//! - `participants.len() ≥ 3` (spec §5 minimum for "real" MPC).
//! - participants strictly sorted, 32 bytes each, no duplicates.
//! - this node's `StorageNodeId` must be in `participants`.
//! - `session_id` must not already exist (write-once primary key).
//! - `initiator_device_id`, `initiator_cdbrw` must each be 32 bytes;
//!   `initiator_pk_attest` must match SPHINCS+ SPX256f public-key
//!   length; `initiator_signature` must SPHINCS+-verify against the
//!   canonical offer-envelope preimage under
//!   `DSM/genesis-mpc-offer\0` domain.
//!
//! Spec §1 + §2 alignment: storage nodes never SIGN, but they DO
//! verify device signatures (the existing stitched-receipt path
//! does the same — verifying does not equal signing). The signature
//! check is the offer-envelope shape predicate; without it a node
//! could be flooded with valid-shape garbage offers under any
//! deterministic `session_id` an attacker can grind.
//!
//! On acceptance the node generates a fresh 32-byte entropy `e_self`,
//! computes
//!   `commit = H("DSM/genesis-commit\0" || session_id || e_self)`,
//! and persists the session row plus its own contribution row
//! (`own_entropy = Some(e_self)`, `revealed_entropy = None`). The
//! hash binds the entropy to the commit (whitepaper §2.5 / spec §5).
//!
//! `POST /api/v2/genesis/mpc/commit/{session_id}`
//!   body: `GenesisMpcCommitV1` (a peer's commit, fanned out by the
//!         orchestrator so every participant can satisfy its
//!         bias-resistance gate)
//!   resp: `204 No Content`
//!
//! The storage node stores peer commits idempotently. Local checks:
//! session must exist, body's `session_id` must match the URL,
//! peer's `contributor_id` must appear in the session's declared
//! participant set, and `contributor_id` MUST NOT equal our own
//! node id (that row is created by /offer). Peer commits are not
//! signed by the peer; they are signed by the orchestrator at the
//! /offer round and bound to the session_id by the orchestrator's
//! initial signature.
//!
//! `POST /api/v2/genesis/mpc/reveal/{session_id}`
//!   body: `GenesisMpcRevealRequestV1` carrying `pk_attest` plus a
//!         SPHINCS+ signature over `H("DSM/genesis-mpc-reveal\0" ||
//!         session_id)`. The node verifies the signature against
//!         the `pk_attest` stored on the session row (must match
//!         byte-for-byte). Defeats arbitrary parties triggering a
//!         reveal on a publicly-derivable `session_id`.
//!   resp: `GenesisMpcRevealV1`
//!
//! Bias-resistance gate (spec §5, strict N-of-N): the node MUST have
//! stored commits from ALL OTHER N-1 declared participants before
//! releasing its `e_self`. We check `contribution_count(session_id)
//! == N` (one row for this node + N-1 peer rows). If short, return
//! `412 Precondition Failed`. Once the gate passes, return the
//! `GenesisMpcRevealV1`, mark the own row as revealed, and
//! transition the session state to `"revealed"`.
//!
//! Idempotency: a second /reveal call (with a valid signed body)
//! returns the same envelope.
//!
//! `GET /api/v2/genesis/mpc/session/{session_id}`
//!   resp: `GenesisMpcStatusV1`
//!
//! Returns the current state and counts. 404 if session unknown.
//!
//! `session_id` in URL paths is base32-Crockford of the 32-byte
//! session_id (the only place we encode it as text — matches the
//! existing `/api/v2/identity/{genesis}/devtree/*` convention).
//!
//! Per spec §1 ("clockless"), there is no `deadline_cycle` field in
//! the protocol. Sessions are purged by operator policy against
//! `created_at_cycle` via the admin router — not by the handler.

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
use dsm::crypto::sphincs;
use dsm::types::proto as pb;

use crate::db;
use crate::replication::StorageNodeId;
use crate::AppState;

/// Minimum participant count to call this MPC (spec §5: "≥3").
const MIN_PARTICIPANTS: usize = 3;

/// Generous upper bound for the session-offer payload. The largest
/// fields are `initiator_pk_attest` (SPHINCS+ device attestation pk)
/// and `initiator_signature` (SPHINCS+ sig). SPHINCS+ signatures for
/// SPX256f are ~50 KiB on the wire, so the cap leaves headroom plus
/// participants. 96 KiB accommodates up to ~64 participants.
const MAX_OFFER_BODY: usize = 96 * 1024;

/// Upper bound on the /commit body. The body is just three 32-byte
/// hash fields, but we keep the limit generous to absorb future
/// schema growth without a hot redeploy. The /reveal body carries a
/// signed `GenesisMpcRevealRequestV1` whose largest field is the
/// SPHINCS+ signature (~50 KiB).
const MAX_COMMIT_BODY: usize = 96 * 1024;

/// Domain tag for the commit digest (matches whitepaper §2.5 / spec §5
/// and `dsm/src/core/identity/genesis_mpc.rs`).
const COMMIT_DOMAIN: &str = "DSM/genesis-commit";

/// Domain tag for the offer-envelope signature preimage. MUST stay
/// in lock-step with
/// `dsm::core::identity::genesis_mpc::OFFER_SIG_DOMAIN`.
const OFFER_SIG_DOMAIN: &str = "DSM/genesis-mpc-offer";

/// Domain tag for the reveal-request signature preimage.
const REVEAL_SIG_DOMAIN: &str = "DSM/genesis-mpc-reveal";

/// SPHINCS+ SPX256f public-key length — used to shape-check the
/// initiator's `pk_attest` in the offer envelope. Storage nodes do
/// NOT sign; they verify device signatures (spec §1 + §2).
fn initiator_pk_attest_len() -> usize {
    sphincs::public_key_bytes(sphincs::SphincsVariant::SPX256f)
}

/// Recompute the canonical offer-envelope preimage (must match
/// `dsm::core::identity::genesis_mpc::compute_offer_sig_preimage`
/// byte-for-byte).
fn compute_offer_sig_preimage(
    session_id: &[u8; 32],
    initiator_device_id: &[u8; 32],
    initiator_cdbrw: &[u8; 32],
    participants: &[[u8; 32]],
    pk_attest: &[u8],
) -> [u8; 32] {
    let mut h = dsm::crypto::blake3::dsm_domain_hasher(OFFER_SIG_DOMAIN);
    h.update(session_id);
    h.update(initiator_device_id);
    h.update(initiator_cdbrw);
    h.update(&(participants.len() as u32).to_le_bytes());
    for p in participants {
        h.update(p);
    }
    h.update(&(pk_attest.len() as u32).to_le_bytes());
    h.update(pk_attest);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// Recompute the canonical reveal-request preimage (must match
/// `dsm::core::identity::genesis_mpc::compute_reveal_sig_preimage`
/// byte-for-byte).
fn compute_reveal_sig_preimage(session_id: &[u8; 32]) -> [u8; 32] {
    let mut h = dsm::crypto::blake3::dsm_domain_hasher(REVEAL_SIG_DOMAIN);
    h.update(session_id);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

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

    let session =
        pb::GenesisMpcSessionV1::decode(body.as_ref()).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Required field shape checks.
    if session.session_id.len() != 32
        || session.initiator_device_id.len() != 32
        || session.initiator_cdbrw.len() != 32
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    if session.initiator_pk_attest.len() != initiator_pk_attest_len() {
        return Err(StatusCode::BAD_REQUEST);
    }
    // Empty signature short-circuits — verification would always
    // reject, but bailing early avoids an unnecessary SPHINCS+ op.
    if session.initiator_signature.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Participant set validation.
    let participants = decode_participants(&session.participants)?;
    if participants.len() < MIN_PARTICIPANTS {
        return Err(StatusCode::BAD_REQUEST);
    }

    let self_id = *state.node_id.as_bytes();

    // Must be in the declared participant set.
    if !participants.iter().any(|p| p == &self_id) {
        return Err(StatusCode::FORBIDDEN);
    }

    // SPHINCS+-verify the offer envelope. Storage nodes verify, never
    // sign (spec §1 + §2). Per the adversarial-stage-6 fix, this
    // signature is the front-running defense against a
    // deterministically-derived `session_id`: an attacker who
    // pre-computes a victim's session_id still cannot produce a
    // valid signature without `sk_attest`.
    let session_id_arr: [u8; 32] = session
        .session_id
        .as_slice()
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let initiator_device_id_arr: [u8; 32] = session
        .initiator_device_id
        .as_slice()
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let initiator_cdbrw_arr: [u8; 32] = session
        .initiator_cdbrw
        .as_slice()
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let preimage = compute_offer_sig_preimage(
        &session_id_arr,
        &initiator_device_id_arr,
        &initiator_cdbrw_arr,
        &participants,
        &session.initiator_pk_attest,
    );
    match sphincs::sphincs_verify(
        &session.initiator_pk_attest,
        &preimage,
        &session.initiator_signature,
    ) {
        Ok(true) => {}
        _ => return Err(StatusCode::UNAUTHORIZED),
    }

    // Fresh, secret entropy for this node's contribution.
    let mut e_self = [0u8; 32];
    use rand::rngs::OsRng;
    use rand::RngCore;
    OsRng
        .try_fill_bytes(&mut e_self)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // commit_digest = H("DSM/genesis-commit\0" || session_id || entropy)
    //
    // Matches the canonical formula in
    // `dsm/src/core/identity/genesis_mpc.rs::compute_commitments` —
    // contributor_id is NOT in the hash input. The wire envelope
    // carries contributor_id separately so the orchestrator can label
    // and order commits during combine, but it never enters the hash.
    let mut input = Vec::with_capacity(32 + 32);
    input.extend_from_slice(&session.session_id);
    input.extend_from_slice(&e_self);
    let commit_digest = domain_hash_bytes(COMMIT_DOMAIN, &input);

    let now_cycle = state.current_tick.load(Ordering::SeqCst);

    // Persist session + own contribution. Insert-then-upsert under one
    // logical "accept" — if the session_id is already known we return
    // 409. The DB layer surfaces this as anyhow with a specific
    // "already exists" message.
    let row = db::GenesisMpcSessionRow {
        session_id: session.session_id.clone(),
        initiator_device_id: session.initiator_device_id.clone(),
        initiator_pk_attest: session.initiator_pk_attest.clone(),
        initiator_cdbrw: session.initiator_cdbrw.clone(),
        participants_blob: flatten_participants(&participants),
        initiator_signature: session.initiator_signature.clone(),
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
            own_entropy: Some(e_self.to_vec()),
            revealed_entropy: None,
        },
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let commit = pb::GenesisMpcCommitV1 {
        session_id: session.session_id,
        contributor_id: self_id.to_vec(),
        commit_digest: commit_digest.to_vec(),
    };
    Ok(proto_response(StatusCode::OK, &commit))
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

    let commit =
        pb::GenesisMpcCommitV1::decode(body.as_ref()).map_err(|_| StatusCode::BAD_REQUEST)?;
    if commit.session_id != session_id {
        return Err(StatusCode::BAD_REQUEST);
    }
    if commit.contributor_id.len() != 32 || commit.commit_digest.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let row = db::genesis_mpc_session_get(&state.db_pool, &session_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // No deadline check (spec §1 clockless). The session exists
    // until purged by operator policy on `created_at_cycle`.

    let participants =
        parse_participants_blob(&row.participants_blob).ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
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
            own_entropy: None,
            revealed_entropy: None,
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
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    if body.len() > MAX_COMMIT_BODY {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let session_id = decode_session_id_path(&session_id_b32)?;

    let req = pb::GenesisMpcRevealRequestV1::decode(body.as_ref())
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if req.session_id != session_id {
        return Err(StatusCode::BAD_REQUEST);
    }

    let session = db::genesis_mpc_session_get(&state.db_pool, &session_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Reveal request MUST carry the same `pk_attest` the session was
    // offered with — defeats key-substitution at reveal time.
    if req.initiator_pk_attest != session.initiator_pk_attest {
        return Err(StatusCode::UNAUTHORIZED);
    }
    // SPHINCS+-verify the reveal-request signature against the
    // canonical reveal preimage. Domain-separated from offer so an
    // /offer signature can't be replayed as a /reveal.
    let preimage = compute_reveal_sig_preimage(&session_id);
    match sphincs::sphincs_verify(
        &session.initiator_pk_attest,
        &preimage,
        &req.initiator_signature,
    ) {
        Ok(true) => {}
        _ => return Err(StatusCode::UNAUTHORIZED),
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
    if let Some(entropy) = own_row.revealed_entropy.as_ref() {
        let envelope = pb::GenesisMpcRevealV1 {
            session_id: session_id.to_vec(),
            contributor_id: self_id.to_vec(),
            entropy: entropy.clone(),
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

    // Persist reveal in our own row + advance session state. Re-upsert
    // preserves commit_digest/own_entropy via COALESCE in the DB helper.
    db::genesis_mpc_contribution_upsert(
        &state.db_pool,
        db::GenesisMpcContributionRow {
            session_id: session_id.to_vec(),
            contributor_id: self_id.to_vec(),
            commit_digest: own_row.commit_digest,
            own_entropy: Some(e_self.clone()),
            revealed_entropy: Some(e_self.clone()),
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
    let bytes =
        dsm_sdk::util::text_id::decode_base32_crockford(s).ok_or(StatusCode::BAD_REQUEST)?;
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
        let arr: [u8; 32] = entry
            .as_slice()
            .try_into()
            .map_err(|_| StatusCode::BAD_REQUEST)?;
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
    /// a participant set sorted ascending. Storage nodes are
    /// signature-free — no key material to load.
    async fn test_state_for_node(node_seed: &str) -> Arc<AppState> {
        let pool = db::create_pool(":memory:", true).expect("test pool");
        db::init_db(&pool).await.expect("init_db");
        let state = AppState::new(
            node_seed.to_string(),
            &format!("http://{}.test", node_seed),
            None,
            Arc::new(pool),
            test_replication_manager(),
        );
        Arc::new(state)
    }

    /// Build a properly-signed offer envelope and return its bytes
    /// plus the orchestrator's keypair so the test can also build
    /// a matching /reveal request body.
    fn make_signed_session_proto(
        session_id: &[u8; 32],
        participants: &[[u8; 32]],
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let initiator_device_id = [0x11u8; 32];
        let initiator_cdbrw = [0x22u8; 32];
        let (pk_attest, sk_attest) =
            sphincs::generate_sphincs_keypair().expect("test: sphincs keypair");

        let preimage = compute_offer_sig_preimage(
            session_id,
            &initiator_device_id,
            &initiator_cdbrw,
            participants,
            &pk_attest,
        );
        let initiator_signature =
            sphincs::sphincs_sign(&sk_attest, &preimage).expect("test: sphincs sign");

        let session = pb::GenesisMpcSessionV1 {
            session_id: session_id.to_vec(),
            initiator_device_id: initiator_device_id.to_vec(),
            initiator_pk_attest: pk_attest.clone(),
            initiator_cdbrw: initiator_cdbrw.to_vec(),
            participants: participants.iter().map(|p| p.to_vec()).collect(),
            initiator_signature,
        };
        (session.encode_to_vec(), pk_attest, sk_attest)
    }

    /// Build a signed /reveal request body for `session_id` using
    /// the same `sk_attest` the orchestrator used at /offer time.
    fn make_signed_reveal_body(
        session_id: &[u8; 32],
        pk_attest: &[u8],
        sk_attest: &[u8],
    ) -> Vec<u8> {
        let preimage = compute_reveal_sig_preimage(session_id);
        let sig = sphincs::sphincs_sign(sk_attest, &preimage).expect("test: sphincs sign reveal");
        let req = pb::GenesisMpcRevealRequestV1 {
            session_id: session_id.to_vec(),
            initiator_pk_attest: pk_attest.to_vec(),
            initiator_signature: sig,
        };
        req.encode_to_vec()
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
    async fn offer_accepted_returns_own_commit() {
        let state = test_state_for_node("offer-accepted").await;
        let participants = participants_including(&state, 3);
        let (body, _pk, _sk) = make_signed_session_proto(&[7u8; 32], &participants);

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
        let state = test_state_for_node("offer-not-in-set").await;
        // Participants set that deliberately excludes our self_id.
        let participants: Vec<[u8; 32]> = (0u8..3u8)
            .map(|i| {
                let mut id = [0u8; 32];
                id[0] = 0x10 + i;
                id
            })
            .collect();
        assert!(!participants.iter().any(|p| p == state.node_id.as_bytes()));
        let (body, _pk, _sk) = make_signed_session_proto(&[8u8; 32], &participants);

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
        let state = test_state_for_node("offer-dup").await;
        let participants = participants_including(&state, 3);
        let session_id = [42u8; 32];
        let (body, _pk, _sk) = make_signed_session_proto(&session_id, &participants);

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
        let state = test_state_for_node("offer-too-few").await;
        let participants = participants_including(&state, 2);
        let (body, _pk, _sk) = make_signed_session_proto(&[9u8; 32], &participants);

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
        let state = test_state_for_node("peer-commit").await;
        let participants = participants_including(&state, 3);
        let session_id = [21u8; 32];
        let (body, _pk, _sk) = make_signed_session_proto(&session_id, &participants);

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

        // Build a peer commit. Storage nodes do not sign — only
        // shape rules are enforced server-side.
        let peer_commit = pb::GenesisMpcCommitV1 {
            session_id: session_id.to_vec(),
            contributor_id: peer_id.to_vec(),
            commit_digest: vec![0x33u8; 32],
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
        let state = test_state_for_node("reveal-gated").await;
        let participants = participants_including(&state, 3);
        let session_id = [55u8; 32];
        let (body, pk_attest, sk_attest) = make_signed_session_proto(&session_id, &participants);

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
        let reveal_body = make_signed_reveal_body(&session_id, &pk_attest, &sk_attest);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&url)
                    .body(Body::from(reveal_body))
                    .expect("req"),
            )
            .await
            .expect("reveal");
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    }

    #[tokio::test]
    async fn reveal_succeeds_after_all_peer_commits_observed_and_is_idempotent() {
        let state = test_state_for_node("reveal-ok").await;
        let participants = participants_including(&state, 3);
        let session_id = [66u8; 32];
        let (body, pk_attest, sk_attest) = make_signed_session_proto(&session_id, &participants);

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
        let reveal_body = make_signed_reveal_body(&session_id, &pk_attest, &sk_attest);
        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&url)
                    .body(Body::from(reveal_body.clone()))
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
                    .body(Body::from(reveal_body))
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
    }

    #[tokio::test]
    async fn purge_removes_session_and_contributions_by_created_at() {
        let state = test_state_for_node("purge").await;
        let participants = participants_including(&state, 3);
        let session_id = [99u8; 32];
        let (body, _pk, _sk) = make_signed_session_proto(&session_id, &participants);

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

        // Admin-driven purge against created_at_cycle (operator policy,
        // not a protocol deadline). Cutoff larger than the row's
        // created_at_cycle (which is the node's current_tick at
        // offer time — 0 for a fresh in-memory test state).
        let purged = db::genesis_mpc_session_purge_expired(&state.db_pool, i64::MAX)
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

    /// Cross-check: the commit_digest this handler produces and stores
    /// MUST match what `dsm::crypto::blake3::domain_hash` produces for
    /// `domain="DSM/genesis-commit"`, body=`session_id || entropy`.
    ///
    /// This is the same formula
    /// `dsm/src/core/identity/genesis_mpc.rs::compute_commitments`
    /// uses to compute commitments — if the orchestrator's
    /// `verify_commitments` doesn't see the same input bytes, every
    /// MPC session will fail at combine time.
    #[tokio::test]
    async fn commit_digest_matches_core_genesis_commit_formula() {
        use dsm::crypto::blake3::domain_hash_bytes;

        let state = test_state_for_node("kat-commit").await;
        let participants = participants_including(&state, 3);
        let session_id = [0xC1u8; 32];
        let (body, _pk, _sk) = make_signed_session_proto(&session_id, &participants);

        let app = create_router(state.clone());
        let resp = app
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

        // Pull our own contribution row back out and recompute the
        // commit_digest from the secret entropy + session_id, using
        // the same domain tag the canonical core uses.
        let own =
            db::genesis_mpc_contribution_get(&state.db_pool, &session_id, state.node_id.as_bytes())
                .await
                .expect("get own")
                .expect("own row");
        let entropy = own.own_entropy.expect("own_entropy stored at /offer");
        assert_eq!(entropy.len(), 32);

        let mut input = Vec::with_capacity(64);
        input.extend_from_slice(&session_id);
        input.extend_from_slice(&entropy);
        let expected = domain_hash_bytes("DSM/genesis-commit", &input);
        assert_eq!(
            own.commit_digest.as_slice(),
            &expected,
            "handler's commit_digest must match \
             H(\"DSM/genesis-commit\\0\" || session_id || entropy) \
             — same as dsm/src/core/identity/genesis_mpc.rs"
        );
    }

    #[tokio::test]
    async fn get_session_404_when_unknown() {
        let state = test_state_for_node("get-404").await;
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
