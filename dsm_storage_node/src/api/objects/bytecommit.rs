// SPDX-License-Identifier: MIT OR Apache-2.0

//! ByteCommits (storage spec §14): this node's own chain, the proofs that it
//! commits a cell's entries, and its mirror of its set-mates' chains.
//!
//! - **Close.** A cycle closes when anyone asks and at least one cell entry
//!   has arrived since the last one. Nothing reads a clock: the cycle index
//!   is a counter, and a quiet node emits nothing. Closing stamps the new
//!   entries with the cycle, so a later proof for that cycle is exactly what
//!   the ByteCommit committed.
//! - **Proof.** For a cell and a cycle, the latest entry committed by then
//!   and its SMT inclusion proof. The proof is checked by the verifier
//!   against the root in a ByteCommit it got elsewhere (its own mirror read),
//!   so a node cannot vouch for itself.
//! - **Mirror.** A node mirrors a set-mate's ByteCommits only by fetching
//!   them from that set-mate at the endpoint its own configuration names for
//!   that member. There is no write path into the mirror: a third party's
//!   bytes never enter it. The node checks only that the answer names the
//!   member configured at that endpoint (the echoed id and the ByteCommit's
//!   member id are both that member); it does not check chain links or
//!   roots. Verifiers do. Every `/latest` answer is kept, so a member that
//!   serves a different ByteCommit for a cycle already mirrored shows as an
//!   equivocation.
//!
//! The node signs nothing and holds no key. ByteCommits are unsigned.

use axum::{
    body::Bytes,
    extract::{Extension, Path},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use prost::Message;
use std::sync::Arc;

use crate::api::cells::{digest32, namespace, octets};
use crate::db;
use crate::AppState;
use dsm::storage_cell::ByteCommit;
use dsm::utils::text_id;

const CYCLE_HEADER: &str = "x-cycle";
const ECHO_HEADER: &str = "x-dsm-node-id";
/// Upper bound on cycles fetched from one member in one sync, so one request
/// does bounded work; a later sync continues where this one stopped.
const MAX_SYNC_CYCLES: u64 = 1024;

pub fn create_router(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route("/api/v2/bytecommit/close", post(close))
        .route("/api/v2/bytecommit/latest", get(latest))
        .route("/api/v2/bytecommit/cycle/{cycle}", get(by_cycle))
        .route("/api/v2/bytecommit/proof/{key}", get(proof))
        .route("/api/v2/bytecommit/mirror/sync", post(mirror_sync))
        .route(
            "/api/v2/bytecommit/mirror/{member}/{cycle}",
            get(mirror_read),
        )
        .layer(Extension(state))
}

fn internal(context: &str) -> impl Fn(anyhow::Error) -> StatusCode + '_ {
    move |e| {
        log::error!("bytecommit {context}: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

/// `204` asserts this node has no ByteCommit yet; `200` carries the latest.
fn commit_or_absent(commit: Option<ByteCommit>) -> Response {
    match commit {
        Some(c) => octets(c.to_proto().encode_to_vec()),
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

/// Close the next cycle if anything arrived since the last; answer with the
/// latest ByteCommit either way.
async fn close(Extension(state): Extension<Arc<AppState>>) -> Result<Response, StatusCode> {
    let commit = db::close_cycle(&state.db_pool, state.configured_member_id.as_bytes())
        .await
        .map_err(internal("close"))?;
    Ok(commit_or_absent(commit))
}

async fn latest(Extension(state): Extension<Arc<AppState>>) -> Result<Response, StatusCode> {
    let commit = db::get_own_bytecommit(&state.db_pool, None)
        .await
        .map_err(internal("latest"))?;
    Ok(commit_or_absent(commit))
}

async fn by_cycle(
    Extension(state): Extension<Arc<AppState>>,
    Path(cycle): Path<u64>,
) -> Result<Response, StatusCode> {
    match db::get_own_bytecommit(&state.db_pool, Some(cycle))
        .await
        .map_err(internal("cycle"))?
    {
        Some(c) => Ok(octets(c.to_proto().encode_to_vec())),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// The proof that this node's ByteCommit for `x-cycle` commits the cell's
/// latest entry as of that cycle. `404` when the cycle does not exist or the
/// cell had nothing committed by then.
async fn proof(
    Extension(state): Extension<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let namespace = namespace(&headers)?;
    let cycle: u64 = headers
        .get(CYCLE_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let key: [u8; 32] = digest32(&key)?
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    match db::cell_commit_proof(&state.db_pool, &namespace, &key, cycle)
        .await
        .map_err(internal("proof"))?
    {
        Some(p) => Ok(octets(p.to_proto().encode_to_vec())),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// Every distinct ByteCommit this node mirrored for the member at the cycle,
/// as `ByteCommitsV4`. An empty list is an answer: nothing mirrored there.
async fn mirror_read(
    Extension(state): Extension<Arc<AppState>>,
    Path((member, cycle)): Path<(String, u64)>,
) -> Result<Response, StatusCode> {
    let member = text_id::decode_base32_crockford(member.trim())
        .filter(|m| !m.is_empty())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let commits = db::mirror_get(&state.db_pool, &member, cycle)
        .await
        .map_err(internal("mirror read"))?;
    let page = dsm::types::proto::ByteCommitsV4 {
        commits: commits.iter().map(ByteCommit::to_proto).collect(),
    };
    Ok(octets(page.encode_to_vec()))
}

/// Fetch every set-mate's new ByteCommits from the set-mate itself, at the
/// endpoint this node's own configuration names for it. Anyone may ask;
/// nothing the caller sends chooses a peer or supplies a byte. One sync runs
/// at a time, and set-mates are fetched concurrently.
///
/// `204 No Content` once every set-mate answered and what it holds is
/// mirrored. `409 Conflict` when this node is in no set, so has no set-mate
/// to mirror. `502 Bad Gateway` when any set-mate did not answer or answered
/// with something that is not its ByteCommit; what the others answered is
/// kept.
async fn mirror_sync(
    Extension(state): Extension<Arc<AppState>>,
    _body: Bytes,
) -> Result<Response, StatusCode> {
    let Some(set) = state.storage_set.clone() else {
        log::warn!("bytecommit mirror: this node is in no storage set");
        return Err(StatusCode::CONFLICT);
    };
    let _one_at_a_time = state.mirror_sync.lock().await;
    let own = state.configured_member_id.as_str();
    let client = &state.set_client;
    let syncs = set
        .member_endpoints()
        .filter(|(member, _)| *member != own)
        .map(|(member, endpoint)| {
            let state = &state;
            async move {
                sync_one(state, client, endpoint, member.as_bytes())
                    .await
                    .map_err(|e| log::warn!("bytecommit mirror: {member} at {endpoint}: {e}"))
            }
        });
    let outcomes = futures::future::join_all(syncs).await;
    if outcomes.iter().any(Result::is_err) {
        return Err(StatusCode::BAD_GATEWAY);
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Fetch `path` from `member`'s configured endpoint and return its
/// ByteCommit, but only if the answering node echoes `member` and the
/// ByteCommit names `member`. `Ok(None)` when the member has no ByteCommit yet.
async fn fetch_commit(
    client: &reqwest::Client,
    endpoint: &str,
    path: &str,
    member: &[u8],
) -> anyhow::Result<Option<ByteCommit>> {
    let resp = client
        .get(format!("{}{path}", endpoint.trim_end_matches('/')))
        .send()
        .await?;
    match resp.status().as_u16() {
        200 => {}
        204 => return Ok(None),
        s => anyhow::bail!("answered HTTP {s}"),
    }
    let echoed = resp
        .headers()
        .get(ECHO_HEADER)
        .map(|v| v.as_bytes().to_vec())
        .ok_or_else(|| anyhow::anyhow!("no identity echo"))?;
    if echoed != member {
        anyhow::bail!("the node at this endpoint is not the member configured there");
    }
    let body = resp.bytes().await?;
    let commit = dsm::types::proto::ByteCommitV4::decode(body.as_ref())
        .ok()
        .and_then(|p| ByteCommit::from_proto(&p))
        .ok_or_else(|| anyhow::anyhow!("not a ByteCommit"))?;
    if commit.member_id != member {
        anyhow::bail!("the ByteCommit names a member other than the one configured here");
    }
    Ok(Some(commit))
}

async fn sync_one(
    state: &AppState,
    client: &reqwest::Client,
    endpoint: &str,
    member: &[u8],
) -> anyhow::Result<u64> {
    let Some(latest) = fetch_commit(client, endpoint, "/api/v2/bytecommit/latest", member).await?
    else {
        return Ok(0);
    };
    let have = db::mirror_last_cycle(&state.db_pool, member).await?;
    let reach = have.saturating_add(MAX_SYNC_CYCLES);
    let mut added = 0u64;
    for t in have + 1..=latest.cycle_index.saturating_sub(1).min(reach) {
        let path = format!("/api/v2/bytecommit/cycle/{t}");
        let commit = fetch_commit(client, endpoint, &path, member)
            .await?
            .ok_or_else(|| anyhow::anyhow!("member has a latest ByteCommit but none at {t}"))?;
        if commit.cycle_index != t {
            anyhow::bail!(
                "member answered cycle {t} with cycle {}",
                commit.cycle_index
            );
        }
        added += u64::from(db::mirror_put(&state.db_pool, &commit).await?);
    }
    // `/latest` is kept whatever its cycle: at or below what is already
    // mirrored, a different ByteCommit is how a rewritten history shows.
    // Beyond this sync's reach it waits, so no cycle in between is skipped.
    if latest.cycle_index <= reach {
        added += u64::from(db::mirror_put(&state.db_pool, &latest).await?);
    }
    Ok(added)
}
