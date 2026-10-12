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
use futures::StreamExt;
use prost::Message;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::api::cells::{digest32, namespace, octets};
use crate::db;
use crate::AppState;
use dsm::storage_cell::ByteCommit;
use dsm::utils::text_id;

const CYCLE_HEADER: &str = "x-cycle";
const ECHO_HEADER: &str = "x-dsm-node-id";
/// Upper bound on cycles fetched from one member in one sync, so one request
/// does bounded work; a later sync continues where this one stopped, since
/// every cycle is kept as it is fetched. At this bound one sync of a member
/// far behind is 128 fetches, well inside what a client waits for one
/// request (the SDK's member client waits 30 s).
const MAX_SYNC_CYCLES: u64 = 128;
/// Cycles of one member fetched at once in a sync. The fetches are reads of
/// a set-mate's own ByteCommits; what is kept, and in what order, does not
/// depend on how many are in flight.
const SYNC_FETCHES_IN_FLIGHT: usize = 16;
/// The most bytes a set-mate's answer can hold and still be a ByteCommit:
/// the largest `ByteCommitV4` encoding, field by field (tag, length,
/// value). An answer longer than this is not a ByteCommit, and is not read
/// past this point.
const MAX_BYTECOMMIT_ANSWER: usize = (1 + 2 + dsm::storage_cell::MAX_MEMBER_ID_LEN) // member id
    + (1 + 10) // cycle index
    + (1 + 1 + 32) // root
    + (1 + 10) // bytes used
    + (1 + 1 + 32); // parent digest

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
    let commit = db::close_cycle(
        &state.db_pool,
        &state.committed,
        state.configured_member_id.as_bytes(),
    )
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
    match db::cell_commit_proof(&state.db_pool, &state.committed, &namespace, &key, cycle)
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
/// nothing the caller sends chooses a peer or supplies a byte. Set-mates are
/// synced concurrently, each one sync at a time, and a caller is answered by
/// a sync of each set-mate that started after it asked ([`MirrorSyncs`]).
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
    let own = state.configured_member_id.as_str();
    let client = &state.set_client;
    let syncs = set
        .member_endpoints()
        .filter(|(member, _)| *member != own)
        .map(|(member, endpoint)| {
            let state = &state;
            async move {
                state
                    .mirror_syncs
                    .of(member)
                    .run(|| sync_one(state, client, endpoint, member.as_bytes()))
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
    let mut resp = client
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
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if body.len() + chunk.len() > MAX_BYTECOMMIT_ANSWER {
            anyhow::bail!(
                "answered more than {MAX_BYTECOMMIT_ANSWER} bytes, which no ByteCommit is"
            );
        }
        body.extend_from_slice(&chunk);
    }
    let commit = dsm::types::proto::ByteCommitV4::decode(body.as_slice())
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
    // Up to SYNC_FETCHES_IN_FLIGHT cycles are fetched at once, and each is
    // checked and kept in cycle order as it comes back, exactly as one
    // fetch after another: the first that fails ends the sync with every
    // cycle before it kept and none after it.
    let mut fetched =
        futures::stream::iter(have + 1..=latest.cycle_index.saturating_sub(1).min(reach))
            .map(|t| async move {
                let path = format!("/api/v2/bytecommit/cycle/{t}");
                (t, fetch_commit(client, endpoint, &path, member).await)
            })
            .buffered(SYNC_FETCHES_IN_FLIGHT);
    while let Some((t, answer)) = fetched.next().await {
        let commit = answer?
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

/// The mirror syncs of each set-mate: one at a time per set-mate, and shared
/// by the callers waiting for the same one.
///
/// Every reader asks for a sync after closing cycles, so syncs arrive in
/// bursts, and each used to queue a whole sync of its own. A caller is still
/// answered only by a sync that STARTED after it asked — one that started
/// earlier may not have seen the cycle it just closed — but every caller that
/// asked while one sync of a set-mate ran is answered by the same next sync.
#[derive(Default)]
pub struct MirrorSyncs {
    members: std::sync::Mutex<HashMap<String, Arc<MemberSync>>>,
}

impl MirrorSyncs {
    fn of(&self, member: &str) -> Arc<MemberSync> {
        // A panic while the map was held leaves whole entries only, each a
        // set-mate's sync state, consistent on its own.
        let mut members = match self.members.lock() {
            Ok(members) => members,
            Err(poisoned) => poisoned.into_inner(),
        };
        members.entry(member.to_string()).or_default().clone()
    }
}

/// One set-mate's syncs: how many callers have asked, and, held while a sync
/// runs, how many of them the last finished sync answers and its answer.
#[derive(Default)]
struct MemberSync {
    asked: AtomicU64,
    last: tokio::sync::Mutex<Option<(u64, Result<u64, String>)>>,
}

impl MemberSync {
    /// Answer this caller from a sync that started after it asked: the last
    /// finished one if it started late enough, else `sync` run now, which
    /// then answers every caller that asked before it started. A sync whose
    /// caller went away before it finished answers nobody.
    async fn run<F: std::future::Future<Output = anyhow::Result<u64>>>(
        &self,
        sync: impl FnOnce() -> F,
    ) -> Result<u64, String> {
        let ticket = self.asked.fetch_add(1, Ordering::SeqCst) + 1;
        let mut last = self.last.lock().await;
        if let Some((answers_through, answer)) = last.as_ref() {
            if *answers_through >= ticket {
                return answer.clone();
            }
        }
        let answers_through = self.asked.load(Ordering::SeqCst);
        let answer = sync().await.map_err(|e| e.to_string());
        *last = Some((answers_through, answer.clone()));
        answer
    }
}

#[cfg(test)]
mod tests {
    use super::MemberSync;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    /// A sync that waits for a permit from `gate`, then answers with its own
    /// number among `runs`.
    fn counted(
        runs: &Arc<AtomicU64>,
        gate: &Arc<Semaphore>,
    ) -> impl FnOnce() -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<u64>> + Send>>
    {
        let (runs, gate) = (runs.clone(), gate.clone());
        move || {
            Box::pin(async move {
                drop(gate.acquire().await?);
                Ok(runs.fetch_add(1, Ordering::SeqCst) + 1)
            })
        }
    }

    fn answered(answer: Result<Result<u64, String>, tokio::task::JoinError>) -> u64 {
        match answer {
            Ok(Ok(run)) => run,
            Ok(Err(e)) => panic!("the sync failed: {e}"),
            Err(e) => panic!("the caller's task: {e}"),
        }
    }

    /// Callers that ask while a sync runs are all answered by one next sync,
    /// which starts after every one of them asked; a caller that asks after
    /// that one finished gets a sync of its own. On one thread, so the first
    /// caller's sync has started before the others ask.
    #[test]
    fn callers_asking_during_a_sync_share_the_next_one() {
        match tokio::runtime::Builder::new_current_thread().build() {
            Ok(runtime) => runtime.block_on(callers_share_the_next_sync()),
            Err(e) => panic!("a runtime: {e}"),
        }
    }

    async fn callers_share_the_next_sync() {
        let member = Arc::new(MemberSync::default());
        let runs = Arc::new(AtomicU64::new(0));
        let gate = Arc::new(Semaphore::new(0));

        let first = {
            let (member, sync) = (member.clone(), counted(&runs, &gate));
            tokio::spawn(async move { member.run(sync).await })
        };
        let waiting: Vec<_> = (0..5)
            .map(|_| {
                let (member, sync) = (member.clone(), counted(&runs, &gate));
                tokio::spawn(async move { member.run(sync).await })
            })
            .collect();
        while member.asked.load(Ordering::SeqCst) < 6 {
            tokio::task::yield_now().await;
        }
        gate.add_permits(16);

        assert_eq!(answered(first.await), 1, "the first caller's own sync");
        for caller in waiting {
            assert_eq!(
                answered(caller.await),
                2,
                "every caller that asked during sync 1 is answered by sync 2"
            );
        }
        assert_eq!(runs.load(Ordering::SeqCst), 2, "six callers, two syncs");

        assert_eq!(
            member.run(counted(&runs, &gate)).await,
            Ok(3),
            "a caller asking after the last sync finished gets a new one"
        );
    }
}
