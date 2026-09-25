// SPDX-License-Identifier: MIT OR Apache-2.0
//! ByteCommits on the served assembly (storage spec §14): a node's own chain,
//! proofs that it commits a cell's entries, and a mirror filled only by
//! fetching from the set-mate itself — two real nodes over real HTTP.

#![allow(clippy::disallowed_methods)]

mod common;

use std::future::IntoFuture;
use std::sync::Arc;

use axum::{body::Body, http::Request, http::StatusCode, Router};
use dsm::storage_cell::{ArrivalRecord, ByteCommit, CellCommitProof};
use dsm::utils::text_id;
use dsm_storage_node::{
    db,
    replication::{ReplicationConfig, ReplicationManager},
    AppState, NodeStorageSet,
};
use prost::Message;
use tower::ServiceExt;

const NS: &str = "DSM/bytecommit-contract";

fn rm(id: &str, endpoint: &str) -> Arc<ReplicationManager> {
    Arc::new(
        ReplicationManager::new(
            ReplicationConfig {
                replication_factor: 3,
                gossip_interval_ticks: 100,
                failure_timeout_ticks: 300,
                gossip_fanout: 3,
                max_concurrent_jobs: 10,
            },
            id.to_string(),
            endpoint.to_string(),
            &common::set_ca_pem(),
            Vec::new(),
        )
        .expect("replication manager"),
    )
}

/// A node over `pool`, a member of `set`, knowing its set-mates only at the
/// `endpoints` its own configuration names.
fn node_state_on(
    pool: Arc<db::DBPool>,
    id: &str,
    endpoint: &str,
    set: &[&str],
    endpoints: &[(&str, &str)],
) -> Arc<AppState> {
    let state = AppState::new(id.to_string(), endpoint, None, pool, rm(id, endpoint));
    let members: Vec<(String, [u8; 32])> = set.iter().map(|m| (m.to_string(), [7u8; 32])).collect();
    let endpoints = endpoints
        .iter()
        .map(|(m, e)| (m.to_string(), e.to_string()))
        .collect();
    let set = NodeStorageSet::new(members, id, [7u8; 32])
        .expect("set")
        .with_endpoints(id, endpoints)
        .expect("endpoints");
    Arc::new(state.with_storage_set(set))
}

/// A node over a fresh store of its own, named `store`.
async fn node_state(
    store: &str,
    id: &str,
    endpoint: &str,
    set: &[&str],
    endpoints: &[(&str, &str)],
) -> Arc<AppState> {
    node_state_on(
        common::fresh_store(store).await,
        id,
        endpoint,
        set,
        endpoints,
    )
}

async fn listener() -> (tokio::net::TcpListener, String) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    (l, url)
}

async fn sync(app: &Router) -> u64 {
    let req = Request::post("/api/v2/bytecommit/mirror/sync")
        .body(Body::empty())
        .unwrap();
    let (s, n) = call(app, req).await;
    assert_eq!(s, StatusCode::OK);
    u64::from_be_bytes(n.try_into().unwrap())
}

async fn mirrored(app: &Router, member: &[u8], cycle: u64) -> Vec<ByteCommit> {
    let member = text_id::encode_base32_crockford(member);
    let req = Request::get(format!("/api/v2/bytecommit/mirror/{member}/{cycle}"))
        .body(Body::empty())
        .unwrap();
    let (s, body) = call(app, req).await;
    assert_eq!(s, StatusCode::OK);
    dsm::types::proto::ByteCommitsV4::decode(body.as_slice())
        .unwrap()
        .commits
        .iter()
        .map(|p| ByteCommit::from_proto(p).unwrap())
        .collect()
}

fn app(state: Arc<AppState>) -> Router {
    let id = state.configured_member_id.clone();
    dsm_storage_node::storage_contract_router(state)
        .layer(dsm_storage_node::node_identity_echo_layer(&id))
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, Vec<u8>) {
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body")
        .to_vec();
    (status, body)
}

async fn put(app: &Router, key: [u8; 32], v: &[u8]) -> ArrivalRecord {
    let req = Request::post(format!(
        "/api/v2/cell/{}",
        text_id::encode_base32_crockford(&key)
    ))
    .header("x-namespace", NS)
    .body(Body::from(v.to_vec()))
    .expect("request");
    let (s, b) = call(app, req).await;
    assert_eq!(s, StatusCode::OK);
    ArrivalRecord::from_proto(&dsm::types::proto::ArrivalRecordV1::decode(b.as_slice()).unwrap())
        .unwrap()
}

async fn values(app: &Router, key: [u8; 32]) -> Vec<Vec<u8>> {
    let req = Request::get(format!(
        "/api/v2/cell/{}",
        text_id::encode_base32_crockford(&key)
    ))
    .header("x-namespace", NS)
    .body(Body::empty())
    .expect("request");
    let (_, b) = call(app, req).await;
    dsm::types::proto::CellValuesV1::decode(b.as_slice())
        .unwrap()
        .values
}

async fn close(app: &Router) -> Option<ByteCommit> {
    let (s, b) = call(
        app,
        Request::post("/api/v2/bytecommit/close")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    match s {
        StatusCode::NO_CONTENT => None,
        StatusCode::OK => {
            ByteCommit::from_proto(&dsm::types::proto::ByteCommitV4::decode(b.as_slice()).unwrap())
        }
        other => panic!("close answered {other}"),
    }
}

async fn proof(app: &Router, key: [u8; 32], cycle: u64) -> Option<CellCommitProof> {
    let req = Request::get(format!(
        "/api/v2/bytecommit/proof/{}",
        text_id::encode_base32_crockford(&key)
    ))
    .header("x-namespace", NS)
    .header("x-cycle", cycle.to_string())
    .body(Body::empty())
    .unwrap();
    let (s, b) = call(app, req).await;
    if s == StatusCode::NOT_FOUND {
        return None;
    }
    assert_eq!(s, StatusCode::OK);
    CellCommitProof::from_proto(
        &dsm::types::proto::CellCommitProofV1::decode(b.as_slice()).unwrap(),
    )
}

/// A quiet node emits nothing; a cycle closes only over new entries; each
/// ByteCommit links to the one before; a record verifies against the first
/// ByteCommit that covers it, and not against one that closed before it.
#[tokio::test]
async fn cycles_close_over_new_entries_and_commit_their_records() {
    let a = app(node_state(
        "bc_close_a",
        "dsm-node-a",
        "http://a.local",
        &["dsm-node-a"],
        &[],
    )
    .await);
    assert_eq!(close(&a).await, None, "nothing held, nothing to commit");

    let key = [0x11; 32];
    let r1 = put(&a, key, b"first").await;
    let c1 = close(&a).await.expect("cycle 1");
    assert_eq!((c1.cycle_index, c1.parent_digest), (1, [0u8; 32]));
    assert_eq!(c1.member_id, b"dsm-node-a");
    assert_eq!(
        close(&a).await,
        Some(c1.clone()),
        "no new entry, no new cycle"
    );

    let r2 = put(&a, key, b"second").await;
    let c2 = close(&a).await.expect("cycle 2");
    assert!(c2.follows(&c1), "cycle 2 links to cycle 1");

    let held = values(&a, key).await;
    let p1 = proof(&a, key, 1).await.expect("proof at cycle 1");
    let p2 = proof(&a, key, 2).await.expect("proof at cycle 2");
    assert!(dsm::storage_cell::record_is_committed(&r1, &held, &c1, &p1));
    assert!(
        !dsm::storage_cell::record_is_committed(&r2, &held, &c1, &p1),
        "r2 arrived after cycle 1 closed"
    );
    assert!(dsm::storage_cell::record_is_committed(&r1, &held, &c2, &p2));
    assert!(dsm::storage_cell::record_is_committed(&r2, &held, &c2, &p2));
    assert!(
        proof(&a, [0x12; 32], 2).await.is_none(),
        "a cell with nothing committed has no proof"
    );
    assert!(
        proof(&a, key, 3).await.is_none(),
        "a cycle that never closed has no proof"
    );
}

/// The old open publish path is gone: nobody can post a ByteCommit to a node.
#[tokio::test]
async fn there_is_no_path_to_post_a_bytecommit() {
    let a = app(node_state(
        "bc_nopost_a",
        "dsm-node-a",
        "http://a.local",
        &["dsm-node-a"],
        &[],
    )
    .await);
    let (s, _) = call(
        &a,
        Request::post("/api/v2/bytecommit/publish")
            .body(Body::from(vec![1u8, 2, 3]))
            .unwrap(),
    )
    .await;
    assert!(
        s == StatusCode::NOT_FOUND || s == StatusCode::METHOD_NOT_ALLOWED,
        "got {s}"
    );
}

/// Two real nodes over HTTP. B mirrors A only by fetching from A at the
/// endpoint B's own configuration names for A; the mirrored ByteCommit is
/// byte-for-byte A's, and a verifier can check A's record using B's mirror
/// and A's proof.
#[tokio::test]
async fn a_set_mate_mirrors_by_fetching_from_the_member_itself() {
    let ((la, ua), (lb, ub)) = (listener().await, listener().await);
    let set = ["dsm-node-a", "dsm-node-b"];
    let sa = node_state(
        "bc_mirror_a",
        "dsm-node-a",
        &ua,
        &set,
        &[("dsm-node-b", &ub)],
    )
    .await;
    let sb = node_state(
        "bc_mirror_b",
        "dsm-node-b",
        &ub,
        &set,
        &[("dsm-node-a", &ua)],
    )
    .await;
    let (a, b) = (app(sa), app(sb));
    tokio::spawn(axum::serve(la, a.clone()).into_future());
    tokio::spawn(axum::serve(lb, b.clone()).into_future());

    let key = [0x21; 32];
    let rec = put(&a, key, b"at a").await;
    let c1 = close(&a).await.expect("A closes cycle 1");

    assert_eq!(sync(&b).await, 1, "one ByteCommit mirrored");
    let mirrored = mirrored(&b, b"dsm-node-a", 1).await;
    assert_eq!(mirrored, vec![c1.clone()], "B holds exactly A's ByteCommit");

    // The verifier's check: A's record, A's values, B's mirror of A, A's proof.
    let held = values(&a, key).await;
    let p = proof(&a, key, 1).await.unwrap();
    assert!(dsm::storage_cell::record_is_committed(
        &rec,
        &held,
        &mirrored[0],
        &p
    ));

    // A second sync with nothing new mirrors nothing.
    assert_eq!(sync(&b).await, 0);
}

/// A node answering at the endpoint B's configuration names for set-mate A,
/// but which is not A, fills no mirror: neither under A's id nor its own.
#[tokio::test]
async fn an_impostor_at_a_set_mates_endpoint_is_not_mirrored() {
    let ((lc, uc), (lb, ub)) = (listener().await, listener().await);
    let sc = node_state("bc_impostor_c", "dsm-node-c", &uc, &["dsm-node-c"], &[]).await;
    let sb = node_state(
        "bc_impostor_b",
        "dsm-node-b",
        &ub,
        &["dsm-node-a", "dsm-node-b"],
        &[("dsm-node-a", &uc)],
    )
    .await;
    let (c, b) = (app(sc), app(sb));
    tokio::spawn(axum::serve(lc, c.clone()).into_future());
    tokio::spawn(axum::serve(lb, b.clone()).into_future());

    put(&c, [0x31; 32], b"at c").await;
    close(&c).await.expect("C closes cycle 1");

    assert_eq!(sync(&b).await, 0, "nothing from the impostor is mirrored");
    assert!(mirrored(&b, b"dsm-node-a", 1).await.is_empty());
    assert!(mirrored(&b, b"dsm-node-c", 1).await.is_empty());
}

/// A member that later serves a different ByteCommit for a cycle already
/// mirrored (a rewritten history) shows as two ByteCommits at that cycle.
#[tokio::test]
async fn a_rewritten_cycle_is_kept_beside_the_first() {
    let ((la, ua), (la2, ua2)) = (listener().await, listener().await);
    let set = ["dsm-node-a", "dsm-node-b"];
    // A, and a rebuilt A: two stores answering as dsm-node-a.
    let a = app(node_state("bc_rewrite_a", "dsm-node-a", &ua, &["dsm-node-a"], &[]).await);
    let a2 = app(node_state("bc_rewrite_a2", "dsm-node-a", &ua2, &["dsm-node-a"], &[]).await);
    tokio::spawn(axum::serve(la, a.clone()).into_future());
    tokio::spawn(axum::serve(la2, a2.clone()).into_future());
    // B, then B again over the same store with its configuration pointing at
    // the rebuilt A.
    let b_db = common::fresh_store("bc_rewrite_b").await;
    let b = app(node_state_on(
        b_db.clone(),
        "dsm-node-b",
        "http://b.local",
        &set,
        &[("dsm-node-a", &ua)],
    ));
    let b2 = app(node_state_on(
        b_db,
        "dsm-node-b",
        "http://b.local",
        &set,
        &[("dsm-node-a", &ua2)],
    ));

    let key = [0x41; 32];
    put(&a, key, b"original").await;
    let c1 = close(&a).await.expect("A closes cycle 1");
    put(&a2, key, b"rewritten").await;
    let c1_rewritten = close(&a2).await.expect("rebuilt A closes cycle 1");
    assert_ne!(c1, c1_rewritten);

    assert_eq!(sync(&b).await, 1);
    assert_eq!(sync(&b2).await, 1, "the rewritten cycle 1 is new evidence");
    let held = mirrored(&b, b"dsm-node-a", 1).await;
    assert_eq!(held.len(), 2, "both ByteCommits for cycle 1 are kept");
    assert!(held.contains(&c1) && held.contains(&c1_rewritten));
}
