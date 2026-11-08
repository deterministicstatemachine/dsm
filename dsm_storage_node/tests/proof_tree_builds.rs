// SPDX-License-Identifier: Apache-2.0
//! What a ByteCommit proof costs the node (storage spec §14, proof). A proof
//! for a cell its cycle does not commit is answered from that cell's own row,
//! never from a read or build over the node's other cells; and a proof whose
//! cycle's tree is not kept builds it while it holds the node's one tree
//! build, so however many proofs ask, one tree over every cell is built at a
//! time. Each test holds that build the way another proof would.

mod common;

use std::sync::Arc;
use std::time::Duration;

use dsm_storage_node::db;
use prost::Message;

const NS: &[u8] = b"DSM/proof-tree-builds";
const MEMBER: &[u8] = b"dsm-node-proofs";

/// A store holding one cell at `key`, committed by cycle 1.
async fn one_committed_cell(store: &str, key: [u8; 32]) -> Arc<db::DBPool> {
    let pool = common::fresh_store(store).await;
    common::ok_or_panic(db::put_cell(&pool, NS, &key, b"held").await, "put");
    let closed = common::ok_or_panic(
        db::close_cycle(&pool, &db::CommittedCells::default(), MEMBER).await,
        "close",
    );
    let closed = common::some_or_panic(closed, "cycle 1 closes over the cell");
    assert_eq!(closed.cycle_index, 1);
    pool
}

async fn proof_bytes(
    pool: &db::DBPool,
    node: &db::CommittedCells,
    key: &[u8; 32],
) -> Option<Vec<u8>> {
    common::ok_or_panic(db::cell_commit_proof(pool, node, NS, key, 1).await, "proof")
        .map(|p| p.to_proto().encode_to_vec())
}

/// With another proof's tree build holding the node, a proof for a cell
/// cycle 1 does not commit is answered at once, and leaves no tree kept.
#[test]
fn a_proof_for_a_cell_the_cycle_does_not_commit_builds_no_tree() {
    common::runtime().block_on(async {
        let pool = one_committed_cell("pt_absent", [0x61; 32]).await;
        // A node that keeps no tree for cycle 1, as after a restart.
        let node = db::CommittedCells::default();
        let building = common::ok_or_panic(node.hold_tree_build().await, "the tree build");
        let answer = match tokio::time::timeout(
            Duration::from_secs(5),
            proof_bytes(&pool, &node, &[0x62; 32]),
        )
        .await
        {
            Ok(answer) => answer,
            Err(elapsed) => {
                panic!(
                    "a proof for an absent cell waited for another proof's tree build: {elapsed}"
                )
            }
        };
        assert_eq!(answer, None, "cycle 1 commits no such cell");
        drop(building);
        assert!(
            node.kept_cycles().is_empty(),
            "a proof for an absent cell built a tree"
        );
    });
}

/// With the node's tree build held elsewhere, a proof whose cycle's tree is
/// not kept waits; once it is let go, the proof is answered from the tree it
/// built, byte for byte the proof of a node that kept the tree when it
/// closed, and that tree is kept.
#[test]
fn trees_are_built_one_at_a_time() {
    common::runtime().block_on(async {
        let key = [0x63; 32];
        let pool = one_committed_cell("pt_one_at_a_time", key).await;
        let rebuilt_alone = proof_bytes(&pool, &db::CommittedCells::default(), &key).await;
        assert!(rebuilt_alone.is_some(), "cycle 1 commits the cell");

        let node = Arc::new(db::CommittedCells::default());
        let building = common::ok_or_panic(node.hold_tree_build().await, "the tree build");
        let waiting = {
            let (pool, node) = (pool.clone(), node.clone());
            tokio::spawn(async move { proof_bytes(&pool, &node, &key).await })
        };
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            !waiting.is_finished(),
            "a tree was built while another build held the node"
        );
        drop(building);
        let built = match tokio::time::timeout(Duration::from_secs(10), waiting).await {
            Ok(joined) => common::ok_or_panic(joined, "task"),
            Err(elapsed) => {
                panic!("the proof was never answered once the build was let go: {elapsed}")
            }
        };
        assert_eq!(built, rebuilt_alone, "the built tree's proof");
        assert_eq!(node.kept_cycles(), vec![1], "the built tree is kept");
    });
}

/// The proof route's answer for `key` at cycle 1: its status and body.
async fn route_proof(app: &axum::Router, key: &[u8; 32]) -> (axum::http::StatusCode, Vec<u8>) {
    let uri = format!(
        "/api/v2/bytecommit/proof/{}",
        dsm::utils::text_id::encode_base32_crockford(key)
    );
    let namespace = common::ok_or_panic(std::str::from_utf8(NS), "the namespace");
    common::call(
        app,
        "GET",
        &uri,
        &[("x-namespace", namespace), ("x-cycle", "1")],
        Vec::new(),
    )
    .await
}

/// Proofs at a cycle whose tree is not kept queue for the node's one build
/// only up to [`db::TREE_BUILDS_QUEUED`]: with one build held and the rest of
/// the queue waiting behind it, one more such proof on the served route is
/// answered `503` at once, holding nothing, instead of waiting with the
/// others. Once the build is let go, every queued proof is answered.
#[test]
fn proofs_past_the_queued_tree_builds_are_answered_busy_at_once() {
    common::runtime().block_on(async {
        let key = [0x64; 32];
        let pool = one_committed_cell("pt_queued", key).await;
        // A node that keeps no tree for cycle 1, as after a restart.
        let state = Arc::new(common::ok_or_panic(
            dsm_storage_node::AppState::new(
                String::from_utf8_lossy(MEMBER).into_owned(),
                pool,
                common::set_client(),
            ),
            "app state",
        ));
        let app = common::served(state.clone());
        let building =
            common::ok_or_panic(state.committed.hold_tree_build().await, "the tree build");
        let queued: Vec<_> = (1..db::TREE_BUILDS_QUEUED)
            .map(|_| {
                let app = app.clone();
                tokio::spawn(async move { route_proof(&app, &key).await })
            })
            .collect();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            queued.iter().all(|proof| !proof.is_finished()),
            "a queued proof was answered while the build was held"
        );

        match tokio::time::timeout(Duration::from_secs(2), route_proof(&app, &key)).await {
            Ok((status, _)) => assert_eq!(
                status,
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "a proof past the queue is answered busy"
            ),
            Err(elapsed) => panic!("a proof past the queue waited for the build: {elapsed}"),
        }

        drop(building);
        for proof in queued {
            let answered = match tokio::time::timeout(Duration::from_secs(10), proof).await {
                Ok(joined) => common::ok_or_panic(joined, "task"),
                Err(elapsed) => panic!("a queued proof was never answered: {elapsed}"),
            };
            assert_eq!(answered.0, axum::http::StatusCode::OK, "a queued proof");
        }
        assert_eq!(
            state.committed.kept_cycles(),
            vec![1],
            "the built tree is kept"
        );
    });
}
