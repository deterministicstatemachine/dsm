// SPDX-License-Identifier: MIT OR Apache-2.0

//! The node harness's own tests. They live beside `nodes.rs` rather than in
//! it: `crates/dsm-app-host`'s real-connection suite mounts `nodes.rs` by
//! `#[path]`, and these run once, here.

use super::nodes::NodeSet;

/// The server the nodes share grants every connection each node's pool may
/// hold, all at once, and no pool opens one past them. A pool that may open
/// more than its share asks the server for a connection it refuses ("too many
/// clients already"), and the node answers the request it was serving with a
/// 500: CI's Postgres admits 100, and five pools of `POOL_MAX_SIZE` asked it
/// for 160.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn the_shared_server_grants_every_connection_a_node_set_may_hold() {
    let set = NodeSet::start().await;
    let mut held = Vec::new();
    for node in &set.nodes {
        let may_hold = node.pool().status().max_size;
        for n in 1..=may_hold {
            match node.pool().get().await {
                Ok(client) => held.push(client),
                Err(e) => panic!(
                    "{}: connection {n} of the {may_hold} its pool may hold: {e}",
                    node.member_id
                ),
            }
        }
    }
    // Every connection is held: a pool that may open no more waits for one
    // to come back (`db::POOL_WAIT_TIMEOUT`), and is still waiting here.
    for node in &set.nodes {
        let next =
            tokio::time::timeout(std::time::Duration::from_millis(500), node.pool().get()).await;
        assert!(
            matches!(next, Err(..)),
            "{}: its pool opened a connection past the {} it may hold",
            node.member_id,
            node.pool().status().max_size
        );
    }
    let every: usize = set
        .nodes
        .iter()
        .map(|node| node.pool().status().max_size)
        .sum();
    assert_eq!(held.len(), every, "every connection is held at once");
}
