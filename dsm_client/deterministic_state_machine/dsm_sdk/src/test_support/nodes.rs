// SPDX-License-Identifier: MIT OR Apache-2.0

//! Storage nodes, in process, for SDK tests (owner, 2026-09-23: no fake nodes;
//! 2026-09-24: Postgres only).
//!
//! Each node is the storage node's own code on a Postgres database of its own
//! — the store the fleet runs — on the server `DSM_TEST_DATABASE_URL` names. A
//! test with no server named refuses rather than skips. The node's storage set
//! is checked at start-up against the register incarnation its database holds,
//! and it serves exactly the app the binary serves
//! (`dsm_storage_node::build_app`, with the deployed fleet's limits), bound to
//! a local port.
//!
//! The nodes are the network's pinned register members, one node each. A node
//! draws its incarnation when it first starts on an empty database; these
//! nodes start on a database that already holds the member's pinned
//! incarnation, as a node restored from its database does (owner,
//! 2026-09-24). Nothing else is put in a node's database, and nothing here
//! answers for a node.
//!
//! An outage is a node that stops serving ([`NodeSet::take_down`]): its
//! listener closes and its connections are shut, so a client meets exactly
//! what it meets when a deployed node goes away. [`NodeSet::bring_up`]
//! restarts the same node, on the same database and address. A node whose
//! spool storage fails while its cells still serve is
//! [`NodeSet::fail_spools`].
//!
//! Every node set uses the same database names, recreated at start, so node
//! sets run one at a time; the SDK suites run serially.
//!
//! This file names no SDK path, so the SDK's unit tests (`test_support`) and
//! its integration tests (by `#[path]`) run the same harness. Pointing the SDK
//! at the nodes is `economic_fixtures::point_sdk_at`.

use std::net::SocketAddr;
use std::sync::Arc;

use dsm_storage_node::{db, replication, AppLimits, AppState, NodeStorageSet};

/// The network whose pinned register the nodes are.
const NETWORK: &[u8] = b"dsm-testnet";

/// The deployed fleet's limits (`deploy/nodes/*/config/node.toml`).
fn deployed_limits() -> AppLimits {
    AppLimits {
        body_limit_bytes: 1_048_576,
        concurrency_limit: 256,
    }
}

/// The Postgres server the nodes' databases live on.
fn server_url() -> String {
    std::env::var("DSM_TEST_DATABASE_URL").expect(
        "DSM_TEST_DATABASE_URL must name a Postgres database: the SDK's tests run storage nodes \
         on the store the fleet runs, and skipping them would report a green board that never \
         executed it",
    )
}

/// `url` with its database path replaced by `database`.
fn with_database(url: &str, database: &str) -> String {
    let (head, query) = match url.split_once('?') {
        Some((head, query)) => (head, Some(query)),
        None => (url, None),
    };
    let slash = head.rfind('/').expect("the database URL names no database");
    match query {
        Some(query) => format!("{}/{database}?{query}", &head[..slash]),
        None => format!("{}/{database}", &head[..slash]),
    }
}

/// An empty database named `database` on the server, dropped (with any
/// connection an earlier node set left) and created.
async fn fresh_database(database: &str) -> db::DBPool {
    let server = server_url();
    let admin = db::create_pool(&server).expect("admin pool");
    let client = admin.get().await.expect("admin connection");
    client
        .batch_execute(&format!("DROP DATABASE IF EXISTS {database} WITH (FORCE)"))
        .await
        .expect("drop the node database");
    client
        .batch_execute(&format!("CREATE DATABASE {database}"))
        .await
        .expect("create the node database");
    db::create_pool(&with_database(&server, database)).expect("node pool")
}

/// Put the member's pinned incarnation in the node's register before the node
/// first establishes one, as a restored database holds it. A database that
/// already holds an incarnation refuses the insert.
async fn restore_incarnation(pool: &db::DBPool, incarnation: &[u8; 32]) {
    let client = pool.get().await.expect("node db connection");
    client
        .execute(
            "INSERT INTO register_incarnation (only_row, incarnation) VALUES (1, $1)",
            &[&incarnation.to_vec()],
        )
        .await
        .expect("restore the register incarnation");
}

/// A node's serving task and the signal that stops it.
struct Serving {
    stop: Arc<tokio::sync::Notify>,
    task: tokio::task::JoinHandle<()>,
}

/// Serve the binary's app for `state` on `listener` until stopped.
fn serve(listener: tokio::net::TcpListener, state: Arc<AppState>, member_id: &str) -> Serving {
    let app = dsm_storage_node::build_app(state, member_id, deployed_limits());
    let stop = Arc::new(tokio::sync::Notify::new());
    let signal = stop.clone();
    let task = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move { signal.notified().await })
            .await
            .expect("serve node");
    });
    Serving { stop, task }
}

/// One node.
pub struct Node {
    pub member_id: String,
    pub endpoint: String,
    pub incarnation: [u8; 32],
    address: SocketAddr,
    state: Arc<AppState>,
    serving: Option<Serving>,
}

/// One envelope a node holds in its spool, exactly as the node stored it:
/// the b0x address it was submitted under, its message id, and the sealed
/// bytes.
pub struct Spooled {
    pub address: String,
    pub message_id: String,
    pub envelope: Vec<u8>,
}

impl Node {
    /// Every envelope this node holds in its spool, in arrival order, read
    /// from the node's own database: what an operator of this node can see.
    pub async fn spool(&self) -> Vec<Spooled> {
        let client = self.state.db_pool.get().await.expect("node db connection");
        client
            .query(
                "SELECT device_id, message_id, envelope FROM inbox_spool ORDER BY id",
                &[],
            )
            .await
            .expect("query")
            .iter()
            .map(|row| Spooled {
                address: row.get(0),
                message_id: row.get(1),
                envelope: row.get(2),
            })
            .collect()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(serving) = self.serving.take() {
            serving.stop.notify_one();
        }
    }
}

/// The network's pinned register members, one node each.
pub struct NodeSet {
    pub nodes: Vec<Node>,
}

impl NodeSet {
    /// Start one node per pinned register member of the network. Panics if
    /// any node cannot start: a test on a partial set would be testing
    /// something else. Must run inside a Tokio runtime, which serves the
    /// nodes for as long as it runs.
    pub async fn start() -> Self {
        let pinned = dsm::economic::register::pinned_root_register_members(NETWORK)
            .expect("the beta network is pinned");
        let members: Vec<(String, [u8; 32])> = pinned
            .iter()
            .map(|(id, incarnation)| {
                (
                    String::from_utf8(id.to_vec()).expect("pinned member ids are UTF-8"),
                    *incarnation,
                )
            })
            .collect();

        // Phase 1: every node's database, holding its member's incarnation,
        // and its address. The set names every member's endpoint, so every
        // address must be bound before any node is configured.
        let mut prepared = Vec::with_capacity(members.len());
        for (index, (member_id, pinned_incarnation)) in members.iter().enumerate() {
            let pool = fresh_database(&format!("dsm_sdk_test_node_{index}")).await;
            db::init_db(&pool).await.expect("init node db");
            restore_incarnation(&pool, pinned_incarnation).await;
            let incarnation = db::register_incarnation(&pool).await.expect("incarnation");
            assert_eq!(
                &incarnation, pinned_incarnation,
                "node {member_id} serves the incarnation its database holds"
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let address = listener.local_addr().expect("addr");
            prepared.push(Prepared {
                member_id: member_id.clone(),
                pool: Arc::new(pool),
                incarnation,
                listener,
                address,
            });
        }
        let endpoints: Vec<(String, String)> = prepared
            .iter()
            .map(|p| (p.member_id.clone(), endpoint_of(&p.address)))
            .collect();

        // Phase 2: each node, with the set checked against its own register,
        // serving the binary's app.
        let mut nodes = Vec::with_capacity(prepared.len());
        for p in prepared {
            let endpoint = endpoint_of(&p.address);
            let replication = Arc::new(
                replication::ReplicationManager::new_for_tests(
                    replication::default_production_config(),
                    p.member_id.clone(),
                    endpoint.clone(),
                )
                .expect("replication manager"),
            );
            let set = NodeStorageSet::new(members.clone(), &p.member_id, p.incarnation)
                .expect("set against own register")
                .with_endpoints(&p.member_id, endpoints.clone())
                .expect("set endpoints");
            let state = Arc::new(
                AppState::new(p.member_id.clone(), &endpoint, None, p.pool, replication)
                    .with_register_incarnation(p.incarnation)
                    .with_storage_set(set),
            );
            let serving = serve(p.listener, state.clone(), &p.member_id);
            nodes.push(Node {
                member_id: p.member_id,
                endpoint,
                incarnation: p.incarnation,
                address: p.address,
                state,
                serving: Some(serving),
            });
        }
        Self { nodes }
    }

    /// Every node as `(member id, endpoint, register incarnation)`, in pin
    /// order: what a device's environment config states about its fleet.
    pub fn members(&self) -> Vec<(String, String, [u8; 32])> {
        self.nodes
            .iter()
            .map(|n| (n.member_id.clone(), n.endpoint.clone(), n.incarnation))
            .collect()
    }

    pub fn endpoints(&self) -> Vec<String> {
        self.nodes.iter().map(|n| n.endpoint.clone()).collect()
    }

    /// Stop serving on each named member: its listener closes and its
    /// connections are shut. Returns once every one has stopped.
    pub async fn take_down(&mut self, member_ids: &[String]) {
        for member_id in member_ids {
            let node = self.node_mut(member_id);
            let serving = node
                .serving
                .take()
                .unwrap_or_else(|| panic!("node {member_id} is already down"));
            serving.stop.notify_one();
            serving.task.await.expect("node task");
        }
    }

    /// Restart each named member: the same node on the same database and
    /// address.
    pub async fn bring_up(&mut self, member_ids: &[String]) {
        for member_id in member_ids {
            let node = self.node_mut(member_id);
            assert!(node.serving.is_none(), "node {member_id} is already up");
            let listener = tokio::net::TcpListener::bind(node.address)
                .await
                .expect("rebind node address");
            node.serving = Some(serve(listener, node.state.clone(), &node.member_id));
        }
    }

    /// Fail each named member's spool: its spool table is gone from its
    /// database, so every b0x submit to it and read from it fails while its
    /// cells still serve — a node whose spool storage failed.
    pub async fn fail_spools(&self, member_ids: &[String]) {
        for member_id in member_ids {
            self.spool_ddl(
                member_id,
                "ALTER TABLE inbox_spool RENAME TO inbox_spool_failed",
            )
            .await;
        }
    }

    /// Restore each named member's spool, with everything it held.
    pub async fn restore_spools(&self, member_ids: &[String]) {
        for member_id in member_ids {
            self.spool_ddl(
                member_id,
                "ALTER TABLE inbox_spool_failed RENAME TO inbox_spool",
            )
            .await;
        }
    }

    async fn spool_ddl(&self, member_id: &str, statement: &str) {
        let node = self
            .nodes
            .iter()
            .find(|n| n.member_id == member_id)
            .unwrap_or_else(|| panic!("no node for member {member_id}"));
        node.state
            .db_pool
            .get()
            .await
            .expect("node db connection")
            .batch_execute(statement)
            .await
            .unwrap_or_else(|e| panic!("{member_id}: {statement}: {e}"));
    }

    fn node_mut(&mut self, member_id: &str) -> &mut Node {
        self.nodes
            .iter_mut()
            .find(|n| n.member_id == member_id)
            .unwrap_or_else(|| panic!("no node for member {member_id}"))
    }
}

/// A node between its database and its app.
struct Prepared {
    member_id: String,
    pool: Arc<db::DBPool>,
    incarnation: [u8; 32],
    listener: tokio::net::TcpListener,
    address: SocketAddr,
}

fn endpoint_of(address: &SocketAddr) -> String {
    format!("http://{address}")
}
