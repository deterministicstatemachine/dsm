// SPDX-License-Identifier: MIT OR Apache-2.0

//! Real storage nodes, in process, for SDK tests (owner, 2026-09-23: no fake
//! nodes).
//!
//! Each node is the storage node's own code: its SQLite backend on a temporary
//! file, its register incarnation established by its own database, its pinned
//! storage set checked against that incarnation at start-up, and exactly the
//! app the binary serves (`dsm_storage_node::build_app`), bound to a local
//! port. The SDK is pointed at them through its environment config, as it is
//! pointed at a deployed fleet. Nothing here answers for a node.

use std::sync::Arc;

use dsm_storage_node::{db, replication, AppLimits, AppState, NodeStorageSet};

/// The member names the SDK's pinned-set profile resolves (`dsm-node-1`…).
fn member_name(i: usize) -> String {
    format!("dsm-node-{}", i + 1)
}

/// One running node.
pub struct RealNode {
    pub member_id: String,
    pub endpoint: String,
    pub incarnation: [u8; 32],
    db_path: std::path::PathBuf,
    _db_dir: tempfile::TempDir,
    _serve: tokio::task::JoinHandle<()>,
}

impl RealNode {
    /// Every envelope this node holds in any spool, exactly as stored, read
    /// from the node's own database: what an operator of this node can see.
    pub fn spooled_envelopes(&self) -> Vec<Vec<u8>> {
        let conn = rusqlite::Connection::open_with_flags(
            &self.db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("open node db read-only");
        let mut stmt = conn
            .prepare("SELECT envelope FROM inbox_spool ORDER BY id")
            .expect("prepare");
        stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))
            .expect("query")
            .map(|r| r.expect("row"))
            .collect()
    }
}

/// A full set of real nodes, pinned to one another.
pub struct RealNodeSet {
    pub nodes: Vec<RealNode>,
}

impl RealNodeSet {
    /// Start `count` real nodes (five for a storage set) and point the SDK at
    /// them. Panics if any node cannot start: a test on a partial set would
    /// be testing something else.
    pub async fn start(count: usize) -> Self {
        // Phase 1: every node's database and its own register incarnation.
        // The set names each member with the incarnation its database holds,
        // so every database must exist before any set can be written.
        let mut prepared = Vec::with_capacity(count);
        for i in 0..count {
            let dir = tempfile::tempdir().expect("node db dir");
            let path = dir.path().join("node.db");
            let pool = db::create_pool(path.to_str().expect("utf-8 path"), false).expect("pool");
            db::init_db(&pool).await.expect("init node db");
            let incarnation = db::register_incarnation(&pool).await.expect("incarnation");
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
            prepared.push((member_name(i), dir, path, Arc::new(pool), incarnation, listener, endpoint));
        }
        let members: Vec<(String, [u8; 32])> =
            prepared.iter().map(|(m, _, _, _, inc, _, _)| (m.clone(), *inc)).collect();
        let endpoints: Vec<(String, String)> =
            prepared.iter().map(|(m, _, _, _, _, _, ep)| (m.clone(), ep.clone())).collect();

        // Phase 2: each node, with the set checked against its own register,
        // serving the binary's app.
        let mut nodes = Vec::with_capacity(count);
        for (member_id, dir, db_path, pool, incarnation, listener, endpoint) in prepared {
            let replication = Arc::new(
                replication::ReplicationManager::new_for_tests(
                    replication::default_production_config(),
                    member_id.clone(),
                    endpoint.clone(),
                )
                .expect("replication manager"),
            );
            let set = NodeStorageSet::new(members.clone(), &member_id, incarnation)
                .expect("set against own register")
                .with_endpoints(&member_id, endpoints.clone())
                .expect("set endpoints");
            let state = AppState::new(member_id.clone(), &endpoint, None, pool, replication)
                .with_register_incarnation(incarnation)
                .with_storage_set(set);
            let app = dsm_storage_node::build_app(
                Arc::new(state),
                &member_id,
                AppLimits {
                    body_limit_bytes: 4 * 1024 * 1024,
                    concurrency_limit: 256,
                    benchmark_mode: true,
                },
            );
            let serve = tokio::spawn(async move {
                axum::serve(listener, app).await.expect("serve node");
            });
            nodes.push(RealNode {
                member_id,
                endpoint,
                incarnation,
                db_path,
                _db_dir: dir,
                _serve: serve,
            });
        }
        let set = Self { nodes };
        set.point_sdk_here();
        set
    }

    /// Point the SDK's environment config at these nodes, with each node's
    /// real register incarnation.
    fn point_sdk_here(&self) {
        let cfg_path =
            std::env::temp_dir().join(format!("dsm_sdk_real_nodes_{}.toml", std::process::id()));
        let mut cfg = String::from(
            "protocol = \"http\"\nlan_ip = \"127.0.0.1\"\nallow_localhost = true\n\
             storage_node_mode = \"remote\"\nports = [8080]\n\
             bitcoin_network = \"signet\"\ndbtc_min_confirmations = 1\n",
        );
        for n in &self.nodes {
            cfg.push_str(&format!(
                "\n[[nodes]]\nname = \"{}\"\nendpoint = \"{}\"\nregister_incarnation = \"{}\"\n",
                n.member_id,
                n.endpoint,
                crate::util::text_id::encode_base32_crockford(&n.incarnation)
            ));
        }
        std::fs::write(&cfg_path, cfg).expect("write env config");
        crate::network::set_env_config_path(cfg_path.to_string_lossy().into_owned());
        // SAFETY: tests using real nodes are serialized; no other thread reads
        // the environment while it is set.
        unsafe {
            std::env::set_var("DSM_ENV_CONFIG_PATH", &cfg_path);
        }
    }

    pub fn endpoints(&self) -> Vec<String> {
        self.nodes.iter().map(|n| n.endpoint.clone()).collect()
    }
}
