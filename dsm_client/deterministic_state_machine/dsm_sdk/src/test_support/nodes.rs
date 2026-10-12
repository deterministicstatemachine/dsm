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
//! a local port over TLS, as the binary serves it. Each node set has a CA of
//! its own, and each node a certificate from it naming its member and the
//! loopback address it is served at, as the fleet's certificates name their
//! member and IP (`dsm_storage_node/deploy/generate_node_configs.sh`). A
//! device trusts that CA and nothing else ([`NodeSet::ca_pem`]).
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
//! A deployed node has a Postgres server of its own; these nodes share one.
//! Each node's pool holds at most its share of the connections that server
//! admits ([`pool_share`]), so no node is refused a connection the deployed
//! node would have been granted.
//!
//! This file names no SDK path, so the SDK's unit tests (`test_support`) and
//! its integration tests (by `#[path]`) run the same harness. Pointing the SDK
//! at the nodes is `economic_fixtures::point_sdk_at`.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use dsm_storage_node::{db, set_client, AppLimits, AppState, NodeStorageSet};

/// The network whose pinned register the nodes are.
const NETWORK: &[u8] = b"dsm-testnet";

/// The deployed fleet's limits (`dsm_storage_node/config/production.toml`).
fn deployed_limits() -> AppLimits {
    AppLimits {
        body_limit_bytes: 1_048_576,
        concurrency_limit: 256,
        request_timeout: std::time::Duration::from_secs(60),
        wait_bound: dsm_storage_node::api::transport::b0x::MAX_WAIT,
    }
}

/// The Postgres server the nodes' databases live on.
fn server_url() -> String {
    match std::env::var("DSM_TEST_DATABASE_URL") {
        Ok(url) => url,
        Err(e) => panic!(
            "DSM_TEST_DATABASE_URL must name a Postgres database: the SDK's tests run storage \
             nodes on the store the fleet runs, and skipping them would report a green board \
             that never executed it ({e})"
        ),
    }
}

/// `url` with its database path replaced by `database`.
fn with_database(url: &str, database: &str) -> String {
    let (head, query) = match url.split_once('?') {
        Some((head, query)) => (head, Some(query)),
        None => (url, None),
    };
    let Some(slash) = head.rfind('/') else {
        panic!("the database URL names no database");
    };
    match query {
        Some(query) => format!("{}/{database}?{query}", &head[..slash]),
        None => format!("{}/{database}", &head[..slash]),
    }
}

/// The database of node `index`: the one `DSM_TEST_DATABASE_URL` names,
/// suffixed. Each node's database is dropped and created when a set boots,
/// so a fixed name let two test runs on one server (two worktrees, two
/// sessions) drop each other's nodes mid-test; runs whose URLs name
/// different databases now never share a node database.
fn node_database(index: usize) -> String {
    let server = server_url();
    let head = match server.split_once('?') {
        Some((head, _)) => head,
        None => server.as_str(),
    };
    let Some(slash) = head.rfind('/') else {
        panic!("the database URL names no database");
    };
    let base = &head[slash + 1..];
    assert!(
        !base.is_empty()
            && base
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
        "the database DSM_TEST_DATABASE_URL names ({base:?}) is not a lowercase SQL identifier, \
         and every node's database is named after it"
    );
    format!("{base}_node_{index}")
}

/// An empty database named `database` on the server, dropped (with any
/// connection an earlier node set left) and created, and a pool of at most
/// `connections` on it.
async fn fresh_database(database: &str, connections: usize) -> db::DBPool {
    let server = server_url();
    let admin = match db::create_pool(&server, 1) {
        Ok(pool) => pool,
        Err(e) => panic!("admin pool: {e}"),
    };
    let client = match admin.get().await {
        Ok(client) => client,
        Err(e) => panic!("admin connection: {e}"),
    };
    if let Err(e) = client
        .batch_execute(&format!("DROP DATABASE IF EXISTS {database} WITH (FORCE)"))
        .await
    {
        panic!("drop the node database: {e}");
    }
    if let Err(e) = client
        .batch_execute(&format!("CREATE DATABASE {database}"))
        .await
    {
        panic!("create the node database: {e}");
    }
    match db::create_pool(&with_database(&server, database), connections) {
        Ok(pool) => pool,
        Err(e) => panic!("node pool: {e}"),
    }
}

/// The connections each node's pool may hold, when the nodes run on the
/// databases `databases` names.
///
/// A deployed node runs on a Postgres server of its own (the sibling
/// container in `dsm_storage_node/deploy/docker-compose.node.yml`), which
/// grants every connection its pool asks for: `db::POOL_MAX_SIZE`. Here every
/// node of a set runs on the one server `DSM_TEST_DATABASE_URL` names, and
/// five pools of `POOL_MAX_SIZE` ask it for more than it admits — CI's
/// Postgres admits 100. Past its limit the server refuses the connection, the
/// node answers the request it was serving with a 500, and a reader then holds
/// less evidence than the cell does: a claim final at every seat reads as not
/// final yet. Each node takes an equal share of what the server admits beyond
/// the connections other clients hold, and never more than a deployed node's
/// pool.
async fn pool_share(databases: &[String]) -> usize {
    let admin = match db::create_pool(&server_url(), 1) {
        Ok(pool) => pool,
        Err(e) => panic!("admin pool: {e}"),
    };
    let client = match admin.get().await {
        Ok(client) => client,
        Err(e) => panic!("admin connection: {e}"),
    };
    let row = match client
        .query_one(
            "SELECT current_setting('max_connections')::bigint
                  - (SELECT COALESCE(SUM(setting::bigint), 0)::bigint FROM pg_settings
                      WHERE name IN ('superuser_reserved_connections', 'reserved_connections'))
                  - (SELECT count(*) FROM pg_stat_activity
                      WHERE backend_type = 'client backend'
                        AND NOT datname::text = ANY($1::text[]))",
            &[&databases],
        )
        .await
    {
        Ok(row) => row,
        Err(e) => panic!("the connections the server admits: {e}"),
    };
    let admits: i64 = row.get(0);
    let share = match usize::try_from(admits) {
        Ok(admits) => admits / databases.len(),
        Err(e) => panic!("the server admits {admits} more connections: {e}"),
    };
    assert!(
        share > 0,
        "the server admits {admits} more connections: not one for each of {} nodes",
        databases.len()
    );
    share.min(db::POOL_MAX_SIZE)
}

/// Put the member's pinned incarnation in the node's register before the node
/// first establishes one, as a restored database holds it. A database that
/// already holds an incarnation refuses the insert.
async fn restore_incarnation(pool: &db::DBPool, incarnation: &[u8; 32]) {
    let client = match pool.get().await {
        Ok(client) => client,
        Err(e) => panic!("node db connection: {e}"),
    };
    if let Err(e) = client
        .execute(
            "INSERT INTO register_incarnation (only_row, incarnation) VALUES (1, $1)",
            &[&incarnation.to_vec()],
        )
        .await
    {
        panic!("restore the register incarnation: {e}");
    }
}

/// A node's serving task and the signal that stops it.
struct Serving {
    handle: axum_server::Handle<SocketAddr>,
    task: tokio::task::JoinHandle<()>,
}

/// A node set's CA: it issues every node's certificate, every set-mate is
/// pinned to it, and a device trusts it and nothing else.
struct TestCa {
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    pem: Vec<u8>,
}

impl TestCa {
    fn new() -> Self {
        let key = match rcgen::KeyPair::generate() {
            Ok(key) => key,
            Err(e) => panic!("the CA's key: {e}"),
        };
        let mut params = match rcgen::CertificateParams::new(Vec::<String>::new()) {
            Ok(params) => params,
            Err(e) => panic!("the CA's parameters: {e}"),
        };
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "DSM-Storage-CA (test node set)");
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let pem = match params.self_signed(&key) {
            Ok(cert) => cert.pem(),
            Err(e) => panic!("the CA's certificate: {e}"),
        };
        Self {
            issuer: rcgen::Issuer::new(params, key),
            pem: pem.into_bytes(),
        }
    }

    /// The TLS a node serves `member_id` with: a certificate from this CA
    /// naming the member, as a DNS name, and the loopback address.
    async fn tls_for(&self, member_id: &str) -> axum_server::tls_rustls::RustlsConfig {
        let key = match rcgen::KeyPair::generate() {
            Ok(key) => key,
            Err(e) => panic!("the node's key: {e}"),
        };
        let mut params = match rcgen::CertificateParams::new(vec![
            member_id.to_string(),
            "127.0.0.1".to_string(),
        ]) {
            Ok(params) => params,
            Err(e) => panic!("the node's parameters: {e}"),
        };
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, member_id);
        let cert = match params.signed_by(&key, &self.issuer) {
            Ok(cert) => cert,
            Err(e) => panic!("the node's certificate: {e}"),
        };
        match axum_server::tls_rustls::RustlsConfig::from_pem(
            cert.pem().into_bytes(),
            key.serialize_pem().into_bytes(),
        )
        .await
        {
            Ok(tls) => tls,
            Err(e) => panic!("the node's TLS: {e}"),
        }
    }
}

/// Serve the binary's app for `state` on `listener` until stopped. Every
/// request the app is handed is recorded in `requests` first, as the method
/// and the path: what an operator of this node can see the node was asked.
fn serve(
    listener: tokio::net::TcpListener,
    tls: axum_server::tls_rustls::RustlsConfig,
    state: Arc<AppState>,
    requests: Arc<Mutex<Vec<String>>>,
) -> Serving {
    let app =
        dsm_storage_node::build_app(state, deployed_limits()).layer(axum::middleware::from_fn(
            move |request: axum::extract::Request, next: axum::middleware::Next| {
                let requests = requests.clone();
                async move {
                    match requests.lock() {
                        Ok(mut log) => {
                            log.push(format!("{} {}", request.method(), request.uri().path()))
                        }
                        Err(e) => panic!("request log: {e}"),
                    }
                    next.run(request).await
                }
            },
        ));
    let handle = axum_server::Handle::new();
    let listener = match listener.into_std() {
        Ok(listener) => listener,
        Err(e) => panic!("the node's listener: {e}"),
    };
    let server = match axum_server::from_tcp_rustls(listener, tls) {
        Ok(server) => server.handle(handle.clone()),
        Err(e) => panic!("the node's TLS server: {e}"),
    };
    let task = tokio::spawn(async move {
        if let Err(e) = server.serve(app.into_make_service()).await {
            panic!("serve node: {e}");
        }
    });
    Serving { handle, task }
}

/// One node.
pub struct Node {
    pub member_id: String,
    pub endpoint: String,
    pub incarnation: [u8; 32],
    address: SocketAddr,
    tls: axum_server::tls_rustls::RustlsConfig,
    state: Arc<AppState>,
    serving: Option<Serving>,
    requests: Arc<Mutex<Vec<String>>>,
}

/// One entry a node holds in its spool, exactly as the node stored it: the
/// b0x address it was submitted under and the bytes. The node never opens
/// them; `message_id` is what a reader decodes from them, when they are an
/// envelope.
pub struct Spooled {
    pub address: String,
    pub message_id: Option<String>,
    pub envelope: Vec<u8>,
}

impl Node {
    /// The pool the node draws its database connections from.
    pub fn pool(&self) -> &db::DBPool {
        &self.state.db_pool
    }

    /// Every request this node was asked since it started or was last told
    /// to forget them, in arrival order, as `METHOD /path`.
    pub fn requests(&self) -> Vec<String> {
        match self.requests.lock() {
            Ok(log) => log.clone(),
            Err(e) => panic!("request log: {e}"),
        }
    }

    /// Forget the requests recorded so far.
    pub fn forget_requests(&self) {
        match self.requests.lock() {
            Ok(mut log) => log.clear(),
            Err(e) => panic!("request log: {e}"),
        }
    }

    /// Every envelope this node holds in its spool, in arrival order, read
    /// from the node's own database: what an operator of this node can see.
    pub async fn spool(&self) -> Vec<Spooled> {
        let client = match self.state.db_pool.get().await {
            Ok(client) => client,
            Err(e) => panic!("node db connection: {e}"),
        };
        let rows = match client
            .query(
                "SELECT device_id, envelope FROM inbox_spool ORDER BY id",
                &[],
            )
            .await
        {
            Ok(rows) => rows,
            Err(e) => panic!("the spool: {e}"),
        };
        rows.iter()
            .map(|row| {
                let envelope: Vec<u8> = row.get(1);
                Spooled {
                    address: row.get(0),
                    message_id: dsm::envelope::from_canonical_bytes(&envelope)
                        .ok()
                        .map(|e| dsm::utils::text_id::encode_base32_crockford(&e.message_id)),
                    envelope,
                }
            })
            .collect()
    }
}

impl Node {
    /// Every row of every table in this node's own database, each as the
    /// text Postgres renders it (`row_to_json`: byte columns as `\\x` and
    /// lowercase hex): everything an operator of this node can read.
    pub async fn stored_rows(&self) -> Vec<String> {
        let client = match self.state.db_pool.get().await {
            Ok(client) => client,
            Err(e) => panic!("node db connection: {e}"),
        };
        let listed = match client
            .query(
                "SELECT table_name::text FROM information_schema.tables
                 WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'",
                &[],
            )
            .await
        {
            Ok(listed) => listed,
            Err(e) => panic!("the node's tables: {e}"),
        };
        let tables: Vec<String> = listed.iter().map(|row| row.get(0)).collect();
        assert!(!tables.is_empty(), "{} holds no tables", self.member_id);
        let mut rows = Vec::new();
        for table in tables {
            let held = match client
                .query(
                    &format!("SELECT row_to_json(t)::text FROM \"{table}\" t"),
                    &[],
                )
                .await
            {
                Ok(held) => held,
                Err(e) => panic!("the table's rows: {e}"),
            };
            for row in held {
                rows.push(format!("{table}: {}", row.get::<_, String>(0)));
            }
        }
        rows
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(serving) = self.serving.take() {
            serving.handle.shutdown();
        }
    }
}

/// The network's pinned register members, one node each.
pub struct NodeSet {
    pub nodes: Vec<Node>,
    ca: TestCa,
}

/// The process's rustls provider, installed as the node binary's `main`
/// installs it before its Postgres pool connects: nodes served in-process have
/// no `main`, so without this a test's nodes start only if some earlier test
/// in the process happened to install one.
fn tls_provider_installed() {
    use rustls::crypto::{ring, CryptoProvider};
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        if CryptoProvider::get_default().is_none() {
            if let Err(e) = CryptoProvider::install_default(ring::default_provider()) {
                // Refused only because another install won the race.
                assert!(
                    CryptoProvider::get_default().is_some(),
                    "no rustls provider is installed: {e:?}"
                );
            }
        }
    });
}

impl NodeSet {
    /// Start one node per pinned register member of the network. Panics if
    /// any node cannot start: a test on a partial set would be testing
    /// something else. Must run inside a Tokio runtime, which serves the
    /// nodes for as long as it runs.
    pub async fn start() -> Self {
        tls_provider_installed();
        let pinned = match dsm::economic::register::pinned_root_register_members(NETWORK) {
            Ok(pinned) => pinned,
            Err(e) => panic!("the beta network is pinned: {e}"),
        };
        let members: Vec<(String, [u8; 32])> = pinned
            .iter()
            .map(|(id, incarnation)| match String::from_utf8(id.to_vec()) {
                Ok(id) => (id, *incarnation),
                Err(e) => panic!("pinned member ids are UTF-8: {e}"),
            })
            .collect();

        // Phase 1: every node's database, holding its member's incarnation,
        // its pool within its share of the server, and its address. The set
        // names every member's endpoint, so every address must be bound
        // before any node is configured.
        let databases: Vec<String> = (0..members.len()).map(node_database).collect();
        let share = pool_share(&databases).await;
        let mut prepared = Vec::with_capacity(members.len());
        for ((member_id, pinned_incarnation), database) in members.iter().zip(&databases) {
            let pool = fresh_database(database, share).await;
            if let Err(e) = db::init_db(&pool).await {
                panic!("init node db: {e}");
            }
            restore_incarnation(&pool, pinned_incarnation).await;
            let incarnation = match db::register_incarnation(&pool).await {
                Ok(incarnation) => incarnation,
                Err(e) => panic!("incarnation: {e}"),
            };
            assert_eq!(
                &incarnation, pinned_incarnation,
                "node {member_id} serves the incarnation its database holds"
            );
            let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
                Ok(listener) => listener,
                Err(e) => panic!("bind: {e}"),
            };
            let address = match listener.local_addr() {
                Ok(address) => address,
                Err(e) => panic!("addr: {e}"),
            };
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

        // The set's CA: it issues every node's certificate, and every member
        // pins its peers to it.
        let ca = TestCa::new();

        // Phase 2: each node, with the set checked against its own register,
        // serving the binary's app.
        let mut nodes = Vec::with_capacity(prepared.len());
        for p in prepared {
            let endpoint = endpoint_of(&p.address);
            let own = match NodeStorageSet::new(members.clone(), &p.member_id, p.incarnation) {
                Ok(own) => own,
                Err(e) => panic!("set against own register: {e}"),
            };
            let set = match own.with_endpoints(&p.member_id, endpoints.clone()) {
                Ok(set) => set,
                Err(e) => panic!("set endpoints: {e}"),
            };
            let peers = match set_client::pinned_set_client(&ca.pem) {
                Ok(peers) => peers,
                Err(e) => panic!("pinned set client: {e}"),
            };
            let state = match AppState::new(p.member_id.clone(), p.pool, peers) {
                Ok(state) => Arc::new(state.with_storage_set(set)),
                Err(e) => panic!("app state: {e}"),
            };
            let requests = Arc::new(Mutex::new(Vec::new()));
            let tls = ca.tls_for(&p.member_id).await;
            let serving = serve(p.listener, tls.clone(), state.clone(), requests.clone());
            nodes.push(Node {
                member_id: p.member_id,
                endpoint,
                incarnation: p.incarnation,
                address: p.address,
                tls,
                state,
                serving: Some(serving),
                requests,
            });
        }
        Self { nodes, ca }
    }

    /// The TLS a member serves, from this node set's CA: a certificate naming
    /// `member_id` and the loopback address. For a test that stands a member
    /// up at another address, as an operator moving its node would: a device
    /// that reaches it there knows it by this certificate, as it knows the
    /// node.
    pub async fn tls_for(&self, member_id: &str) -> axum_server::tls_rustls::RustlsConfig {
        self.ca.tls_for(member_id).await
    }

    /// The PEM of this node set's CA: what a device's env config names in
    /// `custom_ca_certs` to reach these nodes, as the bundled config names the
    /// fleet's.
    pub fn ca_pem(&self) -> &[u8] {
        &self.ca.pem
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
            serving.handle.shutdown();
            if let Err(e) = serving.task.await {
                panic!("node task: {e}");
            }
        }
    }

    /// Restart each named member: the same node on the same database and
    /// address.
    pub async fn bring_up(&mut self, member_ids: &[String]) {
        for member_id in member_ids {
            let node = self.node_mut(member_id);
            assert!(node.serving.is_none(), "node {member_id} is already up");
            let listener = match tokio::net::TcpListener::bind(node.address).await {
                Ok(listener) => listener,
                Err(e) => panic!("rebind node address: {e}"),
            };
            node.serving = Some(serve(
                listener,
                node.tls.clone(),
                node.state.clone(),
                node.requests.clone(),
            ));
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
        self.ddl(member_id, statement).await;
    }

    /// Refuse every write of `keys` at member `member_id`: the member's store
    /// raises on the insert, so the put fails whole (§6) and the member
    /// answers an error — a member whose storage failed the write. Every
    /// read, and every other write, serves as before.
    pub async fn refuse_cell_writes(&self, member_id: &str, keys: &[[u8; 32]]) {
        self.ddl(
            member_id,
            "CREATE TABLE IF NOT EXISTS refused_cell_key (cell_key BYTEA PRIMARY KEY);
             CREATE OR REPLACE FUNCTION refuse_cell_write() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN
                 IF EXISTS (SELECT 1 FROM refused_cell_key WHERE cell_key = NEW.cell_key) THEN
                     RAISE EXCEPTION 'the store refused the write';
                 END IF;
                 RETURN NEW;
             END $$;
             DROP TRIGGER IF EXISTS refuse_cell_write ON cells;
             CREATE TRIGGER refuse_cell_write BEFORE INSERT ON cells
                 FOR EACH ROW EXECUTE FUNCTION refuse_cell_write();",
        )
        .await;
        let client = match self.node(member_id).state.db_pool.get().await {
            Ok(client) => client,
            Err(e) => panic!("node db connection: {e}"),
        };
        for key in keys {
            client
                .execute(
                    "INSERT INTO refused_cell_key (cell_key) VALUES ($1) ON CONFLICT DO NOTHING",
                    &[&key.to_vec()],
                )
                .await
                .unwrap_or_else(|e| panic!("{member_id}: refuse a cell key: {e}"));
        }
    }

    /// The member's store takes every write again.
    pub async fn accept_cell_writes(&self, member_id: &str) {
        self.ddl(
            member_id,
            "DROP TRIGGER IF EXISTS refuse_cell_write ON cells;
             DROP TABLE IF EXISTS refused_cell_key",
        )
        .await;
    }

    async fn ddl(&self, member_id: &str, statement: &str) {
        let client = match self.node(member_id).state.db_pool.get().await {
            Ok(client) => client,
            Err(e) => panic!("node db connection: {e}"),
        };
        client
            .batch_execute(statement)
            .await
            .unwrap_or_else(|e| panic!("{member_id}: {statement}: {e}"));
    }

    fn node(&self, member_id: &str) -> &Node {
        self.nodes
            .iter()
            .find(|n| n.member_id == member_id)
            .unwrap_or_else(|| panic!("no node for member {member_id}"))
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
    format!("https://{address}")
}
