// SPDX-License-Identifier: MIT OR Apache-2.0

//! Library crate for dsm_storage_node: shared types and routers for tests
#![deny(warnings)]

use axum::Extension;
use std::sync::atomic::AtomicI64;
use std::sync::Arc;

pub mod api;
pub mod auth;
pub mod db;
#[cfg(feature = "dev-replication")]
pub mod dev_replication;
pub mod replication;
pub mod timing;

use replication::StorageNodeId;

#[derive(Clone)]
pub struct AppState {
    pub node_id: StorageNodeId,
    pub hsts_max_age: Option<u64>,
    pub db_pool: Arc<db::DBPool>,
    pub replication_manager: Arc<replication::ReplicationManager>,
    pub current_tick: Arc<AtomicI64>,
    /// The canonical storage set this node is a member of (`[storage_set]
    /// members = [...]` in config, canonical id derived exactly as clients derive
    /// it). `None` = not configured: the settlement-slot register refuses every
    /// claim (fail closed) rather than accepting claims for an unknown set.
    pub storage_set: Option<Arc<NodeStorageSet>>,
    /// The DSM network this node serves (`node.network_id` in config). Gates
    /// the ERA faucet-ticket register: the canonical faucet identity is
    /// NETWORK-SCOPED (`era_faucet_id(network_id)`), so a node that does not
    /// know its network cannot tell the canonical faucet from an invented
    /// one and refuses every ticket claim (fail closed) rather than
    /// defaulting. `None` = faucet register inactive.
    pub network_id: Option<Arc<Vec<u8>>>,
}

/// This node's view of the canonical storage set it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeStorageSet {
    /// `compute_storage_set_id` over the `(member_id, incarnation)` pairs.
    pub id: [u8; 32],
    /// Every member's configured protocol identity paired with the register
    /// incarnation it is serving. This node's own `node.id` must be among
    /// them, and its configured incarnation must be the one this node's
    /// database actually holds.
    pub members: Vec<(String, [u8; 32])>,
    /// This node's own register incarnation — the value it echoes on every
    /// register read so a reader can tell it apart from a rebuilt member
    /// wearing the same node id.
    pub own_incarnation: [u8; 32],
}

impl NodeStorageSet {
    /// Build from configured members; refuses an empty set, duplicate ids, a
    /// set that does not contain `own_node_id` — a node that would
    /// acknowledge claims for a set it is not a member of is misconfigured —
    /// and, decisively, a configured incarnation for THIS node that is not
    /// the one its database holds.
    ///
    /// That last refusal is the point of the whole mechanism. A node that
    /// lost and rebuilt its register comes back with a new incarnation; if it
    /// were allowed to keep serving the configured old one it would be
    /// asserting a register history it no longer has. Refusing at startup
    /// makes the discontinuity loud, at the one moment an operator is looking,
    /// instead of silent at read time.
    pub fn new(
        members: Vec<(String, [u8; 32])>,
        own_node_id: &str,
        own_incarnation: [u8; 32],
    ) -> anyhow::Result<Self> {
        let Some((_, configured_own)) = members.iter().find(|(m, _)| m == own_node_id) else {
            anyhow::bail!(
                "storage_set.members does not contain this node's own id {own_node_id:?}"
            );
        };
        if *configured_own != own_incarnation {
            anyhow::bail!(
                "storage_set.members lists a register incarnation for this node ({}) that is \
                 not the one this node's database holds ({}) — this node's register was \
                 rebuilt or restored, so it is no longer the member the configured set names",
                dsm_sdk::util::text_id::encode_base32_crockford(configured_own),
                dsm_sdk::util::text_id::encode_base32_crockford(&own_incarnation)
            );
        }
        let entries: Vec<(&str, [u8; 32])> =
            members.iter().map(|(m, i)| (m.as_str(), *i)).collect();
        let id = dsm_sdk::sdk::storage_set::compute_storage_set_id(&entries)
            .map_err(|e| anyhow::anyhow!("storage_set.members: {e}"))?;
        Ok(Self {
            id,
            members,
            own_incarnation,
        })
    }

    /// The configured member ids, for logging and endpoint resolution.
    pub fn member_ids(&self) -> impl Iterator<Item = &str> {
        self.members.iter().map(|(m, _)| m.as_str())
    }
}

impl AppState {
    /// Build an AppState. The supplied `node_id_input` is canonicalised exactly
    /// like `canonical_node_info` does for gossip: if it is a valid 32-byte
    /// base32-crockford string, it is decoded as-is; otherwise a 32-byte node
    /// id is derived from `address_or_seed`. The result is the single
    /// canonical operator identity used across replication, ByteCommit
    /// emission, HTTP headers, and DB chain anchoring.
    pub fn new(
        node_id_input: String,
        address_or_seed: &str,
        hsts_max_age: Option<u64>,
        db_pool: Arc<db::DBPool>,
        replication_manager: Arc<replication::ReplicationManager>,
    ) -> Self {
        let node_id =
            StorageNodeId::from_base32_or_derive(&node_id_input, address_or_seed.as_bytes());
        Self {
            node_id,
            hsts_max_age,
            db_pool,
            replication_manager,
            current_tick: Arc::new(AtomicI64::new(0)),
            storage_set: None,
            network_id: None,
        }
    }

    /// Attach this node's canonical storage set (see [`NodeStorageSet`]).
    pub fn with_network_id(mut self, network_id: Vec<u8>) -> Self {
        self.network_id = Some(Arc::new(network_id));
        self
    }

    pub fn with_storage_set(mut self, set: NodeStorageSet) -> Self {
        self.storage_set = Some(Arc::new(set));
        self
    }
}

/// The device-authenticated WRITE half of the two economic write-once
/// registers (faucet tickets, economic roots), behind `auth::device_auth` so
/// attribution runs against the authenticated key AND device.
///
/// ONE assembly, used by the binary's router and by the register conformance
/// suite, so what the suite drives is what the binary serves.
pub fn economic_register_write_router(state: Arc<AppState>) -> axum::Router<()> {
    let auth_state = Arc::new(auth::AuthState {
        db_pool: state.db_pool.clone(),
    });
    api::economic::faucet_ticket::create_write_router()
        .merge(api::economic::root_register::create_write_router())
        .layer(axum::middleware::from_fn_with_state(
            auth_state,
            auth::device_auth,
        ))
        .layer(Extension(state))
}

/// The public READ half of the same two registers. The binary rate-limits it;
/// the conformance suite mounts it bare.
pub fn economic_register_read_router(state: Arc<AppState>) -> axum::Router<()> {
    api::economic::faucet_ticket::create_read_router(state.clone())
        .merge(api::economic::root_register::create_read_router(state))
}

/// Echo this node's configured protocol identity on EVERY response.
///
/// A client fanning a keyed write out over a canonical storage set counts an
/// acceptance only when the answering node IS the member its catalog says
/// lives at that endpoint — "distinct members" is executable, not
/// administrative. This is identity, not authentication (crash-fault node
/// model): it prevents two catalog entries on one physical node from yielding
/// two acceptances; it does not prove the node is honest. The value is the
/// RAW configured id, byte-for-byte what the client's catalog names.
pub fn node_identity_echo_layer(
    node_id: &str,
) -> tower_http::set_header::SetResponseHeaderLayer<axum::http::HeaderValue> {
    tower_http::set_header::SetResponseHeaderLayer::overriding(
        axum::http::header::HeaderName::from_static("x-dsm-node-id"),
        axum::http::HeaderValue::from_str(node_id)
            .unwrap_or_else(|_| axum::http::HeaderValue::from_static("invalid-node-id")),
    )
}

/// Minimal app builder for tests that don't require DB access.
/// It wires only the routes needed by tests (registry gate), with a lazy pool.
///
/// When compiled with the `local-dev` feature (SQLite), defaults to an
/// in-memory database so no PostgreSQL installation is required.
/// When compiled with the `postgres` feature, honours the `DSM_DATABASE_URL`
/// environment variable (no default database URL is provided — tests that need
/// a real PG instance must set that variable).
pub async fn build_app_for_tests() -> anyhow::Result<axum::Router> {
    let database_url = std::env::var("DSM_DATABASE_URL").unwrap_or_else(|_| {
        // `local-dev` (SQLite) build: open an in-memory database.
        // `postgres` build: callers must supply DSM_DATABASE_URL.
        #[cfg(feature = "local-dev")]
        {
            ":memory:".to_string()
        }
        #[cfg(not(feature = "local-dev"))]
        {
            "postgresql://localhost:5432/dsm_storage".to_string()
        }
    });
    let pool = db::create_pool(&database_url, true)?;

    // Initialize DB schema for tests
    db::init_db(&pool).await?;

    let replication_config = replication::ReplicationConfig {
        replication_factor: 3,
        gossip_interval_ticks: 100,
        failure_timeout_ticks: 500,
        gossip_fanout: 3,
        max_concurrent_jobs: 10,
    };
    let replication_manager = Arc::new(
        replication::ReplicationManager::new_for_tests(
            replication_config,
            "test-node".to_string(),
            "http://localhost:8080".to_string(),
        )
        .map_err(|e| anyhow::anyhow!("Failed to create replication manager: {}", e))?,
    );

    let state = AppState::new(
        "test-node".to_string(),
        "http://localhost:8080",
        None,
        Arc::new(pool),
        replication_manager,
    );
    let state_arc = Arc::new(state);

    // Only mount registry routes for the current tests
    Ok(axum::Router::new()
        .merge(api::registry::core::create_router(state_arc.clone()))
        .layer(Extension(state_arc)))
}

#[cfg(test)]
mod storage_set_tests {
    #![allow(clippy::disallowed_methods)] // unwrap/expect acceptable in deterministic tests
    use super::NodeStorageSet;

    fn members() -> Vec<(String, [u8; 32])> {
        vec![
            ("n1".into(), [0xC1; 32]),
            ("n2".into(), [0xC2; 32]),
            ("n3".into(), [0xC3; 32]),
        ]
    }

    /// THE REFUSAL THIS MECHANISM EXISTS FOR.
    ///
    /// A node that lost and rebuilt its register still owns its identity key
    /// and its configured id, so every check that looks at identity alone
    /// passes. What it no longer has is the register history the set names.
    /// Startup is where that becomes loud: the configured incarnation is what
    /// the set committed, this node's database is what it can still speak
    /// for, and serving the set while those disagree would be asserting a
    /// history it does not have.
    #[test]
    fn a_node_whose_register_was_rebuilt_refuses_to_serve_the_configured_set() {
        let err = NodeStorageSet::new(members(), "n1", [0x99; 32])
            .expect_err("a rebuilt register must refuse the configured set");
        let text = err.to_string();
        assert!(
            text.contains("rebuilt or restored"),
            "the refusal must say WHY, got: {text}"
        );

        // The same node, still serving the incarnation the set committed, is
        // fine — so the refusal is about the register history, not about
        // being strict.
        assert!(NodeStorageSet::new(members(), "n1", [0xC1; 32]).is_ok());
    }

    #[test]
    fn a_set_that_does_not_name_this_node_is_refused() {
        let err = NodeStorageSet::new(members(), "n4", [0xC4; 32])
            .expect_err("a node must be a member of the set it serves");
        assert!(err
            .to_string()
            .contains("does not contain this node's own id"));
    }

    /// The incarnation is an INPUT to the id, not a label beside it: the same
    /// three node ids under a different incarnation are a different set, so a
    /// rebuilt member cannot resolve to the set it used to serve.
    #[test]
    fn one_members_incarnation_changes_the_whole_set_id() {
        let before = NodeStorageSet::new(members(), "n1", [0xC1; 32]).unwrap();
        let mut rebuilt = members();
        rebuilt[2] = ("n3".into(), [0x77; 32]);
        let after = NodeStorageSet::new(rebuilt, "n1", [0xC1; 32]).unwrap();
        assert_ne!(
            before.id, after.id,
            "a member's new register incarnation must change the set id"
        );
    }

    /// Ordering is by MEMBER ID, never by the pair — so the id does not
    /// depend on how the operator happened to list the members.
    #[test]
    fn the_set_id_does_not_depend_on_configuration_order() {
        let a = NodeStorageSet::new(members(), "n1", [0xC1; 32]).unwrap();
        let mut reversed = members();
        reversed.reverse();
        let b = NodeStorageSet::new(reversed, "n1", [0xC1; 32]).unwrap();
        assert_eq!(a.id, b.id);
    }
}
