// SPDX-License-Identifier: MIT OR Apache-2.0

//! Library crate for dsm_storage_node: shared types and routers for tests
#![deny(warnings)]

use axum::Extension;
use std::sync::atomic::AtomicI64;
use std::sync::Arc;

pub mod api;
pub mod db;
pub mod replication;
pub mod timing;

use replication::StorageNodeId;

#[derive(Clone)]
pub struct AppState {
    pub node_id: StorageNodeId,
    /// The protocol identity EXACTLY as configured (`[node] id`) — the string
    /// a client's catalog names, the value the identity echo layer emits, and
    /// therefore the `member_id` every generic-binding answer carries. Kept
    /// beside the canonical 32-byte `node_id` because the two are different
    /// facts: one is how peers address this node, the other is who a quorum
    /// counts.
    pub configured_member_id: String,
    pub hsts_max_age: Option<u64>,
    pub db_pool: Arc<db::DBPool>,
    pub replication_manager: Arc<replication::ReplicationManager>,
    pub current_tick: Arc<AtomicI64>,
    /// The canonical storage set this node is a member of (`[storage_set]
    /// members = [...]` in config, canonical id derived exactly as clients derive
    /// it). `None` = not configured: the settlement-slot register refuses every
    /// claim (fail closed) rather than accepting claims for an unknown set.
    pub storage_set: Option<Arc<NodeStorageSet>>,
    /// The register incarnation THIS node is serving — minted once into its
    /// own database at first boot, established before anything is served.
    /// Stamped on every generic-binding answer so a caller can tell this
    /// register history from a rebuilt one wearing the same node id.
    pub own_register_incarnation: Option<[u8; 32]>,
    /// Held for the whole of a ByteCommit mirror sync, so one sync runs at a
    /// time and a caller asking again waits for it instead of repeating it.
    pub mirror_sync: Arc<tokio::sync::Mutex<()>>,
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
    /// Where each set-mate is reached, from this node's own configuration
    /// (`endpoint` on `[[storage_set.members]]`). A node mirrors every
    /// set-mate's ByteCommits by fetching them at this endpoint and nowhere
    /// else (storage spec §14, mirror provenance and mirror sync).
    pub endpoints: Vec<(String, String)>,
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
            endpoints: Vec::new(),
        })
    }

    /// Attach each set-mate's configured endpoint. A node mirrors every node
    /// it shares the set with (storage spec §14), so every member other than
    /// `own_node_id` needs one. Refuses a missing endpoint, an endpoint for an
    /// id that is not a member, and a member named twice.
    pub fn with_endpoints(
        mut self,
        own_node_id: &str,
        endpoints: Vec<(String, String)>,
    ) -> anyhow::Result<Self> {
        for (i, (member, _)) in endpoints.iter().enumerate() {
            if !self.members.iter().any(|(m, _)| m == member) {
                anyhow::bail!("storage_set endpoint names {member:?}, which is not a member");
            }
            if endpoints[..i].iter().any(|(m, _)| m == member) {
                anyhow::bail!("storage_set names an endpoint for {member:?} twice");
            }
        }
        for (member, _) in &self.members {
            if member != own_node_id && !endpoints.iter().any(|(m, _)| m == member) {
                anyhow::bail!(
                    "storage_set member {member:?} has no endpoint: this node mirrors every \
                     set-mate's ByteCommits and can reach one only at its configured endpoint"
                );
            }
        }
        self.endpoints = endpoints;
        Ok(self)
    }

    /// The configured member ids, for logging and endpoint resolution.
    pub fn member_ids(&self) -> impl Iterator<Item = &str> {
        self.members.iter().map(|(m, _)| m.as_str())
    }

    /// `(member id, endpoint)` for every member with a configured endpoint.
    pub fn member_endpoints(&self) -> impl Iterator<Item = (&str, &str)> {
        self.endpoints.iter().map(|(m, e)| (m.as_str(), e.as_str()))
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
        let configured_member_id = node_id_input.clone();
        let node_id =
            StorageNodeId::from_base32_or_derive(&node_id_input, address_or_seed.as_bytes());
        Self {
            node_id,
            configured_member_id,
            hsts_max_age,
            db_pool,
            replication_manager,
            current_tick: Arc::new(AtomicI64::new(0)),
            storage_set: None,
            own_register_incarnation: None,
            mirror_sync: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Attach this node's canonical storage set (see [`NodeStorageSet`]).
    /// Record the register incarnation this node established at startup.
    pub fn with_register_incarnation(mut self, incarnation: [u8; 32]) -> Self {
        self.own_register_incarnation = Some(incarnation);
        self
    }

    pub fn with_storage_set(mut self, set: NodeStorageSet) -> Self {
        self.storage_set = Some(Arc::new(set));
        self
    }
}

/// Keyed cells and indexes: no write authorization, nothing refused, nothing
/// decided. Every object carries its own authority; whoever carries the bytes
/// does not matter.
pub fn cells_router(state: Arc<AppState>) -> axum::Router<()> {
    api::cells::create_router(state)
}

/// The four operations of the storage contract (Part II §12) — put object,
/// put at a key, append to an index, get — as ONE assembly, used by the
/// binary and by the contract suites, so what the suites drive is what the
/// binary serves.
///
/// No write authorization on any of them (rebuild step R2): a member never
/// checks who carries the bytes, because every object carries its own
/// authority and derived objects need none. The device token stays only on
/// the other mounts (the DLV object store, the identity mirrors), never here.
pub fn storage_contract_router(state: Arc<AppState>) -> axum::Router<()> {
    api::cells::create_router(state.clone())
        .merge(api::objects::bytecommit::create_router(state.clone()))
        .merge(api::objects::immutable::create_read_router(state.clone()))
        .merge(api::objects::immutable::create_write_router().layer(Extension(state)))
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

/// Limits the node's app applies to every request.
#[derive(Debug, Clone, Copy)]
pub struct AppLimits {
    pub body_limit_bytes: usize,
    pub concurrency_limit: usize,
    /// Disables rate limiting on the public routes (benchmarks only).
    pub benchmark_mode: bool,
}

/// The node's whole app: every route it serves, with its limits and layers.
/// The binary serves exactly this, and so do tests that stand up real nodes,
/// so no test ever runs against an assembly the binary does not serve.
pub fn build_app(state: std::sync::Arc<AppState>, node_id: &str, limits: AppLimits) -> axum::Router<()> {
    use axum::http::StatusCode;
    use axum::routing::get;
    use axum::{middleware, Extension, Router};
    use tower::limit::ConcurrencyLimitLayer;
    use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};

    let b0x_router = crate::api::transport::b0x::router(state.clone());
    let app: Router<()> = {
    let public_rate_limiter = if limits.benchmark_mode {
        log::info!("BENCHMARK MODE: rate limiting disabled for all public endpoints");
        Arc::new(crate::api::infra::rate_limit::RateLimiter::new_bypass())
    } else {
        Arc::new(crate::api::infra::rate_limit::RateLimiter::new())
    };
    let public_rate_layer = middleware::from_fn_with_state(
        public_rate_limiter.clone(),
        crate::api::infra::rate_limit::rate_limit_by_ip,
    );

    // The storage contract's four operations (Part II §12): the immutable
    // content-addressed store and the keyed cells and indexes, ONE public
    // assembly with no write authorization (R2). The node is content-blind on
    // every one of them — no payload decode, ever.
    let storage_contract_router =
        crate::storage_contract_router(state.clone()).layer(public_rate_layer.clone());
    // Policy router is transport-only and signature-free; safe to expose.
    let policy_router =
        crate::api::vault::policy::create_router(state.clone()).layer(public_rate_layer.clone());
    // Identity mirrors
    let devtree_router =
        crate::api::identity::devtree::create_router(state.clone()).layer(public_rate_layer.clone());
    // Recovery-authority anchor — single-assignment per genesis (§0.5 bind-once)
    let recovery_anchor_router = crate::api::identity::recovery_anchor::create_router(state.clone())
        .layer(public_rate_layer.clone());
    // Append-only Per-Device SMT head chain (§0.5 gap 13, R4 layer 1)
    let pdsmt_head_router =
        crate::api::identity::pdsmt_head::create_router(state.clone()).layer(public_rate_layer.clone());
    let tips_router =
        crate::api::identity::tips::create_router(state.clone()).layer(public_rate_layer.clone());
    // Genesis mirror
    let genesis_router =
        crate::api::identity::genesis::create_router(state.clone()).layer(public_rate_layer.clone());
    // DLV slot + Recovery Capsule
    let dlv_slot_router =
        crate::api::vault::slot::create_router(state.clone()).layer(public_rate_layer.clone());
    // Keyed cells and indexes: bytes in, bytes out. No write authorization;
    // a member keeps everything it is given and refuses nothing.
    let recovery_capsule_router =
        crate::api::vault::recovery::create_router(state.clone()).layer(public_rate_layer.clone());
    // Gossip protocol for replication
    let gossip_router = crate::api::transport::gossip::gossip_routes(state.clone());
    // Node discovery for SDK auto-discovery
    let discovery_router =
        crate::api::registry::discovery::create_router(state.clone()).layer(public_rate_layer.clone());

    // EVERY `/admin` endpoint, assembled in one place behind one token check.
    // Two sibling admin routers nested at the same path is how the registry's
    // update and seed endpoints came to be reachable unauthenticated.
    let admin_router = crate::api::infra::admin::admin_surface(state.clone());

    // Compose routes and layers, then install `state`.
    // Returning `Router<()>` here is important (see Axum docs).
    // Request metrics for Prometheus scraping

    Router::new()
        // Health check endpoint (lightweight, no DB access)
        .route("/api/v2/health", get(|| async { (StatusCode::OK, "ok") }))
        .merge(storage_contract_router)
        .merge(policy_router)
        .merge(devtree_router)
        .merge(recovery_anchor_router)
        .merge(pdsmt_head_router)
        .merge(tips_router)
        .merge(genesis_router)
        .merge(dlv_slot_router)
        .merge(recovery_capsule_router)
        .merge(gossip_router) // Gossip protocol endpoints
        .merge(discovery_router) // Node discovery for SDK auto-discovery
        .nest("/admin", admin_router) // Every /admin/* endpoint, auth applied once
        .layer(RequestBodyLimitLayer::new(limits.body_limit_bytes))
        .layer(ConcurrencyLimitLayer::new(limits.concurrency_limit))
        .layer(TraceLayer::new_for_http())
        // The node-identity echo (see `node_identity_echo_layer`): NORMATIVE
        // for every quorum read and write, so it is the one shared layer.
        .layer(crate::node_identity_echo_layer(node_id))
        .layer(Extension(state))

    };
    // b0x v2 (protobuf-only, clockless): no writer or reader authorization
    // (storage spec §4, DSM Amendment A3).
    app.merge(b0x_router)
}
