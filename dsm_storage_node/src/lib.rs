// SPDX-License-Identifier: MIT OR Apache-2.0

//! The storage node: its state, the storage contract's routes (storage spec
//! Part II §12), the b0x spool, and the one assembly the binary serves.
#![deny(warnings)]

use axum::Extension;
use std::sync::Arc;

pub mod api;
pub mod db;
pub mod set_client;

#[derive(Clone)]
pub struct AppState {
    /// The protocol identity EXACTLY as configured (`[node] id`): the string
    /// the storage set names, the value the identity echo layer emits, and
    /// the `member_id` of every ByteCommit and arrival record this node
    /// signs for.
    pub configured_member_id: String,
    /// `configured_member_id` as the header value the echo layer sends.
    member_id_header: axum::http::HeaderValue,
    pub db_pool: Arc<db::DBPool>,
    /// The client pinned to the storage set's CA (see [`set_client`]).
    pub set_client: reqwest::Client,
    /// The canonical storage set this node is a member of (`[storage_set]
    /// members = [...]` in config, canonical id derived exactly as clients derive
    /// it). `None` = not configured: the node serves the storage contract but
    /// has no set-mates to mirror.
    pub storage_set: Option<Arc<NodeStorageSet>>,
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
    /// This node's own register incarnation, as its database holds it and
    /// the set commits it.
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
                dsm::utils::text_id::encode_base32_crockford(configured_own),
                dsm::utils::text_id::encode_base32_crockford(&own_incarnation)
            );
        }
        let pairs: Vec<(&[u8], [u8; 32])> =
            members.iter().map(|(m, i)| (m.as_bytes(), *i)).collect();
        let committed = dsm::ccb::StorageSetMembers::new(&pairs)
            .map_err(|e| anyhow::anyhow!("storage_set.members: {e}"))?;
        let id = dsm::ccb::storage_set_id(&committed)
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
    /// The state of the node configured as `member_id`. Refuses a member id
    /// that cannot be sent as the identity echo: a set-mate mirroring this
    /// node keeps a ByteCommit only when the echo names the member the
    /// ByteCommit names (storage spec §14, mirror sync).
    pub fn new(
        member_id: String,
        db_pool: Arc<db::DBPool>,
        set_client: reqwest::Client,
    ) -> anyhow::Result<Self> {
        let member_id_header = axum::http::HeaderValue::from_str(&member_id).map_err(|e| {
            anyhow::anyhow!("node id {member_id:?} cannot be sent as the identity echo: {e}")
        })?;
        Ok(Self {
            configured_member_id: member_id,
            member_id_header,
            db_pool,
            set_client,
            storage_set: None,
            mirror_sync: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    /// Attach this node's canonical storage set (see [`NodeStorageSet`]).
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
/// No write authorization on any of them: a member never checks who carries
/// the bytes, because every object carries its own authority and derived
/// objects need none.
pub fn storage_contract_router(state: Arc<AppState>) -> axum::Router<()> {
    api::cells::create_router(state.clone())
        .merge(api::objects::bytecommit::create_router(state.clone()))
        .merge(api::objects::immutable::create_read_router(state.clone()))
        .merge(api::objects::immutable::create_write_router().layer(Extension(state)))
}

/// Echo this node's configured protocol identity on every response, byte
/// for byte what the storage set names. A set-mate mirroring this node's
/// ByteCommits keeps one only when the echo names the member the ByteCommit
/// names (storage spec §14, mirror sync). This is identity, not
/// authentication: it does not prove the node is honest.
pub fn node_identity_echo_layer(
    member_id: axum::http::HeaderValue,
) -> tower_http::set_header::SetResponseHeaderLayer<axum::http::HeaderValue> {
    tower_http::set_header::SetResponseHeaderLayer::overriding(
        axum::http::header::HeaderName::from_static("x-dsm-node-id"),
        member_id,
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
}

/// The node's whole app: every route it serves, with its limits and layers.
/// The binary serves exactly this, and so do tests that stand up real nodes,
/// so no test ever runs against an assembly the binary does not serve.
pub fn build_app(state: std::sync::Arc<AppState>, limits: AppLimits) -> axum::Router<()> {
    use axum::http::StatusCode;
    use axum::routing::get;
    use axum::Router;
    use tower::limit::ConcurrencyLimitLayer;
    use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};

    Router::new()
        .route("/api/v2/health", get(|| async { (StatusCode::OK, "ok") }))
        // The storage contract's four operations (Part II §12): no write
        // authorization, content-blind.
        .merge(crate::storage_contract_router(state.clone()))
        // The b0x spool (storage spec §8): no writer or reader authorization,
        // envelopes never opened.
        .merge(crate::api::transport::b0x::router(state.clone()))
        .layer(RequestBodyLimitLayer::new(limits.body_limit_bytes))
        .layer(ConcurrencyLimitLayer::new(limits.concurrency_limit))
        .layer(TraceLayer::new_for_http())
        .layer(crate::node_identity_echo_layer(
            state.member_id_header.clone(),
        ))
        .layer(Extension(state))
}
