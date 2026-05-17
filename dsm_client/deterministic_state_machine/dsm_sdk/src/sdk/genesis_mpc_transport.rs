//! # HTTP-backed Genesis MPC transport (Task A.4)
//!
//! Implements `dsm::core::identity::genesis_mpc::GenesisMpcCommitRevealTransport`
//! against real storage-node HTTP endpoints exposed by
//! `dsm_storage_node::api::identity::genesis_mpc`:
//!
//! - `POST /api/v2/genesis/mpc/offer`
//! - `POST /api/v2/genesis/mpc/commit/{session_id_b32}`
//! - `POST /api/v2/genesis/mpc/reveal/{session_id_b32}`
//!
//! Bodies are protobuf (`application/octet-stream`) — no JSON / hex /
//! base64 in the wire content per project encoding policy. Path
//! identifiers are base32-Crockford-encoded 32-byte session IDs
//! (the only place we encode at all, matching the existing
//! `/api/v2/identity/{genesis}/devtree/*` convention).

use std::collections::HashMap;

use async_trait::async_trait;
use prost::Message;

use dsm::core::identity::genesis_mpc::GenesisMpcCommitRevealTransport;
use dsm::types::error::DsmError;
use dsm::types::proto as pb;

use crate::sdk::storage_node_sdk::build_ca_aware_client;
use crate::util::text_id::encode_base32_crockford;

/// HTTP-backed implementation of the three-round commit-reveal
/// transport. One instance covers one MPC session — the participant
/// set is fixed at construction time as a `node_id → base_url` map.
pub struct HttpGenesisMpcTransport {
    client: reqwest::Client,
    /// Maps 32-byte storage-node id → base URL (no trailing slash).
    /// Populated at session start from the orchestrator's discovery
    /// + selection step.
    node_urls: HashMap<[u8; 32], String>,
}

impl HttpGenesisMpcTransport {
    /// Build a transport for the given `(node_id, base_url)` pairs.
    /// The reqwest client is shared across all calls so connection
    /// pooling kicks in for the fan-out rounds.
    pub fn new(node_addr_pairs: Vec<([u8; 32], String)>) -> Self {
        let mut node_urls = HashMap::with_capacity(node_addr_pairs.len());
        for (id, url) in node_addr_pairs {
            // Normalise trailing slash so URLs concat predictably.
            let trimmed = url.trim_end_matches('/').to_string();
            node_urls.insert(id, trimmed);
        }
        Self {
            client: build_ca_aware_client(),
            node_urls,
        }
    }

    fn url_for(&self, node_id: &[u8; 32]) -> Result<&str, DsmError> {
        self.node_urls
            .get(node_id)
            .map(|s| s.as_str())
            .ok_or_else(|| {
                DsmError::invalid_operation(format!(
                    "Genesis MPC: no URL configured for node {}",
                    encode_base32_crockford(node_id)
                ))
            })
    }

    async fn post_proto<Req, Resp>(
        &self,
        url: &str,
        req: &Req,
        decoder: impl FnOnce(&[u8]) -> Result<Resp, prost::DecodeError>,
    ) -> Result<Resp, DsmError>
    where
        Req: Message,
    {
        let body = req.encode_to_vec();
        let resp = self
            .client
            .post(url)
            .header("content-type", "application/octet-stream")
            .body(body)
            .send()
            .await
            .map_err(|e| {
                DsmError::network(
                    format!("Genesis MPC HTTP send to {url} failed: {e}"),
                    Some(e),
                )
            })?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(|e| {
            DsmError::network(
                format!("Genesis MPC HTTP read from {url} failed: {e}"),
                Some(e),
            )
        })?;
        if !status.is_success() {
            return Err(DsmError::invalid_operation(format!(
                "Genesis MPC HTTP {url} returned {status} (body {} bytes)",
                bytes.len()
            )));
        }
        decoder(&bytes).map_err(|e| {
            DsmError::invalid_operation(format!(
                "Genesis MPC HTTP response from {url} failed proto decode: {e}"
            ))
        })
    }

    async fn post_no_response<Req: Message>(&self, url: &str, req: &Req) -> Result<(), DsmError> {
        let body = req.encode_to_vec();
        let resp = self
            .client
            .post(url)
            .header("content-type", "application/octet-stream")
            .body(body)
            .send()
            .await
            .map_err(|e| {
                DsmError::network(
                    format!("Genesis MPC HTTP send to {url} failed: {e}"),
                    Some(e),
                )
            })?;
        let status = resp.status();
        if !status.is_success() {
            return Err(DsmError::invalid_operation(format!(
                "Genesis MPC HTTP {url} returned {status}"
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl GenesisMpcCommitRevealTransport for HttpGenesisMpcTransport {
    async fn offer(
        &self,
        node_id: &[u8; 32],
        session: &pb::GenesisMpcSessionV1,
    ) -> Result<pb::GenesisMpcCommitV1, DsmError> {
        let base = self.url_for(node_id)?;
        let url = format!("{base}/api/v2/genesis/mpc/offer");
        self.post_proto(&url, session, |b| pb::GenesisMpcCommitV1::decode(b))
            .await
    }

    async fn observe_peer_commit(
        &self,
        target_node_id: &[u8; 32],
        peer_commit: &pb::GenesisMpcCommitV1,
    ) -> Result<(), DsmError> {
        let base = self.url_for(target_node_id)?;
        let session_id_arr: [u8; 32] =
            peer_commit.session_id.as_slice().try_into().map_err(|_| {
                DsmError::invalid_operation("observe_peer_commit: bad session_id length")
            })?;
        let url = format!(
            "{base}/api/v2/genesis/mpc/commit/{}",
            encode_base32_crockford(&session_id_arr)
        );
        self.post_no_response(&url, peer_commit).await
    }

    async fn request_reveal(
        &self,
        node_id: &[u8; 32],
        request: &pb::GenesisMpcRevealRequestV1,
    ) -> Result<pb::GenesisMpcRevealV1, DsmError> {
        let base = self.url_for(node_id)?;
        let session_id_arr: [u8; 32] =
            request.session_id.as_slice().try_into().map_err(|_| {
                DsmError::invalid_operation("request_reveal: bad session_id length")
            })?;
        let url = format!(
            "{base}/api/v2/genesis/mpc/reveal/{}",
            encode_base32_crockford(&session_id_arr)
        );
        self.post_proto(&url, request, |b| pb::GenesisMpcRevealV1::decode(b))
            .await
    }
}

/// Active-registry snapshot fetched from one storage node:
/// `R_reg` + the parsed list of 32-byte node IDs sorted as
/// returned (the storage node returns them already sorted per
/// spec §9).
#[derive(Debug, Clone)]
pub struct RegistrySnapshot {
    /// `R_reg = H("DSM/registry\0" || ProtoDet(RegistryV3))` per
    /// `dsm::core::identity::genesis_mpc::compute_registry_root`.
    pub r_reg: [u8; 32],
    /// Active registry node IDs (32 bytes each).
    pub node_ids: Vec<[u8; 32]>,
}

/// Fetch the active registry from a storage node and compute
/// `R_reg` from the returned bytes. Used by the device-side
/// Genesis MPC orchestrator to derive a deterministic `session_id`
/// and pick participants via `permute_unbiased`.
///
/// `r_reg` is the hash OF THE WIRE BYTES the storage node sent —
/// recomputed locally so a tampered transit can't substitute a
/// different anchor. Two storage nodes serving the same registry
/// will both yield the same `r_reg`; if they diverge the caller
/// selects an authoritative one or refuses to proceed.
pub async fn fetch_registry(base_url: &str) -> Result<RegistrySnapshot, DsmError> {
    let client = build_ca_aware_client();
    let url = format!("{}/api/v2/registry/current", base_url.trim_end_matches('/'));
    let resp = client.get(&url).send().await.map_err(|e| {
        DsmError::network(format!("registry/current GET {url} failed: {e}"), Some(e))
    })?;
    let status = resp.status();
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| DsmError::network(format!("registry/current read failed: {e}"), Some(e)))?;
    if !status.is_success() {
        return Err(DsmError::invalid_operation(format!(
            "registry/current {url} returned {status}"
        )));
    }

    let r_reg = dsm::core::identity::genesis_mpc::compute_registry_root(&bytes);

    let registry = pb::RegistryV3::decode(bytes.as_ref())
        .map_err(|e| DsmError::invalid_operation(format!("RegistryV3 proto decode: {e}")))?;
    let mut node_ids: Vec<[u8; 32]> = Vec::with_capacity(registry.node_ids.len());
    for nid in registry.node_ids {
        let arr: [u8; 32] = nid
            .as_slice()
            .try_into()
            .map_err(|_| DsmError::invalid_operation("RegistryV3.node_ids entry not 32 bytes"))?;
        node_ids.push(arr);
    }

    Ok(RegistrySnapshot { r_reg, node_ids })
}

/// Fetch a node's self-reported 32-byte id via
/// `GET /api/v2/node/identity`. Used by the orchestrator to learn
/// the real participant id for a configured URL when discovery
/// returns address-only data.
pub async fn fetch_node_identity(base_url: &str) -> Result<[u8; 32], DsmError> {
    let client = build_ca_aware_client();
    let url = format!("{}/api/v2/node/identity", base_url.trim_end_matches('/'));
    let resp =
        client.get(&url).send().await.map_err(|e| {
            DsmError::network(format!("node/identity GET {url} failed: {e}"), Some(e))
        })?;
    let status = resp.status();
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| DsmError::network(format!("node/identity read failed: {e}"), Some(e)))?;
    if !status.is_success() {
        return Err(DsmError::invalid_operation(format!(
            "node/identity {url} returned {status}"
        )));
    }
    let envelope = pb::NodeIdentityV1::decode(bytes.as_ref())
        .map_err(|e| DsmError::invalid_operation(format!("node/identity proto decode: {e}")))?;
    envelope.node_id.as_slice().try_into().map_err(|_| {
        DsmError::invalid_operation(format!("node/identity {url} returned bad node_id length"))
    })
}

/// Cross-verify a (claimed_node_id, base_url) pair by calling
/// `GET /api/v2/node/identity` on the URL and comparing the returned
/// id to the claimed one. Adversarial-stage-6 defense against
/// discovery-layer Sybils (operator advertising multiple node_ids
/// under one address).
pub async fn fetch_and_verify_node_identity(
    base_url: &str,
    expected_node_id: &[u8; 32],
) -> Result<(), DsmError> {
    let client = build_ca_aware_client();
    let url = format!("{}/api/v2/node/identity", base_url.trim_end_matches('/'));
    let resp =
        client.get(&url).send().await.map_err(|e| {
            DsmError::network(format!("node/identity GET {url} failed: {e}"), Some(e))
        })?;
    let status = resp.status();
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| DsmError::network(format!("node/identity read failed: {e}"), Some(e)))?;
    if !status.is_success() {
        return Err(DsmError::invalid_operation(format!(
            "node/identity {url} returned {status}"
        )));
    }
    let envelope = pb::NodeIdentityV1::decode(bytes.as_ref())
        .map_err(|e| DsmError::invalid_operation(format!("node/identity proto decode: {e}")))?;
    if envelope.node_id.as_slice() != expected_node_id.as_slice() {
        return Err(DsmError::invalid_operation(format!(
            "node/identity mismatch at {url}: expected {} got {}",
            encode_base32_crockford(expected_node_id),
            encode_base32_crockford(&envelope.node_id),
        )));
    }
    Ok(())
}
