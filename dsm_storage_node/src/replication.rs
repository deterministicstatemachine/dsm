// SPDX-License-Identifier: MIT OR Apache-2.0

//! Production-grade replication for DSM storage nodes.
//!
//! Peer membership and failure detection by gossip. A node never places or
//! copies objects to peers it chooses: which members hold a cell or an object
//! is the storage set's and the writer's (storage spec §9), not the node's.
//!
//! Key features:
//! - Dynamic node discovery via gossip protocol
//! - Failure detection and automatic recovery
//! - Data partitioning with consistent hashing
//! - Replication factor management
//! - Network partition tolerance
//! - Clockless operation using deterministic ticks

use crate::api::infra::hardening::{blake3_tagged, DOM_NODE_ID};
use crate::AppState;
use dsm::types::proto as pb;
use prost::Message;
use reqwest::Client;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StorageNodeId([u8; 32]);

impl StorageNodeId {
    pub fn derive(stable_bytes: &[u8]) -> Self {
        Self(blake3_tagged(DOM_NODE_ID, stable_bytes))
    }

    pub fn from_base32(value: &str) -> Option<Self> {
        let bytes = dsm_sdk::util::text_id::decode_base32_crockford(value)?;
        let arr: [u8; 32] = bytes.try_into().ok()?;
        Some(Self(arr))
    }

    pub fn from_base32_or_derive(value: &str, stable_bytes: &[u8]) -> Self {
        Self::from_base32(value).unwrap_or_else(|| Self::derive(stable_bytes))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_base32(self) -> String {
        dsm_sdk::util::text_id::encode_base32_crockford(&self.0)
    }
}

impl std::fmt::Display for StorageNodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_base32())
    }
}

impl std::str::FromStr for StorageNodeId {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_base32(s).ok_or("invalid base32-crockford StorageNodeId")
    }
}

fn canonical_node_info(input_node_id: String, address: String, tick: i64) -> pb::StorageNodeInfoV1 {
    let node_id = StorageNodeId::from_base32_or_derive(&input_node_id, address.as_bytes());
    pb::StorageNodeInfoV1 {
        node_id: node_id.to_base32(),
        address,
        last_seen_tick: tick,
        status: pb::StorageNodeStatus::Alive as i32,
    }
}

fn node_sort_key(node: &pb::StorageNodeInfoV1) -> [u8; 32] {
    *StorageNodeId::from_base32_or_derive(&node.node_id, node.address.as_bytes()).as_bytes()
}

/// Replication configuration
#[derive(Debug, Clone)]
pub struct ReplicationConfig {
    /// Replication factor (number of copies per object)
    pub replication_factor: usize,
    /// Gossip interval in ticks
    pub gossip_interval_ticks: i64,
    /// Failure detection timeout in ticks
    pub failure_timeout_ticks: i64,
    /// Number of gossip targets per round
    pub gossip_fanout: usize,
    /// Maximum concurrent replication jobs
    pub max_concurrent_jobs: usize,
}

fn status_from_i32(value: i32) -> Option<pb::StorageNodeStatus> {
    pb::StorageNodeStatus::try_from(value).ok()
}

/// Load the first certificate from a PEM file for TLS pinning.
///
/// Issue #24 migration: previously used `rustls_pemfile::certs` (unmaintained
/// per RUSTSEC-2025-0134). Now uses `rustls::pki_types::pem::PemObject`,
/// which is the maintained upstream PEM-reading helper exposed by
/// `rustls-pki-types` v1.10+ under the `alloc` feature.
fn load_certificate(
    cert_path: &Path,
) -> Result<CertificateDer<'static>, Box<dyn std::error::Error + Send + Sync>> {
    CertificateDer::from_pem_file(cert_path)
        .map_err(|e| format!("Failed to load PEM certificate from {cert_path:?}: {e}").into())
}

/// Create a reqwest client with certificate pinning
fn create_pinned_client(
    cert_path: &Path,
) -> Result<Client, Box<dyn std::error::Error + Send + Sync>> {
    let cert = load_certificate(cert_path)?;

    let mut root_store = RootCertStore::empty();
    root_store.add(cert)?;

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(Client::builder().use_preconfigured_tls(config).build()?)
}

/// Replication manager for production use
#[derive(Clone)]
pub struct ReplicationManager {
    config: ReplicationConfig,
    local_node_id: StorageNodeId,
    #[allow(dead_code)]
    local_address: String,
    node_states: Arc<std::sync::RwLock<HashMap<String, pb::StorageNodeInfoV1>>>,
    client: Client,
}

impl ReplicationManager {
    pub fn new(
        config: ReplicationConfig,
        local_node_id: String,
        local_address: String,
        cert_path: &Path,
        seed_peers: Vec<String>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut node_states = HashMap::new();
        let local_info = canonical_node_info(local_node_id, local_address.clone(), 0);
        // `canonical_node_info` always sets `node_id = StorageNodeId::to_base32(...)`,
        // so decode must succeed. Fall back to deriving from the address if the
        // invariant is somehow violated rather than panicking in production.
        let local_node_id = StorageNodeId::from_base32(&local_info.node_id)
            .unwrap_or_else(|| StorageNodeId::derive(local_info.address.as_bytes()));

        // Initialize with local node
        node_states.insert(local_info.node_id.clone(), local_info);

        // Seed peers from config so gossip has nodes to talk to on startup.
        // §10.3: Replica placement uses a Fisher-Yates permutation over {nodeID}.
        for peer_addr in seed_peers.iter() {
            let node_id = StorageNodeId::derive(peer_addr.as_bytes()).to_base32();
            log::info!("replication: seeding node {} at {peer_addr}", node_id);
            node_states.insert(
                node_id.clone(),
                pb::StorageNodeInfoV1 {
                    node_id,
                    address: peer_addr.clone(),
                    last_seen_tick: 0,
                    status: pb::StorageNodeStatus::Alive as i32,
                },
            );
        }

        Ok(Self {
            config,
            local_node_id,
            local_address,
            node_states: Arc::new(std::sync::RwLock::new(node_states)),
            client: create_pinned_client(cert_path)?,
        })
    }

    pub fn new_for_tests(
        config: ReplicationConfig,
        local_node_id: String,
        local_address: String,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut node_states = HashMap::new();
        let local_info = canonical_node_info(local_node_id, local_address.clone(), 0);
        // `canonical_node_info` always sets `node_id = StorageNodeId::to_base32(...)`,
        // so decode must succeed. Fall back to deriving from the address if the
        // invariant is somehow violated rather than panicking in production.
        let local_node_id = StorageNodeId::from_base32(&local_info.node_id)
            .unwrap_or_else(|| StorageNodeId::derive(local_info.address.as_bytes()));
        node_states.insert(local_info.node_id.clone(), local_info);

        let client = Client::builder().build()?;

        Ok(Self {
            config,
            local_node_id,
            local_address,
            node_states: Arc::new(std::sync::RwLock::new(node_states)),
            client,
        })
    }

    /// Accessor for the local node's canonical 32-byte identity.
    pub fn local_node_id(&self) -> StorageNodeId {
        self.local_node_id
    }

    /// The client this node uses for peer requests (TLS-pinned in production).
    pub fn http_client(&self) -> &Client {
        &self.client
    }

    /// Get the current set of alive nodes
    #[allow(clippy::disallowed_methods)]
    pub fn get_alive_nodes(&self) -> Vec<pb::StorageNodeInfoV1> {
        let states = match self.node_states.read() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::error!("Node states lock poisoned (read); continuing with inner state");
                poisoned.into_inner()
            }
        };
        states
            .values()
            .filter(|node| status_from_i32(node.status) == Some(pb::StorageNodeStatus::Alive))
            .cloned()
            .collect()
    }

    /// Process gossip messages and update node states
    #[allow(clippy::disallowed_methods)]
    pub async fn process_gossip(&self, gossip: pb::GossipMessageV1, now_tick: i64) {
        let mut states = match self.node_states.write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::error!("Node states lock poisoned (write); continuing with inner state");
                poisoned.into_inner()
            }
        };

        let local_b32 = self.local_node_id.to_base32();
        for remote_info in gossip.node_states {
            let node_id = StorageNodeId::from_base32_or_derive(
                &remote_info.node_id,
                remote_info.address.as_bytes(),
            )
            .to_base32();
            if node_id == local_b32 {
                continue; // Don't update our own state from gossip
            }
            let mut remote_info = remote_info;
            remote_info.node_id = node_id.clone();

            let existing = states
                .entry(node_id.clone())
                .or_insert_with(|| remote_info.clone());

            // Update last seen time and status
            existing.last_seen_tick = remote_info.last_seen_tick.max(existing.last_seen_tick);
            if let Some(status) = status_from_i32(remote_info.status) {
                existing.status = status as i32;
            }
            existing.address = remote_info.address.clone();

            // Mark nodes as suspected if we haven't heard from them recently
            if now_tick - existing.last_seen_tick > self.config.failure_timeout_ticks {
                if status_from_i32(existing.status) == Some(pb::StorageNodeStatus::Alive) {
                    log::warn!("Node {} suspected failed", node_id);
                    existing.status = pb::StorageNodeStatus::Suspected as i32;
                } else if status_from_i32(existing.status) == Some(pb::StorageNodeStatus::Suspected)
                {
                    log::warn!("Node {} marked dead", node_id);
                    existing.status = pb::StorageNodeStatus::Dead as i32;
                }
            }
        }
    }

    /// Send gossip messages to other nodes
    #[allow(clippy::disallowed_methods)]
    pub async fn send_gossip(
        &self,
        alive_nodes: Vec<pb::StorageNodeInfoV1>,
        now_tick: i64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if alive_nodes.len() <= 1 {
            return Ok(()); // No other nodes to gossip with
        }

        // Select gossip targets
        let local_b32 = self.local_node_id.to_base32();
        let gossip_targets: Vec<_> = alive_nodes
            .into_iter()
            .filter(|node| node.node_id != local_b32)
            .take(self.config.gossip_fanout)
            .collect();

        let gossip_payload = {
            let states = match self.node_states.read() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    log::error!(
                        "Node states lock poisoned (read for gossip); continuing with inner state"
                    );
                    poisoned.into_inner()
                }
            };
            let mut nodes: Vec<pb::StorageNodeInfoV1> = states.values().cloned().collect();
            nodes.sort_by_key(node_sort_key);
            let gossip_msg = pb::GossipMessageV1 {
                sender_node_id: local_b32.clone(),
                sender_tick: now_tick,
                node_states: nodes,
            };
            let mut buf = Vec::with_capacity(gossip_msg.encoded_len());
            gossip_msg.encode(&mut buf)?;
            buf
        };

        for target in gossip_targets {
            let url = format!("{}/gossip", target.address);

            match self
                .client
                .post(&url)
                .header("content-type", "application/octet-stream")
                .body(gossip_payload.clone())
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    log::debug!("Gossip sent to {}", target.node_id);
                }
                Ok(resp) => {
                    log::warn!(
                        "Gossip failed to {}: status {}",
                        target.node_id,
                        resp.status()
                    );
                }
                Err(e) => {
                    log::warn!("Gossip error to {}: {}", target.node_id, e);
                }
            }
        }

        Ok(())
    }

    /// Periodic maintenance: send gossip. A node never places or copies
    /// objects to peers it chooses; who holds what is the storage set's.
    pub fn maintenance_cycle(
        &self,
        #[allow(unused_variables)] state: Arc<AppState>,
        now_tick: i64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Send gossip if it's time
        if now_tick % self.config.gossip_interval_ticks == 0 {
            let alive_nodes = self.get_alive_nodes();
            let replication_manager = self.clone();
            tokio::spawn(async move {
                if let Err(e) = replication_manager.send_gossip(alive_nodes, now_tick).await {
                    log::error!("Gossip failed: {}", e);
                }
            });
        }

        Ok(())
    }
}

/// Default production replication configuration
pub fn default_production_config() -> ReplicationConfig {
    ReplicationConfig {
        replication_factor: 3,
        gossip_interval_ticks: 100,  // Every 100 ticks
        failure_timeout_ticks: 1000, // 10x gossip interval
        gossip_fanout: 3,
        max_concurrent_jobs: 10,
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use dsm::types::proto as pb;

    fn must<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        match result {
            Ok(value) => value,
            Err(err) => panic!("unexpected error: {err:?}"),
        }
    }

    fn must_some<T>(value: Option<T>, context: &str) -> T {
        match value {
            Some(value) => value,
            None => panic!("{context}"),
        }
    }

    fn test_config() -> ReplicationConfig {
        ReplicationConfig {
            replication_factor: 2,
            gossip_interval_ticks: 10,
            failure_timeout_ticks: 50,
            gossip_fanout: 2,
            max_concurrent_jobs: 5,
        }
    }

    fn make_manager(node_id: &str, addr: &str) -> ReplicationManager {
        must(ReplicationManager::new_for_tests(
            test_config(),
            node_id.to_string(),
            addr.to_string(),
        ))
    }

    fn node_id_for_addr(addr: &str) -> String {
        StorageNodeId::derive(addr.as_bytes()).to_base32()
    }

    #[test]
    fn default_production_config_values() {
        let cfg = default_production_config();
        assert_eq!(cfg.replication_factor, 3);
        assert_eq!(cfg.gossip_interval_ticks, 100);
        assert_eq!(cfg.failure_timeout_ticks, 1000);
        assert_eq!(cfg.gossip_fanout, 3);
        assert_eq!(cfg.max_concurrent_jobs, 10);
    }

    #[test]
    fn status_from_i32_parses_known_variants() {
        assert_eq!(
            status_from_i32(pb::StorageNodeStatus::Alive as i32),
            Some(pb::StorageNodeStatus::Alive)
        );
        assert_eq!(
            status_from_i32(pb::StorageNodeStatus::Suspected as i32),
            Some(pb::StorageNodeStatus::Suspected)
        );
        assert_eq!(
            status_from_i32(pb::StorageNodeStatus::Dead as i32),
            Some(pb::StorageNodeStatus::Dead)
        );
    }

    #[test]
    fn status_from_i32_rejects_invalid() {
        assert_eq!(status_from_i32(999), None);
        assert_eq!(status_from_i32(-1), None);
    }

    #[test]
    fn new_for_tests_initializes_local_node_alive() {
        let mgr = make_manager("node-1", "http://127.0.0.1:8080");
        let alive = mgr.get_alive_nodes();
        assert_eq!(alive.len(), 1);
        assert_eq!(alive[0].node_id, node_id_for_addr("http://127.0.0.1:8080"));
        assert!(StorageNodeId::from_base32(&alive[0].node_id).is_some());
        assert_eq!(alive[0].address, "http://127.0.0.1:8080");
        assert_eq!(alive[0].status, pb::StorageNodeStatus::Alive as i32);
    }

    #[test]
    fn get_alive_nodes_excludes_dead_and_suspected() {
        let mgr = make_manager("node-local", "http://127.0.0.1:8080");
        {
            let mut states = must(mgr.node_states.write());
            let dead_id = node_id_for_addr("http://127.0.0.1:8081");
            states.insert(
                dead_id.clone(),
                pb::StorageNodeInfoV1 {
                    node_id: dead_id,
                    address: "http://127.0.0.1:8081".to_string(),
                    last_seen_tick: 0,
                    status: pb::StorageNodeStatus::Dead as i32,
                },
            );
            let suspected_id = node_id_for_addr("http://127.0.0.1:8082");
            states.insert(
                suspected_id.clone(),
                pb::StorageNodeInfoV1 {
                    node_id: suspected_id,
                    address: "http://127.0.0.1:8082".to_string(),
                    last_seen_tick: 0,
                    status: pb::StorageNodeStatus::Suspected as i32,
                },
            );
            let alive_id = node_id_for_addr("http://127.0.0.1:8083");
            states.insert(
                alive_id.clone(),
                pb::StorageNodeInfoV1 {
                    node_id: alive_id,
                    address: "http://127.0.0.1:8083".to_string(),
                    last_seen_tick: 0,
                    status: pb::StorageNodeStatus::Alive as i32,
                },
            );
        }
        let alive = mgr.get_alive_nodes();
        assert_eq!(alive.len(), 2);
        let ids: Vec<&str> = alive.iter().map(|n| n.node_id.as_str()).collect();
        let alive_id = node_id_for_addr("http://127.0.0.1:8083");
        let local_b32 = mgr.local_node_id.to_base32();
        assert!(ids.contains(&local_b32.as_str()));
        assert!(ids.contains(&alive_id.as_str()));
    }

    #[tokio::test]
    async fn process_gossip_adds_new_nodes() {
        let mgr = make_manager("node-local", "http://127.0.0.1:8080");
        let remote_id = node_id_for_addr("http://127.0.0.1:9090");
        let gossip = pb::GossipMessageV1 {
            sender_node_id: remote_id.clone(),
            sender_tick: 10,
            node_states: vec![pb::StorageNodeInfoV1 {
                node_id: remote_id,
                address: "http://127.0.0.1:9090".to_string(),
                last_seen_tick: 10,
                status: pb::StorageNodeStatus::Alive as i32,
            }],
        };
        mgr.process_gossip(gossip, 10).await;
        let alive = mgr.get_alive_nodes();
        assert_eq!(alive.len(), 2);
    }

    #[tokio::test]
    async fn process_gossip_ignores_own_node_id() {
        let mgr = make_manager("node-local", "http://127.0.0.1:8080");
        let gossip = pb::GossipMessageV1 {
            sender_node_id: "node-remote".to_string(),
            sender_tick: 10,
            node_states: vec![pb::StorageNodeInfoV1 {
                node_id: mgr.local_node_id.to_base32(),
                address: "http://attacker:6666".to_string(),
                last_seen_tick: 10,
                status: pb::StorageNodeStatus::Dead as i32,
            }],
        };
        mgr.process_gossip(gossip, 10).await;
        let alive = mgr.get_alive_nodes();
        assert_eq!(alive.len(), 1);
        assert_eq!(alive[0].address, "http://127.0.0.1:8080");
    }

    #[tokio::test]
    async fn process_gossip_suspects_stale_nodes() {
        let mgr = make_manager("node-local", "http://127.0.0.1:8080");
        let remote_id = node_id_for_addr("http://127.0.0.1:9090");
        let gossip = pb::GossipMessageV1 {
            sender_node_id: remote_id.clone(),
            sender_tick: 5,
            node_states: vec![pb::StorageNodeInfoV1 {
                node_id: remote_id.clone(),
                address: "http://127.0.0.1:9090".to_string(),
                last_seen_tick: 5,
                status: pb::StorageNodeStatus::Alive as i32,
            }],
        };
        // Process gossip at tick=5 first to insert the node
        mgr.process_gossip(gossip, 5).await;

        // Now process again at tick far in the future (beyond failure_timeout_ticks=50)
        let gossip2 = pb::GossipMessageV1 {
            sender_node_id: "other".to_string(),
            sender_tick: 100,
            node_states: vec![pb::StorageNodeInfoV1 {
                node_id: remote_id.clone(),
                address: "http://127.0.0.1:9090".to_string(),
                last_seen_tick: 5, // stale
                status: pb::StorageNodeStatus::Alive as i32,
            }],
        };
        mgr.process_gossip(gossip2, 100).await;

        let states = must(mgr.node_states.read());
        let remote = must_some(states.get(&remote_id), "remote node should exist");
        assert_eq!(remote.status, pb::StorageNodeStatus::Suspected as i32);
    }

    #[tokio::test]
    async fn process_gossip_marks_suspected_as_dead() {
        let mgr = make_manager("node-local", "http://127.0.0.1:8080");
        let stale_id = node_id_for_addr("http://127.0.0.1:9091");
        {
            let mut states = must(mgr.node_states.write());
            states.insert(
                stale_id.clone(),
                pb::StorageNodeInfoV1 {
                    node_id: stale_id.clone(),
                    address: "http://127.0.0.1:9091".to_string(),
                    last_seen_tick: 1,
                    status: pb::StorageNodeStatus::Suspected as i32,
                },
            );
        }
        let gossip = pb::GossipMessageV1 {
            sender_node_id: "other".to_string(),
            sender_tick: 200,
            node_states: vec![pb::StorageNodeInfoV1 {
                node_id: stale_id.clone(),
                address: "http://127.0.0.1:9091".to_string(),
                last_seen_tick: 1,
                status: pb::StorageNodeStatus::Suspected as i32,
            }],
        };
        mgr.process_gossip(gossip, 200).await;

        let states = must(mgr.node_states.read());
        let stale = must_some(states.get(&stale_id), "stale node should exist");
        assert_eq!(stale.status, pb::StorageNodeStatus::Dead as i32);
    }

    #[tokio::test]
    async fn process_gossip_updates_last_seen_tick_to_max() {
        let mgr = make_manager("node-local", "http://127.0.0.1:8080");
        let node_b_id = node_id_for_addr("http://127.0.0.1:9091");
        {
            let mut states = must(mgr.node_states.write());
            states.insert(
                node_b_id.clone(),
                pb::StorageNodeInfoV1 {
                    node_id: node_b_id.clone(),
                    address: "http://127.0.0.1:9091".to_string(),
                    last_seen_tick: 50,
                    status: pb::StorageNodeStatus::Alive as i32,
                },
            );
        }
        // Gossip with an older tick should not regress last_seen_tick
        let gossip = pb::GossipMessageV1 {
            sender_node_id: "other".to_string(),
            sender_tick: 30,
            node_states: vec![pb::StorageNodeInfoV1 {
                node_id: node_b_id.clone(),
                address: "http://127.0.0.1:9091".to_string(),
                last_seen_tick: 30,
                status: pb::StorageNodeStatus::Alive as i32,
            }],
        };
        mgr.process_gossip(gossip, 30).await;

        let states = must(mgr.node_states.read());
        let b = must_some(states.get(&node_b_id), "node-b should exist");
        assert_eq!(b.last_seen_tick, 50); // should keep max(50, 30)
    }
}
