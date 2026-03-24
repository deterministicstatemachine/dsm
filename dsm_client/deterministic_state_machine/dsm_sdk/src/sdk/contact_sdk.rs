// SPDX-License-Identifier: MIT OR Apache-2.0
//! DSM Contact SDK (proto-only, bytes-only)
//! - No Base64
//! - No hex
//! - No JSON
//!
//! UI layers may encode/decode whole protobuf blobs for display/QR only.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result as AnyResult;
use blake3::Hasher;
use prost::Message;
use tokio::sync::RwLock;

use dsm::core::contact_manager::{ContactError, DsmContactManager};
use dsm::core::state_machine::transition::StateTransition;
use dsm::types::error::DsmError;
use dsm::types::identifiers::NodeId;
use dsm::types::operations::{Operation, TransactionMode};
use dsm::types::state_types::State;

// Use the SAME proto namespace as the rest of the app to avoid type mismatches.
use dsm::types::proto as pb;

use crate::util::deterministic_time as dt;

#[derive(Debug, Clone)]
pub struct ContactManager {
    dsm_manager: Arc<RwLock<DsmContactManager>>,
    pub groups: HashMap<String, Vec<[u8; 32]>>,
    pub device_id: [u8; 32],
    pub genesis_hash: [u8; 32],
}

pub type ContactSDK = ContactManager;

impl ContactManager {
    fn with_manager_write_sync<R, F>(&self, op_name: &str, f: F) -> Result<R, DsmError>
    where
        R: Send,
        F: FnOnce(&mut DsmContactManager) -> Result<R, DsmError> + Send,
    {
        let mgr = self.dsm_manager.clone();
        std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    let mut guard = mgr.blocking_write();
                    f(&mut guard)
                })
                .join()
                .map_err(|_| {
                    DsmError::internal(
                        format!("Thread panicked in {op_name}"),
                        None::<std::io::Error>,
                    )
                })?
        })
    }

    fn compute_initial_chain_tip(
        &self,
        contact_device_id: [u8; 32],
        contact_genesis_hash: [u8; 32],
    ) -> [u8; 32] {
        // h_0 = dsm_domain_hasher("DSM/bilateral-session") || sorted(G_A, DevID_A, G_B, DevID_B)
        // Lexicographic ordering ensures identical hash regardless of initiator.
        // MUST stay in sync with initial_relationship_chain_tip() in bilateral_transaction_manager.rs.
        let our_device_id = self.device_id;
        let our_genesis = self.genesis_hash;

        let (genesis_a, device_a, genesis_b, device_b) = if our_device_id < contact_device_id {
            (
                our_genesis,
                our_device_id,
                contact_genesis_hash,
                contact_device_id,
            )
        } else {
            (
                contact_genesis_hash,
                contact_device_id,
                our_genesis,
                our_device_id,
            )
        };

        // MUST match initial_relationship_chain_tip() in bilateral_transaction_manager.rs exactly.
        // Using dsm_domain_hasher("DSM/bilateral-session") — not a raw blake3 hasher with a
        // manually-injected tag — because dsm_domain_hasher derives a keyed context from the
        // tag string, producing a different output than treating the tag as plain data.
        let mut hasher = dsm::crypto::blake3::dsm_domain_hasher("DSM/bilateral-session");
        hasher.update(&genesis_a);
        hasher.update(&device_a);
        hasher.update(&genesis_b);
        hasher.update(&device_b);

        let hash = hasher.finalize();
        let mut tip = [0u8; 32];
        tip.copy_from_slice(hash.as_bytes());
        tip
    }

    pub fn new_with_storage_nodes(
        device_id: [u8; 32],
        genesis_hash: [u8; 32],
        storage_nodes: Vec<String>,
    ) -> Self {
        let node_ids: Vec<NodeId> = storage_nodes.into_iter().map(NodeId::new).collect();
        let dsm_manager = Arc::new(RwLock::new(DsmContactManager::new(
            device_id,
            node_ids.clone(),
        )));

        let mut instance = Self {
            dsm_manager,
            groups: HashMap::new(),
            device_id,
            genesis_hash,
        };

        // Load persisted contacts from database on startup
        instance.load_contacts_from_database();

        instance
    }

    /// Load persisted contacts from SQLite database on startup
    fn load_contacts_from_database(&mut self) {
        use crate::storage::client_db::get_all_contacts;

        log::info!("[DSM_SDK] 🔄 Loading contacts from SQLite database...");

        match get_all_contacts() {
            Ok(records) => {
                let total_count = records.len();
                log::info!("[DSM_SDK] 📚 Found {} contacts in database", total_count);

                let mut loaded_count = 0;
                for record in records {
                    // Convert ContactRecord to DsmVerifiedContact
                    if record.device_id.len() != 32 {
                        log::warn!(
                            "[DSM_SDK] ⚠️ Skipping contact '{}' with invalid device_id length {}",
                            record.alias,
                            record.device_id.len()
                        );
                        continue;
                    }
                    if record.genesis_hash.len() != 32 {
                        log::warn!("[DSM_SDK] ⚠️ Skipping contact '{}' with invalid genesis_hash length {}",
                            record.alias, record.genesis_hash.len());
                        continue;
                    }

                    let mut device_id = [0u8; 32];
                    let mut genesis_hash = [0u8; 32];
                    device_id.copy_from_slice(&record.device_id);
                    genesis_hash.copy_from_slice(&record.genesis_hash);

                    let verified_contact = dsm::types::contact_types::DsmVerifiedContact {
                        alias: record.alias.clone(),
                        device_id,
                        genesis_hash,
                        public_key: record.public_key.clone(),
                        genesis_material: Vec::new(),
                        chain_tip: record.current_chain_tip.as_ref().map(|tip| {
                            let mut hash = [0u8; 32];
                            if tip.len() == 32 {
                                hash.copy_from_slice(tip);
                            }
                            hash
                        }),
                        chain_tip_smt_proof: None,
                        genesis_verified_online: record.verified,
                        verified_at_commit_height: record.added_at,
                        added_at_commit_height: record.added_at,
                        last_updated_commit_height: record.added_at,
                        verifying_storage_nodes: Vec::new(),
                        ble_address: record.ble_address.clone(),
                    };

                    let smt_arc = crate::security::shared_smt::init_shared_smt(256);
                    let own_device_id = self.device_id;
                    let load_result =
                        self.with_manager_write_sync("load_contacts_from_database", move |mgr| {
                            mgr.add_verified_contact(verified_contact.clone())?;
                            if let Some(chain_tip) = verified_contact.chain_tip {
                                let smt = smt_arc.blocking_read();
                                let smt_key =
                                    dsm::core::bilateral_transaction_manager::compute_smt_key(
                                        &own_device_id,
                                        &device_id,
                                    );
                                mgr.initialize_contact_chain_tip(
                                    &device_id, chain_tip, &smt, &smt_key,
                                )
                                .map_err(|e| {
                                    DsmError::internal(
                                        "Failed to initialize contact chain tip",
                                        Some(e),
                                    )
                                })?;
                            }
                            Ok(())
                        });

                    if let Err(e) = load_result {
                        log::warn!(
                            "[DSM_SDK] ⚠️ Failed to load contact '{}' from database: {}",
                            record.alias,
                            e
                        );
                    } else {
                        loaded_count += 1;
                        log::info!(
                            "[DSM_SDK] ✅ Loaded contact '{}' from database",
                            record.alias
                        );
                    }
                }

                log::info!(
                    "[DSM_SDK] 🎉 Successfully loaded {}/{} contacts from database",
                    loaded_count,
                    total_count
                );
            }
            Err(e) => {
                log::warn!("[DSM_SDK] ⚠️ Failed to load contacts from database: {}", e);
                // Non-fatal: continue with empty contact list
            }
        }
    }

    pub fn new_with_default_storage_nodes(device_id: [u8; 32], genesis_hash: [u8; 32]) -> Self {
        let defaults = match std::env::var("DSM_STORAGE_LAN_IP") {
            Ok(lan_ip) if !lan_ip.trim().is_empty() => vec![
                format!("http://{lan_ip}:8080"),
                format!("http://{lan_ip}:8081"),
                format!("http://{lan_ip}:8082"),
            ],
            _ => {
                log::warn!("ContactSDK: no DSM_STORAGE_LAN_IP set; storage nodes empty");
                Vec::new()
            }
        };
        Self::new_with_storage_nodes(device_id, genesis_hash, defaults)
    }

    /// Add a contact when you already trust/verified the genesis payload bytes.
    pub async fn add_contact_with_verified_genesis(
        &mut self,
        contact_device_id: [u8; 32],
        alias: &str,
        genesis_payload: &[u8],
    ) -> Result<pb::ContactAddResponse, ContactError> {
        self.add_contact_with_verified_genesis_and_ble(
            contact_device_id,
            alias,
            genesis_payload,
            None,
            Vec::new(),
            Vec::new(),
        )
        .await
    }

    /// Add a contact with optional BLE address for offline transfers
    pub async fn add_contact_with_verified_genesis_and_ble(
        &mut self,
        contact_device_id: [u8; 32],
        alias: &str,
        genesis_payload: &[u8],
        ble_address: Option<String>,
        signing_public_key: Vec<u8>,
        verifying_nodes: Vec<NodeId>,
    ) -> Result<pb::ContactAddResponse, ContactError> {
        // Compute canonical genesis hash (BLAKE3-256).
        let h = dsm::crypto::blake3::domain_hash("DSM/contact-genesis", genesis_payload);
        let mut gh = [0u8; 32];
        gh.copy_from_slice(h.as_bytes());

        // Deterministic initial relationship tip (h_0) for this contact.
        let initial_chain_tip = self.compute_initial_chain_tip(contact_device_id, gh);

        // Deterministic counters: advance exactly once for this event.
        let _now: u64 = dt::tick();

        // Persist into core
        let verified = dsm::types::contact_types::DsmVerifiedContact {
            alias: alias.to_string(),
            device_id: contact_device_id,
            genesis_hash: gh,
            public_key: signing_public_key.clone(),
            genesis_material: genesis_payload.to_vec(),
            chain_tip: Some(initial_chain_tip),
            chain_tip_smt_proof: None,
            genesis_verified_online: true,
            verified_at_commit_height: _now,
            added_at_commit_height: _now,
            last_updated_commit_height: _now,
            verifying_storage_nodes: verifying_nodes.clone(),
            ble_address: ble_address.clone(),
        };
        {
            let smt_arc = crate::security::shared_smt::init_shared_smt(256);
            let smt = smt_arc.read().await;
            let smt_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
                &self.device_id,
                &contact_device_id,
            );
            let mut mgr = self.dsm_manager.write().await;
            mgr.add_verified_contact(verified.clone()).map_err(|e| {
                ContactError::InvalidContactData(format!("Core add_verified_contact failed: {e}"))
            })?;
            if let Err(e) = mgr.initialize_contact_chain_tip(
                &contact_device_id,
                initial_chain_tip,
                &smt,
                &smt_key,
            ) {
                return Err(ContactError::InvalidChainTip(format!(
                    "Failed to initialize chain tip SMT proof: {e}"
                )));
            }
        }

        // ✅ PRODUCTION FIX: Persist to SQLite for durability across restarts
        {
            use crate::storage::client_db::{store_contact, ContactRecord};
            use std::collections::HashMap;

            log::info!("[DSM_SDK] 📝 Persisting contact to SQLite: alias={}", alias);
            let hash_bytes = crate::util::domain_helpers::device_id_hash_bytes(&contact_device_id);
            let contact_id = format!(
                "c_{}",
                &crate::util::text_id::encode_base32_crockford(&hash_bytes)[..8]
            );

            let contact_record = ContactRecord {
                contact_id,
                device_id: contact_device_id.to_vec(),
                alias: alias.to_string(),
                genesis_hash: gh.to_vec(),
                // CRITICAL: Initialize chain_tip to deterministic relationship tip (h_0).
                current_chain_tip: Some(initial_chain_tip.to_vec()),
                added_at: _now,
                verified: true,
                verification_proof: None,
                metadata: HashMap::new(),
                ble_address: ble_address.clone(),
                status: "Created".to_string(),
                needs_online_reconcile: false,
                last_seen_online_counter: 0,
                last_seen_ble_counter: 0,
                public_key: signing_public_key.clone(),
                previous_chain_tip: None,
            };

            match store_contact(&contact_record) {
                Ok(_) => {
                    if let Err(e) = crate::storage::client_db::update_local_bilateral_chain_tip(
                        &contact_device_id,
                        &initial_chain_tip,
                    ) {
                        log::warn!(
                            "[DSM_SDK] ⚠️ Failed to persist initial local bilateral chain tip: {}",
                            e
                        );
                    }
                    log::info!("[DSM_SDK] ✅ Contact stored successfully in SQLite");

                    // Mark device as paired to persist BLE connection in Android layer
                    #[allow(unused_variables)]
                    if let Some(ref addr) = ble_address {
                        #[cfg(all(target_os = "android", feature = "bluetooth"))]
                        {
                            use crate::bluetooth::mark_device_as_paired;
                            if let Err(e) = mark_device_as_paired(addr) {
                                log::warn!("[DSM_SDK] ⚠️ Failed to mark device as paired: {}", e);
                                // Non-fatal: contact is still stored
                            } else {
                                log::info!("[DSM_SDK] ✅ Device marked as paired: {}", addr);
                            }
                        }
                    }
                }
                Err(e) => {
                    log::warn!("[DSM_SDK] ⚠️ Failed to persist contact to SQLite: {}", e);
                    // Non-fatal: contact is still in memory
                }
            }
        }

        // Read back (authoritative)
        let stored = {
            let mgr = self.dsm_manager.read().await;
            mgr.get_contact(&contact_device_id).cloned()
        };

        let (
            alias,
            device_id,
            genesis_hash,
            chain_tip,
            verified_online,
            verified_at,
            added_at,
            nodes,
        ) = if let Some(ref c) = stored {
            (
                c.alias.clone(),
                c.device_id.to_vec(),
                c.genesis_hash.to_vec(),
                c.chain_tip.map(|h| h.to_vec()),
                c.genesis_verified_online,
                c.verified_at_commit_height,
                c.added_at_commit_height,
                c.verifying_storage_nodes
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>(),
            )
        } else {
            (
                alias.to_string(),
                contact_device_id.to_vec(),
                gh.to_vec(),
                Some(initial_chain_tip.to_vec()),
                true,
                _now,
                _now,
                Vec::new(),
            )
        };

        Ok(pb::ContactAddResponse {
            alias,
            device_id,
            genesis_hash: Some(pb::Hash32 { v: genesis_hash }),
            chain_tip: chain_tip.map(|h| pb::Hash32 { v: h }),
            chain_tip_smt_proof: None,
            alias_binding: None,
            genesis_verified_online: verified_online,
            verify_counter: verified_at,
            added_counter: added_at,
            verifying_storage_nodes: nodes,
            ble_address: ble_address.unwrap_or_default(),
            signing_public_key: stored
                .as_ref()
                .map(|c| c.public_key.clone())
                .unwrap_or_else(|| signing_public_key.clone()),
        })
    }

    /// Add a contact when you have an expected genesis hash (bytes) and the payload (bytes).
    pub async fn add_contact_with_genesis_and_hash(
        &mut self,
        contact_device_id: [u8; 32],
        alias: &str,
        expected_genesis_hash: [u8; 32],
        genesis_payload: &[u8],
    ) -> Result<pb::ContactAddResponse, ContactError> {
        self.add_contact_with_genesis_and_hash_and_signing_key(
            contact_device_id,
            alias,
            expected_genesis_hash,
            genesis_payload,
            Vec::new(),
            Vec::new(),
        )
        .await
    }

    /// Add a contact when you have an expected genesis hash (bytes), the payload (bytes),
    /// and the signing public key.
    pub async fn add_contact_with_genesis_and_hash_and_signing_key(
        &mut self,
        contact_device_id: [u8; 32],
        alias: &str,
        expected_genesis_hash: [u8; 32],
        genesis_payload: &[u8],
        signing_public_key: Vec<u8>,
        verifying_nodes: Vec<NodeId>,
    ) -> Result<pb::ContactAddResponse, ContactError> {
        let computed = dsm::crypto::blake3::domain_hash("DSM/contact-genesis", genesis_payload);
        if computed.as_bytes() != &expected_genesis_hash {
            return Err(ContactError::GenesisVerificationFailed(
                "Genesis hash mismatch".to_string(),
            ));
        }
        self.add_contact_with_verified_genesis_and_ble(
            contact_device_id,
            alias,
            genesis_payload,
            None,
            signing_public_key,
            verifying_nodes,
        )
        .await
    }

    /// Strict path: add a contact when a quorum (≥3) of storage nodes has attested
    /// the counterparty's genesis hash equals expected_genesis_hash.
    /// No local payload preimage is required; we persist empty genesis_material and
    /// record verifying_storage_nodes.
    pub async fn add_contact_with_verified_hash_from_nodes(
        &mut self,
        contact_device_id: [u8; 32],
        alias: &str,
        expected_genesis_hash: [u8; 32],
        verifying_nodes: Vec<NodeId>,
    ) -> Result<pb::ContactAddResponse, ContactError> {
        self.add_contact_with_verified_hash_from_nodes_and_ble(
            contact_device_id,
            alias,
            expected_genesis_hash,
            verifying_nodes,
            None,
            Vec::new(),
        )
        .await
    }

    /// Strict path with signing key (no BLE address)
    pub async fn add_contact_with_verified_hash_from_nodes_and_signing_key(
        &mut self,
        contact_device_id: [u8; 32],
        alias: &str,
        expected_genesis_hash: [u8; 32],
        verifying_nodes: Vec<NodeId>,
        signing_public_key: Vec<u8>,
    ) -> Result<pb::ContactAddResponse, ContactError> {
        self.add_contact_with_verified_hash_from_nodes_and_ble(
            contact_device_id,
            alias,
            expected_genesis_hash,
            verifying_nodes,
            None,
            signing_public_key,
        )
        .await
    }

    /// Strict path with optional BLE address for offline transfers
    pub async fn add_contact_with_verified_hash_from_nodes_and_ble(
        &mut self,
        contact_device_id: [u8; 32],
        alias: &str,
        expected_genesis_hash: [u8; 32],
        verifying_nodes: Vec<NodeId>,
        ble_address: Option<String>,
        signing_public_key: Vec<u8>,
    ) -> Result<pb::ContactAddResponse, ContactError> {
        if verifying_nodes.len() < 3 {
            return Err(ContactError::GenesisVerificationFailed(
                "Insufficient verifying nodes (need ≥3)".to_string(),
            ));
        }

        let _now: u64 = dt::tick();

        let initial_chain_tip =
            self.compute_initial_chain_tip(contact_device_id, expected_genesis_hash);
        log::info!("[DSM_SDK] ✅ Created initial chain tip for bilateral relationship");

        let verified = dsm::types::contact_types::DsmVerifiedContact {
            alias: alias.to_string(),
            device_id: contact_device_id,
            genesis_hash: expected_genesis_hash,
            public_key: signing_public_key.clone(),
            genesis_material: Vec::new(),
            chain_tip: Some(initial_chain_tip),
            chain_tip_smt_proof: None,
            genesis_verified_online: true,
            verified_at_commit_height: _now,
            added_at_commit_height: _now,
            last_updated_commit_height: _now,
            verifying_storage_nodes: verifying_nodes.clone(),
            ble_address: ble_address.clone(),
        };
        {
            let smt_arc = crate::security::shared_smt::init_shared_smt(256);
            let smt = smt_arc.read().await;
            let smt_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
                &self.device_id,
                &contact_device_id,
            );
            let mut mgr = self.dsm_manager.write().await;
            log::info!(
                "[DSM_SDK] ➕ Adding contact to in-memory HashMap: alias={}",
                alias
            );
            mgr.add_verified_contact(verified.clone()).map_err(|e| {
                ContactError::InvalidContactData(format!("Core add_verified_contact failed: {e}"))
            })?;
            if let Err(e) = mgr.initialize_contact_chain_tip(
                &contact_device_id,
                initial_chain_tip,
                &smt,
                &smt_key,
            ) {
                return Err(ContactError::InvalidChainTip(format!(
                    "Failed to initialize chain tip SMT proof: {e}"
                )));
            }
            log::info!("[DSM_SDK] ✅ Contact added to HashMap successfully");
        }

        // ✅ Verify it's in the HashMap
        {
            let mgr = self.dsm_manager.read().await;
            let count = mgr.list_contacts().len();
            log::info!(
                "[DSM_SDK] 📊 Total contacts in HashMap after add: {}",
                count
            );
        }

        // ✅ PRODUCTION FIX: Persist to SQLite for durability across restarts
        {
            use crate::storage::client_db::{store_contact, ContactRecord};
            use std::collections::HashMap;

            log::info!("[DSM_SDK] 📝 Persisting contact to SQLite: alias={}", alias);
            let hash_bytes = crate::util::domain_helpers::device_id_hash_bytes(&contact_device_id);
            let contact_id = format!(
                "c_{}",
                &crate::util::text_id::encode_base32_crockford(&hash_bytes)[..8]
            );
            log::info!("[DSM_SDK] 📝 Generated contact_id: {}", contact_id);

            let contact_record = ContactRecord {
                contact_id,
                device_id: contact_device_id.to_vec(),
                alias: alias.to_string(),
                genesis_hash: expected_genesis_hash.to_vec(),
                // CRITICAL: Initialize chain_tip to deterministic relationship tip (h_0).
                current_chain_tip: Some(initial_chain_tip.to_vec()),
                added_at: _now,
                verified: true,
                verification_proof: None,
                metadata: HashMap::new(),
                ble_address: ble_address.clone(),
                status: "Created".to_string(),
                needs_online_reconcile: false,
                last_seen_online_counter: 0,
                last_seen_ble_counter: 0,
                public_key: signing_public_key.clone(),
                previous_chain_tip: None,
            };

            log::info!("[DSM_SDK] 📝 Calling store_contact()...");
            match store_contact(&contact_record) {
                Ok(_) => {
                    log::info!("[DSM_SDK] ✅ Contact stored successfully in SQLite");
                    if let Err(e) = crate::storage::client_db::update_local_bilateral_chain_tip(
                        &contact_device_id,
                        &initial_chain_tip,
                    ) {
                        log::error!(
                            "[DSM_SDK] ❌ Failed to persist initial local bilateral chain tip: {}",
                            e
                        );
                        return Err(ContactError::InvalidChainTip(format!(
                            "Failed to persist initial local bilateral chain tip: {e}"
                        )));
                    }

                    // Mark device as paired to persist BLE connection in Android layer
                    #[allow(unused_variables)]
                    if let Some(ref addr) = ble_address {
                        #[cfg(all(target_os = "android", feature = "bluetooth"))]
                        {
                            use crate::bluetooth::mark_device_as_paired;
                            if let Err(e) = mark_device_as_paired(addr) {
                                log::warn!("[DSM_SDK] ⚠️ Failed to mark device as paired: {}", e);
                                // Non-fatal: contact is still stored
                            } else {
                                log::info!("[DSM_SDK] ✅ Device marked as paired: {}", addr);
                            }
                        }
                    }
                }
                Err(e) => {
                    log::error!("[DSM_SDK] ❌ SQLite persistence failed: {}", e);
                    return Err(ContactError::InvalidContactData(format!(
                        "SQLite persistence failed: {e}"
                    )));
                }
            }
        }

        // Read back (authoritative)
        let stored = {
            let mgr = self.dsm_manager.read().await;
            mgr.get_contact(&contact_device_id).cloned()
        };

        let (
            alias,
            device_id,
            genesis_hash,
            chain_tip,
            verified_online,
            verified_at,
            added_at,
            nodes,
        ) = if let Some(ref c) = stored {
            (
                c.alias.clone(),
                c.device_id.to_vec(),
                c.genesis_hash.to_vec(),
                c.chain_tip.map(|h| h.to_vec()),
                c.genesis_verified_online,
                c.verified_at_commit_height,
                c.added_at_commit_height,
                c.verifying_storage_nodes
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>(),
            )
        } else {
            (
                alias.to_string(),
                contact_device_id.to_vec(),
                expected_genesis_hash.to_vec(),
                Some(initial_chain_tip.to_vec()),
                true,
                _now,
                _now,
                verifying_nodes.into_iter().map(|n| n.to_string()).collect(),
            )
        };

        Ok(pb::ContactAddResponse {
            alias,
            device_id,
            genesis_hash: Some(pb::Hash32 { v: genesis_hash }),
            chain_tip: chain_tip.map(|h| pb::Hash32 { v: h }),
            chain_tip_smt_proof: None,
            alias_binding: None,
            genesis_verified_online: verified_online,
            verify_counter: verified_at,
            added_counter: added_at,
            verifying_storage_nodes: nodes,
            ble_address: ble_address.unwrap_or_default(),
            signing_public_key: stored
                .as_ref()
                .map(|c| c.public_key.clone())
                .unwrap_or_else(|| signing_public_key.clone()),
        })
    }

    pub async fn get_verified_contact(
        &self,
        device_id: [u8; 32],
    ) -> Option<dsm::types::contact_types::DsmVerifiedContact> {
        let mgr = self.dsm_manager.read().await;
        mgr.get_contact(&device_id).cloned()
    }

    pub async fn can_perform_bilateral_transaction(
        &self,
        device_id: [u8; 32],
    ) -> Result<bool, ContactError> {
        let mgr = self.dsm_manager.read().await;
        if let Some(c) = mgr.get_contact(&device_id) {
            Ok(c.can_perform_bilateral_transaction())
        } else {
            Err(ContactError::ContactNotFound)
        }
    }

    pub async fn update_contact_chain_tip_unilateral(
        &mut self,
        contact_device_id: [u8; 32],
        expected_parent_tip: [u8; 32],
        new_chain_tip: [u8; 32],
    ) -> Result<(), ContactError> {
        // §4.2: SMT-Replace is mandatory for every state transition.
        let smt_arc = crate::security::shared_smt::get_shared_smt().ok_or(
            ContactError::InvalidContactData(
                "Per-Device SMT not initialized — cannot produce valid proof (§4.2)".into(),
            ),
        )?;
        let smt = smt_arc.read().await;
        let smt_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
            &self.device_id,
            &contact_device_id,
        );
        let mut mgr = self.dsm_manager.write().await;
        mgr.update_contact_chain_tip_unilateral(&contact_device_id, new_chain_tip, &smt, &smt_key)?;

        match crate::storage::client_db::try_advance_finalized_bilateral_chain_tip(
            &contact_device_id,
            &expected_parent_tip,
            &new_chain_tip,
        ) {
            Ok(true) => {}
            Ok(false) => {
                return Err(ContactError::InvalidChainTip(
                    "Finalized unilateral chain tip parent mismatch".to_string(),
                ));
            }
            Err(e) => {
                return Err(ContactError::InvalidChainTip(format!(
                    "Failed to persist finalized unilateral chain tip update: {e}"
                )));
            }
        }

        Ok(())
    }

    pub async fn list_verified_contacts(
        &self,
    ) -> Vec<dsm::types::contact_types::DsmVerifiedContact> {
        use crate::storage::client_db::get_contact_by_device_id;

        let mgr = self.dsm_manager.read().await;
        let mut out: Vec<dsm::types::contact_types::DsmVerifiedContact> =
            Vec::with_capacity(mgr.list_contacts().len());

        // Overlay persisted fields (e.g., ble_address) from SQLite onto the in-memory contacts
        // so callers like contacts.list see the latest BLE readiness without requiring a restart
        // or a separate in-memory mutation hook.
        let contacts = mgr.list_contacts();
        for mut cc in contacts.into_iter().cloned() {
            // Fetch persisted record; best-effort overlay
            match get_contact_by_device_id(&cc.device_id) {
                Ok(Some(rec)) => {
                    if rec.ble_address.is_some() {
                        cc.ble_address = rec.ble_address.clone();
                    }
                    // If in the future more persisted fields must override memory, add here.
                }
                Ok(None) => {
                    // No persisted record found; leave as-is
                }
                Err(e) => {
                    log::debug!(
                        "[DSM_SDK] list_verified_contacts: get_contact_by_device_id error: {}",
                        e
                    );
                }
            }
            out.push(cc);
        }

        out
    }

    /// Restore a contact from persistent storage (used on app startup)
    pub async fn restore_contact_from_storage(
        &mut self,
        contact: dsm::types::contact_types::DsmVerifiedContact,
    ) -> Result<(), DsmError> {
        let mut mgr = self.dsm_manager.write().await;
        mgr.add_verified_contact(contact)
    }

    /// Synchronous version for app startup
    pub fn restore_contact_from_storage_sync(
        &mut self,
        contact: dsm::types::contact_types::DsmVerifiedContact,
    ) -> Result<(), DsmError> {
        self.with_manager_write_sync("restore_contact_from_storage_sync", move |mgr| {
            mgr.add_verified_contact(contact)
        })
    }

    pub async fn export_contacts(&self) -> Result<pb::ContactsListResponse, DsmError> {
        let mgr = self.dsm_manager.read().await;
        let contacts = mgr.list_contacts();
        let mut out: Vec<pb::ContactAddResponse> = Vec::with_capacity(contacts.len());

        for c in contacts {
            out.push(pb::ContactAddResponse {
                alias: c.alias.clone(),
                device_id: c.device_id.to_vec(),
                genesis_hash: Some(pb::Hash32 {
                    v: c.genesis_hash.to_vec(),
                }),
                chain_tip: c.chain_tip.map(|h| pb::Hash32 { v: h.to_vec() }),
                chain_tip_smt_proof: None,
                alias_binding: None,
                genesis_verified_online: c.genesis_verified_online,
                verify_counter: c.verified_at_commit_height,
                added_counter: c.added_at_commit_height,
                verifying_storage_nodes: c
                    .verifying_storage_nodes
                    .iter()
                    .map(|n| n.to_string())
                    .collect(),
                ble_address: c.ble_address.clone().unwrap_or_default(),
                signing_public_key: c.public_key.clone(),
            });
        }

        Ok(pb::ContactsListResponse { contacts: out })
    }

    pub fn add_to_group(&mut self, contact_device_id: [u8; 32], group: &str) {
        self.groups
            .entry(group.to_string())
            .or_default()
            .push(contact_device_id);
    }

    pub fn get_group(&self, group: &str) -> Option<&Vec<[u8; 32]>> {
        self.groups.get(group)
    }

    // -------------------- Operation builders (boundary caution) --------------------
    //
    // Operation::AddRelationship currently uses string identifiers.
    // To keep this module bytes-only, provide a labels-based builder;
    // the bytes-only wrappers fail closed (explicit error) to avoid ad-hoc encodings.

    /// Preferred: build an AddRelationship operation from human labels (provided by UI).
    pub fn create_add_contact_operation_with_labels(
        &self,
        from_label: &str,
        to_label: &str,
        relationship_type: &str,
        metadata: Vec<u8>,
        use_bilateral: bool,
    ) -> Result<Operation, DsmError> {
        Ok(Operation::AddRelationship {
            from_id: crate::util::domain_helpers::device_id_hash(from_label),
            to_id: crate::util::domain_helpers::device_id_hash(to_label),
            relationship_type: relationship_type.as_bytes().to_vec(),
            metadata,
            proof: vec![],
            mode: if use_bilateral {
                TransactionMode::Bilateral
            } else {
                TransactionMode::Unilateral
            },
            message: "Add contact relationship".to_string(),
        })
    }

    /// Bytes-only wrapper: fail closed to prevent silent encodings.
    pub fn create_add_contact_operation(
        &self,
        _contact_device_id: [u8; 32],
        _relationship_type: &str,
        _metadata: Vec<u8>,
        _use_bilateral: bool,
    ) -> Result<Operation, DsmError> {
        Err(DsmError::invalid_operation(
            "create_add_contact_operation requires UI-provided labels; \
             use create_add_contact_operation_with_labels(from_label, to_label, ...)",
        ))
    }

    /// Bytes-only wrapper with explicit from-device: same fail-closed stance.
    pub fn create_add_contact_operation_with_device(
        &self,
        _from_device_id: [u8; 32],
        _contact_device_id: [u8; 32],
        _relationship_type: &str,
        _metadata: Vec<u8>,
        _use_bilateral: bool,
    ) -> Result<Operation, DsmError> {
        Err(DsmError::invalid_operation(
            "create_add_contact_operation_with_device requires UI-provided labels; \
             use create_add_contact_operation_with_labels(from_label, to_label, ...)",
        ))
    }
}

// ------------------------ Contact QR (bytes-only) ------------------------

impl ContactManager {
    /// Build a ContactQrV3 protobuf payload as raw bytes (for UI display/QR).
    pub fn build_contact_qr_v3_payload(
        &self,
        network: &str,
        storage_nodes: &[&str],
        sdk_build_bytes: &[u8],
        device_id_bytes: &[u8; 32],
    ) -> AnyResult<Vec<u8>> {
        let mut h = Hasher::new();
        h.update(sdk_build_bytes);
        let fp = h.finalize();

        // Fetch local genesis hash from AppState as raw 32 bytes.
        let genesis_bytes = {
            if let Some(gh) = crate::sdk::app_state::AppState::get_genesis_hash() {
                if gh.len() == 32 {
                    gh
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        };

        let msg = pb::ContactQrV3 {
            device_id: device_id_bytes.to_vec(),
            network: network.trim().to_string(),
            storage_nodes: storage_nodes
                .iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            sdk_fingerprint: fp.as_bytes().to_vec(),
            genesis_hash: genesis_bytes,
            // Include SPHINCS+ signing public key from AppState for bilateral verification
            signing_public_key: crate::sdk::app_state::AppState::get_public_key()
                .unwrap_or_default(),
            preferred_alias: String::new(),
        };

        let mut buf = Vec::with_capacity(msg.encoded_len());
        msg.encode(&mut buf)?;
        Ok(buf)
    }

    /// Parse a ContactQrV3 from raw protobuf bytes.
    pub fn parse_contact_qr_v3_payload(bytes: &[u8]) -> AnyResult<pb::ContactQrV3> {
        Ok(pb::ContactQrV3::decode(bytes)?)
    }
}

// ------------------------ Optional state update hook ------------------------

impl ContactManager {
    pub fn update_contact_from_transition(
        &mut self,
        transition: &StateTransition,
        state: &State,
    ) -> Result<(), DsmError> {
        match &transition.operation {
            Operation::AddRelationship { .. } | Operation::RemoveRelationship { .. } => {
                let _ = state; // no-op for now; reserved for future chain-tip syncing
                Ok(())
            }
            _ => Err(DsmError::invalid_operation(
                "Unsupported operation type for contact update",
            )),
        }
    }
}
