// SPDX-License-Identifier: MIT OR Apache-2.0
//! Contacts: the counterparties this device resolved through the device
//! directory, held in memory by Core's contact manager and persisted in the
//! client database.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use dsm::core::contact_manager::{ContactError, DsmContactManager};
use dsm::core::identity::directory::DirectoryEntry;
use dsm::types::contact_types::DsmVerifiedContact;
use dsm::types::error::DsmError;
use dsm::types::identifiers::NodeId;
use dsm::types::proto as pb;

fn storage_err(what: &str, e: impl core::fmt::Display) -> DsmError {
    DsmError::storage(format!("{what}: {e}"), None::<std::io::Error>)
}

#[derive(Debug, Clone)]
pub struct ContactManager {
    dsm_manager: Arc<RwLock<DsmContactManager>>,
    pub device_id: [u8; 32],
    pub genesis_hash: [u8; 32],
}

impl ContactManager {
    /// Open this device's contacts: Core's manager holding every persisted
    /// contact. A malformed persisted contact is refused, never skipped.
    pub fn open(device_id: [u8; 32], genesis_hash: [u8; 32]) -> Result<Self, DsmError> {
        let mut manager = DsmContactManager::new(device_id);
        let records = crate::storage::client_db::get_all_contacts()
            .map_err(|e| storage_err("load contacts", e))?;
        for record in records {
            let contact = record
                .to_verified_contact()
                .map_err(|e| storage_err("load contacts", e))?;
            manager.add_verified_contact(contact)?;
        }
        Ok(Self {
            dsm_manager: Arc::new(RwLock::new(manager)),
            device_id,
            genesis_hash,
        })
    }

    fn compute_initial_chain_tip(
        &self,
        contact_device_id: [u8; 32],
        contact_genesis_hash: [u8; 32],
    ) -> [u8; 32] {
        dsm::core::bilateral_transaction_manager::initial_relationship_chain_tip(
            &self.device_id,
            &self.genesis_hash,
            &contact_device_id,
            &contact_genesis_hash,
        )
    }

    /// Add the counterparty a directory read proved: its genesis, device id,
    /// AK and Kyber key exactly as its own entry signs them, with the members
    /// of the pinned set that hold that entry.
    pub async fn add_contact_from_directory(
        &mut self,
        alias: &str,
        entry: &DirectoryEntry,
        verifying_nodes: Vec<NodeId>,
    ) -> Result<pb::ContactAddResponse, ContactError> {
        let required = dsm::sofi::wire::STORAGE_FINALITY_COUNT;
        if verifying_nodes.len() < required {
            return Err(ContactError::GenesisVerificationFailed(format!(
                "{} members hold the directory entry; {required} needed",
                verifying_nodes.len()
            )));
        }
        entry
            .verify()
            .map_err(|e| ContactError::GenesisVerificationFailed(e.to_string()))?;
        let device_id = entry.body.device_id;
        let genesis_hash = entry.body.genesis;
        let initial_chain_tip = self.compute_initial_chain_tip(device_id, genesis_hash);

        let verified = DsmVerifiedContact {
            alias: alias.to_string(),
            device_id,
            genesis_hash,
            public_key: entry.body.ak_public_key.clone(),
            chain_tip: Some(initial_chain_tip),
            genesis_verified_online: true,
            verifying_storage_nodes: verifying_nodes,
            ble_address: None,
        };
        self.dsm_manager
            .write()
            .await
            .add_verified_contact(verified.clone())
            .map_err(|e| {
                ContactError::InvalidContactData(format!("Core add_verified_contact failed: {e}"))
            })?;

        let hash_bytes = crate::util::domain_helpers::device_id_hash_bytes(&device_id);
        let contact_id = format!(
            "c_{}",
            &crate::util::text_id::encode_base32_crockford(&hash_bytes)[..8]
        );
        let record = crate::storage::client_db::ContactRecord {
            contact_id,
            device_id: device_id.to_vec(),
            alias: alias.to_string(),
            genesis_hash: genesis_hash.to_vec(),
            current_chain_tip: Some(initial_chain_tip.to_vec()),
            verified: true,
            verification_proof: None,
            metadata: HashMap::new(),
            ble_address: None,
            status: "Created".to_string(),
            needs_online_reconcile: false,
            public_key: entry.body.ak_public_key.clone(),
            kyber_public_key: entry.body.kyber_public_key.clone(),
            previous_chain_tip: None,
        };
        crate::storage::client_db::store_contact(&record).map_err(|e| {
            ContactError::InvalidContactData(format!("SQLite persistence failed: {e}"))
        })?;
        let request = crate::storage::client_db::bilateral_tip_sync::TipSyncRequest {
            counterparty_device_id: device_id,
            expected_parent_tip: initial_chain_tip,
            target_tip: initial_chain_tip,
        };
        crate::storage::client_db::bilateral_tip_sync::sync_bilateral_tips_atomically(&request)
            .map_err(|e| {
                ContactError::InvalidChainTip(format!(
                    "Failed to persist initial local bilateral chain tip: {e}"
                ))
            })?;
        // §2.3: the contact's Device Tree root R_G, against which receipt
        // verification during inbox sync checks π_dev proofs.
        let contact_device_tree_root =
            dsm::common::device_tree::DeviceTree::single(device_id).root();
        crate::storage::client_db::store_contact_device_tree_root(
            &device_id,
            &contact_device_tree_root,
        )
        .map_err(|e| {
            ContactError::InvalidContactData(format!(
                "Failed to store contact device tree root: {e}"
            ))
        })?;

        Ok(contact_add_response(&verified))
    }

    pub async fn get_verified_contact(&self, device_id: [u8; 32]) -> Option<DsmVerifiedContact> {
        self.dsm_manager
            .read()
            .await
            .get_contact(&device_id)
            .cloned()
    }

    /// Every contact, with the BLE address the client database holds for it:
    /// that address is written there, apart from the in-memory contact.
    pub async fn list_verified_contacts(&self) -> Result<Vec<DsmVerifiedContact>, DsmError> {
        let manager = self.dsm_manager.read().await;
        manager
            .list_contacts()
            .into_iter()
            .map(|contact| {
                let mut contact = contact.clone();
                let record =
                    crate::storage::client_db::get_contact_by_device_id(&contact.device_id)
                        .map_err(|e| storage_err("contact lookup", e))?
                        .ok_or_else(|| {
                            storage_err(
                                "contact lookup",
                                "a contact held in memory has no persisted row",
                            )
                        })?;
                contact.ble_address = record.ble_address;
                Ok(contact)
            })
            .collect()
    }

    /// Replace the in-memory contact with one read back from storage.
    pub async fn restore_contact_from_storage(
        &mut self,
        contact: DsmVerifiedContact,
    ) -> Result<(), DsmError> {
        self.dsm_manager.write().await.add_verified_contact(contact)
    }
}

/// The response a contact add or lookup returns for `contact`.
pub fn contact_add_response(
    contact: &dsm::types::contact_types::DsmVerifiedContact,
) -> pb::ContactAddResponse {
    pb::ContactAddResponse {
        alias: contact.alias.clone(),
        device_id: contact.device_id.to_vec(),
        genesis_hash: Some(pb::Hash32 {
            v: contact.genesis_hash.to_vec(),
        }),
        chain_tip: contact.chain_tip.map(|tip| pb::Hash32 { v: tip.to_vec() }),
        alias_binding: None,
        genesis_verified_online: contact.genesis_verified_online,
        verifying_storage_nodes: contact
            .verifying_storage_nodes
            .iter()
            .map(|node| node.to_string())
            .collect(),
        // proto3: the empty string is how an absent address encodes.
        ble_address: match &contact.ble_address {
            Some(address) => address.clone(),
            None => String::new(),
        },
        signing_public_key: contact.public_key.clone(),
        send_status: Some(
            crate::handlers::relationship_status::derive_local_send_status_for_device_id(
                &contact.device_id,
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager_of(device_id: [u8; 32], genesis_hash: [u8; 32]) -> ContactManager {
        ContactManager {
            dsm_manager: Arc::new(RwLock::new(DsmContactManager::new(device_id))),
            device_id,
            genesis_hash,
        }
    }

    #[test]
    fn chain_tip_is_deterministic() {
        let cm = manager_of([0xAA; 32], [0xBB; 32]);
        let tip1 = cm.compute_initial_chain_tip([0xCC; 32], [0xDD; 32]);
        let tip2 = cm.compute_initial_chain_tip([0xCC; 32], [0xDD; 32]);
        assert_eq!(tip1, tip2, "same inputs must produce same tip");
    }

    #[test]
    fn chain_tip_is_order_independent() {
        let device_a = [0x01; 32];
        let genesis_a = [0x11; 32];
        let device_b = [0x02; 32];
        let genesis_b = [0x22; 32];
        let tip_a_to_b =
            manager_of(device_a, genesis_a).compute_initial_chain_tip(device_b, genesis_b);
        let tip_b_to_a =
            manager_of(device_b, genesis_b).compute_initial_chain_tip(device_a, genesis_a);
        assert_eq!(
            tip_a_to_b, tip_b_to_a,
            "chain tip must be symmetric regardless of initiator"
        );
    }

    #[test]
    fn chain_tip_differs_for_different_contacts() {
        let cm = manager_of([0xAA; 32], [0xBB; 32]);
        let tip1 = cm.compute_initial_chain_tip([0x01; 32], [0x11; 32]);
        let tip2 = cm.compute_initial_chain_tip([0x02; 32], [0x22; 32]);
        assert_ne!(tip1, tip2, "different contacts should have different tips");
    }
}
