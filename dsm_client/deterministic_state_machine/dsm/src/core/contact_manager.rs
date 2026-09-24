// SPDX-License-Identifier: MIT OR Apache-2.0

// dsm_client/deterministic_state_machine/dsm/src/core/contact_manager.rs

//! DSM Contact Manager - Production Implementation (STRICT, bytes-only, no wall-clock)
//!
//! Invariants:
//! - No time of any kind.
//! - No JSON/GSON at any boundary. No hex/base64 in data structures or logs; bytes-only.
//! - Mandatory online genesis verification is enforced by the SDK layer; core only exposes bytes APIs.
//! - Chain tip tracking is bytes-based with deterministic SMT proofs.

use std::collections::HashMap;

#[cfg(test)]
use blake3;
use tracing::info;

use crate::core::utility::labeling;
use crate::types::contact_types::DsmVerifiedContact;
use crate::types::error::DsmError;

// -------------------- Contact Manager --------------------
#[derive(Debug, Clone)]
pub struct DsmContactManager {
    pub contacts: HashMap<[u8; 32], DsmVerifiedContact>,
    pub own_device_id: [u8; 32],
}

#[derive(Debug)]
pub enum ContactAddResult {
    Success(DsmVerifiedContact),
    AlreadyExists(DsmVerifiedContact),
}

#[derive(Debug, thiserror::Error)]
pub enum ContactError {
    #[error("Genesis verification failed: {0}")]
    GenesisVerificationFailed(String),
    #[error("Storage nodes unreachable")]
    StorageNodesUnreachable,
    #[error("Invalid contact data: {0}")]
    InvalidContactData(String),
    #[error("Contact not found")]
    ContactNotFound,
    #[error("Invalid chain tip: {0}")]
    InvalidChainTip(String),
    #[error("SMT verification failed: {0}")]
    SmtVerificationFailed(String),
}

impl DsmContactManager {
    pub fn new(own_device_id: [u8; 32]) -> Self {
        Self {
            contacts: HashMap::new(),
            own_device_id,
        }
    }

    /// Bytes-only: add a **pre-verified** contact (SDK must have verified genesis online already)
    pub fn add_verified_contact(&mut self, contact: DsmVerifiedContact) -> Result<(), DsmError> {
        if contact.device_id == [0u8; 32] || contact.genesis_hash == [0u8; 32] {
            return Err(DsmError::InvalidContact(
                "Contact must have device_id & genesis_hash".into(),
            ));
        }

        let id = contact.device_id;

        info!(
            "Adding verified contact (id_dec={})",
            labeling::hash_to_short_id(&id)
        );

        self.contacts.insert(id, contact);
        Ok(())
    }

    #[inline]
    pub fn get_contact(&self, device_id: &[u8; 32]) -> Option<&DsmVerifiedContact> {
        self.contacts.get(device_id)
    }

    #[inline]
    pub fn get_contact_mut(&mut self, device_id: &[u8; 32]) -> Option<&mut DsmVerifiedContact> {
        self.contacts.get_mut(device_id)
    }

    pub fn list_contacts(&self) -> Vec<&DsmVerifiedContact> {
        self.contacts.values().collect()
    }

    pub fn remove_contact(&mut self, device_id: &[u8; 32]) -> Option<DsmVerifiedContact> {
        self.contacts.remove(device_id)
    }

    /// Update the public key for a contact (used during BLE bilateral exchange)
    pub fn update_contact_public_key(
        &mut self,
        device_id: &[u8; 32],
        public_key: Vec<u8>,
    ) -> Result<(), DsmError> {
        let contact = self.contacts.get_mut(device_id).ok_or_else(|| {
            DsmError::ContactNotFound(labeling::hash_to_short_id(device_id).to_string())
        })?;

        contact.public_key = public_key;

        info!(
            "Updated public_key for contact (id_dec={}, key_len={})",
            labeling::hash_to_short_id(device_id),
            contact.public_key.len()
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::identifiers::NodeId;

    fn create_test_device_id(seed: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = seed;
        id[31] = seed.wrapping_add(1);
        id
    }

    fn create_test_genesis_hash(device_id: &[u8; 32], seed: u64) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"TEST_GENESIS");
        h.update(device_id);
        h.update(&seed.to_le_bytes());
        let out = h.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(out.as_bytes());
        hash
    }

    fn create_test_storage_nodes() -> Vec<NodeId> {
        vec![NodeId::new("test_node_1")]
    }

    fn create_test_contact(device_id: [u8; 32], genesis_hash: [u8; 32]) -> DsmVerifiedContact {
        DsmVerifiedContact {
            device_id,
            genesis_hash,
            alias: "Test".into(),
            public_key: vec![0u8; 32],
            genesis_verified_online: true,
            verifying_storage_nodes: create_test_storage_nodes(),
            chain_tip: None,
            ble_address: None,
        }
    }

    #[test]
    fn test_dsm_contact_manager_add_contact() {
        let own_device_id = create_test_device_id(0);
        let mut manager = DsmContactManager::new(own_device_id);

        let device_id = create_test_device_id(1);
        let genesis_hash = create_test_genesis_hash(&device_id, 0);
        let contact = create_test_contact(device_id, genesis_hash);

        assert!(manager.add_verified_contact(contact.clone()).is_ok());
        assert_eq!(manager.contacts.len(), 1);
        assert!(manager.get_contact(&device_id).is_some());
    }

    #[test]
    fn test_dsm_contact_manager_get_contact() {
        let own_device_id = create_test_device_id(0);
        let mut manager = DsmContactManager::new(own_device_id);

        let device_id = create_test_device_id(1);
        let genesis_hash = create_test_genesis_hash(&device_id, 0);
        let contact = create_test_contact(device_id, genesis_hash);

        manager.add_verified_contact(contact).unwrap();
        let retrieved = manager.get_contact(&device_id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().device_id, device_id);
    }

    #[test]
    fn test_dsm_contact_manager_remove_contact() {
        let own_device_id = create_test_device_id(0);
        let mut manager = DsmContactManager::new(own_device_id);

        let device_id = create_test_device_id(1);
        let genesis_hash = create_test_genesis_hash(&device_id, 0);
        let contact = create_test_contact(device_id, genesis_hash);

        manager.add_verified_contact(contact).unwrap();
        assert_eq!(manager.contacts.len(), 1);

        manager.remove_contact(&device_id);
        assert_eq!(manager.contacts.len(), 0);
    }

    #[test]
    fn test_dsm_contact_manager_invalid_contact() {
        let own_device_id = create_test_device_id(0);
        let mut manager = DsmContactManager::new(own_device_id);

        let invalid_contact = create_test_contact([0u8; 32], [1u8; 32]);
        assert!(manager.add_verified_contact(invalid_contact).is_err());
    }

    #[test]
    fn test_dsm_contact_manager_multiple_contacts() {
        let own_device_id = create_test_device_id(0);
        let mut manager = DsmContactManager::new(own_device_id);

        for i in 1..=5 {
            let device_id = create_test_device_id(i);
            let genesis_hash = create_test_genesis_hash(&device_id, i as u64);
            let contact = create_test_contact(device_id, genesis_hash);
            manager.add_verified_contact(contact).unwrap();
        }

        assert_eq!(manager.contacts.len(), 5);
        assert_eq!(manager.list_contacts().len(), 5);
    }

    #[test]
    fn test_short_dec_fingerprint() {
        let device_id = create_test_device_id(42);
        let fingerprint = crate::core::utility::labeling::hash_to_short_id(&device_id);

        assert!(!fingerprint.is_empty(), "Fingerprint should be non-empty");
        assert!(
            fingerprint.chars().all(char::is_numeric),
            "Fingerprint should be numeric string"
        );

        let fingerprint2 = crate::core::utility::labeling::hash_to_short_id(&device_id);
        assert_eq!(fingerprint, fingerprint2);
    }
}
