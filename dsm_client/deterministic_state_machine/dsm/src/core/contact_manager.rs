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
    ///
    /// Refused: the device's own id, since a device is never its own
    /// counterparty, and a contact already held under another genesis or
    /// another signing key. A contact's genesis and AK are what every later
    /// check of its steps is made against, so re-adding a contact never
    /// changes either; re-adding the same identity replaces the rest of the
    /// record (alias, BLE address, chain tip).
    pub fn add_verified_contact(&mut self, contact: DsmVerifiedContact) -> Result<(), DsmError> {
        if contact.device_id == [0u8; 32] || contact.genesis_hash == [0u8; 32] {
            return Err(DsmError::InvalidContact(
                "Contact must have device_id & genesis_hash".into(),
            ));
        }
        if contact.device_id == self.own_device_id {
            return Err(DsmError::InvalidContact(
                "a device cannot add its own device id as a contact".into(),
            ));
        }
        if let Some(held) = self.contacts.get(&contact.device_id) {
            if held.genesis_hash != contact.genesis_hash {
                return Err(DsmError::InvalidContact(format!(
                    "contact {} is held under another genesis; re-adding it does not change it",
                    labeling::hash_to_short_id(&contact.device_id)
                )));
            }
            if held.public_key != contact.public_key {
                return Err(DsmError::InvalidContact(format!(
                    "contact {} is held under another signing key; re-adding it does not change it",
                    labeling::hash_to_short_id(&contact.device_id)
                )));
            }
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

    /// A device is never its own contact.
    #[test]
    fn the_devices_own_id_is_refused_as_a_contact() {
        let own_device_id = create_test_device_id(0);
        let mut manager = DsmContactManager::new(own_device_id);
        let genesis_hash = create_test_genesis_hash(&own_device_id, 0);
        let refused = manager
            .add_verified_contact(create_test_contact(own_device_id, genesis_hash))
            .expect_err("the device's own id");
        assert!(matches!(refused, DsmError::InvalidContact(_)), "{refused}");
        assert!(manager.contacts.is_empty());
    }

    /// Re-adding a contact never changes its genesis or its signing key: both
    /// are refused and the held record is kept. Re-adding the same identity
    /// replaces the rest of the record.
    #[test]
    fn a_readd_never_changes_a_contacts_genesis_or_signing_key() {
        let own_device_id = create_test_device_id(0);
        let mut manager = DsmContactManager::new(own_device_id);
        let device_id = create_test_device_id(1);
        let genesis_hash = create_test_genesis_hash(&device_id, 0);
        let held = create_test_contact(device_id, genesis_hash);
        manager.add_verified_contact(held.clone()).unwrap();

        let other_genesis = create_test_genesis_hash(&device_id, 1);
        let refused = manager
            .add_verified_contact(create_test_contact(device_id, other_genesis))
            .expect_err("another genesis");
        assert!(matches!(refused, DsmError::InvalidContact(_)), "{refused}");

        let mut other_key = held.clone();
        other_key.public_key = vec![9u8; 32];
        let refused = manager
            .add_verified_contact(other_key)
            .expect_err("another signing key");
        assert!(matches!(refused, DsmError::InvalidContact(_)), "{refused}");

        let kept = manager.get_contact(&device_id).unwrap();
        assert_eq!(kept.genesis_hash, held.genesis_hash);
        assert_eq!(kept.public_key, held.public_key);

        let mut renamed = held.clone();
        renamed.alias = "Renamed".into();
        manager.add_verified_contact(renamed).unwrap();
        assert_eq!(manager.get_contact(&device_id).unwrap().alias, "Renamed");
    }
}
