// SPDX-License-Identifier: MIT OR Apache-2.0

//! Contact types for DSM protocol
//!
//! This module contains shared contact-related types used across the DSM system.

use crate::types::identifiers::NodeId;

/// DSM-compliant verified contact with mandatory online genesis verification
#[derive(Clone, Debug)]
pub struct DsmVerifiedContact {
    /// User-friendly alias
    pub alias: String,
    /// Device ID derived from genesis (immutable)
    pub device_id: [u8; 32],
    /// Genesis hash from decentralized storage (immutable)
    pub genesis_hash: [u8; 32],
    /// Contact's SPHINCS+ signing public key (bytes-only)
    pub public_key: Vec<u8>,
    /// Current chain tip (last state hash) - updated after each transaction
    pub chain_tip: Option<[u8; 32]>,
    /// MANDATORY: Must be verified online before bilateral transactions
    pub genesis_verified_online: bool,
    /// Storage nodes that verified the genesis (typed identifier)
    pub verifying_storage_nodes: Vec<NodeId>,
    /// BLE MAC address for offline bilateral transfers (e.g., "AA:BB:CC:DD:EE:FF")
    pub ble_address: Option<String>,
}

impl DsmVerifiedContact {
    /// Check if bilateral transactions are allowed with this contact
    pub fn can_perform_bilateral_transaction(&self) -> bool {
        // DSM Protocol Requirement: Genesis MUST be verified online first
        // Chain tip will be created during the first transaction
        self.genesis_verified_online
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_contact(verified: bool) -> DsmVerifiedContact {
        DsmVerifiedContact {
            alias: "Alice".into(),
            device_id: [1u8; 32],
            genesis_hash: [2u8; 32],
            public_key: vec![3u8; 64],
            chain_tip: None,
            genesis_verified_online: verified,
            verifying_storage_nodes: vec![],
            ble_address: None,
        }
    }

    #[test]
    fn bilateral_allowed_when_genesis_verified() {
        assert!(make_contact(true).can_perform_bilateral_transaction());
    }

    #[test]
    fn bilateral_denied_when_genesis_not_verified() {
        assert!(!make_contact(false).can_perform_bilateral_transaction());
    }
}
