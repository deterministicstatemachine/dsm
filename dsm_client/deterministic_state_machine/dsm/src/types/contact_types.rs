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
    /// What the row holding this contact records, shown to the user. It gates
    /// nothing: a contact is proved when it is added
    /// (`ContactManager::add_contact_from_directory`, the entry's own signature
    /// and the members holding it), and a relationship stands on the signing
    /// key and the tip its store holds.
    pub genesis_verified_online: bool,
    /// Storage nodes that verified the genesis (typed identifier)
    pub verifying_storage_nodes: Vec<NodeId>,
    /// BLE MAC address for offline bilateral transfers (e.g., "AA:BB:CC:DD:EE:FF")
    pub ble_address: Option<String>,
}
