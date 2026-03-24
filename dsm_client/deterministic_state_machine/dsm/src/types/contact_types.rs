//! Contact types for DSM protocol
//!
//! This module contains shared contact-related types used across the DSM system.

use crate::types::identifiers::NodeId;

/// SMT proof data for chain tip verification
#[derive(Clone, Debug)]
pub struct ChainTipSmtProof {
    /// SMT root hash
    pub smt_root: [u8; 32],
    /// State hash being proven
    pub state_hash: [u8; 32],
    /// 256-bit SMT key for this relationship (k_{A↔B})
    /// Required for Merkle path verification (determines bit-path through tree).
    pub smt_key: [u8; 32],
    /// Merkle proof path (sibling hashes, leaf-to-root order)
    pub proof_path: Vec<[u8; 32]>,
    /// State index in the SMT
    pub state_index: u64,
    /// Deterministic tick when proof was generated
    pub proof_commit_height: u64,
}

/// DSM-compliant verified contact with mandatory online genesis verification
#[derive(Clone, Debug)]
pub struct DsmVerifiedContact {
    /// User-friendly alias
    pub alias: String,
    /// Device ID derived from genesis/DBRW (immutable)
    pub device_id: [u8; 32],
    /// Genesis hash from decentralized storage (immutable)
    pub genesis_hash: [u8; 32],
    /// Contact's SPHINCS+ signing public key (bytes-only)
    pub public_key: Vec<u8>,
    /// Raw genesis material bytes (for local verification cache)
    pub genesis_material: Vec<u8>,
    /// Current chain tip (last state hash) - updated after each transaction
    pub chain_tip: Option<[u8; 32]>,
    /// SMT proof for the current chain tip
    pub chain_tip_smt_proof: Option<ChainTipSmtProof>,
    /// MANDATORY: Must be verified online before bilateral transactions
    pub genesis_verified_online: bool,
    /// Commit height when genesis was verified online
    pub verified_at_commit_height: u64,
    /// Commit height when contact was added
    pub added_at_commit_height: u64,
    /// Last updated commit height (monotonic)
    pub last_updated_commit_height: u64,
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

    /// Check if contact needs re-verification (e.g., after long period)
    pub fn needs_reverification_commit_height(
        &self,
        now_commit_height: u64,
        max_age_commit_height: u64,
    ) -> bool {
        (now_commit_height - self.verified_at_commit_height) > max_age_commit_height
    }

    /// Update chain tip after transaction with SMT proof
    pub fn update_chain_tip_with_proof(
        &mut self,
        new_chain_tip: [u8; 32],
        smt_proof: Option<ChainTipSmtProof>,
    ) {
        self.chain_tip = Some(new_chain_tip);
        self.chain_tip_smt_proof = smt_proof;
        // caller should set last_updated_commit_height explicitly if desired
    }

    /// Verify the current chain tip against its SMT proof
    pub fn verify_chain_tip_proof(&self) -> bool {
        match (&self.chain_tip, &self.chain_tip_smt_proof) {
            (Some(chain_tip), Some(proof)) => {
                // Verify that the proof state hash matches the chain tip
                proof.state_hash == *chain_tip
                // Note: Full SMT verification would be done by the contact manager
                // using the storage node's SMT verification methods
            }
            _ => false, // No chain tip or no proof available
        }
    }

    /// Check if chain tip has valid SMT proof
    pub fn has_verified_chain_tip(&self) -> bool {
        self.chain_tip.is_some()
            && self.chain_tip_smt_proof.is_some()
            && self.verify_chain_tip_proof()
    }
}

/// An inbox message received from a remote device via BLE or online relay.
#[derive(Debug, Clone)]
pub struct InboxMessage {
    /// Unique message identifier.
    pub id: String,
    /// Message type label (e.g., "bilateral_prepare", "contact_request").
    pub msg_type: String,
    /// Serialized message payload.
    pub payload: String,
    /// BLAKE3 hash of the payload for integrity verification.
    pub hash: String,
    /// Hash of the previous message in the chain (if part of a sequence).
    pub prev_hash: Option<String>,
    /// Logical tick (commit height) when this message was created.
    pub tick: i64,
    /// Device ID of the sender.
    pub from_device: String,
    /// Device ID of the intended recipient.
    pub to_device: String,
    /// SPHINCS+ signature over the message content.
    pub signature: String,
}

/// Transaction data exchanged during bilateral or online transfers.
#[derive(Debug, Clone)]
pub struct TransactionData {
    /// Sender device identifier.
    pub from: String,
    /// Recipient device identifier.
    pub to: String,
    /// Token amount being transferred.
    pub amount: u64,
    /// Human-readable transfer memo.
    pub memo: String,
    /// Logical tick (commit height) of the transaction.
    pub tick: i64,
    /// SPHINCS+ signature over the transaction fields.
    pub signature: String,
    /// BLAKE3 hash of the transaction for integrity verification.
    pub hash: String,
}

/// A request to establish a verified contact relationship.
#[derive(Debug, Clone)]
pub struct ContactRequest {
    /// Device ID of the contact request sender.
    pub from_device_id: String,
    /// Device ID of the intended contact recipient.
    pub to_device_id: String,
    /// Genesis hash of the sender (for online verification).
    pub genesis_hash: String,
    /// SPHINCS+ public key of the sender.
    pub public_key: Vec<u8>,
    /// Logical tick when the request was created.
    pub tick: i64,
    /// SPHINCS+ signature over the request fields.
    pub signature: String,
    /// Optional human-readable message.
    pub message: Option<String>,
}
