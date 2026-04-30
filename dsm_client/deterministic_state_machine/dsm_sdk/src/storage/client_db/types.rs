// SPDX-License-Identifier: MIT OR Apache-2.0
//! Public type definitions for the DSM client persistent storage layer.

use std::collections::HashMap;

use anyhow::{anyhow, Result};

#[derive(Debug, Clone)]
pub struct WalletState {
    pub wallet_id: String,
    pub device_id: String,
    pub genesis_id: Option<String>,
    pub chain_tip: String,
    pub chain_height: u64,
    pub merkle_root: String,
    pub balance: u64,
    pub created_at: u64,
    pub updated_at: u64,
    pub status: String,
    pub metadata: HashMap<String, Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct GenesisRecord {
    pub genesis_id: String,
    pub device_id: String,
    pub mpc_proof: String,
    pub dbrw_binding: String,
    pub merkle_root: String,
    pub participant_count: u32,
    pub progress_marker: String,
    pub publication_hash: String,
    pub storage_nodes: Vec<String>,
    pub entropy_hash: String,
    pub protocol_version: String,
    pub hash_chain_proof: Option<Vec<u8>>,
    pub smt_proof: Option<Vec<u8>>,
    pub verification_step: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub verified: bool,
    pub genesis_hash: Option<Vec<u8>>,
    pub wallet_hash: Option<Vec<u8>>,
    pub merkle_proof: Option<Vec<u8>>,
    pub verification_step: u64,
    pub details: HashMap<String, Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct PendingTransaction {
    pub tx_id: String,
    pub payload: Vec<u8>,
    pub state: String,
    pub retry_count: u32,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone)]
pub struct PendingOnlineOutboxRecord {
    pub counterparty_device_id: Vec<u8>,
    pub message_id: String,
    pub parent_tip: Vec<u8>,
    pub next_tip: Vec<u8>,
    pub created_at: u64,
}

#[derive(Debug, Clone)]
pub struct ContactRecord {
    pub contact_id: String,
    pub device_id: Vec<u8>, // Raw bytes (32 bytes for device_id)
    pub alias: String,
    pub genesis_hash: Vec<u8>,              // Raw bytes (32 bytes)
    pub public_key: Vec<u8>, // SPHINCS+ signing public key for bilateral verification
    /// Counterparty's Kyber-768 (ML-KEM) public key. Required for the
    /// per-step Kyber encapsulation in receipt EK derivation
    /// (whitepaper §11). The sender encapsulates against this pubkey to
    /// derive `k_step` for the per-step EK. Empty means the contact was
    /// established before per-step EK signing was wired (legacy path);
    /// such contacts cannot be used as receipt recipients under strict
    /// mode and must be re-established to upgrade.
    pub kyber_public_key: Vec<u8>,
    pub current_chain_tip: Option<Vec<u8>>, // Raw bytes (32 bytes if present)
    pub added_at: u64,
    pub verified: bool,
    pub verification_proof: Option<Vec<u8>>,
    pub metadata: HashMap<String, Vec<u8>>,
    pub ble_address: Option<String>, // BLE MAC address for offline transfers
    pub status: String,
    pub needs_online_reconcile: bool,
    pub last_seen_online_counter: u64,
    pub last_seen_ble_counter: u64,
    pub previous_chain_tip: Option<Vec<u8>>, // Predecessor tip for stale-route polling
}

impl ContactRecord {
    /// Validate that a ContactRecord has a non-empty public key.
    /// This MUST be called before storing any contact that will be used for verification.
    /// Returns an error if the public key is empty, preventing trust boundary violations.
    pub fn validate_for_verification(&self) -> Result<()> {
        if self.public_key.is_empty() {
            return Err(anyhow!(
                "ContactRecord for \"{}\" has empty public_key; cannot be used for verification.  \
                 Use SystemPeerRecord for protocol-controlled actors like DLV/Faucet.",
                self.alias
            ));
        }
        if self.public_key.len() < 32 {
            return Err(anyhow!(
                "ContactRecord for \"{}\" has invalid public_key length {} (expected >= 32 bytes)",
                self.alias,
                self.public_key.len()
            ));
        }
        Ok(())
    }

    /// Convert a SQLite ContactRecord to a Core DsmVerifiedContact.
    ///
    /// This is the SINGLE authoritative conversion — all code paths that need
    /// a `DsmVerifiedContact` from SQLite MUST use this method to avoid field
    /// omissions (e.g. dropping `public_key`).
    ///
    /// Returns `None` if `device_id` or `genesis_hash` are not exactly 32 bytes.
    pub fn to_verified_contact(&self) -> Option<dsm::types::contact_types::DsmVerifiedContact> {
        if self.device_id.len() != 32 || self.genesis_hash.len() != 32 {
            return None;
        }
        let mut dev = [0u8; 32];
        dev.copy_from_slice(&self.device_id);
        let mut gh = [0u8; 32];
        gh.copy_from_slice(&self.genesis_hash);

        log::warn!(
            "[ContactRecord::to_verified_contact] alias={} public_key_len={}",
            self.alias,
            self.public_key.len()
        );

        Some(dsm::types::contact_types::DsmVerifiedContact {
            alias: self.alias.clone(),
            device_id: dev,
            genesis_hash: gh,
            public_key: self.public_key.clone(),
            genesis_material: Vec::new(),
            chain_tip: self.current_chain_tip.as_ref().and_then(|ct| {
                if ct.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(ct);
                    Some(arr)
                } else {
                    None
                }
            }),
            chain_tip_smt_proof: None,
            genesis_verified_online: self.verified,
            verified_at_commit_height: self.added_at,
            added_at_commit_height: self.added_at,
            last_updated_commit_height: self.added_at,
            verifying_storage_nodes: Vec::new(),
            ble_address: self.ble_address.clone(),
        })
    }
}

/// SystemPeerRecord: lightweight record for protocol-controlled actors (DLV, Faucet, etc.)
///
/// This type is intentionally separate from ContactRecord to enforce the trust boundary:
/// - ContactRecord: authenticated counterparty with public key for bilateral verification
/// - SystemPeerRecord: protocol-controlled actor without bilateral trust (no public key)
///
/// Any operation requiring verification MUST use ContactRecord, not SystemPeerRecord.
#[derive(Debug, Clone)]
pub struct SystemPeerRecord {
    pub peer_key: String,          // Unique identifier (e.g., "dlv", "faucet")
    pub device_id: Vec<u8>,        // Deterministic 32-byte identifier
    pub display_name: String,      // Human-readable name for UI
    pub peer_type: SystemPeerType, // Type of system peer
    pub current_chain_tip: Option<Vec<u8>>, // Chain tip for state tracking
    pub created_at: u64,
    pub updated_at: u64,
    pub metadata: HashMap<String, Vec<u8>>,
}

/// Persisted protocol-actor transition under a stable `SystemPeerRecord`.
///
/// These events track sovereign DLV/faucet/protocol progression and are never
/// interpreted as bilateral relationship receipts or contact chain tips.
#[derive(Debug, Clone)]
pub struct SystemPeerEvent {
    pub peer_key: String,
    pub peer_type: SystemPeerType,
    pub parent_tip: Vec<u8>,
    pub child_tip: Vec<u8>,
    pub transition_digest: Vec<u8>,
    pub source_state_hash: Vec<u8>,
    pub source_state_number: u64,
    pub payload_bytes: Vec<u8>,
    pub created_at: u64,
}

/// Type of system peer for categorization
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemPeerType {
    /// Deterministic Limbo Vault (protocol-controlled escrow)
    Dlv,
    /// Faucet for token distribution
    Faucet,
    /// Other protocol-controlled actor
    Protocol,
}

impl SystemPeerType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SystemPeerType::Dlv => "dlv",
            SystemPeerType::Faucet => "faucet",
            SystemPeerType::Protocol => "protocol",
        }
    }
}

impl std::str::FromStr for SystemPeerType {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s.trim().to_ascii_lowercase().as_str() {
            "dlv" => SystemPeerType::Dlv,
            "faucet" => SystemPeerType::Faucet,
            "protocol" => SystemPeerType::Protocol,
            _ => SystemPeerType::Protocol,
        })
    }
}

pub struct TransactionRecord {
    pub tx_id: String,
    pub tx_hash: String,
    pub from_device: String,
    pub to_device: String,
    pub amount: u64,
    pub tx_type: String,
    pub status: String,
    pub chain_height: u64,
    pub step_index: u64,
    pub commitment_hash: Option<Vec<u8>>,
    /// Bilateral stitched receipt bytes only. Protocol-actor transitions must
    /// use metadata or dedicated protocol event rows instead.
    pub proof_data: Option<Vec<u8>>,
    pub metadata: HashMap<String, Vec<u8>>,
    pub created_at: u64,
}

#[derive(Debug, Clone)]
pub struct BilateralSessionRecord {
    pub commitment_hash: Vec<u8>,
    pub counterparty_device_id: Vec<u8>,
    pub counterparty_genesis_hash: Option<Vec<u8>>, // Optional for older rows/migrations
    pub operation_bytes: Vec<u8>,
    pub phase: String,
    pub local_signature: Option<Vec<u8>>,
    pub counterparty_signature: Option<Vec<u8>>,
    pub created_at_step: u64,
    pub sender_ble_address: Option<String>,
    /// Sender-cached signed stitched receipt (full protobuf, with per-step EK
    /// signing artifacts already stamped). Persisted here so that post-crash
    /// recovery in `mark_sender_committed_with_post_state_hash` can reuse the
    /// already-signed bytes verbatim instead of attempting to rebuild from
    /// the canonical `AdvanceOutcome` (which would lack §11.1 per-step EK
    /// signing artifacts).
    pub stitched_receipt_bytes: Option<Vec<u8>>,
}

/// Locally persisted DLV stitched receipt record (§7.3, §18.4).
#[derive(Debug, Clone)]
pub struct DlvReceiptRecord {
    pub sigma: [u8; 32],
    pub vault_id: String,
    pub genesis: [u8; 32],
    pub devid_a: [u8; 32],
    pub devid_b: [u8; 32],
    pub receipt_cbor: Vec<u8>,
    pub sig_a: Vec<u8>,
    pub sig_b: Vec<u8>,
    pub created_at: u64,
}

/// Persisted BLE chunk for durable reassembly across connection drops.
/// Stored in `ble_reassembly_state` table, keyed by (frame_commitment, chunk_index).
#[derive(Debug, Clone)]
pub struct PersistedChunk {
    pub chunk_index: u16,
    pub chunk_data: Vec<u8>,
    pub checksum: u32,
    pub frame_type: i32,
    pub total_chunks: u16,
    pub payload_len: u32,
}

/// Parameters for persisting a BLE chunk.
#[derive(Debug, Clone)]
pub struct ChunkPersistenceParams<'a> {
    pub frame_commitment: &'a [u8; 32],
    pub chunk_index: u16,
    pub frame_type: i32,
    pub total_chunks: u16,
    pub payload_len: u32,
    pub chunk_data: &'a [u8],
    pub checksum: u32,
    pub counterparty_id: Option<&'a [u8; 32]>,
}

#[cfg(test)]
mod system_peer_type_tests {
    use super::SystemPeerType;

    #[test]
    fn system_peer_type_parse_is_case_insensitive_and_trimmed() {
        assert_eq!(
            "dlv".parse::<SystemPeerType>().unwrap(),
            SystemPeerType::Dlv
        );
        assert_eq!(
            "DLV".parse::<SystemPeerType>().unwrap(),
            SystemPeerType::Dlv
        );
        assert_eq!(
            "  faucet  ".parse::<SystemPeerType>().unwrap(),
            SystemPeerType::Faucet
        );
        assert_eq!(
            "protocol".parse::<SystemPeerType>().unwrap(),
            SystemPeerType::Protocol
        );
    }

    #[test]
    fn system_peer_type_parse_unknown_defaults_to_protocol() {
        assert_eq!(
            "something-else".parse::<SystemPeerType>().unwrap(),
            SystemPeerType::Protocol
        );
        assert_eq!(
            "".parse::<SystemPeerType>().unwrap(),
            SystemPeerType::Protocol
        );
    }
}
