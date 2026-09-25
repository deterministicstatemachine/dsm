// SPDX-License-Identifier: MIT OR Apache-2.0
//! Public type definitions for the DSM client persistent storage layer.

use std::collections::HashMap;

use anyhow::{anyhow, Result};

#[derive(Debug, Clone)]
pub struct GenesisRecord {
    pub genesis_id: String,
    pub device_id: String,
    pub device_birth_binding: String,
    pub merkle_root: String,
    pub progress_marker: String,
    pub publication_hash: String,
    pub entropy_hash: String,
    pub protocol_version: String,
    pub hash_chain_proof: Option<Vec<u8>>,
    pub smt_proof: Option<Vec<u8>>,
    pub verification_step: Option<u64>,
    /// Public genesis nonce (Base32-Crockford).
    pub genesis_nonce: String,
    /// Genesis derivation profile: "MnemonicV2" or "MnemonicV3".
    pub genesis_profile: String,
    /// The network id the genesis was created under (v3: a GRK derivation
    /// input, so the authority chain is re-derivable after restart).
    pub network_id: String,
}

#[derive(Debug, Clone)]
pub struct PendingOnlineOutboxRecord {
    pub counterparty_device_id: Vec<u8>,
    pub message_id: String,
    pub parent_tip: Vec<u8>,
    pub next_tip: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ContactRecord {
    pub contact_id: String,
    pub device_id: Vec<u8>, // Raw bytes (32 bytes for device_id)
    pub alias: String,
    pub genesis_hash: Vec<u8>, // Raw bytes (32 bytes)
    pub public_key: Vec<u8>,   // SPHINCS+ signing public key for bilateral verification
    /// Counterparty's Kyber-768 (ML-KEM) public key. Required for the
    /// per-step Kyber encapsulation in receipt EK derivation
    /// (whitepaper §11). The sender encapsulates against this pubkey to
    /// derive `k_step` for the per-step EK. Empty means the contact was
    /// established before per-step EK signing was wired (legacy path);
    /// such contacts cannot be used as receipt recipients under strict
    /// mode and must be re-established to upgrade.
    pub kyber_public_key: Vec<u8>,
    pub current_chain_tip: Option<Vec<u8>>, // Raw bytes (32 bytes if present)
    pub verified: bool,
    pub verification_proof: Option<Vec<u8>>,
    pub metadata: HashMap<String, Vec<u8>>,
    pub ble_address: Option<String>, // BLE MAC address for offline transfers
    pub status: String,
    pub needs_online_reconcile: bool,
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
    /// omissions (e.g. dropping `public_key`). A row whose device id, genesis
    /// or chain tip is not 32 bytes is malformed state and is refused.
    pub fn to_verified_contact(&self) -> Result<dsm::types::contact_types::DsmVerifiedContact> {
        let d32 = |bytes: &[u8], what: &str| {
            <[u8; 32]>::try_from(bytes).map_err(|e| {
                anyhow!(
                    "contact \"{}\": {what} is {} bytes, not 32: {e}",
                    self.alias,
                    bytes.len()
                )
            })
        };
        let chain_tip = match &self.current_chain_tip {
            Some(tip) => Some(d32(tip, "chain tip")?),
            None => None,
        };
        Ok(dsm::types::contact_types::DsmVerifiedContact {
            alias: self.alias.clone(),
            device_id: d32(&self.device_id, "device id")?,
            genesis_hash: d32(&self.genesis_hash, "genesis")?,
            public_key: self.public_key.clone(),
            chain_tip,
            genesis_verified_online: self.verified,
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

/// The inverse of [`SystemPeerType::as_str`], exactly. Any other spelling is
/// not a peer type.
impl std::str::FromStr for SystemPeerType {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "dlv" => Ok(SystemPeerType::Dlv),
            "faucet" => Ok(SystemPeerType::Faucet),
            "protocol" => Ok(SystemPeerType::Protocol),
            _ => Err(()),
        }
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
    pub commitment_hash: Option<Vec<u8>>,
    /// Bilateral stitched receipt bytes only. Protocol-actor transitions must
    /// use metadata or dedicated protocol event rows instead.
    pub proof_data: Option<Vec<u8>>,
    pub metadata: HashMap<String, Vec<u8>>,
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
    pub sender_ble_address: Option<String>,
    /// Sender-cached signed stitched receipt (full protobuf, with per-step EK
    /// signing artifacts already stamped). Persisted here so that post-crash
    /// recovery in `mark_sender_committed_with_post_state_hash` can reuse the
    /// already-signed bytes verbatim instead of attempting to rebuild from
    /// the canonical `AdvanceOutcome` (which would lack §11.1 per-step EK
    /// signing artifacts).
    pub stitched_receipt_bytes: Option<Vec<u8>>,
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
    fn system_peer_type_parse_inverts_as_str() {
        for t in [
            SystemPeerType::Dlv,
            SystemPeerType::Faucet,
            SystemPeerType::Protocol,
        ] {
            assert_eq!(t.as_str().parse::<SystemPeerType>(), Ok(t));
        }
    }

    #[test]
    fn system_peer_type_parse_refuses_any_other_spelling() {
        for s in ["something-else", "", "DLV", "  faucet  "] {
            assert_eq!(s.parse::<SystemPeerType>(), Err(()), "{s:?}");
        }
    }
}
