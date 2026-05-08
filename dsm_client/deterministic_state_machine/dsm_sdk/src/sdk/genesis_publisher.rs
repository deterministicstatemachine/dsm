//! # Genesis Publisher
//!
//! Implements the [`GenesisPublisher`](dsm::core::identity::genesis_mpc::GenesisPublisher)
//! trait to publish sanitized genesis payloads to storage nodes via the
//! `StorageNodeSDK`. Used during MPC-based genesis creation to anchor the
//! new device identity across storage nodes.

use async_trait::async_trait;
use dsm::core::identity::genesis_mpc::{GenesisPublisher, SanitizedGenesisPayload};
use dsm::types::error::DsmError;
use dsm::types::identifiers::NodeId;
use crate::sdk::storage_node_sdk::StorageNodeSDK;
use log::info;

pub struct SdkGenesisPublisher {
    storage_sdk: StorageNodeSDK,
}

impl SdkGenesisPublisher {
    pub fn new(storage_sdk: StorageNodeSDK) -> Self {
        Self { storage_sdk }
    }

    /// Serialize SanitizedGenesisPayload to bytes
    fn serialize_payload(payload: &SanitizedGenesisPayload) -> Vec<u8> {
        let mut data = Vec::new();

        // genesis_hash: 32 bytes
        data.extend_from_slice(&payload.genesis_hash);

        // device_id: 32 bytes
        data.extend_from_slice(&payload.device_id);

        // public_key: length-prefixed
        let pk_len = payload.public_key.len() as u32;
        data.extend_from_slice(&pk_len.to_le_bytes());
        data.extend_from_slice(&payload.public_key);

        // (no threshold field — whitepaper §2.5 is n-of-n, not t-of-n)

        // participants: length-prefixed vector of strings
        let participants_count = payload.participants.len() as u32;
        data.extend_from_slice(&participants_count.to_le_bytes());
        for participant in &payload.participants {
            let participant_bytes = participant.as_bytes();
            let participant_len = participant_bytes.len() as u32;
            data.extend_from_slice(&participant_len.to_le_bytes());
            data.extend_from_slice(participant_bytes);
        }

        // created_at_ticks: 8 bytes
        data.extend_from_slice(&payload.created_at_ticks.to_le_bytes());

        data
    }

    /// Deserialize bytes to SanitizedGenesisPayload
    fn deserialize_payload(data: &[u8]) -> Result<SanitizedGenesisPayload, DsmError> {
        // Layout: genesis_hash (32) ‖ device_id (32) ‖ pk_len (4) ‖ pk
        // ‖ participants_count (4) ‖ <participant>* ‖ created_at_ticks (8).
        // Threshold is no longer carried (whitepaper §2.5: n-of-n).
        if data.len() < 32 + 32 + 4 + 4 + 8 {
            return Err(DsmError::InvalidState("Payload too short".into()));
        }

        let mut offset = 0;

        let read_u32_le = |buf: &[u8], off: usize, label: &str| -> Result<u32, DsmError> {
            let slice = buf
                .get(off..off + 4)
                .ok_or_else(|| DsmError::InvalidState(format!("Invalid {label} length")))?;
            let arr: [u8; 4] = slice
                .try_into()
                .map_err(|_| DsmError::InvalidState(format!("Invalid {label} length")))?;
            Ok(u32::from_le_bytes(arr))
        };

        let read_u64_le = |buf: &[u8], off: usize, label: &str| -> Result<u64, DsmError> {
            let slice = buf
                .get(off..off + 8)
                .ok_or_else(|| DsmError::InvalidState(format!("Invalid {label} length")))?;
            let arr: [u8; 8] = slice
                .try_into()
                .map_err(|_| DsmError::InvalidState(format!("Invalid {label} length")))?;
            Ok(u64::from_le_bytes(arr))
        };

        // genesis_hash: 32 bytes
        let mut genesis_hash = [0u8; 32];
        genesis_hash.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        // device_id: 32 bytes
        let mut device_id = [0u8; 32];
        device_id.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        // public_key: length-prefixed
        let pk_len = read_u32_le(data, offset, "public key")? as usize;
        offset += 4;
        if offset + pk_len > data.len() {
            return Err(DsmError::InvalidState("Invalid public key length".into()));
        }
        let public_key = data[offset..offset + pk_len].to_vec();
        offset += pk_len;

        // (no threshold field — whitepaper §2.5 is n-of-n, not t-of-n)

        // participants: length-prefixed vector of strings
        let participants_count = read_u32_le(data, offset, "participants count")? as usize;
        offset += 4;

        let mut participants = Vec::with_capacity(participants_count);
        for _ in 0..participants_count {
            if offset + 4 > data.len() {
                return Err(DsmError::InvalidState("Invalid participant data".into()));
            }
            let participant_len = read_u32_le(data, offset, "participant length")? as usize;
            offset += 4;
            if offset + participant_len > data.len() {
                return Err(DsmError::InvalidState(
                    "Invalid participant string length".into(),
                ));
            }
            let participant_str = std::str::from_utf8(&data[offset..offset + participant_len])
                .map_err(|_| DsmError::InvalidState("Invalid participant UTF-8".into()))?;
            participants.push(NodeId::new(participant_str));
            offset += participant_len;
        }

        // created_at_ticks: 8 bytes
        if offset + 8 != data.len() {
            return Err(DsmError::InvalidState("Invalid payload length".into()));
        }
        let created_at_ticks = read_u64_le(data, offset, "created_at_ticks")?;

        Ok(SanitizedGenesisPayload {
            genesis_hash,
            device_id,
            public_key,
            participants,
            created_at_ticks,
        })
    }
}

#[async_trait]
impl GenesisPublisher for SdkGenesisPublisher {
    async fn publish(&self, payload: &SanitizedGenesisPayload) -> Result<(), DsmError> {
        log::info!(
            "SdkGenesisPublisher::publish(start): genesis_hash_b32={} device_id_b32={} public_key_len={} participants={}",
            crate::util::text_id::encode_base32_crockford(&payload.genesis_hash),
            crate::util::text_id::encode_base32_crockford(&payload.device_id),
            payload.public_key.len(),
            payload.participants.len()
        );
        // Serialize payload to bytes (using deterministic protobuf if possible, or just raw bytes for now)
        // For now, we'll just serialize the genesis hash and device id as a simple check
        // In a real implementation, we would use a proper protobuf serialization

        // Serialize the full payload using our binary format
        let body = Self::serialize_payload(payload);

        // Use the path as the key for StorageNodeSDK
        let genesis_b32 = crate::util::text_id::encode_base32_crockford(&payload.genesis_hash);
        let key = format!("genesis/{}", genesis_b32);

        self.storage_sdk.put(&key, &body, None).await.map_err(|e| {
            DsmError::network(
                format!("Failed to publish genesis: {}", e),
                None::<std::io::Error>,
            )
        })?;

        info!(
            "SdkGenesisPublisher::publish(done): published genesis to storage node: {}",
            key
        );
        Ok(())
    }

    async fn retrieve(&self, genesis_hash: &[u8; 32]) -> Result<SanitizedGenesisPayload, DsmError> {
        log::info!(
            "SdkGenesisPublisher::retrieve(start): genesis_hash_b32={}",
            crate::util::text_id::encode_base32_crockford(genesis_hash)
        );

        // Use the same key format as in publish
        let genesis_b32 = crate::util::text_id::encode_base32_crockford(genesis_hash);
        let key = format!("genesis/{}", genesis_b32);

        // Retrieve the data from storage nodes
        let body = self.storage_sdk.get(&key).await.map_err(|e| {
            DsmError::network(
                format!("Failed to retrieve genesis: {}", e),
                None::<std::io::Error>,
            )
        })?;

        // Deserialize the payload
        let payload = Self::deserialize_payload(&body)?;

        // Verify the genesis hash matches what we requested
        if payload.genesis_hash != *genesis_hash {
            return Err(DsmError::InvalidState("Genesis hash mismatch".into()));
        }

        info!(
            "SdkGenesisPublisher::retrieve(done): retrieved genesis from storage node: {}",
            key
        );
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::types::identifiers::NodeId;

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        // Create a test payload
        let payload = SanitizedGenesisPayload {
            genesis_hash: [1u8; 32],
            device_id: [2u8; 32],
            public_key: vec![3u8; 64],
            participants: vec![
                NodeId::new("node1".to_string()),
                NodeId::new("node2".to_string()),
                NodeId::new("node3".to_string()),
            ],
            created_at_ticks: 123456789,
        };

        // Serialize
        let data = SdkGenesisPublisher::serialize_payload(&payload);

        // Deserialize
        let deserialized = SdkGenesisPublisher::deserialize_payload(&data)
            .expect("deserialize payload should succeed");

        // Verify all fields match
        assert_eq!(deserialized.genesis_hash, payload.genesis_hash);
        assert_eq!(deserialized.device_id, payload.device_id);
        assert_eq!(deserialized.public_key, payload.public_key);
        assert_eq!(deserialized.participants, payload.participants);
        assert_eq!(deserialized.created_at_ticks, payload.created_at_ticks);
    }

    #[test]
    fn test_deserialize_invalid_data() {
        // Test with too short data
        let short_data = vec![0u8; 10];
        assert!(SdkGenesisPublisher::deserialize_payload(&short_data).is_err());

        // Test with invalid UTF-8 in participant
        let mut invalid_data = SdkGenesisPublisher::serialize_payload(&SanitizedGenesisPayload {
            genesis_hash: [1u8; 32],
            device_id: [2u8; 32],
            public_key: vec![3u8; 64],
            participants: vec![NodeId::new("valid".to_string())],
            created_at_ticks: 123,
        });
        // Layout offsets: genesis_hash (32) ‖ device_id (32) ‖ pk_len (4) ‖
        // pk (64) ‖ participants_count (4) ‖ participant_len (4) ‖ ...
        // We corrupt the first byte of the participant string itself.
        let participant_start = 32 + 32 + 4 + 64 + 4; // offset to first participant length
        if participant_start + 4 < invalid_data.len() {
            invalid_data[participant_start + 4] = 0xFF; // invalid UTF-8 byte
        }
        assert!(SdkGenesisPublisher::deserialize_payload(&invalid_data).is_err());
    }
}
