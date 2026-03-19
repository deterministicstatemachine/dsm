//! # External Commitment SDK
//!
//! Creates, publishes, and verifies External Commitments — cryptographic
//! anchors that bind off-chain evidence (e.g. Bitcoin block headers, oracle
//! attestations) into a device's DSM hash chain via storage-node mirroring.

use crate::sdk::storage_node_sdk::StorageNodeSDK;
use dsm::commitments::{
    create_external_commitment, external_evidence_hash, external_source_id, ExternalCommitment,
};
use dsm::types::error::DsmError;
use std::collections::HashMap;
use std::sync::Arc;

/// External Commitment SDK for managing external commitments
pub struct ExternalCommitmentSdk {
    #[allow(dead_code)]
    config: HashMap<String, String>,
    storage_sdk: Option<Arc<StorageNodeSDK>>,
}

impl ExternalCommitmentSdk {
    /// Create a new External Commitment SDK instance
    pub fn new(config: HashMap<String, String>) -> Self {
        Self {
            config,
            storage_sdk: None,
        }
    }

    /// Create a new External Commitment SDK instance with storage support
    pub fn new_with_storage(
        config: HashMap<String, String>,
        storage_sdk: Arc<StorageNodeSDK>,
    ) -> Self {
        Self {
            config,
            storage_sdk: Some(storage_sdk),
        }
    }

    /// Fetch an external commitment by ID
    pub async fn fetch_commitment(
        &self,
        commitment_id: &str,
    ) -> Result<ExternalCommitment, DsmError> {
        if let Some(sdk) = &self.storage_sdk {
            // Fetch bytes from storage node
            let bytes = sdk.get(commitment_id).await.map_err(|e| {
                DsmError::external_commitment(format!(
                    "Failed to fetch commitment {commitment_id}: {e}"
                ))
            })?;

            // Deserialize
            self.deserialize_commitment(&bytes)
        } else {
            Err(DsmError::external_commitment(format!(
                "Storage SDK not configured, cannot fetch commitment ID: {commitment_id}",
            )))
        }
    }

    /// Serialize commitment to bytes for storage
    /// Format: version(1) | payload_len(4) | payload | source_id(32) | evidence_len(4) | evidence | commit_id(32)
    fn serialize_commitment(&self, commitment: &ExternalCommitment) -> Vec<u8> {
        let mut bytes = Vec::new();
        // Version 2
        bytes.push(2);

        // Payload
        let payload_len = commitment.payload.len() as u32;
        bytes.extend_from_slice(&payload_len.to_le_bytes());
        bytes.extend_from_slice(&commitment.payload);

        // Source id
        bytes.extend_from_slice(&commitment.source_id);

        // Evidence
        let evidence_len = commitment.evidence.len() as u32;
        bytes.extend_from_slice(&evidence_len.to_le_bytes());
        bytes.extend_from_slice(&commitment.evidence);

        // Commit id
        bytes.extend_from_slice(&commitment.commit_id);

        bytes
    }

    /// Deserialize commitment from bytes
    fn deserialize_commitment(&self, data: &[u8]) -> Result<ExternalCommitment, DsmError> {
        if data.len() < 1 + 4 + 32 + 4 + 32 {
            return Err(DsmError::invalid_operation("Commitment data too short"));
        }

        let mut cursor = 0;

        // Version check
        if data[cursor] != 2 {
            return Err(DsmError::invalid_operation(format!(
                "Unsupported commitment version: {}",
                data[cursor]
            )));
        }
        cursor += 1;

        // Payload
        if cursor + 4 > data.len() {
            return Err(DsmError::invalid_operation("Invalid data length"));
        }
        let payload_len = u32::from_le_bytes(
            data[cursor..cursor + 4]
                .try_into()
                .map_err(|_| DsmError::invalid_operation("Failed to parse length"))?,
        ) as usize;
        cursor += 4;

        if cursor + payload_len > data.len() {
            return Err(DsmError::invalid_operation("Invalid payload length"));
        }
        let payload = data[cursor..cursor + payload_len].to_vec();
        cursor += payload_len;

        // Source id
        if cursor + 32 > data.len() {
            return Err(DsmError::invalid_operation("Missing source id"));
        }
        let mut source_id = [0u8; 32];
        source_id.copy_from_slice(&data[cursor..cursor + 32]);
        cursor += 32;

        // Evidence
        if cursor + 4 > data.len() {
            return Err(DsmError::invalid_operation("Invalid data length"));
        }
        let evidence_len = u32::from_le_bytes(
            data[cursor..cursor + 4]
                .try_into()
                .map_err(|_| DsmError::invalid_operation("Failed to parse length"))?,
        ) as usize;
        cursor += 4;

        if cursor + evidence_len > data.len() {
            return Err(DsmError::invalid_operation("Invalid evidence length"));
        }
        let evidence = data[cursor..cursor + evidence_len].to_vec();
        cursor += evidence_len;

        // Commit id
        if cursor + 32 > data.len() {
            return Err(DsmError::invalid_operation("Missing commit id"));
        }
        let mut commit_id = [0u8; 32];
        commit_id.copy_from_slice(&data[cursor..cursor + 32]);

        // Allow extra bytes? Strict:
        // if cursor + 32 != data.len() { return Err(...) }
        // But for forward compatibility maybe allow.

        Ok(ExternalCommitment {
            payload,
            source_id,
            evidence,
            commit_id,
        })
    }

    /// Serialize v2 commitment bytes (public, strict)
    pub fn to_v2_bytes(&self, commitment: &ExternalCommitment) -> Vec<u8> {
        self.serialize_commitment(commitment)
    }

    /// Deserialize v2 commitment bytes (public, strict)
    pub fn from_v2_bytes(&self, data: &[u8]) -> Result<ExternalCommitment, DsmError> {
        self.deserialize_commitment(data)
    }

    /// List all external commitments
    pub async fn list_commitments(&self) -> Result<Vec<ExternalCommitment>, DsmError> {
        // Direct listing is not available in the API
        Err(DsmError::external_commitment(
            "List commitments functionality not available in current API".to_string(),
        ))
    }

    /// Verify an external commitment using the API
    pub async fn verify_commitment_with_data(
        &self,
        commit_id: &[u8],
        source: &str,
        data: &[u8],
        evidence: &[u8],
    ) -> Result<bool, DsmError> {
        if commit_id.len() != 32 {
            return Err(DsmError::invalid_operation("commit_id must be 32 bytes"));
        }
        let source_id = external_source_id(source);
        let evidence_hash = external_evidence_hash(evidence);
        let expected = create_external_commitment(data, &source_id, &evidence_hash);
        Ok(expected.as_slice() == commit_id)
    }

    /// Verify an external commitment structure internally
    pub fn verify_commitment(&self, commitment: &ExternalCommitment) -> Result<bool, DsmError> {
        // Validate commitment format using actual struct fields
        self.validate_commitment_format(commitment)
    }

    /// Validate commitment format using actual ExternalCommitment fields
    fn validate_commitment_format(
        &self,
        commitment: &ExternalCommitment,
    ) -> Result<bool, DsmError> {
        // Check if payload is not empty
        if commitment.payload.is_empty() {
            return Err(DsmError::invalid_operation("Payload cannot be empty"));
        }

        if commitment.source_id == [0u8; 32] {
            return Err(DsmError::invalid_operation("Source id cannot be zero"));
        }

        if commitment.commit_id == [0u8; 32] {
            return Err(DsmError::invalid_operation("Commit id cannot be zero"));
        }

        Ok(true)
    }

    /// Register an external commitment using the API
    pub async fn register_commitment(
        &self,
        data: &[u8],
        provider: &str,
    ) -> Result<String, DsmError> {
        let commitment = ExternalCommitment::new_with_source(data.to_vec(), provider, Vec::new());

        if let Some(sdk) = &self.storage_sdk {
            let serialized = self.serialize_commitment(&commitment);
            // Calculate CAS key logic
            let hash = dsm::crypto::blake3::domain_hash("DSM/external-commit-hash", &serialized);
            let key = crate::util::text_id::encode_base32_crockford(hash.as_bytes());

            // Store using store_data(key, data)
            let addr = sdk.store_data(&key, &serialized).await.map_err(|e| {
                DsmError::external_commitment(format!("Failed to register commitment: {e}"))
            })?;

            Ok(addr)
        } else {
            Err(DsmError::external_commitment(
                "Storage SDK not configured, cannot register commitment".to_string(),
            ))
        }
    }

    /// Create a new external commitment
    pub fn create_commitment(
        &self,
        payload: Vec<u8>,
        source: &str,
        evidence: Vec<u8>,
    ) -> Result<ExternalCommitment, DsmError> {
        // Create commitment using the correct constructor
        let commitment = ExternalCommitment::new_with_source(payload, source, evidence);

        // Validate the new commitment
        match self.validate_commitment_format(&commitment) {
            Ok(_) => Ok(commitment),
            Err(e) => Err(DsmError::invalid_operation(format!(
                "Failed to create commitment: {e}"
            ))),
        }
    }

    /// Delete an external commitment
    pub async fn delete_commitment(&self, commitment_id: &str) -> Result<(), DsmError> {
        if let Some(sdk) = &self.storage_sdk {
            sdk.delete(commitment_id).await.map_err(|e| {
                DsmError::external_commitment(format!(
                    "Failed to delete commitment {commitment_id}: {e}"
                ))
            })
        } else {
            Err(DsmError::external_commitment(format!(
                "Storage SDK not configured, cannot delete commitment: {commitment_id}",
            )))
        }
    }

    /// Get commitment statistics (simplified implementation)
    pub async fn get_statistics(&self) -> Result<HashMap<String, u64>, DsmError> {
        // Since listing is not available, return minimal stats
        let mut stats = HashMap::new();
        stats.insert("total_commitments".to_string(), 0u64);
        stats.insert("unique_providers".to_string(), 0u64);

        Ok(stats)
    }

    /// Verify a commitment internally using its verify method
    pub fn verify_commitment_internal(
        &self,
        commitment: &ExternalCommitment,
        payload: &[u8],
    ) -> bool {
        commitment.verify(payload)
    }

    /// Get the external hash from a commitment
    pub fn get_external_hash(&self, commitment: &ExternalCommitment) -> Vec<u8> {
        commitment.commit_id.to_vec()
    }

    /// Get the payload from a commitment
    pub fn get_payload(&self, commitment: &ExternalCommitment) -> Vec<u8> {
        commitment.payload.clone()
    }

    /// Get the source id from a commitment
    pub fn get_source_id(&self, commitment: &ExternalCommitment) -> Vec<u8> {
        commitment.source_id.to_vec()
    }
}
