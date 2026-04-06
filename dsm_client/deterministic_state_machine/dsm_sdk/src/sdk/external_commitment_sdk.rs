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

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::commitments::{create_external_commitment, external_evidence_hash, external_source_id};
    use std::collections::HashMap;

    fn make_sdk() -> ExternalCommitmentSdk {
        ExternalCommitmentSdk::new(HashMap::new())
    }

    fn sample_commitment() -> ExternalCommitment {
        ExternalCommitment::new_with_source(
            b"payload-data".to_vec(),
            "bitcoin",
            b"block-hash".to_vec(),
        )
    }

    // ---- serialize / deserialize round-trip ----

    #[test]
    fn serialize_deserialize_round_trip() {
        let sdk = make_sdk();
        let c = sample_commitment();
        let bytes = sdk.serialize_commitment(&c);
        let recovered = sdk.deserialize_commitment(&bytes).unwrap();

        assert_eq!(recovered.payload, c.payload);
        assert_eq!(recovered.source_id, c.source_id);
        assert_eq!(recovered.evidence, c.evidence);
        assert_eq!(recovered.commit_id, c.commit_id);
    }

    #[test]
    fn serialize_deserialize_empty_evidence() {
        let sdk = make_sdk();
        let c = ExternalCommitment::new_with_source(b"data".to_vec(), "oracle", Vec::new());
        let bytes = sdk.serialize_commitment(&c);
        let recovered = sdk.deserialize_commitment(&bytes).unwrap();
        assert!(recovered.evidence.is_empty());
        assert_eq!(recovered.payload, b"data");
    }

    #[test]
    fn serialize_deserialize_large_payload() {
        let sdk = make_sdk();
        let big_payload = vec![0xABu8; 10_000];
        let c = ExternalCommitment::new_with_source(big_payload.clone(), "src", b"ev".to_vec());
        let bytes = sdk.serialize_commitment(&c);
        let recovered = sdk.deserialize_commitment(&bytes).unwrap();
        assert_eq!(recovered.payload, big_payload);
    }

    #[test]
    fn to_v2_bytes_from_v2_bytes_public_api() {
        let sdk = make_sdk();
        let c = sample_commitment();
        let bytes = sdk.to_v2_bytes(&c);
        let recovered = sdk.from_v2_bytes(&bytes).unwrap();
        assert_eq!(recovered.commit_id, c.commit_id);
    }

    // ---- deserialize error cases ----

    #[test]
    fn deserialize_too_short() {
        let sdk = make_sdk();
        let err = sdk.deserialize_commitment(&[0u8; 10]).unwrap_err();
        assert!(format!("{err:?}").contains("too short"));
    }

    #[test]
    fn deserialize_wrong_version() {
        let sdk = make_sdk();
        let mut bytes = vec![1u8]; // version 1 unsupported
        bytes.extend_from_slice(&[0u8; 72]);
        let err = sdk.deserialize_commitment(&bytes).unwrap_err();
        assert!(format!("{err:?}").contains("Unsupported commitment version"));
    }

    #[test]
    fn deserialize_truncated_payload() {
        let sdk = make_sdk();
        // Need total > 73 bytes to pass minimum length check, then fail at payload boundary
        let mut bytes = vec![2u8]; // version
        bytes.extend_from_slice(&1000u32.to_le_bytes()); // payload_len = 1000
                                                         // Pad to pass min length check (73 bytes total) but payload is still short
        bytes.extend_from_slice(&[0u8; 80]);
        let err = sdk.deserialize_commitment(&bytes).unwrap_err();
        assert!(
            err.to_string().contains("payload")
                || format!("{err:?}").contains("payload")
                || err.to_string().contains("length")
                || format!("{err:?}").contains("length")
        );
    }

    #[test]
    fn deserialize_truncated_evidence() {
        let sdk = make_sdk();
        let mut bytes = vec![2u8]; // version
        let payload = vec![0xAA; 10]; // 10-byte payload
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&payload);
        bytes.extend_from_slice(&[1u8; 32]); // source_id
        bytes.extend_from_slice(&500u32.to_le_bytes()); // evidence_len=500
        bytes.extend_from_slice(&[0u8; 40]); // only 40 bytes (need 500)
        let err = sdk.deserialize_commitment(&bytes).unwrap_err();
        assert!(
            err.to_string().contains("evidence")
                || format!("{err:?}").contains("evidence")
                || err.to_string().contains("length")
                || format!("{err:?}").contains("length")
        );
    }

    #[test]
    fn deserialize_missing_source_id_rejects() {
        let sdk = make_sdk();
        // Payload that doesn't leave enough room for source_id (32 bytes)
        let mut bytes = vec![2u8]; // version
        let payload = vec![0xCC; 50];
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&payload);
        bytes.extend_from_slice(&[0u8; 10]); // only 10 bytes after payload
        assert!(sdk.deserialize_commitment(&bytes).is_err());
    }

    #[test]
    fn deserialize_missing_commit_id_rejects() {
        let sdk = make_sdk();
        let mut bytes = vec![2u8]; // version
        let payload = vec![0xDD; 5];
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&payload);
        bytes.extend_from_slice(&[2u8; 32]); // source_id
        bytes.extend_from_slice(&0u32.to_le_bytes()); // evidence_len=0
        bytes.extend_from_slice(&[0u8; 10]); // only 10 bytes for commit_id
        assert!(sdk.deserialize_commitment(&bytes).is_err());
    }

    // ---- validate_commitment_format ----

    #[test]
    fn validate_format_good_commitment() {
        let sdk = make_sdk();
        let c = sample_commitment();
        assert!(sdk.validate_commitment_format(&c).unwrap());
    }

    #[test]
    fn validate_format_empty_payload() {
        let sdk = make_sdk();
        let c = ExternalCommitment {
            payload: Vec::new(),
            source_id: [1u8; 32],
            evidence: Vec::new(),
            commit_id: [2u8; 32],
        };
        let err = sdk.validate_commitment_format(&c).unwrap_err();
        assert!(format!("{err:?}").contains("Payload cannot be empty"));
    }

    #[test]
    fn validate_format_zero_source_id() {
        let sdk = make_sdk();
        let c = ExternalCommitment {
            payload: vec![1],
            source_id: [0u8; 32],
            evidence: Vec::new(),
            commit_id: [2u8; 32],
        };
        let err = sdk.validate_commitment_format(&c).unwrap_err();
        assert!(format!("{err:?}").contains("Source id cannot be zero"));
    }

    #[test]
    fn validate_format_zero_commit_id() {
        let sdk = make_sdk();
        let c = ExternalCommitment {
            payload: vec![1],
            source_id: [1u8; 32],
            evidence: Vec::new(),
            commit_id: [0u8; 32],
        };
        let err = sdk.validate_commitment_format(&c).unwrap_err();
        assert!(format!("{err:?}").contains("Commit id cannot be zero"));
    }

    // ---- create_commitment ----

    #[test]
    fn create_commitment_success() {
        let sdk = make_sdk();
        let c = sdk
            .create_commitment(b"hello".to_vec(), "bitcoin", b"evidence".to_vec())
            .unwrap();
        assert_eq!(c.payload, b"hello");
        assert_ne!(c.source_id, [0u8; 32]);
        assert_ne!(c.commit_id, [0u8; 32]);
    }

    #[test]
    fn create_commitment_empty_payload_fails() {
        let sdk = make_sdk();
        let err = sdk
            .create_commitment(Vec::new(), "bitcoin", Vec::new())
            .unwrap_err();
        assert!(format!("{err:?}").contains("Payload cannot be empty"));
    }

    // ---- verify_commitment ----

    #[test]
    fn verify_commitment_valid() {
        let sdk = make_sdk();
        let c = sample_commitment();
        assert!(sdk.verify_commitment(&c).unwrap());
    }

    #[test]
    fn verify_commitment_internal_matches_payload() {
        let sdk = make_sdk();
        let c = sample_commitment();
        assert!(sdk.verify_commitment_internal(&c, b"payload-data"));
    }

    #[test]
    fn verify_commitment_internal_wrong_payload() {
        let sdk = make_sdk();
        let c = sample_commitment();
        assert!(!sdk.verify_commitment_internal(&c, b"wrong-data"));
    }

    // ---- verify_commitment_with_data ----

    #[tokio::test]
    async fn verify_commitment_with_data_correct() {
        let sdk = make_sdk();
        let source = "bitcoin";
        let data = b"my-payload";
        let evidence = b"block-header";
        let source_id = external_source_id(source);
        let evidence_hash = external_evidence_hash(evidence);
        let commit_id = create_external_commitment(data, &source_id, &evidence_hash);
        assert!(sdk
            .verify_commitment_with_data(&commit_id, source, data, evidence)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn verify_commitment_with_data_wrong_source() {
        let sdk = make_sdk();
        let source_id = external_source_id("bitcoin");
        let evidence_hash = external_evidence_hash(b"ev");
        let commit_id = create_external_commitment(b"data", &source_id, &evidence_hash);
        assert!(!sdk
            .verify_commitment_with_data(&commit_id, "ethereum", b"data", b"ev")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn verify_commitment_with_data_wrong_length() {
        let sdk = make_sdk();
        let err = sdk
            .verify_commitment_with_data(&[0u8; 16], "src", b"data", b"ev")
            .await
            .unwrap_err();
        assert!(format!("{err:?}").contains("32 bytes"));
    }

    // ---- accessor helpers ----

    #[test]
    fn get_external_hash_returns_commit_id() {
        let sdk = make_sdk();
        let c = sample_commitment();
        assert_eq!(sdk.get_external_hash(&c), c.commit_id.to_vec());
    }

    #[test]
    fn get_payload_returns_payload() {
        let sdk = make_sdk();
        let c = sample_commitment();
        assert_eq!(sdk.get_payload(&c), b"payload-data".to_vec());
    }

    #[test]
    fn get_source_id_returns_source_id() {
        let sdk = make_sdk();
        let c = sample_commitment();
        let expected = external_source_id("bitcoin");
        assert_eq!(sdk.get_source_id(&c), expected.to_vec());
    }

    // ---- statistics ----

    #[tokio::test]
    async fn get_statistics_returns_defaults() {
        let sdk = make_sdk();
        let stats = sdk.get_statistics().await.unwrap();
        assert_eq!(stats["total_commitments"], 0);
        assert_eq!(stats["unique_providers"], 0);
    }

    // ---- list_commitments always errors ----

    #[tokio::test]
    async fn list_commitments_not_available() {
        let sdk = make_sdk();
        assert!(sdk.list_commitments().await.is_err());
    }

    // ---- no storage SDK operations ----

    #[tokio::test]
    async fn fetch_commitment_without_storage_errors() {
        let sdk = make_sdk();
        assert!(sdk.fetch_commitment("abc").await.is_err());
    }

    #[tokio::test]
    async fn register_commitment_without_storage_errors() {
        let sdk = make_sdk();
        assert!(sdk.register_commitment(b"data", "prov").await.is_err());
    }

    #[tokio::test]
    async fn delete_commitment_without_storage_errors() {
        let sdk = make_sdk();
        assert!(sdk.delete_commitment("id").await.is_err());
    }

    // ---- serialization format details ----

    #[test]
    fn serialize_starts_with_version_2() {
        let sdk = make_sdk();
        let c = sample_commitment();
        let bytes = sdk.serialize_commitment(&c);
        assert_eq!(bytes[0], 2);
    }

    #[test]
    fn serialize_payload_length_correct() {
        let sdk = make_sdk();
        let c = sample_commitment();
        let bytes = sdk.serialize_commitment(&c);
        let payload_len = u32::from_le_bytes(bytes[1..5].try_into().unwrap()) as usize;
        assert_eq!(payload_len, c.payload.len());
    }

    // ---- serialization is deterministic ----

    #[test]
    fn serialize_deterministic_same_input_same_output() {
        let sdk = make_sdk();
        let c = sample_commitment();
        let bytes1 = sdk.serialize_commitment(&c);
        let bytes2 = sdk.serialize_commitment(&c);
        assert_eq!(bytes1, bytes2);
    }

    // ---- deserialize with trailing bytes succeeds (forward compat) ----

    #[test]
    fn deserialize_with_trailing_bytes_succeeds() {
        let sdk = make_sdk();
        let c = sample_commitment();
        let mut bytes = sdk.serialize_commitment(&c);
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let recovered = sdk.deserialize_commitment(&bytes).unwrap();
        assert_eq!(recovered.payload, c.payload);
        assert_eq!(recovered.commit_id, c.commit_id);
    }

    // ---- constructor ----

    #[test]
    fn new_stores_config() {
        let mut config = HashMap::new();
        config.insert("key1".to_string(), "value1".to_string());
        config.insert("key2".to_string(), "value2".to_string());
        let sdk = ExternalCommitmentSdk::new(config);
        assert!(sdk.storage_sdk.is_none());
    }

    // ---- create_commitment with different sources have different source_ids ----

    #[test]
    fn create_commitment_different_sources_different_ids() {
        let sdk = make_sdk();
        let c1 = sdk
            .create_commitment(b"data".to_vec(), "bitcoin", Vec::new())
            .unwrap();
        let c2 = sdk
            .create_commitment(b"data".to_vec(), "ethereum", Vec::new())
            .unwrap();
        assert_ne!(c1.source_id, c2.source_id);
    }

    // ---- create_commitment same inputs produce same commit_id ----

    #[test]
    fn create_commitment_deterministic() {
        let sdk = make_sdk();
        let c1 = sdk
            .create_commitment(b"payload".to_vec(), "src", b"ev".to_vec())
            .unwrap();
        let c2 = sdk
            .create_commitment(b"payload".to_vec(), "src", b"ev".to_vec())
            .unwrap();
        assert_eq!(c1.commit_id, c2.commit_id);
        assert_eq!(c1.source_id, c2.source_id);
    }

    // ---- verify_commitment_with_data wrong evidence ----

    #[tokio::test]
    async fn verify_commitment_with_data_wrong_evidence() {
        let sdk = make_sdk();
        let source = "oracle";
        let data = b"my-data";
        let evidence = b"correct-evidence";
        let source_id = external_source_id(source);
        let evidence_hash = external_evidence_hash(evidence);
        let commit_id = create_external_commitment(data, &source_id, &evidence_hash);
        assert!(!sdk
            .verify_commitment_with_data(&commit_id, source, data, b"wrong-evidence")
            .await
            .unwrap());
    }

    // ---- verify_commitment on invalid structures ----

    #[test]
    fn verify_commitment_empty_payload_fails() {
        let sdk = make_sdk();
        let c = ExternalCommitment {
            payload: Vec::new(),
            source_id: [1u8; 32],
            evidence: vec![1],
            commit_id: [2u8; 32],
        };
        assert!(sdk.verify_commitment(&c).is_err());
    }

    #[test]
    fn verify_commitment_zero_source_fails() {
        let sdk = make_sdk();
        let c = ExternalCommitment {
            payload: vec![1],
            source_id: [0u8; 32],
            evidence: Vec::new(),
            commit_id: [2u8; 32],
        };
        assert!(sdk.verify_commitment(&c).is_err());
    }

    // ---- serialize evidence_len position ----

    #[test]
    fn serialize_evidence_length_correct() {
        let sdk = make_sdk();
        let evidence = b"my-evidence-data";
        let c = ExternalCommitment::new_with_source(b"pl".to_vec(), "src", evidence.to_vec());
        let bytes = sdk.serialize_commitment(&c);

        let payload_len = u32::from_le_bytes(bytes[1..5].try_into().unwrap()) as usize;
        let evidence_offset = 1 + 4 + payload_len + 32;
        let evidence_len = u32::from_le_bytes(
            bytes[evidence_offset..evidence_offset + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        assert_eq!(evidence_len, evidence.len());
    }

    // ---- get_external_hash / get_payload / get_source_id consistency ----

    #[test]
    fn accessor_helpers_consistent_with_fields() {
        let sdk = make_sdk();
        let c = ExternalCommitment::new_with_source(
            b"test-payload".to_vec(),
            "test-source",
            b"test-evidence".to_vec(),
        );
        assert_eq!(sdk.get_payload(&c), c.payload);
        assert_eq!(sdk.get_external_hash(&c), c.commit_id.to_vec());
        assert_eq!(sdk.get_source_id(&c), c.source_id.to_vec());
    }

    // ---- deserialize payload boundary ----

    #[test]
    fn deserialize_zero_length_payload() {
        let sdk = make_sdk();
        let mut bytes = vec![2u8]; // version
        bytes.extend_from_slice(&0u32.to_le_bytes()); // payload_len = 0
        bytes.extend_from_slice(&[5u8; 32]); // source_id
        bytes.extend_from_slice(&0u32.to_le_bytes()); // evidence_len = 0
        bytes.extend_from_slice(&[6u8; 32]); // commit_id
        let recovered = sdk.deserialize_commitment(&bytes).unwrap();
        assert!(recovered.payload.is_empty());
        assert!(recovered.evidence.is_empty());
        assert_eq!(recovered.source_id, [5u8; 32]);
        assert_eq!(recovered.commit_id, [6u8; 32]);
    }
}
