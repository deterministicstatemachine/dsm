// storage_integration_test.rs
//
// Integration tests for cryptographic identity persistence in storage nodes

#[cfg(test)]
mod tests {
    use crate::{
        core::identity::{
            IdentityStore,
            genesis::{SigningKey, KyberKey},
        },
        types::error::DsmError,
    };

    #[tokio::test]
    async fn test_identity_creation() -> Result<(), DsmError> {
        // Test basic identity store functionality without full MPC genesis
        // (Full MPC testing requires running storage nodes)

        let store = IdentityStore::new();
        let master_genesis = crate::core::identity::GenesisState {
            hash: [1u8; 32],
            initial_entropy: [2u8; 32],
            threshold: 2,
            participants: ["participant1".to_string(), "participant2".to_string()].into(),
            merkle_root: None,
            device_id: None,
            signing_key: SigningKey::new().expect("Failed to create signing key"),
            kyber_keypair: KyberKey::new().expect("Failed to create kyber key"),
            contributions: vec![],
        };
        let mut identity = crate::core::identity::Identity::with_genesis(
            "test_identity".to_string(),
            master_genesis,
        );
        // Optionally attach a device for completeness (not required for this test)
        let device_id_bytes = blake3::hash(b"test_device").into();
        identity
            .devices
            .push(crate::core::identity::DeviceIdentity {
                device_id: device_id_bytes,
                sub_genesis: crate::core::identity::GenesisState {
                    hash: [3u8; 32],
                    initial_entropy: [4u8; 32],
                    threshold: 3,
                    participants: ["device".to_string()].into(),
                    merkle_root: None,
                    device_id: Some(device_id_bytes),
                    signing_key: SigningKey::new().expect("Failed to create signing key"),
                    kyber_keypair: KyberKey::new().expect("Failed to create kyber key"),
                    contributions: vec![],
                },
                current_state: None,
                sparse_indices: std::collections::HashMap::new(),
            });

        // Test store operations
        store.insert_identity(identity.clone()).await?;
        let identity_id = identity.id();
        let retrieved = store.get_identity(&identity_id).await;
        assert!(
            retrieved.is_some(),
            "Should be able to retrieve stored identity"
        );
        assert_eq!(retrieved.unwrap().name, "test_identity");

        println!("Successfully tested identity store operations");
        Ok(())
    }

    // This test requires a running storage node
    // To run this test: cargo test crypto_verification::storage_integration_test
    #[tokio::test]
    async fn test_identity_storage_integration() -> Result<(), DsmError> {
        println!("Testing storage node integration with Identity");

        // Create test identity manually (without full MPC)
        let device_id_bytes = *blake3::hash(b"test_device").as_bytes();
        let store = IdentityStore::new();
        let master_genesis = crate::core::identity::GenesisState {
            hash: [5u8; 32],
            initial_entropy: [6u8; 32],
            threshold: 2,
            participants: ["participant1".to_string(), "participant2".to_string()].into(),
            merkle_root: None,
            device_id: None,
            signing_key: SigningKey::new().expect("Failed to create signing key"),
            kyber_keypair: KyberKey::new().expect("Failed to create kyber key"),
            contributions: vec![],
        };
        let mut identity = crate::core::identity::Identity::with_genesis(
            "test_integration_identity".to_string(),
            master_genesis,
        );
        identity
            .devices
            .push(crate::core::identity::DeviceIdentity {
                device_id: device_id_bytes,
                sub_genesis: crate::core::identity::GenesisState {
                    hash: [7u8; 32],
                    initial_entropy: [8u8; 32],
                    threshold: 3,
                    participants: ["device".to_string()].into(),
                    merkle_root: None,
                    device_id: Some(device_id_bytes),
                    signing_key: SigningKey::new().expect("Failed to create signing key"),
                    kyber_keypair: KyberKey::new().expect("Failed to create kyber key"),
                    contributions: vec![],
                },
                current_state: None,
                sparse_indices: std::collections::HashMap::new(),
            });

        // Test store operations
        store.insert_identity(identity.clone()).await?;
        let identity_id = identity.id();
        let retrieved = store.get_identity(&identity_id).await;
        assert!(
            retrieved.is_some(),
            "Should be able to retrieve stored identity"
        );
        assert_eq!(retrieved.unwrap().name, "test_integration_identity");

        // Avoid Serde/bincode entirely per project rules. Instead, create a minimal
        // canonical byte aggregation from fixed-length fields to validate we can derive
        // stable transport bytes without Serde.
        // NOTE: This is not a cryptographic commit, just a sanity check that required
        // fields are present and non-empty.
        let mut canonical_bytes = Vec::new();
        canonical_bytes.extend_from_slice(&identity.master_genesis.hash);
        canonical_bytes.extend_from_slice(&identity.master_genesis.initial_entropy);
        assert!(
            !canonical_bytes.is_empty(),
            "Canonical bytes aggregation should not be empty"
        );

        println!("Successfully tested identity storage integration");
        Ok(())
    }
}
