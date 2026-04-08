//! Deterministic Limbo Vault SDK (STRICT, fail-closed)
//!
//! This SDK exposes high-level, *identity-centric* helpers for DLVs.
//! - SPHINCS+ signing authority is derived from canonical C-DBRW state.
//! - Content Encryption Key (CEK) and unsealing KEK are managed **inside DLVManager**.
//! - No alternate paths, no discovery shortcuts, explicit errors on missing inputs.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
};
use crate::util::deterministic_time as dt;

use prost::Message;
use dsm::types::proto::{SmartPolicy, VaultPostProto};
use dsm::crypto::blake3;

// No hex/base64 here; bytes-only.

// Byte-key store: identity -> (public, secret)
type KeyStore = Arc<RwLock<HashMap<String, (Vec<u8>, Vec<u8>)>>>;

/// Helper: Get canonical protobuf bytes for SmartPolicy
fn policy_bytes(policy: &SmartPolicy) -> Vec<u8> {
    policy.encode_to_vec()
}

/// Helper: Compute BLAKE3 hash of SmartPolicy bytes (policy anchor)
fn policy_hash_b3(policy: &SmartPolicy) -> [u8; 32] {
    *blake3::domain_hash("DSM/dlv-policy", &policy_bytes(policy)).as_bytes()
}

fn vault_post_from_proto(proto: VaultPostProto) -> VaultPost {
    VaultPost {
        vault_id: proto.vault_id,
        lock_description: proto.lock_description,
        creator_id: proto.creator_id,
        commitment_hash: proto.commitment_hash,
        status: proto.status,
        metadata: proto
            .metadata
            .into_iter()
            .map(|kv| (kv.key, kv.value))
            .collect(),
        vault_data: proto.vault_data,
    }
}

use dsm::{
    crypto::{kyber, kyber::KyberKeyPair, sphincs},
    types::{error::DsmError, policy_types::VaultCondition, state_types::State},
    vault::{
        asset_manager::{AssetManager, AssetType, DigitalAsset},
        dlv_manager::DLVManager,
        FulfillmentMechanism, FulfillmentProof, LimboVault, VaultPost, VaultState,
    },
};
use crate::sdk::receipts::{compute_protocol_transition_commitment, encode_protocol_transition_payload};

/// High-level SDK for Deterministic Limbo Vault operations
pub struct DlvSdk {
    /// Internal vault manager (handles CEK/KEK and validation)
    manager: Arc<DLVManager>,
    /// Asset manager for handling digital assets
    asset_manager: Arc<Mutex<AssetManager>>,
    /// Encryption key store (Kyber for vault encryption)
    kyber_key_store: KeyStore,
}

/// Configuration for creating a new vault
#[derive(Debug, Clone)]
pub struct VaultConfig {
    /// Content to store in the vault
    pub content: Vec<u8>,
    /// MIME type of the content
    pub content_type: String,
    /// Human-readable description of the vault purpose
    pub description: String,
    /// Optional intended recipient public key
    pub recipient_public_key: Option<Vec<u8>>,
    /// Fulfillment condition for the vault
    pub condition: VaultCondition,
    /// Optional timeout for the vault (in seconds from now)
    pub timeout_seconds: Option<u64>,
    /// Optional metadata for the vault
    pub metadata: HashMap<String, String>,
}

/// Result of a vault creation operation
#[derive(Debug, Clone)]
pub struct VaultCreationResult {
    /// Unique identifier of the created vault
    pub vault_id: String,
    /// Creator's SPHINCS+ public key (identity key)
    pub creator_public_key: Vec<u8>,
    /// Vault post ready for storage/sharing
    pub vault_post: VaultPost,
    /// Creation logical tick (deterministic, not wall-clock)
    pub created_at: u64,
}

/// Information about a vault's current state
#[derive(Debug, Clone)]
pub struct VaultInfo {
    /// Vault identifier
    pub id: String,
    /// Creator's public key
    pub creator_public_key: Vec<u8>,
    /// Current state of the vault
    pub state: VaultState,
    /// Content type
    pub content_type: String,
    /// Creation state number
    pub created_at_state: u64,
    /// Intended recipient (if any)
    pub intended_recipient: Option<Vec<u8>>,
    /// Human-readable condition description
    pub condition_description: String,
}

/// Options for vault unlocking
#[derive(Debug, Clone)]
pub struct UnlockOptions {
    /// Requester's public key — Kyber key checked against vault's `intended_recipient`.
    pub requester_public_key: Vec<u8>,
    /// SPHINCS+ public key embedded in the DlvUnlock operation for signature verification.
    /// If `None`, the SDK derives the current canonical C-DBRW signing public key.
    pub signing_public_key: Option<Vec<u8>>,
    /// Additional context data
    pub context: HashMap<String, String>,
    /// Optional stitched receipt commitment sigma.
    /// If absent, SDK derives one deterministically from unlock inputs.
    pub stitched_receipt_sigma: Option<[u8; 32]>,
}

impl DlvSdk {
    /// Create a new DLV SDK instance
    pub fn new() -> Self {
        Self {
            manager: Arc::new(DLVManager::new()),
            asset_manager: Arc::new(Mutex::new(AssetManager::new())),
            kyber_key_store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    // ------------------------------------------------------------------------
    // Encryption key management (Kyber) — for vault content encryption
    // ------------------------------------------------------------------------

    /// Generate Kyber keypair for vault encryption.
    pub fn generate_encryption_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), DsmError> {
        let kyber_pair = kyber::generate_kyber_keypair()?;
        Ok((kyber_pair.public_key.clone(), kyber_pair.secret_key.clone()))
    }

    /// Store Kyber encryption keys.
    pub fn store_encryption_keys(
        &self,
        identity: &str,
        public_key: Vec<u8>,
        secret_key: Vec<u8>,
    ) -> Result<(), DsmError> {
        let mut ks = self.kyber_key_store.write().map_err(|_| {
            DsmError::internal(
                "Kyber key store lock poisoned",
                None::<std::convert::Infallible>,
            )
        })?;
        ks.insert(identity.to_string(), (public_key, secret_key));
        Ok(())
    }

    /// Retrieve Kyber encryption keys.
    pub async fn get_encryption_keys(
        &self,
        identity: &str,
    ) -> Result<(Vec<u8>, Vec<u8>), DsmError> {
        let ks = self.kyber_key_store.read().map_err(|_| {
            DsmError::internal(
                "Kyber key store lock poisoned",
                None::<std::convert::Infallible>,
            )
        })?;
        ks.get(identity).cloned().ok_or_else(|| {
            DsmError::not_found(
                "Encryption keys",
                Some(format!("No Kyber keys for identity: {identity}")),
            )
        })
    }

    // ------------------------------------------------------------------------
    // Vault lifecycle
    // ------------------------------------------------------------------------

    /// Create a new vault with the given configuration (CEK/KEK handled by manager).
    pub async fn create_vault(
        &self,
        creator_identity: &str,
        config: VaultConfig,
        reference_state: &State,
    ) -> Result<VaultCreationResult, DsmError> {
        let creator_keypair = crate::sdk::signing_authority::derive_current_signing_keypair()?;
        let creator_pk = creator_keypair.public_key().to_vec();
        let creator_sk = creator_keypair.secret_key().to_vec();

        // Determine encryption key (Kyber PK):
        // - If config specifies a recipient key, use it
        // - Otherwise, use creator's Kyber encryption key for self-encryption
        let (creator_kyber_pk, _) = self.get_encryption_keys(creator_identity).await?;
        let encryption_key = match &config.recipient_public_key {
            Some(key) => key.clone(),
            None => creator_kyber_pk.clone(),
        };
        let intended_recipient = Some(encryption_key.clone());

        // Convert high-level condition to concrete mechanism
        let mech = self.convert_condition_to_mechanism(&config.condition, reference_state)?;

        // Create the vault (manager owns CEK/KEK & proof commitments)
        let (vault_id, _op) = self
            .manager
            .create_vault(
                (&creator_pk, &creator_sk),
                mech,
                &config.content,
                &config.content_type,
                intended_recipient,
                &encryption_key,
                reference_state,
                None,
                None,
            )
            .await?; // Produce a shareable post
        let vault_post_data = self
            .manager
            .create_vault_post(&vault_id, &config.description, config.timeout_seconds)
            .await?;
        let vault_post_proto = VaultPostProto::decode(vault_post_data.as_slice()).map_err(|e| {
            DsmError::serialization_error(
                "Failed to decode vault post",
                "VaultPostProto",
                None::<String>,
                Some(e),
            )
        })?;
        let vault_post = vault_post_from_proto(vault_post_proto);

        // Optional asset cataloging
        if !config.metadata.is_empty() {
            let am = self.asset_manager.lock().map_err(|_| {
                DsmError::internal(
                    "Asset manager lock poisoned",
                    None::<std::convert::Infallible>,
                )
            })?;

            let mut asset = DigitalAsset::new(
                format!("vault_{vault_id}"),
                AssetType::EncryptedState,
                config.content.clone(),
            );

            for (k, v) in config.metadata {
                asset = asset.with_metadata(&k, &v);
            }
            am.add_asset(asset)?;
        }

        Ok(VaultCreationResult {
            vault_id,
            creator_public_key: creator_pk.clone(),
            vault_post,
            created_at: dt::tick(),
        })
    }

    /// Create a simple time-locked vault (no longer supported)
    pub async fn create_time_locked_vault(
        &self,
        _creator_identity: &str,
        _content: Vec<u8>,
        _unlock_after_seconds: u64,
        _reference_state: &State,
    ) -> Result<VaultCreationResult, DsmError> {
        Err(DsmError::invalid_operation(
            "time-locked vaults are not supported by the protocol",
        ))
    }

    /// Create a payment-locked vault
    pub async fn create_payment_vault(
        &self,
        creator_identity: &str,
        content: Vec<u8>,
        payment_amount: u64,
        recipient_identity: Option<&str>,
        reference_state: &State,
    ) -> Result<VaultCreationResult, DsmError> {
        let recipient_public_key = if let Some(recipient) = recipient_identity {
            Some(self.get_encryption_keys(recipient).await?.0)
        } else {
            None
        };

        let cfg = VaultConfig {
            content,
            content_type: "application/octet-stream".to_string(),
            description: format!("Payment-locked vault (requires {payment_amount} tokens)"),
            recipient_public_key,
            condition: VaultCondition::MinimumBalance(payment_amount),
            timeout_seconds: None,
            metadata: HashMap::new(),
        };

        self.create_vault(creator_identity, cfg, reference_state)
            .await
    }

    /// Get information about a vault
    pub async fn get_vault_info(&self, vault_id: &str) -> Result<VaultInfo, DsmError> {
        let vault_lock = self.manager.get_vault(vault_id).await?;
        let vault = vault_lock.lock().await;

        let condition_description = match &vault.fulfillment_condition {
            FulfillmentMechanism::Payment {
                amount, token_id, ..
            } => {
                format!("Requires payment of {amount} {token_id}")
            }
            FulfillmentMechanism::MultiSignature {
                threshold,
                public_keys,
            } => {
                format!("Requires {} of {} signatures", threshold, public_keys.len())
            }
            FulfillmentMechanism::CryptoCondition { .. } => {
                "Cryptographic condition required".to_string()
            }
            FulfillmentMechanism::StateReference { .. } => {
                "State reference verification required".to_string()
            }
            FulfillmentMechanism::RandomWalkVerification { statement, .. } => {
                format!("Random walk verification: {statement}")
            }
            FulfillmentMechanism::And(conditions) => {
                format!("All {} conditions must be met", conditions.len())
            }
            FulfillmentMechanism::Or(conditions) => {
                format!("Any of {} conditions must be met", conditions.len())
            }
            FulfillmentMechanism::BitcoinHTLC {
                expected_btc_amount_sats,
                ..
            } => {
                format!("Bitcoin HTLC vault ({expected_btc_amount_sats} sats)")
            }
        };

        Ok(VaultInfo {
            id: vault.id.clone(),
            creator_public_key: vault.creator_public_key.clone(),
            state: vault.state.clone(),
            content_type: vault.content_type.clone(),
            created_at_state: vault.created_at_state,
            intended_recipient: vault.intended_recipient.clone(),
            condition_description,
        })
    }

    /// List all vaults managed by this SDK instance
    pub async fn list_vaults(&self) -> Result<Vec<String>, DsmError> {
        self.manager.list_vaults().await
    }

    /// Get vaults by their current state
    pub async fn get_vaults_by_state(&self, state: VaultState) -> Result<Vec<String>, DsmError> {
        self.manager.get_vaults_by_status(state).await
    }

    // ------------------------------------------------------------------------
    // Unlock & claim (proofs mandatory; CEK/KEK stay in manager)
    // ------------------------------------------------------------------------

    /// Attempt to unlock a time-based vault (no longer supported)
    pub async fn unlock_time_vault(
        &self,
        _vault_id: &str,
        _options: UnlockOptions,
        _reference_state: &State,
    ) -> Result<bool, DsmError> {
        Err(DsmError::invalid_operation(
            "time-based vaults are not supported by the protocol",
        ))
    }

    /// Attempt to unlock a payment-locked vault
    pub async fn unlock_payment_vault(
        &self,
        vault_id: &str,
        payment_proof: Vec<u8>,
        options: UnlockOptions,
        reference_state: &State,
    ) -> Result<bool, DsmError> {
        let state_hash = reference_state.hash()?;
        let stitched_receipt_sigma = options.stitched_receipt_sigma.or_else(|| {
            let payload = encode_protocol_transition_payload(
                b"dlv.payment.unlock",
                &[
                    vault_id.as_bytes(),
                    &payment_proof,
                    &options.requester_public_key,
                    &state_hash,
                ],
            );
            Some(compute_protocol_transition_commitment(&payload))
        });

        let proof = FulfillmentProof::PaymentProof {
            state_transition: payment_proof,
            merkle_proof: self.generate_merkle_proof(reference_state)?,
            stitched_receipt_sigma,
        };

        let signing_public_key = options
            .signing_public_key
            .unwrap_or(crate::sdk::signing_authority::current_public_key()?);
        let (unlocked, _op) = self
            .manager
            .try_unlock_vault(
                vault_id,
                proof,
                &options.requester_public_key,
                &signing_public_key,
                reference_state,
            )
            .await?;
        Ok(unlocked)
    }

    /// Claim the content of an unlocked vault
    pub async fn claim_vault(
        &self,
        vault_id: &str,
        claimant_identity: &str,
        reference_state: &State,
    ) -> Result<Vec<u8>, DsmError> {
        let claimant_pk = crate::sdk::signing_authority::current_public_key()?;
        let (_, kyber_sk) = self.get_encryption_keys(claimant_identity).await?;
        let (content, _op) = self
            .manager
            .claim_vault_content(vault_id, &kyber_sk, &claimant_pk, reference_state)
            .await?;
        Ok(content)
    }

    /// Invalidate a vault (only by creator)
    pub async fn invalidate_vault(
        &self,
        vault_id: &str,
        _creator_identity: &str,
        reason: &str,
        reference_state: &State,
    ) -> Result<(), DsmError> {
        let invalidation_message = [
            vault_id.as_bytes(),
            reason.as_bytes(),
            &reference_state.hash[..],
        ]
        .concat();
        let creator_signature = dsm::crypto::sphincs::sphincs_sign(
            &crate::sdk::signing_authority::current_secret_key()?,
            &invalidation_message,
        )
        .map_err(|e| DsmError::crypto("sphincs_sign", Some(e)))?;
        let _op = self
            .manager
            .invalidate_vault(vault_id, reason, &creator_signature, reference_state)
            .await?;
        Ok(())
    }

    /// Load a vault from a vault post
    pub async fn load_vault_from_post(&self, post: &VaultPost) -> Result<String, DsmError> {
        let vault = LimboVault::from_vault_post(post)?;
        let vault_id = vault.id.clone();

        self.manager
            .add_vault(vault)
            .await
            .map_err(|e| DsmError::internal(format!("Failed to add vault: {e}"), Some(e)))?;

        Ok(vault_id)
    }

    /// Export a vault as a vault post
    pub async fn export_vault(&self, vault_id: &str, purpose: &str) -> Result<VaultPost, DsmError> {
        let data = self
            .manager
            .create_vault_post(vault_id, purpose, None)
            .await?;
        let vault_post_proto = VaultPostProto::decode(data.as_slice()).map_err(|e| {
            DsmError::serialization_error(
                "Failed to decode vault post",
                "VaultPostProto",
                None::<String>,
                Some(e),
            )
        })?;
        Ok(vault_post_from_proto(vault_post_proto))
    }

    /// Verify the integrity of a vault
    pub async fn verify_vault(&self, vault_id: &str) -> Result<bool, DsmError> {
        let v = self.manager.get_vault(vault_id).await?;
        let g = v.lock().await;
        g.verify()
    }

    /// Create a Kyber key asset for vault encryption (asset cataloging)
    pub fn create_encryption_asset(&self, asset_id: &str) -> Result<String, DsmError> {
        let kp = KyberKeyPair::generate()?;
        let am = self.asset_manager.lock().map_err(|_| {
            DsmError::internal(
                "Asset manager lock poisoned",
                None::<std::convert::Infallible>,
            )
        })?;
        am.create_key_asset(asset_id, &kp)
    }

    /// Get statistics about vaults
    pub async fn get_vault_statistics(&self) -> Result<VaultStatistics, DsmError> {
        let ids = self.list_vaults().await?;
        let mut stats = VaultStatistics {
            total_vaults: ids.len(),
            ..Default::default()
        };

        for id in ids {
            if let Ok(info) = self.get_vault_info(&id).await {
                match info.state {
                    VaultState::Limbo => stats.limbo_vaults += 1,
                    VaultState::Active { .. } => stats.unlocked_vaults += 1,
                    VaultState::Unlocked { .. } => stats.unlocked_vaults += 1,
                    VaultState::Claimed { .. } => stats.claimed_vaults += 1,
                    VaultState::Invalidated { .. } => stats.invalidated_vaults += 1,
                }
            }
        }
        Ok(stats)
    }

    // ------------------------------------------------------------------------
    // Helpers (deterministic, no secrets leak)
    // ------------------------------------------------------------------------

    /// Convert high-level VaultCondition to concrete FulfillmentMechanism
    fn convert_condition_to_mechanism(
        &self,
        condition: &VaultCondition,
        reference_state: &State,
    ) -> Result<FulfillmentMechanism, DsmError> {
        match condition {
            VaultCondition::MinimumBalance(amount) => Ok(FulfillmentMechanism::Payment {
                amount: *amount,
                token_id: "default".to_string(),
                recipient: "default".to_string(),
                verification_state: reference_state.hash.to_vec(),
            }),
            VaultCondition::VaultType(vt) => {
                if vt == "multisig" {
                    let (pk, _) = sphincs::generate_sphincs_keypair()?;
                    Ok(FulfillmentMechanism::MultiSignature {
                        public_keys: vec![pk],
                        threshold: 3,
                    })
                } else {
                    Ok(FulfillmentMechanism::CryptoCondition {
                        condition_hash: blake3::domain_hash("DSM/dlv-condition", vt.as_bytes())
                            .as_bytes()
                            .to_vec(),
                        public_params: vt.as_bytes().to_vec(),
                    })
                }
            }
            VaultCondition::Hash(hs) => Ok(FulfillmentMechanism::CryptoCondition {
                condition_hash: blake3::domain_hash("DSM/dlv-condition", hs.as_slice())
                    .as_bytes()
                    .to_vec(),
                public_params: hs.clone(),
            }),
            VaultCondition::SmartPolicy(policy_bytes) => {
                let policy = SmartPolicy::decode(policy_bytes.as_slice()).map_err(|e| {
                    DsmError::serialization_error(
                        "Failed to decode SmartPolicy protobuf",
                        "SmartPolicy",
                        None::<String>,
                        Some(e),
                    )
                })?;
                let condition_hash = policy_hash_b3(&policy).to_vec();
                Ok(FulfillmentMechanism::CryptoCondition {
                    condition_hash,
                    public_params: policy_bytes.clone(),
                })
            }
        }
    }

    /// Deterministic state proof (binds to reference state; manager validates)
    fn generate_state_proof(&self, reference_state: &State) -> Result<Vec<u8>, DsmError> {
        let sn = reference_state.state_number.to_le_bytes();
        let proof = [&reference_state.hash[..], &sn, &reference_state.entropy[..]].concat();
        Ok(blake3::domain_hash("DSM/dlv-proof", &proof)
            .as_bytes()
            .to_vec())
    }

    /// Simplified Merkle proof placeholder (binds to reference state)
    fn generate_merkle_proof(&self, reference_state: &State) -> Result<Vec<u8>, DsmError> {
        let merkle_data = [&reference_state.hash[..], b"payment_verification"].concat();
        Ok(blake3::domain_hash("DSM/dlv-merkle", &merkle_data)
            .as_bytes()
            .to_vec())
    }
}

/// Statistics about vaults managed by the SDK
#[derive(Debug, Clone, Default)]
pub struct VaultStatistics {
    /// Total number of vaults
    pub total_vaults: usize,
    /// Number of vaults in limbo state
    pub limbo_vaults: usize,
    /// Number of unlocked vaults
    pub unlocked_vaults: usize,
    /// Number of claimed vaults
    pub claimed_vaults: usize,
    /// Number of invalidated vaults
    pub invalidated_vaults: usize,
}

impl Default for DlvSdk {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use dsm::types::state_types::DeviceInfo;
    use dsm::types::proto::{SmartPolicy, SmartClause, SmartBalance};

    const TEST_DEVICE_ID: [u8; 32] = [0xD2; 32];
    const TEST_GENESIS_HASH: [u8; 32] = [0xD4; 32];
    const TEST_BINDING_KEY: [u8; 32] = [0xD5; 32];

    fn install_test_identity() -> Vec<u8> {
        std::env::set_var("DSM_SDK_TEST_MODE", "1");
        crate::sdk::app_state::AppState::reset_memory_for_testing();
        crate::sdk::app_state::AppState::prime_memory_for_testing();
        let (public_key, _) = crate::sdk::signing_authority::derive_signing_keys_for_testing(
            &TEST_DEVICE_ID,
            &TEST_GENESIS_HASH,
            &TEST_BINDING_KEY,
        )
        .expect("canonical test signing key derivation failed");
        crate::sdk::app_state::AppState::set_identity_info(
            TEST_DEVICE_ID.to_vec(),
            public_key.clone(),
            TEST_GENESIS_HASH.to_vec(),
            vec![0u8; 32],
        );
        crate::set_cdbrw_binding_key_for_testing(TEST_BINDING_KEY.to_vec());
        public_key
    }

    fn create_test_state() -> State {
        let device_info = DeviceInfo::from_hashed_label("test_device", vec![1, 2, 3, 4]);
        let mut entropy = [0u8; 32];
        entropy[0..4].copy_from_slice(&[1, 2, 3, 4]);
        State::new_genesis(entropy, device_info)
    }

    #[tokio::test]
    async fn test_sdk_vault_creation() -> Result<(), DsmError> {
        let sdk = DlvSdk::new();
        install_test_identity();

        // Generate and store Kyber encryption keys (for vault encryption)
        let (kyber_pk, kyber_sk) = sdk.generate_encryption_keypair()?;
        sdk.store_encryption_keys("test_creator", kyber_pk, kyber_sk)?;

        let state = create_test_state();
        let content = b"Test vault content".to_vec();

        let result = sdk
            .create_payment_vault("test_creator", content, 100, None, &state)
            .await?;

        assert!(!result.vault_id.is_empty());
        // SPHINCS+ pk length depends on chosen parameter set; use > 32 as sanity check
        assert!(result.creator_public_key.len() > 32);

        Ok(())
    }

    #[tokio::test]
    async fn test_vault_info_retrieval() -> Result<(), DsmError> {
        let sdk = DlvSdk::new();
        install_test_identity();

        // Generate and store Kyber encryption keys (for vault encryption)
        let (kyber_pk, kyber_sk) = sdk.generate_encryption_keypair()?;
        sdk.store_encryption_keys("test_creator", kyber_pk, kyber_sk)?;

        let state = create_test_state();
        let content = b"Test vault content".to_vec();

        let result = sdk
            .create_payment_vault("test_creator", content, 100, None, &state)
            .await?;

        let info = sdk.get_vault_info(&result.vault_id).await?;
        assert_eq!(info.id, result.vault_id);
        assert!(matches!(info.state, VaultState::Limbo));
        assert!(info.condition_description.contains("Requires payment"));

        Ok(())
    }

    #[tokio::test]
    async fn test_vault_statistics() -> Result<(), DsmError> {
        let sdk = DlvSdk::new();
        install_test_identity();

        // Generate and store Kyber encryption keys (for vault encryption)
        let (kyber_pk, kyber_sk) = sdk.generate_encryption_keypair()?;
        sdk.store_encryption_keys("test_creator", kyber_pk, kyber_sk)?;

        let state = create_test_state();

        // Reduce vault creation in debug builds to avoid slow SPHINCS+ operations
        let num_vaults = if cfg!(debug_assertions) { 1 } else { 3 };
        for i in 0..num_vaults {
            let content = format!("Test vault content {i}").into_bytes();
            sdk.create_payment_vault("test_creator", content, 100, None, &state)
                .await?;
        }

        let stats = sdk.get_vault_statistics().await?;
        assert_eq!(stats.total_vaults, num_vaults);
        assert_eq!(stats.limbo_vaults, num_vaults);
        assert_eq!(stats.unlocked_vaults, 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_dlv_with_smart_commitments() -> Result<(), DsmError> {
        let sdk = DlvSdk::new();
        let creator_pk = install_test_identity();

        // Generate and store Kyber encryption keys (for vault encryption)
        let (kyber_pk, kyber_sk) = sdk.generate_encryption_keypair()?;
        sdk.store_encryption_keys("smart_commitment_creator", kyber_pk, kyber_sk)?;

        let state = create_test_state();
        let content = b"Smart commitment vault content".to_vec(); // Create a vault with SmartPolicy condition
                                                                  // This demonstrates a conditional vault that requires specific criteria
        let smart_policy = SmartPolicy {
            version: 1,
            logic: 1, // SMART_AND
            clauses: vec![SmartClause {
                clause: Some(dsm::types::proto::smart_clause::Clause::Balance(
                    SmartBalance {
                        minimum_balance: 1000,
                        token_id: "".to_string(),
                    },
                )),
            }],
        };
        let policy_bytes = smart_policy.encode_to_vec();

        let cfg = VaultConfig {
            content: content.clone(),
            content_type: "application/json".to_string(),
            description: "Smart commitment vault with conditional logic".to_string(),
            recipient_public_key: None,
            condition: VaultCondition::SmartPolicy(policy_bytes),
            timeout_seconds: Some(86400), // 24 hours
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("smart_commitment_version".to_string(), "1.0".to_string());
                meta.insert("complexity".to_string(), "high".to_string());
                meta
            },
        };

        // Create the vault with smart commitments
        let result = sdk
            .create_vault("smart_commitment_creator", cfg, &state)
            .await?;

        // Verify vault was created successfully
        assert!(!result.vault_id.is_empty());
        assert_eq!(result.creator_public_key, creator_pk);

        // Get vault information
        let info = sdk.get_vault_info(&result.vault_id).await?;
        assert_eq!(info.id, result.vault_id);
        assert!(matches!(info.state, VaultState::Limbo));
        assert!(info
            .condition_description
            .contains("Cryptographic condition"));

        // Verify vault integrity
        let is_valid = sdk.verify_vault(&result.vault_id).await?;
        assert!(is_valid);

        // Export vault as post for sharing
        let vault_post = sdk
            .export_vault(&result.vault_id, "Smart commitment demonstration")
            .await?;
        assert!(!vault_post.vault_id.is_empty());

        // Load vault from post (simulating receiving it)
        let loaded_vault_id = sdk.load_vault_from_post(&vault_post).await?;
        assert_eq!(loaded_vault_id, result.vault_id);

        // Verify statistics include our new vault
        let stats = sdk.get_vault_statistics().await?;
        assert!(stats.total_vaults >= 1);
        assert!(stats.limbo_vaults >= 1);

        println!("Successfully created DLV with smart commitments:");
        println!("  Vault ID: {}", result.vault_id);
        println!("  Creator: smart_commitment_creator");
        println!("  Content type: {}", info.content_type);
        println!("  Condition: {}", info.condition_description);

        Ok(())
    }
}
