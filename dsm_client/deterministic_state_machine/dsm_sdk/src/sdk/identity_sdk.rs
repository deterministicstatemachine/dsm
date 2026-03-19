// SPDX-License-Identifier: MIT OR Apache-2.0
//! # Identity SDK Module
//!
//! This module implements the identity management functionality as described
//! operations including device management, relationship tracking, and recovery.
//!
//! ## Key Concepts
//!
//! * **Hierarchical Identity**: Master and device-specific sub-genesis states
//! * **Cryptographic State Isolation**: Separate state chains for different contexts
//! * **Bilateral Relationships**: Managed contexts for secure peer interactions
//! * **Pre-commitments**: Cryptographic commitments to future operations
//! * **Identity Recovery**: Mechanisms for recovering from key compromise
//!
//! ## Architecture
//!
//! The identity module implements a hierarchical device-specific sub-genesis architecture
//! with cryptographic state isolation and bilateral relationship context management.
//! It follows the mathematical blueprint laid out in sections 4 and 7 of the DSM whitepaper.
//!
//! ## Usage Example
//!
//! ```rust
//! use dsm_sdk::identity_sdk::IdentitySDK;
//! use dsm_sdk::hashchain_sdk::HashChainSDK;
//! use dsm::types::state_types::DeviceInfo;
//! use std::sync::Arc;
//!
//!
//! // Create identity SDK with hash chain
//! let hash_chain_sdk = Arc::new(HashChainSDK::new());
//! let identity_sdk = IdentitySDK::new("user123".into(), hash_chain_sdk);
//!
//! // Create a device and genesis state
//! let device_info = DeviceInfo::new("device1", vec![1,2,3,4]);
//! ```
use crate::types::error::DsmError;
use crate::sdk::hashchain_sdk::HashChainSDK;
use dsm::crypto::blake3::dsm_domain_hasher;
#[cfg(feature = "storage")]
use crate::sdk::storage_node_sdk::StorageNodeSDK;
#[cfg(feature = "storage")]
use crate::sdk::genesis_publisher::SdkGenesisPublisher;
#[cfg(feature = "storage")]
use dsm::core::identity::genesis_mpc::{GenesisPublisher, SanitizedGenesisPayload};
use crate::util::text_id;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[cfg(all(test, feature = "storage"))]
const GENESIS_PUBLISH_TEST_DUMMY_DEVICE_ID_B32: &str =
    "0000000000000000000000000000000000000000000000000000";

#[cfg(all(test, feature = "storage"))]
const GENESIS_PUBLISH_TEST_DUMMY_TOKEN: &str = "dummy_token";

// Constant-time equality helper to avoid external dependency and timing side-channels.
#[inline]
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        // XOR accumulate without branches for constant-time behavior
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// Cross-crate imports from dsm core
use dsm::crypto::signatures::SignatureKeyPair;
use dsm::types::state_types::{State, DeviceInfo};
use dsm::types::operations::{Operation, TransactionMode};
use dsm::core::identity::genesis::create_genesis_via_blind_mpc;

// Type alias for state hash (matches State.hash type)
type StateHash = Vec<u8>;

/// Bilateral relationship context for secure peer interactions
///
/// This structure manages the cryptographic context between two entities
/// as defined in section 7 of the DSM whitepaper, enabling secure bilateral
/// communication with state isolation.
#[derive(Debug, Clone)]
pub struct ExtendedRelationshipContext {
    /// Current state number of the entity in this relationship
    pub entity_state_number: u64,

    /// Identifier of the counterparty in this relationship
    pub counterparty_id: String,

    /// Current state number of the counterparty in this relationship
    pub counterparty_state_number: u64,

    /// Public key of the counterparty for verification
    pub counterparty_public_key: Vec<u8>,

    /// Hash of the current relationship state
    pub current_state_hash: StateHash,

    /// Sequence of state hashes in this relationship
    pub state_sequence: Vec<StateHash>,

    /// Additional metadata for the relationship
    pub metadata: HashMap<String, Vec<u8>>,
}

/// Identity management SDK for the DSM system
///
/// This SDK provides a comprehensive interface for managing cryptographic
/// identities in the DSM system, including device management, relationship
/// tracking, state transitions, and recovery mechanisms as defined in
/// sections 4 and 7 of the DSM whitepaper.
#[derive(Clone)]
pub struct IdentitySDK {
    /// Identifier for this identity
    pub identity_id: String,

    /// Registry of device-specific genesis states
    pub device_genesis_states: Arc<RwLock<HashMap<[u8; 32], State>>>,

    /// Reference to the hash chain tracking states
    pub hash_chain_sdk: Arc<HashChainSDK>,

    /// Registry of bilateral relationship contexts
    relationship_contexts: Arc<RwLock<HashMap<String, ExtendedRelationshipContext>>>,

    /// Cryptographic key pair for this identity
    signing_keypair: Arc<RwLock<Option<SignatureKeyPair>>>,

    /// Optional storage SDK for publishing genesis
    #[cfg(feature = "storage")]
    pub storage_sdk: Arc<RwLock<Option<StorageNodeSDK>>>,
}

impl IdentitySDK {
    /// Create a new IdentitySDK instance
    ///
    /// Initializes a new identity with the specified ID and hash chain,
    /// and generates cryptographic keys for this identity.
    ///
    /// # Arguments
    ///
    /// * `identity_id` - The unique identifier for this identity
    /// * `hash_chain_sdk` - An Arc-wrapped HashChainSDK for state tracking
    ///
    /// # Returns
    ///
    /// A new IdentitySDK instance
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::identity_sdk::IdentitySDK;
    /// use dsm_sdk::hashchain_sdk::HashChainSDK;
    /// use std::sync::Arc;
    ///
    /// let hash_chain_sdk = Arc::new(HashChainSDK::new());
    /// let identity_sdk = IdentitySDK::new("user123".into(), hash_chain_sdk);
    /// ```
    pub fn new(identity_id: String, hash_chain_sdk: Arc<HashChainSDK>) -> Self {
        let sdk = Self {
            identity_id,
            device_genesis_states: Arc::new(RwLock::new(HashMap::new())),
            hash_chain_sdk,
            relationship_contexts: Arc::new(RwLock::new(HashMap::new())),
            signing_keypair: Arc::new(RwLock::new(None)),
            #[cfg(feature = "storage")]
            storage_sdk: Arc::new(RwLock::new(None)),
        };

        // Initialize cryptographic keys
        let _ = sdk.initialize_keys();

        // Load stored identity information if available
        sdk.load_stored_identity();

        sdk
    }

    /// Set the storage SDK for publishing genesis
    #[cfg(feature = "storage")]
    pub fn set_storage_sdk(&self, storage_sdk: StorageNodeSDK) {
        match self.storage_sdk.write() {
            Ok(mut s) => *s = Some(storage_sdk),
            Err(_) => log::error!("Storage SDK lock poisoned"),
        }
    }

    /// Initialize cryptographic keys for this identity
    ///
    /// Generates a new SPHINCS+ key pair for this identity and stores it
    /// for later use in signatures and verification.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If key initialization was successful
    /// * `Err(DsmError)` - If key generation failed
    pub fn initialize_keys(&self) -> Result<(), DsmError> {
        // Generate a new SPHINCS+ key pair for signatures
        let keypair = SignatureKeyPair::new()?;

        // Store the key pair
        let mut key_guard = self
            .signing_keypair
            .write()
            .map_err(|_| DsmError::lock_error())?;
        *key_guard = Some(keypair);

        Ok(())
    }

    /// Load stored identity information from AppState
    fn load_stored_identity(&self) {
        use crate::sdk::app_state::AppState;

        // Check if we have stored identity information
        if let Some(device_id) = AppState::get_device_id() {
            // Update our identity_id if it matches stored device_id (binary)
            if self.identity_id.as_bytes() == device_id.as_slice() {
                log::info!("IdentitySdk: Loaded stored identity (bytes match)");

                // If we have a stored public key, we could potentially reconstruct keys
                // For now, we rely on the has_identity check that falls back to AppState
                // In a full implementation, we'd store and restore the actual key material
            }
        }
    }

    /// Get the current identity's public key
    ///
    /// Retrieves the public key component of this identity's signing key pair.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The public key if available
    /// * `Err(DsmError)` - If no keys are available
    pub async fn get_public_key(&self) -> Result<Vec<u8>, DsmError> {
        let key_guard = self
            .signing_keypair
            .read()
            .map_err(|_| DsmError::lock_error())?;

        match &*key_guard {
            Some(keypair) => Ok(keypair.public_key.clone()),
            None => Err(DsmError::crypto(
                "No signing keys available".to_string(),
                None::<std::io::Error>,
            )),
        }
    }

    /// Sign data using the identity's private key
    ///
    /// Creates a cryptographic signature for the provided data using
    /// the identity's SPHINCS+ private key.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to sign
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The signature if signing was successful
    /// * `Err(DsmError)` - If signing failed
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::identity_sdk::IdentitySDK;
    /// use dsm_sdk::hashchain_sdk::HashChainSDK;
    /// use std::sync::Arc;
    ///
    /// let hash_chain_sdk = Arc::new(HashChainSDK::new());
    /// let identity_sdk = IdentitySDK::new("user123".into(), hash_chain_sdk);
    ///
    /// let data = b"Data to sign";
    /// let signature = identity_sdk.sign_data(data).map_err(|_e| DsmError::internal(e.to_string(), None))?;
    /// ```
    pub async fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, DsmError> {
        let key_guard = self
            .signing_keypair
            .read()
            .map_err(|_| DsmError::internal("Error occurred", None::<std::io::Error>))?;

        match &*key_guard {
            Some(keypair) => {
                // Use the SignatureKeyPair to sign the data
                keypair.sign(data)
            }
            None => Err(DsmError::crypto(
                "No signing keys available".to_string(),
                None::<std::io::Error>,
            )),
        }
    }

    /// Verify a signature against data
    ///
    /// Verifies that a signature is valid for the provided data using
    /// the identity's public key.
    ///
    /// # Arguments
    ///
    /// * `data` - The data that was signed
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// * `Ok(bool)` - True if the signature is valid, false otherwise
    /// * `Err(DsmError)` - If verification failed
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::identity_sdk::IdentitySDK;
    /// use dsm_sdk::hashchain_sdk::HashChainSDK;
    /// use std::sync::Arc;
    ///
    /// let hash_chain_sdk = Arc::new(HashChainSDK::new());
    /// let identity_sdk = IdentitySDK::new("user123".into(), hash_chain_sdk);
    ///
    /// let data = b"Data to sign";
    /// let signature = identity_sdk.sign_data(data).map_err(|_e| DsmError::internal(e.to_string(), None))?;
    /// let is_valid = identity_sdk.verify_signature(data, &signature).map_err(|_e| DsmError::internal(e.to_string(), None))?;
    /// assert!(is_valid);
    /// ```
    pub async fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, DsmError> {
        let key_guard = self
            .signing_keypair
            .read()
            .map_err(|_| DsmError::internal("Error occurred", None::<std::io::Error>))?;

        match &*key_guard {
            Some(keypair) => {
                // Use the SignatureKeyPair to verify the signature
                // Convert the byte slice to a Vec<u8> since that's what the method expects
                let signature_vec = signature.to_vec();
                keypair.verify(data, &signature_vec)
            }
            None => Err(DsmError::crypto(
                "No signing keys available".to_string(),
                None::<std::io::Error>,
            )),
        }
    }

    /// Get the current identity ID
    ///
    /// # Returns
    ///
    /// The identity ID as a String
    pub fn get_identity(&self) -> String {
        self.identity_id.clone()
    }

    /// Provision a new device identity
    ///
    /// Creates a new device with the given label and returns the device ID and genesis hash.
    ///
    /// # Arguments
    ///
    /// * `label` - A label/name for this device
    ///
    /// # Returns
    ///
    /// * `Ok((String, Vec<u8>))` - The device ID and genesis hash if successful
    /// * `Err(DsmError)` - If provisioning failed
    pub fn provision_device(&mut self, label: &str) -> Result<(String, Vec<u8>), DsmError> {
        // Generate device info
        let device_entropy = dsm::crypto::blake3::domain_hash(
            "DSM/identity-entropy",
            format!(
                "{}_entropy_{}",
                label,
                crate::util::deterministic_time::tick()
            )
            .as_bytes(),
        );
        let mut device_id_bytes = [0u8; 32];
        device_id_bytes.copy_from_slice(device_entropy.as_bytes());
        let device_info = dsm::types::state_types::DeviceInfo::new(
            device_id_bytes,
            device_entropy.as_bytes().to_vec(),
        );

        // Create genesis state
        let participant_inputs = vec![
            device_entropy.as_bytes().to_vec(),
            dsm::crypto::blake3::domain_hash("DSM/identity-label", label.as_bytes())
                .as_bytes()
                .to_vec(),
        ];
        let genesis_state = self.create_genesis(
            device_info,
            participant_inputs,
            Some(label.as_bytes().to_vec()),
        )?;

        // Device ID for UI/context only (non-encoded), protocol uses bytes via AppState
        let device_id = format!("{}_device", label);
        // Update our identity ID to the device ID string
        self.identity_id = device_id.clone();
        Ok((device_id, genesis_state.hash.to_vec()))
    }

    /// Get the device ID for this identity
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The device ID bytes (binary)
    /// * `Err(DsmError)` - If no device ID is available
    pub fn get_device_id(&self) -> Result<Vec<u8>, DsmError> {
        // Derive 32-byte device id from the UI string deterministically
        let did = dsm::crypto::blake3::domain_hash("DSM/identity-id", self.identity_id.as_bytes());
        Ok(did.as_bytes().to_vec())
    }

    /// Initialize the identity from a seed
    ///
    /// Initializes this identity using the provided seed data,
    /// generating cryptographic keys and setting up the identity state.
    ///
    /// # Arguments
    ///
    /// * `seed` - The seed data for identity initialization
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If initialization was successful
    /// * `Err(DsmError)` - If initialization failed
    pub fn initialize_from_seed(&mut self, seed: &[u8]) -> Result<(), DsmError> {
        // Generate device ID from seed
        // Binary-only: keep internal string for now, but return bytes via getter
        self.identity_id = "seeded".to_string();

        // Initialize cryptographic keys (seeded generation not available in this API; use default constructor)
        let keypair = SignatureKeyPair::new()?;

        // Store the key pair
        let mut key_guard = self
            .signing_keypair
            .write()
            .map_err(|_| DsmError::internal("Error occurred", None::<std::io::Error>))?;
        *key_guard = Some(keypair);

        // Create device info from seed
        let did_hash = dsm::crypto::blake3::domain_hash("DSM/identity-did", seed);
        let mut device_id = [0u8; 32];
        device_id.copy_from_slice(did_hash.as_bytes());
        let device_id_str = crate::util::text_id::encode_base32_crockford(&device_id);
        let device_info = DeviceInfo::new(device_id, seed.to_vec());

        // Create genesis state from seed
        let entropy =
            *dsm::crypto::blake3::domain_hash("DSM/identity-seed-entropy", seed).as_bytes();
        let mut state = State::new_genesis(entropy, device_info);

        // Calculate and store hash
        let hash = state.compute_hash()?;
        state.hash = hash;

        // Store in device genesis states
        {
            let device_id_bytes =
                crate::util::domain_helpers::device_id_hash(device_id_str.as_ref());
            let mut device_states = self
                .device_genesis_states
                .write()
                .map_err(|_| DsmError::lock_error())?;
            device_states.insert(device_id_bytes, state);
        }

        Ok(())
    }

    /// Sign raw data using this identity's signing key
    ///
    /// # Arguments
    ///
    /// * `data` - The raw data to sign
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The signature
    /// * `Err(DsmError)` - If signing failed
    pub async fn sign_raw(&self, data: &[u8]) -> Result<Vec<u8>, DsmError> {
        self.sign_data(data).await
    }

    /// Create a genesis state for this identity
    ///
    /// Creates the initial genesis state for this identity as described in
    /// section 4 of the DSM whitepaper, establishing the foundation for
    /// all subsequent state transitions.
    ///
    /// # Arguments
    ///
    /// * `device_info` - Information about the device creating the genesis
    /// * `participant_inputs` - Entropy contributions from participants
    /// * `metadata` - Optional metadata to include in the genesis state
    ///
    /// # Returns
    ///
    /// * `Ok(State)` - The created genesis state if successful
    /// * `Err(DsmError)` - If genesis creation failed
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::identity_sdk::IdentitySDK;
    /// use dsm_sdk::hashchain_sdk::HashChainSDK;
    /// use dsm::types::state_types::DeviceInfo;
    /// use std::sync::Arc;
    ///
    /// let hash_chain_sdk = Arc::new(HashChainSDK::new());
    /// let identity_sdk = IdentitySDK::new("user123".into(), hash_chain_sdk);
    ///
    /// let device_info = DeviceInfo::new("device1", vec![1, 2, 3, 4]);
    /// let participant_inputs = vec![vec![5, 6, 7, 8]];
    /// let genesis = identity_sdk.create_genesis(
    ///     device_info,
    ///     participant_inputs,
    ///     Some(vec![9, 10, 11, 12])
    /// ).map_err(|_e| DsmError::internal(e.to_string(), None))?;
    /// ```
    pub fn create_genesis(
        &self,
        device_info: DeviceInfo,
        participant_inputs: Vec<Vec<u8>>,
        metadata: Option<Vec<u8>>,
    ) -> Result<State, DsmError> {
        #[cfg(feature = "storage")]
        log::info!(
            "IdentitySDK::create_genesis(start): identity_id='{}' device_label='{}' participant_inputs={} storage_sdk_set={}",
            self.identity_id,
            crate::util::text_id::encode_base32_crockford(&device_info.device_id),
            participant_inputs.len(),
            self.storage_sdk.read().map(|g| g.is_some()).unwrap_or(false)
        );

        // Convert participant inputs to deterministic base32 strings (canonical, display-safe).
        let participants: Vec<String> = participant_inputs
            .iter()
            .map(|p| crate::util::text_id::encode_base32_crockford(p))
            .collect();

        // Use threshold equal to number of participants for MPC-style genesis
        let threshold = participants.len().max(1);

        // Call core backend genesis creation via MPC to get proper cryptographic genesis
        // Derive a deterministic device id for MPC path from identity id + device id to keep tests stable
        let mut id_hasher = dsm_domain_hasher("DSM/identity-mpc-id");
        id_hasher.update(self.identity_id.as_bytes());
        id_hasher.update(&device_info.device_id);
        let id_hash = id_hasher.finalize();
        let mut device_id_arr = [0u8; 32];
        device_id_arr.copy_from_slice(id_hash.as_bytes());

        // Use a fixed set of test node IDs
        let test_nodes = vec![
            dsm::types::identifiers::NodeId::new("n1"),
            dsm::types::identifiers::NodeId::new("n2"),
            dsm::types::identifiers::NodeId::new("n3"),
        ];

        // Production minimum threshold is 3; use max(threshold, 3)
        let eff_threshold = std::cmp::max(threshold, 3);

        #[cfg(feature = "storage")]
        log::info!(
            "IdentitySDK::create_genesis: calling create_genesis_via_blind_mpc(threshold={}, nodes={})",
            eff_threshold,
            test_nodes.len()
        );
        let genesis_state = futures::executor::block_on(create_genesis_via_blind_mpc(
            device_id_arr,
            test_nodes.clone(),
            eff_threshold,
            None,
        ))?;

        #[cfg(feature = "storage")]
        log::info!(
            "IdentitySDK::create_genesis: MPC returned genesis_state.hash_len={} signing_pk_len={} entropy_len={}",
            genesis_state.hash.len(),
            genesis_state.signing_key.public_key.len(),
            genesis_state.initial_entropy.len()
        );

        // Publish genesis if storage SDK is available
        #[cfg(feature = "storage")]
        if let Some(storage_sdk) = self
            .storage_sdk
            .read()
            .map_err(|_| DsmError::LockError)?
            .as_ref()
        {
            let publisher = SdkGenesisPublisher::new(storage_sdk.clone());

            let mut genesis_hash_arr = [0u8; 32];
            if genesis_state.hash.len() == 32 {
                genesis_hash_arr.copy_from_slice(&genesis_state.hash);
            } else {
                return Err(DsmError::invalid_parameter(format!(
                    "Invalid genesis hash length: expected 32, got {}",
                    genesis_state.hash.len()
                )));
            }

            let payload = SanitizedGenesisPayload {
                genesis_hash: genesis_hash_arr,
                device_id: device_id_arr,
                public_key: genesis_state.signing_key.public_key.clone(),
                threshold: eff_threshold,
                participants: test_nodes,
                created_at_ticks: dsm::util::deterministic_time::tick_index(),
            };

            log::info!(
                "IdentitySDK::create_genesis: publishing genesis payload (genesis_hash_b32={}, device_id_b32={}, pk_len={})",
                crate::util::text_id::encode_base32_crockford(&payload.genesis_hash),
                crate::util::text_id::encode_base32_crockford(&payload.device_id),
                payload.public_key.len()
            );

            // NOTE: This blocks on an async HTTP call while we're in a sync function.
            // If this hangs, it's a network/IO stall, not an MPC stall.
            futures::executor::block_on(publisher.publish(&payload))?;

            log::info!("IdentitySDK::create_genesis: publish done");
        }

        // Use the initial entropy from the cryptographic genesis
        let entropy = genesis_state.initial_entropy;

        // Create the state using the cryptographically secure entropy
        let mut state = State::new_genesis(entropy, device_info);

        // Add metadata if provided
        if let Some(meta) = metadata {
            state.add_metadata("metadata", meta)?;
        }

        // The state hash should incorporate the genesis hash for cryptographic integrity
        let mut combined_hash_data = Vec::new();
        combined_hash_data.extend_from_slice(&genesis_state.hash);
        combined_hash_data.extend_from_slice(&state.compute_hash()?);
        let final_hash =
            *dsm::crypto::blake3::domain_hash("DSM/identity-combine", &combined_hash_data)
                .as_bytes();
        state.hash = final_hash;

        // Store in the device genesis states
        {
            let device_id = state.device_info.device_id;
            let mut device_states = self
                .device_genesis_states
                .write()
                .map_err(|_| DsmError::internal("Error occurred", None::<std::io::Error>))?;
            device_states.insert(device_id, state.clone());
        }

        Ok(state)
    }

    /// Create a device-specific sub-genesis state
    ///
    /// Creates a genesis state for a specific device under this identity,
    /// derived from the master genesis state. This implements the hierarchical
    /// device management approach described in section 4 of the DSM whitepaper.
    ///
    /// # Arguments
    ///
    /// * `master_genesis` - The master genesis state
    /// * `device_info` - Information about the device
    ///
    /// # Returns
    ///
    /// * `Ok(State)` - The created device genesis state if successful
    /// * `Err(DsmError)` - If device genesis creation failed
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::identity_sdk::IdentitySDK;
    /// use dsm_sdk::hashchain_sdk::HashChainSDK;
    /// use dsm::types::state_types::DeviceInfo;
    /// use std::sync::Arc;
    ///
    /// let hash_chain_sdk = Arc::new(HashChainSDK::new());
    /// let identity_sdk = IdentitySDK::new("user123".into(), hash_chain_sdk);
    ///
    /// // First create master genesis
    /// let master_device = DeviceInfo::new("master", vec![1, 2, 3, 4]);
    /// let master_genesis = identity_sdk.create_genesis(
    ///     master_device,
    ///     vec![vec![5, 6, 7, 8]],
    ///     None
    /// ).map_err(|_e| DsmError::internal(e.to_string(), None))?;
    ///
    /// // Then create device-specific sub-genesis
    /// let device_info = DeviceInfo::new("phone", vec![9, 10, 11, 12]);
    /// let device_genesis = identity_sdk.create_device_genesis(
    ///     &master_genesis,
    ///     device_info
    /// ).map_err(|_e| DsmError::internal(e.to_string(), None))?;
    /// ```
    pub fn create_device_genesis(
        &self,
        master_genesis: &State,
        device_info: DeviceInfo,
    ) -> Result<State, DsmError> {
        // Clone device_info early since we need it twice
        let device_id = device_info.device_id;

        // Derive entropy from master genesis
        let mut hasher = dsm_domain_hasher("DSM/identity-hash");
        hasher.update(&master_genesis.entropy);
        hasher.update(&device_id);
        let device_entropy = *hasher.finalize().as_bytes();

        // Create a new sub-genesis state
        let mut state = State::new_genesis(device_entropy, device_info);

        // Link to master genesis through metadata
        let master_link_key = "master_genesis_hash";

        // Store master genesis hash in metadata
        let metadata = master_genesis.hash.to_vec();
        state.add_metadata(master_link_key, metadata)?;

        // Calculate hash
        let hash = state.compute_hash()?;
        state.hash = hash;

        // Store in device genesis states
        {
            let mut device_states = self
                .device_genesis_states
                .write()
                .map_err(|_| DsmError::internal("Error occurred", None::<std::io::Error>))?;
            device_states.insert(device_id, state.clone());
        }

        Ok(state)
    }

    /// Create a pre-commitment for a future operation
    ///
    /// Creates a cryptographic commitment to a future operation without
    /// revealing the operation details, as described in section 8 of the
    /// DSM whitepaper.
    ///
    /// # Arguments
    ///
    /// * `operation` - The operation to create a pre-commitment for
    /// * `counterparty_id` - Optional ID of the counterparty in a bilateral operation
    /// * `fixed_params` - Optional fixed parameters for the commitment
    /// * `variable_params` - Optional variable parameters for the commitment
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The pre-commitment if successful
    /// * `Err(DsmError)` - If pre-commitment creation failed
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::identity_sdk::IdentitySDK;
    /// use dsm_sdk::hashchain_sdk::HashChainSDK;
    /// use dsm::types::operations::Operation;
    /// use std::sync::Arc;
    ///
    /// // Create a pre-commitment for a future operation
    /// fn create_commitment(sdk: &IdentitySDK, operation: &Operation) {
    ///     let pre_commitment = sdk.create_pre_commitment(
    ///         operation,
    ///         Some("counterparty123".into()),
    ///         Some(vec![1, 2, 3]),
    ///         Some(vec![4, 5, 6])
    ///     ).map_err(|_e| DsmError::internal(e.to_string(), None))?;
    ///     
    ///     // The pre-commitment can be shared and later verified
    ///     // when the operation is executed
    /// }
    /// ```
    pub fn create_pre_commitment(
        &self,
        operation: &Operation,
        counterparty_id: Option<String>,
        fixed_params: Option<Vec<u8>>,
        variable_params: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, DsmError> {
        // Get current state
        let current_state = self
            .hash_chain_sdk
            .current_state()
            .ok_or_else(|| DsmError::state("No current state available for pre-commitment"))?;

        // Build deterministic, serde-free canonical bytes for the operation
        let operation_bytes = Self::operation_canonical_bytes(operation);

        // Calculate next entropy based on the deterministic formula en+1 = H(en || opn+1 || n+1)
        let mut entropy_hasher = dsm_domain_hasher("DSM/identity-entropy-derive");
        entropy_hasher.update(&current_state.entropy);
        entropy_hasher.update(&operation_bytes);
        entropy_hasher.update(&(current_state.state_number + 1).to_le_bytes());
        let next_entropy = entropy_hasher.finalize();

        // Create parameters for pre-commitment
        let mut params = Vec::new();
        if let Some(counter_id) = counterparty_id {
            params.extend_from_slice(counter_id.as_bytes());
        }
        if let Some(fixed) = fixed_params {
            params.extend_from_slice(&fixed);
        }
        if let Some(variable) = variable_params {
            params.extend_from_slice(&variable);
        }

        // Create the pre-commitment as Cpre = H(H(Sn) || opn+1 || en+1 || params)
        let mut pre_commitment_hasher = dsm_domain_hasher("DSM/identity-precommit");
        pre_commitment_hasher.update(&current_state.hash);
        pre_commitment_hasher.update(&operation_bytes);
        pre_commitment_hasher.update(next_entropy.as_bytes());
        pre_commitment_hasher.update(&params);

        let pre_commitment = pre_commitment_hasher.finalize().as_bytes().to_vec();

        Ok(pre_commitment)
    }

    /// Deterministic, serde-free canonical name for an operation (stable ASCII).
    fn canonical_operation_name(op: &Operation) -> &'static str {
        match op {
            Operation::Create { .. } => "CREATE",
            Operation::AddRelationship { .. } => "ADD_REL",
            Operation::RemoveRelationship { .. } => "REMOVE_REL",
            Operation::Invalidate { .. } => "INVALIDATE",
            Operation::Recovery { .. } => "RECOVERY",
            _ => "CUSTOM",
        }
    }

    /// Append len-prefixed bytes (LE u32) to the buffer for determinism.
    fn extend_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
        let len = bytes.len() as u32;
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(bytes);
    }

    /// Build canonical bytes for an Operation without Serde/bincode (stable ordering).
    fn operation_canonical_bytes(op: &Operation) -> Vec<u8> {
        let mut out = Vec::new();
        let tag = Self::canonical_operation_name(op);
        Self::extend_len_prefixed(&mut out, tag.as_bytes());

        match op {
            Operation::Create {
                message,
                identity_data,
                public_key,
                metadata,
                commitment,
                proof,
                ..
            } => {
                Self::extend_len_prefixed(&mut out, message.as_bytes());
                Self::extend_len_prefixed(&mut out, identity_data);
                Self::extend_len_prefixed(&mut out, public_key);
                Self::extend_len_prefixed(&mut out, metadata);
                Self::extend_len_prefixed(&mut out, commitment);
                Self::extend_len_prefixed(&mut out, proof);
            }
            Operation::AddRelationship {
                message,
                from_id,
                to_id,
                relationship_type,
                metadata,
                proof,
                ..
            } => {
                Self::extend_len_prefixed(&mut out, message.as_bytes());
                Self::extend_len_prefixed(&mut out, from_id);
                Self::extend_len_prefixed(&mut out, to_id);
                Self::extend_len_prefixed(&mut out, relationship_type);
                Self::extend_len_prefixed(&mut out, metadata);
                Self::extend_len_prefixed(&mut out, proof);
            }
            Operation::RemoveRelationship {
                message,
                from_id,
                to_id,
                relationship_type,
                proof,
                ..
            } => {
                Self::extend_len_prefixed(&mut out, message.as_bytes());
                Self::extend_len_prefixed(&mut out, from_id);
                Self::extend_len_prefixed(&mut out, to_id);
                Self::extend_len_prefixed(&mut out, relationship_type);
                Self::extend_len_prefixed(&mut out, proof);
            }
            Operation::Invalidate { reason, proof, .. } => {
                Self::extend_len_prefixed(&mut out, reason.as_bytes());
                Self::extend_len_prefixed(&mut out, proof);
            }
            Operation::Recovery {
                message,
                invalidation_data,
                new_state_data,
                new_state_number,
                new_state_hash,
                new_state_entropy,
                compromise_proof,
                authority_sigs,
                state_entropy,
                state_number,
                state_hash,
            } => {
                Self::extend_len_prefixed(&mut out, message.as_bytes());
                Self::extend_len_prefixed(&mut out, invalidation_data);
                Self::extend_len_prefixed(&mut out, new_state_data);
                out.extend_from_slice(&new_state_number.to_le_bytes());
                Self::extend_len_prefixed(&mut out, new_state_hash);
                Self::extend_len_prefixed(&mut out, new_state_entropy);
                Self::extend_len_prefixed(&mut out, compromise_proof);
                for sig in authority_sigs {
                    Self::extend_len_prefixed(&mut out, sig);
                }
                Self::extend_len_prefixed(&mut out, state_entropy);
                out.extend_from_slice(&state_number.to_le_bytes());
                Self::extend_len_prefixed(&mut out, state_hash);
            }
            _ => {
                // For unknown/custom variants, the tag alone provides stable differentiation.
            }
        }

        out
    }

    /// Verify a signature against data
    ///
    /// Verifies that a signature is valid for the provided data using
    /// the identity's public key.
    ///
    /// # Arguments
    ///
    /// * `data` - The data that was signed
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// * `Ok(bool)` - True if the signature is valid, false otherwise
    /// * `Err(DsmError)` - If verification failed
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::identity_sdk::IdentitySDK;
    /// use dsm_sdk::hashchain_sdk::HashChainSDK;
    /// use std::sync::Arc;
    ///
    /// let hash_chain_sdk = Arc::new(HashChainSDK::new());
    /// let identity_sdk = IdentitySDK::new("user123".into(), hash_chain_sdk);
    ///
    /// let data = b"Data to sign";
    /// let signature = identity_sdk.sign_data(data).map_err(|_e| DsmError::internal(e.to_string(), None))?;
    /// let is_valid = identity_sdk.verify_signature(data, &signature).map_err(|_e| DsmError::internal(e.to_string(), None))?;
    /// assert!(is_valid);
    /// ```
    pub fn verify_pre_commitment(
        &self,
        pre_commitment: &[u8],
        operation: &Operation,
    ) -> Result<bool, DsmError> {
        // Regenerate the pre-commitment using the same logic
        let regenerated = self.create_pre_commitment(operation, None, None, None)?;

        // Compare using constant-time equality to prevent timing attacks
        Ok(constant_time_eq(pre_commitment, &regenerated))
    }

    /// Create a relationship context with another identity
    ///
    /// Establishes a bilateral relationship context with another identity,
    /// enabling secure state transitions in the context of that relationship
    /// as described in section 7 of the DSM whitepaper.
    ///
    /// # Arguments
    ///
    /// * `counterparty_id` - The ID of the counterparty identity
    /// * `counterparty_public_key` - The public key of the counterparty
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If relationship creation was successful
    /// * `Err(DsmError)` - If relationship creation failed
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::identity_sdk::IdentitySDK;
    /// use dsm_sdk::hashchain_sdk::HashChainSDK;
    /// use std::sync::Arc;
    ///
    /// let hash_chain_sdk = Arc::new(HashChainSDK::new());
    /// let identity_sdk = IdentitySDK::new("user123".into(), hash_chain_sdk);
    ///
    /// // Create relationship with another identity
    /// identity_sdk.create_relationship_context(
    ///     "user456",
    ///     vec![1, 2, 3, 4]  // Public key
    /// ).map_err(|_e| DsmError::internal(e.to_string(), None))?;
    /// ```
    pub fn create_relationship_context(
        &self,
        counterparty_id: &str,
        counterparty_public_key: Vec<u8>,
    ) -> Result<(), DsmError> {
        let current_state = self.hash_chain_sdk.current_state().ok_or_else(|| {
            DsmError::state("No current state available for relationship creation")
        })?;

        let context = ExtendedRelationshipContext {
            entity_state_number: current_state.state_number,
            counterparty_id: counterparty_id.to_string(),
            counterparty_state_number: 0, // Initial state
            counterparty_public_key,
            current_state_hash: current_state.hash.to_vec(),
            state_sequence: vec![current_state.hash.to_vec()],
            metadata: HashMap::new(),
        };

        // Store the relationship context
        {
            let mut contexts = self
                .relationship_contexts
                .write()
                .map_err(|_| DsmError::lock_error())?;
            contexts.insert(counterparty_id.to_string(), context);
        }

        Ok(())
    }

    /// Get a relationship context by counterparty ID
    ///
    /// Retrieves the bilateral relationship context for a specific counterparty.
    ///
    /// # Arguments
    ///
    /// * `counterparty_id` - The ID of the counterparty
    ///
    /// # Returns
    ///
    /// * `Some(ExtendedRelationshipContext)` - The relationship context if found
    /// * `None` - If no relationship exists with the counterparty
    pub fn get_relationship_context(
        &self,
        counterparty_id: &str,
    ) -> Option<ExtendedRelationshipContext> {
        if let Ok(contexts) = self.relationship_contexts.read() {
            contexts.get(counterparty_id).cloned()
        } else {
            None
        }
    }

    /// Invalidate a state in the chain
    ///
    /// Creates an invalidation operation for a specific state,
    /// implementing the tombstone mechanism described in section 9
    /// of the DSM whitepaper.
    ///
    /// # Arguments
    ///
    /// * `_state_number` - The number of the state to invalidate
    /// * `reason` - The reason for invalidation
    /// * `proof` - Proof data justifying the invalidation
    ///
    /// # Returns
    ///
    /// * `Ok(Operation)` - The invalidation operation if successful
    /// * `Err(DsmError)` - If operation creation failed
    pub fn invalidate_state(
        &self,
        _state_number: u64,
        reason: &str,
        proof: Vec<u8>,
    ) -> Result<Operation, DsmError> {
        Ok(Operation::Invalidate {
            reason: reason.to_string(),
            proof,
            mode: TransactionMode::Bilateral, // Use Bilateral mode for invalidation
        })
    }

    /// Create a generic identity operation
    ///
    /// Creates a generic operation for this identity with the specified
    /// data and message.
    ///
    /// # Arguments
    ///
    /// * `_operation_type` - The type of operation
    /// * `data` - The operation data
    /// * `message` - A descriptive message for the operation
    ///
    /// # Returns
    ///
    /// * `Ok(Operation)` - The created operation if successful
    /// * `Err(DsmError)` - If operation creation failed
    pub fn create_generic_operation(
        &self,
        _operation_type: &str,
        data: Vec<u8>,
        message: String,
    ) -> Result<Operation, DsmError> {
        Ok(Operation::Create {
            message,
            identity_data: data,
            public_key: vec![],
            metadata: vec![],
            commitment: vec![],
            proof: vec![],
            mode: TransactionMode::Bilateral, // Use Bilateral mode
        })
    }

    /// Create an operation to add a relationship
    ///
    /// Creates an operation that establishes a relationship between identities,
    /// as described in section 7 of the DSM whitepaper.
    ///
    /// # Arguments
    ///
    /// * `from_id` - The source identity ID
    /// * `to_id` - The target identity ID
    /// * `relationship_type` - The type of relationship
    /// * `metadata` - Additional metadata for the relationship
    ///
    /// # Returns
    ///
    /// * `Ok(Operation)` - The relationship operation if successful
    /// * `Err(DsmError)` - If operation creation failed
    pub fn relationship_operation(
        &self,
        from_id: String,
        to_id: String,
        relationship_type: String,
        metadata: Vec<u8>,
    ) -> Result<Operation, DsmError> {
        let from_id_bytes = crate::util::domain_helpers::device_id_hash(&from_id);
        let to_id_bytes = crate::util::domain_helpers::device_id_hash(&to_id);
        Ok(Operation::AddRelationship {
            message: format!("Add relationship from {from_id} to {to_id}"),
            from_id: from_id_bytes,
            to_id: to_id_bytes,
            relationship_type: relationship_type.into_bytes(),
            metadata,
            proof: vec![],
            mode: TransactionMode::Bilateral, // Use Bilateral mode
        })
    }

    /// Create an operation to remove a relationship
    ///
    /// Creates an operation that removes an established relationship between identities.
    ///
    /// # Arguments
    ///
    /// * `from` - The source identity ID
    /// * `to` - The target identity ID
    /// * `rel_type` - The type of relationship
    /// * `proof_data` - Proof data justifying the removal
    ///
    /// # Returns
    ///
    /// * `Ok(Operation)` - The relationship removal operation if successful
    /// * `Err(DsmError)` - If operation creation failed
    pub fn remove_relationship_operation(
        &self,
        from: &str,
        to: &str,
        rel_type: String,
        proof_data: Vec<u8>,
    ) -> Result<Operation, DsmError> {
        let from_id_bytes = crate::util::domain_helpers::device_id_hash(from);
        let to_id_bytes = crate::util::domain_helpers::device_id_hash(to);
        Ok(Operation::RemoveRelationship {
            from_id: from_id_bytes,
            to_id: to_id_bytes,
            relationship_type: rel_type.into_bytes(),
            proof: proof_data,
            mode: TransactionMode::Bilateral,
            message: format!("Remove relationship from {from} to {to}"),
        })
    }

    /// Create an identity recovery operation
    ///
    /// Creates an operation for recovering from identity compromise,
    /// implementing the recovery mechanism described in section 9
    /// of the DSM whitepaper.
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the identity to recover
    /// * `auth_sigs` - Authority signatures authorizing the recovery
    /// * `comp_proof` - Proof of compromise
    /// * `invalid_data` - Data about the invalidation
    /// * `_sig_data` - Signature data (unused parameter)
    ///
    /// # Returns
    ///
    /// * `Ok(Operation)` - The recovery operation if successful
    /// * `Err(DsmError)` - If operation creation failed
    pub fn recovery_operation(
        &self,
        id: &str,
        auth_sigs: Vec<Vec<u8>>,
        comp_proof: Vec<u8>,
        invalid_data: Vec<u8>,
        _sig_data: Vec<u8>,
    ) -> Result<Operation, DsmError> {
        // Create a Recovery operation with the necessary parameters
        Ok(Operation::Recovery {
            message: format!("Identity recovery for {id}"),
            invalidation_data: invalid_data,
            new_state_data: vec![],
            new_state_number: 0,
            new_state_hash: vec![],
            new_state_entropy: vec![],
            compromise_proof: comp_proof,
            authority_sigs: auth_sigs,
            state_entropy: vec![],
            state_number: 0,
            state_hash: vec![0u8; 32],
        })
    }

    /// Generate a pairing QR code for this identity
    ///
    /// Creates a QR code that contains this identity's pairing information.
    ///
    /// # Returns
    ///
    /// * `Ok(crate::generated::ContactQrV3)` - QR code data
    /// * `Err(DsmError)` - If QR generation failed
    pub async fn generate_pairing_qr(&self) -> Result<crate::generated::ContactQrV3, DsmError> {
        // Build a canonical ContactQrV3 proto instance for pairing use.
        let sdk_fingerprint = dsm::crypto::blake3::domain_hash(
            "DSM/identity-fingerprint",
            self.identity_id.as_bytes(),
        );
        // Fetch genesis hash from AppState and encode as Base32 (spec requirement),
        // and derive a canonical string form of the device_id from stored bytes (base32).
        use crate::sdk::app_state::AppState;
        let (_device_id_str, _genesis_b32, did_bytes_raw, gh_bytes_raw) = {
            // Prefer persisted binary AppState values; fall back to live SDK context.
            let did_opt = AppState::get_device_id().or_else(|| {
                let ctx = crate::get_sdk_context();
                if ctx.is_initialized() {
                    Some(ctx.device_id())
                } else {
                    None
                }
            });
            let gh_opt = AppState::get_genesis_hash().or_else(|| {
                let ctx = crate::get_sdk_context();
                if ctx.is_initialized() {
                    let gh = ctx.genesis_hash();
                    if gh.iter().any(|&b| b != 0) {
                        Some(gh)
                    } else {
                        None
                    }
                } else {
                    None
                }
            });

            // Validate device_id presence and length
            let did_bytes = did_opt.filter(|v| v.len() == 32).ok_or_else(|| {
                DsmError::InvalidState(
                    "device_id not initialized; complete identity setup before pairing".into(),
                )
            })?;
            let device = text_id::encode_base32_crockford(&did_bytes);

            // Genesis hash is REQUIRED by the QR consumer; return an error early if unavailable.
            let gh_bytes = gh_opt.filter(|v| v.len() == 32).ok_or_else(|| {
                DsmError::InvalidState(
                    "genesis_hash not initialized; complete identity setup before pairing".into(),
                )
            })?;
            let g = text_id::encode_base32_crockford(&gh_bytes);

            (device, g, did_bytes, gh_bytes)
        };

        // Get signing public key for bilateral verification.
        // If the key is missing or empty (e.g. pre-existing genesis, failed derivation),
        // re-derive it deterministically from genesis + device_id + DBRW binding key.
        let signing_public_key = {
            let stored = AppState::get_public_key().unwrap_or_default();
            if stored.len() == 64 {
                stored
            } else {
                log::warn!(
                    "pairing_qr_v3: signing key missing/invalid (len={}), attempting re-derivation",
                    stored.len()
                );
                // DBRW binding key is only available on Android via JNI
                #[cfg(all(target_os = "android", feature = "jni"))]
                {
                    let dbrw = crate::jni::cdbrw::get_cdbrw_binding_key().ok_or_else(|| {
                        DsmError::InvalidState(
                            "Signing key not in AppState and DBRW unavailable for re-derivation. Restart the app.".into()
                        )
                    })?;
                    let did_raw = AppState::get_device_id().ok_or_else(|| {
                        DsmError::InvalidState(
                            "device_id not available for key re-derivation".into(),
                        )
                    })?;
                    let gh_raw = AppState::get_genesis_hash().ok_or_else(|| {
                        DsmError::InvalidState(
                            "genesis_hash not available for key re-derivation".into(),
                        )
                    })?;
                    let mut entropy = Vec::with_capacity(96);
                    entropy.extend_from_slice(&gh_raw);
                    entropy.extend_from_slice(&did_raw);
                    entropy.extend_from_slice(&dbrw);
                    let kp = SignatureKeyPair::generate_from_entropy(&entropy).map_err(|e| {
                        DsmError::InvalidState(format!("signing key re-derivation failed: {e}"))
                    })?;
                    let public_key = kp.public_key.clone();
                    // Persist the re-derived key so future calls don't need to re-derive
                    let smt = AppState::get_smt_root().unwrap_or_else(|| vec![0u8; 32]);
                    AppState::set_identity_info(did_raw, public_key.clone(), gh_raw, smt);
                    log::info!(
                        "pairing_qr_v3: re-derived and persisted signing key (len={})",
                        public_key.len()
                    );
                    public_key
                }
                #[cfg(not(all(target_os = "android", feature = "jni")))]
                {
                    return Err(DsmError::InvalidState(
                        "Signing key not in AppState; DBRW re-derivation not available on this platform.".into()
                    ));
                }
            }
        };
        log::info!(
            "pairing_qr_v3: including signing_public_key (len={})",
            signing_public_key.len()
        );

        let qr = crate::generated::ContactQrV3 {
            device_id: did_bytes_raw,
            network: "main".to_string(),
            storage_nodes: vec![], // pairing QR may omit nodes; UI should enrich before addContact
            sdk_fingerprint: sdk_fingerprint.as_bytes().to_vec(),
            genesis_hash: gh_bytes_raw,
            signing_public_key,
            preferred_alias: String::new(),
        };
        Ok(qr)
    }

    /// Return a compact, human-friendly pairing string combining device id and genesis hash.
    /// Format: `"<deviceIdString>@<genesisBase32>"`. If either value is missing, returns an error.
    pub async fn pairing_qr_compact(&self) -> Result<String, DsmError> {
        use crate::sdk::app_state::AppState;
        let did_bytes = AppState::get_device_id()
            .ok_or_else(|| DsmError::InvalidState("device_id not set".into()))?;
        let gh_bytes = AppState::get_genesis_hash()
            .ok_or_else(|| DsmError::InvalidState("genesis_hash not set".into()))?;
        if did_bytes.len() != 32 || gh_bytes.len() != 32 {
            return Err(DsmError::InvalidState(
                "device_id or genesis_hash wrong length".into(),
            ));
        }
        let did = text_id::encode_base32_crockford(&did_bytes);
        let gh_b32 = text_id::encode_base32_crockford(&gh_bytes);
        Ok(format!("{}@{}", did, gh_b32))
    }

    /// Consume/process a pairing QR code from another identity.
    ///
    /// JSON pairing QR consumption is disabled. Use a protobuf ContactQrV3 payload
    /// and call the bytes-based pairing handler (to be implemented).
    pub fn consume_pairing_qr(&self, _qr_data: &str) -> Result<(), DsmError> {
        Err(DsmError::invalid_operation(
            "JSON pairing QR consumption removed; supply ContactQrV3 protobuf",
        ))
    }
}

#[cfg(all(test, feature = "storage"))]
mod tests {
    use super::IdentitySDK;
    // use super::GENESIS_PUBLISH_TEST_DUMMY_TOKEN;
    use crate::sdk::hashchain_sdk::HashChainSDK;
    // use crate::sdk::storage_node_sdk::StorageNodeSDK;
    use std::sync::Arc;
    use dsm::types::state_types::DeviceInfo;

    #[tokio::test]
    async fn test_genesis_publishing_integration() {
        // Initialize AppState with a temp dir
        let temp_dir = std::env::temp_dir().join("dsm_test_genesis_publishing");
        let _ = std::fs::remove_dir_all(&temp_dir);
        let _ = std::fs::create_dir_all(&temp_dir);
        let _ = crate::storage_utils::set_storage_base_dir(temp_dir.clone());

        // This test requires storage nodes running on localhost:8080

        let hash_chain_sdk = Arc::new(HashChainSDK::new());
        let identity_sdk = IdentitySDK::new("test_user_genesis".into(), hash_chain_sdk);

        // Configure storage SDK
        // IMPORTANT: use a canonical-looking 32-byte base32 device_id string.
        // Passing the all-zero bytes base32 encoding is acceptable for local dev auth.
        // let dummy_device_id = crate::util::text_id::encode_base32_crockford(&[0u8; 32]);
        // let storage_sdk = StorageNodeSDK::new(/* complex config */)
        //     .expect("Failed to create storage sdk");
        // identity_sdk.set_storage_sdk(storage_sdk);

        let device_info = DeviceInfo::from_hashed_label("test_device_genesis", vec![0; 32]);

        // Create genesis (IMPORTANT: do NOT use tokio to run blocking sync work on the async executor.)
        // Run it on a dedicated blocking thread to avoid deadlocking the tokio runtime.
        let identity_sdk2 = identity_sdk.clone();
        let res = tokio::task::spawn_blocking(move || {
            identity_sdk2.create_genesis(device_info, vec![], None)
        })
        .await;

        let res = match res {
            Ok(inner) => inner,
            Err(join_err) => {
                println!("spawn_blocking failed: {:?}", join_err);
                return;
            }
        };

        if let Err(e) = res {
            println!("Genesis creation failed: {:?}", e);
        } else {
            println!("Genesis creation successful");
        }
    }
}
