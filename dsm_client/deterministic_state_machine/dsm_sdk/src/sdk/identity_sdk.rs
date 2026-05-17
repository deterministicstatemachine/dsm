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
//! use dsm::types::state_types::DeviceInfo;
//!
//!
//! // Create identity SDK
//! let identity_sdk = IdentitySDK::new("user123".into());
//!
//! // Create a device and genesis state
//! let device_info = DeviceInfo::new("device1", vec![1,2,3,4]);
//! ```
use crate::types::error::DsmError;
use dsm::crypto::blake3::dsm_domain_hasher;
#[cfg(feature = "storage")]
use crate::sdk::storage_node_sdk::StorageNodeSDK;
#[cfg(feature = "storage")]
use crate::sdk::genesis_publisher::SdkGenesisPublisher;
// `GenesisPublisher` + `SanitizedGenesisPayload` removed; publish
// now takes `pb::PublishableGenesisV1` directly via
// `SdkGenesisPublisher::publish`.
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
// `create_genesis_via_blind_mpc` was a thin wrapper around the
// orchestrator; this SDK now invokes the orchestrator
// (`create_root_genesis_mpc`) directly with a real
// `HttpGenesisMpcTransport`.

// ExtendedRelationshipContext struct deleted: only used by
// IdentitySDK::create_relationship_context + get_relationship_context, both
// dead (zero external callers). Relationship context per §7 now lives in
// dsm::types::state_types::RelationshipContext on DeviceState chain states.

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

    /// Cryptographic key pair for this identity
    signing_keypair: Arc<RwLock<Option<SignatureKeyPair>>>,

    /// Optional storage SDK for publishing genesis
    #[cfg(feature = "storage")]
    pub storage_sdk: Arc<RwLock<Option<StorageNodeSDK>>>,
}

impl IdentitySDK {
    /// Create a new IdentitySDK instance
    ///
    /// Initializes a new identity with the specified ID and generates
    /// cryptographic keys.
    ///
    /// # Arguments
    ///
    /// * `identity_id` - The unique identifier for this identity
    ///
    /// # Returns
    ///
    /// A new IdentitySDK instance
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::identity_sdk::IdentitySDK;
    ///
    /// let identity_sdk = IdentitySDK::new("user123".into());
    /// ```
    pub fn new(identity_id: String) -> Self {
        let sdk = Self {
            identity_id,
            device_genesis_states: Arc::new(RwLock::new(HashMap::new())),
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
    /// use std::sync::Arc;
    ///
    /// let identity_sdk = IdentitySDK::new("user123".into());
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
    /// use std::sync::Arc;
    ///
    /// let identity_sdk = IdentitySDK::new("user123".into());
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
    /// use dsm::types::state_types::DeviceInfo;
    /// use std::sync::Arc;
    ///
    /// let identity_sdk = IdentitySDK::new("user123".into());
    ///
    /// let device_info = DeviceInfo::new("device1", vec![1, 2, 3, 4]);
    /// let participant_inputs = vec![vec![5, 6, 7, 8]];
    /// let genesis = identity_sdk.create_genesis(
    ///     device_info,
    ///     participant_inputs,
    ///     Some(vec![9, 10, 11, 12])
    /// ).map_err(|_e| DsmError::internal(e.to_string(), None))?;
    /// ```
    #[cfg(not(feature = "storage"))]
    pub fn create_genesis(
        &self,
        _device_info: DeviceInfo,
        _participant_inputs: Vec<Vec<u8>>,
        _metadata: Option<Vec<u8>>,
    ) -> Result<State, DsmError> {
        Err(DsmError::invalid_operation(
            "IdentitySDK::create_genesis requires the `storage` feature; \
             production genesis MPC contacts real storage-node URLs.",
        ))
    }

    #[cfg(feature = "storage")]
    pub fn create_genesis(
        &self,
        device_info: DeviceInfo,
        participant_inputs: Vec<Vec<u8>>,
        metadata: Option<Vec<u8>>,
    ) -> Result<State, DsmError> {
        log::info!(
            "IdentitySDK::create_genesis(start): identity_id='{}' device_label='{}' participant_inputs={} storage_sdk_set={}",
            self.identity_id,
            crate::util::text_id::encode_base32_crockford(&device_info.device_id),
            participant_inputs.len(),
            self.storage_sdk.read().map(|g| g.is_some()).unwrap_or(false)
        );

        // Convert participant inputs to deterministic base32 strings (canonical, display-safe).
        let _participants: Vec<String> = participant_inputs
            .iter()
            .map(|p| crate::util::text_id::encode_base32_crockford(p))
            .collect();

        // Per whitepaper §2.5: n-of-n MPC; no threshold parameter.

        // Derive a deterministic 32-byte device id for MPC path from
        // identity id + device id to keep tests stable.
        let mut id_hasher = dsm_domain_hasher("DSM/identity-mpc-id");
        id_hasher.update(self.identity_id.as_bytes());
        id_hasher.update(&device_info.device_id);
        let id_hash = id_hasher.finalize();
        let mut device_id_arr = [0u8; 32];
        device_id_arr.copy_from_slice(id_hash.as_bytes());

        let k_dbrw =
            crate::sdk::app_state::AppState::take_platform_cdbrw_binding_key("identity_sdk")
                .map_err(dsm::types::error::DsmError::invalid_operation)?;

        // ---- Genesis MPC against real storage nodes (Task A.4) ----
        //
        // 1. Fetch the active registry from any reachable bootstrap
        //    storage node and compute
        //    `R_reg = H("DSM/registry\0" || ProtoDet(RegistryV3))`.
        // 2. Derive `session_id = H("DSM/genesis-mpc-session\0" ||
        //    R_reg || device_id)` — publicly recomputable, not
        //    orchestrator-chosen.
        // 3. Pick N participants by `permute_unbiased(session_id,
        //    registry).take(N)` — deterministic from public inputs;
        //    the orchestrator cannot grind a favorable subset.
        // 4. Resolve each picked node_id to a reachable URL via
        //    discovery (`/api/v2/nodes/discover`) and cross-verify
        //    by hitting `/api/v2/node/identity` on the address.
        // 5. Run the strict N-of-N commit-reveal protocol.

        let storage_sdk = self
            .storage_sdk
            .read()
            .map_err(|_| DsmError::LockError)?
            .clone()
            .ok_or_else(|| {
                DsmError::invalid_operation(
                    "IdentitySDK::create_genesis: storage_sdk not configured; \
                     production genesis MPC requires storage-node URLs.",
                )
            })?;
        let bootstrap_urls = storage_sdk.get_node_urls();
        if bootstrap_urls.is_empty() {
            return Err(DsmError::invalid_operation(
                "IdentitySDK::create_genesis: no bootstrap storage-node URLs configured",
            ));
        }

        // Fetch the active registry from any reachable bootstrap node.
        // First successful response wins. (R_reg recomputation locally
        // means a tampered transit can't substitute a different anchor.)
        let mut snapshot_opt: Option<crate::sdk::genesis_mpc_transport::RegistrySnapshot> = None;
        let mut last_err: Option<DsmError> = None;
        for url in &bootstrap_urls {
            match futures::executor::block_on(crate::sdk::genesis_mpc_transport::fetch_registry(
                url,
            )) {
                Ok(snap) => {
                    snapshot_opt = Some(snap);
                    break;
                }
                Err(e) => {
                    log::warn!(
                        "IdentitySDK::create_genesis: registry fetch from {url} failed: {e}"
                    );
                    last_err = Some(e);
                }
            }
        }
        let snapshot = snapshot_opt.ok_or_else(|| {
            last_err.unwrap_or_else(|| {
                DsmError::invalid_operation(
                    "IdentitySDK::create_genesis: registry unreachable on every bootstrap URL",
                )
            })
        })?;

        let n_required: usize = 3;
        if snapshot.node_ids.len() < n_required {
            return Err(DsmError::invalid_operation(format!(
                "IdentitySDK::create_genesis: registry has {} active node(s); \
                 need ≥{} for N-of-N MPC (whitepaper §2.5)",
                snapshot.node_ids.len(),
                n_required
            )));
        }

        // Deterministic session_id + permute-based participant pick.
        let session_id_arr = dsm::core::identity::genesis_mpc::compute_genesis_mpc_session_id(
            &snapshot.r_reg,
            &device_id_arr,
        );
        let permuted =
            dsm::core::identity::genesis_mpc::permute_unbiased(session_id_arr, &snapshot.node_ids);
        let chosen_ids: Vec<[u8; 32]> = permuted.into_iter().take(n_required).collect();

        // Resolve picked node_ids → URLs via discovery. The
        // bootstrap node tells us about all alive peers; the
        // address-to-id pairing is then cross-verified by directly
        // calling /api/v2/node/identity on each picked address.
        let discovered: Vec<(String, [u8; 32])> = {
            let mut acc: Vec<(String, [u8; 32])> = Vec::new();
            for url in &bootstrap_urls {
                if let Ok(resp) = futures::executor::block_on(storage_sdk.discover_local()) {
                    for info in &resp.discovered_node_infos {
                        if let Ok(id_arr) = info.node_id.as_slice().try_into() {
                            acc.push((info.address.clone(), id_arr));
                        }
                    }
                    if !resp.discovered_node_infos.is_empty() {
                        break;
                    }
                }
                let _ = url;
            }
            // Fallback: if `discover_local()` is a config-only stub,
            // pair each configured URL with the id reported by
            // `/api/v2/node/identity`. This is the same path the
            // earlier "first ≥3 reachable" code used, kept as a
            // legitimate non-registry resolution branch.
            if acc.is_empty() {
                for url in &bootstrap_urls {
                    if let Ok(id) = futures::executor::block_on(
                        crate::sdk::genesis_mpc_transport::fetch_node_identity(url),
                    ) {
                        acc.push((url.clone(), id));
                    }
                }
            }
            acc
        };

        let mut id_to_url: std::collections::HashMap<[u8; 32], String> =
            std::collections::HashMap::new();
        for (addr, id) in discovered {
            id_to_url.entry(id).or_insert(addr);
        }

        // Build the chosen `(node_id, url)` pairs, cross-verifying
        // each via `/api/v2/node/identity` so a discovery operator
        // can't lie about which id lives at which address.
        let mut node_urls_pairs: Vec<([u8; 32], String)> = Vec::with_capacity(n_required);
        for id in &chosen_ids {
            let url = id_to_url.get(id).ok_or_else(|| {
                DsmError::invalid_operation(format!(
                    "IdentitySDK::create_genesis: picked participant {} not reachable via discovery",
                    crate::util::text_id::encode_base32_crockford(id)
                ))
            })?;
            futures::executor::block_on(
                crate::sdk::genesis_mpc_transport::fetch_and_verify_node_identity(url, id),
            )?;
            node_urls_pairs.push((*id, url.clone()));
        }

        // Device's platform-attestation SPHINCS+ keypair. In a
        // production silicon-binding integration this would come
        // from the secure element; for this pass we generate a
        // fresh keypair per session — still defeats offer
        // front-running (sk_attest never leaves this process).
        let (pk_attest, sk_attest) = dsm::crypto::sphincs::generate_sphincs_keypair()?;

        // Build participants list, canonicalised by the orchestrator.
        let participants: Vec<[u8; 32]> = node_urls_pairs.iter().map(|(id, _)| *id).collect();

        // Compute device_cdbrw binding for the offer envelope.
        let device_cdbrw = {
            let mut h = dsm_domain_hasher("DSM/genesis-mpc-cdbrw");
            h.update(&device_id_arr);
            h.update(&k_dbrw);
            let mut out = [0u8; 32];
            out.copy_from_slice(h.finalize().as_bytes());
            out
        };

        let transport =
            crate::sdk::genesis_mpc_transport::HttpGenesisMpcTransport::new(node_urls_pairs);

        #[cfg(feature = "storage")]
        log::info!(
            "IdentitySDK::create_genesis: launching N-of-N MPC against {} participants",
            participants.len()
        );

        let outcome = futures::executor::block_on(
            dsm::core::identity::genesis_mpc::create_root_genesis_mpc(
                session_id_arr,
                device_id_arr,
                device_cdbrw,
                participants,
                k_dbrw,
                None,
                pk_attest,
                &sk_attest,
                &transport,
            ),
        )?;

        let genesis_state = dsm::core::identity::genesis::convert_session_to_genesis_state_compat(
            &outcome.session,
        )?;

        #[cfg(feature = "storage")]
        log::info!(
            "IdentitySDK::create_genesis: MPC returned genesis_state.hash_len={} signing_pk_len={} entropy_len={}",
            genesis_state.hash.len(),
            genesis_state.signing_key.public_key.len(),
            genesis_state.initial_entropy.len()
        );

        // Publish genesis content-addressed at
        // `addr = H("DSM/genesis-mirror\0" || G)` per spec §6 — the
        // counterparty fetch path resolves the same address.
        #[cfg(feature = "storage")]
        if let Some(storage_sdk) = self
            .storage_sdk
            .read()
            .map_err(|_| DsmError::LockError)?
            .as_ref()
        {
            let publisher = SdkGenesisPublisher::new(storage_sdk.clone());
            let publishable = outcome.to_publishable()?;

            log::info!(
                "IdentitySDK::create_genesis: publishing genesis (genesis_hash_b32={}, participants={})",
                crate::util::text_id::encode_base32_crockford(&publishable.genesis_hash),
                publishable.participants.len(),
            );

            // NOTE: This blocks on an async HTTP call while we're in a
            // sync function — if it hangs, it's a network/IO stall.
            futures::executor::block_on(publisher.publish(&publishable))?;

            log::info!("IdentitySDK::create_genesis: publish done");
        }

        // Use the initial entropy from the cryptographic genesis
        let entropy = genesis_state.initial_entropy;

        // Create the state using the cryptographically secure entropy
        let mut state = State::new_genesis(entropy, device_info);

        // §4.3 — State.external_data parameter map removed. Metadata
        // attached to identity creation is no longer carried on the
        // canonical State; if needed, callers should attach it to a
        // separate identity-metadata sidecar.
        let _ = metadata;

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
    /// use dsm::types::state_types::DeviceInfo;
    /// use std::sync::Arc;
    ///
    /// let identity_sdk = IdentitySDK::new("user123".into());
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

        // §4.3 — State.external_data removed. Master-genesis linkage now
        // travels via prev_state_hash (§2.1 hash adjacency); the dedicated
        // "master_genesis_hash" metadata key is no longer needed because the
        // device-state genesis is rooted at the master genesis hash via the
        // prev_state_hash chain rather than a side-channel parameter map.
        let _ = master_genesis;

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

    // Dead IdentitySDK methods removed (Apr 2026 State residue sweep):
    //   - create_pre_commitment / verify_pre_commitment: pre-commitment hashing
    //     that read hash_chain_sdk.current_state(). Zero external callers; pre-
    //     commitment logic now lives in commitments::precommit::PreCommitment
    //     which takes a canonical parent-hash directly.
    //   - create_relationship_context / get_relationship_context: relationship
    //     registry that read hash_chain_sdk.current_state(). Zero external
    //     callers; §7 relationship context now lives on DeviceState chain tips
    //     (state_types::RelationshipContext embedded in RelationshipChainState).
    //   - canonical_operation_name / extend_len_prefixed / operation_canonical_bytes:
    //     serde-free serializers used only by create_pre_commitment.
    // Deletion also enabled dropping the hash_chain_sdk field (replaced by the
    // DeviceState/RelationshipChainState flow) and the ExtendedRelationshipContext
    // struct + relationship_contexts map.

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
    // use crate::sdk::storage_node_sdk::StorageNodeSDK;
    use dsm::types::state_types::DeviceInfo;

    #[tokio::test]
    async fn test_genesis_publishing_integration() {
        // Initialize AppState with a temp dir
        let temp_dir = std::env::temp_dir().join("dsm_test_genesis_publishing");
        let _ = std::fs::remove_dir_all(&temp_dir);
        let _ = std::fs::create_dir_all(&temp_dir);
        let _ = crate::storage_utils::set_storage_base_dir(temp_dir.clone());

        // This test requires storage nodes running on localhost:8080

        let identity_sdk = IdentitySDK::new("test_user_genesis".into());

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
