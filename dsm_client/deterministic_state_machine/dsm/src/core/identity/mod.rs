//! Identity Module
//!
//! This module handles all aspects of identity management in DSM, including:
//! - Secure genesis state creation
//! - Hierarchical device-specific sub-identities
//! - Device management and invalidation
//! - Cross-device identity verification
//!
//! # DSM Core Identity Policy
//! DSM core enforces ≥3 storage nodes and threshold ≥3; no 2-of-N convenience,
//! no alternate-path entropy; storage is trait-only.

// DSM Protocol Security Invariants - Compile-time enforced
pub const MIN_PARTICIPANTS: usize = 3;
pub const MIN_THRESHOLD: usize = 3;

// Compile-time assertions to prevent regression
const _: () = assert!(
    MIN_PARTICIPANTS >= 3,
    "MPC security requires at least 3 participants"
);
const _: () = assert!(
    MIN_THRESHOLD >= 3,
    "MPC threshold must be >= 3 to resist 2 colluding nodes"
);
const _: () = assert!(
    MIN_THRESHOLD <= MIN_PARTICIPANTS,
    "Threshold cannot exceed participants"
);

pub mod genesis;
pub mod genesis_mpc;
pub mod hierarchical_device_management;
// JNI bridge moved to dsm_sdk - see dsm_sdk/src/jni/unified_protobuf_bridge.rs

use crate::types::state_types::MerkleProof;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use crate::types::error::DsmError;
use crate::core::utility::labeling;
use crate::types::identifiers::NodeId;
use crate::types::state_types::State;
use crate::prelude::*; // common items incl. Uuid, etc.
use crate::crypto::blake3::{dsm_domain_hasher, domain_hash};
use blake3;
use tracing;
use zeroize::Zeroize;

// Import MPC types
use crate::core::identity::genesis_mpc::{create_mpc_genesis, GenesisSession};
// Re-export GenesisState for other modules
pub use crate::core::identity::genesis::{verify_genesis_state, GenesisState};

#[allow(dead_code)]
fn sanitize_genesis_state(genesis: &GenesisState) -> GenesisState {
    let mut sanitized = genesis.clone();
    sanitized.signing_key.secret_key.zeroize();
    sanitized.kyber_keypair.secret_key.zeroize();
    sanitized
}

fn compute_contribution_merkle_root(contributions: &[genesis::Contribution]) -> Option<[u8; 32]> {
    if contributions.is_empty() {
        return None;
    }

    // Leaf = BLAKE3("DSM/GENESIS/CONTRIB/v2" || data)
    let mut leaves: Vec<[u8; 32]> = contributions
        .iter()
        .map(|c| {
            let mut h = dsm_domain_hasher("DSM/GENESIS/CONTRIB/v2");
            h.update(&c.data);
            *h.finalize().as_bytes()
        })
        .collect();

    // Canonicalize order
    leaves.sort();

    // Pairwise hash up the tree (duplicate last if odd)
    let mut level = leaves;
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0usize;
        while i < level.len() {
            let left = &level[i];
            let right = if i + 1 < level.len() {
                &level[i + 1]
            } else {
                &level[i]
            };
            let mut h = dsm_domain_hasher("DSM/genesis");
            h.update(left);
            h.update(right);
            next.push(*h.finalize().as_bytes());
            i += 2;
        }
        level = next;
    }

    level.into_iter().next()
}

/// Convert session to genesis state for compatibility (no encodings for IDs)
pub fn convert_session_to_genesis_state(
    session: &GenesisSession,
) -> Result<GenesisState, IdentityError> {
    // DBRW is an optional, local anti-cloning signal and must NOT be required to
    // create or represent genesis / identity. Genesis must remain derivable and
    // recoverable without DBRW present.

    if session.storage_nodes.is_empty() {
        return Err(IdentityError::InvalidParameter(
            "MPC session did not record any storage node participants".into(),
        ));
    }

    if session.threshold == 0 {
        return Err(IdentityError::InvalidParameter(
            "MPC session reported threshold of zero".into(),
        ));
    }

    if session.genesis_id == [0u8; 32] {
        return Err(IdentityError::GenesisError {
            context: "MPC session is missing computed genesis identifier".into(),
            step: "verify_session".into(),
            internal_error: None,
        });
    }

    let signing_key = genesis::SigningKey::new().map_err(|e| IdentityError::GenesisError {
        context: "Failed to generate signing key".into(),
        step: "key_generation".into(),
        internal_error: Some(format!("{e:?}")),
    })?;
    let kyber_keypair = genesis::KyberKey::new().map_err(|e| IdentityError::GenesisError {
        context: "Failed to generate kyber key".into(),
        step: "key_generation".into(),
        internal_error: Some(format!("{e:?}")),
    })?;

    let participants: HashSet<String> = session
        .storage_nodes
        .iter()
        .map(|n| n.to_string())
        .collect();

    let contributions: Vec<genesis::Contribution> = session
        .mpc_entropies
        .iter()
        .map(|entropy| genesis::Contribution {
            data: entropy.to_vec(),
            verified: true,
        })
        .collect();

    let merkle_root = compute_contribution_merkle_root(&contributions);

    Ok(GenesisState {
        hash: session.genesis_id,
        initial_entropy: session.device_entropy,
        signing_key,
        kyber_keypair,
        threshold: session.threshold,
        participants,
        merkle_root,
        // device_id is display-only in GenesisState; omit any encoding
        device_id: None,
        contributions,
    })
}

/// Genesis creation result
#[derive(Debug, Clone)]
pub struct GenesisCreationResult {
    pub genesis_id: [u8; 32],
    pub device_id: [u8; 32],
}

/// Detailed artifacts produced by trustless MPC genesis creation.
#[derive(Debug, Clone)]
pub struct TrustlessGenesisArtifacts {
    pub device_id: [u8; 32],
    pub genesis_state: GenesisState,
    pub session: GenesisSession,
}

impl TrustlessGenesisArtifacts {
    /// Convert artifacts into a lightweight creation result summary.
    pub fn as_creation_result(&self) -> GenesisCreationResult {
        GenesisCreationResult {
            genesis_id: self.genesis_state.hash,
            device_id: self.device_id,
        }
    }
}

/// Perform trustless blind MPC genesis creation at the core level.
pub async fn create_trustless_genesis<
    S: crate::core::identity::genesis_mpc::GenesisStorage + Sync + Send,
>(
    device_id: String,
    storage_nodes: Vec<NodeId>,
    threshold: usize,
    metadata: Option<String>,
    storage: Option<&S>,
) -> Result<TrustlessGenesisArtifacts, IdentityError> {
    let span = tracing::span!(
        tracing::Level::INFO,
        "MPC/genesis/create_trustless",
        device_id = %device_id,
        session_id = tracing::field::Empty,
        threshold = threshold,
        n_participants = storage_nodes.len()
    );
    let _enter = span.enter();

    if storage_nodes.len() < MIN_PARTICIPANTS {
        return Err(IdentityError::InvalidParameter(
            "MPC/threshold/too_low: requires at least 3 participants for trustless genesis".into(),
        ));
    }

    if threshold < MIN_THRESHOLD {
        return Err(IdentityError::InvalidParameter(
            "MPC/threshold/too_low: threshold must be at least 3 for MPC security".into(),
        ));
    }

    if threshold > storage_nodes.len() {
        return Err(IdentityError::InvalidParameter(
            "MPC/threshold/invalid: threshold cannot exceed number of participants".into(),
        ));
    }

    // Deterministic 32B device hash label for MPC inputs
    let device_id_bytes: [u8; 32] = *domain_hash("DSM/device-id", device_id.as_bytes()).as_bytes();

    let session = create_mpc_genesis(
        device_id_bytes,
        storage_nodes,
        threshold,
        metadata.map(|s| s.into_bytes()),
    )
    .await
    .map_err(|e| IdentityError::GenesisError {
        context: "MPC genesis failed".into(),
        step: "mpc_genesis".into(),
        internal_error: Some(format!("{e:?}")),
    })?;

    // Purely for tracing: generate a decimal label from session.genesis_id (no hex)
    let sess_label = {
        let bytes = &session.genesis_id;
        if bytes.len() >= 8 {
            let mut lo = [0u8; 8];
            lo.copy_from_slice(&bytes[0..8]);
            u64::from_le_bytes(lo).to_string()
        } else {
            "0".to_string()
        }
    };
    span.record("session_id", tracing::field::display(&sess_label));

    let genesis_state =
        convert_session_to_genesis_state(&session).map_err(|e| IdentityError::GenesisError {
            context: "MPC genesis conversion failed".into(),
            step: "mpc_conversion".into(),
            internal_error: Some(format!("{e:?}")),
        })?;

    // Optionally publish sanitized genesis state to storage (binary, deterministic; no serde/json)
    if let Some(s) = storage {
        fn encode_genesis_for_storage(gs: &genesis::GenesisState) -> Vec<u8> {
            let mut out = Vec::new();
            // hash (len + bytes)
            out.extend_from_slice(&(gs.hash.len() as u32).to_le_bytes());
            out.extend_from_slice(&gs.hash);
            // threshold (u64)
            out.extend_from_slice(&(gs.threshold as u64).to_le_bytes());
            // participants sorted (len + each len+bytes)
            let mut parts: Vec<_> = gs.participants.iter().cloned().collect();
            parts.sort();
            out.extend_from_slice(&(parts.len() as u32).to_le_bytes());
            for p in parts {
                let pb = p.as_bytes();
                out.extend_from_slice(&(pb.len() as u32).to_le_bytes());
                out.extend_from_slice(pb);
            }
            // merkle_root optional
            match &gs.merkle_root {
                Some(mr) => {
                    out.push(1);
                    out.extend_from_slice(&(mr.len() as u32).to_le_bytes());
                    out.extend_from_slice(mr);
                }
                None => out.push(0),
            }
            // device_id optional (omitted to avoid encodings)
            out.push(0);
            out
        }

        let ser = encode_genesis_for_storage(&genesis_state);
        let mut hash32 = [0u8; 32];
        hash32.copy_from_slice(&genesis_state.hash[0..32]);
        s.put(&hash32, &ser).await?;
    }

    let device_id_bytes = domain_hash("DSM/device-id", device_id.as_bytes()).into();
    Ok(TrustlessGenesisArtifacts {
        device_id: device_id_bytes,
        genesis_state,
        session,
    })
}

/// Context-based identity store
/// Replaces global store to enforce bilateral isolation (no global state)
#[derive(Clone)]
pub struct IdentityStore {
    pub store: Arc<RwLock<HashMap<String, Identity>>>,
}

impl Default for IdentityStore {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityStore {
    /// Create a new, empty identity store
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Retrieve an identity by its genesis ID
    #[allow(clippy::unused_async)]
    pub async fn get_identity(&self, genesis_id: &str) -> Option<Identity> {
        if let Ok(store) = self.store.read() {
            store.get(genesis_id).cloned()
        } else {
            None
        }
    }

    /// Insert or update an identity in the store
    #[allow(clippy::unused_async)]
    pub async fn insert_identity(&self, identity: Identity) -> Result<(), IdentityError> {
        if let Ok(mut store) = self.store.write() {
            store.insert(labeling::identity_to_string(&identity), identity);
            Ok(())
        } else {
            Err(IdentityError::StorageError(
                "Failed to write to identity store".into(),
            ))
        }
    }

    /// Check if an identity has been invalidated
    #[allow(clippy::unused_async)]
    pub async fn is_invalidated(&self, genesis_id: &str) -> Result<bool, IdentityError> {
        if let Ok(store) = self.store.read() {
            let identity = store
                .get(genesis_id)
                .ok_or_else(|| IdentityError::IdentityNotFound("Identity not found".into()))?;
            Ok(identity.invalidated)
        } else {
            Err(IdentityError::StorageError(
                "Failed to access identity store".into(),
            ))
        }
    }

    /// Add a new device to an existing identity
    #[allow(clippy::unused_async)]
    pub async fn add_device(&self, genesis_id: &str) -> Result<DeviceIdentity, IdentityError> {
        if let Ok(mut store) = self.store.write() {
            let identity = store
                .get_mut(genesis_id)
                .ok_or_else(|| IdentityError::IdentityNotFound("Identity not found".into()))?;
            let device_id = format!("device_{:016x}", crate::performance::mono_commit_height());
            let device_id_bytes = domain_hash("DSM/device-id", device_id.as_bytes()).into();
            if identity
                .devices
                .iter()
                .any(|d| d.device_id == device_id_bytes)
            {
                return Err(IdentityError::DuplicateDevice(
                    "Device already registered for this identity".into(),
                ));
            }
            // Device entropy (caller can provide real entropy; we use 32 zero bytes here deterministically)
            let device_entropy = vec![0u8; 32];
            let device_identity = match genesis::derive_device_sub_genesis(
                &identity.master_genesis,
                &device_id,
                &device_entropy,
            ) {
                Ok(g) => DeviceIdentity {
                    device_id: device_id_bytes,
                    sub_genesis: g,
                    current_state: None,
                    sparse_indices: HashMap::new(),
                },
                Err(e) => {
                    return Err(IdentityError::DeviceError(format!(
                        "Device genesis derivation failed: {e:?}"
                    )))
                }
            };
            identity.devices.push(device_identity.clone());
            Ok(device_identity)
        } else {
            Err(IdentityError::StorageError(
                "Failed to access identity store".into(),
            ))
        }
    }

    /// Create a new identity with MANDATORY MPC genesis creation
    pub async fn create_identity<
        S: crate::core::identity::genesis_mpc::GenesisStorage + Sync + Send,
    >(
        &self,
        name: &str,
        threshold: usize,
        participants: Vec<NodeId>,
        storage: Option<&S>,
    ) -> Result<Identity, IdentityError> {
        let span = tracing::span!(
            tracing::Level::INFO,
            "MPC/identity/create",
            name = %name,
            session_id = tracing::field::Empty,
            threshold = threshold,
            n_participants = participants.len()
        );
        let _enter = span.enter();

        if participants.len() < MIN_PARTICIPANTS {
            return Err(IdentityError::InvalidParameter(
                "MPC/threshold/too_low: MPC requires at least 3 storage-node participants (plus device entropy)"
                    .into(),
            ));
        }

        if threshold < MIN_THRESHOLD {
            return Err(IdentityError::InvalidParameter(
                "MPC/threshold/too_low: threshold must be ≥3 to resist 2 colluding nodes".into(),
            ));
        }

        if threshold > participants.len() {
            return Err(IdentityError::InvalidParameter(
                "MPC/threshold/invalid: threshold cannot be greater than number of participants"
                    .into(),
            ));
        }

        let device_id = format!("device_{:016x}", crate::performance::mono_commit_height());

        // Core-level trustless MPC genesis protocol
        let artifacts = create_trustless_genesis(
            device_id.clone(),
            participants.clone(),
            threshold,
            Some(format!("DSM_IDENTITY_{name}")),
            storage,
        )
        .await?;

        // Purely for tracing: decimal session label from genesis hash
        let sess_label = {
            let bytes = &artifacts.genesis_state.hash;
            if bytes.len() >= 8 {
                let mut lo = [0u8; 8];
                lo.copy_from_slice(&bytes[0..8]);
                u64::from_le_bytes(lo).to_string()
            } else {
                "0".to_string()
            }
        };
        span.record("session_id", tracing::field::display(&sess_label));

        let genesis = artifacts.genesis_state.clone();

        // Derive device-specific sub-genesis
        let device_entropy = genesis::get_device_entropy(&device_id)?;
        let device_identity =
            genesis::derive_device_sub_genesis(&genesis, &device_id, &device_entropy).map_err(
                |e| IdentityError::DeviceError(format!("Device genesis derivation failed: {e:?}")),
            )?;

        let device_id_bytes = domain_hash("DSM/device-id", device_id.as_bytes()).into();
        let identity = Identity {
            name: name.to_string(),
            master_genesis: genesis,
            devices: vec![DeviceIdentity {
                device_id: device_id_bytes,
                sub_genesis: device_identity,
                current_state: None,
                sparse_indices: HashMap::new(),
            }],
            invalidated: false,
        };

        if let Ok(mut store) = self.store.write() {
            store.insert(labeling::identity_to_string(&identity), identity.clone());
        }

        Ok(identity)
    }

    /// Create identity with storage nodes for MPC (production method)
    pub async fn create_identity_with_storage_nodes<
        S: crate::core::identity::genesis_mpc::GenesisStorage + Sync + Send,
    >(
        &self,
        name: &str,
        storage_nodes: Vec<NodeId>,
        threshold: usize,
        storage: Option<&S>,
    ) -> Result<Identity, IdentityError> {
        if storage_nodes.len() < MIN_PARTICIPANTS {
            return Err(IdentityError::InvalidParameter(
                "At least 3 storage nodes required for MPC genesis creation".into(),
            ));
        }

        if threshold > storage_nodes.len() {
            return Err(IdentityError::InvalidParameter(
                "Threshold cannot exceed number of storage nodes".into(),
            ));
        }

        self.create_identity(name, threshold, storage_nodes, storage)
            .await
    }

    /// Get the public key for this identity (binary; not encoded)
    pub fn get_public_key(&self) -> Result<Vec<u8>, crate::types::error::DsmError> {
        if let Ok(store) = self.store.read() {
            if let Some((_, identity)) = store.iter().next() {
                return Ok(identity.master_genesis.signing_key.public_key.clone());
            }
        }

        Err(crate::types::error::DsmError::not_found(
            "Identity",
            Some("No signing key available".to_string()),
        ))
    }
}

/// Error types specific to identity operations
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("Identity not found: {0}")]
    IdentityNotFound(String),

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("Genesis error: {context} (step: {step})")]
    GenesisError {
        context: String,
        step: String,
        internal_error: Option<String>,
    },

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Device error: {0}")]
    DeviceError(String),

    #[error("Duplicate device: {0}")]
    DuplicateDevice(String),

    #[error("Identity invalidated: {0}")]
    IdentityInvalidated(String),

    #[error("Genesis failed: {0}")]
    GenesisFailed(String),
}

impl From<crate::types::error::DsmError> for IdentityError {
    fn from(error: crate::types::error::DsmError) -> Self {
        IdentityError::GenesisError {
            context: "Converted from DsmError".into(),
            step: "conversion".into(),
            internal_error: Some(format!("{error:?}")),
        }
    }
}

impl From<IdentityError> for crate::types::error::DsmError {
    fn from(error: IdentityError) -> Self {
        crate::types::error::DsmError::Identity(error.to_string())
    }
}

/// Verify a trustless identity chain against a genesis state.
pub fn verify_trustless_identity(
    genesis: &GenesisState,
    chain: &[State],
) -> Result<(), IdentityError> {
    let genesis_valid = verify_genesis_state(genesis)?;
    if !genesis_valid {
        return Err(IdentityError::GenesisError {
            context: "Genesis state failed structural verification".into(),
            step: "verify_trustless_identity".into(),
            internal_error: None,
        });
    }

    let mut expected_prev_hash = genesis.hash;
    let mut previous_number = 0u64;

    for state in chain {
        if state.state_number == 0 {
            let state_hash = state.compute_hash().map_err(IdentityError::from)?;
            if state_hash != genesis.hash {
                return Err(IdentityError::GenesisError {
                    context: "Provided chain contains a genesis state that does not match the supplied genesis hash".into(),
                    step: "verify_trustless_identity".into(),
                    internal_error: None,
                });
            }
            expected_prev_hash = state_hash;
            previous_number = 0;
            continue;
        }

        if state.state_number != previous_number + 1 {
            return Err(IdentityError::InvalidParameter(format!(
                "State number {} out of sequence (expected {})",
                state.state_number,
                previous_number + 1
            )));
        }

        if state.prev_state_hash != expected_prev_hash {
            return Err(IdentityError::GenesisError {
                context: format!("State {} has mismatched prev hash", state.state_number),
                step: "verify_trustless_identity".into(),
                internal_error: None,
            });
        }

        expected_prev_hash = state.compute_hash().map_err(IdentityError::from)?;
        previous_number = state.state_number;
    }

    Ok(())
}

/// Identity provider interface
pub trait IdentityProvider {
    /// Create a new identity
    fn create_identity(&self, device_id: &str, entropy: &[u8]) -> Result<Identity, DsmError>;

    /// Validate an identity
    fn validate_identity(&self, state: &State) -> Result<bool, DsmError>;

    /// Generate an invalidation marker
    fn generate_invalidation(&self, state: &State, reason: &str) -> Result<Vec<u8>, DsmError>;

    /// Verify an invalidation marker
    fn verify_invalidation(&self, state: &State, invalidation: &[u8]) -> Result<bool, DsmError>;
}

/// DeviceIdentity holds device-specific derived genesis and current state
#[derive(Debug, Clone)]
pub struct DeviceIdentity {
    pub device_id: [u8; 32],
    pub sub_genesis: GenesisState,
    pub current_state: Option<State>,
    pub sparse_indices: HashMap<u64, Vec<u8>>,
}

/// Identity root object
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Identity {
    pub name: String,
    pub master_genesis: GenesisState,
    pub devices: Vec<DeviceIdentity>,
    pub invalidated: bool,
}

impl Identity {
    /// Get the string representation of the identity ID
    pub fn id(&self) -> String {
        labeling::identity_to_string(self)
    }

    /// Construct an Identity from a provided genesis, with default fields initialized.
    pub fn with_genesis(name: String, master_genesis: GenesisState) -> Self {
        Self {
            name,
            master_genesis,
            devices: Vec::new(),
            invalidated: false,
        }
    }

    pub fn new() -> Result<Self, DsmError> {
        let genesis = GenesisState::new()?;
        Ok(Self {
            name: "new_identity".to_string(),
            master_genesis: genesis,
            devices: Vec::new(),
            invalidated: false,
        })
    }
    /// Apply a state transition to create a new state
    pub async fn apply_transition(
        &mut self,
        transition: crate::core::state_machine::transition::StateTransition,
    ) -> Result<State, DsmError> {
        // Get current state
        let current_state = self.get_current_state().await?;

        // Apply the transition using the state machine
        let new_state = crate::core::state_machine::transition::apply_transition(
            &current_state,
            &transition.operation,
            &transition.new_entropy.unwrap_or_default(),
        )?;

        // Per-Device SMT update belongs at the bilateral relationship level, not here.
        // The Per-Device SMT uses 256-bit relationship keys and lives in
        // merkle::sparse_merkle_tree::SparseMerkleTree.

        if let Some(device) = self.devices.first_mut() {
            device.current_state = Some(new_state.clone());
        }

        Ok(new_state)
    }

    /// Get the current state of this identity
    #[allow(clippy::unused_async)]
    pub async fn get_current_state(&self) -> Result<State, DsmError> {
        if let Some(device) = self.devices.first() {
            if let Some(current_state) = &device.current_state {
                Ok(current_state.clone())
            } else {
                // Create a basic genesis state if no current state exists
                let device_info = crate::types::state_types::DeviceInfo::new(
                    device.device_id,
                    self.master_genesis.signing_key.public_key.clone(),
                );
                Ok(State::new_genesis(
                    self.master_genesis.initial_entropy,
                    device_info,
                ))
            }
        } else {
            Err(DsmError::InvalidState(
                "No devices available for this identity".to_string(),
            ))
        }
    }

    /// Sign data using this identity's signing key (binary in/out, no encodings)
    #[allow(clippy::unused_async)]
    pub async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, DsmError> {
        crate::crypto::sphincs::sphincs_sign(&self.master_genesis.signing_key.secret_key, data)
    }

    /// Get a Merkle proof for the given key.
    ///
    /// NOTE: This previously used the embedded u64-index tree which has been removed.
    /// Inclusion proofs should come from the Per-Device SMT (SparseMerkleTree) using
    /// 256-bit relationship keys. Returns an error until migrated.
    // Callers should migrate to Per-Device SMT for inclusion proofs
    pub async fn get_proof(&self, _key: [u8; 32]) -> Result<MerkleProof, DsmError> {
        Err(DsmError::internal(
            "Identity::get_proof not yet migrated to Per-Device SMT",
            None::<String>,
        ))
    }

    pub fn genesis_hash(&self) -> blake3::Hash {
        domain_hash("DSM/genesis-hash", &self.master_genesis.hash)
    }
}
