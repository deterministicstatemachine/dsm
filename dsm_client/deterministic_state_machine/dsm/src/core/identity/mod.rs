//! Identity Module
//!
//! This module handles all aspects of identity management in DSM, including:
//! - Secure genesis state creation
//! - Hierarchical device-specific sub-identities
//! - Device management and invalidation
//! - Cross-device identity verification
//!
//! # DSM Core Identity Policy
//!
//! Per whitepaper §2.5, genesis MPC is n-of-n commit-then-reveal — there is
//! no threshold cryptography.  The `b_1, ..., b_n` notation in the spec is
//! mathematical index notation for "all n contributions"; not a t-of-n DKG.
//! DSM core enforces ≥3 storage nodes (anti-collusion floor); no alternate-
//! path entropy; storage is trait-only.

// DSM Protocol Security Invariants - Compile-time enforced
pub const MIN_PARTICIPANTS: usize = 3;

// Compile-time assertion to prevent regression.
const _: () = assert!(
    MIN_PARTICIPANTS >= 3,
    "MPC security requires at least 3 participants (n-of-n commit-then-reveal)"
);

pub mod genesis;
pub mod genesis_mpc;
// hierarchical_device_management deleted: 1180-line module with zero external
// callers. Its own doc comment noted "DO NOT use this Merkle implementation for
// π_dev" — it's legacy superseded by crate::common::device_tree (§5 Device Tree)
// and the SMT-based DeviceState (§2.2).
// JNI bridge moved to dsm_sdk - see dsm_sdk/src/jni/unified_protobuf_bridge.rs

use crate::types::state_types::MerkleProof;

use crate::types::error::DsmError;
use crate::prelude::*; // common items incl. Uuid, etc.
use crate::crypto::blake3::domain_hash;
use blake3;

// Re-export GenesisState for other modules
pub use crate::core::identity::genesis::{verify_genesis_state, GenesisState};

// `convert_session_to_genesis_state`, `sanitize_genesis_state`,
// `compute_contribution_merkle_root`,
// `create_trustless_genesis`, `TrustlessGenesisArtifacts`,
// `GenesisCreationResult`, and the `IdentityStore` helper struct
// have been removed (zero external callers; verified by repo-wide
// grep). The canonical production path for genesis creation is
// `dsm::core::identity::genesis_mpc::create_root_genesis_mpc` invoked
// directly from `dsm_sdk::sdk::identity_sdk::IdentitySDK::create_genesis`
// with a real `HttpGenesisMpcTransport`. Per zero-legacy discipline
// these wrappers were not preserved (they wrapped the deleted
// `create_mpc_genesis` placeholder).

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

// verify_trustless_identity deleted: zero callers, and the body was full
// of `state.hash[0] as u64` fake state_number reads (residue from §4.3
// state_number deletion). Verifying a chain of legacy State objects no
// longer maps to anything meaningful — chain integrity now flows through
// the per-relationship SMT in DeviceState, not through array walks of
// monolithic State.

// IdentityProvider trait deleted: zero implementers anywhere. Each method
// took &State (validate_identity, generate_invalidation, verify_invalidation)
// and the create_identity/state-shape contract is obsolete in the §2.2 model.

/// DeviceIdentity holds device-specific derived genesis.
///
/// `current_state` and `sparse_indices` fields removed: the former was only
/// touched by `Identity::apply_transition` / `get_current_state` (both deleted,
/// zero callers) and the latter was never read after construction. Per §2.2,
/// canonical per-device state lives in `DeviceState` (SMT root + balances +
/// per-relationship tips), not in this identity-management struct.
#[derive(Debug, Clone)]
pub struct DeviceIdentity {
    pub device_id: [u8; 32],
    pub sub_genesis: GenesisState,
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

fn canonical_identity_id(genesis_hash: &[u8; 32]) -> String {
    let mut hi = [0u8; 16];
    hi.copy_from_slice(&genesis_hash[..16]);
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&genesis_hash[16..]);
    format!(
        "genesis:{}:{}",
        u128::from_be_bytes(hi),
        u128::from_be_bytes(lo)
    )
}

impl Identity {
    /// Get the canonical string representation of the exact master genesis hash.
    pub fn id(&self) -> String {
        canonical_identity_id(&self.master_genesis.hash)
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
    // Identity::apply_transition + Identity::get_current_state deleted: zero
    // external callers. Both took/returned monolithic State and routed through
    // the legacy state_machine::transition::apply_transition path. The §2.2
    // canonical transition path is StateMachine::advance_relationship which
    // operates on DeviceState (SMT root + per-relationship tips), not on the
    // Identity struct's first device's current_state field.

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
