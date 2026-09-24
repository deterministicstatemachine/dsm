// SPDX-License-Identifier: MIT OR Apache-2.0

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

pub mod authority_resolver;
pub mod directory;
pub mod genesis;
pub mod genesis_session;
pub mod genesis_v2;
pub mod genesis_v3;
// hierarchical_device_management deleted: 1180-line module with zero external
// callers. Its own doc comment noted "DO NOT use this Merkle implementation for
// π_dev" — it's legacy superseded by crate::common::device_tree (§5 Device Tree)
// and the SMT-based DeviceState (§2.2).
// JNI bridge moved to dsm_sdk - see dsm_sdk/src/jni/unified_protobuf_bridge.rs

use std::collections::HashSet;

use crate::types::error::DsmError;
use crate::types::identifiers::NodeId;
use crate::prelude::*; // common items incl. Uuid, etc.
use crate::crypto::blake3::{dsm_domain_hasher, domain_hash};
use blake3;
use tracing;

// Import genesis-session types
use crate::core::identity::genesis_session::{create_genesis, GenesisSession};
// Re-export GenesisState for other modules
pub use crate::core::identity::genesis::{verify_genesis_state, GenesisState};

fn compute_contribution_merkle_root(contributions: &[genesis::Contribution]) -> Option<[u8; 32]> {
    if contributions.is_empty() {
        return None;
    }

    // Leaf = BLAKE3("DSM/GENESIS/CONTRIB/v2" || data)
    let mut leaves: Vec<[u8; 32]> = contributions
        .iter()
        .map(|c| {
            let mut h = dsm_domain_hasher(crate::crypto::domain::TaggedHashDomain::from_static(
                b"DSM/GENESIS/CONTRIB/v2",
            ));
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
            // Distinct sub-domain — this is the contribution Merkle tree,
            // not the whitepaper's genesis hash (`crate::tagged_domain!(b"DSM/genesis")`).
            let mut h = dsm_domain_hasher(crate::crypto::domain::TaggedHashDomain::from_static(
                b"DSM/genesis-merkle",
            ));
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
    // GenesisV2 is mnemonic-rooted; no DBRW/anti-cloning signal is required to
    // create or represent genesis / identity. Genesis must remain derivable and
    // recoverable from the wallet seed alone.

    if session.storage_nodes.len() < 3 {
        return Err(IdentityError::InvalidParameter(
            "MPC session must record ≥3 storage node participants (whitepaper §2.5)".into(),
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
///
/// Per whitepaper §2.5 the MPC is n-of-n commit-then-reveal — there is no
/// threshold cryptography.  All `storage_nodes` participate; the `≥3`
/// floor is enforced (per spec invariant; resists 2-collusion-only).
pub async fn create_trustless_genesis<
    S: crate::core::identity::genesis_session::GenesisStorage + Sync + Send,
>(
    device_id: String,
    storage_nodes: Vec<NodeId>,
    metadata: Option<String>,
    storage: Option<&S>,
) -> Result<TrustlessGenesisArtifacts, IdentityError> {
    let span = tracing::span!(
        tracing::Level::INFO,
        "MPC/genesis/create_trustless",
        device_id = %device_id,
        session_id = tracing::field::Empty,
        n_participants = storage_nodes.len()
    );
    let _enter = span.enter();

    if storage_nodes.len() < MIN_PARTICIPANTS {
        return Err(IdentityError::InvalidParameter(
            "MPC/participants/too_few: requires at least 3 storage nodes for trustless genesis (whitepaper §2.5)".into(),
        ));
    }

    // Deterministic 32B device hash label for MPC inputs
    let device_id_bytes: [u8; 32] = *domain_hash(
        crate::tagged_domain!(b"DSM/device-id"),
        device_id.as_bytes(),
    )
    .as_bytes();

    let session = create_genesis(
        device_id_bytes,
        storage_nodes,
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

    let device_id_bytes = domain_hash(
        crate::tagged_domain!(b"DSM/device-id"),
        device_id.as_bytes(),
    )
    .into();
    Ok(TrustlessGenesisArtifacts {
        device_id: device_id_bytes,
        genesis_state,
        session,
    })
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
    /// Sign data using this identity's signing key (binary in/out, no encodings)
    #[allow(clippy::unused_async)]
    pub async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, DsmError> {
        crate::crypto::sphincs::sphincs_sign(&self.master_genesis.signing_key.secret_key, data)
    }

    pub fn genesis_hash(&self) -> blake3::Hash {
        domain_hash(
            crate::tagged_domain!(b"DSM/genesis-hash"),
            &self.master_genesis.hash,
        )
    }
}
