//! State evolution and hash computation (whitepaper Sections 3.1 and 6).
//!
//! Implements forward-only state evolution with cryptographic binding.
//! All hashing is BLAKE3-only (no SHA3/SHAKE), uses internal constant-time
//! comparison for security-sensitive checks, and operates bytes-first
//! with no JSON/serde on the canonical path.

use crate::crypto::blake3::dsm_domain_hasher;
use crate::types::error::DsmError;
use crate::types::operations::Operation;
use crate::types::state_types::{DeviceInfo, SparseIndex, StateParams};

/// Constant-time equality for byte slices (no external crate)
#[inline]
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for i in 0..a.len() {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}

/// Represents a cryptographic state in the DSM system
#[derive(Debug, Clone)]
pub struct State {
    /// State identifier
    pub id: String,

    /// State number in sequence
    pub state_number: u64,

    /// State hash (raw bytes)
    pub hash: [u8; 32],

    /// Previous state hash (raw bytes)
    pub prev_state_hash: [u8; 32],

    /// State entropy (raw bytes)
    pub entropy: Vec<u8>,

    /// Encapsulated entropy from quantum-resistant KEM (raw bytes)
    pub encapsulated_entropy: Option<Vec<u8>>,

    /// Operation that produced this state
    pub operation: Operation,

    /// Device info
    pub device_info: DeviceInfo,

    /// Forward commitment for future states
    pub forward_commitment: Option<Vec<u8>>,

    /// Whether state matches forward commitment parameters
    pub matches_parameters: bool,

    /// Type of state
    pub state_type: String,

    /// State value (raw bytes)
    pub value: Vec<u8>,

    /// Commitment value (raw bytes)
    pub commitment: Vec<u8>,

    /// Sparse indexing for efficient traversal
    pub sparse_index: SparseIndex,
}

impl State {
    /// Create a new state
    pub fn new(params: StateParams) -> Self {
        Self {
            id: String::new(),
            state_number: params.state_number,
            hash: [0u8; 32],
            prev_state_hash: params.prev_state_hash,
            entropy: params.entropy,
            encapsulated_entropy: params.encapsulated_entropy,
            operation: params.operation,
            device_info: params.device_info,
            // Convert the PreCommitment to Vec<u8> if present
            forward_commitment: params.forward_commitment.map(|pc| pc.to_bytes()),
            matches_parameters: params.matches_parameters,
            state_type: params.state_type,
            value: params.value.into_iter().map(|i| i as u8).collect(),
            commitment: params.commitment.into_iter().map(|i| i as u8).collect(),
            sparse_index: params.sparse_index,
        }
    }

    /// Create a new genesis state
    pub fn new_genesis(entropy: [u8; 32], device_info: DeviceInfo) -> Self {
        Self {
            id: String::new(),
            state_number: 0,
            hash: [0u8; 32],
            prev_state_hash: [0u8; 32],
            entropy: entropy.to_vec(),
            encapsulated_entropy: None,
            operation: Operation::Genesis,
            device_info,
            forward_commitment: None,
            matches_parameters: false,
            state_type: "genesis".to_string(),
            value: Vec::new(),
            commitment: Vec::new(),
            sparse_index: SparseIndex::default(),
        }
    }

    /// Compute state hash (BLAKE3-only, domain-separated, bytes-first)
    pub fn compute_hash(&self) -> Result<Vec<u8>, DsmError> {
        // Canonical, deterministic encoding of fields included in the hash
        // NOTE: Keep the exact field set aligned with previous semantics.
        let mut h = dsm_domain_hasher("DSM/state-hash");
        h.update(&self.state_number.to_le_bytes());
        h.update(&self.prev_state_hash);
        h.update(&self.entropy);

        // Operation bytes (canonical, deterministic encoding; no serde/json)
        let operation_bytes = self.operation.to_bytes();
        h.update(&operation_bytes);

        // Device info bytes (canonical)
        let device_bytes = self.device_info.to_bytes();
        h.update(&device_bytes);

        Ok(h.finalize().as_bytes().to_vec()) // 32 bytes
    }

    /// Hash function for the state
    pub fn hash(&self) -> Result<Vec<u8>, DsmError> {
        self.compute_hash()
    }

    /// Calculate sparse indices for a state
    pub fn calculate_sparse_indices(state_number: u64) -> Result<Vec<u64>, DsmError> {
        if state_number == 0 {
            return Err(DsmError::invalid_parameter(
                "Genesis state (state_number == 0) should not have sparse indices",
            ));
        }

        let mut indices = Vec::new();

        // Always include previous state
        indices.push(state_number - 1);

        // Add exponentially spaced checkpoints
        let mut checkpoint = state_number;
        while checkpoint > 0 {
            checkpoint = checkpoint.saturating_sub(checkpoint.next_power_of_two() / 2);
            if checkpoint > 0 && checkpoint < state_number {
                indices.push(checkpoint);
            }
        }

        // Add genesis state if not already included
        if !indices.contains(&0) {
            indices.push(0);
        }

        Ok(indices)
    }

    /// Validate state integrity using BLAKE3-only verification
    ///
    /// Verifies the cryptographic integrity of a state according to whitepaper Section 14
    pub fn validate_state_integrity(state: &State) -> Result<bool, DsmError> {
        // For genesis states, validation is different
        if state.state_number == 0 {
            // Genesis states should have empty prev_state_hash
            if state.prev_state_hash != [0u8; 32] {
                return Ok(false);
            }

            // Verify hash integrity
            let computed_hash = state.compute_hash()?;
            return Ok(ct_eq(&computed_hash, &state.hash));
        }

        // Non-genesis states must have a non-empty prev_state_hash
        if state.prev_state_hash == [0u8; 32] {
            return Ok(false);
        }

        // Verify hash integrity
        let computed_hash = state.compute_hash()?;
        if !ct_eq(&computed_hash, &state.hash) {
            return Ok(false);
        }

        // For states with encapsulated entropy, verify it derives correctly
        if let Some(encapsulated) = &state.encapsulated_entropy {
            // Derive entropy using BLAKE3-only (domain-separated)
            let mut h = dsm_domain_hasher("DSM/encapsulated-entropy");
            h.update(encapsulated);
            let derived = h.finalize();

            // Compare with state entropy
            if !ct_eq(derived.as_bytes(), &state.entropy) {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Verify hash chain integrity between two consecutive states
    pub fn verify_hash_chain(prev_state: &State, next_state: &State) -> Result<bool, DsmError> {
        // Verify state numbers are sequential
        if next_state.state_number != prev_state.state_number + 1 {
            return Ok(false);
        }

        // Verify both states individually
        if !Self::validate_state_integrity(prev_state)?
            || !Self::validate_state_integrity(next_state)?
        {
            return Ok(false);
        }

        // Verify hash chain linkage
        let prev_hash = prev_state.compute_hash()?;
        Ok(ct_eq(&prev_hash, &next_state.prev_state_hash))
    }
}
