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

/// Represents a cryptographic state in the DSM system.
///
/// Per §4.3 no counter is included — state identity comes from
/// `prev_state_hash` adjacency (§2.1 eq. 1) and per-transition entropy.
#[derive(Debug, Clone)]
pub struct State {
    /// State identifier
    pub id: String,

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

    /// Compute state hash (BLAKE3-only, domain-separated, bytes-first).
    /// Per §4.3 no counter participates in the canonical hash.
    pub fn compute_hash(&self) -> Result<Vec<u8>, DsmError> {
        let mut h = dsm_domain_hasher("DSM/state-hash");
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

    /// Validate state integrity using BLAKE3-only verification.
    ///
    /// Per §4.3 no counter is checked — genesis is identified purely by
    /// `prev_state_hash == [0u8; 32]`.
    pub fn validate_state_integrity(state: &State) -> Result<bool, DsmError> {
        // Genesis: zero parent hash → hash-only check
        if state.prev_state_hash == [0u8; 32] {
            let computed_hash = state.compute_hash()?;
            return Ok(ct_eq(&computed_hash, &state.hash));
        }

        // Non-genesis: verify hash integrity
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

    /// Verify hash chain integrity between two consecutive states.
    /// Per §4.3 no counter comparison — only hash-adjacency and self-integrity.
    pub fn verify_hash_chain(prev_state: &State, next_state: &State) -> Result<bool, DsmError> {
        // Verify both states individually
        if !Self::validate_state_integrity(prev_state)?
            || !Self::validate_state_integrity(next_state)?
        {
            return Ok(false);
        }

        // Verify hash chain linkage (§2.1 eq. 1)
        let prev_hash = prev_state.compute_hash()?;
        Ok(ct_eq(&prev_hash, &next_state.prev_state_hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::operations::Operation;
    use crate::types::state_types::{DeviceInfo, StateParams};

    fn test_device_info() -> DeviceInfo {
        DeviceInfo::new([0x11; 32], vec![0x22; 64])
    }

    fn test_entropy() -> Vec<u8> {
        (1..=32).collect()
    }

    fn test_entropy_array() -> [u8; 32] {
        let mut arr = [0u8; 32];
        for (i, byte) in arr.iter_mut().enumerate() {
            *byte = (i + 1) as u8;
        }
        arr
    }

    fn finalize_hash(state: &mut State) {
        let computed = state.compute_hash().unwrap();
        let mut h = [0u8; 32];
        h.copy_from_slice(&computed);
        state.hash = h;
    }

    // ---- ct_eq ----

    #[test]
    fn ct_eq_equal_slices_returns_true() {
        assert!(ct_eq(&[1, 2, 3, 4, 5], &[1, 2, 3, 4, 5]));
    }

    #[test]
    fn ct_eq_different_slices_returns_false() {
        assert!(!ct_eq(&[1, 2, 3, 4, 5], &[1, 2, 3, 4, 6]));
    }

    #[test]
    fn ct_eq_different_lengths_returns_false() {
        assert!(!ct_eq(&[1, 2, 3], &[1, 2, 3, 4]));
    }

    #[test]
    fn ct_eq_empty_slices_returns_true() {
        assert!(ct_eq(&[], &[]));
    }

    #[test]
    fn ct_eq_single_bit_difference_returns_false() {
        assert!(!ct_eq(&[0b1111_1111], &[0b1111_1110]));
    }

    // ---- State::new ----

    #[test]
    fn new_state_has_zero_hash() {
        let params = StateParams::new( test_entropy(), Operation::Noop, test_device_info());
        let state = State::new(params);
        assert_eq!(state.hash, [0u8; 32]);
    }

    #[test]
    fn new_state_preserves_entropy() {
        let entropy = test_entropy();
        let params = StateParams::new( entropy.clone(), Operation::Noop, test_device_info());
        let state = State::new(params);
        assert_eq!(state.entropy, entropy);
    }

    #[test]
    fn new_state_preserves_prev_hash() {
        let prev_hash = [0xAA; 32];
        let params = StateParams::new( test_entropy(), Operation::Noop, test_device_info())
            .with_prev_state_hash(prev_hash);
        let state = State::new(params);
        assert_eq!(state.prev_state_hash, prev_hash);
    }

    #[test]
    fn new_state_preserves_operation() {
        let params = StateParams::new( test_entropy(), Operation::Genesis, test_device_info());
        let state = State::new(params);
        assert!(matches!(state.operation, Operation::Genesis));
    }

    // ---- State::new_genesis ----

    #[test]
    fn genesis_state_has_zero_prev_hash() {
        let state = State::new_genesis(test_entropy_array(), test_device_info());
        assert_eq!(state.prev_state_hash, [0u8; 32]);
    }

    #[test]
    fn genesis_state_has_correct_entropy() {
        let entropy = test_entropy_array();
        let state = State::new_genesis(entropy, test_device_info());
        assert_eq!(state.entropy, entropy.to_vec());
    }

    #[test]
    fn genesis_state_has_genesis_operation() {
        let state = State::new_genesis(test_entropy_array(), test_device_info());
        assert!(matches!(state.operation, Operation::Genesis));
    }

    #[test]
    fn genesis_state_has_no_forward_commitment() {
        let state = State::new_genesis(test_entropy_array(), test_device_info());
        assert!(state.forward_commitment.is_none());
    }

    // ---- State::compute_hash ----

    #[test]
    fn compute_hash_is_deterministic() {
        let s1 = State::new(StateParams::new(
            test_entropy(),
            Operation::Noop,
            test_device_info(),
        ));
        let s2 = State::new(StateParams::new(
            test_entropy(),
            Operation::Noop,
            test_device_info(),
        ));
        assert_eq!(s1.compute_hash().unwrap(), s2.compute_hash().unwrap());
    }

    #[test]
    fn compute_hash_returns_32_bytes() {
        let state = State::new_genesis(test_entropy_array(), test_device_info());
        assert_eq!(state.compute_hash().unwrap().len(), 32);
    }

    #[test]
    fn compute_hash_different_entropy_yields_different_hash() {
        let s1 = State::new(StateParams::new(
            vec![1, 2, 3],
            Operation::Noop,
            test_device_info(),
        ));
        let s2 = State::new(StateParams::new(
            vec![4, 5, 6],
            Operation::Noop,
            test_device_info(),
        ));
        assert_ne!(s1.compute_hash().unwrap(), s2.compute_hash().unwrap());
    }

    // Counter-based hash-distinction tests were removed per §4.3 — state
    // identity now comes from `prev_state_hash` + entropy, not a counter.

    // ---- State::hash ----

    #[test]
    fn hash_returns_same_as_compute_hash() {
        let state = State::new_genesis(test_entropy_array(), test_device_info());
        assert_eq!(state.hash().unwrap(), state.compute_hash().unwrap());
    }

    #[test]
    fn hash_always_computes_fresh_value() {
        let mut state = State::new_genesis(test_entropy_array(), test_device_info());
        state.hash = [0xFF; 32];
        let result = state.hash().unwrap();
        let computed = state.compute_hash().unwrap();
        assert_eq!(result, computed);
    }

    // Sparse index tests removed — sparse indexing is advisory-only per §2.2
    // and no longer lives on the core State type.

    // ---- State::validate_state_integrity ----

    #[test]
    fn validate_genesis_with_matching_hash_is_valid() {
        let mut state = State::new_genesis(test_entropy_array(), test_device_info());
        finalize_hash(&mut state);
        assert!(State::validate_state_integrity(&state).unwrap());
    }

    #[test]
    fn validate_genesis_with_nonzero_prev_hash_is_invalid() {
        let mut state = State::new_genesis(test_entropy_array(), test_device_info());
        finalize_hash(&mut state);
        state.prev_state_hash = [0xFF; 32];
        assert!(!State::validate_state_integrity(&state).unwrap());
    }

    // validate_nongenesis_with_zero_prev_hash test removed — genesis is now
    // identified by prev_state_hash == [0u8; 32] (§4.3), not by counter.
    // A state with zero parent hash IS genesis by definition.

    #[test]
    fn validate_nongenesis_with_correct_hash_is_valid() {
        let prev_hash = [0xBB; 32];
        let params = StateParams::new( test_entropy(), Operation::Noop, test_device_info())
            .with_prev_state_hash(prev_hash);
        let mut state = State::new(params);
        finalize_hash(&mut state);
        assert!(State::validate_state_integrity(&state).unwrap());
    }

    #[test]
    fn validate_state_with_mismatched_hash_is_invalid() {
        let prev_hash = [0xBB; 32];
        let params = StateParams::new( test_entropy(), Operation::Noop, test_device_info())
            .with_prev_state_hash(prev_hash);
        let mut state = State::new(params);
        state.hash = [0xCC; 32];
        assert!(!State::validate_state_integrity(&state).unwrap());
    }

    // ---- State::verify_hash_chain ----

    #[test]
    fn verify_hash_chain_valid_sequential_states() {
        let mut genesis = State::new_genesis(test_entropy_array(), test_device_info());
        finalize_hash(&mut genesis);

        let mut prev_hash = [0u8; 32];
        prev_hash.copy_from_slice(&genesis.compute_hash().unwrap());

        let params = StateParams::new( vec![99; 16], Operation::Noop, test_device_info())
            .with_prev_state_hash(prev_hash);
        let mut next = State::new(params);
        finalize_hash(&mut next);

        assert!(State::verify_hash_chain(&genesis, &next).unwrap());
    }

    #[test]
    fn verify_hash_chain_broken_linkage_is_invalid() {
        let mut genesis = State::new_genesis(test_entropy_array(), test_device_info());
        finalize_hash(&mut genesis);

        let wrong_prev = [0xDD; 32];
        let params = StateParams::new( vec![99; 16], Operation::Noop, test_device_info())
            .with_prev_state_hash(wrong_prev);
        let mut next = State::new(params);
        finalize_hash(&mut next);

        assert!(!State::verify_hash_chain(&genesis, &next).unwrap());
    }
}
