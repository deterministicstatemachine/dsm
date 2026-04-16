//! Utility functions for the DSM state machine
//!
//! This module contains common utility functions used across the state machine
//! implementation, ensuring consistent behavior and reducing duplication.

use crate::types::error::DsmError;
use crate::types::state_types::State;
use blake3;

/// Perform constant-time equality comparison to prevent timing attacks
///
/// This function implements constant-time comparison for cryptographic values,
/// ensuring that timing information cannot be used to infer partial matches.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

/// Domain-separated BLAKE3 hash for general state machine operations.
///
/// Uses the `"DSM/state-hash"` domain tag per the whitepaper mandate that all
/// production hashing must be domain-separated: `BLAKE3("DSM/<domain>\0" || data)`.
pub fn hash_blake3(data: &[u8]) -> blake3::Hash {
    crate::crypto::blake3::domain_hash("DSM/state-hash", data)
}

/// Verify a state's hash integrity with constant-time comparison
///
/// This implements the cryptographic validation described in whitepaper Section 3.1.
pub fn verify_state_hash(state: &State) -> Result<bool, DsmError> {
    let computed_hash = state.hash()?;

    // Use constant-time comparison to prevent timing side-channel attacks
    if computed_hash.len() != state.hash.len() {
        return Ok(false);
    }

    Ok(constant_time_eq(&computed_hash, &state.hash))
}

/// Calculate the next entropy based on current entropy, operation, and state number
///
/// Implements the deterministic entropy evolution from whitepaper §11 eq. 14:
/// `e_{n+1} = H("DSM/next-entropy" || e_n || op || H(S_n))`. Per §4.3 no
/// counter participates — adjacency comes from the parent hash.
pub fn calculate_next_entropy(
    current_entropy: &[u8],
    operation_bytes: &[u8],
    parent_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = crate::crypto::blake3::dsm_domain_hasher("DSM/next-entropy");
    hasher.update(current_entropy);
    hasher.update(operation_bytes);
    hasher.update(parent_hash);

    *hasher.finalize().as_bytes()
}

// Add a utility function for creating test transitions

/// Create a test transition for testing purposes
#[cfg(test)]
pub fn create_test_transition() -> crate::core::state_machine::transition::StateTransition {
    use crate::core::state_machine::transition::StateTransition;
    use crate::crypto::sphincs::{generate_sphincs_keypair, sphincs_sign};
    use crate::types::operations::{Operation, TransactionMode, VerificationType};
    use crate::types::token_types::Balance;
    use std::collections::HashMap;

    let (_pk, sk) = generate_sphincs_keypair().expect("keypair");
    let mut op = Operation::Transfer {
        to_device_id: b"recipient".to_vec(),
        amount: Balance::from_state(10, [0u8; 32]),
        recipient: b"recipient".to_vec(),
        token_id: b"token1".to_vec(),
        to: b"recipient".to_vec(),
        message: "Test transfer".to_string(),
        mode: TransactionMode::Bilateral,
        nonce: vec![1, 2, 3, 4],
        verification: VerificationType::Standard,
        pre_commit: None,
        signature: Vec::new(),
    };

    let sig = sphincs_sign(&sk, &op.to_bytes()).expect("sign transfer");
    if let Operation::Transfer { signature, .. } = &mut op {
        *signature = sig.clone();
    }

    StateTransition {
        operation: op,
        new_entropy: Some(vec![4, 5, 6]),
        encapsulated_entropy: None,
        device_id: blake3::hash(b"test_device").into(),
        tick: 1_234_567_890,
        flags: vec![], // Protocol: no flags set for test state; production code must set as needed
        position_sequence: None,
        token_balances: Some(HashMap::new()),
        forward_commitment: None,
        proof_of_authorization: sig.clone(),
        prev_state_hash: Some([0; 32]),
        entity_signature: None,       // Default empty signature for tests
        counterparty_signature: None, // Default empty signature for tests
        signature: sig,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &[1, 2, 3]));
    }

    #[test]
    fn test_hash_blake3() {
        let data = b"test data";
        let hash = hash_blake3(data);

        // hash_blake3 uses domain_hash("DSM/state-hash", data) internally
        let expected = crate::crypto::blake3::domain_hash("DSM/state-hash", data);
        assert_eq!(hash.as_bytes(), expected.as_bytes());
    }

    #[test]
    fn test_calculate_next_entropy() {
        let current_entropy = vec![1, 2, 3];
        let operation_bytes = b"test_operation";
        let next_state_number = 42;

        let entropy1 = calculate_next_entropy(&current_entropy, operation_bytes, next_state_number);
        let entropy2 = calculate_next_entropy(&current_entropy, operation_bytes, next_state_number);

        // Entropy generation must be deterministic
        assert_eq!(entropy1, entropy2);

        // Different inputs should produce different entropy
        let different_entropy =
            calculate_next_entropy(&current_entropy, b"different", next_state_number);
        assert_ne!(entropy1, different_entropy);
    }
}
