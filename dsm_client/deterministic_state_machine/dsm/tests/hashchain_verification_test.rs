//! Test to verify that the hash chain implementation correctly follows the mathematical model
//! from the whitepaper, specifically the formula: S(n+1).prev_hash = H(S(n))

use dsm::core::state_machine::hashchain::HashChain;
use dsm::crypto::sphincs::generate_sphincs_keypair;
use dsm::types::error::DsmError;
use dsm::types::operations::Operation;
use dsm::types::state_types::{DeviceInfo, SparseIndex, State, StateParams};

#[test]
fn test_hash_chain_mathematical_model() -> Result<(), DsmError> {
    // Create a new hash chain
    let mut chain = HashChain::new();

    // Create a device info with real SPHINCS+ keypair for signature verification
    let (pk, _sk) =
        generate_sphincs_keypair().unwrap_or_else(|e| panic!("keypair generation failed: {e}"));
    let device_info = DeviceInfo::new(*blake3::hash(b"test_device").as_bytes(), pk);

    // Create a genesis state
    let mut entropy = [0u8; 32];
    entropy[0..3].copy_from_slice(&[1, 2, 3]);
    let mut genesis = State::new_genesis(entropy, device_info.clone());

    // Set ID
    genesis.id = "state_0".to_string();

    // Compute hash
    let genesis_hash = genesis.compute_hash()?;
    genesis.hash = genesis_hash;

    // Add genesis state to chain
    chain.add_state(genesis.clone())?;

    // Create 10 subsequent states to verify the mathematical model
    let mut prev_state = genesis;

    for i in 1..10 {
        // Calculate sparse indices including both genesis and direct predecessor
        let mut indices = State::calculate_sparse_indices(i)?;
        if !indices.contains(&(i - 1)) {
            indices.push(i - 1);
            indices.sort_unstable();
        }
        let sparse_index = SparseIndex::new(indices);

        // Use the proper StateParams::new constructor with 8 parameters, not 9
        let operation = Operation::Generic {
            operation_type: b"init".to_vec(),
            data: vec![],
            message: "".to_string(),
            signature: vec![],
        };

        let state_params = StateParams::new(
            i,      // state_number
            vec![], // entropy
            operation,
            device_info.clone(), // device_info
        )
        .with_encapsulated_entropy(vec![])
        .with_prev_state_hash(prev_state.hash)
        .with_sparse_index(sparse_index);

        // Initialize state
        let mut state = State::new(state_params);
        state.id = format!("state_{}", i);

        // Compute and set the hash
        let hash = state.compute_hash()?;
        state.hash = hash;

        // Verify S(n+1).prev_hash = H(S(n)) - this is the key mathematical formula from the whitepaper
        assert_eq!(
            state.prev_state_hash,
            prev_state.hash,
            "Mathematical model violation: S({}).prev_hash != H(S({}))",
            i,
            i - 1
        );

        // Add state to chain
        chain.add_state(state.clone())?;

        // Update prev_state for next iteration
        prev_state = state;
    }

    // Verify the entire chain
    let chain_valid = chain.verify_chain()?;
    assert!(chain_valid, "Chain verification failed");

    Ok(())
}
