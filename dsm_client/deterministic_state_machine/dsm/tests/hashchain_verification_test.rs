//! Test to verify that the hash chain implementation correctly follows the mathematical model
//! from the whitepaper, specifically the formula: S(n+1).prev_hash = H(S(n))

use dsm::core::state_machine::hashchain::HashChain;
use dsm::core::state_machine::hashchain::BatchStatus;
use dsm::crypto::sphincs::{generate_sphincs_keypair, sphincs_sign};
use dsm::types::error::DsmError;
use dsm::types::operations::Operation;
use dsm::types::state_types::{DeviceInfo, SparseIndex, State, StateParams};

#[test]
fn test_hash_chain_mathematical_model() -> Result<(), DsmError> {
    // Create a new hash chain
    let mut chain = HashChain::new();

    // Create a device info with real SPHINCS+ keypair for signature verification
    let (pk, sk) =
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

    // Test batch operations to verify they maintain mathematical constraints
    let batch_id = chain.create_batch()?;

    // Create a signed transition using the available constructors
    let mut operation = Operation::Generic {
        operation_type: b"batch_test".to_vec(),
        data: vec![],
        message: "Batch operation test".to_string(),
        signature: vec![],
    };
    let op_bytes = operation.to_bytes();
    let sig = sphincs_sign(&sk, &op_bytes).unwrap_or_else(|e| panic!("sign batch op failed: {e}"));
    if let Operation::Generic { signature, .. } = &mut operation {
        *signature = sig;
    }

    // Get the current state to use for transition
    let current_state = chain.get_latest_state()?;

    // Create a state transition by using the proper factory method with only 3 required arguments
    let transition = dsm::core::state_machine::transition::create_transition(
        current_state,
        operation,
        &[10, 11, 12], // new_entropy
    )?;

    // Add transition to batch
    let _transition_index = chain.add_transition_to_batch(batch_id, transition.clone())?;

    // Finalize and commit batch
    chain.finalize_batch(batch_id)?;
    chain.commit_batch(batch_id)?;

    // Verify chain is still valid after batch operations
    let chain_still_valid = chain.verify_chain()?;
    assert!(
        chain_still_valid,
        "Chain verification failed after batch operations"
    );

    // Verify that the batch status is committed
    let batch_status = chain.get_batch_status(batch_id)?;
    assert_eq!(
        batch_status,
        BatchStatus::Committed,
        "Batch should be in committed status"
    );
    Ok(())
}
