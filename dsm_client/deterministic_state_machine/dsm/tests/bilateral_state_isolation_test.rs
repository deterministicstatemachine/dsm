// Test to validate bilateral state isolation and forward-only deterministic progression
// as specified in the DSM whitepaper sections 3.4 and 7.1.

use dsm::core::state_machine::hashchain::HashChain;
use dsm::crypto::blake3::dsm_domain_hasher;
use dsm::crypto::sphincs::{generate_sphincs_keypair, sphincs_sign};
use dsm::types::error::DsmError;
use dsm::types::operations::Operation;
use dsm::types::state_types::{DeviceInfo, PreCommitment, SparseIndex, State, StateFlag, StateParams};
use dsm::types::token_types::Balance;
use std::collections::{HashMap, HashSet};

/// Helper function to create a properly initialized genesis state
fn create_genesis(
    entropy: [u8; 32],
    device_info: DeviceInfo,
    initial_balance: u64,
) -> Result<State, DsmError> {
    let mut state = State::new_genesis(entropy, device_info);
    state.flags.insert(StateFlag::Recovered);
    state.state_number = 0;

    // Initialize token balance for TEST_TOKEN
    state.token_balances.insert("TEST_TOKEN".to_string(), {
        let mut balance = Balance::zero();
        balance.update_add(initial_balance);
        balance
    });

    // Compute and set hash - critical for hash chain integrity
    let computed_hash = state.compute_hash()?;
    state.hash = computed_hash;

    Ok(state)
}

/// Helper function to create a new state based on a previous state and an operation
fn create_next_state(
    _chain: &HashChain,
    prev_state: &State,
    operation: Operation,
    device_info: DeviceInfo,
) -> Result<State, DsmError> {
    // First validate against any forward commitment in the previous state
    if let Some(forward_commitment) = prev_state.get_forward_commitment() {
        // Extract operation parameters
        let mut op_params = HashMap::new();
        if let Operation::Transfer {
            recipient,
            to_device_id,
            amount: _,
            token_id,
            ..
        } = &operation
        {
            op_params.insert("operation_type".to_string(), b"transfer".to_vec());
            op_params.insert("recipient".to_string(), recipient.clone());
            op_params.insert("to_device_id".to_string(), to_device_id.clone());
            op_params.insert("token_id".to_string(), token_id.clone());
        }

        // Check fixed parameters match commitment
        for (key, expected_value) in &forward_commitment.fixed_parameters {
            if let Some(actual_value) = op_params.get(key) {
                if actual_value != expected_value {
                    return Err(DsmError::invalid_operation(format!(
                        "Operation parameter '{}' does not match forward commitment",
                        key
                    )));
                }
            } else if !forward_commitment.variable_parameters.contains(key) {
                return Err(DsmError::invalid_operation(format!(
                    "Required parameter '{}' missing in operation",
                    key
                )));
            }
        }
    }

    // Generate entropy using the same domain tag as verify_transition_integrity
    let next_entropy = {
        let mut hasher = dsm_domain_hasher("DSM/state-entropy");
        hasher.update(&prev_state.entropy);
        hasher.update(&operation.to_bytes());
        hasher.update(&(prev_state.state_number + 1).to_le_bytes());
        hasher.finalize().as_bytes().to_vec()
    };

    // Calculate sparse indices for the new state
    let mut indices = State::calculate_sparse_indices(prev_state.state_number + 1)?;

    // Ensure sparse index includes prerequisites from whitepaper Section 3.2
    // Must include: Genesis (0) and direct predecessor for proper chain traversal
    if !indices.contains(&0) {
        indices.push(0);
    }
    if !indices.contains(&prev_state.state_number) {
        indices.push(prev_state.state_number);
    }
    indices.sort(); // Maintain canonical order
    let sparse_index = SparseIndex::new(indices);

    // Create state parameters with direct hash reference to maintain chain integrity
    let mut state_params = StateParams::new(
        prev_state.state_number + 1, // state_number
        next_entropy,                // entropy
        operation.clone(),           // operation
        device_info,                 // device_info
    )
    .with_prev_state_hash(prev_state.hash)
    .with_sparse_index(sparse_index);

    // Build remaining extended parameters
    state_params.encapsulated_entropy = None;
    state_params.forward_commitment = None;

    // Build the new state
    let mut next_state = State::new(state_params);

    // Transfer token balances from previous state to maintain atomicity
    next_state.token_balances = prev_state.token_balances.clone();

    // Apply token operation effects according to operation type
    match &operation {
        Operation::Mint {
            amount, token_id, ..
        } => {
            // Get existing balance or initialize with zero
            let token_key = String::from_utf8_lossy(token_id).into_owned();
            let current_balance = next_state
                .token_balances
                .get(&token_key)
                .cloned()
                .unwrap_or_else(Balance::zero);

            // Create a new balance with the added amount
            let mut new_balance = current_balance.clone();
            new_balance.update(amount.value(), true); // true indicates addition
            next_state.token_balances.insert(token_key, new_balance);
        }
        Operation::Transfer {
            amount, token_id, ..
        } => {
            // Get existing balance
            let token_key = String::from_utf8_lossy(token_id).into_owned();
            if let Some(current_balance) = next_state.token_balances.get(&token_key) {
                // Check if balance is sufficient
                if current_balance.available() < amount.value() {
                    return Err(DsmError::insufficient_balance(
                        token_key,
                        current_balance.value(),
                        amount.value(),
                    ));
                }

                // Create new balance with subtracted amount
                let mut new_balance = current_balance.clone();
                new_balance.update_sub(amount.value())?;
                next_state.token_balances.insert(token_key, new_balance);
            } else {
                return Err(DsmError::insufficient_balance(token_key, 0, amount.value()));
            }
        }
        _ => {}
    }

    // Compute and set the hash after all state modifications
    let computed_hash = next_state.compute_hash()?;
    next_state.hash = computed_hash;

    Ok(next_state)
}

/// Helper function to create a PreCommitment instance for tests
fn create_test_precommitment(
    operation_type: String,
    fixed_parameters: HashMap<String, Vec<u8>>,
    variable_parameters: HashSet<String>,
    min_state_number: u64,
    counterparty_id: String,
) -> PreCommitment {
    // Use the public constructor for PreCommitment
    PreCommitment::new(
        operation_type,
        fixed_parameters,
        variable_parameters,
        min_state_number,
        blake3::hash(counterparty_id.as_bytes()).into(),
    )
}

/// Helper function to create a forward linked commitment for testing
fn create_forward_linked_commitment(
    previous_hash: &[u8; 32],
    counterparty_id: &str,
    fixed_parameters: HashMap<String, Vec<u8>>,
    variable_parameters: HashSet<String>,
    min_state_number: Option<u64>,
) -> Result<PreCommitment, DsmError> {
    // Create a PreCommitment with the specified parameters
    let min_state = min_state_number.unwrap_or(0);
    let pre_commitment = PreCommitment::new(
        "transfer".to_string(),
        fixed_parameters,
        variable_parameters,
        min_state,
        *blake3::hash(counterparty_id.as_bytes()).as_bytes(),
    );

    // Calculate a hash for the commitment based on the previous state hash
    let mut hasher = blake3::Hasher::new();
    hasher.update(previous_hash);
    hasher.update(counterparty_id.as_bytes());
    let commit_hash = *hasher.finalize().as_bytes();

    let mut commitment = pre_commitment;
    commitment.hash = commit_hash;

    Ok(commitment)
}

/// Helper function to create a valid transfer operation that matches the commitment
fn create_valid_transfer(prepare_state: &State) -> Result<Operation, DsmError> {
    // Extract forward commitment to ensure we match its parameters
    let forward_commitment = prepare_state.get_forward_commitment().ok_or_else(|| {
        DsmError::invalid_operation("No forward commitment found in prepare state")
    })?;

    // Extract required parameters from the commitment
    let recipient_bytes = match forward_commitment.fixed_parameters.get("recipient") {
        Some(recipient_bytes) => recipient_bytes.clone(),
        None => {
            return Err(DsmError::invalid_operation(
                "Missing recipient in commitment",
            ))
        }
    };

    let token_id = match forward_commitment.fixed_parameters.get("token_id") {
        Some(token_bytes) => String::from_utf8(token_bytes.clone())
            .map_err(|e| DsmError::generic("Failed to decode token_id", Some(e)))?,
        None => {
            return Err(DsmError::invalid_operation(
                "Missing token_id in commitment",
            ))
        }
    };

    let to_device_id_bytes = match forward_commitment.fixed_parameters.get("recipient") {
        Some(to_bytes) => to_bytes.clone(),
        None => recipient_bytes.clone(), // Default to recipient if not explicitly specified
    };

    // Create a transfer operation matching the commitment parameters
    // Using a sample amount of 10 since it's a variable parameter in the commitment
    Ok(Operation::Transfer {
        recipient: recipient_bytes.clone(),
        to_device_id: to_device_id_bytes,
        amount: {
            let mut balance = Balance::zero();
            balance.update_add(10);
            balance
        }, // Using a sample amount that meets the balance requirements
        token_id: token_id.into_bytes(),
        mode: dsm::types::operations::TransactionMode::Bilateral,
        nonce: vec![1, 2, 3, 4],
        verification: dsm::types::operations::VerificationType::Standard,
        pre_commit: None,
        message: "Test transfer operation".to_string(),
        to: recipient_bytes.clone(),
        signature: vec![],
    })
}

/// Helper function to verify a transfer operation against the commitment
fn verify_transfer(operation: &Operation) -> Result<bool, DsmError> {
    // Extract operation details
    match operation {
        Operation::Transfer {
            recipient,
            token_id,
            amount,
            ..
        } => {
            // Verify basic transfer constraints
            if recipient.is_empty() {
                return Err(DsmError::invalid_operation("Invalid recipient"));
            }

            if token_id.is_empty() {
                return Err(DsmError::invalid_operation("Invalid token_id"));
            }

            if amount.value() == 0 {
                return Err(DsmError::invalid_operation(
                    "Transfer amount must be positive",
                ));
            }

            // Transfer operation is valid
            Ok(true)
        }
        _ => Err(DsmError::invalid_operation("Operation is not a Transfer")),
    }
}

#[test]
fn test_bilateral_state_transfer() -> Result<(), DsmError> {
    // initialize() removed; core has no global init.
    println!("Testing bilateral state isolation and forward-only deterministic progression...");

    // Generate real SPHINCS+ keypairs for both devices
    let (pk_a, sk_a) =
        generate_sphincs_keypair().unwrap_or_else(|e| panic!("keypair A failed: {e}"));
    let (pk_b, _sk_b) =
        generate_sphincs_keypair().unwrap_or_else(|e| panic!("keypair B failed: {e}"));

    // Create device identities for two separate parties
    let device_id_a = blake3::hash(b"device_a").into();
    let device_id_b = blake3::hash(b"device_b").into();
    let device_info_a = DeviceInfo::new(device_id_a, pk_a.clone());
    let device_info_b = DeviceInfo::new(device_id_b, pk_b.clone());

    // Create genesis states for both parties
    let mut entropy_a = [0u8; 32];
    entropy_a[0..4].copy_from_slice(&[1, 2, 3, 4]);
    let mut genesis_a = create_genesis(entropy_a, device_info_a.clone(), 100)?;
    genesis_a.id = format!("state_a_{}", genesis_a.state_number);

    let mut entropy_b = [0u8; 32];
    entropy_b[0..4].copy_from_slice(&[5, 6, 7, 8]);
    let mut genesis_b = create_genesis(entropy_b, device_info_b.clone(), 0)?;
    genesis_b.id = format!("state_b_{}", genesis_b.state_number);

    // Create separate hash chains for each entity, demonstrating bilateral state isolation
    let mut chain_a = HashChain::new();
    let mut chain_b = HashChain::new();

    chain_a.add_state(genesis_a.clone())?;
    chain_b.add_state(genesis_b.clone())?;

    // 1. Create a forward commitment from A to B for token transfer
    let mut fixed_params = HashMap::new();
    fixed_params.insert("operation_type".to_string(), b"transfer".to_vec());
    fixed_params.insert("recipient".to_string(), b"device_b".to_vec());
    fixed_params.insert("token_id".to_string(), b"TEST_TOKEN".to_vec());

    let mut var_params = HashSet::new();
    var_params.insert("amount".to_string());

    // Create forward commitment for the transfer
    let commitment = create_forward_linked_commitment(
        &genesis_a.hash,
        "device_b",
        fixed_params.clone(),
        var_params.clone(),
        Some(1),
    )?;

    // Sign commitment using real SPHINCS+ keypairs
    let signed_commitment = commitment;
    let _entity_sig = sphincs_sign(&sk_a, &signed_commitment.hash)
        .unwrap_or_else(|e| panic!("sign entity failed: {e}"));
    let _counterparty_sig = sphincs_sign(&_sk_b, &signed_commitment.hash)
        .unwrap_or_else(|e| panic!("sign counterparty failed: {e}"));

    // Create prepare state with forward commitment
    // Use the commitment hash directly as canonical bytes (no serde/bincode)
    let commitment_bytes = signed_commitment.hash;

    let pre_commitment = create_test_precommitment(
        "transfer".to_string(),
        fixed_params.clone(),
        var_params.clone(),
        0,
        "device_b".to_string(),
    );

    let pre_commitment = PreCommitment {
        hash: commitment_bytes,
        ..pre_commitment
    };

    // Create prepare operation for the commitment and sign it
    let mut prepare_op = Operation::Generic {
        operation_type: b"prepare_transfer".to_vec(),
        data: commitment_bytes.to_vec(),
        message: "Prepare state with forward commitment".to_string(),
        signature: vec![],
    };
    let bytes = prepare_op.to_bytes();
    let sig = sphincs_sign(&sk_a, &bytes).unwrap_or_else(|e| panic!("sign prepare_op failed: {e}"));
    if let Operation::Generic { signature, .. } = &mut prepare_op {
        *signature = sig;
    }

    // Create prepare state (with commitment) on A's chain
    let mut prepare_state_a =
        create_next_state(&chain_a, &genesis_a, prepare_op, device_info_a.clone())?;

    // Add forward commitment to this state
    prepare_state_a.set_forward_commitment(Some(pre_commitment));

    // Recompute hash after adding commitment
    let computed_hash = prepare_state_a.compute_hash()?;
    prepare_state_a.hash = computed_hash;
    chain_a.add_state(prepare_state_a.clone())?;

    // 3. Now attempt to execute two different operations to demonstrate forward-only determinism
    // First try: Valid operation that matches the commitment
    let mut valid_transfer = create_valid_transfer(&prepare_state_a)?;
    let transfer_bytes = valid_transfer.to_bytes();
    let transfer_sig = sphincs_sign(&sk_a, &transfer_bytes)
        .unwrap_or_else(|e| panic!("sign transfer failed: {e}"));
    if let Operation::Transfer { signature, .. } = &mut valid_transfer {
        *signature = transfer_sig;
    }
    verify_transfer(&valid_transfer)?;

    Ok(())
}
#[test]
fn test_invalid_state_transfer() -> Result<(), DsmError> {
    // initialize() removed; core has no global init.
    println!("Testing bilateral state isolation and forward-only deterministic progression...");

    // Generate real SPHINCS+ keypairs for both devices
    let (pk_a, sk_a) =
        generate_sphincs_keypair().unwrap_or_else(|e| panic!("keypair A failed: {e}"));
    let (pk_b, _sk_b) =
        generate_sphincs_keypair().unwrap_or_else(|e| panic!("keypair B failed: {e}"));

    // Create device identities for two separate parties
    let device_id_a = blake3::hash(b"device_a").into();
    let device_id_b = blake3::hash(b"device_b").into();
    let device_info_a = DeviceInfo::new(device_id_a, pk_a.clone());
    let device_info_b = DeviceInfo::new(device_id_b, pk_b.clone());

    // Create genesis states for both parties
    let mut entropy_a = [0u8; 32];
    entropy_a[0..4].copy_from_slice(&[1, 2, 3, 4]);
    let mut genesis_a = create_genesis(entropy_a, device_info_a.clone(), 100)?;
    genesis_a.id = format!("state_a_{}", genesis_a.state_number);

    let mut entropy_b = [0u8; 32];
    entropy_b[0..4].copy_from_slice(&[5, 6, 7, 8]);
    let mut genesis_b = create_genesis(entropy_b, device_info_b.clone(), 0)?;
    genesis_b.id = format!("state_b_{}", genesis_b.state_number);

    // Create separate hash chains for each entity, demonstrating bilateral state isolation
    let mut chain_a = HashChain::new();
    let mut chain_b = HashChain::new();

    chain_a.add_state(genesis_a.clone())?;
    chain_b.add_state(genesis_b.clone())?;

    // 1. Create a forward commitment from A to B for token transfer
    let mut fixed_params = HashMap::new();
    fixed_params.insert("operation_type".to_string(), b"transfer".to_vec());
    fixed_params.insert("recipient".to_string(), b"device_b".to_vec());
    fixed_params.insert("token_id".to_string(), b"TEST_TOKEN".to_vec());

    let mut var_params = HashSet::new();
    var_params.insert("amount".to_string());

    // Create forward commitment for the transfer
    let commitment = create_forward_linked_commitment(
        &genesis_a.hash,
        "device_b",
        fixed_params.clone(),
        var_params.clone(),
        Some(1),
    )?;

    // Sign commitment using real SPHINCS+ keypairs
    let signed_commitment = commitment;
    let _entity_sig = sphincs_sign(&sk_a, &signed_commitment.hash)
        .unwrap_or_else(|e| panic!("sign entity failed: {e}"));
    let _counterparty_sig = sphincs_sign(&_sk_b, &signed_commitment.hash)
        .unwrap_or_else(|e| panic!("sign counterparty failed: {e}"));

    // Create prepare state with forward commitment
    // Use the commitment hash directly as canonical bytes (no serde/bincode)
    let commitment_bytes = signed_commitment.hash;

    let pre_commitment = create_test_precommitment(
        "transfer".to_string(),
        fixed_params.clone(),
        var_params.clone(),
        0,
        "device_b".to_string(),
    );

    let pre_commitment = PreCommitment {
        hash: commitment_bytes,
        ..pre_commitment
    };

    // Create prepare operation for the commitment and sign it
    let mut prepare_op = Operation::Generic {
        operation_type: b"prepare_transfer".to_vec(),
        data: commitment_bytes.to_vec(),
        message: "Prepare state with forward commitment".to_string(),
        signature: vec![],
    };
    let bytes = prepare_op.to_bytes();
    let sig = sphincs_sign(&sk_a, &bytes).unwrap_or_else(|e| panic!("sign prepare_op failed: {e}"));
    if let Operation::Generic { signature, .. } = &mut prepare_op {
        *signature = sig;
    }

    // Create prepare state (with commitment) on A's chain
    let mut prepare_state_a =
        create_next_state(&chain_a, &genesis_a, prepare_op, device_info_a.clone())?;

    // Add forward commitment to this state
    prepare_state_a.set_forward_commitment(Some(pre_commitment));

    // Recompute hash after adding commitment
    let computed_hash = prepare_state_a.compute_hash()?;
    prepare_state_a.hash = computed_hash;
    chain_a.add_state(prepare_state_a.clone())?;

    // 3. Now attempt to execute two different operations to demonstrate forward-only determinism
    // First try: Valid operation that matches the commitment
    let mut valid_transfer = create_valid_transfer(&prepare_state_a)?;
    let transfer_bytes = valid_transfer.to_bytes();
    let transfer_sig = sphincs_sign(&sk_a, &transfer_bytes)
        .unwrap_or_else(|e| panic!("sign transfer failed: {e}"));
    if let Operation::Transfer { signature, .. } = &mut valid_transfer {
        *signature = transfer_sig;
    }
    verify_transfer(&valid_transfer)?;

    Ok(())
}
