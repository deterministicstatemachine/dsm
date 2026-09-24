#![allow(clippy::disallowed_methods)]
// Integration test for commitment verification; unwrap/expect usage is acceptable here.
use dsm::commitments::smart_commitment::{CommitmentCondition, CommitmentContext, SmartCommitment};
use dsm::commitments::smart_commitment::ThresholdOperator;
use dsm::types::operations::Operation;
use dsm::types::state_types::{DeviceInfo, State};

#[test]
fn test_precommitment_integrity() {
    // Establish a genesis state
    let device_id = blake3::hash(b"test_device").into();
    let device_info = DeviceInfo::new(device_id, vec![1, 2, 3, 4]);
    let mut entropy = [0u8; 32];
    entropy[0..3].copy_from_slice(&[1, 2, 3]);
    let state = State::new_genesis(entropy, device_info);

    // Create a next operation
    let next_operation = Operation::Generic {
        operation_type: b"test".to_vec(),
        data: vec![4, 5, 6],
        message: "Generic operation: test".to_string(),
        signature: vec![],
    };

    let condition = CommitmentCondition::ValueThreshold {
        parameter_name: "balance".into(),
        threshold: 1,
        operator: ThresholdOperator::GreaterThanOrEqual,
    };
    let precommitment = SmartCommitment::new(
        "test_precommitment",
        &state.hash,
        &state.entropy,
        condition.clone(),
        next_operation.clone(),
    )
    .unwrap();

    // It verifies against the origin it was made from, and only against it.
    assert!(precommitment.verify_against_origin(&state.entropy).unwrap());
    assert!(!precommitment.verify_against_origin(&[9u8; 32]).unwrap());

    // It commits its operation: the same condition over another operation is
    // another commitment.
    let other = SmartCommitment::new(
        "test_precommitment",
        &state.hash,
        &state.entropy,
        condition,
        Operation::Generic {
            operation_type: b"test".to_vec(),
            data: vec![4, 5, 7],
            message: "Generic operation: test".to_string(),
            signature: vec![],
        },
    )
    .unwrap();
    assert_ne!(precommitment.commitment_hash, other.commitment_hash);
    let again = SmartCommitment::new(
        "test_precommitment",
        &state.hash,
        &state.entropy,
        CommitmentCondition::ValueThreshold {
            parameter_name: "balance".into(),
            threshold: 1,
            operator: ThresholdOperator::GreaterThanOrEqual,
        },
        next_operation,
    )
    .unwrap();
    assert_eq!(precommitment.commitment_hash, again.commitment_hash);
}

#[test]
fn test_smart_commitment_evaluation() {
    // Establish a genesis state
    let device_id = blake3::hash(b"test_device").into();
    let device_info = DeviceInfo::new(device_id, vec![1, 2, 3, 4]);
    let mut entropy = [0u8; 32];
    entropy[0..3].copy_from_slice(&[1, 2, 3]);
    let state = State::new_genesis(entropy, device_info);

    let condition = CommitmentCondition::ValueThreshold {
        parameter_name: "balance".into(),
        threshold: 1,
        operator: ThresholdOperator::GreaterThanOrEqual,
    };

    // Create a smart commitment
    let commitment = SmartCommitment::new(
        "test_commitment",
        &state.hash,
        &state.entropy,
        condition,
        Operation::Generic {
            operation_type: b"conditional_action".to_vec(),
            data: vec![1, 2, 3],
            message: "Conditional action".to_string(),
            signature: vec![],
        },
    )
    .unwrap();

    // Create evaluation context. For clockless commitments, evaluation is a pure
    // predicate over deterministic context.
    let mut context = CommitmentContext::new();
    context.set_parameter("balance", 1);

    // This commitment should evaluate to true when the named parameter is present
    // and satisfies the threshold predicate.
    assert!(commitment.evaluate(&context));

    // Verify the commitment against the origin entropy.
    assert!(commitment.verify_against_origin(&state.entropy).unwrap());
}

#[test]
fn test_compound_commitment() {
    // Establish a genesis state
    let device_id = blake3::hash(b"test_device").into();
    let device_info = DeviceInfo::new(device_id, vec![1, 2, 3, 4]);
    let mut entropy = [0u8; 32];
    entropy[0..3].copy_from_slice(&[1, 2, 3]);
    let state = State::new_genesis(entropy, device_info);

    // Create conditions
    let value_condition = CommitmentCondition::ValueThreshold {
        parameter_name: "amount".into(),
        threshold: 500,
        operator: ThresholdOperator::GreaterThanOrEqual,
    };
    let sig_condition = CommitmentCondition::MultiSignature {
        required_keys: vec![vec![1, 2, 3]],
        threshold: 1,
    };

    let operation = Operation::Generic {
        operation_type: b"conditional_action".to_vec(),
        data: vec![1, 2, 3],
        message: "Compound action".to_string(),
        signature: vec![],
    };

    let and_commitment = SmartCommitment::new_compound(
        &state.hash,
        &state.entropy,
        operation.clone(),
        vec![sig_condition.clone(), value_condition.clone()],
        "test_and",
    )
    .unwrap();
    let or_commitment = SmartCommitment::new_compound_or(
        &state.hash,
        &state.entropy,
        operation,
        vec![sig_condition, value_condition],
        "test_or",
    )
    .unwrap();

    // Nothing in hand: neither holds.
    let empty = CommitmentContext::new();
    assert!(!and_commitment.evaluate(&empty));
    assert!(!or_commitment.evaluate(&empty));

    // The amount alone: OR holds, AND still needs the signature.
    let mut amount_only = CommitmentContext::new();
    amount_only.set_parameter("amount", 600);
    assert!(or_commitment.evaluate(&amount_only));
    assert!(!and_commitment.evaluate(&amount_only));

    // An amount below the threshold satisfies neither.
    let mut too_small = CommitmentContext::new();
    too_small.set_parameter("amount", 499);
    assert!(!or_commitment.evaluate(&too_small));
    assert!(!and_commitment.evaluate(&too_small));
}
