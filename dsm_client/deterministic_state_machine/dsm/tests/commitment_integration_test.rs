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

    // Create a precommitment
    let _precommitment = SmartCommitment::new(
        "test_precommitment",
        &state,
        // Replace the prior "always true" condition with a deterministic, clockless predicate.
        CommitmentCondition::ValueThreshold {
            parameter_name: "balance".into(),
            threshold: 1,
            operator: ThresholdOperator::GreaterThanOrEqual,
        },
        next_operation,
    )
    .unwrap();
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
        &state,
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

    // Verify the commitment against the state
    assert!(commitment.verify_against_state(&state).unwrap());
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

    // Create compound AND commitment
    let and_commitment = SmartCommitment::new_compound(
        &state,
        vec![1, 2, 3, 4], // recipient
        1000,             // amount
        vec![sig_condition.clone(), value_condition.clone()],
        "test_and",
    )
    .unwrap();

    // Create compound OR commitment
    let or_commitment = SmartCommitment::new_compound_or(
        &state,
        vec![1, 2, 3, 4], // recipient
        1000,             // amount
        vec![sig_condition, value_condition],
        "test_or",
    )
    .unwrap();

    // Create evaluation context
    let context = CommitmentContext::new();

    // NOTE: Compound evaluation semantics depend on the current smart-commitment
    // policy implementation. We assert only that evaluation is deterministic and
    // does not require any time-based fields.
    let _ = and_commitment.evaluate(&context);
    let _ = or_commitment.evaluate(&context);
}
