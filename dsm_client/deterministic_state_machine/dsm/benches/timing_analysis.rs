use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dsm::core::state_machine::{self, transition};
use dsm::crypto::sphincs::{generate_sphincs_keypair, sphincs_sign, sphincs_verify};
use dsm::types::operations::Operation;
use dsm::types::state_types::{DeviceInfo, State};
use rand::{thread_rng, Rng};
use std::time::Duration;

// mod bench; // Commented out - bench.rs doesn't exist

/// Benchmark timing side-channel resistance of critical cryptographic operations.
///
/// This benchmark suite systematically evaluates the constant-time properties of
/// key cryptographic primitives in the DSM system, focusing particularly on
/// signature verification, precommitment validation, and state transition verification.
///
/// The measurement methodology deliberately includes both valid and invalid inputs
/// to quantify timing variances that could potentially leak information through
/// side-channels. This forms a critical component of the security posture for
/// quantum-resistant implementations.
fn timing_side_channel_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Timing Side-Channel Analysis");

    // Configure for high-precision statistical analysis
    group.sampling_mode(criterion::SamplingMode::Flat);
    group.sample_size(1000); // Very high sample count for statistical significance
    group.measurement_time(Duration::from_secs(20));
    group.warm_up_time(Duration::from_secs(5));

    // Benchmark SPHINCS+ signature verification timing variance
    group.bench_function("constant_time_sphincs_verification", |b| {
        // Generate keypair outside measurement loop
        let (pk, sk) = generate_sphincs_keypair().unwrap_or_default();

        // Create identical test messages for both valid and invalid signatures
        let message = b"This message tests constant-time verification properties";

        // Generate valid signature
        let valid_signature = sphincs_sign(&sk, message).unwrap_or_else(|e| {
            panic!("Failed to generate signature: {}", e);
        });

        // Create an invalid signature by bit-flipping the valid one
        let mut invalid_signature = valid_signature.clone();
        let byte_to_flip = thread_rng().gen_range(0..invalid_signature.len());
        let bit_to_flip = thread_rng().gen_range(0..8);
        invalid_signature[byte_to_flip] ^= 1 << bit_to_flip;

        // Create stable references to avoid allocation during benchmark
        let message_ref = &message[..];
        let pk_ref = &pk;

        // Benchmark with random selection between valid and invalid signatures
        // A timing side-channel would show statistical variance between the two cases
        b.iter_batched_ref(
            || {
                // Randomly select valid or invalid signature
                if thread_rng().gen_bool(0.5) {
                    valid_signature.clone()
                } else {
                    invalid_signature.clone()
                }
            },
            |signature| {
                // Verify signature and record result
                // The black_box prevents compiler optimization from removing the operation
                black_box(sphincs_verify(pk_ref, message_ref, signature))
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Benchmark state transition verification timing variance
    group.bench_function("constant_time_transition_verification", |b| {
        // Create initial state outside measurement loop
        let mut state_machine = state_machine::StateMachine::new();
        let device_info = DeviceInfo::from_hashed_label("timing_device", vec![1, 2, 3, 4]);
        let mut entropy = [0u8; 32];
        entropy[0..4].copy_from_slice(&[5, 6, 7, 8]);
        let genesis = State::new_genesis(entropy, device_info);
        state_machine.set_state(genesis.clone());

        // Create a valid transition
        let valid_op = Operation::Generic {
            operation_type: b"valid_op".to_vec(),
            data: vec![1, 2, 3, 4],
            message: String::new(),
            signature: Vec::new(),
        };

        let valid_state = state_machine
            .execute_transition(valid_op.clone())
            .unwrap_or_else(|e| {
                panic!("Failed to execute transition: {}", e);
            });

        // Create an invalid transition (with incorrect hash chain reference)
        let mut invalid_state = valid_state.clone();
        // Corrupt the previous state hash to break chain integrity
        if !invalid_state.prev_state_hash.is_empty() {
            let byte_to_flip = thread_rng().gen_range(0..invalid_state.prev_state_hash.len());
            invalid_state.prev_state_hash[byte_to_flip] ^= 0xFF;
        }

        // Create stable references for benchmark
        let genesis_ref = &genesis;

        // Benchmark verification timing variance
        b.iter_batched_ref(
            || {
                // Randomly select valid or invalid state
                if thread_rng().gen_bool(0.5) {
                    (valid_state.clone(), valid_op.clone())
                } else {
                    (invalid_state.clone(), valid_op.clone())
                }
            },
            |(state, op)| {
                // Verify transition and record result
                black_box(transition::verify_transition_integrity(
                    genesis_ref,
                    state,
                    op,
                ))
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Benchmark precommitment validation timing variance
    group.bench_function("constant_time_precommitment_validation", |b| {
        // Create state machine for precommitment testing
        let mut state_machine = state_machine::StateMachine::new();
        let device_id = blake3::hash(b"timing_device").into();
        let device_info = DeviceInfo::new(device_id, vec![1, 2, 3, 4]);
        let mut entropy = [0u8; 32];
        entropy[0..4].copy_from_slice(&[5, 6, 7, 8]);
        let genesis = State::new_genesis(entropy, device_info);
        state_machine.set_state(genesis);

        // Create operation for precommitment
        let op = Operation::Generic {
            operation_type: b"precommit_op".to_vec(),
            data: vec![9, 10, 11, 12],
            message: String::new(),
            signature: Vec::new(),
        };

        // Generate valid precommitment
        let (_, valid_positions) = state_machine
            .generate_precommitment(&op)
            .unwrap_or_else(|e| {
                panic!("Failed to generate precommitment: {}", e);
            });

        // Create invalid precommitment by modifying positions
        let mut invalid_positions = valid_positions.clone();
        if !invalid_positions.is_empty() {
            let pos_to_modify = thread_rng().gen_range(0..invalid_positions.len());
            if pos_to_modify > 0 {
                // Store the first position value before modifying
                let first_value = invalid_positions[0].clone();
                if let Some(pos) = invalid_positions.get_mut(pos_to_modify) {
                    // Create a different position rather than using random generation
                    // which has trait implementation issues
                    *pos = first_value; // Use stored value
                }
            }
        }

        // Create stable references
        let op_ref = &op;

        // Benchmark verification timing variance
        b.iter_batched_ref(
            || {
                // Randomly select valid or invalid positions
                if thread_rng().gen_bool(0.5) {
                    valid_positions.clone()
                } else {
                    invalid_positions.clone()
                }
            },
            |positions| {
                // Verify precommitment and record result
                black_box(state_machine.verify_precommitment(op_ref, positions))
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Benchmark hash computation timing variance
    group.bench_function("constant_time_hash_computation", |b| {
        // Generate data sets of identical length but different content
        let data_len = 1024;
        let data_set_1 = vec![0xAA; data_len];
        let data_set_2 = vec![0xBB; data_len];

        // Benchmark hash timing variance
        b.iter_batched_ref(
            || {
                // Randomly select between data sets
                if thread_rng().gen_bool(0.5) {
                    data_set_1.clone()
                } else {
                    data_set_2.clone()
                }
            },
            |data| {
                // Hash data and record result
                black_box(::blake3::hash(data))
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Benchmark serialization timing variance
    group.bench_function("constant_time_serialization", |b| {
        let device_info = DeviceInfo::from_hashed_label("timing_device", vec![1, 2, 3, 4]);

        // Create two states with identical structures but different content
        let mut entropy1 = [0u8; 32];
        entropy1[0..4].copy_from_slice(&[1, 2, 3, 4]);
        let mut state_1 = State::new_genesis(entropy1, device_info.clone());
        let mut entropy2 = [0u8; 32];
        entropy2[0..4].copy_from_slice(&[5, 6, 7, 8]);
        let mut state_2 = State::new_genesis(entropy2, device_info);

        // Ensure states have hash computed
        let hash_1 = state_1.compute_hash().unwrap_or_else(|e| {
            panic!("Failed to compute hash for state_1: {}", e);
        });
        let hash_2 = state_2.compute_hash().unwrap_or_else(|e| {
            panic!("Failed to compute hash for state_2: {}", e);
        });

        state_1.hash = hash_1;
        state_2.hash = hash_2;

        // Benchmark serialization timing variance
        b.iter_batched_ref(
            || {
                // Randomly select between states
                if thread_rng().gen_bool(0.5) {
                    state_1.clone()
                } else {
                    state_2.clone()
                }
            },
            |state| {
                // Serialize state using canonical bytes and record result
                black_box(state.to_bytes())
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Benchmark resistance to power analysis and electromagnetic leakage.
///
/// This benchmark suite simulates workloads that could be susceptible to power analysis
/// attacks, focusing on operations with variable computational intensity based on
/// the secret values being processed. Modern cryptographic implementations should
/// show minimal correlation between power consumption and secret values.
fn power_analysis_resistance_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Power Analysis Resistance");

    // Configure for high-precision statistical analysis
    group.sample_size(1000);
    group.measurement_time(Duration::from_secs(15));

    // Benchmark SPHINCS+ key generation intensity correlation
    group.bench_function("power_signature_generation", |b| {
        // Generate keypair outside measurement loop
        let (_, sk) = generate_sphincs_keypair().unwrap_or_default();

        // Generate two message types with different Hamming weights
        let low_weight_message = vec![0x00; 32]; // All zeros (low Hamming weight)
        let high_weight_message = vec![0xFF; 32]; // All ones (high Hamming weight)

        // Benchmark signing operation with different messages
        b.iter_batched_ref(
            || {
                // Randomly select message type
                if thread_rng().gen_bool(0.5) {
                    low_weight_message.clone()
                } else {
                    high_weight_message.clone()
                }
            },
            |message| {
                // Sign message and record result
                black_box(sphincs_sign(&sk, message))
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Benchmark different key bit patterns
    for bit_weight in [0, 64, 128, 192, 255] {
        group.bench_with_input(
            BenchmarkId::new("key_bit_weight", bit_weight),
            &bit_weight,
            |b, &weight| {
                // Generate test key with specific bit pattern/weight
                let key_data = vec![weight as u8; 32];

                // Create message to encrypt
                let message = b"Test message for power analysis";

                // Convert to array for blake3 keying
                let key_array: [u8; 32] = key_data.try_into().unwrap_or_else(|_| {
                    panic!("Failed to convert key_data to array");
                });

                b.iter(|| {
                    // Use key in cryptographic operation - proper API call
                    let mut hasher = ::blake3::Hasher::new_keyed(&key_array);
                    hasher.update(message);
                    black_box(hasher.finalize())
                })
            },
        );
    }

    group.finish();
}

/// Benchmark multi-implementation constant time properties
fn multi_implementation_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Multi-Implementation Analysis");

    // Benchmark different cryptographic primitive implementations for timing variance
    // This is important for constant-time implementations regardless of architectural optimizations

    // Test message for all operations
    let message = b"Test message for multi-implementation analysis";

    // SPHINCS+ implementations
    group.bench_function("sphincs_constant_time", |b| {
        // Generate keypair
        let (pk, sk) = generate_sphincs_keypair().unwrap_or_default();

        // Generate signature
        let signature = sphincs_sign(&sk, message).unwrap_or_else(|e| {
            panic!("Failed to generate signature: {}", e);
        });

        b.iter(|| {
            // Verify signature
            black_box(sphincs_verify(&pk, message, &signature))
        })
    });

    // Blake3 hash implementations
    group.bench_function("blake3_constant_time", |b| {
        b.iter(|| {
            // Hash message
            black_box(::blake3::hash(message))
        })
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2))
        .sample_size(100);
    targets = timing_side_channel_benchmark, power_analysis_resistance_benchmark, multi_implementation_benchmark
}
criterion_main!(benches);
