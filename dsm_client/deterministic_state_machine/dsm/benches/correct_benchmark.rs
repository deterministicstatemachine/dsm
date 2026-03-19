// A properly architected benchmark for DSM's cryptographic primitives
use criterion::{criterion_group, criterion_main, Criterion};
use dsm::core::state_machine::{generate_transition_entropy, StateMachine, verify_transition_integrity};
use dsm::core::state_machine::transition::apply_transition;
use dsm::types::operations::Operation;
use dsm::types::state_types::{DeviceInfo, State};

/// Create a properly initialized genesis state for benchmarking
fn create_benchmark_genesis() -> State {
    let device_info = DeviceInfo::from_hashed_label("benchmark_device", vec![1, 2, 3, 4]);
    let mut entropy = [0u8; 32];
    entropy[0..4].copy_from_slice(&[5, 6, 7, 8]);
    let mut genesis = State::new_genesis(entropy, device_info);
    let computed_hash = genesis.compute_hash().unwrap_or_else(|e| {
        panic!("Failed to compute hash: {}", e);
    });
    genesis.hash = computed_hash;
    genesis
}

/// Benchmark core cryptographic operations
fn bench_crypto_primitives(c: &mut Criterion) {
    // Group for cryptographic primitives
    let mut group = c.benchmark_group("Cryptographic Primitives");

    // Benchmark Blake3 hash computation - foundation of hash chain integrity
    group.bench_function("blake3_hash_1kb", |b| {
        let data = vec![0u8; 1024]; // 1KB of data
        b.iter(|| blake3::hash(&data));
    });

    // Benchmark entropy generation - critical for state evolution
    group.bench_function("entropy_generation", |b| {
        let state = create_benchmark_genesis();
        let op = Operation::Generic {
            operation_type: b"benchmark".to_vec(),
            data: vec![1, 2, 3, 4],
            message: "Benchmark operation".to_string(),
            signature: Vec::new(),
        };

        b.iter(|| {
            generate_transition_entropy(&state, &op).unwrap_or_else(|e| {
                panic!("Failed to generate entropy: {}", e);
            })
        });
    });

    group.finish();
}

/// Benchmark state transition operations
fn bench_state_transitions(c: &mut Criterion) {
    // Group for state transitions
    let mut group = c.benchmark_group("State Transitions");

    // Benchmark complete state transition cycle
    group.bench_function("full_transition", |b| {
        let genesis = create_benchmark_genesis();
        let op = Operation::Generic {
            operation_type: b"benchmark".to_vec(),
            data: vec![1, 2, 3, 4],
            message: "Benchmark operation".to_string(),
            signature: Vec::new(),
        };

        b.iter(|| {
            // Create a new state machine for each iteration to ensure isolation
            let mut state_machine = StateMachine::new();
            state_machine.set_state(genesis.clone());
            state_machine
                .execute_transition(op.clone())
                .unwrap_or_else(|e| {
                    panic!("Failed to execute transition: {}", e);
                })
        });
    });

    // Benchmark state verification
    group.bench_function("state_verification", |b| {
        // Setup: Create two sequential states
        let genesis = create_benchmark_genesis();
        let op = Operation::Generic {
            operation_type: b"benchmark".to_vec(),
            data: vec![1, 2, 3, 4],
            message: "Benchmark operation".to_string(),
            signature: Vec::new(),
        };

        let entropy = generate_transition_entropy(&genesis, &op).unwrap_or_else(|e| {
            panic!("Failed to generate entropy: {}", e);
        });
        let state1 = apply_transition(&genesis, &op, &entropy).unwrap_or_else(|e| {
            panic!("Failed to apply transition: {}", e);
        });

        // Benchmark verification
        b.iter(|| {
            verify_transition_integrity(&genesis, &state1, &op).unwrap_or_else(|e| {
                panic!("Failed to verify transition: {}", e);
            })
        });
    });

    group.finish();
}

// Register benchmark groups properly
criterion_group!(
    name = crypto_benchmarks;
    config = Criterion::default().sample_size(30);
    targets = bench_crypto_primitives
);

criterion_group!(
    name = transition_benchmarks;
    config = Criterion::default().sample_size(20);
    targets = bench_state_transitions
);

// Main entry point
criterion_main!(crypto_benchmarks, transition_benchmarks);
