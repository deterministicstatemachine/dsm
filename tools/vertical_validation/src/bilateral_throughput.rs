//! Bilateral Throughput Benchmark
//!
//! Measures REAL protocol throughput — actual `StateMachine::execute_transition()`
//! calls with SPHINCS+ signing, BLAKE3 hashing, entropy evolution, and sparse
//! index computation.  Reports two modes:
//!
//! 1. **With signing**: end-to-end cost (SPHINCS+ sign + transition). Expected
//!    ~15-20 ops/sec — post-quantum security is the cost.
//! 2. **Without signing**: pre-signed ops, isolates state machine cost.
//!    Expected ~1000+ ops/sec — proves the SM is not the bottleneck.

// Validation harness: panicking on crypto setup failures is correct behavior.
#![allow(clippy::expect_used)]

use instant::Instant;
use serde::Serialize;

use dsm::core::state_machine::StateMachine;
use dsm::crypto::blake3::domain_hash;
use dsm::crypto::sphincs::{generate_keypair_from_seed, sphincs_sign, SphincsVariant};
use dsm::types::operations::{Operation, TransactionMode, VerificationType};
use dsm::types::state_types::{DeviceInfo, State};
use dsm::types::token_types::Balance;

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct ThroughputDataPoint {
    pub label: String,
    pub iterations: u64,
    pub total_duration_ms: f64,
    pub ops_per_sec: f64,
    pub p50_us: f64,
    pub p95_us: f64,
    pub p99_us: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BilateralThroughputResult {
    /// End-to-end: SPHINCS+ sign + execute_transition per iteration
    pub with_signing: ThroughputDataPoint,
    /// Isolated: pre-signed Generic ops, execute_transition only
    pub without_signing: ThroughputDataPoint,
    /// SPHINCS+ keygen cost (single measurement)
    pub keygen_cost_ms: f64,
    /// SPHINCS+ sign cost (averaged)
    pub avg_sign_cost_ms: f64,
    /// BLAKE3 domain_hash cost (averaged)
    pub avg_blake3_cost_us: f64,
    pub duration_ms: f64,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_genesis(seed: &[u8; 32], pk: &[u8]) -> (State, StateMachine) {
    let device_id: [u8; 32] = *domain_hash("DSM/test-device", seed).as_bytes();
    let device_info = DeviceInfo::new(device_id, pk.to_vec());
    let mut state = State::new_genesis(*seed, device_info);
    if let Ok(h) = state.hash() {
        state.hash = h;
    }
    state.token_balances.insert(
        "ERA".into(),
        Balance::from_state(1_000_000, state.hash, state.state_number),
    );
    let mut machine = StateMachine::new();
    machine.set_state(state.clone());
    (state, machine)
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64) * p / 100.0).ceil() as usize;
    let idx = idx.min(sorted.len()).saturating_sub(1);
    sorted[idx]
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn collect_bilateral_throughput_results(iterations: u64) -> BilateralThroughputResult {
    eprintln!("\n=== BILATERAL THROUGHPUT BENCHMARK ===\n");
    let suite_start = Instant::now();

    // 1. Measure keygen cost
    let seed = [55u8; 32];
    eprintln!("  Measuring SPHINCS+ keygen cost...");
    let keygen_start = Instant::now();
    let kp = generate_keypair_from_seed(SphincsVariant::SPX256f, &seed).expect("SPHINCS+ keygen");
    let keygen_cost_ms = keygen_start.elapsed().as_secs_f64() * 1000.0;
    eprintln!("    keygen: {keygen_cost_ms:.1}ms");

    let pk = kp.public_key.clone();
    let sk = kp.secret_key.clone();

    // 2. Measure sign cost (average over 5 samples)
    eprintln!("  Measuring SPHINCS+ sign cost (5 samples)...");
    let sign_samples = 5u64;
    let mut sign_total_ms = 0.0;
    for i in 0..sign_samples {
        let msg = format!("sign_cost_sample_{i}");
        let t = Instant::now();
        let _sig = sphincs_sign(&sk, msg.as_bytes()).expect("sign");
        sign_total_ms += t.elapsed().as_secs_f64() * 1000.0;
    }
    let avg_sign_cost_ms = sign_total_ms / sign_samples as f64;
    eprintln!("    avg sign: {avg_sign_cost_ms:.1}ms");

    // 3. Measure BLAKE3 domain_hash cost (average over 10000 samples)
    eprintln!("  Measuring BLAKE3 cost (10000 samples)...");
    let blake3_samples = 10_000u64;
    let blake3_start = Instant::now();
    for i in 0..blake3_samples {
        let _ = domain_hash("DSM/bench", &i.to_le_bytes());
    }
    let avg_blake3_cost_us =
        blake3_start.elapsed().as_secs_f64() * 1_000_000.0 / blake3_samples as f64;
    eprintln!("    avg BLAKE3: {avg_blake3_cost_us:.2}us");

    // 4. Benchmark WITH signing
    eprintln!("  Running {iterations} iterations WITH signing...");
    let with_signing = benchmark_with_signing(&seed, &pk, &sk, iterations);
    eprintln!(
        "    {:.1} ops/sec  P50={:.0}us P95={:.0}us P99={:.0}us",
        with_signing.ops_per_sec, with_signing.p50_us, with_signing.p95_us, with_signing.p99_us
    );

    // 5. Benchmark WITHOUT signing (Generic ops, no SPHINCS+ cost)
    let without_iterations = iterations * 10; // can run more since no signing
    eprintln!("  Running {without_iterations} iterations WITHOUT signing (Generic ops)...");
    let without_signing = benchmark_without_signing(&seed, &pk, without_iterations);
    eprintln!(
        "    {:.1} ops/sec  P50={:.0}us P95={:.0}us P99={:.0}us",
        without_signing.ops_per_sec,
        without_signing.p50_us,
        without_signing.p95_us,
        without_signing.p99_us
    );

    let duration_ms = suite_start.elapsed().as_secs_f64() * 1000.0;
    eprintln!();

    BilateralThroughputResult {
        with_signing,
        without_signing,
        keygen_cost_ms,
        avg_sign_cost_ms,
        avg_blake3_cost_us,
        duration_ms,
    }
}

// ---------------------------------------------------------------------------
// Benchmark WITH signing (end-to-end)
// ---------------------------------------------------------------------------

fn benchmark_with_signing(
    seed: &[u8; 32],
    pk: &[u8],
    sk: &[u8],
    iterations: u64,
) -> ThroughputDataPoint {
    let (mut state, mut machine) = make_genesis(seed, pk);
    let mut latencies_us = Vec::with_capacity(iterations as usize);

    let bench_start = Instant::now();

    for i in 0..iterations {
        let nonce = i.to_le_bytes().to_vec();

        let iter_start = Instant::now();

        // Sign a transfer
        let mut op = Operation::Transfer {
            token_id: "ERA".into(),
            to_device_id: vec![0xDD; 32],
            amount: Balance::from_state(1, state.hash, state.state_number),
            mode: TransactionMode::Unilateral,
            nonce,
            verification: VerificationType::Standard,
            pre_commit: None,
            recipient: vec![0xDD; 32],
            to: "b32bench".into(),
            message: String::new(),
            signature: Vec::new(),
        };
        let bytes = op.to_bytes();
        let sig = sphincs_sign(sk, &bytes).expect("sign");
        if let Operation::Transfer { signature, .. } = &mut op {
            *signature = sig;
        }

        // Execute transition
        match machine.execute_transition(op) {
            Ok(new_state) => {
                state = new_state;
            }
            Err(e) => {
                eprintln!("    WARNING: transition {i} failed: {e}");
                break;
            }
        }

        latencies_us.push(iter_start.elapsed().as_secs_f64() * 1_000_000.0);
    }

    let total_duration_ms = bench_start.elapsed().as_secs_f64() * 1000.0;
    let actual_iters = latencies_us.len() as u64;
    let ops_per_sec = if total_duration_ms > 0.0 {
        actual_iters as f64 / (total_duration_ms / 1000.0)
    } else {
        0.0
    };

    latencies_us.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    ThroughputDataPoint {
        label: "with_signing (SPHINCS+ + SM)".into(),
        iterations: actual_iters,
        total_duration_ms,
        ops_per_sec,
        p50_us: percentile(&latencies_us, 50.0),
        p95_us: percentile(&latencies_us, 95.0),
        p99_us: percentile(&latencies_us, 99.0),
    }
}

// ---------------------------------------------------------------------------
// Benchmark WITHOUT signing (isolated state machine cost)
// ---------------------------------------------------------------------------

fn benchmark_without_signing(seed: &[u8; 32], pk: &[u8], iterations: u64) -> ThroughputDataPoint {
    // Pre-generate a signing key so Generic ops satisfy the signature requirement.
    // The signing cost is excluded from timing below (only execute_transition is timed).
    let kp = generate_keypair_from_seed(SphincsVariant::SPX256f, seed).expect("keygen");
    let sk = &kp.secret_key;

    let (_state, mut machine) = make_genesis(seed, pk);
    let mut latencies_us = Vec::with_capacity(iterations as usize);

    let bench_start = Instant::now();

    for i in 0..iterations {
        let mut op = Operation::Generic {
            operation_type: "bench".into(),
            data: i.to_le_bytes().to_vec(),
            message: String::new(),
            signature: vec![],
        };
        // Sign before timing — we're isolating state machine cost only.
        let bytes = op.to_bytes();
        let sig = sphincs_sign(sk, &bytes).expect("sign");
        if let Operation::Generic { signature, .. } = &mut op {
            *signature = sig;
        }

        let iter_start = Instant::now();
        match machine.execute_transition(op) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("    WARNING: transition {i} failed: {e}");
                break;
            }
        }
        latencies_us.push(iter_start.elapsed().as_secs_f64() * 1_000_000.0);
    }

    let total_duration_ms = bench_start.elapsed().as_secs_f64() * 1000.0;
    let actual_iters = latencies_us.len() as u64;
    let ops_per_sec = if total_duration_ms > 0.0 {
        actual_iters as f64 / (total_duration_ms / 1000.0)
    } else {
        0.0
    };

    latencies_us.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    ThroughputDataPoint {
        label: "without_signing (SM only)".into(),
        iterations: actual_iters,
        total_duration_ms,
        ops_per_sec,
        p50_us: percentile(&latencies_us, 50.0),
        p95_us: percentile(&latencies_us, 95.0),
        p99_us: percentile(&latencies_us, 99.0),
    }
}
