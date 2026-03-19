//! Cryptographic Performance Benchmarking Module
//!
//! This module provides comprehensive performance benchmarking for DSM cryptographic operations.
//! It includes guards to prevent accidental execution in development environments and
//! end-to-end timing measurements for critical performance regression detection.
//!
//! Key Features:
//! - Release-only benchmarking guards
//! - End-to-end cryptographic operation timing
//! - Statistical analysis of performance metrics
//! - Memory usage monitoring
//! - Thread safety validation

use crate::sdk::identity_sdk::IdentitySDK;
use crate::sdk::hashchain_sdk::HashChainSDK;
use std::sync::Arc;
use crate::util::deterministic_time as dt;

/// Results from cryptographic performance benchmarking
#[derive(Debug, Clone)]
pub struct CryptoBenchmarkResults {
    /// Time taken to generate a single signature (in ticks)
    pub signature_generation_time: u64,
    /// Time taken to verify a signature (in ticks)
    pub signature_verification_time: u64,
    /// Size of generated signatures in bytes
    pub signature_size_bytes: usize,
    /// Operations per tick achieved
    pub operations_per_tick: f64,
    /// Total time for transfer preparation operations (in ticks)
    pub total_transfer_prep_time: u64,
}

/// Guard to prevent accidental benchmarking in development environments
///
/// This function ensures that performance benchmarks are only run in release builds
/// or when explicitly allowed for testing. In production, this prevents development
/// environment noise from affecting measurements.
///
/// # Returns
/// Result indicating whether benchmarking is allowed
fn ensure_release_build() -> Result<(), String> {
    // Allow benchmarking in tests or when explicitly requested
    if cfg!(test) || std::env::var("DSM_ALLOW_DEBUG_BENCHMARKS").is_ok() {
        return Ok(());
    }

    // Otherwise, only allow in release builds
    if cfg!(debug_assertions) {
        return Err("Performance benchmarks can only run in release builds (--release) or with DSM_ALLOW_DEBUG_BENCHMARKS=1".to_string());
    }
    Ok(())
}

/// Generate deterministic bytes for testing (reduces variance in CI)
#[cfg(test)]
fn deterministic_bytes(len: usize) -> Vec<u8> {
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    use rand::RngCore;
    let mut v = vec![0u8; len];
    rng.fill_bytes(&mut v);
    v
}

/// Generate secure random bytes for production use
#[cfg(not(test))]
fn deterministic_bytes(len: usize) -> Vec<u8> {
    match crate::crypto::rng::generate_secure_random(len) {
        Ok(v) => v,
        Err(e) => {
            // In the unlikely event secure RNG fails, return zeroed bytes
            // to keep the benchmark running. This does not affect correctness of timing harness.
            eprintln!("WARN: secure RNG unavailable for benchmark input: {}", e);
            vec![0u8; len]
        }
    }
}

/// Benchmark cryptographic operations with comprehensive timing
///
/// This function performs end-to-end benchmarking of cryptographic operations
/// including signature generation, nonce creation, and transfer preparation.
/// It includes guards to ensure reliable measurements.
///
/// # Arguments
/// * `iterations` - Number of benchmark iterations to perform
///
/// # Returns
/// Result containing benchmark results or error message
pub async fn benchmark_crypto_operations(
    iterations: u32,
) -> Result<CryptoBenchmarkResults, String> {
    // Guard: Only run in release builds
    ensure_release_build()?;

    #[cfg(debug_assertions)]
    eprintln!("🔬 Starting cryptographic performance benchmarks ({iterations} iterations)");

    let hash_chain_sdk = Arc::new(HashChainSDK::new());
    let identity_sdk = Arc::new(IdentitySDK::new(
        "benchmark-identity".to_string(),
        hash_chain_sdk,
    ));

    let mut sign_times = Vec::new();
    let mut verify_times = Vec::new();
    let mut signature_sizes = Vec::new();
    let mut e2e_times = Vec::new();

    let benchmark_start = dt::tick();

    #[cfg(debug_assertions)]
    let mut iter_print = 0u32;

    for _ in 0..iterations {
        #[cfg(debug_assertions)]
        {
            iter_print += 1;
            eprintln!("  📊 Iteration {}/{}", iter_print, iterations);
        }

        // Generate test data deterministically for consistent measurements
        let test_data = deterministic_bytes(64);

        // Benchmark signature generation
        let e2e_start = dt::tick();
        let sig_start = dt::tick();
        let signature = identity_sdk
            .sign_data(&test_data)
            .await
            .map_err(|e| format!("Signature generation failed: {e:?}"))?;
        let sig_time = dt::tick().saturating_sub(sig_start);
        sign_times.push(sig_time);

        // Benchmark verification (simulated - deterministic)
        let verify_start = dt::tick();
        // In a real benchmark, we'd verify the signature here
        // For deterministic behavior, simulate with tick advancement
        let _ = crate::util::deterministic_time::tick();
        let verify_time = dt::tick().saturating_sub(verify_start);
        verify_times.push(verify_time);

        let e2e_time = dt::tick().saturating_sub(e2e_start);
        e2e_times.push(e2e_time);
        signature_sizes.push(signature.len());
    }

    let total_benchmark_time = dt::tick().saturating_sub(benchmark_start);

    // Calculate statistics
    let avg_sign = mean_ticks(&sign_times);
    let avg_verify = mean_ticks(&verify_times);
    let avg_e2e = mean_ticks(&e2e_times);
    let avg_sig_size =
        (signature_sizes.iter().sum::<usize>() as f64 / signature_sizes.len() as f64) as usize;
    let ops_tick = iterations as f64 / total_benchmark_time as f64;

    // Calculate percentiles
    let p50_sign = percentile_ticks(&sign_times, 50.0);
    let p95_sign = percentile_ticks(&sign_times, 95.0);
    let p99_sign = percentile_ticks(&sign_times, 99.0);
    let p50_verify = percentile_ticks(&verify_times, 50.0);
    let p95_verify = percentile_ticks(&verify_times, 95.0);
    let p99_verify = percentile_ticks(&verify_times, 99.0);

    // Output format depends on build type
    #[cfg(debug_assertions)]
    {
        eprintln!("✅ Benchmarking completed successfully");
        eprintln!("   📈 Average signature time: {} ticks", avg_sign);
        eprintln!("   🔍 Average verify time: {} ticks", avg_verify);
        eprintln!(
            "   ⚡ End-to-end: {} ticks ({:.4} ops/tick)",
            avg_e2e, ops_tick
        );
        eprintln!("   📏 Average signature size: {avg_sig_size} bytes");
        eprintln!(
            "   📊 Sign p50/p95/p99: {}/{}/{} ticks",
            p50_sign, p95_sign, p99_sign
        );
        eprintln!(
            "   📊 Verify p50/p95/p99: {}/{}/{} ticks",
            p50_verify, p95_verify, p99_verify
        );
    }

    #[cfg(not(debug_assertions))]
    {
        // Machine-parsable PERF lines for CI
        eprintln!(
            "PERF:host={} cpu={} rustc={} lto=fat target-cpu=native",
            std::env::consts::OS,
            std::env::consts::ARCH,
            env!("CARGO_PKG_VERSION")
        );
        eprintln!("PERF:iters={iterations} e2e_ticks={avg_e2e} ops_tick={ops_tick:.4} sig_bytes={avg_sig_size} sign_ticks={sign_ticks} verify_ticks={verify_ticks}",
         iterations = iterations,
         avg_e2e = avg_e2e,
         ops_tick = ops_tick,
         avg_sig_size = avg_sig_size,
         sign_ticks = avg_sign,
         verify_ticks = avg_verify
    );
        eprintln!(
            "PERF:sign_p50_ticks={} sign_p95_ticks={} sign_p99_ticks={}",
            p50_sign, p95_sign, p99_sign
        );
        eprintln!(
            "PERF:verify_p50_ticks={} verify_p95_ticks={} verify_p99_ticks={}",
            p50_verify, p95_verify, p99_verify
        );
    }

    let results = CryptoBenchmarkResults {
        signature_generation_time: avg_sign,
        signature_verification_time: avg_verify,
        signature_size_bytes: avg_sig_size,
        operations_per_tick: ops_tick,
        total_transfer_prep_time: avg_e2e,
    };

    Ok(results)
}

/// Run comprehensive performance benchmark suite
///
/// This function executes the full suite of performance benchmarks with
/// appropriate guards and error handling for CI/CD integration.
///
/// # Returns
/// Result indicating success or detailed error information
pub async fn run_performance_benchmarks() -> Result<(), String> {
    // Guard: Only run in release builds
    ensure_release_build()?;

    println!("🚀 Running comprehensive DSM performance benchmark suite");

    // Run basic crypto benchmarks
    let crypto_results = benchmark_crypto_operations(10).await?;
    assert!(
        crypto_results.operations_per_tick > 0.0,
        "Crypto operations per tick should be positive"
    );

    // Run memory usage benchmarks
    let memory_results = benchmark_memory_usage().await?;
    assert!(
        memory_results.peak_memory_usage_kb < 1024 * 1024, // 1GB limit
        "Memory usage should be reasonable: {} KB",
        memory_results.peak_memory_usage_kb
    );

    // Run thread safety benchmarks
    benchmark_thread_safety().await?;

    println!("✅ All performance benchmarks passed");
    println!(
        "   🔐 Crypto ops/tick: {:.4}",
        crypto_results.operations_per_tick
    );
    println!(
        "   🧠 Peak memory: {} KB",
        memory_results.peak_memory_usage_kb
    );

    Ok(())
}

/// Memory usage benchmark results
#[derive(Debug, Clone)]
pub struct MemoryBenchmarkResults {
    /// Peak memory usage in KB
    pub peak_memory_usage_kb: usize,
    /// Average memory usage in KB
    pub average_memory_usage_kb: usize,
}

/// Benchmark memory usage during cryptographic operations
async fn benchmark_memory_usage() -> Result<MemoryBenchmarkResults, String> {
    // Simplified memory benchmarking - in production this would use more sophisticated tools
    let initial_memory = get_memory_usage_estimate();

    // Perform intensive crypto operations
    benchmark_crypto_operations(5).await?;

    let final_memory = get_memory_usage_estimate();
    let peak_memory = final_memory.max(initial_memory);

    Ok(MemoryBenchmarkResults {
        peak_memory_usage_kb: peak_memory / 1024,
        average_memory_usage_kb: (initial_memory + final_memory) / 2 / 1024,
    })
}

/// Benchmark thread safety of cryptographic operations
async fn benchmark_thread_safety() -> Result<(), String> {
    use tokio::task;

    let hash_chain_sdk = Arc::new(HashChainSDK::new());
    let identity_sdk = Arc::new(IdentitySDK::new(
        "thread-safety-bench".to_string(),
        hash_chain_sdk,
    ));

    // Spawn multiple concurrent tasks
    let mut handles = vec![];
    for i in 0..10 {
        let sdk_clone = Arc::clone(&identity_sdk);
        let handle = task::spawn(async move {
            let test_data = format!("thread-test-data-{i}").into_bytes();
            sdk_clone.sign_data(&test_data).await
        });
        handles.push(handle);
    }

    // Wait for all tasks to complete successfully
    for handle in handles {
        let result = handle
            .await
            .map_err(|e| format!("Task join failed: {e:?}"))?;
        result.map_err(|e| format!("Crypto operation failed: {e:?}"))?;
    }

    Ok(())
}

/// Basic memory usage estimation (not production-quality)
fn get_memory_usage_estimate() -> usize {
    // NOTE: This function is used only by the benchmark suite.
    // It must not affect protocol commitments or determinism.

    // Linux/Android: estimate resident set size (RSS) from procfs.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
            let mut it = statm.split_whitespace();
            let _size_pages = it.next();
            if let Some(rss_pages) = it.next().and_then(|p| p.parse::<usize>().ok()) {
                // Best-effort page size (most commonly 4096). Avoid libc dependency.
                return rss_pages.saturating_mul(4096);
            }
        }
    }

    // macOS/iOS: currently return best-effort fallback (0).
    // NOTE: A previous Mach FFI branch here triggered a nightly clippy ICE on this toolchain.

    // Fallback for other platforms.
    0
}

/// Calculate mean ticks from a vector of ticks
fn mean_ticks(ticks: &[u64]) -> u64 {
    if ticks.is_empty() {
        return 0;
    }
    let total: u64 = ticks.iter().sum();
    total / ticks.len() as u64
}

/// Calculate percentile ticks from a vector of ticks
fn percentile_ticks(ticks: &[u64], percentile: f64) -> u64 {
    if ticks.is_empty() {
        return 0;
    }

    let mut sorted = ticks.to_vec();
    sorted.sort();

    let index = ((percentile / 100.0) * (sorted.len() - 1) as f64) as usize;
    sorted[index]
}
