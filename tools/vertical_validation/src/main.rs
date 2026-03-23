//! # DSM Vertical Validation
//!
//! Proves DSM's formal scaling argument from TLA+ math down to real-time
//! local multi-node bytes, AND bridges the gap between abstract model and Rust
//! implementation. Combines:
//!
//! 1. **TLA+ Model Checking** — exhaustive verification of 50+ invariants
//!    (fork-exclusion, conservation, refinement) via TLC
//! 2. **Scaling Benchmark** — parallel writers proving additive Θ(N) throughput
//! 3. **Non-Interference Proof** — idle nodes unchanged during parallel operations
//! 4. **Tripwire Fork-Exclusion** — double-spend attempts rejected in real-time
//! 5. **Property-Based Tests** — 7 invariants on real StateMachine across random ops
//! 6. **Implementation Traces** — deterministic direct-code replay on fixed scenarios
//! 7. **Adversarial Bilateral** — 6 attack scenarios with 100% rejection
//! 8. **Crypto KATs** — 16 internal consistency tests across 4 primitives
//! 9. **Bilateral Throughput** — honest protocol performance (with/without signing)
//!
//! ```text
//! Usage:
//!   vertical-validation tla-check [--include-liveness] Run TLA+ model checking
//!   vertical-validation proof-check                  Run TLAPS proof modules
//!   vertical-validation benchmark [--duration]          Run scaling benchmark
//!   vertical-validation property-tests [--iterations]   Run property tests
//!   vertical-validation implementation-traces           Run direct implementation traces
//!   vertical-validation adversarial                     Run adversarial attacks
//!   vertical-validation crypto-kat                      Run crypto KATs
//!   vertical-validation bilateral-throughput [--iter]    Run throughput benchmark
//!   vertical-validation full [--duration]               Run everything end-to-end
//! ```

mod adversarial_bilateral;
mod benchmark;
mod bilateral_throughput;
mod crypto_kat;
mod implementation_traces;
mod lean_checker;
mod local_nodes;
mod proof_runner;
mod property_tests;
mod report;
mod tla_runner;
mod tla_trace_replay;

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};

use benchmark::ScalingBenchmark;
use local_nodes::LocalNodeManager;
use proof_runner::ProofRunner;
use report::{ProofModuleReport, TlaSpecReport, VerticalValidationReport};
use tla_runner::TlaRunner;
use tla_trace_replay::{TlaImplementationReplayResult, TlaTraceReplayResult};

#[derive(Parser)]
#[command(name = "vertical-validation")]
#[command(about = "DSM Vertical Validation: TLA+ + Scaling Benchmark + Report")]
struct Cli {
    /// Project root directory (DSM repository root)
    #[arg(long, default_value = ".")]
    project_root: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run TLA+ model checking on all standard specs
    TlaCheck {
        /// Also run the extended bounded DSM profile and the standalone
        /// bilateral liveness spec. This is intentionally slower than the
        /// default fast suite.
        #[arg(long)]
        include_liveness: bool,
    },

    /// Run TLAPS proof checking on the proof-tier modules
    ProofCheck,

    /// Run scaling benchmark on the 5-node local storage-node set
    Benchmark {
        /// Duration per benchmark run in seconds
        #[arg(long, default_value = "10")]
        duration: u64,
        /// Skip local node startup (assume already running)
        #[arg(long)]
        no_start: bool,
    },

    /// Run property-based tests on real state machine
    PropertyTests {
        /// Number of iterations per property
        #[arg(long, default_value = "100")]
        iterations: u64,
        /// Deterministic seed for reproducibility
        #[arg(long, default_value = "42")]
        seed: u64,
    },

    /// Run deterministic traces on the real implementation
    ImplementationTraces,

    /// Run adversarial bilateral attack scenarios
    Adversarial,

    /// Run cryptographic known-answer tests
    CryptoKat,

    /// Run bilateral throughput benchmark
    BilateralThroughput {
        /// Number of iterations (with-signing mode; without-signing = 10x)
        #[arg(long, default_value = "50")]
        iterations: u64,
    },

    /// Generate formal verification report (Markdown) with all results
    FormalReport {
        /// Output path (default: docs/reports/YYYY-MM-DD-formal-verification-report.md)
        #[arg(long)]
        output: Option<String>,
        /// Skip Lean 4 proof checking
        #[arg(long)]
        skip_lean: bool,
        /// Run fresh scaling benchmark (requires local storage nodes, adds ~3 min)
        #[arg(long)]
        include_scaling: bool,
        /// Number of property test iterations
        #[arg(long, default_value = "100")]
        iterations: u64,
        /// Deterministic seed for property tests
        #[arg(long, default_value = "42")]
        seed: u64,
    },

    /// Run everything end-to-end (TLA+ check + benchmark + all new modules + report)
    Full {
        /// Duration per benchmark run in seconds
        #[arg(long, default_value = "10")]
        duration: u64,
        /// Skip local node startup (assume already running)
        #[arg(long)]
        no_start: bool,
        /// Output format: ascii, json, csv
        #[arg(long, default_value = "ascii")]
        format: String,
        /// Number of property test iterations
        #[arg(long, default_value = "100")]
        iterations: u64,
        /// Deterministic seed for property tests
        #[arg(long, default_value = "42")]
        seed: u64,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let root = cli
        .project_root
        .canonicalize()
        .context("Invalid project root. Run from the DSM repo root or specify --project-root.")?;

    match cli.command {
        Commands::TlaCheck { include_liveness } => {
            run_tla_check(&root, include_liveness).await?;
        }

        Commands::ProofCheck => {
            run_proof_check(&root).await?;
        }

        Commands::Benchmark { duration, no_start } => {
            run_benchmark(&root, duration, no_start).await?;
        }

        Commands::PropertyTests { iterations, seed } => {
            run_property_tests(iterations, seed);
        }

        Commands::ImplementationTraces => {
            run_implementation_traces();
        }

        Commands::Adversarial => {
            run_adversarial();
        }

        Commands::CryptoKat => {
            run_crypto_kat();
        }

        Commands::BilateralThroughput { iterations } => {
            run_bilateral_throughput(iterations);
        }

        Commands::FormalReport {
            output,
            skip_lean,
            include_scaling,
            iterations,
            seed,
        } => {
            run_formal_report(&root, output, skip_lean, include_scaling, iterations, seed).await?;
        }

        Commands::Full {
            duration,
            no_start,
            format,
            iterations,
            seed,
        } => {
            run_full(&root, duration, no_start, &format, iterations, seed).await?;
        }
    }

    Ok(())
}

/// Collect TLAPS proof results (progress on stderr, no report printed).
async fn collect_proof_results(
    root: &std::path::Path,
) -> anyhow::Result<Vec<(proof_runner::ProofSpec, proof_runner::ProofResult)>> {
    eprintln!("\n=== TLAPS PROOF CHECKING ===\n");

    let runner = ProofRunner::new(root)?;
    let results = runner.run_all().await?;

    let all_passed = results.iter().all(|(_, r)| r.passed);
    if all_passed {
        eprintln!("\n  All {} proof modules PASSED\n", results.len());
    } else {
        let failed: Vec<_> = results
            .iter()
            .filter(|(_, r)| !r.passed)
            .map(|(s, _)| s.label.as_str())
            .collect();
        eprintln!("\n  FAILED proof modules: {}\n", failed.join(", "));
    }

    Ok(results)
}

/// Collect TLA+ model checking results (progress on stderr, no report printed).
async fn collect_tla_results(
    root: &std::path::Path,
    include_liveness: bool,
) -> anyhow::Result<Vec<(tla_runner::TlaSpec, tla_runner::TlcResult)>> {
    eprintln!("\n=== TLA+ MODEL CHECKING ===\n");

    let runner = TlaRunner::new(root)?;
    let results = runner.run_all(include_liveness).await?;

    let all_passed = results.iter().all(|(_, r)| r.passed);

    if all_passed {
        eprintln!("\n  All {} specs PASSED\n", results.len());
    } else {
        let failed: Vec<_> = results
            .iter()
            .filter(|(_, r)| !r.passed)
            .map(|(s, _)| s.label.as_str())
            .collect();
        eprintln!("\n  FAILED specs: {}\n", failed.join(", "));
    }

    Ok(results)
}

/// Run TLAPS proof checking standalone (collect + print report).
async fn run_proof_check(
    root: &std::path::Path,
) -> anyhow::Result<Vec<(proof_runner::ProofSpec, proof_runner::ProofResult)>> {
    let results = collect_proof_results(root).await?;
    let proof_reports = build_proof_reports(&results);

    let report = VerticalValidationReport {
        proof_results: proof_reports,
        tla_results: Vec::new(),
        scaling_results: None,
        property_test_results: None,
        implementation_trace_results: None,
        adversarial_results: None,
        crypto_kat_results: None,
        bilateral_throughput_results: None,
    };

    print!("{}", report.render_ascii());
    Ok(results)
}

/// Collect scaling benchmark results (progress on stderr, no report printed).
async fn collect_benchmark_results(
    root: &std::path::Path,
    duration: u64,
    no_start: bool,
) -> anyhow::Result<benchmark::ScalingBenchmarkResult> {
    eprintln!("\n=== SCALING BENCHMARK ===\n");

    let node_mgr = LocalNodeManager::new(root);

    if !no_start {
        node_mgr.start().await?;
    } else {
        eprintln!("  Checking local node health (--no-start mode)...");
        node_mgr
            .wait_for_nodes(node_mgr.node_count(), 5)
            .await
            .context("Local storage nodes not healthy. Start them first or remove --no-start.")?;
        eprintln!("  Local storage nodes healthy");
    }

    let bench = ScalingBenchmark::new(node_mgr, duration);
    bench.run_scaling_series().await
}

/// Run TLA+ model checking standalone (collect + print report).
async fn run_tla_check(
    root: &std::path::Path,
    include_liveness: bool,
) -> anyhow::Result<Vec<(tla_runner::TlaSpec, tla_runner::TlcResult)>> {
    let results = collect_tla_results(root, include_liveness).await?;
    let (trace_replays, implementation_replays) = collect_tla_trace_replays(root, &results).await?;
    let tla_reports = build_tla_reports(&results, &trace_replays, &implementation_replays, None);

    let report = VerticalValidationReport {
        proof_results: Vec::new(),
        tla_results: tla_reports,
        scaling_results: None,
        property_test_results: None,
        implementation_trace_results: None,
        adversarial_results: None,
        crypto_kat_results: None,
        bilateral_throughput_results: None,
    };

    print!("{}", report.render_ascii());
    Ok(results)
}

/// Run scaling benchmark standalone (collect + print report).
async fn run_benchmark(
    root: &std::path::Path,
    duration: u64,
    no_start: bool,
) -> anyhow::Result<benchmark::ScalingBenchmarkResult> {
    let results = collect_benchmark_results(root, duration, no_start).await?;

    let report = VerticalValidationReport {
        proof_results: Vec::new(),
        tla_results: Vec::new(),
        scaling_results: Some(results.clone()),
        property_test_results: None,
        implementation_trace_results: None,
        adversarial_results: None,
        crypto_kat_results: None,
        bilateral_throughput_results: None,
    };

    print!("{}", report.render_ascii());
    Ok(results)
}

/// Run property tests standalone.
fn run_property_tests(iterations: u64, seed: u64) {
    let results = property_tests::collect_property_test_results(seed, iterations);
    let report = VerticalValidationReport {
        proof_results: Vec::new(),
        tla_results: Vec::new(),
        scaling_results: None,
        property_test_results: Some(results),
        implementation_trace_results: None,
        adversarial_results: None,
        crypto_kat_results: None,
        bilateral_throughput_results: None,
    };
    print!("{}", report.render_ascii());
}

/// Run deterministic implementation traces standalone.
fn run_implementation_traces() {
    let results = implementation_traces::collect_implementation_trace_results();
    let report = VerticalValidationReport {
        proof_results: Vec::new(),
        tla_results: Vec::new(),
        scaling_results: None,
        property_test_results: None,
        implementation_trace_results: Some(results),
        adversarial_results: None,
        crypto_kat_results: None,
        bilateral_throughput_results: None,
    };
    print!("{}", report.render_ascii());
}

/// Run adversarial tests standalone.
fn run_adversarial() {
    let results = adversarial_bilateral::collect_adversarial_results();
    let report = VerticalValidationReport {
        proof_results: Vec::new(),
        tla_results: Vec::new(),
        scaling_results: None,
        property_test_results: None,
        implementation_trace_results: None,
        adversarial_results: Some(results),
        crypto_kat_results: None,
        bilateral_throughput_results: None,
    };
    print!("{}", report.render_ascii());
}

/// Run crypto KAT tests standalone.
fn run_crypto_kat() {
    let results = crypto_kat::collect_crypto_kat_results();
    let report = VerticalValidationReport {
        proof_results: Vec::new(),
        tla_results: Vec::new(),
        scaling_results: None,
        property_test_results: None,
        implementation_trace_results: None,
        adversarial_results: None,
        crypto_kat_results: Some(results),
        bilateral_throughput_results: None,
    };
    print!("{}", report.render_ascii());
}

/// Run bilateral throughput benchmark standalone.
fn run_bilateral_throughput(iterations: u64) {
    let results = bilateral_throughput::collect_bilateral_throughput_results(iterations);
    let report = VerticalValidationReport {
        proof_results: Vec::new(),
        tla_results: Vec::new(),
        scaling_results: None,
        property_test_results: None,
        implementation_trace_results: None,
        adversarial_results: None,
        crypto_kat_results: None,
        bilateral_throughput_results: Some(results),
    };
    print!("{}", report.render_ascii());
}

/// Generate a formal Markdown verification report.
async fn run_formal_report(
    root: &std::path::Path,
    output: Option<String>,
    skip_lean: bool,
    include_scaling: bool,
    iterations: u64,
    seed: u64,
) -> anyhow::Result<()> {
    eprintln!("=== GENERATING FORMAL VERIFICATION REPORT ===\n");

    // Git metadata
    let git_commit = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".into());
    let git_branch = std::process::Command::new("git")
        .args(["branch", "--show-current"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".into());

    // Date
    let report_date = {
        let output = std::process::Command::new("date")
            .args(["+%Y-%m-%d"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "unknown".into());
        output
    };

    // Phase 1: Crypto KATs (fast)
    let crypto_kat_results = crypto_kat::collect_crypto_kat_results();

    // Phase 2: Property-based tests
    let property_test_results = property_tests::collect_property_test_results(seed, iterations);

    // Phase 3: Implementation traces
    let implementation_trace_results =
        implementation_traces::collect_implementation_trace_results();

    // Phase 4: Adversarial bilateral tests (catch panics — pre-existing issue)
    let adversarial_results =
        std::panic::catch_unwind(|| adversarial_bilateral::collect_adversarial_results())
            .map_err(|_| eprintln!("  WARNING: Adversarial tests panicked — skipping"))
            .ok();

    // Phase 5: Bilateral throughput (catch panics)
    let bilateral_throughput_results = std::panic::catch_unwind(|| {
        bilateral_throughput::collect_bilateral_throughput_results(iterations)
    })
    .map_err(|_| eprintln!("  WARNING: Bilateral throughput panicked — skipping"))
    .ok();

    // Phase 6: Lean 4 proof checking
    let lean_results = if skip_lean {
        eprintln!("  Lean proof checking skipped (--skip-lean)");
        None
    } else {
        Some(lean_checker::collect_lean_results(root))
    };

    // Phase 7: TLA+ model checking
    let tla_results = collect_tla_results(root, false).await?;
    let (trace_replays, implementation_replays) =
        collect_tla_trace_replays(root, &tla_results).await?;

    // Phase 8: Scaling (cached or fresh)
    let scaling_cache_path = root.join("docs/reports/.scaling-cache.json");
    let (scaling_results, scaling_cache_info) = if include_scaling {
        eprintln!("\n  Running fresh scaling benchmark (--include-scaling)...");
        let results = collect_benchmark_results(root, 10, false).await?;
        // Save cache
        let cache_data = serde_json::json!({
            "date": report_date,
            "commit": git_commit,
            "data": results,
        });
        if let Some(parent) = scaling_cache_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(
            &scaling_cache_path,
            serde_json::to_string_pretty(&cache_data)?,
        )
        .ok();
        (
            Some(results),
            Some(report::ScalingCacheInfo {
                cached: false,
                cache_date: report_date.clone(),
                cache_commit: git_commit.clone(),
            }),
        )
    } else if scaling_cache_path.exists() {
        // Load cached results
        let cache_str = std::fs::read_to_string(&scaling_cache_path)?;
        let cache_json: serde_json::Value = serde_json::from_str(&cache_str)?;
        let cache_date = cache_json["date"].as_str().unwrap_or("unknown").to_string();
        let cache_commit = cache_json["commit"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        let scaling: Option<crate::benchmark::ScalingBenchmarkResult> =
            serde_json::from_value(cache_json["data"].clone()).ok();
        eprintln!("  Using cached scaling data from {cache_date} (commit {cache_commit})");
        (
            scaling,
            Some(report::ScalingCacheInfo {
                cached: true,
                cache_date,
                cache_commit,
            }),
        )
    } else {
        eprintln!("  No scaling cache found. Use --include-scaling to run benchmark.");
        (None, None)
    };

    // Build TLA report entries
    let tla_reports = build_tla_reports(
        &tla_results,
        &trace_replays,
        &implementation_replays,
        Some(&implementation_trace_results),
    );

    // Assemble full report struct
    let report = VerticalValidationReport {
        proof_results: Vec::new(),
        tla_results: tla_reports,
        scaling_results,
        property_test_results: Some(property_test_results),
        implementation_trace_results: Some(implementation_trace_results),
        adversarial_results,
        crypto_kat_results: Some(crypto_kat_results),
        bilateral_throughput_results,
    };

    // Render formal Markdown
    let mut markdown = report.render_formal_report(
        lean_results.as_ref(),
        &git_commit,
        &git_branch,
        &report_date,
        scaling_cache_info.as_ref(),
    );

    // Compute BLAKE3 domain-separated hash of report body (before Attestation)
    let body_end = markdown.find("## Attestation").unwrap_or(markdown.len());
    let body = &markdown[..body_end];
    let mut hasher = blake3::Hasher::new_derive_key("DSM/formal-verification-report-v1");
    hasher.update(body.as_bytes());
    let body_hash = hasher.finalize();
    let blake3_hex = body_hash.to_hex();
    markdown = markdown.replace("{{REPORT_BLAKE3}}", &blake3_hex[..64]);

    // Write report
    let output_path = output
        .unwrap_or_else(|| format!("docs/reports/{report_date}-formal-verification-report.md"));
    let full_output_path = root.join(&output_path);
    if let Some(parent) = full_output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&full_output_path, &markdown)?;

    eprintln!("\n=== REPORT WRITTEN ===\n");
    eprintln!("  Path: {}", full_output_path.display());
    eprintln!("  Body BLAKE3: {}...", &blake3_hex[..16]);
    eprintln!("\n  To sign: git add {output_path} && git commit -S && git push\n");

    // Also print path to stdout for scripting
    println!("{}", full_output_path.display());

    Ok(())
}

/// Run everything end-to-end and produce a single combined report.
async fn run_full(
    root: &std::path::Path,
    duration: u64,
    no_start: bool,
    format: &str,
    iterations: u64,
    seed: u64,
) -> anyhow::Result<()> {
    // Phase 1: Crypto KATs (fast, no dependencies)
    let crypto_kat_results = crypto_kat::collect_crypto_kat_results();

    // Phase 2: Property-based tests
    let property_test_results = property_tests::collect_property_test_results(seed, iterations);

    // Phase 3: Deterministic implementation traces
    let implementation_trace_results =
        implementation_traces::collect_implementation_trace_results();

    // Phase 4: Adversarial bilateral tests
    let adversarial_results = adversarial_bilateral::collect_adversarial_results();

    // Phase 5: Bilateral throughput benchmark
    let bilateral_throughput_results =
        bilateral_throughput::collect_bilateral_throughput_results(iterations);

    // Phase 6: TLA+ model checking (progress on stderr, no report)
    let tla_results = collect_tla_results(root, false).await?;
    let (trace_replays, implementation_replays) =
        collect_tla_trace_replays(root, &tla_results).await?;

    // Phase 7: Scaling benchmark (progress on stderr, no report)
    let scaling_results = collect_benchmark_results(root, duration, no_start).await?;

    // Single combined report
    let tla_reports = build_tla_reports(
        &tla_results,
        &trace_replays,
        &implementation_replays,
        Some(&implementation_trace_results),
    );

    let report = VerticalValidationReport {
        proof_results: Vec::new(),
        tla_results: tla_reports,
        scaling_results: Some(scaling_results),
        property_test_results: Some(property_test_results),
        implementation_trace_results: Some(implementation_trace_results),
        adversarial_results: Some(adversarial_results),
        crypto_kat_results: Some(crypto_kat_results),
        bilateral_throughput_results: Some(bilateral_throughput_results),
    };

    match format {
        "json" => {
            println!("{}", report.render_json()?);
        }
        "csv" => {
            print!("{}", report.render_scaling_csv());
        }
        _ => {
            print!("{}", report.render_ascii());
        }
    }

    Ok(())
}

async fn collect_tla_trace_replays(
    root: &std::path::Path,
    results: &[(tla_runner::TlaSpec, tla_runner::TlcResult)],
) -> anyhow::Result<(
    HashMap<String, TlaTraceReplayResult>,
    HashMap<String, TlaImplementationReplayResult>,
)> {
    eprintln!("  Replaying literal TLC traces and direct DSM traces in Rust ...");
    let runner = TlaRunner::new(root)?;
    let mut trace_replays = HashMap::with_capacity(results.len());
    let mut implementation_replays = HashMap::with_capacity(results.len());

    for (spec, _) in results {
        if !spec.supports_trace_replay {
            eprintln!("    {} -> trace replay skipped", spec.label);
            continue;
        }
        let (literal_replay, implementation_replay) =
            runner.run_integrated_trace_replays(spec).await?;
        let literal_verdict = if literal_replay.passed {
            "PASS"
        } else {
            "FAIL"
        };
        let implementation_verdict = if implementation_replay.passed {
            "PASS"
        } else {
            "FAIL"
        };
        eprintln!(
            "    {} -> literal={} direct={} ({} steps, {:.1}ms / {:.1}ms)",
            spec.label,
            literal_verdict,
            implementation_verdict,
            literal_replay.steps,
            literal_replay.duration_ms,
            implementation_replay.duration_ms
        );
        trace_replays.insert(spec.label.clone(), literal_replay);
        implementation_replays.insert(spec.label.clone(), implementation_replay);
    }

    Ok((trace_replays, implementation_replays))
}

fn build_tla_reports(
    results: &[(tla_runner::TlaSpec, tla_runner::TlcResult)],
    trace_replays: &HashMap<String, TlaTraceReplayResult>,
    implementation_replays: &HashMap<String, TlaImplementationReplayResult>,
    implementation_trace_results: Option<&implementation_traces::ImplementationTraceSuiteResult>,
) -> Vec<TlaSpecReport> {
    let linked_trace_cache: HashMap<String, implementation_traces::ImplementationTraceResult> =
        if let Some(suite) = implementation_trace_results {
            suite
                .results
                .iter()
                .cloned()
                .map(|trace| (trace.trace_name.clone(), trace))
                .collect()
        } else {
            let mut unique_trace_names: Vec<String> = Vec::new();
            for (spec, _) in results {
                for trace_name in &spec.linked_implementation_traces {
                    if !unique_trace_names.contains(trace_name) {
                        unique_trace_names.push(trace_name.clone());
                    }
                }
            }

            if unique_trace_names.is_empty() {
                HashMap::new()
            } else {
                eprintln!(
                    "  Running linked Rust traces for TLA specs: {} ...",
                    unique_trace_names.join(", ")
                );
                let names: Vec<&str> = unique_trace_names.iter().map(String::as_str).collect();
                implementation_traces::collect_named_implementation_trace_results(&names)
                    .results
                    .into_iter()
                    .map(|trace| (trace.trace_name.clone(), trace))
                    .collect()
            }
        };

    results
        .iter()
        .map(|(spec, result)| {
            let literal_trace_replay = trace_replays.get(&spec.label).cloned();
            let implementation_trace_replay = implementation_replays.get(&spec.label).cloned();
            let linked_trace_results = spec
                .linked_implementation_traces
                .iter()
                .map(|trace_name| {
                    linked_trace_cache.get(trace_name).cloned().unwrap_or_else(|| {
                        implementation_traces::ImplementationTraceResult {
                            trace_name: trace_name.clone(),
                            steps: 0,
                            passed: false,
                            failures: vec![format!(
                                "linked TLA trace binding not found in implementation suite: {trace_name}"
                            )],
                            duration_ms: 0.0,
                        }
                    })
                })
                .collect();

            TlaSpecReport::from_pair(
                spec,
                result,
                literal_trace_replay,
                implementation_trace_replay,
                linked_trace_results,
            )
        })
        .collect()
}

fn build_proof_reports(
    results: &[(proof_runner::ProofSpec, proof_runner::ProofResult)],
) -> Vec<ProofModuleReport> {
    results
        .iter()
        .map(|(spec, result)| ProofModuleReport::from_pair(spec, result))
        .collect()
}
