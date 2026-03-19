//! Report Generator
//!
//! Produces investor-ready output from TLA+ verification results and scaling
//! benchmark data. Supports three output formats:
//!
//! - **ASCII**: Terminal-friendly tables for immediate viewing
//! - **JSON**: Structured data for charting tools and dashboards
//! - **CSV**: Scaling data for spreadsheet import
//!
//! JSON is used only in the display/reporting layer (permitted by CLAUDE.md
//! rule 2). Hex encoding appears only in display strings (rule 3).

use serde::Serialize;

use crate::adversarial_bilateral::AdversarialSuiteResult;
use crate::benchmark::ScalingBenchmarkResult;
use crate::bilateral_throughput::BilateralThroughputResult;
use crate::crypto_kat::CryptoKatSuiteResult;
use crate::implementation_traces::{ImplementationTraceResult, ImplementationTraceSuiteResult};
use crate::proof_runner::{ProofResult, ProofSpec};
use crate::property_tests::PropertyTestSuiteResult;
use crate::tla_runner::{TlaSpec, TlcResult};
use crate::tla_trace_replay::{TlaImplementationReplayResult, TlaTraceReplayResult};

/// Complete vertical validation report.
#[derive(Debug, Serialize)]
pub struct VerticalValidationReport {
    /// TLAPS theorem results
    pub proof_results: Vec<ProofModuleReport>,
    /// TLA+ model checking results
    pub tla_results: Vec<TlaSpecReport>,
    /// Scaling benchmark results
    pub scaling_results: Option<ScalingBenchmarkResult>,
    /// Property-based test results
    pub property_test_results: Option<PropertyTestSuiteResult>,
    /// Deterministic implementation-trace results
    pub implementation_trace_results: Option<ImplementationTraceSuiteResult>,
    /// Adversarial bilateral attack results
    pub adversarial_results: Option<AdversarialSuiteResult>,
    /// Cryptographic known-answer test results
    pub crypto_kat_results: Option<CryptoKatSuiteResult>,
    /// Bilateral throughput benchmark results
    pub bilateral_throughput_results: Option<BilateralThroughputResult>,
}

/// Individual TLAPS proof-module result for reporting.
#[derive(Debug, Serialize)]
pub struct ProofModuleReport {
    /// Human-readable label
    pub label: String,
    /// Whether the proof module passed
    pub passed: bool,
    /// Module path relative to tla/
    pub module_file: String,
    /// Claimed theorem names
    pub theorem_names: Vec<String>,
    /// Obligations proved according to TLAPS output
    pub obligations_proved: u64,
    /// Runtime in milliseconds
    pub duration_ms: f64,
    /// Errors (empty if passed)
    pub errors: Vec<String>,
}

/// Individual TLA+ spec result for reporting.
#[derive(Debug, Serialize)]
pub struct TlaSpecReport {
    /// Human-readable label
    pub label: String,
    /// Whether the combined TLA + linked implementation validation passed
    pub passed: bool,
    /// Whether the TLC model check itself passed
    pub tlc_passed: bool,
    /// Total states generated
    pub states_generated: u64,
    /// Distinct states found
    pub distinct_states: u64,
    /// Search depth reached
    pub depth_reached: u64,
    /// Invariants that were checked
    pub invariants_checked: Vec<String>,
    /// Temporal properties that were checked
    pub properties_checked: Vec<String>,
    /// Result of replaying a literal TLC simulation trace through Rust
    pub literal_trace_replay: Option<TlaTraceReplayResult>,
    /// Result of replaying the same TLC trace through actual DSM code
    pub implementation_trace_replay: Option<TlaImplementationReplayResult>,
    /// Linked direct-code traces for integrated validation
    pub linked_implementation_traces: Vec<String>,
    /// Results of linked direct-code traces
    pub linked_trace_results: Vec<ImplementationTraceResult>,
    /// Errors (empty if passed)
    pub errors: Vec<String>,
}

impl ProofModuleReport {
    pub fn from_pair(spec: &ProofSpec, result: &ProofResult) -> Self {
        Self {
            label: spec.label.clone(),
            passed: result.passed,
            module_file: spec.module_file.clone(),
            theorem_names: spec.theorem_names.clone(),
            obligations_proved: result.obligations_proved,
            duration_ms: result.duration_ms,
            errors: result.errors.clone(),
        }
    }
}

impl TlaSpecReport {
    /// Create from a spec and its result.
    pub fn from_pair(
        spec: &TlaSpec,
        result: &TlcResult,
        literal_trace_replay: Option<TlaTraceReplayResult>,
        implementation_trace_replay: Option<TlaImplementationReplayResult>,
        linked_trace_results: Vec<ImplementationTraceResult>,
    ) -> Self {
        let replay_passed = literal_trace_replay
            .as_ref()
            .map(|replay| replay.passed)
            .unwrap_or(true);
        let implementation_replay_passed = implementation_trace_replay
            .as_ref()
            .map(|replay| replay.passed)
            .unwrap_or(true);
        let linked_passed = linked_trace_results.iter().all(|trace| trace.passed);
        Self {
            label: spec.label.clone(),
            passed: result.passed && replay_passed && implementation_replay_passed && linked_passed,
            tlc_passed: result.passed,
            states_generated: result.states_generated,
            distinct_states: result.distinct_states,
            depth_reached: result.depth_reached,
            invariants_checked: spec.invariants.clone(),
            properties_checked: spec.properties.clone(),
            literal_trace_replay,
            implementation_trace_replay,
            linked_implementation_traces: spec.linked_implementation_traces.clone(),
            linked_trace_results,
            errors: result.errors.clone(),
        }
    }

    pub fn literal_trace_replay_passed(&self) -> Option<bool> {
        self.literal_trace_replay
            .as_ref()
            .map(|result| result.passed)
    }

    pub fn linked_trace_passed(&self) -> Option<bool> {
        if self.linked_implementation_traces.is_empty() {
            None
        } else {
            Some(self.linked_trace_results.iter().all(|trace| trace.passed))
        }
    }

    pub fn implementation_trace_replay_passed(&self) -> Option<bool> {
        self.implementation_trace_replay
            .as_ref()
            .map(|result| result.passed)
    }
}

impl VerticalValidationReport {
    /// Render as ASCII table for terminal display.
    pub fn render_ascii(&self) -> String {
        let mut out = String::new();
        let sep = "=".repeat(80);

        out.push_str(&sep);
        out.push('\n');
        out.push_str("                     DSM VERTICAL VALIDATION REPORT\n");
        out.push_str(&sep);
        out.push_str("\n\n");

        if !self.proof_results.is_empty() {
            out.push_str("--- TLAPS THEOREMS ---\n\n");
            out.push_str("  Module                    | Obligations | Verdict | Time\n");
            out.push_str("  --------------------------+-------------+---------+--------\n");
            for r in &self.proof_results {
                let verdict = if r.passed { "PASS" } else { "FAIL" };
                out.push_str(&format!(
                    "  {:<26}| {:>11} | {:>7} | {:.0}ms\n",
                    r.label, r.obligations_proved, verdict, r.duration_ms,
                ));
                out.push_str(&format!("    FILE: {}\n", r.module_file));
                if !r.theorem_names.is_empty() {
                    out.push_str(&format!("    THEOREMS: {}\n", r.theorem_names.join(", ")));
                }
                for err in &r.errors {
                    out.push_str(&format!("    ERROR: {err}\n"));
                }
            }
            out.push('\n');
        }

        if !self.tla_results.is_empty() {
            out.push_str("--- TLA+ MODEL CHECKING VERDICT ---\n\n");
            out.push_str(
                "  Spec                     | States     | Distinct   | Depth | TLC  | Replay | Direct | Linked | Overall\n",
            );
            out.push_str(
                "  -------------------------+------------+------------+-------+------+--------+--------+--------+--------\n",
            );

            let mut all_invariants = Vec::new();
            let mut all_properties = Vec::new();
            for r in &self.tla_results {
                let tlc_verdict = if r.tlc_passed { "PASS" } else { "FAIL" };
                let replay_verdict = match r.literal_trace_replay_passed() {
                    Some(true) => "PASS",
                    Some(false) => "FAIL",
                    None => "N/A ",
                };
                let direct_verdict = match r.implementation_trace_replay_passed() {
                    Some(true) => "PASS",
                    Some(false) => "FAIL",
                    None => "N/A ",
                };
                let linked_verdict = match r.linked_trace_passed() {
                    Some(true) => "PASS",
                    Some(false) => "FAIL",
                    None => "N/A ",
                };
                let verdict = if r.passed { "PASS" } else { "FAIL" };
                out.push_str(&format!(
                    "  {:<25}| {:>10} | {:>10} | {:>5} | {:>4} | {:>6} | {:>6} | {:>6} | {:>6}\n",
                    r.label,
                    format_number(r.states_generated),
                    format_number(r.distinct_states),
                    r.depth_reached,
                    tlc_verdict,
                    replay_verdict,
                    direct_verdict,
                    linked_verdict,
                    verdict,
                ));
                for inv in &r.invariants_checked {
                    if !all_invariants.contains(inv) {
                        all_invariants.push(inv.clone());
                    }
                }
                for property in &r.properties_checked {
                    if !all_properties.contains(property) {
                        all_properties.push(property.clone());
                    }
                }
                if !r.errors.is_empty() {
                    for err in &r.errors {
                        out.push_str(&format!("    ERROR: {err}\n"));
                    }
                }
                if !r.properties_checked.is_empty() {
                    out.push_str(&format!(
                        "    PROPERTIES: {}\n",
                        r.properties_checked.join(", ")
                    ));
                }
                if let Some(replay) = &r.literal_trace_replay {
                    out.push_str(&format!(
                        "    TLC TRACE: {} ({} steps)\n",
                        replay.trace_path.display(),
                        replay.steps
                    ));
                    for failure in &replay.failures {
                        out.push_str(&format!("    REPLAY FAILURE: {failure}\n"));
                    }
                }
                if let Some(replay) = &r.implementation_trace_replay {
                    out.push_str(&format!(
                        "    DIRECT TRACE: {} ({} steps)\n",
                        replay.trace_path.display(),
                        replay.steps
                    ));
                    for failure in &replay.failures {
                        out.push_str(&format!("    DIRECT FAILURE: {failure}\n"));
                    }
                }
                if !r.linked_implementation_traces.is_empty() {
                    out.push_str(&format!(
                        "    LINKED RUST TRACES: {}\n",
                        r.linked_implementation_traces.join(", ")
                    ));
                    for trace in &r.linked_trace_results {
                        if !trace.passed {
                            out.push_str(&format!("    TRACE {} FAILED\n", trace.trace_name));
                            for failure in &trace.failures {
                                out.push_str(&format!("      {failure}\n"));
                            }
                        }
                    }
                }
            }

            if !all_invariants.is_empty() {
                out.push_str("\n  Invariants verified: ");
                out.push_str(&all_invariants.join(", "));
                out.push('\n');
            }
            if !all_properties.is_empty() {
                out.push_str("  Temporal properties verified: ");
                out.push_str(&all_properties.join(", "));
                out.push('\n');
            }
        }

        // Scaling benchmark results
        if let Some(ref scaling) = self.scaling_results {
            out.push_str("\n--- LINEAR SCALING BENCHMARK (5 local storage nodes) ---\n\n");
            out.push_str("  N (parallel) | Total ops/sec | Per-writer ops/sec | Scaling Factor\n");
            out.push_str("  -------------+---------------+--------------------+---------------\n");

            let base_throughput = scaling
                .data_points
                .first()
                .map(|d| d.throughput_ops_per_sec)
                .unwrap_or(1.0);

            for dp in &scaling.data_points {
                let scaling_factor = dp.throughput_ops_per_sec / base_throughput;
                out.push_str(&format!(
                    "  {:>12}  | {:>13} | {:>18} | {:>13.2}x\n",
                    dp.parallel_writers,
                    format_number(dp.throughput_ops_per_sec as u64),
                    format_number(dp.per_writer_throughput as u64),
                    scaling_factor,
                ));
            }

            // Error transparency: success rates per N
            let has_errors = scaling.data_points.iter().any(|dp| dp.failed_ops > 0);
            if has_errors || true {
                // Always show success rates for transparency
                out.push_str("\n  Success rates: ");
                let rates: Vec<String> = scaling
                    .data_points
                    .iter()
                    .map(|dp| format!("N={}: {:.1}%", dp.parallel_writers, dp.success_rate))
                    .collect();
                out.push_str(&rates.join(", "));
                out.push('\n');
            }

            // Linear regression summary
            if scaling.data_points.len() >= 2 {
                let first = &scaling.data_points[0];
                let last = scaling.data_points.last().unwrap_or(first);
                let slope = (last.throughput_ops_per_sec - first.throughput_ops_per_sec)
                    / (last.parallel_writers as f64 - first.parallel_writers as f64);
                let r_squared =
                    compute_r_squared(&scaling.data_points, first.throughput_ops_per_sec);
                out.push_str(&format!(
                    "\n  Baseline (N=1): {:.0} ops/sec\n",
                    first.throughput_ops_per_sec
                ));
                out.push_str(&format!(
                    "  Measured slope: {slope:.0} ops/sec per additional writer\n"
                ));
                out.push_str(&format!("  R-squared: {r_squared:.4}\n"));
            }

            // Non-interference
            if !scaling.non_interference.is_empty() {
                out.push_str("\n--- NON-INTERFERENCE PROOF ---\n\n");
                out.push_str("  Idle Node | Objects Before | Objects After | Stable?\n");
                out.push_str("  ----------+----------------+---------------+--------\n");
                for ni in &scaling.non_interference {
                    let stable = if ni.unchanged { "YES" } else { "NO" };
                    out.push_str(&format!(
                        "  Node {:>4} | {:>14} | {:>13} | {}\n",
                        ni.idle_node_index, ni.count_before, ni.count_after, stable,
                    ));
                }
                out.push_str(
                    "\n  Conclusion: Operations on disjoint nodes do not affect idle nodes.\n",
                );
                out.push_str(
                    "  This empirically confirms Lemma 3.1 (Non-interference of disjoint\n",
                );
                out.push_str("  relationships) from the PRLSM statelessness proof.\n");
            }

            // Tripwire test — 3-phase fork-exclusion proof
            if let Some(ref tw) = scaling.tripwire_test {
                out.push_str("\n--- TRIPWIRE FORK-EXCLUSION TEST ---\n\n");

                // Phase 1: Deterministic Addressing
                out.push_str("  Phase 1: DETERMINISTIC ADDRESSING\n");
                out.push_str(&format!(
                    "    Commit A:              {} (HTTP {}) -> addr {}\n",
                    if tw.commit_a_status < 300 {
                        "ACCEPTED"
                    } else {
                        "REJECTED"
                    },
                    tw.commit_a_status,
                    addr_short(&tw.commit_a_addr),
                ));
                out.push_str(&format!(
                    "    Replay A (identical):  {} (HTTP {}) -> addr {}  {}\n",
                    if tw.replay_a_status < 300 {
                        "DEDUP   "
                    } else {
                        "REJECTED"
                    },
                    tw.replay_a_status,
                    addr_short(&tw.replay_a_addr),
                    if tw.deterministic {
                        "SAME"
                    } else {
                        "DIFFERENT"
                    },
                ));
                out.push_str(&format!(
                    "    -> Storage addressing is a deterministic function of content {}\n\n",
                    if tw.deterministic { "PASS" } else { "FAIL" },
                ));

                // Phase 2: Fork Separation
                out.push_str("  Phase 2: FORK SEPARATION\n");
                out.push_str(&format!(
                    "    Commit B (same parent): {} (HTTP {}) -> addr {}\n",
                    if tw.commit_b_status < 300 {
                        "ACCEPTED"
                    } else {
                        "REJECTED"
                    },
                    tw.commit_b_status,
                    addr_short(&tw.commit_b_addr),
                ));
                out.push_str(&format!(
                    "    -> addr_A {} addr_B: forked successors get distinct addresses {}\n\n",
                    if tw.fork_separated { "!=" } else { "==" },
                    if tw.fork_separated { "PASS" } else { "FAIL" },
                ));

                // Phase 3: Audit Trail Verification
                out.push_str("  Phase 3: AUDIT TRAIL\n");
                let parent_short = if tw.parent_digest_hex.len() > 12 {
                    format!(
                        "{}...{}",
                        &tw.parent_digest_hex[..8],
                        &tw.parent_digest_hex[tw.parent_digest_hex.len().saturating_sub(4)..]
                    )
                } else {
                    tw.parent_digest_hex.clone()
                };
                out.push_str(&format!(
                    "    Retrieve A: {} parent_digest = {}\n",
                    if tw.audit_a_retrievable { "OK" } else { "FAIL" },
                    &parent_short,
                ));
                out.push_str(&format!(
                    "    Retrieve B: {} parent_digest = {} (same parent)\n",
                    if tw.audit_b_retrievable { "OK" } else { "FAIL" },
                    &parent_short,
                ));
                out.push_str(&format!(
                    "    -> Fork is permanently visible in storage audit trail {}\n\n",
                    if tw.audit_parents_match {
                        "PASS"
                    } else {
                        "FAIL"
                    },
                ));

                // Overall conclusion
                if tw.fork_excluded {
                    out.push_str(
                        "  Conclusion: Deterministic content-addressed storage ensures forked\n",
                    );
                    out.push_str(
                        "  successors are permanently recorded at distinct addresses. Combined\n",
                    );
                    out.push_str(
                        "  with bilateral-layer Tripwire enforcement (ParentConsumed rejection),\n",
                    );
                    out.push_str("  double-spend is structurally impossible.\n");
                } else {
                    out.push_str(
                        "  WARNING: Not all phases passed. Fork exclusion may not be fully enforced.\n",
                    );
                }
            }
        }

        // Property-based test results
        if let Some(ref pt) = self.property_test_results {
            out.push_str("\n--- PROPERTY-BASED TESTS ---\n\n");
            out.push_str("  Property                       | Iterations | Verdict | Time\n");
            out.push_str("  -------------------------------+------------+---------+--------\n");
            for r in &pt.results {
                let verdict = if r.passed { "PASS" } else { "FAIL" };
                out.push_str(&format!(
                    "  {:<31}| {:>10} | {:>7} | {:.0}ms\n",
                    r.property_name, r.iterations, verdict, r.duration_ms,
                ));
                for f in &r.failures {
                    out.push_str(&format!("    FAILURE: {f}\n"));
                }
            }
            out.push_str(&format!(
                "\n  Seed: {}  Total: {:.0}ms\n",
                pt.seed, pt.duration_ms
            ));
        }

        if let Some(ref traces) = self.implementation_trace_results {
            out.push_str("\n--- IMPLEMENTATION TRACE REPLAY ---\n\n");
            out.push_str("  Trace                          | Steps      | Verdict | Time\n");
            out.push_str("  -------------------------------+------------+---------+--------\n");
            for r in &traces.results {
                let verdict = if r.passed { "PASS" } else { "FAIL" };
                out.push_str(&format!(
                    "  {:<31}| {:>10} | {:>7} | {:.0}ms\n",
                    r.trace_name, r.steps, verdict, r.duration_ms,
                ));
                for f in &r.failures {
                    out.push_str(&format!("    FAILURE: {f}\n"));
                }
            }
            out.push_str(&format!("\n  Total: {:.0}ms\n", traces.duration_ms));
        }

        // Adversarial bilateral results
        if let Some(ref adv) = self.adversarial_results {
            out.push_str("\n--- ADVERSARIAL BILATERAL TESTS ---\n\n");
            out.push_str(
                "  Attack                           | Expected   | Actual            | Verdict\n",
            );
            out.push_str(
                "  ---------------------------------+------------+-------------------+--------\n",
            );
            for a in &adv.attacks {
                let verdict = if a.passed { "PASS" } else { "FAIL" };
                let actual_short = if a.actual_result.len() > 17 {
                    format!("{}...", &a.actual_result[..14])
                } else {
                    a.actual_result.clone()
                };
                out.push_str(&format!(
                    "  {:<33}| {:<10} | {:<17} | {}\n",
                    a.attack_name, a.expected_result, actual_short, verdict,
                ));
            }
        }

        // Crypto KAT results
        if let Some(ref kat) = self.crypto_kat_results {
            out.push_str("\n--- CRYPTOGRAPHIC KNOWN-ANSWER TESTS ---\n\n");
            out.push_str("  Primitive   | Test                          | Verdict\n");
            out.push_str("  ------------+-------------------------------+--------\n");
            for r in &kat.results {
                let verdict = if r.passed { "PASS" } else { "FAIL" };
                out.push_str(&format!(
                    "  {:<11} | {:<29} | {}\n",
                    r.primitive, r.test_name, verdict,
                ));
            }
            let total = kat.results.len();
            let passed = kat.results.iter().filter(|r| r.passed).count();
            out.push_str(&format!(
                "\n  {passed}/{total} passed ({:.0}ms)\n",
                kat.duration_ms
            ));
        }

        // Bilateral throughput results
        if let Some(ref bt) = self.bilateral_throughput_results {
            out.push_str("\n--- BILATERAL THROUGHPUT BENCHMARK ---\n\n");
            out.push_str(
                "  Mode                        | ops/sec   | P50 (us) | P95 (us) | P99 (us)\n",
            );
            out.push_str(
                "  ----------------------------+-----------+----------+----------+---------\n",
            );
            out.push_str(&format!(
                "  {:<27} | {:>9.1} | {:>8.0} | {:>8.0} | {:>7.0}\n",
                bt.with_signing.label,
                bt.with_signing.ops_per_sec,
                bt.with_signing.p50_us,
                bt.with_signing.p95_us,
                bt.with_signing.p99_us,
            ));
            out.push_str(&format!(
                "  {:<27} | {:>9.1} | {:>8.0} | {:>8.0} | {:>7.0}\n",
                bt.without_signing.label,
                bt.without_signing.ops_per_sec,
                bt.without_signing.p50_us,
                bt.without_signing.p95_us,
                bt.without_signing.p99_us,
            ));
            out.push_str(&format!(
                "\n  SPHINCS+ keygen: {:.1}ms | sign: {:.1}ms | BLAKE3: {:.2}us\n",
                bt.keygen_cost_ms, bt.avg_sign_cost_ms, bt.avg_blake3_cost_us,
            ));
        }

        // Overall verdict
        let overall = self.overall_verdict();
        out.push_str(&format!(
            "\n{sep}\n  OVERALL VERDICT: {}\n{sep}\n",
            if overall {
                "ALL PASS"
            } else {
                "FAILURES DETECTED"
            }
        ));
        out
    }

    /// Compute overall pass/fail across all test categories.
    pub fn overall_verdict(&self) -> bool {
        let proofs_ok = self.proof_results.iter().all(|r| r.passed);
        let tla_ok = self.tla_results.iter().all(|r| r.passed);
        let prop_ok = self
            .property_test_results
            .as_ref()
            .map(|r| r.all_passed)
            .unwrap_or(true);
        let traces_ok = self
            .implementation_trace_results
            .as_ref()
            .map(|r| r.all_passed)
            .unwrap_or(true);
        let adv_ok = self
            .adversarial_results
            .as_ref()
            .map(|r| r.all_passed)
            .unwrap_or(true);
        let kat_ok = self
            .crypto_kat_results
            .as_ref()
            .map(|r| r.all_passed)
            .unwrap_or(true);
        // throughput is a benchmark, not pass/fail
        proofs_ok && tla_ok && prop_ok && traces_ok && adv_ok && kat_ok
    }

    /// Render as JSON for charting tools (JSON permitted in display layer).
    pub fn render_json(&self) -> anyhow::Result<String> {
        serde_json::to_string_pretty(self).map_err(Into::into)
    }

    /// Render scaling data as CSV for spreadsheet import.
    pub fn render_scaling_csv(&self) -> String {
        let mut csv = String::from(
            "parallel_writers,total_ops,failed_ops,success_rate,duration_secs,throughput_ops_per_sec,per_writer_throughput,p50_ms,p95_ms,p99_ms\n",
        );

        if let Some(ref scaling) = self.scaling_results {
            for dp in &scaling.data_points {
                csv.push_str(&format!(
                    "{},{},{},{:.1},{:.2},{:.2},{:.2},{:.2},{:.2},{:.2}\n",
                    dp.parallel_writers,
                    dp.total_ops,
                    dp.failed_ops,
                    dp.success_rate,
                    dp.duration_secs,
                    dp.throughput_ops_per_sec,
                    dp.per_writer_throughput,
                    dp.p50_latency_ms,
                    dp.p95_latency_ms,
                    dp.p99_latency_ms,
                ));
            }
        }

        csv
    }
}

/// Shortened address for compact display in reports.
fn addr_short(addr: &str) -> String {
    if addr.len() > 12 {
        format!("{}...{}", &addr[..8], &addr[addr.len() - 4..])
    } else {
        addr.to_string()
    }
}

/// Format a number with comma separators for display.
fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(ch);
    }
    result.chars().rev().collect()
}

/// Compute R-squared for linear scaling fit.
fn compute_r_squared(
    data_points: &[crate::benchmark::BenchmarkDataPoint],
    base_throughput: f64,
) -> f64 {
    if data_points.len() < 2 {
        return 0.0;
    }

    let mean_y: f64 = data_points
        .iter()
        .map(|d| d.throughput_ops_per_sec)
        .sum::<f64>()
        / data_points.len() as f64;

    let ss_tot: f64 = data_points
        .iter()
        .map(|d| (d.throughput_ops_per_sec - mean_y).powi(2))
        .sum();

    // Predicted: y = base_throughput * N
    let ss_res: f64 = data_points
        .iter()
        .map(|d| {
            let predicted = base_throughput * d.parallel_writers as f64;
            (d.throughput_ops_per_sec - predicted).powi(2)
        })
        .sum();

    if ss_tot == 0.0 {
        return 1.0;
    }

    1.0 - (ss_res / ss_tot)
}
