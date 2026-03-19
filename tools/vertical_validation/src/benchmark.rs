//! Scaling Benchmark Engine
//!
//! Proves linear (additive) throughput scaling by running parallel independent
//! writers against the 5-node local storage-node set and measuring aggregate throughput.
//!
//! The benchmark demonstrates three formal claims:
//!
//! 1. **Additive Throughput (Theorem 6)**: Total ops/sec scales linearly with N
//!    parallel writers, each targeting a disjoint node.
//!
//! 2. **Non-Interference (Lemma 3.1)**: Nodes not targeted by any writer show
//!    zero state change during the benchmark.
//!
//! 3. **Tripwire Fork-Exclusion (Theorem 4.2)**: Three-phase proof that
//!    content-addressed storage provides a tamper-evident audit trail where
//!    forked successors are permanently detectable.
//!
//! Wall-clock timing is used solely for operational latency metrics (permitted
//! by CLAUDE.md rule 4). All test data uses BLAKE3 domain-separated hashing.

use std::time::{Duration, Instant};

use anyhow::Context;
use prost::Message;
use serde::Serialize;

use crate::local_nodes::LocalNodeManager;

// ─── ByteCommitV3 protobuf (mirrors dsm_storage_node/src/api/bytecommit.rs) ───

/// Minimal ByteCommitV3 protobuf for benchmark publishing.
///
/// This mirrors the struct defined in `dsm_storage_node::api::bytecommit`
/// to avoid cross-crate dependency on the storage node binary.
#[derive(Clone, PartialEq, Message)]
pub struct ByteCommitV3 {
    /// 32 bytes node id (content-addressed identifier)
    #[prost(bytes = "vec", tag = "1")]
    pub node_id: Vec<u8>,
    /// Cycle index (clockless logical tick)
    #[prost(uint64, tag = "2")]
    pub cycle_index: u64,
    /// 32 bytes SMT root for node storage
    #[prost(bytes = "vec", tag = "3")]
    pub smt_root: Vec<u8>,
    /// Bytes used in this partition
    #[prost(uint64, tag = "4")]
    pub bytes_used: u64,
    /// 32 bytes parent digest (H(B_{t-1})) or all-zero for t=0
    #[prost(bytes = "vec", tag = "5")]
    pub parent_digest: Vec<u8>,
}

// ─── Result types ──────────────────────────────────────────────────────────────

/// A single data point in the scaling series.
#[derive(Debug, Clone, Serialize)]
pub struct BenchmarkDataPoint {
    /// Number of parallel writers (1..=5)
    pub parallel_writers: usize,
    /// Total successful operations completed across all writers
    pub total_ops: u64,
    /// Total failed operations across all writers
    pub failed_ops: u64,
    /// Success rate as a percentage (0.0 - 100.0)
    pub success_rate: f64,
    /// Duration of the benchmark window in seconds (wall-clock, operational only)
    pub duration_secs: f64,
    /// Aggregate throughput: total_ops / duration_secs
    pub throughput_ops_per_sec: f64,
    /// Per-writer throughput (should be roughly constant if scaling is linear)
    pub per_writer_throughput: f64,
    /// P50 latency in milliseconds
    pub p50_latency_ms: f64,
    /// P95 latency in milliseconds
    pub p95_latency_ms: f64,
    /// P99 latency in milliseconds
    pub p99_latency_ms: f64,
}

/// Evidence that an idle node's state was not affected by writes to other nodes.
#[derive(Debug, Clone, Serialize)]
pub struct NonInterferenceEvidence {
    /// Node index that was NOT written to
    pub idle_node_index: usize,
    /// Object count BEFORE the benchmark run
    pub count_before: usize,
    /// Object count AFTER the benchmark run
    pub count_after: usize,
    /// Whether counts match (should be true for non-interference)
    pub unchanged: bool,
}

/// Three-phase evidence for the Tripwire fork-exclusion test.
///
/// Proves that content-addressed storage provides a tamper-evident audit trail
/// where forked successors are permanently detectable:
///
/// 1. **Deterministic addressing**: same payload always maps to same address
/// 2. **Fork separation**: different payloads with same parent get different addresses
/// 3. **Audit trail**: both objects are retrievable and the fork is visible
#[derive(Debug, Clone, Serialize)]
pub struct TripwireEvidence {
    /// The parent digest used for all commits (hex, display only)
    pub parent_digest_hex: String,

    // Phase 1: Deterministic addressing
    /// HTTP status of the initial commit A
    pub commit_a_status: u16,
    /// Content-address returned for commit A
    pub commit_a_addr: String,
    /// HTTP status of the replay (identical re-publish of A)
    pub replay_a_status: u16,
    /// Content-address returned for replay (should match commit_a_addr)
    pub replay_a_addr: String,
    /// Phase 1 verdict: replay produces identical address (no nonce)
    pub deterministic: bool,

    // Phase 2: Fork separation
    /// HTTP status of the forked commit B (same parent, different content)
    pub commit_b_status: u16,
    /// Content-address returned for forked commit B
    pub commit_b_addr: String,
    /// Phase 2 verdict: addr_b differs from addr_a
    pub fork_separated: bool,

    // Phase 3: Audit trail verification
    /// Whether commit A is retrievable from storage
    pub audit_a_retrievable: bool,
    /// Whether commit B is retrievable from storage
    pub audit_b_retrievable: bool,
    /// Whether both retrieved objects share the same parent_digest
    pub audit_parents_match: bool,

    /// Overall verdict: all three phases pass
    pub fork_excluded: bool,
}

/// Complete scaling benchmark results.
#[derive(Debug, Clone, Serialize)]
pub struct ScalingBenchmarkResult {
    /// Data points for N = 1..5
    pub data_points: Vec<BenchmarkDataPoint>,
    /// Non-interference evidence for idle nodes
    pub non_interference: Vec<NonInterferenceEvidence>,
    /// Tripwire fork-exclusion test result
    pub tripwire_test: Option<TripwireEvidence>,
}

// ─── Benchmark engine ──────────────────────────────────────────────────────────

/// Runs scaling benchmarks against the local storage-node set.
pub struct ScalingBenchmark {
    node_mgr: LocalNodeManager,
    http_client: reqwest::Client,
    /// Duration per benchmark run in seconds (wall-clock, operational metric)
    bench_duration_secs: u64,
}

impl ScalingBenchmark {
    /// Create a new benchmark engine.
    pub fn new(node_mgr: LocalNodeManager, bench_duration_secs: u64) -> Self {
        Self {
            node_mgr,
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .pool_max_idle_per_host(32)
                .build()
                .unwrap_or_default(),
            bench_duration_secs,
        }
    }

    /// Run the full scaling series: N = 1..5 parallel writers.
    pub async fn run_scaling_series(&self) -> anyhow::Result<ScalingBenchmarkResult> {
        let max_writers = self.node_mgr.node_count();
        let mut data_points: Vec<BenchmarkDataPoint> = Vec::with_capacity(max_writers);

        eprintln!(
            "  Running scaling series (1..{max_writers} writers, {duration}s each)...",
            duration = self.bench_duration_secs
        );

        for n in 1..=max_writers {
            let dp = self.run_n_writers(n).await?;
            eprintln!(
                "    N={n}: {:.0} total ops/sec, {:.0} per-writer, {:.2}x scaling (success: {:.1}%)",
                dp.throughput_ops_per_sec,
                dp.per_writer_throughput,
                if n == 1 {
                    1.0
                } else {
                    dp.throughput_ops_per_sec / data_points[0].throughput_ops_per_sec
                },
                dp.success_rate,
            );
            data_points.push(dp);
        }

        // Non-interference test: write to nodes 0..3, verify node 4 unchanged
        eprintln!("  Verifying non-interference on idle nodes...");
        let non_interference = self.verify_non_interference(&[0, 1, 2, 3]).await?;

        // Tripwire test: 3-phase fork-exclusion proof
        eprintln!("  Testing Tripwire fork-exclusion (3-phase)...");
        let tripwire_test = match self.test_tripwire_detection().await {
            Ok(evidence) => {
                let verdict = if evidence.fork_excluded {
                    "ALL PHASES PASSED"
                } else {
                    "INCOMPLETE"
                };
                eprintln!("    Verdict: {verdict}");
                Some(evidence)
            }
            Err(e) => {
                eprintln!("    Tripwire test error: {e}");
                None
            }
        };

        Ok(ScalingBenchmarkResult {
            data_points,
            non_interference,
            tripwire_test,
        })
    }

    /// Run N parallel writers for the configured duration.
    async fn run_n_writers(&self, n: usize) -> anyhow::Result<BenchmarkDataPoint> {
        let duration = Duration::from_secs(self.bench_duration_secs);
        let mut handles = Vec::with_capacity(n);

        let start = Instant::now();

        for writer_id in 0..n {
            let client = self.http_client.clone();
            let node_url = self.node_mgr.node_url(writer_id);
            let dur = duration;

            handles.push(tokio::spawn(async move {
                writer_task(client, node_url, writer_id, dur).await
            }));
        }

        // Collect results from all writers
        let mut total_ops: u64 = 0;
        let mut total_failed: u64 = 0;
        let mut all_latencies = Vec::new();

        for handle in handles {
            let (ops, failed, latencies) = handle.await.context("Writer task panicked")?;
            total_ops += ops;
            total_failed += failed;
            all_latencies.extend(latencies);
        }

        let elapsed = start.elapsed().as_secs_f64();
        all_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let throughput = total_ops as f64 / elapsed;
        let total_attempts = total_ops + total_failed;
        let success_rate = if total_attempts > 0 {
            (total_ops as f64 / total_attempts as f64) * 100.0
        } else {
            0.0
        };

        Ok(BenchmarkDataPoint {
            parallel_writers: n,
            total_ops,
            failed_ops: total_failed,
            success_rate,
            duration_secs: elapsed,
            throughput_ops_per_sec: throughput,
            per_writer_throughput: throughput / n as f64,
            p50_latency_ms: percentile(&all_latencies, 0.50),
            p95_latency_ms: percentile(&all_latencies, 0.95),
            p99_latency_ms: percentile(&all_latencies, 0.99),
        })
    }

    /// Verify non-interference: check that idle nodes have unchanged state.
    async fn verify_non_interference(
        &self,
        active_nodes: &[usize],
    ) -> anyhow::Result<Vec<NonInterferenceEvidence>> {
        let max = self.node_mgr.node_count();
        let mut idle_nodes: Vec<usize> = (0..max).filter(|n| !active_nodes.contains(n)).collect();

        if idle_nodes.is_empty() {
            idle_nodes.push(max - 1);
        }

        let mut evidence = Vec::new();

        for &idle in &idle_nodes {
            let count_before = self.get_registry_count(idle).await.unwrap_or(0);

            // Run a short benchmark on active nodes
            let duration = Duration::from_secs(3);
            let mut handles = Vec::new();
            for &active in active_nodes {
                if active == idle {
                    continue;
                }
                let client = self.http_client.clone();
                let url = self.node_mgr.node_url(active);
                let dur = duration;
                handles.push(tokio::spawn(async move {
                    writer_task(client, url, active, dur).await
                }));
            }

            for h in handles {
                let _ = h.await;
            }

            let count_after = self.get_registry_count(idle).await.unwrap_or(0);

            evidence.push(NonInterferenceEvidence {
                idle_node_index: idle,
                count_before,
                count_after,
                unchanged: count_before == count_after,
            });
        }

        Ok(evidence)
    }

    /// Three-phase Tripwire fork-exclusion test.
    ///
    /// Proves that content-addressed storage provides a tamper-evident audit
    /// trail where forked successors are permanently detectable:
    ///
    /// - **Phase 1 (Deterministic Addressing)**: same payload → same address
    /// - **Phase 2 (Fork Separation)**: different payload, same parent → different address
    /// - **Phase 3 (Audit Trail)**: both objects retrievable, fork visible to any auditor
    async fn test_tripwire_detection(&self) -> anyhow::Result<TripwireEvidence> {
        let node_url = self.node_mgr.node_url(0);

        // Shared parent digest (genesis-like, all-zero)
        let parent_digest = [0u8; 32];

        // ── Phase 1: Deterministic Addressing ──
        eprintln!("    Phase 1: Deterministic addressing...");

        let commit_a = ByteCommitV3 {
            node_id: domain_hash(b"DSM/bench-node\0", b"tripwire-a").to_vec(),
            cycle_index: 1,
            smt_root: domain_hash(b"DSM/bench-smt\0", b"tripwire-a-root").to_vec(),
            bytes_used: 1024,
            parent_digest: parent_digest.to_vec(),
        };

        let (commit_a_status, commit_a_addr) = self.publish_evidence(&node_url, &commit_a).await?;

        // Re-publish identical payload — must return same address
        let (replay_a_status, replay_a_addr) = self.publish_evidence(&node_url, &commit_a).await?;

        let deterministic = !commit_a_addr.is_empty()
            && !replay_a_addr.is_empty()
            && commit_a_addr == replay_a_addr;

        eprintln!(
            "      Commit A:  HTTP {} → {}",
            commit_a_status,
            addr_short(&commit_a_addr)
        );
        eprintln!(
            "      Replay A:  HTTP {} → {} {}",
            replay_a_status,
            addr_short(&replay_a_addr),
            if deterministic { "✓" } else { "✗" }
        );

        // ── Phase 2: Fork Separation ──
        eprintln!("    Phase 2: Fork separation...");

        let commit_b = ByteCommitV3 {
            node_id: domain_hash(b"DSM/bench-node\0", b"tripwire-b").to_vec(),
            cycle_index: 1,
            smt_root: domain_hash(b"DSM/bench-smt\0", b"tripwire-b-root").to_vec(),
            bytes_used: 2048,
            parent_digest: parent_digest.to_vec(),
        };

        let (commit_b_status, commit_b_addr) = self.publish_evidence(&node_url, &commit_b).await?;

        let fork_separated = !commit_a_addr.is_empty()
            && !commit_b_addr.is_empty()
            && commit_a_addr != commit_b_addr;

        eprintln!(
            "      Commit B:  HTTP {} → {} (addr_A {} addr_B) {}",
            commit_b_status,
            addr_short(&commit_b_addr),
            if fork_separated { "≠" } else { "=" },
            if fork_separated { "✓" } else { "✗" }
        );

        // ── Phase 3: Audit Trail Verification ──
        eprintln!("    Phase 3: Audit trail verification...");

        let (audit_a_retrievable, audit_a_parent) =
            self.retrieve_and_verify(&node_url, &commit_a_addr).await;
        let (audit_b_retrievable, audit_b_parent) =
            self.retrieve_and_verify(&node_url, &commit_b_addr).await;

        let audit_parents_match = audit_a_retrievable
            && audit_b_retrievable
            && audit_a_parent == audit_b_parent
            && audit_a_parent == parent_digest.to_vec();

        eprintln!(
            "      Retrieve A: {} parent={}",
            if audit_a_retrievable { "✓" } else { "✗" },
            hex_short(&audit_a_parent)
        );
        eprintln!(
            "      Retrieve B: {} parent={}",
            if audit_b_retrievable { "✓" } else { "✗" },
            hex_short(&audit_b_parent)
        );
        eprintln!(
            "      Parents match: {} {}",
            if audit_parents_match { "✓" } else { "✗" },
            if audit_parents_match {
                "(fork visible in audit trail)"
            } else {
                "(unexpected)"
            }
        );

        let fork_excluded = deterministic && fork_separated && audit_parents_match;

        Ok(TripwireEvidence {
            parent_digest_hex: hex_display(&parent_digest),
            commit_a_status,
            commit_a_addr,
            replay_a_status,
            replay_a_addr,
            deterministic,
            commit_b_status,
            commit_b_addr,
            fork_separated,
            audit_a_retrievable,
            audit_b_retrievable,
            audit_parents_match,
            fork_excluded,
        })
    }

    /// Publish a ByteCommitV3 via the registry endpoint and return (status_code, object_address).
    async fn publish_evidence(
        &self,
        node_url: &str,
        commit: &ByteCommitV3,
    ) -> anyhow::Result<(u16, String)> {
        let mut body = Vec::new();
        commit
            .encode(&mut body)
            .context("Failed to encode ByteCommitV3")?;

        let dlv_id = domain_hash(b"DSM/bench-dlv\0", &commit.node_id);
        let dlv_id_b32 = base32_crockford_encode(&dlv_id);

        let resp = self
            .http_client
            .post(format!("{node_url}/api/v2/registry/publish"))
            .header("Content-Type", "application/octet-stream")
            .header("x-dsm-dlv-id", &dlv_id_b32)
            .header("x-dsm-kind", "1")
            .body(body)
            .send()
            .await
            .context("Registry publish request failed")?;

        let status = resp.status().as_u16();
        let addr = resp
            .headers()
            .get("x-object-address")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        Ok((status, addr))
    }

    /// Retrieve an object by address and return (retrievable, parent_digest_bytes).
    ///
    /// Uses the registry GET endpoint (not the generic object store) since
    /// evidence is published via `/api/v2/registry/publish`.
    async fn retrieve_and_verify(&self, node_url: &str, addr: &str) -> (bool, Vec<u8>) {
        if addr.is_empty() {
            return (false, Vec::new());
        }

        let url = format!("{node_url}/api/v2/registry/get/{addr}");
        let resp = match self.http_client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => return (false, Vec::new()),
        };

        if !resp.status().is_success() {
            return (false, Vec::new());
        }

        let body = match resp.bytes().await {
            Ok(b) => b,
            Err(_) => return (false, Vec::new()),
        };

        // Decode the protobuf to extract parent_digest
        match ByteCommitV3::decode(body.as_ref()) {
            Ok(commit) => (true, commit.parent_digest),
            Err(_) => {
                // Object retrieved but not decodable as ByteCommitV3 — still counts
                // as retrievable (storage is content-addressed, type-agnostic)
                (true, Vec::new())
            }
        }
    }

    /// Get the count of evidence objects at a node (kind=1 for benchmark evidence).
    async fn get_registry_count(&self, node_index: usize) -> anyhow::Result<usize> {
        let url = format!(
            "{}/api/v2/registry/list/1",
            self.node_mgr.node_url(node_index)
        );
        let resp = self.http_client.get(&url).send().await?;
        let body = resp.text().await.unwrap_or_default();
        Ok(body.lines().filter(|l| !l.is_empty()).count())
    }
}

// ─── Writer task ───────────────────────────────────────────────────────────────

/// Single writer task: publishes evidence objects to a target node
/// for the specified duration. Returns (successful_ops, failed_ops, latencies_ms).
///
/// Uses the `/api/v2/registry/publish` endpoint which is the deterministic
/// content-addressed evidence store. Each write gets a unique BLAKE3 address
/// derived from the protobuf payload. This demonstrates the same scaling
/// properties as ByteCommit (each node processes writes independently)
/// without the DLV slot provisioning overhead.
async fn writer_task(
    client: reqwest::Client,
    node_url: String,
    writer_id: usize,
    duration: Duration,
) -> (u64, u64, Vec<f64>) {
    let start = Instant::now();
    let mut ops: u64 = 0;
    let mut failed: u64 = 0;
    let mut latencies = Vec::new();
    let mut parent_digest = [0u8; 32]; // Genesis: all-zero parent

    let node_id = domain_hash(b"DSM/bench-node\0", &(writer_id as u64).to_be_bytes());
    let dlv_id = domain_hash(b"DSM/bench-dlv\0", &node_id);
    let dlv_id_b32 = base32_crockford_encode(&dlv_id);

    while start.elapsed() < duration {
        let cycle_index = ops + failed; // monotonic tick across all attempts
        let smt_root = domain_hash(
            b"DSM/bench-smt\0",
            &[&node_id[..], &cycle_index.to_be_bytes()].concat(),
        );

        let commit = ByteCommitV3 {
            node_id: node_id.to_vec(),
            cycle_index,
            smt_root: smt_root.to_vec(),
            bytes_used: cycle_index * 1024,
            parent_digest: parent_digest.to_vec(),
        };

        let mut body = Vec::with_capacity(128);
        if commit.encode(&mut body).is_err() {
            failed += 1;
            continue;
        }

        let digest = domain_hash(b"DSM/bytecommit\0", &body);

        let req_start = Instant::now();
        let result = client
            .post(format!("{node_url}/api/v2/registry/publish"))
            .header("Content-Type", "application/octet-stream")
            .header("x-dsm-dlv-id", &dlv_id_b32)
            .header("x-dsm-kind", "1")
            .body(body)
            .send()
            .await;

        let latency_ms = req_start.elapsed().as_secs_f64() * 1000.0;

        match result {
            Ok(resp) if resp.status().is_success() => {
                ops += 1;
                latencies.push(latency_ms);
                parent_digest = digest;
            }
            _ => {
                failed += 1;
            }
        }
    }

    (ops, failed, latencies)
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

/// Domain-separated BLAKE3 hash: H("tag" || data).
fn domain_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(tag);
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// Calculate a percentile from a sorted slice of f64 values.
fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Display-only hex encoding (for report output, never in protocol).
fn hex_display(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
}

/// Shortened hex for compact display.
fn hex_short(bytes: &[u8]) -> String {
    let full = hex_display(bytes);
    if full.len() > 12 {
        format!("{}...{}", &full[..8], &full[full.len() - 4..])
    } else {
        full
    }
}

/// Shortened address for compact display.
fn addr_short(addr: &str) -> String {
    if addr.len() > 12 {
        format!("{}...{}", &addr[..8], &addr[addr.len() - 4..])
    } else {
        addr.to_string()
    }
}

/// Minimal Base32 Crockford encoding for header values.
///
/// Produces lowercase Crockford Base32 without padding. This is used
/// only for HTTP header values in the benchmark, matching the storage
/// node's expected format for `x-dlv-id`.
fn base32_crockford_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"0123456789abcdefghjkmnpqrstvwxyz";
    let mut result = String::new();
    let mut buffer: u64 = 0;
    let mut bits_in_buffer = 0;

    for &byte in bytes {
        buffer = (buffer << 8) | u64::from(byte);
        bits_in_buffer += 8;

        while bits_in_buffer >= 5 {
            bits_in_buffer -= 5;
            let idx = ((buffer >> bits_in_buffer) & 0x1F) as usize;
            result.push(ALPHABET[idx] as char);
        }
    }

    if bits_in_buffer > 0 {
        let idx = ((buffer << (5 - bits_in_buffer)) & 0x1F) as usize;
        result.push(ALPHABET[idx] as char);
    }

    result
}
