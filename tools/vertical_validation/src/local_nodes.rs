//! Local Storage Node Manager
//!
//! Wraps the existing `dsm_storage_node/start_dev_cluster.sh` script to
//! manage 5 local development storage nodes. Provides start, stop, and health
//! check operations with retry logic.
//!
//! The local node set runs on ports 8080-8084, with each node configured via
//! `config/dev/node{1-5}.toml`. Health is verified via HTTP GET to
//! `/api/v2/health` on each node.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context};

/// Manages the 5-node DSM local storage-node set for benchmarking.
pub struct LocalNodeManager {
    /// Path to the dsm_storage_node directory
    storage_node_dir: PathBuf,
    /// Base port (node 1 = base_port, node 2 = base_port+1, etc.)
    base_port: u16,
    /// Number of nodes in the local node set
    node_count: usize,
    /// HTTP client for health checks
    client: reqwest::Client,
}

impl LocalNodeManager {
    /// Create a new local node-set manager.
    ///
    /// `project_root` is the DSM repository root (contains `dsm_storage_node/`).
    pub fn new(project_root: &Path) -> Self {
        Self {
            storage_node_dir: project_root.join("dsm_storage_node"),
            base_port: 8080,
            node_count: 5,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Start the local nodes using the existing shell script.
    pub async fn start(&self) -> anyhow::Result<()> {
        let script = self.storage_node_dir.join("start_dev_cluster.sh");
        if !script.exists() {
            bail!("Local node-set script not found: {}", script.display());
        }

        eprintln!("  Starting 5 local storage nodes...");

        let output = tokio::process::Command::new("bash")
            .arg(&script)
            .arg("start")
            .env("BENCHMARK_MODE", "1")
            .current_dir(&self.storage_node_dir)
            .output()
            .await
            .context("Failed to run start_dev_cluster.sh")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Local node-set start failed: {stderr}");
        }

        // Wait for all nodes to become healthy
        self.wait_for_nodes(self.node_count, 30).await?;

        eprintln!("  All {} nodes healthy", self.node_count);
        Ok(())
    }

    /// Stop the local nodes.
    #[allow(dead_code)]
    pub async fn stop(&self) -> anyhow::Result<()> {
        let script = self.storage_node_dir.join("start_dev_cluster.sh");

        let output = tokio::process::Command::new("bash")
            .arg(&script)
            .arg("stop")
            .current_dir(&self.storage_node_dir)
            .output()
            .await
            .context("Failed to stop local storage nodes")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("  Warning: local node shutdown returned error: {stderr}");
        }

        Ok(())
    }

    /// Check if a specific node is healthy (0-indexed).
    pub async fn health_check(&self, node_index: usize) -> bool {
        let url = format!("{}/api/v2/health", self.node_url(node_index));
        self.client
            .get(&url)
            .send()
            .await
            .map(|resp| resp.status().is_success())
            .unwrap_or(false)
    }

    /// Wait for the specified number of nodes to become healthy.
    pub async fn wait_for_nodes(&self, count: usize, max_retries: usize) -> anyhow::Result<()> {
        for attempt in 1..=max_retries {
            let mut healthy = 0;
            for i in 0..count {
                if self.health_check(i).await {
                    healthy += 1;
                }
            }

            if healthy >= count {
                return Ok(());
            }

            if attempt == max_retries {
                bail!("Only {healthy}/{count} nodes healthy after {max_retries} retries");
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        Ok(())
    }

    /// Get the HTTP base URL for a specific node (0-indexed).
    pub fn node_url(&self, node_index: usize) -> String {
        format!("http://127.0.0.1:{}", self.base_port + node_index as u16)
    }

    /// Get the total number of nodes in the local node set.
    pub fn node_count(&self) -> usize {
        self.node_count
    }
}
