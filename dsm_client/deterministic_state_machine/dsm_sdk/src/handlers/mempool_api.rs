//! mempool.space REST API client for Bitcoin Signet/Testnet/Mainnet.
//!
//! Provides UTXO lookup, transaction broadcast, confirmation polling,
//! SPV proof building, and balance queries via the free mempool.space
//! public API for product Bitcoin network access.
//!
//! **NOTE:** `serde_json` is used here exclusively for the mempool.space
//! external REST API — it is *not* used on the DSM wire format (protobuf-only).

use serde_json::Value;

/// Default mempool.space base URL.
const DEFAULT_BASE_URL: &str = "https://mempool.space";

/// Unified UTXO info used by both Bitcoin Core RPC and mempool.space paths.
#[derive(Debug, Clone)]
pub struct RpcUtxo {
    pub txid: String,
    pub vout: u32,
    pub amount_sats: u64,
    /// The owning address (used to map back to derivation index for signing).
    pub address: String,
    /// Whether the UTXO is confirmed on-chain.
    pub confirmed: bool,
}

/// UTXO information returned by mempool.space.
#[derive(Debug, Clone)]
pub struct MempoolUtxo {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    /// Whether this UTXO is confirmed on-chain.
    pub confirmed: bool,
}

/// Transaction status from mempool.space.
#[derive(Debug, Clone)]
pub struct MempoolTxStatus {
    pub confirmed: bool,
    pub block_height: Option<u64>,
    pub block_hash: Option<String>,
}

/// Merkle proof from mempool.space.
#[derive(Debug, Clone)]
pub struct MempoolMerkleProof {
    pub block_height: u64,
    /// Merkle path siblings (hex-encoded, display byte order).
    pub merkle: Vec<String>,
    /// Position (index) of the transaction in the block.
    pub pos: u32,
}

/// mempool.space REST API client.
pub struct MempoolClient {
    base_url: String,
    /// Network path prefix: "" for mainnet, "/signet", "/testnet4"
    network_prefix: String,
    client: reqwest::Client,
}

impl MempoolClient {
    /// Create a new client for the given Bitcoin network.
    ///
    /// `base_url`: override for `https://mempool.space` (from TOML config).
    /// `network`: determines the URL prefix (`/signet`, `/testnet4`, or empty for mainnet).
    pub fn new(
        base_url: Option<&str>,
        network: dsm::bitcoin::types::BitcoinNetwork,
    ) -> Result<Self, String> {
        let base = base_url
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_BASE_URL)
            .trim_end_matches('/')
            .to_string();

        let network_prefix = match network {
            dsm::bitcoin::types::BitcoinNetwork::Signet => "/signet".to_string(),
            dsm::bitcoin::types::BitcoinNetwork::Testnet => "/testnet4".to_string(),
            dsm::bitcoin::types::BitcoinNetwork::Mainnet => String::new(),
        };

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| format!("HTTP client init: {e}"))?;

        Ok(Self {
            base_url: base,
            network_prefix,
            client,
        })
    }

    /// Create a client from the TOML env config for a specific network.
    ///
    /// Reads `mempool_api_url` from the TOML config. Falls back to default
    /// `https://mempool.space` if not set.
    pub fn from_config_for_network(
        network: dsm::bitcoin::types::BitcoinNetwork,
    ) -> Result<Self, String> {
        let base_url = crate::network::NetworkConfigLoader::load_env_config()
            .ok()
            .and_then(|cfg| cfg.mempool_api_url);
        Self::new(base_url.as_deref(), network)
    }

    /// Accessor for the base URL (e.g. `https://mempool.space`).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Build a full API URL: `{base}{network_prefix}/api/{path}`
    fn api_url(&self, path: &str) -> String {
        format!("{}{}/api/{}", self.base_url, self.network_prefix, path)
    }

    // ──────────────────────────────────────────────────────────
    // UTXO queries
    // ──────────────────────────────────────────────────────────

    /// List confirmed UTXOs for a single address.
    pub async fn address_utxos(&self, address: &str) -> Result<Vec<MempoolUtxo>, String> {
        let url = self.api_url(&format!("address/{address}/utxo"));
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("mempool utxo request failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("mempool utxo HTTP {status}: {body}"));
        }

        let arr: Vec<Value> = resp
            .json()
            .await
            .map_err(|e| format!("mempool utxo parse: {e}"))?;

        let mut utxos = Vec::with_capacity(arr.len());
        for item in &arr {
            let txid = item["txid"]
                .as_str()
                .ok_or("utxo missing txid")?
                .to_string();
            let vout = item["vout"].as_u64().ok_or("utxo missing vout")? as u32;
            let value_sats = item["value"].as_u64().ok_or("utxo missing value")?;
            let confirmed = item["status"]["confirmed"].as_bool().unwrap_or(false);
            utxos.push(MempoolUtxo {
                txid,
                vout,
                value_sats,
                confirmed,
            });
        }
        Ok(utxos)
    }

    /// Sum UTXO values across multiple addresses (balance query).
    /// Returns `(confirmed_sats, unconfirmed_sats)`.
    /// Addresses are queried in parallel (batches of 10) to avoid sequential latency.
    pub async fn addresses_balance_sats(&self, addresses: &[String]) -> Result<(u64, u64), String> {
        let mut confirmed: u64 = 0;
        let mut unconfirmed: u64 = 0;
        for chunk in addresses.chunks(10) {
            let futs: Vec<_> = chunk.iter().map(|addr| self.address_utxos(addr)).collect();
            let results = futures::future::join_all(futs).await;
            for res in results {
                for u in &res? {
                    if u.confirmed {
                        confirmed = confirmed.saturating_add(u.value_sats);
                    } else {
                        unconfirmed = unconfirmed.saturating_add(u.value_sats);
                    }
                }
            }
        }
        Ok((confirmed, unconfirmed))
    }

    /// List spendable UTXOs (confirmed + unconfirmed) across multiple addresses,
    /// returning `RpcUtxo` compatible with the Bitcoin Core RPC path.
    ///
    /// The `confirmed` flag is preserved so higher-level routes can choose
    /// deterministic policies (e.g., confirmed-only coin selection for HTLC
    /// funding to avoid ancestor-chain limits).
    /// Addresses are queried in parallel (batches of 10) to avoid sequential latency.
    pub async fn list_address_utxos(&self, addresses: &[String]) -> Result<Vec<RpcUtxo>, String> {
        let mut result = Vec::new();
        for chunk in addresses.chunks(10) {
            let futs: Vec<_> = chunk
                .iter()
                .map(|addr| {
                    let addr_owned = addr.clone();
                    async move {
                        let utxos = self.address_utxos(&addr_owned).await?;
                        Ok::<_, String>(
                            utxos
                                .into_iter()
                                .map(|u| RpcUtxo {
                                    txid: u.txid,
                                    vout: u.vout,
                                    amount_sats: u.value_sats,
                                    address: addr_owned.clone(),
                                    confirmed: u.confirmed,
                                })
                                .collect::<Vec<_>>(),
                        )
                    }
                })
                .collect();
            let results = futures::future::join_all(futs).await;
            for res in results {
                result.extend(res?);
            }
        }
        Ok(result)
    }

    /// List confirmed UTXOs across multiple addresses with derivation metadata.
    /// Addresses are queried in parallel (batches of 10) to avoid sequential latency.
    pub async fn list_utxos_for_addresses(
        &self,
        addresses: &[(String, u32, u32)], // (address, change, index)
    ) -> Result<Vec<(MempoolUtxo, u32, u32)>, String> {
        let mut result = Vec::new();
        for chunk in addresses.chunks(10) {
            let futs: Vec<_> = chunk
                .iter()
                .map(|(addr, change, index)| {
                    let addr_owned = addr.clone();
                    let ch = *change;
                    let idx = *index;
                    async move {
                        let utxos = self.address_utxos(&addr_owned).await?;
                        Ok::<_, String>(
                            utxos
                                .into_iter()
                                .filter(|u| u.confirmed)
                                .map(|u| (u, ch, idx))
                                .collect::<Vec<_>>(),
                        )
                    }
                })
                .collect();
            let results = futures::future::join_all(futs).await;
            for res in results {
                result.extend(res?);
            }
        }
        Ok(result)
    }

    // ──────────────────────────────────────────────────────────
    // Transaction broadcast
    // ──────────────────────────────────────────────────────────

    /// Broadcast a raw transaction from raw bytes.
    /// Hex-encodes internally then POSTs to mempool.space.
    pub async fn broadcast_tx_raw(&self, raw_tx: &[u8]) -> Result<String, String> {
        let hex: String = raw_tx.iter().map(|b| format!("{:02x}", b)).collect();
        self.broadcast_tx(&hex).await
    }

    /// Broadcast a raw transaction (hex-encoded body).
    /// Returns the txid string on success.
    pub async fn broadcast_tx(&self, raw_tx_hex: &str) -> Result<String, String> {
        let url = self.api_url("tx");
        let resp = self
            .client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "text/plain")
            .body(raw_tx_hex.to_string())
            .send()
            .await
            .map_err(|e| format!("mempool broadcast failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("mempool broadcast HTTP {status}: {body}"));
        }

        let txid = resp
            .text()
            .await
            .map_err(|e| format!("mempool broadcast response: {e}"))?;
        Ok(txid.trim().to_string())
    }

    // ──────────────────────────────────────────────────────────
    // Transaction status + confirmation polling
    // ──────────────────────────────────────────────────────────

    /// Get transaction status (confirmed, block height, block hash).
    pub async fn tx_status(&self, txid: &str) -> Result<MempoolTxStatus, String> {
        let url = self.api_url(&format!("tx/{txid}"));
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("mempool tx status failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("mempool tx status HTTP {status}: {body}"));
        }

        let v: Value = resp
            .json()
            .await
            .map_err(|e| format!("mempool tx parse: {e}"))?;

        let confirmed = v["status"]["confirmed"].as_bool().unwrap_or(false);
        let block_height = v["status"]["block_height"].as_u64();
        let block_hash = v["status"]["block_hash"].as_str().map(|s| s.to_string());

        Ok(MempoolTxStatus {
            confirmed,
            block_height,
            block_hash,
        })
    }

    /// Get the current chain tip height.
    pub async fn chain_tip_height(&self) -> Result<u64, String> {
        let url = self.api_url("blocks/tip/height");
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("mempool tip height failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("mempool tip height HTTP {status}: {body}"));
        }

        let text = resp
            .text()
            .await
            .map_err(|e| format!("mempool tip height parse: {e}"))?;
        text.trim()
            .parse::<u64>()
            .map_err(|e| format!("mempool tip height not a number: {e}"))
    }

    /// Poll until a transaction has at least `required` confirmations.
    /// Returns the final `MempoolTxStatus`.
    ///
    /// Polls every 30 seconds, up to `max_polls` attempts (default ~60 = 30 min).
    pub async fn wait_for_confirmations(
        &self,
        txid: &str,
        required: u64,
        max_polls: u32,
    ) -> Result<MempoolTxStatus, String> {
        for attempt in 0..max_polls {
            let status = self.tx_status(txid).await?;
            if status.confirmed {
                if let Some(block_height) = status.block_height {
                    let tip = self.chain_tip_height().await?;
                    let confs = tip.saturating_sub(block_height) + 1;
                    if confs >= required {
                        log::info!(
                            "[MEMPOOL] tx {txid} has {confs} confirmations (required {required})"
                        );
                        return Ok(status);
                    }
                    log::info!(
                        "[MEMPOOL] tx {txid} has {confs}/{required} confirmations (attempt {}/{})",
                        attempt + 1,
                        max_polls
                    );
                }
            } else {
                log::info!(
                    "[MEMPOOL] tx {txid} not yet confirmed (attempt {}/{})",
                    attempt + 1,
                    max_polls
                );
            }
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
        Err(format!(
            "Timed out waiting for {required} confirmations on tx {txid} after {max_polls} polls"
        ))
    }

    // ──────────────────────────────────────────────────────────
    // Raw transaction data
    // ──────────────────────────────────────────────────────────

    /// Get raw transaction hex.
    pub async fn raw_tx_hex(&self, txid: &str) -> Result<String, String> {
        let url = self.api_url(&format!("tx/{txid}/hex"));
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("mempool raw tx failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("mempool raw tx HTTP {status}: {body}"));
        }

        resp.text()
            .await
            .map(|s| s.trim().to_string())
            .map_err(|e| format!("mempool raw tx parse: {e}"))
    }

    /// Get raw transaction as bytes.
    pub async fn raw_tx_bytes(&self, txid: &str) -> Result<Vec<u8>, String> {
        let hex = self.raw_tx_hex(txid).await?;
        hex_to_bytes(&hex)
    }

    // ──────────────────────────────────────────────────────────
    // SPV proof building
    // ──────────────────────────────────────────────────────────

    /// Get merkle proof for a confirmed transaction.
    pub async fn merkle_proof(&self, txid: &str) -> Result<MempoolMerkleProof, String> {
        let url = self.api_url(&format!("tx/{txid}/merkle-proof"));
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("mempool merkle proof failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("mempool merkle proof HTTP {status}: {body}"));
        }

        let v: Value = resp
            .json()
            .await
            .map_err(|e| format!("mempool merkle proof parse: {e}"))?;

        let block_height = v["block_height"]
            .as_u64()
            .ok_or("merkle proof missing block_height")?;
        let pos = v["pos"].as_u64().ok_or("merkle proof missing pos")? as u32;
        let merkle = v["merkle"]
            .as_array()
            .ok_or("merkle proof missing merkle array")?
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();

        Ok(MempoolMerkleProof {
            block_height,
            merkle,
            pos,
        })
    }

    /// Get block hash at a given height.
    pub async fn block_hash_at_height(&self, height: u64) -> Result<String, String> {
        let url = self.api_url(&format!("block-height/{height}"));
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("mempool block-height failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("mempool block-height HTTP {status}: {body}"));
        }

        resp.text()
            .await
            .map(|s| s.trim().to_string())
            .map_err(|e| format!("mempool block-height parse: {e}"))
    }

    /// Get raw 80-byte block header for a given block hash.
    pub async fn block_header_raw(&self, block_hash: &str) -> Result<[u8; 80], String> {
        let url = self.api_url(&format!("block/{block_hash}/header"));
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("mempool block header failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("mempool block header HTTP {status}: {body}"));
        }

        let hex = resp
            .text()
            .await
            .map_err(|e| format!("mempool block header parse: {e}"))?;
        let bytes = hex_to_bytes(hex.trim())?;
        if bytes.len() != 80 {
            return Err(format!(
                "Block header must be 80 bytes, got {}",
                bytes.len()
            ));
        }
        let mut header = [0u8; 80];
        header.copy_from_slice(&bytes);
        Ok(header)
    }

    /// Build a complete SPV proof for a confirmed transaction.
    ///
    /// Returns `(txid_internal_bytes, spv_proof_bytes, block_header_80)`.
    pub async fn build_spv_proof(
        &self,
        txid_display: &str,
    ) -> Result<([u8; 32], Vec<u8>, [u8; 80]), String> {
        // 1. Convert display txid (big-endian hex) to internal byte order (little-endian)
        let txid_be_bytes = hex_to_bytes(txid_display)?;
        if txid_be_bytes.len() != 32 {
            return Err(format!(
                "txid must be 32 bytes, got {}",
                txid_be_bytes.len()
            ));
        }
        let mut txid_internal = [0u8; 32];
        for (i, b) in txid_be_bytes.iter().enumerate() {
            txid_internal[31 - i] = *b;
        }

        // 2. Get merkle proof from mempool.space
        let proof = self.merkle_proof(txid_display).await?;

        // 3. Convert merkle siblings from display hex to internal byte order
        let mut siblings: Vec<[u8; 32]> = Vec::with_capacity(proof.merkle.len());
        for hex_str in &proof.merkle {
            let bytes = hex_to_bytes(hex_str)?;
            if bytes.len() != 32 {
                return Err(format!("merkle sibling not 32 bytes: {}", bytes.len()));
            }
            // mempool.space returns siblings in display byte order (big-endian hex).
            // Convert to internal byte order (little-endian) for Merkle computation,
            // matching the txid conversion at lines 544-547.
            let mut sib = [0u8; 32];
            for (i, b) in bytes.iter().enumerate() {
                sib[31 - i] = *b;
            }
            siblings.push(sib);
        }

        let spv_proof = dsm::bitcoin::spv::SpvProof {
            siblings,
            index: proof.pos,
        };

        // 4. Get block header
        let block_hash = self.block_hash_at_height(proof.block_height).await?;
        let block_header = self.block_header_raw(&block_hash).await?;

        Ok((txid_internal, spv_proof.to_bytes(), block_header))
    }

    /// Fetch raw 80-byte headers for a range of block heights.
    ///
    /// Used to build the confirmation header chain required by deep-anchor
    /// verification (`header_chain.len() + 1 >= min_confirmations`).
    pub async fn fetch_header_chain(
        &self,
        start_height: u64,
        count: u64,
    ) -> Result<Vec<[u8; 80]>, String> {
        let mut headers = Vec::with_capacity(count as usize);
        for h in start_height..start_height + count {
            let hash = self.block_hash_at_height(h).await?;
            let header = self.block_header_raw(&hash).await?;
            headers.push(header);
        }
        Ok(headers)
    }
}

// ──────────────────────────────────────────────────────────
// Utilities
// ──────────────────────────────────────────────────────────

/// Decode a hex string to bytes.
pub(crate) fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(
                hex.get(i..i + 2)
                    .ok_or_else(|| format!("hex string truncated at {i}"))?,
                16,
            )
            .map_err(|e| format!("hex decode at {i}: {e}"))
        })
        .collect()
}

/// Encode bytes as hex string.
pub(crate) fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}
