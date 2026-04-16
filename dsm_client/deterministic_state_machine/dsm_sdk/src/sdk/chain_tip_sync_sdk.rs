// SPDX-License-Identifier: MIT OR Apache-2.0
//! DSM Anchor Sync SDK — storage-node anchoring only (no external blockchains)
//!
//! What this does (and does NOT do):
//! - ✅ Maintains bilateral hashchain tips and batches state transitions
//! - ✅ Anchors those transitions to **DSM storage nodes** via the
//!   Universal Protobuf API (Envelope → UniversalTx → UniversalOp)
//! - ✅ Health/availability tracks storage-link reachability (not chains)
//! - ❌ No Ethereum/Bitcoin/etc. No gas, RPC, or external consensus
//!
//! Protocol surface used:
//! - `UniversalOp::Query(QueryOp)` for health checks (e.g., kv.get of a health key)
//! - `UniversalOp::Invoke(Invoke)` with `method = "kv.set"` to persist anchor records
//!   (ArgPack.codec = "proto"; body = gp::KvSetRequest). Values are opaque bytes.
//!
//! Notes:
//! - This module is transport-agnostic. The host provides a `UniversalTransport`
//!   that actually sends `gp::Envelope` bytes to a DSM storage node and returns
//!   the `gp::Envelope` response.
//! - We deliberately do **not** depend on any external blockchain client libs.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use dsm::crypto::blake3 as dsm_blake3;
use log::{debug, info, warn};
use prost::Message;
use tokio::sync::{Mutex, RwLock};
use crate::util::deterministic_time as dt;
use dsm::common::deterministic_id;
use dsm::types::error::DsmError;
use dsm::types::state_types::State;
use dsm::types::proto as gp; // Schema 2.3.0 Universal types
use crate::generated;

/* =============================== Transport ================================ */

/// Transport that can send Universal Envelopes to a DSM storage node.
#[async_trait::async_trait]
pub trait UniversalTransport: Send + Sync {
    async fn send_envelope(&self, env: gp::Envelope) -> Result<gp::Envelope, DsmError>;
    /// Quick reachability/health probe of the storage link.
    async fn link_status(&self) -> LinkStatus;
    /// Optional display name of the current target node/region.
    fn node_label(&self) -> Option<String> {
        None
    }
}

/* ============================ Data structures ============================ */

/// Link/transport availability status (for storage nodes)
#[derive(Debug, Clone, PartialEq)]
pub enum LinkStatus {
    Online,
    Offline,
    Limited,
    Synchronizing,
}

/// Chain tip information for bilateral hashchain anchoring
#[derive(Debug, Clone)]
pub struct ChainTip {
    /// Hash of the current bilateral hashchain tip state
    pub tip_hash: Vec<u8>,
    /// State number at the tip of this bilateral hashchain
    pub state_number: u64,
    /// Deterministic logical tick of the tip state
    pub tick: u64,
    /// Device ID of the local party
    pub device_id: String,
    /// Device ID of the counterparty (for bilateral hashchains)
    pub counterparty_id: String,
    /// Bilateral hashchain identifier (typically "device_id:counterparty_id")
    pub bilateral_chain_id: String,
    /// Storage-node receipt/reference for last successful anchor (opaque)
    pub anchor_receipt_id: Option<String>,
    /// Whether this tip has been anchored to storage
    pub anchored: bool,
    /// Last anchoring attempt logical tick
    pub last_anchor_tick: Option<u64>,
    /// Number of failed anchoring attempts
    pub failed_anchor_attempts: u32,
}

/// Individual bilateral state transition to anchor to storage
#[derive(Debug, Clone)]
pub struct StateTransition {
    pub device_id: String,
    pub counterparty_id: String,
    pub bilateral_chain_id: String,
    pub prev_state_hash: Vec<u8>,
    pub new_state_hash: Vec<u8>,
    pub state_number: u64,
    pub operation: String,
    pub balance_delta: HashMap<String, i64>,
    pub tick: u64,
    pub signature: Vec<u8>,
    pub transaction_direction: String,
}

/// Aggregated batch submitted to storage
#[derive(Debug, Clone)]
pub struct TransactionBatch {
    pub batch_id: String,
    pub state_transitions: Vec<StateTransition>,
    pub merkle_root: Vec<u8>,
    pub created_at: u64,
    pub priority: u8,
    pub bilateral_chains: Vec<String>,
}

/// Synchronization result
#[derive(Debug, Clone)]
pub struct SyncResult {
    pub success: bool,
    pub receipt_id: Option<String>,
    pub storage_label: Option<String>,
    pub error_message: Option<String>,
    pub tick: u64,
}

/// Retry configuration
#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub backoff_multiplier: f64,
}
impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
        }
    }
}

/// Anchor-layer sync configuration (no chain RPC here)
#[derive(Debug, Clone)]
pub struct AnchorSyncConfig {
    pub max_batch_size: usize,
    pub max_batch_wait_time: Duration,
    pub retry_config: RetryConfig,
    pub auto_sync_enabled: bool,
    pub network_check_interval: Duration,
}

/// Synchronization metrics and statistics
#[derive(Debug, Clone, Default)]
pub struct SyncMetrics {
    pub total_sync_attempts: u64,
    pub successful_syncs: u64,
    pub failed_syncs: u64,
    pub average_sync_time_ms: f64,
    pub largest_batch_size: usize,
    pub total_state_transitions: u64,
    pub last_successful_sync: Option<u64>,
}

/* ================================ SDK ==================================== */

pub struct ChainTipSyncSDK<T: UniversalTransport + 'static> {
    chain_tips: Arc<RwLock<HashMap<String, ChainTip>>>,
    pending_batches: Arc<Mutex<VecDeque<TransactionBatch>>>,
    link_status: Arc<RwLock<LinkStatus>>,
    config: AnchorSyncConfig,
    metrics: Arc<RwLock<SyncMetrics>>,
    transport: Arc<T>,
    device_id: Vec<u8>,
    chain_tip: Vec<u8>,
    genesis_hash: Vec<u8>,
}

impl<T: UniversalTransport + 'static> ChainTipSyncSDK<T> {
    pub fn new(config: AnchorSyncConfig, transport: Arc<T>) -> Self {
        let context = crate::get_sdk_context();
        Self {
            chain_tips: Arc::new(RwLock::new(HashMap::new())),
            pending_batches: Arc::new(Mutex::new(VecDeque::new())),
            link_status: Arc::new(RwLock::new(LinkStatus::Offline)),
            config,
            metrics: Arc::new(RwLock::new(SyncMetrics::default())),
            transport,
            device_id: context.device_id(),
            chain_tip: context.chain_tip(),
            genesis_hash: context.genesis_hash(),
        }
    }

    /// Update chain tip for a bilateral relationship and try to anchor via storage.
    pub async fn update_chain_tip(
        &self,
        bilateral_chain_id: &str,
        new_state: &State,
    ) -> Result<(), DsmError> {
        let tip_hash = self.compute_state_hash(new_state).await?;
        let ts = dt::tick();

        let mut tips = self.chain_tips.write().await;
        if let Some(existing) = tips.get(bilateral_chain_id) {
            if new_state.hash[0] as u64 <= existing.hash[0] as u64 {
                return Err(DsmError::InvalidOperation(
                    "State number must increase (forward-only)".into(),
                ));
            }
        }

        let parts: Vec<&str> = bilateral_chain_id.split(':').collect();
        if parts.len() != 2 {
            return Err(DsmError::InvalidOperation(
                "bilateral_chain_id must be 'device:counterparty'".into(),
            ));
        }
        let (device_id, counterparty_id) = (parts[0].to_string(), parts[1].to_string());

        let tip = ChainTip {
            tip_hash: tip_hash.clone(),
            state_number: new_state.hash[0] as u64,
            tick: ts,
            device_id: device_id.clone(),
            counterparty_id: counterparty_id.clone(),
            bilateral_chain_id: bilateral_chain_id.to_string(),
            anchor_receipt_id: None,
            anchored: false,
            last_anchor_tick: None,
            failed_anchor_attempts: 0,
        };
        tips.insert(bilateral_chain_id.to_string(), tip);
        drop(tips);

        info!(
            "updated tip for {} → #{} ({})",
            bilateral_chain_id,
            new_state.hash[0] as u64,
            encode_id_text(&tip_hash)
        );

        match *self.link_status.read().await {
            LinkStatus::Online => {
                if let Err(e) = self
                    .attempt_immediate_sync(bilateral_chain_id, new_state)
                    .await
                {
                    warn!("immediate anchor failed for {bilateral_chain_id}: {e} — queueing");
                    self.add_to_pending_batch(bilateral_chain_id, new_state)
                        .await?;
                }
            }
            _ => {
                self.add_to_pending_batch(bilateral_chain_id, new_state)
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn get_chain_tip(&self, bilateral_chain_id: &str) -> Option<ChainTip> {
        self.chain_tips
            .read()
            .await
            .get(bilateral_chain_id)
            .cloned()
    }
    pub async fn get_all_chain_tips(&self) -> HashMap<String, ChainTip> {
        self.chain_tips.read().await.clone()
    }

    /// Storage link availability (via transport)
    pub async fn check_link_status(&self) -> Result<LinkStatus, DsmError> {
        let status = self.transport.link_status().await;
        let mut cur = self.link_status.write().await;
        if *cur != status {
            info!("link status: {:?} → {:?}", *cur, status);
            *cur = status.clone();
            if status == LinkStatus::Online {
                if let Err(e) = self.process_pending_batches().await {
                    warn!("pending batches processing failed: {e}");
                }
            }
        }
        Ok(status)
    }

    pub async fn force_sync_all(&self) -> Result<Vec<SyncResult>, DsmError> {
        match self.check_link_status().await? {
            LinkStatus::Offline => Err(DsmError::network(
                "storage link offline",
                None::<std::io::Error>,
            )),
            _ => self.process_pending_batches().await,
        }
    }

    pub async fn get_sync_metrics(&self) -> SyncMetrics {
        self.metrics.read().await.clone()
    }

    pub async fn clear_pending_batches(&self) -> usize {
        let mut q = self.pending_batches.lock().await;
        let n = q.len();
        q.clear();
        warn!("cleared {n} pending anchor batches");
        n
    }

    /* ---------------------------- internal -------------------------------- */

    async fn compute_state_hash(&self, state: &State) -> Result<Vec<u8>, DsmError> {
        // Build canonical proto representation (map -> repeated entries, deterministic order)
        let mut entries: Vec<generated::TokenBalanceEntry> =
            Vec::with_capacity(state.token_balances.len());
        let mut keys: Vec<String> = state.token_balances.keys().cloned().collect();
        keys.sort();
        for k in keys {
            match state.token_balances.get(&k) {
                Some(v) => {
                    entries.push(generated::TokenBalanceEntry {
                        token_id: k,
                        amount: Some(u128_to_le(v.value() as u128)),
                    });
                }
                None => {
                    // Invariant violation: key collected from keys() missing on second lookup.
                    // Rather than panic, surface a state corruption error.
                    return Err(DsmError::InvalidState(format!(
                        "token balance key disappeared during hash computation: {k}"
                    )));
                }
            }
        }

        let wire = generated::StateWire {
            state_number: state.hash[0] as u64,
            prev_state_hash: state.prev_state_hash.to_vec(),
            token_balances: entries,
            operation: state
                .get_operation_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            device_id: state.device_info.device_id.to_vec(),
        };

        let bytes = wire.encode_to_vec();
        Ok(dsm_blake3::domain_hash("DSM/chain-tip", &bytes)
            .as_bytes()
            .to_vec())
    }

    async fn attempt_immediate_sync(
        &self,
        bilateral_chain_id: &str,
        state: &State,
    ) -> Result<SyncResult, DsmError> {
        let parts: Vec<&str> = bilateral_chain_id.split(':').collect();
        let (device_id, counterparty_id) = (parts[0].to_string(), parts[1].to_string());
        let transition = self
            .build_transition(&device_id, &counterparty_id, bilateral_chain_id, state)
            .await?;
        let batch = TransactionBatch {
            batch_id: deterministic_id::generate_batch_id(
                &dsm_blake3::domain_hash("DSM/bilateral-chain-id", bilateral_chain_id.as_bytes())
                    .as_bytes()[..],
            ),
            state_transitions: vec![transition],
            merkle_root: self.compute_merkle_root(&[state]).await?,
            created_at: dt::tick(),
            priority: 10,
            bilateral_chains: vec![bilateral_chain_id.to_string()],
        };
        self.submit_transaction_batch(&batch).await
    }

    async fn add_to_pending_batch(
        &self,
        bilateral_chain_id: &str,
        state: &State,
    ) -> Result<(), DsmError> {
        let parts: Vec<&str> = bilateral_chain_id.split(':').collect();
        let (device_id, counterparty_id) = (parts[0].to_string(), parts[1].to_string());
        let transition = self
            .build_transition(&device_id, &counterparty_id, bilateral_chain_id, state)
            .await?;
        let batch = TransactionBatch {
            batch_id: deterministic_id::generate_batch_id(
                &dsm_blake3::domain_hash("DSM/bilateral-chain-id", bilateral_chain_id.as_bytes())
                    .as_bytes()[..],
            ),
            state_transitions: vec![transition],
            merkle_root: self.compute_merkle_root(&[state]).await?,
            created_at: dt::tick(),
            priority: 5,
            bilateral_chains: vec![bilateral_chain_id.to_string()],
        };
        let mut q = self.pending_batches.lock().await;
        q.push_back(batch);
        debug!("queued anchor for {bilateral_chain_id}");
        Ok(())
    }

    async fn process_pending_batches(&self) -> Result<Vec<SyncResult>, DsmError> {
        let mut took = Vec::new();
        {
            let mut q = self.pending_batches.lock().await;
            while let Some(b) = q.pop_front() {
                took.push(b);
                if took.len() >= self.config.max_batch_size {
                    break;
                }
            }
        }
        if took.is_empty() {
            return Ok(Vec::new());
        }
        info!("processing {} pending batches", took.len());
        let mut results = Vec::with_capacity(took.len());
        for b in took {
            let res = self.submit_transaction_batch(&b).await?;
            results.push(res);
        }
        Ok(results)
    }

    async fn submit_transaction_batch(
        &self,
        batch: &TransactionBatch,
    ) -> Result<SyncResult, DsmError> {
        let start = dt::tick();
        let ts = dt::tick();

        // For each transition, write an anchor record via kv.set under a deterministic key.
        let mut ops = Vec::with_capacity(batch.state_transitions.len());
        for tr in &batch.state_transitions {
            let key = format!(
                "anchor/{bil}/{num}",
                bil = tr.bilateral_chain_id,
                num = tr.state_number
            )
            .into_bytes();
            // Serialize transition using canonical protobuf (StateTransitionProto)
            let mut proto_balance_delta: Vec<generated::BalanceDeltaEntry> = Vec::new();
            // Sort entries deterministically by token_id without relying on expect
            let mut entries: Vec<(&String, &i64)> = tr.balance_delta.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            for (k, v) in entries {
                proto_balance_delta.push(generated::BalanceDeltaEntry {
                    token_id: k.clone(),
                    delta: Some(i128_to_le(*v as i128)),
                });
            }
            let proto_tr = generated::StateTransitionProto {
                device_id: tr.device_id.as_bytes().to_vec(),
                counterparty_id: tr.counterparty_id.as_bytes().to_vec(),
                bilateral_chain_id: tr.bilateral_chain_id.clone(),
                prev_state_hash: tr.prev_state_hash.clone(),
                new_state_hash: tr.new_state_hash.clone(),
                state_number: tr.state_number,
                operation: tr.operation.clone(),
                balance_delta: proto_balance_delta,
                signature: tr.signature.clone(),
                transaction_direction: tr.transaction_direction.clone(),
            };
            let value = proto_tr.encode_to_vec();
            let kv_req = gp::KvSetRequest { key, value };
            let args = gp::ArgPack {
                schema_hash: Some(hash32_zero()),
                codec: gp::Codec::Proto as i32,
                body: kv_req.encode_to_vec(),
            };
            let invoke = gp::Invoke {
                program: Some(gp::ProgramRef {
                    program_id: "dsm.anchor.v2".into(),
                    dag_root: Some(hash32_zero()),
                }),
                method: "kv.set".into(),
                args: Some(args),
                pre_state_hash: Some(hash32_zero()),
                post_state_hash: Some(hash32_zero()),
                cosigners: vec![],
                evidence: None,
                nonce: Some(hash16_zero()),
            };
            let op = gp::UniversalOp {
                op_id: Some(hash32_zero()),
                actor: vec![],
                genesis_hash: hash32_zero().v.clone(),
                kind: Some(gp::universal_op::Kind::Invoke(invoke)),
            };
            ops.push(op);
        }
        let tx = gp::UniversalTx { ops, atomic: false };
        let env = gp::Envelope {
            version: 3,
            headers: Some(gp::Headers {
                device_id: self.device_id.clone(),
                chain_tip: self.chain_tip.clone(),
                genesis_hash: self.genesis_hash.clone(),
                seq: 0,
            }),
            message_id: uuid_v7_bytes(),
            payload: Some(gp::envelope::Payload::UniversalTx(tx)),
        };

        let rx_env = self.transport.send_envelope(env).await?;
        let receipt = match rx_env.payload {
            Some(gp::envelope::Payload::UniversalRx(rx)) => {
                let ok = rx.results.iter().all(|r| r.accepted);
                if !ok {
                    let first_err = rx
                        .results
                        .iter()
                        .find(|r| !r.accepted)
                        .and_then(|r| r.error.as_ref())
                        .map(|e| e.message.clone())
                        .unwrap_or_else(|| "anchor rejected".into());
                    self.bump_metrics(false, batch, dt::tick().saturating_sub(start) as f64);
                    return Ok(SyncResult {
                        success: false,
                        receipt_id: None,
                        storage_label: self.transport.node_label(),
                        error_message: Some(first_err),
                        tick: ts,
                    });
                }
                // Display-only identifier for log correlation -- never enters protocol fields.
                // Uses the batch merkle_root as a stable anchor reference.
                Some(format!("anch:{}", encode_id_text(&batch.merkle_root)))
            }
            Some(gp::envelope::Payload::Error(e)) => {
                self.bump_metrics(false, batch, dt::tick().saturating_sub(start) as f64);
                return Ok(SyncResult {
                    success: false,
                    receipt_id: None,
                    storage_label: self.transport.node_label(),
                    error_message: Some(e.message),
                    tick: ts,
                });
            }
            _ => None,
        };

        // Mark tips as anchored
        self.mark_batch_as_synchronized(batch, receipt.as_deref().unwrap_or("ok"))
            .await?;
        self.bump_metrics(true, batch, dt::tick().saturating_sub(start) as f64);
        Ok(SyncResult {
            success: true,
            receipt_id: receipt,
            storage_label: self.transport.node_label(),
            error_message: None,
            tick: ts,
        })
    }

    async fn mark_batch_as_synchronized(
        &self,
        batch: &TransactionBatch,
        receipt_id: &str,
    ) -> Result<(), DsmError> {
        let mut tips = self.chain_tips.write().await;
        for tr in &batch.state_transitions {
            if let Some(t) = tips.get_mut(&tr.bilateral_chain_id) {
                t.anchored = true;
                t.anchor_receipt_id = Some(receipt_id.to_string());
                t.last_anchor_tick = Some(dt::tick());
                t.failed_anchor_attempts = 0;
            }
        }
        Ok(())
    }

    fn bump_metrics(&self, success: bool, batch: &TransactionBatch, elapsed_ms: f64) {
        let mut m = futures::executor::block_on(self.metrics.write());
        let count = m.total_sync_attempts;
        m.total_sync_attempts += 1;
        m.average_sync_time_ms =
            (m.average_sync_time_ms * count as f64 + elapsed_ms) / (count as f64 + 1.0);
        if success {
            m.successful_syncs += 1;
            m.last_successful_sync = Some(dt::tick());
        } else {
            m.failed_syncs += 1;
        }
        m.total_state_transitions += batch.state_transitions.len() as u64;
        if batch.state_transitions.len() > m.largest_batch_size {
            m.largest_batch_size = batch.state_transitions.len();
        }
    }

    async fn compute_merkle_root(&self, states: &[&State]) -> Result<Vec<u8>, DsmError> {
        if states.is_empty() {
            return Ok(vec![0u8; 32]);
        }
        let mut hashes: Vec<u8> = Vec::new();
        for s in states {
            let h = self.compute_state_hash(s).await?;
            hashes.extend_from_slice(&h);
        }
        Ok(dsm_blake3::domain_hash("DSM/chain-combine", &hashes)
            .as_bytes()
            .to_vec())
    }

    fn extract_balance_delta(&self, state: &State) -> HashMap<String, i64> {
        let mut delta = HashMap::new();
        for (k, v) in &state.token_balances {
            delta.insert(k.clone(), v.value() as i64);
        }
        delta
    }

    async fn build_transition(
        &self,
        device_id: &str,
        counterparty_id: &str,
        bilateral_chain_id: &str,
        state: &State,
    ) -> Result<StateTransition, DsmError> {
        Ok(StateTransition {
            device_id: device_id.to_string(),
            counterparty_id: counterparty_id.to_string(),
            bilateral_chain_id: bilateral_chain_id.to_string(),
            prev_state_hash: state.prev_state_hash.to_vec(),
            new_state_hash: self.compute_state_hash(state).await?,
            state_number: state.hash[0] as u64,
            operation: "state_transition".into(),
            balance_delta: self.extract_balance_delta(state),
            tick: dt::tick(),
            signature: vec![], // signing of anchor payload is optional here; use AttestedAction if needed
            transaction_direction: format!("{device_id}_to_{counterparty_id}"),
        })
    }
}

/* -------------------------- helpers (schema) --------------------------- */

fn hash32_zero() -> gp::Hash32 {
    gp::Hash32 { v: vec![0u8; 32] }
}
fn hash16_zero() -> gp::Hash16 {
    gp::Hash16 { v: vec![0u8; 16] }
}
fn u128_to_le(v: u128) -> generated::U128 {
    generated::U128 {
        le: v.to_le_bytes().to_vec(),
    }
}
fn i128_to_le(v: i128) -> generated::S128 {
    generated::S128 {
        le: v.to_le_bytes().to_vec(),
    }
}

/* ================================ Builder ================================= */

pub struct ChainTipSyncSDKBuilder<T: UniversalTransport + 'static> {
    config: AnchorSyncConfig,
    transport: Arc<T>,
}
impl<T: UniversalTransport + 'static> ChainTipSyncSDKBuilder<T> {
    pub fn new(transport: Arc<T>) -> Self {
        Self {
            config: AnchorSyncConfig {
                max_batch_size: 100,
                max_batch_wait_time: Duration::from_secs(60),
                retry_config: RetryConfig::default(),
                auto_sync_enabled: true,
                network_check_interval: Duration::from_secs(30),
            },
            transport,
        }
    }
    pub fn max_batch_size(mut self, n: usize) -> Self {
        self.config.max_batch_size = n;
        self
    }
    pub fn max_batch_wait_time(mut self, d: Duration) -> Self {
        self.config.max_batch_wait_time = d;
        self
    }
    pub fn auto_sync_enabled(mut self, enabled: bool) -> Self {
        self.config.auto_sync_enabled = enabled;
        self
    }
    pub fn network_check_interval(mut self, d: Duration) -> Self {
        self.config.network_check_interval = d;
        self
    }
    pub fn build(self) -> ChainTipSyncSDK<T> {
        ChainTipSyncSDK::new(self.config, self.transport)
    }
}

/* ================================= util =================================== */

fn encode_id_text(bytes: &[u8]) -> String {
    crate::util::text_id::encode_base32_crockford(bytes)
}
fn uuid_v7_bytes() -> Vec<u8> {
    // Use deterministic sequential ID instead of UUID v7
    let id_str = deterministic_id::generate_sequential_id("v7");
    dsm_blake3::domain_hash("DSM/chain-tip-short", id_str.as_bytes()).as_bytes()[0..16].to_vec()
}

/* ================================= tests ================================== */

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    struct DummyTransport;
    #[async_trait::async_trait]
    impl UniversalTransport for DummyTransport {
        async fn send_envelope(&self, env: gp::Envelope) -> Result<gp::Envelope, DsmError> {
            // Always accept all ops
            let rx = match env.payload {
                Some(gp::envelope::Payload::UniversalTx(tx)) => {
                    let results = tx
                        .ops
                        .into_iter()
                        .map(|op| gp::OpResult {
                            op_id: op.op_id,
                            accepted: true,
                            post_state_hash: Some(hash32_zero()),
                            result: Some(gp::ResultPack {
                                schema_hash: Some(hash32_zero()),
                                codec: gp::Codec::Proto as i32,
                                body: vec![],
                            }),
                            error: None,
                        })
                        .collect();
                    gp::UniversalRx { results }
                }
                _ => gp::UniversalRx { results: vec![] },
            };
            Ok(gp::Envelope {
                version: 3,
                headers: Some(gp::Headers {
                    device_id: vec![0; 32],    // Dummy device ID for test transport
                    chain_tip: vec![0; 32],    // Dummy chain tip for test transport
                    genesis_hash: vec![0; 32], // Dummy genesis hash for test transport
                    seq: 0,
                }),
                message_id: uuid_v7_bytes(),
                payload: Some(gp::envelope::Payload::UniversalRx(rx)),
            })
        }
        async fn link_status(&self) -> LinkStatus {
            LinkStatus::Online
        }
        fn node_label(&self) -> Option<String> {
            Some("dummy-node".into())
        }
    }

    #[tokio::test]
    async fn update_and_anchor_tip() {
        let sdk = ChainTipSyncSDKBuilder::new(Arc::new(DummyTransport))
            .max_batch_size(8)
            .build();
        let mut state = State::default();
        state.hash[0] as u64 = 1;
        let id = "alice:bob";
        sdk.update_chain_tip(id, &state).await.unwrap();
        let tip = sdk.get_chain_tip(id).await.unwrap();
        assert_eq!(tip.state_number, 1);
        let res = sdk.force_sync_all().await.unwrap_or_default();
        assert!(res.is_empty() || res.iter().all(|r| r.success));
    }

    #[tokio::test]
    async fn link_status_through_transport() {
        let sdk = ChainTipSyncSDKBuilder::new(Arc::new(DummyTransport)).build();
        let st = sdk.check_link_status().await.unwrap();
        assert_eq!(st, LinkStatus::Online);
    }
}
