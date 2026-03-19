//! Bilateral control attack resistance utilities.
//!
//! Bytes-first, strict implementation that enforces hard rules against
//! bilateral control attacks (where one party attempts to manipulate the
//! other's state chain). No wall-clock time, no JSON, no hex on protocol path.
//!
//! Hard rules enforced here:
// - No hex/base64/json/serde encodings for protocol-relevant data.
// - No wall-clock time; ordering uses state_number only.
// - Graph + detectors operate on fixed 32-byte identity tags (BLAKE3 of device labels)
//   so we never stringify identifiers for “analysis keys”.
//
// Notes:
// - `State.device_info.device_id` is assumed to be a human/UI label (String). We hash it
//   to a stable 32-byte tag for analysis and graph operations.
// - Storage here is a *placeholder trait* suitable for mobile compilation. Real SDK
//   implementations can implement this trait without pulling in any heavy dependencies.

use crate::types::error::DsmError;
use crate::types::operations::Operation;
use crate::types::state_types::{IdentityAnchor, State};

use std::collections::{HashMap, HashSet};

/// Placeholder trait for DecentralizedStorage for mobile compilation.
///
/// Boundaries are bytes-first:
/// - Reports are raw bytes (caller decides formatting).
/// - device_id is now &[u8; 32] for canonical binary representation.
pub trait DecentralizedStorage {
    fn store_suspicious_activity_report(&self, report: &[u8]) -> Result<(), DsmError>;
    fn get_historical_states(&self, device_id: &[u8; 32]) -> Result<Vec<State>, DsmError>;
    fn get_published_states(&self, device_id: &[u8; 32]) -> Result<Vec<State>, DsmError>;
}

/// Alert severity levels for suspicious pattern detection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Alert structure for suspicious pattern detection
#[derive(Debug, Clone)]
pub struct Alert {
    pub alert_type: String,
    pub description: String,
    pub severity: AlertSeverity,
}

/// Test relationship state pair structure for isolation verification
#[derive(Debug, Clone)]
pub struct RelationshipStatePair {
    pub entity_id: [u8; 32],
    pub counterparty_id: [u8; 32],
    pub states: Vec<State>,
}

impl RelationshipStatePair {
    /// Check if the relationship contains a given state
    pub fn contains_state(&self, state: &State) -> bool {
        self.states.iter().any(|s| s.hash == state.hash)
    }
}

/// Implements bilateral control attack resistance (whitepaper Section 29)
pub struct BilateralControlResistance;

impl BilateralControlResistance {
    // -------------------- Core helpers --------------------

    #[inline]
    fn tag_bytes(bytes: &[u8]) -> [u8; 32] {
        *crate::crypto::blake3::domain_hash("DSM/device-id", bytes).as_bytes()
    }

    #[inline]
    fn op_bytes(op: &Operation) -> Vec<u8> {
        // Protocol-safe operation comparison without requiring PartialEq on Operation.
        op.to_bytes()
    }

    #[inline]
    fn report_prefix() -> &'static [u8] {
        b"DSM/BCR/REPORT/v2\0"
    }

    // -------------------- Genesis threshold verification --------------------

    /// Verify genesis authentication requirements (whitepaper Section 13).
    ///
    /// This is a structural check only (independence/collusion analysis is out-of-scope here),
    /// but we enforce the non-negotiable minimum signer count and reject self-signing.
    #[allow(clippy::unused_async)]
    pub async fn verify_genesis_threshold(
        identity: &IdentityAnchor,
        signers: &[IdentityAnchor],
        threshold: usize,
        _storage: &impl DecentralizedStorage,
    ) -> Result<bool, DsmError> {
        if threshold < 3 {
            return Ok(false);
        }
        if signers.len() < threshold {
            return Ok(false);
        }
        for signer in signers {
            if signer.id == identity.id {
                return Ok(false);
            }
        }
        Ok(true)
    }

    // -------------------- Directory sync / conflict detection --------------------

    /// Verify directory synchronization (whitepaper Section 29.5).
    #[allow(clippy::unused_async)]
    pub async fn verify_directory_sync(
        state: &State,
        storage: &impl DecentralizedStorage,
    ) -> Result<bool, DsmError> {
        let published_states = storage.get_published_states(&state.device_info.device_id)?;
        for other in &published_states {
            if Self::detect_sequence_conflict(state, other)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Detect conflicting publications using state_number proximity as the ordering proxy.
    ///
    /// We treat "nearby state numbers with different semantic payload" as a probable fork/conflict.
    fn detect_sequence_conflict(a: &State, b: &State) -> Result<bool, DsmError> {
        const CONFLICT_THRESHOLD: u64 = 2;

        if a.state_number.abs_diff(b.state_number) < CONFLICT_THRESHOLD {
            // Semantic conflict: different operation bytes.
            if Self::op_bytes(&a.operation) != Self::op_bytes(&b.operation) {
                return Ok(true);
            }

            // Balance conflict: same token id but different value.
            for (token_id, bal_a) in &a.token_balances {
                if let Some(bal_b) = b.token_balances.get(token_id) {
                    if bal_a.value() != bal_b.value() {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    // -------------------- Relationship isolation --------------------

    /// Verify bilateral state isolation (whitepaper Section 29.3).
    #[allow(clippy::unused_async)]
    pub async fn verify_state_isolation(
        state: &State,
        relationship: &RelationshipStatePair,
        storage: &impl DecentralizedStorage,
    ) -> Result<bool, DsmError> {
        if !relationship.contains_state(state) {
            return Ok(false);
        }

        if let Some(rc) = &state.relationship_context {
            if rc.counterparty_id != relationship.counterparty_id {
                return Ok(false);
            }

            // Ensure the counterparty state referenced by the relationship exists in published states.
            let counterparty_states =
                storage.get_published_states(&relationship.counterparty_id)?;
            let ok = counterparty_states.iter().any(|cs| {
                cs.device_info.device_id == relationship.counterparty_id
                    && cs.state_number == rc.counterparty_state_number
            });

            if !ok {
                return Ok(false);
            }
        }

        // Enforce sequential ordering + hash-chain continuity inside the relationship slice.
        for win in relationship.states.windows(2) {
            let prev = &win[0];
            let next = &win[1];

            if next.state_number != prev.state_number + 1 {
                return Ok(false);
            }

            // Avoid any method calls; use raw hash bytes.
            if next.prev_state_hash != prev.hash {
                return Ok(false);
            }

            if next.state_number <= prev.state_number {
                return Ok(false);
            }
        }

        Ok(true)
    }

    // -------------------- Probability bound --------------------

    /// Calculate bilateral control attack probability bound:
    /// P ≤ 1/2^λ + |R|/|N|^2
    ///
    /// This is a reporting utility; it must be numerically stable.
    pub fn calculate_attack_probability(
        security_parameter: u32,
        controlled_relationships: usize,
        network_size: usize,
    ) -> f64 {
        let crypto_term = if security_parameter >= 1024 {
            0.0
        } else {
            1.0 / (2.0_f64).powi(security_parameter as i32)
        };

        let n = network_size as f64;
        let network_term = if network_size == 0 {
            1.0
        } else {
            (controlled_relationships as f64) / (n * n)
        };

        crypto_term + network_term
    }

    // -------------------- Temporal consistency --------------------

    /// Verify temporal consistency attestations (whitepaper Section 29.5).
    #[allow(clippy::unused_async)]
    pub async fn verify_temporal_consistency(
        states: &[State],
        _storage: &impl DecentralizedStorage,
    ) -> Result<bool, DsmError> {
        for win in states.windows(2) {
            let prev = &win[0];
            let next = &win[1];

            if next.state_number != prev.state_number + 1 {
                return Ok(false);
            }
            if next.prev_state_hash != prev.hash {
                return Ok(false);
            }
            if next.state_number <= prev.state_number {
                return Ok(false);
            }
        }
        Ok(true)
    }

    // -------------------- Suspicious pattern detection --------------------

    /// Monitor for suspicious transaction patterns (whitepaper Section 29.5).
    ///
    /// This returns alerts only; any persistence/reporting is optional and bytes-only.
    pub async fn detect_suspicious_patterns(
        states: &[State],
        storage: &impl DecentralizedStorage,
    ) -> Result<Vec<Alert>, DsmError> {
        let mut alerts = Vec::new();

        // Many consecutive states suggests automated/high-frequency behavior.
        if states.len() > 10
            && states
                .windows(2)
                .all(|w| w[1].state_number == w[0].state_number + 1)
        {
            alerts.push(Alert {
                alert_type: "RapidTransactions".to_string(),
                description: "Unusually long run of consecutive state transitions detected"
                    .to_string(),
                severity: AlertSeverity::Medium,
            });
        }

        let cycles = Self::detect_circular_transfers(states).await?;
        if !cycles.is_empty() {
            alerts.push(Alert {
                alert_type: "CircularTransfer".to_string(),
                description: format!(
                    "Circular value transfer pattern detected involving {} cycle roots",
                    cycles.len()
                ),
                severity: AlertSeverity::High,
            });
        }

        let clustering = Self::detect_relationship_clustering(states, storage).await?;
        if clustering {
            alerts.push(Alert {
                alert_type: "RelationshipClustering".to_string(),
                description: "Suspicious relationship clustering detected".to_string(),
                severity: AlertSeverity::High,
            });
        }

        let anomalous = Self::detect_anomalous_balance_changes(states)?;
        if !anomalous.is_empty() {
            alerts.push(Alert {
                alert_type: "AnomalousBalanceChange".to_string(),
                description: format!(
                    "Anomalous balance changes detected in {} state transitions",
                    anomalous.len()
                ),
                severity: AlertSeverity::Medium,
            });
        }

        let temporal = Self::detect_temporal_manipulation(states)?;
        if temporal {
            alerts.push(Alert {
                alert_type: "TemporalManipulation".to_string(),
                description: "Non-monotonic or highly regular state-number patterns detected"
                    .to_string(),
                severity: AlertSeverity::Critical,
            });
        }

        // Optional: persist a compact report if anything tripped.
        if !alerts.is_empty() {
            let report = Self::build_compact_report(states, &alerts);
            let _ = storage.store_suspicious_activity_report(&report);
        }

        Ok(alerts)
    }

    fn build_compact_report(states: &[State], alerts: &[Alert]) -> Vec<u8> {
        // Format (bytes-only, deterministic):
        // PREFIX || u32(alert_count) || for each alert: u32(type_len)||type||u32(desc_len)||desc
        // || u32(state_count) || for each state: u64(state_number) || u32(hash_len)||hash || u32(prev_len)||prev
        let mut out = Vec::new();
        out.extend_from_slice(Self::report_prefix());

        out.extend_from_slice(&(alerts.len() as u32).to_le_bytes());
        for a in alerts {
            let t = a.alert_type.as_bytes();
            let d = a.description.as_bytes();
            out.extend_from_slice(&(t.len() as u32).to_le_bytes());
            out.extend_from_slice(t);
            out.extend_from_slice(&(d.len() as u32).to_le_bytes());
            out.extend_from_slice(d);
            out.push(match a.severity {
                AlertSeverity::Low => 1,
                AlertSeverity::Medium => 2,
                AlertSeverity::High => 3,
                AlertSeverity::Critical => 4,
            });
        }

        out.extend_from_slice(&(states.len() as u32).to_le_bytes());
        for s in states {
            out.extend_from_slice(&s.state_number.to_le_bytes());

            out.extend_from_slice(&(s.hash.len() as u32).to_le_bytes());
            out.extend_from_slice(&s.hash);

            out.extend_from_slice(&(s.prev_state_hash.len() as u32).to_le_bytes());
            out.extend_from_slice(&s.prev_state_hash);

            // Include device label length + bytes as local context, not a protocol identifier.
            let dev = &s.device_info.device_id;
            out.extend_from_slice(&(dev.len() as u32).to_le_bytes());
            out.extend_from_slice(dev);
        }

        out
    }

    // -------------------- Circular transfer detection --------------------

    /// Detect circular transfer patterns using graph analysis.
    ///
    /// Graph vertices are 32-byte tags:
    /// - sender = H(device_id_label_bytes)
    /// - recipient = H(recipient_raw_bytes)
    #[allow(clippy::unused_async)]
    async fn detect_circular_transfers(states: &[State]) -> Result<Vec<[u8; 32]>, DsmError> {
        let mut graph: HashMap<[u8; 32], Vec<[u8; 32]>> = HashMap::new();

        for s in states {
            if let Operation::Transfer { recipient, .. } = &s.operation {
                let from = s.device_info.device_id;
                let to = Self::tag_bytes(recipient);
                graph.entry(from).or_default().push(to);
            }
        }

        // Cycle detection: iterative DFS per node.
        let mut cycle_roots = Vec::new();
        let keys: Vec<[u8; 32]> = graph.keys().copied().collect();

        for start in keys {
            if Self::has_cycle_from(&graph, start) {
                cycle_roots.push(start);
            }
        }

        Ok(cycle_roots)
    }

    fn has_cycle_from(graph: &HashMap<[u8; 32], Vec<[u8; 32]>>, start: [u8; 32]) -> bool {
        // Standard DFS cycle detection with explicit stack:
        // stack entries: (node, next_neighbor_index)
        let mut in_stack: HashSet<[u8; 32]> = HashSet::new();
        let mut visited: HashSet<[u8; 32]> = HashSet::new();
        let mut stack: Vec<([u8; 32], usize)> = Vec::new();

        stack.push((start, 0));
        in_stack.insert(start);

        while let Some((node, idx)) = stack.pop() {
            if visited.contains(&node) && !in_stack.contains(&node) {
                continue;
            }

            visited.insert(node);

            let neigh = graph.get(&node).map(|v| v.as_slice()).unwrap_or(&[]);
            if idx < neigh.len() {
                // Put current node back with incremented index.
                stack.push((node, idx + 1));

                let next = neigh[idx];
                if in_stack.contains(&next) {
                    return true;
                }
                if !visited.contains(&next) {
                    stack.push((next, 0));
                    in_stack.insert(next);
                }
            } else {
                // Done exploring this node.
                in_stack.remove(&node);
            }
        }

        false
    }

    // -------------------- Relationship clustering detection --------------------

    /// Detect suspicious relationship clustering patterns.
    ///
    /// We avoid depending on specific `Operation` variants (to keep this module stable),
    /// and instead infer relationships from `relationship_context` occurrences.
    #[allow(clippy::unused_async)]
    async fn detect_relationship_clustering(
        states: &[State],
        storage: &impl DecentralizedStorage,
    ) -> Result<bool, DsmError> {
        let mut rels: HashMap<[u8; 32], HashSet<[u8; 32]>> = HashMap::new();

        for s in states {
            if let Some(rc) = &s.relationship_context {
                rels.entry(s.device_info.device_id)
                    .or_default()
                    .insert(rc.counterparty_id);
                rels.entry(rc.counterparty_id)
                    .or_default()
                    .insert(s.device_info.device_id);
            }
        }

        const MAX_RELATIONSHIPS_THRESHOLD: usize = 10;
        const RAPID_FORMATION_SPAN: u64 = 10;
        const RAPID_FORMATION_MIN: usize = 3;

        for (entity, peers) in &rels {
            if peers.len() > MAX_RELATIONSHIPS_THRESHOLD {
                return Ok(true);
            }

            // Pull published states for the entity and look for relationship_context density.
            let hist = storage.get_published_states(entity)?;
            let mut rel_state_numbers: Vec<u64> = hist
                .iter()
                .filter_map(|s| s.relationship_context.as_ref().map(|_| s.state_number))
                .collect();
            rel_state_numbers.sort_unstable();

            if rel_state_numbers.len() >= RAPID_FORMATION_MIN {
                // Sliding window: any 3 relationship-context states within a small span is suspicious.
                for w in rel_state_numbers.windows(RAPID_FORMATION_MIN) {
                    if w[w.len() - 1].saturating_sub(w[0]) < RAPID_FORMATION_SPAN {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    // -------------------- Balance anomaly detection --------------------

    fn detect_anomalous_balance_changes(states: &[State]) -> Result<Vec<u64>, DsmError> {
        let mut anomalous = Vec::new();

        for win in states.windows(2) {
            let prev = &win[0];
            let next = &win[1];

            for (token_id, next_bal) in &next.token_balances {
                if let Some(prev_bal) = prev.token_balances.get(token_id) {
                    let delta = next_bal.value() as i128 - prev_bal.value() as i128;

                    match &next.operation {
                        Operation::Transfer {
                            amount,
                            token_id: op_token,
                            ..
                        } => {
                            if token_id.as_bytes() == op_token.as_slice() {
                                let expected = -(amount.value() as i128);

                                if delta != expected {
                                    anomalous.push(next.state_number);
                                }

                                // >90% of previous balance in one transfer is suspicious.
                                if amount.value() > (prev_bal.value().saturating_mul(9) / 10) {
                                    anomalous.push(next.state_number);
                                }
                            }
                        }
                        _ => {
                            // Generic bound: delta magnitude exceeding previous balance is suspect.
                            if delta.unsigned_abs() > (prev_bal.value() as i128).unsigned_abs() {
                                anomalous.push(next.state_number);
                            }
                        }
                    }
                }
            }
        }

        Ok(anomalous)
    }

    // -------------------- Temporal manipulation detection --------------------

    fn detect_temporal_manipulation(states: &[State]) -> Result<bool, DsmError> {
        if states.len() < 2 {
            return Ok(false);
        }

        // Non-monotonic state numbers
        for win in states.windows(2) {
            if win[1].state_number <= win[0].state_number {
                return Ok(true);
            }
        }

        // Highly regular intervals across a long sequence (automation signature).
        if states.len() >= 8 {
            let mut gaps: Vec<u64> = Vec::with_capacity(states.len() - 1);
            for win in states.windows(2) {
                gaps.push(win[1].state_number.saturating_sub(win[0].state_number));
            }

            let first = gaps[0];
            if first != 0 && gaps.iter().all(|&g| g == first) {
                return Ok(true);
            }
        }

        // Suspiciously large jumps.
        for win in states.windows(2) {
            let gap = win[1].state_number.saturating_sub(win[0].state_number);
            if gap > 100 {
                return Ok(true);
            }
        }

        Ok(false)
    }
}
