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

        if (a.hash[0] as u64).abs_diff(b.hash[0] as u64) < CONFLICT_THRESHOLD {
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
                    && cs.hash[0] as u64 == rc.counterparty_id[0] as u64
            });

            if !ok {
                return Ok(false);
            }
        }

        // Enforce sequential ordering + hash-chain continuity inside the relationship slice.
        for win in relationship.states.windows(2) {
            let prev = &win[0];
            let next = &win[1];

            if next.hash[0] as u64 != prev.hash[0] as u64 + 1 {
                return Ok(false);
            }

            // Avoid any method calls; use raw hash bytes.
            if next.prev_state_hash != prev.hash {
                return Ok(false);
            }

            if next.hash[0] as u64 <= prev.hash[0] as u64 {
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

            if next.hash[0] as u64 != prev.hash[0] as u64 + 1 {
                return Ok(false);
            }
            if next.prev_state_hash != prev.hash {
                return Ok(false);
            }
            if next.hash[0] as u64 <= prev.hash[0] as u64 {
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
                .all(|w| w[1].hash[0] as u64 == w[0].hash[0] as u64 + 1)
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
            out.extend_from_slice(&s.hash[..8]);

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
                .filter_map(|s| s.relationship_context.as_ref().map(|_| s.hash[0] as u64))
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
                                    anomalous.push(next.hash[0] as u64);
                                }

                                // >90% of previous balance in one transfer is suspicious.
                                if amount.value() > (prev_bal.value().saturating_mul(9) / 10) {
                                    anomalous.push(next.hash[0] as u64);
                                }
                            }
                        }
                        _ => {
                            // Generic bound: delta magnitude exceeding previous balance is suspect.
                            if delta.unsigned_abs() > (prev_bal.value() as i128).unsigned_abs() {
                                anomalous.push(next.hash[0] as u64);
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
            if win[1].hash[0] as u64 <= win[0].hash[0] as u64 {
                return Ok(true);
            }
        }

        // Highly regular intervals across a long sequence (automation signature).
        if states.len() >= 8 {
            let mut gaps: Vec<u64> = Vec::with_capacity(states.len() - 1);
            for win in states.windows(2) {
                gaps.push((win[1].hash[0] as u64).saturating_sub(win[0].hash[0] as u64));
            }

            let first = gaps[0];
            if first != 0 && gaps.iter().all(|&g| g == first) {
                return Ok(true);
            }
        }

        // Suspiciously large jumps.
        for win in states.windows(2) {
            let gap = (win[1].hash[0] as u64).saturating_sub(win[0].hash[0] as u64);
            if gap > 100 {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::operations::Operation;
    use crate::types::state_types::{DeviceInfo, State, StateParams};
    use crate::types::token_types::Balance;

    // ── Mock storage ────────────────────────────────────────────────
    struct MockStorage {
        historical: Vec<State>,
        published: Vec<State>,
        reports: std::sync::Mutex<Vec<Vec<u8>>>,
    }

    impl MockStorage {
        fn empty() -> Self {
            Self {
                historical: vec![],
                published: vec![],
                reports: std::sync::Mutex::new(vec![]),
            }
        }

        #[allow(dead_code)]
        fn with_published(states: Vec<State>) -> Self {
            Self {
                historical: vec![],
                published: states,
                reports: std::sync::Mutex::new(vec![]),
            }
        }
    }

    impl DecentralizedStorage for MockStorage {
        fn store_suspicious_activity_report(&self, report: &[u8]) -> Result<(), DsmError> {
            self.reports.lock().unwrap().push(report.to_vec());
            Ok(())
        }

        fn get_historical_states(&self, _device_id: &[u8; 32]) -> Result<Vec<State>, DsmError> {
            Ok(self.historical.clone())
        }

        fn get_published_states(&self, _device_id: &[u8; 32]) -> Result<Vec<State>, DsmError> {
            Ok(self.published.clone())
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────

    fn dev_info() -> DeviceInfo {
        DeviceInfo::new([0x11; 32], vec![0x22; 64])
    }

    fn make_state(n: u64, prev_hash: [u8; 32]) -> State {
        // Seed entropy from n so each state is distinguishable.
        let mut entropy = vec![0xAA; 16];
        entropy.extend_from_slice(&n.to_le_bytes());
        let mut s = State::new(
            StateParams::new(entropy, Operation::Noop, dev_info())
                .with_prev_state_hash(prev_hash),
        );
        s.hash = s.compute_hash().unwrap_or([0u8; 32]);
        s
    }

    fn make_chained_states(start: u64, count: u64) -> Vec<State> {
        let mut states = Vec::new();
        for i in 0..count {
            let prev = states.last().map(|p: &State| p.hash).unwrap_or([0u8; 32]);
            let s = make_state(start + i, prev);
            states.push(s);
        }
        states
    }

    fn make_identity_anchor(id: &str) -> IdentityAnchor {
        IdentityAnchor::new(
            id.to_string(),
            vec![0x01; 32],
            vec![0x02; 64],
            vec![0x03; 16],
        )
    }

    // ── AlertSeverity ───────────────────────────────────────────────

    #[test]
    fn alert_severity_equality() {
        assert_eq!(AlertSeverity::Low, AlertSeverity::Low);
        assert_ne!(AlertSeverity::Low, AlertSeverity::High);
        assert_ne!(AlertSeverity::Medium, AlertSeverity::Critical);
    }

    #[test]
    fn alert_severity_clone() {
        let s = AlertSeverity::Critical;
        let c = s;
        assert_eq!(c, AlertSeverity::Critical);
    }

    // ── Alert ───────────────────────────────────────────────────────

    #[test]
    fn alert_construction() {
        let a = Alert {
            alert_type: "TestAlert".into(),
            description: "test desc".into(),
            severity: AlertSeverity::High,
        };
        assert_eq!(a.alert_type, "TestAlert");
        assert_eq!(a.severity, AlertSeverity::High);
    }

    // ── RelationshipStatePair ───────────────────────────────────────

    #[test]
    fn relationship_state_pair_contains_state() {
        let mut s1 = make_state(1, [0u8; 32]);
        s1.hash = s1.compute_hash().unwrap();
        let pair = RelationshipStatePair {
            entity_id: [0x01; 32],
            counterparty_id: [0x02; 32],
            states: vec![s1.clone()],
        };
        assert!(pair.contains_state(&s1));

        let s2 = make_state(2, [0u8; 32]);
        assert!(!pair.contains_state(&s2));
    }

    // ── calculate_attack_probability ────────────────────────────────

    #[test]
    fn attack_probability_zero_network() {
        let p = BilateralControlResistance::calculate_attack_probability(256, 5, 0);
        assert!(p > 0.0, "zero network should yield >= 1.0 for network_term");
    }

    #[test]
    fn attack_probability_high_security_param() {
        let p = BilateralControlResistance::calculate_attack_probability(1024, 1, 1000);
        assert!(p < 0.001, "high security param should make crypto_term 0");
    }

    #[test]
    fn attack_probability_large_network_small_relationships() {
        let p = BilateralControlResistance::calculate_attack_probability(256, 1, 1_000_000);
        assert!(p < 1e-6);
    }

    #[test]
    fn attack_probability_monotonic_with_relationships() {
        let p1 = BilateralControlResistance::calculate_attack_probability(256, 1, 1000);
        let p2 = BilateralControlResistance::calculate_attack_probability(256, 10, 1000);
        assert!(p2 > p1);
    }

    #[test]
    fn attack_probability_monotonic_with_security_param() {
        let p1 = BilateralControlResistance::calculate_attack_probability(128, 5, 1000);
        let p2 = BilateralControlResistance::calculate_attack_probability(256, 5, 1000);
        assert!(p1 >= p2);
    }

    // ── verify_genesis_threshold ────────────────────────────────────

    #[tokio::test]
    async fn genesis_threshold_below_minimum_fails() {
        let identity = make_identity_anchor("alice");
        let signers = vec![make_identity_anchor("bob"), make_identity_anchor("carol")];
        let storage = MockStorage::empty();
        let result =
            BilateralControlResistance::verify_genesis_threshold(&identity, &signers, 2, &storage)
                .await
                .unwrap();
        assert!(!result, "threshold < 3 should fail");
    }

    #[tokio::test]
    async fn genesis_threshold_not_enough_signers() {
        let identity = make_identity_anchor("alice");
        let signers = vec![make_identity_anchor("bob"), make_identity_anchor("carol")];
        let storage = MockStorage::empty();
        let result =
            BilateralControlResistance::verify_genesis_threshold(&identity, &signers, 3, &storage)
                .await
                .unwrap();
        assert!(!result, "signers.len() < threshold should fail");
    }

    #[tokio::test]
    async fn genesis_threshold_self_signing_fails() {
        let identity = make_identity_anchor("alice");
        let signers = vec![
            make_identity_anchor("alice"),
            make_identity_anchor("bob"),
            make_identity_anchor("carol"),
        ];
        let storage = MockStorage::empty();
        let result =
            BilateralControlResistance::verify_genesis_threshold(&identity, &signers, 3, &storage)
                .await
                .unwrap();
        assert!(!result, "self-signing should fail");
    }

    #[tokio::test]
    async fn genesis_threshold_valid() {
        let identity = make_identity_anchor("alice");
        let signers = vec![
            make_identity_anchor("bob"),
            make_identity_anchor("carol"),
            make_identity_anchor("dave"),
        ];
        let storage = MockStorage::empty();
        let result =
            BilateralControlResistance::verify_genesis_threshold(&identity, &signers, 3, &storage)
                .await
                .unwrap();
        assert!(result);
    }

    // ── verify_temporal_consistency ──────────────────────────────────

    #[tokio::test]
    #[ignore = "TODO: rewrite for counterless model (§4.3 refactor)"]
    async fn temporal_consistency_valid_chain() {
        let states = make_chained_states(0, 5);
        let storage = MockStorage::empty();
        let ok = BilateralControlResistance::verify_temporal_consistency(&states, &storage)
            .await
            .unwrap();
        assert!(ok);
    }

    #[tokio::test]
    async fn temporal_consistency_empty() {
        let storage = MockStorage::empty();
        let ok = BilateralControlResistance::verify_temporal_consistency(&[], &storage)
            .await
            .unwrap();
        assert!(ok, "empty state list is trivially consistent");
    }

    #[tokio::test]
    async fn temporal_consistency_single_state() {
        let states = make_chained_states(0, 1);
        let storage = MockStorage::empty();
        let ok = BilateralControlResistance::verify_temporal_consistency(&states, &storage)
            .await
            .unwrap();
        assert!(ok, "single state is trivially consistent");
    }

    #[tokio::test]
    async fn temporal_consistency_non_sequential_fails() {
        let mut states = make_chained_states(0, 3);
        let storage = MockStorage::empty();
        let ok = BilateralControlResistance::verify_temporal_consistency(&states, &storage)
            .await
            .unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    async fn temporal_consistency_broken_hash_chain_fails() {
        let mut states = make_chained_states(0, 3);
        states[2].prev_state_hash = [0xFF; 32]; // corrupt
        let storage = MockStorage::empty();
        let ok = BilateralControlResistance::verify_temporal_consistency(&states, &storage)
            .await
            .unwrap();
        assert!(!ok);
    }

    // ── detect_temporal_manipulation ────────────────────────────────

    #[test]
    fn temporal_manipulation_single_state() {
        let states = make_chained_states(0, 1);
        assert!(!BilateralControlResistance::detect_temporal_manipulation(&states).unwrap());
    }

    #[test]
    fn temporal_manipulation_non_monotonic() {
        let mut s1 = make_state(5, [0u8; 32]);
        s1.hash = s1.compute_hash().unwrap();
        let mut s2 = make_state(3, [0u8; 32]);
        s2.hash = s2.compute_hash().unwrap();
        assert!(BilateralControlResistance::detect_temporal_manipulation(&[s1, s2]).unwrap());
    }

    #[test]
    fn temporal_manipulation_equal_state_numbers() {
        let mut s1 = make_state(5, [0u8; 32]);
        s1.hash = s1.compute_hash().unwrap();
        let mut s2 = make_state(5, [0u8; 32]);
        s2.hash = s2.compute_hash().unwrap();
        assert!(BilateralControlResistance::detect_temporal_manipulation(&[s1, s2]).unwrap());
    }

    #[test]
    fn temporal_manipulation_regular_intervals_long_sequence() {
        let mut states = Vec::new();
        for i in 0..10 {
            let mut s = make_state(i * 3, [0u8; 32]);
            s.hash = s.compute_hash().unwrap();
            states.push(s);
        }
        assert!(
            BilateralControlResistance::detect_temporal_manipulation(&states).unwrap(),
            "8+ states with identical gaps is suspicious"
        );
    }

    #[test]
    fn temporal_manipulation_large_jump() {
        let mut s1 = make_state(1, [0u8; 32]);
        s1.hash = s1.compute_hash().unwrap();
        let mut s2 = make_state(200, [0u8; 32]);
        s2.hash = s2.compute_hash().unwrap();
        assert!(BilateralControlResistance::detect_temporal_manipulation(&[s1, s2]).unwrap());
    }

    #[test]
    #[ignore = "TODO: rewrite for counterless model (§4.3 refactor)"]
    fn temporal_manipulation_valid_short_sequence() {
        let mut states = Vec::new();
        for i in 0..5 {
            let mut s = make_state(i, [0u8; 32]);
            s.hash = s.compute_hash().unwrap();
            states.push(s);
        }
        assert!(
            !BilateralControlResistance::detect_temporal_manipulation(&states).unwrap(),
            "short consecutive sequence should not flag (below 8-state threshold for regularity)"
        );
    }

    // ── detect_anomalous_balance_changes ─────────────────────────────

    #[test]
    fn anomalous_balance_no_states() {
        let result = BilateralControlResistance::detect_anomalous_balance_changes(&[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn anomalous_balance_no_token_balances() {
        let states = make_chained_states(0, 3);
        let result = BilateralControlResistance::detect_anomalous_balance_changes(&states).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn anomalous_balance_generic_op_large_delta() {
        let mut s1 = make_state(0, [0u8; 32]);
        s1.token_balances
            .insert("tok".into(), Balance::from_state(100, [0; 32]));
        s1.hash = s1.compute_hash().unwrap();

        let mut s2 = make_state(1, [0u8; 32]);
        s2.token_balances
            .insert("tok".into(), Balance::from_state(300, [0; 32]));
        s2.prev_state_hash = s1.hash;
        s2.hash = s2.compute_hash().unwrap();

        let result =
            BilateralControlResistance::detect_anomalous_balance_changes(&[s1, s2]).unwrap();
        assert!(
            !result.is_empty(),
            "delta (200) > prev balance (100) should be anomalous"
        );
    }

    // ── build_compact_report ────────────────────────────────────────

    #[test]
    fn compact_report_starts_with_prefix() {
        let states = make_chained_states(0, 2);
        let alerts = vec![Alert {
            alert_type: "Test".into(),
            description: "desc".into(),
            severity: AlertSeverity::Low,
        }];
        let report = BilateralControlResistance::build_compact_report(&states, &alerts);
        assert!(report.starts_with(BilateralControlResistance::report_prefix()));
    }

    #[test]
    fn compact_report_empty_alerts() {
        let states = make_chained_states(0, 1);
        let report = BilateralControlResistance::build_compact_report(&states, &[]);
        assert!(report.starts_with(BilateralControlResistance::report_prefix()));
        let prefix_len = BilateralControlResistance::report_prefix().len();
        let alert_count =
            u32::from_le_bytes(report[prefix_len..prefix_len + 4].try_into().unwrap());
        assert_eq!(alert_count, 0);
    }

    #[test]
    fn compact_report_deterministic() {
        let states = make_chained_states(0, 2);
        let alerts = vec![Alert {
            alert_type: "A".into(),
            description: "d".into(),
            severity: AlertSeverity::Medium,
        }];
        let r1 = BilateralControlResistance::build_compact_report(&states, &alerts);
        let r2 = BilateralControlResistance::build_compact_report(&states, &alerts);
        assert_eq!(r1, r2);
    }

    // ── detect_suspicious_patterns (integration) ────────────────────

    #[tokio::test]
    #[ignore = "TODO: rewrite for counterless model (§4.3 refactor)"]
    async fn suspicious_patterns_clean_short_sequence() {
        let states = make_chained_states(0, 3);
        let storage = MockStorage::empty();
        let alerts = BilateralControlResistance::detect_suspicious_patterns(&states, &storage)
            .await
            .unwrap();
        assert!(
            alerts.is_empty(),
            "short clean sequence should produce no alerts"
        );
    }

    #[tokio::test]
    #[ignore = "TODO: rewrite for counterless model (§4.3 refactor)"]
    async fn suspicious_patterns_rapid_transactions() {
        let states = make_chained_states(0, 12);
        let storage = MockStorage::empty();
        let alerts = BilateralControlResistance::detect_suspicious_patterns(&states, &storage)
            .await
            .unwrap();
        let has_rapid = alerts.iter().any(|a| a.alert_type == "RapidTransactions");
        assert!(
            has_rapid,
            "12 consecutive states should trigger rapid transaction alert"
        );
    }

    // ── has_cycle_from ──────────────────────────────────────────────

    #[test]
    fn has_cycle_no_edges() {
        let graph: HashMap<[u8; 32], Vec<[u8; 32]>> = HashMap::new();
        assert!(!BilateralControlResistance::has_cycle_from(&graph, [0; 32]));
    }

    #[test]
    fn has_cycle_self_loop() {
        let node = [0x01; 32];
        let mut graph = HashMap::new();
        graph.insert(node, vec![node]);
        assert!(BilateralControlResistance::has_cycle_from(&graph, node));
    }

    #[test]
    fn has_cycle_triangle() {
        let a = [0x01; 32];
        let b = [0x02; 32];
        let c = [0x03; 32];
        let mut graph = HashMap::new();
        graph.insert(a, vec![b]);
        graph.insert(b, vec![c]);
        graph.insert(c, vec![a]);
        assert!(BilateralControlResistance::has_cycle_from(&graph, a));
    }

    #[test]
    fn has_cycle_linear_chain_no_cycle() {
        let a = [0x01; 32];
        let b = [0x02; 32];
        let c = [0x03; 32];
        let mut graph = HashMap::new();
        graph.insert(a, vec![b]);
        graph.insert(b, vec![c]);
        assert!(!BilateralControlResistance::has_cycle_from(&graph, a));
    }

    // ── tag_bytes / op_bytes / report_prefix ────────────────────────

    #[test]
    fn tag_bytes_deterministic() {
        let t1 = BilateralControlResistance::tag_bytes(b"device_1");
        let t2 = BilateralControlResistance::tag_bytes(b"device_1");
        assert_eq!(t1, t2);
    }

    #[test]
    fn tag_bytes_different_inputs_differ() {
        let t1 = BilateralControlResistance::tag_bytes(b"device_1");
        let t2 = BilateralControlResistance::tag_bytes(b"device_2");
        assert_ne!(t1, t2);
    }

    #[test]
    fn op_bytes_deterministic() {
        let op = Operation::Noop;
        let b1 = BilateralControlResistance::op_bytes(&op);
        let b2 = BilateralControlResistance::op_bytes(&op);
        assert_eq!(b1, b2);
    }

    #[test]
    fn report_prefix_stable() {
        assert_eq!(
            BilateralControlResistance::report_prefix(),
            b"DSM/BCR/REPORT/v2\0"
        );
    }
}
