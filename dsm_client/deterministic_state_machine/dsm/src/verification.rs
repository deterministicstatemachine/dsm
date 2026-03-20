//! Formal verification and property-based testing for DSM
//!
//! This module provides property-based testing with proptest,
//! invariant checking, formal verification support, and
//! comprehensive testing infrastructure.
//!
//! DSM constraints enforced here:
//! - No wall-clock / epoch time dependencies
//! - No OS randomness / UUID v4 randomness
//! - Deterministic, reproducible generators (counter + BLAKE3 domain hashing)
//! - Property tests must actually assert properties (no "always Ok" runners)

pub mod proof_primitives;
pub mod receipt_verification;
pub mod smt_replace_witness;

use futures::Stream;
use std::collections::HashMap;

use crate::types::unified_error::{DsmResult, UnifiedDsmError};
use crate::types::{SessionId, TransactionId, VaultId};
#[cfg(test)]
use crate::crypto::blake3::domain_hash_bytes;
#[cfg(test)]
use proptest::prelude::*;
#[cfg(test)]
use proptest::strategy::Strategy;

/// Invariant checker for system properties
pub struct InvariantChecker {
    invariants: Vec<Box<dyn Invariant>>,
}

impl Default for InvariantChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl InvariantChecker {
    /// Create a new invariant checker
    pub fn new() -> Self {
        Self {
            invariants: Vec::new(),
        }
    }

    /// Add an invariant to check
    pub fn add_invariant<I: Invariant + 'static>(mut self, invariant: I) -> Self {
        self.invariants.push(Box::new(invariant));
        self
    }

    /// Check all invariants
    pub async fn check_all(&self, state: &SystemState) -> DsmResult<Vec<InvariantResult>> {
        let mut results = Vec::with_capacity(self.invariants.len());
        for invariant in &self.invariants {
            let result = invariant.check(state).await?;
            results.push(result);
        }
        Ok(results)
    }

    /// Check invariants continuously
    pub async fn check_continuous(
        &self,
        state_stream: impl Stream<Item = SystemState>,
    ) -> DsmResult<()> {
        use futures::StreamExt;

        let mut stream = Box::pin(state_stream);
        while let Some(state) = stream.next().await {
            let results = self.check_all(&state).await?;
            for result in results {
                if !result.passed {
                    return Err(UnifiedDsmError::Validation {
                        context: format!("Invariant failed: {}", result.description),
                        field: Some(result.description.clone()),
                        recoverable: false,
                    });
                }
            }

            tracing::info!(
                operation = "All invariants passed",
                state_version = %state.version
            );
        }

        Ok(())
    }
}

/// System state for invariant checking
#[derive(Debug, Clone)]
pub struct SystemState {
    /// Logical version / tick (monotonic, deterministic)
    pub version: u64,
    pub vaults: HashMap<VaultId, VaultState>,
    pub transactions: Vec<TransactionState>,
    pub sessions: HashMap<SessionId, SessionState>,
    pub network_state: NetworkState,
    /// The sum of all vault balances before applying any generated transactions. Used to
    /// verify conservation of supply across state transitions in property tests.
    pub initial_total_balance: u64,
}

#[derive(Debug, Clone)]
pub struct VaultState {
    pub id: VaultId,
    pub balance: u64,
    pub transactions: Vec<TransactionId>,
    /// Logical tick of last activity (NOT epoch time)
    pub last_activity: u64,
}

#[derive(Debug, Clone)]
pub struct TransactionState {
    pub id: TransactionId,
    pub sender: VaultId,
    pub receiver: VaultId,
    pub amount: u64,
    pub status: TransactionStatus,
}

#[derive(Debug, Clone)]
pub enum TransactionStatus {
    Pending,
    Confirmed,
    Failed,
}

#[derive(Debug, Clone)]
pub struct SessionState {
    pub id: SessionId,
    pub vault_id: VaultId,
    /// Logical tick at creation
    pub created_at: u64,
    /// Logical tick at expiry
    pub expires_at: u64,
    pub active: bool,
}

#[derive(Debug, Clone)]
pub struct NetworkState {
    pub connected_nodes: usize,
    pub total_transactions: u64,
    pub network_hash_rate: u64,
}

/// Invariant trait
#[async_trait::async_trait]
pub trait Invariant: Send + Sync {
    #[allow(clippy::unused_async)]
    async fn check(&self, state: &SystemState) -> DsmResult<InvariantResult>;
    fn description(&self) -> &'static str;
}

/// Invariant check result
#[derive(Debug, Clone)]
pub struct InvariantResult {
    pub description: String,
    pub passed: bool,
    pub details: Option<String>,
}

/// Balance conservation invariant
pub struct BalanceConservationInvariant;

#[async_trait::async_trait]
impl Invariant for BalanceConservationInvariant {
    #[allow(clippy::unused_async)]
    async fn check(&self, state: &SystemState) -> DsmResult<InvariantResult> {
        let mut total_balance = 0u64;
        for vault in state.vaults.values() {
            total_balance = total_balance.saturating_add(vault.balance);
        }

        // Verify that total supply is conserved: the sum of current vault balances must
        // equal the initial total balance recorded before applying any generated transactions.
        // Transfers are internal to the vault set and should preserve the total supply.
        let passed = total_balance == state.initial_total_balance;
        let details = if passed {
            None
        } else {
            Some(format!(
                "Initial total: {}, Current total vault balance: {}",
                state.initial_total_balance, total_balance
            ))
        };

        Ok(InvariantResult {
            description: "Balance conservation".to_string(),
            passed,
            details,
        })
    }

    fn description(&self) -> &'static str {
        "Total system balance must remain consistent with confirmed transfers"
    }
}

/// Transaction integrity invariant
pub struct TransactionIntegrityInvariant;

#[async_trait::async_trait]
impl Invariant for TransactionIntegrityInvariant {
    #[allow(clippy::unused_async)]
    async fn check(&self, state: &SystemState) -> DsmResult<InvariantResult> {
        for tx in &state.transactions {
            if !state.vaults.contains_key(&tx.sender) {
                return Ok(InvariantResult {
                    description: "Transaction integrity".to_string(),
                    passed: false,
                    details: Some(format!(
                        "Transaction {} has non-existent sender {}",
                        tx.id, tx.sender
                    )),
                });
            }

            if !state.vaults.contains_key(&tx.receiver) {
                return Ok(InvariantResult {
                    description: "Transaction integrity".to_string(),
                    passed: false,
                    details: Some(format!(
                        "Transaction {} has non-existent receiver {}",
                        tx.id, tx.receiver
                    )),
                });
            }

            if matches!(tx.status, TransactionStatus::Pending) {
                let sender_balance = state.vaults[&tx.sender].balance;
                if sender_balance < tx.amount {
                    return Ok(InvariantResult {
                        description: "Transaction integrity".to_string(),
                        passed: false,
                        details: Some(format!(
                            "Transaction {} exceeds sender balance: {} < {}",
                            tx.id, sender_balance, tx.amount
                        )),
                    });
                }
            }
        }

        Ok(InvariantResult {
            description: "Transaction integrity".to_string(),
            passed: true,
            details: None,
        })
    }

    fn description(&self) -> &'static str {
        "All transactions must reference valid vaults and have sufficient balance for pending sends"
    }
}

/// Session validity invariant
pub struct SessionValidityInvariant;

#[async_trait::async_trait]
impl Invariant for SessionValidityInvariant {
    #[allow(clippy::unused_async)]
    async fn check(&self, state: &SystemState) -> DsmResult<InvariantResult> {
        // DSM rule: never consult wall-clock time.
        // We interpret session ticks as logical ticks and use state.version as "now".
        let now = state.version;

        for session in state.sessions.values() {
            if !state.vaults.contains_key(&session.vault_id) {
                return Ok(InvariantResult {
                    description: "Session validity".to_string(),
                    passed: false,
                    details: Some(format!(
                        "Session {} references non-existent vault {}",
                        session.id, session.vault_id
                    )),
                });
            }

            if session.active && session.expires_at < now {
                return Ok(InvariantResult {
                    description: "Session validity".to_string(),
                    passed: false,
                    details: Some(format!(
                        "Session {} is expired (expires_at={}, now={}) but still active",
                        session.id, session.expires_at, now
                    )),
                });
            }
        }

        Ok(InvariantResult {
            description: "Session validity".to_string(),
            passed: true,
            details: None,
        })
    }

    fn description(&self) -> &'static str {
        "All sessions must reference valid vaults and must not be expired while active (logical time)"
    }
}

#[cfg(test)]
/// Property-based testing configuration
#[derive(Debug, Clone)]
pub struct PropertyTestConfig {
    /// Number of test cases to generate
    pub cases: u32,
    /// Maximum size of generated data (interpreted as a deterministic bound, not time)
    pub max_size: usize,
    /// Enable shrinking of failing cases
    pub shrink: bool,
    /// Deterministic step budget per test case (NOT wall-clock seconds)
    pub timeout_seconds: u64,
    /// Enable verbose output
    pub verbose: bool,
}

#[cfg(test)]
/// Deterministic test generator: counter + BLAKE3 domain hashing
#[derive(Clone, Debug)]
struct DeterministicRng {
    seed: [u8; 32],
    ctr: u64,
}

#[cfg(test)]
impl DeterministicRng {
    fn new(seed: [u8; 32]) -> Self {
        Self { seed, ctr: 0 }
    }

    fn next_block(&mut self, domain: &'static str) -> [u8; 32] {
        let mut buf = [0u8; 40];
        buf[0..32].copy_from_slice(&self.seed);
        buf[32..40].copy_from_slice(&self.ctr.to_le_bytes());
        self.ctr = self.ctr.wrapping_add(1);
        domain_hash_bytes(domain, &buf)
    }

    fn next_u64(&mut self, domain: &'static str) -> u64 {
        let b = self.next_block(domain);
        let mut x = [0u8; 8];
        x.copy_from_slice(&b[0..8]);
        u64::from_le_bytes(x)
    }

    fn next_bool(&mut self, domain: &'static str, true_every: u64, out_of: u64) -> bool {
        if out_of == 0 {
            return false;
        }
        (self.next_u64(domain) % out_of) < true_every
    }

    fn next_range_u64(&mut self, domain: &'static str, lo: u64, hi_inclusive: u64) -> u64 {
        if lo >= hi_inclusive {
            return lo;
        }
        let span = hi_inclusive - lo + 1;
        lo + (self.next_u64(domain) % span)
    }

    fn next_uuid(&mut self, domain: &'static str) -> uuid::Uuid {
        let b = self.next_block(domain);
        let mut id = [0u8; 16];
        id.copy_from_slice(&b[0..16]);
        uuid::Uuid::from_bytes(id)
    }
}

#[cfg(test)]
/// Property-based test strategies
pub mod strategies {
    use super::*;

    const MAX_VAULTS: u64 = 10;
    const MAX_TXS: u64 = 100;
    const MAX_SESSIONS_PER_VAULT: u64 = 1;

    const MIN_BALANCE: u64 = 1_000;
    const MAX_BALANCE: u64 = 5_000_000;

    const MIN_TX_AMOUNT: u64 = 1;
    const MAX_TX_AMOUNT: u64 = 10_000;

    /// Deterministic valid system state (coherent references, no wall-clock time).
    pub fn valid_system_state() -> SystemState {
        let seed = domain_hash_bytes("DSM/PBT/VALID_STATE", b"");
        build_system_state_from_seed(seed)
    }

    fn build_system_state_from_seed(seed: [u8; 32]) -> SystemState {
        let mut rng = DeterministicRng::new(seed);

        let version = rng.next_range_u64("DSM/PBT/VERSION", 1, 1_000_000);

        let vault_count = rng.next_range_u64("DSM/PBT/VAULT_COUNT", 1, MAX_VAULTS) as usize;
        let mut vault_ids: Vec<VaultId> = Vec::with_capacity(vault_count);
        let mut vaults: HashMap<VaultId, VaultState> = HashMap::with_capacity(vault_count);

        for _ in 0..vault_count {
            let vid = VaultId::new(rng.next_uuid("DSM/PBT/VAULT_ID"));
            let balance = rng.next_range_u64("DSM/PBT/VAULT_BAL", MIN_BALANCE, MAX_BALANCE);
            let last_activity = rng.next_range_u64("DSM/PBT/VAULT_LAST", 0, version);

            let vs = VaultState {
                id: vid.clone(),
                balance,
                transactions: Vec::new(),
                last_activity,
            };

            vault_ids.push(vid.clone());
            vaults.insert(vid, vs);
        }

        // Record the initial total balance before applying generated transactions so we
        // can assert conservation of supply after applying confirmed transfers.
        let initial_total_balance = vaults
            .values()
            .fold(0u64, |acc, v| acc.saturating_add(v.balance));

        let tx_count = rng.next_range_u64("DSM/PBT/TX_COUNT", 0, MAX_TXS) as usize;
        let mut transactions: Vec<TransactionState> = Vec::with_capacity(tx_count);
        // Track reserved amounts for pending transactions so that later confirmed
        // transactions cannot consume funds already promised to pending sends.
        let mut reserved: HashMap<VaultId, u64> = HashMap::new();

        for _ in 0..tx_count {
            if vault_ids.len() < 2 {
                break;
            }

            let sender_idx = (rng.next_u64("DSM/PBT/SENDER_IDX") as usize) % vault_ids.len();
            let mut receiver_idx = (rng.next_u64("DSM/PBT/RECV_IDX") as usize) % vault_ids.len();
            if receiver_idx == sender_idx {
                receiver_idx = (receiver_idx + 1) % vault_ids.len();
            }

            let sender = vault_ids[sender_idx].clone();
            let receiver = vault_ids[receiver_idx].clone();

            // Get current sender base balance (after any previous confirmed transactions)
            let base_balance = vaults
                .get(&sender)
                .map(|v| v.balance)
                .unwrap_or(MIN_BALANCE);
            // Subtract amounts already reserved by earlier pending transactions for this sender
            let reserved_for_sender = *reserved.get(&sender).unwrap_or(&0u64);
            let available_balance = base_balance.saturating_sub(reserved_for_sender);

            let status = if rng.next_bool("DSM/PBT/TX_STATUS", 7, 10) {
                TransactionStatus::Confirmed
            } else {
                TransactionStatus::Pending
            };

            // Ensure we never propose an amount larger than the sender's available balance
            // (base balance minus existing reservations). Cap by MAX_TX_AMOUNT as well.
            let max_amt = available_balance.min(MAX_TX_AMOUNT);
            // If the sender cannot even afford the minimum configured tx amount, skip creating a tx.
            if max_amt < MIN_TX_AMOUNT {
                continue;
            }
            let amount = rng.next_range_u64("DSM/PBT/TX_AMT", MIN_TX_AMOUNT, max_amt);

            let tx_id = TransactionId::new(rng.next_uuid("DSM/PBT/TX_ID"));
            let status_clone = status.clone();
            transactions.push(TransactionState {
                id: tx_id.clone(),
                sender: sender.clone(),
                receiver: receiver.clone(),
                amount,
                status: status_clone,
            });

            // Apply effects:
            // - Confirmed transactions immediately move funds (debit sender, credit receiver).
            // - Pending transactions reserve the amount so later confirmed transactions cannot
            //   consume those funds; reservation does not change vault balances.
            if matches!(status, TransactionStatus::Confirmed) {
                if let Some(sender_vault) = vaults.get_mut(&sender) {
                    sender_vault.balance = sender_vault.balance.saturating_sub(amount);
                }
                if let Some(receiver_vault) = vaults.get_mut(&receiver) {
                    receiver_vault.balance = receiver_vault.balance.saturating_add(amount);
                }
            } else {
                let e = reserved.entry(sender.clone()).or_insert(0);
                *e = e.saturating_add(amount);
            }

            if let Some(v) = vaults.get_mut(&sender) {
                v.transactions.push(tx_id.clone());
            }
            if let Some(v) = vaults.get_mut(&receiver) {
                v.transactions.push(tx_id);
            }
        }

        let mut sessions: HashMap<SessionId, SessionState> = HashMap::new();
        for vid in &vault_ids {
            // Deterministic ~60% inclusion
            if rng.next_bool("DSM/PBT/SESS_INCLUDE", 6, 10) {
                for _ in 0..MAX_SESSIONS_PER_VAULT {
                    let sid = SessionId::new(rng.next_uuid("DSM/PBT/SESS_ID"));
                    let created_at = rng.next_range_u64("DSM/PBT/SESS_CREATED", 0, version);
                    let expires_after = rng.next_range_u64("DSM/PBT/SESS_TTL", 1, 10_000);

                    let mut expires_at = created_at.saturating_add(expires_after);
                    // If active, force non-expired (logical time)
                    let mut active = rng.next_bool("DSM/PBT/SESS_ACTIVE", 8, 10);
                    if active && expires_at < version {
                        expires_at = version;
                    }
                    // If created_at is after expires_at (overflow safety), pin.
                    if expires_at < created_at {
                        expires_at = created_at;
                        active = false;
                    }

                    sessions.insert(
                        sid.clone(),
                        SessionState {
                            id: sid,
                            vault_id: vid.clone(),
                            created_at,
                            expires_at,
                            active,
                        },
                    );
                }
            }
        }

        SystemState {
            version,
            vaults,
            transactions: transactions.clone(),
            sessions,
            network_state: NetworkState {
                connected_nodes: (rng.next_range_u64("DSM/PBT/NODES", 1, 100) as usize).max(1),
                total_transactions: transactions.len() as u64,
                network_hash_rate: rng.next_range_u64("DSM/PBT/NHR", 1, 10_000),
            },
            initial_total_balance,
        }
    }

    /// Seed strategy (drives the deterministic builder).
    pub fn seed32() -> impl Strategy<Value = [u8; 32]> {
        any::<[u8; 32]>()
    }

    /// Strategy for generating valid vault IDs (deterministic bytes; not UUID v4 randomness)
    pub fn vault_id() -> impl Strategy<Value = VaultId> {
        any::<[u8; 16]>().prop_map(|bytes| VaultId::new(uuid::Uuid::from_bytes(bytes)))
    }

    /// Strategy for generating valid transaction IDs
    pub fn transaction_id() -> impl Strategy<Value = TransactionId> {
        any::<[u8; 16]>().prop_map(|bytes| TransactionId::new(uuid::Uuid::from_bytes(bytes)))
    }

    /// Strategy for generating valid session IDs
    pub fn session_id() -> impl Strategy<Value = SessionId> {
        any::<[u8; 16]>().prop_map(|bytes| SessionId::new(uuid::Uuid::from_bytes(bytes)))
    }

    /// Strategy for generating valid amounts
    pub fn amount() -> impl Strategy<Value = u64> {
        1u64..=10_000u64
    }

    /// Strategy for generating vault states (standalone; may be incoherent outside builder usage)
    pub fn vault_state() -> impl Strategy<Value = VaultState> {
        (vault_id(), 1u64..=5_000_000u64, 0u64..=1_000_000u64).prop_map(
            |(id, balance, last_activity)| VaultState {
                id,
                balance,
                transactions: Vec::new(),
                last_activity,
            },
        )
    }

    /// Strategy for generating transaction states (standalone; may be incoherent outside builder usage)
    pub fn transaction_state() -> impl Strategy<Value = TransactionState> {
        (transaction_id(), vault_id(), vault_id(), amount()).prop_map(
            |(id, sender, receiver, amount)| TransactionState {
                id,
                sender,
                receiver,
                amount,
                status: TransactionStatus::Pending,
            },
        )
    }

    /// Strategy for generating session states (standalone; may be incoherent outside builder usage)
    pub fn session_state() -> impl Strategy<Value = SessionState> {
        (session_id(), vault_id(), 0u64..=1_000_000u64, any::<bool>()).prop_map(
            |(id, vault_id, created_at, active)| SessionState {
                id,
                vault_id,
                created_at,
                expires_at: created_at.saturating_add(3600),
                active,
            },
        )
    }

    /// Strategy for generating coherent system states (invariants expected to hold).
    pub fn system_state() -> impl Strategy<Value = SystemState> {
        seed32().prop_map(build_system_state_from_seed)
    }
}

#[cfg(test)]
/// Property-based test runner
pub struct PropertyTestRunner {
    config: PropertyTestConfig,
}

#[cfg(test)]
impl PropertyTestRunner {
    pub fn new(config: PropertyTestConfig) -> Self {
        Self { config }
    }

    /// Run property-based tests for invariants
    pub async fn run_invariant_tests(&self) -> DsmResult<TestResults> {
        let mut results = TestResults::new();

        results.add_test(
            "balance_conservation",
            self.run_invariant::<BalanceConservationInvariant>("balance_conservation")
                .await?,
        );

        results.add_test(
            "transaction_integrity",
            self.run_invariant::<TransactionIntegrityInvariant>("transaction_integrity")
                .await?,
        );

        results.add_test(
            "session_validity",
            self.run_invariant::<SessionValidityInvariant>("session_validity")
                .await?,
        );

        tracing::info!(
            operation = "Property-based testing completed",
            tests_run = %results.tests.len()
        );

        Ok(results)
    }

    async fn run_invariant<I: Invariant + Default + 'static>(
        &self,
        _name: &str,
    ) -> DsmResult<TestResult> {
        use proptest::test_runner::{Config, TestCaseError, TestRunner};

        let cfg = Config {
            cases: self.config.cases,
            ..Default::default()
        };

        let mut runner = TestRunner::new(cfg);
        let invariant = I::default();

        let strat = strategies::system_state();

        let res = runner.run(&strat, |state| {
            let r = futures::executor::block_on(invariant.check(&state))
                .map_err(|e| TestCaseError::fail(format!("Invariant check errored: {e}")))?;

            if r.passed {
                Ok(())
            } else {
                let msg = r
                    .details
                    .unwrap_or_else(|| "Invariant returned passed=false".to_string());
                Err(TestCaseError::fail(msg))
            }
        });

        match res {
            Ok(_) => Ok(TestResult::Passed),
            Err(e) => Ok(TestResult::Failed(e.to_string())),
        }
    }
}

#[cfg(test)]
/// Test result types
#[derive(Debug, Clone)]
pub enum TestResult {
    Passed,
    Failed(String),
    Skipped(String),
}

#[cfg(test)]
#[derive(Debug, Clone)]
pub struct TestResults {
    pub tests: HashMap<String, TestResult>,
}

#[cfg(test)]
impl Default for TestResults {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl TestResults {
    pub fn new() -> Self {
        Self {
            tests: HashMap::new(),
        }
    }

    pub fn add_test(&mut self, name: &str, result: TestResult) {
        self.tests.insert(name.to_string(), result);
    }

    pub fn passed(&self) -> usize {
        self.tests
            .values()
            .filter(|r| matches!(r, TestResult::Passed))
            .count()
    }

    pub fn failed(&self) -> usize {
        self.tests
            .values()
            .filter(|r| matches!(r, TestResult::Failed(_)))
            .count()
    }

    pub fn total(&self) -> usize {
        self.tests.len()
    }
}

/// Formal verification utilities
pub mod formal {
    use super::*;

    /// Model checker for TLA+ specifications
    pub struct TlaModelChecker {
        _spec_path: std::path::PathBuf,
    }

    impl TlaModelChecker {
        pub fn new(_spec_path: std::path::PathBuf) -> Self {
            Self { _spec_path }
        }

        /// Run model checking
        ///
        /// Production rule: never return a success placeholder. If there's no linked backend,
        /// fail explicitly and deterministically.
        #[allow(clippy::unused_async)]
        pub async fn check_model(&self) -> DsmResult<ModelCheckResult> {
            Err(UnifiedDsmError::Configuration {
                context: "formal model checking backend not linked".to_string(),
                component: Some("verification::formal".to_string()),
                source: None,
                recoverable: false,
            })
        }
    }

    #[derive(Debug, Clone)]
    pub struct ModelCheckResult {
        pub passed: bool,
        pub states_explored: u64,
        pub depth_reached: u64,
        pub errors: Vec<String>,
    }
}

impl Default for BalanceConservationInvariant {
    fn default() -> Self {
        Self
    }
}
impl Default for TransactionIntegrityInvariant {
    fn default() -> Self {
        Self
    }
}
impl Default for SessionValidityInvariant {
    fn default() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strategies::*;

    #[tokio::test]
    #[allow(clippy::unused_async)]
    async fn test_invariant_checker() {
        let checker = InvariantChecker::new()
            .add_invariant(BalanceConservationInvariant)
            .add_invariant(TransactionIntegrityInvariant)
            .add_invariant(SessionValidityInvariant);

        let state = SystemState {
            version: 1,
            vaults: HashMap::new(),
            transactions: Vec::new(),
            sessions: HashMap::new(),
            network_state: NetworkState {
                connected_nodes: 1,
                total_transactions: 0,
                network_hash_rate: 1000,
            },
            initial_total_balance: 0,
        };

        let results = checker.check_all(&state).await.unwrap();
        assert_eq!(results.len(), 3);

        for result in results {
            assert!(result.passed, "Invariant failed: {}", result.description);
        }
    }

    proptest! {
        #[test]
        fn test_balance_conservation_property(state in system_state()) {
            let invariant = BalanceConservationInvariant;
            let result = futures::executor::block_on(invariant.check(&state)).unwrap();
            prop_assert!(result.passed, "{}", result.details.unwrap_or_else(|| "failed".to_string()));
        }

        #[test]
        fn test_transaction_integrity_property(state in system_state()) {
            let invariant = TransactionIntegrityInvariant;
            let result = futures::executor::block_on(invariant.check(&state)).unwrap();
            prop_assert!(result.passed, "{}", result.details.unwrap_or_else(|| "failed".to_string()));
        }

        #[test]
        fn test_session_validity_property(state in system_state()) {
            let invariant = SessionValidityInvariant;
            let result = futures::executor::block_on(invariant.check(&state)).unwrap();
            prop_assert!(result.passed, "{}", result.details.unwrap_or_else(|| "failed".to_string()));
        }
    }

    #[tokio::test]
    #[allow(clippy::unused_async)]
    async fn test_property_test_runner() {
        let config = PropertyTestConfig {
            cases: if cfg!(debug_assertions) { 3 } else { 10 },
            max_size: 100,
            shrink: true,
            timeout_seconds: 30,
            verbose: false,
        };

        let runner = PropertyTestRunner::new(config);
        let results = runner.run_invariant_tests().await.unwrap();

        assert_eq!(results.total(), 3);
        assert!(
            results.failed() == 0,
            "Some invariant property tests failed: {:?}",
            results.tests
        );
    }

    #[test]
    fn test_valid_system_state_builder_is_deterministic() {
        let s1 = valid_system_state();
        let s2 = valid_system_state();
        assert_eq!(s1.version, s2.version);
        assert_eq!(s1.vaults.len(), s2.vaults.len());
        assert_eq!(s1.transactions.len(), s2.transactions.len());
        assert_eq!(s1.sessions.len(), s2.sessions.len());
    }
}
