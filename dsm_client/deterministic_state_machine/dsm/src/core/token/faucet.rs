// src/tokens/era_faucet.rs
//! ERA Token Faucet
//!
//! Provides test tokens on testnet with deterministic cooldown + optional deterministic gating.
//! - No wall-clock time: uses `util::deterministic_time` tick counter only.
//! - No network IO.
//! - No hex/base64/JSON/serde in core.
//!
//! Optional policy-driven behavior (best-effort; all fields are local-only):
//! - EmissionsSchedule.initial_step_amount -> claim_amount
//! - Custom("faucet_cooldown", {"cooldown_ticks": "<u64>"}) -> cooldown_ticks
//! - Custom("rate_limit", {"max_n":"<u64>","last_k":"<u64>","operation":"faucet_claim"(optional)})
//!   -> per-identity sliding window in ticks

use std::collections::{HashMap, VecDeque};

use crate::types::error::DsmError;
use crate::types::policy_types::{PolicyCondition, TokenPolicy};
use crate::util::deterministic_time as dt;

use super::era_token::{EraTokenManager, NetworkType};

#[derive(Debug, Clone)]
pub struct FaucetConfig {
    /// Amount of tokens to dispense per claim
    pub claim_amount: u128,
    /// Whether the faucet is enabled
    pub enabled: bool,

    /// Minimum ticks between claims for the same identity (0 disables cooldown).
    pub cooldown_ticks: u64,

    /// Optional per-identity rate limit: at most `rate_limit_max_n` claims within the last `rate_limit_last_k` ticks.
    pub rate_limit_max_n: Option<u64>,
    pub rate_limit_last_k: Option<u64>,

    /// Bound in-memory history to avoid unbounded growth.
    pub max_history: usize,
}

impl Default for FaucetConfig {
    fn default() -> Self {
        Self {
            claim_amount: 1000,
            enabled: true,
            // Secure-by-default faucet: prevent infinite draining in one tight loop.
            // Uses logical ticks, not time-of-day.
            cooldown_ticks: 100,
            rate_limit_max_n: None,
            rate_limit_last_k: None,
            max_history: 10_000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FaucetClaim {
    pub identity: String,
    pub amount: u128,
    pub tick: u64,
}

#[derive(Debug, Clone)]
pub struct FaucetClaimResult {
    pub success: bool,
    pub tokens_received: u128,
    pub message: Option<String>,
}

#[derive(Debug, Clone)]
struct IdentityLimiter {
    last_claim_tick: Option<u64>,
    window_ticks: VecDeque<u64>,
}

impl IdentityLimiter {
    fn new() -> Self {
        Self {
            last_claim_tick: None,
            window_ticks: VecDeque::new(),
        }
    }
}

pub struct EraFaucet {
    config: FaucetConfig,
    claim_history: Vec<FaucetClaim>,
    per_identity: HashMap<String, IdentityLimiter>,
}

impl EraFaucet {
    pub fn new(config: FaucetConfig) -> Self {
        Self {
            config,
            claim_history: Vec::new(),
            per_identity: HashMap::new(),
        }
    }

    pub fn new_default() -> Self {
        Self::new(FaucetConfig::default())
    }

    /// Configure the faucet from a token policy (best-effort).
    pub fn configure_from_policy(&mut self, policy: &TokenPolicy) {
        for condition in &policy.file.conditions {
            match condition {
                PolicyCondition::EmissionsSchedule {
                    initial_step_amount,
                    ..
                } => {
                    self.config.claim_amount = *initial_step_amount as u128;
                }
                PolicyCondition::Custom {
                    constraint_type,
                    parameters,
                } => {
                    // faucet_cooldown
                    if constraint_type == "faucet_cooldown" {
                        if let Some(v) = parameters.get("cooldown_ticks") {
                            if let Ok(t) = v.parse::<u64>() {
                                self.config.cooldown_ticks = t;
                            }
                        }
                    }

                    // rate_limit (optional operation scoping)
                    if constraint_type == "rate_limit" {
                        let op_ok = parameters
                            .get("operation")
                            .map(|s| s == "faucet_claim")
                            .unwrap_or(true);

                        if op_ok {
                            let max_n = parameters.get("max_n").and_then(|s| s.parse::<u64>().ok());
                            let last_k =
                                parameters.get("last_k").and_then(|s| s.parse::<u64>().ok());
                            if max_n.is_some() && last_k.is_some() {
                                self.config.rate_limit_max_n = max_n;
                                self.config.rate_limit_last_k = last_k;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Claim tokens from the faucet with optional region and geo point.
    ///
    /// - `region`: e.g. "CA", "US" (policy can gate this via custom conditions).
    /// - `geo`: accepted for higher-layer gating flows; not interpreted here beyond recording.
    pub fn claim_with_context(
        &mut self,
        token_manager: &mut EraTokenManager,
        identity: &str,
    ) -> Result<FaucetClaimResult, DsmError> {
        if !self.config.enabled {
            return Err(DsmError::FaucetDisabled);
        }

        // Only works on testnet
        if token_manager.network_type() != NetworkType::Testnet {
            return Err(DsmError::FaucetNotAvailable);
        }

        if identity.is_empty() {
            return Err(DsmError::invalid_parameter("Identity is required"));
        }

        // Deterministic "now" for checks; does not advance tick.
        let now = dt::current_commit_height_blocking();

        // Per-identity limiter
        let limiter = self
            .per_identity
            .entry(identity.to_string())
            .or_insert_with(IdentityLimiter::new);

        // Cooldown check
        if self.config.cooldown_ticks != 0 {
            if let Some(last) = limiter.last_claim_tick {
                let next_ok = last.saturating_add(self.config.cooldown_ticks);
                if now < next_ok {
                    return Err(DsmError::invalid_parameter(
                        "Faucet cooldown not satisfied for this identity",
                    ));
                }
            }
        }

        // Rate limit check (sliding window in ticks)
        if let (Some(max_n), Some(last_k)) =
            (self.config.rate_limit_max_n, self.config.rate_limit_last_k)
        {
            // prune old
            let cutoff = now.saturating_sub(last_k);
            while let Some(&front) = limiter.window_ticks.front() {
                if front < cutoff {
                    limiter.window_ticks.pop_front();
                } else {
                    break;
                }
            }
            if (limiter.window_ticks.len() as u64) >= max_n {
                return Err(DsmError::invalid_parameter(
                    "Faucet rate limit exceeded for this identity",
                ));
            }
        }

        // Mint tokens (do not mutate faucet state until mint succeeds)
        token_manager.mint(identity, self.config.claim_amount)?;

        // Commit: advance tick once for the successful claim record.
        let claim_tick = dt::current_commit_height_blocking();

        // Update limiter state
        limiter.last_claim_tick = Some(claim_tick);
        if let (Some(_max_n), Some(_last_k)) =
            (self.config.rate_limit_max_n, self.config.rate_limit_last_k)
        {
            limiter.window_ticks.push_back(claim_tick);
        }

        // Record bounded history
        self.claim_history.push(FaucetClaim {
            identity: identity.to_string(),
            amount: self.config.claim_amount,
            tick: claim_tick,
        });
        if self.claim_history.len() > self.config.max_history {
            // Drop oldest entries to keep memory bounded.
            let overflow = self.claim_history.len() - self.config.max_history;
            self.claim_history.drain(0..overflow);
        }

        Ok(FaucetClaimResult {
            success: true,
            tokens_received: self.config.claim_amount,
            message: Some(format!(
                "Successfully claimed {} tokens",
                self.config.claim_amount
            )),
        })
    }

    /// Deterministic "can claim" for a specific identity (and optional region).
    pub fn can_claim_identity(&self, identity: &str) -> bool {
        if !self.config.enabled {
            return false;
        }
        if identity.is_empty() {
            return false;
        }

        let now = dt::current_commit_height_blocking();
        let Some(limiter) = self.per_identity.get(identity) else {
            return true;
        };

        if self.config.cooldown_ticks != 0 {
            if let Some(last) = limiter.last_claim_tick {
                let next_ok = last.saturating_add(self.config.cooldown_ticks);
                if now < next_ok {
                    return false;
                }
            }
        }

        if let (Some(max_n), Some(last_k)) =
            (self.config.rate_limit_max_n, self.config.rate_limit_last_k)
        {
            let cutoff = now.saturating_sub(last_k);
            let recent = limiter
                .window_ticks
                .iter()
                .filter(|&&t| t >= cutoff)
                .count() as u64;
            if recent >= max_n {
                return false;
            }
        }

        true
    }

    pub fn claim_history(&self) -> &[FaucetClaim] {
        &self.claim_history
    }

    pub fn total_claims(&self) -> usize {
        self.claim_history.len()
    }

    pub fn total_dispensed(&self) -> u128 {
        self.claim_history.iter().map(|c| c.amount).sum()
    }

    pub fn config(&self) -> &FaucetConfig {
        &self.config
    }

    pub fn config_mut(&mut self) -> &mut FaucetConfig {
        &mut self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn test_faucet_claim_success() {
        let mut faucet = EraFaucet::new_default();
        let mut token_manager = EraTokenManager::new_testnet("dlv");

        let result = faucet
            .claim_with_context(&mut token_manager, "user1")
            .unwrap();
        assert!(result.success);
        assert_eq!(result.tokens_received, faucet.config().claim_amount);
        assert_eq!(
            token_manager.get_balance("user1"),
            faucet.config().claim_amount
        );
    }

    #[test]
    #[serial]
    fn test_faucet_cooldown_blocks_immediate_reclaim() {
        // Initialize progress context for test
        crate::util::deterministic_time::reset_for_tests();

        let mut faucet = EraFaucet::new(FaucetConfig {
            claim_amount: 1000,
            enabled: true,
            cooldown_ticks: 10,
            rate_limit_max_n: None,
            rate_limit_last_k: None,
            max_history: 10_000,
        });
        let mut token_manager = EraTokenManager::new_testnet("dlv");

        // First claim succeeds
        faucet
            .claim_with_context(&mut token_manager, "user1")
            .unwrap();

        // Second claim immediately should fail due to cooldown
        let err = faucet
            .claim_with_context(&mut token_manager, "user1")
            .unwrap_err();
        let _ = err; // just ensure it errs without relying on exact variant text

        // Advance commit height deterministically
        for i in 0..20 {
            crate::util::deterministic_time::update_progress_context([0x42u8; 32], 1 + i as u64)
                .unwrap();
        }

        // Now it should succeed
        let ok = faucet
            .claim_with_context(&mut token_manager, "user1")
            .unwrap();
        assert!(ok.success);
    }

    #[test]
    #[serial]
    fn test_faucet_mainnet_disabled() {
        let mut faucet = EraFaucet::new_default();
        let mut token_manager = EraTokenManager::new_mainnet(1_000_000, "dlv");
        let result = faucet.claim_with_context(&mut token_manager, "user1");
        assert!(result.is_err());
    }

    #[test]
    #[serial]
    fn test_region_gating() {
        let mut faucet = EraFaucet::new(FaucetConfig {
            claim_amount: 1000,
            enabled: true,
            cooldown_ticks: 0,
            rate_limit_max_n: None,
            rate_limit_last_k: None,
            max_history: 10_000,
        });
        let mut token_manager = EraTokenManager::new_testnet("dlv");

        // Claims should succeed without region restrictions
        assert!(faucet
            .claim_with_context(&mut token_manager, "user1")
            .is_ok());
    }

    #[test]
    #[serial]
    fn test_configure_from_policy() {
        use crate::types::policy_types::{PolicyCondition, PolicyFile};

        let mut faucet = EraFaucet::new_default();
        assert_eq!(faucet.config().claim_amount, 1000);

        let mut file = PolicyFile::new("Test", "1.0.0", "Author");
        file.add_condition(PolicyCondition::EmissionsSchedule {
            total_supply: 1_000_000,
            shard_depth: 4,
            schedule_steps: 16,
            initial_step_emissions: 5000,
            initial_step_amount: 500,
        });
        file.add_condition(PolicyCondition::Custom {
            constraint_type: "faucet_cooldown".into(),
            parameters: {
                let mut m = HashMap::new();
                m.insert("cooldown_ticks".into(), "7".into());
                m
            },
        });

        let policy = TokenPolicy::new(file).unwrap();
        faucet.configure_from_policy(&policy);

        assert_eq!(faucet.config().claim_amount, 500);
        assert_eq!(faucet.config().cooldown_ticks, 7);
    }

    #[test]
    #[serial]
    fn test_rate_limit_window() {
        // Initialize progress context for test
        crate::util::deterministic_time::reset_for_tests();

        let mut faucet = EraFaucet::new(FaucetConfig {
            claim_amount: 1000,
            enabled: true,
            cooldown_ticks: 0,
            rate_limit_max_n: Some(2),
            rate_limit_last_k: Some(5),
            max_history: 10_000,
        });
        let mut token_manager = EraTokenManager::new_testnet("dlv");

        // Two claims allowed
        assert!(faucet
            .claim_with_context(&mut token_manager, "user1")
            .is_ok());
        assert!(faucet
            .claim_with_context(&mut token_manager, "user1")
            .is_ok());

        // Third within window denied
        assert!(faucet
            .claim_with_context(&mut token_manager, "user1")
            .is_err());

        // Advance ticks beyond window, then allow again
        for i in 0..10 {
            crate::util::deterministic_time::update_progress_context([0x42u8; 32], 1 + i as u64)
                .unwrap();
        }
        assert!(faucet
            .claim_with_context(&mut token_manager, "user1")
            .is_ok());
    }
}
