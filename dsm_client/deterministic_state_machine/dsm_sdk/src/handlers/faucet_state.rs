// SPDX-License-Identifier: MIT OR Apache-2.0
//! Faucet state machine for testnet ERA token distribution.
//!
//! Provides per-identity cooldown and rate-limit enforcement for faucet claims.
//! The state is held in-memory by the `AppRouterImpl` behind an async `Mutex`.

use std::collections::{HashMap, VecDeque};
use dsm::types::policy_types::{PolicyCondition, PolicyFile};

#[derive(Debug, Clone)]
pub(crate) struct FaucetLimiter {
    last_claim_tick: Option<u64>,
    window_ticks: VecDeque<u64>,
}

impl FaucetLimiter {
    fn new() -> Self {
        Self {
            last_claim_tick: None,
            window_ticks: VecDeque::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FaucetConfig {
    pub claim_amount: u64,
    pub cooldown_ticks: u64,
    pub rate_limit_max_n: Option<u64>,
    pub rate_limit_last_k: Option<u64>,
    pub max_history: usize,
}

impl Default for FaucetConfig {
    fn default() -> Self {
        Self {
            claim_amount: 100,
            cooldown_ticks: 0,
            rate_limit_max_n: None,
            rate_limit_last_k: None,
            max_history: 10_000,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FaucetState {
    pub config: FaucetConfig,
    per_identity: HashMap<String, FaucetLimiter>,
    claim_history: Vec<(String, u64)>,
}

impl FaucetState {
    pub fn new_with_policy(policy: PolicyFile) -> Self {
        let mut state = Self {
            config: FaucetConfig::default(),
            per_identity: HashMap::new(),
            claim_history: Vec::new(),
        };

        for condition in &policy.conditions {
            match condition {
                PolicyCondition::EmissionsSchedule {
                    initial_step_amount,
                    ..
                } => {
                    state.config.claim_amount = (*initial_step_amount).max(1);
                }
                PolicyCondition::Custom {
                    constraint_type,
                    parameters,
                } => {
                    if constraint_type == "faucet_cooldown" {
                        if let Some(v) = parameters.get("cooldown_ticks") {
                            if let Ok(t) = v.parse::<u64>() {
                                state.config.cooldown_ticks = t;
                            }
                        }
                    }

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
                                state.config.rate_limit_max_n = max_n;
                                state.config.rate_limit_last_k = last_k;
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        state
    }

    pub fn claim(&mut self, identity: &str, now: u64) -> Result<(u64, u64), String> {
        if identity.is_empty() {
            return Err("Identity is required".to_string());
        }

        let limiter = self
            .per_identity
            .entry(identity.to_string())
            .or_insert_with(FaucetLimiter::new);

        if self.config.cooldown_ticks != 0 {
            if let Some(last) = limiter.last_claim_tick {
                let next_ok = last.saturating_add(self.config.cooldown_ticks);
                if now < next_ok {
                    return Err("Faucet cooldown not satisfied for this identity".to_string());
                }
            }
        }

        if let (Some(max_n), Some(last_k)) =
            (self.config.rate_limit_max_n, self.config.rate_limit_last_k)
        {
            let cutoff = now.saturating_sub(last_k);
            while let Some(&front) = limiter.window_ticks.front() {
                if front < cutoff {
                    limiter.window_ticks.pop_front();
                } else {
                    break;
                }
            }
            if (limiter.window_ticks.len() as u64) >= max_n {
                return Err("Faucet rate limit exceeded for this identity".to_string());
            }
        }

        limiter.last_claim_tick = Some(now);
        if self.config.rate_limit_max_n.is_some() && self.config.rate_limit_last_k.is_some() {
            limiter.window_ticks.push_back(now);
        }

        self.claim_history.push((identity.to_string(), now));
        if self.claim_history.len() > self.config.max_history {
            let overflow = self.claim_history.len() - self.config.max_history;
            self.claim_history.drain(0..overflow);
        }

        let next_available = if self.config.cooldown_ticks == 0 {
            0
        } else {
            now.saturating_add(self.config.cooldown_ticks)
        };

        Ok((self.config.claim_amount, next_available))
    }
}

pub(crate) fn build_testnet_faucet_policy() -> PolicyFile {
    let mut policy = PolicyFile::new("ERA Testnet Faucet Policy", "1.0.0", "system");
    policy.with_description(
        "Testnet faucet policy with per-identity cooldown (no emissions schedule)",
    );
    policy.add_metadata("network", "testnet");
    policy.add_metadata("mode", "faucet-claim");
    policy.add_condition(PolicyCondition::Custom {
        constraint_type: "faucet_cooldown".into(),
        parameters: {
            let mut m = HashMap::new();
            m.insert("cooldown_ticks".into(), "0".into());
            m
        },
    });
    policy
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_policy() -> PolicyFile {
        PolicyFile::new("test", "1.0", "tester")
    }

    fn cooldown_policy(ticks: u64) -> PolicyFile {
        let mut p = default_policy();
        p.add_condition(PolicyCondition::Custom {
            constraint_type: "faucet_cooldown".into(),
            parameters: {
                let mut m = HashMap::new();
                m.insert("cooldown_ticks".into(), ticks.to_string());
                m
            },
        });
        p
    }

    fn rate_limit_policy(max_n: u64, last_k: u64) -> PolicyFile {
        let mut p = default_policy();
        p.add_condition(PolicyCondition::Custom {
            constraint_type: "rate_limit".into(),
            parameters: {
                let mut m = HashMap::new();
                m.insert("max_n".into(), max_n.to_string());
                m.insert("last_k".into(), last_k.to_string());
                m.insert("operation".into(), "faucet_claim".into());
                m
            },
        });
        p
    }

    // --- FaucetConfig defaults ---

    #[test]
    fn default_config_values() {
        let cfg = FaucetConfig::default();
        assert_eq!(cfg.claim_amount, 100);
        assert_eq!(cfg.cooldown_ticks, 0);
        assert!(cfg.rate_limit_max_n.is_none());
        assert!(cfg.rate_limit_last_k.is_none());
        assert_eq!(cfg.max_history, 10_000);
    }

    // --- FaucetState construction ---

    #[test]
    fn new_with_empty_policy_uses_defaults() {
        let state = FaucetState::new_with_policy(default_policy());
        assert_eq!(state.config.claim_amount, 100);
        assert_eq!(state.config.cooldown_ticks, 0);
    }

    #[test]
    fn new_with_cooldown_policy() {
        let state = FaucetState::new_with_policy(cooldown_policy(10));
        assert_eq!(state.config.cooldown_ticks, 10);
    }

    #[test]
    fn new_with_emissions_schedule_sets_claim_amount() {
        let mut p = default_policy();
        p.add_condition(PolicyCondition::EmissionsSchedule {
            total_supply: 1_000_000,
            shard_depth: 4,
            schedule_steps: 10,
            initial_step_emissions: 100,
            initial_step_amount: 500,
        });
        let state = FaucetState::new_with_policy(p);
        assert_eq!(state.config.claim_amount, 500);
    }

    #[test]
    fn emissions_schedule_clamps_zero_to_one() {
        let mut p = default_policy();
        p.add_condition(PolicyCondition::EmissionsSchedule {
            total_supply: 0,
            shard_depth: 0,
            schedule_steps: 0,
            initial_step_emissions: 0,
            initial_step_amount: 0,
        });
        let state = FaucetState::new_with_policy(p);
        assert_eq!(state.config.claim_amount, 1);
    }

    #[test]
    fn new_with_rate_limit_policy() {
        let state = FaucetState::new_with_policy(rate_limit_policy(5, 100));
        assert_eq!(state.config.rate_limit_max_n, Some(5));
        assert_eq!(state.config.rate_limit_last_k, Some(100));
    }

    // --- claim() basics ---

    #[test]
    fn claim_succeeds_without_cooldown() {
        let mut state = FaucetState::new_with_policy(default_policy());
        let result = state.claim("alice", 1);
        assert!(result.is_ok());
        let (amount, next) = result.unwrap();
        assert_eq!(amount, 100);
        assert_eq!(next, 0); // no cooldown → next_available = 0
    }

    #[test]
    fn claim_empty_identity_rejected() {
        let mut state = FaucetState::new_with_policy(default_policy());
        let result = state.claim("", 1);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Identity is required"));
    }

    // --- Cooldown enforcement ---

    #[test]
    fn cooldown_blocks_early_claim() {
        let mut state = FaucetState::new_with_policy(cooldown_policy(10));
        assert!(state.claim("bob", 0).is_ok());
        let err = state.claim("bob", 5).unwrap_err();
        assert!(err.contains("cooldown"));
    }

    #[test]
    fn cooldown_allows_claim_after_expiry() {
        let mut state = FaucetState::new_with_policy(cooldown_policy(10));
        assert!(state.claim("bob", 0).is_ok());
        assert!(state.claim("bob", 10).is_ok());
    }

    #[test]
    fn cooldown_next_available_returned() {
        let mut state = FaucetState::new_with_policy(cooldown_policy(5));
        let (_, next) = state.claim("eve", 100).unwrap();
        assert_eq!(next, 105);
    }

    #[test]
    fn cooldown_separate_identities_independent() {
        let mut state = FaucetState::new_with_policy(cooldown_policy(100));
        assert!(state.claim("alice", 0).is_ok());
        assert!(state.claim("bob", 1).is_ok()); // different identity, no cooldown conflict
    }

    // --- Rate limit enforcement ---

    #[test]
    fn rate_limit_blocks_excess_claims() {
        let mut state = FaucetState::new_with_policy(rate_limit_policy(2, 100));
        assert!(state.claim("carol", 10).is_ok());
        assert!(state.claim("carol", 20).is_ok());
        let err = state.claim("carol", 30).unwrap_err();
        assert!(err.contains("rate limit"));
    }

    #[test]
    fn rate_limit_allows_after_window_expires() {
        let mut state = FaucetState::new_with_policy(rate_limit_policy(2, 50));
        assert!(state.claim("dan", 10).is_ok());
        assert!(state.claim("dan", 20).is_ok());
        // Window is 50 ticks; at tick 70, tick 10 falls out of window
        assert!(state.claim("dan", 70).is_ok());
    }

    // --- History pruning ---

    #[test]
    fn history_pruned_to_max() {
        let p = default_policy();
        let mut state = FaucetState::new_with_policy(p);
        state.config.max_history = 3;
        for i in 0..5 {
            state.claim(&format!("user{i}"), i).unwrap();
        }
        assert_eq!(state.claim_history.len(), 3);
    }

    // --- build_testnet_faucet_policy ---

    #[test]
    fn testnet_policy_has_faucet_cooldown() {
        let policy = build_testnet_faucet_policy();
        assert_eq!(policy.name, "ERA Testnet Faucet Policy");
        let has_cooldown = policy.conditions.iter().any(|c| {
            matches!(c, PolicyCondition::Custom { constraint_type, .. } if constraint_type == "faucet_cooldown")
        });
        assert!(has_cooldown);
    }

    #[test]
    fn testnet_policy_metadata() {
        let policy = build_testnet_faucet_policy();
        assert_eq!(policy.metadata.get("network").map(|s| s.as_str()), Some("testnet"));
        assert_eq!(policy.metadata.get("mode").map(|s| s.as_str()), Some("faucet-claim"));
    }
}
