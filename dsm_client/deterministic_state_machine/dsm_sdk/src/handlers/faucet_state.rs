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
