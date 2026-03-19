// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bilateral initialization poller with adaptive backoff and telemetry.
//! Gated behind android+bluetooth. Extracted from unified_protobuf_bridge for testability.

#![allow(dead_code)]

use std::sync::atomic::{AtomicUsize, Ordering};

// (No direct runtime usage here; caller supplies async init via closure)

// Telemetry counters
pub static POLL_ATTEMPTS_STARTED: AtomicUsize = AtomicUsize::new(0);
pub static POLL_ATTEMPTS_SUCCESS: AtomicUsize = AtomicUsize::new(0);
pub static POLL_ATTEMPTS_TIMEOUT: AtomicUsize = AtomicUsize::new(0);
pub static POLL_TOTAL_ITERATIONS: AtomicUsize = AtomicUsize::new(0);

// Allows tests / JNI layer to reset telemetry if needed.
pub fn reset_poll_telemetry() {
    POLL_ATTEMPTS_STARTED.store(0, Ordering::SeqCst);
    POLL_ATTEMPTS_SUCCESS.store(0, Ordering::SeqCst);
    POLL_ATTEMPTS_TIMEOUT.store(0, Ordering::SeqCst);
    POLL_TOTAL_ITERATIONS.store(0, Ordering::SeqCst);
}

/// Deterministic backoff expressed in iterations (no wall clocks).
struct BackoffState {
    current_iters: u32,
    max_iters: u32,
}
impl BackoffState {
    fn new(initial_iters: u32, max_iters: u32) -> Self {
        Self {
            current_iters: initial_iters.max(1),
            max_iters: max_iters.max(1),
        }
    }
    fn next(&mut self) -> u32 {
        let iters = self.current_iters;
        if self.current_iters < self.max_iters {
            let doubled = self.current_iters.saturating_mul(2);
            self.current_iters = if doubled > self.max_iters {
                self.max_iters
            } else {
                doubled
            };
        }
        iters
    }
}

/// Poller configuration knobs.
pub struct PollConfig {
    /// Initial idle iterations between readiness checks
    pub initial_idle_iters: u32,
    /// Maximum idle iterations between readiness checks
    pub max_idle_iters: u32,
    /// Base total iteration budget before giving up
    pub base_iteration_budget: u32,
    /// Extra iteration budget to grant when progress is detected
    pub progress_extension_iters: u32,
    /// Maximum cap for total iteration budget
    pub max_total_iteration_budget: u32,
}
impl Default for PollConfig {
    fn default() -> Self {
        Self {
            initial_idle_iters: 1,
            max_idle_iters: 64,
            base_iteration_budget: 2_000,
            progress_extension_iters: 500,
            max_total_iteration_budget: 5_000,
        }
    }
}

/// Run a bilateral initialization poll loop.
/// ready_pred: returns (context_ready, handler_ready).
/// init_fn: async initializer that returns Ok(()) when bilateral readiness should be marked.
/// Returns true if initialized, false if timed out.
pub fn run_bilateral_poll<FReady, FInit>(
    ready_pred: FReady,
    init_fn: FInit,
    cfg: PollConfig,
) -> bool
where
    FReady: Fn() -> (bool, bool),
    FInit: Fn() -> Result<(), dsm::types::error::DsmError>,
{
    POLL_ATTEMPTS_STARTED.fetch_add(1, Ordering::SeqCst);
    let mut backoff = BackoffState::new(cfg.initial_idle_iters, cfg.max_idle_iters);
    let mut total_budget = cfg.base_iteration_budget;
    let mut iterations = 0usize;
    let mut last_progress_phase: Option<&'static str> = None;

    loop {
        let (ctx, handler) = ready_pred();
        iterations += 1;
        POLL_TOTAL_ITERATIONS.fetch_add(1, Ordering::SeqCst);

        if ctx && handler {
            // Preconditions satisfied: perform initialization (sync wrapper around async call).
            match init_fn() {
                Ok(()) => {
                    POLL_ATTEMPTS_SUCCESS.fetch_add(1, Ordering::SeqCst);
                    log::info!("bilateral_poll: success after {} iterations", iterations);
                    return true;
                }
                Err(e) => {
                    log::error!(
                        "bilateral_poll: init_fn failed after preconditions satisfied: {}",
                        e
                    );
                    // Keep polling in case ephemeral failure recovers.
                }
            }
        } else {
            // Progress detection: exactly one of ctx/handler ready.
            let phase = if ctx {
                Some("context-only")
            } else if handler {
                Some("handler-only")
            } else {
                None
            };
            if let Some(p) = phase {
                if last_progress_phase != Some(p) {
                    // Extend iteration budget on first observation of a new progress phase
                    total_budget = total_budget.saturating_add(cfg.progress_extension_iters);
                    if total_budget > cfg.max_total_iteration_budget {
                        total_budget = cfg.max_total_iteration_budget;
                    }
                    last_progress_phase = Some(p);
                    log::debug!("bilateral_poll: progress phase '{}' detected; extending iteration budget to {}", p, total_budget);
                }
            }
        }

        if (iterations as u32) >= total_budget {
            POLL_ATTEMPTS_TIMEOUT.fetch_add(1, Ordering::SeqCst);
            log::warn!("bilateral_poll: timed out after {} iterations", iterations);
            return false;
        }

        // Deterministic idle spinning (no wall clock). Yield to scheduler to avoid starve.
        let idle_iters = backoff.next();
        for _ in 0..idle_iters {
            std::thread::yield_now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn poll_extends_on_progress() {
        reset_poll_telemetry();
        static ITER: AtomicUsize = AtomicUsize::new(0);
        let cfg = PollConfig::default();
        let succeeded = run_bilateral_poll(
            || {
                let i = ITER.fetch_add(1, Ordering::SeqCst);
                // Inject phases: handler-only for first 5 iterations, context-only next 5, then both.
                if i < 5 {
                    (false, true)
                } else if i < 10 {
                    (true, false)
                } else {
                    (true, true)
                }
            },
            || Ok(()),
            cfg,
        );
        assert!(succeeded, "poll should succeed after progress phases");
        assert_eq!(POLL_ATTEMPTS_SUCCESS.load(Ordering::SeqCst), 1);
        assert_eq!(POLL_ATTEMPTS_TIMEOUT.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn poll_times_out_without_progress() {
        reset_poll_telemetry();
        let cfg = PollConfig {
            base_iteration_budget: 50,
            progress_extension_iters: 10,
            max_total_iteration_budget: 70,
            ..PollConfig::default()
        };
        let succeeded = run_bilateral_poll(|| (false, false), || Ok(()), cfg);
        assert!(!succeeded, "poll should time out with no progress");
        assert_eq!(POLL_ATTEMPTS_TIMEOUT.load(Ordering::SeqCst), 1);
    }
}
