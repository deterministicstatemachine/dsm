// SPDX-License-Identifier: Apache-2.0
//! Simple in-memory rate limiter for public endpoints (per-IP)

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use tokio::sync::RwLock;

const RATE_LIMIT_REQUESTS: u32 = 120;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
struct RateLimitEntry {
    tokens: u32,
    last_refill: Instant,
}

impl RateLimitEntry {
    fn new() -> Self {
        Self {
            tokens: RATE_LIMIT_REQUESTS,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let windows_elapsed = elapsed.as_secs() / RATE_LIMIT_WINDOW.as_secs();

        if windows_elapsed > 0 {
            self.tokens = RATE_LIMIT_REQUESTS;
            self.last_refill = now;
        }
    }

    fn consume(&mut self) -> bool {
        self.refill();
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

type RateLimitMap = HashMap<String, RateLimitEntry>;

#[derive(Clone)]
pub struct RateLimiter {
    limits: Arc<RwLock<RateLimitMap>>,
    /// When true, all requests pass through without token consumption.
    /// Used for throughput benchmarking to measure real protocol overhead.
    bypass: bool,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            limits: Arc::new(RwLock::new(HashMap::new())),
            bypass: false,
        }
    }

    /// Create a rate limiter that passes all requests through (benchmark mode).
    pub fn new_bypass() -> Self {
        Self {
            limits: Arc::new(RwLock::new(HashMap::new())),
            bypass: true,
        }
    }

    fn should_prune(entry: &RateLimitEntry, now: Instant) -> bool {
        let elapsed = now.duration_since(entry.last_refill);
        elapsed > RATE_LIMIT_WINDOW.saturating_mul(10)
    }

    pub async fn check_rate_limit(&self, key: &str) -> Result<(), StatusCode> {
        if self.bypass {
            return Ok(());
        }
        let mut limits = self.limits.write().await;
        let now = Instant::now();
        limits.retain(|_, entry| !Self::should_prune(entry, now));
        let entry = limits
            .entry(key.to_string())
            .or_insert_with(RateLimitEntry::new);

        if entry.consume() {
            Ok(())
        } else {
            Err(StatusCode::TOO_MANY_REQUESTS)
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn rate_limit_by_ip(
    State(limiter): State<Arc<RateLimiter>>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let key = req
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    limiter.check_rate_limit(&key).await?;
    Ok(next.run(req).await)
}

/// No-op rate limiter for benchmark mode. Passes all requests through
/// without token-bucket checks, allowing measurement of true protocol
/// throughput (BLAKE3 validation + DB I/O) rather than rate-limiter ceiling.
pub async fn rate_limit_noop(req: Request, next: Next) -> Response {
    next.run(req).await
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_entry_starts_full() {
        let entry = RateLimitEntry::new();
        assert_eq!(entry.tokens, RATE_LIMIT_REQUESTS);
    }

    #[test]
    fn rate_limit_entry_consume_decrements() {
        let mut entry = RateLimitEntry::new();
        let initial = entry.tokens;
        assert!(entry.consume());
        assert_eq!(entry.tokens, initial - 1);
    }

    #[test]
    fn rate_limit_entry_consume_exhausts_tokens() {
        let mut entry = RateLimitEntry::new();
        for _ in 0..RATE_LIMIT_REQUESTS {
            assert!(entry.consume());
        }
        assert!(!entry.consume());
        assert_eq!(entry.tokens, 0);
    }

    #[test]
    fn rate_limit_entry_refill_within_window_no_change() {
        let mut entry = RateLimitEntry::new();
        for _ in 0..10 {
            entry.consume();
        }
        let remaining = entry.tokens;
        entry.refill(); // Still within the same window
        assert_eq!(entry.tokens, remaining);
    }

    #[test]
    fn should_prune_recent_entry_false() {
        let entry = RateLimitEntry::new();
        assert!(!RateLimiter::should_prune(&entry, Instant::now()));
    }

    #[test]
    fn should_prune_old_entry_true() {
        let mut entry = RateLimitEntry::new();
        // Simulate an entry from long ago by backdating last_refill
        entry.last_refill = Instant::now() - RATE_LIMIT_WINDOW.saturating_mul(11);
        assert!(RateLimiter::should_prune(&entry, Instant::now()));
    }

    #[test]
    fn should_prune_boundary_false() {
        let mut entry = RateLimitEntry::new();
        let now = Instant::now();
        // Exactly 10x window — should NOT be pruned (> required, not >=)
        entry.last_refill = now - RATE_LIMIT_WINDOW.saturating_mul(10);
        assert!(!RateLimiter::should_prune(&entry, now));
    }

    #[tokio::test]
    async fn check_rate_limit_allows_requests() {
        let limiter = RateLimiter::new();
        assert!(limiter.check_rate_limit("192.168.1.1").await.is_ok());
    }

    #[tokio::test]
    async fn check_rate_limit_exhaustion_returns_429() {
        let limiter = RateLimiter::new();
        for _ in 0..RATE_LIMIT_REQUESTS {
            assert!(limiter.check_rate_limit("192.168.1.1").await.is_ok());
        }
        let result = limiter.check_rate_limit("192.168.1.1").await;
        assert_eq!(result, Err(StatusCode::TOO_MANY_REQUESTS));
    }

    #[tokio::test]
    async fn check_rate_limit_per_key_isolation() {
        let limiter = RateLimiter::new();
        for _ in 0..RATE_LIMIT_REQUESTS {
            assert!(limiter.check_rate_limit("192.168.1.1").await.is_ok());
        }
        // Different key should still have tokens
        assert!(limiter.check_rate_limit("10.0.0.1").await.is_ok());
    }

    #[tokio::test]
    async fn check_rate_limit_bypass_always_ok() {
        let limiter = RateLimiter::new_bypass();
        for _ in 0..(RATE_LIMIT_REQUESTS + 100) {
            assert!(limiter.check_rate_limit("192.168.1.1").await.is_ok());
        }
    }

    #[test]
    fn default_creates_non_bypass_limiter() {
        let limiter = RateLimiter::default();
        assert!(!limiter.bypass);
    }

    #[test]
    fn new_bypass_sets_bypass_flag() {
        let limiter = RateLimiter::new_bypass();
        assert!(limiter.bypass);
    }
}
