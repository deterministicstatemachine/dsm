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
