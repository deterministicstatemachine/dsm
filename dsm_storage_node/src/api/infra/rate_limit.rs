// SPDX-License-Identifier: Apache-2.0
//! Clockless storage API admission shim.
//!
//! Storage protocol endpoints decide acceptance from deterministic protobuf,
//! identity, and PaidK/credit gates. This middleware intentionally performs no
//! wall-clock token-bucket checks.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;

#[derive(Clone, Default)]
pub struct RateLimiter;

impl RateLimiter {
    pub fn new() -> Self {
        Self
    }

    pub fn new_bypass() -> Self {
        Self
    }

    pub async fn check_rate_limit(&self, _key: &str) -> Result<(), StatusCode> {
        Ok(())
    }
}

pub async fn rate_limit_by_ip(
    State(limiter): State<Arc<RateLimiter>>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    limiter.check_rate_limit("clockless").await?;
    Ok(next.run(req).await)
}

pub async fn rate_limit_noop(req: Request, next: Next) -> Response {
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_is_clockless_pass_through() {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(err) => panic!("failed to build Tokio runtime: {err}"),
        };

        runtime.block_on(async {
            let limiter = RateLimiter::new();
            for _ in 0..1_000 {
                if let Err(err) = limiter.check_rate_limit("any").await {
                    panic!("rate limiter unexpectedly rejected request: {err:?}");
                }
            }
        });
    }

    #[test]
    fn bypass_constructor_is_equivalent() {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(err) => panic!("failed to build Tokio runtime: {err}"),
        };

        runtime.block_on(async {
            let limiter = RateLimiter::new_bypass();
            if let Err(err) = limiter.check_rate_limit("any").await {
                panic!("bypass limiter unexpectedly rejected request: {err:?}");
            }
        });
    }
}
