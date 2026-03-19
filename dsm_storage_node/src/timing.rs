// SPDX-License-Identifier: Apache-2.0
//! Timing Strategy Abstraction for DSM Storage Node
//! Implements clockless timing logic to decouple database layer from timing implementation.
//! Addresses the critique recommendation to abstract raw i64 timing values.

/// Timing strategy trait that hides implementation details from database functions.
/// This allows the database layer to ask timing questions without knowing how time is calculated.
#[async_trait::async_trait]
pub trait TimingStrategy: Send + Sync {
    /// Check if a record is eligible for retry based on current time and last attempt
    async fn is_eligible_for_retry(
        &self,
        now_iter: i64,
        last_attempt_iter: i64,
        attempts: i32,
    ) -> bool;

    /// Calculate the next eligible iteration for retry
    async fn calculate_next_retry_iter(&self, now_iter: i64, attempts: i32) -> i64;

    /// Calculate retry eligible iteration (same as calculate_next_retry_iter for compatibility)
    async fn calculate_retry_eligible_iter(&self, now_iter: i64, attempts: i32) -> i64;

    /// Calculate expiration time for cleanup operations
    async fn calculate_expiration_iter(&self, now_iter: i64, ttl_iters: i64) -> i64;

    /// Check if a record has expired
    async fn is_expired(&self, now_iter: i64, created_iter: i64, ttl_iters: i64) -> bool;
}

/// Default implementation using exponential backoff (clockless)
pub struct ExponentialBackoffTiming {
    base_delay_iters: i64,
    max_delay_iters: i64,
    max_attempts: i32,
}

impl ExponentialBackoffTiming {
    pub fn new(base_delay_iters: i64, max_delay_iters: i64, max_attempts: i32) -> Self {
        Self {
            base_delay_iters,
            max_delay_iters,
            max_attempts,
        }
    }

    /// Calculate exponential backoff delay (replaces bitwise shift logic)
    fn calculate_backoff_delay(&self, attempts: i32) -> i64 {
        if attempts <= 0 {
            return 0;
        }

        let delay =
            self.base_delay_iters * (2_i64.saturating_pow(attempts.saturating_sub(1) as u32));
        std::cmp::min(delay, self.max_delay_iters)
    }
}

impl Default for ExponentialBackoffTiming {
    fn default() -> Self {
        Self::new(1, i64::MAX, 20) // base_delay=1, max_delay=MAX, max_attempts=20
    }
}

#[async_trait::async_trait]
impl TimingStrategy for ExponentialBackoffTiming {
    async fn is_eligible_for_retry(
        &self,
        now_iter: i64,
        last_attempt_iter: i64,
        attempts: i32,
    ) -> bool {
        if attempts >= self.max_attempts {
            return false;
        }

        let next_retry_iter = last_attempt_iter + self.calculate_backoff_delay(attempts);
        now_iter >= next_retry_iter
    }

    async fn calculate_next_retry_iter(&self, now_iter: i64, attempts: i32) -> i64 {
        now_iter + self.calculate_backoff_delay(attempts)
    }

    async fn calculate_retry_eligible_iter(&self, now_iter: i64, attempts: i32) -> i64 {
        self.calculate_next_retry_iter(now_iter, attempts).await
    }

    async fn calculate_expiration_iter(&self, now_iter: i64, ttl_iters: i64) -> i64 {
        now_iter + ttl_iters
    }

    async fn is_expired(&self, now_iter: i64, created_iter: i64, ttl_iters: i64) -> bool {
        now_iter > created_iter + ttl_iters
    }
}

/// No-op timing strategy for testing (immediate eligibility)
pub struct ImmediateTiming;

#[async_trait::async_trait]
impl TimingStrategy for ImmediateTiming {
    async fn is_eligible_for_retry(
        &self,
        _now_iter: i64,
        _last_attempt_iter: i64,
        _attempts: i32,
    ) -> bool {
        true
    }

    async fn calculate_next_retry_iter(&self, now_iter: i64, _attempts: i32) -> i64 {
        now_iter
    }

    async fn calculate_retry_eligible_iter(&self, now_iter: i64, attempts: i32) -> i64 {
        self.calculate_next_retry_iter(now_iter, attempts).await
    }

    async fn calculate_expiration_iter(&self, now_iter: i64, ttl_iters: i64) -> i64 {
        now_iter + ttl_iters
    }

    async fn is_expired(&self, now_iter: i64, created_iter: i64, ttl_iters: i64) -> bool {
        now_iter > created_iter + ttl_iters
    }
}

/// Timing strategy factory
pub struct TimingStrategyFactory;

impl TimingStrategyFactory {
    /// Create production timing strategy with exponential backoff
    pub fn production() -> Box<dyn TimingStrategy> {
        Box::new(ExponentialBackoffTiming::new(
            60,   // 1 minute base delay (in iterations)
            3600, // 1 hour max delay
            10,   // max attempts
        ))
    }

    /// Create test timing strategy (immediate)
    pub fn test() -> Box<dyn TimingStrategy> {
        Box::new(ImmediateTiming)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exponential_backoff_eligibility() {
        let rt = tokio::runtime::Runtime::new()
            .unwrap_or_else(|e| panic!("failed to create runtime: {e}"));
        rt.block_on(async {
            let timing = ExponentialBackoffTiming::new(10, 100, 5);

            // First attempt should be eligible immediately
            assert!(timing.is_eligible_for_retry(100, 90, 0).await);

            // Second attempt should wait for backoff
            assert!(timing.is_eligible_for_retry(100, 90, 1).await); // 90 + 10 = 100, 100 >= 100
            assert!(timing.is_eligible_for_retry(101, 90, 1).await); // 90 + 10 = 100, 101 >= 100

            // Third attempt should wait longer (20 iterations)
            assert!(!timing.is_eligible_for_retry(109, 90, 2).await); // 90 + 20 = 110, 109 < 110
            assert!(timing.is_eligible_for_retry(110, 90, 2).await); // 90 + 20 = 110, 110 >= 110
        });
    }

    #[test]
    fn test_exponential_backoff_calculation() {
        let rt = tokio::runtime::Runtime::new()
            .unwrap_or_else(|e| panic!("failed to create runtime: {e}"));
        rt.block_on(async {
            let timing = ExponentialBackoffTiming::new(10, 100, 5);

            // First retry: 10 iterations
            assert_eq!(timing.calculate_next_retry_iter(100, 1).await, 110);

            // Second retry: 20 iterations
            assert_eq!(timing.calculate_next_retry_iter(100, 2).await, 120);

            // Third retry: 40 iterations
            assert_eq!(timing.calculate_next_retry_iter(100, 3).await, 140);

            // Capped at max delay
            assert_eq!(timing.calculate_next_retry_iter(100, 10).await, 200); // 10 * 2^9 = 5120, capped to 100
        });
    }

    #[test]
    fn test_expiration_logic() {
        let rt = tokio::runtime::Runtime::new()
            .unwrap_or_else(|e| panic!("failed to create runtime: {e}"));
        rt.block_on(async {
            let timing = ExponentialBackoffTiming::new(10, 100, 5);

            // Not expired
            assert!(!timing.is_expired(100, 90, 20).await); // 90 + 20 = 110 > 100

            // Expired
            assert!(timing.is_expired(111, 90, 20).await); // 90 + 20 = 110, 111 > 110
        });
    }

    #[test]
    fn test_immediate_timing() {
        let rt = tokio::runtime::Runtime::new()
            .unwrap_or_else(|e| panic!("failed to create runtime: {e}"));
        rt.block_on(async {
            let timing = ImmediateTiming;

            // Always eligible
            assert!(timing.is_eligible_for_retry(100, 200, 10).await);

            // Immediate next retry
            assert_eq!(timing.calculate_next_retry_iter(100, 5).await, 100);
        });
    }
}
