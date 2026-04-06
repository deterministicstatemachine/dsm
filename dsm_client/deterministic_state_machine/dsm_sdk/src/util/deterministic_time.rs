// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deterministic logical tick provider — clockless time substitute.
//!
//! This provides a simple atomic logical counter for ordering and deterministic
//! ticks in clockless builds. Use `tick()` to advance the logical clock and
//! `peek()` to inspect without advancing. The `reset()` helper is only available
//! in test builds or when the `testutils` feature is enabled.

// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deterministic logical tick provider — clockless time substitute.
//!
//! IMPORTANT:
//! - The CORE (`dsm`) owns the canonical deterministic tick chain.
//! - The SDK must mirror core behavior; do not introduce a second counter.
//!
//! This module delegates to `dsm::utils::deterministic_time` so iOS/Android/host
//! builds share the same tick behavior.

#[inline]
pub fn tick() -> u64 {
    dsm::utils::deterministic_time::current_commit_height_blocking()
}

#[inline]
pub fn tick_index() -> u64 {
    dsm::utils::deterministic_time::current_commit_height_blocking()
}

#[inline]
pub fn clean_tick_index() -> u64 {
    dsm::utils::deterministic_time::current_commit_height_blocking()
}

#[inline]
pub fn peek() -> u64 {
    dsm::utils::deterministic_time::current_commit_height_blocking()
}

#[cfg(test)]
#[inline]
pub fn reset() {
    dsm::utils::deterministic_time::reset_for_tests();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tick_returns_value() {
        reset();
        let _t = tick();
    }

    #[test]
    fn tick_index_matches_tick() {
        reset();
        let a = tick();
        let b = tick_index();
        assert_eq!(
            a, b,
            "tick() and tick_index() should delegate to the same source"
        );
    }

    #[test]
    fn clean_tick_index_matches_tick() {
        reset();
        let a = tick();
        let b = clean_tick_index();
        assert_eq!(a, b, "clean_tick_index() should match tick()");
    }

    #[test]
    fn peek_returns_value() {
        reset();
        let _p = peek();
    }

    #[test]
    fn reset_is_idempotent() {
        reset();
        let a = tick();
        reset();
        let b = tick();
        assert_eq!(a, b, "reset should restore to the same initial state");
    }
}
