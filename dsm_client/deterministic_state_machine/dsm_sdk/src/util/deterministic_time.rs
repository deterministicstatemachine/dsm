// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deterministic logical tick provider — clockless time substitute.
//!
//! This provides a simple atomic logical counter for ordering and deterministic
//! ticks in clockless builds. Use `tick()` to advance the logical clock and
//! `peek()` to inspect without advancing. The `reset()` helper is only available
//! in test builds or when the `testutils` feature is enabled.

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
    use serial_test::serial;

    // These tests read/reset the process-global PROGRESS_CONTEXT. Without
    // serialization they race other tests in this binary (e.g. SDK-init paths
    // that call update_progress_context): one test's reset()/init() holds the
    // write lock while another's tick() does a `try_read()`, which falls back
    // to 0 on contention — making assertions like reset_is_idempotent flaky.
    // `#[serial]` runs them in the global serial group, eliminating the race.
    #[test]
    #[serial]
    fn tick_returns_value() {
        reset();
        let _t = tick();
    }

    #[test]
    #[serial]
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
    #[serial]
    fn clean_tick_index_matches_tick() {
        reset();
        let a = tick();
        let b = clean_tick_index();
        assert_eq!(a, b, "clean_tick_index() should match tick()");
    }

    #[test]
    #[serial]
    fn peek_returns_value() {
        reset();
        let _p = peek();
    }

    #[test]
    #[serial]
    fn reset_is_idempotent() {
        reset();
        let a = tick();
        reset();
        let b = tick();
        assert_eq!(a, b, "reset should restore to the same initial state");
    }
}
