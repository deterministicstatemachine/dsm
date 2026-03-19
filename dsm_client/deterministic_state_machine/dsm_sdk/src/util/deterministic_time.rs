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
//! This module delegates to `dsm::util::deterministic_time` so iOS/Android/host
//! builds share the same tick behavior.

#[inline]
pub fn tick() -> u64 {
    dsm::util::deterministic_time::current_commit_height_blocking()
}

#[inline]
pub fn tick_index() -> u64 {
    dsm::util::deterministic_time::current_commit_height_blocking()
}

#[inline]
pub fn clean_tick_index() -> u64 {
    dsm::util::deterministic_time::current_commit_height_blocking()
}

#[inline]
pub fn peek() -> u64 {
    dsm::util::deterministic_time::current_commit_height_blocking()
}

#[cfg(test)]
#[inline]
pub fn reset() {
    dsm::util::deterministic_time::reset_for_tests();
}
