// path: dsm_client/deterministic_state_machine/dsm/src/utils/time.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deterministic time facade for DSM (tick-based; no std::time in core builds).
//! Public API exposes a tick-based Duration. 1 tick is an abstract logical unit.

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Duration {
    ticks: u64,
}

impl Duration {
    #[inline]
    pub const fn from_ticks(ticks: u64) -> Self {
        Self { ticks }
    }
    #[inline]
    pub const fn zero() -> Self {
        Self { ticks: 0 }
    }

    #[inline]
    pub fn as_ticks(&self) -> u64 {
        self.ticks
    }
    #[inline]
    pub fn as_secs(&self) -> u64 {
        self.ticks
    }
    #[inline]
    pub fn as_millis(&self) -> u128 {
        self.ticks as u128
    }

    #[inline]
    pub fn min(self, other: Self) -> Self {
        if self.ticks <= other.ticks {
            self
        } else {
            other
        }
    }
}

impl core::ops::Add for Duration {
    type Output = Duration;
    #[inline]
    fn add(self, rhs: Duration) -> Duration {
        Duration::from_ticks(self.ticks.saturating_add(rhs.ticks))
    }
}
impl core::ops::AddAssign for Duration {
    #[inline]
    fn add_assign(&mut self, rhs: Duration) {
        self.ticks = self.ticks.saturating_add(rhs.ticks)
    }
}
impl core::ops::Mul<u32> for Duration {
    type Output = Duration;
    #[inline]
    fn mul(self, rhs: u32) -> Duration {
        Duration::from_ticks(self.ticks.saturating_mul(rhs as u64))
    }
}

// Removed unused Duration::into_std to satisfy clippy (no adapters rely on it)

/// Monotonic logical "now" (no wall clock).
#[inline]
pub fn now() -> u64 {
    // Provided by deterministic logical counter.
    let (_hash, tick) = crate::utils::deterministic_time::peek();
    tick
}
