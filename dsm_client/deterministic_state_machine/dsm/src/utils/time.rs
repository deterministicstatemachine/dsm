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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_duration_from_ticks() {
        let d = Duration::from_ticks(42);
        assert_eq!(d.as_ticks(), 42);
    }

    #[test]
    fn test_duration_zero() {
        let d = Duration::zero();
        assert_eq!(d.as_ticks(), 0);
        assert_eq!(d.as_secs(), 0);
        assert_eq!(d.as_millis(), 0);
    }

    #[test]
    fn test_duration_as_secs_equals_ticks() {
        let d = Duration::from_ticks(100);
        assert_eq!(d.as_secs(), d.as_ticks());
    }

    #[test]
    fn test_duration_as_millis() {
        let d = Duration::from_ticks(55);
        assert_eq!(d.as_millis(), 55u128);
    }

    #[test]
    fn test_duration_add() {
        let a = Duration::from_ticks(10);
        let b = Duration::from_ticks(20);
        let c = a + b;
        assert_eq!(c.as_ticks(), 30);
    }

    #[test]
    fn test_duration_add_saturating() {
        let a = Duration::from_ticks(u64::MAX);
        let b = Duration::from_ticks(1);
        let c = a + b;
        assert_eq!(c.as_ticks(), u64::MAX);
    }

    #[test]
    fn test_duration_add_assign() {
        let mut a = Duration::from_ticks(5);
        a += Duration::from_ticks(3);
        assert_eq!(a.as_ticks(), 8);
    }

    #[test]
    fn test_duration_add_assign_saturating() {
        let mut a = Duration::from_ticks(u64::MAX);
        a += Duration::from_ticks(10);
        assert_eq!(a.as_ticks(), u64::MAX);
    }

    #[test]
    fn test_duration_mul() {
        let d = Duration::from_ticks(7);
        let result = d * 3;
        assert_eq!(result.as_ticks(), 21);
    }

    #[test]
    fn test_duration_mul_saturating() {
        let d = Duration::from_ticks(u64::MAX);
        let result = d * 2;
        assert_eq!(result.as_ticks(), u64::MAX);
    }

    #[test]
    fn test_duration_min() {
        let a = Duration::from_ticks(10);
        let b = Duration::from_ticks(5);
        assert_eq!(a.min(b).as_ticks(), 5);
        assert_eq!(b.min(a).as_ticks(), 5);
    }

    #[test]
    fn test_duration_min_equal() {
        let a = Duration::from_ticks(7);
        let b = Duration::from_ticks(7);
        assert_eq!(a.min(b).as_ticks(), 7);
    }

    #[test]
    fn test_duration_ord() {
        let a = Duration::from_ticks(1);
        let b = Duration::from_ticks(2);
        assert!(a < b);
        assert!(b > a);
        assert_eq!(a, Duration::from_ticks(1));
    }

    #[test]
    fn test_duration_clone_and_copy() {
        let a = Duration::from_ticks(99);
        let b = a;
        let c = a.clone();
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn test_duration_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Duration::from_ticks(1));
        set.insert(Duration::from_ticks(2));
        set.insert(Duration::from_ticks(1));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_now_returns_value() {
        let tick = now();
        // Should be some non-negative value; we just confirm it doesn't panic.
        assert!(tick <= u64::MAX);
    }

    #[test]
    fn test_duration_debug_format() {
        let d = Duration::from_ticks(42);
        let dbg = format!("{:?}", d);
        assert!(dbg.contains("42"));
    }
}
