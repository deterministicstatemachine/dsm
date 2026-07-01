// SPDX-License-Identifier: MIT OR Apache-2.0
//! The exact Path-B counter acceptance check (tropic01-free, CI-tested).

/// The exact Path-B acceptance check: the authenticated live counter `h_attested` must equal
/// `H0 - (u_i + 1)` — i.e. the counter the chip must show AFTER committing the `(u_i+1)`-th anchor
/// advance. `next_anchor_counter` is `u_i + 1` (from the release). No monotonic slack, no
/// host-supplied value.
#[must_use]
pub fn counter_matches(
    h_attested: u32,
    enrolled_counter_h0: u64,
    next_anchor_counter: u64,
) -> bool {
    match enrolled_counter_h0.checked_sub(next_anchor_counter) {
        Some(expected) => u64::from(h_attested) == expected,
        None => false, // counter exhausted / nonsensical -> reject
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_counter_check() {
        // H0 = 1000, u_i+1 = 1 -> chip must read 999.
        assert!(counter_matches(999, 1000, 1));
        assert!(!counter_matches(1000, 1000, 1)); // not decremented -> reject
        assert!(!counter_matches(998, 1000, 1)); // over-decremented -> reject
                                                 // No monotonic slack: only the exact value passes.
        assert!(counter_matches(0, 1000, 1000)); // fully consumed but exact
        assert!(!counter_matches(1, 1000, 1000));
        // Nonsensical (next_anchor_counter > H0) -> reject, no panic.
        assert!(!counter_matches(0, 1000, 1001));
    }
}
