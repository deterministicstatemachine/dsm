// SPDX-License-Identifier: MIT OR Apache-2.0

//! Utility functions for the DSM state machine
//!
//! This module contains common utility functions used across the state machine
//! implementation, ensuring consistent behavior and reducing duplication.

/// Perform constant-time equality comparison to prevent timing attacks
///
/// This function implements constant-time comparison for cryptographic values,
/// ensuring that timing information cannot be used to infer partial matches.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &[1, 2, 3]));
    }
}
