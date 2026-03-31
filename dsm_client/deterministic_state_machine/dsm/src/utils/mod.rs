//! # Utilities Module
//!
//! This module provides general utility functions used throughout the DSM codebase.
//! It contains sub-modules for specific utility categories and standalone
//! functions for common operations.
//!
//! ## Sub-modules
//!
//! * `deterministic_time`: cryptographic progress anchors and tick-compatible helpers
//! * `file`: File system operations and helpers
//! * `time`: Time-related utilities and formatting functions

pub mod deterministic_time;
#[cfg(test)]
pub mod file;
pub mod time;
pub mod timeout;

pub use deterministic_time::*;

/// Generate cryptographically secure random bytes
///
/// This function produces a specified number of cryptographically secure
/// random bytes using the operating system's secure random number generator.
/// This is suitable for use in cryptographic applications like key generation.
///
/// # Arguments
///
/// * `length` - The number of random bytes to generate
///
/// # Returns
///
/// A vector containing the requested number of random bytes
///
/// # Examples
///
/// ```
/// use dsm::utils;
///
/// // Generate a 32-byte (256-bit) random value
/// let random_key = utils::random_bytes(32);
/// assert_eq!(random_key.len(), 32);
///
/// // Generate a different random value
/// let another_key = utils::random_bytes(32);
/// assert_eq!(another_key.len(), 32);
///
/// // The two should be different (with extremely high probability)
/// assert_ne!(random_key, another_key);
/// ```
#[allow(unused)]
pub fn random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    use rand::rngs::SysRng;
    use chacha20::rand_core::TryRng;
    let mut bytes = vec![0u8; length];
    SysRng.try_fill_bytes(&mut bytes).expect("OS RNG failed");
    bytes
}

/// Get the current deterministic tick index (preferred)
#[allow(unused)]
pub fn current_tick() -> u64 {
    crate::utils::time::now()
}
