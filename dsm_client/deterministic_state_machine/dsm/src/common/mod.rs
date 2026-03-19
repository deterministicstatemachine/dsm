//! # Common Module
//!
//! Dependency-free, circular-import-safe primitives shared across DSM.
//!
//! Hard constraints (enforced here, expected system-wide):
//! - No wall-clock time (no durations, timeouts, or backoffs). All logic is tick-based and deterministic.
//! - No hex/json/base64/serde encodings for identifiers or binary values.
//! - Binary-only helpers; canonicality first.

/// DSM Protocol Version identifier (wire-level compat)
pub const PROTOCOL_VERSION: &str = "0.1.0";

/// Standard BLAKE3-256 output length (bytes)
pub const HASH_LENGTH: usize = 32;

/// Default symmetric key size (bytes)
pub const KEY_SIZE: usize = 32;

/// Maximum buffer size for internal I/O (defensive ceiling)
pub const MAX_BUFFER_SIZE: usize = 4_096;

/// Centralized canonical encoding for cryptographic commitments
pub mod canonical_encoding;
/// Deterministic ID generation (no UUID, no wall-clock)
pub mod deterministic_id;
pub mod device_tree;
/// Domain tag constants for BLAKE3 domain-separated hashing
pub mod domain_tags;

/// DSM protocol magic bytes ("SECI")
pub const PROTOCOL_MAGIC: [u8; 4] = [0x53, 0x45, 0x43, 0x49];

/// Centralized non-time-based constants
pub mod constants {
    /// Default network port for DSM nodes
    pub const DEFAULT_PORT: u16 = 8421;

    /// Default network buffer size (bytes)
    pub const DEFAULT_BUFFER_SIZE: usize = 8_192;

    /// Default data directory path
    pub const DEFAULT_DB_PATH: &str = "./seci_data";

    /// Minimum acceptable password length
    pub const MIN_PASSWORD_LENGTH: usize = 12;

    /// Default iteration count for password-based KDFs
    pub const DEFAULT_KEY_DERIVATION_ITERATIONS: u32 = 100_000;
}

/// Binary-only helpers. No encoders/decoders. No time.
pub mod helpers {
    /// Return `true` iff all bytes are zero.
    #[inline]
    pub fn is_all_zeros(data: &[u8]) -> bool {
        data.iter().all(|&b| b == 0)
    }

    /// Branchless byte-wise equality to reduce timing variance.
    /// Not a substitute for a dedicated constant-time lib, but avoids
    /// early-return equality and keeps comparisons uniform.
    #[inline]
    pub fn secure_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for i in 0..a.len() {
            diff |= a[i] ^ b[i];
        }
        diff == 0
    }

    /// Clamp a slice to at most `max_len` bytes (no allocation).
    #[inline]
    pub fn clamp_slice(bytes: &[u8], max_len: usize) -> &[u8] {
        if bytes.len() <= max_len {
            bytes
        } else {
            &bytes[..max_len]
        }
    }
}

#[cfg(test)]
mod tests {}
