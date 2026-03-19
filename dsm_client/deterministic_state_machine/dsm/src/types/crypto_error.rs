//! Structured error type for cryptographic operations.
//!
//! [`CryptoError`] captures the context, operation name, and optional source
//! error string for failures occurring within the DSM cryptographic subsystem
//! (BLAKE3, SPHINCS+, ML-KEM-768, Pedersen, DBRW, etc.).

use std::fmt;

/// Structured error type for cryptographic operations.
/// Captures context, operation, and source error details without generic boxing.
#[derive(Debug)]
pub struct CryptoError {
    /// Human-readable description of what was being attempted when the error occurred.
    pub context: String,
    /// Name of the cryptographic operation that failed (e.g., "blake3_hash", "sphincs_sign").
    pub operation: String,
    /// Optional stringified source error from the underlying cryptographic library.
    pub source: Option<String>,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CryptoError [{}]: {}", self.operation, self.context)?;
        if let Some(src) = &self.source {
            write!(f, " (source: {})", src)?;
        }
        Ok(())
    }
}

impl std::error::Error for CryptoError {}
