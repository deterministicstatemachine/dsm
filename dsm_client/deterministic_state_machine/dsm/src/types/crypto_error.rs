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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_without_source() {
        let err = CryptoError {
            context: "key derivation failed".into(),
            operation: "blake3_hash".into(),
            source: None,
        };
        assert_eq!(
            err.to_string(),
            "CryptoError [blake3_hash]: key derivation failed"
        );
    }

    #[test]
    fn display_with_source() {
        let err = CryptoError {
            context: "sign failed".into(),
            operation: "sphincs_sign".into(),
            source: Some("invalid key material".into()),
        };
        let msg = err.to_string();
        assert_eq!(
            msg,
            "CryptoError [sphincs_sign]: sign failed (source: invalid key material)"
        );
    }

    #[test]
    fn display_empty_fields() {
        let err = CryptoError {
            context: String::new(),
            operation: String::new(),
            source: None,
        };
        assert_eq!(err.to_string(), "CryptoError []: ");
    }

    #[test]
    fn debug_format() {
        let err = CryptoError {
            context: "ctx".into(),
            operation: "op".into(),
            source: Some("src".into()),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("CryptoError"));
        assert!(dbg.contains("ctx"));
        assert!(dbg.contains("op"));
        assert!(dbg.contains("src"));
    }

    #[test]
    fn implements_error_trait() {
        let err = CryptoError {
            context: "test".into(),
            operation: "test_op".into(),
            source: None,
        };
        let dyn_err: &dyn std::error::Error = &err;
        assert!(std::error::Error::source(dyn_err).is_none());
    }

    #[test]
    fn fields_accessible() {
        let err = CryptoError {
            context: "ctx".into(),
            operation: "ml_kem_encaps".into(),
            source: Some("rng failure".into()),
        };
        assert_eq!(err.context, "ctx");
        assert_eq!(err.operation, "ml_kem_encaps");
        assert_eq!(err.source.as_deref(), Some("rng failure"));
    }

    fn accepts_std_error(_e: &dyn std::error::Error) {}

    #[test]
    fn usable_as_dyn_error() {
        let err = CryptoError {
            context: "test".into(),
            operation: "test".into(),
            source: None,
        };
        accepts_std_error(&err);
    }
}
