//! Structured error hierarchy for core DSM operations.
//!
//! [`DsmCoreError`] covers all failure modes within the core library:
//! cryptographic failures, integrity violations, storage errors, network
//! issues, state machine faults, and bilateral protocol errors. Each variant
//! carries structured context and an optional source error chain. The
//! [`is_recoverable`](DsmCoreError::is_recoverable) method indicates whether
//! the caller should attempt retry or recovery.

use std::{error::Error, fmt::Display};

/// Core error type for DSM operations without UI-specific fields.
#[derive(Debug)]
#[non_exhaustive]
pub enum DsmCoreError {
    /// Cryptographic operation errors
    Crypto {
        context: String,
        source: Option<Box<dyn Error + Send + Sync>>,
    },

    /// Integrity check failures
    Integrity {
        context: String,
        source: Option<Box<dyn Error + Send + Sync>>,
    },

    /// Invalid public key error
    InvalidPublicKey,

    /// Invalid secret/private key error
    InvalidSecretKey,

    /// Storage-related errors
    Storage {
        context: String,
        source: Option<Box<dyn Error + Send + Sync>>,
    },

    /// Network-related errors
    Network {
        context: String,
        source: Option<Box<dyn Error + Send + Sync>>,
        entity: String,
        details: Option<String>,
    },

    /// Invalid key length error
    InvalidKeyLength,

    /// State machine errors
    StateMachine(String),

    /// Entity not found errors
    NotFound {
        entity: String,
        details: Option<String>,
        context: String,
        source: Option<Box<dyn Error + Send + Sync>>,
    },

    /// Internal implementation errors
    Internal {
        context: String,
        source: Option<Box<dyn Error + Send + Sync>>,
    },

    /// Validation errors
    Validation {
        context: String,
        source: Option<Box<dyn Error + Send + Sync>>,
    },

    /// Invalid parameter errors
    InvalidParameter(String),

    /// Serialization/deserialization errors
    Serialization {
        context: String,
        source: Option<Box<dyn Error + Send + Sync>>,
        entity: String,
        details: Option<String>,
    },

    /// Verification failures
    Verification(String),

    /// State-specific errors
    State(String),

    /// Merkle tree operation errors
    Merkle(String),

    /// Hash chain specific errors
    HashChain(String),

    /// Transaction errors
    Transaction(String),

    /// Pre-commitment errors
    PreCommitment(String),

    /// Genesis errors
    Genesis(String),

    /// Device hierarchy errors
    DeviceHierarchy(String),

    /// Forward commitment errors
    ForwardCommitment(String),

    /// Relationship errors
    Relationship(String),

    /// External commitment errors
    ExternalCommitment(String),

    /// Identity errors
    Identity(String),

    /// Communication errors
    Communication {
        context: String,
        source: Option<Box<dyn Error + Send + Sync>>,
    },

    /// Not initialized error
    NotInitialized {
        context: String,
        source: Option<Box<dyn Error + Send + Sync>>,
    },

    /// Transport-related errors
    Transport {
        context: String,
        source: Option<Box<dyn Error + Send + Sync>>,
    },

    /// Invalid ciphertext error
    InvalidCiphertext,

    /// Lock acquisition error
    LockError,

    /// Generic error with optional source
    Generic {
        message: String,
        source: Option<Box<dyn Error + Send + Sync>>,
    },

    /// Invalid index error
    InvalidIndex,

    /// Invalid operation error
    InvalidOperation(String),

    /// System error
    SystemError(String),

    /// Token error
    TokenError {
        context: String,
        source: Option<Box<dyn Error + Send + Sync>>,
    },

    /// Invalid token error
    InvalidToken {
        context: String,
        source: Option<Box<dyn Error + Send + Sync>>,
    },

    /// Unauthorized access error
    Unauthorized {
        context: String,
        source: Option<Box<dyn Error + Send + Sync>>,
    },

    /// Insufficient balance error
    InsufficientBalance {
        token_id: String,
        available: u64,
        requested: u64,
    },

    /// Feature not available error
    FeatureNotAvailable {
        feature: String,
        details: Option<String>,
    },

    /// Token Policy Violation error
    PolicyViolation {
        token_id: String,
        message: String,
        source: Option<Box<dyn Error + Send + Sync>>,
    },

    /// Invalid state error
    InvalidState(String),

    /// Time error
    TimeError(String),

    /// Blockchain-related errors
    Blockchain {
        context: String,
        source: Option<Box<dyn Error + Send + Sync>>,
    },
}

impl DsmCoreError {
    /// Creates a new cryptographic error
    pub fn crypto<E>(context: impl Into<String>, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmCoreError::Crypto {
            context: context.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new storage error
    pub fn storage<E>(context: impl Into<String>, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmCoreError::Storage {
            context: context.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new network error
    pub fn network<E>(context: impl Into<String>, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmCoreError::Network {
            context: context.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
            entity: String::new(),
            details: None,
        }
    }

    /// Creates a new state machine error
    pub fn state_machine(message: impl Into<String>) -> Self {
        DsmCoreError::StateMachine(message.into())
    }

    /// Creates a new "not found" error
    pub fn not_found(entity: impl Into<String>, details: Option<impl Into<String>>) -> Self {
        DsmCoreError::NotFound {
            entity: entity.into(),
            details: details.map(|d| d.into()),
            context: String::from("Entity not found"),
            source: None,
        }
    }

    /// Creates a new internal error
    pub fn internal<E>(context: impl Into<String>, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmCoreError::Internal {
            context: context.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new validation error
    pub fn validation<E>(context: impl Into<String>, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmCoreError::Validation {
            context: context.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new serialization error
    pub fn serialization<E>(context: impl Into<String>, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmCoreError::Serialization {
            context: context.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
            entity: "Data".to_string(),
            details: None,
        }
    }

    /// Creates a new lock error
    pub fn lock_error() -> Self {
        DsmCoreError::LockError
    }

    /// Determines if an error represents a recoverable condition
    pub fn is_recoverable(&self) -> bool {
        match self {
            // Network errors are often recoverable
            DsmCoreError::Network { .. } => true,
            // Storage errors might be recoverable
            DsmCoreError::Storage { .. } => true,
            // Transport errors are often recoverable
            DsmCoreError::Transport { .. } => true,
            // Communication errors are often recoverable
            DsmCoreError::Communication { .. } => true,
            // Timeout errors are recoverable
            DsmCoreError::TimeError(_) => true,
            // Lock errors might be recoverable
            DsmCoreError::LockError => true,
            // Not initialized might be recoverable
            DsmCoreError::NotInitialized { .. } => true,
            // Blockchain errors might be recoverable
            DsmCoreError::Blockchain { .. } => true,
            // System errors might be recoverable
            DsmCoreError::SystemError(_) => true,

            // These are typically not recoverable
            _ => false,
        }
    }
}

impl Display for DsmCoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DsmCoreError::Crypto { context, source } => {
                write!(f, "Cryptographic error: {context}")?;
                if let Some(s) = source {
                    write!(f, " - caused by: {s}")?;
                }
                Ok(())
            }
            DsmCoreError::InvalidPublicKey => write!(f, "Invalid public key"),
            DsmCoreError::InvalidSecretKey => write!(f, "Invalid secret key"),
            DsmCoreError::Storage { context, source } => {
                write!(f, "Storage error: {context}")?;
                if let Some(s) = source {
                    write!(f, " - caused by: {s}")?;
                }
                Ok(())
            }
            DsmCoreError::Network {
                context,
                source,
                entity: _,
                details: _,
            } => {
                write!(f, "Network error: {context}")?;
                if let Some(s) = source {
                    write!(f, " - caused by: {s}")?;
                }
                Ok(())
            }
            DsmCoreError::StateMachine(msg) => write!(f, "State machine error: {msg}"),
            DsmCoreError::NotFound {
                entity,
                details,
                context,
                source: _,
            } => {
                write!(f, "{entity} not found")?;
                if let Some(d) = details {
                    write!(f, ": {d}")?;
                }
                write!(f, " ({context})")?;
                Ok(())
            }
            DsmCoreError::Internal { context, source } => {
                write!(f, "Internal error: {context}")?;
                if let Some(s) = source {
                    write!(f, " - caused by: {s}")?;
                }
                Ok(())
            }
            DsmCoreError::LockError => write!(f, "Failed to acquire lock"),
            _ => write!(f, "DSM core error"),
        }
    }
}

impl Error for DsmCoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            DsmCoreError::Crypto { source, .. } => {
                source.as_ref().map(|s| s.as_ref() as &dyn Error)
            }
            DsmCoreError::Storage { source, .. } => {
                source.as_ref().map(|s| s.as_ref() as &dyn Error)
            }
            DsmCoreError::Network { source, .. } => {
                source.as_ref().map(|s| s.as_ref() as &dyn Error)
            }
            DsmCoreError::Internal { source, .. } => {
                source.as_ref().map(|s| s.as_ref() as &dyn Error)
            }
            DsmCoreError::Validation { source, .. } => {
                source.as_ref().map(|s| s.as_ref() as &dyn Error)
            }
            DsmCoreError::Serialization { source, .. } => {
                source.as_ref().map(|s| s.as_ref() as &dyn Error)
            }
            DsmCoreError::Generic { source, .. } => {
                source.as_ref().map(|s| s.as_ref() as &dyn Error)
            }
            _ => None,
        }
    }
}

// From implementations
impl From<std::io::Error> for DsmCoreError {
    fn from(error: std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::NotFound => {
                DsmCoreError::not_found("Resource", Some(error.to_string()))
            }
            std::io::ErrorKind::PermissionDenied => {
                DsmCoreError::storage("Permission denied", Some(error))
            }
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::AddrInUse
            | std::io::ErrorKind::AddrNotAvailable
            | std::io::ErrorKind::TimedOut => DsmCoreError::network(error.to_string(), Some(error)),
            _ => DsmCoreError::Generic {
                message: format!("I/O error: {error}"),
                source: Some(Box::new(error)),
            },
        }
    }
}

impl<T> From<std::sync::PoisonError<T>> for DsmCoreError {
    fn from(_err: std::sync::PoisonError<T>) -> Self {
        DsmCoreError::LockError
    }
}

// No From<serde_json::Error> in core (JSON-free)

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as StdError;
    use std::io;

    // ── Helper: a trivial error type for testing source chains ──

    #[derive(Debug)]
    struct TestSourceError(String);
    impl std::fmt::Display for TestSourceError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }
    impl StdError for TestSourceError {}

    // ── Constructor tests ──

    #[test]
    fn crypto_with_source() {
        let src = TestSourceError("bad nonce".into());
        let e = DsmCoreError::crypto("lattice op failed", Some(src));
        assert!(matches!(e, DsmCoreError::Crypto { .. }));
        let msg = e.to_string();
        assert!(msg.contains("lattice op failed"));
        assert!(msg.contains("bad nonce"));
    }

    #[test]
    fn crypto_without_source() {
        let e = DsmCoreError::crypto("no source", Option::<TestSourceError>::None);
        assert!(matches!(e, DsmCoreError::Crypto { source: None, .. }));
        assert!(!e.to_string().contains("caused by"));
    }

    #[test]
    fn storage_with_source() {
        let src = TestSourceError("disk full".into());
        let e = DsmCoreError::storage("write failed", Some(src));
        assert!(matches!(e, DsmCoreError::Storage { .. }));
        assert!(e.to_string().contains("write failed"));
        assert!(e.to_string().contains("disk full"));
    }

    #[test]
    fn storage_without_source() {
        let e = DsmCoreError::storage("no source", Option::<TestSourceError>::None);
        assert!(matches!(e, DsmCoreError::Storage { source: None, .. }));
    }

    #[test]
    fn network_with_source() {
        let src = TestSourceError("dns fail".into());
        let e = DsmCoreError::network("lookup", Some(src));
        assert!(matches!(e, DsmCoreError::Network { .. }));
        assert!(e.to_string().contains("lookup"));
    }

    #[test]
    fn network_without_source() {
        let e = DsmCoreError::network("timeout", Option::<TestSourceError>::None);
        if let DsmCoreError::Network {
            entity, details, ..
        } = &e
        {
            assert!(entity.is_empty());
            assert!(details.is_none());
        } else {
            panic!("expected Network");
        }
    }

    #[test]
    fn state_machine_constructor() {
        let e = DsmCoreError::state_machine("bad transition");
        assert!(matches!(e, DsmCoreError::StateMachine(ref m) if m == "bad transition"));
    }

    #[test]
    fn not_found_with_details() {
        let e = DsmCoreError::not_found("Token", Some("id=42"));
        if let DsmCoreError::NotFound {
            entity,
            details,
            context,
            source,
        } = &e
        {
            assert_eq!(entity, "Token");
            assert_eq!(details.as_deref(), Some("id=42"));
            assert_eq!(context, "Entity not found");
            assert!(source.is_none());
        } else {
            panic!("expected NotFound");
        }
    }

    #[test]
    fn not_found_without_details() {
        let e = DsmCoreError::not_found("Wallet", Option::<String>::None);
        if let DsmCoreError::NotFound { details, .. } = &e {
            assert!(details.is_none());
        } else {
            panic!("expected NotFound");
        }
    }

    #[test]
    fn internal_constructor() {
        let src = TestSourceError("oops".into());
        let e = DsmCoreError::internal("unexpected", Some(src));
        assert!(matches!(e, DsmCoreError::Internal { .. }));
        assert!(e.to_string().contains("unexpected"));
    }

    #[test]
    fn validation_constructor() {
        let e = DsmCoreError::validation("bad input", Option::<TestSourceError>::None);
        assert!(matches!(e, DsmCoreError::Validation { source: None, .. }));
    }

    #[test]
    fn serialization_constructor() {
        let e = DsmCoreError::serialization("decode failed", Option::<TestSourceError>::None);
        if let DsmCoreError::Serialization {
            context,
            entity,
            details,
            ..
        } = &e
        {
            assert_eq!(context, "decode failed");
            assert_eq!(entity, "Data");
            assert!(details.is_none());
        } else {
            panic!("expected Serialization");
        }
    }

    #[test]
    fn lock_error_constructor() {
        let e = DsmCoreError::lock_error();
        assert!(matches!(e, DsmCoreError::LockError));
    }

    // ── Display for every variant ──

    #[test]
    fn display_crypto() {
        let e = DsmCoreError::crypto("aes fail", Option::<TestSourceError>::None);
        assert!(e.to_string().starts_with("Cryptographic error:"));
    }

    #[test]
    fn display_invalid_public_key() {
        let e = DsmCoreError::InvalidPublicKey;
        assert_eq!(e.to_string(), "Invalid public key");
    }

    #[test]
    fn display_invalid_secret_key() {
        let e = DsmCoreError::InvalidSecretKey;
        assert_eq!(e.to_string(), "Invalid secret key");
    }

    #[test]
    fn display_storage() {
        let e = DsmCoreError::storage("corrupted", Option::<TestSourceError>::None);
        assert!(e.to_string().starts_with("Storage error:"));
    }

    #[test]
    fn display_network() {
        let e = DsmCoreError::network("refused", Option::<TestSourceError>::None);
        assert!(e.to_string().starts_with("Network error:"));
    }

    #[test]
    fn display_state_machine() {
        let e = DsmCoreError::state_machine("stuck");
        assert_eq!(e.to_string(), "State machine error: stuck");
    }

    #[test]
    fn display_not_found() {
        let e = DsmCoreError::not_found("Peer", Some("abc"));
        let msg = e.to_string();
        assert!(msg.contains("Peer not found"));
        assert!(msg.contains("abc"));
        assert!(msg.contains("Entity not found"));
    }

    #[test]
    fn display_not_found_without_details() {
        let e = DsmCoreError::not_found("Peer", Option::<String>::None);
        let msg = e.to_string();
        assert!(msg.contains("Peer not found"));
        assert!(!msg.contains(':'));
    }

    #[test]
    fn display_internal() {
        let e = DsmCoreError::internal("bug", Option::<TestSourceError>::None);
        assert!(e.to_string().starts_with("Internal error:"));
    }

    #[test]
    fn display_lock_error() {
        let e = DsmCoreError::LockError;
        assert_eq!(e.to_string(), "Failed to acquire lock");
    }

    #[test]
    fn display_catchall_variants() {
        let catchall_variants: Vec<DsmCoreError> = vec![
            DsmCoreError::Integrity {
                context: "x".into(),
                source: None,
            },
            DsmCoreError::InvalidKeyLength,
            DsmCoreError::Validation {
                context: "x".into(),
                source: None,
            },
            DsmCoreError::InvalidParameter("x".into()),
            DsmCoreError::Serialization {
                context: "x".into(),
                source: None,
                entity: "x".into(),
                details: None,
            },
            DsmCoreError::Verification("x".into()),
            DsmCoreError::State("x".into()),
            DsmCoreError::Merkle("x".into()),
            DsmCoreError::HashChain("x".into()),
            DsmCoreError::Transaction("x".into()),
            DsmCoreError::PreCommitment("x".into()),
            DsmCoreError::Genesis("x".into()),
            DsmCoreError::DeviceHierarchy("x".into()),
            DsmCoreError::ForwardCommitment("x".into()),
            DsmCoreError::Relationship("x".into()),
            DsmCoreError::ExternalCommitment("x".into()),
            DsmCoreError::Identity("x".into()),
            DsmCoreError::Communication {
                context: "x".into(),
                source: None,
            },
            DsmCoreError::NotInitialized {
                context: "x".into(),
                source: None,
            },
            DsmCoreError::Transport {
                context: "x".into(),
                source: None,
            },
            DsmCoreError::InvalidCiphertext,
            DsmCoreError::Generic {
                message: "x".into(),
                source: None,
            },
            DsmCoreError::InvalidIndex,
            DsmCoreError::InvalidOperation("x".into()),
            DsmCoreError::SystemError("x".into()),
            DsmCoreError::TokenError {
                context: "x".into(),
                source: None,
            },
            DsmCoreError::InvalidToken {
                context: "x".into(),
                source: None,
            },
            DsmCoreError::Unauthorized {
                context: "x".into(),
                source: None,
            },
            DsmCoreError::InsufficientBalance {
                token_id: "t".into(),
                available: 10,
                requested: 20,
            },
            DsmCoreError::FeatureNotAvailable {
                feature: "x".into(),
                details: None,
            },
            DsmCoreError::PolicyViolation {
                token_id: "t".into(),
                message: "x".into(),
                source: None,
            },
            DsmCoreError::InvalidState("x".into()),
            DsmCoreError::TimeError("x".into()),
            DsmCoreError::Blockchain {
                context: "x".into(),
                source: None,
            },
        ];
        for v in catchall_variants {
            assert_eq!(v.to_string(), "DSM core error");
        }
    }

    // ── is_recoverable for every variant ──

    #[test]
    fn recoverable_variants() {
        let recoverable = vec![
            DsmCoreError::Network {
                context: "".into(),
                source: None,
                entity: "".into(),
                details: None,
            },
            DsmCoreError::Storage {
                context: "".into(),
                source: None,
            },
            DsmCoreError::Transport {
                context: "".into(),
                source: None,
            },
            DsmCoreError::Communication {
                context: "".into(),
                source: None,
            },
            DsmCoreError::TimeError("".into()),
            DsmCoreError::LockError,
            DsmCoreError::NotInitialized {
                context: "".into(),
                source: None,
            },
            DsmCoreError::Blockchain {
                context: "".into(),
                source: None,
            },
            DsmCoreError::SystemError("".into()),
        ];
        for v in &recoverable {
            assert!(v.is_recoverable(), "{v:?} should be recoverable");
        }
    }

    #[test]
    fn non_recoverable_variants() {
        let non_recoverable = vec![
            DsmCoreError::Crypto {
                context: "".into(),
                source: None,
            },
            DsmCoreError::Integrity {
                context: "".into(),
                source: None,
            },
            DsmCoreError::InvalidPublicKey,
            DsmCoreError::InvalidSecretKey,
            DsmCoreError::InvalidKeyLength,
            DsmCoreError::StateMachine("".into()),
            DsmCoreError::NotFound {
                entity: "".into(),
                details: None,
                context: "".into(),
                source: None,
            },
            DsmCoreError::Internal {
                context: "".into(),
                source: None,
            },
            DsmCoreError::Validation {
                context: "".into(),
                source: None,
            },
            DsmCoreError::InvalidParameter("".into()),
            DsmCoreError::Serialization {
                context: "".into(),
                source: None,
                entity: "".into(),
                details: None,
            },
            DsmCoreError::Verification("".into()),
            DsmCoreError::State("".into()),
            DsmCoreError::Merkle("".into()),
            DsmCoreError::HashChain("".into()),
            DsmCoreError::Transaction("".into()),
            DsmCoreError::PreCommitment("".into()),
            DsmCoreError::Genesis("".into()),
            DsmCoreError::DeviceHierarchy("".into()),
            DsmCoreError::ForwardCommitment("".into()),
            DsmCoreError::Relationship("".into()),
            DsmCoreError::ExternalCommitment("".into()),
            DsmCoreError::Identity("".into()),
            DsmCoreError::InvalidCiphertext,
            DsmCoreError::Generic {
                message: "".into(),
                source: None,
            },
            DsmCoreError::InvalidIndex,
            DsmCoreError::InvalidOperation("".into()),
            DsmCoreError::TokenError {
                context: "".into(),
                source: None,
            },
            DsmCoreError::InvalidToken {
                context: "".into(),
                source: None,
            },
            DsmCoreError::Unauthorized {
                context: "".into(),
                source: None,
            },
            DsmCoreError::InsufficientBalance {
                token_id: "".into(),
                available: 0,
                requested: 0,
            },
            DsmCoreError::FeatureNotAvailable {
                feature: "".into(),
                details: None,
            },
            DsmCoreError::PolicyViolation {
                token_id: "".into(),
                message: "".into(),
                source: None,
            },
            DsmCoreError::InvalidState("".into()),
        ];
        for v in &non_recoverable {
            assert!(!v.is_recoverable(), "{v:?} should NOT be recoverable");
        }
    }

    // ── Error::source ──

    #[test]
    fn source_crypto_with_source() {
        let e = DsmCoreError::crypto("ctx", Some(TestSourceError("inner".into())));
        assert!(e.source().is_some());
        assert!(e.source().unwrap().to_string().contains("inner"));
    }

    #[test]
    fn source_crypto_without_source() {
        let e = DsmCoreError::crypto("ctx", Option::<TestSourceError>::None);
        assert!(e.source().is_none());
    }

    #[test]
    fn source_storage() {
        let e = DsmCoreError::storage("ctx", Some(TestSourceError("s".into())));
        assert!(e.source().is_some());
    }

    #[test]
    fn source_network() {
        let e = DsmCoreError::network("ctx", Some(TestSourceError("n".into())));
        assert!(e.source().is_some());
    }

    #[test]
    fn source_internal() {
        let e = DsmCoreError::internal("ctx", Some(TestSourceError("i".into())));
        assert!(e.source().is_some());
    }

    #[test]
    fn source_validation() {
        let e = DsmCoreError::validation("ctx", Some(TestSourceError("v".into())));
        assert!(e.source().is_some());
    }

    #[test]
    fn source_serialization() {
        let e = DsmCoreError::serialization("ctx", Some(TestSourceError("ser".into())));
        assert!(e.source().is_some());
    }

    #[test]
    fn source_generic() {
        let e = DsmCoreError::Generic {
            message: "g".into(),
            source: Some(Box::new(TestSourceError("gen".into()))),
        };
        assert!(e.source().is_some());
    }

    #[test]
    fn source_returns_none_for_other_variants() {
        let e = DsmCoreError::InvalidPublicKey;
        assert!(e.source().is_none());
        let e2 = DsmCoreError::StateMachine("x".into());
        assert!(e2.source().is_none());
    }

    // ── From<std::io::Error> ──

    #[test]
    fn from_io_not_found() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "gone");
        let e: DsmCoreError = io_err.into();
        assert!(matches!(e, DsmCoreError::NotFound { .. }));
    }

    #[test]
    fn from_io_permission_denied() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "nope");
        let e: DsmCoreError = io_err.into();
        assert!(matches!(e, DsmCoreError::Storage { .. }));
    }

    #[test]
    fn from_io_connection_refused() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        let e: DsmCoreError = io_err.into();
        assert!(matches!(e, DsmCoreError::Network { .. }));
    }

    #[test]
    fn from_io_connection_reset() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
        let e: DsmCoreError = io_err.into();
        assert!(matches!(e, DsmCoreError::Network { .. }));
    }

    #[test]
    fn from_io_timed_out() {
        let io_err = io::Error::new(io::ErrorKind::TimedOut, "slow");
        let e: DsmCoreError = io_err.into();
        assert!(matches!(e, DsmCoreError::Network { .. }));
    }

    #[test]
    fn from_io_other_becomes_generic() {
        let io_err = io::Error::other("misc");
        let e: DsmCoreError = io_err.into();
        assert!(matches!(e, DsmCoreError::Generic { .. }));
        assert!(e.to_string().contains("DSM core error"));
    }

    // ── From<PoisonError> ──

    #[test]
    fn from_poison_error() {
        let lock = std::sync::Mutex::new(42);
        // Poison the mutex by panicking inside a lock
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = lock.lock().unwrap();
            panic!("poison");
        }));
        let err = lock.lock().unwrap_err();
        let e: DsmCoreError = err.into();
        assert!(matches!(e, DsmCoreError::LockError));
    }

    // ── Debug is implemented ──

    #[test]
    fn debug_format_works() {
        let e = DsmCoreError::crypto("dbg test", Option::<TestSourceError>::None);
        let dbg = format!("{:?}", e);
        assert!(dbg.contains("Crypto"));
        assert!(dbg.contains("dbg test"));
    }

    // ── Send + Sync ──

    #[test]
    fn error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DsmCoreError>();
        let e = DsmCoreError::crypto("t", Option::<TestSourceError>::None);
        let _ = format!("{e}");
    }
}
