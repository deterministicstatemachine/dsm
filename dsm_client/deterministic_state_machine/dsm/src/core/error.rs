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
