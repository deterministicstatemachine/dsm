//! Cross-layer unified error type for the DSM protocol.
//!
//! [`UnifiedDsmError`] provides a single error enum that spans all subsystems
//! (crypto, network, storage, configuration, validation, authentication,
//! authorization, rate limiting) with structured recovery strategies and
//! retry semantics. Each variant carries a `recoverable` flag and maps to
//! a [`RecoveryStrategy`] so callers can decide how to handle failures
//! without inspecting error messages.
//!
//! [`ErrorResponse`] is a transport-agnostic response structure for surfacing
//! errors through the JNI bridge to the Kotlin/WebView layer. All encoding
//! is protobuf-compatible (BTreeMap, no JSON).

use std::error::Error;
use std::fmt;
use std::collections::BTreeMap;

/// Unified error type spanning all DSM subsystems.
///
/// Each variant includes structured context and a `recoverable` flag indicating
/// whether the caller should retry the operation. Use [`recovery_strategy`](UnifiedDsmError::recovery_strategy)
/// to determine the appropriate recovery action.
#[derive(Debug)]
pub enum UnifiedDsmError {
    /// Cryptographic operation failure (BLAKE3, SPHINCS+, ML-KEM, Pedersen, DBRW).
    Crypto {
        /// Description of the failed operation.
        context: String,
        /// Subsystem component where the error originated.
        component: Option<String>,
        /// Underlying error from the crypto library.
        source: Option<Box<dyn Error + Send + Sync + 'static>>,
        /// Whether retrying might succeed.
        recoverable: bool,
    },
    /// Network or transport-layer failure (BLE, online relay, storage node communication).
    Network {
        /// Description of the failed network operation.
        context: String,
        /// Network subsystem component.
        component: Option<String>,
        /// Underlying I/O or transport error.
        source: Option<Box<dyn Error + Send + Sync + 'static>>,
        /// Whether reconnecting might resolve the issue.
        recoverable: bool,
    },
    /// Persistent storage failure (database, file system, key-value store).
    Storage {
        /// Description of the failed storage operation.
        context: String,
        /// Storage subsystem component.
        component: Option<String>,
        /// Underlying storage error.
        source: Option<Box<dyn Error + Send + Sync + 'static>>,
        /// Whether reloading or retrying might succeed.
        recoverable: bool,
    },
    /// Configuration or initialization failure.
    Configuration {
        /// Description of the configuration problem.
        context: String,
        /// Configuration subsystem component.
        component: Option<String>,
        /// Underlying error.
        source: Option<Box<dyn Error + Send + Sync + 'static>>,
        /// Whether reconfiguring might resolve the issue.
        recoverable: bool,
    },
    /// Internal logic error (invariant violation, unexpected state).
    Internal {
        /// Description of the internal error.
        context: String,
        /// Component where the error occurred.
        component: Option<String>,
        /// Underlying error.
        source: Option<Box<dyn Error + Send + Sync + 'static>>,
        /// Whether a restart might resolve the issue.
        recoverable: bool,
    },
    /// Input validation failure (malformed parameters, constraint violations).
    Validation {
        /// Description of the validation failure.
        context: String,
        /// Name of the field that failed validation, if applicable.
        field: Option<String>,
        /// Whether correcting the input might resolve the issue.
        recoverable: bool,
    },
    /// Requested resource does not exist.
    NotFound {
        /// Type of resource (e.g., "state", "vault", "device").
        resource_type: String,
        /// Identifier of the missing resource.
        resource_id: String,
    },
    /// Authentication failure (invalid credentials or signatures).
    Authentication {
        /// Description of the authentication failure.
        context: String,
    },
    /// Authorization failure (insufficient permissions).
    Authorization {
        /// Description of the authorization failure.
        context: String,
    },
    /// Rate limit exceeded; caller should back off.
    RateLimit {
        /// Description of which rate limit was exceeded.
        context: String,
        /// Suggested wait time in seconds before retrying.
        retry_after_seconds: Option<u64>,
    },
}

/// Generic error response structure (transport-agnostic)
#[derive(Debug)]
pub struct ErrorResponse {
    /// Error type identifier
    pub error_type: String,
    /// Human-readable error message
    pub message: String,
    /// Error code for programmatic handling
    pub code: String,
    /// Additional context or details (key-value, JSON-free)
    pub details: Option<BTreeMap<String, String>>,
    /// Request ID for tracing
    pub request_id: Option<String>,
    /// Base32-Crockford debug string encoding of canonical debug bytes (UI-only)
    pub debug_b32: String,
}

/// Recommended recovery action for a given error type.
#[derive(Debug)]
pub enum RecoveryStrategy {
    /// Retry the operation with exponential backoff.
    RetryWithBackoff,
    /// Re-establish the network or BLE connection.
    Reconnect,
    /// Reload the data from storage.
    Reload,
    /// Fix configuration and retry.
    Reconfigure,
    /// Restart the SDK or application.
    Restart,
}

impl fmt::Display for UnifiedDsmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnifiedDsmError::Crypto {
                context, component, ..
            } => {
                if let Some(comp) = component {
                    write!(f, "Crypto error in {comp}: {context}")
                } else {
                    write!(f, "Crypto error: {context}")
                }
            }
            UnifiedDsmError::Network {
                context, component, ..
            } => {
                if let Some(comp) = component {
                    write!(f, "Network error in {comp}: {context}")
                } else {
                    write!(f, "Network error: {context}")
                }
            }
            UnifiedDsmError::Storage {
                context, component, ..
            } => {
                if let Some(comp) = component {
                    write!(f, "Storage error in {comp}: {context}")
                } else {
                    write!(f, "Storage error: {context}")
                }
            }
            UnifiedDsmError::Configuration {
                context, component, ..
            } => {
                if let Some(comp) = component {
                    write!(f, "Configuration error in {comp}: {context}")
                } else {
                    write!(f, "Configuration error: {context}")
                }
            }
            UnifiedDsmError::Internal {
                context, component, ..
            } => {
                if let Some(comp) = component {
                    write!(f, "Internal error in {comp}: {context}")
                } else {
                    write!(f, "Internal error: {context}")
                }
            }
            UnifiedDsmError::Validation { context, field, .. } => {
                if let Some(field_name) = field {
                    write!(f, "Validation error for field '{field_name}': {context}")
                } else {
                    write!(f, "Validation error: {context}")
                }
            }
            UnifiedDsmError::NotFound {
                resource_type,
                resource_id,
            } => {
                write!(f, "Resource not found: {resource_type} '{resource_id}'")
            }
            UnifiedDsmError::Authentication { context } => {
                write!(f, "Authentication failed: {context}")
            }
            UnifiedDsmError::Authorization { context } => {
                write!(f, "Authorization failed: {context}")
            }
            UnifiedDsmError::RateLimit { context, .. } => {
                write!(f, "Rate limit exceeded: {context}")
            }
        }
    }
}

impl Error for UnifiedDsmError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            UnifiedDsmError::Crypto { source, .. } => source
                .as_ref()
                .map(|e| e.as_ref() as &(dyn Error + 'static)),
            UnifiedDsmError::Network { source, .. } => source
                .as_ref()
                .map(|e| e.as_ref() as &(dyn Error + 'static)),
            UnifiedDsmError::Storage { source, .. } => source
                .as_ref()
                .map(|e| e.as_ref() as &(dyn Error + 'static)),
            UnifiedDsmError::Configuration { source, .. } => source
                .as_ref()
                .map(|e| e.as_ref() as &(dyn Error + 'static)),
            UnifiedDsmError::Internal { source, .. } => source
                .as_ref()
                .map(|e| e.as_ref() as &(dyn Error + 'static)),
            UnifiedDsmError::Validation { .. } => None,
            UnifiedDsmError::NotFound { .. } => None,
            UnifiedDsmError::Authentication { .. } => None,
            UnifiedDsmError::Authorization { .. } => None,
            UnifiedDsmError::RateLimit { .. } => None,
        }
    }
}

impl UnifiedDsmError {
    pub fn new_internal(context: String) -> Self {
        UnifiedDsmError::Internal {
            context,
            component: None,
            source: None,
            recoverable: false,
        }
    }

    pub fn is_recoverable(&self) -> bool {
        match self {
            UnifiedDsmError::Crypto { recoverable, .. } => *recoverable,
            UnifiedDsmError::Network { recoverable, .. } => *recoverable,
            UnifiedDsmError::Storage { recoverable, .. } => *recoverable,
            UnifiedDsmError::Configuration { recoverable, .. } => *recoverable,
            UnifiedDsmError::Internal { recoverable, .. } => *recoverable,
            UnifiedDsmError::Validation { recoverable, .. } => *recoverable,
            UnifiedDsmError::NotFound { .. } => false,
            UnifiedDsmError::Authentication { .. } => false,
            UnifiedDsmError::Authorization { .. } => false,
            UnifiedDsmError::RateLimit { .. } => true,
        }
    }

    pub fn error_type(&self) -> &'static str {
        match self {
            UnifiedDsmError::Crypto { .. } => "crypto",
            UnifiedDsmError::Network { .. } => "network",
            UnifiedDsmError::Storage { .. } => "storage",
            UnifiedDsmError::Configuration { .. } => "configuration",
            UnifiedDsmError::Internal { .. } => "internal",
            UnifiedDsmError::Validation { .. } => "validation",
            UnifiedDsmError::NotFound { .. } => "not_found",
            UnifiedDsmError::Authentication { .. } => "authentication",
            UnifiedDsmError::Authorization { .. } => "authorization",
            UnifiedDsmError::RateLimit { .. } => "rate_limit",
        }
    }

    pub fn recovery_strategy(&self) -> RecoveryStrategy {
        match self {
            UnifiedDsmError::Crypto { .. } => RecoveryStrategy::RetryWithBackoff,
            UnifiedDsmError::Network { .. } => RecoveryStrategy::Reconnect,
            UnifiedDsmError::Storage { .. } => RecoveryStrategy::Reload,
            UnifiedDsmError::Configuration { .. } => RecoveryStrategy::Reconfigure,
            UnifiedDsmError::Internal { .. } => RecoveryStrategy::Restart,
            UnifiedDsmError::Validation { .. } => RecoveryStrategy::Reconfigure,
            UnifiedDsmError::NotFound { .. } => RecoveryStrategy::Reconnect,
            UnifiedDsmError::Authentication { .. } => RecoveryStrategy::Reconfigure,
            UnifiedDsmError::Authorization { .. } => RecoveryStrategy::Reconfigure,
            UnifiedDsmError::RateLimit { .. } => RecoveryStrategy::RetryWithBackoff,
        }
    }

    pub fn max_retries(&self) -> u32 {
        match self {
            UnifiedDsmError::Crypto { .. } => 0, // Never retry crypto errors
            UnifiedDsmError::Network { .. } => 3,
            UnifiedDsmError::Storage { .. } => 2,
            UnifiedDsmError::Configuration { .. } => 0, // Never retry config errors
            UnifiedDsmError::Internal { .. } => 1,
            UnifiedDsmError::Validation { .. } => 0,
            UnifiedDsmError::NotFound { .. } => 0,
            UnifiedDsmError::Authentication { .. } => 0,
            UnifiedDsmError::Authorization { .. } => 0,
            UnifiedDsmError::RateLimit { .. } => 1,
        }
    }
}

// Helper function to create internal error
pub fn internal_error() -> UnifiedDsmError {
    UnifiedDsmError::new_internal("internal error".to_string())
}

impl UnifiedDsmError {
    /// Convert to a structured error response (transport-agnostic)
    pub fn to_error_response(&self) -> ErrorResponse {
        let details = match self {
            UnifiedDsmError::RateLimit {
                retry_after_seconds: Some(seconds),
                ..
            } => {
                let mut map = BTreeMap::new();
                map.insert("retry_after_seconds".to_string(), seconds.to_string());
                Some(map)
            }
            UnifiedDsmError::NotFound {
                resource_type,
                resource_id,
            } => {
                let mut map = BTreeMap::new();
                map.insert("resource_type".to_string(), resource_type.clone());
                map.insert("resource_id".to_string(), resource_id.clone());
                Some(map)
            }
            UnifiedDsmError::Validation {
                field: Some(field_name),
                ..
            } => {
                let mut map = BTreeMap::new();
                map.insert("field".to_string(), field_name.clone());
                Some(map)
            }
            _ => None,
        };

        ErrorResponse {
            error_type: self.error_type().to_string(),
            message: self.to_string(),
            code: self.error_type().to_string(),
            details,
            request_id: None,          // Can be set by middleware
            debug_b32: "".to_string(), // Computed in JNI layer
        }
    }

    /// Create a validation error
    pub fn validation(context: impl Into<String>) -> Self {
        UnifiedDsmError::Validation {
            context: context.into(),
            field: None,
            recoverable: false,
        }
    }

    /// Create a validation error with field information
    pub fn validation_field(context: impl Into<String>, field: impl Into<String>) -> Self {
        UnifiedDsmError::Validation {
            context: context.into(),
            field: Some(field.into()),
            recoverable: false,
        }
    }

    /// Create a not found error
    pub fn not_found(resource_type: impl Into<String>, resource_id: impl Into<String>) -> Self {
        UnifiedDsmError::NotFound {
            resource_type: resource_type.into(),
            resource_id: resource_id.into(),
        }
    }

    /// Create an authentication error
    pub fn authentication(context: impl Into<String>) -> Self {
        UnifiedDsmError::Authentication {
            context: context.into(),
        }
    }

    /// Create an authorization error
    pub fn authorization(context: impl Into<String>) -> Self {
        UnifiedDsmError::Authorization {
            context: context.into(),
        }
    }

    /// Create a rate limit error
    pub fn rate_limit(context: impl Into<String>, retry_after_seconds: Option<u64>) -> Self {
        UnifiedDsmError::RateLimit {
            context: context.into(),
            retry_after_seconds,
        }
    }
}

impl From<std::io::Error> for UnifiedDsmError {
    fn from(err: std::io::Error) -> Self {
        UnifiedDsmError::Storage {
            context: "I/O operation failed".to_string(),
            component: None,
            source: Some(Box::new(err)),
            recoverable: true,
        }
    }
}

// Note: No From<serde_json::Error> to keep core JSON-free

/// Result type alias for DSM operations
pub type DsmResult<T> = Result<T, UnifiedDsmError>;

#[cfg(test)]
mod tests {
    use super::*;

    // ── Display tests ───────────────────────────────────────────────

    #[test]
    fn display_crypto_with_component() {
        let e = UnifiedDsmError::Crypto {
            context: "bad key".into(),
            component: Some("ML-KEM".into()),
            source: None,
            recoverable: false,
        };
        assert_eq!(e.to_string(), "Crypto error in ML-KEM: bad key");
    }

    #[test]
    fn display_crypto_without_component() {
        let e = UnifiedDsmError::Crypto {
            context: "bad key".into(),
            component: None,
            source: None,
            recoverable: false,
        };
        assert_eq!(e.to_string(), "Crypto error: bad key");
    }

    #[test]
    fn display_network_with_component() {
        let e = UnifiedDsmError::Network {
            context: "timeout".into(),
            component: Some("BLE".into()),
            source: None,
            recoverable: true,
        };
        assert_eq!(e.to_string(), "Network error in BLE: timeout");
    }

    #[test]
    fn display_network_without_component() {
        let e = UnifiedDsmError::Network {
            context: "timeout".into(),
            component: None,
            source: None,
            recoverable: true,
        };
        assert_eq!(e.to_string(), "Network error: timeout");
    }

    #[test]
    fn display_storage() {
        let e = UnifiedDsmError::Storage {
            context: "disk full".into(),
            component: Some("kv".into()),
            source: None,
            recoverable: false,
        };
        assert_eq!(e.to_string(), "Storage error in kv: disk full");
    }

    #[test]
    fn display_configuration() {
        let e = UnifiedDsmError::Configuration {
            context: "missing key".into(),
            component: None,
            source: None,
            recoverable: false,
        };
        assert_eq!(e.to_string(), "Configuration error: missing key");
    }

    #[test]
    fn display_internal() {
        let e = UnifiedDsmError::Internal {
            context: "invariant".into(),
            component: Some("vault".into()),
            source: None,
            recoverable: false,
        };
        assert_eq!(e.to_string(), "Internal error in vault: invariant");
    }

    #[test]
    fn display_validation_with_field() {
        let e = UnifiedDsmError::Validation {
            context: "too long".into(),
            field: Some("name".into()),
            recoverable: false,
        };
        assert_eq!(e.to_string(), "Validation error for field 'name': too long");
    }

    #[test]
    fn display_validation_without_field() {
        let e = UnifiedDsmError::Validation {
            context: "too long".into(),
            field: None,
            recoverable: false,
        };
        assert_eq!(e.to_string(), "Validation error: too long");
    }

    #[test]
    fn display_not_found() {
        let e = UnifiedDsmError::NotFound {
            resource_type: "vault".into(),
            resource_id: "abc".into(),
        };
        assert_eq!(e.to_string(), "Resource not found: vault 'abc'");
    }

    #[test]
    fn display_authentication() {
        let e = UnifiedDsmError::Authentication {
            context: "bad sig".into(),
        };
        assert_eq!(e.to_string(), "Authentication failed: bad sig");
    }

    #[test]
    fn display_authorization() {
        let e = UnifiedDsmError::Authorization {
            context: "no perms".into(),
        };
        assert_eq!(e.to_string(), "Authorization failed: no perms");
    }

    #[test]
    fn display_rate_limit() {
        let e = UnifiedDsmError::RateLimit {
            context: "too fast".into(),
            retry_after_seconds: Some(30),
        };
        assert_eq!(e.to_string(), "Rate limit exceeded: too fast");
    }

    // ── is_recoverable ──────────────────────────────────────────────

    #[test]
    fn recoverable_respects_flag() {
        let yes = UnifiedDsmError::Crypto {
            context: "".into(),
            component: None,
            source: None,
            recoverable: true,
        };
        assert!(yes.is_recoverable());

        let no = UnifiedDsmError::Crypto {
            context: "".into(),
            component: None,
            source: None,
            recoverable: false,
        };
        assert!(!no.is_recoverable());
    }

    #[test]
    fn not_found_never_recoverable() {
        let e = UnifiedDsmError::not_found("x", "y");
        assert!(!e.is_recoverable());
    }

    #[test]
    fn authentication_never_recoverable() {
        assert!(!UnifiedDsmError::authentication("x").is_recoverable());
    }

    #[test]
    fn authorization_never_recoverable() {
        assert!(!UnifiedDsmError::authorization("x").is_recoverable());
    }

    #[test]
    fn rate_limit_always_recoverable() {
        assert!(UnifiedDsmError::rate_limit("x", None).is_recoverable());
    }

    // ── error_type ──────────────────────────────────────────────────

    #[test]
    fn error_type_returns_correct_tag() {
        assert_eq!(
            UnifiedDsmError::Crypto {
                context: "".into(),
                component: None,
                source: None,
                recoverable: false
            }
            .error_type(),
            "crypto"
        );
        assert_eq!(
            UnifiedDsmError::Network {
                context: "".into(),
                component: None,
                source: None,
                recoverable: false
            }
            .error_type(),
            "network"
        );
        assert_eq!(
            UnifiedDsmError::Storage {
                context: "".into(),
                component: None,
                source: None,
                recoverable: false
            }
            .error_type(),
            "storage"
        );
        assert_eq!(
            UnifiedDsmError::Configuration {
                context: "".into(),
                component: None,
                source: None,
                recoverable: false
            }
            .error_type(),
            "configuration"
        );
        assert_eq!(
            UnifiedDsmError::new_internal("x".into()).error_type(),
            "internal"
        );
        assert_eq!(UnifiedDsmError::validation("x").error_type(), "validation");
        assert_eq!(
            UnifiedDsmError::not_found("a", "b").error_type(),
            "not_found"
        );
        assert_eq!(
            UnifiedDsmError::authentication("x").error_type(),
            "authentication"
        );
        assert_eq!(
            UnifiedDsmError::authorization("x").error_type(),
            "authorization"
        );
        assert_eq!(
            UnifiedDsmError::rate_limit("x", None).error_type(),
            "rate_limit"
        );
    }

    // ── recovery_strategy ───────────────────────────────────────────

    #[test]
    fn recovery_strategy_mapping() {
        assert!(matches!(
            UnifiedDsmError::Crypto {
                context: "".into(),
                component: None,
                source: None,
                recoverable: false
            }
            .recovery_strategy(),
            RecoveryStrategy::RetryWithBackoff
        ));
        assert!(matches!(
            UnifiedDsmError::Network {
                context: "".into(),
                component: None,
                source: None,
                recoverable: false
            }
            .recovery_strategy(),
            RecoveryStrategy::Reconnect
        ));
        assert!(matches!(
            UnifiedDsmError::Storage {
                context: "".into(),
                component: None,
                source: None,
                recoverable: false
            }
            .recovery_strategy(),
            RecoveryStrategy::Reload
        ));
        assert!(matches!(
            UnifiedDsmError::Configuration {
                context: "".into(),
                component: None,
                source: None,
                recoverable: false
            }
            .recovery_strategy(),
            RecoveryStrategy::Reconfigure
        ));
        assert!(matches!(
            UnifiedDsmError::new_internal("x".into()).recovery_strategy(),
            RecoveryStrategy::Restart
        ));
        assert!(matches!(
            UnifiedDsmError::rate_limit("x", None).recovery_strategy(),
            RecoveryStrategy::RetryWithBackoff
        ));
    }

    // ── max_retries ─────────────────────────────────────────────────

    #[test]
    fn max_retries_values() {
        assert_eq!(
            UnifiedDsmError::Crypto {
                context: "".into(),
                component: None,
                source: None,
                recoverable: false
            }
            .max_retries(),
            0
        );
        assert_eq!(
            UnifiedDsmError::Network {
                context: "".into(),
                component: None,
                source: None,
                recoverable: false
            }
            .max_retries(),
            3
        );
        assert_eq!(
            UnifiedDsmError::Storage {
                context: "".into(),
                component: None,
                source: None,
                recoverable: false
            }
            .max_retries(),
            2
        );
        assert_eq!(UnifiedDsmError::new_internal("x".into()).max_retries(), 1);
        assert_eq!(UnifiedDsmError::validation("x").max_retries(), 0);
        assert_eq!(UnifiedDsmError::not_found("a", "b").max_retries(), 0);
        assert_eq!(UnifiedDsmError::rate_limit("x", None).max_retries(), 1);
    }

    // ── constructors ────────────────────────────────────────────────

    #[test]
    fn new_internal_sets_defaults() {
        let e = UnifiedDsmError::new_internal("oops".into());
        assert!(!e.is_recoverable());
        assert_eq!(e.error_type(), "internal");
        assert!(e.to_string().contains("oops"));
    }

    #[test]
    fn internal_error_helper() {
        let e = internal_error();
        assert_eq!(e.to_string(), "Internal error: internal error");
    }

    #[test]
    fn validation_field_constructor() {
        let e = UnifiedDsmError::validation_field("too short", "password");
        let msg = e.to_string();
        assert!(msg.contains("password"), "got: {msg}");
        assert!(msg.contains("too short"), "got: {msg}");
    }

    // ── to_error_response ───────────────────────────────────────────

    #[test]
    fn error_response_rate_limit_includes_retry_after() {
        let e = UnifiedDsmError::rate_limit("quota hit", Some(60));
        let resp = e.to_error_response();
        assert_eq!(resp.error_type, "rate_limit");
        assert_eq!(resp.code, "rate_limit");
        let details = resp.details.unwrap();
        assert_eq!(details.get("retry_after_seconds").unwrap(), "60");
    }

    #[test]
    fn error_response_not_found_includes_resource() {
        let e = UnifiedDsmError::not_found("vault", "v123");
        let resp = e.to_error_response();
        let details = resp.details.unwrap();
        assert_eq!(details.get("resource_type").unwrap(), "vault");
        assert_eq!(details.get("resource_id").unwrap(), "v123");
    }

    #[test]
    fn error_response_validation_with_field() {
        let e = UnifiedDsmError::validation_field("bad", "email");
        let resp = e.to_error_response();
        let details = resp.details.unwrap();
        assert_eq!(details.get("field").unwrap(), "email");
    }

    #[test]
    fn error_response_generic_has_no_details() {
        let e = UnifiedDsmError::authentication("nope");
        let resp = e.to_error_response();
        assert!(resp.details.is_none());
        assert!(resp.request_id.is_none());
        assert!(resp.debug_b32.is_empty());
    }

    // ── Error trait source ──────────────────────────────────────────

    #[test]
    fn source_returns_inner_when_present() {
        let inner = std::io::Error::other("disk");
        let e = UnifiedDsmError::Storage {
            context: "write".into(),
            component: None,
            source: Some(Box::new(inner)),
            recoverable: false,
        };
        assert!(e.source().is_some());
    }

    #[test]
    fn source_returns_none_for_simple_variants() {
        assert!(UnifiedDsmError::not_found("x", "y").source().is_none());
        assert!(UnifiedDsmError::authentication("x").source().is_none());
        assert!(UnifiedDsmError::authorization("x").source().is_none());
        assert!(UnifiedDsmError::rate_limit("x", None).source().is_none());
        assert!(UnifiedDsmError::validation("x").source().is_none());
    }

    // ── From<io::Error> ─────────────────────────────────────────────

    #[test]
    fn from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe");
        let e: UnifiedDsmError = io_err.into();
        assert_eq!(e.error_type(), "storage");
        assert!(e.is_recoverable());
    }
}
