//! Comprehensive error types for DSM protocol operations.
//!
//! The primary error type is [`DsmError`], which covers all failure modes across
//! the protocol stack: cryptographic failures, state machine violations, storage
//! errors, network issues, and protocol-level rejections.
//!
//! [`DeterministicSafetyClass`] categorizes Tripwire fork-exclusion rejections
//! that are deterministic and canonical across all participants.

use std::{error::Error, fmt::Display};
use super::crypto_error::CryptoError;

/// Deterministic safety classification for Tripwire fork-exclusion rejections.
///
/// These classifications are stable and canonical — all honest participants
/// will arrive at the same classification for a given state transition attempt.
/// They represent protocol-level rejections that prevent fork attacks.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum DeterministicSafetyClass {
    /// The parent state has already been consumed by another successor.
    /// This is the core Tripwire invariant: no two valid successors from the same tip.
    ParentConsumed,
    /// A precommitment has become stale (superseded by a newer chain tip).
    StalePrecommit,
    /// The expected chain tip does not match the actual current tip.
    TipMismatch,
}

impl DeterministicSafetyClass {
    pub const fn as_str(&self) -> &'static str {
        match self {
            DeterministicSafetyClass::ParentConsumed => "ParentConsumed",
            DeterministicSafetyClass::StalePrecommit => "StalePrecommit",
            DeterministicSafetyClass::TipMismatch => "TipMismatch",
        }
    }
}

/// Specific error types for Bitcoin operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BitcoinErrorType {
    /// Invalid Bitcoin address format.
    InvalidAddress,
    /// Insufficient Bitcoin balance for operation.
    InsufficientBalance,
    /// Bitcoin transaction failed to broadcast.
    BroadcastFailure,
    /// Bitcoin transaction confirmation timeout.
    ConfirmationTimeout,
    /// Invalid transaction format or structure.
    InvalidTransaction,
    /// Bitcoin network connection error.
    NetworkError,
    /// Bitcoin script validation failure.
    ScriptValidationError,
    /// Fee estimation failure.
    FeeEstimationError,
    /// UTXO selection failure.
    UtxoSelectionError,
    /// Transaction size exceeds limits.
    TransactionTooLarge,
    /// Invalid signature on Bitcoin transaction.
    InvalidSignature,
    /// Bitcoin block not found.
    BlockNotFound,
    /// Transaction not found in blockchain.
    TransactionNotFound,
    /// Insufficient confirmations for operation.
    InsufficientConfirmations,
    /// Bitcoin amount is below dust threshold.
    DustAmount,
    /// Invalid Bitcoin network (mainnet/testnet mismatch).
    InvalidNetwork,
}

/// Specific error types for HTLC operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HtlcErrorType {
    /// HTLC hash lock mismatch.
    HashLockMismatch,
    /// HTLC timelock expired.
    TimelockExpired,
    /// HTLC preimage invalid.
    InvalidPreimage,
    /// HTLC script construction failure.
    ScriptConstructionError,
    /// HTLC refund condition not met.
    RefundConditionNotMet,
    /// HTLC claim condition not met.
    ClaimConditionNotMet,
    /// HTLC already claimed.
    AlreadyClaimed,
    /// HTLC already refunded.
    AlreadyRefunded,
    /// HTLC amount mismatch.
    AmountMismatch,
}

/// Specific error types for storage node operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageNodeErrorType {
    /// Storage node capacity exceeded.
    CapacityExceeded,
    /// Object not found in storage.
    ObjectNotFound,
    /// Invalid object address or identifier.
    InvalidObjectAddress,
    /// Storage node replication failure.
    ReplicationFailure,
    /// Storage node consensus failure.
    ConsensusFailure,
    /// Invalid partition or slot assignment.
    InvalidPartition,
    /// Storage node authentication failure.
    AuthenticationFailure,
    /// Rate limit exceeded.
    RateLimitExceeded,
    /// Storage node maintenance mode.
    MaintenanceMode,
    /// Invalid request format.
    InvalidRequestFormat,
}

/// Specific error types for vault operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultErrorType {
    /// Vault not found.
    VaultNotFound,
    /// Vault already exists.
    VaultAlreadyExists,
    /// Invalid vault state for operation.
    InvalidVaultState,
    /// Vault fulfillment condition not met.
    FulfillmentConditionNotMet,
    /// Vault timeout exceeded.
    TimeoutExceeded,
    /// Invalid vault content.
    InvalidContent,
    /// Vault encryption/decryption failure.
    EncryptionError,
    /// Vault signature verification failure.
    SignatureVerificationError,
    /// Vault capacity exceeded.
    CapacityExceeded,
}

/// Specific error types for replication operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplicationErrorType {
    /// Replication partner unavailable.
    PartnerUnavailable,
    /// Replication data inconsistency.
    DataInconsistency,
    /// Replication timeout.
    Timeout,
    /// Replication authentication failure.
    AuthenticationFailure,
    /// Replication network error.
    NetworkError,
    /// Replication configuration error.
    ConfigurationError,
    /// Replication queue full.
    QueueFull,
}

/// Types of resources that can hit capacity limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceType {
    /// Storage space in bytes.
    StorageSpace,
    /// Number of objects.
    ObjectCount,
    /// Network bandwidth.
    Bandwidth,
    /// CPU processing time.
    CpuTime,
    /// Memory usage.
    Memory,
    /// Database connections.
    DatabaseConnections,
}

/// Specific error types for consensus operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusErrorType {
    /// Consensus timeout.
    Timeout,
    /// Insufficient consensus participants.
    InsufficientParticipants,
    /// Consensus conflict detected.
    Conflict,
    /// Consensus validation failure.
    ValidationFailure,
    /// Consensus state divergence.
    StateDivergence,
    /// Consensus protocol violation.
    ProtocolViolation,
}

impl BitcoinErrorType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            BitcoinErrorType::InvalidAddress => "InvalidAddress",
            BitcoinErrorType::InsufficientBalance => "InsufficientBalance",
            BitcoinErrorType::BroadcastFailure => "BroadcastFailure",
            BitcoinErrorType::ConfirmationTimeout => "ConfirmationTimeout",
            BitcoinErrorType::InvalidTransaction => "InvalidTransaction",
            BitcoinErrorType::NetworkError => "NetworkError",
            BitcoinErrorType::ScriptValidationError => "ScriptValidationError",
            BitcoinErrorType::FeeEstimationError => "FeeEstimationError",
            BitcoinErrorType::UtxoSelectionError => "UtxoSelectionError",
            BitcoinErrorType::TransactionTooLarge => "TransactionTooLarge",
            BitcoinErrorType::InvalidSignature => "InvalidSignature",
            BitcoinErrorType::BlockNotFound => "BlockNotFound",
            BitcoinErrorType::TransactionNotFound => "TransactionNotFound",
            BitcoinErrorType::InsufficientConfirmations => "InsufficientConfirmations",
            BitcoinErrorType::DustAmount => "DustAmount",
            BitcoinErrorType::InvalidNetwork => "InvalidNetwork",
        }
    }
}

impl HtlcErrorType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            HtlcErrorType::HashLockMismatch => "HashLockMismatch",
            HtlcErrorType::TimelockExpired => "TimelockExpired",
            HtlcErrorType::InvalidPreimage => "InvalidPreimage",
            HtlcErrorType::ScriptConstructionError => "ScriptConstructionError",
            HtlcErrorType::RefundConditionNotMet => "RefundConditionNotMet",
            HtlcErrorType::ClaimConditionNotMet => "ClaimConditionNotMet",
            HtlcErrorType::AlreadyClaimed => "AlreadyClaimed",
            HtlcErrorType::AlreadyRefunded => "AlreadyRefunded",
            HtlcErrorType::AmountMismatch => "AmountMismatch",
        }
    }
}

impl StorageNodeErrorType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            StorageNodeErrorType::CapacityExceeded => "CapacityExceeded",
            StorageNodeErrorType::ObjectNotFound => "ObjectNotFound",
            StorageNodeErrorType::InvalidObjectAddress => "InvalidObjectAddress",
            StorageNodeErrorType::ReplicationFailure => "ReplicationFailure",
            StorageNodeErrorType::ConsensusFailure => "ConsensusFailure",
            StorageNodeErrorType::InvalidPartition => "InvalidPartition",
            StorageNodeErrorType::AuthenticationFailure => "AuthenticationFailure",
            StorageNodeErrorType::RateLimitExceeded => "RateLimitExceeded",
            StorageNodeErrorType::MaintenanceMode => "MaintenanceMode",
            StorageNodeErrorType::InvalidRequestFormat => "InvalidRequestFormat",
        }
    }
}

impl VaultErrorType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            VaultErrorType::VaultNotFound => "VaultNotFound",
            VaultErrorType::VaultAlreadyExists => "VaultAlreadyExists",
            VaultErrorType::InvalidVaultState => "InvalidVaultState",
            VaultErrorType::FulfillmentConditionNotMet => "FulfillmentConditionNotMet",
            VaultErrorType::TimeoutExceeded => "TimeoutExceeded",
            VaultErrorType::InvalidContent => "InvalidContent",
            VaultErrorType::EncryptionError => "EncryptionError",
            VaultErrorType::SignatureVerificationError => "SignatureVerificationError",
            VaultErrorType::CapacityExceeded => "CapacityExceeded",
        }
    }
}

impl ReplicationErrorType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            ReplicationErrorType::PartnerUnavailable => "PartnerUnavailable",
            ReplicationErrorType::DataInconsistency => "DataInconsistency",
            ReplicationErrorType::Timeout => "Timeout",
            ReplicationErrorType::AuthenticationFailure => "AuthenticationFailure",
            ReplicationErrorType::NetworkError => "NetworkError",
            ReplicationErrorType::ConfigurationError => "ConfigurationError",
            ReplicationErrorType::QueueFull => "QueueFull",
        }
    }
}

impl ResourceType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            ResourceType::StorageSpace => "StorageSpace",
            ResourceType::ObjectCount => "ObjectCount",
            ResourceType::Bandwidth => "Bandwidth",
            ResourceType::CpuTime => "CpuTime",
            ResourceType::Memory => "Memory",
            ResourceType::DatabaseConnections => "DatabaseConnections",
        }
    }
}

impl ConsensusErrorType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            ConsensusErrorType::Timeout => "Timeout",
            ConsensusErrorType::InsufficientParticipants => "InsufficientParticipants",
            ConsensusErrorType::Conflict => "Conflict",
            ConsensusErrorType::ValidationFailure => "ValidationFailure",
            ConsensusErrorType::StateDivergence => "StateDivergence",
            ConsensusErrorType::ProtocolViolation => "ProtocolViolation",
        }
    }
}

/// Comprehensive error type for DSM operations
#[derive(Debug)]
pub enum DsmError {
    /// Deterministic safety rejection (Tripwire): parent already consumed or stale precommit.
    DeterministicSafety {
        classification: DeterministicSafetyClass,
        message: String,
    },
    /// Protobuf serialization or deserialization failure.
    Serialization {
        /// What operation was being performed.
        context: String,
        /// Underlying serialization error, if any.
        source: Option<Box<dyn Error + Send + Sync>>,
        /// The entity type being serialized (e.g., "Envelope", "State").
        entity: String,
        /// Additional diagnostic details.
        details: Option<String>,
    },
    /// Internal logic error that should not occur under normal operation.
    Internal {
        /// Description of the internal failure.
        context: String,
        /// Underlying cause, if available.
        source: Option<String>,
    },
    /// BLE (Bluetooth Low Energy) transport error.
    Bluetooth(String),
    /// The current state is invalid for the requested operation.
    InvalidState(String),
    /// A function argument failed validation.
    InvalidArgument(String),
    /// The entity being created already exists (e.g., duplicate contact, token).
    AlreadyExists(String),
    /// An operation exceeded its allowed duration.
    Timeout(String),
    /// Standard I/O error wrapper.
    Io(std::io::Error),
    /// Uncategorized error with a descriptive message.
    Other(String),
    /// Failed to acquire a mutex or RwLock (poisoned or contended).
    LockError,
    /// Generic error with optional chained source.
    Generic {
        /// Error description.
        message: String,
        /// Underlying cause, if any.
        source: Option<Box<dyn Error + Send + Sync>>,
    },
    /// Persistent storage read/write failure.
    Storage {
        /// Description of the storage operation that failed.
        context: String,
        /// Underlying storage error, if any.
        source: Option<Box<dyn Error + Send + Sync>>,
    },
    /// Network communication failure (storage node, relay).
    Network {
        /// Description of the network operation that failed.
        context: String,
        /// Underlying network error, if any.
        source: Option<Box<dyn Error + Send + Sync>>,
        /// The network entity involved (e.g., storage node ID).
        entity: String,
        /// Additional diagnostic details.
        details: Option<String>,
    },
    /// State machine transition or validation failure.
    StateMachine(String),
    /// A required entity was not found in storage or state.
    NotFound {
        /// Type of entity that was not found (e.g., "Token", "Contact").
        entity: String,
        /// Additional lookup details (e.g., the ID searched for).
        details: Option<String>,
        /// Context of the lookup operation.
        context: String,
        /// Underlying cause, if any.
        source: Option<Box<dyn Error + Send + Sync>>,
    },
    /// Input validation failure (malformed data, constraint violation).
    Validation {
        /// Description of what validation failed.
        context: String,
        /// Underlying cause, if available.
        source: Option<String>,
    },
    /// Security policy violation (unauthorized access, tampered data).
    Security {
        /// Description of the security violation.
        context: String,
        /// Detailed explanation of the violation.
        details: String,
    },
    /// Chain height divergence detected between local and remote state.
    ClockDrift {
        /// Description of the drift condition.
        message: String,
        /// Local hash chain height.
        local_height: u64,
        /// Remote hash chain height.
        remote_height: u64,
    },
    /// A function parameter is out of range or malformed.
    InvalidParameter(String),
    /// Cryptographic or state verification failure.
    Verification(String),
    /// State construction or access error.
    State(String),
    /// Sparse Merkle Tree proof generation or verification failure.
    Merkle(String),
    /// Hash chain integrity violation (broken link, missing parent).
    HashChain(String),
    /// Bilateral transaction protocol error.
    Transaction(String),
    /// Pre-commitment phase failure in bilateral protocol.
    PreCommitment(String),
    /// Genesis state creation or validation failure.
    Genesis(String),
    /// Device hierarchy (Device Tree) operation failure.
    DeviceHierarchy(String),
    /// Forward commitment validation or processing failure.
    ForwardCommitment(String),
    /// Bilateral relationship management error.
    Relationship(String),
    /// External commitment (cross-chain or DLV) error.
    ExternalCommitment(String),
    /// Identity anchor or claim operation failure.
    Identity(String),
    /// Batch processing error (state batch, proof batch).
    Batch(String),
    /// Inter-node or inter-device communication failure.
    Communication {
        /// Description of the communication failure.
        context: String,
        /// Underlying cause, if any.
        source: Option<Box<dyn Error + Send + Sync>>,
    },
    /// A required subsystem has not been initialized yet.
    NotInitialized {
        /// Description of what is not initialized.
        context: String,
        /// Underlying cause, if any.
        source: Option<Box<dyn Error + Send + Sync>>,
    },
    /// Transport layer error (BLE framing, envelope encoding).
    Transport {
        /// Description of the transport failure.
        context: String,
        /// Underlying cause, if any.
        source: Option<Box<dyn Error + Send + Sync>>,
    },
    /// External blockchain interaction error (dBTC tap).
    Blockchain {
        /// Description of the blockchain operation that failed.
        context: String,
        /// Underlying cause, if any.
        source: Option<Box<dyn Error + Send + Sync>>,
    },
    /// dBTC tap safety violation (policy-enforced, §12).
    /// These are hard rejections — the operation cannot proceed because it
    /// would create an unredeemable vault or violate a protocol invariant.
    BitcoinTapSafety {
        /// Which safety invariant was violated (e.g., "dust_floor", "successor_depth",
        /// "timeout_ordering", "vault_floor").
        invariant: String,
        /// Human-readable explanation.
        message: String,
    },
    /// Configuration loading or validation error.
    Configuration {
        /// Description of the configuration issue.
        context: String,
        /// Underlying cause, if any.
        source: Option<Box<dyn Error + Send + Sync>>,
    },
    /// Async runtime error (tokio, task spawn failure).
    Runtime {
        /// Description of the runtime failure.
        context: String,
        /// Underlying cause, if any.
        source: Option<Box<dyn Error + Send + Sync>>,
    },
    /// Token balance is too low for the requested transfer.
    InsufficientBalance {
        /// The token type that has insufficient balance.
        token_id: String,
        /// Current available balance.
        available: u64,
        /// Amount that was requested.
        requested: u64,
    },
    /// The requested operation is not valid in the current context.
    InvalidOperation(String),
    /// Token subsystem error (creation, transfer, policy).
    TokenError {
        /// Description of the token operation that failed.
        context: String,
        /// Underlying cause, if any.
        source: Option<Box<dyn Error + Send + Sync>>,
    },
    /// A token policy (CPTA) was violated during a state transition.
    PolicyViolation {
        /// The token whose policy was violated.
        token_id: String,
        /// Description of the policy violation.
        message: String,
        /// Underlying cause, if any.
        source: Option<Box<dyn Error + Send + Sync>>,
    },
    /// The caller lacks authorization for the requested operation.
    Unauthorized {
        /// Description of the unauthorized action.
        context: String,
        /// Underlying cause, if any.
        source: Option<Box<dyn Error + Send + Sync>>,
    },
    /// Timing-related error (used only for non-authoritative operational purposes).
    TimeError(String),
    /// A required feature is not available (not compiled in or not supported).
    FeatureNotAvailable {
        /// Name of the unavailable feature.
        feature: String,
        /// Additional context about why it is unavailable.
        context: Option<String>,
    },
    /// Data integrity check failure (hash mismatch, corrupted data).
    Integrity {
        /// Description of the integrity violation.
        context: String,
        /// Underlying cause, if any.
        source: Option<Box<dyn Error + Send + Sync>>,
    },
    /// A contact was not found in the contact manager.
    ContactNotFound(String),
    /// A bilateral relationship was not found.
    RelationshipNotFound(String),
    /// Contact data is malformed or fails validation.
    InvalidContact(String),
    /// A pending request (pairing, transfer) was not found.
    RequestNotFound(String),
    /// Legacy serialization error (prefer [`DsmError::Serialization`] for new code).
    SerializationError(String),
    /// SPHINCS+ signature verification failed.
    InvalidSignature,
    /// The requested functionality has not been implemented.
    NotImplemented(String),
    /// SPHINCS+ or ML-KEM public key is malformed or the wrong length.
    InvalidPublicKey,
    /// SPHINCS+ secret key is malformed or the wrong length.
    InvalidSecretKey,
    /// A cryptographic key has an incorrect length.
    InvalidKeyLength,
    /// ML-KEM ciphertext decapsulation failed.
    InvalidCiphertext,
    /// An index is out of bounds for the target collection.
    InvalidIndex,
    /// A token reference is invalid or points to a non-existent token.
    InvalidToken {
        /// The token ID that is invalid.
        token_id: String,
        /// Additional context about why it is invalid.
        context: Option<String>,
    },
    /// Cryptographic primitive error (BLAKE3, SPHINCS+, ML-KEM, Pedersen).
    Crypto(CryptoError),
    /// OS-level system error (file permissions, resource limits).
    SystemError(String),
    /// Token minting is not allowed on this network configuration.
    MintNotAllowed,
    /// Token burning is not allowed on this network configuration.
    BurnNotAllowed,
    /// The faucet has been administratively disabled.
    FaucetDisabled,
    /// The faucet is not available on this network (e.g., mainnet).
    FaucetNotAvailable,
    /// Inbox token is invalid and cannot be re-registered (genesis-bound).
    InboxTokenInvalid(String),
    /// Bitcoin-specific errors for deposits, withdrawals, and HTLC operations.
    BitcoinDeposit {
        /// Description of the deposit operation that failed.
        context: String,
        /// The specific Bitcoin error type.
        error_type: BitcoinErrorType,
        /// Underlying cause, if any.
        source: Option<Box<dyn Error + Send + Sync>>,
    },
    /// Bitcoin withdrawal operation errors.
    BitcoinWithdrawal {
        /// Description of the withdrawal operation that failed.
        context: String,
        /// The specific Bitcoin error type.
        error_type: BitcoinErrorType,
        /// Underlying cause, if any.
        source: Option<Box<dyn Error + Send + Sync>>,
    },
    /// HTLC (Hash Time Locked Contract) operation errors.
    HtlcError {
        /// Description of the HTLC operation that failed.
        context: String,
        /// The specific HTLC error type.
        error_type: HtlcErrorType,
        /// Underlying cause, if any.
        source: Option<Box<dyn Error + Send + Sync>>,
    },
    /// Storage node operation errors.
    StorageNode {
        /// Description of the storage node operation that failed.
        context: String,
        /// The specific storage node error type.
        error_type: StorageNodeErrorType,
        /// Underlying cause, if any.
        source: Option<Box<dyn Error + Send + Sync>>,
    },
    /// Vault operation errors specific to DLV (Deterministic Limbo Vaults).
    VaultOperation {
        /// Description of the vault operation that failed.
        context: String,
        /// The specific vault error type.
        error_type: VaultErrorType,
        /// Underlying cause, if any.
        source: Option<Box<dyn Error + Send + Sync>>,
    },
    /// Replication and consensus errors for storage nodes.
    Replication {
        /// Description of the replication operation that failed.
        context: String,
        /// The specific replication error type.
        error_type: ReplicationErrorType,
        /// Underlying cause, if any.
        source: Option<Box<dyn Error + Send + Sync>>,
    },
    /// Capacity and resource limit errors.
    CapacityLimit {
        /// Description of the capacity limit that was exceeded.
        context: String,
        /// The type of resource that hit its limit.
        resource_type: ResourceType,
        /// Current usage level.
        current_usage: u64,
        /// Maximum allowed usage.
        limit: u64,
    },
    /// Consensus and validation errors for storage node operations.
    Consensus {
        /// Description of the consensus operation that failed.
        context: String,
        /// The specific consensus error type.
        error_type: ConsensusErrorType,
        /// Additional diagnostic information.
        details: Option<String>,
    },
}

impl DsmError {
    /// Creates a new crypto error
    ///
    /// # Arguments
    /// * `context` - Descriptive context for the error
    /// * `source` - Optional source error that caused this error
    pub fn crypto<E>(context: impl Into<String>, source: Option<E>) -> Self
    where
        E: std::fmt::Display,
    {
        DsmError::Crypto(CryptoError {
            context: context.into(),
            operation: "crypto_op".to_string(),
            source: source.map(|e| e.to_string()),
        })
    }

    /// Creates a new crypto error with operation
    pub fn crypto_op<E>(
        operation: impl Into<String>,
        context: impl Into<String>,
        source: Option<E>,
    ) -> Self
    where
        E: std::fmt::Display,
    {
        DsmError::Crypto(CryptoError {
            context: context.into(),
            operation: operation.into(),
            source: source.map(|e| e.to_string()),
        })
    }

    /// Creates a new storage error
    pub fn storage<E>(context: impl Into<String>, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::Storage {
            context: context.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new network error
    ///
    /// # Arguments
    /// * `context` - Descriptive context for the error
    /// * `source` - Optional source error that caused this error
    pub fn network<E>(context: impl Into<String>, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::Network {
            context: context.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
            entity: String::new(),
            details: None,
        }
    }

    /// Creates a new state machine error
    ///
    /// # Arguments
    /// * `message` - Error message
    pub fn state_machine(message: impl Into<String>) -> Self {
        DsmError::StateMachine(message.into())
    }

    /// Creates a new "not found" error
    ///
    /// # Arguments
    pub fn not_found(entity: impl Into<String>, details: Option<impl Into<String>>) -> Self {
        DsmError::NotFound {
            entity: entity.into(),
            details: details.map(|d| d.into()),
            context: String::from("Entity not found"),
            source: None,
        }
    }

    /// Creates a not found error specifically for tokens
    ///
    /// # Arguments
    /// * `token_id` - The ID of the token that wasn't found
    pub fn token_not_found(token_id: String) -> Self {
        Self::not_found("Token", Some(token_id))
    }

    /// Creates a new internal error
    ///
    /// # Arguments
    /// * `context` - Descriptive context for the error
    /// * `source` - Optional source error that caused this error
    pub fn internal<E>(context: impl Into<String>, source: Option<E>) -> Self
    where
        E: std::fmt::Display,
    {
        DsmError::Internal {
            context: context.into(),
            source: source.map(|e| e.to_string()),
        }
    }

    // ...existing code...
    ///
    /// # Arguments
    /// * `message` - Description of the invalid parameter
    pub fn invalid_parameter(message: impl Into<String>) -> Self {
        DsmError::InvalidParameter(message.into())
    }

    // ...existing code...

    /// Creates a new verification error
    ///
    /// # Arguments
    /// * `message` - Description of the verification error
    pub fn verification(message: impl Into<String>) -> Self {
        DsmError::Verification(message.into())
    }

    /// Creates a new state error
    ///
    /// # Arguments
    /// * `message` - Description of the state error
    pub fn state(message: impl Into<String>) -> Self {
        DsmError::State(message.into())
    }

    /// Creates a new Merkle tree error
    ///
    /// # Arguments
    /// * `message` - Description of the Merkle error
    pub fn merkle(message: impl Into<String>) -> Self {
        DsmError::Merkle(message.into())
    }

    /// Creates a new hash chain error
    ///
    /// # Arguments
    /// * `message` - Description of the hash chain error
    pub fn hash_chain(message: impl Into<String>) -> Self {
        DsmError::HashChain(message.into())
    }

    /// Creates a new transaction error
    ///
    /// # Arguments
    /// * `message` - Description of the transaction error
    pub fn transaction(message: impl Into<String>) -> Self {
        DsmError::Transaction(message.into())
    }

    /// Creates a new pre-commitment error
    ///
    /// # Arguments
    /// * `message` - Description of the pre-commitment error
    pub fn pre_commitment(message: impl Into<String>) -> Self {
        DsmError::PreCommitment(message.into())
    }

    /// Creates a new genesis error
    ///
    /// # Arguments
    /// * `message` - Description of the genesis error
    pub fn genesis(message: impl Into<String>) -> Self {
        DsmError::Genesis(message.into())
    }

    /// Creates a new device hierarchy error
    ///
    /// # Arguments
    /// * `message` - Description of the device hierarchy error
    pub fn device_hierarchy(message: impl Into<String>) -> Self {
        DsmError::DeviceHierarchy(message.into())
    }

    /// Creates a new forward commitment error
    ///
    /// # Arguments
    /// * `message` - Description of the forward commitment error
    pub fn forward_commitment(message: impl Into<String>) -> Self {
        DsmError::ForwardCommitment(message.into())
    }

    /// Creates a new relationship error
    ///
    /// # Arguments
    /// * `message` - Description of the relationship error
    pub fn relationship(message: impl Into<String>) -> Self {
        DsmError::Relationship(message.into())
    }

    /// Creates a new parsing error
    ///
    /// # Arguments
    /// * `context` - Descriptive context for the error
    /// * `source` - Optional source error that caused this error
    pub fn parsing<E>(context: impl Into<String>, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::Validation {
            context: format!("Parsing error: {}", context.into()),
            source: source.map(|e| e.to_string()),
        }
    }

    /// Creates a new external commitment error
    ///
    /// # Arguments
    /// * `message` - Description of the external commitment error
    pub fn external_commitment(message: impl Into<String>) -> Self {
        DsmError::ExternalCommitment(message.into())
    }

    /// Creates a new identity error
    ///
    /// # Arguments
    /// * `message` - Description of the identity error
    pub fn identity(message: impl Into<String>) -> Self {
        DsmError::Identity(message.into())
    }

    /// Creates a new communication error
    ///
    /// # Arguments
    /// * `context` - Descriptive context for the error
    /// * `source` - Optional source error that caused this error
    pub fn communication<E>(context: impl Into<String>, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::Communication {
            context: context.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new not initialized error
    ///
    /// # Arguments
    /// * `context` - Descriptive context for what was not initialized
    /// * `source` - Optional source error that caused this error
    pub fn not_initialized<E>(context: impl Into<String>, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::NotInitialized {
            context: context.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new transport error
    ///
    /// # Arguments
    /// * `context` - Descriptive context for the transport error
    /// * `source` - Optional source error that caused this error
    pub fn transport<E>(context: impl Into<String>, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::Transport {
            context: context.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new blockchain error
    ///
    /// # Arguments
    /// * `context` - Descriptive context for the blockchain error
    /// * `source` - Optional source error that caused this error
    pub fn blockchain<E>(context: impl Into<String>, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::Blockchain {
            context: context.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new configuration error
    ///
    /// # Arguments
    /// * `context` - Descriptive context for the configuration error
    /// * `source` - Optional source error that caused this error
    pub fn config<E>(context: impl Into<String>, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::Configuration {
            context: context.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new configuration error with just a message
    ///
    /// # Arguments
    /// * `message` - Error message
    pub fn config_simple(message: impl Into<String>) -> Self {
        DsmError::Configuration {
            context: message.into(),
            source: None,
        }
    }

    /// Creates a new generic error
    ///
    /// # Arguments
    /// * `message` - Error message
    /// * `source` - Optional source error that caused this error
    pub fn generic<E>(message: impl Into<String>, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::Generic {
            message: message.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new lock error
    pub fn lock_error() -> Self {
        DsmError::LockError
    }

    /// Creates a new timeout error
    ///
    /// # Arguments
    /// * `message` - Description of the timeout error
    pub fn timeout(message: impl Into<String>) -> Self {
        DsmError::TimeError(message.into())
    }

    /// Creates a new runtime error
    ///
    /// # Arguments
    /// * `context` - Descriptive context for the runtime error
    /// * `source` - Optional source error that caused this error
    pub fn runtime<E>(context: impl Into<String>, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::Runtime {
            context: context.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new insufficient balance error
    ///
    /// # Arguments
    /// * `token_id` - Token ID that has insufficient balance
    /// * `available` - Current available balance
    /// * `requested` - Attempted transaction amount
    pub fn insufficient_balance(
        token_id: impl Into<String>,
        available: u64,
        requested: u64,
    ) -> Self {
        DsmError::InsufficientBalance {
            token_id: token_id.into(),
            available,
            requested,
        }
    }

    /// Creates a new serialization error
    ///
    /// # Arguments
    /// * `context` - Descriptive context for the error
    /// * `entity` - Entity being serialized
    /// * `details` - Optional additional details
    /// * `source` - Optional source error
    pub fn serialization_error<E>(
        context: impl Into<String>,
        entity: impl Into<String>,
        details: Option<impl Into<String>>,
        source: Option<E>,
    ) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::Serialization {
            context: context.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
            entity: entity.into(),
            details: details.map(|d| d.into()),
        }
    }

    /// Creates a new invalid operation error
    ///
    /// # Arguments
    /// * `message` - Description of the invalid operation
    pub fn invalid_operation(message: impl Into<String>) -> Self {
        DsmError::InvalidOperation(message.into())
    }

    /// Creates a deterministic safety rejection (Tripwire / stale precommit)
    pub fn deterministic_safety(
        classification: DeterministicSafetyClass,
        message: impl Into<String>,
    ) -> Self {
        DsmError::DeterministicSafety {
            classification,
            message: message.into(),
        }
    }

    /// Creates a new token error
    ///
    /// # Arguments
    /// * `context` - Descriptive context for the token error
    /// * `source` - Optional source error that caused this error
    pub fn token_error<E>(context: impl Into<String>, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::TokenError {
            context: context.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new policy violation error
    ///
    /// # Arguments
    /// * `token_id` - Token ID that has the policy violation
    /// * `message` - Description of the policy violation
    /// * `source` - Optional source error that caused this error
    pub fn policy_violation<E>(
        token_id: impl Into<String>,
        message: impl Into<String>,
        source: Option<E>,
    ) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::PolicyViolation {
            token_id: token_id.into(),
            message: message.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new unauthorized error
    ///
    /// # Arguments
    /// * `context` - Description of what was unauthorized
    /// * `source` - Optional source error
    pub fn unauthorized<E>(context: impl Into<String>, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::Unauthorized {
            context: context.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new Bitcoin deposit error
    ///
    /// # Arguments
    /// * `context` - Descriptive context for the deposit error
    /// * `error_type` - Specific type of Bitcoin error
    /// * `source` - Optional source error that caused this error
    pub fn bitcoin_deposit<E>(
        context: impl Into<String>,
        error_type: BitcoinErrorType,
        source: Option<E>,
    ) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::BitcoinDeposit {
            context: context.into(),
            error_type,
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new Bitcoin withdrawal error
    ///
    /// # Arguments
    /// * `context` - Descriptive context for the withdrawal error
    /// * `error_type` - Specific type of Bitcoin error
    /// * `source` - Optional source error that caused this error
    pub fn bitcoin_withdrawal<E>(
        context: impl Into<String>,
        error_type: BitcoinErrorType,
        source: Option<E>,
    ) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::BitcoinWithdrawal {
            context: context.into(),
            error_type,
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new HTLC error
    ///
    /// # Arguments
    /// * `context` - Descriptive context for the HTLC error
    /// * `error_type` - Specific type of HTLC error
    /// * `source` - Optional source error that caused this error
    pub fn htlc_error<E>(
        context: impl Into<String>,
        error_type: HtlcErrorType,
        source: Option<E>,
    ) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::HtlcError {
            context: context.into(),
            error_type,
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new storage node error
    ///
    /// # Arguments
    /// * `context` - Descriptive context for the storage node error
    /// * `error_type` - Specific type of storage node error
    /// * `source` - Optional source error that caused this error
    pub fn storage_node<E>(
        context: impl Into<String>,
        error_type: StorageNodeErrorType,
        source: Option<E>,
    ) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::StorageNode {
            context: context.into(),
            error_type,
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new vault operation error
    ///
    /// # Arguments
    /// * `context` - Descriptive context for the vault operation error
    /// * `error_type` - Specific type of vault error
    /// * `source` - Optional source error that caused this error
    pub fn vault_operation<E>(
        context: impl Into<String>,
        error_type: VaultErrorType,
        source: Option<E>,
    ) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::VaultOperation {
            context: context.into(),
            error_type,
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new replication error
    ///
    /// # Arguments
    /// * `context` - Descriptive context for the replication error
    /// * `error_type` - Specific type of replication error
    /// * `source` - Optional source error that caused this error
    pub fn replication<E>(
        context: impl Into<String>,
        error_type: ReplicationErrorType,
        source: Option<E>,
    ) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::Replication {
            context: context.into(),
            error_type,
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new capacity limit error
    ///
    /// # Arguments
    /// * `context` - Descriptive context for the capacity limit error
    /// * `resource_type` - Type of resource that hit its limit
    /// * `current_usage` - Current usage level
    /// * `limit` - Maximum allowed usage
    pub fn capacity_limit(
        context: impl Into<String>,
        resource_type: ResourceType,
        current_usage: u64,
        limit: u64,
    ) -> Self {
        DsmError::CapacityLimit {
            context: context.into(),
            resource_type,
            current_usage,
            limit,
        }
    }

    /// Creates a new consensus error
    ///
    /// # Arguments
    /// * `context` - Descriptive context for the consensus error
    /// * `error_type` - Specific type of consensus error
    /// * `details` - Optional additional diagnostic details
    pub fn consensus(
        context: impl Into<String>,
        error_type: ConsensusErrorType,
        details: Option<impl Into<String>>,
    ) -> Self {
        DsmError::Consensus {
            context: context.into(),
            error_type,
            details: details.map(|d| d.into()),
        }
    }

    /// Determines if an error represents a recoverable condition
    ///
    /// # Returns
    /// * `true` if the error might be recoverable with retry
    /// * `false` if the error represents a permanent failure
    pub fn is_recoverable(&self) -> bool {
        match self {
            DsmError::Serialization { .. } => false,
            DsmError::State(_) => false,
            DsmError::Generic { .. } => false,
            DsmError::Bluetooth(_) => false,
            DsmError::InvalidOperation(_) => false,
            DsmError::DeterministicSafety { .. } => false,
            // ...existing arms...
            DsmError::Network { .. } => true,
            DsmError::Storage { .. } => true,
            DsmError::Transport { .. } => true,
            DsmError::Communication { .. } => true,
            DsmError::Timeout(_) => true,
            DsmError::Runtime { .. } => true,
            DsmError::LockError => true,
            DsmError::NotInitialized { .. } => true,
            DsmError::Blockchain { .. } => true,
            _ => false,
        }
    }
}

impl Display for DsmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DsmError::Serialization {
                context,
                source,
                entity,
                details,
            } => {
                write!(f, "Serialization error [{entity}]: {context}")?;
                if let Some(d) = details {
                    write!(f, " - details: {d}")?;
                }
                if let Some(s) = source {
                    write!(f, " - caused by: {s}")?;
                }
                Ok(())
            }
            DsmError::DeterministicSafety {
                classification,
                message,
            } => write!(
                f,
                "Deterministic safety rejection [{}]: {message}",
                classification.as_str()
            ),
            DsmError::InboxTokenInvalid(msg) => write!(f, "Inbox token invalid: {msg}"),
            DsmError::Internal { context, source } => {
                write!(f, "Internal error: {context}")?;
                if let Some(s) = source {
                    write!(f, " - caused by: {s}")?;
                }
                Ok(())
            }
            DsmError::Bluetooth(msg) => write!(f, "Bluetooth error: {msg}"),
            DsmError::InvalidState(msg) => write!(f, "Invalid state: {msg}"),
            DsmError::InvalidArgument(msg) => write!(f, "Invalid argument: {msg}"),
            DsmError::AlreadyExists(msg) => write!(f, "Already exists: {msg}"),
            DsmError::Timeout(msg) => write!(f, "Timeout error: {msg}"),
            DsmError::Io(err) => write!(f, "I/O error: {err}"),
            DsmError::Other(msg) => write!(f, "Other error: {msg}"),
            DsmError::LockError => write!(f, "Failed to acquire lock"),
            DsmError::Generic { message, source } => {
                write!(f, "Generic error: {message}")?;
                if let Some(s) = source {
                    write!(f, " - caused by: {s}")?;
                }
                Ok(())
            }
            DsmError::Storage { context, source } => {
                write!(f, "Storage error: {context}")?;
                if let Some(s) = source {
                    write!(f, " - caused by: {s}")?;
                }
                Ok(())
            }
            DsmError::Network {
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
            DsmError::StateMachine(msg) => write!(f, "State machine error: {msg}"),
            DsmError::NotFound {
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
            DsmError::Validation { context, source } => {
                write!(f, "Validation error: {context}")?;
                if let Some(s) = source {
                    write!(f, " - caused by: {s}")?;
                }
                Ok(())
            }
            DsmError::Security { context, details } => {
                write!(f, "Security error: {context} - {details}")
            }
            DsmError::InvalidParameter(msg) => write!(f, "Invalid parameter: {msg}"),
            DsmError::Verification(msg) => write!(f, "Verification error: {msg}"),
            DsmError::State(msg) => write!(f, "State error: {msg}"),
            DsmError::Merkle(msg) => write!(f, "Merkle tree error: {msg}"),
            DsmError::HashChain(msg) => write!(f, "Hash chain error: {msg}"),
            DsmError::Transaction(msg) => write!(f, "Transaction error: {msg}"),
            DsmError::PreCommitment(msg) => write!(f, "Pre-commitment error: {msg}"),
            DsmError::Genesis(msg) => write!(f, "Genesis error: {msg}"),
            DsmError::DeviceHierarchy(msg) => write!(f, "Device hierarchy error: {msg}"),
            DsmError::ForwardCommitment(msg) => write!(f, "Forward commitment error: {msg}"),
            DsmError::Relationship(msg) => write!(f, "Relationship error: {msg}"),
            DsmError::ExternalCommitment(msg) => write!(f, "External commitment error: {msg}"),
            DsmError::Identity(msg) => write!(f, "Identity error: {msg}"),
            DsmError::Batch(msg) => write!(f, "Batch error: {msg}"),
            DsmError::Communication { context, source } => {
                write!(f, "Communication error: {context}")?;
                if let Some(s) = source {
                    write!(f, " - caused by: {s}")?;
                }
                Ok(())
            }
            DsmError::NotInitialized { context, source } => {
                write!(f, "Not initialized: {context}")?;
                if let Some(s) = source {
                    write!(f, " - caused by: {s}")?;
                }
                Ok(())
            }
            DsmError::Transport { context, source } => {
                write!(f, "Transport error: {context}")?;
                if let Some(s) = source {
                    write!(f, " - caused by: {s}")?;
                }
                Ok(())
            }
            DsmError::Blockchain { context, source } => {
                write!(f, "Blockchain error: {context}")?;
                if let Some(s) = source {
                    write!(f, " - caused by: {s}")?;
                }
                Ok(())
            }
            DsmError::BitcoinTapSafety { invariant, message } => {
                write!(f, "Bitcoin tap safety violation [{invariant}]: {message}")
            }
            DsmError::Configuration { context, source } => {
                write!(f, "Configuration error: {context}")?;
                if let Some(s) = source {
                    write!(f, " - caused by: {s}")?;
                }
                Ok(())
            }
            DsmError::Runtime { context, source } => {
                write!(f, "Runtime error: {context}")?;
                if let Some(s) = source {
                    write!(f, " - caused by: {s}")?;
                }
                Ok(())
            }
            DsmError::InsufficientBalance {
                token_id,
                available,
                requested,
            } => {
                write!(
                    f,
                    "Insufficient balance for token {token_id}: available {available}, requested {requested}"
                )
            }
            DsmError::InvalidOperation(msg) => write!(f, "Invalid operation: {msg}"),
            DsmError::TokenError { context, source } => {
                write!(f, "Token error: {context}")?;
                if let Some(s) = source {
                    write!(f, " - caused by: {s}")?;
                }
                Ok(())
            }
            DsmError::PolicyViolation {
                token_id,
                message,
                source,
            } => {
                write!(f, "Token policy violation for {token_id}: {message}")?;
                if let Some(s) = source {
                    write!(f, " - caused by: {s}")?;
                }
                Ok(())
            }
            DsmError::Unauthorized { context, source } => {
                write!(f, "Unauthorized access: {context}")?;
                if let Some(s) = source {
                    write!(f, " - caused by: {s}")?;
                }
                Ok(())
            }
            DsmError::TimeError(msg) => write!(f, "Time error: {msg}"),
            DsmError::FeatureNotAvailable { feature, context } => {
                write!(f, "Feature not available: {feature}")?;
                if let Some(ctx) = context {
                    write!(f, " - context: {ctx}")?;
                }
                Ok(())
            }
            DsmError::Integrity { context, source } => {
                write!(f, "Integrity error: {context}")?;
                if let Some(s) = source {
                    write!(f, " - caused by: {s}")?;
                }
                Ok(())
            }
            DsmError::ContactNotFound(msg) => write!(f, "Contact not found: {msg}"),
            DsmError::RelationshipNotFound(msg) => write!(f, "Relationship not found: {msg}"),
            DsmError::InvalidContact(msg) => write!(f, "Invalid contact: {msg}"),
            DsmError::RequestNotFound(msg) => write!(f, "Request not found: {msg}"),
            DsmError::SerializationError(msg) => write!(f, "Serialization error: {msg}"),
            DsmError::InvalidSignature => write!(f, "Invalid signature"),
            DsmError::NotImplemented(msg) => write!(f, "Not implemented: {msg}"),
            DsmError::InvalidPublicKey => write!(f, "Invalid public key"),
            DsmError::InvalidSecretKey => write!(f, "Invalid secret key"),
            DsmError::InvalidKeyLength => write!(f, "Invalid key length"),
            DsmError::InvalidCiphertext => write!(f, "Invalid ciphertext"),
            DsmError::InvalidIndex => write!(f, "Invalid or out-of-bounds index"),
            DsmError::InvalidToken { token_id, context } => {
                write!(f, "Invalid token: {token_id}")?;
                if let Some(ctx) = context {
                    write!(f, " - context: {ctx}")?;
                }
                Ok(())
            }
            DsmError::Crypto(error) => {
                write!(f, "Cryptographic error: {}", error.context)?;
                if let Some(s) = &error.source {
                    write!(f, " - caused by: {s}")?;
                }
                Ok(())
            }
            DsmError::SystemError(msg) => write!(f, "System error: {msg}"),
            DsmError::MintNotAllowed => write!(f, "Minting not allowed on this network"),
            DsmError::BurnNotAllowed => write!(f, "Burning not allowed on this network"),
            DsmError::FaucetDisabled => write!(f, "Faucet is currently disabled"),
            DsmError::FaucetNotAvailable => write!(f, "Faucet is not available on this network"),
            DsmError::ClockDrift {
                message,
                local_height,
                remote_height,
            } => {
                write!(
                    f,
                    "Clock drift detected: local_height={}, remote_height={}, {}",
                    local_height, remote_height, message
                )
            }
            DsmError::BitcoinDeposit {
                context,
                error_type,
                source,
            } => {
                write!(
                    f,
                    "Bitcoin deposit error [{}]: {context}",
                    error_type.as_str()
                )?;
                if let Some(s) = source {
                    write!(f, " - caused by: {s}")?;
                }
                Ok(())
            }
            DsmError::BitcoinWithdrawal {
                context,
                error_type,
                source,
            } => {
                write!(
                    f,
                    "Bitcoin withdrawal error [{}]: {context}",
                    error_type.as_str()
                )?;
                if let Some(s) = source {
                    write!(f, " - caused by: {s}")?;
                }
                Ok(())
            }
            DsmError::HtlcError {
                context,
                error_type,
                source,
            } => {
                write!(f, "HTLC error [{}]: {context}", error_type.as_str())?;
                if let Some(s) = source {
                    write!(f, " - caused by: {s}")?;
                }
                Ok(())
            }
            DsmError::StorageNode {
                context,
                error_type,
                source,
            } => {
                write!(f, "Storage node error [{}]: {context}", error_type.as_str())?;
                if let Some(s) = source {
                    write!(f, " - caused by: {s}")?;
                }
                Ok(())
            }
            DsmError::VaultOperation {
                context,
                error_type,
                source,
            } => {
                write!(
                    f,
                    "Vault operation error [{}]: {context}",
                    error_type.as_str()
                )?;
                if let Some(s) = source {
                    write!(f, " - caused by: {s}")?;
                }
                Ok(())
            }
            DsmError::Replication {
                context,
                error_type,
                source,
            } => {
                write!(f, "Replication error [{}]: {context}", error_type.as_str())?;
                if let Some(s) = source {
                    write!(f, " - caused by: {s}")?;
                }
                Ok(())
            }
            DsmError::CapacityLimit {
                context,
                resource_type,
                current_usage,
                limit,
            } => {
                write!(
                    f,
                    "Capacity limit exceeded [{}]: {context} - current: {}, limit: {}",
                    resource_type.as_str(),
                    current_usage,
                    limit
                )
            }
            DsmError::Consensus {
                context,
                error_type,
                details,
            } => {
                write!(f, "Consensus error [{}]: {context}", error_type.as_str())?;
                if let Some(d) = details {
                    write!(f, " - details: {d}")?;
                }
                Ok(())
            }
        }
    }
}

impl Error for DsmError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            DsmError::Timeout(_) => None,
            DsmError::Io(_) => None,
            DsmError::Other(_) => None,
            DsmError::InvalidToken { .. } => None,
            DsmError::Runtime { source: None, .. } => None,
            DsmError::Bluetooth(_) => None,
            DsmError::InvalidOperation(_) => None,
            DsmError::DeterministicSafety { .. } => None,
            DsmError::Generic { source: None, .. } => None,
            DsmError::Serialization { source, .. } => {
                source.as_ref().map(|s| s.as_ref() as &dyn Error)
            }
            DsmError::State(_) => None,
            DsmError::Generic { source, .. } => source.as_ref().map(|s| s.as_ref() as &dyn Error),
            // ...existing arms...
            DsmError::Crypto(_) => None,
            DsmError::Storage { source, .. } => source.as_ref().map(|s| s.as_ref() as &dyn Error),
            DsmError::Network { source, .. } => source.as_ref().map(|s| s.as_ref() as &dyn Error),
            DsmError::Internal { .. } => None,
            DsmError::Validation { .. } => None,

            DsmError::LockError => None,
            DsmError::StateMachine(_) => None,
            DsmError::NotFound { .. } => None,
            DsmError::InvalidParameter(_) => None,
            DsmError::Verification(_) => None,
            DsmError::Merkle(_) => None,
            DsmError::HashChain(_) => None,
            DsmError::Transaction(_) => None,
            DsmError::PreCommitment(_) => None,
            DsmError::Genesis(_) => None,
            DsmError::DeviceHierarchy(_) => None,
            DsmError::ForwardCommitment(_) => None,
            DsmError::Relationship(_) => None,
            DsmError::ExternalCommitment(_) => None,
            DsmError::Identity(_) => None,
            DsmError::Batch(_) => None,
            DsmError::Communication { source, .. } => {
                source.as_ref().map(|s| s.as_ref() as &dyn Error)
            }
            DsmError::NotInitialized { source, .. } => {
                source.as_ref().map(|s| s.as_ref() as &dyn Error)
            }
            DsmError::Transport { source, .. } => source.as_ref().map(|s| s.as_ref() as &dyn Error),
            DsmError::Blockchain { source, .. } => {
                source.as_ref().map(|s| s.as_ref() as &dyn Error)
            }
            DsmError::BitcoinTapSafety { .. } => None,
            DsmError::Configuration { source, .. } => {
                source.as_ref().map(|s| s.as_ref() as &dyn Error)
            }
            DsmError::Runtime { source, .. } => source.as_ref().map(|s| s.as_ref() as &dyn Error),
            DsmError::InsufficientBalance { .. } => None,
            DsmError::TokenError { source, .. } => {
                source.as_ref().map(|s| s.as_ref() as &dyn Error)
            }
            DsmError::PolicyViolation { source, .. } => {
                source.as_ref().map(|s| s.as_ref() as &dyn Error)
            }
            DsmError::Unauthorized { source, .. } => {
                source.as_ref().map(|s| s.as_ref() as &dyn Error)
            }
            DsmError::TimeError(_) => None,
            DsmError::FeatureNotAvailable { .. } => None,
            DsmError::Integrity { source, .. } => source.as_ref().map(|s| s.as_ref() as &dyn Error),
            DsmError::ContactNotFound(_) => None,
            DsmError::RelationshipNotFound(_) => None,
            DsmError::InvalidContact(_) => None,
            DsmError::RequestNotFound(_) => None,
            DsmError::SerializationError(_) => None,
            DsmError::InvalidSignature => None,
            DsmError::NotImplemented(_) => None,
            DsmError::InvalidPublicKey => None,
            DsmError::InvalidSecretKey => None,
            DsmError::InvalidKeyLength => None,
            DsmError::InvalidCiphertext => None,
            DsmError::InvalidIndex => None,
            DsmError::InboxTokenInvalid(_) => None,
            DsmError::InvalidArgument(_) => None,
            DsmError::AlreadyExists(_) => None,
            DsmError::InvalidState(_) => None,
            DsmError::SystemError(_) => None,
            DsmError::MintNotAllowed => None,
            DsmError::BurnNotAllowed => None,
            DsmError::FaucetDisabled => None,
            DsmError::FaucetNotAvailable => None,
            DsmError::ClockDrift { .. } => None,
            DsmError::Security { .. } => None,
            DsmError::BitcoinDeposit { source, .. } => {
                source.as_ref().map(|s| s.as_ref() as &dyn Error)
            }
            DsmError::BitcoinWithdrawal { source, .. } => {
                source.as_ref().map(|s| s.as_ref() as &dyn Error)
            }
            DsmError::HtlcError { source, .. } => source.as_ref().map(|s| s.as_ref() as &dyn Error),
            DsmError::StorageNode { source, .. } => {
                source.as_ref().map(|s| s.as_ref() as &dyn Error)
            }
            DsmError::VaultOperation { source, .. } => {
                source.as_ref().map(|s| s.as_ref() as &dyn Error)
            }
            DsmError::Replication { source, .. } => {
                source.as_ref().map(|s| s.as_ref() as &dyn Error)
            }
            DsmError::CapacityLimit { .. } => None,
            DsmError::Consensus { .. } => None,
        }
    }
}

// Implementation of common From traits for convenient error conversion

impl From<std::io::Error> for DsmError {
    fn from(error: std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::NotFound => {
                DsmError::not_found("Resource", Some(error.to_string()))
            }
            std::io::ErrorKind::PermissionDenied => {
                DsmError::storage("Permission denied", Some(error))
            }
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::AddrInUse
            | std::io::ErrorKind::AddrNotAvailable
            | std::io::ErrorKind::TimedOut => DsmError::network(error.to_string(), Some(error)),
            _ => DsmError::generic(format!("I/O error: {error}"), Some(error)),
        }
    }
}

impl From<std::fmt::Error> for DsmError {
    fn from(error: std::fmt::Error) -> Self {
        DsmError::generic("Formatting error", Some(error))
    }
}

impl From<std::str::Utf8Error> for DsmError {
    fn from(error: std::str::Utf8Error) -> Self {
        DsmError::SerializationError(format!("UTF-8 decoding error: {error}"))
    }
}

impl From<std::string::FromUtf8Error> for DsmError {
    fn from(error: std::string::FromUtf8Error) -> Self {
        DsmError::SerializationError(format!("UTF-8 string conversion error: {error}"))
    }
}

impl From<std::num::ParseIntError> for DsmError {
    fn from(error: std::num::ParseIntError) -> Self {
        DsmError::parsing("Integer parsing error", Some(error))
    }
}

impl From<std::num::ParseFloatError> for DsmError {
    fn from(error: std::num::ParseFloatError) -> Self {
        DsmError::Validation {
            context: "Float parsing error".to_string(),
            source: Some(error.to_string()),
        }
    }
}

impl From<std::convert::Infallible> for DsmError {
    fn from(_: std::convert::Infallible) -> Self {
        // This should never happen, but we need to handle the conversion
        DsmError::internal(
            "Infallible error occurred",
            None::<std::convert::Infallible>,
        )
    }
}

// No From<serde_json::Error> in core (JSON-free)

// Add From implementation for EnforcementError
impl From<crate::core::token::policy::policy_enforcement::EnforcementError> for DsmError {
    fn from(err: crate::core::token::policy::policy_enforcement::EnforcementError) -> Self {
        DsmError::PolicyViolation {
            token_id: "unknown".to_string(),
            message: err.to_string(),
            source: Some(Box::new(err)),
        }
    }
}

// This conversion must be implemented in the SDK crate, not in the core DSM crate.
