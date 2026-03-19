//! Token types for DSM
//!
//! This module defines the comprehensive token system for DSM, including:
//! - Native ERA token and created tokens
//! - Token balance management with atomic state integration
//! - Token registry and supply tracking
//! - Advanced token operations (transfer, mint, burn, lock)
//! - Quantum-resistant token state evolution
use std::collections::HashMap;
use std::cell::RefCell;

use crate::types::error::DsmError;
use crate::types::policy_types::{PolicyAnchor, PolicyFile};
use base32::encode;

// Thread-local storage for current state context
thread_local! {
    static CURRENT_STATE_CONTEXT: RefCell<Option<StateContext>> = const { RefCell::new(None) };
}

/// State context for proper DSM protocol compliance
#[derive(Clone, Debug)]
pub struct StateContext {
    /// Current canonical state hash as per DSM protocol
    pub state_hash: [u8; 32],
    /// State number for forward-only verification
    pub state_number: u64,
    /// Device ID for this state context
    pub device_id: [u8; 32],
}

impl StateContext {
    /// Create a new state context
    pub fn new(state_hash: [u8; 32], state_number: u64, device_id: [u8; 32]) -> Self {
        Self {
            state_hash,
            state_number,
            device_id,
        }
    }

    /// Set the current state context (thread-local)
    pub fn set_current(context: StateContext) {
        CURRENT_STATE_CONTEXT.with(|c| {
            *c.borrow_mut() = Some(context);
        });
    }

    /// Clear the current state context
    pub fn clear_current() {
        CURRENT_STATE_CONTEXT.with(|c| {
            *c.borrow_mut() = None;
        });
    }

    /// Get the current state context if available
    pub fn get_current() -> Option<StateContext> {
        CURRENT_STATE_CONTEXT.with(|c| c.borrow().clone())
    }
}

/// Token type representing the nature and properties of a token
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TokenType {
    /// Native token for the DSM system (ERA)
    Native,
    /// User-created tokens through token factory
    Created,
    /// Special-purpose tokens with restricted operations
    Restricted,
    /// Tokens that represent external assets
    Wrapped,
}

/// Token supply management parameters
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TokenSupply {
    /// Fixed supply with a specific amount
    Fixed(u64),
    /// Unlimited supply that can be minted as needed
    Unlimited,
}

/// Token supply implementation details (internal struct)
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TokenSupplyInfo {
    /// Total fixed supply
    pub total_supply: u64,
    /// Current circulating supply
    pub circulating_supply: u64,
    /// Maximum allowed supply (can be None for unlimited)
    pub max_supply: Option<u64>,
    /// Minimum allowed supply (cannot go below this value)
    pub min_supply: Option<u64>,
}

impl TokenSupply {
    /// Create a new fixed TokenSupply
    pub fn new(total_supply: u64) -> Self {
        Self::Fixed(total_supply)
    }

    /// Create a fixed supply token
    pub fn fixed(total_supply: u64) -> Self {
        Self::Fixed(total_supply)
    }

    /// Create an unlimited supply token  
    pub fn unlimited() -> Self {
        Self::Unlimited
    }

    /// Get the maximum supply if it's a fixed supply
    pub fn max_supply(&self) -> Option<u64> {
        match self {
            TokenSupply::Fixed(amount) => Some(*amount),
            TokenSupply::Unlimited => None,
        }
    }

    /// Check if this is a fixed supply
    pub fn is_fixed(&self) -> bool {
        matches!(self, TokenSupply::Fixed(_))
    }

    /// Check if this is unlimited supply
    pub fn is_unlimited(&self) -> bool {
        matches!(self, TokenSupply::Unlimited)
    }
}

impl TokenSupplyInfo {
    /// Create a new TokenSupplyInfo with fixed total supply
    pub fn new(total_supply: u64) -> Self {
        Self {
            total_supply,
            circulating_supply: total_supply,
            max_supply: Some(total_supply),
            min_supply: Some(0),
        }
    }

    /// Create a TokenSupplyInfo with flexible minting/burning parameters
    pub fn with_limits(
        total_supply: u64,
        max_supply: Option<u64>,
        min_supply: Option<u64>,
    ) -> Self {
        Self {
            total_supply,
            circulating_supply: total_supply,
            max_supply,
            min_supply,
        }
    }

    /// Check if a supply change is within allowed limits
    /// Returns true if applying the amount would keep supply within limits
    pub fn is_valid_supply_change(&self, amount: u64, is_addition: bool) -> bool {
        if is_addition {
            // For additions, ensure we don't exceed maximum
            let new_supply = self.circulating_supply.saturating_add(amount);
            if let Some(max) = self.max_supply {
                if new_supply > max {
                    return false;
                }
            }
            true
        } else {
            // For subtractions, ensure we don't go below minimum
            // If attempting to decrease by more than current supply, it's invalid
            if amount > self.circulating_supply {
                return false;
            }

            let new_supply = self.circulating_supply.saturating_sub(amount);
            if let Some(min) = self.min_supply {
                if new_supply < min {
                    return false;
                }
            }
            true
        }
    }

    /// Check if a supply change using TokenAmount is within allowed limits
    pub fn validate_supply_change(&self, amount: TokenAmount, is_mint: bool) -> bool {
        if is_mint {
            // Adding tokens - check against max_supply
            let new_supply = self.circulating_supply.saturating_add(amount.value());
            if let Some(max) = self.max_supply {
                if new_supply > max {
                    return false;
                }
            }
            true
        } else {
            // Burning tokens - check against min_supply and circulating_supply
            if amount.value() > self.circulating_supply {
                return false;
            }

            let new_supply = self.circulating_supply.saturating_sub(amount.value());
            if let Some(min) = self.min_supply {
                if new_supply < min {
                    return false;
                }
            }
            true
        }
    }
}

/// Token identity and metadata
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenMetadata {
    /// Unique identifier for this token
    pub token_id: String,
    /// Name of the token
    pub name: String,
    /// Symbol for the token (e.g., "ROOT")
    pub symbol: String,
    /// Number of decimal places for token precision
    pub decimals: u8,
    /// Token type (Native, Created, etc.)
    pub token_type: TokenType,
    /// Owner of the token (creator's identity)
    pub owner_id: [u8; 32],
    /// Creation tick
    pub creation_tick: u64,
    /// Optional URI for token metadata
    pub metadata_uri: Option<String>,
    /// Description of the token
    pub description: Option<String>,
    /// Token icon URL
    pub icon_url: Option<String>,
    /// Content-Addressed Token Policy Anchor (CTPA) hash
    pub policy_anchor: Option<String>,
    /// Additional metadata fields
    pub fields: HashMap<String, String>,
}

impl TokenMetadata {
    /// Create new token metadata
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        token_id: &str,
        name: &str,
        symbol: &str,
        decimals: u8,
        token_type: TokenType,
        owner_id: [u8; 32],
        state_number: u64,
        policy_anchor: Option<String>,
    ) -> Self {
        Self {
            token_id: token_id.to_string(),
            name: name.to_string(),
            symbol: symbol.to_string(),
            decimals,
            token_type,
            owner_id,
            creation_tick: state_number,
            metadata_uri: None,
            description: None,
            icon_url: None,
            policy_anchor,
            fields: HashMap::new(),
        }
    }

    /// Add metadata URI
    pub fn with_metadata_uri(mut self, uri: &str) -> Self {
        self.metadata_uri = Some(uri.to_string());
        self
    }

    /// Add description
    pub fn with_description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }

    /// Add icon URL
    pub fn with_icon_url(mut self, url: &str) -> Self {
        self.icon_url = Some(url.to_string());
        self
    }

    /// Add custom metadata field
    pub fn with_field(mut self, key: &str, value: &str) -> Self {
        self.fields.insert(key.to_string(), value.to_string());
        self
    }

    /// Generate canonical token identifier for balance mapping
    pub fn canonical_id(&self) -> String {
        format!(
            "{}.{}",
            encode(base32::Alphabet::Crockford, &self.owner_id),
            self.token_id
        )
    }
}

/// Specialized token amount with non-negative invariants
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TokenAmount {
    /// Non-negative token amount
    value: u64,
}

impl TokenAmount {
    /// Create a new TokenAmount with the given value
    pub fn new(value: u64) -> Self {
        Self { value }
    }

    /// Checked addition that prevents overflow
    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.value.checked_add(other.value).map(Self::new)
    }

    /// Checked subtraction that maintains non-negative invariant
    pub fn checked_sub(self, other: Self) -> Option<Self> {
        if self.value < other.value {
            return None; // Prevents negative balance
        }
        Some(Self::new(self.value - other.value))
    }

    /// Saturating addition that never overflows
    pub fn saturating_add(self, other: Self) -> Self {
        Self::new(self.value.saturating_add(other.value))
    }

    /// Saturating subtraction that never goes below zero
    pub fn saturating_sub(self, other: Self) -> Self {
        Self::new(self.value.saturating_sub(other.value))
    }

    /// Get the underlying value
    pub fn value(&self) -> u64 {
        self.value
    }
}

impl Default for TokenAmount {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Core token balance type
///
/// This implementation uses unsigned integers to represent balances,
/// enforcing non-negative value invariants in accordance with the
/// conservation of value principle described in whitepaper Section 10.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Balance {
    /// Token value
    value: u64,
    /// Locked portion of balance that cannot be spent
    locked: u64,
    /// Last update tick
    last_updated_tick: u64,
    /// Ledger state hash referencing the last update
    state_hash: Option<[u8; 32]>,
}

impl Balance {
    /// Create a zero balance for non-state-transition contexts
    ///
    /// This method is intended for use in contexts where a balance is needed
    /// for structure initialization, testing, or other purposes that don't
    /// involve actual state transitions in the DSM protocol.
    ///
    /// For actual token operations within DSM state transitions, use `from_state()`.
    pub fn zero() -> Self {
        // Always derive a deterministic canonical anchor (no WARN spam)
        let anchor = Self::get_current_canonical_state_hash()
            .unwrap_or_else(Self::derive_default_canonical_state_hash);
        Self::from_state(0, anchor, 0)
    }

    /// Get the current canonical state hash from the DSM system context
    pub fn get_current_canonical_state_hash() -> Option<[u8; 32]> {
        // For the `dsm` crate, we use a thread-local state context if available
        // This allows proper state hash linking without cross-crate dependencies

        // Try to access thread-local state context first (if implemented)
        if let Some(hash) = Self::get_thread_local_state_hash() {
            return Some(hash);
        }

        // No thread-local context: no warnings — tests and non-transition sites
        None
    }

    /// Deterministic default when no thread-local state context is present.
    /// Uses device_id from StateContext when available; otherwise a fixed domain-separated salt.
    fn derive_default_canonical_state_hash() -> [u8; 32] {
        // Prefer a device_id from the last known StateContext (without consuming it)
        let device_tag = StateContext::get_current()
            .map(|c| c.device_id.to_vec())
            .unwrap_or_else(|| {
                let mut tag = b"DSM/balance-fall".to_vec();
                tag.extend_from_slice(b"back\0");
                tag
            });

        let mut hasher = crate::crypto::blake3::dsm_domain_hasher("DSM/canonical-balance");
        hasher.update(&device_tag);
        let digest = hasher.finalize();
        *digest.as_bytes()
    }

    /// Get thread-local state hash if available
    pub fn get_thread_local_state_hash() -> Option<[u8; 32]> {
        StateContext::get_current().map(|ctx| ctx.state_hash)
    }

    /// Create a balance from a state transition.
    ///
    /// `state_number` is the deterministic tick — the hash chain height at
    /// which this balance was created.  Both devices in a bilateral exchange
    /// agree on the same state_number, so `to_le_bytes()` produces identical
    /// output and the state hash is deterministic.
    pub fn from_state(value: u64, state_hash: [u8; 32], state_number: u64) -> Self {
        Self {
            value,
            locked: 0,
            last_updated_tick: state_number,
            state_hash: Some(state_hash),
        }
    }

    /// Get the available balance (total minus locked)
    pub fn available(&self) -> u64 {
        self.value
    }

    /// Get the total balance value
    pub fn value(&self) -> u64 {
        self.value
    }

    /// Get the locked balance
    pub fn locked(&self) -> u64 {
        self.locked
    }

    /// Lock a portion of the balance
    pub fn lock(&mut self, amount: u64) -> Result<(), DsmError> {
        if amount == 0 {
            return Err(DsmError::invalid_operation("Lock amount must be positive"));
        }
        if amount > self.available() {
            return Err(DsmError::invalid_operation(
                "Insufficient available balance to lock",
            ));
        }
        self.locked = self.locked.saturating_add(amount);

        Ok(())
    }

    /// Unlock a portion of the locked balance
    pub fn unlock(&mut self, amount: u64) -> Result<(), DsmError> {
        if amount == 0 {
            return Err(DsmError::invalid_operation(
                "Unlock amount must be positive",
            ));
        }
        if amount > self.locked {
            return Err(DsmError::invalid_operation(
                "Unlock amount exceeds locked balance",
            ));
        }
        self.locked = self.locked.saturating_sub(amount);

        Ok(())
    }

    /// Update the balance with an amount and operation type
    /// This provides a type-safe interface with explicit operation semantics
    pub fn update(&mut self, amount: u64, is_addition: bool) {
        if is_addition {
            self.value = self.value.saturating_add(amount);
        } else {
            self.value = self.value.saturating_sub(amount);
        }
    }

    /// Update balance with TokenAmount and operation type
    /// This provides a safer and more semantically accurate way to update balances
    pub fn update_with_amount(
        &mut self,
        amount: TokenAmount,
        is_addition: bool,
    ) -> Result<(), DsmError> {
        if is_addition {
            self.value = self.value.saturating_add(amount.value());
        } else {
            if amount.value() > self.value {
                return Err(DsmError::invalid_operation(
                    "Insufficient balance for deduction",
                ));
            }
            self.value = self.value.saturating_sub(amount.value());
        }

        Ok(())
    }

    /// Update the balance with an unsigned delta (always an addition)
    pub fn update_add(&mut self, delta: u64) {
        self.value = self.value.saturating_add(delta);
    }

    /// Update the balance with an unsigned delta (always a subtraction)
    pub fn update_sub(&mut self, delta: u64) -> Result<(), DsmError> {
        if delta > self.value {
            return Err(DsmError::invalid_operation(
                "Insufficient balance for deduction",
            ));
        }
        self.value = self.value.saturating_sub(delta);

        Ok(())
    }

    /// Format balance with appropriate decimals
    pub fn formatted(&self, decimals: u8) -> String {
        let factor = 10u64.saturating_pow(decimals as u32) as f64;
        format!(
            "{:.precision$}",
            self.value as f64 / factor,
            precision = decimals as usize
        )
    }

    /// Set state hash reference
    pub fn with_state_hash(mut self, hash: [u8; 32]) -> Self {
        self.state_hash = Some(hash);
        self
    }

    /// Convert to little-endian bytes for hashing
    pub fn to_le_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(24); // 8 bytes for each u64, 8 for tick
        result.extend_from_slice(&self.value.to_le_bytes());
        result.extend_from_slice(&self.locked.to_le_bytes());
        result.extend_from_slice(&self.last_updated_tick.to_le_bytes());
        if let Some(hash) = &self.state_hash {
            result.extend_from_slice(hash);
        }
        result
    }

    /// Internal helper to reconstruct a Balance from raw parts (used by canonical decoders).
    pub(crate) fn from_parts(
        value: u64,
        locked: u64,
        last_updated_tick: u64,
        state_hash: Option<[u8; 32]>,
    ) -> Self {
        Self {
            value,
            locked,
            last_updated_tick,
            state_hash,
        }
    }
}

impl std::fmt::Display for Balance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

/// Token Registry for managing token metadata and supply information
#[derive(Clone, Debug, Default)]
pub struct TokenRegistry {
    /// Map of token IDs to their metadata
    pub tokens: HashMap<String, TokenMetadata>,
    /// Map of token IDs to their supply information
    pub supplies: HashMap<String, TokenSupplyInfo>,
    /// Native token ID (ERA)
    pub native_token_id: String,
}

fn default_era_policy_anchor_uri() -> String {
    let mut policy = PolicyFile::new("ERA Token Policy", "1.0.0", "system");
    policy.with_description("Default policy for the ERA token in DSM ecosystem");
    policy.add_metadata("token_type", "native");
    policy.add_metadata("governance", "meritocratic");
    policy.add_metadata("supply_model", "fixed");
    let anchor = PolicyAnchor::from_policy(&policy)
        .expect("default ERA policy file should always produce a valid policy anchor");
    format!("dsm:policy:{}", anchor.to_base32())
}

impl TokenRegistry {
    /// Create a new empty TokenRegistry
    pub fn new() -> Self {
        let native_token_id = "ERA".to_string();
        let mut tokens = HashMap::new();
        let mut supplies = HashMap::new();

        // Initialize ERA token
        let system_owner = {
            let hash = crate::crypto::blake3::domain_hash("DSM/token-hash", b"system");
            let mut arr = [0u8; 32];
            arr.copy_from_slice(hash.as_bytes());
            arr
        };
        let root_metadata = TokenMetadata::new(
            &native_token_id,
            "ERA",
            "ERA",
            18, // 18 decimals like ETH
            TokenType::Native,
            system_owner,
            0, // genesis state_number
            Some(default_era_policy_anchor_uri()),
        );

        // Initialize with a fixed supply of 80 billion tokens
        let root_supply =
            TokenSupplyInfo::new(80_000_000_000u64.saturating_mul(10u64.saturating_pow(18)));

        tokens.insert(native_token_id.clone(), root_metadata);
        supplies.insert(native_token_id.clone(), root_supply);

        Self {
            tokens,
            supplies,
            native_token_id,
        }
    }

    /// Register a new token
    pub fn register_token(
        &mut self,
        metadata: TokenMetadata,
        supply: TokenSupplyInfo,
    ) -> Result<(), DsmError> {
        let token_id = metadata.token_id.clone();

        if self.tokens.contains_key(&token_id) {
            return Err(DsmError::invalid_operation(format!(
                "Token {token_id} already exists"
            )));
        }

        // Register the token
        self.tokens.insert(token_id.clone(), metadata);
        self.supplies.insert(token_id, supply);

        Ok(())
    }

    /// Get token metadata by ID
    pub fn get_token(&self, token_id: &str) -> Option<&TokenMetadata> {
        self.tokens.get(token_id)
    }

    /// Get token supply information by ID
    pub fn get_supply(&self, token_id: &str) -> Option<&TokenSupplyInfo> {
        self.supplies.get(token_id)
    }

    /// Update token supply with unsigned amount and explicit addition/subtraction flag
    pub fn update_supply(
        &mut self,
        token_id: &str,
        amount: u64,
        is_addition: bool,
    ) -> Result<(), DsmError> {
        let supply = self
            .supplies
            .get_mut(token_id)
            .ok_or_else(|| DsmError::invalid_operation(format!("Token {token_id} not found")))?;

        if !supply.is_valid_supply_change(amount, is_addition) {
            return Err(DsmError::invalid_operation(format!(
                "Invalid supply change for token {token_id}"
            )));
        }

        // Handle supply change with explicit operation semantics
        if is_addition {
            supply.circulating_supply = supply.circulating_supply.saturating_add(amount);
        } else {
            supply.circulating_supply = supply.circulating_supply.saturating_sub(amount);
        }

        Ok(())
    }

    /// Check if a token is native (ERA)
    pub fn is_native_token(&self, token_id: &str) -> bool {
        token_id == self.native_token_id
    }

    /// Get canonical token ID combining owner ID and token ID
    pub fn canonical_token_id(&self, token_id: &str) -> Result<String, DsmError> {
        let metadata = self
            .get_token(token_id)
            .ok_or_else(|| DsmError::invalid_operation(format!("Token {token_id} not found")))?;

        Ok(metadata.canonical_id())
    }

    pub fn create_token(
        &mut self,
        params: CreateTokenParams,
        state_number: u64,
    ) -> Result<(TokenMetadata, TokenSupplyInfo), DsmError> {
        let system_owner = {
            let hash = crate::crypto::blake3::domain_hash("DSM/token-hash", b"system");
            let mut arr = [0u8; 32];
            arr.copy_from_slice(hash.as_bytes());
            arr
        };

        // Use the params to create token
        let metadata = TokenMetadata {
            name: params.name,
            symbol: params.token_id.clone(),
            description: params.description,
            icon_url: params.icon_url,
            decimals: params.decimals,
            fields: HashMap::new(),
            token_id: params.token_id.clone(),
            token_type: TokenType::Created,
            owner_id: system_owner,
            creation_tick: state_number,
            metadata_uri: params.metadata_uri,
            policy_anchor: params.policy_anchor,
        };

        let supply = TokenSupplyInfo {
            total_supply: params.initial_supply.unwrap_or(0),
            circulating_supply: params.initial_supply.unwrap_or(0),
            max_supply: params.max_supply,
            min_supply: Some(0),
        };

        self.tokens.insert(params.token_id, metadata.clone());
        self.supplies
            .insert(metadata.token_id.clone(), supply.clone());

        Ok((metadata, supply))
    }
}

pub struct CreateTokenParams {
    pub token_id: String,
    pub name: String,
    pub description: Option<String>,
    pub icon_url: Option<String>,
    pub metadata_uri: Option<String>,
    pub decimals: u8,
    pub initial_supply: Option<u64>,
    pub max_supply: Option<u64>,
    pub policy_anchor: Option<String>,
}

/// Token Factory for creating new tokens
#[derive(Clone, Debug)]
pub struct TokenFactory {
    /// Token registry
    pub registry: TokenRegistry,
    /// Fee in ERA tokens for token creation
    pub creation_fee: u64,
    /// Genesis state hash
    pub genesis_hash: Vec<u8>,
}

impl TokenFactory {
    /// Create a new TokenFactory
    pub fn new(creation_fee: u64, genesis_hash: Vec<u8>) -> Self {
        Self {
            registry: TokenRegistry::new(),
            creation_fee,
            genesis_hash,
        }
    }

    /// Get creation fee
    pub fn get_creation_fee(&self) -> u64 {
        self.creation_fee
    }

    /// Update creation fee
    pub fn set_creation_fee(&mut self, fee: u64) {
        self.creation_fee = fee;
    }
}

/// Token operation for state transitions
#[derive(Clone, Debug)]
pub enum TokenOperation {
    /// Create a new token
    Create {
        /// Token metadata
        metadata: Box<TokenMetadata>,
        /// Initial token supply
        supply: TokenSupply,
        /// Creation fee in ERA tokens
        fee: u64,
    },
    /// Transfer tokens between accounts
    Transfer {
        /// Token ID to transfer
        token_id: String,
        /// Recipient identity (32 bytes, canonical binary)
        recipient: [u8; 32],
        /// Amount to transfer
        amount: u64,
        /// Optional memo
        memo: Option<String>,
    },
    /// Mint additional tokens (if allowed by supply)
    Mint {
        /// Token ID to mint
        token_id: String,
        /// Recipient of the newly minted tokens (32 bytes, canonical binary)
        recipient: [u8; 32],
        /// Amount to mint
        amount: u64,
    },
    /// Burn (destroy) tokens
    Burn {
        /// Token ID to burn
        token_id: String,
        /// Amount to burn
        amount: u64,
    },
    /// Lock tokens for a specific purpose
    Lock {
        /// Token ID to lock
        token_id: String,
        /// Amount to lock
        amount: u64,
        /// Binary lock reason/purpose
        purpose: Vec<u8>,
    },
    /// Unlock previously locked tokens
    Unlock {
        /// Token ID to unlock
        token_id: String,
        /// Amount to unlock
        amount: u64,
        /// Binary original lock purpose
        purpose: Vec<u8>,
    },

    /// Receive tokens in a bilateral transfer
    /// This is the counterpart to Transfer in a bilateral exchange
    Receive {
        /// Token ID to receive
        token_id: String,
        /// Sender identity (32 bytes, canonical binary)
        sender: [u8; 32],
        /// Amount to receive
        amount: u64,
        /// Optional memo
        memo: Option<String>,
        /// Hash of the sender's state transition
        sender_state_hash: Option<Vec<u8>>,
    },
}

/// Token represents a complete token entity in the DSM system
#[derive(Debug, Clone)]
pub struct Token {
    /// Unique identifier for this token
    id: String,
    /// The owner's identity
    owner_id: String,
    /// Token data containing specification
    token_data: Vec<u8>,
    /// Metadata associated with this token
    metadata: Vec<u8>,
    /// Cryptographic hash of this token
    token_hash: Vec<u8>,
    /// Current token status
    status: TokenStatus,
    /// Token balance
    balance: Balance,
    /// Content-Addressed Token Policy Anchor (CTPA) hash
    policy_anchor: Option<[u8; 32]>,
}

impl Token {
    /// Create a new token with an explicit policy anchor.
    pub fn new(
        owner_id: &str,
        token_data: Vec<u8>,
        metadata: Vec<u8>,
        balance: Balance,
        policy_anchor: [u8; 32],
    ) -> Self {
        // Use first 8 bytes of blake3 hash as a numeric suffix for the token id
        let hash_bytes = crate::crypto::blake3::domain_hash("DSM/token-hash", &token_data);
        let num = u64::from_le_bytes(hash_bytes.as_bytes()[..8].try_into().unwrap_or([0u8; 8]));
        let id = format!("{}-{}", owner_id, num);
        let token_hash = crate::crypto::blake3::domain_hash(
            "DSM/token-hash",
            &[&token_data[..], &metadata[..]].concat(),
        )
        .as_bytes()
        .to_vec();

        Self {
            id,
            owner_id: owner_id.to_string(),
            token_data,
            metadata,
            token_hash,
            status: TokenStatus::Active,
            balance,
            policy_anchor: Some(policy_anchor),
        }
    }

    /// Get token ID
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get owner ID
    pub fn owner_id(&self) -> &str {
        &self.owner_id
    }

    /// Get token data
    pub fn token_data(&self) -> &[u8] {
        &self.token_data
    }

    /// Get metadata
    pub fn metadata(&self) -> &[u8] {
        &self.metadata
    }

    /// Get token hash
    pub fn token_hash(&self) -> &[u8] {
        &self.token_hash
    }

    /// Get token status
    pub fn status(&self) -> &TokenStatus {
        &self.status
    }

    /// Get balance
    pub fn balance(&self) -> &Balance {
        &self.balance
    }

    /// Set token status
    pub fn set_status(&mut self, status: TokenStatus) {
        self.status = status;
    }

    /// Set token owner
    pub fn set_owner(&mut self, owner_id: &str) {
        self.owner_id = owner_id.to_string();
    }

    /// Check if token is valid
    pub fn is_valid(&self) -> bool {
        self.status == TokenStatus::Active
    }

    /// Get policy anchor
    pub fn policy_anchor(&self) -> Option<&[u8; 32]> {
        self.policy_anchor.as_ref()
    }

    /// Set policy anchor
    pub fn set_policy_anchor(&mut self, anchor: [u8; 32]) {
        self.policy_anchor = Some(anchor);
    }

    /// Update token balance with explicit operation semantics
    pub fn update_balance(&mut self, amount: u64, is_addition: bool) {
        self.balance.update(amount, is_addition);
    }

    /// Update token balance with TokenAmount
    pub fn update_balance_with_amount(
        &mut self,
        amount: TokenAmount,
        is_addition: bool,
    ) -> Result<(), DsmError> {
        self.balance.update_with_amount(amount, is_addition)
    }
}

/// Token status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenStatus {
    /// Token is active and can be transferred
    Active,
    /// Token has been revoked and is no longer valid
    Revoked,
    /// Token has expired (expiration enforced by state progression)
    Expired,
    /// Token is temporarily locked
    Locked,
}
