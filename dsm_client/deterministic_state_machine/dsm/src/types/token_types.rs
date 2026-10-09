// SPDX-License-Identifier: MIT OR Apache-2.0

//! Token types for DSM
//!
//! This module defines the comprehensive token system for DSM, including:
//! - Native ERA token and created tokens
//! - Token balance management with atomic state integration
//! - Token registry and supply tracking
//! - Advanced token operations (transfer, mint, burn, lock)
//! - Quantum-resistant token state evolution
use std::collections::HashMap;

use crate::types::error::DsmError;
use base32::encode;

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

/// Token supply: always a fixed genesis supply. Neither supply class has an
/// unlimited option, and nothing is minted after genesis (SoFi §48, §50).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TokenSupply {
    /// The whole supply that will ever exist.
    Fixed(u64),
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

    /// Get the maximum supply if it's a fixed supply
    pub fn max_supply(&self) -> Option<u64> {
        match self {
            TokenSupply::Fixed(amount) => Some(*amount),
        }
    }

    /// Check if this is a fixed supply
    pub fn is_fixed(&self) -> bool {
        matches!(self, TokenSupply::Fixed(_))
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
        policy_anchor: Option<String>,
    ) -> Self {
        Self {
            token_id: token_id.to_string(),
            name: name.to_string(),
            symbol: symbol.to_string(),
            decimals,
            token_type,
            owner_id,
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

/// Core token balance type.
///
/// Uses unsigned integers to represent balances, enforcing non-negative value
/// invariants per whitepaper §8 eq. 10 (`B_{n+1} ≥ 0`).
///
/// Per §4.3 no counter/height/timestamp participates in canonical encoding.
/// A balance is just a scalar value plus an optional linkage hash to the
/// state that produced it (a hash, not a counter).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Balance {
    /// Token value
    value: u64,
    /// Locked portion of balance that cannot be spent
    locked: u64,
    /// Ledger state hash referencing the last update
    state_hash: Option<[u8; 32]>,
}

impl Balance {
    /// A zero amount, referencing no state.
    pub fn zero() -> Self {
        Self::amount(0)
    }

    /// An amount as an operation carries it: a value, no lock, and no
    /// reference to a state. An operation's signed bytes encode the value and
    /// the lock only ([`Balance::canonical_amount_bytes`]).
    pub fn amount(value: u64) -> Self {
        Self {
            value,
            locked: 0,
            state_hash: None,
        }
    }

    /// Create a balance bound to a specific state hash (§2.1 hash adjacency).
    /// The `state_hash` is a 32-byte digest, not a counter — it links this
    /// balance to the state that produced it.
    pub fn from_state(value: u64, state_hash: [u8; 32]) -> Self {
        Self {
            value,
            locked: 0,
            state_hash: Some(state_hash),
        }
    }

    /// Returns the full token amount.
    ///
    /// Per whitepaper §8 (balance binding), DSM uses a **single-value**
    /// balance model: token-affecting operations are enforced through
    /// atomic DSM state transitions, not by subtracting a separately
    /// tracked "locked" amount at display/accounting time. Subtracting
    /// `locked` here was a historical bug — the whitepaper explicitly
    /// fixes it by treating `Balance` as a single canonical value.
    ///
    /// **Do NOT change this to `self.value - self.locked`.** That
    /// regression has been intentionally rejected; locked-amount
    /// semantics live in higher-level vault/HTLC machinery, not in the
    /// canonical balance type.
    ///
    /// Closes Issue #188.
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

    /// The ledger state hash this balance was derived from, if it carries one.
    ///
    /// `None` means the balance was built outside a state transition (see
    /// [`Balance::zero`]) — a caller persisting a balance MUST preserve that
    /// distinction rather than substituting a zero hash, which would assert a
    /// state the balance never referenced.
    pub fn state_hash(&self) -> Option<[u8; 32]> {
        self.state_hash
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

    /// The 16 bytes an operation signs for an amount: value then lock, little
    /// endian. The state reference a held balance may carry is not part of
    /// any signed operation.
    pub fn canonical_amount_bytes(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.value.to_le_bytes());
        out[8..].copy_from_slice(&self.locked.to_le_bytes());
        out
    }

    /// Convert to little-endian bytes for hashing. Per §4.3 no counter participates.
    pub fn to_le_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(16 + 32);
        result.extend_from_slice(&self.value.to_le_bytes());
        result.extend_from_slice(&self.locked.to_le_bytes());
        if let Some(hash) = &self.state_hash {
            result.extend_from_slice(hash);
        }
        result
    }

    /// Reconstruct a Balance from its exact parts — the inverse of
    /// [`Balance::value`], [`Balance::locked`] and [`Balance::state_hash`].
    ///
    /// Used by canonical decoders, including the SDK storage codec. Unlike
    /// [`Balance::zero`], which anchors to the current canonical state, this
    /// preserves `state_hash: None` rather than substituting a hash the balance
    /// never referenced.
    pub fn from_parts(value: u64, locked: u64, state_hash: Option<[u8; 32]>) -> Self {
        Self {
            value,
            locked,
            state_hash,
        }
    }
}

impl std::fmt::Display for Balance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
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

#[cfg(test)]
mod tests {
    use super::*;

    // --- TokenAmount ---

    #[test]
    fn token_amount_new_and_value() {
        let a = TokenAmount::new(42);
        assert_eq!(a.value(), 42);
    }

    #[test]
    fn token_amount_default_is_zero() {
        let a = TokenAmount::default();
        assert_eq!(a.value(), 0);
    }

    #[test]
    fn token_amount_checked_add_normal() {
        let a = TokenAmount::new(10);
        let b = TokenAmount::new(20);
        let c = a.checked_add(b).unwrap();
        assert_eq!(c.value(), 30);
    }

    #[test]
    fn token_amount_checked_add_overflow() {
        let a = TokenAmount::new(u64::MAX);
        let b = TokenAmount::new(1);
        assert!(a.checked_add(b).is_none());
    }

    #[test]
    fn token_amount_checked_sub_normal() {
        let a = TokenAmount::new(50);
        let b = TokenAmount::new(20);
        let c = a.checked_sub(b).unwrap();
        assert_eq!(c.value(), 30);
    }

    #[test]
    fn token_amount_checked_sub_underflow() {
        let a = TokenAmount::new(5);
        let b = TokenAmount::new(10);
        assert!(a.checked_sub(b).is_none());
    }

    #[test]
    fn token_amount_saturating_add() {
        let a = TokenAmount::new(u64::MAX);
        let b = TokenAmount::new(100);
        assert_eq!(a.saturating_add(b).value(), u64::MAX);
    }

    #[test]
    fn token_amount_saturating_sub() {
        let a = TokenAmount::new(5);
        let b = TokenAmount::new(100);
        assert_eq!(a.saturating_sub(b).value(), 0);
    }

    #[test]
    fn token_amount_ordering() {
        let a = TokenAmount::new(10);
        let b = TokenAmount::new(20);
        assert!(a < b);
        assert!(b > a);
    }

    // --- TokenSupply ---

    #[test]
    fn token_supply_fixed() {
        let s = TokenSupply::fixed(1000);
        assert!(s.is_fixed());
        assert_eq!(s.max_supply(), Some(1000));
    }

    #[test]
    fn token_supply_new_is_fixed() {
        let s = TokenSupply::new(500);
        assert!(s.is_fixed());
    }

    // --- Balance ---

    #[test]
    fn balance_zero() {
        let b = Balance::zero();
        assert_eq!(b.value(), 0);
        assert_eq!(b.locked(), 0);
    }

    #[test]
    fn balance_from_state() {
        let b = Balance::from_state(1000, [0xAA; 32]);
        assert_eq!(b.value(), 1000);
        assert_eq!(b.available(), 1000);
        assert_eq!(b.locked(), 0);
    }

    #[test]
    fn balance_lock_and_unlock() {
        let mut b = Balance::amount(100);
        b.lock(30).unwrap();
        assert_eq!(b.locked(), 30);

        b.unlock(10).unwrap();
        assert_eq!(b.locked(), 20);
    }

    #[test]
    fn balance_lock_zero_fails() {
        let mut b = Balance::amount(100);
        assert!(b.lock(0).is_err());
    }

    #[test]
    fn balance_lock_exceeds_available() {
        let mut b = Balance::amount(50);
        assert!(b.lock(51).is_err());
    }

    #[test]
    fn balance_unlock_zero_fails() {
        let mut b = Balance::amount(100);
        b.lock(50).unwrap();
        assert!(b.unlock(0).is_err());
    }

    #[test]
    fn balance_unlock_exceeds_locked() {
        let mut b = Balance::amount(100);
        b.lock(30).unwrap();
        assert!(b.unlock(31).is_err());
    }

    #[test]
    fn balance_formatted() {
        let b = Balance::amount(1_500_000);
        let f = b.formatted(6);
        assert_eq!(f, "1.500000");
    }

    #[test]
    fn balance_with_state_hash() {
        let b = Balance::amount(100).with_state_hash([0xFF; 32]);
        let bytes = b.to_le_bytes();
        assert!(bytes.len() > 24);
    }

    #[test]
    fn balance_to_le_bytes_deterministic() {
        let b = Balance::from_state(42, [0xAB; 32]);
        assert_eq!(b.to_le_bytes(), b.to_le_bytes());
    }

    #[test]
    fn balance_display() {
        let b = Balance::amount(12345);
        assert_eq!(format!("{b}"), "12345");
    }

    // --- TokenMetadata ---

    #[test]
    fn token_metadata_builder_methods() {
        let meta = TokenMetadata::new(
            "TEST",
            "Test Token",
            "TST",
            8,
            TokenType::Created,
            [0; 32],
            None,
        )
        .with_description("A test token")
        .with_metadata_uri("https://example.com")
        .with_icon_url("https://example.com/icon.png")
        .with_field("website", "https://test.com");

        assert_eq!(meta.description.as_deref(), Some("A test token"));
        assert_eq!(meta.metadata_uri.as_deref(), Some("https://example.com"));
        assert_eq!(
            meta.icon_url.as_deref(),
            Some("https://example.com/icon.png")
        );
        assert_eq!(
            meta.fields.get("website").map(|s| s.as_str()),
            Some("https://test.com")
        );
    }

    #[test]
    fn token_metadata_canonical_id() {
        let meta = TokenMetadata::new("ERA", "ERA", "ERA", 18, TokenType::Native, [0xAA; 32], None);
        let cid = meta.canonical_id();
        assert!(cid.ends_with(".ERA"));
    }

    // --- Token ---
}
