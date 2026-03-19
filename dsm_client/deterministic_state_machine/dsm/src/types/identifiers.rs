//! Newtype wrappers for type-safe identifiers
//!
//! This module provides compile-time guarantees that identifiers cannot be mixed up.
//! Each identifier type has its own distinct type, preventing accidental misuse.
//!
//! Constraints (project-wide, enforced here):
//! - No hex/json/base64/serde encodings for binary identifiers.
//! - No wall-clock time usage anywhere.
//! - All IDs are binary internally. Base32 Crockford at display boundaries only.
//! - GenesisHash is binary, not textual. We expose bytes-only APIs.

use std::fmt;

/// Base32 Crockford encoding for display boundaries only.
/// Alphabet: 0-9 A-H J-K M-N P-T V-Z (excludes I, L, O, U).
fn encode_crockford(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut out = String::new();
    let mut buffer: u16 = 0;
    let mut bits_left: u8 = 0;
    for &b in bytes {
        buffer = (buffer << 8) | b as u16;
        bits_left += 8;
        while bits_left >= 5 {
            let idx = ((buffer >> (bits_left - 5)) & 0b1_1111) as usize;
            out.push(ALPHABET[idx] as char);
            bits_left -= 5;
        }
    }
    if bits_left > 0 {
        let idx = ((buffer << (5 - bits_left)) & 0b1_1111) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out
}

// ---------------------------------------------------------------------------
// Macro to reduce boilerplate for the four routing/logging ID types.
// All share: Vec<u8> inner, new() from string, from_bytes(), as_bytes(),
// generate(), Display with prefix, AsRef<[u8]>, From<_> for Vec<u8>.
// ---------------------------------------------------------------------------

macro_rules! define_id_type {
    (
        $(#[$meta:meta])*
        $name:ident, $prefix:literal
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(Vec<u8>);

        impl $name {
            /// Create from a string label (converts to UTF-8 bytes internally).
            pub fn new(label: impl Into<String>) -> Self {
                Self(label.into().into_bytes())
            }

            /// Create from raw bytes.
            pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
                Self(bytes.into())
            }

            /// Access the raw inner bytes.
            #[inline]
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            /// Generate a fresh ID (deterministic, process-local).
            /// 8 bytes from monotonic counter (LE) + 8 bytes from RNG.
            pub fn generate() -> Self {
                let counter = crate::performance::mono_commit_height();
                let mut bytes = Vec::with_capacity(16);
                bytes.extend_from_slice(&counter.to_le_bytes());
                bytes.extend_from_slice(&crate::crypto::rng::random_bytes(8));
                Self(bytes)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}_{}", $prefix, encode_crockford(&self.0))
            }
        }

        impl From<$name> for Vec<u8> {
            fn from(id: $name) -> Vec<u8> {
                id.0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
    };
}

define_id_type!(
    /// Vault identifier - uniquely identifies a vault.
    /// Binary internally; Display renders `vault_{base32}`.
    VaultId, "vault"
);

define_id_type!(
    /// Session identifier - uniquely identifies a session.
    /// Binary internally; Display renders `session_{base32}`.
    SessionId, "session"
);

define_id_type!(
    /// Node identifier - uniquely identifies a storage node.
    /// Binary internally; Display renders `node_{base32}`.
    NodeId, "node"
);

define_id_type!(
    /// Transaction identifier - uniquely identifies a transaction.
    /// Binary internally; Display renders `tx_{base32}`.
    TransactionId, "tx"
);

/// Genesis hash identifier - uniquely identifies a genesis state (BINARY, not text)
///
/// Binary-only, no hex/json/base64. This prevents accidental textual transport
/// and keeps hashing canonical. Provide bytes-based APIs only.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GenesisHash([u8; 32]);

impl GenesisHash {
    /// Create from a fixed 32-byte array
    pub fn new(bytes32: [u8; 32]) -> Self {
        Self(bytes32)
    }

    /// Create from bytes; requires exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GenesisHashError> {
        if bytes.len() != 32 {
            return Err(GenesisHashError::Length(bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Access the inner bytes
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Borrow as a plain slice
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Consume into the inner array
    pub fn into_inner(self) -> [u8; 32] {
        self.0
    }
}

/// Minimal error type for GenesisHash construction without serde/hex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisHashError {
    Length(usize),
}

impl fmt::Display for GenesisHashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GenesisHashError::Length(len) => {
                write!(f, "GenesisHash requires 32 bytes, got {}", len)
            }
        }
    }
}

impl From<[u8; 32]> for GenesisHash {
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl From<GenesisHash> for [u8; 32] {
    fn from(h: GenesisHash) -> Self {
        h.0
    }
}

impl AsRef<[u8]> for GenesisHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for GenesisHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "genesis_hash[32 bytes]")
    }
}

/// Entropy type - represents cryptographic entropy (binary)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entropy(Vec<u8>);

impl Entropy {
    /// Create new entropy from bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the entropy bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Generate random entropy (no wall clock; RNG only)
    pub fn generate() -> Self {
        let bytes = crate::crypto::rng::random_bytes(32);
        Self(bytes)
    }

    /// Get length of entropy
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if entropy is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for Entropy {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<Entropy> for Vec<u8> {
    fn from(entropy: Entropy) -> Vec<u8> {
        entropy.0
    }
}

impl AsRef<[u8]> for Entropy {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Entropy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Entropy({} bytes)", self.0.len())
    }
}

/// Signature type - represents cryptographic signatures (binary)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(Vec<u8>);

impl Signature {
    /// Create new signature from bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the signature bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get length of signature
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if signature is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for Signature {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<Signature> for Vec<u8> {
    fn from(sig: Signature) -> Vec<u8> {
        sig.0
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({} bytes)", self.0.len())
    }
}
