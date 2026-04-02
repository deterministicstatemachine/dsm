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

#[cfg(test)]
mod tests {
    use super::*;

    // --- encode_crockford ---

    #[test]
    fn crockford_empty_input() {
        assert_eq!(encode_crockford(&[]), "");
    }

    #[test]
    fn crockford_single_byte() {
        let result = encode_crockford(&[0xFF]);
        assert!(!result.is_empty());
        for c in result.chars() {
            assert!("0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(c));
        }
    }

    #[test]
    fn crockford_deterministic() {
        let data = b"hello";
        assert_eq!(encode_crockford(data), encode_crockford(data));
    }

    // --- Macro-generated ID types (VaultId, SessionId, NodeId, TransactionId) ---

    #[test]
    fn vault_id_new_from_string() {
        let id = VaultId::new("my-vault");
        assert_eq!(id.as_bytes(), b"my-vault");
    }

    #[test]
    fn vault_id_from_bytes() {
        let id = VaultId::from_bytes(vec![1, 2, 3]);
        assert_eq!(id.as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn vault_id_display_has_prefix() {
        let id = VaultId::new("test");
        let display = format!("{id}");
        assert!(display.starts_with("vault_"));
    }

    #[test]
    fn vault_id_into_vec() {
        let id = VaultId::new("abc");
        let bytes: Vec<u8> = id.into();
        assert_eq!(bytes, b"abc");
    }

    #[test]
    fn vault_id_as_ref() {
        let id = VaultId::new("ref");
        let slice: &[u8] = id.as_ref();
        assert_eq!(slice, b"ref");
    }

    #[test]
    fn session_id_display_prefix() {
        let id = SessionId::new("s1");
        assert!(format!("{id}").starts_with("session_"));
    }

    #[test]
    fn node_id_display_prefix() {
        let id = NodeId::new("n1");
        assert!(format!("{id}").starts_with("node_"));
    }

    #[test]
    fn transaction_id_display_prefix() {
        let id = TransactionId::new("t1");
        assert!(format!("{id}").starts_with("tx_"));
    }

    #[test]
    fn id_type_equality() {
        let a = VaultId::new("same");
        let b = VaultId::new("same");
        assert_eq!(a, b);
    }

    #[test]
    fn id_type_inequality() {
        let a = VaultId::new("one");
        let b = VaultId::new("two");
        assert_ne!(a, b);
    }

    #[test]
    fn id_type_clone() {
        let a = NodeId::new("cloned");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn id_type_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(VaultId::new("x"));
        set.insert(VaultId::new("x"));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn id_generate_is_unique() {
        let a = VaultId::generate();
        let b = VaultId::generate();
        assert_ne!(a, b);
    }

    // --- GenesisHash ---

    #[test]
    fn genesis_hash_new_and_accessors() {
        let bytes = [0xAB; 32];
        let gh = GenesisHash::new(bytes);
        assert_eq!(gh.as_bytes(), &bytes);
        assert_eq!(gh.as_slice(), &bytes[..]);
    }

    #[test]
    fn genesis_hash_from_bytes_valid() {
        let bytes = vec![0x42u8; 32];
        let gh = GenesisHash::from_bytes(&bytes).unwrap();
        assert_eq!(gh.as_bytes(), &[0x42; 32]);
    }

    #[test]
    fn genesis_hash_from_bytes_too_short() {
        let err = GenesisHash::from_bytes(&[0u8; 16]).unwrap_err();
        assert_eq!(err, GenesisHashError::Length(16));
    }

    #[test]
    fn genesis_hash_from_bytes_too_long() {
        let err = GenesisHash::from_bytes(&[0u8; 64]).unwrap_err();
        assert_eq!(err, GenesisHashError::Length(64));
    }

    #[test]
    fn genesis_hash_from_bytes_empty() {
        let err = GenesisHash::from_bytes(&[]).unwrap_err();
        assert_eq!(err, GenesisHashError::Length(0));
    }

    #[test]
    fn genesis_hash_into_inner() {
        let bytes = [0xCD; 32];
        let gh = GenesisHash::new(bytes);
        assert_eq!(gh.into_inner(), bytes);
    }

    #[test]
    fn genesis_hash_from_array() {
        let arr = [0xEF; 32];
        let gh: GenesisHash = arr.into();
        assert_eq!(gh.as_bytes(), &arr);
    }

    #[test]
    fn genesis_hash_into_array() {
        let gh = GenesisHash::new([0x11; 32]);
        let arr: [u8; 32] = gh.into();
        assert_eq!(arr, [0x11; 32]);
    }

    #[test]
    fn genesis_hash_display() {
        let gh = GenesisHash::new([0; 32]);
        assert_eq!(format!("{gh}"), "genesis_hash[32 bytes]");
    }

    #[test]
    fn genesis_hash_error_display() {
        let err = GenesisHashError::Length(5);
        let msg = format!("{err}");
        assert!(msg.contains("32 bytes"));
        assert!(msg.contains("5"));
    }

    // --- Entropy ---

    #[test]
    fn entropy_new_and_accessors() {
        let e = Entropy::new(vec![1, 2, 3, 4]);
        assert_eq!(e.as_bytes(), &[1, 2, 3, 4]);
        assert_eq!(e.len(), 4);
        assert!(!e.is_empty());
    }

    #[test]
    fn entropy_empty() {
        let e = Entropy::new(vec![]);
        assert!(e.is_empty());
        assert_eq!(e.len(), 0);
    }

    #[test]
    fn entropy_from_vec() {
        let e: Entropy = vec![10, 20].into();
        assert_eq!(e.as_bytes(), &[10, 20]);
    }

    #[test]
    fn entropy_into_vec() {
        let e = Entropy::new(vec![5, 6, 7]);
        let v: Vec<u8> = e.into();
        assert_eq!(v, vec![5, 6, 7]);
    }

    #[test]
    fn entropy_display() {
        let e = Entropy::new(vec![0; 32]);
        assert_eq!(format!("{e}"), "Entropy(32 bytes)");
    }

    #[test]
    fn entropy_generate_is_32_bytes() {
        let e = Entropy::generate();
        assert_eq!(e.len(), 32);
    }

    // --- Signature ---

    #[test]
    fn signature_new_and_accessors() {
        let s = Signature::new(vec![0xAA; 64]);
        assert_eq!(s.as_bytes().len(), 64);
        assert_eq!(s.len(), 64);
        assert!(!s.is_empty());
    }

    #[test]
    fn signature_empty() {
        let s = Signature::new(vec![]);
        assert!(s.is_empty());
    }

    #[test]
    fn signature_from_vec() {
        let s: Signature = vec![1, 2, 3].into();
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn signature_into_vec() {
        let s = Signature::new(vec![10, 20]);
        let v: Vec<u8> = s.into();
        assert_eq!(v, vec![10, 20]);
    }

    #[test]
    fn signature_display() {
        let s = Signature::new(vec![0; 128]);
        assert_eq!(format!("{s}"), "Signature(128 bytes)");
    }

    #[test]
    fn signature_as_ref() {
        let s = Signature::new(vec![9, 8, 7]);
        let slice: &[u8] = s.as_ref();
        assert_eq!(slice, &[9, 8, 7]);
    }
}
