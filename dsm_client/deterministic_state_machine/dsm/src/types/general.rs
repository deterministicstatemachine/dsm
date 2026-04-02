//! General-purpose shared types for the DSM protocol.
//!
//! This module contains foundational types that are used across multiple subsystems:
//!
//! - [`KeyPair`] — SPHINCS+ public/private key pair (private key redacted in Debug)
//! - [`GenericOps`] — Concrete generic operation container (distinct from the trait in [`super::operations`])
//! - [`IdToken`] — Identity token with SPHINCS+ signature verification
//! - [`DirectoryEntry`] — Decentralized directory entries for genesis state lookup
//! - [`Commitment`] — Cryptographic commitment to a future state update
//! - [`VerificationResult`] — Detailed verification outcome with hash chain path
//! - [`SecurityLevel`] — Post-quantum security parameter selection (128/192/256-bit)

use crate::crypto::sphincs::sphincs_verify;
use crate::types::error::DsmError;
use std::fmt;

/// Represents a public/private key pair
#[derive(Clone)]
pub struct KeyPair {
    /// Public key
    pub public_key: Vec<u8>,

    /// Private key - should be stored securely or in a TEE
    pub private_key: Vec<u8>,
}
impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field(
                "public_key",
                &format!("{:?}...", &self.public_key.get(0..4).unwrap_or(&[])),
            )
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

/// Concrete generic operation container with type label and raw payload.
///
/// Distinct from the [`super::operations::GenericOps`] trait; this is a simple
/// data holder for application-defined operations that do not fit the standard
/// identity or token categories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericOps {
    /// Application-defined operation type label.
    operation_type: String,
    /// Raw payload bytes for this operation.
    data: Vec<u8>,
}

impl GenericOps {
    pub fn new(operation_type: &str, data: Vec<u8>) -> Self {
        Self {
            operation_type: operation_type.to_string(),
            data,
        }
    }

    pub fn get_operation_type(&self) -> &str {
        &self.operation_type
    }

    pub fn get_data(&self) -> &[u8] {
        &self.data
    }
}
impl fmt::Display for GenericOps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Operation Type: {}, Data: {:?}",
            self.operation_type, self.data
        )
    }
}
impl Default for GenericOps {
    fn default() -> Self {
        Self {
            operation_type: "default".to_string(),
            data: vec![],
        }
    }
}

/// Identity token binding a subject to a SPHINCS+ public key.
///
/// Used for identity verification flows where a token issuer vouches for
/// a subject's public key via a cryptographic signature.
#[derive(Debug, Clone)]
pub struct IdToken {
    /// Unique identifier for this token.
    pub token_id: String,
    /// Identifier of the entity that issued this token.
    pub issuer: String,
    /// Identifier of the entity this token describes.
    pub subject: String,
    /// SPHINCS+ public key bound to this identity.
    pub public_key: Vec<u8>,
    /// SPHINCS+ signature over `(token_id || issuer || subject || public_key)`.
    pub signature: Vec<u8>,
}

/// Token operations trait for identity tokens.
///
/// Provides validity checking, expiration detection, and SPHINCS+ signature verification.
pub trait TokenOps {
    /// Check whether this token has valid, non-empty required fields.
    fn is_valid(&self) -> bool;
    /// Check whether this token has expired based on state progression (logical ticks).
    fn has_expired(&self) -> bool;
    /// Verify the token's SPHINCS+ signature against the given public key.
    fn verify_signature(&self, public_key: &[u8]) -> Result<bool, DsmError>;
}

impl TokenOps for IdToken {
    fn is_valid(&self) -> bool {
        !self.token_id.is_empty() && !self.issuer.is_empty()
    }

    fn has_expired(&self) -> bool {
        false // No expiration - tokens are valid until explicitly revoked
    }

    fn verify_signature(&self, public_key: &[u8]) -> Result<bool, DsmError> {
        // Construct message to verify
        let mut msg = Vec::new();
        msg.extend_from_slice(self.token_id.as_bytes());
        msg.extend_from_slice(self.issuer.as_bytes());
        msg.extend_from_slice(self.subject.as_bytes());
        msg.extend_from_slice(&self.public_key);

        // Verify signature
        sphincs_verify(public_key, &msg, &self.signature)
    }
}

/// Directory entry for storing Genesis states and invalidation markers
#[derive(Debug, Clone)]
pub struct DirectoryEntry {
    /// Unique identifier for the entry
    pub id: String,

    /// Genesis state hash
    pub genesis_hash: Vec<u8>,

    /// Invalidation markers, if any
    pub invalidation_markers: Vec<Vec<u8>>,
}

/// A commitment to a future state update
#[derive(Debug, Clone)]
pub struct Commitment {
    /// Hash of the commitment
    pub hash: Vec<u8>,

    /// Signature from the creator
    pub signature: Vec<u8>,

    /// Co-signature from counterparty, if available
    pub co_signature: Option<Vec<u8>>,
}

/// Verification result with details
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether verification was successful
    pub is_valid: bool,

    /// Reason for failure, if any
    pub reason: Option<String>,

    /// Additional details about verification
    pub details: Option<String>,

    /// Path of states verified (for hash-chain verification)
    pub verification_path: Vec<usize>,
}

/// Post-quantum security parameter level.
///
/// Determines the parameter sizes for SPHINCS+ signatures and ML-KEM key exchange.
/// Higher levels provide greater security margins at the cost of larger keys and signatures.
#[derive(Clone, Debug, PartialEq, Copy)]
pub enum SecurityLevel {
    /// 128-bit post-quantum security (NIST Level 1).
    Standard128,
    /// 192-bit post-quantum security (NIST Level 3).
    Medium192,
    /// 256-bit post-quantum security (NIST Level 5).
    High256,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write;

    #[test]
    fn test_keypair_debug_redacts_private_key() {
        let kp = KeyPair {
            public_key: vec![1, 2, 3, 4, 5],
            private_key: vec![6, 7, 8, 9, 10],
        };

        let mut debug_output = String::new();
        write!(debug_output, "{:?}", kp)
            .map_err(|_| DsmError::internal(0.to_string(), None::<std::convert::Infallible>))
            .unwrap();

        assert!(debug_output.contains("[1, 2, 3, 4]..."));
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("6, 7, 8, 9, 10"));
    }

    #[test]
    fn test_directory_entry() {
        let id = "entry123".to_string();
        let genesis_hash = vec![1, 2, 3];

        let entry = DirectoryEntry {
            id: id.clone(),
            genesis_hash: genesis_hash.clone(),
            invalidation_markers: Vec::new(),
        };

        assert_eq!(entry.id, id);
        assert_eq!(entry.genesis_hash, genesis_hash);
        assert!(entry.invalidation_markers.is_empty());
    }

    #[test]
    fn test_commitment_serialization() {
        let commitment = Commitment {
            hash: vec![1, 2, 3],
            signature: vec![4, 5, 6],
            co_signature: Some(vec![7, 8, 9]),
        };

        // Manual, deterministic encoding for testing roundtrip
        use crate::types::serialization::put_bytes;

        fn get_u32(off: &mut usize, data: &[u8]) -> Option<u32> {
            if *off + 4 > data.len() {
                return None;
            }
            let mut b = [0; 4];
            b.copy_from_slice(&data[*off..*off + 4]);
            *off += 4;
            Some(u32::from_le_bytes(b))
        }
        fn get_bytes(off: &mut usize, data: &[u8]) -> Option<Vec<u8>> {
            let len = get_u32(off, data)? as usize;
            if *off + len > data.len() {
                return None;
            }
            let s = data[*off..*off + len].to_vec();
            *off += len;
            Some(s)
        }

        let mut serialized = Vec::new();
        put_bytes(&mut serialized, &commitment.hash);
        put_bytes(&mut serialized, &commitment.signature);
        match &commitment.co_signature {
            Some(cs) => {
                serialized.push(1);
                put_bytes(&mut serialized, cs);
            }
            None => serialized.push(0),
        }

        let mut off = 0usize;
        let hash = get_bytes(&mut off, &serialized).unwrap();
        let signature = get_bytes(&mut off, &serialized).unwrap();
        let co_sig = match serialized.get(off) {
            Some(1) => {
                off += 1;
                Some(get_bytes(&mut off, &serialized).unwrap())
            }
            _ => None,
        };
        let deserialized = Commitment {
            hash,
            signature,
            co_signature: co_sig,
        };

        assert_eq!(deserialized.hash, commitment.hash);
        assert_eq!(deserialized.signature, commitment.signature);
        assert_eq!(deserialized.co_signature, commitment.co_signature);
    }

    #[test]
    fn test_verification_result() {
        let result = VerificationResult {
            is_valid: true,
            reason: None,
            details: Some("Test verification passed".to_string()),
            verification_path: vec![0, 1, 3, 7],
        };

        assert!(result.is_valid);
        assert!(result.reason.is_none());
        assert_eq!(
            result.details.expect("details present"),
            "Test verification passed"
        );
        assert_eq!(result.verification_path, vec![0, 1, 3, 7]);
    }

    #[test]
    fn generic_ops_new_and_accessors() {
        let op = GenericOps::new("transfer", vec![1, 2, 3]);
        assert_eq!(op.get_operation_type(), "transfer");
        assert_eq!(op.get_data(), &[1, 2, 3]);
    }

    #[test]
    fn generic_ops_default() {
        let op = GenericOps::default();
        assert_eq!(op.get_operation_type(), "default");
        assert!(op.get_data().is_empty());
    }

    #[test]
    fn generic_ops_display() {
        let op = GenericOps::new("mint", vec![0xAB]);
        let display = format!("{}", op);
        assert!(display.contains("mint"));
        assert!(display.contains("171")); // 0xAB = 171
    }

    #[test]
    fn generic_ops_equality() {
        let a = GenericOps::new("op", vec![1]);
        let b = GenericOps::new("op", vec![1]);
        let c = GenericOps::new("op", vec![2]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn id_token_is_valid_with_all_fields() {
        let token = IdToken {
            token_id: "t1".to_string(),
            issuer: "iss".to_string(),
            subject: "sub".to_string(),
            public_key: vec![1, 2, 3],
            signature: vec![4, 5, 6],
        };
        assert!(token.is_valid());
    }

    #[test]
    fn id_token_is_invalid_with_empty_token_id() {
        let token = IdToken {
            token_id: "".to_string(),
            issuer: "iss".to_string(),
            subject: "sub".to_string(),
            public_key: vec![],
            signature: vec![],
        };
        assert!(!token.is_valid());
    }

    #[test]
    fn id_token_is_invalid_with_empty_issuer() {
        let token = IdToken {
            token_id: "t1".to_string(),
            issuer: "".to_string(),
            subject: "sub".to_string(),
            public_key: vec![],
            signature: vec![],
        };
        assert!(!token.is_valid());
    }

    #[test]
    fn id_token_never_expires() {
        let token = IdToken {
            token_id: "t1".to_string(),
            issuer: "iss".to_string(),
            subject: "sub".to_string(),
            public_key: vec![],
            signature: vec![],
        };
        assert!(!token.has_expired());
    }

    #[test]
    fn security_level_equality_and_copy() {
        let a = SecurityLevel::Standard128;
        let b = a; // Copy
        assert_eq!(a, b);
        assert_ne!(SecurityLevel::Standard128, SecurityLevel::Medium192);
        assert_ne!(SecurityLevel::Medium192, SecurityLevel::High256);
    }

    #[test]
    fn verification_result_failure() {
        let result = VerificationResult {
            is_valid: false,
            reason: Some("Hash mismatch".to_string()),
            details: None,
            verification_path: vec![],
        };
        assert!(!result.is_valid);
        assert_eq!(result.reason.as_deref(), Some("Hash mismatch"));
        assert!(result.details.is_none());
        assert!(result.verification_path.is_empty());
    }

    #[test]
    fn directory_entry_with_invalidation_markers() {
        let entry = DirectoryEntry {
            id: "dir1".to_string(),
            genesis_hash: vec![0xFF; 32],
            invalidation_markers: vec![vec![1, 2], vec![3, 4]],
        };
        assert_eq!(entry.invalidation_markers.len(), 2);
        assert_eq!(entry.invalidation_markers[0], vec![1, 2]);
    }

    #[test]
    fn commitment_without_co_signature() {
        let c = Commitment {
            hash: vec![1],
            signature: vec![2],
            co_signature: None,
        };
        assert!(c.co_signature.is_none());
        assert_eq!(c.hash, vec![1]);
    }

    #[test]
    fn keypair_debug_with_short_public_key() {
        let kp = KeyPair {
            public_key: vec![1, 2],
            private_key: vec![99],
        };
        let dbg = format!("{:?}", kp);
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("99"));
    }
}
