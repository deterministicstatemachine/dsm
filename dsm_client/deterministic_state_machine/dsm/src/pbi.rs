// SPDX-License-Identifier: MIT OR Apache-2.0

//! Platform Boundary Interface (PBI)
//!
//! This module implements the hard platform boundary described in the public
//! protocol and security documentation.
//! It acts as the sole entry point for ingesting raw, non-deterministic platform inputs (IO, JNI, Entropy)
//! and transforming them into canonical, immutable, cryptographic types *before* they touch the Core State Machine.
//!
//! # Architecture
//!
//! 1. **Ingestion**: Raw bytes from JNI/Platform are accepted.
//! 2. **Canonization**: Inputs are immediately hashed/validated into domain-separated types.
//! 3. **Context Creation**: A `PlatformContext` is built. This is the ONLY object the Core trusts.
//!
//! # Invariants
//!
//! - No raw `Vec<u8>` or `String` inputs allowed deep in the core.
//! - All inputs must be length-checked and domain-separated immediately.

use crate::types::error::DsmError;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Canonical, immutable platform context.
/// This is the "Safe" object that the Core consumes.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct PlatformContext {
    /// Canonical Device ID (32 bytes)
    pub device_id: [u8; 32],
    /// Canonical Genesis Hash (32 bytes)
    pub genesis_hash: [u8; 32],
}

/// Raw inputs from the platform (JNI/Kotlin/Swift).
/// These are "unsafe" and must be processed immediately.
pub struct RawPlatformInputs {
    pub device_id_raw: Vec<u8>,
    pub genesis_hash_raw: Vec<u8>,
}

impl PlatformContext {
    /// The Single Point of Entry for bootstrapping the Core.
    ///
    /// This function consumes raw inputs and returns a sanitized Context or an Error.
    /// It enforces the "Zero Tolerance" policy at the perimeter.
    pub fn bootstrap(inputs: RawPlatformInputs) -> Result<Self, DsmError> {
        // 1. Canonize Device ID
        let device_id = Self::canonize_identifier(&inputs.device_id_raw, "DSM/devid\0")?;

        // 2. Canonize Genesis Hash
        let genesis_hash = Self::canonize_identifier(&inputs.genesis_hash_raw, "DSM/genesis\0")?;

        Ok(Self {
            device_id,
            genesis_hash,
        })
    }

    /// Helper to validate and canonize 32-byte identifiers.
    /// STRICTNESS: We expect the platform to pass the *pre-calculated* digests for IDs,
    /// but we verify lengths strictly.
    fn canonize_identifier(input: &[u8], _domain_tag: &str) -> Result<[u8; 32], DsmError> {
        if input.len() != 32 {
            return Err(DsmError::Validation {
                context: format!(
                    "Invalid identifier length: expected 32, got {}",
                    input.len()
                ),
                source: None,
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(input);
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_inputs() -> RawPlatformInputs {
        RawPlatformInputs {
            device_id_raw: vec![0xAA; 32],
            genesis_hash_raw: vec![0xBB; 32],
        }
    }

    #[test]
    fn canonize_identifier_exact_32_bytes() {
        let input = vec![0x42u8; 32];
        let result = PlatformContext::canonize_identifier(&input, "DSM/test\0");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), [0x42u8; 32]);
    }

    #[test]
    fn canonize_identifier_too_short() {
        let input = vec![0x01u8; 16];
        let result = PlatformContext::canonize_identifier(&input, "DSM/test\0");
        assert!(result.is_err());
        match result.unwrap_err() {
            DsmError::Validation { context, .. } => {
                assert!(context.contains("expected 32"));
                assert!(context.contains("got 16"));
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn canonize_identifier_too_long() {
        let input = vec![0x01u8; 64];
        let result = PlatformContext::canonize_identifier(&input, "DSM/test\0");
        assert!(result.is_err());
        match result.unwrap_err() {
            DsmError::Validation { context, .. } => {
                assert!(context.contains("expected 32"));
                assert!(context.contains("got 64"));
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn canonize_identifier_empty() {
        let result = PlatformContext::canonize_identifier(&[], "DSM/test\0");
        assert!(result.is_err());
    }

    #[test]
    fn canonize_identifier_preserves_bytes() {
        let input: Vec<u8> = (0..32).collect();
        let arr = PlatformContext::canonize_identifier(&input, "DSM/devid\0").unwrap();
        assert_eq!(&arr[..], &input[..]);
    }

    #[test]
    fn bootstrap_valid_inputs_succeeds() {
        let ctx = PlatformContext::bootstrap(valid_inputs()).expect("bootstrap should succeed");
        assert_eq!(ctx.device_id, [0xAA; 32]);
        assert_eq!(ctx.genesis_hash, [0xBB; 32]);
    }

    #[test]
    fn bootstrap_short_device_id_fails() {
        let mut inputs = valid_inputs();
        inputs.device_id_raw = vec![0xAA; 10];
        let result = PlatformContext::bootstrap(inputs);
        assert!(result.is_err());
        match result.unwrap_err() {
            DsmError::Validation { context, .. } => {
                assert!(context.contains("expected 32"));
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn bootstrap_short_genesis_hash_fails() {
        let mut inputs = valid_inputs();
        inputs.genesis_hash_raw = vec![0xBB; 5];
        let result = PlatformContext::bootstrap(inputs);
        assert!(result.is_err());
    }

    #[test]
    fn raw_platform_inputs_construction() {
        let raw = RawPlatformInputs {
            device_id_raw: vec![1; 32],
            genesis_hash_raw: vec![2; 32],
        };
        assert_eq!(raw.device_id_raw.len(), 32);
        assert_eq!(raw.genesis_hash_raw.len(), 32);
    }

    #[test]
    fn platform_context_fields_correct_after_bootstrap() {
        let inputs = valid_inputs();
        let ctx = PlatformContext::bootstrap(inputs).unwrap();

        assert_eq!(ctx.device_id, [0xAA; 32]);
        assert_eq!(ctx.genesis_hash, [0xBB; 32]);
    }

    #[test]
    fn bootstrap_deterministic() {
        let ctx1 = PlatformContext::bootstrap(valid_inputs()).unwrap();
        let ctx2 = PlatformContext::bootstrap(valid_inputs()).unwrap();
        assert_eq!(ctx1.device_id, ctx2.device_id);
        assert_eq!(ctx1.genesis_hash, ctx2.genesis_hash);
    }
}
