// SPDX-License-Identifier: MIT OR Apache-2.0

//! Platform boundary: the identity pair the platform hands the SDK.
//!
//! The platform (JNI/Kotlin) hands over the persisted device id and genesis hash
//! as raw bytes. This module turns them into fixed-size arrays and nothing else:
//! each must be exactly 32 bytes. It does not hash, derive or verify them; whether
//! they name a real identity is established by the SDK's identity restore and by
//! the signing authority that derives from them.

use crate::types::error::DsmError;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The identity pair as two 32-byte arrays.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct PlatformContext {
    /// Device ID (32 bytes)
    pub device_id: [u8; 32],
    /// Genesis hash (32 bytes)
    pub genesis_hash: [u8; 32],
}

/// The pair as the platform hands it over: raw bytes of any length.
pub struct RawPlatformInputs {
    pub device_id_raw: Vec<u8>,
    pub genesis_hash_raw: Vec<u8>,
}

impl PlatformContext {
    /// Fixes both identifiers to 32 bytes, or refuses the pair.
    pub fn bootstrap(inputs: RawPlatformInputs) -> Result<Self, DsmError> {
        let device_id = Self::exactly_32_bytes(&inputs.device_id_raw)?;
        let genesis_hash = Self::exactly_32_bytes(&inputs.genesis_hash_raw)?;

        Ok(Self {
            device_id,
            genesis_hash,
        })
    }

    fn exactly_32_bytes(input: &[u8]) -> Result<[u8; 32], DsmError> {
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
    fn exactly_32_bytes_exact_32_bytes() {
        let input = vec![0x42u8; 32];
        let result = PlatformContext::exactly_32_bytes(&input);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), [0x42u8; 32]);
    }

    #[test]
    fn exactly_32_bytes_too_short() {
        let input = vec![0x01u8; 16];
        let result = PlatformContext::exactly_32_bytes(&input);
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
    fn exactly_32_bytes_too_long() {
        let input = vec![0x01u8; 64];
        let result = PlatformContext::exactly_32_bytes(&input);
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
    fn exactly_32_bytes_empty() {
        let result = PlatformContext::exactly_32_bytes(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn exactly_32_bytes_preserves_bytes() {
        let input: Vec<u8> = (0..32).collect();
        let arr = PlatformContext::exactly_32_bytes(&input).unwrap();
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
