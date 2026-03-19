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
//! - C-DBRW binding derivation is delegated to `crypto::cdbrw_binding` (single source of truth).

use crate::types::error::DsmError;
use crate::crypto::cdbrw_binding;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Canonical, immutable platform context.
/// This is the "Safe" object that the Core consumes.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct PlatformContext {
    /// Canonical Device ID (32 bytes)
    pub device_id: [u8; 32],
    /// Canonical Genesis Hash (32 bytes)
    pub genesis_hash: [u8; 32],
    /// Canonical C-DBRW Binding Key K_DBRW (32 bytes)
    /// Derived from HW entropy + Env fingerprint + Salt via `cdbrw_binding::derive_cdbrw_binding_key`.
    pub cdbrw_binding: [u8; 32],
}

/// Raw inputs from the platform (JNI/Kotlin/Swift).
/// These are "unsafe" and must be processed immediately.
pub struct RawPlatformInputs {
    pub device_id_raw: Vec<u8>,
    pub genesis_hash_raw: Vec<u8>,
    pub cdbrw_hw_entropy: Vec<u8>,
    pub cdbrw_env_fingerprint: Vec<u8>,
    pub cdbrw_salt: Vec<u8>,
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

        // 3. Delegate C-DBRW binding derivation to the crypto module.
        // PBI responsibility: strict validation only.
        // Crypto responsibility: canonical serialization + domain-separated hashing.
        let cdbrw_binding = cdbrw_binding::derive_cdbrw_binding_key(
            &inputs.cdbrw_hw_entropy,
            &inputs.cdbrw_env_fingerprint,
            &inputs.cdbrw_salt,
        )?;

        Ok(Self {
            device_id,
            genesis_hash,
            cdbrw_binding,
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
