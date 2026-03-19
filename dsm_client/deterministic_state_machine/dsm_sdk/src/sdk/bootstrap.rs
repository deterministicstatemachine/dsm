//! # SDK Bootstrap (Platform Boundary Interface)
//!
//! Provides the [`SdkBootstrap`] loader that transactionally validates
//! persisted identity from [`AppState`] and returns a [`CanonicalSdkContext`]
//! with fixed-size `[u8; 32]` fields. This is the single entry point for
//! loading device identity into the SDK; it either succeeds with a fully
//! valid context or returns an error.

// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::sdk::app_state::AppState;
use dsm::types::error::DsmError;

/// Canonical SDK Context - The only valid entry point for the core state machine.
/// This struct is guaranteed to contain valid, canonical data.
pub struct CanonicalSdkContext {
    pub device_id: [u8; 32],
    pub genesis_hash: [u8; 32],
}

/// Platform Boundary Interface (PBI) for bootstrapping the SDK.
/// Isolates non-deterministic I/O and validation from the core.
pub struct SdkBootstrap;

impl SdkBootstrap {
    /// Load and validate the SDK context from persistence.
    /// This is a transactional operation: it either returns a fully valid context or fails.
    pub fn load() -> Result<CanonicalSdkContext, DsmError> {
        // 1. Load raw state (I/O boundary)
        AppState::ensure_storage_loaded();

        // 2. Validate and Canonize Device ID
        let device_id_vec = AppState::get_device_id().ok_or_else(|| DsmError::NotInitialized {
            context: "Device ID not found in AppState".to_string(),
            source: None,
        })?;

        if device_id_vec.len() != 32 {
            return Err(DsmError::Validation {
                context: format!(
                    "Device ID must be exactly 32 bytes, got {}",
                    device_id_vec.len()
                ),
                source: None,
            });
        }

        let mut device_id = [0u8; 32];
        device_id.copy_from_slice(&device_id_vec);

        // 3. Validate and Canonize Genesis Hash
        let genesis_vec = AppState::get_genesis_hash().ok_or_else(|| DsmError::NotInitialized {
            context: "Genesis hash not found in AppState".to_string(),
            source: None,
        })?;

        if genesis_vec.len() != 32 {
            return Err(DsmError::Validation {
                context: format!(
                    "Genesis hash must be exactly 32 bytes, got {}",
                    genesis_vec.len()
                ),
                source: None,
            });
        }

        let mut genesis_hash = [0u8; 32];
        genesis_hash.copy_from_slice(&genesis_vec);

        // 4. Return canonical context
        Ok(CanonicalSdkContext {
            device_id,
            genesis_hash,
        })
    }
}
