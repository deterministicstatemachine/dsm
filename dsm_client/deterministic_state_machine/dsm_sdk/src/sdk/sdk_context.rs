//! # SDK Context Management
//!
//! This module provides centralized context management for the DSM SDK,
//! ensuring consistent access to device identity, chain state, and configuration
//! across all SDK components.

use std::sync::Arc;
use parking_lot::RwLock;
use dsm::types::error::DsmError;

/// SDK Context containing shared state for all SDK operations
#[derive(Clone)]
pub struct SdkContext {
    /// Device identifier (32 bytes, mandatory)
    device_id: Arc<RwLock<[u8; 32]>>,
    /// Current chain tip hash (32 bytes, mandatory)
    chain_tip: Arc<RwLock<[u8; 32]>>,
    /// Genesis hash for this device/user (32 bytes, mandatory)
    genesis_hash: Arc<RwLock<[u8; 32]>>,
    /// Whether the context has been initialized with valid identity
    initialized: Arc<RwLock<bool>>,
    /// Sequence number for operations
    sequence_number: Arc<RwLock<u64>>,
    /// Device entropy for cryptographic operations
    device_entropy: Arc<RwLock<Vec<u8>>>,
}

impl SdkContext {
    /// Create a new SDK context with default values
    pub fn new() -> Self {
        SdkContext {
            device_id: Arc::new(RwLock::new([0u8; 32])),
            chain_tip: Arc::new(RwLock::new([0u8; 32])),
            genesis_hash: Arc::new(RwLock::new([0u8; 32])),
            initialized: Arc::new(RwLock::new(false)),
            sequence_number: Arc::new(RwLock::new(0)),
            device_entropy: Arc::new(RwLock::new(vec![0; 32])),
        }
    }

    /// Initialize context with device-specific values
    pub fn initialize(
        &self,
        device_id: Vec<u8>,
        genesis_hash: Vec<u8>,
        initial_entropy: Vec<u8>,
    ) -> Result<(), DsmError> {
        // Validate inputs - all identity fields are mandatory
        if device_id.len() != 32 {
            return Err(DsmError::invalid_parameter(format!(
                "Device ID must be 32 bytes, got {}",
                device_id.len()
            )));
        }
        if genesis_hash.len() != 32 {
            return Err(DsmError::invalid_parameter(format!(
                "Genesis hash must be 32 bytes, got {}",
                genesis_hash.len()
            )));
        }
        // Genesis cannot be all zeros (that indicates uninitialized)
        if genesis_hash.iter().all(|&b| b == 0) {
            return Err(DsmError::invalid_parameter(
                "Genesis hash cannot be all zeros",
            ));
        }
        if initial_entropy.is_empty() {
            return Err(DsmError::invalid_parameter(
                "Initial entropy cannot be empty",
            ));
        }

        // Convert to fixed arrays
        let mut dev_arr = [0u8; 32];
        let mut gen_arr = [0u8; 32];
        dev_arr.copy_from_slice(&device_id);
        gen_arr.copy_from_slice(&genesis_hash);

        // Set values atomically
        *self.device_id.write() = dev_arr;
        *self.genesis_hash.write() = gen_arr;
        *self.chain_tip.write() = gen_arr; // Chain tip starts at genesis
        *self.device_entropy.write() = initial_entropy;
        *self.initialized.write() = true;

        log::info!("SDK context initialized successfully");
        Ok(())
    }

    /// Get the current device ID (32 bytes)
    pub fn device_id(&self) -> Vec<u8> {
        self.device_id.read().to_vec()
    }

    /// Get the current chain tip (32 bytes)
    pub fn chain_tip(&self) -> Vec<u8> {
        self.chain_tip.read().to_vec()
    }

    /// Get the genesis hash (32 bytes, mandatory once initialized)
    /// Per DSM spec, genesis is the root identity anchor and is always required.
    /// Returns the genesis hash bytes. Before initialization, returns zeros.
    pub fn genesis_hash(&self) -> Vec<u8> {
        self.genesis_hash.read().to_vec()
    }

    /// Get the genesis hash as a fixed-size array (32 bytes)
    pub fn genesis_hash_array(&self) -> [u8; 32] {
        *self.genesis_hash.read()
    }

    /// Get the device ID as a fixed-size array (32 bytes)
    pub fn device_id_array(&self) -> [u8; 32] {
        *self.device_id.read()
    }

    /// Get the chain tip as a fixed-size array (32 bytes)
    pub fn chain_tip_array(&self) -> [u8; 32] {
        *self.chain_tip.read()
    }

    /// Get the current sequence number
    pub fn sequence_number(&self) -> u64 {
        *self.sequence_number.read()
    }

    /// Get device entropy
    pub fn device_entropy(&self) -> Vec<u8> {
        self.device_entropy.read().clone()
    }

    /// Update the chain tip
    pub fn update_chain_tip(&self, new_tip: Vec<u8>) -> Result<(), DsmError> {
        if new_tip.len() != 32 {
            return Err(DsmError::invalid_parameter(format!(
                "Chain tip must be 32 bytes, got {}",
                new_tip.len()
            )));
        }
        let mut tip_arr = [0u8; 32];
        tip_arr.copy_from_slice(&new_tip);
        let tip_txt = crate::util::text_id::encode_base32_crockford(&tip_arr[..8]);
        log::info!(
            "[SDK_CONTEXT] ✅ Updated chain_tip to {} (first 8 bytes)",
            tip_txt
        );
        *self.chain_tip.write() = tip_arr;
        Ok(())
    }

    /// Increment and return the next sequence number
    pub fn next_sequence_number(&self) -> u64 {
        let mut seq = self.sequence_number.write();
        *seq += 1;
        *seq
    }

    /// Reset sequence number (for testing)
    pub fn reset_sequence_number(&self) {
        *self.sequence_number.write() = 0;
    }

    /// Check if context is properly initialized
    pub fn is_initialized(&self) -> bool {
        *self.initialized.read()
    }

    /// Reset SDK context state (for testing only)
    #[cfg(any(test, feature = "test-utils"))]
    pub fn reset_for_testing(&self) {
        *self.device_id.write() = [0u8; 32];
        *self.chain_tip.write() = [0u8; 32];
        *self.genesis_hash.write() = [0u8; 32];
        *self.initialized.write() = false;
        *self.sequence_number.write() = 0;
        *self.device_entropy.write() = vec![0; 32];
    }
}

impl Default for SdkContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    #[test]
    fn test_sdk_context_initialization() {
        let context = SdkContext::new();

        // Initially not initialized
        assert!(!context.is_initialized());

        // Initialize with valid values
        let device_id = vec![1; 32];
        let genesis_hash = vec![2; 32];
        let entropy = vec![3; 32];

        context
            .initialize(device_id.clone(), genesis_hash.clone(), entropy)
            .unwrap();

        // Now initialized
        assert!(context.is_initialized());
        assert_eq!(context.device_id(), device_id);
        assert_eq!(context.genesis_hash(), genesis_hash.clone());
        assert_eq!(context.chain_tip(), genesis_hash.clone()); // Chain tip should be set to genesis
    }

    #[test]
    fn test_sequence_number_increment() {
        let context = SdkContext::new();

        assert_eq!(context.sequence_number(), 0);
        assert_eq!(context.next_sequence_number(), 1);
        assert_eq!(context.sequence_number(), 1);
    }

    #[test]
    fn test_chain_tip_update() {
        let context = SdkContext::new();

        let new_tip = vec![4; 32];
        context.update_chain_tip(new_tip.clone()).unwrap();
        assert_eq!(context.chain_tip(), new_tip);
    }

    #[test]
    fn test_invalid_initialization() {
        let context = SdkContext::new();

        // Invalid device ID length
        let result = context.initialize(vec![1; 16], vec![2; 32], vec![3; 32]);
        assert!(result.is_err());

        // Invalid genesis hash length
        let result = context.initialize(vec![1; 32], vec![2; 16], vec![3; 32]);
        assert!(result.is_err());

        // Empty entropy
        let result = context.initialize(vec![1; 32], vec![2; 32], vec![]);
        assert!(result.is_err());
    }
}
