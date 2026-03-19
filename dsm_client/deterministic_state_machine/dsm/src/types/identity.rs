//! Cryptographic identity types for the DSM protocol.
//!
//! Provides [`IdentityClaim`] (an unverified request to establish identity) and
//! [`IdentityAnchor`] (a verified, committed identity root). Both are anchored
//! to the device's genesis state via SPHINCS+ public keys and use logical ticks
//! (not wall-clock time) for creation and expiration semantics.

use std::collections::HashMap;

/// IdentityClaim represents a request to validate or establish an identity
#[derive(Clone, Debug)]
pub struct IdentityClaim {
    /// Unique identifier for this identity
    pub identity_id: String,

    /// Logical tick when this claim was created
    pub tick: u64,

    /// Expiration tick for this claim
    pub expires_at_tick: u64,

    /// Public key associated with this claim
    pub public_key: Vec<u8>,

    /// Cryptographic signature over the claim data
    pub signature: Vec<u8>,

    /// Hash of the claim data
    pub claim_hash: Vec<u8>,

    /// Commitment to the identity anchor
    pub anchor_commitment: Vec<u8>,

    /// Device information
    pub device_info: crate::types::state_types::DeviceInfo,

    /// Additional metadata
    pub meta_data: HashMap<String, Vec<u8>>,
}

/// IdentityAnchor represents a verified cryptographic identity root
#[derive(Clone, Debug)]
pub struct IdentityAnchor {
    /// Unique identifier for this identity
    pub identity_id: String,

    /// Public key associated with this identity
    pub public_key: Vec<u8>,

    /// Logical tick when this identity was created
    pub created_at_tick: u64,

    /// Optional tick when this identity was revoked
    pub revoked_at_tick: Option<u64>,

    /// Additional metadata
    pub meta_data: HashMap<String, Vec<u8>>,
}
