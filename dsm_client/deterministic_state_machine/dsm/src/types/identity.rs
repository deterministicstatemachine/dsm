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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::state_types::DeviceInfo;

    #[test]
    fn identity_claim_roundtrip_fields() {
        let claim = IdentityClaim {
            identity_id: "id-001".into(),
            tick: 42,
            expires_at_tick: 100,
            public_key: vec![1, 2, 3],
            signature: vec![4, 5, 6],
            claim_hash: vec![7, 8, 9],
            anchor_commitment: vec![10, 11],
            device_info: DeviceInfo::new([0xAA; 32], vec![0xBB; 4]),
            meta_data: HashMap::new(),
        };
        assert_eq!(claim.identity_id, "id-001");
        assert_eq!(claim.tick, 42);
        assert_eq!(claim.expires_at_tick, 100);
        assert_eq!(claim.public_key, vec![1, 2, 3]);
        assert_eq!(claim.signature, vec![4, 5, 6]);
        assert_eq!(claim.claim_hash, vec![7, 8, 9]);
        assert_eq!(claim.anchor_commitment, vec![10, 11]);
    }

    #[test]
    fn identity_claim_with_metadata() {
        let mut meta = HashMap::new();
        meta.insert("label".into(), b"phone".to_vec());

        let claim = IdentityClaim {
            identity_id: "id-002".into(),
            tick: 0,
            expires_at_tick: u64::MAX,
            public_key: vec![],
            signature: vec![],
            claim_hash: vec![],
            anchor_commitment: vec![],
            device_info: DeviceInfo::new([0; 32], vec![]),
            meta_data: meta,
        };
        assert_eq!(claim.meta_data.get("label").unwrap(), b"phone");
    }

    #[test]
    fn identity_claim_clone() {
        let claim = IdentityClaim {
            identity_id: "clone-me".into(),
            tick: 1,
            expires_at_tick: 2,
            public_key: vec![0xFF],
            signature: vec![],
            claim_hash: vec![],
            anchor_commitment: vec![],
            device_info: DeviceInfo::new([0; 32], vec![]),
            meta_data: HashMap::new(),
        };
        let cloned = claim.clone();
        assert_eq!(cloned.identity_id, "clone-me");
        assert_eq!(cloned.public_key, vec![0xFF]);
    }

    #[test]
    fn identity_anchor_basic() {
        let anchor = IdentityAnchor {
            identity_id: "anchor-1".into(),
            public_key: vec![1, 2, 3, 4],
            created_at_tick: 10,
            revoked_at_tick: None,
            meta_data: HashMap::new(),
        };
        assert_eq!(anchor.identity_id, "anchor-1");
        assert_eq!(anchor.created_at_tick, 10);
        assert!(anchor.revoked_at_tick.is_none());
    }

    #[test]
    fn identity_anchor_revoked() {
        let anchor = IdentityAnchor {
            identity_id: "anchor-2".into(),
            public_key: vec![],
            created_at_tick: 5,
            revoked_at_tick: Some(50),
            meta_data: HashMap::new(),
        };
        assert_eq!(anchor.revoked_at_tick, Some(50));
    }

    #[test]
    fn identity_anchor_clone() {
        let anchor = IdentityAnchor {
            identity_id: "anchor-3".into(),
            public_key: vec![9],
            created_at_tick: 0,
            revoked_at_tick: Some(99),
            meta_data: HashMap::new(),
        };
        let cloned = anchor.clone();
        assert_eq!(cloned.identity_id, "anchor-3");
        assert_eq!(cloned.revoked_at_tick, Some(99));
    }

    #[test]
    fn identity_anchor_debug() {
        let anchor = IdentityAnchor {
            identity_id: "dbg".into(),
            public_key: vec![],
            created_at_tick: 0,
            revoked_at_tick: None,
            meta_data: HashMap::new(),
        };
        let dbg = format!("{anchor:?}");
        assert!(dbg.contains("IdentityAnchor"));
        assert!(dbg.contains("dbg"));
    }
}
