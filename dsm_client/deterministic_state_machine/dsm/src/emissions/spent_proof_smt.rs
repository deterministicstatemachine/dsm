//! SpentProofSMT: single-use JAP consumption tracking (emissions spec §3.6)
//!
//! An SMT mapping `jap_hash → 1` if consumed, else absent.
//! Root at emission state `e` is `spent_root_e`.
//!
//! Emission transitions carry:
//! - Non-membership proof under `spent_root_e` that `jap_hash` is absent (before)
//! - Membership proof under `spent_root_{e+1}` that `jap_hash → 1` is present (after)
//!
//! # Current Implementation
//!
//! Uses a flat `HashMap<[u8; 32], bool>` with sorted-concatenation root.
//! This is a placeholder — it does not produce real SMT inclusion/non-inclusion proofs.
//!
//! # Planned Upgrade
//!
//! Convert to a proper 256-bit SMT using `merkle::sparse_merkle_tree::SparseMerkleTree`
//! with DJTE-specific domain separation (`DJTE/spent-leaf`, `DJTE/spent-node`).
//! The 256-bit key SMT is the correct structure here since `jap_hash` values are
//! 32-byte BLAKE3 digests.
//!
//! # Storage
//!
//! These trees live on storage nodes (as part of the Source DLV state),
//! not locally on devices. Devices verify proofs against committed roots.

use crate::crypto::blake3::dsm_domain_hasher;
use std::collections::HashMap;

/// Spent Proof SMT
///
/// Maps jap_hash -> 1 (represented as a deterministic commitment over sorted keys).
#[derive(Clone, Debug)]
pub struct SpentProofSmt {
    pub spent: HashMap<[u8; 32], bool>,
}

impl SpentProofSmt {
    pub fn new() -> Self {
        Self {
            spent: HashMap::new(),
        }
    }

    pub fn mark_spent(&mut self, jap_hash: [u8; 32]) {
        self.spent.insert(jap_hash, true);
    }

    pub fn is_spent(&self, jap_hash: &[u8; 32]) -> bool {
        self.spent.contains_key(jap_hash)
    }

    pub fn len(&self) -> usize {
        self.spent.len()
    }

    pub fn is_empty(&self) -> bool {
        self.spent.is_empty()
    }

    /// Compute a deterministic root commitment over sorted spent keys.
    ///
    /// NOTE: This is NOT a proper SMT root — it's a sorted-concatenation hash.
    /// See module-level "Planned Upgrade" for the upgrade path.
    pub fn root(&self) -> [u8; 32] {
        let mut keys: Vec<[u8; 32]> = self.spent.keys().cloned().collect();
        keys.sort();

        let mut hasher = dsm_domain_hasher("DSM/djte-spent-proof");
        for k in keys {
            hasher.update(&k);
        }
        let res = hasher.finalize();
        let mut h = [0u8; 32];
        h.copy_from_slice(res.as_bytes());
        h
    }
}

impl Default for SpentProofSmt {
    fn default() -> Self {
        Self::new()
    }
}
