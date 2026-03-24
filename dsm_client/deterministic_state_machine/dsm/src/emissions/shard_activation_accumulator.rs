//! Shard Activation Accumulator / SAA (emissions spec §3.4)
//!
//! Per-shard append-only accumulator whose leaves are activated identities:
//!   `SAA_s: L_s[i] = H("DJTE.ACTIVE" || id_i)`
//!
//! The accumulator provides `acc_root_{e,s}` and inclusion proofs of `(i, L_s[i])`.
//!
//! This is NOT a Sparse Merkle Tree — it's an append-only structure (MMR or
//! append-only Merkle tree). Currently implemented as a simple binary Merkle tree
//! over the leaf vector.
//!
//! # Storage
//!
//! These accumulators live on storage nodes (as part of the Source DLV state),
//! not locally on devices. Devices verify proofs against committed roots.
//!
//! # Domain Separation
//!
//! - Leaf values use `DJTE.ACTIVE` domain (per emissions spec §3.4)
//! - Internal nodes currently use `DSM/djte-shard-merkle` domain
//! - TODO: Consider using `DJTE/saa-node` when parameterized domains are implemented

use crate::crypto::blake3::{domain_hash_bytes, dsm_domain_hasher};

/// Shard Activation Accumulator
///
/// Append-only list of activated identities, stored as:
///   leaf = H("DJTE.ACTIVE", id)
#[derive(Clone, Debug)]
pub struct ShardActivationAccumulator {
    pub leaves: Vec<[u8; 32]>,
}

impl ShardActivationAccumulator {
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    pub fn append(&mut self, id: [u8; 32]) {
        let leaf = domain_hash_bytes("DJTE.ACTIVE", &id);
        self.leaves.push(leaf);
    }

    pub fn root(&self) -> [u8; 32] {
        if self.leaves.is_empty() {
            return [0u8; 32];
        }
        let mut current_level = self.leaves.clone();
        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
            for chunk in current_level.chunks(2) {
                let mut hasher = dsm_domain_hasher("DSM/djte-shard-merkle");
                hasher.update(&chunk[0]);
                if chunk.len() == 2 {
                    hasher.update(&chunk[1]);
                } else {
                    hasher.update(&chunk[0]);
                }
                let res = hasher.finalize();
                let mut h = [0u8; 32];
                h.copy_from_slice(res.as_bytes());
                next_level.push(h);
            }
            current_level = next_level;
        }
        current_level[0]
    }

    pub fn get_leaf(&self, index: usize) -> Option<[u8; 32]> {
        self.leaves.get(index).cloned()
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }
}

impl Default for ShardActivationAccumulator {
    fn default() -> Self {
        Self::new()
    }
}
