//! SMT Replace Witness (Tripwire)
//!
//! Centralized parsing and verification utilities for the per-device SMT "replace" witness.
//!
//! Used by acceptance predicates that must be able to recompute an SMT root
//! from a leaf hash and a sibling path, deterministically and fail-closed.

use crate::types::error::DsmError;

/// Hard cap for witness path length (DoS resistance).
pub const MAX_SMT_WITNESS_PATH_LEN: usize = 256;

#[derive(Clone, Debug)]
struct Step {
    sibling: [u8; 32],
    is_left: bool,
}

#[derive(Clone, Debug)]
pub struct SmtReplaceWitness {
    path: Vec<Step>,
}

impl SmtReplaceWitness {
    /// Deterministic encoding:
    /// - u32 little-endian path length
    /// - repeated: 1 byte is_left (0/1) + 32-byte sibling
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 4 {
            return None;
        }
        let n = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        let expected = 4usize.checked_add(n.checked_mul(33)?)?;
        if bytes.len() != expected {
            return None;
        }

        if n > MAX_SMT_WITNESS_PATH_LEN {
            return None;
        }

        let mut path = Vec::with_capacity(n);
        let mut offset = 4;
        for _ in 0..n {
            let is_left = match bytes[offset] {
                0 => false,
                1 => true,
                _ => return None,
            };
            offset += 1;
            let sibling: [u8; 32] = bytes[offset..offset + 32].try_into().ok()?;
            offset += 32;
            path.push(Step { sibling, is_left });
        }
        Some(Self { path })
    }

    pub fn recompute_root(&self, leaf_hash: &[u8; 32]) -> [u8; 32] {
        let mut cur = *leaf_hash;
        for step in &self.path {
            cur = if step.is_left {
                hash_smt_node(&cur, &step.sibling)
            } else {
                hash_smt_node(&step.sibling, &cur)
            };
        }
        cur
    }
}

/// Re-export canonical SMT key computation from its single home.
pub use crate::core::bilateral_transaction_manager::compute_smt_key;

/// Hash an SMT leaf deterministically.
///
/// Per spec §2.2: `Leaf(X) := BLAKE3("DSM/smt-leaf\0" ∥ X)`.
/// The relationship key is NOT part of the leaf hash.
pub fn hash_smt_leaf(tip: &[u8; 32]) -> [u8; 32] {
    let mut hasher = crate::crypto::blake3::dsm_domain_hasher("DSM/smt-leaf");
    hasher.update(tip);
    *hasher.finalize().as_bytes()
}

/// Hash an SMT internal node deterministically.
pub fn hash_smt_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = crate::crypto::blake3::dsm_domain_hasher("DSM/smt-node");
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// Verify the Tripwire SMT replace by recomputing both roots from a single witness path.
///
/// Fail-closed:
/// - returns `Ok(false)` if witness is missing/unparseable.
/// - returns `Ok(false)` if structural preconditions fail.
pub fn verify_tripwire_smt_replace(
    parent_root: &[u8; 32],
    child_root: &[u8; 32],
    parent_tip: &[u8; 32],
    child_tip: &[u8; 32],
    witness_bytes: &[u8],
) -> Result<bool, DsmError> {
    if parent_root == child_root {
        return Ok(false);
    }
    if parent_tip == child_tip {
        return Ok(false);
    }
    if witness_bytes.is_empty() {
        return Ok(false);
    }

    let witness = SmtReplaceWitness::from_bytes(witness_bytes).ok_or_else(|| {
        DsmError::InvalidOperation("Failed to parse SMT replace witness".to_string())
    })?;

    let old_leaf = hash_smt_leaf(parent_tip);
    let new_leaf = hash_smt_leaf(child_tip);

    let recomputed_parent = witness.recompute_root(&old_leaf);
    if &recomputed_parent != parent_root {
        return Ok(false);
    }
    let recomputed_child = witness.recompute_root(&new_leaf);
    Ok(&recomputed_child == child_root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_rejects_bad_length() {
        assert!(SmtReplaceWitness::from_bytes(&[]).is_none());
        assert!(SmtReplaceWitness::from_bytes(&[0, 0, 0]).is_none());
        assert!(SmtReplaceWitness::from_bytes(&[0, 0, 0, 0, 1]).is_none());
    }

    #[test]
    fn witness_rejects_overlong() {
        let n = (MAX_SMT_WITNESS_PATH_LEN as u32) + 1;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&n.to_le_bytes());
        bytes.resize(4 + (n as usize) * 33, 0);
        assert!(SmtReplaceWitness::from_bytes(&bytes).is_none());
    }

    #[test]
    fn witness_smoke_deterministic_recompute() {
        // Build a witness with 1 step.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(1u32.to_le_bytes()));
        bytes.push(1u8);
        bytes.extend_from_slice(&[9u8; 32]);

        let w = SmtReplaceWitness::from_bytes(&bytes).expect("parse");
        let leaf = [7u8; 32];
        assert_eq!(w.recompute_root(&leaf), w.recompute_root(&leaf));
    }

    #[test]
    fn smt_key_is_order_invariant() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(compute_smt_key(&a, &b), compute_smt_key(&b, &a));
    }
}
