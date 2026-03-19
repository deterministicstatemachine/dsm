//! Proof primitives (centralized)
//!
//! Centralizes proof parsing + verification helpers so acceptance predicates
//! don't re-implement byte caps, parsing, or deterministic edge-case rules.
//!
//! Policy:
//! - Fail-closed: malformed or missing proofs return `Ok(false)` (or `None` for parsing helpers).
//! - DoS bounds: caps enforced consistently (64 KiB where proofs are caller-provided bytes).
//! - No JSON/hex/base64.

use crate::types::error::DsmError;
use prost::Message;

use crate::types::proto as pb;
use crate::verification::smt_replace_witness::{hash_smt_leaf, hash_smt_node};

/// Maximum allowed size for proof byte strings.
///
/// This cap is enforced anywhere we accept caller-provided proof bytes to
/// prevent parsing/malloc DoS.
pub const MAX_PROOF_BYTES: usize = 64 * 1024;

/// Parse a little-endian u64 witness (exactly 8 bytes).
#[inline]
pub fn parse_u64_le(w: &[u8]) -> Option<u64> {
    if w.len() != 8 {
        return None;
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(w);
    Some(u64::from_le_bytes(arr))
}

/// Parse a UTF-8 decimal u64 witness.
#[inline]
pub fn parse_u64_utf8_decimal(w: &[u8]) -> Option<u64> {
    let s = core::str::from_utf8(w).ok()?;
    s.parse::<u64>().ok()
}

/// Extract deterministic tick from context data.
///
/// Preferred: `"tick" -> u64 LE`.
#[inline]
pub fn tick_from_context_data(
    context_data: &std::collections::HashMap<String, Vec<u8>>,
) -> Option<u64> {
    context_data.get("tick").and_then(|b| parse_u64_le(b))
}

/// Build and read a rate limit witness.
///
/// Key format: `rate_limit::<op>.last_k::<N>` -> u64 LE
#[inline]
pub fn rate_limit_witness_u64(
    data: &std::collections::HashMap<String, Vec<u8>>,
    op: &str,
    last_k: u64,
) -> Option<u64> {
    let key = format!("rate_limit::{op}.last_k::{last_k}");
    data.get(&key).and_then(|b| parse_u64_le(b))
}

/// Extract amount witness.
///
/// Require `amount_u64` -> u64 LE.
#[inline]
pub fn amount_witness_u64(data: &std::collections::HashMap<String, Vec<u8>>) -> Option<u64> {
    data.get("amount_u64").and_then(|b| parse_u64_le(b))
}

/// Extract vault balance witness.
///
/// Key: `vault.balance_u64` -> u64 LE.
#[inline]
pub fn vault_balance_witness_u64(data: &std::collections::HashMap<String, Vec<u8>>) -> Option<u64> {
    data.get("vault.balance_u64").and_then(|b| parse_u64_le(b))
}

/// Deterministic witness check for SmartPolicy constraints.
///
/// Current rule is presence + non-empty bytes under key `smart_policy_witness`.
#[inline]
pub fn smart_policy_witness_present(data: &std::collections::HashMap<String, Vec<u8>>) -> bool {
    data.get("smart_policy_witness")
        .map(|w| !w.is_empty())
        .unwrap_or(false)
}

#[inline]
fn bit_msb_first(key: &[u8; 32], bit_index: usize) -> bool {
    let byte = bit_index / 8;
    let bit = 7 - (bit_index % 8);
    ((key[byte] >> bit) & 1) == 1
}

/// Verify inclusion for a canonical SMT proof serialized as protobuf `dsm.SmtProof`.
///
/// Fail-closed: empty or malformed proofs are rejected unless the root is
/// the all-zeros sentinel (empty tree). An empty proof is valid only when
/// the root is all zeros, indicating the tree has no leaves.
pub fn verify_smt_inclusion_proof_bytes(
    root: &[u8; 32],
    relationship_key: &[u8; 32],
    value: &[u8; 32],
    proof_bytes: &[u8],
) -> Result<bool, DsmError> {
    if proof_bytes.is_empty() {
        // Empty proof is valid only if tree is empty (root == all-zeros sentinel).
        return Ok(root.iter().all(|&b| b == 0));
    }

    if proof_bytes.len() > MAX_PROOF_BYTES {
        return Err(DsmError::InvalidOperation(
            "SMT proof exceeds maximum size".to_string(),
        ));
    }

    let proof = pb::SmtProof::decode(proof_bytes).map_err(|_| {
        DsmError::InvalidOperation("Failed to decode SMT proof (protobuf)".to_string())
    })?;

    if proof.key.len() != 32 || proof.key.as_slice() != relationship_key {
        return Ok(false);
    }

    // Require an existing leaf with matching key/value.
    let leaf_ok = match &proof.v_path {
        Some(pb::smt_proof::VPath::ExistingLeaf(l)) => {
            l.key.len() == 32
                && l.value.len() == 32
                && l.key.as_slice() == relationship_key
                && l.value.as_slice() == value
        }
        _ => false,
    };
    if !leaf_ok {
        return Ok(false);
    }

    let leaf_hash = hash_smt_leaf(relationship_key, value);

    // siblings are root->leaf (MSB-first), so walk in reverse to rebuild root
    let mut acc = leaf_hash;
    for (i, sib_bytes) in proof.siblings.iter().rev().enumerate() {
        if sib_bytes.len() != 32 {
            return Ok(false);
        }
        let mut sib = [0u8; 32];
        sib.copy_from_slice(sib_bytes);

        // Depth indexing convention: the last sibling corresponds to bit index 255.
        // This matches existing witness folding semantics: leaf->root uses low-order bits first.
        let bit_index = 255usize.saturating_sub(i);
        let is_right = bit_msb_first(relationship_key, bit_index);
        acc = if is_right {
            hash_smt_node(&sib, &acc)
        } else {
            hash_smt_node(&acc, &sib)
        };
    }

    Ok(&acc == root)
}

/// Verify inclusion for a canonical Device Tree proof serialized as protobuf `dsm.DeviceTreeProof`.
///
/// Fail-closed: empty or malformed proofs are rejected unless the root
/// matches a known sentinel (empty tree or single-leaf tree).
pub fn verify_device_tree_inclusion_proof_bytes(
    root: &[u8; 32],
    devid: &[u8; 32],
    proof_bytes: &[u8],
) -> Result<bool, DsmError> {
    if proof_bytes.is_empty() {
        // Empty proof is valid in two cases:
        // 1. Tree is empty (root == canonical empty-tree sentinel hash).
        if root == &crate::common::device_tree::empty_root() {
            return Ok(true);
        }
        // 2. Tree has exactly one leaf matching devid (root == hash_leaf(devid),
        //    no siblings needed since DevTreeProof::verify walks zero siblings).
        if root == &crate::common::device_tree::hash_leaf(devid) {
            return Ok(true);
        }
        return Ok(false);
    }

    if proof_bytes.len() > MAX_PROOF_BYTES {
        return Err(DsmError::InvalidOperation(
            "Device Tree proof exceeds maximum size".to_string(),
        ));
    }

    let proof = pb::DeviceTreeProof::decode(proof_bytes).map_err(|_| {
        DsmError::InvalidOperation("Failed to decode Device Tree proof (protobuf)".to_string())
    })?;

    if proof.siblings.iter().any(|s| s.len() != 32) {
        return Ok(false);
    }

    let mut siblings = Vec::with_capacity(proof.siblings.len());
    for s in proof.siblings.iter() {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(s);
        siblings.push(arr);
    }

    // Unpack LSB-first bitfield.
    let mut path_bits = Vec::with_capacity(proof.path_bits_len as usize);
    let packed = &proof.path_bits;
    let bit_len = proof.path_bits_len as usize;
    for i in 0..bit_len {
        let b = packed.get(i / 8).copied().unwrap_or(0);
        let bit = (b & (1 << (i % 8))) != 0;
        path_bits.push(bit);
    }

    let dev_proof = crate::common::device_tree::DevTreeProof {
        siblings,
        leaf_to_root: proof.leaf_to_root,
        path_bits,
    };

    Ok(dev_proof.verify(devid, root))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_u64_le_requires_exact_len() {
        assert!(parse_u64_le(&[]).is_none());
        assert!(parse_u64_le(&[0u8; 7]).is_none());
        assert!(parse_u64_le(&[0u8; 9]).is_none());
        assert_eq!(parse_u64_le(&1u64.to_le_bytes()), Some(1));
    }

    #[test]
    fn parse_u64_utf8_decimal_parses() {
        assert_eq!(parse_u64_utf8_decimal(b"0"), Some(0));
        assert_eq!(parse_u64_utf8_decimal(b"42"), Some(42));
        assert!(parse_u64_utf8_decimal(b"-1").is_none());
        assert!(parse_u64_utf8_decimal(&[0xff]).is_none());
    }
}
