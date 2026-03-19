//! Bitcoin SPV (Simplified Payment Verification) proof verification.
//!
//! Verifies that a transaction is included in a Bitcoin block by checking
//! the Merkle proof against the block header's Merkle root.
//! Uses double-SHA256 (SHA256d) as per Bitcoin consensus rules.
//!
//! Formal correspondence:
//! - successful Merkle verification here feeds the `spvValid` /
//!   `spv_inclusion_valid` predicate in `bitcoin::trust`.
//! - successful PoW verification here feeds the `powValid` / `pow_valid`
//!   predicate in `bitcoin::trust`.
//! - this module alone is not sufficient for the mainnet theorem; checkpoint
//!   and entry-anchor predicates are supplied by `header_chain.rs`.

use bitcoin::hashes::{sha256d, Hash};
use crate::types::error::DsmError;

/// Minimum proof-of-work difficulty (mainnet genesis target)
/// This is a sanity check — real validation should check against a known
/// difficulty target for the block height.
const _MIN_DIFFICULTY_BITS: u32 = 0x1d00ffff;

/// Parsed SPV proof for verification
#[derive(Debug, Clone)]
pub struct SpvProof {
    /// Merkle siblings, from leaf to root
    pub siblings: Vec<[u8; 32]>,
    /// Bit flags: 0 = sibling is on right, 1 = sibling is on left
    pub index: u32,
}

impl SpvProof {
    /// Deserialize from compact wire format:
    /// [index: u32 LE][count: u32 LE][sibling_0: 32 bytes]...[sibling_n: 32 bytes]
    pub fn from_bytes(data: &[u8]) -> Result<Self, DsmError> {
        if data.len() < 8 {
            return Err(DsmError::invalid_operation("SPV proof too short"));
        }

        let index = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let count = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;

        let expected_len = 8 + count * 32;
        if data.len() < expected_len {
            return Err(DsmError::invalid_operation(format!(
                "SPV proof data too short: expected {expected_len}, got {}",
                data.len()
            )));
        }

        let mut siblings = Vec::with_capacity(count);
        for i in 0..count {
            let offset = 8 + i * 32;
            let mut sibling = [0u8; 32];
            sibling.copy_from_slice(&data[offset..offset + 32]);
            siblings.push(sibling);
        }

        Ok(SpvProof { siblings, index })
    }

    /// Serialize to compact wire format
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.siblings.len() * 32);
        out.extend_from_slice(&self.index.to_le_bytes());
        out.extend_from_slice(&(self.siblings.len() as u32).to_le_bytes());
        for sibling in &self.siblings {
            out.extend_from_slice(sibling);
        }
        out
    }
}

/// Compute Bitcoin double-SHA256 of data
fn sha256d(data: &[u8]) -> [u8; 32] {
    let hash = sha256d::Hash::hash(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_byte_array());
    out
}

/// Compute Merkle parent from two children (Bitcoin-style: SHA256d of concatenation)
fn merkle_parent(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(left);
    combined[32..].copy_from_slice(right);
    sha256d(&combined)
}

/// Verify that a transaction ID is included in a Merkle root via an SPV proof.
///
/// # Parameters
/// - `txid`: The transaction ID (little-endian, as stored in Bitcoin)
/// - `merkle_root`: The Merkle root from the block header
/// - `proof`: The SPV Merkle proof
///
/// # Returns
/// `true` if the proof is valid
pub fn verify_spv_proof(txid: &[u8; 32], merkle_root: &[u8; 32], proof: &SpvProof) -> bool {
    let mut current = *txid;
    let mut idx = proof.index;

    for sibling in &proof.siblings {
        if idx & 1 == 0 {
            // Current node is on the left
            current = merkle_parent(&current, sibling);
        } else {
            // Current node is on the right
            current = merkle_parent(sibling, &current);
        }
        idx >>= 1;
    }

    current == *merkle_root
}

/// Extract the Merkle root from a raw 80-byte Bitcoin block header.
///
/// Block header layout (80 bytes):
/// - [0..4]   version (LE)
/// - [4..36]  previous block hash
/// - [36..68] Merkle root
/// - [68..72] time
/// - [72..76] nBits (difficulty target)
/// - [76..80] nonce
pub fn extract_merkle_root(block_header: &[u8; 80]) -> [u8; 32] {
    let mut root = [0u8; 32];
    root.copy_from_slice(&block_header[36..68]);
    root
}

/// Compute the block hash from a raw 80-byte header (double SHA256)
pub fn block_hash(header: &[u8; 80]) -> [u8; 32] {
    sha256d(header)
}

/// Extract the difficulty target (nBits) from a block header
pub fn extract_nbits(block_header: &[u8; 80]) -> u32 {
    u32::from_le_bytes([
        block_header[72],
        block_header[73],
        block_header[74],
        block_header[75],
    ])
}

/// Convert nBits compact target to a 256-bit target value.
/// Returns the target as a 32-byte big-endian number.
pub(crate) fn nbits_to_target(nbits: u32) -> [u8; 32] {
    let mut target = [0u8; 32];
    let exponent = (nbits >> 24) as usize;
    let mantissa = nbits & 0x007fffff;

    if exponent == 0 {
        return target;
    }

    // Place the 3-byte mantissa at the correct position
    if exponent <= 3 {
        let shifted = mantissa >> (8 * (3 - exponent));
        target[31] = (shifted & 0xff) as u8;
        if exponent >= 2 {
            target[30] = ((shifted >> 8) & 0xff) as u8;
        }
        if exponent >= 3 {
            target[29] = ((shifted >> 16) & 0xff) as u8;
        }
    } else if exponent > 32 {
        // Exponent > 32 would underflow the subtraction below.
        // The resulting target is zero (impossible to meet), so the block
        // is invalid. Return the zero target to let the caller reject it.
        return target;
    } else {
        let pos = 32 - exponent;
        if pos < 32 {
            target[pos] = ((mantissa >> 16) & 0xff) as u8;
        }
        if pos + 1 < 32 {
            target[pos + 1] = ((mantissa >> 8) & 0xff) as u8;
        }
        if pos + 2 < 32 {
            target[pos + 2] = (mantissa & 0xff) as u8;
        }
    }

    target
}

/// Verify that a block header meets minimum proof-of-work requirements.
///
/// The block hash (interpreted as a big-endian 256-bit number) must be
/// less than or equal to the target derived from the nBits field.
pub fn verify_block_header_work(block_header: &[u8; 80]) -> bool {
    let hash = block_hash(block_header);
    let nbits = extract_nbits(block_header);

    // Sanity: nBits must represent a reasonable difficulty
    if nbits == 0 {
        return false;
    }

    let target = nbits_to_target(nbits);

    // Block hash must be <= target (both big-endian comparison)
    // Bitcoin block hash bytes are in internal byte order (little-endian of the
    // display hash). For PoW comparison, we reverse to get big-endian.
    let mut hash_be = hash;
    hash_be.reverse();

    // Compare big-endian: hash_be <= target
    for i in 0..32 {
        if hash_be[i] < target[i] {
            return true;
        }
        if hash_be[i] > target[i] {
            return false;
        }
    }
    true // equal
}

/// Full SPV verification: checks that txid is in the block and the block meets PoW.
///
/// This establishes only the `spvValid ∧ powValid` portion of the formal
/// dBTC trust predicate. Mainnet trust reduction additionally requires
/// checkpoint-rooted continuity and the confirmation gate.
pub fn verify_tx_in_block(txid: &[u8; 32], block_header: &[u8; 80], proof: &SpvProof) -> bool {
    let merkle_root = extract_merkle_root(block_header);
    let merkle_ok = verify_spv_proof(txid, &merkle_root, proof);
    if !merkle_ok {
        log::error!(
            "verify_tx_in_block: Merkle proof failed (txid does not match block Merkle root)"
        );
        return false;
    }
    let pow_ok = verify_block_header_work(block_header);
    if !pow_ok {
        log::error!("verify_tx_in_block: PoW check failed (block hash exceeds target)");
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spv_proof_roundtrip() {
        let proof = SpvProof {
            siblings: vec![[0xAA; 32], [0xBB; 32]],
            index: 3,
        };
        let bytes = proof.to_bytes();
        let decoded = SpvProof::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.index, 3);
        assert_eq!(decoded.siblings.len(), 2);
        assert_eq!(decoded.siblings[0], [0xAA; 32]);
        assert_eq!(decoded.siblings[1], [0xBB; 32]);
    }

    #[test]
    fn merkle_proof_single_tx() {
        // A block with a single transaction: the merkle root IS the txid
        let txid = sha256d(b"test transaction");
        let merkle_root = txid;
        let proof = SpvProof {
            siblings: vec![],
            index: 0,
        };
        assert!(verify_spv_proof(&txid, &merkle_root, &proof));
    }

    #[test]
    fn merkle_proof_two_txs() {
        let tx0 = sha256d(b"tx0");
        let tx1 = sha256d(b"tx1");
        let root = merkle_parent(&tx0, &tx1);

        // Proof for tx0: sibling is tx1, index = 0 (left)
        let proof0 = SpvProof {
            siblings: vec![tx1],
            index: 0,
        };
        assert!(verify_spv_proof(&tx0, &root, &proof0));

        // Proof for tx1: sibling is tx0, index = 1 (right)
        let proof1 = SpvProof {
            siblings: vec![tx0],
            index: 1,
        };
        assert!(verify_spv_proof(&tx1, &root, &proof1));

        // Wrong txid should fail
        let fake = sha256d(b"fake");
        assert!(!verify_spv_proof(&fake, &root, &proof0));
    }

    #[test]
    fn extract_merkle_root_from_header() {
        let mut header = [0u8; 80];
        header[36..68].copy_from_slice(&[0x42; 32]);
        assert_eq!(extract_merkle_root(&header), [0x42; 32]);
    }
}
