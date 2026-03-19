//! Bitcoin header chain verification for SPV proof hardening.
//!
//! Validates that a block header connects back to a known checkpoint via
//! prev_hash chaining. Each intermediate header must meet its stated PoW.
//! This prevents fabricated-header attacks where an attacker creates a
//! block header with valid PoW at an easy difficulty target.
//!
//! Checkpoints are hardcoded per network and updated with app releases.
//! For signet/testnet, checkpoint enforcement is skipped.
//!
//! Formal correspondence:
//! - on mainnet, successful verification here feeds the `checkpointed`
//!   predicate used by the dBTC trust-reduction artifacts;
//! - on signet/testnet, bypassed checks mean runtime behavior is intentionally
//!   weaker than the formal mainnet predicate.

use crate::types::error::DsmError;
use super::spv::{block_hash, extract_nbits, nbits_to_target, verify_block_header_work};
use super::types::BitcoinNetwork;

/// A known Bitcoin block header checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    pub height: u32,
    /// Block hash in internal byte order (little-endian of display hash)
    pub block_hash: [u8; 32],
}

/// Extract prev_block_hash from a raw 80-byte Bitcoin block header (bytes 4..36).
pub fn extract_prev_hash(header: &[u8; 80]) -> [u8; 32] {
    let mut prev = [0u8; 32];
    prev.copy_from_slice(&header[4..36]);
    prev
}

/// Returns hardcoded checkpoints for the given network.
///
/// Mainnet checkpoints are well-known block hashes at ~100K block intervals.
/// Block hashes are in internal byte order (reversed from the display format).
///
/// Signet/Testnet return empty — checkpoint-rooted chain verification
/// is skipped for test networks (matching `verify_entry_anchor` behaviour).
/// Signet's genesis-only checkpoint would require ~200K headers to reach,
/// making it impractical. SPV proof (Merkle + PoW) still runs for all networks.
pub fn checkpoints(network: BitcoinNetwork) -> &'static [Checkpoint] {
    match network {
        BitcoinNetwork::Mainnet => &MAINNET_CHECKPOINTS,
        // Test networks: no checkpoint enforcement.
        // Signet genesis-only is unreachable and testnet has frequent reorgs —
        // both are impractical for SPV anchoring.
        _ => &[],
    }
}

/// Minimum nBits (maximum target) allowed per network.
///
/// For mainnet and signet, blocks must have difficulty at or above this floor.
/// Returns `None` for networks where difficulty floor is not enforced.
///
/// nBits uses Bitcoin's compact target format: lower nBits = harder difficulty.
/// The floor is set conservatively at ~2016 era difficulty.
pub fn difficulty_floor(network: BitcoinNetwork) -> Option<u32> {
    match network {
        // 0x1900ffff ≈ difficulty ~16M — well below current mainnet but
        // expensive enough that fabricating a single block is impractical.
        BitcoinNetwork::Mainnet => Some(0x1900ffff),
        _ => None,
    }
}

/// Check if a block header's nBits meets the difficulty floor for a network.
///
/// In Bitcoin's compact target format, a *lower* nBits exponent byte means
/// *higher* difficulty. We compare the full 256-bit targets: the block's
/// target must be <= the floor target.
pub fn meets_difficulty_floor(header: &[u8; 80], network: BitcoinNetwork) -> bool {
    let floor_nbits = match difficulty_floor(network) {
        Some(f) => f,
        None => return true, // no floor for this network
    };

    let block_nbits = extract_nbits(header);
    let block_target = nbits_to_target(block_nbits);
    let floor_target = nbits_to_target(floor_nbits);

    // block_target <= floor_target means block is at least as hard as the floor
    for i in 0..32 {
        if block_target[i] < floor_target[i] {
            return true;
        }
        if block_target[i] > floor_target[i] {
            return false;
        }
    }
    true // equal
}

/// Verify that a block header chains back to a known checkpoint via `prev_hash` linkage.
///
/// # Arguments
/// - `block_header`: The 80-byte block header containing the transaction
/// - `header_chain`: Intermediate headers connecting a checkpoint to `block_header`.
///   Can be empty if `block_header`'s prev_hash is itself a checkpoint.
/// - `network`: Which Bitcoin network (determines checkpoint set and difficulty floor)
///
/// # Returns
/// - `Ok(true)` if the chain is valid and rooted at a known checkpoint
/// - `Ok(false)` if the chain doesn't validate
/// - `Err` on malformed input
///
/// # Verification steps
/// 1. Testnet/Signet: always returns `Ok(true)` (no checkpoint enforcement)
/// 2. Build the full chain: `[header_chain..., block_header]`
/// 3. The first header's `prev_hash` must match a known checkpoint's `block_hash`
/// 4. Each subsequent header's `prev_hash == block_hash(previous_header)`
/// 5. Each header passes PoW validation and difficulty floor check
pub fn verify_header_chain(
    block_header: &[u8; 80],
    header_chain: &[[u8; 80]],
    network: BitcoinNetwork,
) -> Result<bool, DsmError> {
    let known_checkpoints = checkpoints(network);

    // If no checkpoints for this network: test networks pass (no PoW enforcement),
    // mainnet fails closed (cannot verify without anchors).
    // Matches verify_entry_anchor which also bypasses Testnet/Signet.
    //
    // NON_PAPER_MODE: The paper (§17, Definition 13) requires checkpoint-rooted
    // header-chain enforcement on all networks. This bypass is intentional for
    // development/testing only. When this branch is taken, runtime acceptance
    // no longer implies the formal `RustVerifierAccepted` mainnet predicate.
    // See audit finding §5 and `bitcoin::trust`.
    if known_checkpoints.is_empty() {
        return match network {
            BitcoinNetwork::Testnet | BitcoinNetwork::Signet => Ok(true),
            _ => Err(DsmError::Validation {
                context: "No checkpoints available for network; SPV verification cannot proceed"
                    .to_string(),
                source: None,
            }),
        };
    }

    // Build ordered list of headers to validate: [header_chain..., block_header]
    // The first header's prev_hash must be a known checkpoint.

    // Determine the first header in the chain
    let first_header = if header_chain.is_empty() {
        block_header
    } else {
        &header_chain[0]
    };

    // Check that the first header's prev_hash matches a known checkpoint
    let first_prev_hash = extract_prev_hash(first_header);
    let rooted = known_checkpoints
        .iter()
        .any(|cp| cp.block_hash == first_prev_hash);

    if !rooted {
        return Ok(false);
    }

    // Validate header_chain internal linkage
    for i in 1..header_chain.len() {
        let expected_prev = block_hash(&header_chain[i - 1]);
        let actual_prev = extract_prev_hash(&header_chain[i]);
        if expected_prev != actual_prev {
            return Ok(false);
        }
    }

    // Validate that block_header links to the last header in header_chain
    if let Some(last_header) = header_chain.last() {
        let last_chain_hash = block_hash(last_header);
        let block_prev = extract_prev_hash(block_header);
        if last_chain_hash != block_prev {
            return Ok(false);
        }
    }

    // Validate PoW and difficulty floor for every header in the chain
    for h in header_chain.iter() {
        if !verify_block_header_work(h) {
            return Ok(false);
        }
        if !meets_difficulty_floor(h, network) {
            return Ok(false);
        }
    }

    // Validate block_header itself (PoW already checked by verify_tx_in_block,
    // but check difficulty floor here)
    if !meets_difficulty_floor(block_header, network) {
        return Ok(false);
    }

    Ok(true)
}

/// Verify that an exit block header chains forward from a known entry anchor.
///
/// dBTC paper §12.2.3, Invariant 19: the exit block must be on the same
/// chain as the entry block. For mainnet, `connecting_headers` must form a
/// valid prev_hash chain from `entry_header` to `exit_header`.
///
/// For signet/testnet: always returns `Ok(true)` (both headers are synthetic).
///
/// # Arguments
/// - `entry_header`: The 80-byte block header cached at DLV creation (BTC→dBTC entry)
/// - `exit_header`: The 80-byte block header provided in the exit proof (dBTC→BTC exit)
/// - `connecting_headers`: Intermediate headers from entry to exit (may be empty
///   if exit_header's prev_hash == block_hash(entry_header))
/// - `network`: Bitcoin network
pub fn verify_entry_anchor(
    entry_header: &[u8; 80],
    exit_header: &[u8; 80],
    connecting_headers: &[[u8; 80]],
    network: BitcoinNetwork,
) -> Result<bool, DsmError> {
    // For testnet/signet: always returns Ok(true) (headers are synthetic)
    //
    // NON_PAPER_MODE: The paper (§21.1, §21.3) requires entry-anchor chain
    // verification on all networks. This bypass is intentional for development
    // and testing only; it must not be used on mainnet. When bypassed,
    // `sameChain` in the formal trust model is not established.
    // See audit finding §5 and `bitcoin::trust`.
    if matches!(network, BitcoinNetwork::Testnet | BitcoinNetwork::Signet) {
        return Ok(true);
    }

    // Build the chain: [entry_header, connecting_headers..., exit_header]
    // Verify that each header's prev_hash == block_hash(previous_header)
    let entry_hash = block_hash(entry_header);

    let first_after_entry = if connecting_headers.is_empty() {
        exit_header
    } else {
        &connecting_headers[0]
    };

    // First header after entry must link back to entry
    let first_prev = extract_prev_hash(first_after_entry);
    if first_prev != entry_hash {
        return Ok(false);
    }

    // Validate connecting_headers internal linkage
    for i in 1..connecting_headers.len() {
        let expected_prev = block_hash(&connecting_headers[i - 1]);
        let actual_prev = extract_prev_hash(&connecting_headers[i]);
        if expected_prev != actual_prev {
            return Ok(false);
        }
    }

    // Validate that exit_header links to the last connecting header
    if let Some(last_connecting) = connecting_headers.last() {
        let last_hash = block_hash(last_connecting);
        let exit_prev = extract_prev_hash(exit_header);
        if last_hash != exit_prev {
            return Ok(false);
        }
    }

    // Validate PoW and difficulty floor for each connecting header
    for h in connecting_headers {
        if !verify_block_header_work(h) {
            return Ok(false);
        }
        if !meets_difficulty_floor(h, network) {
            return Ok(false);
        }
    }

    Ok(true)
}

// =========================================================================
// Mainnet checkpoints — well-known block hashes at ~100K block intervals.
// Block hashes are in internal byte order (little-endian of display format).
// Display hash (big-endian) is the reversed form shown on block explorers.
//
// To convert display hash to internal byte order:
//   display "000000000019d6689c..." → reverse bytes → internal order
// =========================================================================

/// Helper: convert a hex display hash (big-endian) to internal byte order at compile time.
/// We store them as const arrays since const fn hex decode isn't stable.
const fn rev32(b: [u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = b[31 - i];
        i += 1;
    }
    out
}

// Block 0 (genesis): 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
const GENESIS_HASH_BE: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0xd6, 0x68, 0x9c, 0x08, 0x5a, 0xe1, 0x65, 0x83, 0x1e, 0x93,
    0x4f, 0xf7, 0x63, 0xae, 0x46, 0xa2, 0xa6, 0xc1, 0x72, 0xb3, 0xf1, 0xb6, 0x0a, 0x8c, 0xe2, 0x6f,
];

// Block 100000: 000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506
const BLOCK_100K_BE: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xba, 0x27, 0xaa, 0x20, 0x0b, 0x1c, 0xec, 0xaa, 0xd4, 0x78,
    0xd2, 0xb0, 0x04, 0x32, 0x34, 0x6c, 0x3f, 0x1f, 0x39, 0x86, 0xda, 0x1a, 0xfd, 0x33, 0xe5, 0x06,
];

// Block 200000: 000000000000034a7dedef4a161fa058a2d67a173a90155f3a2fe6fc132e0ebf
const BLOCK_200K_BE: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x4a, 0x7d, 0xed, 0xef, 0x4a, 0x16, 0x1f, 0xa0, 0x58,
    0xa2, 0xd6, 0x7a, 0x17, 0x3a, 0x90, 0x15, 0x5f, 0x3a, 0x2f, 0xe6, 0xfc, 0x13, 0x2e, 0x0e, 0xbf,
];

// Block 300000: 000000000000000082ccf8f1557c5d40b21edabb18d2d691cfbf87118bac7254
const BLOCK_300K_BE: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x82, 0xcc, 0xf8, 0xf1, 0x55, 0x7c, 0x5d, 0x40,
    0xb2, 0x1e, 0xda, 0xbb, 0x18, 0xd2, 0xd6, 0x91, 0xcf, 0xbf, 0x87, 0x11, 0x8b, 0xac, 0x72, 0x54,
];

// Block 400000: 000000000000000004ec466ce4732fe6f1ed1cddc2ed4b328fff5224276e3f6f
const BLOCK_400K_BE: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xec, 0x46, 0x6c, 0xe4, 0x73, 0x2f, 0xe6,
    0xf1, 0xed, 0x1c, 0xdd, 0xc2, 0xed, 0x4b, 0x32, 0x8f, 0xff, 0x52, 0x24, 0x27, 0x6e, 0x3f, 0x6f,
];

// Block 500000: 00000000000000000024fb37364cbf81fd49cc2d51c09c75c35433c3a1945d04
const BLOCK_500K_BE: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0xfb, 0x37, 0x36, 0x4c, 0xbf, 0x81,
    0xfd, 0x49, 0xcc, 0x2d, 0x51, 0xc0, 0x9c, 0x75, 0xc3, 0x54, 0x33, 0xc3, 0xa1, 0x94, 0x5d, 0x04,
];

// Block 600000: 00000000000000000007316856900e76b4f7a9139cfbfba89842c8d196cd5f57
const BLOCK_600K_BE: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x31, 0x68, 0x56, 0x90, 0x0e, 0x76,
    0xb4, 0xf7, 0xa9, 0x13, 0x9c, 0xfb, 0xfb, 0xa8, 0x98, 0x42, 0xc8, 0xd1, 0x96, 0xcd, 0x5f, 0x57,
];

// Block 700000: 0000000000000000000590fc0f3eba193a278534220b2b37e9849e1a770ca959
const BLOCK_700K_BE: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x90, 0xfc, 0x0f, 0x3e, 0xba, 0x19,
    0x3a, 0x27, 0x85, 0x34, 0x22, 0x0b, 0x2b, 0x37, 0xe9, 0x84, 0x9e, 0x1a, 0x77, 0x0c, 0xa9, 0x59,
];

// Block 800000: 00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72f2ea775
const BLOCK_800K_BE: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xa7, 0xc4, 0xc1, 0xe4, 0x8d, 0x76,
    0xc5, 0xa3, 0x79, 0x02, 0x16, 0x5a, 0x27, 0x01, 0x56, 0xb7, 0xa8, 0xd7, 0x2f, 0x2e, 0xa7, 0x75,
];

// Block 850000: 00000000000000000002a0b5db2a7f8d9087464c2586b546be7bce8eb53b8187
const BLOCK_850K_BE: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xa0, 0xb5, 0xdb, 0x2a, 0x7f, 0x8d,
    0x90, 0x87, 0x46, 0x4c, 0x25, 0x86, 0xb5, 0x46, 0xbe, 0x7b, 0xce, 0x8e, 0xb5, 0x3b, 0x81, 0x87,
];

// Block 880000: 000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880
const BLOCK_880K_BE: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0b, 0x17, 0x28, 0x3c, 0x3c, 0x40,
    0x05, 0x07, 0x96, 0x9a, 0x9c, 0x2a, 0xfd, 0x1d, 0xcf, 0x20, 0x82, 0xec, 0x5c, 0xca, 0x28, 0x80,
];

static MAINNET_CHECKPOINTS: [Checkpoint; 11] = [
    Checkpoint {
        height: 0,
        block_hash: rev32(GENESIS_HASH_BE),
    },
    Checkpoint {
        height: 100_000,
        block_hash: rev32(BLOCK_100K_BE),
    },
    Checkpoint {
        height: 200_000,
        block_hash: rev32(BLOCK_200K_BE),
    },
    Checkpoint {
        height: 300_000,
        block_hash: rev32(BLOCK_300K_BE),
    },
    Checkpoint {
        height: 400_000,
        block_hash: rev32(BLOCK_400K_BE),
    },
    Checkpoint {
        height: 500_000,
        block_hash: rev32(BLOCK_500K_BE),
    },
    Checkpoint {
        height: 600_000,
        block_hash: rev32(BLOCK_600K_BE),
    },
    Checkpoint {
        height: 700_000,
        block_hash: rev32(BLOCK_700K_BE),
    },
    Checkpoint {
        height: 800_000,
        block_hash: rev32(BLOCK_800K_BE),
    },
    Checkpoint {
        height: 850_000,
        block_hash: rev32(BLOCK_850K_BE),
    },
    Checkpoint {
        height: 880_000,
        block_hash: rev32(BLOCK_880K_BE),
    },
];

// Signet checkpoint data retained for reference but not used in verification.
// checkpoints() returns empty for all test networks (signet, testnet)
// because signet genesis-only is unreachable for practical block heights (~200K+).
// See verify_entry_anchor for the matching bypass pattern.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_prev_hash_correct() {
        let mut header = [0u8; 80];
        header[4..36].copy_from_slice(&[0xAB; 32]);
        assert_eq!(extract_prev_hash(&header), [0xAB; 32]);
    }

    #[test]
    fn checkpoints_mainnet_non_empty() {
        let cps = checkpoints(BitcoinNetwork::Mainnet);
        assert!(cps.len() >= 9);
        assert_eq!(cps[0].height, 0);
    }

    #[test]
    fn checkpoints_signet_empty() {
        // Signet bypasses checkpoint enforcement (genesis-only is unreachable
        // at practical block heights). Matches verify_entry_anchor pattern.
        let cps = checkpoints(BitcoinNetwork::Signet);
        assert!(cps.is_empty());
    }

    #[test]
    fn checkpoints_testnet_empty() {
        let cps = checkpoints(BitcoinNetwork::Testnet);
        assert_eq!(cps.len(), 0);
    }

    #[test]
    fn difficulty_floor_mainnet_set() {
        assert!(difficulty_floor(BitcoinNetwork::Mainnet).is_some());
    }

    #[test]
    fn difficulty_floor_signet_none() {
        // Signet uses authority-signed blocks with easy nBits (0x1e0377ae).
        // No difficulty floor enforcement for test networks.
        assert!(difficulty_floor(BitcoinNetwork::Signet).is_none());
    }

    #[test]
    fn difficulty_floor_testnet_none() {
        assert!(difficulty_floor(BitcoinNetwork::Testnet).is_none());
    }

    #[test]
    fn test_networks_always_pass() {
        // Testnet and signet have no checkpoint enforcement — any header chain is accepted.
        let header = [0u8; 80];
        assert!(verify_header_chain(&header, &[], BitcoinNetwork::Testnet).unwrap());
        assert!(verify_header_chain(&header, &[], BitcoinNetwork::Signet).unwrap());
    }

    #[test]
    fn mainnet_empty_chain_unrooted_fails() {
        // A block whose prev_hash doesn't match any checkpoint should fail
        let mut header = [0u8; 80];
        header[4..36].copy_from_slice(&[0xFF; 32]); // random prev_hash
        assert!(!verify_header_chain(&header, &[], BitcoinNetwork::Mainnet).unwrap());
    }

    #[test]
    fn mainnet_rooted_at_genesis_passes() {
        // A block whose prev_hash is the genesis block hash
        let genesis_hash = checkpoints(BitcoinNetwork::Mainnet)[0].block_hash;
        let mut header = [0u8; 80];
        header[4..36].copy_from_slice(&genesis_hash);
        // Set easy nBits for test (below difficulty floor, so this should fail
        // the difficulty floor check for mainnet)
        header[72..76].copy_from_slice(&0x20ffffffu32.to_le_bytes());

        // Even though rooted at checkpoint, the difficulty floor check should fail
        // because 0x20ffffff is way above (easier than) 0x1900ffff
        assert!(!verify_header_chain(&header, &[], BitcoinNetwork::Mainnet).unwrap());
    }

    #[test]
    fn header_chain_broken_link_fails() {
        // Build a chain where header[1].prev_hash doesn't match hash(header[0])
        let genesis_hash = checkpoints(BitcoinNetwork::Mainnet)[0].block_hash;

        let mut h0 = [0u8; 80];
        h0[4..36].copy_from_slice(&genesis_hash);
        h0[72..76].copy_from_slice(&0x1800ffffu32.to_le_bytes()); // hard enough

        let mut h1 = [0u8; 80];
        h1[4..36].copy_from_slice(&[0xDE; 32]); // wrong prev_hash
        h1[72..76].copy_from_slice(&0x1800ffffu32.to_le_bytes());

        let mut block = [0u8; 80];
        block[72..76].copy_from_slice(&0x1800ffffu32.to_le_bytes());

        let chain = vec![h0, h1];
        assert!(!verify_header_chain(&block, &chain, BitcoinNetwork::Mainnet).unwrap());
    }

    #[test]
    fn meets_difficulty_floor_easy_fails_mainnet() {
        // 0x20ffffff is very easy — should fail mainnet floor
        let mut header = [0u8; 80];
        header[72..76].copy_from_slice(&0x20ffffffu32.to_le_bytes());
        assert!(!meets_difficulty_floor(&header, BitcoinNetwork::Mainnet));
    }

    #[test]
    fn meets_difficulty_floor_hard_passes_mainnet() {
        // 0x1800ffff is harder than 0x1900ffff — should pass
        let mut header = [0u8; 80];
        header[72..76].copy_from_slice(&0x1800ffffu32.to_le_bytes());
        assert!(meets_difficulty_floor(&header, BitcoinNetwork::Mainnet));
    }

    #[test]
    fn meets_difficulty_floor_testnet_always() {
        let mut header = [0u8; 80];
        header[72..76].copy_from_slice(&0x20ffffffu32.to_le_bytes());
        assert!(meets_difficulty_floor(&header, BitcoinNetwork::Testnet));
    }
}
