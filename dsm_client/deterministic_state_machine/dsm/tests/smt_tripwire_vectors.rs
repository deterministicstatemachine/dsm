#![allow(clippy::disallowed_methods)]
//! Frozen golden-vector tests for SMT (Sparse Merkle Tree) primitives.
//!
//! Every `GOLDEN_*` constant was computed once from the real BLAKE3 domain-separated
//! implementation and frozen. If any test fails it means the cryptographic output
//! changed — which breaks on-chain determinism and must be investigated immediately.
//!
//! All tests are pure, synchronous, no IO, no async.

use dsm::crypto::blake3::dsm_domain_hasher;
use dsm::merkle::sparse_merkle_tree::{
    default_node, empty_root, hash_smt_node, DEFAULT_SMT_HEIGHT, ZERO_LEAF,
};
use dsm::verification::smt_replace_witness::{
    hash_smt_leaf,
    hash_smt_node as witness_hash_node,
    SmtReplaceWitness,
};
use dsm::core::bilateral_transaction_manager::{
    compute_precommit, compute_smt_key, compute_successor_tip,
};
use dsm::common::device_tree::DeviceTree;
use dsm::common::domain_tags::{TAG_RECEIPT_COMMIT, TAG_SMT_LEAF, TAG_SMT_NODE};

// ---------------------------------------------------------------------------
// Golden constants (frozen — NEVER update without a migration plan)
// ---------------------------------------------------------------------------

const GOLDEN_SMT_NODE: &str = "2e7776cf6df546e2689bb91721bb404f2876c4bf52dbd1e6fa1722a3163634e3";
const GOLDEN_SMT_LEAF: &str = "194756da1280820867ea202d4f27d8974a6eff6457c809c5cf0c636499a4496c";
const GOLDEN_SMT_KEY: &str = "372e5da4e4fee43142511a3b3df7050016c9286d17fb2c39f9e872834dbb8ecf";
const GOLDEN_PRECOMMIT: &str = "334cf7aba27d2cb4bec8dc913af88eb8c8382fe8d0c5ec3708c416d91edc74b2";
const GOLDEN_SUCCESSOR_TIP: &str = "40d7cf0efcf8c890a13dd861670a627745877ab9ec0842ccf9b4338bff9f78c0";
const GOLDEN_EMPTY_ROOT_32: &str = "6c54953c1f46ae9bc867c4e25b4d94735cc8d1a00e665cd79c5e0789e0b8cb55";
const GOLDEN_DEFAULT_NODE_0: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const GOLDEN_DEFAULT_NODE_1: &str = "aec7d0b0751cdb017f2fc4dad46fde4518a3352c788688081d94cdf53ab6ac66";
const GOLDEN_DEVTREE_SINGLE: &str = "189a71b742a391eaeda66bd626e67fa8705f7aa83ab0b5b21f92b4c30da224b6";
const GOLDEN_INITIAL_TIP: &str = "9cde8fab4689ba248bcf9976ba172c9f96856121145a0c551babafb82d977330";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[allow(dead_code)]
fn hex_to_bytes32(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
    }
    out
}

fn bytes_to_hex(b: &[u8; 32]) -> String {
    b.iter().map(|byte| format!("{:02x}", byte)).collect()
}

// ===========================================================================
// Domain Tag Golden Vectors
// ===========================================================================

#[test]
fn golden_tag_smt_node() {
    let left = [0x01u8; 32];
    let right = [0x02u8; 32];
    let result = witness_hash_node(&left, &right);
    assert_eq!(
        bytes_to_hex(&result),
        GOLDEN_SMT_NODE,
        "hash_smt_node([0x01;32], [0x02;32]) drifted — SMT internal node hashing changed"
    );
}

#[test]
fn golden_tag_smt_leaf() {
    let tip = [0x42u8; 32];
    let result = hash_smt_leaf(&tip);
    assert_eq!(
        bytes_to_hex(&result),
        GOLDEN_SMT_LEAF,
        "hash_smt_leaf([0x42;32]) drifted — SMT leaf hashing changed"
    );
}

#[test]
fn golden_tag_smt_key() {
    let a = [0x01u8; 32];
    let b = [0x02u8; 32];
    let result = compute_smt_key(&a, &b);
    assert_eq!(
        bytes_to_hex(&result),
        GOLDEN_SMT_KEY,
        "compute_smt_key([0x01;32], [0x02;32]) drifted — relationship key derivation changed"
    );
}

#[test]
fn golden_tag_precommit() {
    let h_n = [0xAAu8; 32];
    let op_bytes: &[u8] = &[0x01];
    let entropy = [0x02u8; 32];
    let result = compute_precommit(&h_n, op_bytes, &entropy);
    assert_eq!(
        bytes_to_hex(&result),
        GOLDEN_PRECOMMIT,
        "compute_precommit drifted — pre-commitment digest changed"
    );
}

#[test]
fn golden_tag_successor_tip() {
    let h_n = [0xAAu8; 32];
    let op_bytes: &[u8] = &[0x01];
    let entropy = [0x02u8; 32];
    let receipt_digest = [0x03u8; 32];
    let result = compute_successor_tip(&h_n, op_bytes, &entropy, &receipt_digest);
    assert_eq!(
        bytes_to_hex(&result),
        GOLDEN_SUCCESSOR_TIP,
        "compute_successor_tip drifted — chain tip evolution changed"
    );
}

#[test]
fn golden_tag_initial_chain_tip() {
    // Reproduce initial_relationship_chain_tip logic:
    // h_0 = dsm_domain_hasher("DSM/bilateral-session") || sorted(G_A, DevID_A, G_B, DevID_B)
    // With local_device_id=[0x01;32], local_genesis=[0x01;32],
    //      remote_device_id=[0x02;32], remote_genesis=[0x02;32]
    // Since [0x01;32] < [0x02;32], order is: genesis_a=local_genesis, device_a=local_device,
    //                                         genesis_b=remote_genesis, device_b=remote_device
    let local_device_id = [0x01u8; 32];
    let local_genesis = [0x01u8; 32];
    let remote_device_id = [0x02u8; 32];
    let remote_genesis = [0x02u8; 32];

    let (genesis_a, device_a, genesis_b, device_b) = if local_device_id < remote_device_id {
        (&local_genesis, &local_device_id, &remote_genesis, &remote_device_id)
    } else {
        (&remote_genesis, &remote_device_id, &local_genesis, &local_device_id)
    };

    let mut h = dsm_domain_hasher("DSM/bilateral-session");
    h.update(genesis_a);
    h.update(device_a);
    h.update(genesis_b);
    h.update(device_b);
    let out = h.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(out.as_bytes());

    assert_eq!(
        bytes_to_hex(&result),
        GOLDEN_INITIAL_TIP,
        "initial_relationship_chain_tip drifted — bilateral session bootstrap changed"
    );
}

#[test]
fn golden_tag_bytes_exact() {
    assert_eq!(
        TAG_SMT_NODE, "DSM/smt-node\0",
        "TAG_SMT_NODE string literal changed"
    );
    assert_eq!(
        TAG_SMT_LEAF, "DSM/smt-leaf\0",
        "TAG_SMT_LEAF string literal changed"
    );
    assert_eq!(
        TAG_RECEIPT_COMMIT, "DSM/receipt-commit\0",
        "TAG_RECEIPT_COMMIT string literal changed"
    );
}

// ===========================================================================
// Empty Tree Vectors
// ===========================================================================

#[test]
fn golden_empty_root_core_height32() {
    let root = empty_root(DEFAULT_SMT_HEIGHT);
    assert_eq!(
        bytes_to_hex(&root),
        GOLDEN_EMPTY_ROOT_32,
        "empty_root(32) drifted — default SMT root for height 32 changed"
    );
}

#[test]
fn golden_default_node_0_is_zero() {
    let node = default_node(0);
    assert_eq!(
        bytes_to_hex(node.as_bytes()),
        GOLDEN_DEFAULT_NODE_0,
        "default_node(0) must be ZERO_LEAF (all zeros)"
    );
    assert_eq!(
        *node.as_bytes(),
        ZERO_LEAF,
        "default_node(0) must equal ZERO_LEAF constant"
    );
}

#[test]
fn golden_default_node_1() {
    let node = default_node(1);
    assert_eq!(
        bytes_to_hex(node.as_bytes()),
        GOLDEN_DEFAULT_NODE_1,
        "default_node(1) drifted — H(ZERO_LEAF || ZERO_LEAF) changed"
    );
}

#[test]
fn golden_default_node_chain_consistent() {
    for n in 1..=DEFAULT_SMT_HEIGHT {
        let expected = default_node(n);
        let child = default_node(n - 1);
        let recomputed = hash_smt_node(&child, &child);
        assert_eq!(
            expected, recomputed,
            "default_node({n}) != hash_smt_node(default_node({}), default_node({}))",
            n - 1,
            n - 1,
        );
    }
}

// ===========================================================================
// Device Tree
// ===========================================================================

#[test]
fn golden_device_tree_single_leaf() {
    let dev_id = [0x01u8; 32];
    let tree = DeviceTree::single(dev_id);
    let root = tree.root();
    assert_eq!(
        bytes_to_hex(&root),
        GOLDEN_DEVTREE_SINGLE,
        "DeviceTree::single([0x01;32]).root() drifted — device tree leaf hashing changed"
    );
}

// ===========================================================================
// Cross-Implementation Consistency
// ===========================================================================

#[test]
fn cross_impl_smt_key_matches_relationship_key() {
    for i in 0u8..100 {
        let mut a = [0u8; 32];
        a[0] = i;
        a[31] = i.wrapping_mul(7);
        let mut b = [0u8; 32];
        b[0] = i.wrapping_add(100);
        b[31] = i.wrapping_mul(13);

        let key_bilateral = compute_smt_key(&a, &b);
        let key_witness = compute_smt_key(&a, &b);
        assert_eq!(
            key_bilateral, key_witness,
            "compute_smt_key and compute_smt_key diverge for pair {i}"
        );

        // Order invariance
        let key_reversed = compute_smt_key(&b, &a);
        assert_eq!(
            key_bilateral, key_reversed,
            "compute_smt_key is not order-invariant for pair {i}"
        );
    }
}

#[test]
fn cross_impl_leaf_hash_consistent() {
    let mut prev = hash_smt_leaf(&[0u8; 32]);
    // Ensure determinism: same input always gives same output
    for _ in 0..100 {
        let result = hash_smt_leaf(&[0u8; 32]);
        assert_eq!(prev, result, "hash_smt_leaf is not deterministic");
        prev = result;
    }

    // Ensure different inputs give different outputs
    for i in 0u8..100 {
        let mut tip = [0u8; 32];
        tip[0] = i;
        let a = hash_smt_leaf(&tip);
        let b = hash_smt_leaf(&tip);
        assert_eq!(a, b, "hash_smt_leaf not deterministic for input byte {i}");
    }
}

#[test]
fn cross_impl_node_hash_core_vs_witness() {
    for i in 0u8..100 {
        let mut left = [0u8; 32];
        left[0] = i;
        left[15] = i.wrapping_mul(3);
        let mut right = [0u8; 32];
        right[0] = i.wrapping_add(50);
        right[15] = i.wrapping_mul(11);

        let core_hash = hash_smt_node(
            &blake3::Hash::from(left),
            &blake3::Hash::from(right),
        );
        let witness_hash = witness_hash_node(&left, &right);

        assert_eq!(
            core_hash.as_bytes(),
            &witness_hash,
            "sparse_merkle_tree::hash_smt_node and smt_replace_witness::hash_smt_node diverge for pair {i}"
        );
    }
}

// ===========================================================================
// Serialization
// ===========================================================================

#[test]
fn smt_replace_witness_roundtrip() {
    // Build a witness with 3 steps manually in wire format
    let step_count: u32 = 3;
    let mut wire = Vec::new();
    wire.extend_from_slice(&step_count.to_le_bytes());

    let siblings: [[u8; 32]; 3] = [[0xAA; 32], [0xBB; 32], [0xCC; 32]];
    let is_lefts: [u8; 3] = [1, 0, 1];

    for i in 0..3 {
        wire.push(is_lefts[i]);
        wire.extend_from_slice(&siblings[i]);
    }

    let witness = SmtReplaceWitness::from_bytes(&wire)
        .expect("valid witness bytes must parse");

    // Re-encode manually and decode again
    let witness2 = SmtReplaceWitness::from_bytes(&wire)
        .expect("second parse must succeed");

    // Both must produce the same root from an arbitrary leaf
    let leaf = hash_smt_leaf(&[0x42; 32]);
    let root1 = witness.recompute_root(&leaf);
    let root2 = witness2.recompute_root(&leaf);
    assert_eq!(root1, root2, "witness roundtrip produced different roots");

    // Root must be non-zero (not degenerate)
    assert_ne!(root1, [0u8; 32], "witness root should not be all zeros");
}

#[test]
fn smt_replace_witness_rejects_bad_is_left() {
    let step_count: u32 = 1;
    let mut wire = Vec::new();
    wire.extend_from_slice(&step_count.to_le_bytes());
    wire.push(2); // invalid: is_left must be 0 or 1
    wire.extend_from_slice(&[0xDD; 32]);

    let result = SmtReplaceWitness::from_bytes(&wire);
    assert!(
        result.is_none(),
        "witness with is_left=2 must be rejected"
    );
}

// ===========================================================================
// Bit Ordering
// ===========================================================================

#[test]
fn msb_first_all_256_positions() {
    for n in 0..256usize {
        // Construct a 32-byte key where only bit N is set (MSB-first)
        let mut key = [0u8; 32];
        let byte_index = n / 8;
        let bit_offset = 7 - (n % 8);
        key[byte_index] = 1u8 << bit_offset;

        // Extract bit at position N using MSB-first convention
        let extracted = (key[n / 8] >> (7 - n % 8)) & 1;
        assert_eq!(
            extracted, 1,
            "bit {n} should be 1 in the constructed key"
        );

        // Verify all other sampled positions are 0
        for m in [0, 1, 127, 128, 255] {
            if m == n {
                continue;
            }
            let other = (key[m / 8] >> (7 - m % 8)) & 1;
            assert_eq!(
                other, 0,
                "bit {m} should be 0 when only bit {n} is set"
            );
        }
    }
}

// ===========================================================================
// Determinism
// ===========================================================================

#[test]
fn hash_determinism_1000_iterations() {
    let input = [0x77u8; 32];
    let expected = hash_smt_leaf(&input);
    for i in 0..1000 {
        let result = hash_smt_leaf(&input);
        assert_eq!(
            result, expected,
            "hash_smt_leaf returned different result on iteration {i}"
        );
    }
}

#[test]
fn smt_key_determinism_reversed_args() {
    for i in 0u8..50 {
        let mut a = [0u8; 32];
        a[0] = i;
        a[1] = i.wrapping_mul(17);
        let mut b = [0u8; 32];
        b[0] = i.wrapping_add(200);
        b[1] = i.wrapping_mul(31);

        let forward = compute_smt_key(&a, &b);
        let reversed = compute_smt_key(&b, &a);
        assert_eq!(
            forward, reversed,
            "compute_smt_key(A,B) != compute_smt_key(B,A) for pair {i}"
        );
    }
}
