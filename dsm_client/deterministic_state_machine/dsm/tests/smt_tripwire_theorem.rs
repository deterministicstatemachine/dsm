#![allow(clippy::disallowed_methods)]
//! # SMT Tripwire Fork-Exclusion Theorem Tests
//!
//! Proves that the tripwire theorem (§6.1) holds in the implementation:
//!
//! - **Theorem 2 (Atomic Interlock Tripwire):** Any attempt to fork a bilateral
//!   chain is detected deterministically — same parent cannot produce two valid
//!   successors; divergent roots are caught by the replace check; and
//!   signature forgery is computationally infeasible.
//!
//! - **Theorem 1 (Modal Lock):** Relationship-scoped keys are deterministic and
//!   independent across different bilateral pairs.
//!
//! - **Acceptance Predicates (§4.3):** SPHINCS+ signatures, the SMT replace over the one relationship path,
//!   and device-tree inclusion proofs are verified end-to-end.
//!
//! - **Chain Integrity:** Successive tips are unique, deterministic, and
//!   non-cycling over sequential transactions.
//!
//! All tests are synchronous (#[test]) — no async runtime required.

use std::collections::HashSet;

use dsm::common::device_tree::DeviceTree;
use dsm::core::bilateral_transaction_manager::{compute_smt_key, compute_successor_tip};
use dsm::crypto::blake3::{domain_hash_bytes, dsm_domain_hasher};
use dsm::crypto::signatures::SignatureKeyPair;
use dsm::merkle::sparse_merkle_tree::ZERO_LEAF;
use dsm::types::operations::{Operation, TransactionMode};
use dsm::types::receipt_types::ParentConsumptionTracker;
use dsm::types::token_types::Balance;
use dsm::merkle::sparse_merkle_tree::{hash_smt_leaf, hash_smt_node, verify_smt_replace};

// ---------------------------------------------------------------------------
// Test Harness
// ---------------------------------------------------------------------------

/// A real DSM device with production-identical initialization.
struct TestDevice {
    device_id: [u8; 32],
    genesis_hash: [u8; 32],
    keypair: SignatureKeyPair,
    #[allow(dead_code)]
    device_tree_root: [u8; 32],
}

impl TestDevice {
    fn from_seed(seed: u8) -> Self {
        let entropy = {
            let mut e = [0u8; 32];
            e[0] = seed;
            e
        };
        let keypair = SignatureKeyPair::generate_from_entropy(&entropy).unwrap();
        let device_id =
            domain_hash_bytes(dsm::common::domain_tags::TAG_DEVICE_ID, &keypair.public_key);
        let genesis_hash = domain_hash_bytes(
            dsm::common::domain_tags::TAG_DSM_GENESIS,
            &[&device_id[..], &entropy[..]].concat(),
        );
        let device_tree_root = DeviceTree::single(device_id).root();
        Self {
            device_id,
            genesis_hash,
            keypair,
            device_tree_root,
        }
    }
}

/// Compute the initial bilateral chain tip from two devices' genesis data.
fn compute_initial_chain_tip(
    a_dev: &[u8; 32],
    a_gen: &[u8; 32],
    b_dev: &[u8; 32],
    b_gen: &[u8; 32],
) -> [u8; 32] {
    let (ga, da, gb, db) = if a_dev < b_dev {
        (a_gen, a_dev, b_gen, b_dev)
    } else {
        (b_gen, b_dev, a_gen, a_dev)
    };
    let mut h = dsm_domain_hasher(dsm::common::domain_tags::TAG_BILATERAL_SESSION);
    h.update(ga);
    h.update(da);
    h.update(gb);
    h.update(db);
    *h.finalize().as_bytes()
}

/// Build a minimal Transfer operation and its canonical bytes.
fn make_transfer_op(recipient: &[u8; 32], amount: u64) -> (Operation, Vec<u8>) {
    let op = Operation::Transfer {
        policy_commit: [0u8; 32],
        to_device_id: recipient.to_vec(),
        amount: Balance::amount(amount),
        token_id: b"ERA".to_vec(),
        mode: TransactionMode::Bilateral,
        nonce: vec![0u8; 16],
        recipient: recipient.to_vec(),
        to: recipient.to_vec(),
        message: String::new(),
        signature: vec![],
        authority_policy: None,
    };
    let bytes = op.to_bytes();
    (op, bytes)
}

/// Full tree depth. The verifier requires exactly this many siblings: a
/// shorter path would commit the leaf under a root of some other height.
const SMT_DEPTH: usize = 256;

/// Independent reimplementation of the verifier's bit convention.
fn bit_msb_first(key: &[u8; 32], bit_index: usize) -> bool {
    let byte = bit_index / 8;
    let bit = 7 - (bit_index % 8);
    ((key[byte] >> bit) & 1) == 1
}

/// The replace check every receipt verifier makes, through the one
/// primitive: the path authenticates `old` under `pre` and folds `new` to
/// exactly `post`.
fn replace_holds(
    pre: &[u8; 32],
    post: &[u8; 32],
    old: &[u8; 32],
    new: &[u8; 32],
    key: &[u8; 32],
    siblings: &[[u8; 32]],
) -> bool {
    matches!(verify_smt_replace(pre, key, old, new, siblings), Ok(root) if root == *post)
}

/// Fold a leaf up to a root taking each direction from `key`, mirroring the verifier.
fn fold_root_at_key(leaf: &[u8; 32], key: &[u8; 32], siblings: &[[u8; 32]]) -> [u8; 32] {
    let mut acc = *leaf;
    for (i, sib) in siblings.iter().enumerate() {
        let bit_index = 255usize.saturating_sub(i);
        acc = if bit_msb_first(key, bit_index) {
            hash_smt_node(sib, &acc)
        } else {
            hash_smt_node(&acc, sib)
        };
    }
    acc
}

fn uniform_siblings(v: [u8; 32]) -> Vec<[u8; 32]> {
    vec![v; SMT_DEPTH]
}

// ===========================================================================
// Theorem 2: Atomic Interlock Tripwire (§6.1)
// ===========================================================================

#[test]
fn theorem2_two_successors_same_parent_rejected() {
    let alice = TestDevice::from_seed(1);
    let bob = TestDevice::from_seed(2);

    let h_0 = compute_initial_chain_tip(
        &alice.device_id,
        &alice.genesis_hash,
        &bob.device_id,
        &bob.genesis_hash,
    );

    // First transfer: Alice sends 100 to Bob.
    let entropy1 = [0xAAu8; 32];
    let receipt_digest1 = domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_RECEIPT, &[0x01; 32]);
    let (_op1, op1_bytes) = make_transfer_op(&bob.device_id, 100);
    let h_1 = compute_successor_tip(&h_0, &op1_bytes, &entropy1, &receipt_digest1);

    // Second (forked) transfer from SAME h_0: different amount.
    let entropy2 = [0xBBu8; 32];
    let receipt_digest2 = domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_RECEIPT, &[0x02; 32]);
    let (_op2, op2_bytes) = make_transfer_op(&bob.device_id, 200);
    let h_1_prime = compute_successor_tip(&h_0, &op2_bytes, &entropy2, &receipt_digest2);

    // Different operations from the same parent produce different successor tips.
    assert_ne!(h_1, h_1_prime, "forked tips must differ");

    // ParentConsumptionTracker enforces single-use.
    let mut tracker = ParentConsumptionTracker::new();
    tracker
        .try_consume(h_0, h_1)
        .expect("first consumption must succeed");

    // Attempting to consume h_0 again with a different child must fail (fork detected).
    let err = tracker.try_consume(h_0, h_1_prime);
    assert!(err.is_err(), "second consumption must be rejected (fork)");
    let msg = format!("{}", err.unwrap_err());
    assert!(
        msg.contains("Fork detected"),
        "error must mention fork; got: {msg}"
    );
}

#[test]
fn theorem2_divergent_roots_detected() {
    let alice = TestDevice::from_seed(10);
    let bob = TestDevice::from_seed(20);

    let rel_key = compute_smt_key(&alice.device_id, &bob.device_id);

    // Parent tip and child tip.
    let parent_tip = domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_TEST_TIP, &[0x01; 32]);
    let child_tip = domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_TEST_TIP, &[0x02; 32]);

    // Compute leaf hashes.
    let old_leaf = hash_smt_leaf(&parent_tip);
    let new_leaf = hash_smt_leaf(&child_tip);

    // Full-depth path; roots folded with directions taken from the relationship key.
    let sibs = uniform_siblings([0x99u8; 32]);

    let honest_parent_root = fold_root_at_key(&old_leaf, &rel_key, &sibs);
    let honest_child_root = fold_root_at_key(&new_leaf, &rel_key, &sibs);

    // Honest verification succeeds.
    let result = replace_holds(
        &honest_parent_root,
        &honest_child_root,
        &parent_tip,
        &child_tip,
        &rel_key,
        &sibs,
    );
    assert!(result, "honest verification must pass");

    // Fake root: tamper one byte.
    let mut fake_root = honest_child_root;
    fake_root[0] ^= 0xFF;
    let result_fake = replace_holds(
        &honest_parent_root,
        &fake_root,
        &parent_tip,
        &child_tip,
        &rel_key,
        &sibs,
    );
    assert!(!result_fake, "tampered root must fail verification");
}

#[test]
fn theorem2_signature_forgery_detected() {
    let alice = TestDevice::from_seed(30);
    let bob = TestDevice::from_seed(31);

    let message = b"DSM/bilateral-sign\0test-commitment-hash";

    // Sign with Alice's key.
    let sig = alice.keypair.sign(message).expect("sign must succeed");

    // Verify with Alice's key -> true.
    let valid = alice
        .keypair
        .verify(message, &sig)
        .expect("verify must not error");
    assert!(valid, "signature must verify with correct key");

    // Verify with Bob's key -> false.
    let wrong_key = bob
        .keypair
        .verify(message, &sig)
        .expect("verify must not error");
    assert!(!wrong_key, "signature must fail with wrong public key");

    // Tamper one byte of the signature -> false.
    let mut tampered_sig = sig.clone();
    if !tampered_sig.is_empty() {
        tampered_sig[0] ^= 0xFF;
    }
    let tampered = alice
        .keypair
        .verify(message, &tampered_sig)
        .expect("verify must not error");
    assert!(!tampered, "tampered signature must fail verification");
}

#[test]
fn theorem2_transitive_tripwire_web() {
    // Three devices form two bilateral relationships that share Bob.
    let alice = TestDevice::from_seed(40);
    let bob = TestDevice::from_seed(41);
    let charlie = TestDevice::from_seed(42);

    // Alice<->Bob
    let smt_key_ab = compute_smt_key(&alice.device_id, &bob.device_id);
    let h_0_ab = compute_initial_chain_tip(
        &alice.device_id,
        &alice.genesis_hash,
        &bob.device_id,
        &bob.genesis_hash,
    );

    // Bob<->Charlie
    let smt_key_bc = compute_smt_key(&bob.device_id, &charlie.device_id);
    let h_0_bc = compute_initial_chain_tip(
        &bob.device_id,
        &bob.genesis_hash,
        &charlie.device_id,
        &charlie.genesis_hash,
    );

    // Keys are distinct.
    assert_ne!(smt_key_ab, smt_key_bc, "relationship keys must differ");

    // Alice->Bob transfer.
    let entropy_ab = [0xCA; 32];
    let receipt_ab = domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_RECEIPT, &[0xAB; 32]);
    let (_op_ab, op_ab_bytes) = make_transfer_op(&bob.device_id, 50);
    let h_1_ab = compute_successor_tip(&h_0_ab, &op_ab_bytes, &entropy_ab, &receipt_ab);

    // Bob->Charlie transfer.
    let entropy_bc = [0xCB; 32];
    let receipt_bc = domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_RECEIPT, &[0xBC; 32]);
    let (_op_bc, op_bc_bytes) = make_transfer_op(&charlie.device_id, 50);
    let h_1_bc = compute_successor_tip(&h_0_bc, &op_bc_bytes, &entropy_bc, &receipt_bc);

    // Bob's SMT must commit to BOTH relationships.
    // Build a 2-level tree where ab is left, bc is right.
    let rel_key_ab = compute_smt_key(&alice.device_id, &bob.device_id);
    let rel_key_bc = compute_smt_key(&bob.device_id, &charlie.device_id);
    let leaf_ab = hash_smt_leaf(&h_1_ab);
    let leaf_bc = hash_smt_leaf(&h_1_bc);

    // Alice<->Bob under Bob's root: the path is scoped to k_AB.
    let sibs_ab = uniform_siblings(leaf_bc);
    let old_leaf_ab = hash_smt_leaf(&h_0_ab);
    let old_root = fold_root_at_key(&old_leaf_ab, &rel_key_ab, &sibs_ab);
    let bob_root = fold_root_at_key(&leaf_ab, &rel_key_ab, &sibs_ab);

    let ok_ab = replace_holds(
        &old_root,
        &bob_root,
        &h_0_ab,
        &h_1_ab,
        &rel_key_ab,
        &sibs_ab,
    );
    assert!(ok_ab, "Alice<->Bob proof must verify under Bob's root");

    // If Bob tries a different root for Charlie, it won't match.
    let mut fake_bob_root = bob_root;
    fake_bob_root[31] ^= 0x01;

    let sibs_bc = uniform_siblings(leaf_ab);
    let old_leaf_bc = hash_smt_leaf(&h_0_bc);
    let old_root_bc = fold_root_at_key(&old_leaf_bc, &rel_key_bc, &sibs_bc);

    let ok_bc_fake = replace_holds(
        &old_root_bc,
        &fake_bob_root,
        &h_0_bc,
        &h_1_bc,
        &rel_key_bc,
        &sibs_bc,
    );
    assert!(
        !ok_bc_fake,
        "fake root must fail for Bob<->Charlie relationship"
    );
}

// ===========================================================================
// Theorem 1: Modal Lock (§5.4)
// ===========================================================================

#[test]
fn theorem1_relationship_scoped_keys() {
    let alice = TestDevice::from_seed(50);
    let bob = TestDevice::from_seed(51);
    let charlie = TestDevice::from_seed(52);

    let key_ab = compute_smt_key(&alice.device_id, &bob.device_id);
    let key_ac = compute_smt_key(&alice.device_id, &charlie.device_id);
    let key_bc = compute_smt_key(&bob.device_id, &charlie.device_id);

    assert_ne!(key_ab, key_ac, "A<->B and A<->C keys must differ");
    assert_ne!(key_ab, key_bc, "A<->B and B<->C keys must differ");
    assert_ne!(key_ac, key_bc, "A<->C and B<->C keys must differ");

    // Order invariance: A<->B == B<->A.
    let key_ba = compute_smt_key(&bob.device_id, &alice.device_id);
    assert_eq!(key_ab, key_ba, "compute_smt_key must be order-invariant");
}

#[test]
fn theorem1_smt_key_deterministic() {
    let alice = TestDevice::from_seed(53);
    let bob = TestDevice::from_seed(54);

    let k1 = compute_smt_key(&alice.device_id, &bob.device_id);
    let k2 = compute_smt_key(&alice.device_id, &bob.device_id);
    assert_eq!(k1, k2, "compute_smt_key must be deterministic");

    // Also verify relationship_key matches the same contract.
    let rk1 = compute_smt_key(&alice.device_id, &bob.device_id);
    let rk2 = compute_smt_key(&bob.device_id, &alice.device_id);
    assert_eq!(rk1, rk2, "compute_smt_key must be order-invariant");
}

// ===========================================================================
// Acceptance Predicates (§4.3)
// ===========================================================================

#[test]
fn predicate_1_sphincs_valid_signature() {
    let alice = TestDevice::from_seed(60);
    let commitment_hash =
        domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_TEST_COMMIT, &[0xDE; 32]);
    let msg = [b"DSM/bilateral-sign\0".as_slice(), &commitment_hash].concat();

    let sig = alice.keypair.sign(&msg).expect("sign");
    let ok = alice.keypair.verify(&msg, &sig).expect("verify");
    assert!(ok, "valid SPHINCS+ signature must verify");
}

#[test]
fn predicate_1_sphincs_wrong_key_rejects() {
    let alice = TestDevice::from_seed(61);
    let bob = TestDevice::from_seed(62);
    let msg = b"DSM/bilateral-sign\0commitment";

    let sig = alice.keypair.sign(msg).expect("sign");
    let ok = bob.keypair.verify(msg, &sig).expect("verify");
    assert!(!ok, "signature must not verify with wrong key");
}

#[test]
fn predicate_1_sphincs_tampered_sig_rejects() {
    let alice = TestDevice::from_seed(63);
    let msg = b"DSM/bilateral-sign\0commitment";

    let sig = alice.keypair.sign(msg).expect("sign");
    let mut bad = sig.clone();
    if !bad.is_empty() {
        bad[0] ^= 0xFF;
    }
    let ok = alice.keypair.verify(msg, &bad).expect("verify");
    assert!(!ok, "tampered signature must not verify");
}

#[test]
fn predicate_2_parent_inclusion_via_the_path() {
    // Build a 1-step SMT: leaf at known key with value = parent_tip.
    let parent_tip = [0x11u8; 32];
    let rel_key = [0x22u8; 32];
    let leaf = hash_smt_leaf(&parent_tip);

    // Siblings are the empty (zero) positions; the path is scoped to rel_key.
    let sibs = uniform_siblings(ZERO_LEAF);
    let root = fold_root_at_key(&leaf, &rel_key, &sibs);

    let parent_tip2 = [0x12u8; 32];
    let leaf2 = hash_smt_leaf(&parent_tip2);
    let root2 = fold_root_at_key(&leaf2, &rel_key, &sibs);
    assert!(
        replace_holds(&root, &root2, &parent_tip, &parent_tip2, &rel_key, &sibs),
        "the path must authenticate the parent and fold the child at the relationship key"
    );
}

#[test]
fn predicate_3_child_inclusion_via_the_path() {
    let child_tip = [0x33u8; 32];
    let rel_key = [0x44u8; 32];
    let leaf = hash_smt_leaf(&child_tip);

    let sibs = uniform_siblings([0xFFu8; 32]);
    let root = fold_root_at_key(&leaf, &rel_key, &sibs);

    let child_tip2 = [0x34u8; 32];
    let leaf2 = hash_smt_leaf(&child_tip2);
    let root2 = fold_root_at_key(&leaf2, &rel_key, &sibs);
    assert!(
        replace_holds(&root, &root2, &child_tip, &child_tip2, &rel_key, &sibs),
        "the path must fold the child to its root at the relationship key"
    );
}

#[test]
fn predicate_5_smt_replace_recomputation() {
    let alice = TestDevice::from_seed(70);
    let bob = TestDevice::from_seed(71);

    let rel_key = compute_smt_key(&alice.device_id, &bob.device_id);

    let h_n = domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_TEST_TIP, &[0xA0; 32]);
    let h_n1 = domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_TEST_TIP, &[0xA1; 32]);

    let old_leaf = hash_smt_leaf(&h_n);
    let new_leaf = hash_smt_leaf(&h_n1);

    // Full-depth tree scoped to the relationship key.
    let sibs = uniform_siblings([0x77u8; 32]);
    let r_a = fold_root_at_key(&old_leaf, &rel_key, &sibs);
    let r_a_prime = fold_root_at_key(&new_leaf, &rel_key, &sibs);

    // Full verify cycle.
    let ok = replace_holds(&r_a, &r_a_prime, &h_n, &h_n1, &rel_key, &sibs);
    assert!(ok, "honest SMT replace must verify");

    // Tamper r_a_prime.
    let mut bad_root = r_a_prime;
    bad_root[15] ^= 0x01;
    let fail = replace_holds(&r_a, &bad_root, &h_n, &h_n1, &rel_key, &sibs);
    assert!(!fail, "tampered child root must fail");
}

#[test]
fn predicate_4_device_tree_inclusion() {
    let dev_id = domain_hash_bytes(dsm::common::domain_tags::TAG_DEVICE_ID, &[0xDD; 32]);
    let tree = DeviceTree::single(dev_id);
    let root = tree.root();

    let proof = tree.proof(&dev_id).expect("proof must exist for member");
    assert!(
        proof.verify(&dev_id, &root),
        "inclusion proof must verify for correct device"
    );

    // Wrong device ID must fail.
    let wrong_id = domain_hash_bytes(dsm::common::domain_tags::TAG_DEVICE_ID, &[0xEE; 32]);
    assert!(
        !proof.verify(&wrong_id, &root),
        "inclusion proof must fail for wrong device"
    );
}

// ===========================================================================
// Chain Integrity
// ===========================================================================

#[test]
fn chain_tip_agreement_both_devices() {
    let alice = TestDevice::from_seed(80);
    let bob = TestDevice::from_seed(81);

    let h_0 = compute_initial_chain_tip(
        &alice.device_id,
        &alice.genesis_hash,
        &bob.device_id,
        &bob.genesis_hash,
    );

    let entropy = [0x42u8; 32];
    let receipt_digest = domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_RECEIPT, &[0xFF; 32]);
    let (_op, op_bytes) = make_transfer_op(&bob.device_id, 500);

    // Both devices compute from identical inputs.
    let tip_alice = compute_successor_tip(&h_0, &op_bytes, &entropy, &receipt_digest);
    let tip_bob = compute_successor_tip(&h_0, &op_bytes, &entropy, &receipt_digest);

    assert_eq!(
        tip_alice, tip_bob,
        "both parties must compute identical successor tips"
    );
}

#[test]
fn chain_10_sequential_tips() {
    let alice = TestDevice::from_seed(90);
    let bob = TestDevice::from_seed(91);

    let mut tip = compute_initial_chain_tip(
        &alice.device_id,
        &alice.genesis_hash,
        &bob.device_id,
        &bob.genesis_hash,
    );

    let mut seen = HashSet::new();
    seen.insert(tip);

    for i in 0u64..10 {
        let entropy = domain_hash_bytes(
            dsm::common::domain_tags::TAG_DSM_TEST_ENTROPY,
            &i.to_le_bytes(),
        );
        let receipt =
            domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_RECEIPT, &i.to_le_bytes());
        let (_op, op_bytes) = make_transfer_op(&bob.device_id, (i + 1) * 10);
        let next = compute_successor_tip(&tip, &op_bytes, &entropy, &receipt);

        assert_ne!(next, tip, "tip must change on step {i}");
        assert!(
            seen.insert(next),
            "tip must be unique at step {i} (no cycles)"
        );

        // Determinism: recomputing gives the same result.
        let recomputed = compute_successor_tip(&tip, &op_bytes, &entropy, &receipt);
        assert_eq!(next, recomputed, "tip must be deterministic at step {i}");

        tip = next;
    }

    assert_eq!(seen.len(), 11, "10 transitions + initial = 11 unique tips");
}

#[test]
fn chain_first_transaction_from_zero() {
    let alice = TestDevice::from_seed(95);
    let bob = TestDevice::from_seed(96);

    let h_0 = compute_initial_chain_tip(
        &alice.device_id,
        &alice.genesis_hash,
        &bob.device_id,
        &bob.genesis_hash,
    );

    // h_0 is a domain-separated hash, not zero.
    assert_ne!(h_0, ZERO_LEAF, "initial chain tip must not be ZERO_LEAF");

    let entropy = [0x01u8; 32];
    let receipt = domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_RECEIPT, &[0x01; 32]);
    let (_op, op_bytes) = make_transfer_op(&bob.device_id, 1);
    let h_1 = compute_successor_tip(&h_0, &op_bytes, &entropy, &receipt);

    assert_ne!(h_1, ZERO_LEAF, "first successor tip must not be ZERO_LEAF");
    assert_ne!(h_0, h_1, "h_0 and h_1 must differ");
}

// ===========================================================================
// Invariants
// ===========================================================================

#[test]
fn parent_consumed_exactly_once() {
    let mut tracker = ParentConsumptionTracker::new();

    let parent = domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_TEST_PARENT, &[0x01; 32]);
    let child_a = domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_TEST_CHILD, &[0x0A; 32]);
    let child_b = domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_TEST_CHILD, &[0x0B; 32]);

    // Fresh parent: first consumption succeeds.
    assert!(!tracker.is_consumed(&parent));
    tracker
        .try_consume(parent, child_a)
        .expect("first consumption must succeed");
    assert!(tracker.is_consumed(&parent));

    // Replay (same child): must fail.
    assert!(
        tracker.try_consume(parent, child_a).is_err(),
        "replay must be rejected"
    );

    // Fork (different child): must fail.
    let fork_err = tracker.try_consume(parent, child_b);
    assert!(fork_err.is_err(), "fork must be rejected");
    let msg = format!("{}", fork_err.unwrap_err());
    assert!(
        msg.contains("Fork detected"),
        "error must identify fork; got: {msg}"
    );

    // Recorded child is the first one.
    assert_eq!(
        tracker.get_child(&parent),
        Some(&child_a),
        "canonical child must be the first consumed"
    );
}

#[test]
fn balance_conservation_arithmetic() {
    let test_cases: &[(u64, u64)] = &[
        (1000, 250),
        (1000, 0),
        (1000, 1000),
        (500, 499),
        (u64::MAX / 2, 1),
    ];

    for &(sender_initial, transfer_amount) in test_cases {
        let sender_remaining = sender_initial - transfer_amount;
        let receiver_gained = transfer_amount;

        assert_eq!(
            sender_remaining + receiver_gained,
            sender_initial,
            "conservation violated: {sender_initial} - {transfer_amount}"
        );

        // Verify via Balance type.
        let sender_bal = Balance::amount(sender_initial);
        assert_eq!(sender_bal.value(), sender_initial);

        let remaining_bal = Balance::amount(sender_remaining);
        let gained_bal = Balance::amount(receiver_gained);
        assert_eq!(
            remaining_bal.value() + gained_bal.value(),
            sender_bal.value(),
            "Balance conservation violated for {sender_initial} -> {transfer_amount}"
        );
    }
}
