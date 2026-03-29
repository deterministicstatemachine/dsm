#![allow(clippy::disallowed_methods)]

use dsm::crypto::blake3::{dsm_domain_hasher, domain_hash_bytes};
use dsm::crypto::signatures::SignatureKeyPair;
use dsm::verification::smt_replace_witness::{hash_smt_leaf, verify_tripwire_smt_replace};
use dsm::core::bilateral_transaction_manager::{
    compute_smt_key, compute_precommit, compute_successor_tip,
};
use dsm::common::device_tree::DeviceTree;
use dsm::types::operations::{Operation, TransactionMode, VerificationType};
use dsm::types::token_types::Balance;

use dsm::merkle::sparse_merkle_tree::{SparseMerkleTree, SmtInclusionProof};
use dsm_sdk::security::shared_smt;
use dsm_sdk::sdk::app_state::AppState;
use dsm_sdk::sdk::receipts::{
    build_bilateral_receipt_with_smt, deserialize_inclusion_proof, serialize_inclusion_proof,
    verify_receipt_bytes, DeviceTreeAcceptanceCommitment,
};

use serial_test::serial;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn setup_test_env() {
    std::env::set_var("DSM_SDK_TEST_MODE", "1");
    let _ = dsm_sdk::storage_utils::set_storage_base_dir(std::path::PathBuf::from(
        "./.dsm_smt_smoke_testdata",
    ));
    dsm_sdk::storage::client_db::reset_database_for_tests();
    let _ = dsm_sdk::storage::client_db::init_database();
}

struct TestDevice {
    device_id: [u8; 32],
    genesis_hash: [u8; 32],
    keypair: SignatureKeyPair,
    smt: SparseMerkleTree,
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
        let device_id = domain_hash_bytes("DSM/device-id", &keypair.public_key);
        let genesis_hash =
            domain_hash_bytes("DSM/genesis", &[&device_id[..], &entropy[..]].concat());
        let device_tree_root = DeviceTree::single(device_id).root();
        let smt = SparseMerkleTree::new(256);
        Self {
            device_id,
            genesis_hash,
            keypair,
            smt,
            device_tree_root,
        }
    }

    fn configure_appstate(&self) {
        AppState::set_identity_info(
            self.device_id.to_vec(),
            self.keypair.public_key.clone(),
            self.genesis_hash.to_vec(),
            self.device_tree_root.to_vec(),
        );
        AppState::set_has_identity(true);
    }
}

fn compute_h0(a: &TestDevice, b: &TestDevice) -> [u8; 32] {
    let (ga, da, gb, db) = if a.device_id < b.device_id {
        (&a.genesis_hash, &a.device_id, &b.genesis_hash, &b.device_id)
    } else {
        (&b.genesis_hash, &b.device_id, &a.genesis_hash, &a.device_id)
    };
    let mut h = dsm_domain_hasher("DSM/bilateral-session");
    h.update(ga);
    h.update(da);
    h.update(gb);
    h.update(db);
    *h.finalize().as_bytes()
}

// ---------------------------------------------------------------------------
// Transfer helper
// ---------------------------------------------------------------------------

struct TransferResult {
    h_n_plus_1: [u8; 32],
    pre_root: [u8; 32],
    post_root: [u8; 32],
    parent_proof: SmtInclusionProof,
    child_proof: SmtInclusionProof,
    receipt_bytes: Vec<u8>,
}

fn execute_transfer(
    sender: &mut TestDevice,
    receiver: &mut TestDevice,
    smt_key: &[u8; 32],
    h_n: &[u8; 32],
    tx_count: u64,
    amount: u64,
) -> TransferResult {
    let op = Operation::Transfer {
        to_device_id: receiver.device_id.to_vec(),
        amount: Balance::from_state(amount, [0u8; 32], 0),
        token_id: b"ERA".to_vec(),
        mode: TransactionMode::Bilateral,
        nonce: vec![0u8; 16],
        verification: VerificationType::Standard,
        pre_commit: None,
        recipient: receiver.device_id.to_vec(),
        to: receiver.device_id.to_vec(),
        message: String::new(),
        signature: vec![],
    };
    let op_bytes = op.to_bytes();

    let entropy = domain_hash_bytes(
        "DSM/test-entropy",
        &[&h_n[..], &tx_count.to_le_bytes()[..]].concat(),
    );

    let receipt_digest = compute_precommit(h_n, &op_bytes, &entropy);
    let h_n_plus_1 = compute_successor_tip(h_n, &op_bytes, &entropy, &receipt_digest);

    // SMT-Replace on sender
    let pre_root = *sender.smt.root();
    let parent_proof = sender.smt.get_inclusion_proof(smt_key, 256).unwrap();
    sender.smt.update_leaf(smt_key, &h_n_plus_1).unwrap();
    let post_root = *sender.smt.root();
    let child_proof = sender.smt.get_inclusion_proof(smt_key, 256).unwrap();

    // Configure AppState for receipt building
    sender.configure_appstate();

    // Build receipt via production code path
    let receipt_bytes = build_bilateral_receipt_with_smt(
        sender.device_id,
        receiver.device_id,
        *h_n,
        h_n_plus_1,
        pre_root,
        post_root,
        serialize_inclusion_proof(&parent_proof),
        serialize_inclusion_proof(&child_proof),
        Some(DeviceTreeAcceptanceCommitment::from_root(
            sender.device_tree_root,
        )),
    )
    .expect("receipt must build");

    // Receiver also updates their SMT
    receiver.smt.update_leaf(smt_key, &h_n_plus_1).unwrap();

    TransferResult {
        h_n_plus_1,
        pre_root,
        post_root,
        parent_proof,
        child_proof,
        receipt_bytes,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[tokio::test]
#[serial]
async fn smoke_full_smt_roundtrip() {
    setup_test_env();

    let mut a = TestDevice::from_seed(0x10);
    let mut b = TestDevice::from_seed(0x20);

    let smt_key = compute_smt_key(&a.device_id, &b.device_id);
    let h_0 = compute_h0(&a, &b);

    // Insert h_0 into both SMTs
    a.smt.update_leaf(&smt_key, &h_0).unwrap();
    b.smt.update_leaf(&smt_key, &h_0).unwrap();

    // Execute one transfer
    let result = execute_transfer(&mut a, &mut b, &smt_key, &h_0, 0, 100);

    // Verify child proof against post_root
    assert!(
        SparseMerkleTree::verify_proof_against_root(&result.child_proof, &result.post_root),
        "child proof must verify against post_root"
    );
    // Verify parent proof against pre_root
    assert!(
        SparseMerkleTree::verify_proof_against_root(&result.parent_proof, &result.pre_root),
        "parent proof must verify against pre_root"
    );
    // Receipt bytes non-empty
    assert!(
        !result.receipt_bytes.is_empty(),
        "receipt bytes must be non-empty"
    );
}

#[tokio::test]
#[serial]
async fn smoke_receiver_verifies_sender_proofs() {
    setup_test_env();

    let mut a = TestDevice::from_seed(0x10);
    let mut b = TestDevice::from_seed(0x20);

    let smt_key = compute_smt_key(&a.device_id, &b.device_id);
    let h_0 = compute_h0(&a, &b);

    a.smt.update_leaf(&smt_key, &h_0).unwrap();
    b.smt.update_leaf(&smt_key, &h_0).unwrap();

    let result = execute_transfer(&mut a, &mut b, &smt_key, &h_0, 0, 50);

    // Receiver verifies child proof against post_root
    assert!(SparseMerkleTree::verify_proof_against_root(
        &result.child_proof,
        &result.post_root
    ));

    // Tamper with root: flip one byte
    let mut tampered_root = result.post_root;
    tampered_root[0] ^= 0xFF;
    assert!(
        !SparseMerkleTree::verify_proof_against_root(&result.child_proof, &tampered_root),
        "tampered root must fail verification"
    );
}

#[tokio::test]
#[serial]
async fn smoke_verify_receipt_bytes_accepts_authenticated_commitment() {
    setup_test_env();

    let mut a = TestDevice::from_seed(0x10);
    let mut b = TestDevice::from_seed(0x20);

    let smt_key = compute_smt_key(&a.device_id, &b.device_id);
    let h_0 = compute_h0(&a, &b);

    a.smt.update_leaf(&smt_key, &h_0).unwrap();
    b.smt.update_leaf(&smt_key, &h_0).unwrap();

    let result = execute_transfer(&mut a, &mut b, &smt_key, &h_0, 0, 25);

    assert!(
        verify_receipt_bytes(
            &result.receipt_bytes,
            Some(DeviceTreeAcceptanceCommitment::from_root(
                a.device_tree_root
            )),
        ),
        "receipt verification must accept the correct authenticated device-tree commitment"
    );
}

#[tokio::test]
#[serial]
async fn smoke_verify_receipt_bytes_rejects_missing_authenticated_commitment() {
    setup_test_env();

    let mut a = TestDevice::from_seed(0x30);
    let mut b = TestDevice::from_seed(0x40);

    let smt_key = compute_smt_key(&a.device_id, &b.device_id);
    let h_0 = compute_h0(&a, &b);

    a.smt.update_leaf(&smt_key, &h_0).unwrap();
    b.smt.update_leaf(&smt_key, &h_0).unwrap();

    let result = execute_transfer(&mut a, &mut b, &smt_key, &h_0, 0, 25);

    assert!(
        !verify_receipt_bytes(&result.receipt_bytes, None),
        "receipt verification must reject when the authenticated device-tree commitment is absent"
    );
}

#[tokio::test]
#[serial]
async fn smoke_verify_receipt_bytes_rejects_wrong_authenticated_commitment() {
    setup_test_env();

    let mut a = TestDevice::from_seed(0x50);
    let mut b = TestDevice::from_seed(0x60);

    let smt_key = compute_smt_key(&a.device_id, &b.device_id);
    let h_0 = compute_h0(&a, &b);

    a.smt.update_leaf(&smt_key, &h_0).unwrap();
    b.smt.update_leaf(&smt_key, &h_0).unwrap();

    let result = execute_transfer(&mut a, &mut b, &smt_key, &h_0, 0, 25);

    assert!(
        !verify_receipt_bytes(
            &result.receipt_bytes,
            Some(DeviceTreeAcceptanceCommitment::from_root(b.device_tree_root)),
        ),
        "receipt verification must reject when the authenticated device-tree commitment does not match π_dev"
    );
}

#[tokio::test]
#[serial]
async fn smoke_receipt_failure_scope_is_relationship_local() {
    setup_test_env();

    let mut a = TestDevice::from_seed(0x11);
    let mut b = TestDevice::from_seed(0x22);
    let mut c = TestDevice::from_seed(0x33);
    let mut d = TestDevice::from_seed(0x44);

    let smt_key_ab = compute_smt_key(&a.device_id, &b.device_id);
    let smt_key_cd = compute_smt_key(&c.device_id, &d.device_id);
    let h_0_ab = compute_h0(&a, &b);
    let h_0_cd = compute_h0(&c, &d);

    a.smt.update_leaf(&smt_key_ab, &h_0_ab).unwrap();
    b.smt.update_leaf(&smt_key_ab, &h_0_ab).unwrap();
    c.smt.update_leaf(&smt_key_cd, &h_0_cd).unwrap();
    d.smt.update_leaf(&smt_key_cd, &h_0_cd).unwrap();

    let result_ab = execute_transfer(&mut a, &mut b, &smt_key_ab, &h_0_ab, 0, 10);
    let result_cd = execute_transfer(&mut c, &mut d, &smt_key_cd, &h_0_cd, 0, 20);

    assert!(
        !verify_receipt_bytes(&result_ab.receipt_bytes, None),
        "missing authenticated commitment must reject the affected relationship path"
    );
    assert!(
        verify_receipt_bytes(
            &result_cd.receipt_bytes,
            Some(DeviceTreeAcceptanceCommitment::from_root(
                c.device_tree_root
            )),
        ),
        "an unrelated relationship with a valid authenticated commitment must continue to verify"
    );
}

#[tokio::test]
#[serial]
async fn smoke_multi_relationship_3_peers() {
    setup_test_env();

    let mut a = TestDevice::from_seed(0x10);
    let mut b = TestDevice::from_seed(0x20);
    let c = TestDevice::from_seed(0x30);
    let d = TestDevice::from_seed(0x40);

    let key_ab = compute_smt_key(&a.device_id, &b.device_id);
    let key_ac = compute_smt_key(&a.device_id, &c.device_id);
    let key_ad = compute_smt_key(&a.device_id, &d.device_id);

    let h0_ab = compute_h0(&a, &b);
    let h0_ac = compute_h0(&a, &c);
    let h0_ad = compute_h0(&a, &d);

    // Insert all h_0 values into A's SMT
    a.smt.update_leaf(&key_ab, &h0_ab).unwrap();
    a.smt.update_leaf(&key_ac, &h0_ac).unwrap();
    a.smt.update_leaf(&key_ad, &h0_ad).unwrap();
    b.smt.update_leaf(&key_ab, &h0_ab).unwrap();

    // Execute a transfer A<->B
    let result = execute_transfer(&mut a, &mut b, &key_ab, &h0_ab, 0, 100);
    let new_root = *a.smt.root();

    // A<->C proof still verifies against A's new root
    let proof_ac = a.smt.get_inclusion_proof(&key_ac, 256).unwrap();
    assert!(
        SparseMerkleTree::verify_proof_against_root(&proof_ac, &new_root),
        "A<->C proof must still verify after A<->B update"
    );

    // A<->D proof still verifies against A's new root
    let proof_ad = a.smt.get_inclusion_proof(&key_ad, 256).unwrap();
    assert!(
        SparseMerkleTree::verify_proof_against_root(&proof_ad, &new_root),
        "A<->D proof must still verify after A<->B update"
    );

    // Sanity: A<->B child proof verifies against new root
    assert!(SparseMerkleTree::verify_proof_against_root(
        &result.child_proof,
        &result.post_root
    ));
}

#[tokio::test]
#[serial]
async fn smoke_10_roundtrip_transfers() {
    setup_test_env();

    let mut a = TestDevice::from_seed(0x10);
    let mut b = TestDevice::from_seed(0x20);

    let smt_key = compute_smt_key(&a.device_id, &b.device_id);
    let h_0 = compute_h0(&a, &b);

    a.smt.update_leaf(&smt_key, &h_0).unwrap();
    b.smt.update_leaf(&smt_key, &h_0).unwrap();

    let mut current_tip = h_0;

    for i in 0..10u64 {
        let result = execute_transfer(&mut a, &mut b, &smt_key, &current_tip, i, 10);

        // After each transfer, child proof verifies against new root
        let root = *a.smt.root();
        let proof = a.smt.get_inclusion_proof(&smt_key, 256).unwrap();
        assert!(
            SparseMerkleTree::verify_proof_against_root(&proof, &root),
            "proof must verify at round {i}"
        );

        current_tip = result.h_n_plus_1;
    }

    // Verify final tip by recomputing from h_0
    let mut expected_tip = h_0;
    for i in 0..10u64 {
        let op = Operation::Transfer {
            to_device_id: b.device_id.to_vec(),
            amount: Balance::from_state(10, [0u8; 32], 0),
            token_id: b"ERA".to_vec(),
            mode: TransactionMode::Bilateral,
            nonce: vec![0u8; 16],
            verification: VerificationType::Standard,
            pre_commit: None,
            recipient: b.device_id.to_vec(),
            to: b.device_id.to_vec(),
            message: String::new(),
            signature: vec![],
        };
        let op_bytes = op.to_bytes();
        let entropy = domain_hash_bytes(
            "DSM/test-entropy",
            &[&expected_tip[..], &i.to_le_bytes()[..]].concat(),
        );
        let receipt_digest = compute_precommit(&expected_tip, &op_bytes, &entropy);
        expected_tip = compute_successor_tip(&expected_tip, &op_bytes, &entropy, &receipt_digest);
    }

    assert_eq!(
        current_tip, expected_tip,
        "final tip must match recomputed chain"
    );
}

#[tokio::test]
#[serial]
async fn smoke_eviction_boundary() {
    setup_test_env();

    let mut smt = SparseMerkleTree::new(256);

    // Generate 257 distinct keys
    let mut keys: Vec<[u8; 32]> = Vec::with_capacity(257);
    for i in 0u32..257 {
        keys.push(domain_hash_bytes("DSM/test-key", &i.to_le_bytes()));
    }

    let value = [1u8; 32];

    // Insert 256 keys
    for key in &keys[..256] {
        smt.update_leaf(key, &value).unwrap();
    }

    // All 256 proofs verify
    let root_256 = *smt.root();
    for key in &keys[..256] {
        let proof = smt.get_inclusion_proof(key, 256).unwrap();
        assert!(
            SparseMerkleTree::verify_proof_against_root(&proof, &root_256),
            "all 256 proofs must verify"
        );
    }

    // Insert 257th key -- oldest (keys[0]) evicted
    smt.update_leaf(&keys[256], &value).unwrap();

    // 255 surviving proofs still verify (keys[1..256])
    let root_257 = *smt.root();
    for key in &keys[1..256] {
        let proof = smt.get_inclusion_proof(key, 256).unwrap();
        assert!(
            SparseMerkleTree::verify_proof_against_root(&proof, &root_257),
            "surviving proofs must verify after eviction"
        );
    }

    // The 257th key also verifies
    let proof_257 = smt.get_inclusion_proof(&keys[256], 256).unwrap();
    assert!(SparseMerkleTree::verify_proof_against_root(
        &proof_257, &root_257
    ));

    // Evicted key returns a ZERO_LEAF non-inclusion proof (key no longer in tree)
    let evicted_proof = smt.get_inclusion_proof(&keys[0], 256).unwrap();
    assert_eq!(
        evicted_proof.value,
        Some(dsm::merkle::sparse_merkle_tree::ZERO_LEAF),
        "evicted key must produce ZERO_LEAF proof"
    );
}

#[tokio::test]
#[serial]
async fn smoke_concurrent_5_relationships() {
    setup_test_env();

    let mut a = TestDevice::from_seed(0x01);
    let mut peers: Vec<TestDevice> = (0..5).map(|i| TestDevice::from_seed(0x10 + i)).collect();

    let mut smt_keys = Vec::new();
    let mut tips = Vec::new();

    // Set up all 5 relationships
    for peer in &mut *peers {
        let key = compute_smt_key(&a.device_id, &peer.device_id);
        let h0 = compute_h0(&a, peer);
        a.smt.update_leaf(&key, &h0).unwrap();
        peer.smt.update_leaf(&key, &h0).unwrap();
        smt_keys.push(key);
        tips.push(h0);
    }

    // 3 transfers per relationship (15 total)
    for rel in 0..5 {
        for round in 0..3u64 {
            let result = execute_transfer(
                &mut a,
                &mut peers[rel],
                &smt_keys[rel],
                &tips[rel],
                round,
                10,
            );
            tips[rel] = result.h_n_plus_1;
        }
    }

    // All 5 inclusion proofs verify against final root
    let final_root = *a.smt.root();
    for (i, key) in smt_keys.iter().enumerate() {
        let proof = a.smt.get_inclusion_proof(key, 256).unwrap();
        assert!(
            SparseMerkleTree::verify_proof_against_root(&proof, &final_root),
            "relationship {i} proof must verify against final root"
        );
    }
}

#[tokio::test]
#[serial]
async fn smoke_tripwire_witness_roundtrip() {
    setup_test_env();

    let a = TestDevice::from_seed(0x10);
    let b = TestDevice::from_seed(0x20);

    let h_0 = compute_h0(&a, &b);
    let _rel_key = compute_smt_key(&a.device_id, &b.device_id);

    // Compute h_1
    let op = Operation::Transfer {
        to_device_id: b.device_id.to_vec(),
        amount: Balance::from_state(100, [0u8; 32], 0),
        token_id: b"ERA".to_vec(),
        mode: TransactionMode::Bilateral,
        nonce: vec![0u8; 16],
        verification: VerificationType::Standard,
        pre_commit: None,
        recipient: b.device_id.to_vec(),
        to: b.device_id.to_vec(),
        message: String::new(),
        signature: vec![],
    };
    let op_bytes = op.to_bytes();
    let entropy = domain_hash_bytes(
        "DSM/test-entropy",
        &[&h_0[..], &0u64.to_le_bytes()[..]].concat(),
    );
    let receipt_digest = compute_precommit(&h_0, &op_bytes, &entropy);
    let h_1 = compute_successor_tip(&h_0, &op_bytes, &entropy, &receipt_digest);

    // For a zero-depth witness (single-leaf tree), the root IS the leaf hash.
    // recompute_root with empty path returns the leaf hash unchanged.
    let parent_root = hash_smt_leaf(&h_0);
    let child_root = hash_smt_leaf(&h_1);

    // Zero-depth witness: u32 LE path length = 0
    let witness_bytes: Vec<u8> = 0u32.to_le_bytes().to_vec();

    let ok = verify_tripwire_smt_replace(&parent_root, &child_root, &h_0, &h_1, &witness_bytes)
        .expect("verify must not error");

    assert!(
        ok,
        "tripwire verification must succeed for zero-depth witness"
    );

    // Tampered child tip must fail
    let mut bad_tip = h_1;
    bad_tip[31] ^= 0x01;
    let bad =
        verify_tripwire_smt_replace(&parent_root, &child_root, &h_0, &bad_tip, &witness_bytes)
            .expect("verify must not error on bad tip");

    assert!(!bad, "tampered tip must fail tripwire verification");
}

#[tokio::test]
#[serial]
async fn smoke_chain_tip_agreement_independent_devices() {
    setup_test_env();

    // Two separate TestDevices created independently with same seeds
    let a1 = TestDevice::from_seed(0x10);
    let b1 = TestDevice::from_seed(0x20);

    let a2 = TestDevice::from_seed(0x10);
    let b2 = TestDevice::from_seed(0x20);

    let h0_1 = compute_h0(&a1, &b1);
    let h0_2 = compute_h0(&a2, &b2);
    assert_eq!(h0_1, h0_2, "h_0 must be identical for same-seed devices");

    // Compute h_1 on both independently
    let op = Operation::Transfer {
        to_device_id: b1.device_id.to_vec(),
        amount: Balance::from_state(42, [0u8; 32], 0),
        token_id: b"ERA".to_vec(),
        mode: TransactionMode::Bilateral,
        nonce: vec![0u8; 16],
        verification: VerificationType::Standard,
        pre_commit: None,
        recipient: b1.device_id.to_vec(),
        to: b1.device_id.to_vec(),
        message: String::new(),
        signature: vec![],
    };
    let op_bytes = op.to_bytes();
    let entropy = domain_hash_bytes(
        "DSM/test-entropy",
        &[&h0_1[..], &0u64.to_le_bytes()[..]].concat(),
    );
    let rd1 = compute_precommit(&h0_1, &op_bytes, &entropy);
    let tip1 = compute_successor_tip(&h0_1, &op_bytes, &entropy, &rd1);

    let rd2 = compute_precommit(&h0_2, &op_bytes, &entropy);
    let tip2 = compute_successor_tip(&h0_2, &op_bytes, &entropy, &rd2);

    assert_eq!(
        tip1, tip2,
        "h_{{n+1}} must be byte-identical across independent devices"
    );
}

#[tokio::test]
#[serial]
async fn smoke_modal_lock_full_lifecycle() {
    setup_test_env();

    let a = TestDevice::from_seed(0x10);
    let b = TestDevice::from_seed(0x20);
    let smt_key = compute_smt_key(&a.device_id, &b.device_id);

    // set_pending_online: was not set, returns true
    assert!(
        shared_smt::set_pending_online(&smt_key).await,
        "first set_pending_online must return true"
    );

    // is_pending_online: true
    assert!(
        shared_smt::is_pending_online(&smt_key).await,
        "must be pending after set"
    );

    // clear
    shared_smt::clear_pending_online(&smt_key).await;

    // is_pending_online: false
    assert!(
        !shared_smt::is_pending_online(&smt_key).await,
        "must not be pending after clear"
    );
}

#[tokio::test]
#[serial]
async fn smoke_receipt_canonical_determinism() {
    setup_test_env();

    let a = TestDevice::from_seed(0x10);
    let b = TestDevice::from_seed(0x20);

    let smt_key = compute_smt_key(&a.device_id, &b.device_id);
    let h_0 = compute_h0(&a, &b);

    // Precompute common transfer data
    let op = Operation::Transfer {
        to_device_id: b.device_id.to_vec(),
        amount: Balance::from_state(100, [0u8; 32], 0),
        token_id: b"ERA".to_vec(),
        mode: TransactionMode::Bilateral,
        nonce: vec![0u8; 16],
        verification: VerificationType::Standard,
        pre_commit: None,
        recipient: b.device_id.to_vec(),
        to: b.device_id.to_vec(),
        message: String::new(),
        signature: vec![],
    };
    let op_bytes = op.to_bytes();
    let entropy = domain_hash_bytes(
        "DSM/test-entropy",
        &[&h_0[..], &0u64.to_le_bytes()[..]].concat(),
    );
    let receipt_digest = compute_precommit(&h_0, &op_bytes, &entropy);
    let h_1 = compute_successor_tip(&h_0, &op_bytes, &entropy, &receipt_digest);

    // Build two independent SMTs and collect proofs
    let build_receipt = |seed_a: u8, seed_b: u8| -> Vec<u8> {
        let dev_a = TestDevice::from_seed(seed_a);
        let dev_b = TestDevice::from_seed(seed_b);

        let mut smt = SparseMerkleTree::new(256);
        smt.update_leaf(&smt_key, &h_0).unwrap();
        let pre_root = *smt.root();
        let parent_proof = smt.get_inclusion_proof(&smt_key, 256).unwrap();
        smt.update_leaf(&smt_key, &h_1).unwrap();
        let post_root = *smt.root();
        let child_proof = smt.get_inclusion_proof(&smt_key, 256).unwrap();

        dev_a.configure_appstate();

        build_bilateral_receipt_with_smt(
            dev_a.device_id,
            dev_b.device_id,
            h_0,
            h_1,
            pre_root,
            post_root,
            serialize_inclusion_proof(&parent_proof),
            serialize_inclusion_proof(&child_proof),
            Some(DeviceTreeAcceptanceCommitment::from_root(
                dev_a.device_tree_root,
            )),
        )
        .expect("receipt must build")
    };

    let receipt1 = build_receipt(0x10, 0x20);
    let receipt2 = build_receipt(0x10, 0x20);

    assert_eq!(
        receipt1, receipt2,
        "receipts built from identical inputs must be byte-identical"
    );
}

#[tokio::test]
#[serial]
async fn smoke_first_transaction_zero_leaf_edge() {
    setup_test_env();

    let a = TestDevice::from_seed(0x10);
    let b = TestDevice::from_seed(0x20);

    let smt_key = compute_smt_key(&a.device_id, &b.device_id);
    let h_0 = compute_h0(&a, &b);

    let mut smt = SparseMerkleTree::new(256);

    // Brand new SMT: get_inclusion_proof for absent key returns a valid
    // ZERO_LEAF non-inclusion proof that verifies against the empty-tree root.
    let absent_proof = smt.get_inclusion_proof(&smt_key, 256).unwrap();
    assert_eq!(
        absent_proof.value,
        Some(dsm::merkle::sparse_merkle_tree::ZERO_LEAF),
        "absent key must produce ZERO_LEAF proof"
    );
    assert!(
        SparseMerkleTree::verify_proof_against_root(&absent_proof, smt.root()),
        "ZERO_LEAF proof must verify against empty-tree root"
    );

    // Insert h_0
    smt.update_leaf(&smt_key, &h_0).unwrap();

    // Now proof succeeds
    let proof_h0 = smt.get_inclusion_proof(&smt_key, 256).unwrap();
    assert!(
        SparseMerkleTree::verify_proof_against_root(&proof_h0, smt.root()),
        "proof for h_0 must verify"
    );

    // Compute h_1
    let op = Operation::Transfer {
        to_device_id: b.device_id.to_vec(),
        amount: Balance::from_state(10, [0u8; 32], 0),
        token_id: b"ERA".to_vec(),
        mode: TransactionMode::Bilateral,
        nonce: vec![0u8; 16],
        verification: VerificationType::Standard,
        pre_commit: None,
        recipient: b.device_id.to_vec(),
        to: b.device_id.to_vec(),
        message: String::new(),
        signature: vec![],
    };
    let op_bytes = op.to_bytes();
    let entropy = domain_hash_bytes(
        "DSM/test-entropy",
        &[&h_0[..], &0u64.to_le_bytes()[..]].concat(),
    );
    let receipt_digest = compute_precommit(&h_0, &op_bytes, &entropy);
    let h_1 = compute_successor_tip(&h_0, &op_bytes, &entropy, &receipt_digest);

    // Update to h_1
    smt.update_leaf(&smt_key, &h_1).unwrap();
    let proof_h1 = smt.get_inclusion_proof(&smt_key, 256).unwrap();
    assert!(
        SparseMerkleTree::verify_proof_against_root(&proof_h1, smt.root()),
        "proof for h_1 must verify"
    );
}

#[tokio::test]
#[serial]
async fn smoke_appstate_device_tree_root_canonical() {
    setup_test_env();

    let dev = TestDevice::from_seed(0x42);
    dev.configure_appstate();

    let stored_root = AppState::get_device_tree_root()
        .expect("device tree root must be Some after configure_appstate");

    let expected = DeviceTree::single(dev.device_id).root();
    assert_eq!(
        stored_root, expected,
        "AppState device_tree_root must equal DeviceTree::single(device_id).root()"
    );

    let stored_commitment = AppState::get_device_tree_commitment()
        .expect("device tree commitment must be Some after configure_appstate");
    assert_eq!(
        stored_commitment.root(),
        expected,
        "AppState device_tree_commitment must wrap the canonical persisted R_G"
    );
}

/// Validate that adding a contact stores the sender's Device Tree root (R_G)
/// in the contacts table, so that receipt verification during `storage.sync`
/// can succeed (§2.3 / §4.3#3).
///
/// Both `store_contact` (client_db) and the explicit `store_contact_device_tree_root`
/// call (added in contact_sdk.rs) ensure R_G is persisted.  This test validates
/// the end-to-end invariant: after a contact is stored, `verify_receipt_bytes`
/// succeeds for any receipt built with that contact's device_id as the sender.
#[tokio::test]
#[serial]
async fn contact_add_stores_device_tree_root() {
    setup_test_env();

    // Contact (Bob) details — Bob is the sender whose R_G the receiver (Alice) needs.
    let mut bob_id = [0u8; 32];
    bob_id[0] = 0xB1;
    let mut bob_genesis = [0u8; 32];
    bob_genesis[0] = 0xB2;

    use dsm_sdk::storage::client_db::{
        store_contact, get_contact_device_tree_commitment, ContactRecord,
    };
    let record = ContactRecord {
        contact_id: "c_bob".to_string(),
        device_id: bob_id.to_vec(),
        alias: "Bob".to_string(),
        genesis_hash: bob_genesis.to_vec(),
        current_chain_tip: None,
        added_at: 0,
        verified: true,
        verification_proof: None,
        metadata: std::collections::HashMap::new(),
        ble_address: None,
        status: "Created".to_string(),
        needs_online_reconcile: false,
        last_seen_online_counter: 0,
        last_seen_ble_counter: 0,
        public_key: vec![],
        previous_chain_tip: None,
    };
    store_contact(&record).expect("store_contact must succeed");

    // After store_contact, R_G must be available for the contact.
    // Both the internal UPDATE in store_contact and the explicit call in
    // contact_sdk.rs ensure this invariant is satisfied.
    let expected_root = DeviceTree::single(bob_id).root();
    let commitment = get_contact_device_tree_commitment(&bob_id)
        .expect("device tree commitment must be Some after store_contact");
    assert_eq!(
        commitment.root(),
        expected_root,
        "stored R_G must equal DeviceTree::single(bob_id).root()"
    );

    // End-to-end smoke-check: build a receipt as Bob (sender) and verify as Alice (receiver).
    // This exercises the full verify_receipt_bytes code path used in storage.sync.
    let mut alice_id = [0u8; 32];
    alice_id[0] = 0xA1;
    let mut alice_genesis = [0u8; 32];
    alice_genesis[0] = 0xA2;

    // Set AppState to Bob (sender) for receipt construction.
    AppState::set_identity_info(
        bob_id.to_vec(),
        vec![0u8; 64],
        bob_genesis.to_vec(),
        vec![0u8; 32],
    );
    AppState::set_has_identity(true);

    let smt_a_arc = shared_smt::init_shared_smt(256);
    let smt_key = dsm::core::bilateral_transaction_manager::compute_smt_key(&bob_id, &alice_id);
    let h0 = compute_h0(
        &TestDevice {
            device_id: bob_id,
            genesis_hash: bob_genesis,
            keypair: SignatureKeyPair::generate_from_entropy(&[0xB1u8; 32]).unwrap(),
            smt: SparseMerkleTree::new(256),
            device_tree_root: expected_root,
        },
        &TestDevice {
            device_id: alice_id,
            genesis_hash: alice_genesis,
            keypair: SignatureKeyPair::generate_from_entropy(&[0xA1u8; 32]).unwrap(),
            smt: SparseMerkleTree::new(256),
            device_tree_root: DeviceTree::single(alice_id).root(),
        },
    );

    let h1 = {
        let nonce = [0u8; 32];
        let op_bytes = b"test-op".to_vec();
        let sigma =
            dsm::core::bilateral_transaction_manager::compute_precommit(&h0, &op_bytes, &nonce);
        dsm::core::bilateral_transaction_manager::compute_successor_tip(
            &h0, &op_bytes, &nonce, &sigma,
        )
    };

    let (pre_root, post_root, parent_proof_bytes, child_proof_bytes) = {
        let mut smt = smt_a_arc.write().await;
        // Establish h0 as the initial relationship tip (mirrors establish_relationship).
        smt.update_leaf(&smt_key, &h0)
            .expect("initial h0 insert must succeed");
        // Now advance h0 → h1 (the actual transfer); parent_proof proves h0 ∈ pre_root.
        let result = smt
            .smt_replace(&smt_key, &h1)
            .expect("smt_replace must succeed");
        (
            result.pre_root,
            result.post_root,
            result.parent_proof.to_bytes(),
            result.child_proof.to_bytes(),
        )
    };

    let bob_device_tree_commitment = AppState::get_device_tree_commitment()
        .expect("Bob's device tree commitment must be set after set_identity_info");

    let receipt_bytes = build_bilateral_receipt_with_smt(
        bob_id,
        alice_id,
        h0,
        h1,
        pre_root,
        post_root,
        parent_proof_bytes,
        child_proof_bytes,
        Some(bob_device_tree_commitment),
    )
    .expect("build_bilateral_receipt_with_smt must return Some");

    // Alice verifying: looks up Bob's stored R_G from contacts table → must succeed.
    let ok = verify_receipt_bytes(&receipt_bytes, Some(commitment));
    assert!(
        ok,
        "verify_receipt_bytes must succeed when contact device tree root is stored"
    );
}

#[tokio::test]
#[serial]
async fn smoke_proof_serialize_deserialize_roundtrip() {
    setup_test_env();

    let mut smt = SparseMerkleTree::new(256);
    let key = domain_hash_bytes("DSM/test-key", &[0xAA]);
    let value = domain_hash_bytes("DSM/test-value", &[0xBB]);

    smt.update_leaf(&key, &value).unwrap();
    let proof = smt.get_inclusion_proof(&key, 256).unwrap();

    // Serialize
    let bytes = serialize_inclusion_proof(&proof);
    assert!(!bytes.is_empty(), "serialized proof must be non-empty");

    // Deserialize
    let restored = deserialize_inclusion_proof(&bytes).expect("deserialization must succeed");

    // Verify restored proof against the same root
    assert!(
        SparseMerkleTree::verify_proof_against_root(&restored, smt.root()),
        "deserialized proof must verify against original root"
    );

    // Structural equality
    assert_eq!(proof.key, restored.key, "keys must match");
    assert_eq!(proof.value, restored.value, "values must match");
    assert_eq!(
        proof.siblings.len(),
        restored.siblings.len(),
        "sibling counts must match"
    );
    for (i, (a, b)) in proof
        .siblings
        .iter()
        .zip(restored.siblings.iter())
        .enumerate()
    {
        assert_eq!(a, b, "sibling {i} must match");
    }
}
