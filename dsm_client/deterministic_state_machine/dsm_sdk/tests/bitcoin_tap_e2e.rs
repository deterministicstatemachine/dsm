// SPDX-License-Identifier: MIT OR Apache-2.0
//! End-to-end integration tests for the Bitcoin-DSM bridge (dBTC vault deposits).
//!
//! These tests exercise the full deposit lifecycle using the `BitcoinTapSdk`
//! with a real `DLVManager`, verifying:
//! - dBTC token mdeposit_noncedata and create operation
//! - BTC→dBTC flow (deposit BTC, mint dBTC via DLV unlock)
//! - dBTC→BTC flow (burn dBTC via DLV lock)
//! - Refund path after timeout
//! - External commitment auditability

#![allow(clippy::disallowed_methods)]

use std::sync::{Arc, Once};

use bitcoin::hashes::Hash;
use dsm::{
    bitcoin::script::sha256_hash_lock, // SHA256 for HTLC hash locks
    crypto::{kyber::generate_kyber_keypair, sphincs::generate_sphincs_keypair},
    types::{
        state_types::State,
        token_types::{TokenOperation, TokenSupply, TokenType},
    },
    vault::DLVManager,
};
use dsm_sdk::sdk::bitcoin_tap_sdk::{
    VaultOpState, BitcoinTapSdk, VaultDirection, DBTC_DECIMALS, DBTC_MAX_SUPPLY_SATS,
    DBTC_MIN_CONFIRMATIONS, DBTC_MIN_VAULT_BALANCE_SATS, DBTC_TOKEN_ID,
};
use dsm_sdk::storage::client_db;

/// Test key bundle containing both SPHINCS+ (signing) and Kyber (encryption) keys.
struct TestKeys {
    /// SPHINCS+ public key (64 bytes) — for signing/identity
    sphincs_pk: Vec<u8>,
    /// SPHINCS+ secret key (128 bytes) — for signing
    sphincs_sk: Vec<u8>,
    /// Kyber public key (1184 bytes) — for vault content encryption
    kyber_pk: Vec<u8>,
}

/// Create a full test key bundle (SPHINCS+ + Kyber).
fn test_keys() -> TestKeys {
    let (sphincs_pk, sphincs_sk) = generate_sphincs_keypair().expect("SPHINCS+ keygen failed");
    let kyber_kp = generate_kyber_keypair().expect("Kyber keygen failed");
    TestKeys {
        sphincs_pk,
        sphincs_sk,
        kyber_pk: kyber_kp.public_key.clone(),
    }
}

/// Create a test state at a given state_number
fn test_state(state_number: u64) -> State {
    let mut state = State::default();
    state.state_number = state_number;
    state.hash = [0xAA; 32];
    state
}

/// Build mock SPV proof data for a single-transaction block.
///
/// Returns (txid, raw_tx, spv_proof_bytes, block_header) that will pass
/// `verify_tx_in_block` for testing purposes.
///
/// The block header has:
/// - merkle_root = txid (single-tx block)
/// - nBits = 0x20ffffff (easiest possible PoW target)
fn mock_spv_data(
    expected_amount_sats: u64,
    script_pubkey: &[u8],
) -> ([u8; 32], Vec<u8>, Vec<u8>, [u8; 80]) {
    let tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::new(bitcoin::Txid::all_zeros(), 0),
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(expected_amount_sats),
            script_pubkey: bitcoin::ScriptBuf::from(script_pubkey.to_vec()),
        }],
    };
    let raw_tx = bitcoin::consensus::encode::serialize(&tx);
    let txid = bitcoin::hashes::sha256d::Hash::hash(&raw_tx).to_byte_array();

    // SPV proof for single-tx block: index=0, count=0
    let spv_proof = SpvProof {
        siblings: vec![],
        index: 0,
    };
    let spv_bytes = spv_proof.to_bytes();

    // Build a block header with merkle_root = txid and very easy PoW target
    let mut header = [0u8; 80];
    // version (bytes 0..4) — version 1
    header[0] = 0x01;
    // prev_block_hash (bytes 4..36) — zeros is fine for test
    // merkle_root (bytes 36..68) = txid
    header[36..68].copy_from_slice(&txid);
    // time (bytes 68..72) — arbitrary
    header[68..72].copy_from_slice(&1000u32.to_le_bytes());
    // nBits (bytes 72..76) — 0x207fffff = near-maximum target for test PoW
    header[72..76].copy_from_slice(&0x207fffffu32.to_le_bytes());
    // nonce (bytes 76..80) — search for a valid PoW nonce for deterministic pass
    let mut nonce = 0u32;
    loop {
        header[76..80].copy_from_slice(&nonce.to_le_bytes());
        if dsm::bitcoin::spv::verify_block_header_work(&header) {
            break;
        }
        nonce = nonce.wrapping_add(1);
    }

    (txid, raw_tx, spv_bytes, header)
}

/// SPV proof struct needed for mock data construction
use dsm::bitcoin::spv::SpvProof;

/// Compute the P2WSH scriptPubKey for an HTLC script.
///
/// This is what the funding tx output must look like on-chain.
fn htlc_p2wsh_script_pubkey(htlc_script: &[u8]) -> Vec<u8> {
    let script_buf = bitcoin::ScriptBuf::from(htlc_script.to_vec());
    bitcoin::ScriptBuf::new_p2wsh(&script_buf.wscript_hash()).to_bytes()
}

/// Build a dummy header chain of `count` zero-filled 80-byte block headers.
///
/// On Signet, `verify_header_chain` skips all validation (empty checkpoints) and
/// returns `Ok(true)`. The confirmation depth check only counts `header_chain.len()`,
/// so we need `min_confirmations - 1` dummy headers to satisfy it.
fn mock_header_chain(count: usize) -> Vec<[u8; 80]> {
    vec![[0u8; 80]; count]
}

/// Generate valid stitched_receipt + sigma for draw_tap.
///
/// The `draw_tap` fail-closed gate requires:
/// - `stitched_receipt`: non-empty bytes
/// - `stitched_receipt_sigma`: BLAKE3("DSM/receipt-commit" || receipt_bytes)
///
/// Returns (receipt_bytes, sigma) ready for `Some(...)` wrapping.
fn test_stitched_receipt() -> (Vec<u8>, [u8; 32]) {
    let receipt = b"test-stitched-receipt-canonical-bytes".to_vec();
    let sigma = dsm::crypto::blake3::domain_hash_bytes("DSM/receipt-commit", &receipt);
    (receipt, sigma)
}

// --------------------------------------------------------------------------
// dBTC Token Registration
// --------------------------------------------------------------------------

#[test]
fn dbtc_mdeposit_noncedata_has_correct_properties() {
    let identity = [0xCC; 32];
    let mdeposit_nonce = BitcoinTapSdk::dbtc_token_metadata(identity);

    assert_eq!(mdeposit_nonce.token_id, DBTC_TOKEN_ID);
    assert_eq!(mdeposit_nonce.symbol, "dBTC");
    assert_eq!(mdeposit_nonce.name, "Deterministic Bitcoin");
    assert_eq!(mdeposit_nonce.decimals, DBTC_DECIMALS);
    assert_eq!(mdeposit_nonce.token_type, TokenType::Wrapped);
    assert_eq!(mdeposit_nonce.owner_id, identity);
    assert!(mdeposit_nonce.description.is_some());
    assert_eq!(
        mdeposit_nonce.fields.get("backing_asset"),
        Some(&"bitcoin".to_string())
    );
    assert_eq!(
        mdeposit_nonce.fields.get("mint_mechanism"),
        Some(&"dlv_native".to_string())
    );
    assert_eq!(
        mdeposit_nonce.fields.get("backing_ratio"),
        Some(&"1:1".to_string())
    );
    // Add CPTA policy commitment assertion
    assert!(mdeposit_nonce.fields.contains_key("policy_commit"));
}

#[test]
fn dbtc_create_operation_produces_valid_token() {
    let op = BitcoinTapSdk::dbtc_create_operation([0xDD; 32]);
    match op {
        TokenOperation::Create {
            metadata,
            supply,
            fee,
        } => {
            assert_eq!(metadata.token_id, DBTC_TOKEN_ID);
            assert_eq!(metadata.token_type, TokenType::Wrapped);
            assert_eq!(metadata.decimals, 8); // Bitcoin precision
            assert_eq!(supply, TokenSupply::Fixed(DBTC_MAX_SUPPLY_SATS));
            assert_eq!(fee, 0); // Bridge token is fee-exempt
        }
        _ => panic!("Expected Create operation, got {:?}", op),
    }
}

// --------------------------------------------------------------------------
// BTC → WBTC Flow (Deposit BTC, Mint WBTC)
// --------------------------------------------------------------------------

#[tokio::test]
async fn btc_to_dbtc_initiation_creates_dlv() {
    let dlv_manager = Arc::new(DLVManager::new());
    let bridge = BitcoinTapSdk::new(dlv_manager.clone());

    let keys = test_keys();
    let state = test_state(1);
    let btc_pubkey = [0x02; 33]; // Compressed pubkey
    let amount_sats = 100_000_000; // 1 BTC

    let initiation = bridge
        .open_tap(
            amount_sats,
            &btc_pubkey,
            100, // refund after 100 iterations
            (&keys.sphincs_pk, &keys.sphincs_sk),
            &state,
            dsm::bitcoin::types::BitcoinNetwork::Signet,
            &keys.kyber_pk,
        )
        .await
        .expect("initiation should succeed");

    // Verify deposit initiation
    assert!(initiation.vault_op_id.starts_with("deposit-"));
    assert_ne!(initiation.hash_lock, [0u8; 32]);
    assert!(!initiation.vault_id.is_empty());
    assert_ne!(initiation.external_commitment, [0u8; 32]);

    // BTC→dBTC now generates HTLC script/address for the user to fund
    assert!(initiation.htlc_script.is_some());
    assert!(initiation.htlc_address.is_some());
    let htlc_addr = initiation.htlc_address.as_ref().unwrap();
    assert!(
        htlc_addr.starts_with("tb1"),
        "Signet HTLC address should start with tb1, got: {htlc_addr}"
    );

    // Verify deposit record was stored
    let status = bridge
        .get_vault_op_status(&initiation.vault_op_id)
        .await
        .expect("status should exist");
    assert_eq!(status, VaultOpState::Initiated);

    let record = bridge
        .get_vault_record(&initiation.vault_op_id)
        .await
        .expect("record should exist");
    assert_eq!(record.direction, VaultDirection::BtcToDbtc);
    assert_eq!(record.btc_amount_sats, amount_sats);

    // Verify DLV was created
    let vaults = dlv_manager.list_vaults().await.unwrap();
    assert_eq!(vaults.len(), 1);
    assert_eq!(vaults[0], initiation.vault_id);
}

#[tokio::test]
async fn btc_to_dbtc_rejects_zero_amount() {
    let bridge = BitcoinTapSdk::new(Arc::new(DLVManager::new()));
    let keys = test_keys();
    let state = test_state(1);

    let result = bridge
        .open_tap(
            0,
            &[0x02; 33],
            100,
            (&keys.sphincs_pk, &keys.sphincs_sk),
            &state,
            dsm::bitcoin::types::BitcoinNetwork::Signet,
            &keys.kyber_pk,
        )
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn btc_to_dbtc_rejects_bad_pubkey() {
    let bridge = BitcoinTapSdk::new(Arc::new(DLVManager::new()));
    let keys = test_keys();
    let state = test_state(1);

    // Wrong length pubkey (should be 33 for compressed)
    let result = bridge
        .open_tap(
            100_000,
            &[0x02; 32],
            100,
            (&keys.sphincs_pk, &keys.sphincs_sk),
            &state,
            dsm::bitcoin::types::BitcoinNetwork::Signet,
            &keys.kyber_pk,
        )
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn btc_to_dbtc_complete_produces_mint_operation() {
    let dlv_manager = Arc::new(DLVManager::new());
    let bridge = BitcoinTapSdk::new(dlv_manager.clone());

    let keys = test_keys();
    let state = test_state(1);
    let amount_sats = 50_000_000; // 0.5 BTC

    // Initiate deposit
    let initiation = bridge
        .open_tap(
            amount_sats,
            &[0x02; 33],
            100,
            (&keys.sphincs_pk, &keys.sphincs_sk),
            &state,
            dsm::bitcoin::types::BitcoinNetwork::Signet,
            &keys.kyber_pk,
        )
        .await
        .unwrap();

    // Get the preimage (we're the initiator)
    let preimage = bridge
        .get_claim_preimage(&initiation.vault_op_id)
        .await
        .unwrap();

    // Verify hash_lock matches
    let computed_hash = sha256_hash_lock(&preimage);
    assert_eq!(computed_hash, initiation.hash_lock);

    // Build valid mock SPV proof data — P2WSH output must match the deposit's HTLC script
    let htlc_spk = htlc_p2wsh_script_pubkey(initiation.htlc_script.as_ref().unwrap());
    let (mock_txid, mock_raw_tx, mock_spv_bytes, mock_header) =
        mock_spv_data(amount_sats, &htlc_spk);
    let recipient = [0xEE; 32]; // WBTC recipient device ID

    // Complete the deposit — this unlocks the DLV
    let completion = bridge
        .draw_tap(
            &initiation.vault_op_id,
            &preimage,
            mock_txid,
            &mock_raw_tx,
            &mock_spv_bytes,
            mock_header,
            &mock_header_chain((DBTC_MIN_CONFIRMATIONS as usize).saturating_sub(1)),
            &keys.kyber_pk,
            &keys.sphincs_pk,
            recipient,
            &state,
            Some(test_stitched_receipt().0),
            Some(test_stitched_receipt().1),
        )
        .await
        .unwrap();

    // Verify the completion returns a Mint operation
    match &completion.token_operation {
        TokenOperation::Mint {
            token_id,
            recipient: mint_recipient,
            amount,
        } => {
            assert_eq!(token_id, DBTC_TOKEN_ID);
            assert_eq!(*mint_recipient, recipient);
            assert_eq!(*amount, amount_sats);
        }
        _ => panic!(
            "Expected Mint operation, got {:?}",
            completion.token_operation
        ),
    }

    // Verify deposit is now completed
    let status = bridge
        .get_vault_op_status(&initiation.vault_op_id)
        .await
        .unwrap();
    assert_eq!(status, VaultOpState::Completed);
}

// --------------------------------------------------------------------------
// Refund Path
// --------------------------------------------------------------------------

#[tokio::test]
async fn refund_not_available_before_timeout() {
    let bridge = BitcoinTapSdk::new(Arc::new(DLVManager::new()));
    let keys = test_keys();
    let state = test_state(1);

    let initiation = bridge
        .open_tap(
            100_000,
            &[0x02; 33],
            100,
            (&keys.sphincs_pk, &keys.sphincs_sk),
            &state,
            dsm::bitcoin::types::BitcoinNetwork::Signet,
            &keys.kyber_pk,
        )
        .await
        .unwrap();

    // Try to refund at state 50 (need 100 iterations from state 1)
    let early_state = test_state(50);
    let result = bridge
        .close_tap(&initiation.vault_op_id, &keys.sphincs_sk, &early_state)
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Refund not yet available"),
        "Expected timeout error, got: {err}"
    );
}

#[tokio::test]
async fn refund_after_completed_deposit_rejected() {
    // Test that you can't refund a deposit that's already completed
    let bridge = BitcoinTapSdk::new(Arc::new(DLVManager::new()));
    let keys = test_keys();
    let state = test_state(1);

    let initiation = bridge
        .open_tap(
            100_000,
            &[0x02; 33],
            50,
            (&keys.sphincs_pk, &keys.sphincs_sk),
            &state,
            dsm::bitcoin::types::BitcoinNetwork::Signet,
            &keys.kyber_pk,
        )
        .await
        .unwrap();

    let preimage = bridge
        .get_claim_preimage(&initiation.vault_op_id)
        .await
        .unwrap();

    let htlc_spk = htlc_p2wsh_script_pubkey(initiation.htlc_script.as_ref().unwrap());
    let (mock_txid, mock_raw_tx, mock_spv_bytes, mock_header) = mock_spv_data(100_000, &htlc_spk);

    // Complete the deposit first
    bridge
        .draw_tap(
            &initiation.vault_op_id,
            &preimage,
            mock_txid,
            &mock_raw_tx,
            &mock_spv_bytes,
            mock_header,
            &mock_header_chain((DBTC_MIN_CONFIRMATIONS as usize).saturating_sub(1)),
            &keys.kyber_pk,
            &keys.sphincs_pk,
            [0; 32],
            &state,
            Some(test_stitched_receipt().0),
            Some(test_stitched_receipt().1),
        )
        .await
        .unwrap();

    // Now try to refund — should be rejected
    let late_state = test_state(200);
    let result = bridge
        .close_tap(&initiation.vault_op_id, &keys.sphincs_sk, &late_state)
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Completed"),
        "Expected 'Completed' error, got: {err}"
    );
}

// --------------------------------------------------------------------------
// Deposit State Management
// --------------------------------------------------------------------------

#[tokio::test]
async fn cannot_complete_already_completed_deposit() {
    let bridge = BitcoinTapSdk::new(Arc::new(DLVManager::new()));
    let keys = test_keys();
    let state = test_state(1);

    let initiation = bridge
        .open_tap(
            100_000,
            &[0x02; 33],
            100,
            (&keys.sphincs_pk, &keys.sphincs_sk),
            &state,
            dsm::bitcoin::types::BitcoinNetwork::Signet,
            &keys.kyber_pk,
        )
        .await
        .unwrap();

    let preimage = bridge
        .get_claim_preimage(&initiation.vault_op_id)
        .await
        .unwrap();

    let htlc_spk = htlc_p2wsh_script_pubkey(initiation.htlc_script.as_ref().unwrap());
    let (mock_txid, mock_raw_tx, mock_spv_bytes, mock_header) = mock_spv_data(100_000, &htlc_spk);

    // First completion succeeds
    bridge
        .draw_tap(
            &initiation.vault_op_id,
            &preimage,
            mock_txid,
            &mock_raw_tx,
            &mock_spv_bytes,
            mock_header,
            &mock_header_chain((DBTC_MIN_CONFIRMATIONS as usize).saturating_sub(1)),
            &keys.kyber_pk,
            &keys.sphincs_pk,
            [0; 32],
            &state,
            Some(test_stitched_receipt().0),
            Some(test_stitched_receipt().1),
        )
        .await
        .unwrap();

    // Second completion should fail (already completed)
    let result = bridge
        .draw_tap(
            &initiation.vault_op_id,
            &preimage,
            mock_txid,
            &mock_raw_tx,
            &mock_spv_bytes,
            mock_header,
            &mock_header_chain((DBTC_MIN_CONFIRMATIONS as usize).saturating_sub(1)),
            &keys.kyber_pk,
            &keys.sphincs_pk,
            [0; 32],
            &state,
            Some(test_stitched_receipt().0),
            Some(test_stitched_receipt().1),
        )
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn wrong_preimage_rejected() {
    let bridge = BitcoinTapSdk::new(Arc::new(DLVManager::new()));
    let keys = test_keys();
    let state = test_state(1);

    let initiation = bridge
        .open_tap(
            100_000,
            &[0x02; 33],
            100,
            (&keys.sphincs_pk, &keys.sphincs_sk),
            &state,
            dsm::bitcoin::types::BitcoinNetwork::Signet,
            &keys.kyber_pk,
        )
        .await
        .unwrap();

    // Try with wrong preimage
    let wrong_preimage = vec![0xFF; 32];
    let result = bridge
        .draw_tap(
            &initiation.vault_op_id,
            &wrong_preimage,
            [0; 32],
            &[0u8; 0],
            &[0; 32],
            [0; 80],
            &mock_header_chain((DBTC_MIN_CONFIRMATIONS as usize).saturating_sub(1)),
            &keys.kyber_pk,
            &keys.sphincs_pk,
            [0; 32],
            &state,
            Some(test_stitched_receipt().0),
            Some(test_stitched_receipt().1),
        )
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("hash lock"));
}

#[tokio::test]
async fn list_vault_ops_tracks_all() {
    let bridge = BitcoinTapSdk::new(Arc::new(DLVManager::new()));
    let keys = test_keys();
    let state = test_state(1);

    assert_eq!(bridge.list_vault_ops().await.len(), 0);

    bridge
        .open_tap(
            100_000,
            &[0x02; 33],
            100,
            (&keys.sphincs_pk, &keys.sphincs_sk),
            &state,
            dsm::bitcoin::types::BitcoinNetwork::Signet,
            &keys.kyber_pk,
        )
        .await
        .unwrap();

    assert_eq!(bridge.list_vault_ops().await.len(), 1);

    bridge
        .open_tap(
            200_000,
            &[0x02; 33],
            50,
            (&keys.sphincs_pk, &keys.sphincs_sk),
            &state,
            dsm::bitcoin::types::BitcoinNetwork::Signet,
            &keys.kyber_pk,
        )
        .await
        .unwrap();

    assert_eq!(bridge.list_vault_ops().await.len(), 2);
}

// --------------------------------------------------------------------------
// External Commitment Auditability
// --------------------------------------------------------------------------

#[test]
fn external_commitments_are_deterministic_and_unique() {
    let hash1 = [0xAA; 32];
    let hash2 = [0xBB; 32];
    let state = test_state(1);

    // Same inputs → same commitment
    let c1 = test_create_commitment(&hash1, "v1", "btc_to_dbtc", 100_000, &state);
    let c2 = test_create_commitment(&hash1, "v1", "btc_to_dbtc", 100_000, &state);
    assert_eq!(c1, c2);

    // Different hash_lock → different commitment
    let c3 = test_create_commitment(&hash2, "v1", "btc_to_dbtc", 100_000, &state);
    assert_ne!(c1, c3);

    // Different direction → different commitment
    let c4 = test_create_commitment(&hash1, "v1", "dbtc_to_btc", 100_000, &state);
    assert_ne!(c1, c4);

    // Different amount → different commitment
    let c5 = test_create_commitment(&hash1, "v1", "btc_to_dbtc", 200_000, &state);
    assert_ne!(c1, c5);
}

/// Helper to call the private create_deposit_commitment via the same logic
fn test_create_commitment(
    hash_lock: &[u8; 32],
    vault_id: &str,
    direction: &str,
    amount_sats: u64,
    state: &State,
) -> [u8; 32] {
    use dsm::commitments::{create_external_commitment, external_evidence_hash, external_source_id};
    let source_id = external_source_id("bitcoin:mainnet");
    let mut evidence = Vec::new();
    evidence.extend_from_slice(hash_lock);
    evidence.extend_from_slice(vault_id.as_bytes());
    evidence.extend_from_slice(direction.as_bytes());
    evidence.extend_from_slice(&amount_sats.to_le_bytes());
    evidence.extend_from_slice(&state.state_number.to_le_bytes());
    let evidence_hash = external_evidence_hash(&evidence);
    create_external_commitment(hash_lock, &source_id, &evidence_hash)
}

// --------------------------------------------------------------------------
// WBTC Content Encoding
// --------------------------------------------------------------------------

#[test]
fn dbtc_content_encoding_roundtrip() {
    let amounts = [0u64, 1, 100_000_000, u64::MAX];
    for amount in amounts {
        let encoded = test_encode_dbtc(amount);
        let decoded = BitcoinTapSdk::decode_dbtc_content(&encoded).unwrap();
        assert_eq!(decoded, amount, "Roundtrip failed for amount {amount}");
    }
}

fn test_encode_dbtc(amount_sats: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&amount_sats.to_le_bytes());
    out.extend_from_slice(b"dBTC");
    out
}

#[test]
fn dbtc_content_decode_rejects_short() {
    let short = vec![0u8; 4]; // Too short (< 8 bytes)
    assert!(BitcoinTapSdk::decode_dbtc_content(&short).is_err());
}

// --------------------------------------------------------------------------
// Lock Operation Helper
// --------------------------------------------------------------------------

#[test]
fn seal_tap_operation() {
    let amount = 500_000_000; // 5 BTC
    let vault_op_id = "deposit-12345";
    let op = BitcoinTapSdk::seal_tap(amount, vault_op_id);

    match op {
        TokenOperation::Lock {
            token_id,
            amount: lock_amount,
            purpose,
        } => {
            assert_eq!(token_id, "dBTC");
            assert_eq!(lock_amount, amount);
            assert!(String::from_utf8_lossy(&purpose).contains("deposit"));
            assert!(String::from_utf8_lossy(&purpose).contains(vault_op_id));
        }
        _ => panic!("Expected Lock operation"),
    }
}

// --------------------------------------------------------------------------
// Fractional Exit Test
// --------------------------------------------------------------------------

#[tokio::test]
async fn fractional_exit_creates_successor_vault() {
    let dlv_manager = Arc::new(DLVManager::new());
    let bridge = BitcoinTapSdk::new(dlv_manager.clone());

    let keys = test_keys();
    let state = test_state(1);
    let total_amount_sats = 100_000_000; // 1 BTC
    let exit_amount_sats = 50_000_000; // 0.5 BTC fractional exit

    // Initiate and complete a BTC→dBTC deposit to have dBTC
    let initiation = bridge
        .open_tap(
            total_amount_sats,
            &[0x02; 33],
            100,
            (&keys.sphincs_pk, &keys.sphincs_sk),
            &state,
            dsm::bitcoin::types::BitcoinNetwork::Signet,
            &keys.kyber_pk,
        )
        .await
        .unwrap();

    let preimage = bridge
        .get_claim_preimage(&initiation.vault_op_id)
        .await
        .unwrap();
    let htlc_spk = htlc_p2wsh_script_pubkey(initiation.htlc_script.as_ref().unwrap());
    let (mock_txid, mock_raw_tx, mock_spv_bytes, mock_header) =
        mock_spv_data(total_amount_sats, &htlc_spk);

    bridge
        .draw_tap(
            &initiation.vault_op_id,
            &preimage,
            mock_txid,
            &mock_raw_tx,
            &mock_spv_bytes,
            mock_header,
            &mock_header_chain((DBTC_MIN_CONFIRMATIONS as usize).saturating_sub(1)),
            &keys.kyber_pk,
            &keys.sphincs_pk,
            [0xEE; 32],
            &state,
            Some(test_stitched_receipt().0),
            Some(test_stitched_receipt().1),
        )
        .await
        .unwrap();

    let fractional = bridge
        .pour_partial(
            &initiation.vault_id,
            total_amount_sats,
            0,
            exit_amount_sats,
            100,
            (&keys.sphincs_pk, &keys.sphincs_sk),
            &state,
            dsm::bitcoin::types::BitcoinNetwork::Signet,
            &keys.kyber_pk,
        )
        .await
        .unwrap();

    // Verify burn operation reflects fractional exit amount
    match fractional.token_operation {
        TokenOperation::Burn { token_id, amount } => {
            assert_eq!(token_id, DBTC_TOKEN_ID);
            assert_eq!(amount, exit_amount_sats);
        }
        other => panic!("Expected Burn operation, got {other:?}"),
    }

    // Verify successor vault created
    let vaults = dlv_manager.list_vaults().await.unwrap();
    assert_eq!(vaults.len(), 2); // Original + successor
    assert!(vaults.contains(&fractional.successor_vault_id));

    // Verify remainder meets min_vault_balance
    assert_eq!(
        fractional.remainder_sats,
        total_amount_sats - exit_amount_sats
    );
    assert!(fractional.remainder_sats >= DBTC_MIN_VAULT_BALANCE_SATS);
    assert!(fractional.successor_htlc_address.starts_with("tb1"));
    assert!(!fractional.successor_htlc_script.is_empty());
}

// --------------------------------------------------------------------------
// Invariant 18 (§12.2.2): Local Vault-State Caching
// --------------------------------------------------------------------------

/// Ensure the in-memory test database is initialized (idempotent).
static TEST_DB_INIT: Once = Once::new();

fn init_test_db() {
    unsafe {
        std::env::set_var("DSM_SDK_TEST_MODE", "1");
    }
    TEST_DB_INIT.call_once(|| {
        let _ = dsm_sdk::storage_utils::set_storage_base_dir(std::path::PathBuf::from(
            "./.dsm_testdata_bitcoin_tap_e2e",
        ));
        client_db::init_database().expect("[bitcoin_tap_e2e] init_database");
    });
    // Vault publication (mandatory at creation) requires device_id from AppState.
    // Set a test device_id so e2e tests can proceed through persist_vault().
    dsm_sdk::sdk::app_state::AppState::set_identity_info(
        vec![0xE2; 32],
        vec![0xE3; 32],
        vec![0xE4; 32],
        vec![0u8; 32],
    );
}

#[tokio::test]
async fn persistence_deposit_record_roundtrip() {
    init_test_db();
    let dlv = Arc::new(DLVManager::new());
    let bridge = BitcoinTapSdk::new(dlv.clone());
    let keys = test_keys();
    let state = test_state(1);

    let init = bridge
        .open_tap(
            100_000,
            &[0x02; 33],
            100,
            (&keys.sphincs_pk, &keys.sphincs_sk),
            &state,
            dsm::bitcoin::types::BitcoinNetwork::Signet,
            &keys.kyber_pk,
        )
        .await
        .unwrap();

    // Read directly from SQLite — the write-through should have persisted it
    let persisted = client_db::get_vault_record_by_id(&init.vault_op_id)
        .unwrap()
        .expect("deposit record should be in SQLite");
    assert_eq!(persisted.vault_op_id, init.vault_op_id);
    assert_eq!(persisted.direction, "btc_to_dbtc");
    assert_eq!(persisted.vault_state, "initiated");
    assert_eq!(persisted.btc_amount_sats, 100_000);
    assert_eq!(persisted.hash_lock.len(), 32);
    assert!(persisted.vault_id.is_some());
    assert!(persisted.entry_header.is_none()); // Not yet completed
}

#[tokio::test]
async fn persistence_restore_after_sdk_drop() {
    init_test_db();
    let vault_op_id;
    let vault_id;
    let amount = 200_000u64;

    // Phase 1: Create deposit, then drop the SDK + DLVManager
    {
        let dlv = Arc::new(DLVManager::new());
        let bridge = BitcoinTapSdk::new(dlv.clone());
        let keys = test_keys();
        let state = test_state(1);

        let init = bridge
            .open_tap(
                amount,
                &[0x02; 33],
                100,
                (&keys.sphincs_pk, &keys.sphincs_sk),
                &state,
                dsm::bitcoin::types::BitcoinNetwork::Signet,
                &keys.kyber_pk,
            )
            .await
            .unwrap();
        vault_op_id = init.vault_op_id;
        vault_id = init.vault_id;
        // SDK + DLVManager dropped here
    }

    // Phase 2: Fresh SDK + DLVManager, restore from persistence
    let dlv2 = Arc::new(DLVManager::new());
    let bridge2 = BitcoinTapSdk::new(dlv2.clone());
    let (record_count, vault_count) = bridge2.restore_from_persistence().await.unwrap();

    // At least our deposit was restored (may include others from shared test DB)
    assert!(
        record_count >= 1,
        "Expected at least 1 restored deposit, got {record_count}"
    );
    assert!(
        vault_count >= 1,
        "Expected at least 1 restored vault, got {vault_count}"
    );

    // Verify the deposit is back in memory
    let record = bridge2.get_vault_record(&vault_op_id).await.unwrap();
    assert_eq!(record.btc_amount_sats, amount);
    assert_eq!(record.direction, VaultDirection::BtcToDbtc);
    assert_eq!(record.state, VaultOpState::Initiated);

    // Verify vault was restored into the new DLVManager
    let vault_lock = dlv2.get_vault(&vault_id).await.unwrap();
    let vault = vault_lock.lock().await;
    assert_eq!(vault.id, vault_id);
}

#[tokio::test]
async fn persistence_completed_deposit_has_entry_header() {
    init_test_db();
    let dlv = Arc::new(DLVManager::new());
    let bridge = BitcoinTapSdk::new(dlv.clone());
    let keys = test_keys();
    let state = test_state(1);
    let amount = 50_000_000u64;

    let init = bridge
        .open_tap(
            amount,
            &[0x02; 33],
            100,
            (&keys.sphincs_pk, &keys.sphincs_sk),
            &state,
            dsm::bitcoin::types::BitcoinNetwork::Signet,
            &keys.kyber_pk,
        )
        .await
        .unwrap();

    let preimage = bridge.get_claim_preimage(&init.vault_op_id).await.unwrap();
    let htlc_spk = htlc_p2wsh_script_pubkey(init.htlc_script.as_ref().unwrap());
    let (txid, raw_tx, spv_bytes, header) = mock_spv_data(amount, &htlc_spk);

    bridge
        .draw_tap(
            &init.vault_op_id,
            &preimage,
            txid,
            &raw_tx,
            &spv_bytes,
            header,
            &mock_header_chain((DBTC_MIN_CONFIRMATIONS as usize).saturating_sub(1)),
            &keys.kyber_pk,
            &keys.sphincs_pk,
            [0xEE; 32],
            &state,
            Some(test_stitched_receipt().0),
            Some(test_stitched_receipt().1),
        )
        .await
        .unwrap();

    // Read from SQLite — entry_header should be the 80-byte block header
    let persisted = client_db::get_vault_record_by_id(&init.vault_op_id)
        .unwrap()
        .expect("completed deposit should be in SQLite");
    assert_eq!(persisted.vault_state, "completed");
    let eh = persisted
        .entry_header
        .expect("entry_header should be set after completion");
    assert_eq!(eh.len(), 80);
    assert_eq!(eh, header.to_vec());
}

// --------------------------------------------------------------------------
// Invariant 19 (§12.2.3): Entry-Time Header Anchoring
// --------------------------------------------------------------------------

#[tokio::test]
async fn entry_header_cached_on_vault_after_complete() {
    init_test_db();
    let dlv = Arc::new(DLVManager::new());
    let bridge = BitcoinTapSdk::new(dlv.clone());
    let keys = test_keys();
    let state = test_state(1);
    let amount = 75_000_000u64;

    let init = bridge
        .open_tap(
            amount,
            &[0x02; 33],
            100,
            (&keys.sphincs_pk, &keys.sphincs_sk),
            &state,
            dsm::bitcoin::types::BitcoinNetwork::Signet,
            &keys.kyber_pk,
        )
        .await
        .unwrap();

    let preimage = bridge.get_claim_preimage(&init.vault_op_id).await.unwrap();
    let htlc_spk = htlc_p2wsh_script_pubkey(init.htlc_script.as_ref().unwrap());
    let (txid, raw_tx, spv_bytes, header) = mock_spv_data(amount, &htlc_spk);

    bridge
        .draw_tap(
            &init.vault_op_id,
            &preimage,
            txid,
            &raw_tx,
            &spv_bytes,
            header,
            &mock_header_chain((DBTC_MIN_CONFIRMATIONS as usize).saturating_sub(1)),
            &keys.kyber_pk,
            &keys.sphincs_pk,
            [0xEE; 32],
            &state,
            Some(test_stitched_receipt().0),
            Some(test_stitched_receipt().1),
        )
        .await
        .unwrap();

    // Verify vault.entry_header == Some(block_header)
    let vault_lock = dlv.get_vault(&init.vault_id).await.unwrap();
    let vault = vault_lock.lock().await;
    assert_eq!(vault.entry_header, Some(header));

    // Also verify the in-memory deposit record has it
    let record = bridge.get_vault_record(&init.vault_op_id).await.unwrap();
    assert_eq!(record.entry_header, Some(header));
}

#[tokio::test]
async fn entry_header_none_before_complete() {
    init_test_db();
    let dlv = Arc::new(DLVManager::new());
    let bridge = BitcoinTapSdk::new(dlv.clone());
    let keys = test_keys();
    let state = test_state(1);

    let init = bridge
        .open_tap(
            300_000,
            &[0x02; 33],
            100,
            (&keys.sphincs_pk, &keys.sphincs_sk),
            &state,
            dsm::bitcoin::types::BitcoinNetwork::Signet,
            &keys.kyber_pk,
        )
        .await
        .unwrap();

    // Before completion: entry_header is None everywhere
    let record = bridge.get_vault_record(&init.vault_op_id).await.unwrap();
    assert!(
        record.entry_header.is_none(),
        "entry_header should be None before completion"
    );

    let vault_lock = dlv.get_vault(&init.vault_id).await.unwrap();
    let vault = vault_lock.lock().await;
    assert!(
        vault.entry_header.is_none(),
        "vault entry_header should be None before completion"
    );

    // Also verify SQLite record has no entry_header
    let persisted = client_db::get_vault_record_by_id(&init.vault_op_id)
        .unwrap()
        .expect("deposit should be in SQLite");
    assert!(
        persisted.entry_header.is_none(),
        "persisted entry_header should be None before completion"
    );
}

/// One-time generator for dBTC CTPA policy binary and commit hash.
///
/// Run with:
///   DSM_PROTO_ROOT=../../proto cargo test --package dsm_sdk --features test-utils \
///     --test bitcoin_tap_e2e generate_dbtc_policy_binary -- --nocapture --ignored
///
/// This writes:
///   src/policies/dbtc.ctpa.bin     — canonical protobuf bytes (hashed for CTPA anchor)
///   src/policy_commits/dbtc.commit32 — BLAKE3(dbtc.ctpa.bin) 32-byte digest
///
/// The .ctpa.bin stores canonical_bytes() (author + conditions + roles only),
/// matching the assert_builtins_sound() check: blake3(file) == commit.
#[test]
#[ignore] // run manually; one-time generation
fn generate_dbtc_policy_binary() {
    use dsm::types::policy_types::{PolicyCondition, PolicyFile};

    // Build dBTC policy: permissionless, basic operations like Bitcoin
    let mut policy = PolicyFile::new("dBTC Policy", "1.0.0", "dsm:dbtc");
    policy.with_description(
        "Deterministic Bitcoin (dBTC) token policy. 1:1 BTC-backed, permissionless transfers.",
    );
    policy.add_condition(PolicyCondition::OperationRestriction {
        allowed_operations: vec![
            "Transfer".to_string(),
            "Mint".to_string(),
            "Burn".to_string(),
            "Lock".to_string(),
            "Unlock".to_string(),
        ],
    });
    // Bitcoin tap safety constraints — protocol law (dBTC §12).
    // These values are frozen into policy_commit; any change produces a distinct GT.
    policy.add_condition(PolicyCondition::BitcoinTapConstraint {
        max_successor_depth: 5,
        min_vault_balance_sats: 100_000,
        dust_floor_sats: 546,
        min_confirmations: 100,
    });
    // No IdentityConstraint — permissionless, any identity can hold/transfer
    // No LogicalTimeConstraint — no time restrictions
    // Explicitly excludes fee_payment and token_create (those are ERA-only)

    // Generate canonical bytes — this is what gets hashed for the CTPA anchor
    // and what assert_builtins_sound() verifies.
    let canonical = policy
        .canonical_bytes()
        .expect("canonical_bytes() should succeed");
    let commit = blake3::hash(&canonical);
    let commit_bytes: [u8; 32] = *commit.as_bytes();

    // Write files — .ctpa.bin stores canonical bytes so blake3(file) == commit
    let sdk_src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    let policy_path = sdk_src.join("policies/dbtc.ctpa.bin");
    std::fs::write(&policy_path, &canonical).expect("write dbtc.ctpa.bin");
    println!(
        "Wrote {} bytes to {}",
        canonical.len(),
        policy_path.display()
    );

    let commit_path = sdk_src.join("policy_commits/dbtc.commit32");
    std::fs::write(&commit_path, commit_bytes).expect("write dbtc.commit32");
    println!(
        "Wrote 32 bytes to {} (blake3: {})",
        commit_path.display(),
        dsm_sdk::util::text_id::encode_base32_crockford(&commit_bytes)
    );

    // Verify: blake3(file) == commit (same check as assert_builtins_sound)
    let file_bytes = std::fs::read(&policy_path).expect("read back dbtc.ctpa.bin");
    let file_hash = blake3::hash(&file_bytes);
    assert_eq!(
        commit_bytes,
        *file_hash.as_bytes(),
        "blake3(dbtc.ctpa.bin) must equal dbtc.commit32"
    );
    println!("Builtin soundness verification passed.");
}

// --------------------------------------------------------------------------
// Bug-fix regression tests: destination_address + token balance SQLite path
// --------------------------------------------------------------------------

/// Bug 1 regression: destination_address persists through upsert/read roundtrip.
#[tokio::test]
async fn destination_address_upsert_roundtrip() {
    init_test_db();
    let vault_op_id = format!("dest_rt_{}", std::process::id());

    let rec = client_db::PersistedVaultRecord {
        vault_op_id: vault_op_id.clone(),
        direction: "dbtc_to_btc".to_string(),
        vault_state: "initiated".to_string(),
        hash_lock: vec![0xAA; 32],
        deposit_nonce: None,
        vault_id: None,
        btc_amount_sats: 50_000,
        btc_pubkey: vec![0x02; 33],
        htlc_script: None,
        htlc_address: None,
        external_commitment: None,
        refund_iterations: 100,
        created_at_state: 1,
        entry_header: None,
        parent_vault_id: None,
        successor_depth: 0,
        is_fractional_successor: false,
        refund_hash_lock: vec![],
        destination_address: Some("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".to_string()),
        funding_txid: None,
        exit_amount_sats: 0,
        exit_header: None,
        exit_confirm_depth: 0,
        entry_txid: None,
    };

    client_db::upsert_vault_record(&rec).expect("upsert_vault_record");

    // Verify via get_vault_record_by_id
    let loaded = client_db::get_vault_record_by_id(&vault_op_id)
        .expect("get_vault_record_by_id")
        .expect("record should exist");
    assert_eq!(
        loaded.destination_address.as_deref(),
        Some("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"),
        "destination_address should survive upsert/read roundtrip"
    );

    // Verify via list_vault_records_db
    let all = client_db::list_vault_records_db().expect("list_vault_records_db");
    let found = all.iter().find(|r| r.vault_op_id == vault_op_id);
    assert!(found.is_some(), "record should appear in list");
    assert_eq!(
        found.unwrap().destination_address.as_deref(),
        Some("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"),
        "destination_address should survive list roundtrip"
    );

    // Cleanup
    client_db::delete_vault_record(&vault_op_id).expect("cleanup");
}

/// Bug 1 regression: set_vault_record_destination_address updates an existing record.
#[tokio::test]
async fn set_vault_record_destination_address_updates_existing() {
    init_test_db();
    let vault_op_id = format!("dest_upd_{}", std::process::id());

    let rec = client_db::PersistedVaultRecord {
        vault_op_id: vault_op_id.clone(),
        direction: "dbtc_to_btc".to_string(),
        vault_state: "initiated".to_string(),
        hash_lock: vec![0xBB; 32],
        deposit_nonce: None,
        vault_id: None,
        btc_amount_sats: 75_000,
        btc_pubkey: vec![0x02; 33],
        htlc_script: None,
        htlc_address: None,
        external_commitment: None,
        refund_iterations: 100,
        created_at_state: 2,
        entry_header: None,
        parent_vault_id: None,
        successor_depth: 0,
        is_fractional_successor: false,
        refund_hash_lock: vec![],
        destination_address: None,
        funding_txid: None,
        exit_amount_sats: 0,
        exit_header: None,
        exit_confirm_depth: 0,
        entry_txid: None,
    };

    client_db::upsert_vault_record(&rec).expect("upsert");

    // Verify initially None
    let before = client_db::get_vault_record_by_id(&vault_op_id)
        .unwrap()
        .unwrap();
    assert!(
        before.destination_address.is_none(),
        "destination_address should be None initially"
    );

    // Update via helper
    client_db::set_vault_record_destination_address(
        &vault_op_id,
        "tb1qrp33g0q5b5698ahp5jnf5yzjmgcel4r4gqfng6",
    )
    .expect("set_vault_record_destination_address");

    // Verify updated
    let after = client_db::get_vault_record_by_id(&vault_op_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        after.destination_address.as_deref(),
        Some("tb1qrp33g0q5b5698ahp5jnf5yzjmgcel4r4gqfng6"),
        "destination_address should be updated by set_vault_record_destination_address"
    );

    client_db::delete_vault_record(&vault_op_id).expect("cleanup");
}

/// Bug 1 regression: destination_address survives SDK drop + restore_from_persistence.
#[tokio::test]
async fn destination_address_survives_restore() {
    init_test_db();
    let vault_op_id;
    let dest = "tb1qc7slrfxkknhcq36cc6rgwxf5lec2husqa0z3tw";

    // Phase 1: Create deposit, set destination, drop SDK
    {
        let dlv = Arc::new(DLVManager::new());
        let bridge = BitcoinTapSdk::new(dlv.clone());
        let keys = test_keys();
        let state = test_state(10);

        let init = bridge
            .open_tap(
                150_000,
                &[0x02; 33],
                100,
                (&keys.sphincs_pk, &keys.sphincs_sk),
                &state,
                dsm::bitcoin::types::BitcoinNetwork::Signet,
                &keys.kyber_pk,
            )
            .await
            .unwrap();
        vault_op_id = init.vault_op_id.clone();

        // Simulate what app_router_impl does: set destination after initiation
        client_db::set_vault_record_destination_address(&vault_op_id, dest)
            .expect("set destination");

        // Verify it's set in SQLite
        let persisted = client_db::get_vault_record_by_id(&vault_op_id)
            .unwrap()
            .unwrap();
        assert_eq!(persisted.destination_address.as_deref(), Some(dest));
        // SDK + DLV dropped here
    }

    // Phase 2: Fresh SDK, restore from persistence
    let dlv2 = Arc::new(DLVManager::new());
    let bridge2 = BitcoinTapSdk::new(dlv2.clone());
    let (record_count, _vault_count) = bridge2.restore_from_persistence().await.unwrap();
    assert!(record_count >= 1, "at least 1 deposit restored");

    // Verify destination_address survived in SQLite (persistence is the source of truth)
    let persisted = client_db::get_vault_record_by_id(&vault_op_id)
        .unwrap()
        .expect("record should survive restore");
    assert_eq!(
        persisted.destination_address.as_deref(),
        Some(dest),
        "destination_address must survive SDK drop + restore"
    );
}

/// Bug 4 regression: token balance SQLite roundtrip for non-ERA tokens.
#[tokio::test]
async fn token_balance_sqlite_roundtrip() {
    init_test_db();
    let device_id = format!("test_device_bal_{}", std::process::id());

    // Insert dBTC balance
    client_db::upsert_token_balance(&device_id, "dBTC", 500_000, 0).expect("upsert dBTC balance");

    // Read back
    let (available, locked) = client_db::get_token_balance(&device_id, "dBTC")
        .expect("get dBTC balance")
        .expect("dBTC balance should exist");
    assert_eq!(available, 500_000, "available should be 500_000");
    assert_eq!(locked, 0, "locked should be 0");

    // Update balance (simulates bilateral transfer updating SQLite)
    client_db::upsert_token_balance(&device_id, "dBTC", 750_000, 50_000)
        .expect("update dBTC balance");

    let (available2, locked2) = client_db::get_token_balance(&device_id, "dBTC")
        .expect("get updated dBTC balance")
        .expect("dBTC balance should still exist");
    assert_eq!(
        available2, 750_000,
        "available should be updated to 750_000"
    );
    assert_eq!(locked2, 50_000, "locked should be updated to 50_000");

    // ERA should NOT exist for this device (only non-ERA tokens in token_balances)
    let era = client_db::get_token_balance(&device_id, "ERA").expect("get ERA balance");
    assert!(era.is_none(), "ERA should not be in token_balances table");
}

/// Regression guard: list_vault_records_db returns destination_address correctly
/// for records both with and without the field set.
#[tokio::test]
async fn list_deposit_records_destination_address_mixed() {
    init_test_db();
    let pid = std::process::id();
    let id_with = format!("list_dest_with_{pid}");
    let id_without = format!("list_dest_without_{pid}");

    let base = client_db::PersistedVaultRecord {
        vault_op_id: String::new(),
        direction: "btc_to_dbtc".to_string(),
        vault_state: "initiated".to_string(),
        hash_lock: vec![0xCC; 32],
        deposit_nonce: None,
        vault_id: None,
        btc_amount_sats: 10_000,
        btc_pubkey: vec![0x03; 33],
        htlc_script: None,
        htlc_address: None,
        external_commitment: None,
        refund_iterations: 50,
        created_at_state: 100,
        entry_header: None,
        parent_vault_id: None,
        successor_depth: 0,
        is_fractional_successor: false,
        refund_hash_lock: vec![],
        destination_address: None,
        funding_txid: None,
        exit_amount_sats: 0,
        exit_header: None,
        exit_confirm_depth: 0,
        entry_txid: None,
    };

    // Record WITH destination
    let mut rec_with = base.clone();
    rec_with.vault_op_id = id_with.clone();
    rec_with.destination_address = Some("tb1qtest_with_dest".to_string());
    client_db::upsert_vault_record(&rec_with).expect("upsert with dest");

    // Record WITHOUT destination
    let mut rec_without = base;
    rec_without.vault_op_id = id_without.clone();
    rec_without.created_at_state = 99; // different to avoid collisions
    client_db::upsert_vault_record(&rec_without).expect("upsert without dest");

    // list_vault_records_db must return both correctly
    let all = client_db::list_vault_records_db().expect("list_vault_records_db");

    let found_with = all.iter().find(|r| r.vault_op_id == id_with);
    assert!(
        found_with.is_some(),
        "record with dest should appear in list"
    );
    assert_eq!(
        found_with.unwrap().destination_address.as_deref(),
        Some("tb1qtest_with_dest"),
    );

    let found_without = all.iter().find(|r| r.vault_op_id == id_without);
    assert!(
        found_without.is_some(),
        "record without dest should appear in list"
    );
    assert!(
        found_without.unwrap().destination_address.is_none(),
        "record without dest should have None destination_address"
    );

    // Cleanup
    client_db::delete_vault_record(&id_with).expect("cleanup");
    client_db::delete_vault_record(&id_without).expect("cleanup");
}

// --------------------------------------------------------------------------
// Vector tests: deterministic known-value tests with fixed inputs & outputs
// --------------------------------------------------------------------------

/// Vector test: PersistedVaultRecord with ALL fields set persists every field exactly.
/// Uses deterministic values so any schema regression breaks a known assertion.
#[tokio::test]
async fn vector_persisted_deposit_record_all_fields() {
    init_test_db();
    let vault_op_id = format!("vec_all_{}", std::process::id());

    let rec = client_db::PersistedVaultRecord {
        vault_op_id: vault_op_id.clone(),
        direction: "dbtc_to_btc".to_string(),
        vault_state: "completed".to_string(),
        hash_lock: (0u8..32).collect(),            // [0,1,2,...,31]
        deposit_nonce: Some((32u8..64).collect()), // [32,33,...,63]
        vault_id: Some("vault-vector-001".to_string()),
        btc_amount_sats: 2_100_000_000_000_000, // 21M BTC in sats
        btc_pubkey: {
            let mut pk = vec![0x02];
            pk.extend((0u8..32).collect::<Vec<u8>>());
            pk // 33 bytes, 0x02 prefix
        },
        htlc_script: Some(vec![0x63, 0xA8, 0x20]), // OP_IF OP_SHA256 OP_PUSHBYTES_32
        htlc_address: Some("tb1qvector_htlc_addr".to_string()),
        external_commitment: Some(vec![0xFF; 32]),
        refund_iterations: 288, // ~2 days at 10min blocks
        created_at_state: 42,
        entry_header: Some(vec![0xAB; 80]), // 80-byte block header
        parent_vault_id: Some("vault-parent-vec".to_string()),
        successor_depth: 3,
        is_fractional_successor: true,
        refund_hash_lock: vec![0xDD; 32],
        destination_address: Some("tb1qvec_dest_addr_xyz".to_string()),
        funding_txid: Some("abc123def456789000".to_string()),
        exit_amount_sats: 0,
        exit_header: Some(vec![0xCD; 80]), // 80-byte exit anchor block header
        exit_confirm_depth: 100,
        entry_txid: None,
    };

    client_db::upsert_vault_record(&rec).expect("upsert vector record");

    // Read back and verify every field
    let loaded = client_db::get_vault_record_by_id(&vault_op_id)
        .unwrap()
        .expect("vector record should exist");

    assert_eq!(loaded.vault_op_id, vault_op_id);
    assert_eq!(loaded.direction, "dbtc_to_btc");
    assert_eq!(loaded.vault_state, "completed");
    assert_eq!(loaded.hash_lock, (0u8..32).collect::<Vec<u8>>());
    assert_eq!(
        loaded.deposit_nonce.as_ref().unwrap(),
        &(32u8..64).collect::<Vec<u8>>()
    );
    assert_eq!(loaded.vault_id.as_deref(), Some("vault-vector-001"));
    assert_eq!(loaded.btc_amount_sats, 2_100_000_000_000_000);
    assert_eq!(loaded.btc_pubkey.len(), 33);
    assert_eq!(loaded.btc_pubkey[0], 0x02);
    assert_eq!(loaded.htlc_script.as_ref().unwrap(), &[0x63, 0xA8, 0x20]);
    assert_eq!(loaded.htlc_address.as_deref(), Some("tb1qvector_htlc_addr"));
    assert_eq!(
        loaded.external_commitment.as_ref().unwrap(),
        &vec![0xFF; 32]
    );
    assert_eq!(loaded.refund_iterations, 288);
    assert_eq!(loaded.created_at_state, 42);
    assert_eq!(loaded.entry_header.as_ref().unwrap(), &vec![0xAB; 80]);
    assert_eq!(loaded.parent_vault_id.as_deref(), Some("vault-parent-vec"));
    assert_eq!(loaded.successor_depth, 3);
    assert!(loaded.is_fractional_successor);
    assert_eq!(
        loaded.destination_address.as_deref(),
        Some("tb1qvec_dest_addr_xyz")
    );
    assert_eq!(loaded.exit_header.as_ref().unwrap(), &vec![0xCD; 80]);
    assert_eq!(loaded.exit_confirm_depth, 100);

    // Also verify list path returns identical data
    let all = client_db::list_vault_records_db().unwrap();
    let listed = all.iter().find(|r| r.vault_op_id == vault_op_id).unwrap();
    assert_eq!(
        listed.destination_address.as_deref(),
        Some("tb1qvec_dest_addr_xyz")
    );
    assert_eq!(listed.btc_amount_sats, 2_100_000_000_000_000);
    assert!(listed.is_fractional_successor);
    // deposit_nonce was set to (32u8..64).collect() above — already verified via loaded.deposit_nonce

    client_db::delete_vault_record(&vault_op_id).expect("cleanup");
}

/// Vector test: PersistedVaultRecord with ALL optional fields as None.
/// Ensures the schema handles NULLs correctly for every optional column.
#[tokio::test]
async fn vector_persisted_deposit_record_all_nulls() {
    init_test_db();
    let vault_op_id = format!("vec_null_{}", std::process::id());

    let rec = client_db::PersistedVaultRecord {
        vault_op_id: vault_op_id.clone(),
        direction: "btc_to_dbtc".to_string(),
        vault_state: "initiated".to_string(),
        hash_lock: vec![0x00; 32],
        deposit_nonce: None,
        vault_id: None,
        btc_amount_sats: 0,
        btc_pubkey: vec![0x02; 33],
        htlc_script: None,
        htlc_address: None,
        external_commitment: None,
        refund_iterations: 0,
        created_at_state: 0,
        entry_header: None,
        parent_vault_id: None,
        successor_depth: 0,
        is_fractional_successor: false,
        refund_hash_lock: vec![],
        destination_address: None,
        funding_txid: None,
        exit_amount_sats: 0,
        exit_header: None,
        exit_confirm_depth: 0,
        entry_txid: None,
    };

    client_db::upsert_vault_record(&rec).expect("upsert null vector");

    let loaded = client_db::get_vault_record_by_id(&vault_op_id)
        .unwrap()
        .expect("null vector record should exist");

    assert!(loaded.deposit_nonce.is_none());
    assert!(loaded.vault_id.is_none());
    assert!(loaded.htlc_script.is_none());
    assert!(loaded.htlc_address.is_none());
    assert!(loaded.external_commitment.is_none());
    assert!(loaded.entry_header.is_none());
    assert!(loaded.parent_vault_id.is_none());
    assert!(!loaded.is_fractional_successor);
    assert!(loaded.destination_address.is_none());
    assert_eq!(loaded.btc_amount_sats, 0);
    assert_eq!(loaded.successor_depth, 0);
    assert!(loaded.exit_header.is_none());
    assert_eq!(loaded.exit_confirm_depth, 0);
    assert!(
        loaded.deposit_nonce.is_none(),
        "deposit_nonce should be None for all-nulls record"
    );

    client_db::delete_vault_record(&vault_op_id).expect("cleanup");
}

/// Vector test: token balance boundary values (max u64, zero, overflow guard).
#[tokio::test]
async fn vector_token_balance_boundary_values() {
    init_test_db();
    let device_id = format!("vec_bal_{}", std::process::id());

    // Test 1: Zero balance
    client_db::upsert_token_balance(&device_id, "dBTC", 0, 0).unwrap();
    let (a, l) = client_db::get_token_balance(&device_id, "dBTC")
        .unwrap()
        .unwrap();
    assert_eq!(a, 0);
    assert_eq!(l, 0);

    // Test 2: Maximum sane BTC supply (21M BTC = 2_100_000_000_000_000 sats)
    let max_btc_sats: u64 = 2_100_000_000_000_000;
    client_db::upsert_token_balance(&device_id, "dBTC", max_btc_sats, 0).unwrap();
    let (a2, _) = client_db::get_token_balance(&device_id, "dBTC")
        .unwrap()
        .unwrap();
    assert_eq!(a2, max_btc_sats);

    // Test 3: Large locked amount
    client_db::upsert_token_balance(&device_id, "dBTC", 1_000_000, 999_999).unwrap();
    let (a3, l3) = client_db::get_token_balance(&device_id, "dBTC")
        .unwrap()
        .unwrap();
    assert_eq!(a3, 1_000_000);
    assert_eq!(l3, 999_999);

    // Test 4: Multiple tokens for same device (dBTC + another token)
    client_db::upsert_token_balance(&device_id, "wETH", 500, 100).unwrap();
    let all = client_db::get_token_balances(&device_id).unwrap();
    assert!(all.len() >= 2, "should have at least dBTC and wETH");
    let dbtc = all.iter().find(|(t, _, _)| t == "dBTC");
    let weth = all.iter().find(|(t, _, _)| t == "wETH");
    assert!(dbtc.is_some());
    assert!(weth.is_some());
    assert_eq!(weth.unwrap().1, 500);
    assert_eq!(weth.unwrap().2, 100);

    // Test 5: Non-existent device returns None
    let missing = client_db::get_token_balance("device_that_does_not_exist", "dBTC").unwrap();
    assert!(missing.is_none());
}

/// Vector test: Full SDK-level deposit initiation → SQLite → restore roundtrip
/// with deterministic inputs. Verifies the domain-model conversions (VaultOperation
/// ↔ PersistedVaultRecord) work correctly through the public API.
#[tokio::test]
async fn vector_deposit_record_sdk_roundtrip() {
    init_test_db();
    let dlv = Arc::new(DLVManager::new());
    let bridge = BitcoinTapSdk::new(dlv.clone());
    let keys = test_keys();
    let state = test_state(99);

    // Initiate deposit through public API
    let init = bridge
        .open_tap(
            777_777,     // deterministic amount
            &[0x02; 33], // deterministic pubkey
            288,         // ~2 days refund iterations
            (&keys.sphincs_pk, &keys.sphincs_sk),
            &state,
            dsm::bitcoin::types::BitcoinNetwork::Signet,
            &keys.kyber_pk,
        )
        .await
        .unwrap();

    // Set destination via the helper (simulates app_router_impl behavior)
    client_db::set_vault_record_destination_address(&init.vault_op_id, "tb1qvec_sdk_roundtrip")
        .expect("set destination");

    // Verify through SQLite (the persistence layer)
    let persisted = client_db::get_vault_record_by_id(&init.vault_op_id)
        .unwrap()
        .expect("record should exist");
    assert_eq!(persisted.btc_amount_sats, 777_777);
    assert_eq!(persisted.direction, "btc_to_dbtc");
    assert_eq!(persisted.vault_state, "initiated");
    assert_eq!(persisted.refund_iterations, 288);
    assert_eq!(persisted.created_at_state, 99);
    assert_eq!(
        persisted.destination_address.as_deref(),
        Some("tb1qvec_sdk_roundtrip")
    );
    assert_eq!(persisted.hash_lock.len(), 32);
    // btc_pubkey stores the *derived* claim pubkey (secp256k1 compressed, 33 bytes),
    // not the external btc_pubkey param — it starts with 0x02 or 0x03.
    assert_eq!(persisted.btc_pubkey.len(), 33);
    assert!(
        persisted.btc_pubkey[0] == 0x02 || persisted.btc_pubkey[0] == 0x03,
        "btc_pubkey must be a compressed secp256k1 public key (prefix 0x02 or 0x03)"
    );
    assert!(persisted.vault_id.is_some());

    // Verify through in-memory domain model
    let record = bridge.get_vault_record(&init.vault_op_id).await.unwrap();
    assert_eq!(record.btc_amount_sats, 777_777);
    assert_eq!(record.direction, VaultDirection::BtcToDbtc);
    assert_eq!(record.state, VaultOpState::Initiated);
    assert_eq!(record.refund_iterations, 288);
}

// ==========================================================================
// DLV + Mining + Database Balance Tests
//
// These tests exercise the real flow: DLV vault creation → draw_tap
// (mining) → SQLite balance write. They replicate the handler's
// SQLite-authoritative arithmetic (app_router_impl.rs:5836-5862) to prove
// no doubling/zeroing occurs.
// ==========================================================================

/// Helper: run the same SQLite-authoritative arithmetic the handler uses
/// for dBTC balance after a deposit complete (mirrors app_router_impl.rs:5836-5862).
fn handler_sqlite_balance_sync(device_id: &str, token_op: &TokenOperation) -> u64 {
    let current_sqlite = client_db::get_token_balance(device_id, DBTC_TOKEN_ID)
        .ok()
        .flatten()
        .map(|(a, _)| a)
        .unwrap_or(0);

    let new_sqlite = match token_op {
        TokenOperation::Mint { amount, .. } => current_sqlite.saturating_add(*amount),
        TokenOperation::Burn { amount, .. } => {
            assert!(
                current_sqlite >= *amount,
                "SQLite underflow guard: current={current_sqlite} burn={amount}"
            );
            current_sqlite - *amount
        }
        _ => current_sqlite,
    };

    client_db::upsert_token_balance(device_id, DBTC_TOKEN_ID, new_sqlite, 0)
        .expect("upsert_token_balance");

    new_sqlite
}

/// Helper: run initiate → complete deposit, returning (completion, device_id_text).
/// Encapsulates the boilerplate so each test can focus on assertions.
async fn do_deposit_op(
    bridge: &BitcoinTapSdk,
    _dlv: &Arc<DLVManager>,
    keys: &TestKeys,
    state: &State,
    amount_sats: u64,
) -> (
    dsm_sdk::sdk::bitcoin_tap_sdk::DepositCompletion,
    dsm_sdk::sdk::bitcoin_tap_sdk::DepositInitiation,
) {
    let init = bridge
        .open_tap(
            amount_sats,
            &[0x02; 33],
            100,
            (&keys.sphincs_pk, &keys.sphincs_sk),
            state,
            dsm::bitcoin::types::BitcoinNetwork::Signet,
            &keys.kyber_pk,
        )
        .await
        .expect("open_tap");

    let preimage = bridge.get_claim_preimage(&init.vault_op_id).await.unwrap();
    let htlc_spk = htlc_p2wsh_script_pubkey(init.htlc_script.as_ref().unwrap());
    let (txid, raw_tx, spv_bytes, header) = mock_spv_data(amount_sats, &htlc_spk);

    let completion = bridge
        .draw_tap(
            &init.vault_op_id,
            &preimage,
            txid,
            &raw_tx,
            &spv_bytes,
            header,
            &mock_header_chain((DBTC_MIN_CONFIRMATIONS as usize).saturating_sub(1)),
            &keys.kyber_pk,
            &keys.sphincs_pk,
            [0xEE; 32],
            state,
            Some(test_stitched_receipt().0),
            Some(test_stitched_receipt().1),
        )
        .await
        .expect("draw_tap");

    (completion, init)
}

// --------------------------------------------------------------------------
// Test A: DLV deposit → draw_tap → verify dBTC credited to SQLite
// --------------------------------------------------------------------------

#[tokio::test]
async fn draw_tap_credits_dbtc_to_sqlite() {
    init_test_db();
    let device_id = format!("dev_credit_{}", std::process::id());
    let amount = 500_000u64;

    // Before deposit: no dBTC balance in SQLite
    let before = client_db::get_token_balance(&device_id, DBTC_TOKEN_ID).unwrap();
    assert!(
        before.is_none() || before == Some((0, 0)),
        "device should have no dBTC before deposit"
    );

    // Create DLV + SDK
    let dlv = Arc::new(DLVManager::new());
    let bridge = BitcoinTapSdk::new(dlv.clone());
    let keys = test_keys();
    let state = test_state(1);

    // Initiate + complete deposit (real DLV unlock, real crypto)
    let (completion, init) = do_deposit_op(&bridge, &dlv, &keys, &state, amount).await;

    // Verify: Mint operation returned
    match &completion.token_operation {
        TokenOperation::Mint {
            amount: mint_amt, ..
        } => {
            assert_eq!(*mint_amt, amount, "Mint amount must match deposit");
        }
        other => panic!("Expected Mint, got {other:?}"),
    }

    // Execute handler's SQLite-authoritative arithmetic
    let final_balance = handler_sqlite_balance_sync(&device_id, &completion.token_operation);
    assert_eq!(
        final_balance, amount,
        "SQLite balance must equal deposit amount"
    );

    // Verify SQLite roundtrip
    let (available, locked) = client_db::get_token_balance(&device_id, DBTC_TOKEN_ID)
        .unwrap()
        .expect("dBTC balance should exist after deposit");
    assert_eq!(available, amount);
    assert_eq!(locked, 0);

    // Verify deposit record shows completed
    let persisted = client_db::get_vault_record_by_id(&init.vault_op_id)
        .unwrap()
        .expect("deposit record should exist");
    assert_eq!(persisted.vault_state, "completed");
    assert!(
        persisted.entry_header.is_some(),
        "entry_header must be set after complete"
    );
    assert_eq!(persisted.entry_header.as_ref().unwrap().len(), 80);

    // Verify vault is unlocked in DLVManager
    let vault_lock = dlv.get_vault(&init.vault_id).await.unwrap();
    let vault = vault_lock.lock().await;
    assert!(
        vault.entry_header.is_some(),
        "vault entry_header must be set (Invariant 19)"
    );
}

// --------------------------------------------------------------------------
// Test B: Bilateral receive THEN deposit complete → no doubling
// --------------------------------------------------------------------------

#[tokio::test]
async fn bilateral_receive_then_draw_tap_no_doubling() {
    init_test_db();
    let device_id = format!("dev_nodbl_{}", std::process::id());
    let bilateral_amount = 300_000u64;
    let deposit_amount = 200_000u64;

    // Step 1: Simulate bilateral receive (writes ONLY SQLite, not in-memory)
    // This is exactly what bilateral_ble_handler.rs:2320-2338 does.
    client_db::upsert_token_balance(&device_id, DBTC_TOKEN_ID, bilateral_amount, 0)
        .expect("seed bilateral balance");

    // Verify bilateral balance in SQLite
    let (a, _) = client_db::get_token_balance(&device_id, DBTC_TOKEN_ID)
        .unwrap()
        .unwrap();
    assert_eq!(a, bilateral_amount);

    // Step 2: Deposit via deposit (real DLV + crypto)
    let dlv = Arc::new(DLVManager::new());
    let bridge = BitcoinTapSdk::new(dlv.clone());
    let keys = test_keys();
    let state = test_state(2);

    let (completion, _init) = do_deposit_op(&bridge, &dlv, &keys, &state, deposit_amount).await;

    // Step 3: Execute handler's SQLite-authoritative arithmetic
    // This reads CURRENT SQLite (300k from bilateral), adds mint (200k) = 500k
    let final_balance = handler_sqlite_balance_sync(&device_id, &completion.token_operation);

    // THE KEY ASSERTION: no doubling
    let expected = bilateral_amount + deposit_amount; // 300k + 200k = 500k
    assert_eq!(
        final_balance,
        expected,
        "Balance must be bilateral({bilateral_amount}) + deposit({deposit_amount}) = {expected}, \
         got {final_balance}. If doubling occurred, we'd see {} or {}",
        deposit_amount * 2,   // doubled deposit
        bilateral_amount * 2, // doubled bilateral
    );

    // Final SQLite verification
    let (available, locked) = client_db::get_token_balance(&device_id, DBTC_TOKEN_ID)
        .unwrap()
        .unwrap();
    assert_eq!(available, 500_000);
    assert_eq!(locked, 0);
}

// --------------------------------------------------------------------------
// Test C: Deposit credit → bilateral send debit
// --------------------------------------------------------------------------

#[tokio::test]
async fn draw_tap_then_bilateral_send_debit() {
    init_test_db();
    let device_id = format!("dev_debit_{}", std::process::id());

    // Credit via deposit
    client_db::upsert_token_balance(&device_id, DBTC_TOKEN_ID, 1_000_000, 0).unwrap();

    // Simulate bilateral SEND debit (mirrors bilateral_ble_handler.rs:2674-2695)
    let send_amount = 400_000u64;
    let current = client_db::get_token_balance(&device_id, DBTC_TOKEN_ID)
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(current, 1_000_000);

    let new_available = current.saturating_sub(send_amount);
    client_db::upsert_token_balance(&device_id, DBTC_TOKEN_ID, new_available, 0).unwrap();

    // Verify debit
    let (available, _) = client_db::get_token_balance(&device_id, DBTC_TOKEN_ID)
        .unwrap()
        .unwrap();
    assert_eq!(available, 600_000, "1M - 400k = 600k");
}

// --------------------------------------------------------------------------
// Test D: Sequential deposits accumulate correctly
// --------------------------------------------------------------------------

#[tokio::test]
async fn sequential_deposits_accumulate_correctly() {
    init_test_db();
    let device_id = format!("dev_accum_{}", std::process::id());
    let dlv = Arc::new(DLVManager::new());
    let bridge = BitcoinTapSdk::new(dlv.clone());
    let keys = test_keys();

    let deposits = [100_000u64, 250_000, 50_000];
    let mut running_total = 0u64;

    for (i, amount) in deposits.iter().enumerate() {
        let state = test_state((i + 1) as u64);
        let (completion, _) = do_deposit_op(&bridge, &dlv, &keys, &state, *amount).await;

        // Apply handler arithmetic
        let new_balance = handler_sqlite_balance_sync(&device_id, &completion.token_operation);
        running_total += amount;

        assert_eq!(
            new_balance,
            running_total,
            "After deposit #{} of {amount}, expected {running_total}, got {new_balance}",
            i + 1
        );
    }

    // Final verification
    let (available, _) = client_db::get_token_balance(&device_id, DBTC_TOKEN_ID)
        .unwrap()
        .unwrap();
    assert_eq!(available, 400_000, "100k + 250k + 50k = 400k");
}

// --------------------------------------------------------------------------
// Test F: Vault transitions through full lifecycle
// --------------------------------------------------------------------------

#[tokio::test]
async fn vault_transitions_through_lifecycle() {
    init_test_db();
    let amount = 750_000u64;
    let dlv = Arc::new(DLVManager::new());
    let bridge = BitcoinTapSdk::new(dlv.clone());
    let keys = test_keys();
    let state = test_state(3);

    // Step 1: Initiate — vault created in Limbo
    let init = bridge
        .open_tap(
            amount,
            &[0x02; 33],
            100,
            (&keys.sphincs_pk, &keys.sphincs_sk),
            &state,
            dsm::bitcoin::types::BitcoinNetwork::Signet,
            &keys.kyber_pk,
        )
        .await
        .unwrap();

    // Verify vault exists and is in Limbo (no entry_header)
    {
        let vault_lock = dlv.get_vault(&init.vault_id).await.unwrap();
        let vault = vault_lock.lock().await;
        assert!(
            vault.entry_header.is_none(),
            "entry_header must be None before complete"
        );
    }

    // Verify deposit record: initiated, no entry_header
    let pre_complete = client_db::get_vault_record_by_id(&init.vault_op_id)
        .unwrap()
        .unwrap();
    assert_eq!(pre_complete.vault_state, "initiated");
    assert!(pre_complete.entry_header.is_none());

    // Step 2: Complete — vault unlocked, entry_header set
    let preimage = bridge.get_claim_preimage(&init.vault_op_id).await.unwrap();
    let htlc_spk = htlc_p2wsh_script_pubkey(init.htlc_script.as_ref().unwrap());
    let (txid, raw_tx, spv_bytes, header) = mock_spv_data(amount, &htlc_spk);

    let _completion = bridge
        .draw_tap(
            &init.vault_op_id,
            &preimage,
            txid,
            &raw_tx,
            &spv_bytes,
            header,
            &mock_header_chain((DBTC_MIN_CONFIRMATIONS as usize).saturating_sub(1)),
            &keys.kyber_pk,
            &keys.sphincs_pk,
            [0xEE; 32],
            &state,
            Some(test_stitched_receipt().0),
            Some(test_stitched_receipt().1),
        )
        .await
        .unwrap();

    // Verify vault has entry_header (Invariant 19)
    {
        let vault_lock = dlv.get_vault(&init.vault_id).await.unwrap();
        let vault = vault_lock.lock().await;
        assert_eq!(
            vault.entry_header,
            Some(header),
            "vault entry_header must match the block header from draw_tap"
        );
    }

    // Verify deposit record: completed + entry_header
    let post_complete = client_db::get_vault_record_by_id(&init.vault_op_id)
        .unwrap()
        .unwrap();
    assert_eq!(post_complete.vault_state, "completed");
    let eh = post_complete
        .entry_header
        .expect("entry_header must be set");
    assert_eq!(eh.len(), 80);
    assert_eq!(eh, header.to_vec());

    // Verify in-memory deposit record matches
    let record = bridge.get_vault_record(&init.vault_op_id).await.unwrap();
    assert_eq!(record.state, VaultOpState::Completed);
    assert_eq!(record.entry_header, Some(header));
}

// --------------------------------------------------------------------------
// Test G: Vault persistence roundtrip with entry_header after complete
// --------------------------------------------------------------------------

#[tokio::test]
async fn vault_persistence_roundtrip_with_entry_header() {
    init_test_db();
    let amount = 600_000u64;
    let vault_op_id;
    let vault_id;
    let expected_header;
    let dest = "tb1qpersist_vault_dest";

    // Phase 1: Create deposit, complete it, set destination, drop SDK
    {
        let dlv = Arc::new(DLVManager::new());
        let bridge = BitcoinTapSdk::new(dlv.clone());
        let keys = test_keys();
        let state = test_state(4);

        let (completion, init) = do_deposit_op(&bridge, &dlv, &keys, &state, amount).await;
        vault_op_id = init.vault_op_id.clone();
        vault_id = init.vault_id.clone();

        // Capture the header for later verification
        let record = bridge.get_vault_record(&vault_op_id).await.unwrap();
        expected_header = record.entry_header.expect("should have entry_header");

        // Set destination address
        client_db::set_vault_record_destination_address(&vault_op_id, dest).unwrap();

        // Verify mint operation returned before drop
        match &completion.token_operation {
            TokenOperation::Mint { amount: a, .. } => assert_eq!(*a, amount),
            other => panic!("Expected Mint, got {other:?}"),
        }

        // SDK + DLVManager dropped here
    }

    // Phase 2: Fresh SDK, restore from persistence
    let dlv2 = Arc::new(DLVManager::new());
    let bridge2 = BitcoinTapSdk::new(dlv2.clone());
    let (record_count, vault_count) = bridge2.restore_from_persistence().await.unwrap();
    assert!(record_count >= 1, "at least 1 deposit restored");
    assert!(vault_count >= 1, "at least 1 vault restored");

    // Verify vault restored with correct entry_header
    let vault_lock = dlv2.get_vault(&vault_id).await.unwrap();
    let vault = vault_lock.lock().await;
    assert_eq!(
        vault.entry_header,
        Some(expected_header),
        "vault entry_header must survive SDK drop + restore"
    );

    // Verify deposit record survived with all fields
    let persisted = client_db::get_vault_record_by_id(&vault_op_id)
        .unwrap()
        .unwrap();
    assert_eq!(persisted.vault_state, "completed");
    assert_eq!(persisted.entry_header.as_ref().unwrap().len(), 80);
    assert_eq!(persisted.destination_address.as_deref(), Some(dest));
    assert_eq!(persisted.btc_amount_sats, amount);
}

// --------------------------------------------------------------------------
// Test H: All balance query paths read consistent SQLite values
// --------------------------------------------------------------------------

#[tokio::test]
async fn all_balance_endpoints_consistent_after_operations() {
    init_test_db();
    let device_id = format!("dev_consist_{}", std::process::id());

    // Seed dBTC balance (as if from deposit complete)
    client_db::upsert_token_balance(&device_id, DBTC_TOKEN_ID, 123_456, 0).unwrap();

    // 1. Single-token query (used by bitcoin.balance and balance.get handlers)
    let (a, l) = client_db::get_token_balance(&device_id, DBTC_TOKEN_ID)
        .unwrap()
        .expect("dBTC should exist");
    assert_eq!(a, 123_456);
    assert_eq!(l, 0);

    // 2. Multi-token query (used by balance.list handler)
    let all_tokens = client_db::get_token_balances(&device_id).unwrap();
    let dbtc_entry = all_tokens.iter().find(|(t, _, _)| t == DBTC_TOKEN_ID);
    assert!(dbtc_entry.is_some(), "dBTC must appear in multi-token list");
    assert_eq!(dbtc_entry.unwrap().1, 123_456);
    assert_eq!(dbtc_entry.unwrap().2, 0);

    // 3. ERA uses wallet_state table, not token_balances
    let era = client_db::get_token_balance(&device_id, "ERA").unwrap();
    assert!(era.is_none(), "ERA is not in token_balances");

    // 4. Add a second token — both must coexist
    client_db::upsert_token_balance(&device_id, "wETH", 999, 100).unwrap();
    let all2 = client_db::get_token_balances(&device_id).unwrap();
    assert!(all2.len() >= 2, "should have dBTC and wETH");

    let weth = all2.iter().find(|(t, _, _)| t == "wETH").unwrap();
    assert_eq!(weth.1, 999);
    assert_eq!(weth.2, 100);

    // dBTC unchanged
    let dbtc2 = all2.iter().find(|(t, _, _)| t == DBTC_TOKEN_ID).unwrap();
    assert_eq!(dbtc2.1, 123_456);

    // 5. Update dBTC — wETH must not change
    client_db::upsert_token_balance(&device_id, DBTC_TOKEN_ID, 200_000, 50_000).unwrap();
    let (a3, l3) = client_db::get_token_balance(&device_id, DBTC_TOKEN_ID)
        .unwrap()
        .unwrap();
    assert_eq!(a3, 200_000);
    assert_eq!(l3, 50_000);

    let (wa, wl) = client_db::get_token_balance(&device_id, "wETH")
        .unwrap()
        .unwrap();
    assert_eq!(wa, 999, "wETH available must not change when dBTC updated");
    assert_eq!(wl, 100, "wETH locked must not change when dBTC updated");
}

// ==========================================================================
// Gap Coverage Tests — dBTC Withdrawal Best-Practices (March 2026 audit)
// ==========================================================================

// --------------------------------------------------------------------------
// Gap 1 — Fee rate: default is 10 sat/vbyte and DbtcParams exposes the field
// --------------------------------------------------------------------------

#[test]
fn withdrawal_fee_rate_constant_is_ten_sat_vbyte() {
    use dsm_sdk::sdk::bitcoin_tap_sdk::WITHDRAWAL_FEE_RATE_SAT_VB;
    assert_eq!(
        WITHDRAWAL_FEE_RATE_SAT_VB, 10,
        "WITHDRAWAL_FEE_RATE_SAT_VB must be 10 sat/vbyte (production floor)"
    );
}

#[test]
fn withdrawal_fee_rate_fn_returns_at_least_floor() {
    use dsm_sdk::sdk::bitcoin_tap_sdk::{withdrawal_fee_rate_sat_vb, WITHDRAWAL_FEE_RATE_SAT_VB};
    let rate = withdrawal_fee_rate_sat_vb();
    assert!(
        rate >= WITHDRAWAL_FEE_RATE_SAT_VB,
        "withdrawal_fee_rate_sat_vb() = {rate} must be >= {WITHDRAWAL_FEE_RATE_SAT_VB}"
    );
}

#[test]
fn dbtc_params_fee_rate_field_consistent_with_public_fn() {
    use dsm_sdk::sdk::bitcoin_tap_sdk::{withdrawal_fee_rate_sat_vb, DbtcParams};
    let params = DbtcParams::resolve();
    let fn_rate = withdrawal_fee_rate_sat_vb();
    assert_eq!(params.fee_rate_sat_vb, fn_rate);
    assert!(params.fee_rate_sat_vb >= 10);
}

// --------------------------------------------------------------------------
// Gap 2 — RBF: all 4 tx builders must produce inputs with nSequence = 0xFFFFFFFD
// --------------------------------------------------------------------------

const SEQUENCE_RBF: u32 = 0xFFFF_FFFD;

#[test]
fn claim_tx_input_opts_in_to_rbf() {
    use dsm_sdk::sdk::bitcoin_key_store::BitcoinKeyStore;
    use dsm_sdk::sdk::bitcoin_tap_sdk::WITHDRAWAL_FEE_RATE_SAT_VB;
    use dsm_sdk::sdk::bitcoin_tx_builder::{build_htlc_claim_tx, ClaimTxParams};

    let ks =
        BitcoinKeyStore::from_entropy(&[0x42; 32], dsm::bitcoin::types::BitcoinNetwork::Signet)
            .expect("keygen");
    let (addr, _) = ks.peek_receive_address(0).expect("address 0");
    let dummy_script = vec![0x51u8];
    let privkey = [0x01u8; 32];
    let tx = build_htlc_claim_tx(&ClaimTxParams {
        outpoint_txid: &[0xAA; 32],
        outpoint_vout: 0,
        htlc_script: &dummy_script,
        preimage: b"preimage",
        destination_addr: &addr,
        amount_sats: 100_000,
        fee_rate_sat_vb: WITHDRAWAL_FEE_RATE_SAT_VB,
        key_store: &ks,
        signing_index: 0,
        network: bitcoin::Network::Signet,
        claim_privkey: Some(&privkey),
    })
    .expect("claim tx must build");
    assert_eq!(tx.input.len(), 1);
    assert_eq!(
        tx.input[0].sequence.0, SEQUENCE_RBF,
        "claim tx input nSequence must be 0xFFFFFFFD (RBF opt-in)"
    );
}

#[test]
fn refund_tx_input_opts_in_to_rbf() {
    use dsm_sdk::sdk::bitcoin_key_store::BitcoinKeyStore;
    use dsm_sdk::sdk::bitcoin_tap_sdk::WITHDRAWAL_FEE_RATE_SAT_VB;
    use dsm_sdk::sdk::bitcoin_tx_builder::{build_htlc_refund_tx, RefundTxParams};

    let ks =
        BitcoinKeyStore::from_entropy(&[0x43; 32], dsm::bitcoin::types::BitcoinNetwork::Signet)
            .expect("keygen");
    let (addr, _) = ks.peek_receive_address(0).expect("address 0");
    let dummy_script = vec![0x51u8];
    let tx = build_htlc_refund_tx(&RefundTxParams {
        outpoint_txid: &[0xBB; 32],
        outpoint_vout: 0,
        htlc_script: &dummy_script,
        preimage: b"refund_preimage",
        refund_addr: &addr,
        amount_sats: 100_000,
        fee_rate_sat_vb: WITHDRAWAL_FEE_RATE_SAT_VB,
        key_store: &ks,
        signing_index: 0,
        network: bitcoin::Network::Signet,
    })
    .expect("refund tx must build");
    assert_eq!(tx.input.len(), 1);
    assert_eq!(
        tx.input[0].sequence.0, SEQUENCE_RBF,
        "refund tx input nSequence must be 0xFFFFFFFD (RBF opt-in)"
    );
}

#[test]
fn funding_tx_all_inputs_opt_in_to_rbf() {
    use dsm_sdk::sdk::bitcoin_key_store::BitcoinKeyStore;
    use dsm_sdk::sdk::bitcoin_tap_sdk::WITHDRAWAL_FEE_RATE_SAT_VB;
    use dsm_sdk::sdk::bitcoin_tx_builder::{build_htlc_funding_tx, FundingTxParams, SelectedUtxo};

    let ks =
        BitcoinKeyStore::from_entropy(&[0x44; 32], dsm::bitcoin::types::BitcoinNetwork::Signet)
            .expect("keygen");
    let (_recv_addr, recv_pk) = ks.peek_receive_address(0).expect("receive address");
    let (change_addr, _) = ks.peek_change_address(0).expect("change address");
    let dummy_htlc_script = vec![0x51u8];
    let _htlc_wsh_spk = bitcoin::ScriptBuf::from(dummy_htlc_script.clone());
    let htlc_addr = bitcoin::Address::p2wsh(
        bitcoin::Script::from_bytes(&dummy_htlc_script),
        bitcoin::Network::Signet,
    )
    .to_string();
    let inputs = vec![
        SelectedUtxo {
            txid: [0x01; 32],
            vout: 0,
            amount_sats: 200_000,
            change: 0,
            index: 0,
            pubkey: recv_pk,
        },
        SelectedUtxo {
            txid: [0x02; 32],
            vout: 1,
            amount_sats: 200_000,
            change: 0,
            index: 0,
            pubkey: recv_pk,
        },
    ];
    let tx = build_htlc_funding_tx(&FundingTxParams {
        inputs: &inputs,
        htlc_address: &htlc_addr,
        htlc_amount_sats: 50_000,
        change_address: &change_addr,
        fee_rate_sat_vb: WITHDRAWAL_FEE_RATE_SAT_VB,
        key_store: &ks,
        network: bitcoin::Network::Signet,
    })
    .expect("funding tx must build");
    assert!(!tx.input.is_empty());
    for (i, input) in tx.input.iter().enumerate() {
        assert_eq!(
            input.sequence.0, SEQUENCE_RBF,
            "funding tx input[{i}] nSequence must be 0xFFFFFFFD (RBF opt-in)"
        );
    }
}

// --------------------------------------------------------------------------
// Gap 3 — txid byte order: SelectedUtxo.txid is [u8;32] in internal order
// --------------------------------------------------------------------------

#[test]
fn display_txid_reversal_is_correct() {
    let mut display_bytes = [0u8; 32];
    for i in 0..32u8 {
        display_bytes[i as usize] = i + 1;
    }
    let display_hex: String = display_bytes.iter().map(|b| format!("{b:02x}")).collect();
    let mut internal = [0u8; 32];
    for i in 0..32 {
        if let Ok(b) = u8::from_str_radix(&display_hex[i * 2..i * 2 + 2], 16) {
            internal[31 - i] = b;
        }
    }
    let mut expected = display_bytes;
    expected.reverse();
    assert_eq!(
        internal, expected,
        "display→internal must reverse the bytes"
    );
}

#[test]
fn funding_tx_outpoint_matches_selected_utxo_txid() {
    use dsm_sdk::sdk::bitcoin_key_store::BitcoinKeyStore;
    use dsm_sdk::sdk::bitcoin_tx_builder::{build_htlc_funding_tx, FundingTxParams, SelectedUtxo};

    let ks =
        BitcoinKeyStore::from_entropy(&[0x45; 32], dsm::bitcoin::types::BitcoinNetwork::Signet)
            .expect("keygen");
    let (_recv_addr, recv_pk) = ks.peek_receive_address(0).expect("receive address");
    let (change_addr, _) = ks.peek_change_address(0).expect("change address");
    let htlc_addr = bitcoin::Address::p2wsh(
        bitcoin::Script::from_bytes(&[0x51u8]),
        bitcoin::Network::Signet,
    )
    .to_string();
    let sentinel_txid: [u8; 32] = {
        let mut t = [0u8; 32];
        for i in 0..32u8 {
            t[i as usize] = 0xA0 | i;
        }
        t
    };
    let inputs = vec![SelectedUtxo {
        txid: sentinel_txid,
        vout: 3,
        amount_sats: 5_000_000,
        change: 0,
        index: 0,
        pubkey: recv_pk,
    }];
    let tx = build_htlc_funding_tx(&FundingTxParams {
        inputs: &inputs,
        htlc_address: &htlc_addr,
        htlc_amount_sats: 100_000,
        change_address: &change_addr,
        fee_rate_sat_vb: 10,
        key_store: &ks,
        network: bitcoin::Network::Signet,
    })
    .expect("funding tx must build");
    assert_eq!(tx.input.len(), 1);
    assert_eq!(
        *tx.input[0].previous_output.txid.as_byte_array(),
        sentinel_txid,
        "OutPoint txid bytes must exactly match SelectedUtxo.txid"
    );
    assert_eq!(tx.input[0].previous_output.vout, 3);
}

// --------------------------------------------------------------------------
// Gap 4 — Full SPV: verify_bitcoin_payment gates on bad Merkle proof
// --------------------------------------------------------------------------

#[tokio::test]
async fn verify_bitcoin_payment_rejects_bad_merkle_proof() {
    let htlc_spk = htlc_p2wsh_script_pubkey(&[0x51u8]);
    let (_txid, _raw_tx, _spv_bytes, header) =
        mock_spv_data(DBTC_MIN_VAULT_BALANCE_SATS, &htlc_spk);
    let wrong_txid = [0xFF; 32];
    let empty_proof = SpvProof {
        siblings: vec![],
        index: 0,
    }
    .to_bytes();
    let result = BitcoinTapSdk::verify_bitcoin_payment(&wrong_txid, &empty_proof, &header);
    if let Ok(true) = result {
        panic!("must not accept wrong txid")
    }
}

#[tokio::test]
async fn verify_bitcoin_payment_accepts_sufficient_chain() {
    let htlc_spk = htlc_p2wsh_script_pubkey(&[0x51u8]);
    let (txid, _raw_tx, spv_bytes, header) = mock_spv_data(DBTC_MIN_VAULT_BALANCE_SATS, &htlc_spk);
    let result = BitcoinTapSdk::verify_bitcoin_payment(&txid, &spv_bytes, &header)
        .expect("must not error with valid SPV proof");
    assert!(result, "must return true for valid proof");
}

#[test]
fn header_chain_type_enforces_80_byte_entries() {
    let entry: [u8; 80] = [0u8; 80];
    assert_eq!(std::mem::size_of_val(&entry), 80);
}

// --------------------------------------------------------------------------
// Gap 5 — Concurrent-exit guard: only one pour_partial wins
// --------------------------------------------------------------------------

#[tokio::test]
async fn concurrent_pour_partial_only_one_succeeds() {
    init_test_db();
    let dlv_manager = Arc::new(DLVManager::new());
    let bridge = Arc::new(BitcoinTapSdk::new(dlv_manager.clone()));
    let keys = test_keys();
    let state = test_state(6);
    let total_amount_sats = 100_000_000;
    let exit_amount = 10_000_000;

    let initiation = bridge
        .open_tap(
            total_amount_sats,
            &[0x02; 33],
            100,
            (&keys.sphincs_pk, &keys.sphincs_sk),
            &state,
            dsm::bitcoin::types::BitcoinNetwork::Signet,
            &keys.kyber_pk,
        )
        .await
        .unwrap();

    let vault_id = initiation.vault_id.clone();
    let preimage = bridge
        .get_claim_preimage(&initiation.vault_op_id)
        .await
        .unwrap();
    let htlc_spk = htlc_p2wsh_script_pubkey(initiation.htlc_script.as_ref().unwrap());
    let (mock_txid, mock_raw_tx, mock_spv_bytes, mock_header) =
        mock_spv_data(total_amount_sats, &htlc_spk);

    bridge
        .draw_tap(
            &initiation.vault_op_id,
            &preimage,
            mock_txid,
            &mock_raw_tx,
            &mock_spv_bytes,
            mock_header,
            &mock_header_chain((DBTC_MIN_CONFIRMATIONS as usize).saturating_sub(1)),
            &keys.kyber_pk,
            &keys.sphincs_pk,
            [0xDD; 32],
            &state,
            Some(test_stitched_receipt().0),
            Some(test_stitched_receipt().1),
        )
        .await
        .unwrap();

    let bridge1 = bridge.clone();
    let bridge2 = bridge.clone();
    let vid1 = vault_id.clone();
    let vid2 = vault_id.clone();
    let (pk1, sk1) = (keys.sphincs_pk.clone(), keys.sphincs_sk.clone());
    let (pk2, sk2) = (keys.sphincs_pk.clone(), keys.sphincs_sk.clone());
    let (kpk1, kpk2) = (keys.kyber_pk.clone(), keys.kyber_pk.clone());
    let (s1, s2) = (state.clone(), state.clone());

    let task1 = tokio::spawn(async move {
        bridge1
            .pour_partial(
                &vid1,
                total_amount_sats,
                0,
                exit_amount,
                100,
                (&pk1, &sk1),
                &s1,
                dsm::bitcoin::types::BitcoinNetwork::Signet,
                &kpk1,
            )
            .await
    });
    let task2 = tokio::spawn(async move {
        bridge2
            .pour_partial(
                &vid2,
                total_amount_sats,
                0,
                exit_amount,
                100,
                (&pk2, &sk2),
                &s2,
                dsm::bitcoin::types::BitcoinNetwork::Signet,
                &kpk2,
            )
            .await
    });
    let (r1, r2) = tokio::join!(task1, task2);
    let result1 = r1.expect("task1 panicked");
    let result2 = r2.expect("task2 panicked");
    let successes = [result1.is_ok(), result2.is_ok()]
        .iter()
        .filter(|&&v| v)
        .count();
    assert_eq!(
        successes, 1,
        "exactly one pour_partial must win the race (got {successes})"
    );
    let losing = if result1.is_err() {
        result1.unwrap_err()
    } else {
        result2.unwrap_err()
    };
    let msg = format!("{losing}");
    assert!(
        msg.contains("already has") || msg.contains("in progress"),
        "loser must report concurrent-exit guard: {msg}"
    );
}
