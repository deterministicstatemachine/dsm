#![allow(clippy::disallowed_methods)]

use dsm_sdk::handlers::app_router_impl::AppRouterImpl;
use dsm_sdk::init::SdkConfig;
use dsm_sdk::sdk::app_state::AppState;
use dsm_sdk::bridge::{AppRouter, AppInvoke, AppQuery};
use dsm_sdk::generated as proto;
use dsm_sdk::sdk::b0x_sdk::B0xSDK;
use prost::Message;
use dsm_sdk::storage_utils;
use dsm_sdk::sdk::storage_node_sdk::{StorageNodeConfig, StorageNodeSDK};
use dsm_sdk::storage::client_db::{
    ensure_wallet_state_for_device, store_contact, update_local_bilateral_chain_tip, ContactRecord,
    GenesisRecord, store_genesis_record_with_verification,
};
use std::process::Command;
use std::collections::HashMap;
use rand::{rngs::OsRng, RngCore};
use tokio::time::{timeout, Duration};

fn seed_era_projection(device_txt: &str, available: u64) {
    dsm_sdk::storage::client_db::upsert_balance_projection(
        &dsm_sdk::storage::client_db::BalanceProjectionRecord {
            balance_key: format!("test:{device_txt}:ERA"),
            device_id: device_txt.to_string(),
            token_id: "ERA".to_string(),
            policy_commit: dsm_sdk::util::text_id::encode_base32_crockford(
                dsm_sdk::policy::builtins::NATIVE_POLICY_COMMIT,
            ),
            available,
            locked: 0,
            source_state_hash: dsm_sdk::util::text_id::encode_base32_crockford(&[0u8; 32]),
            source_state_number: 0,
            updated_at: 0,
        },
    )
    .unwrap_or_else(|e| panic!("Failed to seed ERA projection: {e}"));
}

fn persist_live_genesis_record(
    genesis_device_id: &[u8],
    genesis_hash: &[u8],
    session_id: &str,
    entropy: &[u8],
    storage_nodes: &[String],
) {
    let genesis_record = GenesisRecord {
        genesis_id: dsm_sdk::util::text_id::encode_base32_crockford(genesis_hash),
        device_id: dsm_sdk::util::text_id::encode_base32_crockford(genesis_device_id),
        mpc_proof: session_id.to_string(),
        dbrw_binding: dsm_sdk::util::text_id::encode_base32_crockford(entropy),
        merkle_root: dsm_sdk::util::text_id::encode_base32_crockford(&[0u8; 32]),
        participant_count: 3,
        progress_marker: "genesis".to_string(),
        publication_hash: dsm_sdk::util::text_id::encode_base32_crockford(genesis_hash),
        storage_nodes: storage_nodes.to_vec(),
        entropy_hash: dsm_sdk::util::text_id::encode_base32_crockford(
            blake3::hash(entropy).as_bytes(),
        ),
        protocol_version: "v3".to_string(),
        hash_chain_proof: None,
        smt_proof: None,
        verification_step: None,
    };
    store_genesis_record_with_verification(&genesis_record)
        .unwrap_or_else(|e| panic!("Failed to store genesis record: {e}"));
    ensure_wallet_state_for_device(&genesis_record.device_id)
        .unwrap_or_else(|e| panic!("Failed to ensure wallet state for genesis device: {e}"));
}

/// E2E test: Online Transfer (ERA success + custom token rejection)
///
/// Validates:
/// 1. wallet.send with custom token (0 balance) fails with insufficient balance
/// 2. wallet.send ERA succeeds, sender balance decreases
/// 3. Bob receives ERA after inbox sync
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore] // Requires live AWS storage nodes
async fn e2e_online_transfer_era_and_custom_token() {
    unsafe {
        std::env::set_var("DSM_SDK_TEST_MODE", "1");
    }

    // Point at real AWS storage nodes via env config TOML
    let env_config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../new_frontend/public/dsm_env_config.toml");
    unsafe {
        std::env::set_var(
            "DSM_ENV_CONFIG_PATH",
            env_config_path.to_str().expect("config path"),
        );
    }

    // --- Setup Alice ---
    let (alice_pk, alice_sk) = dsm::crypto::sphincs::generate_sphincs_keypair()
        .unwrap_or_else(|e| panic!("Failed to generate Alice keys: {e}"));
    let pk_b32 = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &alice_pk);
    let sk_b32 = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &alice_sk);
    unsafe {
        std::env::set_var("DSM_SDK_TEST_IMPORT_PK", pk_b32);
        std::env::set_var("DSM_SDK_TEST_IMPORT_SK", sk_b32);
    }

    let temp_dir = std::env::temp_dir().join("dsm_e2e_online_transfer");
    if temp_dir.exists() {
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
    std::fs::create_dir_all(&temp_dir).unwrap_or_else(|e| panic!("Failed to create temp dir: {e}"));
    storage_utils::set_storage_base_dir(temp_dir.clone())
        .unwrap_or_else(|e| panic!("Failed to set storage dir: {e}"));

    let storage_config = StorageNodeConfig::from_env_config()
        .await
        .unwrap_or_else(|e| panic!("Failed to load storage config: {e}"));
    let storage_nodes = storage_config.node_urls.clone();
    let storage_sdk = StorageNodeSDK::new(storage_config.clone())
        .await
        .unwrap_or_else(|e| panic!("Failed to create StorageNodeSDK: {e}"));

    let mut os_rng = OsRng;
    let mut alice_entropy = vec![0u8; 32];
    os_rng.fill_bytes(&mut alice_entropy);

    println!("Creating Alice genesis via MPC...");
    let alice_genesis = timeout(
        Duration::from_secs(20),
        storage_sdk.create_genesis_with_mpc(Some(3), Some(alice_entropy)),
    )
    .await
    .unwrap_or_else(|e| panic!("Alice MPC genesis timeout: {e}"))
    .unwrap_or_else(|e| panic!("Alice MPC genesis failed: {e}"));

    let alice_genesis_hash = alice_genesis
        .genesis_hash
        .unwrap_or_else(|| panic!("Alice genesis_hash missing"));
    let alice_device_id = alice_genesis.genesis_device_id.clone();
    println!("✅ Alice genesis created");

    let alice_smt_root = [0u8; 32];
    dsm::utils::deterministic_time::update_progress_context(alice_smt_root, 0)
        .unwrap_or_else(|e| panic!("Failed to init Alice progress context: {e}"));

    let config = SdkConfig {
        node_id: "test-node".to_string(),
        storage_endpoints: storage_nodes.clone(),
        enable_offline: true,
    };

    AppState::set_identity_info(
        alice_device_id.clone(),
        alice_pk.clone(),
        alice_genesis_hash.clone(),
        alice_smt_root.to_vec(),
    );
    AppState::set_has_identity(true);

    let router = AppRouterImpl::new(config.clone())
        .unwrap_or_else(|e| panic!("Failed to init Alice AppRouter: {e}"));
    ensure_b0x_tokens(&router, &storage_nodes).await;
    clear_inbox_receipts();

    // --- Alice: Faucet claim ---
    let claim_req = proto::FaucetClaimRequest {
        device_id: alice_device_id.clone(),
    };
    let res = router
        .invoke(AppInvoke {
            method: "faucet.claim".to_string(),
            args: pack_proto(&claim_req),
        })
        .await;
    assert!(res.success, "Faucet claim failed: {:?}", res.error_message);

    let balances = fetch_balances(&router).await;
    let era_after_faucet = get_era_balance(&balances).unwrap_or(0);
    assert!(era_after_faucet > 0, "Expected ERA > 0 after faucet");
    println!("✅ Alice faucet: ERA = {}", era_after_faucet);

    // --- Alice: Create custom token "BETA" ---
    let beta_policy_anchor = blake3::hash(b"DSM/test-policy-beta").as_bytes()[..32].to_vec();
    let beta_max_supply = {
        let mut buf = [0u8; 16];
        buf[8..].copy_from_slice(&1_000_000u64.to_be_bytes());
        buf.to_vec()
    };

    let beta_req = proto::TokenCreateRequest {
        ticker: "BETA".to_string(),
        alias: "Beta Token".to_string(),
        decimals: 2,
        max_supply_u128: beta_max_supply,
        policy_anchor: beta_policy_anchor,
    };

    let res = router
        .invoke(AppInvoke {
            method: "token.create".to_string(),
            args: pack_proto(&beta_req),
        })
        .await;
    assert!(
        res.success,
        "token.create BETA failed: {:?}",
        res.error_message
    );

    let env = decode_framed_envelope(&res.data, "token.create BETA");
    let beta_resp = match env.payload {
        Some(proto::envelope::Payload::TokenCreateResponse(resp)) => resp,
        other => panic!("token.create BETA unexpected payload: {:?}", other),
    };
    assert!(beta_resp.success, "BETA create not successful");
    let beta_token_id = beta_resp.token_id.clone();
    println!("✅ Token BETA created: {}", beta_token_id);

    // --- Create Bob ---
    let storage_sdk_bob = StorageNodeSDK::new(storage_config.clone())
        .await
        .unwrap_or_else(|e| panic!("Failed to init Bob StorageNodeSDK: {e}"));
    let mut bob_entropy = vec![0u8; 32];
    os_rng.fill_bytes(&mut bob_entropy);

    println!("Creating Bob genesis via MPC...");
    let bob_genesis = timeout(
        Duration::from_secs(20),
        storage_sdk_bob.create_genesis_with_mpc(Some(3), Some(bob_entropy)),
    )
    .await
    .unwrap_or_else(|e| panic!("Bob MPC genesis timeout: {e}"))
    .unwrap_or_else(|e| panic!("Bob MPC genesis failed: {e}"));

    let bob_device_id = bob_genesis.genesis_device_id.clone();
    let bob_genesis_hash = bob_genesis
        .genesis_hash
        .unwrap_or_else(|| panic!("Bob genesis_hash missing"));
    let (bob_pk, bob_sk) = dsm::crypto::sphincs::generate_sphincs_keypair()
        .unwrap_or_else(|e| panic!("Failed to generate Bob keys: {e}"));
    println!("✅ Bob genesis created");

    // Register Bob in device tree
    let register_result = storage_sdk_bob
        .register_device_in_tree(&bob_device_id, &bob_genesis_hash)
        .await
        .unwrap_or_else(|e| panic!("Failed to register Bob in device tree: {e}"));
    println!(
        "✅ Bob registered in device tree: published={}",
        register_result.published_to_nodes
    );
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Add Bob as Alice's contact
    let _bob_device_id_b32 = dsm_sdk::util::text_id::encode_base32_crockford(&bob_device_id);
    let _bob_genesis_b32 = dsm_sdk::util::text_id::encode_base32_crockford(&bob_genesis_hash);

    let contact_qr = proto::ContactQrV3 {
        device_id: bob_device_id.clone(),
        network: "test".to_string(),
        storage_nodes: storage_nodes.iter().take(3).cloned().collect(),
        sdk_fingerprint: vec![0u8; 32],
        genesis_hash: bob_genesis_hash.to_vec(),
        signing_public_key: bob_pk.clone(),
        preferred_alias: String::new(),
    };

    let res = router
        .query(AppQuery {
            path: "contacts.handle_contact_qr_v3".to_string(),
            params: pack_proto(&contact_qr),
        })
        .await;
    assert!(
        res.success,
        "Add Bob as contact failed: {:?}",
        res.error_message
    );
    println!("✅ Bob added as Alice's contact");

    let chain_tip = compute_initial_chain_tip(
        &alice_device_id,
        &alice_genesis_hash,
        &bob_device_id,
        &bob_genesis_hash,
    );

    // ========== TEST 1: wallet.send BETA (should fail — 0 balance) ==========
    println!("\n--- TEST: wallet.send BETA to Bob (should fail) ---");
    let beta_transfer_req = proto::OnlineTransferRequest {
        token_id: beta_token_id.clone(),
        to_device_id: bob_device_id.clone(),
        amount: 5,
        memo: "BETA transfer (should fail)".to_string(),
        nonce: vec![0u8; 12],
        signature: vec![],
        from_device_id: alice_device_id.clone(),
        chain_tip: chain_tip.clone(),
        seq: 1,
        receipt_commit: vec![],
    };

    let res = router
        .invoke(AppInvoke {
            method: "wallet.send".to_string(),
            args: pack_proto(&beta_transfer_req),
        })
        .await;

    // The transfer should fail — Alice has 0 BETA balance
    if res.success && !res.data.is_empty() {
        let env = decode_framed_envelope(&res.data, "wallet.send BETA");
        match env.payload {
            Some(proto::envelope::Payload::OnlineTransferResponse(resp)) => {
                assert!(
                    !resp.success,
                    "wallet.send BETA should fail (insufficient balance) but succeeded"
                );
                println!("✅ BETA transfer rejected: {}", resp.message);
            }
            Some(proto::envelope::Payload::Error(e)) => {
                println!("✅ BETA transfer rejected with error: {}", e.message);
            }
            _ => {
                println!("✅ BETA transfer rejected (non-transfer payload)");
            }
        }
    } else {
        assert!(
            !res.success,
            "wallet.send BETA: expected failure for 0-balance token"
        );
        println!(
            "✅ BETA transfer rejected at router level: {:?}",
            res.error_message
        );
    }

    // ========== TEST 2: wallet.send ERA (should succeed) ==========
    println!("\n--- TEST: wallet.send ERA to Bob (should succeed) ---");
    let era_transfer_req = proto::OnlineTransferRequest {
        token_id: "ERA".to_string(),
        to_device_id: bob_device_id.clone(),
        amount: 10,
        memo: "ERA transfer".to_string(),
        nonce: vec![0u8; 12],
        signature: vec![],
        from_device_id: alice_device_id.clone(),
        chain_tip: chain_tip.clone(),
        seq: 1,
        receipt_commit: vec![],
    };

    let res = router
        .invoke(AppInvoke {
            method: "wallet.send".to_string(),
            args: pack_proto(&era_transfer_req),
        })
        .await;
    assert!(
        res.success,
        "wallet.send ERA failed: {:?}",
        res.error_message
    );
    println!("✅ ERA transfer success");

    // Verify Alice balance decreased
    let balances_after = fetch_balances(&router).await;
    let era_after_transfer = get_era_balance(&balances_after).unwrap_or(0);
    assert!(
        era_after_transfer + 10 <= era_after_faucet,
        "Expected ERA to decrease by at least 10 (before={}, after={})",
        era_after_faucet,
        era_after_transfer
    );
    println!(
        "✅ Alice ERA decreased: {} → {}",
        era_after_faucet, era_after_transfer
    );

    // ========== TEST 3: Bob syncs inbox, receives ERA ==========
    println!("\n--- TEST: Bob inbox sync ---");

    // Switch to Bob identity
    let bob_pk_b32 = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &bob_pk);
    let bob_sk_b32 = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &bob_sk);
    unsafe {
        std::env::set_var("DSM_SDK_TEST_IMPORT_PK", bob_pk_b32);
        std::env::set_var("DSM_SDK_TEST_IMPORT_SK", bob_sk_b32);
    }

    let bob_smt_root = [0u8; 32];
    dsm::utils::deterministic_time::update_progress_context(bob_smt_root, 0)
        .unwrap_or_else(|e| panic!("Failed to init Bob progress context: {e}"));

    AppState::set_identity_info(
        bob_device_id.clone(),
        bob_pk.clone(),
        bob_genesis_hash,
        bob_smt_root.to_vec(),
    );
    AppState::set_has_identity(true);

    let bob_router = tokio::task::block_in_place(|| {
        AppRouterImpl::new(config).unwrap_or_else(|e| panic!("Failed to init Bob AppRouter: {e}"))
    });

    // Add Alice as Bob's contact
    let _alice_device_id_b32 = dsm_sdk::util::text_id::encode_base32_crockford(&alice_device_id);
    let _alice_genesis_b32 = dsm_sdk::util::text_id::encode_base32_crockford(&alice_genesis_hash);
    let alice_contact_qr = proto::ContactQrV3 {
        device_id: alice_device_id.clone(),
        network: "test".to_string(),
        storage_nodes: storage_nodes.iter().take(3).cloned().collect(),
        sdk_fingerprint: vec![0u8; 32],
        genesis_hash: alice_genesis_hash.to_vec(),
        signing_public_key: alice_pk.clone(),
        preferred_alias: String::new(),
    };
    let res = bob_router
        .query(AppQuery {
            path: "contacts.handle_contact_qr_v3".to_string(),
            params: pack_proto(&alice_contact_qr),
        })
        .await;
    assert!(
        res.success,
        "Bob add-contact failed: {:?}",
        res.error_message
    );
    println!("✅ Alice added as Bob's contact");

    // Sync Bob's inbox with retries
    let mut bob_era = 0u64;
    let mut last_sync_errors: Vec<String> = Vec::new();
    let mut last_sync_pulled = 0u32;
    let mut last_sync_processed = 0u32;
    for _ in 0..5u8 {
        let sync_res = storage_sync(&bob_router).await;
        assert!(
            sync_res.success,
            "storage.sync failed for Bob: {:?}",
            sync_res.errors
        );
        last_sync_errors = sync_res.errors;
        last_sync_pulled = sync_res.pulled;
        last_sync_processed = sync_res.processed;

        let bob_balances = fetch_balances(&bob_router).await;
        bob_era = get_era_balance(&bob_balances).unwrap_or(0);
        if bob_era >= 10 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    assert!(
        bob_era >= 10,
        "Expected Bob ERA >= 10 after sync (got={}, pulled={}, processed={}, errors={:?})",
        bob_era,
        last_sync_pulled,
        last_sync_processed,
        last_sync_errors
    );
    println!("✅ Bob received ERA: balance = {}", bob_era);

    println!("\n✅✅ e2e_online_transfer PASSED ✅✅");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore] // Requires live AWS storage nodes via DSM_ENV_CONFIG_PATH
async fn live_aws_online_transfer_recipient_storage_sync() {
    unsafe {
        std::env::set_var("DSM_SDK_TEST_MODE", "1");
    }
    let storage_config = StorageNodeConfig::from_env_config()
        .await
        .unwrap_or_else(|e| panic!("Failed to load AWS storage config: {e}"));
    let storage_nodes = storage_config.node_urls.clone();
    assert!(
        !storage_nodes.is_empty(),
        "Expected AWS storage nodes from env config"
    );

    let temp_dir = std::env::temp_dir().join("dsm_live_aws_online_transfer");
    if temp_dir.exists() {
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
    std::fs::create_dir_all(&temp_dir).unwrap_or_else(|e| panic!("Failed to create temp dir: {e}"));
    storage_utils::set_storage_base_dir(temp_dir.clone())
        .unwrap_or_else(|e| panic!("Failed to set storage dir: {e}"));
    dsm_sdk::storage::client_db::reset_database_for_tests();

    let (sender_pk, sender_sk) = dsm::crypto::sphincs::generate_sphincs_keypair()
        .unwrap_or_else(|e| panic!("Failed to generate sender keys: {e}"));

    let zero_root = [0u8; 32];
    let config = SdkConfig {
        node_id: "aws-live-test".to_string(),
        storage_endpoints: storage_nodes.clone(),
        enable_offline: true,
    };
    let storage_sdk = StorageNodeSDK::new(storage_config.clone())
        .await
        .unwrap_or_else(|e| panic!("Failed to create live AWS StorageNodeSDK: {e}"));
    let (receiver_pk, receiver_sk) = dsm::crypto::sphincs::generate_sphincs_keypair()
        .unwrap_or_else(|e| panic!("Failed to generate receiver keys: {e}"));
    let mut os_rng = OsRng;
    let (receiver_device_id, receiver_genesis) = {
        let mut receiver_entropy = vec![0u8; 32];
        os_rng.fill_bytes(&mut receiver_entropy);
        let receiver_genesis = storage_sdk
            .create_genesis_with_mpc(Some(3), Some(receiver_entropy.clone()))
            .await
            .unwrap_or_else(|e| panic!("Receiver MPC genesis failed: {e}"));
        let receiver_device_id = receiver_genesis.genesis_device_id.clone();
        let receiver_genesis_hash = receiver_genesis
            .genesis_hash
            .clone()
            .unwrap_or_else(|| panic!("Receiver genesis_hash missing"));
        persist_live_genesis_record(
            &receiver_device_id,
            &receiver_genesis_hash,
            &receiver_genesis.session_id,
            &receiver_entropy,
            &receiver_genesis.participating_nodes,
        );
        unsafe {
            std::env::set_var(
                "DSM_SDK_TEST_IMPORT_PK",
                base32::encode(base32::Alphabet::RFC4648 { padding: false }, &receiver_pk),
            );
            std::env::set_var(
                "DSM_SDK_TEST_IMPORT_SK",
                base32::encode(base32::Alphabet::RFC4648 { padding: false }, &receiver_sk),
            );
        }
        AppState::set_identity_info(
            receiver_device_id.clone(),
            receiver_pk.clone(),
            receiver_genesis_hash.clone(),
            zero_root.to_vec(),
        );
        AppState::set_has_identity(true);
        dsm::utils::deterministic_time::update_progress_context(zero_root, 0)
            .unwrap_or_else(|e| panic!("Failed to init receiver progress context: {e}"));

        let receiver_router = AppRouterImpl::new(config.clone())
            .unwrap_or_else(|e| panic!("Failed to init receiver AppRouter: {e}"));
        let receiver_genesis = receiver_router
            .core_sdk
            .local_genesis_hash()
            .await
            .unwrap_or_else(|e| panic!("Receiver genesis missing: {e}"));
        (receiver_device_id, receiver_genesis)
    };

    dsm_sdk::storage::client_db::reset_database_for_tests();

    let (sender_device_id, sender_genesis, relationship_tip, expected_route) = {
        let mut sender_entropy = vec![0u8; 32];
        os_rng.fill_bytes(&mut sender_entropy);
        let sender_genesis_record = storage_sdk
            .create_genesis_with_mpc(Some(3), Some(sender_entropy.clone()))
            .await
            .unwrap_or_else(|e| panic!("Sender MPC genesis failed: {e}"));
        let sender_device_id = sender_genesis_record.genesis_device_id.clone();
        let sender_genesis_hash = sender_genesis_record
            .genesis_hash
            .clone()
            .unwrap_or_else(|| panic!("Sender genesis_hash missing"));
        persist_live_genesis_record(
            &sender_device_id,
            &sender_genesis_hash,
            &sender_genesis_record.session_id,
            &sender_entropy,
            &sender_genesis_record.participating_nodes,
        );
        unsafe {
            std::env::set_var(
                "DSM_SDK_TEST_IMPORT_PK",
                base32::encode(base32::Alphabet::RFC4648 { padding: false }, &sender_pk),
            );
            std::env::set_var(
                "DSM_SDK_TEST_IMPORT_SK",
                base32::encode(base32::Alphabet::RFC4648 { padding: false }, &sender_sk),
            );
        }
        AppState::set_identity_info(
            sender_device_id.clone(),
            sender_pk.clone(),
            sender_genesis_hash.clone(),
            zero_root.to_vec(),
        );
        AppState::set_has_identity(true);
        dsm::utils::deterministic_time::update_progress_context(zero_root, 0)
            .unwrap_or_else(|e| panic!("Failed to init sender progress context: {e}"));

        let sender_router = AppRouterImpl::new(config.clone())
            .unwrap_or_else(|e| panic!("Failed to init sender AppRouter: {e}"));
        let sender_genesis = sender_router
            .core_sdk
            .local_genesis_hash()
            .await
            .unwrap_or_else(|e| panic!("Sender genesis missing: {e}"));
        AppState::set_identity_info(
            sender_device_id.clone(),
            sender_pk.clone(),
            sender_genesis.clone(),
            zero_root.to_vec(),
        );
        ensure_b0x_tokens(&sender_router, &storage_nodes).await;

        let sender_device_b32 = dsm_sdk::util::text_id::encode_base32_crockford(&sender_device_id);
        seed_era_projection(&sender_device_b32, 1_000);

        let relationship_tip = compute_initial_chain_tip(
            &sender_device_id,
            &sender_genesis,
            &receiver_device_id,
            &receiver_genesis,
        );

        store_contact(&ContactRecord {
            contact_id: dsm_sdk::util::text_id::encode_base32_crockford(&receiver_device_id),
            device_id: receiver_device_id.clone(),
            alias: "receiver".to_string(),
            genesis_hash: receiver_genesis.clone(),
            public_key: receiver_pk.clone(),
            current_chain_tip: Some(relationship_tip.clone()),
            added_at: 1,
            verified: true,
            verification_proof: None,
            metadata: HashMap::new(),
            ble_address: None,
            status: "Created".to_string(),
            needs_online_reconcile: false,
            last_seen_online_counter: 0,
            last_seen_ble_counter: 0,
            previous_chain_tip: None,
        })
        .unwrap_or_else(|e| panic!("Failed to store receiver contact for sender: {e}"));
        update_local_bilateral_chain_tip(&receiver_device_id, &relationship_tip)
            .unwrap_or_else(|e| panic!("Failed to store sender local tip: {e}"));

        let transfer_req = proto::OnlineTransferRequest {
            token_id: "ERA".to_string(),
            to_device_id: receiver_device_id.clone(),
            amount: 10,
            memo: "AWS live inbox test".to_string(),
            nonce: vec![0u8; 12],
            signature: vec![],
            from_device_id: sender_device_id.clone(),
            chain_tip: relationship_tip.clone(),
            seq: 1,
            receipt_commit: vec![],
        };
        let send_res = sender_router
            .invoke(AppInvoke {
                method: "wallet.send".to_string(),
                args: pack_proto(&transfer_req),
            })
            .await;
        assert!(
            send_res.success,
            "wallet.send failed: {:?}",
            send_res.error_message
        );

        let expected_route = B0xSDK::compute_b0x_address(
            receiver_genesis.as_slice(),
            receiver_device_id.as_slice(),
            relationship_tip.as_slice(),
        )
        .expect("expected rotated route");

        (
            sender_device_id,
            sender_genesis,
            relationship_tip,
            expected_route,
        )
    };

    dsm_sdk::storage::client_db::reset_database_for_tests();

    unsafe {
        std::env::set_var(
            "DSM_SDK_TEST_IMPORT_PK",
            base32::encode(base32::Alphabet::RFC4648 { padding: false }, &receiver_pk),
        );
        std::env::set_var(
            "DSM_SDK_TEST_IMPORT_SK",
            base32::encode(base32::Alphabet::RFC4648 { padding: false }, &receiver_sk),
        );
    }
    AppState::set_identity_info(
        receiver_device_id.clone(),
        receiver_pk.clone(),
        vec![0u8; 32],
        zero_root.to_vec(),
    );
    AppState::set_has_identity(true);
    dsm::utils::deterministic_time::update_progress_context(zero_root, 0)
        .unwrap_or_else(|e| panic!("Failed to init receiver progress context: {e}"));

    let receiver_router = AppRouterImpl::new(config)
        .unwrap_or_else(|e| panic!("Failed to init receiver AppRouter: {e}"));
    let actual_receiver_genesis = receiver_router
        .core_sdk
        .local_genesis_hash()
        .await
        .unwrap_or_else(|e| panic!("Receiver genesis missing: {e}"));
    assert_eq!(
        actual_receiver_genesis, receiver_genesis,
        "receiver genesis should be stable across isolated phases"
    );
    AppState::set_identity_info(
        receiver_device_id.clone(),
        receiver_pk.clone(),
        receiver_genesis.clone(),
        zero_root.to_vec(),
    );
    ensure_b0x_tokens(&receiver_router, &storage_nodes).await;

    store_contact(&ContactRecord {
        contact_id: dsm_sdk::util::text_id::encode_base32_crockford(&sender_device_id),
        device_id: sender_device_id.clone(),
        alias: "sender".to_string(),
        genesis_hash: sender_genesis.clone(),
        public_key: sender_pk.clone(),
        current_chain_tip: Some(relationship_tip.clone()),
        added_at: 1,
        verified: true,
        verification_proof: None,
        metadata: HashMap::new(),
        ble_address: None,
        status: "Created".to_string(),
        needs_online_reconcile: false,
        last_seen_online_counter: 0,
        last_seen_ble_counter: 0,
        previous_chain_tip: None,
    })
    .unwrap_or_else(|e| panic!("Failed to store sender contact for receiver: {e}"));
    update_local_bilateral_chain_tip(&sender_device_id, &relationship_tip)
        .unwrap_or_else(|e| panic!("Failed to store receiver local tip: {e}"));

    let receiver_device_b32 = dsm_sdk::util::text_id::encode_base32_crockford(&receiver_device_id);
    let mut receiver_b0x = B0xSDK::new(
        receiver_device_b32.clone(),
        receiver_router.core_sdk.clone(),
        storage_nodes.clone(),
    )
    .expect("receiver b0x");
    receiver_b0x
        .register_device()
        .await
        .expect("receiver registration");

    let mut direct_items = Vec::new();
    for _ in 0..6 {
        direct_items = receiver_b0x
            .retrieve_from_b0x_v2(&expected_route, 10)
            .await
            .expect("direct receiver route retrieve");
        if !direct_items.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        !direct_items.is_empty(),
        "expected recipient route {} should expose the transfer before inbox.pull",
        expected_route,
    );

    AppState::set_identity_info(
        receiver_device_id.clone(),
        receiver_pk.clone(),
        receiver_genesis.clone(),
        zero_root.to_vec(),
    );

    let inbox_pull_res = receiver_router
        .query(AppQuery {
            path: "inbox.pull".to_string(),
            params: pack_proto(&proto::InboxRequest {
                limit: 20,
                chain_tip: String::new(),
            }),
        })
        .await;
    assert!(
        inbox_pull_res.success,
        "inbox.pull failed: {:?}",
        inbox_pull_res.error_message
    );
    let inbox_env = decode_framed_envelope(&inbox_pull_res.data, "inbox.pull");
    let inbox_resp = match inbox_env.payload {
        Some(proto::envelope::Payload::InboxResponse(resp)) => resp,
        other => panic!("inbox.pull unexpected payload: {:?}", other),
    };
    assert!(
        !inbox_resp.items.is_empty(),
        "receiver inbox should expose the incoming transfer before processing",
    );

    let sync_res = storage_sync(&receiver_router).await;
    assert!(
        sync_res.success,
        "storage.sync failed: {:?}",
        sync_res.errors
    );
    assert!(
        sync_res.processed > 0 || sync_res.pulled > 0,
        "storage.sync should pull/process the incoming transfer: {:?}",
        sync_res,
    );
    println!("live storage.sync response: {:?}", sync_res);

    receiver_router.sync_balance_cache();
    let receiver_balances = fetch_balances(&receiver_router).await;
    println!("live receiver balances: {:?}", receiver_balances);
    let receiver_era = get_era_balance(&receiver_balances).unwrap_or(0);
    assert!(
        receiver_era >= 10,
        "receiver ERA balance should increase after storage.sync, got {}",
        receiver_era,
    );

    let receiver_history = fetch_wallet_history(&receiver_router, 100).await;
    let online_receive = receiver_history
        .transactions
        .iter()
        .find(|tx| tx.tx_type == proto::TransactionType::TxTypeOnline as i32 && tx.amount == 10)
        .unwrap_or_else(|| {
            panic!(
                "receiver wallet.history should include the incoming online transfer: {:?}",
                receiver_history.transactions
            )
        });
    assert!(
        !online_receive.stitched_receipt.is_empty(),
        "receiver online transfer should expose stitched_receipt bytes in wallet.history"
    );
}

// --- Helpers ---

fn pack_proto<T: Message>(msg: &T) -> Vec<u8> {
    let mut body = Vec::new();
    msg.encode(&mut body)
        .unwrap_or_else(|e| panic!("encode body failed: {e}"));

    let pack = proto::ArgPack {
        schema_hash: Some(proto::Hash32 { v: vec![0; 32] }),
        codec: proto::Codec::Proto as i32,
        body,
    };

    let mut pack_bytes = Vec::new();
    pack.encode(&mut pack_bytes)
        .unwrap_or_else(|e| panic!("encode ArgPack failed: {e}"));
    pack_bytes
}

async fn fetch_balances(router: &AppRouterImpl) -> proto::BalancesListResponse {
    let res = router
        .query(AppQuery {
            path: "balance.list".to_string(),
            params: Vec::new(),
        })
        .await;
    if !res.success {
        panic!("balance.list failed: {:?}", res.error_message);
    }
    let env = decode_framed_envelope(&res.data, "balance.list");
    match env.payload {
        Some(proto::envelope::Payload::BalancesListResponse(resp)) => resp,
        other => panic!("balance.list unexpected payload: {:?}", other),
    }
}

async fn fetch_wallet_history(router: &AppRouterImpl, limit: u64) -> proto::WalletHistoryResponse {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&limit.to_le_bytes());
    body.extend_from_slice(&0u64.to_le_bytes());

    let pack = proto::ArgPack {
        schema_hash: Some(proto::Hash32 { v: vec![0; 32] }),
        codec: proto::Codec::Proto as i32,
        body,
    };

    let mut params = Vec::new();
    pack.encode(&mut params)
        .unwrap_or_else(|e| panic!("encode wallet.history ArgPack failed: {e}"));

    let res = router
        .query(AppQuery {
            path: "wallet.history".to_string(),
            params,
        })
        .await;
    if !res.success {
        panic!("wallet.history failed: {:?}", res.error_message);
    }
    let env = decode_framed_envelope(&res.data, "wallet.history");
    match env.payload {
        Some(proto::envelope::Payload::WalletHistoryResponse(resp)) => resp,
        other => panic!("wallet.history unexpected payload: {:?}", other),
    }
}

fn get_era_balance(resp: &proto::BalancesListResponse) -> Option<u64> {
    resp.balances
        .iter()
        .find(|b| b.token_id == "ERA")
        .map(|b| b.available)
}

fn compute_initial_chain_tip(
    device_a: &[u8],
    genesis_a: &[u8],
    device_b: &[u8],
    genesis_b: &[u8],
) -> Vec<u8> {
    let (genesis_1, device_1, genesis_2, device_2) = if device_a < device_b {
        (genesis_a, device_a, genesis_b, device_b)
    } else {
        (genesis_b, device_b, genesis_a, device_a)
    };

    let mut hasher = dsm::crypto::blake3::dsm_domain_hasher("DSM/bilateral-session");
    hasher.update(genesis_1);
    hasher.update(device_1);
    hasher.update(genesis_2);
    hasher.update(device_2);

    hasher.finalize().as_bytes().to_vec()
}

async fn storage_sync(router: &AppRouterImpl) -> proto::StorageSyncResponse {
    let req = proto::StorageSyncRequest {
        pull_inbox: true,
        push_pending: false,
        limit: 100,
    };
    let res = router
        .query(AppQuery {
            path: "storage.sync".to_string(),
            params: pack_proto(&req),
        })
        .await;
    if !res.success {
        panic!("storage.sync failed: {:?}", res.error_message);
    }
    let env = decode_framed_envelope(&res.data, "storage.sync");
    match env.payload {
        Some(proto::envelope::Payload::StorageSyncResponse(resp)) => resp,
        other => panic!("storage.sync unexpected payload: {:?}", other),
    }
}

fn decode_framed_envelope(bytes: &[u8], label: &str) -> proto::Envelope {
    assert!(!bytes.is_empty(), "{label}: empty response bytes");
    assert_eq!(bytes[0], 0x03, "{label}: expected FramedEnvelopeV3 prefix");
    proto::Envelope::decode(&bytes[1..]).unwrap_or_else(|e| panic!("decode Envelope failed: {e}"))
}

async fn ensure_b0x_tokens(router: &AppRouterImpl, endpoints: &[String]) {
    let device_id =
        AppState::get_device_id().unwrap_or_else(|| panic!("AppState device_id missing"));
    let device_id_b32 = dsm_sdk::util::text_id::encode_base32_crockford(&device_id);
    let b0x = B0xSDK::new(device_id_b32, router.core_sdk.clone(), endpoints.to_vec())
        .unwrap_or_else(|e| panic!("B0xSDK init failed: {e}"));

    for ep in endpoints {
        b0x.ensure_token_for_endpoint(ep)
            .await
            .unwrap_or_else(|e| panic!("b0x token acquisition failed for {}: {}", ep, e));
    }
}

fn clear_inbox_receipts() {
    let dbs = [
        "dsm_storage_node1",
        "dsm_storage_node2",
        "dsm_storage_node3",
    ];

    for db in dbs {
        let status = Command::new("psql")
            .args([
                "-h",
                "localhost",
                "-U",
                "dsm",
                "-d",
                db,
                "-c",
                "delete from inbox_receipts; delete from inbox_spool;",
            ])
            .status();

        if let Ok(st) = status {
            if !st.success() {
                panic!("Failed to clear inbox_receipts for {}", db);
            }
        } else {
            panic!("Failed to execute psql for {}", db);
        }
    }
}
