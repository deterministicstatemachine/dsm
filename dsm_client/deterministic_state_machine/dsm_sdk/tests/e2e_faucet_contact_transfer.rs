#![allow(clippy::disallowed_methods)]

use dsm_sdk::handlers::app_router_impl::AppRouterImpl;
use dsm_sdk::init::SdkConfig;
use dsm_sdk::sdk::app_state::AppState;
use dsm_sdk::bridge::{AppRouter, AppInvoke, AppQuery};
use dsm_sdk::generated as proto;
use prost::Message;
use dsm_sdk::storage_utils;
use dsm_sdk::sdk::storage_node_sdk::{StorageNodeConfig, StorageNodeSDK};
use dsm_sdk::sdk::b0x_sdk::B0xSDK;
use rand_core06::{OsRng, RngCore};
use std::process::Command;
use tokio::time::{timeout, Duration};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore] // Requires live AWS storage nodes
async fn e2e_flow_faucet_contact_transfer() {
    // Enable test mode to bypass PaidK spend gate requirement for ContactQrV3 verification
    unsafe {
        std::env::set_var("DSM_SDK_TEST_MODE", "1");
    }

    // Point at real AWS storage nodes via env config TOML
    let env_config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../frontend/public/dsm_env_config.toml");
    unsafe {
        std::env::set_var(
            "DSM_ENV_CONFIG_PATH",
            env_config_path.to_str().expect("config path"),
        );
    }

    // 1. Generate keys
    let (pk, sk) = dsm::crypto::sphincs::generate_sphincs_keypair()
        .unwrap_or_else(|e| panic!("Failed to generate keys: {e}"));

    // 2. DeviceID will be taken from MPC genesis (authoritative)

    // 3. Inject keys for WalletSDK
    let pk_b32 = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &pk);
    let sk_b32 = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &sk);

    unsafe {
        std::env::set_var("DSM_SDK_TEST_IMPORT_PK", pk_b32);
        std::env::set_var("DSM_SDK_TEST_IMPORT_SK", sk_b32);
    }

    // 4. Initialize SDK
    let temp_dir = std::env::temp_dir().join("dsm_e2e_test");
    // Ensure clean state
    if temp_dir.exists() {
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
    std::fs::create_dir_all(&temp_dir).unwrap_or_else(|e| panic!("Failed to create temp dir: {e}"));
    storage_utils::set_storage_base_dir(temp_dir.clone())
        .unwrap_or_else(|e| panic!("Failed to set storage dir: {e}"));

    // 5. Create Alice's genesis via real MPC
    println!("Creating Alice genesis via MPC...");

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
    let device_id = alice_genesis.genesis_device_id.clone();
    let alice_device_id_b32 = dsm_sdk::util::text_id::encode_base32_crockford(&device_id);
    let alice_genesis_b32 = dsm_sdk::util::text_id::encode_base32_crockford(&alice_genesis_hash);
    println!(
        "✅ Alice genesis created: {}...",
        alice_genesis_hash
            .iter()
            .take(8)
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    println!(
        "✅ Alice device_id (b32) prefix={}",
        &alice_device_id_b32[..8.min(alice_device_id_b32.len())]
    );
    println!(
        "✅ Alice genesis (b32) prefix={}",
        &alice_genesis_b32[..8.min(alice_genesis_b32.len())]
    );

    // Initialize deterministic time progress context at genesis (before any transactions)
    // Use zero SMT root at genesis (no state transitions yet)
    let alice_smt_root = [0u8; 32];
    dsm::utils::deterministic_time::update_progress_context(alice_smt_root, 0)
        .unwrap_or_else(|e| panic!("Failed to initialize progress context at genesis: {e}"));

    let config = SdkConfig {
        node_id: "test-node".to_string(),
        storage_endpoints: storage_nodes.clone(),
        enable_offline: true,
    };

    // Set Alice's real identity info in AppState BEFORE router init
    AppState::set_identity_info(
        device_id.clone(),
        pk.clone(),
        alice_genesis_hash.clone(),
        alice_smt_root.to_vec(),
    );
    AppState::set_has_identity(true);

    let router = AppRouterImpl::new(config.clone())
        .unwrap_or_else(|e| panic!("Failed to init AppRouter: {e}"));

    // Preflight: ensure b0x auth tokens can be acquired (required for real delivery)
    ensure_b0x_tokens(&router, &storage_nodes).await;

    // Clear replay guard table to avoid message-id conflicts from prior runs (dev DB only)
    clear_inbox_receipts();

    // 5. Verify AppState has keys
    // assert!(AppState::get_secret_key().is_some(), "Secret key not injected"); // Removed
    let stored_pk = AppState::get_public_key().unwrap_or_else(|| panic!("Public key missing"));
    assert_eq!(stored_pk, pk, "Stored PK mismatch");

    // 6. Faucet Claim
    let claim_req = proto::FaucetClaimRequest {
        device_id: device_id.clone(),
        // proof_of_work_nonce: 0, // Removed
    };

    let res = router
        .invoke(AppInvoke {
            method: "faucet.claim".to_string(),
            args: pack_proto(&claim_req),
        })
        .await;

    if !res.success {
        panic!("Faucet claim failed: {:?}", res.error_message);
    }
    println!("✅ Faucet claim success");

    // 6b. Verify faucet updated ERA balance
    let balances = fetch_balances(&router).await;
    let era_after_faucet = get_era_balance(&balances).unwrap_or(0);
    assert!(
        era_after_faucet > 0,
        "Expected ERA balance > 0 after faucet claim"
    );

    // 7. Add Contact (Alice -> Bob) using real protocol inputs
    assert!(
        storage_nodes.len() >= 3,
        "Need at least 3 storage nodes for verified-hash contact flow"
    );

    let storage_sdk_contact = StorageNodeSDK::new(storage_config.clone())
        .await
        .unwrap_or_else(|e| panic!("Failed to init StorageNodeSDK: {e}"));
    let mut bob_entropy = vec![0u8; 32];
    os_rng.fill_bytes(&mut bob_entropy);
    println!("Creating Bob genesis via MPC...");
    let bob_genesis = timeout(
        Duration::from_secs(20),
        storage_sdk_contact.create_genesis_with_mpc(Some(3), Some(bob_entropy.clone())),
    )
    .await
    .unwrap_or_else(|e| panic!("Bob genesis MPC timed out: {e}"))
    .unwrap_or_else(|e| panic!("Bob genesis creation failed: {e}"));

    let bob_device_id = bob_genesis.genesis_device_id.clone();
    let bob_genesis_hash = bob_genesis
        .genesis_hash
        .clone()
        .unwrap_or_else(|| panic!("Bob genesis hash missing"));
    let (bob_pk, bob_sk) = dsm::crypto::sphincs::generate_sphincs_keypair()
        .unwrap_or_else(|e| panic!("Failed to generate Bob keys: {e}"));

    // Register Bob's device in the Device Tree on storage nodes so Alice can verify it
    println!("Registering Bob's device in Device Tree...");
    let register_result = storage_sdk_contact
        .register_device_in_tree(&bob_device_id, &bob_genesis_hash)
        .await
        .unwrap_or_else(|e| panic!("Failed to register Bob's device in tree: {e}"));
    println!(
        "✅ Bob's device registered in Device Tree: published_to_nodes={}, success={}",
        register_result.published_to_nodes, register_result.success
    );

    // Wait for storage nodes to index the device tree evidence (asynchronous DB writes)
    // The storage nodes are "dumb mirrors" that persist immediately but may need time
    // for index updates to propagate. Retry with exponential backoff.
    println!("⏳ Waiting for storage nodes to index Bob's device tree evidence...");
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Convert to strings for ContactQrV3 (as expected by handle_contact_qr_v3)
    let bob_device_id_b32 = dsm_sdk::util::text_id::encode_base32_crockford(&bob_device_id);
    let bob_genesis_b32 = dsm_sdk::util::text_id::encode_base32_crockford(&bob_genesis_hash);
    println!(
        "✅ Bob device_id (b32) prefix={}",
        &bob_device_id_b32[..8.min(bob_device_id_b32.len())]
    );
    println!(
        "✅ Bob genesis (b32) prefix={}",
        &bob_genesis_b32[..8.min(bob_genesis_b32.len())]
    );

    // Updated to match proto definition
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

    if !res.success {
        panic!("Add contact failed: {:?}", res.error_message);
    }
    println!("✅ Add contact success");

    let bob_chain_tip = compute_initial_chain_tip(
        &device_id,
        &alice_genesis_hash,
        &bob_device_id,
        &bob_genesis_hash,
    );

    // 8. Transfer (Alice -> Bob)
    println!("[TEST] Starting transfer to Bob...");
    let transfer_req = proto::OnlineTransferRequest {
        token_id: "ERA".to_string(),
        to_device_id: bob_device_id.clone(),
        amount: 10,
        memo: "Test E2E".to_string(),
        nonce: vec![0u8; 12],
        signature: vec![],
        from_device_id: device_id.clone(),
        chain_tip: bob_chain_tip,
        seq: 1,
        receipt_commit: vec![],
        canonical_operation_bytes: vec![],
    };

    println!("[TEST] Calling router.invoke for transfer...");
    let res = router
        .invoke(AppInvoke {
            method: "wallet.send".to_string(),
            args: pack_proto(&transfer_req),
        })
        .await;

    println!("[TEST] router.invoke returned");
    if !res.success {
        panic!("Transfer failed: {:?}", res.error_message);
    }
    println!("✅ Transfer success");

    // 9. Verify Alice balance decreased by transfer amount
    let balances_after = fetch_balances(&router).await;
    let era_after_transfer = get_era_balance(&balances_after).unwrap_or(0);
    assert!(
        era_after_transfer + 10 <= era_after_faucet,
        "Expected ERA balance to decrease after transfer (before={}, after={})",
        era_after_faucet,
        era_after_transfer
    );

    // 10. Switch to Bob identity, sync inbox, and verify Bob balance increased
    let bob_pk_b32 = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &bob_pk);
    let bob_sk_b32 = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &bob_sk);
    unsafe {
        std::env::set_var("DSM_SDK_TEST_IMPORT_PK", bob_pk_b32);
        std::env::set_var("DSM_SDK_TEST_IMPORT_SK", bob_sk_b32);
    }

    let bob_smt_root = [0u8; 32];
    dsm::utils::deterministic_time::update_progress_context(bob_smt_root, 0)
        .unwrap_or_else(|e| panic!("Failed to initialize Bob progress context: {e}"));

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

    // Add Alice as a contact for Bob (so inbox polling has the correct chain tip)
    let _alice_device_id_b32 = dsm_sdk::util::text_id::encode_base32_crockford(&device_id);
    let _alice_genesis_b32 = dsm_sdk::util::text_id::encode_base32_crockford(&alice_genesis_hash);
    let alice_contact_qr = proto::ContactQrV3 {
        device_id: device_id.clone(),
        network: "test".to_string(),
        storage_nodes: storage_nodes.clone().into_iter().take(3).collect(),
        sdk_fingerprint: vec![0u8; 32],
        genesis_hash: alice_genesis_hash.to_vec(),
        signing_public_key: pk.clone(),
        preferred_alias: String::new(),
    };
    let bob_add_res = bob_router
        .query(AppQuery {
            path: "contacts.handle_contact_qr_v3".to_string(),
            params: pack_proto(&alice_contact_qr),
        })
        .await;
    if !bob_add_res.success {
        panic!("Bob add-contact failed: {:?}", bob_add_res.error_message);
    }

    // Pull & process inbox for Bob (real system path) with small retries
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
        "Expected Bob ERA balance >= 10 after sync (got={}, pulled={}, processed={}, errors={:?})",
        bob_era,
        last_sync_pulled,
        last_sync_processed,
        last_sync_errors
    );
}

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

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"DSM/bilateral-init\0");
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
