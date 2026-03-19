#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use serial_test::serial;

use dsm_sdk::sdk::b0x_sdk::B0xSDK;
use dsm_sdk::sdk::core_sdk::CoreSDK;
use dsm_sdk::types::error::DsmError;
use dsm_sdk::storage::client_db;
use dsm_sdk::storage::client_db::GenesisRecord;
use dsm_sdk::util::text_id;
use dsm_sdk::types::state_types::DeviceInfo;

fn test_device_id() -> String {
    // 32-byte Crockford Base32 string (52 chars).
    // Keep this decoding-valid under `text_id::decode_base32`.
    text_id::encode_base32_crockford(&[7u8; 32])
}

fn device_info_from(id_b32: &str) -> DeviceInfo {
    let decoded = text_id::decode_base32_crockford(id_b32).expect("base32 decode");
    assert_eq!(decoded.len(), 32, "device id must decode to 32 bytes");
    let mut device_id = [0u8; 32];
    device_id.copy_from_slice(&decoded);
    DeviceInfo::new(device_id, decoded)
}

fn init_isolated_test_db(storage_dir_name: &str) {
    std::env::set_var("DSM_SDK_TEST_MODE", "1");
    let _ =
        dsm_sdk::storage_utils::set_storage_base_dir(std::env::temp_dir().join(storage_dir_name));
    client_db::reset_database_for_tests();
    client_db::init_database().unwrap();
}

fn store_verified_genesis(device_id_b32: &str, genesis_bytes: [u8; 32]) {
    let genesis_b32 = text_id::encode_base32_crockford(&genesis_bytes);
    let record = GenesisRecord {
        genesis_id: genesis_b32.clone(),
        device_id: device_id_b32.to_string(),
        mpc_proof: "mpc-proof".to_string(),
        dbrw_binding: "binding".to_string(),
        merkle_root: genesis_b32.clone(),
        participant_count: 3,
        progress_marker: "t".to_string(),
        publication_hash: genesis_b32.clone(),
        storage_nodes: vec!["node1".to_string()],
        entropy_hash: genesis_b32,
        protocol_version: "v3".to_string(),
        hash_chain_proof: None,
        smt_proof: None,
        verification_step: None,
    };

    client_db::store_genesis_record_with_verification(&record).unwrap();
    client_db::ensure_wallet_state_for_device(device_id_b32).unwrap();
}

#[tokio::test]
#[serial]
async fn inbox_token_genesis_mismatch_returns_error() {
    init_isolated_test_db("dsm_inbox_genesis_mismatch_1");

    let endpoint = "http://127.0.0.1:1"; // will not be contacted; mismatch should short-circuit
    let device_id_b32 = test_device_id();

    let core = Arc::new(CoreSDK::new_with_device(device_info_from(&device_id_b32)).unwrap());
    core.initialize_with_genesis_state().unwrap();
    store_verified_genesis(&device_id_b32, [3u8; 32]);
    let local_genesis = core.local_genesis_hash().await.unwrap();
    let local_genesis_b32 = text_id::encode_base32_crockford(&local_genesis);

    // Ensure a clean slate for this endpoint/device/genesis in case prior runs left data behind.
    let mismatch_genesis = text_id::encode_base32_crockford(&[1u8; 32]);
    let _ = client_db::delete_auth_token(endpoint, &device_id_b32, &mismatch_genesis);
    let _ = client_db::delete_auth_token(endpoint, &device_id_b32, &local_genesis_b32);

    // Store a token under a different genesis to simulate stale inbox binding
    client_db::store_auth_token(endpoint, &device_id_b32, &mismatch_genesis, "tok_old").unwrap();

    let b0x = B0xSDK::new(
        device_id_b32.clone(),
        core.clone(),
        vec![endpoint.to_string()],
    )
    .unwrap();
    let res = b0x.ensure_token_for_endpoint(endpoint).await;

    match res {
        Err(DsmError::InboxTokenInvalid(msg)) => {
            assert!(
                msg.contains("GENESIS_INBOX_MISMATCH"),
                "expected explicit mismatch marker"
            );
            assert!(
                msg.contains(&mismatch_genesis),
                "message should include stored genesis"
            );
            assert!(
                msg.contains(&local_genesis_b32),
                "message should include local genesis"
            );
        }
        other => panic!("expected InboxTokenInvalid, got {:?}", other),
    }
}

#[tokio::test]
#[serial]
async fn purge_only_removes_matching_genesis() {
    init_isolated_test_db("dsm_inbox_genesis_mismatch_2");

    let endpoint = "http://127.0.0.1:2";
    let device_id_b32 = test_device_id();
    let core = Arc::new(CoreSDK::new_with_device(device_info_from(&device_id_b32)).unwrap());
    core.initialize_with_genesis_state().unwrap();
    store_verified_genesis(&device_id_b32, [4u8; 32]);
    let local_genesis = core.local_genesis_hash().await.unwrap();
    let local_genesis_b32 = text_id::encode_base32_crockford(&local_genesis);

    let other_genesis = text_id::encode_base32_crockford(&[2u8; 32]);

    // Ensure a clean slate for this endpoint/device/genesis in case prior runs left data behind.
    let _ = client_db::delete_auth_token(endpoint, &device_id_b32, &local_genesis_b32);
    let _ = client_db::delete_auth_token(endpoint, &device_id_b32, &other_genesis);

    // Store two tokens: one for the current genesis, one for another genesis
    client_db::store_auth_token(endpoint, &device_id_b32, &local_genesis_b32, "tok_local").unwrap();
    client_db::store_auth_token(endpoint, &device_id_b32, &other_genesis, "tok_other").unwrap();

    let b0x = B0xSDK::new(
        device_id_b32.clone(),
        core.clone(),
        vec![endpoint.to_string()],
    )
    .unwrap();
    b0x.purge_persisted_token_for_endpoint(endpoint).await;

    // Matching genesis token should be gone
    assert!(
        client_db::get_auth_token(endpoint, &device_id_b32, &local_genesis_b32)
            .unwrap()
            .is_none()
    );
    // Other genesis token should remain untouched
    assert_eq!(
        client_db::get_auth_token(endpoint, &device_id_b32, &other_genesis).unwrap(),
        Some("tok_other".to_string())
    );
}
