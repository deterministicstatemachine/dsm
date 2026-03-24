#![allow(clippy::disallowed_methods)]

use dsm_sdk::storage::client_db;
use dsm_sdk::storage::client_db::GenesisRecord;

#[test]
fn genesis_persists_and_initializes_wallet_metadata() {
    // Enable test mode to avoid writing AppState files
    std::env::set_var("DSM_SDK_TEST_MODE", "1");

    // Reset any existing DB singletons (unsafe test helper)
    // unsafe { client_db::reset_database_for_tests() };
    if let Err(e) = client_db::init_database() {
        eprintln!("[genesis_wallet_persistence] init_database skipped (already init): {e}");
    }

    // Create a minimal GenesisRecord (base32-encoded fields expected by schema)
    let device_bytes = vec![1u8; 32];
    let genesis_bytes = vec![2u8; 32];
    let device_b32 = dsm_sdk::util::text_id::encode_base32_crockford(&device_bytes);
    let genesis_b32 = dsm_sdk::util::text_id::encode_base32_crockford(&genesis_bytes);

    let gen = GenesisRecord {
        genesis_id: genesis_b32.clone(),
        device_id: device_b32.clone(),
        mpc_proof: "mpc-proof".to_string(),
        dbrw_binding: "binding".to_string(),
        merkle_root: genesis_b32.clone(),
        participant_count: 3,
        progress_marker: "t".to_string(),
        publication_hash: genesis_b32.clone(),
        storage_nodes: vec!["node1".to_string()],
        entropy_hash: genesis_b32.clone(),
        protocol_version: "v3".to_string(),
        hash_chain_proof: None,
        smt_proof: None,
        verification_step: None,
    };

    // Store genesis record and ensure wallet state
    client_db::store_genesis_record_with_verification(&gen).expect("store genesis");
    client_db::ensure_wallet_state_for_device(&gen.device_id).expect("ensure wallet");

    // Verify wallet metadata exists; balances now live in projections/canonical state.
    let ws = client_db::get_wallet_state(&gen.device_id).expect("get_wallet_state");
    assert!(ws.is_some(), "wallet state should be present");
}
