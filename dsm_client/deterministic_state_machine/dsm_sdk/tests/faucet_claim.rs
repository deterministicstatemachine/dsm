// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(clippy::disallowed_methods)]

use prost::Message;

use dsm::types::proto as generated;
use dsm_sdk::runtime;
use dsm_sdk::init::SdkConfig;
use dsm_sdk::handlers::app_router_impl::AppRouterImpl;
use dsm_sdk::bridge::{AppInvoke, AppQuery, AppRouter};
use dsm_sdk::storage::client_db::{
    get_all_system_peers, get_contact_by_device_id, get_local_bilateral_chain_tip, get_system_peer,
    get_system_peer_events, get_transaction_history, reset_database_for_tests, store_contact,
    update_local_bilateral_chain_tip, ContactRecord,
};
use std::path::PathBuf;
use std::collections::HashMap;

fn init_test_storage() {
    std::env::set_var("DSM_SDK_TEST_MODE", "1");
    reset_database_for_tests();
    let _ = dsm_sdk::storage_utils::set_storage_base_dir(PathBuf::from("./.dsm_testdata"));
    dsm_sdk::sdk::app_state::AppState::set_identity_info(
        vec![0xAA; 32],
        vec![0xBB; 32],
        vec![0xCC; 32],
        vec![0xDD; 32],
    );
    // Install a deterministic 32-byte C-DBRW binding key so the canonical
    // signing authority can derive a keypair during AppRouter::new().
    // DBRW enforcement is ON, so without this the router fails to construct.
    dsm_sdk::set_cdbrw_binding_key_for_testing(vec![0xEE; 32]);
    // Publish a FullAccess trust snapshot so the C-DBRW access gate allows
    // sensitive router operations (faucet.claim, balance.list, etc).
    publish_full_access_for_tests();
}

fn publish_full_access_for_tests() {
    use dsm_sdk::security::cdbrw_access_gate::{
        next_iter, store_trust, AccessLevel, ResonantStatus, TrustSnapshot,
    };
    store_trust(TrustSnapshot {
        access_level: AccessLevel::FullAccess,
        resonant_status: ResonantStatus::Resonant,
        h_hat: 1.0,
        rho_hat: 1.0,
        l_hat: 1.0,
        h0_eff: 1.0,
        trust_score: 1.0,
        recommended_n: 1,
        w1_distance: 0.0,
        w1_threshold: 1.0,
        iter: next_iter(),
    });
}

#[test]
#[serial_test::serial]
fn faucet_claim_increases_era_balance() {
    // Initialize runtime for async execution
    runtime::dsm_init_runtime();
    init_test_storage();

    // Minimal config (offline disabled)
    let cfg = SdkConfig {
        node_id: "test-device".to_string(),
        storage_endpoints: vec![],
        enable_offline: false,
    };
    let router = AppRouterImpl::new(cfg).expect("AppRouterImpl::new should succeed in test");

    // Build FaucetClaimRequest ArgPack
    let req = generated::FaucetClaimRequest {
        device_id: vec![0u8; 32],
    };
    let mut body = Vec::new();
    req.encode(&mut body).unwrap();
    let arg_pack = generated::ArgPack {
        schema_hash: Some(generated::Hash32 { v: vec![0u8; 32] }),
        codec: generated::Codec::Proto as i32,
        body,
    };
    let mut args_bytes = Vec::new();
    arg_pack.encode(&mut args_bytes).unwrap();

    // Invoke faucet.claim
    let inv = AppInvoke {
        method: "faucet.claim".to_string(),
        args: args_bytes,
    };
    let res = runtime::get_runtime().block_on(async { router.invoke(inv).await });
    assert!(
        res.success,
        "faucet.claim invoke should succeed: {:?}",
        res.error_message
    );

    // Query balance.list
    let q_args = generated::ArgPack {
        schema_hash: Some(generated::Hash32 { v: vec![0u8; 32] }),
        codec: generated::Codec::Proto as i32,
        body: Vec::new(),
    };
    let mut q_bytes = Vec::new();
    q_args.encode(&mut q_bytes).unwrap();
    let q = AppQuery {
        path: "balance.list".to_string(),
        params: q_bytes,
    };
    let qres = runtime::get_runtime().block_on(async { router.query(q).await });
    assert!(
        qres.success,
        "balance.list should succeed: {:?}",
        qres.error_message
    );

    // Decode FramedEnvelopeV3 response
    assert!(!qres.data.is_empty(), "response bytes must not be empty");
    assert_eq!(qres.data[0], 0x03, "expected FramedEnvelopeV3 prefix");
    let env = generated::Envelope::decode(&qres.data[1..]).expect("decode Envelope");
    assert_eq!(env.version, 3);
    let list = match env.payload {
        Some(generated::envelope::Payload::BalancesListResponse(r)) => r,
        other => panic!("unexpected payload: {:?}", other),
    };

    let era_ok = list
        .balances
        .iter()
        .any(|b| b.token_id == "ERA" && b.available > 0);
    assert!(era_ok, "ERA balance should be > 0 after faucet claim");
}

#[test]
#[serial_test::serial]
fn faucet_claim_keeps_bilateral_tips_isolated_from_protocol_peer_progression() {
    runtime::dsm_init_runtime();
    init_test_storage();

    let cfg = SdkConfig {
        node_id: "test-device".to_string(),
        storage_endpoints: vec![],
        enable_offline: false,
    };
    let router = AppRouterImpl::new(cfg).expect("AppRouterImpl::new should succeed in test");

    let contact_device_id = [0x21u8; 32];
    let original_tip = [0x42u8; 32];
    let contact = ContactRecord {
        contact_id: dsm_sdk::util::text_id::encode_base32_crockford(&contact_device_id),
        device_id: contact_device_id.to_vec(),
        alias: "peer".to_string(),
        genesis_hash: [0x63u8; 32].to_vec(),
        public_key: vec![0x55; 64],
        kyber_public_key: Vec::new(),
        current_chain_tip: Some(original_tip.to_vec()),
        added_at: 1,
        verified: true,
        verification_proof: None,
        metadata: HashMap::new(),
        ble_address: None,
        status: "BleCapable".to_string(),
        needs_online_reconcile: false,
        last_seen_online_counter: 0,
        last_seen_ble_counter: 0,
        previous_chain_tip: None,
    };
    store_contact(&contact).expect("store contact");
    update_local_bilateral_chain_tip(&contact_device_id, &original_tip)
        .expect("seed local bilateral tip");

    let claim_req = generated::FaucetClaimRequest {
        device_id: vec![0u8; 32],
    };
    let invoke_claim = |router: &AppRouterImpl| {
        let mut body = Vec::new();
        claim_req.encode(&mut body).expect("encode claim");
        let arg_pack = generated::ArgPack {
            schema_hash: Some(generated::Hash32 { v: vec![0u8; 32] }),
            codec: generated::Codec::Proto as i32,
            body,
        };
        let mut args_bytes = Vec::new();
        arg_pack.encode(&mut args_bytes).expect("encode arg pack");
        runtime::get_runtime().block_on(async {
            router
                .invoke(AppInvoke {
                    method: "faucet.claim".to_string(),
                    args: args_bytes,
                })
                .await
        })
    };

    let first = invoke_claim(&router);
    assert!(first.success, "first faucet claim should succeed");
    let second = invoke_claim(&router);
    assert!(second.success, "second faucet claim should succeed");

    let stored_contact = get_contact_by_device_id(&contact_device_id)
        .expect("load contact")
        .expect("contact exists");
    assert_eq!(
        stored_contact.current_chain_tip,
        Some(original_tip.to_vec())
    );
    assert_eq!(
        get_local_bilateral_chain_tip(&contact_device_id).expect("local bilateral tip"),
        original_tip
    );

    let system_peer = get_system_peer("era-source-dlv")
        .expect("load stable source peer")
        .expect("stable source peer exists");
    assert_eq!(system_peer.peer_type.as_str(), "dlv");
    assert!(system_peer.current_chain_tip.is_some());

    let peer_events = get_system_peer_events("era-source-dlv").expect("load peer events");
    assert_eq!(
        peer_events.len(),
        2,
        "claims should advance one stable peer"
    );
    assert_ne!(peer_events[0].child_tip, peer_events[0].source_state_hash);
    assert_ne!(peer_events[0].child_tip, peer_events[1].child_tip);

    let all_peers = get_all_system_peers().expect("load all system peers");
    assert_eq!(all_peers.len(), 1);
    assert!(all_peers
        .iter()
        .all(|peer| !peer.peer_key.starts_with("faucet-")));

    let history = get_transaction_history(None, Some(16)).expect("load tx history");
    let faucet_entries: Vec<_> = history
        .into_iter()
        .filter(|tx| tx.tx_type == "faucet")
        .collect();
    assert_eq!(faucet_entries.len(), 2);
    assert!(faucet_entries.iter().all(|tx| tx.proof_data.is_none()));
    assert!(faucet_entries.iter().all(|tx| {
        tx.metadata
            .get("protocol_peer_key")
            .is_some_and(|value| value == b"era-source-dlv")
    }));
}
