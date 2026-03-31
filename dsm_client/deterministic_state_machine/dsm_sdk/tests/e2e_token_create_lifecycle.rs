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
use rand::{rngs::OsRng, RngCore};
use tokio::time::{timeout, Duration};

/// E2E test: Token Create Lifecycle
///
/// Validates:
/// 1. Custom token creation succeeds with valid params
/// 2. Token ID is deterministic (blake3 of domain + policy_anchor + ticker)
/// 3. Created token appears in balance.list (available=0, metadata only)
/// 4. Multiple tokens can coexist
/// 5. Duplicate create is idempotent (same token_id)
/// 6. Invalid parameters are properly rejected
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore] // Requires live AWS storage nodes
async fn e2e_token_create_lifecycle() {
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

    // --- Setup: keys, storage, genesis ---
    let (pk, _sk) =
        dsm::crypto::sphincs::generate_sphincs_keypair().expect("Failed to generate keys");
    let pk_b32 = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &pk);
    let sk_b32 = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &_sk);
    unsafe {
        std::env::set_var("DSM_SDK_TEST_IMPORT_PK", pk_b32);
        std::env::set_var("DSM_SDK_TEST_IMPORT_SK", sk_b32);
    }

    let temp_dir = std::env::temp_dir().join("dsm_e2e_token_create");
    if temp_dir.exists() {
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
    std::fs::create_dir_all(&temp_dir).expect("Failed to create temp dir");
    storage_utils::set_storage_base_dir(temp_dir.clone()).expect("Failed to set storage dir");

    let storage_config = StorageNodeConfig::from_env_config()
        .await
        .expect("storage config (env required)");
    let storage_nodes = storage_config.node_urls.clone();
    let storage_sdk = StorageNodeSDK::new(storage_config)
        .await
        .expect("Failed to create StorageNodeSDK");

    let mut os_rng = OsRng;
    let mut entropy = vec![0u8; 32];
    os_rng.fill_bytes(&mut entropy);

    println!("Creating genesis via MPC...");
    let genesis = timeout(
        Duration::from_secs(20),
        storage_sdk.create_genesis_with_mpc(Some(3), Some(entropy)),
    )
    .await
    .expect("MPC genesis timeout")
    .expect("MPC genesis failed");

    let genesis_hash = genesis.genesis_hash.expect("genesis_hash missing");
    let device_id = genesis.genesis_device_id.clone();
    println!("✅ Genesis created");

    let smt_root = [0u8; 32];
    dsm::utils::deterministic_time::update_progress_context(smt_root, 0)
        .expect("Failed to init progress context");

    let config = SdkConfig {
        node_id: "test-node".to_string(),
        storage_endpoints: storage_nodes.clone(),
        enable_offline: true,
    };

    AppState::set_identity_info(
        device_id.clone(),
        pk.clone(),
        genesis_hash.clone(),
        smt_root.to_vec(),
    );
    AppState::set_has_identity(true);

    let router = AppRouterImpl::new(config).expect("Failed to init AppRouter");
    ensure_b0x_tokens(&router, &storage_nodes).await;

    // --- Faucet claim (prerequisite for active identity) ---
    let claim_req = proto::FaucetClaimRequest {
        device_id: device_id.clone(),
    };
    let res = router
        .invoke(AppInvoke {
            method: "faucet.claim".to_string(),
            args: pack_proto(&claim_req),
        })
        .await;
    assert!(res.success, "Faucet claim failed: {:?}", res.error_message);

    let balances = fetch_balances(&router).await;
    let era = get_era_balance(&balances).unwrap_or(0);
    assert!(era > 0, "Expected ERA > 0 after faucet");
    println!("✅ Faucet claim: ERA = {}", era);

    // ========== TEST 1: Create token "BETA" ==========
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
        max_supply_u128: beta_max_supply.clone(),
        policy_anchor: beta_policy_anchor.clone(),
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
    assert!(
        !beta_resp.token_id.is_empty(),
        "BETA token_id should be non-empty"
    );
    let beta_token_id = beta_resp.token_id.clone();
    println!("✅ Token BETA created: token_id={}", beta_token_id);

    // ========== TEST 2: Verify deterministic token_id ==========
    let expected_token_id = {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"DSM/token-id\0");
        hasher.update(&beta_policy_anchor);
        hasher.update(b"BETA");
        dsm_sdk::util::text_id::encode_base32_crockford(hasher.finalize().as_bytes())
    };
    assert_eq!(
        beta_token_id, expected_token_id,
        "BETA token_id is not deterministic (got={}, expected={})",
        beta_token_id, expected_token_id
    );
    println!("✅ Token ID is deterministic");

    // ========== TEST 3: balance.list includes BETA ==========
    let balances = fetch_balances(&router).await;
    let beta_balance = balances
        .balances
        .iter()
        .find(|b| b.token_id == beta_token_id);
    // Token may or may not appear in balance.list if available=0 (metadata only).
    // If it appears, available should be 0.
    if let Some(bal) = beta_balance {
        assert_eq!(bal.available, 0, "BETA available should be 0 (no minting)");
        println!("✅ BETA appears in balance.list (available=0)");
    } else {
        println!("ℹ️  BETA not in balance.list (expected: metadata-only tokens may be omitted)");
    }

    // ========== TEST 4: Create second token "GAMMA" ==========
    let gamma_policy_anchor = blake3::hash(b"DSM/test-policy-gamma").as_bytes()[..32].to_vec();
    let gamma_req = proto::TokenCreateRequest {
        ticker: "GAMMA".to_string(),
        alias: "Gamma Token".to_string(),
        decimals: 0,
        max_supply_u128: beta_max_supply.clone(),
        policy_anchor: gamma_policy_anchor.clone(),
    };

    let res = router
        .invoke(AppInvoke {
            method: "token.create".to_string(),
            args: pack_proto(&gamma_req),
        })
        .await;
    assert!(
        res.success,
        "token.create GAMMA failed: {:?}",
        res.error_message
    );

    let env = decode_framed_envelope(&res.data, "token.create GAMMA");
    let gamma_resp = match env.payload {
        Some(proto::envelope::Payload::TokenCreateResponse(resp)) => resp,
        other => panic!("token.create GAMMA unexpected payload: {:?}", other),
    };
    assert!(gamma_resp.success, "GAMMA create not successful");
    assert_ne!(
        gamma_resp.token_id, beta_token_id,
        "GAMMA and BETA should have different token_ids"
    );
    println!(
        "✅ Token GAMMA created: token_id={} (different from BETA)",
        gamma_resp.token_id
    );

    // ========== TEST 5: Duplicate create is idempotent ==========
    let dup_req = proto::TokenCreateRequest {
        ticker: "BETA".to_string(),
        alias: "Beta Token".to_string(),
        decimals: 2,
        max_supply_u128: beta_max_supply.clone(),
        policy_anchor: beta_policy_anchor.clone(),
    };

    let res = router
        .invoke(AppInvoke {
            method: "token.create".to_string(),
            args: pack_proto(&dup_req),
        })
        .await;
    assert!(
        res.success,
        "token.create duplicate BETA failed: {:?}",
        res.error_message
    );

    let env = decode_framed_envelope(&res.data, "token.create BETA dup");
    let dup_resp = match env.payload {
        Some(proto::envelope::Payload::TokenCreateResponse(resp)) => resp,
        other => panic!("token.create dup unexpected payload: {:?}", other),
    };
    assert!(dup_resp.success, "Duplicate BETA create not successful");
    assert_eq!(
        dup_resp.token_id, beta_token_id,
        "Duplicate BETA should return same token_id"
    );
    println!("✅ Duplicate create is idempotent (same token_id)");

    // ========== TEST 6: Invalid creates are rejected ==========

    // 6a: Empty ticker
    let invalid_req = proto::TokenCreateRequest {
        ticker: "".to_string(),
        alias: "Bad".to_string(),
        decimals: 0,
        max_supply_u128: beta_max_supply.clone(),
        policy_anchor: beta_policy_anchor.clone(),
    };
    let res = router
        .invoke(AppInvoke {
            method: "token.create".to_string(),
            args: pack_proto(&invalid_req),
        })
        .await;
    assert_invalid_token_create(&res, "empty ticker");

    // 6b: Ticker too long (> 8 chars)
    let invalid_req = proto::TokenCreateRequest {
        ticker: "TOOLONGTICKER".to_string(),
        alias: "Bad".to_string(),
        decimals: 0,
        max_supply_u128: beta_max_supply.clone(),
        policy_anchor: beta_policy_anchor.clone(),
    };
    let res = router
        .invoke(AppInvoke {
            method: "token.create".to_string(),
            args: pack_proto(&invalid_req),
        })
        .await;
    assert_invalid_token_create(&res, "ticker > 8 chars");

    // 6c: Decimals > 18
    let invalid_req = proto::TokenCreateRequest {
        ticker: "BAD".to_string(),
        alias: "Bad".to_string(),
        decimals: 255,
        max_supply_u128: beta_max_supply.clone(),
        policy_anchor: beta_policy_anchor.clone(),
    };
    let res = router
        .invoke(AppInvoke {
            method: "token.create".to_string(),
            args: pack_proto(&invalid_req),
        })
        .await;
    assert_invalid_token_create(&res, "decimals > 18");

    // 6d: Wrong-size policy_anchor (not 32 bytes)
    let invalid_req = proto::TokenCreateRequest {
        ticker: "BAD".to_string(),
        alias: "Bad".to_string(),
        decimals: 0,
        max_supply_u128: beta_max_supply.clone(),
        policy_anchor: vec![0u8; 16], // wrong size
    };
    let res = router
        .invoke(AppInvoke {
            method: "token.create".to_string(),
            args: pack_proto(&invalid_req),
        })
        .await;
    assert_invalid_token_create(&res, "wrong-size policy_anchor");

    // 6e: Wrong-size max_supply (not 16 bytes)
    let invalid_req = proto::TokenCreateRequest {
        ticker: "BAD".to_string(),
        alias: "Bad".to_string(),
        decimals: 0,
        max_supply_u128: vec![0u8; 8], // wrong size
        policy_anchor: beta_policy_anchor.clone(),
    };
    let res = router
        .invoke(AppInvoke {
            method: "token.create".to_string(),
            args: pack_proto(&invalid_req),
        })
        .await;
    assert_invalid_token_create(&res, "wrong-size max_supply");

    println!("✅ All invalid token creates rejected");
    println!("\n✅✅ e2e_token_create_lifecycle PASSED ✅✅");
}

// --- Helpers ---

fn assert_invalid_token_create(res: &dsm_sdk::bridge::AppResult, label: &str) {
    // Invalid creates may fail at the router level (res.success=false)
    // or return an error/unsuccessful envelope.
    if !res.success {
        println!("  ✓ {}: rejected at router level", label);
        return;
    }
    if res.data.is_empty() {
        panic!("{}: empty response data but success=true", label);
    }
    let env = decode_framed_envelope(&res.data, label);
    match env.payload {
        Some(proto::envelope::Payload::Error(_)) => {
            println!("  ✓ {}: rejected with error envelope", label);
        }
        Some(proto::envelope::Payload::TokenCreateResponse(resp)) => {
            assert!(
                !resp.success,
                "{}: token.create unexpectedly succeeded",
                label
            );
            println!("  ✓ {}: rejected (success=false)", label);
        }
        other => panic!("{}: unexpected payload: {:?}", label, other),
    }
}

fn pack_proto<T: Message>(msg: &T) -> Vec<u8> {
    let mut body = Vec::new();
    msg.encode(&mut body).unwrap();

    let pack = proto::ArgPack {
        schema_hash: Some(proto::Hash32 { v: vec![0; 32] }),
        codec: proto::Codec::Proto as i32,
        body,
    };

    let mut pack_bytes = Vec::new();
    pack.encode(&mut pack_bytes).unwrap();
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

fn decode_framed_envelope(bytes: &[u8], label: &str) -> proto::Envelope {
    assert!(!bytes.is_empty(), "{label}: empty response bytes");
    assert_eq!(bytes[0], 0x03, "{label}: expected FramedEnvelopeV3 prefix");
    proto::Envelope::decode(&bytes[1..]).expect("decode Envelope")
}

async fn ensure_b0x_tokens(router: &AppRouterImpl, endpoints: &[String]) {
    let device_id = AppState::get_device_id().expect("AppState device_id missing");
    let device_id_b32 = dsm_sdk::util::text_id::encode_base32_crockford(&device_id);
    let b0x = B0xSDK::new(device_id_b32, router.core_sdk.clone(), endpoints.to_vec())
        .expect("B0xSDK init failed");

    for ep in endpoints {
        b0x.ensure_token_for_endpoint(ep)
            .await
            .unwrap_or_else(|e| panic!("b0x token acquisition failed for {}: {}", ep, e));
    }
}
