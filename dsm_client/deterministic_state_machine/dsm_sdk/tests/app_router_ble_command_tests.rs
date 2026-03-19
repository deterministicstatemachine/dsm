use dsm_sdk::handlers::AppRouterImpl;
use dsm_sdk::bridge::{AppInvoke, AppRouter as _};
use dsm_sdk::init::SdkConfig;
use dsm_sdk::ble::{self, BleBackend};
use dsm_sdk::ble::pb;
use dsm_sdk::sdk::app_state::AppState;
use prost::Message;
use std::sync::{Mutex, OnceLock};

// Ensure app state has a writable base dir for these tests to avoid panics from AppState
fn ensure_storage_base_dir() {
    static STORAGE_ONCE: OnceLock<()> = OnceLock::new();
    STORAGE_ONCE.get_or_init(|| {
        let _ = dsm_sdk::storage_utils::set_storage_base_dir(std::path::PathBuf::from(
            "./.dsm_testdata_ble",
        ));
        // Avoid persisting during unit tests
        std::env::set_var("DSM_SDK_TEST_MODE", "1");

        // Seed a dummy identity so AppRouter initialization can proceed without genesis
        let dev = vec![0xAA; 32];
        let pk = vec![0xBB; 32];
        let genesis = vec![0xCC; 32];
        let smt_root = vec![0xDD; 32];
        AppState::set_identity_info_if_empty(dev, pk, genesis, smt_root);
        AppState::set_has_identity(true);
    });
}

// Serialize tests in this module to avoid races on the global BLE registry/flag
static TEST_GUARD: OnceLock<Mutex<()>> = OnceLock::new();
fn test_guard() -> &'static Mutex<()> {
    TEST_GUARD.get_or_init(|| Mutex::new(()))
}

fn mk_router() -> AppRouterImpl {
    ensure_storage_base_dir();
    match AppRouterImpl::new(SdkConfig {
        node_id: "test-node".into(),
        storage_endpoints: vec!["http://127.0.0.1:8080".into()],
        enable_offline: true,
    }) {
        Ok(router) => router,
        Err(e) => panic!("AppRouterImpl::new should succeed in test: {:?}", e),
    }
}

fn mk_ble_command_bytes() -> Vec<u8> {
    // Build a simple StartScan BleCommand
    let cmd = pb::BleCommand {
        cmd: Some(pb::ble_command::Cmd::StartScan(pb::BleStartScan {})),
    };
    let mut body = Vec::new();
    match cmd.encode(&mut body) {
        Ok(_) => {}
        Err(e) => panic!("encode BleCommand: {:?}", e),
    }
    // Wrap in ArgPack (PROTO)
    let pack = pb::ArgPack {
        schema_hash: None,
        codec: pb::Codec::Proto as i32,
        body,
    };
    let mut bytes = Vec::new();
    match pack.encode(&mut bytes) {
        Ok(_) => {}
        Err(e) => panic!("encode ArgPack: {:?}", e),
    }
    bytes
}

#[test]
fn ble_command_no_backend_returns_error() {
    let _g = match test_guard().lock() {
        Ok(g) => g,
        Err(e) => panic!("Failed to acquire test guard: {:?}", e),
    };
    // Ensure we simulate no backend even if another test registered one
    dsm_sdk::ble::force_no_backend_for_tests(true);
    let router = mk_router();
    let bytes = mk_ble_command_bytes();
    let res = futures::executor::block_on(router.invoke(AppInvoke {
        method: "ble.command".into(),
        args: bytes,
    }));
    assert!(!res.success);
    let msg = res.error_message.unwrap_or_default();
    assert!(
        msg.contains("no BLE backend registered"),
        "unexpected message: {msg}"
    );
    // Reset for other tests
    dsm_sdk::ble::force_no_backend_for_tests(false);
}

#[test]
fn ble_command_wrong_codec_is_rejected() {
    let _g = match test_guard().lock() {
        Ok(g) => g,
        Err(e) => panic!("Failed to acquire test guard: {:?}", e),
    };
    let router = mk_router();
    // Build ArgPack with wrong codec
    let cmd = pb::BleCommand {
        cmd: Some(pb::ble_command::Cmd::StopScan(pb::BleStopScan {})),
    };
    let mut body = Vec::new();
    match cmd.encode(&mut body) {
        Ok(_) => {}
        Err(e) => panic!("encode BleCommand: {:?}", e),
    }
    let pack = pb::ArgPack {
        schema_hash: None,
        codec: pb::Codec::Unspecified as i32, // wrong (must be PROTO)
        body,
    };
    let mut bytes = Vec::new();
    match pack.encode(&mut bytes) {
        Ok(_) => {}
        Err(e) => panic!("encode ArgPack: {:?}", e),
    }

    let res = futures::executor::block_on(router.invoke(AppInvoke {
        method: "ble.command".into(),
        args: bytes,
    }));
    assert!(!res.success);
    let msg = res.error_message.unwrap_or_default();
    assert_eq!(msg, "ble.command: ArgPack.codec must be PROTO");
}

struct DummyBleBackend;
impl BleBackend for DummyBleBackend {
    fn handle_command(&self, _cmd: pb::BleCommand) -> pb::BleCommandResponse {
        pb::BleCommandResponse {
            ok: true,
            message: "ok".into(),
            payload: vec![],
        }
    }
}

#[test]
fn ble_command_with_backend_succeeds() {
    let _g = match test_guard().lock() {
        Ok(g) => g,
        Err(e) => panic!("Failed to acquire test guard: {:?}", e),
    };
    // Register dummy backend once (subsequent calls are ignored)
    if ble::get_ble_backend().is_none() {
        ble::register_ble_backend(DummyBleBackend);
    }

    let router = mk_router();
    let bytes = mk_ble_command_bytes();
    let res = futures::executor::block_on(router.invoke(AppInvoke {
        method: "ble.command".into(),
        args: bytes,
    }));
    assert!(res.success, "invoke should succeed");
    assert!(res.error_message.is_none());
    // Response is a FramedEnvelopeV3 with BleCommandResponse payload.
    assert!(!res.data.is_empty(), "response bytes must not be empty");
    assert_eq!(res.data[0], 0x03, "expected FramedEnvelopeV3 prefix");
    let env = match pb::Envelope::decode(&res.data[1..]) {
        Ok(env) => env,
        Err(e) => panic!("decode Envelope: {:?}", e),
    };
    assert_eq!(env.version, 3);
    let resp = match env.payload {
        Some(pb::envelope::Payload::BleCommandResponse(r)) => r,
        other => panic!("unexpected payload: {:?}", other),
    };
    assert!(resp.ok);
    assert_eq!(resp.message, "ok");
}
