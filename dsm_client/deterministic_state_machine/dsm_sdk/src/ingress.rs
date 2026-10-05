// SPDX-License-Identifier: MIT OR Apache-2.0

//! # Shared Native Ingress
//!
//! Platform-agnostic native boundary shared by Android JNI and iOS FFI.
//! Request dispatch and startup/bootstrap both terminate here; platform shims
//! above this layer only marshal inputs and collect platform-specific hardware
//! facts.

use std::path::PathBuf;

use dsm::pbi::{PlatformContext, RawPlatformInputs};
use prost::Message;

use crate::generated as pb;
use crate::generated::{
    ingress_request, ingress_response, startup_request, startup_response, Envelope, IngressRequest,
    IngressResponse, StartupRequest, StartupResponse,
};

pub(crate) const ERROR_CODE_INVALID_INPUT: u32 = 1;
pub(crate) const ERROR_CODE_PROCESSING_FAILED: u32 = 2;
pub(crate) const ERROR_CODE_NOT_READY: u32 = 5;

const STARTUP_OK_BYTES: &[u8] = &[1];

fn ingress_error(code: u32, message: impl Into<String>) -> pb::Error {
    pb::Error {
        code,
        message: message.into(),
        context: Vec::new(),
        source_tag: 0,
        is_recoverable: false,
        debug_b32: String::new(),
    }
}

#[cfg(all(target_os = "android", feature = "jni"))]
fn encode_framed_envelope(payload: pb::envelope::Payload) -> Result<Vec<u8>, pb::Error> {
    let envelope = crate::envelope::local_answer(payload);
    let mut buf = Vec::with_capacity(1 + envelope.encoded_len());
    buf.push(0x03);
    envelope.encode(&mut buf).map_err(|e| {
        ingress_error(
            ERROR_CODE_PROCESSING_FAILED,
            format!("ingress: envelope encode failed: {e}"),
        )
    })?;
    Ok(buf)
}

fn push_canonical_envelope_event(payload: pb::envelope::Payload) -> Result<(), pb::Error> {
    #[cfg(all(target_os = "android", feature = "jni"))]
    {
        let framed = encode_framed_envelope(payload)?;
        crate::jni::event_dispatch::post_event_to_webview("canonical.envelope.bin", &framed)
            .map_err(|e| {
                ingress_error(
                    ERROR_CODE_PROCESSING_FAILED,
                    format!("ingress: canonical envelope dispatch failed: {e}"),
                )
            })?;
    }
    #[cfg(not(all(target_os = "android", feature = "jni")))]
    {
        let _ = payload;
    }
    Ok(())
}

/// Push a genesis lifecycle event to the WebView (EventBridge maps kinds to the
/// `genesis.securing-device*` topics the frontend renders). `pub(crate)` for the
/// canonical Genesis v2 route (`system.createGenesisV2` in `handlers::system_routes`),
/// which drives the securing-screen rail.
pub(crate) fn push_genesis_lifecycle_event(kind: i32, progress: u32) -> Result<(), pb::Error> {
    push_canonical_envelope_event(pb::envelope::Payload::GenesisLifecycle(
        pb::GenesisLifecycleEvent { kind, progress },
    ))
}

fn process_envelope_core(envelope_in: Envelope) -> Result<Envelope, pb::Error> {
    crate::envelope::validate_envelope_v3(&envelope_in).map_err(|e| {
        ingress_error(
            ERROR_CODE_INVALID_INPUT,
            format!("ingress: envelope validation failed: {e}"),
        )
    })?;

    let mut raw = Vec::new();
    match envelope_in.encode(&mut raw) {
        Ok(()) => {}
        Err(e) => {
            return Err(ingress_error(
                ERROR_CODE_INVALID_INPUT,
                format!("ingress: envelope re-encode failed: {e}"),
            ));
        }
    }

    let out = dsm::core::bridge::handle_envelope_universal(&raw);
    let payload = if out.first() == Some(&0x03) {
        &out[1..]
    } else {
        &out[..]
    };

    crate::envelope::local_answer_from_canonical_bytes(payload).map_err(|e| {
        ingress_error(
            ERROR_CODE_PROCESSING_FAILED,
            format!("ingress: response envelope decode failed: {e}"),
        )
    })
}

fn router_query_core(method: String, args: Vec<u8>) -> Result<Vec<u8>, pb::Error> {
    if method.is_empty() {
        return Err(ingress_error(
            ERROR_CODE_INVALID_INPUT,
            "ingress: router query path missing",
        ));
    }

    let router = match crate::bridge::app_router() {
        Some(router) => router,
        None => {
            return Err(ingress_error(
                ERROR_CODE_NOT_READY,
                "ingress: app router not installed",
            ));
        }
    };
    let q = crate::bridge::AppQuery {
        path: method,
        params: args,
    };
    let res = crate::runtime::get_runtime().block_on(router.query(q));

    if res.success {
        Ok(res.data)
    } else {
        Err(ingress_error(
            ERROR_CODE_PROCESSING_FAILED,
            res.error_message
                .unwrap_or_else(|| "router_query_core failed".to_string()),
        ))
    }
}

fn router_invoke_core(method: String, args: Vec<u8>) -> Result<Vec<u8>, pb::Error> {
    if method.is_empty() {
        return Err(ingress_error(
            ERROR_CODE_INVALID_INPUT,
            "ingress: router invoke method missing",
        ));
    }

    let router = match crate::bridge::app_router() {
        Some(router) => router,
        None => {
            return Err(ingress_error(
                ERROR_CODE_NOT_READY,
                "ingress: app router not installed",
            ));
        }
    };
    let invoke = crate::bridge::AppInvoke { method, args };
    let res = crate::runtime::get_runtime().block_on(router.invoke(invoke));

    if res.success {
        Ok(res.data)
    } else {
        Err(ingress_error(
            ERROR_CODE_PROCESSING_FAILED,
            res.error_message
                .unwrap_or_else(|| "router_invoke_core failed".to_string()),
        ))
    }
}

fn update_hardware_facts_core(facts: pb::SessionHardwareFactsProto) -> Result<Vec<u8>, pb::Error> {
    let mut facts_bytes = Vec::new();
    match facts.encode(&mut facts_bytes) {
        Ok(()) => {}
        Err(e) => {
            return Err(ingress_error(
                ERROR_CODE_INVALID_INPUT,
                format!("ingress: hardware facts encode failed: {e}"),
            ));
        }
    }

    crate::sdk::session_manager::update_hardware_and_snapshot(&facts_bytes).map_err(|e| {
        ingress_error(
            ERROR_CODE_PROCESSING_FAILED,
            format!("ingress: hardware facts update failed: {e}"),
        )
    })
}

fn startup_ok() -> Vec<u8> {
    STARTUP_OK_BYTES.to_vec()
}

fn set_storage_base_dir_core(path_utf8: String) -> Result<Vec<u8>, pb::Error> {
    if path_utf8.trim().is_empty() {
        return Err(ingress_error(
            ERROR_CODE_INVALID_INPUT,
            "startup: storage base dir path missing",
        ));
    }

    let requested = PathBuf::from(path_utf8);
    if let Some(existing) = crate::storage_utils::get_storage_base_dir() {
        if existing == requested {
            return Ok(startup_ok());
        }
        return Err(ingress_error(
            ERROR_CODE_INVALID_INPUT,
            format!(
                "startup: storage base dir already set to {}",
                existing.display()
            ),
        ));
    }

    crate::storage_utils::set_storage_base_dir(requested).map_err(|e| {
        ingress_error(
            ERROR_CODE_PROCESSING_FAILED,
            format!("startup: failed to set storage base dir: {e}"),
        )
    })?;
    Ok(startup_ok())
}

fn configure_env_core(config_path_utf8: String) -> Result<Vec<u8>, pb::Error> {
    if config_path_utf8.trim().is_empty() {
        return Err(ingress_error(
            ERROR_CODE_INVALID_INPUT,
            "startup: env config path missing",
        ));
    }

    if let Some(existing) = crate::network::get_env_config_path() {
        if existing == config_path_utf8 {
            return Ok(startup_ok());
        }
        return Err(ingress_error(
            ERROR_CODE_INVALID_INPUT,
            format!("startup: env config path already set to {existing}"),
        ));
    }

    crate::network::set_env_config_path(config_path_utf8);
    Ok(startup_ok())
}

fn initialize_sdk_core() -> Result<Vec<u8>, pb::Error> {
    match crate::runtime::get_runtime().block_on(crate::init_dsm_sdk()) {
        Ok(()) => {
            crate::sdk::session_manager::set_sdk_ready(true);
            crate::sdk::session_manager::clear_startup_failure();

            // Resume any identity whose publication never reached quorum.
            // Publication is a precondition of "identity created", so a device
            // that got as far as a durable local genesis must keep trying to
            // publish on its own — the user must never have to discover this
            // through unrelated symptoms or repair it from the storage screen.
            // Spawned so a slow/unreachable fleet cannot delay startup.
            crate::runtime::get_runtime().spawn(async {
                crate::sdk::identity_publication::retry_pending_publications().await;
            });

            Ok(startup_ok())
        }
        Err(e) => {
            crate::sdk::session_manager::set_sdk_ready(false);
            let message = format!("startup: init_dsm_sdk failed: {e}");
            crate::sdk::session_manager::record_startup_failure(&message);
            Err(ingress_error(ERROR_CODE_NOT_READY, message))
        }
    }
}

fn prime_identity_app_state(device_id: &[u8], genesis_hash: &[u8]) -> Result<(), pb::Error> {
    // Re-derive the canonical device signing (AK) public key from the unlocked wallet seed
    // via the single Genesis v2 derivation (`derive_device_ak_keypair`, byte-identical to the
    // key `create_genesis_v2` registered). No C-DBRW binding key. Fails closed if the wallet
    // is locked (the seed is re-derived from the session-cached mnemonic, never persisted).
    if device_id.len() != 32 {
        return Err(ingress_error(
            ERROR_CODE_INVALID_INPUT,
            format!(
                "startup: device_id must be 32 bytes before identity priming, got {}",
                device_id.len()
            ),
        ));
    }
    if genesis_hash.len() != 32 {
        return Err(ingress_error(
            ERROR_CODE_INVALID_INPUT,
            format!(
                "startup: genesis_hash must be 32 bytes before identity priming, got {}",
                genesis_hash.len()
            ),
        ));
    }
    let wallet_seed = crate::fetch_wallet_seed().map_err(|e| {
        ingress_error(
            ERROR_CODE_PROCESSING_FAILED,
            format!("startup: wallet locked before identity priming: {e}"),
        )
    })?;
    let mut g = [0u8; 32];
    g.copy_from_slice(genesis_hash);
    let kp = crate::init::derive_device_signing_keypair(&wallet_seed, &g).map_err(|e| {
        ingress_error(
            ERROR_CODE_PROCESSING_FAILED,
            format!("startup: canonical SPHINCS+ key derivation failed: {e}"),
        )
    })?;
    log::info!(
        "prime_identity_app_state: derived canonical SPHINCS+ public key (len={})",
        kp.public_key().len()
    );

    // The SMT root genesis recorded for this identity.
    let genesis_b32 = crate::util::text_id::encode_base32_crockford(&g);
    let record = crate::storage::client_db::get_genesis_record_by_id(&genesis_b32)
        .map_err(|e| {
            ingress_error(
                ERROR_CODE_PROCESSING_FAILED,
                format!("startup: read the genesis record: {e}"),
            )
        })?
        .ok_or_else(|| {
            ingress_error(
                ERROR_CODE_PROCESSING_FAILED,
                "startup: no genesis record for this identity".to_string(),
            )
        })?;
    let smt_root = crate::util::text_id::decode_base32_crockford(&record.merkle_root)
        .filter(|root| root.len() == 32)
        .ok_or_else(|| {
            ingress_error(
                ERROR_CODE_PROCESSING_FAILED,
                "startup: the genesis record's SMT root is not 32 Base32 bytes".to_string(),
            )
        })?;

    crate::sdk::app_state::AppState::set_identity_info(
        device_id.to_vec(),
        kp.public_key().to_vec(),
        genesis_hash.to_vec(),
        smt_root,
    )
    .and_then(|()| crate::sdk::app_state::AppState::set_has_identity(true))
    .map_err(|e| {
        ingress_error(
            ERROR_CODE_PROCESSING_FAILED,
            format!("startup: persist the identity: {e}"),
        )
    })
}

fn ensure_identity_context_matches(
    device_id: &[u8],
    genesis_hash: &[u8],
) -> Result<bool, pb::Error> {
    let has_identity = crate::sdk::app_state::AppState::get_has_identity();
    let stored_device_id = crate::sdk::app_state::AppState::get_device_id();
    let stored_genesis_hash = crate::sdk::app_state::AppState::get_genesis_hash();

    if !has_identity && stored_device_id.is_none() && stored_genesis_hash.is_none() {
        return Ok(false);
    }

    let Some(current_device_id) = stored_device_id else {
        return Err(ingress_error(
            ERROR_CODE_PROCESSING_FAILED,
            "startup: identity state inconsistent (has identity flag without device_id)",
        ));
    };
    let Some(current_genesis_hash) = stored_genesis_hash else {
        return Err(ingress_error(
            ERROR_CODE_PROCESSING_FAILED,
            "startup: identity state inconsistent (has identity flag without genesis_hash)",
        ));
    };

    if current_device_id != device_id {
        return Err(ingress_error(
            ERROR_CODE_INVALID_INPUT,
            "startup: identity context already installed for a different device_id",
        ));
    }
    if current_genesis_hash != genesis_hash {
        return Err(ingress_error(
            ERROR_CODE_INVALID_INPUT,
            "startup: identity context already installed for a different genesis_hash",
        ));
    }

    Ok(true)
}

fn install_identity_context_core(
    device_id: Vec<u8>,
    genesis_hash: Vec<u8>,
) -> Result<(), pb::Error> {
    if device_id.len() != 32 {
        return Err(ingress_error(
            ERROR_CODE_INVALID_INPUT,
            format!(
                "startup: device_id must be 32 bytes, got {}",
                device_id.len()
            ),
        ));
    }
    if genesis_hash.len() != 32 {
        return Err(ingress_error(
            ERROR_CODE_INVALID_INPUT,
            format!(
                "startup: genesis_hash must be 32 bytes, got {}",
                genesis_hash.len()
            ),
        ));
    }

    // The same identity already installed, with its SDK context up, is done.
    // An identity on disk with no context in this process — a restart — is
    // not: its context is brought up below.
    if ensure_identity_context_matches(&device_id, &genesis_hash)?
        && crate::is_sdk_context_initialized()
    {
        return Ok(());
    }

    prime_identity_app_state(&device_id, &genesis_hash)?;

    let wallet_seed = crate::fetch_wallet_seed().map_err(|e| {
        ingress_error(
            ERROR_CODE_PROCESSING_FAILED,
            format!("startup: wallet locked before SDK context init: {e}"),
        )
    })?;
    let entropy = crate::derive_production_entropy(&device_id, &genesis_hash, &wallet_seed);
    crate::initialize_sdk_context(device_id, genesis_hash, entropy).map_err(|e| {
        ingress_error(
            ERROR_CODE_PROCESSING_FAILED,
            format!("startup: initialize_sdk_context failed: {e}"),
        )
    })
}

fn initialize_identity_context_core(
    device_id: Vec<u8>,
    genesis_hash: Vec<u8>,
) -> Result<Vec<u8>, pb::Error> {
    install_identity_context_core(device_id, genesis_hash)?;
    initialize_sdk_core()
}

fn restore_identity_context_core(
    device_id: Vec<u8>,
    genesis_hash: Vec<u8>,
) -> Result<Vec<u8>, pb::Error> {
    let context = PlatformContext::bootstrap(RawPlatformInputs {
        device_id_raw: device_id,
        genesis_hash_raw: genesis_hash,
    })
    .map_err(|e| {
        ingress_error(
            ERROR_CODE_INVALID_INPUT,
            format!("startup: restore_identity_context failed: {e}"),
        )
    })?;

    initialize_identity_context_core(context.device_id.to_vec(), context.genesis_hash.to_vec())
}

pub fn dispatch_ingress(request: IngressRequest) -> IngressResponse {
    let result: Result<Vec<u8>, pb::Error> = match request.operation {
        Some(ingress_request::Operation::RouterQuery(op)) => router_query_core(op.method, op.args),
        Some(ingress_request::Operation::RouterInvoke(op)) => {
            router_invoke_core(op.method, op.args)
        }
        Some(ingress_request::Operation::Envelope(op)) => {
            if op.envelope_bytes.is_empty() {
                Err(ingress_error(
                    ERROR_CODE_INVALID_INPUT,
                    "ingress: envelope bytes missing",
                ))
            } else {
                let slice = if op.envelope_bytes.first() == Some(&0x03) {
                    &op.envelope_bytes[1..]
                } else {
                    op.envelope_bytes.as_slice()
                };
                let env_in = crate::envelope::from_canonical_bytes(slice).map_err(|e| {
                    ingress_error(
                        ERROR_CODE_INVALID_INPUT,
                        format!("ingress: envelope decode failed: {e}"),
                    )
                });
                match env_in.and_then(process_envelope_core) {
                    Ok(env_out) => {
                        let mut buf = Vec::with_capacity(1 + env_out.encoded_len());
                        buf.push(0x03);
                        match env_out.encode(&mut buf) {
                            Ok(()) => Ok(buf),
                            Err(e) => Err(ingress_error(
                                ERROR_CODE_PROCESSING_FAILED,
                                format!("ingress: response encode failed: {e}"),
                            )),
                        }
                    }
                    Err(e) => Err(e),
                }
            }
        }
        Some(ingress_request::Operation::HardwareFacts(op)) => match op.facts {
            Some(facts) => update_hardware_facts_core(facts),
            None => Err(ingress_error(
                ERROR_CODE_INVALID_INPUT,
                "ingress: hardware facts missing",
            )),
        },
        Some(_) => Err(ingress_error(
            ERROR_CODE_INVALID_INPUT,
            "ingress: unsupported operation",
        )),
        None => Err(ingress_error(
            ERROR_CODE_INVALID_INPUT,
            "ingress: empty IngressRequest (no operation set)",
        )),
    };

    match result {
        Ok(bytes) => IngressResponse {
            result: Some(ingress_response::Result::OkBytes(bytes)),
        },
        Err(error) => IngressResponse {
            result: Some(ingress_response::Result::Error(error)),
        },
    }
}

pub fn dispatch_ingress_bytes(request_bytes: &[u8]) -> Vec<u8> {
    let request = match IngressRequest::decode(request_bytes) {
        Ok(r) => r,
        Err(e) => {
            return IngressResponse {
                result: Some(ingress_response::Result::Error(ingress_error(
                    ERROR_CODE_INVALID_INPUT,
                    format!("ingress: IngressRequest decode failed: {e}"),
                ))),
            }
            .encode_to_vec();
        }
    };

    dispatch_ingress(request).encode_to_vec()
}

pub fn dispatch_startup(request: StartupRequest) -> StartupResponse {
    let result: Result<Vec<u8>, pb::Error> = match request.operation {
        Some(startup_request::Operation::SetStorageBaseDir(op)) => {
            set_storage_base_dir_core(op.path_utf8)
        }
        Some(startup_request::Operation::ConfigureEnv(op)) => {
            configure_env_core(op.config_path_utf8)
        }
        Some(startup_request::Operation::InitializeSdk(_)) => initialize_sdk_core(),
        Some(startup_request::Operation::InitializeIdentityContext(op)) => {
            // op.binding_key is a reserved/ignored legacy C-DBRW field (Genesis v2 roots
            // identity in the wallet seed).
            initialize_identity_context_core(op.device_id, op.genesis_hash)
        }
        Some(startup_request::Operation::RestoreIdentityContext(op)) => {
            // op.cdbrw_hw_entropy / op.cdbrw_env_fingerprint / op.cdbrw_salt are reserved/ignored
            // legacy C-DBRW fields; identity restores deterministically from the wallet seed.
            restore_identity_context_core(op.device_id, op.genesis_hash)
        }
        None => Err(ingress_error(
            ERROR_CODE_INVALID_INPUT,
            "startup: empty StartupRequest (no operation set)",
        )),
    };

    match result {
        Ok(bytes) => StartupResponse {
            result: Some(startup_response::Result::OkBytes(bytes)),
        },
        Err(error) => StartupResponse {
            result: Some(startup_response::Result::Error(error)),
        },
    }
}

pub fn dispatch_startup_bytes(request_bytes: &[u8]) -> Vec<u8> {
    let request = match StartupRequest::decode(request_bytes) {
        Ok(r) => r,
        Err(e) => {
            return StartupResponse {
                result: Some(startup_response::Result::Error(ingress_error(
                    ERROR_CODE_INVALID_INPUT,
                    format!("startup: StartupRequest decode failed: {e}"),
                ))),
            }
            .encode_to_vec();
        }
    };

    dispatch_startup(request).encode_to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use serial_test::serial;

    use crate::bridge::install_app_router;
    use crate::economic_fixtures::{self, TestIdentity};

    /// A process with nothing installed yet: no router, no SDK context, no
    /// identity in memory, the SDK not ready.
    fn fresh_process() {
        economic_fixtures::use_test_storage_dir();
        crate::sdk::session_manager::set_sdk_ready(false);
        crate::reset_sdk_context_for_testing();
        unsafe { crate::bridge::reset_bridge_handlers_for_tests() };
    }

    /// A device created as wallet creation creates it, then the process that
    /// created it gone: its identity is on disk, the new process holds
    /// nothing in memory, and the wallet is unlocked from its mnemonic.
    fn restarted_device(seed: u8) -> TestIdentity {
        let identity = economic_fixtures::local_device(seed).0;
        crate::sdk::app_state::AppState::reset_memory_for_testing();
        fresh_process();
        crate::sdk::recovery_sdk::RecoverySDK::derive_and_cache_key(
            &economic_fixtures::test_mnemonic(seed),
        )
        .expect("unlock the wallet");
        identity
    }

    /// The network's pinned nodes and the env config naming them — what
    /// `ConfigureEnv` points a device at.
    fn fleet() -> crate::test_support::one_device::Fleet {
        crate::test_support::one_device::Fleet::start()
    }

    fn expect_ok_bytes(response: IngressResponse) -> Vec<u8> {
        match response.result {
            Some(ingress_response::Result::OkBytes(bytes)) => bytes,
            other => panic!("expected ok bytes, got {:?}", other),
        }
    }

    /// A device as wallet creation creates it, with its router installed as
    /// the app installs it and no storage nodes named: the router answers what
    /// this device holds.
    fn device_with_router(seed: u8) {
        fresh_process();
        economic_fixtures::local_device(seed);
        let router = crate::handlers::app_router_impl::AppRouterImpl::new(crate::init::SdkConfig {
            node_id: "ingress-router-test".to_string(),
            storage_endpoints: Vec::new(),
            enable_offline: false,
        })
        .expect("router");
        install_app_router(Arc::new(router)).expect("install router");
    }

    fn expect_error(response: IngressResponse) -> pb::Error {
        match response.result {
            Some(ingress_response::Result::Error(error)) => error,
            other => panic!("expected error, got {:?}", other),
        }
    }

    fn expect_startup_ok(response: StartupResponse) -> Vec<u8> {
        match response.result {
            Some(startup_response::Result::OkBytes(bytes)) => bytes,
            other => panic!("expected startup ok bytes, got {:?}", other),
        }
    }

    fn expect_startup_error(response: StartupResponse) -> pb::Error {
        match response.result {
            Some(startup_response::Result::Error(error)) => error,
            other => panic!("expected startup error, got {:?}", other),
        }
    }

    #[test]
    #[serial]
    fn dispatch_ingress_empty_request_returns_invalid_input() {
        fresh_process();
        let response = dispatch_ingress(IngressRequest { operation: None });
        let error = expect_error(response);
        assert_eq!(error.code, ERROR_CODE_INVALID_INPUT);
        assert!(error.message.contains("empty IngressRequest"));
    }

    #[test]
    #[serial]
    fn dispatch_ingress_bytes_invalid_proto_returns_invalid_input() {
        fresh_process();
        let response_bytes = dispatch_ingress_bytes(&[0xff, 0xfe, 0xfd]);
        let response = IngressResponse::decode(response_bytes.as_slice()).expect("decode response");
        let error = expect_error(response);
        assert_eq!(error.code, ERROR_CODE_INVALID_INPUT);
    }

    #[test]
    #[serial]
    fn envelope_request_strips_optional_prefix_and_reframes_success_output() {
        fresh_process();
        let request_env = Envelope {
            version: 3,
            headers: Some(pb::Headers {
                device_id: vec![1; 32],
                genesis_hash: vec![3; 32],
            }),
            message_id: vec![7; 16],
            payload: Some(pb::envelope::Payload::Error(pb::Error {
                code: 99,
                message: "request already a response".to_string(),
                context: Vec::new(),
                source_tag: 0,
                is_recoverable: false,
                debug_b32: String::new(),
            })),
        };
        let mut framed = vec![0x03];
        framed.extend_from_slice(&request_env.encode_to_vec());

        let response = dispatch_ingress(IngressRequest {
            operation: Some(ingress_request::Operation::Envelope(pb::EnvelopeOp {
                envelope_bytes: framed,
            })),
        });
        let ok_bytes = expect_ok_bytes(response);
        assert_eq!(ok_bytes.first(), Some(&0x03));
        let decoded = crate::envelope::local_answer_from_canonical_bytes(&ok_bytes[1..])
            .expect("the answer is a local answer");
        assert_eq!(decoded.version, 3);
    }

    #[test]
    #[serial]
    fn malformed_envelope_returns_invalid_input() {
        fresh_process();
        let response = dispatch_ingress(IngressRequest {
            operation: Some(ingress_request::Operation::Envelope(pb::EnvelopeOp {
                envelope_bytes: vec![0x03, 0xaa, 0xbb, 0xcc],
            })),
        });
        let error = expect_error(response);
        assert_eq!(error.code, ERROR_CODE_INVALID_INPUT);
        assert!(error.message.contains("envelope decode failed"));
    }

    #[test]
    #[serial]
    fn wrong_version_envelope_returns_invalid_input() {
        fresh_process();
        let request_env = Envelope {
            version: 2,
            headers: Some(pb::Headers {
                device_id: vec![1; 32],
                genesis_hash: vec![3; 32],
            }),
            message_id: vec![4; 16],
            payload: Some(pb::envelope::Payload::Error(pb::Error {
                code: 7,
                message: "wrong version".to_string(),
                context: Vec::new(),
                source_tag: 0,
                is_recoverable: false,
                debug_b32: String::new(),
            })),
        };
        let mut framed = vec![0x03];
        framed.extend_from_slice(&request_env.encode_to_vec());

        let response = dispatch_ingress(IngressRequest {
            operation: Some(ingress_request::Operation::Envelope(pb::EnvelopeOp {
                envelope_bytes: framed,
            })),
        });
        let error = expect_error(response);
        assert_eq!(error.code, ERROR_CODE_INVALID_INPUT);
        assert!(
            error.message.contains("Envelope.version must be 3"),
            "unexpected error: {}",
            error.message
        );
    }

    /// The device's router answers through the ingress byte for byte: a
    /// preference set and read back through `RouterQuery`.
    #[test]
    #[serial]
    fn a_router_query_answer_passes_through_unchanged() {
        device_with_router(0x44);
        let pref = |path: &str, value: &str| {
            dispatch_ingress(IngressRequest {
                operation: Some(ingress_request::Operation::RouterQuery(pb::RouterQueryOp {
                    method: path.to_string(),
                    args: pb::ArgPack {
                        codec: pb::Codec::Proto as i32,
                        body: pb::AppStateRequest {
                            key: "ingress.test".to_string(),
                            operation: String::new(),
                            value: value.to_string(),
                        }
                        .encode_to_vec(),
                        ..Default::default()
                    }
                    .encode_to_vec(),
                })),
            })
        };
        expect_ok_bytes(pref("prefs.set", "through the ingress"));
        let answer = expect_ok_bytes(pref("prefs.get", ""));
        let envelope = crate::handlers::response_helpers::decode_local_envelope(&answer)
            .expect("the router's local answer");
        match envelope.payload {
            Some(dsm::types::proto::envelope::Payload::AppStateResponse(r)) => {
                assert_eq!(r.value.as_deref(), Some("through the ingress"))
            }
            other => panic!("prefs.get answered {other:?}"),
        }
    }

    /// The record the frontend's tests answer `wallet.amount` from. Jest runs
    /// no Rust, so the guided tour's practice wallet, which asks Rust for every
    /// figure it shows, is tested against this process's own answers: each
    /// request those tests send, framed as the WebView frames it, and the bytes
    /// this ingress answered, as the JNI hands them back. The committed record
    /// must equal the live answers; DSM_WRITE_FRONTEND_FIXTURES=1 rewrites it.
    const WALLET_AMOUNT_RECORD: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../frontend/src/components/tour/__tests__/fixtures/wallet_amount.ingress.bin"
    );

    /// `wallet.amount` through the ingress: ERA by its committed policy, the
    /// practice coin at its stated decimals, and a refusal in Rust's words; and
    /// `balance.list`, whose ERA row is where the practice wallet reads that ERA
    /// is protocol-defined, as every screen reads it. The frontend's record of
    /// these answers is this process's own.
    #[test]
    #[serial]
    fn wallet_amount_answers_through_the_ingress_as_the_frontend_records_it() {
        use pb::wallet_amount_request::{Amount, Unit};
        device_with_router(0x46);

        // What the practice wallet's tests ask (practiceMode.test.ts).
        let asked = vec![
            // Practice ERA, counted by ERA's committed policy.
            (
                Unit::TokenId("ERA".to_string()),
                Amount::Entered("1000".to_string()),
            ),
            // 5 of the practice coin sent, and what is left of its 50.
            (Unit::Decimals(0), Amount::Entered("5".to_string())),
            (Unit::Decimals(0), Amount::BaseUnits(45)),
            // 25 ERA sent, and what is left.
            (Unit::Decimals(2), Amount::Entered("25".to_string())),
            (Unit::Decimals(2), Amount::BaseUnits(97_500)),
            // The faucet's 100 ERA, and the balance after it.
            (Unit::Decimals(2), Amount::Entered("100".to_string())),
            (Unit::Decimals(2), Amount::BaseUnits(110_000)),
            // Finer than ERA counts, and nothing at all.
            (Unit::Decimals(2), Amount::Entered("1.234".to_string())),
            (Unit::Decimals(2), Amount::Entered("0".to_string())),
        ];
        let mut record = Vec::new();
        let mut answers = Vec::new();
        for (unit, amount) in asked {
            let request = IngressRequest {
                operation: Some(ingress_request::Operation::RouterQuery(pb::RouterQueryOp {
                    method: "wallet.amount".to_string(),
                    args: pb::ArgPack {
                        codec: pb::Codec::Proto as i32,
                        body: pb::WalletAmountRequest {
                            unit: Some(unit),
                            amount: Some(amount),
                        }
                        .encode_to_vec(),
                        ..Default::default()
                    }
                    .encode_to_vec(),
                })),
            }
            .encode_to_vec();
            let response = dispatch_ingress_bytes(&request);
            for part in [&request, &response] {
                let len = u32::try_from(part.len()).expect("a record part fits a u32 length");
                record.extend_from_slice(&len.to_be_bytes());
                record.extend_from_slice(part);
            }
            answers.push(IngressResponse::decode(response.as_slice()).expect("an IngressResponse"));
        }

        // The practice wallet's ERA row states ERA as Rust lists it
        // (practiceMode.ts `seedEra`): the router's `balance.list`, which lists
        // ERA at any balance, asked as the WebView asks it, with no arguments.
        let listed_request = IngressRequest {
            operation: Some(ingress_request::Operation::RouterQuery(pb::RouterQueryOp {
                method: "balance.list".to_string(),
                args: Vec::new(),
            })),
        }
        .encode_to_vec();
        let listed_response = dispatch_ingress_bytes(&listed_request);
        for part in [&listed_request, &listed_response] {
            let len = u32::try_from(part.len()).expect("a record part fits a u32 length");
            record.extend_from_slice(&len.to_be_bytes());
            record.extend_from_slice(part);
        }
        let listed = expect_ok_bytes(
            IngressResponse::decode(listed_response.as_slice()).expect("an IngressResponse"),
        );
        match crate::handlers::response_helpers::decode_local_envelope(&listed)
            .expect("the router's local answer")
            .payload
        {
            Some(dsm::types::proto::envelope::Payload::BalancesListResponse(list)) => {
                let era = list
                    .balances
                    .iter()
                    .find(|row| row.token_id == "ERA")
                    .expect("balance.list lists ERA at any balance");
                assert!(era.protocol_defined, "Rust lists ERA as protocol-defined");
            }
            other => panic!("balance.list answered {other:?}"),
        }

        let forms = |response: IngressResponse| {
            let answer = expect_ok_bytes(response);
            match crate::handlers::response_helpers::decode_local_envelope(&answer)
                .expect("the router's local answer")
                .payload
            {
                Some(dsm::types::proto::envelope::Payload::WalletAmountResponse(r)) => {
                    (r.base_units, r.display_amount, r.decimals)
                }
                other => panic!("wallet.amount answered {other:?}"),
            }
        };
        let mut answers = answers.into_iter();
        let mut next = || answers.next().expect("an answer to every request");
        assert_eq!(forms(next()), (100_000, "1000.00".to_string(), 2));
        assert_eq!(forms(next()), (5, "5".to_string(), 0));
        assert_eq!(forms(next()), (45, "45".to_string(), 0));
        assert_eq!(forms(next()), (2_500, "25.00".to_string(), 2));
        assert_eq!(forms(next()), (97_500, "975.00".to_string(), 2));
        assert_eq!(forms(next()), (10_000, "100.00".to_string(), 2));
        assert_eq!(forms(next()), (110_000, "1100.00".to_string(), 2));
        let refused = expect_error(next());
        assert!(
            refused
                .message
                .contains("wallet.amount: amount exceeds 2 fractional digits"),
            "{}",
            refused.message
        );
        assert_eq!(forms(next()), (0, "0.00".to_string(), 2));

        match std::env::var_os("DSM_WRITE_FRONTEND_FIXTURES") {
            Some(_) => {
                std::fs::write(WALLET_AMOUNT_RECORD, &record).expect("write the frontend's record")
            }
            None => assert_eq!(
                std::fs::read(WALLET_AMOUNT_RECORD).expect("the frontend's committed record"),
                record,
                "the frontend's wallet.amount record differs from this ingress's answers; \
                 rewrite it with DSM_WRITE_FRONTEND_FIXTURES=1"
            ),
        }
    }

    /// The record the frontend's lock screen tests answer `session.*` from:
    /// each try the lock screen sends, framed as the WebView frames it, and
    /// this ingress's answer. The committed record must equal the live
    /// answers; DSM_WRITE_FRONTEND_FIXTURES=1 rewrites it.
    const SESSION_LOCK_RECORD: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../frontend/src/components/lock/__tests__/fixtures/session_lock.ingress.bin"
    );

    /// The BIP39 vectors the lock screen's tests type: this wallet's phrase,
    /// and another wallet's.
    const LOCK_RECORD_PHRASE: &str = "abandon abandon abandon abandon abandon abandon \
                                      abandon abandon abandon abandon abandon about";
    const LOCK_RECORD_OTHER_PHRASE: &str = "legal winner thank year wave sausage worth useful \
                                            legal winner thank yellow";

    /// The app lock through the ingress, as the lock screen meets it: a PIN
    /// lock on, the session locked, three wrong PINs answered with the tries
    /// left and then the phrase required, the right PIN no longer opening it,
    /// another wallet's phrase refused, and this wallet's phrase opening it.
    /// Each answer is Rust's session snapshot; the frontend's record of them
    /// is this process's own.
    #[test]
    #[serial]
    fn the_lock_answers_through_the_ingress_as_the_frontend_records_it() {
        // A fresh store: no lock settings left by an earlier test.
        economic_fixtures::use_test_storage_dir();
        crate::sdk::app_state::AppState::reset_for_testing();
        device_with_router(0x47);
        crate::sdk::recovery_sdk::RecoverySDK::derive_and_cache_key(LOCK_RECORD_PHRASE)
            .expect("this wallet's seed");
        *crate::sdk::session_manager::SESSION_MANAGER
            .lock()
            .expect("the session manager") = crate::sdk::session_manager::SessionManager::default();

        let invoke = |method: &str, body: Vec<u8>| {
            IngressRequest {
                operation: Some(ingress_request::Operation::RouterInvoke(
                    pb::RouterInvokeOp {
                        method: method.to_string(),
                        args: pb::ArgPack {
                            codec: pb::Codec::Proto as i32,
                            body,
                            ..Default::default()
                        }
                        .encode_to_vec(),
                    },
                )),
            }
            .encode_to_vec()
        };
        let unlock = |key: pb::session_unlock_request::Key| {
            invoke(
                "session.unlock",
                pb::SessionUnlockRequest { key: Some(key) }.encode_to_vec(),
            )
        };
        let lock_of = |response: &[u8]| {
            let answer =
                expect_ok_bytes(IngressResponse::decode(response).expect("an IngressResponse"));
            match crate::handlers::response_helpers::decode_local_envelope(&answer)
                .expect("the router's local answer")
                .payload
            {
                Some(dsm::types::proto::envelope::Payload::SessionStateResponse(s)) => {
                    let lock = s.lock_status.expect("a lock status");
                    (lock.locked, lock.misses_left, lock.phrase_required)
                }
                other => panic!("the session route answered {other:?}"),
            }
        };

        // The lock the user set up: a PIN. Not part of the record.
        let on = dispatch_ingress_bytes(&invoke(
            "session.configure_lock",
            pb::SessionConfigureLockRequest {
                method: "pin".to_string(),
                secret: "2468".to_string(),
                ..Default::default()
            }
            .encode_to_vec(),
        ));
        let (locked, left, phrase) = lock_of(&on);
        assert!(!locked && !phrase, "a new lock leaves the wallet open");
        assert_eq!(left, crate::sdk::app_lock::MISSES_BEFORE_PHRASE);

        use pb::session_unlock_request::Key;
        let asked = vec![
            IngressRequest {
                operation: Some(ingress_request::Operation::RouterInvoke(
                    pb::RouterInvokeOp {
                        method: "session.lock".to_string(),
                        args: Vec::new(),
                    },
                )),
            }
            .encode_to_vec(),
            unlock(Key::Secret("0000".to_string())),
            unlock(Key::Secret("0001".to_string())),
            unlock(Key::Secret("0002".to_string())),
            unlock(Key::RecoveryPhrase(LOCK_RECORD_OTHER_PHRASE.to_string())),
            unlock(Key::RecoveryPhrase(LOCK_RECORD_PHRASE.to_string())),
        ];
        let mut record = Vec::new();
        let mut answers = Vec::new();
        for (at, request) in asked.iter().enumerate() {
            let response = dispatch_ingress_bytes(request);
            for part in [request, &response] {
                let len = u32::try_from(part.len()).expect("a record part fits a u32 length");
                record.extend_from_slice(&len.to_be_bytes());
                record.extend_from_slice(part);
            }
            answers.push(lock_of(&response));
            // Once the tries are used up, the right PIN opens nothing either.
            // The lock screen no longer offers the PIN, so this is not recorded.
            if at == 3 {
                let right = dispatch_ingress_bytes(&unlock(Key::Secret("2468".to_string())));
                let (locked, _, phrase) = lock_of(&right);
                assert!(
                    locked && phrase,
                    "the right PIN opened a lock past its tries"
                );
            }
        }
        // Locked with `left` tries, the phrase required exactly when none are.
        let locked_with = |(locked, misses_left, phrase): (bool, u32, bool), left: u32| {
            assert!(locked, "the wallet stays locked");
            assert_eq!(misses_left, left);
            assert_eq!(
                phrase,
                left == 0,
                "the phrase is required once no tries are left"
            );
        };
        let max = crate::sdk::app_lock::MISSES_BEFORE_PHRASE;
        let mut answers = answers.into_iter();
        let mut next = || answers.next().expect("an answer to every request");
        locked_with(next(), max);
        locked_with(next(), max - 1);
        locked_with(next(), max - 2);
        locked_with(next(), 0);
        locked_with(next(), 0);
        let (locked, misses_left, phrase) = next();
        assert!(!locked && !phrase, "this wallet's phrase opens it");
        assert_eq!(misses_left, max, "and starts the tries again");

        match std::env::var_os("DSM_WRITE_FRONTEND_FIXTURES") {
            Some(_) => {
                std::fs::write(SESSION_LOCK_RECORD, &record).expect("write the frontend's record")
            }
            None => assert_eq!(
                std::fs::read(SESSION_LOCK_RECORD).expect("the frontend's committed record"),
                record,
                "the frontend's session lock record differs from this ingress's answers; \
                 rewrite it with DSM_WRITE_FRONTEND_FIXTURES=1"
            ),
        }
    }

    /// A router refusal reaches the caller as an error carrying the router's
    /// own reason: an invoke for a token this device does not hold.
    #[test]
    #[serial]
    fn a_router_invoke_refusal_passes_through_with_its_reason() {
        device_with_router(0x45);
        let response = dispatch_ingress(IngressRequest {
            operation: Some(ingress_request::Operation::RouterInvoke(
                pb::RouterInvokeOp {
                    method: "token.forget".to_string(),
                    args: pb::ArgPack {
                        codec: pb::Codec::Proto as i32,
                        body: pb::TokenForgetRequest {
                            token_id: "NOTHELD".to_string(),
                        }
                        .encode_to_vec(),
                        ..Default::default()
                    }
                    .encode_to_vec(),
                },
            )),
        });
        let error = expect_error(response);
        assert!(error.message.contains("token.forget"), "{}", error.message);
    }

    #[test]
    #[serial]
    fn router_absent_maps_to_not_ready() {
        fresh_process();
        let response = dispatch_ingress(IngressRequest {
            operation: Some(ingress_request::Operation::RouterQuery(pb::RouterQueryOp {
                method: "wallet.balance".to_string(),
                args: Vec::new(),
            })),
        });
        let error = expect_error(response);
        assert_eq!(error.code, ERROR_CODE_NOT_READY);
        assert!(error.message.contains("app router not installed"));
    }

    #[test]
    #[serial]
    fn hardware_facts_success_returns_envelope_wrapped_snapshot() {
        fresh_process();
        let response = dispatch_ingress(IngressRequest {
            operation: Some(ingress_request::Operation::HardwareFacts(
                pb::HardwareFactsOp {
                    facts: Some(pb::SessionHardwareFactsProto {
                        app_foreground: true,
                        ble_enabled: true,
                        ble_permissions: true,
                        ble_scanning: false,
                        ble_advertising: true,
                        qr_available: true,
                        qr_active: false,
                        camera_permission: true,
                        battery_charging: false,
                        battery_level_percent: 88,
                    }),
                },
            )),
        });
        let ok_bytes = expect_ok_bytes(response);
        assert_eq!(ok_bytes.first(), Some(&0x03));
        let envelope = crate::handlers::response_helpers::decode_local_envelope(&ok_bytes)
            .expect("the session snapshot is a local answer");
        match envelope.payload {
            Some(dsm::types::proto::envelope::Payload::SessionStateResponse(snapshot)) => {
                let hardware = snapshot.hardware_status.expect("hardware status");
                assert!(hardware.app_foreground);
            }
            other => panic!("expected SessionStateResponse, got {:?}", other),
        }
    }

    #[test]
    #[serial]
    fn startup_empty_request_returns_invalid_input() {
        fresh_process();
        let response = dispatch_startup(StartupRequest { operation: None });
        let error = expect_startup_error(response);
        assert_eq!(error.code, ERROR_CODE_INVALID_INPUT);
        assert!(error.message.contains("empty StartupRequest"));
    }

    #[test]
    #[serial]
    fn startup_set_storage_base_dir_is_idempotent() {
        fresh_process();
        let path_utf8 = crate::storage_utils::get_storage_base_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("./.dsm_testdata"))
            .to_string_lossy()
            .to_string();
        let request = StartupRequest {
            operation: Some(startup_request::Operation::SetStorageBaseDir(
                pb::SetStorageBaseDirOp { path_utf8 },
            )),
        };
        assert_eq!(
            expect_startup_ok(dispatch_startup(request.clone())),
            STARTUP_OK_BYTES
        );
        assert_eq!(
            expect_startup_ok(dispatch_startup(request)),
            STARTUP_OK_BYTES
        );
    }

    #[test]
    #[serial]
    fn startup_initialize_sdk_installs_minimal_router() {
        fresh_process();
        let fleet = fleet();
        let response = dispatch_startup(StartupRequest {
            operation: Some(startup_request::Operation::InitializeSdk(
                pb::InitializeSdkOp {},
            )),
        });
        assert_eq!(expect_startup_ok(response), STARTUP_OK_BYTES);
        assert!(crate::sdk::session_manager::SDK_READY.load(std::sync::atomic::Ordering::SeqCst));

        let response = dispatch_ingress(IngressRequest {
            operation: Some(ingress_request::Operation::RouterQuery(pb::RouterQueryOp {
                method: "system.generateMnemonic".to_string(),
                args: Vec::new(),
            })),
        });
        // Before genesis the minimal router answers wallet creation's first
        // query: a fresh BIP39 mnemonic.
        let ok_bytes = expect_ok_bytes(response);
        let pack = pb::ArgPack::decode(ok_bytes.as_slice()).expect("an ArgPack answer");
        let phrase = String::from_utf8(pack.body).expect("a UTF-8 phrase");
        bip39::Mnemonic::parse_in(bip39::Language::English, &phrase)
            .expect("the minimal router answers a valid mnemonic");
        drop(fleet);
    }

    /// A phone an older build provisioned keeps its store at that build's
    /// schema, and this build refuses it: beta does not migrate. Startup fails
    /// in the store's own words and that is the session's error, so the page
    /// leaves "starting runtime" and says what to do. The nodes run, the device
    /// is created as wallet creation creates it, and its store is left as the
    /// older build left it: stamped 24, without the table 25 added.
    #[test]
    #[serial]
    fn a_store_at_an_older_schema_fails_startup_as_the_sessions_error() {
        let fleet = fleet();
        let _identity = economic_fixtures::local_device(0x12).0;
        {
            let store = crate::storage::client_db::get_connection().expect("the store");
            let conn = store.lock().expect("the store lock");
            conn.execute_batch("DROP TABLE history_repair_queue; PRAGMA user_version = 24;")
                .expect("leave the store as schema 24 left it");
        }
        // The process that provisioned it is gone.
        crate::storage::client_db::close_database_for_tests();
        crate::sdk::app_state::AppState::reset_memory_for_testing();
        fresh_process();
        crate::sdk::session_manager::clear_fatal_error_and_snapshot().expect("clear");

        let start = || {
            dispatch_startup(StartupRequest {
                operation: Some(startup_request::Operation::InitializeSdk(
                    pb::InitializeSdkOp {},
                )),
            })
        };
        let snapshot = || {
            crate::sdk::session_manager::SESSION_MANAGER
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .compute_snapshot()
        };
        let error = expect_startup_error(start());
        assert!(
            error.message.contains("SCHEMA RESET REQUIRED"),
            "{}",
            error.message
        );
        assert_eq!(snapshot().phase, "error");
        assert_eq!(snapshot().fatal_error, error.message);

        // The remedy the refusal names, a wiped store: startup then succeeds
        // and takes its own failure back.
        crate::storage::client_db::reset_database_for_tests();
        expect_startup_ok(start());
        assert_eq!(snapshot().fatal_error, "");
        assert_ne!(snapshot().phase, "error");
        drop(fleet);
    }

    #[test]
    #[serial]
    fn initialize_identity_context_sets_identity_and_router() {
        let identity = restarted_device(0x11);
        install_identity_context_core(identity.device_id.to_vec(), identity.genesis.to_vec())
            .expect("identity context install should succeed");
        assert!(crate::is_sdk_context_initialized());
    }

    #[test]
    #[serial]
    fn prime_identity_app_state_returns_error_when_wallet_locked() {
        let identity = restarted_device(0x12);
        // The wallet locks: its seed leaves RAM.
        crate::sdk::recovery_sdk::RecoverySDK::clear_wallet_seed_cache();
        let error = prime_identity_app_state(&identity.device_id, &identity.genesis)
            .expect_err("a locked wallet must be surfaced as a startup error");
        assert_eq!(error.code, ERROR_CODE_PROCESSING_FAILED);
        assert!(error
            .message
            .contains("wallet locked before identity priming"));
    }

    #[test]
    #[serial]
    fn initialize_identity_context_via_dispatch_succeeds() {
        let identity = restarted_device(0x13);
        let fleet = fleet();
        let response = dispatch_startup(StartupRequest {
            operation: Some(startup_request::Operation::InitializeIdentityContext(
                pb::InitializeIdentityContextOp {
                    device_id: identity.device_id.to_vec(),
                    genesis_hash: identity.genesis.to_vec(),
                },
            )),
        });
        assert_eq!(expect_startup_ok(response), STARTUP_OK_BYTES);
        assert!(crate::is_sdk_context_initialized());
        drop(fleet);
    }

    fn restore(identity_device: [u8; 32], genesis: [u8; 32]) -> StartupResponse {
        dispatch_startup(StartupRequest {
            operation: Some(startup_request::Operation::RestoreIdentityContext(
                pb::RestoreIdentityContextOp {
                    device_id: identity_device.to_vec(),
                    genesis_hash: genesis.to_vec(),
                },
            )),
        })
    }

    #[test]
    #[serial]
    fn startup_restore_identity_context_initializes_router() {
        let identity = restarted_device(0x14);
        let fleet = fleet();
        assert_eq!(
            expect_startup_ok(restore(identity.device_id, identity.genesis)),
            STARTUP_OK_BYTES
        );
        assert!(crate::is_sdk_context_initialized());
        drop(fleet);
    }

    #[test]
    #[serial]
    fn startup_restore_identity_context_is_idempotent_for_same_identity() {
        let identity = restarted_device(0x15);
        let fleet = fleet();
        assert_eq!(
            expect_startup_ok(restore(identity.device_id, identity.genesis)),
            STARTUP_OK_BYTES
        );
        assert_eq!(
            expect_startup_ok(restore(identity.device_id, identity.genesis)),
            STARTUP_OK_BYTES
        );
        drop(fleet);
    }

    #[test]
    #[serial]
    fn startup_restore_identity_context_rejects_mismatched_identity() {
        let other = crate::test_support::two_device::TestDevice::create("other", 0x99);
        let identity = restarted_device(0x16);
        let fleet = fleet();
        assert_eq!(
            expect_startup_ok(restore(identity.device_id, identity.genesis)),
            STARTUP_OK_BYTES
        );
        let error = expect_startup_error(restore(other.device_id, identity.genesis));
        assert_eq!(error.code, ERROR_CODE_INVALID_INPUT);
        assert!(
            error.message.contains("different device_id"),
            "{}",
            error.message
        );
        drop(fleet);
    }
}
