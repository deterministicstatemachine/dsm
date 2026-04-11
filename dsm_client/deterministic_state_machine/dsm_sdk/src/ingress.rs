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
    ingress_request, ingress_response, startup_request, startup_response, Envelope,
    IngressRequest, IngressResponse, StartupRequest, StartupResponse,
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

fn build_envelope(payload: pb::envelope::Payload) -> Envelope {
    Envelope {
        version: 3,
        headers: None,
        message_id: vec![0u8; 16],
        payload: Some(payload),
    }
}

fn encode_framed_envelope(payload: pb::envelope::Payload) -> Result<Vec<u8>, pb::Error> {
    let envelope = build_envelope(payload);
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

fn push_genesis_lifecycle_event(kind: i32, progress: u32) -> Result<(), pb::Error> {
    push_canonical_envelope_event(pb::envelope::Payload::GenesisLifecycle(
        pb::GenesisLifecycleEvent { kind, progress },
    ))
}

fn bootstrap_finalize_envelope(
    result: i32,
    device_id: Vec<u8>,
    genesis_hash: Vec<u8>,
    message: impl Into<String>,
) -> Envelope {
    build_envelope(pb::envelope::Payload::BootstrapFinalizeResponse(
        pb::BootstrapFinalizeResponse {
            result,
            device_id,
            genesis_hash,
            message: message.into(),
        },
    ))
}

fn startup_initialize_identity_context(
    device_id: Vec<u8>,
    genesis_hash: Vec<u8>,
    binding_key: Vec<u8>,
) -> Result<(), pb::Error> {
    match dispatch_startup(StartupRequest {
        operation: Some(startup_request::Operation::InitializeIdentityContext(
            pb::InitializeIdentityContextOp {
                device_id,
                genesis_hash,
                binding_key,
            },
        )),
    })
    .result
    {
        Some(startup_response::Result::OkBytes(_)) => Ok(()),
        Some(startup_response::Result::Error(error)) => Err(error),
        None => Err(ingress_error(
            ERROR_CODE_PROCESSING_FAILED,
            "startup: empty initialize identity response",
        )),
    }
}

fn finalize_bootstrap_core(
    report: pb::BootstrapMeasurementReport,
) -> Result<Envelope, pb::Error> {
    log::info!("FINALIZE_BOOTSTRAP: ENTRY phase={} trust={}", report.phase, report.trust_level);
    // Scope guard: keep BOOTSTRAP_SECURING=true until this function exits, then clear it
    // unconditionally. This preserves phase=securing_device throughout the whole finalize
    // (including startup_initialize_identity_context which writes the identity), so any
    // concurrent session state read observes securing_device → wallet_ready atomically
    // instead of the prior race where the flag was cleared BEFORE has_identity became true,
    // exposing a transient phase=needs_genesis flash in the UI.
    struct ClearBootstrapSecuringOnDrop;
    impl Drop for ClearBootstrapSecuringOnDrop {
        fn drop(&mut self) {
            log::info!("FINALIZE_BOOTSTRAP: SCOPE_GUARD_DROP clearing BOOTSTRAP_SECURING=false");
            crate::sdk::session_manager::BOOTSTRAP_SECURING
                .store(false, std::sync::atomic::Ordering::SeqCst);
            log::info!(
                "FINALIZE_BOOTSTRAP: POST_DROP BOOTSTRAP_SECURING={} SDK_READY={} has_id={}",
                crate::sdk::session_manager::BOOTSTRAP_SECURING.load(std::sync::atomic::Ordering::SeqCst),
                crate::sdk::session_manager::SDK_READY.load(std::sync::atomic::Ordering::SeqCst),
                crate::sdk::app_state::AppState::get_has_identity()
            );
        }
    }
    let _clear_on_exit = ClearBootstrapSecuringOnDrop;

    if report.device_id.len() != 32 {
        return Err(ingress_error(
            ERROR_CODE_INVALID_INPUT,
            format!(
                "bootstrap_finalize: device_id must be 32 bytes, got {}",
                report.device_id.len()
            ),
        ));
    }
    if report.genesis_hash.len() != 32 {
        return Err(ingress_error(
            ERROR_CODE_INVALID_INPUT,
            format!(
                "bootstrap_finalize: genesis_hash must be 32 bytes, got {}",
                report.genesis_hash.len()
            ),
        ));
    }

    let device_id = report.device_id.clone();
    let genesis_hash = report.genesis_hash.clone();

    match report.trust_level {
        x if x
            == pb::bootstrap_measurement_report::TrustLevel::BootstrapTrustLevelReadOnly as i32 =>
        {
            push_genesis_lifecycle_event(
                pb::genesis_lifecycle_event::Kind::GenesisKindError as i32,
                0,
            )?;
            return Ok(bootstrap_finalize_envelope(
                pb::bootstrap_finalize_response::Result::BootstrapResultReadOnly as i32,
                device_id,
                genesis_hash,
                "bootstrap rejected by Rust: read-only trust state",
            ));
        }
        x if x
            == pb::bootstrap_measurement_report::TrustLevel::BootstrapTrustLevelBlocked as i32 =>
        {
            push_genesis_lifecycle_event(
                pb::genesis_lifecycle_event::Kind::GenesisKindError as i32,
                0,
            )?;
            return Ok(bootstrap_finalize_envelope(
                pb::bootstrap_finalize_response::Result::BootstrapResultBlocked as i32,
                device_id,
                genesis_hash,
                "bootstrap rejected by Rust: blocked trust state",
            ));
        }
        x if x
            == pb::bootstrap_measurement_report::TrustLevel::BootstrapTrustLevelUnspecified as i32 =>
        {
            push_genesis_lifecycle_event(
                pb::genesis_lifecycle_event::Kind::GenesisKindError as i32,
                0,
            )?;
            return Ok(bootstrap_finalize_envelope(
                pb::bootstrap_finalize_response::Result::BootstrapResultRejected as i32,
                device_id,
                genesis_hash,
                "bootstrap rejected by Rust: missing trust level",
            ));
        }
        _ => {}
    }

    let context = PlatformContext::bootstrap(RawPlatformInputs {
        device_id_raw: device_id.clone(),
        genesis_hash_raw: genesis_hash.clone(),
        cdbrw_hw_entropy: report.cdbrw_hw_entropy.clone(),
        cdbrw_env_fingerprint: report.cdbrw_env_fingerprint.clone(),
        cdbrw_salt: report.cdbrw_salt.clone(),
    })
    .map_err(|e| {
        ingress_error(
            ERROR_CODE_PROCESSING_FAILED,
            format!("bootstrap_finalize: PlatformContext::bootstrap failed: {e}"),
        )
    })?;

    #[cfg(target_os = "android")]
    crate::jni::cdbrw::set_cdbrw_binding_key(context.cdbrw_binding.to_vec());

    if let Err(error) = startup_initialize_identity_context(
        context.device_id.to_vec(),
        context.genesis_hash.to_vec(),
        context.cdbrw_binding.to_vec(),
    ) {
        log::error!(
            "FLASH_DEBUG: FINALIZE_BOOTSTRAP: startup_initialize_identity_context FAILED err={} BOOTSTRAP_SECURING={} SDK_READY={} has_id={}",
            error.message,
            crate::sdk::session_manager::BOOTSTRAP_SECURING.load(std::sync::atomic::Ordering::SeqCst),
            crate::sdk::session_manager::SDK_READY.load(std::sync::atomic::Ordering::SeqCst),
            crate::sdk::app_state::AppState::get_has_identity()
        );
        let _ = push_genesis_lifecycle_event(
            pb::genesis_lifecycle_event::Kind::GenesisKindError as i32,
            0,
        );
        return Ok(bootstrap_finalize_envelope(
            pb::bootstrap_finalize_response::Result::BootstrapResultError as i32,
            device_id,
            genesis_hash,
            error.message,
        ));
    }

    // CRITICAL EVIDENCE POINT: at this moment, startup_initialize_identity_context has
    // returned successfully, which means prime_identity_app_state has already stored
    // has_identity=true AND initialize_sdk_core has stored SDK_READY=true. The scope
    // guard is still holding BOOTSTRAP_SECURING=true. If compute_phase runs at this
    // exact instant it should return `securing_device` (not `wallet_ready` yet). The
    // scope guard drops only after we return from finalize_bootstrap_core below.
    log::info!(
        "FLASH_DEBUG: FINALIZE_BOOTSTRAP: IDENTITY_INSTALLED BOOTSTRAP_SECURING={} SDK_READY={} has_id={}",
        crate::sdk::session_manager::BOOTSTRAP_SECURING.load(std::sync::atomic::Ordering::SeqCst),
        crate::sdk::session_manager::SDK_READY.load(std::sync::atomic::Ordering::SeqCst),
        crate::sdk::app_state::AppState::get_has_identity()
    );

    push_genesis_lifecycle_event(
        pb::genesis_lifecycle_event::Kind::GenesisKindSecuringComplete as i32,
        0,
    )?;
    push_genesis_lifecycle_event(
        pb::genesis_lifecycle_event::Kind::GenesisKindOk as i32,
        0,
    )?;

    let ready_message = if report.trust_level
        == pb::bootstrap_measurement_report::TrustLevel::BootstrapTrustLevelPinRequired as i32
    {
        "bootstrap ready with degraded trust: PIN required"
    } else {
        "bootstrap ready"
    };

    Ok(bootstrap_finalize_envelope(
        pb::bootstrap_finalize_response::Result::BootstrapResultReady as i32,
        context.device_id.to_vec(),
        context.genesis_hash.to_vec(),
        ready_message,
    ))
}

fn handle_bootstrap_measurement_report_core(
    report: pb::BootstrapMeasurementReport,
) -> Result<Envelope, pb::Error> {
    match report.phase {
        x if x
            == pb::bootstrap_measurement_report::Phase::BootstrapPhaseStarted as i32 =>
        {
            // Mark that C-DBRW securing is in progress — session manager returns
            // "securing_device" phase until finalization completes.
            crate::sdk::session_manager::BOOTSTRAP_SECURING.store(true, std::sync::atomic::Ordering::SeqCst);
            push_genesis_lifecycle_event(
                pb::genesis_lifecycle_event::Kind::GenesisKindStarted as i32,
                0,
            )?;
            push_genesis_lifecycle_event(
                pb::genesis_lifecycle_event::Kind::GenesisKindSecuringDevice as i32,
                0,
            )?;
            Ok(bootstrap_finalize_envelope(
                pb::bootstrap_finalize_response::Result::BootstrapResultUnspecified as i32,
                report.device_id,
                report.genesis_hash,
                "bootstrap measurement started",
            ))
        }
        x if x
            == pb::bootstrap_measurement_report::Phase::BootstrapPhaseProgress as i32 =>
        {
            push_genesis_lifecycle_event(
                pb::genesis_lifecycle_event::Kind::GenesisKindSecuringProgress as i32,
                report.progress_percent,
            )?;
            Ok(bootstrap_finalize_envelope(
                pb::bootstrap_finalize_response::Result::BootstrapResultUnspecified as i32,
                report.device_id,
                report.genesis_hash,
                "bootstrap progress",
            ))
        }
        x if x == pb::bootstrap_measurement_report::Phase::BootstrapPhaseFinalize as i32
            || x
                == pb::bootstrap_measurement_report::Phase::BootstrapPhaseResumeFinalize as i32 =>
        {
            finalize_bootstrap_core(report)
        }
        x if x
            == pb::bootstrap_measurement_report::Phase::BootstrapPhaseAborted as i32 =>
        {
            push_genesis_lifecycle_event(
                pb::genesis_lifecycle_event::Kind::GenesisKindSecuringAborted as i32,
                0,
            )?;
            push_genesis_lifecycle_event(
                pb::genesis_lifecycle_event::Kind::GenesisKindError as i32,
                0,
            )?;
            Ok(bootstrap_finalize_envelope(
                pb::bootstrap_finalize_response::Result::BootstrapResultAborted as i32,
                report.device_id,
                report.genesis_hash,
                report.error_message,
            ))
        }
        x if x == pb::bootstrap_measurement_report::Phase::BootstrapPhaseError as i32 => {
            push_genesis_lifecycle_event(
                pb::genesis_lifecycle_event::Kind::GenesisKindError as i32,
                0,
            )?;
            Ok(bootstrap_finalize_envelope(
                pb::bootstrap_finalize_response::Result::BootstrapResultError as i32,
                report.device_id,
                report.genesis_hash,
                report.error_message,
            ))
        }
        _ => Err(ingress_error(
            ERROR_CODE_INVALID_INPUT,
            format!("bootstrap measurement: unsupported phase {}", report.phase),
        )),
    }
}

fn process_envelope_core(envelope_in: Envelope) -> Result<Envelope, pb::Error> {
    if let Some(pb::envelope::Payload::BootstrapMeasurementReport(report)) =
        envelope_in.payload.clone()
    {
        return handle_bootstrap_measurement_report_core(report);
    }

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

    Envelope::decode(payload).map_err(|e| {
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

    if method == "system.genesis" {
        let res = crate::handlers::handle_system_genesis_query(crate::bridge::AppQuery {
            path: method,
            params: args,
        });
        return if res.success {
            Ok(res.data)
        } else {
            Err(ingress_error(
                ERROR_CODE_PROCESSING_FAILED,
                res.error_message
                    .unwrap_or_else(|| "router_query_core failed".to_string()),
            ))
        };
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
    #[cfg(debug_assertions)]
    std::env::set_var("DSM_ALLOW_LOCALHOST", "1");
    Ok(startup_ok())
}

fn initialize_sdk_core() -> Result<Vec<u8>, pb::Error> {
    match crate::runtime::get_runtime().block_on(crate::init_dsm_sdk()) {
        Ok(()) => {
            crate::sdk::session_manager::set_sdk_ready(true);
            Ok(startup_ok())
        }
        Err(e) => {
            crate::sdk::session_manager::set_sdk_ready(false);
            Err(ingress_error(
                ERROR_CODE_NOT_READY,
                format!("startup: init_dsm_sdk failed: {e}"),
            ))
        }
    }
}

fn seed_public_key_for_app_state(device_id: &[u8]) -> Vec<u8> {
    let mut hasher = dsm::crypto::blake3::dsm_domain_hasher("DSM/device-key");
    hasher.update(device_id);
    let seed = hasher.finalize();
    seed.as_bytes()[0..32].to_vec()
}

fn prime_identity_app_state(device_id: &[u8], genesis_hash: &[u8]) {
    let public_key = seed_public_key_for_app_state(device_id);
    let smt_root = dsm::merkle::sparse_merkle_tree::empty_root(
        dsm::merkle::sparse_merkle_tree::DEFAULT_SMT_HEIGHT,
    )
    .to_vec();

    crate::sdk::app_state::AppState::set_identity_info(
        device_id.to_vec(),
        public_key,
        genesis_hash.to_vec(),
        smt_root,
    );
    crate::sdk::app_state::AppState::set_has_identity(true);
}

fn install_identity_context_core(
    device_id: Vec<u8>,
    genesis_hash: Vec<u8>,
    binding_key: Vec<u8>,
) -> Result<(), pb::Error> {
    if device_id.len() != 32 {
        return Err(ingress_error(
            ERROR_CODE_INVALID_INPUT,
            format!("startup: device_id must be 32 bytes, got {}", device_id.len()),
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
    if binding_key.len() != 32 {
        return Err(ingress_error(
            ERROR_CODE_INVALID_INPUT,
            format!(
                "startup: binding_key must be 32 bytes, got {}",
                binding_key.len()
            ),
        ));
    }

    crate::install_canonical_binding_key(binding_key.clone()).map_err(|e| {
        ingress_error(
            ERROR_CODE_INVALID_INPUT,
            format!("startup: invalid binding key: {e}"),
        )
    })?;
    #[cfg(target_os = "android")]
    crate::jni::cdbrw::set_cdbrw_binding_key(binding_key.clone());

    prime_identity_app_state(&device_id, &genesis_hash);

    let entropy = crate::derive_production_entropy(&device_id, &genesis_hash, &binding_key);
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
    binding_key: Vec<u8>,
) -> Result<Vec<u8>, pb::Error> {
    install_identity_context_core(device_id, genesis_hash, binding_key)?;
    initialize_sdk_core()
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
                let env_in = Envelope::decode(slice).map_err(|e| {
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
            initialize_identity_context_core(op.device_id, op.genesis_hash, op.binding_key)
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
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use once_cell::sync::Lazy;

    use crate::bridge::{install_app_router, AppInvoke, AppQuery, AppResult, AppRouter};

    static TEST_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    struct TestRouter;

    #[async_trait]
    impl AppRouter for TestRouter {
        async fn query(&self, q: AppQuery) -> AppResult {
            AppResult {
                success: true,
                data: format!("query:{}:{}", q.path, q.params.len()).into_bytes(),
                error_message: None,
            }
        }

        async fn invoke(&self, i: AppInvoke) -> AppResult {
            AppResult {
                success: true,
                data: format!("invoke:{}:{}", i.method, i.args.len()).into_bytes(),
                error_message: None,
            }
        }
    }

    fn ensure_test_env_config() -> String {
        let path = crate::network::get_env_config_path()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("dsm_ingress_startup_test_env.toml"));
        let body = r#"
protocol = "http"
lan_ip = "127.0.0.1"
allow_localhost = true

[[nodes]]
name = "test-1"
endpoint = "http://127.0.0.1:8080"
"#;
        std::fs::write(&path, body).expect("write env config");
        path.to_string_lossy().to_string()
    }

    fn setup_test_env() -> std::sync::MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("DSM_SDK_TEST_MODE", "1");
        let storage_base = crate::storage_utils::get_storage_base_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("./.dsm_testdata"));
        let _ = crate::storage_utils::set_storage_base_dir(storage_base);
        crate::sdk::app_state::AppState::reset_for_testing();
        crate::sdk::app_state::AppState::prime_memory_for_testing();
        crate::sdk::session_manager::set_sdk_ready(false);
        crate::reset_sdk_context_for_testing();
        unsafe { crate::bridge::reset_bridge_handlers_for_tests() };
        let config_path = ensure_test_env_config();
        let _ = dispatch_startup(StartupRequest {
            operation: Some(startup_request::Operation::ConfigureEnv(pb::ConfigureEnvOp {
                config_path_utf8: config_path,
            })),
        });
        guard
    }

    fn expect_ok_bytes(response: IngressResponse) -> Vec<u8> {
        match response.result {
            Some(ingress_response::Result::OkBytes(bytes)) => bytes,
            other => panic!("expected ok bytes, got {:?}", other),
        }
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
    fn dispatch_ingress_empty_request_returns_invalid_input() {
        let _guard = setup_test_env();
        let response = dispatch_ingress(IngressRequest { operation: None });
        let error = expect_error(response);
        assert_eq!(error.code, ERROR_CODE_INVALID_INPUT);
        assert!(error.message.contains("empty IngressRequest"));
    }

    #[test]
    fn dispatch_ingress_bytes_invalid_proto_returns_invalid_input() {
        let _guard = setup_test_env();
        let response_bytes = dispatch_ingress_bytes(&[0xff, 0xfe, 0xfd]);
        let response = IngressResponse::decode(response_bytes.as_slice()).expect("decode response");
        let error = expect_error(response);
        assert_eq!(error.code, ERROR_CODE_INVALID_INPUT);
    }

    #[test]
    fn envelope_request_strips_optional_prefix_and_reframes_success_output() {
        let _guard = setup_test_env();
        let request_env = Envelope {
            version: 3,
            message_id: vec![7; 16],
            payload: Some(pb::envelope::Payload::Error(pb::Error {
                code: 99,
                message: "request already a response".to_string(),
                context: Vec::new(),
                source_tag: 0,
                is_recoverable: false,
                debug_b32: String::new(),
            })),
            ..Default::default()
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
        let decoded = Envelope::decode(&ok_bytes[1..]).expect("decode framed envelope");
        assert_eq!(decoded.version, 3);
    }

    #[test]
    fn malformed_envelope_returns_invalid_input() {
        let _guard = setup_test_env();
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
    fn router_query_success_returns_router_payload() {
        let _guard = setup_test_env();
        install_app_router(Arc::new(TestRouter)).expect("install router");

        let response = dispatch_ingress(IngressRequest {
            operation: Some(ingress_request::Operation::RouterQuery(pb::RouterQueryOp {
                method: "wallet.balance".to_string(),
                args: vec![1, 2, 3],
            })),
        });
        let ok_bytes = expect_ok_bytes(response);
        assert_eq!(ok_bytes, b"query:wallet.balance:3".to_vec());
    }

    #[test]
    fn router_invoke_success_returns_router_payload() {
        let _guard = setup_test_env();
        install_app_router(Arc::new(TestRouter)).expect("install router");

        let response = dispatch_ingress(IngressRequest {
            operation: Some(ingress_request::Operation::RouterInvoke(
                pb::RouterInvokeOp {
                    method: "wallet.send".to_string(),
                    args: vec![9, 8],
                },
            )),
        });
        let ok_bytes = expect_ok_bytes(response);
        assert_eq!(ok_bytes, b"invoke:wallet.send:2".to_vec());
    }

    #[test]
    fn router_absent_maps_to_not_ready() {
        let _guard = setup_test_env();
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
    fn hardware_facts_success_returns_envelope_wrapped_snapshot() {
        let _guard = setup_test_env();
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
        let envelope = Envelope::decode(&ok_bytes[1..]).expect("decode snapshot envelope");
        match envelope.payload {
            Some(pb::envelope::Payload::SessionStateResponse(snapshot)) => {
                let hardware = snapshot.hardware_status.expect("hardware status");
                assert!(hardware.app_foreground);
            }
            other => panic!("expected SessionStateResponse, got {:?}", other),
        }
    }

    #[test]
    fn startup_empty_request_returns_invalid_input() {
        let _guard = setup_test_env();
        let response = dispatch_startup(StartupRequest { operation: None });
        let error = expect_startup_error(response);
        assert_eq!(error.code, ERROR_CODE_INVALID_INPUT);
        assert!(error.message.contains("empty StartupRequest"));
    }

    #[test]
    fn startup_set_storage_base_dir_is_idempotent() {
        let _guard = setup_test_env();
        let path_utf8 = crate::storage_utils::get_storage_base_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("./.dsm_testdata"))
            .to_string_lossy()
            .to_string();
        let request = StartupRequest {
            operation: Some(startup_request::Operation::SetStorageBaseDir(
                pb::SetStorageBaseDirOp {
                    path_utf8,
                },
            )),
        };
        assert_eq!(expect_startup_ok(dispatch_startup(request.clone())), STARTUP_OK_BYTES);
        assert_eq!(expect_startup_ok(dispatch_startup(request)), STARTUP_OK_BYTES);
    }

    #[test]
    fn startup_initialize_sdk_installs_minimal_router() {
        let _guard = setup_test_env();
        let response = dispatch_startup(StartupRequest {
            operation: Some(startup_request::Operation::InitializeSdk(
                pb::InitializeSdkOp {},
            )),
        });
        assert_eq!(expect_startup_ok(response), STARTUP_OK_BYTES);
        assert!(crate::sdk::session_manager::SDK_READY.load(std::sync::atomic::Ordering::SeqCst));

        let response = dispatch_ingress(IngressRequest {
            operation: Some(ingress_request::Operation::RouterQuery(pb::RouterQueryOp {
                method: "sys.tick".to_string(),
                args: Vec::new(),
            })),
        });
        let ok_bytes = expect_ok_bytes(response);
        assert!(!ok_bytes.is_empty());
    }

    #[test]
    fn startup_minimal_router_routes_system_genesis_validation() {
        let _guard = setup_test_env();
        let response = dispatch_startup(StartupRequest {
            operation: Some(startup_request::Operation::InitializeSdk(
                pb::InitializeSdkOp {},
            )),
        });
        assert_eq!(expect_startup_ok(response), STARTUP_OK_BYTES);

        let args = pb::ArgPack {
            schema_hash: None,
            codec: pb::Codec::Proto as i32,
            body: pb::SystemGenesisRequest {
                locale: "en-US".to_string(),
                network_id: "testnet".to_string(),
                device_entropy: vec![0x42; 8],
            }
            .encode_to_vec(),
        }
        .encode_to_vec();

        let response = dispatch_ingress(IngressRequest {
            operation: Some(ingress_request::Operation::RouterQuery(pb::RouterQueryOp {
                method: "system.genesis".to_string(),
                args,
            })),
        });
        let error = expect_error(response);
        assert_eq!(error.code, ERROR_CODE_PROCESSING_FAILED);
        assert!(error.message.contains("device_entropy must be 32 bytes"));
        assert!(!error.message.contains("requires genesis"));
    }

    #[test]
    fn startup_initialize_identity_context_sets_binding_key_and_router() {
        let _guard = setup_test_env();
        install_identity_context_core(vec![0x11; 32], vec![0x22; 32], vec![0x33; 32])
            .expect("identity context install should succeed");
        assert_eq!(
            crate::fetch_dbrw_binding_key().expect("binding key"),
            vec![0x33; 32]
        );
        assert!(crate::is_sdk_context_initialized());
    }

    #[test]
    fn startup_initialize_identity_context_rejects_short_binding_key() {
        let _guard = setup_test_env();
        let response = dispatch_startup(StartupRequest {
            operation: Some(startup_request::Operation::InitializeIdentityContext(
                pb::InitializeIdentityContextOp {
                    device_id: vec![0x11; 32],
                    genesis_hash: vec![0x22; 32],
                    binding_key: vec![0x33; 8],
                },
            )),
        });
        let error = expect_startup_error(response);
        assert_eq!(error.code, ERROR_CODE_INVALID_INPUT);
        assert!(error.message.contains("binding_key must be 32 bytes"));
    }
}
