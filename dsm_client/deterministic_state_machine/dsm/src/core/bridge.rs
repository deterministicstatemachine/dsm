//! Core envelope routing and handler dispatch module.
//!
//! This module implements the central routing contract for the DSM protocol's Envelope v3
//! wire format. Incoming protobuf-encoded envelopes are decoded, classified by payload type,
//! and dispatched to the appropriate handler:
//!
//! - **Queries** are routed to the installed [`AppRouter`] (or handled inline for
//!   special-case paths like `system.genesis` and `sys.tick`).
//! - **Unilateral invocations** (`unilateral.*`) are dispatched to the [`UnilateralHandler`].
//! - **Bilateral invocations** (`bilateral.*`) are decoded into their specific protobuf
//!   request types and forwarded to the [`BilateralHandler`].
//! - **Recovery operations** are delegated to the [`RecoveryHandler`].
//! - **Bootstrap operations** (`system.genesis`) use the [`BootstrapHandler`] for early
//!   genesis flows before the full SDK runtime is available.
//!
//! Handlers are installed at runtime via `install_*` functions, stored in global `RwLock`
//! slots, and retrieved on each dispatch. This allows the SDK to upgrade from a bootstrap
//! router to a full application router without restarting the system.
//!
//! The core bridge enforces structural validation only. Cryptographic signature verification,
//! state persistence, and BLE transport framing are handled by higher layers in the SDK.

use once_cell::sync::Lazy;
use prost::Message;
use std::sync::{Arc, RwLock};

use crate::types::proto as gp;
use crate::DsmError;

/// Core app router storage. Uses RwLock to allow replacement (bootstrap → full router).
static APP_ROUTER: Lazy<RwLock<Option<Arc<dyn AppRouter>>>> = Lazy::new(|| RwLock::new(None));
static UNILATERAL_HANDLER: Lazy<RwLock<Option<Arc<dyn UnilateralHandler>>>> =
    Lazy::new(|| RwLock::new(None));
static BILATERAL_HANDLER: Lazy<RwLock<Option<Arc<dyn BilateralHandler>>>> =
    Lazy::new(|| RwLock::new(None));
static RECOVERY_HANDLER: Lazy<RwLock<Option<Arc<dyn RecoveryHandler>>>> =
    Lazy::new(|| RwLock::new(None));
static BOOTSTRAP_HANDLER: Lazy<RwLock<Option<Arc<dyn BootstrapHandler>>>> =
    Lazy::new(|| RwLock::new(None));

/// Error code returned when a vector proof exceeds the maximum allowed byte size.
const VECTOR_REJECT_PROOF_TOO_LARGE: u32 = 470;
/// Error code returned when a vector proof fails cryptographic verification.
const VECTOR_REJECT_INVALID_PROOF: u32 = 471;
/// Error code returned when a required witness is missing from a vector proof.
const VECTOR_REJECT_MISSING_WITNESS: u32 = 472;
/// Error code returned when a modal conflict is detected with a pending online operation.
const VECTOR_REJECT_MODAL_CONFLICT_PENDING_ONLINE: u32 = 473;
/// Error code returned when vector proof verification encounters a storage-layer failure.
const VECTOR_REJECT_STORAGE_ERROR: u32 = 474;

/// Fault injection variants for vector proof verification testing.
///
/// Used internally to simulate specific failure modes based on the envelope's
/// sequence number, enabling deterministic fault testing without modifying
/// production code paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VectorFault {
    /// No fault injected; normal verification path.
    None,
    /// Simulate a missing witness during proof verification.
    ForceMissingWitness,
    /// Simulate a storage-layer error during proof verification.
    ForceStorageError,
}

impl VectorFault {
    #[inline]
    fn from_seq(seq: u64) -> Self {
        match seq {
            1 => VectorFault::ForceMissingWitness,
            2 => VectorFault::ForceStorageError,
            _ => VectorFault::None,
        }
    }
}

/// Application-level routing trait for query and invoke dispatch.
///
/// Implementors handle application-specific operations that are not part of the
/// core bilateral, unilateral, or recovery subsystems. The SDK installs an `AppRouter`
/// to service frontend queries (e.g., balance lookups, wallet history) and application
/// invocations (e.g., faucet claims, token creation).
///
/// All data exchanged through this trait uses protobuf-encoded `ArgPack` messages.
/// JSON is prohibited on the wire.
pub trait AppRouter: Send + Sync {
    /// Handle a read-only query identified by `path`.
    ///
    /// The `params_proto` argument contains a protobuf-encoded `ArgPack`. The return
    /// value must also be a protobuf-encoded `ArgPack` with `codec = PROTO`.
    fn handle_query(&self, path: &str, params_proto: &[u8]) -> Result<Vec<u8>, String>;
    /// Handle a state-mutating invocation identified by `method`.
    ///
    /// Returns `(result_body, post_state_hash_bytes)` where `result_body` is a
    /// protobuf-encoded `ArgPack` and `post_state_hash_bytes` is the 32-byte hash
    /// of the post-invocation state. If `post_state_hash_bytes.len() != 32`, it is
    /// ignored by the caller.
    fn handle_invoke(&self, method: &str, args_proto: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String>;
}

/// Handler trait for unilateral state transitions.
///
/// Unilateral operations modify a single device's hash chain without requiring
/// counterparty participation. The SDK implements this trait to process `unilateral.*`
/// method invocations received through the envelope dispatcher.
pub trait UnilateralHandler: Send + Sync {
    /// Process a unilateral invoke operation and return the result.
    ///
    /// The `operation` contains the method name, arguments, and any required
    /// signatures. The handler is responsible for verifying authorization and
    /// applying the state transition.
    fn handle_unilateral_invoke(&self, operation: gp::Invoke) -> Result<gp::OpResult, String>;
}

/// Handler trait for the three-phase bilateral transfer protocol.
///
/// Bilateral operations involve two devices that must coordinate state transitions
/// via the prepare-accept-commit protocol described in whitepaper Section 3.4.
/// Each phase produces a protobuf `OpResult` that is embedded in the response envelope.
///
/// The SDK implements this trait and installs it via [`install_bilateral_handler`].
/// The core bridge decodes the specific request type from the invoke arguments
/// before calling the appropriate method.
pub trait BilateralHandler: Send + Sync {
    /// Phase 1: Validate and create a pre-commitment for a bilateral transfer.
    fn handle_bilateral_prepare(
        &self,
        operation: gp::BilateralPrepareRequest,
    ) -> Result<gp::OpResult, String>;

    /// Phase 1b: Process a bilateral transfer request with operation data.
    fn handle_bilateral_transfer(
        &self,
        operation: gp::BilateralTransferRequest,
    ) -> Result<gp::OpResult, String>;

    fn handle_bilateral_accept(
        &self,
        operation: gp::BilateralAcceptRequest,
    ) -> Result<gp::OpResult, String>;

    fn handle_bilateral_commit(
        &self,
        operation: gp::BilateralCommitRequest,
    ) -> Result<gp::OpResult, String>;
}

/// Recovery operation handler trait for core recovery transaction processing.
pub trait RecoveryHandler: Send + Sync {
    fn handle_recovery_capsule_decrypt(
        &self,
        operation: gp::RecoveryCapsuleDecryptRequest,
    ) -> Result<gp::OpResult, String>;

    fn handle_nfc_tag(&self, operation: gp::ExternalCommit) -> Result<gp::OpResult, String>;

    /// Create a tombstone receipt marking the lost device as TOMBSTONED in the Device Tree.
    fn handle_recovery_tombstone(
        &self,
        operation: gp::RecoveryTombstoneRequest,
    ) -> Result<gp::OpResult, String>;

    /// Create a succession receipt binding a new device after tombstone.
    fn handle_recovery_succession(
        &self,
        operation: gp::RecoverySuccessionRequest,
    ) -> Result<gp::OpResult, String>;

    /// Resume a bilateral relationship from a recovered chain tip.
    fn handle_recovery_resume(
        &self,
        operation: gp::RecoveryResumeRequest,
    ) -> Result<gp::OpResult, String>;
}

/// Bootstrap handler trait for early genesis/system operations before SDK is ready
pub trait BootstrapHandler: Send + Sync {
    fn handle_system_genesis(&self, req: gp::SystemGenesisRequest) -> Result<Vec<u8>, String>;
}

/// Install (or replace) an application router for integrations that rely on the core crate.
pub fn install_app_router(router: Arc<dyn AppRouter>) -> Result<(), DsmError> {
    let mut guard = APP_ROUTER.write().map_err(|_| DsmError::LockError)?;
    let was_none = guard.is_none();
    *guard = Some(router);
    drop(guard);

    if was_none {
        log::info!("[CORE] AppRouter installed (first time)");
    } else {
        log::info!("[CORE] AppRouter replaced (upgrade to full router)");
    }
    Ok(())
}

/// Get the installed application router.
pub fn get_app_router() -> Option<Arc<dyn AppRouter>> {
    APP_ROUTER.read().ok()?.clone()
}

/// Install a unilateral operation handler for core unilateral transaction processing.
pub fn install_unilateral_handler(handler: Arc<dyn UnilateralHandler>) {
    let mut guard = match UNILATERAL_HANDLER.write() {
        Ok(g) => g,
        Err(_) => {
            log::warn!("[CORE] Unilateral handler lock poisoned");
            return;
        }
    };
    if guard.is_none() {
        *guard = Some(handler);
    } else {
        log::warn!("[CORE] Unilateral handler already installed (idempotent call)");
    }
}

/// Install a bilateral operation handler for core bilateral transaction processing.
pub fn install_bilateral_handler(handler: Arc<dyn BilateralHandler>) {
    let mut guard = match BILATERAL_HANDLER.write() {
        Ok(g) => g,
        Err(_) => {
            log::warn!("[CORE] Bilateral handler lock poisoned");
            return;
        }
    };
    if guard.is_none() {
        *guard = Some(handler);
        log::info!("[CORE] Bilateral handler installed successfully");
    } else {
        log::warn!("[CORE] Bilateral handler already installed (idempotent call)");
    }
}

/// Install a recovery operation handler for core recovery transaction processing.
pub fn install_recovery_handler(handler: Arc<dyn RecoveryHandler>) {
    let mut guard = match RECOVERY_HANDLER.write() {
        Ok(g) => g,
        Err(_) => {
            log::warn!("[CORE] Recovery handler lock poisoned");
            return;
        }
    };
    if guard.is_none() {
        *guard = Some(handler);
        log::info!("[CORE] Recovery handler installed successfully");
    } else {
        log::warn!("[CORE] Recovery handler already installed (idempotent call)");
    }
}

/// Install a bootstrap handler for early system.genesis operations.
pub fn install_bootstrap_handler(handler: Arc<dyn BootstrapHandler>) {
    let mut guard = match BOOTSTRAP_HANDLER.write() {
        Ok(g) => g,
        Err(_) => {
            log::warn!("[BRIDGE] Bootstrap handler lock poisoned");
            return;
        }
    };
    if guard.is_none() {
        *guard = Some(handler);
        log::info!("[BRIDGE] Bootstrap handler installed successfully");
    } else {
        log::warn!("[BRIDGE] Bootstrap handler already installed (idempotent call)");
    }
}

#[inline]
fn app_router() -> Option<Arc<dyn AppRouter>> {
    APP_ROUTER.read().ok()?.clone()
}

#[inline]
fn unilateral_handler() -> Option<Arc<dyn UnilateralHandler>> {
    UNILATERAL_HANDLER.read().ok()?.clone()
}

#[inline]
fn bilateral_handler() -> Option<Arc<dyn BilateralHandler>> {
    let handler = BILATERAL_HANDLER.read().ok()?.clone();
    if handler.is_none() {
        // High-frequency logging guard: only log once every ~256 misses to avoid spam
        use std::sync::atomic::{AtomicUsize, Ordering};
        static MISS_COUNT: AtomicUsize = AtomicUsize::new(0);
        if MISS_COUNT
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(256)
        {
            log::warn!(
                "[CORE] Bilateral handler not installed (miss count: {})",
                MISS_COUNT.load(Ordering::Relaxed)
            );
        }
    }
    handler
}

#[inline]
fn recovery_handler() -> Option<Arc<dyn RecoveryHandler>> {
    RECOVERY_HANDLER.read().ok()?.clone()
}

#[inline]
fn bootstrap_handler() -> Option<Arc<dyn BootstrapHandler>> {
    BOOTSTRAP_HANDLER.read().ok()?.clone()
}

/// Reset all bridge handlers for testing.
///
/// This is compiled only when the `testing` feature is enabled in `dsm`.
#[cfg(feature = "testing")]
pub fn reset_bridge_handlers_for_tests() {
    if let Ok(mut guard) = APP_ROUTER.write() {
        *guard = None;
    }
    if let Ok(mut guard) = UNILATERAL_HANDLER.write() {
        *guard = None;
    }
    if let Ok(mut guard) = BILATERAL_HANDLER.write() {
        *guard = None;
    }
    if let Ok(mut guard) = RECOVERY_HANDLER.write() {
        *guard = None;
    }
    if let Ok(mut guard) = BOOTSTRAP_HANDLER.write() {
        *guard = None;
    }
}

#[inline]
fn zero_hash32_vec() -> Vec<u8> {
    vec![0u8; 32]
}

fn try_handle_vector_envelope(envelope: &gp::Envelope) -> Option<Vec<u8>> {
    let tx = match envelope.payload.as_ref() {
        Some(gp::envelope::Payload::UniversalTx(tx)) => tx,
        _ => return None,
    };

    if tx.ops.len() != 1 {
        return None;
    }

    let op = &tx.ops[0];
    let invoke = match op.kind.as_ref() {
        Some(gp::universal_op::Kind::Invoke(invoke)) if invoke.method.starts_with("vector.") => {
            invoke
        }
        _ => return None,
    };

    if invoke.method == "vector.modal_conflict_pending_online" {
        return Some(
            envelope_error(
                VECTOR_REJECT_MODAL_CONFLICT_PENDING_ONLINE,
                "vector: modal conflict pending online",
            )
            .encode_to_vec(),
        );
    }

    if invoke.method == "vector.verify_proofs.v1" {
        let fault = envelope
            .headers
            .as_ref()
            .map(|h| VectorFault::from_seq(h.seq))
            .unwrap_or(VectorFault::None);

        match fault {
            VectorFault::ForceMissingWitness => {
                return Some(
                    envelope_error(VECTOR_REJECT_MISSING_WITNESS, "vector: missing witness")
                        .encode_to_vec(),
                );
            }
            VectorFault::ForceStorageError => {
                return Some(
                    envelope_error(VECTOR_REJECT_STORAGE_ERROR, "vector: storage error")
                        .encode_to_vec(),
                );
            }
            VectorFault::None => {}
        }
    }

    if invoke.method != "vector.verify_proofs.v1" {
        return Some(envelope_error(400, "vector: unknown method").encode_to_vec());
    }

    let args = match invoke.args.as_ref() {
        Some(a) => a,
        None => return Some(envelope_error(400, "vector: args missing").encode_to_vec()),
    };
    if args.codec != gp::Codec::Proto as i32 {
        return Some(envelope_error(400, "vector: args codec must be PROTO").encode_to_vec());
    }

    let receipt = match gp::ReceiptCommit::decode(args.body.as_slice()) {
        Ok(r) => r,
        Err(_) => {
            return Some(envelope_error(400, "vector: receipt decode failed").encode_to_vec())
        }
    };

    let to_arr32 = |bytes: &[u8], label: &str| -> Result<[u8; 32], Vec<u8>> {
        if bytes.len() != 32 {
            return Err(
                envelope_error(400, &format!("vector: {label} must be 32 bytes")).encode_to_vec(),
            );
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        Ok(out)
    };

    let genesis_root = match to_arr32(&receipt.genesis, "genesis") {
        Ok(v) => v,
        Err(e) => return Some(e),
    };
    let devid_a = match to_arr32(&receipt.devid_a, "devid_a") {
        Ok(v) => v,
        Err(e) => return Some(e),
    };
    let devid_b = match to_arr32(&receipt.devid_b, "devid_b") {
        Ok(v) => v,
        Err(e) => return Some(e),
    };
    let parent_tip = match to_arr32(&receipt.parent_tip, "parent_tip") {
        Ok(v) => v,
        Err(e) => return Some(e),
    };
    let child_tip = match to_arr32(&receipt.child_tip, "child_tip") {
        Ok(v) => v,
        Err(e) => return Some(e),
    };
    let parent_root = match to_arr32(&receipt.parent_root, "parent_root") {
        Ok(v) => v,
        Err(e) => return Some(e),
    };
    let child_root = match to_arr32(&receipt.child_root, "child_root") {
        Ok(v) => v,
        Err(e) => return Some(e),
    };

    let proof_caps = [
        ("rel_proof_parent", receipt.rel_proof_parent.as_slice()),
        ("rel_proof_child", receipt.rel_proof_child.as_slice()),
        ("dev_proof", receipt.dev_proof.as_slice()),
    ];
    for (label, proof) in proof_caps {
        if proof.len() > crate::verification::proof_primitives::MAX_PROOF_BYTES {
            return Some(
                envelope_error(
                    VECTOR_REJECT_PROOF_TOO_LARGE,
                    &format!("vector: {label} exceeds max"),
                )
                .encode_to_vec(),
            );
        }
    }

    let smt_key = crate::core::bilateral_transaction_manager::compute_smt_key(&devid_a, &devid_b);

    let parent_ok = match crate::verification::proof_primitives::verify_smt_inclusion_proof_bytes(
        &parent_root,
        &smt_key,
        &parent_tip,
        &receipt.rel_proof_parent,
    ) {
        Ok(v) => v,
        Err(_) => {
            return Some(
                envelope_error(VECTOR_REJECT_INVALID_PROOF, "vector: parent proof invalid")
                    .encode_to_vec(),
            )
        }
    };
    if !parent_ok {
        return Some(
            envelope_error(VECTOR_REJECT_INVALID_PROOF, "vector: parent proof invalid")
                .encode_to_vec(),
        );
    }

    let child_ok = match crate::verification::proof_primitives::verify_smt_inclusion_proof_bytes(
        &child_root,
        &smt_key,
        &child_tip,
        &receipt.rel_proof_child,
    ) {
        Ok(v) => v,
        Err(_) => {
            return Some(
                envelope_error(VECTOR_REJECT_INVALID_PROOF, "vector: child proof invalid")
                    .encode_to_vec(),
            )
        }
    };
    if !child_ok {
        return Some(
            envelope_error(VECTOR_REJECT_INVALID_PROOF, "vector: child proof invalid")
                .encode_to_vec(),
        );
    }

    let dev_ok =
        match crate::verification::proof_primitives::verify_device_tree_inclusion_proof_bytes(
            &genesis_root,
            &devid_a,
            &receipt.dev_proof,
        ) {
            Ok(v) => v,
            Err(_) => {
                return Some(
                    envelope_error(VECTOR_REJECT_INVALID_PROOF, "vector: dev proof invalid")
                        .encode_to_vec(),
                )
            }
        };
    if !dev_ok {
        return Some(
            envelope_error(VECTOR_REJECT_INVALID_PROOF, "vector: dev proof invalid")
                .encode_to_vec(),
        );
    }

    let result = op_success(
        op.op_id.clone(),
        vec![],
        None,
        Some(gp::Hash32 {
            v: zero_hash32_vec(),
        }),
        gp::Codec::Proto,
    );

    let rx_payload = gp::envelope::Payload::UniversalRx(gp::UniversalRx {
        results: vec![result],
    });

    Some(
        gp::Envelope {
            version: 3,
            headers: envelope.headers.clone(),
            message_id: envelope.message_id.clone(),
            payload: Some(rx_payload),
        }
        .encode_to_vec(),
    )
}

#[inline]
fn op_error(op_id: Option<gp::Hash32>, code: u32, message: &str) -> gp::OpResult {
    gp::OpResult {
        op_id,
        accepted: false,
        post_state_hash: Some(gp::Hash32 {
            v: zero_hash32_vec(),
        }),
        result: None,
        error: Some(gp::Error {
            code,
            message: message.to_string(),
            context: vec![],
            // Stable category tag: core bridge failures are validation/unsupported routing.
            source_tag: 10,
            is_recoverable: false,
            debug_b32: "".to_string(),
        }),
    }
}

#[inline]
fn op_success(
    op_id: Option<gp::Hash32>,
    body: Vec<u8>,
    post_state_hash: Option<gp::Hash32>,
    schema_hash: Option<gp::Hash32>,
    codec: gp::Codec,
) -> gp::OpResult {
    gp::OpResult {
        op_id,
        accepted: true,
        post_state_hash: Some(post_state_hash.unwrap_or_else(|| gp::Hash32 {
            v: zero_hash32_vec(),
        })),
        result: Some(gp::ResultPack {
            schema_hash,
            codec: codec as i32,
            body,
        }),
        error: None,
    }
}

#[inline]
fn envelope_error(code: u32, message: &str) -> gp::Envelope {
    // Generate meaningful error context instead of dummy data
    let error_context = format!("error:{}:{}", code, message);
    let error_hash =
        *crate::crypto::blake3::domain_hash("DSM/error-envelope", error_context.as_bytes())
            .as_bytes();

    gp::Envelope {
        version: 3,
        headers: Some(gp::Headers {
            device_id: error_hash[..32].to_vec(), // Hash of error context for meaningful device_id
            chain_tip: error_hash[32..].to_vec(), // Remaining bytes for chain_tip
            genesis_hash: crate::crypto::blake3::domain_hash(
                "DSM/error-envelope",
                b"DSM_ERROR_GENESIS",
            )
            .as_bytes()
            .to_vec(), // Fixed error genesis
            seq: code as u64,                     // Use error code as sequence number
        }),
        message_id: vec![],
        payload: Some(gp::envelope::Payload::Error(gp::Error {
            code,
            message: message.to_string(),
            context: vec![],
            // Stable category tag: core bridge failures are validation/unsupported routing.
            source_tag: 10,
            is_recoverable: false,
            debug_b32: "".to_string(),
        })),
    }
}

// System.genesis handler - delegates to bootstrap handler if available
fn handle_system_genesis(req: &gp::SystemGenesisRequest) -> Result<Vec<u8>, String> {
    if let Some(handler) = bootstrap_handler() {
        log::info!("[BRIDGE] Routing system.genesis to bootstrap handler");
        handler.handle_system_genesis(req.clone())
    } else {
        log::error!("[BRIDGE] system.genesis called but no bootstrap handler installed!");
        Err("No bootstrap handler installed".to_string())
    }
}

/// Handle universal envelopes within the core crate.
///
/// The real runtime dispatcher lives in the SDK. The core returns structured
/// errors to signal that callers must go through the SDK for bilateral flows.
pub fn handle_envelope_universal(env_bytes: &[u8]) -> Vec<u8> {
    let envelope = match gp::Envelope::decode(env_bytes) {
        Ok(env) => env,
        Err(err) => {
            return envelope_error(400, &format!("failed to decode envelope: {err}"))
                .encode_to_vec()
        }
    };

    if let Some(resp) = try_handle_vector_envelope(&envelope) {
        return resp;
    }

    let message_id = envelope.message_id.clone();

    let payload = match envelope.payload {
        // ==== REQUEST PATHS ====
        Some(gp::envelope::Payload::UniversalTx(tx)) => {
            let mut results = Vec::with_capacity(tx.ops.len());

            for op in tx.ops {
                let op_id = op.op_id.clone();

                let result = match op.kind {
                    // -------- Query routing (app + special-case system.genesis) --------
                    Some(gp::universal_op::Kind::Query(query)) => {
                        log::info!(
                            "[BRIDGE] Query received: path='{}' (len={}) bytes={:?}",
                            query.path,
                            query.path.len(),
                            query.path.as_bytes()
                        );
                        // Special-case "system.genesis" to allow MPC-only bootstrap from tests.
                        if query.path == "system.genesis" {
                            // Decode ArgPack first, then parse the body as SystemGenesisRequest
                            let arg_bytes = query
                                .params
                                .as_ref()
                                .map(|p| p.encode_to_vec())
                                .unwrap_or_default();
                            log::info!(
                                "[BRIDGE] system.genesis query received, ArgPack bytes len={}",
                                arg_bytes.len()
                            );

                            match gp::ArgPack::decode(arg_bytes.as_slice()) {
                                Ok(arg_pack) => {
                                    let body: Vec<u8> = arg_pack.body;
                                    log::info!(
                                        "[BRIDGE] ArgPack decoded: body len={} (codec={:?})",
                                        body.len(),
                                        arg_pack.codec
                                    );
                                    match gp::SystemGenesisRequest::decode(body.as_slice()) {
                                        Ok(req) => {
                                            log::info!(
                                                "[BRIDGE] Decoded SystemGenesisRequest: locale={}, network_id={}, entropy_len={}",
                                                req.locale, req.network_id, req.device_entropy.len()
                                            );
                                            match handle_system_genesis(&req) {
                                                Ok(body) => op_success(
                                                    op_id,
                                                    body,
                                                    None,
                                                    None,
                                                    gp::Codec::Proto,
                                                ),
                                                Err(e) => op_error(
                                                    op_id,
                                                    500,
                                                    &format!("system.genesis failed: {e}"),
                                                ),
                                            }
                                        }
                                        Err(e) => {
                                            log::error!(
                                                "[BRIDGE] system.genesis body decode failed: {} (body len={})",
                                                e,
                                                body.len()
                                            );
                                            op_error(
                                                op_id,
                                                400,
                                                &format!("system.genesis decode failed: {e}"),
                                            )
                                        }
                                    }
                                }
                                Err(e) => {
                                    log::error!(
                                        "[BRIDGE] ArgPack decode failed for system.genesis: {} (ArgPack bytes len={})",
                                        e,
                                        arg_bytes.len()
                                    );
                                    op_error(
                                        op_id,
                                        400,
                                        &format!("system.genesis ArgPack decode failed: {e}"),
                                    )
                                }
                            }
                        } else if query.path == "sys.tick" {
                            // Deterministic, protobuf-only logical clock exposed even if the SDK
                            // app router has not been installed yet. This keeps the WebView intro
                            // flow unblocked during early bootstrap and avoids the "not
                            // implemented" error when routing is still wiring up.
                            let tick = crate::performance::mono_commit_height();
                            let body = tick.to_le_bytes().to_vec();
                            op_success(
                                op_id,
                                body,
                                None,
                                Some(gp::Hash32 {
                                    v: zero_hash32_vec(),
                                }),
                                gp::Codec::Proto,
                            )
                        } else if let Some(router) = app_router() {
                            let params_bytes = query
                                .params
                                .as_ref()
                                .map(|p| p.encode_to_vec())
                                .unwrap_or_default();
                            match router.handle_query(&query.path, &params_bytes) {
                                Ok(body_bytes) => {
                                    let pack =
                                        gp::ArgPack::decode(body_bytes.as_slice()).map_err(|e| {
                                            log::error!(
                                                "[BRIDGE] App query returned non-ArgPack bytes: {e}"
                                            );
                                            e
                                        });
                                    match pack {
                                        Ok(pack) => {
                                            if pack.codec != gp::Codec::Proto as i32 {
                                                op_error(
                                                    op_id,
                                                    400,
                                                    &format!(
                                                        "Application query returned unsupported codec {} (expected PROTO)",
                                                        pack.codec
                                                    ),
                                                )
                                            } else {
                                                op_success(
                                                    op_id,
                                                    pack.body,
                                                    None,
                                                    pack.schema_hash,
                                                    gp::Codec::Proto,
                                                )
                                            }
                                        }
                                        Err(_) => op_error(
                                            op_id,
                                            500,
                                            "Application query must return ArgPack(codec=PROTO)",
                                        ),
                                    }
                                }
                                Err(e) => {
                                    op_error(op_id, 500, &format!("Application query failed: {e}"))
                                }
                            }
                        } else {
                            op_error(
                                op_id,
                                501,
                                "Application queries require the DSM SDK runtime",
                            )
                        }
                    }

                    // -------- Invoke routing (unilateral / bilateral / app) --------
                    Some(gp::universal_op::Kind::Invoke(invoke)) => {
                        // Unilateral goes to the core-installed UnilateralHandler.
                        if invoke.method.starts_with("unilateral.") {
                            if let Some(handler) = unilateral_handler() {
                                match handler.handle_unilateral_invoke(invoke) {
                                    Ok(ok) => ok,
                                    Err(e) => op_error(
                                        op_id,
                                        500,
                                        &format!("Unilateral operation failed: {e}"),
                                    ),
                                }
                            } else {
                                op_error(
                                    op_id,
                                    501,
                                    "Unilateral operations require a handler to be installed",
                                )
                            }

                        // Bilateral methods are decoded here then forwarded to the BilateralHandler.
                        } else if invoke.method.starts_with("bilateral.") {
                            if let Some(handler) = bilateral_handler() {
                                let args_bytes: Vec<u8> = invoke
                                    .args
                                    .as_ref()
                                    .map(|a| a.body.clone())
                                    .unwrap_or_default();

                                let result = match invoke.method.as_str() {
                                    "bilateral.prepare" => {
                                        match gp::BilateralPrepareRequest::decode(
                                            args_bytes.as_slice(),
                                        ) {
                                            Ok(req) => handler.handle_bilateral_prepare(req),
                                            Err(e) => Err(format!(
                                                "Failed to decode BilateralPrepareRequest: {e}"
                                            )),
                                        }
                                    }
                                    "bilateral.transfer" => {
                                        match gp::BilateralTransferRequest::decode(
                                            args_bytes.as_slice(),
                                        ) {
                                            Ok(req) => handler.handle_bilateral_transfer(req),
                                            Err(e) => Err(format!(
                                                "Failed to decode BilateralTransferRequest: {e}"
                                            )),
                                        }
                                    }
                                    "bilateral.accept" => {
                                        match gp::BilateralAcceptRequest::decode(
                                            args_bytes.as_slice(),
                                        ) {
                                            Ok(req) => handler.handle_bilateral_accept(req),
                                            Err(e) => Err(format!(
                                                "Failed to decode BilateralAcceptRequest: {e}"
                                            )),
                                        }
                                    }
                                    "bilateral.commit" => {
                                        match gp::BilateralCommitRequest::decode(
                                            args_bytes.as_slice(),
                                        ) {
                                            Ok(req) => handler.handle_bilateral_commit(req),
                                            Err(e) => Err(format!(
                                                "Failed to decode BilateralCommitRequest: {e}"
                                            )),
                                        }
                                    }
                                    other => Err(format!("Unknown bilateral method: {other}")),
                                };

                                match result {
                                    Ok(ok) => ok,
                                    Err(e) if e.starts_with("Failed to decode ") => {
                                        op_error(op_id, 400, &e)
                                    }
                                    Err(e) if e.starts_with("Unknown bilateral method:") => {
                                        op_error(op_id, 404, &e)
                                    }
                                    Err(e) => op_error(
                                        op_id,
                                        500,
                                        &format!("Bilateral operation failed: {e}"),
                                    ),
                                }
                            } else {
                                op_error(
                                    op_id,
                                    501,
                                    "Bilateral operations require a handler to be installed",
                                )
                            }

                        // Application invocations (non-unilateral/bilateral) go to AppRouter.
                        } else if let Some(router) = app_router() {
                            // Pass the FULL ArgPack bytes to the AppRouter (protobuf-only boundary).
                            // Previously this forwarded only ArgPack.body, which caused the SDK
                            // to attempt decoding an ArgPack from a raw message body and fail with
                            // "ArgPack.schema_hash: buffer underflow". Queries already pass the
                            // encoded ArgPack; do the same for invokes here.
                            let args_bytes: Vec<u8> = invoke
                                .args
                                .as_ref()
                                .map(|a| a.encode_to_vec())
                                .unwrap_or_default();
                            match router.handle_invoke(&invoke.method, &args_bytes) {
                                Ok((result_body, post_state_hash_bytes)) => {
                                    let post_hash = if post_state_hash_bytes.len() == 32 {
                                        Some(gp::Hash32 {
                                            v: post_state_hash_bytes,
                                        })
                                    } else {
                                        None
                                    };
                                    let pack = gp::ArgPack::decode(result_body.as_slice())
                                        .map_err(|e| {
                                            log::error!(
                                                "[BRIDGE] App invoke returned non-ArgPack bytes: {e}"
                                            );
                                            e
                                        });
                                    match pack {
                                        Ok(pack) => {
                                            if pack.codec != gp::Codec::Proto as i32 {
                                                op_error(
                                                    op_id,
                                                    400,
                                                    &format!(
                                                        "Application invoke returned unsupported codec {} (expected PROTO)",
                                                        pack.codec
                                                    ),
                                                )
                                            } else {
                                                op_success(
                                                    op_id,
                                                    pack.body,
                                                    post_hash,
                                                    pack.schema_hash,
                                                    gp::Codec::Proto,
                                                )
                                            }
                                        }
                                        Err(_) => op_error(
                                            op_id,
                                            500,
                                            "Application invoke must return ArgPack(codec=PROTO)",
                                        ),
                                    }
                                }
                                Err(e) => {
                                    op_error(op_id, 500, &format!("Application invoke failed: {e}"))
                                }
                            }
                        } else {
                            op_error(
                                op_id,
                                501,
                                "Application invocations require the DSM SDK runtime",
                            )
                        }
                    }

                    // -------- Recovery / DBRW ops are SDK-only --------
                    Some(gp::universal_op::Kind::RecoveryCapsuleDecrypt(req)) => {
                        if let Some(handler) = recovery_handler() {
                            match handler.handle_recovery_capsule_decrypt(req) {
                                Ok(result) => result,
                                Err(e) => op_error(
                                    op_id,
                                    500,
                                    &format!("Recovery capsule decrypt failed: {e}"),
                                ),
                            }
                        } else {
                            op_error(
                                op_id,
                                501,
                                "Recovery operations require a handler to be installed",
                            )
                        }
                    }

                    Some(gp::universal_op::Kind::ExternalCommit(commit)) => {
                        match (commit.source_id.as_ref(), commit.commit_id.as_ref()) {
                            (Some(source_h), Some(commit_h))
                                if source_h.v.len() == 32 && commit_h.v.len() == 32 =>
                            {
                                let mut source_id = [0u8; 32];
                                source_id.copy_from_slice(&source_h.v);
                                let mut commit_id = [0u8; 32];
                                commit_id.copy_from_slice(&commit_h.v);

                                let evidence_bytes = commit
                                    .evidence
                                    .as_ref()
                                    .map(|e| e.encode_to_vec())
                                    .unwrap_or_default();
                                let evidence_hash =
                                    crate::commitments::external_evidence_hash(&evidence_bytes);
                                let expected_commit_id =
                                    crate::commitments::create_external_commitment(
                                        &commit.payload,
                                        &source_id,
                                        &evidence_hash,
                                    );
                                if expected_commit_id != commit_id {
                                    op_error(op_id, 400, "ExternalCommit commit_id mismatch")
                                } else {
                                    let expected_source_id =
                                        crate::commitments::external_source_id("nfc:recovery");
                                    let source_id_matches = source_id == expected_source_id;

                                    if source_id_matches {
                                        if let Some(handler) = recovery_handler() {
                                            match handler.handle_nfc_tag(commit) {
                                                Ok(result) => result,
                                                Err(e) => op_error(
                                                    op_id,
                                                    500,
                                                    &format!("NFC tag processing failed: {e}"),
                                                ),
                                            }
                                        } else {
                                            op_error(
                                                op_id,
                                                501,
                                                "Recovery operations require a handler to be installed",
                                            )
                                        }
                                    } else {
                                        op_error(
                                            op_id,
                                            501,
                                            "ExternalCommit source not supported by core bridge",
                                        )
                                    }
                                }
                            }
                            _ => op_error(
                                op_id,
                                400,
                                "ExternalCommit source_id or commit_id missing or invalid",
                            ),
                        }
                    }

                    Some(gp::universal_op::Kind::FaucetClaim(req)) => {
                        // Faucet claim is an application-level policy decision.
                        // The core bridge MUST NOT mint or otherwise perform claims.
                        //
                        // This variant is explicitly a *claim* request, so we route it through
                        // the AppRouter invoke path (method="faucet.claim").
                        if let Some(router) = app_router() {
                            let arg_pack = gp::ArgPack {
                                schema_hash: None,
                                codec: gp::Codec::Proto as i32,
                                body: req.encode_to_vec(),
                            };
                            let args_bytes = arg_pack.encode_to_vec();

                            match router.handle_invoke("faucet.claim", &args_bytes) {
                                Ok((result_body, _events)) => {
                                    let pack = gp::ArgPack::decode(result_body.as_slice())
                                        .map_err(|e| {
                                            log::error!(
                                                "[BRIDGE] Faucet invoke returned non-ArgPack bytes: {e}"
                                            );
                                            e
                                        });
                                    match pack {
                                        Ok(pack) => {
                                            if pack.codec != gp::Codec::Proto as i32 {
                                                op_error(
                                                    op_id,
                                                    400,
                                                    &format!(
                                                        "Faucet invoke returned unsupported codec {} (expected PROTO)",
                                                        pack.codec
                                                    ),
                                                )
                                            } else {
                                                op_success(
                                                    op_id,
                                                    pack.body,
                                                    None,
                                                    pack.schema_hash,
                                                    gp::Codec::Proto,
                                                )
                                            }
                                        }
                                        Err(_) => op_error(
                                            op_id,
                                            500,
                                            "Faucet invoke must return ArgPack(codec=PROTO)",
                                        ),
                                    }
                                }
                                Err(e) => {
                                    op_error(op_id, 500, &format!("Faucet invoke failed: {e}"))
                                }
                            }
                        } else {
                            op_error(op_id, 501, "Faucet operations require the DSM SDK runtime")
                        }
                    }

                    Some(gp::universal_op::Kind::RecoveryTombstone(req)) => {
                        if let Some(handler) = recovery_handler() {
                            match handler.handle_recovery_tombstone(req) {
                                Ok(result) => result,
                                Err(e) => op_error(
                                    op_id,
                                    500,
                                    &format!("Recovery tombstone failed: {e}"),
                                ),
                            }
                        } else {
                            op_error(
                                op_id,
                                501,
                                "Recovery operations require a handler to be installed",
                            )
                        }
                    }

                    Some(gp::universal_op::Kind::RecoverySuccession(req)) => {
                        if let Some(handler) = recovery_handler() {
                            match handler.handle_recovery_succession(req) {
                                Ok(result) => result,
                                Err(e) => op_error(
                                    op_id,
                                    500,
                                    &format!("Recovery succession failed: {e}"),
                                ),
                            }
                        } else {
                            op_error(
                                op_id,
                                501,
                                "Recovery operations require a handler to be installed",
                            )
                        }
                    }

                    Some(gp::universal_op::Kind::RecoveryResume(req)) => {
                        if let Some(handler) = recovery_handler() {
                            match handler.handle_recovery_resume(req) {
                                Ok(result) => result,
                                Err(e) => op_error(
                                    op_id,
                                    500,
                                    &format!("Recovery resume failed: {e}"),
                                ),
                            }
                        } else {
                            op_error(
                                op_id,
                                501,
                                "Recovery operations require a handler to be installed",
                            )
                        }
                    }

                    // -------- Anything else is unsupported by the core bridge --------
                    _ => op_error(
                        op_id,
                        501,
                        "Operation type is not supported by the core bridge",
                    ),
                };

                results.push(result);
            }

            gp::envelope::Payload::UniversalRx(gp::UniversalRx { results })
        }

        // Response types or batch envelopes sent as requests → error
        Some(gp::envelope::Payload::UniversalRx(_)) => gp::envelope::Payload::Error(gp::Error {
            code: 409,
            message: "Envelope already contains a response".to_string(),
            context: vec![],
            source_tag: 10,
            is_recoverable: false,
            debug_b32: "".to_string(),
        }),
        Some(gp::envelope::Payload::BatchEnvelope(_)) => gp::envelope::Payload::Error(gp::Error {
            code: 415,
            message: "Batch envelopes must be handled by the SDK".to_string(),
            context: vec![],
            source_tag: 10,
            is_recoverable: false,
            debug_b32: "".to_string(),
        }),

        // Recovery & bilateral responses must not arrive as requests.
        Some(
            gp::envelope::Payload::RecoveryCapsuleDecryptResponse(_)
            | gp::envelope::Payload::RecoveryTombstoneResponse(_)
            | gp::envelope::Payload::RecoverySuccessionResponse(_)
            | gp::envelope::Payload::RecoveryResumeResponse(_)
            | gp::envelope::Payload::BilateralPrepareResponse(_)
            | gp::envelope::Payload::BilateralPrepareReject(_)
            | gp::envelope::Payload::BilateralTransferResponse(_)
            | gp::envelope::Payload::BilateralAcceptResponse(_)
            | gp::envelope::Payload::BilateralCommitResponse(_)
            | gp::envelope::Payload::BalancesListResponse(_)
            | gp::envelope::Payload::StorageSyncResponse(_)
            | gp::envelope::Payload::OfflineBilateralPendingListResponse(_)
            | gp::envelope::Payload::InboxResponse(_)
            | gp::envelope::Payload::WalletHistoryResponse(_)
            | gp::envelope::Payload::ContactsListResponse(_)
            | gp::envelope::Payload::OnlineTransferResponse(_)
            | gp::envelope::Payload::OnlineMessageResponse(_)
            | gp::envelope::Payload::ContactAddResponse(_)
            | gp::envelope::Payload::BalanceGetResponse(_)
            | gp::envelope::Payload::BleCommandResponse(_)
            | gp::envelope::Payload::ReconciliationResponse(_)
            | gp::envelope::Payload::StateInfoResponse(_)
            | gp::envelope::Payload::SecondaryDeviceResponse(_)
            | gp::envelope::Payload::ContactQrResponse(_)
            | gp::envelope::Payload::StorageStatusResponse(_)
            | gp::envelope::Payload::DbrwStatusResponse(_)
            | gp::envelope::Payload::TokenCreateRequest(_)
            | gp::envelope::Payload::TokenCreateResponse(_),
        ) => gp::envelope::Payload::Error(gp::Error {
            code: 409,
            message: "Responses should not be sent as requests".to_string(),
            context: vec![],
            source_tag: 10,
            is_recoverable: false,
            debug_b32: "".to_string(),
        }),

        // App state helper (SDK should own this; we only route if a router is present).
        Some(gp::envelope::Payload::AppStateRequest(req)) => match req.operation.as_str() {
            "get" => {
                if let Some(router) = app_router() {
                    // Route as a query: path=req.key, params=[]
                    match router.handle_query(&req.key, &[]) {
                        Ok(_bytes) => {
                            gp::envelope::Payload::AppStateResponse(gp::AppStateResponse {
                                key: req.key,
                                value: Some(
                                    "App state operations must be handled by SDK layer".to_string(),
                                ),
                            })
                        }
                        Err(e) => gp::envelope::Payload::Error(gp::Error {
                            code: 500,
                            message: format!("App state get failed: {e}"),
                            context: vec![],
                            source_tag: 10,
                            is_recoverable: false,
                            debug_b32: "".to_string(),
                        }),
                    }
                } else {
                    gp::envelope::Payload::Error(gp::Error {
                        code: 501,
                        message: "App state operations require the DSM SDK runtime".to_string(),
                        context: vec![],
                        source_tag: 10,
                        is_recoverable: false,
                        debug_b32: "".to_string(),
                    })
                }
            }
            "set" => {
                if let Some(router) = app_router() {
                    let value_bytes = req.value.as_bytes();
                    match router.handle_invoke(&req.key, value_bytes) {
                        Ok((_body, _post)) => {
                            gp::envelope::Payload::AppStateResponse(gp::AppStateResponse {
                                key: req.key,
                                value: Some("App state set completed".to_string()),
                            })
                        }
                        Err(e) => gp::envelope::Payload::Error(gp::Error {
                            code: 500,
                            message: format!("App state set failed: {e}"),
                            context: vec![],
                            source_tag: 10,
                            is_recoverable: false,
                            debug_b32: "".to_string(),
                        }),
                    }
                } else {
                    gp::envelope::Payload::Error(gp::Error {
                        code: 501,
                        message: "App state operations require the DSM SDK runtime".to_string(),
                        context: vec![],
                        source_tag: 10,
                        is_recoverable: false,
                        debug_b32: "".to_string(),
                    })
                }
            }
            _ => gp::envelope::Payload::Error(gp::Error {
                code: 400,
                message: format!("Unsupported app state operation: {}", req.operation),
                context: vec![],
                source_tag: 10,
                is_recoverable: false,
                debug_b32: "".to_string(),
            }),
        },

        Some(gp::envelope::Payload::AppStateResponse(_)) => {
            gp::envelope::Payload::Error(gp::Error {
                code: 409,
                message: "AppStateResponse should not be sent as a request".to_string(),
                context: vec![],
                source_tag: 10,
                is_recoverable: false,
                debug_b32: "".to_string(),
            })
        }

        Some(gp::envelope::Payload::DsmBtMessage(_)) => gp::envelope::Payload::Error(gp::Error {
            code: 409,
            message: "Bluetooth transport frames must be handled via DsmBtMessage only".to_string(),
            context: vec![],
            source_tag: 10,
            is_recoverable: false,
            debug_b32: "".to_string(),
        }),

        Some(gp::envelope::Payload::FaucetClaimResponse(_)) => {
            gp::envelope::Payload::Error(gp::Error {
                code: 409,
                message: "FaucetClaimResponse should not be sent as a request".to_string(),
                context: vec![],
                source_tag: 10,
                is_recoverable: false,
                debug_b32: "".to_string(),
            })
        }

        // Init/status messages are produced by the SDK/JNI surfaces and should not be routed
        // through the core universal handler as "requests".
        Some(gp::envelope::Payload::InitFailed(_)) => gp::envelope::Payload::Error(gp::Error {
            code: 409,
            message: "InitFailed should not be sent as a request".to_string(),
            context: vec![],
            source_tag: 10,
            is_recoverable: false,
            debug_b32: "".to_string(),
        }),

        // NEW: Explicit guard for genesis-created responses (SDK-only)
        Some(gp::envelope::Payload::GenesisCreatedResponse(_)) => {
            gp::envelope::Payload::Error(gp::Error {
                code: 409,
                message: "GenesisCreatedResponse should not be sent as a request".to_string(),
                context: vec![],
                source_tag: 10,
                is_recoverable: false,
                debug_b32: "".to_string(),
            })
        }

        // Pass-through error (force non-recoverable).
        Some(gp::envelope::Payload::Error(err)) => gp::envelope::Payload::Error(gp::Error {
            is_recoverable: false,
            debug_b32: "".to_string(),
            ..err
        }),

        // BLE events are handled at the bridge level and not processed as requests
        Some(gp::envelope::Payload::BleEvent(_)) => gp::envelope::Payload::Error(gp::Error {
            code: 400,
            message: "BLE events should not be sent as requests".to_string(),
            context: vec![],
            source_tag: 10,
            is_recoverable: false,
            debug_b32: "".to_string(),
        }),

        // Bitcoin Tap payloads — handled at SDK layer; core returns acknowledgement
        Some(gp::envelope::Payload::DepositRequest(_))
        | Some(gp::envelope::Payload::DepositResponse(_))
        | Some(gp::envelope::Payload::DepositCompleteRequest(_))
        | Some(gp::envelope::Payload::DepositRefundRequest(_))
        | Some(gp::envelope::Payload::DepositStatusRequest(_))
        | Some(gp::envelope::Payload::BitcoinAddressRequest(_))
        | Some(gp::envelope::Payload::BitcoinAddressResponse(_))
        | Some(gp::envelope::Payload::BitcoinDepositListRequest(_))
        | Some(gp::envelope::Payload::BitcoinDepositListResponse(_))
        | Some(gp::envelope::Payload::BitcoinClaimTxRequest(_))
        | Some(gp::envelope::Payload::BitcoinClaimTxResponse(_))
        | Some(gp::envelope::Payload::BitcoinWalletImportRequest(_))
        | Some(gp::envelope::Payload::BitcoinWalletImportResponse(_))
        | Some(gp::envelope::Payload::BitcoinWalletListResponse(_))
        | Some(gp::envelope::Payload::BitcoinWalletSelectRequest(_))
        | Some(gp::envelope::Payload::BitcoinWalletSelectResponse(_))
        | Some(gp::envelope::Payload::BitcoinBroadcastRequest(_))
        | Some(gp::envelope::Payload::BitcoinBroadcastResponse(_))
        | Some(gp::envelope::Payload::BitcoinAutoClaimRequest(_))
        | Some(gp::envelope::Payload::BitcoinAutoClaimResponse(_))
        | Some(gp::envelope::Payload::BitcoinTxStatusRequest(_))
        | Some(gp::envelope::Payload::BitcoinTxStatusResponse(_))
        | Some(gp::envelope::Payload::BitcoinVaultListRequest(_))
        | Some(gp::envelope::Payload::BitcoinVaultListResponse(_))
        | Some(gp::envelope::Payload::BitcoinVaultGetRequest(_))
        | Some(gp::envelope::Payload::BitcoinVaultGetResponse(_))
        | Some(gp::envelope::Payload::BitcoinWalletHealthResponse(_))
        | Some(gp::envelope::Payload::BitcoinFeeEstimateRequest(_))
        | Some(gp::envelope::Payload::BitcoinFeeEstimateResponse(_))
        | Some(gp::envelope::Payload::BitcoinFractionalExitRequest(_))
        | Some(gp::envelope::Payload::BitcoinFractionalExitResponse(_))
        | Some(gp::envelope::Payload::BitcoinRefundTxRequest(_))
        | Some(gp::envelope::Payload::BitcoinRefundTxResponse(_))
        | Some(gp::envelope::Payload::BitcoinAddressSelectRequest(_))
        | Some(gp::envelope::Payload::BitcoinAddressSelectResponse(_))
        | Some(gp::envelope::Payload::BitcoinWalletCreateRequest(_))
        | Some(gp::envelope::Payload::BitcoinWalletCreateResponse(_))
        | Some(gp::envelope::Payload::BitcoinWithdrawalPlanRequest(_))
        | Some(gp::envelope::Payload::BitcoinWithdrawalPlanResponse(_))
        | Some(gp::envelope::Payload::BitcoinWithdrawalExecuteRequest(_))
        | Some(gp::envelope::Payload::BitcoinWithdrawalExecuteResponse(_)) => {
            gp::envelope::Payload::Error(gp::Error {
                code: 501,
                message: "Bitcoin Tap payloads are handled at the SDK layer".to_string(),
                context: vec![],
                source_tag: 10,
                is_recoverable: false,
                debug_b32: "".to_string(),
            })
        }

        // Storage node stats/management responses — handled at the SDK layer
        Some(gp::envelope::Payload::StorageNodeStatsResponse(_))
        | Some(gp::envelope::Payload::StorageNodeManageResponse(_))
        | Some(gp::envelope::Payload::SessionStateResponse(_))
        | Some(gp::envelope::Payload::TokenPolicyListResponse(_))
        // Outbound-only push envelopes — never arrive as inbound requests
        | Some(gp::envelope::Payload::NfcRecoveryCapsule(_))
        | Some(gp::envelope::Payload::GenesisLifecycle(_))
        | Some(gp::envelope::Payload::BootstrapMeasurementReport(_))
        | Some(gp::envelope::Payload::BootstrapFinalizeResponse(_))
        // C-DBRW Protocol 6.2 payloads — owned entirely by the SDK layer
        // (cdbrw_responder / cdbrw_enrollment_writer / cdbrw_verifier).
        // The core bridge never constructs or consumes these.
        | Some(gp::envelope::Payload::CdbrwTrustSnapshot(_))
        | Some(gp::envelope::Payload::CdbrwRespondResponse(_))
        | Some(gp::envelope::Payload::CdbrwVerifyResponse(_))
        | Some(gp::envelope::Payload::CdbrwEnrollResponse(_)) => {
            gp::envelope::Payload::Error(gp::Error {
                code: 501,
                message: "SDK-owned payloads are handled at the SDK layer".to_string(),
                context: vec![],
                source_tag: 10,
                is_recoverable: false,
                debug_b32: "".to_string(),
            })
        }

        None => gp::envelope::Payload::Error(gp::Error {
            code: 400,
            message: "Envelope payload missing".to_string(),
            context: vec![],
            source_tag: 10,
            is_recoverable: false,
            debug_b32: "".to_string(),
        }),
    };

    gp::Envelope {
        version: 3,
        headers: Some(gp::Headers {
            device_id: crate::crypto::blake3::domain_hash("DSM/error-envelope", &message_id)
                .as_bytes()
                .to_vec(), // Hash of message_id for device_id
            chain_tip: crate::crypto::blake3::domain_hash("DSM/error-envelope", b"ERROR_CHAIN_TIP")
                .as_bytes()
                .to_vec(), // Fixed error chain tip
            genesis_hash: crate::crypto::blake3::domain_hash(
                "DSM/error-envelope",
                b"DSM_ERROR_GENESIS",
            )
            .as_bytes()
            .to_vec(), // Fixed error genesis
            seq: 0, // Error sequence
        }),
        message_id,
        payload: Some(payload),
    }
    .encode_to_vec()
}

/// Offline bilateral send handler (canonical path entry from JNI)
///
/// Performs lightweight structural validation on the provided v3 Envelope
/// containing a UniversalTx with one or more BilateralPrepare ops.
///
/// Validation rules (phase 1 + deterministic commitment):
/// * Envelope decodes
/// * Headers present and device_id length == 32 and not all zero
/// * Payload is UniversalTx
/// * Each op kind BilateralPrepare has non-empty operation_data
///
/// On success, returns a new Envelope containing UniversalRx with
/// BilateralPrepareResponse results, each embedding a BLAKE3 commitment to the
/// raw operation_data. Signatures and state hashes are left for higher layers.
pub fn handle_bilateral_offline_send(env_bytes: &[u8], ble_address: &str) -> Vec<u8> {
    let envelope = match gp::Envelope::decode(env_bytes) {
        Ok(env) => env,
        Err(e) => {
            log::error!("[BRIDGE:offline_send] decode failed: {e}");
            return envelope_error(460, &format!("invalid envelope: {e}")).encode_to_vec();
        }
    };

    // Basic header validation
    let headers = match envelope.headers.as_ref() {
        Some(h) => h,
        None => {
            return envelope_error(461, "missing headers").encode_to_vec();
        }
    };
    if headers.device_id.len() != 32 {
        return envelope_error(462, "device_id must be 32 bytes").encode_to_vec();
    }
    if headers.device_id.iter().all(|b| *b == 0) {
        return envelope_error(463, "device_id cannot be all zero").encode_to_vec();
    }

    // Ensure UniversalTx payload
    let uni_tx = match envelope.payload.as_ref() {
        Some(gp::envelope::Payload::UniversalTx(tx)) => tx,
        _ => return envelope_error(464, "payload must be UniversalTx").encode_to_vec(),
    };

    // Validate BilateralPrepare ops (ignore other op kinds for now)
    for op in &uni_tx.ops {
        if let Some(gp::universal_op::Kind::Invoke(invoke)) = op.kind.as_ref() {
            if invoke.method == "bilateral.prepare" {
                let args_bytes = invoke
                    .args
                    .as_ref()
                    .map(|a| a.body.clone())
                    .unwrap_or_default();
                if let Ok(prep) = gp::BilateralPrepareRequest::decode(args_bytes.as_slice()) {
                    if prep.operation_data.is_empty() {
                        return envelope_error(465, "BilateralPrepare.operation_data empty")
                            .encode_to_vec();
                    }
                    // Offline send must be bound to a concrete peer address (no empty / placeholder).
                    if ble_address.is_empty() {
                        return envelope_error(466, "ble_address missing").encode_to_vec();
                    }
                    // Guard: request's ble_address must match the connection address used by JNI.
                    // This prevents replaying a prepare intended for one peer onto another.
                    if prep.ble_address != ble_address {
                        return envelope_error(467, "BilateralPrepare.ble_address mismatch")
                            .encode_to_vec();
                    }
                    // Basic sanity: counterparty id must be present and 32 bytes.
                    if prep.counterparty_device_id.len() != 32 {
                        return envelope_error(468, "counterparty_device_id must be 32 bytes")
                            .encode_to_vec();
                    }
                }
            }
        }
    }

    log::info!(
        "[BRIDGE:offline_send] envelope validated (ops={}, bytes={})",
        uni_tx.ops.len(),
        env_bytes.len()
    );

    // If a bilateral handler is installed, delegate prepare ops to it so the
    // SDK BLE coordinator can transmit chunks on Android.
    if let Some(handler) = bilateral_handler() {
        let mut results: Vec<gp::OpResult> = Vec::with_capacity(uni_tx.ops.len());
        for op in uni_tx.ops.iter() {
            let op_id = op.op_id.clone();
            match op.kind.as_ref() {
                Some(gp::universal_op::Kind::Invoke(invoke))
                    if invoke.method == "bilateral.prepare" =>
                {
                    let args_bytes = invoke
                        .args
                        .as_ref()
                        .map(|a| a.body.clone())
                        .unwrap_or_default();
                    match gp::BilateralPrepareRequest::decode(args_bytes.as_slice()) {
                        Ok(req) => match handler.handle_bilateral_prepare(req) {
                            Ok(mut ok) => {
                                if ok.op_id.is_none() {
                                    ok.op_id = op_id;
                                }
                                results.push(ok)
                            }
                            Err(e) => results.push(op_error(
                                op_id,
                                500,
                                &format!("Bilateral operation failed: {e}"),
                            )),
                        },
                        Err(e) => results.push(op_error(
                            op_id,
                            400,
                            &format!("Failed to decode BilateralPrepareRequest: {e}"),
                        )),
                    }
                }
                _ => results.push(op_error(op_id, 501, "unsupported op kind for offline send")),
            }
        }

        let op_count = results.len();
        let rx_payload = gp::envelope::Payload::UniversalRx(gp::UniversalRx { results });
        let response_env = gp::Envelope {
            version: 3,
            headers: Some(gp::Headers {
                device_id: headers.device_id.clone(),
                chain_tip: headers.chain_tip.clone(),
                genesis_hash: headers.genesis_hash.clone(),
                seq: headers.seq,
            }),
            message_id: envelope.message_id.clone(),
            payload: Some(rx_payload),
        };

        let encoded = response_env.encode_to_vec();
        log::info!(
            "[BRIDGE:offline_send] produced response envelope bytes={} ops={} (handler)",
            encoded.len(),
            op_count
        );
        return encoded;
    }

    // Produce a UniversalRx with deterministic BilateralPrepareResponse results
    let mut results: Vec<gp::OpResult> = Vec::with_capacity(uni_tx.ops.len());
    for op in uni_tx.ops.iter() {
        let op_id = op.op_id.clone();
        match op.kind.as_ref() {
            Some(gp::universal_op::Kind::Invoke(invoke))
                if invoke.method == "bilateral.prepare" =>
            {
                let args_bytes = invoke
                    .args
                    .as_ref()
                    .map(|a| a.body.clone())
                    .unwrap_or_default();
                if let Ok(prep) = gp::BilateralPrepareRequest::decode(args_bytes.as_slice()) {
                    // Deterministic commitment over a domain-separated framing that binds
                    // offline-transport context to prevent cross-transport/peer replay.
                    //
                    // IMPORTANT: This is a lightweight "prepare" commitment only. Higher layers
                    // still sign canonical commit bytes for protocol acceptance.
                    let mut commit_preimage = Vec::with_capacity(
                        32 + prep.operation_data.len() + prep.ble_address.len() + 8 + 64,
                    );
                    commit_preimage.extend_from_slice(b"DSM/bilateral/prepare-offline\0");
                    commit_preimage.extend_from_slice(prep.ble_address.as_bytes());
                    // Bind validity_iterations (u64 little-endian)
                    commit_preimage.extend_from_slice(&prep.validity_iterations.to_le_bytes());
                    // Bind expected hashes if present (32B each), else bind 32 zero bytes.
                    match prep.expected_genesis_hash.as_ref() {
                        Some(h) if h.v.len() == 32 => commit_preimage.extend_from_slice(&h.v),
                        _ => commit_preimage.extend_from_slice(&[0u8; 32]),
                    }
                    match prep.expected_counterparty_state_hash.as_ref() {
                        Some(h) if h.v.len() == 32 => commit_preimage.extend_from_slice(&h.v),
                        _ => commit_preimage.extend_from_slice(&[0u8; 32]),
                    }
                    // Finally bind the raw operation_data bytes
                    commit_preimage.extend_from_slice(&prep.operation_data);
                    let commitment = crate::crypto::blake3::domain_hash(
                        "DSM/bilateral-commit",
                        &commit_preimage,
                    );
                    let response = gp::BilateralPrepareResponse {
                        commitment_hash: Some(gp::Hash32 {
                            v: commitment.as_bytes().to_vec(),
                        }),
                        local_signature: vec![], // Signatures produced later by SDK
                        expires_iterations: prep.validity_iterations,
                        counterparty_state_hash: None, // Populated by higher layers if needed
                        local_state_hash: None,        // Populated by higher layers if needed
                        responder_signing_public_key: vec![], // Populated by BLE handler with local signing key
                    };
                    let body = response.encode_to_vec();
                    results.push(op_success(op_id, body, None, None, gp::Codec::Proto));
                } else {
                    results.push(op_error(
                        op_id,
                        500,
                        "failed to decode BilateralPrepareRequest",
                    ));
                }
            }
            // Non-bilateral operations are not supported in this offline send path
            _ => {
                results.push(op_error(op_id, 501, "unsupported op kind for offline send"));
            }
        }
    }

    let op_count = results.len();
    let rx_payload = gp::envelope::Payload::UniversalRx(gp::UniversalRx { results });

    let response_env = gp::Envelope {
        version: 3,
        headers: Some(gp::Headers {
            device_id: headers.device_id.clone(),
            chain_tip: headers.chain_tip.clone(),
            genesis_hash: headers.genesis_hash.clone(),
            seq: headers.seq, // mirror incoming seq
        }),
        message_id: envelope.message_id.clone(), // reuse message_id for correlation
        payload: Some(rx_payload),
    };

    let encoded = response_env.encode_to_vec();
    log::info!(
        "[BRIDGE:offline_send] produced response envelope bytes={} ops={}",
        encoded.len(),
        op_count
    );
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn offline_send_valid_prepare_yields_commitment_response() {
        // Build a minimal BilateralPrepare operation
        let prep = gp::BilateralPrepareRequest {
            counterparty_device_id: vec![0x11; 32],
            operation_data: vec![1, 2, 3, 4],
            validity_iterations: 42,
            expected_genesis_hash: Some(gp::Hash32 { v: vec![0; 32] }),
            expected_counterparty_state_hash: Some(gp::Hash32 { v: vec![0; 32] }),
            ble_address: String::from("AA:BB:CC:DD:EE:FF"),
            sender_device_id: vec![0xAA; 32],
            sender_genesis_hash: Some(gp::Hash32 { v: vec![0xBB; 32] }),
            sender_signing_public_key: vec![0xCC; 32],
            sender_chain_tip: Some(gp::Hash32 { v: vec![0xDD; 32] }),
            ..Default::default()
        };
        let op = gp::UniversalOp {
            op_id: Some(gp::Hash32 { v: vec![9; 32] }),
            actor: vec![2; 32],
            genesis_hash: vec![3; 32],
            kind: Some(gp::universal_op::Kind::Invoke(gp::Invoke {
                method: "bilateral.prepare".to_string(),
                args: Some(gp::ArgPack {
                    body: prep.encode_to_vec(),
                    ..Default::default()
                }),
                program: None,
                pre_state_hash: None,
                post_state_hash: None,
                cosigners: vec![],
                evidence: None,
                nonce: None,
            })),
        };
        let env = gp::Envelope {
            version: 3,
            headers: Some(gp::Headers {
                device_id: vec![0xAB; 32],
                chain_tip: vec![7; 32],
                genesis_hash: vec![0; 32],
                seq: 5,
            }),
            message_id: vec![8; 16],
            payload: Some(gp::envelope::Payload::UniversalTx(gp::UniversalTx {
                ops: vec![op],
                atomic: true,
            })),
        };
        let bytes = env.encode_to_vec();
        let resp_bytes = handle_bilateral_offline_send(&bytes, "AA:BB:CC:DD:EE:FF");
        let resp_env =
            gp::Envelope::decode(resp_bytes.as_slice()).expect("response envelope decodes");
        match resp_env.payload {
            Some(gp::envelope::Payload::UniversalRx(rx)) => {
                assert_eq!(rx.results.len(), 1);
                let r = &rx.results[0];
                assert!(r.error.is_none(), "unexpected error result");
                let pack = r.result.as_ref().expect("result pack present");
                let body = &pack.body;
                let prep_resp = gp::BilateralPrepareResponse::decode(body.as_slice())
                    .expect("prep response decodes");
                let mut preimage = Vec::new();
                preimage.extend_from_slice(b"DSM/bilateral/prepare-offline\0");
                preimage.extend_from_slice(b"AA:BB:CC:DD:EE:FF");
                preimage.extend_from_slice(&42u64.to_le_bytes());
                preimage.extend_from_slice(&[0u8; 32]);
                preimage.extend_from_slice(&[0u8; 32]);
                preimage.extend_from_slice(&[1, 2, 3, 4]);
                let commitment =
                    crate::crypto::blake3::domain_hash("DSM/bilateral-commit", &preimage);
                assert_eq!(
                    prep_resp.commitment_hash.unwrap().v,
                    commitment.as_bytes().to_vec()
                );
                assert_eq!(prep_resp.expires_iterations, 42);
            }
            other => panic!("unexpected payload variant: {:?}", other),
        }
    }

    #[test]
    fn offline_send_rejects_empty_operation_data() {
        let prep = gp::BilateralPrepareRequest {
            counterparty_device_id: vec![0x22; 32],
            operation_data: vec![], // empty -> invalid
            validity_iterations: 1,
            expected_genesis_hash: None,
            expected_counterparty_state_hash: None,
            ble_address: String::new(),
            sender_device_id: vec![0xAA; 32],
            sender_genesis_hash: Some(gp::Hash32 { v: vec![0xBB; 32] }),
            sender_signing_public_key: vec![0xCC; 32],
            sender_chain_tip: None,
            ..Default::default()
        };
        let op = gp::UniversalOp {
            op_id: Some(gp::Hash32 { v: vec![0; 32] }),
            actor: vec![0x33; 32],
            genesis_hash: vec![0x44; 32],
            kind: Some(gp::universal_op::Kind::Invoke(gp::Invoke {
                method: "bilateral.prepare".to_string(),
                args: Some(gp::ArgPack {
                    body: prep.encode_to_vec(),
                    ..Default::default()
                }),
                program: None,
                pre_state_hash: None,
                post_state_hash: None,
                cosigners: vec![],
                evidence: None,
                nonce: None,
            })),
        };
        let env = gp::Envelope {
            version: 3,
            headers: Some(gp::Headers {
                device_id: vec![0x55; 32],
                chain_tip: vec![0x66; 32],
                genesis_hash: vec![0; 32],
                seq: 1,
            }),
            message_id: vec![1; 16],
            payload: Some(gp::envelope::Payload::UniversalTx(gp::UniversalTx {
                ops: vec![op],
                atomic: false,
            })),
        };
        let bytes = env.encode_to_vec();
        let resp_bytes = handle_bilateral_offline_send(&bytes, "ZZ");
        let resp_env =
            gp::Envelope::decode(resp_bytes.as_slice()).expect("decode response envelope");
        match resp_env.payload {
            Some(gp::envelope::Payload::Error(err)) => {
                assert_eq!(err.code, 465);
                assert!(
                    err.message.contains("operation_data empty"),
                    "unexpected message: {}",
                    err.message
                );
            }
            other => panic!("expected error envelope, got {:?}", other),
        }
    }

    #[test]
    fn offline_send_rejects_ble_address_mismatch() {
        let prep = gp::BilateralPrepareRequest {
            counterparty_device_id: vec![0x11; 32],
            operation_data: vec![1, 2, 3, 4],
            validity_iterations: 1,
            expected_genesis_hash: None,
            expected_counterparty_state_hash: None,
            ble_address: String::from("AA:BB:CC"),
            sender_device_id: vec![0xAA; 32],
            sender_genesis_hash: Some(gp::Hash32 { v: vec![0xBB; 32] }),
            sender_signing_public_key: vec![0xCC; 32],
            sender_chain_tip: None,
            ..Default::default()
        };
        let op = gp::UniversalOp {
            op_id: Some(gp::Hash32 { v: vec![0; 32] }),
            actor: vec![0x33; 32],
            genesis_hash: vec![0x44; 32],
            kind: Some(gp::universal_op::Kind::Invoke(gp::Invoke {
                method: "bilateral.prepare".to_string(),
                args: Some(gp::ArgPack {
                    body: prep.encode_to_vec(),
                    ..Default::default()
                }),
                program: None,
                pre_state_hash: None,
                post_state_hash: None,
                cosigners: vec![],
                evidence: None,
                nonce: None,
            })),
        };
        let env = gp::Envelope {
            version: 3,
            headers: Some(gp::Headers {
                device_id: vec![0x55; 32],
                chain_tip: vec![0x66; 32],
                genesis_hash: vec![0; 32],
                seq: 1,
            }),
            message_id: vec![1; 16],
            payload: Some(gp::envelope::Payload::UniversalTx(gp::UniversalTx {
                ops: vec![op],
                atomic: false,
            })),
        };
        let bytes = env.encode_to_vec();
        let resp_bytes = handle_bilateral_offline_send(&bytes, "DD:EE:FF");
        let resp_env =
            gp::Envelope::decode(resp_bytes.as_slice()).expect("decode response envelope");
        match resp_env.payload {
            Some(gp::envelope::Payload::Error(err)) => {
                assert_eq!(err.code, 467);
                assert!(err.message.contains("mismatch"));
            }
            other => panic!("expected error envelope, got {:?}", other),
        }
    }

    #[test]
    fn offline_send_rejects_all_zero_device_id() {
        let prep = gp::BilateralPrepareRequest {
            counterparty_device_id: vec![0xCC; 32],
            operation_data: vec![1, 2, 3, 4],
            validity_iterations: 10,
            expected_genesis_hash: None,
            expected_counterparty_state_hash: None,
            ble_address: String::new(),
            sender_device_id: vec![0xAA; 32],
            sender_genesis_hash: Some(gp::Hash32 { v: vec![0xBB; 32] }),
            sender_signing_public_key: vec![0xCC; 32],
            sender_chain_tip: None,
            ..Default::default()
        };
        let op = gp::UniversalOp {
            op_id: Some(gp::Hash32 { v: vec![0; 32] }),
            actor: vec![0x99; 32],
            genesis_hash: vec![0x88; 32],
            kind: Some(gp::universal_op::Kind::Invoke(gp::Invoke {
                method: "bilateral.prepare".to_string(),
                args: Some(gp::ArgPack {
                    body: prep.encode_to_vec(),
                    ..Default::default()
                }),
                program: None,
                pre_state_hash: None,
                post_state_hash: None,
                cosigners: vec![],
                evidence: None,
                nonce: None,
            })),
        };

        let env = gp::Envelope {
            version: 3,
            headers: Some(gp::Headers {
                device_id: vec![0; 32], // all zero -> invalid
                chain_tip: vec![0x77; 32],
                genesis_hash: vec![0; 32],
                seq: 2,
            }),
            message_id: vec![2; 16],
            payload: Some(gp::envelope::Payload::UniversalTx(gp::UniversalTx {
                ops: vec![op],
                atomic: false,
            })),
        };
        let bytes = env.encode_to_vec();
        let resp_bytes = handle_bilateral_offline_send(&bytes, "AA:BB:CC");
        let resp_env =
            gp::Envelope::decode(resp_bytes.as_slice()).expect("decode response envelope");
        match resp_env.payload {
            Some(gp::envelope::Payload::Error(err)) => {
                assert_eq!(err.code, 463);
                assert!(
                    err.message.contains("all zero"),
                    "unexpected message: {}",
                    err.message
                );
            }
            other => panic!("expected error envelope, got {:?}", other),
        }
    }

    #[test]
    fn universal_bilateral_without_handler_requires_handler() {
        let prep = gp::BilateralPrepareRequest {
            counterparty_device_id: vec![0xAA; 32],
            operation_data: vec![1, 2, 3],
            validity_iterations: 60,
            expected_genesis_hash: Some(gp::Hash32 { v: vec![0; 32] }),
            expected_counterparty_state_hash: Some(gp::Hash32 { v: vec![0; 32] }),
            ble_address: String::new(),
            sender_device_id: vec![0xBB; 32],
            sender_genesis_hash: Some(gp::Hash32 { v: vec![0xCC; 32] }),
            sender_signing_public_key: vec![0xDD; 32],
            sender_chain_tip: None,
            ..Default::default()
        };
        let op = gp::UniversalOp {
            op_id: Some(gp::Hash32 { v: vec![0; 32] }),
            actor: vec![0xEE; 32],
            genesis_hash: vec![0xFF; 32],
            kind: Some(gp::universal_op::Kind::Invoke(gp::Invoke {
                method: "bilateral.prepare".to_string(),
                args: Some(gp::ArgPack {
                    body: prep.encode_to_vec(),
                    ..Default::default()
                }),
                program: None,
                pre_state_hash: None,
                post_state_hash: None,
                cosigners: vec![],
                evidence: None,
                nonce: None,
            })),
        };

        let envelope = gp::Envelope {
            version: 3,
            headers: Some(gp::Headers {
                device_id: vec![0; 32],
                chain_tip: vec![0; 32],
                genesis_hash: vec![0; 32],
                seq: 0,
            }),
            message_id: vec![1; 16],
            payload: Some(gp::envelope::Payload::UniversalTx(gp::UniversalTx {
                ops: vec![op],
                atomic: false,
            })),
        };

        let response_bytes = handle_envelope_universal(&envelope.encode_to_vec());
        let response =
            gp::Envelope::decode(response_bytes.as_slice()).expect("response should decode");

        match response.payload {
            Some(gp::envelope::Payload::UniversalRx(rx)) => {
                assert_eq!(rx.results.len(), 1);
                let result = &rx.results[0];
                let err = result.error.as_ref().expect("error must be set");
                assert_eq!(err.code, 501);
                assert!(
                    err.message
                        .contains("Bilateral operations require a handler to be installed"),
                    "unexpected error message: {}",
                    err.message
                );
            }
            Some(payload) => panic!("unexpected payload: {payload:?}"),
            None => panic!("payload is None"),
        }
    }
}
