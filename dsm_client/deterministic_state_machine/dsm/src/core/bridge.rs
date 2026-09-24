// SPDX-License-Identifier: MIT OR Apache-2.0

//! Core envelope routing and handler dispatch module.
//!
//! This module implements the central routing contract for the DSM protocol's Envelope v3
//! wire format. Incoming protobuf-encoded envelopes are decoded, classified by payload type,
//! and dispatched to the appropriate handler:
//!
//! - **Queries** are routed to the installed [`AppRouter`] (or handled inline for
//!   special-case paths like `system.genesis`).
//! - **Bilateral invocations** (`bilateral.*`) are decoded into their specific protobuf
//!   request types and forwarded to the [`BilateralHandler`].
//! - **Recovery operations** are delegated to the [`RecoveryHandler`].
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
static BILATERAL_HANDLER: Lazy<RwLock<Option<Arc<dyn BilateralHandler>>>> =
    Lazy::new(|| RwLock::new(None));
static RECOVERY_HANDLER: Lazy<RwLock<Option<Arc<dyn RecoveryHandler>>>> =
    Lazy::new(|| RwLock::new(None));

/// Application-level routing trait for query and invoke dispatch.
///
/// Implementors handle application-specific operations that are not part of the
/// core bilateral or recovery subsystems. The SDK installs an `AppRouter`
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

#[inline]
fn app_router() -> Option<Arc<dyn AppRouter>> {
    APP_ROUTER.read().ok()?.clone()
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
fn op_error(op_id: Option<gp::Hash32>, code: u32, message: &str) -> gp::OpResult {
    gp::OpResult {
        op_id,
        accepted: false,
        post_state_hash: None,
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
        post_state_hash,
        result: Some(gp::ResultPack {
            schema_hash,
            codec: codec as i32,
            body,
        }),
        error: None,
    }
}

/// The local answer for a request the bridge could not take.
#[inline]
fn envelope_error(code: u32, message: &str) -> gp::Envelope {
    crate::envelope::local_answer(gp::envelope::Payload::Error(gp::Error {
        code,
        message: message.to_string(),
        context: vec![],
        // Stable category tag: core bridge failures are validation/unsupported routing.
        source_tag: 10,
        is_recoverable: false,
        debug_b32: "".to_string(),
    }))
}

/// Handle universal envelopes within the core crate.
///
/// The real runtime dispatcher lives in the SDK. The core returns structured
/// errors to signal that callers must go through the SDK for bilateral flows.
pub fn handle_envelope_universal(env_bytes: &[u8]) -> Vec<u8> {
    let envelope = match crate::envelope::from_canonical_bytes(env_bytes) {
        Ok(env) => env,
        Err(err) => {
            return envelope_error(400, &format!("failed to decode envelope: {err}"))
                .encode_to_vec()
        }
    };

    let payload = match envelope.payload {
        // ==== REQUEST PATHS ====
        Some(gp::envelope::Payload::UniversalTx(tx)) => {
            let mut results = Vec::with_capacity(tx.ops.len());

            for op in tx.ops {
                let op_id = op.op_id.clone();

                let result = match op.kind {
                    // -------- Query routing --------
                    Some(gp::universal_op::Kind::Query(query)) => {
                        log::info!(
                            "[BRIDGE] Query received: path='{}' (len={}) bytes={:?}",
                            query.path,
                            query.path.len(),
                            query.path.as_bytes()
                        );
                        if let Some(router) = app_router() {
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

                    // -------- Invoke routing (bilateral / app) --------
                    Some(gp::universal_op::Kind::Invoke(invoke)) => {
                        // Bilateral methods are decoded here then forwarded to the BilateralHandler.
                        if invoke.method.starts_with("bilateral.") {
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

                        // Application invocations (non-bilateral) go to AppRouter.
                        } else if let Some(router) = app_router() {
                            // Pass the FULL ArgPack bytes to the AppRouter (protobuf-only boundary).
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

                    // -------- Recovery ops are SDK-only --------
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

        // A sealed spool payload is opened by the SDK's retrieval path
        // (DSM Amendment A7); it is transport, never a request.
        Some(gp::envelope::Payload::Sealed(_)) => gp::envelope::Payload::Error(gp::Error {
            code: 415,
            message: "Sealed spool payloads are opened by the SDK's retrieval path".to_string(),
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
            | gp::envelope::Payload::TokenCreateRequest(_)
            | gp::envelope::Payload::TokenCreateResponse(_)
            | gp::envelope::Payload::TokenBurnResponse(_)
            | gp::envelope::Payload::TokenFeeScheduleResponse(_)
            | gp::envelope::Payload::SofiVaultCreatedResponse(_)
            | gp::envelope::Payload::SofiSetupResponse(_)
            | gp::envelope::Payload::SofiFindRouteResponse(_)
            | gp::envelope::Payload::SofiPositionResponse(_)
            | gp::envelope::Payload::SofiRelayResponse(_),
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
        // Offline-bearer anchor status (signal (c)) — SDK-owned `anchor.status` query response.
        | Some(gp::envelope::Payload::AnchorStatusResponse(_))
        // Offline-cash load/unload — SDK-owned `wallet.loadOffline`/`unloadOffline` response.
        | Some(gp::envelope::Payload::OfflineCashResponse(_))
        | Some(gp::envelope::Payload::TokenPolicyListResponse(_))
        // SDK-owned `token.forget` response; the core bridge never
        // constructs or consumes it.
        | Some(gp::envelope::Payload::TokenForgetResponse(_))
        // SDK-owned `token.adoptionQr` response; same.
        | Some(gp::envelope::Payload::TokenAdoptionQrResponse(_))
        // Outbound-only push envelopes — never arrive as inbound requests
        | Some(gp::envelope::Payload::NfcRecoveryCapsule(_))
        | Some(gp::envelope::Payload::GenesisLifecycle(_))
        | Some(gp::envelope::Payload::BootstrapMeasurementReport(_))
        | Some(gp::envelope::Payload::BootstrapFinalizeResponse(_))
        // Phase B.7 (issue #278) — DeviceTreeViewer payload is owned by
        // the SDK's identity routes (`identity.devtree.snapshot`); the
        // core bridge never constructs or consumes it.
        | Some(gp::envelope::Payload::DeviceTreeSnapshotResponse(_))
        // Secondary-device admission envelopes are BLE-transport payloads handled by the
        // bilateral transport adapter; the core bridge never routes them directly.
        | Some(gp::envelope::Payload::DeviceAdmissionRequest(_))
        | Some(gp::envelope::Payload::DeviceAdmission(_)) => {
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

    crate::envelope::local_answer(payload).encode_to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    fn decode_response_envelope(bytes: &[u8]) -> gp::Envelope {
        crate::envelope::local_answer_from_canonical_bytes(bytes).expect("decode the local answer")
    }

    #[test]
    fn universal_bridge_rejects_wrong_envelope_version() {
        let env = gp::Envelope {
            version: 2,
            headers: Some(gp::Headers {
                device_id: vec![4u8; 32],
                genesis_hash: vec![3u8; 32],
            }),
            message_id: vec![6u8; 16],
            payload: Some(gp::envelope::Payload::UniversalTx(gp::UniversalTx {
                ops: vec![],
                atomic: false,
            })),
        };

        let resp_bytes = handle_envelope_universal(&env.encode_to_vec());
        let resp_env = decode_response_envelope(resp_bytes.as_slice());

        match resp_env.payload {
            Some(gp::envelope::Payload::Error(err)) => {
                assert_eq!(err.code, 400);
                assert!(
                    err.message.contains("Envelope.version must be 3"),
                    "unexpected error: {}",
                    err.message
                );
            }
            other => panic!("expected error payload, got {:?}", other),
        }
    }

    #[test]
    fn universal_bilateral_without_handler_requires_handler() {
        let prep = gp::BilateralPrepareRequest {
            counterparty_device_id: vec![0xAA; 32],
            operation_data: vec![1, 2, 3],
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
                cosigners: vec![],
                evidence: None,
                nonce: None,
            })),
        };

        let envelope = gp::Envelope {
            version: 3,
            headers: Some(gp::Headers {
                device_id: vec![0; 32],
                genesis_hash: vec![0; 32],
            }),
            message_id: vec![1; 16],
            payload: Some(gp::envelope::Payload::UniversalTx(gp::UniversalTx {
                ops: vec![op],
                atomic: false,
            })),
        };

        let response_bytes = handle_envelope_universal(&envelope.encode_to_vec());
        let response = decode_response_envelope(response_bytes.as_slice());

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
