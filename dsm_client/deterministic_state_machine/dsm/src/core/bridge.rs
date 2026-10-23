// SPDX-License-Identifier: MIT OR Apache-2.0

//! Core envelope routing and handler dispatch module.
//!
//! This module implements the central routing contract for the DSM protocol's Envelope v3
//! wire format. Incoming protobuf-encoded envelopes are decoded, classified by payload type,
//! and dispatched to the appropriate handler:
//!
//! - **Queries** are routed to the installed [`AppRouter`] (or handled inline for
//!   special-case paths like `system.genesis`).
//! - **Recovery operations** are not taken here: they run only as the router's
//!   `recovery.*` routes, behind the gates those routes hold (SA-119, SA-120).
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
    /// Handle a state-mutating invocation identified by `method`. Returns a
    /// protobuf-encoded `ArgPack`.
    fn handle_invoke(&self, method: &str, args_proto: &[u8]) -> Result<Vec<u8>, String>;
}

/// Install the application router the core bridge routes to. It is installed
/// once: a second install is refused, never a silent replacement.
pub fn install_app_router(router: Arc<dyn AppRouter>) -> Result<(), DsmError> {
    let mut guard = APP_ROUTER.write().map_err(|_| DsmError::LockError)?;
    if guard.is_some() {
        return Err(DsmError::invalid_operation(
            "an app router is already installed in the core bridge; it is installed once",
        ));
    }
    *guard = Some(router);
    log::info!("[CORE] AppRouter installed");
    Ok(())
}

/// Get the installed application router.
pub fn get_app_router() -> Option<Arc<dyn AppRouter>> {
    APP_ROUTER.read().ok()?.clone()
}

#[inline]
fn app_router() -> Option<Arc<dyn AppRouter>> {
    APP_ROUTER.read().ok()?.clone()
}

#[inline]
fn op_error(op_id: Option<gp::Hash32>, code: u32, message: &str) -> gp::OpResult {
    gp::OpResult {
        op_id,
        accepted: false,
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
    schema_hash: Option<gp::Hash32>,
    codec: gp::Codec,
) -> gp::OpResult {
    gp::OpResult {
        op_id,
        accepted: true,
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

                    // -------- Invoke routing (app) --------
                    Some(gp::universal_op::Kind::Invoke(invoke)) => {
                        // Invocations go to the AppRouter. Offline bilateral steps
                        // are not envelope-bridge methods: they run in the offline
                        // session engine, over its own transport.
                        if let Some(router) = app_router() {
                            // Pass the FULL ArgPack bytes to the AppRouter (protobuf-only boundary).
                            let args_bytes: Vec<u8> = invoke
                                .args
                                .as_ref()
                                .map(|a| a.encode_to_vec())
                                .unwrap_or_default();
                            match router.handle_invoke(&invoke.method, &args_bytes) {
                                Ok(result_body) => {
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
                                Ok(result_body) => {
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
            | gp::envelope::Payload::ContactAddResponse(_)
            | gp::envelope::Payload::BalanceGetResponse(_)
            | gp::envelope::Payload::BleCommandResponse(_)
            | gp::envelope::Payload::StateInfoResponse(_)
            | gp::envelope::Payload::ContactQrResponse(_)
            | gp::envelope::Payload::StorageStatusResponse(_)
            | gp::envelope::Payload::TokenCreateRequest(_)
            | gp::envelope::Payload::TokenCreateResponse(_)
            | gp::envelope::Payload::TokenCheckResponse(_)
            | gp::envelope::Payload::TokenBurnResponse(_)
            | gp::envelope::Payload::TokenFeeScheduleResponse(_)
            | gp::envelope::Payload::WalletAmountResponse(_)
            | gp::envelope::Payload::SofiVaultCreatedResponse(_)
            | gp::envelope::Payload::SofiFindRouteResponse(_)
            | gp::envelope::Payload::SofiPositionResponse(_)
            | gp::envelope::Payload::SofiRelayResponse(_)
            | gp::envelope::Payload::SofiVaultsResponse(_)
            | gp::envelope::Payload::ConnectReply(_)
            | gp::envelope::Payload::EscrowPartyResponse(_)
            | gp::envelope::Payload::EscrowCreatedResponse(_)
            | gp::envelope::Payload::EscrowSignedResponse(_)
            | gp::envelope::Payload::EscrowVerdictResponse(_)
            | gp::envelope::Payload::EscrowVaultsResponse(_)
            | gp::envelope::Payload::AuthoredPublishedResponse(_)
            | gp::envelope::Payload::AuthoredObjectsResponse(_)
            | gp::envelope::Payload::ContactProfile(_)
            | gp::envelope::Payload::ReceiptEmailResult(_)
            | gp::envelope::Payload::MoneyWaitingResponse(_),
        ) => gp::envelope::Payload::Error(gp::Error {
            code: 409,
            message: "Responses should not be sent as requests".to_string(),
            context: vec![],
            source_tag: 10,
            is_recoverable: false,
            debug_b32: "".to_string(),
        }),

        // App state is the SDK router's (prefs.*, recovery.*); the Core holds none.
        Some(gp::envelope::Payload::AppStateRequest(_)) => gp::envelope::Payload::Error(gp::Error {
            code: 400,
            message: "AppStateRequest is not a Core operation: app state is answered by the SDK router"
                .to_string(),
            context: vec![],
            source_tag: 10,
            is_recoverable: false,
            debug_b32: "".to_string(),
        }),

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

        // SDK-owned `session.status` query response.
        Some(gp::envelope::Payload::SessionStateResponse(_))
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
        // Secondary-device admission envelopes: the core bridge never routes them, and no
        // SDK flow handles them until the device tree store they extend is built.
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

    /// The single result of invoking `method` with `body` through the bridge.
    fn invoke_result(method: &str, body: Vec<u8>) -> gp::OpResult {
        op_result(gp::universal_op::Kind::Invoke(gp::Invoke {
            method: method.to_string(),
            args: Some(gp::ArgPack {
                body,
                ..Default::default()
            }),
            program: None,
            cosigners: vec![],
            evidence: None,
            nonce: None,
        }))
    }

    /// SA-119, SA-120. No recovery operation runs through the envelope
    /// bridge. Its arms called the recovery handler around the router's
    /// gates: a capsule decrypted under a key the request carried and staged,
    /// and a resume that skipped the tombstone-acknowledgement gate. Recovery
    /// runs only as the router's `recovery.*` routes, so each is answered as
    /// an operation the bridge does not take.
    #[test]
    fn no_recovery_operation_runs_through_the_bridge() {
        let kinds = [
            gp::universal_op::Kind::RecoveryCapsuleDecrypt(gp::RecoveryCapsuleDecryptRequest {
                encrypted_capsule: vec![1; 64],
                mnemonic_key: vec![2; 32],
            }),
            gp::universal_op::Kind::RecoveryTombstone(gp::RecoveryTombstoneRequest::default()),
            gp::universal_op::Kind::RecoverySuccession(gp::RecoverySuccessionRequest::default()),
            gp::universal_op::Kind::RecoveryResume(gp::RecoveryResumeRequest::default()),
        ];
        for kind in kinds {
            let label = format!("{kind:?}");
            let result = op_result(kind);
            assert!(!result.accepted, "{label} was taken");
            let error = result.error.expect("a refusal");
            assert_eq!(error.code, 501, "{label}");
            assert!(
                error.message.contains("not supported by the core bridge"),
                "{label}: {}",
                error.message
            );
        }
    }

    /// The single result of the operation `kind` through the bridge.
    fn op_result(kind: gp::universal_op::Kind) -> gp::OpResult {
        let op = gp::UniversalOp {
            op_id: Some(gp::Hash32 { v: vec![7; 32] }),
            actor: vec![0xEE; 32],
            kind: Some(kind),
        };
        let envelope = gp::Envelope {
            version: 3,
            headers: Some(gp::Headers {
                device_id: vec![0xAB; 32],
                genesis_hash: vec![0xCD; 32],
            }),
            message_id: vec![1; 16],
            payload: Some(gp::envelope::Payload::UniversalTx(gp::UniversalTx {
                ops: vec![op],
                atomic: false,
            })),
        };
        let response =
            decode_response_envelope(&handle_envelope_universal(&envelope.encode_to_vec()));
        match response.payload {
            Some(gp::envelope::Payload::UniversalRx(mut rx)) => {
                assert_eq!(rx.results.len(), 1);
                rx.results.remove(0)
            }
            other => panic!("expected a UniversalRx, got {other:?}"),
        }
    }

    /// An offline bilateral step is not an envelope-bridge method: a
    /// `bilateral.*` invoke has no handler of its own and is answered exactly
    /// as any other invocation is, never with a success for work nobody did.
    #[test]
    fn a_bilateral_invoke_is_not_an_envelope_bridge_method() {
        let prepare = gp::BilateralPrepareRequest {
            counterparty_device_id: vec![0xAA; 32],
            operation_data: vec![1, 2, 3],
            sender_device_id: vec![0xBB; 32],
            sender_genesis_hash: Some(gp::Hash32 { v: vec![0xCC; 32] }),
            sender_signing_public_key: vec![0xDD; 32],
            ..Default::default()
        }
        .encode_to_vec();

        let other = invoke_result("an.unrouted.method", prepare.clone());
        for method in [
            "bilateral.prepare",
            "bilateral.accept",
            "bilateral.commit",
            "bilateral.transfer",
        ] {
            let result = invoke_result(method, prepare.clone());
            assert!(!result.accepted, "{method} was accepted");
            let (err, other_err) = (
                result.error.as_ref().expect("an error"),
                other.error.as_ref().expect("an error"),
            );
            assert_eq!(
                (err.code, &err.message),
                (other_err.code, &other_err.message),
                "{method} is answered differently from any other invocation"
            );
        }
    }
}
