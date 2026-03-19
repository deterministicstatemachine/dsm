//! # Bilateral Handler Implementation
//!
//! Implements the `BilateralHandler` trait for the SDK layer. Handles
//! prepare, transfer, accept, and commit phases of the bilateral protocol,
//! dispatching over BLE (Android) or returning deterministic errors on
//! unsupported platforms.
//!
//! ## Single Shared Chain Tip Model
//!
//! Each bilateral relationship has ONE shared chain tip `h_n^{A↔B}`.
//! The BLE session engine (`BilateralBleHandler` + `BleFrameCoordinator`)
//! is the authoritative commit path using a 3-step protocol:
//! Propose(A→B) → Co-sign(B→A) → Confirm(A→B). The `accept()` and
//! `commit()` JNI entry points are disabled — all real bilateral work
//! flows through the BLE coordinator.

use async_trait::async_trait;
use prost::Message;
use std::sync::Arc;

use crate::bridge::{BiAccept, BiCommit, BiPrepare, BiResult, BiTransfer, BilateralHandler};
use crate::init::SdkConfig;
use crate::storage::bilateral::BilateralStorageSDK;
// Use SDK-local generated protobufs to ensure consistency with tests and app router
use crate::generated as pb;

#[cfg(all(target_os = "android", feature = "jni"))]
use dsm::types::error::DsmError;

#[cfg(all(target_os = "android", feature = "bluetooth"))]
use crate::bluetooth::ble_frame_coordinator::BleFrameCoordinator;

/// Helper to send BLE chunks via Android BLE service through JNI
#[cfg(all(target_os = "android", feature = "jni"))]
fn send_ble_chunks_jni(device_address: &str, chunks: &[Vec<u8>]) -> Result<(), DsmError> {
    use jni::objects::{JString, JValue, JObject};

    // Get JavaVM
    let jvm = crate::jni::jni_common::get_java_vm()
        .ok_or_else(|| DsmError::internal("JavaVM not initialized", None::<std::io::Error>))?;

    let mut env = jvm.attach_current_thread().map_err(|e| {
        DsmError::internal(format!("JNI attach failed: {e}"), None::<std::io::Error>)
    })?;

    // Convert device address to JString
    let device_addr_j = env.new_string(device_address).map_err(|e| {
        DsmError::internal(
            format!("JNI new_string failed: {e}"),
            None::<std::io::Error>,
        )
    })?;

    // Create Java byte[][] array for chunks
    let byte_array_class = env.find_class("[B").map_err(|e| {
        DsmError::internal(
            format!("Failed to find byte array class: {e}"),
            None::<std::io::Error>,
        )
    })?;

    let chunks_array = env
        .new_object_array(chunks.len() as i32, &byte_array_class, JObject::null())
        .map_err(|e| {
            DsmError::internal(
                format!("Failed to create chunks array: {e}"),
                None::<std::io::Error>,
            )
        })?;

    // Populate chunks array
    for (i, chunk) in chunks.iter().enumerate() {
        let chunk_bytes = env.byte_array_from_slice(chunk).map_err(|e| {
            DsmError::internal(
                format!("Failed to create byte array for chunk {}: {}", i, e),
                None::<std::io::Error>,
            )
        })?;
        env.set_object_array_element(&chunks_array, i as i32, chunk_bytes)
            .map_err(|e| {
                DsmError::internal(
                    format!("Failed to set chunk {} in array: {}", i, e),
                    None::<std::io::Error>,
                )
            })?;
    }

    // Call Unified.requestGattWriteChunks(String, byte[][]) - the actual Kotlin method
    let class_name = "com/dsm/wallet/bridge/Unified";
    let jstr_addr = JString::from(device_addr_j);
    let jobj_addr = JObject::from(jstr_addr);
    let jobj_chunks = JObject::from(chunks_array);

    let args = [JValue::Object(&jobj_addr), JValue::Object(&jobj_chunks)];
    let result = env
        .call_static_method(
            class_name,
            "requestGattWriteChunks",
            "(Ljava/lang/String;[[B)Z",
            &args,
        )
        .map_err(|e| {
            DsmError::internal(
                format!("JNI call requestGattWriteChunks failed: {e}"),
                None::<std::io::Error>,
            )
        })?;

    let ok = result.z().unwrap_or(false);
    if ok {
        log::info!(
            "[BiImpl] Successfully sent {} BLE chunks to {}",
            chunks.len(),
            device_address
        );
        Ok(())
    } else {
        Err(DsmError::network(
            "requestGattWriteChunks returned false",
            None::<std::io::Error>,
        ))
    }
}

/// Bilateral (offline) protocol handler.
///
/// Implements the bilateral transaction flow at the protobuf boundary.
/// All BLE, receipts, and SMT logic live in `BilateralBleHandler` + `BleFrameCoordinator`.
pub struct BiImpl {
    _config: SdkConfig,
    #[cfg(all(target_os = "android", feature = "bluetooth"))]
    ble_coordinator: Arc<tokio::sync::RwLock<Option<Arc<BleFrameCoordinator>>>>,
    storage: Option<Arc<BilateralStorageSDK>>,
}

impl BiImpl {
    pub fn new(config: SdkConfig) -> Self {
        // Try to initialize bilateral storage
        let storage = match crate::storage::bilateral::bilateral::new() {
            Ok(s) => {
                log::info!("[BiImpl] Bilateral storage initialized successfully");
                Some(Arc::new(s))
            }
            Err(e) => {
                log::warn!("[BiImpl] Failed to initialize bilateral storage: {}", e);
                None
            }
        };

        Self {
            _config: config,
            #[cfg(all(target_os = "android", feature = "bluetooth"))]
            ble_coordinator: Arc::new(tokio::sync::RwLock::new(None)),
            storage,
        }
    }

    /// Inject BleFrameCoordinator after BLE handler initialization.
    #[cfg(all(target_os = "android", feature = "bluetooth"))]
    pub async fn set_ble_coordinator(&self, coordinator: Arc<BleFrameCoordinator>) {
        let mut guard = self.ble_coordinator.write().await;
        *guard = Some(coordinator);
        log::info!("[BiImpl] BLE coordinator injected successfully");
    }

    /// Get a reference to the BleFrameCoordinator if available.
    #[cfg(all(target_os = "android", feature = "bluetooth"))]
    pub async fn get_ble_coordinator(&self) -> Option<Arc<BleFrameCoordinator>> {
        let guard = self.ble_coordinator.read().await;
        guard.clone()
    }
}

#[async_trait]
impl BilateralHandler for BiImpl {
    /// Prepare phase: compute precommitment and (on Android) sign it.
    ///
    /// Deterministic semantics:
    /// - Delegates to BilateralBleHandler which calls core prepare_offline_transfer()
    /// - Returns envelope bytes ready for BLE chunking/transmission
    /// - On Android, this also triggers BLE send via coordinator
    async fn prepare(&self, p: BiPrepare) -> BiResult {
        match pb::BilateralPrepareRequest::decode(&*p.payload) {
            Ok(req) => {
                if req.operation_data.is_empty() {
                    return BiResult {
                        success: false,
                        result_data: vec![],
                        error_message: Some(
                            "BilateralPrepareRequest.operation_data is empty".into(),
                        ),
                    };
                }

                // Android BLE path: requires BLE coordinator and address
                #[cfg(all(target_os = "android", feature = "bluetooth"))]
                {
                    // Parse canonical Operation from operation_data (required)
                    let operation =
                        match dsm::types::operations::Operation::from_bytes(&req.operation_data) {
                            Ok(op) => op,
                            Err(e) => {
                                return BiResult {
                                    success: false,
                                    result_data: vec![],
                                    error_message: Some(format!("Failed to parse Operation: {e}")),
                                };
                            }
                        };

                    // Extract counterparty device id from canonical operation
                    let counterparty_id = match &operation {
                        dsm::types::operations::Operation::Transfer { to_device_id, .. } => {
                            if to_device_id.len() != 32 {
                                return BiResult {
                                    success: false,
                                    result_data: vec![],
                                    error_message: Some(format!(
                                        "to_device_id must be 32 bytes (got {})",
                                        to_device_id.len()
                                    )),
                                };
                            }
                            let mut id = [0u8; 32];
                            id.copy_from_slice(to_device_id);
                            id
                        }
                        _ => {
                            return BiResult {
                                success: false,
                                result_data: vec![],
                                error_message: Some("Unsupported operation for bilateral.prepare (expected Transfer)".into()),
                            };
                        }
                    };
                    let ble_address = req.ble_address.clone();
                    if ble_address.is_empty() {
                        return BiResult {
                            success: false,
                            result_data: vec![],
                            error_message: Some(
                                "BLE address required for bilateral prepare".into(),
                            ),
                        };
                    }

                    let coord_guard = self.ble_coordinator.read().await;
                    let coordinator = match coord_guard.as_ref() {
                        Some(c) => c,
                        None => {
                            return BiResult {
                                success: false,
                                result_data: vec![],
                                error_message: Some("BLE coordinator not initialized".into()),
                            };
                        }
                    };

                    // Create prepare message via BilateralBleHandler
                    match coordinator
                        .create_prepare_message_with_commitment(
                            counterparty_id,
                            operation,
                            req.validity_iterations,
                        )
                        .await
                    {
                        Ok((chunks, commitment_hash_bytes)) => {
                            let commitment_txt = crate::util::text_id::encode_base32_crockford(
                                &commitment_hash_bytes,
                            );
                            log::info!("[BiImpl] Bilateral prepare created {} BLE chunks for device {} (commitment={})", chunks.len(), ble_address, commitment_txt);

                            // Send chunks via Android BLE service
                            #[cfg(all(target_os = "android", feature = "jni"))]
                            {
                                if let Err(e) = send_ble_chunks_jni(&ble_address, &chunks) {
                                    return BiResult {
                                        success: false,
                                        result_data: vec![],
                                        error_message: Some(format!(
                                            "Failed to send BLE chunks: {}",
                                            e
                                        )),
                                    };
                                }
                            }

                            let response = pb::BilateralPrepareResponse {
                                commitment_hash: Some(pb::Hash32 {
                                    v: commitment_hash_bytes.to_vec(),
                                }),
                                local_signature: vec![],
                                expires_iterations: req.validity_iterations,
                                counterparty_state_hash: None,
                                local_state_hash: None,
                                responder_signing_public_key:
                                    crate::sdk::app_state::AppState::get_public_key()
                                        .unwrap_or_default(),
                            };

                            return BiResult {
                                success: true,
                                result_data: response.encode_to_vec(),
                                error_message: None,
                            };
                        }
                        Err(e) => {
                            return BiResult {
                                success: false,
                                result_data: vec![],
                                error_message: Some(format!(
                                    "Failed to create bilateral prepare: {e}"
                                )),
                            };
                        }
                    }
                }

                // Non-Android builds: compute commitment directly
                #[cfg(not(all(target_os = "android", feature = "bluetooth")))]
                {
                    let commitment = dsm::crypto::blake3::domain_hash(
                        "DSM/bilateral-op-commit",
                        &req.operation_data,
                    );

                    let response = pb::BilateralPrepareResponse {
                        commitment_hash: Some(pb::Hash32 {
                            v: commitment.as_bytes().to_vec(),
                        }),
                        local_signature: vec![],
                        expires_iterations: req.validity_iterations,
                        counterparty_state_hash: None,
                        local_state_hash: None,
                        responder_signing_public_key:
                            crate::sdk::app_state::AppState::get_public_key().unwrap_or_default(),
                    };

                    BiResult {
                        success: true,
                        result_data: response.encode_to_vec(),
                        error_message: None,
                    }
                }
            }
            Err(e) => BiResult {
                success: false,
                result_data: vec![],
                error_message: Some(format!("decode BilateralPrepareRequest failed: {e}")),
            },
        }
    }

    /// Accept phase: validate commitment presence/length and acknowledge.
    async fn accept(&self, a: BiAccept) -> BiResult {
        match pb::BilateralAcceptRequest::decode(&*a.payload) {
            Ok(req) => {
                let commitment_hash = match req.commitment_hash {
                    Some(ref h) if h.v.len() == 32 => &h.v,
                    Some(ref h) => {
                        return BiResult {
                            success: false,
                            result_data: vec![],
                            error_message: Some(format!(
                                "commitment_hash must be 32 bytes (got {})",
                                h.v.len()
                            )),
                        };
                    }
                    None => {
                        return BiResult {
                            success: false,
                            result_data: vec![],
                            error_message: Some("commitment_hash missing".into()),
                        };
                    }
                };

                // Fail-closed: accept is performed by the BLE session engine
                // using the 3-step Propose→Co-sign→Confirm protocol with real
                // SMT proofs and single shared chain tip validation.
                let _ = commitment_hash;
                BiResult {
                    success: false,
                    result_data: vec![],
                    error_message: Some(
                        "bilateral.accept disabled. Use BLE session engine (3-step Propose→Co-sign→Confirm).".into(),
                    ),
                }
            }
            Err(e) => BiResult {
                success: false,
                result_data: vec![],
                error_message: Some(format!("decode BilateralAcceptRequest failed: {e}")),
            },
        }
    }

    /// Commit phase: validate commitment hash and persist with real signatures.
    async fn commit(&self, c: BiCommit) -> BiResult {
        match pb::BilateralCommitRequest::decode(&*c.payload) {
            Ok(req) => {
                // Validate counterparty_device_id
                if req.counterparty_device_id.len() != 32 {
                    return BiResult {
                        success: false,
                        result_data: vec![],
                        error_message: Some(format!(
                            "counterparty_device_id must be 32 bytes (got {})",
                            req.counterparty_device_id.len()
                        )),
                    };
                }

                let commitment = match req.commitment_hash {
                    Some(ref h) if h.v.len() == 32 => h.v.clone(),
                    Some(h) => {
                        return BiResult {
                            success: false,
                            result_data: vec![],
                            error_message: Some(format!(
                                "commitment_hash must be 32 bytes (got {})",
                                h.v.len()
                            )),
                        };
                    }
                    None => {
                        return BiResult {
                            success: false,
                            result_data: vec![],
                            error_message: Some("commitment_hash missing".into()),
                        };
                    }
                };

                // Validate signatures are present
                if req.local_signature.is_empty() {
                    return BiResult {
                        success: false,
                        result_data: vec![],
                        error_message: Some("local_signature missing".into()),
                    };
                }
                if req.counterparty_sig.is_empty() {
                    return BiResult {
                        success: false,
                        result_data: vec![],
                        error_message: Some("counterparty_sig missing".into()),
                    };
                }

                // Fail-closed: commit is performed by the BLE session engine
                // using BilateralConfirm (3rd direction change) with real
                // stitched receipts, SMT inclusion proofs, and shared chain
                // tip advancement via compute_successor_tip().
                let _ = commitment;
                BiResult {
                    success: false,
                    result_data: vec![],
                    error_message: Some(
                        "bilateral.commit disabled. Use BLE session engine (3-step Propose→Co-sign→Confirm with BilateralConfirmRequest).".into(),
                    ),
                }
            }
            Err(e) => BiResult {
                success: false,
                result_data: vec![],
                error_message: Some(format!("decode BilateralCommitRequest failed: {e}")),
            },
        }
    }

    /// Transfer method: strict validation only.
    async fn transfer(&self, t: BiTransfer) -> BiResult {
        // Helper: read first 8 bytes little-endian as u64 (0 if insufficient length)
        fn first8_le_u64(bytes: &[u8]) -> u64 {
            if bytes.len() < 8 {
                return 0;
            }
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&bytes[..8]);
            u64::from_le_bytes(arr)
        }

        match pb::BilateralTransferRequest::decode(&*t.payload) {
            Ok(req) => {
                // Validate mandatory bytes-only fields deterministically
                if req.counterparty_device_id.len() != 32 {
                    return BiResult {
                        success: false,
                        result_data: vec![],
                        error_message: Some("counterparty_device_id must be 32 bytes".into()),
                    };
                }

                let commitment = match &req.commitment_hash {
                    Some(h) if h.v.len() == 32 => h.v.clone(),
                    Some(h) => {
                        return BiResult {
                            success: false,
                            result_data: vec![],
                            error_message: Some(format!(
                                "commitment_hash must be 32 bytes (got {})",
                                h.v.len()
                            )),
                        };
                    }
                    None => {
                        return BiResult {
                            success: false,
                            result_data: vec![],
                            error_message: Some("commitment_hash missing".into()),
                        };
                    }
                };

                if !matches!(req.expected_genesis_hash.as_ref(), Some(h) if h.v.len() == 32) {
                    return BiResult {
                        success: false,
                        result_data: vec![],
                        error_message: Some(
                            "expected_genesis_hash must be present (32 bytes)".into(),
                        ),
                    };
                }
                if !matches!(
                    req.expected_counterparty_state_hash.as_ref(),
                    Some(h) if h.v.len() == 32
                ) {
                    return BiResult {
                        success: false,
                        result_data: vec![],
                        error_message: Some(
                            "expected_counterparty_state_hash must be present (32 bytes)".into(),
                        ),
                    };
                }
                if !matches!(req.expected_local_state_hash.as_ref(), Some(h) if h.v.len() == 32) {
                    return BiResult {
                        success: false,
                        result_data: vec![],
                        error_message: Some(
                            "expected_local_state_hash must be present (32 bytes)".into(),
                        ),
                    };
                }
                if req.counterparty_sig.is_empty() {
                    return BiResult {
                        success: false,
                        result_data: vec![],
                        error_message: Some("counterparty_sig must be non-empty".into()),
                    };
                }

                // Parse amount from operation_data (first 8 bytes LE) and require non-zero
                let amount = first8_le_u64(&req.operation_data);
                if amount == 0 {
                    return BiResult {
                        success: false,
                        result_data: vec![],
                        error_message: Some("amount must be non-zero".into()),
                    };
                }

                // Fail-closed: this handler must not acknowledge transfers without the real
                // BLE session engine producing/verifying real receipt bytes.
                let _ = commitment;
                let _ = amount;
                BiResult {
                    success: false,
                    result_data: vec![],
                    error_message: Some(
                        "bilateral.transfer disabled (no synthetic transfer). Use BLE session prepare/accept/commit flow.".into(),
                    ),
                }
            }
            Err(e) => BiResult {
                success: false,
                result_data: vec![],
                error_message: Some(format!("decode BilateralTransferRequest failed: {e}")),
            },
        }
    }

    async fn get_pending_transactions(&self) -> Result<Vec<Vec<u8>>, String> {
        // Pending transactions are tracked via BilateralBleHandler sessions.
        // The BLE coordinator handles all session state; no separate SDK needed.
        Ok(vec![])
    }

    async fn reconcile_before_send(&self, counterparty_device_id: &[u8]) -> Result<(), String> {
        // Clear the `needs_online_reconcile` flag before each send.
        // IMPORTANT: Only clear the flag — do NOT pass a zero tip to
        // update_contact_chain_tip_after_bilateral here. Doing so would destroy
        // the real SQLite chain tip, causing the Prepare to go out with
        // sender_chain_tip=0000… and be rejected by the receiver every time.
        if let Err(e) =
            crate::storage::client_db::clear_contact_reconcile_flag(counterparty_device_id)
        {
            log::warn!("[bilateral] reconcile_before_send: could not clear reconcile flag: {e}");
        }
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
