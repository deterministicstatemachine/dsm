// SPDX-License-Identifier: MIT OR Apache-2.0

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use log::{debug, info, warn};
use dsm::types::error::DsmError;

use crate::bluetooth::bilateral_ble_handler::BilateralBleHandler;
use crate::bluetooth::ble_frame_coordinator::BleFrameType;

pub type DelegateFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportInboundMessage {
    pub peer_address: String,
    pub frame_type: BleFrameType,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportOutbound {
    pub peer_address: Option<String>,
    pub frame_type: BleFrameType,
    pub payload: Vec<u8>,
}

impl TransportOutbound {
    #[must_use]
    pub fn new(frame_type: BleFrameType, payload: Vec<u8>) -> Self {
        Self {
            peer_address: None,
            frame_type,
            payload,
        }
    }
}

pub trait BleTransportDelegate: Send + Sync + 'static {
    fn on_transport_message(
        &self,
        message: TransportInboundMessage,
    ) -> DelegateFuture<Result<Vec<TransportOutbound>, DsmError>>;

    fn on_peer_disconnected(&self, peer_address: String) -> DelegateFuture<()>;
}

pub struct BilateralTransportAdapter {
    bilateral_handler: Arc<BilateralBleHandler>,
    /// Path-B raw-SPI counter relay router (D2): services `TropicSpiRelay` frames on both ends —
    /// sender A forwards to its local Pico, receiver B resolves its pending round-trips.
    tropic_relay: Arc<crate::bluetooth::tropic_relay::TropicRelayRouter>,
}

impl BilateralTransportAdapter {
    #[must_use]
    pub fn new(bilateral_handler: Arc<BilateralBleHandler>) -> Self {
        Self {
            bilateral_handler,
            tropic_relay: Arc::new(crate::bluetooth::tropic_relay::TropicRelayRouter::new()),
        }
    }

    #[must_use]
    pub fn bilateral_handler(&self) -> &Arc<BilateralBleHandler> {
        &self.bilateral_handler
    }

    /// The Path-B counter-relay router. On a sender device, install the local Pico link via
    /// `router.set_local_pico(...)`. The receiver drives round-trips through it for the counter read:
    /// the on-device layer wires `router.round_trip(commitment, mosi, |frame| queue_relay_frame(peer,
    /// frame))` into `dsm_anchor_hw_verifier::read_counter_over_relay` (that reader depends on
    /// `tropic01` and lives in the excluded hardware crate, so it is not referenced here).
    #[must_use]
    pub fn tropic_relay(&self) -> &Arc<crate::bluetooth::tropic_relay::TropicRelayRouter> {
        &self.tropic_relay
    }

    /// Send one Path-B relay frame to `peer_address` over BLE (`TropicSpiRelay`). The on-device
    /// receiver layer uses this as the `send` closure inside `TropicRelayRouter::round_trip`.
    pub async fn queue_relay_frame(peer_address: &str, frame: &[u8]) -> Result<(), DsmError> {
        queue_follow_up_chunks(peer_address, BleFrameType::TropicSpiRelay, frame).await
    }

    /// Send a secondary-device admission REQUEST envelope to the existing device over BLE
    /// (NEW-device initiate). Chunked transport (the admission is too large for QR).
    pub async fn send_admission_request(
        &self,
        peer_address: &str,
        envelope: &[u8],
    ) -> Result<(), DsmError> {
        queue_follow_up_chunks(peer_address, BleFrameType::DeviceAdmissionRequest, envelope).await
    }

    /// Send a gate-signed admission RESPONSE envelope back to the new device over BLE
    /// (EXISTING-device approve). Chunked transport.
    pub async fn send_admission_response(
        &self,
        peer_address: &str,
        envelope: &[u8],
    ) -> Result<(), DsmError> {
        queue_follow_up_chunks(
            peer_address,
            BleFrameType::DeviceAdmissionResponse,
            envelope,
        )
        .await
    }

    pub async fn cancel_prepared_session_for_counterparty(&self, counterparty_device_id: [u8; 32]) {
        self.bilateral_handler
            .cancel_prepared_session_for_counterparty(counterparty_device_id)
            .await;
    }

    pub async fn fail_session_by_commitment(
        &self,
        commitment_hash: [u8; 32],
        reason: &str,
    ) -> bool {
        self.bilateral_handler
            .fail_session_by_commitment(commitment_hash, reason)
            .await
    }

    pub async fn create_prepare_message(
        &self,
        counterparty_device_id: [u8; 32],
        operation: dsm::types::operations::Operation,
        validity_iterations: u64,
    ) -> Result<Vec<u8>, DsmError> {
        let (envelope_bytes, _) = self
            .bilateral_handler
            .prepare_bilateral_transaction_with_commitment(
                counterparty_device_id,
                operation,
                validity_iterations,
            )
            .await?;
        Ok(envelope_bytes)
    }

    pub async fn create_prepare_message_with_commitment(
        &self,
        counterparty_device_id: [u8; 32],
        operation: dsm::types::operations::Operation,
        validity_iterations: u64,
    ) -> Result<(Vec<u8>, [u8; 32]), DsmError> {
        self.bilateral_handler
            .prepare_bilateral_transaction_with_commitment(
                counterparty_device_id,
                operation,
                validity_iterations,
            )
            .await
    }

    pub async fn create_prepare_accept_envelope(
        &self,
        commitment_hash: [u8; 32],
    ) -> Result<Vec<u8>, DsmError> {
        self.bilateral_handler
            .create_prepare_accept_envelope(commitment_hash)
            .await
    }

    pub async fn create_prepare_accept_envelope_with_counterparty(
        &self,
        commitment_hash: [u8; 32],
    ) -> Result<(Vec<u8>, [u8; 32]), DsmError> {
        self.bilateral_handler
            .create_prepare_accept_envelope_with_counterparty(commitment_hash)
            .await
    }

    pub async fn create_prepare_reject_envelope_with_cleanup(
        &self,
        commitment_hash: [u8; 32],
        reason: String,
    ) -> Result<Vec<u8>, DsmError> {
        self.bilateral_handler
            .create_prepare_reject_envelope_with_cleanup(commitment_hash, reason)
            .await
    }

    pub async fn sender_ble_address_for_commitment(
        &self,
        commitment_hash: [u8; 32],
    ) -> Option<String> {
        self.bilateral_handler
            .get_session_for_commitment(&commitment_hash)
            .await
            .and_then(|session| session.sender_ble_address)
            .filter(|address| !address.is_empty())
    }

    pub async fn counterparty_for_commitment(&self, commitment_hash: [u8; 32]) -> Option<[u8; 32]> {
        self.bilateral_handler
            .get_counterparty_for_commitment(&commitment_hash)
            .await
    }
}

#[cfg(all(target_os = "android", feature = "bluetooth", feature = "jni"))]
async fn queue_follow_up_chunks(
    peer_address: &str,
    frame_type: BleFrameType,
    payload: &[u8],
) -> Result<(), DsmError> {
    let coordinator = crate::bridge::get_ble_coordinator().await.map_err(|e| {
        DsmError::invalid_operation(format!("BLE coordinator not ready for follow-up: {e}"))
    })?;

    let chunks = coordinator
        .encode_message(frame_type, payload)
        .map_err(|e| DsmError::invalid_operation(format!("BLE follow-up framing failed: {e}")))?;

    crate::jni::jni_common::with_env(|env| {
        let mut env = unsafe { jni::JNIEnv::from_raw(env.get_raw() as *mut _) }
            .map_err(|e| format!("clone JNIEnv failed: {e}"))?;
        match crate::jni::unified_protobuf_bridge::send_ble_chunks_via_unified(
            &mut env,
            peer_address,
            &chunks,
        )? {
            true => Ok(()),
            false => Err("requestGattWriteChunks returned false".to_string()),
        }
    })
    .map_err(|e| DsmError::invalid_operation(format!("BLE follow-up dispatch failed: {e}")))
}

#[cfg(not(all(target_os = "android", feature = "bluetooth", feature = "jni")))]
async fn queue_follow_up_chunks(
    _peer_address: &str,
    _frame_type: BleFrameType,
    _payload: &[u8],
) -> Result<(), DsmError> {
    Err(DsmError::invalid_operation(
        "BLE follow-up dispatch requires Android JNI Bluetooth build".to_string(),
    ))
}

/// Route a `handle_prepare_response` reply to its BLE frame by the returned envelope's payload
/// (§21 first-transfer split). `handle_prepare_response` returns EITHER the confirm (ordinary +
/// subsequent bearer) OR a `BilateralBearerPrepared` disclosure (first-transfer bearer, pre-commit).
/// Exhaustive + hostile by default: only those two are routable; anything else is `None` →
/// fail-closed at the call site (never a best-effort frame guess).
fn classify_prepare_response_reply(envelope_bytes: &[u8]) -> Option<BleFrameType> {
    let env = crate::envelope::from_canonical_bytes(envelope_bytes).ok()?;
    match env.payload {
        // The confirm rides a UniversalTx with the "bilateral.confirm" invoke method.
        Some(crate::generated::envelope::Payload::UniversalTx(ref tx)) => tx
            .ops
            .first()
            .is_some_and(|op| {
                matches!(
                    &op.kind,
                    Some(crate::generated::universal_op::Kind::Invoke(inv))
                        if inv.method == "bilateral.confirm"
                )
            })
            .then_some(BleFrameType::BilateralConfirm),
        Some(crate::generated::envelope::Payload::BilateralBearerPrepared(_)) => {
            Some(BleFrameType::BilateralBearerPrepared)
        }
        _ => None,
    }
}

impl BleTransportDelegate for BilateralTransportAdapter {
    fn on_transport_message(
        &self,
        message: TransportInboundMessage,
    ) -> DelegateFuture<Result<Vec<TransportOutbound>, DsmError>> {
        let bilateral_handler = Arc::clone(&self.bilateral_handler);
        let tropic_relay = Arc::clone(&self.tropic_relay);
        Box::pin(async move {
            match message.frame_type {
                BleFrameType::BilateralPrepare => {
                    info!("Processing bilateral prepare request via transport adapter");
                    match bilateral_handler
                        .handle_prepare_request(
                            &message.payload,
                            Some(message.peer_address.clone()),
                        )
                        .await
                    {
                        Ok((response, _meta)) => {
                            if crate::bluetooth::manual_accept_enabled() {
                                debug!(
                                    "Manual accept enabled; suppressing immediate prepare response for {}",
                                    message.peer_address
                                );
                                Ok(Vec::new())
                            } else {
                                Ok(vec![TransportOutbound::new(
                                    BleFrameType::BilateralPrepareResponse,
                                    response,
                                )])
                            }
                        }
                        Err(e) if e.to_string().contains("silent_drop_duplicate_packet") => {
                            warn!("Silently dropping duplicate Prepare request.");
                            Ok(Vec::new())
                        }
                        Err(e) => {
                            warn!("BilateralPrepare rejected: {e}. Ensure contact is added/verified and synced to BluetoothManager.");
                            Err(e)
                        }
                    }
                }
                BleFrameType::BilateralPrepareResponse => {
                    let is_prepare_response =
                        match crate::envelope::from_canonical_bytes(&message.payload) {
                            Ok(env) => {
                                matches!(
                            env.payload,
                            Some(crate::generated::envelope::Payload::BilateralPrepareResponse(_))
                        )
                            }
                            Err(_) => false,
                        };
                    if !is_prepare_response {
                        debug!(
                            "Pass-through BilateralPrepareResponse frame (non-prepare-response envelope detected) size={}",
                            message.payload.len()
                        );
                        return Ok(vec![TransportOutbound::new(
                            BleFrameType::BilateralPrepareResponse,
                            message.payload,
                        )]);
                    }

                    match bilateral_handler
                        .handle_prepare_response(&message.payload)
                        .await
                    {
                        // Payload-type routing (§21 first-transfer split): the reply is EITHER the
                        // confirm or the BilateralBearerPrepared disclosure. Route by payload,
                        // exhaustively and fail-closed — never guess the frame.
                        Ok((reply_envelope, _meta)) => {
                            match classify_prepare_response_reply(&reply_envelope) {
                                Some(frame) => {
                                    Ok(vec![TransportOutbound::new(frame, reply_envelope)])
                                }
                                None => Err(DsmError::invalid_operation(
                                    "handle_prepare_response returned an unroutable reply (fail-closed)"
                                        .to_string(),
                                )),
                            }
                        }
                        Err(e) if e.to_string().contains("silent_drop_duplicate_packet") => {
                            warn!("Silently dropping duplicate Prepare Response.");
                            Ok(Vec::new())
                        }
                        Err(e) => Err(e),
                    }
                }
                BleFrameType::BilateralPrepareReject => {
                    let is_prepare_reject =
                        match crate::envelope::from_canonical_bytes(&message.payload) {
                            Ok(env) => matches!(
                                env.payload,
                                Some(crate::generated::envelope::Payload::BilateralPrepareReject(
                                    _
                                ))
                            ),
                            Err(_) => false,
                        };
                    if !is_prepare_reject {
                        debug!(
                            "Pass-through BilateralPrepareReject frame (non-reject envelope detected) size={}",
                            message.payload.len()
                        );
                        return Ok(vec![TransportOutbound::new(
                            BleFrameType::BilateralPrepareReject,
                            message.payload,
                        )]);
                    }

                    bilateral_handler
                        .handle_prepare_reject(&message.payload)
                        .await?;
                    Ok(Vec::new())
                }
                BleFrameType::BilateralConfirm => {
                    let is_confirm_request =
                        match crate::envelope::from_canonical_bytes(&message.payload) {
                            Ok(env) => {
                                if let Some(crate::generated::envelope::Payload::UniversalTx(tx)) =
                                    env.payload
                                {
                                    if let Some(op) = tx.ops.first() {
                                        match &op.kind {
                                            Some(crate::generated::universal_op::Kind::Invoke(
                                                invoke,
                                            )) => invoke.method == "bilateral.confirm",
                                            _ => false,
                                        }
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                }
                            }
                            Err(_) => false,
                        };
                    if !is_confirm_request {
                        debug!(
                            "Pass-through BilateralConfirm frame (non-confirm UniversalTx detected) size={}",
                            message.payload.len()
                        );
                        return Ok(vec![TransportOutbound::new(
                            BleFrameType::BilateralConfirm,
                            message.payload,
                        )]);
                    }

                    // Spawn the confirm handler on the tokio runtime instead of
                    // awaiting inline. The GATT callback thread enters Rust via
                    // block_on(), and handle_confirm_request acquires
                    // bilateral_tx_manager read+write locks. If any other tokio
                    // task holds a write lock, block_on deadlocks because it
                    // cannot yield the thread. Spawning detaches the heavy
                    // state-machine work from the GATT thread, then routes the
                    // receiver's terminal acknowledgment back over BLE.
                    {
                        let handler = bilateral_handler;
                        let payload = message.payload;
                        let peer_address = message.peer_address;
                        tokio::spawn(async move {
                            match handler.handle_confirm_request(&payload).await {
                                Ok(ack_envelope) => {
                                    match queue_follow_up_chunks(
                                        &peer_address,
                                        BleFrameType::BilateralCommitResponse,
                                        &ack_envelope,
                                    )
                                    .await
                                    {
                                        Ok(()) => {
                                            info!("[BILATERAL] Confirm handler completed successfully and queued receiver ack");
                                        }
                                        Err(e) => {
                                            log::error!(
                                                "[BILATERAL] Receiver ack dispatch failed: {e}"
                                            );
                                        }
                                    }
                                }
                                Err(e)
                                    if e.to_string().contains("silent_drop_duplicate_packet") =>
                                {
                                    warn!(
                                        "[BILATERAL] Silently dropping duplicate Confirm Request."
                                    );
                                }
                                Err(e) => {
                                    log::error!("[BILATERAL] Confirm handler failed: {e}");
                                }
                            }
                        });
                        Ok(Vec::new())
                    }
                }
                BleFrameType::BilateralCommitResponse => {
                    let is_commit_response =
                        match crate::envelope::from_canonical_bytes(&message.payload) {
                            Ok(env) => {
                                matches!(
                            env.payload,
                            Some(crate::generated::envelope::Payload::BilateralCommitResponse(_))
                        )
                            }
                            Err(_) => false,
                        };
                    if !is_commit_response {
                        debug!(
                            "Pass-through BilateralCommitResponse frame (non-commit-response envelope detected) size={}",
                            message.payload.len()
                        );
                        return Ok(vec![TransportOutbound::new(
                            BleFrameType::BilateralCommitResponse,
                            message.payload,
                        )]);
                    }

                    bilateral_handler
                        .handle_commit_response(&message.payload)
                        .await?;
                    Ok(Vec::new())
                }
                // Secondary-device admission (§16.3). REQUEST: the existing device holds it pending
                // the owner's explicit approval (the gate) — no immediate response. RESPONSE: the
                // new device verifies + adopts.
                BleFrameType::DeviceAdmissionRequest => {
                    match crate::sdk::DeviceAdmissionSDK::receive_admission_request(
                        &message.payload,
                        &message.peer_address,
                    ) {
                        Ok(new_id) => {
                            info!(
                                "[ADMISSION] request from {} held pending owner approval (device {})",
                                message.peer_address, new_id
                            );
                            Ok(Vec::new())
                        }
                        Err(e) => {
                            warn!("[ADMISSION] request rejected: {e}");
                            Err(e)
                        }
                    }
                }
                BleFrameType::DeviceAdmissionResponse => {
                    match crate::sdk::DeviceAdmissionSDK::handle_admission_response(
                        &message.payload,
                    )
                    .await
                    {
                        Ok((_genesis, _new_id)) => {
                            info!("[ADMISSION] adopted into the device tree");
                            Ok(Vec::new())
                        }
                        Err(e) => {
                            warn!("[ADMISSION] adopt failed: {e}");
                            Err(e)
                        }
                    }
                }
                BleFrameType::TropicSpiRelay => {
                    // Path-B raw-SPI counter relay (D2). One relayed SPI transaction: on the sender
                    // (from_receiver=true) forward to the local Pico and reply; on the receiver
                    // (from_receiver=false) resolve the pending round-trip. The router decides by the
                    // packet's direction. Opaque bytes only — no anchor/counter semantics here.
                    match tropic_relay.handle_inbound(&message.payload).await {
                        Ok(Some(reply)) => Ok(vec![TransportOutbound::new(
                            BleFrameType::TropicSpiRelay,
                            reply,
                        )]),
                        Ok(None) => Ok(Vec::new()),
                        Err(e) => {
                            warn!("TROPIC_SPI_RELAY handling failed (fail-closed): {e}");
                            Ok(Vec::new())
                        }
                    }
                }
                BleFrameType::Unspecified => Ok(vec![TransportOutbound::new(
                    BleFrameType::Unspecified,
                    message.payload,
                )]),
                // §21 first-transfer round-trip. Handlers are wired in later stages (#3 stages 5–6);
                // until then these are fail-closed no-ops. The sender does not emit these frames yet
                // (stage 4), so they are unreachable in production — a peer sending one early is
                // dropped and first-transfer simply stays on the online fallback.
                BleFrameType::BilateralBearerPrepared => {
                    debug!("BilateralBearerPrepared received before handler wired; dropping (fail-closed)");
                    Ok(Vec::new())
                }
                BleFrameType::BilateralBearerProceed => {
                    debug!("BilateralBearerProceed received before handler wired; dropping (fail-closed)");
                    Ok(Vec::new())
                }
                _ => {
                    debug!("Ignoring unknown BLE frame type: {:?}", message.frame_type);
                    Ok(Vec::new())
                }
            }
        })
    }

    fn on_peer_disconnected(&self, peer_address: String) -> DelegateFuture<()> {
        let bilateral_handler = Arc::clone(&self.bilateral_handler);
        Box::pin(async move {
            let failed = bilateral_handler
                .handle_peer_disconnected(&peer_address)
                .await;
            if failed > 0 {
                info!(
                    "BLE disconnect {peer_address}: failed {failed} in-flight bilateral session(s)"
                );
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_outbound_new_sets_fields() {
        let payload = vec![1, 2, 3, 4];
        let out = TransportOutbound::new(BleFrameType::BilateralPrepare, payload.clone());
        assert_eq!(out.frame_type, BleFrameType::BilateralPrepare);
        assert_eq!(out.payload, payload);
        assert!(out.peer_address.is_none());
    }

    #[test]
    fn transport_outbound_new_unspecified() {
        let out = TransportOutbound::new(BleFrameType::Unspecified, vec![]);
        assert_eq!(out.frame_type, BleFrameType::Unspecified);
        assert!(out.payload.is_empty());
    }

    #[test]
    fn transport_inbound_message_equality() {
        let m1 = TransportInboundMessage {
            peer_address: "AA:BB:CC:DD:EE:FF".to_string(),
            frame_type: BleFrameType::BilateralConfirm,
            payload: vec![0xFF; 16],
        };
        let m2 = m1.clone();
        assert_eq!(m1, m2);
    }

    #[test]
    fn transport_inbound_message_inequality_payload() {
        let m1 = TransportInboundMessage {
            peer_address: "addr".to_string(),
            frame_type: BleFrameType::BilateralPrepare,
            payload: vec![1],
        };
        let m2 = TransportInboundMessage {
            peer_address: "addr".to_string(),
            frame_type: BleFrameType::BilateralPrepare,
            payload: vec![2],
        };
        assert_ne!(m1, m2);
    }

    #[test]
    fn transport_inbound_message_inequality_frame_type() {
        let m1 = TransportInboundMessage {
            peer_address: "addr".to_string(),
            frame_type: BleFrameType::BilateralPrepare,
            payload: vec![],
        };
        let m2 = TransportInboundMessage {
            peer_address: "addr".to_string(),
            frame_type: BleFrameType::BilateralConfirm,
            payload: vec![],
        };
        assert_ne!(m1, m2);
    }

    #[test]
    fn transport_outbound_clone() {
        let out = TransportOutbound {
            peer_address: Some("peer".to_string()),
            frame_type: BleFrameType::Ack,
            payload: vec![0xAB; 8],
        };
        let cloned = out.clone();
        assert_eq!(out, cloned);
    }

    #[test]
    fn transport_outbound_debug() {
        let out = TransportOutbound::new(BleFrameType::Nack, vec![]);
        let dbg = format!("{:?}", out);
        assert!(dbg.contains("Nack"));
    }
}
