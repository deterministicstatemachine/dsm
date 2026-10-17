// SPDX-License-Identifier: MIT OR Apache-2.0

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use log::{info, warn};
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
}

pub struct BilateralTransportAdapter {
    bilateral_handler: Arc<BilateralBleHandler>,
}

impl BilateralTransportAdapter {
    #[must_use]
    pub fn new(bilateral_handler: Arc<BilateralBleHandler>) -> Self {
        Self { bilateral_handler }
    }

    #[must_use]
    pub fn bilateral_handler(&self) -> &Arc<BilateralBleHandler> {
        &self.bilateral_handler
    }

    pub async fn create_prepare_message(
        &self,
        counterparty_device_id: [u8; 32],
        operation: dsm::types::operations::Operation,
    ) -> Result<Vec<u8>, DsmError> {
        let (envelope_bytes, _) = self
            .bilateral_handler
            .prepare_bilateral_transaction_with_commitment(counterparty_device_id, operation)
            .await?;
        Ok(envelope_bytes)
    }

    pub async fn create_prepare_message_with_commitment(
        &self,
        counterparty_device_id: [u8; 32],
        operation: dsm::types::operations::Operation,
    ) -> Result<(Vec<u8>, [u8; 32]), DsmError> {
        self.bilateral_handler
            .prepare_bilateral_transaction_with_commitment(counterparty_device_id, operation)
            .await
    }

    /// A transfer's prepare: the operation and, beside it, the terms it
    /// commits to (pre-audit item 4).
    pub async fn create_transfer_prepare_with_commitment(
        &self,
        counterparty_device_id: [u8; 32],
        operation: dsm::types::operations::Operation,
        terms: dsm::types::operations::TransferTerms,
    ) -> Result<(Vec<u8>, [u8; 32]), DsmError> {
        self.bilateral_handler
            .prepare_bilateral_transfer_with_commitment(counterparty_device_id, operation, terms)
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
        // The ack answers the confirm on the link it arrived on; a lost ack is
        // answered again when the sender sends its confirm again.
        match crate::jni::unified_protobuf_bridge::send_ble_reply_on_link(
            &mut env,
            peer_address,
            &chunks,
        )? {
            true => Ok(()),
            false => Err("the reply's link is gone".to_string()),
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

/// Route a `handle_prepare_request` reply to its BLE frame by the returned
/// envelope's payload: the response a proposal delivered again is owed, or a
/// signed rejection. Anything else is `None` → fail-closed at the call site.
fn classify_prepare_reply(envelope_bytes: &[u8]) -> Option<BleFrameType> {
    let env = crate::envelope::from_canonical_bytes(envelope_bytes).ok()?;
    match env.payload {
        Some(crate::generated::envelope::Payload::BilateralPrepareResponse(_)) => {
            Some(BleFrameType::BilateralPrepareResponse)
        }
        Some(crate::generated::envelope::Payload::BilateralPrepareReject(_)) => {
            Some(BleFrameType::BilateralPrepareReject)
        }
        _ => None,
    }
}

/// Route a `handle_prepare_response` reply to its BLE frame by the returned envelope's payload:
/// the confirm (a UniversalTx invoking "bilateral.confirm"), or the signed cancellation of a
/// proposal this device cancelled. Anything else is `None` → fail-closed at the call site
/// (never a best-effort frame guess).
fn classify_prepare_response_reply(envelope_bytes: &[u8]) -> Option<BleFrameType> {
    let env = crate::envelope::from_canonical_bytes(envelope_bytes).ok()?;
    match env.payload {
        Some(crate::generated::envelope::Payload::BilateralPrepareReject(_)) => {
            Some(BleFrameType::BilateralPrepareReject)
        }
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
        _ => None,
    }
}

/// The frames the bilateral transport takes, each known by its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BilateralFrame {
    Prepare,
    PrepareResponse,
    PrepareReject,
    Confirm,
    CommitResponse,
}

impl BilateralFrame {
    /// The frame `envelope` carries: a prepare-response, prepare-reject or
    /// commit-response payload, or a transaction of exactly one op invoking
    /// `bilateral.prepare` or `bilateral.confirm` (the step parsers take one
    /// op only). `None` for anything else.
    #[must_use]
    pub fn of(envelope: &crate::generated::Envelope) -> Option<Self> {
        use crate::generated::{envelope::Payload, universal_op::Kind, UniversalOp};
        match &envelope.payload {
            Some(Payload::BilateralPrepareResponse(_)) => Some(Self::PrepareResponse),
            Some(Payload::BilateralPrepareReject(_)) => Some(Self::PrepareReject),
            Some(Payload::BilateralCommitResponse(_)) => Some(Self::CommitResponse),
            Some(Payload::UniversalTx(tx)) => match tx.ops.as_slice() {
                [UniversalOp {
                    kind: Some(Kind::Invoke(invoke)),
                    ..
                }] => match invoke.method.as_str() {
                    "bilateral.prepare" => Some(Self::Prepare),
                    "bilateral.confirm" => Some(Self::Confirm),
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        }
    }

    /// The BLE frame type this frame travels under.
    #[must_use]
    pub fn frame_type(self) -> BleFrameType {
        match self {
            Self::Prepare => BleFrameType::BilateralPrepare,
            Self::PrepareResponse => BleFrameType::BilateralPrepareResponse,
            Self::PrepareReject => BleFrameType::BilateralPrepareReject,
            Self::Confirm => BleFrameType::BilateralConfirm,
            Self::CommitResponse => BleFrameType::BilateralCommitResponse,
        }
    }
}

/// The frame a message is, when its payload bears out the frame type it
/// arrived under. A frame type is the sender's claim: a payload that is not
/// that frame, a frame type the bilateral transport does not take, and bytes
/// that are not a canonical envelope are refused, and nothing is sent back.
fn frame_borne_out(message: &TransportInboundMessage) -> Result<BilateralFrame, DsmError> {
    let envelope = crate::envelope::from_canonical_bytes(&message.payload).map_err(|e| {
        DsmError::invalid_operation(format!(
            "a {:?} frame that is not a canonical envelope: {e}",
            message.frame_type
        ))
    })?;
    match BilateralFrame::of(&envelope) {
        Some(frame) if frame.frame_type() == message.frame_type => Ok(frame),
        carried => Err(DsmError::invalid_operation(format!(
            "a {:?} frame whose payload is {carried:?}: not taken, nothing sent back",
            message.frame_type
        ))),
    }
}

impl BleTransportDelegate for BilateralTransportAdapter {
    fn on_transport_message(
        &self,
        message: TransportInboundMessage,
    ) -> DelegateFuture<Result<Vec<TransportOutbound>, DsmError>> {
        let bilateral_handler = Arc::clone(&self.bilateral_handler);
        Box::pin(async move {
            match frame_borne_out(&message)? {
                BilateralFrame::Prepare => {
                    info!("Processing bilateral prepare request via transport adapter");
                    match bilateral_handler
                        .handle_prepare_request(
                            &message.payload,
                            Some(message.peer_address.clone()),
                        )
                        .await
                    {
                        // A new proposal waits for its user and answers nothing;
                        // one delivered again is answered with what it is owed.
                        Ok((reply, _meta)) if reply.is_empty() => Ok(Vec::new()),
                        Ok((reply, _meta)) => match classify_prepare_reply(&reply) {
                            Some(frame) => Ok(vec![TransportOutbound::new(frame, reply)]),
                            None => Err(DsmError::invalid_operation(
                                "handle_prepare_request returned an unroutable reply (fail-closed)"
                                    .to_string(),
                            )),
                        },
                        Err(e) => {
                            warn!("BilateralPrepare rejected: {e}. Ensure contact is added/verified and synced to BluetoothManager.");
                            Err(e)
                        }
                    }
                }
                BilateralFrame::PrepareResponse => {
                    match bilateral_handler
                        .handle_prepare_response(&message.payload)
                        .await
                    {
                        // Payload-type routing: only the confirm is routable. Route by payload,
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
                        Err(e) => Err(e),
                    }
                }
                BilateralFrame::PrepareReject => {
                    bilateral_handler
                        .handle_prepare_reject(&message.payload)
                        .await?;
                    Ok(Vec::new())
                }
                BilateralFrame::Confirm => {
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
                                Err(e) => {
                                    log::error!("[BILATERAL] Confirm handler failed: {e}");
                                }
                            }
                        });
                        Ok(Vec::new())
                    }
                }
                BilateralFrame::CommitResponse => {
                    bilateral_handler
                        .handle_commit_response(&message.payload)
                        .await?;
                    Ok(Vec::new())
                }
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
