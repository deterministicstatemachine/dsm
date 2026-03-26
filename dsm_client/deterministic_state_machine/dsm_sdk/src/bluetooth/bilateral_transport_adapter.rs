use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use log::{debug, info, warn};
use prost::Message;

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

    pub async fn cancel_prepared_session_for_counterparty(&self, counterparty_device_id: [u8; 32]) {
        self.bilateral_handler
            .cancel_prepared_session_for_counterparty(counterparty_device_id)
            .await;
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

    pub async fn mark_confirm_delivered(&self, commitment_hash: [u8; 32]) -> Result<(), DsmError> {
        self.bilateral_handler
            .mark_confirm_delivered(commitment_hash)
            .await
    }

    pub async fn mark_any_confirm_pending_delivered(&self) -> Result<usize, DsmError> {
        self.bilateral_handler
            .mark_any_confirm_pending_delivered()
            .await
    }
}

impl BleTransportDelegate for BilateralTransportAdapter {
    fn on_transport_message(
        &self,
        message: TransportInboundMessage,
    ) -> DelegateFuture<Result<Vec<TransportOutbound>, DsmError>> {
        let bilateral_handler = Arc::clone(&self.bilateral_handler);
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
                    let is_prepare_response = match crate::generated::Envelope::decode(
                        &mut std::io::Cursor::new(&message.payload),
                    ) {
                        Ok(env) => matches!(
                            env.payload,
                            Some(crate::generated::envelope::Payload::BilateralPrepareResponse(_))
                        ),
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
                        Ok((commit_envelope, _meta)) => Ok(vec![TransportOutbound::new(
                            BleFrameType::BilateralConfirm,
                            commit_envelope,
                        )]),
                        Err(e) if e.to_string().contains("silent_drop_duplicate_packet") => {
                            warn!("Silently dropping duplicate Prepare Response.");
                            Ok(Vec::new())
                        }
                        Err(e) => Err(e),
                    }
                }
                BleFrameType::BilateralPrepareReject => {
                    let is_prepare_reject = match crate::generated::Envelope::decode(
                        &mut std::io::Cursor::new(&message.payload),
                    ) {
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
                    let is_confirm_request = match crate::generated::Envelope::decode(
                        &mut std::io::Cursor::new(&message.payload),
                    ) {
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
                    // state-machine work from the GATT thread. The confirm
                    // handler returns no response data (Ok(Vec::new())), so the
                    // caller does not need the result.
                    {
                        let handler = bilateral_handler;
                        let payload = message.payload;
                        tokio::spawn(async move {
                            match handler.handle_confirm_request(&payload).await {
                                Ok(_meta) => {
                                    info!("[BILATERAL] Confirm handler completed successfully");
                                }
                                Err(e) if e.to_string().contains("silent_drop_duplicate_packet") => {
                                    warn!("[BILATERAL] Silently dropping duplicate Confirm Request.");
                                }
                                Err(e) => {
                                    log::error!("[BILATERAL] Confirm handler failed: {e}");
                                }
                            }
                        });
                        Ok(Vec::new())
                    }
                }
                BleFrameType::Unspecified => Ok(vec![TransportOutbound::new(
                    BleFrameType::Unspecified,
                    message.payload,
                )]),
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
                    "BLE disconnect {peer_address}: failed {failed} early-phase session(s); late-phase sessions preserved"
                );
            }
        })
    }
}
