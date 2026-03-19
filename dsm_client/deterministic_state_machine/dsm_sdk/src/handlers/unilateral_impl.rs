//! # Unilateral Handler Implementation
//!
//! Implements the `UnilateralHandler` trait for one-sided state transitions
//! (token transfers, balance queries) that do not require bilateral handshake.

// SPDX-License-Identifier: MIT OR Apache-2.0

use async_trait::async_trait;
use prost::Message;
use std::sync::Arc;

use crate::prelude::DsmError;
use tokio::sync::RwLock;

use crate::bridge::{UniOp, UniResult, UnilateralHandler};
use crate::init::SdkConfig;
use crate::sdk::app_state::AppState;
use crate::sdk::b0x_sdk::B0xSDK;
use crate::sdk::core_sdk::CoreSDK;
use crate::sdk::unilateral_ops_sdk::UnilateralOpsSDK;
use crate::util::text_id::encode_base32_crockford;

use dsm::types::identifiers::NodeId;
use dsm::types::operations::Operation;
use dsm::types::state_types::DeviceInfo;

// protobuf bindings for this handler live in this module (see `mod pb` at bottom).

/// Unilateral handler: protobuf-only, strict-fail, no JSON/Base64.
///
/// IMPORTANT: safe to initialize pre-genesis.
/// On first-run startup, `AppState::device_id` can be missing.
/// In that case we MUST NOT panic/abort. We initialize a placeholder handler that
/// deterministically rejects unilateral ops.
pub struct UniImpl {
    config: SdkConfig,
    ops: Arc<UnilateralOpsSDK>,
}

impl UniImpl {
    pub fn new(config: SdkConfig) -> Result<Self, DsmError> {
        match AppState::get_device_id() {
            Some(dev) if dev.len() == 32 => match Self::new_with_device_id(&config, dev) {
                Ok(uni) => Ok(uni),
                Err(e) => {
                    log::error!("Failed to create UniImpl with device_id, falling back to pre-genesis: {:?}", e);
                    Self::new_pre_genesis(config)
                }
            },
            Some(_dev) => {
                // log::error!("...");
                Self::new_pre_genesis(config)
            }
            None => {
                log::warn!(
                    "UniImpl initialized before device_id exists; running pre-genesis (unilateral ops disabled)"
                );
                Self::new_pre_genesis(config)
            }
        }
    }

    fn new_with_device_id(
        config: &SdkConfig,
        device_id_bytes: Vec<u8>,
    ) -> Result<Self, dsm::types::error::DsmError> {
        let device_id = encode_base32_crockford(&device_id_bytes);

        let mut dev32 = [0u8; 32];
        dev32.copy_from_slice(&device_id_bytes);
        let device_info = DeviceInfo::new(dev32, device_id_bytes.clone());
        let core = match CoreSDK::new_with_device(device_info) {
            Ok(c) => Arc::new(c),
            Err(e) => {
                // This is post-genesis; failure indicates corrupt state.
                return Err(dsm::types::error::DsmError::InvalidState(
                    format!("CoreSDK::new_with_device() failed in UniImpl (genesis state missing or corrupt): {:?}", e)
                ));
            }
        };

        let b0x = match B0xSDK::new(
            device_id.clone(),
            core.clone(),
            config.storage_endpoints.clone(),
        ) {
            Ok(b) => b,
            Err(e) => {
                return Err(dsm::types::error::DsmError::InvalidState(format!(
                    "B0xSDK::new() failed in UniImpl: {:?}",
                    e
                )));
            }
        };

        let mut dev32 = [0u8; 32];
        dev32.copy_from_slice(&device_id_bytes);

        let nodes: Vec<NodeId> = config
            .storage_endpoints
            .iter()
            .cloned()
            .map(NodeId::new)
            .collect();

        let contact_manager = dsm::core::contact_manager::DsmContactManager::new(dev32, nodes);
        let ops = UnilateralOpsSDK::new_with_device_id(
            b0x,
            Arc::new(RwLock::new(contact_manager)),
            device_id,
            dev32,
        );

        Ok(Self {
            config: config.clone(),
            ops: Arc::new(ops),
        })
    }

    fn new_pre_genesis(config: SdkConfig) -> Result<Self, DsmError> {
        let device_id_bytes = vec![0u8; 32];
        let device_id = encode_base32_crockford(&device_id_bytes);

        let device_info = DeviceInfo::new([0u8; 32], device_id_bytes);

        let core = match CoreSDK::new_with_device(device_info) {
            Ok(c) => Arc::new(c),
            Err(e) => {
                log::error!("CoreSDK::new_with_device failed in pre-genesis UniImpl: {e:?}");
                // pre-genesis must never abort startup
                match CoreSDK::new() {
                    Ok(c) => Arc::new(c),
                    Err(e2) => {
                        log::error!(
                                "CoreSDK::new also failed in pre-genesis UniImpl; unilateral ops will be disabled: {e2:?}"
                            );
                        return Ok(Self {
                            config,
                            ops: Arc::new(UnilateralOpsSDK::disabled()?),
                        });
                    }
                }
            }
        };

        // Best-effort b0x init; if it fails pre-genesis, still do not abort startup.
        let b0x = match B0xSDK::new(
            device_id.clone(),
            core.clone(),
            config.storage_endpoints.clone(),
        ) {
            Ok(b) => b,
            Err(e) => {
                log::error!("B0xSDK::new failed in pre-genesis UniImpl: {e:?}");
                // Pre-genesis must never abort startup; unilateral ops are gated off anyway.
                return Ok(Self {
                    config,
                    ops: Arc::new(UnilateralOpsSDK::disabled()?),
                });
            }
        };

        let dev32: [u8; 32] = [0u8; 32];
        let nodes: Vec<NodeId> = config
            .storage_endpoints
            .iter()
            .cloned()
            .map(NodeId::new)
            .collect();

        let contact_manager = dsm::core::contact_manager::DsmContactManager::new(dev32, nodes);
        let ops = UnilateralOpsSDK::new_with_device_id(
            b0x,
            Arc::new(RwLock::new(contact_manager)),
            device_id,
            dev32,
        );

        Ok(Self {
            config,
            ops: Arc::new(ops),
        })
    }
}

#[async_trait]
impl UnilateralHandler for UniImpl {
    async fn handle(&self, op: UniOp) -> UniResult {
        // If we've been initialized pre-genesis, block unilateral online flows.
        if self.ops.device_id_bytes == [0u8; 32] {
            return UniResult {
                success: false,
                result_data: Vec::new(),
                error_message: Some("unilateral handler unavailable pre-genesis".into()),
            };
        }

        match op.operation_type.as_str() {
            // Online inbox sync (result_data = u64 LE count)
            "unilateral.sync" => {
                if self.config.enable_offline {
                    return UniResult {
                        success: true,
                        result_data: 0u64.to_le_bytes().to_vec(),
                        error_message: None,
                    };
                }

                let b0x_address = match std::str::from_utf8(&op.data) {
                    Ok(s) => s,
                    Err(_) => {
                        return UniResult {
                            success: false,
                            result_data: Vec::new(),
                            error_message: Some(
                                "unilateral.sync: op.data must be UTF-8 b0x address".into(),
                            ),
                        };
                    }
                };

                match self
                    .ops
                    .sync_unilateral_transactions(b0x_address, None)
                    .await
                {
                    Ok(count) => UniResult {
                        success: true,
                        result_data: (count as u64).to_le_bytes().to_vec(),
                        error_message: None,
                    },
                    Err(e) => UniResult {
                        success: false,
                        result_data: Vec::new(),
                        error_message: Some(format!("unilateral.sync failed: {e}")),
                    },
                }
            }

            // Submit a unilateral operation (result_data = tx_id bytes)
            "unilateral.submit" => {
                if self.config.enable_offline {
                    // deterministic 16-byte placeholder in offline test mode
                    return UniResult {
                        success: true,
                        result_data: vec![0u8; 16],
                        error_message: None,
                    };
                }

                let req = match pb::UniSubmitRequest::decode(op.data.as_slice()) {
                    Ok(r) => r,
                    Err(e) => {
                        return UniResult {
                            success: false,
                            result_data: Vec::new(),
                            error_message: Some(format!("unilateral.submit: decode failed: {e}")),
                        };
                    }
                };

                let operation = match Operation::from_bytes(req.operation.as_slice()) {
                    Ok(opr) => opr,
                    Err(e) => {
                        return UniResult {
                            success: false,
                            result_data: Vec::new(),
                            error_message: Some(format!(
                                "unilateral.submit: invalid operation bytes: {e}"
                            )),
                        };
                    }
                };

                if req.seq == 0 {
                    return UniResult {
                        success: false,
                        result_data: Vec::new(),
                        error_message: Some("unilateral.submit: seq is required".to_string()),
                    };
                }

                let next_tip = if req.next_chain_tip.is_empty() {
                    None
                } else {
                    Some(req.next_chain_tip.clone())
                };
                let res = self
                    .ops
                    .submit_unilateral_transaction_with_next_tip(
                        req.recipient_device_id,
                        req.recipient_genesis_hash,
                        operation,
                        req.signature,
                        req.sender_genesis_hash,
                        req.sender_chain_tip,
                        req.seq,
                        next_tip,
                    )
                    .await;

                match res {
                    Ok(tx_id) => UniResult {
                        success: true,
                        result_data: tx_id.into_bytes(),
                        error_message: None,
                    },
                    Err(e) => UniResult {
                        success: false,
                        result_data: Vec::new(),
                        error_message: Some(format!("unilateral.submit failed: {e}")),
                    },
                }
            }

            other => UniResult {
                success: false,
                result_data: Vec::new(),
                error_message: Some(format!("unilateral handler not wired: {other}")),
            },
        }
    }
}

// Transport-facing protobuf (edge strings are acceptable here; canonical bytes live in core).
mod pb {
    use prost::Message;

    #[derive(Clone, PartialEq, Message)]
    pub struct UniSubmitRequest {
        #[prost(string, tag = "1")]
        pub recipient_device_id: String,
        #[prost(string, tag = "2")]
        pub recipient_genesis_hash: String,
        #[prost(bytes, tag = "4")]
        pub operation: Vec<u8>,
        #[prost(bytes, tag = "5")]
        pub signature: Vec<u8>,
        #[prost(string, tag = "6")]
        pub sender_genesis_hash: String,
        #[prost(string, tag = "7")]
        pub sender_chain_tip: String,
        #[prost(uint64, tag = "8")]
        pub seq: u64,
        #[prost(string, tag = "9")]
        pub next_chain_tip: String,
    }
}
