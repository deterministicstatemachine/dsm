//! Bilateral envelope construction and payload extraction.
//!
//! Stateless free functions for building outgoing Envelope v3 messages and
//! extracting `BilateralPrepareRequest` / `BilateralConfirmRequest` from
//! incoming envelopes.  These are pure data transformations — no session
//! state, no side effects.
//!
//! Extracted from `bilateral_ble_handler.rs` to keep the handler focused on
//! protocol phase coordination.

use dsm::crypto::blake3::dsm_domain_hasher;
use dsm::types::error::DsmError;
use log::warn;
use prost::Message;

use crate::generated;

/// Build an Envelope v3 with an explicit chain tip override.
///
/// All header values (`device_id`, `genesis_hash`, `ticks`) must be supplied
/// by the caller — this function has no access to `BilateralTransactionManager`
/// or any shared state.
pub fn build_envelope(
    device_id: &[u8; 32],
    genesis_hash: &[u8; 32],
    ticks: u64,
    chain_tip_override: Option<[u8; 32]>,
    payload: generated::envelope::Payload,
) -> Result<generated::Envelope, DsmError> {
    // Derive chain tip from genesis_hash + ticks if no override supplied
    let chain_tip_bytes = match chain_tip_override {
        Some(ct) => ct,
        None => {
            let mut hasher = dsm_domain_hasher("DSM/CHAIN_TIP");
            hasher.update(genesis_hash);
            hasher.update(&ticks.to_le_bytes());
            let mut ct = [0u8; 32];
            ct.copy_from_slice(hasher.finalize().as_bytes());
            ct
        }
    };

    // Deterministic message id
    let mut idh = dsm_domain_hasher("DSM/ENVELOPE_ID");
    idh.update(device_id);
    idh.update(genesis_hash);
    idh.update(&chain_tip_bytes);
    idh.update(&ticks.to_le_bytes());
    let mut msgid = vec![0u8; 16];
    msgid.copy_from_slice(&idh.finalize().as_bytes()[..16]);

    Ok(generated::Envelope {
        version: 3,
        headers: Some(generated::Headers {
            device_id: device_id.to_vec(),
            chain_tip: chain_tip_bytes.to_vec(),
            genesis_hash: genesis_hash.to_vec(),
            seq: 0,
        }),
        message_id: msgid,
        payload: Some(payload),
    })
}

/// Build an Envelope v3 using the default chain tip derived from genesis hash + ticks.
#[allow(dead_code)]
pub fn build_envelope_default_tip(
    device_id: &[u8; 32],
    genesis_hash: &[u8; 32],
    ticks: u64,
    payload: generated::envelope::Payload,
) -> Result<generated::Envelope, DsmError> {
    build_envelope(device_id, genesis_hash, ticks, None, payload)
}

/// Extract a `BilateralPrepareRequest` from an incoming Envelope.
///
/// Expects the envelope to contain a `UniversalTx` with a single `Invoke` op
/// whose method is `"bilateral.prepare"`.
pub fn extract_prepare_request(
    envelope: &generated::Envelope,
) -> Result<generated::BilateralPrepareRequest, DsmError> {
    match &envelope.payload {
        Some(generated::envelope::Payload::UniversalTx(tx)) => {
            if let Some(op) = tx.ops.first() {
                match &op.kind {
                    Some(generated::universal_op::Kind::Invoke(invoke))
                        if invoke.method == "bilateral.prepare" =>
                    {
                        let args = invoke
                            .args
                            .as_ref()
                            .ok_or_else(|| DsmError::invalid_operation("missing args"))?;
                        generated::BilateralPrepareRequest::decode(args.body.as_slice()).map_err(
                            |e| {
                                DsmError::invalid_operation(format!(
                                    "failed to decode prepare request: {}",
                                    e
                                ))
                            },
                        )
                    }
                    Some(other) => {
                        warn!("extract_prepare_request: got op.kind but not Invoke(bilateral.prepare), variant: {:?}", std::mem::discriminant(other));
                        Err(DsmError::invalid_operation(
                            "expected bilateral prepare operation",
                        ))
                    }
                    None => {
                        warn!("extract_prepare_request: op.kind is None");
                        Err(DsmError::invalid_operation(
                            "expected bilateral prepare operation",
                        ))
                    }
                }
            } else {
                Err(DsmError::invalid_operation("no operations in transaction"))
            }
        }
        _ => Err(DsmError::invalid_operation(
            "expected universal transaction",
        )),
    }
}

/// Extract a `BilateralConfirmRequest` from an incoming Envelope.
///
/// Expects the envelope to contain a `UniversalTx` with a single `Invoke` op
/// whose method is `"bilateral.confirm"`.
pub fn extract_confirm_request(
    envelope: &generated::Envelope,
) -> Result<generated::BilateralConfirmRequest, DsmError> {
    match &envelope.payload {
        Some(generated::envelope::Payload::UniversalTx(tx)) => {
            if let Some(op) = tx.ops.first() {
                match &op.kind {
                    Some(generated::universal_op::Kind::Invoke(invoke))
                        if invoke.method == "bilateral.confirm" =>
                    {
                        let args = invoke
                            .args
                            .as_ref()
                            .ok_or_else(|| DsmError::invalid_operation("missing args"))?;
                        generated::BilateralConfirmRequest::decode(args.body.as_slice()).map_err(
                            |e| {
                                DsmError::invalid_operation(format!(
                                    "failed to decode confirm request: {}",
                                    e
                                ))
                            },
                        )
                    }
                    Some(other) => {
                        warn!("extract_confirm_request: got op.kind but not Invoke(bilateral.confirm), variant: {:?}", std::mem::discriminant(other));
                        Err(DsmError::invalid_operation(
                            "expected bilateral confirm operation",
                        ))
                    }
                    None => {
                        warn!("extract_confirm_request: op.kind is None");
                        Err(DsmError::invalid_operation(
                            "expected bilateral confirm operation",
                        ))
                    }
                }
            } else {
                Err(DsmError::invalid_operation("no operations in transaction"))
            }
        }
        _ => Err(DsmError::invalid_operation(
            "expected universal transaction",
        )),
    }
}
