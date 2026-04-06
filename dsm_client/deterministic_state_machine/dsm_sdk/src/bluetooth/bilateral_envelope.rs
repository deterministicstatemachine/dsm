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

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    fn test_device_id() -> [u8; 32] {
        [0xAA; 32]
    }
    fn test_genesis_hash() -> [u8; 32] {
        [0xBB; 32]
    }

    #[test]
    fn build_envelope_version_and_headers() {
        let did = test_device_id();
        let gh = test_genesis_hash();
        let payload = generated::envelope::Payload::UniversalTx(generated::UniversalTx {
            ops: vec![],
            atomic: false,
        });

        let env = build_envelope(&did, &gh, 1, None, payload).unwrap();
        assert_eq!(env.version, 3);
        let hdrs = env.headers.as_ref().unwrap();
        assert_eq!(hdrs.device_id, did.to_vec());
        assert_eq!(hdrs.genesis_hash, gh.to_vec());
        assert_eq!(hdrs.seq, 0);
    }

    #[test]
    fn build_envelope_message_id_is_16_bytes() {
        let did = test_device_id();
        let gh = test_genesis_hash();
        let payload = generated::envelope::Payload::UniversalTx(generated::UniversalTx {
            ops: vec![],
            atomic: false,
        });
        let env = build_envelope(&did, &gh, 5, None, payload).unwrap();
        assert_eq!(env.message_id.len(), 16);
    }

    #[test]
    fn build_envelope_deterministic_message_id() {
        let did = test_device_id();
        let gh = test_genesis_hash();
        let mk = |ticks| {
            let p = generated::envelope::Payload::UniversalTx(generated::UniversalTx {
                ops: vec![],
                atomic: false,
            });
            build_envelope(&did, &gh, ticks, None, p).unwrap()
        };
        let e1 = mk(10);
        let e2 = mk(10);
        let e3 = mk(11);
        assert_eq!(e1.message_id, e2.message_id, "same inputs → same id");
        assert_ne!(
            e1.message_id, e3.message_id,
            "different ticks → different id"
        );
    }

    #[test]
    fn build_envelope_chain_tip_override() {
        let did = test_device_id();
        let gh = test_genesis_hash();
        let custom_tip = [0xFF; 32];
        let payload = generated::envelope::Payload::UniversalTx(generated::UniversalTx {
            ops: vec![],
            atomic: false,
        });
        let env = build_envelope(&did, &gh, 1, Some(custom_tip), payload).unwrap();
        let hdrs = env.headers.unwrap();
        assert_eq!(hdrs.chain_tip, custom_tip.to_vec());
    }

    #[test]
    fn build_envelope_derived_chain_tip() {
        let did = test_device_id();
        let gh = test_genesis_hash();
        let payload = generated::envelope::Payload::UniversalTx(generated::UniversalTx {
            ops: vec![],
            atomic: false,
        });
        let env = build_envelope(&did, &gh, 42, None, payload).unwrap();
        let hdrs = env.headers.unwrap();
        assert_eq!(hdrs.chain_tip.len(), 32);
        assert_ne!(
            hdrs.chain_tip,
            vec![0u8; 32],
            "derived tip should not be zeros"
        );
    }

    fn make_invoke_envelope(method: &str, body: &[u8]) -> generated::Envelope {
        let args = generated::ArgPack {
            schema_hash: None,
            codec: 0,
            body: body.to_vec(),
        };
        let invoke = generated::Invoke {
            program: None,
            method: method.to_string(),
            args: Some(args),
            pre_state_hash: None,
            post_state_hash: None,
            cosigners: vec![],
            evidence: None,
            nonce: None,
        };
        let op = generated::UniversalOp {
            op_id: None,
            actor: vec![],
            genesis_hash: vec![],
            kind: Some(generated::universal_op::Kind::Invoke(invoke)),
        };
        generated::Envelope {
            version: 3,
            headers: None,
            message_id: vec![],
            payload: Some(generated::envelope::Payload::UniversalTx(
                generated::UniversalTx {
                    ops: vec![op],
                    atomic: false,
                },
            )),
        }
    }

    #[test]
    fn extract_prepare_request_success() {
        let req = generated::BilateralPrepareRequest {
            counterparty_device_id: vec![1; 32],
            operation_data: vec![2; 16],
            validity_iterations: 100,
            expected_genesis_hash: None,
            expected_counterparty_state_hash: None,
            ble_address: String::new(),
            sender_signing_public_key: vec![0; 64],
            sender_device_id: vec![0; 32],
            sender_genesis_hash: None,
            sender_chain_tip: None,
            transfer_amount: 0,
            token_id_hint: String::new(),
            memo_hint: String::new(),
            transfer_amount_display: String::new(),
        };
        let body = req.encode_to_vec();
        let env = make_invoke_envelope("bilateral.prepare", &body);
        let decoded = extract_prepare_request(&env).unwrap();
        assert_eq!(decoded.counterparty_device_id, vec![1; 32]);
        assert_eq!(decoded.validity_iterations, 100);
    }

    #[test]
    fn extract_prepare_request_wrong_method() {
        let env = make_invoke_envelope("bilateral.confirm", &[]);
        assert!(extract_prepare_request(&env).is_err());
    }

    #[test]
    fn extract_prepare_request_no_payload() {
        let env = generated::Envelope {
            version: 3,
            headers: None,
            message_id: vec![],
            payload: None,
        };
        assert!(extract_prepare_request(&env).is_err());
    }

    #[test]
    fn extract_prepare_request_empty_ops() {
        let env = generated::Envelope {
            version: 3,
            headers: None,
            message_id: vec![],
            payload: Some(generated::envelope::Payload::UniversalTx(
                generated::UniversalTx {
                    ops: vec![],
                    atomic: false,
                },
            )),
        };
        assert!(extract_prepare_request(&env).is_err());
    }

    #[test]
    fn extract_confirm_request_success() {
        let req = generated::BilateralConfirmRequest {
            commitment_hash: Some(generated::Hash32 { v: vec![0xCC; 32] }),
            sender_signature: vec![3; 16],
            sender_smt_root: vec![],
            rel_proof_parent: vec![],
            rel_proof_child: vec![],
            stitched_receipt: vec![],
            shared_chain_tip_new: Some(generated::Hash32 { v: vec![0; 32] }),
            pre_entropy: vec![],
            sender_smt_root_before: vec![],
        };
        let body = req.encode_to_vec();
        let env = make_invoke_envelope("bilateral.confirm", &body);
        let decoded = extract_confirm_request(&env).unwrap();
        assert_eq!(decoded.commitment_hash.unwrap().v, vec![0xCC; 32]);
    }

    #[test]
    fn extract_confirm_request_wrong_method() {
        let env = make_invoke_envelope("bilateral.prepare", &[]);
        assert!(extract_confirm_request(&env).is_err());
    }
}
