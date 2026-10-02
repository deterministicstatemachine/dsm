// SPDX-License-Identifier: MIT OR Apache-2.0

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

/// Build an Envelope v3 from `device_id` under `genesis_hash`.
///
/// `Headers.chain_tip` is reserved on the wire (`dsm_app.proto`: the SDK emits
/// zeros there and no reader may use it), so the envelope carries that reserved
/// value; no BLE receiver reads it.
///
/// The message id is content-addressed: the first 16 bytes of
/// BLAKE3("DSM/envelope-id", the envelope encoded with an empty id). Two
/// envelopes share an id only when they are the same envelope.
pub fn build_envelope(
    device_id: &[u8; 32],
    genesis_hash: &[u8; 32],
    payload: generated::envelope::Payload,
) -> generated::Envelope {
    let mut envelope = generated::Envelope {
        version: 3,
        headers: Some(generated::Headers {
            device_id: device_id.to_vec(),
            genesis_hash: genesis_hash.to_vec(),
        }),
        message_id: Vec::new(),
        payload: Some(payload),
    };
    let mut idh = dsm_domain_hasher(dsm::common::domain_tags::TAG_DSM_ENVELOPE_ID);
    idh.update(&envelope.encode_to_vec());
    envelope.message_id = idh.finalize().as_bytes()[..16].to_vec();
    envelope
}

/// Frame a BLE pairing message this device sends a peer (its identity
/// write-back, a pairing accept or a pairing confirm): an Envelope v3 from
/// `device_id` under `genesis_hash`, with its headers and message id, behind
/// the `0x03` framing byte. The peer decodes pairing frames with the strict
/// addressed decoder, which refuses the headerless local-answer form the
/// WebView's BLE events use.
pub fn pairing_frame(
    device_id: &[u8; 32],
    genesis_hash: &[u8; 32],
    event: generated::BleEvent,
) -> Vec<u8> {
    let envelope = build_envelope(
        device_id,
        genesis_hash,
        generated::envelope::Payload::BleEvent(event),
    );
    let mut frame = vec![0x03];
    frame.extend(envelope.encode_to_vec());
    frame
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
            if tx.ops.len() != 1 {
                return Err(DsmError::invalid_operation(
                    "expected exactly one operation in transaction",
                ));
            }
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
            if tx.ops.len() != 1 {
                return Err(DsmError::invalid_operation(
                    "expected exactly one operation in transaction",
                ));
            }
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

    /// A pairing frame is taken by the strict addressed decoder the peer runs
    /// it through (`processBleIdentityEnvelope`), headers and all, and carries
    /// its event unchanged. The headerless local-answer form the pairing frames
    /// used to be built in is refused by that decoder — on hardware, "Envelope.
    /// headers is required" (9FF, 2026-09-27). MUTATION CONTROL: building the
    /// frame as a local answer turns this red.
    #[test]
    fn a_pairing_frame_is_taken_by_the_peers_strict_decoder() {
        let event = generated::BleEvent {
            ev: Some(generated::ble_event::Ev::PairingConfirm(
                generated::BlePairingConfirm {
                    address: "43:CD:4F:E4:A9:19".to_string(),
                    device_id: test_device_id().to_vec(),
                },
            )),
        };
        let frame = pairing_frame(&test_device_id(), &test_genesis_hash(), event.clone());

        assert_eq!(frame.first(), Some(&0x03));
        let envelope = crate::envelope::from_canonical_bytes(&frame[1..])
            .expect("the peer's decoder takes a pairing frame");
        let headers = envelope.headers.expect("a pairing frame names its sender");
        assert_eq!(headers.device_id, test_device_id().to_vec());
        assert_eq!(headers.genesis_hash, test_genesis_hash().to_vec());
        assert!(matches!(
            envelope.payload,
            Some(generated::envelope::Payload::BleEvent(ref carried)) if *carried == event
        ));

        let local_answer =
            crate::envelope::local_answer(generated::envelope::Payload::BleEvent(event))
                .encode_to_vec();
        assert!(crate::envelope::from_canonical_bytes(&local_answer).is_err());
    }

    fn tx_payload(atomic: bool) -> generated::envelope::Payload {
        generated::envelope::Payload::UniversalTx(generated::UniversalTx {
            ops: vec![],
            atomic,
        })
    }

    #[test]
    fn build_envelope_version_and_headers() {
        let did = test_device_id();
        let gh = test_genesis_hash();
        let env = build_envelope(&did, &gh, tx_payload(false));
        assert_eq!(env.version, 3);
        let hdrs = env.headers.as_ref().unwrap();
        assert_eq!(hdrs.device_id, did.to_vec());
        assert_eq!(hdrs.genesis_hash, gh.to_vec());
        assert_eq!(env.message_id.len(), 16);
    }

    /// The id names the envelope's bytes: equal envelopes share it, and a
    /// change to the payload or the sender changes it.
    #[test]
    fn build_envelope_message_id_is_content_addressed() {
        let did = test_device_id();
        let gh = test_genesis_hash();
        let e1 = build_envelope(&did, &gh, tx_payload(false));
        let e2 = build_envelope(&did, &gh, tx_payload(false));
        let other_payload = build_envelope(&did, &gh, tx_payload(true));
        let other_sender = build_envelope(&[0xCC; 32], &gh, tx_payload(false));
        assert_eq!(e1.message_id, e2.message_id);
        assert_ne!(e1.message_id, other_payload.message_id);
        assert_ne!(e1.message_id, other_sender.message_id);

        let mut unnamed = e1.clone();
        unnamed.message_id = Vec::new();
        let mut idh = dsm_domain_hasher(dsm::common::domain_tags::TAG_DSM_ENVELOPE_ID);
        idh.update(&unnamed.encode_to_vec());
        assert_eq!(e1.message_id, idh.finalize().as_bytes()[..16].to_vec());
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
            cosigners: vec![],
            evidence: None,
            nonce: None,
        };
        let op = generated::UniversalOp {
            op_id: None,
            actor: vec![],
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
            expected_genesis_hash: None,
            expected_counterparty_state_hash: None,
            sender_signing_public_key: vec![0; 64],
            sender_device_id: vec![0; 32],
            sender_genesis_hash: None,
            sender_signature: vec![],
            sender_kyber_public_key: vec![],
            sender_kyber_binding_sig: vec![],
            transfer_terms: Vec::new(),
        };
        let body = req.encode_to_vec();
        let env = make_invoke_envelope("bilateral.prepare", &body);
        let decoded = extract_prepare_request(&env).unwrap();
        assert_eq!(decoded.counterparty_device_id, vec![1; 32]);
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
    fn extract_prepare_request_rejects_multiple_ops() {
        let req = generated::BilateralPrepareRequest {
            counterparty_device_id: vec![1; 32],
            operation_data: vec![2; 16],
            expected_genesis_hash: None,
            expected_counterparty_state_hash: None,
            sender_signing_public_key: vec![0; 64],
            sender_device_id: vec![0; 32],
            sender_genesis_hash: None,
            sender_signature: vec![],
            sender_kyber_public_key: vec![],
            sender_kyber_binding_sig: vec![],
            transfer_terms: Vec::new(),
        };
        let body = req.encode_to_vec();
        let mut env = make_invoke_envelope("bilateral.prepare", &body);
        if let Some(generated::envelope::Payload::UniversalTx(tx)) = env.payload.as_mut() {
            tx.ops.push(tx.ops[0].clone());
        }
        assert!(extract_prepare_request(&env).is_err());
    }

    #[test]
    fn extract_confirm_request_success() {
        let req = generated::BilateralConfirmRequest {
            commitment_hash: Some(generated::Hash32 { v: vec![0xCC; 32] }),
            sender_signature: vec![3; 16],
            ..Default::default()
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

    #[test]
    fn extract_confirm_request_rejects_multiple_ops() {
        let req = generated::BilateralConfirmRequest {
            commitment_hash: Some(generated::Hash32 { v: vec![0xCC; 32] }),
            sender_signature: vec![3; 16],
            ..Default::default()
        };
        let body = req.encode_to_vec();
        let mut env = make_invoke_envelope("bilateral.confirm", &body);
        if let Some(generated::envelope::Payload::UniversalTx(tx)) = env.payload.as_mut() {
            tx.ops.push(tx.ops[0].clone());
        }
        assert!(extract_confirm_request(&env).is_err());
    }
}
