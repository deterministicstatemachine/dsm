// SPDX-License-Identifier: MIT OR Apache-2.0

//! BLE frame-type classification and chunking eligibility.
//!
//! These helpers decide, for a canonical DSM envelope or a frame type, which
//! `BleFrameType` a payload carries and whether the outbound reply must be
//! `BleChunk`-framed rather than pushed raw. They are consumed by the Android JNI
//! bridge (`crate::jni::unified_protobuf_bridge`, compiled only for
//! `target_os = "android"`), so they live here in the host-compiled transport layer
//! to keep the routing/classification logic under host CI unit tests.
//!
//! The functions are `dead_code`-allowed on non-Android hosts because their only
//! non-test caller is the Android-only JNI shim; on Android they are live.

use crate::generated as pb;
use prost::Message;

/// Strip the single `0x03` envelope-v3 frame tag if present, returning the raw
/// canonical envelope bytes.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) fn strip_envelope_v3_framing(bytes: &[u8]) -> &[u8] {
    if bytes.first() == Some(&0x03) {
        &bytes[1..]
    } else {
        bytes
    }
}

/// Classify a (possibly v3-framed) canonical envelope into its `BleFrameType`
/// discriminant, returning `Unspecified` when the payload is not a routed BLE frame.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) fn detect_ble_frame_type_from_bytes(bytes: &[u8]) -> i32 {
    let raw = strip_envelope_v3_framing(bytes);

    if let Ok(env) = crate::envelope::from_canonical_bytes(raw) {
        return match env.payload {
            Some(pb::envelope::Payload::BilateralPrepareResponse(_)) => {
                pb::BleFrameType::BilateralPrepareResponse as i32
            }
            Some(pb::envelope::Payload::BilateralPrepareReject(_)) => {
                pb::BleFrameType::BilateralPrepareReject as i32
            }
            Some(pb::envelope::Payload::BilateralCommitResponse(_)) => {
                pb::BleFrameType::BilateralCommitResponse as i32
            }
            Some(pb::envelope::Payload::UniversalTx(tx)) => {
                if let Some(op) = tx.ops.first() {
                    if let Some(pb::universal_op::Kind::Invoke(inv)) = op.kind.as_ref() {
                        if inv.method == "bilateral.prepare" {
                            return pb::BleFrameType::BilateralPrepare as i32;
                        }
                        if inv.method == "bilateral.confirm" {
                            return pb::BleFrameType::BilateralConfirm as i32;
                        }
                        if inv.method == "bilateral.commit" {
                            return pb::BleFrameType::BilateralCommit as i32;
                        }
                    }
                }
                pb::BleFrameType::Unspecified as i32
            }
            _ => pb::BleFrameType::Unspecified as i32,
        };
    }

    if let Ok(env) = pb::BilateralMessageEnvelope::decode(raw) {
        if let Some(msg) = env.msg {
            return match msg {
                pb::bilateral_message_envelope::Msg::ChainHistoryRequest(_) => {
                    pb::BleFrameType::ChainHistoryRequest as i32
                }
                pb::bilateral_message_envelope::Msg::ChainHistoryResponse(_) => {
                    pb::BleFrameType::ChainHistoryResponse as i32
                }
                pb::bilateral_message_envelope::Msg::ReconciliationRequest(_) => {
                    pb::BleFrameType::ReconciliationRequest as i32
                }
                pb::bilateral_message_envelope::Msg::ReconciliationResponse(_) => {
                    pb::BleFrameType::ReconciliationResponse as i32
                }
                _ => pb::BleFrameType::Unspecified as i32,
            };
        }
    }

    pb::BleFrameType::Unspecified as i32
}

/// Frame types whose outbound reply must be `BleChunk`-framed rather than pushed raw.
///
/// A frame needs chunking when its payload can exceed a single BLE notification, or
/// when the peer recovers the frame type from the `BleChunk` header (so a raw frame
/// would be misdecoded).
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) fn ble_frame_needs_chunking(frame_type: i32) -> bool {
    frame_type == pb::BleFrameType::BilateralPrepareReject as i32
        || frame_type == pb::BleFrameType::BilateralCommit as i32
        || frame_type == pb::BleFrameType::BilateralCommitResponse as i32
        || frame_type == pb::BleFrameType::BilateralConfirm as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_envelope() -> pb::Envelope {
        pb::Envelope {
            version: 3,
            headers: Some(pb::Headers {
                device_id: vec![1; 32],
                chain_tip: vec![2; 32],
                genesis_hash: vec![3; 32],
                seq: 0,
            }),
            message_id: vec![4; 16],
            payload: None,
        }
    }

    fn encode(env: pb::Envelope) -> Vec<u8> {
        let mut bytes = Vec::new();
        env.encode(&mut bytes).expect("encode envelope");
        bytes
    }

    fn build_bilateral_confirm_envelope() -> Vec<u8> {
        let mut env = base_envelope();
        env.payload = Some(pb::envelope::Payload::UniversalTx(pb::UniversalTx {
            ops: vec![pb::UniversalOp {
                op_id: Some(pb::Hash32 { v: vec![5; 32] }),
                actor: vec![1; 32],
                genesis_hash: vec![3; 32],
                kind: Some(pb::universal_op::Kind::Invoke(pb::Invoke {
                    method: "bilateral.confirm".to_string(),
                    args: Some(pb::ArgPack {
                        body: vec![9, 9, 9],
                        ..Default::default()
                    }),
                    ..Default::default()
                })),
            }],
            atomic: true,
        }));
        encode(env)
    }

    #[test]
    fn strips_envelope_v3_framing_only_when_present() {
        let raw = build_bilateral_confirm_envelope();
        let mut framed = vec![0x03];
        framed.extend_from_slice(&raw);
        assert_eq!(strip_envelope_v3_framing(&raw), raw.as_slice());
        assert_eq!(strip_envelope_v3_framing(&framed), raw.as_slice());
    }

    #[test]
    fn detects_bilateral_confirm_for_raw_and_framed_envelopes() {
        let raw = build_bilateral_confirm_envelope();
        let mut framed = vec![0x03];
        framed.extend_from_slice(&raw);
        assert_eq!(
            detect_ble_frame_type_from_bytes(&raw),
            pb::BleFrameType::BilateralConfirm as i32
        );
        assert_eq!(
            detect_ble_frame_type_from_bytes(&framed),
            pb::BleFrameType::BilateralConfirm as i32
        );
    }

    #[test]
    fn chunking_eligibility_matches_frame_budget() {
        assert!(ble_frame_needs_chunking(
            pb::BleFrameType::BilateralConfirm as i32
        ));
        assert!(ble_frame_needs_chunking(
            pb::BleFrameType::BilateralCommitResponse as i32
        ));
        assert!(!ble_frame_needs_chunking(
            pb::BleFrameType::BilateralPrepareResponse as i32
        ));
        assert!(!ble_frame_needs_chunking(
            pb::BleFrameType::Unspecified as i32
        ));
    }
}
