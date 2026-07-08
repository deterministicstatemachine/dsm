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
            Some(pb::envelope::Payload::BilateralBearerPrepared(_)) => {
                pb::BleFrameType::BilateralBearerPrepared as i32
            }
            Some(pb::envelope::Payload::BilateralBearerProceed(_)) => {
                pb::BleFrameType::BilateralBearerProceed as i32
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
/// would be misdecoded). `BilateralBearerPrepared` carries the full `AnchorDisclosure`
/// (anchor bundle, partition pubkey up to 4 KiB, verifier slot + chip static pubkey)
/// and readily exceeds the unframed budget — sent raw it truncates and the first-transfer
/// round-trip fails before the protocol runs. `BilateralBearerProceed` is small but is
/// chunk-framed for symmetry so the sender recovers its frame type from the header.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) fn ble_frame_needs_chunking(frame_type: i32) -> bool {
    frame_type == pb::BleFrameType::BilateralPrepareReject as i32
        || frame_type == pb::BleFrameType::BilateralCommit as i32
        || frame_type == pb::BleFrameType::BilateralCommitResponse as i32
        || frame_type == pb::BleFrameType::BilateralConfirm as i32
        || frame_type == pb::BleFrameType::BilateralBearerPrepared as i32
        || frame_type == pb::BleFrameType::BilateralBearerProceed as i32
        // Path-B relay reply (chip->receiver counter read): the REQUEST is chunked via
        // `queue_follow_up_chunks`, so the REPLY must be BleChunk-framed too — otherwise
        // the receiver decodes the raw `TropicSpiRelayPacket` as a `BleChunk` and fails
        // (`invalid tag value: 0`), dropping the reply and timing out the counter read.
        || frame_type == pb::BleFrameType::TropicSpiRelay as i32
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

    fn build_bilateral_bearer_prepared_envelope(partition_pk_len: usize) -> Vec<u8> {
        let mut env = base_envelope();
        env.payload = Some(pb::envelope::Payload::BilateralBearerPrepared(
            pb::BilateralBearerPrepared {
                commitment_hash: Some(pb::Hash32 { v: vec![5; 32] }),
                anchor_disclosure: Some(pb::AnchorDisclosure {
                    bundle: vec![6; 32],
                    anchor_id: vec![7; 32],
                    enrolled_counter: 42,
                    partition_pk: vec![8; partition_pk_len],
                    policy_hash: vec![9; 32],
                    verifier_slot: 1,
                    verifier_slot_present: true,
                    chip_static_pubkey: vec![10; 32],
                }),
            },
        ));
        encode(env)
    }

    fn build_bilateral_bearer_proceed_envelope() -> Vec<u8> {
        let mut env = base_envelope();
        env.payload = Some(pb::envelope::Payload::BilateralBearerProceed(
            pb::BilateralBearerProceed {
                commitment_hash: Some(pb::Hash32 { v: vec![5; 32] }),
                receiver_signature: vec![11; 64],
            },
        ));
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
    fn detects_bilateral_bearer_frames_for_raw_and_framed_envelopes() {
        let prepared = build_bilateral_bearer_prepared_envelope(64);
        let mut prepared_framed = vec![0x03];
        prepared_framed.extend_from_slice(&prepared);
        assert_eq!(
            detect_ble_frame_type_from_bytes(&prepared),
            pb::BleFrameType::BilateralBearerPrepared as i32
        );
        assert_eq!(
            detect_ble_frame_type_from_bytes(&prepared_framed),
            pb::BleFrameType::BilateralBearerPrepared as i32
        );

        let proceed = build_bilateral_bearer_proceed_envelope();
        let mut proceed_framed = vec![0x03];
        proceed_framed.extend_from_slice(&proceed);
        assert_eq!(
            detect_ble_frame_type_from_bytes(&proceed),
            pb::BleFrameType::BilateralBearerProceed as i32
        );
        assert_eq!(
            detect_ble_frame_type_from_bytes(&proceed_framed),
            pb::BleFrameType::BilateralBearerProceed as i32
        );
    }

    #[test]
    fn bearer_frames_are_chunking_eligible() {
        // Both bearer frames must be BleChunk-framed on the outbound reply path.
        assert!(ble_frame_needs_chunking(
            pb::BleFrameType::BilateralBearerPrepared as i32
        ));
        assert!(ble_frame_needs_chunking(
            pb::BleFrameType::BilateralBearerProceed as i32
        ));
        // Pre-existing large frames stay eligible; a small unframed frame stays ineligible.
        assert!(ble_frame_needs_chunking(
            pb::BleFrameType::BilateralConfirm as i32
        ));
        assert!(ble_frame_needs_chunking(
            pb::BleFrameType::TropicSpiRelay as i32
        ));
        assert!(!ble_frame_needs_chunking(
            pb::BleFrameType::BilateralPrepareResponse as i32
        ));
        assert!(!ble_frame_needs_chunking(
            pb::BleFrameType::Unspecified as i32
        ));
    }

    #[test]
    fn large_bearer_prepared_disclosure_is_chunked_not_truncated() {
        // A realistic first-transfer disclosure (partition_pk up to 4 KiB) exceeds a single
        // BLE notification. Prove it is (a) chunk-eligible and (b) actually split by the frame
        // coordinator into >1 chunk, each stamped with the bearer frame type — so the receiver
        // reassembles the full disclosure instead of a truncated one.
        let prepared = build_bilateral_bearer_prepared_envelope(1024);
        assert!(
            prepared.len() > 512,
            "test disclosure should exceed one notification, got {}",
            prepared.len()
        );
        assert!(ble_frame_needs_chunking(
            pb::BleFrameType::BilateralBearerPrepared as i32
        ));

        let coord = crate::bluetooth::BleFrameCoordinator::new([7u8; 32]);
        let chunks = coord
            .encode_message(pb::BleFrameType::BilateralBearerPrepared, &prepared)
            .expect("encode_message chunks bearer-prepared");
        assert!(
            chunks.len() > 1,
            "large disclosure must span multiple chunks, got {}",
            chunks.len()
        );
        for chunk_bytes in &chunks {
            let chunk = pb::BleChunk::decode(chunk_bytes.as_slice()).expect("decode BleChunk");
            let header = chunk.header.expect("chunk header present");
            assert_eq!(
                header.frame_type,
                pb::BleFrameType::BilateralBearerPrepared as i32
            );
        }
    }
}
