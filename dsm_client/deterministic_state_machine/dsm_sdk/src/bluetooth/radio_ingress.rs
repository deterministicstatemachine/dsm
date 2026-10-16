// SPDX-License-Identifier: MIT OR Apache-2.0

//! The radio's way into the wallet.
//!
//! Bytes that arrive over BLE were written by whoever is in range: nothing on
//! the link says who wrote them. They are taken as one of two things only — a
//! `BleChunk` of a bilateral frame, which the frame coordinator reassembles,
//! or a whole Envelope v3 (`0x03`-framed) whose payload is a bilateral frame —
//! and both go to the bilateral transport, whose handlers check the frame
//! against its session and the counterparty's keys. Pairing frames have their
//! own entry (`processBleIdentityEnvelope`).
//!
//! Nothing here reaches the local entry (`crate::ingress`), the Core bridge or
//! the app router. Those run the wallet owner's requests, from the WebView and
//! the JNI exports; a peer in radio range is not the owner. A `BleEvent` is
//! this device's own BLE stack reporting what happened to it, so a peer's
//! bytes claiming to be one are refused too. Where bytes came from is decided
//! by the function they entered through, never by a flag carried beside them.

use crate::bluetooth::bilateral_transport_adapter::{
    BleTransportDelegate, TransportInboundMessage, TransportOutbound,
};
use crate::bluetooth::ble_frame_coordinator::{BleFrameCoordinator, FrameIngressResult};
use crate::generated as pb;
use dsm::types::error::DsmError;

/// Why bytes a peer wrote over BLE were not handed on.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RadioRefusal {
    /// The bytes do not decode as a canonical Envelope v3.
    #[error("not a canonical Envelope v3: {0}")]
    Undecodable(String),
    /// A BLE lifecycle event. Only this device's BLE stack reports those.
    #[error("a BleEvent is this device's own BLE stack speaking, never a peer")]
    PlatformEvent,
    /// An envelope that is not a bilateral frame: an app-router query or
    /// invoke, or any other payload the local entry runs.
    #[error("not a bilateral frame: {0}")]
    NotABilateralFrame(String),
}

/// What became of bytes a peer wrote over BLE that were not answered.
#[derive(Debug, thiserror::Error)]
pub enum RadioError {
    /// The bytes are not something a peer may send this device.
    #[error("refused: {0}")]
    Refused(RadioRefusal),
    /// The bilateral transport failed: a chunk its frame coordinator could
    /// not take, or a frame its handler refused.
    #[error("bilateral transport: {0}")]
    Bilateral(DsmError),
}

/// The bilateral frame a whole envelope from the radio carries: the payloads
/// a peer answers this device's bilateral steps with, and the one-op
/// `bilateral.confirm` invoke. Anything else is refused.
pub fn bilateral_frame_of(envelope: &pb::Envelope) -> Result<pb::BleFrameType, RadioRefusal> {
    match &envelope.payload {
        Some(pb::envelope::Payload::BilateralPrepareResponse(_)) => {
            Ok(pb::BleFrameType::BilateralPrepareResponse)
        }
        Some(pb::envelope::Payload::BilateralPrepareReject(_)) => {
            Ok(pb::BleFrameType::BilateralPrepareReject)
        }
        Some(pb::envelope::Payload::BilateralCommitResponse(_)) => {
            Ok(pb::BleFrameType::BilateralCommitResponse)
        }
        Some(pb::envelope::Payload::UniversalTx(tx)) => match tx.ops.as_slice() {
            [pb::UniversalOp {
                kind: Some(pb::universal_op::Kind::Invoke(invoke)),
                ..
            }] if invoke.method == "bilateral.confirm" => Ok(pb::BleFrameType::BilateralConfirm),
            ops => Err(RadioRefusal::NotABilateralFrame(describe_ops(ops))),
        },
        Some(pb::envelope::Payload::BleEvent(_)) => Err(RadioRefusal::PlatformEvent),
        Some(other) => Err(RadioRefusal::NotABilateralFrame(payload_name(other))),
        None => Err(RadioRefusal::NotABilateralFrame(
            "an envelope with no payload".to_string(),
        )),
    }
}

/// Take bytes a peer wrote over BLE from `peer_address`.
///
/// `0x03`-framed bytes are a whole envelope and must carry a bilateral frame
/// ([`bilateral_frame_of`]); anything else is a `BleChunk`, reassembled by
/// `coordinator`. A whole frame goes to `bilateral`. `Ok(None)` is nothing to
/// answer yet: a chunk of a frame still arriving, a transport acknowledgement,
/// or a frame its handler answers later.
pub async fn receive_from_radio<D: BleTransportDelegate + ?Sized>(
    coordinator: &BleFrameCoordinator,
    bilateral: &D,
    peer_address: &str,
    bytes: &[u8],
) -> Result<Option<Vec<TransportOutbound>>, RadioError> {
    let message = match bytes.split_first() {
        None => return Ok(None),
        Some((&0x03, raw)) => {
            let envelope = crate::envelope::from_canonical_bytes(raw)
                .map_err(|e| RadioError::Refused(RadioRefusal::Undecodable(e)))?;
            let frame_type = bilateral_frame_of(&envelope).map_err(RadioError::Refused)?;
            TransportInboundMessage {
                peer_address: peer_address.to_string(),
                frame_type,
                payload: raw.to_vec(),
            }
        }
        Some(_) => match coordinator
            .ingest_chunk(bytes)
            .await
            .map_err(RadioError::Bilateral)?
        {
            FrameIngressResult::NeedMoreChunks | FrameIngressResult::ProtocolControl(_) => {
                return Ok(None)
            }
            FrameIngressResult::MessageComplete { message } => TransportInboundMessage {
                peer_address: peer_address.to_string(),
                frame_type: message.frame_type,
                payload: message.payload,
            },
        },
    };
    let outbound = bilateral
        .on_transport_message(message)
        .await
        .map_err(RadioError::Bilateral)?;
    Ok(Some(outbound).filter(|frames| !frames.is_empty()))
}

/// The ops of a transaction that is not a bilateral frame, as a refusal names
/// them: each op's kind and its router method or path.
fn describe_ops(ops: &[pb::UniversalOp]) -> String {
    if ops.is_empty() {
        return "a transaction with no operations".to_string();
    }
    ops.iter()
        .map(|op| match &op.kind {
            Some(pb::universal_op::Kind::Invoke(invoke)) => format!("invoke {}", invoke.method),
            Some(pb::universal_op::Kind::Query(query)) => format!("query {}", query.path),
            Some(other) => payload_name(other),
            None => "an operation with no kind".to_string(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The variant name of a protobuf oneof value, without its contents.
fn payload_name<T: std::fmt::Debug>(value: &T) -> String {
    let shown = format!("{value:?}");
    match shown.split_once('(') {
        Some((name, _contents)) => name.to_string(),
        None => shown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bluetooth::bilateral_ble_handler::BilateralBleHandler;
    use crate::bluetooth::bilateral_transport_adapter::BilateralTransportAdapter;
    use crate::economic_fixtures::{self, TestIdentity};
    use dsm::core::bilateral_transaction_manager::BilateralTransactionManager;
    use dsm::core::contact_manager::DsmContactManager;
    use prost::Message;
    use serial_test::serial;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    /// The device a peer in range writes to: a wallet as wallet creation
    /// makes it, its app router installed as the app installs it (the Core
    /// bridge's adapter in front of the SDK router), and its BLE transport —
    /// frame coordinator and bilateral handler — as `init_dsm_sdk` builds them.
    struct Wallet {
        coordinator: BleFrameCoordinator,
        bilateral: BilateralTransportAdapter,
    }

    impl Wallet {
        fn new(seed: u8) -> Self {
            economic_fixtures::use_test_storage_dir();
            unsafe { crate::bridge::reset_bridge_handlers_for_tests() };
            let identity: TestIdentity = economic_fixtures::local_device(seed).0;
            assert!(
                crate::init::install_full_app_router_self_config().expect("install the router"),
                "the wallet's identity is not ready for its router"
            );
            // The wallet open, as its owner left it.
            *crate::sdk::session_manager::SESSION_MANAGER
                .lock()
                .expect("the session manager") =
                crate::sdk::session_manager::SessionManager::default();
            let manager = BilateralTransactionManager::new(
                DsmContactManager::new(identity.device_id),
                identity.signing_keypair(),
                identity.device_id,
                identity.genesis,
                Arc::new(crate::sdk::chain_tip_store::SqliteChainTipStore::new()),
            );
            let handler =
                BilateralBleHandler::new(Arc::new(RwLock::new(manager)), identity.device_id);
            Self {
                coordinator: BleFrameCoordinator::new(identity.device_id),
                bilateral: BilateralTransportAdapter::new(Arc::new(handler)),
            }
        }

        /// What this wallet does with `bytes` a peer wrote from its address.
        fn receive(&self, bytes: &[u8]) -> Result<Option<Vec<TransportOutbound>>, RadioError> {
            crate::runtime::get_runtime().block_on(receive_from_radio(
                &self.coordinator,
                &self.bilateral,
                PEER_ADDRESS,
                bytes,
            ))
        }
    }

    const PEER_ADDRESS: &str = "5A:3C:91:0E:77:D2";

    /// A peer's envelope as it goes on the air: `0x03`, then the canonical
    /// bytes of an envelope addressed from the peer's own (claimed) identity.
    fn on_air(payload: pb::envelope::Payload) -> Vec<u8> {
        let envelope =
            crate::bluetooth::bilateral_envelope::build_envelope(&[0x51; 32], &[0x52; 32], payload);
        let mut framed = vec![0x03];
        framed.extend(envelope.encode_to_vec());
        framed
    }

    /// A transaction of one app-router invoke, as the frontend builds one.
    fn invoke(method: &str, body: Vec<u8>) -> pb::envelope::Payload {
        pb::envelope::Payload::UniversalTx(pb::UniversalTx {
            ops: vec![pb::UniversalOp {
                op_id: Some(pb::Hash32 { v: vec![0x61; 32] }),
                actor: vec![0x51; 32],
                kind: Some(pb::universal_op::Kind::Invoke(pb::Invoke {
                    method: method.to_string(),
                    args: Some(pb::ArgPack {
                        codec: pb::Codec::Proto as i32,
                        body,
                        ..Default::default()
                    }),
                    ..Default::default()
                })),
            }],
            ..Default::default()
        })
    }

    fn refusal(received: Result<Option<Vec<TransportOutbound>>, RadioError>) -> RadioRefusal {
        match received {
            Err(RadioError::Refused(refusal)) => refusal,
            other => panic!("the wallet took the peer's bytes: {other:?}"),
        }
    }

    /// A peer in radio range cannot spend the wallet: a `wallet.sendSmart`
    /// invoke written over BLE is refused as not a bilateral frame, and
    /// nothing answers it — the app router never runs it.
    /// MUTATION CONTROL: handing what `bilateral_frame_of` refuses to the
    /// local entry (`crate::ingress::dispatch_ingress`), as the bridge did
    /// before, turns this red: the router runs the send, and its answer goes
    /// back to the peer.
    #[test]
    #[serial]
    fn a_radio_peer_cannot_invoke_wallet_send_smart() {
        let wallet = Wallet::new(0x5A);
        let send = pb::OnlineTransferSmartRequest {
            recipient_device_id: vec![0x51; 32],
            amount: "5".to_string(),
            token_id: "ERA".to_string(),
            memo: "from the radio".to_string(),
        };

        let refused =
            refusal(wallet.receive(&on_air(invoke("wallet.sendSmart", send.encode_to_vec()))));

        assert_eq!(
            refused,
            RadioRefusal::NotABilateralFrame("invoke wallet.sendSmart".to_string())
        );
    }

    /// A peer in radio range cannot lock the owner out: a
    /// `session.configure_lock` invoke written over BLE is refused, and the
    /// wallet still has no lock.
    /// MUTATION CONTROL: handing what `bilateral_frame_of` refuses to the
    /// local entry turns this red — the peer's PIN becomes the wallet's lock.
    #[test]
    #[serial]
    fn a_radio_peer_cannot_set_the_wallet_lock() {
        let wallet = Wallet::new(0x5B);
        crate::sdk::app_lock::clear().expect("the wallet starts with no lock");
        let configure = pb::SessionConfigureLockRequest {
            method: "pin".to_string(),
            secret: "1357".to_string(),
            ..Default::default()
        };

        let received = wallet.receive(&on_air(invoke(
            "session.configure_lock",
            configure.encode_to_vec(),
        )));

        assert!(
            !crate::sdk::app_lock::enrolled(),
            "a peer's bytes set the wallet's lock"
        );
        assert_eq!(
            refusal(received),
            RadioRefusal::NotABilateralFrame("invoke session.configure_lock".to_string())
        );
    }

    /// A peer in radio range cannot read the wallet: a `balance.list` query
    /// written over BLE is refused and nothing answers it.
    /// MUTATION CONTROL: handing what `bilateral_frame_of` refuses to the
    /// local entry turns this red with the router's answer to the query.
    #[test]
    #[serial]
    fn a_radio_peer_cannot_query_the_wallet() {
        let wallet = Wallet::new(0x5C);
        let query = pb::envelope::Payload::UniversalTx(pb::UniversalTx {
            ops: vec![pb::UniversalOp {
                op_id: Some(pb::Hash32 { v: vec![0x62; 32] }),
                actor: vec![0x51; 32],
                kind: Some(pb::universal_op::Kind::Query(pb::QueryOp {
                    path: "balance.list".to_string(),
                    ..Default::default()
                })),
            }],
            ..Default::default()
        });

        assert_eq!(
            refusal(wallet.receive(&on_air(query))),
            RadioRefusal::NotABilateralFrame("query balance.list".to_string())
        );
    }

    /// A peer cannot speak for this device's BLE stack: a `BleEvent` written
    /// over BLE — here one that would point a contact at the peer's address —
    /// is refused, never handled as a platform event.
    /// MUTATION CONTROL: handing what `bilateral_frame_of` refuses to the
    /// local entry turns this red.
    #[test]
    #[serial]
    fn a_radio_peer_cannot_send_a_ble_platform_event() {
        let wallet = Wallet::new(0x5D);
        let observed = pb::envelope::Payload::BleEvent(pb::BleEvent {
            ev: Some(pb::ble_event::Ev::IdentityObserved(
                pb::BleIdentityObserved {
                    address: PEER_ADDRESS.to_string(),
                    genesis_hash: vec![0x52; 32],
                    device_id: vec![0x51; 32],
                },
            )),
        });

        assert_eq!(
            refusal(wallet.receive(&on_air(observed))),
            RadioRefusal::PlatformEvent
        );
    }

    /// A confirm invoke is a bilateral frame only alone: a transaction that
    /// carries `bilateral.confirm` beside a router invoke is refused whole.
    /// MUTATION CONTROL: handing what `bilateral_frame_of` refuses to the
    /// local entry turns this red: the router runs both ops.
    #[test]
    #[serial]
    fn a_confirm_carrying_a_router_invoke_is_refused() {
        let wallet = Wallet::new(0x5E);
        let pb::envelope::Payload::UniversalTx(mut tx) = invoke("bilateral.confirm", Vec::new())
        else {
            panic!("an invoke is a transaction");
        };
        let pb::envelope::Payload::UniversalTx(send) = invoke("wallet.sendSmart", Vec::new())
        else {
            panic!("an invoke is a transaction");
        };
        tx.ops.extend(send.ops);

        assert_eq!(
            refusal(wallet.receive(&on_air(pb::envelope::Payload::UniversalTx(tx)))),
            RadioRefusal::NotABilateralFrame(
                "invoke bilateral.confirm, invoke wallet.sendSmart".to_string()
            )
        );
    }

    /// The gate refuses what is not a bilateral frame, not everything: a
    /// whole bilateral frame reaches the bilateral handler, which checks it
    /// against its sessions — here, a rejection of a proposal this wallet
    /// never made.
    #[test]
    #[serial]
    fn a_whole_bilateral_frame_reaches_the_bilateral_handler() {
        let wallet = Wallet::new(0x5F);
        let reject = pb::envelope::Payload::BilateralPrepareReject(pb::BilateralPrepareReject {
            commitment_hash: Some(pb::Hash32 { v: vec![0x63; 32] }),
            rejector_device_id: vec![0x51; 32],
            ..Default::default()
        });

        match wallet.receive(&on_air(reject)) {
            Err(RadioError::Bilateral(e)) => assert!(
                e.to_string()
                    .contains("no session found for commitment hash"),
                "{e}"
            ),
            other => panic!("the frame did not reach the bilateral handler: {other:?}"),
        }
    }

    /// Bytes framed as a whole envelope that are not a canonical Envelope v3
    /// are refused as such.
    #[test]
    #[serial]
    fn undecodable_whole_bytes_are_refused() {
        let wallet = Wallet::new(0x60);
        assert!(matches!(
            refusal(wallet.receive(&[0x03, 0x0a, 0x00])),
            RadioRefusal::Undecodable(_)
        ));
    }
}
