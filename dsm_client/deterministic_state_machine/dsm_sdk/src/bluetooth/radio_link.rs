// SPDX-License-Identifier: MIT OR Apache-2.0

//! The radio's way in and out of the wallet, for any host (DSM Amendment
//! A27, SA-35).
//!
//! The host moves bytes on a link and nothing else. Every byte it takes from
//! the radio comes here, where the link session opens it
//! (`crate::bluetooth::link_session`); every byte it writes was sealed here
//! for the link Rust chose. Rust chooses the link: a frame for a contact is
//! sealed on the link this wallet is paired with it on and handed to the host
//! to write on exactly that link (`crate::host::HostBridge::write_on_link`);
//! with no such link the host is asked to connect, and the frame stays owed
//! until the link's handshake pairs it. A link that is gone fails closed;
//! nothing switches to another link.
//!
//! This is the one copy of that logic; the JNI exports and the C ABI are its
//! callers.

use crate::bluetooth::bilateral_session::OfflineFrameKind;
use crate::bluetooth::link_session::{links, GattRole, Link, WalletKeys};
use crate::bluetooth::owed_frame_driver::FrameKey;
use crate::generated as pb;
use crate::host::Delivery;

/// Why radio bytes were not taken, with the error taxonomy the hosts report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RadioWriteError {
    /// The bytes themselves were refused: a handshake that failed, a record
    /// that does not open, bytes that are neither. The link closes.
    Refused(String),
    /// The wallet cannot take them yet: the BLE transport is not built.
    NotReady(String),
    /// The bytes were taken and the step they carry failed.
    Failed(String),
}

impl RadioWriteError {
    /// The numeric code of the error taxonomy (`JniErrorCode`).
    pub fn code(&self) -> u32 {
        match self {
            RadioWriteError::Refused(_) => 1,
            RadioWriteError::Failed(_) => 2,
            RadioWriteError::NotReady(_) => 5,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            RadioWriteError::Refused(why)
            | RadioWriteError::NotReady(why)
            | RadioWriteError::Failed(why) => why,
        }
    }
}

impl std::fmt::Display for RadioWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}

/// A GATT link came up at `address`, this device on it as `role`. The client
/// names the contact it reached for in `target` (none when it connected to
/// any DSM device). Answers the radio bytes to write on the link: the
/// client's first Hello, nothing for the server. A target contact's pairing
/// moves to its handshake. An error means the link is not opened: the host
/// closes it.
pub fn link_opened(
    address: &str,
    role: GattRole,
    target: Option<[u8; 32]>,
) -> Result<Vec<Vec<u8>>, String> {
    if let Some(contact) = target {
        crate::runtime::get_runtime()
            .block_on(crate::bluetooth::get_pairing_orchestrator().link_opened(contact, address));
    }
    links()
        .opened(
            Link {
                address: address.to_string(),
                role,
            },
            target,
            &WalletKeys,
        )
        .map_err(|e| e.to_string())
}

/// The GATT link at `address`, this device on it as `role`, closed: its
/// session is dropped. A paired link's contact is reached for again by the
/// owed-frame driver, and an unfinished pairing on it is retried.
pub fn link_closed(address: &str, role: GattRole) {
    let paired = links().closed(&Link {
        address: address.to_string(),
        role,
    });
    if let Some(peer) = paired {
        crate::bluetooth::owed_frame_driver::link_down(&peer.device_id);
    }
    crate::runtime::get_runtime()
        .block_on(crate::bluetooth::get_pairing_orchestrator().handle_peer_disconnected(address));
}

/// The BLE frame type an owed offline frame travels as.
fn owed_frame_type(kind: OfflineFrameKind) -> pb::BleFrameType {
    match kind {
        OfflineFrameKind::Prepare => pb::BleFrameType::BilateralPrepare,
        OfflineFrameKind::PrepareResponse => pb::BleFrameType::BilateralPrepareResponse,
        OfflineFrameKind::Confirm => pb::BleFrameType::BilateralConfirm,
    }
}

/// Every frame this device owes `counterparty`, chunked and sealed on
/// `link`, the link that just paired with it, to be written behind the answer
/// that paired it. Each is marked delivered; one the link drops before it is
/// written goes again on the next link.
fn owed_frames_on(link: &Link, counterparty: &[u8; 32]) -> Vec<Vec<u8>> {
    let rt = crate::runtime::get_runtime();
    let (coord, adapter) = match (
        rt.block_on(crate::bridge::get_ble_coordinator()),
        rt.block_on(crate::bridge::get_ble_transport_adapter()),
    ) {
        (Ok(coord), Ok(adapter)) => (coord, adapter),
        (Err(e), _) | (_, Err(e)) => {
            log::warn!("[BLE link] owed frames not delivered: the BLE transport is not ready: {e}");
            return Vec::new();
        }
    };
    let owed = rt.block_on(adapter.bilateral_handler().frames_owed_to(counterparty));
    let mut sealed = Vec::new();
    let mut delivered = Vec::new();
    for frame in owed {
        let on_link = coord
            .encode_message(owed_frame_type(frame.kind), &frame.bytes)
            .and_then(|chunks| links().seal_on(link, &chunks));
        match on_link {
            Ok(records) => {
                sealed.extend(records);
                delivered.push((frame.commitment_hash, frame.kind));
            }
            Err(e) => log::error!(
                "[BLE link] an owed {:?} was not sealed on the link: {e}; it stays owed",
                frame.kind
            ),
        }
    }
    crate::bluetooth::owed_frame_driver::delivered(*counterparty, &delivered);
    sealed
}

/// One write from the radio on the link at `address`, as `role`: the radio
/// bytes to write back on that link. The bytes go first to the link session:
/// a handshake fragment is answered on the link, a sealed record is opened.
/// Only a unit a link opened reaches `crate::bluetooth::radio_ingress`, which
/// hands a bilateral frame to the bilateral transport and refuses everything
/// else; what the transport answers is sealed on the same link. When a write
/// pairs the link, the contact's pairing completes and the frames owed to it
/// are sealed behind the answer.
pub fn radio_write(
    address: &str,
    role: GattRole,
    bytes: &[u8],
) -> Result<Vec<Vec<u8>>, RadioWriteError> {
    let link = Link {
        address: address.to_string(),
        role,
    };
    let inbound = links()
        .inbound(&link, bytes, &WalletKeys)
        .map_err(|e| RadioWriteError::Refused(e.to_string()))?;
    let mut response_chunks = inbound.reply;
    let rt = crate::runtime::get_runtime();
    if let Some(peer) = inbound.paired {
        rt.block_on(crate::bluetooth::get_pairing_orchestrator().link_paired(&peer, address))
            .map_err(RadioWriteError::Failed)?;
        crate::bluetooth::peer_address::record_sighting(&peer.device_id, address);
        response_chunks.extend(owed_frames_on(&link, &peer.device_id));
    }
    let Some(unit) = inbound.unit else {
        return Ok(response_chunks);
    };
    let coord = rt
        .block_on(crate::bridge::get_ble_coordinator())
        .map_err(RadioWriteError::NotReady)?;
    let adapter = rt
        .block_on(crate::bridge::get_ble_transport_adapter())
        .map_err(RadioWriteError::NotReady)?;
    let outbounds = rt
        .block_on(crate::bluetooth::radio_ingress::receive_from_radio(
            &coord,
            adapter.as_ref(),
            address,
            &unit,
        ))
        .map_err(|e| match e {
            crate::bluetooth::radio_ingress::RadioError::Refused(refusal) => {
                RadioWriteError::Refused(refusal.to_string())
            }
            crate::bluetooth::radio_ingress::RadioError::Bilateral(e) => {
                RadioWriteError::Failed(e.to_string())
            }
        })?;
    // Every answer is chunked, so each chunk fits one sealed record.
    let mut units = Vec::new();
    for outbound in outbounds.into_iter().flatten() {
        if outbound.payload.is_empty() {
            continue;
        }
        units.extend(
            coord
                .encode_message(outbound.frame_type, &outbound.payload)
                .map_err(|e| RadioWriteError::Failed(e.to_string()))?,
        );
    }
    response_chunks.extend(
        links()
            .seal_on(&link, &units)
            .map_err(|e| RadioWriteError::Failed(e.to_string()))?,
    );
    Ok(response_chunks)
}

/// Send one message's chunks to the contact `device_id` (the owner's choice
/// of 2026-11-01: "Rust chooses the link"): sealed on the link this device
/// is paired with it on, and handed to the host to write on exactly that
/// link. With no paired link, the host is asked to connect, reaching for
/// `address_hint` first, and the frame is not delivered now: the link's
/// handshake delivers what is owed once it pairs. The frame of a send that
/// is `NotNow` stays owed.
pub fn send_to_contact(
    device_id: &[u8; 32],
    address_hint: Option<&str>,
    chunks: &[Vec<u8>],
) -> Result<Delivery, String> {
    let host = crate::host::host()?;
    match links().link_of(device_id) {
        Some(link) => {
            let sealed = links().seal_on(&link, chunks).map_err(|e| e.to_string())?;
            host.write_on_link(&link, &sealed)
        }
        None => {
            host.request_connect(device_id, address_hint)?;
            Ok(Delivery::NotNow)
        }
    }
}

/// Send a reply on the link at `address` the frame it answers arrived on,
/// sealed for that link's session. Nothing reconnects for it: a reply whose
/// link is gone is answered again when the counterparty sends its frame
/// again.
pub fn send_reply_on_link(address: &str, chunks: &[Vec<u8>]) -> Result<Delivery, String> {
    match links().at_address(address).into_iter().next() {
        Some(link) => {
            let sealed = links().seal_on(&link, chunks).map_err(|e| e.to_string())?;
            crate::host::host()?.write_on_link(&link, &sealed)
        }
        None => Ok(Delivery::NotNow),
    }
}

/// Deliver every frame this device owes `counterparty`, reaching for it at
/// `address_hint` first; answers the frames delivered. A frame that cannot be
/// sent now stays owed; the next link-up, or the owed-frame driver, delivers
/// it again.
pub fn deliver_owed_frames(counterparty: &[u8; 32], address_hint: Option<&str>) -> Vec<FrameKey> {
    let rt = crate::runtime::get_runtime();
    let (coord, adapter) = match (
        rt.block_on(crate::bridge::get_ble_coordinator()),
        rt.block_on(crate::bridge::get_ble_transport_adapter()),
    ) {
        (Ok(coord), Ok(adapter)) => (coord, adapter),
        (Err(e), _) | (_, Err(e)) => {
            log::warn!("[BLE link] owed frames not delivered: the BLE transport is not ready: {e}");
            return Vec::new();
        }
    };
    let owed = rt.block_on(adapter.bilateral_handler().frames_owed_to(counterparty));
    let counterparty_b32 = crate::util::text_id::encode_base32_crockford(counterparty);
    let counterparty_short = match counterparty_b32.get(..8) {
        Some(short) => short,
        None => counterparty_b32.as_str(),
    };
    let mut delivered = Vec::new();
    for frame in owed {
        let sent = coord
            .encode_message(owed_frame_type(frame.kind), &frame.bytes)
            .map_err(|e| e.to_string())
            .and_then(|chunks| send_to_contact(counterparty, address_hint, &chunks));
        let step = crate::util::text_id::encode_base32_crockford(&frame.commitment_hash[..8]);
        // A frame not delivered stays owed: the outcome is the driver's pacing
        // input, and what kept it from going is said.
        let kept_from_going = match sent {
            Ok(Delivery::Sent) => {
                log::info!(
                    "[BLE link] delivered owed {:?} for step {step} to {counterparty_short}",
                    frame.kind
                );
                delivered.push((frame.commitment_hash, frame.kind));
                continue;
            }
            Ok(Delivery::NotNow) => "no paired link now".to_string(),
            Err(why) => why,
        };
        log::warn!(
            "[BLE link] owed {:?} for step {step} not delivered to {counterparty_short} ({kept_from_going}); it stays owed",
            frame.kind
        );
    }
    delivered
}

/// The user accepts the proposal with `commitment`: the prepare response is
/// authored, sent to the sender over the link Rust chooses, and answered to
/// the page as a framed envelope. A send that did not complete fails
/// nothing: the acceptance is kept and its response is sent again when the
/// link returns, and the page is told so.
pub fn accept_proposal(commitment: [u8; 32]) -> Result<Vec<u8>, RadioWriteError> {
    crate::sdk::session_manager::refuse_while_locked("acceptBilateralByCommitment")
        .map_err(RadioWriteError::Failed)?;
    let rt = crate::runtime::get_runtime();
    let coord = rt
        .block_on(crate::bridge::get_ble_coordinator())
        .map_err(|e| RadioWriteError::NotReady(format!("BLE coordinator not ready: {e}")))?;
    let adapter = rt
        .block_on(crate::bridge::get_ble_transport_adapter())
        .map_err(|e| RadioWriteError::NotReady(format!("BLE transport adapter not ready: {e}")))?;
    let (envelope_bytes, counterparty) = rt
        .block_on(adapter.create_prepare_accept_envelope_with_counterparty(commitment))
        .map_err(|e| RadioWriteError::Failed(format!("acceptBilateralByCommitment failed: {e}")))?;
    // Where to look for the sender first: the link its prepare arrived on,
    // else where its appliance was last seen.
    let address_hint = rt
        .block_on(adapter.sender_ble_address_for_commitment(commitment))
        .or_else(|| last_seen_address(&counterparty));
    let chunks = coord
        .encode_message(pb::BleFrameType::BilateralPrepareResponse, &envelope_bytes)
        .map_err(|e| RadioWriteError::Failed(format!("chunking accept envelope failed: {e}")))?;
    match send_to_contact(&counterparty, address_hint.as_deref(), &chunks) {
        Ok(Delivery::Sent) => crate::bluetooth::owed_frame_driver::delivered(
            counterparty,
            &[(commitment, OfflineFrameKind::PrepareResponse)],
        ),
        Ok(Delivery::NotNow) => {
            crate::bluetooth::owed_frame_driver::kick();
            return Err(RadioWriteError::Failed(
                "the response was not delivered now; it is sent again when the link returns"
                    .to_string(),
            ));
        }
        Err(e) => return Err(RadioWriteError::Failed(format!("BLE send failed: {e}"))),
    }
    Ok(framed(&envelope_bytes))
}

/// The user rejects the proposal with `commitment`, for `reason`: the
/// rejection is authored and sent, and answered to the page framed.
pub fn reject_proposal(commitment: [u8; 32], reason: String) -> Result<Vec<u8>, RadioWriteError> {
    crate::sdk::session_manager::refuse_while_locked("rejectBilateralByCommitment")
        .map_err(RadioWriteError::Failed)?;
    let rt = crate::runtime::get_runtime();
    let coord = rt
        .block_on(crate::bridge::get_ble_coordinator())
        .map_err(|e| RadioWriteError::NotReady(format!("BLE coordinator not ready: {e}")))?;
    let adapter = rt
        .block_on(crate::bridge::get_ble_transport_adapter())
        .map_err(|e| RadioWriteError::NotReady(format!("BLE transport adapter not ready: {e}")))?;
    let envelope_bytes = rt
        .block_on(adapter.create_prepare_reject_envelope_with_cleanup(commitment, reason))
        .map_err(|e| RadioWriteError::Failed(format!("rejectBilateralByCommitment failed: {e}")))?;
    let counterparty = rt
        .block_on(adapter.counterparty_for_commitment(commitment))
        .ok_or_else(|| {
            RadioWriteError::Failed(
                "rejectBilateralByCommitment: the step names no counterparty".to_string(),
            )
        })?;
    let address_hint = rt
        .block_on(adapter.sender_ble_address_for_commitment(commitment))
        .or_else(|| last_seen_address(&counterparty));
    let chunks = coord
        .chunk_message(pb::BleFrameType::BilateralPrepareReject, &envelope_bytes)
        .map_err(|e| RadioWriteError::Failed(format!("chunking reject envelope failed: {e}")))?;
    match send_to_contact(&counterparty, address_hint.as_deref(), &chunks) {
        Ok(Delivery::Sent) => Ok(framed(&envelope_bytes)),
        Ok(Delivery::NotNow) => Err(RadioWriteError::Failed(
            "the frame was not delivered now".to_string(),
        )),
        Err(e) => Err(RadioWriteError::Failed(format!("BLE send failed: {e}"))),
    }
}

/// The proposer cancels a proposal it has not confirmed and sends the signed
/// cancellation to the counterparty. The cancellation holds whether or not
/// this send completes: it is also the answer to the counterparty's next
/// frame for the step.
pub fn cancel_proposal(commitment: [u8; 32], reason: String) -> Result<Vec<u8>, RadioWriteError> {
    crate::sdk::session_manager::refuse_while_locked("cancelBilateralByCommitment")
        .map_err(RadioWriteError::Failed)?;
    let rt = crate::runtime::get_runtime();
    let (coord, adapter) = match (
        rt.block_on(crate::bridge::get_ble_coordinator()),
        rt.block_on(crate::bridge::get_ble_transport_adapter()),
    ) {
        (Ok(coord), Ok(adapter)) => (coord, adapter),
        (Err(e), _) | (_, Err(e)) => {
            return Err(RadioWriteError::NotReady(format!(
                "BLE transport not ready: {e}"
            )))
        }
    };
    let counterparty = rt.block_on(adapter.counterparty_for_commitment(commitment));
    let cancellation = rt
        .block_on(
            adapter
                .bilateral_handler()
                .cancel_proposal(commitment, reason),
        )
        .map_err(|e| RadioWriteError::Failed(format!("cancelBilateralByCommitment failed: {e}")))?;
    if let Some(counterparty) = counterparty {
        let address_hint = last_seen_address(&counterparty);
        let sent = coord
            .chunk_message(pb::BleFrameType::BilateralPrepareReject, &cancellation)
            .map_err(|e| e.to_string())
            .and_then(|chunks| send_to_contact(&counterparty, address_hint.as_deref(), &chunks));
        if !matches!(sent, Ok(Delivery::Sent)) {
            log::warn!(
                "[BLE] cancellation not delivered now ({sent:?}); it answers the counterparty's next frame"
            );
        }
    }
    Ok(framed(&cancellation))
}

/// Where `counterparty`'s appliance was last seen, as a hint for the host's
/// connect. A contact store that cannot answer is reported, and the connect
/// goes without a hint: the hint narrows the search, it never gates it.
fn last_seen_address(counterparty: &[u8; 32]) -> Option<String> {
    match crate::bluetooth::peer_address::counterparty_address(counterparty) {
        Ok(hint) => hint,
        Err(e) => {
            log::warn!(
                "[BLE link] the contact store did not answer where the appliance was seen: {e}"
            );
            None
        }
    }
}

/// `0x03 ‖ envelope`, as the page reads one.
fn framed(envelope: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(1 + envelope.len());
    framed.push(0x03);
    framed.extend_from_slice(envelope);
    framed
}
