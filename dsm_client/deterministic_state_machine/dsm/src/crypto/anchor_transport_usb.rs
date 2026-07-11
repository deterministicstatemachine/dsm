// SPDX-License-Identifier: MIT OR Apache-2.0
//! USB (WebUSB) [`AnchorTransport`] — a production host transport to a forked
//! Trezor Safe 7 over the simple **codec_v1** wire. Co-equal with the BLE
//! transport (the device is provisioned for both USB and Bluetooth).
//!
//! # Why codec_v1 (not THP)
//!
//! DSM's offline-bearer security is end-to-end at the **application** layer: the
//! island signature over the device-recomputed challenge, the consent transcript,
//! and the on-chip monotonic frontier — exactly what
//! [`crate::crypto::anchor_transport::verify_anchor_signature`] checks. The
//! transport only needs to deliver `DsmAnchorSign` and return the signed
//! `DsmAnchorSignature`, so the encrypted/paired THP layer is redundant here and
//! the plain codec_v1 framing (`?##` + type + length, 64-byte reports) is
//! sufficient and fully implementable host-side. The forked firmware must be
//! built with `USE_THP=false` so it speaks codec_v1 on this link.
//!
//! # What the device provides vs. what the record needs
//!
//! `DsmAnchorGetIdentity` returns only the raw Ed25519 `anchor_pubkey` + slot.
//! The host [`crate::crypto::anchor_transport::AnchorIdentityRecord`] also needs
//! `firmware_id` / `screen_template_id` (device display constants the host pins)
//! and `firmware_hash` (the secmon-measured value, returned in the signature and
//! pinned at enrollment) — `verify_anchor_signature` consumes exactly those, not
//! `commitment_c` / `id_anchor`. So those pinned constants live on
//! [`UsbAnchorConfig`]; the pubkey is wrapped into SPKI and `id_anchor` is derived
//! with the same domain the in-process mock uses.
//!
//! Host-only: gated behind the `usb-anchor` cargo feature so it never enters the
//! Android cross-compile.

use crate::crypto::anchor_transport::{AnchorIdentityRecord, AnchorSignRequest, AnchorTransport};
use crate::types::error::DsmError;
use async_trait::async_trait;
use prost::Message as _;
use rusb::{DeviceHandle, GlobalContext};
use std::time::Duration;

/// Prost-generated DsmAnchor message types (see `proto/anchor_usb.proto`).
mod proto {
    #![allow(clippy::all, clippy::pedantic, clippy::nursery)]
    include!(concat!(env!("OUT_DIR"), "/dsm.anchor.usb.rs"));
}

// --- codec_v1 wire constants (must match trezor/wire/codec/codec_v1.py) ---
const REP_MARKER: u8 = 0x3f; // '?'
const REP_MAGIC: u8 = 0x23; // '#'
const REPORT_LEN: usize = 64;
const REP_INIT_DATA: usize = 9; // marker(1) + magic(2) + type(2) + len(4)
const REP_CONT_DATA: usize = 1; // marker(1)

// --- DsmAnchor MessageType numbers (common/protob/messages.proto) ---
const MT_GET_IDENTITY: u16 = 2300;
const MT_IDENTITY: u16 = 2301;
const MT_SIGN: u16 = 2302;
const MT_SIGNATURE: u16 = 2303;

/// Minimal Ed25519 SubjectPublicKeyInfo prefix — matches the verifier's parser
/// and the firmware's `_ED25519_SPKI_PREFIX`.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

fn ed25519_raw_to_spki(raw_pubkey: &[u8]) -> Vec<u8> {
    let mut spki = Vec::with_capacity(ED25519_SPKI_PREFIX.len() + raw_pubkey.len());
    spki.extend_from_slice(&ED25519_SPKI_PREFIX);
    spki.extend_from_slice(raw_pubkey);
    spki
}

/// Connection + pinned-device-constant configuration for [`UsbAnchorTransport`].
#[derive(Clone)]
pub struct UsbAnchorConfig {
    /// USB vendor id (Trezor T-series WebUSB default `0x1209`).
    pub vendor_id: u16,
    /// USB product id (Trezor T-series default `0x53c1`).
    pub product_id: u16,
    /// WebUSB interface number to claim.
    pub interface: u8,
    /// Bulk IN endpoint (device → host).
    pub ep_in: u8,
    /// Bulk OUT endpoint (host → device).
    pub ep_out: u8,
    /// Per-transfer timeout. `sign` blocks on human hold-to-confirm, so this must
    /// be generous.
    pub timeout: Duration,
    /// Pinned DSM firmware identity displayed/folded into the UI transcript.
    pub firmware_id: [u8; 32],
    /// Pinned screen-layout template id.
    pub screen_template_id: u32,
    /// Enrolled secmon-measured firmware hash (pinned at admission).
    pub firmware_hash: [u8; 32],
    /// Birth commitment `C` if known (folded only into the host-derived
    /// `id_anchor`; not part of signature verification).
    pub commitment_c: [u8; 32],
    /// Genesis / identity root carried in `DsmAnchorSign` for receipt
    /// completeness (NOT in the signed challenge).
    pub genesis_hash: [u8; 32],
}

impl Default for UsbAnchorConfig {
    fn default() -> Self {
        Self {
            vendor_id: 0x1209,
            product_id: 0x53c1,
            interface: 0,
            ep_in: 0x81,
            ep_out: 0x01,
            timeout: Duration::from_secs(120),
            firmware_id: [0u8; 32],
            screen_template_id: 1,
            firmware_hash: [0u8; 32],
            commitment_c: [0u8; 32],
            genesis_hash: [0u8; 32],
        }
    }
}

/// Host transport that drives a forked Safe 7 anchor over WebUSB + codec_v1.
pub struct UsbAnchorTransport {
    cfg: UsbAnchorConfig,
    handle: std::sync::Mutex<Option<DeviceHandle<GlobalContext>>>,
}

impl std::fmt::Debug for UsbAnchorTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsbAnchorTransport")
            .field("vendor_id", &format_args!("{:04x}", self.cfg.vendor_id))
            .field("product_id", &format_args!("{:04x}", self.cfg.product_id))
            .field("interface", &self.cfg.interface)
            .finish()
    }
}

impl UsbAnchorTransport {
    /// Construct a transport. The device is opened lazily on first call.
    pub fn new(cfg: UsbAnchorConfig) -> Self {
        Self {
            cfg,
            handle: std::sync::Mutex::new(None),
        }
    }

    fn open_device(&self) -> Result<DeviceHandle<GlobalContext>, DsmError> {
        let handle = rusb::open_device_with_vid_pid(self.cfg.vendor_id, self.cfg.product_id)
            .ok_or_else(|| {
                DsmError::invalid_parameter(format!(
                    "usb anchor: device {:04x}:{:04x} not found",
                    self.cfg.vendor_id, self.cfg.product_id
                ))
            })?;
        // Best-effort on platforms that support it (Linux); no-op elsewhere.
        let _ = handle.set_auto_detach_kernel_driver(true);
        handle.claim_interface(self.cfg.interface).map_err(|e| {
            DsmError::invalid_parameter(format!(
                "usb anchor: claim_interface({}) failed: {e}",
                self.cfg.interface
            ))
        })?;
        Ok(handle)
    }

    /// One request/response round-trip; opens the device on first use.
    fn transact(&self, req_type: u16, payload: &[u8]) -> Result<(u16, Vec<u8>), DsmError> {
        let mut guard = self
            .handle
            .lock()
            .map_err(|_| DsmError::invalid_parameter("usb anchor: device handle lock poisoned"))?;
        if guard.is_none() {
            *guard = Some(self.open_device()?);
        }
        let handle = guard
            .as_ref()
            .ok_or_else(|| DsmError::invalid_parameter("usb anchor: device handle unexpectedly absent"))?;
        write_message(handle, self.cfg.ep_out, self.cfg.timeout, req_type, payload)?;
        read_message(handle, self.cfg.ep_in, self.cfg.timeout)
    }

    fn fetch_identity(&self) -> Result<AnchorIdentityRecord, DsmError> {
        let payload = proto::DsmAnchorGetIdentity {}.encode_to_vec();
        let (mtype, resp) = self.transact(MT_GET_IDENTITY, &payload)?;
        if mtype != MT_IDENTITY {
            return Err(DsmError::verification(format!(
                "usb anchor: expected DsmAnchorIdentity ({MT_IDENTITY}), got {mtype}"
            )));
        }
        let id = proto::DsmAnchorIdentity::decode(resp.as_slice())
            .map_err(|e| DsmError::invalid_parameter(format!("usb anchor: decode identity: {e}")))?;
        let pubkey = id
            .anchor_pubkey
            .ok_or_else(|| DsmError::verification("usb anchor: anchor_pubkey missing in response"))?;
        if pubkey.len() != 32 {
            return Err(DsmError::verification(format!(
                "usb anchor: anchor_pubkey length {} != 32",
                pubkey.len()
            )));
        }
        Ok(self.record_from_pubkey(&pubkey))
    }

    fn record_from_pubkey(&self, pubkey: &[u8]) -> AnchorIdentityRecord {
        let leaf_spki = ed25519_raw_to_spki(pubkey);
        let id_anchor = {
            let mut h = crate::crypto::blake3::dsm_domain_hasher("DSM/anchor-id/v1");
            h.update(&self.cfg.commitment_c);
            h.update(pubkey);
            *h.finalize().as_bytes()
        };
        AnchorIdentityRecord {
            id_anchor,
            commitment_c: self.cfg.commitment_c,
            leaf_spki,
            firmware_id: self.cfg.firmware_id,
            screen_template_id: self.cfg.screen_template_id,
            firmware_hash: self.cfg.firmware_hash,
        }
    }

    fn build_sign_message(&self, req: &AnchorSignRequest<'_>) -> proto::DsmAnchorSign {
        proto::DsmAnchorSign {
            amount: Some(req.amount),
            asset: Some(req.asset.to_vec()),
            counterparty_id: Some(req.counterparty_id.to_vec()),
            policy_id: Some(req.policy_id.to_vec()),
            firmware_id: Some(self.cfg.firmware_id.to_vec()),
            screen_template_id: Some(self.cfg.screen_template_id),
            h_n: Some(req.h_n.to_vec()),
            payload_hash: Some(req.payload_hash.to_vec()),
            relationship_id: Some(req.relationship_id.to_vec()),
            device_id: Some(req.device_id.to_vec()),
            value_capability: Some(u32::from(req.value_capability)),
            offline_bearer_mode: Some(u32::from(req.offline_bearer_mode)),
            nonce: Some(req.nonce.to_vec()),
            expiry_tick: Some(req.expiry_tick),
            genesis_hash: Some(self.cfg.genesis_hash.to_vec()),
            policy_hash: Some(req.policy_hash.to_vec()),
            successor_root: Some(req.successor_root.to_vec()),
            state_number: Some(req.state_number),
            parent_root: Some(req.parent_root.to_vec()),
        }
    }
}

#[async_trait]
impl AnchorTransport for UsbAnchorTransport {
    async fn birth(&self, _device_context: &[u8]) -> Result<AnchorIdentityRecord, DsmError> {
        // The firmware self-provisions the anchor key lazily on first identity
        // read; there is no separate birth ceremony over this link.
        self.fetch_identity()
    }

    async fn get_identity(&self) -> Result<AnchorIdentityRecord, DsmError> {
        self.fetch_identity()
    }

    async fn sign(&self, req: &AnchorSignRequest<'_>) -> Result<Vec<u8>, DsmError> {
        let payload = self.build_sign_message(req).encode_to_vec();
        let (mtype, resp) = self.transact(MT_SIGN, &payload)?;
        if mtype != MT_SIGNATURE {
            return Err(DsmError::verification(format!(
                "usb anchor: expected DsmAnchorSignature ({MT_SIGNATURE}), got {mtype}"
            )));
        }
        let sig = proto::DsmAnchorSignature::decode(resp.as_slice())
            .map_err(|e| DsmError::invalid_parameter(format!("usb anchor: decode signature: {e}")))?;
        sig.signature
            .ok_or_else(|| DsmError::verification("usb anchor: signature missing in response"))
    }
}

// ===== codec_v1 framing (pure — unit-testable without hardware) =====

/// Split a `(mtype, payload)` message into 64-byte codec_v1 reports.
fn frame_message(mtype: u16, payload: &[u8]) -> Result<Vec<[u8; REPORT_LEN]>, DsmError> {
    let len = u32::try_from(payload.len())
        .map_err(|_| DsmError::invalid_parameter("usb anchor: payload too large for codec_v1"))?;
    let mut reports = Vec::new();

    let mut first = [0u8; REPORT_LEN];
    first[0] = REP_MARKER;
    first[1] = REP_MAGIC;
    first[2] = REP_MAGIC;
    first[3..5].copy_from_slice(&mtype.to_be_bytes());
    first[5..9].copy_from_slice(&len.to_be_bytes());
    let n0 = (REPORT_LEN - REP_INIT_DATA).min(payload.len());
    first[REP_INIT_DATA..REP_INIT_DATA + n0].copy_from_slice(&payload[..n0]);
    reports.push(first);

    let mut off = n0;
    while off < payload.len() {
        let mut cont = [0u8; REPORT_LEN];
        cont[0] = REP_MARKER;
        let take = (REPORT_LEN - REP_CONT_DATA).min(payload.len() - off);
        cont[REP_CONT_DATA..REP_CONT_DATA + take].copy_from_slice(&payload[off..off + take]);
        reports.push(cont);
        off += take;
    }
    Ok(reports)
}

/// Reassemble codec_v1 reports into `(mtype, payload)`.
fn dechunk(reports: &[[u8; REPORT_LEN]]) -> Result<(u16, Vec<u8>), DsmError> {
    let first = reports
        .first()
        .ok_or_else(|| DsmError::verification("usb anchor: empty response"))?;
    if first[0] != REP_MARKER || first[1] != REP_MAGIC || first[2] != REP_MAGIC {
        return Err(DsmError::verification("usb anchor: invalid codec_v1 header"));
    }
    let mtype = u16::from_be_bytes([first[3], first[4]]);
    let msize = u32::from_be_bytes([first[5], first[6], first[7], first[8]]) as usize;

    let mut data = Vec::with_capacity(msize);
    let n0 = (REPORT_LEN - REP_INIT_DATA).min(msize);
    data.extend_from_slice(&first[REP_INIT_DATA..REP_INIT_DATA + n0]);
    for cont in &reports[1..] {
        if data.len() >= msize {
            break;
        }
        if cont[0] != REP_MARKER {
            return Err(DsmError::verification("usb anchor: invalid continuation marker"));
        }
        let take = (REPORT_LEN - REP_CONT_DATA).min(msize - data.len());
        data.extend_from_slice(&cont[REP_CONT_DATA..REP_CONT_DATA + take]);
    }
    if data.len() != msize {
        return Err(DsmError::verification("usb anchor: truncated response"));
    }
    Ok((mtype, data))
}

fn write_message(
    handle: &DeviceHandle<GlobalContext>,
    ep_out: u8,
    timeout: Duration,
    mtype: u16,
    payload: &[u8],
) -> Result<(), DsmError> {
    for report in frame_message(mtype, payload)? {
        let n = handle
            .write_bulk(ep_out, &report, timeout)
            .map_err(|e| DsmError::invalid_parameter(format!("usb anchor: bulk write: {e}")))?;
        if n != report.len() {
            return Err(DsmError::invalid_parameter(format!(
                "usb anchor: short bulk write {n}/{}",
                report.len()
            )));
        }
    }
    Ok(())
}

fn read_message(
    handle: &DeviceHandle<GlobalContext>,
    ep_in: u8,
    timeout: Duration,
) -> Result<(u16, Vec<u8>), DsmError> {
    let mut reports: Vec<[u8; REPORT_LEN]> = Vec::new();

    let mut first = [0u8; REPORT_LEN];
    read_full(handle, ep_in, timeout, &mut first)?;
    if first[0] != REP_MARKER || first[1] != REP_MAGIC || first[2] != REP_MAGIC {
        return Err(DsmError::verification("usb anchor: invalid codec_v1 header"));
    }
    let msize = u32::from_be_bytes([first[5], first[6], first[7], first[8]]) as usize;
    let mut have = (REPORT_LEN - REP_INIT_DATA).min(msize);
    reports.push(first);

    while have < msize {
        let mut cont = [0u8; REPORT_LEN];
        read_full(handle, ep_in, timeout, &mut cont)?;
        reports.push(cont);
        have += REPORT_LEN - REP_CONT_DATA;
    }
    dechunk(&reports)
}

fn read_full(
    handle: &DeviceHandle<GlobalContext>,
    ep_in: u8,
    timeout: Duration,
    buf: &mut [u8; REPORT_LEN],
) -> Result<(), DsmError> {
    let n = handle
        .read_bulk(ep_in, buf, timeout)
        .map_err(|e| DsmError::invalid_parameter(format!("usb anchor: bulk read: {e}")))?;
    if n != buf.len() {
        return Err(DsmError::verification(format!(
            "usb anchor: short bulk read {n}/{}",
            buf.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_v1_frames_roundtrip_for_empty_single_and_multireport() {
        for payload in [vec![], vec![7u8; 10], vec![0xABu8; 55], vec![0x5Au8; 200]] {
            let reports = frame_message(MT_SIGN, &payload).expect("frame");
            // every report is exactly one 64-byte HID report, correctly marked.
            assert!(reports.iter().all(|r| r.len() == REPORT_LEN && r[0] == REP_MARKER));
            let (mtype, got) = dechunk(&reports).expect("dechunk");
            assert_eq!(mtype, MT_SIGN);
            assert_eq!(got, payload, "roundtrip mismatch for {}-byte payload", payload.len());
        }
    }

    #[test]
    fn dechunk_rejects_bad_header() {
        let mut report = [0u8; REPORT_LEN];
        report[0] = 0x00; // not the marker
        assert!(dechunk(&[report]).is_err());
    }

    #[test]
    fn dsm_anchor_sign_encodes_every_field_on_the_wire() {
        // proto3 `optional` => each Some field is emitted even at scalar default,
        // so the firmware's proto2 `required` decode never sees a missing field.
        let cfg = UsbAnchorConfig::default();
        let t = UsbAnchorTransport::new(cfg);
        let h_n = [1u8; 32];
        let payload = [2u8; 32];
        let rel = [3u8; 32];
        let dev = [4u8; 32];
        let cp = [5u8; 32];
        let policy = [6u8; 32];
        let policy_hash = [0u8; 32];
        let parent = [0u8; 32];
        let succ = [0u8; 32];
        let req = AnchorSignRequest {
            h_n: &h_n,
            payload_hash: &payload,
            relationship_id: &rel,
            device_id: &dev,
            value_capability: 1,
            offline_bearer_mode: 1,
            nonce: b"n0",
            expiry_tick: 9,
            amount: 0, // default scalar — must still be present on the wire
            asset: b"ERA",
            counterparty_id: &cp,
            policy_id: &policy,
            policy_hash: &policy_hash,
            parent_root: &parent,
            successor_root: &succ,
            state_number: 1,
        };
        let encoded = t.build_sign_message(&req).encode_to_vec();
        let decoded = proto::DsmAnchorSign::decode(encoded.as_slice()).expect("decode");
        assert_eq!(decoded.amount, Some(0)); // present despite default value
        assert_eq!(decoded.asset.as_deref(), Some(&b"ERA"[..]));
        assert_eq!(decoded.value_capability, Some(1));
        assert_eq!(decoded.state_number, Some(1));
        assert_eq!(decoded.firmware_id.as_deref(), Some(&[0u8; 32][..]));
    }
}
