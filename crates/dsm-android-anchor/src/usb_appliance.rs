// SPDX-License-Identifier: MIT OR Apache-2.0
//! Phone-side USB client for the PHYSICAL RP2350 + TROPIC01 anchor appliance (v2
//! Software-Authority / Hardware-Identity).
//!
//! The Pico firmware runs the full `anchor_core::Appliance` on real silicon and serves the
//! `ApplianceRequest`/`ApplianceResponse` protocol over USB-CDC (`LE32` length ++ prost body).
//! This is the concrete `AnchorAppliance` the SDK flagged as "a real RP2350 USB-CDC/BLE client ...
//! hardware follow-on" (`dsm_sdk::anchor::appliance_client`): each trait op is exactly one framed
//! round-trip to the chip, over the same opaque Kotlin USB round-trip as [`crate::usb_pico`].
//!
//! Installing this in place of `InProcessAnchorAppliance` makes the SENDER's `OfflineRelease` come
//! from the physical secure element: `σ^chip` is signed by the resident non-exportable Ed25519 key
//! on the die, `σ^host` by the RP2350 partition, and the COMMIT consumes a real TROPIC01
//! monotonic-counter step (the local double-spend floor). Every op fails CLOSED into `DsmError`
//! (transport error, on-chip error, or malformed response) so a missing/wedged chip can never
//! fabricate a release.

use anchor_core::appliance::RecoverOutcome;
use anchor_core::proto::{decode_response, encode_release, encode_request, pb};
use anchor_core::root_advance::{OwnedTransition, Transition};
use dsm::types::error::DsmError;
use dsm_sdk::anchor::{AnchorAppliance, AnchorPin, ApplianceStatus};

use crate::usb_pico::UsbTransceive;

/// A physical-chip appliance driven over USB. The `pin` is self-sourced from a STATUS round-trip
/// at construction — the chip self-describes its enrolled identity (`B`, `anchor_id`, `H0`,
/// `pk_host`, `pk_chip`), so there is no host-side enrollment DB and the pin is always the REAL
/// silicon's.
pub struct UsbAnchorAppliance {
    usb: UsbTransceive,
    pin: AnchorPin,
}

fn arr32(b: &[u8]) -> Result<[u8; 32], DsmError> {
    b.try_into()
        .map_err(|_| DsmError::invalid_operation("anchor appliance: expected 32-byte field"))
}

/// One appliance op over the transport: frame `LE32(len) ++ ApplianceRequest`, run the opaque USB
/// round-trip, decode `ApplianceResponse`, and fail closed unless the chip reported `ok`. Free
/// function so it is usable from `connect()` before `self` exists.
fn roundtrip(usb: &UsbTransceive, req: pb::ApplianceRequest) -> Result<pb::ApplianceResponse, DsmError> {
    let body = encode_request(&req);
    let mut frame = (body.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(&body);
    let resp_body = usb(frame)?;
    let resp = decode_response(&resp_body).map_err(|e| {
        DsmError::invalid_operation(format!("anchor appliance: decode response: {e:?}"))
    })?;
    if !resp.ok {
        return Err(DsmError::invalid_operation(format!(
            "anchor appliance: op {} failed on-chip (error code {})",
            resp.op, resp.error
        )));
    }
    Ok(resp)
}

fn bare(op: pb::Op) -> pb::ApplianceRequest {
    pb::ApplianceRequest {
        op: op as i32,
        ..Default::default()
    }
}

impl UsbAnchorAppliance {
    /// Connect to the physical appliance and self-source its pin from one STATUS round-trip.
    /// Fails closed if the chip is unreachable or STATUS omits any pin material (pre-v2 firmware)
    /// — an appliance whose identity cannot be read must never produce releases.
    pub fn connect(usb: UsbTransceive) -> Result<Self, DsmError> {
        let s = roundtrip(&usb, bare(pb::Op::Status))?;
        let pin = AnchorPin {
            bundle: arr32(&s.anchor_bundle)?,
            anchor_id: arr32(&s.pin_anchor_id)?,
            enrolled_counter: s.pin_enrolled_counter,
            partition_pk: s.pin_partition_pk,
            pk_chip: s.pin_chip_pk,
        };
        if pin.partition_pk.is_empty() || pin.pk_chip.len() != 32 {
            return Err(DsmError::invalid_operation(
                "anchor appliance: STATUS returned incomplete pin material (pk_host/pk_chip) — \
                 firmware lacks the v2 STATUS pin; cannot produce verifiable releases (fail closed)",
            ));
        }
        Ok(Self { usb, pin })
    }

    fn roundtrip(&self, req: pb::ApplianceRequest) -> Result<pb::ApplianceResponse, DsmError> {
        roundtrip(&self.usb, req)
    }
}

impl AnchorAppliance for UsbAnchorAppliance {
    fn status(&mut self) -> Result<ApplianceStatus, DsmError> {
        let r = self.roundtrip(bare(pb::Op::Status))?;
        Ok(ApplianceStatus {
            root: arr32(&r.active_root)?,
            anchor_counter: r.active_anchor_counter,
        })
    }

    fn prepare(
        &mut self,
        t: &Transition,
        receiver_challenge: &[u8; 32],
        sender_device_root_before: &[u8; 32],
        sender_device_root_after: &[u8; 32],
    ) -> Result<(), DsmError> {
        let req = pb::ApplianceRequest {
            op: pb::Op::Prepare as i32,
            transition: Some(OwnedTransition::from(t).to_pb()),
            receiver_challenge: receiver_challenge.to_vec(),
            sender_device_root_before: sender_device_root_before.to_vec(),
            sender_device_root_after: sender_device_root_after.to_vec(),
            ..Default::default()
        };
        self.roundtrip(req).map(|_| ())
    }

    fn commit(&mut self) -> Result<(), DsmError> {
        self.roundtrip(bare(pb::Op::Commit)).map(|_| ())
    }

    fn emit(&mut self) -> Result<Vec<u8>, DsmError> {
        let r = self.roundtrip(bare(pb::Op::Emit))?;
        let release = r.release.ok_or_else(|| {
            DsmError::invalid_operation("anchor appliance: EMIT returned no release")
        })?;
        // Re-encode the OfflineRelease sub-message to the exact bytes the in-process appliance's
        // emit() produces — the SDK attaches Π_i/Π_{i+1} and drops it into the confirm.
        Ok(encode_release(&release))
    }

    fn finalize(&mut self) -> Result<[u8; 32], DsmError> {
        let r = self.roundtrip(bare(pb::Op::Finalize))?;
        arr32(&r.active_root)
    }

    fn cancel(&mut self) -> Result<(), DsmError> {
        self.roundtrip(bare(pb::Op::Cancel)).map(|_| ())
    }

    fn recover(&mut self) -> Result<RecoverOutcome, DsmError> {
        // The wire has no OP_RECOVER: the firmware self-recovers at boot; over USB the client
        // OBSERVES via STATUS (0=Ready 1=Prepared 2=Committed) and maps to the §26 outcome the
        // host policy consumes. An unreadable/unknown status downgrades online (fail-safe).
        let r = self.roundtrip(bare(pb::Op::Status))?;
        Ok(match r.status {
            0 => RecoverOutcome::Accept(arr32(&r.active_root)?),
            1 => RecoverOutcome::AcceptPreparedCanComplete,
            2 => RecoverOutcome::ReemitCommitted(arr32(&r.active_root)?),
            _ => RecoverOutcome::DowngradeOnline,
        })
    }

    fn pin(&self) -> AnchorPin {
        self.pin.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn status_response(status: u32) -> Vec<u8> {
        anchor_core::proto::encode_response(&pb::ApplianceResponse {
            op: pb::Op::Status as i32,
            ok: true,
            active_root: vec![0x11; 32],
            anchor_bundle: vec![0xB1; 32],
            active_anchor_counter: 3,
            status,
            pin_anchor_id: vec![0xA1; 32],
            pin_enrolled_counter: 1_000,
            pin_partition_pk: vec![0x07; 64],
            pin_chip_pk: vec![0x0C; 32],
            ..Default::default()
        })
    }

    #[test]
    fn connect_self_sources_the_full_v2_pin_from_status() {
        let usb: UsbTransceive = Arc::new(|_frame| Ok(status_response(0)));
        let app = UsbAnchorAppliance::connect(usb).expect("connect");
        let pin = app.pin();
        assert_eq!(pin.bundle, [0xB1; 32]);
        assert_eq!(pin.anchor_id, [0xA1; 32]);
        assert_eq!(pin.enrolled_counter, 1_000);
        assert_eq!(pin.partition_pk, vec![0x07; 64]);
        assert_eq!(pin.pk_chip, vec![0x0C; 32]);
    }

    #[test]
    fn connect_fails_closed_without_pk_chip() {
        let usb: UsbTransceive = Arc::new(|_frame| {
            Ok(anchor_core::proto::encode_response(&pb::ApplianceResponse {
                op: pb::Op::Status as i32,
                ok: true,
                active_root: vec![0x11; 32],
                anchor_bundle: vec![0xB1; 32],
                pin_anchor_id: vec![0xA1; 32],
                pin_enrolled_counter: 1_000,
                pin_partition_pk: vec![0x07; 64],
                pin_chip_pk: Vec::new(), // pre-v2 firmware
                ..Default::default()
            }))
        });
        assert!(
            UsbAnchorAppliance::connect(usb).is_err(),
            "a pin without pk_chip cannot verify σ^chip — connect must fail closed"
        );
    }

    #[test]
    fn recover_maps_wire_status_to_the_section26_outcome() {
        for (wire, want_ready) in [(0u32, true), (1, false), (2, false), (9, false)] {
            let usb: UsbTransceive = Arc::new(move |_f| Ok(status_response(wire)));
            let mut app = UsbAnchorAppliance::connect(usb).expect("connect");
            let out = app.recover().expect("recover");
            match (wire, out) {
                (0, RecoverOutcome::Accept(r)) => assert_eq!(r, [0x11; 32]),
                (1, RecoverOutcome::AcceptPreparedCanComplete) => {}
                (2, RecoverOutcome::ReemitCommitted(r)) => assert_eq!(r, [0x11; 32]),
                (9, RecoverOutcome::DowngradeOnline) => {}
                (w, o) => panic!("wire status {w} mapped to unexpected {o:?} (ready={want_ready})"),
            }
        }
    }

    #[test]
    fn onchip_error_fails_closed() {
        let usb: UsbTransceive = Arc::new(|_frame| {
            Ok(anchor_core::proto::encode_response(&pb::ApplianceResponse {
                op: pb::Op::Status as i32,
                ok: false,
                error: 5,
                ..Default::default()
            }))
        });
        assert!(UsbAnchorAppliance::connect(usb).is_err());
    }
}
