// SPDX-License-Identifier: MIT OR Apache-2.0
//! Phone-side USB client for the PHYSICAL RP2350 + TROPIC01 fused-anchor appliance.
//!
//! The Pico firmware runs the full `anchor_core::Appliance` on real silicon and serves the
//! `ApplianceRequest`/`ApplianceResponse` protocol over USB-CDC (`LE32` length ++ prost body). This
//! is the concrete `AnchorAppliance` the SDK flagged as "a real RP2350 USB-CDC/BLE client ...
//! hardware follow-on" (`dsm_sdk::anchor::appliance_client`): each trait op is exactly one framed
//! round-trip to the chip, reusing the SAME opaque USB transport proven end-to-end in H2/H3.
//!
//! Installing this in place of `InProcessAnchorAppliance` makes the SENDER's `OfflineRelease` come
//! from the physical secure element and consume a real TROPIC01 monotonic-counter step — the
//! receiver then reads the decremented counter over the relay and the predicate `H == H0 − (u+1)`
//! holds against actual silicon. Every op fails CLOSED into `DsmError` (transport error, on-chip
//! error, or malformed response) so a missing/wedged chip can never fabricate a release.

use anchor_core::proto::{decode_response, encode_release, encode_request, pb};
use anchor_core::root_advance::{OwnedTransition, Transition};
use dsm::types::error::DsmError;
use dsm_sdk::anchor::{AnchorAppliance, AnchorPin, ApplianceStatus};

use crate::usb_pico::UsbTransceive;

/// A physical-chip appliance driven over USB. `pin` is the chip's enrolled identity
/// (`B`, `anchor_id`, `H0`, `partition_pk`), captured at admission because the appliance wire
/// protocol has no host op that returns it (STATUS returns `B` but not the rest).
pub struct UsbAnchorAppliance {
    usb: UsbTransceive,
    pin: AnchorPin,
}

fn arr32(b: &[u8]) -> Result<[u8; 32], DsmError> {
    b.try_into()
        .map_err(|_| DsmError::invalid_operation("anchor appliance: expected 32-byte field"))
}

impl UsbAnchorAppliance {
    pub fn new(usb: UsbTransceive, pin: AnchorPin) -> Self {
        Self { usb, pin }
    }

    /// One appliance op: frame `LE32(len) ++ ApplianceRequest`, run the opaque USB round-trip,
    /// decode `ApplianceResponse`, and fail closed unless the chip reported `ok`.
    fn roundtrip(&self, req: pb::ApplianceRequest) -> Result<pb::ApplianceResponse, DsmError> {
        let body = encode_request(&req);
        let mut frame = (body.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(&body);
        let resp_body = (self.usb)(frame)?;
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
}

impl AnchorAppliance for UsbAnchorAppliance {
    fn status(&mut self) -> Result<ApplianceStatus, DsmError> {
        let r = self.roundtrip(Self::bare(pb::Op::Status))?;
        Ok(ApplianceStatus {
            root: arr32(&r.active_root)?,
            anchor_head: arr32(&r.active_anchor_head)?,
            boot_head: arr32(&r.active_boot_head)?,
            committed_boot_head: arr32(&r.active_committed_boot_head)?,
            anchor_counter: r.active_anchor_counter,
        })
    }

    fn prepare(&mut self, t: &Transition, receiver_challenge: &[u8; 32]) -> Result<(), DsmError> {
        let req = pb::ApplianceRequest {
            op: pb::Op::Prepare as i32,
            transition: Some(OwnedTransition::from(t).to_pb()),
            receiver_challenge: receiver_challenge.to_vec(),
            ..Default::default()
        };
        self.roundtrip(req).map(|_| ())
    }

    fn commit(&mut self) -> Result<(), DsmError> {
        self.roundtrip(Self::bare(pb::Op::Commit)).map(|_| ())
    }

    fn emit(&mut self) -> Result<Vec<u8>, DsmError> {
        let r = self.roundtrip(Self::bare(pb::Op::Emit))?;
        let release = r.release.ok_or_else(|| {
            DsmError::invalid_operation("anchor appliance: EMIT returned no release")
        })?;
        // Re-encode the OfflineRelease sub-message to the exact bytes the mock's emit() produces,
        // ready to drop into BilateralConfirmRequest.offline_release.
        Ok(encode_release(&release))
    }

    fn finalize(&mut self) -> Result<[u8; 32], DsmError> {
        let r = self.roundtrip(Self::bare(pb::Op::Finalize))?;
        arr32(&r.active_root)
    }

    fn cancel(&mut self) -> Result<(), DsmError> {
        self.roundtrip(Self::bare(pb::Op::Cancel)).map(|_| ())
    }

    fn pin(&self) -> AnchorPin {
        self.pin.clone()
    }
}
