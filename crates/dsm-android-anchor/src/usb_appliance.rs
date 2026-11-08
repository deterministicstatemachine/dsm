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
use anchor_core::enrollment::Install;
use anchor_core::proto::{decode_response, encode_release, encode_request, pb};
use anchor_core::root_advance::{OwnedTransition, Transition};
use anchor_core::service::err;
use anchor_core::try_run::Requirement;
use dsm::types::error::DsmError;
use dsm_sdk::anchor::{
    AnchorAppliance, AnchorPin, ApplianceStatus, RehearsalOwner, TryRunReport, TryRunStep,
};

use crate::usb_pico::UsbTransceive;

/// A physical-chip appliance driven over USB. The pin is self-sourced from a STATUS round-trip —
/// the chip self-describes its enrolled identity (`B`, `anchor_id`, `H0`, `pk_host`, `pk_chip`,
/// `S_birth`), so there is no host-side enrollment DB and the pin is always the REAL silicon's.
pub struct UsbAnchorAppliance {
    usb: UsbTransceive,
}

fn arr32(b: &[u8]) -> Result<[u8; 32], DsmError> {
    b.try_into()
        .map_err(|_| DsmError::invalid_operation("anchor appliance: expected 32-byte field"))
}

/// One appliance op over the transport: frame `LE32(len) ++ ApplianceRequest`, run the opaque USB
/// round-trip and decode the `ApplianceResponse`, refused or not. An answer to another op is a stream
/// out of step, never this op's answer: an undecodable frame's refusal alone carries no op.
fn exchange(
    usb: &UsbTransceive,
    req: pb::ApplianceRequest,
) -> Result<pb::ApplianceResponse, DsmError> {
    exchange_with_tail(usb, req, &[])
}

/// One request over the wire with `tail` after its message: an `OP_AUTHORIZE`'s signature, which
/// the anchor reads from the frame's end (anchor-core `decode_frame`).
fn exchange_with_tail(
    usb: &UsbTransceive,
    req: pb::ApplianceRequest,
    tail: &[u8],
) -> Result<pb::ApplianceResponse, DsmError> {
    let op = req.op;
    let mut body = encode_request(&req);
    body.extend_from_slice(tail);
    let mut frame = (body.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(&body);
    let resp_body = usb(frame)?;
    let resp = decode_response(&resp_body).map_err(|e| {
        DsmError::invalid_operation(format!("anchor appliance: decode response: {e:?}"))
    })?;
    if resp.op == op || (resp.op == pb::Op::Unspecified as i32 && !resp.ok) {
        return Ok(resp);
    }
    Err(DsmError::invalid_operation(format!(
        "anchor appliance: op {op} was answered as op {} (the stream is out of step)",
        resp.op
    )))
}

/// One appliance op that must succeed: fail closed unless the chip reported `ok`. Free function so
/// it is usable from `connect()` before `self` exists.
fn roundtrip(
    usb: &UsbTransceive,
    req: pb::ApplianceRequest,
) -> Result<pb::ApplianceResponse, DsmError> {
    let resp = exchange(usb, req)?;
    if !resp.ok {
        return Err(refused(&resp));
    }
    Ok(resp)
}

/// A try-run or a provisioning, as two requests: `req`, and when the anchor answers with the digest
/// its rehearsal payment waits on, the rehearsal owner's authorization of it. Answers what the anchor
/// answered last: the run's report, or for a provisioning that passed, the anchor's status.
fn rehearse(
    usb: &UsbTransceive,
    req: pb::ApplianceRequest,
    rehearsal: &RehearsalOwner,
) -> Result<pb::ApplianceResponse, DsmError> {
    let begun = exchange(usb, req)?;
    if begun.awaiting_authorization.is_empty() {
        return Ok(begun);
    }
    let digest = arr32(&begun.awaiting_authorization)?;
    let signature = rehearsal.sign(&digest)?;
    exchange_with_tail(
        usb,
        pb::ApplianceRequest {
            op: pb::Op::Authorize as i32,
            authorization_digest: digest.to_vec(),
            ..Default::default()
        },
        &signature,
    )
}

/// A refusal as the wallet reports it: the op, the appliance's code and, when it gave one, its reason.
fn refused(resp: &pb::ApplianceResponse) -> DsmError {
    DsmError::invalid_operation(format!(
        "anchor appliance: op {} failed on-chip (error code {}) {}",
        resp.op, resp.error, resp.detail
    ))
}

fn bare(op: pb::Op) -> pb::ApplianceRequest {
    pb::ApplianceRequest {
        op: op as i32,
        ..Default::default()
    }
}

impl UsbAnchorAppliance {
    /// Connect to the physical appliance. Its pin is read from STATUS when the SDK attaches it
    /// ([`AnchorAppliance::provisioned_pin`]).
    pub fn connect(usb: UsbTransceive) -> Result<Self, DsmError> {
        Ok(Self { usb })
    }

    /// The pin STATUS discloses ([`pin_of`]).
    fn status_pin(&self) -> Result<AnchorPin, DsmError> {
        pin_of(&self.roundtrip(bare(pb::Op::Status))?)
    }

    fn roundtrip(&self, req: pb::ApplianceRequest) -> Result<pb::ApplianceResponse, DsmError> {
        roundtrip(&self.usb, req)
    }
}

/// The pin a STATUS answer discloses. Fails closed if it omits any pin material (pre-v2 firmware,
/// or firmware without the birth commitment) — an appliance whose identity cannot be checked
/// against its owner must never produce releases.
fn pin_of(s: &pb::ApplianceResponse) -> Result<AnchorPin, DsmError> {
    let pin = AnchorPin {
        bundle: arr32(&s.anchor_bundle)?,
        anchor_id: arr32(&s.pin_anchor_id)?,
        enrolled_counter: s.pin_enrolled_counter,
        partition_pk: s.pin_partition_pk.clone(),
        pk_chip: s.pin_chip_pk.clone(),
        birth_commitment: arr32(&s.pin_birth_commitment)?,
    };
    if pin.partition_pk.is_empty() || pin.pk_chip.len() != 32 {
        return Err(DsmError::invalid_operation(
            "anchor appliance: STATUS returned incomplete pin material (pk_host/pk_chip) — \
             firmware lacks the v2 STATUS pin; cannot produce verifiable releases (fail closed)",
        ));
    }
    Ok(pin)
}

/// The identity an install binds, on the wire.
fn provisioning_pb(provisioning: &anchor_core::enrollment::Provisioning) -> pb::Provisioning {
    pb::Provisioning {
        device_id: provisioning.device_id.to_vec(),
        online_id_pk: provisioning.online_id_pk.clone(),
        policy_hash: provisioning.policy_hash.to_vec(),
        genesis_root: provisioning.genesis_root.to_vec(),
    }
}

/// The install an answer names: for good, or a trial its next boot ends. `None` when it names none,
/// as an anchor that would not run a try-run at all does.
fn install_of(r: &pb::ApplianceResponse) -> Option<Install> {
    match pb::InstallKind::try_from(r.install) {
        Ok(pb::InstallKind::InstallForGood) => Some(Install::ForGood),
        Ok(pb::InstallKind::InstallForTrial) => Some(Install::ForTrial),
        Ok(pb::InstallKind::InstallUnspecified) => None,
        Err(_unknown) => None,
    }
}

impl AnchorAppliance for UsbAnchorAppliance {
    fn status(&mut self) -> Result<ApplianceStatus, DsmError> {
        let r = self.roundtrip(bare(pb::Op::Status))?;
        Ok(ApplianceStatus {
            root: arr32(&r.active_root)?,
            anchor_counter: r.active_anchor_counter,
            install: install_of(&r).ok_or_else(|| {
                DsmError::invalid_operation("anchor appliance: STATUS named no install")
            })?,
            open_challenge: match r.open_challenge.as_slice() {
                [] => None,
                held => Some(arr32(held)?),
            },
        })
    }

    fn authorize(&mut self, digest: &[u8; 32], signature: &[u8]) -> Result<(), DsmError> {
        let req = pb::ApplianceRequest {
            op: pb::Op::Authorize as i32,
            authorization_digest: digest.to_vec(),
            ..Default::default()
        };
        let resp = exchange_with_tail(&self.usb, req, signature)?;
        if !resp.ok {
            return Err(refused(&resp));
        }
        Ok(())
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
        // The appliance runs §26 recovery itself and answers its outcome and the frontier it
        // names; nothing is inferred from a status code. An outcome the wire does not name fails
        // closed.
        let r = self.roundtrip(bare(pb::Op::Recover))?;
        match pb::Recovery::try_from(r.recovery) {
            Ok(pb::Recovery::Accept) => Ok(RecoverOutcome::Accept(arr32(&r.active_root)?)),
            Ok(pb::Recovery::ReemitCommitted) => {
                Ok(RecoverOutcome::ReemitCommitted(arr32(&r.active_root)?))
            }
            Ok(pb::Recovery::DowngradeOnline) => Ok(RecoverOutcome::DowngradeOnline),
            Ok(pb::Recovery::FailClosed) => Ok(RecoverOutcome::FailClosed),
            Ok(pb::Recovery::ExhaustedOnlineOnly) => Ok(RecoverOutcome::ExhaustedOnlineOnly),
            Ok(pb::Recovery::AcceptPreparedCanComplete) => {
                Ok(RecoverOutcome::AcceptPreparedCanComplete)
            }
            Ok(pb::Recovery::OnlineCancelOrResolve) => Ok(RecoverOutcome::OnlineCancelOrResolve),
            Ok(pb::Recovery::Unspecified) => Err(DsmError::invalid_operation(
                "anchor appliance: OP_RECOVER answered no outcome",
            )),
            Err(unknown) => Err(DsmError::invalid_operation(format!(
                "anchor appliance: OP_RECOVER answered an outcome the wire does not name ({unknown:?})"
            ))),
        }
    }

    fn provisioned_pin(&mut self) -> Result<Option<AnchorPin>, DsmError> {
        // An unprovisioned appliance answers STATUS with `NOT_PROVISIONED`: it is waiting for its
        // owner's provisioning. Any other refusal fails closed.
        let status = exchange(&self.usb, bare(pb::Op::Status))?;
        if !status.ok && status.error == anchor_core::service::err::NOT_PROVISIONED {
            return Ok(None);
        }
        if !status.ok {
            return Err(refused(&status));
        }
        pin_of(&status).map(Some)
    }

    fn try_run(
        &mut self,
        provisioning: &anchor_core::enrollment::Provisioning,
        rehearsal: &RehearsalOwner,
    ) -> Result<TryRunReport, DsmError> {
        // A try-run that does not pass is an answer, and so is an anchor that will not run one: the
        // report says which. Only a transport that failed is an error.
        let req = pb::ApplianceRequest {
            op: pb::Op::TryRun as i32,
            provision: Some(provisioning_pb(provisioning)),
            rehearsal_pk: rehearsal.public_key().to_vec(),
            ..Default::default()
        };
        let resp = rehearse(&self.usb, req, rehearsal)?;
        let mut steps: Vec<TryRunStep> = resp
            .try_run
            .iter()
            .map(|step| TryRunStep {
                name: step.name.clone(),
                passed: step.passed,
                detail: step.detail.clone(),
                requirement: if step.production {
                    Requirement::Production
                } else {
                    Requirement::Works
                },
            })
            .collect();
        // The transport carried an answer as long as the largest the anchor ever gives: checked on
        // any run that went through its payment, whatever production still needs.
        let carried = resp.transport_check.len();
        let whole =
            carried > 0 && resp.transport_check == anchor_core::try_run::transport_check(carried);
        if resp.ok || carried > 0 {
            steps.push(TryRunStep {
                name: "the anchor's largest answer came through whole".to_string(),
                passed: whole,
                detail: if whole {
                    String::new()
                } else {
                    format!("{carried} bytes arrived")
                },
                requirement: Requirement::Works,
            });
        }
        // A run that went through answers with its steps; only an anchor that would not run one at
        // all is a refusal, and it says why.
        let refused = match resp.error {
            err::NONE | err::TRY_RUN_FAILED => String::new(),
            code if resp.detail.is_empty() => {
                format!("the anchor refused the try-run (error {code})")
            }
            _ => resp.detail.clone(),
        };
        Ok(TryRunReport {
            passed: resp.ok && whole,
            steps,
            install: install_of(&resp),
            permanent: resp.permanent.clone(),
            refused,
        })
    }

    fn draw_challenge(&mut self) -> Result<[u8; 32], DsmError> {
        let r = self.roundtrip(bare(pb::Op::Challenge))?;
        arr32(&r.receiver_challenge)
    }

    fn check_payment(
        &mut self,
        payment: &anchor_core::root_advance::OfflineRelease,
        payer: &anchor_core::receive::PayerDisclosure,
    ) -> Result<(), DsmError> {
        // Only what the anchor checks goes over the cable: the transition and the certificate. The
        // offline-state proofs and any spend chain are the phone's to verify.
        let req = pb::ApplianceRequest {
            op: pb::Op::CheckPayment as i32,
            payment: Some(Box::new(pb::OfflineRelease {
                transition: Some(payment.transition.to_pb()),
                cert: Some(payment.cert.to_pb()),
                ..Default::default()
            })),
            payer: Some(Box::new(payer.to_pb())),
            ..Default::default()
        };
        self.roundtrip(req).map(|_| ())
    }

    fn provision(
        &mut self,
        provisioning: &anchor_core::enrollment::Provisioning,
        rehearsal: &RehearsalOwner,
    ) -> Result<AnchorPin, DsmError> {
        let req = pb::ApplianceRequest {
            op: pb::Op::Provision as i32,
            provision: Some(provisioning_pb(provisioning)),
            rehearsal_pk: rehearsal.public_key().to_vec(),
            ..Default::default()
        };
        let resp = rehearse(&self.usb, req, rehearsal)?;
        if !resp.ok {
            return Err(refused(&resp));
        }
        self.status_pin()
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
            pin_birth_commitment: vec![0x5B; 32],
            install: pb::InstallKind::InstallForGood as i32,
            ..Default::default()
        })
    }

    #[test]
    fn connect_self_sources_the_full_v2_pin_from_status() {
        let usb: UsbTransceive = Arc::new(|_frame| Ok(status_response(0)));
        let mut app = UsbAnchorAppliance::connect(usb).expect("connect");
        let pin = app
            .provisioned_pin()
            .expect("status")
            .expect("a serving appliance is provisioned");
        assert_eq!(pin.birth_commitment, [0x5B; 32]);
        assert_eq!(pin.bundle, [0xB1; 32]);
        assert_eq!(pin.anchor_id, [0xA1; 32]);
        assert_eq!(pin.enrolled_counter, 1_000);
        assert_eq!(pin.partition_pk, vec![0x07; 64]);
        assert_eq!(pin.pk_chip, vec![0x0C; 32]);
    }

    #[test]
    fn connect_fails_closed_without_pk_chip() {
        let usb: UsbTransceive = Arc::new(|_frame| {
            Ok(anchor_core::proto::encode_response(
                &pb::ApplianceResponse {
                    op: pb::Op::Status as i32,
                    ok: true,
                    active_root: vec![0x11; 32],
                    anchor_bundle: vec![0xB1; 32],
                    pin_anchor_id: vec![0xA1; 32],
                    pin_enrolled_counter: 1_000,
                    pin_partition_pk: vec![0x07; 64],
                    pin_chip_pk: Vec::new(), // pre-v2 firmware
                    ..Default::default()
                },
            ))
        });
        let mut app = UsbAnchorAppliance::connect(usb).expect("connect");
        let refused = app
            .provisioned_pin()
            .expect_err("a pin without pk_chip cannot verify σ^chip — reading it must fail closed");
        assert!(
            refused.to_string().contains("expected 32-byte field"),
            "{refused}"
        );
    }

    #[test]
    fn recover_answers_the_appliances_own_outcome_and_frontier() {
        for (kind, want) in [
            (pb::Recovery::Accept, RecoverOutcome::Accept([0x11; 32])),
            (
                pb::Recovery::ReemitCommitted,
                RecoverOutcome::ReemitCommitted([0x11; 32]),
            ),
            (
                pb::Recovery::AcceptPreparedCanComplete,
                RecoverOutcome::AcceptPreparedCanComplete,
            ),
            (
                pb::Recovery::DowngradeOnline,
                RecoverOutcome::DowngradeOnline,
            ),
        ] {
            let usb: UsbTransceive = Arc::new(move |frame| {
                let req = anchor_core::proto::decode_request(&frame[4..]).expect("a request");
                assert_eq!(req.op, pb::Op::Recover as i32);
                let mut answer =
                    anchor_core::proto::decode_response(&status_response(0)).expect("an answer");
                answer.op = req.op;
                answer.recovery = kind as i32;
                Ok(anchor_core::proto::encode_response(&answer))
            });
            let mut app = UsbAnchorAppliance::connect(usb).expect("connect");
            assert_eq!(app.recover().expect("recover"), want);
        }
        let unnamed: UsbTransceive = Arc::new(|frame| {
            let req = anchor_core::proto::decode_request(&frame[4..]).expect("a request");
            let mut answer =
                anchor_core::proto::decode_response(&status_response(0)).expect("an answer");
            answer.op = req.op;
            Ok(anchor_core::proto::encode_response(&answer))
        });
        let mut app = UsbAnchorAppliance::connect(unnamed).expect("connect");
        let refused = app
            .recover()
            .expect_err("an outcome the wire does not name fails closed");
        assert!(refused.to_string().contains("no outcome"), "{refused}");
    }

    #[test]
    fn an_unprovisioned_appliance_has_no_pin_and_is_provisioned() {
        let usb: UsbTransceive = Arc::new(|frame| {
            let req = anchor_core::proto::decode_request(&frame[4..]).expect("a request");
            if req.op == pb::Op::Status as i32 {
                return Ok(anchor_core::proto::encode_response(
                    &pb::ApplianceResponse {
                        op: req.op,
                        error: anchor_core::service::err::NOT_PROVISIONED,
                        ..Default::default()
                    },
                ));
            }
            Ok(status_response(0))
        });
        let mut app = UsbAnchorAppliance::connect(usb).expect("connect");
        assert_eq!(
            app.provisioned_pin().expect("status").map(|pin| pin.bundle),
            None
        );
    }

    /// An answer left over from another op is never taken as this op's: a stale release or status
    /// read as the answer would be believed. MUTATION CONTROL: dropping the op check in `exchange`
    /// takes the status as the commit's answer and turns this red.
    #[test]
    fn an_answer_to_another_op_is_refused() {
        let usb: UsbTransceive = Arc::new(|_frame| Ok(status_response(0)));
        let mut app = UsbAnchorAppliance::connect(usb).expect("connect");
        let refused = app
            .commit()
            .expect_err("a status answer is no commit's answer");
        assert!(refused.to_string().contains("out of step"), "{refused}");
    }

    /// A refusal the firmware gives before it knows the op, and its reason, reach the wallet.
    #[test]
    fn a_refusal_with_no_op_keeps_its_reason() {
        let usb: UsbTransceive = Arc::new(|_frame| {
            Ok(anchor_core::service::refusal(
                pb::Op::Unspecified as i32,
                anchor_core::service::err::NOT_UP,
                "Sealed: secure boot is not enabled in OTP",
            ))
        });
        let mut app = UsbAnchorAppliance::connect(usb).expect("connect");
        let refused = app.commit().expect_err("an anchor that is not up");
        assert!(
            refused.to_string().contains("secure boot is not enabled"),
            "{refused}"
        );
    }

    #[test]
    fn onchip_error_fails_closed() {
        let usb: UsbTransceive = Arc::new(|_frame| {
            Ok(anchor_core::proto::encode_response(
                &pb::ApplianceResponse {
                    op: pb::Op::Status as i32,
                    ok: false,
                    error: 5,
                    ..Default::default()
                },
            ))
        });
        let mut app = UsbAnchorAppliance::connect(usb).expect("connect");
        let refused = app
            .provisioned_pin()
            .expect_err("an on-chip error fails closed");
        assert!(refused.to_string().contains("failed on-chip"), "{refused}");
    }
}
