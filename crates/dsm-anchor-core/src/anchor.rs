//! The anchor as its firmware runs it. It boots unprovisioned until its owner's device provisions
//! it, once, with the identity its bundle `B` binds (the device id, the online key `pk_on`, the
//! policy and the genesis). From then on it boots from its durable record, through §26 recovery.
//! It serves an offline step only once its chip is closed to a second birth.
//!
//! A try-run, alone or a provisioning's, is two requests. The anchor is born into its trial slots
//! and answers with the digest its rehearsal payment waits on; the wallet's authorization of that
//! digest under the rehearsal key, an `OP_AUTHORIZE`, finishes the run, and a provisioning's goes
//! on to the install. The anchor holds no owner's key and never signs as one: the rehearsal's
//! payment goes through the same check a real payment's does.

use alloc::vec::Vec;

use crate::durable::{
    provisioning_from_pb, ActiveStore, DurableAppliance, DurableBootRefusal, DurableError,
};
use crate::enrollment::{ChipBirth, Provisioning};
use crate::proto::{arr32, decode_frame, encode_response, pb, ProtoError};
use crate::service::{
    appliance_refusal, awaiting_response, durable_code, err, fail, handle, proto_code, status,
    try_run_response,
};
use crate::tropic::{PartitionSig, Tropic};
use crate::try_run::{begin, finish, Begun, TryRun, TryStep};

/// An anchor and the state its firmware holds it in.
pub enum Anchor<T: Tropic, P: PartitionSig, S: ActiveStore> {
    /// Its store holds no record: it answers only a provisioning or a try-run.
    Unprovisioned {
        chip: ChipBirth,
        tropic: T,
        store: S,
    },
    /// A try-run begun and waiting on the rehearsal owner's authorization of its payment. An
    /// `OP_AUTHORIZE` of [`Begun::awaiting`] finishes it; any other request ends it, and the anchor
    /// is as it was found.
    Rehearsing {
        chip: ChipBirth,
        tropic: T,
        store: S,
        /// The device the install that follows a passing run is for, when the run is a
        /// provisioning's.
        install: Option<Provisioning>,
        begun: Begun,
    },
    /// Provisioned, its chip not yet closed to a second birth: it closes it before it serves.
    Unclosed(DurableAppliance<T, P, S>),
    /// Provisioned and closed: it serves.
    Serving(DurableAppliance<T, P, S>),
}

/// Why an anchor will not come up at boot.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AnchorBootRefusal {
    /// The store could not be read, or the record it holds could not be restored.
    Restore(DurableError),
    /// The restored appliance will not serve (§26).
    Recovery(DurableBootRefusal),
}

impl<T: Tropic, P: PartitionSig, S: ActiveStore> Anchor<T, P, S> {
    /// The anchor its store describes: unprovisioned when the store holds no record; otherwise
    /// restored from the record and recovered (§26), to be closed before it serves.
    pub fn boot(chip: ChipBirth, tropic: T, mut store: S) -> Result<Self, AnchorBootRefusal> {
        match store.read() {
            Ok(None) => Ok(Self::Unprovisioned {
                chip,
                tropic,
                store,
            }),
            Ok(Some(_)) => {
                let mut d = DurableAppliance::restore(&chip, tropic, store)
                    .map_err(AnchorBootRefusal::Restore)?;
                d.recover_at_boot().map_err(AnchorBootRefusal::Recovery)?;
                Ok(Self::Unclosed(d))
            }
            Err(e) => Err(AnchorBootRefusal::Restore(DurableError::Store(e))),
        }
    }

    /// Whether the anchor would serve a payment check now: it is provisioned and holds no record. A
    /// payment check's frame is as large as a record, so a firmware asks before it allocates one.
    pub fn takes_a_payment_check(&self) -> bool {
        matches!(
            self,
            Self::Serving(d) | Self::Unclosed(d)
                if d.appliance().active.status == crate::appliance::Status::Ready
        )
    }

    /// Answer one request frame, and the anchor as the request leaves it. The frame is the anchor's
    /// own copy: it is held no longer than its request needs it, and wiped when let go.
    pub fn serve(self, frame: &[u8]) -> (Self, Vec<u8>) {
        self.serve_owned(frame.to_vec())
    }

    /// [`Self::serve`] on the frame itself, as the monitor hands it over.
    pub fn serve_owned(self, mut frame: Vec<u8>) -> (Self, Vec<u8>) {
        let served = self.serve_held(&mut frame);
        crate::util::zeroize_vec(&mut frame);
        served
    }

    fn serve_held(self, frame: &mut Vec<u8>) -> (Self, Vec<u8>) {
        match self {
            Self::Serving(mut d) => {
                let out = handle(&mut d, frame);
                (Self::Serving(d), out)
            }
            Self::Unclosed(mut d) => match d.close_birth() {
                Ok(()) => {
                    let out = handle(&mut d, frame);
                    (Self::Serving(d), out)
                }
                Err(e) => {
                    let answer = match decode_frame(frame) {
                        Ok((req, _)) => appliance_refusal(req.op, e),
                        Err(pe) => fail(0, proto_code(pe)),
                    };
                    (Self::Unclosed(d), encode_response(&answer))
                }
            },
            Self::Unprovisioned {
                chip,
                tropic,
                store,
            } => provision(chip, tropic, store, frame),
            Self::Rehearsing {
                chip,
                tropic,
                store,
                install,
                begun,
            } => rehearsing(chip, tropic, store, install, begun, frame),
        }
    }
}

/// An unprovisioned anchor's answer: a try-run or a provisioning begins a rehearsal, which waits on
/// its owner's authorization ([`Anchor::Rehearsing`]); anything else is refused as not provisioned.
fn provision<T: Tropic, P: PartitionSig, S: ActiveStore>(
    chip: ChipBirth,
    mut tropic: T,
    mut store: S,
    frame: &[u8],
) -> (Anchor<T, P, S>, Vec<u8>) {
    let unprovisioned = |tropic, store, code: u32, op: i32| {
        (
            Anchor::Unprovisioned {
                chip: chip.clone(),
                tropic,
                store,
            },
            encode_response(&fail(op, code)),
        )
    };
    let (req, _signature) = match decode_frame(frame) {
        Ok(decoded) => decoded,
        Err(e) => return unprovisioned(tropic, store, proto_code(e), 0),
    };
    let op = req.op;
    if op != pb::Op::Provision as i32 && op != pb::Op::TryRun as i32 {
        return unprovisioned(tropic, store, err::NOT_PROVISIONED, op);
    }
    let provisioning = match req
        .provision
        .ok_or(ProtoError::MissingField)
        .and_then(provisioning_from_pb)
    {
        Ok(p) => p,
        Err(e) => return unprovisioned(tropic, store, proto_code(e), op),
    };
    if req.rehearsal_pk.is_empty() {
        return unprovisioned(tropic, store, err::MISSING_FIELD, op);
    }
    // The rehearsal is born for the device under its rehearsal owner key: the owner's device key
    // never signs a rehearsal, and the install that may follow binds the device key.
    let rehearsal = Provisioning {
        online_id_pk: req.rehearsal_pk,
        ..provisioning.clone()
    };
    let begun = begin::<T, P, S>(&chip, &mut tropic, &mut store, &rehearsal);
    let install = match pb::Op::try_from(op) {
        Ok(pb::Op::Provision) => Some(provisioning),
        _ => None,
    };
    match begun.awaiting {
        Some(awaiting) => {
            let answer = awaiting_response(op, &begun.steps, chip.install, awaiting);
            (
                Anchor::Rehearsing {
                    chip,
                    tropic,
                    store,
                    install,
                    begun,
                },
                encode_response(&answer),
            )
        }
        None => {
            // The run did not reach its payment: it ends here, and says where it stopped.
            let run = finish::<T, P, S>(&chip, &mut tropic, &mut store, begun, None);
            let answer = ended(op, &run, chip.install);
            (
                Anchor::Unprovisioned {
                    chip,
                    tropic,
                    store,
                },
                encode_response(&answer),
            )
        }
    }
}

/// A rehearsing anchor's answer. The authorization it waits on finishes the run and, for a
/// provisioning's, the install follows a passing one. Any other request ends the run with the
/// anchor as it was found, and is not served: the answer says so, with how far the run got.
fn rehearsing<T: Tropic, P: PartitionSig, S: ActiveStore>(
    chip: ChipBirth,
    mut tropic: T,
    mut store: S,
    install: Option<Provisioning>,
    mut begun: Begun,
    frame: &mut Vec<u8>,
) -> (Anchor<T, P, S>, Vec<u8>) {
    let (req, signature_len) = match decode_frame(frame) {
        Ok((req, signature)) => (req, signature.len()),
        Err(e) => {
            let run = finish::<T, P, S>(&chip, &mut tropic, &mut store, begun, None);
            let answer = pb::ApplianceResponse {
                error: proto_code(e),
                ..ended(0, &run, chip.install)
            };
            return (
                Anchor::Unprovisioned {
                    chip,
                    tropic,
                    store,
                },
                encode_response(&answer),
            );
        }
    };
    let op = req.op;
    if op != pb::Op::Authorize as i32 {
        let run = finish::<T, P, S>(&chip, &mut tropic, &mut store, begun, None);
        let answer = pb::ApplianceResponse {
            error: err::REHEARSAL_ENDED,
            detail: alloc::string::String::from(
                "a try-run was waiting on its authorization; it has ended, and the anchor is as \
                 it was found: ask again",
            ),
            ..ended(op, &run, chip.install)
        };
        return (
            Anchor::Unprovisioned {
                chip,
                tropic,
                store,
            },
            encode_response(&answer),
        );
    }
    // The authorization must name the payment begun; one naming another is not even verified. The
    // signature is taken out of the frame, to be let go once it is checked: a try-run's payment
    // signs with it no longer held.
    let authorization = match arr32(&req.authorization_digest) {
        Ok(claimed) if begun.awaiting == Some(claimed) && signature_len > 0 => {
            frame.drain(..frame.len() - signature_len);
            Some(core::mem::take(frame))
        }
        _ => {
            begun.steps.push(TryStep::new(
                "the authorization names the payment begun",
                Err(alloc::string::String::from(
                    "it names another, or carries no signature",
                )),
            ));
            begun.awaiting = None;
            None
        }
    };
    let run = finish::<T, P, S>(&chip, &mut tropic, &mut store, begun, authorization);
    match install {
        None => {
            let answer = encode_response(&try_run_response(op, &run, chip.install));
            (
                Anchor::Unprovisioned {
                    chip,
                    tropic,
                    store,
                },
                answer,
            )
        }
        Some(provisioning) => match run.blocking(chip.install) {
            Some(stopped) => {
                let answer = pb::ApplianceResponse {
                    detail: alloc::format!("{}: {:?}", stopped.name, stopped.outcome),
                    ..try_run_response(op, &run, chip.install)
                };
                (
                    Anchor::Unprovisioned {
                        chip,
                        tropic,
                        store,
                    },
                    encode_response(&answer),
                )
            }
            None => install_after(chip, tropic, store, provisioning, op),
        },
    }
}

/// A try-run that ended short of its payment, or was ended by another request: its steps, under
/// the run's own verdict, and where it stopped.
fn ended(op: i32, run: &TryRun, install: crate::enrollment::Install) -> pb::ApplianceResponse {
    let detail = match run.blocking(install) {
        Some(stopped) => alloc::format!("{}: {:?}", stopped.name, stopped.outcome),
        None => alloc::string::String::new(),
    };
    pb::ApplianceResponse {
        detail,
        ..try_run_response(op, run, install)
    }
}

/// The install, once its try-run passed: the anchor is born for `provisioning`, its first record
/// written, and its chip closed before it serves. Answered with the pin material it made.
fn install_after<T: Tropic, P: PartitionSig, S: ActiveStore>(
    chip: ChipBirth,
    tropic: T,
    store: S,
    provisioning: Provisioning,
    op: i32,
) -> (Anchor<T, P, S>, Vec<u8>) {
    match DurableAppliance::born(&chip, tropic, store, provisioning) {
        Ok(mut d) => match d.close_birth() {
            Ok(()) => {
                let answer = encode_response(&status(op, d.appliance()));
                (Anchor::Serving(d), answer)
            }
            Err(e) => (
                Anchor::Unclosed(d),
                encode_response(&appliance_refusal(op, e)),
            ),
        },
        Err(refused) => {
            let answer = pb::ApplianceResponse {
                detail: alloc::format!("{:?}", refused.error),
                ..fail(op, durable_code(refused.error.clone()))
            };
            (
                Anchor::Unprovisioned {
                    chip,
                    tropic: refused.tropic,
                    store: refused.store,
                },
                encode_response(&answer),
            )
        }
    }
}
