//! The anchor as its firmware runs it. It boots unprovisioned until its owner's device provisions
//! it, once, with the identity its bundle `B` binds (the device id, the online key `pk_on`, the
//! policy and the genesis). From then on it boots from its durable record, through §26 recovery.
//! It serves an offline step only once its chip is closed to a second birth.

use alloc::vec::Vec;

use crate::durable::{
    provisioning_from_pb, ActiveStore, DurableAppliance, DurableBootRefusal, DurableError,
};
use crate::enrollment::ChipBirth;
use crate::proto::{decode_request, encode_response, pb, ProtoError};
use crate::service::{
    appliance_refusal, durable_code, err, fail, handle, proto_code, status, try_run_response,
    MAX_FRAME_LEN,
};
use crate::tropic::{PartitionSig, Tropic};

/// An anchor and the state its firmware holds it in.
pub enum Anchor<T: Tropic, P: PartitionSig, S: ActiveStore> {
    /// Its store holds no record: it answers only a provisioning.
    Unprovisioned {
        chip: ChipBirth,
        tropic: T,
        store: S,
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

    /// Answer one request frame, and the anchor as the request leaves it.
    pub fn serve(self, frame: &[u8]) -> (Self, Vec<u8>) {
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
                    let answer = match decode_request(frame) {
                        Ok(req) => appliance_refusal(req.op, e),
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
        }
    }
}

/// An unprovisioned anchor's answer: a try-run goes through an install and leaves it unprovisioned;
/// a provisioning provisions it; anything else is refused as not provisioned.
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
    if frame.len() > MAX_FRAME_LEN {
        return unprovisioned(tropic, store, err::FRAME_TOO_LARGE, 0);
    }
    let req = match decode_request(frame) {
        Ok(req) => req,
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
    if op == pb::Op::TryRun as i32 {
        let run =
            crate::try_run::rehearse::<T, P, S>(&chip, &mut tropic, &mut store, &provisioning);
        let answer = encode_response(&try_run_response(op, &run));
        return (
            Anchor::Unprovisioned {
                chip,
                tropic,
                store,
            },
            answer,
        );
    }
    match DurableAppliance::provision(&chip, tropic, store, provisioning) {
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
