//! The secure-core appliance service: decode an `ApplianceRequest`, drive the
//! [`Appliance`], and encode an `ApplianceResponse`. [`handle`] is the single mediated
//! entry point — in a TrustZone-M deployment it is the secure-gateway veneer (the only NSC
//! entry), and the non-secure transport reaches the TROPIC01 solely through it; the
//! transport holds no chip handle of its own.

extern crate alloc;
use alloc::vec::Vec;

use crate::appliance::{Appliance, ApplianceError, Status};
use crate::durable::{ActiveStore, DurableAppliance, DurableError};
use crate::proto::{arr32, decode_request, encode_response, pb, ProtoError};
use crate::root_advance::Transition;
use crate::tropic::{PartitionSig, Tropic};

/// Wire error codes carried in `ApplianceResponse.error`.
pub mod err {
    pub const NONE: u32 = 0;
    pub const WRONG_STATE: u32 = 1;
    pub const PREV_ROOT_MISMATCH: u32 = 2;
    pub const NEXT_ROOT_MISMATCH: u32 = 3;
    pub const INDEX_MISMATCH: u32 = 4;
    pub const COUNTER_MISMATCH: u32 = 5;
    pub const COUNTER_EXHAUSTED: u32 = 6;
    pub const NOT_COMMITTED: u32 = 7;
    pub const TROPIC: u32 = 8;
    pub const PARTITION: u32 = 9;
    pub const BAD_PROTO: u32 = 100;
    pub const MISSING_FIELD: u32 = 101;
    pub const BAD_OP: u32 = 102;
    pub const FRAME_TOO_LARGE: u32 = 103;
    /// OP_PROVISION to an anchor that is already provisioned: an anchor is provisioned once.
    pub const ALREADY_PROVISIONED: u32 = 104;
    /// The anchor is not provisioned: it answers only a provisioning.
    pub const NOT_PROVISIONED: u32 = 105;
    /// The durable store did not take a write or answer a read.
    pub const STORE: u32 = 106;
    /// The durable store holds bytes that are not an anchor record.
    pub const RECORD: u32 = 107;
}

/// Protocol-level ceiling on a request frame, a backstop against absurd inputs before prost
/// decode allocates. The non-secure transport must additionally enforce a heap-appropriate
/// cap at its receive edge.
pub const MAX_FRAME_LEN: usize = 64 * 1024;

pub(crate) fn appliance_code(e: ApplianceError) -> u32 {
    match e {
        ApplianceError::WrongState => err::WRONG_STATE,
        ApplianceError::PrevRootMismatch => err::PREV_ROOT_MISMATCH,
        ApplianceError::NextRootMismatch => err::NEXT_ROOT_MISMATCH,
        ApplianceError::IndexMismatch => err::INDEX_MISMATCH,
        ApplianceError::CounterMismatch => err::COUNTER_MISMATCH,
        ApplianceError::CounterExhausted => err::COUNTER_EXHAUSTED,
        ApplianceError::NotCommitted => err::NOT_COMMITTED,
        ApplianceError::Tropic(_) => err::TROPIC,
        ApplianceError::Partition(_) => err::PARTITION,
    }
}

pub(crate) fn durable_code(e: DurableError) -> u32 {
    match e {
        DurableError::Appliance(e) => appliance_code(e),
        DurableError::Store(_) => err::STORE,
        DurableError::Record(_) => err::RECORD,
        DurableError::NotProvisioned => err::NOT_PROVISIONED,
        DurableError::AlreadyProvisioned => err::ALREADY_PROVISIONED,
    }
}

pub(crate) fn proto_code(e: ProtoError) -> u32 {
    match e {
        ProtoError::MissingField => err::MISSING_FIELD,
        ProtoError::BadOp => err::BAD_OP,
        _ => err::BAD_PROTO,
    }
}

fn status_code(s: Status) -> u32 {
    match s {
        Status::Ready => 0,
        Status::Prepared => 1,
        Status::Committed => 2,
    }
}

fn base(op: i32) -> pb::ApplianceResponse {
    pb::ApplianceResponse {
        op,
        ok: false,
        error: err::NONE,
        release: None,
        active_root: Vec::new(),
        anchor_bundle: Vec::new(),
        active_anchor_counter: 0,
        status: 0,
        spi_response: Vec::new(),
        pin_anchor_id: Vec::new(),
        pin_enrolled_counter: 0,
        pin_partition_pk: Vec::new(),
        pin_chip_pk: Vec::new(),
        pin_birth_commitment: Vec::new(),
    }
}

fn ok(op: i32) -> pb::ApplianceResponse {
    pb::ApplianceResponse {
        ok: true,
        ..base(op)
    }
}

pub(crate) fn fail(op: i32, code: u32) -> pb::ApplianceResponse {
    pb::ApplianceResponse {
        error: code,
        ..base(op)
    }
}

/// An appliance the wire drives: each operation, its failure as the wire code, and the appliance
/// to read for a status.
pub trait Served {
    type T: Tropic;
    type P: PartitionSig;
    fn view(&self) -> &Appliance<Self::T, Self::P>;
    fn prepare(
        &mut self,
        t: &Transition,
        receiver_challenge: &[u8; 32],
        sender_device_root_before: &[u8; 32],
        sender_device_root_after: &[u8; 32],
    ) -> Result<(), u32>;
    fn commit(&mut self) -> Result<(), u32>;
    fn emit(&mut self) -> Result<pb::OfflineRelease, u32>;
    fn finalize(&mut self) -> Result<[u8; 32], u32>;
    fn cancel(&mut self) -> Result<(), u32>;
}

impl<T: Tropic, P: PartitionSig> Served for Appliance<T, P> {
    type T = T;
    type P = P;
    fn view(&self) -> &Appliance<T, P> {
        self
    }
    fn prepare(
        &mut self,
        t: &Transition,
        rc: &[u8; 32],
        before: &[u8; 32],
        after: &[u8; 32],
    ) -> Result<(), u32> {
        Appliance::prepare(self, t, rc, before, after).map_err(appliance_code)
    }
    fn commit(&mut self) -> Result<(), u32> {
        Appliance::commit(self).map_err(appliance_code)
    }
    fn emit(&mut self) -> Result<pb::OfflineRelease, u32> {
        Appliance::emit(self)
            .map(|rel| rel.to_pb())
            .map_err(appliance_code)
    }
    fn finalize(&mut self) -> Result<[u8; 32], u32> {
        Appliance::finalize(self).map_err(appliance_code)
    }
    fn cancel(&mut self) -> Result<(), u32> {
        Appliance::cancel(self).map_err(appliance_code)
    }
}

impl<T: Tropic, P: PartitionSig, S: ActiveStore> Served for DurableAppliance<T, P, S> {
    type T = T;
    type P = P;
    fn view(&self) -> &Appliance<T, P> {
        self.appliance()
    }
    fn prepare(
        &mut self,
        t: &Transition,
        rc: &[u8; 32],
        before: &[u8; 32],
        after: &[u8; 32],
    ) -> Result<(), u32> {
        DurableAppliance::prepare(self, t, rc, before, after).map_err(durable_code)
    }
    fn commit(&mut self) -> Result<(), u32> {
        DurableAppliance::commit(self).map_err(durable_code)
    }
    fn emit(&mut self) -> Result<pb::OfflineRelease, u32> {
        DurableAppliance::emit(self)
            .map(|rel| rel.to_pb())
            .map_err(appliance_code)
    }
    fn finalize(&mut self) -> Result<[u8; 32], u32> {
        DurableAppliance::finalize(self).map_err(durable_code)
    }
    fn cancel(&mut self) -> Result<(), u32> {
        DurableAppliance::cancel(self).map_err(durable_code)
    }
}

/// The status of an appliance: its active state and the pin a receiver checks it against.
pub(crate) fn status<T: Tropic, P: PartitionSig>(
    op: i32,
    app: &Appliance<T, P>,
) -> pb::ApplianceResponse {
    pb::ApplianceResponse {
        ok: true,
        active_root: app.active.root.to_vec(),
        anchor_bundle: app.bundle.to_vec(),
        active_anchor_counter: app.active.anchor_counter,
        status: status_code(app.active.status),
        pin_anchor_id: app.anchor_id.to_vec(),
        pin_enrolled_counter: u64::from(app.h0),
        pin_partition_pk: app.partition_pk.clone(),
        pin_chip_pk: app.chip_pk.clone(),
        pin_birth_commitment: app.birth_commitment.to_vec(),
        ..base(op)
    }
}

/// Dispatch a decoded request against the appliance.
pub fn dispatch<A: Served>(app: &mut A, req: &pb::ApplianceRequest) -> pb::ApplianceResponse {
    let op = req.op;
    // Boot is NOT a host operation: the firmware self-measures at startup as an
    // implementation gate. The old wire OP_BOOT (proto enum value 1, reserved) is rejected
    // here as an unknown op.
    match pb::Op::try_from(op) {
        Ok(pb::Op::Prepare) => {
            let t = match &req.transition {
                Some(t) => t,
                None => return fail(op, err::MISSING_FIELD),
            };
            let owned = match t.to_owned_transition() {
                Ok(o) => o,
                Err(e) => return fail(op, proto_code(e)),
            };
            let rc = match arr32(&req.receiver_challenge) {
                Ok(a) => a,
                Err(e) => return fail(op, proto_code(e)),
            };
            let r_before = match arr32(&req.sender_device_root_before) {
                Ok(a) => a,
                Err(e) => return fail(op, proto_code(e)),
            };
            let r_after = match arr32(&req.sender_device_root_after) {
                Ok(a) => a,
                Err(e) => return fail(op, proto_code(e)),
            };
            match app.prepare(&owned.as_transition(), &rc, &r_before, &r_after) {
                Ok(()) => ok(op),
                Err(code) => fail(op, code),
            }
        }
        Ok(pb::Op::Commit) => match app.commit() {
            Ok(()) => ok(op),
            Err(code) => fail(op, code),
        },
        Ok(pb::Op::Emit) => match app.emit() {
            Ok(rel) => pb::ApplianceResponse {
                ok: true,
                release: Some(rel),
                ..base(op)
            },
            Err(code) => fail(op, code),
        },
        Ok(pb::Op::Finalize) => match app.finalize() {
            Ok(h) => pb::ApplianceResponse {
                ok: true,
                active_root: h.to_vec(),
                ..base(op)
            },
            Err(code) => fail(op, code),
        },
        Ok(pb::Op::Status) => status(op, app.view()),
        Ok(pb::Op::Cancel) => match app.cancel() {
            Ok(()) => ok(op),
            Err(code) => fail(op, code),
        },
        // An appliance exists only once its anchor is provisioned, and an anchor is provisioned
        // once: provisioning it again is refused.
        Ok(pb::Op::Provision) => fail(op, err::ALREADY_PROVISIONED),
        // OP_SPI_PASSTHROUGH is not an appliance op; the software-authority firmware offers no
        // raw-SPI relay, so it is rejected as an unknown op.
        Ok(pb::Op::SpiPassthrough) => fail(op, err::BAD_OP),
        Ok(pb::Op::Unspecified) | Err(_) => fail(op, err::BAD_OP),
    }
}

/// Decode a request frame, dispatch it, and encode the response frame. The single secure-core
/// entry point; a malformed frame yields a `BAD_PROTO` error response rather than a panic.
pub fn handle<A: Served>(app: &mut A, frame: &[u8]) -> Vec<u8> {
    if frame.len() > MAX_FRAME_LEN {
        return encode_response(&fail(0, err::FRAME_TOO_LARGE));
    }
    match decode_request(frame) {
        Ok(req) => encode_response(&dispatch(app, &req)),
        Err(_) => encode_response(&fail(0, err::BAD_PROTO)),
    }
}
