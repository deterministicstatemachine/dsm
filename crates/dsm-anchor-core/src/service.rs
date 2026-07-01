//! The secure-core appliance service: decode an `ApplianceRequest`, drive the
//! [`Appliance`], and encode an `ApplianceResponse`. [`handle`] is the single
//! mediated entry point — in a TrustZone-M deployment it is the secure-gateway
//! veneer (the only NSC entry), and the non-secure transport reaches the
//! TROPIC01 solely through it; the transport holds no chip handle of its own.

extern crate alloc;
use alloc::vec::Vec;

use crate::appliance::{Appliance, ApplianceError, Status};
use crate::proto::{arr32, decode_request, encode_response, pb, ProtoError};
use crate::tropic::{PartitionSig, Tropic, WitnessSig};

/// Wire error codes carried in `ApplianceResponse.error`.
pub mod err {
    pub const NONE: u32 = 0;
    pub const WRONG_STATE: u32 = 1;
    pub const PREV_ROOT_MISMATCH: u32 = 2;
    pub const INDEX_MISMATCH: u32 = 3;
    pub const COUNTER_MISMATCH: u32 = 4;
    pub const WITNESS_KEY_LOST: u32 = 5;
    pub const COUNTER_EXHAUSTED: u32 = 6;
    pub const NOT_COMMITTED: u32 = 7;
    pub const TROPIC: u32 = 8;
    pub const NOT_BOOTED: u32 = 9;
    pub const ANCHOR_HEAD_MISMATCH: u32 = 10;
    pub const BOOT_CHAIN_FULL: u32 = 11;
    pub const BAD_PROTO: u32 = 100;
    pub const MISSING_FIELD: u32 = 101;
    pub const BAD_OP: u32 = 102;
    pub const FRAME_TOO_LARGE: u32 = 103;
}

/// Protocol-level ceiling on a request frame, a backstop against absurd inputs
/// before prost decode allocates. The non-secure transport must additionally
/// enforce a heap-appropriate cap at its receive edge.
pub const MAX_FRAME_LEN: usize = 64 * 1024;

fn appliance_code(e: ApplianceError) -> u32 {
    match e {
        ApplianceError::WrongState => err::WRONG_STATE,
        ApplianceError::NotBooted => err::NOT_BOOTED,
        ApplianceError::PrevRootMismatch => err::PREV_ROOT_MISMATCH,
        ApplianceError::AnchorHeadMismatch => err::ANCHOR_HEAD_MISMATCH,
        ApplianceError::IndexMismatch => err::INDEX_MISMATCH,
        ApplianceError::CounterMismatch => err::COUNTER_MISMATCH,
        ApplianceError::WitnessKeyLost => err::WITNESS_KEY_LOST,
        ApplianceError::CounterExhausted => err::COUNTER_EXHAUSTED,
        ApplianceError::NotCommitted => err::NOT_COMMITTED,
        ApplianceError::BootChainFull => err::BOOT_CHAIN_FULL,
        ApplianceError::Tropic(_) => err::TROPIC,
    }
}

fn proto_code(e: ProtoError) -> u32 {
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
        active_anchor_head: Vec::new(),
        active_boot_head: Vec::new(),
        active_anchor_counter: 0,
        status: 0,
        boot_valid: false,
        spi_response: Vec::new(),
    }
}

fn ok(op: i32) -> pb::ApplianceResponse {
    pb::ApplianceResponse {
        ok: true,
        ..base(op)
    }
}

fn fail(op: i32, code: u32) -> pb::ApplianceResponse {
    pb::ApplianceResponse {
        error: code,
        ..base(op)
    }
}

/// Dispatch a decoded request against the appliance.
pub fn dispatch<T: Tropic, S: WitnessSig, P: PartitionSig>(
    app: &mut Appliance<T, S, P>,
    req: &pb::ApplianceRequest,
) -> pb::ApplianceResponse {
    let op = req.op;
    // Boot is NOT a host operation: the firmware boot-fences itself with a
    // device-authoritative firmware measurement at startup. The old wire OP_BOOT
    // (proto enum value 1, reserved) is rejected here as an unknown op so the host
    // can never drive a boot-head advance with an attacker-chosen measurement.
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
            match app.prepare(&owned.as_transition(), &rc) {
                Ok(()) => ok(op),
                Err(e) => fail(op, appliance_code(e)),
            }
        }
        Ok(pb::Op::Commit) => match app.commit() {
            Ok(()) => ok(op),
            Err(e) => fail(op, appliance_code(e)),
        },
        Ok(pb::Op::Emit) => match app.emit() {
            Ok(rel) => pb::ApplianceResponse {
                ok: true,
                release: Some(rel.to_pb()),
                ..base(op)
            },
            Err(e) => fail(op, appliance_code(e)),
        },
        Ok(pb::Op::Finalize) => match app.finalize() {
            Ok(h) => pb::ApplianceResponse {
                ok: true,
                active_root: h.to_vec(),
                ..base(op)
            },
            Err(e) => fail(op, appliance_code(e)),
        },
        Ok(pb::Op::Status) => pb::ApplianceResponse {
            ok: true,
            active_root: app.active.root.to_vec(),
            anchor_bundle: app.bundle.to_vec(),
            active_anchor_head: app.active.anchor_head.to_vec(),
            active_boot_head: app.active.boot_head.to_vec(),
            active_anchor_counter: app.active.anchor_counter,
            status: status_code(app.active.status),
            boot_valid: app.active.boot_valid,
            ..base(op)
        },
        Ok(pb::Op::Cancel) => match app.cancel() {
            Ok(()) => ok(op),
            Err(e) => fail(op, appliance_code(e)),
        },
        // OP_SPI_PASSTHROUGH is not an appliance op — the firmware host services it directly against
        // the chip backend before this generic dispatch. Reaching here means a misrouted frame.
        Ok(pb::Op::SpiPassthrough) => fail(op, err::BAD_OP),
        Ok(pb::Op::Unspecified) | Err(_) => fail(op, err::BAD_OP),
    }
}

/// Decode a request frame, dispatch it, and encode the response frame. The
/// single secure-core entry point; a malformed frame yields a `BAD_PROTO` error
/// response rather than a panic.
pub fn handle<T: Tropic, S: WitnessSig, P: PartitionSig>(
    app: &mut Appliance<T, S, P>,
    frame: &[u8],
) -> Vec<u8> {
    if frame.len() > MAX_FRAME_LEN {
        return encode_response(&fail(0, err::FRAME_TOO_LARGE));
    }
    match decode_request(frame) {
        Ok(req) => encode_response(&dispatch(app, &req)),
        Err(_) => encode_response(&fail(0, err::BAD_PROTO)),
    }
}
