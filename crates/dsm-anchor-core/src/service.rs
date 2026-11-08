//! The secure-core appliance service: decode an `ApplianceRequest`, drive the
//! [`Appliance`], and encode an `ApplianceResponse`. [`handle`] is the single mediated
//! entry point — in a TrustZone-M deployment it is the secure-gateway veneer (the only NSC
//! entry), and the non-secure transport reaches the TROPIC01 solely through it; the
//! transport holds no chip handle of its own.

extern crate alloc;
use alloc::vec::Vec;

use crate::appliance::{Appliance, ApplianceError, RecoverOutcome, Status};
use crate::durable::{ActiveStore, DurableAppliance, DurableError};
use crate::proto::{arr32, decode_frame, encode_response, pb, ProtoError};
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
    /// A prepare its owner did not authorize: no valid signature of the provisioned device key
    /// over its authorization digest. Nothing was signed.
    pub const OWNER_UNAUTHORIZED: u32 = 10;
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
    /// A try-run was waiting on its owner's authorization when another request arrived. The run has
    /// ended, the anchor is as it was found, and the request was not served: it is asked again.
    pub const REHEARSAL_ENDED: u32 = 108;
    /// The Non-secure image does not hash to the digest burned for it: no authority op runs and the
    /// chip is not touched.
    pub const MEASUREMENT: u32 = 200;
    /// The anchor did not come up at boot; `detail` says why.
    pub const NOT_UP: u32 = 201;
    /// A try-run did not pass; its steps say where. A provisioning refused for it bound nothing.
    pub const TRY_RUN_FAILED: u32 = 202;
    // 203 was the trial image's refusal of an install; its install is a trial now, and binds nothing.
    /// This image reads the chip and says what it is and holds (`OP_IDENTIFY`). It serves nothing else.
    pub const IDENTIFY_IMAGE: u32 = 204;
}

/// Protocol-level ceiling on a request frame, a backstop against absurd inputs before prost
/// decode allocates. The non-secure transport must additionally enforce a heap-appropriate
/// cap at its receive edge.
pub const MAX_FRAME_LEN: usize = 64 * 1024;

/// The owner's authorization of a prepare: one BLAKE3-SPHINCS+ SPX256f signature of the device key
/// the anchor was provisioned for, the scheme's own length
/// (`owner_authorization_is_one_spx256f_signature` holds this to it).
pub const OWNER_AUTHORIZATION_BYTES: usize = 49_856;

/// The largest message of any request. A prepare holds its transition several times over while it
/// signs and records it, so a larger one could exhaust a board's heap; the wallet's own messages
/// are a few hundred bytes. The authorization's signature is not a message: it follows one on the
/// wire ([`crate::proto::decode_frame`]) and is read in place.
pub const REQUEST_HEAD_MAX: usize = 4 * 1024;

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
        ApplianceError::OwnerUnauthorized => err::OWNER_UNAUTHORIZED,
    }
}

pub(crate) fn durable_code(e: DurableError) -> u32 {
    match e {
        DurableError::Appliance(e) => appliance_code(e),
        DurableError::Store(_) => err::STORE,
        DurableError::Record(_) => err::RECORD,
        DurableError::NotProvisioned => err::NOT_PROVISIONED,
        DurableError::AlreadyProvisioned => err::ALREADY_PROVISIONED,
        DurableError::TryRun(_) => err::TRY_RUN_FAILED,
    }
}

pub(crate) fn proto_code(e: ProtoError) -> u32 {
    match e {
        ProtoError::MissingField => err::MISSING_FIELD,
        ProtoError::BadOp => err::BAD_OP,
        ProtoError::FrameTooLarge => err::FRAME_TOO_LARGE,
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
        awaiting_authorization: Vec::new(),
        active_root: Vec::new(),
        anchor_bundle: Vec::new(),
        active_anchor_counter: 0,
        status: 0,
        pin_anchor_id: Vec::new(),
        pin_enrolled_counter: 0,
        pin_partition_pk: Vec::new(),
        pin_chip_pk: Vec::new(),
        pin_birth_commitment: Vec::new(),
        recovery: pb::Recovery::Unspecified as i32,
        detail: alloc::string::String::new(),
        try_run: Vec::new(),
        permanent: Vec::new(),
        transport_check: Vec::new(),
        chip_readings: Vec::new(),
        chip_certificates: Vec::new(),
        install: pb::InstallKind::InstallUnspecified as i32,
    }
}

/// What an install makes, on the wire.
pub(crate) fn install_kind(install: crate::enrollment::Install) -> i32 {
    match install {
        crate::enrollment::Install::ForGood => pb::InstallKind::InstallForGood as i32,
        crate::enrollment::Install::ForTrial => pb::InstallKind::InstallForTrial as i32,
    }
}

/// A try-run on the wire: every step, and what installing would make permanent.
pub(crate) fn try_run_response(
    op: i32,
    run: &crate::try_run::TryRun,
    install: crate::enrollment::Install,
) -> pb::ApplianceResponse {
    let answer = match run.blocking(install) {
        None => ok(op),
        Some(_stopped) => fail(op, err::TRY_RUN_FAILED),
    };
    pb::ApplianceResponse {
        try_run: steps_pb(&run.steps),
        permanent: permanent_pb(install),
        transport_check: crate::try_run::transport_check(run.release_bytes),
        install: install_kind(install),
        ..answer
    }
}

/// A try-run begun and waiting on its owner's authorization: the steps so far, and the digest
/// (`awaiting`) whose signature under the rehearsal key finishes it.
pub(crate) fn awaiting_response(
    op: i32,
    steps: &[crate::try_run::TryStep],
    install: crate::enrollment::Install,
    awaiting: [u8; 32],
) -> pb::ApplianceResponse {
    pb::ApplianceResponse {
        try_run: steps_pb(steps),
        permanent: permanent_pb(install),
        install: install_kind(install),
        awaiting_authorization: awaiting.to_vec(),
        ..ok(op)
    }
}

fn steps_pb(steps: &[crate::try_run::TryStep]) -> Vec<pb::TryRunStep> {
    steps
        .iter()
        .map(|step| pb::TryRunStep {
            name: step.name.clone(),
            passed: matches!(step.outcome, Ok(())),
            production: step.requirement == crate::try_run::Requirement::Production,
            detail: match &step.outcome {
                Ok(()) => alloc::string::String::new(),
                Err(why) => why.clone(),
            },
        })
        .collect()
}

fn permanent_pb(install: crate::enrollment::Install) -> Vec<alloc::string::String> {
    crate::try_run::permanent(install)
        .iter()
        .map(|line| alloc::string::String::from(*line))
        .collect()
}

pub(crate) fn ok(op: i32) -> pb::ApplianceResponse {
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

/// A refusal of an appliance operation with its cause: what the code alone does not say.
pub(crate) fn appliance_refusal(op: i32, e: ApplianceError) -> pb::ApplianceResponse {
    pb::ApplianceResponse {
        detail: alloc::format!("{e:?}"),
        ..fail(op, appliance_code(e))
    }
}

/// A refusal frame from outside the anchor: the firmware's own gates, and an anchor that did not come
/// up. The code says which, and `detail` what the code alone does not.
pub fn refusal(op: i32, code: u32, detail: &str) -> Vec<u8> {
    encode_response(&pb::ApplianceResponse {
        detail: alloc::string::String::from(detail),
        ..fail(op, code)
    })
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
    /// The owner's authorization of the next prepare ([`Appliance::authorize`]).
    fn authorize(&mut self, digest: &[u8; 32], signature: &[u8]) -> Result<(), u32>;
    fn commit(&mut self) -> Result<(), u32>;
    fn emit(&mut self) -> Result<pb::OfflineRelease, u32>;
    fn finalize(&mut self) -> Result<[u8; 32], u32>;
    fn cancel(&mut self) -> Result<(), u32>;
    fn recover(&mut self) -> RecoverOutcome;
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
    fn authorize(&mut self, digest: &[u8; 32], signature: &[u8]) -> Result<(), u32> {
        Appliance::authorize(self, digest, signature).map_err(appliance_code)
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
    fn recover(&mut self) -> RecoverOutcome {
        Appliance::recover(self)
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
    fn authorize(&mut self, digest: &[u8; 32], signature: &[u8]) -> Result<(), u32> {
        DurableAppliance::authorize(self, digest, signature).map_err(durable_code)
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
    fn recover(&mut self) -> RecoverOutcome {
        DurableAppliance::recover(self)
    }
}

/// A recovery outcome on the wire: its kind, and the frontier it names (the active frontier for
/// `Accept`, the committed release's successor frontier for `ReemitCommitted`).
fn recovery_wire(outcome: RecoverOutcome) -> (pb::Recovery, Vec<u8>) {
    match outcome {
        RecoverOutcome::Accept(root) => (pb::Recovery::Accept, root.to_vec()),
        RecoverOutcome::ReemitCommitted(next) => (pb::Recovery::ReemitCommitted, next.to_vec()),
        RecoverOutcome::DowngradeOnline => (pb::Recovery::DowngradeOnline, Vec::new()),
        RecoverOutcome::FailClosed => (pb::Recovery::FailClosed, Vec::new()),
        RecoverOutcome::ExhaustedOnlineOnly => (pb::Recovery::ExhaustedOnlineOnly, Vec::new()),
        RecoverOutcome::AcceptPreparedCanComplete => {
            (pb::Recovery::AcceptPreparedCanComplete, Vec::new())
        }
        RecoverOutcome::OnlineCancelOrResolve => (pb::Recovery::OnlineCancelOrResolve, Vec::new()),
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
        install: install_kind(app.install),
        ..base(op)
    }
}

/// Dispatch a decoded request against the appliance. `signature` is what followed the message on
/// the wire: an `OP_AUTHORIZE`'s owner signature, and nothing for any other op.
pub fn dispatch<A: Served>(
    app: &mut A,
    req: &pb::ApplianceRequest,
    signature: &[u8],
) -> pb::ApplianceResponse {
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
        Ok(pb::Op::Authorize) => {
            if signature.is_empty() {
                return fail(op, err::MISSING_FIELD);
            }
            let digest = match arr32(&req.authorization_digest) {
                Ok(a) => a,
                Err(e) => return fail(op, proto_code(e)),
            };
            match app.authorize(&digest, signature) {
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
        Ok(pb::Op::Recover) => {
            let (kind, frontier) = recovery_wire(app.recover());
            pb::ApplianceResponse {
                recovery: kind as i32,
                active_root: frontier,
                ..ok(op)
            }
        }
        Ok(pb::Op::Cancel) => match app.cancel() {
            Ok(()) => ok(op),
            Err(code) => fail(op, code),
        },
        // An appliance exists only once its anchor is provisioned, and an anchor is provisioned
        // once: provisioning it again is refused.
        Ok(pb::Op::Provision | pb::Op::TryRun) => fail(op, err::ALREADY_PROVISIONED),
        // Only the identify image reads a chip for whoever asks (`identify`); an anchor does not.
        Ok(pb::Op::Identify) => fail(op, err::BAD_OP),
        Ok(pb::Op::Unspecified) | Err(_) => fail(op, err::BAD_OP),
    }
}

/// Decode a request frame, dispatch it, and encode the response frame. The single secure-core
/// entry point; a malformed frame yields a `BAD_PROTO` error response rather than a panic.
pub fn handle<A: Served>(app: &mut A, frame: &[u8]) -> Vec<u8> {
    match decode_frame(frame) {
        Ok((req, signature)) => encode_response(&dispatch(app, &req, signature)),
        Err(e) => encode_response(&fail(0, proto_code(e))),
    }
}
