//! The compact 3-state appliance (§12) plus power-loss recovery.
//!
//! `Active = (h_i, B, u_i, status, record)` with `status ∈ {Ready, Prepared, Committed}`.
//! Every offline transfer advances the forward-only frontier `h_i → h_{i+1}` and the local
//! counter floor `u_i → u_i+1` together. The appliance is **not** the transfer authority —
//! the DSM device SMT is (uniqueness is software). The appliance holds the two hardware
//! identity factors and produces `σ^chip` (resident non-exportable Ed25519, on-die) and
//! `σ^host` (RP2350 partition) over the single root-advance message `M_{i+1}`. The DSM
//! layer supplies the device SMT roots `R_i`/`R_{i+1}` (it owns the tree); the appliance
//! signs over them. The counter is a non-rewind floor + offline exposure cap, moved at
//! commit — it is never read by the receiver.
//!
//! Flow: prepare (form `M`, obtain `σ^chip` + `σ^host`, no counter move, no export) →
//! commit (persist candidate → move counter → mark committed) → emit (export after commit)
//! → finalize (advance the active frontier).

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::enrollment::Birth;
use crate::root_advance::{
    anchor_root_advance, root_advance_message, transition_digest, Certificate, OfflineRelease,
    OwnedTransition, Transition,
};
use crate::tropic::{PartitionSig, Tropic, TropicError};
use crate::util::{ct_eq_32, zeroize_vec};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Ready,
    Prepared,
    Committed,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ApplianceError {
    /// Operation not valid in the current status.
    WrongState,
    /// Requested previous frontier is not the active frontier `h_i`.
    PrevRootMismatch,
    /// Claimed successor frontier does not equal `H(h_i ‖ D_{i+1})`.
    NextRootMismatch,
    /// `next_anchor_counter != anchor_counter + 1`, or `anchor_counter != active.u`.
    IndexMismatch,
    /// `active.u != H₀ − H` — the appliance is not offline-ready.
    CounterMismatch,
    /// `MCounter_Update` on an exhausted counter (`H == 0`).
    CounterExhausted,
    /// A committed release is not yet present to emit/finalize.
    NotCommitted,
    Tropic(TropicError),
}

/// Prepared record (§12.2): the certificate carrying the appliance's two on-device identity
/// witnesses (`σ^chip` + `σ^host`) over `M`, plus the transition it signs, retained until
/// commit moves the counter. The third release signature `σ^DSM` rides on the transition, not
/// this certificate.
pub struct PreparedRecord {
    pub txn: OwnedTransition,
    pub cert: Certificate,
}

/// Committed record (§12.3): the assembled release + the counter-committed flag.
pub struct CommittedRecord {
    pub prev_frontier: [u8; 32],
    pub next_frontier: [u8; 32],
    pub anchor_counter: u64,
    pub next_anchor_counter: u64,
    pub release: OfflineRelease,
    pub committed: bool,
}

pub enum Record {
    Empty,
    Prepared(Box<PreparedRecord>),
    Committed(Box<CommittedRecord>),
}

/// The single active state.
pub struct Active {
    /// The current offline frontier `h_i`.
    pub root: [u8; 32],
    /// The local counter floor `u_i = H₀ − H`.
    pub anchor_counter: u64,
    pub status: Status,
    pub record: Record,
}

/// Recovery outcomes (§26).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecoverOutcome {
    Accept([u8; 32]),
    /// A committed successor is pending: the record stays `Committed{committed:true}` so the
    /// caller re-emits with [`Appliance::emit`] and advances with [`Appliance::finalize`] —
    /// never signs a new one.
    ReemitCommitted([u8; 32]),
    DowngradeOnline,
    FailClosed,
    ExhaustedOnlineOnly,
    AcceptPreparedCanComplete,
    OnlineCancelOrResolve,
}

/// The v2 software-authority / hardware-identity appliance for one active frontier.
pub struct Appliance<T: Tropic, P: PartitionSig> {
    pub h0: u32,
    pub anchor_id: [u8; 32],
    pub bundle: [u8; 32],
    pub partition_device_id: [u8; 32],
    /// PUBLIC partition (`σ^host`) verification key `pk_host` — receiver pin material.
    pub partition_pk: Vec<u8>,
    /// PUBLIC resident chip (`σ^chip`) verification key `pk_chip` — receiver pin material.
    pub chip_pk: Vec<u8>,
    pub active: Active,
    /// Set when recovery sees a firmware-boundary / R-memory-map event (downgrades to online).
    pub firmware_boundary_invalid: bool,
    pub rmemory_map_invalid: bool,
    /// SECRET partition signing key (non-exportable on device).
    partition_sk: Vec<u8>,
    tropic: T,
    _p: PhantomData<P>,
}

impl<T: Tropic, P: PartitionSig> Appliance<T, P> {
    /// Construct from a [`Birth`] result. Starts at the genesis frontier `h_0`, counter 0.
    pub fn new(
        tropic: T,
        h0: u32,
        anchor_id: [u8; 32],
        partition_device_id: [u8; 32],
        birth: Birth,
    ) -> Self {
        Self {
            h0,
            anchor_id,
            bundle: birth.bundle,
            partition_device_id,
            partition_pk: birth.partition_pk,
            chip_pk: birth.chip_pk,
            active: Active {
                root: birth.genesis_frontier,
                anchor_counter: 0,
                status: Status::Ready,
                record: Record::Empty,
            },
            firmware_boundary_invalid: false,
            rmemory_map_invalid: false,
            partition_sk: birth.partition_sk,
            tropic,
            _p: PhantomData,
        }
    }

    /// Live anchor counter `u = H₀ − H` from the chip. The counter only counts down, so
    /// `H ≤ H₀`; a reported `H > H₀` is impossible and is rejected.
    pub fn live_index(&mut self) -> Result<u64, ApplianceError> {
        let h = self.tropic.counter_get().map_err(ApplianceError::Tropic)?;
        let u = self.h0.checked_sub(h).ok_or(ApplianceError::CounterMismatch)?;
        Ok(u as u64)
    }

    /// §12.2 Prepare: form the root-advance message `M_{i+1}` binding the DSM-supplied device
    /// roots `R_i`/`R_{i+1}`, obtain `σ^chip` (on-die) and `σ^host` (partition) over it, and
    /// store a durable Prepared record. No counter move, no export. Refused unless Ready and
    /// offline-ready (`active.u = H₀ − H`).
    ///
    /// `sender_device_root_before`/`_after` are the sender's device SMT roots, computed by the
    /// DSM layer (which owns the tree); the appliance signs over them. The receiver
    /// independently verifies their SMT inclusion, so a wrong root yields a release the
    /// receiver rejects fail-closed.
    pub fn prepare(
        &mut self,
        t: &Transition,
        receiver_challenge: &[u8; 32],
        sender_device_root_before: &[u8; 32],
        sender_device_root_after: &[u8; 32],
    ) -> Result<(), ApplianceError> {
        if self.active.status != Status::Ready {
            return Err(ApplianceError::WrongState);
        }
        if !ct_eq_32(&self.active.root, t.prev_root) {
            return Err(ApplianceError::PrevRootMismatch);
        }
        if t.anchor_counter != self.active.anchor_counter {
            return Err(ApplianceError::IndexMismatch);
        }
        if t.next_anchor_counter != t.anchor_counter + 1 {
            return Err(ApplianceError::IndexMismatch);
        }
        // Read H once and reject an exhausted down-counter before signing. commit() guards
        // this too; prepare must not build a release that can never commit.
        let h = self.tropic.counter_get().map_err(ApplianceError::Tropic)?;
        if h == 0 {
            return Err(ApplianceError::CounterExhausted);
        }
        let live_u = self.h0.checked_sub(h).ok_or(ApplianceError::CounterMismatch)? as u64;
        if self.active.anchor_counter != live_u {
            return Err(ApplianceError::CounterMismatch);
        }

        // D_{i+1} over Δ° (excludes the successor root — the DAG property), then the
        // forward-only frontier advance; the claimed successor must match exactly.
        let d = transition_digest(t, receiver_challenge);
        let h_next = anchor_root_advance(&self.active.root, &d);
        if !ct_eq_32(&h_next, t.next_root) {
            return Err(ApplianceError::NextRootMismatch);
        }

        let m = root_advance_message(
            &self.bundle,
            sender_device_root_before,
            sender_device_root_after,
            &self.active.root,
            &h_next,
            t.anchor_counter,
            t.next_anchor_counter,
            &d,
            t.recipient_device_id,
            receiver_challenge,
        );
        // σ^chip on the die (key never leaves the chip) and σ^host from the partition.
        let sigma_chip = self.tropic.chip_sign(&m).map_err(ApplianceError::Tropic)?;
        let sigma_host = P::part_sign(&self.partition_sk, &m);

        let cert = Certificate {
            anchor_bundle: self.bundle,
            sender_device_root_before: *sender_device_root_before,
            sender_device_root_after: *sender_device_root_after,
            prev_frontier: self.active.root,
            next_frontier: h_next,
            anchor_counter: t.anchor_counter,
            next_anchor_counter: t.next_anchor_counter,
            transition_digest: d,
            root_advance_message: m,
            anchor_id: self.anchor_id,
            sigma_chip,
            sigma_host,
            receiver_challenge: *receiver_challenge,
            recipient: *t.recipient_device_id,
        };

        self.active.status = Status::Prepared;
        self.active.record = Record::Prepared(Box::new(PreparedRecord {
            txn: OwnedTransition::from(t),
            cert,
        }));
        Ok(())
    }

    /// §12.3 Commit, in three durable phases: persist the committed candidate
    /// (`committed=false`) → move the counter → mark committed. The release exists durably
    /// before the counter moves, so an interrupted commit is completable by [`recover`].
    /// Nothing is exported before phase 2. The DSM SMT inclusion proofs are attached by the
    /// SDK (which owns the tree) after emit — the appliance carries them as empty here.
    pub fn commit(&mut self) -> Result<(), ApplianceError> {
        let p = match &self.active.record {
            Record::Prepared(p) => p,
            _ => return Err(ApplianceError::WrongState),
        };
        if !ct_eq_32(&p.cert.prev_frontier, &self.active.root) {
            return Err(ApplianceError::PrevRootMismatch);
        }

        // The counter must be movable AND still pinned to this transfer's counter.
        let h = self.tropic.counter_get().map_err(ApplianceError::Tropic)?;
        if h == 0 {
            return Err(ApplianceError::CounterExhausted);
        }
        let live_u = self.h0.checked_sub(h).ok_or(ApplianceError::CounterMismatch)? as u64;
        if live_u != p.cert.anchor_counter {
            return Err(ApplianceError::CounterMismatch);
        }

        let release = OfflineRelease {
            transition: p.txn.clone(),
            anchor_smt_proof_before: Vec::new(),
            anchor_smt_proof_after: Vec::new(),
            cert: p.cert.clone(),
            branch_proof: Vec::new(),
        };
        let prev_frontier = p.cert.prev_frontier;
        let next_frontier = p.cert.next_frontier;
        let anchor_counter = p.cert.anchor_counter;
        let next_anchor_counter = p.cert.next_anchor_counter;

        // Phase 1: persist the committed candidate.
        self.active.status = Status::Committed;
        self.active.record = Record::Committed(Box::new(CommittedRecord {
            prev_frontier,
            next_frontier,
            anchor_counter,
            next_anchor_counter,
            release,
            committed: false,
        }));

        // Phase 2: move the counter (the non-rewind floor). On failure nothing is exported;
        // recovery completes the durable candidate.
        self.tropic
            .counter_update()
            .map_err(|_| ApplianceError::CounterExhausted)?;

        // Phase 3: mark counter-committed.
        if let Record::Committed(c) = &mut self.active.record {
            c.committed = true;
        }
        self.active.anchor_counter = next_anchor_counter;
        Ok(())
    }

    /// §12.5 Emit: export the committed release (the SDK attaches the SMT proofs before send).
    pub fn emit(&self) -> Result<&OfflineRelease, ApplianceError> {
        match &self.active.record {
            Record::Committed(c) if c.committed => Ok(&c.release),
            _ => Err(ApplianceError::NotCommitted),
        }
    }

    /// §12.6 Finalize: advance the active frontier to `(h_{i+1}, u_i+1)`, guarded by
    /// `active.u = H₀ − H`.
    pub fn finalize(&mut self) -> Result<[u8; 32], ApplianceError> {
        let (next_frontier, next_anchor_counter) = match &self.active.record {
            Record::Committed(c) if c.committed => (c.next_frontier, c.next_anchor_counter),
            _ => return Err(ApplianceError::NotCommitted),
        };
        let live_u = self.live_index()?;
        if self.active.anchor_counter != live_u {
            return Err(ApplianceError::CounterMismatch);
        }
        self.active = Active {
            root: next_frontier,
            anchor_counter: next_anchor_counter,
            status: Status::Ready,
            record: Record::Empty,
        };
        Ok(next_frontier)
    }

    /// Cancel a prepared (not yet committed) record.
    pub fn cancel(&mut self) -> Result<(), ApplianceError> {
        match &self.active.record {
            Record::Prepared(_) => {
                self.active.status = Status::Ready;
                self.active.record = Record::Empty;
                Ok(())
            }
            _ => Err(ApplianceError::WrongState),
        }
    }

    /// §26 power-loss recovery. Never signs a new successor — a committed record is re-emitted
    /// and finalized as the *same* successor.
    pub fn recover(&mut self) -> RecoverOutcome {
        if self.firmware_boundary_invalid || self.rmemory_map_invalid {
            return RecoverOutcome::DowngradeOnline;
        }
        let live_u = match self.live_index() {
            Ok(u) => u,
            Err(_) => return RecoverOutcome::DowngradeOnline,
        };

        match self.active.status {
            Status::Committed => {
                let (committed, rec_u, next_frontier, prev_frontier) = match &self.active.record {
                    Record::Committed(c) => {
                        (c.committed, c.next_anchor_counter, c.next_frontier, c.prev_frontier)
                    }
                    _ => return RecoverOutcome::DowngradeOnline,
                };
                if committed {
                    if rec_u != live_u {
                        return RecoverOutcome::DowngradeOnline;
                    }
                    self.active.anchor_counter = rec_u;
                    RecoverOutcome::ReemitCommitted(next_frontier)
                } else if rec_u == live_u {
                    // Counter moved but the committed flag was not persisted.
                    if let Record::Committed(c) = &mut self.active.record {
                        c.committed = true;
                    }
                    self.active.anchor_counter = rec_u;
                    RecoverOutcome::ReemitCommitted(next_frontier)
                } else if rec_u == live_u + 1 {
                    // Durable release, counter not yet moved: complete only if the previous
                    // frontier still matches the active state.
                    if !ct_eq_32(&prev_frontier, &self.active.root) {
                        return RecoverOutcome::DowngradeOnline;
                    }
                    if self.tropic.counter_update().is_err() {
                        return RecoverOutcome::DowngradeOnline;
                    }
                    if let Record::Committed(c) = &mut self.active.record {
                        c.committed = true;
                    }
                    self.active.anchor_counter = rec_u;
                    RecoverOutcome::ReemitCommitted(next_frontier)
                } else {
                    RecoverOutcome::DowngradeOnline
                }
            }
            Status::Prepared => {
                if self.active.anchor_counter != live_u {
                    return RecoverOutcome::DowngradeOnline;
                }
                // Both on-device witnesses (σ^chip, σ^host) are formed atomically in prepare and
                // no counter has moved, so a Prepared record is always safe to complete when its
                // frontier + signatures are intact.
                let (root_ok, sigs_present) = match &self.active.record {
                    Record::Prepared(p) => (
                        ct_eq_32(&p.cert.prev_frontier, &self.active.root),
                        !p.cert.sigma_chip.is_empty() && !p.cert.sigma_host.is_empty(),
                    ),
                    _ => return RecoverOutcome::DowngradeOnline,
                };
                if !root_ok {
                    return RecoverOutcome::DowngradeOnline;
                }
                if sigs_present {
                    RecoverOutcome::AcceptPreparedCanComplete
                } else {
                    RecoverOutcome::OnlineCancelOrResolve
                }
            }
            Status::Ready => {
                // The chip's monotonic counter is the source of truth (it can only fall). If it
                // reads LOWER than our model (`active < live_u` — more steps consumed than we
                // tracked), ADOPT the live position rather than downgrading: it only shrinks the
                // remaining budget, never mints value, and restores `active.u == live_u` so
                // prepare's counter check passes. `active > live_u` is impossible for a real
                // down-counter -> fail closed.
                if self.active.anchor_counter < live_u {
                    self.active.anchor_counter = live_u;
                }
                if self.active.anchor_counter > live_u {
                    return RecoverOutcome::FailClosed;
                }
                let h = match self.tropic.counter_get() {
                    Ok(h) => h,
                    Err(_) => return RecoverOutcome::DowngradeOnline,
                };
                if h == 0 {
                    return RecoverOutcome::ExhaustedOnlineOnly;
                }
                RecoverOutcome::Accept(self.active.root)
            }
        }
    }
}

/// Wipe the partition signing key on teardown (its disclosure forges `σ^host`). The
/// per-transfer signatures are public (`σ^chip` + `σ^host` are exported in the certificate);
/// the resident chip key never leaves the die, so the only long-lived local secret is
/// `partition_sk`.
impl<T: Tropic, P: PartitionSig> Drop for Appliance<T, P> {
    fn drop(&mut self) {
        zeroize_vec(&mut self.partition_sk);
    }
}
