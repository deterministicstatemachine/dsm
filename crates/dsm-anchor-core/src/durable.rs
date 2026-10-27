//! The appliance's durable record (§26): what a power cut leaves behind.
//!
//! The chip keeps its own monotonic counter. Everything else the appliance holds across a power
//! cut is one record: the active frontier `h_i`, the counter `u_i` it last saw, and the prepared
//! or committed transfer. [`DurableAppliance`] writes that record whole at every durable point of
//! the flow — after prepare, after the committed candidate (before the counter moves), after the
//! counter moved, after finalize, after cancel, and after a recovery that completed a commit — and
//! restores the appliance from it at boot, before §26 recovery decides whether it may serve.
//!
//! A store holds the last record written in full. A write the power cut short leaves the record
//! before it. So the two crash points inside a commit are exactly the ones [`Appliance::recover`]
//! completes: the candidate written with the counter not yet moved, and the counter moved with
//! the committed flag not yet written.
//!
//! On the RP2350 the record lives in TROPIC01 R-memory; on a host it lives wherever the
//! [`ActiveStore`] it is given keeps it. The protocol is the same.

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use prost::Message;

use crate::appliance::{
    Active, Appliance, ApplianceError, BootRecoveryRefusal, CommittedRecord, PreparedRecord,
    Record, RecoverOutcome, Status,
};
use crate::proto::{arr32, pb, ProtoError};
use crate::root_advance::{OfflineRelease, Transition};
use crate::tropic::{PartitionSig, Tropic};

/// Why the durable record could not be written or read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StoreError {
    /// The store did not take the write or answer the read: no power, or the bus failed.
    Unavailable,
}

/// Where the appliance's durable record lives: one record, replaced whole.
pub trait ActiveStore {
    /// Replace the record with `record`. After a power cut the store holds either this record or
    /// the one before it, never a mixture.
    fn write(&mut self, record: &[u8]) -> Result<(), StoreError>;
    /// The record last written in full; `None` if the appliance was never born into this store.
    fn read(&mut self) -> Result<Option<Vec<u8>>, StoreError>;
}

/// Why a stored record is not an appliance record.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RecordError {
    /// The bytes are not a `DurableActive` message.
    Undecodable(prost::DecodeError),
    /// The message decodes, but a field is missing or the wrong length.
    Invalid(ProtoError),
}

impl From<ProtoError> for RecordError {
    fn from(e: ProtoError) -> Self {
        Self::Invalid(e)
    }
}

/// Why a durable operation failed. In every case the appliance's state is the record the store
/// holds: an operation whose record could not be written is undone in memory.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DurableError {
    Appliance(ApplianceError),
    Store(StoreError),
    /// The stored record is not an appliance record.
    Record(RecordError),
    /// The store holds no record: the appliance was never born into it.
    NeverBorn,
}

impl From<ApplianceError> for DurableError {
    fn from(e: ApplianceError) -> Self {
        Self::Appliance(e)
    }
}

/// Why a durable appliance will not serve after boot.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DurableBootRefusal {
    /// §26 recovery refused.
    Recovery(BootRecoveryRefusal),
    /// The reset of a prepared record failed, or could not be made durable.
    Reset(DurableError),
}

/// The canonical bytes of an active state.
pub fn encode_active(active: &Active) -> Vec<u8> {
    let record = match &active.record {
        Record::Empty => None,
        Record::Prepared(p) => Some(pb::durable_active::Record::Prepared(pb::DurablePrepared {
            transition: Some(p.txn.to_pb()),
            cert: Some(p.cert.to_pb()),
        })),
        Record::Committed(c) => Some(pb::durable_active::Record::Committed(
            pb::DurableCommitted {
                prev_frontier: c.prev_frontier.to_vec(),
                next_frontier: c.next_frontier.to_vec(),
                anchor_counter: c.anchor_counter,
                next_anchor_counter: c.next_anchor_counter,
                release: Some(c.release.to_pb()),
                counter_committed: c.committed,
            },
        )),
    };
    pb::DurableActive {
        root: active.root.to_vec(),
        anchor_counter: active.anchor_counter,
        record,
    }
    .encode_to_vec()
}

/// The active state a record holds. Its status is its record's kind.
pub fn decode_active(bytes: &[u8]) -> Result<Active, RecordError> {
    let d = pb::DurableActive::decode(bytes).map_err(RecordError::Undecodable)?;
    let (status, record) = match d.record {
        None => (Status::Ready, Record::Empty),
        Some(pb::durable_active::Record::Prepared(p)) => (
            Status::Prepared,
            Record::Prepared(Box::new(PreparedRecord {
                txn: p
                    .transition
                    .ok_or(ProtoError::MissingField)?
                    .to_owned_transition()?,
                cert: p.cert.ok_or(ProtoError::MissingField)?.to_cert()?,
            })),
        ),
        Some(pb::durable_active::Record::Committed(c)) => {
            let release: OfflineRelease =
                c.release.ok_or(ProtoError::MissingField)?.to_release()?;
            (
                Status::Committed,
                Record::Committed(Box::new(CommittedRecord {
                    prev_frontier: arr32(&c.prev_frontier)?,
                    next_frontier: arr32(&c.next_frontier)?,
                    anchor_counter: c.anchor_counter,
                    next_anchor_counter: c.next_anchor_counter,
                    release,
                    committed: c.counter_committed,
                })),
            )
        }
    };
    Ok(Active {
        root: arr32(&d.root)?,
        anchor_counter: d.anchor_counter,
        status,
        record,
    })
}

/// An appliance whose state outlives a power cut: every change to it is written to its store
/// before the operation that made it returns.
pub struct DurableAppliance<T: Tropic, P: PartitionSig, S: ActiveStore> {
    app: Appliance<T, P>,
    store: S,
    /// The record the store holds, as last written.
    written: Vec<u8>,
}

impl<T: Tropic, P: PartitionSig, S: ActiveStore> DurableAppliance<T, P, S> {
    /// A newly born appliance: its first record is written before it serves anything.
    pub fn born(app: Appliance<T, P>, mut store: S) -> Result<Self, DurableError> {
        let written = encode_active(&app.active);
        store.write(&written).map_err(DurableError::Store)?;
        Ok(Self {
            app,
            store,
            written,
        })
    }

    /// The appliance as its store left it: `app` is the appliance its birth makes, and its
    /// active state is replaced by the stored record. Nothing is decided here; boot recovery
    /// ([`Self::recover_at_boot`]) decides whether it serves.
    pub fn restore(mut app: Appliance<T, P>, mut store: S) -> Result<Self, DurableError> {
        let written = store
            .read()
            .map_err(DurableError::Store)?
            .ok_or(DurableError::NeverBorn)?;
        app.active = decode_active(&written).map_err(DurableError::Record)?;
        Ok(Self {
            app,
            store,
            written,
        })
    }

    /// The appliance, to read.
    pub fn appliance(&self) -> &Appliance<T, P> {
        &self.app
    }

    /// The appliance's store, to read.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Write the active state if it changed. A write the store does not take undoes the change in
    /// memory: the appliance is again what the store holds.
    fn persist(&mut self) -> Result<(), DurableError> {
        let record = encode_active(&self.app.active);
        if record == self.written {
            return Ok(());
        }
        match self.store.write(&record) {
            Ok(()) => {
                self.written = record;
                Ok(())
            }
            Err(e) => {
                self.app.active = decode_active(&self.written).map_err(DurableError::Record)?;
                Err(DurableError::Store(e))
            }
        }
    }

    /// Undo in memory whatever an operation changed before it failed: the appliance is what the
    /// store holds.
    fn back_to_written(&mut self, e: ApplianceError) -> DurableError {
        match decode_active(&self.written) {
            Ok(active) => {
                self.app.active = active;
                DurableError::Appliance(e)
            }
            Err(record) => DurableError::Record(record),
        }
    }

    /// [`Appliance::prepare`], then the prepared record written.
    pub fn prepare(
        &mut self,
        t: &Transition,
        receiver_challenge: &[u8; 32],
        sender_device_root_before: &[u8; 32],
        sender_device_root_after: &[u8; 32],
    ) -> Result<(), DurableError> {
        self.app.prepare(
            t,
            receiver_challenge,
            sender_device_root_before,
            sender_device_root_after,
        )?;
        self.persist()
    }

    /// [`Appliance::commit`] with its record written between the phases: the committed candidate
    /// before the counter moves, then the counter-committed record after it.
    pub fn commit(&mut self) -> Result<(), DurableError> {
        self.app.commit_candidate()?;
        self.persist()?;
        if let Err(e) = self.app.commit_counter() {
            return Err(self.back_to_written(e));
        }
        self.persist()
    }

    /// [`Appliance::emit`]: export the committed release. Reads only.
    pub fn emit(&self) -> Result<&OfflineRelease, ApplianceError> {
        self.app.emit()
    }

    /// [`Appliance::finalize`], then the advanced frontier written.
    pub fn finalize(&mut self) -> Result<[u8; 32], DurableError> {
        let next = self.app.finalize()?;
        self.persist()?;
        Ok(next)
    }

    /// [`Appliance::cancel`], then the emptied record written.
    pub fn cancel(&mut self) -> Result<(), DurableError> {
        self.app.cancel()?;
        self.persist()
    }

    /// [`Appliance::recover`], with a commit it completes written. A completion the store does
    /// not take is no completion: the outcome is `DowngradeOnline`.
    pub fn recover(&mut self) -> RecoverOutcome {
        let outcome = self.app.recover();
        self.persist()
            .map_or(RecoverOutcome::DowngradeOnline, |()| outcome)
    }

    /// [`Appliance::recover_at_boot`] over the durable record: a prepared record no session can
    /// own across the reboot is cancelled durably, then recovery must accept.
    pub fn recover_at_boot(&mut self) -> Result<(), DurableBootRefusal> {
        match self.recover() {
            RecoverOutcome::Accept(_) | RecoverOutcome::ReemitCommitted(_) => Ok(()),
            RecoverOutcome::AcceptPreparedCanComplete => {
                self.cancel().map_err(DurableBootRefusal::Reset)?;
                match self.recover() {
                    RecoverOutcome::Accept(_) => Ok(()),
                    other => Err(DurableBootRefusal::Recovery(
                        BootRecoveryRefusal::OutcomeAfterReset(other),
                    )),
                }
            }
            other => Err(DurableBootRefusal::Recovery(BootRecoveryRefusal::Outcome(
                other,
            ))),
        }
    }

    /// The live counter `u = H₀ − H` from the chip.
    pub fn live_index(&mut self) -> Result<u64, ApplianceError> {
        self.app.live_index()
    }
}
