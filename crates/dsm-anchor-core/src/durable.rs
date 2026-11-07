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
use alloc::string::String;
use alloc::vec::Vec;

use prost::Message;

use crate::appliance::{
    Active, Appliance, ApplianceError, BootRecoveryRefusal, CommittedRecord, PreparedRecord,
    Record, RecoverOutcome, Status,
};
use crate::enrollment::{ChipBirth, Provisioning};
use crate::proto::{arr32, pb, ProtoError};
use crate::root_advance::{OfflineRelease, Transition};
use crate::tropic::{PartitionSig, Tropic};

/// Why the durable record could not be written or read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StoreError {
    /// The store did not take the write or answer the read: no power, or the bus failed.
    Unavailable,
    /// The store's device took the command and refused it.
    Refused,
    /// The store holds written slots that form no complete record.
    Corrupt,
    /// The record is larger than the store was laid out to hold.
    TooLarge,
    /// The chip answered and will not give this slot back, as a write cut short can leave it. The
    /// slot holds no record; the store reads the record before it.
    Unreadable,
    /// A slot read back does not hold what was just written to it. The record before it stands.
    NotHeld,
}

/// Where the appliance's durable record lives: one record, replaced whole.
pub trait ActiveStore {
    /// Replace the record with `record`. After a power cut the store holds either this record or
    /// the one before it, never a mixture.
    fn write(&mut self, record: &[u8]) -> Result<(), StoreError>;
    /// The record last written in full; `None` if the appliance was never born into this store.
    fn read(&mut self) -> Result<Option<Vec<u8>>, StoreError>;
    /// With no record in the store: try `record` where the store's own record would go, read it back
    /// and erase it. Refused over a record.
    fn try_record(&mut self, record: &[u8]) -> Result<(), StoreError>;
    /// [`Self::write`], where no record is ever read from: what a try-run writes through.
    fn trial_write(&mut self, record: &[u8]) -> Result<(), StoreError>;
    /// [`Self::read`] of what [`Self::trial_write`] wrote.
    fn trial_read(&mut self) -> Result<Option<Vec<u8>>, StoreError>;
    /// Erase whatever a try-run wrote, a power cut's remains included.
    fn trial_clear(&mut self) -> Result<(), StoreError>;
}

/// A store behind a `Box`, as a firmware holds it, and as a try-run drives its trial slots.
impl<S: ActiveStore + ?Sized> ActiveStore for Box<S> {
    fn write(&mut self, record: &[u8]) -> Result<(), StoreError> {
        (**self).write(record)
    }
    fn read(&mut self) -> Result<Option<Vec<u8>>, StoreError> {
        (**self).read()
    }
    fn try_record(&mut self, record: &[u8]) -> Result<(), StoreError> {
        (**self).try_record(record)
    }
    fn trial_write(&mut self, record: &[u8]) -> Result<(), StoreError> {
        (**self).trial_write(record)
    }
    fn trial_read(&mut self) -> Result<Option<Vec<u8>>, StoreError> {
        (**self).trial_read()
    }
    fn trial_clear(&mut self) -> Result<(), StoreError> {
        (**self).trial_clear()
    }
}

/// A store a try-run lends out for the length of one payment.
impl<S: ActiveStore + ?Sized> ActiveStore for &mut S {
    fn write(&mut self, record: &[u8]) -> Result<(), StoreError> {
        (**self).write(record)
    }
    fn read(&mut self) -> Result<Option<Vec<u8>>, StoreError> {
        (**self).read()
    }
    fn try_record(&mut self, record: &[u8]) -> Result<(), StoreError> {
        (**self).try_record(record)
    }
    fn trial_write(&mut self, record: &[u8]) -> Result<(), StoreError> {
        (**self).trial_write(record)
    }
    fn trial_read(&mut self) -> Result<Option<Vec<u8>>, StoreError> {
        (**self).trial_read()
    }
    fn trial_clear(&mut self) -> Result<(), StoreError> {
        (**self).trial_clear()
    }
}

/// A store's trial slots, driven as the store itself: what a try-run's payment and a trial install
/// keep their record in. The trial image clears them at every boot. The record is the anchor's own,
/// written and read as any record is, in slots no install for good reads. Its own slots are still
/// tried before an install, as for one for good.
pub struct TrialRecords<S>(pub S);

impl<S: ActiveStore> ActiveStore for TrialRecords<S> {
    fn write(&mut self, record: &[u8]) -> Result<(), StoreError> {
        self.0.trial_write(record)
    }
    fn read(&mut self) -> Result<Option<Vec<u8>>, StoreError> {
        self.0.trial_read()
    }
    fn try_record(&mut self, record: &[u8]) -> Result<(), StoreError> {
        self.0.try_record(record)
    }
    fn trial_write(&mut self, record: &[u8]) -> Result<(), StoreError> {
        self.0.trial_write(record)
    }
    fn trial_read(&mut self) -> Result<Option<Vec<u8>>, StoreError> {
        self.0.trial_read()
    }
    fn trial_clear(&mut self) -> Result<(), StoreError> {
        self.0.trial_clear()
    }
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
    /// The store holds no record: the anchor was never provisioned.
    NotProvisioned,
    /// The store already holds a record: an anchor is provisioned once.
    AlreadyProvisioned,
    /// The try-run did not pass, so nothing was bound: the step it stopped at, and why.
    TryRun(String),
}

impl From<ApplianceError> for DurableError {
    fn from(e: ApplianceError) -> Self {
        Self::Appliance(e)
    }
}

/// A provisioning the anchor refused, with the chip and the store it was given: the anchor is
/// still unprovisioned and can be provisioned again.
pub struct ProvisionRefused<T, S> {
    pub error: DurableError,
    pub tropic: T,
    pub store: S,
}

impl<T, S> core::fmt::Debug for ProvisionRefused<T, S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "provisioning refused: {:?}", self.error)
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

fn active_pb(active: &Active) -> pb::DurableActive {
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
}

/// The canonical bytes of an active state.
pub fn encode_active(active: &Active) -> Vec<u8> {
    active_pb(active).encode_to_vec()
}

/// The active state a record holds. Its status is its record's kind.
pub fn decode_active(bytes: &[u8]) -> Result<Active, RecordError> {
    active_from_pb(pb::DurableActive::decode(bytes).map_err(RecordError::Undecodable)?)
}

fn active_from_pb(d: pb::DurableActive) -> Result<Active, RecordError> {
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

fn provisioning_pb(p: &Provisioning) -> pb::Provisioning {
    pb::Provisioning {
        device_id: p.device_id.to_vec(),
        online_id_pk: p.online_id_pk.clone(),
        policy_hash: p.policy_hash.to_vec(),
        genesis_root: p.genesis_root.to_vec(),
    }
}

/// The canonical bytes of an anchor's durable record: what it was provisioned for, and its
/// active state.
pub fn encode_anchor(provisioning: &Provisioning, active: &Active) -> Vec<u8> {
    pb::DurableAnchor {
        provisioning: Some(provisioning_pb(provisioning)),
        active: Some(active_pb(active)),
    }
    .encode_to_vec()
}

/// The identity a provisioning names: the owner's device id, its online key, the policy and the
/// genesis, each as the anchor binds it.
pub fn provisioning_from_pb(p: pb::Provisioning) -> Result<Provisioning, ProtoError> {
    if p.online_id_pk.is_empty() {
        return Err(ProtoError::MissingField);
    }
    Ok(Provisioning {
        device_id: arr32(&p.device_id)?,
        online_id_pk: p.online_id_pk,
        policy_hash: arr32(&p.policy_hash)?,
        genesis_root: arr32(&p.genesis_root)?,
    })
}

/// What an anchor's durable record holds: what it was provisioned for, and its active state.
pub fn decode_anchor(bytes: &[u8]) -> Result<(Provisioning, Active), RecordError> {
    let d = pb::DurableAnchor::decode(bytes).map_err(RecordError::Undecodable)?;
    let provisioning = provisioning_from_pb(d.provisioning.ok_or(ProtoError::MissingField)?)?;
    let active = active_from_pb(d.active.ok_or(ProtoError::MissingField)?)?;
    Ok((provisioning, active))
}

/// An appliance whose state outlives a power cut: every change to it is written to its store
/// before the operation that made it returns.
pub struct DurableAppliance<T: Tropic, P: PartitionSig, S: ActiveStore> {
    app: Appliance<T, P>,
    provisioning: Provisioning,
    store: S,
    /// The record the store holds, as last written.
    written: Vec<u8>,
}

impl<T: Tropic, P: PartitionSig, S: ActiveStore> DurableAppliance<T, P, S> {
    /// Provision the anchor for the device `provisioning` names: the birth ceremony over the
    /// chip's own identity and that device's, and the first record written before the appliance
    /// serves anything. Refused when the store already holds a record: an anchor is provisioned
    /// once, and never for a second device. Refused too, with nothing written, unless a try-run of
    /// this very install passes first ([`crate::try_run`]): nothing permanent happens on a chip that
    /// has not just gone through it.
    pub fn provision(
        chip: &ChipBirth,
        mut tropic: T,
        mut store: S,
        provisioning: Provisioning,
    ) -> Result<Self, ProvisionRefused<T, S>> {
        let refused = |error, tropic, store| ProvisionRefused {
            error,
            tropic,
            store,
        };
        match store.read() {
            Ok(None) => {}
            Ok(Some(_)) => return Err(refused(DurableError::AlreadyProvisioned, tropic, store)),
            Err(e) => return Err(refused(DurableError::Store(e), tropic, store)),
        }
        let run = crate::try_run::rehearse::<T, P, S>(chip, &mut tropic, &mut store, &provisioning);
        if let Some(failed) = run.blocking(chip.install) {
            let why = alloc::format!("{}: {:?}", failed.name, failed.outcome);
            return Err(refused(DurableError::TryRun(why), tropic, store));
        }
        Self::born(chip, tropic, store, provisioning)
    }

    /// The birth ceremony and the first record written, before the appliance serves anything: what
    /// a provisioning does once it may, and what a try-run goes through.
    pub(crate) fn born(
        chip: &ChipBirth,
        tropic: T,
        mut store: S,
        provisioning: Provisioning,
    ) -> Result<Self, ProvisionRefused<T, S>> {
        let refused = |error, tropic, store| ProvisionRefused {
            error,
            tropic,
            store,
        };
        let birth = match chip.birth::<P>(&provisioning) {
            Ok(birth) => birth,
            Err(e) => {
                return Err(refused(
                    DurableError::Appliance(ApplianceError::Partition(e)),
                    tropic,
                    store,
                ))
            }
        };
        // The first record is written before the appliance exists, so a write the store does not
        // take leaves the chip and the store with the caller, the anchor unprovisioned.
        let written = encode_anchor(&provisioning, &Active::genesis(birth.genesis_frontier));
        if let Err(e) = store.write(&written) {
            return Err(refused(DurableError::Store(e), tropic, store));
        }
        let app = Appliance::new(
            tropic,
            chip.enrolled_counter,
            chip.anchor_id,
            chip.partition_device_id,
            birth,
            chip.install,
        );
        Ok(Self {
            app,
            provisioning,
            store,
            written,
        })
    }

    /// The anchor as its store left it: born again from the chip's identity and the provisioning
    /// its record holds, with its active state the record's. Nothing is decided here; boot
    /// recovery ([`Self::recover_at_boot`]) decides whether it serves.
    pub fn restore(chip: &ChipBirth, tropic: T, mut store: S) -> Result<Self, DurableError> {
        let written = store
            .read()
            .map_err(DurableError::Store)?
            .ok_or(DurableError::NotProvisioned)?;
        let (provisioning, active) = decode_anchor(&written).map_err(DurableError::Record)?;
        let mut app = Appliance::new(
            tropic,
            chip.enrolled_counter,
            chip.anchor_id,
            chip.partition_device_id,
            chip.birth::<P>(&provisioning)
                .map_err(ApplianceError::Partition)?,
            chip.install,
        );
        app.active = active;
        Ok(Self {
            app,
            provisioning,
            store,
            written,
        })
    }

    /// What the anchor was provisioned for.
    pub fn provisioning(&self) -> &Provisioning {
        &self.provisioning
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
        let record = encode_anchor(&self.provisioning, &self.app.active);
        if record == self.written {
            return Ok(());
        }
        match self.store.write(&record) {
            Ok(()) => {
                self.written = record;
                Ok(())
            }
            Err(e) => {
                self.app.active = self.written_active()?;
                Err(DurableError::Store(e))
            }
        }
    }

    /// Undo in memory whatever an operation changed before it failed: the appliance is what the
    /// store holds.
    fn back_to_written(&mut self, e: ApplianceError) -> DurableError {
        match self.written_active() {
            Ok(active) => {
                self.app.active = active;
                DurableError::Appliance(e)
            }
            Err(record) => record,
        }
    }

    /// The active state the store holds.
    fn written_active(&self) -> Result<Active, DurableError> {
        decode_anchor(&self.written)
            .map(|(_, active)| active)
            .map_err(DurableError::Record)
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
    /// own across the reboot, its counter unchanged, is cancelled durably, then recovery must accept.
    pub fn recover_at_boot(&mut self) -> Result<(), DurableBootRefusal> {
        match self.recover() {
            RecoverOutcome::Accept(_) | RecoverOutcome::ReemitCommitted(_) => Ok(()),
            RecoverOutcome::AcceptPreparedCanComplete | RecoverOutcome::OnlineCancelOrResolve => {
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

    /// Close the chip to a second birth ([`Appliance::close_birth`]).
    pub fn close_birth(&mut self) -> Result<(), ApplianceError> {
        self.app.close_birth()
    }

    /// The live counter `u = H₀ − H` from the chip.
    pub fn live_index(&mut self) -> Result<u64, ApplianceError> {
        self.app.live_index()
    }
}
