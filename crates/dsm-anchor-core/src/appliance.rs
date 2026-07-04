//! The compact 3-state appliance (§21) plus the boot fence (§11) and power-loss
//! recovery (§26–§28).
//!
//! `Active = (hᵢ, B, Aᵢ, J_b, uᵢ, status, record)` with `status ∈ {Ready,
//! Prepared, Committed}` and a `boot_valid` gate. Offline transfer is disabled
//! until a boot ticket advances the boot head from the DSM-committed boot head;
//! every transfer then advances all three fused lineages together:
//! `(hᵢ, Aᵢ, J_b, uᵢ) → (hᵢ₊₁, Aᵢ₊₁, J_{b'}, uᵢ+1)`. The flow is: boot →
//! prepare (one transfer-slot MACANDD, full cross-bound Cert, no export, no
//! counter move) → commit (durable candidate → move counter → erase `sk_hw`) →
//! emit (export after commit) → finalize (advance the active fused state).

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::boot::{
    advance_ratchet, boot_cert_message, boot_fuse_input, next_boot_head, BootTicket,
};
use crate::enrollment::{commit, Birth};
use crate::proto::MAX_BOOT_CHAIN;
use crate::root_advance::{
    next_anchor_head, partition_commit, partition_final_cert_message, pk_hash,
    root_advance_message, transfer_witness_key, transition_digest, tropic_transfer_input,
    tropic_witness_message, Certificate, CounterEvidence, OfflineRelease, OwnedTransition,
    Transition,
};
use crate::tropic::{PartitionSig, Tropic, TropicError, WitnessSig};
use crate::util::{ct_eq_32, zeroize, zeroize_vec};

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
    /// Offline mode not enabled — no valid boot ticket this power cycle (§11).
    NotBooted,
    /// Requested previous root is not the active root.
    PrevRootMismatch,
    /// Requested previous fused anchor head is not the active head.
    AnchorHeadMismatch,
    /// `next_anchor_counter != anchor_counter + 1`, or `anchor_counter != active.u`.
    IndexMismatch,
    /// `active.u != H₀ − H` — the appliance is not offline-ready.
    CounterMismatch,
    /// The prepared record's witness key was lost (power-loss write race).
    WitnessKeyLost,
    /// `MCounter_Update` on an exhausted counter (`H == 0`) — online only.
    CounterExhausted,
    /// A committed release is not yet present to emit/finalize.
    NotCommitted,
    /// The producer boot chain reached `MAX_BOOT_CHAIN` (no more boots this power
    /// cycle until a finalize resets it) — mirrors the receiver's decode cap.
    BootChainFull,
    Tropic(TropicError),
}

/// Prepared record (§21.2): the fully formed cross-bound certificate + the boot
/// chain snapshot, retained with `sk_hw` (liveness gate) until commit erases it.
pub struct PreparedRecord {
    pub txn: OwnedTransition,
    pub cert: Certificate,
    pub boot_chain: Vec<BootTicket>,
    /// SECRET witness signing key; erased at commit/cancel.
    pub sk_hw: Vec<u8>,
}

/// Committed record (§21.3): the signed release + the counter-committed flag.
pub struct CommittedRecord {
    pub prev_root: [u8; 32],
    pub next_root: [u8; 32],
    pub prev_anchor_head: [u8; 32],
    pub next_anchor_head: [u8; 32],
    pub current_boot_head: [u8; 32],
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

/// The single active fused state.
pub struct Active {
    pub root: [u8; 32],
    pub anchor_head: [u8; 32],
    /// Boot head committed by `root` (the DSM-committed boot head `J_b`).
    pub committed_boot_head: [u8; 32],
    /// Live boot head `J_{b'}` after this power cycle's boots.
    pub boot_head: [u8; 32],
    pub anchor_counter: u64,
    pub boot_valid: bool,
    pub status: Status,
    pub record: Record,
}

/// Recovery outcomes (§27).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecoverOutcome {
    Accept([u8; 32]),
    /// A committed successor (carried `hᵢ₊₁`) is pending: the record stays
    /// `Committed{committed:true}` so the caller re-emits with [`Appliance::emit`]
    /// and advances with [`Appliance::finalize`] — never signs a new one.
    ReemitCommitted([u8; 32]),
    DowngradeOnline,
    FailClosed,
    ExhaustedOnlineOnly,
    AcceptPreparedCanComplete,
    OnlineCancelOrResolve,
}

/// The boot-fenced fused offline-bearer appliance for one active root.
pub struct Appliance<T: Tropic, S: WitnessSig, P: PartitionSig> {
    pub h0: u32,
    pub anchor_id: [u8; 32],
    pub bundle: [u8; 32],
    pub q_boot: u16,
    pub q_tx: u16,
    pub partition_device_id: [u8; 32],
    /// PUBLIC partition verification key (safe to disclose). Part of the receiver pin material; the
    /// STATUS op returns it so a host client / disclosure can carry the full `AnchorPin`.
    pub partition_pk: Vec<u8>,
    pub active: Active,
    /// Set when recovery sees a firmware-boundary / R-memory-map event.
    pub firmware_boundary_invalid: bool,
    pub rmemory_map_invalid: bool,
    /// SECRET partition signing key (non-exportable on device).
    partition_sk: Vec<u8>,
    /// SECRET partition ratchet `p_i`.
    partition_ratchet: [u8; 32],
    /// Boot tickets accumulated since the committed boot head (the release chain).
    boot_chain: Vec<BootTicket>,
    tropic: T,
    _w: PhantomData<S>,
    _p: PhantomData<P>,
}

impl<T: Tropic, S: WitnessSig, P: PartitionSig> Appliance<T, S, P> {
    /// Construct from a [`Birth`] result. Starts at the genesis root, anchor
    /// counter 0, `boot_valid = false` (a boot ticket is required before offline).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tropic: T,
        h0: u32,
        anchor_id: [u8; 32],
        q_boot: u16,
        q_tx: u16,
        partition_device_id: [u8; 32],
        genesis_root: [u8; 32],
        birth: Birth,
    ) -> Self {
        Self {
            h0,
            anchor_id,
            bundle: birth.bundle,
            q_boot,
            q_tx,
            partition_device_id,
            partition_pk: birth.partition_pk.clone(),
            active: Active {
                root: genesis_root,
                anchor_head: birth.anchor_head,
                committed_boot_head: birth.boot_head,
                boot_head: birth.boot_head,
                anchor_counter: 0,
                boot_valid: false,
                status: Status::Ready,
                record: Record::Empty,
            },
            firmware_boundary_invalid: false,
            rmemory_map_invalid: false,
            partition_sk: birth.partition_sk,
            partition_ratchet: birth.partition_ratchet,
            boot_chain: Vec::new(),
            tropic,
            _w: PhantomData,
            _p: PhantomData,
        }
    }

    /// Mutable access to the underlying `Tropic` backend. For a firmware host that also serves a
    /// transparent raw-SPI relay (DSM Path-B counter read): the relayed transactions go straight to
    /// the chip via the backend, bypassing the appliance protocol entirely. Not used by the
    /// appliance's own operations.
    pub fn tropic_mut(&mut self) -> &mut T {
        &mut self.tropic
    }

    /// Live anchor counter `u = H₀ − H` from the chip. The counter only counts
    /// down, so `H ≤ H₀`; a reported `H > H₀` is impossible and is rejected.
    pub fn live_index(&mut self) -> Result<u64, ApplianceError> {
        let h = self.tropic.counter_get().map_err(ApplianceError::Tropic)?;
        let u = self
            .h0
            .checked_sub(h)
            .ok_or(ApplianceError::CounterMismatch)?;
        Ok(u as u64)
    }

    /// §11/§21.1 Boot: advance the boot head `J_b → J_{b+1}` via the boot MACANDD
    /// slot + partition ratchet, produce a partition-signed boot ticket, and
    /// enable offline mode. Returns the new live boot head.
    pub fn boot(
        &mut self,
        boot_seq: u64,
        firmware_measurement: &[u8; 32],
    ) -> Result<[u8; 32], ApplianceError> {
        // Boot only advances the fence between transfers; never mid-transfer (a
        // boot during Prepared/Committed would desync the forward-secure ratchet
        // from the boot head it is fused to).
        if self.active.status != Status::Ready {
            return Err(ApplianceError::WrongState);
        }
        // Fail closed at the same bound the receiver decodes, so the producer can
        // never build a boot chain the receiver must reject (and never unbounded-
        // grow the chain's 17 KiB-per-ticket heap footprint).
        if self.boot_chain.len() >= MAX_BOOT_CHAIN {
            return Err(ApplianceError::BootChainFull);
        }
        let prev_boot_head = self.active.boot_head;
        let x_boot = boot_fuse_input(
            &self.bundle,
            &self.active.anchor_head,
            &prev_boot_head,
            boot_seq,
            firmware_measurement,
            &self.partition_device_id,
        );
        let mut w_boot = self
            .tropic
            .mac_and_destroy(self.q_boot, &x_boot)
            .map_err(ApplianceError::Tropic)?;
        let p_next = advance_ratchet(
            &self.partition_ratchet,
            &w_boot,
            &self.bundle,
            &self.active.anchor_head,
            &prev_boot_head,
            boot_seq,
            firmware_measurement,
        );
        let j_next = next_boot_head(
            &self.bundle,
            &self.active.anchor_head,
            &prev_boot_head,
            boot_seq,
            &p_next,
            &w_boot,
            firmware_measurement,
        );
        let m_boot = boot_cert_message(
            &self.bundle,
            &self.active.anchor_head,
            &prev_boot_head,
            &j_next,
            boot_seq,
            firmware_measurement,
        );
        let sig_boot = P::part_sign(&self.partition_sk, &m_boot);

        self.boot_chain.push(BootTicket {
            anchor_bundle: self.bundle,
            anchor_head: self.active.anchor_head,
            prev_boot_head,
            next_boot_head: j_next,
            boot_seq,
            firmware_measurement: *firmware_measurement,
            partition_boot_signature: sig_boot,
            tropic_boot_input: x_boot,
            tropic_boot_witness: commit(&w_boot),
        });
        w_boot.iter_mut().for_each(|b| *b = 0); // the slot's MAC output is a secret
        self.partition_ratchet = p_next;
        self.active.boot_head = j_next;
        self.active.boot_valid = true;
        Ok(j_next)
    }

    /// §21.2 Prepare: one transfer-slot MACANDD witness; build the full
    /// cross-bound certificate (`C^P → X^T → σ^T → M^P → σ^P → A_{i+1}`); store a
    /// durable Prepared record. No counter move, no export. Refused unless Ready,
    /// booted, and offline-ready (`active.u = H₀ − H`).
    pub fn prepare(
        &mut self,
        t: &Transition,
        receiver_challenge: &[u8; 32],
    ) -> Result<(), ApplianceError> {
        if self.active.status != Status::Ready {
            return Err(ApplianceError::WrongState);
        }
        if !self.active.boot_valid {
            return Err(ApplianceError::NotBooted);
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
        // Read H once and reject an exhausted down-counter *before* spending the
        // one-time q_tx MACANDD witness — commit() guards this too, but prepare()
        // must not burn a single-use slot on a transfer that can never commit.
        let h = self.tropic.counter_get().map_err(ApplianceError::Tropic)?;
        if h == 0 {
            return Err(ApplianceError::CounterExhausted);
        }
        let live_u = self
            .h0
            .checked_sub(h)
            .ok_or(ApplianceError::CounterMismatch)? as u64;
        if self.active.anchor_counter != live_u {
            return Err(ApplianceError::CounterMismatch);
        }

        let a_i = self.active.anchor_head;
        let j_now = self.active.boot_head;
        let d = transition_digest(t);
        let m = root_advance_message(t, &d, &self.bundle, &a_i, &j_now, receiver_challenge);
        let c_p = partition_commit(&self.bundle, &a_i, &j_now, &m);
        let x_t = tropic_transfer_input(&self.bundle, &a_i, &j_now, &m, &c_p, self.q_tx);

        let mut w_t = self
            .tropic
            .mac_and_destroy(self.q_tx, &x_t)
            .map_err(ApplianceError::Tropic)?;
        let mut k_t = transfer_witness_key(
            &w_t,
            &x_t,
            &m,
            &self.bundle,
            &a_i,
            &j_now,
            &self.anchor_id,
            self.q_tx,
        );
        let (sk_hw, pk_hw) = S::keygen(&k_t);
        let p_hw = pk_hash(&pk_hw);
        let m_t = tropic_witness_message(&m, &c_p, &x_t, &p_hw);
        let sigma_tropic = S::sign(&sk_hw, &m_t);
        let m_p = partition_final_cert_message(
            &self.bundle,
            &a_i,
            &j_now,
            &m,
            &c_p,
            &p_hw,
            &sigma_tropic,
            t.next_anchor_counter,
        );
        let sigma_partition = P::part_sign(&self.partition_sk, &m_p);
        // = H₀ − (uᵢ+1); the h==0 guard + counter pin above keep this ≥ 0, the
        // checked_sub is the belt-and-suspenders the receiver also applies.
        let attested = (self.h0 as u64)
            .checked_sub(t.next_anchor_counter)
            .ok_or(ApplianceError::CounterExhausted)?;
        let a_next = next_anchor_head(
            &self.bundle,
            &a_i,
            &j_now,
            &m,
            &c_p,
            &sigma_partition,
            &p_hw,
            &sigma_tropic,
            attested,
        );

        w_t.iter_mut().for_each(|b| *b = 0);
        k_t.iter_mut().for_each(|b| *b = 0);

        let cert = Certificate {
            anchor_bundle: self.bundle,
            prev_anchor_head: a_i,
            next_anchor_head: a_next,
            prev_boot_head: self.active.committed_boot_head,
            current_boot_head: j_now,
            prev_root: *t.prev_root,
            next_root: *t.next_root,
            anchor_counter: t.anchor_counter,
            next_anchor_counter: t.next_anchor_counter,
            transition_digest: d,
            root_advance_message: m,
            partition_commitment: c_p,
            tropic_transfer_input: x_t,
            pk_hash: p_hw,
            pk_hw,
            sigma_tropic,
            sigma_partition,
            anchor_id: self.anchor_id,
            transfer_slot: self.q_tx,
            receiver_challenge: *receiver_challenge,
        };

        self.active.status = Status::Prepared;
        self.active.record = Record::Prepared(Box::new(PreparedRecord {
            txn: OwnedTransition::from(t),
            cert,
            boot_chain: self.boot_chain.clone(),
            sk_hw,
        }));
        Ok(())
    }

    /// §21.3 Commit, in three durable phases: persist the committed candidate
    /// (`committed=false`, erase `sk_hw`) → move the counter → mark committed.
    /// The release exists durably before the counter moves, so an interrupted
    /// commit is completable by [`recover`]. Nothing is exported before phase 2.
    pub fn commit(&mut self) -> Result<(), ApplianceError> {
        let p = match &self.active.record {
            Record::Prepared(p) => p,
            _ => return Err(ApplianceError::WrongState),
        };
        if p.sk_hw.is_empty() {
            return Err(ApplianceError::WitnessKeyLost);
        }
        if !ct_eq_32(&p.cert.prev_root, &self.active.root) {
            return Err(ApplianceError::PrevRootMismatch);
        }
        if !ct_eq_32(&p.cert.prev_anchor_head, &self.active.anchor_head) {
            return Err(ApplianceError::AnchorHeadMismatch);
        }

        // The counter must be movable AND still pinned to this transfer's counter.
        let h = self.tropic.counter_get().map_err(ApplianceError::Tropic)?;
        if h == 0 {
            return Err(ApplianceError::CounterExhausted);
        }
        let live_u = self
            .h0
            .checked_sub(h)
            .ok_or(ApplianceError::CounterMismatch)? as u64;
        if live_u != p.cert.anchor_counter {
            return Err(ApplianceError::CounterMismatch);
        }

        let release = OfflineRelease {
            transition: p.txn.clone(),
            boot_chain: p.boot_chain.clone(),
            cert: p.cert.clone(),
            counter: CounterEvidence {
                anchor_id: self.anchor_id,
                enrolled_counter: self.h0 as u64,
                live_counter_claim: (h - 1) as u64,
                derived_anchor_counter_claim: p.cert.next_anchor_counter,
                verifier_transcript: Vec::new(),
            },
        };
        let prev_root = p.cert.prev_root;
        let next_root = p.cert.next_root;
        let prev_anchor_head = p.cert.prev_anchor_head;
        let next_anchor_head = p.cert.next_anchor_head;
        let current_boot_head = p.cert.current_boot_head;
        let anchor_counter = p.cert.anchor_counter;
        let next_anchor_counter = p.cert.next_anchor_counter;

        // Phase 1: persist the committed candidate; erase the witness key.
        if let Record::Prepared(p) = &mut self.active.record {
            zeroize_vec(&mut p.sk_hw);
        }
        self.active.status = Status::Committed;
        self.active.record = Record::Committed(Box::new(CommittedRecord {
            prev_root,
            next_root,
            prev_anchor_head,
            next_anchor_head,
            current_boot_head,
            anchor_counter,
            next_anchor_counter,
            release,
            committed: false,
        }));

        // Phase 2: move the counter. On failure nothing is exported; recovery
        // completes the durable candidate (committed=false, counter not moved).
        self.tropic
            .counter_update()
            .map_err(|_| ApplianceError::CounterExhausted)?;

        // Phase 3: mark counter-committed; the counter now reflects the moved value.
        if let Record::Committed(c) = &mut self.active.record {
            c.committed = true;
        }
        self.active.anchor_counter = next_anchor_counter;
        Ok(())
    }

    /// §21.5 Emit: export the committed release. The receiver attaches its own
    /// counter evidence and verifies.
    pub fn emit(&self) -> Result<&OfflineRelease, ApplianceError> {
        match &self.active.record {
            Record::Committed(c) if c.committed => Ok(&c.release),
            _ => Err(ApplianceError::NotCommitted),
        }
    }

    /// §21.6 Finalize: advance the active fused state to
    /// `(hᵢ₊₁, Aᵢ₊₁, J_{b'}, uᵢ+1)`, guarded by `Active.u = H₀ − H`. The new root
    /// commits the current boot head, so the boot chain resets.
    pub fn finalize(&mut self) -> Result<[u8; 32], ApplianceError> {
        let (next_root, next_anchor_head, current_boot_head, next_anchor_counter) =
            match &self.active.record {
                Record::Committed(c) if c.committed => (
                    c.next_root,
                    c.next_anchor_head,
                    c.current_boot_head,
                    c.next_anchor_counter,
                ),
                _ => return Err(ApplianceError::NotCommitted),
            };
        let live_u = self.live_index()?;
        if self.active.anchor_counter != live_u {
            return Err(ApplianceError::CounterMismatch);
        }
        self.active = Active {
            root: next_root,
            anchor_head: next_anchor_head,
            committed_boot_head: current_boot_head,
            boot_head: current_boot_head,
            anchor_counter: next_anchor_counter,
            boot_valid: true, // current boot head is now the committed one
            status: Status::Ready,
            record: Record::Empty,
        };
        self.boot_chain.clear();
        Ok(next_root)
    }

    /// Cancel a prepared (not yet committed) record, erasing its witness key.
    pub fn cancel(&mut self) -> Result<(), ApplianceError> {
        match &mut self.active.record {
            Record::Prepared(p) => {
                zeroize_vec(&mut p.sk_hw);
                self.active.status = Status::Ready;
                self.active.record = Record::Empty;
                Ok(())
            }
            _ => Err(ApplianceError::WrongState),
        }
    }

    /// §27–§28 power-loss recovery. Never signs a new successor — a committed
    /// record is re-emitted and finalized as the *same* successor. The boot fence
    /// gates recovery: offline recovery requires a valid boot ticket this cycle.
    pub fn recover(&mut self) -> RecoverOutcome {
        if self.firmware_boundary_invalid || self.rmemory_map_invalid {
            return RecoverOutcome::DowngradeOnline;
        }
        let live_u = match self.live_index() {
            Ok(u) => u,
            Err(_) => return RecoverOutcome::DowngradeOnline,
        };
        if !self.active.boot_valid {
            return RecoverOutcome::DowngradeOnline;
        }

        match self.active.status {
            Status::Committed => {
                let (committed, rec_u, next_root, prev_root, prev_anchor_head) =
                    match &self.active.record {
                        Record::Committed(c) => (
                            c.committed,
                            c.next_anchor_counter,
                            c.next_root,
                            c.prev_root,
                            c.prev_anchor_head,
                        ),
                        _ => return RecoverOutcome::DowngradeOnline,
                    };
                if committed {
                    if rec_u != live_u {
                        return RecoverOutcome::DowngradeOnline;
                    }
                    self.active.anchor_counter = rec_u;
                    RecoverOutcome::ReemitCommitted(next_root)
                } else if rec_u == live_u {
                    // Counter moved but the committed flag was not persisted.
                    if let Record::Committed(c) = &mut self.active.record {
                        c.committed = true;
                    }
                    self.active.anchor_counter = rec_u;
                    RecoverOutcome::ReemitCommitted(next_root)
                } else if rec_u == live_u + 1 {
                    // Durable release, counter not yet moved: complete only if the
                    // previous root + fused anchor head still match the active state.
                    if !ct_eq_32(&prev_root, &self.active.root)
                        || !ct_eq_32(&prev_anchor_head, &self.active.anchor_head)
                    {
                        return RecoverOutcome::DowngradeOnline;
                    }
                    if self.tropic.counter_update().is_err() {
                        return RecoverOutcome::DowngradeOnline;
                    }
                    if let Record::Committed(c) = &mut self.active.record {
                        c.committed = true;
                    }
                    self.active.anchor_counter = rec_u;
                    RecoverOutcome::ReemitCommitted(next_root)
                } else {
                    RecoverOutcome::DowngradeOnline
                }
            }
            Status::Prepared => {
                if self.active.anchor_counter != live_u {
                    return RecoverOutcome::DowngradeOnline;
                }
                let (root_ok, key_present, partition_present) = match &self.active.record {
                    Record::Prepared(p) => (
                        ct_eq_32(&p.cert.prev_root, &self.active.root)
                            && ct_eq_32(&p.cert.prev_anchor_head, &self.active.anchor_head),
                        !p.sk_hw.is_empty(),
                        !p.cert.sigma_partition.is_empty(),
                    ),
                    _ => return RecoverOutcome::DowngradeOnline,
                };
                if !root_ok {
                    return RecoverOutcome::DowngradeOnline;
                }
                if key_present && partition_present {
                    RecoverOutcome::AcceptPreparedCanComplete
                } else {
                    RecoverOutcome::OnlineCancelOrResolve
                }
            }
            Status::Ready => {
                if self.active.anchor_counter < live_u {
                    return RecoverOutcome::DowngradeOnline;
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

/// Wipe the two highest-value, longest-lived secrets on teardown: `partition_sk`
/// (the partition root of trust — its disclosure forges boot tickets and final
/// certs) and `partition_ratchet` (the Thm 28 anti-clone secret). The crate
/// already wipes the per-transfer secrets (`sk_hw`, `w_t`, `k_t`, `w_boot`) and
/// `s_birth` inline; this closes the residual / cold-boot / refactor drop paths.
impl<T: Tropic, S: WitnessSig, P: PartitionSig> Drop for Appliance<T, S, P> {
    fn drop(&mut self) {
        zeroize_vec(&mut self.partition_sk);
        zeroize(&mut self.partition_ratchet);
    }
}

/// Wipe the witness signing key if a Prepared record is dropped on a path that did
/// not already erase it (panic-unwind, future refactor). The normal commit/cancel
/// paths zeroize `sk_hw` before this runs, leaving an empty buffer.
impl Drop for PreparedRecord {
    fn drop(&mut self) {
        zeroize_vec(&mut self.sk_hw);
    }
}
