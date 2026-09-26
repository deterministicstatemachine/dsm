// SPDX-License-Identifier: Apache-2.0

//! Part II §17.4 and stage 7 of §31, rebuild step R9: install a fulfillment at
//! its position — the two position cells, written together.
//!
//! The writer puts the signed envelope of `F` at `K_ful(q)` and
//! `C_q = SofiResolutionClaim(G, DevID, q, FulfillmentId, R_realize, R_void)`
//! at `K_root(q)`: both in one transaction at the leader of `s(q)`, then the
//! same bytes at each later seat of the route (storage spec §9). `C_q` is
//! computed from the verified `P` and `F` and never caller-supplied, so no
//! claim that disagrees with `F` can be `F`'s claim. A member stores bytes;
//! it establishes nothing. Whether `F` registered is Core's conclusion from
//! the cells' route chains (`FulfillmentRegistered`, rebuild step R10), read
//! by the verifier (`dsm::sofi::resolve::Verifier::read_registration`), never
//! a fact this module produces.
//!
//! Before anything is written the producer obtains
//! `FulfillmentConformance(F) = Valid` over evidence the verifier acquired
//! from storage (Section 20.2: "A producer MUST obtain Valid before it
//! publishes F"). Rule T5: while evidence is not in hand nothing is written
//! and what is missing is named; on `Invalid` the fulfillment is refused with
//! its reason.

use std::collections::BTreeMap;

use dsm::sofi::conformance::{
    fulfillment_conformance, ConformanceMissing, FulfillmentConformance,
    FulfillmentConformanceError,
};
use dsm::sofi::derive;
use dsm::sofi::publication::Publication;
use dsm::sofi::registration::PositionCells;
use dsm::sofi::resolve::{Acquired, ExerciseObjects, SofiReads, Verifier};
use dsm::sofi::wire::{
    SettlementPreimage, SofiWireError, TraderFulfillmentBody, TraderPrecommitBody, ValidationRef,
};
use dsm::types::error::DsmError;

use crate::sdk::route_seats::{write_recorded_position, WriteReport};
use crate::sdk::storage_set::StorageSet;

type D32 = [u8; 32];

fn storage_err(what: &str, e: impl core::fmt::Display) -> DsmError {
    DsmError::storage(format!("{what}: {e}"), None::<std::io::Error>)
}

/// Everything an install takes: the exercise the trader signed, the `P` it
/// names, `P(E)`, and the exact bytes the trader holds for the closure
/// references that are its own.
#[derive(Debug, Clone, Copy)]
pub struct InstallRequest<'a> {
    pub precommit: &'a TraderPrecommitBody,
    pub precommit_signature: &'a [u8],
    pub preimage: &'a SettlementPreimage,
    pub fulfillment: &'a TraderFulfillmentBody,
    pub fulfillment_signature: &'a [u8],
    /// Bytes the trader holds for the closure references only it can supply
    /// exactly: the registered claim envelope a `SingleRootClaim` names, the
    /// final claim bytes at `K_root(p)` a `ConditionalClaim` names. Core
    /// re-derives every reference from the bytes; nothing here is trusted.
    pub own_objects: &'a BTreeMap<ValidationRef, Vec<u8>>,
}

impl<'a> InstallRequest<'a> {
    /// The objects the verifier decides conformance over.
    pub fn objects(&self) -> ExerciseObjects<'a> {
        ExerciseObjects {
            precommit: self.precommit,
            precommit_signature: self.precommit_signature,
            preimage: self.preimage,
            fulfillment: self.fulfillment,
            fulfillment_signature: self.fulfillment_signature,
            own_objects: self.own_objects,
        }
    }
}

/// Why nothing was installed, or the install stopped before the leader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallError {
    /// The objects do not have canonical bytes in this shape.
    Wire(SofiWireError),
    /// `FulfillmentConformance(F)` is Invalid, for this reason. Nothing is
    /// written: an installed non-conforming `F` would occupy the position
    /// with an exercise nothing realizes.
    NotConforming(FulfillmentConformanceError),
    /// Rule T5: after the retry budget, evidence conformance needs is still
    /// not in hand. Nothing is written; what is missing is named.
    Unavailable(Vec<ConformanceMissing>),
    /// The members could not be read or written, or the cells could not be
    /// derived over the set.
    Storage(String),
    /// The leader of `s(q)` did not answer with the pair's links. The write
    /// is recorded and resumes at the leader; no other seat stands in.
    LeaderUnreached,
}

impl From<SofiWireError> for InstallError {
    fn from(e: SofiWireError) -> Self {
        Self::Wire(e)
    }
}

impl From<DsmError> for InstallError {
    fn from(e: DsmError) -> Self {
        Self::Storage(e.to_string())
    }
}

/// The two cells of trader `(genesis, device_id)`'s position `position`,
/// routed by `s(q)` from `parent_root` over `set`, which must be the
/// register's committed set.
pub fn position_cells(
    set: &StorageSet,
    genesis: &D32,
    device_id: &D32,
    position: u64,
    parent_root: &D32,
) -> Result<PositionCells, DsmError> {
    let members = crate::sdk::storage_set::as_ccb_members(set)?;
    PositionCells::new(
        genesis,
        device_id,
        position,
        parent_root,
        &members,
        &set.id(),
    )
    .map_err(|e| storage_err("position cells", format!("{e:?}")))
}

/// The cells a fulfillment of `precommit` installs at: position `F.q`, routed
/// by the root the operation was built on — `P.void_root = T°.pre_root`.
pub fn cells_of(
    set: &StorageSet,
    precommit: &TraderPrecommitBody,
    fulfillment: &TraderFulfillmentBody,
) -> Result<PositionCells, DsmError> {
    position_cells(
        set,
        precommit.genesis(),
        precommit.device_id(),
        fulfillment.position(),
        precommit.void_root(),
    )
}

/// What the install wrote: the pair's cells, and what the write produced at
/// each route position — `K_ful(q)` first, then `K_root(q)`. Registration is
/// not among these: the verifier reads it from the cells.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub cells: PositionCells,
    pub reports: [WriteReport; 2],
}

/// Install `F` at its position: conformance first — over evidence the
/// verifier acquires and decides — then the pair at the leader of `s(q)`
/// and the same bytes at each later seat, continuing an earlier install of
/// the same pair.
pub async fn install_fulfillment<R: SofiReads>(
    verifier: &Verifier<'_, R>,
    set: &StorageSet,
    request: &InstallRequest<'_>,
) -> Result<Installed, InstallError> {
    let objects = request.objects();
    let evidence = match verifier
        .acquire_conformance_evidence(&objects)
        .map_err(|e| InstallError::Storage(e.to_string()))?
    {
        Acquired::Complete(evidence) => evidence,
        Acquired::Exhausted(missing) | Acquired::NoSource(missing) => {
            return Err(InstallError::Unavailable(missing))
        }
    };
    match fulfillment_conformance(
        request.fulfillment,
        request.fulfillment_signature,
        &evidence,
    ) {
        Ok(FulfillmentConformance::Valid) => {}
        Ok(FulfillmentConformance::Invalid(why)) => return Err(InstallError::NotConforming(why)),
        Err(what) => return Err(InstallError::Unavailable(vec![what])),
    }
    let cells = cells_of(set, request.precommit, request.fulfillment)?;
    let fulfillment_bytes = Publication::Fulfillment {
        body: request.fulfillment,
        signature: request.fulfillment_signature,
    }
    .object_bytes()?;
    let claim_bytes = derive::resolution_claim(request.precommit, request.fulfillment).encode();
    let reports = write_recorded_position(set, &cells, &fulfillment_bytes, &claim_bytes).await?;
    let [ful, root] = &reports;
    if !(ful.reached_leader() && root.reached_leader()) {
        return Err(InstallError::LeaderUnreached);
    }
    Ok(Installed { cells, reports })
}
