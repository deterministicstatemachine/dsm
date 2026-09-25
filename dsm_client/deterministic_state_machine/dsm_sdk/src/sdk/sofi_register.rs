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
//! the cells' route chains (`FulfillmentRegistered`, rebuild step R10), never
//! a fact this module produces.
//!
//! Before anything is written the producer obtains
//! `FulfillmentConformance(F) = Valid` over evidence it acquired from storage
//! (Section 20.2: "A producer MUST obtain Valid before it publishes F"). Rule
//! T5: while evidence is not in hand nothing is written and what is missing
//! is named; on `Invalid` the fulfillment is refused with its reason.

use std::collections::BTreeMap;

use dsm::economic::register::root_completion;
use dsm::route_chain::{CellFact, Missing as CellMissing};
use dsm::sofi::conformance::{
    fulfillment_conformance, ConformanceEvidence, ConformanceMissing, FulfillmentConformance,
    FulfillmentConformanceError,
};
use dsm::sofi::derive;
use dsm::sofi::publication::{recognize_fulfillment, Publication, Signed};
use dsm::sofi::registration::{
    fulfillment_completion, fulfillment_registered, PositionCells, Registration,
};
use dsm::sofi::storage::Resolved;
use dsm::sofi::wire::{
    ParentClaimRef, SettlementPreimage, SofiWireError, TraderFulfillmentBody, TraderPrecommitBody,
    ValidationRef,
};
use dsm::types::error::DsmError;

use crate::sdk::route_seats::{
    keep_completion, read_cell, write_recorded_position, NodeSeats, WriteReport,
};
use crate::sdk::sofi_evidence::{Acquired, ACQUIRE_ROUNDS, LOCATOR_BUDGET};
use crate::sdk::sofi_exercise::read_attempt_cell;
use crate::sdk::sofi_publish::{fetch_fulfillment, fetch_precommit, fetch_setup_bytes};
use crate::sdk::storage_io::read_stored_bytes;
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
/// not among these: Core reads it from the cells ([`read_registration`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub cells: PositionCells,
    pub reports: [WriteReport; 2],
}

/// Cells read per leg when acquiring what an attempt skipped past. The same
/// bound the walk uses (`sofi_resolve::WALK_BUDGET`), for the same reason:
/// past it the earlier keys are unread, never assumed skipped.
pub const PRIOR_ATTEMPT_BUDGET: usize = crate::sdk::sofi_resolve::WALK_BUDGET;

/// The cells an attempt above zero skips past, read from the committed set:
/// for every leg the fulfillment names at attempt `a`, the storage fact at
/// `K^(0) … K^(a-1)` of that leg's vault at its parent root.
///
/// ONE PATH, SHARED (owner ruling, §44.4). The producer's install (R9) and
/// the verifier's resolution (R12) read the same cells the same way, because
/// they answer the same question: conformance item 5 requires the key before
/// this one to have a permanent storage resolution. A key whose reads do not
/// decide it yet, or past `budget`, is absent from the map, and conformance
/// names it missing. An attempt of zero has no earlier key and contributes no
/// entry.
pub async fn acquire_prior_attempts(
    set: &StorageSet,
    precommit: &TraderPrecommitBody,
    fulfillment: &TraderFulfillmentBody,
    budget: usize,
) -> Result<BTreeMap<(D32, u64), CellFact>, DsmError> {
    let reach = u64::try_from(budget).unwrap_or(u64::MAX);
    let mut cells = BTreeMap::new();
    for entry in fulfillment.attempts() {
        // F naming a leg P does not is conformance item 4's refusal; there is
        // no parent root to read a cell at.
        let Some(leg) = precommit
            .legs()
            .iter()
            .find(|l| l.vault_id == entry.vault_id)
        else {
            continue;
        };
        for earlier in 0..entry.attempt.min(reach) {
            match read_attempt_cell(set, &leg.vault_id, &leg.parent_root, earlier).await? {
                Ok(read) => {
                    cells.insert((entry.vault_id, earlier), read.fact);
                }
                Err(undecided) => {
                    log::info!("[sofi register] K^({earlier}) is not decided yet: {undecided:?}")
                }
            }
        }
    }
    Ok(cells)
}

/// One round of fetching what `FulfillmentConformance(F)` reads: `P` and
/// `P(E)` from the request, every leg's setup under its `ρ` (R8), the
/// closure objects by the rule of each reference kind, and item 5's earlier
/// attempt cells from [`acquire_prior_attempts`].
async fn gather_conformance(
    set: &StorageSet,
    request: &InstallRequest<'_>,
) -> Result<ConformanceEvidence, DsmError> {
    let mut setups = BTreeMap::new();
    for leg in request.precommit.legs() {
        if let Resolved::Kept(bytes) = fetch_setup_bytes(set, &leg.setup_ref).await? {
            setups.insert(leg.setup_ref, bytes);
        }
    }
    let mut closure = BTreeMap::new();
    for reference in request.preimage.settlement().closure().refs() {
        let bytes = match reference {
            ValidationRef::ContentAddr { addr, .. } => read_stored_bytes(set, addr).await?,
            ValidationRef::Setup { setup_ref } => match fetch_setup_bytes(set, setup_ref).await? {
                Resolved::Kept(bytes) => Some(bytes),
                Resolved::None | Resolved::Unavailable => None,
            },
            ValidationRef::SingleRootClaim { .. } | ValidationRef::ConditionalClaim { .. } => {
                request.own_objects.get(reference).cloned()
            }
        };
        if let Some(bytes) = bytes {
            closure.insert(*reference, bytes);
        }
    }
    // Item 1 for a conditional parent: the F whose id P names, by that id.
    // Its id is the hash of its body, so the kept bytes are that F.
    let parent_fulfillment = match request.precommit.parent_claim_ref() {
        ParentClaimRef::Conditional { fulfillment_id } => {
            match fetch_fulfillment(set, fulfillment_id).await? {
                Resolved::Kept(signed) => Some(signed.body),
                Resolved::None | Resolved::Unavailable => None,
            }
        }
        ParentClaimRef::SingleRoot { .. } => None,
    };
    Ok(ConformanceEvidence {
        precommit: Signed {
            body: request.precommit.clone(),
            signature: request.precommit_signature.to_vec(),
        },
        preimage: request.preimage.clone(),
        closure,
        setups,
        prior_attempts: acquire_prior_attempts(
            set,
            request.precommit,
            request.fulfillment,
            PRIOR_ATTEMPT_BUDGET,
        )
        .await?,
        parent_fulfillment,
    })
}

/// Acquire what `FulfillmentConformance(F)` reads, and ask Core whether it is
/// complete: `Complete` once conformance reaches a verdict over it,
/// `Exhausted` naming what Core still misses after the retry budget
/// (Amendment S3).
pub async fn acquire_conformance_evidence(
    set: &StorageSet,
    request: &InstallRequest<'_>,
) -> Result<Acquired<ConformanceEvidence, ConformanceMissing>, DsmError> {
    let mut missing = Vec::new();
    for round in 1..=ACQUIRE_ROUNDS {
        let evidence = gather_conformance(set, request).await?;
        match fulfillment_conformance(
            request.fulfillment,
            request.fulfillment_signature,
            &evidence,
        ) {
            Ok(FulfillmentConformance::Valid | FulfillmentConformance::Invalid(..)) => {
                return Ok(Acquired::Complete(evidence))
            }
            Err(what) => {
                log::info!("[sofi register] round {round}/{ACQUIRE_ROUNDS}: not in hand: {what:?}");
                missing = vec![what];
            }
        }
    }
    Ok(Acquired::Exhausted(missing))
}

/// Install `F` at its position: conformance first, then the pair at the
/// leader of `s(q)` and the same bytes at each later seat, continuing an
/// earlier install of the same pair.
pub async fn install_fulfillment(
    set: &StorageSet,
    request: &InstallRequest<'_>,
) -> Result<Installed, InstallError> {
    let evidence = match acquire_conformance_evidence(set, request).await? {
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

/// `FulfillmentRegistered` at position `q` of trader `(G, DevID)`, derived by
/// Core from the route-chain reads of the two cells (Part II §13, rebuild
/// step R10). `parent_root` is `R_p`, the root the verifier validated itself,
/// from which `s(q)` and the route follow. No member computes or writes any
/// of this. Once registered, the completion proofs of both cells are kept
/// (SoFi Amendment S10).
///
/// Recognizing a value at `K_ful(q)` needs the `P` it names: every
/// fulfillment envelope any seat holds at the key names one, and those are
/// fetched by id (R8), at most [`LOCATOR_BUDGET`] of them. A `P` the fetch
/// could not decide leaves the cell undecided — the call fails, and a later
/// read can answer — so that no later value is read as the first recognized
/// one while an earlier one's `P` is merely not in hand. The inner `Err` is
/// what Core names as missing from the reads.
pub async fn read_registration(
    set: &StorageSet,
    genesis: &D32,
    device_id: &D32,
    position: u64,
    parent_root: &D32,
) -> Result<Result<Registration, CellMissing>, DsmError> {
    let cells = position_cells(set, genesis, device_id, position, parent_root)?;
    let seats = NodeSeats::new(set)?;
    let ful_evidence = read_cell(&seats, cells.fulfillment()).await;
    let root_evidence = read_cell(&seats, cells.root().routed()).await;

    let mut precommits: BTreeMap<D32, TraderPrecommitBody> = BTreeMap::new();
    let mut named: Vec<D32> = Vec::new();
    for value in crate::sdk::route_seats::carried_values(&ful_evidence) {
        if let Some((.., signed)) = recognize_fulfillment(&value) {
            let id = *signed.body.precommit_id();
            if !named.contains(&id) {
                named.push(id);
            }
        }
    }
    if named.len() > LOCATOR_BUDGET {
        return Err(storage_err(
            "fulfillment register",
            format!(
                "{} precommits are named at K_ful({position}), past the budget of {LOCATOR_BUDGET}",
                named.len()
            ),
        ));
    }
    for id in named {
        match fetch_precommit(set, &id).await? {
            Resolved::Kept(precommit) => {
                precommits.insert(id, precommit.body);
            }
            Resolved::None => {}
            Resolved::Unavailable => {
                return Err(storage_err(
                    "fulfillment register",
                    "a precommit a candidate names could not be fetched",
                ))
            }
        }
    }

    let registration =
        match fulfillment_registered(&cells, &ful_evidence, &root_evidence, &precommits) {
            Ok(registration) => registration,
            Err(missing) => return Ok(Err(missing)),
        };
    if let Registration::Registered(..) = &registration {
        let (.., ful_proof) = fulfillment_completion(&cells, &ful_evidence, &precommits)
            .map_err(|missing| storage_err("fulfillment completion", format!("{missing:?}")))?
            .ok_or_else(|| storage_err("fulfillment completion", "a final value has no proof"))?;
        keep_completion(cells.fulfillment(), &ful_proof)?;
        let (.., root_proof) = root_completion(cells.root(), &root_evidence)
            .map_err(|missing| storage_err("root claim completion", format!("{missing:?}")))?
            .ok_or_else(|| storage_err("root claim completion", "a final value has no proof"))?;
        keep_completion(cells.root().routed(), &root_proof)?;
    }
    Ok(Ok(registration))
}
