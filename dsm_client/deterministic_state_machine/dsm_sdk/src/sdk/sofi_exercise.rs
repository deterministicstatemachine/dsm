// SPDX-License-Identifier: Apache-2.0

//! Section 17.5 and stage 8 of §31, rebuild step R11: the exercise, written
//! to every successor key of a route and read back as the ladder reads it.
//!
//! After `F` registers, any party MAY write the exercise (P2): the object
//! carries `F`, which only the trader could sign, and everything else in it
//! is bound to `F` by hashed preimages, so a relayer adds nothing and can
//! forge nothing. Each leg's cell is `K^(a_j)` of vault `v_j` at parent
//! `R_j` ([`AttemptCell`]), routed by the vault's storage seed over the
//! network's pinned set and written along that route, leader first (storage
//! spec §9); the member stores bytes and decides nothing. What counts at a
//! key is Core's (`sofi::exercise::exercise_names_key`): the first exercise
//! at the leader whose `F` names `(v, a)` and whose `P` names `(v, R_n)`.

use dsm::route_chain::{CellFact, CellReading};
use dsm::sofi::conformance::{derive_policy_fulfillments, ConformanceEvidence};
use dsm::sofi::derive;
use dsm::sofi::exercise::{attempt_completion, attempt_resolution, AttemptCell, RecognizedExercise};
use dsm::sofi::publication::Publication;
use dsm::sofi::wire::{DlvPolicyFulfillmentBody, SofiExercise};
use dsm::types::error::DsmError;

use crate::sdk::route_seats::{read_cell, write_recorded, NodeSeats};
use crate::sdk::sofi_register::InstallRequest;
use crate::sdk::storage_set::StorageSet;

type D32 = [u8; 32];

fn err(what: &str, e: impl core::fmt::Display) -> DsmError {
    DsmError::verification(format!("{what}: {e}"))
}

/// The exercise of a request, over the evidence its conformance was decided
/// on: `F` and `P` in their envelopes, `P(E)`, the canonical witnesses
/// derived from `P` and the shadows `P(E)` commits, and every closure object
/// in reference order. A closure object the evidence does not hold is an
/// error here — the exercise carries the closure, so it cannot be built
/// without it.
pub fn build_exercise(
    request: &InstallRequest<'_>,
    evidence: &ConformanceEvidence,
) -> Result<SofiExercise, DsmError> {
    let canonical =
        derive::canonical_legs(request.preimage).map_err(|e| err("canonical legs", e))?;
    let shadows: Vec<D32> = request
        .precommit
        .legs()
        .iter()
        .map(|leg| {
            canonical
                .iter()
                .find(|l| l.vault_id == leg.vault_id)
                .map(|l| l.shadow_core)
                .ok_or_else(|| err("witnesses", "a leg P(E) does not derive"))
        })
        .collect::<Result<_, _>>()?;
    let witnesses: Vec<Vec<u8>> = derive_policy_fulfillments(request.precommit, &shadows)
        .map_err(|e| err("witnesses", format!("{e:?}")))?
        .iter()
        .map(DlvPolicyFulfillmentBody::encode)
        .collect();
    let mut closure = Vec::new();
    for reference in request.preimage.settlement().closure().refs() {
        let bytes = evidence
            .closure
            .get(reference)
            .ok_or_else(|| err("closure", format!("object not acquired for {reference:?}")))?;
        closure.push(bytes.clone());
    }
    SofiExercise::new(
        Publication::Fulfillment {
            body: request.fulfillment,
            signature: request.fulfillment_signature,
        }
        .object_bytes()
        .map_err(|e| err("fulfillment envelope", e))?,
        Publication::Precommit {
            body: request.precommit,
            signature: request.precommit_signature,
        }
        .object_bytes()
        .map_err(|e| err("precommit envelope", e))?,
        request.preimage.encode().map_err(|e| err("preimage", e))?,
        witnesses,
        closure,
    )
    .map_err(|e| err("exercise", e))
}

/// One leg's cell write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegWrite {
    pub vault_id: D32,
    pub parent_root: D32,
    pub attempt: u64,
    pub key: D32,
    /// The leader returned its record: the write got past position 0.
    pub reached_leader: bool,
}

/// `K^(attempt)` of `vault_id` at `parent_root`, routed over `set`: the
/// network's pinned set, as `storage_set::canonical_set` resolved and
/// checked it.
pub(crate) fn attempt_cell(
    set: &StorageSet,
    vault_id: &D32,
    parent_root: &D32,
    attempt: u64,
) -> Result<AttemptCell, DsmError> {
    let members = crate::sdk::storage_set::as_ccb_members(set)?;
    AttemptCell::new(vault_id, parent_root, attempt, &members, &set.id())
        .map_err(|e| err("attempt cell", format!("{e:?}")))
}

/// Write `exercise` to every successor key its `F` names — `K^(a_j)` of
/// `v_j` at the parent `R_j` its `P` names — along each cell's route,
/// continuing an earlier write of the same bytes. The bytes are the same at
/// every seat.
pub async fn write_exercise(
    set: &StorageSet,
    exercise: &SofiExercise,
    recognized: &RecognizedExercise,
) -> Result<Vec<LegWrite>, DsmError> {
    let bytes = exercise.encode();
    let mut writes = Vec::new();
    for attempt in recognized.fulfillment.body.attempts() {
        let leg = recognized
            .precommit
            .body
            .legs()
            .iter()
            .find(|l| l.vault_id == attempt.vault_id)
            .ok_or_else(|| err("exercise", "an attempt names a vault P has no leg for"))?;
        let cell = attempt_cell(set, &leg.vault_id, &leg.parent_root, attempt.attempt)?;
        let write = write_recorded(set, cell.routed(), &bytes).await?;
        writes.push(LegWrite {
            vault_id: leg.vault_id,
            parent_root: leg.parent_root,
            attempt: attempt.attempt,
            key: *cell.routed().key(),
            reached_leader: write.reached_leader(),
        });
    }
    Ok(writes)
}

/// What the ladder reads at one attempt key (Section 23.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptRead {
    /// The storage fact: open, or which exercise (by its `E`) holds the
    /// cell and how far its chain has gone.
    pub fact: CellFact,
    /// The exercise holding the cell, if any.
    pub exercise: Option<RecognizedExercise>,
}

/// `SuccessorResolution(K^(attempt))` of `vault_id` at `parent_root`, as the
/// ladder reads it (Section 23.1): Core evaluates the cell's route chains
/// from every seat's reads. An exercise final at the cell has its completion
/// proof kept (storage spec §9 rule 11). Reads that do not decide the cell
/// yet — its leader unread, or its leader link not yet committed — are the
/// inner `Err`, what Core names as missing: a network status for the caller
/// to retry, never an open cell.
pub async fn read_attempt_cell(
    set: &StorageSet,
    vault_id: &D32,
    parent_root: &D32,
    attempt: u64,
) -> Result<Result<AttemptRead, dsm::route_chain::Missing>, DsmError> {
    let cell = attempt_cell(set, vault_id, parent_root, attempt)?;
    let seats = NodeSeats::new(set)?;
    let evidence = read_cell(&seats, cell.routed()).await;
    let reading = match attempt_resolution(&cell, &evidence) {
        Ok(reading) => reading,
        Err(missing) => return Ok(Err(missing)),
    };
    let fact = reading.fact();
    let exercise = match reading {
        CellReading::Held { object, .. } => Some(object),
        CellReading::Open => None,
    };
    if let CellFact::Held {
        state: dsm::route_chain::ChainState::Final,
        ..
    } = fact
    {
        keep_attempt_completion(&cell, &evidence)?;
    }
    Ok(Ok(AttemptRead { fact, exercise }))
}

/// Keep the completion proof of the exercise final at `cell`.
fn keep_attempt_completion(
    cell: &AttemptCell,
    evidence: &dsm::route_chain::CellEvidence,
) -> Result<(), DsmError> {
    let (.., proof) = attempt_completion(cell, evidence)
        .map_err(|missing| err("attempt completion", format!("{missing:?}")))?
        .ok_or_else(|| {
            err(
                "attempt completion",
                "a final exercise has no completion proof",
            )
        })?;
    crate::sdk::route_seats::keep_completion(cell.routed(), &proof)
}
