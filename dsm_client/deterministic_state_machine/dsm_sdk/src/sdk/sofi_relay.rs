// SPDX-License-Identifier: Apache-2.0
//! Relaying (§33), and the line it must not cross.
//!
//! **Any device may carry immutable signed protocol objects to storage. Only
//! the owning device may touch its own admission, fence, lineage and leaf
//! cache** (owner ruling, §44.4). Those are two different operations and this
//! module is one of them: everything here takes a fulfillment id and a
//! committed set, holds no `CoreSDK`, reads no device head, and writes
//! nothing local but the progress of its own route writes. The owner-local
//! half — `complete_pending_fulfillment` and `resolve_pending_position` —
//! stays in `sofi_advance`.
//!
//! A relay creates nothing and decides nothing. `F` and `C_q` are signed by
//! the trader (SoFi Amendment S20), so a relayer carrying them adds no
//! authority of its own and can author neither; the exercise it carries is
//! the value Core reads as holding one of the fulfillment's leg cells,
//! relayed verbatim rather than rebuilt, because the trader's own closure
//! objects are not a relayer's to hold. The exercise carries the trader's
//! signed `C_q` too, so a fulfillment whose exercise holds a vault key can
//! always be registered from that exercise's bytes, whatever its trader
//! withholds. Every write goes along its cell's route from the
//! leader (storage spec §9). Nothing here re-gates on conformance: that gate
//! is the PRODUCER's discipline before it publishes, not a second opinion at
//! every carrier.
use dsm::economic::claim_envelope::RegisteredEconomicClaim;
use dsm::economic::register::read_root_cell;
use dsm::route_chain::CellReading;
use dsm::sofi::exercise::{attempt_resolution, AttemptCell, RecognizedExercise};
use dsm::sofi::publication::{Publication, Signed};
use dsm::sofi::storage::Resolved;
use dsm::sofi::wire::{TraderFulfillmentBody, TraderPrecommitBody};
use dsm::types::error::DsmError;

use crate::sdk::route_seats::{
    read_cell, write_recorded, write_recorded_position, NodeSeats, WriteReport,
};
use crate::sdk::sofi_exercise::{attempt_cell, LegWrite};
use crate::sdk::sofi_publish::{fetch_fulfillment, fetch_precommit};
use crate::sdk::sofi_register::cells_of;
use crate::sdk::storage_set::StorageSet;

type D32 = [u8; 32];

fn refuse(what: impl std::fmt::Display) -> DsmError {
    DsmError::invalid_operation(format!("sofi relay: {what}"))
}

/// What a relay carried. Nothing here is a claim about registration or
/// resolution: those are Core's, from the cells' route chains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relayed {
    pub fulfillment_id: D32,
    pub position: u64,
    /// What the pair's write produced at each route position of `s(q)`,
    /// `K_ful(q)` first, then `K_root(q)`.
    pub pair: [WriteReport; 2],
    /// Every leg key the exercise was carried to. Empty when no leg cell is
    /// held by this fulfillment's exercise: a relayer cannot build one.
    pub legs: Vec<LegWrite>,
}

/// The two objects a relay works from, fetched by content address alone.
async fn objects(
    set: &StorageSet,
    fulfillment_id: &D32,
) -> Result<(Signed<TraderFulfillmentBody>, Signed<TraderPrecommitBody>), DsmError> {
    let Resolved::Kept(fulfillment) = fetch_fulfillment(set, fulfillment_id).await? else {
        return Err(refuse(
            "the fulfillment is not Stored; there is nothing to relay",
        ));
    };
    let Resolved::Kept(precommit) = fetch_precommit(set, fulfillment.body.precommit_id()).await?
    else {
        return Err(refuse(
            "the fulfillment's P is not Stored; there is nothing to relay",
        ));
    };
    Ok((fulfillment, precommit))
}

/// The trader's signed `C_q` of a position pair, exactly as signed (SoFi
/// Amendment S20): the bytes `K_root(q)` holds when its claim is this
/// fulfillment's, and otherwise the bytes the fulfillment's exercise carries.
/// A relayer never authors it. `K_root(q)` held by another claim loses `F`
/// there, so there is no pair to carry.
async fn carry_pair(
    set: &StorageSet,
    fulfillment: &Signed<TraderFulfillmentBody>,
    precommit: &Signed<TraderPrecommitBody>,
    carried: Option<&[u8]>,
) -> Result<[WriteReport; 2], DsmError> {
    let cells = cells_of(set, &precommit.body, &fulfillment.body)?;
    let f_bytes = Publication::Fulfillment {
        body: &fulfillment.body,
        signature: &fulfillment.signature,
    }
    .object_bytes()
    .map_err(refuse)?;
    let derived = dsm::sofi::derive::resolution_claim(&precommit.body, &fulfillment.body);
    let seats = NodeSeats::new(set)?;
    let evidence = read_cell(&seats, cells.root().routed()).await;
    let claim = match read_root_cell(cells.root(), &evidence) {
        Ok(CellReading::Held {
            object: RegisteredEconomicClaim::ConditionalSofi(held),
            value,
            ..
        }) if held == derived => value,
        Ok(CellReading::Held { .. }) => {
            return Err(refuse(
                "K_root(q) holds another claim: the fulfillment is lost at its position, and \
                 there is no pair to carry",
            ))
        }
        Ok(CellReading::Open) => carried_claim(carried, "K_root(q) holds no claim yet")?,
        Err(missing) => carried_claim(
            carried,
            &format!("K_root(q) is not decided yet ({missing:?})"),
        )?,
    };
    write_recorded_position(set, &cells, &f_bytes, &claim).await
}

/// The signed `C_q` an exercise carries, or why there is none to carry.
fn carried_claim(carried: Option<&[u8]>, why: &str) -> Result<Vec<u8>, DsmError> {
    carried.map(<[u8]>::to_vec).ok_or_else(|| {
        refuse(format!(
            "{why}, and no exercise of this fulfillment is in hand to carry the trader's \
             signed C_q: only the trader can sign it"
        ))
    })
}

/// Every leg key a fulfillment names: `K^(a_j)` of `v_j` at the parent `R_j`
/// its `P` names.
fn leg_cells(
    set: &StorageSet,
    fulfillment: &Signed<TraderFulfillmentBody>,
    precommit: &Signed<TraderPrecommitBody>,
) -> Result<Vec<(D32, D32, u64, AttemptCell)>, DsmError> {
    let mut cells = Vec::new();
    for attempt in fulfillment.body.attempts() {
        let Some(leg) = precommit
            .body
            .legs()
            .iter()
            .find(|l| l.vault_id == attempt.vault_id)
        else {
            return Err(refuse("an attempt names a vault P has no leg for"));
        };
        cells.push((
            leg.vault_id,
            leg.parent_root,
            attempt.attempt,
            attempt_cell(set, &leg.vault_id, &leg.parent_root, attempt.attempt)?,
        ));
    }
    Ok(cells)
}

/// The exercise of `fulfillment` holding one of its leg keys, with the exact
/// bytes Core read as holding it. `None` when no leg key is held by this
/// fulfillment's exercise.
async fn held_exercise(
    set: &StorageSet,
    cells: &[(D32, D32, u64, AttemptCell)],
    fulfillment: &Signed<TraderFulfillmentBody>,
) -> Result<Option<(RecognizedExercise, Vec<u8>)>, DsmError> {
    let seats = NodeSeats::new(set)?;
    for (.., cell) in cells {
        let evidence = read_cell(&seats, cell.routed()).await;
        let read = match attempt_resolution(cell, &evidence) {
            Ok(read) => read,
            Err(undecided) => {
                log::info!("[sofi relay] a leg cell is not decided yet: {undecided:?}");
                continue;
            }
        };
        // The exact bytes Core read as holding the cell, when the exercise
        // they are is this fulfillment's.
        if let (Some(object), Some(value)) = (read.exercise(), read.value()) {
            if object.fulfillment().body == fulfillment.body {
                return Ok(Some((object.clone(), value.to_vec())));
            }
        }
    }
    Ok(None)
}

/// Carry the exercise `bytes` to every leg key its `F` names.
async fn carry_exercise(
    set: &StorageSet,
    cells: Vec<(D32, D32, u64, AttemptCell)>,
    bytes: &[u8],
) -> Result<Vec<LegWrite>, DsmError> {
    // The one exercise names every leg's key, so the same bytes belong at
    // each of them; Core counts only an exercise naming the key it sits at,
    // so carrying it where it names nothing would carry nothing. Every key
    // is checked before anything is carried.
    for (vault_id, parent_root, attempt, _) in &cells {
        if dsm::sofi::exercise::exercise_names_key(bytes, vault_id, parent_root, *attempt).is_none()
        {
            return Err(refuse(
                "the exercise found does not name every key its F does",
            ));
        }
    }
    // Each leg's key is its own vault's cell on its own route: the legs are
    // carried at once, as `write_exercise` writes them, and reported in the
    // order `F` names them.
    futures::future::try_join_all(cells.into_iter().map(
        |(vault_id, parent_root, attempt, cell)| async move {
            let write = write_recorded(set, cell.routed(), bytes).await?;
            Ok::<_, DsmError>(LegWrite {
                vault_id,
                parent_root,
                attempt,
                key: *cell.routed().key(),
                reached_leader: write.reached_leader(),
            })
        },
    ))
    .await
}

/// §33: complete a fulfillment whose hops are not all final.
///
/// The exercise is the value Core reads as holding one of the fulfillment's
/// leg cells, taken from that cell's reads and carried VERBATIM to every leg
/// key the fulfillment names — never rebuilt, because building one needs the
/// trader's own closure objects and those are not a relayer's to hold. The
/// position pair is carried with the trader's signed `C_q`: the one
/// `K_root(q)` holds, or the one that exercise carries. If no leg cell is
/// held by this fulfillment's exercise only the pair is carried, and only
/// when `K_root(q)` already holds the trader's claim; that is reported
/// rather than papered over.
pub async fn relay_fulfillment(
    set: &StorageSet,
    fulfillment_id: &D32,
) -> Result<Relayed, DsmError> {
    let (fulfillment, precommit) = objects(set, fulfillment_id).await?;
    let cells = leg_cells(set, &fulfillment, &precommit)?;
    let held = held_exercise(set, &cells, &fulfillment).await?;
    let pair = carry_pair(
        set,
        &fulfillment,
        &precommit,
        held.as_ref()
            .map(|(exercise, _)| exercise.resolution_claim()),
    )
    .await?;
    let legs = match held {
        Some((_, bytes)) => carry_exercise(set, cells, &bytes).await?,
        None => Vec::new(),
    };
    Ok(Relayed {
        fulfillment_id: *fulfillment_id,
        position: fulfillment.body.position(),
        pair,
        legs,
    })
}

/// Register the fulfillment whose exercise holds `vault_id`'s key
/// `K^(attempt)` at `parent_root`, from that exercise's bytes alone (SoFi
/// Amendment S20), and carry the exercise to every key its `F` names.
///
/// Everything comes from the exercise: `F` in its envelope, the trader's
/// signed `C_q`, and `P`, whose parent root routes the pair. Nothing is
/// fetched from the trader or by content address, so a trader that wrote its
/// exercise and withheld its pair — or never published `F` on its own —
/// cannot keep the key held: any device that reads the key completes the
/// pair.
pub async fn relay_exercise(
    set: &StorageSet,
    vault_id: &D32,
    parent_root: &D32,
    attempt: u64,
) -> Result<Relayed, DsmError> {
    let cell = attempt_cell(set, vault_id, parent_root, attempt)?;
    let seats = NodeSeats::new(set)?;
    let evidence = read_cell(&seats, cell.routed()).await;
    let read = attempt_resolution(&cell, &evidence)
        .map_err(|undecided| refuse(format!("the key is not decided yet: {undecided:?}")))?;
    let (Some(exercise), Some(bytes)) = (read.exercise(), read.value()) else {
        return Err(refuse(
            "no exercise holds the key; there is nothing to relay",
        ));
    };
    let (fulfillment, precommit) = (exercise.fulfillment(), exercise.precommit());
    let cells = leg_cells(set, fulfillment, precommit)?;
    let pair = carry_pair(
        set,
        fulfillment,
        precommit,
        Some(exercise.resolution_claim()),
    )
    .await?;
    let legs = carry_exercise(set, cells, bytes).await?;
    Ok(Relayed {
        fulfillment_id: dsm::sofi::derive::fulfillment_id(&fulfillment.body),
        position: fulfillment.body.position(),
        pair,
        legs,
    })
}
