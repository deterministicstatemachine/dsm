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
//! A relay creates nothing and decides nothing. `F` is signed by the trader
//! and `C_q` is a function of the two verified objects, so a relayer carrying
//! them adds no authority of its own; the exercise it carries is the value
//! Core reads as holding one of the fulfillment's leg cells, relayed verbatim
//! rather than rebuilt, because the trader's own closure objects are not a
//! relayer's to hold. Every write goes along its cell's route from the
//! leader (storage spec §9). Nothing here re-gates on conformance: that gate
//! is the PRODUCER's discipline before it publishes, not a second opinion at
//! every carrier.
use dsm::route_chain::CellFact;
use dsm::sofi::exercise::attempt_resolution;
use dsm::sofi::resolve::value_of;
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

/// Carry the position pair of a registered-or-not fulfillment along the
/// route of `s(q)`: `F` in the envelope it was published in, and `C_q`
/// derived from the two verified objects. It establishes no registration —
/// Core derives that from the cells (R10).
pub async fn relay_position_pair(
    set: &StorageSet,
    fulfillment_id: &D32,
) -> Result<Relayed, DsmError> {
    let (fulfillment, precommit) = objects(set, fulfillment_id).await?;
    let pair = carry_pair(set, &fulfillment, &precommit).await?;
    Ok(Relayed {
        fulfillment_id: *fulfillment_id,
        position: fulfillment.body.position(),
        pair,
        legs: Vec::new(),
    })
}

async fn carry_pair(
    set: &StorageSet,
    fulfillment: &Signed<TraderFulfillmentBody>,
    precommit: &Signed<TraderPrecommitBody>,
) -> Result<[WriteReport; 2], DsmError> {
    let cells = cells_of(set, &precommit.body, &fulfillment.body)?;
    let f_bytes = Publication::Fulfillment {
        body: &fulfillment.body,
        signature: &fulfillment.signature,
    }
    .object_bytes()
    .map_err(refuse)?;
    let claim = dsm::sofi::derive::resolution_claim(&precommit.body, &fulfillment.body).encode();
    write_recorded_position(set, &cells, &f_bytes, &claim).await
}

/// §33: complete a fulfillment whose hops are not all final.
///
/// The exercise is the value Core reads as holding one of the fulfillment's
/// leg cells, taken from that cell's reads and carried VERBATIM to every leg
/// key the fulfillment names — never rebuilt, because building one needs the
/// trader's own closure objects and those are not a relayer's to hold. If no
/// leg cell is held by this fulfillment's exercise there is nothing to relay,
/// and that is reported rather than papered over: the trader must write it
/// once before any relayer can carry it.
pub async fn relay_fulfillment(
    set: &StorageSet,
    fulfillment_id: &D32,
) -> Result<Relayed, DsmError> {
    let (fulfillment, precommit) = objects(set, fulfillment_id).await?;
    let pair = carry_pair(set, &fulfillment, &precommit).await?;

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

    let seats = NodeSeats::new(set)?;
    let mut carried: Option<Vec<u8>> = None;
    for (.., cell) in &cells {
        let evidence = read_cell(&seats, cell.routed()).await;
        let id = match attempt_resolution(cell, &evidence) {
            Ok(read) => match (read.fact(), read.exercise()) {
                (CellFact::Held { id, .. }, Some(object))
                    if object.fulfillment.body == fulfillment.body =>
                {
                    id
                }
                _ => continue,
            },
            Err(undecided) => {
                log::info!("[sofi relay] a leg cell is not decided yet: {undecided:?}");
                continue;
            }
        };
        carried = value_of(&evidence, &id);
        if carried.is_some() {
            break;
        }
    }
    let Some(bytes) = carried else {
        return Ok(Relayed {
            fulfillment_id: *fulfillment_id,
            position: fulfillment.body.position(),
            pair,
            legs: Vec::new(),
        });
    };

    let mut legs = Vec::new();
    for (vault_id, parent_root, attempt, cell) in cells {
        // The one exercise names every leg's key, so the same bytes belong at
        // each of them; Core counts only an exercise naming the key it sits
        // at, so carrying it where it names nothing would carry nothing.
        if dsm::sofi::exercise::exercise_names_key(&bytes, &vault_id, &parent_root, attempt)
            .is_none()
        {
            return Err(refuse(
                "the exercise found does not name every key its F does",
            ));
        }
        let write = write_recorded(set, cell.routed(), &bytes).await?;
        legs.push(LegWrite {
            vault_id,
            parent_root,
            attempt,
            key: *cell.routed().key(),
            reached_leader: write.reached_leader(),
        });
    }
    Ok(Relayed {
        fulfillment_id: *fulfillment_id,
        position: fulfillment.body.position(),
        pair,
        legs,
    })
}
