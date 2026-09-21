// SPDX-License-Identifier: Apache-2.0
//! Relaying (§33), and the line it must not cross.
//!
//! **Any device may carry immutable signed protocol objects to storage. Only
//! the owning device may touch its own admission, fence, lineage and leaf
//! cache** (owner ruling, §44.4). Those are two different operations and this
//! module is one of them: everything here takes a fulfillment id and a
//! committed set, holds no `CoreSDK`, reads no device head, and writes
//! nothing local. The owner-local half — `complete_pending_fulfillment` and
//! `resolve_pending_position` — stays in `sofi_advance`.
//!
//! A relay creates nothing and decides nothing. `F` is signed by the trader
//! and `C_q` is a function of the two verified objects, so a relayer carrying
//! them adds no authority of its own; the exercise it carries is bytes it
//! read back from a cell, relayed verbatim rather than rebuilt, because the
//! trader's own closure objects are not a relayer's to hold. Members keep
//! what they are given and Core decides what counts, which is why nothing
//! here re-gates on conformance: that gate is the PRODUCER's discipline
//! before it publishes, not a second opinion at every carrier.
use dsm::common::domain_tags::{TAG_DSM_SOFI_FULFILLMENT, TAG_DSM_SOFI_SUCC_CELL_V2};
use dsm::economic::register::{economic_root_register_key, position_seed};
use dsm::sofi::derive;
use dsm::sofi::exercise::exercise_names_key;
use dsm::sofi::publication::{Publication, Signed};
use dsm::sofi::storage::Resolved;
use dsm::sofi::wire::{TraderFulfillmentBody, TraderPrecommitBody};
use dsm::types::error::DsmError;

use crate::sdk::economic_registers::economic_root_namespace;
use crate::sdk::sofi_exercise::LegWrite;
use crate::sdk::sofi_publish::{fetch_fulfillment, fetch_precommit};
use crate::sdk::storage_io::{read_cell_raw, write_cell_leader_first, write_cells_leader_first};
use crate::sdk::storage_set::StorageSet;

type D32 = [u8; 32];

fn refuse(what: impl std::fmt::Display) -> DsmError {
    DsmError::invalid_operation(format!("sofi relay: {what}"))
}

/// What a relay carried. Nothing here is a claim about registration or
/// resolution: those are Core's, from raw reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relayed {
    pub fulfillment_id: D32,
    pub position: u64,
    /// The position pair, carried to the leader of `s(q)` and the members.
    pub pair_leader_reached: bool,
    pub pair_copies: u32,
    /// Every leg key the exercise now sits at. Empty when no cell held an
    /// exercise to carry: a relayer cannot build one.
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

/// Carry the position pair of a registered-or-not fulfillment to the leader
/// of `s(q)` and to every other member: `F` in the envelope it was published
/// in, and `C_q` derived from the two verified objects.
///
/// Idempotent at the members, which keep what they were given: a member that
/// already holds the bytes keeps them, and one that missed the trader's write
/// gets them now. It establishes no registration — Core derives that from
/// raw reads (R10).
pub async fn relay_position_pair(
    set: &StorageSet,
    fulfillment_id: &D32,
) -> Result<Relayed, DsmError> {
    let (fulfillment, precommit) = objects(set, fulfillment_id).await?;
    let pair = carry_pair(set, &fulfillment, &precommit).await?;
    Ok(Relayed {
        fulfillment_id: *fulfillment_id,
        position: fulfillment.body.position(),
        pair_leader_reached: pair.0,
        pair_copies: pair.1,
        legs: Vec::new(),
    })
}

async fn carry_pair(
    set: &StorageSet,
    fulfillment: &Signed<TraderFulfillmentBody>,
    precommit: &Signed<TraderPrecommitBody>,
) -> Result<(bool, u32), DsmError> {
    let q = fulfillment.body.position();
    let genesis = precommit.body.genesis();
    let device_id = precommit.body.device_id();
    let k_ful = derive::fulfillment_register_key(genesis, device_id, q);
    let k_root = economic_root_register_key(genesis, device_id, q);
    let seed = position_seed(genesis, device_id, q, precommit.body.void_root());
    let f_bytes = Publication::Fulfillment {
        body: &fulfillment.body,
        signature: &fulfillment.signature,
    }
    .object_bytes()
    .map_err(refuse)?;
    let claim = derive::resolution_claim(&precommit.body, &fulfillment.body).encode();
    let write = write_cells_leader_first(
        set,
        &seed,
        &[
            (
                TAG_DSM_SOFI_FULFILLMENT.source_bytes().to_vec(),
                k_ful,
                f_bytes,
            ),
            (economic_root_namespace().to_vec(), k_root, claim),
        ],
    )
    .await?;
    Ok((write.leader_reached, write.copies))
}

/// §33: complete any registered fulfillment whose hops are not all final.
///
/// The exercise is read back from whichever leg cell already holds one and
/// carried VERBATIM to every leg key the fulfillment names — never rebuilt,
/// because building one needs the trader's own closure objects and those are
/// not a relayer's to hold. If no cell holds an exercise there is nothing to
/// relay, and that is reported rather than papered over: the trader must
/// publish it once before any relayer can carry it.
pub async fn relay_fulfillment(
    set: &StorageSet,
    fulfillment_id: &D32,
) -> Result<Relayed, DsmError> {
    let (fulfillment, precommit) = objects(set, fulfillment_id).await?;
    let (pair_leader_reached, pair_copies) = carry_pair(set, &fulfillment, &precommit).await?;

    // The keys this fulfillment names, and the exercise if any of them holds
    // it. A cell is read raw: what counts at a key is Core's question
    // (`exercise_names_key`), not a member's.
    let mut keys = Vec::new();
    for attempt in fulfillment.body.attempts() {
        let Some(leg) = precommit
            .body
            .legs()
            .iter()
            .find(|l| l.vault_id == attempt.vault_id)
        else {
            return Err(refuse("an attempt names a vault P has no leg for"));
        };
        keys.push((
            leg.vault_id,
            leg.parent_root,
            attempt.attempt,
            derive::successor_attempt_key(&leg.vault_id, &leg.parent_root, attempt.attempt),
        ));
    }
    let mut carried: Option<Vec<u8>> = None;
    for (vault_id, parent_root, attempt, key) in &keys {
        let reads = read_cell_raw(set, TAG_DSM_SOFI_SUCC_CELL_V2.source_bytes(), key).await?;
        for value in reads.iter().flatten().flatten() {
            if exercise_names_key(value, vault_id, parent_root, *attempt).is_some() {
                carried = Some(value.clone());
                break;
            }
        }
        if carried.is_some() {
            break;
        }
    }
    let Some(bytes) = carried else {
        return Ok(Relayed {
            fulfillment_id: *fulfillment_id,
            position: fulfillment.body.position(),
            pair_leader_reached,
            pair_copies,
            legs: Vec::new(),
        });
    };

    let mut legs = Vec::new();
    for (vault_id, parent_root, attempt, key) in keys {
        // The one exercise names every leg's key, so the same bytes belong at
        // each of them; a relayer that carried them anywhere else would be
        // carrying nothing, because Core counts only an exercise naming the
        // key it sits at.
        if exercise_names_key(&bytes, &vault_id, &parent_root, attempt).is_none() {
            return Err(refuse(
                "the exercise found does not name every key its F does",
            ));
        }
        let seed = derive::storage_seed(&vault_id, &parent_root);
        let write = write_cell_leader_first(
            set,
            TAG_DSM_SOFI_SUCC_CELL_V2.source_bytes(),
            &key,
            &seed,
            &bytes,
        )
        .await?;
        legs.push(LegWrite {
            vault_id,
            parent_root,
            attempt,
            key,
            leader_reached: write.leader_reached,
            copies: write.copies,
        });
    }
    Ok(Relayed {
        fulfillment_id: *fulfillment_id,
        position: fulfillment.body.position(),
        pair_leader_reached,
        pair_copies,
        legs,
    })
}
