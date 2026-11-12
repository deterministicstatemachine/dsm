// SPDX-License-Identifier: MIT OR Apache-2.0

//! Application cells on storage nodes (DSM Amendment A35): this device's
//! write at a cell an application names, and what holds a cell.
//!
//! The rules are Core's (`dsm::app_cell`). This device signs a write with its
//! own key, puts it at the cell leader first, and reads back the cell's
//! canonical occupant, which is another writer's when that one reached the
//! leader first.

use dsm::app_cell::{self, AppCell, AppCellRead, AppCellWrite, Writer, WriterSet};
use dsm::route_chain::{CellFact, ChainState};
use dsm::types::error::DsmError;

use crate::sdk::core_sdk::CoreSDK;
use crate::sdk::route_seats::{write_recorded, AtLeader};
use crate::sdk::sofi_flow::{identity, refuse, storage, SIGNATURE_ALG};
use crate::sdk::sofi_reads::{verifier_error, VerifierContext};
use crate::sdk::storage_set::{as_ccb_members, StorageSet};

type D32 = [u8; 32];

/// `key` as a writer of the device signing algorithm, the one every wallet
/// and application account signs with.
pub fn writer(key: &[u8]) -> Result<Writer, String> {
    Writer::new(SIGNATURE_ALG, key).map_err(|e| format!("a writer's key: {e}"))
}

/// The writer set these keys form: 1 to `app_cell::MAX_WRITERS` distinct
/// device keys, in any order.
pub fn writers(keys: &[Vec<u8>]) -> Result<WriterSet, String> {
    let named = keys
        .iter()
        .map(|key| writer(key))
        .collect::<Result<Vec<_>, _>>()?;
    WriterSet::new(named).map_err(|e| format!("the cell's writers: {e}"))
}

/// The cell `application` names `name` for `writers`.
pub fn cell_of(application: &D32, name: &[u8], writers: &WriterSet) -> D32 {
    app_cell::cell_key(application, &app_cell::writers_digest(writers), name)
}

/// What a read found at a cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Occupied {
    pub cell: D32,
    /// The write holding the cell and how far its chain has gone; `None`
    /// while no recognized write holds it.
    pub held: Option<(AppCellWrite, ChainState)>,
    /// `step(cell, occupant)` once the occupant is final: what the
    /// application's next cell name commits.
    pub step: Option<D32>,
}

impl Occupied {
    fn of(read: &AppCellRead) -> Self {
        let held = match (read.occupant(), read.fact()) {
            (Some(write), CellFact::Held { state, .. }) => Some((write.clone(), state)),
            (Some(..), CellFact::Open) | (None, _) => None,
        };
        Self {
            cell: *read.key(),
            held,
            step: read.settled().map(|(_, step)| step),
        }
    }
}

/// What the cell at `cell` holds, read from the set's seats.
pub fn read(core: &CoreSDK, set: &StorageSet, cell: &D32) -> Result<Occupied, DsmError> {
    let ctx = VerifierContext::new(set, Some(identity(core)?), None)?;
    let read = ctx
        .verifier()
        .read_app_cell(cell)
        .map_err(verifier_error)?
        .map_err(|missing| storage("application cell", format!("not decided yet: {missing:?}")))?;
    Ok(Occupied::of(&read))
}

/// This device's write of `payload` at the cell `application` names `name`
/// for `writers`, signed with its own key and put at the cell leader first;
/// then what the cell holds, which is another writer's write when that one
/// was first at the leader. This device's key must be one of `writers`.
pub async fn write(
    core: &CoreSDK,
    set: &StorageSet,
    application: &D32,
    name: &[u8],
    writers: &WriterSet,
    payload: &[u8],
) -> Result<(AppCellWrite, Occupied), DsmError> {
    let me = writer(&crate::sdk::signing_authority::current_public_key()?).map_err(refuse)?;
    let secret_key = crate::sdk::signing_authority::current_secret_key()?;
    let signed = app_cell::sign_write(
        *application,
        name,
        writers.clone(),
        &me,
        &secret_key,
        payload,
    )?;
    let key = signed.cell();
    let cell = AppCell::new(&key, &as_ccb_members(set)?, &set.id())
        .map_err(|e| refuse(format!("application cell: {e:?}")))?;
    let report = write_recorded(set, cell.routed(), &cell.recognizes(), &signed.encode()).await?;
    match report.leader() {
        // This write, or another one first at the cell's leader: the cell is
        // held, and what holds it is read back.
        AtLeader::Link | AtLeader::Taken => {}
        AtLeader::Unanswered => {
            return Err(storage(
                "application cell",
                "the cell's leader did not take the write; nothing holds the cell",
            ))
        }
    }
    Ok((signed, read(core, set, &key)?))
}
