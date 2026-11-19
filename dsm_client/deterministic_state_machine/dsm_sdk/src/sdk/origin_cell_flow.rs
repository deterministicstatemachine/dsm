// SPDX-License-Identifier: MIT OR Apache-2.0

//! Offline origin cells on storage nodes (DSM Amendment A39 draft, prototype):
//! writing a step an offline account's board signed, by anyone holding it, and
//! reading the cells to settle a payment without its payer or to find where an
//! account stands.
//!
//! The rules are Core's (`dsm::offline_origin`). A write goes to its cell's
//! leader first; the cell holds the first recognized one there. Reading a cell
//! relies on a final step only through its completion proof, checked against
//! fresh reads.

use dsm::economic::offline_boundary::BoundaryAnchor;
use dsm::offline_origin::{self, OriginCell, OriginRead, OriginStep, OriginWrite};
use dsm::types::error::DsmError;
use dsm::types::offline_chain::{AccountHop, ChainPayment, MAX_CHAIN_HOPS};

use crate::sdk::core_sdk::CoreSDK;
use crate::sdk::route_seats::{write_recorded, AtLeader};
use crate::sdk::sofi_flow::{identity, refuse, storage};
use crate::sdk::sofi_reads::{verifier_error, VerifierContext};
use crate::sdk::storage_set::{as_ccb_members, StorageSet};

type D32 = [u8; 32];

/// The write of `step`, a step of the account of the board `pin` names, owned
/// by `(owner_key, device_id)`.
pub fn write_of(
    pin: &crate::anchor::AnchorPin,
    owner_key: &[u8],
    device_id: D32,
    step: &AccountHop,
) -> OriginWrite {
    OriginWrite::new(
        owner_key,
        device_id,
        pin.bundle,
        &BoundaryAnchor {
            anchor_id: pin.anchor_id,
            pk_chip: pin.pk_chip.clone(),
            pk_host: pin.partition_pk.clone(),
            enrolled_counter: pin.enrolled_counter,
            birth_commitment: pin.birth_commitment,
        },
        step,
    )
}

fn cell(set: &StorageSet, bundle: &D32, account_root: &D32) -> Result<OriginCell, DsmError> {
    OriginCell::new(bundle, account_root, &as_ccb_members(set)?, &set.id())
        .map_err(|e| refuse(format!("origin cell: {e:?}")))
}

/// Put `bytes` at the origin cell of `account_root` of `bundle`, leader first.
/// Anyone may put anything at a cell; only a write that proves its own
/// authority there ever holds it.
pub async fn put(
    set: &StorageSet,
    bundle: &D32,
    account_root: &D32,
    bytes: &[u8],
) -> Result<AtLeader, DsmError> {
    let cell = cell(set, bundle, account_root)?;
    let report = write_recorded(set, cell.routed(), &cell.keeps(), bytes).await?;
    Ok(report.leader())
}

/// Put `write` at the origin cell of the root its step starts from. Whoever
/// holds the step may: the authority is the board's signatures under `B`.
pub async fn write(set: &StorageSet, write: &OriginWrite) -> Result<AtLeader, DsmError> {
    let step = AccountHop::from_bytes(&write.step)?;
    let bytes = write
        .encode()
        .map_err(|e| refuse(format!("origin write: {e:?}")))?;
    put(set, &write.bundle, &step.starts_from(), &bytes).await
}

/// What the origin cell of `account_root` of `bundle` holds, read from the
/// set's seats. Reads that do not decide the cell yet are a storage error,
/// never an open cell.
pub fn read(
    core: &CoreSDK,
    set: &StorageSet,
    bundle: &D32,
    account_root: &D32,
) -> Result<OriginRead, DsmError> {
    let ctx = VerifierContext::new(set, Some(identity(core)?), None)?;
    ctx.verifier()
        .read_origin_cell(bundle, account_root)
        .map_err(verifier_error)?
        .map_err(|missing| storage("origin cell", format!("not decided yet: {missing:?}")))
}

/// The history the cells of `bundle`'s account hold from `start`: each step
/// final at the cell of the root the last one left, in order, and the root
/// where the walk stops — the first cell holding no final step. What a
/// restored wallet reads to find where its account stands.
pub fn walk(
    core: &CoreSDK,
    set: &StorageSet,
    bundle: &D32,
    start: &D32,
) -> Result<(Vec<OriginStep>, D32), DsmError> {
    let mut at = *start;
    let mut steps = Vec::new();
    for _ in 0..MAX_CHAIN_HOPS {
        let read = read(core, set, bundle, &at)?;
        let Some(step) = read.settled() else {
            return Ok((steps, at));
        };
        at = step.after;
        steps.push(step.clone());
    }
    Ok((steps, at))
}

/// The payer's origin cells of `bundle`'s account read from `start`, each the
/// cell of the root the last final step left, through the cell of
/// `payment_root`, where the payment's own step starts. A cell holding no final
/// step ends the path early.
pub fn path(
    core: &CoreSDK,
    set: &StorageSet,
    bundle: &D32,
    start: &D32,
    payment_root: &D32,
) -> Result<Vec<OriginRead>, DsmError> {
    let mut at = *start;
    let mut reads = Vec::new();
    for _ in 0..MAX_CHAIN_HOPS {
        let read = read(core, set, bundle, &at)?;
        let next = read.settled().map(|step| step.after);
        reads.push(read);
        // The payment's own cell is the last one read: whatever holds it decides.
        if at == *payment_root {
            break;
        }
        match next {
            Some(after) => at = after,
            None => break,
        }
    }
    Ok(reads)
}

/// Whether `reads` reached the payment's own cell with a step final there:
/// until they do, a payment stays pending, which is no refusal.
pub fn reaches_a_final_step(reads: &[OriginRead], bundle: &D32, payment_root: &D32) -> bool {
    reads.last().is_some_and(|last| {
        *last.key() == offline_origin::origin_key(bundle, payment_root)
            && last.settled().is_some()
    })
}

/// Put each of `writes` (`0x0078 OfflineOriginWrite` bytes) at its origin cell,
/// leader first. A cell another step already holds keeps it; reading the cells
/// says which.
pub async fn put_writes(set: &StorageSet, writes: &[Vec<u8>]) -> Result<(), DsmError> {
    for bytes in writes {
        let held = OriginWrite::decode(bytes)
            .map_err(|e| refuse(format!("a kept origin write: {e}")))?;
        write(set, &held).await?;
    }
    Ok(())
}

/// The payment `message` of the payer's account of `bundle`, to this device
/// `me`, proved by the payer's origin cells from `start` — the account a
/// boundary of the payer left, which this device recorded before it took the
/// payment — through `payment_start`, the root the payment's own step starts
/// from, which the payer's carried steps told this device. The payer is never
/// asked.
pub fn payment_from_cells(
    core: &CoreSDK,
    set: &StorageSet,
    bundle: &D32,
    start: &D32,
    payment_start: &D32,
    message: &D32,
    me: &D32,
) -> Result<ChainPayment, DsmError> {
    let reads = path(core, set, bundle, start, payment_start)?;
    let paid = offline_origin::payment_at_cells(bundle, start, &reads, message)?;
    if paid.recipient != *me {
        return Err(DsmError::invalid_operation(
            "the payment the payer's cells hold is not to this device",
        ));
    }
    Ok(paid)
}
