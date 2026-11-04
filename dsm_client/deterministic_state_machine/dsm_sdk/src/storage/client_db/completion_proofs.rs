// SPDX-License-Identifier: MIT OR Apache-2.0

//! The completion proofs this device relies on (storage spec §9 rule 11).
//!
//! The client that relies on a `Final` keeps its completion proof; nothing
//! else stores it. The seats hold everything the proof is made of, so a
//! verifier rebuilds and checks it from its own reads; this store is what
//! lets the client present the exact proof and its digest again, and check
//! it against fresh reads before it relies on the value (SoFi Amendment S10).
//!
//! A proof is kept under its cell's whole route — namespace, key, seed and
//! committed set — and the value it proves. A proof kept for a value is never
//! replaced by another, and one fresh reads refuted is recorded as refuted:
//! the value is never relied on through it again.

use anyhow::{anyhow, Result};
use prost::Message;
use rusqlite::{params, OptionalExtension};

use dsm::route_chain::{ChainSlot, CompletionProof, RoutedCell};

use super::get_connection;

/// A kept proof and its completion digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeptProof {
    pub digest: [u8; 32],
    pub proof: CompletionProof,
}

/// A cell's route as a kept proof is keyed by it, with the digest of the value.
struct ProofKey<'c> {
    namespace: &'c [u8],
    cell_key: &'c [u8; 32],
    seed: &'c [u8; 32],
    set_id: &'c [u8; 32],
    value_digest: [u8; 32],
}

impl<'c> ProofKey<'c> {
    fn of(cell: &'c RoutedCell, value: &[u8]) -> Self {
        Self {
            namespace: cell.namespace(),
            cell_key: cell.key(),
            seed: cell.seed(),
            set_id: cell.committed_set_id(),
            value_digest: dsm::storage_cell::entry_digest(value),
        }
    }
}

/// Keep the completion proof `proof`, whose digest is `digest`, of the value
/// it names at `cell`. Keeping the same proof again changes nothing; a
/// different proof of a value that already has one kept is refused.
pub fn keep(cell: &RoutedCell, digest: &[u8; 32], proof: &CompletionProof) -> Result<()> {
    let key = ProofKey::of(cell, &proof.value);
    let binding = get_connection()?;
    let mut conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    let tx = conn.transaction()?;
    let kept: Option<Vec<u8>> = tx
        .query_row(
            "SELECT digest FROM completion_proof
              WHERE namespace = ?1 AND cell_key = ?2 AND seed = ?3
                AND committed_set_id = ?4 AND value_digest = ?5",
            params![
                key.namespace,
                key.cell_key.as_slice(),
                key.seed.as_slice(),
                key.set_id.as_slice(),
                key.value_digest.as_slice()
            ],
            |r| r.get(0),
        )
        .optional()?;
    match kept {
        Some(kept) if kept.as_slice() == digest.as_slice() => return Ok(()),
        Some(..) => {
            return Err(anyhow!(
                "another completion proof is already kept for this value at this cell"
            ))
        }
        None => {}
    }
    tx.execute(
        "INSERT INTO completion_proof
            (namespace, cell_key, seed, committed_set_id, value_digest, value, digest)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            key.namespace,
            key.cell_key.as_slice(),
            key.seed.as_slice(),
            key.set_id.as_slice(),
            key.value_digest.as_slice(),
            proof.value,
            digest.as_slice()
        ],
    )?;
    for (position, slot) in proof.slots.iter().enumerate() {
        tx.execute(
            "INSERT INTO completion_proof_slot
                (namespace, cell_key, seed, committed_set_id, value_digest, position, slot)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                key.namespace,
                key.cell_key.as_slice(),
                key.seed.as_slice(),
                key.set_id.as_slice(),
                key.value_digest.as_slice(),
                i64::try_from(position).map_err(|e| anyhow!("slot position: {e}"))?,
                slot.to_proto().encode_to_vec()
            ],
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// The kept completion proof of `value` at `cell`, if any.
pub fn get(cell: &RoutedCell, value: &[u8]) -> Result<Option<KeptProof>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    get_with_conn(&conn, cell, value)
}

/// [`get`], on a connection the caller already holds: what a reader asks
/// while it folds another table on that connection.
pub fn get_with_conn(
    conn: &rusqlite::Connection,
    cell: &RoutedCell,
    value: &[u8],
) -> Result<Option<KeptProof>> {
    let key = ProofKey::of(cell, value);
    let digest: Option<Vec<u8>> = conn
        .query_row(
            "SELECT digest FROM completion_proof
              WHERE namespace = ?1 AND cell_key = ?2 AND seed = ?3
                AND committed_set_id = ?4 AND value_digest = ?5",
            params![
                key.namespace,
                key.cell_key.as_slice(),
                key.seed.as_slice(),
                key.set_id.as_slice(),
                key.value_digest.as_slice()
            ],
            |r| r.get(0),
        )
        .optional()?;
    let Some(digest) = digest else {
        return Ok(None);
    };
    let digest = <[u8; 32]>::try_from(digest.as_slice()).map_err(|e| anyhow!("digest: {e}"))?;
    let mut stmt = conn.prepare(
        "SELECT position, slot FROM completion_proof_slot
          WHERE namespace = ?1 AND cell_key = ?2 AND seed = ?3
            AND committed_set_id = ?4 AND value_digest = ?5
          ORDER BY position ASC",
    )?;
    let rows = stmt.query_map(
        params![
            key.namespace,
            key.cell_key.as_slice(),
            key.seed.as_slice(),
            key.set_id.as_slice(),
            key.value_digest.as_slice()
        ],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
    )?;
    let mut slots = Vec::new();
    for row in rows {
        let (position, bytes) = row?;
        if usize::try_from(position).map_err(|e| anyhow!("slot position: {e}"))? != slots.len() {
            return Err(anyhow!("kept proof slots are not one per position"));
        }
        let proto = dsm::types::proto::ChainSlotV1::decode(bytes.as_slice())
            .map_err(|e| anyhow!("kept slot: {e}"))?;
        slots.push(ChainSlot::from_proto(&proto).ok_or_else(|| anyhow!("malformed kept slot"))?);
    }
    Ok(Some(KeptProof {
        digest,
        proof: CompletionProof {
            value: value.to_vec(),
            slots,
        },
    }))
}

/// Record that fresh reads refuted the proof of `value` at `cell`, with its
/// completion digest when it has one, and why. Recording it again changes
/// nothing.
pub fn refute(cell: &RoutedCell, value: &[u8], digest: Option<&[u8; 32]>, why: &str) -> Result<()> {
    let key = ProofKey::of(cell, value);
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    conn.execute(
        "INSERT INTO completion_proof_refuted
            (namespace, cell_key, seed, committed_set_id, value_digest, digest, why)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT (namespace, cell_key, seed, committed_set_id, value_digest) DO NOTHING",
        params![
            key.namespace,
            key.cell_key.as_slice(),
            key.seed.as_slice(),
            key.set_id.as_slice(),
            key.value_digest.as_slice(),
            digest.map(|d| d.as_slice()),
            why
        ],
    )?;
    Ok(())
}

/// Why fresh reads refuted the proof of `value` at `cell`, if they did.
pub fn refuted(cell: &RoutedCell, value: &[u8]) -> Result<Option<String>> {
    let key = ProofKey::of(cell, value);
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    conn.query_row(
        "SELECT why FROM completion_proof_refuted
              WHERE namespace = ?1 AND cell_key = ?2 AND seed = ?3
                AND committed_set_id = ?4 AND value_digest = ?5",
        params![
            key.namespace,
            key.cell_key.as_slice(),
            key.seed.as_slice(),
            key.set_id.as_slice(),
            key.value_digest.as_slice()
        ],
        |r| r.get(0),
    )
    .optional()
    .map_err(|e| anyhow!("refuted completion: {e}"))
}
