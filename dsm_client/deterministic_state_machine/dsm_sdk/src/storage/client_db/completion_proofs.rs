// SPDX-License-Identifier: MIT OR Apache-2.0

//! The completion proofs this device relies on (storage spec §9 rule 11).
//!
//! The client that relies on a `Final` keeps its completion proof; nothing
//! else stores it. The seats hold everything the proof is made of, so a
//! verifier rebuilds and checks it from its own reads; this store is what
//! lets the client present the exact proof and its digest again.

use anyhow::{anyhow, Result};
use prost::Message;
use rusqlite::{params, OptionalExtension};

use dsm::route_chain::{ChainSlot, CompletionProof};

use super::get_connection;

/// A kept proof and its completion digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeptProof {
    pub digest: [u8; 32],
    pub proof: CompletionProof,
}

/// Keep a completion proof of the value it names at `(namespace, cell_key)`.
/// Keeping the same proof again changes nothing.
pub fn keep(
    namespace: &[u8],
    cell_key: &[u8; 32],
    digest: &[u8; 32],
    proof: &CompletionProof,
) -> Result<()> {
    let value_digest = dsm::storage_cell::entry_digest(&proof.value);
    let binding = get_connection()?;
    let mut conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT OR REPLACE INTO completion_proof
            (namespace, cell_key, value_digest, value, digest)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            namespace,
            cell_key.as_slice(),
            value_digest.as_slice(),
            proof.value,
            digest.as_slice()
        ],
    )?;
    tx.execute(
        "DELETE FROM completion_proof_slot
          WHERE namespace = ?1 AND cell_key = ?2 AND value_digest = ?3",
        params![namespace, cell_key.as_slice(), value_digest.as_slice()],
    )?;
    for (position, slot) in proof.slots.iter().enumerate() {
        tx.execute(
            "INSERT INTO completion_proof_slot
                (namespace, cell_key, value_digest, position, slot)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                namespace,
                cell_key.as_slice(),
                value_digest.as_slice(),
                i64::try_from(position).map_err(|e| anyhow!("slot position: {e}"))?,
                slot.to_proto().encode_to_vec()
            ],
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// The kept completion proof of `value` at `(namespace, cell_key)`, if any.
pub fn get(namespace: &[u8], cell_key: &[u8; 32], value: &[u8]) -> Result<Option<KeptProof>> {
    let value_digest = dsm::storage_cell::entry_digest(value);
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let digest: Option<Vec<u8>> = conn
        .query_row(
            "SELECT digest FROM completion_proof
              WHERE namespace = ?1 AND cell_key = ?2 AND value_digest = ?3",
            params![namespace, cell_key.as_slice(), value_digest.as_slice()],
            |r| r.get(0),
        )
        .optional()?;
    let Some(digest) = digest else {
        return Ok(None);
    };
    let digest = <[u8; 32]>::try_from(digest.as_slice()).map_err(|e| anyhow!("digest: {e}"))?;
    let mut stmt = conn.prepare(
        "SELECT position, slot FROM completion_proof_slot
          WHERE namespace = ?1 AND cell_key = ?2 AND value_digest = ?3
          ORDER BY position ASC",
    )?;
    let rows = stmt.query_map(
        params![namespace, cell_key.as_slice(), value_digest.as_slice()],
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
