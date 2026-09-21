// SPDX-License-Identifier: Apache-2.0
//! The vault head and evidence store (spec §44.4): the post state a resolved
//! transition SELECTED, kept so the next trade against that vault has
//! evidence to stand on.
//!
//! **It decides no canonicality.** `advance_resolved` already selected the
//! state; this only preserves it. What it holds is two things, and the
//! distinction matters:
//!
//! | Table | Holds | Why |
//! |---|---|---|
//! | `sofi_vault_root` | `(vault, generation) -> root` | the chain this verifier established, one row per generation, kept forever because a parent's status is asked about a GENERATION |
//! | `sofi_vault_leaf` | `(vault, leaf_key) -> value + preimage` | the CURRENT head's leaves, replaced wholesale, because evidence needs leaf PREIMAGES and a later acquisition reads them |
//!
//! **A read is checked, never trusted.** The leaves are a cache of this
//! device's own conclusions, so `leaves_at_head` rebuilds the tree from them
//! and requires the recomputed root to equal the recorded one. That equality
//! is exactly what detects an INCOMPLETE record: a vault another trader moved
//! between our own trades leaves us missing their relationship leaf, and a
//! record that cannot reproduce its own root is not evidence. The caller then
//! gets `None`, Core answers `Unavailable`, and the position waits — which is
//! the right answer, because this device has not established that state.
//!
//! This replaces the persistent node store R14 deleted. A node store returned
//! leaf VALUES; evidence needs the preimages, so the values alone could never
//! have served the next trade.
use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension, Transaction};

use dsm::economic::tree::EconomicSmt;
use dsm::sofi::derive;
use dsm::sofi::validation::{VaultLeafPre, VaultPostState};
use dsm::sofi::wire::{VaultRelationshipLeaf, VaultStateLeaf};

use super::get_connection;

type D32 = [u8; 32];

const KIND_STATE: i64 = 0;
const KIND_RELATIONSHIP: i64 = 1;

fn digest32(v: Vec<u8>, what: &str) -> Result<D32> {
    <D32>::try_from(v.as_slice()).map_err(|_| anyhow!("{what} is not 32 bytes"))
}

/// What this verifier established about one vault: the root of the highest
/// generation it resolved, and that generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultHead {
    pub vault_id: D32,
    pub generation: u64,
    pub root: D32,
}

/// Record a vault's accepted GENESIS as generation zero, inside the caller's
/// transaction. The genesis is the one head nobody resolved: it is where the
/// chain starts, and without it the first trade's parent has no status.
pub fn record_genesis_with_conn(
    tx: &Transaction<'_>,
    vault_id: &D32,
    root: &D32,
    state: &VaultStateLeaf,
    now: i64,
) -> Result<()> {
    let leaf = (
        derive::vault_state_key(vault_id),
        derive::vault_state_leaf_value(state).map_err(|e| anyhow!("state leaf value: {e}"))?,
        KIND_STATE,
        state.encode().map_err(|e| anyhow!("state leaf: {e}"))?,
    );
    write(tx, vault_id, 0, root, &[leaf], now)
}

/// Record the post state a resolved transition selected, inside the caller's
/// transaction — the same one that makes the position durable, so a head and
/// the position that chose it cannot disagree.
///
/// The leaves REPLACE this vault's previous set rather than merging into it,
/// because a head is a whole tree and a mixture of two generations is not one.
pub fn record_resolved_with_conn(
    tx: &Transaction<'_>,
    post: &VaultPostState,
    now: i64,
) -> Result<()> {
    // The previous set is read through the CALLER'S transaction, not a second
    // connection: the admit path already holds the connection mutex, and a
    // nested acquisition would deadlock rather than fail.
    let previous = rows_with_conn(tx, &post.vault_id)?;
    let mut leaves: Vec<(D32, D32, i64, Vec<u8>)> = previous
        .iter()
        .filter(|(key, ..)| *key != derive::vault_state_key(&post.vault_id))
        .cloned()
        .collect();
    leaves.push((
        derive::vault_state_key(&post.vault_id),
        derive::vault_state_leaf_value(&post.state)
            .map_err(|e| anyhow!("state leaf value: {e}"))?,
        KIND_STATE,
        post.state
            .encode()
            .map_err(|e| anyhow!("state leaf: {e}"))?,
    ));
    if let Some((key, leaf)) = &post.relationship {
        leaves.retain(|(k, ..)| k != key);
        leaves.push((
            *key,
            derive::vault_relationship_leaf_value(leaf),
            KIND_RELATIONSHIP,
            leaf.encode(),
        ));
    }
    // BOTH ends of the link. A store that kept only post roots would hold a
    // set and not a chain, and `root_at(v, g)` is what a parent's status is
    // asked about. Idempotent: re-resolving the same position writes the same
    // two rows.
    write_root(tx, &post.vault_id, post.pre_generation, &post.pre_root, now)?;
    write(
        tx,
        &post.vault_id,
        post.state.generation,
        &post.root,
        &leaves,
        now,
    )
}

fn write_root(
    tx: &Transaction<'_>,
    vault_id: &D32,
    generation: u64,
    root: &D32,
    now: i64,
) -> Result<()> {
    tx.execute(
        "INSERT INTO sofi_vault_root (vault_id, generation, root, updated_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(vault_id, generation) DO UPDATE SET
             root = excluded.root, updated_at = excluded.updated_at",
        params![
            vault_id.as_slice(),
            i64::try_from(generation).map_err(|_| anyhow!("generation overflow"))?,
            root.as_slice(),
            now
        ],
    )?;
    Ok(())
}

fn write(
    tx: &Transaction<'_>,
    vault_id: &D32,
    generation: u64,
    root: &D32,
    leaves: &[(D32, D32, i64, Vec<u8>)],
    now: i64,
) -> Result<()> {
    write_root(tx, vault_id, generation, root, now)?;
    tx.execute(
        "DELETE FROM sofi_vault_leaf WHERE vault_id = ?1",
        params![vault_id.as_slice()],
    )?;
    for (key, value, kind, preimage) in leaves {
        tx.execute(
            "INSERT INTO sofi_vault_leaf (vault_id, leaf_key, leaf_value, kind, preimage, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                vault_id.as_slice(),
                key.as_slice(),
                value.as_slice(),
                kind,
                preimage,
                now
            ],
        )?;
    }
    Ok(())
}

/// The highest generation this verifier established for `vault_id`.
pub fn head(vault_id: &D32) -> Result<Option<VaultHead>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.query_row(
        "SELECT generation, root FROM sofi_vault_root
          WHERE vault_id = ?1 ORDER BY generation DESC LIMIT 1",
        params![vault_id.as_slice()],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
    )
    .optional()?
    .map(|(generation, root)| {
        Ok(VaultHead {
            vault_id: *vault_id,
            generation: u64::try_from(generation).map_err(|_| anyhow!("generation negative"))?,
            root: digest32(root, "vault root")?,
        })
    })
    .transpose()
}

/// The root this verifier established for `vault_id` at `generation`, if it
/// established one. `None` is "not established", which is NOT "another root".
pub fn root_at(vault_id: &D32, generation: u64) -> Result<Option<D32>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.query_row(
        "SELECT root FROM sofi_vault_root WHERE vault_id = ?1 AND generation = ?2",
        params![
            vault_id.as_slice(),
            i64::try_from(generation).map_err(|_| anyhow!("generation overflow"))?
        ],
        |r| r.get::<_, Vec<u8>>(0),
    )
    .optional()?
    .map(|root| digest32(root, "vault root"))
    .transpose()
}

/// The stored leaves of a vault, as rows.
pub fn leaf_rows(vault_id: &D32) -> Result<Vec<(D32, D32, i64, Vec<u8>)>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    rows_with_conn(&conn, vault_id)
}

fn rows_with_conn(
    conn: &rusqlite::Connection,
    vault_id: &D32,
) -> Result<Vec<(D32, D32, i64, Vec<u8>)>> {
    let mut stmt = conn.prepare(
        "SELECT leaf_key, leaf_value, kind, preimage FROM sofi_vault_leaf WHERE vault_id = ?1",
    )?;
    let rows = stmt.query_map(params![vault_id.as_slice()], |r| {
        Ok((
            r.get::<_, Vec<u8>>(0)?,
            r.get::<_, Vec<u8>>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, Vec<u8>>(3)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (key, value, kind, preimage) = row?;
        out.push((
            digest32(key, "leaf key")?,
            digest32(value, "leaf value")?,
            kind,
            preimage,
        ));
    }
    Ok(out)
}

/// The vault's leaves at its established head, for the keys an acquisition
/// needs — CHECKED against the head's own root.
///
/// The cache is this device's own conclusions, so it proves nothing by
/// existing. The tree is rebuilt from every stored leaf and its root must
/// equal the recorded one; a record that cannot reproduce its own root is
/// incomplete (a vault another trader moved between our trades) and yields
/// `None`, so Core answers `Unavailable` and the position waits.
pub fn leaves_at_head(
    vault_id: &D32,
    keys: &std::collections::BTreeSet<D32>,
) -> Result<
    Option<(
        VaultHead,
        std::collections::BTreeMap<(D32, D32), VaultLeafPre>,
    )>,
> {
    let Some(head) = head(vault_id)? else {
        return Ok(None);
    };
    let rows = leaf_rows(vault_id)?;
    let mut tree = EconomicSmt::new();
    for (key, value, ..) in &rows {
        tree.insert(*key, *value);
    }
    if tree.root() != head.root {
        // Not an error: an incomplete record is a fact about what this device
        // established, and the honest answer is that it established nothing
        // usable here.
        return Ok(None);
    }
    let mut out = std::collections::BTreeMap::new();
    for key in keys {
        let pre = match rows.iter().find(|(k, ..)| k == key) {
            Some((_, _, kind, preimage)) if *kind == KIND_STATE => VaultLeafPre::State(
                VaultStateLeaf::decode(preimage).map_err(|e| anyhow!("state leaf: {e}"))?,
            ),
            Some((_, _, kind, preimage)) if *kind == KIND_RELATIONSHIP => {
                VaultLeafPre::Relationship(
                    VaultRelationshipLeaf::decode(preimage)
                        .map_err(|e| anyhow!("relationship leaf: {e}"))?,
                )
            }
            Some(_) => return Err(anyhow!("unknown vault leaf kind")),
            None => VaultLeafPre::Absent,
        };
        out.insert((*vault_id, *key), pre);
    }
    Ok(Some((head, out)))
}
