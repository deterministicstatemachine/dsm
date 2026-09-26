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
//! | `sofi_vault_leaf` | `(vault, generation, leaf_key) -> value + preimage` | the whole tree of every generation this verifier established, kept as long as the generation is, because evidence for an operation built on generation `g` needs `g`'s leaf PREIMAGES — and it is read after this device has walked past `g`: its own position resolves after the walk recorded the generation its exercise produced |
//!
//! **A read is checked, never trusted.** The leaves are a cache of this
//! device's own conclusions, so `leaves_at` rebuilds the generation's tree
//! from them and requires the recomputed root to equal the recorded one. That
//! equality is exactly what detects an INCOMPLETE record: a vault another
//! trader moved between our own trades leaves us missing their relationship
//! leaf, and a record that cannot reproduce its own root is not evidence. The
//! caller then gets `None`, Core answers `Unavailable`, and the position
//! waits — which is the right answer, because this device has not
//! established that state.
//!
//! This replaces the persistent node store R14 deleted. A node store returned
//! leaf VALUES; evidence needs the preimages, so the values alone could never
//! have served the next trade.
use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension, Transaction};

use dsm::economic::tree::EconomicSmt;
use dsm::sofi::derive;
use dsm::sofi::resolve::RecordedGenerationRow;
use dsm::sofi::validation::{VaultLeafPre, VaultPostState};
use dsm::sofi::wire::{VaultRelationshipLeaf, VaultStateLeaf};

use super::get_connection;

type D32 = [u8; 32];

const KIND_STATE: i64 = 0;
const KIND_RELATIONSHIP: i64 = 1;

fn digest32(v: Vec<u8>, what: &str) -> Result<D32> {
    <D32>::try_from(v.as_slice()).map_err(|e| anyhow!("{what} is not 32 bytes: {e}"))
}

/// One generation this verifier established for a vault: its root and its
/// generation. [`head`] is the highest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultHead {
    pub vault_id: D32,
    pub generation: u64,
    pub root: D32,
}

/// Record the post state a resolved transition selected, inside the caller's
/// transaction — the same one that makes the position durable, so a head and
/// the position that chose it cannot disagree.
///
/// The post generation's leaves are the pre generation's with the state leaf
/// and the trader's relationship leaf replaced: a whole tree, because a
/// mixture of two generations is not one. The pre generation's own set
/// stays. At the genesis generation nothing is stored — its tree is exactly
/// the state leaf (SoFi §19.8), which the post state replaces.
pub fn record_resolved_with_conn(tx: &Transaction<'_>, post: &VaultPostState) -> Result<()> {
    // The previous set is read through the CALLER'S transaction, not a second
    // connection: the admit path already holds the connection mutex, and a
    // nested acquisition would deadlock rather than fail.
    let vault_id = post.vault_id();
    let state = post.state();
    let previous = rows_with_conn(tx, vault_id, post.pre_generation())?;
    let mut leaves: Vec<(D32, D32, i64, Vec<u8>)> = previous
        .iter()
        .filter(|(key, ..)| *key != derive::vault_state_key(vault_id))
        .cloned()
        .collect();
    leaves.push((
        derive::vault_state_key(vault_id),
        derive::vault_state_leaf_value(state).map_err(|e| anyhow!("state leaf value: {e}"))?,
        KIND_STATE,
        state.encode().map_err(|e| anyhow!("state leaf: {e}"))?,
    ));
    if let Some((key, leaf)) = post.relationship() {
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
    // asked about. The pre generation's row stands as it is (it was the post
    // of the consumption before, or the genesis); the post generation's row
    // records what it was built on and what consumed it. Idempotent:
    // re-resolving the same position writes the same two rows, and a
    // DIFFERENT root or link at an established generation is a
    // contradiction, refused, never an update.
    write_root(tx, vault_id, post.pre_generation(), post.pre_root(), None)?;
    write(
        tx,
        vault_id,
        post.generation(),
        post.root(),
        Some((post.pre_root(), post.consumed_by())),
        &leaves,
    )
}

/// One generation's row, as recorded.
struct RootRow {
    root: D32,
    pre_root: Option<D32>,
    consumed_by: Option<D32>,
}

fn root_row_with_conn(
    conn: &rusqlite::Connection,
    vault_id: &D32,
    generation: u64,
) -> Result<Option<RootRow>> {
    conn.query_row(
        "SELECT root, pre_root, consumed_by FROM sofi_vault_root
          WHERE vault_id = ?1 AND generation = ?2",
        params![
            vault_id.as_slice(),
            i64::try_from(generation).map_err(|e| anyhow!("generation overflow: {e}"))?
        ],
        |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Option<Vec<u8>>>(1)?,
                r.get::<_, Option<Vec<u8>>>(2)?,
            ))
        },
    )
    .optional()?
    .map(|(root, pre_root, consumed_by)| {
        Ok(RootRow {
            root: digest32(root, "vault root")?,
            pre_root: pre_root
                .map(|b| digest32(b, "vault pre root"))
                .transpose()?,
            consumed_by: consumed_by
                .map(|b| digest32(b, "consuming operation"))
                .transpose()?,
        })
    })
    .transpose()
}

/// Write generation `generation`'s root, with its link — the root it was
/// built on and the operation that consumed that root — when the caller
/// records a consumption. A row already there must agree: the same root,
/// and the same link or none recorded yet. `R*_g` is unique (a successor
/// cell admits one realized consumption per attempt key), so a second,
/// different answer at a generation is a contradiction, never an update.
fn write_root(
    tx: &Transaction<'_>,
    vault_id: &D32,
    generation: u64,
    root: &D32,
    link: Option<(&D32, &D32)>,
) -> Result<()> {
    let generation_i64 =
        i64::try_from(generation).map_err(|e| anyhow!("generation overflow: {e}"))?;
    match root_row_with_conn(tx, vault_id, generation)? {
        None => {
            tx.execute(
                "INSERT INTO sofi_vault_root (vault_id, generation, root, pre_root, consumed_by)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    vault_id.as_slice(),
                    generation_i64,
                    root.as_slice(),
                    link.map(|(pre, ..)| pre.as_slice()),
                    link.map(|(.., by)| by.as_slice()),
                ],
            )?;
            Ok(())
        }
        Some(existing) => {
            if existing.root != *root {
                return Err(anyhow!(
                    "generation {generation} of this vault already established another root"
                ));
            }
            let Some((pre_root, consumed_by)) = link else {
                return Ok(());
            };
            match (existing.pre_root, existing.consumed_by) {
                (None, None) => {
                    tx.execute(
                        "UPDATE sofi_vault_root SET pre_root = ?3, consumed_by = ?4
                          WHERE vault_id = ?1 AND generation = ?2",
                        params![
                            vault_id.as_slice(),
                            generation_i64,
                            pre_root.as_slice(),
                            consumed_by.as_slice()
                        ],
                    )?;
                    Ok(())
                }
                (Some(pre), Some(by)) if pre == *pre_root && by == *consumed_by => Ok(()),
                _ => Err(anyhow!(
                    "generation {generation} of this vault already records another consumption"
                )),
            }
        }
    }
}

fn write(
    tx: &Transaction<'_>,
    vault_id: &D32,
    generation: u64,
    root: &D32,
    link: Option<(&D32, &D32)>,
    leaves: &[(D32, D32, i64, Vec<u8>)],
) -> Result<()> {
    write_root(tx, vault_id, generation, root, link)?;
    let generation = i64::try_from(generation).map_err(|e| anyhow!("generation overflow: {e}"))?;
    tx.execute(
        "DELETE FROM sofi_vault_leaf WHERE vault_id = ?1 AND generation = ?2",
        params![vault_id.as_slice(), generation],
    )?;
    for (key, value, kind, preimage) in leaves {
        tx.execute(
            "INSERT INTO sofi_vault_leaf (vault_id, generation, leaf_key, leaf_value, kind, preimage)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                vault_id.as_slice(),
                generation,
                key.as_slice(),
                value.as_slice(),
                kind,
                preimage,
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
            generation: u64::try_from(generation)
                .map_err(|e| anyhow!("generation negative: {e}"))?,
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
    root_at_with_conn(&conn, vault_id, generation)
}

fn root_at_with_conn(
    conn: &rusqlite::Connection,
    vault_id: &D32,
    generation: u64,
) -> Result<Option<D32>> {
    conn.query_row(
        "SELECT root FROM sofi_vault_root WHERE vault_id = ?1 AND generation = ?2",
        params![
            vault_id.as_slice(),
            i64::try_from(generation).map_err(|e| anyhow!("generation overflow: {e}"))?
        ],
        |r| r.get::<_, Vec<u8>>(0),
    )
    .optional()?
    .map(|root| digest32(root, "vault root"))
    .transpose()
}

/// Record a post state the FORWARD WALK established (R14), in its own
/// transaction.
///
/// Same writer as the resolved path, deliberately. The walk is not a party to
/// the transition it records — it reconstructs another trader's realized
/// consumption — but it establishes it by the SAME predicate: Core classified
/// that attempt key `Consumed`, which is `resolve_position` over the whole
/// operation, and `vault_post_states` recomputed the post state rather than
/// reading back what the producer stated. Two callers, one writer, one
/// meaning for a row, and the writer refuses a different root or link at an
/// established generation (`write_root`).
pub fn record_walked(post: &VaultPostState) -> Result<()> {
    let binding = get_connection()?;
    let mut conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let tx = conn.transaction()?;
    record_resolved_with_conn(&tx, post)?;
    tx.commit()?;
    Ok(())
}

/// The generations this device recorded for `vault_id`, from generation
/// zero and contiguous, each with the link it recorded: what the verifier
/// anchors at the accepted genesis and checks link by link before it stands
/// on any of it (`VaultChain::from_recorded`). A gap ends the memo there.
pub fn recorded_generations(vault_id: &D32) -> Result<Vec<RecordedGenerationRow>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    recorded_generations_with_conn(&conn, vault_id)
}

fn recorded_generations_with_conn(
    conn: &rusqlite::Connection,
    vault_id: &D32,
) -> Result<Vec<RecordedGenerationRow>> {
    let mut rows = Vec::new();
    loop {
        let generation = u64::try_from(rows.len()).map_err(|e| anyhow!("generation: {e}"))?;
        let Some(row) = root_row_with_conn(conn, vault_id, generation)? else {
            return Ok(rows);
        };
        rows.push(RecordedGenerationRow {
            generation,
            root: row.root,
            pre_root: row.pre_root,
            consumed_by: row.consumed_by,
        });
    }
}

/// The stored leaves of a vault at one generation, as rows.
pub fn leaf_rows(vault_id: &D32, generation: u64) -> Result<Vec<(D32, D32, i64, Vec<u8>)>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    rows_with_conn(&conn, vault_id, generation)
}

fn rows_with_conn(
    conn: &rusqlite::Connection,
    vault_id: &D32,
    generation: u64,
) -> Result<Vec<(D32, D32, i64, Vec<u8>)>> {
    let generation = i64::try_from(generation).map_err(|e| anyhow!("generation overflow: {e}"))?;
    let mut stmt = conn.prepare(
        "SELECT leaf_key, leaf_value, kind, preimage FROM sofi_vault_leaf
          WHERE vault_id = ?1 AND generation = ?2",
    )?;
    let rows = stmt.query_map(params![vault_id.as_slice(), generation], |r| {
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

/// The vault's whole tree at its established head, rebuilt from every stored
/// leaf and CHECKED against the head's own root, with its state leaf: what a
/// producer builds `V°` against. `None` when no head is established, or the
/// record cannot reproduce its own root (another trader moved the vault
/// between this device's trades).
pub fn tree_at_head(vault_id: &D32) -> Result<Option<(VaultHead, EconomicSmt, VaultStateLeaf)>> {
    let Some(head) = head(vault_id)? else {
        return Ok(None);
    };
    let rows = leaf_rows(vault_id, head.generation)?;
    let mut tree = EconomicSmt::new();
    for (key, value, ..) in &rows {
        tree.insert(*key, *value);
    }
    if tree.root() != head.root {
        return Ok(None);
    }
    let state_key = derive::vault_state_key(vault_id);
    let state = match rows.iter().find(|(key, ..)| *key == state_key) {
        Some((.., kind, preimage)) if *kind == KIND_STATE => {
            VaultStateLeaf::decode(preimage).map_err(|e| anyhow!("state leaf: {e}"))?
        }
        Some(row) => return Err(anyhow!("the vault's state key holds leaf kind {}", row.2)),
        None => return Err(anyhow!("the vault's record holds no state leaf")),
    };
    Ok(Some((head, tree, state)))
}

/// The generation this verifier established `root` at for `vault_id`, if it
/// established one: the highest, when a generation repeats its
/// predecessor's root.
fn generation_of_with_conn(
    conn: &rusqlite::Connection,
    vault_id: &D32,
    root: &D32,
) -> Result<Option<u64>> {
    conn.query_row(
        "SELECT generation FROM sofi_vault_root WHERE vault_id = ?1 AND root = ?2
          ORDER BY generation DESC LIMIT 1",
        params![vault_id.as_slice(), root.as_slice()],
        |r| r.get::<_, i64>(0),
    )
    .optional()?
    .map(|g| u64::try_from(g).map_err(|e| anyhow!("generation negative: {e}")))
    .transpose()
}

/// The vault's leaves at the generation this verifier established `root`
/// at, for the keys an acquisition needs — CHECKED against that root. The
/// generation is whichever one the root names, not the head: an operation is
/// built on the generation it names, and this device may have walked past it
/// before it resolves that operation.
///
/// The cache is this device's own conclusions, so it proves nothing by
/// existing. The tree is rebuilt from every stored leaf and its root must
/// equal the recorded one; a record that cannot reproduce its own root is
/// incomplete (a vault another trader moved between our trades) and yields
/// `None`, so Core answers `Unavailable` and the position waits.
pub fn leaves_at(
    vault_id: &D32,
    root: &D32,
    keys: &std::collections::BTreeSet<D32>,
) -> Result<
    Option<(
        VaultHead,
        std::collections::BTreeMap<(D32, D32), VaultLeafPre>,
    )>,
> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let Some(generation) = generation_of_with_conn(&conn, vault_id, root)? else {
        return Ok(None);
    };
    let head = VaultHead {
        vault_id: *vault_id,
        generation,
        root: *root,
    };
    let rows = rows_with_conn(&conn, vault_id, generation)?;
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
            Some((.., kind, preimage)) if *kind == KIND_STATE => VaultLeafPre::State(
                VaultStateLeaf::decode(preimage).map_err(|e| anyhow!("state leaf: {e}"))?,
            ),
            Some((.., kind, preimage)) if *kind == KIND_RELATIONSHIP => VaultLeafPre::Relationship(
                VaultRelationshipLeaf::decode(preimage)
                    .map_err(|e| anyhow!("relationship leaf: {e}"))?,
            ),
            Some(row) => return Err(anyhow!("unknown vault leaf kind {}", row.2)),
            None => VaultLeafPre::Absent,
        };
        out.insert((*vault_id, *key), pre);
    }
    Ok(Some((head, out)))
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn db() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory db");
        super::super::create_schema(&conn).expect("the client schema");
        conn.execute_batch("PRAGMA foreign_keys = ON;").ok();
        conn
    }

    const V: D32 = [0x51; 32];
    const G0: D32 = [0xA0; 32];
    const R1: D32 = [0xA1; 32];
    const R2: D32 = [0xA2; 32];
    const E1: D32 = [0xE1; 32];
    const E2: D32 = [0xE2; 32];
    const OTHER: D32 = [0x77; 32];

    /// A recorded generation is written once and stands: the same root and
    /// link again is idempotent; a different root, or a different link, at
    /// an established generation is refused, never an update — `R*_g` is
    /// unique, and the record is this device's own memo of it.
    /// MUTATION CONTROL: a writer that updates on conflict turns this red.
    #[test]
    fn an_established_generation_is_never_rewritten() {
        let mut conn = db();
        let tx = conn.transaction().unwrap();
        write_root(&tx, &V, 0, &G0, None).unwrap();
        write_root(&tx, &V, 1, &R1, Some((&G0, &E1))).unwrap();
        // The same again: idempotent.
        write_root(&tx, &V, 0, &G0, None).unwrap();
        write_root(&tx, &V, 1, &R1, Some((&G0, &E1))).unwrap();
        // Another root at an established generation.
        assert!(write_root(&tx, &V, 1, &OTHER, Some((&G0, &E1))).is_err());
        assert!(write_root(&tx, &V, 0, &OTHER, None).is_err());
        // Another link at an established generation.
        assert!(write_root(&tx, &V, 1, &R1, Some((&OTHER, &E1))).is_err());
        assert!(write_root(&tx, &V, 1, &R1, Some((&G0, &E2))).is_err());
        // A pre-generation write of an established post generation leaves
        // its link as it is.
        write_root(&tx, &V, 1, &R1, None).unwrap();
        let row = root_row_with_conn(&tx, &V, 1).unwrap().unwrap();
        assert_eq!(
            (row.root, row.pre_root, row.consumed_by),
            (R1, Some(G0), Some(E1))
        );
        // A row first written without its link takes the link once.
        write_root(&tx, &V, 2, &R2, None).unwrap();
        write_root(&tx, &V, 2, &R2, Some((&R1, &E2))).unwrap();
        assert!(write_root(&tx, &V, 2, &R2, Some((&R1, &E1))).is_err());
        tx.commit().unwrap();
    }

    /// The memo is read from generation zero, contiguously, with the links
    /// each row recorded; a gap ends it there.
    #[test]
    fn the_recorded_generations_are_read_contiguously_with_their_links() {
        let mut conn = db();
        let tx = conn.transaction().unwrap();
        write_root(&tx, &V, 0, &G0, None).unwrap();
        write_root(&tx, &V, 1, &R1, Some((&G0, &E1))).unwrap();
        write_root(&tx, &V, 3, &R2, Some((&R1, &E2))).unwrap();
        tx.commit().unwrap();
        let rows = recorded_generations_with_conn(&conn, &V).unwrap();
        assert_eq!(
            rows,
            vec![
                RecordedGenerationRow {
                    generation: 0,
                    root: G0,
                    pre_root: None,
                    consumed_by: None
                },
                RecordedGenerationRow {
                    generation: 1,
                    root: R1,
                    pre_root: Some(G0),
                    consumed_by: Some(E1)
                },
            ],
            "generation 2 is not recorded, so the memo ends at 1"
        );
        assert!(recorded_generations_with_conn(&conn, &OTHER)
            .unwrap()
            .is_empty());
    }
}
