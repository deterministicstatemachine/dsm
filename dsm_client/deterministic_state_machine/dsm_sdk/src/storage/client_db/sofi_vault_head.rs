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
//! | `sofi_vault_leaf` | `(vault, generation, leaf_key) -> value + preimage` | every generation's state leaf, which the verifier reads as the state at a root it established (every other leaf an operation reads is proven by its core's path, SoFi Amendment S24), and the leaves this device saw, which rebuild the whole tree where it saw them all: an owner's record, from which it hands traders their witnesses |
//! | `sofi_vault_step` | `(vault, generation) -> bundle step` | what a checkpoint's bundle carries for each generation (SoFi Amendment S23): the attempt, `E`, the trader's `(G, DevID, q)` and the route's other legs, written with the generation's row; discovery only |
//! | `sofi_vault_witness` | `vault -> generation, root, witness` | this device's own witness at the generation it established last: the state leaf and its relationship leaf with their paths, advanced as each generation is recorded |
//! | `sofi_vault_baseline` | `vault -> generation, baseline` | the owner baseline a chain starts at, when it does not start at the genesis |
//!
//! **The record follows Core** (MR-DSM-0331). The rows are a cache of what
//! Core established and have no standing to block Core: where a generation
//! Core establishes meets a row that holds something else, the record from
//! that generation up — roots, leaves, bundle steps and a witness not under
//! Core's root there — is removed and Core's generation written, in one
//! transaction, and the replacement is returned by name
//! ([`ReplacedRecord`]). Nothing but a generation Core established
//! ([`VaultPostState`], which only Core hands out) replaces a row; every
//! lower writer refuses another value at a recorded generation.
//!
//! **A read is checked, never trusted.** The rows are a cache of this
//! device's own conclusions. A whole tree is rebuilt from them only by Core
//! (`sofi::frontier::vault_tree_at`), which binds every leaf and requires the
//! rows to recompute the root it is asked at — one Core's walk established —
//! which is exactly what detects an INCOMPLETE record; a witness is checked by Core against the root it is
//! read at before anything stands on it.
//!
//! This replaces the persistent node store R14 deleted. A node store returned
//! leaf VALUES; evidence needs the preimages, so the values alone could never
//! have served the next trade.
use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension, Transaction};

use dsm::shared_lineage::BundleStep;
use dsm::sofi::derive;
use dsm::sofi::frontier::VaultWitness;
use dsm::sofi::resolve::{Contradicted, ReplacedRecord};
use dsm::sofi::validation::VaultPostState;
use dsm::sofi::wire::{VaultFrontierV1, VaultFrontierWitnessV1, VaultStateLeaf};

use super::get_connection;

type D32 = [u8; 32];

const KIND_STATE: i64 = 0;
const KIND_RELATIONSHIP: i64 = 1;

fn digest32(v: Vec<u8>, what: &str) -> Result<D32> {
    <D32>::try_from(v.as_slice()).map_err(|e| anyhow!("{what} is not 32 bytes: {e}"))
}

/// One generation this device recorded for a vault: the root at that
/// generation and, past genesis, the root it was built on and the operation
/// that consumed it. A record says where a walk may read, never what holds:
/// Core's walk establishes every generation from the genesis or an adopted
/// baseline (MR-DSM-0331).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordedGenerationRow {
    pub generation: u64,
    pub root: D32,
    pub pre_root: Option<D32>,
    pub consumed_by: Option<D32>,
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
///
/// `post` is a generation Core established, and the record follows it: what
/// the record held that contradicts it is replaced, from the lowest
/// generation contradicted up, before it is written, and returned by name.
pub fn record_resolved_with_conn(
    tx: &Transaction<'_>,
    post: &VaultPostState,
) -> Result<Option<ReplacedRecord>> {
    // The previous set is read through the CALLER'S transaction, not a second
    // connection: the admit path already holds the connection mutex, and a
    // nested acquisition would deadlock rather than fail.
    let replaced = contradiction_with_conn(tx, &Establishes::of(post))?;
    if let Some(replaced) = &replaced {
        forget_from_with_conn(tx, replaced)?;
    }
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
    advance_witness_with_conn(tx, post)?;
    // BOTH ends of the link. A store that kept only post roots would hold a
    // set and not a chain, and `root_at(v, g)` is what a parent's status is
    // asked about. The pre generation's row stands as it is (it was the post
    // of the consumption before, or the genesis); the post generation's row
    // records what it was built on and what consumed it. Idempotent:
    // re-resolving the same position writes the same two rows. Whatever
    // contradicted them was removed above, so the writers below, which
    // refuse another value at a recorded generation, meet none.
    write_root(tx, vault_id, post.pre_generation(), post.pre_root(), None)?;
    write(
        tx,
        vault_id,
        post.generation(),
        post.root(),
        Some((post.pre_root(), post.consumed_by())),
        &leaves,
    )?;
    write_step(tx, vault_id, post.generation(), post.step())?;
    Ok(replaced)
}

/// What a generation Core established says of the record of its vault: the
/// root at the generation it was built on, and at its own generation the
/// root, the link and the bundle step. Built from a [`VaultPostState`] and
/// from nothing else outside this module's tests.
struct Establishes<'a> {
    vault_id: D32,
    pre_generation: u64,
    pre_root: D32,
    generation: u64,
    root: D32,
    consumed_by: D32,
    step: &'a BundleStep,
}

impl<'a> Establishes<'a> {
    fn of(post: &'a VaultPostState) -> Self {
        Self {
            vault_id: *post.vault_id(),
            pre_generation: post.pre_generation(),
            pre_root: *post.pre_root(),
            generation: post.generation(),
            root: *post.root(),
            consumed_by: *post.consumed_by(),
            step: post.step(),
        }
    }
}

/// The lowest generation at which this device's record of the vault holds
/// something other than what `established` says: another root at the
/// generation it was built on, or at its own generation another root,
/// another link or another bundle step. A row it does not reach is no
/// contradiction of it.
fn contradiction_with_conn(
    conn: &rusqlite::Connection,
    established: &Establishes<'_>,
) -> Result<Option<ReplacedRecord>> {
    let replaced = |generation: u64,
                    recorded_root: Option<D32>,
                    established_root: D32,
                    contradicted: Contradicted| ReplacedRecord {
        vault_id: established.vault_id,
        generation,
        recorded_root,
        established_root,
        contradicted,
    };
    let vault_id = established.vault_id;
    if let Some(row) = root_row_with_conn(conn, &vault_id, established.pre_generation)? {
        if row.root != established.pre_root {
            return Ok(Some(replaced(
                established.pre_generation,
                Some(row.root),
                established.pre_root,
                Contradicted::Root,
            )));
        }
    }
    let generation = established.generation;
    let row = root_row_with_conn(conn, &vault_id, generation)?;
    if let Some(row) = &row {
        if row.root != established.root {
            return Ok(Some(replaced(
                generation,
                Some(row.root),
                established.root,
                Contradicted::Root,
            )));
        }
        match (row.pre_root, row.consumed_by) {
            (None, None) => {}
            (Some(pre), Some(by))
                if pre == established.pre_root && by == established.consumed_by => {}
            _ => {
                return Ok(Some(replaced(
                    generation,
                    Some(row.root),
                    established.root,
                    Contradicted::Link,
                )))
            }
        }
    }
    Ok(match step_at_with_conn(conn, &vault_id, generation)? {
        Some(step) if step != *established.step => Some(replaced(
            generation,
            row.map(|row| row.root),
            established.root,
            Contradicted::Step,
        )),
        Some(..) | None => None,
    })
}

/// Remove this device's record of the vault from `replaced.generation` up —
/// its roots, leaves and bundle steps — and the witness kept there, unless
/// it is at that generation under the root Core established: what replacing
/// a contradicted record removes, in the caller's transaction, before
/// Core's generation is written.
fn forget_from_with_conn(tx: &Transaction<'_>, replaced: &ReplacedRecord) -> Result<()> {
    let vault_id = replaced.vault_id.as_slice();
    let from =
        i64::try_from(replaced.generation).map_err(|e| anyhow!("generation overflow: {e}"))?;
    tx.execute(
        "DELETE FROM sofi_vault_root WHERE vault_id = ?1 AND generation >= ?2",
        params![vault_id, from],
    )?;
    tx.execute(
        "DELETE FROM sofi_vault_leaf WHERE vault_id = ?1 AND generation >= ?2",
        params![vault_id, from],
    )?;
    tx.execute(
        "DELETE FROM sofi_vault_step WHERE vault_id = ?1 AND generation >= ?2",
        params![vault_id, from],
    )?;
    tx.execute(
        "DELETE FROM sofi_vault_witness
          WHERE vault_id = ?1 AND (generation > ?2 OR (generation = ?2 AND root != ?3))",
        params![vault_id, from, replaced.established_root.as_slice()],
    )?;
    Ok(())
}

/// The step columns of a vault generation: attempt, `E`, `G`, `DevID`, `q`
/// and the sibling pairs, concatenated.
type StepColumns = (i64, D32, D32, D32, i64, Vec<u8>);

fn step_columns(step: &BundleStep) -> Result<StepColumns> {
    let BundleStep::Vault {
        attempt,
        external_commitment,
        trader_genesis,
        trader_device_id,
        trader_position,
        siblings,
    } = step
    else {
        return Err(anyhow!("a vault generation's step is a reserve step"));
    };
    let mut pairs = Vec::with_capacity(siblings.len() * 64);
    for (vault, parent_root) in siblings {
        pairs.extend_from_slice(vault);
        pairs.extend_from_slice(parent_root);
    }
    Ok((
        i64::try_from(*attempt).map_err(|e| anyhow!("attempt overflow: {e}"))?,
        *external_commitment,
        *trader_genesis,
        *trader_device_id,
        i64::try_from(*trader_position).map_err(|e| anyhow!("position overflow: {e}"))?,
        pairs,
    ))
}

fn step_of(columns: StepColumns) -> Result<BundleStep> {
    let (attempt, external_commitment, trader_genesis, trader_device_id, position, pairs) = columns;
    let mut siblings = Vec::with_capacity(pairs.len() / 64);
    for pair in pairs.chunks(64) {
        let (vault, parent_root) = pair.split_at(32);
        siblings.push((
            digest32(vault.to_vec(), "sibling vault")?,
            digest32(parent_root.to_vec(), "sibling parent root")?,
        ));
    }
    Ok(BundleStep::Vault {
        attempt: u64::try_from(attempt).map_err(|e| anyhow!("attempt negative: {e}"))?,
        external_commitment,
        trader_genesis,
        trader_device_id,
        trader_position: u64::try_from(position).map_err(|e| anyhow!("position negative: {e}"))?,
        siblings,
    })
}

/// Write generation `generation`'s bundle step. A step already recorded
/// there must be the same one: one consumption per generation, so another
/// step is a contradiction, never an update.
fn write_step(
    tx: &Transaction<'_>,
    vault_id: &D32,
    generation: u64,
    step: &BundleStep,
) -> Result<()> {
    let generation_i64 =
        i64::try_from(generation).map_err(|e| anyhow!("generation overflow: {e}"))?;
    let (attempt, e, genesis, device_id, position, siblings) = step_columns(step)?;
    let inserted = tx.execute(
        "INSERT OR IGNORE INTO sofi_vault_step (vault_id, generation, attempt,
             external_commitment, trader_genesis, trader_device_id, trader_position, siblings)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            vault_id.as_slice(),
            generation_i64,
            attempt,
            e.as_slice(),
            genesis.as_slice(),
            device_id.as_slice(),
            position,
            siblings,
        ],
    )?;
    if inserted == 1 {
        return Ok(());
    }
    match step_at_with_conn(tx, vault_id, generation)? {
        Some(recorded) if recorded == *step => Ok(()),
        _ => Err(anyhow!(
            "generation {generation} of this vault already records another step"
        )),
    }
}

/// The bundle step this device recorded at `generation` of `vault_id`.
fn step_at_with_conn(
    conn: &rusqlite::Connection,
    vault_id: &D32,
    generation: u64,
) -> Result<Option<BundleStep>> {
    conn.query_row(
        "SELECT attempt, external_commitment, trader_genesis, trader_device_id,
                trader_position, siblings
           FROM sofi_vault_step WHERE vault_id = ?1 AND generation = ?2",
        params![
            vault_id.as_slice(),
            i64::try_from(generation).map_err(|e| anyhow!("generation overflow: {e}"))?
        ],
        |r| {
            Ok((
                r.get::<_, i64>(0)?,
                super::column_32(r, 1)?,
                super::column_32(r, 2)?,
                super::column_32(r, 3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, Vec<u8>>(5)?,
            ))
        },
    )
    .optional()?
    .map(step_of)
    .transpose()
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
/// meaning for a row: what Core established, replacing what contradicts it
/// and naming the replacement.
pub fn record_walked(post: &VaultPostState) -> Result<Option<ReplacedRecord>> {
    let binding = get_connection()?;
    let mut conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let tx = conn.transaction()?;
    let replaced = record_resolved_with_conn(&tx, post)?;
    tx.commit()?;
    Ok(replaced)
}

/// The generations this device recorded for `vault_id`, from the lowest it
/// recorded and contiguous, each with the link it recorded: where a walk
/// may read ahead, and nothing a walk stands on. A gap ends the record
/// there.
pub fn recorded_generations(vault_id: &D32) -> Result<Vec<RecordedGenerationRow>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    recorded_generations_with_conn(&conn, vault_id)
}

fn recorded_generations_with_conn(
    conn: &rusqlite::Connection,
    vault_id: &D32,
) -> Result<Vec<RecordedGenerationRow>> {
    let mut stmt = conn.prepare(
        "SELECT generation, root, pre_root, consumed_by FROM sofi_vault_root
          WHERE vault_id = ?1 ORDER BY generation ASC",
    )?;
    let read = stmt.query_map(params![vault_id.as_slice()], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, Vec<u8>>(1)?,
            r.get::<_, Option<Vec<u8>>>(2)?,
            r.get::<_, Option<Vec<u8>>>(3)?,
        ))
    })?;
    let mut rows: Vec<RecordedGenerationRow> = Vec::new();
    for row in read {
        let (generation, root, pre_root, consumed_by) = row?;
        let generation = u64::try_from(generation).map_err(|e| anyhow!("generation: {e}"))?;
        // Contiguous from the lowest: a gap ends the memo there.
        if let Some(last) = rows.last() {
            if generation != last.generation + 1 {
                break;
            }
        }
        rows.push(RecordedGenerationRow {
            generation,
            root: digest32(root, "vault root")?,
            pre_root: pre_root
                .map(|b| digest32(b, "vault pre root"))
                .transpose()?,
            consumed_by: consumed_by
                .map(|b| digest32(b, "consuming operation"))
                .transpose()?,
        });
    }
    Ok(rows)
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

/// The vault's state leaf at the generation this verifier established `root`
/// at: the highest such generation, when a generation repeats its
/// predecessor's root. `None` when it established no generation there.
pub fn state_at(vault_id: &D32, root: &D32) -> Result<Option<VaultStateLeaf>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("vault head: the store is poisoned: {e}"))?;
    let Some(generation) = generation_of_with_conn(&conn, vault_id, root)? else {
        return Ok(None);
    };
    let state_key = derive::vault_state_key(vault_id);
    match rows_with_conn(&conn, vault_id, generation)?
        .into_iter()
        .find(|(key, ..)| *key == state_key)
    {
        Some((.., kind, preimage)) if kind == KIND_STATE => Ok(Some(
            VaultStateLeaf::decode(&preimage).map_err(|e| anyhow!("state leaf: {e}"))?,
        )),
        Some((.., kind, _)) => Err(anyhow!("the vault's state key holds leaf kind {kind}")),
        None => Ok(None),
    }
}

/// This device's recorded witness of a vault, as stored: the generation and
/// root it is at, the trader it is for, and its wire bytes, decoded.
pub struct RecordedWitness {
    pub generation: u64,
    pub root: D32,
    pub trader_genesis: D32,
    pub trader_device_id: D32,
    pub witness: VaultFrontierWitnessV1,
}

fn witness_with_conn(
    conn: &rusqlite::Connection,
    vault_id: &D32,
) -> Result<Option<RecordedWitness>> {
    conn.query_row(
        "SELECT generation, root, trader_genesis, trader_device_id, witness
           FROM sofi_vault_witness WHERE vault_id = ?1",
        params![vault_id.as_slice()],
        |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, Vec<u8>>(4)?,
            ))
        },
    )
    .optional()?
    .map(|(generation, root, genesis, device, witness)| {
        Ok(RecordedWitness {
            generation: u64::try_from(generation)
                .map_err(|e| anyhow!("witness generation: {e}"))?,
            root: digest32(root, "witness root")?,
            trader_genesis: digest32(genesis, "witness trader")?,
            trader_device_id: digest32(device, "witness device")?,
            witness: VaultFrontierWitnessV1::decode(&witness)
                .map_err(|e| anyhow!("witness: {e}"))?,
        })
    })
    .transpose()
}

/// This device's recorded witness of `vault_id`, if it keeps one.
pub fn witness(vault_id: &D32) -> Result<Option<RecordedWitness>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("vault head: the store is poisoned: {e}"))?;
    witness_with_conn(&conn, vault_id)
}

fn put_witness_with_conn(conn: &rusqlite::Connection, witness: &VaultWitness) -> Result<()> {
    let (genesis, device) = witness.trader();
    conn.execute(
        "INSERT OR REPLACE INTO sofi_vault_witness
            (vault_id, generation, root, trader_genesis, trader_device_id, witness)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            witness.vault_id().as_slice(),
            i64::try_from(witness.generation()).map_err(|e| anyhow!("generation: {e}"))?,
            witness.root().as_slice(),
            genesis.as_slice(),
            device.as_slice(),
            witness
                .to_wire()
                .encode()
                .map_err(|e| anyhow!("witness: {e}"))?,
        ],
    )?;
    Ok(())
}

/// Keep `witness` as this device's witness of its vault.
pub fn put_witness(witness: &VaultWitness) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("vault head: the store is poisoned: {e}"))?;
    put_witness_with_conn(&conn, witness)
}

/// Advance this device's witness through `post`, when it is kept at the
/// generation `post` was built on; a witness at another generation is left
/// as it is. A witness at that generation that Core refuses to advance is an
/// authenticated contradiction — both are this device's own conclusions,
/// and they disagree — so the vault is quarantined for this device in the
/// same transaction, the witness kept as it was, and nothing falls back.
fn advance_witness_with_conn(tx: &Transaction<'_>, post: &VaultPostState) -> Result<()> {
    let Some(held) = witness_with_conn(tx, post.vault_id())? else {
        return Ok(());
    };
    if held.generation != post.pre_generation() || held.root != *post.pre_root() {
        return Ok(());
    }
    match VaultWitness::advance_recorded(
        &held.witness,
        held.trader_genesis,
        held.trader_device_id,
        post,
    ) {
        Ok(advanced) => put_witness_with_conn(tx, &advanced),
        Err(refused) => quarantine_with_conn(
            tx,
            post.vault_id(),
            &format!(
                "the recorded witness at generation {} does not advance through the \
                 generation Core recomputed: {refused}",
                held.generation
            ),
        ),
    }
}

/// What adopting an owner baseline did to this device's record of its vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineAdoption {
    /// The record starts at the baseline now, and holds no generation below
    /// it.
    Adopted,
    /// The record already starts at a baseline at this generation or a later
    /// one: this one is not the latest, and is not taken. Nothing is refused
    /// or decided about it.
    NotLater { held: u64 },
    /// The record holds another root at the baseline's generation. Two
    /// authenticated roots at one generation: nothing is replaced and
    /// nothing is decided, and the record is kept as it is. A record a walk
    /// heals takes the baseline after.
    Contradicted { held_root: D32 },
}

/// Start `vault_id`'s record at an owner baseline Core authenticated, when it
/// is later than the one the record starts at (MR-DSM-0331: the latest
/// authenticated owner baseline): the baseline's generation and root, its
/// state leaf where the record holds no row there, the baseline's bytes
/// (authenticated again whenever the chain starts there) and this device's
/// witness under its root, unless the record keeps a later one. A reader
/// holding a baseline holds no generation below it, so every row below is
/// removed. All in one transaction; a record that contradicts the baseline
/// at its generation is kept as it is.
pub fn adopt_baseline(witness: &VaultWitness, bundle: &[u8]) -> Result<BaselineAdoption> {
    let binding = get_connection()?;
    let mut conn = binding
        .lock()
        .map_err(|e| anyhow!("vault head: the store is poisoned: {e}"))?;
    let tx = conn.transaction()?;
    let vault_id = witness.vault_id();
    let generation = witness.generation();
    let generation_i64 = i64::try_from(generation).map_err(|e| anyhow!("generation: {e}"))?;
    let held: Option<i64> = tx
        .query_row(
            "SELECT generation FROM sofi_vault_baseline WHERE vault_id = ?1",
            params![vault_id.as_slice()],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(held) = held {
        if held >= generation_i64 {
            return Ok(BaselineAdoption::NotLater {
                held: u64::try_from(held).map_err(|e| anyhow!("held baseline: {e}"))?,
            });
        }
    }
    let row = root_row_with_conn(&tx, vault_id, generation)?;
    if let Some(row) = &row {
        if row.root != *witness.root() {
            return Ok(BaselineAdoption::Contradicted {
                held_root: row.root,
            });
        }
    }
    for table in ["sofi_vault_root", "sofi_vault_leaf", "sofi_vault_step"] {
        tx.execute(
            &format!("DELETE FROM {table} WHERE vault_id = ?1 AND generation < ?2"),
            params![vault_id.as_slice(), generation_i64],
        )?;
    }
    if row.is_none() {
        let state = witness.state();
        write(
            &tx,
            vault_id,
            generation,
            witness.root(),
            None,
            &[(
                derive::vault_state_key(vault_id),
                derive::vault_state_leaf_value(state)
                    .map_err(|e| anyhow!("state leaf value: {e}"))?,
                KIND_STATE,
                state.encode().map_err(|e| anyhow!("state leaf: {e}"))?,
            )],
        )?;
    }
    tx.execute(
        "INSERT OR REPLACE INTO sofi_vault_baseline (vault_id, generation, bundle)
         VALUES (?1, ?2, ?3)",
        params![vault_id.as_slice(), generation_i64, bundle],
    )?;
    // This device's own witness stands when it is past the baseline: it was
    // advanced by the generations Core established after it.
    let keeps_later = witness_with_conn(&tx, vault_id)?.is_some_and(|held| {
        held.generation > generation
            && (&held.trader_genesis, &held.trader_device_id) == witness.trader()
    });
    if !keeps_later {
        put_witness_with_conn(&tx, witness)?;
    }
    tx.commit()?;
    Ok(BaselineAdoption::Adopted)
}

/// The baseline `vault_id`'s record starts at, as adopted: its generation
/// and bytes.
pub fn baseline(vault_id: &D32) -> Result<Option<(u64, Vec<u8>)>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("vault head: the store is poisoned: {e}"))?;
    conn.query_row(
        "SELECT generation, bundle FROM sofi_vault_baseline WHERE vault_id = ?1",
        params![vault_id.as_slice()],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
    )
    .optional()?
    .map(|(generation, bundle)| {
        Ok((
            u64::try_from(generation).map_err(|e| anyhow!("baseline generation: {e}"))?,
            bundle,
        ))
    })
    .transpose()
}

/// The baseline this device signed as `vault_id`'s owner at `generation`.
pub fn owner_baseline(vault_id: &D32, generation: u64) -> Result<Option<Vec<u8>>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("vault head: the store is poisoned: {e}"))?;
    Ok(conn
        .query_row(
            "SELECT bundle FROM sofi_vault_owner_baseline WHERE vault_id = ?1 AND generation = ?2",
            params![
                vault_id.as_slice(),
                i64::try_from(generation).map_err(|e| anyhow!("generation: {e}"))?
            ],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()?)
}

/// Keep the baseline this device signed as `vault_id`'s owner at
/// `generation`. One per generation: the owner signs one frontier there.
pub fn put_owner_baseline(vault_id: &D32, generation: u64, bundle: &[u8]) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("vault head: the store is poisoned: {e}"))?;
    conn.execute(
        "INSERT OR IGNORE INTO sofi_vault_owner_baseline (vault_id, generation, bundle)
         VALUES (?1, ?2, ?3)",
        params![
            vault_id.as_slice(),
            i64::try_from(generation).map_err(|e| anyhow!("generation: {e}"))?,
            bundle
        ],
    )?;
    Ok(())
}

/// How far this device, as `vault_id`'s owner, published its history (SoFi
/// Amendment S26): every leaf, node and state leaf up to that generation.
pub fn history_published(vault_id: &D32) -> Result<Option<u64>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("vault head: the store is poisoned: {e}"))?;
    conn.query_row(
        "SELECT generation FROM sofi_vault_history_published WHERE vault_id = ?1",
        params![vault_id.as_slice()],
        |r| r.get::<_, i64>(0),
    )
    .optional()?
    .map(|g| u64::try_from(g).map_err(|e| anyhow!("history generation: {e}")))
    .transpose()
}

/// Record that `vault_id`'s history is published up to `generation`.
pub fn put_history_published(vault_id: &D32, generation: u64) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("vault head: the store is poisoned: {e}"))?;
    conn.execute(
        "INSERT INTO sofi_vault_history_published (vault_id, generation) VALUES (?1, ?2)
         ON CONFLICT(vault_id) DO UPDATE SET generation = max(generation, excluded.generation)",
        params![
            vault_id.as_slice(),
            i64::try_from(generation).map_err(|e| anyhow!("generation: {e}"))?
        ],
    )?;
    Ok(())
}

/// The frontier a stored `VaultBaselineV1` carries, or why this build does
/// not decode it.
fn stored_frontier(bundle: &[u8]) -> std::result::Result<VaultFrontierV1, String> {
    use prost::Message;
    crate::generated::VaultBaselineV1::decode(bundle)
        .map_err(|e| e.to_string())
        .and_then(|baseline| {
            VaultFrontierV1::decode(&baseline.frontier_ccb).map_err(|e| e.to_string())
        })
}

/// SoFi Amendment S26 put a history root in the frontier, so a baseline
/// signed before it no longer decodes. A record this device started at such
/// a baseline is dropped whole — its rows, leaves, witness and baseline —
/// and the vault is adopted again from a current baseline; a baseline this
/// device signed as owner is dropped and signed again when next offered.
/// Nothing else is touched.
pub(crate) fn drop_superseded_baselines(conn: &rusqlite::Connection) -> Result<()> {
    let adopted: Vec<(Vec<u8>, Vec<u8>)> = {
        let mut stmt = conn.prepare("SELECT vault_id, bundle FROM sofi_vault_baseline")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    for (vault_id, bundle) in adopted {
        let Err(why) = stored_frontier(&bundle) else {
            continue;
        };
        for table in [
            "sofi_vault_leaf",
            "sofi_vault_root",
            "sofi_vault_witness",
            "sofi_vault_baseline",
        ] {
            conn.execute(
                &format!("DELETE FROM {table} WHERE vault_id = ?1"),
                params![vault_id],
            )?;
        }
        log::info!("[vault head] a record started at a superseded baseline was dropped: {why}");
    }
    let signed: Vec<(Vec<u8>, i64, Vec<u8>)> = {
        let mut stmt =
            conn.prepare("SELECT vault_id, generation, bundle FROM sofi_vault_owner_baseline")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    for (vault_id, generation, bundle) in signed {
        let Err(why) = stored_frontier(&bundle) else {
            continue;
        };
        conn.execute(
            "DELETE FROM sofi_vault_owner_baseline WHERE vault_id = ?1 AND generation = ?2",
            params![vault_id, generation],
        )?;
        log::info!("[vault head] a superseded owner baseline was dropped: {why}");
    }
    Ok(())
}

/// The longest name an account keeps for one of its vaults.
pub const LABEL_MAX: usize = 128;

/// Keep `label` as this account's own name for the vault it created (owner
/// bookkeeping: carried nowhere, never read for validity). A vault keeps the
/// name it was given first.
pub fn put_label(vault_id: &D32, label: &str) -> Result<()> {
    if label.len() > LABEL_MAX {
        return Err(anyhow!("a vault label is at most {LABEL_MAX} bytes"));
    }
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("vault head: the store is poisoned: {e}"))?;
    conn.execute(
        "INSERT OR IGNORE INTO sofi_vault_label (vault_id, label) VALUES (?1, ?2)",
        params![vault_id.as_slice(), label],
    )?;
    Ok(())
}

/// This account's own name for `vault_id`, if it gave one.
pub fn label(vault_id: &D32) -> Result<Option<String>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("vault head: the store is poisoned: {e}"))?;
    Ok(conn
        .query_row(
            "SELECT label FROM sofi_vault_label WHERE vault_id = ?1",
            params![vault_id.as_slice()],
            |r| r.get::<_, String>(0),
        )
        .optional()?)
}

/// Why `vault_id` is quarantined for this device, if it is.
pub fn quarantined(vault_id: &D32) -> Result<Option<String>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("vault head: the store is poisoned: {e}"))?;
    Ok(conn
        .query_row(
            "SELECT why FROM sofi_vault_quarantine WHERE vault_id = ?1",
            params![vault_id.as_slice()],
            |r| r.get::<_, String>(0),
        )
        .optional()?)
}

/// Quarantine `vault_id` for this device (SoFi Req 6.3): its owner signed two
/// frontiers at one generation.
pub fn quarantine(vault_id: &D32, why: &str) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("vault head: the store is poisoned: {e}"))?;
    quarantine_with_conn(&conn, vault_id, why)
}

fn quarantine_with_conn(conn: &rusqlite::Connection, vault_id: &D32, why: &str) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO sofi_vault_quarantine (vault_id, why) VALUES (?1, ?2)",
        params![vault_id.as_slice(), why],
    )?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use rusqlite::Connection;
    use std::collections::BTreeMap;

    /// The bundle steps `vault` records at generations 0 to 3.
    fn steps_of(conn: &Connection, vault: &D32) -> BTreeMap<u64, BundleStep> {
        (0..=3)
            .filter_map(|g| {
                step_at_with_conn(conn, vault, g)
                    .unwrap()
                    .map(|step| (g, step))
            })
            .collect()
    }

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

    /// A recorded generation is written once by these writers: the same root
    /// and link again is idempotent; a different root, or a different link,
    /// at a recorded generation is refused, never an update — `R*_g` is
    /// unique. A row is replaced only as the record follows a generation
    /// Core established (`record_resolved_with_conn`, MR-DSM-0331).
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

    /// SoFi Amendment S23 (MR-SOFI-0399): a generation's bundle step is
    /// recorded once and read back exactly — attempt, `E`, trader, position
    /// and every sibling pair in order; the same step again is idempotent.
    /// Another step at a recorded generation is refused by the writer, and
    /// replaced only by what Core establishes (MR-DSM-0331): a generation
    /// Core established with another step there names the contradiction,
    /// and the record from there up gives way to it.
    /// MUTATION CONTROL: a writer that ignores a conflicting step, or a
    /// contradicted step left unnamed, turns this red.
    #[test]
    fn a_generations_bundle_step_is_replaced_only_by_what_core_establishes() {
        let step = |attempt: u64, e: D32| BundleStep::Vault {
            attempt,
            external_commitment: e,
            trader_genesis: [0x61; 32],
            trader_device_id: [0x62; 32],
            trader_position: 9,
            siblings: vec![([0x53; 32], [0x54; 32]), ([0x55; 32], [0x56; 32])],
        };
        let mut conn = db();
        let tx = conn.transaction().unwrap();
        write_step(&tx, &V, 1, &step(4, E1)).unwrap();
        write_step(&tx, &V, 2, &step(0, E2)).unwrap();
        write_step(&tx, &V, 1, &step(4, E1)).unwrap();
        let Err(conflict) = write_step(&tx, &V, 1, &step(5, E1)) else {
            panic!("another attempt at a recorded generation was taken");
        };
        assert!(conflict.to_string().contains("another step"), "{conflict}");
        let Err(reserve) = write_step(
            &tx,
            &V,
            3,
            &BundleStep::Reserve {
                release_evidence_addr: E2,
            },
        ) else {
            panic!("a reserve step was recorded for a vault");
        };
        assert!(reserve.to_string().contains("reserve step"), "{reserve}");
        tx.commit().unwrap();
        assert_eq!(
            steps_of(&conn, &V),
            BTreeMap::from([(1, step(4, E1)), (2, step(0, E2))])
        );
        assert_eq!(steps_of(&conn, &OTHER), BTreeMap::new());

        // Core established generation 1 on the same root and link, by
        // attempt 5: the step recorded there is contradicted, and named.
        let tx = conn.transaction().unwrap();
        write_root(&tx, &V, 0, &G0, None).unwrap();
        write_root(&tx, &V, 1, &R1, Some((&G0, &E1))).unwrap();
        let core_step = step(5, E1);
        let established = Establishes {
            vault_id: V,
            pre_generation: 0,
            pre_root: G0,
            generation: 1,
            root: R1,
            consumed_by: E1,
            step: &core_step,
        };
        let Some(replaced) = contradiction_with_conn(&tx, &established).unwrap() else {
            panic!("the contradicted step went unnamed");
        };
        assert_eq!(
            replaced,
            ReplacedRecord {
                vault_id: V,
                generation: 1,
                recorded_root: Some(R1),
                established_root: R1,
                contradicted: Contradicted::Step,
            }
        );
        forget_from_with_conn(&tx, &replaced).unwrap();
        write_root(&tx, &V, 1, &R1, Some((&G0, &E1))).unwrap();
        write_step(&tx, &V, 1, &core_step).unwrap();
        tx.commit().unwrap();
        assert_eq!(
            steps_of(&conn, &V),
            BTreeMap::from([(1, core_step.clone())]),
            "Core's step at 1, and nothing recorded above it"
        );
        assert_eq!(
            contradiction_with_conn(&conn, &established).unwrap(),
            None,
            "the record now follows what Core established"
        );
    }

    /// MR-DSM-0331: the record is a cache of what Core established and has
    /// no standing to block it. Where it contradicts a generation Core
    /// established — another root at the generation it was built on, or at
    /// its own another root or link — the lowest generation contradicted is
    /// named with the root recorded there and the root Core established, and
    /// the record from there up, roots, leaves, steps and a witness not under
    /// Core's root there, is removed. What lies below stays; agreement, and a
    /// generation the record holds nothing at, name nothing.
    /// MUTATION CONTROL: removing only the contradicted generation, or
    /// keeping a witness above it, turns this red.
    #[test]
    fn a_contradicted_record_gives_way_from_the_lowest_generation_contradicted_up() {
        const R3: D32 = [0xA3; 32];
        const X2: D32 = [0xB2; 32];
        const E3: D32 = [0xE3; 32];
        let step = |attempt: u64, e: D32| BundleStep::Vault {
            attempt,
            external_commitment: e,
            trader_genesis: [0x61; 32],
            trader_device_id: [0x62; 32],
            trader_position: 9,
            siblings: Vec::new(),
        };
        let leaf = |g: u8| vec![([0x40 + g; 32], [0x50 + g; 32], KIND_STATE, vec![g])];
        let record = |conn: &mut Connection, witness_at: (i64, D32)| {
            let tx = conn.transaction().unwrap();
            for table in [
                "sofi_vault_root",
                "sofi_vault_leaf",
                "sofi_vault_step",
                "sofi_vault_witness",
            ] {
                tx.execute(&format!("DELETE FROM {table}"), []).unwrap();
            }
            write_root(&tx, &V, 0, &G0, None).unwrap();
            write(&tx, &V, 1, &R1, Some((&G0, &E1)), &leaf(1)).unwrap();
            write(&tx, &V, 2, &R2, Some((&R1, &E2)), &leaf(2)).unwrap();
            write(&tx, &V, 3, &R3, Some((&R2, &E3)), &leaf(3)).unwrap();
            for (g, e) in [(1, E1), (2, E2), (3, E3)] {
                write_step(&tx, &V, g, &step(g, e)).unwrap();
            }
            tx.execute(
                "INSERT INTO sofi_vault_witness
                    (vault_id, generation, root, trader_genesis, trader_device_id, witness)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    V.as_slice(),
                    witness_at.0,
                    witness_at.1.as_slice(),
                    [0x61u8; 32].as_slice(),
                    [0x62u8; 32].as_slice(),
                    [0x07u8].as_slice()
                ],
            )
            .unwrap();
            tx.commit().unwrap();
        };
        let held = |conn: &Connection, table: &str| -> Vec<i64> {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT DISTINCT generation FROM {table} WHERE vault_id = ?1 ORDER BY 1"
                ))
                .unwrap();
            stmt.query_map(params![V.as_slice()], |r| r.get(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<i64>>>()
                .unwrap()
        };
        let mut conn = db();
        let core_step = step(2, E2);
        let at_two = |root: D32| Establishes {
            vault_id: V,
            pre_generation: 1,
            pre_root: R1,
            generation: 2,
            root,
            consumed_by: E2,
            step: &core_step,
        };

        // Another root at 2: named, and 2 and 3 removed with their witness.
        record(&mut conn, (3, R3));
        let Some(replaced) = contradiction_with_conn(&conn, &at_two(X2)).unwrap() else {
            panic!("another root at an established generation went unnamed");
        };
        assert_eq!(
            replaced,
            ReplacedRecord {
                vault_id: V,
                generation: 2,
                recorded_root: Some(R2),
                established_root: X2,
                contradicted: Contradicted::Root,
            }
        );
        let tx = conn.transaction().unwrap();
        forget_from_with_conn(&tx, &replaced).unwrap();
        tx.commit().unwrap();
        assert_eq!(held(&conn, "sofi_vault_root"), vec![0, 1]);
        assert_eq!(held(&conn, "sofi_vault_leaf"), vec![1]);
        assert_eq!(held(&conn, "sofi_vault_step"), vec![1]);
        assert_eq!(held(&conn, "sofi_vault_witness"), Vec::<i64>::new());

        // A witness at the contradicted generation under the root recorded
        // there goes; one under Core's root there, or below, stays.
        for (witness_at, kept) in [
            ((2, R2), Vec::<i64>::new()),
            ((2, X2), vec![2]),
            ((1, R1), vec![1]),
        ] {
            record(&mut conn, witness_at);
            let tx = conn.transaction().unwrap();
            forget_from_with_conn(&tx, &replaced).unwrap();
            tx.commit().unwrap();
            assert_eq!(
                held(&conn, "sofi_vault_witness"),
                kept,
                "witness at {witness_at:?}"
            );
        }

        // Another root at the generation Core built on: named there.
        record(&mut conn, (1, R1));
        let built_on_other = Establishes {
            pre_root: X2,
            ..at_two(R2)
        };
        assert_eq!(
            contradiction_with_conn(&conn, &built_on_other).unwrap(),
            Some(ReplacedRecord {
                vault_id: V,
                generation: 1,
                recorded_root: Some(R1),
                established_root: X2,
                contradicted: Contradicted::Root,
            })
        );
        // The same root at 2 by another consumption: the link is named.
        let other_link = Establishes {
            consumed_by: E3,
            ..at_two(R2)
        };
        assert_eq!(
            contradiction_with_conn(&conn, &other_link)
                .unwrap()
                .map(|r| (r.generation, r.contradicted)),
            Some((2, Contradicted::Link))
        );
        // Agreement names nothing, and nor does a generation not recorded.
        assert_eq!(contradiction_with_conn(&conn, &at_two(R2)).unwrap(), None);
        let beyond = Establishes {
            pre_generation: 3,
            pre_root: R3,
            generation: 4,
            ..at_two(X2)
        };
        assert_eq!(contradiction_with_conn(&conn, &beyond).unwrap(), None);
    }
}
