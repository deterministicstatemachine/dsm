// SPDX-License-Identifier: MIT OR Apache-2.0
//! ADR 0003 step 3: the recipient's durable staging area — recognized objects
//! only.
//!
//! > **Transport may be multi-message; acceptance remains atomic.**
//!
//! A split transfer arrives as two independent artifacts: the small signed
//! transfer, and the ~118 KB A-side receipt. Neither alone authorises
//! anything. Nothing reaches these tables except through the ingestion
//! boundary (`handlers::recipient_dispatch`), which writes an object only
//! after verifying it: a transfer's SIG A under the stored key of the contact
//! it came from, a receipt's signature chain for (that contact, this device).
//! The bytes stored are the signed material itself, never a wrapper around it.
//!
//! Three identities are kept apart, each with one job:
//!
//! 1. **What an object is.** A transfer by its op id (the signed operation
//!    bytes, signature included — the bytes the receipt's child tip consumes),
//!    a receipt by its commitment, a pair by both. Staging keys, dedup and
//!    binding use these and nothing else. Two copies of one object are one row,
//!    so arrival order decides nothing.
//! 2. **Which step it would take.** `(relationship, parent)` and the nonce.
//!    Decided only by the canonical apply (`canonical_apply_identity`,
//!    `spent_nonces`). Staging never compares objects to settle a conflict;
//!    it reads the apply's decision to know an object can no longer execute.
//! 3. **What the spool showed.** The address and message id each copy was read
//!    under, and a transfer copy's economic locator hints. Observations, for
//!    dedup, polling and collection only — never an identity, never a verdict.
//!
//! There is no rejected state. A transfer that does not execute changes no
//! state and records nothing negative (DSM Amendment A1, MR-DSM-0018).

use std::sync::{Mutex, MutexGuard};

use anyhow::{anyhow, Result};
use rusqlite::{params, Connection, OptionalExtension};

use super::get_connection;

/// A poisoned lock means a thread panicked while holding the store; the
/// caller is told, as `get_connection` does for its own lock.
fn lock(binding: &Mutex<Connection>) -> Result<MutexGuard<'_, Connection>> {
    binding
        .lock()
        .map_err(|e| anyhow!("recipient_staging: the client store lock is poisoned: {e}"))
}

/// Column `col` of a row, which must hold exactly 32 bytes.
fn col32(r: &rusqlite::Row<'_>, col: usize, what: &str) -> rusqlite::Result<[u8; 32]> {
    let v: Vec<u8> = r.get(col)?;
    <[u8; 32]>::try_from(v.as_slice()).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            col,
            rusqlite::types::Type::Blob,
            format!(
                "recipient_staging: {what} holds {} bytes, not 32: {e}",
                v.len()
            )
            .into(),
        )
    })
}

/// A transfer half that passed the ingestion boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedTransfer {
    /// What the object is: the signed operation's id.
    pub op_id: [u8; 32],
    /// The contact whose stored key verified SIG A.
    pub sender: [u8; 32],
    /// The signed nonce, hashed the way `spent_nonces` keys it.
    pub nonce_hash: [u8; 32],
    /// SIG A's message: the unsigned operation preimage.
    pub canonical_operation_bytes: Vec<u8>,
    /// SIG A.
    pub signature: Vec<u8>,
    /// The canonical bytes of the terms that open the operation's
    /// `terms_commitment`: its ticker, nonce, mode and memo, which no public
    /// object carries (pre-audit item 4).
    pub terms: Vec<u8>,
}

/// A receipt half that passed the ingestion boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedReceipt {
    /// What the object is: the receipt commitment.
    pub commitment: [u8; 32],
    /// The contact whose key chain verified the receipt's `sig_a`.
    pub sender: [u8; 32],
    /// The step it would take: the relationship and the signed parent.
    pub relationship_key: [u8; 32],
    pub parent_tip: [u8; 32],
    /// The exact full receipt wire bytes, and their role-separated digest.
    pub evidence_bytes: Vec<u8>,
    pub evidence_digest: [u8; 32],
}

/// A transfer copy's economic locator hints: where the sender says its debit
/// sits. Untrusted; prevalidation resolves them against the register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LocatorHint {
    pub economic_position: u64,
    pub debit_mutation_index: u32,
}

/// A staged transfer bound to the staged receipt whose child tip it produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairState {
    /// Both halves are recognized and bound; the apply has not committed.
    Bound,
    /// The canonical apply committed (or had already committed) this pair.
    Accepted,
}

impl PairState {
    fn as_str(self) -> &'static str {
        match self {
            PairState::Bound => "bound",
            PairState::Accepted => "accepted",
        }
    }

    /// The state stored in column `col`.
    fn parse(s: &str, col: usize) -> rusqlite::Result<Self> {
        match s {
            "bound" => Ok(PairState::Bound),
            "accepted" => Ok(PairState::Accepted),
            other => Err(rusqlite::Error::FromSqlConversionFailure(
                col,
                rusqlite::types::Type::Text,
                format!("recipient_staging: unknown pair state {other}").into(),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StagedPair {
    pub op_id: [u8; 32],
    pub commitment: [u8; 32],
    pub state: PairState,
}

fn row_to_transfer(r: &rusqlite::Row<'_>) -> rusqlite::Result<StagedTransfer> {
    Ok(StagedTransfer {
        op_id: col32(r, 0, "op_id")?,
        sender: col32(r, 1, "sender_device_id")?,
        nonce_hash: col32(r, 2, "nonce_hash")?,
        canonical_operation_bytes: r.get(3)?,
        signature: r.get(4)?,
        terms: r.get(5)?,
    })
}

const TRANSFER_COLS: &str =
    "op_id, sender_device_id, nonce_hash, canonical_operation_bytes, signature, terms_bytes";

fn row_to_receipt(r: &rusqlite::Row<'_>) -> rusqlite::Result<StagedReceipt> {
    Ok(StagedReceipt {
        commitment: col32(r, 0, "commitment")?,
        sender: col32(r, 1, "sender_device_id")?,
        relationship_key: col32(r, 2, "relationship_key")?,
        parent_tip: col32(r, 3, "parent_tip")?,
        evidence_bytes: r.get(4)?,
        evidence_digest: col32(r, 5, "evidence_digest")?,
    })
}

const RECEIPT_COLS: &str =
    "commitment, sender_device_id, relationship_key, parent_tip, evidence_bytes, evidence_digest";

fn row_to_pair(r: &rusqlite::Row<'_>) -> rusqlite::Result<StagedPair> {
    Ok(StagedPair {
        op_id: col32(r, 0, "op_id")?,
        commitment: col32(r, 1, "commitment")?,
        state: PairState::parse(&r.get::<_, String>(2)?, 2)?,
    })
}

/// Stage a recognized transfer. A second copy of the same signed operation is
/// the same row: the key is the content.
pub fn stage_transfer(t: &StagedTransfer) -> Result<()> {
    let binding = get_connection()?;
    let conn = lock(&binding)?;
    conn.execute(
        &format!(
            "INSERT OR IGNORE INTO recipient_staged_transfer({TRANSFER_COLS})
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        ),
        params![
            t.op_id.as_slice(),
            t.sender.as_slice(),
            t.nonce_hash.as_slice(),
            t.canonical_operation_bytes,
            t.signature,
            t.terms
        ],
    )?;
    Ok(())
}

/// Stage a recognized receipt. A second copy is the same row.
pub fn stage_receipt(r: &StagedReceipt) -> Result<()> {
    let binding = get_connection()?;
    let conn = lock(&binding)?;
    conn.execute(
        &format!(
            "INSERT OR IGNORE INTO recipient_staged_receipt({RECEIPT_COLS})
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        ),
        params![
            r.commitment.as_slice(),
            r.sender.as_slice(),
            r.relationship_key.as_slice(),
            r.parent_tip.as_slice(),
            r.evidence_bytes,
            r.evidence_digest.as_slice()
        ],
    )?;
    Ok(())
}

/// Record that a copy of a staged transfer was read at `address` under
/// `message_id`, with the locator hints that copy carried.
pub fn observe_transfer(
    op_id: &[u8; 32],
    address: &str,
    message_id: &str,
    hint: LocatorHint,
) -> Result<()> {
    let binding = get_connection()?;
    let conn = lock(&binding)?;
    conn.execute(
        "INSERT OR IGNORE INTO recipient_transfer_observation(
            op_id, address, message_id, economic_position, debit_mutation_index
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            op_id.as_slice(),
            address,
            message_id,
            i64::try_from(hint.economic_position)
                .map_err(|e| anyhow!("recipient_staging: economic position out of range: {e}"))?,
            i64::from(hint.debit_mutation_index)
        ],
    )?;
    Ok(())
}

/// Record that a copy of a staged receipt was read at `address` under
/// `message_id`.
pub fn observe_receipt(commitment: &[u8; 32], address: &str, message_id: &str) -> Result<()> {
    let binding = get_connection()?;
    let conn = lock(&binding)?;
    conn.execute(
        "INSERT OR IGNORE INTO recipient_receipt_observation(commitment, address, message_id)
         VALUES (?1, ?2, ?3)",
        params![commitment.as_slice(), address, message_id],
    )?;
    Ok(())
}

pub fn get_transfer(op_id: &[u8; 32]) -> Result<Option<StagedTransfer>> {
    let binding = get_connection()?;
    let conn = lock(&binding)?;
    Ok(conn
        .query_row(
            &format!("SELECT {TRANSFER_COLS} FROM recipient_staged_transfer WHERE op_id = ?1"),
            params![op_id.as_slice()],
            row_to_transfer,
        )
        .optional()?)
}

pub fn get_receipt(commitment: &[u8; 32]) -> Result<Option<StagedReceipt>> {
    let binding = get_connection()?;
    let conn = lock(&binding)?;
    Ok(conn
        .query_row(
            &format!("SELECT {RECEIPT_COLS} FROM recipient_staged_receipt WHERE commitment = ?1"),
            params![commitment.as_slice()],
            row_to_receipt,
        )
        .optional()?)
}

/// Staged transfers from `sender` that no pair holds yet.
pub fn unbound_transfers_from(sender: &[u8; 32]) -> Result<Vec<StagedTransfer>> {
    let binding = get_connection()?;
    let conn = lock(&binding)?;
    let mut stmt = conn.prepare(&format!(
        "SELECT {TRANSFER_COLS} FROM recipient_staged_transfer t
         WHERE t.sender_device_id = ?1
           AND NOT EXISTS (SELECT 1 FROM recipient_pair p WHERE p.op_id = t.op_id)
         ORDER BY t.rowid"
    ))?;
    let rows = stmt
        .query_map(params![sender.as_slice()], row_to_transfer)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Staged receipts from `sender` that no pair holds yet.
pub fn unbound_receipts_from(sender: &[u8; 32]) -> Result<Vec<StagedReceipt>> {
    let binding = get_connection()?;
    let conn = lock(&binding)?;
    let mut stmt = conn.prepare(&format!(
        "SELECT {RECEIPT_COLS} FROM recipient_staged_receipt r
         WHERE r.sender_device_id = ?1
           AND NOT EXISTS (SELECT 1 FROM recipient_pair p WHERE p.commitment = r.commitment)
         ORDER BY r.rowid"
    ))?;
    let rows = stmt
        .query_map(params![sender.as_slice()], row_to_receipt)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Bind a staged transfer to the staged receipt whose child tip it produces.
/// The caller has recomputed that child; the pair is keyed by both objects,
/// so neither can be bound twice.
pub fn bind(op_id: &[u8; 32], commitment: &[u8; 32]) -> Result<()> {
    let binding = get_connection()?;
    let conn = lock(&binding)?;
    conn.execute(
        "INSERT OR IGNORE INTO recipient_pair(op_id, commitment, state) VALUES (?1, ?2, ?3)",
        params![
            op_id.as_slice(),
            commitment.as_slice(),
            PairState::Bound.as_str()
        ],
    )?;
    Ok(())
}

pub fn get_pair(op_id: &[u8; 32]) -> Result<Option<StagedPair>> {
    let binding = get_connection()?;
    let conn = lock(&binding)?;
    Ok(conn
        .query_row(
            "SELECT op_id, commitment, state FROM recipient_pair WHERE op_id = ?1",
            params![op_id.as_slice()],
            row_to_pair,
        )
        .optional()?)
}

/// Every pair still in flight, in binding order: bound ones need the apply,
/// accepted ones need finishing (history, consumed markers, release). Read
/// from the store every poll, so a process that died anywhere in between is
/// driven forward by what the store durably holds. Released pairs are gone, which
/// keeps the scan bounded by the transfers still in flight.
pub fn pairs_in_flight() -> Result<Vec<StagedPair>> {
    let binding = get_connection()?;
    let conn = lock(&binding)?;
    let mut stmt =
        conn.prepare("SELECT op_id, commitment, state FROM recipient_pair ORDER BY rowid")?;
    let rows = stmt
        .query_map([], row_to_pair)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// The distinct locator hints the copies of a staged transfer carried.
pub fn locator_hints(op_id: &[u8; 32]) -> Result<Vec<LocatorHint>> {
    let binding = get_connection()?;
    let conn = lock(&binding)?;
    let mut stmt = conn.prepare(
        "SELECT DISTINCT economic_position, debit_mutation_index
         FROM recipient_transfer_observation WHERE op_id = ?1
         ORDER BY economic_position, debit_mutation_index",
    )?;
    let rows = stmt
        .query_map(params![op_id.as_slice()], |r| {
            let position: i64 = r.get(0)?;
            let index: i64 = r.get(1)?;
            let convert = |v: i64, col: usize| {
                u64::try_from(v).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        col,
                        rusqlite::types::Type::Integer,
                        Box::new(e),
                    )
                })
            };
            Ok(LocatorHint {
                economic_position: convert(position, 0)?,
                debit_mutation_index: u32::try_from(convert(index, 1)?).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Integer,
                        Box::new(e),
                    )
                })?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Mark a pair accepted inside the canonical apply's own transaction, so the
/// apply and the acceptance commit together or not at all.
pub fn mark_pair_accepted_with_conn(conn: &Connection, op_id: &[u8; 32]) -> Result<()> {
    let n = conn.execute(
        "UPDATE recipient_pair SET state = ?2 WHERE op_id = ?1",
        params![op_id.as_slice(), PairState::Accepted.as_str()],
    )?;
    if n != 1 {
        return Err(anyhow!(
            "recipient_staging: no bound pair holds this operation; nothing to accept"
        ));
    }
    Ok(())
}

/// Mark a pair accepted when the canonical apply found it already applied:
/// no apply transaction ran this time.
pub fn mark_pair_accepted(op_id: &[u8; 32]) -> Result<()> {
    let binding = get_connection()?;
    let conn = lock(&binding)?;
    mark_pair_accepted_with_conn(&conn, op_id)
}

/// Every `(address, message_id)` a copy of this pair's transfer or receipt
/// was read under — what the consumed markers are written with.
pub fn observed_ids_of_pair(pair: &StagedPair) -> Result<Vec<(String, String)>> {
    let binding = get_connection()?;
    let conn = lock(&binding)?;
    let mut stmt = conn.prepare(
        "SELECT address, message_id FROM recipient_transfer_observation WHERE op_id = ?1
         UNION
         SELECT address, message_id FROM recipient_receipt_observation WHERE commitment = ?2
         ORDER BY 1, 2",
    )?;
    let rows = stmt
        .query_map(
            params![pair.op_id.as_slice(), pair.commitment.as_slice()],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Collect a finished pair: its objects, its observations, and every staged
/// object the canonical apply has already decided can never execute — a
/// transfer whose nonce is spent, a receipt whose step is taken. Called only
/// once the pair is accepted and its consumed markers landed. State-based,
/// never age-based: an object still waiting for its other half stays.
pub fn release_pair(pair: &StagedPair) -> Result<()> {
    let binding = get_connection()?;
    let mut conn = lock(&binding)?;
    let tx = conn.transaction()?;
    let stored = tx
        .query_row(
            "SELECT state FROM recipient_pair WHERE op_id = ?1 AND commitment = ?2",
            params![pair.op_id.as_slice(), pair.commitment.as_slice()],
            |r| r.get::<_, String>(0),
        )
        .optional()?;
    match stored
        .as_deref()
        .map(|state| PairState::parse(state, 0))
        .transpose()?
    {
        Some(PairState::Accepted) => {}
        other => {
            return Err(anyhow!(
                "recipient_staging: only an accepted pair is released; this one is {other:?}"
            ))
        }
    }
    tx.execute(
        "DELETE FROM recipient_pair WHERE op_id = ?1",
        params![pair.op_id.as_slice()],
    )?;
    tx.execute(
        "DELETE FROM recipient_transfer_observation WHERE op_id = ?1",
        params![pair.op_id.as_slice()],
    )?;
    tx.execute(
        "DELETE FROM recipient_receipt_observation WHERE commitment = ?1",
        params![pair.commitment.as_slice()],
    )?;
    tx.execute(
        "DELETE FROM recipient_staged_transfer WHERE op_id = ?1",
        params![pair.op_id.as_slice()],
    )?;
    tx.execute(
        "DELETE FROM recipient_staged_receipt WHERE commitment = ?1",
        params![pair.commitment.as_slice()],
    )?;
    collect_decided_with_conn(&tx)?;
    tx.commit()?;
    Ok(())
}

/// Delete every unpaired staged object the canonical apply has decided can
/// never execute, with its observations.
fn collect_decided_with_conn(conn: &Connection) -> Result<()> {
    conn.execute(
        "DELETE FROM recipient_transfer_observation WHERE op_id IN (
            SELECT t.op_id FROM recipient_staged_transfer t
            WHERE EXISTS (SELECT 1 FROM spent_nonces s WHERE s.nonce_hash = t.nonce_hash)
              AND NOT EXISTS (SELECT 1 FROM recipient_pair p WHERE p.op_id = t.op_id))",
        [],
    )?;
    conn.execute(
        "DELETE FROM recipient_staged_transfer
         WHERE EXISTS (SELECT 1 FROM spent_nonces s
                       WHERE s.nonce_hash = recipient_staged_transfer.nonce_hash)
           AND NOT EXISTS (SELECT 1 FROM recipient_pair p
                           WHERE p.op_id = recipient_staged_transfer.op_id)",
        [],
    )?;
    conn.execute(
        "DELETE FROM recipient_receipt_observation WHERE commitment IN (
            SELECT r.commitment FROM recipient_staged_receipt r
            WHERE EXISTS (SELECT 1 FROM canonical_apply_identity c
                          WHERE c.relationship_key = r.relationship_key
                            AND c.parent_tip = r.parent_tip)
              AND NOT EXISTS (SELECT 1 FROM recipient_pair p WHERE p.commitment = r.commitment))",
        [],
    )?;
    conn.execute(
        "DELETE FROM recipient_staged_receipt
         WHERE EXISTS (SELECT 1 FROM canonical_apply_identity c
                       WHERE c.relationship_key = recipient_staged_receipt.relationship_key
                         AND c.parent_tip = recipient_staged_receipt.parent_tip)
           AND NOT EXISTS (SELECT 1 FROM recipient_pair p
                           WHERE p.commitment = recipient_staged_receipt.commitment)",
        [],
    )?;
    Ok(())
}

/// Whether the canonical apply has consumed this nonce: an operation carrying
/// it can no longer execute here (it executed, or another took its place).
pub fn nonce_decided(nonce_hash: &[u8; 32]) -> Result<bool> {
    let binding = get_connection()?;
    let conn = lock(&binding)?;
    Ok(conn
        .query_row(
            "SELECT 1 FROM spent_nonces WHERE nonce_hash = ?1",
            params![nonce_hash.as_slice()],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// Whether the canonical apply has taken this step: a receipt for it can no
/// longer execute here (it executed, or another took its place).
pub fn step_decided(relationship_key: &[u8; 32], parent_tip: &[u8; 32]) -> Result<bool> {
    let binding = get_connection()?;
    let conn = lock(&binding)?;
    Ok(conn
        .query_row(
            "SELECT 1 FROM canonical_apply_identity
             WHERE relationship_key = ?1 AND parent_tip = ?2",
            params![relationship_key.as_slice(), parent_tip.as_slice()],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// Whether an INBOUND transfer from `counterparty_device_id` is recognized
/// here and can still execute. The finality barrier treats this as
/// PendingCatchup for originating toward that peer: an inbound step is in
/// flight on the relationship and originating under it would cross it.
///
/// The counterparty is the contact whose key verified the object — never a
/// field the object carries. An object the apply has decided (its nonce spent,
/// its step taken) no longer holds the barrier.
pub fn counterparty_has_unconverged_inbound(counterparty_device_id: &[u8]) -> Result<bool> {
    let binding = get_connection()?;
    let conn = lock(&binding)?;
    Ok(conn
        .query_row(
            "SELECT 1 FROM recipient_staged_transfer t
             WHERE t.sender_device_id = ?1
               AND NOT EXISTS (SELECT 1 FROM spent_nonces s WHERE s.nonce_hash = t.nonce_hash)
             UNION ALL
             SELECT 1 FROM recipient_staged_receipt r
             WHERE r.sender_device_id = ?1
               AND NOT EXISTS (SELECT 1 FROM canonical_apply_identity c
                               WHERE c.relationship_key = r.relationship_key
                                 AND c.parent_tip = r.parent_tip)
             LIMIT 1",
            params![counterparty_device_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// Every address a staged object was read at, which must stay in the poll
/// set: the other half of a pair, replayed by the sender under the same frozen
/// route, is still received after the relationship tip advances. An address
/// leaves the set when its objects are released.
pub fn retained_routes_for_polling() -> Result<Vec<String>> {
    let binding = get_connection()?;
    let conn = lock(&binding)?;
    let mut stmt = conn.prepare(
        "SELECT address FROM recipient_transfer_observation
         UNION
         SELECT address FROM recipient_receipt_observation
         ORDER BY 1",
    )?;
    let routes = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(routes)
}
