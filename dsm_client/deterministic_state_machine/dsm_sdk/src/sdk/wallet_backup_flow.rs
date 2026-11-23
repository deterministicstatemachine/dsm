// SPDX-License-Identifier: MIT OR Apache-2.0

//! A wallet's sealed backups on the storage nodes (DSM Amendment A40).
//!
//! What a phone needs to carry on with its contacts lives only in its own
//! database. The wallet therefore keeps a backup of it on the nodes, sealed
//! under a key only its 24 words give (`dsm::wallet_backup`), and a wallet
//! restored from those words installs the latest one.
//!
//! When: never while the wallet is moving (owner, 2026-11-19: "It should happen
//! automatically unless you're starting another transaction right away. If
//! another transaction comes through, it should interrupt it and cancel it").
//! A backup is taken once the wallet has been still for [`QUIET`]; a step that
//! comes while one is being written cancels it, and the quiet starts over.
//! The loop learns the wallet moved from the database itself: a change to a
//! row of the tables the activity mark reads ([`MARK_READS`]) wakes it, and a
//! wallet that does not move wakes nothing.
//!
//! What: the tables in [`BACKUP_TABLES`], read in one transaction so the copy
//! is the wallet as it stood at one moment. Never the sealed seed, the records
//! the restore writes itself, the register (the network holds it) or caches.

use std::time::Duration;

use dsm::types::error::DsmError;
use dsm::wallet_backup::{BackupCell, BackupKeys, BackupRead, Place};
use rusqlite::types::Value;

use crate::sdk::route_seats::{write_recorded, AtLeader};
use crate::sdk::storage_set::{as_ccb_members, StorageSet};

type D32 = [u8; 32];

/// How long the wallet must be still before a backup is taken.
pub const QUIET: Duration = Duration::from_secs(20);

/// The longest the loop waits before it tries a backup that could not be
/// written again, the wallet still: the wait starts at [`QUIET`] and doubles.
const RETRY_AT_MOST: Duration = Duration::from_secs(600);

/// How often a backup being written looks whether the wallet moved.
const WATCH: Duration = Duration::from_millis(250);

/// The setting naming the last backup this wallet wrote or restored.
const LATEST: &str = "wallet_backup_latest";

/// What a backup carries: each contact's resume state (its chain tip, through
/// the device head; its key chain heads and step chain; its write grants and
/// inbox routes; the contact's head as this wallet holds it), the steps still
/// in flight, the replay guards, and the token, anchor pin and SoFi vault state
/// the head refers to, and the offline account's records: its own steps since
/// its last boundary and its anchor, and the payers' paths the payments it took
/// settle from. A restored offline account is advanced through its origin cells
/// past the backup (owner, 2026-11-19: "it needs to reestablish your counter
/// position"), and used only when it is exactly its board's.
pub const BACKUP_TABLES: &[&str] = &[
    "bcr_device_heads",
    "contacts",
    "contact_relationship",
    "contact_first_inbox_lock",
    "relationship_write_authorization",
    "inbox_route",
    "cert_chain_heads",
    "pending_local_cert_heads",
    "ek_cert_step_chain",
    "cert_resync_state",
    "counterparty_canonical_heads",
    "relationship_passed_tips",
    "peer_kept_state",
    "peer_offline_account",
    "peer_ek_step",
    "acceptance_fold_journal",
    "sender_online_proposal",
    "sender_outbox",
    "sender_outbox_artifacts",
    "pending_online_outbox",
    "recipient_outbound_reply",
    "recipient_pair",
    "recipient_staged_receipt",
    "recipient_staged_transfer",
    "recipient_receipt_observation",
    "recipient_transfer_observation",
    "received_notices",
    "received_notices_seen",
    "spent_nonces",
    "canonical_apply_identity",
    "accepted_transition_marker",
    "b0x_consumed",
    "token_policies",
    "token_registry",
    "anchor_enrollments",
    "anchor_accepted_roots",
    "own_offline_anchor",
    "own_offline_hop",
    "own_offline_boundary",
    "offline_boundary_told",
    "offline_acknowledgement",
    "pending_offline_receipt",
    "pending_offline_origin",
    "pending_offline_origin_write",
    "sofi_vault_baseline",
    "sofi_vault_history_published",
    "sofi_vault_label",
    "sofi_vault_leaf",
    "sofi_vault_owner_baseline",
    "sofi_vault_quarantine",
    "sofi_vault_root",
    "sofi_vault_step",
    "sofi_vault_witness",
];

fn storage(what: &str, e: impl std::fmt::Display) -> DsmError {
    DsmError::storage(
        format!("wallet backup: {what}: {e}"),
        None::<std::io::Error>,
    )
}

/// This wallet's backup keys, from its unlocked wallet seed.
pub fn keys() -> Result<BackupKeys, DsmError> {
    let seed = crate::fetch_wallet_seed()
        .map_err(|e| DsmError::invalid_operation(format!("wallet backup: wallet locked: {e}")))?;
    Ok(BackupKeys::of_wallet_seed(&seed))
}

// ── the body ────────────────────────────────────────────────────────────────

const MAGIC: &[u8] = b"DSM/wallet-backup/body/v1";

/// One table as a backup carries it.
#[derive(Debug, Clone, PartialEq)]
pub struct Table {
    pub name: String,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
}

/// A backup's body: the database schema it was taken under, the register
/// position the wallet had admitted then, and its tables.
#[derive(Debug, Clone, PartialEq)]
pub struct Body {
    pub schema: i64,
    pub admitted: Option<(u64, D32)>,
    pub tables: Vec<Table>,
}

fn put_len(out: &mut Vec<u8>, n: usize) -> Result<(), DsmError> {
    let n = u32::try_from(n).map_err(|e| storage("length", e))?;
    out.extend_from_slice(&n.to_le_bytes());
    Ok(())
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) -> Result<(), DsmError> {
    put_len(out, b.len())?;
    out.extend_from_slice(b);
    Ok(())
}

impl Body {
    pub fn encode(&self) -> Result<Vec<u8>, DsmError> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.schema.to_le_bytes());
        match &self.admitted {
            Some((position, root)) => {
                out.push(1);
                out.extend_from_slice(&position.to_le_bytes());
                out.extend_from_slice(root);
            }
            None => out.push(0),
        }
        put_len(&mut out, self.tables.len())?;
        for table in &self.tables {
            put_bytes(&mut out, table.name.as_bytes())?;
            put_len(&mut out, table.columns.len())?;
            for column in &table.columns {
                put_bytes(&mut out, column.as_bytes())?;
            }
            put_len(&mut out, table.rows.len())?;
            for row in &table.rows {
                for value in row {
                    match value {
                        Value::Null => out.push(0),
                        Value::Integer(i) => {
                            out.push(1);
                            out.extend_from_slice(&i.to_le_bytes());
                        }
                        Value::Real(r) => {
                            out.push(2);
                            out.extend_from_slice(&r.to_le_bytes());
                        }
                        Value::Text(t) => {
                            out.push(3);
                            put_bytes(&mut out, t.as_bytes())?;
                        }
                        Value::Blob(b) => {
                            out.push(4);
                            put_bytes(&mut out, b)?;
                        }
                    }
                }
            }
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DsmError> {
        let mut r = Reader { bytes, at: 0 };
        if r.take(MAGIC.len())? != MAGIC {
            return Err(storage("body", "not a wallet backup body"));
        }
        let schema = i64::from_le_bytes(r.array()?);
        let admitted = match r.byte()? {
            0 => None,
            1 => Some((u64::from_le_bytes(r.array()?), r.array()?)),
            other => return Err(storage("body", format!("admitted flag {other}"))),
        };
        let mut tables = Vec::new();
        for _ in 0..r.len()? {
            let name = r.text()?;
            let width = r.len()?;
            let mut columns = Vec::with_capacity(width);
            for _ in 0..width {
                columns.push(r.text()?);
            }
            let mut rows = Vec::new();
            for _ in 0..r.len()? {
                let mut row = Vec::with_capacity(width);
                for _ in 0..width {
                    row.push(match r.byte()? {
                        0 => Value::Null,
                        1 => Value::Integer(i64::from_le_bytes(r.array()?)),
                        2 => Value::Real(f64::from_le_bytes(r.array()?)),
                        3 => Value::Text(r.text()?),
                        4 => Value::Blob(r.bytes()?),
                        other => return Err(storage("body", format!("value tag {other}"))),
                    });
                }
                rows.push(row);
            }
            tables.push(Table {
                name,
                columns,
                rows,
            });
        }
        if r.at != bytes.len() {
            return Err(storage("body", "trailing bytes"));
        }
        Ok(Self {
            schema,
            admitted,
            tables,
        })
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DsmError> {
        let end = self
            .at
            .checked_add(n)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| storage("body", "truncated"))?;
        let out = &self.bytes[self.at..end];
        self.at = end;
        Ok(out)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DsmError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn byte(&mut self) -> Result<u8, DsmError> {
        Ok(self.take(1)?[0])
    }

    fn len(&mut self) -> Result<usize, DsmError> {
        usize::try_from(u32::from_le_bytes(self.array()?)).map_err(|e| storage("length", e))
    }

    fn bytes(&mut self) -> Result<Vec<u8>, DsmError> {
        let n = self.len()?;
        Ok(self.take(n)?.to_vec())
    }

    fn text(&mut self) -> Result<String, DsmError> {
        String::from_utf8(self.bytes()?).map_err(|e| storage("text", e))
    }
}

// ── taking and installing ───────────────────────────────────────────────────

/// Why no backup was taken now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotNow {
    /// An economic admission or a board signing is in flight.
    Moving(&'static str),
}

/// The wallet as it stands, in one read transaction: a backup's body, or why
/// none is taken now.
pub fn snapshot() -> Result<Result<Body, NotNow>, DsmError> {
    let binding = crate::storage::client_db::get_connection().map_err(|e| storage("db", e))?;
    let mut conn = binding.lock().map_err(|e| storage("db lock", e))?;
    let tx = conn.transaction().map_err(|e| storage("read", e))?;
    let count = |table: &str| -> Result<i64, DsmError> {
        tx.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .map_err(|e| storage(table, e))
    };
    if count("economic_pending_admissions")? > 0 {
        return Ok(Err(NotNow::Moving("an economic admission is in flight")));
    }
    if count("offline_boundary_signing")? > 0 {
        return Ok(Err(NotNow::Moving("a board is signing a boundary")));
    }
    let admitted: Option<(i64, Option<Vec<u8>>)> = tx
        .query_row(
            "SELECT economic_position, economic_root FROM economic_admitted_v2 WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })
        .map_err(|e| storage("admitted position", e))?;
    let admitted = match admitted {
        None => None,
        // An unresolved SoFi position has selected no root yet.
        Some((_, None)) => return Ok(Err(NotNow::Moving("a SoFi position is unresolved"))),
        Some((position, Some(root))) => Some((
            u64::try_from(position).map_err(|e| storage("position", e))?,
            <D32>::try_from(root.as_slice()).map_err(|e| storage("root", e))?,
        )),
    };
    let mut tables = Vec::with_capacity(BACKUP_TABLES.len());
    for name in BACKUP_TABLES {
        let mut stmt = tx
            .prepare(&format!("SELECT * FROM {name}"))
            .map_err(|e| storage(name, e))?;
        let columns: Vec<String> = stmt.column_names().map(|c| c.to_string()).collect();
        let width = columns.len();
        let rows = stmt
            .query_map([], |row| {
                (0..width)
                    .map(|i| row.get::<_, Value>(i))
                    .collect::<Result<Vec<_>, _>>()
            })
            .map_err(|e| storage(name, e))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| storage(name, e))?;
        tables.push(Table {
            name: (*name).to_string(),
            columns,
            rows,
        });
    }
    Ok(Ok(Body {
        schema: crate::storage::client_db::CLIENT_DB_SCHEMA_VERSION,
        admitted,
        tables,
    }))
}

/// Install `body`'s tables in `tx`, each replacing what the table held. Only
/// the tables a backup carries are written, by the names this build gives
/// their columns.
pub fn install(tx: &rusqlite::Transaction<'_>, body: &Body) -> Result<(), DsmError> {
    if body.schema != crate::storage::client_db::CLIENT_DB_SCHEMA_VERSION {
        return Err(storage(
            "schema",
            format!(
                "the backup was taken under database schema {}, this build serves {}",
                body.schema,
                crate::storage::client_db::CLIENT_DB_SCHEMA_VERSION
            ),
        ));
    }
    for table in &body.tables {
        let Some(name) = BACKUP_TABLES.iter().find(|t| **t == table.name) else {
            return Err(storage(
                "table",
                format!("{} is not a backup table", table.name),
            ));
        };
        let known: Vec<String> = tx
            .prepare(&format!("SELECT * FROM {name} LIMIT 0"))
            .map_err(|e| storage(name, e))?
            .column_names()
            .map(|c| c.to_string())
            .collect();
        if known != table.columns {
            return Err(storage(
                name,
                format!("columns {:?}, this build has {known:?}", table.columns),
            ));
        }
        tx.execute(&format!("DELETE FROM {name}"), [])
            .map_err(|e| storage(name, e))?;
        let marks: Vec<String> = (1..=known.len()).map(|i| format!("?{i}")).collect();
        let sql = format!(
            "INSERT INTO {name} ({}) VALUES ({})",
            known.join(", "),
            marks.join(", ")
        );
        let mut stmt = tx.prepare(&sql).map_err(|e| storage(name, e))?;
        for row in &table.rows {
            stmt.execute(rusqlite::params_from_iter(row.iter()))
                .map_err(|e| storage(name, e))?;
        }
    }
    Ok(())
}

/// The device head a backup carries for `device_id`.
pub fn head_of(
    body: &Body,
    device_id: &D32,
) -> Result<dsm::types::device_state::RealizedHead, DsmError> {
    let table = body
        .tables
        .iter()
        .find(|t| t.name == "bcr_device_heads")
        .ok_or_else(|| storage("head", "the backup carries no device head"))?;
    let column = |name: &str| {
        table
            .columns
            .iter()
            .position(|c| c == name)
            .ok_or_else(|| storage("head", format!("no {name} column")))
    };
    let (id_at, bytes_at) = (column("device_id")?, column("head_bytes")?);
    let row = table
        .rows
        .iter()
        .find(|row| matches!(&row[id_at], Value::Blob(id) if id.as_slice() == device_id))
        .ok_or_else(|| storage("head", "the backup carries no head of this device"))?;
    let Value::Blob(bytes) = &row[bytes_at] else {
        return Err(storage("head", "head bytes are not a blob"));
    };
    let (head, _root) = crate::storage::client_db::bcr::decode_device_state(bytes, None)
        .map_err(|e| storage("head", e))?;
    Ok(head)
}

// ── the cells ───────────────────────────────────────────────────────────────

/// The last backup this wallet wrote or restored; 0 when none.
pub fn latest_written() -> Result<u64, DsmError> {
    match crate::storage::client_db::get_setting(LATEST).map_err(|e| storage("setting", e))? {
        Some(n) => n.parse().map_err(|e| storage("setting", e)),
        None => Ok(0),
    }
}

/// Record `n` as the last backup this wallet wrote or restored.
pub fn record_latest(n: u64) -> Result<(), DsmError> {
    crate::storage::client_db::set_setting(LATEST, &n.to_string())
        .map_err(|e| storage("setting", e))
}

/// The most one part of a backup carries: a sealed part is one cell value at
/// its largest.
pub const PART: usize = dsm::wallet_backup::MAX_PART;

/// Write `body` as backup `n` in one attempt of its own, in parts of at most
/// [`PART`], each leader first: the later parts under the attempt, then part 0,
/// which names the attempt and the count of parts, at the backup's own cell. An
/// attempt cut short leaves only cells no later attempt uses. Answers the
/// leader's answer for part 0, or for the later part it stopped at.
pub async fn write(
    set: &StorageSet,
    keys: &BackupKeys,
    n: u64,
    body: &Body,
) -> Result<Written, DsmError> {
    let bytes = body.encode()?;
    let chunks: Vec<&[u8]> = bytes.chunks(PART).collect();
    let parts = u32::try_from(chunks.len()).map_err(|e| storage("parts", e))?;
    let attempt = dsm::wallet_backup::new_attempt();
    let members = as_ccb_members(set)?;
    for (index, chunk) in chunks.iter().enumerate().rev() {
        let part = u32::try_from(index).map_err(|e| storage("part", e))?;
        let place = Place::of(part, attempt);
        let cell = BackupCell::new(keys, n, place, &members, &set.id())
            .map_err(|e| storage("cell", format!("{e:?}")))?;
        let sealed = keys.seal(n, part, parts, &attempt, chunk)?;
        let report = write_recorded(set, cell.routed(), &cell.keeps(), &sealed).await?;
        match (place, report.leader()) {
            (_, AtLeader::Link) => {}
            (Place::First, AtLeader::Taken) => return Ok(Written::NumberTaken),
            (Place::Later { .. }, AtLeader::Taken) | (_, AtLeader::Unanswered) => {
                return Ok(Written::Stopped { part })
            }
        }
    }
    Ok(Written::Whole)
}

/// How a write of a backup came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Written {
    /// Every part holds its cell, part 0 last: the backup is written.
    Whole,
    /// Part 0's cell already holds a whole backup of this wallet's: the number
    /// is used, and the next backup goes after it.
    NumberTaken,
    /// The write stopped at `part` without part 0: nothing of it is relied on,
    /// and the number stays free for the next attempt.
    Stopped { part: u32 },
}

/// What the cell of the part of backup `n` at `place` holds, read from the
/// set's seats. Reads that do not decide it yet are a storage error, never an
/// open cell.
pub fn read(
    set: &StorageSet,
    own: (D32, D32),
    keys: &BackupKeys,
    n: u64,
    place: Place,
) -> Result<BackupRead, DsmError> {
    let ctx = crate::sdk::sofi_reads::VerifierContext::new(set, Some(own), None)?;
    ctx.verifier()
        .read_backup_cell(keys, n, place)
        .map_err(crate::sdk::sofi_reads::verifier_error)?
        .map_err(|missing| {
            storage(
                &format!("backup {n} part {}", place.index()),
                format!("not decided yet: {missing:?}"),
            )
        })
}

/// The part of backup `n` at `place` once final, `None` when its cell is
/// open. A cell held by a write not final yet is an error to try again on.
fn settled_part(
    set: &StorageSet,
    own: (D32, D32),
    keys: &BackupKeys,
    n: u64,
    place: Place,
) -> Result<Option<dsm::wallet_backup::Opened>, DsmError> {
    let at = read(set, own, keys, n, place)?;
    if at.open() {
        return Ok(None);
    }
    at.settled().cloned().map(Some).ok_or_else(|| {
        storage(
            &format!("backup {n} part {}", place.index()),
            "held, not final yet; try again shortly",
        )
    })
}

/// The latest backup the cells hold, by its number: backup `n`'s part 0 holds
/// its cell only once its later parts do, and `n` is written only once
/// `n − 1`'s part 0 holds its cell, so the part 0 cells fill in order with no
/// gap, and the latest is found by doubling, then halving, on part 0. Its later
/// parts are read under the attempt part 0 names, and each must be final.
pub fn latest(
    set: &StorageSet,
    own: (D32, D32),
    keys: &BackupKeys,
) -> Result<Option<(u64, Body)>, DsmError> {
    let head = |n: u64| settled_part(set, own, keys, n, Place::First);
    let Some(first) = head(1)? else {
        return Ok(None);
    };
    let (mut lo, mut lo_head) = (1u64, first);
    let mut hi = 2u64;
    while let Some(found) = head(hi)? {
        (lo, lo_head) = (hi, found);
        hi = hi
            .checked_mul(2)
            .ok_or_else(|| storage("latest", "backup numbers exhausted"))?;
    }
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        match head(mid)? {
            Some(found) => (lo, lo_head) = (mid, found),
            None => hi = mid,
        }
    }
    let mut bytes = lo_head.chunk;
    for part in 1..lo_head.parts {
        let place = Place::of(part, lo_head.attempt);
        let found = settled_part(set, own, keys, lo, place)?.ok_or_else(|| {
            storage(
                &format!("backup {lo} part {part}"),
                "missing though part 0 is written",
            )
        })?;
        if found.parts != lo_head.parts {
            return Err(storage(
                &format!("backup {lo} part {part}"),
                "names another count of parts",
            ));
        }
        bytes.extend_from_slice(&found.chunk);
    }
    Ok(Some((lo, Body::decode(&bytes)?)))
}

// ── backing up once the wallet is still ────────────────────────────────────

/// The tables the activity mark reads, and the column of each it reads.
pub const MARK_READS: [(&str, &str); 6] = [
    ("bcr_device_heads", "head_bytes"),
    ("economic_admitted_v2", "economic_root"),
    ("economic_pending_admissions", "pre_economic_root"),
    ("sender_outbox", "submission_id"),
    ("acceptance_fold_journal", "relationship_key"),
    ("own_offline_hop", "hop"),
];

/// Signalled when a row of a table the activity mark reads changes. A
/// notify keeps one wake given while nobody waits, so a move made while the
/// loop is busy is seen when it next waits.
static MOVED: once_cell::sync::Lazy<tokio::sync::Notify> =
    once_cell::sync::Lazy::new(tokio::sync::Notify::new);

/// The device database changed a row of `table`: the backup loop is woken
/// when the table is one the activity mark reads. Called by the database's
/// update hook, inside the write; it only signals.
pub fn row_changed(table: &str) {
    if MARK_READS.iter().any(|(read, _)| *read == table) {
        MOVED.notify_one();
    }
}

/// What moving looks like from outside: the device head, the admitted register
/// position and the in-flight steps. A step changes it the moment it lands.
pub fn activity_mark() -> Result<D32, DsmError> {
    #[cfg(test)]
    MARKS_READ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let binding = crate::storage::client_db::get_connection().map_err(|e| storage("db", e))?;
    let conn = binding.lock().map_err(|e| storage("db lock", e))?;
    let mut h = dsm::crypto::blake3::Hasher::new_derive_key("DSM/wallet-backup/activity/v1\0");
    for (table, column) in MARK_READS {
        let sql = format!("SELECT {column} FROM {table}");
        let mut stmt = conn.prepare(&sql).map_err(|e| storage("mark", e))?;
        let values = stmt
            .query_map([], |r| r.get::<_, Value>(0))
            .map_err(|e| storage("mark", e))?;
        for value in values {
            h.update(format!("{:?}", value.map_err(|e| storage("mark", e))?).as_bytes());
        }
    }
    Ok(*h.finalize().as_bytes())
}

/// What one backup attempt came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attempt {
    /// Backup `n` holds its cell.
    Written(u64),
    /// Nothing written now, and why.
    NotNow(NotNow),
    /// The wallet moved while the backup was being written; nothing of it is
    /// relied on.
    Cancelled,
}

/// Take a backup now and write it as the next one, unless the wallet is
/// moving. `mark` is the wallet's activity mark the backup is taken at: a
/// change of it while the write is under way cancels the write.
pub async fn back_up_now(set: &StorageSet, mark: D32) -> Result<Attempt, DsmError> {
    let keys = keys()?;
    let body = match snapshot()? {
        Ok(body) => body,
        Err(not_now) => return Ok(Attempt::NotNow(not_now)),
    };
    if activity_mark()? != mark {
        return Ok(Attempt::Cancelled);
    }
    let n = latest_written()?
        .checked_add(1)
        .ok_or_else(|| storage("number", "backup numbers exhausted"))?;
    let moved = async {
        loop {
            tokio::time::sleep(WATCH).await;
            match activity_mark() {
                Ok(now) if now == mark => {}
                Ok(_moved) => break,
                Err(e) => {
                    log::debug!("[wallet backup] watching the wallet: {e}");
                    break;
                }
            }
        }
    };
    tokio::select! {
        written = write(set, &keys, n, &body) => match written? {
            Written::Whole => {
                record_latest(n)?;
                Ok(Attempt::Written(n))
            }
            // A whole backup of this wallet's holds the number already: one
            // an earlier attempt finished. The next backup goes after it.
            Written::NumberTaken => {
                record_latest(n)?;
                Err(storage(&format!("backup {n}"), "the number is used; the next goes after it"))
            }
            // Nothing of this attempt is relied on, and the number stays free.
            Written::Stopped { part } => Err(storage(
                &format!("backup {n} part {part}"),
                "the write stopped before part 0; the next attempt takes the number",
            )),
        },
        () = moved => Ok(Attempt::Cancelled),
    }
}

static LOOP: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>> = std::sync::Mutex::new(None);

/// How many times this process has read the wallet's activity mark: each read
/// scans the mark's tables whole.
#[cfg(test)]
static MARKS_READ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
pub(crate) fn marks_read() -> u64 {
    MARKS_READ.load(std::sync::atomic::Ordering::SeqCst)
}

/// The next wake a move gives the backup loop, for a test that waits on one.
#[cfg(test)]
pub(crate) fn moved() -> tokio::sync::futures::Notified<'static> {
    MOVED.notified()
}

/// End the backup loop a test started, so no later test finds it reading the
/// database it has entered.
#[cfg(test)]
pub(crate) fn stop_for_test() {
    let mut running = match LOOP.lock() {
        Ok(running) => running,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(task) = running.take() {
        task.abort();
    }
}

/// Start the wallet's backup loop, once: it backs the wallet up each time it
/// has been still for [`QUIET`] since it last moved.
pub fn start() {
    #[cfg(test)]
    if crate::sdk::inbox_poller::background_held() {
        return;
    }
    let Ok(mut running) = LOOP.lock() else {
        log::warn!("[wallet backup] the loop's lock is poisoned; not started");
        return;
    };
    if running.as_ref().is_some_and(|task| !task.is_finished()) {
        return;
    }
    *running = Some(crate::runtime::get_runtime().spawn(run()));
}

/// What one look at the still wallet came to.
enum Look {
    /// The wallet is backed up as it stands, or a backup was cancelled by a
    /// move: the loop waits for the next move.
    Done,
    /// No backup could be written now: tried again after a wait, or sooner
    /// if the wallet moves.
    TryAgain,
}

/// Wait until the wallet has been still for `quiet`: every move restarts it.
async fn still_for(quiet: Duration) {
    loop {
        tokio::select! {
            () = MOVED.notified() => {}
            () = tokio::time::sleep(quiet) => return,
        }
    }
}

async fn run() {
    let mut backed_up: Option<D32> = None;
    let mut retry = QUIET;
    // A process starts as a move does: its first look comes once the wallet
    // has been still for QUIET.
    loop {
        still_for(QUIET).await;
        match look(&mut backed_up).await {
            Look::Done => {
                retry = QUIET;
                MOVED.notified().await;
            }
            Look::TryAgain => {
                tokio::select! {
                    () = MOVED.notified() => {}
                    () = tokio::time::sleep(retry) => {}
                }
                retry = retry.saturating_mul(2).min(RETRY_AT_MOST);
            }
        }
    }
}

/// Back the still wallet up, unless it is backed up as it stands.
async fn look(backed_up: &mut Option<D32>) -> Look {
    let mark = match activity_mark() {
        Ok(mark) => mark,
        Err(e) => {
            log::debug!("[wallet backup] {e}");
            return Look::TryAgain;
        }
    };
    if *backed_up == Some(mark) {
        return Look::Done;
    }
    let set = match crate::sdk::economic_admission_flow::committed_network_id()
        .and_then(|network| crate::sdk::storage_set::canonical_set(&network))
    {
        Ok(set) => set,
        Err(e) => {
            log::debug!("[wallet backup] no set yet: {e}");
            return Look::TryAgain;
        }
    };
    match publish_own_steps(&set).await {
        Ok(0) => {}
        Ok(n) => log::info!("[wallet backup] {n} own offline steps put at their cells"),
        Err(e) => {
            log::warn!("[wallet backup] own offline steps not put yet: {e}");
            return Look::TryAgain;
        }
    }
    match back_up_now(&set, mark).await {
        Ok(Attempt::Written(n)) => {
            *backed_up = Some(mark);
            log::info!("[wallet backup] backup {n} written");
            Look::Done
        }
        Ok(Attempt::NotNow(why)) => {
            log::debug!("[wallet backup] not now: {why:?}");
            Look::TryAgain
        }
        Ok(Attempt::Cancelled) => {
            log::info!("[wallet backup] cancelled: the wallet moved");
            Look::Done
        }
        Err(e) => {
            log::warn!("[wallet backup] {e}");
            Look::TryAgain
        }
    }
}

// ── the offline account on the network ─────────────────────────────────────

/// The setting naming the last own step of `bundle` put at its cell.
fn published_key(bundle: &D32) -> String {
    format!(
        "offline_steps_published_{}",
        crate::util::text_id::encode_base32_crockford(bundle)
    )
}

/// Put every board-signed step of this wallet's own offline accounts since the
/// last one put at its origin cell (DSM Amendment A40): so the network holds the
/// whole history of the account, and a wallet restored from its words reaches
/// the account its board holds. A cell another step already holds is a step of
/// another history, and nothing after it is put. Answers how many were put.
pub async fn publish_own_steps(set: &StorageSet) -> Result<usize, DsmError> {
    let anchors = crate::storage::client_db::offline_spends::own_anchors()
        .map_err(|e| storage("own anchors", e))?;
    if anchors.is_empty() {
        return Ok(0);
    }
    let field = |v: Option<Vec<u8>>, what: &str| -> Result<D32, DsmError> {
        let v = v.ok_or_else(|| storage(what, "not set"))?;
        <D32>::try_from(v.as_slice()).map_err(|e| storage(what, e))
    };
    let devid = field(
        crate::sdk::app_state::AppState::get_device_id(),
        "device id",
    )?;
    let owner_key = crate::sdk::app_state::AppState::get_public_key()
        .ok_or_else(|| storage("owner key", "not set"))?;
    let mut put = 0;
    for (bundle, anchor) in anchors {
        let hops = crate::storage::client_db::offline_spends::own_offline_hops(&bundle)
            .map_err(|e| storage("own steps", e))?;
        let last = crate::storage::client_db::get_setting(&published_key(&bundle))
            .map_err(|e| storage("setting", e))?;
        let mut steps = Vec::with_capacity(hops.len());
        for bytes in &hops {
            steps.push(dsm::types::offline_chain::AccountHop::from_bytes(bytes)?);
        }
        let named = |step: &dsm::types::offline_chain::AccountHop| {
            step.board_message()
                .map(|m| crate::util::text_id::encode_base32_crockford(&m))
        };
        let from = match &last {
            Some(last) => steps
                .iter()
                .position(|step| named(step).as_deref() == Some(last.as_str()))
                .map_or(0, |at| at + 1),
            None => 0,
        };
        for step in &steps[from..] {
            let Some(message) = named(step) else {
                continue;
            };
            let write =
                dsm::offline_origin::OriginWrite::new(&owner_key, devid, bundle, &anchor, step);
            match crate::sdk::origin_cell_flow::write(set, &write).await? {
                AtLeader::Link => {}
                AtLeader::Taken => {
                    log::warn!(
                        "[wallet backup] the cell of own step {message} holds another write; \
                         reading the cells says which"
                    );
                }
                AtLeader::Unanswered => {
                    return Err(storage(
                        &format!("own step {message}"),
                        "the leader did not answer",
                    ))
                }
            }
            crate::storage::client_db::set_setting(&published_key(&bundle), &message)
                .map_err(|e| storage("setting", e))?;
            put += 1;
        }
    }
    Ok(put)
}

/// The steps final at the origin cells of `bundle`'s account after `root`,
/// each a write of this wallet's device, in order, with the anchor they carry:
/// what a restored account is advanced through. The walk stops at the first
/// cell holding no final step, or at a departure, a boundary the register has
/// not admitted.
pub fn own_steps_after(
    core: &crate::sdk::core_sdk::CoreSDK,
    set: &StorageSet,
    bundle: &D32,
    root: &D32,
    devid: &D32,
) -> Result<
    (
        Vec<dsm::types::offline_chain::AccountHop>,
        Option<dsm::types::offline_chain::ChainAnchor>,
    ),
    DsmError,
> {
    let mut at = *root;
    let mut hops = Vec::new();
    let mut anchor = None;
    for _ in 0..dsm::types::offline_chain::MAX_CHAIN_HOPS {
        let read = crate::sdk::origin_cell_flow::read(core, set, bundle, &at)?;
        let (Some(step), Some(value)) = (read.settled(), read.value()) else {
            break;
        };
        match dsm::offline_origin::OriginDeparture::decode(value) {
            Ok(_boundary_not_admitted) => break,
            Err(_a_step) => {}
        }
        let write = dsm::offline_origin::OriginWrite::decode(value)
            .map_err(|e| storage("origin write", e))?;
        if write.device_id != *devid {
            return Err(storage(
                "origin write",
                "a step of another device's account",
            ));
        }
        anchor.get_or_insert(dsm::types::offline_chain::ChainAnchor {
            bundle: *bundle,
            anchor_id: write.anchor.anchor_id,
            pk_chip: write.anchor.pk_chip.clone(),
            pk_host: write.anchor.pk_host.clone(),
        });
        hops.push(dsm::types::offline_chain::AccountHop::from_bytes(
            &write.step,
        )?);
        at = step.after;
    }
    Ok((hops, anchor))
}
