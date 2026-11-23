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
//!
//! What: the tables in [`BACKUP_TABLES`], read in one transaction so the copy
//! is the wallet as it stood at one moment. Never the sealed seed, the records
//! the restore writes itself, the register (the network holds it) or caches.

use std::time::Duration;

use dsm::types::error::DsmError;
use dsm::wallet_backup::BackupKeys;
use rusqlite::types::Value;

use crate::sdk::route_seats::AtLeader;
use crate::sdk::storage_node_sdk::SetClient;
use crate::sdk::storage_set::StorageSet;

type D32 = [u8; 32];

/// How long the wallet must be still before a backup is taken.
pub const QUIET: Duration = Duration::from_secs(20);

/// How often the backup loop looks whether the wallet moved.
const TICK: Duration = Duration::from_secs(2);

/// [`QUIET`] in the loop's looks: the loop counts them, and reads no clock.
const QUIET_TICKS: u64 = QUIET.as_secs() / TICK.as_secs();

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

/// A journal row a backup carries: one still in flight (prepared, applied,
/// or awaiting the sender's finality), or one at or after its contact's
/// latest accepted step. Earlier steps are history the relationship has moved
/// past: nothing a restored wallet does with that contact reads them.
const KEPT_JOURNAL: &str = "(j.status IN ('prepared', 'applied') \
     OR (j.status != 'rejected' AND j.peer_finalized = 0) \
     OR j.rowid >= COALESCE((SELECT MAX(l.rowid) FROM acceptance_fold_journal l \
                              WHERE l.relationship_key = j.relationship_key \
                                AND l.status != 'rejected'), 0))";

/// A send a backup carries: one not complete, or its contact's latest.
const KEPT_SEND: &str = "(o.status != 'complete' \
     OR o.rowid >= (SELECT MAX(l.rowid) FROM sender_outbox l \
                     WHERE l.relationship_key = o.relationship_key))";

/// The rows of `table` a backup carries, in the order the wallet wrote them.
/// Four tables keep a record of every payment ever sent or taken; a backup
/// carries only the steps in flight and each contact's latest step (DSM
/// Amendment A40: "the steps in flight", "each relationship's chain tip"),
/// so its size follows the wallet's contacts, not every payment it ever made.
/// Every other table is carried whole, the offline account's among them.
fn kept_rows(table: &str) -> String {
    match table {
        "acceptance_fold_journal" => format!(
            "SELECT j.* FROM acceptance_fold_journal j WHERE {KEPT_JOURNAL} ORDER BY j.rowid"
        ),
        "recipient_outbound_reply" => format!(
            "SELECT r.* FROM recipient_outbound_reply r \
              WHERE r.submitted = 0 OR r.held = 1 \
                 OR EXISTS (SELECT 1 FROM acceptance_fold_journal j \
                             WHERE j.commitment = r.commitment AND {KEPT_JOURNAL}) \
              ORDER BY r.rowid"
        ),
        "sender_outbox" => {
            format!("SELECT o.* FROM sender_outbox o WHERE {KEPT_SEND} ORDER BY o.rowid")
        }
        "sender_outbox_artifacts" => format!(
            "SELECT a.* FROM sender_outbox_artifacts a \
              WHERE EXISTS (SELECT 1 FROM sender_outbox o \
                             WHERE o.relationship_key = a.relationship_key \
                               AND o.canonical_parent = a.canonical_parent \
                               AND o.proposal_nonce = a.proposal_nonce AND {KEPT_SEND}) \
              ORDER BY a.rowid"
        ),
        other => format!("SELECT * FROM {other}"),
    }
}

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
        let mut stmt = tx.prepare(&kept_rows(name)).map_err(|e| storage(name, e))?;
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

// ── the slot ────────────────────────────────────────────────────────────────

/// The last generation this wallet used for a backup or restored, or the
/// highest a member named; 0 when none.
pub fn latest_written() -> Result<u64, DsmError> {
    match crate::storage::client_db::get_setting(LATEST).map_err(|e| storage("setting", e))? {
        Some(n) => n.parse().map_err(|e| storage("setting", e)),
        None => Ok(0),
    }
}

/// Record `n` as the last generation this wallet used or restored, or the
/// highest a member named: the next backup is written as a higher one.
pub fn record_latest(n: u64) -> Result<(), DsmError> {
    crate::storage::client_db::set_setting(LATEST, &n.to_string())
        .map_err(|e| storage("setting", e))
}

/// The most one part of a backup carries.
pub const PART: usize = dsm::wallet_backup::MAX_PART;

/// The cell lock of the device `own` names, `(genesis, device id)`: the key
/// its slot is bound to and the one that starts every write of it. It comes
/// from the wallet seed, so a wallet restored from its words has it again.
pub(crate) fn slot_lock(own: (D32, D32)) -> Result<dsm::crypto::sphincs::SphincsKeyPair, DsmError> {
    let seed = crate::fetch_wallet_seed()
        .map_err(|e| DsmError::invalid_operation(format!("wallet backup: wallet locked: {e}")))?;
    let s_master = crate::init::smaster_of(seed.as_slice(), &own.0, &own.1);
    dsm::owned_cell::derive_cell_lock_keypair(&s_master, &own.1)
}

/// This device's `(genesis, device id)`.
fn own_device() -> Result<(D32, D32), DsmError> {
    let id32 = |v: Option<Vec<u8>>, what: &str| -> Result<D32, DsmError> {
        let bytes = v.ok_or_else(|| storage(what, "none yet"))?;
        D32::try_from(bytes.as_slice()).map_err(|e| storage(what, e))
    };
    Ok((
        id32(crate::sdk::app_state::AppState::get_genesis_hash(), "genesis")?,
        id32(crate::sdk::app_state::AppState::get_device_id(), "device id")?,
    ))
}

/// How a write of a backup came out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Written {
    /// At least the set's quorum of members hold it as their whole backup.
    Whole,
    /// A member holds a start of `highest`, not lower than this one: the next
    /// backup is written after it.
    Superseded { highest: u64 },
    /// Fewer than the quorum hold it whole: `whole` of `members`, and what
    /// the others answered.
    Short {
        whole: usize,
        members: usize,
        why: Vec<String>,
    },
}

/// How one member took a write.
enum AtMember {
    Whole,
    Superseded(u64),
}

/// Write `sealed`, generation `generation` of `slot`, at `member`: the start,
/// then every part in order.
async fn write_at(
    member: &crate::sdk::storage_node_sdk::MemberClient,
    slot: &D32,
    generation: u64,
    start: &[u8],
    sealed: &[Vec<u8>],
) -> Result<AtMember, String> {
    use crate::sdk::storage_node_sdk::SlotAnswer;
    let mut held = match member.backup_start(slot, start).await? {
        SlotAnswer::Taken(held) => held,
        SlotAnswer::Superseded(held) => return Ok(AtMember::Superseded(held.highest_generation)),
    };
    if held.generation != generation {
        for (part, bytes) in sealed.iter().enumerate() {
            let part = u32::try_from(part).map_err(|e| format!("part {part}: {e}"))?;
            held = match member.backup_part(slot, generation, part, bytes).await? {
                SlotAnswer::Taken(held) => held,
                SlotAnswer::Superseded(held) => {
                    return Ok(AtMember::Superseded(held.highest_generation))
                }
            };
        }
    }
    if held.generation == generation {
        Ok(AtMember::Whole)
    } else {
        Err(format!(
            "every part sent, and the member holds generation {} whole",
            held.generation
        ))
    }
}

/// Write `body` as generation `generation` of this wallet's slot on the
/// device whose cell lock is `lock`, at every member of `set` at once: the
/// start the lock signs, then the parts, each no larger than [`PART`].
pub async fn write(
    set: &StorageSet,
    keys: &BackupKeys,
    lock: &dsm::crypto::sphincs::SphincsKeyPair,
    generation: u64,
    body: &Body,
) -> Result<Written, DsmError> {
    let bytes = body.encode()?;
    let chunks: Vec<&[u8]> = bytes.chunks(PART).collect();
    if chunks.len() > dsm::wallet_backup::MAX_PARTS {
        return Err(storage(
            "size",
            format!(
                "{} bytes is more than {} parts",
                bytes.len(),
                dsm::wallet_backup::MAX_PARTS
            ),
        ));
    }
    let count = u32::try_from(chunks.len()).map_err(|e| storage("parts", e))?;
    let slot = keys.slot(&lock.public_key);
    let sealed = chunks
        .iter()
        .enumerate()
        .map(|(i, chunk)| {
            let i = u32::try_from(i).map_err(|e| storage("part", e))?;
            keys.seal(&slot, generation, i, count, chunk)
        })
        .collect::<Result<Vec<_>, DsmError>>()?;
    let digests: Vec<D32> = sealed
        .iter()
        .map(|p| dsm::wallet_backup::part_digest(p))
        .collect();
    let (slot, start) = keys.start(lock, generation, &digests)?;
    let client = SetClient::new(set)?;
    let answers = futures::future::join_all(
        client
            .members()
            .iter()
            .map(|m| write_at(m, &slot, generation, &start, &sealed)),
    )
    .await;
    let mut whole = 0usize;
    let mut highest = None;
    let mut why = Vec::new();
    for (member, answer) in client.members().iter().zip(answers) {
        match answer {
            Ok(AtMember::Whole) => whole += 1,
            Ok(AtMember::Superseded(h)) => highest = highest.max(Some(h)),
            Err(e) => why.push(format!("{}: {e}", member.member_id())),
        }
    }
    let quorum = usize::try_from(set.quorum()).map_err(|e| storage("quorum", e))?;
    Ok(match highest {
        _ if whole >= quorum => Written::Whole,
        Some(highest) => Written::Superseded { highest },
        None => Written::Short {
            whole,
            members: client.members().len(),
            why,
        },
    })
}

/// The latest backup the members of `set` hold whole in the slot of the
/// device `own` names, `(genesis, device id)`, with its generation: the
/// highest whole one whose every part a member serves as the digest that
/// member names and that opens under this wallet's key as that part. `None`
/// only when every member answered that it holds none; a read that does not
/// decide it is an error to try again on.
pub async fn latest(
    set: &StorageSet,
    own: (D32, D32),
    keys: &BackupKeys,
) -> Result<Option<(u64, Body)>, DsmError> {
    let lock = slot_lock(own)?;
    let slot = keys.slot(&lock.public_key);
    let client = SetClient::new(set)?;
    let states =
        futures::future::join_all(client.members().iter().map(|m| m.backup_slot(&slot))).await;
    let mut unanswered = 0usize;
    let mut why = Vec::new();
    let mut held: Vec<(u64, Vec<D32>, usize)> = Vec::new();
    for (at, state) in states.into_iter().enumerate() {
        let member = client.members().get(at).map(|m| m.member_id().to_string());
        let named = dsm::wallet_backup::digests_of;
        match state.map(|state| (state.generation, named(&state.part_digests))) {
            Ok((0, _)) => {}
            Ok((generation, Ok(digests))) => held.push((generation, digests, at)),
            Ok((generation, Err(e))) => why.push(format!("{member:?}: generation {generation}: {e}")),
            Err(e) => {
                unanswered += 1;
                why.push(format!("{member:?}: {e}"));
            }
        }
    }
    held.sort_by_key(|h| std::cmp::Reverse(h.0));
    for (generation, digests, _) in &held {
        let servers: Vec<usize> = held
            .iter()
            .filter(|(g, d, _)| g == generation && d == digests)
            .map(|(_, _, at)| *at)
            .collect();
        match read_whole(&client, &slot, keys, *generation, digests, &servers).await {
            Ok(body) => return Ok(Some((*generation, body))),
            Err(e) => why.push(format!("generation {generation}: {e}")),
        }
    }
    if held.is_empty() && unanswered == 0 {
        return Ok(None);
    }
    Err(storage(
        "slot",
        format!(
            "no whole backup read back from the members that answered ({unanswered} did not); \
             not decided yet: {}",
            why.join("; ")
        ),
    ))
}

/// Generation `generation` of `slot`, read part by part from the members at
/// `servers`, each part taken only as its digest and as that part when it
/// opens.
async fn read_whole(
    client: &SetClient,
    slot: &D32,
    keys: &BackupKeys,
    generation: u64,
    digests: &[D32],
    servers: &[usize],
) -> Result<Body, DsmError> {
    let count = u32::try_from(digests.len()).map_err(|e| storage("parts", e))?;
    let mut bytes = Vec::new();
    for (part, digest) in digests.iter().enumerate() {
        let part = u32::try_from(part).map_err(|e| storage("part", e))?;
        let mut found = None;
        let mut why = Vec::new();
        for member in servers.iter().filter_map(|at| client.members().get(*at)) {
            let served = member.backup_whole_part(slot, generation, part).await;
            let opened = match served {
                Ok(Some(sealed)) if dsm::wallet_backup::part_digest(&sealed) == *digest => {
                    keys.open(slot, generation, part, &sealed)
                        .map_err(|refusal| format!("{refusal:?}"))
                }
                Ok(Some(_other)) => Err("not the digest it names".to_string()),
                Ok(None) => Err("holds no such part".to_string()),
                Err(e) => Err(e),
            };
            match opened {
                Ok(opened) if opened.parts == count => {
                    found = Some(opened.chunk);
                    break;
                }
                Ok(opened) => why.push(format!(
                    "{}: names {} parts, not {count}",
                    member.member_id(),
                    opened.parts
                )),
                Err(e) => why.push(format!("{}: {e}", member.member_id())),
            }
        }
        let chunk = found.ok_or_else(|| storage(&format!("part {part}"), why.join("; ")))?;
        bytes.extend_from_slice(&chunk);
    }
    Body::decode(&bytes)
}

// ── backing up once the wallet is still ────────────────────────────────────

/// What moving looks like from outside: the device head, the admitted register
/// position and the in-flight steps. A step changes it the moment it lands.
pub fn activity_mark() -> Result<D32, DsmError> {
    let binding = crate::storage::client_db::get_connection().map_err(|e| storage("db", e))?;
    let conn = binding.lock().map_err(|e| storage("db lock", e))?;
    let mut h = dsm::crypto::blake3::Hasher::new_derive_key("DSM/wallet-backup/activity/v1\0");
    for sql in [
        "SELECT head_bytes FROM bcr_device_heads",
        "SELECT economic_root FROM economic_admitted_v2",
        "SELECT pre_economic_root FROM economic_pending_admissions",
        "SELECT submission_id FROM sender_outbox",
        "SELECT relationship_key FROM acceptance_fold_journal",
        "SELECT hop FROM own_offline_hop",
    ] {
        let mut stmt = conn.prepare(sql).map_err(|e| storage("mark", e))?;
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
    /// Generation `n` is the whole backup at the set's quorum of members,
    /// written over the one before.
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
    let lock = slot_lock(own_device()?)?;
    let body = match snapshot()? {
        Ok(body) => body,
        Err(not_now) => return Ok(Attempt::NotNow(not_now)),
    };
    if activity_mark()? != mark {
        return Ok(Attempt::Cancelled);
    }
    let generation = latest_written()?
        .checked_add(1)
        .ok_or_else(|| storage("generation", "backup generations exhausted"))?;
    // The generation is used from here: an attempt the wallet's next step
    // cuts short is written over by the next, which goes higher.
    record_latest(generation)?;
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
        written = write(set, &keys, &lock, generation, &body) => match written? {
            Written::Whole => Ok(Attempt::Written(generation)),
            // A member took a start at least this high: one this wallet wrote
            // from another device, or before it was restored. The next backup
            // goes after it.
            Written::Superseded { highest } => {
                record_latest(highest)?;
                Err(storage(
                    &format!("generation {generation}"),
                    format!("a member holds {highest}; the next backup goes after it"),
                ))
            }
            Written::Short { whole, members, why } => Err(storage(
                &format!("generation {generation}"),
                format!(
                    "whole at {whole} of {members} members ({}); the next attempt writes it over",
                    why.join("; ")
                ),
            )),
        },
        () = moved => Ok(Attempt::Cancelled),
    }
}

static LOOP: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>> = std::sync::Mutex::new(None);

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

/// Forget this phone's records of writing the backup cells of before the
/// slot: no member takes a write there any more, so nothing of them is left
/// to continue.
fn forget_old_backup_writes() -> Result<(), DsmError> {
    let forgotten = crate::storage::client_db::route_writes::forget_writes_in(
        dsm::common::domain_tags::RETIRED_WALLET_BACKUP_CELLS,
    )
    .map_err(|e| storage("forgetting the old backup cells' writes", e))?;
    if forgotten > 0 {
        log::info!("[wallet backup] forgot {forgotten} writes of the old backup cells");
    }
    Ok(())
}

async fn run() {
    if let Err(e) = forget_old_backup_writes() {
        log::warn!("{e}");
    }
    let mut seen: Option<D32> = None;
    let mut still_ticks: u64 = 0;
    let mut backed_up: Option<D32> = None;
    loop {
        tokio::time::sleep(TICK).await;
        let mark = match activity_mark() {
            Ok(mark) => mark,
            Err(e) => {
                log::debug!("[wallet backup] {e}");
                continue;
            }
        };
        if seen != Some(mark) {
            seen = Some(mark);
            still_ticks = 0;
            continue;
        }
        still_ticks = still_ticks.saturating_add(1);
        if backed_up == Some(mark) || still_ticks < QUIET_TICKS {
            continue;
        }
        let set = match crate::sdk::economic_admission_flow::committed_network_id()
            .and_then(|network| crate::sdk::storage_set::canonical_set(&network))
        {
            Ok(set) => set,
            Err(e) => {
                log::debug!("[wallet backup] no set yet: {e}");
                continue;
            }
        };
        match publish_own_steps(&set).await {
            Ok(0) => {}
            Ok(n) => log::info!("[wallet backup] {n} own offline steps put at their cells"),
            Err(e) => {
                still_ticks = 0;
                log::warn!("[wallet backup] own offline steps not put yet: {e}");
                continue;
            }
        }
        match back_up_now(&set, mark).await {
            Ok(Attempt::Written(n)) => {
                backed_up = Some(mark);
                log::info!("[wallet backup] generation {n} written over the last");
            }
            Ok(Attempt::NotNow(why)) => log::debug!("[wallet backup] not now: {why:?}"),
            Ok(Attempt::Cancelled) => log::info!("[wallet backup] cancelled: the wallet moved"),
            Err(e) => {
                still_ticks = 0;
                log::warn!("[wallet backup] {e}");
            }
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
