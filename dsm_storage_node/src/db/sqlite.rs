//! Storage node DB layer — SQLite backend for local development.
//!
//! Provides the same public API as `db::pg` but backed by a single SQLite file.
//! All operations use `tokio::task::spawn_blocking` since rusqlite is synchronous.

use crate::api::hardening::{BBYTES, BEV};
use crate::timing::TimingStrategy;
use anyhow::{anyhow, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::sync::{Arc, Mutex};

// ===================== Pool Type Alias =====================

/// SQLite "pool" — a mutex-protected connection (single writer, local-dev only).
pub type DBPool = Arc<Mutex<Connection>>;

// ===================== Durable Replication Outbox (clockless) =====================

/// A pending outbox row loaded from the DB.
#[derive(Debug, Clone)]
pub struct ReplicationOutboxRow {
    pub id: i64,
    pub target: String,
    pub method: String,
    pub path: String,
    pub headers: Vec<u8>,
    pub body: Vec<u8>,
    pub idempotency_key: String,
    pub attempts: i32,
    pub eligible_iter: i64,
}

/// Parameters for enqueuing a replication outbox entry.
#[derive(Debug, Clone, Copy)]
pub struct ReplicationOutboxEnqueueParams<'a> {
    pub target: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub headers: &'a [u8],
    pub body: &'a [u8],
    pub idempotency_key: &'a str,
    pub eligible_iter: i64,
}

/// Deterministically encode HTTP headers to bytes.
pub fn encode_headers_deterministic(headers: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut items: Vec<(Vec<u8>, Vec<u8>)> = headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase().into_bytes(), v.clone()))
        .collect();
    items.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    let mut out = Vec::new();
    for (k, v) in items {
        let klen: u16 = u16::try_from(k.len()).unwrap_or(u16::MAX);
        let vlen: u32 = u32::try_from(v.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&klen.to_le_bytes());
        out.extend_from_slice(&k[..(klen as usize)]);
        out.extend_from_slice(&vlen.to_le_bytes());
        out.extend_from_slice(&v[..(vlen as usize)]);
    }
    out
}

/// Decode deterministic header bytes back into pairs.
pub fn decode_headers_deterministic(mut bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 2 {
            return Err(anyhow!("header decode: truncated k_len"));
        }
        let mut klen_b = [0u8; 2];
        klen_b.copy_from_slice(&bytes[..2]);
        bytes = &bytes[2..];
        let klen = u16::from_le_bytes(klen_b) as usize;
        if bytes.len() < klen {
            return Err(anyhow!("header decode: truncated key"));
        }
        let k = bytes[..klen].to_vec();
        bytes = &bytes[klen..];

        if bytes.len() < 4 {
            return Err(anyhow!("header decode: truncated v_len"));
        }
        let mut vlen_b = [0u8; 4];
        vlen_b.copy_from_slice(&bytes[..4]);
        bytes = &bytes[4..];
        let vlen = u32::from_le_bytes(vlen_b) as usize;
        if bytes.len() < vlen {
            return Err(anyhow!("header decode: truncated value"));
        }
        let v = bytes[..vlen].to_vec();
        bytes = &bytes[vlen..];

        let k = String::from_utf8(k).map_err(|_| anyhow!("header decode: non-utf8 key"))?;
        out.push((k, v));
    }
    Ok(out)
}

// Helper to run blocking DB operations on a spawn_blocking thread
async fn with_conn<F, T>(pool: &DBPool, f: F) -> Result<T>
where
    F: FnOnce(&Connection) -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    let pool = pool.clone();
    tokio::task::spawn_blocking(move || {
        let conn = pool.lock().map_err(|e| anyhow!("mutex poisoned: {}", e))?;
        f(&conn)
    })
    .await
    .map_err(|e| anyhow!("spawn_blocking join: {}", e))?
}

// ===================== Pool Creation =====================

/// Create a SQLite "pool" (single connection).
/// The `database_url` is treated as a file path. If it contains "postgresql" it's ignored
/// and a default local path is used.
pub fn create_pool(database_url: &str, _lazy: bool) -> Result<DBPool> {
    let path = if database_url.contains("postgresql") || database_url.contains("postgres") {
        // Derive a unique SQLite filename from the PostgreSQL database name
        // (e.g. "postgresql://...dsm_storage_node3" → "dsm-storage-node3.db")
        // so that each dev node gets its own file.
        let db_name = database_url.rsplit('/').next().unwrap_or("local");
        let sqlite_file = format!("dsm-storage-{}.db", db_name);
        log::info!(
            "local-dev mode: ignoring PostgreSQL URL, using local SQLite: {}",
            sqlite_file
        );
        sqlite_file
    } else {
        database_url.to_string()
    };
    log::info!("Opening SQLite database: {}", path);
    let conn = Connection::open(&path)?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;",
    )?;
    Ok(Arc::new(Mutex::new(conn)))
}

// ===================== Schema Init =====================

/// Initialize database schema (SQLite version).
pub async fn init_db(pool: &DBPool) -> Result<()> {
    with_conn(pool, |conn| {
        conn.execute_batch(
            r#"CREATE TABLE IF NOT EXISTS dlv_slots (
                    dlv_id         BLOB PRIMARY KEY,
                    capacity_bytes INTEGER NOT NULL,
                    used_bytes     INTEGER NOT NULL DEFAULT 0,
                    stake_hash     BLOB NOT NULL
                );

                CREATE TABLE IF NOT EXISTS objects (
                    key           TEXT PRIMARY KEY,
                    value         BLOB NOT NULL,
                    dlv_id        BLOB NOT NULL,
                    size_bytes    INTEGER NOT NULL,
                    iter_created  INTEGER NOT NULL DEFAULT 0,
                    iter_expires  INTEGER
                );

                CREATE INDEX IF NOT EXISTS idx_objects_dlv_id ON objects(dlv_id);
                CREATE INDEX IF NOT EXISTS idx_objects_iter_expires ON objects(iter_expires);

                CREATE TABLE IF NOT EXISTS registry_evidence (
                    addr        TEXT PRIMARY KEY,
                    kind_code   INTEGER NOT NULL,
                    dlv_id      BLOB NOT NULL,
                    size_bytes  INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_registry_evidence_kind ON registry_evidence(kind_code);

                CREATE TABLE IF NOT EXISTS replication_outbox (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    target          TEXT NOT NULL,
                    method          TEXT NOT NULL,
                    path            TEXT NOT NULL,
                    headers         BLOB NOT NULL,
                    body            BLOB NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    attempts        INTEGER NOT NULL DEFAULT 0,
                    eligible_iter   INTEGER NOT NULL DEFAULT 0,
                    done            INTEGER NOT NULL DEFAULT 0,
                    last_err        TEXT
                );

                CREATE UNIQUE INDEX IF NOT EXISTS ux_replication_outbox_idem_target
                    ON replication_outbox(target, idempotency_key);

                CREATE INDEX IF NOT EXISTS idx_replication_outbox_due
                    ON replication_outbox(done, eligible_iter, id);

                CREATE TABLE IF NOT EXISTS devices (
                    device_id        TEXT PRIMARY KEY,
                    genesis_hash     BLOB NOT NULL,
                    pubkey           BLOB NOT NULL,
                    token_hash       BLOB NOT NULL,
                    revoked          INTEGER NOT NULL DEFAULT 0,
                    paidk_satisfied  INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS inbox_receipts (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id  TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    UNIQUE(device_id, message_id)
                );

                CREATE INDEX IF NOT EXISTS idx_inbox_receipts_device ON inbox_receipts(device_id);
                CREATE INDEX IF NOT EXISTS idx_inbox_receipts_device_id ON inbox_receipts(device_id, id);

                CREATE TABLE IF NOT EXISTS inbox_spool (
                    id                INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id         TEXT NOT NULL,
                    message_id        TEXT NOT NULL UNIQUE,
                    envelope          BLOB NOT NULL,
                    acked             INTEGER NOT NULL DEFAULT 0,
                    seq_num           INTEGER NOT NULL DEFAULT 0,
                    expires_at_iter   INTEGER
                );

                CREATE INDEX IF NOT EXISTS idx_inbox_spool_device_acked ON inbox_spool(device_id, acked, id);
                CREATE INDEX IF NOT EXISTS idx_inbox_spool_device_seq ON inbox_spool(device_id, seq_num);
                CREATE INDEX IF NOT EXISTS idx_inbox_spool_expires ON inbox_spool(expires_at_iter)
                    WHERE expires_at_iter IS NOT NULL;

                CREATE TABLE IF NOT EXISTS bytecommit_chain (
                    node_id      TEXT NOT NULL,
                    cycle_index  INTEGER NOT NULL,
                    digest       BLOB NOT NULL,
                    PRIMARY KEY(node_id, cycle_index)
                );

                CREATE INDEX IF NOT EXISTS idx_bytecommit_chain_node_cycle
                    ON bytecommit_chain(node_id, cycle_index);

                -- PaidK payment receipts
                CREATE TABLE IF NOT EXISTS payment_receipts (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id        TEXT NOT NULL,
                    operator_node_id BLOB NOT NULL,
                    amount           INTEGER NOT NULL,
                    receipt_addr     TEXT NOT NULL UNIQUE,
                    receipt_bytes    BLOB NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_payment_receipts_device ON payment_receipts(device_id);

                -- Node registry
                CREATE TABLE IF NOT EXISTS node_registry (
                    node_id         BLOB PRIMARY KEY,
                    first_cycle     INTEGER NOT NULL,
                    utilization_avg REAL NOT NULL DEFAULT 0.0,
                    active          INTEGER NOT NULL DEFAULT 1
                );
                CREATE INDEX IF NOT EXISTS idx_node_registry_active ON node_registry(active);

                -- Capacity signals
                CREATE TABLE IF NOT EXISTS capacity_signals (
                    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                    signal_addr        TEXT NOT NULL UNIQUE,
                    node_id            BLOB NOT NULL,
                    signal_type        INTEGER NOT NULL,
                    capacity           INTEGER NOT NULL,
                    cycle_window_start INTEGER NOT NULL,
                    cycle_window_end   INTEGER NOT NULL,
                    signal_bytes       BLOB NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_capacity_signals_node ON capacity_signals(node_id);
                CREATE INDEX IF NOT EXISTS idx_capacity_signals_window ON capacity_signals(cycle_window_end);

                -- Applicant submissions
                CREATE TABLE IF NOT EXISTS applicants (
                    applicant_addr  TEXT PRIMARY KEY,
                    seed_app        BLOB NOT NULL,
                    stake_dlv       BLOB NOT NULL,
                    capacity        INTEGER NOT NULL,
                    applicant_bytes BLOB NOT NULL
                );

                -- Drain proofs
                CREATE TABLE IF NOT EXISTS drain_proofs (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    proof_addr     TEXT NOT NULL UNIQUE,
                    node_id        BLOB NOT NULL,
                    start_cycle    INTEGER NOT NULL,
                    end_cycle      INTEGER NOT NULL,
                    verified_local INTEGER NOT NULL DEFAULT 0,
                    proof_bytes    BLOB NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_drain_proofs_node ON drain_proofs(node_id);
            "#,
        )?;
        Ok(())
    })
    .await
}

// ===================== Replication Outbox =====================

pub async fn replication_outbox_enqueue(
    pool: &DBPool,
    params: ReplicationOutboxEnqueueParams<'_>,
) -> Result<()> {
    let target = params.target.to_string();
    let method = params.method.to_string();
    let path = params.path.to_string();
    let headers = params.headers.to_vec();
    let body = params.body.to_vec();
    let idempotency_key = params.idempotency_key.to_string();
    let eligible_iter = params.eligible_iter;

    with_conn(pool, move |conn| {
        conn.execute(
            "INSERT OR IGNORE INTO replication_outbox (target, method, path, headers, body, idempotency_key, eligible_iter)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![target, method, path, headers, body, idempotency_key, eligible_iter],
        )?;
        Ok(())
    }).await
}

pub async fn replication_outbox_list_due(
    pool: &DBPool,
    now_iter: i64,
    limit: i64,
) -> Result<Vec<ReplicationOutboxRow>> {
    with_conn(pool, move |conn| {
        let mut stmt = conn.prepare_cached(
            "SELECT id, target, method, path, headers, body, idempotency_key, attempts, eligible_iter
             FROM replication_outbox WHERE done=0 AND eligible_iter <= ?1
             ORDER BY eligible_iter ASC, id ASC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![now_iter, limit], |row| {
                Ok(ReplicationOutboxRow {
                    id: row.get(0)?,
                    target: row.get(1)?,
                    method: row.get(2)?,
                    path: row.get(3)?,
                    headers: row.get(4)?,
                    body: row.get(5)?,
                    idempotency_key: row.get(6)?,
                    attempts: row.get(7)?,
                    eligible_iter: row.get(8)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .await
}

pub async fn replication_outbox_mark_done(pool: &DBPool, id: i64) -> Result<()> {
    with_conn(pool, move |conn| {
        conn.execute(
            "UPDATE replication_outbox SET done=1, last_err=NULL WHERE id=?1",
            params![id],
        )?;
        Ok(())
    })
    .await
}

pub async fn replication_outbox_record_failure(
    pool: &DBPool,
    timing: &dyn TimingStrategy,
    id: i64,
    now_iter: i64,
    attempts_next: i32,
    last_err: &str,
) -> Result<()> {
    let eligible_iter_next = timing
        .calculate_retry_eligible_iter(now_iter, attempts_next)
        .await;
    let last_err = last_err.to_string();

    with_conn(pool, move |conn| {
        conn.execute(
            "UPDATE replication_outbox SET attempts=?2, eligible_iter=?3, last_err=?4 WHERE id=?1",
            params![id, attempts_next, eligible_iter_next, last_err],
        )?;
        Ok(())
    })
    .await
}

// ===================== Core Object Store =====================

pub async fn get_current_cycle_stats(pool: &DBPool) -> Result<([u8; 32], u64)> {
    with_conn(pool, |conn| {
        let mut stmt =
            conn.prepare_cached("SELECT key, size_bytes FROM objects ORDER BY key ASC")?;
        let mut bytes_used: u64 = 0;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"DSM/smt-node\0");

        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let key: String = row.get(0)?;
            let sz: i64 = row.get(1)?;
            if sz > 0 {
                bytes_used = bytes_used.saturating_add(sz as u64);
            }
            hasher.update(key.as_bytes());
            hasher.update(&[0u8]);
            hasher.update(&sz.to_le_bytes());
        }

        let out = hasher.finalize();
        Ok((*out.as_bytes(), bytes_used))
    })
    .await
}

pub async fn get_last_bytecommit_hash(pool: &DBPool, node_id: &str) -> Result<Option<[u8; 32]>> {
    let node_id = node_id.to_string();
    with_conn(pool, move |conn| {
        let result: Option<Vec<u8>> = conn
            .query_row(
                "SELECT digest FROM bytecommit_chain WHERE node_id=?1 ORDER BY cycle_index DESC LIMIT 1",
                params![node_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(result.map(|b| {
            let mut out = [0u8; 32];
            if b.len() == 32 {
                out.copy_from_slice(&b);
            }
            out
        }))
    })
    .await
}

pub async fn record_bytecommit_hash(
    pool: &DBPool,
    node_id: &str,
    cycle_index: u64,
    digest: &[u8; 32],
) -> Result<()> {
    let node_id = node_id.to_string();
    let digest = digest.to_vec();
    with_conn(pool, move |conn| {
        conn.execute(
            "INSERT OR IGNORE INTO bytecommit_chain(node_id, cycle_index, digest) VALUES (?1,?2,?3)",
            params![node_id, cycle_index as i64, digest],
        )?;
        Ok(())
    })
    .await
}

// ===================== DLV Slots =====================

pub async fn slot_exists(pool: &DBPool, dlv_id: &[u8]) -> Result<bool> {
    let dlv_id = dlv_id.to_vec();
    with_conn(pool, move |conn| {
        let exists: bool = conn
            .query_row(
                "SELECT 1 FROM dlv_slots WHERE dlv_id = ?1 LIMIT 1",
                params![dlv_id],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);
        Ok(exists)
    })
    .await
}

pub async fn create_slot(
    pool: &DBPool,
    dlv_id: &[u8],
    capacity_bytes: i64,
    stake_hash: &[u8],
) -> Result<()> {
    let dlv_id = dlv_id.to_vec();
    let stake_hash = stake_hash.to_vec();
    with_conn(pool, move |conn| {
        conn.execute(
            "INSERT OR IGNORE INTO dlv_slots (dlv_id, capacity_bytes, used_bytes, stake_hash) VALUES (?1,?2,0,?3)",
            params![dlv_id, capacity_bytes, stake_hash],
        )?;
        Ok(())
    })
    .await
}

pub async fn upsert_object(
    pool: &DBPool,
    key: &str,
    value: &[u8],
    dlv_id: &[u8],
    size_bytes: i64,
) -> Result<()> {
    let key = key.to_string();
    let value = value.to_vec();
    let dlv_id = dlv_id.to_vec();
    with_conn(pool, move |conn| {
        conn.execute(
            "INSERT INTO objects(key, value, dlv_id, size_bytes) VALUES (?1,?2,?3,?4)
             ON CONFLICT (key) DO UPDATE SET value=excluded.value, size_bytes=excluded.size_bytes, dlv_id=excluded.dlv_id",
            params![key, value, dlv_id, size_bytes],
        )?;
        Ok(())
    })
    .await
}

pub async fn store_registry_evidence(
    pool: &DBPool,
    addr: &str,
    kind_code: i16,
    dlv_id: &[u8],
    size_bytes: i64,
) -> Result<()> {
    let addr = addr.to_string();
    let dlv_id = dlv_id.to_vec();
    with_conn(pool, move |conn| {
        conn.execute(
            "INSERT OR IGNORE INTO registry_evidence (addr, kind_code, dlv_id, size_bytes) VALUES (?1, ?2, ?3, ?4)",
            params![addr, kind_code as i32, dlv_id, size_bytes],
        )?;
        Ok(())
    })
    .await
}

pub async fn list_registry_evidence_by_kind(
    pool: &DBPool,
    kind_code: i16,
) -> Result<Vec<(String, i16, i64)>> {
    with_conn(pool, move |conn| {
        let mut stmt = conn.prepare_cached(
            "SELECT addr, kind_code, size_bytes FROM registry_evidence WHERE kind_code=?1 ORDER BY addr ASC",
        )?;
        let rows = stmt
            .query_map(params![kind_code as i32], |row| {
                let kc: i32 = row.get(1)?;
                Ok((row.get::<_, String>(0)?, kc as i16, row.get::<_, i64>(2)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .await
}

pub async fn get_registry_object_by_addr(pool: &DBPool, addr: &str) -> Result<Option<Vec<u8>>> {
    let addr = addr.to_string();
    with_conn(pool, move |conn| {
        let result: Option<Vec<u8>> = conn
            .query_row(
                "SELECT o.value FROM objects o JOIN registry_evidence r ON o.key = r.addr WHERE r.addr=?1 LIMIT 1",
                params![addr],
                |row| row.get(0),
            )
            .optional()?;
        Ok(result)
    })
    .await
}

pub async fn upsert_object_with_capacity_check(
    pool: &DBPool,
    key: &str,
    value: &[u8],
    dlv_id: &[u8],
    new_size: i64,
) -> Result<()> {
    let key = key.to_string();
    let value = value.to_vec();
    let dlv_id = dlv_id.to_vec();
    with_conn(pool, move |conn| {
        let tx = conn.unchecked_transaction()?;

        let (capacity, used): (i64, i64) = tx.query_row(
            "SELECT capacity_bytes, used_bytes FROM dlv_slots WHERE dlv_id=?1",
            params![dlv_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).map_err(|_| anyhow!("slot not found"))?;

        let prev_size: i64 = tx
            .query_row(
                "SELECT size_bytes FROM objects WHERE key=?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);

        let delta = new_size - prev_size;

        if delta > 0 && used + delta > capacity {
            return Err(anyhow!(
                "capacity_exceeded: used={} delta={} cap={}",
                used,
                delta,
                capacity
            ));
        }

        tx.execute(
            "INSERT INTO objects(key, value, dlv_id, size_bytes) VALUES (?1,?2,?3,?4)
             ON CONFLICT (key) DO UPDATE SET value=excluded.value, size_bytes=excluded.size_bytes, dlv_id=excluded.dlv_id",
            params![key, value, dlv_id, new_size],
        )?;

        if delta != 0 {
            tx.execute(
                "UPDATE dlv_slots SET used_bytes = used_bytes + ?2 WHERE dlv_id = ?1",
                params![dlv_id, delta],
            )?;
        }

        tx.commit()?;
        Ok(())
    })
    .await
}

pub async fn list_objects_page(
    pool: &DBPool,
    prefix: Option<&str>,
    cursor: Option<&str>,
    limit: i64,
) -> Result<Vec<(String, Vec<u8>, i64)>> {
    let prefix = prefix.map(|s| s.to_string());
    let cursor = cursor.map(|s| s.to_string());
    let limit = limit.clamp(1, 1000);

    with_conn(pool, move |conn| {
        let rows: Vec<(String, Vec<u8>, i64)> = match (prefix.as_deref(), cursor.as_deref()) {
            (Some(p), Some(c)) => {
                let like = format!("{}%", p);
                let mut stmt = conn.prepare_cached(
                    "SELECT key, dlv_id, size_bytes FROM objects WHERE key LIKE ?1 AND key > ?2 ORDER BY key ASC LIMIT ?3",
                )?;
                let result = stmt.query_map(params![like, c, limit], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?.collect::<std::result::Result<Vec<_>, _>>()?;
                result
            }
            (Some(p), None) => {
                let like = format!("{}%", p);
                let mut stmt = conn.prepare_cached(
                    "SELECT key, dlv_id, size_bytes FROM objects WHERE key LIKE ?1 ORDER BY key ASC LIMIT ?2",
                )?;
                let result = stmt.query_map(params![like, limit], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?.collect::<std::result::Result<Vec<_>, _>>()?;
                result
            }
            (None, Some(c)) => {
                let mut stmt = conn.prepare_cached(
                    "SELECT key, dlv_id, size_bytes FROM objects WHERE key > ?1 ORDER BY key ASC LIMIT ?2",
                )?;
                let result = stmt.query_map(params![c, limit], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?.collect::<std::result::Result<Vec<_>, _>>()?;
                result
            }
            (None, None) => {
                let mut stmt = conn.prepare_cached(
                    "SELECT key, dlv_id, size_bytes FROM objects ORDER BY key ASC LIMIT ?1",
                )?;
                let result = stmt.query_map(params![limit], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?.collect::<std::result::Result<Vec<_>, _>>()?;
                result
            }
        };
        Ok(rows)
    })
    .await
}

// ===================== b0x Inbox Spool (clockless) =====================

pub async fn spool_insert(
    pool: &DBPool,
    device_id: &str,
    message_id: &str,
    envelope: &[u8],
) -> Result<()> {
    let device_id = device_id.to_string();
    let message_id = message_id.to_string();
    let envelope = envelope.to_vec();
    with_conn(pool, move |conn| {
        let tx = conn.unchecked_transaction()?;
        let seq: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(seq_num), 0) + 1 FROM inbox_spool WHERE device_id = ?1",
                params![device_id],
                |row| row.get(0),
            )?;
        tx.execute(
            "INSERT OR IGNORE INTO inbox_spool(device_id, message_id, envelope, seq_num) VALUES (?1, ?2, ?3, ?4)",
            params![device_id, message_id, envelope, seq],
        )?;
        tx.commit()?;
        Ok(())
    })
    .await
}

pub async fn spool_insert_with_expiration(
    pool: &DBPool,
    device_id: &str,
    message_id: &str,
    envelope: &[u8],
    expires_at_iter: Option<i64>,
) -> Result<()> {
    let device_id = device_id.to_string();
    let message_id = message_id.to_string();
    let envelope = envelope.to_vec();
    with_conn(pool, move |conn| {
        let tx = conn.unchecked_transaction()?;
        let seq: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(seq_num), 0) + 1 FROM inbox_spool WHERE device_id = ?1",
                params![device_id],
                |row| row.get(0),
            )?;
        tx.execute(
            "INSERT OR IGNORE INTO inbox_spool(device_id, message_id, envelope, seq_num, expires_at_iter)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![device_id, message_id, envelope, seq, expires_at_iter],
        )?;
        tx.commit()?;
        Ok(())
    })
    .await
}

pub async fn spool_list_unacked_from_seq(
    pool: &DBPool,
    device_id: &str,
    from_seq: i64,
    limit: i64,
) -> Result<Vec<(Vec<u8>, i64)>> {
    let device_id = device_id.to_string();
    with_conn(pool, move |conn| {
        let mut stmt = conn.prepare_cached(
            "SELECT envelope, seq_num FROM inbox_spool
             WHERE device_id=?1 AND acked=0 AND seq_num >= ?2
             ORDER BY seq_num ASC LIMIT ?3",
        )?;
        let rows = stmt
            .query_map(params![device_id, from_seq, limit], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .await
}

pub async fn spool_list(
    pool: &DBPool,
    device_id: &str,
    include_acked: bool,
    limit: i64,
) -> Result<Vec<Vec<u8>>> {
    let device_id = device_id.to_string();
    with_conn(pool, move |conn| {
        let rows: Vec<Vec<u8>> = if include_acked {
            let mut stmt = conn.prepare_cached(
                "SELECT envelope FROM inbox_spool WHERE device_id=?1 ORDER BY id ASC LIMIT ?2",
            )?;
            let result = stmt.query_map(params![device_id, limit], |row| row.get(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            result
        } else {
            let mut stmt = conn.prepare_cached(
                "SELECT envelope FROM inbox_spool WHERE device_id=?1 AND acked=0 ORDER BY id ASC LIMIT ?2",
            )?;
            let result = stmt.query_map(params![device_id, limit], |row| row.get(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            result
        };
        Ok(rows)
    })
    .await
}

pub async fn spool_ack(pool: &DBPool, device_id: &str, message_ids: &[String]) -> Result<u64> {
    if message_ids.is_empty() {
        return Ok(0);
    }
    let device_id = device_id.to_string();
    let message_ids = message_ids.to_vec();
    with_conn(pool, move |conn| {
        let mut total: u64 = 0;
        for mid in &message_ids {
            let n = conn.execute(
                "UPDATE inbox_spool SET acked=1 WHERE device_id=?1 AND message_id=?2",
                params![device_id, mid],
            )?;
            total += n as u64;
        }
        Ok(total)
    })
    .await
}

pub async fn spool_lookup_by_message_id(
    pool: &DBPool,
    message_id: &str,
) -> Result<Option<(Vec<u8>, bool)>> {
    let message_id = message_id.to_string();
    with_conn(pool, move |conn| {
        let row = conn.query_row(
            "SELECT envelope, acked FROM inbox_spool WHERE message_id = ?1 LIMIT 1",
            params![message_id],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)? != 0)),
        );

        match row {
            Ok(record) => Ok(Some(record)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    })
    .await
}

pub async fn cleanup_expired_objects_and_spool(
    pool: &DBPool,
    timing: &dyn TimingStrategy,
    current_iter: i64,
) -> Result<(u64, u64)> {
    let expiration_threshold = timing.calculate_expiration_iter(current_iter, 0).await;

    with_conn(pool, move |conn| {
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM objects", [], |row| row.get(0))?;
        let size: i64 = conn.query_row(
            "SELECT COALESCE(SUM(size_bytes), 0) FROM objects",
            [],
            |row| row.get(0),
        )?;

        if count < (BEV as i64) && size < (BBYTES as i64) {
            return Ok((0, 0));
        }

        let objects_deleted = conn.execute(
            "DELETE FROM objects WHERE iter_expires IS NOT NULL AND iter_expires < ?1",
            params![expiration_threshold],
        )? as u64;

        let spool_deleted = conn.execute(
            "DELETE FROM inbox_spool WHERE expires_at_iter IS NOT NULL AND expires_at_iter < ?1",
            params![expiration_threshold],
        )? as u64;

        let acked_cleanup_iter = current_iter - 1000;
        let acked_deleted = conn.execute(
            "DELETE FROM inbox_spool WHERE acked = 1 AND seq_num < ?1",
            params![acked_cleanup_iter],
        )? as u64;

        Ok((objects_deleted, spool_deleted + acked_deleted))
    })
    .await
}

pub async fn delete_slot_object(pool: &DBPool, _dlv_id: &[u8], key: &str) -> Result<u64> {
    let key = key.to_string();
    with_conn(pool, move |conn| {
        let tx = conn.unchecked_transaction()?;

        let row: Option<(Vec<u8>, i64)> = tx
            .query_row(
                "SELECT dlv_id, size_bytes FROM objects WHERE key = ?1",
                params![key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        let Some((dlv_id, size_bytes)) = row else {
            tx.commit()?;
            return Ok(0);
        };

        let deleted = tx.execute("DELETE FROM objects WHERE key = ?1", params![key])? as u64;

        if deleted > 0 && size_bytes > 0 {
            tx.execute(
                "UPDATE dlv_slots SET used_bytes = MAX(used_bytes - ?2, 0) WHERE dlv_id = ?1",
                params![dlv_id, size_bytes],
            )?;
        }

        tx.commit()?;
        Ok(deleted)
    })
    .await
}

// ===================== Centralized Query Functions =====================

pub async fn get_object_by_key(pool: &DBPool, key: &str) -> Result<Option<Vec<u8>>> {
    let key = key.to_string();
    with_conn(pool, move |conn| {
        let result: Option<Vec<u8>> = conn
            .query_row(
                "SELECT value FROM objects WHERE key=?1 LIMIT 1",
                params![key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(result)
    })
    .await
}

pub async fn get_dlv_slot_capacity(pool: &DBPool, dlv_id: &[u8]) -> Result<Option<(i64, i64)>> {
    let dlv_id = dlv_id.to_vec();
    with_conn(pool, move |conn| {
        let result: Option<(i64, i64)> = conn
            .query_row(
                "SELECT capacity_bytes, used_bytes FROM dlv_slots WHERE dlv_id=?1 LIMIT 1",
                params![dlv_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        Ok(result)
    })
    .await
}

pub async fn register_device(
    pool: &DBPool,
    device_id: &str,
    genesis_hash: &[u8],
    pubkey: &[u8],
    token_hash: &[u8],
) -> Result<u64> {
    let device_id = device_id.to_string();
    let genesis_hash = genesis_hash.to_vec();
    let pubkey = pubkey.to_vec();
    let token_hash = token_hash.to_vec();
    with_conn(pool, move |conn| {
        let rows = conn.execute(
            "INSERT OR IGNORE INTO devices (device_id, genesis_hash, pubkey, token_hash, revoked)
             VALUES (?1, ?2, ?3, ?4, 0)",
            params![device_id, genesis_hash, pubkey, token_hash],
        )?;
        Ok(rows as u64)
    })
    .await
}

pub async fn get_device(pool: &DBPool, device_id: &str) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let device_id = device_id.to_string();
    with_conn(pool, move |conn| {
        let result: Option<(Vec<u8>, Vec<u8>)> = conn
            .query_row(
                "SELECT genesis_hash, pubkey FROM devices WHERE device_id = ?1",
                params![device_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        Ok(result)
    })
    .await
}

pub async fn update_device_token_hash(
    pool: &DBPool,
    device_id: &str,
    token_hash: &[u8],
) -> Result<()> {
    let device_id = device_id.to_string();
    let token_hash = token_hash.to_vec();
    with_conn(pool, move |conn| {
        conn.execute(
            "UPDATE devices SET token_hash = ?1 WHERE device_id = ?2",
            params![token_hash, device_id],
        )?;
        Ok(())
    })
    .await
}

pub async fn lookup_device_auth(
    pool: &DBPool,
    device_id: &str,
) -> Result<Option<(Vec<u8>, Vec<u8>, bool)>> {
    let device_id = device_id.to_string();
    with_conn(pool, move |conn| {
        let result: Option<(Vec<u8>, Vec<u8>, bool)> = conn
            .query_row(
                "SELECT pubkey, token_hash, revoked FROM devices WHERE device_id = ?1",
                params![device_id],
                |row| {
                    let revoked: i32 = row.get(2)?;
                    Ok((row.get(0)?, row.get(1)?, revoked != 0))
                },
            )
            .optional()?;
        Ok(result)
    })
    .await
}

pub async fn insert_inbox_receipt(
    pool: &DBPool,
    device_id: &str,
    message_id: &str,
) -> Result<bool> {
    let device_id = device_id.to_string();
    let message_id = message_id.to_string();
    with_conn(pool, move |conn| {
        let rows = conn.execute(
            "INSERT OR IGNORE INTO inbox_receipts(device_id, message_id) VALUES (?1, ?2)",
            params![device_id, message_id],
        )?;
        Ok(rows > 0)
    })
    .await
}

pub async fn prune_inbox_receipts(pool: &DBPool, device_id: &str, keep_count: i64) -> Result<()> {
    let device_id = device_id.to_string();
    with_conn(pool, move |conn| {
        let _ = conn.execute(
            "DELETE FROM inbox_receipts
             WHERE device_id = ?1 AND id < (
               SELECT id FROM inbox_receipts
               WHERE device_id = ?1
               ORDER BY id DESC
               LIMIT 1 OFFSET ?2
             )",
            params![device_id, keep_count],
        );
        Ok(())
    })
    .await
}

// ===================== PaidK Spend-Gate =====================

pub async fn store_payment_receipt(
    pool: &DBPool,
    device_id: &str,
    operator_node_id: &[u8],
    amount: i64,
    receipt_addr: &str,
    receipt_bytes: &[u8],
) -> Result<()> {
    let device_id = device_id.to_string();
    let operator_node_id = operator_node_id.to_vec();
    let receipt_addr = receipt_addr.to_string();
    let receipt_bytes = receipt_bytes.to_vec();
    with_conn(pool, move |conn| {
        conn.execute(
            "INSERT OR IGNORE INTO payment_receipts
             (device_id, operator_node_id, amount, receipt_addr, receipt_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                device_id,
                operator_node_id,
                amount,
                receipt_addr,
                receipt_bytes
            ],
        )?;
        Ok(())
    })
    .await
}

pub async fn count_distinct_paid_operators(
    pool: &DBPool,
    device_id: &str,
    flat_rate: i64,
) -> Result<i64> {
    let device_id = device_id.to_string();
    with_conn(pool, move |conn| {
        let count: i64 = conn.query_row(
            "SELECT COUNT(DISTINCT operator_node_id) FROM payment_receipts
             WHERE device_id = ?1 AND amount >= ?2",
            params![device_id, flat_rate],
            |row| row.get(0),
        )?;
        Ok(count)
    })
    .await
}

pub async fn mark_paidk_satisfied(pool: &DBPool, device_id: &str) -> Result<()> {
    let device_id = device_id.to_string();
    with_conn(pool, move |conn| {
        conn.execute(
            "UPDATE devices SET paidk_satisfied = 1 WHERE device_id = ?1",
            params![device_id],
        )?;
        Ok(())
    })
    .await
}

pub async fn is_paidk_satisfied(pool: &DBPool, device_id: &str) -> Result<bool> {
    let device_id = device_id.to_string();
    with_conn(pool, move |conn| {
        let result: Option<i32> = conn
            .query_row(
                "SELECT paidk_satisfied FROM devices WHERE device_id = ?1",
                params![device_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(result.map(|v| v != 0).unwrap_or(false))
    })
    .await
}

// ===================== Node Registry & Signals =====================

pub async fn upsert_registry_node(pool: &DBPool, node_id: &[u8], first_cycle: i64) -> Result<()> {
    let node_id = node_id.to_vec();
    with_conn(pool, move |conn| {
        conn.execute(
            "INSERT OR IGNORE INTO node_registry (node_id, first_cycle) VALUES (?1, ?2)",
            params![node_id, first_cycle],
        )?;
        Ok(())
    })
    .await
}

pub async fn get_active_registry_node_ids(pool: &DBPool) -> Result<Vec<Vec<u8>>> {
    with_conn(pool, |conn| {
        let mut stmt = conn.prepare_cached(
            "SELECT node_id FROM node_registry WHERE active = 1 ORDER BY node_id ASC",
        )?;
        let rows = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .await
}

pub async fn get_active_registry_nodes(pool: &DBPool) -> Result<Vec<(Vec<u8>, i64, f64)>> {
    with_conn(pool, |conn| {
        let mut stmt = conn.prepare_cached(
            "SELECT node_id, first_cycle, utilization_avg FROM node_registry
             WHERE active = 1 ORDER BY node_id ASC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, f64>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .await
}

pub async fn deactivate_registry_node(pool: &DBPool, node_id: &[u8]) -> Result<()> {
    let node_id = node_id.to_vec();
    with_conn(pool, move |conn| {
        conn.execute(
            "UPDATE node_registry SET active = 0 WHERE node_id = ?1",
            params![node_id],
        )?;
        Ok(())
    })
    .await
}

pub async fn update_registry_node_utilization(
    pool: &DBPool,
    node_id: &[u8],
    utilization_avg: f64,
) -> Result<()> {
    let node_id = node_id.to_vec();
    with_conn(pool, move |conn| {
        conn.execute(
            "UPDATE node_registry SET utilization_avg = ?2 WHERE node_id = ?1",
            params![node_id, utilization_avg],
        )?;
        Ok(())
    })
    .await
}

/// Parameters for storing a capacity signal. Mirrors the pg.rs definition to
/// satisfy the 7-argument clippy limit on both backends.
#[derive(Debug, Clone, Copy)]
pub struct CapacitySignalParams<'a> {
    pub signal_addr: &'a str,
    pub node_id: &'a [u8],
    pub signal_type: i16,
    pub capacity: i64,
    pub cycle_window_start: i64,
    pub cycle_window_end: i64,
    pub signal_bytes: &'a [u8],
}

pub async fn store_capacity_signal(pool: &DBPool, p: &CapacitySignalParams<'_>) -> Result<()> {
    let signal_addr = p.signal_addr.to_string();
    let node_id = p.node_id.to_vec();
    let signal_type = p.signal_type;
    let capacity = p.capacity;
    let cycle_window_start = p.cycle_window_start;
    let cycle_window_end = p.cycle_window_end;
    let signal_bytes = p.signal_bytes.to_vec();
    with_conn(pool, move |conn| {
        conn.execute(
            "INSERT OR IGNORE INTO capacity_signals
             (signal_addr, node_id, signal_type, capacity, cycle_window_start, cycle_window_end, signal_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                signal_addr,
                node_id,
                signal_type as i32,
                capacity,
                cycle_window_start,
                cycle_window_end,
                signal_bytes
            ],
        )?;
        Ok(())
    })
    .await
}

pub async fn count_up_signals(pool: &DBPool, window_start: i64, window_end: i64) -> Result<i64> {
    with_conn(pool, move |conn| {
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM capacity_signals
             WHERE signal_type = 1 AND cycle_window_end >= ?1 AND cycle_window_end <= ?2",
            params![window_start, window_end],
            |row| row.get(0),
        )?;
        Ok(count)
    })
    .await
}

pub async fn count_down_signals_excluding_grace(
    pool: &DBPool,
    window_start: i64,
    window_end: i64,
    current_cycle: i64,
    grace_cycles: i64,
) -> Result<i64> {
    with_conn(pool, move |conn| {
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM capacity_signals cs
             WHERE cs.signal_type = 2
               AND cs.cycle_window_end >= ?1
               AND cs.cycle_window_end <= ?2
               AND NOT EXISTS (
                 SELECT 1 FROM node_registry nr
                 WHERE nr.node_id = cs.node_id
                   AND nr.active = 1
                   AND nr.first_cycle + ?4 > ?3
               )",
            params![window_start, window_end, current_cycle, grace_cycles],
            |row| row.get(0),
        )?;
        Ok(count)
    })
    .await
}

pub async fn store_applicant(
    pool: &DBPool,
    applicant_addr: &str,
    seed_app: &[u8],
    stake_dlv: &[u8],
    capacity: i64,
    applicant_bytes: &[u8],
) -> Result<()> {
    let applicant_addr = applicant_addr.to_string();
    let seed_app = seed_app.to_vec();
    let stake_dlv = stake_dlv.to_vec();
    let applicant_bytes = applicant_bytes.to_vec();
    with_conn(pool, move |conn| {
        conn.execute(
            "INSERT OR IGNORE INTO applicants
             (applicant_addr, seed_app, stake_dlv, capacity, applicant_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                applicant_addr,
                seed_app,
                stake_dlv,
                capacity,
                applicant_bytes
            ],
        )?;
        Ok(())
    })
    .await
}

pub async fn list_pending_applicants(
    pool: &DBPool,
) -> Result<Vec<(String, Vec<u8>, Vec<u8>, i64)>> {
    with_conn(pool, |conn| {
        let mut stmt = conn.prepare_cached(
            "SELECT applicant_addr, seed_app, stake_dlv, capacity FROM applicants
             ORDER BY applicant_addr ASC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .await
}

pub async fn remove_applicant(pool: &DBPool, applicant_addr: &str) -> Result<()> {
    let applicant_addr = applicant_addr.to_string();
    with_conn(pool, move |conn| {
        conn.execute(
            "DELETE FROM applicants WHERE applicant_addr = ?1",
            params![applicant_addr],
        )?;
        Ok(())
    })
    .await
}

// ===================== DrainProof & Stake Exit =====================

pub async fn store_drain_proof(
    pool: &DBPool,
    proof_addr: &str,
    node_id: &[u8],
    start_cycle: i64,
    end_cycle: i64,
    verified_local: bool,
    proof_bytes: &[u8],
) -> Result<()> {
    let proof_addr = proof_addr.to_string();
    let node_id = node_id.to_vec();
    let proof_bytes = proof_bytes.to_vec();
    let verified_local_i = if verified_local { 1i32 } else { 0i32 };
    with_conn(pool, move |conn| {
        conn.execute(
            "INSERT OR IGNORE INTO drain_proofs
             (proof_addr, node_id, start_cycle, end_cycle, verified_local, proof_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                proof_addr,
                node_id,
                start_cycle,
                end_cycle,
                verified_local_i,
                proof_bytes
            ],
        )?;
        Ok(())
    })
    .await
}

pub async fn get_drain_proof_for_node(pool: &DBPool, node_id: &[u8]) -> Result<Option<Vec<u8>>> {
    let node_id = node_id.to_vec();
    with_conn(pool, move |conn| {
        let result: Option<Vec<u8>> = conn
            .query_row(
                "SELECT proof_bytes FROM drain_proofs WHERE node_id = ?1
                 ORDER BY end_cycle DESC LIMIT 1",
                params![node_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(result)
    })
    .await
}

pub async fn verify_bytecommit_chain_empty(
    pool: &DBPool,
    node_id_text: &str,
    start_cycle: i64,
    required_d: i64,
) -> Result<bool> {
    let node_id_text = node_id_text.to_string();
    with_conn(pool, move |conn| {
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM bytecommit_chain
             WHERE node_id = ?1 AND cycle_index >= ?2 AND cycle_index < ?2 + ?3",
            params![node_id_text, start_cycle, required_d],
            |row| row.get(0),
        )?;
        Ok(count >= required_d)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_encode_decode_roundtrip_and_sorting() {
        let headers = vec![
            ("X-Test".to_string(), b"b".to_vec()),
            ("x-test".to_string(), b"a".to_vec()),
            (
                "Content-Type".to_string(),
                b"application/octet-stream".to_vec(),
            ),
        ];
        let enc = encode_headers_deterministic(&headers);
        let dec = match decode_headers_deterministic(&enc) {
            Ok(decoded) => decoded,
            Err(err) => panic!("header decode should succeed: {err:?}"),
        };

        assert_eq!(dec[0].0, "content-type");
        assert_eq!(dec[1].0, "x-test");
        assert_eq!(dec[1].1, b"a".to_vec());
        assert_eq!(dec[2].0, "x-test");
        assert_eq!(dec[2].1, b"b".to_vec());
    }
}
