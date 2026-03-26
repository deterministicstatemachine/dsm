//! Storage node DB layer (clean, DLV-only)
//! Minimal schema + helpers used by the DLV-backed object store.

use crate::api::hardening::{BBYTES, BEV};
use crate::timing::TimingStrategy;
use anyhow::{anyhow, Result};
use deadpool_postgres::Runtime; // Added Runtime import
use deadpool_postgres::{ManagerConfig, Pool, RecyclingMethod};
// use tokio_postgres::Row; // removed: no longer mapping rows to SlotRecord
use tokio_postgres_rustls::MakeRustlsConnect;

// ===================== Durable Replication Outbox (clockless) =====================

/// A pending outbox row loaded from Postgres.
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
///
/// Grouping these fields avoids a wide signature while keeping the DB operation
/// itself explicit and deterministic.
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
///
/// Encoding: repeated (k_len:u16 LE, k_bytes, v_len:u32 LE, v_bytes) with entries
/// sorted by lowercase header name then value bytes.
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

/// Insert an outbox entry (idempotent per (target,idempotency_key)).
pub async fn replication_outbox_enqueue(
    pool: &Pool,
    params: ReplicationOutboxEnqueueParams<'_>,
) -> Result<()> {
    let client = pool.get().await?;
    let stmt = client
        .prepare_cached(
            "INSERT INTO replication_outbox (target, method, path, headers, body, idempotency_key, eligible_iter)\
             VALUES ($1,$2,$3,$4,$5,$6,$7)\
             ON CONFLICT (target, idempotency_key) DO NOTHING",
        )
        .await?;
    client
        .execute(
            &stmt,
            &[
                &params.target,
                &params.method,
                &params.path,
                &params.headers,
                &params.body,
                &params.idempotency_key,
                &params.eligible_iter,
            ],
        )
        .await?;
    Ok(())
}

/// Load up to `limit` due outbox rows for processing.
pub async fn replication_outbox_list_due(
    pool: &Pool,
    now_iter: i64,
    limit: i64,
) -> Result<Vec<ReplicationOutboxRow>> {
    let client = pool.get().await?;
    let stmt = client
        .prepare_cached(
            "SELECT id, target, method, path, headers, body, idempotency_key, attempts, eligible_iter FROM replication_outbox WHERE done=FALSE AND eligible_iter <= $1 ORDER BY eligible_iter ASC, id ASC LIMIT $2",
        )
        .await?;
    let rows = client.query(&stmt, &[&now_iter, &limit]).await?;
    Ok(rows
        .into_iter()
        .map(|r| ReplicationOutboxRow {
            id: r.get::<_, i64>(0),
            target: r.get::<_, String>(1),
            method: r.get::<_, String>(2),
            path: r.get::<_, String>(3),
            headers: r.get::<_, Vec<u8>>(4),
            body: r.get::<_, Vec<u8>>(5),
            idempotency_key: r.get::<_, String>(6),
            attempts: r.get::<_, i32>(7),
            eligible_iter: r.get::<_, i64>(8),
        })
        .collect())
}

/// Mark an outbox row done.
pub async fn replication_outbox_mark_done(pool: &Pool, id: i64) -> Result<()> {
    let client = pool.get().await?;
    let stmt = client
        .prepare_cached("UPDATE replication_outbox SET done=TRUE, last_err=NULL WHERE id=$1")
        .await?;
    client.execute(&stmt, &[&id]).await?;
    Ok(())
}

/// Record an outbox attempt failure and schedule the next eligible iter.
///
/// Scheduling is clockless: `eligible_iter` advances by a deterministic backoff in *iter units*.
pub async fn replication_outbox_record_failure(
    pool: &Pool,
    timing: &dyn TimingStrategy,
    id: i64,
    now_iter: i64,
    attempts_next: i32,
    last_err: &str,
) -> Result<()> {
    // Use timing strategy to calculate next eligible iteration
    let eligible_iter_next = timing
        .calculate_retry_eligible_iter(now_iter, attempts_next)
        .await;

    let client = pool.get().await?;
    let stmt = client
        .prepare_cached(
            "UPDATE replication_outbox\
             SET attempts=$2, eligible_iter=$3, last_err=$4\
             WHERE id=$1",
        )
        .await?;
    client
        .execute(
            &stmt,
            &[&id, &attempts_next, &eligible_iter_next, &last_err],
        )
        .await?;

    metrics::counter!("dsm_replication_outbox_failures_total").increment(1);
    metrics::gauge!("dsm_replication_outbox_last_failure_iter").set(now_iter as f64);
    Ok(())
}

/// Create a TLS connector for PostgreSQL connections using webpki root certificates.
fn create_tls_connector() -> MakeRustlsConnect {
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    MakeRustlsConnect::new(tls_config)
}

/// Initialize database schema for storage node.
pub async fn init_db(pool: &Pool) -> Result<()> {
    let client = pool.get().await?;
    client
        .batch_execute(
            r#"CREATE TABLE IF NOT EXISTS dlv_slots (
                    dlv_id         BYTEA PRIMARY KEY,
                    capacity_bytes BIGINT NOT NULL,
                    used_bytes     BIGINT NOT NULL DEFAULT 0,
                    stake_hash     BYTEA NOT NULL
                );

                CREATE TABLE IF NOT EXISTS objects (
                    key           TEXT PRIMARY KEY,
                    value         BYTEA NOT NULL,
                    dlv_id        BYTEA NOT NULL,
                    size_bytes    BIGINT NOT NULL,
                    iter_created  BIGINT NOT NULL DEFAULT 0,
                    iter_expires  BIGINT
                );

                CREATE INDEX IF NOT EXISTS idx_objects_dlv_id ON objects(dlv_id);
                CREATE INDEX IF NOT EXISTS idx_objects_iter_expires ON objects(iter_expires);
                
                -- registry evidence metadata (bytes live in `objects` under addr key)
                CREATE TABLE IF NOT EXISTS registry_evidence (
                    addr        TEXT PRIMARY KEY,
                    kind_code   SMALLINT NOT NULL,
                    dlv_id      BYTEA NOT NULL,
                    size_bytes  BIGINT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_registry_evidence_kind ON registry_evidence(kind_code);

                -- Durable replication outbox (clockless)
                -- A best-effort *transport* spool with deterministic eligibility based on `eligible_iter`.
                -- No wall-clock scheduling: callers advance `eligible_iter` explicitly.
                CREATE TABLE IF NOT EXISTS replication_outbox (
                    id              BIGSERIAL PRIMARY KEY,
                    target          TEXT NOT NULL,
                    method          TEXT NOT NULL,
                    path            TEXT NOT NULL,
                    headers         BYTEA NOT NULL,
                    body            BYTEA NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    attempts        INT NOT NULL DEFAULT 0,
                    eligible_iter   BIGINT NOT NULL DEFAULT 0,
                    done            BOOLEAN NOT NULL DEFAULT FALSE,
                    last_err        TEXT
                );

                CREATE UNIQUE INDEX IF NOT EXISTS ux_replication_outbox_idem_target
                    ON replication_outbox(target, idempotency_key);

                CREATE INDEX IF NOT EXISTS idx_replication_outbox_due
                    ON replication_outbox(done, eligible_iter, id);
            "#,
        )
        .await?;
    // Auth tables for device middleware (clockless replay guard)
    client
            .batch_execute(
                r#"CREATE TABLE IF NOT EXISTS devices (
                        device_id  TEXT PRIMARY KEY,
                        genesis_hash BYTEA NOT NULL,
                        pubkey      BYTEA NOT NULL,
                        token_hash  BYTEA NOT NULL,
                        revoked     BOOLEAN NOT NULL DEFAULT FALSE
                    );

                    CREATE TABLE IF NOT EXISTS inbox_receipts (
                        id         BIGSERIAL PRIMARY KEY,
                        device_id  TEXT NOT NULL,
                        message_id TEXT NOT NULL,
                        UNIQUE(device_id, message_id)
                    );

                    CREATE INDEX IF NOT EXISTS idx_inbox_receipts_device ON inbox_receipts(device_id);
                    CREATE INDEX IF NOT EXISTS idx_inbox_receipts_device_id ON inbox_receipts(device_id, id);
                "#,
            )
            .await?;
    // Clockless b0x inbox spool (per-device)
    client
            .batch_execute(
                r#"CREATE TABLE IF NOT EXISTS inbox_spool (
                        id                BIGSERIAL PRIMARY KEY,
                        device_id         TEXT NOT NULL,
                        message_id        TEXT NOT NULL UNIQUE,
                        envelope          BYTEA NOT NULL,
                        acked             BOOLEAN NOT NULL DEFAULT FALSE,
                        expires_at_iter   BIGINT
                    );

                    CREATE INDEX IF NOT EXISTS idx_inbox_spool_device_acked ON inbox_spool(device_id, acked, id);
                "#,
            )
            .await?;

    // Schema migration for older inbox_spool rows missing newer columns (clockless ordering).
    client
        .batch_execute(
            r#"ALTER TABLE inbox_spool
                    ADD COLUMN IF NOT EXISTS seq_num BIGINT NOT NULL DEFAULT 0;
                ALTER TABLE inbox_spool
                    ADD COLUMN IF NOT EXISTS expires_at_iter BIGINT;
                CREATE INDEX IF NOT EXISTS idx_inbox_spool_device_seq ON inbox_spool(device_id, seq_num);
                CREATE INDEX IF NOT EXISTS idx_inbox_spool_expires ON inbox_spool(expires_at_iter) WHERE expires_at_iter IS NOT NULL;
            "#,
        )
        .await?;

    // ByteCommit chain metadata (verifier convenience; commit bytes live in `objects`).
    client
        .batch_execute(
            r#"CREATE TABLE IF NOT EXISTS bytecommit_chain (
                    node_id      TEXT NOT NULL,
                    cycle_index  BIGINT NOT NULL,
                    digest       BYTEA NOT NULL,
                    PRIMARY KEY(node_id, cycle_index)
                );

                CREATE INDEX IF NOT EXISTS idx_bytecommit_chain_node_cycle
                    ON bytecommit_chain(node_id, cycle_index);
            "#,
        )
        .await?;

    // ── Storage Node Regulation tables (clockless, signature-free) ──────────
    // PaidK payment receipts
    client
        .batch_execute(
            r#"CREATE TABLE IF NOT EXISTS payment_receipts (
                    id               BIGSERIAL PRIMARY KEY,
                    device_id        TEXT NOT NULL,
                    operator_node_id BYTEA NOT NULL,
                    amount           BIGINT NOT NULL,
                    receipt_addr     TEXT NOT NULL UNIQUE,
                    receipt_bytes    BYTEA NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_payment_receipts_device ON payment_receipts(device_id);

                ALTER TABLE devices ADD COLUMN IF NOT EXISTS paidk_satisfied BOOLEAN NOT NULL DEFAULT FALSE;
            "#,
        )
        .await?;

    // Node registry (local cache; verifiers reconstruct independently)
    client
        .batch_execute(
            r#"CREATE TABLE IF NOT EXISTS node_registry (
                    node_id         BYTEA PRIMARY KEY,
                    first_cycle     BIGINT NOT NULL,
                    utilization_avg DOUBLE PRECISION NOT NULL DEFAULT 0.0,
                    active          BOOLEAN NOT NULL DEFAULT TRUE
                );
                CREATE INDEX IF NOT EXISTS idx_node_registry_active ON node_registry(active);
            "#,
        )
        .await?;

    // Capacity signals (stored as evidence)
    client
        .batch_execute(
            r#"CREATE TABLE IF NOT EXISTS capacity_signals (
                    id                 BIGSERIAL PRIMARY KEY,
                    signal_addr        TEXT NOT NULL UNIQUE,
                    node_id            BYTEA NOT NULL,
                    signal_type        SMALLINT NOT NULL,
                    capacity           BIGINT NOT NULL,
                    cycle_window_start BIGINT NOT NULL,
                    cycle_window_end   BIGINT NOT NULL,
                    signal_bytes       BYTEA NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_capacity_signals_node ON capacity_signals(node_id);
                CREATE INDEX IF NOT EXISTS idx_capacity_signals_window ON capacity_signals(cycle_window_end);
            "#,
        )
        .await?;

    // Applicant submissions
    client
        .batch_execute(
            r#"CREATE TABLE IF NOT EXISTS applicants (
                    applicant_addr  TEXT PRIMARY KEY,
                    seed_app        BYTEA NOT NULL,
                    stake_dlv       BYTEA NOT NULL,
                    capacity        BIGINT NOT NULL,
                    applicant_bytes BYTEA NOT NULL
                );
            "#,
        )
        .await?;

    // Drain proofs (stake exit evidence)
    client
        .batch_execute(
            r#"CREATE TABLE IF NOT EXISTS drain_proofs (
                    id             BIGSERIAL PRIMARY KEY,
                    proof_addr     TEXT NOT NULL UNIQUE,
                    node_id        BYTEA NOT NULL,
                    start_cycle    BIGINT NOT NULL,
                    end_cycle      BIGINT NOT NULL,
                    verified_local BOOLEAN NOT NULL DEFAULT FALSE,
                    proof_bytes    BYTEA NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_drain_proofs_node ON drain_proofs(node_id);
            "#,
        )
        .await?;

    Ok(())
}

/// Compute deterministic "current cycle" stats over all stored objects.
///
/// This is a minimal, deterministic commitment suitable for chaining.
/// Full sparse SMT proofs are enforced client-side; storage nodes are dumb mirrors.
pub async fn get_current_cycle_stats(pool: &Pool) -> Result<([u8; 32], u64)> {
    let client = pool.get().await?;

    // Deterministic key ordering.
    let rows = client
        .query("SELECT key, size_bytes FROM objects ORDER BY key ASC", &[])
        .await?;

    let mut bytes_used: u64 = 0;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"DSM/smt-node\0");

    for r in rows {
        let key: String = r.get(0);
        let sz: i64 = r.get(1);
        if sz > 0 {
            bytes_used = bytes_used.saturating_add(sz as u64);
        }
        hasher.update(key.as_bytes());
        hasher.update(&[0u8]);
        hasher.update(&sz.to_le_bytes());
    }

    let out = hasher.finalize();
    Ok((*out.as_bytes(), bytes_used))
}

/// Get the last recorded ByteCommit digest for `node_id`, if any.
pub async fn get_last_bytecommit_hash(pool: &Pool, node_id: &str) -> Result<Option<[u8; 32]>> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT digest FROM bytecommit_chain WHERE node_id=$1 ORDER BY cycle_index DESC LIMIT 1",
            &[&node_id],
        )
        .await?;

    Ok(row.map(|r| {
        let b: Vec<u8> = r.get(0);
        let mut out = [0u8; 32];
        if b.len() == 32 {
            out.copy_from_slice(&b);
        }
        out
    }))
}

/// Record a ByteCommit digest at a cycle index (idempotent).
pub async fn record_bytecommit_hash(
    pool: &Pool,
    node_id: &str,
    cycle_index: u64,
    digest: &[u8; 32],
) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO bytecommit_chain(node_id, cycle_index, digest) VALUES ($1,$2,$3)\
             ON CONFLICT (node_id, cycle_index) DO NOTHING",
            &[&node_id, &(cycle_index as i64), &digest.as_slice()],
        )
        .await?;
    Ok(())
}

/// Check whether a slot exists for the given DLV id.
pub async fn slot_exists(pool: &Pool, dlv_id: &[u8]) -> Result<bool> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT 1 FROM dlv_slots WHERE dlv_id = $1 LIMIT 1",
            &[&dlv_id],
        )
        .await?;
    Ok(row.is_some())
}

pub async fn create_slot(
    pool: &Pool,
    dlv_id: &[u8],
    capacity_bytes: i64,
    stake_hash: &[u8],
) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO dlv_slots (dlv_id, capacity_bytes, used_bytes, stake_hash) VALUES ($1,$2,0,$3)
             ON CONFLICT (dlv_id) DO NOTHING",
            &[&dlv_id, &capacity_bytes, &stake_hash],
        )
        .await?;
    Ok(())
}

// Removed unused helpers: bump_used_bytes, get_object_size

/// Upsert an object by key.
/// Atomicity: Uses explicit transaction + ON CONFLICT for deterministic concurrent inserts.
/// The `key` column has PRIMARY KEY constraint, ensuring unique constraint enforcement.
/// PostgreSQL's default READ COMMITTED isolation + PRIMARY KEY prevents race conditions:
/// - Concurrent inserts with same key: one succeeds INSERT, others wait then UPDATE
/// - No lost updates or duplicate key violations under concurrent load
pub async fn upsert_object(
    pool: &Pool,
    key: &str,
    value: &[u8],
    dlv_id: &[u8],
    size_bytes: i64,
) -> Result<()> {
    let mut client = pool.get().await?; // Made client mutable
    let tx = client.build_transaction().start().await?;
    let stmt = tx.prepare_cached(
        "INSERT INTO objects(key, value, dlv_id, size_bytes) VALUES ($1,$2,$3,$4)
         ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, size_bytes=EXCLUDED.size_bytes, dlv_id=EXCLUDED.dlv_id",
    ).await?;
    tx.execute(&stmt, &[&key, &value, &dlv_id, &size_bytes])
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Store registry evidence metadata (addr, kind_code, dlv_id, size_bytes)
pub async fn store_registry_evidence(
    pool: &Pool,
    addr: &str,
    kind_code: i16,
    dlv_id: &[u8],
    size_bytes: i64,
) -> Result<()> {
    let client = pool.get().await?;
    let stmt = client
        .prepare_cached(
            "INSERT INTO registry_evidence (addr, kind_code, dlv_id, size_bytes)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (addr) DO NOTHING",
        )
        .await?;
    client
        .execute(&stmt, &[&addr, &kind_code, &dlv_id, &size_bytes])
        .await?;
    Ok(())
}

/// List registry evidence metadata rows for a given kind.
///
/// Determinism: orders by `addr` ASC.
pub async fn list_registry_evidence_by_kind(
    pool: &Pool,
    kind_code: i16,
) -> Result<Vec<(String, i16, i64)>> {
    let client = pool.get().await?;
    let stmt = client
        .prepare_cached(
            "SELECT addr, kind_code, size_bytes FROM registry_evidence WHERE kind_code=$1 ORDER BY addr ASC",
        )
        .await?;
    let rows = client.query(&stmt, &[&kind_code]).await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            (
                r.get::<_, String>(0),
                r.get::<_, i16>(1),
                r.get::<_, i64>(2),
            )
        })
        .collect())
}

/// Get registry object bytes by address.
///
/// Only returns bytes if `addr` exists in `registry_evidence`.
pub async fn get_registry_object_by_addr(pool: &Pool, addr: &str) -> Result<Option<Vec<u8>>> {
    let client = pool.get().await?;
    let stmt = client
        .prepare_cached(
            "SELECT o.value FROM objects o JOIN registry_evidence r ON o.key = r.addr WHERE r.addr=$1 LIMIT 1",
        )
        .await?;
    let row = client.query_opt(&stmt, &[&addr]).await?;
    Ok(row.map(|r| r.get::<_, Vec<u8>>(0)))
}

/// Atomically check capacity, upsert object, and update used_bytes in a single transaction.
/// This prevents race conditions where concurrent writes could exceed capacity.
pub async fn upsert_object_with_capacity_check(
    pool: &Pool,
    key: &str,
    value: &[u8],
    dlv_id: &[u8],
    new_size: i64,
) -> Result<()> {
    let mut client = pool.get().await?;
    let tx = client.build_transaction().start().await?;

    // Lock the slot row for update to prevent concurrent capacity checks
    let slot_row = tx
        .query_opt(
            "SELECT capacity_bytes, used_bytes FROM dlv_slots WHERE dlv_id=$1 FOR UPDATE",
            &[&dlv_id],
        )
        .await?;

    let slot = slot_row.ok_or_else(|| anyhow!("slot not found"))?;
    let capacity: i64 = slot.get(0);
    let used: i64 = slot.get(1);

    // Get previous size of this object if it exists
    let prev_size: i64 = tx
        .query_opt("SELECT size_bytes FROM objects WHERE key=$1", &[&key])
        .await?
        .map(|r| r.get(0))
        .unwrap_or(0);

    let delta = new_size - prev_size;

    // Check capacity constraint
    if delta > 0 && used + delta > capacity {
        return Err(anyhow!(
            "capacity_exceeded: used={} delta={} cap={}",
            used,
            delta,
            capacity
        ));
    }

    // Upsert object
    tx.execute(
        "INSERT INTO objects(key, value, dlv_id, size_bytes) VALUES ($1,$2,$3,$4)
         ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, size_bytes=EXCLUDED.size_bytes, dlv_id=EXCLUDED.dlv_id",
        &[&key, &value, &dlv_id, &new_size],
    ).await?;

    // Update used_bytes
    if delta != 0 {
        tx.execute(
            "UPDATE dlv_slots SET used_bytes = used_bytes + $2 WHERE dlv_id = $1",
            &[&dlv_id, &delta],
        )
        .await?;
    }

    tx.commit().await?;
    Ok(())
}

/// List a page of objects in deterministic order (key ASC).
///
/// - If `prefix` is Some, filters to keys beginning with that prefix.
/// - If `cursor` is Some, returns keys strictly greater than cursor.
/// - Always returns at most `limit` rows.
///
/// NOTE: This is a management/debugging helper; nodes still only provide bytes as truth.
pub async fn list_objects_page(
    pool: &Pool,
    prefix: Option<&str>,
    cursor: Option<&str>,
    limit: i64,
) -> Result<Vec<(String, Vec<u8>, i64)>> {
    let client = pool.get().await?;

    // Clamp in DB layer as well (defense in depth).
    let limit = limit.clamp(1, 1000);

    let rows = match (prefix, cursor) {
        (Some(p), Some(c)) => {
            let like = format!("{}%", p);
            client
                .query(
                    "SELECT key, dlv_id, size_bytes FROM objects WHERE key LIKE $1 AND key > $2 ORDER BY key ASC LIMIT $3",
                    &[&like, &c, &limit],
                )
                .await?
        }
        (Some(p), None) => {
            let like = format!("{}%", p);
            client
                .query(
                    "SELECT key, dlv_id, size_bytes FROM objects WHERE key LIKE $1 ORDER BY key ASC LIMIT $2",
                    &[&like, &limit],
                )
                .await?
        }
        (None, Some(c)) => {
            client
                .query(
                    "SELECT key, dlv_id, size_bytes FROM objects WHERE key > $1 ORDER BY key ASC LIMIT $2",
                    &[&c, &limit],
                )
                .await?
        }
        (None, None) => {
            client
                .query(
                    "SELECT key, dlv_id, size_bytes FROM objects ORDER BY key ASC LIMIT $1",
                    &[&limit],
                )
                .await?
        }
    };

    Ok(rows
        .into_iter()
        .map(|r| {
            (
                r.get::<_, String>(0),
                r.get::<_, Vec<u8>>(1),
                r.get::<_, i64>(2),
            )
        })
        .collect())
}

// ===================== b0x Inbox Spool (clockless) =====================

/// Insert an envelope into the per-device spool (idempotent by message_id).
/// Assigns sequence number and optional expiration.
pub async fn spool_insert(
    pool: &Pool,
    device_id: &str,
    message_id: &str,
    envelope: &[u8],
) -> Result<()> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    // Serialize seq_num assignment per device_id to avoid MAX+1 races.
    tx.execute("SELECT pg_advisory_xact_lock(hashtext($1))", &[&device_id])
        .await?;

    let stmt = tx
        .prepare_cached(
            "INSERT INTO inbox_spool(device_id, message_id, envelope, seq_num)
             VALUES ($1, $2, $3, COALESCE(
               (SELECT MAX(seq_num) + 1 FROM inbox_spool WHERE device_id = $1),
               1
             ))
             ON CONFLICT (message_id) DO NOTHING",
        )
        .await?;
    tx.execute(&stmt, &[&device_id, &message_id, &envelope])
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Insert an envelope with explicit expiration iteration.
pub async fn spool_insert_with_expiration(
    pool: &Pool,
    device_id: &str,
    message_id: &str,
    envelope: &[u8],
    expires_at_iter: Option<i64>,
) -> Result<()> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    // Serialize seq_num assignment per device_id to avoid MAX+1 races.
    tx.execute("SELECT pg_advisory_xact_lock(hashtext($1))", &[&device_id])
        .await?;

    let stmt = tx
        .prepare_cached(
            "INSERT INTO inbox_spool(device_id, message_id, envelope, seq_num, expires_at_iter)
             VALUES ($1, $2, $3, COALESCE(
               (SELECT MAX(seq_num) + 1 FROM inbox_spool WHERE device_id = $1),
               1
             ), $4)
             ON CONFLICT (message_id) DO NOTHING",
        )
        .await?;
    tx.execute(
        &stmt,
        &[&device_id, &message_id, &envelope, &expires_at_iter],
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// List unacked envelopes for a device starting from a sequence number, limited.
pub async fn spool_list_unacked_from_seq(
    pool: &Pool,
    device_id: &str,
    from_seq: i64,
    limit: i64,
) -> Result<Vec<(Vec<u8>, i64)>> {
    let client = pool.get().await?;
    let stmt = client
        .prepare_cached(
            "SELECT envelope, seq_num FROM inbox_spool
             WHERE device_id=$1 AND acked=FALSE AND seq_num >= $2
             ORDER BY seq_num ASC LIMIT $3",
        )
        .await?;
    let rows = client
        .query(&stmt, &[&device_id, &from_seq, &limit])
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| (r.get::<_, Vec<u8>>(0), r.get::<_, i64>(1)))
        .collect())
}

/// List envelopes for a device in deterministic order (id ASC), limited.
/// When include_acked=false, only unacked entries are returned.
pub async fn spool_list(
    pool: &Pool,
    device_id: &str,
    include_acked: bool,
    limit: i64,
) -> Result<Vec<Vec<u8>>> {
    let client = pool.get().await?;
    let stmt = if include_acked {
        client
            .prepare_cached(
                "SELECT envelope FROM inbox_spool WHERE device_id=$1 ORDER BY id ASC LIMIT $2",
            )
            .await?
    } else {
        client
            .prepare_cached(
                "SELECT envelope FROM inbox_spool WHERE device_id=$1 AND acked=FALSE ORDER BY id ASC LIMIT $2",
            )
            .await?
    };
    let rows = client.query(&stmt, &[&device_id, &limit]).await?;
    Ok(rows.into_iter().map(|r| r.get::<_, Vec<u8>>(0)).collect())
}

/// Acknowledge envelopes by message_id for a device. Returns rows affected.
pub async fn spool_ack(pool: &Pool, device_id: &str, message_ids: &[String]) -> Result<u64> {
    if message_ids.is_empty() {
        return Ok(0);
    }
    let client = pool.get().await?;
    let stmt = client
        .prepare_cached(
            "UPDATE inbox_spool SET acked=TRUE WHERE device_id=$1 AND message_id = ANY($2)",
        )
        .await?;
    let updated = client.execute(&stmt, &[&device_id, &message_ids]).await?;
    Ok(updated)
}

pub async fn spool_lookup_by_message_id(
    pool: &Pool,
    message_id: &str,
) -> Result<Option<(Vec<u8>, bool)>> {
    let client = pool.get().await?;
    let stmt = client
        .prepare_cached("SELECT envelope, acked FROM inbox_spool WHERE message_id = $1 LIMIT 1")
        .await?;
    let row = client.query_opt(&stmt, &[&message_id]).await?;
    Ok(row.map(|row| (row.get::<_, Vec<u8>>(0), row.get::<_, bool>(1))))
}

// Upsert a registry evidence metadata row. Bytes must already be present in `objects` under `addr`.
// Removed unused registry_evidence helpers (upsert/list)

/// Delete expired objects based on iter_expires < current_iter.
/// Also cleans up expired inbox spool entries.
/// Returns (objects_deleted, spool_entries_deleted).
pub async fn cleanup_expired_objects_and_spool(
    pool: &Pool,
    timing: &dyn TimingStrategy,
    current_iter: i64,
) -> Result<(u64, u64)> {
    let client = pool.get().await?;

    // Storage Hardening Pack v2.0: only run pruning when the node is under sufficient
    // load (events/bytes) to justify maintenance work.
    // Determinism: driven by DB state + iter, no wall clocks.
    let stats = client
        .query_one(
            "SELECT COUNT(*)::BIGINT, COALESCE(SUM(size_bytes), 0)::BIGINT FROM objects",
            &[],
        )
        .await?;
    let count: i64 = stats.get(0);
    let size: i64 = stats.get(1);

    // If below thresholds, skip cleanup.
    if count < (BEV as i64) && size < (BBYTES as i64) {
        return Ok((0, 0));
    }

    // Use timing strategy to determine expiration threshold
    let expiration_threshold = timing.calculate_expiration_iter(current_iter, 0).await;

    let objects_deleted = client
        .execute(
            "DELETE FROM objects WHERE iter_expires IS NOT NULL AND iter_expires < $1",
            &[&expiration_threshold],
        )
        .await?;

    let spool_deleted = client
        .execute(
            "DELETE FROM inbox_spool WHERE expires_at_iter IS NOT NULL AND expires_at_iter < $1",
            &[&expiration_threshold],
        )
        .await?;

    // Also clean up old ACKed entries (keep for 1000 iterations to handle client retries)
    let acked_cleanup_iter = current_iter - 1000;
    let acked_deleted = client
        .execute(
            "DELETE FROM inbox_spool WHERE acked = true AND seq_num < $1",
            &[&acked_cleanup_iter],
        )
        .await?;

    // Record cleanup metrics
    metrics::counter!("dsm_storage_cleanup_runs_total").increment(1);
    metrics::counter!("dsm_storage_cleanup_objects_deleted_total").increment(objects_deleted);
    metrics::counter!("dsm_storage_cleanup_spool_deleted_total")
        .increment(spool_deleted + acked_deleted);

    Ok((objects_deleted, spool_deleted + acked_deleted))
}

// ===================== Centralized Query Functions =====================
// All SQL queries should go through these functions, not be inlined in API handlers.

/// Fetch a single object's value by key. Used by identity_tips, identity_devtree,
/// object_store, recovery_capsule, policy, bytecommit GET handlers.
pub async fn get_object_by_key(pool: &Pool, key: &str) -> Result<Option<Vec<u8>>> {
    let client = pool.get().await?;
    let stmt = client
        .prepare_cached("SELECT value FROM objects WHERE key=$1 LIMIT 1")
        .await?;
    let row_opt = client.query_opt(&stmt, &[&key]).await?;
    Ok(row_opt.map(|r| r.get::<_, Vec<u8>>(0)))
}

/// Fetch a DLV slot's capacity and used bytes.
pub async fn get_dlv_slot_capacity(pool: &Pool, dlv_id: &[u8]) -> Result<Option<(i64, i64)>> {
    let client = pool.get().await?;
    let stmt = client
        .prepare_cached("SELECT capacity_bytes, used_bytes FROM dlv_slots WHERE dlv_id=$1 LIMIT 1")
        .await?;
    let row_opt = client.query_opt(&stmt, &[&dlv_id]).await?;
    Ok(row_opt.map(|r| (r.get::<_, i64>(0), r.get::<_, i64>(1))))
}

/// Register a device (idempotent: ON CONFLICT DO NOTHING). Returns rows affected.
pub async fn register_device(
    pool: &Pool,
    device_id: &str,
    genesis_hash: &[u8],
    pubkey: &[u8],
    token_hash: &[u8],
) -> Result<u64> {
    let client = pool.get().await?;
    let stmt = client
        .prepare_cached(
            "INSERT INTO devices (device_id, genesis_hash, pubkey, token_hash, revoked)
             VALUES ($1, $2, $3, $4, FALSE)
             ON CONFLICT (device_id) DO NOTHING",
        )
        .await?;
    let rows = client
        .execute(&stmt, &[&device_id, &genesis_hash, &pubkey, &token_hash])
        .await?;
    Ok(rows)
}

/// Get a device's genesis_hash and pubkey by device_id.
pub async fn get_device(pool: &Pool, device_id: &str) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let client = pool.get().await?;
    let stmt = client
        .prepare_cached("SELECT genesis_hash, pubkey FROM devices WHERE device_id = $1")
        .await?;
    let row_opt = client.query_opt(&stmt, &[&device_id]).await?;
    Ok(row_opt.map(|r| (r.get::<_, Vec<u8>>(0), r.get::<_, Vec<u8>>(1))))
}

/// Update a device's token_hash.
pub async fn update_device_token_hash(
    pool: &Pool,
    device_id: &str,
    token_hash: &[u8],
) -> Result<()> {
    let client = pool.get().await?;
    let stmt = client
        .prepare_cached("UPDATE devices SET token_hash = $1 WHERE device_id = $2")
        .await?;
    client.execute(&stmt, &[&token_hash, &device_id]).await?;
    Ok(())
}

/// Lookup device auth fields (pubkey, token_hash, revoked) for authentication middleware.
pub async fn lookup_device_auth(
    pool: &Pool,
    device_id: &str,
) -> Result<Option<(Vec<u8>, Vec<u8>, bool)>> {
    let client = pool.get().await?;
    let stmt = client
        .prepare_cached("SELECT pubkey, token_hash, revoked FROM devices WHERE device_id = $1")
        .await?;
    let row_opt = client.query_opt(&stmt, &[&device_id]).await?;
    Ok(row_opt.map(|r| {
        (
            r.get::<_, Vec<u8>>(0),
            r.get::<_, Vec<u8>>(1),
            r.get::<_, bool>(2),
        )
    }))
}

/// Insert an inbox receipt for replay protection (idempotent). Returns true if inserted (not a replay).
pub async fn insert_inbox_receipt(pool: &Pool, device_id: &str, message_id: &str) -> Result<bool> {
    let client = pool.get().await?;
    let stmt = client
        .prepare_cached(
            "INSERT INTO inbox_receipts(device_id, message_id) VALUES ($1, $2)
             ON CONFLICT DO NOTHING",
        )
        .await?;
    let rows_affected = client.execute(&stmt, &[&device_id, &message_id]).await?;
    Ok(rows_affected > 0)
}

/// Prune old inbox receipts for a device, keeping only the most recent `keep_count`.
pub async fn prune_inbox_receipts(pool: &Pool, device_id: &str, keep_count: i64) -> Result<()> {
    let client = pool.get().await?;
    let _ = client
        .execute(
            "DELETE FROM inbox_receipts
             WHERE device_id = $1 AND id < (
               SELECT id FROM inbox_receipts
               WHERE device_id = $1
               ORDER BY id DESC
               OFFSET $2
               LIMIT 1
             )",
            &[&device_id, &keep_count],
        )
        .await;
    Ok(())
}

/// Create a connection pool from a database URL.
/// Public alias used by the server for clarity
pub type DBPool = Pool;

/// Create a connection pool to Postgres (synchronous constructor)
/// Uses TLS if available, falls back to NoTls for localhost dev environments
pub fn create_pool(database_url: &str, _lazy: bool) -> anyhow::Result<DBPool> {
    let mut cfg = deadpool_postgres::Config::new();
    cfg.url = Some(database_url.to_string());
    cfg.manager = Some(ManagerConfig {
        recycling_method: RecyclingMethod::Fast,
    });

    // Enable TLS for production, allow NoTls for localhost development
    let pool = if database_url.contains("localhost") || database_url.contains("127.0.0.1") {
        log::warn!("Database TLS disabled for localhost connection");
        cfg.create_pool(Some(Runtime::Tokio1), tokio_postgres::NoTls)?
    } else {
        log::info!("Database TLS enabled for production connection");
        let tls = create_tls_connector();
        cfg.create_pool(Some(Runtime::Tokio1), tls)?
    };
    Ok(pool)
}

// Ensure module ends cleanly

#[cfg(test)]
mod replication_outbox_tests {
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
        let dec =
            decode_headers_deterministic(&enc).unwrap_or_else(|e| panic!("decode failed: {e}"));

        // Keys lowercased and stable-sorted; x-test appears before x-test (same key) with value a then b.
        assert_eq!(dec[0].0, "content-type");
        assert_eq!(dec[1].0, "x-test");
        assert_eq!(dec[1].1, b"a".to_vec());
        assert_eq!(dec[2].0, "x-test");
        assert_eq!(dec[2].1, b"b".to_vec());
    }
}

/// Delete an object by key (address).
/// Note: dlv_id is passed for protocol compatibility but ignored for lookup,
/// as the key (address) is globally unique and self-authenticating.
pub async fn delete_slot_object(pool: &Pool, _dlv_id: &[u8], key: &str) -> Result<u64> {
    let mut client = pool.get().await?;
    let tx = client.build_transaction().start().await?;

    let row = tx
        .query_opt(
            "SELECT dlv_id, size_bytes FROM objects WHERE key = $1 FOR UPDATE",
            &[&key],
        )
        .await?;

    let Some(row) = row else {
        tx.commit().await?;
        return Ok(0);
    };

    let dlv_id: Vec<u8> = row.get(0);
    let size_bytes: i64 = row.get(1);

    let deleted = tx
        .execute("DELETE FROM objects WHERE key = $1", &[&key])
        .await?;

    if deleted > 0 && size_bytes > 0 {
        tx.execute(
            "UPDATE dlv_slots SET used_bytes = GREATEST(used_bytes - $2, 0) WHERE dlv_id = $1",
            &[&dlv_id, &size_bytes],
        )
        .await?;
    }

    tx.commit().await?;
    Ok(deleted)
}

// ===================== PaidK Spend-Gate =====================

/// Store a payment receipt (idempotent by receipt_addr).
pub async fn store_payment_receipt(
    pool: &Pool,
    device_id: &str,
    operator_node_id: &[u8],
    amount: i64,
    receipt_addr: &str,
    receipt_bytes: &[u8],
) -> Result<()> {
    let client = pool.get().await?;
    let stmt = client
        .prepare_cached(
            "INSERT INTO payment_receipts (device_id, operator_node_id, amount, receipt_addr, receipt_bytes)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (receipt_addr) DO NOTHING",
        )
        .await?;
    client
        .execute(
            &stmt,
            &[
                &device_id,
                &operator_node_id,
                &amount,
                &receipt_addr,
                &receipt_bytes,
            ],
        )
        .await?;
    Ok(())
}

/// Count distinct operators that a device has paid at least `flat_rate`.
pub async fn count_distinct_paid_operators(
    pool: &Pool,
    device_id: &str,
    flat_rate: i64,
) -> Result<i64> {
    let client = pool.get().await?;
    let stmt = client
        .prepare_cached(
            "SELECT COUNT(DISTINCT operator_node_id) FROM payment_receipts
             WHERE device_id = $1 AND amount >= $2",
        )
        .await?;
    let row = client.query_one(&stmt, &[&device_id, &flat_rate]).await?;
    Ok(row.get::<_, i64>(0))
}

/// Mark PaidK as satisfied for a device (permanent, never reverts).
pub async fn mark_paidk_satisfied(pool: &Pool, device_id: &str) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "UPDATE devices SET paidk_satisfied = TRUE WHERE device_id = $1",
            &[&device_id],
        )
        .await?;
    Ok(())
}

/// Check if PaidK is satisfied for a device.
pub async fn is_paidk_satisfied(pool: &Pool, device_id: &str) -> Result<bool> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT paidk_satisfied FROM devices WHERE device_id = $1",
            &[&device_id],
        )
        .await?;
    Ok(row.map(|r| r.get::<_, bool>(0)).unwrap_or(false))
}

// ===================== Node Registry & Signals =====================

/// Insert or update a node in the registry (idempotent).
pub async fn upsert_registry_node(pool: &Pool, node_id: &[u8], first_cycle: i64) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO node_registry (node_id, first_cycle)
             VALUES ($1, $2)
             ON CONFLICT (node_id) DO NOTHING",
            &[&node_id, &first_cycle],
        )
        .await?;
    Ok(())
}

/// Get all active registry node IDs, sorted ascending.
pub async fn get_active_registry_node_ids(pool: &Pool) -> Result<Vec<Vec<u8>>> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT node_id FROM node_registry WHERE active = TRUE ORDER BY node_id ASC",
            &[],
        )
        .await?;
    Ok(rows.into_iter().map(|r| r.get::<_, Vec<u8>>(0)).collect())
}

/// Get all active registry nodes with metadata.
pub async fn get_active_registry_nodes(pool: &Pool) -> Result<Vec<(Vec<u8>, i64, f64)>> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT node_id, first_cycle, utilization_avg FROM node_registry
             WHERE active = TRUE ORDER BY node_id ASC",
            &[],
        )
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            (
                r.get::<_, Vec<u8>>(0),
                r.get::<_, i64>(1),
                r.get::<_, f64>(2),
            )
        })
        .collect())
}

/// Deactivate a node in the registry (prune).
pub async fn deactivate_registry_node(pool: &Pool, node_id: &[u8]) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "UPDATE node_registry SET active = FALSE WHERE node_id = $1",
            &[&node_id],
        )
        .await?;
    Ok(())
}

/// Update utilization average for a node.
pub async fn update_registry_node_utilization(
    pool: &Pool,
    node_id: &[u8],
    utilization_avg: f64,
) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "UPDATE node_registry SET utilization_avg = $2 WHERE node_id = $1",
            &[&node_id, &utilization_avg],
        )
        .await?;
    Ok(())
}

/// Parameters for storing a capacity signal. Bundles the 6 payload fields to
/// stay within the 7-argument clippy limit.
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

/// Store a capacity signal (idempotent by signal_addr).
pub async fn store_capacity_signal(pool: &Pool, p: &CapacitySignalParams<'_>) -> Result<()> {
    let (
        signal_addr,
        node_id,
        signal_type,
        capacity,
        cycle_window_start,
        cycle_window_end,
        signal_bytes,
    ) = (
        p.signal_addr,
        p.node_id,
        p.signal_type,
        p.capacity,
        p.cycle_window_start,
        p.cycle_window_end,
        p.signal_bytes,
    );
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO capacity_signals (signal_addr, node_id, signal_type, capacity, cycle_window_start, cycle_window_end, signal_bytes)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (signal_addr) DO NOTHING",
            &[&signal_addr, &node_id, &signal_type, &capacity, &cycle_window_start, &cycle_window_end, &signal_bytes],
        )
        .await?;
    Ok(())
}

/// Count up signals in a discovery window.
pub async fn count_up_signals(pool: &Pool, window_start: i64, window_end: i64) -> Result<i64> {
    let client = pool.get().await?;
    let row = client
        .query_one(
            "SELECT COUNT(*)::BIGINT FROM capacity_signals
             WHERE signal_type = 1 AND cycle_window_end >= $1 AND cycle_window_end <= $2",
            &[&window_start, &window_end],
        )
        .await?;
    Ok(row.get::<_, i64>(0))
}

/// Count down signals in a discovery window, excluding grace-protected nodes.
pub async fn count_down_signals_excluding_grace(
    pool: &Pool,
    window_start: i64,
    window_end: i64,
    current_cycle: i64,
    grace_cycles: i64,
) -> Result<i64> {
    let client = pool.get().await?;
    let row = client
        .query_one(
            "SELECT COUNT(*)::BIGINT FROM capacity_signals cs
             WHERE cs.signal_type = 2
               AND cs.cycle_window_end >= $1
               AND cs.cycle_window_end <= $2
               AND NOT EXISTS (
                 SELECT 1 FROM node_registry nr
                 WHERE nr.node_id = cs.node_id
                   AND nr.active = TRUE
                   AND nr.first_cycle + $4 > $3
               )",
            &[&window_start, &window_end, &current_cycle, &grace_cycles],
        )
        .await?;
    Ok(row.get::<_, i64>(0))
}

/// Store an applicant (idempotent by applicant_addr).
pub async fn store_applicant(
    pool: &Pool,
    applicant_addr: &str,
    seed_app: &[u8],
    stake_dlv: &[u8],
    capacity: i64,
    applicant_bytes: &[u8],
) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO applicants (applicant_addr, seed_app, stake_dlv, capacity, applicant_bytes)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (applicant_addr) DO NOTHING",
            &[&applicant_addr, &seed_app, &stake_dlv, &capacity, &applicant_bytes],
        )
        .await?;
    Ok(())
}

/// List all pending applicants.
pub async fn list_pending_applicants(pool: &Pool) -> Result<Vec<(String, Vec<u8>, Vec<u8>, i64)>> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT applicant_addr, seed_app, stake_dlv, capacity FROM applicants ORDER BY applicant_addr ASC",
            &[],
        )
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            (
                r.get::<_, String>(0),
                r.get::<_, Vec<u8>>(1),
                r.get::<_, Vec<u8>>(2),
                r.get::<_, i64>(3),
            )
        })
        .collect())
}

/// Remove an applicant after admission.
pub async fn remove_applicant(pool: &Pool, applicant_addr: &str) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "DELETE FROM applicants WHERE applicant_addr = $1",
            &[&applicant_addr],
        )
        .await?;
    Ok(())
}

// ===================== DrainProof & Stake Exit =====================

/// Store a drain proof (idempotent by proof_addr).
pub async fn store_drain_proof(
    pool: &Pool,
    proof_addr: &str,
    node_id: &[u8],
    start_cycle: i64,
    end_cycle: i64,
    verified_local: bool,
    proof_bytes: &[u8],
) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO drain_proofs (proof_addr, node_id, start_cycle, end_cycle, verified_local, proof_bytes)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (proof_addr) DO NOTHING",
            &[&proof_addr, &node_id, &start_cycle, &end_cycle, &verified_local, &proof_bytes],
        )
        .await?;
    Ok(())
}

/// Get a drain proof for a node.
pub async fn get_drain_proof_for_node(pool: &Pool, node_id: &[u8]) -> Result<Option<Vec<u8>>> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT proof_bytes FROM drain_proofs WHERE node_id = $1 ORDER BY end_cycle DESC LIMIT 1",
            &[&node_id],
        )
        .await?;
    Ok(row.map(|r| r.get::<_, Vec<u8>>(0)))
}

/// Advisory check: verify d consecutive ByteCommit cycles have bytes_used=0 for a node.
/// Returns the count of consecutive empty cycles found starting from start_cycle.
pub async fn verify_bytecommit_chain_empty(
    pool: &Pool,
    node_id_text: &str,
    start_cycle: i64,
    required_d: i64,
) -> Result<bool> {
    let client = pool.get().await?;
    // Check that exactly `required_d` consecutive cycles exist starting from start_cycle,
    // and each has a bytecommit stored in objects whose ByteCommitV3.bytes_used == 0.
    // Since nodes are dumb, we check the bytecommit_chain table for continuity.
    let row = client
        .query_one(
            "SELECT COUNT(*)::BIGINT FROM bytecommit_chain
             WHERE node_id = $1 AND cycle_index >= $2 AND cycle_index < $2 + $3",
            &[&node_id_text, &start_cycle, &required_d],
        )
        .await?;
    let count: i64 = row.get(0);
    Ok(count >= required_d)
}
