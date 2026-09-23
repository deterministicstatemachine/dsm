// SPDX-License-Identifier: MIT OR Apache-2.0

//! Storage node DB layer (clean, DLV-only)
//! Minimal schema + helpers used by the DLV-backed object store.

use crate::api::infra::hardening::{BBYTES, BEV};
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

/// REFUSE TO RUN ON A SERVER THAT CANNOT KEEP WHAT IT ACKNOWLEDGES.
///
/// The one-shot registers are safe only because a member that acknowledged a
/// claim still holds it after a restart. `SET LOCAL synchronous_commit = on`
/// makes each claim transaction flush its own commit, but two server-level
/// settings can defeat that no matter what a transaction asks for: `fsync`
/// off means the server never flushes at all, and `full_page_writes` off can
/// leave a torn page after a crash. Neither is something a claim can override,
/// so a node that finds them refuses to start rather than serving a register
/// whose acknowledgements it cannot keep.
///
/// This is a startup gate, not a warning: an acknowledgement is a promise, and
/// a node that cannot keep it should not be part of a quorum.
pub async fn require_durable_commit_posture(pool: &Pool) -> Result<()> {
    let client = pool.get().await?;
    let mut readings = Vec::with_capacity(REQUIRED_SERVER_SETTINGS.len());
    for (setting, _) in REQUIRED_SERVER_SETTINGS {
        let row = client.query_one(&format!("SHOW {setting}"), &[]).await?;
        readings.push((*setting, row.get::<_, String>(0)));
    }
    check_durable_commit_posture(&readings)
}

/// The server-level settings a node must find before it will serve a
/// register, and the value each must have.
const REQUIRED_SERVER_SETTINGS: &[(&str, &str)] = &[("fsync", "on"), ("full_page_writes", "on")];

/// The refusal DECISION, separated from the query so it can be tested in both
/// directions. A gate whose only rejecting input needs a differently
/// configured server is a gate no test ever exercises.
fn check_durable_commit_posture(readings: &[(&str, String)]) -> Result<()> {
    for (setting, required) in REQUIRED_SERVER_SETTINGS {
        let Some((_, value)) = readings.iter().find(|(name, _)| name == setting) else {
            anyhow::bail!(
                "refusing to start: postgres did not report {setting}, so this node cannot \
                 establish that an acknowledged claim survives a restart"
            );
        };
        if !value.eq_ignore_ascii_case(required) {
            anyhow::bail!(
                "refusing to start: postgres reports {setting}={value}, but this node's \
                 one-shot registers promise that an acknowledged claim survives a restart, \
                 and {setting} must be {required} for that promise to hold"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod durable_posture_tests {
    #![allow(clippy::disallowed_methods)] // unwrap/expect acceptable in deterministic tests
    use super::*;

    fn readings(pairs: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
        pairs.iter().map(|(k, v)| (*k, (*v).to_string())).collect()
    }

    #[test]
    fn a_fully_durable_server_is_accepted_in_any_letter_case() {
        check_durable_commit_posture(&readings(&[("fsync", "on"), ("full_page_writes", "ON")]))
            .expect("a server with both settings on is accepted");
    }

    #[test]
    fn a_weaker_posture_is_refused_and_the_refusal_names_the_setting() {
        for weak in ["off", "", "false"] {
            let err = check_durable_commit_posture(&readings(&[
                ("fsync", weak),
                ("full_page_writes", "on"),
            ]))
            .expect_err("fsync must be on");
            assert!(
                err.to_string().contains("fsync"),
                "names the setting: {err}"
            );

            let err = check_durable_commit_posture(&readings(&[
                ("fsync", "on"),
                ("full_page_writes", weak),
            ]))
            .expect_err("full_page_writes must be on");
            assert!(
                err.to_string().contains("full_page_writes"),
                "names the setting: {err}"
            );
        }
    }

    /// A server that answers nothing for a required setting is refused too —
    /// a missing reading is not a passing one.
    #[test]
    fn an_unreported_setting_is_refused_rather_than_assumed() {
        let err = check_durable_commit_posture(&readings(&[("fsync", "on")]))
            .expect_err("an unreported setting cannot be assumed durable");
        assert!(err.to_string().contains("full_page_writes"), "{err}");
    }

    /// The claim transaction SETS its durability; it does not inherit it.
    ///
    /// Stated hostilely, because the passing version of this test is
    /// worthless otherwise: the connection is first weakened at session level
    /// (`synchronous_commit = off`), which the pool's `RecyclingMethod::Fast`
    /// would carry to every later borrow of that connection, and the
    /// transaction must still report `on`. Reading `on` off a server that was
    /// already `on` would prove nothing.
    #[tokio::test]
    async fn a_claim_transaction_sets_its_own_durability_rather_than_inheriting_it() {
        let pool = crate::db::cell_properties::test_pool();
        let mut client = pool.get().await.expect("client");
        client
            .batch_execute("SET synchronous_commit = off")
            .await
            .expect("weaken the session");
        let weakened: String = client
            .query_one("SHOW synchronous_commit", &[])
            .await
            .expect("show")
            .get(0);
        assert_eq!(weakened, "off", "the session really is weakened");

        let tx = begin_durable_write(&mut client)
            .await
            .expect("durable write");
        let inside: String = tx
            .query_one("SHOW synchronous_commit", &[])
            .await
            .expect("show")
            .get(0);
        assert_eq!(
            inside, "on",
            "a claim transaction commits durably even on a connection whose session says otherwise"
        );
        tx.commit().await.expect("commit");

        // Leave the borrowed connection as we found it: the pool does not
        // reset session state between borrows.
        client
            .batch_execute("SET synchronous_commit = on")
            .await
            .expect("restore the session");
    }
}

/// This node's durable REGISTER INCARNATION: the identity of its register
/// history, not of the node.
///
/// Generated once, from the OS random source, and stored only here. It is
/// deliberately not derivable from the node's signing key, its id, or any
/// seed — a node that still holds its identity key but lost its register
/// database MUST come back with a different incarnation, because that is the
/// fact a vault needs to know. Otherwise a rebuilt member can assert "no
/// claim here" for a cell the real incarnation once held, and owning the
/// identity key would be the whole test.
///
/// Write-once with a same-transaction read-back, like the registers it
/// speaks for: two racing callers agree on one value rather than each
/// minting one.
pub async fn register_incarnation(pool: &Pool) -> Result<[u8; 32]> {
    let fresh: [u8; 32] = rand::random();
    let mut client = pool.get().await?;
    let tx = begin_durable_write(&mut client).await?;
    tx.execute(
        "INSERT INTO register_incarnation (only_row, incarnation) VALUES (1, $1)
         ON CONFLICT (only_row) DO NOTHING",
        &[&fresh.as_slice()],
    )
    .await?;
    let row = tx
        .query_one(
            "SELECT incarnation FROM register_incarnation WHERE only_row = 1",
            &[],
        )
        .await?;
    let held: Vec<u8> = row.get(0);
    tx.commit().await?;
    held.try_into()
        .map_err(|_| anyhow!("stored register incarnation is not 32 bytes"))
}

// ===================== Generic conditional binding (Rev 15 §15.5) =====================

/// Initialize database schema for storage node.
/// Advisory-lock key serialising schema initialisation on one database.
const INIT_DB_LOCK: i64 = 0x4453_4D49_4E49_5444;

/// Create or migrate the schema. Initialisations of one database run one at
/// a time: concurrent `CREATE … IF NOT EXISTS` statements race inside the
/// Postgres catalog and fail, so the whole run holds a session advisory lock,
/// released on every path.
pub async fn init_db(pool: &Pool) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute("SELECT pg_advisory_lock($1)", &[&INIT_DB_LOCK])
        .await?;
    let result = init_db_serialized(pool, &client).await;
    client
        .execute("SELECT pg_advisory_unlock($1)", &[&INIT_DB_LOCK])
        .await?;
    result
}

async fn init_db_serialized(pool: &Pool, client: &deadpool_postgres::Object) -> Result<()> {
    client
        .batch_execute(
            r#"CREATE TABLE IF NOT EXISTS register_incarnation (
                    only_row    SMALLINT PRIMARY KEY CHECK (only_row = 1),
                    incarnation BYTEA NOT NULL
                );

                -- Keyed cells: the member keeps EVERY value it is given for a
                -- key, in arrival order, and never refuses, replaces or
                -- compares. Which value counts is the reader's question.
                CREATE TABLE IF NOT EXISTS cells (
                    seq       BIGSERIAL PRIMARY KEY,
                    namespace BYTEA NOT NULL,
                    cell_key  BYTEA NOT NULL,
                    value     BYTEA NOT NULL
                );
                CREATE INDEX IF NOT EXISTS cells_by_key ON cells (namespace, cell_key, seq);

                -- Indexes: content addresses appended under a locator, never
                -- removed, read back in append order.
                CREATE TABLE IF NOT EXISTS index_entries (
                    seq     BIGSERIAL PRIMARY KEY,
                    locator BYTEA NOT NULL,
                    addr    BYTEA NOT NULL
                );
                CREATE INDEX IF NOT EXISTS index_entries_by_locator ON index_entries (locator, seq);

                CREATE TABLE IF NOT EXISTS dlv_slots (
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
                        kyber_public_key  BYTEA NOT NULL,
                        kyber_binding_sig BYTEA NOT NULL,
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

                -- ML-KEM identity binding (ec6f8322, 2026-07-15). These were added to the
                -- CREATE TABLE above and NOWHERE ELSE, so every database created before that
                -- commit never got them: `CREATE TABLE IF NOT EXISTS` is a no-op on a live
                -- table. `register_device` then INSERTs naming these columns, Postgres
                -- rejects it, and the handler maps that to a 500 "Database error" — which is
                -- what the production fleet has returned for EVERY device registration since.
                -- Genesis logs it as best-effort and continues, so the symptom is silent:
                -- wallets are created, never published, and are invisible to `wallet.send`'s
                -- identity quorum.
                --
                -- Backfilled EMPTY on purpose. An empty `kyber_binding_sig` is refused by the
                -- reader (`fetch_quorum_device_identity`), so pre-existing rows stay
                -- fail-closed until the device re-registers with a real binding, rather than
                -- becoming silently trusted with no binding at all.
                ALTER TABLE devices ADD COLUMN IF NOT EXISTS kyber_public_key  BYTEA NOT NULL DEFAULT ''::bytea;
                ALTER TABLE devices ADD COLUMN IF NOT EXISTS kyber_binding_sig BYTEA NOT NULL DEFAULT ''::bytea;
                -- The DEFAULT exists only to satisfy NOT NULL while backfilling. Dropping it
                -- means a future INSERT that forgets these columns FAILS instead of silently
                -- writing an unusable identity — the create-time-only change is exactly how
                -- this bug happened, and a lingering default would let it happen again.
                ALTER TABLE devices ALTER COLUMN kyber_public_key  DROP DEFAULT;
                ALTER TABLE devices ALTER COLUMN kyber_binding_sig DROP DEFAULT;
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

    // Phase B.4 (issue #275): bounded validator for the published
    // Device Tree state. One row per genesis. `version_number` is the
    // monotone counter the PUT /devtree/root validator enforces;
    // `root_hash` and `device_count` are broken out for indexed lookup.
    // `payload` is the canonical `DeviceTreeStateV1` proto bytes.
    client
        .batch_execute(
            r#"CREATE TABLE IF NOT EXISTS device_tree_states (
                    genesis_b32     TEXT PRIMARY KEY,
                    version_number  BIGINT NOT NULL,
                    device_count    BIGINT NOT NULL,
                    root_hash       BYTEA NOT NULL,
                    payload         BYTEA NOT NULL,
                    updated_at_tick BIGINT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_device_tree_states_version
                    ON device_tree_states(genesis_b32, version_number);

                -- Single-assignment store for recovery-authority anchors
                -- (spec §0.5 bind-once). Keyed by genesis: the FIRST valid
                -- anchor wins and is immutable; a different anchor for the same
                -- genesis is rejected (409). Storage enforces single-assignment
                -- ONLY — clients verify the anchor cryptographically.
                CREATE TABLE IF NOT EXISTS recovery_authority_anchors (
                    genesis_b32        TEXT PRIMARY KEY,
                    anchor_hash        BYTEA NOT NULL,
                    payload            BYTEA NOT NULL,
                    first_written_tick BIGINT NOT NULL
                );

                -- IMMUTABLE OBJECT STORE (Area 4, Rev 15 §15.3). Keyed by the
                -- content address addr(N, P); write-once forever — no UPDATE
                -- and no DELETE statement exists against this table anywhere.
                -- The node recomputes the address on write AND on read; it
                -- never decodes the payload.
                CREATE TABLE IF NOT EXISTS immutable_objects (
                    addr_b32           TEXT PRIMARY KEY,
                    namespace          BYTEA NOT NULL,
                    payload            BYTEA NOT NULL,
                    first_written_tick BIGINT NOT NULL
                );

                -- Append-only Per-Device SMT head chain (spec §0.5 gap 13, R4
                -- layer 1). One row per (device, head_number); a head is accepted
                -- only if it links the current tip. No overwrite, no fork. Full
                -- history retained for snapshot reads. Storage enforces the chain
                -- shape ONLY; clients verify head signatures + inclusion.
                CREATE TABLE IF NOT EXISTS pdsmt_head_chain (
                    device_b32        TEXT NOT NULL,
                    head_number       BIGINT NOT NULL,
                    head_hash         BYTEA NOT NULL,
                    parent_head_hash  BYTEA NOT NULL,
                    payload           BYTEA NOT NULL,
                    inserted_at_tick  BIGINT NOT NULL,
                    PRIMARY KEY (device_b32, head_number)
                );
            "#,
        )
        .await?;

    // Arrival order is committed (storage spec §14): each entry's per-key
    // arrival index (from 1) and the member's running hash for the key after
    // it. The columns are added once, under an explicit table lock taken
    // first, so two concurrent initialisations queue instead of deadlocking
    // on a lock upgrade; after that, startup never takes the lock again.
    let has_arrival: bool = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_name = 'cells' AND column_name = 'arrival_index')",
            &[],
        )
        .await?
        .get(0);
    if !has_arrival {
        client
            .batch_execute(
                "BEGIN;
                 LOCK TABLE cells IN ACCESS EXCLUSIVE MODE;
                 ALTER TABLE cells ADD COLUMN IF NOT EXISTS arrival_index BIGINT;
                 ALTER TABLE cells ADD COLUMN IF NOT EXISTS running_hash BYTEA;
                 CREATE UNIQUE INDEX IF NOT EXISTS cells_by_arrival
                     ON cells (namespace, cell_key, arrival_index);
                 COMMIT;",
            )
            .await?;
    }

    // Which ByteCommit first committed an entry (storage spec §14). NULL
    // until the next cycle closes. Guarded like the arrival columns.
    let has_committed: bool = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_name = 'cells' AND column_name = 'committed_cycle')",
            &[],
        )
        .await?
        .get(0);
    if !has_committed {
        client
            .batch_execute(
                "BEGIN;
                 LOCK TABLE cells IN ACCESS EXCLUSIVE MODE;
                 ALTER TABLE cells ADD COLUMN IF NOT EXISTS committed_cycle BIGINT;
                 CREATE INDEX IF NOT EXISTS cells_uncommitted
                     ON cells (seq) WHERE committed_cycle IS NULL;
                 COMMIT;",
            )
            .await?;
    }
    client
        .batch_execute(
            r#"-- This node's own ByteCommits, one per cycle (storage spec §14).
               CREATE TABLE IF NOT EXISTS own_bytecommits (
                   cycle_index BIGINT PRIMARY KEY,
                   digest      BYTEA NOT NULL,
                   commit_pb   BYTEA NOT NULL
               );
               -- This node's mirror of its set-mates' ByteCommits: only what it
               -- fetched from that member itself, never a third party's bytes.
               -- Every distinct ByteCommit is kept, so an equivocation shows.
               CREATE TABLE IF NOT EXISTS bytecommit_mirror (
                   member_id   BYTEA NOT NULL,
                   cycle_index BIGINT NOT NULL,
                   digest      BYTEA NOT NULL,
                   commit_pb   BYTEA NOT NULL,
                   PRIMARY KEY (member_id, cycle_index, digest)
               );"#,
        )
        .await?;

    // Before the node serves a single put: rows from before arrival records
    // existed get theirs, so no key ever mixes recorded and unrecorded rows.
    let backfilled = backfill_cell_arrival_records(pool).await?;
    if backfilled > 0 {
        log::info!("cells: backfilled arrival records for {backfilled} keys");
    }

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

// ============================================================
// Phase B.4 (issue #275): Device Tree state — bounded validator
// ============================================================

/// Outcome of a [`upsert_device_tree_state_if_monotonic`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceTreeUpsertOutcome {
    /// No prior row existed for this genesis; the row was newly inserted.
    Inserted,
    /// A prior row existed and was replaced because
    /// `new_version > prior_version`.
    Updated { prior_version: u64 },
    /// A prior row existed and the write was rejected because
    /// `new_version <= prior_version`. The persisted state is unchanged.
    RejectedStale { prior_version: u64 },
}

/// Atomically upsert a `DeviceTreeStateV1` row for `genesis_b32`,
/// enforcing strictly-monotonic `version_number`. Runs as a single
/// `SERIALIZABLE` transaction so concurrent writers cannot bypass the
/// monotonicity check.
#[allow(clippy::too_many_arguments)]
pub async fn upsert_device_tree_state_if_monotonic(
    pool: &Pool,
    genesis_b32: &str,
    new_version: u64,
    device_count: u32,
    root_hash: &[u8],
    payload: &[u8],
    updated_at_tick: u64,
) -> Result<DeviceTreeUpsertOutcome> {
    use tokio_postgres::IsolationLevel;

    let new_version_i64 = i64::try_from(new_version)
        .map_err(|_| anyhow::anyhow!("version_number {new_version} does not fit in i64"))?;
    let device_count_i64 = i64::from(device_count);
    let updated_at_tick_i64 = i64::try_from(updated_at_tick)
        .map_err(|_| anyhow::anyhow!("updated_at_tick {updated_at_tick} does not fit in i64"))?;

    let mut client = pool.get().await?;
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .start()
        .await?;

    let row = tx
        .query_opt(
            "SELECT version_number FROM device_tree_states WHERE genesis_b32 = $1 FOR UPDATE",
            &[&genesis_b32],
        )
        .await?;

    let outcome = match row {
        Some(r) => {
            let prior_i64: i64 = r.get(0);
            let prior_u64 = u64::try_from(prior_i64).unwrap_or(0);
            if new_version_i64 <= prior_i64 {
                DeviceTreeUpsertOutcome::RejectedStale {
                    prior_version: prior_u64,
                }
            } else {
                let stmt = tx
                    .prepare_cached(
                        "UPDATE device_tree_states
                         SET version_number=$2, device_count=$3, root_hash=$4,
                             payload=$5, updated_at_tick=$6
                         WHERE genesis_b32=$1",
                    )
                    .await?;
                tx.execute(
                    &stmt,
                    &[
                        &genesis_b32,
                        &new_version_i64,
                        &device_count_i64,
                        &root_hash,
                        &payload,
                        &updated_at_tick_i64,
                    ],
                )
                .await?;
                DeviceTreeUpsertOutcome::Updated {
                    prior_version: prior_u64,
                }
            }
        }
        None => {
            let stmt = tx
                .prepare_cached(
                    "INSERT INTO device_tree_states
                       (genesis_b32, version_number, device_count, root_hash, payload, updated_at_tick)
                     VALUES ($1, $2, $3, $4, $5, $6)",
                )
                .await?;
            tx.execute(
                &stmt,
                &[
                    &genesis_b32,
                    &new_version_i64,
                    &device_count_i64,
                    &root_hash,
                    &payload,
                    &updated_at_tick_i64,
                ],
            )
            .await?;
            DeviceTreeUpsertOutcome::Inserted
        }
    };

    tx.commit().await?;
    Ok(outcome)
}

/// Return the persisted `DeviceTreeStateV1` payload bytes for a
/// genesis, or `None` if no state has been written yet.
pub async fn get_device_tree_state_payload(
    pool: &Pool,
    genesis_b32: &str,
) -> Result<Option<Vec<u8>>> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT payload FROM device_tree_states WHERE genesis_b32 = $1",
            &[&genesis_b32],
        )
        .await?;
    Ok(row.map(|r| {
        let payload: Vec<u8> = r.get(0);
        payload
    }))
}

/// Return only the current `version_number` for a genesis's persisted
/// Device Tree state, or `None`. Used by tests asserting monotonic
/// enforcement without re-decoding the full proto.
pub async fn get_device_tree_state_version(pool: &Pool, genesis_b32: &str) -> Result<Option<u64>> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT version_number FROM device_tree_states WHERE genesis_b32 = $1",
            &[&genesis_b32],
        )
        .await?;
    Ok(row.map(|r| {
        let v: i64 = r.get(0);
        u64::try_from(v).unwrap_or(0)
    }))
}

// ============================================================
// Recovery-authority anchor — single-assignment (spec §0.5 bind-once)
// ============================================================

/// Begin a write transaction whose commit is durable BEFORE it is
/// acknowledged.
///
/// DURABILITY IS SET HERE, NOT INHERITED. `SET LOCAL synchronous_commit = on`
/// applies to this transaction only and does not depend on the server's
/// default, the connection pool, or the image this node happens to run: a
/// claim this node acknowledges has reached disk before the acknowledgement.
/// An earlier doc-string credited "the pool's default", which set nothing —
/// the guarantee was the upstream image's default and would have changed
/// silently with it. `require_durable_commit_posture` additionally refuses to
/// start a node whose server-level settings could defeat this.
///
/// Every one-shot register claim goes through this one function so the posture
/// cannot hold for one register and silently lapse for another.
async fn begin_durable_write(
    client: &mut deadpool_postgres::Client,
) -> Result<deadpool_postgres::Transaction<'_>> {
    let tx = client.build_transaction().start().await?;
    tx.batch_execute("SET LOCAL synchronous_commit = on")
        .await?;
    Ok(tx)
}

/// Outcome of [`insert_recovery_authority_anchor_if_absent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryAnchorUpsertOutcome {
    /// No prior anchor existed for this genesis; the row was newly inserted.
    Inserted,
    /// An identical anchor (same `anchor_hash`) already exists — idempotent replay.
    AlreadyExistsIdentical,
    /// A DIFFERENT anchor already exists for this genesis — rejected (bind-once).
    Conflict,
}

/// Single-assignment insert of a recovery-authority anchor, keyed by genesis
/// (spec §0.5 bind-once). First write wins; an identical replay (same
/// `anchor_hash`) is idempotent; any DIFFERENT anchor for the same genesis is
/// rejected. Runs as a `SERIALIZABLE` transaction with `FOR UPDATE` so concurrent
/// writers serialise. Storage enforces single-assignment ONLY — it does NOT attest
/// recovery validity; clients verify the anchor cryptographically.
pub async fn insert_recovery_authority_anchor_if_absent(
    pool: &Pool,
    genesis_b32: &str,
    anchor_hash: &[u8],
    payload: &[u8],
    first_written_tick: u64,
) -> Result<RecoveryAnchorUpsertOutcome> {
    use tokio_postgres::IsolationLevel;

    let tick_i64 = i64::try_from(first_written_tick).map_err(|_| {
        anyhow::anyhow!("first_written_tick {first_written_tick} does not fit in i64")
    })?;

    let mut client = pool.get().await?;
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .start()
        .await?;

    let row = tx
        .query_opt(
            "SELECT anchor_hash FROM recovery_authority_anchors WHERE genesis_b32 = $1 FOR UPDATE",
            &[&genesis_b32],
        )
        .await?;

    let outcome = match row {
        Some(r) => {
            let existing: Vec<u8> = r.get(0);
            if existing == anchor_hash {
                RecoveryAnchorUpsertOutcome::AlreadyExistsIdentical
            } else {
                RecoveryAnchorUpsertOutcome::Conflict
            }
        }
        None => {
            let stmt = tx
                .prepare_cached(
                    "INSERT INTO recovery_authority_anchors
                       (genesis_b32, anchor_hash, payload, first_written_tick)
                     VALUES ($1, $2, $3, $4)",
                )
                .await?;
            tx.execute(&stmt, &[&genesis_b32, &anchor_hash, &payload, &tick_i64])
                .await?;
            RecoveryAnchorUpsertOutcome::Inserted
        }
    };

    tx.commit().await?;
    Ok(outcome)
}

/// Return the persisted recovery-authority anchor payload bytes for a genesis,
/// or `None` if none has been written.
/// Outcome of [`insert_immutable_object_if_absent`]. See `sqlite.rs` for the
/// contract; the two backends implement one behaviour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImmutablePutOutcome {
    Inserted,
    AlreadyExistsIdentical,
    Conflict,
}

/// Write-once insert of an immutable object, keyed by content address.
/// Idempotence compares the stored `(namespace, payload)` TUPLE.
pub async fn insert_immutable_object_if_absent(
    pool: &Pool,
    addr_b32: &str,
    namespace: &[u8],
    payload: &[u8],
    first_written_tick: u64,
) -> Result<ImmutablePutOutcome> {
    use tokio_postgres::IsolationLevel;

    let tick_i64 = i64::try_from(first_written_tick).map_err(|_| {
        anyhow::anyhow!("first_written_tick {first_written_tick} does not fit in i64")
    })?;

    let mut client = pool.get().await?;
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .start()
        .await?;

    let row = tx
        .query_opt(
            "SELECT namespace, payload FROM immutable_objects WHERE addr_b32 = $1 FOR UPDATE",
            &[&addr_b32],
        )
        .await?;

    let outcome = match row {
        Some(r) => {
            let ns: Vec<u8> = r.get(0);
            let pl: Vec<u8> = r.get(1);
            if ns == namespace && pl == payload {
                ImmutablePutOutcome::AlreadyExistsIdentical
            } else {
                ImmutablePutOutcome::Conflict
            }
        }
        None => {
            let stmt = tx
                .prepare_cached(
                    "INSERT INTO immutable_objects
                       (addr_b32, namespace, payload, first_written_tick)
                     VALUES ($1, $2, $3, $4)",
                )
                .await?;
            tx.execute(&stmt, &[&addr_b32, &namespace, &payload, &tick_i64])
                .await?;
            ImmutablePutOutcome::Inserted
        }
    };

    tx.commit().await?;
    Ok(outcome)
}

/// Return the `(namespace, payload)` tuple at a content address, or `None`.
pub async fn get_immutable_object(
    pool: &Pool,
    addr_b32: &str,
) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT namespace, payload FROM immutable_objects WHERE addr_b32 = $1",
            &[&addr_b32],
        )
        .await?;
    Ok(row.map(|r| (r.get(0), r.get(1))))
}

pub async fn get_recovery_authority_anchor_payload(
    pool: &Pool,
    genesis_b32: &str,
) -> Result<Option<Vec<u8>>> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT payload FROM recovery_authority_anchors WHERE genesis_b32 = $1",
            &[&genesis_b32],
        )
        .await?;
    Ok(row.map(|r| {
        let payload: Vec<u8> = r.get(0);
        payload
    }))
}

// ============================================================
// Append-only Per-Device SMT head chain (spec §0.5 gap 13, R4 layer 1)
// ============================================================

/// Outcome of [`insert_pdsmt_head_if_chained`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdsmtHeadChainOutcome {
    /// The head was appended at `head_number` (0 = genesis head).
    Appended { head_number: u64 },
    /// A head with the SAME hash already exists at this `head_number` — idempotent replay.
    AlreadyExistsIdentical,
    /// The head does not link the current tip (fork / gap / stale / position mismatch).
    Conflict,
}

/// Append a PDSMT head iff it correctly links the device's current chain tip (see the
/// sqlite twin for the full contract). Runs as a `SERIALIZABLE` transaction with
/// `FOR UPDATE` so concurrent posters serialise. Append-only: existing rows are never
/// updated or deleted.
#[allow(clippy::too_many_arguments)]
pub async fn insert_pdsmt_head_if_chained(
    pool: &Pool,
    device_b32: &str,
    head_number: u64,
    head_hash: &[u8],
    parent_head_hash: &[u8],
    payload: &[u8],
    inserted_at_tick: u64,
) -> Result<PdsmtHeadChainOutcome> {
    use tokio_postgres::IsolationLevel;

    let head_number_i64 = i64::try_from(head_number)
        .map_err(|_| anyhow::anyhow!("head_number {head_number} does not fit in i64"))?;
    let tick_i64 = i64::try_from(inserted_at_tick)
        .map_err(|_| anyhow::anyhow!("inserted_at_tick {inserted_at_tick} does not fit in i64"))?;

    let mut client = pool.get().await?;
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .start()
        .await?;

    // A row already at this position? (idempotent replay vs position fork)
    let at_row = tx
        .query_opt(
            "SELECT head_hash FROM pdsmt_head_chain WHERE device_b32 = $1 AND head_number = $2 FOR UPDATE",
            &[&device_b32, &head_number_i64],
        )
        .await?;

    let outcome = if let Some(r) = at_row {
        let existing: Vec<u8> = r.get(0);
        if existing == head_hash {
            PdsmtHeadChainOutcome::AlreadyExistsIdentical
        } else {
            PdsmtHeadChainOutcome::Conflict
        }
    } else {
        let tip = tx
            .query_opt(
                "SELECT head_number, head_hash FROM pdsmt_head_chain
                 WHERE device_b32 = $1 ORDER BY head_number DESC LIMIT 1 FOR UPDATE",
                &[&device_b32],
            )
            .await?;

        let chains = match &tip {
            None => head_number == 0 && parent_head_hash.iter().all(|&b| b == 0),
            Some(r) => {
                let tip_n: i64 = r.get(0);
                let tip_hash: Vec<u8> = r.get(1);
                let tip_n_u = u64::try_from(tip_n).unwrap_or(u64::MAX);
                head_number == tip_n_u.saturating_add(1) && parent_head_hash == tip_hash.as_slice()
            }
        };

        if chains {
            let stmt = tx
                .prepare_cached(
                    "INSERT INTO pdsmt_head_chain
                       (device_b32, head_number, head_hash, parent_head_hash, payload, inserted_at_tick)
                     VALUES ($1, $2, $3, $4, $5, $6)",
                )
                .await?;
            tx.execute(
                &stmt,
                &[
                    &device_b32,
                    &head_number_i64,
                    &head_hash,
                    &parent_head_hash,
                    &payload,
                    &tick_i64,
                ],
            )
            .await?;
            PdsmtHeadChainOutcome::Appended { head_number }
        } else {
            PdsmtHeadChainOutcome::Conflict
        }
    };

    tx.commit().await?;
    Ok(outcome)
}

/// Return the payload of the device's latest (highest `head_number`) PDSMT head, or `None`.
pub async fn get_pdsmt_head_latest(pool: &Pool, device_b32: &str) -> Result<Option<Vec<u8>>> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT payload FROM pdsmt_head_chain WHERE device_b32 = $1
             ORDER BY head_number DESC LIMIT 1",
            &[&device_b32],
        )
        .await?;
    Ok(row.map(|r| {
        let payload: Vec<u8> = r.get(0);
        payload
    }))
}

/// Return the payload of the device's PDSMT head at a specific `head_number`, or `None`.
pub async fn get_pdsmt_head_at(
    pool: &Pool,
    device_b32: &str,
    head_number: u64,
) -> Result<Option<Vec<u8>>> {
    let head_number_i64 = i64::try_from(head_number)
        .map_err(|_| anyhow::anyhow!("head_number {head_number} does not fit in i64"))?;
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT payload FROM pdsmt_head_chain WHERE device_b32 = $1 AND head_number = $2",
            &[&device_b32, &head_number_i64],
        )
        .await?;
    Ok(row.map(|r| {
        let payload: Vec<u8> = r.get(0);
        payload
    }))
}

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
#[allow(clippy::too_many_arguments)]
pub async fn register_device(
    pool: &Pool,
    device_id: &str,
    genesis_hash: &[u8],
    pubkey: &[u8],
    token_hash: &[u8],
    kyber_public_key: &[u8],
    kyber_binding_sig: &[u8],
) -> Result<u64> {
    let client = pool.get().await?;
    let stmt = client
        .prepare_cached(
            "INSERT INTO devices
                (device_id, genesis_hash, pubkey, token_hash, kyber_public_key, kyber_binding_sig, revoked)
             VALUES ($1, $2, $3, $4, $5, $6, FALSE)
             ON CONFLICT (device_id) DO NOTHING",
        )
        .await?;
    let rows = client
        .execute(
            &stmt,
            &[
                &device_id,
                &genesis_hash,
                &pubkey,
                &token_hash,
                &kyber_public_key,
                &kyber_binding_sig,
            ],
        )
        .await?;
    Ok(rows)
}

/// A device's registered identity row:
/// `(genesis_hash, pubkey, kyber_public_key, kyber_binding_sig)`.
pub type DeviceIdentityRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// Get a device's identity: (genesis_hash, pubkey, kyber_public_key, kyber_binding_sig).
pub async fn get_device(pool: &Pool, device_id: &str) -> Result<Option<DeviceIdentityRow>> {
    let client = pool.get().await?;
    let stmt = client
        .prepare_cached(
            "SELECT genesis_hash, pubkey, kyber_public_key, kyber_binding_sig
             FROM devices WHERE device_id = $1",
        )
        .await?;
    let row_opt = client.query_opt(&stmt, &[&device_id]).await?;
    Ok(row_opt.map(|r| {
        (
            r.get::<_, Vec<u8>>(0),
            r.get::<_, Vec<u8>>(1),
            r.get::<_, Vec<u8>>(2),
            r.get::<_, Vec<u8>>(3),
        )
    }))
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

// ── keyed cells and indexes: bytes in, bytes out ───────────────────────────

/// Keep `value` for `(namespace, key)`, after anything already held there,
/// and return its arrival record's `(index, running hash)` (storage spec
/// §6, §14). Nothing is compared and nothing is refused. The write is
/// durable before it is acknowledged.
pub async fn put_cell(
    pool: &Pool,
    namespace: &[u8],
    key: &[u8],
    value: &[u8],
) -> Result<(u64, [u8; 32])> {
    let mut client = pool.get().await?;
    let tx = begin_durable_write(&mut client).await?;
    lock_cells(&tx, [(namespace, key)]).await?;
    let record = append_cell_entry(&tx, namespace, key, value).await?;
    tx.commit().await?;
    Ok(record)
}

/// Several keys in ONE durable transaction: every entry is kept after
/// anything already at its key, or none of them is. An entry that names no
/// coordinate — an empty namespace, a key that is not 32 bytes — makes the
/// whole batch nothing; it is not a value the member could refuse, it is
/// not a cell. Returns each entry's `(index, running hash)` in batch order.
pub async fn put_cells(
    pool: &Pool,
    entries: &[(Vec<u8>, Vec<u8>, Vec<u8>)],
) -> Result<Vec<(u64, [u8; 32])>> {
    if entries
        .iter()
        .any(|(namespace, key, _)| namespace.is_empty() || key.len() != 32)
    {
        anyhow::bail!("batch put: an entry names no cell");
    }
    let mut client = pool.get().await?;
    let tx = begin_durable_write(&mut client).await?;
    lock_cells(
        &tx,
        entries
            .iter()
            .map(|(namespace, key, _)| (namespace.as_slice(), key.as_slice())),
    )
    .await?;
    let mut records = Vec::with_capacity(entries.len());
    for (namespace, key, value) in entries {
        records.push(append_cell_entry(&tx, namespace, key, value).await?);
    }
    tx.commit().await?;
    Ok(records)
}

/// Take the advisory lock of every cell a write touches, each once and in
/// ascending lock-id order, before anything is appended. The locks serialise
/// concurrent puts to one key so no two entries can claim the same arrival
/// index (the unique index is the backstop); one global order means two
/// batches over the same keys queue instead of deadlocking.
async fn lock_cells<'a>(
    tx: &deadpool_postgres::Transaction<'_>,
    cells: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<()> {
    let mut ids = Vec::new();
    for (namespace, key) in cells {
        let key32: [u8; 32] = key
            .try_into()
            .map_err(|_| anyhow::anyhow!("cell key is not 32 bytes"))?;
        let lock = dsm::storage_cell::leaf_key(namespace, &key32);
        ids.push(i64::from_be_bytes([
            lock[0], lock[1], lock[2], lock[3], lock[4], lock[5], lock[6], lock[7],
        ]));
    }
    ids.sort_unstable();
    ids.dedup();
    for id in ids {
        tx.execute("SELECT pg_advisory_xact_lock($1)", &[&id])
            .await?;
    }
    Ok(())
}

/// Append one entry inside `tx`, whose cell lock [`lock_cells`] already
/// holds: extend the key's running hash, insert.
async fn append_cell_entry(
    tx: &deadpool_postgres::Transaction<'_>,
    namespace: &[u8],
    key: &[u8],
    value: &[u8],
) -> Result<(u64, [u8; 32])> {
    let key32: [u8; 32] = key
        .try_into()
        .map_err(|_| anyhow::anyhow!("cell key is not 32 bytes"))?;
    let last = tx
        .query_opt(
            "SELECT arrival_index, running_hash FROM cells
             WHERE namespace = $1 AND cell_key = $2 AND arrival_index IS NOT NULL
             ORDER BY arrival_index DESC LIMIT 1",
            &[&namespace, &key],
        )
        .await?;
    let (prev_index, prev_hash) = match last {
        Some(row) => {
            let i: i64 = row.get(0);
            let h: Vec<u8> = row.get(1);
            let h: [u8; 32] = h
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("stored running hash is not 32 bytes"))?;
            (u64::try_from(i)?, h)
        }
        None => (0, dsm::storage_cell::running_hash_init(namespace, &key32)),
    };
    let index = prev_index + 1;
    let running_hash =
        dsm::storage_cell::running_hash_next(&prev_hash, &dsm::storage_cell::entry_digest(value));
    tx.execute(
        "INSERT INTO cells (namespace, cell_key, value, arrival_index, running_hash)
         VALUES ($1, $2, $3, $4, $5)",
        &[
            &namespace,
            &key,
            &value,
            &i64::try_from(index)?,
            &running_hash.as_slice(),
        ],
    )
    .await?;
    Ok((index, running_hash))
}

/// Everything held for `(namespace, key)`, in the order it arrived.
pub async fn get_cell_values(pool: &Pool, namespace: &[u8], key: &[u8]) -> Result<Vec<Vec<u8>>> {
    Ok(get_cell_entries(pool, namespace, key)
        .await?
        .into_iter()
        .map(|(v, _, _)| v)
        .collect())
}

/// Everything held for `(namespace, key)`, in arrival order, each with its
/// `(index, running hash)`.
pub async fn get_cell_entries(
    pool: &Pool,
    namespace: &[u8],
    key: &[u8],
) -> Result<Vec<(Vec<u8>, u64, [u8; 32])>> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT value, arrival_index, running_hash FROM cells
             WHERE namespace = $1 AND cell_key = $2 ORDER BY seq ASC",
            &[&namespace, &key],
        )
        .await?;
    rows.iter()
        .map(|r| {
            let i: Option<i64> = r.get(1);
            let h: Option<Vec<u8>> = r.get(2);
            let (Some(i), Some(h)) = (i, h) else {
                anyhow::bail!("cell entry has no arrival record; backfill has not run");
            };
            let h: [u8; 32] = h
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("stored running hash is not 32 bytes"))?;
            Ok((r.get::<_, Vec<u8>>(0), u64::try_from(i)?, h))
        })
        .collect()
}

/// Give every entry of every key that holds an entry without an arrival
/// record its record: the key's values replayed in arrival (`seq`) order,
/// exactly as storage spec §14 defines `(i, h_i)`. The key's indexes are
/// cleared first so the unique arrival index never sees two rows claim one
/// position mid-rewrite. Only the two metadata columns are written; no value
/// is touched. Idempotent: a key whose entries all hold records is not read.
pub async fn backfill_cell_arrival_records(pool: &Pool) -> Result<u64> {
    let mut client = pool.get().await?;
    let keys = client
        .query(
            "SELECT DISTINCT namespace, cell_key FROM cells WHERE arrival_index IS NULL",
            &[],
        )
        .await?;
    let mut fixed = 0u64;
    for k in keys {
        let namespace: Vec<u8> = k.get(0);
        let key: Vec<u8> = k.get(1);
        let key32: [u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("a held cell key is not 32 bytes"))?;
        let tx = begin_durable_write(&mut client).await?;
        let rows = tx
            .query(
                "SELECT seq, value FROM cells WHERE namespace = $1 AND cell_key = $2
                 ORDER BY seq ASC FOR UPDATE",
                &[&namespace, &key],
            )
            .await?;
        tx.execute(
            "UPDATE cells SET arrival_index = NULL, running_hash = NULL
             WHERE namespace = $1 AND cell_key = $2",
            &[&namespace, &key],
        )
        .await?;
        let mut h = dsm::storage_cell::running_hash_init(&namespace, &key32);
        for (n, row) in rows.iter().enumerate() {
            let seq: i64 = row.get(0);
            let value: Vec<u8> = row.get(1);
            h = dsm::storage_cell::running_hash_next(&h, &dsm::storage_cell::entry_digest(&value));
            tx.execute(
                "UPDATE cells SET arrival_index = $2, running_hash = $3 WHERE seq = $1",
                &[&seq, &(n as i64 + 1), &h.as_slice()],
            )
            .await?;
        }
        tx.commit().await?;
        fixed += 1;
    }
    Ok(fixed)
}

/// A cell row exactly as a binary from before arrival records wrote it: the
/// value and nothing else. Unit tests only.
#[cfg(test)]
pub(crate) async fn insert_cell_without_record(
    pool: &Pool,
    namespace: &[u8],
    key: &[u8],
    value: &[u8],
) -> Result<()> {
    pool.get()
        .await?
        .execute(
            "INSERT INTO cells (namespace, cell_key, value) VALUES ($1, $2, $3)",
            &[&namespace, &key, &value],
        )
        .await?;
    Ok(())
}

// ── ByteCommits (storage spec §14) ─────────────────────────────────────────

/// Close the next cycle if any cell entry has arrived since the last one:
/// stamp those entries with the new cycle, build the SMT over every cell's
/// latest committed entry, and store the ByteCommit chained to the previous
/// one — all in one durable transaction. Returns the latest ByteCommit
/// (the new one, or the existing one if nothing arrived), or `None` if this
/// node has never closed a cycle and holds no entries.
pub async fn close_cycle(
    pool: &Pool,
    member_id: &[u8],
) -> Result<Option<dsm::storage_cell::ByteCommit>> {
    use prost::Message;
    if member_id.is_empty() || member_id.len() > dsm::storage_cell::MAX_MEMBER_ID_LEN {
        anyhow::bail!("member id cannot name a ByteCommit");
    }
    let mut client = pool.get().await?;
    let tx = begin_durable_write(&mut client).await?;
    // One closer at a time; puts are not blocked.
    tx.execute(
        "SELECT pg_advisory_xact_lock($1)",
        &[&0x4453_4D42_434C_4F53_i64],
    )
    .await?;
    let last = tx
        .query_opt(
            "SELECT commit_pb FROM own_bytecommits ORDER BY cycle_index DESC LIMIT 1",
            &[],
        )
        .await?
        .map(|r| decode_commit(&r.get::<_, Vec<u8>>(0)))
        .transpose()?;
    let pending: bool = tx
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM cells WHERE committed_cycle IS NULL)",
            &[],
        )
        .await?
        .get(0);
    if !pending {
        tx.commit().await?;
        return Ok(last);
    }
    let cycle = last.as_ref().map_or(1, |c| c.cycle_index + 1);
    let cycle_i64 = i64::try_from(cycle)?;
    tx.execute(
        "UPDATE cells SET committed_cycle = $1 WHERE committed_cycle IS NULL",
        &[&cycle_i64],
    )
    .await?;
    let leaves = cell_leaves_tx(&tx, cycle_i64).await?;
    let tree =
        dsm::storage_cell::cell_tree(leaves.iter().map(|(n, k, i, h)| (n.as_slice(), k, *i, h)));
    let bytes_used: i64 = tx
        .query_one(
            "SELECT COALESCE((SELECT SUM(LENGTH(value)) FROM cells), 0)::BIGINT
                  + COALESCE((SELECT SUM(LENGTH(payload)) FROM immutable_objects), 0)::BIGINT",
            &[],
        )
        .await?
        .get(0);
    let commit = dsm::storage_cell::ByteCommit {
        member_id: member_id.to_vec(),
        cycle_index: cycle,
        smt_root: *tree.root(),
        bytes_used: u64::try_from(bytes_used.max(0))?,
        parent_digest: last.as_ref().map_or([0u8; 32], |c| c.digest()),
    };
    let digest = commit.digest();
    tx.execute(
        "INSERT INTO own_bytecommits (cycle_index, digest, commit_pb) VALUES ($1, $2, $3)",
        &[
            &cycle_i64,
            &digest.as_slice(),
            &commit.to_proto().encode_to_vec(),
        ],
    )
    .await?;
    tx.commit().await?;
    Ok(Some(commit))
}

fn decode_commit(bytes: &[u8]) -> Result<dsm::storage_cell::ByteCommit> {
    use prost::Message;
    let p = dsm::types::proto::ByteCommitV4::decode(bytes)?;
    dsm::storage_cell::ByteCommit::from_proto(&p)
        .ok_or_else(|| anyhow::anyhow!("stored ByteCommit is malformed"))
}

type CellLeaf = (Vec<u8>, [u8; 32], u64, [u8; 32]);

/// Every cell's latest entry committed at or before `cycle`.
async fn cell_leaves_tx(
    tx: &deadpool_postgres::Transaction<'_>,
    cycle: i64,
) -> Result<Vec<CellLeaf>> {
    let rows = tx
        .query(
            "SELECT DISTINCT ON (namespace, cell_key)
                    namespace, cell_key, arrival_index, running_hash
             FROM cells WHERE committed_cycle <= $1
             ORDER BY namespace, cell_key, arrival_index DESC",
            &[&cycle],
        )
        .await?;
    rows.iter().map(row_to_leaf).collect()
}

fn row_to_leaf(r: &tokio_postgres::Row) -> Result<CellLeaf> {
    let key: Vec<u8> = r.get(1);
    let i: i64 = r.get(2);
    let h: Vec<u8> = r.get(3);
    Ok((
        r.get(0),
        key.as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("cell key is not 32 bytes"))?,
        u64::try_from(i)?,
        h.as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("stored running hash is not 32 bytes"))?,
    ))
}

/// This node's ByteCommit for `cycle`, or its latest when `cycle` is `None`.
pub async fn get_own_bytecommit(
    pool: &Pool,
    cycle: Option<u64>,
) -> Result<Option<dsm::storage_cell::ByteCommit>> {
    let client = pool.get().await?;
    let row = match cycle {
        Some(t) => {
            client
                .query_opt(
                    "SELECT commit_pb FROM own_bytecommits WHERE cycle_index = $1",
                    &[&i64::try_from(t)?],
                )
                .await?
        }
        None => {
            client
                .query_opt(
                    "SELECT commit_pb FROM own_bytecommits ORDER BY cycle_index DESC LIMIT 1",
                    &[],
                )
                .await?
        }
    };
    row.map(|r| decode_commit(&r.get::<_, Vec<u8>>(0)))
        .transpose()
}

/// The proof that this node's ByteCommit for `cycle` commits `(namespace,
/// key)`'s latest entry as of that cycle. `None` if the cycle does not exist
/// or the cell had no entry committed by then.
pub async fn cell_commit_proof(
    pool: &Pool,
    namespace: &[u8],
    key: &[u8; 32],
    cycle: u64,
) -> Result<Option<dsm::storage_cell::CellCommitProof>> {
    let mut client = pool.get().await?;
    let tx = client.build_transaction().read_only(true).start().await?;
    let cycle_i64 = i64::try_from(cycle)?;
    let exists: bool = tx
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM own_bytecommits WHERE cycle_index = $1)",
            &[&cycle_i64],
        )
        .await?
        .get(0);
    if !exists {
        return Ok(None);
    }
    let leaves = cell_leaves_tx(&tx, cycle_i64).await?;
    tx.commit().await?;
    let Some((_, _, index, running_hash)) = leaves
        .iter()
        .find(|(n, k, _, _)| n.as_slice() == namespace && k == key)
        .cloned()
    else {
        return Ok(None);
    };
    let tree =
        dsm::storage_cell::cell_tree(leaves.iter().map(|(n, k, i, h)| (n.as_slice(), k, *i, h)));
    Ok(dsm::storage_cell::CellCommitProof::from_tree(
        &tree,
        namespace,
        key,
        index,
        running_hash,
    ))
}

/// Keep a ByteCommit this node fetched from `member_id` itself. Idempotent
/// for identical bytes; a different ByteCommit for the same cycle is kept
/// beside the first as evidence. Returns whether it was not already held.
pub async fn mirror_put(pool: &Pool, commit: &dsm::storage_cell::ByteCommit) -> Result<bool> {
    use prost::Message;
    let client = pool.get().await?;
    let inserted = client
        .execute(
            "INSERT INTO bytecommit_mirror (member_id, cycle_index, digest, commit_pb)
             VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
            &[
                &commit.member_id,
                &i64::try_from(commit.cycle_index)?,
                &commit.digest().as_slice(),
                &commit.to_proto().encode_to_vec(),
            ],
        )
        .await?;
    Ok(inserted == 1)
}

/// Every distinct ByteCommit this node mirrored for `member_id` at `cycle`.
pub async fn mirror_get(
    pool: &Pool,
    member_id: &[u8],
    cycle: u64,
) -> Result<Vec<dsm::storage_cell::ByteCommit>> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT commit_pb FROM bytecommit_mirror
             WHERE member_id = $1 AND cycle_index = $2 ORDER BY digest",
            &[&member_id, &i64::try_from(cycle)?],
        )
        .await?;
    rows.iter()
        .map(|r| decode_commit(&r.get::<_, Vec<u8>>(0)))
        .collect()
}

/// The highest cycle mirrored for `member_id`, 0 if none.
pub async fn mirror_last_cycle(pool: &Pool, member_id: &[u8]) -> Result<u64> {
    let client = pool.get().await?;
    let t: Option<i64> = client
        .query_one(
            "SELECT MAX(cycle_index) FROM bytecommit_mirror WHERE member_id = $1",
            &[&member_id],
        )
        .await?
        .get(0);
    Ok(u64::try_from(t.unwrap_or(0))?)
}

/// Append a content address under `locator`. Never removed.
pub async fn append_index(pool: &Pool, locator: &[u8], addr: &[u8]) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO index_entries (locator, addr) VALUES ($1, $2)",
            &[&locator, &addr],
        )
        .await?;
    Ok(())
}

/// Addresses under `locator` with `seq > after`, in append order, at most
/// `limit`. Returns `(seq, addr)` so a reader can page from the last `seq`.
pub async fn read_index(
    pool: &Pool,
    locator: &[u8],
    after: i64,
    limit: i64,
) -> Result<Vec<(i64, Vec<u8>)>> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT seq, addr FROM index_entries WHERE locator = $1 AND seq > $2 \
             ORDER BY seq ASC LIMIT $3",
            &[&locator, &after, &limit],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| (r.get::<_, i64>(0), r.get::<_, Vec<u8>>(1)))
        .collect())
}
