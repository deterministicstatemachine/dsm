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
                        envelope          BYTEA NOT NULL
                    );
                "#,
            )
            .await?;

    // Schema migration for older inbox_spool rows missing newer columns (clockless ordering).
    client
        .batch_execute(
            r#"ALTER TABLE inbox_spool
                    ADD COLUMN IF NOT EXISTS seq_num BIGINT NOT NULL DEFAULT 0;
                CREATE INDEX IF NOT EXISTS idx_inbox_spool_device_seq ON inbox_spool(device_id, seq_num);
                -- The spool is append-only: no read flag and no expiry. Which
                -- messages a device has consumed is the device's own state.
                DROP INDEX IF EXISTS idx_inbox_spool_device_acked;
                DROP INDEX IF EXISTS idx_inbox_spool_expires;
                ALTER TABLE inbox_spool DROP COLUMN IF EXISTS acked;
                ALTER TABLE inbox_spool DROP COLUMN IF EXISTS expires_at_iter;
            "#,
        )
        .await?;

    // ── Storage Node Regulation tables (clockless, signature-free) ──────────
    client
        .batch_execute(
            r#"-- Device tokens, their replay guard, and the spend gate's
                -- receipts and flag are gone with writer authorization and the
                -- spend gate (storage spec §4; owner, 2026-09-23).
                DROP TABLE IF EXISTS payment_receipts;
                -- The node decides no registry (storage spec §13).
                DROP TABLE IF EXISTS registry_evidence;
                DROP TABLE IF EXISTS node_registry;
                DROP TABLE IF EXISTS capacity_signals;
                DROP TABLE IF EXISTS applicants;
                DROP TABLE IF EXISTS inbox_receipts;
                -- The device directory is self-signed entries in keyed cells
                -- that readers verify; the node keeps no device table
                -- (owner, 2026-09-23).
                DROP TABLE IF EXISTS devices;
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

/// Every envelope in a spool from a sequence number on, in order, limited.
/// The spool is append-only (storage spec §4): nothing is marked, hidden or
/// removed after a write, and which messages a device has consumed is the
/// device's own state.
pub async fn spool_list_from_seq(
    pool: &Pool,
    device_id: &str,
    from_seq: i64,
    limit: i64,
) -> Result<Vec<(Vec<u8>, i64)>> {
    let client = pool.get().await?;
    let stmt = client
        .prepare_cached(
            "SELECT envelope, seq_num FROM inbox_spool
             WHERE device_id=$1 AND seq_num >= $2
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


// ===================== PaidK Spend-Gate =====================

// ===================== Node Registry & Signals =====================

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
