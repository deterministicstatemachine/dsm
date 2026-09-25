// SPDX-License-Identifier: MIT OR Apache-2.0

//! Storage node DB layer (clean, DLV-only)
//! Minimal schema + helpers used by the DLV-backed object store.

use anyhow::{anyhow, bail, Result};
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
        let pool = crate::db::test_store::test_pool();
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

/// The storage layout this build creates and serves (owner ruling #3).
///
/// A database carries exactly one schema version. This build starts only on an
/// empty database, which it creates at this version, or on one already at this
/// version whose layout is exactly [`SCHEMA_LAYOUT`]. It migrates nothing: an
/// older, newer or unversioned database is refused, and is reprovisioned, not
/// transformed. The schema version is its own axis — not the protocol version,
/// and not the register incarnation, which names this node's register history.
pub const SCHEMA_VERSION: i32 = 1;

/// The DDL of [`SCHEMA_VERSION`], run once, on an empty database, in one
/// transaction with the version row.
const SCHEMA_DDL: &str = r#"
    CREATE TABLE schema_version (
        only_row SMALLINT PRIMARY KEY CHECK (only_row = 1),
        version  INTEGER NOT NULL
    );

    CREATE TABLE register_incarnation (
        only_row    SMALLINT PRIMARY KEY CHECK (only_row = 1),
        incarnation BYTEA NOT NULL
    );

    -- Keyed cells: the member keeps EVERY value it is given for a key, in
    -- arrival order, and never refuses, replaces or compares. Which value
    -- counts is the reader's question. Each entry carries its per-key arrival
    -- index (from 1) and the member's running hash for the key after it, and,
    -- once a cycle closes over it, that cycle (storage spec §14).
    CREATE TABLE cells (
        seq             BIGSERIAL PRIMARY KEY,
        namespace       BYTEA NOT NULL,
        cell_key        BYTEA NOT NULL,
        value           BYTEA NOT NULL,
        arrival_index   BIGINT NOT NULL,
        running_hash    BYTEA NOT NULL,
        committed_cycle BIGINT
    );
    CREATE INDEX cells_by_key ON cells (namespace, cell_key, seq);
    CREATE UNIQUE INDEX cells_by_arrival ON cells (namespace, cell_key, arrival_index);
    CREATE INDEX cells_uncommitted ON cells (seq) WHERE committed_cycle IS NULL;

    -- Indexes: content addresses appended under a locator, never removed,
    -- read back in append order.
    CREATE TABLE index_entries (
        seq     BIGSERIAL PRIMARY KEY,
        locator BYTEA NOT NULL,
        addr    BYTEA NOT NULL
    );
    CREATE INDEX index_entries_by_locator ON index_entries (locator, seq);

    CREATE TABLE dlv_slots (
        dlv_id         BYTEA PRIMARY KEY,
        capacity_bytes BIGINT NOT NULL,
        used_bytes     BIGINT NOT NULL,
        stake_hash     BYTEA NOT NULL
    );

    -- The b0x inbox spool: append-only, per device, read from a position.
    -- Which messages a device has consumed is the device's own state.
    CREATE TABLE inbox_spool (
        id         BIGSERIAL PRIMARY KEY,
        device_id  TEXT NOT NULL,
        message_id TEXT NOT NULL UNIQUE,
        envelope   BYTEA NOT NULL,
        seq_num    BIGINT NOT NULL
    );
    CREATE INDEX idx_inbox_spool_device_seq ON inbox_spool (device_id, seq_num);

    -- One validated Device Tree state per genesis; `version_number` is the
    -- monotone counter the PUT /devtree/root validator enforces.
    CREATE TABLE device_tree_states (
        genesis_b32     TEXT PRIMARY KEY,
        version_number  BIGINT NOT NULL,
        device_count    BIGINT NOT NULL,
        root_hash       BYTEA NOT NULL,
        payload         BYTEA NOT NULL,
        updated_at_tick BIGINT NOT NULL
    );
    CREATE INDEX idx_device_tree_states_version ON device_tree_states (genesis_b32, version_number);

    -- The immutable object store, keyed by the content address addr(N, P);
    -- write-once: no UPDATE and no DELETE statement exists against it.
    CREATE TABLE immutable_objects (
        addr_b32           TEXT PRIMARY KEY,
        namespace          BYTEA NOT NULL,
        payload            BYTEA NOT NULL,
        first_written_tick BIGINT NOT NULL
    );

    -- This node's own ByteCommits, one per cycle (storage spec §14).
    CREATE TABLE own_bytecommits (
        cycle_index BIGINT PRIMARY KEY,
        digest      BYTEA NOT NULL,
        commit_pb   BYTEA NOT NULL
    );
    -- This node's mirror of its set-mates' ByteCommits: only what it fetched
    -- from that member itself. Every distinct ByteCommit is kept, so an
    -- equivocation shows.
    CREATE TABLE bytecommit_mirror (
        member_id   BYTEA NOT NULL,
        cycle_index BIGINT NOT NULL,
        digest      BYTEA NOT NULL,
        commit_pb   BYTEA NOT NULL,
        PRIMARY KEY (member_id, cycle_index, digest)
    );
"#;

/// A column as `information_schema.columns` reports it: name, `udt_name`,
/// nullable.
type ExpectedColumn = (&'static str, &'static str, bool);

/// The layout of [`SCHEMA_VERSION`]: every table with its columns in order,
/// and every index. A database at this version holds exactly this — nothing
/// missing, nothing extra — or the node does not start on it.
pub const SCHEMA_LAYOUT: &[(&str, &[ExpectedColumn])] = &[
    (
        "bytecommit_mirror",
        &[
            ("member_id", "bytea", false),
            ("cycle_index", "int8", false),
            ("digest", "bytea", false),
            ("commit_pb", "bytea", false),
        ],
    ),
    (
        "cells",
        &[
            ("seq", "int8", false),
            ("namespace", "bytea", false),
            ("cell_key", "bytea", false),
            ("value", "bytea", false),
            ("arrival_index", "int8", false),
            ("running_hash", "bytea", false),
            ("committed_cycle", "int8", true),
        ],
    ),
    (
        "device_tree_states",
        &[
            ("genesis_b32", "text", false),
            ("version_number", "int8", false),
            ("device_count", "int8", false),
            ("root_hash", "bytea", false),
            ("payload", "bytea", false),
            ("updated_at_tick", "int8", false),
        ],
    ),
    (
        "dlv_slots",
        &[
            ("dlv_id", "bytea", false),
            ("capacity_bytes", "int8", false),
            ("used_bytes", "int8", false),
            ("stake_hash", "bytea", false),
        ],
    ),
    (
        "immutable_objects",
        &[
            ("addr_b32", "text", false),
            ("namespace", "bytea", false),
            ("payload", "bytea", false),
            ("first_written_tick", "int8", false),
        ],
    ),
    (
        "inbox_spool",
        &[
            ("id", "int8", false),
            ("device_id", "text", false),
            ("message_id", "text", false),
            ("envelope", "bytea", false),
            ("seq_num", "int8", false),
        ],
    ),
    (
        "index_entries",
        &[
            ("seq", "int8", false),
            ("locator", "bytea", false),
            ("addr", "bytea", false),
        ],
    ),
    (
        "own_bytecommits",
        &[
            ("cycle_index", "int8", false),
            ("digest", "bytea", false),
            ("commit_pb", "bytea", false),
        ],
    ),
    (
        "register_incarnation",
        &[("only_row", "int2", false), ("incarnation", "bytea", false)],
    ),
    (
        "schema_version",
        &[("only_row", "int2", false), ("version", "int4", false)],
    ),
];

/// Every index of [`SCHEMA_VERSION`], the implicit ones of primary keys and
/// unique constraints included.
pub const SCHEMA_INDEXES: &[&str] = &[
    "bytecommit_mirror_pkey",
    "cells_by_arrival",
    "cells_by_key",
    "cells_pkey",
    "cells_uncommitted",
    "device_tree_states_pkey",
    "dlv_slots_pkey",
    "idx_device_tree_states_version",
    "idx_inbox_spool_device_seq",
    "immutable_objects_pkey",
    "inbox_spool_message_id_key",
    "inbox_spool_pkey",
    "index_entries_by_locator",
    "index_entries_pkey",
    "own_bytecommits_pkey",
    "register_incarnation_pkey",
    "schema_version_pkey",
];

/// Advisory-lock key serialising schema initialisation on one database.
const INIT_DB_LOCK: i64 = 0x4453_4D49_4E49_5444;

/// Open the database at [`SCHEMA_VERSION`] or refuse. An empty database is
/// created at this version; a database at this version is checked against
/// [`SCHEMA_LAYOUT`] and [`SCHEMA_INDEXES`]; anything else — tables with no
/// version row, or another version — is refused. Initialisations of one
/// database run one at a time under a session advisory lock, released on
/// every path.
pub async fn init_db(pool: &Pool) -> Result<()> {
    let mut client = pool.get().await?;
    client
        .execute("SELECT pg_advisory_lock($1)", &[&INIT_DB_LOCK])
        .await?;
    let result = init_db_serialized(&mut client).await;
    client
        .execute("SELECT pg_advisory_unlock($1)", &[&INIT_DB_LOCK])
        .await?;
    result
}

async fn init_db_serialized(client: &mut deadpool_postgres::Object) -> Result<()> {
    let tables: Vec<String> = client
        .query(
            "SELECT table_name::text FROM information_schema.tables
              WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    if tables.is_empty() {
        let tx = client.transaction().await?;
        tx.batch_execute(SCHEMA_DDL).await?;
        tx.execute(
            "INSERT INTO schema_version (only_row, version) VALUES (1, $1)",
            &[&SCHEMA_VERSION],
        )
        .await?;
        tx.commit().await?;
        log::info!("storage database created at schema version {SCHEMA_VERSION}");
    } else {
        if !tables.iter().any(|t| t == "schema_version") {
            bail!(
                "the storage database holds tables but no schema version; this build \
                 starts only on an empty database or one at schema version {SCHEMA_VERSION} \
                 — reprovision the database"
            );
        }
        let held: Option<i32> = client
            .query_opt("SELECT version FROM schema_version WHERE only_row = 1", &[])
            .await?
            .map(|r| r.get(0));
        match held {
            Some(v) if v == SCHEMA_VERSION => {}
            Some(v) => bail!(
                "the storage database is at schema version {v}; this build serves exactly \
                 {SCHEMA_VERSION} and migrates nothing — reprovision the database"
            ),
            None => bail!(
                "the storage database's schema_version table holds no version row — \
                 reprovision the database"
            ),
        }
    }
    verify_schema_layout(client).await
}

/// The database's tables, columns and indexes are exactly those of
/// [`SCHEMA_VERSION`].
async fn verify_schema_layout(client: &deadpool_postgres::Object) -> Result<()> {
    let rows = client
        .query(
            "SELECT table_name::text, column_name::text, udt_name::text, is_nullable::text
               FROM information_schema.columns
              WHERE table_schema = current_schema()
              ORDER BY table_name, ordinal_position",
            &[],
        )
        .await?;
    let held: Vec<(String, String, String, bool)> = rows
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get::<_, String>(3) == "YES"))
        .collect();
    let expected: Vec<(String, String, String, bool)> = SCHEMA_LAYOUT
        .iter()
        .flat_map(|(table, columns)| {
            columns.iter().map(move |(column, udt, nullable)| {
                (
                    table.to_string(),
                    column.to_string(),
                    udt.to_string(),
                    *nullable,
                )
            })
        })
        .collect();
    if held != expected {
        let missing: Vec<_> = expected.iter().filter(|c| !held.contains(c)).collect();
        let extra: Vec<_> = held.iter().filter(|c| !expected.contains(c)).collect();
        bail!(
            "the storage database's columns are not those of schema version {SCHEMA_VERSION} \
             (missing {missing:?}, unexpected {extra:?}) — reprovision the database"
        );
    }

    let mut indexes: Vec<String> = client
        .query(
            "SELECT indexname::text FROM pg_indexes WHERE schemaname = current_schema()",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    indexes.sort();
    let expected_indexes: Vec<String> = SCHEMA_INDEXES.iter().map(|s| s.to_string()).collect();
    if indexes != expected_indexes {
        bail!(
            "the storage database's indexes are not those of schema version {SCHEMA_VERSION} \
             (held {indexes:?}) — reprovision the database"
        );
    }
    Ok(())
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

/// Outcome of [`insert_immutable_object_if_absent`]: the tuple was inserted,
/// the identical `(namespace, payload)` tuple was already held, or a different
/// tuple is held at the address and stays as it was.
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
pub fn create_pool(database_url: &str) -> anyhow::Result<DBPool> {
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
             WHERE namespace = $1 AND cell_key = $2
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
            let i: i64 = r.get(1);
            let h: Vec<u8> = r.get(2);
            let h: [u8; 32] = h
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("stored running hash is not 32 bytes"))?;
            Ok((r.get::<_, Vec<u8>>(0), u64::try_from(i)?, h))
        })
        .collect()
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
