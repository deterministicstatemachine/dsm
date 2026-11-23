// SPDX-License-Identifier: MIT OR Apache-2.0

//! The schema a node starts on (owner ruling #3): an empty database is created
//! at `SCHEMA_VERSION`; one at that version with exactly its layout is served;
//! one at 4 is brought up in place by adding the backup slot tables alone
//! (owner, 2026-11-23); anything else is refused. Each test runs in a Postgres schema of its own,
//! so "empty" is genuinely empty.

#![allow(clippy::disallowed_methods)] // unwrap/expect acceptable in deterministic tests

use crate::db::{self, test_store::unique_name, SCHEMA_VERSION};

/// A pool whose connections see only `schema`, created empty, and a pool on
/// the database to drop it with.
pub(super) async fn isolated_schema(tag: u8) -> (db::DBPool, db::DBPool, String) {
    let url = std::env::var("DSM_TEST_DATABASE_URL").expect(
        "DSM_TEST_DATABASE_URL must name a Postgres database: the node's store is Postgres",
    );
    let schema = format!("schema_{}", unique_name(tag).to_lowercase());
    let admin = db::create_pool(&url, db::POOL_MAX_SIZE).expect("pool");
    admin
        .get()
        .await
        .expect("connection")
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("create the schema");
    let sep = if url.contains('?') { '&' } else { '?' };
    let scoped = db::create_pool(
        &format!("{url}{sep}options=-c%20search_path%3D{schema}"),
        db::POOL_MAX_SIZE,
    )
    .expect("pool");
    (scoped, admin, schema)
}

pub(super) async fn drop_schema(admin: &db::DBPool, schema: &str) {
    admin
        .get()
        .await
        .expect("connection")
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .expect("drop the schema");
}

async fn exec(pool: &db::DBPool, sql: &str) {
    pool.get()
        .await
        .expect("connection")
        .batch_execute(sql)
        .await
        .expect("statement");
}

/// An empty database is created at the schema version with exactly its
/// layout, and a database at that version opens again.
#[tokio::test]
async fn an_empty_database_is_created_at_the_schema_version() {
    let (pool, admin, schema) = isolated_schema(0x51).await;
    db::init_db(&pool)
        .await
        .expect("an empty database is created");
    let version: i32 = pool
        .get()
        .await
        .expect("connection")
        .query_one("SELECT version FROM schema_version WHERE only_row = 1", &[])
        .await
        .expect("the version row")
        .get(0);
    assert_eq!(version, SCHEMA_VERSION);
    db::init_db(&pool)
        .await
        .expect("a database at the schema version opens");
    drop_schema(&admin, &schema).await;
}

/// Tables with no version row are not version zero: the node refuses them.
#[tokio::test]
async fn a_database_with_tables_and_no_version_is_refused() {
    let (pool, admin, schema) = isolated_schema(0x52).await;
    exec(&pool, "CREATE TABLE cells (seq BIGSERIAL PRIMARY KEY)").await;
    let err = db::init_db(&pool)
        .await
        .expect_err("an unversioned database is refused");
    assert!(err.to_string().contains("no schema version"), "{err}");
    drop_schema(&admin, &schema).await;
}

/// A database at another version is refused, older or newer, except the one
/// version brought up in place.
#[tokio::test]
async fn a_database_at_another_version_is_refused() {
    let (pool, admin, schema) = isolated_schema(0x53).await;
    db::init_db(&pool).await.expect("created");
    for other in [SCHEMA_VERSION - 2, SCHEMA_VERSION + 1] {
        exec(
            &pool,
            &format!("UPDATE schema_version SET version = {other} WHERE only_row = 1"),
        )
        .await;
        let err = db::init_db(&pool)
            .await
            .expect_err("another version is refused");
        assert!(
            err.to_string()
                .contains(&format!("is at schema version {other}")),
            "{err}"
        );
    }
    drop_schema(&admin, &schema).await;
}

/// A database stamped with the version whose layout drifted from it is
/// refused: the version row alone is not the schema.
#[tokio::test]
async fn a_database_whose_layout_is_not_the_versions_is_refused() {
    let (pool, admin, schema) = isolated_schema(0x54).await;
    db::init_db(&pool).await.expect("created");
    exec(&pool, "ALTER TABLE cells ADD COLUMN acked BOOLEAN").await;
    let err = db::init_db(&pool)
        .await
        .expect_err("an extra column is refused");
    assert!(err.to_string().contains("columns are not those"), "{err}");
    exec(&pool, "ALTER TABLE cells DROP COLUMN acked").await;
    db::init_db(&pool).await.expect("the layout is whole again");
    exec(&pool, "CREATE INDEX cells_extra ON cells (value)").await;
    let err = db::init_db(&pool)
        .await
        .expect_err("an extra index is refused");
    assert!(err.to_string().contains("indexes are not those"), "{err}");
    drop_schema(&admin, &schema).await;
}

/// Put the database as a version-4 node left it: the backup slot tables gone
/// and the version row at 4.
async fn as_version_4(pool: &db::DBPool) {
    exec(
        pool,
        "DROP TABLE backup_parts; DROP TABLE backup_slots;
         UPDATE schema_version SET version = 4 WHERE only_row = 1",
    )
    .await;
}

/// A database at 4 is brought up to the schema version in place: the backup
/// slot tables are added and every cell it held is held exactly as it was,
/// arrival record and all. One at 4 whose layout drifted is refused, and left
/// at 4 with nothing added.
/// MUTATION CONTROL: refusing version 4 in `init_db` as before (no
/// `upgrade_in_place`) turns the first half red; committing before the layout
/// check turns the second half red.
#[tokio::test]
async fn a_database_at_4_is_brought_up_in_place_keeping_every_cell() {
    let (pool, admin, schema) = isolated_schema(0x55).await;
    db::init_db(&pool).await.expect("created");
    let key = [0x3C; 32];
    let record = db::put_cell(&pool, b"DSM/test/kept", &key, b"a board account's cell")
        .await
        .expect("a cell");
    as_version_4(&pool).await;
    db::init_db(&pool).await.expect("brought up in place");
    let client = pool.get().await.expect("connection");
    let version: i32 = client
        .query_one("SELECT version FROM schema_version WHERE only_row = 1", &[])
        .await
        .expect("the version row")
        .get(0);
    assert_eq!(version, SCHEMA_VERSION);
    let held = client
        .query_one(
            "SELECT value, arrival_index, running_hash FROM cells WHERE cell_key = $1",
            &[&key.as_slice()],
        )
        .await
        .expect("the cell is still held");
    assert_eq!(held.get::<_, Vec<u8>>(0), b"a board account's cell".to_vec());
    assert_eq!(
        (held.get::<_, i64>(1), held.get::<_, Vec<u8>>(2)),
        (i64::try_from(record.0).expect("index"), record.1.to_vec()),
        "its arrival record as it was"
    );
    drop(client);

    as_version_4(&pool).await;
    exec(&pool, "ALTER TABLE cells ADD COLUMN acked BOOLEAN").await;
    let err = db::init_db(&pool)
        .await
        .expect_err("a drifted version 4 is refused");
    assert!(err.to_string().contains("columns are not those"), "{err}");
    let client = pool.get().await.expect("connection");
    let version: i32 = client
        .query_one("SELECT version FROM schema_version WHERE only_row = 1", &[])
        .await
        .expect("the version row")
        .get(0);
    assert_eq!(version, 4, "nothing committed");
    let tables: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM information_schema.tables
              WHERE table_schema = current_schema() AND table_name LIKE 'backup_%'",
            &[],
        )
        .await
        .expect("count")
        .get(0);
    assert_eq!(tables, 0, "no backup table added");
    drop(client);
    drop_schema(&admin, &schema).await;
}
