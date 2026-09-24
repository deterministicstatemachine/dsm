// SPDX-License-Identifier: MIT OR Apache-2.0

//! The schema a node starts on (owner ruling #3): an empty database is created
//! at `SCHEMA_VERSION`; one at that version with exactly its layout is served;
//! anything else is refused. Each test runs in a Postgres schema of its own,
//! so "empty" is genuinely empty.

#![allow(clippy::disallowed_methods)] // unwrap/expect acceptable in deterministic tests

use crate::db::{self, test_store::unique_name, SCHEMA_VERSION};

/// A pool whose connections see only `schema`, created empty, and a pool on
/// the database to drop it with.
async fn isolated_schema(tag: u8) -> (db::DBPool, db::DBPool, String) {
    let url = std::env::var("DSM_TEST_DATABASE_URL").expect(
        "DSM_TEST_DATABASE_URL must name a Postgres database: the node's store is Postgres",
    );
    let schema = format!("schema_{}", unique_name(tag).to_lowercase());
    let admin = db::create_pool(&url).expect("pool");
    admin
        .get()
        .await
        .expect("connection")
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("create the schema");
    let sep = if url.contains('?') { '&' } else { '?' };
    let scoped =
        db::create_pool(&format!("{url}{sep}options=-c%20search_path%3D{schema}")).expect("pool");
    (scoped, admin, schema)
}

async fn drop_schema(admin: &db::DBPool, schema: &str) {
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

/// A database at another version is refused, older or newer: nothing is
/// migrated.
#[tokio::test]
async fn a_database_at_another_version_is_refused() {
    let (pool, admin, schema) = isolated_schema(0x53).await;
    db::init_db(&pool).await.expect("created");
    for other in [SCHEMA_VERSION - 1, SCHEMA_VERSION + 1] {
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
