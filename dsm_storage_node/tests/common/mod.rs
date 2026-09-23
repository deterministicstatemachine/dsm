// SPDX-License-Identifier: Apache-2.0
//! Shared helpers for storage-node integration tests.
//!
//! Cargo treats `tests/common/` specially: files inside it are NOT compiled
//! as standalone integration test binaries, so we can safely keep helpers
//! here without spawning a phantom test target.

#![allow(dead_code)]

pub fn ok_or_panic<T, E: std::fmt::Debug>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{context}: {err:?}"),
    }
}

pub fn some_or_panic<T>(value: Option<T>, context: &str) -> T {
    match value {
        Some(value) => value,
        None => panic!("{context}"),
    }
}

/// A fresh, empty store for one node of one test, on the backend this build
/// serves: in-memory SQLite on a `local-dev` build, and on the shipped
/// Postgres build a database of its own on the server
/// `DSM_TEST_DATABASE_URL` names, dropped and recreated so a rerun starts
/// empty. `name` must be unique per node per test (letters, digits, `_`).
#[cfg(feature = "local-dev")]
pub async fn fresh_store(_name: &str) -> std::sync::Arc<dsm_storage_node::db::DBPool> {
    let pool = std::sync::Arc::new(ok_or_panic(
        dsm_storage_node::db::create_pool(":memory:", true),
        "pool",
    ));
    ok_or_panic(dsm_storage_node::db::init_db(&pool).await, "init db");
    pool
}

#[cfg(not(feature = "local-dev"))]
pub async fn fresh_store(name: &str) -> std::sync::Arc<dsm_storage_node::db::DBPool> {
    let server = std::env::var("DSM_TEST_DATABASE_URL").unwrap_or_else(|_| {
        panic!(
            "DSM_TEST_DATABASE_URL must name a Postgres server: these suites run on the \
             shipped backend, and skipping them would report a board that never executed it"
        )
    });
    let database = format!("dsm_test_{name}");
    let admin = ok_or_panic(
        dsm_storage_node::db::create_pool(&server, true),
        "admin pool",
    );
    let client = ok_or_panic(admin.get().await, "admin connection");
    ok_or_panic(
        client
            .batch_execute(&format!("DROP DATABASE IF EXISTS {database}"))
            .await,
        "drop the test database",
    );
    ok_or_panic(
        client
            .batch_execute(&format!("CREATE DATABASE {database}"))
            .await,
        "create the test database",
    );
    drop(client);
    let url = with_database(&server, &database);
    let pool = std::sync::Arc::new(ok_or_panic(
        dsm_storage_node::db::create_pool(&url, true),
        "pool",
    ));
    ok_or_panic(dsm_storage_node::db::init_db(&pool).await, "init db");
    pool
}

/// `url` with its database path replaced by `database`.
#[cfg(not(feature = "local-dev"))]
fn with_database(url: &str, database: &str) -> String {
    let (head, query) = match url.split_once('?') {
        Some((head, query)) => (head, Some(query)),
        None => (url, None),
    };
    let slash = some_or_panic(head.rfind('/'), "the database URL names no database");
    match query {
        Some(query) => format!("{}/{database}?{query}", &head[..slash]),
        None => format!("{}/{database}", &head[..slash]),
    }
}
