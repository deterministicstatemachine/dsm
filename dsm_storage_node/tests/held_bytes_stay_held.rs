// SPDX-License-Identifier: MIT OR Apache-2.0
//! Storage spec §19: a node never deletes, expires or ages out what it
//! holds, and nothing is pruned. What a member holds (a cell's values, an
//! index entry, an immutable object, a spool envelope, a closed ByteCommit)
//! is answered byte for byte the same while the node keeps working, when a
//! caller asks it to delete, replace or patch, and after the node restarts on
//! the same store. Driven through the routers the binary serves, on a
//! Postgres database of its own.

mod common;

use std::sync::Arc;

use axum::{body::Body, http::Request, http::StatusCode, Router};
use dsm::utils::text_id;
use dsm_storage_node::AppState;
use prost::Message;
use tower::ServiceExt;

const STORE: &str = "held_bytes_stay_held";
const NS: &str = "DSM/test/held-bytes";

/// The member the binary serves on `pool`.
fn member(pool: Arc<dsm_storage_node::db::DBPool>) -> Router {
    let state = Arc::new(common::ok_or_panic(
        AppState::new("member".to_string(), pool, common::set_client()),
        "app state",
    ));
    common::served(state)
}

/// The member's answer to `method uri`: its status and its body.
async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> (StatusCode, Vec<u8>) {
    let mut req = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        req = req.header(*name, *value);
    }
    let req = common::ok_or_panic(req.body(Body::from(body)), "request");
    let resp = common::ok_or_panic(app.clone().oneshot(req).await, "the router answers");
    let status = resp.status();
    let bytes = common::ok_or_panic(
        axum::body::to_bytes(resp.into_body(), usize::MAX).await,
        "body",
    );
    (status, bytes.to_vec())
}

/// What one test holds at the member, by the paths it is read at.
struct Held {
    cell: String,
    locator: String,
    object: String,
    spool: String,
}

impl Held {
    /// Every read of what is held, in order: the member's answers.
    async fn reads(&self, app: &Router) -> Vec<(StatusCode, Vec<u8>)> {
        let ns = [("x-namespace", NS)];
        vec![
            call(
                app,
                "GET",
                &format!("/api/v2/cell/{}", self.cell),
                &ns,
                Vec::new(),
            )
            .await,
            call(
                app,
                "GET",
                &format!("/api/v2/index/{}", self.locator),
                &ns,
                Vec::new(),
            )
            .await,
            call(
                app,
                "GET",
                &format!("/api/v2/immutable/{}", self.object),
                &[],
                Vec::new(),
            )
            .await,
            call(
                app,
                "GET",
                "/api/v2/b0x/retrieve/0",
                &[("x-dsm-b0x-address", self.spool.as_str())],
                Vec::new(),
            )
            .await,
            call(app, "GET", "/api/v2/bytecommit/cycle/1", &[], Vec::new()).await,
        ]
    }

    /// Every path a held thing is read or written at.
    fn paths(&self) -> Vec<String> {
        vec![
            format!("/api/v2/cell/{}", self.cell),
            format!("/api/v2/index/{}", self.locator),
            format!("/api/v2/immutable/{}", self.object),
            "/api/v2/immutable/put".to_string(),
            "/api/v2/b0x/retrieve/0".to_string(),
            "/api/v2/b0x/submit".to_string(),
            "/api/v2/bytecommit/cycle/1".to_string(),
            "/api/v2/bytecommit/latest".to_string(),
        ]
    }
}

/// Close the member's next cycle; the ByteCommit it answers with.
async fn close(app: &Router) -> dsm::types::proto::ByteCommitV4 {
    let (status, bytes) = call(app, "POST", "/api/v2/bytecommit/close", &[], Vec::new()).await;
    assert_eq!(status, StatusCode::OK, "a cycle closes");
    common::ok_or_panic(
        dsm::types::proto::ByteCommitV4::decode(bytes.as_slice()),
        "a ByteCommit",
    )
}

/// Put `value` at `key` in the test namespace.
async fn put_cell(app: &Router, key: &str, value: &[u8]) {
    let (status, _) = call(
        app,
        "POST",
        &format!("/api/v2/cell/{key}"),
        &[("x-namespace", NS)],
        value.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the cell takes {value:?}");
}

/// Storage spec §19, §20: nothing the member does on its own, nothing a
/// caller asks of it, and no restart removes, replaces or hides what it
/// holds.
///
/// The member holds two values at a cell, an index entry, an immutable
/// object and a spool envelope, and closes a cycle over them. Then it keeps
/// working: three more cycles close over other cells. Every held path is
/// asked to delete, replace and patch. The member restarts on its store.
/// After each, every read answers byte for byte what it answered before.
#[test]
fn nothing_the_member_does_removes_what_it_holds() {
    // A runtime of its own: `#[tokio::test]` builds one with `expect`, which
    // this crate's lints refuse.
    let runtime = common::ok_or_panic(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build(),
        "a Tokio runtime",
    );
    runtime.block_on(keeps_everything());
}

/// The steps of `nothing_the_member_does_removes_what_it_holds`.
async fn keeps_everything() {
    let app = member(common::fresh_store(STORE).await);

    let cell = text_id::encode_base32_crockford(&[0x41; 32]);
    put_cell(&app, &cell, b"the first value").await;
    put_cell(&app, &cell, b"the second value").await;

    let (status, object) = call(
        &app,
        "POST",
        "/api/v2/immutable/put",
        &[("x-namespace", NS)],
        b"an object the member keeps".to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let object = common::ok_or_panic(String::from_utf8(object), "an address");
    let address = common::some_or_panic(
        text_id::decode_base32_crockford(&object),
        "a Base32 address",
    );

    let locator = text_id::encode_base32_crockford(&[0x42; 32]);
    let (status, _) = call(
        &app,
        "POST",
        &format!("/api/v2/index/{locator}"),
        &[("x-namespace", NS)],
        address,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let spool = text_id::encode_base32_crockford(&[0x43; 32]);
    let (status, _) = call(
        &app,
        "POST",
        "/api/v2/b0x/submit",
        &[
            ("content-type", "application/octet-stream"),
            ("x-dsm-recipient", spool.as_str()),
        ],
        b"an envelope the member never opens".to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let first = close(&app).await;
    assert_eq!(first.cycle_index, 1, "the first cycle commits the cell");

    let held = Held {
        cell,
        locator,
        object,
        spool,
    };
    let before = held.reads(&app).await;
    assert!(
        before.iter().all(|(status, _)| *status == StatusCode::OK),
        "everything held is read: {:?}",
        before.iter().map(|(status, _)| *status).collect::<Vec<_>>()
    );
    let values = common::ok_or_panic(
        dsm::types::proto::CellValuesV1::decode(before[0].1.as_slice()),
        "values",
    );
    assert_eq!(
        values.values,
        vec![b"the first value".to_vec(), b"the second value".to_vec()]
    );

    for n in 0..3u8 {
        let other = text_id::encode_base32_crockford(&[0x50 + n; 32]);
        put_cell(&app, &other, &[0x60 + n; 8]).await;
        assert_eq!(
            close(&app).await.cycle_index,
            u64::from(n) + 2,
            "a later cycle closes"
        );
    }
    assert_eq!(
        held.reads(&app).await,
        before,
        "later cycles removed or changed what was held"
    );

    for path in held.paths() {
        for method in ["DELETE", "PUT", "PATCH"] {
            let (status, _) = call(
                &app,
                method,
                &path,
                &[
                    ("x-namespace", NS),
                    ("content-type", "application/octet-stream"),
                    ("x-dsm-recipient", held.spool.as_str()),
                    ("x-dsm-b0x-address", held.spool.as_str()),
                ],
                b"replacement bytes".to_vec(),
            )
            .await;
            assert!(
                status == StatusCode::METHOD_NOT_ALLOWED || status == StatusCode::NOT_FOUND,
                "{method} {path} is served: {status}"
            );
        }
    }
    assert_eq!(
        held.reads(&app).await,
        before,
        "a request to delete, replace or patch changed what was held"
    );

    drop(app);
    let restarted = member(common::reopened_store(STORE).await);
    assert_eq!(
        held.reads(&restarted).await,
        before,
        "the restarted member does not answer what it held"
    );
}
