// SPDX-License-Identifier: MIT OR Apache-2.0
//! What a reader, a repairer and a writer can and cannot do to a member, on
//! the app the binary serves, each member on a Postgres database of its own.
//!
//! - Storage spec §19.3: a read costs the reader nothing. It asks for no
//!   credential and moves nothing the member commits.
//! - §21: any client may restore a missing replica of an immutable object at
//!   another member, and the member accepts it by hash only.
//! - §19, §12.6: a keyed cell's arrival order is not repairable by clients.
//!   Writing its values again, in whatever order, only appends.

mod common;

use axum::{http::StatusCode, Router};
use common::call;
use dsm::utils::text_id;
use prost::Message;

const NS: &str = "DSM/test/reads-restores";

/// Put `value` at `cell`; the member's arrival record for it, as bytes.
async fn put_cell(app: &Router, cell: &str, value: &[u8]) -> Vec<u8> {
    let (status, record) = call(
        app,
        "POST",
        &format!("/api/v2/cell/{cell}"),
        &[("x-namespace", NS)],
        value.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the cell takes {value:?}");
    record
}

/// Put `bytes` in the immutable store with `headers`: the status and the
/// address the member answers.
async fn put_object(app: &Router, headers: &[(&str, &str)], bytes: &[u8]) -> (StatusCode, String) {
    let (status, body) = call(
        app,
        "POST",
        "/api/v2/immutable/put",
        headers,
        bytes.to_vec(),
    )
    .await;
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// Close the member's cycle: the ByteCommit it answers with, as bytes.
async fn close(app: &Router) -> Vec<u8> {
    let (status, bytes) = call(app, "POST", "/api/v2/bytecommit/close", &[], Vec::new()).await;
    assert_eq!(status, StatusCode::OK, "a cycle closes");
    bytes
}

/// Storage spec §19.3: reads for verification cost no credits, and receiving
/// value or verifying provenance costs the reader nothing.
///
/// The member holds a cell value, an immutable object, an index entry and a
/// spool envelope, and closes a cycle over them. Every read the member serves
/// is asked for with nothing but the address it reads, and no credential of
/// any kind:
/// - the cell;
/// - the index;
/// - the object;
/// - the spool;
/// - the latest ByteCommit;
/// - cycle 1;
/// - the cell's commit proof.
///
/// Every read answers, and three rounds later every answer is the same. A
/// read is not an arrival: closing the cycle afterwards answers the
/// ByteCommit the member had, so the reads moved nothing the member commits
/// and charges by.
#[test]
fn a_read_asks_nothing_of_the_reader_and_moves_nothing() {
    common::runtime().block_on(reads_are_free());
}

/// The steps of `a_read_asks_nothing_of_the_reader_and_moves_nothing`.
async fn reads_are_free() {
    let app = common::member("member", common::fresh_store("reads_are_free").await);
    let cell = text_id::encode_base32_crockford(&[0x71; 32]);
    put_cell(&app, &cell, b"a value to read").await;
    let (status, object) = put_object(&app, &[("x-namespace", NS)], b"an object to read").await;
    assert_eq!(status, StatusCode::CREATED);
    let address = common::some_or_panic(
        text_id::decode_base32_crockford(&object),
        "a Base32 address",
    );
    let locator = text_id::encode_base32_crockford(&[0x72; 32]);
    let (status, _) = call(
        &app,
        "POST",
        &format!("/api/v2/index/{locator}"),
        &[("x-namespace", NS)],
        address,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let spool = text_id::encode_base32_crockford(&[0x73; 32]);
    let (status, _) = call(
        &app,
        "POST",
        "/api/v2/b0x/submit",
        &[
            ("content-type", "application/octet-stream"),
            ("x-dsm-recipient", spool.as_str()),
        ],
        b"an envelope to read".to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let committed = close(&app).await;

    let reads: Vec<(String, Vec<(&str, &str)>)> = vec![
        (format!("/api/v2/cell/{cell}"), vec![("x-namespace", NS)]),
        (
            format!("/api/v2/index/{locator}"),
            vec![("x-namespace", NS)],
        ),
        (format!("/api/v2/immutable/{object}"), Vec::new()),
        (
            "/api/v2/b0x/retrieve/0".to_string(),
            vec![("x-dsm-b0x-address", spool.as_str())],
        ),
        ("/api/v2/bytecommit/latest".to_string(), Vec::new()),
        ("/api/v2/bytecommit/cycle/1".to_string(), Vec::new()),
        (
            format!("/api/v2/bytecommit/proof/{cell}"),
            vec![("x-namespace", NS), ("x-cycle", "1")],
        ),
    ];
    let mut first = Vec::with_capacity(reads.len());
    for (path, headers) in &reads {
        let (status, body) = call(&app, "GET", path, headers, Vec::new()).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "GET {path} asked something of the reader"
        );
        first.push(body);
    }
    for round in 0..3 {
        for ((path, headers), before) in reads.iter().zip(&first) {
            let (status, body) = call(&app, "GET", path, headers, Vec::new()).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                &body, before,
                "GET {path} answered differently in round {round}"
            );
        }
    }
    assert_eq!(
        close(&app).await,
        committed,
        "the reads moved what the member commits"
    );
}

/// Storage spec §21: after a prune or an exit, any client may restore a
/// missing replica of an immutable object, and it is accepted by hash only.
///
/// Member A holds an object; member B does not. A client reads it from A and
/// puts it at B with no authorization, stating the address it restores. B
/// holds it at that address and serves the same bytes A does. At member C,
/// bytes that do not hash to that address, stated for it, are refused, and C
/// holds nothing there.
#[test]
fn a_client_restores_a_missing_object_accepted_by_hash_only() {
    common::runtime().block_on(restores());
}

/// The steps of `a_client_restores_a_missing_object_accepted_by_hash_only`.
async fn restores() {
    let a = common::member("member-a", common::fresh_store("restore_a").await);
    let b = common::member("member-b", common::fresh_store("restore_b").await);
    let c = common::member("member-c", common::fresh_store("restore_c").await);
    let object = b"an object member B has lost".to_vec();
    let (status, address) = put_object(&a, &[("x-namespace", NS)], &object).await;
    assert_eq!(status, StatusCode::CREATED);
    let path = format!("/api/v2/immutable/{address}");

    let (status, _) = call(&b, "GET", &path, &[], Vec::new()).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "B is missing the replica");

    let (status, read) = call(&a, "GET", &path, &[], Vec::new()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(read, object);
    let restore = [("x-namespace", NS), ("x-expected-addr", address.as_str())];
    let (status, restored) = put_object(&b, &restore, &read).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "B takes the replica from any client"
    );
    assert_eq!(restored, address, "B holds it at the address it hashes to");
    let (status, served) = call(&b, "GET", &path, &[], Vec::new()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(served, object, "B serves the bytes A serves");

    let (status, _) = put_object(&c, &restore, b"bytes that are not the object").await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "bytes that do not hash to the address are taken for it"
    );
    let (status, _) = call(&c, "GET", &path, &[], Vec::new()).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "C holds something at the address"
    );
}

/// Storage spec §19, §12.6: a keyed cell's arrival order is not repairable
/// by clients; it moves only by handover.
///
/// A cell holds `first` then `second`. A client writes the values again in
/// the order it would prefer, `second` then `first`. The member appends
/// them: the cell reads `first`, `second`, `second`, `first`. The first two
/// entries keep the arrival records the member returned when they arrived.
#[test]
fn a_client_cannot_reorder_a_cells_arrival_log() {
    common::runtime().block_on(order_is_kept());
}

/// The steps of `a_client_cannot_reorder_a_cells_arrival_log`.
async fn order_is_kept() {
    let app = common::member("member", common::fresh_store("arrival_order").await);
    let cell = text_id::encode_base32_crockford(&[0x74; 32]);
    let first_record = put_cell(&app, &cell, b"first").await;
    let second_record = put_cell(&app, &cell, b"second").await;

    put_cell(&app, &cell, b"second").await;
    put_cell(&app, &cell, b"first").await;

    let (status, body) = call(
        &app,
        "GET",
        &format!("/api/v2/cell/{cell}"),
        &[("x-namespace", NS)],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let held = common::ok_or_panic(
        dsm::types::proto::CellValuesV1::decode(body.as_slice()),
        "values",
    );
    assert_eq!(
        held.values,
        vec![
            b"first".to_vec(),
            b"second".to_vec(),
            b"second".to_vec(),
            b"first".to_vec()
        ],
        "the values written again were not appended in arrival order"
    );
    let records: Vec<Vec<u8>> = held.records.iter().map(|r| r.encode_to_vec()).collect();
    assert_eq!(
        records[..2],
        [first_record, second_record],
        "the first entries' arrival records moved"
    );
}
