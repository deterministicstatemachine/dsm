// SPDX-License-Identifier: MIT OR Apache-2.0
//! The keyed-cell and index contract, executed against the real routers.
//!
//! A member keeps every value it is given for a key, in arrival order, and
//! never refuses, replaces or compares. Absence is asserted by shape: `200`
//! with an empty list. An index is append-only and pages from the last `seq`.
//! Nothing here decodes a value; the payloads are arbitrary bytes on purpose.

#![allow(clippy::disallowed_methods)]

mod common;

use std::sync::Arc;

use axum::{body::Body, http::Request, http::StatusCode, Router};
use dsm::utils::text_id;
use dsm_storage_node::AppState;
use prost::Message;
use tower::ServiceExt;

const NS: &str = "DSM/cells-contract";

/// A member over a fresh store of its own, named `store`.
async fn member(store: &str) -> Router {
    let pool = common::fresh_store(store).await;
    let state = Arc::new(common::ok_or_panic(
        AppState::new("member".to_string(), pool, common::set_client()),
        "app state",
    ));
    // The binary's own assembly: what this suite drives is what is served.
    common::served(state)
}

fn key(tag: u8) -> String {
    text_id::encode_base32_crockford(&[tag; 32])
}

async fn put(app: &Router, ns: Option<&str>, key: &str, bytes: &[u8]) -> StatusCode {
    let mut req = Request::builder()
        .method("POST")
        .uri(format!("/api/v2/cell/{key}"));
    if let Some(ns) = ns {
        req = req.header("x-namespace", ns);
    }
    let req = req.body(Body::from(bytes.to_vec())).expect("request");
    app.clone().oneshot(req).await.expect("oneshot").status()
}

async fn get(app: &Router, key: &str) -> (StatusCode, Vec<Vec<u8>>) {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v2/cell/{key}"))
        .header("x-namespace", NS)
        .body(Body::empty())
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    let values = if status == StatusCode::OK {
        dsm::types::proto::CellValuesV1::decode(body.as_ref())
            .expect("CellValuesV1")
            .values
    } else {
        Vec::new()
    };
    (status, values)
}

async fn append(app: &Router, locator: &str, addr: &[u8]) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v2/index/{locator}"))
        .header("x-namespace", NS)
        .body(Body::from(addr.to_vec()))
        .expect("request");
    app.clone().oneshot(req).await.expect("oneshot").status()
}

/// Put `bytes` in the member's immutable store: the address it computes.
async fn held(app: &Router, bytes: &[u8]) -> [u8; 32] {
    let (status, addr) = common::call(
        app,
        "POST",
        "/api/v2/immutable/put",
        &[("x-namespace", NS)],
        bytes.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "the member takes the object");
    let addr = common::some_or_panic(
        text_id::decode_base32_crockford(&String::from_utf8_lossy(&addr)),
        "a Base32 address",
    );
    common::ok_or_panic(addr.as_slice().try_into(), "a 32-byte address")
}

async fn page(app: &Router, locator: &str, query: &str) -> Vec<(i64, Vec<u8>)> {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v2/index/{locator}{query}"))
        .header("x-namespace", NS)
        .body(Body::empty())
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    dsm::types::proto::IndexPageV1::decode(body.as_ref())
        .expect("IndexPageV1")
        .entries
        .into_iter()
        .map(|e| (e.seq, e.addr))
        .collect()
}

/// The property the old registers broke: a second, different value at a
/// key is KEPT, after the first. Nothing is refused and nothing is compared.
async fn put_batch(app: &Router, entries: Vec<(Vec<u8>, [u8; 32], Vec<u8>)>) -> StatusCode {
    let batch = dsm::types::proto::CellPutsV1 {
        entries: entries
            .into_iter()
            .map(|(namespace, key, value)| dsm::types::proto::CellPutV1 {
                namespace,
                key: key.to_vec(),
                value,
            })
            .collect(),
    };
    let req = Request::builder()
        .method("POST")
        .uri("/api/v2/cells")
        .body(Body::from(batch.encode_to_vec()))
        .expect("request");
    app.clone().oneshot(req).await.expect("oneshot").status()
}

/// Part II §17.4: the two position cells are taken in ONE local transaction
/// on the served assembly — both after anything already there, or, for a
/// batch that names no cell, neither.
#[tokio::test]
async fn a_batch_put_takes_every_key_or_none_on_the_served_assembly() {
    let app = member("cells_a_batch_put_takes_every_key_or_none_on_the_s").await;
    let (k1, k2) = (key(0x21), key(0x22));
    assert_eq!(
        put(&app, Some(NS), &k1, b"already here").await,
        StatusCode::OK
    );
    assert_eq!(
        put_batch(
            &app,
            vec![
                (NS.as_bytes().to_vec(), [0x21; 32], b"half one".to_vec()),
                (NS.as_bytes().to_vec(), [0x22; 32], b"half two".to_vec()),
            ],
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        get(&app, &k1).await.1,
        vec![b"already here".to_vec(), b"half one".to_vec()]
    );
    assert_eq!(get(&app, &k2).await.1, vec![b"half two".to_vec()]);

    // A batch with an entry that names no cell is refused whole: the shape
    // is checked before anything is written.
    let (k3, k4) = (key(0x23), key(0x24));
    assert_eq!(
        put_batch(
            &app,
            vec![
                (
                    NS.as_bytes().to_vec(),
                    [0x23; 32],
                    b"would be held".to_vec()
                ),
                (
                    b"not a namespace".to_vec(),
                    [0x24; 32],
                    b"names no cell".to_vec()
                ),
            ],
        )
        .await,
        StatusCode::BAD_REQUEST
    );
    assert!(get(&app, &k3).await.1.is_empty(), "none, not one");
    assert!(get(&app, &k4).await.1.is_empty());
}

#[tokio::test]
async fn a_second_value_at_a_key_is_kept_after_the_first_never_refused() {
    let app = member("cells_a_second_value_at_a_key_is_kept_after_the_fi").await;
    let k = key(0x01);
    assert_eq!(put(&app, Some(NS), &k, b"first").await, StatusCode::OK);
    assert_eq!(
        put(&app, Some(NS), &k, b"second, different").await,
        StatusCode::OK,
        "a contested key is not a refusal"
    );
    let (status, values) = get(&app, &k).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        values,
        vec![b"first".to_vec(), b"second, different".to_vec()],
        "both values, in arrival order"
    );
}

/// Identical bytes twice are two arrivals. The member does not compare.
#[tokio::test]
async fn an_identical_value_put_twice_is_held_twice() {
    let app = member("cells_an_identical_value_put_twice_is_held_twice").await;
    let k = key(0x02);
    put(&app, Some(NS), &k, b"same").await;
    put(&app, Some(NS), &k, b"same").await;
    let (_, values) = get(&app, &k).await;
    assert_eq!(values, vec![b"same".to_vec(), b"same".to_vec()]);
}

/// Absence is asserted by shape, not by status: an empty list under `200`.
#[tokio::test]
async fn a_key_nothing_was_put_under_reads_as_an_empty_list_with_200() {
    let app = member("cells_a_key_nothing_was_put_under_reads_as_an_empt").await;
    let (status, values) = get(&app, &key(0x5E)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(values.is_empty());
}

/// The namespace scopes the key: the same key under another namespace is
/// another cell.
#[tokio::test]
async fn a_namespace_scopes_the_key() {
    let app = member("cells_a_namespace_scopes_the_key").await;
    let k = key(0x03);
    put(&app, Some(NS), &k, b"in NS").await;
    put(&app, Some("DSM/other"), &k, b"in other").await;
    let (_, values) = get(&app, &k).await;
    assert_eq!(values, vec![b"in NS".to_vec()]);
}

/// An index is append-only and pages from the last `seq`.
#[tokio::test]
async fn an_index_pages_in_append_order_from_the_last_seq() {
    let app = member("cells_an_index_pages_in_append_order_from_the_last").await;
    let loc = key(0x10);
    let addrs = [
        held(&app, b"first").await,
        held(&app, b"second").await,
        held(&app, b"third").await,
    ];
    for a in &addrs {
        assert_eq!(append(&app, &loc, a).await, StatusCode::NO_CONTENT);
    }
    let first = page(&app, &loc, "?limit=2").await;
    assert_eq!(
        first.iter().map(|(_, a)| a.clone()).collect::<Vec<_>>(),
        vec![addrs[0].to_vec(), addrs[1].to_vec()]
    );
    let last_seq = first[1].0;
    let rest = page(&app, &loc, &format!("?after={last_seq}")).await;
    assert_eq!(
        rest.iter().map(|(_, a)| a.clone()).collect::<Vec<_>>(),
        vec![addrs[2].to_vec()]
    );
    let none = page(&app, &loc, &format!("?after={}", rest[0].0)).await;
    assert!(
        none.is_empty(),
        "past the end is an empty page, not an error"
    );
}

/// Storage spec §7: anyone may append the address of an object the member
/// already holds. An address it holds no object at is not appended, and the
/// index reads as it did; once the member holds the object, the same address
/// is appended. Taking every address, a member's index carried appends of
/// objects nobody held, and a reader had to decide each one.
/// MUTATION CONTROL: dropping the holds check turns this red.
#[tokio::test]
async fn an_address_the_member_holds_no_object_at_is_not_appended() {
    let app = member("cells_an_address_the_member_holds_no_object_at").await;
    let loc = key(0x12);
    let addrs = |entries: Vec<(i64, Vec<u8>)>| -> Vec<Vec<u8>> {
        entries.into_iter().map(|(_, a)| a).collect()
    };
    let first = held(&app, b"held").await;
    assert_eq!(append(&app, &loc, &first).await, StatusCode::NO_CONTENT);
    // The address of an object another member holds, and this one does not.
    let elsewhere = member("cells_an_address_the_member_holds_no_object_else").await;
    let unheld = held(&elsewhere, b"not yet held").await;
    assert_eq!(
        append(&app, &loc, &unheld).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "no object is held at the address"
    );
    assert_eq!(
        addrs(page(&app, &loc, "").await),
        vec![first.to_vec()],
        "the index reads as it did"
    );
    assert_eq!(held(&app, b"not yet held").await, unheld);
    assert_eq!(append(&app, &loc, &unheld).await, StatusCode::NO_CONTENT);
    assert_eq!(
        addrs(page(&app, &loc, "").await),
        vec![first.to_vec(), unheld.to_vec()]
    );
}

/// The only refusals are bounds, and they are about the request's shape,
/// never its meaning.
#[tokio::test]
async fn only_malformed_requests_are_refused() {
    let app = member("cells_only_malformed_requests_are_refused").await;
    let k = key(0x04);
    assert_eq!(
        put(&app, Some(NS), &k, b"").await,
        StatusCode::BAD_REQUEST,
        "empty body"
    );
    assert_eq!(
        put(&app, None, &k, b"x").await,
        StatusCode::BAD_REQUEST,
        "no namespace"
    );
    assert_eq!(
        put(&app, Some("no-prefix"), &k, b"x").await,
        StatusCode::BAD_REQUEST,
        "namespace outside the hasher's contract"
    );
    assert_eq!(
        put(&app, Some(NS), "not-base32!!", b"x").await,
        StatusCode::BAD_REQUEST,
        "key is not a 32-byte digest"
    );
    assert_eq!(
        append(&app, &key(0x11), b"short").await,
        StatusCode::BAD_REQUEST,
        "an index entry is exactly 32 bytes"
    );
}

/// A put answers with the entry's arrival record, and a get returns every
/// value's record beside it; both are the verifier's replay (storage spec §14).
#[tokio::test]
async fn a_put_answers_with_the_arrival_record_a_verifier_replays() {
    let app = member("cells_a_put_answers_with_the_arrival_record_a_veri").await;
    let k = key(0x41);
    let mut returned = Vec::new();
    for v in [b"one".as_slice(), b"two"] {
        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v2/cell/{k}"))
            .header("x-namespace", NS)
            .body(Body::from(v.to_vec()))
            .expect("request");
        let resp = app.clone().oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body");
        let rec = dsm::types::proto::ArrivalRecordV1::decode(body.as_ref()).expect("record");
        returned.push(dsm::storage_cell::ArrivalRecord::from_proto(&rec).expect("well formed"));
    }
    let values = vec![b"one".to_vec(), b"two".to_vec()];
    let replay = dsm::storage_cell::replay(NS.as_bytes(), &[0x41; 32], &values);
    for (rec, (i, h)) in returned.iter().zip(&replay) {
        assert_eq!((rec.index, rec.running_hash), (*i, *h));
        assert_eq!(rec.key, [0x41; 32]);
        assert_eq!(rec.namespace, NS.as_bytes());
        assert!(rec.agrees_with(&values));
    }

    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v2/cell/{k}"))
        .header("x-namespace", NS)
        .body(Body::empty())
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    let page = dsm::types::proto::CellValuesV1::decode(body.as_ref()).expect("page");
    assert_eq!(page.values, values);
    let got: Vec<_> = page
        .records
        .iter()
        .map(|r| dsm::storage_cell::ArrivalRecord::from_proto(r).expect("well formed"))
        .collect();
    assert_eq!(got, returned, "get reports what put returned");
}

/// A cell takes a value up to Core's largest route entry and refuses one
/// byte more, alone and in a batch, and holds nothing from a refused put. The
/// limit is `dsm::route_chain::MAX_ENTRY_BYTES`, so it moves with Core's
/// largest value (a SoFi exercise) and with nothing else. Both values are
/// well under the request body limit, so the refusal is the cell's own.
#[tokio::test]
async fn a_cell_takes_the_largest_route_entry_and_refuses_a_byte_more() {
    let app = member("cells_value_cap").await;
    let at_cap = vec![0xC5u8; dsm::route_chain::MAX_ENTRY_BYTES];
    let over = vec![0xC5u8; dsm::route_chain::MAX_ENTRY_BYTES + 1];

    assert_eq!(
        put(&app, Some(NS), &key(0xC1), &over).await,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(get(&app, &key(0xC1)).await.1, Vec::<Vec<u8>>::new());
    let taken = put(&app, Some(NS), &key(0xC1), &at_cap).await;
    assert!(
        taken.is_success(),
        "a value at the limit was refused: {taken}"
    );
    assert_eq!(get(&app, &key(0xC1)).await.1, vec![at_cap.clone()]);

    let one = |value: &[u8]| vec![(NS.as_bytes().to_vec(), [0xC2u8; 32], value.to_vec())];
    assert_eq!(
        put_batch(&app, one(&over)).await,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(get(&app, &key(0xC2)).await.1, Vec::<Vec<u8>>::new());
    let taken = put_batch(&app, one(&at_cap)).await;
    assert!(
        taken.is_success(),
        "a batched value at the limit was refused: {taken}"
    );
    assert_eq!(get(&app, &key(0xC2)).await.1, vec![at_cap]);
}

/// One page of a cell read from arrival index `from`: the status, the values,
/// their records' arrival indexes and where the next page starts.
async fn get_page(
    app: &Router,
    key: &str,
    query: &str,
) -> (StatusCode, Vec<Vec<u8>>, Vec<u64>, u64) {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v2/cell/{key}{query}"))
        .header("x-namespace", NS)
        .body(Body::empty())
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    if status != StatusCode::OK {
        return (status, Vec::new(), Vec::new(), 0);
    }
    let page = dsm::types::proto::CellValuesV1::decode(body.as_ref()).expect("CellValuesV1");
    let indexes = page.records.iter().map(|r| r.index).collect();
    (status, page.values, indexes, page.next)
}

/// A cell is read a page at a time (storage spec §6): from the arrival index
/// the read names, at most the cell-value cap of value bytes and
/// MAX_CELL_PAGE_ENTRIES entries, each page naming where the next starts and
/// the last naming none. Reading every page returns everything held, in
/// arrival order, and a read past the last entry is an empty page.
#[tokio::test]
async fn a_cell_is_read_a_page_at_a_time() {
    use dsm::storage_cell::{CELL_PAGE_VALUE_BYTES, MAX_CELL_PAGE_ENTRIES};
    let app = member("cells_paged").await;

    // Three values, any two of which pass the cap: one to a page.
    let large = key(0x71);
    let big: Vec<Vec<u8>> = (0..3u8)
        .map(|i| vec![i; CELL_PAGE_VALUE_BYTES * 2 / 3])
        .collect();
    for value in &big {
        assert_eq!(put(&app, Some(NS), &large, value).await, StatusCode::OK);
    }
    for (from, next) in [(1u64, 2u64), (2, 3), (3, 0)] {
        let (status, values, indexes, at) = get_page(&app, &large, &format!("?from={from}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            values,
            vec![big[usize::try_from(from - 1).expect("index")].clone()]
        );
        assert_eq!(indexes, vec![from]);
        assert_eq!(at, next, "the page from {from} names where the next starts");
    }

    // More small values than a page holds: a full page, then the rest.
    let many = key(0x72);
    let count = MAX_CELL_PAGE_ENTRIES + 10;
    let small: Vec<Vec<u8>> = (0..count)
        .map(|i| format!("entry {i}").into_bytes())
        .collect();
    let ns = NS.as_bytes().to_vec();
    let raw_key = [0x72u8; 32];
    for chunk in small.chunks(16) {
        let batch = chunk
            .iter()
            .map(|v| (ns.clone(), raw_key, v.clone()))
            .collect();
        assert_eq!(put_batch(&app, batch).await, StatusCode::OK);
    }
    let (status, first, first_indexes, next) = get_page(&app, &many, "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first, small[..MAX_CELL_PAGE_ENTRIES].to_vec());
    let expected: Vec<u64> = (1..=u64::try_from(MAX_CELL_PAGE_ENTRIES).expect("entries")).collect();
    assert_eq!(first_indexes, expected);
    assert_eq!(
        next,
        u64::try_from(MAX_CELL_PAGE_ENTRIES + 1).expect("index")
    );
    let (_, rest, _, after) = get_page(&app, &many, &format!("?from={next}")).await;
    assert_eq!(rest, small[MAX_CELL_PAGE_ENTRIES..].to_vec());
    assert_eq!(after, 0, "the last page names no next page");

    // Past the last entry: an empty page that names none.
    let (status, none, _, past) = get_page(&app, &many, "?from=10000").await;
    assert_eq!(status, StatusCode::OK);
    assert!(none.is_empty());
    assert_eq!(past, 0);

    // An arrival index starts at 1, and a read names nothing else.
    for query in ["?from=0", "?from=first", "?after=3", "?from=2&limit=9"] {
        assert_eq!(
            get_page(&app, &many, query).await.0,
            StatusCode::BAD_REQUEST,
            "{query}"
        );
    }
}
