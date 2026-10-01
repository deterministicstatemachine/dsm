// SPDX-License-Identifier: MIT OR Apache-2.0
//! POSITIVE CONTROL for the demolition: the surviving immutable store still
//! does the one thing a member does with an object — take bytes, return the
//! same bytes. Driven through the routers the binary serves, on a Postgres
//! database of its own per test.
//!
//! The node computes the address from the bytes and interprets nothing. A
//! read recomputes the address from the stored tuple and refuses to serve a
//! row that no longer hashes to its own key. Neither side decodes the payload,
//! so the payload here is deliberately arbitrary: not a protocol object.

#![allow(clippy::disallowed_methods)]

mod common;

use std::sync::Arc;

use axum::{body::Body, http::Request, http::StatusCode, Router};
use dsm::utils::text_id;
use dsm_storage_node::AppState;
use tower::ServiceExt;

/// One member on a fresh store named `store`.
async fn member(store: &str) -> Router {
    let pool = common::fresh_store(store).await;
    let state = Arc::new(common::ok_or_panic(
        AppState::new("member".to_string(), pool, common::set_client()),
        "app state",
    ));
    // The binary's own assembly: what this suite drives is what is served.
    common::served(state)
}

async fn put(app: &Router, namespace: &str, bytes: &[u8]) -> (StatusCode, String) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v2/immutable/put")
        .header("x-namespace", namespace)
        .body(Body::from(bytes.to_vec()))
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    (
        status,
        String::from_utf8(body.to_vec()).expect("address is text"),
    )
}

async fn get(app: &Router, addr: &str) -> (StatusCode, Option<String>, Vec<u8>) {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v2/immutable/{addr}"))
        .body(Body::empty())
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let ns = resp
        .headers()
        .get("x-namespace")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, ns, body.to_vec())
}

/// Bytes in, the same bytes out, under the address the node derived from
/// them — and that address is exactly the registry's content address, so a
/// reader that recomputes it from the returned bytes lands on the same key.
#[tokio::test]
async fn bytes_put_into_the_immutable_store_come_back_byte_identical() {
    let app = member("immutable_round_trip").await;
    let payload: Vec<u8> = (0u8..=255).cycle().take(3_001).collect();
    let namespace = "DSM/demolition-positive-control";

    let (status, addr) = put(&app, namespace, &payload).await;
    assert_eq!(status, StatusCode::CREATED, "first put stores");

    let expected = dsm::storage_object::immutable_addr(
        dsm::crypto::domain::TaggedHashDomain::try_new(namespace.as_bytes()).expect("tag"),
        &payload,
    );
    assert_eq!(
        addr,
        text_id::encode_base32_crockford(&expected),
        "the node's address is the registry's content address of the bytes"
    );

    let (status, ns, got) = get(&app, &addr).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        ns.as_deref(),
        Some(namespace),
        "the namespace comes back with the bytes"
    );
    assert_eq!(got, payload, "byte identical");
}

/// Storing the same bytes again is an ack, not a conflict, and changes
/// nothing about what a reader gets.
#[tokio::test]
async fn re_putting_identical_bytes_acks_and_the_read_is_unchanged() {
    let app = member("immutable_re_put").await;
    let payload = b"the same object, twice".to_vec();
    let namespace = "DSM/demolition-positive-control";

    let (first, addr) = put(&app, namespace, &payload).await;
    assert_eq!(first, StatusCode::CREATED);
    let (again, addr_again) = put(&app, namespace, &payload).await;
    assert_eq!(again, StatusCode::OK, "identical bytes re-put is an ack");
    assert_eq!(addr, addr_again);

    let (status, _, got) = get(&app, &addr).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(got, payload);
}

/// R2: no write authorization anywhere. The put carries no `authorization`
/// header and no device token exists, and the member takes the bytes — on
/// the assembly the binary serves. MUTATION CONTROL: any writer check added
/// to the write router in `storage_contract_router` turns this test red.
#[tokio::test]
async fn a_put_with_no_authorization_is_taken_on_the_served_assembly() {
    let app = member("immutable_no_authorization").await;
    let (status, addr) = put(
        &app,
        "DSM/demolition-positive-control",
        b"unauthorized bytes",
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "no token, no header, taken");
    let (status, _, got) = get(&app, &addr).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(got, b"unauthorized bytes");
}

/// An address nothing was put under is absent, not invented.
#[tokio::test]
async fn an_unknown_address_is_not_found() {
    let app = member("immutable_unknown_address").await;
    let never = text_id::encode_base32_crockford(&[0x5Eu8; 32]);
    let (status, _, got) = get(&app, &never).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(got.is_empty());
}

/// One member on a fresh store named `store`, and that store, so a test can
/// reach the rows the member keeps.
async fn member_and_store(store: &str) -> (Router, Arc<dsm_storage_node::db::DBPool>) {
    let pool = common::fresh_store(store).await;
    let state = Arc::new(common::ok_or_panic(
        AppState::new("member".to_string(), pool.clone(), common::set_client()),
        "app state",
    ));
    (common::served(state), pool)
}

/// A put that states the address its caller computed, as `x-expected-addr`.
async fn put_stating(app: &Router, namespace: &str, bytes: &[u8], stated: &str) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v2/immutable/put")
        .header("x-namespace", namespace)
        .header("x-expected-addr", stated)
        .body(Body::from(bytes.to_vec()))
        .expect("request");
    app.clone().oneshot(req).await.expect("oneshot").status()
}

/// The content address of `bytes` in `namespace`, as the registry derives it.
fn address_of(namespace: &str, bytes: &[u8]) -> String {
    text_id::encode_base32_crockford(&dsm::storage_object::immutable_addr(
        dsm::crypto::domain::TaggedHashDomain::try_new(namespace.as_bytes()).expect("tag"),
        bytes,
    ))
}

/// Storage spec §5 rules 1 and 2: the node computes the address, and a
/// caller-supplied address is a check, never the key. A put that states the
/// address of other bytes is refused, and the refused bytes are held under
/// neither address. The same bytes stating their own address are stored at
/// it. MUTATION CONTROL: dropping the comparison in `put_immutable` stores
/// the bytes and turns this test red.
#[tokio::test]
async fn a_put_stating_another_address_is_refused_and_nothing_is_held() {
    let app = member("immutable_stated_address").await;
    let namespace = "DSM/stated-address-check";
    let payload = b"the bytes this put carries".to_vec();
    let computed = address_of(namespace, &payload);
    let stated = address_of(namespace, b"other bytes entirely");
    assert_ne!(computed, stated);

    assert_eq!(
        put_stating(&app, namespace, &payload, &stated).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "an address the node did not compute is refused"
    );
    for addr in [&computed, &stated] {
        let (status, _, got) = get(&app, addr).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "nothing is held at {addr}");
        assert!(got.is_empty());
    }

    assert_eq!(
        put_stating(&app, namespace, &payload, &computed).await,
        StatusCode::CREATED,
        "its own address is taken"
    );
    let (status, _, got) = get(&app, &computed).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(got, payload);
}

/// Storage spec §5 rule 5 and §3 rule 5: on read the node recomputes the
/// address from what it holds before serving, and a store outside the fault
/// model fails closed. Rows damaged in place are never served: one whose
/// payload changed, one whose namespace became another namespace, and one
/// whose namespace is no longer a namespace at all. An undamaged object
/// beside them still is. MUTATION CONTROL: dropping the recomputation in
/// `get_immutable` serves the first two and turns this test red.
#[tokio::test]
async fn a_held_object_that_no_longer_hashes_to_its_address_is_not_served() {
    let (app, store) = member_and_store("immutable_damaged_row").await;
    let namespace = "DSM/hash-on-read";
    let damage: [(&str, &[u8]); 3] = [
        ("payload", b"other bytes"),
        ("namespace", b"DSM/another-namespace"),
        ("namespace", b"no longer a namespace"),
    ];
    let client = common::ok_or_panic(store.get().await, "store connection");
    let mut damaged = Vec::new();
    for (n, (column, value)) in damage.iter().enumerate() {
        let (status, addr) = put(&app, namespace, format!("object {n}").as_bytes()).await;
        assert_eq!(status, StatusCode::CREATED);
        let changed = common::ok_or_panic(
            client
                .execute(
                    &format!("UPDATE immutable_objects SET {column} = $1 WHERE addr_b32 = $2"),
                    &[value, &addr],
                )
                .await,
            "damage the row",
        );
        assert_eq!(changed, 1, "one row damaged at {addr}");
        damaged.push(addr);
    }
    let intact = b"an object nobody damaged".to_vec();
    let (status, intact_addr) = put(&app, namespace, &intact).await;
    assert_eq!(status, StatusCode::CREATED);

    for addr in &damaged {
        let (status, ns, got) = get(&app, addr).await;
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "a row that no longer hashes to {addr} is not served"
        );
        assert_eq!(ns, None, "no namespace is served for it");
        assert!(got.is_empty(), "no bytes are served for it");
    }
    let (status, _, got) = get(&app, &intact_addr).await;
    assert_eq!(status, StatusCode::OK, "the intact object is still served");
    assert_eq!(got, intact);
}

/// Storage spec §5 rule 4: replaying identical bytes re-acknowledges, and
/// different bytes at the same address are reported as corruption. With the
/// row at an address damaged in place, the object's own bytes put again meet
/// a different tuple there: the node reports it, and the held row is left
/// exactly as it was. MUTATION CONTROL: answering the conflict as an ack in
/// `put_immutable` turns this test red.
#[tokio::test]
async fn different_bytes_at_an_address_are_reported_as_corruption() {
    let (app, store) = member_and_store("immutable_conflict_reported").await;
    let namespace = "DSM/conflict-reported";
    let payload = b"the object as it was put".to_vec();
    let (status, addr) = put(&app, namespace, &payload).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = put(&app, namespace, &payload).await;
    assert_eq!(status, StatusCode::OK, "an identical replay is an ack");

    let damaged = b"the bytes a failing disk left".to_vec();
    let client = common::ok_or_panic(store.get().await, "store connection");
    let changed = common::ok_or_panic(
        client
            .execute(
                "UPDATE immutable_objects SET payload = $1 WHERE addr_b32 = $2",
                &[&damaged, &addr],
            )
            .await,
        "damage the row",
    );
    assert_eq!(changed, 1);

    let (status, _) = put(&app, namespace, &payload).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a different tuple at the address is reported, never acknowledged"
    );
    let held = common::ok_or_panic(
        dsm_storage_node::db::get_immutable_object(&store, &addr).await,
        "read the row",
    );
    assert_eq!(
        held,
        Some((namespace.as_bytes().to_vec(), damaged)),
        "the held row is left as it was"
    );
}

/// Puts made at one member at once never refuse each other. Three rounds of
/// sixty-four different objects, each round put all at once, are each taken;
/// and sixteen puts of one object at once are each acknowledged, under the
/// one address. A serializable put refused some of a concurrent burst with a
/// 500 (a serialization failure) though no two of them touched the same
/// address, so a device's write could fail for having run beside another's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn puts_made_at_once_are_each_taken() {
    let app = member("immutable_concurrent").await;
    for round in 0..3u8 {
        let objects: Vec<[u8; 3]> = (0..64u8).map(|i| [round, i, 0x5A]).collect();
        let answers = futures::future::join_all(
            objects
                .iter()
                .map(|object| put(&app, "DSM/test/concurrent", object)),
        )
        .await;
        let refused: Vec<StatusCode> = answers
            .iter()
            .map(|(status, _)| *status)
            .filter(|status| !status.is_success())
            .collect();
        assert_eq!(
            refused,
            Vec::<StatusCode>::new(),
            "round {round}: distinct puts refused while others ran"
        );
    }

    let answers = futures::future::join_all(
        (0..16).map(|_| put(&app, "DSM/test/concurrent", b"one object put at once")),
    )
    .await;
    let first = answers[0].1.clone();
    for (status, addr) in &answers {
        assert!(status.is_success(), "an identical put was refused: {status}");
        assert_eq!(addr, &first, "every identical put names the one address");
    }
}
