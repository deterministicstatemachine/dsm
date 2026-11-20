// SPDX-License-Identifier: MIT OR Apache-2.0
//! Cells a person pays for are theirs (owner ruling, 2026-11-19), executed
//! against the served assembly.
//!
//! An owned cell's address is its route bound to the owner's cell lock, and a
//! member keeps a write there only when that lock signed it
//! (`dsm::owned_cell`). A device's directory cell is bound to its device id,
//! and only its AK writes it. A cell several parties write by protocol still
//! takes a write with no proof.

mod common;

use std::sync::Arc;

use axum::{body::Body, http::Request, http::StatusCode, Router};
use dsm::crypto::sphincs::{generate_keypair_from_seed, SphincsKeyPair};
use dsm::owned_cell::{sign_directory_cell_write, sign_owned_cell_write, CELL_LOCK_VARIANT};
use dsm::utils::text_id;
use dsm_storage_node::AppState;
use prost::Message;
use tower::ServiceExt;

/// `result`'s value, or a panic naming `context`.
fn ok<T, E: std::fmt::Debug>(result: Result<T, E>, context: &str) -> T {
    common::ok_or_panic(result, context)
}

async fn member(store: &str) -> Router {
    let pool = common::fresh_store(store).await;
    let state = Arc::new(ok(AppState::new("member".to_string(), pool), "app state"));
    common::served(state)
}

fn key_pair(seed: u8) -> SphincsKeyPair {
    ok(
        generate_keypair_from_seed(CELL_LOCK_VARIANT, &[seed; 32]),
        "a key",
    )
}

async fn status(app: &Router, req: Request<Body>) -> StatusCode {
    ok(app.clone().oneshot(req).await, "oneshot").status()
}

/// One batch put of `value` at `key` in `namespace` with `proof`.
async fn put_one(
    app: &Router,
    namespace: &[u8],
    key: [u8; 32],
    value: &[u8],
    proof: &[u8],
) -> StatusCode {
    let batch = dsm::types::proto::CellPutsV1 {
        entries: vec![dsm::types::proto::CellPutV1 {
            namespace: namespace.to_vec(),
            key: key.to_vec(),
            value: value.to_vec(),
            owner_proof: proof.to_vec(),
        }],
    };
    let req = ok(
        Request::builder()
            .method("POST")
            .uri("/api/v2/cells")
            .body(Body::from(batch.encode_to_vec())),
        "request",
    );
    status(app, req).await
}

/// A single put, which carries no owner's proof.
async fn put_single(app: &Router, namespace: &str, key: [u8; 32], value: &[u8]) -> StatusCode {
    let req = ok(
        Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v2/cell/{}",
                text_id::encode_base32_crockford(&key)
            ))
            .header("x-namespace", namespace)
            .body(Body::from(value.to_vec())),
        "request",
    );
    status(app, req).await
}

/// How many values the member holds at `key` in `namespace`.
async fn held(app: &Router, namespace: &str, key: [u8; 32]) -> usize {
    let req = ok(
        Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v2/cell/{}",
                text_id::encode_base32_crockford(&key)
            ))
            .header("x-namespace", namespace)
            .body(Body::empty()),
        "request",
    );
    let resp = ok(app.clone().oneshot(req).await, "oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = ok(
        axum::body::to_bytes(resp.into_body(), usize::MAX).await,
        "body",
    );
    ok(
        dsm::types::proto::CellValuesV1::decode(body.as_ref()),
        "CellValuesV1",
    )
    .values
    .len()
}

fn text(namespace: &[u8]) -> &str {
    ok(std::str::from_utf8(namespace), "an ASCII namespace")
}

/// The owner's write is kept; a stranger's write at the owner's address, the
/// owner's proof carried with another value, and a single put with no proof
/// are refused, and the cell holds the owner's write alone.
/// MUTATION CONTROL: taking an owned cell's write unchecked in
/// `dsm::owned_cell::admit_cell_write` turns every refusal here red.
#[test]
fn a_member_keeps_only_the_owners_write_in_an_owned_cell() {
    common::runtime().block_on(async {
        let app = member("owned_cells_only_the_owners_write").await;
        let ns = dsm::recovery::RecoveryCell::namespace();
        let (owner, stranger) = (key_pair(0x11), key_pair(0x22));
        let route = [0x7A; 32];

        let (address, proof) = ok(
            sign_owned_cell_write(ns, &route, &owner, b"the anchor"),
            "signed",
        );
        assert_eq!(
            put_one(&app, ns, address, b"the anchor", &proof).await,
            StatusCode::OK
        );

        let (_, foreign) = ok(
            sign_owned_cell_write(ns, &route, &stranger, b"a copy"),
            "signed",
        );
        assert_eq!(
            put_one(&app, ns, address, b"a copy", &foreign).await,
            StatusCode::FORBIDDEN,
            "a stranger's lock does not name the owner's cell"
        );
        // The attack itself: the stranger signs a write naming the owner's
        // address with its own lock; only the address check refuses it.
        let target = ok(
            dsm::owned_cell::owned_cell_write_target(ns, &address, b"a copy"),
            "a target",
        );
        let aimed = dsm::types::proto::OwnedCellWriteV1 {
            route: route.to_vec(),
            lock_public_key: stranger.public_key.clone(),
            write_signature: ok(
                dsm::crypto::sphincs::sphincs_sign(&stranger.secret_key, &target),
                "signed",
            ),
        }
        .encode_to_vec();
        assert_eq!(
            put_one(&app, ns, address, b"a copy", &aimed).await,
            StatusCode::FORBIDDEN,
            "a stranger's own signature over the owner's address"
        );
        assert_eq!(
            put_one(&app, ns, address, b"a copy", &proof).await,
            StatusCode::FORBIDDEN,
            "the owner's proof does not carry another value"
        );
        assert_eq!(
            put_single(&app, text(ns), address, b"a copy").await,
            StatusCode::FORBIDDEN,
            "a single put carries no owner's proof"
        );
        assert_eq!(
            held(&app, text(ns), address).await,
            1,
            "the owner's write alone"
        );
    });
}

/// A device writes its own directory cell; another device's AK cannot.
#[test]
fn a_member_keeps_only_the_devices_write_in_its_directory_cell() {
    common::runtime().block_on(async {
        let app = member("owned_cells_only_the_devices_directory_write").await;
        let ns = dsm::core::identity::directory::DIRECTORY_NAMESPACE;
        let (ak, other) = (key_pair(0x31), key_pair(0x32));
        let (genesis, att_a) = ([0x6E; 32], [0xA7; 32]);

        let (address, proof) = ok(
            sign_directory_cell_write(&genesis, &ak.public_key, &att_a, &ak.secret_key, b"entry"),
            "signed",
        );
        assert_eq!(
            put_one(&app, ns, address, b"entry", &proof).await,
            StatusCode::OK
        );

        let (_, by_other) = ok(
            sign_directory_cell_write(
                &genesis,
                &other.public_key,
                &att_a,
                &other.secret_key,
                b"junk",
            ),
            "signed",
        );
        assert_eq!(
            put_one(&app, ns, address, b"junk", &by_other).await,
            StatusCode::FORBIDDEN,
            "another device's AK does not name this device's cell"
        );
        assert_eq!(
            put_single(&app, text(ns), address, b"junk").await,
            StatusCode::FORBIDDEN,
            "a single put carries no proof"
        );
        assert_eq!(
            held(&app, text(ns), address).await,
            1,
            "the device's entry alone"
        );
    });
}

/// A cell several parties write by protocol takes a write with no proof, and
/// refuses one that carries a proof (it has one encoding, without).
#[test]
fn an_open_cell_takes_a_write_with_no_proof() {
    common::runtime().block_on(async {
        let app = member("owned_cells_an_open_cell").await;
        let ns = "DSM/open-cell-contract";
        assert_eq!(put_single(&app, ns, [0x41; 32], b"v").await, StatusCode::OK);
        assert_eq!(
            put_one(&app, ns.as_bytes(), [0x41; 32], b"w", &[]).await,
            StatusCode::OK
        );
        assert_eq!(
            put_one(&app, ns.as_bytes(), [0x41; 32], b"x", &[0x0A, 0x00]).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(held(&app, ns, [0x41; 32]).await, 2);
    });
}
