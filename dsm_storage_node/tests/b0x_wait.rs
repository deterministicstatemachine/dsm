// SPDX-License-Identifier: Apache-2.0
//! A device's wait on its spools (storage spec §8, long-poll), on the app the
//! binary serves: answered at once when an entry is already past its mark,
//! answered when one lands, never by an entry in a spool it does not name,
//! answered `204` once its bound passes with nothing landed, and refused when
//! it is not a wait.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use dsm_storage_node::{build_app, AppLimits, AppState};
use prost::Message;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

/// The node's app over a fresh store named `store`, its waits held for at
/// most `wait_bound`.
async fn node(store: &str, wait_bound: Duration) -> axum::Router {
    let pool = common::fresh_store(store).await;
    let state = Arc::new(common::ok_or_panic(
        AppState::new("member".to_string(), pool, common::set_client()),
        "app state",
    ));
    build_app(
        state,
        AppLimits {
            body_limit_bytes: 1_048_576,
            concurrency_limit: 256,
            request_timeout: Duration::from_secs(60),
            wait_bound,
        },
    )
}

fn spool_key(byte: u8) -> String {
    dsm::utils::text_id::encode_base32_crockford(&[byte; 32])
}

/// Submit `body` to the spool at `key`.
async fn submit(app: &axum::Router, key: &str, body: &[u8]) {
    let request = common::ok_or_panic(
        Request::builder()
            .method("POST")
            .uri("/api/v2/b0x/submit")
            .header("content-type", "application/octet-stream")
            .header("x-dsm-recipient", key)
            .body(Body::from(body.to_vec())),
        "request",
    );
    let answer = common::ok_or_panic(app.clone().oneshot(request).await, "the app answers");
    assert_eq!(answer.status(), StatusCode::NO_CONTENT);
}

/// The answer to a wait on `marks`, sent as `content_type`: its status, and
/// the spools it names when it names any.
async fn wait_on(
    app: &axum::Router,
    marks: &[(&str, u64)],
    content_type: &str,
) -> (StatusCode, Vec<String>) {
    let request = dsm::types::proto::B0xWaitRequest {
        marks: marks
            .iter()
            .map(|(address, from_seq)| dsm::types::proto::B0xWaitMark {
                address: address.to_string(),
                from_seq: *from_seq,
            })
            .collect(),
    };
    let request = common::ok_or_panic(
        Request::builder()
            .method("POST")
            .uri("/api/v2/b0x/wait")
            .header("content-type", content_type)
            .body(Body::from(request.encode_to_vec())),
        "request",
    );
    let answer = common::ok_or_panic(app.clone().oneshot(request).await, "the app answers");
    let status = answer.status();
    let body = common::ok_or_panic(
        axum::body::to_bytes(answer.into_body(), usize::MAX).await,
        "body",
    );
    if status != StatusCode::OK {
        return (status, Vec::new());
    }
    let ready = common::ok_or_panic(
        dsm::types::proto::B0xWaitResponse::decode(body.as_ref()),
        "a wait answer",
    );
    (status, ready.ready)
}

/// A wait on a spool that already holds an entry at or after its mark is
/// answered at once with that spool. A mark past the last entry is not met:
/// that wait is held to its bound and answered `204`.
#[test]
fn a_wait_is_answered_at_once_for_an_entry_already_past_its_mark() {
    common::runtime().block_on(async {
        let app = node("wait_at_once", Duration::from_millis(600)).await;
        let key = spool_key(0x71);
        submit(&app, &key, &[0x0A, 0x01]).await;

        let started = std::time::Instant::now();
        assert_eq!(
            wait_on(&app, &[(key.as_str(), 1)], "application/octet-stream").await,
            (StatusCode::OK, vec![key.clone()])
        );
        assert!(
            started.elapsed() < Duration::from_millis(600),
            "a wait whose spool already held an entry was held"
        );

        let started = std::time::Instant::now();
        assert_eq!(
            wait_on(&app, &[(key.as_str(), 2)], "application/octet-stream").await,
            (StatusCode::NO_CONTENT, Vec::new())
        );
        assert!(
            started.elapsed() >= Duration::from_millis(600),
            "a wait whose mark was past every entry ended before its bound"
        );
    });
}

/// A wait held on an empty spool is answered when an entry lands there, with
/// that spool, long before its bound. An entry landing in a spool the wait
/// does not name wakes nothing.
#[test]
fn a_held_wait_is_answered_when_an_entry_lands_in_its_spool() {
    common::runtime().block_on(async {
        let app = node("wait_wakes", Duration::from_secs(20)).await;
        let watched = spool_key(0x72);
        let elsewhere = spool_key(0x73);
        let started = std::time::Instant::now();
        let waiting = {
            let (app, watched) = (app.clone(), watched.clone());
            tokio::spawn(async move {
                wait_on(&app, &[(watched.as_str(), 1)], "application/octet-stream").await
            })
        };
        tokio::time::sleep(Duration::from_millis(300)).await;
        submit(&app, &elsewhere, &[0x0A, 0x02]).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !waiting.is_finished(),
            "an entry in a spool the wait does not name answered it"
        );

        submit(&app, &watched, &[0x0A, 0x03]).await;
        let answer = match tokio::time::timeout(Duration::from_secs(10), waiting).await {
            Ok(joined) => common::ok_or_panic(joined, "the waiting task"),
            Err(elapsed) => {
                panic!("the wait was not answered when its spool took an entry: {elapsed}")
            }
        };
        assert_eq!(answer, (StatusCode::OK, vec![watched]));
        assert!(started.elapsed() < Duration::from_secs(10));
    });
}

/// A wait names one spool or more, each under a key a spool can have, at a
/// position a spool can hold, and no more spools than the node holds a wait
/// for; it is protobuf. Anything else is refused before it is held.
#[test]
fn a_wait_that_is_not_one_is_refused() {
    common::runtime().block_on(async {
        let app = node("wait_refused", Duration::from_secs(20)).await;
        let key = spool_key(0x74);
        let protobuf = "application/octet-stream";
        assert_eq!(
            wait_on(&app, &[], protobuf).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            wait_on(&app, &[("b0x[TEST]", 1)], protobuf).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            wait_on(&app, &[(key.as_str(), u64::MAX)], protobuf).await.0,
            StatusCode::BAD_REQUEST
        );
        let too_many: Vec<(&str, u64)> = (0
            ..=dsm_storage_node::api::transport::b0x::MAX_WAIT_MARKS)
            .map(|_| (key.as_str(), 1))
            .collect();
        assert_eq!(
            wait_on(&app, &too_many, protobuf).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            wait_on(&app, &[(key.as_str(), 1)], "text/plain").await.0,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    });
}
