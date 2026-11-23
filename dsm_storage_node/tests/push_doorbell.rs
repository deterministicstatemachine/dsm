// SPDX-License-Identifier: Apache-2.0
//! Inbox doorbells on the app the binary serves, over Postgres, pushing
//! through the node's own outbound client to Google's push endpoints served
//! by the test on a local port over TLS (`common::google_push`): an entry
//! landing on a spool with a doorbell sends exactly one push, to that
//! doorbell's token and carrying nothing of the entry; one landing on a spool
//! with none sends nothing; and no device replaces or removes another's
//! doorbell.
//!
//! Pushes are sent one at a time, in the order arrivals rang them. A test
//! that must show a push was *not* sent rings a marker doorbell after it and
//! waits for the marker's push: anything rung before it went out before it.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::google_push::GooglePush;
use dsm_storage_node::api::transport::doorbell::Doorbells;
use dsm_storage_node::push::FcmSender;
use dsm_storage_node::{build_app, AppLimits, AppState};
use prost::Message;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

/// How long a push may take to reach the endpoints.
const PUSH_LIMIT: Duration = Duration::from_secs(20);

/// A node over a fresh store named `store`, pushing through `google`.
async fn node(store: &str, google: &GooglePush) -> (axum::Router, Arc<Doorbells>) {
    let pool = common::fresh_store(store).await;
    let sender = common::ok_or_panic(FcmSender::new(google.config()), "the push sender");
    let doorbells = Doorbells::start(sender);
    let state = Arc::new(
        common::ok_or_panic(AppState::new("member".to_string(), pool), "app state")
            .with_doorbells(doorbells.clone()),
    );
    (app(state), doorbells)
}

fn app(state: Arc<AppState>) -> axum::Router {
    build_app(
        state,
        AppLimits {
            body_limit_bytes: 1_048_576,
            concurrency_limit: 256,
            request_timeout: Duration::from_secs(60),
            wait_bound: Duration::from_secs(25),
        },
    )
}

async fn post(app: &axum::Router, path: &str, body: Vec<u8>) -> StatusCode {
    let request = common::ok_or_panic(
        Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/protobuf")
            .body(Body::from(body)),
        "request",
    );
    common::ok_or_panic(app.clone().oneshot(request).await, "the app answers").status()
}

/// Put up the doorbell `key` names: pushes to `push_token` for `spools`.
async fn ring_at(app: &axum::Router, key: [u8; 32], push_token: &str, spools: &[&str]) {
    let doorbell = dsm::types::proto::B0xDoorbell {
        key: key.to_vec(),
        push_token: push_token.to_string(),
        addresses: spools.iter().map(|s| s.to_string()).collect(),
    };
    assert_eq!(
        post(app, "/api/v2/b0x/doorbell", doorbell.encode_to_vec()).await,
        StatusCode::NO_CONTENT
    );
}

async fn take_down(app: &axum::Router, key: [u8; 32]) {
    let remove = dsm::types::proto::B0xDoorbellRemove { key: key.to_vec() };
    assert_eq!(
        post(app, "/api/v2/b0x/doorbell/remove", remove.encode_to_vec()).await,
        StatusCode::NO_CONTENT
    );
}

/// Submit one entry to the spool at `spool`.
async fn deliver(app: &axum::Router, spool: &str) {
    let (write, message_id) = common::signed_write(spool, b"sealed bytes the node never opens");
    let request = common::ok_or_panic(
        Request::builder()
            .method("POST")
            .uri("/api/v2/b0x/submit")
            .header("content-type", "application/octet-stream")
            .header("x-dsm-recipient", spool)
            .header("x-dsm-message-id", message_id)
            .body(Body::from(write)),
        "request",
    );
    let answer = common::ok_or_panic(app.clone().oneshot(request).await, "the app answers");
    assert_eq!(answer.status(), StatusCode::NO_CONTENT);
}

/// Ring a marker doorbell and wait for its push: every push rung before it
/// has gone out by then. The tokens pushed, in order.
async fn after_marker(app: &axum::Router, google: &GooglePush, marker: u8) -> Vec<String> {
    let spool = common::locked_spool(marker);
    let token = format!("marker-{marker}");
    ring_at(app, [marker; 32], &token, &[&spool]).await;
    deliver(app, &spool).await;
    let mut waited = Duration::ZERO;
    while !google.pushed_tokens().contains(&token) {
        assert!(waited < PUSH_LIMIT, "the marker's push never went out");
        tokio::time::sleep(Duration::from_millis(20)).await;
        waited += Duration::from_millis(20);
    }
    google.pushed_tokens()
}

/// An entry on a spool with a doorbell sends one push, to that doorbell's
/// token, naming nothing of the entry: no spool, no bytes. Exactly one: a
/// marker rung after it finds it the only push before its own.
/// MUTATION CONTROL: a submit that rings no doorbell, or rings twice, is red.
#[test]
fn a_delivery_on_a_registered_spool_sends_exactly_one_push() {
    common::runtime().block_on(async {
        let google = GooglePush::start().await;
        let (app, _doorbells) = node("doorbell_one_push", &google).await;
        let spool = common::locked_spool(0x31);
        ring_at(&app, [0x01; 32], "phone-1", &[&spool]).await;

        deliver(&app, &spool).await;
        let pushes = google.until_pushes(1, PUSH_LIMIT).await;
        assert_eq!(pushes.len(), 1, "one delivery, one push");
        assert_eq!(pushes[0].push_token, "phone-1");
        let sent = pushes[0].message.to_string();
        assert!(!sent.contains(&spool), "the push names the spool: {sent}");
        assert!(
            !sent.contains("sealed"),
            "the push carries the entry: {sent}"
        );
        assert_eq!(pushes[0].message["data"]["dsm"], "inbox");
        assert_eq!(
            pushes[0].message["data"].as_object().map(|data| data.len()),
            Some(1),
            "the push carries more than its one constant entry"
        );
        assert_eq!(pushes[0].message["android"]["priority"], "HIGH");

        assert_eq!(
            after_marker(&app, &google, 0x7E).await,
            vec!["phone-1".to_string(), "marker-126".to_string()]
        );
        assert_eq!(
            google.exchanges(),
            1,
            "the access token is kept between pushes"
        );
    });
}

/// An entry on a spool no doorbell watches sends no push, though another
/// spool has a doorbell.
/// MUTATION CONTROL: ringing every doorbell on any arrival is red.
#[test]
fn a_delivery_on_a_spool_with_no_doorbell_sends_none() {
    common::runtime().block_on(async {
        let google = GooglePush::start().await;
        let (app, _doorbells) = node("doorbell_none", &google).await;
        let watched = common::locked_spool(0x41);
        let unwatched = common::locked_spool(0x42);
        ring_at(&app, [0x02; 32], "phone-2", &[&watched]).await;

        deliver(&app, &unwatched).await;
        assert_eq!(
            after_marker(&app, &google, 0x7D).await,
            vec!["marker-125".to_string()],
            "an entry on a spool with no doorbell was pushed"
        );
    });
}

/// A doorbell is changed only under its own key. Another device asking to
/// take it down, under its key, takes nothing down; another device
/// registering on the same spool puts up a doorbell of its own beside it and
/// replaces nothing. The first device's doorbell stands, with its own token,
/// and rings; taken down under its own key, it rings no more.
/// MUTATION CONTROL: a doorbell named by its spool instead of its key, or a
/// removal that ignores the key, is red.
#[test]
fn one_device_cannot_replace_or_remove_another_devices_doorbell() {
    common::runtime().block_on(async {
        let google = GooglePush::start().await;
        let (app, doorbells) = node("doorbell_owned", &google).await;
        let spool = common::locked_spool(0x51);
        let mine = [0x0A; 32];
        let theirs = [0x0B; 32];
        ring_at(&app, mine, "phone-mine", &[&spool]).await;

        take_down(&app, theirs).await;
        ring_at(&app, theirs, "phone-theirs", &[&spool]).await;
        assert_eq!(
            doorbells.registered(&mine),
            Some(("phone-mine".to_string(), vec![spool.clone()])),
            "another device's registration changed this one"
        );

        deliver(&app, &spool).await;
        let mut pushed = google
            .until_pushes(2, PUSH_LIMIT)
            .await
            .into_iter()
            .map(|p| p.push_token)
            .collect::<Vec<_>>();
        pushed.sort();
        assert_eq!(
            pushed,
            vec!["phone-mine".to_string(), "phone-theirs".to_string()]
        );

        take_down(&app, mine).await;
        assert_eq!(doorbells.registered(&mine), None);
        deliver(&app, &spool).await;
        let tokens = after_marker(&app, &google, 0x7C).await;
        assert_eq!(
            tokens[2..].to_vec(),
            vec!["phone-theirs".to_string(), "marker-124".to_string()],
            "a doorbell taken down under its own key still rang"
        );
    });
}

/// An access token Firebase refuses is made again, once, for the same push.
#[test]
fn a_refused_access_token_is_made_again_for_the_push() {
    common::runtime().block_on(async {
        let google = GooglePush::start().await;
        let (app, _doorbells) = node("doorbell_refresh", &google).await;
        let spool = common::locked_spool(0x61);
        ring_at(&app, [0x06; 32], "phone-6", &[&spool]).await;
        deliver(&app, &spool).await;
        assert_eq!(google.until_pushes(1, PUSH_LIMIT).await.len(), 1);

        google.expire_access();
        deliver(&app, &spool).await;
        assert_eq!(google.until_pushes(2, PUSH_LIMIT).await.len(), 2);
        assert_eq!(
            google.exchanges(),
            2,
            "the refused token was not made again"
        );
    });
}

/// A token Firebase says is no app's takes its doorbell down.
#[test]
fn a_token_no_app_holds_takes_its_doorbell_down() {
    common::runtime().block_on(async {
        let google = GooglePush::start().await;
        let (app, doorbells) = node("doorbell_gone", &google).await;
        let spool = common::locked_spool(0x71);
        let key = [0x07; 32];
        ring_at(&app, key, "phone-7", &[&spool]).await;
        google.uninstall("phone-7");
        deliver(&app, &spool).await;
        after_marker(&app, &google, 0x7B).await;
        assert_eq!(doorbells.registered(&key), None);
    });
}

/// A node not configured to push serves no doorbell route: its devices keep
/// their waits.
#[test]
fn a_node_that_does_not_push_serves_no_doorbell() {
    common::runtime().block_on(async {
        let pool = common::fresh_store("doorbell_unconfigured").await;
        let state = Arc::new(common::ok_or_panic(
            AppState::new("member".to_string(), pool),
            "app state",
        ));
        let app = app(state);
        let spool = common::locked_spool(0x72);
        let doorbell = dsm::types::proto::B0xDoorbell {
            key: vec![0x08; 32],
            push_token: "phone-8".to_string(),
            addresses: vec![spool],
        };
        assert_eq!(
            post(&app, "/api/v2/b0x/doorbell", doorbell.encode_to_vec()).await,
            StatusCode::NOT_FOUND
        );
    });
}
