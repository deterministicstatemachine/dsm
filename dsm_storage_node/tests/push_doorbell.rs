// SPDX-License-Identifier: Apache-2.0
//! Inbox doorbells on the app the binary serves, over Postgres, pushing
//! through the node's own outbound client to Google's push endpoints and
//! Apple's, served by the test on local ports over TLS
//! (`common::google_push`, `common::apple_push`): an entry
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
use common::apple_push::ApplePush;
use common::google_push::GooglePush;
use dsm::types::proto::PushService;
use dsm_storage_node::api::transport::doorbell::Doorbells;
use dsm_storage_node::push::{ApnsSender, FcmSender, Pusher};
use dsm_storage_node::{build_app, AppLimits, AppState};
use prost::Message;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

/// How long a push may take to reach the endpoints.
const PUSH_LIMIT: Duration = Duration::from_secs(20);

/// Google's endpoints and Apple's, served for one test.
struct Services {
    google: GooglePush,
    apple: ApplePush,
}

async fn services() -> Services {
    Services {
        google: GooglePush::start().await,
        apple: ApplePush::start().await,
    }
}

/// A node over a fresh store named `store`, pushing through `services`.
async fn node(store: &str, services: &Services) -> (axum::Router, Arc<Doorbells>) {
    let fcm = common::ok_or_panic(FcmSender::new(services.google.config()), "the FCM sender");
    let apns = common::ok_or_panic(ApnsSender::new(services.apple.config()), "the APNs sender");
    node_pushing(
        store,
        Pusher {
            fcm: Some(fcm),
            apns: Some(apns),
        },
    )
    .await
}

/// A node over a fresh store named `store`, pushing through `pusher`.
async fn node_pushing(store: &str, pusher: Pusher) -> (axum::Router, Arc<Doorbells>) {
    let pool = common::fresh_store(store).await;
    let doorbells = Doorbells::start(pusher);
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
    assert_eq!(
        register(app, key, PushService::Fcm, push_token, spools).await,
        StatusCode::NO_CONTENT
    );
}

/// The node's answer to the doorbell `key` names, through `service`.
async fn register(
    app: &axum::Router,
    key: [u8; 32],
    service: PushService,
    push_token: &str,
    spools: &[&str],
) -> StatusCode {
    let doorbell = dsm::types::proto::B0xDoorbell {
        key: key.to_vec(),
        push_token: push_token.to_string(),
        addresses: spools.iter().map(|s| s.to_string()).collect(),
        service: service.into(),
    };
    post(app, "/api/v2/b0x/doorbell", doorbell.encode_to_vec()).await
}

/// An iPhone's device token: 32 bytes, as Base32 Crockford (what the phone
/// registers) and as lowercase hex (what Apple's path names).
fn iphone(byte: u8) -> (String, String) {
    let bytes = [byte; 32];
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    (dsm::utils::text_id::encode_base32_crockford(&bytes), hex)
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
        let services = services().await;
        let google = &services.google;
        let (app, _doorbells) = node("doorbell_one_push", &services).await;
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
            after_marker(&app, google, 0x7E).await,
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
        let services = services().await;
        let google = &services.google;
        let (app, _doorbells) = node("doorbell_none", &services).await;
        let watched = common::locked_spool(0x41);
        let unwatched = common::locked_spool(0x42);
        ring_at(&app, [0x02; 32], "phone-2", &[&watched]).await;

        deliver(&app, &unwatched).await;
        assert_eq!(
            after_marker(&app, google, 0x7D).await,
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
        let services = services().await;
        let google = &services.google;
        let (app, doorbells) = node("doorbell_owned", &services).await;
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
        let tokens = after_marker(&app, google, 0x7C).await;
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
        let services = services().await;
        let google = &services.google;
        let (app, _doorbells) = node("doorbell_refresh", &services).await;
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
        let services = services().await;
        let google = &services.google;
        let (app, doorbells) = node("doorbell_gone", &services).await;
        let spool = common::locked_spool(0x71);
        let key = [0x07; 32];
        ring_at(&app, key, "phone-7", &[&spool]).await;
        google.uninstall("phone-7");
        deliver(&app, &spool).await;
        after_marker(&app, google, 0x7B).await;
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
        assert_eq!(
            register(&app, [0x08; 32], PushService::Fcm, "phone-8", &[&spool]).await,
            StatusCode::NOT_FOUND
        );
    });
}

/// An iPhone's doorbell rings through APNs: an entry on its spool sends one
/// background push to its device, over HTTP/2, for the app's topic, at
/// priority 5, carrying nothing but the flag that wakes the app. Nothing goes
/// through Firebase for it, and exactly one push goes to Apple: a marker rung
/// after it through Firebase finds Apple's count unchanged.
/// MUTATION CONTROL: an APNs doorbell rung through Firebase, or a push that
/// is not a background push, is red.
#[test]
fn an_iphone_doorbell_rings_through_apns_once_per_delivery() {
    common::runtime().block_on(async {
        let services = services().await;
        let (app, doorbells) = node("doorbell_apns", &services).await;
        let spool = common::locked_spool(0x81);
        let (device, hex) = iphone(0x11);
        let key = [0x11; 32];
        assert_eq!(
            register(&app, key, PushService::Apns, &device, &[&spool]).await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(doorbells.service(&key), Some(PushService::Apns));

        deliver(&app, &spool).await;
        let pushes = services.apple.until_pushes(1, PUSH_LIMIT).await;
        assert_eq!(pushes.len(), 1, "one delivery, one push");
        assert_eq!(pushes[0].device, hex);
        assert_eq!(pushes[0].push_type, "background");
        assert_eq!(pushes[0].priority, "5");
        assert_eq!(pushes[0].body["aps"]["content-available"], 1);
        assert_eq!(
            pushes[0].body.as_object().map(|body| body.len()),
            Some(1),
            "the push carries more than the flag that wakes the app: {}",
            pushes[0].body
        );
        assert!(!pushes[0].body.to_string().contains(&spool));

        assert_eq!(
            after_marker(&app, &services.google, 0x7A).await,
            vec!["marker-122".to_string()],
            "an APNs doorbell rang through Firebase"
        );
        assert_eq!(
            services.apple.pushes().len(),
            1,
            "one delivery, more than one push"
        );
    });
}

/// An iPhone whose app Apple says is gone takes its doorbell down.
#[test]
fn an_iphone_whose_app_is_gone_takes_its_doorbell_down() {
    common::runtime().block_on(async {
        let services = services().await;
        let (app, doorbells) = node("doorbell_apns_gone", &services).await;
        let spool = common::locked_spool(0x82);
        let (device, hex) = iphone(0x12);
        let key = [0x12; 32];
        assert_eq!(
            register(&app, key, PushService::Apns, &device, &[&spool]).await,
            StatusCode::NO_CONTENT
        );
        services.apple.uninstall(&hex);
        deliver(&app, &spool).await;
        let mut waited = Duration::ZERO;
        while doorbells.registered(&key).is_some() {
            assert!(waited < PUSH_LIMIT, "the gone app's doorbell still stands");
            tokio::time::sleep(Duration::from_millis(20)).await;
            waited += Duration::from_millis(20);
        }
    });
}

/// A node that pushes through Firebase only answers an iPhone's doorbell
/// `404`, as a node that pushes no one does: its device keeps its waits. An
/// APNs device token that is not one is refused.
#[test]
fn a_node_without_apns_refuses_an_iphone_doorbell() {
    common::runtime().block_on(async {
        let google = GooglePush::start().await;
        let fcm = common::ok_or_panic(FcmSender::new(google.config()), "the FCM sender");
        let (app, _doorbells) = node_pushing(
            "doorbell_no_apns",
            Pusher {
                fcm: Some(fcm),
                apns: None,
            },
        )
        .await;
        let spool = common::locked_spool(0x83);
        let (device, _) = iphone(0x13);
        assert_eq!(
            register(&app, [0x13; 32], PushService::Apns, &device, &[&spool]).await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            register(&app, [0x14; 32], PushService::Fcm, "phone-14", &[&spool]).await,
            StatusCode::NO_CONTENT
        );

        let services = services().await;
        let (app, _doorbells) = node("doorbell_apns_malformed", &services).await;
        let short = dsm::utils::text_id::encode_base32_crockford(&[0x15; 8]);
        assert_eq!(
            register(&app, [0x15; 32], PushService::Apns, &short, &[&spool]).await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            register(
                &app,
                [0x16; 32],
                PushService::Apns,
                "not base32!",
                &[&spool]
            )
            .await,
            StatusCode::BAD_REQUEST
        );
    });
}
