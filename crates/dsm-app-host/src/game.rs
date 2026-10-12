// SPDX-License-Identifier: MIT OR Apache-2.0

//! The game-facing side: the SDK's own protobuf ingress on a local address,
//! and the record of what each call did.
//!
//! - `POST /ingress`: an `IngressRequest`, answered with the SDK's
//!   `IngressResponse`; an invoke is recorded.
//! - `POST /ingress/quiet`: the same, never recorded (what the application
//!   polls).
//! - `GET /activity/{after}`: the record after `after` (`AppHostActivityV1`).
//!
//! On `connect.app.offer` the host names its own relay: the endpoint and the
//! certificate pin are its own, never the application's to choose.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State as Extract};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use dsm_sdk::generated as pb;
use prost::Message;

use crate::activity::Record;
use crate::dispatch::{Call, Label, Sdk};

#[derive(Clone)]
pub struct State {
    pub sdk: Sdk,
    pub record: Arc<Record>,
    pub requests_changed: Arc<tokio::sync::Notify>,
    pub relay_endpoint: String,
    pub relay_pin: [u8; 32],
}

pub fn protobuf(bytes: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/x-protobuf")],
        bytes,
    )
        .into_response()
}

pub fn refused(status: StatusCode, why: String) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        why,
    )
        .into_response()
}

pub fn router(state: State) -> Router {
    Router::new()
        .route("/ingress", post(recorded))
        .route("/ingress/quiet", post(quiet))
        .route("/activity/{after}", get(activity))
        .with_state(state)
}

/// The host's relay in an offer's arguments, whatever the application sent.
fn name_own_relay(state: &State, args: &[u8]) -> Result<Vec<u8>, String> {
    let pack = pb::ArgPack::decode(args).map_err(|e| format!("connect.app.offer: {e}"))?;
    let mut offer = pb::ConnectAppOfferRequestV1::decode(pack.body.as_slice())
        .map_err(|e| format!("connect.app.offer: {e}"))?;
    offer.endpoint = state.relay_endpoint.clone();
    offer.cert_pin = state.relay_pin.to_vec();
    Ok(crate::dispatch::arg_pack(offer.encode_to_vec()))
}

async fn call(state: State, body: Bytes, record: Recording) -> Response {
    let mut request = match pb::IngressRequest::decode(body.as_ref()) {
        Ok(r) => r,
        Err(e) => {
            return refused(
                StatusCode::BAD_REQUEST,
                format!("not an IngressRequest: {e}"),
            )
        }
    };
    let (method, invoked) = match &mut request.operation {
        Some(pb::ingress_request::Operation::RouterInvoke(op)) => {
            if op.method == "connect.app.offer" {
                match name_own_relay(&state, &op.args) {
                    Ok(args) => op.args = args,
                    Err(e) => return refused(StatusCode::BAD_REQUEST, e),
                }
            }
            (op.method.clone(), Invoked::Yes)
        }
        Some(pb::ingress_request::Operation::RouterQuery(op)) => (op.method.clone(), Invoked::No),
        _ => {
            return refused(
                StatusCode::BAD_REQUEST,
                "the ingress takes router queries and invokes".into(),
            )
        }
    };
    let label = match (record, invoked) {
        (Recording::Yes, Invoked::Yes) => Some(Label {
            kind: pb::AppHostActivityKind::Route,
            name: method.clone(),
        }),
        _ => None,
    };
    let done = match state.sdk.call(Call { request, label }).await {
        Ok(done) => done,
        Err(e) => return refused(StatusCode::SERVICE_UNAVAILABLE, e),
    };
    if method == "connect.app.request" {
        if let Some(pb::ingress_response::Result::OkBytes(..)) = &done.response.result {
            state.requests_changed.notify_waiters();
        }
    }
    protobuf(done.response.encode_to_vec())
}

enum Recording {
    Yes,
    No,
}

enum Invoked {
    Yes,
    No,
}

async fn recorded(Extract(state): Extract<State>, body: Bytes) -> Response {
    call(state, body, Recording::Yes).await
}

async fn quiet(Extract(state): Extract<State>, body: Bytes) -> Response {
    call(state, body, Recording::No).await
}

async fn activity(Extract(state): Extract<State>, Path(after): Path<u64>) -> Response {
    match state.record.since(after) {
        Ok(feed) => protobuf(feed.encode_to_vec()),
        Err(e) => refused(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}
