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
//!
//! Only the application reaches it. The ingress listens on a loopback
//! address alone, and every request must carry the secret this launch wrote
//! to `<data-dir>/ingress-token` (readable by the operator alone) as
//! `Authorization: Bearer <secret>`, name this ingress as its `Host`, and
//! come from no other web origin. A web page in a browser on the same host
//! can neither read the secret nor send it, and a page whose name was
//! rebound to the loopback address names another host.

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

/// Who may call the ingress: whoever holds this launch's secret and reaches
/// the ingress by its own address.
#[derive(Clone)]
pub struct Caller {
    /// `Bearer <secret>`, the whole `Authorization` value a call carries.
    authorization: Vec<u8>,
    /// The names the ingress answers to as a `Host`: its loopback address
    /// and port, and `localhost` with that port.
    hosts: Vec<String>,
}

impl Caller {
    /// The caller holding `secret`, reaching the ingress bound at `bind`.
    pub fn new(secret: &str, bind: std::net::SocketAddr) -> Self {
        Self {
            authorization: format!("Bearer {secret}").into_bytes(),
            hosts: vec![bind.to_string(), format!("localhost:{}", bind.port())],
        }
    }

    /// Admit a call with these headers to this host, or say why not.
    fn admits(
        &self,
        host: Option<&[u8]>,
        headers: &axum::http::HeaderMap,
    ) -> Result<(), (StatusCode, String)> {
        let Some(host) = host else {
            return Err((StatusCode::BAD_REQUEST, "the call names no host".into()));
        };
        let Some(named) = self.hosts.iter().find(|h| h.as_bytes() == host) else {
            return Err((
                StatusCode::FORBIDDEN,
                "the call names another host than this ingress".into(),
            ));
        };
        if let Some(origin) = headers.get(header::ORIGIN) {
            if origin.as_bytes() != format!("http://{named}").as_bytes() {
                return Err((
                    StatusCode::FORBIDDEN,
                    "the call comes from another web origin".into(),
                ));
            }
        }
        let presented = headers
            .get(header::AUTHORIZATION)
            .map_or(&[][..], |v| v.as_bytes());
        if !same_secret(presented, &self.authorization) {
            return Err((
                StatusCode::UNAUTHORIZED,
                "the call does not carry this launch's ingress secret".into(),
            ));
        }
        Ok(())
    }
}

/// Whether `a` and `b` are the same bytes, read in full whatever they hold,
/// so how long the comparison takes says nothing about where they differ.
fn same_secret(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |differ, (x, y)| differ | (x ^ y)) == 0
}

/// Refuse every call `caller` does not admit, before it reaches a route.
async fn admit(
    Extract(caller): Extract<Arc<Caller>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let host = match request.headers().get(header::HOST) {
        Some(host) => Some(host.as_bytes().to_vec()),
        None => request
            .uri()
            .authority()
            .map(|a| a.as_str().as_bytes().to_vec()),
    };
    match caller.admits(host.as_deref(), request.headers()) {
        Ok(()) => next.run(request).await,
        Err((status, why)) => refused(status, why),
    }
}

pub fn router(state: State, caller: Caller) -> Router {
    Router::new()
        .route("/ingress", post(recorded))
        .route("/ingress/quiet", post(quiet))
        .route("/activity/{after}", get(activity))
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(caller),
            admit,
        ))
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use std::sync::mpsc::Receiver;
    use std::time::Duration;
    use tower::ServiceExt;

    const SECRET: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    /// The ingress on `127.0.0.1:8787`, and the receiving end of its SDK
    /// queue: a call that gets past the guard lands there.
    fn ingress() -> (Router, Receiver<crate::dispatch::Job>) {
        let (sdk, queue) = Sdk::with_queue(4);
        let state = State {
            sdk,
            record: Arc::new(Record::new(crate::identity::Account {
                device_id: [0x11; 32],
            })),
            requests_changed: Arc::new(tokio::sync::Notify::new()),
            relay_endpoint: "https://127.0.0.1:8443".into(),
            relay_pin: [0x22; 32],
        };
        let bind = std::net::SocketAddr::from(([127, 0, 0, 1], 8787));
        (router(state, Caller::new(SECRET, bind)), queue)
    }

    /// An invoke of `wallet.sendSmart`, what a hostile page would send.
    fn send_smart(headers: &[(&str, &str)]) -> Result<Request<Body>, String> {
        let invoke = pb::IngressRequest {
            operation: Some(pb::ingress_request::Operation::RouterInvoke(
                pb::RouterInvokeOp {
                    method: "wallet.sendSmart".into(),
                    args: Vec::new(),
                },
            )),
        };
        let mut request = Request::post("/ingress");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        request
            .body(Body::from(invoke.encode_to_vec()))
            .map_err(|e| format!("request: {e}"))
    }

    /// A call the guard refuses is answered with `refused` at once, and
    /// nothing reaches the SDK.
    async fn refused_at_the_guard(
        app: &Router,
        queue: &Receiver<crate::dispatch::Job>,
        request: Request<Body>,
        refused: StatusCode,
    ) -> Result<(), String> {
        let answer = tokio::time::timeout(Duration::from_secs(5), app.clone().oneshot(request))
            .await
            .map_err(|e| format!("the call reached the SDK and waited there: {e}"))?
            .map_err(|e| format!("the ingress answers: {e}"))?;
        assert_eq!(answer.status(), refused);
        match queue.try_recv() {
            Ok(..) => Err("a refused call reached the SDK".into()),
            Err(empty) => {
                assert_eq!(empty, std::sync::mpsc::TryRecvError::Empty);
                Ok(())
            }
        }
    }

    /// A call the guard admits reaches the SDK's queue. The test, standing
    /// in no worker's place, lets it go unanswered, and the ingress says so.
    async fn admitted(
        app: &Router,
        queue: &Receiver<crate::dispatch::Job>,
        request: Request<Body>,
    ) -> Result<(), String> {
        let call = tokio::spawn(app.clone().oneshot(request));
        let job = queue
            .recv_timeout(Duration::from_secs(5))
            .map_err(|e| format!("an admitted call never reached the SDK: {e}"))?;
        drop(job);
        let answer = call
            .await
            .map_err(|e| format!("task: {e}"))?
            .map_err(|e| format!("the ingress answers: {e}"))?;
        assert_eq!(answer.status(), StatusCode::SERVICE_UNAVAILABLE);
        Ok(())
    }

    /// A call holding the secret, naming the ingress and coming from no other
    /// origin reaches the SDK; one without the secret, naming another host,
    /// or sent by another web origin is refused before any route runs and
    /// reaches nothing. A browser page's simple text/plain post of an invoke
    /// is the last case.
    #[test]
    fn only_a_caller_with_the_secret_at_this_address_reaches_a_route() -> Result<(), String> {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("the runtime: {e}"))?
            .block_on(async {
                let (app, queue) = ingress();
                let bearer = format!("Bearer {SECRET}");
                for host in ["127.0.0.1:8787", "localhost:8787"] {
                    let call = send_smart(&[("host", host), ("authorization", &bearer)])?;
                    admitted(&app, &queue, call).await?;
                }
                let same_origin = send_smart(&[
                    ("host", "127.0.0.1:8787"),
                    ("origin", "http://127.0.0.1:8787"),
                    ("authorization", &bearer),
                ])?;
                admitted(&app, &queue, same_origin).await?;

                for (headers, refused) in [
                    (vec![("host", "127.0.0.1:8787")], StatusCode::UNAUTHORIZED),
                    (
                        vec![
                            ("host", "127.0.0.1:8787"),
                            ("authorization", "Bearer guess"),
                        ],
                        StatusCode::UNAUTHORIZED,
                    ),
                    (
                        vec![("host", "rebound.example:8787"), ("authorization", &bearer)],
                        StatusCode::FORBIDDEN,
                    ),
                    (
                        vec![
                            ("host", "127.0.0.1:8787"),
                            ("origin", "https://page.example"),
                            ("authorization", &bearer),
                        ],
                        StatusCode::FORBIDDEN,
                    ),
                    (
                        vec![
                            ("host", "127.0.0.1:8787"),
                            ("origin", "https://page.example"),
                            ("content-type", "text/plain"),
                        ],
                        StatusCode::FORBIDDEN,
                    ),
                ] {
                    refused_at_the_guard(&app, &queue, send_smart(&headers)?, refused).await?;
                }
                Ok(())
            })
    }
}
