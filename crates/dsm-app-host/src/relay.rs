// SPDX-License-Identifier: MIT OR Apache-2.0

//! The DSM Connect relay a wallet reaches (DSM Amendment A11), over TLS
//! bound to the pin its connect code names. Transport, never evidence: every
//! object it carries is signed and checked by the SDK's `connect` routes, and
//! nothing a wallet posts is a fact about DSM.
//!
//! - `GET /connect/offer/{digest}`: the signed offer a code names.
//! - `POST /connect/accept`: a wallet's signed accept.
//! - `GET /connect/requests/{session}/{after}`: the session's requests above
//!   `after`, held a while when there are none yet.
//! - `POST /connect/responses`: a wallet's signed answer.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, State as Extract};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use dsm_sdk::generated as pb;
use prost::Message;

use crate::activity::Record;
use crate::dispatch::{arg_pack, connect_reply, Call, Sdk};
use crate::game::{protobuf, refused};
use dsm_sdk::util::text_id::{decode_base32_crockford, encode_base32_crockford};

#[derive(Clone)]
pub struct State {
    pub sdk: Sdk,
    pub record: Arc<Record>,
    pub requests_changed: Arc<tokio::sync::Notify>,
}

/// How many times a request read with nothing to answer waits, and how long
/// each wait may be: a transport bound, never a validity rule.
const HOLD_ROUNDS: usize = 10;
const HOLD_ROUND: Duration = Duration::from_secs(2);

pub fn router(state: State) -> Router {
    Router::new()
        .route("/connect/offer/{digest}", get(offer))
        .route("/connect/accept", post(accept))
        .route("/connect/requests/{session}/{after}", get(requests))
        .route("/connect/responses", post(respond))
        .with_state(state)
}

fn id32(text: &str, what: &str) -> Result<[u8; 32], String> {
    let bytes = decode_base32_crockford(&text.to_ascii_uppercase())
        .ok_or_else(|| format!("{what} is not Base32 Crockford"))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|e| format!("{what}: {e}"))
}

fn short(bytes: &[u8]) -> String {
    encode_base32_crockford(bytes).chars().take(10).collect()
}

async fn offer(Extract(state): Extract<State>, Path(digest): Path<String>) -> Response {
    let digest = match id32(&digest, "the offer digest") {
        Ok(d) => d,
        Err(e) => return refused(StatusCode::BAD_REQUEST, e),
    };
    let call = Call::query(
        "connect.app.offerOf",
        arg_pack(
            pb::ConnectOfferRefV1 {
                offer_digest: digest.to_vec(),
            }
            .encode_to_vec(),
        ),
    );
    let reply = match state.sdk.call(call).await {
        Ok(done) => connect_reply(done.response),
        Err(e) => return refused(StatusCode::SERVICE_UNAVAILABLE, e),
    };
    match reply {
        Ok(pb::connect_reply_v1::Reply::Offer(o)) => {
            state.record.relay(
                "relay: offer",
                format!("a wallet fetched offer {}", short(&digest)),
                Ok(format!("{} signed bytes", o.offer.len())),
            );
            protobuf(o.offer)
        }
        Ok(other) => refused(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("connect.app.offerOf answered {other:?}"),
        ),
        Err(e) => refused(StatusCode::NOT_FOUND, e),
    }
}

async fn accept(Extract(state): Extract<State>, body: Bytes) -> Response {
    let call = Call::invoke("connect.app.accept", arg_pack(body.to_vec()));
    let reply = match state.sdk.call(call).await {
        Ok(done) => connect_reply(done.response),
        Err(e) => return refused(StatusCode::SERVICE_UNAVAILABLE, e),
    };
    match reply {
        Ok(pb::connect_reply_v1::Reply::Session(s)) => {
            state.record.relay(
                "relay: accept",
                format!("{} accepted the offer", s.display_name),
                Ok(format!(
                    "session {}: its card resolved on the pinned set; it is a contact, the relationship is established",
                    short(&s.session_id)
                )),
            );
            protobuf(s.encode_to_vec())
        }
        Ok(other) => refused(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("connect.app.accept answered {other:?}"),
        ),
        Err(e) => {
            state
                .record
                .relay("relay: accept", "a wallet's accept".into(), Err(e.clone()));
            refused(StatusCode::FORBIDDEN, e)
        }
    }
}

async fn requests(
    Extract(state): Extract<State>,
    Path((session, after)): Path<(String, u64)>,
) -> Response {
    let session = match id32(&session, "the session") {
        Ok(s) => s,
        Err(e) => return refused(StatusCode::BAD_REQUEST, e),
    };
    let args = arg_pack(
        pb::ConnectAppRequestsQueryV1 {
            session_id: session.to_vec(),
            after,
        }
        .encode_to_vec(),
    );
    for _round in 0..HOLD_ROUNDS {
        // Registered before the read, so a request signed after it wakes us.
        let changed = state.requests_changed.notified();
        let reply = match state
            .sdk
            .call(Call::query("connect.app.requests", args.clone()))
            .await
        {
            Ok(done) => connect_reply(done.response),
            Err(e) => return refused(StatusCode::SERVICE_UNAVAILABLE, e),
        };
        match reply {
            Ok(pb::connect_reply_v1::Reply::Requests(batch)) => {
                if !batch.requests.is_empty() {
                    state.record.relay(
                        "relay: requests",
                        format!(
                            "the wallet of session {} fetched its requests",
                            short(&session)
                        ),
                        Ok(format!(
                            "{} signed requests above #{after}",
                            batch.requests.len()
                        )),
                    );
                    return protobuf(batch.encode_to_vec());
                }
            }
            Ok(other) => {
                return refused(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("connect.app.requests answered {other:?}"),
                )
            }
            Err(e) => return refused(StatusCode::NOT_FOUND, e),
        }
        if let Err(elapsed) = tokio::time::timeout(HOLD_ROUND, changed).await {
            log::debug!("[relay] a held read waits on: {elapsed}");
        }
    }
    protobuf(pb::AppRequestBatchV1::default().encode_to_vec())
}

async fn respond(Extract(state): Extract<State>, body: Bytes) -> Response {
    let summary = match pb::AppResponseV1::decode(body.as_ref())
        .map_err(|e| e.to_string())
        .and_then(|r| pb::AppResponseBodyV1::decode(r.body.as_slice()).map_err(|e| e.to_string()))
    {
        Ok(b) => format!(
            "the wallet answered request #{}: {:?}{}",
            b.seq,
            pb::ConnectOutcome::try_from(b.outcome),
            match b.reason.as_str() {
                "" => String::new(),
                why => format!(" ({why})"),
            }
        ),
        Err(e) => format!("an unreadable answer: {e}"),
    };
    let call = Call::invoke("connect.app.respond", arg_pack(body.to_vec()));
    let reply = match state.sdk.call(call).await {
        Ok(done) => connect_reply(done.response),
        Err(e) => return refused(StatusCode::SERVICE_UNAVAILABLE, e),
    };
    match reply {
        Ok(pb::connect_reply_v1::Reply::Request(r)) => {
            state.record.relay(
                "relay: answer",
                summary,
                Ok("a signed notification, kept; it establishes nothing about DSM".into()),
            );
            protobuf(r.encode_to_vec())
        }
        Ok(other) => refused(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("connect.app.respond answered {other:?}"),
        ),
        Err(e) => {
            state.record.relay("relay: answer", summary, Err(e.clone()));
            refused(StatusCode::FORBIDDEN, e)
        }
    }
}
