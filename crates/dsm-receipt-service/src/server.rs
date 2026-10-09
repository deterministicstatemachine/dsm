// SPDX-License-Identifier: MIT OR Apache-2.0
//! The HTTP side: `POST /v1/receipt` with a `ReceiptEmailRequestV1` body,
//! answered with a `ReceiptEmailResultV1` (where it went, masked) or a
//! refusal's status and reason as text.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use dsm::types::proto as pb;
use lettre::message::{header::ContentType, Mailbox, MultiPart, SinglePart};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message as Email, Tokio1Executor};
use prost::Message;
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::{masked, read_request, render, RateLimiter, Rates, Refusal};

/// Requests larger than a whole receipt request with a SPHINCS+ signature
/// are refused before they are read.
pub const MAX_BODY: usize = 64 * 1024;

pub struct Service {
    pub limiter: Mutex<RateLimiter>,
    pub mailer: AsyncSmtpTransport<Tokio1Executor>,
    pub from: Mailbox,
}

impl Service {
    pub fn new(mailer: AsyncSmtpTransport<Tokio1Executor>, from: Mailbox, rates: Rates) -> Self {
        Self {
            limiter: Mutex::new(RateLimiter::new(rates)),
            mailer,
            from,
        }
    }
}

pub fn app(service: Arc<Service>) -> Router {
    Router::new()
        .route("/v1/receipt", post(receipt))
        .with_state(service)
}

fn refused(refusal: Refusal) -> Response {
    let status = StatusCode::from_u16(refusal.status).map_or(StatusCode::BAD_REQUEST, |s| s);
    (status, refusal.reason).into_response()
}

async fn receipt(State(service): State<Arc<Service>>, body: Bytes) -> Response {
    if body.len() > MAX_BODY {
        return refused(Refusal {
            status: 413,
            reason: "the request is too large".into(),
        });
    }
    let request = match read_request(&body) {
        Ok(request) => request,
        Err(refusal) => return refused(refusal),
    };
    if let Err(refusal) = service.limiter.lock().await.admit(
        &request.sender_device_id,
        &request.to_email,
        Instant::now(),
    ) {
        return refused(refusal);
    }
    let to: Mailbox = match request.to_email.parse() {
        Ok(to) => to,
        Err(e) => {
            return refused(Refusal {
                status: 400,
                reason: format!("the email is not an address: {e}"),
            })
        }
    };
    let receipt = render(&request);
    let email = match Email::builder()
        .from(service.from.clone())
        .to(to)
        .subject(receipt.subject)
        .multipart(
            MultiPart::alternative()
                .singlepart(
                    SinglePart::builder()
                        .header(ContentType::TEXT_PLAIN)
                        .body(receipt.text),
                )
                .singlepart(
                    SinglePart::builder()
                        .header(ContentType::TEXT_HTML)
                        .body(receipt.html),
                ),
        ) {
        Ok(email) => email,
        Err(e) => {
            return refused(Refusal {
                status: 500,
                reason: format!("the receipt was not composed: {e}"),
            })
        }
    };
    if let Err(e) = service.mailer.send(email).await {
        log::warn!("a receipt was not sent: {e}");
        return refused(Refusal {
            status: 502,
            reason: "the mail server did not take the receipt".into(),
        });
    }
    let answer = pb::ReceiptEmailResultV1 {
        sent_to_masked: masked(&request.to_email),
    };
    (
        [(header::CONTENT_TYPE, "application/x-protobuf")],
        answer.encode_to_vec(),
    )
        .into_response()
}
