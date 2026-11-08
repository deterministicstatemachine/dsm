// SPDX-License-Identifier: MIT OR Apache-2.0
//! The HTTP side: `POST /v1/receipt` with a `ReceiptEmailRequestV1` body,
//! answered with a `ReceiptEmailResultV1` (where it went, masked) or a
//! refusal's status and reason as text.

use std::sync::Arc;
use std::time::Duration;

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

use crate::{counted_as, masked, read_request, recipient, render, RateLimiter, Rates, Refusal};

/// Requests larger than a whole receipt request with a SPHINCS+ signature
/// are refused before they are read.
pub const MAX_BODY: usize = 64 * 1024;

/// What one client can hold on the service, and for how long.
#[derive(Debug, Clone, Copy)]
pub struct Bounds {
    /// How long a connection has to send a request's headers, the next
    /// request's included once it has answered one.
    pub header_read: Duration,
    /// How long one request may take, its body and its email included,
    /// before it is answered `408`.
    pub request_time: Duration,
    /// Requests worked on at once. One more is answered `503` at once rather
    /// than queued behind them.
    pub in_flight: usize,
}

impl Bounds {
    /// The deployed service's bounds.
    pub const DEPLOYED: Bounds = Bounds {
        header_read: Duration::from_secs(10),
        request_time: Duration::from_secs(30),
        in_flight: 64,
    };
}

pub struct Service {
    pub limiter: Mutex<RateLimiter>,
    pub mailer: AsyncSmtpTransport<Tokio1Executor>,
    pub from: Mailbox,
    in_flight: tokio::sync::Semaphore,
}

impl Service {
    /// The service, working on at most `in_flight` requests at once.
    pub fn new(
        mailer: AsyncSmtpTransport<Tokio1Executor>,
        from: Mailbox,
        rates: Rates,
        in_flight: usize,
    ) -> Self {
        Self {
            limiter: Mutex::new(RateLimiter::new(rates)),
            mailer,
            from,
            in_flight: tokio::sync::Semaphore::new(in_flight),
        }
    }
}

/// The routes, each request answered within `request_time`.
pub fn app(service: Arc<Service>, request_time: Duration) -> Router {
    Router::new()
        .route("/v1/receipt", post(receipt))
        .with_state(service)
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            request_time,
        ))
}

/// Serve `service` on `listener` until it fails, every connection and
/// request held to `bounds`. The binary serves through exactly this.
pub async fn serve(
    listener: std::net::TcpListener,
    service: Arc<Service>,
    bounds: Bounds,
) -> std::io::Result<()> {
    let mut server = axum_server::from_tcp(listener)?;
    server
        .http_builder()
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(bounds.header_read);
    server
        .serve(app(service, bounds.request_time).into_make_service())
        .await
}

fn refused(refusal: Refusal) -> Response {
    match StatusCode::from_u16(refusal.status) {
        Ok(status) => (status, refusal.reason).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("{} ({e})", refusal.reason),
        )
            .into_response(),
    }
}

/// Why a receipt was not sent, as the service logs it: the mail server's
/// status code, or the kind of failure. The mail server's own words are left
/// out, because a refusal of a recipient quotes the recipient's address.
pub fn undelivered(e: &lettre::transport::smtp::Error) -> String {
    if let Some(code) = e.status() {
        return format!("the mail server answered {code}");
    }
    if e.is_timeout() {
        return "the mail server did not answer in time".into();
    }
    if e.is_tls() {
        return "the TLS session with the mail server failed".into();
    }
    "the mail server could not be reached, or broke off".into()
}

async fn receipt(State(service): State<Arc<Service>>, body: Bytes) -> Response {
    let Ok(_working) = service.in_flight.try_acquire() else {
        return refused(Refusal {
            status: 503,
            reason: "the service is busy; try later".into(),
        });
    };
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
    let to = match recipient(&request) {
        Ok(to) => to,
        Err(refusal) => return refused(refusal),
    };
    if let Err(refusal) = service.limiter.lock().await.admit(
        &request.sender_signing_public_key,
        &counted_as(&to),
        Instant::now(),
    ) {
        return refused(refusal);
    }
    let receipt = render(&request);
    let email = match Email::builder()
        .from(service.from.clone())
        .to(Mailbox::new(None, to))
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
        log::warn!("a receipt was not sent: {}", undelivered(&e));
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
