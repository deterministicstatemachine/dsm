// SPDX-License-Identifier: MIT OR Apache-2.0
//! The receipt service's binary. Configured by environment:
//! - RECEIPT_BIND: the address to listen on (e.g. 0.0.0.0:8090);
//! - RECEIPT_SMTP_URL: the mail server, as lettre reads it
//!   (smtps://user:password@smtp.example.com:465);
//! - RECEIPT_FROM: who receipts come from ("DSM Receipts <receipts@example.com>");
//! - RECEIPT_PER_DEVICE, RECEIPT_PER_RECIPIENT, RECEIPT_WINDOW_SECS: the rates.
//!
//! TLS is the proxy's in front of it: the service listens on plain HTTP on
//! the host, and the wallet reaches it only over https://.

use std::sync::Arc;
use std::time::Duration;

use dsm_receipt_service::server::{app, Service};
use dsm_receipt_service::Rates;
use lettre::{AsyncSmtpTransport, Tokio1Executor};

fn var(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|e| format!("{name}: {e}"))
}

fn number(name: &str) -> Result<u64, String> {
    var(name)?
        .parse()
        .map_err(|e| format!("{name} is not a number: {e}"))
}

fn main() -> Result<(), String> {
    env_logger::init();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("the runtime: {e}"))?
        .block_on(run())
}

async fn run() -> Result<(), String> {
    let bind = var("RECEIPT_BIND")?;
    let mailer = AsyncSmtpTransport::<Tokio1Executor>::from_url(&var("RECEIPT_SMTP_URL")?)
        .map_err(|e| format!("RECEIPT_SMTP_URL: {e}"))?
        .build();
    let from = var("RECEIPT_FROM")?
        .parse()
        .map_err(|e| format!("RECEIPT_FROM is not a mailbox: {e}"))?;
    let per_device = usize::try_from(number("RECEIPT_PER_DEVICE")?).map_err(|e| e.to_string())?;
    let per_recipient =
        usize::try_from(number("RECEIPT_PER_RECIPIENT")?).map_err(|e| e.to_string())?;
    let rates = Rates {
        per_device,
        per_recipient,
        window: Duration::from_secs(number("RECEIPT_WINDOW_SECS")?),
    };
    let service = Arc::new(Service::new(mailer, from, rates));
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .map_err(|e| format!("bind {bind}: {e}"))?;
    log::info!("the receipt service listens on {bind}");
    axum::serve(listener, app(service))
        .await
        .map_err(|e| format!("serve: {e}"))
}
