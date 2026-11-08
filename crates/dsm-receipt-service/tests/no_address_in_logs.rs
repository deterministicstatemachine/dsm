// SPDX-License-Identifier: MIT OR Apache-2.0
//! The service logs no address. A mail server that refuses a recipient quotes
//! the address in its answer, and that answer is what the mail library's
//! error says; the service logs why a receipt was not sent without it. This
//! binary installs a logger that keeps every record, drives the service
//! against such a mail server, and reads what was logged.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use dsm::types::proto as pb;
use dsm_receipt_service::server::{serve, Bounds, Service};
use dsm_receipt_service::{signing_digest, Rates};
use lettre::{AsyncSmtpTransport, Tokio1Executor};
use prost::Message;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

type R<T = ()> = Result<T, String>;

const ADDRESS: &str = "jane@example.com";

/// Every record logged in this process.
struct Kept(Mutex<Vec<String>>);

impl log::Log for Kept {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Trace
    }

    fn log(&self, record: &log::Record) {
        match self.0.lock() {
            Ok(mut kept) => kept.push(format!("{}", record.args())),
            Err(poisoned) => poisoned.into_inner().push(format!("{}", record.args())),
        }
    }

    fn flush(&self) {}
}

static LOGGED: Kept = Kept(Mutex::new(Vec::new()));

/// A mail server that refuses every recipient, quoting the address back.
async fn refusing_mail_server() -> R<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind smtp: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("smtp addr: {e}"))?
        .port();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (read, mut write) = socket.into_split();
                let mut lines = BufReader::new(read).lines();
                if let Err(e) = write.write_all(b"220 sink ESMTP\r\n").await {
                    panic!("greet: {e}");
                }
                while let Ok(Some(line)) = lines.next_line().await {
                    let verb = line
                        .split_whitespace()
                        .next()
                        .map_or(String::new(), str::to_uppercase);
                    let reply = match verb.as_str() {
                        "EHLO" | "HELO" => "250 sink\r\n".to_string(),
                        "RCPT" => format!("550 5.1.1 <{ADDRESS}>: Recipient address rejected\r\n"),
                        "QUIT" => "221 bye\r\n".to_string(),
                        _ => "250 ok\r\n".to_string(),
                    };
                    if let Err(e) = write.write_all(reply.as_bytes()).await {
                        panic!("reply: {e}");
                    }
                }
            });
        }
    });
    Ok(port)
}

#[test]
fn a_refused_recipient_is_logged_without_its_address() -> R {
    log::set_logger(&LOGGED).map_err(|e| format!("install the logger: {e}"))?;
    log::set_max_level(log::LevelFilter::Trace);
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("the runtime: {e}"))?
        .block_on(async {
            let smtp = refusing_mail_server().await?;
            let mailer = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("127.0.0.1")
                .port(smtp)
                .build();
            let from = "DSM Receipts <receipts@example.com>"
                .parse()
                .map_err(|e| format!("from: {e}"))?;
            let rates = Rates {
                per_device: 10,
                per_recipient: 10,
                window: Duration::from_secs(3600),
            };
            let bounds = Bounds::DEPLOYED;
            let service = Arc::new(Service::new(mailer, from, rates, bounds.in_flight));
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|e| format!("bind http: {e}"))?;
            let addr = listener
                .local_addr()
                .map_err(|e| format!("http addr: {e}"))?;
            let listener = listener
                .into_std()
                .map_err(|e| format!("the listener: {e}"))?;
            tokio::spawn(async move {
                if let Err(e) = serve(listener, service, bounds).await {
                    panic!("the service stopped: {e}");
                }
            });

            let (pk, sk) = dsm::crypto::sphincs::generate_sphincs_keypair()
                .map_err(|e| format!("keys: {e}"))?;
            let mut request = pb::ReceiptEmailRequestV1 {
                to_email: ADDRESS.into(),
                sender_name: "Dana".into(),
                token: "ERA".into(),
                amount: "50".into(),
                memo: String::new(),
                reference: "7KQ2ABCD".into(),
                sent_at_local: String::new(),
                sender_device_id: vec![0x44; 32],
                sender_signing_public_key: pk,
                signature: Vec::new(),
            };
            request.signature = dsm::crypto::sphincs::sphincs_sign(&sk, &signing_digest(&request))
                .map_err(|e| format!("sign: {e}"))?;
            let answer = reqwest::Client::new()
                .post(format!("http://{addr}/v1/receipt"))
                .body(request.encode_to_vec())
                .send()
                .await
                .map_err(|e| format!("post: {e}"))?;
            assert_eq!(answer.status().as_u16(), 502);
            Ok::<(), String>(())
        })?;

    let logged = match LOGGED.0.lock() {
        Ok(kept) => kept.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    let refusal: Vec<&String> = logged
        .iter()
        .filter(|line| line.contains("a receipt was not sent"))
        .collect();
    assert_eq!(refusal.len(), 1, "the refusal is logged once: {logged:?}");
    assert!(
        refusal[0].contains("550"),
        "the log says what the mail server answered: {}",
        refusal[0]
    );
    for line in &logged {
        assert!(!line.contains(ADDRESS), "an address was logged: {line}");
    }
    Ok(())
}
