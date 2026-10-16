// SPDX-License-Identifier: MIT OR Apache-2.0
//! The receipt service end to end: a wallet's signed request over HTTP, the
//! service's checks and rates, and the email it hands a mail server over SMTP.
//! The mail server here is a minimal SMTP listener that keeps what it is
//! given, so the test reads the very message the service sent.

use std::sync::Arc;
use std::time::Duration;

use dsm::types::proto as pb;
use dsm_receipt_service::server::{serve, Bounds, Service};
use dsm_receipt_service::{signing_digest, Rates};
use lettre::{AsyncSmtpTransport, Tokio1Executor};
use prost::Message;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

type R<T = ()> = Result<T, String>;

/// Each test runs on its own runtime, built here so a failure to build one is
/// an error the test returns.
fn on_runtime(test: impl std::future::Future<Output = R>) -> R {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("the runtime: {e}"))?
        .block_on(test)
}

fn why(what: &str) -> impl Fn(std::io::Error) -> String + '_ {
    move |e| format!("{what}: {e}")
}

/// One SMTP conversation: every command is accepted and DATA is kept.
async fn converse(socket: TcpStream, store: Arc<Mutex<Vec<String>>>) -> R {
    let (read, mut write) = socket.into_split();
    let mut lines = BufReader::new(read).lines();
    write
        .write_all(b"220 sink ESMTP\r\n")
        .await
        .map_err(why("greet"))?;
    let mut data = String::new();
    let mut phase = "commands";
    while let Some(line) = lines.next_line().await.map_err(why("read"))? {
        if phase == "data" {
            if line == "." {
                phase = "commands";
                store.lock().await.push(std::mem::take(&mut data));
                write
                    .write_all(b"250 kept\r\n")
                    .await
                    .map_err(why("kept"))?;
            } else {
                data.push_str(&line);
                data.push('\n');
            }
            continue;
        }
        let verb = line
            .split_whitespace()
            .next()
            .map_or(String::new(), str::to_uppercase);
        let reply: &[u8] = match verb.as_str() {
            "EHLO" | "HELO" => b"250 sink\r\n",
            "DATA" => {
                phase = "data";
                b"354 go on\r\n"
            }
            "QUIT" => {
                write.write_all(b"221 bye\r\n").await.map_err(why("bye"))?;
                return Ok(());
            }
            _ => b"250 ok\r\n",
        };
        write.write_all(reply).await.map_err(why("reply"))?;
    }
    Ok(())
}

/// A mail server that accepts every message and keeps its DATA.
async fn mail_server() -> R<(u16, Arc<Mutex<Vec<String>>>)> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(why("bind smtp"))?;
    let port = listener.local_addr().map_err(why("smtp addr"))?.port();
    let kept = Arc::new(Mutex::new(Vec::new()));
    let store = kept.clone();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let store = store.clone();
            tokio::spawn(async move {
                if let Err(e) = converse(socket, store).await {
                    panic!("the mail server's conversation failed: {e}");
                }
            });
        }
    });
    Ok((port, kept))
}

/// The service on a local port, sending through `smtp_port`, as the binary
/// serves it.
async fn service(smtp_port: u16, per_device: usize) -> R<String> {
    let rates = Rates {
        per_device,
        per_recipient: 10,
        window: Duration::from_secs(3600),
    };
    service_with(smtp_port, rates, Bounds::DEPLOYED).await
}

/// The service with `rates` and `bounds`, its address and the URL it takes
/// receipts at.
async fn service_with(smtp_port: u16, rates: Rates, bounds: Bounds) -> R<String> {
    Ok(format!(
        "http://{}/v1/receipt",
        served(smtp_port, rates, bounds).await?
    ))
}

async fn served(smtp_port: u16, rates: Rates, bounds: Bounds) -> R<std::net::SocketAddr> {
    let mailer = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("127.0.0.1")
        .port(smtp_port)
        .build();
    let from = "DSM Receipts <receipts@example.com>"
        .parse()
        .map_err(|e| format!("from: {e}"))?;
    let svc = Arc::new(Service::new(mailer, from, rates, bounds.in_flight));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(why("bind http"))?;
    let addr = listener.local_addr().map_err(why("http addr"))?;
    let listener = listener.into_std().map_err(why("the listener"))?;
    tokio::spawn(async move {
        if let Err(e) = serve(listener, svc, bounds).await {
            panic!("the service stopped: {e}");
        }
    });
    Ok(addr)
}

fn request(public_key: &[u8]) -> pb::ReceiptEmailRequestV1 {
    pb::ReceiptEmailRequestV1 {
        to_email: "jane@example.com".into(),
        sender_name: "Dana <b>".into(),
        token: "ERA".into(),
        amount: "50".into(),
        memo: "Thanks for lunch!".into(),
        reference: "7KQ2ABCD".into(),
        sent_at_local: "10/9/2026, 9:20 AM".into(),
        sender_device_id: vec![0x44; 32],
        sender_signing_public_key: public_key.to_vec(),
        signature: Vec::new(),
    }
}

fn signed(mut r: pb::ReceiptEmailRequestV1, secret_key: &[u8]) -> R<pb::ReceiptEmailRequestV1> {
    r.signature = dsm::crypto::sphincs::sphincs_sign(secret_key, &signing_digest(&r))
        .map_err(|e| format!("sign: {e}"))?;
    Ok(r)
}

fn keys() -> R<(Vec<u8>, Vec<u8>)> {
    dsm::crypto::sphincs::generate_sphincs_keypair().map_err(|e| format!("keys: {e}"))
}

async fn post(url: &str, r: &pb::ReceiptEmailRequestV1) -> R<(u16, Vec<u8>)> {
    let response = reqwest::Client::new()
        .post(url)
        .body(r.encode_to_vec())
        .send()
        .await
        .map_err(|e| format!("post: {e}"))?;
    let status = response.status().as_u16();
    Ok((
        status,
        response
            .bytes()
            .await
            .map_err(|e| format!("body: {e}"))?
            .to_vec(),
    ))
}

#[test]
fn a_signed_request_is_emailed_once_and_answered_masked() -> R {
    on_runtime(async {
        let (smtp, kept) = mail_server().await?;
        let url = service(smtp, 5).await?;
        let (pk, sk) = keys()?;

        let (status, body) = post(&url, &signed(request(&pk), &sk)?).await?;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        let answer = pb::ReceiptEmailResultV1::decode(body.as_slice())
            .map_err(|e| format!("result: {e}"))?;
        assert_eq!(answer.sent_to_masked, "j…@example.com");

        let mail = kept.lock().await.clone();
        assert_eq!(mail.len(), 1);
        let message = &mail[0];
        assert!(message.contains("To: jane@example.com"), "{message}");
        assert!(message.contains("Thanks for lunch!"), "{message}");
        assert!(message.contains("Reference: 7KQ2ABCD"), "{message}");
        // The sender's name is escaped in the HTML part, never markup.
        assert!(message.contains("Dana &lt;b&gt;"), "{message}");
        Ok(())
    })
}

#[test]
fn an_unsigned_a_wrongly_signed_or_a_redirected_request_sends_nothing() -> R {
    on_runtime(async {
        let (smtp, kept) = mail_server().await?;
        let url = service(smtp, 5).await?;
        let (pk, sk) = keys()?;
        let (_, other_sk) = keys()?;

        assert_eq!(post(&url, &request(&pk)).await?.0, 401);
        assert_eq!(post(&url, &signed(request(&pk), &other_sk)?).await?.0, 401);
        let redirected = pb::ReceiptEmailRequestV1 {
            to_email: "eve@example.com".into(),
            ..signed(request(&pk), &sk)?
        };
        assert_eq!(post(&url, &redirected).await?.0, 401);
        assert_eq!(kept.lock().await.len(), 0);
        Ok(())
    })
}

#[test]
fn a_device_over_its_rate_is_refused_and_nothing_more_is_sent() -> R {
    on_runtime(async {
        let (smtp, kept) = mail_server().await?;
        let url = service(smtp, 2).await?;
        let (pk, sk) = keys()?;
        let one = signed(request(&pk), &sk)?;
        assert_eq!(post(&url, &one).await?.0, 200);
        assert_eq!(post(&url, &one).await?.0, 200);
        let (status, body) = post(&url, &one).await?;
        assert_eq!(status, 429, "{}", String::from_utf8_lossy(&body));
        assert_eq!(kept.lock().await.len(), 2);
        Ok(())
    })
}

/// The rate a recipient is held to counts the address the mail goes to:
/// another spelling of the same inbox counts against it, and a display-name
/// form that would deliver to it is refused outright.
#[test]
fn a_recipients_rate_counts_every_spelling_of_its_inbox() -> R {
    on_runtime(async {
        let (smtp, kept) = mail_server().await?;
        let rates = Rates {
            per_device: 10,
            per_recipient: 1,
            window: Duration::from_secs(3600),
        };
        let url = service_with(smtp, rates, Bounds::DEPLOYED).await?;
        let (pk, sk) = keys()?;
        let to = |email: &str| -> R<pb::ReceiptEmailRequestV1> {
            signed(
                pb::ReceiptEmailRequestV1 {
                    to_email: email.into(),
                    ..request(&pk)
                },
                &sk,
            )
        };
        assert_eq!(post(&url, &to("jane@example.com")?).await?.0, 200);
        for spelling in ["Jane@Example.com", "jane+again@example.com"] {
            let (status, body) = post(&url, &to(spelling)?).await?;
            assert_eq!(
                status,
                429,
                "{spelling}: {}",
                String::from_utf8_lossy(&body)
            );
        }
        let (status, body) = post(&url, &to("Eve <jane@example.com>")?).await?;
        assert_eq!(status, 400, "{}", String::from_utf8_lossy(&body));
        assert_eq!(kept.lock().await.len(), 1);
        Ok(())
    })
}

/// A device is counted by the key it signs under: a fresh device id under
/// the same key is the same device, and is held to its rate.
#[test]
fn a_fresh_device_id_under_the_same_key_is_the_same_device() -> R {
    on_runtime(async {
        let (smtp, kept) = mail_server().await?;
        let url = service(smtp, 1).await?;
        let (pk, sk) = keys()?;
        assert_eq!(post(&url, &signed(request(&pk), &sk)?).await?.0, 200);
        let renamed = pb::ReceiptEmailRequestV1 {
            sender_device_id: vec![0x45; 32],
            to_email: "john@example.com".into(),
            ..request(&pk)
        };
        let (status, body) = post(&url, &signed(renamed, &sk)?).await?;
        assert_eq!(status, 429, "{}", String::from_utf8_lossy(&body));
        assert_eq!(kept.lock().await.len(), 1);
        Ok(())
    })
}

/// A mail server that takes connections and never greets: every send to it
/// waits on it.
async fn silent_mail_server() -> R<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(why("bind smtp"))?;
    let port = listener.local_addr().map_err(why("smtp addr"))?.port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            held.push(socket);
        }
    });
    Ok(port)
}

/// With room for one request at a time, a request held on a mail server that
/// never answers leaves the next one answered `503` at once, not queued; and
/// the held request is answered `408` once the request time has passed.
#[test]
fn a_busy_service_answers_at_once_and_a_held_request_is_cut_off() -> R {
    on_runtime(async {
        let smtp = silent_mail_server().await?;
        let rates = Rates {
            per_device: 10,
            per_recipient: 10,
            window: Duration::from_secs(3600),
        };
        let bounds = Bounds {
            in_flight: 1,
            request_time: Duration::from_secs(2),
            ..Bounds::DEPLOYED
        };
        let url = service_with(smtp, rates, bounds).await?;
        let (pk, sk) = keys()?;
        let one = signed(request(&pk), &sk)?;
        let started = std::time::Instant::now();
        let held = tokio::spawn({
            let (url, one) = (url.clone(), one.clone());
            async move { post(&url, &one).await }
        });
        tokio::time::sleep(Duration::from_millis(500)).await;
        let busy = tokio::time::timeout(Duration::from_secs(1), post(&url, &one))
            .await
            .map_err(|e| format!("a request was queued behind the one in flight: {e}"))??;
        assert_eq!(busy.0, 503, "{}", String::from_utf8_lossy(&busy.1));
        let held = tokio::time::timeout(Duration::from_secs(10), held)
            .await
            .map_err(|e| format!("the held request was never cut off: {e}"))?
            .map_err(|e| format!("task: {e}"))??;
        assert_eq!(held.0, 408, "{}", String::from_utf8_lossy(&held.1));
        assert!(started.elapsed() >= Duration::from_secs(2));
        Ok(())
    })
}

/// A connection that never finishes sending a request's headers is closed
/// once the header time has passed, instead of being held open.
#[test]
fn a_connection_that_never_finishes_its_headers_is_closed() -> R {
    use tokio::io::AsyncReadExt;
    on_runtime(async {
        let smtp = silent_mail_server().await?;
        let rates = Rates {
            per_device: 10,
            per_recipient: 10,
            window: Duration::from_secs(3600),
        };
        let header_read = Duration::from_secs(1);
        let bounds = Bounds {
            header_read,
            ..Bounds::DEPLOYED
        };
        let addr = served(smtp, rates, bounds).await?;
        let mut socket = TcpStream::connect(addr).await.map_err(why("connect"))?;
        socket
            .write_all(b"POST /v1/receipt HTTP/1.1\r\nhost: receipts\r\n")
            .await
            .map_err(why("half of a request's headers"))?;
        let opened = std::time::Instant::now();
        let mut rest = Vec::new();
        match tokio::time::timeout(Duration::from_secs(10), socket.read_to_end(&mut rest)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            Ok(Err(e)) => return Err(format!("the connection ended in an error: {e}")),
            Err(elapsed) => {
                return Err(format!(
                    "a connection that never finished its headers was held open: {elapsed}"
                ))
            }
        }
        assert!(
            opened.elapsed() >= header_read.mul_f32(0.9),
            "closed after {:?}, before the header time",
            opened.elapsed()
        );
        Ok(())
    })
}
