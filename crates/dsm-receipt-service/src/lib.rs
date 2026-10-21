// SPDX-License-Identifier: MIT OR Apache-2.0
//! The DSM receipt service (DSM Amendment A17).
//!
//! A wallet that has receipts switched on posts a `ReceiptEmailRequestV1`
//! after a send: the recipient's email, the sender's name, what was sent, the
//! transfer's hash and the phone's time, signed by the sender device's AK over
//! `H(DSM/receipt-email ‖ the request with an empty signature)`. The service
//! checks the signature and the fields, holds each device and each recipient
//! to a rate, and emails one fixed, plain receipt.
//!
//! A device is counted by the key its request is signed under, the one thing
//! about the sender the signature binds: the device id beside it is a claim
//! the request makes, and DSM derives it from the key and an attestation
//! digest the request does not carry. A recipient is counted by the address
//! the receipt is delivered to, read once and used for both.
//!
//! Outside the DSM protocol: the service decides nothing about any transfer,
//! keeps no record of who was emailed, and logs no address. The signature
//! proves a device asked; it does not prove the device is in the network's
//! directory, and the service does not read the directory (an open item of
//! A17, stated in its CONFORMANCE row).

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use dsm::common::domain_tags::TAG_DSM_RECEIPT_EMAIL;
use dsm::crypto::blake3::domain_hash;
use dsm::types::proto as pb;
use prost::Message;
use tokio::time::Instant;

/// Why a request is refused, and the HTTP status that says so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub status: u16,
    pub reason: String,
}

impl Refusal {
    fn bad(reason: impl Into<String>) -> Self {
        Self {
            status: 400,
            reason: reason.into(),
        }
    }
    fn unsigned(reason: impl Into<String>) -> Self {
        Self {
            status: 401,
            reason: reason.into(),
        }
    }
    fn too_many(reason: impl Into<String>) -> Self {
        Self {
            status: 429,
            reason: reason.into(),
        }
    }
}

/// The 32 bytes the sender's AK signs.
pub fn signing_digest(request: &pb::ReceiptEmailRequestV1) -> [u8; 32] {
    let unsigned = pb::ReceiptEmailRequestV1 {
        signature: Vec::new(),
        ..request.clone()
    };
    *domain_hash(TAG_DSM_RECEIPT_EMAIL, &unsigned.encode_to_vec()).as_bytes()
}

const LIMITS: [(&str, usize); 7] = [
    ("email", 254),
    ("name", 64),
    ("currency", 32),
    ("amount", 64),
    ("note", 256),
    ("reference", 64),
    ("time", 64),
];

/// A request decoded from its body, refused unless it is the canonical
/// encoding of a whole, signed request.
pub fn read_request(body: &[u8]) -> Result<pb::ReceiptEmailRequestV1, Refusal> {
    let request = pb::ReceiptEmailRequestV1::decode(body)
        .map_err(|e| Refusal::bad(format!("the body is not a receipt request: {e}")))?;
    if request.encode_to_vec() != body {
        return Err(Refusal::bad("the request is not in its canonical encoding"));
    }
    check(&request)?;
    Ok(request)
}

/// Every field within its bounds and free of control characters, an email
/// that is an address, and the sender's signature over the rest.
pub fn check(request: &pb::ReceiptEmailRequestV1) -> Result<(), Refusal> {
    let fields = [
        &request.to_email,
        &request.sender_name,
        &request.token,
        &request.amount,
        &request.memo,
        &request.reference,
        &request.sent_at_local,
    ];
    for ((field, max), value) in LIMITS.iter().zip(fields) {
        if value.chars().count() > *max {
            return Err(Refusal::bad(format!(
                "the {field} is longer than {max} characters"
            )));
        }
        if value.chars().any(char::is_control) {
            return Err(Refusal::bad(format!(
                "the {field} holds a control character"
            )));
        }
    }
    if request.amount.is_empty() || request.token.is_empty() || request.reference.is_empty() {
        return Err(Refusal::bad(
            "a receipt names an amount, a currency and a transfer",
        ));
    }
    recipient(request)?;
    if request.sender_device_id.len() != 32 || request.sender_signing_public_key.len() != 64 {
        return Err(Refusal::bad(
            "the sender's device id is 32 bytes and its key 64",
        ));
    }
    match dsm::crypto::sphincs::sphincs_verify(
        &request.sender_signing_public_key,
        &signing_digest(request),
        &request.signature,
    ) {
        Ok(verified) if verified => Ok(()),
        Ok(..) => Err(Refusal::unsigned(
            "the signature does not verify under the sender's key",
        )),
        Err(e) => Err(Refusal::unsigned(format!(
            "the signature cannot be checked: {e}"
        ))),
    }
}

/// The address a request's receipt goes to: `to_email` when it is a bare
/// address (`user@domain.tld`) and nothing else. It is read as an address,
/// never as a mailbox: a display name, angle brackets, a second address or
/// anything after the address is refused, and the address keeps exactly the
/// text it was read from, so the address the rate is held to is the address
/// the mail is sent to.
pub fn recipient(request: &pb::ReceiptEmailRequestV1) -> Result<lettre::Address, Refusal> {
    let not_an_address = || Refusal::bad("the email is not an address");
    let address: lettre::Address = request
        .to_email
        .parse()
        .map_err(|_unparsed: lettre::address::AddressError| not_an_address())?;
    let domain = address.domain();
    if !domain.contains('.') || domain.starts_with('.') || domain.starts_with('[') {
        return Err(not_an_address());
    }
    Ok(address)
}

/// The mailbox an address names, as a rate counts it: the domain and the
/// user in lower case, the user without a `+` subaddress, and at Gmail
/// (`gmail.com`, `googlemail.com`) the user without its dots, which Gmail
/// ignores. Every spelling that reaches one inbox at the providers that read
/// addresses this way counts as that inbox, so a sender cannot spread one
/// person's receipts over spellings of their address (SA-153). The mail
/// itself goes to the address as given.
pub fn counted_as(address: &lettre::Address) -> String {
    let user = address.user().to_lowercase();
    let mailbox = match user.split_once('+') {
        Some((mailbox, _subaddress)) => mailbox.to_string(),
        None => user,
    };
    let domain = address.domain().to_lowercase();
    match domain.as_str() {
        "gmail.com" | "googlemail.com" => format!("{}@gmail.com", mailbox.replace('.', "")),
        _ => format!("{mailbox}@{domain}"),
    }
}

/// An email as the service may say it back: its first character, then `…`,
/// then the domain. The full address is never logged or answered.
pub fn masked(email: &str) -> String {
    match email.split_once('@') {
        Some((local, domain)) => format!("{}…@{domain}", local.chars().take(1).collect::<String>()),
        None => "…".to_string(),
    }
}

/// The receipt: one fixed template for everyone.
pub struct Receipt {
    pub subject: String,
    pub text: String,
    pub html: String,
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn render(request: &pb::ReceiptEmailRequestV1) -> Receipt {
    let paid = format!("{} {}", request.amount, request.token);
    let subject = format!("{} paid you {paid} with DSM", request.sender_name);
    let mut lines = vec![
        format!("{} paid you {paid}.", request.sender_name),
        String::new(),
        format!("Amount: {paid}"),
    ];
    if !request.memo.is_empty() {
        lines.push(format!("Note: {}", request.memo));
    }
    if !request.sent_at_local.is_empty() {
        lines.push(format!(
            "Sent (the sender's phone time): {}",
            request.sent_at_local
        ));
    }
    lines.push(format!("Reference: {}", request.reference));
    lines.push(String::new());
    lines.push(format!(
        "You get this receipt because {} paid you with the DSM wallet and asked for one. \
         The payment is in your DSM wallet; this email is only a note about it.",
        request.sender_name
    ));
    let text = lines.join("\n");
    let rows = lines
        .iter()
        .filter(|l| !l.is_empty())
        .map(|l| format!("<p>{}</p>", escape(l)))
        .collect::<String>();
    let html = format!(
        "<!doctype html><html><body style=\"font-family:system-ui,sans-serif;color:#121212\">\
         <h2 style=\"margin:0 0 12px\">{}</h2>{rows}</body></html>",
        escape(&subject)
    );
    Receipt {
        subject,
        text,
        html,
    }
}

/// How many receipts a key may ask for, and one address may get, in a window.
#[derive(Debug, Clone, Copy)]
pub struct Rates {
    pub per_device: usize,
    pub per_recipient: usize,
    pub window: Duration,
}

/// Counts per device and per recipient over a sliding window, in memory: a
/// restart forgets them, and nothing else is kept. Every count is let go once
/// its window has passed, so what the limiter holds is what the window holds.
pub struct RateLimiter {
    rates: Rates,
    /// Receipts admitted within the window, per key.
    counts: HashMap<Vec<u8>, usize>,
    /// Every admitted receipt's keys, oldest first, with when it was
    /// admitted: the order counts are let go in.
    admitted: VecDeque<(Instant, Vec<u8>)>,
}

impl RateLimiter {
    pub fn new(rates: Rates) -> Self {
        Self {
            rates,
            counts: HashMap::new(),
            admitted: VecDeque::new(),
        }
    }

    /// The keys the limiter holds a count for.
    pub fn tracked(&self) -> usize {
        self.counts.len()
    }

    /// Admits one receipt signed under `signer` to `recipient` (as
    /// [`counted_as`] names it), or refuses it when either is over its rate.
    /// A refused request counts against neither.
    pub fn admit(&mut self, signer: &[u8], recipient: &str, now: Instant) -> Result<(), Refusal> {
        while let Some((when, _)) = self.admitted.front() {
            if now.duration_since(*when) < self.rates.window {
                break;
            }
            if let Some((_, key)) = self.admitted.pop_front() {
                if let Some(count) = self.counts.get_mut(&key) {
                    *count -= 1;
                    if *count == 0 {
                        self.counts.remove(&key);
                    }
                }
            }
        }
        let device_key = [b"d:".as_slice(), signer].concat();
        let email_key = [b"e:".as_slice(), recipient.as_bytes()].concat();
        let count = |key: &Vec<u8>| self.counts.get(key).map_or(0, |n| *n);
        if count(&device_key) >= self.rates.per_device {
            return Err(Refusal::too_many(
                "this device has asked for too many receipts; try later",
            ));
        }
        if count(&email_key) >= self.rates.per_recipient {
            return Err(Refusal::too_many(
                "this address has had too many receipts; try later",
            ));
        }
        for key in [device_key, email_key] {
            *self.counts.entry(key.clone()).or_insert(0) += 1;
            self.admitted.push_back((now, key));
        }
        Ok(())
    }
}

pub mod server;

#[cfg(test)]
mod tests {
    use super::*;

    fn req(memo: &str) -> pb::ReceiptEmailRequestV1 {
        pb::ReceiptEmailRequestV1 {
            to_email: "jane@example.com".into(),
            sender_name: "Dana".into(),
            token: "ERA".into(),
            amount: "50".into(),
            memo: memo.into(),
            reference: "7KQ2".into(),
            sent_at_local: String::new(),
            sender_device_id: vec![1; 32],
            sender_signing_public_key: vec![2; 64],
            signature: Vec::new(),
        }
    }

    #[test]
    fn the_receipt_says_who_paid_what_and_escapes_markup() {
        let r = render(&req("<script>x</script> & co"));
        assert_eq!(r.subject, "Dana paid you 50 ERA with DSM");
        assert!(
            r.text.contains("Note: <script>x</script> & co"),
            "{}",
            r.text
        );
        assert!(
            r.html
                .contains("Note: &lt;script&gt;x&lt;/script&gt; &amp; co"),
            "{}",
            r.html
        );
        assert!(!r.html.contains("<script>"), "{}", r.html);
        assert!(
            !r.text.contains("Sent (the sender's phone time)"),
            "no time was given: {}",
            r.text
        );
    }

    #[test]
    fn an_address_is_said_back_masked() {
        assert_eq!(masked("jane@example.com"), "j…@example.com");
    }

    #[test]
    fn a_recipient_over_its_rate_is_refused_until_the_window_passes() {
        let rates = Rates {
            per_device: 10,
            per_recipient: 2,
            window: Duration::from_secs(60),
        };
        let mut limiter = RateLimiter::new(rates);
        let t0 = Instant::now();
        assert_eq!(limiter.admit(&[1; 32], "jane@example.com", t0), Ok(()));
        assert_eq!(limiter.admit(&[2; 32], "jane@example.com", t0), Ok(()));
        assert_eq!(
            limiter
                .admit(&[3; 32], "jane@example.com", t0)
                .map_err(|r| r.status),
            Err(429),
        );
        assert_eq!(
            limiter.admit(&[3; 32], "jane@example.com", t0 + rates.window),
            Ok(())
        );
    }

    /// Every count is let go once its window has passed: a thousand senders
    /// to a thousand addresses leave nothing held a window later but the
    /// receipt admitted then.
    #[test]
    fn counts_are_let_go_once_their_window_has_passed() {
        let rates = Rates {
            per_device: 10,
            per_recipient: 10,
            window: Duration::from_secs(60),
        };
        let mut limiter = RateLimiter::new(rates);
        let t0 = Instant::now();
        for i in 0..1000u32 {
            let signer = i.to_be_bytes();
            assert_eq!(
                limiter.admit(&signer, &format!("p{i}@example.com"), t0),
                Ok(())
            );
        }
        assert_eq!(limiter.tracked(), 2000);
        assert_eq!(
            limiter.admit(b"later", "later@example.com", t0 + rates.window),
            Ok(())
        );
        assert_eq!(
            limiter.tracked(),
            2,
            "only the receipt admitted now is held"
        );
    }

    /// The address a rate counts is the address the mail goes to: a display
    /// name, a second address or anything after the address is refused, and
    /// spellings of one inbox count as that inbox.
    #[test]
    fn only_a_bare_address_is_a_recipient_and_its_spellings_count_as_one() {
        let to = |email: &str| pb::ReceiptEmailRequestV1 {
            to_email: email.into(),
            ..req("")
        };
        for refused in [
            "Eve <jane@example.com>",
            "<jane@example.com>",
            "jane@example.com extra",
            "jane@example.com, eve@example.com",
            "jane@localhost",
            "jane@[127.0.0.1]",
            " jane@example.com",
        ] {
            assert_eq!(
                recipient(&to(refused)).map_err(|r| r.status),
                Err(400),
                "{refused:?} is not a bare address"
            );
        }
        let counted = |email: &str| match recipient(&to(email)) {
            Ok(address) => counted_as(&address),
            Err(refusal) => panic!("{email:?}: {}", refusal.reason),
        };
        assert_eq!(counted("jane@example.com"), "jane@example.com");
        assert_eq!(counted("Jane@Example.COM"), "jane@example.com");
        assert_eq!(counted("jane+receipts@example.com"), "jane@example.com");
        // Gmail ignores the dots in a user and answers at both of its domains.
        assert_eq!(counted("j.ane@gmail.com"), "jane@gmail.com");
        assert_eq!(counted("ja.ne+x@GoogleMail.com"), "jane@gmail.com");
        assert_eq!(counted("j.ane@example.com"), "j.ane@example.com");
    }

    #[test]
    fn a_field_with_a_control_character_or_no_address_is_refused() {
        assert_eq!(
            check(&req("a\u{7}")).map_err(|r| r.reason),
            Err("the note holds a control character".into()),
        );
        let no_address = pb::ReceiptEmailRequestV1 {
            to_email: "jane".into(),
            ..req("")
        };
        assert_eq!(
            check(&no_address).map_err(|r| r.reason),
            Err("the email is not an address".into())
        );
    }
}
