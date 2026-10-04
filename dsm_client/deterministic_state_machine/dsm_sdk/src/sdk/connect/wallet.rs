// SPDX-License-Identifier: MIT OR Apache-2.0

//! The wallet's side of DSM Connect (DSM Amendment A11), apart from the
//! routes: verifying an offer, rendering scopes and requests for the player,
//! and the background listener that keeps connected applications' requests
//! flowing while the wallet runs.
//!
//! The listener only asks the installed app router for `connect.sync`, the
//! same route a screen may call: every request is decided against its grant
//! and carried out by the router's own production routes, exactly as if the
//! player had started it by hand.

use std::collections::BTreeSet;
use std::time::Duration;

use dsm::types::proto as generated;
use prost::Message;

use super::d32;
use super::grant::{scopes_from_wire, Request, Scope, ScopeKind};
use super::signed::{canonical, card_identity, offer_digest, own_network, verify, CardIdentity, Signed};
use crate::util::text_id::encode_base32_crockford;

/// The longest display name an offer may carry.
pub const MAX_DISPLAY_NAME: usize = 64;

/// An offer whose digest, encoding, card and signature checked.
#[derive(Debug, Clone)]
pub struct VerifiedOffer {
    pub digest: [u8; 32],
    pub body: generated::AppConnectOfferBodyV1,
    pub app: CardIdentity,
    pub scopes: Vec<Scope>,
    pub anchors: Vec<[u8; 32]>,
}

/// Check an offer served at `endpoint` as the one a code named by `digest`:
/// its bytes hash to the digest, are canonical, name the endpoint, carry a
/// card whose AK derives its device on this device's network, and are signed
/// under that AK as an offer.
pub fn verify_offer(
    offer: &generated::AppConnectOfferV1,
    endpoint: &str,
    digest: &[u8; 32],
) -> Result<VerifiedOffer, String> {
    if &offer_digest(&offer.body) != digest {
        return Err("the endpoint served another offer than the code names".into());
    }
    let body: generated::AppConnectOfferBodyV1 = canonical(&offer.body, "the offer")?;
    if body.endpoint != endpoint {
        return Err("the offer names another endpoint than the code".into());
    }
    let name = body.display_name.trim();
    if name.is_empty() || body.display_name.len() > MAX_DISPLAY_NAME {
        return Err(format!(
            "an application's name is 1 to {MAX_DISPLAY_NAME} bytes"
        ));
    }
    d32(&body.nonce, "the offer's nonce")?;
    let card = body
        .app_card
        .as_ref()
        .ok_or_else(|| "the offer carries no contact card".to_string())?;
    let app = card_identity(card, &body.app_att_a, &own_network()?)?;
    verify(Signed::Offer, &offer.body, &app.ak, &offer.signature)?;
    let scopes = scopes_from_wire(&body.scopes)?;
    let mut anchors = Vec::with_capacity(body.token_anchors.len());
    for a in &body.token_anchors {
        let a = d32(a, "an offered anchor")?;
        if anchors.contains(&a) {
            return Err("the offer names one anchor twice".into());
        }
        anchors.push(a);
    }
    Ok(VerifiedOffer {
        digest: *digest,
        body,
        app,
        scopes,
        anchors,
    })
}

/// The grant a session's signed accept body carries.
pub fn granted_scopes(accept_body: &[u8]) -> Result<Vec<Scope>, String> {
    let body: generated::AppConnectAcceptBodyV1 = canonical(accept_body, "the stored accept")?;
    scopes_from_wire(&body.granted)
}

/// A token as the player reads it: its symbol and an amount in its decimals,
/// or its anchor's first characters while this device has not rooted it.
fn amount_of(policy_commit: &[u8; 32], amount: u64) -> String {
    match crate::handlers::wallet_routes::token_of_commit(policy_commit) {
        Ok((symbol, decimals)) => format!(
            "{} {symbol}",
            crate::handlers::wallet_routes::format_base_units_for_display(amount, decimals)
        ),
        Err(..) => format!("{amount} base units of {}", short(policy_commit)),
    }
}

fn symbol_of(policy_commit: &[u8; 32]) -> String {
    match crate::handlers::wallet_routes::token_of_commit(policy_commit) {
        Ok((symbol, _)) => symbol,
        Err(..) => short(policy_commit),
    }
}

/// The first eight Base32 characters of a 32-byte id.
pub fn short(id: &[u8; 32]) -> String {
    encode_base32_crockford(id).chars().take(8).collect()
}

/// One scope, as the approval screen lists it.
pub fn describe_scope(scope: &Scope) -> String {
    let caps = |s: &Scope| {
        s.caps
            .iter()
            .map(|c| {
                format!(
                    "up to {} a time, {} in all",
                    amount_of(&c.policy_commit, c.per_request),
                    amount_of(&c.policy_commit, c.total)
                )
            })
            .collect::<Vec<_>>()
            .join("; ")
    };
    match scope.kind {
        ScopeKind::AcceptIssued => "Receive objects this app issues".to_string(),
        ScopeKind::Pay => format!("Pay this app: {}", caps(scope)),
        ScopeKind::Swap => match scope.policy_commits.as_slice() {
            [a, b] => format!(
                "Swap {} for {} through SoFi: {}",
                symbol_of(a),
                symbol_of(b),
                caps(scope)
            ),
            other => format!(
                "Swap among {} tokens through SoFi: {}",
                other.len(),
                caps(scope)
            ),
        },
        ScopeKind::Holdings => {
            let named: Vec<String> = scope.policy_commits.iter().map(symbol_of).collect();
            if named.is_empty() {
                "Prove your holdings of objects this app issued".to_string()
            } else {
                format!(
                    "Prove your holdings of {} and of objects this app issued",
                    named.join(", ")
                )
            }
        }
    }
}

/// One request, as the pending list and the log render it.
pub fn describe_request(request: &Request) -> String {
    match request {
        Request::AcceptIssued { anchor } => format!("Receive object {}", short(anchor)),
        Request::Pay {
            policy_commit,
            amount,
            memo,
        } => {
            let paid = amount_of(policy_commit, *amount);
            match memo.trim() {
                "" => format!("Pay {paid}"),
                memo => format!("Pay {paid} for {memo}"),
            }
        }
        Request::Quote {
            token_in,
            token_out,
            amount_in,
        } => format!(
            "Quote {} for {}",
            amount_of(token_in, *amount_in),
            symbol_of(token_out)
        ),
        Request::Swap {
            token_in,
            token_out,
            amount_in,
            min_amount_out,
        } => format!(
            "Swap {} for at least {}",
            amount_of(token_in, *amount_in),
            amount_of(token_out, *min_amount_out)
        ),
        Request::Holdings { policy_commits } => format!(
            "Prove holdings of {}",
            policy_commits
                .iter()
                .map(symbol_of)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// The tokens on this device whose committed policy names `app_device_id` as
/// its creating device.
pub fn issued_by(app_device_id: &[u8; 32]) -> Result<BTreeSet<[u8; 32]>, String> {
    let rows = crate::storage::client_db::token_registry::all_tokens()
        .map_err(|e| format!("the token registry: {e}"))?;
    let mut issued = BTreeSet::new();
    for row in rows {
        if &row.creator_device_id == app_device_id {
            issued.insert(row.policy_commit);
        }
    }
    Ok(issued)
}

/// The memo a payment to a connected application carries: the session and
/// request it answers, then what it is for. It rides inside the transfer's
/// terms, which the signed operation commits to, so the application reads it
/// from the transfer it accepted, never from the relay.
pub fn payment_memo(session_id: &[u8; 32], seq: u64, memo: &str) -> String {
    let what: String = memo.trim().chars().take(96).collect();
    format!("{} {what}", payment_ref(session_id, seq))
        .trim_end()
        .to_string()
}

/// The reference a payment memo starts with.
pub fn payment_ref(session_id: &[u8; 32], seq: u64) -> String {
    format!("dsm-connect:{}:{seq}", encode_base32_crockford(session_id))
}

// ------------------------------- the listener -------------------------------

/// The running listener, if one is.
static LISTENER: once_cell::sync::Lazy<std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(None));

/// How long to wait after a cycle that could not run before the next one.
const RETRY_AFTER: Duration = Duration::from_secs(3);

/// Start the listener unless one is running. It ends by itself once no
/// application is connected; approving one starts it again.
pub fn start_listener() -> Result<(), String> {
    // The two-device harness drives `connect.sync` itself, one device at a
    // time, as it drives `storage.sync`: no background task runs behind it.
    #[cfg(test)]
    if crate::sdk::inbox_poller::background_held() {
        return Ok(());
    }
    let mut slot = LISTENER
        .lock()
        .map_err(|e| format!("the connect listener's slot: {e}"))?;
    if let Some(handle) = slot.as_ref() {
        if !handle.is_finished() {
            return Ok(());
        }
    }
    *slot = Some(crate::runtime::get_runtime().spawn(listen()));
    Ok(())
}

/// Start the listener when the wallet starts again with an application still
/// connected: approving or answering one starts it otherwise.
pub fn resume_listener() -> Result<(), String> {
    let connected = crate::storage::client_db::connect::sessions()
        .map_err(|e| format!("the connected applications: {e}"))?
        .iter()
        .any(|s| s.connected == crate::storage::client_db::connect::SessionStatus::Connected);
    if connected {
        start_listener()?;
    }
    Ok(())
}

async fn listen() {
    log::info!("[connect] listener started");
    loop {
        let Some(router) = crate::bridge::app_router() else {
            tokio::time::sleep(RETRY_AFTER).await;
            continue;
        };
        let result = router
            .invoke(crate::bridge::AppInvoke {
                method: "connect.sync".into(),
                args: Vec::new(),
            })
            .await;
        if !result.success {
            log::warn!(
                "[connect] a sync cycle did not run: {:?}",
                result.error_message
            );
            tokio::time::sleep(RETRY_AFTER).await;
            continue;
        }
        match crate::handlers::response_helpers::decode_local_envelope(&result.data) {
            Ok(generated::Envelope {
                payload:
                    Some(generated::envelope::Payload::ConnectReply(generated::ConnectReplyV1 {
                        reply: Some(generated::connect_reply_v1::Reply::Sessions(s)),
                    })),
                ..
            }) => {
                if s.sessions.is_empty() {
                    break;
                }
            }
            other => {
                log::warn!("[connect] a sync cycle answered {other:?}, not the sessions");
                tokio::time::sleep(RETRY_AFTER).await;
            }
        }
    }
    log::info!("[connect] listener stopped: no application is connected");
}

/// Encode an `AppResponseV1` the wallet signed over `body`.
pub fn signed_response(body: &generated::AppResponseBodyV1) -> Result<Vec<u8>, String> {
    let bytes = body.encode_to_vec();
    let signature = super::signed::sign_own(Signed::Response, &bytes)?;
    Ok(generated::AppResponseV1 {
        body: bytes,
        signature,
    }
    .encode_to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_payment_memo_names_its_session_and_request() {
        let session = [3u8; 32];
        let memo = payment_memo(&session, 7, "1 capsule");
        assert!(memo.starts_with(&payment_ref(&session, 7)));
        assert!(memo.ends_with("1 capsule"));
        assert_ne!(payment_ref(&session, 7), payment_ref(&session, 8));
        assert_eq!(payment_memo(&session, 7, "  "), payment_ref(&session, 7));
    }
}
