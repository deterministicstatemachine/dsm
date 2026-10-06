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

use std::collections::{BTreeMap, BTreeSet};
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
/// An amount as the player reads it, by what this device has rooted.
pub(crate) fn amount_text(policy_commit: &[u8; 32], amount: u64) -> String {
    amount_of(policy_commit, amount, &Names::new())
}

fn amount_of(policy_commit: &[u8; 32], amount: u64, names: &Names) -> String {
    match name_of(policy_commit, names) {
        Some((symbol, decimals)) => format!(
            "{} {symbol}",
            crate::handlers::wallet_routes::format_base_units_for_display(amount, decimals)
        ),
        None => format!("{amount} base units of {}", short(policy_commit)),
    }
}

/// Tokens the approval screen names before this device has rooted them:
/// each one's ticker and decimals from a policy fetched and re-hashed to its
/// anchor. For display only; nothing is adopted.
pub type Names = BTreeMap<[u8; 32], (String, u32)>;

/// A token's ticker and decimals: as this device has rooted it, or as
/// `names` carries it.
fn name_of(policy_commit: &[u8; 32], names: &Names) -> Option<(String, u32)> {
    match crate::handlers::wallet_routes::token_of_commit(policy_commit) {
        Ok(named) => Some(named),
        Err(..) => names.get(policy_commit).cloned(),
    }
}

fn symbol_of(policy_commit: &[u8; 32], names: &Names) -> String {
    match name_of(policy_commit, names) {
        Some((symbol, _)) => symbol,
        None => short(policy_commit),
    }
}

/// The first eight Base32 characters of a 32-byte id.
pub fn short(id: &[u8; 32]) -> String {
    encode_base32_crockford(id).chars().take(8).collect()
}

/// One scope, as the approval screen lists it.
pub fn describe_scope(scope: &Scope, names: &Names) -> String {
    let caps = |s: &Scope| {
        s.caps
            .iter()
            .map(|c| {
                format!(
                    "up to {} a time, {} in all",
                    amount_of(&c.policy_commit, c.per_request, names),
                    amount_of(&c.policy_commit, c.total, names)
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
                symbol_of(a, names),
                symbol_of(b, names),
                caps(scope)
            ),
            other => format!(
                "Swap among {} tokens through SoFi: {}",
                other.len(),
                caps(scope)
            ),
        },
        ScopeKind::Escrow => format!("Lock stakes for matches: {}", caps(scope)),
        ScopeKind::Duel => {
            let programs: Vec<String> = scope
                .programs
                .iter()
                .map(crate::sdk::outcome_programs::program_text)
                .collect();
            format!(
                "Stake {}, in battles decided by program {}, and play your moves",
                caps(scope),
                programs.join(" or ")
            )
        }
        ScopeKind::Holdings => {
            let named: Vec<String> = scope
                .policy_commits
                .iter()
                .map(|c| symbol_of(c, names))
                .collect();
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
    // A request names tokens this device rooted when it approved the grant.
    let none = Names::new();
    match request {
        Request::AcceptIssued { anchor } => format!("Receive object {}", short(anchor)),
        Request::Pay {
            policy_commit,
            amount,
            memo,
        } => {
            let paid = amount_of(policy_commit, *amount, &none);
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
            amount_of(token_in, *amount_in, &none),
            symbol_of(token_out, &none)
        ),
        Request::Swap {
            token_in,
            token_out,
            amount_in,
            min_amount_out,
        } => format!(
            "Swap {} for at least {}",
            amount_of(token_in, *amount_in, &none),
            amount_of(token_out, *min_amount_out, &none)
        ),
        Request::Holdings { policy_commits } => format!(
            "Prove holdings of {}",
            policy_commits
                .iter()
                .map(|c| symbol_of(c, &none))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Request::EscrowLock(lock) => {
            let staked = amount_of(&lock.policy_commit, lock.amount, &none);
            match lock.memo.trim() {
                "" => format!("Lock {staked} for a match"),
                memo => format!("Lock {staked} for a match ({memo})"),
            }
        }
        Request::EscrowRelease { vault_ids } => match vault_ids.len() {
            1 => "Collect a match result".to_string(),
            n => format!("Collect a match result ({n} stakes)"),
        },
        Request::DuelSessionKey { .. } => "Name your key for a battle".to_string(),
        Request::DuelLock(lock) => {
            let staked = amount_of(&lock.policy_commit, lock.amount, &none);
            let by = crate::sdk::outcome_programs::program_text(&lock.program);
            match lock.memo.trim() {
                "" => format!("Stake {staked} in a battle decided by program {by}"),
                memo => format!("Stake {staked} in a battle decided by program {by} ({memo})"),
            }
        }
        Request::DuelReady { match_cell, .. } => {
            format!("Ready for battle {}", short(match_cell))
        }
        Request::DuelWithdraw { match_cell } => {
            format!("Withdraw from battle {}", short(match_cell))
        }
        Request::DuelSign { match_cell, .. } => {
            format!("Play a move in battle {}", short(match_cell))
        }
        Request::DuelSettle { match_cell, .. } => {
            format!("Settle battle {}", short(match_cell))
        }
        Request::DuelCollect { vault_ids } => match vault_ids.len() {
            1 => "Collect a battle result".to_string(),
            n => format!("Collect a battle result ({n} stakes)"),
        },
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

/// Whether any application is connected: its requests can arrive at any time.
pub fn any_connected() -> Result<bool, String> {
    Ok(crate::storage::client_db::connect::sessions()
        .map_err(|e| format!("the connected applications: {e}"))?
        .iter()
        .any(|s| s.connected == crate::storage::client_db::connect::SessionStatus::Connected))
}

/// Start the listener when the wallet starts again with an application still
/// connected: approving or answering one starts it otherwise.
pub fn resume_listener() -> Result<(), String> {
    if any_connected()? {
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
