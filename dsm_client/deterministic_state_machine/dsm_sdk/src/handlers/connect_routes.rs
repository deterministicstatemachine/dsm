// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM Connect routes (DSM Amendment A11). Every reply is a `ConnectReplyV1`.
//!
//! The wallet's side:
//! - `connect.preview` (query): read a scanned code, fetch its offer over TLS
//!   bound to the code's pin, verify it, and render it for the player.
//! - `connect.approve`: add the application as a contact, root the anchors it
//!   offered, record the grant, sign the accept and deliver it.
//! - `connect.list`, `connect.pending`, `connect.log` (queries).
//! - `connect.respond`: the player's decision on a request outside its grant.
//! - `connect.disconnect`.
//! - `connect.sync`: fetch connected applications' requests and process them
//!   in order. The background listener calls it; a screen may too.
//!
//! The application account's side:
//! - `connect.app.offer`, `connect.app.accept`, `connect.app.request`,
//!   `connect.app.respond`, `connect.app.status` (invokes);
//! - `connect.app.requests`, `connect.app.sessions` (queries).
//!
//! A connected application may also ask a wallet to lock a stake for a match
//! it decides, and to collect the result (DSM Amendment A12). The wallet
//! builds the escrow terms itself from the match template
//! (`sdk::connect::wager`); the request names no branch, signer or recipient.
//!
//! The relay is transport, never evidence. A request inside its grant is
//! carried out by the router's own production routes, exactly as the player
//! would by hand; what the application learns from an answer is a
//! notification, and `connect.app.status` reports only what this account
//! established from DSM evidence itself.

use std::collections::{BTreeMap, BTreeSet};

use dsm::types::proto as generated;
use generated::connect_reply_v1::Reply;
use prost::Message;

use super::app_router_impl::{resolve_counterparty_via_transport, AppRouterImpl, OnlineSendIntent};
use super::response_helpers::{err, pack_envelope_ok};
use crate::bridge::{AppInvoke, AppQuery, AppResult};
use crate::sdk::connect::grant::{
    decide, narrows, request_from_wire, scopes_from_wire, scopes_to_wire, Decision, EscrowLock,
    Opponent, Request, Scope,
};
use crate::sdk::connect::wager::{self, Player, Referee};
use crate::sdk::connect::pinned_tls::Relay;
use crate::sdk::connect::signed::{
    canonical, own_card, own_network, session_id, sign_own, verify, Signed,
};
use crate::sdk::connect::wallet::{
    describe_request, describe_scope, granted_scopes, issued_by, payment_memo, short, Names,
    signed_response, verify_offer,
};
use crate::sdk::connect::{app, code, d32, holdings};
use crate::storage::client_db::connect as store;

fn reply(r: Reply) -> AppResult {
    pack_envelope_ok(generated::envelope::Payload::ConnectReply(
        generated::ConnectReplyV1 { reply: Some(r) },
    ))
}

/// A route's request: an `ArgPack` of PROTO codec carrying `T`.
fn body<T: Message + Default>(args: &[u8], route: &str) -> Result<T, String> {
    let pack = generated::ArgPack::decode(args)
        .map_err(|e| format!("{route}: decode ArgPack failed: {e}"))?;
    if pack.codec != generated::Codec::Proto as i32 {
        return Err(format!("{route}: ArgPack.codec must be PROTO"));
    }
    T::decode(&*pack.body).map_err(|e| format!("{route}: decode request failed: {e}"))
}

/// The base units of `amount` in `token`, rendered, or the raw count.
fn shown(policy_commit: &[u8; 32], amount: u64) -> (String, String) {
    match super::wallet_routes::token_of_commit(policy_commit) {
        Ok((symbol, decimals)) => (
            super::wallet_routes::format_base_units_for_display(amount, decimals),
            symbol,
        ),
        Err(..) => (amount.to_string(), short(policy_commit)),
    }
}

/// What carrying out one request produced.
struct Executed {
    outcome: generated::ConnectOutcome,
    reason: String,
    result: Option<generated::app_response_body_v1::Result>,
}

impl Executed {
    fn failed(reason: impl Into<String>) -> Self {
        Self {
            outcome: generated::ConnectOutcome::Failed,
            reason: reason.into(),
            result: None,
        }
    }

    fn carried_out(result: Option<generated::app_response_body_v1::Result>) -> Self {
        Self {
            outcome: generated::ConnectOutcome::CarriedOut,
            reason: String::new(),
            result,
        }
    }

    /// What a request carried out under its grant counts against it: its
    /// spend, only when it was carried out.
    fn spend(&self, spend: Option<([u8; 32], u64)>) -> Option<([u8; 32], u64)> {
        match self.outcome {
            generated::ConnectOutcome::CarriedOut => spend,
            _ => None,
        }
    }
}

/// How far one fetched request got.
enum Flow {
    /// Processed (carried out, declined or failed): the next may follow.
    Processed,
    /// Already processed earlier: skipped.
    Seen,
    /// Outside its grant: it waits for the player, and so does every later
    /// request of the session.
    Waiting,
    /// Inside its grant but not yet constructible: its relationship with the
    /// application is catching up (a transfer the wallet received awaits the
    /// application's finality). Nothing is answered or spent; the next sync
    /// tries it again.
    NotYet(String),
}

/// One processor at a time: the replay guard is read and a request carried
/// out under it as one step, whichever of the listener's sync, a sync the
/// player starts, the player's own decision or a disconnect reaches it first.
static PROCESSING: once_cell::sync::Lazy<tokio::sync::Mutex<()>> =
    once_cell::sync::Lazy::new(|| tokio::sync::Mutex::new(()));

/// What became of a request the player approved.
enum Approved {
    /// Carried out or failed, and answered.
    Done(generated::ConnectOutcome, String),
    /// A payment waiting for its relationship with the application to
    /// settle: the approval is kept and the next sync carries it out.
    Waits(String),
}

/// The session `sid`, while its application is connected.
fn connected(sid: &[u8; 32]) -> Result<store::WalletSession, String> {
    store::session(sid)
        .map_err(|e| e.to_string())?
        .filter(|s| s.connected == store::SessionStatus::Connected)
        .ok_or_else(|| "the application was disconnected".to_string())
}

/// Why `request` cannot be carried out yet, if it cannot. A payment waits
/// while its relationship with the application catches up; a holdings proof,
/// an escrow request, a quote and a swap wait while this device is still
/// admitting its latest position (SoFi builds no route on a pending one).
/// None is a refusal: the request stays queued, unanswered and unspent.
fn waits(
    core: &crate::sdk::core_sdk::CoreSDK,
    session: &store::WalletSession,
    request: &Request,
) -> Result<Option<String>, String> {
    match request {
        Request::Pay { .. } => Ok(payment_waits(&session.app_device_id)
            .map(|why| format!("the relationship with the application is settling: {why}"))),
        Request::Holdings { .. }
        | Request::EscrowLock(..)
        | Request::EscrowRelease { .. }
        | Request::Quote { .. }
        | Request::Swap { .. } => Ok(holdings::admission_pending(core)?
            .map(|position| format!("position {position} is still being admitted"))),
        Request::AcceptIssued { .. } => Ok(None),
    }
}

/// This device as a player of a match: the identity a branch pays and the
/// key it decides a cancel with.
fn own_player(core: &crate::sdk::core_sdk::CoreSDK) -> Result<Player, String> {
    let me = crate::sdk::escrow_flow::party(core)
        .map_err(|e| format!("this device as an escrow party: {e}"))?;
    Ok(Player {
        genesis: me.genesis,
        device_id: me.device_id,
        signer: me.signer,
    })
}

fn opponent_player(o: &Opponent) -> Player {
    Player {
        genesis: o.genesis,
        device_id: o.device_id,
        signer: o.signer.clone(),
    }
}

/// The connected application deciding a match, as the wallet holds it: its
/// device and the key on the card its offer carried, the key its requests
/// verify under.
fn app_referee(session: &store::WalletSession) -> Result<Referee, String> {
    Ok(Referee {
        device_id: session.app_device_id,
        signer: wager::signer(&session.app_ak)?,
    })
}

/// This account as the application deciding a match.
fn own_referee(core: &crate::sdk::core_sdk::CoreSDK) -> Result<Referee, String> {
    let me = own_player(core)?;
    Ok(Referee {
        device_id: me.device_id,
        signer: me.signer,
    })
}

/// The wallet of an application's session as a player of a match: the
/// identity and key its accepted card carried.
fn wallet_player(session: &store::AppSession) -> Result<Player, String> {
    Ok(Player {
        genesis: session.wallet_genesis,
        device_id: session.wallet_device_id,
        signer: wager::signer(&session.wallet_ak)?,
    })
}

fn position_state(state: crate::sdk::sofi_flow::PositionState) -> generated::SofiPositionState {
    match state {
        crate::sdk::sofi_flow::PositionState::Realized => generated::SofiPositionState::Realized,
        crate::sdk::sofi_flow::PositionState::Void => generated::SofiPositionState::Void,
        crate::sdk::sofi_flow::PositionState::Invalid => generated::SofiPositionState::Invalid,
        crate::sdk::sofi_flow::PositionState::RetriesExhausted => {
            generated::SofiPositionState::RetriesExhausted
        }
    }
}

/// Whether a payment to `app` can be constructed now. A relationship that is
/// catching up is not a refusal: the payment waits for it.
fn payment_waits(app: &[u8; 32]) -> Option<String> {
    let status = super::relationship_status::derive_local_send_status_for_device_id(app);
    match (
        status.send_ready,
        generated::RelationshipSendBlockReason::try_from(status.send_block_reason),
    ) {
        (ready, _) if ready => None,
        (_, Ok(generated::RelationshipSendBlockReason::PendingCatchup)) => {
            Some(super::relationship_status::status_message(&status))
        }
        _ => None,
    }
}

impl AppRouterImpl {
    pub(crate) async fn handle_connect_query(&self, q: AppQuery) -> AppResult {
        let result = match q.path.as_str() {
            "connect.preview" => self.connect_preview(&q.params).await,
            "connect.list" => connect_list(),
            "connect.pending" => connect_pending(),
            "connect.log" => connect_log(&q.params),
            "connect.app.requests" => connect_app_requests(&q.params),
            "connect.app.sessions" => connect_app_sessions(),
            "connect.app.offerOf" => connect_app_offer_of(&q.params),
            other => Err(format!("unknown connect query: {other}")),
        };
        match result {
            Ok(r) => reply(r),
            Err(e) => err(e),
        }
    }

    pub(crate) async fn handle_connect_invoke(&self, i: AppInvoke) -> AppResult {
        let result = match i.method.as_str() {
            "connect.approve" => self.connect_approve(&i.args).await,
            "connect.respond" => self.connect_respond(&i.args).await,
            "connect.disconnect" => connect_disconnect(&i.args).await,
            "connect.sync" => self.connect_sync().await,
            "connect.app.offer" => connect_app_offer(&i.args),
            "connect.app.accept" => self.connect_app_accept(&i.args).await,
            "connect.app.request" => self.connect_app_request(&i.args),
            "connect.app.respond" => connect_app_respond(&i.args),
            "connect.app.status" => self.connect_app_status(&i.args).await,
            other => Err(format!("unknown connect invoke: {other}")),
        };
        match result {
            Ok(r) => reply(r),
            Err(e) => err(e),
        }
    }

    // ------------------------------ the wallet ------------------------------

    async fn connect_preview(&self, params: &[u8]) -> Result<Reply, String> {
        const ROUTE: &str = "connect.preview";
        let req: generated::ConnectPreviewRequestV1 = body(params, ROUTE)?;
        let code = code::parse(&req.code).map_err(|e| format!("{ROUTE}: {e}"))?;
        let relay = Relay::new(&code.endpoint, code.cert_pin)?;
        let offer = relay
            .offer(&code.offer_digest)
            .await
            .map_err(|e| format!("{ROUTE}: {e}"))?;
        let verified = verify_offer(&offer, &code.endpoint, &code.offer_digest)
            .map_err(|e| format!("{ROUTE}: {e}"))?;
        store::put_preview(
            &code.offer_digest,
            &store::PreviewRow {
                endpoint: code.endpoint.clone(),
                cert_pin: code.cert_pin,
                offer: offer.encode_to_vec(),
            },
        )
        .map_err(|e| format!("{ROUTE}: keeping the preview: {e}"))?;
        // The approval screen names each token the offer names, before this
        // device roots any of them: each policy fetched and re-hashed to its
        // anchor here, as rooting it on approval will.
        let mut names = Names::new();
        for anchor in &verified.anchors {
            let named = match super::wallet_routes::token_of_commit(anchor) {
                Ok(rooted) => rooted,
                Err(..) => {
                    let policy = self
                        .verified_policy(*anchor)
                        .await
                        .map_err(|e| format!("{ROUTE}: a token the offer names: {e}"))?;
                    (policy.ticker, policy.decimals)
                }
            };
            names.insert(*anchor, named);
        }
        Ok(Reply::Preview(generated::ConnectPreviewV1 {
            offer_digest: verified.digest.to_vec(),
            display_name: verified.body.display_name.clone(),
            app_device_id: verified.app.device_id.to_vec(),
            endpoint: code.endpoint,
            scopes: scopes_to_wire(&verified.scopes),
            token_anchors: verified.anchors.iter().map(|a| a.to_vec()).collect(),
            scope_lines: verified
                .scopes
                .iter()
                .map(|s| describe_scope(s, &names))
                .collect(),
        }))
    }

    /// Root `anchor` through `tokens.addByAnchor`: the policy is fetched,
    /// re-hashed to the anchor and adopted into this device's state.
    async fn root_anchor(&self, anchor: &[u8; 32]) -> Result<(), String> {
        let rooted = crate::bridge::AppRouter::query(
            self,
            AppQuery {
                path: "tokens.addByAnchor".into(),
                params: crate::util::text_id::encode_base32_crockford(anchor).into_bytes(),
            },
        )
        .await;
        match (rooted.success, rooted.error_message) {
            (ok, _) if ok => Ok(()),
            (_, Some(why)) => Err(why),
            (_, None) => Err("tokens.addByAnchor refused it and said nothing more".into()),
        }
    }

    async fn connect_approve(&self, args: &[u8]) -> Result<Reply, String> {
        const ROUTE: &str = "connect.approve";
        let req: generated::ConnectApproveRequestV1 = body(args, ROUTE)?;
        let digest = d32(&req.offer_digest, "the offer digest")?;
        let preview = store::preview(&digest)
            .map_err(|e| format!("{ROUTE}: {e}"))?
            .ok_or_else(|| format!("{ROUTE}: no previewed offer with that digest"))?;
        let offer = generated::AppConnectOfferV1::decode(preview.offer.as_slice())
            .map_err(|e| format!("{ROUTE}: the previewed offer: {e}"))?;
        let verified = verify_offer(&offer, &preview.endpoint, &digest)
            .map_err(|e| format!("{ROUTE}: {e}"))?;
        let granted: Vec<Scope> = if req.granted.is_empty() {
            verified.scopes.clone()
        } else {
            let granted = scopes_from_wire(&req.granted).map_err(|e| format!("{ROUTE}: {e}"))?;
            narrows(&verified.scopes, &granted).map_err(|e| format!("{ROUTE}: {e}"))?;
            granted
        };
        let (card, att_a) = own_card()?;
        let own_device = d32(&card.device_id, "this device's id")?;
        let sid = session_id(&digest, &own_device);
        if let Some(existing) = store::session(&sid).map_err(|e| format!("{ROUTE}: {e}"))? {
            if existing.connected == store::SessionStatus::Connected {
                return Err(format!("{ROUTE}: this application is already connected"));
            }
        }
        let app_card = verified
            .body
            .app_card
            .clone()
            .ok_or_else(|| format!("{ROUTE}: the offer carries no card"))?;

        // The relationship first: each side holds it before the first step.
        let resolved = resolve_counterparty_via_transport(&app_card)
            .await
            .map_err(|e| format!("{ROUTE}: resolving the application: {e}"))?;
        self.add_contact_from_resolved(&verified.body.display_name, resolved)
            .await
            .map_err(|e| format!("{ROUTE}: {e}"))?;
        for anchor in &verified.anchors {
            self.root_anchor(anchor)
                .await
                .map_err(|e| format!("{ROUTE}: rooting {}: {e}", short(anchor)))?;
        }

        let accept_body = generated::AppConnectAcceptBodyV1 {
            offer_digest: digest.to_vec(),
            wallet_card: Some(card),
            wallet_att_a: att_a.to_vec(),
            granted: scopes_to_wire(&granted),
        }
        .encode_to_vec();
        let signature = sign_own(Signed::Accept, &accept_body)?;
        let relay = Relay::new(&preview.endpoint, preview.cert_pin)?;
        relay
            .accept(&generated::AppConnectAcceptV1 {
                body: accept_body.clone(),
                signature,
            })
            .await
            .map_err(|e| format!("{ROUTE}: delivering the accept: {e}"))?;
        let session = store::WalletSession {
            session_id: sid,
            app_device_id: verified.app.device_id,
            app_genesis: verified.app.genesis,
            app_ak: verified.app.ak.clone(),
            display_name: verified.body.display_name.clone(),
            endpoint: preview.endpoint.clone(),
            cert_pin: preview.cert_pin,
            offer_digest: digest,
            accept_body,
            last_seq: 0,
            connected: store::SessionStatus::Connected,
        };
        store::insert_session(&session).map_err(|e| format!("{ROUTE}: {e}"))?;
        crate::sdk::connect::wallet::start_listener()?;
        Ok(Reply::Session(wallet_session_view(
            &session,
            String::new(),
        )?))
    }

    async fn connect_respond(&self, args: &[u8]) -> Result<Reply, String> {
        const ROUTE: &str = "connect.respond";
        let req: generated::ConnectRespondRequestV1 = body(args, ROUTE)?;
        let sid = d32(&req.session_id, "the session")?;
        let one = PROCESSING.lock().await;
        let session = store::session(&sid)
            .map_err(|e| format!("{ROUTE}: {e}"))?
            .filter(|s| s.connected == store::SessionStatus::Connected)
            .ok_or_else(|| format!("{ROUTE}: no such connected application"))?;
        let held = store::pending(&sid, req.seq)
            .map_err(|e| format!("{ROUTE}: {e}"))?
            .ok_or_else(|| format!("{ROUTE}: request {} is not waiting", req.seq))?;
        let (request_body, request) = read_request(&held.request, &session)?;
        let summary = describe_request(&request);
        let name = session.display_name.clone();
        let (outcome, line) = match generated::ConnectDecision::try_from(req.decision) {
            Ok(generated::ConnectDecision::Approve) => {
                match self.carry_out_approved(&session, &held).await? {
                    Approved::Done(generated::ConnectOutcome::CarriedOut, _) => (
                        generated::ConnectOutcome::CarriedOut,
                        format!("{name}: {summary}, carried out."),
                    ),
                    Approved::Done(outcome, reason) => (
                        outcome,
                        format!("{name}: {summary}, not carried out: {reason}"),
                    ),
                    Approved::Waits(why) => (
                        generated::ConnectOutcome::Unspecified,
                        format!(
                            "{name}: {summary}, approved. It is carried out once this clears: {why}"
                        ),
                    ),
                }
            }
            Ok(generated::ConnectDecision::Decline) => {
                let declined = Executed {
                    outcome: generated::ConnectOutcome::Declined,
                    reason: "the player declined it".into(),
                    result: None,
                };
                self.finish(&session, request_body.seq, summary.clone(), declined, None)?;
                (
                    generated::ConnectOutcome::Declined,
                    format!("{name}: {summary}, declined."),
                )
            }
            _ => return Err(format!("{ROUTE}: approve or decline")),
        };
        drop(one);
        // The answer goes out now; the queue behind it moves on.
        let delivered = match deliver_owed(&session).await {
            Ok(()) => String::new(),
            Err(e) => format!("the answer is owed, not delivered yet: {e}"),
        };
        crate::sdk::connect::wallet::start_listener()?;
        let now = store::session(&sid)
            .map_err(|e| format!("{ROUTE}: {e}"))?
            .ok_or_else(|| format!("{ROUTE}: the session vanished"))?;
        Ok(Reply::Decided(generated::ConnectDecidedV1 {
            session: Some(wallet_session_view(&now, delivered)?),
            outcome: outcome as i32,
            line,
        }))
    }

    /// The tokens whose committed policy names the application as creator:
    /// those this device rooted, and, for a holdings request, each other
    /// token it names whose policy, fetched and re-hashed to its anchor,
    /// names the application. A proof of an object this device never held
    /// proves it is not held; nothing is adopted. A policy that cannot be
    /// read leaves the request for the next sync.
    async fn issued_by_app(
        &self,
        app: &[u8; 32],
        request: &Request,
    ) -> Result<BTreeSet<[u8; 32]>, String> {
        let mut issued = issued_by(app)?;
        let Request::Holdings { policy_commits } = request else {
            return Ok(issued);
        };
        for commit in policy_commits {
            match super::wallet_routes::token_of_commit(commit) {
                // Rooted here (or a protocol asset): `issued_by` decided it.
                Ok(..) => continue,
                Err(..) => {
                    let policy = self
                        .verified_policy(*commit)
                        .await
                        .map_err(|e| format!("the policy of {}: {e}", short(commit)))?;
                    if let dsm::economic::token_policy::Release::AllAtCreation {
                        creator_device_id,
                        ..
                    } = &policy.release
                    {
                        if creator_device_id == app {
                            issued.insert(*commit);
                        }
                    }
                }
            }
        }
        Ok(issued)
    }

    /// Carry out a request the player approved. A payment waits while the
    /// relationship with the application is catching up: the approval is
    /// kept, and the next sync carries it out. Called under [`PROCESSING`].
    async fn carry_out_approved(
        &self,
        session: &store::WalletSession,
        held: &store::PendingRow,
    ) -> Result<Approved, String> {
        let (request_body, request) = read_request(&held.request, session)?;
        if let Some(why) = waits(&self.core_sdk, session, &request)? {
            store::approve_pending(&session.session_id, request_body.seq)
                .map_err(|e| e.to_string())?;
            return Ok(Approved::Waits(why));
        }
        let summary = describe_request(&request);
        let executed = self.execute(session, request_body.seq, &request).await;
        let outcome = executed.outcome;
        let reason = executed.reason.clone();
        // Approved by hand, outside the grant: it never counts against the
        // grant's totals.
        self.finish(session, request_body.seq, summary, executed, None)?;
        Ok(Approved::Done(outcome, reason))
    }

    /// One pass over every connected application: deliver owed answers,
    /// then fetch and process its requests in order, stopping at one that
    /// waits for the player. Answers with the connected sessions.
    async fn connect_sync(&self) -> Result<Reply, String> {
        let sessions: Vec<store::WalletSession> = store::sessions()
            .map_err(|e| format!("connect.sync: {e}"))?
            .into_iter()
            .filter(|s| s.connected == store::SessionStatus::Connected)
            .collect();
        let cycles = sessions.iter().map(|s| self.sync_session(s));
        let outcomes = futures::future::join_all(cycles).await;
        let mut views = Vec::with_capacity(sessions.len());
        for (session, outcome) in sessions.iter().zip(outcomes) {
            let last_error = match outcome {
                Ok(()) => String::new(),
                Err(e) => e,
            };
            views.push(wallet_session_view(session, last_error)?);
        }
        Ok(Reply::Sessions(generated::ConnectSessionsV1 {
            sessions: views,
        }))
    }

    async fn sync_session(&self, session: &store::WalletSession) -> Result<(), String> {
        let relay = Relay::new(&session.endpoint, session.cert_pin)?;
        deliver_owed(session).await?;
        // A request waiting for the player holds every later one behind it.
        // One the player approved is carried out once it can be.
        let held = store::pending_all()
            .map_err(|e| e.to_string())?
            .into_iter()
            .find(|p| p.session_id == session.session_id);
        if let Some(held) = held {
            if held.state != store::PendingState::Approved {
                return Ok(());
            }
            let one = PROCESSING.lock().await;
            let current = connected(&session.session_id)?;
            let approved = self.carry_out_approved(&current, &held).await?;
            drop(one);
            if let Approved::Waits(why) = approved {
                return Err(format!("request {} is approved and waits: {why}", held.seq));
            }
            deliver_owed(&current).await?;
        }
        let after = connected(&session.session_id)?.last_seq;
        let batch = relay.requests(&session.session_id, after).await?;
        for request in &batch.requests {
            let one = PROCESSING.lock().await;
            // Re-read under the lock: each processed request moves the guard.
            let current = connected(&session.session_id)?;
            let flow = self
                .process(&current, &relay, &request.encode_to_vec())
                .await?;
            drop(one);
            match flow {
                Flow::Processed => deliver_owed(&current).await?,
                Flow::Seen => {}
                Flow::Waiting => break,
                Flow::NotYet(why) => return Err(why),
            }
        }
        Ok(())
    }

    async fn process(
        &self,
        session: &store::WalletSession,
        relay: &Relay,
        request_bytes: &[u8],
    ) -> Result<Flow, String> {
        let (request_body, request) = match read_request(request_bytes, session) {
            Ok(read) => read,
            Err(e) => return Err(format!("a request that does not verify is ignored: {e}")),
        };
        let seq = request_body.seq;
        if seq <= session.last_seq {
            return Ok(Flow::Seen);
        }
        if seq != session.last_seq + 1 {
            return Err(format!(
                "request {seq} arrived before request {}",
                session.last_seq + 1
            ));
        }
        let summary = describe_request(&request);
        let scopes = granted_scopes(&session.accept_body)?;
        let spent: BTreeMap<[u8; 32], u64> = store::spent_all(&session.session_id)
            .map_err(|e| e.to_string())?
            .into_iter()
            .collect();
        let issued = self.issued_by_app(&session.app_device_id, &request).await?;
        let spent_of = |c: &[u8; 32]| match spent.get(c) {
            Some(v) => *v,
            None => 0,
        };
        match decide(&scopes, &request, &spent_of, &issued) {
            Decision::InScope { spend } => {
                // A quote or swap behind this device's own pending SoFi position (a
                // trade cut off before it settled) finishes that position first, from
                // what storage holds, as `sofi.resolve` does; anything else pending is
                // waited for.
                if matches!(request, Request::Quote { .. } | Request::Swap { .. })
                    && holdings::admission_pending(&self.core_sdk)?.is_some()
                {
                    if let Err(e) = crate::sdk::sofi_flow::resolve(&self.core_sdk, &own_set()?).await {
                        log::info!("[connect] request {seq}: the pending position is not a SoFi one to finish here ({e})");
                    }
                }
                if let Some(why) = waits(&self.core_sdk, session, &request)? {
                    return Ok(Flow::NotYet(format!("request {seq} waits: {why}")));
                }
                let executed = self.execute(session, seq, &request).await;
                let spend = executed.spend(spend);
                self.finish(session, seq, summary, executed, spend)?;
                Ok(Flow::Processed)
            }
            Decision::Outside(reason) => {
                store::put_pending(&store::PendingRow {
                    session_id: session.session_id,
                    seq,
                    request: request_bytes.to_vec(),
                    reason: reason.clone(),
                    state: store::PendingState::Waiting,
                })
                .map_err(|e| e.to_string())?;
                // A notice that it waits: what the application may show
                // while the player decides. The final answer replaces it.
                let interim = signed_response(&generated::AppResponseBodyV1 {
                    session_id: session.session_id.to_vec(),
                    seq,
                    outcome: generated::ConnectOutcome::AwaitingApproval as i32,
                    reason,
                    result: None,
                })?;
                let interim = generated::AppResponseV1::decode(interim.as_slice())
                    .map_err(|e| format!("the waiting notice just signed: {e}"))?;
                relay.respond(&interim).await.map_err(|e| {
                    format!(
                        "request {seq} waits for the player; telling the application failed: {e}"
                    )
                })?;
                Ok(Flow::Waiting)
            }
        }
    }

    /// Record `seq` as processed with its signed answer and `spend` counted
    /// against its grant. The answer is then owed until it is delivered
    /// ([`deliver_owed`]); the request is never carried out again.
    fn finish(
        &self,
        session: &store::WalletSession,
        seq: u64,
        summary: String,
        executed: Executed,
        spend: Option<([u8; 32], u64)>,
    ) -> Result<(), String> {
        let response = signed_response(&generated::AppResponseBodyV1 {
            session_id: session.session_id.to_vec(),
            seq,
            outcome: executed.outcome as i32,
            reason: executed.reason.clone(),
            result: executed.result,
        })?;
        store::record_processed(
            &session.session_id,
            spend,
            &store::LogRow {
                seq,
                summary,
                outcome: executed.outcome as i32,
                detail: executed.reason,
            },
            &response,
        )
        .map_err(|e| e.to_string())
    }

    /// Carry out one request through the routes the player uses by hand.
    async fn execute(
        &self,
        session: &store::WalletSession,
        seq: u64,
        request: &Request,
    ) -> Executed {
        match request {
            Request::AcceptIssued { anchor } => {
                if let Err(e) = self.root_anchor(anchor).await {
                    return Executed::failed(format!("rooting the object: {e}"));
                }
                match crate::storage::client_db::token_registry::get_token_by_policy_commit(anchor)
                {
                    Ok(Some(row)) if row.creator_device_id == session.app_device_id => {
                        Executed::carried_out(None)
                    }
                    Ok(Some(..)) => Executed::failed(
                        "the object's committed policy names another creator than this application",
                    ),
                    Ok(None) => Executed::failed("the object is not in the registry after rooting"),
                    Err(e) => Executed::failed(format!("the token registry: {e}")),
                }
            }
            Request::Pay {
                policy_commit,
                amount,
                memo,
            } => {
                let ticker = match super::wallet_routes::token_of_commit(policy_commit) {
                    Ok((ticker, _)) => ticker,
                    Err(e) => return Executed::failed(e),
                };
                let sent = self
                    .process_online_transfer_logic(OnlineSendIntent {
                        to_device_id: session.app_device_id,
                        token_id: ticker,
                        amount: *amount,
                        memo: payment_memo(&session.session_id, seq, memo),
                    })
                    .await;
                match (sent.success, sent.error_message) {
                    (ok, _) if ok => Executed::carried_out(None),
                    (_, Some(why)) => Executed::failed(why),
                    (_, None) => {
                        Executed::failed("wallet.sendSmart refused it and said nothing more")
                    }
                }
            }
            Request::Quote {
                token_in,
                token_out,
                amount_in,
            } => match self.quote(token_in, token_out, *amount_in).await {
                Ok(found) => match found.ends {
                    Some(ends) => {
                        Executed::carried_out(Some(generated::app_response_body_v1::Result::Quote(
                            generated::ConnectQuoteResultV1 {
                                amount_in: ends.amount_in,
                                amount_out: ends.amount_out,
                                hops: found.hops.len() as u32,
                                shape: route_shape(ends.shape) as i32,
                            },
                        )))
                    }
                    None => Executed::failed("no route among the vaults searched"),
                },
                Err(e) => Executed::failed(e),
            },
            Request::Swap {
                token_in,
                token_out,
                amount_in,
                min_amount_out,
            } => {
                self.swap(token_in, token_out, *amount_in, *min_amount_out)
                    .await
            }
            Request::Holdings { policy_commits } => {
                match holdings::prove(&self.core_sdk, policy_commits) {
                    Ok(proof) => Executed::carried_out(Some(
                        generated::app_response_body_v1::Result::Holdings(proof),
                    )),
                    Err(e) => Executed::failed(e),
                }
            }
            Request::EscrowLock(lock) => match self.lock_stake(session, lock).await {
                Ok(locked) => Executed::carried_out(Some(
                    generated::app_response_body_v1::Result::EscrowLock(locked),
                )),
                Err(e) => Executed::failed(e),
            },
            Request::EscrowRelease { vault_ids } => self.collect(session, vault_ids).await,
        }
    }

    /// Lock a stake for a match (DSM Amendment A12). The terms are the match
    /// template's, built here for this wallet, the opponent the application
    /// named and the application's own key; nothing in them comes from the
    /// request but the match, the stake and who the opponent is. Side B locks
    /// only against side A's vault holding the same stake under the template
    /// with this wallet as B.
    async fn lock_stake(
        &self,
        session: &store::WalletSession,
        lock: &EscrowLock,
    ) -> Result<generated::ConnectEscrowLockResultV1, String> {
        let me = own_player(&self.core_sdk)?;
        let referee = app_referee(session)?;
        let opponent = opponent_player(&lock.opponent);
        let terms = wager::terms(
            &lock.external,
            lock.policy_commit,
            lock.side,
            &me,
            &opponent,
            &referee,
        )?;
        let set = own_set()?;
        if let Some(counterpart) = &lock.counterpart {
            let held = crate::sdk::escrow_flow::vault(&self.core_sdk, &set, counterpart)
                .await
                .map_err(|e| format!("side A's vault {}: {e}", short(counterpart)))?;
            if (held.owner_genesis, held.owner_device_id) != (opponent.genesis, opponent.device_id)
            {
                return Err(format!(
                    "side A's vault {} is not the opponent's",
                    short(counterpart)
                ));
            }
            if held.status != dsm::sofi::wire::VAULT_STATUS_ACTIVE {
                return Err(format!(
                    "side A's vault {} is no longer Active",
                    short(counterpart)
                ));
            }
            if (held.token, held.amount) != (lock.policy_commit, lock.amount) {
                return Err(format!(
                    "side A's vault holds {}, not the {} this stake matches",
                    crate::sdk::connect::wallet::amount_text(&held.token, held.amount),
                    crate::sdk::connect::wallet::amount_text(&lock.policy_commit, lock.amount)
                ));
            }
            let side_a = wager::branches(lock.side.other(), &opponent, &me, &referee)?;
            if held.external_commitment != *terms.external_commitment() || held.branches != side_a {
                return Err(format!(
                    "side A's vault {} is not this match's stake with this wallet as B",
                    short(counterpart)
                ));
            }
        }
        let created = crate::sdk::escrow_flow::create(
            &self.core_sdk,
            &set,
            &crate::sdk::escrow_flow::CreateEscrowIntent {
                external: lock.external.clone(),
                token: lock.policy_commit,
                amount: lock.amount,
                branches: terms.branches().to_vec(),
                counterpart: lock.counterpart,
            },
        )
        .await
        .map_err(|e| format!("locking the stake: {e}"))?;
        Ok(generated::ConnectEscrowLockResultV1 {
            vault_id: created.vault_id.to_vec(),
            verdict_cell: created.verdict_cell.to_vec(),
            external_commitment: created.external_commitment.to_vec(),
            position: created.position,
        })
    }

    /// Collect a match result (DSM Amendment A12): each vault released to
    /// this wallet by `escrow.release`, which builds a release only once the
    /// cell's verdict is final on a branch that pays this wallet. Every vault
    /// is checked first to be a match this application decides with this
    /// wallet as a player; one that is not is no business of the application,
    /// and nothing is released.
    async fn collect(&self, session: &store::WalletSession, vault_ids: &[[u8; 32]]) -> Executed {
        let checked = async {
            let me = own_player(&self.core_sdk)?;
            let referee = app_referee(session)?;
            let set = own_set()?;
            for vault_id in vault_ids {
                let held = crate::sdk::escrow_flow::vault(&self.core_sdk, &set, vault_id)
                    .await
                    .map_err(|e| format!("vault {}: {e}", short(vault_id)))?;
                wager::is_match_of(
                    &held.owner_genesis,
                    &held.owner_device_id,
                    &held.branches,
                    &me,
                    &referee,
                )
                .map_err(|why| {
                    format!(
                        "vault {} is not a match this application decides with this wallet as a \
                         player: {why}",
                        short(vault_id)
                    )
                })?;
            }
            Ok::<_, String>(set)
        };
        let set = match checked.await {
            Ok(set) => set,
            Err(e) => return Executed::failed(e),
        };
        let mut released = Vec::with_capacity(vault_ids.len());
        for vault_id in vault_ids {
            let done = crate::sdk::escrow_flow::release(&self.core_sdk, &set, vault_id).await;
            let (outcome, failure) = match done {
                Ok(outcome) => {
                    let failure = match outcome.state {
                        crate::sdk::sofi_flow::PositionState::Realized => None,
                        other => Some(format!(
                            "the release of {} at position {} did not realize: {other:?}",
                            short(vault_id),
                            outcome.position
                        )),
                    };
                    (Some(outcome), failure)
                }
                Err(e) => (None, Some(format!("releasing {}: {e}", short(vault_id)))),
            };
            if let Some(outcome) = outcome {
                released.push(generated::ConnectEscrowReleasedV1 {
                    vault_id: vault_id.to_vec(),
                    position: outcome.position,
                    state: position_state(outcome.state) as i32,
                });
            }
            if let Some(reason) = failure {
                return Executed {
                    outcome: generated::ConnectOutcome::Failed,
                    reason,
                    result: Some(generated::app_response_body_v1::Result::EscrowRelease(
                        generated::ConnectEscrowReleaseResultV1 { released },
                    )),
                };
            }
        }
        Executed::carried_out(Some(
            generated::app_response_body_v1::Result::EscrowRelease(
                generated::ConnectEscrowReleaseResultV1 { released },
            ),
        ))
    }

    async fn quote(
        &self,
        token_in: &[u8; 32],
        token_out: &[u8; 32],
        amount_in: u64,
    ) -> Result<crate::sdk::sofi_flow::RouteFound, String> {
        let set = own_set()?;
        crate::sdk::sofi_flow::find_route(
            &self.core_sdk,
            &set,
            &crate::sdk::sofi_flow::FindRouteIntent {
                token_in_policy_commit: *token_in,
                token_out_policy_commit: *token_out,
                amount_in,
            },
        )
        .await
        .map_err(|e| format!("sofi.findRoute: {e}"))
    }

    /// A swap is an ordinary SoFi trade: the route `sofi.findRoute` finds,
    /// traded as the SoFi screen trades it, chained or split (SoFi Amendment
    /// S19). Every predicate decides it.
    async fn swap(
        &self,
        token_in: &[u8; 32],
        token_out: &[u8; 32],
        amount_in: u64,
        min_amount_out: u64,
    ) -> Executed {
        let found = match self.quote(token_in, token_out, amount_in).await {
            Ok(found) => found,
            Err(e) => return Executed::failed(e),
        };
        if found.hops.is_empty() {
            return Executed::failed("no route among the vaults searched");
        }
        let mut vault_ids: Vec<[u8; 32]> = Vec::with_capacity(found.hops.len());
        for hop in &found.hops {
            if !vault_ids.contains(&hop.vault_id) {
                vault_ids.push(hop.vault_id);
            }
        }
        let set = match own_set() {
            Ok(set) => set,
            Err(e) => return Executed::failed(e),
        };
        let traded = crate::sdk::sofi_flow::trade(
            &self.core_sdk,
            &set,
            &crate::sdk::sofi_flow::TradeIntent {
                vault_ids: vault_ids.clone(),
                token_in_policy_commit: *token_in,
                token_out_policy_commit: *token_out,
                amount_in,
                min_amount_out,
            },
        )
        .await;
        let outcome = match traded {
            Ok(outcome) => outcome,
            Err(e) => return Executed::failed(format!("sofi trade: {e}")),
        };
        let state = position_state(outcome.state);
        let result = Some(generated::app_response_body_v1::Result::Swap(
            generated::ConnectSwapResultV1 {
                position: outcome.position,
                state: state as i32,
                vault_ids: vault_ids.iter().map(|v| v.to_vec()).collect(),
            },
        ));
        match outcome.state {
            crate::sdk::sofi_flow::PositionState::Realized => Executed::carried_out(result),
            other => Executed {
                outcome: generated::ConnectOutcome::Failed,
                reason: format!(
                    "the trade at position {} did not realize: {other:?}",
                    outcome.position
                ),
                result,
            },
        }
    }

    // ------------------------- the application account -------------------------

    async fn connect_app_accept(&self, args: &[u8]) -> Result<Reply, String> {
        const ROUTE: &str = "connect.app.accept";
        let accept = generated::AppConnectAcceptV1::decode(args_body(args, ROUTE)?.as_slice())
            .map_err(|e| format!("{ROUTE}: decode the accept: {e}"))?;
        let probe: generated::AppConnectAcceptBodyV1 =
            canonical(&accept.body, "the accept").map_err(|e| format!("{ROUTE}: {e}"))?;
        let digest = d32(&probe.offer_digest, "the accepted offer")?;
        let (_, offer) = store::app_offer(&digest)
            .map_err(|e| format!("{ROUTE}: {e}"))?
            .ok_or_else(|| format!("{ROUTE}: this account made no such offer"))?;
        let network = own_network()?;
        let verified =
            app::verify_accept(&accept, &offer, &network).map_err(|e| format!("{ROUTE}: {e}"))?;
        let resolved = resolve_counterparty_via_transport(&verified.wallet_card)
            .await
            .map_err(|e| format!("{ROUTE}: resolving the wallet: {e}"))?;
        self.add_contact_from_resolved(
            &format!("wallet {}", short(&verified.wallet.device_id)),
            resolved,
        )
        .await
        .map_err(|e| format!("{ROUTE}: {e}"))?;
        let session = store::AppSession {
            session_id: verified.session_id,
            offer_digest: verified.offer_digest,
            wallet_device_id: verified.wallet.device_id,
            wallet_genesis: verified.wallet.genesis,
            wallet_ak: verified.wallet.ak.clone(),
            accept: accept.encode_to_vec(),
            next_seq: 1,
        };
        store::app_insert_session(&session).map_err(|e| format!("{ROUTE}: {e}"))?;
        Ok(Reply::Session(app_session_view(&session)?))
    }

    /// What this account established about one request, from DSM evidence
    /// it checked itself. An answer alone establishes nothing.
    async fn connect_app_status(&self, args: &[u8]) -> Result<Reply, String> {
        const ROUTE: &str = "connect.app.status";
        let req: generated::ConnectRequestRefV1 = body(args, ROUTE)?;
        let sid = d32(&req.session_id, "the session")?;
        let session = store::app_session(&sid)
            .map_err(|e| format!("{ROUTE}: {e}"))?
            .ok_or_else(|| format!("{ROUTE}: no such session"))?;
        let (request, response) = store::app_request(&sid, req.seq)
            .map_err(|e| format!("{ROUTE}: {e}"))?
            .ok_or_else(|| format!("{ROUTE}: no request {} in this session", req.seq))?;
        let request = generated::AppRequestV1::decode(request.as_slice())
            .map_err(|e| format!("{ROUTE}: the stored request: {e}"))?;
        let request_body: generated::AppRequestBodyV1 =
            canonical(&request.body, "the stored request")?;
        let asked = request_from_wire(&request_body)?;
        let answer = match response {
            Some(bytes) => Some(canonical::<generated::AppResponseBodyV1>(
                &generated::AppResponseV1::decode(bytes.as_slice())
                    .map_err(|e| format!("{ROUTE}: the stored answer: {e}"))?
                    .body,
                "the stored answer",
            )?),
            None => None,
        };
        let mut status = generated::ConnectAppStatusV1 {
            session_id: sid.to_vec(),
            seq: req.seq,
            answered: answer.is_some(),
            fact: generated::ConnectFact::None as i32,
            ..Default::default()
        };
        if let Some(a) = &answer {
            status.outcome = a.outcome;
            status.reason = a.reason.clone();
            match &a.result {
                Some(generated::app_response_body_v1::Result::Quote(q)) => status.quote = Some(*q),
                Some(generated::app_response_body_v1::Result::Swap(s)) => {
                    status.swap = Some(s.clone())
                }
                _ => {}
            }
        }
        match &asked {
            Request::Pay {
                policy_commit,
                amount,
                ..
            } => {
                if let Some(fact) = store::app_fact_of(&sid, req.seq).map_err(|e| e.to_string())? {
                    status.fact = generated::ConnectFact::Paid as i32;
                    status.paid_tx = fact;
                    status.fact_detail =
                        "the transfer is accepted onto this account's relationship with the wallet"
                            .into();
                } else {
                    // Take in whatever the storage nodes hold for this
                    // account first: the transfer may be waiting there.
                    let synced = crate::bridge::AppRouter::query(
                        self,
                        AppQuery {
                            path: "storage.sync".into(),
                            // The sync the inbox poller makes.
                            params: generated::ArgPack {
                                codec: generated::Codec::Proto as i32,
                                body: crate::sdk::inbox_poller::poll_sync_request().encode_to_vec(),
                                ..Default::default()
                            }
                            .encode_to_vec(),
                        },
                    )
                    .await;
                    let sync_note = match (synced.success, synced.error_message) {
                        (ok, _) if ok => String::new(),
                        (_, why) => format!(" (taking in this account's inbox: {why:?})"),
                    };
                    match app::landed_payment(&session, req.seq, policy_commit, *amount)? {
                        Some(tx) => {
                            store::app_record_fact(tx.as_bytes(), &sid, req.seq)
                                .map_err(|e| e.to_string())?;
                            status.fact = generated::ConnectFact::Paid as i32;
                            status.paid_tx = tx.into_bytes();
                            status.fact_detail = "the transfer is accepted onto this account's relationship with the wallet".into();
                        }
                        None => {
                            status.fact_detail = format!(
                                "no transfer this account accepted pays it yet; an answer saying paid grants nothing{sync_note}"
                            );
                        }
                    }
                }
            }
            Request::Holdings { policy_commits } => match &answer {
                Some(generated::AppResponseBodyV1 {
                    result: Some(generated::app_response_body_v1::Result::Holdings(proof)),
                    ..
                }) => match holdings::verify(
                    proof,
                    &session.wallet_genesis,
                    &session.wallet_device_id,
                    policy_commits,
                )
                .await
                {
                    Ok(verified) => {
                        status.fact = generated::ConnectFact::Holdings as i32;
                        status.holdings_position = verified.position;
                        status.holdings = verified
                            .balances
                            .iter()
                            .map(|(policy_commit, amount)| generated::VerifiedHoldingV1 {
                                policy_commit: policy_commit.to_vec(),
                                amount: *amount,
                            })
                            .collect();
                        status.fact_detail = format!(
                            "proven at the wallet's position {}, whose next cell is still open",
                            verified.position
                        );
                    }
                    Err(refusal) => {
                        status.fact_detail = format!("the proof established nothing: {refusal:?}")
                    }
                },
                _ => status.fact_detail = "no proof answers it yet".into(),
            },
            Request::Swap { .. } => {
                status.fact_detail = "a trade shows through this account's own vault (sofi.vaults) or a later holdings proof; the answer is a notification".into();
            }
            Request::Quote { .. } => {
                status.fact_detail = "a quote is information and carries no authority".into();
            }
            Request::AcceptIssued { .. } => {
                status.fact_detail =
                    "whether the wallet holds the object shows in a holdings proof".into();
            }
            Request::EscrowLock(lock) => self.lock_fact(&session, lock, &mut status).await?,
            Request::EscrowRelease { vault_ids } => {
                self.release_fact(&session, vault_ids, &mut status).await?
            }
        }
        Ok(Reply::Status(status))
    }

    /// FACT_ESCROW_LOCKED (DSM Amendment A12), from the vaults bound to the
    /// match's verdict cell, which this account derives from the template and
    /// reads and walks itself: the wallet's vault there, Active, holding
    /// exactly the asked token and amount under exactly the template's terms.
    /// Another vault on the cell, the opponent's included, is not the
    /// wallet's stake.
    async fn lock_fact(
        &self,
        session: &store::AppSession,
        lock: &EscrowLock,
        status: &mut generated::ConnectAppStatusV1,
    ) -> Result<(), String> {
        let wallet = wallet_player(session)?;
        let terms = wager::terms(
            &lock.external,
            lock.policy_commit,
            lock.side,
            &wallet,
            &opponent_player(&lock.opponent),
            &own_referee(&self.core_sdk)?,
        )?;
        let cell = dsm::sofi::escrow::verdict_cell_of(&terms);
        let set = own_set()?;
        let (vaults, search) = crate::sdk::escrow_flow::locked(&self.core_sdk, &set, &cell)
            .await
            .map_err(|e| format!("the vaults of the match's verdict cell: {e}"))?;
        let held = vaults.iter().find(|v| {
            (v.owner_genesis, v.owner_device_id) == (wallet.genesis, wallet.device_id)
                && v.status == dsm::sofi::wire::VAULT_STATUS_ACTIVE
                && (v.token, v.amount) == (lock.policy_commit, lock.amount)
                && v.external_commitment == *terms.external_commitment()
                && v.branches.as_slice() == terms.branches()
        });
        match (held, search) {
            (Some(v), _) => {
                status.fact = generated::ConnectFact::EscrowLocked as i32;
                status.escrow_vault_ids = vec![v.vault_id.to_vec()];
                status.escrow_verdict_cell = cell.to_vec();
                status.escrow_amount = v.amount;
                status.fact_detail = format!(
                    "the wallet's vault {} holds the stake under the match's terms, Active on its \
                     verdict cell",
                    short(&v.vault_id)
                );
            }
            (None, crate::sdk::sofi_flow::Search::Complete) => {
                status.fact_detail = "no vault of the wallet's holds this stake on the match's \
                                      verdict cell; an answer saying locked grants nothing"
                    .into();
            }
            (None, crate::sdk::sofi_flow::Search::Partial) => {
                status.fact_detail = "no vault of the wallet's holds this stake on the match's \
                                      verdict cell yet; not every vault there could be walked"
                    .into();
            }
        }
        Ok(())
    }

    /// FACT_ESCROW_RELEASED (DSM Amendment A12): every named vault is a stake
    /// of a match this account decides with the session's wallet as a
    /// player, Retired at its walked head, and its cell's final verdict names
    /// an outcome whose branch pays the wallet. Only that branch's recipient
    /// can have released it (SoFi §19.9).
    async fn release_fact(
        &self,
        session: &store::AppSession,
        vault_ids: &[[u8; 32]],
        status: &mut generated::ConnectAppStatusV1,
    ) -> Result<(), String> {
        let wallet = wallet_player(session)?;
        let referee = own_referee(&self.core_sdk)?;
        let set = own_set()?;
        let mut cells = Vec::with_capacity(vault_ids.len());
        let mut outcomes = Vec::with_capacity(vault_ids.len());
        for vault_id in vault_ids {
            let held = match crate::sdk::escrow_flow::vault(&self.core_sdk, &set, vault_id).await {
                Ok(held) => held,
                Err(e) => {
                    status.fact_detail = format!("vault {}: {e}", short(vault_id));
                    return Ok(());
                }
            };
            if let Err(why) = wager::is_match_of(
                &held.owner_genesis,
                &held.owner_device_id,
                &held.branches,
                &wallet,
                &referee,
            ) {
                status.fact_detail = format!(
                    "vault {} is not a match this account decides with the wallet as a player: \
                     {why}",
                    short(vault_id)
                );
                return Ok(());
            }
            if held.status != dsm::sofi::wire::VAULT_STATUS_RETIRED {
                status.fact_detail = format!(
                    "vault {} is not released yet; an answer saying collected grants nothing",
                    short(vault_id)
                );
                return Ok(());
            }
            let verdict = crate::sdk::escrow_flow::verdict(&self.core_sdk, &set, vault_id)
                .await
                .map_err(|e| format!("the verdict of vault {}: {e}", short(vault_id)))?;
            let outcome = match verdict.held {
                Some((outcome, dsm::route_chain::ChainState::Final)) => outcome,
                Some(..) | None => {
                    status.fact_detail = format!(
                        "vault {} is Retired but its cell's verdict is not final",
                        short(vault_id)
                    );
                    return Ok(());
                }
            };
            let pays_wallet = held.branches.iter().any(|b| {
                b.outcome() == outcome.as_slice()
                    && (b.recipient_genesis(), b.recipient_device_id())
                        == (&wallet.genesis, &wallet.device_id)
            });
            if !pays_wallet {
                status.fact_detail = format!(
                    "vault {} was released on {:?}, which pays another identity",
                    short(vault_id),
                    String::from_utf8_lossy(&outcome)
                );
                return Ok(());
            }
            cells.push(held.verdict_cell);
            outcomes.push(String::from_utf8_lossy(&outcome).into_owned());
        }
        status.fact = generated::ConnectFact::EscrowReleased as i32;
        status.escrow_vault_ids = vault_ids.iter().map(|v| v.to_vec()).collect();
        if let Some(cell) = cells.first() {
            status.escrow_verdict_cell = cell.to_vec();
        }
        status.fact_detail = format!(
            "each vault is Retired and its cell's final verdict ({}) pays the wallet",
            outcomes.join(", ")
        );
        Ok(())
    }

    /// `connect.app.request`: the application signs a request for a
    /// connected wallet. A lock is checked as the wallet will build it: the
    /// opponent is neither the wallet nor this account.
    fn connect_app_request(&self, args: &[u8]) -> Result<Reply, String> {
        const ROUTE: &str = "connect.app.request";
        let req: generated::ConnectAppRequestIntentV1 = body(args, ROUTE)?;
        let sid = d32(&req.session_id, "the session")?;
        let session = store::app_session(&sid)
            .map_err(|e| format!("{ROUTE}: {e}"))?
            .ok_or_else(|| format!("{ROUTE}: no such session"))?;
        use generated::app_request_body_v1::Kind as Body;
        use generated::connect_app_request_intent_v1::Kind as Intent;
        let kind = match req.kind {
            Some(Intent::AcceptIssued(k)) => Body::AcceptIssued(k),
            Some(Intent::Pay(k)) => Body::Pay(k),
            Some(Intent::Quote(k)) => Body::Quote(k),
            Some(Intent::Swap(k)) => Body::Swap(k),
            Some(Intent::Holdings(k)) => Body::Holdings(k),
            Some(Intent::EscrowLock(k)) => Body::EscrowLock(k),
            Some(Intent::EscrowRelease(k)) => Body::EscrowRelease(k),
            None => return Err(format!("{ROUTE}: the request asks for nothing")),
        };
        // The shape a wallet will read, checked before it is signed.
        let asked = request_from_wire(&generated::AppRequestBodyV1 {
            session_id: sid.to_vec(),
            seq: 1,
            kind: Some(kind.clone()),
        })
        .map_err(|e| format!("{ROUTE}: {e}"))?;
        if let Request::EscrowLock(lock) = &asked {
            wager::branches(
                lock.side,
                &wallet_player(&session)?,
                &opponent_player(&lock.opponent),
                &own_referee(&self.core_sdk)?,
            )
            .map_err(|e| format!("{ROUTE}: {e}"))?;
        }
        let seq = store::app_append_request(&sid, |seq| app::signed_request(&sid, seq, kind))
            .map_err(|e| format!("{ROUTE}: {e}"))?;
        Ok(Reply::Request(generated::ConnectRequestRefV1 {
            session_id: sid.to_vec(),
            seq,
        }))
    }
}

fn route_shape(shape: dsm::sofi::validation::RouteShape) -> generated::SofiRouteShape {
    match shape {
        dsm::sofi::validation::RouteShape::Chain => generated::SofiRouteShape::Chain,
        dsm::sofi::validation::RouteShape::Split => generated::SofiRouteShape::Split,
    }
}

/// The pinned set of this device's committed network.
fn own_set() -> Result<crate::sdk::storage_set::StorageSet, String> {
    let network = crate::sdk::economic_admission_flow::committed_network_id()
        .map_err(|e| format!("no committed network: {e}"))?;
    crate::sdk::storage_set::canonical_set(&network)
        .map_err(|e| format!("no pinned storage set: {e}"))
}

/// The bytes an `ArgPack` of PROTO codec carries.
fn args_body(args: &[u8], route: &str) -> Result<Vec<u8>, String> {
    let pack = generated::ArgPack::decode(args)
        .map_err(|e| format!("{route}: decode ArgPack failed: {e}"))?;
    if pack.codec != generated::Codec::Proto as i32 {
        return Err(format!("{route}: ArgPack.codec must be PROTO"));
    }
    Ok(pack.body)
}

/// A request verified as the session's application's: its signature under
/// the application's AK, its canonical body, its session.
fn read_request(
    bytes: &[u8],
    session: &store::WalletSession,
) -> Result<(generated::AppRequestBodyV1, Request), String> {
    let request = generated::AppRequestV1::decode(bytes).map_err(|e| format!("a request: {e}"))?;
    verify(
        Signed::Request,
        &request.body,
        &session.app_ak,
        &request.signature,
    )?;
    let body: generated::AppRequestBodyV1 = canonical(&request.body, "a request")?;
    if body.session_id.as_slice() != session.session_id.as_slice() {
        return Err("the request is another session's".into());
    }
    let read = request_from_wire(&body)?;
    Ok((body, read))
}

fn wallet_session_view(
    s: &store::WalletSession,
    last_error: String,
) -> Result<generated::ConnectSessionV1, String> {
    let granted = granted_scopes(&s.accept_body)?;
    let mut spent = Vec::new();
    for (policy_commit, amount) in store::spent_all(&s.session_id).map_err(|e| e.to_string())? {
        let total = granted
            .iter()
            .flat_map(|g| g.caps.iter())
            .filter(|c| c.policy_commit == policy_commit)
            .map(|c| c.total)
            .max();
        let (spent_display, symbol) = shown(&policy_commit, amount);
        let total_display = match total {
            Some(t) => shown(&policy_commit, t).0,
            None => String::new(),
        };
        spent.push(generated::ConnectSpentV1 {
            policy_commit: policy_commit.to_vec(),
            spent: amount,
            spent_display,
            total_display,
            symbol,
        });
    }
    Ok(generated::ConnectSessionV1 {
        session_id: s.session_id.to_vec(),
        display_name: s.display_name.clone(),
        peer_device_id: s.app_device_id.to_vec(),
        endpoint: s.endpoint.clone(),
        granted: scopes_to_wire(&granted),
        last_seq: s.last_seq,
        status: match s.connected {
            store::SessionStatus::Connected => generated::ConnectSessionStatus::Connected,
            store::SessionStatus::Disconnected => generated::ConnectSessionStatus::Disconnected,
        } as i32,
        spent,
        scope_lines: granted
            .iter()
            .map(|s| describe_scope(s, &Names::new()))
            .collect(),
        last_error,
        offer_digest: s.offer_digest.to_vec(),
        peer_genesis: s.app_genesis.to_vec(),
        peer_signing_key: s.app_ak.clone(),
    })
}

/// Deliver every answer `session` still owes its application, in order.
async fn deliver_owed(session: &store::WalletSession) -> Result<(), String> {
    let owed = store::undelivered(&session.session_id).map_err(|e| e.to_string())?;
    if owed.is_empty() {
        return Ok(());
    }
    let relay = Relay::new(&session.endpoint, session.cert_pin)?;
    for (seq, response) in owed {
        let response = generated::AppResponseV1::decode(response.as_slice())
            .map_err(|e| format!("a stored answer: {e}"))?;
        relay.respond(&response).await?;
        store::mark_delivered(&session.session_id, seq).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn connect_list() -> Result<Reply, String> {
    let mut sessions = Vec::new();
    for s in store::sessions().map_err(|e| format!("connect.list: {e}"))? {
        sessions.push(wallet_session_view(&s, String::new())?);
    }
    Ok(Reply::Sessions(generated::ConnectSessionsV1 { sessions }))
}

fn pending_list() -> Result<generated::ConnectPendingListV1, String> {
    let mut pending = Vec::new();
    for row in store::pending_all().map_err(|e| format!("connect.pending: {e}"))? {
        let Some(session) = store::session(&row.session_id).map_err(|e| e.to_string())? else {
            continue;
        };
        let summary = match read_request(&row.request, &session) {
            Ok((_, request)) => describe_request(&request),
            Err(e) => format!("unreadable request: {e}"),
        };
        pending.push(generated::ConnectPendingV1 {
            session_id: row.session_id.to_vec(),
            seq: row.seq,
            display_name: session.display_name.clone(),
            summary,
            reason: row.reason,
            approved: row.state == store::PendingState::Approved,
        });
    }
    Ok(generated::ConnectPendingListV1 { pending })
}

fn connect_pending() -> Result<Reply, String> {
    Ok(Reply::Pending(pending_list()?))
}

fn connect_log(params: &[u8]) -> Result<Reply, String> {
    let req: generated::ConnectSessionRefV1 = body(params, "connect.log")?;
    let sid = d32(&req.session_id, "the session")?;
    let entries = store::log(&sid)
        .map_err(|e| format!("connect.log: {e}"))?
        .into_iter()
        .map(|row| generated::ConnectLogEntryV1 {
            seq: row.seq,
            summary: row.summary,
            outcome: row.outcome,
            detail: row.detail,
        })
        .collect();
    Ok(Reply::Log(generated::ConnectLogV1 { entries }))
}

async fn connect_disconnect(args: &[u8]) -> Result<Reply, String> {
    let req: generated::ConnectSessionRefV1 = body(args, "connect.disconnect")?;
    let sid = d32(&req.session_id, "the session")?;
    // A request being carried out finishes first; none starts after.
    let one = PROCESSING.lock().await;
    store::disconnect(&sid).map_err(|e| format!("connect.disconnect: {e}"))?;
    drop(one);
    let session = store::session(&sid)
        .map_err(|e| format!("connect.disconnect: {e}"))?
        .ok_or_else(|| "connect.disconnect: the session vanished".to_string())?;
    Ok(Reply::Session(wallet_session_view(
        &session,
        String::new(),
    )?))
}

fn app_session_view(s: &store::AppSession) -> Result<generated::ConnectSessionV1, String> {
    let accept = generated::AppConnectAcceptV1::decode(s.accept.as_slice())
        .map_err(|e| format!("the stored accept: {e}"))?;
    let granted = granted_scopes(&accept.body)?;
    Ok(generated::ConnectSessionV1 {
        session_id: s.session_id.to_vec(),
        display_name: format!("wallet {}", short(&s.wallet_device_id)),
        peer_device_id: s.wallet_device_id.to_vec(),
        endpoint: String::new(),
        granted: scopes_to_wire(&granted),
        last_seq: s.next_seq.saturating_sub(1),
        status: generated::ConnectSessionStatus::Connected as i32,
        spent: Vec::new(),
        scope_lines: granted
            .iter()
            .map(|s| describe_scope(s, &Names::new()))
            .collect(),
        last_error: String::new(),
        offer_digest: s.offer_digest.to_vec(),
        peer_genesis: s.wallet_genesis.to_vec(),
        peer_signing_key: s.wallet_ak.clone(),
    })
}

fn connect_app_sessions() -> Result<Reply, String> {
    let mut sessions = Vec::new();
    for s in store::app_sessions().map_err(|e| format!("connect.app.sessions: {e}"))? {
        sessions.push(app_session_view(&s)?);
    }
    Ok(Reply::Sessions(generated::ConnectSessionsV1 { sessions }))
}

fn connect_app_offer(args: &[u8]) -> Result<Reply, String> {
    const ROUTE: &str = "connect.app.offer";
    let req: generated::ConnectAppOfferRequestV1 = body(args, ROUTE)?;
    let scopes = scopes_from_wire(&req.scopes).map_err(|e| format!("{ROUTE}: {e}"))?;
    let mut anchors = Vec::with_capacity(req.token_anchors.len());
    for a in &req.token_anchors {
        let a = d32(a, "an anchor")?;
        if anchors.contains(&a) {
            return Err(format!("{ROUTE}: an anchor is named twice"));
        }
        anchors.push(a);
    }
    let pin = d32(&req.cert_pin, "the certificate pin")?;
    let made = app::make_offer(&req.display_name, &req.endpoint, pin, &scopes, &anchors)
        .map_err(|e| format!("{ROUTE}: {e}"))?;
    let text = code::encode(&made.code);
    store::app_put_offer(&made.code.offer_digest, &text, &made.offer)
        .map_err(|e| format!("{ROUTE}: {e}"))?;
    Ok(Reply::Offer(generated::ConnectAppOfferV1 {
        code: text,
        offer_digest: made.code.offer_digest.to_vec(),
        offer: made.offer,
    }))
}

fn connect_app_offer_of(params: &[u8]) -> Result<Reply, String> {
    const ROUTE: &str = "connect.app.offerOf";
    let req: generated::ConnectOfferRefV1 = body(params, ROUTE)?;
    let digest = d32(&req.offer_digest, "the offer digest")?;
    let (code, offer) = store::app_offer(&digest)
        .map_err(|e| format!("{ROUTE}: {e}"))?
        .ok_or_else(|| format!("{ROUTE}: this account made no such offer"))?;
    Ok(Reply::Offer(generated::ConnectAppOfferV1 {
        code,
        offer_digest: digest.to_vec(),
        offer,
    }))
}

fn connect_app_requests(params: &[u8]) -> Result<Reply, String> {
    const ROUTE: &str = "connect.app.requests";
    let req: generated::ConnectAppRequestsQueryV1 = body(params, ROUTE)?;
    let sid = d32(&req.session_id, "the session")?;
    let mut requests = Vec::new();
    for bytes in store::app_requests_after(&sid, req.after).map_err(|e| format!("{ROUTE}: {e}"))? {
        requests.push(
            generated::AppRequestV1::decode(bytes.as_slice())
                .map_err(|e| format!("{ROUTE}: a stored request: {e}"))?,
        );
    }
    Ok(Reply::Requests(generated::AppRequestBatchV1 { requests }))
}

/// Take a wallet's answer: the session's wallet's signature over a canonical
/// body answering a request this account made. A waiting notice may be
/// followed by the final answer; any other second answer is refused. Nothing
/// in it is evidence.
fn connect_app_respond(args: &[u8]) -> Result<Reply, String> {
    const ROUTE: &str = "connect.app.respond";
    let response = generated::AppResponseV1::decode(args_body(args, ROUTE)?.as_slice())
        .map_err(|e| format!("{ROUTE}: decode the answer: {e}"))?;
    let probe: generated::AppResponseBodyV1 =
        canonical(&response.body, "the answer").map_err(|e| format!("{ROUTE}: {e}"))?;
    let sid = d32(&probe.session_id, "the session")?;
    let session = store::app_session(&sid)
        .map_err(|e| format!("{ROUTE}: {e}"))?
        .ok_or_else(|| format!("{ROUTE}: no such session"))?;
    let answer = app::verify_response(&response, &session).map_err(|e| format!("{ROUTE}: {e}"))?;
    let (_, stored) = store::app_request(&sid, answer.seq)
        .map_err(|e| format!("{ROUTE}: {e}"))?
        .ok_or_else(|| format!("{ROUTE}: no request {} in this session", answer.seq))?;
    let bytes = response.encode_to_vec();
    match stored {
        None => store::app_store_response(&sid, answer.seq, &bytes),
        Some(held) if held == bytes => Ok(()),
        Some(held) => {
            let held_body: generated::AppResponseBodyV1 = canonical(
                &generated::AppResponseV1::decode(held.as_slice())
                    .map_err(|e| format!("{ROUTE}: the stored answer: {e}"))?
                    .body,
                "the stored answer",
            )?;
            if held_body.outcome == generated::ConnectOutcome::AwaitingApproval as i32
                && answer.outcome != generated::ConnectOutcome::AwaitingApproval as i32
            {
                store::app_replace_response(&sid, answer.seq, &bytes)
            } else {
                return Err(format!(
                    "{ROUTE}: request {} already has another answer",
                    answer.seq
                ));
            }
        }
    }
    .map_err(|e| format!("{ROUTE}: {e}"))?;
    Ok(Reply::Request(generated::ConnectRequestRefV1 {
        session_id: sid.to_vec(),
        seq: answer.seq,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_route_body_needs_the_proto_codec() {
        let pack = generated::ArgPack {
            codec: generated::Codec::Proto as i32,
            body: generated::ConnectSessionRefV1 {
                session_id: vec![1; 32],
            }
            .encode_to_vec(),
            ..Default::default()
        };
        let read: Result<generated::ConnectSessionRefV1, String> = body(&pack.encode_to_vec(), "t");
        assert_eq!(read.map(|r| r.session_id), Ok(vec![1; 32]));
        let mut other = pack.clone();
        other.codec = generated::Codec::Proto as i32 + 1;
        let read: Result<generated::ConnectSessionRefV1, String> =
            body(&other.encode_to_vec(), "t");
        read.expect_err("must be refused");
    }
}
