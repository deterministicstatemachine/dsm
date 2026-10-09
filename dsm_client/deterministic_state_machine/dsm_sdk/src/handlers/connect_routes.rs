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
    decide, narrows, request_from_wire, scopes_from_wire, scopes_to_wire, Decision, DuelLock,
    DuelSigned, EscrowLock, Opponent, Request, Scope,
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
        | Request::DuelLock(..)
        | Request::DuelCollect { .. }
        | Request::Quote { .. }
        | Request::Swap { .. } => Ok(holdings::admission_pending(core)?
            .map(|position| format!("position {position} is still being admitted"))),
        // The other steps of a match admit no position: they sign, or write
        // a match's own cells.
        Request::AcceptIssued { .. }
        | Request::Contacts
        | Request::DuelSessionKey { .. }
        | Request::DuelReady { .. }
        | Request::DuelWithdraw { .. }
        | Request::DuelSign { .. }
        | Request::DuelSettle { .. } => Ok(None),
    }
}

/// This wallet's contacts as a CONTACTS request shares them (DSM Amendment
/// A16): their device ids, without the applications it connected to.
fn shared_contacts() -> Result<generated::ConnectContactsResultV1, String> {
    let contacts = crate::storage::client_db::get_all_contacts()
        .map_err(|e| format!("the wallet's contacts: {e}"))?;
    let apps: BTreeSet<[u8; 32]> = store::sessions()
        .map_err(|e| format!("the wallet's connected applications: {e}"))?
        .into_iter()
        .map(|s| s.app_device_id)
        .collect();
    Ok(crate::sdk::connect::wallet::contacts_to_share(
        contacts.into_iter().map(|c| c.device_id),
        &apps,
    ))
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

/// How many times a swap is traded when it keeps losing its vault's key to
/// another trade (each loss resolves Void, moving nothing).
const SWAP_ATTEMPTS: usize = 3;

/// The prefix of a recorded FACT_ESCROW_RELEASED in this account's facts.
const RELEASED_FACT: &[u8] = b"DSM/connect/escrow-released/v1";

/// A collect this account established (FACT_ESCROW_RELEASED): each vault the
/// request named, in its order, with its verdict cell and the final outcome
/// that paid the wallet. Recorded under the request once established, and
/// unique to those vaults: a vault is released once.
struct Released {
    vaults: Vec<([u8; 32], [u8; 32], Vec<u8>)>,
}

impl Released {
    fn vault_ids(&self) -> Vec<[u8; 32]> {
        self.vaults.iter().map(|(vault, ..)| *vault).collect()
    }

    /// The status this fact gives a request.
    fn show(&self, status: &mut generated::ConnectAppStatusV1) {
        status.fact = generated::ConnectFact::EscrowReleased as i32;
        status.escrow_vault_ids = self.vaults.iter().map(|(v, ..)| v.to_vec()).collect();
        if let Some((_, cell, _)) = self.vaults.first() {
            status.escrow_verdict_cell = cell.to_vec();
        }
        let outcomes: Vec<String> = self
            .vaults
            .iter()
            .map(|(.., outcome)| String::from_utf8_lossy(outcome).into_owned())
            .collect();
        status.fact_detail = format!(
            "each vault is Retired and its cell's final verdict ({}) pays the wallet",
            outcomes.join(", ")
        );
    }

    /// The prefix, the vault count, then each vault, its cell, its outcome's
    /// length and the outcome; big-endian lengths.
    fn encode(&self) -> Result<Vec<u8>, String> {
        let count = |n: usize| {
            u32::try_from(n)
                .map(u32::to_be_bytes)
                .map_err(|e| format!("a released fact's length: {e}"))
        };
        let mut out = RELEASED_FACT.to_vec();
        out.extend(count(self.vaults.len())?);
        for (vault, cell, outcome) in &self.vaults {
            out.extend(vault);
            out.extend(cell);
            out.extend(count(outcome.len())?);
            out.extend(outcome);
        }
        Ok(out)
    }

    /// Exactly what [`Self::encode`] wrote, and nothing else.
    fn decode(bytes: &[u8]) -> Result<Self, String> {
        fn take<'b>(bytes: &mut &'b [u8], n: usize) -> Result<&'b [u8], String> {
            let (head, rest) = bytes
                .split_at_checked(n)
                .ok_or_else(|| "a recorded release is cut short".to_string())?;
            *bytes = rest;
            Ok(head)
        }
        fn take_len(bytes: &mut &[u8]) -> Result<usize, String> {
            let raw: [u8; 4] = take(bytes, 4)?
                .try_into()
                .map_err(|e| format!("a recorded release's length: {e}"))?;
            usize::try_from(u32::from_be_bytes(raw))
                .map_err(|e| format!("a recorded release's length: {e}"))
        }
        fn take_id(bytes: &mut &[u8]) -> Result<[u8; 32], String> {
            take(bytes, 32)?
                .try_into()
                .map_err(|e| format!("a recorded release's id: {e}"))
        }
        let mut rest = bytes
            .strip_prefix(RELEASED_FACT)
            .ok_or_else(|| "the request's recorded fact is not a release".to_string())?;
        let count = take_len(&mut rest)?;
        let mut vaults = Vec::new();
        for _ in 0..count {
            let vault = take_id(&mut rest)?;
            let cell = take_id(&mut rest)?;
            let len = take_len(&mut rest)?;
            vaults.push((vault, cell, take(&mut rest, len)?.to_vec()));
        }
        if !rest.is_empty() {
            return Err("a recorded release has bytes past its last vault".into());
        }
        Ok(Self { vaults })
    }
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
            "connect.app.request" => self.connect_app_request(&i.args).await,
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
                    if let Err(e) =
                        crate::sdk::sofi_flow::resolve(&self.core_sdk, &own_set()?).await
                    {
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
                witnesses,
            } => match self.quote(token_in, token_out, *amount_in, witnesses).await {
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
                witnesses,
            } => {
                self.swap(token_in, token_out, *amount_in, *min_amount_out, witnesses)
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
            Request::Contacts => match shared_contacts() {
                Ok(shared) => Executed::carried_out(Some(
                    generated::app_response_body_v1::Result::Contacts(shared),
                )),
                Err(e) => Executed::failed(e),
            },
            Request::EscrowLock(lock) => match self.lock_stake(session, lock).await {
                Ok(locked) => Executed::carried_out(Some(
                    generated::app_response_body_v1::Result::EscrowLock(locked),
                )),
                Err(e) => Executed::failed(e),
            },
            Request::EscrowRelease { vault_ids } => self.collect(session, vault_ids).await,
            Request::DuelSessionKey { match_nonce } => {
                match crate::sdk::computed_flow::session_public_key(match_nonce) {
                    Ok(key) => Executed::carried_out(Some(
                        generated::app_response_body_v1::Result::DuelSessionKey(
                            generated::ConnectDuelSessionKeyResultV1 {
                                session_public_key: key,
                                signature_alg: u32::from(crate::sdk::sofi_flow::SIGNATURE_ALG),
                            },
                        ),
                    )),
                    Err(e) => Executed::failed(format!("the session key: {e}")),
                }
            }
            Request::DuelLock(lock) => match self.duel_lock(lock).await {
                Ok(locked) => Executed::carried_out(Some(
                    generated::app_response_body_v1::Result::DuelLock(locked),
                )),
                Err(e) => Executed::failed(e),
            },
            Request::DuelReady {
                match_cell,
                opponent_ready,
            } => {
                let readied = async {
                    let set = own_set()?;
                    crate::sdk::computed_flow::ready(
                        &self.core_sdk,
                        &set,
                        match_cell,
                        opponent_ready.as_deref(),
                    )
                    .await
                    .map_err(|e| format!("readying: {e}"))
                };
                match readied.await {
                    Ok(r) => Executed::carried_out(Some(
                        generated::app_response_body_v1::Result::DuelReady(
                            generated::ConnectDuelReadyResultV1 {
                                ready_signature: r.ready_signature,
                                cells: Some(duel_cells(&r.view)),
                            },
                        ),
                    )),
                    Err(e) => Executed::failed(e),
                }
            }
            Request::DuelWithdraw { match_cell } => {
                let withdrawn = async {
                    let set = own_set()?;
                    crate::sdk::computed_flow::withdraw(&self.core_sdk, &set, match_cell)
                        .await
                        .map_err(|e| format!("withdrawing: {e}"))
                };
                match withdrawn.await {
                    Ok(view) => Executed::carried_out(Some(
                        generated::app_response_body_v1::Result::DuelCells(duel_cells(&view)),
                    )),
                    Err(e) => Executed::failed(e),
                }
            }
            Request::DuelSign {
                match_cell,
                preceding,
                entry,
            } => {
                let signed = own_set().and_then(|set| {
                    crate::sdk::computed_flow::sign_entry(
                        &self.core_sdk,
                        &set,
                        match_cell,
                        &signed_entries(preceding),
                        entry,
                    )
                    .map_err(|e| format!("signing: {e}"))
                });
                match signed {
                    Ok(s) => Executed::carried_out(Some(
                        generated::app_response_body_v1::Result::DuelSign(
                            generated::ConnectDuelSignResultV1 {
                                index: s.index,
                                head: s.head.to_vec(),
                                signature: s.signature,
                            },
                        ),
                    )),
                    Err(e) => Executed::failed(e),
                }
            }
            Request::DuelSettle {
                match_cell,
                entries,
            } => {
                let settled = async {
                    let set = own_set()?;
                    crate::sdk::computed_flow::settle(
                        &self.core_sdk,
                        &set,
                        match_cell,
                        &signed_entries(entries),
                    )
                    .await
                    .map_err(|e| format!("settling: {e}"))
                };
                match settled.await {
                    Ok(view) => Executed::carried_out(Some(
                        generated::app_response_body_v1::Result::DuelCells(duel_cells(&view)),
                    )),
                    Err(e) => Executed::failed(e),
                }
            }
            Request::DuelCollect { vault_ids } => self.duel_collect(vault_ids).await,
        }
    }

    /// Lock a stake in a computed match (SoFi Amendment S22). The terms are
    /// built by `computed_flow::create` from the setup, read by the program
    /// this wallet registered; nothing in them comes from the request but
    /// the setup, the side, the stake and who the opponent is.
    async fn duel_lock(
        &self,
        lock: &DuelLock,
    ) -> Result<generated::ConnectDuelLockResultV1, String> {
        let set = own_set()?;
        let side = match lock.side {
            crate::sdk::connect::grant::Side::A => dsm::sofi::wire::MatchSide::A,
            crate::sdk::connect::grant::Side::B => dsm::sofi::wire::MatchSide::B,
        };
        let locked = crate::sdk::computed_flow::create(
            &self.core_sdk,
            &set,
            &crate::sdk::computed_flow::LockIntent {
                setup: lock.setup.clone(),
                side,
                token: lock.policy_commit,
                amount: lock.amount,
                opponent: (lock.opponent_genesis, lock.opponent_device_id),
                counterpart: lock.counterpart,
                opponent_holdings: lock.opponent_holdings.clone(),
            },
        )
        .await
        .map_err(|e| format!("locking the stake: {e}"))?;
        Ok(generated::ConnectDuelLockResultV1 {
            vault_id: locked.vault_id.to_vec(),
            match_cell: locked.match_cell.to_vec(),
            start_cell: locked.start_cell.to_vec(),
            external_commitment: locked.external_commitment.to_vec(),
            program: locked.program.to_vec(),
            session_public_key: locked.session_public_key,
            position: locked.position,
        })
    }

    /// Collect a computed match's result: each vault released to this wallet
    /// by `computed_flow::release`, which builds a release only once the
    /// match's outcome is final on a branch that pays this wallet. Every
    /// vault is checked first to be a stake in a match this wallet locked a
    /// stake in itself; any other is no business of the application.
    async fn duel_collect(&self, vault_ids: &[[u8; 32]]) -> Executed {
        let checked = async {
            let set = own_set()?;
            for vault_id in vault_ids {
                let held = crate::sdk::escrow_flow::vault(&self.core_sdk, &set, vault_id)
                    .await
                    .map_err(|e| format!("vault {}: {e}", short(vault_id)))?;
                let kept = crate::storage::client_db::duel_matches::get_match(&held.verdict_cell)
                    .map_err(|e| format!("the kept matches: {e}"))?;
                if held.program.is_none() || kept.is_none() {
                    return Err(format!(
                        "vault {} is not a stake in a computed match this wallet staked in",
                        short(vault_id)
                    ));
                }
            }
            Ok::<_, String>(set)
        };
        let set = match checked.await {
            Ok(set) => set,
            Err(e) => return Executed::failed(e),
        };
        let mut released = Vec::with_capacity(vault_ids.len());
        for vault_id in vault_ids {
            let done = crate::sdk::computed_flow::release(&self.core_sdk, &set, vault_id).await;
            let failure = match &done {
                Ok(outcome) => match outcome.state {
                    crate::sdk::sofi_flow::PositionState::Realized => None,
                    other => Some(format!(
                        "the release of {} at position {} did not realize: {other:?}",
                        short(vault_id),
                        outcome.position
                    )),
                },
                Err(e) => Some(format!("releasing {}: {e}", short(vault_id))),
            };
            if let Ok(outcome) = &done {
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
        witnesses: &[crate::sdk::connect::grant::OfferedWitness],
    ) -> Result<crate::sdk::sofi_flow::RouteFound, String> {
        let set = own_set()?;
        // The vaults the application owns, offered at its baselines (SoFi
        // Amendment S24): a vault this wallet holds nothing of starts there.
        if !witnesses.is_empty() {
            let offered: Vec<generated::ConnectVaultWitnessV1> =
                witnesses.iter().map(|w| w.to_wire()).collect();
            crate::sdk::sofi_flow::adopt_offered(&self.core_sdk, &set, &offered)
                .await
                .map_err(|e| format!("sofi.findRoute: {e}"))?;
        }
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
        witnesses: &[crate::sdk::connect::grant::OfferedWitness],
    ) -> Executed {
        // A trade that lost its vault's key to another resolves Void: nothing
        // moved, and the swap is quoted and traded again at the vault's new
        // head (SoFi Amendment S25 makes the loss provable to everyone, so
        // nothing waits on it). Invalid and a pending position never retry.
        let mut attempt = 1;
        loop {
            let (state, executed) = self
                .swap_once(token_in, token_out, amount_in, min_amount_out, witnesses)
                .await;
            if state != Some(crate::sdk::sofi_flow::PositionState::Void) || attempt >= SWAP_ATTEMPTS
            {
                return executed;
            }
            log::info!(
                "[connect] swap attempt {attempt}/{SWAP_ATTEMPTS} lost its vault's key: Void, \
                 trading again"
            );
            attempt += 1;
        }
    }

    /// One quote and trade of a swap, and the state its position resolved
    /// to, when it took one.
    async fn swap_once(
        &self,
        token_in: &[u8; 32],
        token_out: &[u8; 32],
        amount_in: u64,
        min_amount_out: u64,
        witnesses: &[crate::sdk::connect::grant::OfferedWitness],
    ) -> (Option<crate::sdk::sofi_flow::PositionState>, Executed) {
        let found = match self.quote(token_in, token_out, amount_in, witnesses).await {
            Ok(found) => found,
            Err(e) => return (None, Executed::failed(e)),
        };
        if found.hops.is_empty() {
            return (None, Executed::failed("no route among the vaults searched"));
        }
        let mut vault_ids: Vec<[u8; 32]> = Vec::with_capacity(found.hops.len());
        for hop in &found.hops {
            if !vault_ids.contains(&hop.vault_id) {
                vault_ids.push(hop.vault_id);
            }
        }
        let set = match own_set() {
            Ok(set) => set,
            Err(e) => return (None, Executed::failed(e)),
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
            Err(e) => return (None, Executed::failed(format!("sofi trade: {e}"))),
        };
        let state = position_state(outcome.state);
        let result = Some(generated::app_response_body_v1::Result::Swap(
            generated::ConnectSwapResultV1 {
                position: outcome.position,
                state: state as i32,
                vault_ids: vault_ids.iter().map(|v| v.to_vec()).collect(),
            },
        ));
        let executed = match outcome.state {
            crate::sdk::sofi_flow::PositionState::Realized => Executed::carried_out(result),
            other => Executed {
                outcome: generated::ConnectOutcome::Failed,
                reason: format!(
                    "the trade at position {} did not realize: {other:?}",
                    outcome.position
                ),
                result,
            },
        };
        (Some(outcome.state), executed)
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
        let (answer, answer_body) = match response {
            Some(bytes) => {
                let body = generated::AppResponseV1::decode(bytes.as_slice())
                    .map_err(|e| format!("{ROUTE}: the stored answer: {e}"))?
                    .body;
                (
                    Some(canonical::<generated::AppResponseBodyV1>(
                        &body,
                        "the stored answer",
                    )?),
                    body,
                )
            }
            None => (None, Vec::new()),
        };
        let mut status = generated::ConnectAppStatusV1 {
            session_id: sid.to_vec(),
            seq: req.seq,
            answered: answer.is_some(),
            answer_body,
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
            Request::Contacts => {
                status.fact_detail =
                    "contacts are the wallet's word: who its owner keeps, never proof of anything"
                        .into();
            }
            Request::AcceptIssued { .. } => {
                status.fact_detail =
                    "whether the wallet holds the object shows in a holdings proof".into();
            }
            Request::EscrowLock(lock) => self.lock_fact(&session, lock, &mut status).await?,
            Request::EscrowRelease { vault_ids } => {
                self.release_fact(&session, req.seq, vault_ids, &mut status)
                    .await?
            }
            Request::DuelLock(lock) => self.duel_lock_fact(&session, lock, &mut status).await?,
            Request::DuelReady { match_cell, .. }
            | Request::DuelWithdraw { match_cell }
            | Request::DuelSettle { match_cell, .. } => {
                self.duel_cells_fact(&session, match_cell, &mut status)
                    .await?
            }
            Request::DuelSessionKey { .. } | Request::DuelSign { .. } => {
                status.fact_detail = "a session key or a signature is relay data: a match proves \
                                      itself only from its cells"
                    .into();
            }
            Request::DuelCollect { vault_ids } => {
                self.duel_collect_fact(&session, req.seq, vault_ids, &mut status)
                    .await?
            }
        }
        Ok(Reply::Status(status))
    }

    /// FACT_DUEL_LOCKED (SoFi Amendment S22), from the vaults bound to the
    /// match cell, which this account derives from the setup itself, reading
    /// it with the program it registered: the wallet's vault there, Active,
    /// holding exactly the asked token and amount under exactly the terms the
    /// setup gives the wallet.
    async fn duel_lock_fact(
        &self,
        session: &store::AppSession,
        lock: &DuelLock,
        status: &mut generated::ConnectAppStatusV1,
    ) -> Result<(), String> {
        let wallet = wallet_player(session)?;
        let read = crate::sdk::outcome_programs::read_setup(&lock.setup)?;
        let named = match lock.side {
            crate::sdk::connect::grant::Side::A => &read.a,
            crate::sdk::connect::grant::Side::B => &read.b,
        };
        if (named.genesis, named.device_id) != (wallet.genesis, wallet.device_id) {
            status.fact_detail = "the setup does not name the wallet on its side".into();
            return Ok(());
        }
        let terms = crate::sdk::computed_flow::terms_of(
            &lock.setup,
            &read,
            lock.policy_commit,
            (wallet.genesis, wallet.device_id),
        )
        .map_err(|e| format!("the match's terms: {e}"))?;
        let cell = dsm::sofi::computed::match_cell_of(&terms);
        let set = own_set()?;
        let (vaults, search) = crate::sdk::escrow_flow::locked_by(
            &self.core_sdk,
            &set,
            &cell,
            &(wallet.genesis, wallet.device_id),
        )
        .await
        .map_err(|e| format!("the wallet's vaults on the match cell: {e}"))?;
        let held = vaults.iter().find(|v| {
            v.status == dsm::sofi::wire::VAULT_STATUS_ACTIVE
                && (v.token, v.amount) == (lock.policy_commit, lock.amount)
                && v.external_commitment == *terms.external_commitment()
                && v.program == Some(read.program)
                && v.computed.as_slice() == terms.branches()
        });
        match (held, search) {
            (Some(v), _) => {
                status.fact = generated::ConnectFact::DuelLocked as i32;
                status.escrow_vault_ids = vec![v.vault_id.to_vec()];
                status.escrow_verdict_cell = cell.to_vec();
                status.escrow_amount = v.amount;
                status.fact_detail = format!(
                    "the wallet's vault {} holds the stake under the setup's terms, Active on \
                     the match cell, decided by program {}",
                    short(&v.vault_id),
                    crate::sdk::outcome_programs::program_text(&read.program)
                );
            }
            (None, crate::sdk::sofi_flow::Search::Complete) => {
                status.fact_detail = "no vault of the wallet's holds this stake on the match \
                                      cell; an answer saying locked grants nothing"
                    .into();
            }
            (None, crate::sdk::sofi_flow::Search::Partial) => {
                status.fact_detail = "no vault of the wallet's holds this stake on the match \
                                      cell yet; not every vault there could be walked"
                    .into();
            }
        }
        Ok(())
    }

    /// The match's cells as this account reads them itself, through the
    /// wallet's own vault on the match cell: FACT_DUEL_STARTED or
    /// FACT_DUEL_WITHDRAWN at the start cell, FACT_DUEL_SETTLED once an
    /// occupant the registered program recognizes holds the match cell.
    async fn duel_cells_fact(
        &self,
        session: &store::AppSession,
        match_cell: &[u8; 32],
        status: &mut generated::ConnectAppStatusV1,
    ) -> Result<(), String> {
        let wallet = wallet_player(session)?;
        let set = own_set()?;
        let (vaults, _) = crate::sdk::escrow_flow::locked_by(
            &self.core_sdk,
            &set,
            match_cell,
            &(wallet.genesis, wallet.device_id),
        )
        .await
        .map_err(|e| format!("the wallet's vaults on the match cell: {e}"))?;
        let Some(vault) = vaults.iter().find(|v| v.program.is_some()) else {
            status.fact_detail = "the wallet holds no computed vault on this match cell".into();
            return Ok(());
        };
        let (_, view) =
            crate::sdk::computed_flow::view_of_vault(&self.core_sdk, &set, &vault.vault_id)
                .map_err(|e| format!("the match's cells: {e}"))?;
        status.escrow_verdict_cell = match_cell.to_vec();
        status.duel_cells = Some(duel_cells(&view));
        match (&view.occupant, &view.start) {
            (Some((label, ..)), _) => {
                status.fact = generated::ConnectFact::DuelSettled as i32;
                status.fact_detail = format!(
                    "the match cell holds an occupant the registered program decides {:?}",
                    String::from_utf8_lossy(label)
                );
            }
            (None, Some((dsm::sofi::wire::StartKind::Start, ..))) => {
                status.fact = generated::ConnectFact::DuelStarted as i32;
                status.fact_detail = "a Start holds the start cell: both sides readied".into();
            }
            (None, Some((dsm::sofi::wire::StartKind::Withdraw, ..))) => {
                status.fact = generated::ConnectFact::DuelWithdrawn as i32;
                status.fact_detail =
                    "a Withdraw holds the start cell: the match is void, both refunded".into();
            }
            (None, None) => {
                status.fact_detail = "nothing holds the match's start cell yet".into();
            }
        }
        Ok(())
    }

    /// FACT_ESCROW_RELEASED for a computed match: every named vault is a
    /// computed stake of the session's wallet's match, Retired at its walked
    /// head, and the match's final outcome names a branch that pays the
    /// wallet. Recorded once established, as for a signed match.
    async fn duel_collect_fact(
        &self,
        session: &store::AppSession,
        seq: u64,
        vault_ids: &[[u8; 32]],
        status: &mut generated::ConnectAppStatusV1,
    ) -> Result<(), String> {
        if let Some(recorded) =
            store::app_fact_of(&session.session_id, seq).map_err(|e| e.to_string())?
        {
            let released = Released::decode(&recorded)?;
            if released.vault_ids() != vault_ids {
                return Err(format!(
                    "request {seq}'s recorded release names other vaults than it asks about"
                ));
            }
            released.show(status);
            return Ok(());
        }
        let wallet = wallet_player(session)?;
        let set = own_set()?;
        let mut released = Released {
            vaults: Vec::with_capacity(vault_ids.len()),
        };
        for vault_id in vault_ids {
            let held = match crate::sdk::escrow_flow::vault(&self.core_sdk, &set, vault_id).await {
                Ok(held) => held,
                Err(e) => {
                    status.fact_detail = format!("vault {}: {e}", short(vault_id));
                    return Ok(());
                }
            };
            if held.program.is_none() {
                status.fact_detail = format!("vault {} is not a computed vault", short(vault_id));
                return Ok(());
            }
            if held.status != dsm::sofi::wire::VAULT_STATUS_RETIRED {
                status.fact_detail = format!(
                    "vault {} is not released yet; an answer saying collected grants nothing",
                    short(vault_id)
                );
                return Ok(());
            }
            let (terms, view) =
                crate::sdk::computed_flow::view_of_vault(&self.core_sdk, &set, vault_id)
                    .map_err(|e| format!("the match of vault {}: {e}", short(vault_id)))?;
            let Some(outcome) = view.final_outcome() else {
                status.fact_detail = format!(
                    "vault {} is Retired but its match's outcome is not final",
                    short(vault_id)
                );
                return Ok(());
            };
            let pays_wallet = terms.branch(&outcome).is_some_and(|b| {
                (b.recipient_genesis(), b.recipient_device_id())
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
            released
                .vaults
                .push((*vault_id, held.verdict_cell, outcome));
        }
        released.show(status);
        let record = released.encode()?;
        let used = || store::app_fact_used(&record).map_err(|e| e.to_string());
        if used()?.is_none() {
            if let Err(e) = store::app_record_fact(&record, &session.session_id, seq) {
                if used()?.is_none() {
                    return Err(e.to_string());
                }
            }
        }
        Ok(())
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
        // Only the wallet's own vaults on the cell are walked to their heads:
        // another vault there, the opponent's included, is not its stake.
        let (vaults, search) = crate::sdk::escrow_flow::locked_by(
            &self.core_sdk,
            &set,
            &cell,
            &(wallet.genesis, wallet.device_id),
        )
        .await
        .map_err(|e| format!("the wallet's vaults on the match's verdict cell: {e}"))?;
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
    ///
    /// Once established, the fact is recorded for the request and answered
    /// from that record after: a Retired vault stays Retired and a final
    /// verdict stays final, so nothing a later poll could read changes it.
    /// Each vault and its verdict are read through one context. Anything
    /// short of the fact is read again on every poll.
    async fn release_fact(
        &self,
        session: &store::AppSession,
        seq: u64,
        vault_ids: &[[u8; 32]],
        status: &mut generated::ConnectAppStatusV1,
    ) -> Result<(), String> {
        if let Some(recorded) =
            store::app_fact_of(&session.session_id, seq).map_err(|e| e.to_string())?
        {
            let released = Released::decode(&recorded)?;
            if released.vault_ids() != vault_ids {
                return Err(format!(
                    "request {seq}'s recorded release names other vaults than it asks about"
                ));
            }
            released.show(status);
            return Ok(());
        }
        let wallet = wallet_player(session)?;
        let referee = own_referee(&self.core_sdk)?;
        let set = own_set()?;
        let reads = crate::sdk::escrow_flow::EscrowReads::new(&self.core_sdk, &set)
            .map_err(|e| format!("the escrow reads: {e}"))?;
        let mut released = Released {
            vaults: Vec::with_capacity(vault_ids.len()),
        };
        for vault_id in vault_ids {
            let held = match reads.vault(vault_id).await {
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
            let verdict = reads
                .verdict(vault_id)
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
            released
                .vaults
                .push((*vault_id, held.verdict_cell, outcome));
        }
        released.show(status);
        // One release answers one request, as one transfer does: a second
        // request naming the same vaults is answered by reading them again.
        let record = released.encode()?;
        let used = || store::app_fact_used(&record).map_err(|e| e.to_string());
        if used()?.is_none() {
            if let Err(e) = store::app_record_fact(&record, &session.session_id, seq) {
                // A poll of the same request may have recorded it first.
                if used()?.is_none() {
                    return Err(e.to_string());
                }
            }
        }
        Ok(())
    }

    /// The witnesses this account offers `wallet` for its vaults that trade
    /// `token_in` or `token_out`, and why any vault it owns was left out.
    async fn witnesses(
        &self,
        token_in: &[u8],
        token_out: &[u8],
        wallet: ([u8; 32], [u8; 32]),
    ) -> Result<Vec<generated::ConnectVaultWitnessV1>, String> {
        let tokens = [
            d32(token_in, "the token in")?,
            d32(token_out, "the token out")?,
        ];
        let offered =
            crate::sdk::vault_baseline::offer(&self.core_sdk, &own_set()?, &tokens, wallet).await;
        for why in &offered.not_offered {
            log::info!("[connect] no witness offered for {why}; the wallet walks it");
        }
        Ok(offered.witnesses)
    }

    /// `connect.app.request`: the application signs a request for a
    /// connected wallet. A lock is checked as the wallet will build it: the
    /// opponent is neither the wallet nor this account.
    async fn connect_app_request(&self, args: &[u8]) -> Result<Reply, String> {
        const ROUTE: &str = "connect.app.request";
        let req: generated::ConnectAppRequestIntentV1 = body(args, ROUTE)?;
        let sid = d32(&req.session_id, "the session")?;
        let session = store::app_session(&sid)
            .map_err(|e| format!("{ROUTE}: {e}"))?
            .ok_or_else(|| format!("{ROUTE}: no such session"))?;
        use generated::app_request_body_v1::Kind as Body;
        use generated::connect_app_request_intent_v1::Kind as Intent;
        // A quote or a swap carries, for each vault this account owns that
        // trades either token, the wallet's witness at the baseline this
        // account published (SoFi Amendment S24). A vault it cannot witness
        // is left out, and the wallet walks that one from its genesis.
        let wallet = (session.wallet_genesis, session.wallet_device_id);
        let kind = match req.kind {
            Some(Intent::AcceptIssued(k)) => Body::AcceptIssued(k),
            Some(Intent::Pay(k)) => Body::Pay(k),
            Some(Intent::Quote(mut k)) => {
                k.vault_witnesses = self.witnesses(&k.token_in, &k.token_out, wallet).await?;
                Body::Quote(k)
            }
            Some(Intent::Swap(mut k)) => {
                k.vault_witnesses = self.witnesses(&k.token_in, &k.token_out, wallet).await?;
                Body::Swap(k)
            }
            Some(Intent::Holdings(k)) => Body::Holdings(k),
            Some(Intent::Contacts(k)) => Body::Contacts(k),
            Some(Intent::EscrowLock(k)) => Body::EscrowLock(k),
            Some(Intent::EscrowRelease(k)) => Body::EscrowRelease(k),
            Some(Intent::DuelSessionKey(k)) => Body::DuelSessionKey(k),
            Some(Intent::DuelLock(k)) => Body::DuelLock(k),
            Some(Intent::DuelReady(k)) => Body::DuelReady(k),
            Some(Intent::DuelWithdraw(k)) => Body::DuelWithdraw(k),
            Some(Intent::DuelSign(k)) => Body::DuelSign(k),
            Some(Intent::DuelSettle(k)) => Body::DuelSettle(k),
            Some(Intent::DuelCollect(k)) => Body::DuelCollect(k),
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
        // A stake in a computed match: the setup names the wallet on its side,
        // read by the program this account registered.
        if let Request::DuelLock(lock) = &asked {
            let read = crate::sdk::outcome_programs::read_setup(&lock.setup)
                .map_err(|e| format!("{ROUTE}: {e}"))?;
            let wallet = wallet_player(&session)?;
            let named = match lock.side {
                crate::sdk::connect::grant::Side::A => &read.a,
                crate::sdk::connect::grant::Side::B => &read.b,
            };
            if (named.genesis, named.device_id) != (wallet.genesis, wallet.device_id) {
                return Err(format!(
                    "{ROUTE}: the setup does not name the session's wallet on its side"
                ));
            }
        }
        let seq = store::app_append_request(&sid, |seq| app::signed_request(&sid, seq, kind))
            .map_err(|e| format!("{ROUTE}: {e}"))?;
        Ok(Reply::Request(generated::ConnectRequestRefV1 {
            session_id: sid.to_vec(),
            seq,
        }))
    }
}

/// The other side's signed entries a duel request carries, as the wallet's
/// flow takes them.
fn signed_entries(given: &[DuelSigned]) -> Vec<crate::sdk::computed_flow::SignedEntry> {
    given
        .iter()
        .map(|e| crate::sdk::computed_flow::SignedEntry {
            entry: e.entry.clone(),
            signature: e.signature.clone(),
        })
        .collect()
}

fn chain_state(state: dsm::route_chain::ChainState) -> generated::EscrowVerdictState {
    match state {
        dsm::route_chain::ChainState::LeaderHeld => generated::EscrowVerdictState::LeaderHeld,
        dsm::route_chain::ChainState::Preserved => generated::EscrowVerdictState::Preserved,
        dsm::route_chain::ChainState::Final => generated::EscrowVerdictState::Final,
    }
}

/// A computed match's cells on the wire.
fn duel_cells(view: &crate::sdk::computed_flow::MatchView) -> generated::ConnectDuelCellsV1 {
    let (start, start_state) = match &view.start {
        None => (
            generated::ConnectDuelStart::Open,
            generated::EscrowVerdictState::None,
        ),
        Some((dsm::sofi::wire::StartKind::Start, state)) => {
            (generated::ConnectDuelStart::Started, chain_state(*state))
        }
        Some((dsm::sofi::wire::StartKind::Withdraw, state)) => {
            (generated::ConnectDuelStart::Withdrawn, chain_state(*state))
        }
    };
    let (outcome, outcome_state, by_equivocation) = match &view.occupant {
        None => (Vec::new(), generated::EscrowVerdictState::None, None),
        Some((label, kind, state)) => (label.clone(), chain_state(*state), Some(*kind)),
    };
    generated::ConnectDuelCellsV1 {
        match_cell: view.match_cell.to_vec(),
        start_cell: view.start_cell.to_vec(),
        start: start as i32,
        start_state: start_state as i32,
        outcome,
        outcome_state: outcome_state as i32,
        by_equivocation: by_equivocation
            == Some(crate::sdk::computed_flow::OccupantKind::Equivocation),
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
