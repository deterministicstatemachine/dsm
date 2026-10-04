// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the host did, recorded as it happened, for the application to show.
//!
//! Each entry names a route the application called (or a relay exchange with
//! a wallet), what was asked, what came back, and this account's own state
//! before and after: its admitted economic position and root, and its Device
//! Tree commitment, read from its store. A record, never evidence.

use std::collections::VecDeque;
use std::sync::Mutex;

use dsm_sdk::generated as pb;
use prost::Message;

use crate::identity::Account;
use dsm_sdk::util::text_id::encode_base32_crockford;

/// How many entries the host keeps.
const KEPT: usize = 512;

/// An admitted economic position and, when it selected one, its root.
type Admitted = (u64, Option<[u8; 32]>);

/// This account's state, read from its store.
#[derive(Clone)]
pub struct Snapshot {
    /// The admitted economic position, if any; the read's failure, if it
    /// failed.
    economic: Result<Option<Admitted>, String>,
    device_tree: Option<[u8; 32]>,
}

impl Snapshot {
    pub fn take() -> Self {
        use dsm::economic::lineage::AdmittedEconomicPosition as A;
        let economic = dsm_sdk::storage::client_db::economic_lineage::get_admitted()
            .map(|admitted| {
                admitted.map(|a| match a {
                    A::SingleRoot {
                        economic_position,
                        economic_root,
                        ..
                    } => (economic_position, Some(economic_root)),
                    A::ResolvedSofi {
                        economic_position,
                        selected_root,
                        ..
                    } => (economic_position, Some(selected_root)),
                    A::UnresolvedSofi {
                        economic_position, ..
                    } => (economic_position, None),
                })
            })
            .map_err(|e| e.to_string());
        Self {
            economic,
            device_tree: dsm_sdk::sdk::app_state::AppState::get_device_tree_root(),
        }
    }
}

/// The admitted economic position a snapshot read: 0 before the first
/// admission (the activation root), unset when the store could not be read.
fn position(s: &Snapshot) -> Option<u64> {
    match &s.economic {
        Ok(Some((position, _))) => Some(*position),
        Ok(None) => Some(0),
        Err(..) => None,
    }
}

pub struct Record {
    account: Account,
    entries: Mutex<(u64, VecDeque<pb::AppHostActivityEntryV1>)>,
}

fn short(bytes: &[u8]) -> String {
    encode_base32_crockford(bytes).chars().take(10).collect()
}

/// The arguments a route call carries, as an `ArgPack`'s body.
fn args_body<M: Message + Default>(args: &[u8]) -> Result<M, prost::DecodeError> {
    M::decode(pb::ArgPack::decode(args)?.body.as_slice())
}

/// What a call asked, as the host renders it.
pub fn describe_call(method: &str, args: &[u8]) -> String {
    match method {
        "token.create" => match args_body::<pb::TokenCreateRequest>(args) {
            Ok(r) => {
                let supply = match <[u8; 16]>::try_from(r.genesis_supply_u128.as_slice()) {
                    Ok(be) => u128::from_be_bytes(be).to_string(),
                    Err(e) => format!("unreadable ({e})"),
                };
                format!(
                    "create token {} \u{201c}{}\u{201d}: supply {supply}, {} decimals",
                    r.ticker, r.alias, r.decimals
                )
            }
            Err(e) => format!("create a token: unreadable arguments ({e})"),
        },
        "faucet.claim" => "claim ERA from the network's faucet".into(),
        "wallet.sendSmart" => match args_body::<pb::OnlineTransferSmartRequest>(args) {
            Ok(r) => format!(
                "send {} {} to {}",
                r.amount,
                r.token_id,
                short(&r.recipient_device_id)
            ),
            Err(e) => format!("send a transfer: unreadable arguments ({e})"),
        },
        "sofi.createVault" => match args_body::<pb::SofiCreateVaultRequest>(args) {
            Ok(r) => format!(
                "open a SoFi vault {}/{} with reserves {}/{} at {} bps",
                short(&r.token_a_policy_commit),
                short(&r.token_b_policy_commit),
                r.reserve_a_entered,
                r.reserve_b_entered,
                r.fee_bps
            ),
            Err(e) => format!("open a SoFi vault: unreadable arguments ({e})"),
        },
        "connect.app.offer" => match args_body::<pb::ConnectAppOfferRequestV1>(args) {
            Ok(r) => format!("offer \u{201c}{}\u{201d} to wallets", r.display_name),
            Err(e) => format!("make a connect offer: unreadable arguments ({e})"),
        },
        "connect.app.request" => match args_body::<pb::ConnectAppRequestIntentV1>(args) {
            Ok(r) => match r.kind {
                Some(pb::connect_app_request_intent_v1::Kind::AcceptIssued(k)) => {
                    format!("ask the wallet to accept object {}", short(&k.anchor))
                }
                Some(pb::connect_app_request_intent_v1::Kind::Pay(k)) => format!(
                    "ask the wallet to pay {} of {} ({})",
                    k.amount,
                    short(&k.policy_commit),
                    k.memo
                ),
                Some(pb::connect_app_request_intent_v1::Kind::Quote(k)) => {
                    format!("ask the wallet for a SoFi quote of {}", k.amount_in)
                }
                Some(pb::connect_app_request_intent_v1::Kind::Swap(k)) => format!(
                    "ask the wallet to swap {} for at least {}",
                    k.amount_in, k.min_amount_out
                ),
                Some(pb::connect_app_request_intent_v1::Kind::Holdings(k)) => format!(
                    "ask the wallet to prove holdings of {} tokens",
                    k.policy_commits.len()
                ),
                None => "an empty request".into(),
            },
            Err(e) => format!("make a request: unreadable arguments ({e})"),
        },
        "connect.app.status" => match args_body::<pb::ConnectRequestRefV1>(args) {
            Ok(r) => format!("check what DSM established for request #{}", r.seq),
            Err(e) => format!("check a request: unreadable arguments ({e})"),
        },
        other => other.to_string(),
    }
}

/// What a call answered, as the host renders it.
pub fn describe_answer(response: &pb::IngressResponse) -> Result<String, String> {
    let bytes = match &response.result {
        Some(pb::ingress_response::Result::OkBytes(bytes)) => bytes,
        Some(pb::ingress_response::Result::Error(e)) => return Err(e.message.clone()),
        None => return Err("the ingress answered nothing".into()),
    };
    let Some(body) = bytes.strip_prefix(&[0x03]) else {
        return Ok(format!("{} bytes", bytes.len()));
    };
    let envelope = pb::Envelope::decode(body).map_err(|e| format!("the answer: {e}"))?;
    Ok(match envelope.payload {
        Some(pb::envelope::Payload::Error(e)) => return Err(e.message),
        Some(pb::envelope::Payload::TokenCreateResponse(r)) => {
            format!("token {} anchored at {}", r.ticker, short(&r.policy_anchor))
        }
        Some(pb::envelope::Payload::SofiVaultCreatedResponse(r)) => format!(
            "vault {} created at economic position {}",
            short(&r.vault_id),
            r.position
        ),
        Some(pb::envelope::Payload::ConnectReply(pb::ConnectReplyV1 { reply: Some(reply) })) => {
            match reply {
                pb::connect_reply_v1::Reply::Offer(o) => {
                    format!("connect code for offer {}", short(&o.offer_digest))
                }
                pb::connect_reply_v1::Reply::Request(r) => format!("request #{} signed", r.seq),
                pb::connect_reply_v1::Reply::Session(s) => {
                    format!("session {} with {}", short(&s.session_id), s.display_name)
                }
                pb::connect_reply_v1::Reply::Status(s) => format!(
                    "{}: {}",
                    match pb::ConnectFact::try_from(s.fact) {
                        Ok(pb::ConnectFact::Paid) => "PAID",
                        Ok(pb::ConnectFact::Holdings) => "HOLDINGS PROVEN",
                        _ => "nothing established",
                    },
                    s.fact_detail
                ),
                pb::connect_reply_v1::Reply::Requests(r) => {
                    format!("{} requests", r.requests.len())
                }
                other => format!("{other:?}"),
            }
        }
        Some(other) => {
            let text = format!("{other:?}");
            text.chars().take(160).collect()
        }
        None => "an empty answer".into(),
    })
}

impl Record {
    pub fn new(account: Account) -> Self {
        Self {
            account,
            entries: Mutex::new((1, VecDeque::new())),
        }
    }

    /// Record one call: what was asked, what came back, and this account's
    /// state on either side of it.
    pub fn add(
        &self,
        label: &crate::dispatch::Label,
        request: &pb::IngressRequest,
        response: &pb::IngressResponse,
        before: &Snapshot,
        after: &Snapshot,
    ) {
        let summary = match &request.operation {
            Some(pb::ingress_request::Operation::RouterInvoke(op)) => {
                describe_call(&op.method, &op.args)
            }
            Some(pb::ingress_request::Operation::RouterQuery(op)) => {
                describe_call(&op.method, &op.args)
            }
            _ => label.name.clone(),
        };
        let (result, mut error) = match describe_answer(response) {
            Ok(result) => (result, String::new()),
            Err(error) => (String::new(), error),
        };
        let (position_before, position_after) = (position(before), position(after));
        if let (Err(b), _) | (_, Err(b)) = (&before.economic, &after.economic) {
            error.push_str(&format!(
                " (this account's position could not be read: {b})"
            ));
        }
        let econ_root_after = match &after.economic {
            Ok(Some((_, Some(root)))) => root.to_vec(),
            _ => Vec::new(),
        };
        let device_tree_after = match after.device_tree {
            Some(root) => root.to_vec(),
            None => Vec::new(),
        };
        let entry = pb::AppHostActivityEntryV1 {
            seq: 0,
            kind: label.kind as i32,
            name: label.name.clone(),
            summary,
            result,
            error,
            position_before,
            position_after,
            econ_root_after,
            device_tree_after,
        };
        self.push(entry);
    }

    /// Record a relay exchange the host handled itself.
    pub fn relay(&self, name: &str, summary: String, outcome: Result<String, String>) {
        let after = Snapshot::take();
        let (result, error) = match outcome {
            Ok(result) => (result, String::new()),
            Err(error) => (String::new(), error),
        };
        let position = position(&after);
        self.push(pb::AppHostActivityEntryV1 {
            seq: 0,
            kind: pb::AppHostActivityKind::Relay as i32,
            name: name.to_string(),
            summary,
            result,
            error,
            position_before: position,
            position_after: position,
            econ_root_after: match &after.economic {
                Ok(Some((_, Some(root)))) => root.to_vec(),
                _ => Vec::new(),
            },
            device_tree_after: match after.device_tree {
                Some(root) => root.to_vec(),
                None => Vec::new(),
            },
        });
    }

    fn push(&self, mut entry: pb::AppHostActivityEntryV1) {
        match self.entries.lock() {
            Ok(mut guard) => {
                let (next, entries) = &mut *guard;
                entry.seq = *next;
                *next += 1;
                entries.push_back(entry);
                while entries.len() > KEPT {
                    entries.pop_front();
                }
            }
            Err(poisoned) => log::error!("[host] the activity record is poisoned: {poisoned}"),
        }
    }

    /// Every kept entry after `after`.
    pub fn since(&self, after: u64) -> Result<pb::AppHostActivityV1, String> {
        let guard = self
            .entries
            .lock()
            .map_err(|e| format!("the activity record: {e}"))?;
        let (next, entries) = &*guard;
        let set =
            dsm_sdk::sdk::storage_set::canonical_set(dsm::economic::register::BETA_NETWORK_ID)
                .map_err(|e| format!("the pinned storage set: {e}"))?;
        Ok(pb::AppHostActivityV1 {
            entries: entries.iter().filter(|e| e.seq > after).cloned().collect(),
            next: *next,
            device_id: self.account.device_id.to_vec(),
            storage_set_id: set.id().to_vec(),
            signature_bytes: dsm::crypto::sphincs::signature_bytes(
                dsm::crypto::sphincs::SphincsVariant::SPX256f,
            ) as u32,
        })
    }
}
