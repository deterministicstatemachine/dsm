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

/// An amount a request names, as people read it: in the object's own units
/// when this account knows the object, in its smallest units otherwise.
fn amount_of(policy_commit: &[u8], amount: u64) -> String {
    match <[u8; 32]>::try_from(policy_commit) {
        Ok(commit) => dsm_sdk::sdk::connect::wallet::amount_text(&commit, amount),
        Err(..) => format!("{amount} smallest units of {}", short(policy_commit)),
    }
}

/// A request's memo after what it asks, or nothing when it carries none.
fn memo_note(memo: &str) -> String {
    match memo.trim() {
        "" => String::new(),
        memo => format!(" ({memo})"),
    }
}

/// What a call asked, as the host renders it.
pub fn describe_call(method: &str, args: &[u8]) -> String {
    match method {
        "token.create" => match args_body::<pb::TokenCreateRequest>(args) {
            Ok(r) => format!(
                "issue {} \u{201c}{}\u{201d}: supply {}, {} decimals",
                r.ticker, r.alias, r.genesis_supply_entered, r.decimals
            ),
            Err(e) => format!("issue an object: unreadable arguments ({e})"),
        },
        "faucet.claim" => "claim ERA from the network's faucet".into(),
        "wallet.sendSmart" => match args_body::<pb::OnlineTransferSmartRequest>(args) {
            Ok(r) => format!(
                "give {} {} to {}",
                r.amount,
                r.token_id,
                short(&r.recipient_device_id)
            ),
            Err(e) => format!("give an object: unreadable arguments ({e})"),
        },
        "sofi.createVault" => match args_body::<pb::SofiCreateVaultRequest>(args) {
            Ok(r) => format!(
                "open a vault {}/{} with reserves {}/{} at {} bps",
                short(&r.token_a_policy_commit),
                short(&r.token_b_policy_commit),
                r.reserve_a_entered,
                r.reserve_b_entered,
                r.fee_bps
            ),
            Err(e) => format!("open a vault: unreadable arguments ({e})"),
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
                    "ask the wallet to send {}{}",
                    amount_of(&k.policy_commit, k.amount),
                    memo_note(&k.memo)
                ),
                Some(pb::connect_app_request_intent_v1::Kind::Quote(k)) => format!(
                    "ask the wallet to price {}",
                    amount_of(&k.token_in, k.amount_in)
                ),
                Some(pb::connect_app_request_intent_v1::Kind::Swap(k)) => format!(
                    "ask the wallet to trade {} for at least {}",
                    amount_of(&k.token_in, k.amount_in),
                    amount_of(&k.token_out, k.min_amount_out)
                ),
                Some(pb::connect_app_request_intent_v1::Kind::Holdings(k)) => {
                    match k.policy_commits.len() {
                        1 => "ask the wallet to prove what it owns of one object".to_string(),
                        n => format!("ask the wallet to prove what it owns of {n} objects"),
                    }
                }
                Some(pb::connect_app_request_intent_v1::Kind::Sign(k)) => {
                    format!("ask the wallet to sign: {}", k.statement)
                }
                Some(pb::connect_app_request_intent_v1::Kind::Contacts(..)) => {
                    "ask the wallet which of its contacts are here".to_string()
                }
                Some(pb::connect_app_request_intent_v1::Kind::EscrowLock(k)) => format!(
                    "ask the wallet to lock {} as side {} against {}{}",
                    amount_of(&k.policy_commit, k.amount),
                    match k.side {
                        1 => "A",
                        2 => "B",
                        _ => "?",
                    },
                    short(&k.opponent_device_id),
                    memo_note(&k.memo)
                ),
                Some(pb::connect_app_request_intent_v1::Kind::Contribute(k)) => format!(
                    "ask the wallet to commit {}{}",
                    amount_of(&k.policy_commit, k.amount),
                    memo_note(&k.memo)
                ),
                Some(pb::connect_app_request_intent_v1::Kind::ContributionRelease(k)) => format!(
                    "ask the wallet to take back {}",
                    k.vault_ids
                        .iter()
                        .map(|v| short(v))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                Some(pb::connect_app_request_intent_v1::Kind::EscrowRelease(k)) => format!(
                    "ask the wallet to collect a match result from {}",
                    k.vault_ids
                        .iter()
                        .map(|v| short(v))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                Some(pb::connect_app_request_intent_v1::Kind::DuelSessionKey(k)) => format!(
                    "ask the wallet for its session key for match nonce {}",
                    short(&k.match_nonce)
                ),
                Some(pb::connect_app_request_intent_v1::Kind::DuelLock(k)) => format!(
                    "ask the wallet to stake {} as side {} in a computed match against {}{}",
                    amount_of(&k.policy_commit, k.amount),
                    match k.side {
                        1 => "A",
                        2 => "B",
                        _ => "?",
                    },
                    short(&k.opponent_device_id),
                    memo_note(&k.memo)
                ),
                Some(pb::connect_app_request_intent_v1::Kind::DuelReady(k)) => {
                    format!("ask the wallet to ready for match {}", short(&k.match_cell))
                }
                Some(pb::connect_app_request_intent_v1::Kind::DuelWithdraw(k)) => format!(
                    "ask the wallet to withdraw from match {}",
                    short(&k.match_cell)
                ),
                Some(pb::connect_app_request_intent_v1::Kind::DuelSign(k)) => format!(
                    "ask the wallet to sign its next entry of match {}",
                    short(&k.match_cell)
                ),
                Some(pb::connect_app_request_intent_v1::Kind::DuelSettle(k)) => {
                    format!("ask the wallet to settle match {}", short(&k.match_cell))
                }
                Some(pb::connect_app_request_intent_v1::Kind::DuelCollect(k)) => format!(
                    "ask the wallet to collect a computed match result from {}",
                    k.vault_ids
                        .iter()
                        .map(|v| short(v))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                None => "an empty request".into(),
            },
            Err(e) => format!("make a request: unreadable arguments ({e})"),
        },
        "escrow.adjudicate" | "escrow.sign" => match args_body::<pb::EscrowOutcomeRequest>(args) {
            Ok(r) => format!(
                "{} {:?} for vault {}",
                match method {
                    "escrow.adjudicate" => "decide",
                    _ => "sign",
                },
                String::from_utf8_lossy(&r.outcome),
                short(&r.vault_id)
            ),
            Err(e) => format!("{method}: unreadable arguments ({e})"),
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
        Some(pb::envelope::Payload::FaucetClaimResponse(r)) => r.message,
        Some(pb::envelope::Payload::OnlineTransferResponse(r)) => r.message,
        Some(pb::envelope::Payload::StorageSyncResponse(r)) => {
            let mut line = format!(
                "pulled {}, processed {}, pushed {}",
                r.pulled, r.processed, r.pushed
            );
            if !r.errors.is_empty() {
                line.push_str(&format!("; {}", r.errors.join("; ")));
            }
            if !r.more_pending.is_empty() {
                line.push_str(&format!("; more waits on {}", r.more_pending.join(", ")));
            }
            line
        }
        Some(pb::envelope::Payload::SofiVaultsResponse(r)) => {
            format!("{} vault(s) of this account", r.vaults.len())
        }
        Some(pb::envelope::Payload::TokenCreateResponse(r)) => {
            format!(
                "object {} anchored at {}",
                r.ticker,
                short(&r.policy_anchor)
            )
        }
        Some(pb::envelope::Payload::EscrowVerdictResponse(r)) => format!(
            "the verdict cell {} holds {}",
            short(&r.verdict_cell),
            match r.outcome.as_slice() {
                [] => "no verdict yet".to_string(),
                outcome => format!(
                    "{:?} ({:?})",
                    String::from_utf8_lossy(outcome),
                    pb::EscrowVerdictState::try_from(r.state)
                ),
            }
        ),
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
                    format!(
                        "connection {} with {}",
                        short(&s.session_id),
                        s.display_name
                    )
                }
                pb::connect_reply_v1::Reply::Status(s) => format!(
                    "{}: {}",
                    match pb::ConnectFact::try_from(s.fact) {
                        Ok(pb::ConnectFact::Paid) => "RECEIVED",
                        Ok(pb::ConnectFact::Holdings) => "OWNS",
                        Ok(pb::ConnectFact::Signed) => "SIGNED",
                        Ok(pb::ConnectFact::EscrowLocked) => "STAKE LOCKED",
                        Ok(pb::ConnectFact::EscrowReleased) => "RESULT COLLECTED",
                        Ok(pb::ConnectFact::Contributed) => "CONTRIBUTED",
                        Ok(pb::ConnectFact::ContributionReleased) => "TAKEN BACK",
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

#[cfg(test)]
mod tests {
    use super::*;
    use pb::connect_app_request_intent_v1::Kind;

    /// What `connect.app.request` records for a request of `kind`.
    fn asked(kind: Kind) -> String {
        let body = pb::ConnectAppRequestIntentV1 {
            session_id: vec![7; 32],
            kind: Some(kind),
        }
        .encode_to_vec();
        let args = pb::ArgPack {
            schema_hash: None,
            codec: pb::Codec::Proto as i32,
            body,
        };
        describe_call("connect.app.request", &args.encode_to_vec())
    }

    /// What a call answered with `reply`, as the record shows it.
    fn answered(reply: pb::connect_reply_v1::Reply) -> Result<String, String> {
        let envelope = pb::Envelope {
            version: 3,
            payload: Some(pb::envelope::Payload::ConnectReply(pb::ConnectReplyV1 {
                reply: Some(reply),
            })),
            ..Default::default()
        };
        let mut bytes = vec![0x03];
        bytes.extend(envelope.encode_to_vec());
        describe_answer(&pb::IngressResponse {
            result: Some(pb::ingress_response::Result::OkBytes(bytes)),
        })
    }

    /// The record speaks as the clients do: `send`, `price`, `trade`, what a
    /// wallet owns, connections; an amount in the object's own units, or in
    /// its smallest units when the object cannot be named; no memo where a
    /// request carries none.
    #[test]
    fn the_record_reads_in_the_clients_words_and_each_objects_own_units() -> Result<(), String> {
        let era = dsm::core::token::token_state_manager::builtin_policy_commit_for_token("ERA")
            .ok_or_else(|| "ERA is not built in".to_string())?
            .to_vec();
        let send = |amount, memo: &str| {
            asked(Kind::Pay(pb::ConnectPayV1 {
                policy_commit: era.clone(),
                amount,
                memo: memo.into(),
            }))
        };
        assert_eq!(send(20, ""), "ask the wallet to send 0.20 ERA");
        assert_eq!(
            send(5, "a capsule"),
            "ask the wallet to send 0.05 ERA (a capsule)"
        );
        assert_eq!(
            asked(Kind::Quote(pb::ConnectQuoteV1 {
                token_in: era.clone(),
                token_out: vec![9; 32],
                amount_in: 150,
                vault_witnesses: Vec::new(),
            })),
            "ask the wallet to price 1.50 ERA"
        );
        // Not a 32-byte id: no object is named, so the smallest units show.
        assert_eq!(
            asked(Kind::Swap(pb::ConnectSwapV1 {
                token_in: era.clone(),
                token_out: vec![9; 5],
                amount_in: 150,
                min_amount_out: 4510,
                vault_witnesses: Vec::new(),
            })),
            format!(
                "ask the wallet to trade 1.50 ERA for at least 4510 smallest units of {}",
                short(&[9; 5])
            )
        );
        assert_eq!(
            asked(Kind::Holdings(pb::ConnectHoldingsV1 {
                policy_commits: vec![era.clone()],
            })),
            "ask the wallet to prove what it owns of one object"
        );
        assert_eq!(
            asked(Kind::Holdings(pb::ConnectHoldingsV1 {
                policy_commits: vec![era.clone(), vec![9; 32]],
            })),
            "ask the wallet to prove what it owns of 2 objects"
        );
        assert_eq!(
            answered(pb::connect_reply_v1::Reply::Session(pb::ConnectSessionV1 {
                session_id: vec![1; 32],
                display_name: "My Game".into(),
                ..Default::default()
            })),
            Ok(format!("connection {} with My Game", short(&[1; 32])))
        );
        assert_eq!(
            answered(pb::connect_reply_v1::Reply::Status(
                pb::ConnectAppStatusV1 {
                    fact: pb::ConnectFact::Holdings as i32,
                    fact_detail: "proven at the wallet's position 4".into(),
                    ..Default::default()
                }
            )),
            Ok("OWNS: proven at the wallet's position 4".to_string())
        );
        Ok(())
    }
}
