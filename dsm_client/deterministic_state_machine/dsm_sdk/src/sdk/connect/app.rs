// SPDX-License-Identifier: MIT OR Apache-2.0

//! An application account's side of DSM Connect (DSM Amendment A11), apart
//! from the routes: making offers, checking a wallet's accept and answers,
//! signing requests, and reading the facts its own account established.
//!
//! Nothing a wallet posts is evidence. A payment is a transfer this account
//! accepted onto its relationship with the wallet; holdings are a proof this
//! account verifies; a trade shows through this account's own vault or a
//! later proof.

use dsm::types::proto as generated;
use prost::Message;

use super::code::{check_endpoint, ConnectCode};
use super::grant::{narrows, scopes_from_wire, scopes_to_wire, Scope};
use super::signed::{
    canonical, card_identity, offer_digest, own_card, session_id, sign_own, verify, CardIdentity,
    Signed,
};
use super::wallet::{payment_ref, MAX_DISPLAY_NAME};
use super::d32;
use crate::storage::client_db::connect::AppSession;
use crate::util::text_id::encode_base32_crockford;

/// An offer this account made: the code it shows and the signed offer bytes.
pub struct MadeOffer {
    pub code: ConnectCode,
    pub offer: Vec<u8>,
}

/// Make and sign an offer under this account's AK.
pub fn make_offer(
    display_name: &str,
    endpoint: &str,
    cert_pin: [u8; 32],
    scopes: &[Scope],
    anchors: &[[u8; 32]],
) -> Result<MadeOffer, String> {
    check_endpoint(endpoint)?;
    let name = display_name.trim();
    if name.is_empty() || display_name.len() > MAX_DISPLAY_NAME {
        return Err(format!(
            "an application's name is 1 to {MAX_DISPLAY_NAME} bytes"
        ));
    }
    let (card, att_a) = own_card()?;
    let nonce = dsm::crypto::rng::generate_secure_random(32)
        .map_err(|e| format!("the offer's nonce: {e}"))?;
    let body = generated::AppConnectOfferBodyV1 {
        app_card: Some(card),
        app_att_a: att_a.to_vec(),
        display_name: name.to_string(),
        endpoint: endpoint.to_string(),
        scopes: scopes_to_wire(scopes),
        token_anchors: anchors.iter().map(|a| a.to_vec()).collect(),
        nonce,
    }
    .encode_to_vec();
    let signature = sign_own(Signed::Offer, &body)?;
    let digest = offer_digest(&body);
    Ok(MadeOffer {
        code: ConnectCode {
            endpoint: endpoint.to_string(),
            cert_pin,
            offer_digest: digest,
        },
        offer: generated::AppConnectOfferV1 { body, signature }.encode_to_vec(),
    })
}

/// A wallet's accept, checked.
pub struct VerifiedAccept {
    pub session_id: [u8; 32],
    pub offer_digest: [u8; 32],
    pub wallet: CardIdentity,
    pub wallet_card: generated::ContactQrV3,
    pub granted: Vec<Scope>,
}

/// Check `accept` against the offer it names, which `offer` is (as this
/// account stored it): the wallet's card derives its device on `network`, the
/// accept is signed under that card's AK, and the grant is never wider than
/// the offer asked.
pub fn verify_accept(
    accept: &generated::AppConnectAcceptV1,
    offer: &[u8],
    network: &str,
) -> Result<VerifiedAccept, String> {
    let body: generated::AppConnectAcceptBodyV1 = canonical(&accept.body, "the accept")?;
    let digest = d32(&body.offer_digest, "the accepted offer")?;
    let offer = generated::AppConnectOfferV1::decode(offer)
        .map_err(|e| format!("the stored offer: {e}"))?;
    if offer_digest(&offer.body) != digest {
        return Err("the accept answers another offer".into());
    }
    let offer_body: generated::AppConnectOfferBodyV1 = canonical(&offer.body, "the stored offer")?;
    let card = body
        .wallet_card
        .clone()
        .ok_or_else(|| "the accept carries no contact card".to_string())?;
    let wallet = card_identity(&card, &body.wallet_att_a, network)?;
    verify(Signed::Accept, &accept.body, &wallet.ak, &accept.signature)?;
    let asked = scopes_from_wire(&offer_body.scopes)?;
    let granted = scopes_from_wire(&body.granted)?;
    narrows(&asked, &granted)?;
    Ok(VerifiedAccept {
        session_id: session_id(&digest, &wallet.device_id),
        offer_digest: digest,
        wallet,
        wallet_card: card,
        granted,
    })
}

/// The `AppRequestV1` bytes of request `seq` of `session_id`, signed.
pub fn signed_request(
    session_id: &[u8; 32],
    seq: u64,
    kind: generated::app_request_body_v1::Kind,
) -> Result<Vec<u8>, String> {
    let body = generated::AppRequestBodyV1 {
        session_id: session_id.to_vec(),
        seq,
        kind: Some(kind),
    }
    .encode_to_vec();
    let signature = sign_own(Signed::Request, &body)?;
    Ok(generated::AppRequestV1 { body, signature }.encode_to_vec())
}

/// A wallet's answer, checked as the session's wallet's signed answer to one
/// of its requests. What it says is a notification.
pub fn verify_response(
    response: &generated::AppResponseV1,
    session: &AppSession,
) -> Result<generated::AppResponseBodyV1, String> {
    let body: generated::AppResponseBodyV1 = canonical(&response.body, "the answer")?;
    if body.session_id.as_slice() != session.session_id.as_slice() {
        return Err("the answer is another session's".into());
    }
    verify(
        Signed::Response,
        &response.body,
        &session.wallet_ak,
        &response.signature,
    )?;
    Ok(body)
}

/// Whether a payment memo answers request `seq` of `session_id`.
pub fn memo_answers(memo: &str, session_id: &[u8; 32], seq: u64) -> bool {
    let reference = payment_ref(session_id, seq);
    memo == reference || memo.starts_with(&format!("{reference} "))
}

/// The id of a transfer this account accepted from the session's wallet that
/// pays `amount` of `policy_commit` with the memo of request `seq`, and that
/// answers no other request. Read from this account's own history: each row
/// is a transfer accepted onto its relationship with the payer, its amount
/// and token from the signed operation, its memo from the terms that open it.
pub fn landed_payment(
    session: &AppSession,
    seq: u64,
    policy_commit: &[u8; 32],
    amount: u64,
) -> Result<Option<String>, String> {
    let own = crate::sdk::app_state::AppState::get_device_id()
        .ok_or_else(|| "this account has no device id".to_string())?;
    let own_b32 = encode_base32_crockford(&own);
    let wallet_b32 = encode_base32_crockford(&session.wallet_device_id);
    let rows =
        crate::storage::client_db::get_transaction_history(Some(&own_b32), Some(1_000), None)
            .map_err(|e| format!("this account's history: {e}"))?;
    for row in rows {
        if row.to_device != own_b32 || row.from_device != wallet_b32 || row.tx_type != "online" {
            continue;
        }
        let (Some(operation), Some(kept)) = (
            row.metadata
                .get(crate::storage::client_db::HISTORY_OPERATION_KEY),
            row.metadata
                .get(crate::storage::client_db::HISTORY_TERMS_KEY),
        ) else {
            continue;
        };
        let op = dsm::types::operations::Operation::from_bytes(operation)
            .map_err(|e| format!("transfer {}'s operation: {e}", row.tx_id))?;
        let dsm::types::operations::Operation::Transfer {
            policy_commit: paid_in,
            ..
        } = &op
        else {
            continue;
        };
        if paid_in != policy_commit {
            continue;
        }
        let opened = dsm::types::operations::TransferTerms::from_bytes(kept)
            .map_err(|e| format!("transfer {}'s terms: {e}", row.tx_id))?;
        let terms = crate::handlers::recipient_accept::transfer_terms(&op, &opened)
            .map_err(|e| format!("transfer {}: {e}", row.tx_id))?;
        if terms.amount < amount || !memo_answers(&terms.memo, &session.session_id, seq) {
            continue;
        }
        match crate::storage::client_db::connect::app_fact_used(row.tx_id.as_bytes())
            .map_err(|e| format!("the facts already granted on: {e}"))?
        {
            Some((other_session, other_seq))
                if other_session.as_slice() != session.session_id.as_slice()
                    || other_seq != seq =>
            {
                continue
            }
            _ => return Ok(Some(row.tx_id)),
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_memo_answers_only_its_own_request() {
        let s = [5u8; 32];
        let memo = super::super::wallet::payment_memo(&s, 4, "a capsule");
        assert!(memo_answers(&memo, &s, 4));
        assert!(!memo_answers(&memo, &s, 40), "4 is a prefix of 40, not 40");
        assert!(!memo_answers(&memo, &[6u8; 32], 4));
        assert!(!memo_answers("a capsule", &s, 4));
    }
}
