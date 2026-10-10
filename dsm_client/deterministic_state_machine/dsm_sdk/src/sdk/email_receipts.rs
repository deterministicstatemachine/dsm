// SPDX-License-Identifier: MIT OR Apache-2.0
//! Email receipts (DSM Amendment A17): after a send, the wallet asks the
//! receipt service to email the person paid a plain receipt.
//!
//! Outside the DSM protocol. A receipt is a courtesy note about a transfer
//! that already happened; nothing reads it back and it decides nothing. The
//! request names the recipient's email (from the contact's details), the
//! sender's name (from the owner's card), what was sent, the transfer's hash
//! and the phone's time, and carries the sender device's AK signature over
//! `H(DSM/receipt-email ‖ request with an empty signature)`, so the service
//! emails only what a device signed. The owner turns receipts on in the page,
//! with the consent screen saying exactly this; the page asks for a receipt
//! only then.

use prost::Message;

use dsm::common::domain_tags::TAG_DSM_RECEIPT_EMAIL;
use dsm::crypto::blake3::domain_hash;
use dsm::types::proto as pb;

use crate::sdk::contact_profile;
use crate::storage::client_db;

const MAX_TOKEN: usize = 32;
const MAX_AMOUNT: usize = 64;
const MAX_MEMO: usize = 256;
const MAX_REFERENCE: usize = 64;
const MAX_TIME_TEXT: usize = 64;

/// The 32 bytes the sender's signature signs: the request with its signature
/// field empty, under the receipt-email domain.
pub fn signing_digest(request: &pb::ReceiptEmailRequestV1) -> [u8; 32] {
    let unsigned = pb::ReceiptEmailRequestV1 {
        signature: Vec::new(),
        ..request.clone()
    };
    *domain_hash(TAG_DSM_RECEIPT_EMAIL, &unsigned.encode_to_vec()).as_bytes()
}

/// Why an intent is refused before anything is read: a field too long or
/// holding a control character.
pub fn check_intent(intent: &pb::ReceiptEmailIntentV1) -> Result<(), String> {
    if intent.recipient_device_id.len() != 32 {
        return Err(format!(
            "a device id is 32 bytes, not {}",
            intent.recipient_device_id.len()
        ));
    }
    for (field, value, max) in [
        ("currency", &intent.token, MAX_TOKEN),
        ("amount", &intent.amount, MAX_AMOUNT),
        ("note", &intent.memo, MAX_MEMO),
        ("reference", &intent.reference, MAX_REFERENCE),
        ("time", &intent.sent_at_local, MAX_TIME_TEXT),
    ] {
        if value.chars().count() > max {
            return Err(format!(
                "the receipt's {field} is longer than {max} characters"
            ));
        }
        if value.chars().any(char::is_control) {
            return Err(format!("the receipt's {field} holds a control character"));
        }
    }
    if intent.amount.is_empty() || intent.token.is_empty() || intent.reference.is_empty() {
        return Err("a receipt names an amount, a currency and the transfer it is for".into());
    }
    Ok(())
}

/// How the sender is named on the receipt: the owner's card's name, else the
/// first characters of the device id, which is what the recipient's wallet
/// shows for a contact it has no name for.
fn sender_name(device_id: &[u8]) -> Result<String, String> {
    match contact_profile::own_profile()? {
        Some(card) if !card.display_name.is_empty() => Ok(card.display_name),
        Some(..) | None => Ok(format!(
            "DSM user {}",
            crate::util::text_id::encode_base32_crockford(device_id)
                .chars()
                .take(8)
                .collect::<String>()
        )),
    }
}

/// The signed request for an intent: the recipient's email from the
/// contact's details, the sender's name, and the sender's AK signature.
pub fn build_request(
    intent: &pb::ReceiptEmailIntentV1,
) -> Result<pb::ReceiptEmailRequestV1, String> {
    check_intent(intent)?;
    let record = client_db::get_contact_by_device_id(&intent.recipient_device_id)
        .map_err(|e| format!("the contact was not read: {e}"))?
        .ok_or_else(|| "the person paid is not a contact".to_string())?;
    let email = match contact_profile::profile_of(&record)? {
        Some(profile) if !profile.email.is_empty() => profile.email,
        Some(..) | None => return Err("there is no email for this contact".into()),
    };
    let (card, _) = crate::sdk::connect::signed::own_card()?;
    let mut request = pb::ReceiptEmailRequestV1 {
        to_email: email,
        sender_name: sender_name(&card.device_id)?,
        token: intent.token.clone(),
        amount: intent.amount.clone(),
        memo: intent.memo.clone(),
        reference: intent.reference.clone(),
        sent_at_local: intent.sent_at_local.clone(),
        sender_device_id: card.device_id,
        sender_signing_public_key: card.signing_public_key,
        signature: Vec::new(),
    };
    let (_, sk) = crate::sdk::signing_authority::current_keypair()
        .map_err(|e| format!("this device's signing key: {e}"))?;
    request.signature = dsm::crypto::sphincs::sphincs_sign(&sk, &signing_digest(&request))
        .map_err(|e| format!("signing the receipt request: {e}"))?;
    Ok(request)
}

/// Posts a signed request to the receipt service and answers where the
/// receipt went, as the service states it, or the service's refusal.
pub async fn post(
    url: &str,
    request: &pb::ReceiptEmailRequestV1,
) -> Result<pb::ReceiptEmailResultV1, String> {
    if !url.starts_with("https://") {
        return Err(format!("the receipt service is not an https:// URL: {url}"));
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| format!("HTTP client init: {e}"))?;
    let response = client
        .post(format!("{}/v1/receipt", url.trim_end_matches('/')))
        .header("content-type", "application/x-protobuf")
        .body(request.encode_to_vec())
        .send()
        .await
        .map_err(|e| format!("the receipt service did not answer: {e}"))?;
    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|e| format!("the receipt service's answer was not read: {e}"))?;
    if !status.is_success() {
        return Err(format!(
            "the receipt service refused it ({status}): {}",
            String::from_utf8_lossy(&body)
        ));
    }
    pb::ReceiptEmailResultV1::decode(body.as_ref())
        .map_err(|e| format!("the receipt service answered no result: {e}"))
}

/// The receipt service this network names; a refusal when it names none.
pub fn service_url() -> Result<String, String> {
    let config = crate::network::NetworkConfigLoader::load_env_config()
        .map_err(|e| format!("the network config was not read: {e}"))?;
    config
        .receipt_service_url
        .ok_or_else(|| "this network has no receipt service".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent() -> pb::ReceiptEmailIntentV1 {
        pb::ReceiptEmailIntentV1 {
            recipient_device_id: vec![0x41; 32],
            token: "ERA".into(),
            amount: "50".into(),
            memo: "Thanks for lunch!".into(),
            reference: "7KQ2".into(),
            sent_at_local: "10/9/2026, 9:20 AM".into(),
        }
    }

    #[test]
    fn a_whole_intent_is_accepted() {
        assert_eq!(check_intent(&intent()), Ok(()));
    }

    #[test]
    fn an_intent_missing_its_amount_or_with_a_control_character_is_refused() {
        let no_amount = pb::ReceiptEmailIntentV1 {
            amount: String::new(),
            ..intent()
        };
        assert_eq!(
            check_intent(&no_amount),
            Err("a receipt names an amount, a currency and the transfer it is for".into()),
        );
        let bell = pb::ReceiptEmailIntentV1 {
            memo: "hi\u{7}".into(),
            ..intent()
        };
        assert_eq!(
            check_intent(&bell),
            Err("the receipt's note holds a control character".into())
        );
        let short_id = pb::ReceiptEmailIntentV1 {
            recipient_device_id: vec![1; 31],
            ..intent()
        };
        assert_eq!(
            check_intent(&short_id),
            Err("a device id is 32 bytes, not 31".into())
        );
    }

    /// The signature covers every field but itself: changing any other field
    /// changes what is signed.
    #[test]
    fn the_signed_digest_covers_every_field_but_the_signature() {
        let request = pb::ReceiptEmailRequestV1 {
            to_email: "jane@example.com".into(),
            sender_name: "Dana".into(),
            token: "ERA".into(),
            amount: "50".into(),
            memo: String::new(),
            reference: "7KQ2".into(),
            sent_at_local: String::new(),
            sender_device_id: vec![2; 32],
            sender_signing_public_key: vec![3; 64],
            signature: Vec::new(),
        };
        let digest = signing_digest(&request);
        let signed = pb::ReceiptEmailRequestV1 {
            signature: vec![9; 10],
            ..request.clone()
        };
        assert_eq!(signing_digest(&signed), digest);
        let redirected = pb::ReceiptEmailRequestV1 {
            to_email: "eve@example.com".into(),
            ..request
        };
        assert_ne!(signing_digest(&redirected), digest);
    }

    fn identity() -> crate::economic_fixtures::TestIdentity {
        crate::economic_fixtures::use_test_storage_dir();
        client_db::reset_database_for_tests();
        client_db::init_database().expect("init db");
        crate::economic_fixtures::create_identity(0x6B)
    }

    fn profile(name: &str, email: &str) -> pb::ContactProfileV1 {
        pb::ContactProfileV1 {
            display_name: name.into(),
            email: email.into(),
            phone: String::new(),
            phone_lookup_key: String::new(),
        }
    }

    /// The request names the contact's email and the owner's name, and its
    /// signature verifies under this device's AK; a request sent elsewhere
    /// than it was signed for does not.
    #[test]
    #[serial_test::serial]
    fn a_request_is_signed_by_the_device_and_names_the_contacts_email() {
        let me = identity();
        contact_profile::set_own_profile(profile("Dana", "")).expect("own card");
        client_db::store_contact_record_for_tests([0x41; 32], "jane");
        contact_profile::set_contact_profile(&[0x41; 32], profile("Jane", "jane@example.com"))
            .expect("details");

        let request = build_request(&intent()).expect("built");
        assert_eq!(
            (request.to_email.as_str(), request.sender_name.as_str()),
            ("jane@example.com", "Dana")
        );
        assert_eq!(request.sender_device_id, me.device_id.to_vec());
        assert_eq!(request.sender_signing_public_key, me.ak_public_key);
        let verifies = |r: &pb::ReceiptEmailRequestV1| {
            dsm::crypto::sphincs::sphincs_verify(
                &me.ak_public_key,
                &signing_digest(r),
                &r.signature,
            )
            .expect("the signature is checkable")
        };
        assert!(verifies(&request), "the device's AK signed the request");
        let redirected = pb::ReceiptEmailRequestV1 {
            to_email: "eve@example.com".into(),
            ..request.clone()
        };
        assert!(
            !verifies(&redirected),
            "a redirected request carries no valid signature"
        );
    }

    /// No email for the person paid: nothing is signed or sent.
    #[test]
    #[serial_test::serial]
    fn a_contact_without_an_email_gets_no_receipt() {
        identity();
        client_db::store_contact_record_for_tests([0x41; 32], "jane");
        assert_eq!(
            build_request(&intent()),
            Err("there is no email for this contact".into())
        );
        contact_profile::set_contact_profile(&[0x41; 32], profile("Jane", "")).expect("details");
        assert_eq!(
            build_request(&intent()),
            Err("there is no email for this contact".into())
        );
    }
}
