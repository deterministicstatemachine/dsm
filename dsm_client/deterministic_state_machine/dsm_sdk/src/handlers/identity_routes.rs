// SPDX-License-Identifier: MIT OR Apache-2.0
//! Identity route handlers.

use dsm::types::error::DsmError;
use dsm::types::proto as generated;
use prost::Message;

use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{err, pack_bytes_ok, pack_envelope_ok};
use crate::bridge::{AppQuery, AppResult};
use crate::sdk::app_state::AppState;

/// This device's identity as `AppState` holds it.
struct OwnIdentity {
    device_id: [u8; 32],
    genesis: [u8; 32],
    ak: Vec<u8>,
}

fn own_identity() -> Result<OwnIdentity, DsmError> {
    let device_id: [u8; 32] = AppState::get_device_id()
        .ok_or_else(|| DsmError::InvalidState("device_id not set: no identity yet".into()))?
        .as_slice()
        .try_into()
        .map_err(|e| DsmError::InvalidState(format!("device_id: {e}")))?;
    let genesis: [u8; 32] = AppState::get_genesis_hash()
        .ok_or_else(|| DsmError::InvalidState("genesis_hash not set: no identity yet".into()))?
        .as_slice()
        .try_into()
        .map_err(|e| DsmError::InvalidState(format!("genesis_hash: {e}")))?;
    let ak = AppState::get_public_key()
        .ok_or_else(|| DsmError::InvalidState("signing key not set: no identity yet".into()))?;
    if ak.len() != 64 {
        return Err(DsmError::InvalidState(format!(
            "signing key is {} bytes, not 64",
            ak.len()
        )));
    }
    Ok(OwnIdentity {
        device_id,
        genesis,
        ak,
    })
}

/// The network this device's genesis committed.
fn committed_network() -> Result<String, DsmError> {
    let network = crate::sdk::economic_admission_flow::committed_network_id()?;
    String::from_utf8(network)
        .map_err(|e| DsmError::InvalidState(format!("the committed network id: {e}")))
}

/// The text form of a contact card: this prefix, then the card's protobuf
/// bytes in Base32 Crockford. `contact_code` writes it and `read_contact_code`
/// reads it; nothing else knows the format.
pub(crate) const CONTACT_CODE_PREFIX: &str = "dsm:contact/v3:";

/// The contact card a peer scans to add this device: its device id, genesis
/// and AK, and the network its genesis committed. The peer resolves the
/// device's directory entry on that network's pinned set, so the card names
/// no nodes.
pub(crate) fn contact_card() -> Result<generated::ContactQrV3, DsmError> {
    let own = own_identity()?;
    Ok(generated::ContactQrV3 {
        device_id: own.device_id.to_vec(),
        network: committed_network()?,
        genesis_hash: own.genesis.to_vec(),
        signing_public_key: own.ak,
        ..Default::default()
    })
}

/// This device's contact card as the text its QR encodes.
pub(crate) fn contact_code() -> Result<String, DsmError> {
    Ok(format!(
        "{CONTACT_CODE_PREFIX}{}",
        crate::util::text_id::encode_base32_crockford(&contact_card()?.encode_to_vec())
    ))
}

/// The contact card a scanned or pasted contact code carries. A card naming
/// another network than the one this device's genesis committed is refused:
/// its device's directory entry is on that network's set, not this one.
pub(crate) fn read_contact_code(text: &str) -> Result<generated::ContactQrV3, DsmError> {
    let body = text
        .trim()
        .strip_prefix(CONTACT_CODE_PREFIX)
        .ok_or_else(|| {
            DsmError::invalid_parameter(format!("a contact code starts with {CONTACT_CODE_PREFIX}"))
        })?;
    let bytes = crate::util::text_id::decode_base32_crockford(body)
        .ok_or_else(|| DsmError::invalid_parameter("the contact code is not Base32 Crockford"))?;
    let card = generated::ContactQrV3::decode(bytes.as_slice()).map_err(|e| {
        DsmError::invalid_parameter(format!("the contact code carries no contact card: {e}"))
    })?;
    for (field, len, expected) in [
        ("device id", card.device_id.len(), 32),
        ("genesis", card.genesis_hash.len(), 32),
        ("signing key", card.signing_public_key.len(), 64),
    ] {
        if len != expected {
            return Err(DsmError::invalid_parameter(format!(
                "the contact card's {field} is {len} bytes, not {expected}"
            )));
        }
    }
    let network = committed_network()?;
    if card.network != network {
        return Err(DsmError::invalid_parameter(format!(
            "the contact is on network \"{}\"; this device is on \"{network}\"",
            card.network
        )));
    }
    Ok(card)
}

impl AppRouterImpl {
    /// Dispatch handler for all `identity.*` query routes.
    pub(crate) async fn handle_identity_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            // ---------- identity.transport_headers_v3 ----------
            "identity.transport_headers_v3" => match crate::get_transport_headers_v3_bytes() {
                Ok(bytes) => pack_bytes_ok(bytes),
                Err(e) => err(format!("identity.transport_headers_v3 failed: {e}")),
            },

            // -------- identity.contact_code (the text this device's QR encodes) --------
            "identity.contact_code" => match contact_code() {
                Ok(code) => pack_envelope_ok(generated::envelope::Payload::AppStateResponse(
                    generated::AppStateResponse {
                        key: "contact_code".into(),
                        value: Some(code),
                    },
                )),
                Err(e) => err(format!("identity.contact_code failed: {e}")),
            },

            _ => err(format!("unknown identity query: {}", q.path)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::economic_fixtures;

    fn identity() -> economic_fixtures::TestIdentity {
        economic_fixtures::use_test_storage_dir();
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
        economic_fixtures::create_identity(0x5A)
    }

    /// A card's text form, written the way `contact_code` writes it.
    fn code_of(card: &generated::ContactQrV3) -> String {
        format!(
            "{CONTACT_CODE_PREFIX}{}",
            crate::util::text_id::encode_base32_crockford(&card.encode_to_vec())
        )
    }

    fn refusal(text: &str) -> String {
        read_contact_code(text)
            .expect_err("the text is refused")
            .to_string()
    }

    /// The contact card carries exactly the identity the device holds and the
    /// network its genesis committed, and its code reads back as that card.
    #[test]
    #[serial_test::serial]
    fn the_contact_code_is_the_devices_own_identity() {
        let identity = identity();

        let card = contact_card().expect("contact card");
        assert_eq!(card.device_id, identity.device_id.to_vec());
        assert_eq!(card.genesis_hash, identity.genesis.to_vec());
        assert_eq!(card.signing_public_key, identity.ak_public_key);
        assert_eq!(card.network.as_bytes(), economic_fixtures::NETWORK);

        let code = contact_code().expect("contact code");
        assert_eq!(code, code_of(&card));
        assert_eq!(read_contact_code(&code).expect("the code reads back"), card);
    }

    /// A card naming another network is refused before any directory read:
    /// its device's entry is on that network's set.
    #[test]
    #[serial_test::serial]
    fn a_contact_code_naming_another_network_is_refused() {
        identity();
        let mut card = contact_card().expect("contact card");
        card.network = "another-network".into();
        let refusal = refusal(&code_of(&card));
        assert!(refusal.contains("\"another-network\""), "{refusal}");
    }

    /// Text that is not a whole contact code names nobody.
    #[test]
    #[serial_test::serial]
    fn text_that_is_not_a_contact_code_is_refused() {
        identity();
        let card = contact_card().expect("contact card");
        let code = code_of(&card);

        let bare = code
            .strip_prefix(CONTACT_CODE_PREFIX)
            .expect("the code has its prefix");
        assert!(refusal(bare).contains("starts with"));
        assert!(refusal(&format!("{CONTACT_CODE_PREFIX}!!")).contains("Base32"));
        let not_a_card = format!(
            "{CONTACT_CODE_PREFIX}{}",
            crate::util::text_id::encode_base32_crockford(&[0xFF, 0xFF, 0xFF])
        );
        assert!(refusal(&not_a_card).contains("no contact card"));

        let mut short = card.clone();
        short.device_id.pop();
        assert!(refusal(&code_of(&short)).contains("device id is 31 bytes"));
        let mut short = card.clone();
        short.genesis_hash.pop();
        assert!(refusal(&code_of(&short)).contains("genesis is 31 bytes"));
        let mut short = card;
        short.signing_public_key.pop();
        assert!(refusal(&code_of(&short)).contains("signing key is 63 bytes"));
    }
}
