// SPDX-License-Identifier: MIT OR Apache-2.0

//! What a GATT identity read establishes, decided before anything about the
//! peer is recorded.
//!
//! The identity characteristic is open: any appliance can present another's
//! (device id, genesis) pair, so matching it authenticates nothing — only the
//! counterparty's signed frames do. It is the routing key: a reach connecting
//! for one appliance keeps a link only when the identity read on it names that
//! appliance, and records nothing about a link that does not.

use crate::generated as pb;
use prost::Message;

/// What a GATT identity read establishes.
#[derive(Debug, PartialEq, Eq)]
pub enum IdentityReadVerdict {
    /// A reach is connecting for another appliance: record nothing.
    NotExpected,
    /// The link carries this peer. `paired` when its contact already holds a
    /// BLE address (pairing completed), so no identity write-back is owed.
    Proceed { paired: bool },
}

/// Decide what the identity characteristic value `raw_proto` establishes for
/// a reach expecting the appliance `expected` (empty: the link is not a reach).
pub fn identity_read_verdict(
    raw_proto: &[u8],
    expected: &[u8],
) -> Result<IdentityReadVerdict, String> {
    let char_value = pb::BleIdentityCharValue::decode(raw_proto)
        .map_err(|e| format!("proto decode failed: {e}"))?;
    if char_value.genesis_hash.len() != 32 || char_value.device_id.len() != 32 {
        return Err("invalid identity field lengths".to_string());
    }
    match expected.len() {
        0 => {}
        32 if expected == char_value.device_id.as_slice() => {}
        32 => return Ok(IdentityReadVerdict::NotExpected),
        n => return Err(format!("expected device id is {n} bytes, not 32")),
    }
    let paired = crate::storage::client_db::get_contact_by_device_id(&char_value.device_id)
        .map_err(|e| format!("SQLite query error: {e}"))?
        .and_then(|contact| contact.ble_address)
        .is_some_and(|address| !address.is_empty());
    Ok(IdentityReadVerdict::Proceed { paired })
}

#[cfg(test)]
mod tests {
    use super::{identity_read_verdict, IdentityReadVerdict};
    use crate::generated as pb;
    use crate::storage::client_db::{store_contact, update_contact_ble_status, ContactRecord};
    use prost::Message;
    use serial_test::serial;

    fn init_test_db() {
        crate::economic_fixtures::use_test_storage_dir();
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
    }

    fn add_contact(device_id: [u8; 32]) {
        store_contact(&ContactRecord {
            contact_id: crate::util::text_id::encode_base32_crockford(&device_id),
            device_id: device_id.to_vec(),
            alias: "peer".to_string(),
            genesis_hash: vec![0xAA; 32],
            public_key: vec![0xBB; 64],
            kyber_public_key: vec![0x4B; 1184],
            current_chain_tip: Some(vec![0x70; 32]),
            verified: true,
            verification_proof: None,
            metadata: std::collections::HashMap::new(),
            ble_address: None,
            status: "OnlineCapable".to_string(),
            needs_online_reconcile: false,
            previous_chain_tip: None,
        })
        .expect("store the contact");
    }

    fn identity_value(device_id: [u8; 32]) -> Vec<u8> {
        pb::BleIdentityCharValue {
            genesis_hash: vec![0xAA; 32],
            device_id: device_id.to_vec(),
        }
        .encode_to_vec()
    }

    /// A reach for A that meets B records nothing about B and keeps no link.
    #[test]
    #[serial]
    fn a_reach_for_one_appliance_establishes_nothing_on_another() {
        init_test_db();
        let target = [0x4d; 32];
        let other = [0x16; 32];
        add_contact(other);

        assert_eq!(
            identity_read_verdict(&identity_value(other), &target),
            Ok(IdentityReadVerdict::NotExpected)
        );
    }

    /// The expected appliance proceeds; whether a write-back is owed is its
    /// contact's pairing, found by device id — not by the address it is at.
    #[test]
    #[serial]
    fn pairing_is_decided_by_the_contacts_device_id() {
        init_test_db();
        let device_id = [0x4d; 32];
        add_contact(device_id);
        assert_eq!(
            identity_read_verdict(&identity_value(device_id), &device_id),
            Ok(IdentityReadVerdict::Proceed { paired: false })
        );

        update_contact_ble_status(&device_id, None, Some("2C:DA:46:4B:73:FA"))
            .expect("persist the paired address");
        // Met at a new address, the paired contact is still paired.
        assert_eq!(
            identity_read_verdict(&identity_value(device_id), &[]),
            Ok(IdentityReadVerdict::Proceed { paired: true })
        );
    }

    #[test]
    #[serial]
    fn a_malformed_identity_or_expected_id_is_an_error() {
        init_test_db();
        let short = pb::BleIdentityCharValue {
            genesis_hash: vec![0xAA; 31],
            device_id: vec![0x4d; 32],
        }
        .encode_to_vec();
        assert!(identity_read_verdict(&short, &[]).is_err());
        assert!(identity_read_verdict(&identity_value([0x4d; 32]), &[0x4d; 16]).is_err());
    }
}
