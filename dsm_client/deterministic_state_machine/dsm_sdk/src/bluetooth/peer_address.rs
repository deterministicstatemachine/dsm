// SPDX-License-Identifier: MIT OR Apache-2.0

//! Where a contact's phone is over BLE, for an offline send to it.
//!
//! Two sources, in this order. The address the contact holds: persisted once
//! pairing confirmed it, and again whenever the contact's identity is seen at
//! a new one. Else the address its identity was seen at this session, before
//! pairing persisted one. Only a contact's identity, checked against the
//! contact's genesis, records an address here. BLE addresses rotate; the
//! native dispatch matches an address to the phone's current one by the
//! identity it was seen with.

use std::collections::HashMap;
use std::sync::Mutex;

use dsm::types::error::DsmError;
use once_cell::sync::Lazy;

/// The addresses contacts' identities were seen at this session.
static SEEN_THIS_SESSION: Lazy<Mutex<HashMap<[u8; 32], String>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Record that the identity of the contact `device_id` was seen at `address`
/// this session. An empty address records nothing.
pub fn record_sighting(device_id: &[u8; 32], address: &str) {
    if address.is_empty() {
        return;
    }
    let mut seen = SEEN_THIS_SESSION
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let previous = seen.insert(*device_id, address.to_string());
    if previous.as_deref() != Some(address) {
        log::info!(
            "[peer_address] {:02x}{:02x}... seen at {} (previously {:?})",
            device_id[0],
            device_id[1],
            address,
            previous
        );
    }
}

fn seen_this_session(device_id: &[u8; 32]) -> Option<String> {
    SEEN_THIS_SESSION
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(device_id)
        .cloned()
}

/// Where an offline send to `device_id` goes: the address its contact holds,
/// else the one its identity was seen at this session. `None` when the phones
/// have not met over BLE.
pub fn counterparty_address(device_id: &[u8; 32]) -> Result<Option<String>, DsmError> {
    let held = crate::storage::client_db::get_contact_by_device_id(device_id)
        .map_err(|e| {
            DsmError::storage(
                format!("the counterparty's contact: {e}"),
                None::<std::io::Error>,
            )
        })?
        .and_then(|contact| contact.ble_address)
        .filter(|address| !address.is_empty());
    Ok(held.or_else(|| seen_this_session(device_id)))
}

#[cfg(test)]
mod tests {
    use super::{counterparty_address, record_sighting};
    use crate::storage::client_db::{store_contact, update_contact_ble_status, ContactRecord};
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

    /// The address the contact holds wins over an address its identity was
    /// seen at this session: pairing confirmed it, and every later sighting at
    /// a new address rewrites it.
    #[test]
    #[serial]
    fn a_send_goes_to_the_address_the_contact_holds() {
        init_test_db();
        let device_id = [0x61; 32];
        add_contact(device_id);
        record_sighting(&device_id, "11:11:11:11:11:11");
        update_contact_ble_status(&device_id, None, Some("22:22:22:22:22:22"))
            .expect("persist the paired address");

        assert_eq!(
            counterparty_address(&device_id)
                .expect("resolve")
                .as_deref(),
            Some("22:22:22:22:22:22")
        );
    }

    /// Before pairing has persisted an address, a send goes to the one the
    /// contact's identity was seen at this session.
    #[test]
    #[serial]
    fn before_pairing_persists_one_the_sighting_is_the_address() {
        init_test_db();
        let device_id = [0x62; 32];
        add_contact(device_id);
        assert_eq!(counterparty_address(&device_id).expect("resolve"), None);

        record_sighting(&device_id, "33:33:33:33:33:33");
        assert_eq!(
            counterparty_address(&device_id)
                .expect("resolve")
                .as_deref(),
            Some("33:33:33:33:33:33")
        );
    }

    /// A phone never seen over BLE has no address, and an empty sighting
    /// records none.
    #[test]
    #[serial]
    fn a_phone_never_seen_has_no_address() {
        init_test_db();
        let device_id = [0x63; 32];
        add_contact(device_id);
        record_sighting(&device_id, "");
        assert_eq!(counterparty_address(&device_id).expect("resolve"), None);
        assert_eq!(counterparty_address(&[0x64; 32]).expect("resolve"), None);
    }
}
