// SPDX-License-Identifier: MIT OR Apache-2.0
// BLE pairing + offline transaction end-to-end tests.
//
// Tests strict contact persistence, BLE address persistence, and the full
// bilateral offline flow with BLE addresses.
#![allow(clippy::disallowed_methods)]

use dsm_sdk as sdk;
use sdk::storage::client_db::{self, ContactRecord};

fn dev(id: u8) -> [u8; 32] {
    [id; 32]
}

fn gen(id: u8) -> [u8; 32] {
    [id; 32]
}

fn reset_db() {
    // Use in-memory DB to avoid stale schema from production DB files
    std::env::set_var("DSM_SDK_TEST_MODE", "1");
    client_db::reset_database_for_tests();
    if let Err(e) = client_db::init_database() {
        eprintln!("[ble_pairing_e2e] init_database skipped (already init): {e}");
    }
}

fn make_contact_record(device_id: [u8; 32], genesis_hash: [u8; 32], alias: &str) -> ContactRecord {
    let hash_bytes = blake3::hash(&device_id);
    ContactRecord {
        contact_id: format!("c_{}", &hash_bytes.to_string()[..8]),
        device_id: device_id.to_vec(),
        alias: alias.to_string(),
        genesis_hash: genesis_hash.to_vec(),
        public_key: vec![1u8; 32],
        kyber_public_key: Vec::new(),
        current_chain_tip: None,
        added_at: 100,
        verified: true,
        verification_proof: None,
        metadata: std::collections::HashMap::new(),
        ble_address: None,
        status: "Created".to_string(),
        needs_online_reconcile: false,
        last_seen_online_counter: 0,
        last_seen_ble_counter: 0,
        previous_chain_tip: None,
    }
}

fn store_test_contact(device_id: [u8; 32], genesis_hash: [u8; 32], alias: &str) -> ContactRecord {
    let record = make_contact_record(device_id, genesis_hash, alias);
    client_db::store_contact(&record).expect("store_contact");
    record
}

// =============================================================================
// Test 1: explicit contact storage creates a new record when missing
// =============================================================================
#[tokio::test]
#[serial_test::serial]
async fn test_store_contact_creates_when_missing() {
    reset_db();

    let device_id = dev(0x11);
    let genesis_hash = gen(0x22);

    // Verify no contact initially
    let result = client_db::get_contact_by_device_id(&device_id).unwrap();
    assert!(result.is_none(), "contact should not exist initially");

    let rec = store_test_contact(device_id, genesis_hash, "BleContact");
    assert_eq!(rec.device_id, device_id.to_vec());
    assert_eq!(rec.genesis_hash, genesis_hash.to_vec());
    assert_eq!(rec.alias, "BleContact");

    // Verify persisted in SQLite
    let re_read = client_db::get_contact_by_device_id(&device_id)
        .unwrap()
        .expect("contact should exist after store");
    assert_eq!(re_read.device_id, device_id.to_vec());
    assert_eq!(re_read.genesis_hash, genesis_hash.to_vec());
}

// =============================================================================
// Test 2: reading an existing contact preserves stored data
// =============================================================================
#[tokio::test]
#[serial_test::serial]
async fn test_read_contact_preserves_existing() {
    reset_db();

    let device_id = dev(0x33);
    let genesis_hash = gen(0x44);

    // Pre-store a contact with a BLE address
    let hash_bytes = blake3::hash(&device_id);
    let contact_id = format!("c_{}", &hash_bytes.to_string()[..8]);
    let record = ContactRecord {
        contact_id,
        device_id: device_id.to_vec(),
        alias: "ExistingContact".to_string(),
        genesis_hash: genesis_hash.to_vec(),
        public_key: vec![1u8; 32],
        kyber_public_key: Vec::new(),
        current_chain_tip: None,
        added_at: 100,
        verified: true,
        verification_proof: None,
        metadata: std::collections::HashMap::new(),
        ble_address: Some("AA:BB:CC:DD:EE:FF".to_string()),
        status: "Created".to_string(),
        needs_online_reconcile: false,
        last_seen_online_counter: 0,
        last_seen_ble_counter: 0,
        previous_chain_tip: None,
    };
    client_db::store_contact(&record).expect("store_contact");

    let result = client_db::get_contact_by_device_id(&device_id)
        .expect("contact lookup should succeed")
        .expect("contact should exist");
    assert_eq!(
        result.alias, "ExistingContact",
        "should return existing alias"
    );
    assert_eq!(
        result.ble_address,
        Some("AA:BB:CC:DD:EE:FF".to_string()),
        "should preserve existing BLE address"
    );
    assert_eq!(
        result.public_key,
        vec![1u8; 32],
        "should preserve public key"
    );
}

// =============================================================================
// Test 3: BLE address persistence after explicit store + update_contact_ble_status
// =============================================================================
#[tokio::test]
#[serial_test::serial]
async fn test_ble_address_persistence_after_ensure() {
    reset_db();

    let device_id = dev(0x55);
    let genesis_hash = gen(0x66);

    // Store contact without BLE address
    let hash_bytes = blake3::hash(&device_id);
    let contact_id = format!("c_{}", &hash_bytes.to_string()[..8]);
    let record = ContactRecord {
        contact_id,
        device_id: device_id.to_vec(),
        alias: "TestContact".to_string(),
        genesis_hash: genesis_hash.to_vec(),
        public_key: Vec::new(),
        kyber_public_key: Vec::new(),
        current_chain_tip: None,
        added_at: 100,
        verified: true,
        verification_proof: None,
        metadata: std::collections::HashMap::new(),
        ble_address: None,
        status: "Created".to_string(),
        needs_online_reconcile: false,
        last_seen_online_counter: 0,
        last_seen_ble_counter: 0,
        previous_chain_tip: None,
    };
    client_db::store_contact(&record).expect("store_contact");

    // Verify no BLE address yet
    let before = client_db::get_contact_by_device_id(&device_id)
        .unwrap()
        .unwrap();
    assert!(before.ble_address.is_none());

    // Update BLE address
    client_db::update_contact_ble_status(&device_id, None, Some("11:22:33:44:55:66"))
        .expect("update should succeed");

    // Verify BLE address persisted
    let after = client_db::get_contact_by_device_id(&device_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        after.ble_address,
        Some("11:22:33:44:55:66".to_string()),
        "BLE address should be persisted"
    );
}

// =============================================================================
// Test 4: BLE status update does not auto-create a missing contact
// =============================================================================
#[tokio::test]
#[serial_test::serial]
async fn test_ble_status_update_skips_missing_contact() {
    reset_db();

    let device_id = dev(0x77);

    // No contact in SQLite initially
    assert!(client_db::get_contact_by_device_id(&device_id)
        .unwrap()
        .is_none());

    // Strict path: missing contacts are not created implicitly.
    client_db::update_contact_ble_status(&device_id, None, Some("AA:BB:CC:DD:EE:FF"))
        .expect("update should succeed");

    assert!(
        client_db::get_contact_by_device_id(&device_id)
            .unwrap()
            .is_none(),
        "missing contact should remain missing after BLE status update"
    );
}

// =============================================================================
// Test 5: has_contact_for_device_id works with explicit store_contact
// =============================================================================
#[tokio::test]
#[serial_test::serial]
async fn test_has_contact_after_store() {
    reset_db();

    let device_id = dev(0x99);
    let genesis_hash = gen(0xAA);

    // Not found before ensure
    assert!(!client_db::has_contact_for_device_id(&device_id).unwrap());

    store_test_contact(device_id, genesis_hash, "StoredContact");

    // Now found
    assert!(client_db::has_contact_for_device_id(&device_id).unwrap());
}

// =============================================================================
// Test 6: BLE address roundtrip through SQLite (store + query + update)
// =============================================================================
#[tokio::test]
#[serial_test::serial]
async fn test_ble_address_roundtrip() {
    reset_db();

    let a_dev = dev(0xA1);
    let b_dev = dev(0xB2);
    let a_gen = gen(0xA2);
    let b_gen = gen(0xB3);

    // Store contacts in SQLite for both sides (simulating QR scan)
    let hash_b = blake3::hash(&b_dev);
    let rec_b = ContactRecord {
        contact_id: format!("c_{}", &hash_b.to_string()[..8]),
        device_id: b_dev.to_vec(),
        alias: "DeviceB".to_string(),
        genesis_hash: b_gen.to_vec(),
        public_key: vec![1u8; 32],
        kyber_public_key: Vec::new(),
        current_chain_tip: None,
        added_at: 1,
        verified: true,
        verification_proof: None,
        metadata: std::collections::HashMap::new(),
        ble_address: None,
        status: "Created".to_string(),
        needs_online_reconcile: false,
        last_seen_online_counter: 0,
        last_seen_ble_counter: 0,
        previous_chain_tip: None,
    };
    let hash_a = blake3::hash(&a_dev);
    let rec_a = ContactRecord {
        contact_id: format!("c_{}", &hash_a.to_string()[..8]),
        device_id: a_dev.to_vec(),
        alias: "DeviceA".to_string(),
        genesis_hash: a_gen.to_vec(),
        public_key: vec![2u8; 32],
        kyber_public_key: Vec::new(),
        current_chain_tip: None,
        added_at: 1,
        verified: true,
        verification_proof: None,
        metadata: std::collections::HashMap::new(),
        ble_address: None,
        status: "Created".to_string(),
        needs_online_reconcile: false,
        last_seen_online_counter: 0,
        last_seen_ble_counter: 0,
        previous_chain_tip: None,
    };
    client_db::store_contact(&rec_b).expect("store B on A's side");
    client_db::store_contact(&rec_a).expect("store A on B's side");

    // Verify contacts exist and have no BLE address
    assert!(client_db::has_contact_for_device_id(&b_dev).unwrap());
    assert!(client_db::has_contact_for_device_id(&a_dev).unwrap());
    let b_before = client_db::get_contact_by_device_id(&b_dev)
        .unwrap()
        .unwrap();
    assert!(b_before.ble_address.is_none());

    // Simulate BLE pairing: update BLE addresses
    client_db::update_contact_ble_status(&b_dev, None, Some("BB:BB:BB:BB:BB:BB"))
        .expect("update B's BLE address");
    client_db::update_contact_ble_status(&a_dev, None, Some("AA:AA:AA:AA:AA:AA"))
        .expect("update A's BLE address");

    // Verify BLE addresses persisted
    let b_after = client_db::get_contact_by_device_id(&b_dev)
        .unwrap()
        .unwrap();
    assert_eq!(b_after.ble_address, Some("BB:BB:BB:BB:BB:BB".to_string()));
    let a_after = client_db::get_contact_by_device_id(&a_dev)
        .unwrap()
        .unwrap();
    assert_eq!(a_after.ble_address, Some("AA:AA:AA:AA:AA:AA".to_string()));

    // Verify get_all_contacts returns them with BLE addresses
    let all = client_db::get_all_contacts().unwrap();
    assert!(all.len() >= 2);
    let b_from_all = all.iter().find(|c| c.device_id == b_dev.to_vec()).unwrap();
    assert_eq!(
        b_from_all.ble_address,
        Some("BB:BB:BB:BB:BB:BB".to_string())
    );
}

// =============================================================================
// Test 7: contact_id determinism — same device_id always produces same contact_id
// =============================================================================
#[tokio::test]
#[serial_test::serial]
async fn test_contact_id_deterministic() {
    let device_id = dev(0xCC);
    let hash_bytes = blake3::hash(&device_id);
    let id1 = format!("c_{}", &hash_bytes.to_string()[..8]);
    let id2 = format!("c_{}", &hash_bytes.to_string()[..8]);
    assert_eq!(
        id1, id2,
        "contact_id should be deterministic for same device_id"
    );
}
