// Schema validation tests for canonical bilateral relationship path
//
// These tests verify the contact storage schema supports the canonical bilateral path:
// 1. Contact lifecycle states: Created → OnlineCapable → BleCapable → Suspended
// 2. Chain tip tracking (current_chain_tip field)
// 3. Reconciliation flag (needs_online_reconcile)
// 4. Tick counters (last_seen_online_counter, last_seen_ble_counter)
// 5. BLE address binding

use dsm_sdk::storage::client_db::ContactRecord;
use std::collections::HashMap;

#[test]
fn test_contact_record_schema_has_status_field() {
    // Verify ContactRecord has status field for lifecycle tracking
    let device_id = vec![1u8; 32];
    let genesis_hash = vec![2u8; 32];

    let contact = ContactRecord {
        contact_id: "test_contact".to_string(),
        device_id: device_id.clone(),
        public_key: vec![0u8; 32],
        kyber_public_key: Vec::new(),
        alias: "Test Contact".to_string(),
        genesis_hash: genesis_hash.clone(),
        current_chain_tip: Some(genesis_hash.clone()),
        added_at: 0,
        verified: true,
        verification_proof: None,
        metadata: HashMap::new(),
        ble_address: None,
        status: "Created".to_string(),
        needs_online_reconcile: false,
        last_seen_online_counter: 0,
        last_seen_ble_counter: 0,
        previous_chain_tip: None,
    };

    // Verify all fields exist
    assert_eq!(contact.status, "Created");
    assert!(!contact.needs_online_reconcile);
    assert_eq!(contact.last_seen_online_counter, 0);
    assert_eq!(contact.last_seen_ble_counter, 0);
    assert_eq!(contact.current_chain_tip, Some(genesis_hash));
}

#[test]
fn test_contact_record_status_transitions() {
    let device_id = vec![1u8; 32];
    let genesis_hash = vec![2u8; 32];

    // Created state
    let mut contact = ContactRecord {
        contact_id: "test_contact".to_string(),
        device_id: device_id.clone(),
        public_key: vec![0u8; 32],
        kyber_public_key: Vec::new(),
        alias: "Lifecycle Test".to_string(),
        genesis_hash: genesis_hash.clone(),
        current_chain_tip: Some(genesis_hash.clone()),
        added_at: 0,
        verified: true,
        verification_proof: None,
        metadata: HashMap::new(),
        ble_address: None,
        status: "Created".to_string(),
        needs_online_reconcile: false,
        last_seen_online_counter: 0,
        last_seen_ble_counter: 0,
        previous_chain_tip: None,
    };
    assert_eq!(contact.status, "Created");

    // Transition to OnlineCapable
    contact.status = "OnlineCapable".to_string();
    contact.last_seen_online_counter = 1;
    assert_eq!(contact.status, "OnlineCapable");
    assert_eq!(contact.last_seen_online_counter, 1);

    // Transition to BleCapable
    contact.status = "BleCapable".to_string();
    contact.last_seen_ble_counter = 2;
    contact.ble_address = Some("AA:BB:CC:DD:EE:FF".to_string());
    assert_eq!(contact.status, "BleCapable");
    assert_eq!(contact.last_seen_ble_counter, 2);
    assert!(contact.ble_address.is_some());

    // Transition to Suspended
    contact.status = "Suspended".to_string();
    assert_eq!(contact.status, "Suspended");
}

#[test]
fn test_contact_record_reconciliation_flag() {
    let device_id = vec![1u8; 32];
    let genesis_hash = vec![2u8; 32];

    let mut contact = ContactRecord {
        contact_id: "test_contact".to_string(),
        device_id: device_id.clone(),
        public_key: vec![0u8; 32],
        kyber_public_key: Vec::new(),
        alias: "Reconcile Test".to_string(),
        genesis_hash: genesis_hash.clone(),
        current_chain_tip: Some(genesis_hash.clone()),
        added_at: 0,
        verified: true,
        verification_proof: None,
        metadata: HashMap::new(),
        ble_address: None,
        status: "OnlineCapable".to_string(),
        needs_online_reconcile: false,
        last_seen_online_counter: 0,
        last_seen_ble_counter: 0,
        previous_chain_tip: None,
    };

    // Initially synchronized
    assert!(!contact.needs_online_reconcile);

    // Simulate chain tip mismatch during BLE handshake
    contact.needs_online_reconcile = true;
    assert!(contact.needs_online_reconcile);

    // After online reconciliation
    contact.needs_online_reconcile = false;
    contact.status = "BleCapable".to_string();
    assert!(!contact.needs_online_reconcile);
    assert_eq!(contact.status, "BleCapable");
}

#[test]
fn test_contact_record_chain_tip_tracking() {
    let device_id = vec![1u8; 32];
    let genesis_hash = vec![2u8; 32];
    let updated_tip = vec![3u8; 32];

    let mut contact = ContactRecord {
        contact_id: "test_contact".to_string(),
        device_id: device_id.clone(),
        public_key: vec![0u8; 32],
        kyber_public_key: Vec::new(),
        alias: "Chain Tip Test".to_string(),
        genesis_hash: genesis_hash.clone(),
        current_chain_tip: Some(genesis_hash.clone()),
        added_at: 0,
        verified: true,
        verification_proof: None,
        metadata: HashMap::new(),
        ble_address: None,
        status: "Created".to_string(),
        needs_online_reconcile: false,
        last_seen_online_counter: 0,
        last_seen_ble_counter: 0,
        previous_chain_tip: None,
    };

    // Initially matches genesis
    assert_eq!(contact.current_chain_tip, Some(genesis_hash.clone()));

    // Update after bilateral transaction
    contact.current_chain_tip = Some(updated_tip.clone());
    contact.status = "OnlineCapable".to_string();
    contact.last_seen_online_counter = 1;

    assert_eq!(contact.current_chain_tip, Some(updated_tip));
    assert_eq!(contact.status, "OnlineCapable");
    assert_eq!(contact.last_seen_online_counter, 1);
}

#[test]
fn test_contact_record_offline_ready_requirements() {
    let device_id = vec![1u8; 32];
    let genesis_hash = vec![2u8; 32];

    // Contact ready for offline operations
    let contact_ready = ContactRecord {
        contact_id: "ready_contact".to_string(),
        device_id: device_id.clone(),
        public_key: vec![0u8; 32],
        kyber_public_key: Vec::new(),
        alias: "Ready Contact".to_string(),
        genesis_hash: genesis_hash.clone(),
        current_chain_tip: Some(genesis_hash.clone()),
        added_at: 0,
        verified: true,
        verification_proof: None,
        metadata: HashMap::new(),
        ble_address: Some("AA:BB:CC:DD:EE:FF".to_string()),
        status: "BleCapable".to_string(),
        needs_online_reconcile: false,
        last_seen_online_counter: 1,
        last_seen_ble_counter: 2,
        previous_chain_tip: None,
    };

    // Verify offline readiness: status == BleCapable && !needs_online_reconcile
    assert_eq!(contact_ready.status, "BleCapable");
    assert!(!contact_ready.needs_online_reconcile);
    assert!(contact_ready.ble_address.is_some());

    // Contact NOT ready (needs reconciliation)
    let contact_not_ready = ContactRecord {
        contact_id: "not_ready_contact".to_string(),
        device_id: device_id.clone(),
        public_key: vec![0u8; 32],
        kyber_public_key: Vec::new(),
        alias: "Not Ready Contact".to_string(),
        genesis_hash: genesis_hash.clone(),
        current_chain_tip: Some(genesis_hash.clone()),
        added_at: 0,
        verified: true,
        verification_proof: None,
        metadata: HashMap::new(),
        ble_address: Some("11:22:33:44:55:66".to_string()),
        status: "OnlineCapable".to_string(),
        needs_online_reconcile: true, // Blocked due to reconciliation flag
        last_seen_online_counter: 1,
        last_seen_ble_counter: 0,
        previous_chain_tip: None,
    };

    // Verify offline operations should be blocked
    assert!(contact_not_ready.status != "BleCapable" || contact_not_ready.needs_online_reconcile);
}
