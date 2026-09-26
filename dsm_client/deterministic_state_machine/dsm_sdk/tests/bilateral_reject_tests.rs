// SPDX-License-Identifier: MIT OR Apache-2.0
// Basic tests for bilateral rejection flow (Rust-side)

#![allow(clippy::disallowed_methods)]

use std::sync::Arc;
use tokio::sync::RwLock;

use dsm_sdk as sdk;
use sdk::bluetooth::bilateral_ble_handler::{BilateralBleHandler, BilateralPhase};

use dsm::core::bilateral_transaction_manager::BilateralTransactionManager;
use dsm::types::operations::Operation;
use prost::Message;

fn fixed_device(id_byte: u8) -> [u8; 32] {
    [id_byte; 32]
}

#[tokio::test]
async fn bilateral_reject_session_emits_event_and_updates_phase() {
    // A device made as wallet creation makes one: its own identity, AK and
    // Kyber key, in a fresh database. Its prepare carries its Kyber identity
    // binding, so it needs them.
    let (identity, _core) = dsm_sdk::economic_fixtures::local_device(0x11);
    let local_device = identity.device_id;
    let remote_device = fixed_device(0x22);
    let remote_genesis = fixed_device(0x33);

    // The relationship's tips live on the persisted contact, as a contact
    // added through the wallet is.
    sdk::storage::client_db::store_contact(&sdk::storage::client_db::ContactRecord {
        contact_id: "peer".to_string(),
        device_id: remote_device.to_vec(),
        alias: "peer".to_string(),
        genesis_hash: remote_genesis.to_vec(),
        public_key: vec![0; 32],
        kyber_public_key: vec![0x4B; 1184],
        current_chain_tip: Some(vec![0x70; 32]),
        verified: true,
        verification_proof: None,
        metadata: std::collections::HashMap::new(),
        ble_address: None,
        status: "Created".to_string(),
        needs_online_reconcile: false,
        previous_chain_tip: None,
    })
    .unwrap();

    // Build bilateral transaction manager with verified contact & relationship
    let keypair = identity.signing_keypair();
    let mut contact_manager = dsm::core::contact_manager::DsmContactManager::new(local_device);

    let contact = dsm::types::contact_types::DsmVerifiedContact {
        alias: "peer".to_string(),
        device_id: remote_device,
        genesis_hash: remote_genesis,
        public_key: vec![0; 32],
        chain_tip: Some([0x70; 32]),
        genesis_verified_online: true,
        verifying_storage_nodes: vec![],
        ble_address: None,
    };
    contact_manager.add_verified_contact(contact).unwrap();

    let mut manager = BilateralTransactionManager::new(
        contact_manager,
        keypair,
        local_device,
        identity.genesis,
        std::sync::Arc::new(dsm_sdk::sdk::chain_tip_store::SqliteChainTipStore::new()),
    );
    manager
        .establish_relationship(&remote_device)
        .await
        .unwrap();
    let manager = Arc::new(RwLock::new(manager));

    let mut handler = BilateralBleHandler::new(manager.clone(), local_device);

    // Capture emitted events
    let received_events: Arc<RwLock<Vec<Vec<u8>>>> = Arc::new(RwLock::new(vec![]));
    let rx_clone = received_events.clone();
    handler.set_event_callback(Arc::new(move |bytes: &[u8]| {
        let mut w = futures::executor::block_on(rx_clone.write());
        w.push(bytes.to_vec());
    }));

    // Create a prepared session via normal prepare path (acts as sender side)
    let (_envelope_bytes, commitment_hash) = {
        let h = &handler; // borrow
        h.prepare_bilateral_transaction(remote_device, Operation::Noop)
            .await
            .unwrap()
    };

    // The proposer's user ends its proposal before any confirm: a signed
    // cancellation, kept as the step's answer.
    let cancellation = handler
        .cancel_proposal(commitment_hash, "user rejected".to_string())
        .await
        .unwrap();
    assert!(!cancellation.is_empty(), "the cancellation is its envelope");

    // Assert session phase updated
    {
        let phase = handler
            .get_session_phase(&commitment_hash)
            .await
            .expect("phase present");
        assert_eq!(
            phase,
            BilateralPhase::Rejected,
            "session phase should be Rejected"
        );
    }

    // Assert event emitted & decodable
    {
        let evs = received_events.read().await;
        assert!(!evs.is_empty(), "should have emitted at least one event");
        let last = evs.last().unwrap();
        if let Ok(note) =
            sdk::generated::BilateralEventNotification::decode(&mut std::io::Cursor::new(&last[..]))
        {
            assert_eq!(
                note.event_type,
                sdk::generated::BilateralEventType::BilateralEventRejected as i32
            );
            assert_eq!(note.status, "cancelled");
            assert_eq!(note.message, "user rejected");
        } else {
            panic!("Failed to decode BilateralEventNotification");
        }
    }
}
