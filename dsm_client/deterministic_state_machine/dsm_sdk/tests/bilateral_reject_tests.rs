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
    // Setup local + counterparty identities
    let local_device = fixed_device(0x11);
    let remote_device = fixed_device(0x22);
    let genesis_hash = fixed_device(0x33);

    // Build bilateral transaction manager with verified contact & relationship
    let keypair =
        dsm::crypto::signatures::SignatureKeyPair::generate_from_entropy(&[0xAA; 32]).unwrap();
    let mut contact_manager = dsm::core::contact_manager::DsmContactManager::new(
        local_device,
        vec![dsm::types::identifiers::NodeId::new("local")],
    );

    let contact = dsm::types::contact_types::DsmVerifiedContact {
        alias: "peer".to_string(),
        device_id: remote_device,
        genesis_hash,
        public_key: vec![0; 32],
        genesis_material: vec![0; 32],
        chain_tip: None,
        chain_tip_smt_proof: None,
        genesis_verified_online: true,
        verified_at_commit_height: 1,
        added_at_commit_height: 1,
        last_updated_commit_height: 1,
        verifying_storage_nodes: vec![],
        ble_address: None,
    };
    contact_manager.add_verified_contact(contact).unwrap();

    let mut manager =
        BilateralTransactionManager::new(contact_manager, keypair, local_device, genesis_hash);
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
        h.prepare_bilateral_transaction(remote_device, Operation::Noop, 100)
            .await
            .unwrap()
    };

    // Reject the session (simulating user cancellation)
    handler
        .reject_incoming_prepare(
            commitment_hash,
            remote_device,
            Some("user rejected".to_string()),
        )
        .await
        .unwrap();

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
            assert_eq!(note.status, "rejected");
            assert_eq!(note.message, "user rejected");
        } else {
            panic!("Failed to decode BilateralEventNotification");
        }
    }
}
