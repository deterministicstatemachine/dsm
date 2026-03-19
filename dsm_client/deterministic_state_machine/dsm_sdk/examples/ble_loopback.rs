//! Run with: cargo run -p dsm_sdk --example ble_loopback
//! Simulates a complete offline bilateral prepare/commit roundtrip entirely in-process.

#![allow(clippy::disallowed_methods)]

use std::sync::Arc;
use tokio::sync::RwLock;

use dsm_sdk::bluetooth::bilateral_ble_handler::BilateralBleHandler;
use dsm_sdk::bluetooth::ble_frame_coordinator::{BleFrameCoordinator, BleFrameType};
use dsm_sdk::bluetooth::android_ble_bridge::AndroidBleBridge;

use dsm::core::bilateral_transaction_manager::BilateralTransactionManager;
use dsm::core::contact_manager::DsmContactManager;
use dsm::crypto::SignatureKeyPair;
use dsm::types::identifiers::NodeId;
use dsm::types::operations::Operation;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("BLE Loopback: Starting...");
    // Minimal identity/context for two peers A and B (single-process simulation)
    let dev_a = [0xAA; 32];
    let dev_b = [0xBB; 32];

    let cm_a = DsmContactManager::new(dev_a, vec![NodeId::new("n1")]);
    let cm_b = DsmContactManager::new(dev_b, vec![NodeId::new("n1")]);

    let kp_a = SignatureKeyPair::generate_from_entropy(b"ble-loopback-a").expect("kp a");
    let kp_b = SignatureKeyPair::generate_from_entropy(b"ble-loopback-b").expect("kp b");

    let mgr_a = Arc::new(RwLock::new(BilateralTransactionManager::new(
        cm_a, kp_a, dev_a, dev_a,
    )));
    let mgr_b = Arc::new(RwLock::new(BilateralTransactionManager::new(
        cm_b, kp_b, dev_b, dev_b,
    )));

    let handler_a = Arc::new(BilateralBleHandler::new(mgr_a.clone(), dev_a));
    let handler_b = Arc::new(BilateralBleHandler::new(mgr_b.clone(), dev_b));

    let coord_a = Arc::new(BleFrameCoordinator::new(handler_a.clone(), dev_a));
    let coord_b = Arc::new(BleFrameCoordinator::new(handler_b.clone(), dev_b));

    // Keep bridge instances alive for the duration of the in-process simulation.
    // The variables are intentionally kept (prefixed with "_") so they are not
    // optimized away or trigger unused-variable lints while still making it
    // obvious they are part of the simulated environment.
    let _bridge_a = AndroidBleBridge::new(coord_a.clone(), handler_a.clone(), dev_a);
    let _bridge_b = AndroidBleBridge::new(coord_b.clone(), handler_b.clone(), dev_b);

    println!("BLE Loopback: Creating prepare message from A to B...");
    // A prepares a transfer to B (Noop op for simplicity)
    let op = Operation::Noop;
    let chunks = coord_a
        .create_prepare_message(dev_b, op, /*validity_iterations*/ 100)
        .await?;
    println!(
        "BLE Loopback: Prepare message created, {} chunks",
        chunks.len()
    );

    println!("BLE Loopback: Feeding chunks to B...");
    // Simulate BLE chunk transfer: feed all chunks to B's coordinator and capture completion
    let mut maybe_response = None;
    for ch in &chunks {
        let got = coord_b.handle_ble_chunk(ch).await?;
        if got.is_some() {
            maybe_response = got;
        }
    }
    println!("BLE Loopback: B processed prepare message");

    // The response from handle_ble_chunk is the prepare response to send back to A
    if let Some(response_result) = maybe_response {
        if let Some(resp_bytes) = response_result.response {
            // Send response back to A (simulate BLE chunks)
            let resp_chunks = coord_b
                .send_bilateral_message(dev_a, BleFrameType::BilateralPrepareResponse, resp_bytes)
                .await?;
            // Feed response chunks back to A and process the prepare response
            for ch in &resp_chunks {
                let _ = coord_a.handle_ble_chunk(ch).await?;
                // The prepare response is processed here
            }
        }
    }

    // A now commits: fetch pending commitment, create commit request, send to B, handle response
    let commitment_hash_opt = {
        let mgr = mgr_a.read().await;
        let pending = mgr.list_pending_commitments();
        pending.first().copied()
    };

    let commitment_hash = commitment_hash_opt.ok_or_else(|| {
        std::io::Error::other("no pending commitment found after prepare response")
    })?;

    // Produce confirm envelope on A (3-step protocol step 3) and fragment into BLE chunks
    let (confirm_payload, _meta) = handler_a.send_bilateral_confirm(commitment_hash).await?;
    let confirm_chunks = coord_a
        .send_bilateral_message(dev_b, BleFrameType::BilateralConfirm, confirm_payload)
        .await?;

    // B reassembles confirm request and processes it — no response needed
    for ch in &confirm_chunks {
        let _ = coord_b.handle_ble_chunk(ch).await?;
    }

    println!("Loopback bilateral prepare/confirm simulation finished successfully.");
    Ok(())
}
