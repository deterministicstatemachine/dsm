// Acknowledge a specific b0x message for a given device id (base32)
#![allow(clippy::disallowed_methods)]

use std::env;

use std::sync::Arc;

use dsm_sdk::sdk::b0x_sdk::B0xSDK;
use dsm_sdk::sdk::core_sdk::CoreSDK;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: ack_for_device <device_id_base32> <message_id_base32>");
        std::process::exit(64);
    }
    let device_b32 = args[1].trim().to_string();
    let msg_id_b32 = args[2].trim().to_string();

    // Storage endpoints (local dev node set)
    let endpoints = vec![
        "http://127.0.0.1:8080".to_string(),
        "http://127.0.0.1:8081".to_string(),
        "http://127.0.0.1:8082".to_string(),
        "http://127.0.0.1:8083".to_string(),
        "http://127.0.0.1:8084".to_string(),
    ];

    // Ensure a storage base dir exists (SDK utilities expect it)
    let _ =
        dsm_sdk::storage_utils::set_storage_base_dir(std::path::PathBuf::from("./.dsm_ack_test"));

    let core = Arc::new(CoreSDK::new().expect("CoreSDK init"));
    core.initialize_with_genesis_state()
        .expect("init genesis state");

    let mut b0x = B0xSDK::new(device_b32.clone(), core.clone(), endpoints).expect("B0xSDK init");

    // Register the device on storage endpoints (idempotent; will fetch token if already registered)
    if let Err(e) = b0x.register_device().await {
        eprintln!("register_device failed: {:?}", e);
        std::process::exit(65);
    }

    // Acknowledge the provided message id across endpoints (quorum required by SDK)
    match b0x.acknowledge_b0x_v2("", vec![msg_id_b32.clone()]).await {
        Ok(()) => {
            println!("ACK_OK {} for device {}", msg_id_b32, device_b32);
        }
        Err(e) => {
            eprintln!("ACK_ERR {:?}", e);
            std::process::exit(66);
        }
    }
}
