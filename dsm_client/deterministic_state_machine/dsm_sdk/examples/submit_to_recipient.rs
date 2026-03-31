// Minimal online submit smoke: register a test device, submit Envelope v3 to a recipient
// Usage: cargo run -p dsm_sdk --example submit_to_recipient -- <recipient_b32>
// If no recipient provided, defaults to a known active device id from recent spool snapshots.

#![allow(clippy::disallowed_methods)]

use prost::Message;
use rand_core06::{OsRng, RngCore};
use reqwest::Client;

fn base32_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    if bytes.is_empty() {
        return String::new();
    }
    let mut result = String::new();
    let mut buffer: u32 = 0;
    let mut bits_left: u32 = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | byte as u32;
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            let index = ((buffer >> bits_left) & 0x1F) as usize;
            result.push(ALPHABET[index] as char);
        }
    }
    if bits_left > 0 {
        let index = ((buffer << (5 - bits_left)) & 0x1F) as usize;
        result.push(ALPHABET[index] as char);
    }
    result
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let recipient_b32 = if args.len() > 1 {
        args[1].clone()
    } else {
        // Known active device from recent DB snapshot (acked entries observed)
        "T4IK43LWNESKAM7DEZK6TYUIO6AOVSGSK4KLJSU2B4X4JJMFSGOQ".to_string()
    };

    let endpoint =
        std::env::var("DSM_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    let http = Client::new();
    let mut os_rng = OsRng;

    // Register a fresh test device (sender)
    let mut device_id_raw = [0u8; 32];
    os_rng.fill_bytes(&mut device_id_raw);
    let device_id_b32 = base32_encode(&device_id_raw);
    let mut pubkey_raw = [0u8; 32];
    os_rng.fill_bytes(&mut pubkey_raw);
    let mut genesis_raw = [0u8; 32];
    os_rng.fill_bytes(&mut genesis_raw);

    let reg_req = dsm_sdk::generated::RegisterDeviceRequest {
        device_id: device_id_raw.to_vec(),
        pubkey: pubkey_raw.to_vec(),
        genesis_hash: genesis_raw.to_vec(),
    };
    let reg_body = reg_req.encode_to_vec();
    let reg_url = format!("{}/api/v2/device/register", endpoint);
    let reg_resp = http
        .post(&reg_url)
        .header("content-type", "application/protobuf")
        .header("accept", "application/protobuf")
        .body(reg_body)
        .send()
        .await?;
    assert!(
        reg_resp.status().is_success(),
        "registration failed: {}",
        reg_resp.status()
    );
    let bytes = reg_resp.bytes().await?;
    let reg = dsm_sdk::generated::RegisterDeviceResponse::decode(bytes.as_ref())?;
    let token = String::from_utf8_lossy(&reg.token).to_string();
    println!(
        "Sender registered: device_id={} token_len={}",
        device_id_b32,
        token.len()
    );

    // Build a minimal Envelope v3 (payload-free) for spool routing; the app should accept/ack only if valid
    let mut msg_id = [0u8; 16];
    os_rng.fill_bytes(&mut msg_id);
    let env = dsm_sdk::generated::Envelope {
        version: 3,
        headers: Some(dsm_sdk::generated::Headers {
            device_id: vec![0u8; 32],
            chain_tip: vec![0u8; 32],
            genesis_hash: vec![0u8; 32],
            seq: 0,
        }),
        message_id: msg_id.to_vec(),
        payload: None,
    };
    let body = env.encode_to_vec();
    let authz = format!("DSM {}:{}", device_id_b32, token);
    let submit_url = format!("{}/api/v2/b0x/submit", endpoint);
    let submit_resp = http
        .post(&submit_url)
        .header("content-type", "application/protobuf")
        .header("accept", "application/protobuf")
        .header("authorization", authz)
        .header("x-dsm-recipient", recipient_b32.clone())
        .header(
            "x-dsm-message-id",
            dsm_sdk::util::text_id::encode_base32_crockford(&msg_id),
        )
        .body(body)
        .send()
        .await?;
    assert!(
        submit_resp.status().is_success(),
        "submit failed: {}",
        submit_resp.status()
    );
    let msg_b32 = base32_encode(&msg_id);
    println!(
        "✅ Submitted to recipient {} msg_id={}",
        &recipient_b32[..8.min(recipient_b32.len())],
        &msg_b32
    );
    println!("MSGB32={}", &msg_b32);

    Ok(())
}
