// Ignored live E2E test: device registration (protobuf) + b0x submit
// Enable with: DSM_RUN_LIVE=1 cargo test -p dsm_sdk -- --ignored

#![allow(clippy::disallowed_methods)]

use prost::Message;
use rand::{rngs::OsRng, RngCore};
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

#[tokio::test]
#[ignore]
async fn live_registration_and_submit() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("DSM_RUN_LIVE").ok().as_deref() != Some("1") {
        eprintln!("Skipping live test (set DSM_RUN_LIVE=1 to enable)");
        return Ok(());
    }

    // Storage node endpoint (local dev default)
    let endpoint = "http://127.0.0.1:8080";

    // Prepare deterministic base32 identifiers (dummy 32-byte values)
    // These satisfy the storage node input validators
    let device_id_b32 = "850M2GA1850M2GA1850M2GA1850M2GA1850M2GA1850M2GA1850G".to_string();
    let pubkey_b32 = "89144GJ289144GJ289144GJ289144GJ289144GJ289144GJ28910".to_string();
    let genesis_b32 = "8D1M6GT38D1M6GT38D1M6GT38D1M6GT38D1M6GT38D1M6GT38D1G".to_string();

    // Raw bytes for proto fields (decode deterministic base32 or use dummy 32-byte values)
    let device_id_bytes = dsm_sdk::util::text_id::decode_base32_crockford(&device_id_b32)
        .unwrap_or_else(|| vec![0x85; 32]);
    let pubkey_bytes = dsm_sdk::util::text_id::decode_base32_crockford(&pubkey_b32)
        .unwrap_or_else(|| vec![0x89; 32]);
    let genesis_bytes = dsm_sdk::util::text_id::decode_base32_crockford(&genesis_b32)
        .unwrap_or_else(|| vec![0x8D; 32]);

    // 1) Register device using protobuf body
    let url = format!("{}/api/v2/device/register", endpoint);
    let http = Client::new();
    let mut os_rng = OsRng;
    // Try initial registration
    #[allow(unused_assignments)]
    let mut token_opt: Option<String> = None;
    let mut device_id_b32 = device_id_b32;
    let mut genesis_b32 = genesis_b32;
    let mut device_id_bytes = device_id_bytes;
    let mut genesis_bytes = genesis_bytes;
    {
        let req = dsm_sdk::generated::RegisterDeviceRequest {
            device_id: device_id_bytes.clone(),
            pubkey: pubkey_bytes.clone(),
            genesis_hash: genesis_bytes.clone(),
        };
        let body = req.encode_to_vec();
        let resp = http
            .post(&url)
            .header("content-type", "application/protobuf")
            .header("accept", "application/protobuf")
            .body(body)
            .send()
            .await?;
        if resp.status().is_success() {
            let bytes = resp.bytes().await?;
            let reg = dsm_sdk::generated::RegisterDeviceResponse::decode(bytes.as_ref())?;
            token_opt = Some(String::from_utf8_lossy(&reg.token).to_string());
        } else if resp.status().as_u16() == 409 {
            // Already exists: always create a fresh identity so token/device_id pair matches
            let mut rand32 = [0u8; 32];
            os_rng.fill_bytes(&mut rand32);
            device_id_bytes = rand32.to_vec();
            device_id_b32 = base32_encode(&rand32);
            os_rng.fill_bytes(&mut rand32);
            let pubkey_bytes_new = rand32.to_vec();
            os_rng.fill_bytes(&mut rand32);
            genesis_bytes = rand32.to_vec();
            genesis_b32 = base32_encode(&rand32);
            let req2 = dsm_sdk::generated::RegisterDeviceRequest {
                device_id: device_id_bytes.clone(),
                pubkey: pubkey_bytes_new,
                genesis_hash: genesis_bytes.clone(),
            };
            let body2 = req2.encode_to_vec();
            let resp2 = http
                .post(&url)
                .header("content-type", "application/protobuf")
                .header("accept", "application/protobuf")
                .body(body2)
                .send()
                .await?;
            if resp2.status().is_success() {
                let bytes = resp2.bytes().await?;
                let reg2 = dsm_sdk::generated::RegisterDeviceResponse::decode(bytes.as_ref())?;
                token_opt = Some(String::from_utf8_lossy(&reg2.token).to_string());
            } else {
                panic!("second registration failed: {}", resp2.status());
            }
        } else {
            panic!("registration failed: {}", resp.status());
        }
    }
    let token = if let Some(t) = token_opt {
        t
    } else {
        // Fallback: use stored token if present
        dsm_sdk::storage::client_db::get_auth_token(endpoint, &device_id_b32, &genesis_b32)?
            .expect("No token available after registration attempts")
    };
    eprintln!(
        "Using device_id={} token_len={}",
        device_id_b32,
        token.len()
    );

    // 2) Persist token so B0xSDK can authenticate
    dsm_sdk::storage::client_db::init_database()?;
    dsm_sdk::storage::client_db::store_auth_token(endpoint, &device_id_b32, &genesis_b32, &token)?;

    // 3) Submit a minimal Envelope v3 directly to b0x spool
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
    let resp = http
        .post(format!("{}/api/v2/b0x/submit", endpoint))
        .header("content-type", "application/protobuf")
        .header("accept", "application/protobuf")
        .header("authorization", authz)
        .header("x-dsm-recipient", device_id_b32.clone())
        .header(
            "x-dsm-message-id",
            dsm_sdk::util::text_id::encode_base32_crockford(&msg_id),
        )
        .body(body)
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    assert!(status.is_success(), "submit failed: {} {}", status, text);
    eprintln!("✅ Submit succeeded");

    // 4) Retrieve from b0x spool
    let retrieve_url = format!("{}/api/v2/b0x/retrieve", endpoint);
    let mut retrieve_msg_id = [0u8; 16];
    os_rng.fill_bytes(&mut retrieve_msg_id);
    let retrieve_resp = http
        .get(&retrieve_url)
        .header("content-type", "application/protobuf")
        .header("accept", "application/protobuf")
        .header("authorization", format!("DSM {}:{}", device_id_b32, token))
        .header(
            "x-dsm-message-id",
            dsm_sdk::util::text_id::encode_base32_crockford(&retrieve_msg_id),
        )
        .send()
        .await?;

    let retrieve_status = retrieve_resp.status();
    if retrieve_status == reqwest::StatusCode::NO_CONTENT {
        eprintln!("✅ Retrieve: no content (spool empty)");
        return Ok(());
    }
    assert!(
        retrieve_status.is_success(),
        "retrieve failed: {}",
        retrieve_status
    );
    let retrieve_body = retrieve_resp.bytes().await?;
    let batch = dsm_sdk::generated::BatchEnvelope::decode(&retrieve_body[..])?;
    eprintln!("✅ Retrieved {} envelopes", batch.envelopes.len());
    assert!(
        !batch.envelopes.is_empty(),
        "expected at least one envelope in retrieve"
    );

    // 5) Acknowledge (ack) the retrieved envelopes
    // The ack endpoint expects a BatchEnvelope with envelopes containing at least message_id
    let ack_envelopes = batch
        .envelopes
        .iter()
        .map(|e| dsm_sdk::generated::Envelope {
            version: 3,
            headers: None,
            message_id: e.message_id.clone(),
            payload: None,
        })
        .collect();
    let ack_batch = dsm_sdk::generated::BatchEnvelope {
        envelopes: ack_envelopes,
        batch_signature: vec![],
        atomic_execution: false,
    };
    let ack_body = ack_batch.encode_to_vec();
    let mut ack_msg_id = [0u8; 16];
    os_rng.fill_bytes(&mut ack_msg_id);
    let ack_resp = http
        .post(format!("{}/api/v2/b0x/ack", endpoint))
        .header("content-type", "application/protobuf")
        .header("accept", "application/protobuf")
        .header("authorization", format!("DSM {}:{}", device_id_b32, token))
        .header(
            "x-dsm-message-id",
            dsm_sdk::util::text_id::encode_base32_crockford(&ack_msg_id),
        )
        .body(ack_body)
        .send()
        .await?;

    assert!(
        ack_resp.status().is_success(),
        "ack failed: {}",
        ack_resp.status()
    );
    eprintln!("✅ Ack succeeded");

    Ok(())
}
