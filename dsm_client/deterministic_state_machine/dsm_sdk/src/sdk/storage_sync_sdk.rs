// SPDX-License-Identifier: MIT OR Apache-2.0
//! DSM Storage Sync SDK (proto-only, no JSON, no alternate paths)
//!
//! - Envelope v3 only
//! - Protobuf bytes over HTTPS (reqwest + rustls)
//! - No serde/JSON, no wall clocks
//! - Thin client: v2 submit (inbox), v2 retrieve/ack (b0x)

use anyhow::{anyhow, Context, Result};
use prost::Message;
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE},
    Client,
};

use dsm::types::proto::{BatchEnvelope, Envelope};

const CT_PROTO: &str = "application/octet-stream";
const MAX_ENVELOPE_BYTES: usize = 128 * 1024;

#[derive(Clone, Debug)]
pub struct StorageSyncSdk {
    base_url: String,      // e.g., "https://node.local:8080"
    device_id_str: String, // canonical device-id string for Authorization
    auth_token: String,    // deterministic token
    http: Client,
}

#[cfg(test)]
mod storage_sync_sdk_tests {
    use super::*;

    #[test]
    fn storage_sync_sdk_new_rejects_dotted_device_id() {
        let res = StorageSyncSdk::new("http://127.0.0.1:8080", "1.2.3.4", "tok");
        assert!(res.is_err());
    }
}

// --- Minimal display structs exported for UI/data plumbing.
// They are plain data carriers (no JSON).
#[derive(Debug, Clone)]
pub struct WalletDisplayData {
    pub device_id: String,
    pub genesis_id: Option<String>,
    pub balance: u64,
    pub chain_height: u64,
    pub status: String,
    pub recent_transactions: Vec<TransactionDisplay>,
    pub contacts: Vec<ContactDisplay>,
    pub last_sync: u64,
}

#[derive(Debug, Clone)]
pub struct TransactionDisplay {
    pub tx_id: String,
    pub tx_hash: String,
    pub amount: u64,
    pub tx_type: String,
    pub status: String,
    pub tick: u64,
    pub counterparty: String,
}

#[derive(Debug, Clone)]
pub struct ContactDisplay {
    pub contact_id: String,
    pub alias: String,
    pub genesis_hash: String,
    pub added_at: u64,
    pub verified: bool,
}

impl StorageSyncSdk {
    /// Build the SDK (HTTP/2-capable, rustls via reqwest default features).
    pub fn new(
        base_url: impl Into<String>,
        device_id_str: impl Into<String>,
        auth_token: impl Into<String>,
    ) -> Result<Self> {
        let device_id_str = device_id_str.into();
        // Safety: storage-node protocol uses base32(32 bytes) for device_id in Authorization.
        // Refuse any non-canonical format.
        let decoded = crate::util::text_id::decode_base32_crockford(&device_id_str)
            .ok_or_else(|| anyhow!("StorageSyncSdk::new: device_id must be base32"))?;
        if decoded.len() != 32 {
            return Err(anyhow!(
                "StorageSyncSdk::new: device_id base32 decoded to {} bytes (expected 32)",
                decoded.len()
            ));
        }
        // No wall-clock timeouts: adhere to DSM "No Clock" invariant.
        // Network operations must not rely on real-time durations; callers can implement
        // deterministic work-unit budgets or cancellation via drop.
        let http = Client::builder().build().context("build reqwest client")?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            device_id_str,
            auth_token: auth_token.into(),
            http,
        })
    }

    /// Submit an Envelope (v3) to the authenticated v2 inbox.
    /// Server is protobuf-only; we send raw prost bytes with Authorization.
    pub async fn submit_inbox_v2(&self, env: &Envelope) -> Result<()> {
        // Encode protobuf
        let mut body = Vec::with_capacity(env.encoded_len());
        env.encode(&mut body).context("encode Envelope")?;
        if body.is_empty() || body.len() > MAX_ENVELOPE_BYTES {
            return Err(anyhow!("Envelope size invalid: {} bytes", body.len()));
        }

        // Local hygiene to match server expectations
        if env.version != 3 {
            return Err(anyhow!("Envelope.version must be 3"));
        }
        if env.message_id.len() != 16 {
            return Err(anyhow!("Envelope.message_id must be exactly 16 bytes"));
        }

        let url = format!("{}/api/v2/b0x/submit", self.base_url);

        // Headers
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static(CT_PROTO));
        // Auth header per the storage-node auth layer: "DSM <device_id>:<token>"
        let authz = format!("DSM {}:{}", self.device_id_str, &self.auth_token);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&authz).context("auth header")?,
        );

        // Replay guard header required by storage-node middleware
        // Canonical: base32 Crockford (0-9,A-H,J-K,M-N,P-T,V-Z with substitutions)
        let msg_id_hex = crate::util::text_id::encode_base32_crockford(&env.message_id);
        headers.insert(
            HeaderName::from_static("x-dsm-message-id"),
            HeaderValue::from_str(&msg_id_hex).context("x-dsm-message-id header")?,
        );

        // Provide recipient routing key: base32 device_id from envelope headers.
        if let Some(h) = env.headers.as_ref() {
            if h.device_id.len() == 32 {
                let recipient_b32 = crate::util::text_id::encode_base32_crockford(&h.device_id);
                headers.insert(
                    HeaderName::from_static("x-dsm-recipient"),
                    HeaderValue::from_str(&recipient_b32).context("x-dsm-recipient header")?,
                );
            }
        }

        let resp = self
            .http
            .post(url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .context("submit inbox request")?;

        if !resp.status().is_success() {
            return Err(anyhow!("inbox submit failed: {}", resp.status()));
        }
        Ok(())
    }

    /// Retrieve a batch (BatchEnvelope) from the v2 b0x spool for a given routing key.
    ///
    /// `b0x_id` must be canonical Base32 Crockford encoding of a 32-byte
    /// domain-separated routing digest.
    pub async fn retrieve_b0x_v2(&self, b0x_id: &str) -> Result<BatchEnvelope> {
        let url = format!("{}/api/v2/b0x/retrieve", self.base_url);
        let authz = format!("DSM {}:{}", self.device_id_str, &self.auth_token);
        let mut req = self.http.get(url).header(CONTENT_TYPE, CT_PROTO).header(
            AUTHORIZATION,
            HeaderValue::from_str(&authz).context("auth header")?,
        );
        if !b0x_id.is_empty() {
            req = req.header(
                HeaderName::from_static("x-dsm-b0x-address"),
                HeaderValue::from_str(b0x_id).context("x-dsm-b0x-address header")?,
            );
        }
        let resp = req.send().await.context("retrieve request")?;

        if !resp.status().is_success() {
            return Err(anyhow!("retrieve failed: {}", resp.status()));
        }

        let bytes = resp.bytes().await.context("read body")?;
        BatchEnvelope::decode(bytes.as_ref()).context("decode BatchEnvelope")
    }

    /// Acknowledge a set of envelopes under a given b0x key.
    /// Pass back a BatchEnvelope where each Envelope has `message_id` set.
    pub async fn ack_b0x_v2(&self, b0x_id: &str, batch: &BatchEnvelope) -> Result<()> {
        let mut body = Vec::with_capacity(batch.encoded_len());
        batch
            .encode(&mut body)
            .context("encode BatchEnvelope for ack")?;

        let url = format!("{}/api/v2/b0x/ack", self.base_url);
        let authz = format!("DSM {}:{}", self.device_id_str, &self.auth_token);
        let mut req = self
            .http
            .post(url)
            .header(CONTENT_TYPE, CT_PROTO)
            .header(
                AUTHORIZATION,
                HeaderValue::from_str(&authz).context("auth header")?,
            )
            .body(body);
        if !b0x_id.is_empty() {
            req = req.header(
                HeaderName::from_static("x-dsm-b0x-address"),
                HeaderValue::from_str(b0x_id).context("x-dsm-b0x-address header")?,
            );
        }
        let resp = req.send().await.context("ack request")?;

        if !resp.status().is_success() {
            return Err(anyhow!("ack failed: {}", resp.status()));
        }
        Ok(())
    }

    /// Put a raw object into the storage node.
    /// Used for genesis publishing and other raw object storage.
    pub async fn put_object(
        &self,
        dlv_id: &str,
        path: &str,
        body: Vec<u8>,
        capacity: Option<i64>,
        stake_hash: Option<&str>,
    ) -> Result<()> {
        let url = format!("{}/api/v2/object/put", self.base_url);
        let authz = format!("DSM {}:{}", self.device_id_str, &self.auth_token);

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static(CT_PROTO));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&authz).context("auth header")?,
        );
        headers.insert(
            HeaderName::from_static("x-dlv-id"),
            HeaderValue::from_str(dlv_id).context("x-dlv-id header")?,
        );
        headers.insert(
            HeaderName::from_static("x-path"),
            HeaderValue::from_str(path).context("x-path header")?,
        );

        if let Some(cap) = capacity {
            headers.insert(
                HeaderName::from_static("x-capacity-bytes"),
                HeaderValue::from_str(&cap.to_string()).context("x-capacity-bytes header")?,
            );
        }
        if let Some(stake) = stake_hash {
            headers.insert(
                HeaderName::from_static("x-stake-hash"),
                HeaderValue::from_str(stake).context("x-stake-hash header")?,
            );
        }

        let resp = self
            .http
            .post(url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .context("put object request")?;

        if !resp.status().is_success() {
            return Err(anyhow!("put object failed: {}", resp.status()));
        }
        Ok(())
    }

    /// Compose the preferred rotated routing key from an Envelope's headers.
    pub fn b0x_id_v2_from_envelope(env: &Envelope) -> Result<String> {
        let headers = env
            .headers
            .as_ref()
            .ok_or_else(|| anyhow!("missing headers"))?;
        if headers.genesis_hash.len() != 32
            || headers.device_id.len() != 32
            || headers.chain_tip.len() != 32
        {
            return Err(anyhow!(
                "genesis_hash, device_id, and chain_tip must all be 32 bytes"
            ));
        }
        crate::sdk::b0x_sdk::B0xSDK::compute_b0x_address(
            &headers.genesis_hash,
            &headers.device_id,
            &headers.chain_tip,
        )
        .map_err(|e| anyhow!("compute rotated b0x routing key: {e}"))
    }
}
