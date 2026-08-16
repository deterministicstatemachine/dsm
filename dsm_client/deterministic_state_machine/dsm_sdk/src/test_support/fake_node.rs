// SPDX-License-Identifier: MIT OR Apache-2.0
//! A loopback storage node for the bilateral protocol tests.
//!
//! The real node is a dumb mirror: it spools envelopes under a route and a
//! message id, serves the un-ACKed ones back on retrieve, retires them on ACK,
//! and answers "acked?" on status. That is ALL the protocol needs from it, and
//! it is exactly what this fake does — nothing is authenticated, parsed beyond
//! the envelope frame, or verified, so a test can only fail for a reason in
//! the code under test.
//!
//! Endpoints implemented (the exact contract `b0x_sdk` speaks):
//!
//! | route | behaviour |
//! |---|---|
//! | `POST /api/v2/device/register`, `/token` | store the `RegisterDeviceRequest`; answer a token |
//! | `GET  /api/v2/device/{b32}` | the stored registration, or 404 |
//! | `POST /api/v2/b0x/submit` | spool `(x-dsm-recipient, x-dsm-message-id, body)`; 204 |
//! | `GET  /api/v2/b0x/retrieve` | un-ACKed envelopes for `x-dsm-b0x-address` as `BatchEnvelope`; 204 if none |
//! | `POST /api/v2/b0x/ack` | retire the ids in the `BatchEnvelope` body; 204 |
//! | `GET  /api/v2/b0x/status/{id}` | 204 acked · 409 spooled · 404 unknown |
//!
//! Per-message-id status overrides let a test make ONE submission fail
//! (`503`) or answer a status probe differently, then lift the override — the
//! "recorder returns 204×K after a 503" shape the checkpoint sweep tests need.

use prost::Message;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// One recorded `POST` (the recorder role — every test that asserts "what
/// went on the wire" reads these).
#[derive(Debug, Clone)]
pub struct RecordedPost {
    pub endpoint: String,
    pub path: String,
    pub body: Vec<u8>,
    /// `x-dsm-recipient` — the route the caller submitted under.
    pub recipient: String,
    /// `x-dsm-message-id` — the deterministic id the caller submitted under.
    pub message_id: String,
}

#[derive(Debug, Clone)]
struct Spooled {
    route: String,
    message_id: String,
    body: Vec<u8>,
    acked: bool,
}

#[derive(Default)]
struct NodeState {
    posts: Vec<RecordedPost>,
    spool: Vec<Spooled>,
    /// `RegisterDeviceRequest` bytes by base32 device id.
    devices: HashMap<String, Vec<u8>>,
    /// Per-message-id HTTP status to answer on submit instead of 204.
    submit_overrides: HashMap<String, u16>,
    /// HTTP status to answer EVERY submit with (a node that is down for
    /// writes); per-id overrides take precedence.
    submit_override_all: Option<u16>,
    /// Message ids spooled but NOT served on retrieve until released — a
    /// message delayed in transit (e.g. a certificate the recipient has not
    /// seen yet while the next transfer already arrived).
    held: std::collections::HashSet<String>,
}

/// Handle to one running fake node.
#[derive(Clone)]
pub struct FakeB0xNode {
    pub endpoint: String,
    state: Arc<Mutex<NodeState>>,
}

impl FakeB0xNode {
    /// Bind a loopback listener and serve until the process exits.
    pub fn spawn() -> Self {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind fake node");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let state: Arc<Mutex<NodeState>> = Arc::default();
        let node = Self {
            endpoint: endpoint.clone(),
            state: state.clone(),
        };

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { break };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                let (mut head_end, mut content_len) = (None, 0usize);
                while head_end.is_none() {
                    match s.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                head_end = Some(p + 4);
                                let head = String::from_utf8_lossy(&buf[..p]).to_lowercase();
                                for line in head.lines() {
                                    if let Some(v) = line.strip_prefix("content-length:") {
                                        content_len = v.trim().parse().unwrap_or(0);
                                    }
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                let Some(hs) = head_end else { continue };
                while buf.len() < hs + content_len {
                    match s.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        Err(_) => break,
                    }
                }
                let head = String::from_utf8_lossy(&buf[..hs]).to_string();
                let body = buf[hs..].to_vec();
                let mut first = head.lines().next().unwrap_or("").split_whitespace();
                let method = first.next().unwrap_or("").to_uppercase();
                let path = first.next().unwrap_or("").to_string();
                let header = |name: &str| -> String {
                    head.lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.trim()
                                .eq_ignore_ascii_case(name)
                                .then(|| v.trim().to_string())
                        })
                        .unwrap_or_default()
                };

                let (status, resp_body) = {
                    let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
                    if method == "POST" {
                        st.posts.push(RecordedPost {
                            endpoint: endpoint.clone(),
                            path: path.clone(),
                            body: body.clone(),
                            recipient: header("x-dsm-recipient"),
                            message_id: header("x-dsm-message-id"),
                        });
                    }
                    Self::route(&mut st, &method, &path, &header, &body)
                };

                let reason = match status {
                    200 => "OK",
                    204 => "No Content",
                    404 => "Not Found",
                    409 => "Conflict",
                    413 => "Payload Too Large",
                    500 => "Internal Server Error",
                    503 => "Service Unavailable",
                    _ => "OK",
                };
                let mut resp = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/protobuf\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    resp_body.len()
                )
                .into_bytes();
                resp.extend_from_slice(&resp_body);
                let _ = s.write_all(&resp);
                let _ = s.flush();
            }
        });
        node
    }

    fn route(
        st: &mut NodeState,
        method: &str,
        path: &str,
        header: &dyn Fn(&str) -> String,
        body: &[u8],
    ) -> (u16, Vec<u8>) {
        match (method, path) {
            ("POST", "/api/v2/device/register") | ("POST", "/api/v2/device/token") => {
                if let Ok(req) = dsm::types::proto::RegisterDeviceRequest::decode(body) {
                    let id = crate::util::text_id::encode_base32_crockford(&req.device_id);
                    st.devices.insert(id, body.to_vec());
                }
                let token = dsm::types::proto::RegisterDeviceResponse {
                    token: vec![0x70u8; 32],
                };
                (200, token.encode_to_vec())
            }
            ("GET", p) if p.starts_with("/api/v2/device/") => {
                let id = p.trim_start_matches("/api/v2/device/");
                match st.devices.get(id) {
                    Some(bytes) => (200, bytes.clone()),
                    None => (404, Vec::new()),
                }
            }
            ("POST", "/api/v2/b0x/submit") => {
                let message_id = header("x-dsm-message-id");
                if let Some(code) = st
                    .submit_overrides
                    .get(&message_id)
                    .copied()
                    .or(st.submit_override_all)
                {
                    return (code, Vec::new());
                }
                let route = header("x-dsm-recipient");
                // Node dedup: the first bytes under an id win; a replay is a no-op.
                if !st.spool.iter().any(|e| e.message_id == message_id) {
                    st.spool.push(Spooled {
                        route,
                        message_id,
                        body: body.to_vec(),
                        acked: false,
                    });
                }
                (204, Vec::new())
            }
            ("GET", "/api/v2/b0x/retrieve") => {
                let route = header("x-dsm-b0x-address");
                let envelopes: Vec<dsm::types::proto::Envelope> = st
                    .spool
                    .iter()
                    .filter(|e| e.route == route && !e.acked && !st.held.contains(&e.message_id))
                    .filter_map(|e| dsm::types::proto::Envelope::decode(e.body.as_slice()).ok())
                    .collect();
                if envelopes.is_empty() {
                    (204, Vec::new())
                } else {
                    let batch = dsm::types::proto::BatchEnvelope {
                        envelopes,
                        ..Default::default()
                    };
                    (200, batch.encode_to_vec())
                }
            }
            ("POST", "/api/v2/b0x/ack") => {
                let route = header("x-dsm-b0x-address");
                if let Ok(batch) = dsm::types::proto::BatchEnvelope::decode(body) {
                    for env in batch.envelopes {
                        let id = crate::util::text_id::encode_base32_crockford(&env.message_id);
                        for e in st.spool.iter_mut() {
                            if e.message_id == id && e.route == route {
                                e.acked = true;
                            }
                        }
                    }
                }
                (204, Vec::new())
            }
            ("GET", p) if p.starts_with("/api/v2/b0x/status/") => {
                let id = p.trim_start_matches("/api/v2/b0x/status/");
                match st.spool.iter().find(|e| e.message_id == id) {
                    Some(e) if e.acked => (204, Vec::new()),
                    Some(_) => (409, Vec::new()),
                    None => (404, Vec::new()),
                }
            }
            _ => (204, Vec::new()),
        }
    }

    /// Every `POST` this node has received, in order.
    pub fn posts(&self) -> Vec<RecordedPost> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .posts
            .clone()
    }

    /// `POST /api/v2/b0x/submit` calls only.
    pub fn submits(&self) -> Vec<RecordedPost> {
        self.posts()
            .into_iter()
            .filter(|p| p.path == "/api/v2/b0x/submit")
            .collect()
    }

    /// Ids currently spooled (un-ACKed) under `route`.
    pub fn spooled_ids(&self, route: &str) -> Vec<String> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .spool
            .iter()
            .filter(|e| e.route == route && !e.acked)
            .map(|e| e.message_id.clone())
            .collect()
    }

    /// Whether `message_id` has been spooled here and ACKed by its recipient.
    pub fn is_acked(&self, message_id: &str) -> Option<bool> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .spool
            .iter()
            .find(|e| e.message_id == message_id)
            .map(|e| e.acked)
    }

    /// Answer `status` (instead of 204) to every submit under `message_id`
    /// until [`clear_submit_override`](Self::clear_submit_override).
    pub fn override_submit(&self, message_id: &str, status: u16) {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .submit_overrides
            .insert(message_id.to_string(), status);
    }

    /// Answer `status` to EVERY submit (None restores normal spooling).
    /// Per-id overrides still take precedence.
    pub fn override_all_submits(&self, status: Option<u16>) {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .submit_override_all = status;
    }

    /// Delay `message_id` in transit: spooled, but not served on retrieve
    /// until [`release_message`](Self::release_message).
    pub fn hold_message(&self, message_id: &str) {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .held
            .insert(message_id.to_string());
    }

    pub fn release_message(&self, message_id: &str) {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .held
            .remove(message_id);
    }

    pub fn clear_submit_override(&self, message_id: &str) {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .submit_overrides
            .remove(message_id);
    }
}

/// Point the runtime's storage-endpoint resolver at `endpoints`.
///
/// Both `wallet.send` and `storage.sync` resolve endpoints through
/// `StorageNodeConfig::from_env_config()`, NOT `SdkConfig`. Under
/// `DSM_SDK_TEST_MODE` that loader returns a hardcoded localhost set unless
/// `DSM_ENV_CONFIG_PATH` names a real file. One fixed path per process,
/// installed through the OnceLock the JNI layer uses in production (immune to
/// other test modules clearing the env var); the file is rewritten per call
/// and re-read by the loader on every use.
pub fn point_env_config_at(endpoints: &[String]) {
    let cfg_path =
        std::env::temp_dir().join(format!("dsm_sdk_test_env_{}.toml", std::process::id()));
    let mut cfg_toml = String::from(
        "protocol = \"http\"\nlan_ip = \"127.0.0.1\"\nallow_localhost = true\n\
         storage_node_mode = \"remote\"\nports = [8080]\n\
         bitcoin_network = \"signet\"\ndbtc_min_confirmations = 1\n",
    );
    for (i, ep) in endpoints.iter().enumerate() {
        cfg_toml.push_str(&format!(
            "\n[[nodes]]\nname = \"node-{i}\"\nendpoint = \"{ep}\"\n"
        ));
    }
    std::fs::write(&cfg_path, cfg_toml).expect("write env config");
    crate::network::set_env_config_path(cfg_path.to_string_lossy().into_owned());
    unsafe {
        std::env::set_var("DSM_ENV_CONFIG_PATH", &cfg_path);
    }
}
