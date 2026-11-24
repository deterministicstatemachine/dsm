// SPDX-License-Identifier: Apache-2.0
//! Apple's push endpoint as a node calls it, served by a test on a local port
//! over TLS and HTTP/2: `POST /3/device/{device}`, taking a connection only
//! with a provider certificate from the CA it trusts, as APNs takes one only
//! with the certificate Apple issued for the app. It checks what Apple
//! checks of a background push — HTTP/2, the push type, its priority, the
//! app's topic and the body that wakes the app — and keeps every push it
//! takes. The node reaches it through its own outbound client, configured
//! as an operator configures it ([`ApplePush::config`]), with the endpoint
//! and the CA pointed here.
//!
//! Shared by the node's tests and the SDK's (`#[path]`), beside
//! `google_push`, whose certificate helpers it uses.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Version};
use axum::response::IntoResponse;
use axum::routing::post;

use super::google_push::{held, issued, issuer, pem_certs};

/// The app's bundle id: the topic every push names.
pub const TOPIC: &str = "com.dsm.wallet";

/// One push Apple took: the device it went to (hex, as Apple's path names
/// it), its headers as sent, and its body.
#[derive(Clone, Debug)]
pub struct ApplePushed {
    pub device: String,
    pub push_type: String,
    pub priority: String,
    pub body: serde_json::Value,
}

/// What the endpoint has taken. A suite that makes Apple refuse a device
/// reaches it from `super`.
pub(super) struct Taken {
    /// Devices whose app is gone (`410`).
    pub(super) gone: Mutex<HashSet<String>>,
    pushes: Mutex<Vec<ApplePushed>>,
}

/// Apple's push endpoint, served until dropped.
pub struct ApplePush {
    pub endpoint: String,
    /// The CA the endpoint's certificate is from.
    pub ca_pem: Vec<u8>,
    /// The provider certificate and its key, from the CA the endpoint trusts.
    pub client_cert_pem: Vec<u8>,
    pub client_key_pem: Vec<u8>,
    pub(super) taken: Arc<Taken>,
    handle: axum_server::Handle<SocketAddr>,
}

impl Drop for ApplePush {
    fn drop(&mut self) {
        self.handle.shutdown();
    }
}

impl ApplePush {
    /// Serve the endpoint on a local port. Must run inside a Tokio runtime.
    pub async fn start() -> Self {
        use rustls::pki_types::pem::PemObject;

        let (server_ca, server_ca_pem) = issuer("Apple (test endpoint)");
        let (client_ca, client_ca_pem) = issuer("Apple provider CA (test)");
        let (server_pem, server_key_pem, _) =
            issued(&server_ca, vec!["127.0.0.1".to_string()], "127.0.0.1");
        let (client_pem, client_key_pem, _) = issued(
            &client_ca,
            Vec::new(),
            "Apple Push Services: com.dsm.wallet (test)",
        );

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut client_roots = rustls::RootCertStore::empty();
        for ca in pem_certs(&client_ca_pem) {
            if let Err(e) = client_roots.add(ca) {
                panic!("the provider CA: {e}");
            }
        }
        let verifier = match rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(client_roots),
            provider.clone(),
        )
        .build()
        {
            Ok(verifier) => verifier,
            Err(e) => panic!("the provider certificate verifier: {e}"),
        };
        let server_key =
            match rustls::pki_types::PrivateKeyDer::from_pem_slice(server_key_pem.as_bytes()) {
                Ok(key) => key,
                Err(e) => panic!("the endpoint's key: {e}"),
            };
        let mut tls = match rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
        {
            Ok(builder) => match builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(pem_certs(&server_pem), server_key)
            {
                Ok(tls) => tls,
                Err(e) => panic!("the endpoint's TLS: {e}"),
            },
            Err(e) => panic!("the endpoint's TLS versions: {e}"),
        };
        // APNs speaks HTTP/2 only.
        tls.alpn_protocols = vec![b"h2".to_vec()];

        let taken = Arc::new(Taken {
            gone: Mutex::new(HashSet::new()),
            pushes: Mutex::new(Vec::new()),
        });
        let app = axum::Router::new()
            .route("/3/device/{device}", post(device_push))
            .with_state(taken.clone());

        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(e) => panic!("bind the APNs endpoint: {e}"),
        };
        let address = match listener.local_addr() {
            Ok(address) => address,
            Err(e) => panic!("the APNs endpoint's address: {e}"),
        };
        let listener = match listener.into_std() {
            Ok(listener) => listener,
            Err(e) => panic!("the APNs endpoint's listener: {e}"),
        };
        let handle = axum_server::Handle::new();
        let config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls));
        let server = match axum_server::from_tcp_rustls(listener, config) {
            Ok(server) => server.handle(handle.clone()),
            Err(e) => panic!("the APNs endpoint's server: {e}"),
        };
        tokio::spawn(async move {
            if let Err(e) = server.serve(app.into_make_service()).await {
                panic!("serve the APNs endpoint: {e}");
            }
        });
        Self {
            endpoint: format!("https://{address}"),
            ca_pem: server_ca_pem.into_bytes(),
            client_cert_pem: client_pem.into_bytes(),
            client_key_pem: client_key_pem.into_bytes(),
            taken,
            handle,
        }
    }

    /// `[push.apns]` as an operator states it for a node pushing through
    /// this endpoint.
    pub fn config(&self) -> dsm_storage_node::push::ApnsConfig {
        dsm_storage_node::push::ApnsConfig {
            topic: TOPIC.to_string(),
            client_cert_pem: self.client_cert_pem.clone(),
            client_key_pem: self.client_key_pem.clone(),
            endpoint: self.endpoint.clone(),
            ca_cert_pem: Some(self.ca_pem.clone()),
        }
    }

    /// Every push Apple took, in the order it took them.
    pub fn pushes(&self) -> Vec<ApplePushed> {
        held(&self.taken.pushes).clone()
    }

    /// Wait until Apple has taken `count` pushes, at most `limit`; the pushes
    /// taken by then.
    pub async fn until_pushes(&self, count: usize, limit: std::time::Duration) -> Vec<ApplePushed> {
        let step = std::time::Duration::from_millis(20);
        let mut waited = std::time::Duration::ZERO;
        loop {
            let pushes = self.pushes();
            if pushes.len() >= count || waited >= limit {
                return pushes;
            }
            tokio::time::sleep(step).await;
            waited += step;
        }
    }
}

/// Apple's refusal: the reason it names.
#[derive(serde::Serialize)]
struct Refusal {
    reason: &'static str,
}

fn refused(status: StatusCode, reason: &'static str) -> axum::response::Response {
    let body = match serde_json::to_string(&Refusal { reason }) {
        Ok(body) => body,
        Err(e) => panic!("the APNs endpoint's refusal: {e}"),
    };
    (
        status,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    let value = headers.get(name)?;
    match value.to_str() {
        Ok(text) => Some(text.to_string()),
        Err(e) => panic!("the node sent a {name} header that is not text: {e}"),
    }
}

/// `POST /3/device/{device}`: one push, taken when it is a background push for
/// the app's topic over HTTP/2.
async fn device_push(
    State(taken): State<Arc<Taken>>,
    Path(device): Path<String>,
    version: Version,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> axum::response::Response {
    if version != Version::HTTP_2 {
        return refused(StatusCode::BAD_REQUEST, "BadProtocolVersion");
    }
    if device.is_empty()
        || !device
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return refused(StatusCode::BAD_REQUEST, "BadDeviceToken");
    }
    if header(&headers, "apns-topic").as_deref() != Some(TOPIC) {
        return refused(StatusCode::BAD_REQUEST, "TopicDisallowed");
    }
    let Some(push_type) = header(&headers, "apns-push-type") else {
        return refused(StatusCode::BAD_REQUEST, "InvalidPushType");
    };
    let Some(priority) = header(&headers, "apns-priority") else {
        return refused(StatusCode::BAD_REQUEST, "BadPriority");
    };
    let Ok(body) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return refused(StatusCode::BAD_REQUEST, "PayloadEmpty");
    };
    // A background push wakes the app only at priority 5 with
    // `content-available` set (Apple's rule for `background`).
    if push_type != "background" || priority != "5" || body["aps"]["content-available"] != 1 {
        return refused(StatusCode::BAD_REQUEST, "BadPriority");
    }
    if held(&taken.gone).contains(&device) {
        return refused(StatusCode::GONE, "Unregistered");
    }
    held(&taken.pushes).push(ApplePushed {
        device,
        push_type,
        priority,
        body,
    });
    StatusCode::OK.into_response()
}
