// SPDX-License-Identifier: Apache-2.0
//! Google's three push endpoints as a node calls them, served by a test on a
//! local port over TLS: the token exchange (over mutual TLS, taking only a
//! client certificate from the CA it trusts), the service account's access
//! token, and Firebase's `messages:send`. Each checks what Google checks of
//! the node's request — the certificate chain in the subject token is the one
//! the connection presented, each bearer token is the one handed out — and
//! keeps every push it takes. The node reaches it through its own outbound
//! client, configured as an operator configures it ([`GooglePush::config`]),
//! with the endpoints and the CA pointed here.
//!
//! Shared by the node's tests and the SDK's (`#[path]`): it names nothing of
//! either crate but the node's [`dsm_storage_node::push::FcmConfig`].

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use base64::Engine;

/// The Firebase project the node's pushes go through.
pub const PROJECT: &str = "dsm-push-test";
/// The workload identity provider the node's certificate is trusted by.
pub const PROVIDER: &str = "//iam.googleapis.com/projects/1/locations/global/\
                            workloadIdentityPools/dsm-nodes/providers/dsm-nodes-x509";
/// The service account the node acts as.
pub const SERVICE_ACCOUNT: &str = "fcm-sender@dsm-push-test.iam.gserviceaccount.com";

/// One push Firebase took: the token it went to and the message as sent.
#[derive(Clone, Debug)]
pub struct Push {
    pub push_token: String,
    pub message: serde_json::Value,
}

/// What the endpoints have handed out and taken. A suite that makes Google
/// refuse something reaches it from `super`.
pub(super) struct Seen {
    /// The DER of the client certificate the node was issued.
    leaf: Vec<u8>,
    pub(super) exchanges: Mutex<u32>,
    federated: Mutex<Option<String>>,
    pub(super) access: Mutex<Option<String>>,
    /// Access tokens Firebase now refuses (`401`).
    pub(super) refused: Mutex<HashSet<String>>,
    /// Push tokens that are no app's (`404`).
    pub(super) gone: Mutex<HashSet<String>>,
    pushes: Mutex<Vec<Push>>,
}

pub(super) fn held<T>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
    match lock.lock() {
        Ok(held) => held,
        Err(e) => panic!("the push endpoints' state: {e}"),
    }
}

/// Google's push endpoints, served until dropped.
pub struct GooglePush {
    pub endpoint: String,
    /// The CA the endpoints' certificate is from.
    pub ca_pem: Vec<u8>,
    /// The node's client certificate and its key, from the CA the token
    /// exchange trusts.
    pub client_cert_pem: Vec<u8>,
    pub client_key_pem: Vec<u8>,
    pub(super) seen: Arc<Seen>,
    handle: axum_server::Handle<SocketAddr>,
}

impl Drop for GooglePush {
    fn drop(&mut self) {
        self.handle.shutdown();
    }
}

pub(super) fn issuer(name: &str) -> (rcgen::Issuer<'static, rcgen::KeyPair>, String) {
    let key = match rcgen::KeyPair::generate() {
        Ok(key) => key,
        Err(e) => panic!("{name}'s key: {e}"),
    };
    let mut params = match rcgen::CertificateParams::new(Vec::<String>::new()) {
        Ok(params) => params,
        Err(e) => panic!("{name}'s parameters: {e}"),
    };
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let pem = match params.self_signed(&key) {
        Ok(cert) => cert.pem(),
        Err(e) => panic!("{name}'s certificate: {e}"),
    };
    (rcgen::Issuer::new(params, key), pem)
}

/// A certificate from `issuer` for `names`, and its key, as PEM.
pub(super) fn issued(
    issuer: &rcgen::Issuer<'static, rcgen::KeyPair>,
    names: Vec<String>,
    common_name: &str,
) -> (String, String, Vec<u8>) {
    let key = match rcgen::KeyPair::generate() {
        Ok(key) => key,
        Err(e) => panic!("{common_name}'s key: {e}"),
    };
    let mut params = match rcgen::CertificateParams::new(names) {
        Ok(params) => params,
        Err(e) => panic!("{common_name}'s parameters: {e}"),
    };
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    let cert = match params.signed_by(&key, issuer) {
        Ok(cert) => cert,
        Err(e) => panic!("{common_name}'s certificate: {e}"),
    };
    (cert.pem(), key.serialize_pem(), cert.der().to_vec())
}

pub(super) fn pem_certs(pem: &str) -> Vec<rustls::pki_types::CertificateDer<'static>> {
    use rustls::pki_types::pem::PemObject;
    match rustls::pki_types::CertificateDer::pem_slice_iter(pem.as_bytes()).collect() {
        Ok(certs) => certs,
        Err(e) => panic!("a test certificate is PEM: {e}"),
    }
}

impl GooglePush {
    /// Serve the endpoints on a local port. Must run inside a Tokio runtime.
    pub async fn start() -> Self {
        use rustls::pki_types::pem::PemObject;

        let (server_ca, server_ca_pem) = issuer("Google (test endpoints)");
        let (client_ca, client_ca_pem) = issuer("DSM node push CA (test)");
        let (server_pem, server_key_pem, _) =
            issued(&server_ca, vec!["127.0.0.1".to_string()], "127.0.0.1");
        let (client_pem, client_key_pem, leaf) =
            issued(&client_ca, Vec::new(), "dsm-node-push (test)");

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut client_roots = rustls::RootCertStore::empty();
        for ca in pem_certs(&client_ca_pem) {
            if let Err(e) = client_roots.add(ca) {
                panic!("the client CA: {e}");
            }
        }
        let verifier = match rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(client_roots),
            provider.clone(),
        )
        .build()
        {
            Ok(verifier) => verifier,
            Err(e) => panic!("the client certificate verifier: {e}"),
        };
        let server_key =
            match rustls::pki_types::PrivateKeyDer::from_pem_slice(server_key_pem.as_bytes()) {
                Ok(key) => key,
                Err(e) => panic!("the endpoints' key: {e}"),
            };
        let tls = match rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
        {
            Ok(builder) => match builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(pem_certs(&server_pem), server_key)
            {
                Ok(tls) => tls,
                Err(e) => panic!("the endpoints' TLS: {e}"),
            },
            Err(e) => panic!("the endpoints' TLS versions: {e}"),
        };

        let seen = Arc::new(Seen {
            leaf,
            exchanges: Mutex::new(0),
            federated: Mutex::new(None),
            access: Mutex::new(None),
            refused: Mutex::new(HashSet::new()),
            gone: Mutex::new(HashSet::new()),
            pushes: Mutex::new(Vec::new()),
        });
        let app = axum::Router::new()
            .route("/v1/token", post(token_exchange))
            .route(
                "/v1/projects/-/serviceAccounts/{call}",
                post(service_account_token),
            )
            .route("/v1/projects/{project}/{call}", post(messages_send))
            .with_state(seen.clone());

        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(e) => panic!("bind the push endpoints: {e}"),
        };
        let address = match listener.local_addr() {
            Ok(address) => address,
            Err(e) => panic!("the push endpoints' address: {e}"),
        };
        let listener = match listener.into_std() {
            Ok(listener) => listener,
            Err(e) => panic!("the push endpoints' listener: {e}"),
        };
        let handle = axum_server::Handle::new();
        let config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls));
        let server = match axum_server::from_tcp_rustls(listener, config) {
            Ok(server) => server.handle(handle.clone()),
            Err(e) => panic!("the push endpoints' server: {e}"),
        };
        tokio::spawn(async move {
            if let Err(e) = server.serve(app.into_make_service()).await {
                panic!("serve the push endpoints: {e}");
            }
        });
        Self {
            endpoint: format!("https://{address}"),
            ca_pem: server_ca_pem.into_bytes(),
            client_cert_pem: client_pem.into_bytes(),
            client_key_pem: client_key_pem.into_bytes(),
            seen,
            handle,
        }
    }

    /// `[push.fcm]` as an operator states it for a node pushing through
    /// these endpoints.
    pub fn config(&self) -> dsm_storage_node::push::FcmConfig {
        dsm_storage_node::push::FcmConfig {
            project_id: PROJECT.to_string(),
            workload_identity_provider: PROVIDER.to_string(),
            service_account: SERVICE_ACCOUNT.to_string(),
            client_cert_pem: self.client_cert_pem.clone(),
            client_key_pem: self.client_key_pem.clone(),
            sts_endpoint: self.endpoint.clone(),
            iam_endpoint: self.endpoint.clone(),
            fcm_endpoint: self.endpoint.clone(),
            ca_cert_pem: Some(self.ca_pem.clone()),
        }
    }

    /// Every push Firebase took, in the order it took them.
    pub fn pushes(&self) -> Vec<Push> {
        held(&self.seen.pushes).clone()
    }

    /// Wait until Firebase has taken `count` pushes, at most `limit`; the
    /// pushes taken by then.
    pub async fn until_pushes(&self, count: usize, limit: std::time::Duration) -> Vec<Push> {
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

fn json(status: StatusCode, body: impl serde::Serialize) -> axum::response::Response {
    let text = match serde_json::to_string(&body) {
        Ok(text) => text,
        Err(e) => panic!("an answer of the push endpoints: {e}"),
    };
    (
        status,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        text,
    )
        .into_response()
}

/// Google's error answer.
#[derive(serde::Serialize)]
struct Refusal<'a> {
    error: RefusalDetail<'a>,
}

#[derive(serde::Serialize)]
struct RefusalDetail<'a> {
    code: u16,
    message: &'a str,
    status: &'a str,
    details: Vec<FcmErrorDetail>,
}

/// The detail Firebase gives an unregistered token.
#[derive(serde::Serialize)]
struct FcmErrorDetail {
    #[serde(rename = "@type")]
    kind: &'static str,
    #[serde(rename = "errorCode")]
    error_code: &'static str,
}

fn refused(status: StatusCode, why: &str) -> axum::response::Response {
    json(
        status,
        Refusal {
            error: RefusalDetail {
                code: status.as_u16(),
                message: why,
                status: "REFUSED",
                details: Vec::new(),
            },
        },
    )
}

#[derive(serde::Serialize)]
struct StsAnswer {
    access_token: String,
    issued_token_type: &'static str,
    token_type: &'static str,
    expires_in: u32,
}

#[derive(serde::Serialize)]
struct IamAnswer {
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "expireTime")]
    expire_time: &'static str,
}

#[derive(serde::Serialize)]
struct FcmTaken {
    name: String,
}

/// The bearer token a request presents, if it presents one in text.
fn bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(axum::http::header::AUTHORIZATION)?;
    match value.to_str() {
        Ok(text) => text.strip_prefix("Bearer ").map(str::to_string),
        Err(e) => panic!("the node sent an Authorization header that is not text: {e}"),
    }
}

/// `POST /v1/token`: a certificate exchanged for a federated access token.
/// The connection's TLS took only a certificate from the trusted CA; the
/// subject token must carry that certificate first.
async fn token_exchange(
    State(seen): State<Arc<Seen>>,
    body: axum::body::Bytes,
) -> axum::response::Response {
    let Ok(request) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return refused(StatusCode::BAD_REQUEST, "not JSON");
    };
    let expected = [
        (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ),
        ("audience", PROVIDER),
        ("scope", "https://www.googleapis.com/auth/cloud-platform"),
        (
            "requested_token_type",
            "urn:ietf:params:oauth:token-type:access_token",
        ),
        (
            "subject_token_type",
            "urn:ietf:params:oauth:token-type:mtls",
        ),
    ];
    for (field, value) in expected {
        if request[field] != value {
            return refused(StatusCode::BAD_REQUEST, &format!("{field} is not {value}"));
        }
    }
    let Some(subject) = request["subject_token"].as_str() else {
        return refused(StatusCode::BAD_REQUEST, "no subject_token");
    };
    let Ok(chain) = serde_json::from_str::<Vec<String>>(subject) else {
        return refused(
            StatusCode::BAD_REQUEST,
            "the subject token is not a JSON list",
        );
    };
    let leaf = match chain.first() {
        Some(first) => match base64::engine::general_purpose::STANDARD.decode(first) {
            Ok(leaf) => leaf,
            Err(e) => {
                return refused(
                    StatusCode::BAD_REQUEST,
                    &format!("the subject token's leaf is not base64: {e}"),
                )
            }
        },
        None => return refused(StatusCode::BAD_REQUEST, "the subject token is empty"),
    };
    if leaf != seen.leaf {
        return refused(
            StatusCode::UNAUTHORIZED,
            "the subject token's leaf is not the client certificate",
        );
    }
    let exchanges = {
        let mut exchanges = held(&seen.exchanges);
        *exchanges += 1;
        *exchanges
    };
    let federated = format!("federated-{exchanges}");
    *held(&seen.federated) = Some(federated.clone());
    json(
        StatusCode::OK,
        StsAnswer {
            access_token: federated,
            issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
            token_type: "Bearer",
            expires_in: 3600,
        },
    )
}

/// `POST /v1/projects/-/serviceAccounts/{account}:generateAccessToken`: the
/// service account's access token, for the federated token last handed out.
async fn service_account_token(
    State(seen): State<Arc<Seen>>,
    Path(call): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> axum::response::Response {
    if call != format!("{SERVICE_ACCOUNT}:generateAccessToken") {
        return refused(StatusCode::NOT_FOUND, "no such service account call");
    }
    let federated = held(&seen.federated).clone();
    if federated.is_none() || bearer(&headers) != federated {
        return refused(
            StatusCode::UNAUTHORIZED,
            "not the federated token handed out",
        );
    }
    let Ok(request) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return refused(StatusCode::BAD_REQUEST, "not JSON");
    };
    match request["scope"].as_array() {
        Some(scopes)
            if scopes.len() == 1
                && scopes[0] == "https://www.googleapis.com/auth/cloud-platform" => {}
        _ => return refused(StatusCode::BAD_REQUEST, "not the cloud-platform scope"),
    }
    let access = format!("access-{}", held(&seen.exchanges));
    *held(&seen.access) = Some(access.clone());
    json(
        StatusCode::OK,
        IamAnswer {
            access_token: access,
            expire_time: "2026-11-23T12:00:00Z",
        },
    )
}

/// `POST /v1/projects/{project}/messages:send`: one push, taken under the
/// access token last handed out unless it is refused now.
async fn messages_send(
    State(seen): State<Arc<Seen>>,
    Path((project, call)): Path<(String, String)>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> axum::response::Response {
    if project != PROJECT || call != "messages:send" {
        return refused(StatusCode::NOT_FOUND, "no such project call");
    }
    let access = held(&seen.access).clone();
    let presented = bearer(&headers);
    if access.is_none()
        || presented != access
        || presented
            .as_ref()
            .is_some_and(|token| held(&seen.refused).contains(token))
    {
        return refused(StatusCode::UNAUTHORIZED, "not a live access token");
    }
    let Ok(request) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return refused(StatusCode::BAD_REQUEST, "not JSON");
    };
    let message = request["message"].clone();
    let Some(push_token) = message["token"].as_str().map(str::to_string) else {
        return refused(StatusCode::BAD_REQUEST, "no token");
    };
    if held(&seen.gone).contains(&push_token) {
        return json(
            StatusCode::NOT_FOUND,
            Refusal {
                error: RefusalDetail {
                    code: 404,
                    message: "Requested entity was not found.",
                    status: "NOT_FOUND",
                    details: vec![FcmErrorDetail {
                        kind: "type.googleapis.com/google.firebase.fcm.v1.FcmError",
                        error_code: "UNREGISTERED",
                    }],
                },
            },
        );
    }
    let taken = {
        let mut pushes = held(&seen.pushes);
        pushes.push(Push {
            push_token,
            message,
        });
        pushes.len()
    };
    json(
        StatusCode::OK,
        FcmTaken {
            name: format!("projects/{PROJECT}/messages/{taken}"),
        },
    )
}
