// SPDX-License-Identifier: MIT OR Apache-2.0

//! The node's one outbound push: an empty message to a device's app, through
//! Firebase Cloud Messaging for Android or the Apple Push Notification
//! service for an iPhone, a doorbell that says only "read your inbox"
//! ([`crate::api::transport::doorbell`]). It names no amount, no sender, no
//! address and no spool; every push this node sends through one service has
//! the same body but for the device it goes to.
//!
//! **APNs.** The node reaches Apple with its provider certificate, a TLS
//! client certificate Apple issues for the app (certificate-based
//! connection to APNs): again a transport key held by TLS, and no JWT, so
//! nothing is signed and no clock is read. One call over HTTP/2:
//! `POST {apns}/3/device/{device}`, a background push
//! (`apns-push-type: background`, priority 5, `content-available`).
//!
//! The node reaches Google over TLS with a client certificate (Google's
//! Workload Identity Federation with X.509 certificates): the certificate's
//! private key is a transport key, held by TLS exactly as the node's server
//! key is, and nothing in the node's own code signs anything or reads a
//! clock (storage spec §1 rules 1 and 4; owner decision, 2026-10-28:
//! "Transport keys permitted, protocol-signing keys prohibited"). Three
//! calls, all of them Google's documented HTTP API:
//!
//! 1. `POST {sts}/v1/token` over mutual TLS: the certificate chain is the
//!    subject token, and the answer a federated access token;
//! 2. `POST {iam}/v1/projects/-/serviceAccounts/{account}:generateAccessToken`
//!    with it: an access token of the service account the operator lets send
//!    Firebase messages;
//! 3. `POST {fcm}/v1/projects/{project}/messages:send` with that token.
//!
//! An access token is kept until Google refuses it (`401`), then made again,
//! once, for that push: no expiry is read or timed. The JSON these calls take
//! is Google's format at this one boundary; nothing of it is DSM's.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Google's token exchange, reached over mutual TLS.
pub const GOOGLE_STS: &str = "https://sts.mtls.googleapis.com";
/// Google's service account credentials API.
pub const GOOGLE_IAM: &str = "https://iamcredentials.googleapis.com";
/// Firebase Cloud Messaging.
pub const GOOGLE_FCM: &str = "https://fcm.googleapis.com";

/// How long the node waits to connect to Google, and for one answer. A push
/// that times out is not sent, and the device reads its inbox the next time
/// it is opened: a transport bound, no protocol fact depends on it (storage
/// spec §1 rule 4).
pub const PUSH_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const PUSH_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// What one wake asks of Android: delivered at once, even to a phone in
/// Doze, and folded into one with any other still waiting for the phone.
const FCM_COLLAPSE_KEY: &str = "dsm-inbox";

/// The scope both access tokens are asked for.
const CLOUD_PLATFORM_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

/// `[push.fcm]` in the node's configuration: where Google is, who the node is
/// to it, and the Firebase project its pushes go through. Every field but the
/// endpoints and `ca_cert` is the operator's to state; none has a default.
#[derive(Clone)]
pub struct FcmConfig {
    /// The Firebase project id (`messages:send` is under it).
    pub project_id: String,
    /// The workload identity pool provider the node's certificate is trusted
    /// by: `//iam.googleapis.com/projects/<number>/locations/global/
    /// workloadIdentityPools/<pool>/providers/<provider>`.
    pub workload_identity_provider: String,
    /// The service account the provider's principal may act as, holding the
    /// role that sends Firebase messages.
    pub service_account: String,
    /// The node's client certificate, then any intermediates (PEM).
    pub client_cert_pem: Vec<u8>,
    /// The private key of that certificate (PEM): a TLS key, used by TLS
    /// alone.
    pub client_key_pem: Vec<u8>,
    /// Google's endpoints: [`GOOGLE_STS`], [`GOOGLE_IAM`], [`GOOGLE_FCM`]
    /// unless the configuration names others.
    pub sts_endpoint: String,
    pub iam_endpoint: String,
    pub fcm_endpoint: String,
    /// The one CA Google's endpoints are verified against (PEM), when the
    /// configuration names one; else the public web roots.
    pub ca_cert_pem: Option<Vec<u8>>,
}

/// What became of one push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// Google took it for the device.
    Taken,
    /// The token is not, or no longer, any app's (`404`): the device
    /// uninstalled the app or its token changed. Its doorbell is taken down.
    TokenGone,
    /// It was not sent: Google refused it, did not answer, or no access
    /// token could be had. The device reads its inbox when next opened.
    NotSent(String),
}

/// The node's Firebase sender: one HTTP client holding the node's client
/// certificate, and the access token it last had.
pub struct FcmSender {
    config: FcmConfig,
    client: reqwest::Client,
    /// The STS subject token: the client certificate chain, leaf first, each
    /// certificate standard base64 of its DER, as a JSON list.
    subject_token: String,
    access: tokio::sync::Mutex<Option<String>>,
}

impl FcmSender {
    /// The sender `config` describes. Refuses a certificate or key that is not
    /// PEM, and endpoints that are not `https://` origins.
    pub fn new(config: FcmConfig) -> anyhow::Result<Self> {
        for endpoint in [
            &config.sts_endpoint,
            &config.iam_endpoint,
            &config.fcm_endpoint,
        ] {
            https_origin(endpoint)?;
        }
        let chain = client_chain(&config.client_cert_pem)?;
        let encoded: Vec<String> = chain
            .iter()
            .map(|cert| base64::engine::general_purpose::STANDARD.encode(cert.as_ref()))
            .collect();
        let subject_token = serde_json::to_string(&encoded)?;
        let tls = client_tls(
            chain,
            &config.client_key_pem,
            config.ca_cert_pem.as_deref(),
            Vec::new(),
        )?;
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(PUSH_CONNECT_TIMEOUT)
            .timeout(PUSH_REQUEST_TIMEOUT)
            .build()?;
        Ok(Self {
            config,
            client,
            subject_token,
            access: tokio::sync::Mutex::new(None),
        })
    }

    /// Send one empty push to `push_token`. With no access token yet, or one
    /// Google refuses, a new one is made, once.
    pub async fn ring(&self, push_token: &str) -> Delivery {
        let mut access = self.access.lock().await;
        let held = match access.as_ref() {
            Some(granted) => granted.clone(),
            None => match self.access_token().await {
                Ok(granted) => {
                    *access = Some(granted.clone());
                    granted
                }
                Err(e) => return Delivery::NotSent(format!("no access token: {e}")),
            },
        };
        match self.send(&held, push_token).await {
            Sent::Answered(delivery) => delivery,
            Sent::AccessRefused => {
                let fresh = match self.access_token().await {
                    Ok(granted) => granted,
                    Err(e) => {
                        *access = None;
                        return Delivery::NotSent(format!("no access token: {e}"));
                    }
                };
                *access = Some(fresh.clone());
                match self.send(&fresh, push_token).await {
                    Sent::Answered(delivery) => delivery,
                    Sent::AccessRefused => {
                        *access = None;
                        Delivery::NotSent("a new access token was refused".to_string())
                    }
                }
            }
        }
    }

    /// One `messages:send`.
    async fn send(&self, access: &str, push_token: &str) -> Sent {
        let url = format!(
            "{}/v1/projects/{}/messages:send",
            self.config.fcm_endpoint.trim_end_matches('/'),
            self.config.project_id
        );
        let body = FcmSend {
            message: FcmMessage {
                registration: push_token,
                data: FcmData { dsm: "inbox" },
                android: FcmAndroid {
                    priority: "HIGH",
                    collapse_key: FCM_COLLAPSE_KEY,
                },
            },
        };
        let answer = match self
            .client
            .post(&url)
            .bearer_auth(access)
            .json(&body)
            .send()
            .await
        {
            Ok(answer) => answer,
            Err(e) => return Sent::Answered(Delivery::NotSent(format!("FCM unreachable: {e}"))),
        };
        let status = answer.status();
        if status.is_success() {
            Sent::Answered(Delivery::Taken)
        } else if status == reqwest::StatusCode::UNAUTHORIZED {
            Sent::AccessRefused
        } else if status == reqwest::StatusCode::NOT_FOUND {
            Sent::Answered(Delivery::TokenGone)
        } else {
            let detail = match answer.text().await {
                Ok(text) => text,
                Err(e) => format!("(the answer's body was not read: {e})"),
            };
            Sent::Answered(Delivery::NotSent(format!(
                "FCM answered {status}: {detail}"
            )))
        }
    }

    /// A new access token of the configured service account: the
    /// certificate exchanged for a federated token over mutual TLS, then that
    /// token for the service account's.
    async fn access_token(&self) -> anyhow::Result<String> {
        let exchange = StsExchange {
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
            audience: &self.config.workload_identity_provider,
            scope: CLOUD_PLATFORM_SCOPE,
            requested_token_type: "urn:ietf:params:oauth:token-type:access_token",
            subject_token_type: "urn:ietf:params:oauth:token-type:mtls",
            subject_token: &self.subject_token,
        };
        let url = format!(
            "{}/v1/token",
            self.config.sts_endpoint.trim_end_matches('/')
        );
        let federated: StsAnswer = answered(
            "the token exchange",
            self.client.post(&url).json(&exchange).send().await,
        )
        .await?;

        let url = format!(
            "{}/v1/projects/-/serviceAccounts/{}:generateAccessToken",
            self.config.iam_endpoint.trim_end_matches('/'),
            self.config.service_account
        );
        let scope = IamScope {
            scope: [CLOUD_PLATFORM_SCOPE],
        };
        let account: IamAnswer = answered(
            "the service account's token",
            self.client
                .post(&url)
                .bearer_auth(&federated.access_token)
                .json(&scope)
                .send()
                .await,
        )
        .await?;
        Ok(account.access_token)
    }
}

/// `messages:send`'s body: the one message every push is, but for its token.
#[derive(serde::Serialize)]
struct FcmSend<'a> {
    message: FcmMessage<'a>,
}

#[derive(serde::Serialize)]
struct FcmMessage<'a> {
    /// The app's Firebase registration, under the name Firebase gives it.
    #[serde(rename = "token")]
    registration: &'a str,
    data: FcmData,
    android: FcmAndroid,
}

/// The one data entry: the same in every push. Firebase documents delivery to
/// the app only for data messages, and an empty one is not a documented case.
#[derive(serde::Serialize)]
struct FcmData {
    dsm: &'static str,
}

#[derive(serde::Serialize)]
struct FcmAndroid {
    priority: &'static str,
    collapse_key: &'static str,
}

/// The token exchange's request (RFC 8693, Google's mutual-TLS subject).
#[derive(serde::Serialize)]
struct StsExchange<'a> {
    grant_type: &'static str,
    audience: &'a str,
    scope: &'static str,
    requested_token_type: &'static str,
    subject_token_type: &'static str,
    subject_token: &'a str,
}

/// `generateAccessToken`'s request.
#[derive(serde::Serialize)]
struct IamScope {
    scope: [&'static str; 1],
}

/// Apple's push service.
pub const APPLE_APNS: &str = "https://api.push.apple.com";
/// Apple's push service for development builds of the app.
pub const APPLE_APNS_SANDBOX: &str = "https://api.sandbox.push.apple.com";

/// What one wake asks of iOS: folded into one with any other still waiting
/// for the phone.
const APNS_COLLAPSE_ID: &str = "dsm-inbox";

/// `[push.apns]` in the node's configuration: where Apple is, the app the
/// pushes are for, and the provider certificate Apple issued for it.
#[derive(Clone)]
pub struct ApnsConfig {
    /// The app's bundle id, the topic every push names.
    pub topic: String,
    /// The provider certificate Apple issued for the app (PEM).
    pub client_cert_pem: Vec<u8>,
    /// Its private key (PEM): a TLS key, used by TLS alone.
    pub client_key_pem: Vec<u8>,
    /// [`APPLE_APNS`], [`APPLE_APNS_SANDBOX`], or another the configuration
    /// names.
    pub endpoint: String,
    /// The one CA Apple's endpoint is verified against (PEM), when the
    /// configuration names one; else the public web roots.
    pub ca_cert_pem: Option<Vec<u8>>,
}

/// The node's APNs sender: one HTTP/2 client holding the provider
/// certificate.
pub struct ApnsSender {
    config: ApnsConfig,
    client: reqwest::Client,
}

impl ApnsSender {
    /// The sender `config` describes. Refuses a certificate or key that is not
    /// PEM, and an endpoint that is not an `https://` origin.
    pub fn new(config: ApnsConfig) -> anyhow::Result<Self> {
        https_origin(&config.endpoint)?;
        let chain = client_chain(&config.client_cert_pem)?;
        let tls = client_tls(
            chain,
            &config.client_key_pem,
            config.ca_cert_pem.as_deref(),
            vec![b"h2".to_vec()],
        )?;
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .http2_prior_knowledge()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(PUSH_CONNECT_TIMEOUT)
            .timeout(PUSH_REQUEST_TIMEOUT)
            .build()?;
        Ok(Self { config, client })
    }

    /// Send one empty background push to the device whose token's bytes
    /// `device` names (Base32 Crockford).
    pub async fn ring(&self, device: &str) -> Delivery {
        let Some(bytes) = dsm::utils::text_id::decode_base32_crockford(device) else {
            return Delivery::NotSent("the device token is not Base32 Crockford".to_string());
        };
        // Apple names a device by its token in lowercase hex, in the path:
        // its own form at its own boundary.
        let path: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let url = format!(
            "{}/3/device/{path}",
            self.config.endpoint.trim_end_matches('/')
        );
        let body = ApnsPush {
            aps: ApnsAps {
                content_available: 1,
            },
        };
        let answer = match self
            .client
            .post(&url)
            .header("apns-push-type", "background")
            .header("apns-priority", "5")
            .header("apns-topic", &self.config.topic)
            .header("apns-collapse-id", APNS_COLLAPSE_ID)
            .json(&body)
            .send()
            .await
        {
            Ok(answer) => answer,
            Err(e) => return Delivery::NotSent(format!("APNs unreachable: {e}")),
        };
        let status = answer.status();
        if status.is_success() {
            return Delivery::Taken;
        }
        let reason = match answer.json::<ApnsRefusal>().await {
            Ok(refusal) => refusal.reason,
            Err(e) => format!("(no reason read: {e})"),
        };
        // 410: the app is gone from the device; BadDeviceToken: no such
        // device for this topic. Either way the doorbell rings no one.
        if status == reqwest::StatusCode::GONE || reason == "BadDeviceToken" {
            Delivery::TokenGone
        } else {
            Delivery::NotSent(format!("APNs answered {status}: {reason}"))
        }
    }
}

/// An APNs background push's body: nothing but the flag that wakes the app.
#[derive(serde::Serialize)]
struct ApnsPush {
    aps: ApnsAps,
}

#[derive(serde::Serialize)]
struct ApnsAps {
    #[serde(rename = "content-available")]
    content_available: u8,
}

/// Apple's refusal: the reason it names.
#[derive(serde::Deserialize)]
struct ApnsRefusal {
    reason: String,
}

/// The services a node pushes through: whichever its configuration names.
pub struct Pusher {
    pub fcm: Option<FcmSender>,
    pub apns: Option<ApnsSender>,
}

impl Pusher {
    /// The services this node is configured for.
    pub fn services(&self) -> Vec<dsm::types::proto::PushService> {
        use dsm::types::proto::PushService;
        let mut services = Vec::new();
        if self.fcm.is_some() {
            services.push(PushService::Fcm);
        }
        if self.apns.is_some() {
            services.push(PushService::Apns);
        }
        services
    }

    /// Send one empty push through `service` to `device`.
    pub async fn ring(&self, service: dsm::types::proto::PushService, device: &str) -> Delivery {
        use dsm::types::proto::PushService;
        match (service, &self.fcm, &self.apns) {
            (PushService::Fcm, Some(fcm), _) => fcm.ring(device).await,
            (PushService::Apns, _, Some(apns)) => apns.ring(device).await,
            (service, _, _) => {
                Delivery::NotSent(format!("this node does not push through {service:?}"))
            }
        }
    }
}

/// An `https://` origin, or why `endpoint` is not one.
fn https_origin(endpoint: &str) -> anyhow::Result<()> {
    let url = reqwest::Url::parse(endpoint)
        .map_err(|e| anyhow::anyhow!("push endpoint {endpoint:?} is not a URL: {e}"))?;
    if url.scheme() != "https" || url.host_str().is_none() {
        anyhow::bail!("push endpoint {endpoint:?} is not an https:// origin");
    }
    Ok(())
}

/// The client certificate and any intermediates in `pem`, leaf first.
fn client_chain(pem: &[u8]) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("the push client certificate is not PEM: {e}"))?;
    if chain.is_empty() {
        anyhow::bail!("the push client certificate file holds no certificate");
    }
    Ok(chain)
}

/// TLS presenting `chain` with the key in `client_key_pem`, verifying the
/// server against `ca_pem` when given, else the public web roots, and
/// offering `alpn`.
fn client_tls(
    chain: Vec<CertificateDer<'static>>,
    client_key_pem: &[u8],
    ca_pem: Option<&[u8]>,
    alpn: Vec<Vec<u8>>,
) -> anyhow::Result<rustls::ClientConfig> {
    let client_key = PrivateKeyDer::from_pem_slice(client_key_pem)
        .map_err(|e| anyhow::anyhow!("the push client certificate's key is not PEM: {e}"))?;
    let mut roots = rustls::RootCertStore::empty();
    match ca_pem {
        Some(pem) => {
            let ca = CertificateDer::from_pem_slice(pem)
                .map_err(|e| anyhow::anyhow!("the push CA certificate is not PEM: {e}"))?;
            roots.add(ca)?;
        }
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }
    // The provider is named here, as the set-mate client names it, so the
    // TLS a push uses never depends on what else was installed first.
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_client_auth_cert(chain, client_key)
    .map_err(|e| anyhow::anyhow!("the push client certificate and its key: {e}"))?;
    tls.alpn_protocols = alpn;
    Ok(tls)
}

/// One send's outcome, before a refused access token is made again.
enum Sent {
    Answered(Delivery),
    AccessRefused,
}

/// The token exchange's answer: the federated access token.
#[derive(serde::Deserialize)]
struct StsAnswer {
    access_token: String,
}

/// `generateAccessToken`'s answer: the service account's access token.
#[derive(serde::Deserialize)]
struct IamAnswer {
    #[serde(rename = "accessToken")]
    access_token: String,
}

/// The JSON a `2xx` answer to `what` holds, or why there is none.
async fn answered<T: serde::de::DeserializeOwned>(
    what: &str,
    sent: Result<reqwest::Response, reqwest::Error>,
) -> anyhow::Result<T> {
    let answer = sent.map_err(|e| anyhow::anyhow!("{what}: Google unreachable: {e}"))?;
    let status = answer.status();
    let body = answer
        .bytes()
        .await
        .map_err(|e| anyhow::anyhow!("{what}: the answer's body was not read: {e}"))?;
    if !status.is_success() {
        anyhow::bail!(
            "{what}: Google answered {status}: {}",
            String::from_utf8_lossy(&body)
        );
    }
    serde_json::from_slice(&body)
        .map_err(|e| anyhow::anyhow!("{what}: the answer is not what Google sends: {e}"))
}
