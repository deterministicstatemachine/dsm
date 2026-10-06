// SPDX-License-Identifier: MIT OR Apache-2.0

//! The wallet's HTTPS client for an application's relay endpoint (DSM
//! Amendment A11), bound to the certificate pin the connect code names.
//!
//! The application's endpoint serves a self-signed certificate: the code the
//! player scanned off the application's own screen is what says which
//! certificate is the application's, so the leaf must hash to that pin and no
//! certificate authority is consulted. The handshake signatures are verified
//! as rustls verifies any; only the chain-of-trust question is answered by
//! the pin. No certificate validity period is read: DSM reads no clock.
//!
//! Everything this client carries is a signed protobuf object checked by its
//! receiver. The relay is transport, never evidence.

use std::sync::Arc;
use std::time::Duration;

use dsm::types::proto as generated;
use prost::Message;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

use super::signed::cert_pin;
use crate::util::text_id::encode_base32_crockford;

/// How long a connection may take to open (a transport bound, never a
/// validity rule).
const CONNECT_BOUND: Duration = Duration::from_secs(10);
/// How long one exchange may take, the endpoint's held request wait included.
const EXCHANGE_BOUND: Duration = Duration::from_secs(60);

const PROTOBUF: &str = "application/x-protobuf";

/// Accepts exactly the leaf certificate whose pin it holds.
#[derive(Debug)]
struct PinnedLeaf {
    pin: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedLeaf {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if cert_pin(end_entity.as_ref()) == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// An application's relay endpoint, reached over TLS bound to its pin.
pub struct Relay {
    endpoint: String,
    client: reqwest::Client,
}

/// The client for one endpoint under one pin: it accepts exactly the leaf
/// that hashes to `pin`.
fn pinned_client(pin: [u8; 32]) -> Result<reqwest::Client, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("the TLS protocol versions: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedLeaf { pin, provider }))
        .with_no_client_auth();
    reqwest::Client::builder()
        .use_preconfigured_tls(config)
        .connect_timeout(CONNECT_BOUND)
        .timeout(EXCHANGE_BOUND)
        .build()
        .map_err(|e| format!("the relay client: {e}"))
}

/// Every relay client this process built, by endpoint and pin. A client
/// keeps its open connections and TLS sessions, so each sync cycle and each
/// delivery to the same endpoint rides the connection the last one opened
/// instead of paying a new handshake. A client is built for one pin and
/// verifies with it alone, and a connection it keeps was verified under that
/// pin when it opened; another pin, even at the same endpoint, gets a client
/// of its own.
static RELAY_CLIENTS: std::sync::Mutex<
    std::collections::BTreeMap<(String, [u8; 32]), reqwest::Client>,
> = std::sync::Mutex::new(std::collections::BTreeMap::new());

fn relay_client(endpoint: &str, pin: [u8; 32]) -> Result<reqwest::Client, String> {
    // A panic elsewhere while the map was held leaves every entry whole: an
    // entry is inserted in one step.
    let mut clients = match RELAY_CLIENTS.lock() {
        Ok(clients) => clients,
        Err(poisoned) => poisoned.into_inner(),
    };
    let key = (endpoint.to_string(), pin);
    if let Some(client) = clients.get(&key) {
        return Ok(client.clone());
    }
    let client = pinned_client(pin)?;
    clients.insert(key, client.clone());
    Ok(client)
}

impl Relay {
    pub fn new(endpoint: &str, pin: [u8; 32]) -> Result<Self, String> {
        super::code::check_endpoint(endpoint)?;
        Ok(Self {
            endpoint: endpoint.to_string(),
            client: relay_client(endpoint, pin)?,
        })
    }

    async fn get(&self, path: &str) -> Result<Vec<u8>, String> {
        let url = format!("{}{path}", self.endpoint);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("GET {path}: {e}"))?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|e| format!("GET {path}: reading the answer: {e}"))?;
        if !status.is_success() {
            return Err(format!(
                "GET {path}: the endpoint answered {status}: {}",
                String::from_utf8_lossy(&body)
            ));
        }
        Ok(body.to_vec())
    }

    async fn post(&self, path: &str, body: Vec<u8>) -> Result<Vec<u8>, String> {
        let url = format!("{}{path}", self.endpoint);
        let response = self
            .client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, PROTOBUF)
            .body(body)
            .send()
            .await
            .map_err(|e| format!("POST {path}: {e}"))?;
        let status = response.status();
        let answer = response
            .bytes()
            .await
            .map_err(|e| format!("POST {path}: reading the answer: {e}"))?;
        if !status.is_success() {
            return Err(format!(
                "POST {path}: the endpoint answered {status}: {}",
                String::from_utf8_lossy(&answer)
            ));
        }
        Ok(answer.to_vec())
    }

    /// The offer a code names, as served. Its digest and signature are the
    /// caller's to check.
    pub async fn offer(
        &self,
        offer_digest: &[u8; 32],
    ) -> Result<generated::AppConnectOfferV1, String> {
        let bytes = self
            .get(&format!(
                "/connect/offer/{}",
                encode_base32_crockford(offer_digest)
            ))
            .await?;
        generated::AppConnectOfferV1::decode(bytes.as_slice())
            .map_err(|e| format!("the endpoint served no offer: {e}"))
    }

    pub async fn accept(&self, accept: &generated::AppConnectAcceptV1) -> Result<(), String> {
        self.post("/connect/accept", accept.encode_to_vec())
            .await
            .map(|_| ())
    }

    /// Every request of `session` above `after`, as served: the endpoint may
    /// hold the read until one arrives or its own bound passes.
    pub async fn requests(
        &self,
        session_id: &[u8; 32],
        after: u64,
    ) -> Result<generated::AppRequestBatchV1, String> {
        let bytes = self
            .get(&format!(
                "/connect/requests/{}/{after}",
                encode_base32_crockford(session_id)
            ))
            .await?;
        generated::AppRequestBatchV1::decode(bytes.as_slice())
            .map_err(|e| format!("the endpoint served no request batch: {e}"))
    }

    pub async fn respond(&self, response: &generated::AppResponseV1) -> Result<(), String> {
        self.post("/connect/responses", response.encode_to_vec())
            .await
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{ConnectInfo, State};
    use std::net::SocketAddr;

    type Peers = Arc<std::sync::Mutex<Vec<SocketAddr>>>;

    /// An empty request batch, recording the address the request came from:
    /// one connection is one client address.
    async fn empty_batch(
        State(peers): State<Peers>,
        ConnectInfo(peer): ConnectInfo<SocketAddr>,
    ) -> Vec<u8> {
        match peers.lock() {
            Ok(mut seen) => seen.push(peer),
            Err(poisoned) => poisoned.into_inner().push(peer),
        }
        generated::AppRequestBatchV1 {
            requests: Vec::new(),
        }
        .encode_to_vec()
    }

    /// An application's endpoint on a self-signed certificate of its own: its
    /// origin, its pin, and where each request came from.
    async fn endpoint() -> (String, [u8; 32], Peers, axum_server::Handle<SocketAddr>) {
        crate::sdk::tls_transport_sdk::ensure_rustls_crypto_provider();
        let made = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()])
            .expect("the endpoint's certificate");
        let cert = made.cert.der().to_vec();
        let pin = cert_pin(&cert);
        let config = axum_server::tls_rustls::RustlsConfig::from_der(
            vec![cert],
            made.signing_key.serialize_der(),
        )
        .await
        .expect("the endpoint's TLS config");
        let peers: Peers = Arc::new(std::sync::Mutex::new(Vec::new()));
        let app = axum::Router::new()
            .route(
                "/connect/requests/{session}/{after}",
                axum::routing::get(empty_batch),
            )
            .with_state(peers.clone());
        let handle: axum_server::Handle<SocketAddr> = axum_server::Handle::new();
        let server = axum_server::bind_rustls("127.0.0.1:0".parse().expect("an address"), config)
            .handle(handle.clone());
        tokio::spawn(async move {
            server
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
        });
        let addr = handle.listening().await.expect("the endpoint listens");
        (
            format!("https://127.0.0.1:{}", addr.port()),
            pin,
            peers,
            handle,
        )
    }

    /// Each sync cycle builds its relay anew. Three of them, at one endpoint
    /// under one pin, ride one connection: the first opens it, the next two
    /// reuse it rather than handshaking again. A relay under another pin, at
    /// the same endpoint, is refused, as the first relay ever was.
    #[tokio::test]
    async fn relays_to_one_endpoint_under_one_pin_ride_one_connection() {
        let (origin, pin, peers, _handle) = endpoint().await;
        for after in 0..3u64 {
            let relay = Relay::new(&origin, pin).expect("a relay");
            let batch = relay
                .requests(&[7; 32], after)
                .await
                .expect("the endpoint answers");
            assert_eq!(batch.requests.len(), 0);
        }
        let seen = match peers.lock() {
            Ok(seen) => seen.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        assert_eq!(seen.len(), 3, "every cycle reached the endpoint");
        assert!(
            seen.iter().all(|peer| *peer == seen[0]),
            "each cycle opened a connection of its own: {seen:?}"
        );

        let mut other = pin;
        other[0] ^= 1;
        let refused = Relay::new(&origin, other)
            .expect("a relay")
            .requests(&[7; 32], 0)
            .await;
        match refused {
            Ok(batch) => panic!("a relay under another pin was answered: {batch:?}"),
            Err(why) => assert!(why.starts_with("GET /connect/requests/"), "{why}"),
        }
    }
}
