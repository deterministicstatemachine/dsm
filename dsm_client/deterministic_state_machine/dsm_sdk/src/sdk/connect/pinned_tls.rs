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
use crate::sdk::bounded_read::{self, Bound, Budget};
use crate::util::text_id::encode_base32_crockford;

/// How long a connection may take to open (a transport bound, never a
/// validity rule).
const CONNECT_BOUND: Duration = Duration::from_secs(10);
/// How long one exchange may take, the endpoint's held request wait included.
const EXCHANGE_BOUND: Duration = Duration::from_secs(60);

const PROTOBUF: &str = "application/x-protobuf";

/// The proto's `dsm_max_len` for an offer's body and its signature
/// (`AppConnectOfferV1`), and for a request's (`AppRequestV1`).
const MAX_SIGNED_FIELD_BYTES: usize = 65_535;

/// The most an offer holds: a body and a signature, each at its longest.
fn offer_limit() -> usize {
    generated::AppConnectOfferV1 {
        body: vec![u8::MAX; MAX_SIGNED_FIELD_BYTES],
        signature: vec![u8::MAX; MAX_SIGNED_FIELD_BYTES],
    }
    .encoded_len()
}

/// One answer to a read of a session's requests: every request above the
/// position read from, in one batch the protocol does not page, so it bounds
/// no batch. This is this device's resource budget for one, not a protocol
/// rule: about sixty of the longest requests. A batch past it is refused as
/// unread, never taken as empty or cut short, and while an endpoint holds
/// more than that above the position, its session's read is not available
/// until the protocol pages these batches. Decoding may allocate four times
/// the bytes.
const REQUESTS_BUDGET: Budget = Budget {
    bytes: 8 * 1024 * 1024,
    allocation: 32 * 1024 * 1024,
};

/// The repeated field of `AppRequestBatchV1`: its requests.
const REQUESTS_ELEMENTS: [(u32, usize); 1] = [(1, std::mem::size_of::<generated::AppRequestV1>())];

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
    // A redirect is not followed: it would carry the exchange away from the
    // endpoint the code names, perhaps over plain HTTP, where the pin is not
    // checked.
    reqwest::Client::builder()
        .use_preconfigured_tls(config)
        .connect_timeout(CONNECT_BOUND)
        .timeout(EXCHANGE_BOUND)
        .redirect(reqwest::redirect::Policy::none())
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

    /// The endpoint's answer at `path`, read within `bound`. A refusal is its
    /// status: its body is not read, and the endpoint's text is not carried
    /// into this device's errors.
    async fn get(&self, path: &str, bound: Bound) -> Result<Vec<u8>, String> {
        let url = format!("{}{path}", self.endpoint);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("GET {path}: {e}"))?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!("GET {path}: the endpoint answered {status}"));
        }
        bounded_read::read(response, bound)
            .await
            .map_err(|e| format!("GET {path}: reading the answer: {e}"))
    }

    /// Deliver `body` at `path`. What the endpoint answers beside its status
    /// is not read: nothing here uses it.
    async fn post(&self, path: &str, body: Vec<u8>) -> Result<(), String> {
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
        if !status.is_success() {
            return Err(format!("POST {path}: the endpoint answered {status}"));
        }
        Ok(())
    }

    /// The offer a code names, as served. Its digest and signature are the
    /// caller's to check.
    pub async fn offer(
        &self,
        offer_digest: &[u8; 32],
    ) -> Result<generated::AppConnectOfferV1, String> {
        let bytes = self
            .get(
                &format!("/connect/offer/{}", encode_base32_crockford(offer_digest)),
                Bound::Limit(offer_limit()),
            )
            .await?;
        generated::AppConnectOfferV1::decode(bytes.as_slice())
            .map_err(|e| format!("the endpoint served no offer: {e}"))
    }

    pub async fn accept(&self, accept: &generated::AppConnectAcceptV1) -> Result<(), String> {
        self.post("/connect/accept", accept.encode_to_vec()).await
    }

    /// Every request of `session` above `after`, as served: the endpoint may
    /// hold the read until one arrives or its own bound passes.
    pub async fn requests(
        &self,
        session_id: &[u8; 32],
        after: u64,
    ) -> Result<generated::AppRequestBatchV1, String> {
        let bytes = self
            .get(
                &format!(
                    "/connect/requests/{}/{after}",
                    encode_base32_crockford(session_id)
                ),
                Bound::Budget(REQUESTS_BUDGET),
            )
            .await?;
        bounded_read::decode_within(&bytes, &REQUESTS_ELEMENTS, REQUESTS_BUDGET)
            .map_err(|e| format!("the endpoint served no request batch: {e}"))
    }

    pub async fn respond(&self, response: &generated::AppResponseV1) -> Result<(), String> {
        self.post("/connect/responses", response.encode_to_vec())
            .await
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

    /// An application's endpoint answering with `app`, on a self-signed
    /// certificate of its own: its origin and its pin.
    async fn serving(app: axum::Router) -> (String, [u8; 32], axum_server::Handle<SocketAddr>) {
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
        let handle: axum_server::Handle<SocketAddr> = axum_server::Handle::new();
        let server = axum_server::bind_rustls("127.0.0.1:0".parse().expect("an address"), config)
            .handle(handle.clone());
        tokio::spawn(async move { server.serve(app.into_make_service()).await });
        let addr = handle.listening().await.expect("the endpoint listens");
        (format!("https://127.0.0.1:{}", addr.port()), pin, handle)
    }

    const PATIENCE: Duration = Duration::from_secs(20);

    /// A request batch of `n` empty requests, as the wire carries it.
    fn empty_requests(n: usize) -> Vec<u8> {
        [0x0a, 0x00].repeat(n)
    }

    /// An endpoint's answers are read within their bounds. An offer that
    /// never ends is refused at the longest offer, not read until the
    /// exchange times out; a request batch, which the protocol does not
    /// bound, is refused past this device's budget for one, in bytes or in
    /// what decoding it would allocate.
    #[tokio::test]
    async fn a_relay_answer_past_its_bound_is_refused_unread() {
        let app = axum::Router::new()
            .route(
                "/connect/offer/{digest}",
                axum::routing::get(|| async { axum::body::Body::from_stream(endless_chunks()) }),
            )
            .route(
                "/connect/requests/{session}/{after}",
                axum::routing::get(
                    |axum::extract::Path((_, after)): axum::extract::Path<(String, u64)>| async move {
                        match after {
                            0 => vec![0x0a; REQUESTS_BUDGET.bytes + 1],
                            _ => empty_requests(REQUESTS_BUDGET.bytes / 4),
                        }
                    },
                ),
            );
        let (origin, pin, _handle) = serving(app).await;
        let relay = Relay::new(&origin, pin).expect("a relay");
        let refused = tokio::time::timeout(PATIENCE, relay.offer(&[7; 32]))
            .await
            .expect("an endless offer is refused, not waited out");
        assert!(
            refused
                .as_ref()
                .is_err_and(|why| why.contains("longer than")),
            "{refused:?}"
        );
        let refused = relay.requests(&[7; 32], 0).await;
        assert!(
            refused
                .as_ref()
                .is_err_and(|why| why.contains("byte budget")),
            "{refused:?}"
        );
        let refused = relay.requests(&[7; 32], 1).await;
        assert!(
            refused
                .as_ref()
                .is_err_and(|why| why.contains("would allocate")),
            "{refused:?}"
        );
    }

    fn endless_chunks(
    ) -> impl futures::Stream<Item = Result<bytes::Bytes, std::io::Error>> + Send + 'static {
        futures::stream::repeat_with(|| Ok(bytes::Bytes::from(vec![0x6f; 16 * 1024])))
    }

    /// A batch of honest requests, each a body and a signature as this
    /// device signs one, that fills the budget's bytes decodes within its
    /// allocation.
    #[test]
    fn the_requests_budget_holds_a_batch_of_signed_requests() {
        let (_, sk) = dsm::crypto::sphincs::generate_sphincs_keypair().expect("a key");
        let body = vec![0x62; 64];
        let request = generated::AppRequestV1 {
            signature: dsm::crypto::sphincs::sphincs_sign(&sk, &body).expect("a signature"),
            body,
        };
        let n = REQUESTS_BUDGET.bytes / (request.encoded_len() + 4);
        let batch = generated::AppRequestBatchV1 {
            requests: vec![request; n],
        }
        .encode_to_vec();
        assert!(batch.len() <= REQUESTS_BUDGET.bytes);
        let decoded = bounded_read::decode_within::<generated::AppRequestBatchV1>(
            &batch,
            &REQUESTS_ELEMENTS,
            REQUESTS_BUDGET,
        )
        .expect("a batch of signed requests decodes within the budget");
        assert_eq!(decoded.requests.len(), n);
    }

    /// The offer limit holds the longest offer an endpoint can serve.
    #[test]
    fn the_offer_limit_holds_the_longest_offer() {
        let longest = generated::AppConnectOfferV1 {
            body: vec![0x62; MAX_SIGNED_FIELD_BYTES],
            signature: vec![0x73; MAX_SIGNED_FIELD_BYTES],
        };
        assert_eq!(longest.encoded_len(), offer_limit());
    }

    /// An endpoint that redirects is not followed: the redirect points at
    /// plain HTTP, where no pin is checked, and nothing reaches it.
    #[tokio::test]
    async fn a_relay_redirect_is_not_followed() {
        let reached: Peers = Arc::new(std::sync::Mutex::new(Vec::new()));
        let plain = axum::Router::new()
            .route(
                "/connect/requests/{session}/{after}",
                axum::routing::get(empty_batch),
            )
            .with_state(reached.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a plain port");
        let port = listener.local_addr().expect("its address").port();
        tokio::spawn(async move {
            axum::serve(
                listener,
                plain.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
        });
        let app =
            axum::Router::new().route(
                "/connect/requests/{session}/{after}",
                axum::routing::get(
                    move |axum::extract::Path((session, after)): axum::extract::Path<(
                        String,
                        u64,
                    )>| async move {
                        axum::response::Redirect::temporary(&format!(
                            "http://127.0.0.1:{port}/connect/requests/{session}/{after}"
                        ))
                    },
                ),
            );
        let (origin, pin, _handle) = serving(app).await;
        let refused = Relay::new(&origin, pin)
            .expect("a relay")
            .requests(&[7; 32], 0)
            .await;
        assert!(
            refused.as_ref().is_err_and(|why| why.contains("307")),
            "{refused:?}"
        );
        let reached = match reached.lock() {
            Ok(seen) => seen.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        };
        assert_eq!(reached, 0, "the redirect was followed");
    }

    /// A refusal is its status: the endpoint's text is not read into this
    /// device's errors.
    #[tokio::test]
    async fn a_relay_refusal_is_its_status_alone() {
        let app = axum::Router::new().route(
            "/connect/requests/{session}/{after}",
            axum::routing::get(|| async {
                (
                    axum::http::StatusCode::FORBIDDEN,
                    "the endpoint's own words".repeat(1000),
                )
            }),
        );
        let (origin, pin, _handle) = serving(app).await;
        let refused = Relay::new(&origin, pin)
            .expect("a relay")
            .requests(&[7; 32], 0)
            .await;
        let why = match refused {
            Err(why) => why,
            Ok(batch) => panic!("a refusal was taken for a batch: {batch:?}"),
        };
        assert!(
            why.ends_with("the endpoint answered 403 Forbidden"),
            "{why}"
        );
        assert!(!why.contains("own words"), "{why}");
    }
}
