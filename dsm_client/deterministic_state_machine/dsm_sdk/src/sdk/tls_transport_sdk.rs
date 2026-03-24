// dsm_sdk/src/sdk/tls_transport_sdk.rs
//! SDK wrapper for DSM Core TLS-over-TCP Transport API.

use async_trait::async_trait;
use dsm::types::error::DsmError;
use rustls::crypto::{ring, CryptoProvider};
use rustls::ClientConfig;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Once;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

/// Errors specific to TLS transport
#[derive(Error, Debug)]
pub enum TlsError {
    #[error("TLS handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("TLS connection failed: {0}")]
    ConnectionFailed(String),

    #[error("TLS transport error: {0}")]
    TransportError(String),

    #[error("TLS certificate error: {0}")]
    CertificateError(String),
}

impl From<TlsError> for DsmError {
    fn from(err: TlsError) -> Self {
        DsmError::network(format!("tls: {err}"), None::<std::io::Error>)
    }
}

/// TLS Configuration for SDK
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Optional client cert chain (DER). If present, mTLS will be used.
    pub client_cert_chain_der: Option<Vec<Vec<u8>>>,
    /// Optional client private key (PKCS#8 DER).
    pub client_key_der: Option<Vec<u8>>,
    /// Root CAs (DER) to trust for server verification.
    pub root_ca_der: Vec<Vec<u8>>,
    /// Expected SNI / DNS name.
    pub server_name: String,
    /// Optional 32-byte BLAKE3 certificate pins for the server certificate DER.
    /// If non-empty, server cert must match at least one pin.
    pub pinned_server_spki_der: Vec<Vec<u8>>,
    /// Development escape hatch: accept invalid certs.
    /// Disabled in clockless builds; set to false.
    pub danger_accept_invalid_certs: bool,
}

impl TlsConfig {
    /// Create a strict client config with a server name and root CAs.
    pub fn new(server_name: String, root_ca_der: Vec<Vec<u8>>) -> Self {
        TlsConfig {
            client_cert_chain_der: None,
            client_key_der: None,
            root_ca_der,
            server_name,
            pinned_server_spki_der: vec![],
            danger_accept_invalid_certs: false,
        }
    }

    /// Configure optional mTLS client identity.
    pub fn with_client_identity(mut self, cert_chain_der: Vec<Vec<u8>>, key_der: Vec<u8>) -> Self {
        self.client_cert_chain_der = Some(cert_chain_der);
        self.client_key_der = Some(key_der);
        self
    }

    /// Add 32-byte BLAKE3 certificate pins for the server certificate DER.
    pub fn with_pinned_server_spki(mut self, spki_der: Vec<Vec<u8>>) -> Self {
        self.pinned_server_spki_der = spki_der;
        self
    }

    /// Development-only: disable cert validity checks.
    pub fn danger_accept_invalid_certs(mut self, yes: bool) -> Self {
        self.danger_accept_invalid_certs = yes;
        self
    }
}

// Transport abstractions live in this crate under sdk; provide minimal trait aliases here to decouple
// from the removed `communication` module. These are intentionally lightweight wrappers.
#[allow(dead_code)]
pub trait Transport {
    fn name(&self) -> &'static str {
        "tls"
    }
}

#[async_trait]
pub trait TransportConnection: Send + Sync {
    async fn send(&self, data: &[u8]) -> Result<(), DsmError>;
    async fn receive(&self) -> Result<Vec<u8>, DsmError>;
    async fn close(&self) -> Result<(), DsmError>;
}

fn normalize_pins(pins: Vec<Vec<u8>>) -> Result<Vec<[u8; 32]>, DsmError> {
    pins.into_iter()
        .map(|p| {
            if p.len() != 32 {
                return Err(DsmError::invalid_parameter(
                    "tls pins must be 32-byte BLAKE3 digests",
                ));
            }
            let mut a = [0u8; 32];
            a.copy_from_slice(&p);
            Ok(a)
        })
        .collect::<Result<Vec<_>, _>>()
}

static INSTALL_RUSTLS_PROVIDER: Once = Once::new();

pub fn ensure_rustls_crypto_provider() {
    INSTALL_RUSTLS_PROVIDER.call_once(|| {
        let _ = CryptoProvider::install_default(ring::default_provider());
    });
}

#[derive(Debug)]
pub struct TlsTransport {
    cfg: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    pins: Vec<[u8; 32]>,
}

impl TlsTransport {
    pub fn from_config(config: TlsConfig) -> Result<Self, DsmError> {
        ensure_rustls_crypto_provider();

        let server_name = ServerName::try_from(config.server_name.clone())
            .map_err(|_| DsmError::invalid_parameter("invalid tls server_name"))?;

        let mut roots = RootCertStore::empty();
        for der in config.root_ca_der.iter() {
            roots.add(CertificateDer::from(der.clone())).map_err(|e| {
                DsmError::network(
                    format!("tls root ca add failed: {e}"),
                    None::<std::io::Error>,
                )
            })?;
        }

        if config.danger_accept_invalid_certs {
            return Err(DsmError::Configuration {
                context: "danger_accept_invalid_certs is disabled in clockless builds".to_string(),
                source: None,
            });
        }

        let builder = ClientConfig::builder().with_root_certificates(roots);

        let client_cfg = if let (Some(chain), Some(key_der)) =
            (config.client_cert_chain_der, config.client_key_der)
        {
            let certs = chain
                .into_iter()
                .map(CertificateDer::from)
                .collect::<Vec<_>>();
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
            builder.with_client_auth_cert(certs, key).map_err(|e| {
                DsmError::network(
                    format!("tls client identity invalid: {e}"),
                    None::<std::io::Error>,
                )
            })?
        } else {
            builder.with_no_client_auth()
        };

        Ok(Self {
            cfg: Arc::new(client_cfg),
            server_name,
            pins: normalize_pins(config.pinned_server_spki_der)?,
        })
    }

    pub fn init() -> Result<Self, DsmError> {
        // Safe default: require explicit configuration (roots + server name) for production.
        Err(DsmError::Configuration {
            context: "TlsTransport::init requires explicit TlsConfig".to_string(),
            source: None,
        })
    }

    pub async fn connect(
        &self,
        addr: SocketAddr,
    ) -> Result<Box<dyn TransportConnection + Send + Sync>, DsmError> {
        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|e| DsmError::network("tls tcp connect failed", Some(e)))?;

        let connector = TlsConnector::from(self.cfg.clone());
        let stream = connector
            .connect(self.server_name.clone(), tcp)
            .await
            .map_err(|e| {
                DsmError::network(format!("tls handshake failed: {e}"), None::<std::io::Error>)
            })?;

        if !self.pins.is_empty() {
            let (_, session) = stream.get_ref();
            let certs = session.peer_certificates().ok_or_else(|| {
                DsmError::network("tls peer certificate missing", None::<std::io::Error>)
            })?;
            let end_entity = certs.first().ok_or_else(|| {
                DsmError::network("tls peer certificate missing", None::<std::io::Error>)
            })?;
            let cert_hash =
                *dsm::crypto::blake3::domain_hash("DSM/tls-cert-hash", end_entity.as_ref())
                    .as_bytes();
            if !self.pins.contains(&cert_hash) {
                return Err(DsmError::network(
                    "tls peer certificate pin mismatch",
                    None::<std::io::Error>,
                ));
            }
        }

        Ok(Box::new(RustlsConnection::new(stream)))
    }
}

#[derive(Debug)]
struct RustlsConnection {
    inner: Mutex<Option<TlsStream<TcpStream>>>,
}

impl RustlsConnection {
    fn new(stream: TlsStream<TcpStream>) -> Self {
        Self {
            inner: Mutex::new(Some(stream)),
        }
    }
}

#[async_trait]
impl TransportConnection for RustlsConnection {
    async fn send(&self, data: &[u8]) -> Result<(), DsmError> {
        // Length-prefixed framing: u32 BE + bytes.
        let mut guard = self.inner.lock().await;
        let s = guard
            .as_mut()
            .ok_or_else(|| DsmError::network("tls connection closed", None::<std::io::Error>))?;
        let len: u32 = data
            .len()
            .try_into()
            .map_err(|_| DsmError::invalid_parameter("tls send too large"))?;
        s.write_all(&len.to_be_bytes())
            .await
            .map_err(|e| DsmError::network("tls write failed", Some(e)))?;
        s.write_all(data)
            .await
            .map_err(|e| DsmError::network("tls write failed", Some(e)))?;
        s.flush()
            .await
            .map_err(|e| DsmError::network("tls flush failed", Some(e)))?;
        Ok(())
    }

    async fn receive(&self) -> Result<Vec<u8>, DsmError> {
        let mut guard = self.inner.lock().await;
        let s = guard
            .as_mut()
            .ok_or_else(|| DsmError::network("tls connection closed", None::<std::io::Error>))?;

        let mut len_buf = [0u8; 4];
        s.read_exact(&mut len_buf)
            .await
            .map_err(|e| DsmError::network("tls read length failed", Some(e)))?;
        let len = u32::from_be_bytes(len_buf) as usize;
        // Hard cap to avoid OOM; caller can chunk.
        const MAX_FRAME: usize = 8 * 1024 * 1024;
        if len > MAX_FRAME {
            return Err(DsmError::invalid_parameter("tls frame too large"));
        }

        let mut buf = vec![0u8; len];
        s.read_exact(&mut buf)
            .await
            .map_err(|e| DsmError::network("tls read payload failed", Some(e)))?;
        Ok(buf)
    }

    async fn close(&self) -> Result<(), DsmError> {
        let mut guard = self.inner.lock().await;
        *guard = None;
        Ok(())
    }
}

/// Exposes DSM TLS-over-TCP transport.
pub struct TlsTransportSDK {
    inner: TlsTransport,
    connection: Option<Box<dyn TransportConnection + Send + Sync>>,
}

impl std::fmt::Debug for TlsTransportSDK {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsTransportSDK")
            .field("inner", &"TlsTransport")
            .field("connected", &self.connection.is_some())
            .finish()
    }
}

impl TlsTransportSDK {
    /// Create a new TLS transport with the given config.
    pub fn new(config: TlsConfig) -> Result<Self, DsmError> {
        let transport = TlsTransport::from_config(config)?;

        Ok(TlsTransportSDK {
            inner: transport,
            connection: None,
        })
    }

    /// Create a new TLS transport with default configuration
    pub fn init() -> Result<Self, DsmError> {
        let transport = TlsTransport::init()?;

        Ok(TlsTransportSDK {
            inner: transport,
            connection: None,
        })
    }

    /// Connect to a remote peer
    pub async fn connect(&mut self, addr: SocketAddr) -> Result<(), DsmError> {
        let connection = self.inner.connect(addr).await?;
        self.connection = Some(connection);
        Ok(())
    }

    /// Securely send bytes to a remote peer.
    pub async fn send(&self, data: &[u8]) -> Result<(), DsmError> {
        match &self.connection {
            Some(conn) => conn.send(data).await,
            None => Err(DsmError::network("Error occurred", None::<std::io::Error>)),
        }
    }

    /// Securely receive bytes from a remote peer.
    pub async fn receive(&self) -> Result<Vec<u8>, DsmError> {
        match &self.connection {
            Some(conn) => conn.receive().await,
            None => Err(DsmError::network("Error occurred", None::<std::io::Error>)),
        }
    }

    /// Close the connection
    pub async fn close(&mut self) -> Result<(), DsmError> {
        if let Some(conn) = &self.connection {
            conn.close().await?;
            self.connection = None;
        }
        Ok(())
    }

    /// Check if the SDK is currently connected.
    pub fn is_connected(&self) -> bool {
        self.connection.is_some()
    }
}

#[async_trait]
pub trait TlsTransportSdkExt {
    async fn connect_and_send(&mut self, addr: SocketAddr, data: &[u8]) -> Result<(), DsmError>;
    async fn connect_and_receive(&mut self, addr: SocketAddr) -> Result<Vec<u8>, DsmError>;
}

#[async_trait]
impl TlsTransportSdkExt for TlsTransportSDK {
    async fn connect_and_send(&mut self, addr: SocketAddr, data: &[u8]) -> Result<(), DsmError> {
        self.connect(addr).await?;
        self.send(data).await?;
        Ok(())
    }

    async fn connect_and_receive(&mut self, addr: SocketAddr) -> Result<Vec<u8>, DsmError> {
        self.connect(addr).await?;
        let data = self.receive().await?;
        Ok(data)
    }
}
