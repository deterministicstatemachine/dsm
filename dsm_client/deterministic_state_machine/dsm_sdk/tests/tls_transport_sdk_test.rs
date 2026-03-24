#![allow(clippy::disallowed_methods)]

use std::net::SocketAddr;

use dsm_sdk::sdk::tls_transport_sdk::{TlsConfig, TlsTransportSDK};
// rcgen API is kept minimal here to avoid depending on private fields.
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

/// Explicitly install the ring crypto provider so that rustls can function
/// when both `ring` and `aws-lc-rs` features are present in the dependency graph.
/// Safe to call multiple times — subsequent installs are silently ignored.
fn install_crypto_provider() {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
}

fn cert_pin(cert_der: &[u8]) -> Vec<u8> {
    dsm::crypto::blake3::domain_hash("DSM/tls-cert-hash", cert_der)
        .as_bytes()
        .to_vec()
}

async fn spawn_tls_echo_server() -> (SocketAddr, Vec<u8>, Vec<u8>, Vec<u8>) {
    install_crypto_provider();

    // Self-signed server cert.
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();

    let cert_der = cert.serialize_der().unwrap();
    let key_der = cert.serialize_private_key_der();
    let pin = cert_pin(&cert_der);

    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.clone())),
        )
        .unwrap();

    let acceptor = TlsAcceptor::from(std::sync::Arc::new(cfg));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut tls = acceptor.accept(tcp).await.unwrap();
                // Echo frames: u32 be + payload
                loop {
                    let mut len_buf = [0u8; 4];
                    if tls.read_exact(&mut len_buf).await.is_err() {
                        return;
                    }
                    let len = u32::from_be_bytes(len_buf) as usize;
                    let mut buf = vec![0u8; len];
                    if tls.read_exact(&mut buf).await.is_err() {
                        return;
                    }
                    if tls.write_all(&len_buf).await.is_err() {
                        return;
                    }
                    if tls.write_all(&buf).await.is_err() {
                        return;
                    }
                    if tls.flush().await.is_err() {
                        return;
                    }
                }
            });
        }
    });

    (addr, cert_der, key_der, pin)
}

#[tokio::test]
async fn tls_transport_connect_send_receive_echo() {
    let (addr, server_cert_der, _server_key_der, _pin) = spawn_tls_echo_server().await;

    let cfg = TlsConfig::new(
        "localhost".to_string(),
        vec![server_cert_der], // trust the self-signed server cert
    );

    let mut sdk = TlsTransportSDK::new(cfg).unwrap();
    sdk.connect(addr).await.unwrap();
    assert!(sdk.is_connected());

    let msg = b"hello tls";
    sdk.send(msg).await.unwrap();
    let got = sdk.receive().await.unwrap();
    assert_eq!(got, msg);

    sdk.close().await.unwrap();
    assert!(!sdk.is_connected());
}

#[tokio::test]
async fn tls_transport_pinned_cert_allows() {
    let (addr, server_cert_der, _server_key_der, pin) = spawn_tls_echo_server().await;

    let cfg = TlsConfig::new("localhost".to_string(), vec![server_cert_der])
        .with_pinned_server_spki(vec![pin]);

    let mut sdk = TlsTransportSDK::new(cfg).unwrap();
    sdk.connect(addr).await.unwrap();
    sdk.close().await.unwrap();
}

#[tokio::test]
async fn tls_transport_pinned_cert_rejects_mismatch() {
    let (addr, server_cert_der, _server_key_der, _pin) = spawn_tls_echo_server().await;

    let cfg = TlsConfig::new("localhost".to_string(), vec![server_cert_der])
        .with_pinned_server_spki(vec![vec![9u8; 32]]);

    let mut sdk = TlsTransportSDK::new(cfg).unwrap();
    let err = sdk.connect(addr).await.expect_err("should fail");
    let s = format!("{err:?}");
    assert!(s.to_lowercase().contains("tls"));
}
