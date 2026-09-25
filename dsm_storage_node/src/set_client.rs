// SPDX-License-Identifier: MIT OR Apache-2.0

//! The HTTP client a node reaches its set-mates with. It trusts exactly the
//! storage set's CA: every set-mate presents a certificate chaining to that
//! one anchor. A node reaches a set-mate only to mirror its ByteCommits
//! (storage spec §14, mirror sync), at the endpoint its own configuration
//! names for it.

use reqwest::Client;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;

/// A client pinned to `set_ca_pem`, the storage set's CA certificate.
pub fn pinned_set_client(set_ca_pem: &[u8]) -> anyhow::Result<Client> {
    let ca = CertificateDer::from_pem_slice(set_ca_pem)
        .map_err(|e| anyhow::anyhow!("the storage set's CA certificate is not PEM: {e}"))?;
    let mut root_store = RootCertStore::empty();
    root_store.add(ca)?;

    // The provider is named here rather than read from a process-wide
    // default, so the pin never depends on what else was installed first.
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(root_store)
            .with_no_client_auth();

    Ok(Client::builder().use_preconfigured_tls(config).build()?)
}

#[cfg(test)]
mod tests {
    use super::pinned_set_client;

    #[test]
    fn a_ca_that_is_not_pem_is_refused() {
        let err = pinned_set_client(b"not a certificate").expect_err("not PEM");
        assert!(err.to_string().contains("not PEM"), "{err}");
    }

    #[test]
    fn a_pem_ca_builds_a_client() {
        let ca = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .unwrap_or_else(|e| panic!("generate a test CA: {e}"));
        pinned_set_client(ca.cert.pem().as_bytes())
            .unwrap_or_else(|e| panic!("a PEM CA builds a pinned client: {e}"));
    }
}
