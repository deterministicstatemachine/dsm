// SPDX-License-Identifier: Apache-2.0
//! Shared helpers for storage-node integration tests.
//!
//! Cargo treats `tests/common/` specially: files inside it are NOT compiled
//! as standalone integration test binaries, so we can safely keep helpers
//! here without spawning a phantom test target.

#![allow(dead_code)]

pub fn ok_or_panic<T, E: std::fmt::Debug>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{context}: {err:?}"),
    }
}

pub fn some_or_panic<T>(value: Option<T>, context: &str) -> T {
    match value {
        Some(value) => value,
        None => panic!("{context}"),
    }
}

/// A fresh, empty store for one node of one test: a Postgres database of its
/// own on the server `DSM_TEST_DATABASE_URL` names, dropped and recreated so a
/// rerun starts empty. `name` must be unique per node per test (letters,
/// digits, `_`).
pub async fn fresh_store(name: &str) -> std::sync::Arc<dsm_storage_node::db::DBPool> {
    let server = std::env::var("DSM_TEST_DATABASE_URL").unwrap_or_else(|_| {
        panic!(
            "DSM_TEST_DATABASE_URL must name a Postgres server: these suites run on the \
             shipped backend, and skipping them would report a board that never executed it"
        )
    });
    let database = format!("dsm_test_{name}");
    let admin = ok_or_panic(
        dsm_storage_node::db::create_pool(&server, dsm_storage_node::db::POOL_MAX_SIZE),
        "admin pool",
    );
    let client = ok_or_panic(admin.get().await, "admin connection");
    ok_or_panic(
        client
            .batch_execute(&format!("DROP DATABASE IF EXISTS {database}"))
            .await,
        "drop the test database",
    );
    ok_or_panic(
        client
            .batch_execute(&format!("CREATE DATABASE {database}"))
            .await,
        "create the test database",
    );
    drop(client);
    let url = with_database(&server, &database);
    let pool = std::sync::Arc::new(ok_or_panic(
        dsm_storage_node::db::create_pool(&url, dsm_storage_node::db::POOL_MAX_SIZE),
        "pool",
    ));
    ok_or_panic(dsm_storage_node::db::init_db(&pool).await, "init db");
    pool
}

/// The store `fresh_store(name)` made, opened again as a restarting node
/// opens its store: a new pool on the same database, then `init_db`.
pub async fn reopened_store(name: &str) -> std::sync::Arc<dsm_storage_node::db::DBPool> {
    let server = ok_or_panic(
        std::env::var("DSM_TEST_DATABASE_URL"),
        "DSM_TEST_DATABASE_URL must name a Postgres server",
    );
    let url = with_database(&server, &format!("dsm_test_{name}"));
    let pool = std::sync::Arc::new(ok_or_panic(
        dsm_storage_node::db::create_pool(&url, dsm_storage_node::db::POOL_MAX_SIZE),
        "pool",
    ));
    ok_or_panic(dsm_storage_node::db::init_db(&pool).await, "init db");
    pool
}

/// `url` with its database path replaced by `database`.
fn with_database(url: &str, database: &str) -> String {
    let (head, query) = match url.split_once('?') {
        Some((head, query)) => (head, Some(query)),
        None => (url, None),
    };
    let slash = some_or_panic(head.rfind('/'), "the database URL names no database");
    match query {
        Some(query) => format!("{}/{database}?{query}", &head[..slash]),
        None => format!("{}/{database}", &head[..slash]),
    }
}

/// The storage set CA every test node is served under, made once per test
/// binary: its certificate, and one certificate it issued for the loopback
/// address with that certificate's key, as the fleet's CA issues each node a
/// certificate naming its IP (`deploy/generate_node_configs.sh`).
struct TestCa {
    ca_pem: String,
    node_cert_pem: String,
    node_key_pem: String,
}

fn test_ca() -> &'static TestCa {
    static CA: std::sync::OnceLock<TestCa> = std::sync::OnceLock::new();
    CA.get_or_init(|| {
        let ca_key = ok_or_panic(rcgen::KeyPair::generate(), "the CA's key");
        let mut ca_params = ok_or_panic(
            rcgen::CertificateParams::new(Vec::<String>::new()),
            "the CA's parameters",
        );
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "DSM-Storage-CA (node tests)");
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca_pem = ok_or_panic(ca_params.self_signed(&ca_key), "the CA's certificate").pem();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let node_key = ok_or_panic(rcgen::KeyPair::generate(), "the node's key");
        let node_params = ok_or_panic(
            rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]),
            "the node's parameters",
        );
        let node_cert = ok_or_panic(
            node_params.signed_by(&node_key, &issuer),
            "the node's certificate",
        );
        TestCa {
            ca_pem,
            node_cert_pem: node_cert.pem(),
            node_key_pem: node_key.serialize_pem(),
        }
    })
}

/// A client pinned to the test storage set's CA, as a node's set client is
/// pinned to its set's.
pub fn set_client() -> reqwest::Client {
    ok_or_panic(
        dsm_storage_node::set_client::pinned_set_client(test_ca().ca_pem.as_bytes()),
        "pinned client",
    )
}

/// The process's TLS provider, as the node binary installs it before it
/// serves (`main.rs`): the TLS server takes the process default.
fn install_tls_provider() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        match rustls::crypto::ring::default_provider().install_default() {
            Ok(()) => {}
            // Refused only because a provider is installed already, which is
            // all a server here needs.
            Err(installed_first) => assert!(
                rustls::crypto::CryptoProvider::get_default().is_some(),
                "no TLS provider installed: {installed_first:?}"
            ),
        }
    });
}

/// The TLS a test node serves: the certificate the test CA issued for the
/// loopback address.
pub async fn node_tls() -> axum_server::tls_rustls::RustlsConfig {
    install_tls_provider();
    let ca = test_ca();
    ok_or_panic(
        axum_server::tls_rustls::RustlsConfig::from_pem(
            ca.node_cert_pem.clone().into_bytes(),
            ca.node_key_pem.clone().into_bytes(),
        )
        .await,
        "the node's TLS",
    )
}

/// A loopback listener and the `https://` endpoint a set-mate's
/// configuration names for it.
pub async fn tls_listener() -> (tokio::net::TcpListener, String) {
    let listener = ok_or_panic(
        tokio::net::TcpListener::bind("127.0.0.1:0").await,
        "bind a listener",
    );
    let address = ok_or_panic(listener.local_addr(), "the listener's address");
    (listener, format!("https://{address}"))
}

/// Serve `app` on `listener` over the test node TLS, as a node serves its
/// set-mates, until the test ends.
pub async fn serve_tls(listener: tokio::net::TcpListener, app: axum::Router) {
    let tls = node_tls().await;
    let listener = ok_or_panic(listener.into_std(), "the listener");
    let server = ok_or_panic(axum_server::from_tcp_rustls(listener, tls), "a TLS server");
    tokio::spawn(async move {
        if let Err(e) = server.serve(app.into_make_service()).await {
            panic!("serve over TLS: {e}");
        }
    });
}

/// A Tokio runtime for a test that drives the served app. `#[tokio::test]`
/// builds its runtime with `expect`, which this crate's lints refuse.
pub fn runtime() -> tokio::runtime::Runtime {
    ok_or_panic(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build(),
        "a Tokio runtime",
    )
}

/// The member the binary serves on `pool`, as member id `id`.
pub fn member(id: &str, pool: std::sync::Arc<dsm_storage_node::db::DBPool>) -> axum::Router {
    let state = std::sync::Arc::new(ok_or_panic(
        dsm_storage_node::AppState::new(id.to_string(), pool, set_client()),
        "app state",
    ));
    served(state)
}

/// `app`'s answer to `method uri` with `headers` and `body`: its status and
/// its body.
pub async fn call(
    app: &axum::Router,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> (axum::http::StatusCode, Vec<u8>) {
    use tower::ServiceExt;
    let mut req = axum::http::Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        req = req.header(*name, *value);
    }
    let req = ok_or_panic(req.body(axum::body::Body::from(body)), "request");
    let resp = ok_or_panic(app.clone().oneshot(req).await, "the router answers");
    let status = resp.status();
    let bytes = ok_or_panic(
        axum::body::to_bytes(resp.into_body(), usize::MAX).await,
        "body",
    );
    (status, bytes.to_vec())
}

/// The app the binary serves for `state`, with the deployed fleet's limits.
pub fn served(state: std::sync::Arc<dsm_storage_node::AppState>) -> axum::Router {
    dsm_storage_node::build_app(
        state,
        dsm_storage_node::AppLimits {
            body_limit_bytes: 1_048_576,
            concurrency_limit: 256,
            request_timeout: std::time::Duration::from_secs(60),
            wait_bound: dsm_storage_node::api::transport::b0x::MAX_WAIT,
        },
    )
}
