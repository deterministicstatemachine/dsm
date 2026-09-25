// SPDX-License-Identifier: MIT OR Apache-2.0

//! # DSM Storage Node Binary
//!
//! Clockless storage node for the DSM network. Serves protobuf-only
//! endpoints for the storage contract (keyed cells, indexes, the immutable
//! object store), ByteCommits and their mirror, and the b0x inbox spool.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum_server::tls_rustls::RustlsConfig;

use clap::Parser;
use config::{Config, File};
use log::info;
use rustls::crypto::{self, CryptoProvider};
use std::sync::Once;

use dsm::utils::text_id;

use dsm_storage_node::{db, set_client, AppState};

#[derive(Parser, Debug)]
#[clap(version = "1.0", author = "DSM Core Team")]
struct Opts {
    #[clap(short, long)]
    config: String,
    #[clap(short, long)]
    verbose: bool,
}

struct ServerConfig {
    bind_addr: SocketAddr,
    node_id: String,
    concurrency_limit: usize,
    tls_cert_path: String,
    tls_key_path: String,
    /// The storage set's CA certificate: the one anchor this node pins its
    /// peers to.
    set_ca_path: String,
    body_limit_bytes: usize,
    database_url: String,
    /// `[[storage_set.members]]` — each member's id and register incarnation.
    storage_set_members: Vec<(String, [u8; 32])>,
    /// `endpoint` on `[[storage_set.members]]` — where each set-mate is
    /// reached, for ByteCommit mirroring.
    storage_set_endpoints: Vec<(String, String)>,
}

/// A setting the node cannot start without: absent is an error, never a
/// value made up in its place.
fn required(settings: &Config, key: &str) -> Result<String> {
    settings
        .get_string(key)
        .with_context(|| format!("the node's config names no `{key}`"))
}

/// A setting the node has a stated default for: absent is the default, and a
/// value of the wrong type or out of range is an error, never the default.
fn optional_positive(settings: &Config, key: &str, default: usize) -> Result<usize> {
    match settings.get_int(key) {
        Ok(v) => usize::try_from(v)
            .ok()
            .filter(|v| *v > 0)
            .with_context(|| format!("`{key}` is {v}; it must be a positive integer")),
        Err(config::ConfigError::NotFound(_)) => Ok(default),
        Err(e) => Err(e).with_context(|| format!("`{key}` is not an integer")),
    }
}

fn load_server_config(opts: &Opts) -> Result<ServerConfig> {
    let settings = Config::builder()
        .add_source(File::with_name(&opts.config).required(true))
        .build()?;

    let concurrency_limit = optional_positive(&settings, "network.max_connections", 256)?;
    let body_limit_bytes = optional_positive(&settings, "http.body_limit_bytes", 1_048_576)?;

    let tls_cert_path = required(&settings, "tls.cert_path")?;
    let tls_key_path = required(&settings, "tls.key_path")?;
    let set_ca_path = required(&settings, "tls.ca_path")?;
    let database_url = required(&settings, "database.url")?;

    // The canonical storage set this node is a member of:
    //
    //     [[storage_set.members]]
    //     id = "dsm-node-1"
    //     register_incarnation = "<Base32-Crockford of 32 bytes>"
    //     endpoint = "https://10.0.0.1:8080"   # required for every other member
    //
    // Absent = this node is in no set yet (it has no set-mates to mirror);
    // present but not containing this node's own id = misconfiguration,
    // refused at startup. The incarnation is REQUIRED per member: a set id is
    // a function of `(member_id, register_incarnation)` pairs, so a member
    // whose incarnation the config cannot state is a member no set id can be
    // derived over. A malformed entry refuses rather than defaulting, because
    // a defaulted incarnation would resolve every set to whatever the default
    // hashed to.
    let storage_set_entries: Vec<(String, [u8; 32], Option<String>)> = match settings
        .get_array("storage_set.members")
    {
        Ok(members) => members,
        Err(config::ConfigError::NotFound(_)) => Vec::new(),
        Err(e) => return Err(e).context("`storage_set.members` is not an array of tables"),
    }
    .into_iter()
    .map(|v| {
        let t = v
            .into_table()
            .map_err(|e| anyhow::anyhow!("[[storage_set.members]] is not a table: {e}"))?;
        let id = t
            .get("id")
            .and_then(|v| v.clone().into_string().ok())
            .ok_or_else(|| anyhow::anyhow!("[[storage_set.members]] is missing `id`"))?;
        let inc_text = t
            .get("register_incarnation")
            .and_then(|v| v.clone().into_string().ok())
            .ok_or_else(|| {
                anyhow::anyhow!("[[storage_set.members]] {id:?} is missing `register_incarnation`")
            })?;
        let raw = text_id::decode_base32_crockford(&inc_text).ok_or_else(|| {
            anyhow::anyhow!(
                "[[storage_set.members]] {id:?} register_incarnation is not Base32-Crockford"
            )
        })?;
        let inc: [u8; 32] = raw.try_into().map_err(|_| {
            anyhow::anyhow!("[[storage_set.members]] {id:?} register_incarnation is not 32 bytes")
        })?;
        let endpoint = match t.get("endpoint") {
            None => None,
            Some(v) => Some(v.clone().into_string().map_err(|_| {
                anyhow::anyhow!("[[storage_set.members]] {id:?} endpoint is not a string")
            })?),
        };
        Ok((id, inc, endpoint))
    })
    .collect::<anyhow::Result<Vec<_>>>()?;
    let storage_set_endpoints: Vec<(String, String)> = storage_set_entries
        .iter()
        .filter_map(|(id, _, e)| e.clone().map(|e| (id.clone(), e)))
        .collect();
    let storage_set_members: Vec<(String, [u8; 32])> = storage_set_entries
        .into_iter()
        .map(|(id, inc, _)| (id, inc))
        .collect();

    let listen_ip = required(&settings, "network.listen_addr")?;
    let port = settings
        .get_int("network.port")
        .context("the node's config names no `network.port`")?;
    let bind_addr: SocketAddr = format!("{listen_ip}:{port}").parse()?;
    let node_id = required(&settings, "node.id")?;

    Ok(ServerConfig {
        bind_addr,
        node_id,
        concurrency_limit,
        tls_cert_path,
        tls_key_path,
        set_ca_path,
        body_limit_bytes,
        database_url,
        storage_set_members,
        storage_set_endpoints,
    })
}

// Ensure a rustls CryptoProvider is installed once per-process (required by rustls >= 0.23)
fn ensure_rustls_provider_installed() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let provider = crypto::ring::default_provider();
        if let Err(e) = CryptoProvider::install_default(provider) {
            log::error!("failed to install rustls ring CryptoProvider: {:?}", e);
        }
    });
}

fn main() -> Result<()> {
    ensure_rustls_provider_installed();

    // Build a Tokio runtime manually to avoid `#[tokio::main]` macro using disallowed expect
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;
    rt.block_on(async_main())
}

async fn async_main() -> Result<()> {
    let opts = Opts::parse();

    // Bridge `log` records into `tracing` subscriber so `log::{info,warn,...}` work
    let _ = tracing_log::LogTracer::init();

    if opts.verbose {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_max_level(tracing::Level::DEBUG)
            .try_init();
    } else {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .try_init();
    }

    let server_config = load_server_config(&opts).context("failed to load server configuration")?;

    // Initialize database
    info!("Initializing database connection pool...");
    let db_pool = Arc::new(
        db::create_pool(&server_config.database_url)
            .context("failed to create database connection pool")?,
    );

    info!("Initializing database schema...");
    // A node that cannot keep an acknowledgement must not serve a register.
    db::require_durable_commit_posture(&db_pool)
        .await
        .map_err(|e| {
            log::error!("{e}");
            e
        })?;
    db::init_db(&db_pool)
        .await
        .context("failed to initialize database schema")?;

    let set_ca_pem = std::fs::read(&server_config.set_ca_path).with_context(|| {
        format!(
            "failed to read the storage set's CA certificate at {}",
            server_config.set_ca_path
        )
    })?;
    let set_client = set_client::pinned_set_client(&set_ca_pem)
        .context("failed to build the client pinned to the storage set's CA")?;
    let mut state = AppState::new(server_config.node_id.clone(), db_pool.clone(), set_client)?;
    // ESTABLISHED AND LOGGED UNCONDITIONALLY, before any set is considered.
    //
    // The incarnation is a property of this node's register, not of its
    // membership in a set, and an operator cannot write `[[storage_set.members]]`
    // for this node without knowing the value. Establishing it only when a set
    // is already configured would be a bootstrap that never starts: no set
    // means no incarnation, no incarnation means no set can be written.
    let own_incarnation = db::register_incarnation(&db_pool)
        .await
        .context("failed to establish this node's register incarnation")?;
    log::info!(
        "register incarnation for node {}: {}",
        server_config.node_id,
        text_id::encode_base32_crockford(&own_incarnation)
    );
    if !server_config.storage_set_members.is_empty() {
        // Config states what the set COMMITTED; the database states what this
        // node can still speak for. `NodeStorageSet` refuses when they differ.
        let set = dsm_storage_node::NodeStorageSet::new(
            server_config.storage_set_members.clone(),
            &server_config.node_id,
            own_incarnation,
        )?
        .with_endpoints(
            &server_config.node_id,
            server_config.storage_set_endpoints.clone(),
        )?;
        log::info!(
            "storage set configured: {} members, id={}",
            set.members.len(),
            text_id::encode_base32_crockford(&set.id)
        );
        state = state.with_storage_set(set);
    } else {
        log::warn!(
            "no [storage_set] configured: this node serves the storage contract and mirrors no \
             set-mate; name its members, with the incarnation above for this node, to join a set"
        );
    }

    let app_state = Arc::new(state.clone());

    // The one assembly the node serves (`dsm_storage_node::build_app`), shared
    // with tests that stand up real nodes.
    let app = dsm_storage_node::build_app(
        app_state.clone(),
        dsm_storage_node::AppLimits {
            body_limit_bytes: server_config.body_limit_bytes,
            concurrency_limit: server_config.concurrency_limit,
        },
    );

    info!(
        "DSM storage node ready (node {} addr {})",
        server_config.node_id, server_config.bind_addr
    );

    // Graceful shutdown with handle pattern
    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();

    tokio::spawn(async move {
        // CTRL-C
        let ctrl_c = async {
            tokio::signal::ctrl_c().await.ok();
        };
        // SIGTERM (Unix only)
        #[cfg(unix)]
        let terminate = async {
            use tokio::signal::unix::{signal, SignalKind};
            if let Ok(mut sig) = signal(SignalKind::terminate()) {
                sig.recv().await;
            }
        };
        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {},
            _ = terminate => {},
        }
        info!("shutdown signal received; commencing graceful shutdown");
        shutdown_handle.graceful_shutdown(None);
    });

    let tls_config =
        RustlsConfig::from_pem_file(&server_config.tls_cert_path, &server_config.tls_key_path)
            .await
            .context("failed to load TLS certificates")?;
    axum_server::bind_rustls(server_config.bind_addr, tls_config)
        .handle(handle)
        .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await
        .context("storage node TLS server error")?;

    Ok(())
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // unwrap/expect acceptable in deterministic tests
mod tests {
    const WHOLE_CONFIG: &str = r#"
[node]
id = "node-under-test"

[network]
listen_addr = "127.0.0.1"
port = 8443

[tls]
cert_path = "/certs/node.crt"
key_path = "/certs/node.key"
ca_path = "/certs/ca.crt"

[database]
url = "postgresql://127.0.0.1:5432/node"
"#;

    fn load(body: &str) -> anyhow::Result<super::ServerConfig> {
        let path = std::env::temp_dir().join(format!(
            "dsm-node-config-{}.toml",
            dsm::utils::text_id::encode_base32_crockford(&rand::random::<[u8; 16]>())
        ));
        std::fs::write(&path, body).expect("write the config");
        let loaded = super::load_server_config(&super::Opts {
            config: path.to_string_lossy().into_owned(),
            verbose: false,
        });
        std::fs::remove_file(&path).expect("remove the config");
        loaded
    }

    /// Ruling #2: a node starts from what its config states. A setting it
    /// cannot run without is refused by name when absent — no identity, TLS
    /// material, trust anchor or database is made up in its place.
    #[test]
    fn a_config_missing_a_required_setting_is_refused_by_name() {
        let whole = load(WHOLE_CONFIG).expect("the whole config loads");
        assert_eq!(whole.node_id, "node-under-test");
        assert_eq!(whole.set_ca_path, "/certs/ca.crt");
        for (line, key) in [
            ("id = \"node-under-test\"", "node.id"),
            ("listen_addr = \"127.0.0.1\"", "network.listen_addr"),
            ("port = 8443", "network.port"),
            ("cert_path = \"/certs/node.crt\"", "tls.cert_path"),
            ("key_path = \"/certs/node.key\"", "tls.key_path"),
            ("ca_path = \"/certs/ca.crt\"", "tls.ca_path"),
            ("url = \"postgresql://127.0.0.1:5432/node\"", "database.url"),
        ] {
            assert!(WHOLE_CONFIG.contains(line), "fixture line {line}");
            let err = match load(&WHOLE_CONFIG.replace(line, "")) {
                Ok(_) => panic!("a config without `{key}` is refused"),
                Err(e) => format!("{e:#}"),
            };
            assert!(err.contains(key), "the refusal names `{key}`: {err}");
        }
    }

    /// A config file that does not exist is refused as missing, before any
    /// setting is read — not treated as an empty config.
    #[test]
    fn a_missing_config_file_is_refused() {
        let err = match super::load_server_config(&super::Opts {
            config: "/nonexistent/dsm-node-config.toml".to_string(),
            verbose: false,
        }) {
            Ok(_) => panic!("a config file that does not exist is refused"),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            err.contains("/nonexistent/dsm-node-config.toml") && err.contains("not found"),
            "the refusal names the missing file: {err}"
        );
    }

    /// A setting with a stated default takes the default only when it is
    /// absent. A value of the wrong type, zero or negative is refused by name
    /// rather than quietly read as the default.
    #[test]
    fn a_limit_of_the_wrong_type_or_out_of_range_is_refused_by_name() {
        let whole = load(WHOLE_CONFIG).expect("the whole config loads");
        assert_eq!(whole.concurrency_limit, 256);
        assert_eq!(whole.body_limit_bytes, 1_048_576);

        let with = |extra: &str| format!("{WHOLE_CONFIG}\n{extra}\n");
        let set = load(&with("[http]\nbody_limit_bytes = 4096")).expect("a stated limit loads");
        assert_eq!(set.body_limit_bytes, 4096);
        for (extra, key) in [
            (
                "[http]\nbody_limit_bytes = \"lots\"",
                "http.body_limit_bytes",
            ),
            ("[http]\nbody_limit_bytes = 0", "http.body_limit_bytes"),
            ("[http]\nbody_limit_bytes = -1", "http.body_limit_bytes"),
        ] {
            let err = match load(&with(extra)) {
                Ok(_) => panic!("`{extra}` is refused"),
                Err(e) => format!("{e:#}"),
            };
            assert!(err.contains(key), "the refusal names `{key}`: {err}");
        }
        let err = match load(
            &WHOLE_CONFIG.replace("port = 8443", "port = 8443\nmax_connections = [1]"),
        ) {
            Ok(_) => panic!("a non-integer max_connections is refused"),
            Err(e) => format!("{e:#}"),
        };
        assert!(err.contains("network.max_connections"), "{err}");
    }

    /// `storage_set.members` of the wrong shape is refused, never read as
    /// "no set".
    #[test]
    fn storage_set_members_of_the_wrong_shape_are_refused() {
        let err = match load(&format!(
            "{WHOLE_CONFIG}\n[storage_set]\nmembers = \"n1\"\n"
        )) {
            Ok(_) => panic!("a string for storage_set.members is refused"),
            Err(e) => format!("{e:#}"),
        };
        assert!(err.contains("storage_set.members"), "{err}");
    }
}
