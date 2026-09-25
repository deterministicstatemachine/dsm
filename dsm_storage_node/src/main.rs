// SPDX-License-Identifier: MIT OR Apache-2.0

//! # DSM Storage Node Binary
//!
//! Index-only, clockless, signature-free storage node for the DSM network.
//! Serves protobuf-only HTTP/2 endpoints for genesis anchoring, ByteCommit
//! mirroring, DLV slot management, unilateral b0x transport, and inter-node
//! replication. (Capacity/scaling parameters are configured at runtime via the
//! `[replication]` config section and `ReplicationConfig`, not hardcoded here.)

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result};
use axum_server::tls_rustls::RustlsConfig;

use clap::Parser;
use config::{Config, File};
use log::info;
use rustls::crypto::{self, CryptoProvider};
use std::sync::Once;

use dsm::utils::text_id;

use dsm_storage_node::{api, db, replication, AppState};

use api::infra::network_config::NetworkDetector;

#[derive(Parser, Debug)]
#[clap(version = "1.0", author = "DSM Core Team")]
struct Opts {
    #[clap(short, long, default_value = "config.toml")]
    config: String,
    #[clap(short, long)]
    verbose: bool,
    #[clap(short, long, help = "Node index for automatic configuration (0-4)")]
    node_index: Option<usize>,
    #[clap(long, help = "Use automatic network detection instead of config file")]
    auto_detect: bool,
}

struct ServerConfig {
    bind_addr: SocketAddr,
    node_id: String,
    concurrency_limit: usize,
    tls_enabled: bool,
    tls_cert_path: Option<String>,
    tls_key_path: Option<String>,
    body_limit_bytes: usize,
    hsts_max_age: Option<u64>,
    database_url: String,
    seed_peers: Vec<String>,
    /// `[[storage_set.members]]` — each member's id and register incarnation.
    storage_set_members: Vec<(String, [u8; 32])>,
    /// `endpoint` on `[[storage_set.members]]` — where each set-mate is
    /// reached, for ByteCommit mirroring.
    storage_set_endpoints: Vec<(String, String)>,
}

fn load_server_config(opts: &Opts) -> Result<ServerConfig> {
    let settings = Config::builder()
        .add_source(File::with_name(&opts.config).required(false))
        .build()?;

    let concurrency_limit = settings
        .get_int("network.max_connections")
        .or_else(|_| settings.get_int("network.max_concurrency"))
        .or_else(|_| settings.get_int("api.max_connections"))
        .unwrap_or(256)
        .max(1) as usize;

    let tls_enabled = settings.get_bool("tls.enabled").unwrap_or(false);
    let tls_cert_path = if tls_enabled {
        Some(
            settings
                .get_string("tls.cert_path")
                .unwrap_or_else(|_| "certs/node.crt".to_string()),
        )
    } else {
        None
    };
    let tls_key_path = if tls_enabled {
        Some(
            settings
                .get_string("tls.key_path")
                .unwrap_or_else(|_| "certs/node.key".to_string()),
        )
    } else {
        None
    };

    let body_limit_bytes = settings.get_int("http.body_limit_bytes").unwrap_or(1048576) as usize;
    let hsts_max_age = if tls_enabled {
        Some(
            settings
                .get_int("security_headers.hsts_max_age")
                .unwrap_or(31536000) as u64,
        )
    } else {
        None
    };

    let database_url = settings
        .get_string("database.url")
        .unwrap_or_else(|_| "postgresql://localhost:5432/dsm_storage".to_string());

    // Extract seed peers from [replication] config section.
    let seed_peers: Vec<String> = settings
        .get_array("replication.peers")
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.into_string().ok())
        .collect();

    // The canonical storage set this node is a member of:
    //
    //     [[storage_set.members]]
    //     id = "dsm-node-1"
    //     register_incarnation = "<Base32-Crockford of 32 bytes>"
    //     endpoint = "https://10.0.0.1:8080"   # required for every other member
    //
    // Absent = the settlement-slot register is inactive (fail closed);
    // present but not containing this node's own id = misconfiguration,
    // refused at startup. The incarnation is REQUIRED per member: a set id is
    // a function of `(member_id, register_incarnation)` pairs, so a member
    // whose incarnation the config cannot state is a member no set id can be
    // derived over. A malformed entry refuses rather than defaulting, because
    // a defaulted incarnation would resolve every set to whatever the default
    // hashed to.
    let storage_set_entries: Vec<(String, [u8; 32], Option<String>)> = settings
        .get_array("storage_set.members")
        .unwrap_or_default()
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
                    anyhow::anyhow!(
                        "[[storage_set.members]] {id:?} is missing `register_incarnation`"
                    )
                })?;
            let raw = text_id::decode_base32_crockford(&inc_text).ok_or_else(|| {
                anyhow::anyhow!(
                    "[[storage_set.members]] {id:?} register_incarnation is not Base32-Crockford"
                )
            })?;
            let inc: [u8; 32] = raw.try_into().map_err(|_| {
                anyhow::anyhow!(
                    "[[storage_set.members]] {id:?} register_incarnation is not 32 bytes"
                )
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

    if opts.auto_detect {
        let node_index = opts.node_index.unwrap_or(0);
        let detected = NetworkDetector::detect_network_config_with_tls(node_index, tls_enabled)?;
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), detected.port);

        return Ok(ServerConfig {
            bind_addr,
            node_id: detected.node_id,
            concurrency_limit,
            tls_enabled,
            tls_cert_path,
            tls_key_path,
            body_limit_bytes,
            hsts_max_age,
            database_url,
            seed_peers,
            storage_set_members,
            storage_set_endpoints,
        });
    }

    let listen_ip = settings
        .get_string("network.listen_addr")
        .or_else(|_| settings.get_string("api.bind_address"))
        .unwrap_or_else(|_| "0.0.0.0".to_string());

    let port = settings
        .get_int("network.port")
        .or_else(|_| settings.get_int("api.port"))
        .unwrap_or(8080) as u16;

    let bind_addr: SocketAddr = format!("{listen_ip}:{port}").parse()?;

    let node_id = settings
        .get_string("node.id")
        .or_else(|_| settings.get_string("node.node_id"))
        .unwrap_or_else(|_| {
            // Generate deterministic node ID from hostname and port
            let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
            let mut material = Vec::new();
            material.extend_from_slice(hostname.as_bytes());
            material.extend_from_slice(&port.to_be_bytes());
            text_id::encode_base32_crockford(&api::infra::hardening::blake3_tagged(
                api::infra::hardening::DOM_NODE_ID,
                &material,
            ))
        });

    Ok(ServerConfig {
        bind_addr,
        node_id,
        concurrency_limit,
        tls_enabled,
        tls_cert_path,
        tls_key_path,
        body_limit_bytes,
        hsts_max_age,
        database_url,
        seed_peers,
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

    // Enforce production safety in release builds.
    if let Err(msg) = api::infra::hardening::enforce_release_safety(&opts.config) {
        anyhow::bail!(msg);
    }

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

    let replication_config = if cfg!(debug_assertions) {
        replication::ReplicationConfig {
            replication_factor: 1,
            gossip_interval_ticks: 100,
            failure_timeout_ticks: 500,
            gossip_fanout: 1,
            max_concurrent_jobs: 2,
        }
    } else {
        replication::default_production_config()
    };

    let replication_manager = if cfg!(debug_assertions) {
        info!("Initializing replication manager (test-mode for dev)...");
        Arc::new(
            replication::ReplicationManager::new_for_tests(
                replication_config,
                server_config.node_id.clone(),
                format!(
                    "http://{}:{}",
                    server_config.bind_addr.ip(),
                    server_config.bind_addr.port()
                ),
            )
            .map_err(|e| anyhow::anyhow!("Failed to create test replication manager: {}", e))?,
        )
    } else {
        info!(
            "Initializing replication manager (production TLS pinning, {} seed peers)...",
            server_config.seed_peers.len()
        );
        let cert_path = server_config
            .tls_cert_path
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing TLS cert_path for replication"))?;
        Arc::new(
            replication::ReplicationManager::new(
                replication_config,
                server_config.node_id.clone(),
                format!(
                    "https://{}:{}",
                    server_config.bind_addr.ip(),
                    server_config.bind_addr.port()
                ),
                std::path::Path::new(cert_path),
                server_config.seed_peers.clone(),
            )
            .map_err(|e| anyhow::anyhow!("Failed to create replication manager: {}", e))?,
        )
    };

    let bind_addr_str = format!(
        "https://{}:{}",
        server_config.bind_addr.ip(),
        server_config.bind_addr.port()
    );
    let mut state = AppState::new(
        server_config.node_id.clone(),
        &bind_addr_str,
        server_config.hsts_max_age,
        db_pool.clone(),
        replication_manager,
    );
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
    state = state.with_register_incarnation(own_incarnation);
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
            "no [storage_set] configured — the settlement-slot register is INACTIVE on this node \
             (every claim is refused)"
        );
    }

    let app_state = Arc::new(state.clone());

    // The one assembly the node serves (`dsm_storage_node::build_app`), shared
    // with tests that stand up real nodes. No wall-clock maintenance loop:
    // maintenance is invoked explicitly with deterministic tick inputs.
    let app = dsm_storage_node::build_app(
        app_state.clone(),
        &server_config.node_id,
        dsm_storage_node::AppLimits {
            body_limit_bytes: server_config.body_limit_bytes,
            concurrency_limit: server_config.concurrency_limit,
        },
    );

    info!(
        "DSM storage node ready: deterministic storage APIs (ByteCommit/ObjectStore + Registry) (node {} addr {} tls {})",
        server_config.node_id,
        server_config.bind_addr,
        server_config.tls_enabled
    );

    // ---------------------------------------------------------------------
    // Cleanup policy (clockless)
    // ---------------------------------------------------------------------
    // IMPORTANT: This storage node is clockless at the protocol boundary.
    // We intentionally do NOT run periodic cleanup using wall-clock time.
    // Expired object pruning is instead invoked explicitly via admin tooling
    // by supplying a deterministic `before_iter` value.

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

    if server_config.tls_enabled {
        let cert_path = server_config
            .tls_cert_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing TLS cert_path"))?;
        let key_path = server_config
            .tls_key_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing TLS key_path"))?;
        let tls_config = RustlsConfig::from_pem_file(cert_path, key_path)
            .await
            .context("failed to load TLS certificates")?;

        axum_server::bind_rustls(server_config.bind_addr, tls_config)
            .handle(handle)
            .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await
            .context("storage node TLS server error")?;
    } else {
        axum_server::bind(server_config.bind_addr)
            .handle(handle)
            .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await
            .context("storage node server error")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use dsm::common::domain_tags::{TAG_DSM_BYTECOMMIT, TAG_DSM_NODE_ID};

    /// Central storage-related tags remain ASCII `DSM/` domains.
    ///
    /// REWRITTEN for the canonical encoder. This used to build `format!("{tag}\0")`
    /// and assert the result ended with a NUL — i.e. it checked that the TEST
    /// could append a delimiter, which was true by construction and proved
    /// nothing about the hasher. The delimiter now belongs to `tagged_hasher`
    /// alone and a tag carrying its own is unrepresentable, so the meaningful
    /// statement is about the SOURCE bytes.
    #[test]
    fn node_id_domain_tags_are_ascii_dsm_and_carry_no_delimiter() {
        for tag in [TAG_DSM_NODE_ID, TAG_DSM_BYTECOMMIT] {
            let b = tag.source_bytes();
            let shown = String::from_utf8_lossy(b);
            assert!(b.is_ascii(), "domain tag must be ASCII: {shown}");
            assert!(
                b.starts_with(b"DSM/"),
                "domain tag must use DSM/ prefix: {shown}"
            );
            assert!(
                !b.contains(&0),
                "the delimiter belongs to the encoder, never the tag: {shown}"
            );
        }
    }
}
