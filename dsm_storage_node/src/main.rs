//! # DSM Storage Node Binary
//!
//! Index-only, clockless, signature-free storage node for the DSM network.
//! Serves protobuf-only HTTP/2 endpoints for genesis anchoring, ByteCommit
//! mirroring, DLV slot management, unilateral b0x transport, and inter-node
//! replication. Parameters: N=6, K=3, U_up=0.85, U_down=0.35.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{http::HeaderValue, middleware, Extension, Router};
use axum_server::tls_rustls::RustlsConfig;

use clap::Parser;
use config::{Config, File};
use log::info;
use once_cell::sync::OnceCell;
use rustls::crypto::{self, CryptoProvider};
use std::sync::Once;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};

// Prometheus metrics handle (installed once per-process)
static PROM_HANDLE: OnceCell<metrics_exporter_prometheus::PrometheusHandle> = OnceCell::new();

use dsm_storage_node::{api, auth, db, replication, AppState};

use api::network_config::NetworkDetector;

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
    #[clap(long, help = "Disable rate limiting for throughput benchmarking")]
    benchmark_mode: bool,
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
            let id_hash = blake3::hash(&[hostname.as_bytes(), &port.to_le_bytes()].concat());
            format!(
                "storage-node-{:x}",
                u64::from_le_bytes(id_hash.as_bytes()[0..8].try_into().unwrap_or([0u8; 8]))
            )
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
    })
}

/// Build the app and return `Router<()>`.
fn build_router(state: Arc<AppState>, config: &ServerConfig, benchmark_mode: bool) -> Router<()> {
    let public_rate_limiter = if benchmark_mode {
        log::info!("BENCHMARK MODE: rate limiting disabled for all public endpoints");
        Arc::new(api::rate_limit::RateLimiter::new_bypass())
    } else {
        Arc::new(api::rate_limit::RateLimiter::new())
    };
    let public_rate_layer = middleware::from_fn_with_state(
        public_rate_limiter.clone(),
        api::rate_limit::rate_limit_by_ip,
    );

    // Start with deterministic storage APIs you already have
    // (merge only the routers that are public & compile cleanly).
    // Object store reads (GET) are public; writes (PUT/DELETE) are behind device_auth
    // to prevent unauthenticated deletion or modification of vault advertisements.
    let object_read_router =
        api::object_store::create_router(state.clone()).layer(public_rate_layer.clone());
    let object_write_auth_state = Arc::new(auth::AuthState {
        db_pool: state.db_pool.clone(),
    });
    let object_write_router = api::object_store::create_write_router()
        .layer(axum::middleware::from_fn_with_state(
            object_write_auth_state,
            auth::device_auth,
        ))
        .layer(Extension(state.clone()));
    let object_list_router =
        api::object_list::create_router(state.clone()).layer(public_rate_layer.clone());
    let registry_router =
        api::registry::create_router(state.clone()).layer(public_rate_layer.clone());
    // Policy router is transport-only and signature-free; safe to expose.
    let policy_router = api::policy::create_router(state.clone()).layer(public_rate_layer.clone());
    // Identity mirrors
    let devtree_router =
        api::identity_devtree::create_router(state.clone()).layer(public_rate_layer.clone());
    let tips_router =
        api::identity_tips::create_router(state.clone()).layer(public_rate_layer.clone());
    // Genesis mirror
    let genesis_router =
        api::genesis::create_router(state.clone()).layer(public_rate_layer.clone());
    // DLV slot + Recovery Capsule
    let dlv_slot_router =
        api::dlv_slot::create_router(state.clone()).layer(public_rate_layer.clone());
    let recovery_capsule_router =
        api::recovery_capsule::create_router(state.clone()).layer(public_rate_layer.clone());
    // Device registration
    let device_router =
        api::device_api::create_router(state.clone()).layer(public_rate_layer.clone());
    // PaidK spend-gate
    let paidk_router = api::paidk::create_router(state.clone()).layer(public_rate_layer.clone());
    // Registry scaling (signals, applicants, registry queries)
    let registry_scaling_router =
        api::registry_scaling::create_router(state.clone()).layer(public_rate_layer.clone());
    // DrainProof & stake exit
    let drain_proof_router =
        api::drain_proof::create_router(state.clone()).layer(public_rate_layer.clone());
    // Gossip protocol for replication
    let gossip_router = api::gossip::gossip_routes(state.clone());
    // Node discovery for SDK auto-discovery
    let discovery_router =
        api::discovery::create_router(state.clone()).layer(public_rate_layer.clone());

    // Admin endpoints (cleanup, etc.)
    let admin_router = api::admin::router(state.clone());
    // Registry scaling admin endpoints (update trigger, seed)
    let registry_admin_router = api::registry_scaling::admin_router(state.clone()); // Compose routes and layers, then install `state`.
                                                                                    // Returning `Router<()>` here is important (see Axum docs).
                                                                                    // Request metrics for Prometheus scraping

    let app = Router::new()
        // Health check endpoint (lightweight, no DB access)
        .route("/api/v2/health", get(|| async { (StatusCode::OK, "ok") }))
        // Prometheus metrics scrape endpoint
        .route(
            "/metrics",
            get(|| async move {
                if let Some(handle) = PROM_HANDLE.get() {
                    let body = handle.render();
                    (StatusCode::OK, body).into_response()
                } else {
                    (StatusCode::SERVICE_UNAVAILABLE, "metrics_not_ready").into_response()
                }
            }),
        )
        .merge(object_read_router)
        .merge(object_write_router)
        .merge(object_list_router)
        .merge(registry_router) // exposes /api/v2/registry/* as in your tests
        .merge(policy_router)
        .merge(devtree_router)
        .merge(tips_router)
        .merge(genesis_router)
        .merge(dlv_slot_router)
        .merge(recovery_capsule_router)
        .merge(device_router) // exposes /api/v2/device/register
        .merge(paidk_router) // PaidK spend-gate endpoints
        .merge(registry_scaling_router) // signals, applicants, registry
        .merge(drain_proof_router) // DrainProof & stake exit
        .merge(gossip_router) // Gossip protocol endpoints
        .merge(discovery_router) // Node discovery for SDK auto-discovery
        .nest("/admin", admin_router) // Admin endpoints under /admin/*
        .nest("/admin", registry_admin_router) // Registry update/seed under /admin/*
        .layer(RequestBodyLimitLayer::new(config.body_limit_bytes))
        .layer(ConcurrencyLimitLayer::new(config.concurrency_limit))
        .layer(TraceLayer::new_for_http())
        .layer(Extension(state))
        .layer(Extension(public_rate_limiter));

    app
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

#[allow(dead_code)]
fn format_hsts_header(max_age: Option<u64>) -> Option<HeaderValue> {
    max_age.and_then(|age| HeaderValue::from_str(&format!("max-age={age}")).ok())
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
    if let Err(msg) = api::hardening::enforce_release_safety(&opts.config) {
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

    // Install Prometheus recorder (idempotent)
    if PROM_HANDLE.get().is_none() {
        let builder = metrics_exporter_prometheus::PrometheusBuilder::new();
        match builder.install_recorder() {
            Ok(handle) => {
                let _ = PROM_HANDLE.set(handle);
                info!("prometheus recorder installed");
            }
            Err(e) => {
                log::error!("failed to install prometheus recorder: {}", e);
            }
        }
    }

    // Initialize database
    info!("Initializing database connection pool...");
    let db_pool = Arc::new(
        db::create_pool(&server_config.database_url, false)
            .context("failed to create database connection pool")?,
    );

    info!("Initializing database schema...");
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

    let state = AppState::new(
        server_config.node_id.clone(),
        server_config.hsts_max_age,
        db_pool.clone(),
        replication_manager,
    );

    let app_state = Arc::new(state.clone());

    let mut app = build_router(app_state.clone(), &server_config, opts.benchmark_mode);

    // NOTE: No wall-clock maintenance loop. Maintenance cycles are invoked explicitly
    // via admin tooling with deterministic tick inputs.

    // Mount b0x v2 (protobuf-only, clockless) with auth middleware
    // Auth now uses the shared DB pool instead of a separate bare connection
    let auth_state = Arc::new(auth::AuthState {
        db_pool: db_pool.clone(),
    });
    let b0x_router = api::unilateral_api::router(Arc::new(state.clone()), auth_state);
    app = app.merge(b0x_router);

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
    /// Verify that the normative BLAKE3 domain tags used in node-id binding
    /// (whitepaper §10.1, CLAUDE.md §9) are NUL-terminated ASCII as required.
    /// BLAKE3 domain separation is: H("DSM/<name>\0" || data).
    #[test]
    fn node_id_domain_tag_is_nul_terminated_ascii() {
        const NODE_ID_TAG: &str = "DSM/node-id\0";
        const BYTECOMMIT_TAG: &str = "DSM/bytecommit\0";
        for tag in [NODE_ID_TAG, BYTECOMMIT_TAG] {
            assert!(tag.is_ascii(), "domain tag must be ASCII: {tag}");
            assert!(
                tag.ends_with('\0'),
                "domain tag must be NUL-terminated per whitepaper §2.1: {tag}"
            );
            assert!(
                tag.starts_with("DSM/"),
                "domain tag must use DSM/ prefix: {tag}"
            );
        }
    }
}
