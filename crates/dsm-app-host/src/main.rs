// SPDX-License-Identifier: MIT OR Apache-2.0

//! `dsm-app-host`: a Web2 application's own account on DSM (DSM Amendment
//! A11).
//!
//! The application stays an ordinary Web2 application. This process is its
//! account: one real DSM identity, on the same production SDK path a phone
//! runs, against the network's pinned storage set. It serves two things:
//!
//! - **the game-facing ingress** on a local address: the same protobuf
//!   boundary the wallet's WebView uses (`IngressRequest` in,
//!   `IngressResponse` out), plus a record of what each call did to this
//!   account, for the application to show;
//! - **the DSM Connect relay** a wallet reaches over TLS bound to the pin its
//!   connect code names: offers, accepts, requests and answers. The relay is
//!   transport, never evidence.
//!
//! The host decides nothing. Every route is the SDK's own; every check a
//! connection needs is in the SDK's `connect` module.

mod activity;
mod dispatch;
mod game;
mod identity;
mod relay;
mod tls;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

/// What the host is started with.
pub struct Args {
    /// Where this account's state lives (its client store, its sealed seed,
    /// the relay's TLS identity).
    pub data_dir: PathBuf,
    /// The network's environment config: the pinned storage set and its CA.
    pub env_config: PathBuf,
    /// The local address the application reaches the ingress on: a loopback
    /// address, never one another machine can reach.
    pub game_bind: SocketAddr,
    /// The address the relay listens on for wallets.
    pub relay_bind: SocketAddr,
    /// The relay's origin as a wallet reaches it (`https://host:port`), named
    /// in every connect code.
    pub relay_endpoint: String,
    /// The names the relay's certificate carries (an IP or a host name each).
    pub relay_names: Vec<String>,
}

const USAGE: &str = "dsm-app-host --data-dir DIR --env-config FILE \
--game-bind 127.0.0.1:8787 --relay-bind 0.0.0.0:8443 \
--relay-endpoint https://HOST:8443 [--relay-name HOST ...]";

impl Args {
    fn parse(mut args: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut data_dir = None;
        let mut env_config = None;
        let mut game_bind = None;
        let mut relay_bind = None;
        let mut relay_endpoint = None;
        let mut relay_names = Vec::new();
        while let Some(flag) = args.next() {
            let value = args
                .next()
                .ok_or_else(|| format!("{flag} needs a value\nusage: {USAGE}"))?;
            match flag.as_str() {
                "--data-dir" => data_dir = Some(PathBuf::from(value)),
                "--env-config" => env_config = Some(PathBuf::from(value)),
                "--game-bind" => {
                    game_bind = Some(value.parse().map_err(|e| format!("--game-bind: {e}"))?)
                }
                "--relay-bind" => {
                    relay_bind = Some(value.parse().map_err(|e| format!("--relay-bind: {e}"))?)
                }
                "--relay-endpoint" => relay_endpoint = Some(value),
                "--relay-name" => relay_names.push(value),
                other => return Err(format!("unknown flag {other}\nusage: {USAGE}")),
            }
        }
        let need = |what: &str| format!("{what} is required\nusage: {USAGE}");
        let game_bind: SocketAddr = game_bind.ok_or_else(|| need("--game-bind"))?;
        if !game_bind.ip().is_loopback() {
            return Err(format!(
                "--game-bind {game_bind} is not a loopback address: the ingress acts for this \
                 account, and only the application on this host may reach it"
            ));
        }
        let relay_endpoint: String = relay_endpoint.ok_or_else(|| need("--relay-endpoint"))?;
        dsm_sdk::sdk::connect::code::check_endpoint(&relay_endpoint)
            .map_err(|e| format!("--relay-endpoint: {e}"))?;
        Ok(Self {
            data_dir: data_dir.ok_or_else(|| need("--data-dir"))?,
            env_config: env_config.ok_or_else(|| need("--env-config"))?,
            game_bind,
            relay_bind: relay_bind.ok_or_else(|| need("--relay-bind"))?,
            relay_endpoint,
            relay_names,
        })
    }
}

fn main() -> Result<(), String> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse(std::env::args().skip(1))?;
    std::fs::create_dir_all(&args.data_dir)
        .map_err(|e| format!("{}: {e}", args.data_dir.display()))?;

    // The SDK first, on this thread: its dispatchers block on the SDK's own
    // runtime, so they never run inside the host's.
    identity::start_sdk(&args)?;
    let host = identity::ensure_identity(&args)?;
    let relay_tls = tls::load_or_make(&args.data_dir, &args.relay_names)?;
    log::info!(
        "[host] on the pinned set; relay {} (certificate pin {})",
        args.relay_endpoint,
        dsm_sdk::util::text_id::encode_base32_crockford(&relay_tls.pin)
    );

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("dsm-app-host")
        .build()
        .map_err(|e| format!("the host runtime: {e}"))?;
    runtime.block_on(serve(args, host, relay_tls))
}

/// Worker threads in front of the SDK's ingress, and the calls that may wait
/// for one.
const SDK_WORKERS: usize = 16;
const SDK_QUEUED: usize = 256;

/// Where this launch's ingress secret is written, readable by the operator
/// alone: the application reads it and sends it with every call.
pub const INGRESS_TOKEN: &str = "ingress-token";

/// A new secret for this launch, written to `<data-dir>/ingress-token` at
/// mode 0600 in place of the last launch's.
fn new_ingress_secret(data_dir: &std::path::Path) -> Result<String, String> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    let raw = dsm::crypto::rng::generate_secure_random(32)
        .map_err(|e| format!("the ingress secret: {e}"))?;
    let secret = dsm_sdk::util::text_id::encode_base32_crockford(&raw);
    let path = data_dir.join(INGRESS_TOKEN);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("{}: {e}", path.display())),
    }
    let mut file =
        std::fs::File::create_new(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    file.write_all(secret.as_bytes())
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(secret)
}

async fn serve(
    args: Args,
    host: identity::Account,
    relay_tls: tls::RelayTls,
) -> Result<(), String> {
    dsm_sdk::sdk::tls_transport_sdk::ensure_rustls_crypto_provider();
    // The outcome programs this account's verifiers run (SoFi Amendment
    // S22), registered once each reproduces its conformance vectors: it reads
    // a computed match's cells itself, never on a wallet's word.
    let refused = dsm_sdk::sdk::outcome_programs::init();
    if !refused.is_empty() {
        return Err(format!(
            "{} outcome program(s) failed their conformance vectors; this host would establish \
             no computed match",
            refused.len()
        ));
    }
    // A call that walks a lineage waits on storage-node reads for seconds; the
    // cheap calls (a status not answered yet, the session listing) must not
    // queue behind a few of those.
    let sdk = dispatch::Sdk::start(SDK_WORKERS, SDK_QUEUED)?;
    let record = Arc::new(activity::Record::new(host.clone()));
    sdk.record_into(record.clone())?;
    let requests_changed = Arc::new(tokio::sync::Notify::new());

    // Payments reach this account through its inbox; the poller takes them in.
    let poller = sdk
        .call(dispatch::Call::invoke("inbox.startPoller", Vec::new()))
        .await?;
    if let Err(e) = dispatch::ok_bytes(poller.response) {
        return Err(format!("starting the inbox poller: {e}"));
    }

    let state = game::State {
        sdk: sdk.clone(),
        record: record.clone(),
        requests_changed: requests_changed.clone(),
        relay_endpoint: args.relay_endpoint.clone(),
        relay_pin: relay_tls.pin,
    };
    let relay_state = relay::State {
        sdk,
        record,
        requests_changed,
    };

    let secret = new_ingress_secret(&args.data_dir)?;
    let game_listener = tokio::net::TcpListener::bind(args.game_bind)
        .await
        .map_err(|e| format!("binding the game ingress at {}: {e}", args.game_bind))?;
    log::info!(
        "[host] game ingress on http://{}; its secret for this launch is in {}",
        args.game_bind,
        args.data_dir.join(INGRESS_TOKEN).display()
    );
    let game_server = axum::serve(
        game_listener,
        game::router(state, game::Caller::new(&secret, args.game_bind)).into_make_service(),
    );

    let config = axum_server::tls_rustls::RustlsConfig::from_der(
        vec![relay_tls.cert_der.clone()],
        relay_tls.key_der.clone(),
    )
    .await
    .map_err(|e| format!("the relay's TLS identity: {e}"))?;
    // Tokio's listener, handed over as the server takes it: already in the
    // non-blocking mode the server needs.
    let relay_listener = tokio::net::TcpListener::bind(args.relay_bind)
        .await
        .map_err(|e| format!("binding the relay at {}: {e}", args.relay_bind))?
        .into_std()
        .map_err(|e| format!("the relay's listener: {e}"))?;
    log::info!("[host] relay on {}", args.relay_bind);
    let relay_server = relay::serve(relay_listener, config, relay_state, relay::Bounds::DEPLOYED);

    tokio::select! {
        served = game_server => served.map_err(|e| format!("the game ingress stopped: {e}")),
        served = relay_server => served.map_err(|e| format!("the relay stopped: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Result<Args, String> {
        Args::parse(list.iter().map(|s| s.to_string()))
    }

    #[test]
    fn the_relay_endpoint_must_be_an_https_origin() {
        let base = [
            "--data-dir",
            "/tmp/x",
            "--env-config",
            "/tmp/x.toml",
            "--game-bind",
            "127.0.0.1:8787",
            "--relay-bind",
            "0.0.0.0:8443",
        ];
        let mut ok = base.to_vec();
        ok.extend(["--relay-endpoint", "https://192.168.1.5:8443"]);
        let parsed = args(&ok).map_err(|e| e.to_string());
        assert_eq!(
            parsed.map(|a| a.relay_endpoint),
            Ok("https://192.168.1.5:8443".to_string())
        );
        let mut plain = base.to_vec();
        plain.extend(["--relay-endpoint", "http://192.168.1.5:8443"]);
        args(&plain)
            .map(|a| a.relay_endpoint)
            .expect_err("a cleartext relay");
        args(&base)
            .map(|a| a.relay_endpoint)
            .expect_err("no relay endpoint");
    }

    /// The ingress acts for this account, so it listens where only this
    /// host reaches it: a loopback address is taken, any other refused.
    #[test]
    fn the_game_ingress_binds_a_loopback_address_only() {
        let with = |bind: &str| {
            args(&[
                "--data-dir",
                "/tmp/x",
                "--env-config",
                "/tmp/x.toml",
                "--game-bind",
                bind,
                "--relay-bind",
                "0.0.0.0:8443",
                "--relay-endpoint",
                "https://192.168.1.5:8443",
            ])
        };
        for loopback in ["127.0.0.1:8787", "[::1]:8787"] {
            let parsed = with(loopback).map(|a| a.game_bind.to_string());
            assert_eq!(parsed, Ok(loopback.to_string()));
        }
        for reachable in ["0.0.0.0:8787", "192.168.1.5:8787", "[::]:8787"] {
            let err = with(reachable)
                .map(|a| a.game_bind)
                .expect_err("an ingress other machines can reach");
            assert!(err.contains("loopback"), "{err}");
        }
    }
}
