// SPDX-License-Identifier: MIT OR Apache-2.0

//! `dsm-dev-net`: a developer's own storage set on one machine.
//!
//! The nodes are the network's pinned register members, one node each, as the
//! SDK's test harness runs them (`dsm_sdk/src/test_support/nodes.rs`): each on
//! a Postgres database of its own that already holds its member's pinned
//! register incarnation, as a node restored from its database does, served by
//! the storage node's own binary over TLS from a CA of this set's own, with a
//! certificate naming its member and the loopback address. Each member has a
//! CA of its own, as each operator of the public set does (owner, 2026-11-05),
//! and every member and device pins each member to its own CA. A device trusts
//! those CAs and nothing else, and reaches the set through the client config
//! this writes. Nothing here answers for a node: `scripts/dev_net.sh` starts
//! the real binary on each config.
//!
//! - `prepare --dir DIR --pg URL --first-port PORT`: every node's database
//!   (dropped and created), its incarnation, its certificate and its config,
//!   and the client config (`DIR/dsm_env_config.toml`, each member's CA
//!   inline, also kept as `DIR/<member>-ca.pem`). Refused when `DIR` already
//!   holds a set.
//! - `drop --pg URL`: every node's database, dropped.
//!
//! `URL` names the Postgres server's administrative database, e.g.
//! `postgresql://localhost:5432/postgres?sslmode=disable`.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use dsm::economic::register::{pinned_root_register_members, BETA_NETWORK_ID};
use dsm::utils::text_id::encode_base32_crockford;
use dsm_storage_node::db;

const USAGE: &str = "usage:\n  dsm-dev-net prepare --dir DIR --pg URL --first-port PORT\n  \
dsm-dev-net drop --pg URL";

/// What a command is started with.
enum Command {
    Prepare {
        dir: PathBuf,
        pg: String,
        first_port: u16,
    },
    Drop {
        pg: String,
    },
}

fn parse(mut args: impl Iterator<Item = String>) -> Result<Command, String> {
    let verb = args.next().ok_or_else(|| USAGE.to_string())?;
    let mut dir = None;
    let mut pg = None;
    let mut first_port = None;
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))?;
        match flag.as_str() {
            "--dir" => dir = Some(PathBuf::from(value)),
            "--pg" => pg = Some(value),
            "--first-port" => {
                first_port = Some(
                    value
                        .parse::<u16>()
                        .map_err(|e| format!("--first-port: {e}"))?,
                )
            }
            other => return Err(format!("unknown flag {other}\n{USAGE}")),
        }
    }
    let pg = pg.ok_or_else(|| format!("--pg is required\n{USAGE}"))?;
    match verb.as_str() {
        "prepare" => Ok(Command::Prepare {
            dir: dir.ok_or_else(|| format!("--dir is required\n{USAGE}"))?,
            pg,
            first_port: first_port.ok_or_else(|| format!("--first-port is required\n{USAGE}"))?,
        }),
        "drop" => Ok(Command::Drop { pg }),
        other => Err(format!("unknown command {other}\n{USAGE}")),
    }
}

/// One node of the set.
struct Member {
    id: String,
    host: std::net::IpAddr,
    incarnation: [u8; 32],
    port: u16,
    database: String,
}

impl Member {
    fn endpoint(&self) -> String {
        format!("https://{}:{}", self.host, self.port)
    }
}

/// The pinned members, each with its port and database.
fn members(first_port: u16) -> Result<Vec<Member>, String> {
    let pinned = pinned_root_register_members(BETA_NETWORK_ID)
        .map_err(|e| format!("the network's pinned register members: {e:?}"))?;
    let mut members = Vec::with_capacity(pinned.len());
    for (index, (id, incarnation)) in pinned.iter().enumerate() {
        let id = String::from_utf8(id.to_vec())
            .map_err(|e| format!("a pinned member id is not UTF-8: {e}"))?;
        let offset =
            u16::try_from(index).map_err(|e| format!("member {id} has no port offset: {e}"))?;
        let port = first_port
            .checked_add(offset)
            .ok_or_else(|| format!("member {id}'s port is past 65535"))?;
        members.push(Member {
            id,
            host: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            incarnation: *incarnation,
            port,
            database: format!("dsm_dev_node_{}", index + 1),
        });
    }
    Ok(members)
}

/// `url` with its database path replaced by `database`.
fn with_database(url: &str, database: &str) -> Result<String, String> {
    let (head, query) = match url.split_once('?') {
        Some((head, query)) => (head, Some(query)),
        None => (url, None),
    };
    let authority = head
        .find("://")
        .map(|scheme| scheme + 3)
        .ok_or_else(|| format!("{url} is not a postgresql:// URL"))?;
    let slash = head[authority..]
        .find('/')
        .map(|slash| authority + slash)
        .ok_or_else(|| {
            format!("{url} names no database: name the server's administrative one, e.g. /postgres")
        })?;
    Ok(match query {
        Some(query) => format!("{}/{database}?{query}", &head[..slash]),
        None => format!("{}/{database}", &head[..slash]),
    })
}

async fn admin_client(pg: &str) -> Result<db::DBPool, String> {
    db::create_pool(pg, 1).map_err(|e| format!("connect to {pg}: {e}"))
}

async fn drop_databases(pg: &str, members: &[Member]) -> Result<(), String> {
    let admin = admin_client(pg).await?;
    let client = admin
        .get()
        .await
        .map_err(|e| format!("a connection to {pg}: {e}"))?;
    for m in members {
        client
            .batch_execute(&format!(
                "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                m.database
            ))
            .await
            .map_err(|e| format!("drop {}: {e}", m.database))?;
    }
    Ok(())
}

/// Each node's database, created empty, its schema initialised by the node's
/// own code, holding its member's pinned incarnation and nothing else.
async fn prepare_databases(pg: &str, members: &[Member]) -> Result<(), String> {
    drop_databases(pg, members).await?;
    let admin = admin_client(pg).await?;
    let client = admin
        .get()
        .await
        .map_err(|e| format!("a connection to {pg}: {e}"))?;
    for m in members {
        client
            .batch_execute(&format!("CREATE DATABASE {}", m.database))
            .await
            .map_err(|e| format!("create {}: {e}", m.database))?;
        let url = with_database(pg, &m.database)?;
        let pool = db::create_pool(&url, 1).map_err(|e| format!("connect to {url}: {e}"))?;
        db::init_db(&pool)
            .await
            .map_err(|e| format!("{}: the node's schema: {e}", m.database))?;
        {
            // The pool holds one connection: this one goes back before the
            // incarnation is read through the node's own code.
            let node = pool
                .get()
                .await
                .map_err(|e| format!("a connection to {url}: {e}"))?;
            node.execute(
                "INSERT INTO register_incarnation (only_row, incarnation) VALUES (1, $1)",
                &[&m.incarnation.to_vec()],
            )
            .await
            .map_err(|e| format!("{}: put the pinned incarnation: {e}", m.database))?;
        }
        let held = db::register_incarnation(&pool)
            .await
            .map_err(|e| format!("{}: read the incarnation back: {e}", m.database))?;
        if held != m.incarnation {
            return Err(format!(
                "{}: the database holds incarnation {}, not {}'s pinned {}",
                m.database,
                encode_base32_crockford(&held),
                m.id,
                encode_base32_crockford(&m.incarnation)
            ));
        }
    }
    Ok(())
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|e| format!("write {}: {e}", path.display()))
}

/// Each member's own CA, and its certificate and key from that CA.
fn write_tls(dir: &Path, members: &[Member]) -> Result<(), String> {
    for m in members {
        let ca_key = rcgen::KeyPair::generate().map_err(|e| format!("{}'s CA key: {e}", m.id))?;
        let mut ca = rcgen::CertificateParams::new(Vec::<String>::new())
            .map_err(|e| format!("{}'s CA parameters: {e}", m.id))?;
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.distinguished_name.push(
            rcgen::DnType::CommonName,
            format!("DSM-Storage-CA {} (developer set)", m.id),
        );
        ca.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca_cert = ca
            .self_signed(&ca_key)
            .map_err(|e| format!("{}'s CA certificate: {e}", m.id))?;
        write(&ca_path(dir, m), ca_cert.pem().as_bytes())?;
        let issuer = rcgen::Issuer::new(ca, ca_key);
        let key = rcgen::KeyPair::generate().map_err(|e| format!("{}'s key: {e}", m.id))?;
        let mut params = rcgen::CertificateParams::new(vec![m.id.clone(), m.host.to_string()])
            .map_err(|e| format!("{}'s parameters: {e}", m.id))?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, m.id.as_str());
        let cert = params
            .signed_by(&key, &issuer)
            .map_err(|e| format!("{}'s certificate: {e}", m.id))?;
        write(&dir.join(format!("{}.crt", m.id)), cert.pem().as_bytes())?;
        write(
            &dir.join(format!("{}.key", m.id)),
            key.serialize_pem().as_bytes(),
        )?;
    }
    Ok(())
}

/// Where `m`'s own CA certificate is kept.
fn ca_path(dir: &Path, m: &Member) -> PathBuf {
    dir.join(format!("{}-ca.pem", m.id))
}

/// `m`'s own CA certificate, as the `ca_cert` its entries carry.
fn ca_cert(dir: &Path, m: &Member) -> Result<String, String> {
    let path = ca_path(dir, m);
    std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))
}

/// Each node's config: the binary's own, naming every member of the set.
fn write_node_configs(dir: &Path, pg: &str, members: &[Member]) -> Result<(), String> {
    let mut set = String::new();
    for m in members {
        writeln!(
            set,
            "\n[[storage_set.members]]\nid = \"{}\"\nregister_incarnation = \"{}\"\nendpoint = \"{}\"\nca_cert = \"\"\"\n{}\"\"\"",
            m.id,
            encode_base32_crockford(&m.incarnation),
            m.endpoint(),
            ca_cert(dir, m)?
        )
        .map_err(|e| format!("the set's members: {e}"))?;
    }
    for m in members {
        let config = format!(
            "# {id}: the storage node's own binary on this machine, one member of the\n\
             # developer's set (written by dsm-dev-net prepare).\n\n\
             [node]\nid = \"{id}\"\n\n\
             [network]\nlisten_addr = \"{host}\"\nport = {port}\n\n\
             [tls]\ncert_path = \"{cert}\"\nkey_path = \"{key}\"\n\n\
             [database]\nurl = \"{url}\"\n{set}",
            id = m.id,
            host = m.host,
            port = m.port,
            cert = dir.join(format!("{}.crt", m.id)).display(),
            key = dir.join(format!("{}.key", m.id)).display(),
            url = with_database(pg, &m.database)?,
        );
        write(&dir.join(format!("{}.toml", m.id)), config.as_bytes())?;
    }
    Ok(())
}

/// The client config a wallet or an application's account reaches the set
/// with: every member, its endpoint and incarnation, and its own CA.
fn write_client_config(dir: &Path, members: &[Member]) -> Result<(), String> {
    let loopback = members.iter().all(|m| m.host.is_loopback());
    let mut config = format!(
        "# The developer's own storage set on this machine (dsm-dev-net prepare).\n\
         allow_localhost = {loopback}\n\
         bitcoin_network = \"signet\"\n"
    );
    for m in members {
        writeln!(
            config,
            "\n[[nodes]]\nname = \"{}\"\nendpoint = \"{}\"\nregister_incarnation = \"{}\"\nca_cert = \"\"\"\n{}\"\"\"",
            m.id,
            m.endpoint(),
            encode_base32_crockford(&m.incarnation),
            ca_cert(dir, m)?
        )
        .map_err(|e| format!("the client config: {e}"))?;
    }
    write(&dir.join("dsm_env_config.toml"), config.as_bytes())
}

async fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Drop { pg } => {
            let members = members(1)?;
            drop_databases(&pg, &members).await?;
            println!("[dev-net] dropped every node's database");
            Ok(())
        }
        Command::Prepare {
            dir,
            pg,
            first_port,
        } => {
            if dir.join("dsm_env_config.toml").exists() {
                return Err(format!(
                    "{} already holds a set; `make nodes-reset` drops it",
                    dir.display()
                ));
            }
            std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
            let dir = dir
                .canonicalize()
                .map_err(|e| format!("{}: {e}", dir.display()))?;
            let members = members(first_port)?;
            prepare_databases(&pg, &members).await?;
            write_tls(&dir, &members)?;
            write_node_configs(&dir, &pg, &members)?;
            write_client_config(&dir, &members)?;
            for m in &members {
                println!(
                    "[dev-net] {} on {} (database {}, incarnation {})",
                    m.id,
                    m.endpoint(),
                    m.database,
                    encode_base32_crockford(&m.incarnation)
                );
            }
            println!(
                "[dev-net] client config: {}",
                dir.join("dsm_env_config.toml").display()
            );
            Ok(())
        }
    }
}

fn main() {
    let command = match parse(std::env::args().skip(1)) {
        Ok(command) => command,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("[dev-net] a runtime: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = runtime.block_on(run(command)) {
        eprintln!("[dev-net] {e}");
        std::process::exit(1);
    }
}
