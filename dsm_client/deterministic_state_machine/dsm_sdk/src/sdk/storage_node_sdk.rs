// SPDX-License-Identifier: MIT OR Apache-2.0

//! The storage operations of a committed set's members (storage spec Part
//! II): immutable objects (§5), keyed cells (§6), indexes (§7), and the
//! ByteCommit reads route chains need (§14).
//!
//! Bytes in, bytes out. A member holds no key, checks no writer, and decides
//! nothing, so nothing here authenticates to a member or counts what members
//! answered. Every storage fact — `Stored`, `LeaderHeld`, `Final` — is Core's,
//! derived from the raw answers these calls return.

use dsm::crypto::domain::TaggedHashDomain;
use dsm::sofi::storage::ObjectRead;
use dsm::storage_cell::{ArrivalRecord, ByteCommit, CellCommitProof};
use dsm::types::error::DsmError;
use dsm::types::proto;
use prost::Message;
use reqwest::header::HeaderValue;

use crate::sdk::storage_set::StorageSet;
use crate::util::text_id::encode_base32_crockford;

// ── The HTTP client ─────────────────────────────────────────────────────────

/// The CA material a storage client is built from: the resolved env-config
/// path and the bytes of every PEM it names, in order. Two calls that resolve
/// the same material get the same client; a re-pointed config or a replaced
/// certificate produces different material and so a fresh build.
#[derive(Clone, PartialEq, Eq, Debug)]
struct CaMaterial {
    env_path: Option<String>,
    certs: Vec<(std::path::PathBuf, Vec<u8>)>,
}

fn ca_error(what: String) -> DsmError {
    DsmError::storage(what, None::<std::io::Error>)
}

/// Read the env config and every CA certificate it names. With no env config
/// the client trusts the system store only. A config that exists but cannot
/// be read or parsed, or that names a certificate that cannot be read, is an
/// error: a client built without a certificate the config requires cannot
/// reach the members that use it.
fn resolve_ca_material() -> Result<CaMaterial, DsmError> {
    let env_path = crate::network::resolved_env_config_path();
    let Some(path) = env_path.as_ref() else {
        return Ok(CaMaterial {
            env_path,
            certs: Vec::new(),
        });
    };
    let certs = read_ca_certs(path)?;
    Ok(CaMaterial { env_path, certs })
}

/// Every CA certificate the env config at `path` names, read from disk.
fn read_ca_certs(path: &str) -> Result<Vec<(std::path::PathBuf, Vec<u8>)>, DsmError> {
    let config_dir = std::path::Path::new(path)
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let text = std::fs::read_to_string(path)
        .map_err(|e| ca_error(format!("storage client: env config {path}: {e}")))?;
    let config: toml::Value = toml::from_str(&text)
        .map_err(|e| ca_error(format!("storage client: env config {path}: {e}")))?;
    let mut certs = Vec::new();
    // An absent key trusts the system store only; a key that is present but
    // not a list of paths is a malformed config, not an empty one.
    let entries = match config.get("custom_ca_certs") {
        None => None,
        Some(value) => Some(value.as_array().ok_or_else(|| {
            ca_error(format!(
                "storage client: {path}: custom_ca_certs is not a list of certificate paths"
            ))
        })?),
    };
    if let Some(entries) = entries {
        for entry in entries {
            let named = entry.as_str().ok_or_else(|| {
                ca_error(format!(
                    "storage client: {path}: custom_ca_certs holds a non-string entry"
                ))
            })?;
            let cert_path = if std::path::Path::new(named).is_absolute() {
                std::path::PathBuf::from(named)
            } else {
                config_dir.join(named)
            };
            let bytes = std::fs::read(&cert_path).map_err(|e| {
                ca_error(format!(
                    "storage client: CA certificate {}: {e}",
                    cert_path.display()
                ))
            })?;
            certs.push((cert_path, bytes));
        }
    }
    Ok(certs)
}

/// Build a client from resolved material: the expensive step (TLS
/// configuration, connection pool), run only when the material changes.
fn build_client_from(material: &CaMaterial) -> Result<reqwest::Client, DsmError> {
    let mut builder = reqwest::Client::builder().user_agent("DSM-SDK/1.0");
    for (cert_path, bytes) in &material.certs {
        let cert = reqwest::Certificate::from_pem(bytes).map_err(|e| {
            ca_error(format!(
                "storage client: CA certificate {}: {e}",
                cert_path.display()
            ))
        })?;
        builder = builder.add_root_certificate(cert);
    }
    let client = builder
        .build()
        .map_err(|e| ca_error(format!("storage client: {e}")))?;
    CA_CERTS_LOADED.store(
        u32::try_from(material.certs.len()).unwrap_or(u32::MAX),
        std::sync::atomic::Ordering::SeqCst,
    );
    CA_AWARE_CLIENT_BUILDS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    Ok(client)
}

/// The HTTP client for storage members, one per CA material. The material is
/// re-read on every call, so a re-pointed config or a replaced certificate
/// takes effect; the client itself is built once per material and shared.
pub fn build_ca_aware_client() -> Result<reqwest::Client, DsmError> {
    let material = resolve_ca_material()?;
    let mut slot = CA_AWARE_CLIENT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((cached, client)) = slot.as_ref() {
        if *cached == material {
            return Ok(client.clone());
        }
    }
    let client = build_client_from(&material)?;
    *slot = Some((material, client.clone()));
    Ok(client)
}

static CA_AWARE_CLIENT: std::sync::Mutex<Option<(CaMaterial, reqwest::Client)>> =
    std::sync::Mutex::new(None);

static CA_AWARE_CLIENT_BUILDS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

static CA_CERTS_LOADED: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// How many clients were built rather than handed back from the cache.
pub fn ca_aware_client_builds() -> u64 {
    CA_AWARE_CLIENT_BUILDS.load(std::sync::atomic::Ordering::SeqCst)
}

/// How many CA certificates the current client trusts beyond the system
/// store.
pub fn ca_certs_loaded_count() -> u32 {
    CA_CERTS_LOADED.load(std::sync::atomic::Ordering::SeqCst)
}

// ── One member ──────────────────────────────────────────────────────────────

/// One member of a committed set, reached at the endpoint the set names.
#[derive(Debug, Clone)]
pub struct MemberClient {
    member_id: String,
    endpoint: String,
    client: reqwest::Client,
}

/// A member's answer: `Ok(Some)` for a `200`/`201` body, `Ok(None)` for `204`
/// (the member answered with nothing), `Err` for anything else. A `404` is not
/// an answer: no route of the member's answers it on success, so it means a
/// wrong path or a member without the route, and reading it as an
/// acknowledgement would count a write that never happened (storage spec §4:
/// nothing a member returns is a verdict, and a fact that is not established
/// is never read as its opposite).
async fn answer(request: reqwest::RequestBuilder) -> Result<Option<Vec<u8>>, String> {
    let response = request
        .send()
        .await
        .map_err(|e| format!("transport: {e}"))?;
    match response.status().as_u16() {
        200 | 201 => response
            .bytes()
            .await
            .map(|b| Some(b.to_vec()))
            .map_err(|e| format!("reading the answer: {e}")),
        204 => Ok(None),
        status => Err(format!("answered HTTP {status}")),
    }
}

fn namespace_header(namespace: &[u8]) -> Result<HeaderValue, String> {
    HeaderValue::from_bytes(namespace).map_err(|e| format!("namespace: {e}"))
}

impl MemberClient {
    pub fn new(member_id: &str, endpoint: &str, client: reqwest::Client) -> Self {
        Self {
            member_id: member_id.to_string(),
            endpoint: endpoint.trim_end_matches('/').to_string(),
            client,
        }
    }

    pub fn member_id(&self) -> &str {
        &self.member_id
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Put an immutable object (§5). The member computes the address; the
    /// address this client computed travels as a check the member applies.
    pub async fn put_immutable(
        &self,
        namespace: TaggedHashDomain<'_>,
        payload: &[u8],
    ) -> Result<(), String> {
        let addr = dsm::storage_object::immutable_addr(namespace, payload);
        answer(
            self.client
                .post(format!("{}/api/v2/immutable/put", self.endpoint))
                .header("x-namespace", namespace_header(namespace.source_bytes())?)
                .header("x-expected-addr", encode_base32_crockford(&addr))
                .body(payload.to_vec()),
        )
        .await
        .map(|body| {
            log::debug!(
                "immutable put at {}: {} bytes answered",
                self.member_id,
                body.map_or(0, |b| b.len())
            )
        })
    }

    /// The `(namespace, payload)` the member holds at `addr`, untrusted until
    /// the caller re-hashes it to `addr`.
    pub async fn get_immutable(&self, addr: &[u8; 32]) -> ObjectRead {
        let response = match self
            .client
            .get(format!(
                "{}/api/v2/immutable/{}",
                self.endpoint,
                encode_base32_crockford(addr)
            ))
            .send()
            .await
        {
            Ok(response) => response,
            Err(e) => {
                log::debug!("immutable get at {}: {e}", self.member_id);
                return ObjectRead::Unavailable;
            }
        };
        match response.status().as_u16() {
            200 => {}
            404 => return ObjectRead::Absent,
            status => {
                log::debug!("immutable get at {}: HTTP {status}", self.member_id);
                return ObjectRead::Unavailable;
            }
        }
        let Some(namespace) = response
            .headers()
            .get("x-namespace")
            .map(|v| v.as_bytes().to_vec())
        else {
            return ObjectRead::Unavailable;
        };
        match response.bytes().await {
            Ok(payload) => ObjectRead::Bytes {
                namespace,
                payload: payload.to_vec(),
            },
            Err(e) => {
                log::debug!("immutable get at {}: {e}", self.member_id);
                ObjectRead::Unavailable
            }
        }
    }

    /// Append `addr` under `locator` (§7).
    pub async fn append_index(
        &self,
        namespace: &[u8],
        locator: &[u8; 32],
        addr: &[u8; 32],
    ) -> Result<(), String> {
        answer(
            self.client
                .post(format!(
                    "{}/api/v2/index/{}",
                    self.endpoint,
                    encode_base32_crockford(locator)
                ))
                .header("x-namespace", namespace_header(namespace)?)
                .body(addr.to_vec()),
        )
        .await
        .map(|body| {
            log::debug!(
                "index append at {}: {} bytes answered",
                self.member_id,
                body.map_or(0, |b| b.len())
            )
        })
    }

    /// One page of the addresses under `locator` after sequence `after`, in
    /// append order. `None` when the member did not answer.
    pub async fn read_index(
        &self,
        namespace: &[u8],
        locator: &[u8; 32],
        after: i64,
        limit: i64,
    ) -> Option<Vec<proto::IndexEntryV1>> {
        let body = answer(
            self.client
                .get(format!(
                    "{}/api/v2/index/{}?after={after}&limit={limit}",
                    self.endpoint,
                    encode_base32_crockford(locator)
                ))
                .header("x-namespace", namespace_header(namespace).ok()?),
        )
        .await
        .ok()??;
        Some(proto::IndexPageV1::decode(body.as_slice()).ok()?.entries)
    }

    /// Put entries in one local transaction at the member, all or none (§6).
    /// One arrival record per entry, in order, each checked to name this
    /// member and its entry's cell.
    pub async fn put_cells(
        &self,
        entries: &[(Vec<u8>, [u8; 32], Vec<u8>)],
    ) -> Result<Vec<ArrivalRecord>, String> {
        let batch = proto::CellPutsV1 {
            entries: entries
                .iter()
                .map(|(namespace, key, value)| proto::CellPutV1 {
                    namespace: namespace.clone(),
                    key: key.to_vec(),
                    value: value.clone(),
                })
                .collect(),
        };
        let body = answer(
            self.client
                .post(format!("{}/api/v2/cells", self.endpoint))
                .body(batch.encode_to_vec()),
        )
        .await?
        .ok_or("cells put: answered with no arrival records")?;
        let page = proto::ArrivalRecordsV1::decode(body.as_slice())
            .map_err(|e| format!("cells put: {e}"))?;
        if page.records.len() != entries.len() {
            return Err(format!(
                "cells put: {} arrival records for {} entries",
                page.records.len(),
                entries.len()
            ));
        }
        page.records
            .iter()
            .zip(entries)
            .map(|(record, (namespace, key, value))| {
                let record = ArrivalRecord::from_proto(record)
                    .ok_or("cells put: a malformed arrival record")?;
                if record.member_id != self.member_id.as_bytes()
                    || record.namespace != *namespace
                    || record.key != *key
                {
                    return Err(format!(
                        "cells put: the record for a {}-byte entry names another member or cell",
                        value.len()
                    ));
                }
                Ok(record)
            })
            .collect()
    }

    /// Everything the member holds at the cell, in arrival order. `None` when
    /// the member did not answer; an empty list is an answer.
    pub async fn get_cell(&self, namespace: &[u8], key: &[u8; 32]) -> Option<Vec<Vec<u8>>> {
        let body = answer(
            self.client
                .get(format!(
                    "{}/api/v2/cell/{}",
                    self.endpoint,
                    encode_base32_crockford(key)
                ))
                .header("x-namespace", namespace_header(namespace).ok()?),
        )
        .await
        .ok()??;
        Some(proto::CellValuesV1::decode(body.as_slice()).ok()?.values)
    }

    /// Close a ByteCommit cycle over what arrived since the last one and
    /// return the cycle of the member's latest ByteCommit, as the member
    /// states it (§14 closing).
    pub async fn close_cycle(&self) -> Option<u64> {
        let body = answer(
            self.client
                .post(format!("{}/api/v2/bytecommit/close", self.endpoint)),
        )
        .await
        .ok()??;
        let commit = ByteCommit::from_proto(&proto::ByteCommitV4::decode(body.as_slice()).ok()?)?;
        (commit.member_id == self.member_id.as_bytes()).then_some(commit.cycle_index)
    }

    /// Ask the member to fetch its set-mates' new ByteCommits into its mirror
    /// (§14 mirror sync). The member answers `204 No Content` once every
    /// set-mate answered; anything else is why its mirror is not current.
    pub async fn sync_mirror(&self) -> Result<(), String> {
        match answer(
            self.client
                .post(format!("{}/api/v2/bytecommit/mirror/sync", self.endpoint)),
        )
        .await?
        {
            None => Ok(()),
            Some(body) => Err(format!(
                "mirror sync at {} answered {} bytes where no content is the answer",
                self.member_id,
                body.len()
            )),
        }
    }

    /// Every distinct ByteCommit this member's mirror holds for `member` at
    /// `cycle`. `None` when the member did not answer.
    pub async fn mirrored(&self, member: &[u8], cycle: u64) -> Option<Vec<ByteCommit>> {
        let body = answer(self.client.get(format!(
            "{}/api/v2/bytecommit/mirror/{}/{cycle}",
            self.endpoint,
            encode_base32_crockford(member)
        )))
        .await
        .ok()??;
        proto::ByteCommitsV4::decode(body.as_slice())
            .ok()?
            .commits
            .iter()
            .map(ByteCommit::from_proto)
            .collect()
    }

    /// The member's proof that its ByteCommit at `cycle` commits the cell's
    /// latest entry as of that cycle.
    pub async fn proof(
        &self,
        namespace: &[u8],
        key: &[u8; 32],
        cycle: u64,
    ) -> Option<CellCommitProof> {
        let body = answer(
            self.client
                .get(format!(
                    "{}/api/v2/bytecommit/proof/{}",
                    self.endpoint,
                    encode_base32_crockford(key)
                ))
                .header("x-namespace", namespace_header(namespace).ok()?)
                .header("x-cycle", cycle.to_string()),
        )
        .await
        .ok()??;
        CellCommitProof::from_proto(&proto::CellCommitProofV1::decode(body.as_slice()).ok()?)
    }

    /// Whether the member answers its health route.
    pub async fn check_health(&self) -> Result<(), String> {
        answer(self.client.get(format!("{}/api/v2/health", self.endpoint)))
            .await
            .map(|body| {
                log::debug!(
                    "health at {}: {} bytes answered",
                    self.member_id,
                    body.map_or(0, |b| b.len())
                )
            })
    }
}

// ── A committed set ─────────────────────────────────────────────────────────

/// Every member of one committed set, in the set's member order.
#[derive(Debug, Clone)]
pub struct SetClient {
    members: Vec<MemberClient>,
}

impl SetClient {
    pub fn new(set: &StorageSet) -> Result<Self, DsmError> {
        let client = build_ca_aware_client()?;
        Ok(Self {
            members: set
                .members()
                .iter()
                .map(|m| MemberClient::new(&m.member_id, &m.endpoint, client.clone()))
                .collect(),
        })
    }

    pub fn members(&self) -> &[MemberClient] {
        &self.members
    }

    /// The member with this id, if the set has it.
    pub fn member(&self, member_id: &[u8]) -> Option<&MemberClient> {
        self.members
            .iter()
            .find(|m| m.member_id.as_bytes() == member_id)
    }

    /// Put an immutable object at every member. Returns how many members
    /// took it; `Stored` is Core's reading of the members afterwards, never
    /// this count.
    pub async fn put_immutable(&self, namespace: TaggedHashDomain<'_>, payload: &[u8]) -> u32 {
        let mut took = 0u32;
        for member in &self.members {
            match member.put_immutable(namespace, payload).await {
                Ok(()) => took += 1,
                Err(e) => log::warn!("immutable put: {} did not take it: {e}", member.member_id),
            }
        }
        took
    }

    /// What every member answered at `addr`, in member order.
    pub async fn get_immutable(&self, addr: &[u8; 32]) -> Vec<ObjectRead> {
        let mut reads = Vec::with_capacity(self.members.len());
        for member in &self.members {
            reads.push(member.get_immutable(addr).await);
        }
        reads
    }

    /// The first member's bytes that re-hash to `addr` under the namespace
    /// they came with. The content address is the check: a member can fail
    /// to serve an object, never substitute one. `None` when no member holds
    /// such bytes.
    pub async fn fetch_verified(&self, addr: &[u8; 32]) -> Option<Vec<u8>> {
        for member in &self.members {
            let ObjectRead::Bytes { namespace, payload } = member.get_immutable(addr).await else {
                continue;
            };
            let Ok(domain) = TaggedHashDomain::try_new(&namespace) else {
                log::warn!(
                    "immutable get at {}: a namespace that is not a domain",
                    member.member_id
                );
                continue;
            };
            if dsm::storage_object::immutable_addr(domain, &payload) == *addr {
                return Some(payload);
            }
            log::warn!(
                "immutable get at {}: bytes that do not hash to the address",
                member.member_id
            );
        }
        None
    }

    /// Append `addr` under `locator` at every member. Returns how many took
    /// it.
    pub async fn append_index(&self, namespace: &[u8], locator: &[u8; 32], addr: &[u8; 32]) -> u32 {
        let mut took = 0u32;
        for member in &self.members {
            match member.append_index(namespace, locator, addr).await {
                Ok(()) => took += 1,
                Err(e) => log::warn!("index append: {} did not take it: {e}", member.member_id),
            }
        }
        took
    }

    /// Every member's addresses under `locator`, in append order, paged
    /// until the member's index ends or `max_per_member` were read; `None`
    /// where a member did not answer.
    pub async fn read_index(
        &self,
        namespace: &[u8],
        locator: &[u8; 32],
        max_per_member: usize,
    ) -> Vec<Option<Vec<[u8; 32]>>> {
        const PAGE: i64 = 256;
        let mut reads = Vec::with_capacity(self.members.len());
        for member in &self.members {
            let mut addrs: Vec<[u8; 32]> = Vec::new();
            let mut after = 0i64;
            let mut answered = false;
            while let Some(page) = member.read_index(namespace, locator, after, PAGE).await {
                answered = true;
                let full = page.len() == PAGE as usize;
                for entry in page {
                    match <[u8; 32]>::try_from(entry.addr.as_slice()) {
                        Ok(addr) => addrs.push(addr),
                        Err(e) => log::warn!(
                            "index read at {}: an entry that is not an address: {e}",
                            member.member_id
                        ),
                    }
                    after = after.max(entry.seq);
                }
                if !full || addrs.len() >= max_per_member {
                    break;
                }
            }
            reads.push(answered.then_some(addrs));
        }
        reads
    }

    /// Put `value` at a cell at every member, each put its own transaction.
    /// For cells whose objects prove themselves and are not raced (the
    /// device directory); a cell that is raced is written along its route
    /// (`sdk::route_seats`). Returns how many members took it.
    pub async fn put_cell(&self, namespace: &[u8], key: &[u8; 32], value: &[u8]) -> u32 {
        let entry = [(namespace.to_vec(), *key, value.to_vec())];
        let mut took = 0u32;
        for member in &self.members {
            match member.put_cells(&entry).await {
                Ok(records) => {
                    log::debug!(
                        "cell put at {}: {} arrival record",
                        member.member_id,
                        records.len()
                    );
                    took += 1;
                }
                Err(e) => log::warn!("cell put: {} did not take it: {e}", member.member_id),
            }
        }
        took
    }

    /// Everything every member holds at a cell, in member order; `None`
    /// where a member did not answer.
    pub async fn get_cell(&self, namespace: &[u8], key: &[u8; 32]) -> Vec<Option<Vec<Vec<u8>>>> {
        let mut reads = Vec::with_capacity(self.members.len());
        for member in &self.members {
            reads.push(member.get_cell(namespace, key).await);
        }
        reads
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::{build_ca_aware_client, read_ca_certs, MemberClient};

    /// A write the member did not take is not acknowledged. The same running
    /// node, reached at a path it does not serve, answers `404`: the put, the
    /// index append, the mirror sync and the health check are all errors,
    /// never acknowledgements. Reached at its real path, every one is taken.
    /// On the storage node's own app, on Postgres.
    #[test]
    #[serial_test::serial]
    fn a_member_that_answers_404_took_nothing() {
        let fleet = crate::test_support::one_device::Fleet::start();
        let endpoint = fleet.endpoints()[0].clone();
        let client = build_ca_aware_client().expect("a client");
        let ns = dsm::crypto::domain::TaggedHashDomain::try_new(b"DSM/test/404-is-not-an-answer")
            .expect("a domain");
        crate::runtime::get_runtime().block_on(async {
            let wrong = MemberClient::new(
                "dsm-node-1",
                &format!("{endpoint}/not-the-api"),
                client.clone(),
            );
            assert!(wrong.put_immutable(ns, b"bytes").await.is_err());
            assert!(wrong
                .append_index(b"DSM/test/index", &[0x41; 32], &[0x42; 32])
                .await
                .is_err());
            assert!(wrong.sync_mirror().await.is_err());
            assert!(wrong.check_health().await.is_err());

            let right = MemberClient::new("dsm-node-1", &endpoint, client);
            right
                .put_immutable(ns, b"bytes")
                .await
                .expect("the put is taken");
            right
                .append_index(b"DSM/test/index", &[0x41; 32], &[0x42; 32])
                .await
                .expect("the append is taken");
            right.check_health().await.expect("the member is healthy");
        });
    }

    fn config(body: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("root.pem"), b"PEM").expect("pem");
        let path = dir.path().join("env.toml");
        std::fs::write(&path, body).expect("config");
        let path = path.to_string_lossy().into_owned();
        (dir, path)
    }

    /// An absent `custom_ca_certs` trusts the system store only; a present one
    /// is a list of readable certificate paths or the config is malformed —
    /// a scalar, a table, a non-string entry or an unreadable file is an
    /// error, never "no certificates".
    #[test]
    fn custom_ca_certs_is_a_list_of_readable_paths_or_an_error() {
        let (_d, path) = config("network_id = \"x\"\n");
        assert!(read_ca_certs(&path).expect("absent key").is_empty());

        let (_d, path) = config("custom_ca_certs = [\"root.pem\"]\n");
        let certs = read_ca_certs(&path).expect("a list of paths");
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].1, b"PEM");

        for malformed in [
            "custom_ca_certs = \"root.pem\"\n",
            "[custom_ca_certs]\nfile = \"root.pem\"\n",
            "custom_ca_certs = [1]\n",
            "custom_ca_certs = [\"missing.pem\"]\n",
        ] {
            let (_d, path) = config(malformed);
            assert!(read_ca_certs(&path).is_err(), "{malformed}");
        }
    }
}
