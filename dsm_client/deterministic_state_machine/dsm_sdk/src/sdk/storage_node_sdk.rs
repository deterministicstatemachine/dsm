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

/// Read the env config and every CA certificate it names. A config that
/// cannot be read or parsed, or that names a certificate that cannot be read,
/// is an error: a client built without a certificate the config requires
/// cannot reach the members that use it. With no env config there is no CA,
/// and [`member_client`] builds no client from no CA.
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
    // An absent key names no CA, and no member can then be known by its
    // certificate; a key that is present but not a list of paths is a
    // malformed config, not an empty one.
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

/// How long a member has to accept a connection.
const MEMBER_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long one request to a member may take, end to end. A member that
/// accepts a connection and never answers is then a member that did not
/// answer, which every flow already handles, rather than a write that hangs
/// with no error. A transport bound only: nothing in DSM's validity or
/// ordering reads it.
const MEMBER_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// A member is reached only over `https://`: its identity is the
/// certificate it presents, and plain HTTP presents none.
pub fn require_https(endpoint: &str) -> Result<(), DsmError> {
    match endpoint.split_once("://") {
        Some((scheme, _)) if scheme.eq_ignore_ascii_case("https") => Ok(()),
        _ => Err(ca_error(format!(
            "storage member endpoint {endpoint} is not https://: a member is known by its \
             certificate, and plain HTTP presents none"
        ))),
    }
}

/// Accepts a member's certificate only when it chains to one of the CAs the
/// env config names AND names the member, as a DNS name among its subject
/// alternative names, whatever address the member was dialled at. A member
/// signs nothing (storage spec §2), so the certificate is the only thing that
/// says which member answered; a certificate for another member of the same
/// set, at this member's address, is refused.
#[derive(Debug)]
struct NamesTheMember {
    chain: std::sync::Arc<rustls::client::WebPkiServerVerifier>,
    member: rustls::pki_types::ServerName<'static>,
}

impl rustls::client::danger::ServerCertVerifier for NamesTheMember {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _dialled: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.chain
            .verify_server_cert(end_entity, intermediates, &self.member, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.chain.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.chain.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.chain.supported_verify_schemes()
    }
}

/// The client for `member_id`, built from resolved material: it trusts the
/// CAs the material holds and nothing else (no system store), and accepts
/// only a certificate that names `member_id`.
fn build_member_client(
    material: &CaMaterial,
    member_id: &str,
) -> Result<reqwest::Client, DsmError> {
    use rustls::pki_types::pem::PemObject;
    if material.certs.is_empty() {
        return Err(ca_error(
            "storage client: the env config names no CA (`custom_ca_certs`), so no member \
             can be known by its certificate"
                .to_string(),
        ));
    }
    let mut roots = rustls::RootCertStore::empty();
    for (cert_path, bytes) in &material.certs {
        let mut held = 0usize;
        for cert in rustls::pki_types::CertificateDer::pem_slice_iter(bytes) {
            let cert = cert.map_err(|e| {
                ca_error(format!(
                    "storage client: CA certificate {}: {e}",
                    cert_path.display()
                ))
            })?;
            roots.add(cert).map_err(|e| {
                ca_error(format!(
                    "storage client: CA certificate {}: {e}",
                    cert_path.display()
                ))
            })?;
            held += 1;
        }
        if held == 0 {
            return Err(ca_error(format!(
                "storage client: {} holds no certificate",
                cert_path.display()
            )));
        }
    }
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let chain = rustls::client::WebPkiServerVerifier::builder_with_provider(
        std::sync::Arc::new(roots),
        provider.clone(),
    )
    .build()
    .map_err(|e| ca_error(format!("storage client: {e}")))?;
    let member = rustls::pki_types::ServerName::try_from(member_id.to_string()).map_err(|e| {
        ca_error(format!(
            "storage member id {member_id} is not a name a certificate can carry: {e}"
        ))
    })?;
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| ca_error(format!("storage client: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(NamesTheMember { chain, member }))
        .with_no_client_auth();
    // HTTP/2 where the member offers it (the node's listener does): every
    // request to a member rides one connection, so a sync that reads many
    // routes at once pays one handshake per member, not one per request.
    // HTTP/1.1 stays for a member that does not offer HTTP/2.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    reqwest::Client::builder()
        .user_agent("DSM-SDK/1.0")
        .connect_timeout(MEMBER_CONNECT_TIMEOUT)
        .timeout(MEMBER_REQUEST_TIMEOUT)
        .use_preconfigured_tls(config)
        .build()
        .map_err(|e| ca_error(format!("storage client: {e}")))
}

/// The HTTP client for the member `member_id`, reached at `endpoint`: over
/// `https://` only, trusting only the CAs the env config names, and accepting
/// only a certificate that names `member_id`. The material is re-read on
/// every call, so a re-pointed config or a replaced certificate takes effect;
/// each member's client is built once per material and shared.
pub fn member_client(member_id: &str, endpoint: &str) -> Result<reqwest::Client, DsmError> {
    require_https(endpoint)?;
    let material = resolve_ca_material()?;
    let mut slot = MEMBER_CLIENTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((cached, clients)) = slot.as_ref() {
        if let Some(client) = clients.get(member_id).filter(|_| *cached == material) {
            return Ok(client.clone());
        }
    }
    let client = build_member_client(&material, member_id)?;
    match slot.as_mut() {
        Some((cached, clients)) if *cached == material => {
            clients.insert(member_id.to_string(), client.clone());
        }
        _ => {
            let clients = MemberClients::from([(member_id.to_string(), client.clone())]);
            *slot = Some((material, clients));
        }
    }
    Ok(client)
}

type MemberClients = std::collections::HashMap<String, reqwest::Client>;

static MEMBER_CLIENTS: std::sync::Mutex<Option<(CaMaterial, MemberClients)>> =
    std::sync::Mutex::new(None);

// ── One member ──────────────────────────────────────────────────────────────

/// One member of a committed set, reached at the endpoint the set names.
#[derive(Debug, Clone)]
pub struct MemberClient {
    member_id: String,
    endpoint: String,
    client: reqwest::Client,
}

/// `error` and every error under it, outermost first: a transport error's
/// own text says only that a request failed, and the reason (a refused
/// certificate, a reset connection) is underneath it.
fn with_causes(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut cause = error.source();
    while let Some(under) = cause {
        text.push_str(": ");
        text.push_str(&under.to_string());
        cause = under.source();
    }
    text
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
        .map_err(|e| format!("transport: {}", with_causes(&e)))?;
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

/// The header every member answers with: the member id it is configured as
/// (§14 mirror sync). Identity, not authentication.
const ECHO_HEADER: &str = "x-dsm-node-id";

/// What a member answered when asked for its latest ByteCommit (§14). An
/// observation, never a verdict (§4): nothing here was checked against a
/// mirror or a predecessor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LatestByteCommit {
    /// `200`: the member's latest ByteCommit, as it stated it. It names this
    /// member; a ByteCommit naming another member is `Unanswered`.
    Stated(ByteCommit),
    /// `204`: the member states it has closed no cycle yet.
    NoCycle,
    /// Why there is no ByteCommit of this member's to show.
    Unanswered(String),
}

/// A member's answer to `bytecommit/latest`, with the member id the node
/// that answered echoed, when it echoed one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatestByteCommitRead {
    pub answer: LatestByteCommit,
    pub answered_as: Option<Vec<u8>>,
}

impl MemberClient {
    /// The member `member_id` at `endpoint`, reached with a client that
    /// accepts only `member_id`'s certificate ([`member_client`]). The client
    /// is built here, from the member id, so a member's name and the identity
    /// its connection checks cannot disagree.
    pub fn new(member_id: &str, endpoint: &str) -> Result<Self, DsmError> {
        Ok(Self {
            member_id: member_id.to_string(),
            endpoint: endpoint.trim_end_matches('/').to_string(),
            client: member_client(member_id, endpoint)?,
        })
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

    /// The member's latest ByteCommit, as it states it (§14).
    pub async fn latest_bytecommit(&self) -> LatestByteCommitRead {
        let response = match self
            .client
            .get(format!("{}/api/v2/bytecommit/latest", self.endpoint))
            .send()
            .await
        {
            Ok(response) => response,
            Err(e) => {
                return LatestByteCommitRead {
                    answer: LatestByteCommit::Unanswered(format!("transport: {}", with_causes(&e))),
                    answered_as: None,
                }
            }
        };
        let answered_as = response
            .headers()
            .get(ECHO_HEADER)
            .map(|v| v.as_bytes().to_vec());
        let answer = match response.status().as_u16() {
            200 => match response.bytes().await {
                Ok(body) => match proto::ByteCommitV4::decode(body.as_ref())
                    .ok()
                    .and_then(|p| ByteCommit::from_proto(&p))
                {
                    Some(commit) if commit.member_id == self.member_id.as_bytes() => {
                        LatestByteCommit::Stated(commit)
                    }
                    Some(commit) => LatestByteCommit::Unanswered(format!(
                        "answered with a ByteCommit naming {}",
                        String::from_utf8_lossy(&commit.member_id)
                    )),
                    None => LatestByteCommit::Unanswered(
                        "answered with bytes that are not a ByteCommit".to_string(),
                    ),
                },
                Err(e) => LatestByteCommit::Unanswered(format!("reading the answer: {e}")),
            },
            204 => LatestByteCommit::NoCycle,
            status => LatestByteCommit::Unanswered(format!("answered HTTP {status}")),
        };
        LatestByteCommitRead {
            answer,
            answered_as,
        }
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
        Ok(Self {
            members: set
                .members()
                .iter()
                .map(|m| MemberClient::new(&m.member_id, &m.endpoint))
                .collect::<Result<_, DsmError>>()?,
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

    // Every set-wide call asks all members at once and keeps their answers
    // in member order: a phone pays one network latency for the set, not
    // one per member, and nothing a member answers changes.

    /// Put an immutable object at every member. Returns how many members
    /// took it; `Stored` is Core's reading of the members afterwards, never
    /// this count.
    pub async fn put_immutable(&self, namespace: TaggedHashDomain<'_>, payload: &[u8]) -> u32 {
        let answers = futures::future::join_all(
            self.members
                .iter()
                .map(|member| member.put_immutable(namespace, payload)),
        )
        .await;
        let mut took = 0u32;
        for (member, answer) in self.members.iter().zip(answers) {
            match answer {
                Ok(()) => took += 1,
                Err(e) => log::warn!("immutable put: {} did not take it: {e}", member.member_id),
            }
        }
        took
    }

    /// What every member answered at `addr`, in member order.
    pub async fn get_immutable(&self, addr: &[u8; 32]) -> Vec<ObjectRead> {
        futures::future::join_all(self.members.iter().map(|member| member.get_immutable(addr)))
            .await
    }

    /// The first bytes a member answers that re-hash to `addr` under the
    /// namespace they came with. The content address is the check: a member
    /// can fail to serve an object, never substitute one, so whichever
    /// member's bytes verify first are the object's bytes, and the answers
    /// still on their way are not waited for. Every member is asked at once.
    /// `None` when no member holds such bytes.
    pub async fn fetch_verified(&self, addr: &[u8; 32]) -> Option<Vec<u8>> {
        let mut answers: futures::stream::FuturesUnordered<_> = self
            .members
            .iter()
            .map(|member| async move { (member, member.get_immutable(addr).await) })
            .collect();
        while let Some((member, read)) = futures::StreamExt::next(&mut answers).await {
            let ObjectRead::Bytes { namespace, payload } = read else {
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
        let answers = futures::future::join_all(
            self.members
                .iter()
                .map(|member| member.append_index(namespace, locator, addr)),
        )
        .await;
        let mut took = 0u32;
        for (member, answer) in self.members.iter().zip(answers) {
            match answer {
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
        // Each member's pages follow one another; the members are read at once.
        futures::future::join_all(self.members.iter().map(|member| async move {
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
            answered.then_some(addrs)
        }))
        .await
    }

    /// Put `value` at a cell at every member, each put its own transaction.
    /// For cells whose objects prove themselves and are not raced (the
    /// device directory); a cell that is raced is written along its route
    /// (`sdk::route_seats`). Returns how many members took it.
    pub async fn put_cell(&self, namespace: &[u8], key: &[u8; 32], value: &[u8]) -> u32 {
        let entry = [(namespace.to_vec(), *key, value.to_vec())];
        let answers =
            futures::future::join_all(self.members.iter().map(|member| member.put_cells(&entry)))
                .await;
        let mut took = 0u32;
        for (member, answer) in self.members.iter().zip(answers) {
            match answer {
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
        futures::future::join_all(
            self.members
                .iter()
                .map(|member| member.get_cell(namespace, key)),
        )
        .await
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::{build_member_client, read_ca_certs, CaMaterial, LatestByteCommit, MemberClient};

    /// The env config the app bundles names the CA bundled beside it, and the
    /// storage client builds from that CA through the same reader and builder
    /// every client is made by. (Which CA issued the fleet's certificates is
    /// not decidable offline; a device run against the fleet is what shows the
    /// bundled CA verifies them.)
    #[test]
    fn the_bundled_env_config_names_a_ca_the_storage_client_builds_from() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../frontend/public/dsm_env_config.toml"
        );
        let certs = read_ca_certs(path).expect("the bundled CA is named and readable");
        assert_eq!(certs.len(), 1, "exactly the fleet's CA");
        assert!(certs[0].0.ends_with("ca.crt"));
        build_member_client(
            &CaMaterial {
                env_path: Some(path.to_string()),
                certs,
            },
            "dsm-node-1",
        )
        .expect("the storage client builds from the bundled CA");
    }

    /// A relay in front of one member: it holds the first connection it
    /// accepts until every relay of the set holds one, then carries the bytes
    /// both ways. A client that asked the members one at a time would wait at
    /// the first relay for ever; one that asks them at once is answered.
    async fn relay(
        scheme: &str,
        target: String,
        all_in: std::sync::Arc<tokio::sync::Barrier>,
    ) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a relay port");
        let port = listener.local_addr().expect("its address").port();
        tokio::spawn(async move {
            let mut gate = Some(all_in);
            loop {
                let (mut inbound, ..) = listener.accept().await.expect("the relay accepts");
                let held = gate.take();
                let target = target.clone();
                tokio::spawn(async move {
                    if let Some(held) = held {
                        held.wait().await;
                    }
                    let mut outbound = tokio::net::TcpStream::connect(&target)
                        .await
                        .expect("the relay reaches its member");
                    // The connection ends when either side closes it.
                    if let Err(e) = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await
                    {
                        log::debug!("relay: {e}");
                    }
                });
            }
        });
        format!("{scheme}://127.0.0.1:{port}")
    }

    /// `set` with every member reached through its own [`relay`], all held
    /// until each has a connection.
    async fn relayed(
        set: &crate::sdk::storage_set::StorageSet,
    ) -> crate::sdk::storage_set::StorageSet {
        let all_in = std::sync::Arc::new(tokio::sync::Barrier::new(set.members().len()));
        let mut members = Vec::new();
        for member in set.members() {
            let (scheme, target) = member
                .endpoint
                .split_once("://")
                .expect("an endpoint names its scheme");
            members.push(crate::sdk::storage_set::StorageMember {
                endpoint: relay(scheme, target.to_string(), all_in.clone()).await,
                ..member.clone()
            });
        }
        crate::sdk::storage_set::StorageSet::new(members).expect("the relayed set")
    }

    /// A set-wide read or write asks every member at once. On the rig a
    /// trade's settle spent most of its minute fetching objects member after
    /// member: five round trips per object over a phone's network. Each
    /// member here sits behind a relay that answers only once every member
    /// has been asked, so a client that waits for one member before asking
    /// the next is never answered. The object put directly is read through
    /// the relays from every member, and a put through them is taken by every
    /// member. On the storage node's own app, on Postgres.
    #[test]
    #[serial_test::serial]
    fn a_set_asks_every_member_at_once() {
        let _fleet = crate::test_support::one_device::Fleet::start();
        let set = crate::sdk::storage_set::canonical_set(crate::economic_fixtures::NETWORK)
            .expect("the pinned set");
        let ns = dsm::crypto::domain::TaggedHashDomain::try_new(b"DSM/test/every-member-at-once")
            .expect("a domain");
        let everyone = set.members().len();
        crate::runtime::get_runtime().block_on(async {
            let direct = super::SetClient::new(&set).expect("a client");
            assert_eq!(
                direct.put_immutable(ns, b"held by every member").await as usize,
                everyone
            );
            let addr = dsm::storage_object::immutable_addr(ns, b"held by every member");

            let reads = super::SetClient::new(&relayed(&set).await)
                .expect("a client")
                .get_immutable(&addr)
                .await;
            assert_eq!(
                reads
                    .iter()
                    .filter(|read| matches!(read, super::ObjectRead::Bytes { .. }))
                    .count(),
                everyone,
                "every member answered the read, each asked while the others were"
            );
            let took = super::SetClient::new(&relayed(&set).await)
                .expect("a client")
                .put_immutable(ns, b"put through the relays")
                .await;
            assert_eq!(
                took as usize, everyone,
                "every member took the put, each asked while the others were"
            );
        });
    }

    /// A relay in front of one member that carries nothing until `opened`
    /// has a permit, then carries every connection both ways.
    async fn relay_after(
        scheme: &str,
        target: String,
        opened: std::sync::Arc<tokio::sync::Semaphore>,
    ) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a relay port");
        let port = listener.local_addr().expect("its address").port();
        tokio::spawn(async move {
            loop {
                let (mut inbound, ..) = listener.accept().await.expect("the relay accepts");
                let (target, opened) = (target.clone(), opened.clone());
                tokio::spawn(async move {
                    drop(opened.acquire().await.expect("the relay is opened"));
                    let mut outbound = tokio::net::TcpStream::connect(&target)
                        .await
                        .expect("the relay reaches its member");
                    if let Err(e) = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await
                    {
                        log::debug!("relay: {e}");
                    }
                });
            }
        });
        format!("{scheme}://127.0.0.1:{port}")
    }

    /// A member that answers the first request it is sent at once, whatever
    /// was asked, with `payload` under `namespace`, and then opens `opened`.
    /// It serves `tls`, a certificate naming the member it stands in for, so
    /// a device reaches it as it reaches that member.
    async fn substituting(
        tls: axum_server::tls_rustls::RustlsConfig,
        namespace: &'static [u8],
        payload: &'static [u8],
        opened: std::sync::Arc<tokio::sync::Semaphore>,
    ) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a member port");
        let port = listener.local_addr().expect("its address").port();
        let acceptor = tokio_rustls::TlsAcceptor::from(tls.get_inner());
        tokio::spawn(async move {
            let (inbound, ..) = listener.accept().await.expect("the member accepts");
            let mut inbound = acceptor.accept(inbound).await.expect("the TLS handshake");
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.windows(4).any(|end| end == b"\r\n\r\n") {
                let read = inbound.read(&mut chunk).await.expect("the request");
                assert!(read > 0, "the request ended before its head did");
                request.extend_from_slice(&chunk[..read]);
            }
            let head = format!(
                "HTTP/1.1 200 OK\r\nx-namespace: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                String::from_utf8_lossy(namespace),
                payload.len()
            );
            inbound
                .write_all(head.as_bytes())
                .await
                .expect("the answer's head");
            inbound.write_all(payload).await.expect("the answer");
            inbound.flush().await.expect("the answer sent");
            opened.add_permits(1);
        });
        format!("https://127.0.0.1:{port}")
    }

    /// A fetch keeps the first bytes that re-hash to the address, not the
    /// first answer. Here every member holds the object, but the first
    /// member is replaced by one that answers at once with other bytes under
    /// the object's namespace, and every other member is reached only after
    /// it has answered: its bytes always arrive first. They are passed over,
    /// and the object fetched is the one the members hold. On the storage
    /// node's own app, on Postgres.
    #[test]
    #[serial_test::serial]
    fn a_fetch_passes_over_a_member_that_answers_first_with_other_bytes() {
        let fleet = crate::test_support::one_device::Fleet::start();
        let set = crate::sdk::storage_set::canonical_set(crate::economic_fixtures::NETWORK)
            .expect("the pinned set");
        const NAMESPACE: &[u8] = b"DSM/test/first-bytes-that-verify";
        let ns = dsm::crypto::domain::TaggedHashDomain::try_new(NAMESPACE).expect("a domain");
        crate::runtime::get_runtime().block_on(async {
            let direct = super::SetClient::new(&set).expect("a client");
            assert_eq!(
                direct.put_immutable(ns, b"the object").await as usize,
                set.members().len()
            );
            let addr = dsm::storage_object::immutable_addr(ns, b"the object");

            let opened = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
            let mut members = Vec::new();
            for (position, member) in set.members().iter().enumerate() {
                let (scheme, target) = member
                    .endpoint
                    .split_once("://")
                    .expect("an endpoint names its scheme");
                let endpoint = if position == 0 {
                    let tls = fleet.tls_for(&member.member_id).await;
                    substituting(tls, NAMESPACE, b"other bytes", opened.clone()).await
                } else {
                    relay_after(scheme, target.to_string(), opened.clone()).await
                };
                members.push(crate::sdk::storage_set::StorageMember {
                    endpoint,
                    ..member.clone()
                });
            }
            let substituted = crate::sdk::storage_set::StorageSet::new(members).expect("the set");
            let fetched = super::SetClient::new(&substituted)
                .expect("a client")
                .fetch_verified(&addr)
                .await;
            assert_eq!(
                fetched.as_deref(),
                Some(&b"the object"[..]),
                "the bytes that verify, not the first answer"
            );
        });
    }

    /// A write the member did not take is not acknowledged. The same running
    /// node, reached at a path it does not serve, answers `404`: the put, the
    /// index append and the mirror sync are errors, never acknowledgements,
    /// and there is no ByteCommit of its to show. Reached at its real path,
    /// every one is taken. On the storage node's own app, on Postgres.
    #[test]
    #[serial_test::serial]
    fn a_member_that_answers_404_took_nothing() {
        let fleet = crate::test_support::one_device::Fleet::start();
        let endpoint = fleet.endpoints()[0].clone();
        let ns = dsm::crypto::domain::TaggedHashDomain::try_new(b"DSM/test/404-is-not-an-answer")
            .expect("a domain");
        crate::runtime::get_runtime().block_on(async {
            let wrong = MemberClient::new("dsm-node-1", &format!("{endpoint}/not-the-api"))
                .expect("a client");
            assert!(wrong.put_immutable(ns, b"bytes").await.is_err());
            assert!(wrong
                .append_index(b"DSM/test/index", &[0x41; 32], &[0x42; 32])
                .await
                .is_err());
            assert!(wrong.sync_mirror().await.is_err());
            assert_eq!(
                wrong.latest_bytecommit().await.answer,
                LatestByteCommit::Unanswered("answered HTTP 404".to_string())
            );

            let right = MemberClient::new("dsm-node-1", &endpoint).expect("a client");
            right
                .put_immutable(ns, b"bytes")
                .await
                .expect("the put is taken");
            right
                .append_index(b"DSM/test/index", &[0x41; 32], &[0x42; 32])
                .await
                .expect("the append is taken");
            assert_eq!(
                right.latest_bytecommit().await.answer,
                LatestByteCommit::NoCycle,
                "no cell entry has arrived, so no cycle has closed"
            );
        });
    }

    /// A member's latest ByteCommit is shown only as that member's own. The
    /// member states "no cycle" until one closes, then the ByteCommit it
    /// closed; the node that answers echoes the member id it is configured
    /// as. Reached as ANOTHER member, at this node's address, nothing is
    /// read at all: the node's certificate names the member it is, and a
    /// client for another member refuses it before any request is sent. On
    /// the storage node's own app, on Postgres.
    #[test]
    #[serial_test::serial]
    fn a_members_latest_bytecommit_is_its_own_or_there_is_none() {
        let fleet = crate::test_support::one_device::Fleet::start();
        let endpoint = fleet.endpoints()[0].clone();
        crate::runtime::get_runtime().block_on(async {
            let member = MemberClient::new("dsm-node-1", &endpoint).expect("a client");
            let before = member.latest_bytecommit().await;
            assert_eq!(before.answer, LatestByteCommit::NoCycle);
            assert_eq!(before.answered_as.as_deref(), Some(&b"dsm-node-1"[..]));

            member
                .put_cells(&[(
                    b"DSM/test/latest-bytecommit".to_vec(),
                    [0x51; 32],
                    b"value".to_vec(),
                )])
                .await
                .expect("the entry is taken");
            let cycle = member.close_cycle().await.expect("the cycle closes");

            let after = member.latest_bytecommit().await;
            let LatestByteCommit::Stated(commit) = after.answer else {
                panic!(
                    "the member states the ByteCommit it closed: {:?}",
                    after.answer
                );
            };
            assert_eq!(commit.member_id, b"dsm-node-1");
            assert_eq!(commit.cycle_index, cycle);
            assert_eq!(after.answered_as.as_deref(), Some(&b"dsm-node-1"[..]));

            let misnamed = MemberClient::new("dsm-node-2", &endpoint).expect("a client");
            let read = misnamed.latest_bytecommit().await;
            let LatestByteCommit::Unanswered(why) = &read.answer else {
                panic!(
                    "dsm-node-1's node answered a client for dsm-node-2: {:?}",
                    read.answer
                );
            };
            assert!(
                why.contains("certificate not valid for name \"dsm-node-2\""),
                "the connection is refused because the certificate names another member: {why}"
            );
            assert_eq!(read.answered_as, None, "nothing was read from the node");
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

    /// An absent `custom_ca_certs` names no CA; a present one is a list of
    /// readable certificate paths or the config is malformed — a scalar, a
    /// table, a non-string entry or an unreadable file is an error, never
    /// "no certificates".
    /// A member is known only by a certificate from a CA the env config
    /// names, so no client is built from no CA (the system store is never
    /// trusted in its place), nor from a named file that holds no
    /// certificate, nor for a member id no certificate can carry.
    #[test]
    fn no_client_is_built_without_a_named_ca_or_for_an_unnameable_member() {
        let none = CaMaterial {
            env_path: None,
            certs: Vec::new(),
        };
        let refused = build_member_client(&none, "dsm-node-1").unwrap_err();
        assert!(refused.to_string().contains("names no CA"), "{refused}");

        let not_pem = CaMaterial {
            env_path: None,
            certs: vec![(std::path::PathBuf::from("root.pem"), b"PEM".to_vec())],
        };
        let refused = build_member_client(&not_pem, "dsm-node-1").unwrap_err();
        assert!(
            refused.to_string().contains("holds no certificate"),
            "{refused}"
        );

        let ca = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("a CA")
            .cert
            .pem()
            .into_bytes();
        let named = CaMaterial {
            env_path: None,
            certs: vec![(std::path::PathBuf::from("ca.pem"), ca)],
        };
        build_member_client(&named, "dsm-node-1").expect("a client for a nameable member");
        let refused = build_member_client(&named, "not a name").unwrap_err();
        assert!(
            refused
                .to_string()
                .contains("not a name a certificate can carry"),
            "{refused}"
        );
    }

    /// Only `https://` reaches a member: a plain or schemeless endpoint gets
    /// no client at all.
    #[test]
    fn a_member_endpoint_that_is_not_https_gets_no_client() {
        for endpoint in ["http://127.0.0.1:8080", "127.0.0.1:8080"] {
            let refused = super::member_client("dsm-node-1", endpoint).unwrap_err();
            assert!(
                refused.to_string().contains("not https://"),
                "{endpoint}: {refused}"
            );
        }
    }

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
