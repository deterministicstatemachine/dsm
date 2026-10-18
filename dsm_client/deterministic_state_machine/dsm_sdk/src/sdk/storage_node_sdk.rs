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
use dsm::merkle::sparse_merkle_tree::SmtInclusionProof;
use dsm::sofi::storage::ObjectRead;
use dsm::storage_cell::{
    ArrivalRecord, ByteCommit, CellCommitProof, CELL_PAGE_VALUE_BYTES, CELL_TREE_DEPTH,
    MAX_CELL_PAGE_ENTRIES,
};
use dsm::storage_object::{MAX_IMMUTABLE_PAYLOAD_BYTES, MAX_INDEX_PAGE};
use dsm::types::error::DsmError;
use dsm::types::proto;
use prost::Message;
use reqwest::header::HeaderValue;

use crate::sdk::bounded_read::{self, Bound, Budget, Refused};
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

/// A file as it stood when it was read: its length and modification time.
/// A file whose stamp is unchanged is taken to hold what it held then.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Stamp {
    len: u64,
    modified: std::time::SystemTime,
}

fn stamp(path: &std::path::Path) -> Result<Stamp, DsmError> {
    let meta = std::fs::metadata(path)
        .map_err(|e| ca_error(format!("storage client: {}: {e}", path.display())))?;
    let modified = meta
        .modified()
        .map_err(|e| ca_error(format!("storage client: {}: {e}", path.display())))?;
    Ok(Stamp {
        len: meta.len(),
        modified,
    })
}

/// One env config's certificates as read: the config's stamp, and each
/// certificate's path, stamp and bytes.
struct CaRead {
    config: Stamp,
    certs: Vec<(std::path::PathBuf, Stamp, Vec<u8>)>,
}

impl CaRead {
    fn certs(&self) -> Vec<(std::path::PathBuf, Vec<u8>)> {
        self.certs
            .iter()
            .map(|(path, _, bytes)| (path.clone(), bytes.clone()))
            .collect()
    }
}

/// Every env config's certificates this process read, by the config's path.
/// Every storage call resolves its client's material, and reading and parsing
/// the config and each certificate from disk for every member of every call
/// is work that only repeats what was read: a config and its certificates
/// are read again once one of them is changed (its stamp differs), so a
/// re-pointed config or a replaced certificate still takes effect.
static CA_READS: std::sync::Mutex<std::collections::BTreeMap<String, CaRead>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

/// The certificates read from the config at `path`, when neither it nor any
/// of them changed since.
fn unchanged_ca_certs(
    path: &str,
    config: &Stamp,
) -> Result<Option<Vec<(std::path::PathBuf, Vec<u8>)>>, DsmError> {
    let reads = match CA_READS.lock() {
        Ok(reads) => reads,
        Err(poisoned) => poisoned.into_inner(),
    };
    let Some(read) = reads.get(path) else {
        return Ok(None);
    };
    if read.config != *config {
        return Ok(None);
    }
    for (cert_path, was, _) in &read.certs {
        if stamp(cert_path)? != *was {
            return Ok(None);
        }
    }
    Ok(Some(read.certs()))
}

/// Every CA certificate the env config at `path` names: as last read when
/// neither the config nor any certificate changed since, read from disk
/// otherwise.
fn read_ca_certs(path: &str) -> Result<Vec<(std::path::PathBuf, Vec<u8>)>, DsmError> {
    let config = stamp(std::path::Path::new(path))?;
    if let Some(certs) = unchanged_ca_certs(path, &config)? {
        return Ok(certs);
    }
    let read = CaRead {
        config,
        certs: read_ca_certs_from_disk(path)?,
    };
    let certs = read.certs();
    match CA_READS.lock() {
        Ok(mut reads) => reads.insert(path.to_string(), read),
        Err(poisoned) => poisoned.into_inner().insert(path.to_string(), read),
    };
    Ok(certs)
}

/// Every CA certificate the env config at `path` names, read from disk, each
/// stamped before it was read: a file changed while it was read is then read
/// again next time.
fn read_ca_certs_from_disk(
    path: &str,
) -> Result<Vec<(std::path::PathBuf, Stamp, Vec<u8>)>, DsmError> {
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
            let was = stamp(&cert_path)?;
            let bytes = std::fs::read(&cert_path).map_err(|e| {
                ca_error(format!(
                    "storage client: CA certificate {}: {e}",
                    cert_path.display()
                ))
            })?;
            certs.push((cert_path, was, bytes));
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
    // A redirect is not followed: it would carry the request to an address the
    // set does not name, perhaps over plain HTTP, and what answered there is
    // not this member. A member that redirects answered with its status.
    reqwest::Client::builder()
        .user_agent("DSM-SDK/1.0")
        .connect_timeout(MEMBER_CONNECT_TIMEOUT)
        .timeout(MEMBER_REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .use_preconfigured_tls(config)
        .build()
        .map_err(|e| ca_error(format!("storage client: {e}")))
}

/// The HTTP client for the member `member_id`, reached at `endpoint`: over
/// `https://` only, trusting only the CAs the env config names, and accepting
/// only a certificate that names `member_id`. The material is resolved on
/// every call, and read from disk again whenever the config or a certificate
/// changed ([`read_ca_certs`]), so a re-pointed config or a replaced
/// certificate takes effect; each member's client is built once per material
/// and shared.
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

/// A member's answer: `Ok(Some)` for a `200`/`201` body read within `bound`
/// ([`bounded_read`]), `Ok(None)` for `204` (the member answered with
/// nothing), `Err` for anything else. A `404` is not an answer: no route of
/// the member's answers it on success, so it means a wrong path or a member
/// without the route, and reading it as an acknowledgement would count a
/// write that never happened (storage spec §4: nothing a member returns is a
/// verdict, and a fact that is not established is never read as its
/// opposite). Nor is a body past its bound: it is refused whole.
async fn answer(request: reqwest::RequestBuilder, bound: Bound) -> Result<Option<Vec<u8>>, String> {
    let response = request
        .send()
        .await
        .map_err(|e| format!("transport: {}", with_causes(&e)))?;
    match response.status().as_u16() {
        200 | 201 => bounded_read::read(response, bound)
            .await
            .map(Some)
            .map_err(|e| format!("reading the answer: {e}")),
        204 => Ok(None),
        status => Err(format!("answered HTTP {status}")),
    }
}

// ── What a member's answers can hold ────────────────────────────────────────
//
// Each kind of answer a member gives is read within the most bytes an honest
// one holds, derived from the kind's own limits ([`Bound::Limit`]); a longer
// one is not an answer. Two kinds have no protocol bound and are read within
// this device's budgets instead ([`Bound::Budget`]).

/// The most an index page holds: [`MAX_INDEX_PAGE`] entries, each at the
/// largest sequence a member's index can hold and a 32-byte address.
fn index_page_limit() -> usize {
    proto::IndexPageV1 {
        entries: vec![
            proto::IndexEntryV1 {
                seq: i64::MAX,
                addr: vec![u8::MAX; 32],
            };
            MAX_INDEX_PAGE
        ],
    }
    .encoded_len()
}

/// The most a ByteCommit of `member_id` holds: every integer at its largest.
fn bytecommit_limit(member_id: &str) -> usize {
    proto::ByteCommitV4 {
        member_id: member_id.as_bytes().to_vec(),
        cycle_index: u64::MAX,
        smt_root: vec![u8::MAX; 32],
        bytes_used: u64::MAX,
        parent_digest: vec![u8::MAX; 32],
    }
    .encoded_len()
}

/// The most a cell's commitment proof holds: an inclusion proof with a value
/// and the full [`CELL_TREE_DEPTH`]-sibling path, at the largest index.
fn cell_proof_limit() -> usize {
    proto::CellCommitProofV1 {
        index: u64::MAX,
        running_hash: vec![u8::MAX; 32],
        smt_proof: SmtInclusionProof {
            key: [u8::MAX; 32],
            value: Some([u8::MAX; 32]),
            siblings: vec![[u8::MAX; 32]; CELL_TREE_DEPTH],
        }
        .to_bytes(),
    }
    .encoded_len()
}

/// The most one page of a cell read from `member_id` under `namespace`
/// holds (§6): [`CELL_PAGE_VALUE_BYTES`] of values over at most
/// [`MAX_CELL_PAGE_ENTRIES`] entries, each with its arrival record at the
/// largest index, and the next page's index.
fn cell_page_limit(member_id: &str, namespace: &[u8]) -> usize {
    use prost::encoding::encoded_len_varint;
    let record = proto::ArrivalRecordV1 {
        member_id: member_id.as_bytes().to_vec(),
        namespace: namespace.to_vec(),
        key: vec![u8::MAX; 32],
        index: u64::MAX,
        running_hash: vec![u8::MAX; 32],
    }
    .encoded_len();
    // A value's field key and length, at the largest length a value has.
    let value_framing = 1 + encoded_len_varint(CELL_PAGE_VALUE_BYTES as u64);
    let record_framing = 1 + encoded_len_varint(record as u64);
    CELL_PAGE_VALUE_BYTES
        + MAX_CELL_PAGE_ENTRIES * (value_framing + record_framing + record)
        + 1
        + encoded_len_varint(u64::MAX)
}

// A cell holds every value anyone put at it (§6). Each page of it is bounded
// by the protocol ([`cell_page_limit`]), and a reader reads page after page;
// how many pages a cell has, the protocol does not bound. A mirror holds every
// distinct ByteCommit a set-mate stated for one cycle (§14), unpaged and
// unbounded. These budgets are this device's resource limits for one whole
// cell and one mirror answer, not protocol rules: a read past one is refused
// as unread, never taken as absent, truncated, or invalid, and while an
// honest cell or mirror is larger than its budget that read is not available
// from that member.

/// One whole cell read from one member, over all its pages: about
/// twenty-five of the largest entries a cell takes. What its values hold may
/// cost five times the bytes: a cell of the smallest entries a member takes
/// costs about four.
const CELL_VALUES_BUDGET: Budget = Budget {
    bytes: 8 * 1024 * 1024,
    allocation: 40 * 1024 * 1024,
};

/// How long one member has to answer a whole cell, every page of it. A
/// member's pages cannot be held to a count (an honest cell of the smallest
/// entries fills [`CELL_VALUES_BUDGET`] over hundreds of full pages), so a
/// member answering each page just inside [`MEMBER_REQUEST_TIMEOUT`] held
/// every read of the cell for hours (SA-68). Like that timeout, a transport
/// bound only: a read past it is that member not answering, never a verdict.
const CELL_READ_DEADLINE: std::time::Duration = std::time::Duration::from_secs(120);

/// What a cell read has taken from one member so far, page by page, held to
/// [`CELL_VALUES_BUDGET`] for the whole cell.
#[derive(Debug, Default)]
struct CellRead {
    values: Vec<Vec<u8>>,
    /// The bytes of every page read.
    bytes: usize,
    /// What the values taken hold: their bytes, and each one's vector
    /// counted twice for the list that holds them as it grows.
    allocation: usize,
    /// The value bytes of the last page, when it named a next page while
    /// holding fewer entries than a page holds. A member ends a page short of
    /// [`MAX_CELL_PAGE_ENTRIES`] only where the next value would carry it past
    /// [`CELL_PAGE_VALUE_BYTES`], so the next page's first value must.
    short_page_bytes: Option<usize>,
}

impl CellRead {
    /// Take the page `body`, read from arrival index `from`, and return the
    /// index the next page starts at (0 when this page reaches the last
    /// entry). A page that holds more entries than a page holds, does not
    /// start where it was read from, runs its records out of step with its
    /// values, or names a next page anywhere but just past itself is not a
    /// page; reading past the budget is a resource limit.
    fn take(&mut self, from: u64, body: &[u8]) -> Result<u64, String> {
        for field in [1, 2] {
            bounded_read::at_most(body, field, MAX_CELL_PAGE_ENTRIES).map_err(|e| e.to_string())?;
        }
        self.bytes = self.bytes.saturating_add(body.len());
        if self.bytes > CELL_VALUES_BUDGET.bytes {
            return Err(Refused::OverByteBudget {
                budget: CELL_VALUES_BUDGET.bytes,
            }
            .to_string());
        }
        let page = proto::CellValuesV1::decode(body).map_err(|e| format!("not a page: {e}"))?;
        if page.records.len() != page.values.len() {
            return Err(format!(
                "a page of {} values and {} records",
                page.values.len(),
                page.records.len()
            ));
        }
        for (at, record) in (from..).zip(&page.records) {
            if record.index != at {
                return Err(format!(
                    "the page read from {from} holds index {} where {at} belongs",
                    record.index
                ));
            }
        }
        let past = from.saturating_add(page.values.len() as u64);
        if page.next != 0 && (page.values.is_empty() || page.next != past) {
            return Err(format!(
                "the page read from {from} holds {} entries and names {} as the next page",
                page.values.len(),
                page.next
            ));
        }
        // A page cut short is borne out by the value that did not fit: a
        // member that ends every page after one entry, to make a cell read
        // take hundreds of thousands of requests, is not answering (SA-68).
        if let Some(short) = self.short_page_bytes.take() {
            let fits = page
                .values
                .first()
                .is_none_or(|first| short.saturating_add(first.len()) <= CELL_PAGE_VALUE_BYTES);
            if fits {
                return Err(format!(
                    "the page before {from} ended short of a page with {short} bytes of values, \
                     and what follows it would have fit"
                ));
            }
        }
        if page.next != 0 && page.values.len() < MAX_CELL_PAGE_ENTRIES {
            self.short_page_bytes = Some(page.values.iter().map(Vec::len).sum());
        }
        for value in page.values {
            self.allocation = self
                .allocation
                .saturating_add(value.len())
                .saturating_add(2 * std::mem::size_of::<Vec<u8>>());
            if self.allocation > CELL_VALUES_BUDGET.allocation {
                return Err(Refused::OverAllocationBudget {
                    needed: self.allocation,
                    budget: CELL_VALUES_BUDGET.allocation,
                }
                .to_string());
            }
            self.values.push(value);
        }
        Ok(page.next)
    }
}

/// One mirror's answer for one member and cycle: thousands of ByteCommits,
/// where one is honest and two prove an equivocation. Decoding a ByteCommit
/// allocates about three times its bytes.
const MIRRORED_BUDGET: Budget = Budget {
    bytes: 1024 * 1024,
    allocation: 4 * 1024 * 1024,
};

/// The repeated field of `ByteCommitsV4`: its ByteCommits.
const MIRRORED_ELEMENTS: [(u32, usize); 1] = [(1, std::mem::size_of::<proto::ByteCommitV4>())];

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
        let addr =
            encode_base32_crockford(&dsm::storage_object::immutable_addr(namespace, payload));
        // The member answers with the address it computed, in Base32.
        let addr_limit = Bound::Limit(addr.len());
        answer(
            self.client
                .post(format!("{}/api/v2/immutable/put", self.endpoint))
                .header("x-namespace", namespace_header(namespace.source_bytes())?)
                .header("x-expected-addr", addr)
                .body(payload.to_vec()),
            addr_limit,
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
        match bounded_read::read(response, Bound::Limit(MAX_IMMUTABLE_PAYLOAD_BYTES)).await {
            Ok(payload) => ObjectRead::Bytes { namespace, payload },
            Err(e) => {
                log::warn!("immutable get at {}: {e}", self.member_id);
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
            // The member answers `204`, with nothing.
            Bound::Limit(0),
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
            Bound::Limit(index_page_limit()),
        )
        .await
        .ok()??;
        Some(proto::IndexPageV1::decode(body.as_slice()).ok()?.entries)
    }

    /// The addresses under `locator` from the start, page after page, until
    /// the index ends, `max` were read, or `pages` pages were. `None` unless
    /// every page was one an honest member gives: answered, no longer than a
    /// page, and holding only addresses, each at a sequence past the one
    /// before it. A member that answers otherwise did not answer, and what it
    /// sent before is not taken for its index. Every page read either ends
    /// the read or holds a full page of new addresses, so the read ends
    /// within `pages` pages whatever the member answers.
    pub async fn index(
        &self,
        namespace: &[u8],
        locator: &[u8; 32],
        max: usize,
        pages: usize,
    ) -> Option<Vec<[u8; 32]>> {
        let mut addrs: Vec<[u8; 32]> = Vec::new();
        let mut after = 0i64;
        for _ in 0..pages {
            let page = self
                .read_index(namespace, locator, after, MAX_INDEX_PAGE as i64)
                .await?;
            if page.len() > MAX_INDEX_PAGE {
                log::warn!(
                    "index read at {}: {} entries, more than a page holds",
                    self.member_id,
                    page.len()
                );
                return None;
            }
            let full = page.len() == MAX_INDEX_PAGE;
            for entry in page {
                if entry.seq <= after {
                    log::warn!(
                        "index read at {}: an entry at sequence {} after sequence {after}",
                        self.member_id,
                        entry.seq
                    );
                    return None;
                }
                after = entry.seq;
                match <[u8; 32]>::try_from(entry.addr.as_slice()) {
                    Ok(addr) => addrs.push(addr),
                    Err(e) => {
                        log::warn!(
                            "index read at {}: an entry that is not an address: {e}",
                            self.member_id
                        );
                        return None;
                    }
                }
            }
            if !full || addrs.len() >= max {
                break;
            }
        }
        Some(addrs)
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
        // One arrival record per entry, each naming this member and its entry's
        // cell, at the largest index.
        let records_limit = proto::ArrivalRecordsV1 {
            records: entries
                .iter()
                .map(|(namespace, key, _)| proto::ArrivalRecordV1 {
                    member_id: self.member_id.as_bytes().to_vec(),
                    namespace: namespace.clone(),
                    key: key.to_vec(),
                    index: u64::MAX,
                    running_hash: vec![u8::MAX; 32],
                })
                .collect(),
        }
        .encoded_len();
        let body = answer(
            self.client
                .post(format!("{}/api/v2/cells", self.endpoint))
                .body(batch.encode_to_vec()),
            Bound::Limit(records_limit),
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

    /// Everything the member holds at the cell, in arrival order, read page
    /// by page (§6). `None` when the member did not answer every page, or
    /// answered one that is not a page, or past this device's budget for a
    /// cell ([`CELL_VALUES_BUDGET`]); an empty list is an answer.
    pub async fn get_cell(&self, namespace: &[u8], key: &[u8; 32]) -> Option<Vec<Vec<u8>>> {
        match self.cell_values(namespace, key).await {
            Ok(values) => values,
            Err(why) => {
                log::warn!("cell get at {}: {why}", self.member_id);
                None
            }
        }
    }

    /// [`Self::get_cell`], with why the member's answer was not taken: every
    /// page within [`CELL_READ_DEADLINE`].
    async fn cell_values(
        &self,
        namespace: &[u8],
        key: &[u8; 32],
    ) -> Result<Option<Vec<Vec<u8>>>, String> {
        self.cell_values_within(namespace, key, CELL_READ_DEADLINE)
            .await
    }

    /// The pages of the cell, every one answered within `deadline` of the
    /// first request.
    async fn cell_values_within(
        &self,
        namespace: &[u8],
        key: &[u8; 32],
        deadline: std::time::Duration,
    ) -> Result<Option<Vec<Vec<u8>>>, String> {
        tokio::time::timeout(deadline, self.cell_pages(namespace, key))
            .await
            .map_err(|elapsed| {
                format!("the cell's pages took longer than {deadline:?} ({elapsed})")
            })?
    }

    /// Read the cell page by page from the first arrival index.
    async fn cell_pages(
        &self,
        namespace: &[u8],
        key: &[u8; 32],
    ) -> Result<Option<Vec<Vec<u8>>>, String> {
        let header = namespace_header(namespace)?;
        let page_limit = Bound::Limit(cell_page_limit(&self.member_id, namespace));
        let mut read = CellRead::default();
        let mut from = 1u64;
        loop {
            let request = self
                .client
                .get(format!(
                    "{}/api/v2/cell/{}?from={from}",
                    self.endpoint,
                    encode_base32_crockford(key)
                ))
                .header("x-namespace", header.clone());
            let Some(body) = answer(request, page_limit).await? else {
                return Ok(None);
            };
            match read.take(from, &body)? {
                0 => return Ok(Some(read.values)),
                next => from = next,
            }
        }
    }

    /// Close a ByteCommit cycle over what arrived since the last one and
    /// return the cycle of the member's latest ByteCommit, as the member
    /// states it (§14 closing).
    pub async fn close_cycle(&self) -> Option<u64> {
        let body = answer(
            self.client
                .post(format!("{}/api/v2/bytecommit/close", self.endpoint)),
            Bound::Limit(bytecommit_limit(&self.member_id)),
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
            // No content is the answer.
            Bound::Limit(0),
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
    /// `cycle`. `None` when the member did not answer, or answered past this
    /// device's budget for a mirror read ([`MIRRORED_BUDGET`]).
    pub async fn mirrored(&self, member: &[u8], cycle: u64) -> Option<Vec<ByteCommit>> {
        let request = self.client.get(format!(
            "{}/api/v2/bytecommit/mirror/{}/{cycle}",
            self.endpoint,
            encode_base32_crockford(member)
        ));
        let page = match answer(request, Bound::Budget(MIRRORED_BUDGET))
            .await
            .and_then(|body| {
                body.map(|body| {
                    bounded_read::decode_within::<proto::ByteCommitsV4>(
                        &body,
                        &MIRRORED_ELEMENTS,
                        MIRRORED_BUDGET,
                    )
                    .map_err(|e| e.to_string())
                })
                .transpose()
            }) {
            Ok(page) => page?,
            Err(why) => {
                log::warn!("mirror read at {}: {why}", self.member_id);
                return None;
            }
        };
        page.commits.iter().map(ByteCommit::from_proto).collect()
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
            Bound::Limit(cell_proof_limit()),
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
            200 => {
                match bounded_read::read(response, Bound::Limit(bytecommit_limit(&self.member_id)))
                    .await
                {
                    Ok(body) => match proto::ByteCommitV4::decode(body.as_slice())
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
                }
            }
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
    /// where a member did not answer whole ([`MemberClient::index`]).
    pub async fn read_index(
        &self,
        namespace: &[u8],
        locator: &[u8; 32],
        max_per_member: usize,
    ) -> Vec<Option<Vec<[u8; 32]>>> {
        // As many pages as `max_per_member` addresses fill, and one at least:
        // a member that was not asked has not answered.
        let pages = max_per_member.div_ceil(MAX_INDEX_PAGE).max(1);
        // Each member's pages follow one another; the members are read at once.
        futures::future::join_all(
            self.members
                .iter()
                .map(|member| member.index(namespace, locator, max_per_member, pages)),
        )
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

    /// A config and its certificates are read once while none of them
    /// changes: a certificate that can no longer be opened, but is unchanged,
    /// is not opened again, and every call resolves what was read. A
    /// replaced certificate is read again, and its new bytes are the
    /// material.
    #[cfg(unix)]
    #[test]
    fn unchanged_ca_material_is_not_read_again_and_a_replaced_one_is() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, path) = config("custom_ca_certs = [\"root.pem\"]\n");
        let pem = dir.path().join("root.pem");
        let first = read_ca_certs(&path).expect("the certificates");
        assert_eq!(first[0].1, b"PEM");

        std::fs::set_permissions(&pem, std::fs::Permissions::from_mode(0o000))
            .expect("the certificate made unreadable");
        let again = read_ca_certs(&path);
        std::fs::set_permissions(&pem, std::fs::Permissions::from_mode(0o644))
            .expect("the certificate readable again");
        assert_eq!(
            again.expect("an unchanged certificate is not opened again"),
            first
        );

        std::fs::write(&pem, b"REPLACED PEM").expect("the certificate replaced");
        let replaced = read_ca_certs(&path).expect("the certificates");
        assert_eq!(
            replaced[0].1, b"REPLACED PEM",
            "a replaced certificate is read again"
        );
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

    // ── Members this test stands up itself ────────────────────────────────
    //
    // Storage members are untrusted (storage spec §4): one member must not be
    // able to stop or exhaust a device that reads from it, whatever the other
    // members hold. Each member below is served at an address of its own with
    // a certificate naming it, from a CA the client trusts alone, and is
    // reached by the client every member is reached by
    // ([`build_member_client`]); it answers whatever its test has it answer.

    use super::{SetClient, CELL_VALUES_BUDGET, MIRRORED_BUDGET};
    use dsm::storage_cell::{CELL_PAGE_VALUE_BYTES, MAX_CELL_PAGE_ENTRIES};
    use crate::sdk::bounded_read::{self, Refused};
    use crate::test_support::nodes::TestCa;
    use dsm::crypto::domain::TaggedHashDomain;
    use dsm::sofi::storage::{ObjectRead, StoredFact};
    use dsm::storage_object::{immutable_addr, MAX_IMMUTABLE_PAYLOAD_BYTES, MAX_INDEX_PAGE};
    use dsm::types::proto;
    use prost::Message;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// Longer than any read below takes when its member is refused: a read
    /// that runs past it was waiting on the member.
    const PATIENCE: Duration = Duration::from_secs(20);

    /// `member_id`, served with `app` at an address of its own.
    async fn member_at(
        ca: &TestCa,
        member_id: &str,
        app: axum::Router,
    ) -> (MemberClient, axum_server::Handle<std::net::SocketAddr>) {
        crate::sdk::tls_transport_sdk::ensure_rustls_crypto_provider();
        let tls = ca.tls_for(member_id).await;
        let handle: axum_server::Handle<std::net::SocketAddr> = axum_server::Handle::new();
        let server = axum_server::bind_rustls("127.0.0.1:0".parse().expect("an address"), tls)
            .handle(handle.clone());
        tokio::spawn(async move { server.serve(app.into_make_service()).await });
        let addr = handle.listening().await.expect("the member listens");
        let material = CaMaterial {
            env_path: None,
            certs: vec![(std::path::PathBuf::from("ca.pem"), ca.pem.clone())],
        };
        let member = MemberClient {
            member_id: member_id.to_string(),
            endpoint: format!("https://127.0.0.1:{}", addr.port()),
            client: build_member_client(&material, member_id).expect("the member's client"),
        };
        (member, handle)
    }

    /// Every member `apps` names, as one set, in that order.
    async fn set_of(
        ca: &TestCa,
        apps: Vec<(&str, axum::Router)>,
    ) -> (SetClient, Vec<axum_server::Handle<std::net::SocketAddr>>) {
        let mut members = Vec::new();
        let mut served = Vec::new();
        for (member_id, app) in apps {
            let (member, handle) = member_at(ca, member_id, app).await;
            members.push(member);
            served.push(handle);
        }
        (SetClient { members }, served)
    }

    /// Answers every object read, after `after`, with `payload` under the
    /// namespace `namespace`.
    fn object_answer(
        namespace: &'static [u8],
        payload: &'static [u8],
        after: Duration,
    ) -> axum::Router {
        axum::Router::new().route(
            "/api/v2/immutable/{addr}",
            axum::routing::get(move || async move {
                tokio::time::sleep(after).await;
                (
                    [(
                        axum::http::HeaderName::from_static("x-namespace"),
                        axum::http::HeaderValue::from_bytes(namespace).expect("a header value"),
                    )],
                    payload.to_vec(),
                )
            }),
        )
    }

    const NAMESPACE: &[u8] = b"DSM/test/hostile-member";

    /// A member that answers an object read with a namespace outside the
    /// domain families is passed over. Its namespace once reached the hasher,
    /// which panicked the read: one member stopped every read that asked it,
    /// whatever the others held. Here it answers first, with the object's own
    /// bytes under `x`, and the three members that hold the object answer
    /// after it: the object is fetched, and it is `Stored`.
    #[tokio::test]
    async fn a_member_namespace_outside_the_domain_families_is_passed_over() {
        let ca = TestCa::new();
        let payload: &'static [u8] = b"the object";
        let addr = immutable_addr(
            TaggedHashDomain::try_new(NAMESPACE).expect("a domain"),
            payload,
        );
        let later = Duration::from_millis(200);
        let (set, _served) = set_of(
            &ca,
            vec![
                ("dsm-node-1", object_answer(b"x", payload, Duration::ZERO)),
                ("dsm-node-2", object_answer(NAMESPACE, payload, later)),
                ("dsm-node-3", object_answer(NAMESPACE, payload, later)),
                ("dsm-node-4", object_answer(NAMESPACE, payload, later)),
            ],
        )
        .await;
        assert_eq!(set.fetch_verified(&addr).await.as_deref(), Some(payload));
        let reads = set.get_immutable(&addr).await;
        assert_eq!(
            reads[0],
            ObjectRead::Bytes {
                namespace: b"x".to_vec(),
                payload: payload.to_vec(),
            },
            "the member answered, and its answer is what was read"
        );
        assert_eq!(
            dsm::sofi::storage::stored(&addr, &reads),
            StoredFact::Stored(payload.to_vec())
        );
    }

    /// Answers every index read with `page(after)`, counting the pages it
    /// was asked for.
    fn index_answer(
        page: fn(i64) -> Vec<proto::IndexEntryV1>,
        asked: Arc<AtomicUsize>,
    ) -> axum::Router {
        axum::Router::new().route(
            "/api/v2/index/{locator}",
            axum::routing::get(
                move |axum::extract::RawQuery(query): axum::extract::RawQuery| {
                    let asked = asked.clone();
                    async move {
                        asked.fetch_add(1, Ordering::SeqCst);
                        let query = query.expect("a page is asked for from a position");
                        let after: i64 = query
                            .split('&')
                            .find_map(|pair| pair.strip_prefix("after="))
                            .expect("the position")
                            .parse()
                            .expect("a position");
                        proto::IndexPageV1 {
                            entries: page(after),
                        }
                        .encode_to_vec()
                    }
                },
            ),
        )
    }

    /// A full page after `after`, each entry at the next sequence.
    fn full_page(after: i64, addr_len: usize) -> Vec<proto::IndexEntryV1> {
        (1..=MAX_INDEX_PAGE as i64)
            .map(|i| proto::IndexEntryV1 {
                seq: after + i,
                addr: vec![0x5a; addr_len],
            })
            .collect()
    }

    /// One address, at sequence 1: the index of a member that holds it.
    fn one_address(after: i64) -> Vec<proto::IndexEntryV1> {
        if after == 0 {
            vec![proto::IndexEntryV1 {
                seq: 1,
                addr: vec![0x41; 32],
            }]
        } else {
            Vec::new()
        }
    }

    const LOCATOR: [u8; 32] = [0x4c; 32];

    /// A member that answers every index page full, with entries that are not
    /// addresses, is passed over after its first page. Such a page kept the
    /// read going for ever: the read stopped only on a short page or once it
    /// held enough addresses, and these pages are never short and hold none,
    /// so every locator resolution that asked the member waited on it. The
    /// member that holds the locator's address is read beside it.
    #[tokio::test]
    async fn an_index_member_whose_pages_hold_no_addresses_is_passed_over() {
        let ca = TestCa::new();
        let asked = Arc::new(AtomicUsize::new(0));
        let (set, _served) = set_of(
            &ca,
            vec![
                (
                    "dsm-node-1",
                    index_answer(|after| full_page(after, 31), asked.clone()),
                ),
                (
                    "dsm-node-2",
                    index_answer(one_address, Arc::new(AtomicUsize::new(0))),
                ),
            ],
        )
        .await;
        let reads = tokio::time::timeout(PATIENCE, set.read_index(NAMESPACE, &LOCATOR, 64))
            .await
            .expect("the read ends whatever a member answers");
        assert_eq!(reads, vec![None, Some(vec![[0x41; 32]])]);
        assert_eq!(asked.load(Ordering::SeqCst), 1, "one page showed it");
    }

    /// A member whose pages do not move past the sequence it last named is
    /// passed over: it answered the same page however far the read had come,
    /// and that page's addresses were read again and again as more of its
    /// index.
    #[tokio::test]
    async fn an_index_member_whose_pages_do_not_advance_is_passed_over() {
        let ca = TestCa::new();
        let asked = Arc::new(AtomicUsize::new(0));
        let (set, _served) = set_of(
            &ca,
            vec![
                (
                    "dsm-node-1",
                    index_answer(|_| full_page(0, 32), asked.clone()),
                ),
                (
                    "dsm-node-2",
                    index_answer(one_address, Arc::new(AtomicUsize::new(0))),
                ),
            ],
        )
        .await;
        let reads = tokio::time::timeout(PATIENCE, set.read_index(NAMESPACE, &LOCATOR, 4096))
            .await
            .expect("the read ends whatever a member answers");
        assert_eq!(reads, vec![None, Some(vec![[0x41; 32]])]);
        assert_eq!(
            asked.load(Ordering::SeqCst),
            2,
            "the second page repeated the first"
        );
    }

    /// A member whose index never ends, page after full page of addresses, is
    /// read for as many pages as the budget's addresses fill, and no more.
    #[tokio::test]
    async fn an_index_read_ends_at_its_budget_however_long_the_index() {
        let ca = TestCa::new();
        let asked = Arc::new(AtomicUsize::new(0));
        let (set, _served) = set_of(
            &ca,
            vec![(
                "dsm-node-1",
                index_answer(|after| full_page(after, 32), asked.clone()),
            )],
        )
        .await;
        let budget = MAX_INDEX_PAGE + 1;
        let reads = tokio::time::timeout(PATIENCE, set.read_index(NAMESPACE, &LOCATOR, budget))
            .await
            .expect("the read ends whatever a member answers");
        let [Some(addrs)] = reads.as_slice() else {
            panic!("the member answered whole pages: {reads:?}");
        };
        assert_eq!(addrs.len(), 2 * MAX_INDEX_PAGE);
        assert_eq!(asked.load(Ordering::SeqCst), 2);
    }

    /// A member whose page lists more entries than a page holds is passed
    /// over: such a page is no answer to a read of one page, though it fits
    /// the bytes of the largest page.
    #[tokio::test]
    async fn an_index_page_longer_than_a_page_is_passed_over() {
        let ca = TestCa::new();
        let (set, _served) = set_of(
            &ca,
            vec![(
                "dsm-node-1",
                index_answer(
                    |after| {
                        let mut page = full_page(after, 32);
                        page.push(proto::IndexEntryV1 {
                            seq: after + MAX_INDEX_PAGE as i64 + 1,
                            addr: vec![0x5a; 32],
                        });
                        page
                    },
                    Arc::new(AtomicUsize::new(0)),
                ),
            )],
        )
        .await;
        let reads = tokio::time::timeout(PATIENCE, set.read_index(NAMESPACE, &LOCATOR, 64))
            .await
            .expect("the read ends whatever a member answers");
        assert_eq!(reads, vec![None]);
    }

    /// Answers every object read with `body` under the test namespace.
    fn streamed_object(body: axum::body::Body) -> axum::Router {
        let body = std::sync::Mutex::new(Some(body));
        let body = Arc::new(body);
        axum::Router::new().route(
            "/api/v2/immutable/{addr}",
            axum::routing::get(move || {
                let body = body.clone();
                async move {
                    let body = match body.lock() {
                        Ok(mut held) => held.take().expect("one read"),
                        Err(poisoned) => poisoned.into_inner().take().expect("one read"),
                    };
                    axum::response::Response::builder()
                        .header("x-namespace", NAMESPACE)
                        .body(body)
                        .expect("an answer")
                }
            }),
        )
    }

    /// An object read is read within the largest object a member takes. A
    /// member that streams without end is refused once its answer passes it,
    /// not when the request times out with the stream held in memory; one
    /// that announces a longer answer is refused before any of it is read;
    /// an answer of exactly the largest object is the object.
    #[tokio::test]
    async fn an_object_answer_past_the_largest_object_is_refused_unread() {
        let ca = TestCa::new();
        let addr = [0x61; 32];
        let announced = vec![0x6f; MAX_IMMUTABLE_PAYLOAD_BYTES + 1];
        let largest = vec![0x6f; MAX_IMMUTABLE_PAYLOAD_BYTES];
        let (set, _served) = set_of(
            &ca,
            vec![
                ("dsm-node-1", streamed_object(bounded_read::endless())),
                (
                    "dsm-node-2",
                    streamed_object(axum::body::Body::from(announced)),
                ),
                (
                    "dsm-node-3",
                    streamed_object(axum::body::Body::from(largest.clone())),
                ),
            ],
        )
        .await;
        let reads = tokio::time::timeout(PATIENCE, set.get_immutable(&addr))
            .await
            .expect("an endless answer is refused, not waited out");
        assert_eq!(reads[0], ObjectRead::Unavailable);
        assert_eq!(reads[1], ObjectRead::Unavailable);
        assert_eq!(
            reads[2],
            ObjectRead::Bytes {
                namespace: NAMESPACE.to_vec(),
                payload: largest,
            }
        );
    }

    /// A member that redirects a read is not followed: the redirect points at
    /// plain HTTP, where the object waits, and nothing reaches it. The member
    /// answered with its status, which is not an answer.
    #[tokio::test]
    async fn a_member_redirect_is_not_followed() {
        let ca = TestCa::new();
        let reached = Arc::new(AtomicUsize::new(0));
        let plain = {
            let reached = reached.clone();
            object_answer(NAMESPACE, b"the object", Duration::ZERO).layer(
                axum::middleware::from_fn(
                    move |request: axum::extract::Request, next: axum::middleware::Next| {
                        let reached = reached.clone();
                        async move {
                            reached.fetch_add(1, Ordering::SeqCst);
                            next.run(request).await
                        }
                    },
                ),
            )
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a plain port");
        let port = listener.local_addr().expect("its address").port();
        tokio::spawn(async move { axum::serve(listener, plain).await });
        let redirect = axum::Router::new().route(
            "/api/v2/immutable/{addr}",
            axum::routing::get(
                move |axum::extract::Path(addr): axum::extract::Path<String>| async move {
                    axum::response::Redirect::temporary(&format!(
                        "http://127.0.0.1:{port}/api/v2/immutable/{addr}"
                    ))
                },
            ),
        );
        let (set, _served) = set_of(&ca, vec![("dsm-node-1", redirect)]).await;
        let reads = set.get_immutable(&[0x61; 32]).await;
        assert_eq!(reads, vec![ObjectRead::Unavailable]);
        assert_eq!(
            reached.load(Ordering::SeqCst),
            0,
            "the redirect was followed"
        );
    }

    /// Answers every cell read with `body`.
    fn cell_answer(body: Vec<u8>) -> axum::Router {
        axum::Router::new().route(
            "/api/v2/cell/{key}",
            axum::routing::get(move || {
                let body = body.clone();
                async move { body }
            }),
        )
    }

    /// The smallest entry a member takes at a cell: a one-byte value, and its
    /// record naming a one-byte member at the shortest namespace a member
    /// takes.
    fn smallest_cell_entry() -> (Vec<u8>, proto::ArrivalRecordV1) {
        (
            vec![0x76],
            proto::ArrivalRecordV1 {
                member_id: b"m".to_vec(),
                namespace: b"DSM/".to_vec(),
                key: vec![0x6b; 32],
                index: 1,
                running_hash: vec![0x68; 32],
            },
        )
    }

    /// A page of a cell read is bounded by the protocol. A page longer than a
    /// page can be is refused before it is all read, and one holding more
    /// entries than a page holds is refused before it is decoded. Either is not
    /// an answer from that member, never an empty cell or a cut-short one;
    /// the member holding the cell's entry is read beside them.
    #[tokio::test]
    async fn a_cell_page_past_what_a_page_holds_is_refused_unread() {
        let ca = TestCa::new();
        // Each page is whole in every other way (a record per value, from
        // index 1, the last page), so its size or its count alone refuses it.
        let page_of = |values: Vec<Vec<u8>>| {
            let (_, record) = smallest_cell_entry();
            proto::CellValuesV1 {
                records: (1..)
                    .take(values.len())
                    .map(|index| proto::ArrivalRecordV1 {
                        index,
                        ..record.clone()
                    })
                    .collect(),
                values,
                next: 0,
            }
        };
        let over_bytes = page_of(vec![vec![0x76; 64 * 1024]; 8]);
        assert!(over_bytes.encoded_len() > super::cell_page_limit("dsm-node-1", NAMESPACE));
        // One more of the smallest entries than a page holds, well within a
        // page's bytes.
        let over_entries = page_of(vec![smallest_cell_entry().0; MAX_CELL_PAGE_ENTRIES + 1]);
        assert!(over_entries.encoded_len() < super::cell_page_limit("dsm-node-2", NAMESPACE));
        let over_entries = over_entries.encode_to_vec();
        let (value, record) = smallest_cell_entry();
        let held = proto::CellValuesV1 {
            values: vec![value.clone()],
            records: vec![record],
            next: 0,
        };
        let (set, _served) = set_of(
            &ca,
            vec![
                ("dsm-node-1", cell_answer(over_bytes.encode_to_vec())),
                ("dsm-node-2", cell_answer(over_entries)),
                ("dsm-node-3", cell_answer(held.encode_to_vec())),
            ],
        )
        .await;
        let reads = tokio::time::timeout(PATIENCE, set.get_cell(NAMESPACE, &[0x6b; 32]))
            .await
            .expect("the read ends");
        assert_eq!(reads, vec![None, None, Some(vec![value])]);
    }

    /// Answers each cell read with the page `page` makes for the arrival
    /// index the read names, counting the reads.
    fn paged_cell(
        page: impl Fn(u64) -> proto::CellValuesV1 + Clone + Send + Sync + 'static,
        reads: Arc<AtomicUsize>,
    ) -> axum::Router {
        axum::Router::new().route(
            "/api/v2/cell/{key}",
            axum::routing::get(
                move |axum::extract::Query(query): axum::extract::Query<
                    std::collections::HashMap<String, u64>,
                >| {
                    let (page, reads) = (page.clone(), reads.clone());
                    async move {
                        reads.fetch_add(1, Ordering::SeqCst);
                        // The client names the arrival index on every read.
                        let Some(&from) = query.get("from") else {
                            panic!("a cell read names the arrival index it starts at");
                        };
                        page(from).encode_to_vec()
                    }
                },
            ),
        )
    }

    /// The page of `held` read from `from`: at most `per_page` entries, each
    /// with its record, and where the next page starts.
    fn honest_page(held: &[Vec<u8>], per_page: usize, from: u64) -> proto::CellValuesV1 {
        let (_, record) = smallest_cell_entry();
        let start = usize::try_from(from - 1).expect("an index");
        let end = held.len().min(start + per_page);
        let values = held.get(start..end).map_or(Vec::new(), <[Vec<u8>]>::to_vec);
        let records = (from..)
            .take(values.len())
            .map(|index| proto::ArrivalRecordV1 {
                index,
                ..record.clone()
            })
            .collect();
        let next = if end < held.len() {
            u64::try_from(end + 1).expect("an index")
        } else {
            0
        };
        proto::CellValuesV1 {
            values,
            records,
            next,
        }
    }

    /// A cell holding more than a page is read page after page, each from
    /// where the last one said the next starts, and the pages are joined in
    /// arrival order: the read returns every value the member holds.
    #[tokio::test]
    async fn every_page_of_a_cell_is_read_and_joined_in_arrival_order() {
        let ca = TestCa::new();
        let held: Vec<Vec<u8>> = (0..600u32).map(|i| i.to_be_bytes().to_vec()).collect();
        let reads = Arc::new(AtomicUsize::new(0));
        let pages = {
            let held = held.clone();
            move |from| honest_page(&held, MAX_CELL_PAGE_ENTRIES, from)
        };
        let (set, _served) =
            set_of(&ca, vec![("dsm-node-1", paged_cell(pages, reads.clone()))]).await;
        let read = tokio::time::timeout(PATIENCE, set.get_cell(NAMESPACE, &[0x6b; 32]))
            .await
            .expect("the read ends");
        assert_eq!(read, vec![Some(held)]);
        assert_eq!(
            reads.load(Ordering::SeqCst),
            3,
            "600 entries are three pages"
        );
    }

    /// A member whose pages never end, each naming the next, is read until
    /// this device's budget for one cell is spent, and no further; the read
    /// is not an answer from it.
    #[tokio::test]
    async fn a_cell_read_ends_at_this_devices_budget_however_many_pages() {
        let ca = TestCa::new();
        let reads = Arc::new(AtomicUsize::new(0));
        let largest = CELL_PAGE_VALUE_BYTES;
        let endless = move |from: u64| {
            let (_, record) = smallest_cell_entry();
            proto::CellValuesV1 {
                values: vec![vec![0x76; largest]],
                records: vec![proto::ArrivalRecordV1 {
                    index: from,
                    ..record
                }],
                next: from + 1,
            }
        };
        let (set, _served) = set_of(
            &ca,
            vec![("dsm-node-1", paged_cell(endless, reads.clone()))],
        )
        .await;
        let read = tokio::time::timeout(PATIENCE, set.get_cell(NAMESPACE, &[0x6b; 32]))
            .await
            .expect("the read ends");
        assert_eq!(read, vec![None]);
        let pages = reads.load(Ordering::SeqCst);
        assert!(
            pages <= CELL_VALUES_BUDGET.bytes / largest + 1,
            "{pages} pages read past a budget of {} bytes",
            CELL_VALUES_BUDGET.bytes
        );
    }

    /// A page that does not follow its read is not an answer: one naming
    /// itself as the next page, one whose records run from another index,
    /// and an empty one that names a next page.
    #[tokio::test]
    async fn a_page_that_does_not_follow_its_read_is_not_an_answer() {
        let ca = TestCa::new();
        let reads = Arc::new(AtomicUsize::new(0));
        let entry = |index: u64| {
            let (value, record) = smallest_cell_entry();
            (value, proto::ArrivalRecordV1 { index, ..record })
        };
        let stalls = move |from: u64| {
            let (value, record) = entry(from);
            proto::CellValuesV1 {
                values: vec![value],
                records: vec![record],
                next: from,
            }
        };
        let elsewhere = move |from: u64| {
            let (value, record) = entry(from + 7);
            proto::CellValuesV1 {
                values: vec![value],
                records: vec![record],
                next: 0,
            }
        };
        let empty_but_more = |from: u64| proto::CellValuesV1 {
            values: Vec::new(),
            records: Vec::new(),
            next: from + 1,
        };
        let (set, _served) = set_of(
            &ca,
            vec![
                ("dsm-node-1", paged_cell(stalls, reads.clone())),
                ("dsm-node-2", paged_cell(elsewhere, reads.clone())),
                ("dsm-node-3", paged_cell(empty_but_more, reads.clone())),
            ],
        )
        .await;
        let read = tokio::time::timeout(PATIENCE, set.get_cell(NAMESPACE, &[0x6b; 32]))
            .await
            .expect("the read ends");
        assert_eq!(read, vec![None, None, None]);
        assert_eq!(reads.load(Ordering::SeqCst), 3, "each member was read once");
    }

    /// The page a member serves of `held` from `from`, as the node builds it:
    /// up to a page's entries while their values fit a page's bytes, and
    /// always the first.
    fn node_page(held: &[Vec<u8>], from: u64) -> proto::CellValuesV1 {
        let start = usize::try_from(from - 1).expect("an index");
        let mut end = start;
        let mut bytes = 0usize;
        while end < held.len() && end - start < MAX_CELL_PAGE_ENTRIES {
            bytes += held[end].len();
            if end > start && bytes > CELL_PAGE_VALUE_BYTES {
                break;
            }
            end += 1;
        }
        let per_page = end - start;
        honest_page(held, per_page.max(1), from)
    }

    /// SA-68. A member that ends every page after one small entry, each
    /// naming the next, would make a cell read take hundreds of thousands of
    /// requests. A page cut short must be borne out by the value after it,
    /// which would not have fit: here it would, so the second page refuses
    /// the member's answer, and nothing more is asked of it.
    /// MUTATION CONTROL: not checking the page cut short turns this red.
    #[tokio::test]
    async fn a_member_cutting_every_page_short_is_not_answering() {
        let ca = TestCa::new();
        let reads = Arc::new(AtomicUsize::new(0));
        let trickle = move |from: u64| {
            let (value, record) = smallest_cell_entry();
            proto::CellValuesV1 {
                values: vec![value],
                records: vec![proto::ArrivalRecordV1 {
                    index: from,
                    ..record
                }],
                next: from + 1,
            }
        };
        let (set, _served) = set_of(
            &ca,
            vec![("dsm-node-1", paged_cell(trickle, reads.clone()))],
        )
        .await;
        let read = tokio::time::timeout(PATIENCE, set.get_cell(NAMESPACE, &[0x6b; 32]))
            .await
            .expect("the read ends");
        assert_eq!(read, vec![None]);
        assert_eq!(
            reads.load(Ordering::SeqCst),
            2,
            "the second page refused it"
        );
    }

    /// A page an honest member ends short, because the value after it would
    /// carry it past a page's bytes, is read on: the cell is read whole.
    #[tokio::test]
    async fn a_page_ended_short_by_the_value_after_it_is_read_on() {
        let ca = TestCa::new();
        let reads = Arc::new(AtomicUsize::new(0));
        let held = vec![
            vec![0x01; 16],
            vec![0x02; CELL_PAGE_VALUE_BYTES],
            vec![0x03; 16],
            vec![0x04; 16],
        ];
        let pages = {
            let held = held.clone();
            move |from| node_page(&held, from)
        };
        assert!(node_page(&held, 1).values.len() < MAX_CELL_PAGE_ENTRIES);
        let (set, _served) =
            set_of(&ca, vec![("dsm-node-1", paged_cell(pages, reads.clone()))]).await;
        let read = tokio::time::timeout(PATIENCE, set.get_cell(NAMESPACE, &[0x6b; 32]))
            .await
            .expect("the read ends");
        assert_eq!(read, vec![Some(held)]);
        assert_eq!(reads.load(Ordering::SeqCst), 3);
    }

    /// SA-68. A member answering full pages, each just inside a request's
    /// timeout, is held to one deadline for the whole cell: past it the read
    /// is that member not answering, however many pages it still has.
    /// MUTATION CONTROL: reading the pages with no deadline turns this red.
    #[tokio::test]
    async fn a_cell_read_ends_at_its_deadline_however_slow_the_pages() {
        let ca = TestCa::new();
        let reads = Arc::new(AtomicUsize::new(0));
        let held: Vec<Vec<u8>> = vec![smallest_cell_entry().0; MAX_CELL_PAGE_ENTRIES * 64];
        let slow = {
            let reads = reads.clone();
            axum::Router::new().route(
                "/api/v2/cell/{key}",
                axum::routing::get(
                    move |axum::extract::Query(query): axum::extract::Query<
                        std::collections::HashMap<String, u64>,
                    >| {
                        let (held, reads) = (held.clone(), reads.clone());
                        async move {
                            reads.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(300)).await;
                            let from = query.get("from").copied().expect("the arrival index");
                            honest_page(&held, MAX_CELL_PAGE_ENTRIES, from).encode_to_vec()
                        }
                    },
                ),
            )
        };
        let (member, _served) = member_at(&ca, "dsm-node-1", slow).await;
        let refused = tokio::time::timeout(
            PATIENCE,
            member.cell_values_within(NAMESPACE, &[0x6b; 32], Duration::from_secs(1)),
        )
        .await
        .expect("the read ends")
        .expect_err("past its deadline the member did not answer");
        assert!(refused.contains("took longer than"), "{refused}");
        assert!(
            reads.load(Ordering::SeqCst) < 64,
            "the read stopped at its deadline"
        );
    }

    /// The budgets hold what an honest member answers: a cell of the
    /// smallest entries a member takes, read page after page until its byte
    /// budget is filled, stays within its allocation budget, and a mirror
    /// answer that fills its byte budget with the smallest ByteCommits
    /// decodes within its allocation budget.
    #[test]
    fn the_budgets_hold_an_answer_of_the_smallest_honest_elements() {
        let held = vec![smallest_cell_entry().0; MAX_CELL_PAGE_ENTRIES * 1024];
        let mut read = super::CellRead::default();
        let (mut from, mut spent) = (1u64, 0usize);
        loop {
            let page = honest_page(&held, MAX_CELL_PAGE_ENTRIES, from).encode_to_vec();
            if spent + page.len() > CELL_VALUES_BUDGET.bytes {
                // The byte budget is filled to within one page.
                assert!(spent + 2 * page.len() > CELL_VALUES_BUDGET.bytes);
                break;
            }
            spent += page.len();
            from = read
                .take(from, &page)
                .expect("a cell of the smallest entries is read within the budget");
        }
        assert_eq!(
            read.values.len(),
            usize::try_from(from - 1).expect("an index")
        );

        let commit = proto::ByteCommitV4 {
            member_id: b"m".to_vec(),
            cycle_index: 2,
            smt_root: vec![0x72; 32],
            bytes_used: 0,
            parent_digest: vec![0x70; 32],
        };
        let commits = MIRRORED_BUDGET.bytes / (commit.encoded_len() + 2);
        let mirror = proto::ByteCommitsV4 {
            commits: vec![commit; commits],
        }
        .encode_to_vec();
        assert!(mirror.len() <= MIRRORED_BUDGET.bytes);
        let decoded = bounded_read::decode_within::<proto::ByteCommitsV4>(
            &mirror,
            &super::MIRRORED_ELEMENTS,
            MIRRORED_BUDGET,
        )
        .expect("a mirror answer of the smallest ByteCommits decodes within the budget");
        assert_eq!(decoded.commits.len(), commits);

        // Empty ByteCommits, as the wire carries them.
        let empties = [0x0a, 0x00].repeat(MIRRORED_BUDGET.bytes / 2);
        assert!(matches!(
            bounded_read::decode_within::<proto::ByteCommitsV4>(
                &empties,
                &super::MIRRORED_ELEMENTS,
                MIRRORED_BUDGET,
            ),
            Err(Refused::OverAllocationBudget { .. })
        ));
    }

    /// Each kind's limit holds the largest answer an honest member gives: a
    /// limit set short would refuse an honest member.
    #[test]
    fn every_limit_holds_the_largest_honest_answer() {
        let leaves: Vec<(Vec<u8>, [u8; 32], u64, [u8; 32])> = (0u8..8)
            .map(|i| (NAMESPACE.to_vec(), [i; 32], u64::from(i) + 1, [0x68; 32]))
            .collect();
        let tree = dsm::storage_cell::cell_tree(
            leaves
                .iter()
                .map(|(ns, key, index, hash)| (ns.as_slice(), key, *index, hash)),
        );
        let proof = dsm::storage_cell::CellCommitProof::from_tree(
            &tree,
            NAMESPACE,
            &[3; 32],
            u64::MAX,
            [0x68; 32],
        )
        .expect("a proof");
        assert!(proof.to_proto().encoded_len() <= super::cell_proof_limit());

        let page = proto::IndexPageV1 {
            entries: full_page(i64::MAX - MAX_INDEX_PAGE as i64, 32),
        };
        assert!(page.encoded_len() <= super::index_page_limit());

        let commit = dsm::storage_cell::ByteCommit {
            member_id: b"dsm-node-1".to_vec(),
            cycle_index: u64::MAX,
            smt_root: [0x72; 32],
            bytes_used: u64::MAX,
            parent_digest: [0x70; 32],
        };
        assert_eq!(
            commit.to_proto().encoded_len(),
            super::bytecommit_limit("dsm-node-1")
        );
    }

    /// On the storage node's own code, on Postgres: a cell holding more than
    /// a page, by its entries and by its bytes, is read whole from every node
    /// of the pinned set, page by page, in arrival order. The client and the
    /// node agree on how a page is asked for and where the next one starts.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn a_cell_holding_more_than_a_page_is_read_whole_from_every_node() {
        let nodes = crate::test_support::nodes::NodeSet::start().await;
        let _config = crate::economic_fixtures::point_sdk_at(&nodes.members(), nodes.ca_pem());
        let set = crate::sdk::storage_set::canonical_set(crate::economic_fixtures::NETWORK)
            .expect("the pinned set");
        let client = SetClient::new(&set).expect("a client of the set");
        let key = [0x6e; 32];
        let mut held: Vec<Vec<u8>> = (0..MAX_CELL_PAGE_ENTRIES + 20)
            .map(|i| format!("small {i}").into_bytes())
            .collect();
        held.extend((0..3u8).map(|i| vec![i; CELL_PAGE_VALUE_BYTES * 2 / 3]));
        for member in &client.members {
            for chunk in held.chunks(16) {
                let entries: Vec<(Vec<u8>, [u8; 32], Vec<u8>)> = chunk
                    .iter()
                    .map(|value| (NAMESPACE.to_vec(), key, value.clone()))
                    .collect();
                let records = member
                    .put_cells(&entries)
                    .await
                    .expect("the node takes them");
                assert_eq!(records.len(), entries.len());
            }
        }
        let reads = client.get_cell(NAMESPACE, &key).await;
        assert_eq!(reads.len(), client.members.len());
        for read in reads {
            assert_eq!(read.as_ref(), Some(&held), "every value, in arrival order");
        }
        drop(nodes);
    }
}
