// SPDX-License-Identifier: MIT OR Apache-2.0

//! # B0x SDK — Unilateral Envelope Transport
//!
//! Deterministic, protobuf-only client for the b0x spool: Envelope v3
//! submission to, and retrieval from, the storage-node `/api/v2/b0x/*`
//! endpoints. A node's spool is append-only and checks no writer or reader
//! (DSM Amendment A3): there is no registration, token or acknowledgement,
//! and what this device consumed is its own state (`client_db::b0x_consumed`).
//!
//! Every payload is sealed end to end (DSM Amendment A7): a node holds an
//! outer envelope carrying only the message id and a `SealedEnvelopeV1` — an
//! ML-KEM encapsulation to the recipient's Kyber key and the inner envelope
//! sealed under its shared secret (`dsm::crypto::spool_seal`). A message is
//! sealed once and its bytes are kept by message id (`client_db::b0x_sealed`),
//! so every member and every retry gets the same bytes. No wall clocks, no
//! JSON, no hex in protocol logic.

use dsm::types::error::DsmError;
use dsm::types::operations::Operation;

use crate::sdk::core_sdk::CoreSDK;
use crate::util::text_id;
// blake3 usage: all calls go through dsm::crypto::blake3::dsm_domain_hasher() for domain separation

use log::{info, warn, debug};
use prost::Message;
use rand::rngs::OsRng;
use reqwest;
use std::collections::HashMap;
use std::sync::Arc;

fn base32_decodes_to_32_bytes(s: &str) -> bool {
    match crate::util::text_id::decode_base32_crockford(s) {
        Some(b) => b.len() == 32,
        None => false,
    }
}

/// Validate the canonical rotated b0x routing key.
///
/// The routing key is a single Base32 Crockford encoding of a 32-byte
/// domain-separated BLAKE3 digest.
fn validate_b0x_address(address: &str) -> Result<(), DsmError> {
    if !base32_decodes_to_32_bytes(address) {
        return Err(DsmError::internal(
            "Invalid b0x address format: must be canonical base32 encoding of 32 bytes",
            None::<std::io::Error>,
        ));
    }

    Ok(())
}

fn decode_base32_32(label: &str, value: &str) -> Result<[u8; 32], DsmError> {
    let bytes = text_id::decode_base32_crockford(value).ok_or_else(|| {
        DsmError::internal(
            format!("{label} must be valid base32 encoding of 32 bytes"),
            None::<std::io::Error>,
        )
    })?;
    if bytes.len() != 32 {
        return Err(DsmError::internal(
            format!(
                "{label} must decode to exactly 32 bytes (got {})",
                bytes.len()
            ),
            None::<std::io::Error>,
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn storage_err(what: &str, e: impl core::fmt::Display) -> DsmError {
    DsmError::storage(format!("{what}: {e}"), None::<std::io::Error>)
}

fn message_id_bytes(
    message_id_b32: &str,
) -> Result<[u8; dsm::crypto::spool_seal::MESSAGE_ID_LEN], DsmError> {
    text_id::decode_base32_crockford(message_id_b32)
        .and_then(|raw| <[u8; dsm::crypto::spool_seal::MESSAGE_ID_LEN]>::try_from(raw).ok())
        .ok_or_else(|| {
            DsmError::invalid_parameter(format!(
                "spool message id {message_id_b32} is not base32 of {} bytes",
                dsm::crypto::spool_seal::MESSAGE_ID_LEN
            ))
        })
}

/// The recipient's Kyber key, as its contact holds it: the key its verified
/// directory entry carries (`sdk::device_directory`), signed by its AK.
fn recipient_kyber_key(recipient_device: &[u8; 32]) -> Result<Vec<u8>, DsmError> {
    let contact = crate::storage::client_db::get_contact_by_device_id(recipient_device)
        .map_err(|e| storage_err("recipient contact", e))?
        .ok_or_else(|| {
            DsmError::invalid_operation("the recipient is not a contact: nothing to seal for")
        })?;
    if contact.kyber_public_key.len() != dsm::crypto::kyber::public_key_bytes() {
        return Err(DsmError::invalid_operation(
            "the recipient's Kyber key is not in hand yet: its directory entry has not been \
             read into the contact",
        ));
    }
    Ok(contact.kyber_public_key)
}

/// Seal `inner` — the exact bytes of an inner envelope — for
/// `recipient_device` under `message_id_b32` (DSM Amendment A7), and keep the
/// sealed bytes: an outer Envelope v3 carrying only the message id and a
/// `SealedEnvelopeV1` — a fresh ML-KEM encapsulation to the recipient's Kyber
/// key and the inner bytes sealed under its shared secret. A message id is
/// sealed once: a later call returns the bytes kept by the first
/// (`client_db::b0x_sealed`).
pub(crate) fn seal_for(
    recipient_device: &[u8; 32],
    message_id_b32: &str,
    inner: &[u8],
) -> Result<Vec<u8>, DsmError> {
    if let Some(kept) = crate::storage::client_db::b0x_sealed::get_sealed(message_id_b32)
        .map_err(|e| storage_err("sealed spool bytes", e))?
    {
        return Ok(kept);
    }
    let message_id = message_id_bytes(message_id_b32)?;
    let (shared_secret, kem_ciphertext) =
        dsm::crypto::kyber::kyber_encapsulate(&recipient_kyber_key(recipient_device)?)?;
    let ciphertext = dsm::crypto::spool_seal::seal(&shared_secret, &message_id, inner)
        .map_err(|e| DsmError::crypto(format!("spool seal: {e}"), None::<std::io::Error>))?;
    let outer = dsm::types::proto::Envelope {
        version: 3,
        headers: None,
        message_id: message_id.to_vec(),
        payload: Some(dsm::types::proto::envelope::Payload::Sealed(
            dsm::types::proto::SealedEnvelopeV1 {
                kem_ciphertext,
                ciphertext,
            },
        )),
    };
    let bytes = outer.encode_to_vec();
    crate::storage::client_db::b0x_sealed::put_sealed(message_id_b32, &bytes)
        .map_err(|e| storage_err("keep sealed spool bytes", e))?;
    Ok(bytes)
}

/// The sealed bytes kept for `message_id_b32` when its envelope was frozen
/// ([`seal_for`]).
pub(crate) fn kept_seal(message_id_b32: &str) -> Result<Vec<u8>, DsmError> {
    crate::storage::client_db::b0x_sealed::get_sealed(message_id_b32)
        .map_err(|e| storage_err("sealed spool bytes", e))?
        .ok_or_else(|| {
            DsmError::invalid_operation(format!(
                "spool message {message_id_b32} was frozen without its seal"
            ))
        })
}

/// This device's Kyber secret, re-derived from `Smaster` under `DSM/kyber\0` —
/// the key pair whose public half its directory entry publishes
/// (`kyber_identity::local_kyber_public_key`). Never kept.
fn local_kyber_secret() -> Result<Vec<u8>, DsmError> {
    let smaster = crate::init::current_smaster()?;
    let (.., secret) =
        dsm::crypto::kyber::generate_kyber_keypair_from_entropy(&smaster, "DSM/kyber\0")?;
    Ok(secret)
}

/// Open a spooled envelope (DSM Amendment A7): the inner envelope its seal
/// carries, once this device's Kyber secret decapsulates the encapsulation and
/// the seal opens under the outer message id. The inner envelope carries the
/// same message id; anything else did not come sealed for this device.
pub(crate) fn open_sealed(
    env: &dsm::types::proto::Envelope,
) -> Result<dsm::types::proto::Envelope, DsmError> {
    let Some(dsm::types::proto::envelope::Payload::Sealed(sealed)) = &env.payload else {
        return Err(DsmError::invalid_operation("the envelope is not sealed"));
    };
    let message_id =
        <[u8; dsm::crypto::spool_seal::MESSAGE_ID_LEN]>::try_from(env.message_id.as_slice())
            .map_err(|_| {
                DsmError::invalid_operation("the sealed envelope's message id is malformed")
            })?;
    let shared_secret =
        dsm::crypto::kyber::kyber_decapsulate(&local_kyber_secret()?, &sealed.kem_ciphertext)?;
    let inner_bytes =
        dsm::crypto::spool_seal::open(&shared_secret, &message_id, &sealed.ciphertext)
            .map_err(|e| DsmError::invalid_operation(format!("spool seal: {e}")))?;
    let inner = dsm::envelope::from_canonical_bytes(&inner_bytes)
        .map_err(|e| DsmError::invalid_operation(format!("sealed inner envelope: {e}")))?;
    if inner.message_id != env.message_id {
        return Err(DsmError::invalid_operation(
            "the sealed inner envelope carries another message id",
        ));
    }
    Ok(inner)
}

/// Retry configuration for b0x operations
#[derive(Debug, Clone)]
pub struct B0xRetryConfig {
    pub max_retries: u32,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
    pub backoff_multiplier: f64,
}

impl Default for B0xRetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay_ms: 1000, // 1 second
            max_delay_ms: 30000, // 30 seconds
            backoff_multiplier: 2.0,
        }
    }
}

/// What `deliver_frozen_logical_send` delivered — every id that reached quorum.
/// Returned only on complete success; there is no partial variant on purpose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenSendDelivery {
    /// The transfer envelope's deterministic submission id (== node message id).
    pub transfer_id: String,
    /// Every frozen outbound artifact's submission id, in delivery order.
    pub artifact_ids: Vec<String>,
}

/// What one spool read covered (storage spec §8 item 2; owner ruling
/// 2026-09-25). A delivery lands on exactly `quorum_k` of the set's members
/// ([`B0xSDK::delivery_quorum`]), so a read that reached at least
/// `members - quorum_k + 1` of them met every delivered message at least once:
/// `Complete`. Fewer is `Partial`: what was read is real, and a message held
/// only by members that did not answer is still there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpoolCoverage {
    Complete,
    Partial { responded: usize, needed: usize },
}

impl SpoolCoverage {
    /// The coverage of a read `responded` members answered, of `members`,
    /// when every delivery lands on `quorum_k` of them.
    pub fn of(responded: usize, members: usize, quorum_k: usize) -> Self {
        let needed = members.saturating_sub(quorum_k) + 1;
        if responded >= needed {
            Self::Complete
        } else {
            Self::Partial { responded, needed }
        }
    }
}

/// One spool read: what it found, how many members answered, and what that
/// covers.
#[derive(Debug)]
pub struct RetrievalOutcome {
    pub entries: Vec<B0xEntry>,
    pub responded: usize,
    pub members: usize,
    pub coverage: SpoolCoverage,
}

/// What a polled entry carries, as its request states it. Nothing here is
/// verified: the transfer pipeline checks the signed bytes it retains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum B0xEntryKind {
    /// An online transfer request: the amount and token it names.
    Transfer { amount: u64, token_id: String },
    /// An online message: the payload's size.
    Message { payload_len: usize },
}

#[derive(Debug, Clone)]
pub struct B0xEntry {
    pub transaction_id: String,
    pub inbox_key: String,
    // Textual fields are base32-encoded (Crockford: 0-9,A-H,J-K,M-N,P-T,V-Z with substitutions)
    pub sender_device_id: String,
    pub sender_genesis_hash: String,
    pub recipient_device_id: String,
    /// What the entry carries, as its request states it.
    pub kind: B0xEntryKind,
    /// Sender's SPHINCS+ public key (optional, embedded in envelope evidence)
    pub sender_signing_public_key: Vec<u8>,
    /// §4.2.1 Canonical unsigned Operation bytes (signing preimage).
    /// Receiver uses these directly for SPHINCS+ verification and tip computation.
    pub canonical_operation_bytes: Vec<u8>,
    /// ADR 0003: the EXACT `OnlineTransferRequest` wire bytes this entry was
    /// decoded from, retained verbatim.
    ///
    /// Not reconstructed fields, and NOT a protobuf re-encode. Recipient staging
    /// FREEZES the bytes it is handed, and every later check — SIG A over the
    /// canonical operation, the evidence digest binding — runs against that
    /// frozen copy. Re-encoding here would mean verifying something the sender
    /// never signed and the peer never sent, so the original must survive the
    /// decode. Whether a re-encode would be byte-identical is beside the point:
    /// the guarantee is that the question never has to be asked.
    ///
    /// Empty for entries not decoded from an `OnlineTransferRequest` (locally
    /// built entries, fixtures). The split path requires it and fails closed.
    pub transfer_wire_bytes: Vec<u8>,
    /// ADR 0003: the A-side evidence reference carried by the request (proto
    /// field 12). NON-EMPTY is the recipient's discriminator that this entry is
    /// only ONE HALF of a split transfer and must not take the legacy inline
    /// path. Empty means the legacy whole-receipt-inline composition.
    pub receipt_evidence_digest: Vec<u8>,
}

/// The product of pure envelope construction: the exact canonical wire bytes
/// plus the identity they were built under. Carries no network capability.
/// The storage node's per-envelope admission cap
/// (`dsm_storage_node/src/api/transport/b0x.rs`). Duplicated deliberately: the
/// client must not silently track a change to the node's limit, and building an
/// artifact that exceeds it produces a 413 that no retry can ever clear.
pub(crate) const MAX_B0X_ENVELOPE_BYTES: usize = 128 * 1024;

#[derive(Debug)]
pub(crate) struct BuiltEnvelope {
    /// EXACT bytes. The durable outbox freezes these; a retry replays them
    /// verbatim rather than re-running construction.
    pub bytes: Vec<u8>,
    pub message_id_b32: String,
    pub to_device_id_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct B0xSubmissionParams {
    // Textual params must be base32-encoded when provided
    pub recipient_device_id: String,    // base32 of 32-byte DevID
    pub recipient_genesis_hash: String, // base32 of 32-byte genesis
    pub transaction: Operation,
    pub signature: Vec<u8>,
    pub sender_genesis_hash: String, // base32 of 32-byte genesis
    pub sender_chain_tip: String,    // base32 of 32-byte tip
    /// Sender's SPHINCS+ public key (optional, embedded for verification hints)
    pub sender_signing_public_key: Vec<u8>,
    /// Tip-scoped b0x routing address (§16.4).
    /// Computed via `B0xSDK::compute_b0x_address(recipient_genesis, recipient_device, chain_tip)`.
    pub routing_address: String,
    /// §4.2.1 Canonical unsigned Operation bytes (signing preimage).
    /// The exact bytes the sender signed with SPHINCS+.  The receiver MUST
    /// use these directly for verification — no field-by-field reconstruction.
    pub canonical_operation_bytes: Vec<u8>,
    /// ADR 0003: content address of the A-side receipt-evidence artifact this
    /// transfer refers to, populated into proto field 12. Every transfer
    /// carries one; the receipt never rides inline.
    pub receipt_evidence_digest: Vec<u8>,
    /// §16.6 defect zero: caller-supplied DETERMINISTIC submission id.
    ///
    /// The forward-transfer path derives this from the receipt commitment
    /// (`sender_outbox::derive_submission_id`) so the id is known BEFORE the
    /// send is committed locally and is identical on every retry. Storage nodes
    /// enforce `UNIQUE(message_id)` with `ON CONFLICT DO NOTHING`, so a resend
    /// collapses onto the same spool row instead of spawning duplicates.
    ///
    /// `None` keeps the legacy random derivation for callers with no durable
    /// identity to key on (non-transfer submissions).
    pub submission_id: Option<String>,
    /// Sender economic locators (3.5b): OUTPUTS of the sender's built
    /// admission — the admitted position and THE debit mutation index of the
    /// exact write set. Untrusted locators on the wire, never authority.
    /// Zero/absent only for non-economic submissions.
    pub sender_economic_position: u64,
    pub sender_debit_mutation_index: u32,
}

pub struct B0xSDK {
    // Device ID in base32 textual form for HTTP auth; decode to bytes for protobuf fields
    pub(crate) device_id: String,
    core_sdk: Arc<CoreSDK>,
    pub(crate) storage_node_endpoints: Vec<String>,
    http_client: reqwest::Client,
    circuit_breaker: CircuitBreaker,
    salt_genesis: [u8; 32],
    salt_device: [u8; 32],
    /// Write quorum K for multi-node ops (submit/ack). Default 3.
    quorum_k: usize,
    /// ADR 0003 B-side countersign deltas decoded during the most recent
    /// retrieve. Buffered rather than returned so the retrieve signature (5 call
    /// sites) stays stable; drained by the sender-finalization path via
    /// [`Self::take_countersign_deltas`].
    pending_countersign_deltas: Vec<CountersignDelta>,
    /// Finality certificates (`relationship.finalized.v1`) decoded by the most
    /// recent retrieve, drained by `take_relationship_finalized`.
    pending_relationship_finalized: Vec<RelationshipFinalizedMessage>,
    /// ADR 0003 A-side evidence halves decoded by the most recent retrieve,
    /// drained by [`Self::take_evidence_artifacts`].
    pending_evidence_artifacts: Vec<dsm::types::proto::ReceiptEvidenceA>,
    /// Cert-resync control messages decoded on retrieve: (method, framed body).
    pending_cert_resync: Vec<(String, Vec<u8>)>,
}

/// Explicit invoke method that marks an ADR 0003 A-side evidence artifact. The
/// evidence half is structurally distinct from both forward transfers and
/// replies — discriminated by this exact string, NEVER trial-decoded. The producer (`build_evidence_envelope`) and this
/// consumer key off this one constant so they cannot drift apart.
pub(crate) const RECEIPT_EVIDENCE_A_METHOD: &str = "receipt.evidence.a";

/// Explicit invoke method that marks an ADR 0003 B-side countersign DELTA — the
/// return leg. Same discipline: discriminated by this string alone, never
/// trial-decoded, one constant shared by producer and consumer.
pub(crate) const RECEIPT_COUNTERSIGN_B_METHOD: &str = "receipt.countersign.b";

/// Explicit invoke method of a `RelationshipFinalizedV1` finality certificate
/// (finality barrier). Same discipline: discriminated by this string alone.
pub(crate) const RELATIONSHIP_FINALIZED_METHOD: &str = "relationship.finalized.v1";

/// One finality certificate as it came off the wire: the node message id it
/// is ACKed under and the raw `ArgPack.body` (unvalidated `RelationshipFinalizedV1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationshipFinalizedMessage {
    pub message_id: String,
    pub body: Vec<u8>,
}

/// One B-side countersign delta as it came off the wire, kept whole so the
/// sender can retain the exact envelope it finalized on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountersignDelta {
    /// Node message id (Base32 Crockford) — the deterministic reply id.
    pub message_id: String,
    /// The whole envelope, re-encoded; what the sender persists as its
    /// `countersign_b` artifact once the delta verifies.
    pub envelope_bytes: Vec<u8>,
    /// `ArgPack.body`: the `ReceiptCountersignB` wire bytes, unvalidated.
    pub body: Vec<u8>,
}

/// Members whose last request failed. A failed member stays failed until a
/// request to it succeeds; callers ask healthy members first and failed ones
/// last, so a failed member is still reachable. No clock decides recovery.
#[derive(Clone)]
struct CircuitBreaker {
    failed_nodes: Arc<tokio::sync::RwLock<std::collections::HashSet<String>>>,
}

impl CircuitBreaker {
    fn new() -> Self {
        Self {
            failed_nodes: Arc::new(tokio::sync::RwLock::new(std::collections::HashSet::new())),
        }
    }
    async fn is_node_healthy(&self, endpoint: &str) -> bool {
        !self.failed_nodes.read().await.contains(endpoint)
    }
    async fn mark_node_failed(&self, endpoint: &str) {
        self.failed_nodes.write().await.insert(endpoint.to_string());
        warn!("CircuitBreaker: marked failed {}", endpoint);
    }
    async fn mark_node_healthy(&self, endpoint: &str) {
        if self.failed_nodes.write().await.remove(endpoint) {
            info!("CircuitBreaker: {} back to healthy", endpoint);
        }
    }
}

/// Spool message id for an acceptance reply: 16 opaque bytes derived from the
/// transition's own commitment (never wall-clock), stable across reposts so
/// the recipient's replay check recognizes a redelivery (impact-table row
/// B5).
pub(crate) fn reply_message_id(commitment: &[u8], sender_projection_tip: &[u8]) -> Vec<u8> {
    let mut h =
        dsm::crypto::blake3::dsm_domain_hasher(dsm::tagged_domain!(b"DSM/b0x-reply-message-id"));
    h.update(commitment);
    h.update(sender_projection_tip);
    h.finalize().as_bytes()[..16].to_vec()
}

/// Cross-endpoint merge key for a polled envelope: `(message_id, CONTENT digest)`,
/// deliberately NOT `message_id` alone.
///
/// Identical replicas of one message still collapse to a single entry, so the
/// honest case is unchanged. Two copies that DISAGREE under one message id are
/// both surfaced, and the consumer decides which (if either) verifies.
///
/// Keying on `message_id` alone made the merge first-responder-wins: whichever
/// endpoint answered first durably shadowed every other copy of that message.
/// These ids are DETERMINISTIC (see [`reply_message_id`]), so the shadowing
/// repeated identically on every poll — a single replica serving a tampered copy
/// could suppress the honest copies indefinitely, and no amount of retrying
/// would ever surface a good one. Recovering from a bad acceptance artifact is
/// meaningless if a correct replacement can never be seen.
pub(crate) fn envelope_merge_key(env: &dsm::types::proto::Envelope) -> String {
    let mut h =
        dsm::crypto::blake3::dsm_domain_hasher(dsm::tagged_domain!(b"DSM/b0x-envelope-content"));
    h.update(&env.encode_to_vec());
    format!(
        "{}:{}",
        text_id::encode_base32_crockford(&env.message_id),
        text_id::encode_base32_crockford(&h.finalize().as_bytes()[..8]),
    )
}

/// Transport-local spool id for a cert-resync message, from method + route + a
/// digest of the body. IMPACT-TABLE ROW B6, same defect and same extraction
/// reason as [`reply_message_id`].
pub(crate) fn certresync_message_id(method: &str, recipient_tip: &[u8], body: &[u8]) -> Vec<u8> {
    let mut h = dsm::crypto::blake3::dsm_domain_hasher(dsm::tagged_domain!(
        b"DSM/b0x-certresync-message-id"
    ));
    h.update(method.as_bytes());
    h.update(recipient_tip);
    h.update(body);
    h.finalize().as_bytes()[..16].to_vec()
}

impl B0xSDK {
    fn hash_b0x_component(
        domain_tag: dsm::crypto::domain::TaggedHashDomain<'_>,
        input: &[u8],
    ) -> [u8; 32] {
        let mut hasher = dsm::crypto::blake3::dsm_domain_hasher(domain_tag);
        hasher.update(input);
        *hasher.finalize().as_bytes()
    }

    /// Derive a per-device blinding salt from domain tag and device identity.
    ///
    /// §16.4: salt = BLAKE3("DSM/b0x-salt-{G|D}\0" || genesis_hash || device_id)
    /// where genesis_hash is obtained from AppState (master secret Smaster).
    /// Falls back to device_id-only derivation if genesis is not yet available
    /// (e.g. during initial registration before genesis is stored).
    fn derive_salt(domain_tag: &[u8], device_id_bytes: &[u8]) -> [u8; 32] {
        // §16.4: salt = BLAKE3("DSM/b0x-salt-{G|D}\0" || genesis_hash || device_id).
        // The legacy C-DBRW (KDBRW) IKM fold has been removed (Genesis v2 has no silicon-bound
        // secret). genesis_hash is the public Genesis v2 digest `G`; combined with device_id it
        // gives per-device, domain-separated salts. (A future §16.4 hardening can fold the secret
        // Smaster here once b0x salt derivation is wired through the unlocked-wallet path.)
        // Runtime domain: validated at construction, falling back to a fixed
        // static domain rather than silently normalizing a malformed one.
        let tag = dsm::crypto::domain::TaggedHashDomain::try_new(domain_tag)
            .unwrap_or(dsm::tagged_domain!(b"DSM/b0x-salt"));
        let mut hasher = dsm::crypto::blake3::dsm_domain_hasher(tag);
        // Augment with public genesis material for domain separation when storage is available.
        if crate::storage_utils::get_storage_base_dir().is_some() {
            if let Some(genesis) = crate::sdk::app_state::AppState::get_genesis_hash() {
                hasher.update(&genesis);
            }
        }
        hasher.update(device_id_bytes);
        *hasher.finalize().as_bytes()
    }

    /// The delivery quorum this SDK fans out to.
    pub fn delivery_quorum(&self) -> usize {
        self.quorum_k
    }

    pub fn new(
        device_id_b32: String,
        core_sdk: Arc<CoreSDK>,
        storage_endpoints: Vec<String>,
    ) -> Result<Self, DsmError> {
        // Safety: the storage-node protocol uses base32(32 bytes) for device_id.
        // Refuse any non-canonical encoding here to avoid silent inbox mismatches.
        let decoded =
            crate::util::text_id::decode_base32_crockford(&device_id_b32).ok_or_else(|| {
                DsmError::internal(
                    "B0xSDK::new: device_id must be base32",
                    None::<std::io::Error>,
                )
            })?;
        if decoded.len() != 32 {
            return Err(DsmError::internal(
                format!(
                    "B0xSDK::new: device_id base32 decoded to {} bytes (expected 32)",
                    decoded.len()
                ),
                None::<std::io::Error>,
            ));
        }
        if !base32_decodes_to_32_bytes(&device_id_b32) {
            return Err(DsmError::internal(
                "B0xSDK::new: device_id is not canonical base32(32)",
                None::<std::io::Error>,
            ));
        }

        // Clockless: do not set wall-clock request timeouts here.
        // Cancellation/limits are owned by the caller task lifetime.
        let http_client = crate::sdk::storage_node_sdk::build_ca_aware_client()?;

        // The delivery fan-out stops at K acknowledging members. K is the
        // register quorum of the network this device is built for — resolved
        // from the pinned profile, never a literal beside it. A literal `3`
        // used to live here; it agreed with the 5/3 pin by coincidence and
        // silently diverged from the 3/2 one (#867). No profile, no fan-out:
        // a device that cannot resolve its register has nothing to deliver to.
        let quorum_k = crate::storage::client_db::publication::quorum_for(
            dsm::economic::register::resolve_root_register_profile(
                dsm::economic::register::BETA_NETWORK_ID,
            )
            .map_err(|e| {
                DsmError::internal(
                    format!("B0xSDK::new: root register profile unresolved: {e}"),
                    None::<std::io::Error>,
                )
            })?
            .members
            .len(),
        ) as usize;

        let sdk = Self {
            device_id: device_id_b32,
            core_sdk,
            storage_node_endpoints: storage_endpoints,
            http_client,
            circuit_breaker: CircuitBreaker::new(),
            salt_genesis: Self::derive_salt(b"DSM/b0x-salt-G", &decoded),
            salt_device: Self::derive_salt(b"DSM/b0x-salt-D", &decoded),
            quorum_k,
            pending_countersign_deltas: Vec::new(),
            pending_relationship_finalized: Vec::new(),
            pending_evidence_artifacts: Vec::new(),
            pending_cert_resync: Vec::new(),
        };

        Ok(sdk)
    }

    /// Compute the deterministic b0x routing key for (genesis, device, tip).
    ///
    /// Each input is first domain-separated on its own axis, then folded into
    /// a single 32-byte routing digest:
    /// `Base32Crockford(BLAKE3-256("DSM/b0x\0" || h_g || h_d || h_t))`
    /// where `h_g = BLAKE3("DSM/b0x-G\0" || genesis)`,
    /// `h_d = BLAKE3("DSM/b0x-D\0" || device)`,
    /// and `h_t = BLAKE3("DSM/b0x-T\0" || tip)`.
    /// Each input MUST be exactly 32 bytes.
    pub fn compute_b0x_address(
        genesis: &[u8],
        device: &[u8],
        tip: &[u8],
    ) -> Result<String, DsmError> {
        if genesis.len() != 32 || device.len() != 32 || tip.len() != 32 {
            return Err(DsmError::invalid_parameter(
                "genesis/device/tip must be 32 bytes",
            ));
        }
        let h_g = Self::hash_b0x_component(dsm::tagged_domain!(b"DSM/b0x-G"), genesis);
        let h_d = Self::hash_b0x_component(dsm::tagged_domain!(b"DSM/b0x-D"), device);
        let h_t = Self::hash_b0x_component(dsm::tagged_domain!(b"DSM/b0x-T"), tip);

        let mut hasher =
            dsm::crypto::blake3::dsm_domain_hasher(dsm::common::domain_tags::TAG_DSM_B0X);
        hasher.update(&h_g);
        hasher.update(&h_d);
        hasher.update(&h_t);
        let h = hasher.finalize();
        let addr = crate::util::text_id::encode_base32_crockford(h.as_bytes());
        validate_b0x_address(&addr)?;
        Ok(addr)
    }

    /// Compute the canonical rotated b0x routing key from an explicit bilateral
    /// relationship tip. Missing or malformed tips are rejected instead of being
    /// normalized to a legacy zero-tip route.
    pub fn compute_b0x_address_for_optional_tip(
        genesis: &[u8],
        device: &[u8],
        chain_tip: Option<&[u8]>,
    ) -> Result<String, DsmError> {
        match chain_tip {
            Some(tip) if tip.len() == 32 => Self::compute_b0x_address(genesis, device, tip),
            Some(tip) => Err(DsmError::invalid_parameter(format!(
                "relationship tip must be exactly 32 bytes, got {}",
                tip.len()
            ))),
            None => Err(DsmError::invalid_parameter(
                "relationship tip is required for rotated b0x routing",
            )),
        }
    }

    #[inline]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    // ------------------------------------------------------------------------
    // b0x ID derivation (deterministic salts; no clocks)
    // ------------------------------------------------------------------------
    pub async fn b0x_id(&mut self, chain_tip_b32: &str) -> Result<String, DsmError> {
        // Use nonce=0 for stable routing key per relationship-step.
        // The receiver derives the address from the shared chain tip and expects nonce=0.
        let nonce = 0;

        // Prefer persisted canonical genesis from AppState; use core path for tests
        let local_genesis_bytes: [u8; 32] =
            match crate::sdk::app_state::AppState::get_genesis_hash() {
                Some(g) if g.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&g);
                    arr
                }
                _ => {
                    let g = self.core_sdk.local_genesis_hash().await?;
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&g);
                    arr
                }
            };

        // Decode inputs
        let device_id_bytes = crate::util::text_id::decode_base32_crockford(&self.device_id)
            .ok_or_else(|| {
                DsmError::internal("device_id base32 decode failed", None::<std::io::Error>)
            })?;
        let chain_tip_bytes = crate::util::text_id::decode_base32_crockford(chain_tip_b32)
            .ok_or_else(|| {
                DsmError::internal("chain_tip base32 decode failed", None::<std::io::Error>)
            })?;
        let mut dev_arr = [0u8; 32];
        dev_arr.copy_from_slice(&device_id_bytes[..32]);
        let mut tip_arr = [0u8; 32];
        tip_arr.copy_from_slice(&chain_tip_bytes[..32]);

        Self::b0x_id_for_device_with_salts(
            &local_genesis_bytes,
            &tip_arr,
            &dev_arr,
            &self.salt_genesis,
            &self.salt_device,
            nonce,
        )
        .await
    }

    pub async fn b0x_id_for_device(
        &mut self,
        recipient_genesis: &[u8; 32],
        chain_tip: &[u8; 32],
        device_id: &[u8; 32],
    ) -> Result<String, DsmError> {
        // Use nonce=0 for stable routing key
        let nonce = 0;
        Self::b0x_id_for_device_with_salts(
            recipient_genesis,
            chain_tip,
            device_id,
            &self.salt_genesis,
            &self.salt_device,
            nonce,
        )
        .await
    }

    pub async fn b0x_id_for_device_with_salts(
        recipient_genesis: &[u8; 32],
        chain_tip: &[u8; 32],
        device_id: &[u8; 32],
        salt_genesis: &[u8; 32],
        salt_device: &[u8; 32],
        nonce: u64,
    ) -> Result<String, DsmError> {
        // §16.4: Domain-separated blinded address components
        // h_G = BLAKE3("DSM/addr-G\0" || genesis || salt_genesis)
        let h_g = {
            let mut h =
                dsm::crypto::blake3::dsm_domain_hasher(dsm::common::domain_tags::TAG_DSM_ADDR_G);
            h.update(recipient_genesis);
            h.update(salt_genesis);
            h.finalize()
        };

        // h_D = BLAKE3("DSM/addr-D\0" || device_id || salt_device)
        let h_d = {
            let mut h =
                dsm::crypto::blake3::dsm_domain_hasher(dsm::common::domain_tags::TAG_DSM_ADDR_D);
            h.update(device_id);
            h.update(salt_device);
            h.finalize()
        };

        // h_T = BLAKE3("DSM/addr-T\0" || chain_tip || nonce)
        let h_t = {
            let mut h =
                dsm::crypto::blake3::dsm_domain_hasher(dsm::common::domain_tags::TAG_DSM_ADDR_T);
            h.update(chain_tip);
            h.update(&nonce.to_be_bytes());
            h.finalize()
        };

        let mut h = dsm::crypto::blake3::dsm_domain_hasher(dsm::common::domain_tags::TAG_DSM_B0X);
        h.update(h_g.as_bytes());
        h.update(h_d.as_bytes());
        h.update(h_t.as_bytes());
        let id = crate::util::text_id::encode_base32_crockford(h.finalize().as_bytes());
        Ok(id)
    }

    // ------------------------------------------------------------------------
    // Device registration / token management
    // ------------------------------------------------------------------------

    // ------------------------------------------------------------------------
    // §16.6 reply window (Envelope v3 over HTTP)
    // ------------------------------------------------------------------------

    /// Decode a §16.6 acceptance artifact from a spooled envelope, or `None` if
    /// this envelope is not one.
    ///
    /// Discrimination is on the EXPLICIT invoke method name, so a forward
    /// transfer can never be mistaken for a reply (and vice versa) — the "no
    /// trial-decode" rule holds even though both ride UniversalTx.
    ///
    /// Returns the raw `ArgPack.body`; nothing here is validated or trusted.
    /// The strict wire codec and the overlay onto the sender's OWN retained
    /// A-side bytes happen in the finalization path.
    pub(crate) fn decode_countersign_b(env: &dsm::types::proto::Envelope) -> Option<Vec<u8>> {
        let Some(dsm::types::proto::envelope::Payload::UniversalTx(tx)) = &env.payload else {
            return None;
        };
        for op in &tx.ops {
            let Some(dsm::types::proto::universal_op::Kind::Invoke(invoke)) = &op.kind else {
                continue;
            };
            if invoke.method != RECEIPT_COUNTERSIGN_B_METHOD {
                continue;
            }
            let Some(args) = &invoke.args else { continue };
            return Some(args.body.clone());
        }
        None
    }

    /// Decode an ADR 0003 A-side evidence half from a spooled envelope,
    /// discriminated on the EXPLICIT invoke method — never trial-decoded.
    ///
    /// Returning the artifact does NOT mean it is trustworthy: nothing here is
    /// verified. `full_receipt_bytes` and the digest it carries are unauthenticated
    /// wire data until the dispatcher checks them against the transfer half's
    /// reference, which is why this is a pure decoder with no side effects.
    pub(crate) fn decode_receipt_evidence_a(
        env: &dsm::types::proto::Envelope,
    ) -> Option<dsm::types::proto::ReceiptEvidenceA> {
        let Some(dsm::types::proto::envelope::Payload::UniversalTx(tx)) = &env.payload else {
            return None;
        };
        for op in &tx.ops {
            let Some(dsm::types::proto::universal_op::Kind::Invoke(invoke)) = &op.kind else {
                continue;
            };
            if invoke.method != RECEIPT_EVIDENCE_A_METHOD {
                continue;
            }
            let Some(args) = &invoke.args else { continue };
            match dsm::types::proto::ReceiptEvidenceA::decode(&*args.body) {
                Ok(a) => return Some(a),
                Err(e) => warn!("receipt evidence: artifact decode failed: {e}"),
            }
        }
        None
    }

    /// Drain the ADR 0003 evidence halves decoded by the most recent retrieve.
    ///
    /// Draining rather than cloning mirrors [`Self::take_countersign_deltas`], but the
    /// durable idempotency guarantee is different and lives downstream: staging is
    /// keyed on the transfer submission id, so a re-polled evidence half with the
    /// SAME bytes is idempotent and one with DIFFERENT bytes fails closed.
    pub fn take_evidence_artifacts(&mut self) -> Vec<dsm::types::proto::ReceiptEvidenceA> {
        std::mem::take(&mut self.pending_evidence_artifacts)
    }

    /// Drain the B-side countersign deltas decoded by the most recent retrieve.
    /// Draining (rather than cloning) keeps a re-poll from re-finalizing the
    /// same reply within one process lifetime; durable idempotency is enforced
    /// downstream by the proposal's terminal status.
    pub fn take_countersign_deltas(&mut self) -> Vec<CountersignDelta> {
        std::mem::take(&mut self.pending_countersign_deltas)
    }

    /// Decode a finality certificate from a spooled envelope, discriminated on
    /// the EXPLICIT invoke method — never trial-decoded. Returns the raw body;
    /// the strict wire codec and the signature check happen in the recipient's
    /// certificate handler.
    pub(crate) fn decode_relationship_finalized(
        env: &dsm::types::proto::Envelope,
    ) -> Option<Vec<u8>> {
        let Some(dsm::types::proto::envelope::Payload::UniversalTx(tx)) = &env.payload else {
            return None;
        };
        for op in &tx.ops {
            let Some(dsm::types::proto::universal_op::Kind::Invoke(invoke)) = &op.kind else {
                continue;
            };
            if invoke.method != RELATIONSHIP_FINALIZED_METHOD {
                continue;
            }
            let Some(args) = &invoke.args else { continue };
            return Some(args.body.clone());
        }
        None
    }

    /// Drain the finality certificates decoded by the most recent retrieve.
    /// Durable idempotency lives in the journal's `peer_finalized` flag.
    pub fn take_relationship_finalized(&mut self) -> Vec<RelationshipFinalizedMessage> {
        std::mem::take(&mut self.pending_relationship_finalized)
    }

    /// Build the `relationship.finalized.v1` envelope for an already-signed
    /// `RelationshipFinalizedV1` (finality barrier). PURE: every input is a
    /// parameter, so the bytes are byte-identical on rebuild — though the
    /// sender never rebuilds; it freezes THESE bytes at finalize and the sweep
    /// replays them. `message_id` = the artifact submission id (16 bytes
    /// derived from the certificate digest); `op_id` = the digest itself.
    /// Refuses at construction if over the node cap.
    pub(crate) fn build_relationship_finalized_envelope(
        local_device_id: &[u8; 32],
        local_genesis: &[u8; 32],
        certificate_wire: &[u8],
        certificate_digest: &[u8; 32],
        message_id_b32: &str,
    ) -> Result<BuiltEnvelope, DsmError> {
        use prost::Message as _;
        let local_device_bytes = local_device_id.to_vec();
        let msg_id_bytes = crate::util::text_id::decode_base32_crockford(message_id_b32)
            .filter(|m| m.len() == 16)
            .ok_or_else(|| {
                DsmError::invalid_parameter(
                    "build_relationship_finalized_envelope: message id must be base32(16)",
                )
            })?;
        let invoke = dsm::types::proto::Invoke {
            program: None,
            method: RELATIONSHIP_FINALIZED_METHOD.to_string(),
            args: Some(dsm::types::proto::ArgPack {
                schema_hash: None,
                codec: dsm::types::proto::Codec::Proto as i32,
                body: certificate_wire.to_vec(),
            }),
            cosigners: vec![],
            evidence: None,
            nonce: None,
        };
        let op = dsm::types::proto::UniversalOp {
            op_id: Some(dsm::types::proto::Hash32 {
                v: certificate_digest.to_vec(),
            }),
            actor: local_device_bytes.clone(),
            kind: Some(dsm::types::proto::universal_op::Kind::Invoke(invoke)),
        };
        let envelope = dsm::types::proto::Envelope {
            version: 3,
            headers: Some(dsm::types::proto::Headers {
                device_id: local_device_bytes,
                genesis_hash: local_genesis.to_vec(),
            }),
            message_id: msg_id_bytes,
            payload: Some(dsm::types::proto::envelope::Payload::UniversalTx(
                dsm::types::proto::UniversalTx {
                    ops: vec![op],
                    atomic: false,
                },
            )),
        };
        let mut buf = Vec::with_capacity(envelope.encoded_len());
        envelope.encode(&mut buf).map_err(|e| {
            DsmError::internal(
                format!("finality certificate envelope encode failed: {e}"),
                None::<std::io::Error>,
            )
        })?;
        if buf.len() >= MAX_B0X_ENVELOPE_BYTES {
            return Err(DsmError::invalid_parameter(format!(
                "build_relationship_finalized_envelope: encoded envelope is {} bytes, at or over \
                 the node's {MAX_B0X_ENVELOPE_BYTES}-byte cap",
                buf.len()
            )));
        }
        Ok(BuiltEnvelope {
            bytes: buf,
            message_id_b32: message_id_b32.to_string(),
            to_device_id_bytes: Vec::new(),
        })
    }

    /// Decode a cert-resync control message (method + framed body) from a spooled
    /// envelope, discriminated on the EXPLICIT invoke method — never trial-decoded.
    fn decode_cert_resync_message(env: &dsm::types::proto::Envelope) -> Option<(String, Vec<u8>)> {
        let Some(dsm::types::proto::envelope::Payload::UniversalTx(tx)) = &env.payload else {
            return None;
        };
        for op in &tx.ops {
            let Some(dsm::types::proto::universal_op::Kind::Invoke(invoke)) = &op.kind else {
                continue;
            };
            if invoke.method == crate::storage::client_db::CERT_RESYNC_REQUEST_METHOD
                || invoke.method == crate::storage::client_db::CERT_RESYNC_ACK_METHOD
            {
                if let Some(args) = &invoke.args {
                    return Some((invoke.method.clone(), args.body.clone()));
                }
            }
        }
        None
    }

    /// Drain cert-resync control messages decoded by the most recent retrieve.
    pub fn take_cert_resync_messages(&mut self) -> Vec<(String, Vec<u8>)> {
        std::mem::take(&mut self.pending_cert_resync)
    }

    /// Deliver the recipient's countersigned acceptance receipt BACK to the
    /// original sender, so the sender can finalize on cryptographic proof rather
    /// than on storage-node message deletion (which is best-effort GC only).
    ///
    /// ADDRESSING IS THE WHOLE GAME HERE. The reply must land on the address the
    /// SENDER polls, which it derives from ITS genesis, ITS device id, and the
    /// SYMMETRIC projection tip of the relationship. By the time the fold
    /// completes, the recipient's own projection has already advanced to the
    /// target, so `sender_projection_tip` MUST be the parent captured at PREPARE —
    /// never a local `contacts.chain_tip` read. Addressing from the advanced tip
    /// would spool the reply where nobody listens, reproducing the stranded-message
    /// failure this window exists to eliminate.
    ///
    /// Delivery is at-least-once and the payload is byte-identical on every
    /// attempt (the receipt is signed once, at prepare, and only replayed), so a
    /// duplicate is harmless: the sender's finalization is idempotent.
    /// Build the ADR 0003 return-leg envelope: the B-side countersign DELTA
    /// derived from the recipient's stored full countersigned receipt. PURE —
    /// no I/O, no ambient state; every input is a parameter, so two calls with
    /// the same inputs are byte-identical (the deterministic reply id relies on
    /// that: the node keeps the first body per message id).
    ///
    /// The delta carries the four B-side fields, two references (the
    /// commitment the sender looks its proposal up by, and the digest of the
    /// exact A-side bytes B countersigned) and the recipient's canonical pair
    /// `b_pair` for the applied step — read from the DURABLE journal/reply row
    /// by the caller, never from current state, because it is the pair `sig_b`
    /// was computed over. Nothing A-side rides back; the sender overlays this
    /// onto the receipt it authored and froze. Refuses at construction if the
    /// encoded envelope would not fit under the node cap — the same guard
    /// `build_evidence_envelope` applies.
    pub(crate) fn build_countersign_reply_envelope(
        &self,
        local_genesis: &[u8; 32],
        sender_projection_tip: &[u8; 32],
        expected_commitment: &[u8; 32],
        full_countersigned_receipt_bytes: &[u8],
        b_pair: ([u8; 32], [u8; 32]),
        release_bytes: &[u8],
    ) -> Result<BuiltEnvelope, DsmError> {
        use prost::Message as _;

        let local_device_bytes =
            crate::util::text_id::decode_base32_crockford(self.device_id.trim())
                .filter(|b| b.len() == 32)
                .ok_or_else(|| {
                    DsmError::invalid_parameter(
                        "build_countersign_reply_envelope: local device_id not base32(32)",
                    )
                })?;

        // The stored bytes must be the receipt this reply is for.
        let full = dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(
            full_countersigned_receipt_bytes,
        )
        .map_err(|e| {
            DsmError::invalid_parameter(format!(
                "build_countersign_reply_envelope: stored receipt does not decode: {e}"
            ))
        })?;
        let commitment = full.compute_commitment()?;
        if &commitment != expected_commitment {
            return Err(DsmError::invalid_parameter(
                "build_countersign_reply_envelope: stored receipt commitment != reply commitment",
            ));
        }
        let (a_side, b) = full.split_countersign_b().map_err(|e| {
            DsmError::invalid_parameter(format!("build_countersign_reply_envelope: {e}"))
        })?;
        // The exact A bytes B countersigned == what the sender froze at send.
        let a_bytes = a_side.to_full_protobuf()?;
        let digest_a = crate::storage::client_db::evidence_content_digest(
            crate::storage::client_db::ArtifactRole::EvidenceA,
            &a_bytes,
        );

        let body = dsm::types::proto::ReceiptCountersignB {
            commitment: commitment.to_vec(),
            receipt_evidence_digest_a: digest_a.to_vec(),
            sig_b: b.sig_b,
            ek_cert_b: b.ek_cert_b,
            ek_pk_b: b.ek_pk_b,
            kyber_ct_b: b.kyber_ct_b,
            b_parent_tip: b_pair.0.to_vec(),
            b_child_tip: b_pair.1.to_vec(),
            // 3.5b PR4: the post-admission RELEASE's content address — the
            // sender fetches the exact bytes re-hash-verified and finalizes
            // only on them. The reply is only deliverable once ECON_ADMITTED
            // promoted it, so a delta without a release is not an acceptance
            // the sender may act on.
            recipient_economic_release_addr: if release_bytes.is_empty() {
                Vec::new()
            } else {
                dsm::economic::release::recipient_economic_release_addr(release_bytes).to_vec()
            },
        }
        .encode_to_vec();
        // Content address of the delta itself, role-separated (op_id, as the
        // A-side builder does).
        let digest_b = crate::storage::client_db::evidence_content_digest(
            crate::storage::client_db::ArtifactRole::CountersignB,
            &body,
        );

        // Transport-local id: 16 opaque bytes derived from the transition's own
        // commitment (never wall-clock). Stable across reposts, so a redelivery
        // collapses onto the same spool row instead of piling up duplicates.
        let message_id_bytes = reply_message_id(&commitment, sender_projection_tip);
        let message_id_b32 = crate::util::text_id::encode_base32_crockford(&message_id_bytes);

        // CARRIER CHOICE (deliberate): storage nodes validate transport envelopes
        // against a COMPILED-IN allowlist of payload tags, so the delta rides
        // inside UniversalTx (an allowlisted tag) as an explicit
        // `receipt.countersign.b` invoke. Discrimination is by that method name
        // — structural, never a trial-decode.
        let invoke = dsm::types::proto::Invoke {
            program: None,
            method: RECEIPT_COUNTERSIGN_B_METHOD.to_string(),
            args: Some(dsm::types::proto::ArgPack {
                schema_hash: None,
                codec: dsm::types::proto::Codec::Proto as i32,
                body,
            }),
            cosigners: vec![],
            evidence: None,
            nonce: None,
        };
        let op = dsm::types::proto::UniversalOp {
            op_id: Some(dsm::types::proto::Hash32 {
                v: digest_b.to_vec(),
            }),
            actor: local_device_bytes.clone(),
            kind: Some(dsm::types::proto::universal_op::Kind::Invoke(invoke)),
        };
        let envelope = dsm::types::proto::Envelope {
            version: 3,
            headers: Some(dsm::types::proto::Headers {
                device_id: local_device_bytes,
                genesis_hash: local_genesis.to_vec(),
                // The tip this artifact is ADDRESSED to (the sender's projection
                // parent), so the receiving side can correlate the route it polled.
            }),
            message_id: message_id_bytes,
            payload: Some(dsm::types::proto::envelope::Payload::UniversalTx(
                dsm::types::proto::UniversalTx {
                    ops: vec![op],
                    atomic: false,
                },
            )),
        };
        let mut buf = Vec::with_capacity(envelope.encoded_len());
        envelope.encode(&mut buf).map_err(|e| {
            DsmError::internal(
                format!("reply envelope encode failed: {e}"),
                None::<std::io::Error>,
            )
        })?;
        if buf.len() >= MAX_B0X_ENVELOPE_BYTES {
            return Err(DsmError::invalid_parameter(format!(
                "build_countersign_reply_envelope: encoded envelope is {} bytes, at or over the \
                 node's {MAX_B0X_ENVELOPE_BYTES}-byte envelope cap; it could never be \
                 delivered — the B-side delta must carry exactly two SPHINCS+-sized objects",
                buf.len()
            )));
        }
        info!(
            "build_countersign_reply_envelope: {} bytes ({}% of cap) msg={}..",
            buf.len(),
            100 * buf.len() / MAX_B0X_ENVELOPE_BYTES,
            &message_id_b32[..8.min(message_id_b32.len())],
        );
        Ok(BuiltEnvelope {
            bytes: buf,
            message_id_b32,
            to_device_id_bytes: Vec::new(),
        })
    }

    /// The local genesis, from AppState when populated, otherwise from the
    /// durable genesis record. Errors rather than encoding an empty genesis —
    /// an envelope built without one would differ byte-for-byte from a later
    /// rebuild under the SAME deterministic message id.
    async fn resolve_local_genesis(&self) -> Result<[u8; 32], DsmError> {
        let from_state =
            crate::sdk::app_state::AppState::get_genesis_hash().filter(|g| g.len() == 32);
        let bytes = match from_state {
            Some(g) => g,
            None => self.core_sdk.local_genesis_hash().await?,
        };
        <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| DsmError::state("local genesis hash unavailable or not 32 bytes"))
    }

    /// ADR 0003 return leg: deliver the B-side countersign delta for
    /// `full_countersigned_receipt_bytes` to the sender's b0x route.
    ///
    /// The recipient keeps the whole countersigned receipt locally; ONLY the
    /// delta goes on the wire (`build_countersign_reply_envelope`). Delivery
    /// success is the SAME quorum rule as frozen sends (`delivered >= K`): a
    /// lost delta strands both sides — the sender's gate and, under the
    /// finality barrier, the recipient's own next origination — so one replica
    /// taking it is not delivery.
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_acceptance_reply(
        &mut self,
        sender_genesis: &[u8; 32],
        sender_device_id: &[u8; 32],
        sender_projection_tip: &[u8; 32],
        commitment: &[u8; 32],
        full_countersigned_receipt_bytes: &[u8],
        b_pair: ([u8; 32], [u8; 32]),
        release_bytes: &[u8],
    ) -> Result<String, DsmError> {
        let routing_key =
            Self::compute_b0x_address(sender_genesis, sender_device_id, sender_projection_tip)?;
        let local_genesis = self.resolve_local_genesis().await?;
        let built = self.build_countersign_reply_envelope(
            &local_genesis,
            sender_projection_tip,
            commitment,
            full_countersigned_receipt_bytes,
            b_pair,
            release_bytes,
        )?;
        self.post_reply_envelope(&routing_key, sender_device_id, &built)
            .await
    }

    /// Seal an already-built reply envelope for `recipient_device` and deliver
    /// it; success is `quorum_k` members answering 204.
    async fn post_reply_envelope(
        &mut self,
        routing_key: &str,
        recipient_device: &[u8; 32],
        built: &BuiltEnvelope,
    ) -> Result<String, DsmError> {
        let sealed = seal_for(recipient_device, &built.message_id_b32, &built.bytes)?;
        self.deliver(
            routing_key,
            &built.message_id_b32,
            &sealed,
            &B0xRetryConfig::default(),
        )
        .await
        .map_err(|e| {
            DsmError::network(format!("§16.6 reply delivery: {e}"), None::<std::io::Error>)
        })?;
        Ok(built.message_id_b32.clone())
    }

    /// Deliver sealed spool bytes under `routing_key` until `quorum_k`
    /// members answered 204. Every member may be asked — those the circuit
    /// breaker marks failed last — so the bar is the register quorum whatever
    /// the breaker holds: a member the breaker skipped would otherwise lower
    /// the count delivery must reach.
    async fn deliver(
        &mut self,
        routing_key: &str,
        message_id_b32: &str,
        sealed: &[u8],
        retry_config: &B0xRetryConfig,
    ) -> Result<(), DsmError> {
        let quorum = self.quorum_k;
        let total = self.storage_node_endpoints.len();
        if total < quorum {
            return Err(DsmError::network(
                format!(
                    "delivery needs {quorum} members and the fleet names {total};                      msg_id={message_id_b32}"
                ),
                None::<std::io::Error>,
            ));
        }
        let mut healthy = Vec::with_capacity(total);
        let mut marked_failed = Vec::new();
        for endpoint in &self.storage_node_endpoints {
            if self.circuit_breaker.is_node_healthy(endpoint).await {
                healthy.push(endpoint.clone());
            } else {
                marked_failed.push(endpoint.clone());
            }
        }
        let mut delivered = 0usize;
        let mut errors: Vec<String> = Vec::new();
        for endpoint in healthy.into_iter().chain(marked_failed) {
            match self
                .submit_with_retry(&endpoint, sealed, routing_key, message_id_b32, retry_config)
                .await
            {
                Ok(()) => {
                    delivered += 1;
                    if delivered >= quorum {
                        info!(
                            "✅ delivered {}.. to {}/{} (K={}) route={}..",
                            &message_id_b32[..8.min(message_id_b32.len())],
                            delivered,
                            total,
                            quorum,
                            &routing_key[..8.min(routing_key.len())]
                        );
                        return Ok(());
                    }
                }
                Err(e) => errors.push(format!("{endpoint}: {e}")),
            }
        }
        Err(DsmError::network(
            format!(
                "delivery below quorum: {delivered}/{total} (K={quorum}); msg_id={message_id_b32}; \
                 errors={errors:?}"
            ),
            None::<std::io::Error>,
        ))
    }

    /// Submit a cert-resync control message (an explicit `invoke.method` with the
    /// framed body in `ArgPack.body`) addressed to the recipient's b0x route. Rides
    /// the SAME allowlisted UniversalTx tag as everything else — no new payload tag,
    /// no fleet redeploy. Mirrors `submit_acceptance_reply`'s carrier choice.
    ///
    /// NOTE ON PAIDK: the deployed fleet does not currently enforce the PaidK gate
    /// on submit; the structural exemption (a recovery message must never depend on
    /// the spend authority it restores) is tracked as node-side follow-up.
    pub async fn submit_cert_resync_message(
        &mut self,
        method: &str,
        body: Vec<u8>,
        recipient_genesis: &[u8; 32],
        recipient_device: &[u8; 32],
        recipient_tip: &[u8; 32],
    ) -> Result<String, DsmError> {
        use prost::Message as _;
        let routing_key =
            Self::compute_b0x_address(recipient_genesis, recipient_device, recipient_tip)?;

        // Deterministic transport id from method + route + a digest of the body.
        let message_id_bytes = certresync_message_id(method, recipient_tip, &body);
        let message_id_b32 = crate::util::text_id::encode_base32_crockford(&message_id_bytes);

        let local_device_bytes =
            crate::util::text_id::decode_base32_crockford(self.device_id.trim())
                .filter(|b| b.len() == 32)
                .ok_or_else(|| {
                    DsmError::invalid_parameter(
                        "submit_cert_resync: local device_id not base32(32)",
                    )
                })?;
        let local_genesis = self.resolve_local_genesis().await?.to_vec();

        let invoke = dsm::types::proto::Invoke {
            program: None,
            method: method.to_string(),
            args: Some(dsm::types::proto::ArgPack {
                schema_hash: None,
                codec: 0,
                body,
            }),
            cosigners: vec![],
            evidence: None,
            nonce: None,
        };
        let op = dsm::types::proto::UniversalOp {
            op_id: Some(dsm::types::proto::Hash32 {
                v: message_id_bytes.clone(),
            }),
            actor: local_device_bytes.clone(),
            kind: Some(dsm::types::proto::universal_op::Kind::Invoke(invoke)),
        };
        let envelope = dsm::types::proto::Envelope {
            version: 3,
            headers: Some(dsm::types::proto::Headers {
                device_id: local_device_bytes,
                genesis_hash: local_genesis,
            }),
            message_id: message_id_bytes,
            payload: Some(dsm::types::proto::envelope::Payload::UniversalTx(
                dsm::types::proto::UniversalTx {
                    ops: vec![op],
                    atomic: false,
                },
            )),
        };
        let mut buf = Vec::with_capacity(envelope.encoded_len());
        envelope.encode(&mut buf).map_err(|e| {
            DsmError::internal(
                format!("cert-resync envelope encode failed: {e}"),
                None::<std::io::Error>,
            )
        })?;
        let sealed = seal_for(recipient_device, &message_id_b32, &buf)?;
        self.deliver(
            &routing_key,
            &message_id_b32,
            &sealed,
            &B0xRetryConfig::default(),
        )
        .await
        .map_err(|e| {
            DsmError::network(
                format!("cert-resync {method} delivery: {e}"),
                None::<std::io::Error>,
            )
        })?;
        Ok(message_id_b32)
    }

    // ------------------------------------------------------------------------
    // Submission (Envelope v3 over HTTP)
    // ------------------------------------------------------------------------

    /// Build the FINAL canonical envelope bytes for `params` without sending
    /// anything. Used by the send path to freeze the exact wire artifact into
    /// the durable outbox before any network call.
    pub async fn submit_to_b0x(&mut self, params: B0xSubmissionParams) -> Result<String, DsmError> {
        self.submit_to_b0x_with_retry(params, &B0xRetryConfig::default())
            .await
    }

    /// Submit to b0x with configurable retry logic and enhanced validation
    pub async fn submit_to_b0x_with_retry(
        &mut self,
        params: B0xSubmissionParams,
        retry_config: &B0xRetryConfig,
    ) -> Result<String, DsmError> {
        self.submit_inner(params, retry_config).await
    }

    /// PURE envelope construction — no network capability, by type.
    ///
    /// Takes `&self` and returns bytes. It cannot submit, retry, or touch the
    /// circuit breaker, and a future edit cannot make it do so without changing
    /// this signature. That is the point: the durable outbox freezes the exact
    /// wire bytes BEFORE anything is deliverable, so the builder must be
    /// callable from inside a synchronous, pre-commit context.
    /// Build the frozen wire bytes for an A-side receipt-evidence artifact
    /// (ADR 0003).
    ///
    /// Deliberately NOT routed through `build_envelope_for_submission`: that
    /// builder dispatches on `params.transaction`, and evidence is not an
    /// `Operation`. Inventing a fake variant to satisfy it would put a
    /// non-operation into the operation type purely for transport convenience.
    ///
    /// Enforces the artifact budget at CONSTRUCTION. CI already asserts the
    /// accepted shapes fit, but production must not cheerfully build an
    /// artifact the peer can never accept -- a 413 at submit time is a far
    /// worse place to learn this than a hard error here.
    pub(crate) fn build_evidence_envelope(
        &self,
        recipient_device_id: &str,
        recipient_genesis_hash: &str,
        transfer_submission_id: &str,
        evidence_submission_id: &str,
        evidence_digest: &[u8; 32],
        full_receipt_bytes: &[u8],
    ) -> Result<BuiltEnvelope, DsmError> {
        // The artifact must be self-consistent before it is frozen.
        let recomputed = crate::storage::client_db::evidence_content_digest(
            crate::storage::client_db::ArtifactRole::EvidenceA,
            full_receipt_bytes,
        );
        if &recomputed != evidence_digest {
            return Err(DsmError::internal(
                "build_evidence_envelope: digest does not match full_receipt_bytes",
                None::<std::io::Error>,
            ));
        }

        let self_device_bytes = crate::util::text_id::decode_base32_crockford(&self.device_id)
            .ok_or_else(|| {
                DsmError::invalid_parameter("build_evidence_envelope: device_id must be base32")
            })?;
        let recipient_bytes = crate::util::text_id::decode_base32_crockford(recipient_device_id)
            .ok_or_else(|| {
                DsmError::invalid_parameter("build_evidence_envelope: recipient must be base32")
            })?;
        let genesis_bytes = crate::util::text_id::decode_base32_crockford(recipient_genesis_hash)
            .ok_or_else(|| {
            DsmError::invalid_parameter("build_evidence_envelope: recipient genesis must be base32")
        })?;
        let msg_id_bytes = crate::util::text_id::decode_base32_crockford(evidence_submission_id)
            .ok_or_else(|| {
                DsmError::invalid_parameter(
                    "build_evidence_envelope: evidence submission id must be base32",
                )
            })?;
        if msg_id_bytes.len() != 16 {
            return Err(DsmError::invalid_parameter(format!(
                "build_evidence_envelope: message id must be 16 bytes, got {}",
                msg_id_bytes.len()
            )));
        }

        let body = dsm::types::proto::ReceiptEvidenceA {
            transfer_submission_id: transfer_submission_id.to_string(),
            receipt_evidence_digest: evidence_digest.to_vec(),
            full_receipt_bytes: full_receipt_bytes.to_vec(),
        };
        let mut body_bytes = Vec::with_capacity(body.encoded_len());
        body.encode(&mut body_bytes).map_err(|e| {
            DsmError::internal(
                format!("ReceiptEvidenceA encode failed: {e}"),
                None::<std::io::Error>,
            )
        })?;

        let arg_pack = dsm::types::proto::ArgPack {
            schema_hash: None,
            codec: dsm::types::proto::Codec::Proto as i32,
            body: body_bytes,
        };
        let invoke = dsm::types::proto::Invoke {
            program: None,
            method: RECEIPT_EVIDENCE_A_METHOD.to_string(),
            args: Some(arg_pack),
            cosigners: vec![],
            evidence: None,
            nonce: None,
        };
        let envelope = dsm::types::proto::Envelope {
            version: 3,
            headers: Some(dsm::types::proto::Headers {
                device_id: self_device_bytes.clone(),
                genesis_hash: genesis_bytes,
            }),
            message_id: msg_id_bytes,
            payload: Some(dsm::types::proto::envelope::Payload::UniversalTx(
                dsm::types::proto::UniversalTx {
                    ops: vec![dsm::types::proto::UniversalOp {
                        op_id: Some(dsm::types::proto::Hash32 {
                            v: evidence_digest.to_vec(),
                        }),
                        actor: self_device_bytes.clone(),
                        kind: Some(dsm::types::proto::universal_op::Kind::Invoke(invoke)),
                    }],
                    atomic: true,
                },
            )),
        };

        let mut buf = Vec::with_capacity(envelope.encoded_len());
        prost::Message::encode(&envelope, &mut buf).map_err(|e| {
            DsmError::internal(
                format!("evidence Envelope encode failed: {e}"),
                None::<std::io::Error>,
            )
        })?;

        if buf.len() >= MAX_B0X_ENVELOPE_BYTES {
            return Err(DsmError::internal(
                format!(
                    "build_evidence_envelope: artifact is {} bytes, at or over the storage \
                     node's {MAX_B0X_ENVELOPE_BYTES}-byte envelope cap; it could never be \
                     accepted. Split the evidence rather than raising the cap (ADR 0003).",
                    buf.len()
                ),
                None::<std::io::Error>,
            ));
        }

        info!(
            "build_evidence_envelope: {} bytes ({}% of cap)",
            buf.len(),
            100 * buf.len() / MAX_B0X_ENVELOPE_BYTES
        );

        Ok(BuiltEnvelope {
            bytes: buf,
            message_id_b32: evidence_submission_id.to_string(),
            to_device_id_bytes: recipient_bytes,
        })
    }

    fn build_envelope_for_submission(
        &self,
        params: &B0xSubmissionParams,
    ) -> Result<BuiltEnvelope, DsmError> {
        info!("🎯 submit_to_b0x_with_retry");

        // Enhanced input validation
        self.validate_submission_params(params)?;

        // 2) Build Envelope v3 with proper request payload.
        //
        // MESSAGE ID. A caller-supplied deterministic id WINS and short-circuits
        // the random derivation entirely — the fallback is never evaluated, so a
        // deterministic send consumes no OS entropy. The supplied id comes from the receipt
        // commitment (`sender_outbox::derive_submission_id`), so it is known
        // before the send is committed locally and is identical on every retry;
        // storage nodes enforce `UNIQUE(message_id)`, making a resend collapse
        // onto the same spool row instead of spooling a duplicate.
        let (message_id_bytes, message_id_b32) = match params.submission_id.as_deref() {
            Some(supplied) => {
                let decoded = text_id::decode_base32_crockford(supplied).ok_or_else(|| {
                    DsmError::invalid_parameter("submission_id must be canonical base32 Crockford")
                })?;
                let arr: [u8; 16] = decoded.as_slice().try_into().map_err(|_| {
                    DsmError::invalid_parameter(format!(
                        "submission_id must decode to 16 bytes (deployed nodes enforce this), got {}",
                        decoded.len()
                    ))
                })?;
                (arr, supplied.to_string())
            }
            // Legacy random derivation, for callers with no durable identity to
            // key on (non-transfer submissions). Retries here are NOT idempotent
            // at the node — each attempt spools a distinct row.
            None => {
                let mut rand_bytes = [0u8; 16];
                let mut os_rng = OsRng;
                rand::TryRngCore::try_fill_bytes(&mut os_rng, &mut rand_bytes).map_err(|e| {
                    DsmError::crypto(
                        format!("OsRng entropy failure: {e}"),
                        None::<std::io::Error>,
                    )
                })?;
                let mut msgid_buf = Vec::with_capacity(16 + self.device_id.len());
                msgid_buf.extend_from_slice(&rand_bytes);
                msgid_buf.extend_from_slice(self.device_id.as_bytes());
                let full = dsm::crypto::blake3::domain_hash(
                    dsm::common::domain_tags::TAG_DSM_B0X_MSGID,
                    &msgid_buf,
                );
                let mut b = [0u8; 16];
                b.copy_from_slice(&full.as_bytes()[..16]);
                let b32 = text_id::encode_base32_crockford(&b);
                (b, b32)
            }
        };
        let actor_device_bytes = crate::util::text_id::decode_base32_crockford(&self.device_id)
            .ok_or_else(|| {
                DsmError::internal("device_id base32 decode failed", None::<std::io::Error>)
            })?;
        let sender_tip_bytes = if params.sender_chain_tip.is_empty() {
            Vec::new()
        } else {
            crate::util::text_id::decode_base32_crockford(&params.sender_chain_tip).ok_or_else(
                || {
                    DsmError::internal(
                        "sender_chain_tip base32 decode failed",
                        None::<std::io::Error>,
                    )
                },
            )?
        };

        enum SubmitOp {
            Transfer {
                to_device_id_bytes: Vec<u8>,
                amount: u64,
                token_id: String,
                memo: String,
                nonce_bytes: Vec<u8>,
            },
            Message {
                to_device_id_bytes: Vec<u8>,
                payload: Vec<u8>,
                memo: String,
                nonce_bytes: Vec<u8>,
            },
        }

        let submit_op = match &params.transaction {
            Operation::Transfer {
                to_device_id,
                amount,
                token_id,
                message,
                nonce,
                ..
            } => {
                info!(
                    "🔍 submit_to_b0x: to_device_id raw bytes (first 8): {:?}",
                    &to_device_id[..8.min(to_device_id.len())]
                );
                SubmitOp::Transfer {
                    to_device_id_bytes: to_device_id.clone(),
                    amount: amount.value(),
                    token_id: String::from_utf8_lossy(token_id).into_owned(),
                    memo: message.clone(),
                    nonce_bytes: nonce.clone(),
                }
            }
            Operation::Generic {
                operation_type,
                data,
                message,
                ..
            } if operation_type.as_slice() == b"online.message" => {
                let to_device_id_bytes =
                    crate::util::text_id::decode_base32_crockford(&params.recipient_device_id)
                        .ok_or_else(|| {
                            DsmError::internal(
                                "submit_to_b0x: recipient_device_id base32 decode failed",
                                None::<std::io::Error>,
                            )
                        })?;
                let exact_32 = |bytes: &[u8], what: &str| -> Result<[u8; 32], DsmError> {
                    <[u8; 32]>::try_from(bytes).map_err(|_| {
                        DsmError::invalid_parameter(format!(
                            "submit_to_b0x: {what} is {} bytes, not 32",
                            bytes.len()
                        ))
                    })
                };
                let from_arr = exact_32(&actor_device_bytes, "the sender device id")?;
                let to_arr = exact_32(&to_device_id_bytes, "the recipient device id")?;
                let tip_arr = exact_32(&sender_tip_bytes, "the sender chain tip")?;
                let nonce_arr = dsm::envelope::compute_online_message_nonce_v3(
                    &from_arr, &to_arr, &tip_arr, data, message,
                );
                SubmitOp::Message {
                    to_device_id_bytes,
                    payload: data.clone(),
                    memo: message.clone(),
                    nonce_bytes: nonce_arr.to_vec(),
                }
            }
            _ => {
                return Err(DsmError::internal(
                    "submit_to_b0x: expected Operation::Transfer or online.message",
                    None::<std::io::Error>,
                ));
            }
        };

        let (invoke_method, arg_pack, to_device_id_bytes, log_context) = match submit_op {
            SubmitOp::Transfer {
                to_device_id_bytes,
                amount,
                token_id,
                memo,
                nonce_bytes,
            } => {
                let transfer_req = dsm::types::proto::OnlineTransferRequest {
                    token_id: token_id.clone(),
                    to_device_id: to_device_id_bytes.clone(),
                    amount,
                    memo: memo.clone(),
                    signature: params.signature.clone(),
                    nonce: nonce_bytes.clone(),
                    from_device_id: actor_device_bytes.clone(),
                    canonical_operation_bytes: params.canonical_operation_bytes.clone(),
                    receipt_evidence_digest: params.receipt_evidence_digest.clone(),
                    sender_economic_position: params.sender_economic_position,
                    sender_debit_mutation_index: params.sender_debit_mutation_index,
                };
                info!(
                    "submit_to_b0x: transfer req context from_device_id(first4)={:?}",
                    &transfer_req.from_device_id[..4.min(transfer_req.from_device_id.len())],
                );

                let mut transfer_req_bytes = Vec::with_capacity(transfer_req.encoded_len());
                transfer_req.encode(&mut transfer_req_bytes).map_err(|e| {
                    DsmError::internal(
                        format!("OnlineTransferRequest encode failed: {e}"),
                        None::<std::io::Error>,
                    )
                })?;
                let arg_pack = dsm::types::proto::ArgPack {
                    schema_hash: None,
                    codec: dsm::types::proto::Codec::Proto as i32,
                    body: transfer_req_bytes.clone(),
                };
                let decoded_req = dsm::types::proto::OnlineTransferRequest::decode(&*arg_pack.body)
                    .map_err(|e| {
                        DsmError::serialization_error(
                            "decode transfer req",
                            "OnlineTransferRequest",
                            None::<String>,
                            Some(e),
                        )
                    })?;
                debug!(
                    "submit_to_b0x: decoded OnlineTransferRequest signature len={}",
                    decoded_req.signature.len()
                );
                assert_eq!(decoded_req.signature, params.signature);

                (
                    "wallet.send".to_string(),
                    arg_pack,
                    to_device_id_bytes,
                    format!("amount={}, token={}", amount, token_id),
                )
            }
            SubmitOp::Message {
                to_device_id_bytes,
                payload,
                memo,
                nonce_bytes,
            } => {
                let msg_req = dsm::types::proto::OnlineMessageRequest {
                    to_device_id: to_device_id_bytes.clone(),
                    payload: payload.clone(),
                    memo: memo.clone(),
                    signature: params.signature.clone(),
                    nonce: nonce_bytes.clone(),
                    from_device_id: actor_device_bytes.clone(),
                    chain_tip: sender_tip_bytes.clone(),
                };
                let mut msg_req_bytes = Vec::with_capacity(msg_req.encoded_len());
                msg_req.encode(&mut msg_req_bytes).map_err(|e| {
                    DsmError::internal(
                        format!("OnlineMessageRequest encode failed: {e}"),
                        None::<std::io::Error>,
                    )
                })?;
                let arg_pack = dsm::types::proto::ArgPack {
                    schema_hash: None,
                    codec: dsm::types::proto::Codec::Proto as i32,
                    body: msg_req_bytes.clone(),
                };
                let decoded_req = dsm::types::proto::OnlineMessageRequest::decode(&*arg_pack.body)
                    .map_err(|e| {
                        DsmError::serialization_error(
                            "decode message req",
                            "OnlineMessageRequest",
                            None::<String>,
                            Some(e),
                        )
                    })?;
                debug!(
                    "submit_to_b0x: decoded OnlineMessageRequest signature len={}",
                    decoded_req.signature.len()
                );
                assert_eq!(decoded_req.signature, params.signature);

                (
                    "message.send".to_string(),
                    arg_pack,
                    to_device_id_bytes,
                    format!("payload_len={}", payload.len()),
                )
            }
        };

        // Build Invoke with method="wallet.send"
        // IMPORTANT: SPHINCS+ signatures are large (~50KB). The canonical sender
        // signature already lives in OnlineTransferRequest.signature / OnlineMessageRequest.signature.
        // Do NOT duplicate that signature into EvidenceOracle.signature for b0x transport,
        // or envelopes can exceed storage-node body limits (HTTP 413).
        // Keep only oracle_key in evidence so receivers can still verify without extra lookups.
        //
        // Source of truth: signing_authority derives the pk deterministically from
        // (genesis_hash, device_id, C-DBRW binding key) — the SAME derivation that
        // produces the secret key used by `wallet.sign_operation_bytes`. Embedding
        // this pk guarantees the receiver's sphincs_verify uses the same pk that
        // produced the signature; using `state.device_info.public_key` or
        // `AppState::get_public_key()` can drift (stale genesis pk, fallback
        // 32-byte placeholder, etc.) and silently poison the inbox.
        // DEADLOCK: the fallback here used to be `self.core_sdk.get_current_state()`,
        // which takes the `state_machine` lock (core_sdk.rs:420). This builder runs
        // inside `pre_write`, where that NON-REENTRANT parking_lot mutex is ALREADY
        // held (core_sdk.rs:1116). Re-locking it hangs silently — no panic, no error.
        //
        // The caller has already resolved this key fail-closed, so prefer the value
        // it handed us over re-deriving one. That removes the re-entry AND removes a
        // live source of public-key drift: the param was previously length-validated
        // and then ignored.
        let sender_signing_public_key = match crate::sdk::signing_authority::current_public_key() {
            Ok(pk) => pk,
            Err(e) if !params.sender_signing_public_key.is_empty() => {
                log::warn!(
                    "submit_to_b0x: signing_authority pk unavailable ({e}); using caller-supplied \
                     sender_signing_public_key"
                );
                params.sender_signing_public_key.clone()
            }
            Err(e) => {
                log::warn!(
                    "submit_to_b0x: signing_authority pk unavailable ({e}) and caller supplied \
                     none; falling back to persisted app-state pk"
                );
                crate::sdk::app_state::AppState::get_public_key().unwrap_or_default()
            }
        };

        let evidence = if !sender_signing_public_key.is_empty() {
            Some(dsm::types::proto::Evidence {
                kind: Some(dsm::types::proto::evidence::Kind::Oracle(
                    dsm::types::proto::EvidenceOracle {
                        payload: vec![],
                        signature: vec![],
                        // Carry sender signing public key so receivers can verify without contact lookups.
                        oracle_key: sender_signing_public_key.clone(),
                    },
                )),
            })
        } else {
            None
        };

        let invoke = dsm::types::proto::Invoke {
            program: None,
            method: invoke_method,
            args: Some(arg_pack),
            cosigners: vec![],
            evidence,
            nonce: None,
        };

        // Build UniversalOp with the Invoke.
        //
        // §16.6 defect zero: use the sender genesis ALREADY carried (and
        // validated as base32(32)) in `params` rather than an async DB read.
        // That keeps envelope construction fully SYNCHRONOUS, which is the
        // precondition for building it inside the staged advance closure — the
        // closure runs under the state-machine lock and cannot await.
        let local_genesis_bytes = text_id::decode_base32_crockford(&params.sender_genesis_hash)
            .filter(|b| b.len() == 32)
            .ok_or_else(|| {
                DsmError::invalid_parameter(
                    "sender_genesis_hash must be base32 Crockford of exactly 32 bytes",
                )
            })?;
        // AF-4 fix: routing MUST be keyed by the *sender's* current relationship parent tip (hn)
        // (whitepaper: b0x key rotates with hn; sender posts to the key derived from the live parent)
        // Do NOT use a cached/stale recipient tip for routing.
        let op = dsm::types::proto::UniversalOp {
            op_id: Some(dsm::types::proto::Hash32 {
                v: message_id_bytes.to_vec(),
            }),
            actor: actor_device_bytes.clone(),
            kind: Some(dsm::types::proto::universal_op::Kind::Invoke(invoke)),
        };

        let universal_tx = dsm::types::proto::UniversalTx {
            ops: vec![op],
            atomic: false,
        };

        let envelope = dsm::types::proto::Envelope {
            version: 3,
            headers: Some(dsm::types::proto::Headers {
                device_id: actor_device_bytes,
                genesis_hash: local_genesis_bytes.to_vec(),
            }),
            message_id: message_id_bytes.to_vec(),
            payload: Some(dsm::types::proto::envelope::Payload::UniversalTx(
                universal_tx,
            )),
        };

        info!("📦 submit_to_b0x: envelope built with {}", log_context);

        let mut buf = Vec::with_capacity(envelope.encoded_len());
        prost::Message::encode(&envelope, &mut buf).map_err(|e| {
            DsmError::internal(
                format!("Envelope encode failed: {e}"),
                None::<std::io::Error>,
            )
        })?;
        info!("submit_to_b0x: envelope bytes={}", buf.len());
        Ok(BuiltEnvelope {
            bytes: buf,
            message_id_b32,
            to_device_id_bytes: to_device_id_bytes.to_vec(),
        })
    }

    /// Build the exact canonical wire bytes without transmitting them.
    /// Synchronous: freezing bytes into the durable outbox must not require an
    /// async context.
    pub fn build_envelope_bytes(
        &self,
        params: &B0xSubmissionParams,
    ) -> Result<(Vec<u8>, String), DsmError> {
        let built = self.build_envelope_for_submission(params)?;
        Ok((built.bytes, built.message_id_b32))
    }

    /// Submit: build the envelope, then replicate it to quorum.
    async fn submit_inner(
        &mut self,
        params: B0xSubmissionParams,
        retry_config: &B0xRetryConfig,
    ) -> Result<String, DsmError> {
        let BuiltEnvelope {
            bytes: buf,
            message_id_b32,
            to_device_id_bytes,
        } = self.build_envelope_for_submission(&params)?;

        // The recipient the operation names is the one the envelope is sealed
        // for and addressed to; params naming another is a malformed send.
        let recipient = decode_base32_32("recipient_device_id", params.recipient_device_id.trim())?;
        if recipient.as_slice() != to_device_id_bytes.as_slice() {
            return Err(DsmError::invalid_operation(
                "submit_to_b0x: the recipient the params name is not the one the operation names",
            ));
        }
        // §16.4: the inbox key is always the explicit rotated address.
        let routing_key = params.routing_address.clone();
        let sealed = seal_for(&recipient, &message_id_b32, &buf)?;
        self.deliver(&routing_key, &message_id_b32, &sealed, retry_config)
            .await?;
        Ok(message_id_b32)
    }

    /// §16.6 defect zero — submit the EXACT bytes frozen in the durable outbox:
    /// the seal the send path made and kept when it froze them
    /// ([`seal_for`]). No envelope reconstruction, so retry identity cannot
    /// drift if envelope-building code changes across upgrades, and the
    /// deterministic `message_id` makes the node collapse duplicates onto one
    /// spool row.
    pub async fn submit_stored_envelope(
        &mut self,
        routing_address: &str,
        message_id_b32: &str,
    ) -> Result<(), DsmError> {
        self.submit_stored_envelope_with_retry(
            routing_address,
            message_id_b32,
            &B0xRetryConfig::default(),
        )
        .await
    }

    /// The bounded time this transport call can take, derived from its own
    /// retry schedule rather than guessed by the caller.
    ///
    /// Sequential per-endpoint attempts, each with up to `max_retries` retries
    /// and exponential backoff capped at `max_delay_ms`. Callers that need to
    /// bound a stored-envelope submission use THIS, so an outer deadline can
    /// never expire before the quorum algorithm has legitimately exhausted the
    /// configured fleet — that would manufacture `submission_uncertain` out of a
    /// still-viable attempt.
    ///
    /// The per-request timeout is not modelled here (it is a property of the
    /// HTTP client, not the retry config); the small fixed margin absorbs it.
    pub fn stored_envelope_deadline(&self, retry: &B0xRetryConfig) -> std::time::Duration {
        let mut per_endpoint_ms: u64 = 0;
        let mut delay = std::time::Duration::from_millis(retry.base_delay_ms);
        for _ in 0..retry.max_retries {
            per_endpoint_ms += delay.as_millis() as u64;
            delay = std::cmp::min(
                delay.mul_f64(retry.backoff_multiplier),
                std::time::Duration::from_millis(retry.max_delay_ms),
            );
        }
        let endpoints = self.storage_node_endpoints.len().max(1) as u64;
        // Attempts themselves are not free: allow a generous per-attempt margin
        // on top of the sleeps, per endpoint, plus a fixed floor.
        let per_attempt_margin_ms: u64 = 5_000 * (retry.max_retries as u64 + 1);
        std::time::Duration::from_millis(
            (per_endpoint_ms + per_attempt_margin_ms) * endpoints + 5_000,
        )
    }

    /// `submit_stored_envelope` with an explicit retry schedule. The schedule
    /// is what bounds the call — see `stored_envelope_deadline`.
    pub async fn submit_stored_envelope_with_retry(
        &mut self,
        routing_address: &str,
        message_id_b32: &str,
        retry: &B0xRetryConfig,
    ) -> Result<(), DsmError> {
        let sealed = kept_seal(message_id_b32)?;
        self.deliver(routing_address, message_id_b32, &sealed, retry)
            .await
    }

    /// Deliver ONE frozen logical send — the transfer envelope plus every
    /// frozen outbound artifact — under the ids and route it was frozen with.
    ///
    /// This is the single delivery path for both the first attempt in
    /// `wallet.send` and the recovery sweep. Having one path is the point: the
    /// initial send used to submit only the transfer and discard the ADR 0003
    /// evidence, and the recovery sweep did not exist, so a split send could
    /// never be completed by any code that ran. Two callers, one operation over
    /// the same frozen bytes.
    ///
    /// Invariants, all enforced here and nowhere else:
    ///
    ///  - **No rebuilding.** Only `envelope_bytes` from the durable rows are
    ///    sent. Nothing is re-encoded from current state.
    ///  - **No route derivation.** Every artifact — transfer and evidence alike
    ///    — is submitted under the OWNING outbox's frozen `routing_address`.
    ///    An artifact's `content_digest` names its bytes; it never selects a
    ///    route. Replaying the same message id under a different recipient is
    ///    not a relocation: the node dedups on `message_id` alone and would
    ///    silently keep the first row while returning success.
    ///  - **All or nothing.** `Ok` only when every submission reached quorum.
    ///    Any failure returns `Err`, and the caller leaves the logical send
    ///    `submission_uncertain` so the next sweep replays the whole frozen
    ///    set. Replaying an already-accepted half is free (deterministic id +
    ///    node `DO NOTHING`), which is why no half-delivery lifecycle exists.
    ///  - **The transport owns its deadline.** No outer timeout is imposed;
    ///    the retry schedule bounds each submission (`stored_envelope_deadline`).
    ///
    /// Order is transfer first, then artifacts in role order. Correctness does
    /// not depend on it — the recipient stages whichever half lands first — but
    /// determinism makes logs and tests legible.
    pub async fn deliver_frozen_logical_send(
        &mut self,
        outbox: &crate::storage::client_db::SenderOutboxRecord,
        artifacts: &[crate::storage::client_db::SenderOutboxArtifact],
        retry: &B0xRetryConfig,
    ) -> Result<FrozenSendDelivery, DsmError> {
        let route = outbox.routing_address.as_str();

        self.submit_stored_envelope_with_retry(route, &outbox.submission_id, retry)
            .await
            .map_err(|e| {
                DsmError::internal(
                    format!(
                        "frozen send {}: transfer half not delivered: {e}",
                        outbox.submission_id
                    ),
                    None::<std::io::Error>,
                )
            })?;

        let mut artifact_ids = Vec::with_capacity(artifacts.len());
        for artifact in artifacts {
            // Only initial-send artifacts ride the transfer's route. A received
            // countersign delta or the finality certificate (own route, own
            // sweep) reaching this primitive is a caller bug — refuse, never
            // relocate it under a route the node would silently dedup.
            if !artifact.role.is_initial_send_artifact() {
                return Err(DsmError::internal(
                    format!(
                        "frozen send {}: artifact role {} is not part of the initial send",
                        outbox.submission_id,
                        artifact.role.as_str()
                    ),
                    None::<std::io::Error>,
                ));
            }
            self.submit_stored_envelope_with_retry(route, &artifact.submission_id, retry)
                .await
                .map_err(|e| {
                    DsmError::internal(
                        format!(
                            "frozen send {}: {} artifact {} not delivered: {e}",
                            outbox.submission_id,
                            artifact.role.as_str(),
                            artifact.submission_id
                        ),
                        None::<std::io::Error>,
                    )
                })?;
            artifact_ids.push(artifact.submission_id.clone());
        }

        info!(
            "✅ frozen logical send delivered: transfer={} artifacts={} route={}..",
            outbox.submission_id,
            artifact_ids.len(),
            &route[..route.len().min(12)]
        );
        Ok(FrozenSendDelivery {
            transfer_id: outbox.submission_id.clone(),
            artifact_ids,
        })
    }

    /// Submit sealed spool bytes to a single endpoint with retry logic. The
    /// node answers 204 once it holds them; a replay of a held message id
    /// answers the same.
    async fn submit_with_retry(
        &mut self,
        endpoint: &str,
        sealed: &[u8],
        routing_key: &str,
        message_id_b32: &str,
        retry_config: &B0xRetryConfig,
    ) -> Result<(), DsmError> {
        let url = format!("{}/api/v2/b0x/submit", endpoint);
        let mut attempt = 0;
        let mut delay = std::time::Duration::from_millis(retry_config.base_delay_ms);
        loop {
            let resp = self
                .http_client
                .post(&url)
                .header("Content-Type", "application/protobuf")
                .header("x-dsm-message-id", message_id_b32)
                .header("x-dsm-recipient", routing_key)
                .body(sealed.to_vec())
                .send()
                .await;
            let retryable = match resp {
                Ok(r) if r.status() == reqwest::StatusCode::NO_CONTENT => {
                    self.circuit_breaker.mark_node_healthy(endpoint).await;
                    return Ok(());
                }
                Ok(r) => {
                    let status = r.status();
                    let body = match r.text().await {
                        Ok(text) => text,
                        Err(e) => format!("(body unreadable: {e})"),
                    };
                    warn!("Submit failed {} via {}: {}", status, endpoint, body);
                    self.circuit_breaker.mark_node_failed(endpoint).await;
                    if !Self::is_retryable_error(status) {
                        return Err(DsmError::network(
                            format!("Submit failed {status} via {endpoint}: {body}"),
                            None::<std::io::Error>,
                        ));
                    }
                    format!("{status}: {body}")
                }
                Err(e) => {
                    warn!("HTTP error via {}: {}", endpoint, e);
                    self.circuit_breaker.mark_node_failed(endpoint).await;
                    e.to_string()
                }
            };
            if attempt >= retry_config.max_retries {
                return Err(DsmError::network(
                    format!(
                        "submit via {endpoint} failed after {} attempts: {retryable}",
                        attempt + 1
                    ),
                    None::<std::io::Error>,
                ));
            }
            attempt += 1;
            tokio::time::sleep(delay).await;
            delay = std::cmp::min(
                delay.mul_f64(retry_config.backoff_multiplier),
                std::time::Duration::from_millis(retry_config.max_delay_ms),
            );
        }
    }

    /// Validate submission parameters comprehensively
    fn validate_submission_params(&self, params: &B0xSubmissionParams) -> Result<(), DsmError> {
        // Validate recipient device ID
        if params.recipient_device_id.is_empty() {
            return Err(DsmError::internal(
                "recipient_device_id cannot be empty",
                None::<std::io::Error>,
            ));
        }
        if !base32_decodes_to_32_bytes(&params.recipient_device_id) {
            return Err(DsmError::internal(
                "recipient_device_id must be valid base32 encoding of 32 bytes",
                None::<std::io::Error>,
            ));
        }

        // Validate recipient genesis hash
        if params.recipient_genesis_hash.is_empty() {
            return Err(DsmError::internal(
                "recipient_genesis_hash cannot be empty",
                None::<std::io::Error>,
            ));
        }
        if !base32_decodes_to_32_bytes(&params.recipient_genesis_hash) {
            return Err(DsmError::internal(
                "recipient_genesis_hash must be valid base32 encoding of 32 bytes",
                None::<std::io::Error>,
            ));
        }

        // Validate sender genesis hash
        if params.sender_genesis_hash.is_empty() {
            return Err(DsmError::internal(
                "sender_genesis_hash cannot be empty",
                None::<std::io::Error>,
            ));
        }
        if !base32_decodes_to_32_bytes(&params.sender_genesis_hash) {
            return Err(DsmError::internal(
                "sender_genesis_hash must be valid base32 encoding of 32 bytes",
                None::<std::io::Error>,
            ));
        }

        // Validate sender chain tip
        if params.sender_chain_tip.is_empty() {
            return Err(DsmError::internal(
                "sender_chain_tip cannot be empty",
                None::<std::io::Error>,
            ));
        }
        if !base32_decodes_to_32_bytes(&params.sender_chain_tip) {
            return Err(DsmError::internal(
                "sender_chain_tip must be valid base32 encoding of 32 bytes",
                None::<std::io::Error>,
            ));
        }

        if params.routing_address.is_empty() {
            return Err(DsmError::internal(
                "routing_address cannot be empty",
                None::<std::io::Error>,
            ));
        }
        validate_b0x_address(&params.routing_address)?;

        // Validate operation
        match &params.transaction {
            dsm::types::operations::Operation::Transfer {
                to_device_id,
                amount,
                token_id,
                ..
            } => {
                if to_device_id.len() != 32 {
                    return Err(DsmError::internal(
                        "transfer to_device_id must be exactly 32 bytes",
                        None::<std::io::Error>,
                    ));
                }
                if amount.value() == 0 {
                    return Err(DsmError::internal(
                        "transfer amount cannot be zero",
                        None::<std::io::Error>,
                    ));
                }
                if token_id.is_empty() {
                    return Err(DsmError::internal(
                        "token_id cannot be empty",
                        None::<std::io::Error>,
                    ));
                }
            }
            dsm::types::operations::Operation::Generic {
                operation_type,
                data,
                ..
            } if operation_type.as_slice() == b"online.message" => {
                if data.is_empty() {
                    return Err(DsmError::internal(
                        "online.message payload cannot be empty",
                        None::<std::io::Error>,
                    ));
                }
                if data.len() > 4096 {
                    return Err(DsmError::internal(
                        "online.message payload exceeds 4096 bytes",
                        None::<std::io::Error>,
                    ));
                }
            }
            _ => {
                return Err(DsmError::internal(
                    "only Transfer or online.message operations are supported for b0x submission",
                    None::<std::io::Error>,
                ));
            }
        }

        // Validate signature if present
        if !params.signature.is_empty() && params.signature.len() < 64 {
            return Err(DsmError::internal(
                "signature must be at least 64 bytes if present",
                None::<std::io::Error>,
            ));
        }

        // Validate sender public key if present
        if !params.sender_signing_public_key.is_empty()
            && params.sender_signing_public_key.len() != 64
        {
            return Err(DsmError::internal(
                "sender_signing_public_key must be exactly 64 bytes (SPHINCS+ public key)",
                None::<std::io::Error>,
            ));
        }

        Ok(())
    }

    /// Determine if an HTTP status code represents a retryable error
    fn is_retryable_error(status: reqwest::StatusCode) -> bool {
        matches!(
            status,
            reqwest::StatusCode::REQUEST_TIMEOUT
                | reqwest::StatusCode::TOO_MANY_REQUESTS
                | reqwest::StatusCode::INTERNAL_SERVER_ERROR
                | reqwest::StatusCode::BAD_GATEWAY
                | reqwest::StatusCode::SERVICE_UNAVAILABLE
                | reqwest::StatusCode::GATEWAY_TIMEOUT
        )
    }

    // ------------------------------------------------------------------------
    // v2 retrieval (Envelope v3 over HTTP)
    //
    // A node's spool is append-only and read from a position (storage spec
    // §4): it never marks, hides or removes a message. Which messages this
    // device has consumed is its own state (`client_db::b0x_consumed`): each
    // node is read from the position below which everything is consumed,
    // consumed messages are skipped, and the rest are merged across nodes.
    // ------------------------------------------------------------------------

    /// Pages read from one node in one retrieval: bounds the work per call.
    /// The next call continues from the stored position.
    const MAX_RETRIEVE_PAGES_PER_NODE: usize = 16;

    /// Read the spool at `b0x_address` from every member that answers. `Err`
    /// when no member answered: nothing was read, which is not an empty
    /// inbox. Otherwise the entries found and what the read covers
    /// ([`SpoolCoverage`]): a read that did not reach enough members to meet
    /// every delivery is partial, and no caller may take it for "nothing
    /// more".
    pub async fn retrieve_from_b0x_v2(
        &mut self,
        b0x_address: &str,
    ) -> Result<RetrievalOutcome, DsmError> {
        use crate::storage::client_db::b0x_consumed;
        let local = |e: anyhow::Error| {
            DsmError::storage(format!("b0x consumed record: {e}"), None::<std::io::Error>)
        };

        if b0x_address.is_empty() {
            return Err(DsmError::internal(
                "retrieve_from_b0x_v2 requires a rotated b0x address",
                None::<std::io::Error>,
            ));
        }
        validate_b0x_address(b0x_address)?;

        let mut endpoints: Vec<String> = Vec::new();
        for endpoint in &self.storage_node_endpoints {
            if self.circuit_breaker.is_node_healthy(endpoint).await {
                endpoints.push(endpoint.clone());
            }
        }
        if endpoints.is_empty() {
            return Err(DsmError::network(
                "b0x retrieve: every storage node is marked failed",
                None::<std::io::Error>,
            ));
        }

        let mut map: HashMap<String, dsm::types::proto::Envelope> = HashMap::new();
        // Members whose spool was read to an answer. None is not an empty
        // inbox: nothing was read (storage spec §4).
        let mut answered = 0usize;
        for epc in endpoints {
            // `position`: below it, everything on this node is consumed.
            // `cursor`: where the next page is read from. A message still
            // waiting (one half of a pair) stops `position`, never `cursor`,
            // so nothing behind it is held up.
            let mut position = b0x_consumed::read_position(b0x_address, &epc).map_err(local)?;
            let mut cursor = position;
            let mut consumed_run = true;
            let mut failed = false;
            let mut pages = 0;
            while pages < Self::MAX_RETRIEVE_PAGES_PER_NODE {
                pages += 1;
                let url = format!("{}/api/v2/b0x/retrieve/{}", epc, cursor);
                let resp = self
                    .http_client
                    .get(&url)
                    .header("Accept", "application/protobuf")
                    .header("x-dsm-b0x-address", b0x_address)
                    .send()
                    .await;
                let batch = match resp {
                    Ok(r) if r.status() == reqwest::StatusCode::NO_CONTENT => break,
                    Ok(r) if r.status().is_success() => {
                        let bytes = match r.bytes().await {
                            Ok(b) => b,
                            Err(e) => {
                                warn!("b0x retrieve read failed from {}: {}", epc, e);
                                failed = true;
                                break;
                            }
                        };
                        match dsm::types::proto::SequencedBatchEnvelope::decode(bytes.as_ref()) {
                            Ok(b) => b,
                            Err(e) => {
                                warn!("SequencedBatchEnvelope decode failed from {}: {}", epc, e);
                                failed = true;
                                break;
                            }
                        }
                    }
                    Ok(r) => {
                        warn!("b0x retrieve from {} answered HTTP {}", epc, r.status());
                        failed = true;
                        break;
                    }
                    Err(e) => {
                        warn!("b0x retrieve transport failure for {}: {}", epc, e);
                        failed = true;
                        break;
                    }
                };
                if batch.envelopes.is_empty() || batch.next_seq <= cursor {
                    break;
                }
                for sequenced in batch.envelopes {
                    // The node never opens what it holds (storage spec §8);
                    // this device decodes. Bytes that are not a canonical
                    // envelope never will be, so nothing waits on them.
                    let env = match dsm::envelope::from_canonical_bytes(&sequenced.envelope) {
                        Ok(env) => env,
                        Err(e) => {
                            warn!(
                                "b0x retrieve from {}: seq {} is not an envelope: {}",
                                epc, sequenced.seq_num, e
                            );
                            if consumed_run {
                                position = position.max(sequenced.seq_num + 1);
                            }
                            continue;
                        }
                    };
                    let id = text_id::encode_base32_crockford(&env.message_id);
                    if b0x_consumed::is_consumed(b0x_address, &id).map_err(local)? {
                        if consumed_run {
                            position = position.max(sequenced.seq_num + 1);
                        }
                    } else {
                        consumed_run = false;
                        // DSM Amendment A7: open the seal before anything reads
                        // the envelope. What does not open is not from this
                        // relationship's counterparty and is skipped.
                        match open_sealed(&env) {
                            Ok(inner) => {
                                map.entry(envelope_merge_key(&inner)).or_insert(inner);
                            }
                            Err(e) => warn!("b0x envelope {} does not open: {}", id, e),
                        }
                    }
                }
                cursor = batch.next_seq;
            }
            b0x_consumed::advance_read_position(b0x_address, &epc, position).map_err(local)?;
            if failed {
                self.circuit_breaker.mark_node_failed(&epc).await;
            } else {
                answered += 1;
                self.circuit_breaker.mark_node_healthy(&epc).await;
            }
        }
        if answered == 0 {
            return Err(DsmError::network(
                "b0x retrieve: no storage node answered; nothing was read",
                None::<std::io::Error>,
            ));
        }
        let members = self.storage_node_endpoints.len();
        let coverage = SpoolCoverage::of(answered, members, self.quorum_k);

        let mut entries = Vec::new();
        for env in map.into_values() {
            // §16.6 reply window: an acceptance artifact is NOT a forward transfer and
            // has no B0xEntry shape. It is discriminated by the EXPLICIT invoke method
            // (never a trial-decode) and buffered for the sender-finalization path;
            // dropping it here is what would strand a countersigned receipt.
            if let Some((method, body)) = Self::decode_cert_resync_message(&env) {
                info!(
                    "📬 cert-resync message method={} body={}B",
                    method,
                    body.len()
                );
                self.pending_cert_resync.push((method, body));
                continue;
            }
            if let Some(body) = Self::decode_countersign_b(&env) {
                info!(
                    "📬 ADR 0003 countersign delta message_id={} ({}B body)",
                    text_id::encode_base32_crockford(&env.message_id),
                    body.len()
                );
                self.pending_countersign_deltas.push(CountersignDelta {
                    message_id: text_id::encode_base32_crockford(&env.message_id),
                    envelope_bytes: env.encode_to_vec(),
                    body,
                });
                continue;
            }
            if let Some(body) = Self::decode_relationship_finalized(&env) {
                info!(
                    "📬 finality checkpoint message_id={} ({}B body)",
                    text_id::encode_base32_crockford(&env.message_id),
                    body.len()
                );
                self.pending_relationship_finalized
                    .push(RelationshipFinalizedMessage {
                        message_id: text_id::encode_base32_crockford(&env.message_id),
                        body,
                    });
                continue;
            }
            if let Some(evidence) = Self::decode_receipt_evidence_a(&env) {
                info!(
                    "📬 ADR 0003 evidence half for transfer={} ({}B receipt)",
                    evidence.transfer_submission_id,
                    evidence.full_receipt_bytes.len()
                );
                self.pending_evidence_artifacts.push(evidence);
                continue;
            }
            if let Some(mut e) = self.envelope_to_b0x_entry(env) {
                e.inbox_key = b0x_address.to_string();
                entries.push(e);
            }
        }
        info!(
            "📬 retrieve_from_b0x_v2: merged {} entries from {answered} of {members} members ({coverage:?})",
            entries.len()
        );
        Ok(RetrievalOutcome {
            entries,
            responded: answered,
            members,
            coverage,
        })
    }

    /// Record `message_ids` (base32 transport ids) as consumed from
    /// `b0x_address` — on this device only. A node is never told: its spool is
    /// append-only, and what this device has consumed is its own state. Call
    /// it for exactly the messages processed; a message left unrecorded is
    /// read again on the next retrieval.
    pub async fn record_consumed_b0x(
        &mut self,
        b0x_address: &str,
        message_ids: Vec<String>,
    ) -> Result<(), DsmError> {
        if message_ids.is_empty() {
            return Ok(());
        }
        validate_b0x_address(b0x_address)?;
        crate::storage::client_db::b0x_consumed::record_consumed(b0x_address, &message_ids).map_err(
            |e| {
                DsmError::storage(
                    format!("record consumed b0x messages: {e}"),
                    None::<std::io::Error>,
                )
            },
        )
    }

    // ------------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------------

    fn envelope_to_b0x_entry(&self, env: dsm::types::proto::Envelope) -> Option<B0xEntry> {
        let tid = text_id::encode_base32_crockford(&env.message_id);
        let (sender_dev, genesis_b32) = match &env.headers {
            Some(h) => (
                crate::util::text_id::encode_base32_crockford(&h.device_id),
                text_id::encode_base32_crockford(&h.genesis_hash),
            ),
            None => (String::new(), String::new()),
        };

        if let Some(dsm::types::proto::envelope::Payload::UniversalTx(tx)) = &env.payload {
            for op in &tx.ops {
                if let Some(dsm::types::proto::universal_op::Kind::Invoke(invoke)) = &op.kind {
                    if invoke.method == "wallet.send" {
                        if let Some(ref arg_pack) = invoke.args {
                            if let Ok(transfer_req) =
                                dsm::types::proto::OnlineTransferRequest::decode(&*arg_pack.body)
                            {
                                if transfer_req.nonce.len() != 32 {
                                    log::warn!(
                                        "📥 envelope_to_b0x_entry: nonce len={} (expected 32)",
                                        transfer_req.nonce.len()
                                    );
                                }

                                let recipient_id =
                                    text_id::encode_base32_crockford(&transfer_req.to_device_id);

                                // Capture sender signing public key from Evidence.oracle.oracle_key if present
                                let sender_pk = match &invoke.evidence {
                                    Some(ev) => match &ev.kind {
                                        Some(dsm::types::proto::evidence::Kind::Oracle(oracle)) => {
                                            oracle.oracle_key.clone()
                                        }
                                        _ => Vec::new(),
                                    },
                                    None => Vec::new(),
                                };

                                info!(
                                    "📥 envelope_to_b0x_entry: extracted Transfer (amount={}, to={})",
                                    transfer_req.amount, recipient_id
                                );
                                return Some(B0xEntry {
                                    // Verbatim, from the SAME buffer the decode read.
                                    transfer_wire_bytes: arg_pack.body.clone(),
                                    receipt_evidence_digest: transfer_req
                                        .receipt_evidence_digest
                                        .clone(),
                                    transaction_id: tid,
                                    inbox_key: String::new(),
                                    sender_device_id: sender_dev,
                                    sender_genesis_hash: genesis_b32,
                                    recipient_device_id: recipient_id,
                                    kind: B0xEntryKind::Transfer {
                                        amount: transfer_req.amount,
                                        token_id: transfer_req.token_id.clone(),
                                    },
                                    sender_signing_public_key: sender_pk,
                                    canonical_operation_bytes: transfer_req
                                        .canonical_operation_bytes
                                        .clone(),
                                });
                            }
                        }
                    } else if invoke.method == "message.send" {
                        if let Some(ref arg_pack) = invoke.args {
                            if let Ok(msg_req) =
                                dsm::types::proto::OnlineMessageRequest::decode(&*arg_pack.body)
                            {
                                let recipient_id =
                                    text_id::encode_base32_crockford(&msg_req.to_device_id);
                                let sender_pk = match &invoke.evidence {
                                    Some(ev) => match &ev.kind {
                                        Some(dsm::types::proto::evidence::Kind::Oracle(oracle)) => {
                                            oracle.oracle_key.clone()
                                        }
                                        _ => Vec::new(),
                                    },
                                    None => Vec::new(),
                                };

                                info!(
                                    "📥 envelope_to_b0x_entry: extracted OnlineMessage (payload_len={}, to={})",
                                    msg_req.payload.len(),
                                    recipient_id,
                                );
                                return Some(B0xEntry {
                                    // This branch decoded an OnlineMessageRequest, not a
                                    // transfer: there is no transfer half and no evidence
                                    // reference, so both stay empty and the split path
                                    // can never mistake a message for a half.
                                    transfer_wire_bytes: Vec::new(),
                                    receipt_evidence_digest: Vec::new(),
                                    transaction_id: tid,
                                    inbox_key: String::new(),
                                    sender_device_id: sender_dev,
                                    sender_genesis_hash: genesis_b32,
                                    recipient_device_id: recipient_id,
                                    kind: B0xEntryKind::Message {
                                        payload_len: msg_req.payload.len(),
                                    },
                                    sender_signing_public_key: sender_pk,
                                    canonical_operation_bytes: Vec::new(),
                                });
                            }
                        }
                    }
                }
            }
        }

        None
    }
}

// -------------------------------
// Tests
// -------------------------------
#[cfg(test)]
#[allow(clippy::disallowed_methods, clippy::useless_conversion)]
mod tests {

    /// IMPACT-TABLE ROWS B5 and B6, asserted in both directions.
    ///
    /// Both derive a spool message id. The double-NUL spelling carried its own
    /// NUL into `dsm_domain_hasher`, which appends another, so its preimage
    /// began `"…id" || 0x00 || 0x00`; it is reconstructed below to show the
    /// id moved.
    #[test]
    fn b5_and_b6_message_ids_moved_off_the_double_nul_digest() {
        fn old_id(tag_with_nul: &[u8], parts: &[&[u8]]) -> Vec<u8> {
            let mut h = blake3::Hasher::new();
            h.update(tag_with_nul); // the literal, NUL included
            h.update(&[0u8]); // the helper's appended NUL
            for p in parts {
                h.update(p);
            }
            h.finalize().as_bytes()[..16].to_vec()
        }
        fn canonical_id(tag: &[u8], parts: &[&[u8]]) -> Vec<u8> {
            let mut h = blake3::Hasher::new();
            h.update(tag);
            h.update(&[0u8]);
            for p in parts {
                h.update(p);
            }
            h.finalize().as_bytes()[..16].to_vec()
        }

        // B5
        let commitment = [0xA1u8; 32];
        let tip = [0xB2u8; 32];
        let b5 = super::reply_message_id(&commitment, &tip);
        assert_ne!(
            b5,
            old_id(b"DSM/b0x-reply-message-id\0", &[&commitment, &tip]),
            "B5 still produces the doubled-NUL id"
        );
        assert_eq!(
            b5,
            canonical_id(b"DSM/b0x-reply-message-id", &[&commitment, &tip]),
            "B5 did not land on the canonical id"
        );
        assert_eq!(b5.len(), 16, "the spool id is 16 truncated bytes");

        // B6
        let method = "cert.resync";
        let rtip = [0xC3u8; 32];
        let body = [0xD4u8; 48];
        let b6 = super::certresync_message_id(method, &rtip, &body);
        assert_ne!(
            b6,
            old_id(
                b"DSM/b0x-certresync-message-id\0",
                &[method.as_bytes(), &rtip, &body]
            ),
            "B6 still produces the doubled-NUL id"
        );
        assert_eq!(
            b6,
            canonical_id(
                b"DSM/b0x-certresync-message-id",
                &[method.as_bytes(), &rtip, &body]
            ),
            "B6 did not land on the canonical id"
        );

        // The two domains stay separated from each other.
        assert_ne!(b5, b6, "B5 and B6 must not share an id space");
    }

    /// The property the ids exist for, preserved across the cut: a repost of the
    /// same logical message derives the SAME id, so a redelivery collapses onto
    /// one spool row rather than piling up.
    #[test]
    fn a_repost_still_derives_the_same_spool_id() {
        let c = [0x11u8; 32];
        let t = [0x22u8; 32];
        assert_eq!(
            super::reply_message_id(&c, &t),
            super::reply_message_id(&c, &t)
        );
        assert_ne!(
            super::reply_message_id(&c, &t),
            super::reply_message_id(&c, &[0x23u8; 32]),
            "a different projection tip must give a different id"
        );
    }

    /// Cross-endpoint merge must not be first-responder-wins.
    ///
    /// Because spool ids are deterministic, a merge keyed on `message_id` alone
    /// let ONE replica serving a tampered copy shadow every honest copy, on every
    /// poll, forever. That is what made a bad acceptance artifact unrecoverable:
    /// the corrected copy existed on other replicas and could never be seen.
    #[test]
    fn divergent_copies_of_one_message_id_do_not_shadow_each_other() {
        // `genesis_hash` stands in for "the bytes a middlebox could alter": any
        // encoded-byte difference under one message id must survive the merge.
        let envelope = |message_id: &[u8; 16], content: u8| dsm::types::proto::Envelope {
            version: 3,
            headers: Some(dsm::types::proto::Headers {
                device_id: vec![0x11; 32],
                genesis_hash: vec![content; 32],
            }),
            message_id: message_id.to_vec(),
            payload: None,
        };
        let (id1, id2) = (&[0xA1u8; 16], &[0xB2u8; 16]);

        // Identical replicas of the same message still collapse: the honest
        // multi-replica case is unchanged.
        assert_eq!(
            super::envelope_merge_key(&envelope(id1, 0xAA)),
            super::envelope_merge_key(&envelope(id1, 0xAA)),
            "identical replicas must still merge to one entry"
        );

        // A tampered copy under the SAME id gets its own key, so both survive the
        // merge and the consumer can reject one and accept the other.
        assert_ne!(
            super::envelope_merge_key(&envelope(id1, 0xAA)),
            super::envelope_merge_key(&envelope(id1, 0xBB)),
            "two copies that disagree under one message id must BOTH survive"
        );

        // The message id is still part of the key -- identical bytes under
        // different ids remain distinct messages.
        assert_ne!(
            super::envelope_merge_key(&envelope(id1, 0xAA)),
            super::envelope_merge_key(&envelope(id2, 0xAA)),
        );
    }
    use super::*;

    /// A device with a real identity, over a fresh database: its device id
    /// and its `CoreSDK`.
    /// A device created as wallet creation creates it, with its fleet
    /// running and configured.
    fn test_device() -> (String, Arc<CoreSDK>, crate::test_support::one_device::Fleet) {
        let (identity, core) = crate::economic_fixtures::local_device(0x11);
        (
            crate::util::text_id::encode_base32_crockford(&identity.device_id),
            Arc::new(core),
            crate::test_support::one_device::Fleet::start(),
        )
    }

    use std::sync::Arc;

    #[test]
    fn test_b0x_id_generation() {
        // Use domain-separated salt derivation per §16.4
        let device_id = [0x33u8; 32];
        let salt_g = B0xSDK::derive_salt(b"DSM/b0x-salt-G", &device_id);
        let salt_d = B0xSDK::derive_salt(b"DSM/b0x-salt-D", &device_id);
        let recipient_genesis = [0x11u8; 32];
        let chain_tip = [0x22u8; 32];
        let id = futures::executor::block_on(B0xSDK::b0x_id_for_device_with_salts(
            &recipient_genesis,
            &chain_tip,
            &device_id,
            &salt_g,
            &salt_d,
            0,
        ))
        .unwrap();
        assert!(base32_decodes_to_32_bytes(&id));
    }

    #[test]
    fn test_salts_are_domain_separated() {
        let dev = [0xAAu8; 32];
        let salt_g = B0xSDK::derive_salt(b"DSM/b0x-salt-G", &dev);
        let salt_d = B0xSDK::derive_salt(b"DSM/b0x-salt-D", &dev);
        // Different domain tags must produce different salts
        assert_ne!(salt_g, salt_d, "genesis and device salts must differ");
    }

    #[test]
    fn test_salts_vary_per_device() {
        let dev_a = [0x01u8; 32];
        let dev_b = [0x02u8; 32];
        let salt_a = B0xSDK::derive_salt(b"DSM/b0x-salt-G", &dev_a);
        let salt_b = B0xSDK::derive_salt(b"DSM/b0x-salt-G", &dev_b);
        // Different devices must produce different salts (correlation resistance)
        assert_ne!(salt_a, salt_b, "salts must vary per device");
    }

    #[test]
    fn test_address_components_domain_separated() {
        // Verify that address components use different domain tags
        let data = [0x11u8; 32];
        let salt = [0x33u8; 32];

        // h_G uses "DSM/addr-G"
        let h_g = {
            let mut h =
                dsm::crypto::blake3::dsm_domain_hasher(dsm::common::domain_tags::TAG_DSM_ADDR_G);
            h.update(&data);
            h.update(&salt);
            *h.finalize().as_bytes()
        };
        // h_D uses "DSM/addr-D" with SAME input data
        let h_d = {
            let mut h =
                dsm::crypto::blake3::dsm_domain_hasher(dsm::common::domain_tags::TAG_DSM_ADDR_D);
            h.update(&data);
            h.update(&salt);
            *h.finalize().as_bytes()
        };
        // Even with identical data, different domain tags must produce different results
        assert_ne!(
            h_g, h_d,
            "domain tags must differentiate address components"
        );
    }

    #[test]
    fn test_compute_b0x_address_rotation() {
        let genesis = dsm::crypto::rng::generate_secure_random(32).expect("rand");
        let device = dsm::crypto::rng::generate_secure_random(32).expect("rand");
        let tip1 = dsm::crypto::rng::generate_secure_random(32).expect("rand");
        let tip2 = dsm::crypto::rng::generate_secure_random(32).expect("rand");

        let a1 = B0xSDK::compute_b0x_address(&genesis, &device, &tip1).expect("ok");
        let a2 = B0xSDK::compute_b0x_address(&genesis, &device, &tip2).expect("ok");
        assert_ne!(a1, a2, "addresses must rotate when tip changes");
        assert_eq!(a1.len(), 52, "expected 52 base32 chars for 32-byte digest");
        assert!(base32_decodes_to_32_bytes(&a1));
        assert!(base32_decodes_to_32_bytes(&a2));
    }

    #[test]
    fn test_compute_b0x_address_matches_domain_hashed_formula() {
        let genesis = [0x11u8; 32];
        let device = [0x22u8; 32];
        let tip = [0x33u8; 32];

        let actual = B0xSDK::compute_b0x_address(&genesis, &device, &tip).expect("ok");

        let h_g = B0xSDK::hash_b0x_component(dsm::tagged_domain!(b"DSM/b0x-G"), &genesis);
        let h_d = B0xSDK::hash_b0x_component(dsm::tagged_domain!(b"DSM/b0x-D"), &device);
        let h_t = B0xSDK::hash_b0x_component(dsm::tagged_domain!(b"DSM/b0x-T"), &tip);

        let mut hasher =
            dsm::crypto::blake3::dsm_domain_hasher(dsm::common::domain_tags::TAG_DSM_B0X);
        hasher.update(&h_g);
        hasher.update(&h_d);
        hasher.update(&h_t);
        let expected = crate::util::text_id::encode_base32_crockford(hasher.finalize().as_bytes());

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_compute_b0x_address_allowed_chars() {
        let genesis = [0u8; 32];
        let device = [1u8; 32];
        let tip = [2u8; 32];
        let a = B0xSDK::compute_b0x_address(&genesis, &device, &tip).expect("ok");
        assert_eq!(a.len(), 52);
        for ch in a.chars() {
            assert!(
                "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(ch),
                "invalid char {}",
                ch
            );
        }
    }

    #[test]
    fn test_compute_b0x_address_for_optional_tip_rejects_missing_tip() {
        let genesis = [7u8; 32];
        let device = [8u8; 32];
        let err = B0xSDK::compute_b0x_address_for_optional_tip(&genesis, &device, None)
            .expect_err("missing tip must fail");
        assert!(
            err.to_string().contains("relationship tip is required"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_compute_b0x_address_for_optional_tip_rejects_invalid_tip() {
        let genesis = [9u8; 32];
        let device = [10u8; 32];
        let invalid_tip = [11u8; 16];
        let err =
            B0xSDK::compute_b0x_address_for_optional_tip(&genesis, &device, Some(&invalid_tip))
                .expect_err("invalid tip must fail");
        assert!(
            err.to_string()
                .contains("relationship tip must be exactly 32 bytes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_validate_b0x_address_rejects_legacy_bracketed_format() {
        let legacy = "b0x[TEST][TEST][TEST]";
        assert!(validate_b0x_address(legacy).is_err());
    }

    #[tokio::test]
    async fn test_circuit_breaker() {
        let cb = CircuitBreaker::new();
        let ep = "http://node";
        assert!(cb.is_node_healthy(ep).await);
        cb.mark_node_failed(ep).await;
        assert!(!cb.is_node_healthy(ep).await);
        cb.mark_node_healthy(ep).await;
        assert!(cb.is_node_healthy(ep).await);
    }

    #[test]
    #[serial_test::serial]
    fn test_sdk_new_scans_tokens() {
        // Construct without endpoints just to call new()
        let (device_id, core, fleet) = test_device();
        let sdk = B0xSDK::new(device_id.clone(), core, fleet.endpoints()).unwrap();
        assert_eq!(sdk.device_id(), &device_id);
    }

    #[test]
    #[serial_test::serial]
    fn test_sdk_new_rejects_dotted_decimal_device_id() {
        let device = test_device();
        let res = B0xSDK::new("1.2.3.4".to_string(), device.1, device.2.endpoints());
        assert!(res.is_err());
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_envelope_to_b0x_entry_names_the_requested_transfer(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (device_b32, core, fleet) = test_device();
        let sdk = B0xSDK::new(device_b32, core, fleet.endpoints()).unwrap();

        // Build an OnlineTransferRequest with an embedded signature
        let transfer_req = dsm::types::proto::OnlineTransferRequest {
            token_id: "ERA".to_string(),
            to_device_id: vec![0x11; 32],
            amount: 42,
            memo: "test".to_string(),
            signature: vec![1, 2, 3, 4, 5],
            nonce: vec![0xAA; 32],
            from_device_id: vec![0x22; 32],
            canonical_operation_bytes: vec![],
            receipt_evidence_digest: Vec::new(),
            sender_economic_position: 0,
            sender_debit_mutation_index: 0,
        };
        let mut transfer_req_bytes = Vec::with_capacity(transfer_req.encoded_len());
        transfer_req.encode(&mut transfer_req_bytes).map_err(|e| {
            DsmError::internal(
                format!("OnlineTransferRequest encode failed: {e}"),
                None::<std::io::Error>,
            )
        })?;

        // Build ArgPack directly (not serialized - passed as struct)
        let arg_pack = dsm::types::proto::ArgPack {
            schema_hash: None,
            codec: dsm::types::proto::Codec::Proto as i32,
            body: transfer_req_bytes.clone(),
        };

        let invoke = dsm::types::proto::Invoke {
            program: None,
            method: "wallet.send".to_string(),
            args: Some(arg_pack),
            cosigners: vec![],
            evidence: None,
            nonce: None,
        };

        let op = dsm::types::proto::UniversalOp {
            op_id: Some(dsm::types::proto::Hash32 { v: vec![9; 32] }),
            actor: vec![2; 32],
            kind: Some(dsm::types::proto::universal_op::Kind::Invoke(invoke)),
        };

        let env = dsm::types::proto::Envelope {
            version: 3,
            headers: Some(dsm::types::proto::Headers {
                device_id: vec![0xAB; 32],
                genesis_hash: vec![0; 32],
            }),
            message_id: vec![8; 16],
            payload: Some(dsm::types::proto::envelope::Payload::UniversalTx(
                dsm::types::proto::UniversalTx {
                    ops: vec![op],
                    atomic: true,
                },
            )),
        };

        let entry = sdk
            .envelope_to_b0x_entry(env)
            .expect("should extract B0xEntry");
        assert_eq!(
            entry.kind,
            B0xEntryKind::Transfer {
                amount: 42,
                token_id: "ERA".to_string()
            }
        );
        assert_eq!(entry.transfer_wire_bytes, transfer_req_bytes);
        Ok(())
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_envelope_to_b0x_entry_names_an_online_message(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (device_b32, core, fleet) = test_device();
        let sdk = B0xSDK::new(device_b32, core, fleet.endpoints()).unwrap();

        let payload = vec![1, 2, 3, 4, 5, 6];
        let memo = "hello".to_string();
        let msg_req = dsm::types::proto::OnlineMessageRequest {
            to_device_id: vec![0x11; 32],
            payload: payload.clone(),
            memo: memo.clone(),
            signature: vec![9, 9, 9],
            nonce: vec![0xAA; 32],
            from_device_id: vec![0x22; 32],
            chain_tip: vec![0x33; 32],
        };
        let mut msg_req_bytes = Vec::with_capacity(msg_req.encoded_len());
        msg_req.encode(&mut msg_req_bytes).map_err(|e| {
            DsmError::internal(
                format!("OnlineMessageRequest encode failed: {e}"),
                None::<std::io::Error>,
            )
        })?;

        let arg_pack = dsm::types::proto::ArgPack {
            schema_hash: None,
            codec: dsm::types::proto::Codec::Proto as i32,
            body: msg_req_bytes,
        };

        let invoke = dsm::types::proto::Invoke {
            program: None,
            method: "message.send".to_string(),
            args: Some(arg_pack),
            cosigners: vec![],
            evidence: None,
            nonce: None,
        };

        let op = dsm::types::proto::UniversalOp {
            op_id: Some(dsm::types::proto::Hash32 { v: vec![9; 32] }),
            actor: vec![2; 32],
            kind: Some(dsm::types::proto::universal_op::Kind::Invoke(invoke)),
        };

        let env = dsm::types::proto::Envelope {
            version: 3,
            headers: Some(dsm::types::proto::Headers {
                device_id: vec![0xAB; 32],
                genesis_hash: vec![0; 32],
            }),
            message_id: vec![8; 16],
            payload: Some(dsm::types::proto::envelope::Payload::UniversalTx(
                dsm::types::proto::UniversalTx {
                    ops: vec![op],
                    atomic: true,
                },
            )),
        };

        let entry = sdk
            .envelope_to_b0x_entry(env)
            .expect("should extract B0xEntry");

        assert_eq!(
            entry.recipient_device_id,
            crate::util::text_id::encode_base32_crockford(&[0x11u8; 32])
        );
        assert_eq!(
            entry.kind,
            B0xEntryKind::Message {
                payload_len: payload.len()
            }
        );

        Ok(())
    }

    // ==================================================================
    // WIRE BUDGET (ADR 0003) — real-size encoded artifacts must fit the
    // storage node's MAX_ENVELOPE_BYTES.
    //
    // These build PRODUCTION-SIZED cryptographic material and measure the
    // ACTUAL encoded `Envelope`, not inner structs. The node enforces the
    // cap with `RequestBodyLimitLayer::new(MAX_ENVELOPE_BYTES)` as its
    // OUTERMOST layer, so the wire message is what must fit — an inner
    // object that fits while its envelope does not still 413s.
    //
    // This budget was absent, which is why a 168,400-byte transfer reached
    // hardware and failed 413 on every fleet node, permanently: the outbox
    // freezes exact submitted bytes, so each retry replayed the same
    // oversized message.
    // ==================================================================

    /// The storage node's cap (`dsm_storage_node/src/api/transport/b0x.rs`).
    /// Duplicated deliberately: the client must not silently track a change
    /// to the node's limit.
    const NODE_MAX_ENVELOPE_BYTES: usize = 128 * 1024;

    /// Report a measured artifact against the budget. A wire-budget test whose
    /// numbers are invisible tells you it passed but not how close it came.
    fn report_budget(shape: &str, bytes: usize) {
        let pct = 100.0 * bytes as f64 / NODE_MAX_ENVELOPE_BYTES as f64;
        let headroom = NODE_MAX_ENVELOPE_BYTES as i64 - bytes as i64;
        println!(
            "[wire-budget] {shape:<34} {bytes:>8} bytes  {pct:5.1}% of cap  headroom {headroom:>8}"
        );
    }

    fn sphincs_sig_len() -> usize {
        dsm::crypto::sphincs::signature_bytes(dsm::crypto::sphincs::SphincsVariant::SPX256f)
    }

    /// Field sizes decoded from a REAL stuck envelope pulled off the bench rig
    /// (submission RX6BA3TY6KRDEBVXGXNCTHWVT0, 168,400 bytes). Using measured
    /// production values, not guesses, is the whole point of this budget.
    const REL_PROOF_LEN: usize = 8_261;
    const DEV_PROOF_LEN: usize = 9;
    const KYBER_CT_LEN: usize = 1_088;
    const EK_PK_LEN: usize = 64;
    const CANONICAL_OP_LEN: usize = 303;

    /// A production-sized one-way (A-side) ReceiptCommit.
    fn production_sized_receipt_a() -> Vec<u8> {
        let sig = sphincs_sig_len();
        let rc = dsm::types::proto::ReceiptCommit {
            genesis: vec![0x01; 32],
            devid_a: vec![0x02; 32],
            devid_b: vec![0x03; 32],
            parent_tip: vec![0x04; 32],
            child_tip: vec![0x05; 32],
            parent_root: vec![0x06; 32],
            child_root: vec![0x07; 32],
            // Canonical field 21 (Part VII step 3): the sender's transition
            // entropy, required at the wire since #934.
            transition_entropy: vec![0x0C; 32],
            rel_proof_parent: vec![0x08; REL_PROOF_LEN],
            dev_proof: vec![0x0A; DEV_PROOF_LEN],
            sig_a: vec![0xAA; sig],
            ek_cert_a: vec![0xCC; sig],
            ek_pk_a: vec![0xDD; EK_PK_LEN],
            kyber_ct_a: vec![0xEE; KYBER_CT_LEN],
            ..Default::default()
        };
        let mut out = Vec::with_capacity(rc.encoded_len());
        rc.encode(&mut out).expect("encode ReceiptCommit");
        out
    }

    /// Submission params carrying production-sized SIG A and canonical op bytes
    /// in the ADR 0003 split composition: no inline receipt, a 32-byte reference.
    fn params_split_shape() -> B0xSubmissionParams {
        let digest = evidence_content_digest_for_test();
        let mut p = params_base();
        p.receipt_evidence_digest = digest.to_vec();
        p
    }

    fn evidence_content_digest_for_test() -> [u8; 32] {
        crate::storage::client_db::evidence_content_digest(
            crate::storage::client_db::ArtifactRole::EvidenceA,
            &production_sized_receipt_a(),
        )
    }

    /// A production-shaped transfer submission (ADR 0003 split: no inline
    /// receipt; the evidence reference is set by `params_split_shape`).
    fn params_base() -> B0xSubmissionParams {
        B0xSubmissionParams {
            recipient_device_id: crate::util::text_id::encode_base32_crockford(&[0x44u8; 32]),
            recipient_genesis_hash: crate::util::text_id::encode_base32_crockford(&[0x55u8; 32]),
            transaction: dsm::types::operations::Operation::Transfer {
                to_device_id: vec![0x44; 32],
                amount: dsm::types::token_types::Balance::amount(100),
                token_id: b"ERA".to_vec(),
                policy_commit: [0x0F; 32],
                mode: dsm::types::operations::TransactionMode::Unilateral,
                nonce: vec![0x7E; 32],
                recipient: vec![0x44; 32],
                to: vec![0x44; 32],
                message: String::new(),
                signature: vec![0xA5; sphincs_sig_len()],
                authority_policy: None,
            },
            signature: vec![0xA5; sphincs_sig_len()],
            sender_genesis_hash: crate::util::text_id::encode_base32_crockford(&[0x66u8; 32]),
            sender_chain_tip: crate::util::text_id::encode_base32_crockford(&[0x77u8; 32]),
            sender_signing_public_key: vec![0x88; EK_PK_LEN],
            routing_address: crate::util::text_id::encode_base32_crockford(&[0xABu8; 32]),
            canonical_operation_bytes: vec![0xCD; CANONICAL_OP_LEN],
            receipt_evidence_digest: Vec::new(),
            submission_id: Some(crate::util::text_id::encode_base32_crockford(&[0xEFu8; 16])),
            sender_economic_position: 0,
            sender_debit_mutation_index: 0,
        }
    }

    /// THE FAN-OUT FOLLOWS THE REGISTER QUORUM, not the fleet size (#867): a
    /// send's transfer and its evidence each land on exactly K members of the
    /// pinned set, K the resolved profile's quorum, never on all of them.
    /// A delivery lands on `quorum_k` of `members`, so a read meets every
    /// delivery exactly when at least `members - quorum_k + 1` answered —
    /// the quorum-intersection boundary, pinned on both sides for the 5/3
    /// and 3/2 profiles.
    #[test]
    fn a_read_covers_every_delivery_only_from_the_quorum_intersection_up() {
        for (members, quorum_k) in [(5, 3), (3, 2)] {
            let needed = members - quorum_k + 1;
            assert_eq!(
                SpoolCoverage::of(needed, members, quorum_k),
                SpoolCoverage::Complete
            );
            assert_eq!(
                SpoolCoverage::of(needed - 1, members, quorum_k),
                SpoolCoverage::Partial {
                    responded: needed - 1,
                    needed
                }
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn a_send_lands_on_exactly_the_register_quorum_of_members() {
        let profile = dsm::economic::register::resolve_root_register_profile(
            dsm::economic::register::BETA_NETWORK_ID,
        )
        .expect("beta profile");
        let k = crate::storage::client_db::publication::quorum_for(profile.members.len()) as usize;
        assert!(
            k < profile.members.len(),
            "the set is wider than its quorum, so reaching K and reaching all differ"
        );

        let p = crate::test_support::two_device::Pair::boot(100, 0).await;
        let sent = p.a.send(&p.b, 10).await;
        assert!(sent.success, "{:?}", sent.error_message);

        p.a.enter();
        let submission_ids: Vec<String> = {
            let binding = crate::storage::client_db::get_connection().expect("conn");
            let conn = binding
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut ids = Vec::new();
            for sql in [
                "SELECT submission_id FROM sender_outbox",
                "SELECT submission_id FROM sender_outbox_artifacts",
            ] {
                let mut stmt = conn.prepare(sql).expect("prepare");
                ids.extend(
                    stmt.query_map([], |row| row.get::<_, String>(0))
                        .expect("query")
                        .map(|row| row.expect("row")),
                );
            }
            ids
        };
        assert_eq!(
            submission_ids.len(),
            2,
            "a send freezes its transfer and its evidence"
        );

        let mut spools = Vec::new();
        for node in 0..p.nodes.nodes.len() {
            spools.push(p.spooled_message_ids(node).await);
        }
        for id in &submission_ids {
            let holders = spools.iter().filter(|spool| spool.contains(id)).count();
            assert_eq!(
                holders, k,
                "{id} is held by {holders} members; the register quorum is {k}"
            );
        }
    }

    /// DELIVERY NEVER COUNTS FEWER THAN THE QUORUM. With n − q + 1 members
    /// down, a frozen send cannot reach K. A second attempt — once the circuit
    /// breaker has marked those members failed — must refuse exactly as the
    /// first did, never deliver to the q − 1 still answering and report done.
    /// With the members back, the same bytes reach the quorum.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn delivery_below_the_quorum_is_refused_however_many_members_are_marked_failed() {
        let mut p = crate::test_support::two_device::Pair::boot(100, 0).await;
        let sent = p.a.send(&p.b, 10).await;
        assert!(sent.success, "{:?}", sent.error_message);

        p.a.enter();
        let (route, id): (String, String) = {
            let binding = crate::storage::client_db::get_connection().expect("conn");
            let conn = binding
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            conn.query_row(
                "SELECT routing_address, submission_id FROM sender_outbox",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("the frozen transfer")
        };
        let down = crate::economic_fixtures::members_to_break_quorum();
        p.nodes.take_down(&down).await;
        let mut sdk = B0xSDK::new(
            crate::util::text_id::encode_base32_crockford(&p.a.device_id),
            p.a.router().core_sdk.clone(),
            p.fleet.endpoints(),
        )
        .expect("B0xSDK");
        let once = B0xRetryConfig {
            max_retries: 0,
            base_delay_ms: 0,
            max_delay_ms: 0,
            backoff_multiplier: 1.0,
        };
        for attempt in 1..=2 {
            let err = sdk
                .submit_stored_envelope_with_retry(&route, &id, &once)
                .await
                .expect_err("q − 1 members cannot hold a delivery");
            assert!(
                err.to_string().contains("delivery below quorum"),
                "attempt {attempt}: {err}"
            );
        }

        p.nodes.bring_up(&down).await;
        sdk.submit_stored_envelope_with_retry(&route, &id, &once)
            .await
            .expect("with the members back, the same bytes reach the quorum");
    }

    fn encode_via_production_path(params: &B0xSubmissionParams) -> usize {
        let (device_b32, core, fleet) = test_device();
        let sdk = B0xSDK::new(device_b32, core, fleet.endpoints()).expect("B0xSDK");
        sdk.build_envelope_for_submission(params)
            .expect("build envelope")
            .bytes
            .len()
    }

    /// ADR 0003 shape 1, as PRODUCTION now builds it: no inline receipt, a
    /// 32-byte role-separated reference in field 12.
    #[test]
    #[serial_test::serial]
    fn adr0003_transfer_envelope_fits_the_node_cap() {
        let params = params_split_shape();
        assert_eq!(
            params.receipt_evidence_digest.len(),
            32,
            "the split transfer must carry a 32-byte evidence reference"
        );

        let bytes = encode_via_production_path(&params);
        report_budget("ADR0003 TransferEnvelope", bytes);
        assert!(
            bytes < NODE_MAX_ENVELOPE_BYTES,
            "TransferEnvelope measured {bytes} bytes, over the {NODE_MAX_ENVELOPE_BYTES} cap"
        );
        // ~50.8 KB. Bounded on both sides: a shape that suddenly got much
        // smaller has probably dropped something the receiver needs.
        assert!(
            (45_000..60_000).contains(&bytes),
            "TransferEnvelope should be ~50.8 KB, measured {bytes}"
        );
    }

    /// The evidence builder must REFUSE to construct an artifact the peer could
    /// never accept. CI asserts the accepted fixtures fit, but production must
    /// not cheerfully build an oversized artifact and discover it as a 413 that
    /// no retry can clear.
    #[test]
    #[serial_test::serial]
    fn the_evidence_builder_refuses_to_build_over_the_cap() {
        let (device_b32, core, fleet) = test_device();
        let sdk = B0xSDK::new(device_b32, core, fleet.endpoints()).expect("B0xSDK");

        // A receipt larger than the cap on its own.
        let oversized = vec![0xAB; MAX_B0X_ENVELOPE_BYTES + 1];
        let digest = crate::storage::client_db::evidence_content_digest(
            crate::storage::client_db::ArtifactRole::EvidenceA,
            &oversized,
        );
        let err = sdk
            .build_evidence_envelope(
                &crate::util::text_id::encode_base32_crockford(&[0x44u8; 32]),
                &crate::util::text_id::encode_base32_crockford(&[0x55u8; 32]),
                "TRANSFER-ID",
                &crate::util::text_id::encode_base32_crockford(&[0xEFu8; 16]),
                &digest,
                &oversized,
            )
            .expect_err("an over-cap artifact must not be constructible");
        assert!(
            format!("{err:?}").contains("envelope cap"),
            "expected the budget refusal, got: {err:?}"
        );
    }

    /// The evidence artifact must be self-consistent before it is frozen: the
    /// digest it carries has to match the bytes it carries. A mismatch here
    /// would produce an artifact that can never satisfy the transfer's
    /// reference.
    #[test]
    #[serial_test::serial]
    fn the_evidence_builder_rejects_a_digest_that_does_not_match_its_bytes() {
        let (device_b32, core, fleet) = test_device();
        let sdk = B0xSDK::new(device_b32, core, fleet.endpoints()).expect("B0xSDK");

        let receipt = production_sized_receipt_a();
        let wrong_digest = [0x00u8; 32];
        let err = sdk
            .build_evidence_envelope(
                &crate::util::text_id::encode_base32_crockford(&[0x44u8; 32]),
                &crate::util::text_id::encode_base32_crockford(&[0x55u8; 32]),
                "TRANSFER-ID",
                &crate::util::text_id::encode_base32_crockford(&[0xEFu8; 16]),
                &wrong_digest,
                &receipt,
            )
            .expect_err("a mismatched digest must be refused");
        assert!(
            format!("{err:?}").contains("does not match"),
            "expected the self-consistency refusal, got: {err:?}"
        );
    }

    /// The evidence artifact round-trips: it decodes to the EXACT receipt bytes
    /// the digest was derived from, and carries that digest for self-
    /// identification before a recipient has paired it with a transfer.
    #[test]
    #[serial_test::serial]
    fn the_evidence_artifact_carries_the_exact_bytes_its_digest_binds() {
        let (device_b32, core, fleet) = test_device();
        let sdk = B0xSDK::new(device_b32, core, fleet.endpoints()).expect("B0xSDK");

        let receipt = production_sized_receipt_a();
        let digest = crate::storage::client_db::evidence_content_digest(
            crate::storage::client_db::ArtifactRole::EvidenceA,
            &receipt,
        );
        let built = sdk
            .build_evidence_envelope(
                &crate::util::text_id::encode_base32_crockford(&[0x44u8; 32]),
                &crate::util::text_id::encode_base32_crockford(&[0x55u8; 32]),
                "TRANSFER-ID",
                &crate::util::text_id::encode_base32_crockford(&[0xEFu8; 16]),
                &digest,
                &receipt,
            )
            .expect("evidence envelope");
        report_budget("ADR0003 A-side evidence (built)", built.bytes.len());
        assert!(built.bytes.len() < NODE_MAX_ENVELOPE_BYTES);

        // Decode back down to the body and compare byte-for-byte.
        let env = dsm::types::proto::Envelope::decode(built.bytes.as_slice()).expect("decode");
        let Some(dsm::types::proto::envelope::Payload::UniversalTx(utx)) = env.payload else {
            panic!("expected a UniversalTx payload");
        };
        let Some(dsm::types::proto::universal_op::Kind::Invoke(invoke)) = utx.ops[0].kind.clone()
        else {
            panic!("expected an Invoke");
        };
        assert_eq!(invoke.method, "receipt.evidence.a");
        let body =
            dsm::types::proto::ReceiptEvidenceA::decode(invoke.args.expect("args").body.as_slice())
                .expect("decode ReceiptEvidenceA");

        assert_eq!(
            body.full_receipt_bytes, receipt,
            "the artifact must carry the EXACT bytes the digest binds"
        );
        assert_eq!(body.receipt_evidence_digest, digest.to_vec());
        assert_eq!(body.transfer_submission_id, "TRANSFER-ID");
    }

    /// Byte stability: the same logical send must produce an identical digest
    /// and identical encoded bytes on every attempt. A retry replays frozen
    /// bytes, so instability here would mean a retry submits a DIFFERENT
    /// artifact under the same deterministic id.
    #[test]
    #[serial_test::serial]
    fn the_split_transfer_encoding_is_byte_stable_across_attempts() {
        let d1 = evidence_content_digest_for_test();
        let d2 = evidence_content_digest_for_test();
        assert_eq!(d1, d2, "evidence digest must be deterministic");

        let a = encode_via_production_path(&params_split_shape());
        let b = encode_via_production_path(&params_split_shape());
        assert_eq!(
            a, b,
            "the same logical send must encode to the same number of bytes"
        );

        // ...and the evidence artifact must be byte-IDENTICAL, not merely the
        // same length: a retry replays frozen bytes under a deterministic id,
        // so instability would submit a different artifact under the same id.
        let (device_b32, core, fleet) = test_device();
        let sdk = B0xSDK::new(device_b32, core, fleet.endpoints()).expect("B0xSDK");
        let receipt = production_sized_receipt_a();
        let build = || {
            sdk.build_evidence_envelope(
                &crate::util::text_id::encode_base32_crockford(&[0x44u8; 32]),
                &crate::util::text_id::encode_base32_crockford(&[0x55u8; 32]),
                "TRANSFER-ID",
                &crate::util::text_id::encode_base32_crockford(&[0xEFu8; 16]),
                &d1,
                &receipt,
            )
            .expect("evidence envelope")
            .bytes
        };
        assert_eq!(
            build(),
            build(),
            "the evidence artifact must encode byte-identically across attempts"
        );

        // The submission id derived from that digest is stable too.
        assert_eq!(
            crate::storage::client_db::derive_artifact_submission_id(&d1),
            crate::storage::client_db::derive_artifact_submission_id(&d2),
        );
    }

    /// The PRODUCTION transfer envelope, decoded from its actual encoded bytes:
    /// field 10 empty, field 12 exactly 32 bytes. Asserting on the params would
    /// only prove what was passed in, not what went on the wire.
    #[test]
    #[serial_test::serial]
    fn the_encoded_transfer_envelope_carries_the_reference_not_the_receipt() {
        let params = params_split_shape();
        let (device_b32, core, fleet) = test_device();
        let sdk = B0xSDK::new(device_b32, core, fleet.endpoints()).expect("B0xSDK");
        let built = sdk
            .build_envelope_for_submission(&params)
            .expect("build envelope");

        let env = dsm::types::proto::Envelope::decode(built.bytes.as_slice()).expect("decode");
        let Some(dsm::types::proto::envelope::Payload::UniversalTx(utx)) = env.payload else {
            panic!("expected a UniversalTx payload");
        };
        let Some(dsm::types::proto::universal_op::Kind::Invoke(invoke)) = utx.ops[0].kind.clone()
        else {
            panic!("expected an Invoke");
        };
        let req = dsm::types::proto::OnlineTransferRequest::decode(
            invoke.args.expect("args").body.as_slice(),
        )
        .expect("decode OnlineTransferRequest");

        assert_eq!(
            req.receipt_evidence_digest.len(),
            32,
            "field 12 must carry a 32-byte evidence reference"
        );
        assert_eq!(
            req.receipt_evidence_digest,
            evidence_content_digest_for_test().to_vec(),
            "the wire reference must be the A-role digest of the evidence bytes"
        );
    }

    /// ADR 0003 shape 2: the A-side evidence artifact. This is the tightest of
    /// the three (~90% of cap) and the one to watch — 99,712 of its bytes are
    /// two SPHINCS+ objects.
    #[test]
    fn adr0003_a_side_evidence_envelope_fits_the_node_cap() {
        let bytes = envelope_bytes_for_evidence_body(production_sized_receipt_a());
        report_budget("ADR0003 A-side evidence", bytes);
        assert!(
            bytes < NODE_MAX_ENVELOPE_BYTES,
            "A-side ReceiptEvidenceEnvelope measured {bytes} bytes, over the cap"
        );
    }

    /// The FULL countersigned receipt as the recipient stores it: the
    /// production-shaped A side plus production-shaped B fields. 218,576 bytes
    /// — the 218,541 observed on 5GN plus canonical field 21 (#934), and 170%
    /// of the node cap.
    fn production_sized_full_countersigned_receipt() -> Vec<u8> {
        let sig = sphincs_sig_len();
        let a = dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(
            &production_sized_receipt_a(),
        )
        .expect("A side decodes");
        let full = a
            .with_countersign_b(dsm::types::receipt_types::CountersignB {
                sig_b: vec![0xBB; sig],
                ek_cert_b: vec![0xCB; sig],
                ek_pk_b: vec![0xEB; EK_PK_LEN],
                kyber_ct_b: vec![0x1B; KYBER_CT_LEN],
            })
            .expect("overlay");
        let bytes = full.to_full_protobuf().expect("encode");
        // The 5GN specimen was 218,541 bytes; canonical field 21 (a two-byte
        // key varint, one length byte, 32 bytes of value) adds 35, and the
        // dropped child proof (field 9, 8,261 + 3) and replace witness
        // (field 11, 4 + 2) remove 8,270.
        assert_eq!(
            bytes.len(),
            210_306,
            "the 5GN specimen size plus field 21, without fields 9 and 11"
        );
        bytes
    }

    fn test_reply_sdk() -> B0xSDK {
        let (device_b32, core, fleet) = test_device();
        B0xSDK::new(device_b32, core, fleet.endpoints()).expect("B0xSDK")
    }

    /// The recipient's canonical pair the reply builder carries (delta-only
    /// metadata; the receipt bytes are untouched by it).
    const TEST_B_PAIR: ([u8; 32], [u8; 32]) = ([0x71u8; 32], [0x72u8; 32]);

    fn commitment_of(full_bytes: &[u8]) -> [u8; 32] {
        dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(full_bytes)
            .expect("decode")
            .compute_commitment()
            .expect("commitment")
    }

    /// ADR 0003 shape 3: the B-side countersign DELTA, built by the REAL
    /// producer from the REAL stored shape (the full 218,541-byte receipt),
    /// wrapped exactly as it goes on the wire.
    ///
    /// NORMATIVE (ADR 0003): this artifact carries exactly TWO SPHINCS+
    /// signature-sized objects, `sig_b` and `ek_cert_b`. Its headroom is less
    /// than one signature, so a third does not degrade it gradually — it
    /// breaks it. Adding one is a transport-design change, not a schema
    /// extension.
    #[test]
    #[serial_test::serial]
    fn adr0003_b_side_countersign_delta_fits_the_node_cap() {
        let full = production_sized_full_countersigned_receipt();
        let sdk = test_reply_sdk();
        let built = sdk
            .build_countersign_reply_envelope(
                &[0x77; 32],
                &[0x22; 32],
                &commitment_of(&full),
                &full,
                TEST_B_PAIR,
                &[],
            )
            .expect("real delta builder");
        report_budget("ADR0003 B-side countersign", built.bytes.len());
        assert!(
            built.bytes.len() < NODE_MAX_ENVELOPE_BYTES,
            "B-side countersign delta measured {} bytes, over the cap",
            built.bytes.len()
        );

        // Decode it the way the sender does: method-discriminated, then the
        // strict wire codec.
        let env = dsm::types::proto::Envelope::decode(&*built.bytes).expect("Envelope");
        let body = B0xSDK::decode_countersign_b(&env).expect("discriminated by method");
        let delta =
            dsm::types::receipt_types::decode_receipt_countersign_b_wire(&body).expect("codec");
        let sig = sphincs_sig_len();
        assert_eq!(delta.sig_b, vec![0xBB; sig]);
        assert_eq!(delta.ek_cert_b, vec![0xCB; sig]);
        assert_eq!(delta.ek_pk_b, vec![0xEB; EK_PK_LEN]);
        assert_eq!(delta.kyber_ct_b, vec![0x1B; KYBER_CT_LEN]);
        assert!(
            body.len() < 2 * sig + 8 * 1024,
            "B delta grew beyond two signatures plus reference material: {} bytes",
            body.len()
        );
        // Nothing A-side rides back: the sig_a / ek_cert_a filler runs are absent.
        assert!(!built
            .bytes
            .windows(1024)
            .any(|w| w.iter().all(|&b| b == 0xAA)));
        assert!(!built
            .bytes
            .windows(1024)
            .any(|w| w.iter().all(|&b| b == 0xCC)));
        // Born canonical: the ArgPack codec is PROTO.
        let Some(dsm::types::proto::envelope::Payload::UniversalTx(tx)) = &env.payload else {
            panic!("UniversalTx")
        };
        let Some(dsm::types::proto::universal_op::Kind::Invoke(inv)) = &tx.ops[0].kind else {
            panic!("Invoke")
        };
        assert_eq!(inv.method, RECEIPT_COUNTERSIGN_B_METHOD);
        assert_eq!(
            inv.args.as_ref().unwrap().codec,
            dsm::types::proto::Codec::Proto as i32
        );
        assert_eq!(env.headers.as_ref().unwrap().genesis_hash, vec![0x77; 32]);
    }

    /// The recipient-derived A digest equals the digest the sender computed at
    /// send over the SAME bytes — the delta names exactly what was countersigned.
    #[test]
    #[serial_test::serial]
    fn the_countersign_reply_names_the_exact_a_side_bytes() {
        let a_bytes = production_sized_receipt_a();
        let full = production_sized_full_countersigned_receipt();
        let built = test_reply_sdk()
            .build_countersign_reply_envelope(
                &[0x77; 32],
                &[0x22; 32],
                &commitment_of(&full),
                &full,
                TEST_B_PAIR,
                &[],
            )
            .expect("build");
        let env = dsm::types::proto::Envelope::decode(&*built.bytes).expect("Envelope");
        let body = B0xSDK::decode_countersign_b(&env).expect("method");
        let delta =
            dsm::types::receipt_types::decode_receipt_countersign_b_wire(&body).expect("codec");
        assert_eq!(
            delta.receipt_evidence_digest_a,
            crate::storage::client_db::evidence_content_digest(
                crate::storage::client_db::ArtifactRole::EvidenceA,
                &a_bytes
            )
            .to_vec()
        );
        assert_eq!(delta.commitment, commitment_of(&full).to_vec());
    }

    /// Two builds from the same inputs are byte-identical — required because
    /// the reply id is deterministic and the node keeps the first body per id.
    #[test]
    #[serial_test::serial]
    fn the_countersign_reply_is_byte_stable_across_attempts() {
        let full = production_sized_full_countersigned_receipt();
        let sdk = test_reply_sdk();
        let c = commitment_of(&full);
        let one = sdk
            .build_countersign_reply_envelope(&[0x77; 32], &[0x22; 32], &c, &full, TEST_B_PAIR, &[])
            .expect("one");
        let two = sdk
            .build_countersign_reply_envelope(&[0x77; 32], &[0x22; 32], &c, &full, TEST_B_PAIR, &[])
            .expect("two");
        assert_eq!(one.bytes, two.bytes);
        assert_eq!(one.message_id_b32, two.message_id_b32);
    }

    #[test]
    #[serial_test::serial]
    fn the_countersign_builder_refuses_what_it_must() {
        let sdk = test_reply_sdk();
        let full = production_sized_full_countersigned_receipt();
        let c = commitment_of(&full);

        // Not countersigned: an A-only receipt has no delta to send.
        let a_only = production_sized_receipt_a();
        let err = sdk
            .build_countersign_reply_envelope(
                &[0x77; 32],
                &[0x22; 32],
                &commitment_of(&a_only),
                &a_only,
                TEST_B_PAIR,
                &[],
            )
            .expect_err("A-only");
        assert!(
            err.to_string()
                .contains("no complete B-side countersignature"),
            "{err}"
        );

        // The stored receipt is not the one this reply is for.
        let err = sdk
            .build_countersign_reply_envelope(
                &[0x77; 32],
                &[0x22; 32],
                &[0x99; 32],
                &full,
                TEST_B_PAIR,
                &[],
            )
            .expect_err("wrong commitment");
        assert!(
            err.to_string().contains("commitment != reply commitment"),
            "{err}"
        );

        // Over the cap: two 65,535-byte "signatures" cannot be delivered, so the
        // builder refuses rather than handing the sweep a guaranteed 413.
        let a = dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(&a_only)
            .expect("A");
        let fat = a
            .with_countersign_b(dsm::types::receipt_types::CountersignB {
                sig_b: vec![0xBB; 65_535],
                ek_cert_b: vec![0xCB; 65_535],
                ek_pk_b: vec![0xEB; EK_PK_LEN],
                kyber_ct_b: vec![0x1B; KYBER_CT_LEN],
            })
            .expect("overlay")
            .to_full_protobuf()
            .expect("encode");
        let err = sdk
            .build_countersign_reply_envelope(
                &[0x77; 32],
                &[0x22; 32],
                &commitment_of(&fat),
                &fat,
                TEST_B_PAIR,
                &[],
            )
            .expect_err("over cap");
        assert!(err.to_string().contains("envelope cap"), "{err}");

        // Positive control in the same shape.
        sdk.build_countersign_reply_envelope(&[0x77; 32], &[0x22; 32], &c, &full, TEST_B_PAIR, &[])
            .expect("the production shape builds");
    }

    /// Wrap an evidence body in the same Envelope framing the production
    /// submit path uses, and return the encoded wire length.
    fn envelope_bytes_for_evidence_body(body: Vec<u8>) -> usize {
        let envelope = test_invoke_envelope("receipt.evidence", body);
        let mut buf = Vec::with_capacity(envelope.encoded_len());
        envelope.encode(&mut buf).expect("encode Envelope");
        buf.len()
    }

    /// One UniversalTx invoke envelope with the given method and ArgPack body,
    /// framed as the production submit path frames it.
    fn test_invoke_envelope(method: &str, body: Vec<u8>) -> dsm::types::proto::Envelope {
        let arg_pack = dsm::types::proto::ArgPack {
            schema_hash: None,
            codec: dsm::types::proto::Codec::Proto as i32,
            body,
        };
        let invoke = dsm::types::proto::Invoke {
            program: None,
            method: method.to_string(),
            args: Some(arg_pack),
            cosigners: vec![],
            evidence: None,
            nonce: Some(dsm::types::proto::Hash16 { v: vec![0u8; 16] }),
        };
        dsm::types::proto::Envelope {
            version: 3,
            headers: Some(dsm::types::proto::Headers {
                device_id: vec![0x11; 32],
                genesis_hash: vec![0x33; 32],
            }),
            message_id: vec![0x44; 16],
            payload: Some(dsm::types::proto::envelope::Payload::UniversalTx(
                dsm::types::proto::UniversalTx {
                    ops: vec![dsm::types::proto::UniversalOp {
                        op_id: Some(dsm::types::proto::Hash32 { v: vec![0u8; 32] }),
                        actor: vec![0x11; 32],
                        kind: Some(dsm::types::proto::universal_op::Kind::Invoke(invoke)),
                    }],
                    atomic: true,
                },
            )),
        }
    }

    /// The return leg is discriminated by its explicit method string and
    /// nothing else: no trial decode, no size heuristic. An evidence half and a
    /// legacy full-receipt reply on the retired `wallet.acceptanceReceipt`
    /// method are both `None` here, and the legacy one is not a transfer either
    /// — it matches no discriminator and is dropped, never consumed.
    #[test]
    #[serial_test::serial]
    fn retrieve_discriminates_a_countersign_delta_by_its_method_only() {
        let body = vec![0xB0u8; 96];
        let delta = test_invoke_envelope(RECEIPT_COUNTERSIGN_B_METHOD, body.clone());
        assert_eq!(B0xSDK::decode_countersign_b(&delta), Some(body.clone()));
        assert!(B0xSDK::decode_receipt_evidence_a(&delta).is_none());

        let evidence = test_invoke_envelope(RECEIPT_EVIDENCE_A_METHOD, body.clone());
        assert!(B0xSDK::decode_countersign_b(&evidence).is_none());

        let legacy = test_invoke_envelope("wallet.acceptanceReceipt", body);
        assert!(B0xSDK::decode_countersign_b(&legacy).is_none());
        assert!(B0xSDK::decode_receipt_evidence_a(&legacy).is_none());
        let (device_b32, core, fleet) = test_device();
        let sdk = B0xSDK::new(device_b32, core, fleet.endpoints()).expect("B0xSDK");
        assert!(
            sdk.envelope_to_b0x_entry(legacy).is_none(),
            "a legacy full-receipt reply is not a transfer and must be dropped, not consumed"
        );
    }
}
