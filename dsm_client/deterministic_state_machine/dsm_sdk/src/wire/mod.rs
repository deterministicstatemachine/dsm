//! # Wire Adapters
//!
//! Conversion adapters between SDK-level types and core DSM types
//! for wire-format translation (protobuf ↔ internal representation).

use std::convert::TryFrom;

use crate::types::error::DsmError;
use crate::types::operations::Operation;
use crate::types::token_types::Balance;
use crate::types::state_types::State;
use prost::Message;

// Provide the prost-generated types locally
#[allow(
    clippy::all,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals
)]
pub mod pb {
    // Generated modules under package namespaces (e.g., `dsm`) live here
    include!(concat!(env!("OUT_DIR"), "/pb.rs")); // adjust filename if your .proto differs
                                                  // Re-export package contents at the pb:: root for backwards compatibility
    pub use self::dsm::*;
}

/* ---------------------- Normative v3 authoring helpers --------------------- */

/// Deterministic domain-separated hash: H(tag \0 || bytes).
///
/// Delegates to `dsm::crypto::blake3::domain_hash_bytes` which automatically
/// appends the NUL terminator. Strips any trailing `\0` from `tag` first to
/// prevent double-NUL when callers embed the terminator in the literal.
pub fn domain_hash_bytes(tag: &str, body: &[u8]) -> [u8; 32] {
    dsm::crypto::blake3::domain_hash_bytes(tag.trim_end_matches('\0'), body)
}

/// Author a ContactAddV3 request for a new peer.
///
/// This is signature-free authoring; device-side authenticity is provided
/// by signing the `ContactAddV3` deterministic bytes with SPHINCS+ in the
/// envelope layer.
pub fn author_contact_add(
    author_id: &[u8; 32],
    device_id: &[u8; 32],
    counterparty_tip: &[u8; 32],
) -> pb::ContactAddV3 {
    pb::ContactAddV3 {
        author_device_id: author_id.to_vec(),
        contact_device_id: device_id.to_vec(),
        contact_chain_tip: counterparty_tip.to_vec(),
        // Root of author's contact stream (optional)
        parent_digest: Vec::new(),
    }
}

/// Author a ContactAcceptV3 response following a received add request.
///
/// Computes add_digest = H("DSM/contact/add" \0 || ProtoDet(ContactAddV3)).
pub fn author_contact_accept(
    accepter_id: &[u8; 32],
    add_req: &pb::ContactAddV3,
    local_tip: &[u8; 32],
) -> pb::ContactAcceptV3 {
    let add_bytes = add_req.encode_to_vec();
    let add_digest = domain_hash_bytes("DSM/contact/add", &add_bytes);

    pb::ContactAcceptV3 {
        accepter_device_id: accepter_id.to_vec(),
        add_digest: add_digest.to_vec(),
        local_chain_tip: local_tip.to_vec(),
    }
}

/* ---------------------------- Hash/Int wrappers ---------------------------- */

impl From<[u8; 32]> for pb::Hash32 {
    fn from(v: [u8; 32]) -> Self {
        pb::Hash32 { v: v.to_vec() }
    }
}
impl TryFrom<pb::Hash32> for [u8; 32] {
    type Error = DsmError;
    fn try_from(h: pb::Hash32) -> Result<Self, Self::Error> {
        let v = h.v;
        if v.len() != 32 {
            return Err(DsmError::invalid_operation("Hash32 must be 32 bytes"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

impl From<u128> for pb::U128 {
    fn from(x: u128) -> Self {
        pb::U128 {
            le: x.to_le_bytes().to_vec(),
        }
    }
}
impl TryFrom<pb::U128> for u128 {
    type Error = DsmError;
    fn try_from(v: pb::U128) -> Result<Self, Self::Error> {
        let b = v.le;
        if b.len() != 16 {
            return Err(DsmError::invalid_operation("U128 must be 16 bytes"));
        }
        let mut a = [0u8; 16];
        a.copy_from_slice(&b);
        Ok(u128::from_le_bytes(a))
    }
}

impl From<i128> for pb::S128 {
    fn from(x: i128) -> Self {
        pb::S128 {
            le: x.to_le_bytes().to_vec(),
        }
    }
}
impl TryFrom<pb::S128> for i128 {
    type Error = DsmError;
    fn try_from(v: pb::S128) -> Result<Self, Self::Error> {
        let b = v.le;
        if b.len() != 16 {
            return Err(DsmError::invalid_operation("S128 must be 16 bytes"));
        }
        let mut a = [0u8; 16];
        a.copy_from_slice(&b);
        Ok(i128::from_le_bytes(a))
    }
}

/* ---------------------------- Error translation --------------------------- */

/// Small, stable code-space you control. Map your `DsmError` categories here.
#[cfg_attr(not(clippy), repr(u32))]
#[derive(Copy, Clone, Debug)]
pub enum ErrorCode {
    Unknown = 0,
    InvalidOperation = 1,
    Merkle = 2,
    Serialization = 3,
    Crypto = 4,
    Storage = 5,
    Network = 6,
    Timeout = 7,
    Preconditions = 8,
}

fn map_error_code(error: &DsmError) -> ErrorCode {
    match error {
        DsmError::InvalidOperation(_)
        | DsmError::InvalidArgument(_)
        | DsmError::InvalidParameter(_)
        | DsmError::InvalidState(_)
        | DsmError::InvalidIndex
        | DsmError::InvalidContact(_)
        | DsmError::PolicyViolation { .. }
        | DsmError::Unauthorized { .. }
        | DsmError::FeatureNotAvailable { .. }
        | DsmError::InvalidToken { .. }
        | DsmError::AlreadyExists(_)
        | DsmError::InsufficientBalance { .. }
        | DsmError::RelationshipNotFound(_)
        | DsmError::ContactNotFound(_)
        | DsmError::RequestNotFound(_)
        | DsmError::NotFound { .. } => ErrorCode::InvalidOperation,

        DsmError::Merkle(_) => ErrorCode::Merkle,

        DsmError::Serialization { .. } | DsmError::SerializationError(_) => {
            ErrorCode::Serialization
        }

        DsmError::Crypto(_)
        | DsmError::Verification(_)
        | DsmError::Integrity { .. }
        | DsmError::InvalidSignature
        | DsmError::InvalidPublicKey
        | DsmError::InvalidSecretKey
        | DsmError::InvalidKeyLength
        | DsmError::InvalidCiphertext
        | DsmError::HashChain(_)
        | DsmError::ForwardCommitment(_)
        | DsmError::Genesis(_)
        | DsmError::DeviceHierarchy(_)
        | DsmError::ExternalCommitment(_)
        | DsmError::Identity(_)
        | DsmError::TokenError { .. } => ErrorCode::Crypto,

        DsmError::Security { .. } => ErrorCode::Crypto,

        DsmError::Storage { .. } => ErrorCode::Storage,

        DsmError::Network { .. }
        | DsmError::Transport { .. }
        | DsmError::Communication { .. }
        | DsmError::Blockchain { .. }
        | DsmError::Runtime { .. } => ErrorCode::Network,

        DsmError::Timeout(_) => ErrorCode::Timeout,

        DsmError::DeterministicSafety { .. } => ErrorCode::Preconditions,

        DsmError::Validation { .. }
        | DsmError::State(_)
        | DsmError::Transaction(_)
        | DsmError::PreCommitment(_)
        | DsmError::StateMachine(_)
        | DsmError::Configuration { .. }
        | DsmError::TimeError(_)
        | DsmError::SystemError(_)
        | DsmError::MintNotAllowed
        | DsmError::BurnNotAllowed
        | DsmError::FaucetDisabled
        | DsmError::FaucetNotAvailable
        | DsmError::InboxTokenInvalid(_)
        | DsmError::Other(_)
        | DsmError::Bluetooth(_)
        | DsmError::LockError
        | DsmError::Internal { .. }
        | DsmError::Io(_)
        | DsmError::Generic { .. }
        | DsmError::Relationship(_)
        | DsmError::NotImplemented(_)
        | DsmError::NotInitialized { .. }
        | DsmError::ClockDrift { .. }
        | DsmError::BitcoinTapSafety { .. }
        | DsmError::VaultOperation { .. } => ErrorCode::Preconditions,

        DsmError::BitcoinDeposit { .. }
        | DsmError::BitcoinWithdrawal { .. }
        | DsmError::HtlcError { .. } => ErrorCode::Crypto,

        DsmError::StorageNode { .. }
        | DsmError::Replication { .. }
        | DsmError::CapacityLimit { .. } => ErrorCode::Storage,

        DsmError::Consensus { .. } => ErrorCode::Network,
    }
}

fn error_context_bytes(error: &DsmError) -> Vec<u8> {
    match error {
        DsmError::Serialization {
            context,
            entity,
            details,
            ..
        } => format!(
            "entity={entity} context={context} details={}",
            details.as_deref().unwrap_or("")
        )
        .into_bytes(),
        DsmError::Network {
            context, details, ..
        } => format!(
            "context={context} details={}",
            details.as_deref().unwrap_or("")
        )
        .into_bytes(),
        DsmError::Storage { context, .. } => context.as_bytes().to_vec(),
        DsmError::Communication { context, .. }
        | DsmError::Transport { context, .. }
        | DsmError::Blockchain { context, .. }
        | DsmError::Configuration { context, .. }
        | DsmError::Runtime { context, .. }
        | DsmError::Validation { context, .. }
        | DsmError::Integrity { context, .. }
        | DsmError::TokenError { context, .. }
        | DsmError::Unauthorized { context, .. }
        | DsmError::PolicyViolation {
            message: context, ..
        } => context.as_bytes().to_vec(),
        DsmError::Crypto(inner) => inner.context.as_bytes().to_vec(),
        DsmError::NotFound {
            entity, details, ..
        } => format!(
            "entity={entity} details={}",
            details.as_deref().unwrap_or("")
        )
        .into_bytes(),
        DsmError::InsufficientBalance {
            token_id,
            available,
            requested,
        } => format!("token={token_id} available={available} requested={requested}").into_bytes(),
        DsmError::FeatureNotAvailable { feature, context } => format!(
            "feature={feature} context={}",
            context.as_deref().unwrap_or("")
        )
        .into_bytes(),
        DsmError::DeterministicSafety {
            classification,
            message,
        } => format!(
            "classification={} message={message}",
            classification.as_str()
        )
        .into_bytes(),
        DsmError::InvalidToken { token_id, context } => format!(
            "token={token_id} context={}",
            context.as_deref().unwrap_or("")
        )
        .into_bytes(),
        _ => Vec::new(),
    }
}

impl From<&DsmError> for pb::Error {
    fn from(e: &DsmError) -> Self {
        let code = map_error_code(e);
        let context = error_context_bytes(e);

        // Stable category tag for clients. This must remain stable across versions
        // because clients may key behavior and telemetry on it.
        let source_tag: u32 = match e {
            // Canonical category tags (small stable set)
            DsmError::Crypto(_) => 1,

            // Verification / validation related failures
            DsmError::Validation { .. }
            | DsmError::Integrity { .. }
            | DsmError::InvalidState(_)
            | DsmError::InvalidOperation(_)
            | DsmError::PolicyViolation { .. }
            | DsmError::Unauthorized { .. }
            | DsmError::InvalidToken { .. }
            | DsmError::InsufficientBalance { .. } => 10,

            DsmError::DeterministicSafety { .. } => 11,

            // Serialization / parsing
            DsmError::Serialization { .. } | DsmError::SerializationError(_) => 15,

            // Storage / network / transport / comms
            DsmError::Storage { .. } => 20,
            DsmError::Network { .. } => 21,
            DsmError::Transport { .. } => 22,
            DsmError::Communication { .. } => 23,

            // Bluetooth / platform boundary
            DsmError::Bluetooth(_) => 30,

            // Time/ticks-related (still deterministic; usually retryable)
            DsmError::TimeError(_) => 40,

            // Default
            _ => 0,
        };

        pb::Error {
            code: code as u32,
            message: e.to_string(),
            context,
            source_tag,
            is_recoverable: e.is_recoverable(),
            debug_b32: "".to_string(),
        }
    }
}

/// Don’t try to reconstruct a full `DsmError` from the wire—treat as transport error.
#[derive(thiserror::Error, Debug)]
pub enum TransportError {
    #[error("remote: code={code} recoverable={recoverable} msg={msg}")]
    Remote {
        code: u32,
        msg: String,
        recoverable: bool,
        context: Vec<u8>,
    },
}

impl From<pb::Error> for TransportError {
    fn from(e: pb::Error) -> Self {
        TransportError::Remote {
            code: e.code,
            msg: e.message,
            recoverable: e.is_recoverable,
            context: e.context,
        }
    }
}

/* -------------------------- Domain ↔ Wire (State) ------------------------- */

/// Convert domain `State` → canonical wire `StateWire` used in preimages/hashes.
/// Important: sort token balances by token_id *before* building the repeated field.
pub fn state_to_wire(s: &State) -> pb::StateWire {
    // Collect and sort by token_id for determinism
    let mut entries: Vec<(&String, &Balance)> = s.token_balances.iter().collect();
    entries.sort_by_key(|(a, _)| *a);

    let token_balances = entries
        .into_iter()
        .map(|(token_id, amt)| pb::TokenBalanceEntry {
            token_id: token_id.clone(),
            amount: Some(pb::U128 {
                // Balance is a plain u128 (type alias); use its value directly
                le: (*amt).to_le_bytes().to_vec(),
            }),
        })
        .collect();

    // Operation string should be a stable canonical verb for hashing.
    let op: String = canonical_operation_name(&s.operation);

    pb::StateWire {
        state_number: s.state_number,
        prev_state_hash: s.prev_state_hash.to_vec(),
        token_balances,
        operation: op,
        // device_id as bytes here (protobuf defines `bytes`).
        device_id: s.device_info.device_id.to_vec(),
    }
}

/// Minimal canonical verb for your Operation variants (no serde; stable strings).
fn canonical_operation_name(op: &Operation) -> String {
    use Operation::*;
    match op {
        Create { .. } => "CREATE",
        Transfer { .. } => "TRANSFER",
        AddRelationship { .. } => "ADD_REL",
        // …extend with all variants, keep ALLCAPS ASCII and stable.
        _ => "CUSTOM",
    }
    .to_string()
}

/* -------------------------- Transitions / Results ------------------------- */

/// Build a `StateTransitionProto` deterministically from a domain transition.
/// Make sure the `balance_delta` list is sorted by token_id.
#[allow(clippy::too_many_arguments)]
pub fn make_state_transition_proto(
    actor_id: &[u8],
    counterparty_id: &[u8],
    bilateral_chain_id: &str,
    prev_hash: [u8; 32],
    new_hash: [u8; 32],
    state_number: u64,
    operation: &Operation,
    balance_delta: &[(String, i128)],
    tx_dir: &str, // e.g. "send" | "recv" (stable ASCII)
    signature: &[u8],
) -> pb::StateTransitionProto {
    let mut deltas = balance_delta.to_vec();
    deltas.sort_by(|(a, _), (b, _)| a.cmp(b));
    let balance_delta = deltas
        .into_iter()
        .map(|(token_id, d)| pb::BalanceDeltaEntry {
            token_id,
            delta: Some(pb::S128 {
                le: d.to_le_bytes().to_vec(),
            }),
        })
        .collect();

    pb::StateTransitionProto {
        device_id: actor_id.to_vec(),
        counterparty_id: counterparty_id.to_vec(),
        bilateral_chain_id: bilateral_chain_id.to_string(),
        prev_state_hash: prev_hash.to_vec(),
        new_state_hash: new_hash.to_vec(),
        state_number,
        operation: canonical_operation_name(operation),
        balance_delta,
        signature: signature.to_vec(),
        transaction_direction: tx_dir.to_string(),
    }
}

/* -------------------------- Bilateral BLE Messaging ----------------------- */

// The removed dsm::bilateral module has been removed. Define a minimal local
// representation of the bilateral message types used solely for protobuf
// envelope encoding/decoding helpers in this module.
use dsm::types::state_types::DeviceInfo;

#[derive(Clone, Debug)]
pub enum SignerRole {
    Initiator,
    Responder,
}

#[derive(Clone, Debug)]
pub enum BilateralMessage {
    SessionInit {
        session_id: [u8; 16],
        initiator_info: DeviceInfo,
        proposed_transaction: Box<dsm::types::operations::Operation>,
    },
    SessionAccept {
        session_id: [u8; 16],
        responder_info: DeviceInfo,
    },
    SessionReject {
        session_id: [u8; 16],
        reason: String,
    },
    StateSync {
        session_id: [u8; 16],
        state_hash: [u8; 32],
        state_number: u64,
    },
    TransactionSign {
        session_id: [u8; 16],
        signature: Vec<u8>,
        signer_role: SignerRole,
    },
    SessionComplete {
        session_id: [u8; 16],
        final_state_hash: [u8; 32],
    },
    Error {
        session_id: [u8; 16],
        error_code: String,
        message: String,
    },
}

/// Encode a domain BilateralMessage into protobuf BilateralMessageEnvelope bytes.
pub fn encode_bilateral_message_to_proto(msg: &BilateralMessage) -> Result<Vec<u8>, DsmError> {
    fn device_info_to_pb(info: &DeviceInfo) -> pb::BilateralDeviceInfo {
        // DeviceInfo only carries device_id + public key in this local struct.
        // For fields not available here, use deterministic zero values.
        let zero32 = [0u8; 32];
        pb::BilateralDeviceInfo {
            device_id: info.device_id.to_vec(),
            genesis_hash: zero32.to_vec(),
            current_state_hash: zero32.to_vec(),
            state_number: 0,
            public_key: info.public_key.clone(),
            bluetooth_address: None,
            device_name: String::new(),
        }
    }

    let envelope_msg = match msg {
        BilateralMessage::SessionInit {
            session_id,
            initiator_info,
            proposed_transaction,
        } => pb::bilateral_message_envelope::Msg::SessionInit(pb::BilateralSessionInit {
            session_id: session_id.to_vec(),
            initiator: Some(device_info_to_pb(initiator_info)),
            proposed_transaction: proposed_transaction.to_bytes(),
        }),
        BilateralMessage::SessionAccept {
            session_id,
            responder_info,
        } => pb::bilateral_message_envelope::Msg::SessionAccept(pb::BilateralSessionAccept {
            session_id: session_id.to_vec(),
            responder: Some(device_info_to_pb(responder_info)),
        }),
        BilateralMessage::SessionReject { session_id, reason } => {
            pb::bilateral_message_envelope::Msg::SessionReject(pb::BilateralSessionReject {
                session_id: session_id.to_vec(),
                reason: reason.clone(),
            })
        }
        BilateralMessage::StateSync {
            session_id,
            state_hash,
            state_number,
        } => pb::bilateral_message_envelope::Msg::StateSync(pb::BilateralStateSync {
            session_id: session_id.to_vec(),
            state_hash: state_hash.to_vec(),
            state_number: *state_number,
        }),
        BilateralMessage::TransactionSign {
            session_id,
            signature,
            signer_role,
        } => {
            let role = match signer_role {
                SignerRole::Initiator => pb::BilateralSignerRole::Initiator,
                SignerRole::Responder => pb::BilateralSignerRole::Responder,
            };
            pb::bilateral_message_envelope::Msg::TransactionSign(pb::BilateralTransactionSign {
                session_id: session_id.to_vec(),
                signature: signature.clone(),
                role: role as i32,
            })
        }
        BilateralMessage::SessionComplete {
            session_id,
            final_state_hash,
        } => pb::bilateral_message_envelope::Msg::SessionComplete(pb::BilateralSessionComplete {
            session_id: session_id.to_vec(),
            final_state_hash: final_state_hash.to_vec(),
        }),
        BilateralMessage::Error {
            session_id,
            error_code,
            message,
        } => pb::bilateral_message_envelope::Msg::Error(pb::BilateralError {
            session_id: session_id.to_vec(),
            error_code: error_code.clone(),
            message: message.clone(),
        }),
    };

    let envelope = pb::BilateralMessageEnvelope {
        msg: Some(envelope_msg),
    };

    Ok(envelope.encode_to_vec())
}

/// Decode protobuf BilateralMessageEnvelope bytes into domain BilateralMessage.
pub fn decode_bilateral_message_from_proto(bytes: &[u8]) -> Result<BilateralMessage, DsmError> {
    fn pb_to_device_info(info: pb::BilateralDeviceInfo) -> Result<DeviceInfo, DsmError> {
        if info.device_id.len() != 32 {
            return Err(DsmError::invalid_operation(
                "device_id must be 32 bytes".to_string(),
            ));
        }
        let mut device_id = [0u8; 32];
        device_id.copy_from_slice(&info.device_id);

        Ok(DeviceInfo {
            device_id,
            public_key: info.public_key,
            metadata: Vec::new(),
        })
    }

    let env = pb::BilateralMessageEnvelope::decode(bytes).map_err(|e| {
        DsmError::serialization_error(
            "decode_bilateral_message_from_proto",
            "protobuf",
            Some(e.to_string()),
            None::<std::io::Error>,
        )
    })?;

    let msg = env.msg.ok_or_else(|| {
        DsmError::invalid_operation("BilateralMessageEnvelope.msg missing".to_string())
    })?;

    let out = match msg {
        pb::bilateral_message_envelope::Msg::SessionInit(m) => {
            let initiator = m
                .initiator
                .ok_or_else(|| DsmError::invalid_operation("initiator missing".to_string()))?;
            if m.session_id.len() != 16 {
                return Err(DsmError::invalid_operation(
                    "session_id must be 16 bytes".to_string(),
                ));
            }
            let mut session_id = [0u8; 16];
            session_id.copy_from_slice(&m.session_id);
            BilateralMessage::SessionInit {
                session_id,
                initiator_info: pb_to_device_info(initiator)?,
                proposed_transaction: Box::new(Operation::from_bytes(&m.proposed_transaction)?),
            }
        }
        pb::bilateral_message_envelope::Msg::SessionAccept(m) => {
            let responder = m
                .responder
                .ok_or_else(|| DsmError::invalid_operation("responder missing".to_string()))?;
            if m.session_id.len() != 16 {
                return Err(DsmError::invalid_operation(
                    "session_id must be 16 bytes".to_string(),
                ));
            }
            let mut session_id = [0u8; 16];
            session_id.copy_from_slice(&m.session_id);
            BilateralMessage::SessionAccept {
                session_id,
                responder_info: pb_to_device_info(responder)?,
            }
        }
        pb::bilateral_message_envelope::Msg::SessionReject(m) => {
            if m.session_id.len() != 16 {
                return Err(DsmError::invalid_operation(
                    "session_id must be 16 bytes".to_string(),
                ));
            }
            let mut session_id = [0u8; 16];
            session_id.copy_from_slice(&m.session_id);
            BilateralMessage::SessionReject {
                session_id,
                reason: m.reason,
            }
        }
        pb::bilateral_message_envelope::Msg::StateSync(m) => {
            if m.session_id.len() != 16 {
                return Err(DsmError::invalid_operation(
                    "session_id must be 16 bytes".to_string(),
                ));
            }
            if m.state_hash.len() != 32 {
                return Err(DsmError::invalid_operation(
                    "state_hash must be 32 bytes".to_string(),
                ));
            }
            let mut session_id = [0u8; 16];
            session_id.copy_from_slice(&m.session_id);
            let mut state_hash = [0u8; 32];
            state_hash.copy_from_slice(&m.state_hash);
            BilateralMessage::StateSync {
                session_id,
                state_hash,
                state_number: m.state_number,
            }
        }
        pb::bilateral_message_envelope::Msg::TransactionSign(m) => {
            let role = match pb::BilateralSignerRole::try_from(m.role) {
                Ok(pb::BilateralSignerRole::Initiator) => SignerRole::Initiator,
                Ok(pb::BilateralSignerRole::Responder) => SignerRole::Responder,
                _ => {
                    return Err(DsmError::invalid_operation(
                        "invalid signer role".to_string(),
                    ))
                }
            };
            if m.session_id.len() != 16 {
                return Err(DsmError::invalid_operation(
                    "session_id must be 16 bytes".to_string(),
                ));
            }
            let mut session_id = [0u8; 16];
            session_id.copy_from_slice(&m.session_id);
            BilateralMessage::TransactionSign {
                session_id,
                signature: m.signature,
                signer_role: role,
            }
        }
        pb::bilateral_message_envelope::Msg::SessionComplete(m) => {
            if m.session_id.len() != 16 {
                return Err(DsmError::invalid_operation(
                    "session_id must be 16 bytes".to_string(),
                ));
            }
            if m.final_state_hash.len() != 32 {
                return Err(DsmError::invalid_operation(
                    "final_state_hash must be 32 bytes".to_string(),
                ));
            }
            let mut session_id = [0u8; 16];
            session_id.copy_from_slice(&m.session_id);
            let mut final_state_hash = [0u8; 32];
            final_state_hash.copy_from_slice(&m.final_state_hash);
            BilateralMessage::SessionComplete {
                session_id,
                final_state_hash,
            }
        }
        pb::bilateral_message_envelope::Msg::Error(m) => {
            if m.session_id.len() != 16 {
                return Err(DsmError::invalid_operation(
                    "session_id must be 16 bytes".to_string(),
                ));
            }
            let mut session_id = [0u8; 16];
            session_id.copy_from_slice(&m.session_id);
            BilateralMessage::Error {
                session_id,
                error_code: m.error_code,
                message: m.message,
            }
        }
        // Task 2: Bilateral reconciliation messages (beta readiness)
        // These are handled at the BLE layer, not exposed to higher-level BilateralMessage enum
        pb::bilateral_message_envelope::Msg::ChainHistoryRequest(_)
        | pb::bilateral_message_envelope::Msg::ChainHistoryResponse(_)
        | pb::bilateral_message_envelope::Msg::ReconciliationRequest(_)
        | pb::bilateral_message_envelope::Msg::ReconciliationResponse(_) => {
            return Err(DsmError::invalid_operation(
                "Reconciliation messages are handled at BLE transport layer".to_string(),
            ));
        }
    };

    Ok(out)
}

#[cfg(test)]
mod bilateral_wire_tests {
    use super::*;
    use crate::wire::pb;
    use prost::Message;

    fn device_info() -> DeviceInfo {
        DeviceInfo {
            device_id: [0x01u8; 32],
            public_key: vec![0x02u8; 32],
            metadata: Vec::new(),
        }
    }

    #[test]
    fn bilateral_encode_decode_roundtrip_session_accept() {
        let msg = BilateralMessage::SessionAccept {
            session_id: [0x11u8; 16],
            responder_info: device_info(),
        };
        let bytes = match encode_bilateral_message_to_proto(&msg) {
            Ok(b) => b,
            Err(e) => panic!("encode failed: {:?}", e),
        };
        let msg2 = match decode_bilateral_message_from_proto(&bytes) {
            Ok(m) => m,
            Err(e) => panic!("decode failed: {:?}", e),
        };
        match msg2 {
            BilateralMessage::SessionAccept {
                session_id,
                responder_info,
            } => {
                assert_eq!(session_id, [0x11u8; 16]);
                assert_eq!(responder_info.device_id, [0x01u8; 32]);
                assert_eq!(responder_info.public_key, vec![0x02u8; 32]);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn bilateral_encoder_uses_bytes_for_hash_fields() {
        let msg = BilateralMessage::SessionComplete {
            session_id: [0x22u8; 16],
            final_state_hash: [0xABu8; 32],
        };
        let bytes = match encode_bilateral_message_to_proto(&msg) {
            Ok(b) => b,
            Err(e) => panic!("encode failed: {:?}", e),
        };
        let env = match pb::BilateralMessageEnvelope::decode(bytes.as_slice()) {
            Ok(e) => e,
            Err(e) => panic!("decode env failed: {:?}", e),
        };
        let inner = match env.msg {
            Some(pb::bilateral_message_envelope::Msg::SessionComplete(m)) => m,
            _ => panic!("unexpected oneof"),
        };
        assert_eq!(inner.session_id, vec![0x22u8; 16]);
        assert_eq!(inner.final_state_hash, vec![0xABu8; 32]);
    }
}
