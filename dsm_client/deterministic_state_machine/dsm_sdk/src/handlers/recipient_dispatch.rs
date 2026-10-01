// SPDX-License-Identifier: MIT OR Apache-2.0
//! ADR 0003 step 3c: the ingestion boundary — the only way spool bytes become
//! recipient state.
//!
//! Fetch and decode happen in `b0x_sdk` (explicit invoke methods, never a
//! trial-decode). Everything a half becomes here, it becomes through the same
//! stages, each taking only what the previous stage produced:
//!
//! ```text
//! parse → resolve candidate identity → verify → derive sender
//!       → check recipient → derive the object key → stage → bind
//! ```
//!
//! - **resolve candidate identity**: the envelope header (transfer) or the
//!   receipt's `devid_a` (evidence) names a contact. That is a lookup hint and
//!   nothing more: it only chooses which STORED key the next stage tries.
//! - **verify**: SIG A over the canonical operation bytes, or the receipt's
//!   per-step signature chain for (that contact, this device), under the key
//!   this device stored for the contact — never a key the artifact carries.
//! - **derive sender**: the contact whose key verified. No field the sender
//!   wrote names the sender.
//! - **check recipient**: the operation's `to_device_id`, or the receipt's
//!   `devid_b`, is this device.
//! - **derive the object key**: what the object IS — a transfer by its op id
//!   (the signed operation bytes, signature included), a receipt by its
//!   commitment. Two copies of one object are one staged row, so a copy that
//!   arrives first decides nothing.
//! - **bind**: a receipt and a transfer from the same verified sender are one
//!   pair when the receipt's signed child tip is the successor recomputed from
//!   the transfer's operation — the one rule the canonical apply also checks.
//!
//! A half that fails any stage is not recognized, and nothing is recorded
//! about it (DSM Amendment A1). Copies are observed by the address and message
//! id the spool held them under; those observations are transport data, used
//! to mark copies consumed and to keep a route polled, never as identity.

use dsm::types::operations::Operation;
use dsm::types::receipt_types::StitchedReceiptV2;
use prost::Message;

use crate::storage::client_db::recipient_staging::{self, LocatorHint, StagedReceipt, StagedTransfer};

/// A transfer half this device verified: SIG A under the stored key of
/// `staged.sender`, addressed to this device.
#[derive(Debug, Clone)]
pub struct RecognizedTransfer {
    /// The signed operation, with SIG A attached — byte-identical to what the
    /// sender advanced.
    pub op: Operation,
    /// What the transfer moves and says, read from `op`.
    pub terms: super::recipient_accept::TransferTerms,
    pub staged: StagedTransfer,
    /// The economic locator hints this copy carried. Untrusted.
    pub hint: LocatorHint,
}

/// A receipt half this device verified: its `sig_a` chain for
/// (`staged.sender`, this device).
#[derive(Debug, Clone)]
pub struct RecognizedReceipt {
    pub receipt: StitchedReceiptV2,
    pub staged: StagedReceipt,
}

/// What the boundary made of a transfer half. Not being recognized is a fact
/// about the half, not a failure: an `Err` from recognition is reserved for
/// this device being unable to decide (its own id or its store unreadable).
#[derive(Debug, Clone)]
pub enum TransferRecognition {
    Recognized(Box<RecognizedTransfer>),
    /// Why the half is not a transfer this device can take.
    NotRecognized(String),
}

/// What the boundary made of a receipt half.
#[derive(Debug, Clone)]
pub enum ReceiptRecognition {
    /// A copy of a receipt this device already accepted: its commitment is
    /// the one the relationship's acceptance journal holds. Its signature chain
    /// is not checked again — it was checked when the receipt was accepted,
    /// and the cert head it chained to has since advanced past it.
    Accepted,
    /// A receipt verified now.
    Verified(Box<RecognizedReceipt>),
    /// Why the half is not a receipt this device can take.
    NotRecognized(String),
}

/// What ingesting one copy did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ingested {
    /// Recognized; its object is staged (now or already) and this copy observed.
    Staged,
    /// Recognized, but the canonical apply has already decided its step — the
    /// transfer's nonce is spent, or the receipt's step is taken — so it can
    /// never execute here. Nothing is staged; the copy may be consumed.
    Decided,
    /// Not recognized. Nothing is recorded about it.
    NotRecognized(String),
}

/// A receipt that names a staged transfer's successor and did not bind to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unbound {
    /// Its state rules fail against the Device Tree root and genesis this
    /// device pinned for the sender: it does not prove the move of the
    /// sender's root it signs, so it never binds and nothing is credited.
    Refused(String),
    /// The sender's Device Tree root is not pinned here yet, so its state
    /// rules cannot be decided: the pair waits, staged and unbound, and binds
    /// on a later copy once they can.
    Pending(String),
}

/// What ingesting one copy did, every staged object of the same sender that
/// could not be read back while looking for its partner, and every receipt
/// that named the transfer's successor without binding. Neither binds; both
/// are reported, and neither stops this copy's ingestion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestOutcome {
    pub ingested: Ingested,
    pub unreadable_candidates: Vec<String>,
    pub unbound: Vec<Unbound>,
}

impl IngestOutcome {
    fn only(ingested: Ingested) -> Self {
        Self {
            ingested,
            unreadable_candidates: Vec::new(),
            unbound: Vec::new(),
        }
    }
}

/// This device's id. Nothing can be checked as addressed here without it.
pub(crate) fn this_device() -> Result<[u8; 32], String> {
    let id = crate::sdk::app_state::AppState::get_device_id()
        .ok_or_else(|| "this device has no device id".to_string())?;
    <[u8; 32]>::try_from(id.as_slice())
        .map_err(|e| format!("this device's id is not 32 bytes: {e}"))
}

/// What a transfer IS: the id of its signed operation bytes (signature
/// included), the exact bytes a receipt's child tip consumes.
pub(crate) fn transfer_object_id(signed_operation_bytes: &[u8]) -> [u8; 32] {
    let mut h = dsm::crypto::blake3::dsm_domain_hasher(dsm::tagged_domain!(
        b"DSM/recipient-transfer-object/v1"
    ));
    h.update(signed_operation_bytes);
    *h.finalize().as_bytes()
}

/// Recognize a transfer half: `wire` is the `OnlineTransferRequest` a spooled
/// envelope carried, `header_sender` the Base32 device id its header named.
pub fn recognize_transfer(wire: &[u8], header_sender: &str) -> Result<TransferRecognition, String> {
    use TransferRecognition::NotRecognized;
    // parse
    let req = match dsm::types::proto::OnlineTransferRequest::decode(wire) {
        Ok(r) => r,
        Err(e) => return Ok(NotRecognized(format!("the transfer does not decode: {e}"))),
    };
    if req.canonical_operation_bytes.is_empty() {
        return Ok(NotRecognized(
            "the transfer carries no canonical operation bytes".to_string(),
        ));
    }
    // resolve candidate identity: a hint choosing which stored key to try
    let Some(candidate) = crate::util::text_id::decode_base32_crockford(header_sender) else {
        return Ok(NotRecognized(format!(
            "the header names {header_sender}, not a Base32 device id"
        )));
    };
    let candidate = match <[u8; 32]>::try_from(candidate.as_slice()) {
        Ok(id) => id,
        Err(e) => {
            return Ok(NotRecognized(format!(
                "the header names {header_sender}, not a device id: {e}"
            )))
        }
    };
    let Some(ak) = super::storage_routes::stored_sender_ak(header_sender)? else {
        return Ok(NotRecognized(format!(
            "no locally trusted sender AK for {header_sender}"
        )));
    };
    // verify
    let op = match Operation::decode_and_bind_signed(
        &req.canonical_operation_bytes,
        &req.signature,
        &ak,
    ) {
        Ok(op) => op,
        Err(e) => {
            return Ok(NotRecognized(format!(
                "SIG A does not verify under {header_sender}'s stored key: {e}"
            )))
        }
    };
    // derive sender: the contact whose key verified
    let sender = candidate;
    // check recipient
    let Operation::Transfer {
        to_device_id,
        nonce,
        amount,
        token_id,
        message,
        ..
    } = &op
    else {
        return Ok(NotRecognized(format!(
            "the signed operation is a {}, not a transfer",
            op.get_operation_type()
        )));
    };
    let here = this_device()?;
    if !crate::sdk::core_sdk::addressed_to(to_device_id, &here) {
        return Ok(NotRecognized(
            "the signed transfer is addressed to another device".to_string(),
        ));
    }
    // derive the object key
    let staged = StagedTransfer {
        op_id: transfer_object_id(&op.to_bytes()),
        sender,
        nonce_hash: crate::storage::codecs::hash_blake3_bytes(nonce),
        canonical_operation_bytes: req.canonical_operation_bytes,
        signature: req.signature,
    };
    let terms = super::recipient_accept::TransferTerms::of(amount, token_id, message);
    Ok(TransferRecognition::Recognized(Box::new(
        RecognizedTransfer {
            op,
            terms,
            staged,
            hint: LocatorHint {
                economic_position: req.sender_economic_position,
                debit_mutation_index: req.sender_debit_mutation_index,
            },
        },
    )))
}

/// Recognize a receipt half from the full A-side receipt wire bytes.
pub fn recognize_receipt(full_receipt_bytes: &[u8]) -> Result<ReceiptRecognition, String> {
    use ReceiptRecognition::NotRecognized;
    // parse
    let receipt = match StitchedReceiptV2::from_canonical_protobuf(full_receipt_bytes) {
        Ok(r) => r,
        Err(e) => return Ok(NotRecognized(format!("the receipt does not decode: {e}"))),
    };
    // check recipient before anything is verified against a relationship: the
    // chain is looked up for (devid_a, devid_b), which must include this device
    let here = this_device()?;
    if receipt.devid_b != here {
        return Ok(NotRecognized(
            "the receipt names another device as its recipient".to_string(),
        ));
    }
    let commitment = match receipt.compute_commitment() {
        Ok(c) => c,
        Err(e) => {
            return Ok(NotRecognized(format!(
                "the receipt commitment cannot be computed: {e}"
            )))
        }
    };
    let relationship_key =
        dsm::core::bilateral_transaction_manager::compute_smt_key(&here, &receipt.devid_a);
    // what the object is: one this device has already accepted
    if crate::storage::client_db::get_acceptance_journal_by_commitment(
        &relationship_key,
        &commitment,
    )
    .map_err(|e| format!("the acceptance journal is unreadable: {e}"))?
    .is_some()
    {
        return Ok(ReceiptRecognition::Accepted);
    }
    // resolve candidate identity
    let candidate_b32 = crate::util::text_id::encode_base32_crockford(&receipt.devid_a);
    let Some(ak) = super::storage_routes::stored_sender_ak(&candidate_b32)? else {
        return Ok(NotRecognized(format!(
            "no locally trusted sender AK for {candidate_b32}"
        )));
    };
    // verify
    if let Err(e) = super::storage_routes::verify_inbound_receipt_sig_a(&receipt, &commitment, &ak)?
    {
        return Ok(NotRecognized(format!(
            "the receipt's sig_a chain does not verify: {e}"
        )));
    }
    // derive sender
    let sender = receipt.devid_a;
    // derive the object key
    let staged = StagedReceipt {
        commitment,
        sender,
        relationship_key,
        parent_tip: receipt.parent_tip,
        evidence_bytes: full_receipt_bytes.to_vec(),
        evidence_digest: crate::storage::client_db::evidence_content_digest(
            crate::storage::client_db::ArtifactRole::EvidenceA,
            full_receipt_bytes,
        ),
    };
    Ok(ReceiptRecognition::Verified(Box::new(RecognizedReceipt {
        receipt,
        staged,
    })))
}

/// The signed operation of a staged transfer, re-derived from its canonical
/// bytes and SIG A under the sender's stored key — the staged row is the signed
/// material itself, and its meaning is read from it again every time.
pub fn signed_operation_of(t: &StagedTransfer) -> Result<Operation, String> {
    let sender_b32 = crate::util::text_id::encode_base32_crockford(&t.sender);
    let ak = super::storage_routes::resolve_trusted_sender_ak(&sender_b32)?;
    Operation::decode_and_bind_signed(&t.canonical_operation_bytes, &t.signature, &ak).map_err(
        |e| format!("the staged transfer no longer verifies under {sender_b32}'s key: {e}"),
    )
}

/// What a staged receipt is to the transfer of `op`.
enum Binding {
    /// The transfer's receipt.
    Binds,
    /// The receipt of another operation.
    Other,
    /// It names the transfer's successor and does not bind.
    Unbound(Unbound),
}

/// What `receipt` is to the transfer of `op`. It is that transfer's receipt
/// when its signed child tip is the successor of its signed parent under
/// `op` and its transition entropy, and its state rules hold
/// (`verify_receipt_state`, the rules every producer and the BLE receiver
/// check): its writes fold from its parent root to its child root, under the
/// Device Tree root and genesis this device pinned for the sender. The
/// signatures are checked before a receipt is staged; a receipt they pass
/// still proves nothing about the sender's root until these rules hold.
fn binding(
    receipt: &StitchedReceiptV2,
    op: &Operation,
    here: &[u8; 32],
) -> Result<Binding, String> {
    let relationship_key =
        dsm::core::bilateral_transaction_manager::compute_smt_key(here, &receipt.devid_a);
    if crate::sdk::core_sdk::successor_child_tip(
        &relationship_key,
        &receipt.parent_tip,
        here,
        &op.to_bytes(),
        &receipt.transition_entropy,
    ) != receipt.child_tip
    {
        return Ok(Binding::Other);
    }
    let sender = crate::util::text_id::encode_base32_crockford(&receipt.devid_a);
    let root = crate::storage::client_db::get_contact_device_tree_root(&receipt.devid_a)
        .map_err(|e| format!("{sender}'s pinned Device Tree root is unreadable: {e}"))?;
    let contact = crate::storage::client_db::get_contact_by_device_id(&receipt.devid_a)
        .map_err(|e| format!("{sender}'s contact is unreadable: {e}"))?;
    let (Some(root), Some(contact)) = (root, contact) else {
        return Ok(Binding::Unbound(Unbound::Pending(format!(
            "{sender}'s Device Tree root is not pinned here yet, so its receipt's state rules \
             cannot be decided"
        ))));
    };
    let author_genesis = match <[u8; 32]>::try_from(contact.genesis_hash.as_slice()) {
        Ok(genesis) => genesis,
        Err(e) => return Err(format!("{sender}'s pinned genesis is not 32 bytes: {e}")),
    };
    let device_tree_commitment =
        dsm::types::receipt_types::DeviceTreeAcceptanceCommitment::from_root(root);
    Ok(
        match dsm::verification::receipt_verification::verify_receipt_state(
            receipt,
            &dsm::verification::receipt_verification::ReceiptStateContext {
                device_tree_commitment: &device_tree_commitment,
                author_genesis,
                operation: op,
                bearer: None,
            },
        ) {
            Ok(()) => Binding::Binds,
            Err(e) => Binding::Unbound(Unbound::Refused(format!(
                "{sender}'s receipt names this transfer's successor, and its state rules fail: {e}"
            ))),
        },
    )
}

/// Ingest one copy of a transfer half read at `address` under `message_id`.
///
/// `Err` is this device failing (its store, its own id); a half that fails a
/// stage is `NotRecognized`, never an error.
pub fn ingest_transfer_half(
    wire: &[u8],
    header_sender: &str,
    address: &str,
    message_id: &str,
) -> Result<IngestOutcome, String> {
    let recognized = match recognize_transfer(wire, header_sender)? {
        TransferRecognition::Recognized(r) => *r,
        TransferRecognition::NotRecognized(why) => {
            return Ok(IngestOutcome::only(Ingested::NotRecognized(why)))
        }
    };
    let store = |e: anyhow::Error| format!("staging a transfer from {header_sender}: {e}");
    if recipient_staging::nonce_decided(&recognized.staged.nonce_hash).map_err(store)? {
        return Ok(IngestOutcome::only(Ingested::Decided));
    }
    recipient_staging::stage_transfer(&recognized.staged).map_err(store)?;
    recipient_staging::observe_transfer(
        &recognized.staged.op_id,
        address,
        message_id,
        recognized.hint,
    )
    .map_err(store)?;
    let here = this_device()?;
    let mut unreadable_candidates = Vec::new();
    let mut unbound = Vec::new();
    for staged in
        recipient_staging::unbound_receipts_from(&recognized.staged.sender).map_err(store)?
    {
        let receipt = match StitchedReceiptV2::from_canonical_protobuf(&staged.evidence_bytes) {
            Ok(r) => r,
            Err(e) => {
                unreadable_candidates.push(format!("a staged receipt no longer decodes: {e}"));
                continue;
            }
        };
        match binding(&receipt, &recognized.op, &here)? {
            Binding::Binds => {
                recipient_staging::bind(&recognized.staged.op_id, &staged.commitment)
                    .map_err(store)?;
                break;
            }
            Binding::Other => {}
            Binding::Unbound(why) => unbound.push(why),
        }
    }
    Ok(IngestOutcome {
        ingested: Ingested::Staged,
        unreadable_candidates,
        unbound,
    })
}

/// Ingest one copy of an evidence half read at `address` under `message_id`.
pub fn ingest_evidence_half(
    full_receipt_bytes: &[u8],
    address: &str,
    message_id: &str,
) -> Result<IngestOutcome, String> {
    let recognized = match recognize_receipt(full_receipt_bytes)? {
        ReceiptRecognition::Verified(r) => *r,
        ReceiptRecognition::Accepted => return Ok(IngestOutcome::only(Ingested::Decided)),
        ReceiptRecognition::NotRecognized(why) => {
            return Ok(IngestOutcome::only(Ingested::NotRecognized(why)))
        }
    };
    let store = |e: anyhow::Error| format!("staging a receipt: {e}");
    if recipient_staging::step_decided(
        &recognized.staged.relationship_key,
        &recognized.staged.parent_tip,
    )
    .map_err(store)?
    {
        return Ok(IngestOutcome::only(Ingested::Decided));
    }
    recipient_staging::stage_receipt(&recognized.staged).map_err(store)?;
    recipient_staging::observe_receipt(&recognized.staged.commitment, address, message_id)
        .map_err(store)?;
    let here = this_device()?;
    let mut unreadable_candidates = Vec::new();
    let mut unbound = Vec::new();
    for staged in
        recipient_staging::unbound_transfers_from(&recognized.staged.sender).map_err(store)?
    {
        let op = match signed_operation_of(&staged) {
            Ok(op) => op,
            Err(e) => {
                unreadable_candidates.push(e);
                continue;
            }
        };
        match binding(&recognized.receipt, &op, &here)? {
            Binding::Binds => {
                recipient_staging::bind(&staged.op_id, &recognized.staged.commitment)
                    .map_err(store)?;
                break;
            }
            Binding::Other => {}
            Binding::Unbound(why) => unbound.push(why),
        }
    }
    Ok(IngestOutcome {
        ingested: Ingested::Staged,
        unreadable_candidates,
        unbound,
    })
}

/// What a copy read on a PREVIOUS-tip route is. Such a route fixes a tip this
/// device advanced past, so nothing on it is staged: a copy of an object the
/// canonical apply has decided is consumed, and anything else is left where it
/// is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaleCopy {
    /// Recognized, and the apply has decided its step.
    Decided,
    /// Recognized; its step is not decided. Left unconsumed.
    Undecided,
    /// Not recognized. Nothing is recorded about it.
    NotRecognized(String),
}

pub fn classify_stale_transfer_copy(wire: &[u8], header_sender: &str) -> Result<StaleCopy, String> {
    let recognized = match recognize_transfer(wire, header_sender)? {
        TransferRecognition::Recognized(r) => r,
        TransferRecognition::NotRecognized(why) => return Ok(StaleCopy::NotRecognized(why)),
    };
    let decided = recipient_staging::nonce_decided(&recognized.staged.nonce_hash)
        .map_err(|e| format!("reading the spent nonces: {e}"))?;
    Ok(if decided {
        StaleCopy::Decided
    } else {
        StaleCopy::Undecided
    })
}

pub fn classify_stale_receipt_copy(full_receipt_bytes: &[u8]) -> Result<StaleCopy, String> {
    let recognized = match recognize_receipt(full_receipt_bytes)? {
        ReceiptRecognition::Verified(r) => r,
        ReceiptRecognition::Accepted => return Ok(StaleCopy::Decided),
        ReceiptRecognition::NotRecognized(why) => return Ok(StaleCopy::NotRecognized(why)),
    };
    let decided = recipient_staging::step_decided(
        &recognized.staged.relationship_key,
        &recognized.staged.parent_tip,
    )
    .map_err(|e| format!("reading the canonical apply identities: {e}"))?;
    Ok(if decided {
        StaleCopy::Decided
    } else {
        StaleCopy::Undecided
    })
}

#[cfg(test)]
mod tests {
    //! The ingestion boundary against what a hostile sender, anyone who can
    //! seal to the recipient, and a withholding node can put on the spool.
    //! Every transfer here is a real send on the fleet; a hostile copy is that
    //! send's own material changed the way its sender could change it, posted
    //! through the sender's own spool client or handed to the boundary exactly
    //! as the poll loop hands it. Each asserts that nothing durable came from
    //! the bad input and that the honest transfer is credited exactly once.

    use super::*;
    use crate::handlers::app_router_impl::transfer_nonce;
    use crate::storage::client_db;
    use crate::test_support::arrivals::{the_one_transfer, OneTransfer};
    use crate::test_support::two_device::Pair;
    use serial_test::serial;

    /// A sends B 10; B has not polled. The transfer as B's poll reads it,
    /// with B entered.
    async fn sent() -> (Pair, OneTransfer) {
        let p = Pair::boot(100, 0).await;
        let sent = p.a.send(&p.b, 10).await;
        assert!(sent.success, "{:?}", sent.error_message);
        let one = the_one_transfer(&p.b, &p.fleet).await;
        p.b.enter();
        (p, one)
    }

    /// Rows in a staging table on the ENTERED device.
    fn rows(table: &str) -> i64 {
        let binding = client_db::get_connection().expect("conn");
        let conn = binding.lock().expect("the store lock");
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .expect("count")
    }

    /// Nothing is staged, bound or observed on the ENTERED device.
    fn nothing_staged() {
        for table in [
            "recipient_staged_transfer",
            "recipient_staged_receipt",
            "recipient_pair",
            "recipient_transfer_observation",
            "recipient_receipt_observation",
        ] {
            assert_eq!(rows(table), 0, "{table} holds nothing");
        }
    }

    /// `wire` with raw protobuf fields appended: what a sender can write into
    /// its own request beside the signed bytes.
    fn with_appended_fields(wire: &[u8], fields: &[(u32, FieldValue)]) -> Vec<u8> {
        use prost::encoding::{encode_key, encode_varint, WireType};
        let mut out = wire.to_vec();
        for (tag, value) in fields {
            match value {
                FieldValue::Varint(v) => {
                    encode_key(*tag, WireType::Varint, &mut out);
                    encode_varint(*v, &mut out);
                }
                FieldValue::Bytes(b) => {
                    encode_key(*tag, WireType::LengthDelimited, &mut out);
                    encode_varint(b.len() as u64, &mut out);
                    out.extend_from_slice(b);
                }
            }
        }
        out
    }

    enum FieldValue {
        Varint(u64),
        Bytes(Vec<u8>),
    }

    /// A sync that completed and recorded no error. `success` alone is not
    /// that: a sync reports success while its passes record errors.
    fn clean(synced: &dsm::types::proto::StorageSyncResponse) {
        assert!(synced.success, "{:?}", synced.errors);
        assert!(synced.errors.is_empty(), "{:?}", synced.errors);
    }

    /// The copy was staged, and every staged object it was checked against
    /// could be read.
    fn staged(outcome: Result<IngestOutcome, String>) {
        assert_eq!(
            outcome.expect("ingest"),
            IngestOutcome::only(Ingested::Staged)
        );
    }

    /// What ingesting the copy did; every staged object it was checked against
    /// could be read.
    fn ingested(outcome: Result<IngestOutcome, String>) -> Ingested {
        let outcome = outcome.expect("ingest");
        assert!(
            outcome.unreadable_candidates.is_empty(),
            "{:?}",
            outcome.unreadable_candidates
        );
        outcome.ingested
    }

    /// The fields the wire used to restate, filled with lies: 3 `amount`,
    /// 1 `token_id`, 7 `from_device_id` naming a device that never sent it.
    fn lying_wrapper(wire: &[u8], named_sender: [u8; 32]) -> Vec<u8> {
        with_appended_fields(
            wire,
            &[
                (3, FieldValue::Varint(1_000_000)),
                (1, FieldValue::Bytes(b"NOTX".to_vec())),
                (7, FieldValue::Bytes(named_sender.to_vec())),
            ],
        )
    }

    /// Post `request` as a transfer from A to B under `message_id` on
    /// `route`, sealed to B, through A's own spool client — what A, as a
    /// hostile sender, can do with its own transfer. The envelope is A's own
    /// frozen transfer envelope (A kept the sealed bytes; B opens them), with
    /// only its id and its request body changed.
    async fn post_as_the_sender(
        p: &Pair,
        route: &str,
        original_id: &str,
        message_id: &str,
        request: Vec<u8>,
    ) {
        use dsm::types::proto as pb;
        p.a.enter();
        let sealed = crate::sdk::b0x_sdk::kept_seal(original_id).expect("A kept the sealed send");
        p.b.enter();
        let outer = dsm::envelope::from_canonical_bytes(&sealed).expect("the sealed envelope");
        let mut inner = crate::sdk::b0x_sdk::open_sealed(
            &crate::sdk::b0x_sdk::local_kyber_secret().expect("B's key"),
            &outer,
        )
        .expect("B opens it");
        let id = crate::util::text_id::decode_base32_crockford(message_id).expect("a Base32 id");
        inner.message_id = id.clone();
        let Some(pb::envelope::Payload::UniversalTx(tx)) = &mut inner.payload else {
            panic!("A's transfer envelope carries a UniversalTx");
        };
        for op in &mut tx.ops {
            op.op_id = Some(pb::Hash32 { v: id.clone() });
            if let Some(pb::universal_op::Kind::Invoke(invoke)) = &mut op.kind {
                if let Some(args) = &mut invoke.args {
                    args.body = request.clone();
                }
            }
        }
        p.a.enter();
        crate::sdk::b0x_sdk::seal_for(&p.b.device_id, message_id, &inner.encode_to_vec())
            .expect("seal for B");
        let mut spool = crate::sdk::b0x_sdk::B0xSDK::new(
            crate::util::text_id::encode_base32_crockford(&p.a.device_id),
            p.a.router().core_sdk.clone(),
            p.fleet.endpoints(),
        )
        .expect("A's spool client");
        spool
            .submit_stored_envelope_with_retry(
                route,
                message_id,
                &crate::sdk::b0x_sdk::B0xRetryConfig::default(),
            )
            .await
            .expect("the copy reaches the members");
    }

    /// Every received online transfer in B's history: (id, amount, token).
    fn received_history(p: &Pair) -> Vec<(String, u64, String)> {
        p.b.enter();
        let b = crate::util::text_id::encode_base32_crockford(&p.b.device_id);
        client_db::get_transaction_history(Some(&b), None, None)
            .expect("history")
            .into_iter()
            .filter(|t| t.tx_type == "online" && t.to_device == b)
            .map(|t| {
                let token = String::from_utf8(
                    t.metadata
                        .get("token_id")
                        .expect("the row names its token")
                        .clone(),
                )
                .expect("a text token");
                (t.tx_id, t.amount, token)
            })
            .collect()
    }

    /// THE ARRIVAL-ORDER AND DUPLICATE-TRUTH PROOF, end to end. A hostile
    /// sender posts its own transfer a second time under another id, the
    /// wrapper now claiming a million NOTX from a third device. Both copies
    /// reach B's spool; B syncs. They are one signed object, so they stage as
    /// one and bind to one receipt: B is credited 10 ERA once, its history
    /// reads the signed terms, and both copies are marked consumed under the
    /// ids the spool holds them by.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_second_copy_with_a_lying_wrapper_is_the_same_transfer_credited_once() {
        let (p, one) = sent().await;
        let second_id = crate::util::text_id::encode_base32_crockford(&[0x7Au8; 16]);
        post_as_the_sender(
            &p,
            &one.route,
            &one.message_id,
            &second_id,
            lying_wrapper(&one.transfer_bytes, [0xC7; 32]),
        )
        .await;

        clean(&p.b.sync().await);
        assert_eq!(p.b.era_balance(), 10, "credited once, in the signed amount");
        assert_eq!(
            received_history(&p),
            vec![(one.message_id.clone(), 10, "ERA".to_string())],
            "one row, named by the transfer, with the signed terms"
        );
        p.b.enter();
        for id in [&one.message_id, &second_id] {
            assert!(
                client_db::b0x_consumed::is_consumed(&one.route, id).expect("consumed"),
                "the copy the spool holds under {id} is consumed"
            );
        }
        nothing_staged();
    }

    /// A sender named in a wrapper is not a sender. The copy's wrapper names a
    /// third device; the boundary stages the transfer under the contact whose
    /// key verified it, so while it waits it holds the send barrier toward A
    /// only.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_sender_named_in_a_wrapper_blocks_nothing() {
        let (p, one) = sent().await;
        let named = [0xC7u8; 32];
        staged(ingest_transfer_half(
            &lying_wrapper(&one.transfer_bytes, named),
            &one.header_sender,
            &one.route,
            &one.message_id,
        ));
        assert!(
            recipient_staging::counterparty_has_unconverged_inbound(&p.a.device_id)
                .expect("barrier"),
            "the transfer in flight holds the barrier toward its real sender"
        );
        assert!(
            !recipient_staging::counterparty_has_unconverged_inbound(&named).expect("barrier"),
            "and toward nobody the wrapper names"
        );
    }

    /// Junk sealed to B, and a copy whose header names a device B holds no key
    /// for, are not recognized: nothing is staged, bound or observed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn junk_and_an_unknown_sender_are_recorded_nowhere() {
        let (p, one) = sent().await;
        let junk = ingested(ingest_transfer_half(
            b"not a request",
            &one.header_sender,
            &one.route,
            "JUNK",
        ));
        assert!(matches!(junk, Ingested::NotRecognized(_)), "{junk:?}");
        let stranger = crate::util::text_id::encode_base32_crockford(&p.b.device_id);
        let unknown = ingested(ingest_transfer_half(
            &one.transfer_bytes,
            &stranger,
            &one.route,
            &one.message_id,
        ));
        assert!(
            matches!(&unknown, Ingested::NotRecognized(why) if why.contains("no locally trusted sender AK")),
            "{unknown:?}"
        );
        nothing_staged();
    }

    /// A transfer whose SIG A does not verify under the key B holds for the
    /// contact its header names is not recognized, and nothing is recorded
    /// about it: the sent request with one byte of its signature changed, as
    /// anyone who can seal to B can post it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_transfer_whose_sig_a_does_not_verify_is_recorded_nowhere() {
        let (_p, one) = sent().await;
        let mut forged =
            dsm::types::proto::OnlineTransferRequest::decode(one.transfer_bytes.as_slice())
                .expect("the delivered request");
        forged.signature[0] ^= 0xFF;
        let out = ingested(ingest_transfer_half(
            &forged.encode_to_vec(),
            &one.header_sender,
            &one.route,
            &one.message_id,
        ));
        assert!(
            matches!(&out, Ingested::NotRecognized(why) if why.contains("SIG A does not verify")),
            "{out:?}"
        );
        nothing_staged();
    }

    /// A transfer A signed to another device, sent to B: SIG A verifies, and
    /// it is still not B's. The other device is A itself, and the nonce the
    /// one A's send would derive. Nothing is staged.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_transfer_addressed_to_another_device_is_not_recognized() {
        let (p, one) = sent().await;
        let (tip, _) = a_view_of_b(&p);
        let elsewhere = p.a.device_id;
        let request = signed_by_a(
            &p,
            elsewhere,
            p.a.ak_pk.clone(),
            5,
            transfer_nonce(&tip, 5, "ERA", &elsewhere),
        );
        let out = ingested(ingest_transfer_half(
            &request,
            &one.header_sender,
            &one.route,
            "ELSEWHERE",
        ));
        assert!(
            matches!(&out, Ingested::NotRecognized(why) if why.contains("another device")),
            "{out:?}"
        );
        nothing_staged();
    }

    /// A receipt whose `sig_a` does not verify is not recognized; the
    /// transfer it would pair with stays unbound.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_receipt_that_does_not_verify_is_recorded_nowhere() {
        let (_p, one) = sent().await;
        let mut receipt =
            StitchedReceiptV2::from_canonical_protobuf(&one.evidence_bytes).expect("the receipt");
        receipt.sig_a[0] ^= 0xFF;
        let tampered = receipt.to_full_protobuf().expect("re-encode");
        let out = ingested(ingest_evidence_half(
            &tampered,
            &one.evidence_route,
            &one.evidence_message_id,
        ));
        assert!(matches!(out, Ingested::NotRecognized(_)), "{out:?}");
        assert_eq!(rows("recipient_staged_receipt"), 0);
        assert_eq!(rows("recipient_receipt_observation"), 0);
    }

    /// A receipt its own sender signed, every signature valid and its child
    /// tip this transfer's successor, whose state writes do not prove the
    /// move of the sender's root, binds nothing and credits nothing:
    /// MR-DSM-0092's "recompute hashes and roots" on the online path. Three
    /// forgeries are refused: a child root the writes do not fold to, a
    /// write whose path is not its leaf's under the parent root, and a write
    /// the operation does not imply. The honest receipt of the same transfer
    /// still binds, and the sync credits it once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_signed_receipt_whose_state_writes_fail_binds_nothing() {
        use crate::test_support::receipts::Party;
        use dsm::types::receipt_types::{
            compute_receipt_challenge_response_target, ReceiptLeaf, ReceiptWrite,
        };
        let (p, one) = sent().await;
        let op = match recognize_transfer(&one.transfer_bytes, &one.header_sender)
            .expect("recognition")
        {
            TransferRecognition::Recognized(r) => r.op,
            TransferRecognition::NotRecognized(why) => panic!("the honest transfer: {why}"),
        };
        let honest =
            StitchedReceiptV2::from_canonical_protobuf(&one.evidence_bytes).expect("the receipt");
        let (a, b) = (Party::from_seed(0x0A), Party::from_seed(0x0B));
        assert_eq!(
            a.device_id(),
            honest.devid_a,
            "the harness's A is seed 0x0A"
        );
        // As A's wallet signs a wallet.send receipt: the relationship's
        // first per-step EK, certified by A's AK, answering the commitment
        // bound to itself.
        let signed_by_a = |mut r: StitchedReceiptV2| -> Vec<u8> {
            let commitment = r.compute_commitment().expect("the commitment");
            let target = compute_receipt_challenge_response_target(&commitment, &commitment);
            let c_pre = dsm::core::bilateral_transaction_manager::compute_precommit(
                &r.parent_tip,
                &op.with_cleared_signature().to_bytes(),
                &r.transition_entropy,
            );
            let answer = a.answer(&b, &r.parent_tip, &c_pre, &target);
            r.set_ek_pk_a(answer.ek_pk);
            r.set_ek_cert_a(answer.ek_cert);
            r.set_kyber_ct_a(answer.kyber_ct);
            r.add_sig_a(answer.sig);
            r.to_full_protobuf().expect("re-encode")
        };
        assert!(
            matches!(
                recognize_receipt(&signed_by_a(honest.clone())).expect("recognition"),
                ReceiptRecognition::Verified(_)
            ),
            "the honest receipt, signed this way, verifies"
        );

        let mut wrong_root = honest.clone();
        wrong_root.child_root[0] ^= 0x01;
        let mut wrong_path = honest.clone();
        wrong_path.step_writes[0].path.siblings[0] ^= 0x01;
        let mut extra_write = honest.clone();
        extra_write.step_writes.push(ReceiptWrite {
            leaf: ReceiptLeaf::AnchorState,
            path: honest.step_writes[0].path.clone(),
        });

        staged(ingest_transfer_half(
            &one.transfer_bytes,
            &one.header_sender,
            &one.route,
            &one.message_id,
        ));
        for (forgery, receipt) in [
            ("a child root its writes do not fold to", wrong_root),
            ("a write whose path is not its leaf's", wrong_path),
            ("a write the operation does not imply", extra_write),
        ] {
            let bytes = signed_by_a(receipt);
            assert!(
                matches!(
                    recognize_receipt(&bytes).expect("recognition"),
                    ReceiptRecognition::Verified(_)
                ),
                "{forgery}: every signature verifies"
            );
            let out = ingest_evidence_half(&bytes, &one.evidence_route, &one.evidence_message_id)
                .expect("ingest");
            assert_eq!(out.ingested, Ingested::Staged, "{forgery}");
            assert!(
                matches!(out.unbound.as_slice(), [Unbound::Refused(_)]),
                "{forgery}: the receipt is refused, and only it"
            );
            assert_eq!(rows("recipient_pair"), 0, "{forgery}: nothing binds");
        }
        assert_eq!(p.b.era_balance(), 0, "nothing is credited");

        staged(ingest_evidence_half(
            &one.evidence_bytes,
            &one.evidence_route,
            &one.evidence_message_id,
        ));
        assert_eq!(rows("recipient_pair"), 1, "the honest receipt binds");
        let synced = p.b.sync().await;
        assert!(synced.success, "{:?}", synced.errors);
        assert!(
            synced.errors.iter().all(|e| e.contains("did not bind")),
            "only the forgeries are reported: {:?}",
            synced.errors
        );
        assert_eq!(p.b.era_balance(), 10);
    }

    /// While this device has not pinned the sender's Device Tree root, a
    /// receipt's state rules cannot be decided: the pair waits, staged and
    /// unbound, and binds on the next copy once the root is pinned.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_receipt_waits_while_its_senders_device_tree_root_is_not_pinned() {
        let (p, one) = sent().await;
        let sender = StitchedReceiptV2::from_canonical_protobuf(&one.evidence_bytes)
            .expect("the receipt")
            .devid_a;
        let pinned = client_db::get_contact_device_tree_root(&sender)
            .expect("the contact reads")
            .expect("the harness pins the sender's root");
        {
            let binding = client_db::get_connection().expect("conn");
            let conn = binding.lock().expect("the store lock");
            conn.execute(
                "UPDATE contacts SET device_tree_root = NULL WHERE device_id = ?1",
                rusqlite::params![&sender[..]],
            )
            .expect("unpin the sender's root");
        }
        staged(ingest_transfer_half(
            &one.transfer_bytes,
            &one.header_sender,
            &one.route,
            &one.message_id,
        ));
        let out = ingest_evidence_half(
            &one.evidence_bytes,
            &one.evidence_route,
            &one.evidence_message_id,
        )
        .expect("ingest");
        assert!(
            matches!(out.unbound.as_slice(), [Unbound::Pending(_)]),
            "the pair waits on the sender's root, and only it"
        );
        assert_eq!(rows("recipient_pair"), 0, "the pair waits");

        client_db::store_contact_device_tree_root(&sender, &pinned).expect("pin the root");
        staged(ingest_evidence_half(
            &one.evidence_bytes,
            &one.evidence_route,
            &one.evidence_message_id,
        ));
        assert_eq!(rows("recipient_pair"), 1, "the next copy binds");
        clean(&p.b.sync().await);
        assert_eq!(p.b.era_balance(), 10);
    }

    /// Either half may arrive first: evidence first, the pair still binds
    /// when the transfer lands, and the sync credits it once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn evidence_first_binds_when_the_transfer_lands() {
        let (p, one) = sent().await;
        staged(ingest_evidence_half(
            &one.evidence_bytes,
            &one.evidence_route,
            &one.evidence_message_id,
        ));
        assert_eq!(rows("recipient_pair"), 0, "a receipt alone binds nothing");
        staged(ingest_transfer_half(
            &one.transfer_bytes,
            &one.header_sender,
            &one.route,
            &one.message_id,
        ));
        assert_eq!(
            rows("recipient_pair"),
            1,
            "the transfer binds the waiting receipt"
        );
        clean(&p.b.sync().await);
        assert_eq!(p.b.era_balance(), 10);
        p.b.enter();
        nothing_staged();
    }

    /// Copies of a finished transfer are decided, not staged: its nonce is
    /// spent and its step is taken, so a later copy of either half is
    /// consumed where it lies and never becomes staging state again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn copies_of_a_finished_transfer_are_decided_not_staged() {
        let (p, one) = sent().await;
        clean(&p.b.sync().await);
        assert_eq!(p.b.era_balance(), 10);
        p.b.enter();
        assert_eq!(
            ingested(ingest_transfer_half(
                &one.transfer_bytes,
                &one.header_sender,
                &one.route,
                "LATE",
            )),
            Ingested::Decided
        );
        assert_eq!(
            ingested(ingest_evidence_half(
                &one.evidence_bytes,
                &one.evidence_route,
                "LATE-EVIDENCE",
            )),
            Ingested::Decided
        );
        nothing_staged();
        assert_eq!(p.b.era_balance(), 10, "and nothing is credited twice");
    }

    /// A locator hint that does not locate the debit is not a verdict. A copy
    /// under another id points at the sender's previous economic position;
    /// the honest copy's hint admits, and B is credited once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_wrong_locator_hint_is_not_a_verdict() {
        let (p, one) = sent().await;
        let honest =
            dsm::types::proto::OnlineTransferRequest::decode(one.transfer_bytes.as_slice())
                .expect("the delivered request");
        assert!(
            honest.sender_economic_position > 0,
            "the debit sits after the sender's funding"
        );
        let misleading = dsm::types::proto::OnlineTransferRequest {
            sender_economic_position: honest.sender_economic_position - 1,
            ..honest.clone()
        };
        staged(ingest_transfer_half(
            &misleading.encode_to_vec(),
            &one.header_sender,
            &one.route,
            "MISLEADING",
        ));
        clean(&p.b.sync().await);
        assert_eq!(p.b.era_balance(), 10, "the honest hint admitted it");
        p.b.enter();
        nothing_staged();
    }

    /// A's relationship tip with B and the key A holds for B: what A's own
    /// send signs over.
    fn a_view_of_b(p: &Pair) -> ([u8; 32], Vec<u8>) {
        p.a.enter();
        let b = client_db::get_contact_by_device_id(&p.b.device_id)
            .expect("A's contacts")
            .expect("A holds B as a contact");
        let tip = crate::handlers::app_router_impl::contact_relationship_tip(&b)
            .expect("A's relationship tip with B");
        (tip, b.public_key)
    }

    /// A transfer A signs, built as A's send builds one (`to` the recipient's
    /// device id in Base32, `recipient` the key A holds for it), on the nonce
    /// A chooses; the locator hints are A's to write. As B's poll reads it.
    fn signed_by_a(
        p: &Pair,
        to_device_id: [u8; 32],
        recipient_key: Vec<u8>,
        amount: u64,
        nonce: Vec<u8>,
    ) -> Vec<u8> {
        p.a.enter();
        let op = Operation::Transfer {
            to_device_id: to_device_id.to_vec(),
            amount: dsm::types::token_types::Balance::amount(amount),
            token_id: b"ERA".to_vec(),
            policy_commit: crate::policy::builtin_policy_commit("ERA").expect("ERA"),
            mode: dsm::types::operations::TransactionMode::Unilateral,
            nonce,
            recipient: recipient_key,
            to: crate::util::text_id::encode_base32_crockford(&to_device_id).into_bytes(),
            message: String::new(),
            signature: Vec::new(),
            authority_policy: None,
        };
        let canonical = op.to_bytes();
        let signature = dsm::crypto::sphincs::sphincs_sign(
            &crate::sdk::signing_authority::current_secret_key().expect("A's signing key"),
            &canonical,
        )
        .expect("A signs");
        p.b.enter();
        dsm::types::proto::OnlineTransferRequest {
            signature,
            canonical_operation_bytes: canonical,
            sender_economic_position: 1,
            sender_debit_mutation_index: 0,
        }
        .encode_to_vec()
    }

    /// A receipt binds only the transfer whose operation its child tip is the
    /// successor under. With A's receipt staged, another transfer A signed to B
    /// stages but binds nothing; the transfer the receipt signs binds it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_receipt_binds_only_the_transfer_it_signs() {
        let (p, one) = sent().await;
        staged(ingest_evidence_half(
            &one.evidence_bytes,
            &one.evidence_route,
            &one.evidence_message_id,
        ));
        let (tip, b_key) = a_view_of_b(&p);
        let other = signed_by_a(
            &p,
            p.b.device_id,
            b_key,
            7,
            transfer_nonce(&tip, 7, "ERA", &p.b.device_id),
        );
        staged(ingest_transfer_half(
            &other,
            &one.header_sender,
            &one.route,
            "OTHER",
        ));
        assert_eq!(
            rows("recipient_pair"),
            0,
            "the receipt does not sign the other transfer"
        );
        staged(ingest_transfer_half(
            &one.transfer_bytes,
            &one.header_sender,
            &one.route,
            &one.message_id,
        ));
        let pairs = recipient_staging::pairs_in_flight().expect("pairs");
        let TransferRecognition::Recognized(signed) =
            recognize_transfer(&one.transfer_bytes, &one.header_sender).expect("recognition")
        else {
            panic!("the sent transfer is recognized");
        };
        assert_eq!(pairs.len(), 1);
        assert_eq!(
            pairs[0].op_id, signed.staged.op_id,
            "bound to the transfer it signs"
        );
    }

    /// Object identity is not step identity. A hostile sender signs a second
    /// transfer to B on the nonce of the one it sent, for another amount, and
    /// it reaches B before B polls. The two are different signed objects, so
    /// both are staged: nothing in staging decides between them. Only the one
    /// A's receipt signs can bind, and the canonical apply takes the nonce with
    /// it. B is credited that transfer once, and the rival, its nonce spent,
    /// holds no barrier and is collected.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_rival_on_the_same_nonce_is_staged_and_never_executes() {
        let (p, one) = sent().await;
        let TransferRecognition::Recognized(honest) =
            recognize_transfer(&one.transfer_bytes, &one.header_sender).expect("recognition")
        else {
            panic!("the sent transfer is recognized");
        };
        let Operation::Transfer { nonce, .. } = &honest.op else {
            panic!("the sent operation is a transfer");
        };
        let (_, b_key) = a_view_of_b(&p);
        let rival = signed_by_a(&p, p.b.device_id, b_key, 7, nonce.clone());
        staged(ingest_transfer_half(
            &rival,
            &one.header_sender,
            &one.route,
            "RIVAL",
        ));
        assert!(
            recipient_staging::counterparty_has_unconverged_inbound(&p.a.device_id)
                .expect("barrier"),
            "while its nonce is unspent, the rival is in flight"
        );

        clean(&p.b.sync().await);
        assert_eq!(
            p.b.era_balance(),
            10,
            "the transfer the receipt signs executes, once"
        );
        p.b.enter();
        nothing_staged();
        assert!(
            !recipient_staging::counterparty_has_unconverged_inbound(&p.a.device_id)
                .expect("barrier"),
            "the rival holds nothing once its nonce is spent"
        );
    }

    /// The inbox lists a transfer by what its sender signed. A hostile
    /// sender's second copy, its wrapper claiming a million NOTX, is listed
    /// with the signed terms; junk sealed to B is listed as unverified, with
    /// no sender and no terms.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn the_inbox_shows_what_the_sender_signed() {
        use crate::bridge::AppRouter;
        let (p, one) = sent().await;
        let second_id = crate::util::text_id::encode_base32_crockford(&[0x7Bu8; 16]);
        post_as_the_sender(
            &p,
            &one.route,
            &one.message_id,
            &second_id,
            lying_wrapper(&one.transfer_bytes, [0xC7; 32]),
        )
        .await;
        let junk_id = crate::util::text_id::encode_base32_crockford(&[0x7Cu8; 16]);
        post_as_the_sender(
            &p,
            &one.route,
            &one.message_id,
            &junk_id,
            b"not a request".to_vec(),
        )
        .await;

        p.b.enter();
        let params = dsm::types::proto::ArgPack {
            codec: dsm::types::proto::Codec::Proto as i32,
            body: dsm::types::proto::InboxRequest {
                limit: 50,
                chain_tip: String::new(),
            }
            .encode_to_vec(),
            schema_hash: None,
        }
        .encode_to_vec();
        let answered =
            p.b.router()
                .query(crate::bridge::AppQuery {
                    path: "inbox.pull".to_string(),
                    params,
                })
                .await;
        assert!(answered.success, "inbox.pull: {:?}", answered.error_message);
        let env = crate::handlers::response_helpers::decode_local_envelope(&answered.data)
            .expect("an envelope");
        let Some(dsm::types::proto::envelope::Payload::InboxResponse(listed)) = env.payload else {
            panic!("inbox.pull answers an InboxResponse");
        };
        fn listing<'a>(
            items: &'a [dsm::types::proto::InboxItem],
            id: &str,
        ) -> &'a dsm::types::proto::InboxItem {
            let Some(item) = items.iter().find(|i| i.id == id) else {
                panic!("{id} is listed: {items:?}");
            };
            item
        }
        let sender = crate::util::text_id::encode_base32_crockford(&p.a.device_id);
        for id in [&one.message_id, &second_id] {
            let item = listing(&listed.items, id);
            assert_eq!(
                item.preview,
                format!("From: {sender} Amount: 0.10 ERA"),
                "every copy of the transfer shows the signed terms"
            );
            assert_eq!(item.sender_id.as_deref(), Some(sender.as_str()));
        }
        let junk = listing(&listed.items, &junk_id);
        assert!(
            junk.preview.starts_with("Unverified: "),
            "junk is not listed as a transfer: {}",
            junk.preview
        );
        assert_eq!(junk.sender_id, None, "and names no sender");
        assert_eq!(listed.items.len(), 3, "{:?}", listed.items);
    }
}
