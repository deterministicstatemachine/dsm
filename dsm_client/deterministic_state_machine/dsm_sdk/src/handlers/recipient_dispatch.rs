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
    /// The terms that open `op`'s commitment: its token, nonce, mode and memo.
    pub opened: dsm::types::operations::TransferTerms,
    /// What the transfer moves and says: `op`'s amount, `opened`'s token and
    /// memo.
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
    /// never execute here. Nothing is staged, and the copy is passed over by
    /// its content: the id it was read under is not the object's, and is
    /// never consumed for it.
    Decided,
    /// Not checked: the contact it names already holds
    /// `MAX_UNBOUND_PER_SENDER` unbound staged objects of its kind here, and
    /// this copy is of none of them (SA-100). Nothing is staged or recorded;
    /// the copy stays on the spool, and is taken once that backlog binds or
    /// is decided.
    Held(String),
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

/// A transfer half parsed, and resolved to the contact its header names and
/// the key this device stores for it: nothing about it is verified yet.
struct CandidateTransfer {
    req: dsm::types::proto::OnlineTransferRequest,
    candidate: [u8; 32],
    ak: Vec<u8>,
}

/// The parse and candidate-identity stages of a transfer half. The inner
/// `Err` is why the half is not a transfer this device can take.
fn candidate_transfer(
    wire: &[u8],
    header_sender: &str,
) -> Result<Result<CandidateTransfer, String>, String> {
    // parse
    let req = match dsm::types::proto::OnlineTransferRequest::decode(wire) {
        Ok(r) => r,
        Err(e) => return Ok(Err(format!("the transfer does not decode: {e}"))),
    };
    if req.canonical_operation_bytes.is_empty() {
        return Ok(Err(
            "the transfer carries no canonical operation bytes".to_string()
        ));
    }
    // resolve candidate identity: a hint choosing which stored key to try
    let Some(candidate) = crate::util::text_id::decode_base32_crockford(header_sender) else {
        return Ok(Err(format!(
            "the header names {header_sender}, not a Base32 device id"
        )));
    };
    let candidate = match <[u8; 32]>::try_from(candidate.as_slice()) {
        Ok(id) => id,
        Err(e) => {
            return Ok(Err(format!(
                "the header names {header_sender}, not a device id: {e}"
            )))
        }
    };
    let Some(ak) = super::storage_routes::stored_sender_ak(header_sender)? else {
        return Ok(Err(format!(
            "no locally trusted sender AK for {header_sender}"
        )));
    };
    Ok(Ok(CandidateTransfer { req, candidate, ak }))
}

/// Recognize a transfer half: `wire` is the `OnlineTransferRequest` a spooled
/// envelope carried, `header_sender` the Base32 device id its header named.
pub fn recognize_transfer(wire: &[u8], header_sender: &str) -> Result<TransferRecognition, String> {
    match candidate_transfer(wire, header_sender)? {
        Ok(candidate) => verify_candidate_transfer(candidate, header_sender),
        Err(why) => Ok(TransferRecognition::NotRecognized(why)),
    }
}

/// Why a candidate transfer is held, if it is: the contact its header names
/// already holds `MAX_UNBOUND_PER_SENDER` unbound staged transfers here, and
/// the candidate is none of them (SA-100). Read before its signature is
/// checked, from rows only verified objects reach, so a copy that merely
/// names a contact cannot fill that contact's backlog.
fn transfer_backlog_full(
    candidate: &CandidateTransfer,
    header_sender: &str,
) -> Result<Option<String>, String> {
    let store = |e: anyhow::Error| format!("reading {header_sender}'s staged transfers: {e}");
    let held = recipient_staging::unbound_transfer_count(&candidate.candidate).map_err(store)?;
    if held < recipient_staging::MAX_UNBOUND_PER_SENDER
        || recipient_staging::transfer_is_staged(
            &candidate.candidate,
            &candidate.req.canonical_operation_bytes,
            &candidate.req.signature,
        )
        .map_err(store)?
    {
        return Ok(None);
    }
    Ok(Some(format!(
        "{header_sender} already holds {held} unbound transfers staged here"
    )))
}

/// The verify, derive-sender, check-recipient and object-key stages of a
/// candidate transfer.
fn verify_candidate_transfer(
    candidate: CandidateTransfer,
    header_sender: &str,
) -> Result<TransferRecognition, String> {
    use TransferRecognition::NotRecognized;
    let CandidateTransfer { req, candidate, ak } = candidate;
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
        amount,
        policy_commit,
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
    // open the terms: the nonce and memo are read from terms that open the
    // signed commitment, and a transfer without them is refused whole
    // (pre-audit item 4)
    let opened = match open_terms(&req.transfer_terms, &op) {
        Ok(terms) => terms,
        Err(why) => return Ok(NotRecognized(why)),
    };
    // derive the object key
    let staged = StagedTransfer {
        op_id: transfer_object_id(&op.to_bytes()),
        sender,
        // Spent in this relationship only, as the apply spends it.
        nonce_hash: crate::storage::client_db::relationship_nonce_hash(
            &dsm::core::bilateral_transaction_manager::compute_smt_key(&here, &sender),
            &opened.nonce,
        ),
        canonical_operation_bytes: req.canonical_operation_bytes,
        signature: req.signature,
        terms: req.transfer_terms,
    };
    let terms = super::recipient_accept::TransferTerms::of(amount, policy_commit, &opened);
    Ok(TransferRecognition::Recognized(Box::new(
        RecognizedTransfer {
            op,
            opened,
            terms,
            staged,
            hint: LocatorHint {
                economic_position: req.sender_economic_position,
                debit_mutation_index: req.sender_debit_mutation_index,
            },
        },
    )))
}

/// A receipt half parsed, addressed to this device and not yet accepted
/// here: its signatures are not checked yet.
struct CandidateReceipt {
    receipt: StitchedReceiptV2,
    commitment: [u8; 32],
    relationship_key: [u8; 32],
}

/// What recognition decides about a receipt half before any signature.
enum ReceiptDecidedUnsigned {
    /// A copy of a receipt this device already accepted.
    Accepted,
    /// Why the half is not a receipt this device can take.
    NotRecognized(String),
}

/// The parse and check-recipient stages of a receipt half, and whether it is
/// one this device already accepted. The inner `Err` is what recognition
/// decided without a signature.
fn candidate_receipt(
    full_receipt_bytes: &[u8],
) -> Result<Result<CandidateReceipt, ReceiptDecidedUnsigned>, String> {
    use ReceiptDecidedUnsigned::NotRecognized;
    // parse
    let receipt = match StitchedReceiptV2::from_canonical_protobuf(full_receipt_bytes) {
        Ok(r) => r,
        Err(e) => {
            return Ok(Err(NotRecognized(format!(
                "the receipt does not decode: {e}"
            ))))
        }
    };
    // check recipient before anything is verified against a relationship: the
    // chain is looked up for (devid_a, devid_b), which must include this device
    let here = this_device()?;
    if receipt.devid_b != here {
        return Ok(Err(NotRecognized(
            "the receipt names another device as its recipient".to_string(),
        )));
    }
    let commitment = match receipt.compute_commitment() {
        Ok(c) => c,
        Err(e) => {
            return Ok(Err(NotRecognized(format!(
                "the receipt commitment cannot be computed: {e}"
            ))))
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
        return Ok(Err(ReceiptDecidedUnsigned::Accepted));
    }
    Ok(Ok(CandidateReceipt {
        receipt,
        commitment,
        relationship_key,
    }))
}

/// Recognize a receipt half from the full A-side receipt wire bytes.
pub fn recognize_receipt(full_receipt_bytes: &[u8]) -> Result<ReceiptRecognition, String> {
    match candidate_receipt(full_receipt_bytes)? {
        Ok(candidate) => verify_candidate_receipt(candidate, full_receipt_bytes),
        Err(ReceiptDecidedUnsigned::Accepted) => Ok(ReceiptRecognition::Accepted),
        Err(ReceiptDecidedUnsigned::NotRecognized(why)) => {
            Ok(ReceiptRecognition::NotRecognized(why))
        }
    }
}

/// Why a candidate receipt is held, if it is: the contact it names as its
/// signer already holds `MAX_UNBOUND_PER_SENDER` unbound staged receipts
/// here, and the candidate is none of them (SA-100). As for transfers, read
/// before any signature is checked, from rows only verified receipts reach.
fn receipt_backlog_full(candidate: &CandidateReceipt) -> Result<Option<String>, String> {
    let signer = crate::util::text_id::encode_base32_crockford(&candidate.receipt.devid_a);
    let store = |e: anyhow::Error| format!("reading {signer}'s staged receipts: {e}");
    let held =
        recipient_staging::unbound_receipt_count(&candidate.receipt.devid_a).map_err(store)?;
    if held < recipient_staging::MAX_UNBOUND_PER_SENDER
        || recipient_staging::get_receipt(&candidate.commitment)
            .map_err(store)?
            .is_some()
    {
        return Ok(None);
    }
    Ok(Some(format!(
        "{signer} already holds {held} unbound receipts staged here"
    )))
}

/// The verify, derive-sender and object-key stages of a candidate receipt.
fn verify_candidate_receipt(
    candidate: CandidateReceipt,
    full_receipt_bytes: &[u8],
) -> Result<ReceiptRecognition, String> {
    use ReceiptRecognition::NotRecognized;
    let CandidateReceipt {
        receipt,
        commitment,
        relationship_key,
    } = candidate;
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
        evidence_digest: dsm::crypto::spool_address::ArtifactRole::EvidenceA
            .content_digest(full_receipt_bytes),
    };
    Ok(ReceiptRecognition::Verified(Box::new(RecognizedReceipt {
        receipt,
        staged,
    })))
}

/// The terms `terms_bytes` state, once they open `op`'s signed commitment.
/// Missing, malformed or mismatched terms are the reason the transfer is not
/// one this device can take.
pub(crate) fn open_terms(
    terms_bytes: &[u8],
    op: &Operation,
) -> Result<dsm::types::operations::TransferTerms, String> {
    if terms_bytes.is_empty() {
        return Err("the transfer carries no terms".to_string());
    }
    let terms = dsm::types::operations::TransferTerms::from_bytes(terms_bytes)
        .map_err(|e| format!("the transfer's terms do not decode: {e}"))?;
    terms.open(op).map_err(|e| e.to_string())?;
    Ok(terms)
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

/// The relationship tip a transfer's signed nonce derives from, when it is the
/// tip this device holds toward `sender` (§4.1: the nonce is taken over the tip
/// the sender made the transfer on). A transfer crossing this device's own send
/// was made on the tip this device still holds when it applies it: its own
/// finalization waits on its pin of the sender's head, which only that apply
/// moves. `None`: the nonce derives from another tip, and the relationship's
/// tips only move on, so the transfer can never execute here.
pub(crate) fn tip_the_nonce_derives_from(
    sender: &[u8; 32],
    op: &Operation,
    terms: &dsm::types::operations::TransferTerms,
) -> Result<Option<[u8; 32]>, String> {
    let Operation::Transfer {
        amount,
        to_device_id,
        ..
    } = op
    else {
        return Err("the verified transfer is not a transfer".to_string());
    };
    let recipient: [u8; 32] = to_device_id
        .as_slice()
        .try_into()
        .map_err(|e| format!("the transfer's recipient is not a device id: {e}"))?;
    let token = std::str::from_utf8(&terms.token_id)
        .map_err(|e| format!("the transfer's token is not text: {e}"))?;
    let current = crate::storage::client_db::get_contact_chain_tip(sender)
        .map_err(|e| format!("the sender's relationship tip is unreadable: {e}"))?
        .ok_or_else(|| "the sender is not a contact".to_string())?;
    let made_on_current = crate::handlers::app_router_impl::transfer_nonce(
        &current,
        amount.value(),
        token,
        &recipient,
    ) == terms.nonce;
    Ok(made_on_current.then_some(current))
}

/// Whether an INBOUND transfer from `counterparty_device_id` is staged here and
/// can still execute. The finality barrier treats this as PendingCatchup for
/// originating toward that peer: an inbound step is in flight on the
/// relationship and originating under it would cross it.
///
/// An object that can no longer execute holds nothing: a transfer whose nonce
/// is spent or derives from another tip than the one this device holds, and a
/// receipt whose step is taken. Otherwise a copy of the sender could hold this
/// device's sends toward it for good with a transfer that will never execute.
/// A transfer bound to a receipt whose step is taken needs no rule of its own:
/// taking that step moved this device's tip off the one the transfer's nonce
/// derives from.
pub fn counterparty_has_unconverged_inbound(counterparty_device_id: &[u8]) -> Result<bool, String> {
    let store = |e: anyhow::Error| format!("the inbound staging state: {e}");
    let receipt_waits =
        recipient_staging::has_undecided_staged_receipt_from(counterparty_device_id)
            .map_err(store)?;
    let mut executable_on = Vec::new();
    for staged in
        recipient_staging::unspent_staged_transfers_from(counterparty_device_id).map_err(store)?
    {
        let op = signed_operation_of(&staged)?;
        let terms = open_terms(&staged.terms, &op)?;
        executable_on.push(tip_the_nonce_derives_from(&staged.sender, &op, &terms)?);
    }
    Ok(receipt_waits || executable_on.iter().any(Option::is_some))
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
    let candidate = match candidate_transfer(wire, header_sender)? {
        Ok(candidate) => candidate,
        Err(why) => return Ok(IngestOutcome::only(Ingested::NotRecognized(why))),
    };
    if let Some(why) = transfer_backlog_full(&candidate, header_sender)? {
        return Ok(IngestOutcome::only(Ingested::Held(why)));
    }
    let recognized = match verify_candidate_transfer(candidate, header_sender)? {
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
    let candidate = match candidate_receipt(full_receipt_bytes)? {
        Ok(candidate) => candidate,
        Err(ReceiptDecidedUnsigned::Accepted) => return Ok(IngestOutcome::only(Ingested::Decided)),
        Err(ReceiptDecidedUnsigned::NotRecognized(why)) => {
            return Ok(IngestOutcome::only(Ingested::NotRecognized(why)))
        }
    };
    if let Some(why) = receipt_backlog_full(&candidate)? {
        return Ok(IngestOutcome::only(Ingested::Held(why)));
    }
    let recognized = match verify_candidate_receipt(candidate, full_receipt_bytes)? {
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
/// canonical apply has decided is passed over by its content, and anything
/// else is left where it is.
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
        sealed_as_the_sender(p, original_id, message_id, request);
        p.a.enter();
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

    /// A's own frozen transfer envelope, the one spooled under `original_id`,
    /// re-sealed to B under `message_id` with `request` as its body: the
    /// sealed bytes, which A keeps under `message_id`.
    fn sealed_as_the_sender(
        p: &Pair,
        original_id: &str,
        message_id: &str,
        request: Vec<u8>,
    ) -> Vec<u8> {
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
            .expect("seal for B")
    }

    /// Every received online transfer in B's history: (id, amount, token),
    /// the token named from the policy the row's signed operation commits to.
    fn received_history(p: &Pair) -> Vec<(String, u64, String)> {
        p.b.enter();
        let b = crate::util::text_id::encode_base32_crockford(&p.b.device_id);
        client_db::get_transaction_history(Some(&b), None, None)
            .expect("history")
            .into_iter()
            .filter(|t| t.tx_type == "online" && t.to_device == b)
            .map(|t| {
                let op = Operation::from_bytes(
                    t.metadata
                        .get(client_db::HISTORY_OPERATION_KEY)
                        .expect("the row keeps its operation"),
                )
                .expect("the operation decodes");
                let Operation::Transfer { policy_commit, .. } = op else {
                    panic!("a received transfer's row keeps a transfer");
                };
                let (token, ..) = crate::handlers::wallet_routes::token_of_commit(&policy_commit)
                    .expect("B names the token it was credited");
                (t.tx_id, t.amount, token)
            })
            .collect()
    }

    /// THE ARRIVAL-ORDER AND DUPLICATE-TRUTH PROOF, end to end. A hostile
    /// sender posts its own transfer a second time under another id, the
    /// wrapper now claiming a million NOTX from a third device. Both copies
    /// reach B's spool; B syncs. They are one signed object, so they stage as
    /// one and bind to one receipt: B is credited 10 ERA once, and its history
    /// reads the signed terms. The id the transfer's receipt derives is
    /// consumed; the other is not the transfer's, so it consumes nothing that
    /// an honest message under it would need, and the copy B read under it is
    /// read once more, decided, and passed over by its content.
    ///
    /// MUTATION CONTROL: consuming every id a pair's copies were read under,
    /// as completion did, turns this red.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_second_copy_with_a_lying_wrapper_is_the_same_transfer_credited_once() {
        let (p, one) = sent().await;
        let second_id = crate::util::text_id::encode_base32_crockford(&[0x7Au8; 16]);
        let wrapped = lying_wrapper(&one.transfer_bytes, [0xC7; 32]);
        post_as_the_sender(&p, &one.route, &one.message_id, &second_id, wrapped.clone()).await;
        let second_copy = copy_key_at_b(
            &p,
            &sealed_as_the_sender(&p, &one.message_id, &second_id, wrapped),
        );

        clean(&p.b.sync().await);
        assert_eq!(p.b.era_balance(), 10, "credited once, in the signed amount");
        assert_eq!(
            received_history(&p),
            vec![(one.message_id.clone(), 10, "ERA".to_string())],
            "one row, named by the transfer, with the signed terms"
        );
        p.b.enter();
        assert!(
            client_db::b0x_consumed::is_consumed(&one.route, &one.message_id).expect("consumed"),
            "the id the transfer's receipt derives is consumed"
        );
        assert!(
            !client_db::b0x_consumed::is_consumed(&one.route, &second_id).expect("consumed"),
            "the id the copy was re-posted under is not the transfer's"
        );
        nothing_staged();

        clean(&p.b.sync().await);
        p.b.enter();
        assert!(
            client_db::b0x_consumed::is_passed_over(&one.route, &second_copy).expect("passed over"),
            "read once more, decided, and passed over by its content"
        );
        assert_eq!(p.b.era_balance(), 10);
    }

    /// Storage §8, routing rule 1: a relationship's inbox address hashes its
    /// current chain tip and changes every step, so an item on a previous-tip
    /// route steps from a tip this device has already advanced past, and is
    /// never taken in. A pays B 10 and B applies it: the route for the tip A
    /// paid from is now B's previous-tip route for A. A then forks its own
    /// chain from that tip, a transfer of 7 to B signed as its send signs
    /// one, which B has never decided, and posts it on that route through its
    /// own spool client. B syncs and reads the route: the copy is left where
    /// it is. Nothing is staged, its id is not consumed, its content is not
    /// passed over, and B holds the 10 it was paid.
    ///
    /// MUTATION CONTROL: `pull_and_process_inbox` reading a previous-tip
    /// route as a current one turns this red: the fork is staged.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn an_item_on_a_previous_tip_route_is_never_taken_in() {
        use crate::handlers::app_router_impl::contact_relationship_tip;
        use dsm::types::operations::{TransactionMode, TransferTerms};

        let p = Pair::boot(100, 0).await;

        // A's tip with B before it pays, and the position its pay advances.
        p.a.enter();
        let b_contact = client_db::get_contact_by_device_id(&p.b.device_id)
            .expect("A's contacts")
            .expect("A holds B as a contact");
        let paid_from = contact_relationship_tip(&b_contact).expect("A's relationship tip with B");
        let fork_position =
            crate::economic_fixtures::admitted_position().expect("A is activated") + 1;

        let sent = p.a.send(&p.b, 10).await;
        assert!(sent.success, "{:?}", sent.error_message);
        let one = the_one_transfer(&p.b, &p.fleet).await;
        clean(&p.b.sync().await);
        assert_eq!(p.b.era_balance(), 10, "B applied the honest payment");

        p.b.enter();
        let a_contact = client_db::get_contact_by_device_id(&p.a.device_id)
            .expect("B's contacts")
            .expect("B holds A as a contact");
        assert_ne!(
            contact_relationship_tip(&a_contact).expect("B's relationship tip with A"),
            paid_from,
            "B has advanced past the tip A paid from"
        );
        assert_eq!(
            a_contact.previous_chain_tip.as_deref(),
            Some(paid_from.as_slice()),
            "the tip A paid from is B's previous tip with A"
        );
        let previous_route =
            dsm::crypto::spool_address::inbox_address(&p.b.genesis, &p.b.device_id, &paid_from);
        assert_eq!(
            previous_route, one.route,
            "the honest payment arrived on that route"
        );

        // The fork: a transfer A's chain never made, from the tip it paid from.
        p.a.enter();
        let a_key = crate::sdk::signing_authority::current_public_key().expect("A's key");
        let a_secret =
            crate::sdk::signing_authority::current_secret_key().expect("A's signing key");
        let terms = TransferTerms::new(
            b"ERA".to_vec(),
            transfer_nonce(&paid_from, 7, "ERA", &p.b.device_id),
            TransactionMode::Unilateral,
            String::new(),
        );
        let canonical = Operation::Transfer {
            to_device_id: p.b.device_id.to_vec(),
            amount: dsm::types::token_types::Balance::amount(7),
            policy_commit: dsm::core::token::token_state_manager::era_policy_commit(),
            token_policy: dsm::core::token::era_policy::era_policy_bytes().to_vec(),
            terms_commitment: terms.commitment(),
            signature: Vec::new(),
            authority_policy: None,
        }
        .to_bytes();
        let signature = dsm::crypto::sphincs::sphincs_sign(&a_secret, &canonical).expect("A signs");
        Operation::decode_and_bind_signed(&canonical, &signature, &a_key)
            .expect("A's signature binds");
        let fork = dsm::types::proto::OnlineTransferRequest {
            signature,
            canonical_operation_bytes: canonical,
            sender_economic_position: fork_position,
            sender_debit_mutation_index: 0,
            transfer_terms: terms.to_bytes(),
        }
        .encode_to_vec();

        p.b.enter();
        assert_eq!(
            classify_stale_transfer_copy(&fork, &one.header_sender).expect("classified"),
            StaleCopy::Undecided,
            "B recognizes the fork and has never decided it"
        );
        nothing_staged();

        let fork_id = crate::util::text_id::encode_base32_crockford(&[0x5Eu8; 16]);
        post_as_the_sender(&p, &previous_route, &one.message_id, &fork_id, fork.clone()).await;
        let fork_copy = copy_key_at_b(
            &p,
            &sealed_as_the_sender(&p, &one.message_id, &fork_id, fork),
        );

        clean(&p.b.sync().await);
        assert_eq!(p.b.era_balance(), 10, "nothing of the fork reached B");
        p.b.enter();
        nothing_staged();
        assert!(
            !client_db::b0x_consumed::is_consumed(&previous_route, &fork_id).expect("consumed"),
            "the fork's id is not consumed"
        );
        assert!(
            !client_db::b0x_consumed::is_passed_over(&previous_route, &fork_copy)
                .expect("passed over"),
            "the fork is left where it is, not passed over"
        );
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
            counterparty_has_unconverged_inbound(&p.a.device_id).expect("barrier"),
            "the transfer in flight holds the barrier toward its real sender"
        );
        assert!(
            !counterparty_has_unconverged_inbound(&named).expect("barrier"),
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

    /// Pre-audit item 4 (owner ruling 2026-10-02): a transfer's terms ride
    /// inside the sealed request, beside an operation that carries only their
    /// commitment, and B takes the transfer only when they open it. A transfer
    /// A signed whose request carries no terms, or terms naming a memo A never
    /// signed, is not recognized, and nothing is staged. With its own terms it
    /// is, and B reads the memo and nonce from them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_transfer_without_terms_that_open_it_is_not_recognized() {
        let (p, one) = sent().await;
        let tip = a_view_of_b(&p);
        let terms = era_terms(
            transfer_nonce(&tip, 5, "ERA", &p.b.device_id),
            "the memo A signed",
        );
        let mut tampered = terms.clone();
        tampered.memo = "a memo A never signed".to_string();
        for (carried, why) in [
            (Vec::new(), "carries no terms"),
            (tampered.to_bytes(), "do not open"),
            (vec![0x01, 0x02], "do not decode"),
        ] {
            let request = signed_by_a_carrying(&p, p.b.device_id, 5, &terms, carried);
            let out = ingested(ingest_transfer_half(
                &request,
                &one.header_sender,
                &one.route,
                "TAMPERED",
            ));
            assert!(
                matches!(&out, Ingested::NotRecognized(w) if w.contains(why)),
                "{why}: {out:?}"
            );
            nothing_staged();
        }
        let honest = signed_by_a_carrying(&p, p.b.device_id, 5, &terms, terms.to_bytes());
        let TransferRecognition::Recognized(recognized) =
            recognize_transfer(&honest, &one.header_sender).expect("recognition")
        else {
            panic!("the transfer with its own terms is recognized");
        };
        assert_eq!(recognized.opened, terms);
        assert_eq!(recognized.terms.memo, "the memo A signed");
        assert_eq!(
            recognized.terms.policy_commit,
            dsm::core::token::builtin_policy_commit_for_token("ERA").expect("ERA's policy")
        );
    }

    /// A transfer A signed to another device, sent to B: SIG A verifies, and
    /// it is still not B's. The other device is A itself, and the nonce the
    /// one A's send would derive. Nothing is staged.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_transfer_addressed_to_another_device_is_not_recognized() {
        let (p, one) = sent().await;
        let tip = a_view_of_b(&p);
        let elsewhere = p.a.device_id;
        let request = signed_by_a(&p, elsewhere, 5, transfer_nonce(&tip, 5, "ERA", &elsewhere));
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

    /// MR-DSM-0050: a receipt is evidence of its own relationship's step and
    /// never advances another. A pays B; C, which holds A as a contact too, is
    /// handed both halves of that step on C's own route for A. Neither is C's:
    /// the receipt names B as its recipient and the transfer pays B, so
    /// nothing is staged at C and C's relationship with A has not moved.
    ///
    /// MUTATION CONTROL: dropping the recipient check from `candidate_receipt`
    /// turns this red: C stages A's receipt for B.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_step_of_one_relationship_never_advances_another() {
        let (p, one) = sent().await;
        let mut c = crate::test_support::two_device::TestDevice::create("C", 0x0C);
        c.boot(&p.fleet).await;
        c.add_contact(&p.a).await;
        p.a.add_contact(&c).await;
        c.enter();
        let tip = |device: &crate::test_support::two_device::TestDevice| {
            device.enter();
            let a = client_db::get_contact_by_device_id(&p.a.device_id)
                .expect("C's contacts")
                .expect("C holds A as a contact");
            crate::handlers::app_router_impl::contact_relationship_tip(&a)
                .expect("C's relationship tip with A")
        };
        let before = tip(&c);
        let route = dsm::crypto::spool_address::inbox_address(&c.genesis, &c.device_id, &before);

        c.enter();
        let receipt = ingested(ingest_evidence_half(
            &one.evidence_bytes,
            &route,
            &one.evidence_message_id,
        ));
        assert!(
            matches!(&receipt, Ingested::NotRecognized(why) if why.contains("another device")),
            "{receipt:?}"
        );
        let transfer = ingested(ingest_transfer_half(
            &one.transfer_bytes,
            &one.header_sender,
            &route,
            &one.message_id,
        ));
        assert!(
            matches!(&transfer, Ingested::NotRecognized(why) if why.contains("another device")),
            "{transfer:?}"
        );
        c.enter();
        nothing_staged();
        assert_eq!(tip(&c), before, "C's relationship with A has not moved");
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
            )
            .expect("the step's C_pre");
            let answer = a.answer(&b, &r.parent_tip, &c_pre, &target);
            r.set_ek_pk_a(answer.ek_pk);
            r.set_ek_cert_a(answer.ek_cert);
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
            leaf: ReceiptLeaf::OfflineAccount(Box::new(
                dsm::types::offline_account::SpendWitness {
                    pre_account_root: honest.parent_root,
                    pre_allocation: 1,
                    pre_counter: 0,
                    pre_frontier: honest.parent_tip,
                    next_frontier: honest.child_tip,
                    account_paths: Vec::new(),
                },
            )),
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
    /// spent and its step is taken, so a later copy of either half is passed
    /// over by its content and never becomes staging state again.
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

    /// A's relationship tip with B: what A's own send signs over.
    fn a_view_of_b(p: &Pair) -> [u8; 32] {
        p.a.enter();
        let b = client_db::get_contact_by_device_id(&p.b.device_id)
            .expect("A's contacts")
            .expect("A holds B as a contact");
        crate::handlers::app_router_impl::contact_relationship_tip(&b)
            .expect("A's relationship tip with B")
    }

    /// Terms of ERA on `nonce`, with `memo`, as A's send builds them.
    fn era_terms(nonce: Vec<u8>, memo: &str) -> dsm::types::operations::TransferTerms {
        dsm::types::operations::TransferTerms::new(
            b"ERA".to_vec(),
            nonce,
            dsm::types::operations::TransactionMode::Unilateral,
            memo.to_string(),
        )
    }

    /// A transfer A signs, built as A's send builds one, on the nonce A
    /// chooses; the locator hints are A's to write. As B's poll reads it.
    fn signed_by_a(p: &Pair, to_device_id: [u8; 32], amount: u64, nonce: Vec<u8>) -> Vec<u8> {
        let terms = era_terms(nonce, "");
        signed_by_a_carrying(p, to_device_id, amount, &terms, terms.to_bytes())
    }

    /// A transfer A signs committing to `terms`, whose request carries
    /// `carried` as its terms — honest when they are `terms`' own bytes.
    fn signed_by_a_carrying(
        p: &Pair,
        to_device_id: [u8; 32],
        amount: u64,
        terms: &dsm::types::operations::TransferTerms,
        carried: Vec<u8>,
    ) -> Vec<u8> {
        p.a.enter();
        let op = Operation::Transfer {
            to_device_id: to_device_id.to_vec(),
            amount: dsm::types::token_types::Balance::amount(amount),
            policy_commit: dsm::core::token::builtin_policy_commit_for_token("ERA").expect("ERA"),
            token_policy: dsm::core::token::era_policy::era_policy_bytes().to_vec(),
            terms_commitment: terms.commitment(),
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
            transfer_terms: carried,
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
        let tip = a_view_of_b(&p);
        let other = signed_by_a(
            &p,
            p.b.device_id,
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
    /// it. B is credited that transfer once. The rival's nonce derives from no
    /// tip B holds for its own amount, so it can never execute: it holds no
    /// barrier even while its nonce is unspent, and it is collected.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_rival_on_the_same_nonce_is_staged_and_never_executes() {
        let (p, one) = sent().await;
        let TransferRecognition::Recognized(honest) =
            recognize_transfer(&one.transfer_bytes, &one.header_sender).expect("recognition")
        else {
            panic!("the sent transfer is recognized");
        };
        let rival = signed_by_a(&p, p.b.device_id, 7, honest.opened.nonce.clone());
        staged(ingest_transfer_half(
            &rival,
            &one.header_sender,
            &one.route,
            "RIVAL",
        ));
        assert!(
            !counterparty_has_unconverged_inbound(&p.a.device_id).expect("barrier"),
            "the rival can never execute, so it holds nothing while its nonce is unspent"
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
            !counterparty_has_unconverged_inbound(&p.a.device_id).expect("barrier"),
            "the rival holds nothing once its nonce is spent"
        );
    }

    /// SA-100: a hostile contact signs transfers and receipts to B without
    /// end, each verifying and none ever executable. B stages at most
    /// `MAX_UNBOUND_PER_SENDER` of each kind from it; every further new copy
    /// is held, recording nothing, while a copy of an object already staged
    /// is still taken, so the backlog that is staged can still bind.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_contacts_unbound_backlog_is_bounded_per_kind() {
        use crate::test_support::receipts::Party;
        use dsm::types::receipt_types::compute_receipt_challenge_response_target;
        let cap = recipient_staging::MAX_UNBOUND_PER_SENDER;
        let (p, one) = sent().await;
        let tip = a_view_of_b(&p);
        let extra = 3;
        let mut transfers = Vec::new();
        for amount in 1..=(cap + extra) as u64 {
            transfers.push(signed_by_a(
                &p,
                p.b.device_id,
                amount,
                transfer_nonce(&tip, amount, "ERA", &p.b.device_id),
            ));
        }
        for (i, request) in transfers.iter().enumerate() {
            let out = ingested(ingest_transfer_half(
                request,
                &one.header_sender,
                &one.route,
                &format!("FLOOD-{i}"),
            ));
            if i < cap {
                assert_eq!(out, Ingested::Staged, "transfer {i} is within the bound");
            } else {
                assert!(
                    matches!(&out, Ingested::Held(why) if why.contains("unbound transfers")),
                    "transfer {i} is past the bound: {out:?}"
                );
            }
        }
        assert_eq!(rows("recipient_staged_transfer"), cap as i64);
        assert_eq!(rows("recipient_transfer_observation"), cap as i64);
        assert_eq!(
            ingested(ingest_transfer_half(
                &transfers[0],
                &one.header_sender,
                &one.route,
                "FLOOD-AGAIN",
            )),
            Ingested::Staged,
            "a copy of a staged transfer is still taken"
        );

        let op = match recognize_transfer(&one.transfer_bytes, &one.header_sender)
            .expect("recognition")
        {
            TransferRecognition::Recognized(r) => r.op,
            TransferRecognition::NotRecognized(why) => panic!("the honest transfer: {why}"),
        };
        let honest =
            StitchedReceiptV2::from_canonical_protobuf(&one.evidence_bytes).expect("the receipt");
        let (a, b) = (Party::from_seed(0x0A), Party::from_seed(0x0B));
        let signed_by_a = |mut r: StitchedReceiptV2| -> Vec<u8> {
            let commitment = r.compute_commitment().expect("the commitment");
            let target = compute_receipt_challenge_response_target(&commitment, &commitment);
            let c_pre = dsm::core::bilateral_transaction_manager::compute_precommit(
                &r.parent_tip,
                &op.with_cleared_signature().to_bytes(),
                &r.transition_entropy,
            )
            .expect("the step's C_pre");
            let answer = a.answer(&b, &r.parent_tip, &c_pre, &target);
            r.set_ek_pk_a(answer.ek_pk);
            r.set_ek_cert_a(answer.ek_cert);
            r.add_sig_a(answer.sig);
            r.to_full_protobuf().expect("re-encode")
        };
        let mut receipts = Vec::new();
        for i in 0..cap + extra {
            let mut receipt = honest.clone();
            receipt.child_root[0] ^= u8::try_from(i + 1).expect("a small index");
            receipts.push(signed_by_a(receipt));
        }
        for (i, bytes) in receipts.iter().enumerate() {
            let out = ingested(ingest_evidence_half(
                bytes,
                &one.evidence_route,
                &format!("FLOOD-RECEIPT-{i}"),
            ));
            if i < cap {
                assert_eq!(out, Ingested::Staged, "receipt {i} is within the bound");
            } else {
                assert!(
                    matches!(&out, Ingested::Held(why) if why.contains("unbound receipts")),
                    "receipt {i} is past the bound"
                );
            }
        }
        assert_eq!(rows("recipient_staged_receipt"), cap as i64);
        assert_eq!(rows("recipient_receipt_observation"), cap as i64);
        assert_eq!(
            ingested(ingest_evidence_half(
                &receipts[0],
                &one.evidence_route,
                "FLOOD-RECEIPT-AGAIN",
            )),
            Ingested::Staged,
            "a copy of a staged receipt is still taken"
        );
        assert_eq!(rows("recipient_pair"), 0, "none of them binds");
    }

    /// SA-101: the first member in set order withholds the honest transfer
    /// and serves, ahead of it, as many fresh copies sealed to B as the poll
    /// takes from a route — anyone can seal to B, so each is new and none was
    /// passed over before. The other members hold the honest copy. One poll
    /// still reaches it: no member's answer fills the route's budget, and B
    /// is credited.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn the_first_member_cannot_fill_a_routes_budget() {
        let (p, one) = sent().await;
        p.b.enter();
        let first = crate::sdk::storage_set::pinned_endpoints().expect("B's pinned set")[0].clone();
        let member = p
            .nodes
            .nodes
            .iter()
            .find(|n| n.endpoint == first)
            .expect("the first member in set order is a node of the fleet");
        let withheld = member
            .spool()
            .await
            .into_iter()
            .filter(|s| s.message_id.as_deref() == Some(one.message_id.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(withheld.len(), 1, "the first member holds the honest copy");
        let client = member.pool().get().await.expect("the member's database");
        client
            .execute(
                "DELETE FROM inbox_spool WHERE envelope = $1",
                &[&withheld[0].envelope],
            )
            .await
            .expect("the first member withholds the honest copy");
        let budget = crate::sdk::inbox_poller::poll_sync_request().limit;
        for i in 0..budget {
            let mut raw = [0x60u8; 16];
            raw[15] = u8::try_from(i).expect("the budget fits a byte");
            let id = crate::util::text_id::encode_base32_crockford(&raw);
            let junk = sealed_as_the_sender(
                &p,
                &one.message_id,
                &id,
                format!("fresh junk {i}").into_bytes(),
            );
            dsm_storage_node::db::spool_insert(member.pool(), &one.route, &junk)
                .await
                .expect("the first member spools its own junk");
        }
        assert!(
            p.holders_of(&one.message_id).await >= 1,
            "the other members hold the honest copy"
        );

        let synced = p.b.sync().await;
        assert!(synced.success, "{:?}", synced.errors);
        assert_eq!(
            p.b.era_balance(),
            10,
            "one poll reaches the honest copy past the first member's junk"
        );
    }

    /// The inbox lists a transfer by what its sender signed. A hostile
    /// sender's second copy, its wrapper claiming a million NOTX, is listed
    /// with the signed terms; a transfer A signed over ERA whose terms call
    /// the token "NOSUCH" is listed as ERA, the policy its operation commits
    /// to; junk sealed to B is listed as unverified, with no sender and no
    /// terms.
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
        let tip = a_view_of_b(&p);
        let mislabelled_terms = dsm::types::operations::TransferTerms::new(
            b"NOSUCH".to_vec(),
            transfer_nonce(&tip, 5, "NOSUCH", &p.b.device_id),
            dsm::types::operations::TransactionMode::Unilateral,
            "a label A chose".to_string(),
        );
        let mislabelled_id = crate::util::text_id::encode_base32_crockford(&[0x7Du8; 16]);
        let mislabelled = signed_by_a_carrying(
            &p,
            p.b.device_id,
            5,
            &mislabelled_terms,
            mislabelled_terms.to_bytes(),
        );
        post_as_the_sender(
            &p,
            &one.route,
            &one.message_id,
            &mislabelled_id,
            mislabelled,
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
        assert_eq!(
            listing(&listed.items, &mislabelled_id).preview,
            format!("From: {sender} Amount: 0.05 ERA"),
            "the token is the one the operation signs, not the terms' label"
        );
        let junk = listing(&listed.items, &junk_id);
        assert!(
            junk.preview.starts_with("Unverified: "),
            "junk is not listed as a transfer: {}",
            junk.preview
        );
        assert_eq!(junk.sender_id, None, "and names no sender");
        assert_eq!(listed.items.len(), 4, "{:?}", listed.items);
    }
    // ── Copies that change nothing: SA-66, MR-DSM-0332 (§6.104) ──────────────

    /// A pays B 10; B syncs and takes it; A syncs and finalizes on B's delta;
    /// then A pays B 7, which B has not read. Each payment's halves as B's
    /// poll read them.
    async fn paid_twice() -> (Pair, OneTransfer, OneTransfer) {
        let p = Pair::boot(100, 0).await;
        let sent = p.a.send(&p.b, 10).await;
        assert!(sent.success, "{:?}", sent.error_message);
        let first = the_one_transfer(&p.b, &p.fleet).await;
        clean(&p.b.sync().await);
        assert_eq!(p.b.era_balance(), 10);
        clean(&p.a.sync().await);
        let sent = p.a.send(&p.b, 7).await;
        assert!(sent.success, "{:?}", sent.error_message);
        let second = the_one_transfer(&p.b, &p.fleet).await;
        (p, first, second)
    }

    /// The set's members split in two: the few a delivery quorum leaves over,
    /// and the quorum.
    fn split_members() -> (Vec<String>, Vec<String>) {
        let members = crate::economic_fixtures::canonical_member_ids();
        let quorum = crate::economic_fixtures::delivery_quorum();
        let (few, rest) = members.split_at(members.len() - quorum);
        (few.to_vec(), rest.to_vec())
    }

    /// A's envelope kept under `original_id`, as B opens it, re-addressed to
    /// `message_id` and sealed to B afresh: the copy A can make of its own
    /// earlier message under a later message's id. A keeps one seal per id
    /// (`b0x_sdk::seal_for`), so this seals with the construction every
    /// sender has, Kyber to B's key and the spool seal under the new id.
    fn resealed_as_the_sender(p: &Pair, original_id: &str, message_id: &str) -> Vec<u8> {
        use dsm::types::proto as pb;
        use prost::Message as _;
        p.a.enter();
        let sealed = crate::sdk::b0x_sdk::kept_seal(original_id).expect("A kept the sealed send");
        p.b.enter();
        let outer = dsm::envelope::from_canonical_bytes(&sealed).expect("the sealed envelope");
        let mut inner = crate::sdk::b0x_sdk::open_sealed(
            &crate::sdk::b0x_sdk::local_kyber_secret().expect("B's key"),
            &outer,
        )
        .expect("B opens it");
        let decode = |b32: &str| -> [u8; 16] {
            let raw = crate::util::text_id::decode_base32_crockford(b32).expect("a Base32 id");
            <[u8; 16]>::try_from(raw.as_slice()).expect("a 16-byte id")
        };
        let (original, id) = (decode(original_id), decode(message_id));
        inner.message_id = id.to_vec();
        if let Some(pb::envelope::Payload::UniversalTx(tx)) = &mut inner.payload {
            for op in &mut tx.ops {
                if op.op_id.as_ref().map(|h| h.v.as_slice()) == Some(original.as_slice()) {
                    op.op_id = Some(pb::Hash32 { v: id.to_vec() });
                }
            }
        }
        let (shared_secret, kem_ciphertext) =
            dsm::crypto::kyber::kyber_encapsulate(&p.b.kyber_pk).expect("encapsulate to B");
        let ciphertext = dsm::crypto::spool_seal::seal(&shared_secret, &id, &inner.encode_to_vec())
            .expect("seal");
        pb::Envelope {
            version: 3,
            headers: None,
            message_id: id.to_vec(),
            payload: Some(pb::envelope::Payload::Sealed(pb::SealedEnvelopeV1 {
                kem_ciphertext,
                ciphertext,
            })),
        }
        .encode_to_vec()
    }

    /// The content key B passes a sealed copy over by: its envelope as B
    /// opens it.
    fn copy_key_at_b(p: &Pair, sealed: &[u8]) -> String {
        p.b.enter();
        let outer = dsm::envelope::from_canonical_bytes(sealed).expect("an envelope");
        let inner = crate::sdk::b0x_sdk::open_sealed(
            &crate::sdk::b0x_sdk::local_kyber_secret().expect("B's key"),
            &outer,
        )
        .expect("B opens it");
        dsm::crypto::spool_address::envelope_merge_key(&inner)
    }

    /// On each of `members`, the honest copy under `message_id` at `route`
    /// withheld and `sealed` spooled in its place: a member serving one copy
    /// under an id in place of another (the node keeps the first row per id).
    async fn served_instead(
        p: &Pair,
        members: &[String],
        route: &str,
        message_id: &str,
        sealed: &[u8],
    ) {
        for member_id in members {
            let member = p
                .nodes
                .nodes
                .iter()
                .find(|n| &n.member_id == member_id)
                .expect("a member of the fleet");
            let honest: Vec<_> = member
                .spool()
                .await
                .into_iter()
                .filter(|s| s.address == route && s.message_id.as_deref() == Some(message_id))
                .collect();
            assert_eq!(honest.len(), 1, "{member_id} holds the honest copy");
            let client = member.pool().get().await.expect("the member's database");
            client
                .execute(
                    "DELETE FROM inbox_spool WHERE envelope = $1",
                    &[&honest[0].envelope],
                )
                .await
                .expect("the member withholds the honest copy");
            dsm_storage_node::db::spool_insert(member.pool(), route, sealed)
                .await
                .expect("the member spools the other copy");
        }
    }

    /// SA-66, MR-DSM-0332. A receipt this device already accepted is decided
    /// before any signature is checked, and the id its copy travels under is
    /// whoever sealed it's to choose. A pays B twice. Two members withhold the
    /// second payment's receipt and serve in its place the FIRST receipt's
    /// bytes, sealed to B under the second receipt's id. B syncs while the
    /// other members' spools fail, so under that id the replay is all it
    /// reads. Once it reads every member, the second receipt is read and the
    /// payment is credited exactly once; the replay is passed over by its
    /// content and consumed nothing.
    ///
    /// MUTATION CONTROL: consuming the id of a decided copy, as the poll did,
    /// turns this red: the second receipt is never read.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_receipt_replayed_under_a_later_receipts_id_hides_nothing() {
        let (p, first, second) = paid_twice().await;
        let replay =
            resealed_as_the_sender(&p, &first.evidence_message_id, &second.evidence_message_id);
        let (few, rest) = split_members();
        served_instead(
            &p,
            &few,
            &second.evidence_route,
            &second.evidence_message_id,
            &replay,
        )
        .await;
        p.nodes.fail_spools(&rest).await;
        p.b.sync().await;
        p.nodes.restore_spools(&rest).await;
        assert_eq!(p.b.era_balance(), 10, "the replay credits nothing");

        clean(&p.b.sync().await);
        assert_eq!(p.b.era_balance(), 17, "the second payment, credited once");
        let history = received_history(&p);
        assert_eq!(history.len(), 2, "{history:?}");
        assert!(history.contains(&(second.message_id.clone(), 7, "ERA".to_string())));
        let replayed = copy_key_at_b(&p, &replay);
        p.b.enter();
        assert!(
            client_db::b0x_consumed::is_passed_over(&second.evidence_route, &replayed)
                .expect("passed over"),
            "the replay is passed over by its content"
        );
        assert!(
            client_db::b0x_consumed::is_consumed(
                &second.evidence_route,
                &second.evidence_message_id
            )
            .expect("consumed"),
            "the second receipt's id, consumed by its own completion"
        );
        nothing_staged();
    }

    /// MR-DSM-0332. No class's message id is recomputed from its content where
    /// a copy is read, so a decided copy consumes no id even when it verifies.
    /// A pays B twice. Two members withhold the second payment's transfer and
    /// serve in its place A's FIRST transfer, signed and verified, sealed to
    /// B under the second transfer's id. B syncs while the other members'
    /// spools fail: the first transfer verifies, its nonce is spent, and it is
    /// decided. Once B reads every member, the second transfer is read and
    /// credited exactly once.
    ///
    /// MUTATION CONTROL: consuming the id of a decided copy, as the poll did,
    /// turns this red: the second transfer is never read.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_transfer_replayed_under_a_later_transfers_id_hides_nothing() {
        let (p, first, second) = paid_twice().await;
        let replay = resealed_as_the_sender(&p, &first.message_id, &second.message_id);
        let (few, rest) = split_members();
        served_instead(&p, &few, &second.route, &second.message_id, &replay).await;
        p.nodes.fail_spools(&rest).await;
        p.b.sync().await;
        p.nodes.restore_spools(&rest).await;
        assert_eq!(p.b.era_balance(), 10, "the replay credits nothing");

        clean(&p.b.sync().await);
        assert_eq!(p.b.era_balance(), 17, "the second payment, credited once");
        let history = received_history(&p);
        assert_eq!(history.len(), 2, "{history:?}");
        assert!(history.contains(&(second.message_id.clone(), 7, "ERA".to_string())));
        let replayed = copy_key_at_b(&p, &replay);
        p.b.enter();
        assert!(
            client_db::b0x_consumed::is_passed_over(&second.route, &replayed).expect("passed over"),
            "the replay is passed over by its content"
        );
        nothing_staged();
    }

    /// An envelope of the class `method` names, from `from`, its object
    /// replaced by `body`, sealed to `to` under a fresh id and posted through
    /// `from`'s own spool client on `to`'s current route for it. The route,
    /// the id and the copy's content key.
    async fn posted_under_a_class(
        p: &Pair,
        from: &crate::test_support::two_device::TestDevice,
        to: &crate::test_support::two_device::TestDevice,
        method: &str,
        body: Vec<u8>,
        fill: u8,
    ) -> (String, String, String) {
        use dsm::types::proto as pb;
        use prost::Message as _;
        to.enter();
        let route = crate::handlers::app_router_impl::collect_tagged_inbox_addresses(
            to.genesis,
            to.device_id,
            &client_db::get_all_contacts().expect("contacts"),
        )
        .expect("routes")
        .into_iter()
        .find(|t| {
            matches!(
                t.freshness,
                crate::handlers::app_router_impl::RouteFreshness::Current
            )
        })
        .expect("a current route")
        .address;
        let id = crate::util::text_id::encode_base32_crockford(&[fill; 16]);
        let mut digest = dsm::crypto::blake3::dsm_domain_hasher(
            dsm::crypto::domain::TaggedHashDomain::try_new(b"DSM/test/class-junk")
                .expect("a domain"),
        );
        digest.update(&body);
        // The class's envelope as its production builder lays it out, with
        // the junk in its object's place; another class differs only in the
        // method its invoke names.
        let built = crate::sdk::b0x_sdk::B0xSDK::build_relationship_finalized_envelope(
            &from.device_id,
            &from.genesis,
            &body,
            digest.finalize().as_bytes(),
            &id,
        )
        .expect("a class envelope");
        let mut inner =
            pb::Envelope::decode(built.bytes.as_slice()).expect("the built envelope decodes");
        if let Some(pb::envelope::Payload::UniversalTx(tx)) = &mut inner.payload {
            for op in &mut tx.ops {
                if let Some(pb::universal_op::Kind::Invoke(invoke)) = &mut op.kind {
                    invoke.method = method.to_string();
                }
            }
        }
        let copy_key = dsm::crypto::spool_address::envelope_merge_key(&inner);
        from.enter();
        crate::sdk::b0x_sdk::seal_for(&to.device_id, &id, &inner.encode_to_vec()).expect("seal");
        let mut spool = crate::sdk::b0x_sdk::B0xSDK::new(
            crate::util::text_id::encode_base32_crockford(&from.device_id),
            from.router().core_sdk.clone(),
            p.fleet.endpoints(),
        )
        .expect("a spool client");
        spool
            .submit_stored_envelope_with_retry(
                &route,
                &id,
                &crate::sdk::b0x_sdk::B0xRetryConfig::default(),
            )
            .await
            .expect("the copy reaches the members");
        (route, id, copy_key)
    }

    /// Pre-audit item 11, MR-DSM-0332: bytes under the finality-certificate
    /// class that are not a certificate never will be one. A posts to B,
    /// through its own spool client, an envelope of that class carrying junk.
    /// B's first sync reads it and passes it over by its content, consuming
    /// no id and reporting nothing; its next sync does not take it up again.
    ///
    /// MUTATION CONTROL: reporting a certificate that does not decode and
    /// leaving it, as the poll did, turns this red: every sync reports it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn junk_under_the_finality_certificate_class_is_passed_over_once_read() {
        let p = Pair::boot(0, 0).await;
        let (route, id, copy_key) = posted_under_a_class(
            &p,
            &p.a,
            &p.b,
            crate::sdk::b0x_sdk::RELATIONSHIP_FINALIZED_METHOD,
            b"not a certificate".to_vec(),
            0x6C,
        )
        .await;
        clean(&p.b.sync().await);
        p.b.enter();
        assert!(
            client_db::b0x_consumed::is_passed_over(&route, &copy_key).expect("passed over"),
            "passed over by its content"
        );
        assert!(
            !client_db::b0x_consumed::is_consumed(&route, &id).expect("consumed"),
            "its id consumed nothing"
        );
        clean(&p.b.sync().await);
    }

    /// Pre-audit item 11, MR-DSM-0332: bytes under the countersign-delta class
    /// that are not a delta never will be one. B posts to A, through its own
    /// spool client, an envelope of that class carrying junk. A's first sync
    /// reads it and passes it over by its content, consuming no id and
    /// reporting nothing; its next sync does not take it up again.
    ///
    /// MUTATION CONTROL: reporting a delta that does not decode and leaving
    /// it, as the poll did, turns this red: every sync reports it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn junk_under_the_countersign_delta_class_is_passed_over_once_read() {
        let p = Pair::boot(0, 0).await;
        let (route, id, copy_key) = posted_under_a_class(
            &p,
            &p.b,
            &p.a,
            crate::sdk::b0x_sdk::RECEIPT_COUNTERSIGN_B_METHOD,
            b"not a countersign delta".to_vec(),
            0x6D,
        )
        .await;
        clean(&p.a.sync().await);
        p.a.enter();
        assert!(
            client_db::b0x_consumed::is_passed_over(&route, &copy_key).expect("passed over"),
            "passed over by its content"
        );
        assert!(
            !client_db::b0x_consumed::is_consumed(&route, &id).expect("consumed"),
            "its id consumed nothing"
        );
        clean(&p.a.sync().await);
    }
}
