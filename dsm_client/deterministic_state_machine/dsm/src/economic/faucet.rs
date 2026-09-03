// SPDX-License-Identifier: Apache-2.0

//! The ERA faucet — a finite, network-scoped bootstrap allocation expressed
//! as independent single-use tickets.
//!
//! ## The one protocol-fixed ERA bootstrap issuance event
//!
//! The validated economic lineage refuses to create value from nothing, so
//! the first legitimate units need an **authorized issuance/source
//! predicate**. For ERA that predicate is THIS: a genesis allocation of
//!
//! ```text
//! 800,000,000 tickets × 100 ERA = 80,000,000,000 ERA   (per DSM network)
//! ```
//!
//! "Already-allocated ERA" is only true *after* this predicate; the tickets
//! are where the units come from, exactly once, and a reader asking "how did
//! an empty `R_econ` come to hold ERA" finds the answer here rather than
//! nowhere. This is deliberately NOT a normal `AuthorizedIssuance` lineage
//! transition and NOT a general "who may issue what" rule — it is one
//! auditable allocation, scoped to one asset, one payout, one ticket
//! universe per network.
//!
//! ## Why tickets, not a faucet state chain
//!
//! A shared faucet head `F_n → F_{n+1}` plus public eligibility is a
//! denial-of-service primitive: one structurally-valid-but-invalid claim wins
//! the unique successor cell, verifiers reject it, and no valid successor can
//! ever be written — the faucet bricks globally at `n`. Tickets remove the
//! shared state instead of guarding it: each ticket is an independent
//! write-once cell, a poisoned cell costs one ticket out of 800M, and there
//! is **no** `faucet_sequence`, no mutable `remaining`, no
//! `parent_state_commitment`, no reserve leaf. Consuming the ticket IS the
//! source depletion:
//!
//! ```text
//! total admitted faucet credits <= distinct consumed tickets × 100
//!                               <= 800,000,000 × 100 = 80,000,000,000
//! ```
//!
//! ## The canonical-id rule
//!
//! Every authoritative check compares against [`era_faucet_id`] — the
//! descriptor and a winner agreeing with EACH OTHER proves nothing. Without
//! the canonical comparison an attacker invents faucet ids F1, F2, … and
//! obtains a fresh 800M-ticket universe under each, which destroys the cap.
//!
//! The id is **network-scoped**: claims are won in the register set the
//! claimant's `network_id` resolves, so an asset-only id would let two
//! networks each consume ticket `i` and each validate +100. One finite
//! allocation per network; the verifier derives `network_id` from the
//! authenticated Genesis v3, never from the claimant.

use prost::Message;

use crate::ccb::decode::DecodeError;
use crate::common::domain_tags::{
    TAG_DSM_ECONOMIC_OPERATION_DIGEST_DSM, TAG_DSM_ECONOMIC_OPERATION_ID_DSM,
    TAG_DSM_ECON_SOURCE_ERA_FAUCET_TICKET, TAG_DSM_ERA_FAUCET_ID, TAG_DSM_ERA_FAUCET_TICKET_CLAIM,
    TAG_DSM_ERA_FAUCET_TICKET_CLAIM_SIGN,
};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::storage_object::immutable_addr;
use crate::types::proto as generated;

/// Tickets in one network's allocation.
pub const ERA_FAUCET_TICKET_COUNT: u64 = 800_000_000;

/// ERA per ticket. ERA is whole-unit (`decimals = 0`), so this is literally
/// 100 ERA.
pub const ERA_FAUCET_PAYOUT: u64 = 100;

/// The canonical faucet identity for one network:
/// `H_dom(DSM/era-faucet-id/v1, network_id ‖ ERA_POLICY_COMMIT)`.
///
/// Recomputable by anyone from public inputs — no magic array, no registry
/// lookup. `network_id` MUST be the one committed in the claimant's
/// authenticated Genesis v3 (recovered by recomputation), never a value the
/// claimant supplies alongside the claim.
pub fn era_faucet_id(network_id: &[u8]) -> [u8; 32] {
    // The ERA commit comes from the one existing authority for builtin
    // commits, through its INFALLIBLE accessor — no Option, no expect, no
    // panic path for an impossibility.
    let era = crate::core::token::token_state_manager::era_policy_commit();
    let mut h = dsm_domain_hasher(TAG_DSM_ERA_FAUCET_ID);
    h.update(network_id);
    h.update(&era);
    *h.finalize().as_bytes()
}

/// `SourceId` for a consumed ticket:
/// `H_dom(DSM/econ-source/era-faucet-ticket/v1, faucet_id ‖ u64_be(index))`.
/// Inherits the network scope through `faucet_id`.
pub fn faucet_ticket_source_id(faucet_id: &[u8; 32], ticket_index: u64) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_ECON_SOURCE_ERA_FAUCET_TICKET);
    h.update(faucet_id);
    h.update(&ticket_index.to_be_bytes());
    *h.finalize().as_bytes()
}

/// `operation_digest_dsm = H_dom(DSM/economic-operation-digest/dsm/v1,
/// exact Operation::to_bytes())`.
pub fn dsm_operation_digest(operation_bytes: &[u8]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_ECONOMIC_OPERATION_DIGEST_DSM);
    h.update(operation_bytes);
    *h.finalize().as_bytes()
}

/// `EconomicOperationId_dsm = H_dom(DSM/economic-operation-id/dsm/v2,
/// G ‖ DevID ‖ C_dsm+)`.
///
/// `c_dsm_plus` is the accepted DSM successor's chain-state commitment — the
/// relationship chain tip the acceptance installed. The id names WHICH
/// authenticated successor performed the operation; the operation digest
/// names WHAT was performed. Two successors can carry byte-identical
/// operation bytes, so an id derived from the digest (the burned `/v1`
/// preimage) could not tell them apart — and
/// `consumed_source.consumer_economic_operation_id` needs to.
pub fn dsm_economic_operation_id(
    genesis: &[u8; 32],
    device_id: &[u8; 32],
    c_dsm_plus: &[u8; 32],
) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_ECONOMIC_OPERATION_ID_DSM);
    h.update(genesis);
    h.update(device_id);
    h.update(c_dsm_plus);
    *h.finalize().as_bytes()
}

/// The content address of the EXACT signed envelope bytes in the immutable
/// object store — what `faucet_claim_evidence_addr` must equal.
pub fn faucet_claim_evidence_addr(envelope_bytes: &[u8]) -> [u8; 32] {
    immutable_addr(TAG_DSM_ERA_FAUCET_TICKET_CLAIM, envelope_bytes)
}

/// Matches the proto's `dsm_max_len`; prost does not enforce it, so this
/// module does.
const MAX_KEY_OR_SIG_BYTES: usize = 65_535;

/// The unsigned claim body — what the signature covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaucetTicketClaimBody {
    pub faucet_id: [u8; 32],
    pub ticket_index: u64,
    pub claimant_genesis: [u8; 32],
    pub claimant_devid: [u8; 32],
    /// The TARGET economic position this claim will fund. Half of the
    /// non-reuse mechanism: the envelope commits ONE position, and the root
    /// register at that position is itself write-once.
    pub claimant_economic_position: u64,
    /// The digest of the exact `Operation::FaucetClaim` this ticket funds —
    /// the other half of non-reuse, pinning WHICH transition.
    pub recipient_operation_digest: [u8; 32],
    pub claimant_public_key: Vec<u8>,
    pub storage_set_id: [u8; 32],
}

/// An envelope that decoded strictly and whose signature verified under its
/// own `claimant_public_key`.
///
/// Verifying the signature proves the body was signed by whoever holds that
/// key. It does NOT prove the key is the claimant's P0–P6-proven AK — the
/// authoritative provenance verifier checks that separately, because the
/// storage node's bearer-token attribution is not the cryptographic
/// DSM-identity binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFaucetTicketClaim {
    pub body: FaucetTicketClaimBody,
    /// The exact bytes a member stores. Retained rather than re-derived: a
    /// byte-different re-encode is a different value at a write-once cell.
    pub envelope_bytes: Vec<u8>,
}

/// Why a register member refuses to STORE a ticket claim that decoded and
/// verified. Storage-layer only; none of these is a judgement about economics.
///
/// The variants are listed in the order a member checks them, and every
/// member implementation — the storage node's handler and the in-process
/// register double — checks them by calling ONE function,
/// [`verify_faucet_claim_attribution`], so the two cannot disagree about
/// which refusal a claim meets first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaucetAttributionError {
    /// The claim names a claimant key that is not the authenticated caller's.
    ClaimantIsNotCaller,
    /// The claim names a device that is not the authenticated caller's.
    DeviceIsNotCaller,
    /// The member is not configured with a storage set at all.
    StorageSetUnconfigured,
    /// The claim names a storage set this member is not a member of.
    WrongStorageSet {
        claimed: [u8; 32],
        configured: [u8; 32],
    },
    /// The member does not know which network it serves.
    NetworkUnconfigured,
    /// The claim names a faucet other than the canonical one for the
    /// member's network — an invented faucet id gets no cell to occupy.
    NoncanonicalFaucet,
    /// The ticket index is not a coordinate that exists.
    TicketOutOfRange,
}

impl core::fmt::Display for FaucetAttributionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ClaimantIsNotCaller => write!(
                f,
                "faucet ticket claim: claimant_public_key is not the authenticated caller — \
                 an authenticated caller may not claim as someone else"
            ),
            Self::DeviceIsNotCaller => write!(
                f,
                "faucet ticket claim: claimant_devid is not the authenticated caller's device"
            ),
            Self::StorageSetUnconfigured => {
                write!(
                    f,
                    "faucet ticket claim: this member has no storage set configured"
                )
            }
            Self::WrongStorageSet {
                claimed,
                configured,
            } => write!(
                f,
                "faucet ticket claim: names storage set {} but this member is configured for {}",
                crate::types::identifiers::encode_crockford(claimed),
                crate::types::identifiers::encode_crockford(configured)
            ),
            Self::NetworkUnconfigured => {
                write!(
                    f,
                    "faucet ticket claim: this member does not know its network"
                )
            }
            Self::NoncanonicalFaucet => write!(
                f,
                "faucet ticket claim: faucet_id is not the canonical faucet for this network"
            ),
            Self::TicketOutOfRange => write!(
                f,
                "faucet ticket claim: ticket_index is not a coordinate that exists — the \
                 allocation is exactly {ERA_FAUCET_TICKET_COUNT} tickets"
            ),
        }
    }
}

impl std::error::Error for FaucetAttributionError {}

/// The member-side attribution and coordinate check for a ticket claim, in
/// the ONE order every member applies it:
///
/// ```text
/// claimant key == caller key      -> ClaimantIsNotCaller
/// claimant devid == caller devid  -> DeviceIsNotCaller
/// member has a set                -> StorageSetUnconfigured
/// body set == member's set        -> WrongStorageSet
/// member knows its network        -> NetworkUnconfigured
/// faucet_id == era_faucet_id(net) -> NoncanonicalFaucet
/// ticket_index < the allocation   -> TicketOutOfRange
/// ```
///
/// Both attribution halves, because the ticket space is public — anyone may
/// claim ticket i — and what must be impossible is claiming AS someone else.
/// Takes a decoded-and-verified claim for the same reason
/// [`super::claim_envelope::verify_claim_attribution`] does: attribution
/// without a verified signature would accept a body anyone wrote in the
/// caller's name.
pub fn verify_faucet_claim_attribution(
    claim: &VerifiedFaucetTicketClaim,
    caller: &super::register::AuthenticatedCaller,
    configured_storage_set_id: Option<&[u8; 32]>,
    network_id: Option<&[u8]>,
) -> Result<(), FaucetAttributionError> {
    if claim.body.claimant_public_key != caller.public_key {
        return Err(FaucetAttributionError::ClaimantIsNotCaller);
    }
    if claim.body.claimant_devid != caller.device_id {
        return Err(FaucetAttributionError::DeviceIsNotCaller);
    }
    let Some(configured) = configured_storage_set_id else {
        return Err(FaucetAttributionError::StorageSetUnconfigured);
    };
    if claim.body.storage_set_id != *configured {
        return Err(FaucetAttributionError::WrongStorageSet {
            claimed: claim.body.storage_set_id,
            configured: *configured,
        });
    }
    let Some(network) = network_id else {
        return Err(FaucetAttributionError::NetworkUnconfigured);
    };
    if claim.body.faucet_id != era_faucet_id(network) {
        return Err(FaucetAttributionError::NoncanonicalFaucet);
    }
    if claim.body.ticket_index >= ERA_FAUCET_TICKET_COUNT {
        return Err(FaucetAttributionError::TicketOutOfRange);
    }
    Ok(())
}

/// Why an envelope is not a usable ticket claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaucetClaimError {
    /// Did not decode, decoded non-canonically, or a bounded field was empty
    /// or oversized.
    Malformed(&'static str),
    /// The signature does not verify over the body under the body's own key.
    SignatureInvalid,
    /// SPHINCS+ signing failed.
    SignFailed(String),
}

impl core::fmt::Display for FaucetClaimError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "faucet ticket claim malformed: {why}"),
            Self::SignatureInvalid => write!(f, "faucet ticket claim signature invalid"),
            Self::SignFailed(e) => write!(f, "faucet ticket claim sign failed: {e}"),
        }
    }
}

impl std::error::Error for FaucetClaimError {}

impl From<FaucetClaimError> for DecodeError {
    fn from(e: FaucetClaimError) -> Self {
        DecodeError::Invalid(e.to_string())
    }
}

impl FaucetTicketClaimBody {
    fn to_proto(&self) -> generated::FaucetTicketClaimBodyV1 {
        generated::FaucetTicketClaimBodyV1 {
            faucet_id: self.faucet_id.to_vec(),
            ticket_index: self.ticket_index,
            claimant_genesis: self.claimant_genesis.to_vec(),
            claimant_devid: self.claimant_devid.to_vec(),
            claimant_economic_position: self.claimant_economic_position,
            recipient_operation_digest: self.recipient_operation_digest.to_vec(),
            claimant_public_key: self.claimant_public_key.clone(),
            storage_set_id: self.storage_set_id.to_vec(),
        }
    }

    /// Canonical body bytes: prost's deterministic encoding.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.to_proto().encode_to_vec()
    }

    fn from_proto(p: &generated::FaucetTicketClaimBodyV1) -> Result<Self, FaucetClaimError> {
        let fixed = |v: &[u8], what: &'static str| -> Result<[u8; 32], FaucetClaimError> {
            <[u8; 32]>::try_from(v).map_err(|_| FaucetClaimError::Malformed(what))
        };
        if p.claimant_public_key.is_empty() || p.claimant_public_key.len() > MAX_KEY_OR_SIG_BYTES {
            return Err(FaucetClaimError::Malformed("claimant_public_key length"));
        }
        Ok(Self {
            faucet_id: fixed(&p.faucet_id, "faucet_id")?,
            ticket_index: p.ticket_index,
            claimant_genesis: fixed(&p.claimant_genesis, "claimant_genesis")?,
            claimant_devid: fixed(&p.claimant_devid, "claimant_devid")?,
            claimant_economic_position: p.claimant_economic_position,
            recipient_operation_digest: fixed(
                &p.recipient_operation_digest,
                "recipient_operation_digest",
            )?,
            claimant_public_key: p.claimant_public_key.clone(),
            storage_set_id: fixed(&p.storage_set_id, "storage_set_id")?,
        })
    }

    /// `m = H_dom(DSM/era-faucet-ticket-claim-sign/v1, canonical body bytes)`.
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut h = dsm_domain_hasher(TAG_DSM_ERA_FAUCET_TICKET_CLAIM_SIGN);
        h.update(&self.canonical_bytes());
        *h.finalize().as_bytes()
    }
}

/// Build and sign an envelope. The caller retains the returned bytes and
/// replays them verbatim on every retry — SPHINCS+ signing here is
/// deterministic, so a REGENERATED envelope is indistinguishable from a
/// replayed one downstream, which is exactly why regeneration is forbidden:
/// sign once, freeze, replay.
pub fn sign_faucet_ticket_claim(
    body: &FaucetTicketClaimBody,
    claimant_secret_key: &[u8],
) -> Result<Vec<u8>, FaucetClaimError> {
    let digest = body.signing_digest();
    let signature = crate::crypto::sphincs::sphincs_sign(claimant_secret_key, &digest)
        .map_err(|e| FaucetClaimError::SignFailed(e.to_string()))?;
    Ok(generated::FaucetTicketClaimV1 {
        body: Some(body.to_proto()),
        claimant_signature: signature,
    }
    .encode_to_vec())
}

/// Strictly decode an envelope and verify its signature under the body's own
/// `claimant_public_key`. Refuses anything that does not re-encode to exactly
/// the input bytes — unknown fields, duplicates and non-canonical encodings
/// all fail that comparison.
pub fn decode_and_verify_faucet_ticket_claim(
    envelope_bytes: &[u8],
) -> Result<VerifiedFaucetTicketClaim, FaucetClaimError> {
    if envelope_bytes.is_empty() {
        return Err(FaucetClaimError::Malformed("empty envelope"));
    }
    let env = generated::FaucetTicketClaimV1::decode(envelope_bytes)
        .map_err(|_| FaucetClaimError::Malformed("envelope does not decode"))?;
    let body_proto = env
        .body
        .as_ref()
        .ok_or(FaucetClaimError::Malformed("envelope has no body"))?;
    if env.claimant_signature.is_empty() || env.claimant_signature.len() > MAX_KEY_OR_SIG_BYTES {
        return Err(FaucetClaimError::Malformed("signature length"));
    }
    let body = FaucetTicketClaimBody::from_proto(body_proto)?;
    let reencoded = generated::FaucetTicketClaimV1 {
        body: Some(body.to_proto()),
        claimant_signature: env.claimant_signature.clone(),
    }
    .encode_to_vec();
    if reencoded != envelope_bytes {
        return Err(FaucetClaimError::Malformed("envelope is not canonical"));
    }
    let digest = body.signing_digest();
    let ok = crate::crypto::sphincs::sphincs_verify(
        &body.claimant_public_key,
        &digest,
        &env.claimant_signature,
    )
    .map_err(|_| FaucetClaimError::SignatureInvalid)?;
    if !ok {
        return Err(FaucetClaimError::SignatureInvalid);
    }
    Ok(VerifiedFaucetTicketClaim {
        body,
        envelope_bytes: envelope_bytes.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_allocation_product_is_pinned() {
        // 800M tickets × 100 ERA = the 80B bootstrap allocation, per network.
        assert_eq!(
            ERA_FAUCET_TICKET_COUNT
                .checked_mul(ERA_FAUCET_PAYOUT)
                .expect("no overflow"),
            80_000_000_000u64
        );
    }

    #[test]
    fn the_faucet_id_is_network_scoped_and_deterministic() {
        let testnet = era_faucet_id(b"dsm-testnet");
        assert_eq!(testnet, era_faucet_id(b"dsm-testnet"), "recomputable");
        assert_ne!(
            testnet,
            era_faucet_id(b"othernet"),
            "a different network is a DIFFERENT 80B allocation — an asset-only id would \
             multiply the cap by the number of networks"
        );
    }

    #[test]
    fn source_ids_inherit_the_network_scope_and_distinguish_tickets() {
        let f_ours = era_faucet_id(b"dsm-testnet");
        let f_other = era_faucet_id(b"othernet");
        assert_ne!(
            faucet_ticket_source_id(&f_ours, 7),
            faucet_ticket_source_id(&f_other, 7)
        );
        assert_ne!(
            faucet_ticket_source_id(&f_ours, 7),
            faucet_ticket_source_id(&f_ours, 8)
        );
    }
}
