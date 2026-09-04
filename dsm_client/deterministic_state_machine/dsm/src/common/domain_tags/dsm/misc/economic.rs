// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: the online economic root `R_econ`.
//!
//! `R_econ` is a **separate tree from the per-device relationship SMT**, and
//! these tags are what make that separation structural rather than a matter of
//! caller discipline. Reusing `DSM/smt-leaf` / `DSM/smt-node` would let a
//! relationship inclusion proof be replayed as an economic one, so the
//! economic tree gets its own leaf and node domains and shares nothing.
//!
//! The offline device-bound allocation has **no leaf here**. It is a separate
//! accounting regime, not an `R_econ` member.

use crate::crypto::domain::TaggedHashDomain;

/// Economic SMT leaf: `H(tag ‖ 0x00 ‖ key ‖ economic_leaf_value(S))`.
///
/// Binds the **key** as well as the value, unlike the relationship SMT's
/// `DSM/smt-leaf`. That is what stops a proof for one economic leaf being
/// replayed at another position with the same value — which matters far more
/// here than for relationship tips, because two distinct assets can genuinely
/// hold the same amount.
pub const TAG_DSM_ECONOMIC_SMT_LEAF: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/economic-smt-leaf/v1");
/// Economic SMT internal node: `H(tag ‖ 0x00 ‖ left ‖ right)`.
pub const TAG_DSM_ECONOMIC_SMT_NODE: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/economic-smt-node/v1");
/// The value committed at an economic leaf: `H(tag ‖ 0x00 ‖ CCB(S))` over the
/// leaf's own state object (classes `0x001F`–`0x0022`).
///
/// A separate domain from the leaf hash so that a leaf-state commitment can
/// never be mistaken for a tree node: the state object is the *content*, the
/// leaf hash is its *position-bound* form.
pub const TAG_DSM_ECONOMIC_LEAF_STATE: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/economic-leaf-state/v1");

/// `balance` leaf key: `H(tag ‖ 0x00 ‖ G ‖ DevID ‖ policy_commit)`.
pub const TAG_DSM_ECONOMIC_BALANCE_KEY: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/economic-balance-key/v1");
/// `vault_reserve` leaf key:
/// `H(tag ‖ 0x00 ‖ G ‖ DevID ‖ vault_id ‖ policy_commit)`.
pub const TAG_DSM_ECONOMIC_VAULT_RESERVE_KEY: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/economic-vault-reserve-key/v1");
/// `settlement_receipt` leaf key:
/// `H(tag ‖ 0x00 ‖ G ‖ DevID ‖ vault_id ‖ receipt_id)`.
pub const TAG_DSM_ECONOMIC_SETTLEMENT_RECEIPT_KEY: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/economic-settlement-receipt-key/v1");
/// `consumed_source` leaf key: `H(tag ‖ 0x00 ‖ G ‖ DevID ‖ source_id)`.
///
/// Every key derivation binds `G ‖ DevID`, so one identity's economic tree
/// can never collide with another's — the key space is per-identity by
/// construction rather than by the tree being private.
pub const TAG_DSM_ECONOMIC_CONSUMED_SOURCE_KEY: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/economic-consumed-source-key/v1");

/// The signed preimage of an issuance authorization (class `0x0029`):
/// `m = H(tag ‖ 0x00 ‖ CCB(IssuanceAuthorizationBody))`.
///
/// The body commits the issuer's write-once economic position and the exact
/// operation digest, so one authorization funds exactly one issuance rather
/// than a standing permission to mint that amount repeatedly.
pub const TAG_DSM_ISSUANCE_AUTHORIZATION_SIGN: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/issuance-authorization-sign/v1");
/// Immutable namespace of the issuance-authorization evidence bundle — the
/// object `CreditSourceAuthorizedIssuance.issuance_authorization_addr` names.
pub const TAG_DSM_ISSUANCE_AUTHORIZATION_EVIDENCE: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/issuance-authorization-evidence/v1");
/// `SourceId` of an authorized-issuance credit.
pub const TAG_DSM_ECON_SOURCE_AUTHORIZED_ISSUANCE: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/econ-source/authorized-issuance/v1");
/// The signed preimage of an economic root claim:
/// `m = H(tag ‖ 0x00 ‖ CCB(EconomicRootClaimBody))`.
pub const TAG_DSM_ECONOMIC_ROOT_CLAIM_SIGN: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/economic-root-claim-sign/v1");
/// Content address of an admission manifest:
/// `admission_manifest_addr = H(tag ‖ 0x00 ‖ CCB(EconomicAdmissionManifest))`.
///
/// The claim names this address and **nothing else** about the evidence. A
/// second digest field beside it (a witness digest, an evidence digest) would
/// be a place for the claim and the manifest to disagree; there is exactly one
/// edge, and everything else hangs off the manifest.
pub const TAG_DSM_ECONOMIC_ADMISSION_MANIFEST: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/economic-admission-manifest/v1");

/// The write-once register cell one identity's economic root occupies at one
/// position: `K_root = H(tag ‖ 0x00 ‖ G ‖ DevID ‖ u64_be(economic_position))`.
///
/// Binding `G ‖ DevID` **identity-scopes** the cell: it gives each identity its
/// own coordinate space, so two identities never collide at a position.
///
/// It does **not**, by itself, stop a third party writing there. Anyone who
/// knows a victim's `G` and `DevID` can compute `K_root(G_v, D_v, k)`, and
/// since the register is write-once, a value landing in that cell burns it
/// permanently. What prevents that is the member-side **claimant attribution**
/// check — see `economic::claim_envelope::verify_claim_attribution`. The two
/// properties are separate and both are required.
pub const TAG_DSM_TRADER_ECONOMIC_ROOT_REGISTER_KEY: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/trader-economic-root-register-key/v1");

/// `SourceId` for an intra-transition move:
/// `H(tag ‖ 0x00 ‖ economic_operation_id ‖ u32_be(debit_mutation_index))`.
///
/// Scoped to the operation that contains it, because the move exists only
/// inside that transition. Two transitions moving value at the same mutation
/// index are different sources, and must not collide in the consumed-source
/// space.
/// SourceId for a DLV reserve consumption (0x0026):
/// `H(tag ‖ 0x00 ‖ vault_id ‖ parent_sequence_be ‖ x)` — one consumption of
/// one vault generation by one trade; the write-once settlement-receipt leaf
/// is the non-reuse marker, so no consumed-source leaf exists for this arm.
pub const TAG_DSM_ECON_SOURCE_DLV_RESERVE_CONSUMPTION: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/econ-source/dlv-reserve-consumption/v1");
/// Immutable namespace for the 0x0026 evidence bundle
/// (`ReserveConsumptionEvidenceV1`: exact CCB(V_n) + the owner's vault-bound
/// authority evidence + both reserve pre-leaves with their 256-sibling
/// inclusion witnesses). Transport proto — no CCB class.
pub const TAG_DSM_DLV_RESERVE_CONSUMPTION_EVIDENCE: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/dlv-reserve-consumption-evidence/v1");
/// SourceId for a validated DLV settlement payment (0x0027):
/// `H(tag ‖ 0x00 ‖ vault_id ‖ settlement_receipt_id)` — one receipt funds
/// the owner's input-reserve credit exactly once; the non-reuse mechanism
/// is the reserve-sequence Merkle CAS (after the first apply the reserve
/// pre-state at n no longer exists in the owner's validated lineage).
pub const TAG_DSM_ECON_SOURCE_VALIDATED_DLV_SETTLEMENT_PAYMENT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/econ-source/validated-dlv-settlement-payment/v1");
/// Immutable namespace for the 0x0027 evidence bundle
/// (`SettlementPaymentEvidenceV1`: the trader's receipt leaf + inclusion
/// witness). Transport proto — no CCB class.
pub const TAG_DSM_DLV_SETTLEMENT_PAYMENT_EVIDENCE: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/dlv-settlement-payment-evidence/v1");
/// Immutable namespace for the GENERIC economic-inclusion proof
/// (`EconomicProofArtifactV1`: a publisher, one named economic position and
/// root, and one or more exact economic leaves with their 256-sibling paths).
/// Transport proto — no CCB class. Distinct from the two semantic evidence
/// namespaces above: those state WHY a credit is funded, this one only shows
/// which leaves a validated root commits, and both directions of a settlement
/// use the same object.
pub const TAG_DSM_ECONOMIC_PROOF_ARTIFACT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/economic-proof-artifact/v1");
pub const TAG_DSM_ECON_SOURCE_SAME_TRANSITION_MOVE: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/econ-source/same-transition-move/v1");

/// `SourceId` for a peer's validated debit:
/// `H(tag ‖ 0x00 ‖ peer_genesis ‖ peer_devid ‖ u64_be(peer_economic_position)
/// ‖ u32_be(peer_debit_mutation_index))`.
///
/// Derived from the peer's authenticated coordinates, never supplied. Those
/// four fields name exactly one debit in exactly one validated transition, so
/// the same debit can fund a credit only once no matter how many times it is
/// presented.
pub const TAG_DSM_ECON_SOURCE_VALIDATED_PEER_DEBIT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/econ-source/validated-peer-debit/v1");

/// The canonical, NETWORK-SCOPED ERA faucet identity:
/// `era_faucet_id(network_id) = H(tag ‖ 0x00 ‖ network_id ‖ ERA_POLICY_COMMIT)`.
///
/// Network-scoped because claims are won in the register set the claimant's
/// `network_id` resolves: an asset-only id would let two networks each consume
/// ticket `i` and each validate +100 ERA — the 80B cap silently multiplied by
/// the number of networks. One finite allocation PER DSM network; the verifier
/// derives `network_id` from the AUTHENTICATED Genesis v3, never from the
/// claimant.
pub const TAG_DSM_ERA_FAUCET_ID: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/era-faucet-id/v1");
/// The signed preimage of a faucet ticket claim:
/// `m = H(tag ‖ 0x00 ‖ canonical FaucetTicketClaimBodyV1 bytes)`.
pub const TAG_DSM_ERA_FAUCET_TICKET_CLAIM_SIGN: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/era-faucet-ticket-claim-sign/v1");
/// Immutable-store namespace for the EXACT signed `FaucetTicketClaimV1`
/// envelope bytes — what `faucet_claim_evidence_addr` addresses.
pub const TAG_DSM_ERA_FAUCET_TICKET_CLAIM: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/era-faucet-ticket-claim/v1");
/// Client-side ticket SEARCH seed (strategy, not validity — any in-range
/// ticket is valid; this only decides where a claimant looks first):
/// `H(tag ‖ 0x00 ‖ G ‖ DevID ‖ u64_be(target_economic_position) ‖ u64_be(attempt))`.
/// The position is in the seed so each admitted position gets its own
/// deterministic sequence rather than re-walking every consumed ticket.
pub const TAG_DSM_ERA_FAUCET_TICKET_SELECT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/era-faucet-ticket-select/v1");
/// `SourceId` for a consumed faucet ticket:
/// `H(tag ‖ 0x00 ‖ faucet_id ‖ u64_be(ticket_index))`. Inherits the network
/// scope through `faucet_id`.
pub const TAG_DSM_ECON_SOURCE_ERA_FAUCET_TICKET: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/econ-source/era-faucet-ticket/v1");
/// Digest of an ordinary DSM operation for economic binding:
/// `operation_digest_dsm = H(tag ‖ 0x00 ‖ exact Operation::to_bytes())`.
pub const TAG_DSM_ECONOMIC_OPERATION_DIGEST_DSM: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/economic-operation-digest/dsm/v1");
/// Identity of an economic operation on the DSM substrate:
/// `EconomicOperationId_dsm = H(tag ‖ 0x00 ‖ G ‖ DevID ‖ C_dsm+)`.
///
/// `/v1` is **burned**: its shipped preimage was `G ‖ DevID ‖
/// operation_digest_dsm`, which identifies WHAT operation was performed but
/// not WHICH authenticated accepted successor performed it. Once
/// `consumed_source.consumer_economic_operation_id` is live that distinction
/// is load-bearing (two successors can carry byte-identical operations), so
/// the corrected preimage binds the successor's chain-state commitment
/// `C_dsm+`. Changing the preimage under the same domain would give one
/// domain two meanings; hence `/v2`, and `/v1` is never reused.
pub const TAG_DSM_ECONOMIC_OPERATION_ID_DSM: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/economic-operation-id/dsm/v2");

/// Digest of the exact `EconomicRootClaimV1` envelope bytes a register member
/// stores and compares: `H(tag ‖ 0x00 ‖ envelope_bytes)`. The settlement
/// register's `-envelope` tag, for this register.
/// Immutable-store namespace of the exact `AuthorityEvidenceV1` bytes the
/// manifest's `authority_evidence_addr` names — the portable P0–P6 bundle a
/// foreign lineage walker verifies to recover the owner's AK and committed
/// network.
pub const TAG_DSM_ECONOMIC_AUTHORITY_EVIDENCE: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/economic-authority-evidence/v1");
/// Immutable-store namespace of the exact `DsmSuccessorEvidenceV1` bytes the
/// manifest's `dsm_successor_evidence_addr` names — the replayable accepted
/// successor: the balance-free chain-tip preimage fields, `C_dsm+`, and
/// `sigma_dsm` under the owner AK.
pub const TAG_DSM_ECONOMIC_SUCCESSOR_EVIDENCE: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/economic-dsm-successor-evidence/v1");
/// Signing domain of `sigma_dsm`:
/// `H(tag ‖ 0x00 ‖ G ‖ DevID ‖ C_dsm+ ‖ operation_digest)` — the signature
/// that makes "this identity ACCEPTED this successor carrying this
/// operation" a foreign-checkable fact rather than a local assertion.
/// Immutable-store namespace of one `EkCertStepV1` — a signer-identity EK
/// certificate step, content-addressed by predecessor.
pub const TAG_DSM_EK_CERT_STEP: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/ek-cert-step/v1");
/// Immutable-store namespace of the exact `PeerTransferAcceptanceEvidenceV1`
/// bytes a peer-debit descriptor's `acceptance_evidence_addr` names.
pub const TAG_DSM_PEER_TRANSFER_ACCEPTANCE: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/peer-transfer-acceptance/v1");
/// Signing domain of the recipient economic RELEASE — the transport-only
/// post-admission finalization authority (3.5b PR4). `sig_b` inside the
/// published acceptance bundle is acceptance PROVENANCE and is discoverable
/// before `ECON_ADMITTED`; the release is what a sender may FINALIZE on, and
/// it exists only after the recipient's credit is admitted into validated
/// `R_econ`.
pub const TAG_DSM_RECIPIENT_ECONOMIC_RELEASE_SIGN: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/recipient-economic-release-sign/v1");
/// Immutable-store namespace of the exact `RecipientEconomicReleaseV1`
/// bytes. The countersign delta carries only the 32-byte content address (a
/// SPHINCS+ release inline would exceed the reply-envelope cap); the sender
/// fetches the exact bytes re-hash-verified. The object is frozen in the
/// ADMIT transaction — never earlier — so it cannot reach the network
/// before ECON_ADMITTED.
pub const TAG_DSM_RECIPIENT_ECONOMIC_RELEASE: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/recipient-economic-release/v1");
pub const TAG_DSM_ECONOMIC_SUBSTRATE_SIGN: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/economic-substrate-sign/v1");
pub const TAG_DSM_ECONOMIC_ROOT_CLAIM_ENVELOPE: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/economic-root-claim-envelope/v1");

/// Immutable-store namespace for the exact `EconomicTransitionWitness` bytes.
/// `immutable_inner(tag, bytes)` under this tag IS the manifest's
/// `transition_witness_addr`, so the DAG address and the fetch address are one
/// computation.
pub const TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/economic-transition-witness/v1");
/// Immutable-store namespace for the exact canonical DSM-substrate operation
/// bytes an admission accepted (`C_dsm+` evidence for the beta claim flow).
pub const TAG_DSM_ECONOMIC_DSM_SUBSTRATE_OBJ: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/economic-dsm-substrate/v1");
