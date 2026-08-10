// SPDX-License-Identifier: MIT OR Apache-2.0

//! State transition operations for the DSM protocol.
//!
//! This module defines [`Operation`], the enum representing every kind of state
//! transition the protocol supports -- from identity creation and token transfers
//! to bilateral relationship management and recovery flows.
//!
//! Operations are encoded to canonical, deterministic byte representations for
//! inclusion in state hashes and Envelope v3 payloads. No JSON or serde is used
//! on the canonical path; all encoding uses length-prefixed binary with fixed
//! variant tags.
//!
//! Trait hierarchies ([`Ops`], [`IdOps`], [`TokenOps`], [`GenericOps`],
//! [`SmartCommitOps`]) provide domain-specific validation and execution
//! interfaces that [`Operation`] implements.

use std::{collections::HashMap, fmt::Debug};

use crate::{
    commitments::precommit::SecurityParameters,
    types::{error::DsmError, token_types::Balance},
};

/// Base operations trait that all specific operation traits inherit from.
///
/// Provides the fundamental interface for validating, executing, identifying,
/// and serialising any state transition operation.
pub trait Ops: Debug {
    /// Validate that this operation's fields are internally consistent.
    fn validate(&self) -> Result<bool, DsmError>;
    /// Execute the operation and return its canonical byte output.
    fn execute(&self) -> Result<Vec<u8>, DsmError>;
    /// Return a string identifier for this operation type.
    fn get_id(&self) -> &str;
    /// Encode this operation to its canonical, deterministic byte representation.
    fn to_bytes(&self) -> Vec<u8>;
}

/// Identity management operations.
///
/// Extended trait for operations that create, update, verify, or revoke
/// cryptographic identities anchored to the genesis state.
pub trait IdOps: Ops {
    /// Verify an identity against the given SPHINCS+ public key.
    fn verify_identity(&self, public_key: &[u8]) -> Result<bool, DsmError>;
    /// Update the identity data associated with this operation.
    fn update_identity(&mut self, new_data: &[u8]) -> Result<(), DsmError>;
    /// Revoke this identity, rendering it permanently invalid.
    fn revoke_identity(&mut self) -> Result<(), DsmError>;
    /// Generate a cryptographic proof of identity for external verification.
    fn get_identity_proof(&self) -> Result<Vec<u8>, DsmError>;
}

/// Token management operations.
///
/// Extended trait for operations that manipulate token balances, including
/// transfer, mint, burn, lock, and unlock. Expiration is enforced by state
/// progression (logical ticks), not wall-clock time.
pub trait TokenOps: Ops {
    /// Check whether this token operation references a valid, non-zero amount.
    fn is_valid(&self) -> bool;
    /// Check whether this token has expired based on state progression.
    fn has_expired(&self) -> bool;
    /// Verify the token operation against the given SPHINCS+ public key.
    fn verify_token(&self, public_key: &[u8]) -> Result<bool, DsmError>;
    /// Extend the validity window by a number of logical ticks.
    fn extend_validity(&mut self, duration: u64) -> Result<(), DsmError>;
}

/// Generic operations for protocol extensibility.
///
/// Provides a type-erased interface for operations that do not fit the
/// identity or token categories, allowing application-specific extensions.
pub trait GenericOps: Ops {
    /// Return the application-defined operation type label.
    fn get_operation_type(&self) -> &str;
    /// Return the raw payload data for this generic operation.
    fn get_data(&self) -> &[u8];
    /// Replace the payload data for this generic operation.
    fn set_data(&mut self, data: Vec<u8>) -> Result<(), DsmError>;
    /// Merge this operation's data with another generic operation's data.
    fn merge(&self, other: &dyn GenericOps) -> Result<Vec<u8>, DsmError>;
}

/// Smart commitment operations.
///
/// Extended trait for operations that create, verify, update, and finalise
/// deterministic smart commitments in the DSM protocol.
pub trait SmartCommitOps: Ops {
    /// Verify the commitment against the given SPHINCS+ public key.
    fn verify_commitment(&self, public_key: &[u8]) -> Result<bool, DsmError>;
    /// Update the commitment data with new material.
    fn update_commitment(&mut self, new_data: &[u8]) -> Result<(), DsmError>;
    /// Finalise the commitment and return its canonical byte representation.
    fn finalize_commitment(&mut self) -> Result<Vec<u8>, DsmError>;
    /// Generate a cryptographic proof of commitment for external verification.
    fn get_commitment_proof(&self) -> Result<Vec<u8>, DsmError>;
}

/// State transition execution mode (canonical encoded; no Serde).
///
/// Determines whether a state transition requires mutual agreement from
/// both parties (bilateral) or can be performed by one party alone (unilateral).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TransactionMode {
    /// Both parties must sign the state transition (3-phase commit protocol).
    #[default]
    Bilateral,
    /// Only the initiating party signs; used for self-directed operations.
    Unilateral,
}

/// Verification strategy for a state transition (canonical encoded; no Serde).
///
/// Specifies which verification path is used to validate the state transition,
/// ranging from simple standard checks to full bilateral verification with
/// pre-committed parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationType {
    /// Default verification using hash chain adjacency.
    Standard,
    /// Enhanced verification with additional cryptographic proofs.
    Enhanced,
    /// Full bilateral verification requiring both parties' signatures.
    Bilateral,
    /// Verification through decentralized directory lookup.
    Directory,
    /// Standard verification within a bilateral relationship context.
    StandardBilateral,
    /// Verification against a previously submitted forward commitment.
    PreCommitted,
    /// Unilateral verification anchored to the initiator's identity.
    UnilateralIdentityAnchor,
    /// Application-defined custom verification with raw parameter bytes.
    Custom(Vec<u8>),
}

/// The authority-proof requirement for a value operation — WHAT proof of authority a transition
/// must carry. A distinct semantic layer from `pre_commit` (settlement / commitment material) and
/// from `value_capability` (whether the operation may carry value at all). Present on a `Transfer`
/// only when the operation opts into the optional offline-bearer tier; absent means the ordinary
/// online-checked path, encoded byte-identically to before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityPolicy {
    /// Which authority mode this operation requires.
    pub mode: AuthorityMode,
    /// Identifier of the pinning policy the offline-bearer proof must satisfy.
    pub policy_id: [u8; 32],
    /// Identifier of the admitted anchor set (single island in cut-1; dual-island later).
    pub anchor_set_id: [u8; 32],
}

/// The authority mode an operation declares (see [`AuthorityPolicy`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityMode {
    /// Ordinary online-checked settlement — no hardware anchor proof required.
    OnlineChecked,
    /// Optional offline-bearer tier: a hardware island MUST sign this transition's intent and the
    /// proof is folded into the successor tip. Fail-closed — if the proof cannot be produced or
    /// verified the transition is rejected, never silently downgraded.
    OfflineBearerRequired,
}

impl AuthorityMode {
    /// Canonical 1-byte tag for byte encoding.
    pub fn tag(self) -> u8 {
        match self {
            AuthorityMode::OnlineChecked => 0,
            AuthorityMode::OfflineBearerRequired => 1,
        }
    }
}

/// Version tag for the canonical authority-policy tail appended to `Operation::Transfer::to_bytes`.
pub const AUTHORITY_POLICY_TAG_V1: u8 = 1;

impl AuthorityPolicy {
    /// Append this policy's canonical, versioned bytes to an operation encoding. Called by
    /// `Operation::Transfer::to_bytes` ONLY when the policy is present; when absent, NOTHING is
    /// appended, so existing operation encodings — and every historical state hash — are unchanged.
    pub fn append_canonical(&self, out: &mut Vec<u8>) {
        use crate::types::serialization::{put_bytes, put_u8};
        put_u8(out, AUTHORITY_POLICY_TAG_V1);
        put_u8(out, self.mode.tag());
        put_bytes(out, &self.policy_id);
        put_bytes(out, &self.anchor_set_id);
    }
}

/// The canonical DSM offline-bearer authority policy (v1). ONE agreed value referenced by BOTH the
/// sender (building the offline-bearer transfer operation) and the receiver (verifying the release
/// commits to the same policy) — so the `policy_id` bound into the operation, the chip's PREPARE
/// `authority_policy_hash`, and the receiver's accept check are provably identical bytes.
/// `policy_id`/`anchor_set_id` are domain-separated constants; per-tenant policy-registry management
/// is a later refinement layered on this default.
pub fn canonical_offline_bearer_policy() -> AuthorityPolicy {
    AuthorityPolicy {
        mode: AuthorityMode::OfflineBearerRequired,
        policy_id: crate::crypto::blake3::domain_hash_bytes(
            crate::crypto::domain::TaggedHashDomain::from_static(
                b"DSM/offline-bearer/policy-id/well-known/v1",
            ),
            &[],
        ),
        anchor_set_id: crate::crypto::blake3::domain_hash_bytes(
            crate::crypto::domain::TaggedHashDomain::from_static(
                b"DSM/offline-bearer/anchor-set-id/well-known/v1",
            ),
            &[],
        ),
    }
}

/// Primary state transition operation enum (no Serde in canonical path).
///
/// Each variant represents a distinct kind of state transition in the DSM
/// protocol. All variants support canonical, deterministic byte encoding
/// via [`Operation::to_bytes`] for inclusion in state hashes and wire payloads.
///
/// `large_enum_variant` is allowed deliberately: this is a flat protocol
/// operation enum whose `Transfer`/`Recovery` variants are intentionally
/// inline (no heap indirection on the hot transition path), and it is
/// constructed/matched at ~190 call sites. Boxing fields to equalize variant
/// size would impose a heap allocation per operation and ripple across every
/// site for no protocol benefit.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Operation {
    /// Genesis operation -- the initial state in a hash chain (state number 0).
    #[default]
    Genesis,
    /// Create a new identity with associated public key material.
    Create {
        /// Human-readable description of the identity creation.
        message: String,
        /// Raw identity data (e.g., device binding material).
        identity_data: Vec<u8>,
        /// SPHINCS+ public key for this identity.
        public_key: Vec<u8>,
        /// Additional metadata associated with the identity.
        metadata: Vec<u8>,
        /// Cryptographic commitment binding the creation to a prior state.
        commitment: Vec<u8>,
        /// Proof of authorization for the creation.
        proof: Vec<u8>,
        /// Bilateral or unilateral execution mode.
        mode: TransactionMode,
    },
    /// Update an existing identity with new data and optional forward link.
    Update {
        /// Human-readable description of the update.
        message: String,
        /// Binary identifier of the identity being updated.
        identity_id: Vec<u8>,
        /// New identity data replacing the previous version.
        updated_data: Vec<u8>,
        /// Proof of authorization to perform the update.
        proof: Vec<u8>,
        /// Optional forward link to pre-commit the next state transition.
        forward_link: Option<Vec<u8>>,
    },
    /// Transfer tokens from the current device to a recipient.
    Transfer {
        /// Raw 32-byte recipient device identifier (canonical bytes; no text encodings on op path).
        to_device_id: Vec<u8>,
        /// Token amount to transfer (must be > 0 for validity).
        amount: Balance,
        /// Binary identifier of the token type being transferred.
        token_id: Vec<u8>,
        /// CPTA policy commitment (32B) binding this transfer to the token's
        /// canonical policy (§9.5: "All TokenOps MUST include policy_commit;
        /// verifiers reject if it differs from the token's creation
        /// policy_commit"). See token-policy-readiness doctrine §4.
        policy_commit: [u8; 32],
        /// Bilateral (3-phase commit) or unilateral execution mode.
        mode: TransactionMode,
        /// Unique nonce preventing replay of this transfer.
        nonce: Vec<u8>,
        /// Verification strategy for validating this transfer.
        verification: VerificationType,
        /// Optional pre-commitment parameters binding this transfer to a prior commitment.
        pre_commit: Option<PreCommitmentOp>,
        /// Raw recipient identifier for policy/precommit matching (kept as bytes).
        recipient: Vec<u8>,
        /// Binary recipient address or alias.
        to: Vec<u8>,
        /// Human-readable transfer description.
        message: String,
        /// Sender's SPHINCS+ signature authorizing this transfer.
        signature: Vec<u8>,
        /// Authority-proof requirement for this transfer. `Some` opts into the offline-bearer
        /// tier (a hardware island must sign and the proof folds into the tip); `None` is the
        /// ordinary online-checked path and encodes byte-identically to before. Must be set on
        /// the operation BEFORE challenge/UI-transcript/signing/tip computation. See
        /// [`AuthorityPolicy`].
        authority_policy: Option<AuthorityPolicy>,
    },
    /// Mint new tokens into existence (requires authorization proof).
    Mint {
        /// Quantity of tokens to mint (must be > 0).
        amount: Balance,
        /// Binary identifier of the token type to mint.
        token_id: Vec<u8>,
        /// CPTA commit of the asset being minted.
        ///
        /// The conservation guard binds the applied `BalanceDelta` to THIS
        /// value, so a mint cannot credit an asset other than the one the
        /// signed operation names. Without it the guard could only check the
        /// delta's count/direction/amount, and a mint for token X could credit
        /// ERA. Mirrors `Transfer.policy_commit`.
        policy_commit: [u8; 32],
        /// Binary identifier of the authority that authorized this minting.
        authorized_by: Vec<u8>,
        /// Cryptographic proof from the minting authority.
        proof_of_authorization: Vec<u8>,
        /// Human-readable description of the minting event.
        message: String,
    },
    /// Burn (destroy) tokens, permanently removing them from circulation.
    Burn {
        /// Quantity of tokens to burn (must be > 0).
        amount: Balance,
        /// Binary identifier of the token type to burn.
        token_id: Vec<u8>,
        /// CPTA commit of the asset being burned. Binds the applied debit to
        /// the asset the signed operation names.
        policy_commit: [u8; 32],
        /// Cryptographic proof that the burner owns these tokens.
        proof_of_ownership: Vec<u8>,
        /// Human-readable description of the burn event.
        message: String,
    },
    /// Lock a quantity of tokens for a specified purpose (e.g., vault collateral).
    LockToken {
        /// Binary identifier of the token type to lock.
        token_id: Vec<u8>,
        /// Quantity of tokens to lock.
        amount: i64,
        /// Binary purpose tag for the lock (e.g., b"dlv_collateral", b"escrow").
        purpose: Vec<u8>,
        /// Bilateral or unilateral execution mode.
        mode: TransactionMode,
        /// SPHINCS+ signature authorizing this lock operation.
        signature: Vec<u8>,
    },
    /// Unlock previously locked tokens, making them available for transfer.
    UnlockToken {
        /// Binary identifier of the token type to unlock.
        token_id: Vec<u8>,
        /// Quantity of tokens to unlock.
        amount: i64,
        /// Binary purpose tag that originally locked these tokens.
        purpose: Vec<u8>,
        /// Bilateral or unilateral execution mode.
        mode: TransactionMode,
        /// SPHINCS+ signature authorizing this unlock operation.
        signature: Vec<u8>,
    },
    /// Lock tokens with owner and balance-level semantics.
    Lock {
        /// Binary identifier of the token type to lock.
        token_id: Vec<u8>,
        /// Balance-typed amount to lock.
        amount: Balance,
        /// Binary purpose tag for the lock.
        purpose: Vec<u8>,
        /// Binary owner of the tokens being locked.
        owner: Vec<u8>,
        /// Human-readable description.
        message: String,
        /// SPHINCS+ signature authorizing this lock operation.
        signature: Vec<u8>,
    },
    /// Unlock tokens with owner and balance-level semantics.
    Unlock {
        /// Binary identifier of the token type to unlock.
        token_id: Vec<u8>,
        /// Balance-typed amount to unlock.
        amount: Balance,
        /// Binary purpose tag that originally locked these tokens.
        purpose: Vec<u8>,
        /// Binary owner of the tokens being unlocked.
        owner: Vec<u8>,
        /// Human-readable description.
        message: String,
        /// SPHINCS+ signature authorizing this unlock operation.
        signature: Vec<u8>,
    },
    /// Register a new bilateral relationship between two devices.
    AddRelationship {
        /// 32-byte device ID of the relationship initiator.
        from_id: [u8; 32],
        /// 32-byte device ID of the relationship target.
        to_id: [u8; 32],
        /// Binary type tag for the relationship (e.g., b"bilateral_transfer").
        relationship_type: Vec<u8>,
        /// Additional metadata for the relationship.
        metadata: Vec<u8>,
        /// Proof of authorization to create this relationship.
        proof: Vec<u8>,
        /// Bilateral or unilateral execution mode.
        mode: TransactionMode,
        /// Human-readable description.
        message: String,
    },
    /// Create a bilateral relationship with a counterparty (simplified form).
    CreateRelationship {
        /// Human-readable description.
        message: String,
        /// Binary identifier of the counterparty device.
        counterparty_id: Vec<u8>,
        /// Cryptographic commitment to the relationship terms.
        commitment: Vec<u8>,
        /// Proof of authorization.
        proof: Vec<u8>,
        /// Bilateral or unilateral execution mode.
        mode: TransactionMode,
    },
    /// Remove an existing bilateral relationship.
    RemoveRelationship {
        /// 32-byte device ID of the relationship initiator.
        from_id: [u8; 32],
        /// 32-byte device ID of the relationship target.
        to_id: [u8; 32],
        /// Binary type tag of the relationship being removed.
        relationship_type: Vec<u8>,
        /// Proof of authorization to remove this relationship.
        proof: Vec<u8>,
        /// Bilateral or unilateral execution mode.
        mode: TransactionMode,
        /// Human-readable description.
        message: String,
    },
    /// Recovery operation to restore a compromised hash chain from a capsule/tombstone.
    Recovery {
        /// Human-readable description of the recovery event.
        message: String,
        /// State number of the compromised state being recovered from.
        state_number: u64,
        /// Hash of the compromised state.
        state_hash: Vec<u8>,
        /// Entropy of the compromised state.
        state_entropy: Vec<u8>,
        /// Data proving the state is invalid or compromised.
        invalidation_data: Vec<u8>,
        /// New state data to replace the compromised chain.
        new_state_data: Vec<u8>,
        /// State number of the replacement state.
        new_state_number: u64,
        /// Hash of the replacement state.
        new_state_hash: Vec<u8>,
        /// Entropy of the replacement state.
        new_state_entropy: Vec<u8>,
        /// Proof of key compromise (e.g., clone/anomaly evidence).
        compromise_proof: Vec<u8>,
        /// Signatures from recovery authorities (multi-party threshold).
        authority_sigs: Vec<Vec<u8>>,
    },
    /// Delete a resource by ID with proof of authorization.
    Delete {
        /// Reason for the deletion.
        reason: String,
        /// Proof of authorization to delete.
        proof: Vec<u8>,
        /// Bilateral or unilateral execution mode.
        mode: TransactionMode,
        /// Binary identifier of the resource to delete.
        id: Vec<u8>,
    },
    /// Create a forward link from the current state to a target.
    Link {
        /// Binary identifier of the link target.
        target_id: Vec<u8>,
        /// Binary type tag for the link.
        link_type: Vec<u8>,
        /// Proof of authorization.
        proof: Vec<u8>,
        /// Bilateral or unilateral execution mode.
        mode: TransactionMode,
    },
    /// Remove a previously created link.
    Unlink {
        /// Binary identifier of the link target to remove.
        target_id: Vec<u8>,
        /// Proof of authorization.
        proof: Vec<u8>,
        /// Bilateral or unilateral execution mode.
        mode: TransactionMode,
    },
    /// Invalidate the current state chain (e.g., due to detected cloning).
    Invalidate {
        /// Reason for invalidation.
        reason: String,
        /// Proof of the condition triggering invalidation.
        proof: Vec<u8>,
        /// Bilateral or unilateral execution mode.
        mode: TransactionMode,
    },
    /// Application-defined generic operation with arbitrary payload.
    Generic {
        /// Binary application-defined operation type identifier.
        operation_type: Vec<u8>,
        /// Raw payload bytes.
        data: Vec<u8>,
        /// Human-readable description.
        message: String,
        /// SPHINCS+ signature authorizing this generic operation.
        signature: Vec<u8>,
    },
    /// Receive tokens from a bilateral transfer (counterpart to Transfer).
    Receive {
        /// Binary identifier of the token type being received.
        token_id: Vec<u8>,
        /// Binary device ID of the sender.
        from_device_id: Vec<u8>,
        /// Amount of tokens received.
        amount: Balance,
        /// Binary identifier of the recipient.
        recipient: Vec<u8>,
        /// Human-readable description.
        message: String,
        /// Bilateral or unilateral execution mode.
        mode: TransactionMode,
        /// Unique nonce matching the sender's Transfer nonce.
        nonce: Vec<u8>,
        /// Verification strategy matching the sender's Transfer verification.
        verification: VerificationType,
        /// Hash of the sender's state at the time of transfer (for cross-chain verification).
        sender_state_hash: Option<Vec<u8>>,
    },
    /// Create a new token type with initial supply and policy parameters.
    CreateToken {
        /// Binary unique identifier for the new token type.
        token_id: Vec<u8>,
        /// Initial supply minted at creation. May be zero.
        initial_supply: Balance,
        /// CPTA commit of the NEW asset — mandatory.
        ///
        /// This is the content hash of the anchored policy, and it is the asset
        /// the issuance delta credits. It was `Option<Vec<u8>>` while nothing
        /// constructed this variant; issuance cannot be optional or
        /// variable-length, so it mirrors `Transfer.policy_commit`.
        policy_commit: [u8; 32],
        /// ERA destroyed to create this token.
        ///
        /// Present on the operation so the conservation guard can see it: the
        /// guard proves `delta == what was signed`, while the SDK proves
        /// `what was signed == the authoritative schedule value`. Same
        /// two-layer split `Transfer` uses for its amount.
        fee_amount: u64,
        /// Human-readable name of the token.
        name: String,
        /// Short symbol (e.g., "DSM", "dBTC").
        symbol: String,
        /// Number of decimal places for display formatting.
        decimals: u8,
        /// Optional URI pointing to token metadata.
        metadata_uri: Option<String>,
        /// SPHINCS+ signature authorizing this token creation.
        signature: Vec<u8>,
    },
    /// No-operation sentinel; produces no state change.
    Noop,
    /// Create a new Deterministic Limbo Vault, binding it to the hash chain.
    DlvCreate {
        /// 32-byte deterministic vault identifier.
        vault_id: Vec<u8>,
        /// SPHINCS+ public key of the vault creator.
        creator_public_key: Vec<u8>,
        /// BLAKE3("DSM/dlv-params\0" || ...) commitment to vault parameters.
        parameters_hash: Vec<u8>,
        /// Serialized FulfillmentMechanism (protobuf bytes).
        fulfillment_condition: Vec<u8>,
        /// Optional intended recipient public key.
        intended_recipient: Option<Vec<u8>>,
        /// Binary token type to lock in the vault (if applicable).
        token_id: Option<Vec<u8>>,
        /// Amount of tokens to lock in the vault (if applicable).
        locked_amount: Option<Balance>,
        /// SPHINCS+ signature by the creator over canonical bytes.
        signature: Vec<u8>,
        /// Execution mode (typically Unilateral for vault creation).
        mode: TransactionMode,
    },
    /// A trader settling a routed swap against a funded vault.
    ///
    /// The two balance deltas this operation carries are the ONLY value movement
    /// on the trader's chain, and `DeviceState::advance` is the sole guard against
    /// value creation *regardless of caller* — so everything needed to judge them
    /// travels here, inside the signed operation, rather than being checked by a
    /// handler an alternate caller could skip. Two correctly-shaped deltas must not
    /// be sufficient to mint the output.
    ///
    /// The authorization is self-contained by construction: every field is either
    /// re-derivable from published bytes or a signature over them, so the chokepoint
    /// can verify it with no network and no local vault.
    DlvSettle {
        /// 32-byte vault being settled against, and whose funds are moving.
        vault_id: Vec<u8>,
        /// SPHINCS+ public key of the vault owner, and the device id its reserve
        /// leaves are keyed under.
        owner_public_key: Vec<u8>,
        owner_devid: [u8; 32],
        owner_genesis: [u8; 32],
        /// The pair, as canonical policy commits — a ticker is not an identity and
        /// cannot name a reserve leaf.
        input_policy_commit: [u8; 32],
        output_policy_commit: [u8; 32],
        /// The exact vault state consumed: sequence, the digest over its reserves,
        /// and the SMT root those reserves were proved against.
        parent_sequence: u64,
        parent_reserves_digest: [u8; 32],
        reserve_proof_root: [u8; 32],
        /// Digest of the owner-published predicate, so a substituted condition
        /// cannot be pointed at.
        predicate_digest: [u8; 32],
        /// The signed quote and the external commitment it derives.
        route_commit_bytes: Vec<u8>,
        external_commitment_x: [u8; 32],
        /// Exact amounts, base units. The deltas must realize precisely these.
        input_amount: u64,
        output_amount: u64,
        /// Fee in basis points, and the DLV unlock proof σ.
        fee_bps: u32,
        sigma: [u8; 32],
        /// Who is being credited.
        settler_public_key: Vec<u8>,
        settler_devid: [u8; 32],
        /// Identity of the canonical settlement receipt this advance produces —
        /// the value a pending pointer commits to, and the thing that makes the
        /// settlement visible to everyone else.
        settlement_receipt_id: [u8; 32],
        /// SPHINCS+ signature by the settler over the canonical operation bytes.
        signature: Vec<u8>,
        mode: TransactionMode,
    },
    /// An owner recording a settlement it has already verified.
    ///
    /// Authorizes NO value movement. The trader's credit was final at the trader's
    /// own advance, authorized by the owner's pre-commitment rather than by owner
    /// liveness; this operation is the owner learning what already happened and
    /// folding it into its own composed state.
    ///
    /// Carries empty balance deltas by construction — the fee accrues inside the
    /// reserves as LP yield, so the owner's spendable balance is untouched — and
    /// moves only the vault's reserve leaves. Replaying the same receipt is a
    /// no-op; a different receipt claiming the same pointer is a conflict.
    DlvOwnerApply {
        /// 32-byte vault whose reserves are being reconciled.
        vault_id: Vec<u8>,
        /// The receipt being recorded, and the pointer that committed to it.
        settlement_receipt_id: [u8; 32],
        pending_pointer_x: [u8; 32],
        /// The sequence this advances from, and to. Exactly one step.
        parent_sequence: u64,
        new_sequence: u64,
        /// Reserve digests before and after, so the recorded state is pinned.
        parent_reserves_digest: [u8; 32],
        new_reserves_digest: [u8; 32],
        /// The pair whose leaves move, and by how much.
        input_policy_commit: [u8; 32],
        output_policy_commit: [u8; 32],
        input_amount: u64,
        output_amount: u64,
        /// SPHINCS+ signature by the owner over the canonical operation bytes.
        signature: Vec<u8>,
        mode: TransactionMode,
    },
    /// Attempt to unlock a vault by providing a fulfillment proof.
    DlvUnlock {
        /// 32-byte vault identifier.
        vault_id: Vec<u8>,
        /// Serialized FulfillmentProof bytes.
        fulfillment_proof: Vec<u8>,
        /// SPHINCS+ public key of the requester.
        requester_public_key: Vec<u8>,
        /// SPHINCS+ signature by the requester over canonical bytes.
        signature: Vec<u8>,
        /// Execution mode (Unilateral or Bilateral depending on mechanism).
        mode: TransactionMode,
    },
    /// Claim the content of an unlocked vault.
    DlvClaim {
        /// 32-byte vault identifier.
        vault_id: Vec<u8>,
        /// Claim proof binding (BLAKE3("DSM/dlv-claim\0" || ...)).
        claim_proof: Vec<u8>,
        /// SPHINCS+ public key of the claimant.
        claimant_public_key: Vec<u8>,
        /// SPHINCS+ signature by the claimant over canonical bytes.
        signature: Vec<u8>,
        /// Execution mode (typically Unilateral).
        mode: TransactionMode,
    },
    /// Invalidate a vault, returning any locked tokens to the creator.
    DlvInvalidate {
        /// 32-byte vault identifier.
        vault_id: Vec<u8>,
        /// Reason for invalidation.
        reason: String,
        /// SPHINCS+ public key of the vault creator.
        creator_public_key: Vec<u8>,
        /// SPHINCS+ signature by the creator over canonical bytes.
        signature: Vec<u8>,
        /// Execution mode (typically Unilateral).
        mode: TransactionMode,
    },
}

/// The bearer asset an egress operation moves, for the per-asset recovery spend-gate
/// (spec §0.4 P5). Produced by [`Operation::egress_asset`] — the canonical, exhaustive
/// companion to [`Operation::is_value_egress`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressAsset {
    /// Not a value-egress operation — no per-asset gate applies.
    NotEgress,
    /// Egress of a specific bearer asset (`token_id`) of `amount` units. `amount` is the
    /// egress quantity used for the `Reduced`-frontier cap; `u64::MAX` when an egress op
    /// cannot be sized (treated as exceeding any reduced frontier — fail-closed).
    Asset { token_id: Vec<u8>, amount: u64 },
    /// A value-egress operation whose canonical bearer-asset id cannot be determined
    /// (e.g. a vault-keyed DLV unlock/claim, or a tokenless DLV). The gate FAILS CLOSED on
    /// this whenever any recovery lock is present — it cannot prove the op avoids a locked
    /// asset. Per-vault resolution is a deferred refinement.
    Unidentified,
}

impl Operation {
    /// Classify whether this operation is owner-initiated **value egress** for
    /// the recovery spend-gate (spec condition R3).
    ///
    /// "Value egress" = an operation that moves the owner's existing value out of
    /// spendable balance or between value states (spend, burn, lock, unlock,
    /// vault create/unlock/claim/invalidate). While identity recovery is in
    /// progress these MUST be refused; otherwise the old and successor devices
    /// could both move the same pre-recovery value — the split-acceptance
    /// recovery double-spend (spec vector V1).
    ///
    /// Pure value *ingress* (receiving, minting) and identity / relationship /
    /// recovery / link / neutral operations are NOT egress and proceed normally — recovery itself must be able to advance, and
    /// receiving value can never create a double-spend of the owner's funds.
    ///
    /// The match is exhaustive (no wildcard): a new `Operation` variant will fail
    /// to compile until it is consciously classified here. This compile-time
    /// enumeration is the discipline behind spec condition R3 (no value-egress
    /// path may silently bypass the gate).
    pub fn is_value_egress(&self) -> bool {
        use Operation::*;
        match self {
            // Owner value egress / value-state movement of the owner's funds.
            Transfer { .. }
            | Burn { .. }
            | Lock { .. }
            | LockToken { .. }
            | Unlock { .. }
            | UnlockToken { .. }
            | DlvCreate { .. }
            | DlvUnlock { .. }
            | DlvClaim { .. }
            | DlvInvalidate { .. }
            // A settling trader pays its input out. Egress despite also
            // receiving the output: value leaves this device's control.
            | DlvSettle { .. }
            // The owner's apply moves the OUTPUT leg out of its vault reserves,
            // so it is egress too — even though the owner's spendable balance
            // is untouched and the operation authorizes no balance delta.
            | DlvOwnerApply { .. }
            // Token creation DESTROYS ERA to pay its fee, so it moves the
            // owner's existing funds outward — egress, despite also issuing a
            // new asset. Classifying it as ingress (as it was while nothing
            // constructed it) would let a create-with-fee bypass the recovery
            // egress gate and the per-asset bearer gate entirely.
            | CreateToken { .. } => true,

            // Not value egress: ingress (Receive / Mint), identity,
            // relationship, recovery, links, invalidation, generic, and no-op.
            Genesis
            | Create { .. }
            | Update { .. }
            | Mint { .. }
            | AddRelationship { .. }
            | CreateRelationship { .. }
            | RemoveRelationship { .. }
            | Recovery { .. }
            | Delete { .. }
            | Link { .. }
            | Unlink { .. }
            | Invalidate { .. }
            | Generic { .. }
            | Receive { .. }
            | Noop => false,
        }
    }

    /// Classify whether this operation is **value-bearing** — value moving in ANY
    /// direction (egress OR ingress) — for the recovery gate-set criterion (spec
    /// §0.5 step 6).
    ///
    /// A relationship is **value-capable** (and thus a recovery gate-set member) iff
    /// its posted state has accepted ≥1 value-bearing operation, OR its relationship
    /// policy independently marks it value-bearing (the policy branch is applied by
    /// the discovery layer, where policy is in scope). Pure contact/social
    /// relationships that never carried value are excluded from the gate-set.
    ///
    /// This is strictly broader than [`Self::is_value_egress`]: it ALSO counts value
    /// *ingress* (`Mint` / `Receive` / `CreateToken`), because a relationship that
    /// only ever received value still holds reconcilable value at recovery time and
    /// must be in the gate-set. Egress and ingress are kept in one classifier (egress
    /// via `is_value_egress`, plus the ingress arm here) so the two cannot drift.
    pub fn is_value_bearing(&self) -> bool {
        use Operation::*;
        if self.is_value_egress() {
            return true;
        }
        // Value ingress: receiving, minting, and token creation bring value INTO the
        // relationship without being egress. Everything else (identity, relationship,
        // recovery, links, invalidation, generic, no-op) is non-value.
        matches!(self, Mint { .. } | Receive { .. } | CreateToken { .. })
    }

    /// The bearer asset this operation egresses (spec §0.4 P5 per-asset spend-gate).
    ///
    /// EXHAUSTIVE companion to [`Self::is_value_egress`]: every egress variant yields either
    /// [`EgressAsset::Asset`] (a canonical `token_id` + egress amount) or
    /// [`EgressAsset::Unidentified`] (egress whose asset can't be named yet — vault-keyed
    /// DLV ops, tokenless DLV); every non-egress variant yields [`EgressAsset::NotEgress`].
    /// The invariant `is_value_egress() == !matches!(egress_asset(), NotEgress)` is tested.
    pub fn egress_asset(&self) -> EgressAsset {
        use Operation::*;
        match self {
            Transfer {
                token_id, amount, ..
            } => EgressAsset::Asset {
                token_id: token_id.clone(),
                amount: amount.value(),
            },
            Burn {
                token_id, amount, ..
            } => EgressAsset::Asset {
                token_id: token_id.clone(),
                amount: amount.value(),
            },
            Lock {
                token_id, amount, ..
            }
            | Unlock {
                token_id, amount, ..
            } => EgressAsset::Asset {
                token_id: token_id.clone(),
                amount: amount.value(),
            },
            LockToken {
                token_id, amount, ..
            }
            | UnlockToken {
                token_id, amount, ..
            } => {
                EgressAsset::Asset {
                    token_id: token_id.clone(),
                    // i64 lock/unlock quantity; clamp negatives to 0 (no canonical egress size).
                    amount: (*amount).max(0) as u64,
                }
            }
            // A token-bound DLV names its asset; a tokenless DLV cannot be sized → Unidentified.
            DlvCreate {
                token_id: Some(token_id),
                locked_amount,
                ..
            } => EgressAsset::Asset {
                token_id: token_id.clone(),
                amount: locked_amount
                    .as_ref()
                    .map(|b| b.value())
                    .unwrap_or(u64::MAX),
            },
            DlvCreate { token_id: None, .. } => EgressAsset::Unidentified,
            // Vault-keyed DLV ops: the asset is determined by the vault, not a token_id.
            DlvUnlock { .. } | DlvClaim { .. } | DlvInvalidate { .. } => EgressAsset::Unidentified,
            // Settlement names its asset exactly: the trader's INPUT leg is what
            // leaves. Unlike the vault-keyed ops above, this is not
            // `Unidentified` — the authorization carries the policy commit and
            // the amount, so the recovery egress gate can see precisely what
            // moved.
            DlvSettle {
                input_policy_commit,
                input_amount,
                ..
            } => EgressAsset::Asset {
                token_id: input_policy_commit.to_vec(),
                amount: *input_amount,
            },
            // The owner's OUTPUT leg leaves its reserves.
            DlvOwnerApply {
                output_policy_commit,
                output_amount,
                ..
            } => EgressAsset::Asset {
                token_id: output_policy_commit.to_vec(),
                amount: *output_amount,
            },

            // Token creation: the asset that LEAVES is ERA (the burned fee) —
            // NOT the new token, which is issued, not spent. Naming the new
            // token here would gate the wrong asset and leave the fee ungated.
            CreateToken { fee_amount, .. } => EgressAsset::Asset {
                token_id: b"ERA".to_vec(),
                amount: *fee_amount,
            },

            // Non-egress: ingress, identity, relationship, recovery, links, generic, no-op.
            Genesis
            | Create { .. }
            | Update { .. }
            | Mint { .. }
            | AddRelationship { .. }
            | CreateRelationship { .. }
            | RemoveRelationship { .. }
            | Recovery { .. }
            | Delete { .. }
            | Link { .. }
            | Unlink { .. }
            | Invalidate { .. }
            | Generic { .. }
            | Receive { .. }
            | Noop => EgressAsset::NotEgress,
        }
    }

    /// Canonical, deterministic encoding for cryptographic use.
    /// Encoding rules:
    /// - Variant tag: u8 fixed per variant below
    /// - Strings/bytes: u32 LE length prefix + raw bytes
    /// - `Vec<Vec<u8>>`: u32 count + each encoded as above
    /// - `Option<Vec<u8>>`: 1 byte tag (0/1) + payload when present
    /// - Balance: Balance::to_le_bytes() (fixed length canonical)
    pub fn to_bytes(&self) -> Vec<u8> {
        use Operation::*;
        let mut out = Vec::new();

        // helpers
        use crate::types::serialization::{put_bytes, put_str, put_u32, put_u64, put_u8};

        fn enc_mode(m: &TransactionMode) -> u8 {
            match m {
                TransactionMode::Bilateral => 0,
                TransactionMode::Unilateral => 1,
            }
        }
        fn put_mode(out: &mut Vec<u8>, m: &TransactionMode) {
            put_u8(out, enc_mode(m));
        }

        fn put_verification(out: &mut Vec<u8>, v: &VerificationType) {
            match v {
                VerificationType::Standard => put_u8(out, 0),
                VerificationType::Enhanced => put_u8(out, 1),
                VerificationType::Bilateral => put_u8(out, 2),
                VerificationType::Directory => put_u8(out, 3),
                VerificationType::StandardBilateral => put_u8(out, 4),
                VerificationType::PreCommitted => put_u8(out, 5),
                VerificationType::UnilateralIdentityAnchor => put_u8(out, 6),
                VerificationType::Custom(b) => {
                    put_u8(out, 255);
                    put_bytes(out, b);
                }
            }
        }

        fn put_vec_bytes(out: &mut Vec<u8>, v: &Vec<Vec<u8>>) {
            put_u32(out, v.len() as u32);
            for item in v {
                put_bytes(out, item);
            }
        }

        // PreCommitmentOp canonical encoding
        fn put_precommit_op(out: &mut Vec<u8>, pc: &PreCommitmentOp) {
            // fixed_parameters: sort by key
            let mut keys: Vec<_> = pc.fixed_parameters.keys().collect();
            keys.sort();
            put_u32(out, keys.len() as u32);
            for k in keys {
                put_str(out, k);
                if let Some(v) = pc.fixed_parameters.get(k) {
                    put_bytes(out, v);
                } else {
                    put_u32(out, 0);
                }
            }
            // variable_parameters: already Vec<String>; encode in lexicographic order for determinism
            let mut vars = pc.variable_parameters.clone();
            vars.sort();
            put_u32(out, vars.len() as u32);
            for v in vars {
                put_str(out, &v);
            }
            // Note: security_params intentionally not included in canonical op bytes
        }

        match self {
            Genesis => {
                put_u8(&mut out, 0);
            }
            Create {
                message,
                identity_data,
                public_key,
                metadata,
                commitment,
                proof,
                mode,
            } => {
                put_u8(&mut out, 1);
                put_str(&mut out, message);
                put_bytes(&mut out, identity_data);
                put_bytes(&mut out, public_key);
                put_bytes(&mut out, metadata);
                put_bytes(&mut out, commitment);
                put_bytes(&mut out, proof);
                put_mode(&mut out, mode);
            }
            Update {
                message,
                identity_id,
                updated_data,
                proof,
                forward_link,
            } => {
                put_u8(&mut out, 2);
                put_str(&mut out, message);
                put_bytes(&mut out, identity_id);
                put_bytes(&mut out, updated_data);
                put_bytes(&mut out, proof);
                match forward_link {
                    Some(b) => {
                        put_u8(&mut out, 1);
                        put_bytes(&mut out, b);
                    }
                    None => put_u8(&mut out, 0),
                }
            }
            Transfer {
                to_device_id,
                amount,
                token_id,
                policy_commit,
                mode,
                nonce,
                verification,
                pre_commit,
                recipient,
                to,
                message,
                signature,
                authority_policy,
            } => {
                put_u8(&mut out, 3);
                put_bytes(&mut out, to_device_id);
                // Balance canonical
                let bal = amount.to_le_bytes();
                put_bytes(&mut out, &bal);
                put_bytes(&mut out, token_id);
                // CPTA policy commitment (§9.5) — bound into the signed bytes.
                put_bytes(&mut out, policy_commit);
                put_mode(&mut out, mode);
                put_bytes(&mut out, nonce);
                put_verification(&mut out, verification);
                match pre_commit {
                    Some(pc) => {
                        put_u8(&mut out, 1);
                        put_precommit_op(&mut out, pc);
                    }
                    None => put_u8(&mut out, 0),
                }
                put_bytes(&mut out, recipient);
                put_bytes(&mut out, to);
                put_str(&mut out, message.as_str());
                // Sender signature (online) or empty for bilateral (signatures in receipt)
                put_bytes(&mut out, signature);
                // Append-only authority-policy tail: None emits NOTHING (byte-identical to every
                // prior encoding / state hash); Some appends the versioned canonical policy. This
                // binds the offline-bearer requirement into op_bytes -> the successor tip, BEFORE
                // the intent challenge, UI transcript, signing, and tip computation.
                if let Some(ap) = authority_policy {
                    ap.append_canonical(&mut out);
                }
            }
            Mint {
                amount,
                token_id,
                policy_commit,
                authorized_by,
                proof_of_authorization,
                message,
            } => {
                put_u8(&mut out, 4);
                let bal = amount.to_le_bytes();
                put_bytes(&mut out, &bal);
                put_bytes(&mut out, token_id);
                // CPTA policy commitment — same length-prefixed convention as Transfer.
                put_bytes(&mut out, policy_commit);
                put_bytes(&mut out, authorized_by);
                put_bytes(&mut out, proof_of_authorization);
                put_str(&mut out, message);
            }
            Burn {
                amount,
                token_id,
                policy_commit,
                proof_of_ownership,
                message,
            } => {
                put_u8(&mut out, 5);
                let bal = amount.to_le_bytes();
                put_bytes(&mut out, &bal);
                put_bytes(&mut out, token_id);
                put_bytes(&mut out, policy_commit);
                put_bytes(&mut out, proof_of_ownership);
                put_str(&mut out, message);
            }
            LockToken {
                token_id,
                amount,
                purpose,
                mode,
                signature,
            } => {
                put_u8(&mut out, 6);
                put_bytes(&mut out, token_id);
                put_u64(&mut out, *amount as u64);
                put_bytes(&mut out, purpose);
                put_mode(&mut out, mode);
                put_bytes(&mut out, signature);
            }
            UnlockToken {
                token_id,
                amount,
                purpose,
                mode,
                signature,
            } => {
                put_u8(&mut out, 7);
                put_bytes(&mut out, token_id);
                put_u64(&mut out, *amount as u64);
                put_bytes(&mut out, purpose);
                put_mode(&mut out, mode);
                put_bytes(&mut out, signature);
            }
            Lock {
                token_id,
                amount,
                purpose,
                owner,
                message,
                signature,
            } => {
                put_u8(&mut out, 8);
                put_bytes(&mut out, token_id);
                let bal = amount.to_le_bytes();
                put_bytes(&mut out, &bal);
                put_bytes(&mut out, purpose);
                put_bytes(&mut out, owner);
                put_str(&mut out, message.as_str());
                put_bytes(&mut out, signature);
            }
            Unlock {
                token_id,
                amount,
                purpose,
                owner,
                message,
                signature,
            } => {
                put_u8(&mut out, 9);
                put_bytes(&mut out, token_id);
                let bal = amount.to_le_bytes();
                put_bytes(&mut out, &bal);
                put_bytes(&mut out, purpose);
                put_bytes(&mut out, owner);
                put_str(&mut out, message.as_str());
                put_bytes(&mut out, signature);
            }
            AddRelationship {
                from_id,
                to_id,
                relationship_type,
                metadata,
                proof,
                mode,
                message,
            } => {
                put_u8(&mut out, 10);
                put_bytes(&mut out, from_id);
                put_bytes(&mut out, to_id);
                put_bytes(&mut out, relationship_type);
                put_bytes(&mut out, metadata);
                put_bytes(&mut out, proof);
                put_mode(&mut out, mode);
                put_str(&mut out, message);
            }
            CreateRelationship {
                message,
                counterparty_id,
                commitment,
                proof,
                mode,
            } => {
                put_u8(&mut out, 11);
                put_str(&mut out, message);
                put_bytes(&mut out, counterparty_id);
                put_bytes(&mut out, commitment);
                put_bytes(&mut out, proof);
                put_mode(&mut out, mode);
            }
            RemoveRelationship {
                from_id,
                to_id,
                relationship_type,
                proof,
                mode,
                message,
            } => {
                put_u8(&mut out, 12);
                put_bytes(&mut out, from_id);
                put_bytes(&mut out, to_id);
                put_bytes(&mut out, relationship_type);
                put_bytes(&mut out, proof);
                put_mode(&mut out, mode);
                put_str(&mut out, message);
            }
            Recovery {
                message,
                state_number,
                state_hash,
                state_entropy,
                invalidation_data,
                new_state_data,
                new_state_number,
                new_state_hash,
                new_state_entropy,
                compromise_proof,
                authority_sigs,
            } => {
                put_u8(&mut out, 13);
                put_str(&mut out, message);
                put_u64(&mut out, *state_number);
                put_bytes(&mut out, state_hash);
                put_bytes(&mut out, state_entropy);
                put_bytes(&mut out, invalidation_data);
                put_bytes(&mut out, new_state_data);
                put_u64(&mut out, *new_state_number);
                put_bytes(&mut out, new_state_hash);
                put_bytes(&mut out, new_state_entropy);
                put_bytes(&mut out, compromise_proof);
                put_vec_bytes(&mut out, authority_sigs);
            }
            Delete {
                reason,
                proof,
                mode,
                id,
            } => {
                put_u8(&mut out, 14);
                put_str(&mut out, reason);
                put_bytes(&mut out, proof);
                put_mode(&mut out, mode);
                put_bytes(&mut out, id);
            }
            Link {
                target_id,
                link_type,
                proof,
                mode,
            } => {
                put_u8(&mut out, 15);
                put_bytes(&mut out, target_id);
                put_bytes(&mut out, link_type);
                put_bytes(&mut out, proof);
                put_mode(&mut out, mode);
            }
            Unlink {
                target_id,
                proof,
                mode,
            } => {
                put_u8(&mut out, 16);
                put_bytes(&mut out, target_id);
                put_bytes(&mut out, proof);
                put_mode(&mut out, mode);
            }
            Invalidate {
                reason,
                proof,
                mode,
            } => {
                put_u8(&mut out, 17);
                put_str(&mut out, reason);
                put_bytes(&mut out, proof);
                put_mode(&mut out, mode);
            }
            Generic {
                operation_type,
                data,
                message,
                signature,
            } => {
                put_u8(&mut out, 18);
                put_bytes(&mut out, operation_type);
                put_bytes(&mut out, data);
                put_str(&mut out, message);
                put_bytes(&mut out, signature);
            }
            Receive {
                token_id,
                from_device_id,
                amount,
                recipient,
                message,
                mode,
                nonce,
                verification,
                sender_state_hash,
            } => {
                put_u8(&mut out, 19);
                put_bytes(&mut out, token_id);
                put_bytes(&mut out, from_device_id);
                let bal = amount.to_le_bytes();
                put_bytes(&mut out, &bal);
                put_bytes(&mut out, recipient);
                put_str(&mut out, message);
                put_mode(&mut out, mode);
                put_bytes(&mut out, nonce);
                put_verification(&mut out, verification);
                match sender_state_hash {
                    Some(h) => {
                        put_u8(&mut out, 1);
                        put_bytes(&mut out, h);
                    }
                    None => put_u8(&mut out, 0),
                }
            }
            CreateToken {
                token_id,
                initial_supply,
                policy_commit,
                fee_amount,
                name,
                symbol,
                decimals,
                metadata_uri,
                signature,
            } => {
                put_u8(&mut out, 20);
                put_bytes(&mut out, token_id);
                let bal = initial_supply.to_le_bytes();
                put_bytes(&mut out, &bal);
                // Mandatory now: the issued asset and the ERA destroyed for it
                // are both part of what gets signed.
                put_bytes(&mut out, policy_commit);
                put_u64(&mut out, *fee_amount);
                put_str(&mut out, name);
                put_str(&mut out, symbol);
                put_u8(&mut out, *decimals);
                match metadata_uri {
                    Some(u) => {
                        put_u8(&mut out, 1);
                        put_str(&mut out, u);
                    }
                    None => put_u8(&mut out, 0),
                }
                put_bytes(&mut out, signature);
            }
            Noop => {
                put_u8(&mut out, 21);
            }
            DlvCreate {
                vault_id,
                creator_public_key,
                parameters_hash,
                fulfillment_condition,
                intended_recipient,
                token_id,
                locked_amount,
                signature,
                mode,
            } => {
                put_u8(&mut out, 22);
                put_bytes(&mut out, vault_id);
                put_bytes(&mut out, creator_public_key);
                put_bytes(&mut out, parameters_hash);
                put_bytes(&mut out, fulfillment_condition);
                match intended_recipient {
                    Some(r) => {
                        put_u8(&mut out, 1);
                        put_bytes(&mut out, r);
                    }
                    None => put_u8(&mut out, 0),
                }
                match token_id {
                    Some(t) => {
                        put_u8(&mut out, 1);
                        put_bytes(&mut out, t);
                    }
                    None => put_u8(&mut out, 0),
                }
                match locked_amount {
                    Some(a) => {
                        put_u8(&mut out, 1);
                        let bal = a.to_le_bytes();
                        put_bytes(&mut out, &bal);
                    }
                    None => put_u8(&mut out, 0),
                }
                put_bytes(&mut out, signature);
                put_mode(&mut out, mode);
            }
            DlvUnlock {
                vault_id,
                fulfillment_proof,
                requester_public_key,
                signature,
                mode,
            } => {
                put_u8(&mut out, 23);
                put_bytes(&mut out, vault_id);
                put_bytes(&mut out, fulfillment_proof);
                put_bytes(&mut out, requester_public_key);
                put_bytes(&mut out, signature);
                put_mode(&mut out, mode);
            }
            DlvClaim {
                vault_id,
                claim_proof,
                claimant_public_key,
                signature,
                mode,
            } => {
                put_u8(&mut out, 24);
                put_bytes(&mut out, vault_id);
                put_bytes(&mut out, claim_proof);
                put_bytes(&mut out, claimant_public_key);
                put_bytes(&mut out, signature);
                put_mode(&mut out, mode);
            }
            DlvInvalidate {
                vault_id,
                reason,
                creator_public_key,
                signature,
                mode,
            } => {
                put_u8(&mut out, 25);
                put_bytes(&mut out, vault_id);
                put_str(&mut out, reason);
                put_bytes(&mut out, creator_public_key);
                put_bytes(&mut out, signature);
                put_mode(&mut out, mode);
            }
            // Every authorization field is in the canonical bytes, so the
            // settler's signature covers all of it and none can be swapped
            // after signing.
            DlvSettle {
                vault_id,
                owner_public_key,
                owner_devid,
                owner_genesis,
                input_policy_commit,
                output_policy_commit,
                parent_sequence,
                parent_reserves_digest,
                reserve_proof_root,
                predicate_digest,
                route_commit_bytes,
                external_commitment_x,
                input_amount,
                output_amount,
                fee_bps,
                sigma,
                settler_public_key,
                settler_devid,
                settlement_receipt_id,
                signature,
                mode,
            } => {
                put_u8(&mut out, 26);
                put_bytes(&mut out, vault_id);
                put_bytes(&mut out, owner_public_key);
                put_bytes(&mut out, owner_devid);
                put_bytes(&mut out, owner_genesis);
                put_bytes(&mut out, input_policy_commit);
                put_bytes(&mut out, output_policy_commit);
                put_u64(&mut out, *parent_sequence);
                put_bytes(&mut out, parent_reserves_digest);
                put_bytes(&mut out, reserve_proof_root);
                put_bytes(&mut out, predicate_digest);
                put_bytes(&mut out, route_commit_bytes);
                put_bytes(&mut out, external_commitment_x);
                put_u64(&mut out, *input_amount);
                put_u64(&mut out, *output_amount);
                put_u32(&mut out, *fee_bps);
                put_bytes(&mut out, sigma);
                put_bytes(&mut out, settler_public_key);
                put_bytes(&mut out, settler_devid);
                put_bytes(&mut out, settlement_receipt_id);
                put_bytes(&mut out, signature);
                put_mode(&mut out, mode);
            }
            DlvOwnerApply {
                vault_id,
                settlement_receipt_id,
                pending_pointer_x,
                parent_sequence,
                new_sequence,
                parent_reserves_digest,
                new_reserves_digest,
                input_policy_commit,
                output_policy_commit,
                input_amount,
                output_amount,
                signature,
                mode,
            } => {
                put_u8(&mut out, 27);
                put_bytes(&mut out, vault_id);
                put_bytes(&mut out, settlement_receipt_id);
                put_bytes(&mut out, pending_pointer_x);
                put_u64(&mut out, *parent_sequence);
                put_u64(&mut out, *new_sequence);
                put_bytes(&mut out, parent_reserves_digest);
                put_bytes(&mut out, new_reserves_digest);
                put_bytes(&mut out, input_policy_commit);
                put_bytes(&mut out, output_policy_commit);
                put_u64(&mut out, *input_amount);
                put_u64(&mut out, *output_amount);
                put_bytes(&mut out, signature);
                put_mode(&mut out, mode);
            }
        }

        out
    }

    /// Canonical decoder that mirrors `to_bytes`.
    /// Accepts the exact bytes produced by `to_bytes()` and reconstructs the Operation.
    /// Returns Err when decoding fails or bytes are malformed.
    pub fn from_bytes(mut input: &[u8]) -> Result<Self, DsmError> {
        use Operation::*;
        // helpers
        fn take<'a>(inp: &mut &'a [u8], n: usize) -> Result<&'a [u8], DsmError> {
            if inp.len() < n {
                return Err(DsmError::serialization_error(
                    "operation.decode",
                    "bytes",
                    Some("short input"),
                    None::<std::io::Error>,
                ));
            }
            let (head, rest) = inp.split_at(n);
            *inp = rest;
            Ok(head)
        }
        fn get_u8(inp: &mut &[u8]) -> Result<u8, DsmError> {
            Ok(take(inp, 1)?[0])
        }
        fn get_u32(inp: &mut &[u8]) -> Result<u32, DsmError> {
            let mut a = [0u8; 4];
            a.copy_from_slice(take(inp, 4)?);
            Ok(u32::from_le_bytes(a))
        }
        fn get_u64(inp: &mut &[u8]) -> Result<u64, DsmError> {
            let mut a = [0u8; 8];
            a.copy_from_slice(take(inp, 8)?);
            Ok(u64::from_le_bytes(a))
        }
        fn get_len_bytes<'a>(inp: &mut &'a [u8]) -> Result<&'a [u8], DsmError> {
            let len = get_u32(inp)? as usize;
            take(inp, len)
        }
        /// A length-prefixed field that must be exactly 32 bytes.
        ///
        /// The encoder writes these through `put_bytes`, so the wire carries a
        /// length. Requiring 32 on the way back keeps a short field from
        /// silently becoming a zero-padded commit that names a different asset.
        fn get_arr32(inp: &mut &[u8]) -> Result<[u8; 32], DsmError> {
            let v = get_bytes(inp)?;
            <[u8; 32]>::try_from(v.as_slice())
                .map_err(|_| DsmError::invalid_operation("expected a 32-byte field"))
        }

        fn get_bytes(inp: &mut &[u8]) -> Result<Vec<u8>, DsmError> {
            Ok(get_len_bytes(inp)?.to_vec())
        }
        fn get_str(inp: &mut &[u8]) -> Result<String, DsmError> {
            let b = get_len_bytes(inp)?;
            std::str::from_utf8(b).map(|s| s.to_string()).map_err(|e| {
                DsmError::serialization_error(
                    "operation.decode",
                    "string",
                    Some(e.to_string()),
                    None::<std::io::Error>,
                )
            })
        }

        fn dec_mode(inp: &mut &[u8]) -> Result<TransactionMode, DsmError> {
            match get_u8(inp)? {
                0 => Ok(TransactionMode::Bilateral),
                1 => Ok(TransactionMode::Unilateral),
                _ => Err(DsmError::invalid_operation("bad mode")),
            }
        }
        fn dec_verification(inp: &mut &[u8]) -> Result<VerificationType, DsmError> {
            Ok(match get_u8(inp)? {
                0 => VerificationType::Standard,
                1 => VerificationType::Enhanced,
                2 => VerificationType::Bilateral,
                3 => VerificationType::Directory,
                4 => VerificationType::StandardBilateral,
                5 => VerificationType::PreCommitted,
                6 => VerificationType::UnilateralIdentityAnchor,
                255 => {
                    let b = get_bytes(inp)?;
                    VerificationType::Custom(b)
                }
                _ => return Err(DsmError::invalid_operation("bad verification tag")),
            })
        }
        fn dec_vec_bytes(inp: &mut &[u8]) -> Result<Vec<Vec<u8>>, DsmError> {
            let n = get_u32(inp)? as usize;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                v.push(get_bytes(inp)?);
            }
            Ok(v)
        }
        // Balance decoding: mirror `Balance::to_le_bytes()` wrapped by a length prefix in to_bytes
        fn dec_balance(inp: &mut &[u8]) -> Result<Balance, DsmError> {
            let blob = get_bytes(inp)?; // length-prefixed canonical balance bytes
            let mut cur: &[u8] = &blob;
            let value = {
                let mut a = [0u8; 8];
                a.copy_from_slice(take(&mut cur, 8)?);
                u64::from_le_bytes(a)
            };
            let locked = {
                let mut a = [0u8; 8];
                a.copy_from_slice(take(&mut cur, 8)?);
                u64::from_le_bytes(a)
            };
            // Per §4.3 no counter is part of canonical Balance encoding.
            let state_hash = if !cur.is_empty() {
                if cur.len() != 32 {
                    return Err(DsmError::SerializationError(
                        "Invalid state hash length".into(),
                    ));
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(cur);
                Some(h)
            } else {
                None
            };
            Ok(Balance::from_parts(value, locked, state_hash))
        }
        #[allow(dead_code)]
        fn dec_option_bytes(inp: &mut &[u8]) -> Result<Option<Vec<u8>>, DsmError> {
            match get_u8(inp)? {
                0 => Ok(None),
                1 => Ok(Some(get_bytes(inp)?)),
                _ => Err(DsmError::invalid_operation("bad opt tag")),
            }
        }
        fn dec_precommit_op(inp: &mut &[u8]) -> Result<PreCommitmentOp, DsmError> {
            // fixed_parameters
            let mut fixed = HashMap::new();
            let cnt = get_u32(inp)? as usize;
            for _ in 0..cnt {
                let k = get_str(inp)?;
                let v = get_bytes(inp)?;
                fixed.insert(k, v);
            }
            // variable_parameters (encoded sorted; here we just read in order)
            let vcnt = get_u32(inp)? as usize;
            let mut vars = Vec::with_capacity(vcnt);
            for _ in 0..vcnt {
                vars.push(get_str(inp)?);
            }
            Ok(PreCommitmentOp {
                fixed_parameters: fixed,
                variable_parameters: vars,
                security_params: SecurityParameters::default(),
            })
        }

        let tag = get_u8(&mut input)?;
        let op = match tag {
            0 => Genesis,
            1 => {
                let message = get_str(&mut input)?;
                let identity_data = get_bytes(&mut input)?;
                let public_key = get_bytes(&mut input)?;
                let metadata = get_bytes(&mut input)?;
                let commitment = get_bytes(&mut input)?;
                let proof = get_bytes(&mut input)?;
                let mode = dec_mode(&mut input)?;
                Create {
                    message,
                    identity_data,
                    public_key,
                    metadata,
                    commitment,
                    proof,
                    mode,
                }
            }
            2 => {
                let message = get_str(&mut input)?;
                let identity_id = get_bytes(&mut input)?;
                let updated_data = get_bytes(&mut input)?;
                let proof = get_bytes(&mut input)?;
                let forward_link = match get_u8(&mut input)? {
                    0 => None,
                    1 => Some(get_bytes(&mut input)?),
                    _ => return Err(DsmError::invalid_operation("bad opt flag")),
                };
                Update {
                    message,
                    identity_id,
                    updated_data,
                    proof,
                    forward_link,
                }
            }
            3 => {
                let to_device_id = get_bytes(&mut input)?;
                let amount = dec_balance(&mut input)?;
                let token_id = get_bytes(&mut input)?;
                // CPTA policy commitment (§9.5) — required, exactly 32 bytes.
                let policy_commit: [u8; 32] =
                    get_bytes(&mut input)?.as_slice().try_into().map_err(|_| {
                        DsmError::invalid_operation("transfer policy_commit must be 32 bytes")
                    })?;
                let mode = dec_mode(&mut input)?;
                let nonce = get_bytes(&mut input)?;
                let verification = dec_verification(&mut input)?;
                let pre_commit = match get_u8(&mut input)? {
                    0 => None,
                    1 => Some(dec_precommit_op(&mut input)?),
                    _ => return Err(DsmError::invalid_operation("bad opt flag")),
                };
                let recipient = get_bytes(&mut input)?;
                let to = get_bytes(&mut input)?;
                let message = get_str(&mut input)?;
                // Signature: try to read if available; empty if not present (backwards compat)
                let signature = if input.is_empty() {
                    vec![]
                } else {
                    get_bytes(&mut input)?
                };
                // Append-only authority-policy tail (symmetric with
                // `AuthorityPolicy::append_canonical`). Absent (no remaining bytes) => None, so
                // every pre-existing transfer round-trips byte-identically; present => the
                // versioned policy.
                let authority_policy = if input.is_empty() {
                    None
                } else {
                    let tag = get_u8(&mut input)?;
                    if tag != AUTHORITY_POLICY_TAG_V1 {
                        return Err(DsmError::invalid_operation("unknown authority_policy tag"));
                    }
                    let mode = match get_u8(&mut input)? {
                        0 => AuthorityMode::OnlineChecked,
                        1 => AuthorityMode::OfflineBearerRequired,
                        _ => return Err(DsmError::invalid_operation("bad authority_policy mode")),
                    };
                    let policy_id: [u8; 32] =
                        get_bytes(&mut input)?.as_slice().try_into().map_err(|_| {
                            DsmError::invalid_operation(
                                "authority_policy policy_id must be 32 bytes",
                            )
                        })?;
                    let anchor_set_id: [u8; 32] =
                        get_bytes(&mut input)?.as_slice().try_into().map_err(|_| {
                            DsmError::invalid_operation(
                                "authority_policy anchor_set_id must be 32 bytes",
                            )
                        })?;
                    Some(AuthorityPolicy {
                        mode,
                        policy_id,
                        anchor_set_id,
                    })
                };
                Transfer {
                    to_device_id,
                    amount,
                    token_id,
                    policy_commit,
                    mode,
                    nonce,
                    verification,
                    pre_commit,
                    recipient,
                    to,
                    message,
                    signature,
                    authority_policy,
                }
            }
            4 => {
                let amount = dec_balance(&mut input)?;
                let token_id = get_bytes(&mut input)?;
                let policy_commit: [u8; 32] =
                    get_bytes(&mut input)?.as_slice().try_into().map_err(|_| {
                        DsmError::invalid_operation("mint policy_commit must be 32 bytes")
                    })?;
                let authorized_by = get_bytes(&mut input)?;
                let proof_of_authorization = get_bytes(&mut input)?;
                let message = get_str(&mut input)?;
                Mint {
                    amount,
                    token_id,
                    policy_commit,
                    authorized_by,
                    proof_of_authorization,
                    message,
                }
            }
            5 => {
                let amount = dec_balance(&mut input)?;
                let token_id = get_bytes(&mut input)?;
                let policy_commit: [u8; 32] =
                    get_bytes(&mut input)?.as_slice().try_into().map_err(|_| {
                        DsmError::invalid_operation("burn policy_commit must be 32 bytes")
                    })?;
                let proof_of_ownership = get_bytes(&mut input)?;
                let message = get_str(&mut input)?;
                Burn {
                    amount,
                    token_id,
                    policy_commit,
                    proof_of_ownership,
                    message,
                }
            }
            6 => {
                let token_id = get_bytes(&mut input)?;
                let amount = get_u64(&mut input)? as i64;
                let purpose = get_bytes(&mut input)?;
                let mode = dec_mode(&mut input)?;
                let signature = if input.is_empty() {
                    vec![]
                } else {
                    get_bytes(&mut input)?
                };
                LockToken {
                    token_id,
                    amount,
                    purpose,
                    mode,
                    signature,
                }
            }
            7 => {
                let token_id = get_bytes(&mut input)?;
                let amount = get_u64(&mut input)? as i64;
                let purpose = get_bytes(&mut input)?;
                let mode = dec_mode(&mut input)?;
                let signature = if input.is_empty() {
                    vec![]
                } else {
                    get_bytes(&mut input)?
                };
                UnlockToken {
                    token_id,
                    amount,
                    purpose,
                    mode,
                    signature,
                }
            }
            8 => {
                let token_id = get_bytes(&mut input)?;
                let amount = dec_balance(&mut input)?;
                let purpose = get_bytes(&mut input)?;
                let owner = get_bytes(&mut input)?;
                let message = get_str(&mut input)?;
                let signature = if input.is_empty() {
                    vec![]
                } else {
                    get_bytes(&mut input)?
                };
                Lock {
                    token_id,
                    amount,
                    purpose,
                    owner,
                    message,
                    signature,
                }
            }
            9 => {
                let token_id = get_bytes(&mut input)?;
                let amount = dec_balance(&mut input)?;
                let purpose = get_bytes(&mut input)?;
                let owner = get_bytes(&mut input)?;
                let message = get_str(&mut input)?;
                let signature = if input.is_empty() {
                    vec![]
                } else {
                    get_bytes(&mut input)?
                };
                Unlock {
                    token_id,
                    amount,
                    purpose,
                    owner,
                    message,
                    signature,
                }
            }
            10 => {
                let from_id_bytes = get_bytes(&mut input)?;
                let to_id_bytes = get_bytes(&mut input)?;
                let from_id: [u8; 32] = from_id_bytes.try_into().map_err(|_| {
                    DsmError::serialization_error(
                        "operation.decode",
                        "from_id",
                        Some("invalid length".to_string()),
                        None::<std::io::Error>,
                    )
                })?;
                let to_id: [u8; 32] = to_id_bytes.try_into().map_err(|_| {
                    DsmError::serialization_error(
                        "operation.decode",
                        "to_id",
                        Some("invalid length".to_string()),
                        None::<std::io::Error>,
                    )
                })?;
                let relationship_type = get_bytes(&mut input)?;
                let metadata = get_bytes(&mut input)?;
                let proof = get_bytes(&mut input)?;
                let mode = dec_mode(&mut input)?;
                let message = get_str(&mut input)?;
                AddRelationship {
                    from_id,
                    to_id,
                    relationship_type,
                    metadata,
                    proof,
                    mode,
                    message,
                }
            }
            11 => {
                let message = get_str(&mut input)?;
                let counterparty_id = get_bytes(&mut input)?;
                let commitment = get_bytes(&mut input)?;
                let proof = get_bytes(&mut input)?;
                let mode = dec_mode(&mut input)?;
                CreateRelationship {
                    message,
                    counterparty_id,
                    commitment,
                    proof,
                    mode,
                }
            }
            12 => {
                let from_id_bytes = get_bytes(&mut input)?;
                let to_id_bytes = get_bytes(&mut input)?;
                let from_id: [u8; 32] = from_id_bytes.try_into().map_err(|_| {
                    DsmError::serialization_error(
                        "operation.decode",
                        "from_id",
                        Some("invalid length".to_string()),
                        None::<std::io::Error>,
                    )
                })?;
                let to_id: [u8; 32] = to_id_bytes.try_into().map_err(|_| {
                    DsmError::serialization_error(
                        "operation.decode",
                        "to_id",
                        Some("invalid length".to_string()),
                        None::<std::io::Error>,
                    )
                })?;
                let relationship_type = get_bytes(&mut input)?;
                let proof = get_bytes(&mut input)?;
                let mode = dec_mode(&mut input)?;
                let message = get_str(&mut input)?;
                RemoveRelationship {
                    from_id,
                    to_id,
                    relationship_type,
                    proof,
                    mode,
                    message,
                }
            }
            13 => {
                let message = get_str(&mut input)?;
                let state_number = get_u64(&mut input)?;
                let state_hash = get_bytes(&mut input)?;
                let state_entropy = get_bytes(&mut input)?;
                let invalidation_data = get_bytes(&mut input)?;
                let new_state_data = get_bytes(&mut input)?;
                let new_state_number = get_u64(&mut input)?;
                let new_state_hash = get_bytes(&mut input)?;
                let new_state_entropy = get_bytes(&mut input)?;
                let compromise_proof = get_bytes(&mut input)?;
                let authority_sigs = dec_vec_bytes(&mut input)?;
                Recovery {
                    message,
                    state_number,
                    state_hash,
                    state_entropy,
                    invalidation_data,
                    new_state_data,
                    new_state_number,
                    new_state_hash,
                    new_state_entropy,
                    compromise_proof,
                    authority_sigs,
                }
            }
            14 => {
                let reason = get_str(&mut input)?;
                let proof = get_bytes(&mut input)?;
                let mode = dec_mode(&mut input)?;
                let id = get_bytes(&mut input)?;
                Delete {
                    reason,
                    proof,
                    mode,
                    id,
                }
            }
            15 => {
                let target_id = get_bytes(&mut input)?;
                let link_type = get_bytes(&mut input)?;
                let proof = get_bytes(&mut input)?;
                let mode = dec_mode(&mut input)?;
                Link {
                    target_id,
                    link_type,
                    proof,
                    mode,
                }
            }
            16 => {
                let target_id = get_bytes(&mut input)?;
                let proof = get_bytes(&mut input)?;
                let mode = dec_mode(&mut input)?;
                Unlink {
                    target_id,
                    proof,
                    mode,
                }
            }
            17 => {
                let reason = get_str(&mut input)?;
                let proof = get_bytes(&mut input)?;
                let mode = dec_mode(&mut input)?;
                Invalidate {
                    reason,
                    proof,
                    mode,
                }
            }
            18 => {
                let operation_type = get_bytes(&mut input)?;
                let data = get_bytes(&mut input)?;
                let message = get_str(&mut input)?;
                let signature = if input.is_empty() {
                    vec![]
                } else {
                    get_bytes(&mut input)?
                };
                Generic {
                    operation_type,
                    data,
                    message,
                    signature,
                }
            }
            19 => {
                let token_id = get_bytes(&mut input)?;
                let from_device_id = get_bytes(&mut input)?;
                let amount = dec_balance(&mut input)?;
                let recipient = get_bytes(&mut input)?;
                let message = get_str(&mut input)?;
                let mode = dec_mode(&mut input)?;
                let nonce = get_bytes(&mut input)?;
                let verification = dec_verification(&mut input)?;
                let sender_state_hash = match get_u8(&mut input)? {
                    0 => None,
                    1 => Some(get_bytes(&mut input)?),
                    _ => return Err(DsmError::invalid_operation("bad opt flag")),
                };
                Receive {
                    token_id,
                    from_device_id,
                    amount,
                    recipient,
                    message,
                    mode,
                    nonce,
                    verification,
                    sender_state_hash,
                }
            }
            20 => {
                let token_id = get_bytes(&mut input)?;
                let initial_supply = dec_balance(&mut input)?;
                let policy_commit: [u8; 32] =
                    get_bytes(&mut input)?.as_slice().try_into().map_err(|_| {
                        DsmError::invalid_operation("create-token policy_commit must be 32 bytes")
                    })?;
                let fee_amount = get_u64(&mut input)?;
                let name = get_str(&mut input)?;
                let symbol = get_str(&mut input)?;
                let decimals = get_u8(&mut input)?;
                let metadata_uri = match get_u8(&mut input)? {
                    0 => None,
                    1 => Some(get_str(&mut input)?),
                    _ => return Err(DsmError::invalid_operation("bad opt flag")),
                };
                let signature = if input.is_empty() {
                    vec![]
                } else {
                    get_bytes(&mut input)?
                };
                CreateToken {
                    token_id,
                    initial_supply,
                    policy_commit,
                    fee_amount,
                    name,
                    symbol,
                    decimals,
                    metadata_uri,
                    signature,
                }
            }
            21 => Noop,
            22 => {
                let vault_id = get_bytes(&mut input)?;
                let creator_public_key = get_bytes(&mut input)?;
                let parameters_hash = get_bytes(&mut input)?;
                let fulfillment_condition = get_bytes(&mut input)?;
                let intended_recipient = match get_u8(&mut input)? {
                    0 => None,
                    1 => Some(get_bytes(&mut input)?),
                    _ => return Err(DsmError::invalid_operation("bad opt flag")),
                };
                let token_id = match get_u8(&mut input)? {
                    0 => None,
                    1 => Some(get_bytes(&mut input)?),
                    _ => return Err(DsmError::invalid_operation("bad opt flag")),
                };
                let locked_amount = match get_u8(&mut input)? {
                    0 => None,
                    1 => Some(dec_balance(&mut input)?),
                    _ => return Err(DsmError::invalid_operation("bad opt flag")),
                };
                let signature = get_bytes(&mut input)?;
                let mode = dec_mode(&mut input)?;
                DlvCreate {
                    vault_id,
                    creator_public_key,
                    parameters_hash,
                    fulfillment_condition,
                    intended_recipient,
                    token_id,
                    locked_amount,
                    signature,
                    mode,
                }
            }
            23 => {
                let vault_id = get_bytes(&mut input)?;
                let fulfillment_proof = get_bytes(&mut input)?;
                let requester_public_key = get_bytes(&mut input)?;
                let signature = get_bytes(&mut input)?;
                let mode = dec_mode(&mut input)?;
                DlvUnlock {
                    vault_id,
                    fulfillment_proof,
                    requester_public_key,
                    signature,
                    mode,
                }
            }
            24 => {
                let vault_id = get_bytes(&mut input)?;
                let claim_proof = get_bytes(&mut input)?;
                let claimant_public_key = get_bytes(&mut input)?;
                let signature = get_bytes(&mut input)?;
                let mode = dec_mode(&mut input)?;
                DlvClaim {
                    vault_id,
                    claim_proof,
                    claimant_public_key,
                    signature,
                    mode,
                }
            }
            25 => {
                let vault_id = get_bytes(&mut input)?;
                let reason = get_str(&mut input)?;
                let creator_public_key = get_bytes(&mut input)?;
                let signature = get_bytes(&mut input)?;
                let mode = dec_mode(&mut input)?;
                DlvInvalidate {
                    vault_id,
                    reason,
                    creator_public_key,
                    signature,
                    mode,
                }
            }
            // Mirrors the encode order exactly. A decoder that drifted from its
            // encoder by one field would produce an operation that reads as
            // valid and describes a different trade.
            26 => {
                let vault_id = get_bytes(&mut input)?;
                let owner_public_key = get_bytes(&mut input)?;
                let owner_devid = get_arr32(&mut input)?;
                let owner_genesis = get_arr32(&mut input)?;
                let input_policy_commit = get_arr32(&mut input)?;
                let output_policy_commit = get_arr32(&mut input)?;
                let parent_sequence = get_u64(&mut input)?;
                let parent_reserves_digest = get_arr32(&mut input)?;
                let reserve_proof_root = get_arr32(&mut input)?;
                let predicate_digest = get_arr32(&mut input)?;
                let route_commit_bytes = get_bytes(&mut input)?;
                let external_commitment_x = get_arr32(&mut input)?;
                let input_amount = get_u64(&mut input)?;
                let output_amount = get_u64(&mut input)?;
                let fee_bps = get_u32(&mut input)?;
                let sigma = get_arr32(&mut input)?;
                let settler_public_key = get_bytes(&mut input)?;
                let settler_devid = get_arr32(&mut input)?;
                let settlement_receipt_id = get_arr32(&mut input)?;
                let signature = get_bytes(&mut input)?;
                let mode = dec_mode(&mut input)?;
                DlvSettle {
                    vault_id,
                    owner_public_key,
                    owner_devid,
                    owner_genesis,
                    input_policy_commit,
                    output_policy_commit,
                    parent_sequence,
                    parent_reserves_digest,
                    reserve_proof_root,
                    predicate_digest,
                    route_commit_bytes,
                    external_commitment_x,
                    input_amount,
                    output_amount,
                    fee_bps,
                    sigma,
                    settler_public_key,
                    settler_devid,
                    settlement_receipt_id,
                    signature,
                    mode,
                }
            }
            27 => {
                let vault_id = get_bytes(&mut input)?;
                let settlement_receipt_id = get_arr32(&mut input)?;
                let pending_pointer_x = get_arr32(&mut input)?;
                let parent_sequence = get_u64(&mut input)?;
                let new_sequence = get_u64(&mut input)?;
                let parent_reserves_digest = get_arr32(&mut input)?;
                let new_reserves_digest = get_arr32(&mut input)?;
                let input_policy_commit = get_arr32(&mut input)?;
                let output_policy_commit = get_arr32(&mut input)?;
                let input_amount = get_u64(&mut input)?;
                let output_amount = get_u64(&mut input)?;
                let signature = get_bytes(&mut input)?;
                let mode = dec_mode(&mut input)?;
                DlvOwnerApply {
                    vault_id,
                    settlement_receipt_id,
                    pending_pointer_x,
                    parent_sequence,
                    new_sequence,
                    parent_reserves_digest,
                    new_reserves_digest,
                    input_policy_commit,
                    output_policy_commit,
                    input_amount,
                    output_amount,
                    signature,
                    mode,
                }
            }
            _ => return Err(DsmError::invalid_operation("unknown op tag")),
        };
        // Canonical decode requires full byte exhaustion: a valid operation must
        // consume its entire input. Trailing bytes are non-canonical — a distinct
        // wire string that decodes to the same operation — and are rejected so a
        // signed operation has exactly one byte encoding. (issue #450)
        if !input.is_empty() {
            return Err(DsmError::invalid_operation(format!(
                "trailing bytes after operation: {} leftover",
                input.len()
            )));
        }
        Ok(op)
    }

    pub fn get_state_number(&self) -> Option<u64> {
        None
    }

    /// Get proof of authorization if available
    pub fn get_proof_of_authorization(&self) -> Option<Vec<u8>> {
        match self {
            Operation::Mint {
                proof_of_authorization,
                ..
            } => Some(proof_of_authorization.clone()),
            // For Transfer, the signature IS the proof of authorization
            Operation::Transfer { signature, .. } if !signature.is_empty() => {
                Some(signature.clone())
            }
            Operation::Create { proof, .. } => Some(proof.clone()),
            Operation::Update { proof, .. } => Some(proof.clone()),
            Operation::AddRelationship { proof, .. } => Some(proof.clone()),
            Operation::CreateRelationship { proof, .. } => Some(proof.clone()),
            Operation::RemoveRelationship { proof, .. } => Some(proof.clone()),
            Operation::Delete { proof, .. } => Some(proof.clone()),
            Operation::Link { proof, .. } => Some(proof.clone()),
            Operation::Unlink { proof, .. } => Some(proof.clone()),
            Operation::Invalidate { proof, .. } => Some(proof.clone()),
            Operation::Recovery {
                compromise_proof, ..
            } => Some(compromise_proof.clone()),
            Operation::CreateToken { signature, .. }
            | Operation::Lock { signature, .. }
            | Operation::Unlock { signature, .. }
            | Operation::LockToken { signature, .. }
            | Operation::UnlockToken { signature, .. }
            | Operation::Generic { signature, .. }
            | Operation::DlvCreate { signature, .. }
            | Operation::DlvUnlock { signature, .. }
            | Operation::DlvClaim { signature, .. }
            | Operation::DlvInvalidate { signature, .. }
                if !signature.is_empty() =>
            {
                Some(signature.clone())
            }
            _ => None,
        }
    }

    /// Get signature if available.
    /// Per whitepaper: receipts are signed by both parties with SPHINCS+ ephemeral keys.
    pub fn get_signature(&self) -> Option<Vec<u8>> {
        match self {
            Operation::Transfer { signature, .. }
            | Operation::CreateToken { signature, .. }
            | Operation::Lock { signature, .. }
            | Operation::Unlock { signature, .. }
            | Operation::LockToken { signature, .. }
            | Operation::UnlockToken { signature, .. }
            | Operation::Generic { signature, .. }
            | Operation::DlvCreate { signature, .. }
            | Operation::DlvUnlock { signature, .. }
            | Operation::DlvClaim { signature, .. }
            | Operation::DlvInvalidate { signature, .. }
            | Operation::DlvSettle { signature, .. }
            | Operation::DlvOwnerApply { signature, .. }
                if !signature.is_empty() =>
            {
                Some(signature.clone())
            }
            _ => None,
        }
    }

    /// Get the operation type as a string
    pub fn get_operation_type(&self) -> &'static str {
        match self {
            Operation::Genesis => "genesis",
            Operation::Create { .. } => "create",
            Operation::Update { .. } => "update",
            Operation::Transfer { .. } => "transfer",
            Operation::Mint { .. } => "mint",
            Operation::Burn { .. } => "burn",
            Operation::LockToken { .. } => "lock_token",
            Operation::UnlockToken { .. } => "unlock_token",
            Operation::Lock { .. } => "lock",
            Operation::Unlock { .. } => "unlock",
            Operation::AddRelationship { .. } => "add_relationship",
            Operation::CreateRelationship { .. } => "create_relationship",
            Operation::RemoveRelationship { .. } => "remove_relationship",
            Operation::Recovery { .. } => "recovery",
            Operation::Delete { .. } => "delete",
            Operation::Link { .. } => "link",
            Operation::Unlink { .. } => "unlink",
            Operation::Invalidate { .. } => "invalidate",
            Operation::Generic { .. } => "generic",
            Operation::Receive { .. } => "receive",
            Operation::CreateToken { .. } => "create_token",
            Operation::Noop => "noop",
            Operation::DlvCreate { .. } => "dlv_create",
            Operation::DlvUnlock { .. } => "dlv_unlock",
            Operation::DlvClaim { .. } => "dlv_claim",
            Operation::DlvSettle { .. } => "dlv_settle",
            Operation::DlvOwnerApply { .. } => "dlv_owner_apply",
            Operation::DlvInvalidate { .. } => "dlv_invalidate",
        }
    }

    /// Return a clone of this operation with all signature/proof fields cleared.
    /// Used to compute the canonical signing payload (sign over everything except
    /// the signature field itself).
    pub fn with_cleared_signature(&self) -> Self {
        let mut clone = self.clone();
        match &mut clone {
            Operation::Transfer { signature, .. }
            | Operation::CreateToken { signature, .. }
            | Operation::Lock { signature, .. }
            | Operation::Unlock { signature, .. }
            | Operation::LockToken { signature, .. }
            | Operation::UnlockToken { signature, .. }
            | Operation::Generic { signature, .. }
            | Operation::DlvCreate { signature, .. }
            | Operation::DlvUnlock { signature, .. }
            | Operation::DlvClaim { signature, .. }
            | Operation::DlvInvalidate { signature, .. }
            | Operation::DlvSettle { signature, .. }
            | Operation::DlvOwnerApply { signature, .. } => {
                signature.clear();
            }
            _ => {}
        }
        clone
    }

    /// Return a clone of this operation with the signature field set to `sig`
    /// for variants that carry a signature. Mirror of [`with_cleared_signature`].
    ///
    /// [`with_cleared_signature`]: Operation::with_cleared_signature
    pub fn with_signature(&self, sig: Vec<u8>) -> Self {
        let mut clone = self.clone();
        match &mut clone {
            Operation::Transfer { signature, .. }
            | Operation::CreateToken { signature, .. }
            | Operation::Lock { signature, .. }
            | Operation::Unlock { signature, .. }
            | Operation::LockToken { signature, .. }
            | Operation::UnlockToken { signature, .. }
            | Operation::Generic { signature, .. }
            | Operation::DlvCreate { signature, .. }
            | Operation::DlvUnlock { signature, .. }
            | Operation::DlvClaim { signature, .. }
            | Operation::DlvInvalidate { signature, .. }
            | Operation::DlvSettle { signature, .. }
            | Operation::DlvOwnerApply { signature, .. } => {
                *signature = sig;
            }
            _ => {}
        }
        clone
    }

    /// §4.2.1 Authoritative binding: decode the sender's signed canonical
    /// preimage and bind it to the verified signature. This is the SINGLE
    /// trusted source for an inbound signed operation — callers MUST route
    /// every value read (amount/token_id/recipient/nonce/message) off the
    /// returned [`Operation`], never off any parallel structured field that
    /// traveled alongside the signed bytes.
    ///
    /// Steps:
    /// 1. SPHINCS+ verify `signature` over `canonical_operation_bytes` under
    ///    `signer_pubkey` (fail fast — never decode unauthenticated bytes).
    /// 2. [`Operation::from_bytes`] the canonical preimage.
    /// 3. Enforce canonical re-serialization equality
    ///    `op.with_cleared_signature().to_bytes() == canonical_operation_bytes`.
    ///    This rejects trailing garbage and any non-canonical encoding for this
    ///    path (independent of the global decoder exhaustion guard, issue #450).
    /// 4. Return the operation with the verified signature re-attached, so the
    ///    result is byte-identical to the operation the sender signed.
    pub fn decode_and_bind_signed(
        canonical_operation_bytes: &[u8],
        signature: &[u8],
        signer_pubkey: &[u8],
    ) -> Result<Operation, DsmError> {
        match crate::crypto::sphincs::sphincs_verify(
            signer_pubkey,
            canonical_operation_bytes,
            signature,
        ) {
            Ok(true) => {}
            Ok(false) => return Err(DsmError::verification("signed operation signature invalid")),
            Err(e) => {
                return Err(DsmError::verification(format!(
                    "signed operation signature verification error: {e}"
                )))
            }
        }

        let op = Operation::from_bytes(canonical_operation_bytes)?;

        if op.with_cleared_signature().to_bytes() != canonical_operation_bytes {
            return Err(DsmError::invalid_operation(
                "non-canonical signed operation bytes (re-serialization mismatch)",
            ));
        }

        Ok(op.with_signature(signature.to_vec()))
    }
}

impl Ops for Operation {
    fn validate(&self) -> Result<bool, DsmError> {
        match self {
            Operation::Generic { .. } => Ok(true),
            Operation::Transfer { amount, .. } => Ok(amount.value() > 0),
            Operation::Mint { amount, .. } => Ok(amount.value() > 0),
            Operation::Burn { amount, .. } => Ok(amount.value() > 0),
            Operation::LockToken { .. } => Ok(true),
            Operation::UnlockToken { .. } => Ok(true),
            Operation::Lock { .. } => Ok(true),
            Operation::Unlock { .. } => Ok(true),
            _ => Ok(true),
        }
    }

    fn execute(&self) -> Result<Vec<u8>, DsmError> {
        Ok(self.to_bytes())
    }

    fn get_id(&self) -> &str {
        match self {
            Operation::Genesis => "genesis",
            Operation::Generic { .. } => "generic",
            Operation::Transfer { .. } => "transfer",
            Operation::Mint { .. } => "mint",
            Operation::Burn { .. } => "burn",
            Operation::Create { .. } => "create",
            Operation::Update { .. } => "update",
            Operation::AddRelationship { .. } => "add_relationship",
            Operation::CreateRelationship { .. } => "create_relationship",
            Operation::RemoveRelationship { .. } => "remove_relationship",
            Operation::Recovery { .. } => "recovery",
            Operation::Delete { .. } => "delete",
            Operation::Link { .. } => "link",
            Operation::Unlink { .. } => "unlink",
            Operation::Invalidate { .. } => "invalidate",
            Operation::LockToken { .. } => "lock_token",
            Operation::UnlockToken { .. } => "unlock_token",
            Operation::Lock { .. } => "lock",
            Operation::Unlock { .. } => "unlock",
            Operation::Receive { .. } => "receive",
            Operation::CreateToken { .. } => "create_token",
            Operation::Noop => "noop",
            Operation::DlvCreate { .. } => "dlv_create",
            Operation::DlvUnlock { .. } => "dlv_unlock",
            Operation::DlvClaim { .. } => "dlv_claim",
            Operation::DlvSettle { .. } => "dlv_settle",
            Operation::DlvOwnerApply { .. } => "dlv_owner_apply",
            Operation::DlvInvalidate { .. } => "dlv_invalidate",
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

impl TokenOps for Operation {
    fn is_valid(&self) -> bool {
        match self {
            Operation::Transfer { amount, .. } => amount.value() > 0,
            Operation::Mint { amount, .. } => amount.value() > 0,
            Operation::Burn { amount, .. } => amount.value() > 0,
            Operation::Lock { amount, .. } => amount.value() > 0,
            Operation::Unlock { amount, .. } => amount.value() > 0,
            _ => false,
        }
    }

    fn has_expired(&self) -> bool {
        false
    }

    fn verify_token(&self, _public_key: &[u8]) -> Result<bool, DsmError> {
        match self {
            Operation::Transfer { .. }
            | Operation::Mint { .. }
            | Operation::Burn { .. }
            | Operation::Lock { .. }
            | Operation::Unlock { .. } => Ok(true),
            _ => Ok(false),
        }
    }

    fn extend_validity(&mut self, _duration: u64) -> Result<(), DsmError> {
        Err(DsmError::generic(
            "Cannot extend validity of an operation",
            None::<std::io::Error>,
        ))
    }
}

impl GenericOps for Operation {
    fn get_operation_type(&self) -> &str {
        match self {
            Operation::Genesis => "genesis",
            Operation::Generic { .. } => "generic",
            _ => self.get_id(),
        }
    }

    fn get_data(&self) -> &[u8] {
        match self {
            Operation::Generic { data, .. } => data,
            _ => &[],
        }
    }

    fn set_data(&mut self, data: Vec<u8>) -> Result<(), DsmError> {
        match self {
            Operation::Generic {
                data: ref mut d, ..
            } => {
                *d = data;
                Ok(())
            }
            _ => Err(DsmError::generic(
                "Cannot set data on non-generic operation",
                None::<std::io::Error>,
            )),
        }
    }

    fn merge(&self, other: &dyn GenericOps) -> Result<Vec<u8>, DsmError> {
        let mut merged = Vec::new();
        merged.extend_from_slice(self.get_data());
        merged.extend_from_slice(other.get_data());
        Ok(merged)
    }
}

impl IdOps for Operation {
    fn verify_identity(&self, _public_key: &[u8]) -> Result<bool, DsmError> {
        match self {
            Operation::Create { .. } | Operation::Update { .. } => Ok(true),
            _ => Ok(false),
        }
    }

    fn update_identity(&mut self, _new_data: &[u8]) -> Result<(), DsmError> {
        match self {
            Operation::Update { .. } => Ok(()),
            _ => Err(DsmError::generic(
                "Cannot update identity with this operation",
                None::<std::io::Error>,
            )),
        }
    }

    fn revoke_identity(&mut self) -> Result<(), DsmError> {
        Err(DsmError::generic(
            "Identity revocation not implemented for operations",
            None::<std::io::Error>,
        ))
    }

    fn get_identity_proof(&self) -> Result<Vec<u8>, DsmError> {
        match self {
            Operation::Create { .. } | Operation::Update { .. } => Ok(Vec::new()),
            _ => Err(DsmError::generic(
                "No identity proof for this operation",
                None::<std::io::Error>,
            )),
        }
    }
}

impl SmartCommitOps for Operation {
    fn verify_commitment(&self, _public_key: &[u8]) -> Result<bool, DsmError> {
        Ok(true)
    }

    fn update_commitment(&mut self, _new_data: &[u8]) -> Result<(), DsmError> {
        Err(DsmError::generic(
            "Cannot update commitment for operation",
            None::<std::io::Error>,
        ))
    }

    fn finalize_commitment(&mut self) -> Result<Vec<u8>, DsmError> {
        Ok(self.to_bytes())
    }

    fn get_commitment_proof(&self) -> Result<Vec<u8>, DsmError> {
        Ok(self.to_bytes())
    }
}

/// Pre-commitment parameters for binding a future state transition.
///
/// A pre-commitment constrains a future operation by fixing certain parameters
/// at commitment time while leaving others variable. This enables deterministic
/// verification without requiring all values to be known in advance.
#[derive(Debug, Clone, Default)]
pub struct PreCommitmentOp {
    /// Parameters whose values are fixed at commitment time (sorted by key for determinism).
    pub fixed_parameters: HashMap<String, Vec<u8>>,
    /// Parameter names whose values will be provided at execution time.
    pub variable_parameters: Vec<String>,
    /// Security parameters governing the commitment (not included in canonical bytes).
    pub security_params: SecurityParameters,
}

// Implement PartialEq, Eq, PartialOrd and Ord for consistent ordering
impl PartialEq for PreCommitmentOp {
    fn eq(&self, other: &Self) -> bool {
        self.fixed_parameters == other.fixed_parameters
            && self.variable_parameters == other.variable_parameters
    }
}

impl PartialOrd for PreCommitmentOp {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for PreCommitmentOp {}

impl Ord for PreCommitmentOp {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let fixed_params_cmp = self
            .fixed_parameters
            .len()
            .cmp(&other.fixed_parameters.len());
        if fixed_params_cmp != std::cmp::Ordering::Equal {
            return fixed_params_cmp;
        }

        let var_params_cmp = self.variable_parameters.cmp(&other.variable_parameters);
        if var_params_cmp != std::cmp::Ordering::Equal {
            return var_params_cmp;
        }

        std::cmp::Ordering::Equal
    }
}

// Implement conversion from StateTransition to Operation
use crate::core::state_machine::transition::StateTransition;

impl From<StateTransition> for Operation {
    fn from(transition: StateTransition) -> Self {
        // Simply extract the operation from the transition
        transition.operation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_balance(value: u64) -> Balance {
        Balance::from_parts(value, 0, Some([0xAB; 32]))
    }

    #[test]
    fn transfer_authority_policy_is_append_only_and_round_trips() {
        let make = |ap: Option<AuthorityPolicy>| Operation::Transfer {
            to_device_id: b"rcpt".to_vec(),
            amount: test_balance(100),
            token_id: b"ERA".to_vec(),
            policy_commit: [7u8; 32],
            mode: TransactionMode::Bilateral,
            nonce: vec![1, 2, 3],
            verification: VerificationType::Bilateral,
            pre_commit: None,
            recipient: b"rcpt".to_vec(),
            to: b"rcpt".to_vec(),
            message: "m".to_string(),
            signature: vec![9, 9, 9],
            authority_policy: ap,
        };
        let none_op = make(None);
        let some_op = make(Some(AuthorityPolicy {
            mode: AuthorityMode::OfflineBearerRequired,
            policy_id: [3u8; 32],
            anchor_set_id: [4u8; 32],
        }));
        let none_bytes = none_op.to_bytes();
        let some_bytes = some_op.to_bytes();

        // Append-only: the None encoding is a strict PREFIX of the Some encoding — the policy is a
        // pure tail, so absent => no bytes => every pre-existing transfer encoding (and state hash)
        // is byte-identical to before this field existed.
        assert!(some_bytes.starts_with(&none_bytes));
        assert!(some_bytes.len() > none_bytes.len());
        // The offline-bearer policy changes the canonical op bytes (Decision 2 #2).
        assert_ne!(none_bytes, some_bytes);
        // Both round-trip through the canonical decoder (the appended tail is read back exactly).
        assert_eq!(Operation::from_bytes(&none_bytes).unwrap(), none_op);
        assert_eq!(Operation::from_bytes(&some_bytes).unwrap(), some_op);
        // The mode is bound: OnlineChecked vs OfflineBearerRequired differ in the bytes.
        let online_op = make(Some(AuthorityPolicy {
            mode: AuthorityMode::OnlineChecked,
            policy_id: [3u8; 32],
            anchor_set_id: [4u8; 32],
        }));
        assert_ne!(online_op.to_bytes(), some_bytes);
    }

    fn roundtrip(op: &Operation) -> Operation {
        let bytes = op.to_bytes();
        let decoded = Operation::from_bytes(&bytes).expect("from_bytes failed");
        assert_eq!(
            op,
            &decoded,
            "round-trip mismatch for {:?}",
            op.get_operation_type()
        );
        let rebytes = decoded.to_bytes();
        assert_eq!(bytes, rebytes, "re-encode mismatch");
        decoded
    }

    #[test]
    fn is_value_egress_classifies_owner_value_movement() {
        // Egress: owner value movement must be gated during identity recovery.
        assert!(Operation::Burn {
            amount: test_balance(1),
            token_id: vec![1],
            policy_commit: [0u8; 32],
            proof_of_ownership: vec![],
            message: String::new(),
        }
        .is_value_egress());
        assert!(Operation::LockToken {
            token_id: vec![1],
            amount: 1,
            purpose: b"dlv_collateral".to_vec(),
            mode: TransactionMode::Unilateral,
            signature: vec![],
        }
        .is_value_egress());

        // Not egress: ingress + identity/neutral operations proceed during recovery.
        assert!(!Operation::Genesis.is_value_egress());
        assert!(!Operation::Noop.is_value_egress());
        assert!(!Operation::default().is_value_egress());
        assert!(!Operation::Mint {
            amount: test_balance(1),
            token_id: vec![1],
            policy_commit: [0u8; 32],
            authorized_by: vec![],
            proof_of_authorization: vec![],
            message: String::new(),
        }
        .is_value_egress());
    }

    #[test]
    fn is_value_bearing_classifies_value_capable_relationships() {
        // Egress ops are value-bearing (superset of is_value_egress).
        let burn = Operation::Burn {
            amount: test_balance(1),
            token_id: vec![1],
            policy_commit: [0u8; 32],
            proof_of_ownership: vec![],
            message: String::new(),
        };
        assert!(burn.is_value_egress() && burn.is_value_bearing());

        // Ingress ops are value-bearing but NOT egress — a relationship that only
        // received value is still value-capable (must be in the recovery gate-set).
        let mint = Operation::Mint {
            amount: test_balance(1),
            token_id: vec![1],
            policy_commit: [0u8; 32],
            authorized_by: vec![],
            proof_of_authorization: vec![],
            message: String::new(),
        };
        assert!(!mint.is_value_egress() && mint.is_value_bearing());
        let receive = Operation::Receive {
            token_id: b"TKN".to_vec(),
            from_device_id: vec![0xAA; 32],
            amount: test_balance(1),
            recipient: vec![],
            message: String::new(),
            mode: TransactionMode::Unilateral,
            nonce: vec![],
            verification: VerificationType::Standard,
            sender_state_hash: None,
        };
        assert!(!receive.is_value_egress() && receive.is_value_bearing());

        // Pure contact/social/neutral relationships are NOT value-capable.
        assert!(!Operation::Genesis.is_value_bearing());
        assert!(!Operation::Noop.is_value_bearing());
        assert!(!Operation::default().is_value_bearing());
        assert!(!Operation::AddRelationship {
            from_id: [1; 32],
            to_id: [2; 32],
            relationship_type: b"bilateral_transfer".to_vec(),
            metadata: vec![],
            proof: vec![],
            mode: TransactionMode::Bilateral,
            message: String::new(),
        }
        .is_value_bearing());
    }

    #[test]
    fn egress_asset_matches_is_value_egress_and_extracts_token() {
        // P5: egress_asset is the canonical asset-id companion to is_value_egress. The
        // invariant `is_value_egress() == (egress_asset() != NotEgress)` must hold for every
        // variant — a representative sample across egress / ingress / neutral.
        let burn = Operation::Burn {
            amount: test_balance(7),
            token_id: b"ERA".to_vec(),
            policy_commit: [0u8; 32],
            proof_of_ownership: vec![],
            message: String::new(),
        };
        assert_eq!(
            burn.egress_asset(),
            EgressAsset::Asset {
                token_id: b"ERA".to_vec(),
                amount: 7
            }
        );

        let lt = Operation::LockToken {
            token_id: b"ERA".to_vec(),
            amount: -5, // negative i64 clamps to 0 (no canonical egress size)
            purpose: b"dlv".to_vec(),
            mode: TransactionMode::Unilateral,
            signature: vec![],
        };
        assert_eq!(
            lt.egress_asset(),
            EgressAsset::Asset {
                token_id: b"ERA".to_vec(),
                amount: 0
            }
        );

        // Vault-keyed DLV claim → asset can't be named here → Unidentified (fail-closed gate).
        let claim = Operation::DlvClaim {
            vault_id: vec![1, 2, 3],
            claim_proof: vec![],
            claimant_public_key: vec![],
            signature: vec![],
            mode: TransactionMode::Unilateral,
        };
        assert_eq!(claim.egress_asset(), EgressAsset::Unidentified);
        assert!(claim.is_value_egress());

        // Non-egress → NotEgress.
        assert_eq!(Operation::Noop.egress_asset(), EgressAsset::NotEgress);
        assert_eq!(Operation::Genesis.egress_asset(), EgressAsset::NotEgress);

        // The invariant, across a representative set.
        let mint = Operation::Mint {
            amount: test_balance(1),
            token_id: b"ERA".to_vec(),
            policy_commit: [0u8; 32],
            authorized_by: vec![],
            proof_of_authorization: vec![],
            message: String::new(),
        };
        for op in [
            &burn,
            &lt,
            &claim,
            &mint,
            &Operation::Noop,
            &Operation::Genesis,
        ] {
            assert_eq!(
                op.is_value_egress(),
                !matches!(op.egress_asset(), EgressAsset::NotEgress),
                "egress_asset must agree with is_value_egress for {op:?}"
            );
        }
    }

    // ------------------------------------------------------------------ //
    //  Round-trip tests for every variant
    // ------------------------------------------------------------------ //
    mod roundtrip {
        use super::*;

        #[test]
        fn genesis() {
            roundtrip(&Operation::Genesis);
        }

        #[test]
        fn noop() {
            roundtrip(&Operation::Noop);
        }

        #[test]
        fn create() {
            roundtrip(&Operation::Create {
                message: "create identity".into(),
                identity_data: vec![1, 2, 3],
                public_key: vec![4, 5, 6],
                metadata: vec![7, 8],
                commitment: vec![9],
                proof: vec![10, 11],
                mode: TransactionMode::Bilateral,
            });
        }

        #[test]
        fn update_with_forward_link() {
            roundtrip(&Operation::Update {
                message: "update id".into(),
                identity_id: vec![0xAA; 16],
                updated_data: vec![0xBB; 8],
                proof: vec![0xCC; 4],
                forward_link: Some(vec![0xDD; 32]),
            });
        }

        #[test]
        fn update_without_forward_link() {
            roundtrip(&Operation::Update {
                message: "no fwd".into(),
                identity_id: vec![1],
                updated_data: vec![2],
                proof: vec![3],
                forward_link: None,
            });
        }

        #[test]
        fn transfer_no_precommit() {
            roundtrip(&Operation::Transfer {
                policy_commit: [0u8; 32],
                to_device_id: vec![0x01; 32],
                amount: test_balance(500),
                token_id: b"ERA".to_vec(),
                mode: TransactionMode::Bilateral,
                nonce: vec![0xFF; 16],
                verification: VerificationType::Standard,
                pre_commit: None,
                recipient: vec![0x02; 32],
                to: vec![0x03; 32],
                message: "send tokens".into(),
                signature: vec![0xAA; 64],
                authority_policy: None,
            });
        }

        #[test]
        fn transfer_with_precommit() {
            let mut fixed = HashMap::new();
            fixed.insert("recipient".into(), vec![0x01; 32]);
            fixed.insert("amount".into(), vec![0, 0, 0, 100]);
            let pc = PreCommitmentOp {
                fixed_parameters: fixed,
                variable_parameters: vec!["nonce".into(), "timestamp".into()],
                security_params: SecurityParameters::default(),
            };
            roundtrip(&Operation::Transfer {
                policy_commit: [0u8; 32],
                to_device_id: vec![0x01; 32],
                amount: test_balance(1000),
                token_id: b"TKN".to_vec(),
                mode: TransactionMode::Unilateral,
                nonce: vec![0x11; 8],
                verification: VerificationType::PreCommitted,
                pre_commit: Some(pc),
                recipient: vec![0x02; 32],
                to: vec![0x03; 32],
                message: "pre-committed transfer".into(),
                signature: vec![0xBB; 48],
                authority_policy: None,
            });
        }

        #[test]
        fn transfer_custom_verification() {
            roundtrip(&Operation::Transfer {
                policy_commit: [0u8; 32],
                to_device_id: vec![0x01; 32],
                amount: test_balance(42),
                token_id: b"ERA".to_vec(),
                mode: TransactionMode::Bilateral,
                nonce: vec![0x99],
                verification: VerificationType::Custom(vec![0xDE, 0xAD]),
                pre_commit: None,
                recipient: vec![],
                to: vec![],
                message: String::new(),
                signature: vec![],
                authority_policy: None,
            });
        }

        #[test]
        fn mint() {
            roundtrip(&Operation::Mint {
                amount: test_balance(10_000),
                token_id: b"ERA".to_vec(),
                policy_commit: [0u8; 32],
                authorized_by: vec![0xAA; 32],
                proof_of_authorization: vec![0xBB; 64],
                message: "mint tokens".into(),
            });
        }

        #[test]
        fn burn() {
            roundtrip(&Operation::Burn {
                amount: test_balance(200),
                token_id: b"TKN".to_vec(),
                policy_commit: [0u8; 32],
                proof_of_ownership: vec![0xCC; 64],
                message: "burn tokens".into(),
            });
        }

        #[test]
        fn lock_token() {
            roundtrip(&Operation::LockToken {
                token_id: b"ERA".to_vec(),
                amount: 500,
                purpose: b"escrow".to_vec(),
                mode: TransactionMode::Unilateral,
                signature: vec![0xDD; 32],
            });
        }

        #[test]
        fn unlock_token() {
            roundtrip(&Operation::UnlockToken {
                token_id: b"ERA".to_vec(),
                amount: 250,
                purpose: b"escrow".to_vec(),
                mode: TransactionMode::Bilateral,
                signature: vec![0xEE; 32],
            });
        }

        #[test]
        fn lock() {
            roundtrip(&Operation::Lock {
                token_id: b"TKN".to_vec(),
                amount: test_balance(100),
                purpose: b"collateral".to_vec(),
                owner: vec![0x11; 32],
                message: "lock for collateral".into(),
                signature: vec![0x22; 48],
            });
        }

        #[test]
        fn unlock() {
            roundtrip(&Operation::Unlock {
                token_id: b"TKN".to_vec(),
                amount: test_balance(50),
                purpose: b"collateral".to_vec(),
                owner: vec![0x33; 32],
                message: "release collateral".into(),
                signature: vec![0x44; 48],
            });
        }

        #[test]
        fn add_relationship() {
            roundtrip(&Operation::AddRelationship {
                from_id: [0x01; 32],
                to_id: [0x02; 32],
                relationship_type: b"bilateral_transfer".to_vec(),
                metadata: vec![0xAA; 10],
                proof: vec![0xBB; 64],
                mode: TransactionMode::Bilateral,
                message: "add rel".into(),
            });
        }

        #[test]
        fn create_relationship() {
            roundtrip(&Operation::CreateRelationship {
                message: "create rel".into(),
                counterparty_id: vec![0x01; 32],
                commitment: vec![0x02; 16],
                proof: vec![0x03; 64],
                mode: TransactionMode::Unilateral,
            });
        }

        #[test]
        fn remove_relationship() {
            roundtrip(&Operation::RemoveRelationship {
                from_id: [0xAA; 32],
                to_id: [0xBB; 32],
                relationship_type: b"expired".to_vec(),
                proof: vec![0xCC; 64],
                mode: TransactionMode::Bilateral,
                message: "remove rel".into(),
            });
        }

        #[test]
        fn recovery() {
            roundtrip(&Operation::Recovery {
                message: "recover chain".into(),
                state_number: 42,
                state_hash: vec![0x11; 32],
                state_entropy: vec![0x22; 32],
                invalidation_data: vec![0x33; 16],
                new_state_data: vec![0x44; 64],
                new_state_number: 43,
                new_state_hash: vec![0x55; 32],
                new_state_entropy: vec![0x66; 32],
                compromise_proof: vec![0x77; 128],
                authority_sigs: vec![vec![0x88; 64], vec![0x99; 64]],
            });
        }

        #[test]
        fn delete() {
            roundtrip(&Operation::Delete {
                reason: "resource expired".into(),
                proof: vec![0xAA; 64],
                mode: TransactionMode::Unilateral,
                id: vec![0xBB; 16],
            });
        }

        #[test]
        fn link() {
            roundtrip(&Operation::Link {
                target_id: vec![0x01; 32],
                link_type: b"forward".to_vec(),
                proof: vec![0x02; 64],
                mode: TransactionMode::Bilateral,
            });
        }

        #[test]
        fn unlink() {
            roundtrip(&Operation::Unlink {
                target_id: vec![0x01; 32],
                proof: vec![0x02; 64],
                mode: TransactionMode::Unilateral,
            });
        }

        #[test]
        fn invalidate() {
            roundtrip(&Operation::Invalidate {
                reason: "clone detected".into(),
                proof: vec![0xDE; 64],
                mode: TransactionMode::Bilateral,
            });
        }

        #[test]
        fn generic() {
            roundtrip(&Operation::Generic {
                operation_type: b"custom_op".to_vec(),
                data: vec![1, 2, 3, 4, 5],
                message: "generic op".into(),
                signature: vec![0xFF; 32],
            });
        }

        #[test]
        fn receive_with_sender_state_hash() {
            roundtrip(&Operation::Receive {
                token_id: b"ERA".to_vec(),
                from_device_id: vec![0x01; 32],
                amount: test_balance(777),
                recipient: vec![0x02; 32],
                message: "receive tokens".into(),
                mode: TransactionMode::Bilateral,
                nonce: vec![0x03; 16],
                verification: VerificationType::StandardBilateral,
                sender_state_hash: Some(vec![0x04; 32]),
            });
        }

        #[test]
        fn receive_without_sender_state_hash() {
            roundtrip(&Operation::Receive {
                token_id: b"TKN".to_vec(),
                from_device_id: vec![0xAA; 32],
                amount: test_balance(1),
                recipient: vec![],
                message: String::new(),
                mode: TransactionMode::Unilateral,
                nonce: vec![],
                verification: VerificationType::Standard,
                sender_state_hash: None,
            });
        }

        #[test]
        fn create_token_full() {
            roundtrip(&Operation::CreateToken {
                token_id: b"dBTC".to_vec(),
                initial_supply: test_balance(21_000_000),
                name: "Deterministic Bitcoin".into(),
                symbol: "dBTC".into(),
                decimals: 8,
                metadata_uri: Some("https://example.com/dbtc".into()),
                policy_commit: [0xAB; 32],
                fee_amount: 10,
                signature: vec![0xCD; 64],
            });
        }

        #[test]
        fn create_token_minimal() {
            roundtrip(&Operation::CreateToken {
                token_id: b"T".to_vec(),
                initial_supply: test_balance(0),
                name: "Test".into(),
                symbol: "T".into(),
                decimals: 0,
                metadata_uri: None,
                policy_commit: [0u8; 32],
                fee_amount: 0,
                signature: vec![],
            });
        }

        #[test]
        fn dlv_create() {
            roundtrip(&Operation::DlvCreate {
                vault_id: vec![0x01; 32],
                creator_public_key: vec![0x02; 64],
                parameters_hash: vec![0x03; 32],
                fulfillment_condition: vec![0x04; 16],
                intended_recipient: Some(vec![0x05; 64]),
                token_id: Some(b"ERA".to_vec()),
                locked_amount: Some(test_balance(999)),
                signature: vec![0x06; 48],
                mode: TransactionMode::Unilateral,
            });
        }

        #[test]
        fn dlv_create_no_optionals() {
            roundtrip(&Operation::DlvCreate {
                vault_id: vec![0x01; 32],
                creator_public_key: vec![0x02; 64],
                parameters_hash: vec![0x03; 32],
                fulfillment_condition: vec![],
                intended_recipient: None,
                token_id: None,
                locked_amount: None,
                signature: vec![0x06; 48],
                mode: TransactionMode::Bilateral,
            });
        }

        #[test]
        fn dlv_unlock() {
            roundtrip(&Operation::DlvUnlock {
                vault_id: vec![0x01; 32],
                fulfillment_proof: vec![0x02; 128],
                requester_public_key: vec![0x03; 64],
                signature: vec![0x04; 48],
                mode: TransactionMode::Unilateral,
            });
        }

        #[test]
        fn dlv_claim() {
            roundtrip(&Operation::DlvClaim {
                vault_id: vec![0x01; 32],
                claim_proof: vec![0x02; 64],
                claimant_public_key: vec![0x03; 64],
                signature: vec![0x04; 48],
                mode: TransactionMode::Bilateral,
            });
        }

        #[test]
        fn dlv_invalidate() {
            roundtrip(&Operation::DlvInvalidate {
                vault_id: vec![0x01; 32],
                reason: "timeout expired".into(),
                creator_public_key: vec![0x02; 64],
                signature: vec![0x03; 48],
                mode: TransactionMode::Unilateral,
            });
        }

        #[test]
        fn all_verification_types() {
            let types = vec![
                VerificationType::Standard,
                VerificationType::Enhanced,
                VerificationType::Bilateral,
                VerificationType::Directory,
                VerificationType::StandardBilateral,
                VerificationType::PreCommitted,
                VerificationType::UnilateralIdentityAnchor,
                VerificationType::Custom(vec![0xCA, 0xFE]),
            ];
            for vt in types {
                roundtrip(&Operation::Transfer {
                    policy_commit: [0u8; 32],
                    to_device_id: vec![0x01; 32],
                    amount: test_balance(1),
                    token_id: b"ERA".to_vec(),
                    mode: TransactionMode::Bilateral,
                    nonce: vec![],
                    verification: vt,
                    pre_commit: None,
                    recipient: vec![],
                    to: vec![],
                    message: String::new(),
                    signature: vec![],
                    authority_policy: None,
                });
            }
        }
    }

    // ------------------------------------------------------------------ //
    //  Ops trait tests
    // ------------------------------------------------------------------ //
    mod ops_trait {
        use super::*;

        #[test]
        fn validate_transfer_zero_amount() {
            let op = Operation::Transfer {
                policy_commit: [0u8; 32],
                to_device_id: vec![0x01; 32],
                amount: test_balance(0),
                token_id: b"ERA".to_vec(),
                mode: TransactionMode::Bilateral,
                nonce: vec![],
                verification: VerificationType::Standard,
                pre_commit: None,
                recipient: vec![],
                to: vec![],
                message: String::new(),
                signature: vec![],
                authority_policy: None,
            };
            assert!(!Ops::validate(&op).unwrap());
        }

        #[test]
        fn validate_transfer_positive_amount() {
            let op = Operation::Transfer {
                policy_commit: [0u8; 32],
                to_device_id: vec![0x01; 32],
                amount: test_balance(100),
                token_id: b"ERA".to_vec(),
                mode: TransactionMode::Bilateral,
                nonce: vec![],
                verification: VerificationType::Standard,
                pre_commit: None,
                recipient: vec![],
                to: vec![],
                message: String::new(),
                signature: vec![],
                authority_policy: None,
            };
            assert!(Ops::validate(&op).unwrap());
        }

        #[test]
        fn validate_genesis_is_true() {
            assert!(Ops::validate(&Operation::Genesis).unwrap());
        }

        #[test]
        fn validate_noop_is_true() {
            assert!(Ops::validate(&Operation::Noop).unwrap());
        }

        #[test]
        fn get_id_returns_correct_strings() {
            let cases: Vec<(Operation, &str)> = vec![
                (Operation::Genesis, "genesis"),
                (Operation::Noop, "noop"),
                (
                    Operation::Create {
                        message: String::new(),
                        identity_data: vec![],
                        public_key: vec![],
                        metadata: vec![],
                        commitment: vec![],
                        proof: vec![],
                        mode: TransactionMode::Bilateral,
                    },
                    "create",
                ),
                (
                    Operation::Update {
                        message: String::new(),
                        identity_id: vec![],
                        updated_data: vec![],
                        proof: vec![],
                        forward_link: None,
                    },
                    "update",
                ),
                (
                    Operation::Delete {
                        reason: String::new(),
                        proof: vec![],
                        mode: TransactionMode::Bilateral,
                        id: vec![],
                    },
                    "delete",
                ),
                (
                    Operation::Recovery {
                        message: String::new(),
                        state_number: 0,
                        state_hash: vec![],
                        state_entropy: vec![],
                        invalidation_data: vec![],
                        new_state_data: vec![],
                        new_state_number: 0,
                        new_state_hash: vec![],
                        new_state_entropy: vec![],
                        compromise_proof: vec![],
                        authority_sigs: vec![],
                    },
                    "recovery",
                ),
                (
                    Operation::DlvCreate {
                        vault_id: vec![],
                        creator_public_key: vec![],
                        parameters_hash: vec![],
                        fulfillment_condition: vec![],
                        intended_recipient: None,
                        token_id: None,
                        locked_amount: None,
                        signature: vec![],
                        mode: TransactionMode::Unilateral,
                    },
                    "dlv_create",
                ),
            ];
            for (op, expected) in cases {
                assert_eq!(Ops::get_id(&op), expected);
            }
        }

        #[test]
        fn execute_returns_bytes() {
            let op = Operation::Genesis;
            let result = Ops::execute(&op).unwrap();
            assert!(!result.is_empty());
            assert_eq!(result, op.to_bytes());
        }
    }

    // ------------------------------------------------------------------ //
    //  get_operation_type tests
    // ------------------------------------------------------------------ //
    mod operation_type {
        use super::*;

        #[test]
        fn returns_correct_type_strings() {
            assert_eq!(Operation::Genesis.get_operation_type(), "genesis");
            assert_eq!(Operation::Noop.get_operation_type(), "noop");

            let transfer = Operation::Transfer {
                policy_commit: [0u8; 32],
                to_device_id: vec![],
                amount: test_balance(1),
                token_id: vec![],
                mode: TransactionMode::Bilateral,
                nonce: vec![],
                verification: VerificationType::Standard,
                pre_commit: None,
                recipient: vec![],
                to: vec![],
                message: String::new(),
                signature: vec![],
                authority_policy: None,
            };
            assert_eq!(transfer.get_operation_type(), "transfer");

            let mint = Operation::Mint {
                amount: test_balance(1),
                token_id: vec![],
                policy_commit: [0u8; 32],
                authorized_by: vec![],
                proof_of_authorization: vec![],
                message: String::new(),
            };
            assert_eq!(mint.get_operation_type(), "mint");

            let burn = Operation::Burn {
                amount: test_balance(1),
                token_id: vec![],
                policy_commit: [0u8; 32],
                proof_of_ownership: vec![],
                message: String::new(),
            };
            assert_eq!(burn.get_operation_type(), "burn");

            assert_eq!(
                Operation::LockToken {
                    token_id: vec![],
                    amount: 0,
                    purpose: vec![],
                    mode: TransactionMode::Bilateral,
                    signature: vec![],
                }
                .get_operation_type(),
                "lock_token"
            );

            assert_eq!(
                Operation::UnlockToken {
                    token_id: vec![],
                    amount: 0,
                    purpose: vec![],
                    mode: TransactionMode::Bilateral,
                    signature: vec![],
                }
                .get_operation_type(),
                "unlock_token"
            );

            assert_eq!(
                Operation::DlvUnlock {
                    vault_id: vec![],
                    fulfillment_proof: vec![],
                    requester_public_key: vec![],
                    signature: vec![],
                    mode: TransactionMode::Bilateral,
                }
                .get_operation_type(),
                "dlv_unlock"
            );

            assert_eq!(
                Operation::DlvClaim {
                    vault_id: vec![],
                    claim_proof: vec![],
                    claimant_public_key: vec![],
                    signature: vec![],
                    mode: TransactionMode::Bilateral,
                }
                .get_operation_type(),
                "dlv_claim"
            );

            assert_eq!(
                Operation::DlvInvalidate {
                    vault_id: vec![],
                    reason: String::new(),
                    creator_public_key: vec![],
                    signature: vec![],
                    mode: TransactionMode::Bilateral,
                }
                .get_operation_type(),
                "dlv_invalidate"
            );
        }
    }

    // ------------------------------------------------------------------ //
    //  with_cleared_signature tests
    // ------------------------------------------------------------------ //
    mod cleared_signature {
        use super::*;

        #[test]
        fn clears_transfer_signature() {
            let op = Operation::Transfer {
                policy_commit: [0u8; 32],
                to_device_id: vec![0x01; 32],
                amount: test_balance(100),
                token_id: b"ERA".to_vec(),
                mode: TransactionMode::Bilateral,
                nonce: vec![0xFF; 16],
                verification: VerificationType::Standard,
                pre_commit: None,
                recipient: vec![],
                to: vec![],
                message: String::new(),
                signature: vec![0xAA; 64],
                authority_policy: None,
            };
            let cleared = op.with_cleared_signature();
            assert_eq!(cleared.get_signature(), None);
        }

        #[test]
        fn clears_create_token_signature() {
            let op = Operation::CreateToken {
                token_id: b"T".to_vec(),
                initial_supply: test_balance(0),
                name: "T".into(),
                symbol: "T".into(),
                decimals: 0,
                metadata_uri: None,
                policy_commit: [0u8; 32],
                fee_amount: 0,
                signature: vec![0xBB; 48],
            };
            let cleared = op.with_cleared_signature();
            assert_eq!(cleared.get_signature(), None);
        }

        #[test]
        fn clears_dlv_create_signature() {
            let op = Operation::DlvCreate {
                vault_id: vec![0x01; 32],
                creator_public_key: vec![0x02; 64],
                parameters_hash: vec![],
                fulfillment_condition: vec![],
                intended_recipient: None,
                token_id: None,
                locked_amount: None,
                signature: vec![0xCC; 48],
                mode: TransactionMode::Unilateral,
            };
            let cleared = op.with_cleared_signature();
            assert_eq!(cleared.get_signature(), None);
        }

        #[test]
        fn genesis_unchanged() {
            let op = Operation::Genesis;
            let cleared = op.with_cleared_signature();
            assert_eq!(op, cleared);
        }

        #[test]
        fn generic_signature_cleared() {
            let op = Operation::Generic {
                operation_type: b"test".to_vec(),
                data: vec![1, 2, 3],
                message: "msg".into(),
                signature: vec![0xDD; 32],
            };
            let cleared = op.with_cleared_signature();
            match &cleared {
                Operation::Generic { signature, .. } => assert!(signature.is_empty()),
                _ => panic!("wrong variant"),
            }
        }
    }

    // ------------------------------------------------------------------ //
    //  from_bytes error cases
    // ------------------------------------------------------------------ //
    mod decode_errors {
        use super::*;

        #[test]
        fn empty_input() {
            assert!(Operation::from_bytes(&[]).is_err());
        }

        #[test]
        fn invalid_tag_byte() {
            assert!(Operation::from_bytes(&[254]).is_err());
        }

        #[test]
        fn truncated_create() {
            let bytes = Operation::Create {
                message: "hello".into(),
                identity_data: vec![1, 2, 3],
                public_key: vec![4, 5],
                metadata: vec![],
                commitment: vec![],
                proof: vec![],
                mode: TransactionMode::Bilateral,
            }
            .to_bytes();
            let truncated = &bytes[..bytes.len() / 2];
            assert!(Operation::from_bytes(truncated).is_err());
        }

        #[test]
        fn truncated_single_byte_tag() {
            assert!(Operation::from_bytes(&[3]).is_err());
        }

        #[test]
        fn bad_mode_byte() {
            let mut bytes = Operation::Invalidate {
                reason: "test".into(),
                proof: vec![],
                mode: TransactionMode::Bilateral,
            }
            .to_bytes();
            *bytes.last_mut().unwrap() = 99;
            assert!(Operation::from_bytes(&bytes).is_err());
        }

        #[test]
        fn trailing_bytes_after_transfer_rejected() {
            let mut bytes = Operation::Transfer {
                to_device_id: vec![0x01; 32],
                amount: test_balance(100),
                token_id: b"ERA".to_vec(),
                policy_commit: [0u8; 32],
                mode: TransactionMode::Unilateral,
                nonce: vec![0xFF; 16],
                verification: VerificationType::Standard,
                pre_commit: None,
                recipient: vec![0x02; 32],
                to: vec![0x03; 32],
                message: "x".into(),
                signature: vec![0xAA; 32],
                authority_policy: None,
            }
            .to_bytes();
            // Exact bytes decode fine; one trailing byte is non-canonical.
            assert!(Operation::from_bytes(&bytes).is_ok());
            bytes.push(0x00);
            assert!(Operation::from_bytes(&bytes).is_err());
        }

        #[test]
        fn trailing_bytes_after_create_rejected() {
            let mut bytes = Operation::Create {
                message: "hello".into(),
                identity_data: vec![1, 2, 3],
                public_key: vec![4, 5],
                metadata: vec![],
                commitment: vec![],
                proof: vec![],
                mode: TransactionMode::Bilateral,
            }
            .to_bytes();
            assert!(Operation::from_bytes(&bytes).is_ok());
            bytes.extend_from_slice(&[0xFF, 0xFF]);
            assert!(Operation::from_bytes(&bytes).is_err());
        }
    }

    // ------------------------------------------------------------------ //
    //  decode_and_bind_signed — authoritative inbound binding (issue #446)
    // ------------------------------------------------------------------ //
    mod decode_and_bind {
        use super::*;
        use crate::crypto::sphincs::{generate_keypair_from_seed, sphincs_sign, SphincsVariant};

        /// Build a legitimately signed Transfer the way the sender does:
        /// sign over `signing_op.to_bytes()` with an EMPTY signature field, and
        /// that exact buffer is the `canonical_operation_bytes` preimage.
        /// Returns `(canonical_bytes, signature, signer_public_key)`.
        fn signed_transfer() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
            let kp =
                generate_keypair_from_seed(SphincsVariant::SPX256f, &[7u8; 32]).expect("keypair");
            let signing_op = Operation::Transfer {
                to_device_id: vec![0x11; 32],
                amount: test_balance(42),
                token_id: b"ERA".to_vec(),
                policy_commit: [0u8; 32],
                mode: TransactionMode::Unilateral,
                nonce: vec![0xAB; 16],
                verification: VerificationType::Standard,
                pre_commit: None,
                recipient: vec![0x22; 32],
                to: vec![0x33; 32],
                message: "unit".into(),
                signature: Vec::new(),
                authority_policy: None,
            };
            let canonical = signing_op.to_bytes();
            let sig = sphincs_sign(&kp.secret_key, &canonical).expect("sign");
            (canonical, sig, kp.public_key.clone())
        }

        #[test]
        fn clean_accept_binds_canonical_values() {
            let (canonical, sig, pk) = signed_transfer();
            let bound = Operation::decode_and_bind_signed(&canonical, &sig, &pk)
                .expect("bind should accept a clean signed op");

            // The bound op derives SOLELY from the signed canonical bytes — there is
            // no structured field input to the helper, so a tampered sibling field
            // (the issue #446 attack) cannot influence these values.
            assert!(
                matches!(bound, Operation::Transfer { .. }),
                "expected Transfer"
            );
            if let Operation::Transfer {
                to_device_id,
                amount,
                token_id,
                nonce,
                ..
            } = &bound
            {
                assert_eq!(to_device_id, &vec![0x11; 32]);
                assert_eq!(amount.value(), 42);
                assert_eq!(token_id, &b"ERA".to_vec());
                assert_eq!(nonce, &vec![0xAB; 16]);
            }

            // Signature re-attached, and re-clearing reproduces the exact preimage.
            assert_eq!(bound.get_signature(), Some(sig));
            assert_eq!(bound.with_cleared_signature().to_bytes(), canonical);
        }

        #[test]
        fn trailing_garbage_rejected() {
            let kp =
                generate_keypair_from_seed(SphincsVariant::SPX256f, &[7u8; 32]).expect("keypair");
            let (canonical, _sig, pk) = signed_transfer();
            let mut tampered = canonical;
            tampered.push(0xFF);
            // Sign the trailing-garbage bytes so the SIGNATURE itself verifies; the
            // re-serialization equality check must still reject the non-canonical input.
            let sig = sphincs_sign(&kp.secret_key, &tampered).expect("sign");
            assert!(Operation::decode_and_bind_signed(&tampered, &sig, &pk).is_err());
        }

        #[test]
        fn wrong_signature_rejected() {
            let (canonical, _sig, pk) = signed_transfer();
            let other =
                generate_keypair_from_seed(SphincsVariant::SPX256f, &[9u8; 32]).expect("keypair2");
            let bad_sig = sphincs_sign(&other.secret_key, &canonical).expect("sign");
            // Verify under the ORIGINAL signer's key -> signature mismatch -> reject,
            // before any decoded value is trusted.
            assert!(Operation::decode_and_bind_signed(&canonical, &bad_sig, &pk).is_err());
        }
    }

    // ------------------------------------------------------------------ //
    //  TokenOps trait tests
    // ------------------------------------------------------------------ //
    mod token_ops {
        use super::*;

        #[test]
        fn is_valid_transfer_positive() {
            let op = Operation::Transfer {
                policy_commit: [0u8; 32],
                to_device_id: vec![0x01; 32],
                amount: test_balance(100),
                token_id: b"ERA".to_vec(),
                mode: TransactionMode::Bilateral,
                nonce: vec![],
                verification: VerificationType::Standard,
                pre_commit: None,
                recipient: vec![],
                to: vec![],
                message: String::new(),
                signature: vec![],
                authority_policy: None,
            };
            assert!(TokenOps::is_valid(&op));
        }

        #[test]
        fn is_valid_transfer_zero() {
            let op = Operation::Transfer {
                policy_commit: [0u8; 32],
                to_device_id: vec![0x01; 32],
                amount: test_balance(0),
                token_id: b"ERA".to_vec(),
                mode: TransactionMode::Bilateral,
                nonce: vec![],
                verification: VerificationType::Standard,
                pre_commit: None,
                recipient: vec![],
                to: vec![],
                message: String::new(),
                signature: vec![],
                authority_policy: None,
            };
            assert!(!TokenOps::is_valid(&op));
        }

        #[test]
        fn is_valid_genesis_returns_false() {
            assert!(!TokenOps::is_valid(&Operation::Genesis));
        }

        #[test]
        fn is_valid_noop_returns_false() {
            assert!(!TokenOps::is_valid(&Operation::Noop));
        }

        #[test]
        fn is_valid_mint_positive() {
            let op = Operation::Mint {
                amount: test_balance(50),
                token_id: b"ERA".to_vec(),
                policy_commit: [0u8; 32],
                authorized_by: vec![],
                proof_of_authorization: vec![],
                message: String::new(),
            };
            assert!(TokenOps::is_valid(&op));
        }

        #[test]
        fn is_valid_lock_positive() {
            let op = Operation::Lock {
                token_id: b"ERA".to_vec(),
                amount: test_balance(10),
                purpose: vec![],
                owner: vec![],
                message: String::new(),
                signature: vec![],
            };
            assert!(TokenOps::is_valid(&op));
        }

        #[test]
        fn has_expired_returns_false() {
            assert!(!TokenOps::has_expired(&Operation::Genesis));
            let transfer = Operation::Transfer {
                policy_commit: [0u8; 32],
                to_device_id: vec![],
                amount: test_balance(1),
                token_id: vec![],
                mode: TransactionMode::Bilateral,
                nonce: vec![],
                verification: VerificationType::Standard,
                pre_commit: None,
                recipient: vec![],
                to: vec![],
                message: String::new(),
                signature: vec![],
                authority_policy: None,
            };
            assert!(!TokenOps::has_expired(&transfer));
        }
    }

    // ------------------------------------------------------------------ //
    //  GenericOps trait tests
    // ------------------------------------------------------------------ //
    mod generic_ops {
        use super::*;

        #[test]
        fn get_data_returns_data_for_generic() {
            let op = Operation::Generic {
                operation_type: b"test".to_vec(),
                data: vec![10, 20, 30],
                message: String::new(),
                signature: vec![],
            };
            assert_eq!(GenericOps::get_data(&op), &[10, 20, 30]);
        }

        #[test]
        fn get_data_returns_empty_for_non_generic() {
            assert!(GenericOps::get_data(&Operation::Genesis).is_empty());
            assert!(GenericOps::get_data(&Operation::Noop).is_empty());
        }

        #[test]
        fn set_data_works_for_generic() {
            let mut op = Operation::Generic {
                operation_type: b"test".to_vec(),
                data: vec![1],
                message: String::new(),
                signature: vec![],
            };
            GenericOps::set_data(&mut op, vec![99, 100]).unwrap();
            assert_eq!(GenericOps::get_data(&op), &[99, 100]);
        }

        #[test]
        fn set_data_errors_for_non_generic() {
            let mut op = Operation::Genesis;
            assert!(GenericOps::set_data(&mut op, vec![1]).is_err());
        }

        #[test]
        fn merge_concatenates_data() {
            let a = Operation::Generic {
                operation_type: b"t".to_vec(),
                data: vec![1, 2],
                message: String::new(),
                signature: vec![],
            };
            let b = Operation::Generic {
                operation_type: b"t".to_vec(),
                data: vec![3, 4],
                message: String::new(),
                signature: vec![],
            };
            let merged = GenericOps::merge(&a, &b).unwrap();
            assert_eq!(merged, vec![1, 2, 3, 4]);
        }
    }

    // ------------------------------------------------------------------ //
    //  Balance round-trip through Operation encoding
    // ------------------------------------------------------------------ //
    mod balance_encoding {
        use super::*;

        #[test]
        fn balance_with_state_hash_roundtrips() {
            let bal = Balance::from_parts(12345, 0, Some([0xFE; 32]));
            let op = Operation::Mint {
                amount: bal.clone(),
                token_id: b"T".to_vec(),
                policy_commit: [0u8; 32],
                authorized_by: vec![],
                proof_of_authorization: vec![],
                message: String::new(),
            };
            let decoded = roundtrip(&op);
            if let Operation::Mint { amount, .. } = decoded {
                assert_eq!(amount.value(), bal.value());
            } else {
                panic!("wrong variant");
            }
        }

        #[test]
        fn balance_without_state_hash_roundtrips() {
            let bal = Balance::from_parts(0, 0, None);
            let op = Operation::Burn {
                amount: bal,
                token_id: b"X".to_vec(),
                policy_commit: [0u8; 32],
                proof_of_ownership: vec![],
                message: String::new(),
            };
            roundtrip(&op);
        }

        #[test]
        fn balance_with_locked_roundtrips() {
            let bal = Balance::from_parts(1000, 200, Some([0x01; 32]));
            let op = Operation::Lock {
                token_id: b"ERA".to_vec(),
                amount: bal.clone(),
                purpose: b"test".to_vec(),
                owner: vec![0x01; 32],
                message: "lock test".into(),
                signature: vec![],
            };
            let decoded = roundtrip(&op);
            if let Operation::Lock { amount, .. } = decoded {
                assert_eq!(amount.value(), 1000);
                assert_eq!(amount.locked(), 200);
            } else {
                panic!("wrong variant");
            }
        }
    }

    // ------------------------------------------------------------------ //
    //  Determinism / stability
    // ------------------------------------------------------------------ //
    mod determinism {
        use super::*;

        #[test]
        fn encoding_is_deterministic() {
            let op = Operation::Transfer {
                policy_commit: [0u8; 32],
                to_device_id: vec![0x01; 32],
                amount: test_balance(42),
                token_id: b"ERA".to_vec(),
                mode: TransactionMode::Bilateral,
                nonce: vec![0xAA; 16],
                verification: VerificationType::Standard,
                pre_commit: None,
                recipient: vec![0x02; 32],
                to: vec![0x03; 32],
                message: "test".into(),
                signature: vec![0xBB; 64],
                authority_policy: None,
            };
            let b1 = op.to_bytes();
            let b2 = op.to_bytes();
            assert_eq!(b1, b2);
        }

        #[test]
        fn precommit_map_order_independent() {
            let make_op = |insert_order: &[(&str, Vec<u8>)]| {
                let mut fixed = HashMap::new();
                for (k, v) in insert_order {
                    fixed.insert(k.to_string(), v.clone());
                }
                Operation::Transfer {
                    policy_commit: [0u8; 32],
                    to_device_id: vec![],
                    amount: test_balance(1),
                    token_id: vec![],
                    mode: TransactionMode::Bilateral,
                    nonce: vec![],
                    verification: VerificationType::Standard,
                    pre_commit: Some(PreCommitmentOp {
                        fixed_parameters: fixed,
                        variable_parameters: vec![],
                        security_params: SecurityParameters::default(),
                    }),
                    recipient: vec![],
                    to: vec![],
                    message: String::new(),
                    signature: vec![],
                    authority_policy: None,
                }
            };
            let a = make_op(&[("alpha", vec![1]), ("beta", vec![2])]);
            let b = make_op(&[("beta", vec![2]), ("alpha", vec![1])]);
            assert_eq!(a.to_bytes(), b.to_bytes());
        }
    }
}
