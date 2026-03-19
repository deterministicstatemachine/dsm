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

/// Primary state transition operation enum (no Serde in canonical path).
///
/// Each variant represents a distinct kind of state transition in the DSM
/// protocol. All variants support canonical, deterministic byte encoding
/// via [`Operation::to_bytes`] for inclusion in state hashes and wire payloads.
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
    },
    /// Mint new tokens into existence (requires authorization proof).
    Mint {
        /// Quantity of tokens to mint (must be > 0).
        amount: Balance,
        /// Binary identifier of the token type to mint.
        token_id: Vec<u8>,
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
        /// Proof of key compromise (e.g., DBRW anomaly evidence).
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
        /// Initial supply minted at creation.
        initial_supply: Balance,
        /// Human-readable name of the token.
        name: String,
        /// Short symbol (e.g., "DSM", "dBTC").
        symbol: String,
        /// Number of decimal places for display formatting.
        decimals: u8,
        /// Optional URI pointing to token metadata.
        metadata_uri: Option<String>,
        /// Optional binary CPTA policy anchor hash constraining this token's behavior.
        policy_anchor: Option<Vec<u8>>,
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

impl Operation {
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
                mode,
                nonce,
                verification,
                pre_commit,
                recipient,
                to,
                message,
                signature,
            } => {
                put_u8(&mut out, 3);
                put_bytes(&mut out, to_device_id);
                // Balance canonical
                let bal = amount.to_le_bytes();
                put_bytes(&mut out, &bal);
                put_bytes(&mut out, token_id);
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
            }
            Mint {
                amount,
                token_id,
                authorized_by,
                proof_of_authorization,
                message,
            } => {
                put_u8(&mut out, 4);
                let bal = amount.to_le_bytes();
                put_bytes(&mut out, &bal);
                put_bytes(&mut out, token_id);
                put_bytes(&mut out, authorized_by);
                put_bytes(&mut out, proof_of_authorization);
                put_str(&mut out, message);
            }
            Burn {
                amount,
                token_id,
                proof_of_ownership,
                message,
            } => {
                put_u8(&mut out, 5);
                let bal = amount.to_le_bytes();
                put_bytes(&mut out, &bal);
                put_bytes(&mut out, token_id);
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
                name,
                symbol,
                decimals,
                metadata_uri,
                policy_anchor,
                signature,
            } => {
                put_u8(&mut out, 20);
                put_bytes(&mut out, token_id);
                let bal = initial_supply.to_le_bytes();
                put_bytes(&mut out, &bal);
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
                match policy_anchor {
                    Some(a) => {
                        put_u8(&mut out, 1);
                        put_bytes(&mut out, a);
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
            let last_updated = {
                let mut a = [0u8; 8];
                a.copy_from_slice(take(&mut cur, 8)?);
                u64::from_le_bytes(a)
            };
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
            Ok(Balance::from_parts(value, locked, last_updated, state_hash))
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
                Transfer {
                    to_device_id,
                    amount,
                    token_id,
                    mode,
                    nonce,
                    verification,
                    pre_commit,
                    recipient,
                    to,
                    message,
                    signature,
                }
            }
            4 => {
                let amount = dec_balance(&mut input)?;
                let token_id = get_bytes(&mut input)?;
                let authorized_by = get_bytes(&mut input)?;
                let proof_of_authorization = get_bytes(&mut input)?;
                let message = get_str(&mut input)?;
                Mint {
                    amount,
                    token_id,
                    authorized_by,
                    proof_of_authorization,
                    message,
                }
            }
            5 => {
                let amount = dec_balance(&mut input)?;
                let token_id = get_bytes(&mut input)?;
                let proof_of_ownership = get_bytes(&mut input)?;
                let message = get_str(&mut input)?;
                Burn {
                    amount,
                    token_id,
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
                let name = get_str(&mut input)?;
                let symbol = get_str(&mut input)?;
                let decimals = get_u8(&mut input)?;
                let metadata_uri = match get_u8(&mut input)? {
                    0 => None,
                    1 => Some(get_str(&mut input)?),
                    _ => return Err(DsmError::invalid_operation("bad opt flag")),
                };
                let policy_anchor = match get_u8(&mut input)? {
                    0 => None,
                    1 => Some(get_bytes(&mut input)?),
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
                    name,
                    symbol,
                    decimals,
                    metadata_uri,
                    policy_anchor,
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
            _ => return Err(DsmError::invalid_operation("unknown op tag")),
        };
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
            | Operation::DlvInvalidate { signature, .. } => {
                signature.clear();
            }
            _ => {}
        }
        clone
    }
}

impl Ops for Operation {
    fn validate(&self) -> Result<bool, DsmError> {
        match self {
            Operation::Generic { .. } => Ok(true),
            Operation::Transfer {
                amount,
                token_id: _,
                ..
            } => Ok(amount.value() > 0),
            Operation::Mint {
                amount,
                token_id: _,
                ..
            } => Ok(amount.value() > 0),
            Operation::Burn {
                amount,
                token_id: _,
                ..
            } => Ok(amount.value() > 0),
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
            Operation::Transfer {
                amount,
                token_id: _,
                ..
            } => amount.value() > 0,
            Operation::Mint {
                amount,
                token_id: _,
                ..
            } => amount.value() > 0,
            Operation::Burn {
                amount,
                token_id: _,
                ..
            } => amount.value() > 0,
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
