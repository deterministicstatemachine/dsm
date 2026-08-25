// SPDX-License-Identifier: Apache-2.0

//! `R_econ` — the online economic root.
//!
//! ## What problem this exists to solve
//!
//! A legitimate Genesis-v3 identity is not evidence about value. An attacker
//! holding one signs an arbitrary economic root, and a write-once register
//! accepts it: the register proves **non-equivocation**, that this identity
//! named one root at this position and never a second one. It does not and
//! cannot prove that the root is the result of a valid transition.
//! `accepted_root != valid_root`. Everything here exists to make the second
//! statement independently checkable by a party who trusts neither the trader
//! nor any storage node.
//!
//! ```text
//! authenticated pre-state + verifiable valid transition
//!         -> authenticated post-state + receipt inclusion
//!         -> authentic successor edge
//! ```
//!
//! ## Scope: online only
//!
//! ```text
//! R_econ = SMT {
//!     balance(policy_commit)
//!     vault_reserve(vault_id, policy_commit)
//!     settlement_receipt(vault_id, receipt_id)
//!     consumed_source(source_id)
//! }
//! ```
//!
//! There is deliberately **no offline-allocation leaf**. The device-bound
//! offline allocation is a separate accounting regime that evolves entirely
//! outside this tree; only its boundaries touch `R_econ`, and they touch it
//! through the ordinary `balance` and `consumed_source` leaves.
//!
//! ## What is here and what is not
//!
//! This module currently provides the primitives: the tree, the key
//! derivations, the leaf encodings, a single leaf mutation, the sequential
//! verifier that turns a mutation list into a post-root, and the exhaustive
//! classifier that says which operations owe a write set at all.
//!
//! It does **not** yet provide credit provenance. That gap is the whole
//! remaining security question and it should be read as one: a closed write
//! set proves *what changed*, never *why a credit may appear*. A verifier that
//! checked only the mutations here would accept a trader crediting itself from
//! nothing, because every mutation in that write set is individually
//! well-formed. Provenance — the six-arm `CreditSource` algebra, classes
//! `0x0023`–`0x0028` — is a separate and **conjunctive** obligation.
//!
//! Class `0x001D` (`EconomicTransitionWitness`) and the provenance classes
//! `0x0023`–`0x0029` are allocated in [`crate::ccb::reserved`] and have no
//! encoder; see [`witness`] for why, and `reserved_classes_have_no_encoder`
//! for the test that keeps allocation from drifting into serialization.

pub mod claim;
pub mod classifier;
pub mod credit;
pub mod decode;
pub mod keys;
pub mod mutation;
pub mod state;
pub mod tree;
pub mod witness;

pub use claim::{
    verify_manifest_provenance_index, AdmissionSubstrate, EconomicAdmissionManifest,
    EconomicRootClaimBody,
};
pub use decode::{
    decode_credit_source, decode_leaf_mutation, decode_leaf_state, decode_transition_witness,
};
pub use credit::{
    CreditSource, CreditSourceAuthorizedIssuance, CreditSourceDlvReserveConsumption,
    CreditSourceSameTransitionMove, CreditSourceValidatedDlvSettlementPayment,
    CreditSourceValidatedPeerDebit, CreditSourceVerifiedOfflineReentry,
};
pub use classifier::{
    check_tripwire, classify, EconomicEffect, EconomicTripwire, ObservedEconomicChange,
};
pub use keys::{balance_key, consumed_source_key, settlement_receipt_key, vault_reserve_key};
pub use mutation::EconomicLeafMutation;
pub use state::{
    EconomicBalanceState, EconomicConsumedSourceState, EconomicLeafState,
    EconomicSettlementReceiptState, EconomicVaultReserveState,
};
pub use tree::{empty_economic_root, EconomicSmt, ECONOMIC_SMT_HEIGHT};
pub use witness::{
    verify_mutation_sequence, EconomicMutationSequence, EconomicTransitionWitness,
    EconomicWitnessError,
};
