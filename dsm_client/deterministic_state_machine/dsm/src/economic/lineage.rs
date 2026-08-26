// SPDX-License-Identifier: Apache-2.0

//! The validated side of the economic lineage.
//!
//! ## The separation is enforced by the compiler, not by discipline
//!
//! [`ValidatedEconomicRoot`] has a private field and **no public constructor
//! that takes a [`RegisteredEconomicRoot`]**. There is no `From`, no
//! `into_validated`, no `assume_valid`. The only way to obtain position 0 is
//! [`activate`], which checks the activation precondition; positions above 0
//! require substrate acceptance that this module does not yet have (see
//! "What is missing" below).
//!
//! That is deliberate. `accepted_root != valid_root` is the single most
//! load-bearing statement in the economic design, and a convenience conversion
//! — added later, in a hurry, "just for this call site" — is exactly how it
//! would stop being true. Making the coercion unwritable costs nothing and
//! removes the failure mode.
//!
//! ```text
//! ValidatedEconomicRoot(0) = the canonical EMPTY economic root
//!                            verifier-derived, never trader-chosen
//! ```
//!
//! ## Activation: no legacy snapshot, ever
//!
//! `R_econ(0) = empty` is non-circular for a **fresh** identity. It is not a
//! valid bootstrap for a device that already holds balances, reserves,
//! receipts or an outstanding offline allocation: taking whatever the device
//! currently holds and calling it position 0 would let the device assert its
//! own opening balances, which re-creates self-rooting at the base of the
//! lineage — the precise defect the whole construction exists to remove.
//!
//! So a device holding value cannot activate. A migration protocol for
//! existing holdings is future work; it must never be an implicit snapshot.
//!
//! ## Advancing a validated root
//!
//! Conjunctive, and every clause is checked:
//!
//! ```text
//! ValidatedEconomicRoot(k) == witness.pre_economic_root
//! the registration is for position k+1
//! registered post_economic_root == witness.post_economic_root
//! verify_mutation_sequence(pre, mutations) == witness.post_economic_root
//! the accepted substrate and the witness bind THE SAME operation_digest
//! registered admission_manifest_addr == the manifest's own address
//! the manifest's provenance index equals what the credit sources reference
//! ```
//!
//! The shared `operation_digest` is the clause that is easiest to omit and
//! most costly to omit. Without it a trader presents a perfectly valid
//! successor and a perfectly valid economic transition **describing different
//! operations** — each verifies alone, and the pair means nothing.
//!
//! ## Provenance is checked here too
//!
//! A closed write set proves *what changed*, never *why a credit may appear*.
//! A lineage validated without provenance would accept a trader crediting
//! itself from nothing, because every mutation in a self-crediting write set
//! is individually well-formed. [`advance_validated`] therefore requires a
//! [`ProvenanceResolver`] and refuses unless every positive credit is funded
//! by exactly one verified source of the right asset and amount.
//!
//! The resolver returns already-validated objects, which is what makes the
//! acyclicity rule structural: an external source resolves from a root this
//! verifier has itself validated, never from the transition being validated.

use crate::economic::claim::{verify_manifest_provenance_index, EconomicAdmissionManifest};
use crate::economic::provenance::{
    verify_transition_provenance, FundedCredit, ProvenanceContext, ProvenanceError,
    ProvenanceResolver,
};
use crate::economic::register::RegisteredEconomicRoot;
use crate::economic::tree::empty_economic_root;
use crate::economic::witness::{
    verify_mutation_sequence, EconomicTransitionWitness, EconomicWitnessError,
};

/// A root this verifier has established is the result of a valid transition
/// from a validated predecessor.
///
/// **Verifier-derived.** There is no network event that declares a root
/// validated, and no message a peer can send that produces one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedEconomicRoot {
    economic_position: u64,
    economic_root: [u8; 32],
}

impl ValidatedEconomicRoot {
    pub fn economic_position(&self) -> u64 {
        self.economic_position
    }

    pub fn economic_root(&self) -> [u8; 32] {
        self.economic_root
    }
}

/// What the device currently holds, as observed by the activating device
/// itself.
///
/// Every field is a reason activation might be refused. A device that cannot
/// answer one of these has not established that it holds nothing, and
/// defaulting an unknown to "empty" would be assuming exactly the thing being
/// checked — so the caller must state all four.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EconomicActivationSnapshot {
    pub online_balances_empty: bool,
    pub vault_reserves_empty: bool,
    pub settlement_receipt_state_empty: bool,
    pub outstanding_offline_allocation: bool,
}

impl EconomicActivationSnapshot {
    /// The snapshot of a genuinely fresh identity.
    pub fn fresh() -> Self {
        Self {
            online_balances_empty: true,
            vault_reserves_empty: true,
            settlement_receipt_state_empty: true,
            outstanding_offline_allocation: false,
        }
    }
}

/// Why a device may not activate an economic lineage at the empty root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedLegacyEconomicState {
    pub snapshot: EconomicActivationSnapshot,
}

impl core::fmt::Display for UnsupportedLegacyEconomicState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "cannot activate an economic lineage on a device that already holds value \
             (balances_empty={}, reserves_empty={}, receipts_empty={}, outstanding_allocation={}): \
             calling the current holdings position 0 would let the device assert its own opening \
             balances, which is self-rooting at the base of the lineage. Beta: use a fresh \
             identity. A migration protocol is future work and must never be an implicit snapshot",
            self.snapshot.online_balances_empty,
            self.snapshot.vault_reserves_empty,
            self.snapshot.settlement_receipt_state_empty,
            self.snapshot.outstanding_offline_allocation
        )
    }
}

impl std::error::Error for UnsupportedLegacyEconomicState {}

/// The ONLY way to obtain a `ValidatedEconomicRoot`.
///
/// Succeeds exactly when the device holds nothing, and yields position 0 at
/// the canonical empty root — a value every verifier derives identically
/// without being told it.
pub fn activate(
    snapshot: EconomicActivationSnapshot,
) -> Result<ValidatedEconomicRoot, UnsupportedLegacyEconomicState> {
    let clean = snapshot.online_balances_empty
        && snapshot.vault_reserves_empty
        && snapshot.settlement_receipt_state_empty
        && !snapshot.outstanding_offline_allocation;
    if !clean {
        return Err(UnsupportedLegacyEconomicState { snapshot });
    }
    Ok(ValidatedEconomicRoot {
        economic_position: 0,
        economic_root: empty_economic_root(),
    })
}

/// A substrate acceptance the caller has **verified**, carrying the digest
/// that binds it to one operation.
///
/// The private field means this cannot be conjured from a literal; the named
/// constructors state what the caller must have established first. Verifying
/// the substrate evidence itself — the exact `C_dsm+` / `sigma_dsm`, or the
/// exact `OfflineBoundaryAttestationV1` — happens at the acceptance layer, and
/// is not repeated here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedSubstrate {
    operation_digest: [u8; 32],
    evidence_addr: [u8; 32],
}

impl AcceptedSubstrate {
    /// Call only after the exact `C_dsm+` / `sigma_dsm` at `evidence_addr` has
    /// been verified and found to commit `operation_digest`.
    pub fn from_verified_dsm_successor(
        operation_digest: [u8; 32],
        evidence_addr: [u8; 32],
    ) -> Self {
        Self {
            operation_digest,
            evidence_addr,
        }
    }

    /// Call only after the exact `OfflineBoundaryAttestationV1` at
    /// `evidence_addr` has been verified and found to commit
    /// `operation_digest`.
    pub fn from_verified_offline_boundary(
        operation_digest: [u8; 32],
        evidence_addr: [u8; 32],
    ) -> Self {
        Self {
            operation_digest,
            evidence_addr,
        }
    }

    pub fn operation_digest(&self) -> [u8; 32] {
        self.operation_digest
    }

    pub fn evidence_addr(&self) -> [u8; 32] {
        self.evidence_addr
    }
}

/// Why a registered root is not a validated successor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EconomicValidationError {
    /// The witness does not start from the validated predecessor.
    PreRootIsNotThePredecessor {
        predecessor: [u8; 32],
        witness_pre: [u8; 32],
    },
    /// The registration is not for the next position.
    PositionIsNotSuccessor { previous: u64, registered: u64 },
    /// The registered root and the witness disagree about the result.
    RegisteredRootDiffersFromWitness {
        registered: [u8; 32],
        witness: [u8; 32],
    },
    /// The mutations do not produce the claimed post-root.
    Transition(EconomicWitnessError),
    /// The accepted substrate and the witness describe DIFFERENT operations.
    OperationDigestMismatch {
        substrate: [u8; 32],
        witness: [u8; 32],
    },
    /// The registration names a manifest other than the one supplied.
    ManifestAddrMismatch {
        registered: [u8; 32],
        computed: [u8; 32],
    },
    /// The manifest or its provenance index is malformed.
    Manifest(crate::ccb::CcbError),
    /// A credit in this transition is not funded.
    Provenance(ProvenanceError),
}

impl core::fmt::Display for EconomicValidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PreRootIsNotThePredecessor { .. } => write!(
                f,
                "economic validation: the witness does not start from the validated predecessor"
            ),
            Self::PositionIsNotSuccessor {
                previous,
                registered,
            } => write!(
                f,
                "economic validation: registration is at position {registered}, which is not the \
                 successor of {previous}"
            ),
            Self::RegisteredRootDiffersFromWitness { .. } => write!(
                f,
                "economic validation: the registered root and the witness disagree about the \
                 result of the transition"
            ),
            Self::Transition(e) => write!(f, "economic validation: {e}"),
            Self::OperationDigestMismatch { .. } => write!(
                f,
                "economic validation: the accepted substrate and the economic transition bind \
                 DIFFERENT operation digests — each is individually valid and the pair describes \
                 two different operations"
            ),
            Self::ManifestAddrMismatch { .. } => write!(
                f,
                "economic validation: the registration names a different admission manifest than \
                 the one supplied"
            ),
            Self::Manifest(e) => write!(f, "economic validation: manifest: {e}"),
            Self::Provenance(e) => write!(f, "economic validation: {e}"),
        }
    }
}

impl std::error::Error for EconomicValidationError {}

/// Advance a validated root by one position.
///
/// `genesis` and `device_id` must be the **authenticated** identity whose tree
/// this is, from authority resolution — never taken from the objects being
/// validated, since every leaf key binds them.
// Each argument is a SEPARATE authenticated input to the conjunctive predicate
// — predecessor, registration, manifest, witness, substrate acceptance,
// provenance resolver, and the two identity components. Bundling any of them
// to satisfy the arity lint would hide which facts the caller must establish
// independently.
#[allow(clippy::too_many_arguments)]
pub fn advance_validated(
    previous: &ValidatedEconomicRoot,
    registered: &RegisteredEconomicRoot,
    manifest: &EconomicAdmissionManifest,
    witness: &EconomicTransitionWitness,
    accepted: &AcceptedSubstrate,
    resolver: &dyn ProvenanceResolver,
    genesis: &[u8; 32],
    device_id: &[u8; 32],
    // From the AUTHENTICATED Genesis v3 — recovered by recomputation, never
    // taken from the claimant beside the claim.
    network_id: &[u8],
    // The P0–P6-proven authority key. Provenance arms that verify signed
    // claims bind against THIS, because storage-node bearer attribution is
    // not the cryptographic identity binding.
    proven_ak: &[u8],
) -> Result<(ValidatedEconomicRoot, Vec<FundedCredit>), EconomicValidationError> {
    if previous.economic_root != witness.pre_economic_root {
        return Err(EconomicValidationError::PreRootIsNotThePredecessor {
            predecessor: previous.economic_root,
            witness_pre: witness.pre_economic_root,
        });
    }
    if registered.economic_position != previous.economic_position.saturating_add(1) {
        return Err(EconomicValidationError::PositionIsNotSuccessor {
            previous: previous.economic_position,
            registered: registered.economic_position,
        });
    }
    if registered.post_economic_root != witness.post_economic_root {
        return Err(EconomicValidationError::RegisteredRootDiffersFromWitness {
            registered: registered.post_economic_root,
            witness: witness.post_economic_root,
        });
    }
    // The clause that stops a valid successor being paired with a valid
    // transition for a DIFFERENT operation.
    if accepted.operation_digest != witness.operation_digest {
        return Err(EconomicValidationError::OperationDigestMismatch {
            substrate: accepted.operation_digest,
            witness: witness.operation_digest,
        });
    }
    let computed = manifest.addr().map_err(EconomicValidationError::Manifest)?;
    if registered.admission_manifest_addr != computed {
        return Err(EconomicValidationError::ManifestAddrMismatch {
            registered: registered.admission_manifest_addr,
            computed,
        });
    }
    verify_manifest_provenance_index(manifest, witness)
        .map_err(EconomicValidationError::Manifest)?;

    let derived = verify_mutation_sequence(&witness.mutation_sequence(), genesis, device_id)
        .map_err(EconomicValidationError::Transition)?;

    // Conjunctive with everything above: the write set is closed AND every
    // credit in it is funded. Checked last because it is the most expensive
    // and the cheap structural clauses should reject first.
    // The canonical register set for the claimant's network, resolved
    // FAIL-CLOSED: an unknown network refuses rather than defaulting, and a
    // winning claim naming any other set is foreign whatever its bytes say.
    let canonical_set = crate::economic::register::resolve_root_register_profile(network_id)
        .map_err(|e| {
            EconomicValidationError::Provenance(ProvenanceError::FaucetWinnerInvalid(match e {
                crate::economic::register::RegisterResolutionError::UnknownNetwork { .. } => {
                    "no register profile for the claimant's network"
                }
                _ => "register profile not derivable",
            }))
        })?
        .storage_set_id;
    let ctx = ProvenanceContext {
        genesis,
        device_id,
        economic_position: registered.economic_position,
        network_id,
        proven_ak,
        canonical_storage_set_id: canonical_set,
    };
    let funded = verify_transition_provenance(witness, resolver, &ctx)
        .map_err(EconomicValidationError::Provenance)?;

    Ok((
        ValidatedEconomicRoot {
            economic_position: registered.economic_position,
            economic_root: derived,
        },
        funded,
    ))
}
