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
    /// Rehydrate THIS DEVICE'S OWN admitted position from its local durable
    /// store.
    ///
    /// This deliberately punctures the no-constructor property for exactly one
    /// case: a coordinate that `advance_validated` produced ON THIS DEVICE and
    /// that was durably recorded in the same transaction that cleared the
    /// pending admission. Without it, a restarted producer could never resume.
    ///
    /// It is NOT for peers, NOT for registered roots, NOT for anything read
    /// from a network. Feeding it any of those is fabrication — the exact
    /// forgery the private constructor exists to prevent — and a resolver or
    /// verifier calling it has a bug by definition. The alternative
    /// (re-verifying the whole lineage on every restart) remains the recovery
    /// truth when the local store is questionable.
    pub fn rehydrate_from_admitted_store(
        admitted: AdmittedEconomicPosition,
    ) -> Result<Self, PredecessorHasNotSelected> {
        match admitted {
            AdmittedEconomicPosition::SingleRoot {
                economic_position,
                economic_root,
                ..
            }
            | AdmittedEconomicPosition::ResolvedSofi {
                economic_position,
                selected_root: economic_root,
                ..
            } => Ok(Self {
                economic_position,
                economic_root,
            }),
            // An unresolved conditional position has two roots and has
            // selected neither: there is no root to return.
            AdmittedEconomicPosition::UnresolvedSofi {
                economic_position,
                fulfillment_id,
                ..
            } => Err(PredecessorHasNotSelected {
                economic_position,
                fulfillment_id,
            }),
        }
    }

    /// The SoFi counterpart of `advance_validated`, for a position whose
    /// claim is conditional (`C_q`).
    ///
    /// **Only `sofi::lineage::advance_resolved` may call this**, and
    /// `ci/sofi_validated_root_constructors.sh` proves it: the
    /// conjunction that earns a validated root at `q` lives there, and a
    /// second caller would be a second, unreviewed definition of what
    /// "validated" means. It is the same puncture as
    /// `rehydrate_from_admitted_store`, kept just as narrow.
    pub(crate) fn from_resolved_sofi_position(
        economic_position: u64,
        economic_root: [u8; 32],
    ) -> Self {
        Self {
            economic_position,
            economic_root,
        }
    }

    /// A peer coordinate THIS verifier validated on an earlier walk and
    /// recorded (`peer_lineage::ValidatedStart`). **Only the peer lineage
    /// walker may call this**, as the start of a walk; a walk that fails
    /// `Invalid` from such a start is retried from the activation root, so
    /// the memo is never authority over what the register holds.
    pub(crate) fn from_verifier_memo(economic_position: u64, economic_root: [u8; 32]) -> Self {
        Self {
            economic_position,
            economic_root,
        }
    }

    pub fn economic_position(&self) -> u64 {
        self.economic_position
    }

    pub fn economic_root(&self) -> [u8; 32] {
        self.economic_root
    }
}

/// The claim Core accepted at one position of one trader's lineage, by the
/// digest of its exact envelope (`ClaimRef_p`, SoFi §16). A setup's
/// `claim_ref` is checked against this (SoFi Amendment S9).
///
/// Verifier-derived, like [`ValidatedEconomicRoot`]: [`advance_validated`]
/// produces one for an ordinary position, `sofi::lineage::advance_resolved`
/// for a SoFi position, and [`Self::rehydrate_from_admitted_store`] for this
/// device's own admitted position. There is no other constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedClaim {
    genesis: [u8; 32],
    device_id: [u8; 32],
    economic_position: u64,
    claim_ref: [u8; 32],
}

impl AcceptedClaim {
    /// Rehydrate THIS DEVICE'S OWN accepted claim from its admitted store,
    /// on exactly the terms of
    /// [`ValidatedEconomicRoot::rehydrate_from_admitted_store`]: a coordinate
    /// this device validated and recorded, never a peer's and never anything
    /// read from a network. An unresolved position was registered but never
    /// accepted, so it yields none.
    pub fn rehydrate_from_admitted_store(
        genesis: [u8; 32],
        device_id: [u8; 32],
        admitted: AdmittedEconomicPosition,
    ) -> Result<Self, PredecessorHasNotSelected> {
        match admitted {
            AdmittedEconomicPosition::SingleRoot {
                economic_position,
                claim_ref,
                ..
            }
            | AdmittedEconomicPosition::ResolvedSofi {
                economic_position,
                claim_ref,
                ..
            } => Ok(Self {
                genesis,
                device_id,
                economic_position,
                claim_ref,
            }),
            AdmittedEconomicPosition::UnresolvedSofi {
                economic_position,
                fulfillment_id,
                ..
            } => Err(PredecessorHasNotSelected {
                economic_position,
                fulfillment_id,
            }),
        }
    }

    /// The SoFi counterpart, for a position whose claim is `C_q`. **Only
    /// `sofi::lineage::advance_resolved` may call this**, for the same reason
    /// as [`ValidatedEconomicRoot::from_resolved_sofi_position`].
    pub(crate) fn from_resolved_sofi_position(
        genesis: [u8; 32],
        device_id: [u8; 32],
        economic_position: u64,
        claim_ref: [u8; 32],
    ) -> Self {
        Self {
            genesis,
            device_id,
            economic_position,
            claim_ref,
        }
    }

    pub fn genesis(&self) -> [u8; 32] {
        self.genesis
    }

    pub fn device_id(&self) -> [u8; 32] {
        self.device_id
    }

    pub fn economic_position(&self) -> u64 {
        self.economic_position
    }

    pub fn claim_ref(&self) -> [u8; 32] {
        self.claim_ref
    }
}

/// What [`advance_validated`] establishes at the registered position: the
/// validated root, the credits it funded, and the claim it accepted.
#[derive(Debug, Clone)]
pub struct ValidatedAdvance {
    pub root: ValidatedEconomicRoot,
    pub funded: Vec<FundedCredit>,
    pub claim: AcceptedClaim,
}

/// The device's own admitted position, as the durable store records it.
///
/// A bare `(position, root)` pair cannot express a conditional position, which
/// is exactly why one was dangerous: something has to be written in the root
/// column, and whatever is written becomes indistinguishable from a selected
/// root. The kind travels with the coordinate so the distinction survives a
/// restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmittedEconomicPosition {
    /// An ordinary position. Its root is the one the register holds, in the
    /// claim whose envelope digest is `claim_ref`.
    SingleRoot {
        economic_position: u64,
        economic_root: [u8; 32],
        claim_ref: [u8; 32],
    },
    /// A conditional SoFi position whose route resolved and selected a root.
    /// Realized selects `realize_root`; Void selects the predecessor's root.
    /// Either way exactly one root is usable, and it is this one.
    ResolvedSofi {
        economic_position: u64,
        selected_root: [u8; 32],
        fulfillment_id: [u8; 32],
        /// The digest of the position's conditional claim `C_q`.
        claim_ref: [u8; 32],
    },
    /// A conditional SoFi position that has not resolved. It commits two roots
    /// and has selected neither, so nothing descends from it.
    UnresolvedSofi {
        economic_position: u64,
        fulfillment_id: [u8; 32],
        realize_root: [u8; 32],
        void_root: [u8; 32],
    },
}

/// The predecessor is a conditional position that has selected no root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PredecessorHasNotSelected {
    pub economic_position: u64,
    pub fulfillment_id: [u8; 32],
}

impl core::fmt::Display for PredecessorHasNotSelected {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "the admitted position {} is conditional on fulfillment {} and has selected \
             no root: nothing descends from it until the route resolves",
            self.economic_position,
            crate::utils::text_id::encode_base32_crockford(&self.fulfillment_id)
        )
    }
}

impl std::error::Error for PredecessorHasNotSelected {}

impl AdmittedEconomicPosition {
    pub fn economic_position(&self) -> u64 {
        match self {
            Self::SingleRoot {
                economic_position, ..
            }
            | Self::ResolvedSofi {
                economic_position, ..
            }
            | Self::UnresolvedSofi {
                economic_position, ..
            } => *economic_position,
        }
    }

    /// What the fence must decide about this position as a PARENT.
    ///
    /// The mapping is the whole point of carrying the kind: a resolved
    /// conditional position parents exactly its selected root, an unresolved
    /// one parents nothing, and an ordinary position is unconstrained.
    pub fn predecessor_claim(&self) -> crate::sofi::lineage::PredecessorClaim {
        use crate::sofi::lineage::PredecessorClaim;
        match self {
            Self::SingleRoot { .. } => PredecessorClaim::SingleRoot,
            Self::ResolvedSofi { selected_root, .. } => PredecessorClaim::ConditionalResolved {
                selected_root: *selected_root,
            },
            Self::UnresolvedSofi { .. } => PredecessorClaim::ConditionalUnresolved,
        }
    }
}

/// What the device currently holds, as observed by the activating device
/// itself.
///
/// Every field is a reason activation might be refused. A device that cannot
/// answer one of these has not established that it holds nothing, and
/// defaulting an unknown to "empty" would be assuming exactly the thing being
/// checked — so the caller must state both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EconomicActivationSnapshot {
    pub online_balances_empty: bool,
    pub outstanding_offline_allocation: bool,
}

impl EconomicActivationSnapshot {
    /// The snapshot of a genuinely fresh identity.
    pub fn fresh() -> Self {
        Self {
            online_balances_empty: true,
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
             (balances_empty={}, outstanding_allocation={}): \
             calling the current holdings position 0 would let the device assert its own opening \
             balances, which is self-rooting at the base of the lineage. Beta: use a fresh \
             identity. A migration protocol is future work and must never be an implicit snapshot",
            self.snapshot.online_balances_empty, self.snapshot.outstanding_offline_allocation
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
    let clean = snapshot.online_balances_empty && !snapshot.outstanding_offline_allocation;
    if !clean {
        return Err(UnsupportedLegacyEconomicState { snapshot });
    }
    Ok(ValidatedEconomicRoot {
        economic_position: 0,
        economic_root: empty_economic_root(),
    })
}

/// A verified DSM-successor acceptance: the exact operation the successor
/// carried and the successor's chain-state commitment.
///
/// Private fields: this cannot be conjured from a literal. The constructor's
/// contract is that the exact `C_dsm+` / `sigma_dsm` evidence at
/// `evidence_addr` has been verified and found to carry `verified_operation`
/// and commit `c_dsm_plus`. The operation DIGEST is derived here, never
/// supplied — a caller cannot claim a digest its own operation bytes do not
/// produce — and `c_dsm_plus` is what the v2 economic operation id binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedDsmSuccessor {
    verified_operation: crate::types::operations::Operation,
    operation_digest: [u8; 32],
    c_dsm_plus: [u8; 32],
    /// The successor's parent tip from the verified evidence preimage —
    /// with `c_dsm_plus` this is the successor's own `(parent, tip)` pair,
    /// the value acceptance-evidence verification binds the countersigned
    /// B-side pair to.
    embedded_parent: [u8; 32],
    evidence_addr: [u8; 32],
}

/// A verified offline-boundary acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedOfflineBoundary {
    operation_digest: [u8; 32],
    evidence_addr: [u8; 32],
}

/// A substrate acceptance the caller has **verified** — TYPED, because the
/// two substrates prove different things and the manifest states which one an
/// admission used. `advance_validated` requires SAME-KIND equality with the
/// manifest's substrate slot; erasing the kind here would let a DSM successor
/// validate against a manifest naming an offline boundary (or vice versa)
/// whenever the digests happened to agree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptedSubstrate {
    // Boxed: the successor arm carries the verified operation (~500B) while
    // the boundary arm is two digests; an unboxed enum would make every
    // substrate the size of the largest.
    DsmSuccessor(Box<AcceptedDsmSuccessor>),
    OfflineBoundary(AcceptedOfflineBoundary),
}

impl AcceptedSubstrate {
    /// Call only after the exact `C_dsm+` / `sigma_dsm` at `evidence_addr`
    /// has been verified and found to carry exactly `verified_operation` and
    /// commit `c_dsm_plus` (the accepted successor's chain-state commitment).
    pub fn from_verified_dsm_successor(
        verified_operation: crate::types::operations::Operation,
        c_dsm_plus: [u8; 32],
        embedded_parent: [u8; 32],
        evidence_addr: [u8; 32],
    ) -> Self {
        let operation_digest =
            crate::economic::admission::dsm_operation_digest(&verified_operation.to_bytes());
        Self::DsmSuccessor(Box::new(AcceptedDsmSuccessor {
            verified_operation,
            operation_digest,
            c_dsm_plus,
            embedded_parent,
            evidence_addr,
        }))
    }

    /// Call only after the exact `OfflineBoundaryAttestationV1` at
    /// `evidence_addr` has been verified and found to commit
    /// `operation_digest`.
    pub fn from_verified_offline_boundary(
        operation_digest: [u8; 32],
        evidence_addr: [u8; 32],
    ) -> Self {
        Self::OfflineBoundary(AcceptedOfflineBoundary {
            operation_digest,
            evidence_addr,
        })
    }

    pub fn operation_digest(&self) -> [u8; 32] {
        match self {
            Self::DsmSuccessor(s) => s.operation_digest,
            Self::OfflineBoundary(b) => b.operation_digest,
        }
    }

    pub fn evidence_addr(&self) -> [u8; 32] {
        match self {
            Self::DsmSuccessor(s) => s.evidence_addr,
            Self::OfflineBoundary(b) => b.evidence_addr,
        }
    }

    /// The accepted DSM successor's own `(embedded_parent, C_dsm+)` pair —
    /// what an acceptance bundle's countersigned B-side pair must equal.
    /// `None` for an offline boundary (which can consume no peer debit).
    pub fn dsm_successor_pair(&self) -> Option<([u8; 32], [u8; 32])> {
        match self {
            Self::DsmSuccessor(s) => Some((s.embedded_parent, s.c_dsm_plus)),
            Self::OfflineBoundary(_) => None,
        }
    }

    /// The exact operation the VERIFIED substrate carried — the provenance
    /// context's one source for operation-level facts (0x0026 reads the
    /// settle's `c_n`/`x`/amounts from it). `None` for an offline boundary.
    pub fn dsm_verified_operation(&self) -> Option<&crate::types::operations::Operation> {
        match self {
            Self::DsmSuccessor(s) => Some(&s.verified_operation),
            Self::OfflineBoundary(_) => None,
        }
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
    /// The registered claim names another trader than the lineage under
    /// validation.
    RegisteredClaimNamesAnotherTrader,
    /// A `SofiSetup` names a predecessor position that is not the one its
    /// transition actually extends (F1: `p` is the position `ClaimRef_p`
    /// names, and the setup lands at `p + 1`).
    SetupPositionIsNotThePredecessor { body: u64, predecessor: u64 },
    /// A `SofiSetup`'s `R_T^setup` is not the root its own transition
    /// produces.
    ///
    /// The field is DERIVED, never asserted: it is the trader economic root
    /// after the P15-6 absent→`h⁰` insertion is applied to the root the
    /// parent claim names. Without this equality a correctly signed first
    /// setup could put ANY 32 bytes there, and the index would then pin a `ρ`
    /// committing them forever — the uniqueness rule would hold over a value
    /// nothing had checked.
    SetupRootIsNotTheDerivedRoot { body: [u8; 32], derived: [u8; 32] },
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
    /// The witness names an economic operation id that is not the v2 identity
    /// of the accepted successor (`H(G ‖ DevID ‖ C_dsm+)`).
    EconomicOperationIdMismatch {
        expected: [u8; 32],
        witness: [u8; 32],
    },
    /// The accepted substrate and the manifest's substrate slot are different
    /// KINDS (DSM successor vs offline boundary).
    SubstrateKindMismatch,
    /// Same kind, but the manifest names different substrate evidence than
    /// the acceptance actually used.
    SubstrateEvidenceMismatch {
        manifest: [u8; 32],
        accepted: [u8; 32],
    },
    /// Offline-boundary admissions have no specified write-set semantics yet
    /// (Step 5); fail closed rather than validate an unchecked boundary.
    OfflineBoundaryWriteSetNotYetSpecified,
    /// The witness is not the exact economic effect of the accepted
    /// operation.
    WriteSet(crate::economic::write_set::WriteSetError),
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
            Self::SetupPositionIsNotThePredecessor { body, predecessor } => write!(
                f,
                "economic validation: setup names predecessor position {body} but extends \
                 {predecessor} — `p` is the position the parent claim names, and the setup \
                 lands at p + 1"
            ),
            Self::SetupRootIsNotTheDerivedRoot { .. } => write!(
                f,
                "economic validation: the setup's R_T^setup is not the root its own \
                 transition produces — the field is DERIVED from the parent root by the \
                 P15-6 absent→h⁰ insertion, never asserted by the body"
            ),
            Self::RegisteredClaimNamesAnotherTrader => write!(
                f,
                "economic validation: the registered claim names another trader than the \
                 lineage under validation"
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
            Self::EconomicOperationIdMismatch { .. } => write!(
                f,
                "economic validation: the witness's economic operation id is not the v2 \
                 identity of the accepted successor — it names WHICH successor performed the \
                 operation, and this witness names a different one"
            ),
            Self::SubstrateKindMismatch => write!(
                f,
                "economic validation: the accepted substrate and the manifest's substrate slot \
                 are different kinds"
            ),
            Self::SubstrateEvidenceMismatch { .. } => write!(
                f,
                "economic validation: the manifest names different substrate evidence than the \
                 acceptance actually used — the evidence DAG would no longer be the evidence"
            ),
            Self::OfflineBoundaryWriteSetNotYetSpecified => write!(
                f,
                "economic validation: offline-boundary write-set semantics are not yet \
                 specified; failing closed"
            ),
            Self::WriteSet(e) => write!(f, "economic validation: {e}"),
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
) -> Result<ValidatedAdvance, EconomicValidationError> {
    if registered.trader_genesis() != *genesis || registered.trader_devid() != *device_id {
        return Err(EconomicValidationError::RegisteredClaimNamesAnotherTrader);
    }
    if previous.economic_root != witness.pre_economic_root {
        return Err(EconomicValidationError::PreRootIsNotThePredecessor {
            predecessor: previous.economic_root,
            witness_pre: witness.pre_economic_root,
        });
    }
    if registered.economic_position() != previous.economic_position.saturating_add(1) {
        return Err(EconomicValidationError::PositionIsNotSuccessor {
            previous: previous.economic_position,
            registered: registered.economic_position(),
        });
    }
    if registered.post_economic_root() != witness.post_economic_root {
        return Err(EconomicValidationError::RegisteredRootDiffersFromWitness {
            registered: registered.post_economic_root(),
            witness: witness.post_economic_root,
        });
    }
    // The clause that stops a valid successor being paired with a valid
    // transition for a DIFFERENT operation. For a DSM successor the digest is
    // DERIVED from the verified operation bytes inside the constructor, so
    // this equality reaches back to the operation itself.
    if accepted.operation_digest() != witness.operation_digest {
        return Err(EconomicValidationError::OperationDigestMismatch {
            substrate: accepted.operation_digest(),
            witness: witness.operation_digest,
        });
    }
    // SAME-KIND substrate binding: the manifest's substrate slot must name
    // the kind AND the exact evidence the acceptance used. Without this, a
    // caller validates one authenticated successor while the registered
    // manifest names a different evidence object — the transition might pass
    // on coinciding digests, but the evidence DAG would no longer be the
    // evidence actually used.
    match (accepted, &manifest.substrate) {
        (
            AcceptedSubstrate::DsmSuccessor(s),
            crate::economic::claim::AdmissionSubstrate::DsmSuccessor { evidence_addr },
        ) => {
            if *evidence_addr != s.evidence_addr {
                return Err(EconomicValidationError::SubstrateEvidenceMismatch {
                    manifest: *evidence_addr,
                    accepted: s.evidence_addr,
                });
            }
            // v2 operation identity: the witness must name THIS successor,
            // not merely this operation. Two successors can carry
            // byte-identical operations; `C_dsm+` is what tells them apart,
            // and `consumed_source.consumer_economic_operation_id` depends
            // on it being told apart.
            let expected = crate::economic::admission::dsm_economic_operation_id(
                genesis,
                device_id,
                &s.c_dsm_plus,
            );
            if expected != witness.economic_operation_id {
                return Err(EconomicValidationError::EconomicOperationIdMismatch {
                    expected,
                    witness: witness.economic_operation_id,
                });
            }
            // The operation ↔ write-set binding: the mutations must be the
            // EXACT semantic effect of the verified operation — no missing
            // mutation, no extra mutation, exact asset, exact amount, exact
            // role, exact source kind. Everything else here proves the write
            // set internally consistent and funded; THIS proves it is the
            // write set of this operation.
            crate::economic::write_set::verify_operation_write_set(
                &s.verified_operation,
                genesis,
                device_id,
                witness,
                registered.economic_position(),
            )
            .map_err(EconomicValidationError::WriteSet)?;
        }
        (
            AcceptedSubstrate::OfflineBoundary(b),
            crate::economic::claim::AdmissionSubstrate::OfflineBoundary { evidence_addr },
        ) => {
            if *evidence_addr != b.evidence_addr {
                return Err(EconomicValidationError::SubstrateEvidenceMismatch {
                    manifest: *evidence_addr,
                    accepted: b.evidence_addr,
                });
            }
            // Step 5 owes the boundary write-set semantics; an unchecked
            // boundary admission must not validate meanwhile.
            return Err(EconomicValidationError::OfflineBoundaryWriteSetNotYetSpecified);
        }
        _ => return Err(EconomicValidationError::SubstrateKindMismatch),
    }
    let computed = manifest.addr().map_err(EconomicValidationError::Manifest)?;
    if registered.admission_manifest_addr() != computed {
        return Err(EconomicValidationError::ManifestAddrMismatch {
            registered: registered.admission_manifest_addr(),
            computed,
        });
    }
    verify_manifest_provenance_index(manifest, witness)
        .map_err(EconomicValidationError::Manifest)?;

    let derived = verify_mutation_sequence(&witness.mutation_sequence(), genesis, device_id)
        .map_err(EconomicValidationError::Transition)?;

    // F1: `R_T^setup` IS THE ROOT THIS TRANSITION PRODUCES, and `p` is the
    // position it extends.
    //
    // `derived` comes from the verified mutation sequence, so comparing
    // against it is comparing against the root the P15-6 absent→`h⁰`
    // insertion actually yields from the predecessor — which is exactly the
    // normative relation, with nothing taken on the body's word. The
    // predecessor root is `previous.economic_root()`, the root the parent
    // claim names, and the setup lands at `p + 1`.
    //
    // `ClaimRef_p` is checked by `SetupValid` against the claim this
    // verifier accepted at `p` (SoFi Amendment S9); `p` and `R_T^setup` need
    // no such evidence, so they are established here.
    if let Some(crate::types::operations::Operation::SofiSetup { setup_body, .. }) =
        accepted.dsm_verified_operation()
    {
        let body = crate::sofi::wire::SofiSetupBody::decode(setup_body).map_err(|_| {
            EconomicValidationError::WriteSet(
                crate::economic::write_set::WriteSetError::MalformedVaultOperation {
                    detail: "a setup body that is not canonical has no write set",
                },
            )
        })?;
        if body.position() != previous.economic_position() {
            return Err(EconomicValidationError::SetupPositionIsNotThePredecessor {
                body: body.position(),
                predecessor: previous.economic_position(),
            });
        }
        if *body.setup_root() != derived {
            return Err(EconomicValidationError::SetupRootIsNotTheDerivedRoot {
                body: *body.setup_root(),
                derived,
            });
        }
    }

    // Conjunctive with everything above: the write set is closed AND every
    // credit in it is funded. Checked last because it is the most expensive
    // and the cheap structural clauses should reject first.
    // The canonical register set for the claimant's network, resolved
    // FAIL-CLOSED: an unknown network refuses rather than defaulting, and a
    // winning claim naming any other set is foreign whatever its bytes say.
    let profile =
        crate::economic::register::resolve_root_register_profile(network_id).map_err(|e| {
            EconomicValidationError::Provenance(ProvenanceError::RegisterNotResolvable(match e {
                crate::economic::register::RegisterResolutionError::UnknownNetwork { .. } => {
                    "no register profile for the claimant's network"
                }
                _ => "register profile not derivable",
            }))
        })?;
    // The set id is a function of `(member_id, register_incarnation_id)`
    // pairs, so it is re-derived from what the resolver offers and refused
    // unless the membership is exactly this network's. The resolver supplies
    // candidates; this is where they stop being taken on trust.
    let candidate = resolver
        .root_register_candidate_set(network_id)
        .map_err(|failure| {
            EconomicValidationError::Provenance(ProvenanceError::RegisterNotEstablished(failure))
        })?;
    // The candidate must re-derive the network's PINNED set id. Membership
    // alone would leave the incarnations to whatever the catalog offered.
    profile.verify_candidate(&candidate).map_err(|_| {
        EconomicValidationError::Provenance(ProvenanceError::RegisterNotResolvable(
            "the resolved register set is not this network's pinned register",
        ))
    })?;
    let canonical_set = profile.storage_set_id;
    let ctx = ProvenanceContext {
        genesis,
        device_id,
        economic_position: registered.economic_position(),
        network_id,
        proven_ak,
        canonical_storage_set_id: canonical_set,
        substrate_b_pair: accepted.dsm_successor_pair(),
        verified_operation: accepted.dsm_verified_operation(),
    };
    // THE MARKET-LEG TOKEN-POLICY CONJUNCT: a DLV successor's legs must
    // satisfy the applicable token policy (SoFi Def 4.1 / Req 4.4 / Req 4.6).
    // Central, on the VERIFIED operation, so fund and close are bound even
    // though their SameTransitionMove credits carry no evidence channel.
    // Non-DLV operations pass vacuously.
    let funded = verify_transition_provenance(witness, resolver, &ctx)
        .map_err(EconomicValidationError::Provenance)?;

    // A SoFi operation cannot reach here — `verify_operation_write_set`
    // refuses it by name above — and if it ever did, "no DLV transition"
    // would be a false statement about an operation that moves DLV
    // reserves. Each carries ITS OWN reason forward rather than one
    // borrowed from whichever arm was written first.
    if let Some(crate::types::operations::Operation::SofiFulfill { .. }) =
        accepted.dsm_verified_operation()
    {
        return Err(EconomicValidationError::WriteSet(
            crate::economic::write_set::WriteSetError::SofiWriteSetBelongsToTheResolvedPath,
        ));
    }

    Ok(ValidatedAdvance {
        root: ValidatedEconomicRoot {
            economic_position: registered.economic_position(),
            economic_root: derived,
        },
        funded,
        claim: AcceptedClaim {
            genesis: *genesis,
            device_id: *device_id,
            economic_position: registered.economic_position(),
            claim_ref: registered.claim_ref(),
        },
    })
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod admitted_position_tests {
    use super::*;
    use crate::sofi::lineage::{descendant_fence, FenceError, PredecessorClaim};

    const REALIZE: [u8; 32] = [0xA1; 32];
    const VOID: [u8; 32] = [0xB1; 32];
    const FID: [u8; 32] = [0xF1; 32];
    const CLAIM_REF: [u8; 32] = [0xC7; 32];

    /// AN UNRESOLVED POSITION MINTS NOTHING, from either of its two roots.
    ///
    /// The store used to hand back a bare `(position, root)` and this returned
    /// a validated root for it unconditionally — no verifier, on the device's
    /// own say-so. A conditional position has to put SOMETHING in a root
    /// column, and whatever went there would have been laundered into
    /// "validated" on the next restart.
    #[test]
    fn no_validated_root_is_minted_from_an_unresolved_position() {
        let unresolved = AdmittedEconomicPosition::UnresolvedSofi {
            economic_position: 9,
            fulfillment_id: FID,
            realize_root: REALIZE,
            void_root: VOID,
        };
        let refusal = ValidatedEconomicRoot::rehydrate_from_admitted_store(unresolved)
            .expect_err("it has selected no root");
        assert_eq!(
            refusal,
            PredecessorHasNotSelected {
                economic_position: 9,
                fulfillment_id: FID,
            }
        );
        // Neither committed root appears in the refusal: nothing read one.
        let rendered = refusal.to_string();
        for root in [REALIZE, VOID] {
            assert!(
                !rendered.contains(&crate::utils::text_id::encode_base32_crockford(&root)),
                "a committed root leaked: {rendered}"
            );
        }
    }

    /// A RESOLVED position yields EXACTLY the selected root — the one the
    /// route chose, not the one it could have chosen.
    #[test]
    fn a_resolved_position_yields_exactly_the_selected_root() {
        for selected in [REALIZE, VOID] {
            let resolved = AdmittedEconomicPosition::ResolvedSofi {
                economic_position: 9,
                selected_root: selected,
                fulfillment_id: FID,
                claim_ref: CLAIM_REF,
            };
            let validated = ValidatedEconomicRoot::rehydrate_from_admitted_store(resolved).unwrap();
            assert_eq!(validated.economic_root(), selected);
            assert_eq!(validated.economic_position(), 9);

            // And the fence admits a descendant on THAT root and no other.
            assert_eq!(
                descendant_fence(resolved.predecessor_claim(), &selected),
                Ok(())
            );
            let other = if selected == REALIZE { VOID } else { REALIZE };
            assert_eq!(
                descendant_fence(resolved.predecessor_claim(), &other),
                Err(FenceError::PreRootIsNotTheSelectedRoot {
                    selected,
                    descendant_pre: other,
                })
            );
        }
    }

    /// The kind decides what the position can parent, and the three answers
    /// are distinct.
    #[test]
    fn the_claim_kind_decides_what_may_descend() {
        let ordinary = AdmittedEconomicPosition::SingleRoot {
            economic_position: 9,
            economic_root: REALIZE,
            claim_ref: CLAIM_REF,
        };
        assert_eq!(ordinary.predecessor_claim(), PredecessorClaim::SingleRoot);
        // An ordinary position is unconstrained by the fence: its own root is
        // checked by the equality the caller already performs.
        assert_eq!(
            descendant_fence(ordinary.predecessor_claim(), &VOID),
            Ok(())
        );

        let unresolved = AdmittedEconomicPosition::UnresolvedSofi {
            economic_position: 9,
            fulfillment_id: FID,
            realize_root: REALIZE,
            void_root: VOID,
        };
        assert_eq!(
            unresolved.predecessor_claim(),
            PredecessorClaim::ConditionalUnresolved
        );
        for attempt in [REALIZE, VOID] {
            assert_eq!(
                descendant_fence(unresolved.predecessor_claim(), &attempt),
                Err(FenceError::PredecessorIsUnresolved),
                "neither branch may be guessed"
            );
        }
    }
}
