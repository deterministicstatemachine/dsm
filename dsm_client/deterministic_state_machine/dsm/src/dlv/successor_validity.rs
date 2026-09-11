// SPDX-License-Identifier: Apache-2.0

//! WHAT MAKES A DLV CONTINUATION VALID.
//!
//! Amendment 2c-C3 froze `ValidDlvSuccessorCore`; this module is its executable
//! form. It is deliberately sans-IO and lives in core rather than the SDK for
//! the same reason [`crate::dlv::route_commit`] does: a foreign economic
//! verifier must be able to recompute the predicate without any SDK machinery,
//! and both the SDK composition walk and [`crate::economic::provenance`] have
//! to reach ONE predicate rather than two that can drift.
//!
//! The shape the amendment fixes, and the reason for each part:
//!
//! - **Derivation is TYPED AND PARTIAL.** [`DeriveExpected`] returns a
//!   successor, or a refusal carrying its exact class and reason. A total
//!   function returning a successor would hide failed arithmetic, unavailable
//!   evidence and invalid authorization inside an apparently successful call,
//!   and the caller would then compare bytes against a value that should never
//!   have been produced.
//! - **The verdict is CLASS-SAFE.** [`C3Verdict`] carries its payload per
//!   class, so `Complete(INCOMPLETE)` and `Refused(VALID)` are not merely
//!   undocumented — they are unconstructible.
//! - **`INCOMPLETE` is not `INVALID`.** Not learning a fact is not learning its
//!   negation (Rev 15 Req 6.25). The distinction decides whether a caller
//!   retries or refuses forever, and collapsing it is the defect this taxonomy
//!   exists to remove.
//!
//! - **`VDS.COMMON.10.a` is performed here, and only here.**
//!   [`check_correspondence`] compares `Canon(expected)` against the exact
//!   supplied byte span of the bound bundle's field-2 successor (amendment
//!   2c-A.1, the wiring point) and returns a [`CorrespondenceWitness`] on
//!   equality — the only way one is made. The walk takes `c_{n+1}` from the
//!   witness, derived from the SUPPLIED bytes, never from its local state.
//! - **Preserved- and mutated-field equality are consequences of `10.a`**
//!   (Ruling B), not conjuncts of their own: a supplied successor that changed
//!   a preserved field encodes differently and fails the comparison. There is
//!   no second per-field predicate beside the frozen one.
//!
//! # What this module does NOT establish
//!
//! - **That a market settlement actually occurred.** See
//!   [`IndependentRealization`] — a trader receipt cannot establish it, and
//!   this module has no way to construct one.
//! - **`TokenPolicyValid`** (Ruling H) and the terminal close's exactly-once
//!   **owner credit** (Ruling G). Both are declared external obligations; the
//!   complete protocol predicate is
//!   `ValidDlvSuccessor := ValidDlvSuccessorCore ∧ TokenPolicyValid`.

use crate::ccb::{MarketPolicy, VaultStateV2};
use crate::dlv::route_commit::{constant_product_output_classified, ConstantProductRefusal};

// ============================================================
// Layer 1 — the class
// ============================================================

/// The four outcomes of any C3 conjunct. Layer 1 of the frozen taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeClass {
    /// The conjunct held.
    Valid,
    /// The conjunct is decidably false.
    Invalid,
    /// The evidence needed to decide it is genuinely missing. A caller may
    /// retry; it may never conclude the claim is false.
    Incomplete,
    /// A proven contradiction in the storage substrate — not a failed check.
    SafetyViolation,
}

impl OutcomeClass {
    /// A stable name for logs and for crossing a boundary.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Valid => "VALID",
            Self::Invalid => "INVALID",
            Self::Incomplete => "INCOMPLETE",
            Self::SafetyViolation => "SAFETY_VIOLATION",
        }
    }
}

impl core::fmt::Display for OutcomeClass {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ============================================================
// Layer 2 — the reason
// ============================================================

/// The exact reason a conjunct did not hold. Layer 2 REFINES layer 1 and never
/// competes with it.
///
/// These are the codes frozen in `lean4/DSMValidDlvSuccessor.lean`, mirrored
/// here rather than paraphrased — a Rust vocabulary that drifted from the
/// proved one would make the proof describe a different predicate. The two
/// lists are kept in lockstep: when this implementation needed a code the model
/// lacked, the MODEL was extended first (see the last three).
///
/// Codes for storage-set change, quorum change and `r_o` change are absent **by
/// design**: Ruling B derives those from the byte comparison rather than making
/// them conjuncts. Their absence here is the frozen shape, not an omission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// `V_n` did not authenticate against `c_n`.
    ParentUnauthenticated,
    /// The operation names a different vault than the authenticated parent.
    VaultMismatch,
    /// The operation names a different generation than the parent.
    GenerationMismatch,
    /// The successor's parent reference is not this parent's `c_n`.
    StaleParent,
    /// `{input, output}` is not the parent's committed market pair.
    PairNotVaultPair,
    /// `a = 0`.
    InputAmountZero,
    /// `x = 0`.
    ReserveInZero,
    /// `y = 0`.
    ReserveOutZero,
    /// `f >= D`.
    FeeAtOrAboveDenominator,
    /// The floor division truncated to zero.
    OutputZero,
    /// `output > R_out`.
    OutputExceedsReserve,
    /// A checked product exceeded its width.
    ArithmeticOverflow,
    /// `β` is present and zero: inadmissible, no successor exists.
    BudgetExhausted,
    /// The operation consumes an encumbrance claim the parent does not hold.
    ClaimNotHeld,
    /// The successor violates `Σ amount(e) ≤ R_t` for some token.
    SolvencyViolated,
    /// `Canon(expected) != supplied` — the bundle's field-2 successor is not
    /// the successor this verifier derives (`VDS.COMMON.10.a`). Every
    /// preserved- and mutated-field disposition of Ruling B lands here.
    CorrespondenceMismatch,
    /// A market successor was proposed for a retired parent.
    ComposeFromRetiredParent,
    /// The embedded settler key is not the externally resolved authority.
    SettlerKeyMismatch,
    /// A quorum of members each explicitly hold nothing at this key. Positive
    /// evidence that this successor never won exclusivity — decidably false,
    /// not unlearned.
    NoBindingEstablished,
    /// Attributed, but neither a chosen value nor a quorum of absences. A value
    /// already chosen behind a down member lands here: retryable evidence, and
    /// **neither emptiness nor forgery**.
    BindingUndetermined,
    /// Fewer than `q` attributed answers. Req 6.25's
    /// `DLV_BINDING_EVIDENCE_UNAVAILABLE`, which is a NORMATIVE code rather
    /// than an implementation name.
    BindingEvidenceUnavailable,
    /// Two distinct binding-final bundles at one DLV parent (Req 6.3).
    DuplicateBindingFinality,

    // ---- clause-table conjuncts the Lean model originally omitted ----
    //
    // Found when this implementation had to choose a code for each and the
    // model had none. Each was reconciled against the merged clause table,
    // found NORMATIVE there, added to the Lean model, and only then here:
    //
    //   SuccessorSignatureInvalid   VDS.COMMON.11, VDS.CLOSE.2
    //   BundleNotCanonical          Ruling J's `operation : Invalid(reason)` arm
    //   BundleForeignToVault        VDS.COMMON.5 "and storage_set_id re-derives",
    //                               VDS.COMMON.6 "and equals the canonical n/2+1"
    //                               -- the SECOND clauses of those rows
    //   RealizationEvidenceInvalid  Ruling J's `economic_facts : Invalid(reason)` arm
    //
    // NONE of these is a field equality. The FIRST clauses of COMMON.5/6 and
    // all of COMMON.14 -- successor field equals parent field -- are what
    // Ruling B derives from VDS.COMMON.10.a alone; codes for those would build
    // a second acceptance predicate beside the frozen one. Deliberately absent.
    /// `VDS.COMMON.11` / `VDS.CLOSE.2` — the advancing party's (for a close,
    /// the owner's) signature over the concrete successor does not verify. A
    /// signature is not a field equality, so this is independent of `10.a`.
    SuccessorSignatureInvalid,
    /// The bound bundle is not a canonical settlement bundle: it does not
    /// decode, does not re-encode, does not hash to the record's identity, or
    /// has no valid shape. A structural fact about bytes in hand.
    BundleNotCanonical,
    /// The bound bundle was bound under a storage set or quorum this vault did
    /// not commit. (A bundle that consumes no leg of the vault is
    /// [`Reason::VaultMismatch`] — `VDS.COMMON.1.a` — not this.)
    BundleForeignToVault,
    /// Ruling J's `economic_facts : Invalid(reason)` arm: realization evidence
    /// that is PRESENT and fails verification — a receipt whose signature does
    /// not verify, a RouteCommit that does not recompute the bundle's `X`, a
    /// claimed output the state's curve does not yield.
    ///
    /// `INVALID`, never absence: a fetched-but-forged receipt is not the same
    /// fact as no receipt, and mapping it to absence let a forged receipt fold
    /// as "not settled yet". Deliberately NOT a safety violation — a bad
    /// signature establishes invalid evidence, not a substrate contradiction,
    /// and quarantining on it would let anyone able to inject a forged receipt
    /// force a denial-of-service quarantine.
    RealizationEvidenceInvalid,
    /// 2c-C3.1 ruling G — a DURABLE quarantine root of this vault refuses this
    /// cursor or this execution. Distinct from
    /// [`Reason::DuplicateBindingFinality`], which is the live observation that
    /// created the root: the refused cursor's own key may read `BoundFinal` or
    /// `Free`, so reporting a duplicate there would be false.
    /// `SAFETY_VIOLATION`, never convertible to `INVALID` or `INCOMPLETE`.
    /// Added to the Lean inventory first (`DSMLineageQuarantine.lean`).
    LineageQuarantined,
}

impl Reason {
    /// The class this reason always carries. Fixing it here is what stops a
    /// caller pairing a reason with a class it does not belong to.
    pub const fn class(&self) -> OutcomeClass {
        match self {
            Self::DuplicateBindingFinality | Self::LineageQuarantined => {
                OutcomeClass::SafetyViolation
            }
            Self::ParentUnauthenticated
            | Self::BindingUndetermined
            | Self::BindingEvidenceUnavailable => OutcomeClass::Incomplete,
            _ => OutcomeClass::Invalid,
        }
    }

    /// A stable name for logs and for crossing a boundary.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ParentUnauthenticated => "PARENT_UNAUTHENTICATED",
            Self::VaultMismatch => "VAULT_MISMATCH",
            Self::GenerationMismatch => "GENERATION_MISMATCH",
            Self::StaleParent => "STALE_PARENT",
            Self::PairNotVaultPair => "PAIR_NOT_VAULT_PAIR",
            Self::InputAmountZero => "INPUT_AMOUNT_ZERO",
            Self::ReserveInZero => "RESERVE_IN_ZERO",
            Self::ReserveOutZero => "RESERVE_OUT_ZERO",
            Self::FeeAtOrAboveDenominator => "FEE_AT_OR_ABOVE_DENOMINATOR",
            Self::OutputZero => "OUTPUT_ZERO",
            Self::OutputExceedsReserve => "OUTPUT_EXCEEDS_RESERVE",
            Self::ArithmeticOverflow => "ARITHMETIC_OVERFLOW",
            Self::BudgetExhausted => "BUDGET_EXHAUSTED",
            Self::ClaimNotHeld => "CLAIM_NOT_HELD",
            Self::SolvencyViolated => "SOLVENCY_VIOLATED",
            Self::CorrespondenceMismatch => "CORRESPONDENCE_MISMATCH",
            Self::ComposeFromRetiredParent => "COMPOSE_FROM_RETIRED_PARENT",
            Self::SettlerKeyMismatch => "SETTLER_KEY_MISMATCH",
            Self::NoBindingEstablished => "NO_BINDING_ESTABLISHED",
            Self::BindingUndetermined => "BINDING_UNDETERMINED",
            Self::BindingEvidenceUnavailable => "DLV_BINDING_EVIDENCE_UNAVAILABLE",
            Self::DuplicateBindingFinality => "DUPLICATE_BINDING_FINALITY",
            Self::SuccessorSignatureInvalid => "SUCCESSOR_SIGNATURE_INVALID",
            Self::BundleNotCanonical => "BUNDLE_NOT_CANONICAL",
            Self::BundleForeignToVault => "BUNDLE_FOREIGN_TO_VAULT",
            Self::RealizationEvidenceInvalid => "REALIZATION_EVIDENCE_INVALID",
            Self::LineageQuarantined => "LINEAGE_QUARANTINED",
        }
    }
}

impl core::fmt::Display for Reason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", self.class().as_str(), self.as_str())
    }
}

impl From<ConstantProductRefusal> for Reason {
    fn from(r: ConstantProductRefusal) -> Self {
        match r {
            ConstantProductRefusal::InputAmountZero => Self::InputAmountZero,
            ConstantProductRefusal::ReserveInZero => Self::ReserveInZero,
            ConstantProductRefusal::ReserveOutZero => Self::ReserveOutZero,
            ConstantProductRefusal::FeeAtOrAboveDenominator => Self::FeeAtOrAboveDenominator,
            ConstantProductRefusal::ArithmeticOverflow => Self::ArithmeticOverflow,
            ConstantProductRefusal::OutputZero => Self::OutputZero,
        }
    }
}

// ============================================================
// Ruling I — settler identity is derived authority, never self-assertion
// ============================================================

/// The SPHINCS+ attestation-key width. A DevID is 32 bytes; an AK is 64. The
/// production route once fell back to a DevID for the settler key, which could
/// never satisfy the correspondence check and yet passed the device-head
/// advance. Making the widths different TYPES is what stops that recurring.
pub const AUTHORITY_KEY_LEN: usize = 64;

/// A device identity. Never an authority key, whatever its bytes look like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DevId(pub [u8; 32]);

/// An authority (attestation) public key. Constructible only at the right
/// width, so DevID bytes cannot be passed where a key belongs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityPublicKey(Vec<u8>);

impl AuthorityPublicKey {
    /// Refuses anything that is not AK-width. `VDS.COMMON.12`: a settler key
    /// of the wrong width is not a key that could correspond to any authority.
    pub fn try_new(bytes: &[u8]) -> Result<Self, Reason> {
        if bytes.len() != AUTHORITY_KEY_LEN {
            return Err(Reason::SettlerKeyMismatch);
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// `VDS.COMMON.12` — settler identity correspondence (Ruling I).
///
/// The operation's embedded `settler_public_key` and `settler_devid` are
/// CORRESPONDENCE CLAIMS. They are checked against identity established
/// EXTERNALLY -- the proven authority key and the DevID ordinary DSM authority
/// resolution produced -- and are never their own source. Pinning is
/// commitment; this is what makes the commitment checkable.
pub fn check_settler_correspondence(
    embedded_key: &AuthorityPublicKey,
    embedded_devid: &DevId,
    proven_ak: &AuthorityPublicKey,
    established_devid: &DevId,
) -> Result<(), Reason> {
    if embedded_key != proven_ak || embedded_devid != established_devid {
        return Err(Reason::SettlerKeyMismatch);
    }
    Ok(())
}

// ============================================================
// The C3 / C4 seam — what an advance carries about a DLV successor
// ============================================================

/// What `advance_validated` established about the DLV successor, if the
/// verified operation was one.
///
/// This is the seam amendment 2c-C4 fills. `advance_validated` verifies the
/// transition's provenance -- for a DLV settle or close, that is the economic
/// arm's parent authentication, pair/fee/quorum axes, binding observation and
/// bundle checks -- and until now discarded that fact into `Ok(())`. It does
/// NOT hold `V_n`, so it cannot yet produce a full [`C3Verdict`]; the walk that
/// carries the parent state is C4's. Widening the return here means C4's
/// change is a PAYLOAD change, not a signature change at every call site.
///
/// A non-DLV operation is `NoDlvTransition`, vacuously.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuccessorValidity {
    /// The verified operation is not a DLV transition; nothing to say.
    NoDlvTransition,
    /// The verified operation is a DLV transition and provenance established
    /// its conjuncts. The KIND is all this carries.
    ///
    /// 2c-C4 ruling V2 deleted the verdict slot rather than filling it. A
    /// verdict here would be produced by the trader's own admission path, and
    /// ruling V1 makes the ordered third-party composition walk the only
    /// authoritative constructor of a market verdict — so a slot on this type
    /// could only ever hold a value no foreign verifier may trust. The typed
    /// intermediate fact that survives is the kind.
    DlvTransition { kind: DlvTransitionKind },
}

/// Which DLV family the verified operation belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlvTransitionKind {
    Settle,
    Close,
}

// ============================================================
// Erratum D2 — retirement has no tuple field
// ============================================================

/// Both reserve legs drained. Amendment 2c-C3 erratum D2.
///
/// Rev 15 requires a terminal close to "mark the DLV terminal/retired" and
/// `VaultStateV2` has no such field. It needs none: market admissibility
/// forbids `a = 0`, so a market successor always leaves at least one strictly
/// positive leg (see [`market_never_retires`] in the tests). Both-zero is
/// therefore reachable ONLY by the close family, and is unambiguous.
pub fn is_retired(state: &VaultStateV2) -> bool {
    state.reserve_a == 0 && state.reserve_b == 0
}

// ============================================================
// Erratum D4 — `direction` is derived, and the derivation is total
// ============================================================

/// Which reserve leg the operation pays in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Input is `token_a`; `x = R_A`, `y = R_B`.
    AtoB,
    /// Input is `token_b`; `x = R_B`, `y = R_A`.
    BtoA,
}

/// Amendment 2c-C3 erratum D4.
///
/// `direction` is carried by neither `T_v`, `Allocation`, nor `V_n`. It is
/// derived from set-equality between the operation's two policy commitments and
/// the parent's committed pair.
///
/// **The derivation is total**, and the same check that establishes membership
/// is what makes it so: [`MarketPolicy::beta_constant_product`] refuses an
/// unordered *or equal* pair, so `token_a < token_b` strictly. Equal input and
/// output commitments therefore cannot match a strictly ordered pair, and every
/// case that survives has exactly one branch.
pub fn derive_direction(
    policy: &MarketPolicy,
    input_policy_commit: &[u8; 32],
    output_policy_commit: &[u8; 32],
) -> Option<Direction> {
    if input_policy_commit == policy.token_a() && output_policy_commit == policy.token_b() {
        Some(Direction::AtoB)
    } else if input_policy_commit == policy.token_b() && output_policy_commit == policy.token_a() {
        Some(Direction::BtoA)
    } else {
        None
    }
}

/// **The asset pair and orientation, as an explicit predicate** (2c-D §14,
/// C2-R2).
///
/// `{input, output}` must be the parent's committed market pair in one
/// permitted orientation, and [`derive_direction`] must succeed for exactly
/// that orientation. No unknown asset, same-side asset, or foreign policy
/// commitment reaches successor comparison. Stated here rather than left to
/// the helper so the asset binding is auditable at the point it is required;
/// both constant-product orientations are permitted in beta, so no direction
/// is disallowed.
pub fn check_market_orientation(
    parent: &VaultStateV2,
    input_policy_commit: &[u8; 32],
    output_policy_commit: &[u8; 32],
) -> Result<Direction, Reason> {
    let pair = [
        parent.market_policy.token_a(),
        parent.market_policy.token_b(),
    ];
    if input_policy_commit == output_policy_commit
        || !pair.contains(&input_policy_commit)
        || !pair.contains(&output_policy_commit)
    {
        return Err(Reason::PairNotVaultPair);
    }
    derive_direction(
        &parent.market_policy,
        input_policy_commit,
        output_policy_commit,
    )
    .ok_or(Reason::PairNotVaultPair)
}

/// **CORR.5's derivation for a market successor** (2c-D §14, C2-R2), from the
/// ACCEPTED operation the lineage walk verified.
///
/// ```text
/// orientation            check_market_orientation, before anything is derived
/// op.parent_sequence  == parent.generation
/// op.fee_bps          == Φ(V_n)
/// derive_market_successor(parent, c_n, {op pair, op.input_amount, Φ(V_n)})
/// derived output      == op.output_amount
/// ```
///
/// The caller then compares `Canon(expected)` with `T_v.successor` (`10.a`).
/// CORR.4 ties the operation to the route; this ties it to `T_v`.
pub fn derive_accepted_market_successor(
    parent: &VaultStateV2,
    c_n: [u8; 32],
    accepted: &AcceptedTransition,
) -> DeriveExpected {
    let direction = match check_market_orientation(
        parent,
        &accepted.input_policy_commit,
        &accepted.output_policy_commit,
    ) {
        Ok(d) => d,
        Err(r) => return DeriveExpected::Refused(r),
    };
    if accepted.parent_sequence != parent.generation {
        return DeriveExpected::Refused(Reason::GenerationMismatch);
    }
    let phi = parent.fee_policy.fee_bps();
    if accepted.fee_bps != phi {
        return DeriveExpected::Refused(Reason::RealizationEvidenceInvalid);
    }
    let next = match derive_market_successor(
        parent,
        c_n,
        &MarketTerms {
            input_policy_commit: accepted.input_policy_commit,
            output_policy_commit: accepted.output_policy_commit,
            input_amount: accepted.input_amount,
            fee_bps: phi,
        },
    ) {
        DeriveExpected::Derived(next) => next,
        refused => return refused,
    };
    let (out_before, out_after) = match direction {
        Direction::AtoB => (parent.reserve_b, next.reserve_b),
        Direction::BtoA => (parent.reserve_a, next.reserve_a),
    };
    match out_before.checked_sub(out_after) {
        Some(paid) if paid == accepted.output_amount => DeriveExpected::Derived(next),
        _ => DeriveExpected::Refused(Reason::RealizationEvidenceInvalid),
    }
}

// ============================================================
// Ruling F — the budget rule
// ============================================================

/// `β` for the successor, per amendment 2c-C3 ruling F.
///
/// ```text
/// absent          -> absent          (nothing to decrement)
/// present, n > 0  -> present, n - 1
/// present, n == 0 -> INADMISSIBLE; no successor exists
/// ```
///
/// Introduction and removal are both unreachable: this function maps absence to
/// absence and presence to presence, so neither can be expressed. Under
/// derive-and-compare a change to the presence marker is a BYTE change, which is
/// why the marker itself has to be derivable rather than merely preserved.
pub fn next_budget(budget: Option<u64>) -> Result<Option<u64>, Reason> {
    match budget {
        None => Ok(None),
        Some(0) => Err(Reason::BudgetExhausted),
        Some(n) => Ok(Some(n - 1)),
    }
}

// ============================================================
// The typed, partial derivation
// ============================================================

/// The result of deriving the successor a verifier would accept.
///
/// This is the routing table's `ApplyDlvTransition`, renamed: it derives an
/// EXPECTED successor and applies nothing to live state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeriveExpected {
    /// The successor this verifier would accept for the operation.
    Derived(Box<VaultStateV2>),
    /// A conjunct decided against the operation.
    Refused(Reason),
}

impl DeriveExpected {
    /// The class of this result. `Derived` is `Valid`; a refusal carries the
    /// class its own reason fixes.
    pub const fn class(&self) -> OutcomeClass {
        match self {
            Self::Derived(_) => OutcomeClass::Valid,
            Self::Refused(r) => r.class(),
        }
    }
}

/// The fact that a market settlement ACTUALLY OCCURRED.
///
/// A trader settlement receipt cannot establish this on its own: the legacy
/// verifier reads the public key, genesis, DevID and root out of the receipt,
/// and the cheapest tree satisfying its inclusion check has one leaf. The fact
/// is built instead from THREE independently established facts, each of which
/// has exactly one constructor:
///
/// ```text
/// MarketCorrespondence      CORR.1-CORR.5          check_market_correspondence
/// BundleAcceptanceWitness   2c-D §7, and only §7   verify_trader_acceptance
/// IntentSatisfaction        2c-E §6 SAT.1-SAT.6    check_intent_satisfaction
/// ```
///
/// The third is C2's (2c-D §14, ruling C2-R2): `may_certify()` must be
/// unreachable unless Tier-1 intent satisfaction held, and the 5-c-1 gate that
/// was its only live enforcement point is deleted by the same change. Making it
/// a required argument is what makes that a type error rather than a review
/// comment. A struct literal remains impossible:
///
/// ```compile_fail
/// use dsm::dlv::successor_validity::IndependentRealization;
/// let _ = IndependentRealization {
///     _corr: unreachable!(),
///     _acceptance: unreachable!(),
///     _intent: unreachable!(),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndependentRealization {
    _corr: MarketCorrespondence,
    _acceptance: BundleAcceptanceWitness,
    _intent: IntentSatisfaction,
}

/// **2c-D's conjunct: this acceptance realizes THIS bundle `b`.**
///
/// The bundle-acceptance leaf under the validated root, whose authenticated
/// content commits `b` (amendment 2c §9.1's two-conjunct rule). There is no
/// constructor here and 2c-C4 may not add one: an amendment cannot verify an
/// object whose fields another amendment defines, and `0x0011`'s field table
/// and `0x0032`'s leaf are both 2c-D's.
///
/// It is what keeps *"the right trader transition happened"* from standing in
/// for *"…for this exact `b`"* — the binding gap 2c-D exists to close.
///
/// It now HAS a constructor — 2c-D §7's verifier — but not a public one, so
/// the impossibility is unchanged for anything outside this crate. Both the
/// struct literal and the constructor are unreachable:
///
/// ```compile_fail
/// use dsm::dlv::successor_validity::BundleAcceptanceWitness;
/// let _ = BundleAcceptanceWitness {
///     bundle: [0u8; 32],
///     economic_operation_id: [0u8; 32],
///     economic_root: [0u8; 32],
/// };
/// ```
///
/// ```compile_fail
/// use dsm::dlv::successor_validity::BundleAcceptanceWitness;
/// let _ = BundleAcceptanceWitness::from_verified_acceptance([0u8; 32], [0u8; 32], [0u8; 32]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleAcceptanceWitness {
    /// The exact bundle the authenticated acceptance leaf committed.
    bundle: [u8; 32],
    /// The authenticated economic operation identity that fixed the leaf's
    /// position, and which §7 required to equal the walk's own recomputation.
    economic_operation_id: [u8; 32],
    /// The validated economic root the acceptance path folded to.
    economic_root: [u8; 32],
}

impl BundleAcceptanceWitness {
    /// **The only constructor, and `pub(crate)` so nothing outside this crate
    /// can mint one.** 2c-D §7's verifier is its single caller; that is pinned
    /// by `the_acceptance_witness_has_exactly_one_construction_site`, because
    /// `pub(crate)` alone would let any module in this crate assert the fact
    /// without doing the work.
    ///
    /// It is not `pub`: a caller outside the crate holding this type must have
    /// received it from the verifier, so HOLDING one is the fact that §7's
    /// conjuncts held — the same property [`MarketCorrespondence`] has.
    pub(crate) const fn from_verified_acceptance(
        bundle: [u8; 32],
        economic_operation_id: [u8; 32],
        economic_root: [u8; 32],
    ) -> Self {
        Self {
            bundle,
            economic_operation_id,
            economic_root,
        }
    }

    /// The exact `b` this acceptance realizes — authenticated, because it was
    /// read from a leaf whose inclusion under the validated root was proven.
    pub const fn bundle(&self) -> [u8; 32] {
        self.bundle
    }

    /// The authenticated economic operation identity.
    pub const fn economic_operation_id(&self) -> [u8; 32] {
        self.economic_operation_id
    }

    /// The validated economic root the path folded to.
    pub const fn economic_root(&self) -> [u8; 32] {
        self.economic_root
    }
}

/// The accepted `DlvSettle` the ordered walk validated, as `CORR` reads it
/// (2c-C4 §4). Every field comes from the transition the walk VALIDATED, never
/// from the bundle's carried bytes and never from a published receipt.
///
/// **The balance effects are typed (2c-D §14, ruling C2-R2).** They used to be
/// one opaque digest that no production code computed, which made CORR.4 — and
/// with it every market realization — unreachable. They are now the operation's
/// own fields, and the only way to obtain them is
/// [`AcceptedTransition::from_verified_settle`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedTransition {
    /// The accepted successor's own parent on the trader's bilateral chain.
    pub embedded_parent: [u8; 32],
    /// `C_dsm+`, recomputed by the walk, never carried (2c-B ruling 1).
    pub c_dsm_plus: [u8; 32],
    /// The trade identity the accepted operation names.
    pub external_commitment_x: [u8; 32],
    /// The vault parent the accepted operation consumes.
    pub parent_binding: [u8; 32],
    /// The vault generation the accepted operation consumes.
    pub parent_sequence: u64,
    /// The asset the trader paid into the vault, and how much.
    pub input_policy_commit: [u8; 32],
    pub input_amount: u64,
    /// The asset the vault paid out, and how much.
    pub output_policy_commit: [u8; 32],
    pub output_amount: u64,
    /// The fee rate the operation states.
    pub fee_bps: u32,
}

impl AcceptedTransition {
    /// The accepted effects of a VERIFIED `DlvSettle`, with the successor pair
    /// the same walk recomputed. `None` for any other operation: a transition
    /// that is not a settle has no market effects to correspond.
    ///
    /// `operation` must be the lineage walk's verified operation — the same
    /// bytes `sigma_dsm` authenticated — and never the bundle's
    /// `recovery_material`, which is what CORR compares AGAINST.
    pub fn from_verified_settle(
        embedded_parent: [u8; 32],
        c_dsm_plus: [u8; 32],
        operation: &crate::types::operations::Operation,
    ) -> Option<Self> {
        let crate::types::operations::Operation::DlvSettle {
            parent_binding,
            parent_sequence,
            external_commitment_x,
            input_policy_commit,
            input_amount,
            output_policy_commit,
            output_amount,
            fee_bps,
            ..
        } = operation
        else {
            return None;
        };
        Some(Self {
            embedded_parent,
            c_dsm_plus,
            external_commitment_x: *external_commitment_x,
            parent_binding: *parent_binding,
            parent_sequence: *parent_sequence,
            input_policy_commit: *input_policy_commit,
            input_amount: *input_amount,
            output_policy_commit: *output_policy_commit,
            output_amount: *output_amount,
            fee_bps: *fee_bps,
        })
    }
}

/// The market coordinates `B` carries, as `CORR` compares them. Read from the
/// decoded bundle; the two coordinate systems are never mixed (2c-C4 §2).
///
/// The route's economics are the ONE beta allocation (2c-A ruling 3), typed.
/// The only constructor that reads a bundle is
/// [`BundleCoordinates::from_market_bundle`], which refuses every other shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleCoordinates {
    pub trader_parent: [u8; 32],
    pub trader_successor: [u8; 32],
    pub route_set_commitment: [u8; 32],
    /// The single allocation's `c_n`, amounts and fee rate.
    pub leg_parent_binding: [u8; 32],
    pub leg_delta_in: u64,
    pub leg_delta_out: u64,
    pub leg_fee_bps: u32,
    /// The parent binding the bundle's one `T_v` names.
    pub transition_parent_binding: [u8; 32],
}

impl BundleCoordinates {
    /// The coordinates of a BETA market bundle: exactly one route leg, that leg
    /// a bare `Allocation`, and exactly one `T_v` (2c-A ruling 3).
    ///
    /// Any other shape is `BundleNotCanonical` — "not specified for this
    /// profile" (2c-D §14, C2-R2), never a shape this function tries to read.
    pub fn from_market_bundle(
        terms: &crate::ccb::MarketTerms,
        transitions: &[crate::ccb::ConsumedDlvTransition],
    ) -> Result<Self, Reason> {
        let alloc = beta_allocation(&terms.selected_route)?;
        let [transition] = transitions else {
            return Err(Reason::BundleNotCanonical);
        };
        Ok(Self {
            trader_parent: terms.trader_parent,
            trader_successor: terms.trader_successor,
            route_set_commitment: terms.route_set_commitment,
            leg_parent_binding: alloc.parent_binding,
            leg_delta_in: alloc.delta_in,
            leg_delta_out: alloc.delta_out,
            leg_fee_bps: alloc.fee_policy.fee_bps(),
            transition_parent_binding: transition.parent_binding,
        })
    }
}

/// The one allocation a beta route may carry, or `BundleNotCanonical`.
fn beta_allocation(route: &crate::ccb::Route) -> Result<&crate::ccb::Allocation, Reason> {
    match route.legs() {
        [crate::ccb::RouteLeg::Single(alloc)] => Ok(alloc),
        _ => Err(Reason::BundleNotCanonical),
    }
}

/// C4's own half of realization: `CORR.1`–`CORR.5` all held for one candidate.
///
/// Private fields and one constructor, [`check_market_correspondence`], so a
/// value of this type IS the fact that the equalities were checked. It is not
/// realization — [`IndependentRealization`] additionally needs 2c-D's
/// [`BundleAcceptanceWitness`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarketCorrespondence {
    witness: CorrespondenceWitness,
    cursor_c_n: [u8; 32],
}

impl MarketCorrespondence {
    /// The `VDS.COMMON.10.a` witness this correspondence rests on (CORR.5).
    pub fn witness(&self) -> &CorrespondenceWitness {
        &self.witness
    }

    /// The vault cursor whose `c_n` the accepted operation consumed (CORR.3).
    pub const fn cursor_c_n(&self) -> [u8; 32] {
        self.cursor_c_n
    }
}

/// **`CORR.1`–`CORR.5`** (2c-C4 §4). Sans-IO: the caller supplies the accepted
/// transition the walk validated, the coordinates `B` carries, the cursor, and
/// the `10.a` witness.
///
/// What this establishes and what it does not: it establishes that the trader
/// accepted the exact transition `B` names, priced as `B`'s route says,
/// consuming the cursor `B`'s transition names. **It does not establish that
/// the acceptance realizes THIS bundle `b`** — that step is
/// [`BundleAcceptanceWitness`]'s, and 2c-D's.
///
/// `CORR.1` is C4's own cross-object check and is NOT 2c-B's deferred
/// chain-tip conjunct: this compares the pair the WALK VALIDATED against `B`'s
/// coordinates, where 2c-B's compares a recomputed tip against `B`'s own
/// carried bytes. The two can hold or fail independently.
pub fn check_market_correspondence(
    accepted: &AcceptedTransition,
    bundle: &BundleCoordinates,
    cursor_c_n: [u8; 32],
    witness: CorrespondenceWitness,
) -> Result<MarketCorrespondence, Reason> {
    // CORR.1 — the accepted pair IS the bundle's pair.
    if accepted.embedded_parent != bundle.trader_parent
        || accepted.c_dsm_plus != bundle.trader_successor
    {
        return Err(Reason::RealizationEvidenceInvalid);
    }
    // CORR.2 — one trade identity.
    if accepted.external_commitment_x != bundle.route_set_commitment {
        return Err(Reason::RealizationEvidenceInvalid);
    }
    // CORR.3 — the accepted settle consumes THIS cursor. A settle naming
    // another parent is stale here in exactly C3's sense.
    if accepted.parent_binding != cursor_c_n {
        return Err(Reason::StaleParent);
    }
    // CORR.4 — the effects are the selected route's economics, TYPED and one
    // equality at a time (2c-D §14, C2-R2), so a mutation dropping any single
    // field is caught by a test named for it.
    if bundle.leg_parent_binding != accepted.parent_binding
        || bundle.transition_parent_binding != accepted.parent_binding
    {
        return Err(Reason::RealizationEvidenceInvalid);
    }
    if bundle.leg_delta_in != accepted.input_amount {
        return Err(Reason::RealizationEvidenceInvalid);
    }
    if bundle.leg_delta_out != accepted.output_amount {
        return Err(Reason::RealizationEvidenceInvalid);
    }
    if bundle.leg_fee_bps != accepted.fee_bps {
        return Err(Reason::RealizationEvidenceInvalid);
    }
    // CORR.5 — the byte correspondence held at the cursor. Structural: a
    // `CorrespondenceWitness` exists only because `check_correspondence`
    // returned it, and its parent must be the cursor this correspondence is
    // about, or the two halves describe different parents.
    if witness.parent_commitment() != cursor_c_n {
        return Err(Reason::CorrespondenceMismatch);
    }
    Ok(MarketCorrespondence {
        witness,
        cursor_c_n,
    })
}

impl IndependentRealization {
    /// **The realization fact, 2c-C4 §5, completed by 2c-D.** C4's own half,
    /// 2c-D's acceptance witness, and the Tier-1 intent fact C2 re-sourced.
    /// Each argument exists only because its one verifier returned it.
    pub fn from_parts(
        correspondence: MarketCorrespondence,
        acceptance: BundleAcceptanceWitness,
        intent: IntentSatisfaction,
    ) -> Self {
        Self {
            _corr: correspondence,
            _acceptance: acceptance,
            _intent: intent,
        }
    }
}

/// **Tier-1 intent satisfaction held** — 2c-E §6 `SAT.1`–`SAT.6` for the
/// authenticated `TradeIntent` and the selected route.
///
/// Private field and one constructor, [`check_intent_satisfaction`], so
/// holding one IS the fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentSatisfaction {
    intent: crate::ccb::TradeIntent,
}

impl IntentSatisfaction {
    /// The intent that was shown satisfied.
    pub fn intent(&self) -> &crate::ccb::TradeIntent {
        &self.intent
    }
}

/// What Tier 1 is checked from. Every operand is authenticated: the intent and
/// route are `B`'s own decoded fields, and the RouteCommit is the one inside
/// the lineage-verified operation, which `sigma_dsm` covers — never a
/// RouteCommit fetched under a storage key (2c-D §14, D-a).
#[derive(Debug, Clone, Copy)]
pub struct IntentEvidence<'a> {
    pub intent: &'a crate::ccb::TradeIntent,
    pub route: &'a crate::ccb::Route,
    /// The VERIFIED operation's `route_commit_bytes`.
    pub route_commit_bytes: &'a [u8],
    pub vault_id: &'a [u8; 32],
    /// The trader authority the lineage walk proved.
    pub proven_ak: &'a [u8],
}

/// **2c-E §6, `SAT.1`–`SAT.6`** — the exact-output restatement of 2c-A's
/// Tier 1, which is what C2 re-sources (2c-D §14, D-a). 2c-A's original
/// `min_out`, `max_fee`, `max_hops`, `max_fanout` and `k` are not evaluated:
/// 2c-E removed them from `TradeIntent`.
///
/// ```text
/// SAT.1  I is B's decoded field 1; nothing carried stands in for it (structural)
/// SAT.2  the RouteCommit's signature verifies, and under the PROVEN key
/// SAT.3  the intent's tokens, amounts and fee equal the signed hop
/// SAT.4  the selected route's one leg equals the signed hop
/// SAT.5  re-simulating V_n at Φ(V_n) reproduces exact_out EXACTLY
/// SAT.6  the intent's fee rate is Φ(V_n)'s
/// ```
///
/// SAT.5 re-simulates from the INTENT against the authenticated `V_n`, not from
/// the route and not by reusing CORR.5's derivation: 2c-E is explicit that the
/// value `exact_out` is checked against must come from authenticated state.
pub fn check_intent_satisfaction(
    evidence: &IntentEvidence<'_>,
    parent: &VaultStateV2,
    c_n: [u8; 32],
) -> Result<IntentSatisfaction, Reason> {
    let intent = evidence.intent;
    let alloc = beta_allocation(evidence.route)?;

    // SAT.2 — pure verification: decode, schema, signature, the hop for THIS
    // vault, bound to THIS parent. Then the signing key must be the proven one.
    let hop = crate::dlv::route_commit::verify_route_commit_hop(
        evidence.route_commit_bytes,
        evidence.vault_id,
        &c_n,
    )
    .map_err(|e| match e {
        crate::dlv::route_commit::RouteHopError::ParentBindingMismatch => Reason::StaleParent,
        _ => Reason::RealizationEvidenceInvalid,
    })?;
    if hop.initiator_public_key.as_slice() != evidence.proven_ak {
        return Err(Reason::SettlerKeyMismatch);
    }

    // SAT.3 — the intent IS what the trader signed.
    if intent.token_in != hop.token_in
        || intent.token_out != hop.token_out
        || intent.amount_in != hop.input_amount
        || intent.exact_out != hop.expected_output
        || intent.fee_bps != hop.fee_bps
    {
        return Err(Reason::RealizationEvidenceInvalid);
    }

    // SAT.4 — the selected route's one leg IS the signed hop. The hop's
    // parent binding was verified equal to `c_n` above.
    if alloc.parent_binding != c_n {
        return Err(Reason::StaleParent);
    }
    if alloc.delta_in != hop.input_amount
        || alloc.delta_out != hop.expected_output
        || alloc.fee_policy.fee_bps() != hop.fee_bps
    {
        return Err(Reason::RealizationEvidenceInvalid);
    }

    // SAT.6 — the vault's fee is the authority.
    let phi = parent.fee_policy.fee_bps();
    if intent.fee_bps != phi {
        return Err(Reason::RealizationEvidenceInvalid);
    }

    // SAT.5 — the independent fact, from authenticated state.
    let direction = check_market_orientation(parent, &intent.token_in, &intent.token_out)?;
    let (reserve_in, reserve_out) = match direction {
        Direction::AtoB => (parent.reserve_a, parent.reserve_b),
        Direction::BtoA => (parent.reserve_b, parent.reserve_a),
    };
    let reproduced =
        constant_product_output_classified(intent.amount_in, reserve_in, reserve_out, phi)
            .map_err(Reason::from)?;
    if reproduced != intent.exact_out {
        return Err(Reason::RealizationEvidenceInvalid);
    }

    Ok(IntentSatisfaction {
        intent: intent.clone(),
    })
}

/// `VDS.COMMON.10.a` held for one candidate: `Canon(expected)` is
/// byte-for-byte the successor the bound bundle carries.
///
/// Private fields and no public constructor — one exists only because
/// [`check_correspondence`] returned it, so holding one IS the fact. `c_next`
/// is derived from the SUPPLIED bytes; by injectivity of the canonical
/// encoding (`canonVault_injective`) it equals the commitment of `expected`,
/// and the walk installs the witness's value rather than recomputing its own.
///
/// ```compile_fail
/// use dsm::dlv::successor_validity::CorrespondenceWitness;
/// let _ = CorrespondenceWitness {
///     expected: Box::new(unreachable!()),
///     parent_commitment: [0; 32],
///     c_next: [0; 32],
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrespondenceWitness {
    expected: Box<VaultStateV2>,
    parent_commitment: [u8; 32],
    c_next: [u8; 32],
}

impl CorrespondenceWitness {
    /// The successor the verifier derived — and, by the comparison that made
    /// this witness, the one the bundle carries.
    pub fn expected(&self) -> &VaultStateV2 {
        &self.expected
    }

    /// The parent `c_n` the successor was derived from.
    pub const fn parent_commitment(&self) -> [u8; 32] {
        self.parent_commitment
    }

    /// `c_{n+1} = H_dom(DSM/vault-state, supplied bytes)`.
    pub const fn c_next(&self) -> [u8; 32] {
        self.c_next
    }
}

/// `VDS.COMMON.10.a`: `Canon(expected) == supplied`, else
/// `CORRESPONDENCE_MISMATCH`.
///
/// `supplied` is the exact byte span of the bound bundle's field-2 successor
/// as fetched — never a re-encoding of anything this verifier holds, or the
/// comparison would be of the verifier against itself. An `expected` with no
/// canonical form cannot equal any supplied span, so an encoding failure is
/// the same refusal.
pub fn check_correspondence(
    expected: &VaultStateV2,
    parent_commitment: [u8; 32],
    supplied: &[u8],
) -> Result<CorrespondenceWitness, Reason> {
    let canon = expected
        .encode()
        .map_err(|_| Reason::CorrespondenceMismatch)?;
    if canon.as_slice() != supplied {
        return Err(Reason::CorrespondenceMismatch);
    }
    Ok(CorrespondenceWitness {
        expected: Box::new(expected.clone()),
        parent_commitment,
        c_next: crate::ccb::vault_state_commitment_of_canon(supplied),
    })
}

/// What C3 concluded about one candidate successor.
///
/// **Class-safe by construction.** Each protocol class carries its own payload,
/// so a result cannot be built that pairs one class with another's evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum C3Verdict {
    /// Every applicable conjunct was evaluated and held.
    ///
    /// Reachable for an OWNER CLOSE through
    /// [`CompleteValidity::from_close_witness`] — its conjuncts are all
    /// present-tense once `10.a` is. A market successor additionally needs an
    /// [`IndependentRealization`], which only
    /// [`IndependentRealization::from_parts`] builds: correspondence, a
    /// [`BundleAcceptanceWitness`] and [`IntentSatisfaction`], all three.
    Valid(CompleteValidity),
    /// A conjunct decided against the successor.
    Invalid(Reason),
    /// The evidence to decide a conjunct is missing. Retryable; never a
    /// conclusion that the successor is false.
    Incomplete(Reason),
    /// A proven contradiction in the storage substrate (Req 6.3).
    SafetyViolation(Reason),
}

/// Evidence that every conjunct held.
///
/// Private field and exactly two constructors, the same discipline
/// `ValidatedEconomicRoot` uses: there is no network event that declares a
/// successor fully valid, and no `assume_valid` shortcut to add later in a
/// hurry. [`Self::from_close_witness`] is the owner-close path — the witness
/// is the last conjunct a close has. [`Self::from_market_witness`] also takes
/// an [`IndependentRealization`], which only
/// [`IndependentRealization::from_parts`] builds, so
/// `2c-A + 10.a = market valid` is a compile error rather than a rule: the
/// realization fact cannot be had without a [`BundleAcceptanceWitness`], and
/// that has one constructor, behind §7.
///
/// Pinned by the compiler, not by convention — this does not build:
///
/// ```compile_fail
/// use dsm::dlv::successor_validity::{C3Verdict, CompleteValidity};
/// let claimed = C3Verdict::Valid(CompleteValidity {
///     witness: unreachable!(),
/// });
/// assert!(claimed.may_certify());
/// ```
///
/// and neither does the default-construction route:
///
/// ```compile_fail
/// use dsm::dlv::successor_validity::CompleteValidity;
/// let _ = CompleteValidity::default();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteValidity {
    witness: CorrespondenceWitness,
}

impl CompleteValidity {
    /// An owner close whose `10.a` held. The close's other conjuncts — the
    /// parent authenticated, the owner's authorization over the exact release
    /// successor verified, the derivation itself — are established before a
    /// witness can exist, because the witness compares against the derived
    /// successor.
    pub fn from_close_witness(witness: CorrespondenceWitness) -> Self {
        Self { witness }
    }

    /// A market successor whose `10.a` held AND whose settlement is
    /// independently established — the composition walk's certification, and
    /// the only way a market fold reaches [`C3Verdict::may_certify`].
    pub fn from_market_witness(
        witness: CorrespondenceWitness,
        realization: IndependentRealization,
    ) -> Self {
        let IndependentRealization { .. } = realization;
        Self { witness }
    }

    /// The correspondence this validity rests on.
    pub fn witness(&self) -> &CorrespondenceWitness {
        &self.witness
    }
}

impl C3Verdict {
    /// The class, for callers that branch on it.
    pub const fn class(&self) -> OutcomeClass {
        match self {
            Self::Valid(_) => OutcomeClass::Valid,
            Self::Invalid(_) => OutcomeClass::Invalid,
            Self::Incomplete(_) => OutcomeClass::Incomplete,
            Self::SafetyViolation(_) => OutcomeClass::SafetyViolation,
        }
    }

    /// Whether the successor may cross a boundary whose semantics require FULL
    /// `ValidDlvSuccessorCore` — accepted-successor finality, fence release,
    /// accepted-frontier advancement. The walk folds nothing that fails this
    /// (2c-D §14): a market fold without its realization fact is the
    /// bound-but-unrealized frontier, not a provisional fold.
    pub const fn may_certify(&self) -> bool {
        matches!(self, Self::Valid(_))
    }
}

// ============================================================
// The derivations
// ============================================================

/// The owner-close successor: drain both legs and retire the vault.
///
/// `OWNER_LOCAL_FULL_CLOSE` takes no parameters — "there is nothing left to
/// parameterise" — so it can express no authority, membership or threshold
/// change, and fields 13/14/15 are invariant on this kind for that reason
/// rather than by separate rule.
pub fn derive_close_successor(parent: &VaultStateV2, c_n: [u8; 32]) -> DeriveExpected {
    if is_retired(parent) {
        return DeriveExpected::Refused(Reason::ComposeFromRetiredParent);
    }
    let budget = match next_budget(parent.iteration_budget) {
        Ok(b) => b,
        Err(r) => return DeriveExpected::Refused(r),
    };
    let mut next = parent.clone();
    next.generation = parent.generation.saturating_add(1);
    next.reserve_a = 0;
    next.reserve_b = 0;
    next.parent_state_commitment = c_n;
    next.iteration_budget = budget;
    DeriveExpected::Derived(Box::new(next))
}

/// The market operation's economic terms, as the predicate needs them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarketTerms {
    pub input_policy_commit: [u8; 32],
    pub output_policy_commit: [u8; 32],
    pub input_amount: u64,
    pub fee_bps: u32,
}

/// The beta market successor: constant product, with the fee left in the pool.
///
/// Amendment 2c-C3 erratum D3 — `fee_t ≡ 0` in §7.1's conservation identity for
/// this family. The fee is not withheld, not routed elsewhere and not
/// represented anywhere in the successor; it shifts the curve and stays inside
/// the reserves. A verifier applying §7.1 with a non-zero `fee_t` rejects every
/// valid beta market successor.
pub fn derive_market_successor(
    parent: &VaultStateV2,
    c_n: [u8; 32],
    terms: &MarketTerms,
) -> DeriveExpected {
    if is_retired(parent) {
        return DeriveExpected::Refused(Reason::ComposeFromRetiredParent);
    }
    let Some(direction) = derive_direction(
        &parent.market_policy,
        &terms.input_policy_commit,
        &terms.output_policy_commit,
    ) else {
        return DeriveExpected::Refused(Reason::PairNotVaultPair);
    };
    let (reserve_in, reserve_out) = match direction {
        Direction::AtoB => (parent.reserve_a, parent.reserve_b),
        Direction::BtoA => (parent.reserve_b, parent.reserve_a),
    };
    let output = match constant_product_output_classified(
        terms.input_amount,
        reserve_in,
        reserve_out,
        terms.fee_bps,
    ) {
        Ok(o) => o,
        Err(refusal) => return DeriveExpected::Refused(refusal.into()),
    };
    if output > reserve_out {
        return DeriveExpected::Refused(Reason::OutputExceedsReserve);
    }
    let budget = match next_budget(parent.iteration_budget) {
        Ok(b) => b,
        Err(r) => return DeriveExpected::Refused(r),
    };
    let (Some(new_in), Some(new_out)) = (
        reserve_in.checked_add(terms.input_amount),
        reserve_out.checked_sub(output),
    ) else {
        return DeriveExpected::Refused(Reason::ArithmeticOverflow);
    };
    let (reserve_a, reserve_b) = match direction {
        Direction::AtoB => (new_in, new_out),
        Direction::BtoA => (new_out, new_in),
    };
    let mut next = parent.clone();
    next.generation = parent.generation.saturating_add(1);
    next.reserve_a = reserve_a;
    next.reserve_b = reserve_b;
    next.parent_state_commitment = c_n;
    next.iteration_budget = budget;
    DeriveExpected::Derived(Box::new(next))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccb::{EncumbranceSet, FeePolicy, ReleasePolicy, StorageSetMembers};

    fn policy() -> MarketPolicy {
        MarketPolicy::beta_constant_product([0x10; 32], [0x20; 32]).expect("ordered pair")
    }

    fn parent(reserve_a: u64, reserve_b: u64, budget: Option<u64>) -> VaultStateV2 {
        VaultStateV2 {
            owner_genesis_id: [1; 32],
            owner_device_id: [2; 32],
            vault_id: [3; 32],
            generation: 7,
            reserve_a,
            reserve_b,
            market_policy: policy(),
            release_policy: ReleasePolicy::beta_owner_local_full_close(),
            fee_policy: FeePolicy::new(30).expect("fee below denominator"),
            encumbrances: EncumbranceSet::empty(),
            iteration_budget: budget,
            parent_state_commitment: [4; 32],
            owner_authority_transition_digest: [5; 32],
            storage_set: StorageSetMembers::new(&[(b"dsm-node-1".as_slice(), [9; 32])])
                .expect("one member"),
            quorum: 1,
        }
    }

    fn terms(input: [u8; 32], output: [u8; 32], amount: u64) -> MarketTerms {
        MarketTerms {
            input_policy_commit: input,
            output_policy_commit: output,
            input_amount: amount,
            fee_bps: 30,
        }
    }

    // ---------- erratum D4: the direction derivation is total ----------

    /// The set-equality check that establishes membership ALSO refutes
    /// `input == output`: equal commitments cannot match a strictly ordered
    /// pair, so no surviving case is ambiguous.
    #[test]
    fn equal_commitments_can_never_derive_a_direction() {
        let p = policy();
        assert_eq!(derive_direction(&p, p.token_a(), p.token_a()), None);
        assert_eq!(derive_direction(&p, p.token_b(), p.token_b()), None);
    }

    #[test]
    fn each_ordered_pair_derives_exactly_one_direction() {
        let p = policy();
        assert_eq!(
            derive_direction(&p, p.token_a(), p.token_b()),
            Some(Direction::AtoB)
        );
        assert_eq!(
            derive_direction(&p, p.token_b(), p.token_a()),
            Some(Direction::BtoA)
        );
    }

    #[test]
    fn a_foreign_token_derives_no_direction() {
        let p = policy();
        assert_eq!(derive_direction(&p, &[0xFF; 32], p.token_b()), None);
    }

    // ---------- erratum D2: retirement is unambiguous ----------

    /// The whole argument for erratum D2. Market admissibility forbids `a = 0`,
    /// so the input leg is `R_in + a > 0` and at least one leg stays strictly
    /// positive. Both-zero is therefore reachable ONLY by the close family,
    /// which is what makes `is_retired` a sound marker with no new tuple field.
    #[test]
    fn market_never_retires() {
        let p = policy();
        // Amounts large enough to clear the floor division against these
        // reserves; a dust amount would refuse with OUTPUT_ZERO, which is a
        // different property and has its own test.
        for amount in [10u64, 100, 1_000] {
            for (input, output) in [(p.token_a(), p.token_b()), (p.token_b(), p.token_a())] {
                let v = parent(1_000, 1_000, None);
                let DeriveExpected::Derived(next) =
                    derive_market_successor(&v, [7; 32], &terms(*input, *output, amount))
                else {
                    panic!("a well-formed market hop must derive");
                };
                assert!(
                    !is_retired(&next),
                    "a market successor must never be retired"
                );
            }
        }
    }

    #[test]
    fn the_close_retires_and_the_market_refuses_a_retired_parent() {
        let v = parent(1_000, 1_000, None);
        let DeriveExpected::Derived(closed) = derive_close_successor(&v, [7; 32]) else {
            panic!("a funded vault must close");
        };
        assert!(is_retired(&closed));

        let p = policy();
        assert_eq!(
            derive_market_successor(&closed, [8; 32], &terms(*p.token_a(), *p.token_b(), 10)),
            DeriveExpected::Refused(Reason::ComposeFromRetiredParent)
        );
        assert_eq!(
            derive_close_successor(&closed, [8; 32]),
            DeriveExpected::Refused(Reason::ComposeFromRetiredParent)
        );
    }

    // ---------- ruling F: the budget rule ----------

    #[test]
    fn the_budget_rule_maps_absence_to_absence_and_decrements_presence() {
        assert_eq!(next_budget(None), Ok(None));
        assert_eq!(next_budget(Some(3)), Ok(Some(2)));
        assert_eq!(next_budget(Some(1)), Ok(Some(0)));
        assert_eq!(next_budget(Some(0)), Err(Reason::BudgetExhausted));
    }

    /// Introduction and removal are not merely forbidden, they are
    /// INEXPRESSIBLE: the rule maps absence to absence and presence to
    /// presence, so no input produces the other marker.
    #[test]
    fn the_budget_presence_marker_can_never_change() {
        assert!(next_budget(None).expect("absent is admissible").is_none());
        for n in [1u64, 2, 9] {
            assert!(
                next_budget(Some(n))
                    .expect("positive is admissible")
                    .is_some(),
                "a present budget must stay present"
            );
        }
    }

    #[test]
    fn an_exhausted_budget_admits_no_successor_of_either_kind() {
        let v = parent(1_000, 1_000, Some(0));
        let p = policy();
        assert_eq!(
            derive_close_successor(&v, [7; 32]),
            DeriveExpected::Refused(Reason::BudgetExhausted)
        );
        assert_eq!(
            derive_market_successor(&v, [7; 32], &terms(*p.token_a(), *p.token_b(), 10)),
            DeriveExpected::Refused(Reason::BudgetExhausted)
        );
    }

    #[test]
    fn a_present_budget_is_decremented_by_both_kinds() {
        let v = parent(1_000, 1_000, Some(4));
        let p = policy();
        let DeriveExpected::Derived(closed) = derive_close_successor(&v, [7; 32]) else {
            panic!("close derives");
        };
        assert_eq!(closed.iteration_budget, Some(3));
        let DeriveExpected::Derived(market) =
            derive_market_successor(&v, [7; 32], &terms(*p.token_a(), *p.token_b(), 10))
        else {
            panic!("market derives");
        };
        assert_eq!(market.iteration_budget, Some(3));
    }

    // ---------- the admissibility conditions each carry their own reason ----------

    /// The `Option` form of the arithmetic collapses a dust trade and a
    /// malformed hop into one `None`. C3 requires them apart, and this is the
    /// test that proves they are.
    #[test]
    fn each_admissibility_condition_refuses_with_its_own_reason() {
        let p = policy();
        let (a, b) = (*p.token_a(), *p.token_b());

        let cases: [(VaultStateV2, MarketTerms, Reason); 4] = [
            (
                parent(1_000, 1_000, None),
                terms(a, b, 0),
                Reason::InputAmountZero,
            ),
            (
                parent(0, 1_000, None),
                terms(a, b, 10),
                Reason::ReserveInZero,
            ),
            (
                parent(1_000, 0, None),
                terms(a, b, 10),
                Reason::ReserveOutZero,
            ),
            (
                parent(1_000, 1_000, None),
                MarketTerms {
                    fee_bps: 10_000,
                    ..terms(a, b, 10)
                },
                Reason::FeeAtOrAboveDenominator,
            ),
        ];
        for (v, t, expected) in cases {
            assert_eq!(
                derive_market_successor(&v, [7; 32], &t),
                DeriveExpected::Refused(expected),
                "{expected:?} must be reported as itself"
            );
        }
    }

    /// A trade too small to move the pool is `OUTPUT_ZERO` — a legitimately
    /// shaped hop, distinct from a malformed one.
    #[test]
    fn a_dust_trade_is_output_zero_and_not_a_malformed_hop() {
        let p = policy();
        let v = parent(1_000_000, 1, None);
        assert_eq!(
            derive_market_successor(&v, [7; 32], &terms(*p.token_a(), *p.token_b(), 1)),
            DeriveExpected::Refused(Reason::OutputZero)
        );
    }

    // ---------- the taxonomy is class-safe ----------

    /// Every reason carries exactly one class, and the three that are NOT
    /// `Invalid` are the ones the frozen taxonomy singles out.
    #[test]
    fn every_reason_carries_exactly_one_class() {
        for r in [Reason::DuplicateBindingFinality, Reason::LineageQuarantined] {
            assert_eq!(r.class(), OutcomeClass::SafetyViolation, "{r:?}");
        }
        for r in [
            Reason::ParentUnauthenticated,
            Reason::BindingUndetermined,
            Reason::BindingEvidenceUnavailable,
        ] {
            assert_eq!(r.class(), OutcomeClass::Incomplete, "{r:?}");
        }
        for r in [
            Reason::NoBindingEstablished,
            Reason::SettlerKeyMismatch,
            Reason::ComposeFromRetiredParent,
            Reason::CorrespondenceMismatch,
            Reason::SuccessorSignatureInvalid,
            Reason::BundleNotCanonical,
            Reason::BundleForeignToVault,
            Reason::RealizationEvidenceInvalid,
        ] {
            assert_eq!(r.class(), OutcomeClass::Invalid, "{r:?}");
        }
    }

    /// `Free` is INVALID and `Undetermined` is INCOMPLETE, and they are
    /// distinguishable. Collapsing either into the other is the misclassification
    /// the binding-observation module warns about: reading `Undetermined` as
    /// free composes past a live bind; reading it as a forgery makes every
    /// concurrent settle permanently invalid.
    #[test]
    fn no_binding_and_undetermined_are_different_facts() {
        assert_ne!(
            Reason::NoBindingEstablished.class(),
            Reason::BindingUndetermined.class()
        );
        assert_ne!(
            Reason::BindingUndetermined,
            Reason::BindingEvidenceUnavailable,
            "mid-flight and unreachable are different facts"
        );
    }

    /// A witness exists only because the bytes matched; it carries the
    /// derived successor, its parent, and `c_{n+1}` from the SUPPLIED bytes —
    /// which equals the commitment of the derived successor, by injectivity.
    #[test]
    fn a_witness_is_made_by_equality_and_names_c_next_from_the_supplied_bytes() {
        let v = parent(1_000, 1_000, None);
        let supplied = v.encode().expect("encodes");
        let w = check_correspondence(&v, [7; 32], &supplied).expect("bytes equal");
        assert_eq!(*w.expected(), v);
        assert_eq!(w.parent_commitment(), [7; 32]);
        assert_eq!(
            w.c_next(),
            crate::ccb::vault_state_commitment(&v).expect("commits")
        );
    }

    /// One byte off — anywhere — is `CORRESPONDENCE_MISMATCH`, class Invalid.
    /// So is a supplied span that is longer or shorter than the canonical
    /// encoding: the comparison is over the whole span.
    #[test]
    fn any_byte_difference_is_a_correspondence_mismatch() {
        let v = parent(1_000, 1_000, None);
        let canon = v.encode().expect("encodes");
        for i in [0usize, 4, 100, canon.len() - 1] {
            let mut supplied = canon.clone();
            supplied[i] ^= 0x01;
            assert_eq!(
                check_correspondence(&v, [7; 32], &supplied).unwrap_err(),
                Reason::CorrespondenceMismatch,
                "byte {i}"
            );
        }
        let mut longer = canon.clone();
        longer.push(0);
        assert_eq!(
            check_correspondence(&v, [7; 32], &longer).unwrap_err(),
            Reason::CorrespondenceMismatch
        );
        assert_eq!(
            check_correspondence(&v, [7; 32], &canon[..canon.len() - 1]).unwrap_err(),
            Reason::CorrespondenceMismatch
        );
        assert_eq!(
            Reason::CorrespondenceMismatch.class(),
            OutcomeClass::Invalid
        );
    }

    // ---------- 2c-C4 §4: CORR.1..5, one negative per conjunct ----------

    fn corr_fixture() -> (
        AcceptedTransition,
        BundleCoordinates,
        [u8; 32],
        CorrespondenceWitness,
    ) {
        let v = parent(1_000, 1_000, None);
        let cursor = [0x3C; 32];
        let w =
            check_correspondence(&v, cursor, &v.encode().expect("encodes")).expect("bytes equal");
        let accepted = AcceptedTransition {
            embedded_parent: [0x11; 32],
            c_dsm_plus: [0x12; 32],
            external_commitment_x: [0x13; 32],
            parent_binding: cursor,
            parent_sequence: 7,
            input_policy_commit: [0x10; 32],
            input_amount: 100,
            output_policy_commit: [0x20; 32],
            output_amount: 90,
            fee_bps: 30,
        };
        let bundle = BundleCoordinates {
            trader_parent: [0x11; 32],
            trader_successor: [0x12; 32],
            route_set_commitment: [0x13; 32],
            leg_parent_binding: cursor,
            leg_delta_in: 100,
            leg_delta_out: 90,
            leg_fee_bps: 30,
            transition_parent_binding: cursor,
        };
        (accepted, bundle, cursor, w)
    }

    /// The honest triple corresponds, and the correspondence carries both the
    /// witness and the cursor it is about.
    #[test]
    fn a_corresponding_transition_yields_the_correspondence() {
        let (a, b, cursor, w) = corr_fixture();
        let c = check_market_correspondence(&a, &b, cursor, w.clone())
            .expect("the honest triple corresponds");
        assert_eq!(c.cursor_c_n(), cursor);
        assert_eq!(*c.witness(), w);
    }

    /// CORR.1 — a foreign trader parent, and a foreign trader successor. Two
    /// halves of one conjunct, each separately necessary.
    #[test]
    fn a_foreign_accepted_pair_does_not_correspond() {
        let (a, b, cursor, w) = corr_fixture();
        let mut wrong = a;
        wrong.embedded_parent = [0xEE; 32];
        assert_eq!(
            check_market_correspondence(&wrong, &b, cursor, w.clone()),
            Err(Reason::RealizationEvidenceInvalid)
        );
        let mut wrong = a;
        wrong.c_dsm_plus = [0xEE; 32];
        assert_eq!(
            check_market_correspondence(&wrong, &b, cursor, w),
            Err(Reason::RealizationEvidenceInvalid)
        );
    }

    /// CORR.2 — the accepted operation names a different trade.
    #[test]
    fn a_foreign_trade_identity_does_not_correspond() {
        let (a, b, cursor, w) = corr_fixture();
        let mut wrong = a;
        wrong.external_commitment_x = [0xEE; 32];
        assert_eq!(
            check_market_correspondence(&wrong, &b, cursor, w),
            Err(Reason::RealizationEvidenceInvalid)
        );
    }

    /// CORR.3 — the accepted operation consumes some other vault parent. That
    /// is STALE_PARENT in exactly C3's sense, not a generic evidence failure.
    #[test]
    fn an_accepted_settle_on_another_cursor_is_stale() {
        let (a, b, cursor, w) = corr_fixture();
        let mut wrong = a;
        wrong.parent_binding = [0xEE; 32];
        assert_eq!(
            check_market_correspondence(&wrong, &b, cursor, w),
            Err(Reason::StaleParent)
        );
    }

    /// CORR.4 — the effects are not the selected route's economics. This is
    /// the conjunct that stops a trader accepting the exactly-right transition
    /// at the wrong price. TYPED (2c-D §14, C2-R2): every field is its own
    /// equality, so each one is exercised alone.
    #[test]
    fn effects_that_are_not_the_routes_economics_do_not_correspond() {
        type Alteration = (&'static str, fn(&mut BundleCoordinates));
        let alterations: [Alteration; 5] = [
            ("the leg's parent binding", |b| {
                b.leg_parent_binding = [0xEE; 32]
            }),
            ("T_v's parent binding", |b| {
                b.transition_parent_binding = [0xEE; 32]
            }),
            ("delta_in", |b| b.leg_delta_in += 1),
            ("delta_out", |b| b.leg_delta_out -= 1),
            ("the leg's fee rate", |b| b.leg_fee_bps += 1),
        ];
        for (what, alter) in alterations {
            let (a, mut b, cursor, w) = corr_fixture();
            alter(&mut b);
            assert_eq!(
                check_market_correspondence(&a, &b, cursor, w),
                Err(Reason::RealizationEvidenceInvalid),
                "a route whose {what} differs from the accepted operation must not correspond"
            );
        }
    }

    /// CORR.5 — a witness about a DIFFERENT parent. The two halves would
    /// otherwise describe different cursors while each looked internally
    /// consistent.
    #[test]
    fn a_witness_about_another_parent_does_not_correspond() {
        let (a, b, cursor, _) = corr_fixture();
        let v = parent(1_000, 1_000, None);
        let elsewhere = check_correspondence(&v, [0x9E; 32], &v.encode().expect("encodes"))
            .expect("bytes equal");
        assert_ne!(elsewhere.parent_commitment(), cursor);
        assert_eq!(
            check_market_correspondence(&a, &b, cursor, elsewhere),
            Err(Reason::CorrespondenceMismatch)
        );
    }

    /// A close's correspondence witness is its last conjunct, so it
    /// certifies. A market has no such shortcut: the same witness reaches
    /// `Valid` only through `from_market_witness`, whose realization argument
    /// the `compile_fail` doctests on `CompleteValidity` pin as unforgeable.
    #[test]
    fn a_close_witness_certifies() {
        let v = parent(1_000, 1_000, None);
        let supplied = v.encode().expect("encodes");
        let w = check_correspondence(&v, [7; 32], &supplied).expect("bytes equal");
        let close = C3Verdict::Valid(CompleteValidity::from_close_witness(w.clone()));
        assert!(close.may_certify(), "a close's 10.a is its last conjunct");
        assert_eq!(close.class(), OutcomeClass::Valid);
        let C3Verdict::Valid(cv) = close else {
            unreachable!()
        };
        assert_eq!(*cv.witness(), w);
    }

    #[test]
    fn a_refused_verdict_never_certifies() {
        for v in [
            C3Verdict::Invalid(Reason::StaleParent),
            C3Verdict::Incomplete(Reason::BindingEvidenceUnavailable),
            C3Verdict::SafetyViolation(Reason::DuplicateBindingFinality),
        ] {
            assert!(!v.may_certify(), "{v:?}");
        }
    }

    /// Req 6.25's normative code survives the taxonomy split. It names a
    /// genuine INCOMPLETE and must not be repurposed or deleted.
    #[test]
    fn the_req_6_25_code_is_preserved_and_is_incomplete() {
        assert_eq!(
            Reason::BindingEvidenceUnavailable.as_str(),
            "DLV_BINDING_EVIDENCE_UNAVAILABLE"
        );
        assert_eq!(
            Reason::BindingEvidenceUnavailable.class(),
            OutcomeClass::Incomplete
        );
    }
    // ---------- ruling I: settler identity ----------

    fn ak(b: u8) -> AuthorityPublicKey {
        AuthorityPublicKey::try_new(&[b; AUTHORITY_KEY_LEN]).expect("64 bytes")
    }

    #[test]
    fn a_matching_key_and_devid_correspond() {
        assert_eq!(
            check_settler_correspondence(&ak(7), &DevId([1; 32]), &ak(7), &DevId([1; 32])),
            Ok(())
        );
    }

    /// Correct DevID, different valid-width key: INVALID.
    #[test]
    fn a_different_valid_width_key_is_rejected() {
        assert_eq!(
            check_settler_correspondence(&ak(7), &DevId([1; 32]), &ak(8), &DevId([1; 32])),
            Err(Reason::SettlerKeyMismatch)
        );
    }

    /// Correct key, wrong DevID: INVALID. The two halves are both claims.
    #[test]
    fn a_correct_key_with_the_wrong_devid_is_rejected() {
        assert_eq!(
            check_settler_correspondence(&ak(7), &DevId([1; 32]), &ak(7), &DevId([2; 32])),
            Err(Reason::SettlerKeyMismatch)
        );
    }

    /// DevID bytes offered as the settler key are refused at CONSTRUCTION --
    /// they never reach a comparison. This is the production fallback that
    /// wrote a 32-byte DevID into a 64-byte key field, made structural.
    #[test]
    fn devid_bytes_can_never_be_an_authority_key() {
        assert_eq!(
            AuthorityPublicKey::try_new(&[9; 32]),
            Err(Reason::SettlerKeyMismatch)
        );
        assert_eq!(
            AuthorityPublicKey::try_new(&[9; 63]),
            Err(Reason::SettlerKeyMismatch)
        );
        assert_eq!(
            AuthorityPublicKey::try_new(&[9; 65]),
            Err(Reason::SettlerKeyMismatch)
        );
        assert!(AuthorityPublicKey::try_new(&[9; 64]).is_ok());
    }
    // ---------- the C3/C4 seam ----------

    /// 2c-C4 ruling V2: the seam carries the KIND and nothing certifiable.
    /// There is no verdict slot to read, so no caller can mistake a
    /// trader-side intermediate fact for a third-party verdict; certification
    /// is `C3Verdict::may_certify` on the walk's own verdict, and this type
    /// has no path to it.
    #[test]
    fn the_seam_carries_a_kind_and_nothing_certifiable() {
        for kind in [DlvTransitionKind::Settle, DlvTransitionKind::Close] {
            let v = SuccessorValidity::DlvTransition { kind };
            assert_eq!(v, SuccessorValidity::DlvTransition { kind });
        }
        assert_ne!(
            SuccessorValidity::NoDlvTransition,
            SuccessorValidity::DlvTransition {
                kind: DlvTransitionKind::Settle
            }
        );
    }

    // ---------- 2c-D §14 (C2): the typed cutover predicates ----------

    use crate::ccb::{
        Allocation, AllocationBundle, ConsumedDlvTransition, Route, RouteLeg, TradeIntent,
    };
    use prost::Message as _;

    const C_N: [u8; 32] = [0x3C; 32];
    const VAULT: [u8; 32] = [3; 32];
    const PC_A: [u8; 32] = [0x10; 32];
    const PC_B: [u8; 32] = [0x20; 32];

    fn curve_out(input: u64, parent: &VaultStateV2) -> u64 {
        crate::dlv::route_commit::constant_product_output(
            input,
            parent.reserve_a,
            parent.reserve_b,
            parent.fee_policy.fee_bps(),
        )
        .expect("curve")
    }

    fn accepted(parent: &VaultStateV2, out: u64) -> AcceptedTransition {
        AcceptedTransition {
            embedded_parent: [0xC1; 32],
            c_dsm_plus: [0xC5; 32],
            external_commitment_x: [0xA0; 32],
            parent_binding: C_N,
            parent_sequence: parent.generation,
            input_policy_commit: PC_A,
            input_amount: 1_000,
            output_policy_commit: PC_B,
            output_amount: out,
            fee_bps: 30,
        }
    }

    /// The orientation predicate is explicit and total over the pair.
    #[test]
    fn only_the_vaults_own_pair_in_a_permitted_orientation_is_tradable() {
        let p = parent(10_000, 5_000, None);
        assert_eq!(
            check_market_orientation(&p, &PC_A, &PC_B),
            Ok(Direction::AtoB)
        );
        assert_eq!(
            check_market_orientation(&p, &PC_B, &PC_A),
            Ok(Direction::BtoA)
        );
        for (i, o, what) in [
            (PC_A, PC_A, "one asset on both sides"),
            (PC_A, [0x99; 32], "a foreign output"),
            ([0x99; 32], PC_B, "a foreign input"),
        ] {
            assert_eq!(
                check_market_orientation(&p, &i, &o),
                Err(Reason::PairNotVaultPair),
                "{what} must not reach successor comparison"
            );
        }
    }

    /// CORR.5's accepted derivation: honest input derives exactly the frozen
    /// successor; each extra conjunct refuses alone.
    #[test]
    fn the_accepted_derivation_is_the_frozen_one_and_refuses_each_disagreement() {
        let p = parent(10_000, 5_000, None);
        let out = curve_out(1_000, &p);
        let DeriveExpected::Derived(next) =
            derive_accepted_market_successor(&p, C_N, &accepted(&p, out))
        else {
            panic!("an honest accepted settle derives");
        };
        let DeriveExpected::Derived(frozen) = derive_market_successor(
            &p,
            C_N,
            &MarketTerms {
                input_policy_commit: PC_A,
                output_policy_commit: PC_B,
                input_amount: 1_000,
                fee_bps: 30,
            },
        ) else {
            panic!("frozen derivation");
        };
        assert_eq!(next, frozen, "no second derivation beside the frozen one");

        type Alteration = (&'static str, fn(&mut AcceptedTransition), Reason);
        let alterations: [Alteration; 4] = [
            (
                "a foreign input asset",
                |a| a.input_policy_commit = [0x99; 32],
                Reason::PairNotVaultPair,
            ),
            (
                "another generation",
                |a| a.parent_sequence += 1,
                Reason::GenerationMismatch,
            ),
            (
                "another fee rate",
                |a| a.fee_bps += 1,
                Reason::RealizationEvidenceInvalid,
            ),
            (
                "an output the curve does not yield",
                |a| a.output_amount += 1,
                Reason::RealizationEvidenceInvalid,
            ),
        ];
        for (what, alter, reason) in alterations {
            let mut a = accepted(&p, out);
            alter(&mut a);
            assert!(
                matches!(derive_accepted_market_successor(&p, C_N, &a), DeriveExpected::Refused(r) if r == reason),
                "{what} must be refused as {reason:?}"
            );
        }
    }

    /// The LEFT side of CORR.4 comes from a verified settle and nothing else.
    #[test]
    fn accepted_effects_are_read_from_a_settle_and_nothing_else() {
        let settle = crate::types::operations::Operation::DlvSettle {
            vault_id: VAULT.to_vec(),
            owner_public_key: vec![0x01; 64],
            owner_devid: [0x41; 32],
            owner_genesis: [0x42; 32],
            input_policy_commit: PC_A,
            output_policy_commit: PC_B,
            parent_sequence: 7,
            parent_binding: C_N,
            route_commit_bytes: vec![0x09; 8],
            external_commitment_x: [0xA0; 32],
            input_amount: 1_000,
            output_amount: 900,
            fee_bps: 30,
            sigma: [0x66; 32],
            settler_public_key: vec![0x02; 64],
            settler_devid: [0x22; 32],
            settlement_receipt_id: [0x33; 32],
            signature: vec![0x77; 48],
            mode: crate::types::operations::TransactionMode::Unilateral,
        };
        let a = AcceptedTransition::from_verified_settle([0xC1; 32], [0xC5; 32], &settle)
            .expect("a settle has effects");
        assert_eq!(
            (
                a.parent_binding,
                a.parent_sequence,
                a.input_amount,
                a.output_amount,
                a.fee_bps
            ),
            (C_N, 7, 1_000, 900, 30)
        );
        let not_a_settle = crate::types::operations::Operation::Noop;
        assert!(
            AcceptedTransition::from_verified_settle([0; 32], [0; 32], &not_a_settle).is_none()
        );
    }

    fn alloc(delta_in: u64, delta_out: u64) -> Allocation {
        Allocation {
            parent_binding: C_N,
            delta_in,
            delta_out,
            encumbrance_claim: [0; 32],
            fee_policy: FeePolicy::new(30).expect("fee"),
        }
    }

    /// Beta's shape (2c-A ruling 3) is the ONLY shape the coordinates read.
    #[test]
    fn only_a_beta_bundle_has_coordinates() {
        let mut successor = parent(11_000, 4_000, None);
        successor.parent_state_commitment = C_N;
        let t = ConsumedDlvTransition::market(C_N, successor).expect("linked");
        let terms = crate::ccb::settlement::fixtures::market_terms(C_N, [0xA0; 32]);

        let coords = BundleCoordinates::from_market_bundle(&terms, std::slice::from_ref(&t))
            .expect("one leg, one allocation, one T_v");
        assert_eq!(
            (coords.leg_parent_binding, coords.transition_parent_binding),
            (C_N, C_N)
        );

        assert_eq!(
            BundleCoordinates::from_market_bundle(&terms, &[]),
            Err(Reason::BundleNotCanonical),
            "no T_v"
        );
        assert_eq!(
            BundleCoordinates::from_market_bundle(&terms, &[t.clone(), t.clone()]),
            Err(Reason::BundleNotCanonical),
            "two T_v"
        );
        let mut two_legs = terms.clone();
        two_legs.selected_route = Route::new(vec![
            RouteLeg::Single(alloc(1, 1)),
            RouteLeg::Single(alloc(2, 2)),
        ])
        .expect("route");
        assert_eq!(
            BundleCoordinates::from_market_bundle(&two_legs, std::slice::from_ref(&t)),
            Err(Reason::BundleNotCanonical),
            "two legs"
        );
        let mut fanned = terms;
        fanned.selected_route = Route::new(vec![RouteLeg::Bundle(
            AllocationBundle::new(vec![alloc(1, 1), alloc(2, 2)]).expect("bundle"),
        )])
        .expect("route");
        assert_eq!(
            BundleCoordinates::from_market_bundle(&fanned, std::slice::from_ref(&t)),
            Err(Reason::BundleNotCanonical),
            "a fanned-out leg"
        );
    }

    /// A RouteCommit genuinely signed by `sk`, with one hop for `VAULT`.
    fn signed_rc(sk: &[u8], pk: &[u8], parent_binding: [u8; 32], input: u64, out: u64) -> Vec<u8> {
        use crate::types::proto as generated;
        let hop = generated::RouteCommitHopV1 {
            vault_id: VAULT.to_vec(),
            token_in: PC_A.to_vec(),
            token_out: PC_B.to_vec(),
            input_amount_u128: (input as u128).to_be_bytes().to_vec(),
            expected_output_amount_u128: (out as u128).to_be_bytes().to_vec(),
            fee_bps: 30,
            parent_binding: parent_binding.to_vec(),
            ..Default::default()
        };
        let mut rc = generated::RouteCommitV1 {
            version: crate::dlv::route_commit::ROUTE_COMMIT_VERSION,
            nonce: vec![0x5E; 32],
            input_token: PC_A.to_vec(),
            output_token: PC_B.to_vec(),
            input_amount_u128: (input as u128).to_be_bytes().to_vec(),
            expected_final_output_amount_u128: (out as u128).to_be_bytes().to_vec(),
            total_fee_bps: 30,
            hops: vec![hop],
            initiator_public_key: pk.to_vec(),
            ..Default::default()
        };
        let canonical = crate::dlv::route_commit::canonicalise_for_commitment(&rc).encode_to_vec();
        rc.initiator_signature =
            crate::crypto::sphincs::sphincs_sign(sk, &canonical).expect("sign");
        rc.encode_to_vec()
    }

    struct Tier1 {
        parent: VaultStateV2,
        intent: TradeIntent,
        route: Route,
        rc: Vec<u8>,
        pk: Vec<u8>,
        sk: Vec<u8>,
    }

    fn tier1() -> Tier1 {
        let (pk, sk) = crate::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
        let parent = parent(10_000, 5_000, None);
        let out = curve_out(1_000, &parent);
        Tier1 {
            intent: TradeIntent {
                token_in: PC_A,
                amount_in: 1_000,
                token_out: PC_B,
                exact_out: out,
                fee_bps: 30,
                nonce: [0x5A; 32],
            },
            route: Route::new(vec![RouteLeg::Single(alloc(1_000, out))]).expect("route"),
            rc: signed_rc(&sk, &pk, C_N, 1_000, out),
            parent,
            pk,
            sk,
        }
    }

    fn sat(t: &Tier1) -> Result<IntentSatisfaction, Reason> {
        check_intent_satisfaction(
            &IntentEvidence {
                intent: &t.intent,
                route: &t.route,
                route_commit_bytes: &t.rc,
                vault_id: &VAULT,
                proven_ak: &t.pk,
            },
            &t.parent,
            C_N,
        )
    }

    /// SAT.1–SAT.6 hold for an honest, genuinely signed trade.
    #[test]
    fn an_honest_signed_trade_satisfies_its_intent() {
        let t = tier1();
        assert_eq!(sat(&t).expect("Tier 1 holds").intent(), &t.intent);
    }

    /// SAT.2 — the signing key must be the PROVEN one, and the signature real.
    #[test]
    fn a_route_commit_signed_by_anyone_else_is_not_the_traders_intent() {
        let mut t = tier1();
        let (other, _) = crate::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
        t.pk = other;
        assert_eq!(sat(&t), Err(Reason::SettlerKeyMismatch));

        let mut t = tier1();
        let mut rc = crate::types::proto::RouteCommitV1::decode(t.rc.as_slice()).expect("rc");
        rc.initiator_signature[0] ^= 0xFF;
        t.rc = rc.encode_to_vec();
        assert_eq!(sat(&t), Err(Reason::RealizationEvidenceInvalid));

        let mut t = tier1();
        let out = t.intent.exact_out;
        t.rc = signed_rc(&t.sk, &t.pk, [0x9E; 32], 1_000, out);
        assert_eq!(
            sat(&t),
            Err(Reason::StaleParent),
            "a hop signed against another parent"
        );
    }

    /// SAT.3 — each intent field must equal the signed hop, alone.
    #[test]
    fn an_intent_that_is_not_what_the_trader_signed_is_refused() {
        type Alteration = (&'static str, fn(&mut TradeIntent));
        let alterations: [Alteration; 4] = [
            ("token_in", |i| i.token_in = [0x99; 32]),
            ("amount_in", |i| i.amount_in += 1),
            ("exact_out", |i| i.exact_out -= 1),
            ("fee_bps", |i| i.fee_bps += 1),
        ];
        for (what, alter) in alterations {
            let mut t = tier1();
            alter(&mut t.intent);
            assert_eq!(
                sat(&t),
                Err(Reason::RealizationEvidenceInvalid),
                "an intent whose {what} differs from the signed hop must be refused"
            );
        }
    }

    /// SAT.4 — the selected route's one leg must equal the signed hop.
    #[test]
    fn a_route_that_is_not_the_signed_hop_is_refused() {
        let mut t = tier1();
        let out = t.intent.exact_out;
        t.route = Route::new(vec![RouteLeg::Single(alloc(1_000, out - 1))]).expect("route");
        assert_eq!(sat(&t), Err(Reason::RealizationEvidenceInvalid));

        let mut t = tier1();
        let mut leg = alloc(1_000, out);
        leg.parent_binding = [0x9E; 32];
        t.route = Route::new(vec![RouteLeg::Single(leg)]).expect("route");
        assert_eq!(sat(&t), Err(Reason::StaleParent));

        let mut t = tier1();
        t.route = Route::new(vec![
            RouteLeg::Single(alloc(1_000, out)),
            RouteLeg::Single(alloc(1, 1)),
        ])
        .expect("route");
        assert_eq!(
            sat(&t),
            Err(Reason::BundleNotCanonical),
            "beta routes have one leg"
        );
    }

    /// SAT.5 — a trade signed, intended and routed CONSISTENTLY at a price the
    /// authenticated V_n does not produce. Every SAT.3/SAT.4 equality holds, so
    /// only the independent re-simulation can refuse it — which is 2c-E's
    /// point: exact_out checked against itself proves nothing.
    #[test]
    fn a_self_consistent_trade_at_the_wrong_price_is_refused() {
        let mut t = tier1();
        let wrong = t.intent.exact_out + 1;
        t.intent.exact_out = wrong;
        t.route = Route::new(vec![RouteLeg::Single(alloc(1_000, wrong))]).expect("route");
        t.rc = signed_rc(&t.sk, &t.pk, C_N, 1_000, wrong);
        assert_eq!(sat(&t), Err(Reason::RealizationEvidenceInvalid));
    }

    /// SAT.6 — the vault's fee is the authority; an intent signed at another
    /// rate is refused even when the route and the hop agree with it.
    #[test]
    fn an_intent_at_a_fee_the_vault_does_not_charge_is_refused() {
        let mut t = tier1();
        t.parent.fee_policy = FeePolicy::new(31).expect("fee");
        assert_eq!(sat(&t), Err(Reason::RealizationEvidenceInvalid));
    }
}

#[cfg(test)]
mod witness_construction_site {
    /// **`pub(crate)` is not "only §7".** The constructor is unreachable from
    /// outside this crate, but any module inside it could assert the fact
    /// without doing the work. This pins the call sites so that becoming true
    /// requires editing a test that says why it must not.
    ///
    /// Exactly one production call site is permitted:
    /// `economic::acceptance_verify::verify_trader_acceptance`, which is 2c-D
    /// §7. If this fails, either a second module started minting the witness —
    /// which is a protocol defect, not a test problem — or §7 moved and this
    /// test should follow it.
    #[test]
    fn the_acceptance_witness_has_exactly_one_construction_site() {
        // ASSEMBLED AT RUNTIME so the complete pattern never appears as a
        // literal in this file. Both earlier attempts counted the scanner's
        // own source line: a test that searches for a string it also contains
        // will always find itself.
        let needle = format!("::{}(", "from_verified_acceptance");

        fn walk(dir: &std::path::Path, needle: &str, hits: &mut Vec<String>) {
            for e in std::fs::read_dir(dir).expect("readable source dir") {
                let path = e.expect("entry").path();
                if path.is_dir() {
                    walk(&path, needle, hits);
                } else if path.extension().is_some_and(|x| x == "rs") {
                    let text = std::fs::read_to_string(&path).expect("readable source");
                    for line in text.lines() {
                        let trimmed = line.trim_start();
                        // Skip the definition and every doc/comment mention:
                        // what is being counted is CALLS.
                        if trimmed.starts_with("//") || trimmed.starts_with("pub(crate) const fn") {
                            continue;
                        }
                        // Matched on the QUALIFIED form. The scanner's own
                        // literal below is unqualified, so this test cannot
                        // count itself — a self-match is how the first version
                        // of it failed.
                        if line.contains(needle) {
                            hits.push(format!("{}: {}", path.display(), trimmed));
                        }
                    }
                }
            }
        }

        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut hits = Vec::new();
        walk(&src, &needle, &mut hits);
        assert_eq!(
            hits.len(),
            1,
            "the bundle-acceptance witness must be minted in exactly one place; found: {hits:#?}"
        );
        assert!(
            hits[0].contains("acceptance_verify"),
            "the one construction site must be 2c-D §7's verifier; found: {}",
            hits[0]
        );
    }
}
