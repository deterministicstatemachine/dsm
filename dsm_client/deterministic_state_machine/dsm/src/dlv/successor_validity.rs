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
    /// its conjuncts. The verdict slot is `None` until C4 threads `V_n`
    /// through -- it is NOT `Valid`, and nothing may read it as such.
    DlvTransition {
        kind: DlvTransitionKind,
        verdict: Option<C3Verdict>,
    },
}

/// Which DLV family the verified operation belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlvTransitionKind {
    Settle,
    Close,
}

impl SuccessorValidity {
    /// Whether anything here may be certified as a complete C3 result.
    /// `false` in every shape this commit can produce.
    pub fn may_certify(&self) -> bool {
        matches!(self, Self::DlvTransition { verdict: Some(v), .. } if v.may_certify())
    }
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
/// **There is deliberately no constructor, here or anywhere else yet.**
///
/// A trader settlement receipt cannot establish this. `verify_trader_settlement_receipt`
/// reads the public key, genesis, DevID and root out of the receipt itself, and
/// the cheapest tree satisfying its inclusion check has one leaf — so, in that
/// module's own words, the honest fixture and a forgery are byte-identical
/// constructions and it must not be read as evidence that value moved.
/// Establishing this fact means binding `post_root` to an independently
/// verifiable trader transition, which is amendment 2c-C4's (5c-2's) work.
///
/// Its absence is load-bearing rather than a stub: a market successor cannot
/// reach [`C3Verdict::Valid`] without one, so the encoder cut alone can never
/// make a market successor look complete. That inference —
/// `2c-A lands + 10.a passes = market valid` — is not sound, and this type is
/// what stops the compiler from letting anyone write it:
///
/// ```compile_fail
/// use dsm::dlv::successor_validity::IndependentRealization;
/// let _ = IndependentRealization {
///     _c4_owns_this: core::marker::PhantomData,
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndependentRealization {
    _c4_owns_this: core::marker::PhantomData<()>,
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
    /// [`IndependentRealization`], which nothing can construct.
    Valid(CompleteValidity),
    /// A conjunct decided against the successor.
    Invalid(Reason),
    /// The evidence to decide a conjunct is missing. Retryable; never a
    /// conclusion that the successor is false.
    Incomplete(Reason),
    /// A proven contradiction in the storage substrate (Req 6.3).
    SafetyViolation(Reason),
    /// A MARKET successor: every conjunct held, `10.a` included, and the one
    /// fact still missing is that the settlement occurred — 2c-C4's
    /// [`IndependentRealization`].
    ///
    /// This is **deployment status, not a protocol outcome** — it deliberately
    /// sits outside the [`Reason`] namespace so it can never be mistaken for a
    /// verdict about the successor. A caller may fold forward on it. A caller
    /// may NOT emit accepted-successor finality, validate `TA_B`, release a
    /// fence, advance the realized frontier as accepted, or convert it to
    /// [`C3Verdict::Valid`] downstream. The fold may compute forward; the
    /// validity claim may not.
    PartialPendingRealization(CorrespondenceWitness),
}

/// Evidence that every conjunct held.
///
/// Private field and exactly two constructors, the same discipline
/// `ValidatedEconomicRoot` uses: there is no network event that declares a
/// successor fully valid, and no `assume_valid` shortcut to add later in a
/// hurry. [`Self::from_close_witness`] is the owner-close path — the witness
/// is the last conjunct a close has. [`Self::from_market_witness`] also takes
/// an [`IndependentRealization`], which has no constructor, so
/// `2c-A + 10.a = market valid` is a compile error rather than a rule.
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
    /// independently established. Uncallable until 2c-C4 gives
    /// [`IndependentRealization`] a constructor — deliberately.
    pub fn from_market_witness(
        witness: CorrespondenceWitness,
        realization: IndependentRealization,
    ) -> Self {
        let IndependentRealization { _c4_owns_this } = realization;
        Self { witness }
    }

    /// The correspondence this validity rests on.
    pub fn witness(&self) -> &CorrespondenceWitness {
        &self.witness
    }
}

impl C3Verdict {
    /// The class, for callers that branch on it.
    ///
    /// `PartialPendingRealization` returns `None` rather than a class: it is
    /// not one of the four protocol outcomes, and returning `Valid` for it
    /// would be exactly the claim this whole type exists to withhold.
    pub const fn class(&self) -> Option<OutcomeClass> {
        match self {
            Self::Valid(_) => Some(OutcomeClass::Valid),
            Self::Invalid(_) => Some(OutcomeClass::Invalid),
            Self::Incomplete(_) => Some(OutcomeClass::Incomplete),
            Self::SafetyViolation(_) => Some(OutcomeClass::SafetyViolation),
            Self::PartialPendingRealization(_) => None,
        }
    }

    /// Whether the caller may fold this successor forward.
    ///
    /// True for a complete verdict and for a market fold pending its
    /// realization fact — the missing fact withholds the validity CLAIM, it
    /// does not halt composition. Blocking the fold instead would stop every
    /// market vault until 2c-C4.
    pub const fn may_fold(&self) -> bool {
        matches!(self, Self::Valid(_) | Self::PartialPendingRealization(_))
    }

    /// Whether the successor may cross a boundary whose semantics require FULL
    /// `ValidDlvSuccessorCore` — accepted-successor finality, `TA_B`, fence
    /// release, accepted-frontier advancement.
    ///
    /// Deliberately NOT the same question as [`Self::may_fold`].
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

    /// A market verdict pending its realization fact may fold and may NOT
    /// certify; a close verdict from the same witness does both. This is the
    /// whole separation the C4 seam rests on.
    #[test]
    fn a_market_witness_folds_but_never_certifies_and_a_close_witness_certifies() {
        let v = parent(1_000, 1_000, None);
        let supplied = v.encode().expect("encodes");
        let w = check_correspondence(&v, [7; 32], &supplied).expect("bytes equal");
        let market = C3Verdict::PartialPendingRealization(w.clone());
        assert!(market.may_fold(), "composition must continue");
        assert!(
            !market.may_certify(),
            "a missing realization fact must never be certified as valid"
        );
        assert_eq!(
            market.class(),
            None,
            "deployment status is not a protocol class"
        );
        let close = C3Verdict::Valid(CompleteValidity::from_close_witness(w.clone()));
        assert!(close.may_fold());
        assert!(close.may_certify(), "a close's 10.a is its last conjunct");
        assert_eq!(close.class(), Some(OutcomeClass::Valid));
        let C3Verdict::Valid(cv) = close else {
            unreachable!()
        };
        assert_eq!(*cv.witness(), w);
    }

    #[test]
    fn a_refused_verdict_neither_folds_nor_certifies() {
        for v in [
            C3Verdict::Invalid(Reason::StaleParent),
            C3Verdict::Incomplete(Reason::BindingEvidenceUnavailable),
            C3Verdict::SafetyViolation(Reason::DuplicateBindingFinality),
        ] {
            assert!(!v.may_fold(), "{v:?}");
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

    /// Nothing this commit can produce is certifiable: the verdict slot is
    /// empty until C4 threads V_n, and an empty slot is not Valid.
    #[test]
    fn a_dlv_transition_with_no_verdict_can_never_certify() {
        for kind in [DlvTransitionKind::Settle, DlvTransitionKind::Close] {
            let v = SuccessorValidity::DlvTransition {
                kind,
                verdict: None,
            };
            assert!(!v.may_certify(), "{kind:?}");
        }
        assert!(!SuccessorValidity::NoDlvTransition.may_certify());
    }

    /// And a partial verdict in the slot still does not certify -- the seam
    /// inherits C3Verdict's separation of fold from claim.
    #[test]
    fn a_partial_verdict_in_the_slot_does_not_certify() {
        let p = parent(1_000, 1_000, None);
        let w = check_correspondence(&p, [7; 32], &p.encode().expect("encodes"))
            .expect("bytes equal");
        let v = SuccessorValidity::DlvTransition {
            kind: DlvTransitionKind::Settle,
            verdict: Some(C3Verdict::PartialPendingRealization(w)),
        };
        assert!(!v.may_certify());
    }
}
