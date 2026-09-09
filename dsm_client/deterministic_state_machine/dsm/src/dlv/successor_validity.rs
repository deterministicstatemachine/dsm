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
//! # What this module does NOT establish
//!
//! - **`VDS.COMMON.10.a` — the canonical-byte successor comparison — is NOT
//!   performed here, and cannot be.** No authoritative supplied successor bytes
//!   exist on the wire: `successor_ccb` carries the route-set commitment on a
//!   market bundle and a slot commitment on a close, and both composition arms
//!   derive the successor locally. The conjunct is normative and
//!   IMPLEMENTATION-BLOCKED on amendment 2c-A's canonical encoder cut, recorded
//!   by [`C3Verdict::PartialPendingEncoderCut`]. Nothing here may substitute a
//!   surrogate operand for it.
//! - **Preserved- and mutated-field equality.** Ruling B derives those from
//!   `10.a` alone. Re-adding them as bespoke per-field checks would create a
//!   SECOND acceptance predicate beside the frozen one, so while `10.a` is
//!   blocked they stay unenforced and the verdict says so.
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
    /// `Canon(expected) != Canon(supplied)`. **Unreachable until 2c-A** — kept
    /// so the frozen vocabulary is complete and the code exists the moment the
    /// comparison does.
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
}

impl Reason {
    /// The class this reason always carries. Fixing it here is what stops a
    /// caller pairing a reason with a class it does not belong to.
    pub const fn class(&self) -> OutcomeClass {
        match self {
            Self::DuplicateBindingFinality => OutcomeClass::SafetyViolation,
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
/// what stops the compiler from letting anyone write it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndependentRealization {
    _c4_owns_this: core::marker::PhantomData<()>,
}

/// Which conjuncts a partial verdict did evaluate.
///
/// Carried by [`C3Verdict::PartialPendingEncoderCut`] so that "everything I
/// could check, I checked" is a statement with content rather than a shrug.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstablishedChecks {
    /// The successor this verifier derived. It is NOT compared against a
    /// supplied successor, because none exists on the wire yet.
    pub expected: Box<VaultStateV2>,
    /// The parent this successor was derived from.
    pub parent_commitment: [u8; 32],
}

/// What C3 concluded about one candidate successor.
///
/// **Class-safe by construction.** Each protocol class carries its own payload,
/// so a result cannot be built that pairs one class with another's evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum C3Verdict {
    /// Every applicable conjunct was evaluated and held.
    ///
    /// **Unreachable today**, and that is the point: reaching it requires
    /// `VDS.COMMON.10.a`, which is blocked on 2c-A, and for a market successor
    /// additionally an [`IndependentRealization`], which nothing can construct.
    Valid(CompleteValidity),
    /// A conjunct decided against the successor.
    Invalid(Reason),
    /// The evidence to decide a conjunct is missing. Retryable; never a
    /// conclusion that the successor is false.
    Incomplete(Reason),
    /// A proven contradiction in the storage substrate (Req 6.3).
    SafetyViolation(Reason),
    /// Every conjunct that CAN be evaluated held, and at least one is
    /// IMPLEMENTATION-BLOCKED.
    ///
    /// This is **deployment status, not a protocol outcome** — it deliberately
    /// sits outside the [`Reason`] namespace so it can never be mistaken for a
    /// verdict about the successor. A caller may fold forward on it. A caller
    /// may NOT emit accepted-successor finality, validate `TA_B`, release a
    /// fence, advance the realized frontier as accepted, or convert it to
    /// [`C3Verdict::Valid`] downstream. The fold may compute forward; the
    /// validity claim may not.
    PartialPendingEncoderCut(EstablishedChecks),
}

/// Evidence that every conjunct held, including the ones that are blocked today.
///
/// Private field and no public constructor, the same discipline
/// `ValidatedEconomicRoot` uses: there is no network event that declares a
/// successor fully valid, and no `assume_valid` shortcut to add later in a hurry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteValidity {
    _unreachable_until_2c_a: core::marker::PhantomData<()>,
}

impl C3Verdict {
    /// The class, for callers that branch on it.
    ///
    /// `PartialPendingEncoderCut` returns `None` rather than a class: it is not
    /// one of the four protocol outcomes, and returning `Valid` for it would be
    /// exactly the claim this whole type exists to withhold.
    pub const fn class(&self) -> Option<OutcomeClass> {
        match self {
            Self::Valid(_) => Some(OutcomeClass::Valid),
            Self::Invalid(_) => Some(OutcomeClass::Invalid),
            Self::Incomplete(_) => Some(OutcomeClass::Incomplete),
            Self::SafetyViolation(_) => Some(OutcomeClass::SafetyViolation),
            Self::PartialPendingEncoderCut(_) => None,
        }
    }

    /// Whether the caller may fold this successor forward.
    ///
    /// True for a complete verdict and for a partial one — the encoder-cut
    /// blocker withholds the validity CLAIM, it does not halt composition.
    /// Blocking the fold instead would stop every vault, since the operand the
    /// blocked conjunct needs does not exist yet.
    pub const fn may_fold(&self) -> bool {
        matches!(self, Self::Valid(_) | Self::PartialPendingEncoderCut(_))
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
        assert_eq!(
            Reason::DuplicateBindingFinality.class(),
            OutcomeClass::SafetyViolation
        );
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

    /// A partial verdict may fold and may NOT certify. This is the whole
    /// separation the encoder-cut blocker rests on.
    #[test]
    fn a_partial_verdict_folds_but_never_certifies() {
        let v = parent(1_000, 1_000, None);
        let partial = C3Verdict::PartialPendingEncoderCut(EstablishedChecks {
            expected: Box::new(v.clone()),
            parent_commitment: [7; 32],
        });
        assert!(partial.may_fold(), "composition must continue");
        assert!(
            !partial.may_certify(),
            "a blocked conjunct must never be certified as valid"
        );
        assert_eq!(
            partial.class(),
            None,
            "deployment status is not a protocol class"
        );
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
}
