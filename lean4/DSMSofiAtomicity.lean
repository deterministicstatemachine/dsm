/-
  SoFi v8 atomicity: one unilateral trader operation, P → G → F → realization —
  self-contained Lean 4 (no Mathlib, no imports)

  Machine-checks plan revision 10.3 F1–F4 and F9–F10 over content-addressed
  objects:

    - IDENTITY      P, G and F identities ignore signatures and are domain-separated
                    from signing digests; exactly one PolicyFulfillmentId per
                    (P, E, vault, parent, shadow); witness encodings never enter it;
                    a G is bound to its precommit, parent and shadow
    - HASH ORDER    𝒞_E^pre → E → P → G → F → C_q strictly increases:
                    no current-E object can be named in the closure, a prior-E
                    conditional claim can, and conditional references are
                    structurally earlier
    - CONFORMANCE   a conforming F carries the complete canonical policy set, one
                    attempt per leg, q = p + 1 and P's key; over fetched evidence
                    (R7) the eight-item predicate is Valid exactly when that holds
                    and every storage fact is established, more evidence only
                    refines, and an unmade read is never a refusal
    - REGISTRATION  the race at the leader of the position pair, and nothing
                    else: no member checks P, a witness, conformance or a parent
                    (Part II). Registered is not conforming and stored is not
                    valid; Realized needs every Core predicate
                    (`realized_requires_valid_setup`, `realized_requires_conformance`,
                    `registration_is_not_conformance`,
                    `early_cell_cannot_cause_consumption`)
    - VALIDATION    three-valued conjunction; RouteValidation is static (no attempt,
                    finality, canonicality or outcome input) and only refines; arm
                    (i) is a predicate on P alone; auxiliary candidates are
                    content-addressed and can only establish Valid; exhausting either
                    budget is Unavailable; garbage never consumes the fetch bound; a
                    known bound violation is Invalid
    - EFFECTS       storing P or G changes no economic fact and no guard, and G never
                    locks; F registers after a parent is lost; F's own C_q does not
                    expire T0; an incompatible transition refuses F
    - ATOMICITY     Realized consumes every parent P names and anything else
                    consumes none; a stranded E cell is not partial execution; the
                    orphan and consumed-elsewhere arms make every F of P
                    unrealizable; a registered, valid F may Void under contention,
                    so success is not guaranteed without a lock — and a lock is free
    - RESOLUTION    Realized and Void are exclusive; resolution is permanent once
                    non-Pending; registered is not validated; a lost parent gives
                    Void, never Invalid; nothing stores an outcome -- completion
                    and defeat are derived from the leg reads; a registered F
                    resolves once evidence is available AND its own trader parent
                    has resolved
    - TRADER PARENT a conditional parent that has not resolved keeps the position
                    Pending and decides nothing; one that selected another root, or
                    none, makes it Invalid with no evidence at all; the arm is
                    monotone (P15-3, R17-3)
    - CANDIDATES    E ↔ F is not one-to-one: many candidate F share one (P, E, q)
                    and one RouteValidation, and at most one of them registers
                    (R15-2)
    - LINEAGE       Invalid terminates the lineage; a descendant needs a selected
                    predecessor root; the fence admits no claim of ANY kind above
                    a fulfillment Core has not resolved, so at most one is
                    unresolved per lineage; SofiVoid has zero economic effect
    - CARRIED       genesis acceptance needs validated creation; setup is bound to
                    the exact envelope; the relationship leaf's first operation is
                    admitted once; a cross-network route is Invalid; close needs the
                    current authority

  Modelling premises:

    * `HashModel`: a content address is injective, and no address is an input to
      its own preimage. `encModel` shows the two are jointly satisfiable.
    * Registration is abstracted to registered facts; the leader-first cell layer
      (LeaderHeld and Final from raw reads — nothing votes, nothing is counted
      against a threshold) is DSMSofiSuccessorCells.
    * `Coherent` restates the storage and walk facts DSMSofiSuccessorCells proves:
      a key lost to another exercise is not final on E, one outcome value, Abort only on objective evidence,
      one consumer per parent, orphaned parents are not canonical.

  What this module does NOT claim:

    * Policy semantics: `Evidence` supplies PolicyFulfillmentValid per witness.
    * BLAKE3, or that the Rust encoders are injective (the Phase B vectors).
    * Liveness beyond `registered_fulfillment_resolves_under_evidence_availability`.

  Finding (ladder step 3):

    Read literally, step 3 (Void on StorageResolved and objective evidence) has no
    validation premise, while step 4 is "Pending otherwise, including Unavailable"
    and the ladder is "permanent once non-Pending". The literal reading is not
    permanent: Void while evidence is Unavailable, then Invalid once it arrives —
    and Invalid ends the lineage that Void had continued
    (`literal_ladder_is_not_permanent`). `resolve` requires RouteValidation = Valid
    for Void, the reading under which `resolution_is_permanent` holds (mutation 16).

  Mutation controls, executed rather than asserted. Each gate was removed and the
  named theorem went red — its proof rejected by the kernel, or `#print axioms`
  showing it now rests on `sorryAx`:

     1. storing P installs a claim at p + 1    -> `precommit_is_non_economic`
     2. F with a subset of the policy set      -> `fulfillment_atomic_all_or_none`
     3. a witness locks its parent             -> `policy_fulfillment_is_non_economic_and_non_locking`
     4. G not bound to PrecommitId             -> `policy_fulfillment_bound_to_precommit_parent_and_shadow`
     5. a storage-resolved Void read Realized  -> `no_guarantee_without_prepare_lock`
     6. P and G classes admitted to 𝒞_E^pre    -> `closure_refuses_current_e_classes`
     7. the witness address inside the G id    -> `witness_encoding_does_not_change_policy_fulfillment_id`,
                                                  `policy_fulfillment_identity_canonical_per_leg`
     8. one evidence slot per (id, class)      -> `aux_candidates_are_content_addressed_no_singleton_slot`
     9. a non-verifying candidate is Invalid   -> `aux_candidate_cannot_establish_invalid`
    10. garbage counted toward 4 MiB           -> `garbage_candidates_do_not_consume_fetch_bound`
    11. parent canonicality inside validation  -> `route_validation_excludes_parent_canonicality`
    12. expiry read as "T0 is still head"      -> `own_conditional_successor_does_not_expire_T0`
    13. F ingress requires unconsumed parents  -> `fulfillment_registrable_after_parent_loss_resolves_void`
    14. validation reads the attempt vector    -> `route_validation_is_static`
    15. arm (i) quantified over any F's set    -> `route_impossible_invalid_arm_monotone_without_f_quantification`
    16. Void without the Valid premise         -> `resolution_is_permanent`
    17. a leg consumed on its own final E      -> `stranded_e_cell_is_not_partial_execution`
    18. the fence on conditional claims only   -> `speculative_descendants_never_admitted`,
                                                  `at_most_one_unresolved_fulfillment_per_lineage`
    19. SofiVoid without the empty mutation set -> `sofi_void_has_zero_economic_effect`
    20. first leaf operation without non-inclusion
                                               -> `leaf_non_inclusion_admits_the_first_operation_once`
    21. authority from a setup at q itself     -> `close_by_current_authority`
    22. network scope removed                  -> `cross_network_route_is_invalid`
    23. setup without the exact envelope digest -> `setup_bound_to_exact_envelope`
    23a. `setupRoot` free rather than derived from the parent root by the
         P15-6 absent->h0 insertion -> `setup_root_is_derived_not_chosen`
         (drop the `SetupPostRoot` conjunct from `SetupIngress` and two
         setups at one parent can disagree about the root)
    24. the walk starts from a stored genesis  -> `genesis_requires_validated_creation`
    25. a known bound violation Unavailable    -> `bound_violation_is_invalid_never_unavailable`
    26. an exhausted budget Invalid            -> `budget_exhaustion_never_yields_invalid`
    27. F ingress ignores K_root(q)            -> `incompatible_trader_transition_refuses_fulfillment`
    28. F at the parent position q = p         -> `own_conditional_successor_does_not_expire_T0`
    29. SetupValid removed from RouteValidation -> `realized_requires_valid_setup`
    30. FulfillmentConformance dropped from    -> `realized_requires_conformance`
        ConsumedRoute
    31. registration read as conformance       -> `registration_is_not_conformance`
    32. storage occupancy read as validity     -> `early_cell_cannot_cause_consumption`
        (ConsumedRoute = the leg predicate)      (29-32: the named theorem rests on `sorryAx`)
    29. the signature inside PrecommitId       -> `identity_is_signature_independent`
    30. id and signing digest share a tag      -> `identity_and_signing_digest_are_domain_separated`
    31. Invalid counted as validated ancestry  -> `invalid_terminates_lineage`
    32. Void selecting the Realize root        -> `route_validation_excludes_parent_canonicality`
    33. the parent's selected branch unchecked -> `conditional_parent_on_another_branch_is_invalid`
    34. an undecided parent read as terminal   -> `conditional_parent_pending_keeps_the_position_pending`
    35. a missing P read as Invalid (R7)       -> `a_missing_p_waits_and_only_an_unsigned_f_refuses`,
                                                  `more_evidence_only_refines`
    36. an unfetched setup read as Invalid (R7) -> `unread_storage_is_unavailable_never_invalid`,
                                                  `more_evidence_only_refines`
    37. `fulfillStep` writes K_ful only (R9)   -> `position_pair_atomic`
    38. (R13) Pending counted as validated     -> `an_undecided_or_terminal_position_extends_nothing`,
        ancestry                                  `descendant_requires_resolved_predecessor`
    39. (R14) `legOk` accepts any parent that   -> `an_unestablished_parent_neither_consumes_nor_defeats`
        is not `.orphaned`

  `p_g_f_hash_order_acyclic` is not a mutation target: acyclicity follows from the
  hash order itself, so admitting a current-E class cannot falsify it. The design
  it rules out is refuted directly by `precommit_in_its_own_closure_is_unconstructible`.

  All mutations were reverted; this file is the unmutated module.
-/

namespace DSMSofiAtomicity

-- ── §1 content addresses ──────────────────────────────────────────────────

/-- The two modelling premises on a BLAKE3 content address `H(tag ‖ bytes)`:
it is injective (collision resistance) and no address is an input to its own
preimage (the Merkle-DAG premise: an object's address cannot be computed before
the addresses it contains). -/
structure HashModel where
  H : List Nat → Nat
  injective : ∀ a b, H a = H b → a = b
  dominates : ∀ l x, x ∈ l → x < H l

def enc : List Nat → Nat
  | [] => 0
  | x :: xs => 2 ^ x * (2 * enc xs + 1)

theorem two_pow_mul_odd_inj : ∀ (a c b d : Nat),
    2 ^ a * (2 * b + 1) = 2 ^ c * (2 * d + 1) → a = c ∧ b = d := by
  intro a
  induction a with
  | zero =>
    intro c b d h
    cases c with
    | zero => simp at h; exact ⟨rfl, by omega⟩
    | succ k =>
      rw [Nat.pow_succ, Nat.mul_comm (2 ^ k) 2, Nat.mul_assoc] at h
      generalize 2 ^ k * (2 * d + 1) = t at h
      simp at h; omega
  | succ k ih =>
    intro c b d h
    cases c with
    | zero =>
      rw [Nat.pow_succ, Nat.mul_comm (2 ^ k) 2, Nat.mul_assoc] at h
      generalize 2 ^ k * (2 * b + 1) = t at h
      simp at h; omega
    | succ m =>
      rw [Nat.pow_succ, Nat.pow_succ, Nat.mul_comm (2 ^ k) 2, Nat.mul_comm (2 ^ m) 2,
        Nat.mul_assoc, Nat.mul_assoc] at h
      have h' := ih m b d (by omega)
      exact ⟨by rw [h'.1], h'.2⟩

theorem enc_pos (x : Nat) (xs : List Nat) : 0 < enc (x :: xs) :=
  Nat.mul_pos (Nat.pow_pos (by decide)) (by omega)

theorem enc_injective : ∀ a b : List Nat, enc a = enc b → a = b := by
  intro a
  induction a with
  | nil =>
    intro b h
    cases b with
    | nil => rfl
    | cons y ys => have := enc_pos y ys; rw [← h] at this; exact absurd this (by decide)
  | cons x xs ih =>
    intro b h
    cases b with
    | nil => have := enc_pos x xs; rw [h] at this; exact absurd this (by decide)
    | cons y ys =>
      obtain ⟨hxy, he⟩ := two_pow_mul_odd_inj x y (enc xs) (enc ys) h
      rw [hxy, ih ys he]

theorem enc_dominates : ∀ (l : List Nat) (x : Nat), x ∈ l → x < enc l := by
  intro l
  induction l with
  | nil => intro x h; cases h
  | cons y ys ih =>
    intro x h
    have hp : 0 < 2 ^ y := Nat.pow_pos (by decide)
    rcases List.mem_cons.mp h with rfl | hm
    · exact Nat.lt_of_lt_of_le (Nat.lt_two_pow_self) (Nat.le_mul_of_pos_right _ (by omega))
    · have h1 := ih x hm
      have h2 : enc ys < 2 * enc ys + 1 := by omega
      exact Nat.lt_of_lt_of_le (Nat.lt_trans h1 h2) (Nat.le_mul_of_pos_left _ hp)

/-- The premises are jointly satisfiable, so nothing below is vacuous. -/
def encModel : HashModel := ⟨enc, enc_injective, enc_dominates⟩

-- Domain tags: distinct leading elements (`DSM/sofi/*`).
def TAG_EXT : Nat := 1
def TAG_PRECOMMIT_ID : Nat := 2
def TAG_PRECOMMIT_SIGN : Nat := 3
def TAG_POLICY_FULFILLMENT : Nat := 4
def TAG_FULFILLMENT_ID : Nat := 5
def TAG_FULFILLMENT_SIGN : Nat := 6
def TAG_RESOLUTION_CLAIM : Nat := 7

-- ── §2 the three objects and their identities ─────────────────────────────

structure Leg where
  vault : Nat
  parent : Nat
  setup : Nat
  deriving DecidableEq, Repr

/-- `TraderPrecommitBody`. -/
structure PBody where
  genesis : Nat
  device : Nat
  p : Nat
  parentClaim : Nat
  e : Nat
  legs : List Leg
  realize : Nat
  void : Nat
  setId : Nat
  key : Nat
  deriving DecidableEq, Repr

/-- `DlvPolicyFulfillmentBody`: identity-bearing fields only. -/
structure GBody where
  pid : Nat
  e : Nat
  vault : Nat
  parent : Nat
  shadow : Nat
  deriving DecidableEq, Repr

/-- `TraderFulfillmentBody`: it restates no P field. -/
structure FBody where
  pid : Nat
  gset : List Nat
  attempts : List (Nat × Nat)
  q : Nat
  key : Nat
  deriving DecidableEq, Repr

/-- A signed envelope: the signature is outside the body. -/
structure Envelope (α : Type) where
  body : α
  signature : Nat

def legBytes : List Leg → List Nat
  | [] => []
  | l :: ls => l.vault :: l.parent :: l.setup :: legBytes ls

def PBody.bytes (b : PBody) : List Nat :=
  [b.genesis, b.device, b.p, b.parentClaim, b.e, b.legs.length] ++ legBytes b.legs
    ++ [b.realize, b.void, b.setId, b.key]

def GBody.bytes (g : GBody) : List Nat := [g.pid, g.e, g.vault, g.parent, g.shadow]

def FBody.bytes (f : FBody) : List Nat :=
  [f.pid, f.gset.length] ++ f.gset ++ [f.attempts.length]
    ++ (f.attempts.map fun a => enc [a.1, a.2]) ++ [f.q, f.key]

section Ids
variable (hm : HashModel)

def pid (b : PBody) : Nat := hm.H (TAG_PRECOMMIT_ID :: b.bytes)
def pSign (b : PBody) : Nat := hm.H (TAG_PRECOMMIT_SIGN :: b.bytes)
def gid (g : GBody) : Nat := hm.H (TAG_POLICY_FULFILLMENT :: g.bytes)
def fid (f : FBody) : Nat := hm.H (TAG_FULFILLMENT_ID :: f.bytes)
def fSign (f : FBody) : Nat := hm.H (TAG_FULFILLMENT_SIGN :: f.bytes)

/-- `DlvPolicyFulfillment G_j` for leg `l` of `P`. `shadowOf E v` is the shadow
core `c°_{V}` that E's preimage commits for vault `v`. -/
def gFor (shadowOf : Nat → Nat → Nat) (P : PBody) (l : Leg) : GBody :=
  ⟨pid hm P, P.e, l.vault, l.parent, shadowOf P.e l.vault⟩

/-- The canonical policy-fulfillment set, one id per P leg, in P's leg order. -/
def canonSet (shadowOf : Nat → Nat → Nat) (P : PBody) : List Nat :=
  P.legs.map fun l => gid hm (gFor hm shadowOf P l)

end Ids

/-- The identities a verifier derives from signed envelopes. -/
def precommitIdOf (hm : HashModel) (env : Envelope PBody) : Nat := pid hm env.body
def fulfillmentIdOf (hm : HashModel) (env : Envelope FBody) : Nat := fid hm env.body

/-- Alternate valid signatures over one body are one object. -/
theorem identity_is_signature_independent (hm : HashModel) (a b : Envelope PBody)
    (c d : Envelope FBody) (h : a.body = b.body) (h' : c.body = d.body) :
    precommitIdOf hm a = precommitIdOf hm b ∧ pSign hm a.body = pSign hm b.body
      ∧ fulfillmentIdOf hm c = fulfillmentIdOf hm d := by
  unfold precommitIdOf fulfillmentIdOf
  rw [h, h']; exact ⟨rfl, rfl, rfl⟩

theorem identity_and_signing_digest_are_domain_separated (hm : HashModel) (b : PBody) :
    pid hm b ≠ pSign hm b ∧ ∀ f : FBody, fid hm f ≠ fSign hm f := by
  refine ⟨fun h => ?_, fun f h => ?_⟩
  · have := hm.injective _ _ h
    simp [TAG_PRECOMMIT_ID, TAG_PRECOMMIT_SIGN] at this
  · have := hm.injective _ _ h
    simp [TAG_FULFILLMENT_ID, TAG_FULFILLMENT_SIGN] at this

/-- Policy witness material. It is published under a content-addressed
`PolicyFulfillmentAuxRef`, never inside the G body. -/
structure Witness where
  cls : Nat
  bytes : List Nat

structure AuxRef where
  pfid : Nat
  cls : Nat
  addr : Nat
  deriving DecidableEq, Repr

/-- Building `G_j` together with its auxiliary reference. -/
def buildG (hm : HashModel) (shadowOf : Nat → Nat → Nat) (P : PBody) (l : Leg) (w : Witness) :
    GBody × AuxRef :=
  let g := gFor hm shadowOf P l
  (g, ⟨gid hm g, w.cls, hm.H w.bytes⟩)

theorem witness_encoding_does_not_change_policy_fulfillment_id (hm : HashModel)
    (shadowOf : Nat → Nat → Nat) (P : PBody) (l : Leg) (w1 w2 : Witness) :
    gid hm (buildG hm shadowOf P l w1).1 = gid hm (buildG hm shadowOf P l w2).1 := rfl

theorem gid_depends_only_on_identity_fields (hm : HashModel) (g1 g2 : GBody)
    (h1 : g1.pid = g2.pid) (h2 : g1.e = g2.e) (h3 : g1.vault = g2.vault)
    (h4 : g1.parent = g2.parent) (h5 : g1.shadow = g2.shadow) : gid hm g1 = gid hm g2 := by
  cases g1; cases g2; simp only at h1 h2 h3 h4 h5; subst h1 h2 h3 h4 h5; rfl

/-- EXACTLY ONE `PolicyFulfillmentId` per `(P, E, vault, parent, shadow)`: two
constructions for legs naming the same vault and parent, with any witnesses, give
one id. -/
theorem policy_fulfillment_identity_canonical_per_leg (hm : HashModel)
    (shadowOf : Nat → Nat → Nat) (P : PBody) (l1 l2 : Leg) (hv : l1.vault = l2.vault)
    (hp : l1.parent = l2.parent) (w1 w2 : Witness) :
    gid hm (buildG hm shadowOf P l1 w1).1 = gid hm (buildG hm shadowOf P l2 w2).1 :=
  gid_depends_only_on_identity_fields hm _ _ rfl rfl hv hp (by simp [buildG, gFor, hv])

theorem gid_injective (hm : HashModel) {g1 g2 : GBody} (h : gid hm g1 = gid hm g2) : g1 = g2 := by
  have := hm.injective _ _ h
  cases g1; cases g2
  simp [GBody.bytes] at this
  obtain ⟨h1, h2, h3, h4, h5⟩ := this
  subst h1 h2 h3 h4 h5; rfl

theorem mem_canonSet {hm : HashModel} {shadowOf : Nat → Nat → Nat} {P : PBody} {x : Nat} :
    x ∈ canonSet hm shadowOf P ↔ ∃ l ∈ P.legs, x = gid hm (gFor hm shadowOf P l) := by
  unfold canonSet
  constructor
  · intro h
    obtain ⟨l, hl, rfl⟩ := List.mem_map.mp h
    exact ⟨l, hl, rfl⟩
  · rintro ⟨l, hl, rfl⟩
    exact List.mem_map.mpr ⟨l, hl, rfl⟩

/-- A witness is bound to its precommit, its E, its DLV parent and its shadow: a
G computed for leg `l` of `P` belongs to the canonical set of `P'` only when
`P'` has the same identity and names the same vault and parent. -/
theorem policy_fulfillment_bound_to_precommit_parent_and_shadow (hm : HashModel)
    (shadowOf : Nat → Nat → Nat) (P P' : PBody) (l : Leg)
    (h : gid hm (gFor hm shadowOf P l) ∈ canonSet hm shadowOf P') :
    pid hm P = pid hm P' ∧ P.e = P'.e
      ∧ ∃ l' ∈ P'.legs, l'.vault = l.vault ∧ l'.parent = l.parent
        ∧ shadowOf P'.e l'.vault = shadowOf P.e l.vault := by
  obtain ⟨l', hl', heq⟩ := mem_canonSet.mp h
  have hg := gid_injective hm heq
  simp only [gFor, GBody.mk.injEq] at hg
  obtain ⟨h1, h2, h3, h4, h5⟩ := hg
  exact ⟨h1, h2, l', hl', h3.symm, h4.symm, h5.symm⟩


-- ── §3 hash order: 𝒞_E^pre → E → P → G → F → C_q ────────────────────────

inductive ObjClass where
  | setup
  | precommit
  | policyFulfillment
  | fulfillment
  | resolutionClaim
  | resolutionRecord
  | other (n : Nat)
  deriving DecidableEq, Repr

/-- `ValidationRef`, the typed union. -/
inductive ValidationRef where
  | contentAddr (cls : ObjClass) (addr : Nat)
  | singleRootClaim (claimRef : Nat)
  | conditionalClaim (genesis device p fulfillmentId : Nat)
  | setupRef (rho : Nat)
  deriving DecidableEq, Repr

/-- Classes that depend on the current E, or that have their own variant, may not
be content-bound in `𝒞_E^pre`. -/
def forbiddenInClosure : ObjClass → Bool
  | .other _ => false
  | _ => true

/-- Admissibility of one closure reference for an E at trader position `q`.
A conditional claim is a structurally earlier dependency: `p < q`. -/
def refAdmissible (q : Nat) : ValidationRef → Bool
  | .contentAddr cls _ => !forbiddenInClosure cls
  | .conditionalClaim _ _ p _ => decide (p < q)
  | .singleRootClaim _ => true
  | .setupRef _ => true

def refDigest (hm : HashModel) : ValidationRef → Nat
  | .contentAddr _ a => hm.H [0, a]
  | .singleRootClaim c => hm.H [1, c]
  | .conditionalClaim g d p x => hm.H [2, g, d, p, x]
  | .setupRef r => hm.H [3, r]

section Order
variable (hm : HashModel)

/-- E: attempt-independent, over the closure digests and the rest of `P(E)`. -/
def extId (closure : List ValidationRef) (rest : List Nat) : Nat :=
  hm.H (TAG_EXT :: (closure.map (refDigest hm) ++ rest))

/-- `C_q = SofiResolutionClaim(G, DevID, q, FulfillmentId, R_realize, R_void)`. -/
def claimId (P : PBody) (F : FBody) : Nat :=
  hm.H [TAG_RESOLUTION_CLAIM, P.genesis, P.device, F.q, fid hm F, P.realize, P.void]

end Order

/-- THE HASH ORDER IS ACYCLIC. Every closure digest precedes E, E precedes P,
P precedes each G, each G and P precede F, and F precedes `C_q`. Nothing
stores a route outcome (Section 21): there is no `K_out`. -/
theorem p_g_f_hash_order_acyclic (hm : HashModel) (shadowOf : Nat → Nat → Nat)
    (closure : List ValidationRef) (rest : List Nat) (P : PBody) (F : FBody)
    (hE : P.e = extId hm closure rest) (hP : F.pid = pid hm P)
    (hG : F.gset = canonSet hm shadowOf P) :
    (∀ r ∈ closure, refDigest hm r < P.e)
      ∧ P.e < pid hm P
      ∧ (∀ g ∈ canonSet hm shadowOf P, pid hm P < g ∧ P.e < g ∧ g < fid hm F)
      ∧ pid hm P < fid hm F
      ∧ fid hm F < claimId hm P F := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · intro r hr
    rw [hE]
    exact hm.dominates _ _ (List.mem_cons_of_mem _ (List.mem_append_left _ (List.mem_map_of_mem hr)))
  · exact hm.dominates _ _ (by simp [PBody.bytes])
  · intro g hg
    obtain ⟨l, _, rfl⟩ := mem_canonSet.mp hg
    refine ⟨hm.dominates _ _ (by simp [GBody.bytes, gFor]), hm.dominates _ _ (by simp [GBody.bytes, gFor]), ?_⟩
    apply hm.dominates
    rw [← hG] at hg
    simp [FBody.bytes, hg]
  · have := hm.dominates (TAG_FULFILLMENT_ID :: F.bytes) F.pid (by simp [FBody.bytes])
    rw [hP] at this; exact this
  · exact hm.dominates _ _ (by simp)

/-- Hence no current-E object can be named in the closure: its address is
strictly after E, and every closure digest strictly before. -/
theorem current_e_objects_never_in_closure (hm : HashModel) (shadowOf : Nat → Nat → Nat)
    (closure : List ValidationRef) (rest : List Nat) (P : PBody) (F : FBody)
    (hE : P.e = extId hm closure rest) (hP : F.pid = pid hm P)
    (hG : F.gset = canonSet hm shadowOf P) (r : ValidationRef) (hr : r ∈ closure) :
    refDigest hm r ≠ pid hm P ∧ (∀ g ∈ canonSet hm shadowOf P, refDigest hm r ≠ g)
      ∧ refDigest hm r ≠ fid hm F ∧ refDigest hm r ≠ claimId hm P F := by
  obtain ⟨h1, h2, h3, h4, h5⟩ := p_g_f_hash_order_acyclic hm shadowOf closure rest P F hE hP hG
  have hr' := h1 r hr
  refine ⟨by omega, fun g hg => ?_, by omega, by omega⟩
  have := (h3 g hg).2.1
  omega

/-- The rejected design: a closure that must name its own precommit has no
construction. -/
theorem precommit_in_its_own_closure_is_unconstructible (hm : HashModel)
    (closure : List ValidationRef) (rest : List Nat) (P : PBody)
    (hE : P.e = extId hm closure rest) :
    ¬ ∃ r ∈ closure, refDigest hm r = pid hm P := by
  rintro ⟨r, hr, heq⟩
  have h1 : refDigest hm r < P.e := by
    rw [hE]
    exact hm.dominates _ _ (List.mem_cons_of_mem _ (List.mem_append_left _ (List.mem_map_of_mem hr)))
  have h2 : P.e < pid hm P := hm.dominates _ _ (by simp [PBody.bytes])
  omega

/-- A prior fulfillment's conditional claim is admissible in a later closure and
precedes the new E: the closure excludes current-E objects, never prior-E ones. -/
theorem closure_admits_prior_e (hm : HashModel) (q g d p x : Nat) (rest : List Nat)
    (hp : p < q) :
    refAdmissible q (.conditionalClaim g d p x) = true
      ∧ refDigest hm (.conditionalClaim g d p x) < extId hm [.conditionalClaim g d p x] rest := by
  refine ⟨by simp [refAdmissible, hp], hm.dominates _ _ (by simp)⟩

theorem closure_refuses_current_e_classes (q a : Nat) :
    refAdmissible q (.contentAddr .precommit a) = false
      ∧ refAdmissible q (.contentAddr .policyFulfillment a) = false
      ∧ refAdmissible q (.contentAddr .fulfillment a) = false
      ∧ refAdmissible q (.contentAddr .resolutionClaim a) = false
      ∧ refAdmissible q (.contentAddr .setup a) = false := by
  simp [refAdmissible, forbiddenInClosure]

theorem structurally_earlier_dependencies (q g d p x : Nat)
    (h : refAdmissible q (.conditionalClaim g d p x) = true) : p < q := by
  simpa [refAdmissible] using h

-- ── §4 fulfillment conformance ────────────────────────────────────────────

def U64_MAX : Nat := 2 ^ 64 - 1

/-- `FulfillmentConforming(F)`, mechanical, checked at ingress. -/
def Conforming (hm : HashModel) (shadowOf : Nat → Nat → Nat) (P : PBody) (F : FBody) : Prop :=
  F.pid = pid hm P ∧ F.gset = canonSet hm shadowOf P
    ∧ F.attempts.map Prod.fst = P.legs.map Leg.vault
    ∧ P.p < U64_MAX ∧ F.q = P.p + 1 ∧ F.key = P.key

/-- NO HALF-FULFILLMENT: a conforming F carries the policy fulfillment of every
P leg and nothing else. -/
theorem fulfillment_requires_complete_policy_fulfillment_set {hm : HashModel}
    {shadowOf : Nat → Nat → Nat} {P : PBody} {F : FBody} (h : Conforming hm shadowOf P F) :
    (∀ l ∈ P.legs, gid hm (gFor hm shadowOf P l) ∈ F.gset)
      ∧ (∀ x ∈ F.gset, ∃ l ∈ P.legs, x = gid hm (gFor hm shadowOf P l))
      ∧ F.attempts.length = P.legs.length := by
  obtain ⟨_, hG, hA, _⟩ := h
  refine ⟨fun l hl => ?_, fun x hx => ?_, ?_⟩
  · rw [hG]; exact mem_canonSet.mpr ⟨l, hl, rfl⟩
  · rw [hG] at hx; exact mem_canonSet.mp hx
  · have := congrArg List.length hA
    simpa using this

/-- The DLV parents a fulfillment's policy set covers, in P's leg order. -/
def fLegs (hm : HashModel) (shadowOf : Nat → Nat → Nat) (P : PBody) (F : FBody) : List Nat :=
  (P.legs.filter fun l => decide (gid hm (gFor hm shadowOf P l) ∈ F.gset)).map Leg.parent

theorem fLegs_conforming {hm : HashModel} {shadowOf : Nat → Nat → Nat} {P : PBody} {F : FBody}
    (h : Conforming hm shadowOf P F) : fLegs hm shadowOf P F = P.legs.map Leg.parent := by
  have hall := (fulfillment_requires_complete_policy_fulfillment_set h).1
  unfold fLegs
  rw [List.filter_eq_self.mpr (fun l hl => by simpa using hall l hl)]

theorem conforming_is_signature_bound {hm : HashModel} {shadowOf : Nat → Nat → Nat}
    {P : PBody} {F : FBody} (h : Conforming hm shadowOf P F) : F.key = P.key ∧ F.q = P.p + 1 :=
  ⟨h.2.2.2.2.2, h.2.2.2.2.1⟩

-- ── §5 validation: three values, static, bounded, candidate-driven ────────

inductive Validation where
  | valid
  | invalid
  | unavailable
  deriving DecidableEq, Repr

/-- Three-valued conjunction: any Invalid → Invalid; else any Unavailable →
Unavailable; else Valid. -/
def Validation.and : Validation → Validation → Validation
  | .invalid, _ => .invalid
  | _, .invalid => .invalid
  | .unavailable, _ => .unavailable
  | _, .unavailable => .unavailable
  | .valid, .valid => .valid

def allV : List Validation → Validation
  | [] => .valid
  | v :: vs => v.and (allV vs)

/-- More evidence only resolves Unavailable. -/
def Refines : Validation → Validation → Prop
  | .unavailable, _ => True
  | v, v' => v = v'

theorem Validation.and_comm (a b : Validation) : a.and b = b.and a := by
  cases a <;> cases b <;> rfl

theorem and_refines {a a' b b' : Validation} (ha : Refines a a') (hb : Refines b b') :
    Refines (a.and b) (a'.and b') := by
  cases a <;> cases b <;> cases a' <;> cases b' <;> simp_all [Refines, Validation.and]

theorem allV_invalid_iff : ∀ l : List Validation, allV l = .invalid ↔ .invalid ∈ l := by
  intro l
  induction l with
  | nil => simp [allV]
  | cons v vs ih => cases v <;> cases h : allV vs <;> simp_all [allV, Validation.and]

theorem allV_valid_iff : ∀ l : List Validation, allV l = .valid ↔ ∀ v ∈ l, v = .valid := by
  intro l
  induction l with
  | nil => simp [allV]
  | cons v vs ih =>
    rw [List.forall_mem_cons, ← ih]
    show v.and (allV vs) = .valid ↔ v = .valid ∧ allV vs = .valid
    generalize allV vs = w
    cases v <;> cases w <;> decide

theorem invalid_refines_only_to_invalid {v : Validation} (h : Refines .invalid v) : v = .invalid :=
  h.symm

theorem valid_refines_only_to_valid {v : Validation} (h : Refines .valid v) : v = .valid :=
  h.symm

structure Evidence where
  /-- `PolicyFulfillmentValid(P, G_j, E)` per policy-fulfillment id, as far as
  the verifying evidence at hand establishes it. -/
  policy : Nat → Validation
  traderSide : Validation
  routeWide : Validation

def EvRefines (ev ev' : Evidence) : Prop :=
  (∀ x, Refines (ev.policy x) (ev'.policy x)) ∧ Refines ev.traderSide ev'.traderSide
    ∧ Refines ev.routeWide ev'.routeWide

/-- `RouteValidation(P, G, E)`. Its inputs are the policy-fulfillment set and the
evidence; there is no attempt, finality, canonicality or outcome input. -/
def routeValidation (gset : List Nat) (ev : Evidence) : Validation :=
  (allV (gset.map ev.policy)).and (ev.traderSide.and ev.routeWide)

theorem allV_map_refines (xs : List Nat) {f f' : Nat → Validation}
    (h : ∀ x, Refines (f x) (f' x)) : Refines (allV (xs.map f)) (allV (xs.map f')) := by
  induction xs with
  | nil => simp [allV, Refines]
  | cons x xs ih => exact and_refines (h x) ih

theorem route_validation_refines {gset : List Nat} {ev ev' : Evidence} (h : EvRefines ev ev') :
    Refines (routeValidation gset ev) (routeValidation gset ev') :=
  and_refines (allV_map_refines gset h.1) (and_refines h.2.1 h.2.2)

/-- The validation a verifier evaluates for ANY conforming fulfillment of a
precommit, registered or not: the verdict is a function of P's canonical
witness set, which is why several candidates share it (R15-2). -/
def fulfillmentValidation (F : FBody) (ev : Evidence) : Validation := routeValidation F.gset ev

/-- STATIC: every fulfillment of one precommit sees the same RouteValidation,
whatever its attempt vector, and more evidence never reverses a verdict. -/
theorem route_validation_is_static {hm : HashModel} {shadowOf : Nat → Nat → Nat}
    {P : PBody} {F1 F2 : FBody} (h1 : Conforming hm shadowOf P F1)
    (h2 : Conforming hm shadowOf P F2) (ev ev' : Evidence) :
    fulfillmentValidation F1 ev = fulfillmentValidation F2 ev
      ∧ (EvRefines ev ev' → Refines (fulfillmentValidation F1 ev) (fulfillmentValidation F1 ev')) := by
  refine ⟨?_, fun he => route_validation_refines he⟩
  unfold fulfillmentValidation
  rw [h1.2.1, h2.2.1]

/-- Arm (i) of RouteImpossible is a predicate on P alone. -/
def ArmInvalid (hm : HashModel) (shadowOf : Nat → Nat → Nat) (P : PBody) (ev : Evidence) : Prop :=
  routeValidation (canonSet hm shadowOf P) ev = .invalid

theorem route_impossible_invalid_arm_monotone_without_f_quantification {hm : HashModel}
    {shadowOf : Nat → Nat → Nat} {P : PBody} {ev ev' : Evidence} :
    (∀ F, Conforming hm shadowOf P F → (routeValidation F.gset ev = .invalid ↔ ArmInvalid hm shadowOf P ev))
      ∧ (ArmInvalid hm shadowOf P ev → EvRefines ev ev' → ArmInvalid hm shadowOf P ev') := by
  refine ⟨fun F hF => by rw [hF.2.1]; rfl, fun ha he => ?_⟩
  have := route_validation_refines (gset := canonSet hm shadowOf P) he
  unfold ArmInvalid at *
  rw [ha] at this
  exact invalid_refines_only_to_invalid this

/-- The rejected alternative: arm (i) evaluated per F over an arbitrary policy
set. Two fulfillments of one P then disagree about whether P is impossible. -/
theorem per_f_arm_diverges :
    let ev : Evidence := ⟨fun x => if x = 7 then .invalid else .valid, .valid, .valid⟩
    routeValidation [5] ev = .valid ∧ routeValidation [7] ev = .invalid := by
  decide

-- auxiliary evidence candidates

structure Candidate where
  ref : AuxRef
  verifies : Bool
  size : Nat
  deriving DecidableEq, Repr

/-- Candidates are write-once BY CONTENT ADDRESS; there is no `(id, class)` slot. -/
def storeCandidate (store : List Candidate) (c : Candidate) : List Candidate :=
  if store.any (fun d => d.ref.addr == c.ref.addr) then store else c :: store

/-- The rejected design: one write-once slot per `(PolicyFulfillmentId, class)`. -/
def storeSlot (store : List Candidate) (c : Candidate) : List Candidate :=
  if store.any (fun d => d.ref.pfid == c.ref.pfid && d.ref.cls == c.ref.cls) then store else c :: store

theorem aux_candidates_are_content_addressed_no_singleton_slot (store : List Candidate)
    (c : Candidate) (hfresh : ∀ d ∈ store, d.ref.addr ≠ c.ref.addr) :
    c ∈ storeCandidate store c := by
  unfold storeCandidate
  have : store.any (fun d => d.ref.addr == c.ref.addr) = false := by
    simpa using hfresh
  rw [this]
  simp

/-- A hostile first write occupies a singleton slot, and the usable proof can
never be stored. -/
theorem singleton_slot_is_hostile :
    let garbage : Candidate := ⟨⟨9, 1, 100⟩, false, 10⟩
    let good : Candidate := ⟨⟨9, 1, 200⟩, true, 10⟩
    storeSlot [garbage] good = [garbage] ∧ good ∈ storeCandidate [garbage] good := by
  decide

/-- Examining candidates under a candidate-count budget and a local byte budget. -/
def examine : Nat → Nat → List Candidate → Validation
  | 0, _, _ => .unavailable
  | _ + 1, _, [] => .unavailable
  | n + 1, bytes, c :: cs =>
    if bytes < c.size then .unavailable
    else if c.verifies then .valid
    else examine n (bytes - c.size) cs

/-- NOTE 9: a candidate establishes that a validity step HOLDS, or nothing.
Missing, garbage or unexamined candidates never yield Invalid. -/
theorem aux_candidate_cannot_establish_invalid :
    ∀ (n bytes : Nat) (cs : List Candidate), examine n bytes cs ≠ .invalid := by
  intro n
  induction n with
  | zero => intro _ _; simp [examine]
  | succ n ih =>
    intro bytes cs
    cases cs with
    | nil => simp [examine]
    | cons c cs =>
      simp only [examine]
      split
      · simp
      · split
        · simp
        · exact ih _ _

/-- R13-2: exhausting either budget yields Unavailable; a Valid verdict always
rests on a verifying candidate. -/
theorem budget_exhaustion_never_yields_invalid :
    (∀ bytes cs, examine 0 bytes cs = .unavailable)
      ∧ (∀ n bytes c cs, bytes < c.size → examine (n + 1) bytes (c :: cs) = .unavailable)
      ∧ (∀ n bytes cs, examine n bytes cs = .valid → ∃ c ∈ cs, c.verifies = true) := by
  refine ⟨fun _ _ => rfl, fun n bytes c cs h => by simp [examine, h], ?_⟩
  intro n
  induction n with
  | zero => intro _ _ h; simp [examine] at h
  | succ n ih =>
    intro bytes cs h
    cases cs with
    | nil => simp [examine] at h
    | cons c cs =>
      simp only [examine] at h
      split at h
      · cases h
      · split at h
        · rename_i hv; exact ⟨c, List.mem_cons_self, hv⟩
        · obtain ⟨d, hd, hv⟩ := ih _ _ h
          exact ⟨d, List.mem_cons_of_mem _ hd, hv⟩

/-- Supplying the valid address validates, whatever garbage exists elsewhere. -/
theorem supplying_the_valid_address_validates (n bytes : Nat) (c : Candidate)
    (hv : c.verifies = true) (hb : c.size ≤ bytes) : examine (n + 1) bytes [c] = .valid := by
  simp [examine, hv, Nat.not_lt.mpr hb]

def MAX_CLOSURE_REFS : Nat := 64
def MAX_CLOSURE_OBJECT_BYTES : Nat := 256 * 1024
def MAX_AUTH_ENVELOPES : Nat := 16
def MAX_VALIDATION_FETCH_BYTES : Nat := 4 * 1024 * 1024
def MAX_PROVENANCE_FANOUT : Nat := 16
def MAX_SETTLEMENT_PREIMAGE_BYTES : Nat := 256 * 1024

def sumSizes : List Candidate → Nat
  | [] => 0
  | c :: cs => c.size + sumSizes cs

/-- `U(E)` bytes: only verifying objects count. -/
def fetchBytes (used : List Candidate) : Nat := sumSizes (used.filter (·.verifies))

theorem garbage_candidates_do_not_consume_fetch_bound (garbage used : List Candidate)
    (hg : ∀ c ∈ garbage, c.verifies = false) :
    fetchBytes (garbage ++ used) = fetchBytes used := by
  unfold fetchBytes
  rw [List.filter_append, List.filter_eq_nil_iff.mpr (fun c hc => by simp [hg c hc])]
  rfl

/-- The rejected accounting: counting garbage flips an honest route Invalid. -/
theorem counting_garbage_flips_an_honest_route :
    let honest : List Candidate := [⟨⟨1, 1, 1⟩, true, 1024⟩]
    let flood : List Candidate := [⟨⟨1, 1, 2⟩, false, 4 * 1024 * 1024⟩]
    fetchBytes (flood ++ honest) ≤ MAX_VALIDATION_FETCH_BYTES
      ∧ MAX_VALIDATION_FETCH_BYTES < sumSizes (flood ++ honest) := by
  decide

/-- What the candidate's own bytes and the retrieved canonical objects establish. -/
structure Sizes where
  refs : Nat
  authEnvelopes : Nat
  preimage : Nat
  fanout : Nat
  /-- Canonical size of each referenced object; `none` when not retrieved. -/
  objects : List (Option Nat)

def retrievedBytes : List (Option Nat) → Nat
  | [] => 0
  | o :: os => o.getD 0 + retrievedBytes os

def knownViolation (s : Sizes) : Bool :=
  decide (MAX_CLOSURE_REFS < s.refs) || decide (MAX_AUTH_ENVELOPES < s.authEnvelopes)
    || decide (MAX_SETTLEMENT_PREIMAGE_BYTES < s.preimage) || decide (MAX_PROVENANCE_FANOUT < s.fanout)
    || s.objects.any (fun o => match o with
        | some n => decide (MAX_CLOSURE_OBJECT_BYTES < n)
        | none => false)
    || decide (MAX_VALIDATION_FETCH_BYTES < retrievedBytes s.objects)

def bounded (s : Sizes) (v : Validation) : Validation := if knownViolation s then .invalid else v

/-- A known bound violation is Invalid, never Unavailable, however much other
evidence is missing. -/
theorem bound_violation_is_invalid_never_unavailable (s : Sizes) (h : knownViolation s = true) :
    bounded s .unavailable = .invalid := by
  simp [bounded, h]

/-- Unretrieved objects never establish a violation: with nothing retrieved, only
the candidate's own counts can. -/
theorem unretrieved_objects_never_establish_a_violation (s : Sizes)
    (hnone : ∀ o ∈ s.objects, o = none) (hr : s.refs ≤ MAX_CLOSURE_REFS)
    (ha : s.authEnvelopes ≤ MAX_AUTH_ENVELOPES) (hp : s.preimage ≤ MAX_SETTLEMENT_PREIMAGE_BYTES)
    (hf : s.fanout ≤ MAX_PROVENANCE_FANOUT) : bounded s .unavailable = .unavailable := by
  have hsum : ∀ os : List (Option Nat), (∀ o ∈ os, o = none) → retrievedBytes os = 0 := by
    intro os
    induction os with
    | nil => intro _; rfl
    | cons o os ih =>
      intro h
      simp [retrievedBytes, h o List.mem_cons_self, ih (fun x hx => h x (List.mem_cons_of_mem _ hx))]
  have hany : s.objects.any (fun o => match o with
      | some n => decide (MAX_CLOSURE_OBJECT_BYTES < n)
      | none => false) = false := by
    rw [List.any_eq_false]
    intro o ho
    rw [hnone o ho]
    simp
  simp [bounded, knownViolation, hsum s.objects hnone, hany, Nat.not_lt.mpr hr, Nat.not_lt.mpr ha,
    Nat.not_lt.mpr hp, Nat.not_lt.mpr hf, MAX_VALIDATION_FETCH_BYTES]


-- ── §6 what storing P, G and F does ───────────────────────────────────────

/-- One trader lineage and the DLV parents it references, at the level of
registered facts (the leader-first cell layer is DSMSofiSuccessorCells; nothing
votes and nothing is counted against a threshold). -/
structure Sys where
  ps : List PBody
  gs : List GBody
  kful : Nat → Option FBody
  kroot : Nat → Option Nat
  consumed : Nat → Option Nat

/-- Everything economic: registered fulfillments, registered root claims, and
canonical DLV consumption. -/
def Sys.econ (s : Sys) : (Nat → Option FBody) × (Nat → Option Nat) × (Nat → Option Nat) :=
  (s.kful, s.kroot, s.consumed)

def storeP (P : PBody) (s : Sys) : Sys := { s with ps := P :: s.ps }
def storeG (g : GBody) (s : Sys) : Sys := { s with gs := g :: s.gs }

/-- P ingress: the exact parent claim at `K_root(p)`. It is not a head check. -/
def PIngress (s : Sys) (P : PBody) : Prop := s.kroot P.p = some P.parentClaim

/-- G ingress: binding to a stored P leg. Policy correctness is never checked. -/
def GIngress (hm : HashModel) (shadowOf : Nat → Nat → Nat) (s : Sys) (g : GBody) : Prop :=
  ∃ P ∈ s.ps, ∃ l ∈ P.legs, g = gFor hm shadowOf P l

/-- Registration (Section 13): `F` is the first object at the leader of
`K_ful(q)` and `C_q` the first at `K_root(q)` -- the race at the position
pair, and nothing else. No member checks P, the witnesses, conformance or a
parent; registered is not conforming (Section 20.2), and storage cannot know
whether a DLV parent is still unconsumed. -/
def FIngress (hm : HashModel) (_shadowOf : Nat → Nat → Nat) (s : Sys) (P : PBody) (F : FBody) : Prop :=
  (s.kful F.q = none ∨ s.kful F.q = some F)
    ∧ (s.kroot F.q = none ∨ s.kroot F.q = some (claimId hm P F))

/-- ONE transaction: `K_ful(q) ↦ F` and `K_root(q) ↦ C_q`. -/
def fulfillStep (hm : HashModel) (P : PBody) (F : FBody) (s : Sys) : Sys :=
  { s with kful := fun q => if q = F.q then some F else s.kful q,
           kroot := fun q => if q = F.q then some (claimId hm P F) else s.kroot q }

def RootIngress (s : Sys) (q : Nat) : Prop := s.kroot q = none

def rootStep (q c : Nat) (s : Sys) : Sys :=
  { s with kroot := fun q' => if q' = q then some c else s.kroot q' }

/-- A DLV parent's canonical consumption. Only an earlier consumption refuses it. -/
def ConsumeIngress (s : Sys) (R : Nat) : Prop := s.consumed R = none

def consumeStep (R e : Nat) (s : Sys) : Sys :=
  { s with consumed := fun r => if r = R then some e else s.consumed r }

inductive SysStep (hm : HashModel) (shadowOf : Nat → Nat → Nat) : Sys → Sys → Prop
  | storeP (s : Sys) (P : PBody) : PIngress s P → SysStep hm shadowOf s (storeP P s)
  | storeG (s : Sys) (g : GBody) : GIngress hm shadowOf s g → SysStep hm shadowOf s (storeG g s)
  | fulfill (s : Sys) (P : PBody) (F : FBody) : FIngress hm shadowOf s P F →
      SysStep hm shadowOf s (fulfillStep hm P F s)
  | root (s : Sys) (q c : Nat) : RootIngress s q → SysStep hm shadowOf s (rootStep q c s)
  | consume (s : Sys) (R e : Nat) : ConsumeIngress s R → SysStep hm shadowOf s (consumeStep R e s)

inductive SysReach (hm : HashModel) (shadowOf : Nat → Nat → Nat) : Sys → Sys → Prop
  | refl (s : Sys) : SysReach hm shadowOf s s
  | tail {a b c : Sys} : SysReach hm shadowOf a b → SysStep hm shadowOf b c → SysReach hm shadowOf a c

/-- POSITION PAIR ATOMIC (rebuild step R9, `no_member_ever_holds_one_half_of_a_position`):
`K_ful(q)` is never held without `K_root(q)`. The only step that writes
`K_ful` is `fulfillStep`, and it writes both keys in one transaction; the
other steps leave `K_ful` alone and never clear `K_root`. Mutation:
`fulfillStep` writing `kful` only — this fails. -/
theorem position_pair_atomic (hm : HashModel) (shadowOf : Nat → Nat → Nat) {s₀ s : Sys}
    (h₀ : ∀ q, s₀.kful q = none) (hr : SysReach hm shadowOf s₀ s) :
    ∀ q F, s.kful q = some F → s.kroot q ≠ none := by
  induction hr with
  | refl => intro q F h; rw [h₀ q] at h; cases h
  | tail _ hstep ih =>
    intro q F h
    cases hstep with
    | storeP P _ => exact ih q F h
    | storeG g _ => exact ih q F h
    | fulfill P F' _ =>
      simp only [fulfillStep] at h ⊢
      by_cases hq : q = F'.q
      · simp [hq]
      · simp only [hq, if_false] at h ⊢; exact ih q F h
    | root q' c _ =>
      simp only [rootStep] at h ⊢
      by_cases hq : q = q'
      · simp [hq]
      · simp only [hq, if_false]; exact ih q F h
    | consume R e _ => exact ih q F h

/-- P IS NON-ECONOMIC: storing it occupies no position and changes no economic
fact or any guard that does not name it. Abandoning it has no effect. -/
theorem precommit_is_non_economic (P : PBody) (s : Sys) :
    (storeP P s).econ = s.econ
      ∧ (∀ q, RootIngress (storeP P s) q ↔ RootIngress s q)
      ∧ (∀ R, ConsumeIngress (storeP P s) R ↔ ConsumeIngress s R)
      ∧ (∀ P', PIngress (storeP P s) P' ↔ PIngress s P') :=
  ⟨rfl, fun _ => Iff.rfl, fun _ => Iff.rfl, fun _ => Iff.rfl⟩

/-- G IS NON-ECONOMIC AND NON-LOCKING: after it is stored, every rival
consumption of its parent is admitted exactly as before. -/
theorem policy_fulfillment_is_non_economic_and_non_locking (g : GBody) (s : Sys) :
    (storeG g s).econ = s.econ
      ∧ (∀ R, ConsumeIngress (storeG g s) R ↔ ConsumeIngress s R)
      ∧ (∀ q, RootIngress (storeG g s) q ↔ RootIngress s q) :=
  ⟨rfl, fun _ => Iff.rfl, fun _ => Iff.rfl⟩

theorem gs_persist {hm : HashModel} {shadowOf : Nat → Nat → Nat} {s s' : Sys}
    (hr : SysReach hm shadowOf s s') {g : GBody} (hg : g ∈ s.gs) : g ∈ s'.gs := by
  induction hr with
  | refl => exact hg
  | tail _ hs ih =>
    cases hs with
    | storeG g' _ => exact List.mem_cons_of_mem _ ih
    | storeP => exact ih
    | fulfill => exact ih
    | root => exact ih
    | consume => exact ih

/-- The rejected design: a witness that locks its parent. -/
def ConsumeIngressLocking (s : Sys) (R e : Nat) : Prop :=
  s.consumed R = none ∧ ∀ g ∈ s.gs, g.parent = R → g.e = e

/-- A locking witness is a FREE LOCK: publish G, never fulfill, and every rival
consumption of the parent is refused forever. Nothing removes a stored G, and
there is no clock and no abort authority. -/
theorem locking_policy_fulfillment_is_a_free_lock {hm : HashModel} {shadowOf : Nat → Nat → Nat}
    {s s' : Sys} {g : GBody} {R e : Nat} (hg : g ∈ s.gs) (hR : g.parent = R) (he : g.e ≠ e)
    (hr : SysReach hm shadowOf s s') : ¬ ConsumeIngressLocking s' R e :=
  fun h => he (h.2 g (gs_persist hr hg) hR)

/-- F's OWN conditional successor does not expire T0: after `C_q` is installed,
P's parent claim at `p` is untouched (q = p + 1) and F is still the registered
value at `q`. -/
theorem own_conditional_successor_does_not_expire_T0 {hm : HashModel}
    {shadowOf : Nat → Nat → Nat} {s : Sys} {P : PBody} {F : FBody}
    (hp : PIngress s P) (hc : Conforming hm shadowOf P F) :
    PIngress (fulfillStep hm P F s) P ∧ FIngress hm shadowOf (fulfillStep hm P F s) P F := by
  have hq : P.p ≠ F.q := by rw [hc.2.2.2.2.1]; omega
  have hp' : PIngress (fulfillStep hm P F s) P := by
    show (if P.p = F.q then some (claimId hm P F) else s.kroot P.p) = some P.parentClaim
    rw [if_neg hq]; exact hp
  exact ⟨hp', Or.inr (if_pos rfl), Or.inr (if_pos rfl)⟩

/-- An incompatible trader transition at `q` refuses every fulfillment at `q`. -/
theorem incompatible_trader_transition_refuses_fulfillment {hm : HashModel}
    {shadowOf : Nat → Nat → Nat} {s : Sys} {P : PBody} {F : FBody} {c : Nat}
    (hk : s.kroot F.q = some c) (hne : c ≠ claimId hm P F) : ¬ FIngress hm shadowOf s P F := by
  rintro ⟨_, hr⟩
  rcases hr with h | h
  · rw [hk] at h; cases h
  · rw [hk] at h; exact hne (Option.some.inj h)

theorem a_registered_rival_refuses_fulfillment {hm : HashModel} {shadowOf : Nat → Nat → Nat}
    {s : Sys} {P : PBody} {F F' : FBody} (hk : s.kful F.q = some F') (hne : F' ≠ F) :
    ¬ FIngress hm shadowOf s P F := by
  rintro ⟨hf, _⟩
  rcases hf with h | h
  · rw [hk] at h; cases h
  · rw [hk] at h; exact hne (Option.some.inj h)

-- ── §7 one operation: consumption, resolution, atomicity ──────────────────

/-- The claim at `p` that P names as its trader parent `T0` (P15-3, R17-3).
A conforming producer never builds on a conditional parent Core has not
resolved (the fence, Section 22); an object supplied from outside may name
one, guessing which branch `p` will take, and rungs 1 and 2 of the ladder
classify it (Section 24). -/
inductive ParentState where
  /-- An ordinary single-root claim; P conformance pinned its root at ingress. -/
  | single
  /-- A conditional claim whose branch selection is not yet known. -/
  | openBranch
  /-- A conditional claim that selected the root P was built on. -/
  | taken
  /-- A conditional claim that selected the opposite branch. -/
  | otherBranch
  /-- A conditional claim that resolved Invalid: no root was ever selected. -/
  | noRoot
  deriving DecidableEq, Repr

def parentCompatible : ParentState → Bool
  | .single => true
  | .taken => true
  | _ => false

def parentImpossible : ParentState → Bool
  | .otherBranch => true
  | .noRoot => true
  | _ => false

def parentPending : ParentState → Bool
  | .openBranch => true
  | _ => false

/-- While the parent is open BOTH are false: an undecided parent decides
nothing, so it neither consumes nor makes the route impossible. Once it is
terminal exactly one holds. -/
theorem parent_states_are_exclusive (q : ParentState) :
    (parentCompatible q = true → parentImpossible q = false)
      ∧ (parentPending q = true → parentCompatible q = false ∧ parentImpossible q = false)
      ∧ (parentPending q = false → (parentCompatible q = true ↔ parentImpossible q = false)) := by
  cases q <;> refine ⟨?_, ?_, ?_⟩ <;> intro h <;> simp_all [parentCompatible, parentImpossible, parentPending]

theorem parent_compatible_is_not_pending {q : ParentState} (h : parentCompatible q = true) :
    parentPending q = false ∧ parentImpossible q = false := by
  cases q <;> simp_all [parentCompatible, parentImpossible, parentPending]

/-- What a verifier has established about a leg's named parent. -/
inductive ParentStatus where
  /-- `R = R*_g`: the root that vault's lineage took. -/
  | canonical
  /-- `R ≠ R*_g`: that generation went elsewhere, so this parent is
  permanently refuted. -/
  | orphaned
  /-- `R*_g` is not established. A parent not reached is not refuted. -/
  | unavailable
  deriving DecidableEq, Repr

/-- What a verifier has established about one fulfillment at one position. A
fulfillment that has not registered is carried with `registered := false`, and
the ladder answers Pending for it — the position's terminal answer comes from
the one fulfillment that does register (R15-2). Keys are DLV parents `R_j`;
per-parent facts are at the fulfillment's own attempt. -/
structure Facts where
  registered : Bool
  /-- The leg half of `RouteValidation(P, G, E)`: policy fulfillment,
  arithmetic, shadows, signatures, canonical witnesses. -/
  validation : Validation
  /-- `SetupValid` of every leg's setup — INSIDE RouteValidation (Section
  20.1), never a separate gate: `routeValidation` is the conjunction. -/
  setupValid : Validation := .valid
  /-- `FulfillmentConformance(F)` (Section 20.2). Registration supplies no
  truth value for it: a registered `F` may be `Invalid`. -/
  conformance : Validation := .valid
  /-- The parent `(v, g, R)` this leg names, against `R*_g`, the validated
  canonical root of that vault at that generation (owner ruling §44.4).
  THREE VALUED: this replaced a pair of booleans whose false-false corner
  meant two different things — a parent not reached, and a parent walked
  past — so `Coherent` had to ASSUME they were exclusive. There is now no
  value that is both, and the assumption is gone. -/
  parentStatus : Nat → ParentStatus
  live : Nat → Bool
  cell : Nat → Option Nat
  /-- `LegFacts::final_on_other`: another exercise's commitment reached this
  key's leader first, or is already final there. `LeaderHeld` settles the loss
  before any copy arrives; no key is ever dead. -/
  lostTo : Nat → Bool
  consumedElsewhere : Nat → Bool
  /-- The claim at `p` this operation was built on. An ordinary parent is the
  default, which is what every pre-P15-3 fact set means. -/
  parent : ParentState := .single

def legOk (x : Facts) (e R : Nat) : Bool :=
  x.parentStatus R == .canonical && x.live R && x.cell R == some e

/-- `RouteValidation(P, G, E)` = SetupValid ∧ the leg predicates, under the
three-valued conjunction. Removing SetupValid from here is the mutation
`realized_requires_valid_setup` must catch. -/
def Facts.routeValidation (x : Facts) : Validation := x.setupValid.and x.validation

theorem routeValidation_valid_iff (x : Facts) :
    x.routeValidation = .valid ↔ x.setupValid = .valid ∧ x.validation = .valid := by
  unfold Facts.routeValidation
  cases x.setupValid <;> cases x.validation <;> simp [Validation.and]

theorem routeValidation_invalid_iff (x : Facts) :
    x.routeValidation = .invalid ↔ x.setupValid = .invalid ∨ x.validation = .invalid := by
  unfold Facts.routeValidation
  cases x.setupValid <;> cases x.validation <;> simp [Validation.and]

/-- `ConsumedRoute(F, E)` (Section 23.2): registration, FulfillmentConformance,
RouteValidation, the trader parent, and every leg — never occupancy alone. A
single-vault trade is the one-leg case. -/
def ConsumedRoute (x : Facts) (legs : List Nat) (e : Nat) : Bool :=
  x.registered && x.conformance == .valid && x.routeValidation == .valid
    && legs.all (legOk x e) && parentCompatible x.parent

/-- Every reserved key permanently resolved: final, or lost to another
exercise at its leader. An input internal to resolution (Section 22); nothing
stores a route outcome. -/
def StorageResolved (x : Facts) (legs : List Nat) : Bool :=
  x.registered && legs.all (fun R => x.lostTo R || (x.cell R).isSome)

def cellOther (x : Facts) (e R : Nat) : Bool :=
  match x.cell R with
  | some y => y != e
  | none => false

def legLost (x : Facts) (e R : Nat) : Bool :=
  x.lostTo R || cellOther x e R || x.consumedElsewhere R || x.parentStatus R == .orphaned

def VoidEvidence (x : Facts) (legs : List Nat) (e : Nat) : Bool :=
  legs.any (legLost x e)

inductive Resolution where
  | pending
  | realized
  | invalid
  | void
  deriving DecidableEq, Repr

/-- The resolution ladder. Rungs 1 and 2 are the trader parent (P15-3): they
sit above every route result, because a position built on a branch the parent
never took is Invalid whatever its own legs did. Void requires
`RouteValidation = Valid`: that is what "Pending otherwise, including
Unavailable" and "permanent once non-Pending" jointly require (see
`literal_ladder_is_not_permanent`). -/
def resolve (x : Facts) (legs : List Nat) (e : Nat) : Resolution :=
  if x.registered = false then .pending
  else if parentPending x.parent = true then .pending
  else if parentImpossible x.parent = true then .invalid
  else if x.conformance = .invalid then .invalid
  else if x.conformance = .unavailable then .pending
  else if ConsumedRoute x legs e = true then .realized
  else if x.routeValidation = .invalid then .invalid
  else if x.routeValidation = .valid ∧ StorageResolved x legs = true ∧ VoidEvidence x legs e = true then .void
  else .pending

def resolveLiteral (x : Facts) (legs : List Nat) (e : Nat) : Resolution :=
  if x.registered = false then .pending
  else if ConsumedRoute x legs e = true then .realized
  else if x.routeValidation = .invalid then .invalid
  else if StorageResolved x legs = true ∧ VoidEvidence x legs e = true then .void
  else .pending

/-- The storage and walk facts the cell layer proves (DSMSofiSuccessorCells):
a key lost to another exercise is not final on E, one outcome value, Abort only
on objective evidence, one consumer per parent, orphaned parents are not
canonical. -/
structure Coherent (x : Facts) (legs : List Nat) (e : Nat) : Prop where
  lost_not_final_on_e : ∀ R, x.lostTo R = true → x.cell R ≠ some e
  consumed_route_exclusive : ConsumedRoute x legs e = true → ∀ R ∈ legs, x.consumedElsewhere R = false

/-- A parent status only becomes more established: `unavailable` may settle
either way, and a settled one never moves. -/
def StatusRefines : ParentStatus → ParentStatus → Prop
  | .unavailable, _ => True
  | s, s' => s = s'

theorem statusRefines_settled {s s' : ParentStatus} (h : StatusRefines s s')
    (hs : s ≠ .unavailable) : s' = s := by
  cases s <;> cases s' <;> simp_all [StatusRefines]

structure Evolves (x x' : Facts) : Prop where
  registered : x.registered = true → x'.registered = true
  validation : Refines x.validation x'.validation
  setupValid : Refines x.setupValid x'.setupValid := by intro; trivial
  conformance : Refines x.conformance x'.conformance := by intro; trivial
  /-- A parent status only ever becomes MORE established: `unavailable` may
  settle either way, and a settled one never moves. -/
  parentStatus : ∀ R, StatusRefines (x.parentStatus R) (x'.parentStatus R)
  live : ∀ R, x.live R = true → x'.live R = true
  cell : ∀ R y, x.cell R = some y → x'.cell R = some y
  lostTo : ∀ R, x.lostTo R = true → x'.lostTo R = true
  consumedElsewhere : ∀ R, x.consumedElsewhere R = true → x'.consumedElsewhere R = true
  /-- An open branch may be selected; a terminal one never changes. -/
  parent : x.parent ≠ .openBranch → x'.parent = x.parent := by intro _; rfl

theorem consumedRoute_iff (x : Facts) (legs : List Nat) (e : Nat) :
    ConsumedRoute x legs e = true ↔
      x.registered = true ∧ x.conformance = .valid ∧ x.routeValidation = .valid
        ∧ (∀ R ∈ legs, x.parentStatus R = .canonical ∧ x.live R = true ∧ x.cell R = some e)
        ∧ parentCompatible x.parent = true := by
  simp [ConsumedRoute, legOk, and_assoc]

theorem legLost_false_of_ok {x : Facts} {legs : List Nat} {e R : Nat} (hc : Coherent x legs e)
    (hcr : ConsumedRoute x legs e = true) (hR : R ∈ legs) : legLost x e R = false := by
  obtain ⟨_, _, _, hall, _⟩ := (consumedRoute_iff x legs e).mp hcr
  obtain ⟨hcan, _, hcell⟩ := hall R hR
  have hd : x.lostTo R = false := by
    cases h : x.lostTo R
    · rfl
    · exact absurd hcell (hc.lost_not_final_on_e R h)
  -- THE EXCLUSION IS THE TYPE. `Coherent` used to assume an orphaned parent
  -- is never canonical; with three values in one field there is nothing to
  -- assume, and `hcan` settles it by constructor.
  have ho : (x.parentStatus R == ParentStatus.orphaned) = false := by
    rw [hcan]; rfl
  have hce := hc.consumed_route_exclusive hcr R hR
  simp [legLost, cellOther, hd, ho, hce, hcell]

/-- THE EXCLUSION IS THE TYPE (owner ruling §44.4). `Coherent` used to carry
`orphan_not_canonical` as an ASSUMPTION, because a parent was described by two
booleans and nothing stopped both being set. With three values in one field
there is no value that is both, so the assumption is gone and this is what
replaces it. -/
theorem orphaned_is_never_canonical (s : ParentStatus) :
    ¬ (s = .canonical ∧ s = .orphaned) := by
  cases s <;> simp

/-! ### R14: the PRODUCER of `ParentStatus` — a vault's canonical chain

`Facts.parentStatus` above is an oracle: the ladder is handed a status per leg
and never asks where it came from. That is exactly the shape the Rust had
before this section's twin landed — `ParentStatus::Orphaned` was a value no
code could produce, so a permanently defeated route waited forever instead of
being defeated.

This supplies the missing half, the twin of `sofi::resolution::parent_status`
and `VaultChain::status_of`. A chain is read POSITIONALLY: `c g` is `R*_g`
when the walk reached generation `g`, and `none` when it did not. -/

/-- The canonical root a verifier established at each generation. -/
abbrev VaultChain := Nat → Option Nat

/-- Rust `sofi::resolution::parent_status`. -/
def parentStatusOf (established : Option Nat) (claimed : Nat) : ParentStatus :=
  match established with
  | some r => if r = claimed then .canonical else .orphaned
  | none => .unavailable

/-- Rust `VaultChain::status_of`. -/
def VaultChain.statusOf (c : VaultChain) (g claimed : Nat) : ParentStatus :=
  parentStatusOf (c g) claimed

/-- ABSENCE NEVER REFUTES — the theorem this whole section exists for.

A generation the chain did not reach is `unavailable`, never `orphaned`. The
tempting rule is the opposite one (a root the chain does not name is refuted),
and it is wrong: a head is open precisely so the NEXT root can still arrive,
so a root the chain does not name may be one an in-flight operation is about
to realize. Since `orphaned` is a `RouteImpossible` arm, refuting it would
Void a route permanently for the sole defect of being looked at early. -/
theorem unreached_generation_is_unavailable (claimed : Nat) :
    parentStatusOf none claimed = ParentStatus.unavailable := by
  simp [parentStatusOf]

/-- The same, through a chain: a generation it did not reach refutes nothing. -/
theorem unreached_generation_never_refutes (c : VaultChain) (g claimed : Nat)
    (h : c g = none) : c.statusOf g claimed ≠ ParentStatus.orphaned := by
  simp [VaultChain.statusOf, parentStatusOf, h]

/-- The root the chain names at that generation is canonical. -/
theorem named_root_is_canonical (c : VaultChain) (g r : Nat) (h : c g = some r) :
    c.statusOf g r = ParentStatus.canonical := by
  simp [VaultChain.statusOf, parentStatusOf, h]

/-- ONLY a different root at the SAME generation refutes. This is the exact
boundary: with `R*_g` established, the claimed root is refuted precisely when
it differs, and never otherwise. -/
theorem refutes_iff_a_different_root_at_that_generation
    (c : VaultChain) (g claimed r : Nat) (h : c g = some r) :
    c.statusOf g claimed = ParentStatus.orphaned ↔ r ≠ claimed := by
  simp [VaultChain.statusOf, parentStatusOf, h]

/-- A chain that established nothing anywhere refutes nothing anywhere: the
verifier that never saw the vault does not thereby defeat its traders. -/
theorem an_empty_chain_refutes_nothing (g claimed : Nat) :
    VaultChain.statusOf (fun _ => none) g claimed = ParentStatus.unavailable := by
  simp [VaultChain.statusOf, parentStatusOf]

/-! ### R14: the ADOPTION INVARIANT on the resolved SoFi seam

Ordinary DSM already carries this rule: `DeviceState::advance` refuses to
credit a non-builtin token unless the PRE-state already commits that token's
adoption leaf. The resolved SoFi path did not pass through `advance` — it
recomputes the post states, recomputes the economic root and admits the
position directly — so the rule was simply absent there, and a realized route
could land a token the receiver never adopted.

Nobody adopts on the receiver's behalf. A token's policy is anchored to ITS
CREATOR's chain, a different anchor from the DLV policy's owner and usually a
different party, so a vault naming a token in its market policy establishes
nothing about the receiver having adopted it. -/

/-- A token, by its policy commitment. -/
abbrev Token := Nat

/-- What a settlement moves in the trader's OWN balances at one endpoint. -/
structure Movement where
  token : Token
  credit : Nat
  debit : Nat
  deriving DecidableEq, Repr

/-- Rust `sofi::validation::trader_credits`: what actually ARRIVES. -/
def credits (ms : List Movement) : List Token :=
  (ms.filter (fun m => 0 < m.credit)).map Movement.token

/-- Rust `sofi::lineage::adoption_admits`. -/
def adoptionAdmits (adopted : Token → Bool) (ms : List Movement) : Bool :=
  (credits ms).all adopted

/-- THE INVARIANT: a realized position that is admitted credits nothing the
receiver had not already adopted. -/
theorem admitted_credits_were_adopted
    (adopted : Token → Bool) (ms : List Movement) (t : Token)
    (h : adoptionAdmits adopted ms = true) (ht : t ∈ credits ms) :
    adopted t = true :=
  List.all_eq_true.mp h t ht

/-- A settlement crediting an UNADOPTED token is not admitted. The
contrapositive, stated because it is the case that must be refused. -/
theorem an_unadopted_credit_is_not_admitted
    (adopted : Token → Bool) (ms : List Movement) (t : Token)
    (ht : t ∈ credits ms) (hna : adopted t = false) :
    adoptionAdmits adopted ms = false := by
  cases h : adoptionAdmits adopted ms with
  | false => rfl
  | true =>
    rw [admitted_credits_were_adopted adopted ms t h ht] at hna
    exact Bool.noConfusion hna

/-- The trader's movements for a route: its ENDS only. A hop chain
`A -> B -> C` moves `A` and `C`; `B` is held by the DLVs across the hop. -/
def routeMovements (tin tout : Token) (amtIn amtOut : Nat) : List Movement :=
  [⟨tout, amtOut, 0⟩, ⟨tin, 0, amtIn⟩]

/-- A route credits its OUTPUT and nothing else: the input is spent, not
received. -/
theorem a_route_credits_only_its_output
    (tin tout : Token) (amtIn amtOut : Nat) (h : 0 < amtOut) :
    credits (routeMovements tin tout amtIn amtOut) = [tout] := by
  simp [credits, routeMovements, h]

/-- THE MULTI-HOP CASE. Any token that is not the route's output — the
intermediate `B` of `A -> B -> C` among them — is never credited to the
trader, so the invariant never demands its adoption. A rule that gated it
would refuse a route over an asset the trader never receives. -/
theorem a_pass_through_token_is_never_credited
    (tin tout b : Token) (amtIn amtOut : Nat) (h : 0 < amtOut) (hb : b ≠ tout) :
    b ∉ credits (routeMovements tin tout amtIn amtOut) := by
  rw [a_route_credits_only_its_output tin tout amtIn amtOut h]
  simpa using hb

/-- And therefore an unadopted pass-through does not block admission. -/
theorem an_unadopted_pass_through_still_admits
    (tin tout : Token) (amtIn amtOut : Nat) (h : 0 < amtOut)
    (adopted : Token → Bool) (hout : adopted tout = true) :
    adoptionAdmits adopted (routeMovements tin tout amtIn amtOut) = true := by
  simp [adoptionAdmits, a_route_credits_only_its_output tin tout amtIn amtOut h, hout]

/-- A concrete position whose every leg names a parent the verifier has NOT
established: registered, conforming, statically valid, every cell final on
this `E`, nothing lost — and still Pending. `unavailable` is not `canonical`,
so nothing consumes; it is not `orphaned`, so nothing is defeated.

This is the corner the pair of booleans could not express. A verifier with no
producer for orphaning wrote `orphan := false` beside `canonical := false` and
the ladder read the first as "not refuted" while the truth was "not
established". Without this witness the theorems above would hold vacuously of
a value no fact set ever takes.

Mutation: widen `legOk` to accept any status that is not `.orphaned` -- this
goes red, because the route then consumes on a parent nobody established. -/
def parentNotEstablished : Facts where
  registered := true
  validation := .valid
  parentStatus := fun _ => .unavailable
  live := fun _ => true
  cell := fun _ => some 50
  lostTo := fun _ => false
  consumedElsewhere := fun _ => false

theorem an_unestablished_parent_neither_consumes_nor_defeats :
    ConsumedRoute parentNotEstablished [10] 50 = false
      ∧ VoidEvidence parentNotEstablished [10] 50 = false
      ∧ resolve parentNotEstablished [10] 50 = .pending :=
  ⟨by decide, by decide, by decide⟩

/-- And the same fact set with the parent ESTABLISHED as another root is
defeated rather than waiting: Void, never Invalid, because the route itself
was valid and conforming. -/
theorem the_same_route_with_an_orphaned_parent_voids :
    resolve { parentNotEstablished with parentStatus := fun _ => .orphaned } [10] 50 = .void :=
  by decide

/-- REALIZED AND VOID ARE EXCLUSIVE. -/
theorem realized_excludes_void_evidence {x : Facts} {legs : List Nat} {e : Nat}
    (hc : Coherent x legs e) (hcr : ConsumedRoute x legs e = true) :
    VoidEvidence x legs e = false := by
  have hany : legs.any (legLost x e) = false := by
    rw [List.any_eq_false]
    intro R hR
    simp [legLost_false_of_ok hc hcr hR]
  simp [VoidEvidence, hany]

/-- A leg is consumed by F exactly when the whole operation is. -/
def ConsumedLeg (x : Facts) (legs : List Nat) (e R : Nat) : Bool :=
  decide (R ∈ legs) && ConsumedRoute x legs e

theorem resolve_realized_iff (x : Facts) (legs : List Nat) (e : Nat) :
    resolve x legs e = .realized ↔ ConsumedRoute x legs e = true := by
  constructor
  · intro h
    unfold resolve at h
    by_cases h1 : x.registered = false
    · rw [if_pos h1] at h; cases h
    · rw [if_neg h1] at h
      by_cases hp : parentPending x.parent = true
      · rw [if_pos hp] at h; cases h
      · rw [if_neg hp] at h
        by_cases hi : parentImpossible x.parent = true
        · rw [if_pos hi] at h; cases h
        · rw [if_neg hi] at h
          by_cases hc3 : x.conformance = .invalid
          · rw [if_pos hc3] at h; cases h
          · rw [if_neg hc3] at h
            by_cases hc4 : x.conformance = .unavailable
            · rw [if_pos hc4] at h; cases h
            · rw [if_neg hc4] at h
              by_cases h2 : ConsumedRoute x legs e = true
              · exact h2
              · rw [if_neg h2] at h
                by_cases h3 : x.routeValidation = .invalid
                · rw [if_pos h3] at h; cases h
                · rw [if_neg h3] at h
                  split at h <;> cases h
  · intro h
    obtain ⟨hreg, hconf, _, _, hcompat⟩ := (consumedRoute_iff x legs e).mp h
    obtain ⟨hpend, himp⟩ := parent_compatible_is_not_pending hcompat
    have h1 : ¬ x.registered = false := by simp [hreg]
    have hp : ¬ parentPending x.parent = true := by simp [hpend]
    have hi : ¬ parentImpossible x.parent = true := by simp [himp]
    have hc3 : ¬ x.conformance = .invalid := by rw [hconf]; decide
    have hc4 : ¬ x.conformance = .unavailable := by rw [hconf]; decide
    unfold resolve
    rw [if_neg h1, if_neg hp, if_neg hi, if_neg hc3, if_neg hc4, if_pos h]

/-- `realized_requires_valid_setup` (Section 20.1): SetupValid sits INSIDE
RouteValidation, so nothing realizes on an invalid or unavailable setup.
Mutation: drop `setupValid` from `Facts.routeValidation` -- this goes red. -/
theorem realized_requires_valid_setup {x : Facts} {legs : List Nat} {e : Nat}
    (h : resolve x legs e = .realized) : x.setupValid = .valid := by
  obtain ⟨_, _, hrv, _, _⟩ :=
    (consumedRoute_iff x legs e).mp ((resolve_realized_iff x legs e).mp h)
  exact ((routeValidation_valid_iff x).mp hrv).1

/-- `realized_requires_conformance` (Section 23.2): FulfillmentConformance is a
conjunct of ConsumedRoute. Mutation: drop it from `ConsumedRoute` -- red. -/
theorem realized_requires_conformance {x : Facts} {legs : List Nat} {e : Nat}
    (h : resolve x legs e = .realized) : x.conformance = .valid := by
  obtain ⟨_, hconf, _, _, _⟩ :=
    (consumedRoute_iff x legs e).mp ((resolve_realized_iff x legs e).mp h)
  exact hconf

/-- `registration_is_not_conformance` (Section 20.2): registration supplies no
truth value. A registered F whose conformance is not Valid never realizes, and
one whose conformance is Invalid IS Invalid. Mutation: read `registered` as
conformance in `ConsumedRoute` -- red. -/
theorem registration_is_not_conformance {x : Facts} {legs : List Nat} {e : Nat}
    (_hreg : x.registered = true) (hnc : x.conformance ≠ .valid) :
    resolve x legs e ≠ .realized :=
  fun h => hnc (realized_requires_conformance h)

theorem registered_but_nonconforming_is_invalid (x : Facts) (legs : List Nat) (e : Nat)
    (hreg : x.registered = true) (hpar : parentPending x.parent = false)
    (himp : parentImpossible x.parent = false) (hci : x.conformance = .invalid) :
    resolve x legs e = .invalid := by
  unfold resolve
  simp [hreg, hpar, himp, hci]

/-- `early_cell_cannot_cause_consumption` (Section 21.2): occupancy is not
admissibility. Whatever the cells hold, an unregistered fulfillment consumes
nothing and its position is Pending. Mutation: make `ConsumedRoute` the leg
predicate alone -- red. -/
theorem early_cell_cannot_cause_consumption {x : Facts} {legs : List Nat} {e : Nat}
    (hnr : x.registered = false) :
    ConsumedRoute x legs e = false ∧ resolve x legs e = .pending := by
  constructor
  · simp [ConsumedRoute, hnr]
  · unfold resolve; rw [if_pos hnr]

/-- Witnesses: every cell final on E, every parent canonical -- and no
registration, or a registered F that does not conform. -/
def cellsFinalUnregistered : Facts where
  registered := false
  validation := .valid
  parentStatus := fun _ => .canonical
  live := fun _ => true
  cell := fun _ => some 50
  lostTo := fun _ => false
  consumedElsewhere := fun _ => false

def registeredNotConforming : Facts := { cellsFinalUnregistered with registered := true, conformance := .invalid }
def registeredConformanceUnknown : Facts := { cellsFinalUnregistered with registered := true, conformance := .unavailable }
def registeredBadSetup : Facts := { cellsFinalUnregistered with registered := true, setupValid := .invalid }

theorem stored_is_not_valid_and_registered_is_not_valid :
    resolve cellsFinalUnregistered [10, 11] 50 = .pending
      ∧ resolve registeredNotConforming [10, 11] 50 = .invalid
      ∧ resolve registeredConformanceUnknown [10, 11] 50 = .pending
      ∧ resolve registeredBadSetup [10, 11] 50 = .invalid
      ∧ resolve { cellsFinalUnregistered with registered := true } [10, 11] 50 = .realized := by
  decide

/-- THE TRADER PARENT, RUNG 1 (P15-3): a conditional parent that has not
resolved keeps the position Pending. The parent alone consumes nothing and
makes nothing impossible — an undecided branch is not a verdict. -/
theorem conditional_parent_pending_keeps_the_position_pending {x : Facts} {legs : List Nat}
    {e : Nat} (hopen : x.parent = .openBranch) :
    resolve x legs e = .pending ∧ ConsumedRoute x legs e = false
      ∧ parentCompatible x.parent = false ∧ parentImpossible x.parent = false := by
  refine ⟨?_, ?_, by rw [hopen]; rfl, by rw [hopen]; rfl⟩
  · unfold resolve
    by_cases hreg : x.registered = false
    · rw [if_pos hreg]
    · rw [if_neg hreg, if_pos (by rw [hopen]; rfl : parentPending x.parent = true)]
  · simp [ConsumedRoute, hopen, parentCompatible]

/-- THE TRADER PARENT, RUNG 2 (P15-3): a parent that selected the other branch,
or no root at all, makes the position Invalid — not Void. The operation was
never the one its own lineage took, whatever its legs did. -/
theorem conditional_parent_on_another_branch_is_invalid {x : Facts} {legs : List Nat} {e : Nat}
    (hreg : x.registered = true) (himp : parentImpossible x.parent = true) :
    resolve x legs e = .invalid ∧ ConsumedRoute x legs e = false := by
  have hpend : parentPending x.parent = false := by
    cases hq : x.parent <;> simp_all [parentImpossible, parentPending]
  refine ⟨?_, ?_⟩
  · unfold resolve
    rw [if_neg (by simp [hreg]), if_neg (by simp [hpend]), if_pos himp]
  · have : parentCompatible x.parent = false := by
      cases hq : x.parent <;> simp_all [parentImpossible, parentCompatible]
    simp [ConsumedRoute, this]

/-- Arm (iv) needs NO validation evidence: a terminal parent that selected no
root decides the position while `RouteValidation` is still Unavailable, which
is what lets a stranded DLV cell of such an operation be skipped. -/
theorem terminal_parent_with_no_root_is_invalid_without_evidence {x : Facts} {legs : List Nat}
    {e : Nat} (hreg : x.registered = true) (hno : x.parent = .noRoot)
    -- Deliberately unused: THAT is the content. The verdict lands with the
    -- validation evidence still missing.
    (_hun : x.validation = .unavailable) : resolve x legs e = .invalid := by
  exact (conditional_parent_on_another_branch_is_invalid hreg (by rw [hno]; rfl)).1

/-- A concrete position on a branch its parent never took: registered, valid,
every leg final on this E, Complete — and still Invalid, because `p` selected
the other root. Its two siblings differ only in the parent's state. Without
these witnesses the rung theorems above could be vacuously true of a predicate
that never holds. -/
def builtOnTheOtherBranch : Facts where
  registered := true
  validation := .valid
  parentStatus := fun _ => .canonical
  live := fun _ => true
  cell := fun _ => some 50
  lostTo := fun _ => false
  consumedElsewhere := fun _ => false
  parent := .otherBranch

def awaitingItsParent : Facts := { builtOnTheOtherBranch with parent := .openBranch }
def onTheTakenBranch : Facts := { builtOnTheOtherBranch with parent := .taken }
def terminalParentNoRoot : Facts := { builtOnTheOtherBranch with parent := .noRoot }

/-- THE RUNGS ARE NOT VACUOUS, and they separate three outcomes on facts that
differ ONLY in what the trader parent did. -/
theorem the_trader_parent_rungs_are_not_vacuous :
    resolve builtOnTheOtherBranch [10] 50 = .invalid
      ∧ resolve terminalParentNoRoot [10] 50 = .invalid
      ∧ resolve awaitingItsParent [10] 50 = .pending
      ∧ resolve onTheTakenBranch [10] 50 = .realized
      ∧ ConsumedRoute builtOnTheOtherBranch [10] 50 = false
      ∧ ConsumedRoute onTheTakenBranch [10] 50 = true := by decide

/-- THE ARM IS MONOTONE: a terminal parent never changes, so neither predicate
ever retracts. Only an open branch can move, and it moves once. -/
theorem trader_parent_arm_is_monotone {x x' : Facts} (hev : Evolves x x') :
    (parentImpossible x.parent = true → parentImpossible x'.parent = true)
      ∧ (parentCompatible x.parent = true → parentCompatible x'.parent = true) := by
  constructor
  · intro h
    have hne : x.parent ≠ .openBranch := by
      intro hq; rw [hq] at h; exact absurd h (by decide)
    rw [hev.parent hne]; exact h
  · intro h
    have hne : x.parent ≠ .openBranch := by
      intro hq; rw [hq] at h; exact absurd h (by decide)
    rw [hev.parent hne]; exact h

/-- ATOMIC, ALL OR NONE, over P's legs: a conforming fulfillment is realized only
by consuming EVERY DLV parent P names; otherwise it consumes none. -/
theorem fulfillment_atomic_all_or_none {hm : HashModel} {shadowOf : Nat → Nat → Nat}
    {P : PBody} {F : FBody} (hconf : Conforming hm shadowOf P F) (x : Facts) (e : Nat) :
    (resolve x (fLegs hm shadowOf P F) e = .realized →
        ∀ l ∈ P.legs, ConsumedLeg x (fLegs hm shadowOf P F) e l.parent = true)
      ∧ (resolve x (fLegs hm shadowOf P F) e ≠ .realized →
        ∀ R, ConsumedLeg x (fLegs hm shadowOf P F) e R = false) := by
  refine ⟨fun h l hl => ?_, fun h R => ?_⟩
  · have hcr := (resolve_realized_iff _ _ _).mp h
    have hmem : l.parent ∈ fLegs hm shadowOf P F := by
      rw [fLegs_conforming hconf]; exact List.mem_map_of_mem hl
    simp [ConsumedLeg, hmem, hcr]
  · have : ConsumedRoute x (fLegs hm shadowOf P F) e = false := by
      cases hh : ConsumedRoute x (fLegs hm shadowOf P F) e
      · rfl
      · exact absurd ((resolve_realized_iff _ _ _).mpr hh) h
    simp [ConsumedLeg, this]

/-- The rejected rule: consuming a leg on its own final E is partial execution. -/
def legConsumedAlone (x : Facts) (e R : Nat) : Bool :=
  x.registered && x.validation == .valid && legOk x e R

def splitFacts : Facts where
  registered := true
  validation := .valid
  parentStatus := fun _ => .canonical
  live := fun _ => true
  cell := fun R => if R = 10 then some 50 else none
  lostTo := fun R => R == 11
  consumedElsewhere := fun _ => false

theorem per_leg_consumption_is_partial_execution :
    legConsumedAlone splitFacts 50 10 = true ∧ legConsumedAlone splitFacts 50 11 = false
      ∧ resolve splitFacts [10, 11] 50 = .void := by
  decide

/-- ROUTE IMPOSSIBILITY, arms (ii) and (iii′): once a parent P names is orphaned
or consumed by another E, no fulfillment of P — at any attempt vector — can be
consumed. -/
theorem route_impossible_orphan_and_consumed_elsewhere_arms {x : Facts} {legs : List Nat}
    {e R : Nat} (hc : Coherent x legs e) (hR : R ∈ legs)
    (h : x.parentStatus R = .orphaned ∨ x.consumedElsewhere R = true) : ConsumedRoute x legs e = false := by
  cases hcr : ConsumedRoute x legs e
  · rfl
  · have := legLost_false_of_ok hc hcr hR
    simp [legLost] at this
    rcases h with h | h <;> simp_all

/-- A STRANDED E CELL IS NOT PARTIAL EXECUTION: an E final at one leg while
another parent is lost consumes nothing, and resolves Void once storage-resolved
under valid evidence. -/
theorem stranded_e_cell_is_not_partial_execution {x : Facts} {legs : List Nat} {e R R' : Nat}
    (hc : Coherent x legs e) (hR' : R' ∈ legs) (hstranded : x.cell R = some e)
    (hlost : x.parentStatus R' = .orphaned ∨ x.consumedElsewhere R' = true) :
    (x.cell R = some e ∧ ∀ R'', ConsumedLeg x legs e R'' = false)
      ∧ (x.registered = true → x.conformance = .valid → x.routeValidation = .valid →
          StorageResolved x legs = true → parentCompatible x.parent = true →
          resolve x legs e = .void) := by
  have hno := route_impossible_orphan_and_consumed_elsewhere_arms hc hR' hlost
  refine ⟨⟨hstranded, fun R'' => by simp [ConsumedLeg, hno]⟩, fun hreg hconf hv hsr hcompat => ?_⟩
  obtain ⟨hpend, himp⟩ := parent_compatible_is_not_pending hcompat
  have hve : VoidEvidence x legs e = true := by
    have : legLost x e R' = true := by
      rcases hlost with h | h <;> simp [legLost, h]
    simp only [VoidEvidence, List.any_eq_true]
    exact ⟨R', hR', this⟩
  simp [resolve, hreg, hno, hconf, hv, hsr, hve, hpend, himp]

/-- Contention: a rival consumed `R_A = 10` between the witnesses and F. -/
def contended : Facts where
  registered := true
  validation := .valid
  parentStatus := fun _ => .canonical
  live := fun R => R == 11
  cell := fun R => if R = 10 then some 99 else if R = 11 then some 50 else none
  lostTo := fun _ => false
  consumedElsewhere := fun R => R == 10

theorem contended_is_coherent : Coherent contended [10, 11] 50 where
  lost_not_final_on_e := fun R h => by simp [contended] at h
  consumed_route_exclusive := fun h => by simp [ConsumedRoute, contended, legOk] at h

/-- A FULFILLMENT MAY VOID UNDER CONTENTION: registered, every witness valid,
and still Void. -/
theorem fulfillment_may_void_under_contention :
    Coherent contended [10, 11] 50 ∧ contended.registered = true
      ∧ contended.validation = .valid ∧ resolve contended [10, 11] 50 = .void :=
  ⟨contended_is_coherent, rfl, rfl, by decide⟩

theorem routeValidation_refines {x x' : Facts} (hev : Evolves x x') :
    Refines x.routeValidation x'.routeValidation :=
  and_refines hev.setupValid hev.validation

theorem consumedRoute_mono {x x' : Facts} (hev : Evolves x x') {legs : List Nat} {e : Nat}
    (h : ConsumedRoute x legs e = true) : ConsumedRoute x' legs e = true := by
  obtain ⟨hreg, hconf, hv, hall, hcompat⟩ := (consumedRoute_iff x legs e).mp h
  have hconf' : x'.conformance = .valid := by
    have := hev.conformance; rw [hconf] at this; exact valid_refines_only_to_valid this
  have hv' : x'.routeValidation = .valid := by
    have := routeValidation_refines hev; rw [hv] at this; exact valid_refines_only_to_valid this
  refine (consumedRoute_iff x' legs e).mpr ⟨hev.registered hreg, hconf', hv', fun R hR => ?_, ?_⟩
  · obtain ⟨a, b, c⟩ := hall R hR
    have hs : x'.parentStatus R = x.parentStatus R :=
      statusRefines_settled (hev.parentStatus R) (by rw [a]; decide)
    exact ⟨by rw [hs, a], hev.live R b, hev.cell R e c⟩
  · have hne : x.parent ≠ .openBranch := by
      intro hq; rw [hq] at hcompat; exact absurd hcompat (by decide)
    rw [hev.parent hne]; exact hcompat

theorem storageResolved_mono {x x' : Facts} (hev : Evolves x x') {legs : List Nat}
    (h : StorageResolved x legs = true) : StorageResolved x' legs = true := by
  simp only [StorageResolved, Bool.and_eq_true, Bool.or_eq_true, List.all_eq_true] at h ⊢
  obtain ⟨hreg, hall⟩ := h
  refine ⟨hev.registered hreg, fun R hR => ?_⟩
  rcases hall R hR with hd | hs
  · exact Or.inl (hev.lostTo R hd)
  · right
    cases hcell : x.cell R with
    | none => rw [hcell] at hs; cases hs
    | some y => rw [hev.cell R y hcell]; rfl

theorem legLost_mono {x x' : Facts} (hev : Evolves x x') {e R : Nat}
    (h : legLost x e R = true) : legLost x' e R = true := by
  simp only [legLost, Bool.or_eq_true] at h ⊢
  rcases h with ((hd | hco) | hce) | ho
  · exact Or.inl (Or.inl (Or.inl (hev.lostTo R hd)))
  · left; left; right
    unfold cellOther at hco ⊢
    cases hcell : x.cell R with
    | none => rw [hcell] at hco; cases hco
    | some y => rw [hcell] at hco; rw [hev.cell R y hcell]; exact hco
  · exact Or.inl (Or.inr (hev.consumedElsewhere R hce))
  · refine Or.inr ?_
    have := hev.parentStatus R
    have hR : x.parentStatus R = .orphaned := by
      simpa using ho
    rw [statusRefines_settled this (by rw [hR]; exact fun h => by cases h), hR]
    rfl

theorem voidEvidence_mono {x x' : Facts} (hev : Evolves x x') {legs : List Nat} {e : Nat}
    (h : VoidEvidence x legs e = true) : VoidEvidence x' legs e = true := by
  simp only [VoidEvidence, List.any_eq_true] at h ⊢
  obtain ⟨R, hR, hl⟩ := h
  exact ⟨R, hR, legLost_mono hev hl⟩

/-- RESOLUTION IS PERMANENT once non-Pending. -/
theorem resolution_is_permanent {x x' : Facts} {legs : List Nat} {e : Nat}
    (hev : Evolves x x') (hc' : Coherent x' legs e) (hnp : resolve x legs e ≠ .pending) :
    resolve x' legs e = resolve x legs e := by
  have hreg : x.registered = true := by
    cases h : x.registered
    · exact absurd (by unfold resolve; rw [if_pos h]) hnp
    · rfl
  have hreg' := hev.registered hreg
  have h1 : ¬ x.registered = false := by simp [hreg]
  have h1' : ¬ x'.registered = false := by simp [hreg']
  -- An open parent makes the position Pending, which hnp excludes; so the
  -- parent is terminal, and a terminal parent never changes.
  have hpend : parentPending x.parent = false := by
    cases hq : parentPending x.parent
    · rfl
    · exact absurd (by unfold resolve; rw [if_neg h1, if_pos hq]) hnp
  have hne : x.parent ≠ .openBranch := by
    intro hq; rw [hq] at hpend; exact absurd hpend (by decide)
  have hpar : x'.parent = x.parent := hev.parent hne
  have hp : ¬ parentPending x.parent = true := by simp [hpend]
  have hp' : ¬ parentPending x'.parent = true := by rw [hpar]; simp [hpend]
  unfold resolve at hnp ⊢
  rw [if_neg h1, if_neg h1', if_neg hp, if_neg hp']
  rw [if_neg h1, if_neg hp] at hnp
  by_cases himp : parentImpossible x.parent = true
  · have himp' : parentImpossible x'.parent = true := by rw [hpar]; exact himp
    rw [if_pos himp, if_pos himp']
  · have himp' : ¬ parentImpossible x'.parent = true := by rw [hpar]; exact himp
    rw [if_neg himp, if_neg himp']
    rw [if_neg himp] at hnp
    by_cases hc3 : x.conformance = .invalid
    · have hc3' : x'.conformance = .invalid := by
        have := hev.conformance; rw [hc3] at this; exact invalid_refines_only_to_invalid this
      rw [if_pos hc3, if_pos hc3']
    · rw [if_neg hc3]
      rw [if_neg hc3] at hnp
      have hc4 : ¬ x.conformance = .unavailable := by
        intro h; rw [if_pos h] at hnp; exact absurd rfl hnp
      have hcv : x.conformance = .valid := by
        cases h : x.conformance
        · rfl
        · exact absurd h hc3
        · exact absurd h hc4
      have hcv' : x'.conformance = .valid := by
        have := hev.conformance; rw [hcv] at this; exact valid_refines_only_to_valid this
      have hc3' : ¬ x'.conformance = .invalid := by rw [hcv']; decide
      have hc4' : ¬ x'.conformance = .unavailable := by rw [hcv']; decide
      rw [if_neg hc3', if_neg hc4', if_neg hc4]
      rw [if_neg hc4] at hnp
      by_cases hcr : ConsumedRoute x legs e = true
      · rw [if_pos hcr, if_pos (consumedRoute_mono hev hcr)]
      · rw [if_neg hcr]
        rw [if_neg hcr] at hnp
        by_cases hinv : x.routeValidation = .invalid
        · have hinv' : x'.routeValidation = .invalid := by
            have := routeValidation_refines hev; rw [hinv] at this
            exact invalid_refines_only_to_invalid this
          have hcr' : ¬ ConsumedRoute x' legs e = true := by simp [ConsumedRoute, hinv']
          rw [if_pos hinv, if_neg hcr', if_pos hinv']
        · rw [if_neg hinv]
          rw [if_neg hinv] at hnp
          by_cases hvoid : x.routeValidation = .valid ∧ StorageResolved x legs = true ∧ VoidEvidence x legs e = true
          · obtain ⟨hv, hsr, hve⟩ := hvoid
            have hv' : x'.routeValidation = .valid := by
              have := routeValidation_refines hev; rw [hv] at this
              exact valid_refines_only_to_valid this
            have hve' := voidEvidence_mono hev hve
            have hcr' : ¬ ConsumedRoute x' legs e = true := by
              intro h
              rw [realized_excludes_void_evidence hc' h] at hve'
              cases hve'
            have hinv' : ¬ x'.routeValidation = .invalid := by rw [hv']; decide
            have hvoid' : x'.routeValidation = .valid ∧ StorageResolved x' legs = true ∧ VoidEvidence x' legs e = true :=
              ⟨hv', storageResolved_mono hev hsr, hve'⟩
            have hvoid : x.routeValidation = .valid ∧ StorageResolved x legs = true ∧ VoidEvidence x legs e = true :=
              ⟨hv, hsr, hve⟩
            rw [if_pos hvoid, if_neg hcr', if_neg hinv', if_pos hvoid']
          · rw [if_neg hvoid] at hnp
            exact absurd rfl hnp

/-- FINDING: the ladder read literally (Void without a validation premise) is
not permanent. A verifier sees Void while evidence is unavailable; the evidence
arrives Invalid; the same position becomes Invalid — which terminates the
lineage that Void had continued. -/
def unavailableThenVoid : Facts where
  registered := true
  validation := .unavailable
  parentStatus := fun _ => .canonical
  live := fun _ => true
  cell := fun _ => none
  lostTo := fun _ => true
  consumedElsewhere := fun _ => false

def laterInvalid : Facts := { unavailableThenVoid with validation := .invalid }

theorem literal_ladder_is_not_permanent :
    Evolves unavailableThenVoid laterInvalid
      ∧ Coherent laterInvalid [10] 50
      ∧ resolveLiteral unavailableThenVoid [10] 50 = .void
      ∧ resolveLiteral laterInvalid [10] 50 = .invalid
      ∧ resolve unavailableThenVoid [10] 50 = .pending := by
  refine ⟨⟨fun h => h, trivial, rfl, rfl, fun _ => rfl, fun _ h => h, fun _ _ h => h,
    fun _ h => h, fun _ h => h, fun _ => rfl⟩, ⟨(fun _ _ h => nomatch h),
    (fun h => by simp [ConsumedRoute, laterInvalid, unavailableThenVoid, Facts.routeValidation, Validation.and] at h)⟩,
    (by decide), (by decide), (by decide)⟩

/-- REGISTERED ≠ VALIDATED: a registered fulfillment without evidence is
Pending and selects no root. -/
theorem registered_is_not_validated :
    unavailableThenVoid.registered = true ∧ resolve unavailableThenVoid [10] 50 = .pending := by
  decide

/-- A FULFILLMENT REGISTERED AFTER ITS PARENT WAS LOST RESOLVES VOID, and stays
Void. -/
theorem fulfillment_registrable_after_parent_loss_resolves_void (hm : HashModel)
    (shadowOf : Nat → Nat → Nat) (s : Sys) (P : PBody) (F : FBody) (y : Nat) {x : Facts}
    {legs : List Nat} {e R : Nat} (hc : Coherent x legs e) (hR : R ∈ legs)
    (hlost : x.consumedElsewhere R = true) (hreg : x.registered = true)
    (hconf : x.conformance = .valid) (hv : x.routeValidation = .valid)
    (hsr : StorageResolved x legs = true)
    (hcompat : parentCompatible x.parent = true) :
    (FIngress hm shadowOf (consumeStep R y s) P F ↔ FIngress hm shadowOf s P F)
      ∧ resolve x legs e = .void
      ∧ ∀ x', Evolves x x' → Coherent x' legs e → resolve x' legs e = .void := by
  have hno := route_impossible_orphan_and_consumed_elsewhere_arms hc hR (Or.inr hlost)
  obtain ⟨hpend, himp⟩ := parent_compatible_is_not_pending hcompat
  have hve : VoidEvidence x legs e = true := by
    simp only [VoidEvidence, List.any_eq_true]
    exact ⟨R, hR, by simp [legLost, hlost]⟩
  have hres : resolve x legs e = .void := by
    simp [resolve, hreg, hno, hconf, hv, hsr, hve, hpend, himp]
  exact ⟨Iff.rfl, hres,
    fun x' hev hc' => by rw [resolution_is_permanent hev hc' (by rw [hres]; decide), hres]⟩


/-- R15-2: `E ↔ F` IS NOT ONE-TO-ONE, AND REGISTRATION IS WHAT IS UNIQUE.
`Conforming` leaves the attempt vector free, so many candidate fulfillments
reference one `(P, E, q)` — `route_validation_is_static` quantifies over exactly
that. What `K_ful(q)` gives is that at most one of them ever registers: a
candidate arriving at a position that already holds one IS that one. -/
theorem at_most_one_candidate_registers_per_position {hm : HashModel}
    {shadowOf : Nat → Nat → Nat} {s : Sys} {P : PBody} {F1 F2 : FBody}
    (hheld : s.kful F1.q = some F1) (hq : F2.q = F1.q)
    (h2 : FIngress hm shadowOf s P F2) : F2 = F1 := by
  obtain ⟨hk, _⟩ := h2
  rw [hq, hheld] at hk
  rcases hk with h | h
  · cases h
  · exact (Option.some.inj h).symm

/-- A candidate that never registers never resolves the position: the ladder
answers Pending for it forever, and the position's terminal answer comes from
the one fulfillment that did register. -/
theorem a_candidate_that_never_registers_stays_pending (x : Facts) (legs : List Nat) (e : Nat)
    (h : x.registered = false) : resolve x legs e = .pending := by
  unfold resolve; rw [if_pos h]

/-- NO GUARANTEE WITHOUT A PREPARE LOCK. Witnesses do not lock (§6), so a
registered, fully valid fulfillment is not guaranteed to realize; the only way to
guarantee it is a lock, and a lock with no clock and no abort authority is free
(`locking_policy_fulfillment_is_a_free_lock`). -/
theorem no_guarantee_without_prepare_lock :
    (∀ (g : GBody) (s : Sys) (R : Nat), ConsumeIngress (storeG g s) R ↔ ConsumeIngress s R)
      ∧ ¬ (∀ (x : Facts) (legs : List Nat) (e : Nat), Coherent x legs e → x.registered = true →
            x.validation = .valid → StorageResolved x legs = true → resolve x legs e = .realized) := by
  refine ⟨fun _ _ _ => Iff.rfl, fun h => ?_⟩
  have := h contended [10, 11] 50 contended_is_coherent rfl rfl (by decide)
  rw [fulfillment_may_void_under_contention.2.2.2] at this
  cases this

/-- The root a resolution selects; Invalid and Pending select none. -/
def selectedRoot (r : Resolution) (P : PBody) : Option Nat :=
  match r with
  | .realized => some P.realize
  | .void => some P.void
  | _ => none

theorem selected_root_is_committed (r : Resolution) (P : PBody) {root : Nat}
    (h : selectedRoot r P = some root) : root = P.realize ∨ root = P.void := by
  cases r <;> simp [selectedRoot] at h
  · exact Or.inl h.symm
  · exact Or.inr h.symm

/-- The rejected verdict: parent canonicality inside RouteValidation. -/
def validationWithCanonicality (x : Facts) (legs : List Nat) : Validation :=
  if legs.any (fun R => x.parentStatus R == .orphaned) then .invalid else x.validation

def orphanedLeg : Facts where
  registered := true
  validation := .valid
  parentStatus := fun R => if R = 10 then .orphaned else .canonical
  live := fun _ => true
  cell := fun R => if R = 10 then some 50 else none
  lostTo := fun R => R == 11
  consumedElsewhere := fun _ => false

/-- ROUTE VALIDATION EXCLUDES PARENT CANONICALITY (R11-1). A parent orphaned by
its own lineage makes the operation Void — the trader continues from `R_void` —
never Invalid, which would end the trader's lineage for another party's fork. -/
theorem route_validation_excludes_parent_canonicality (P : PBody) :
    resolve orphanedLeg [10, 11] 50 = .void
      ∧ selectedRoot (resolve orphanedLeg [10, 11] 50) P = some P.void
      ∧ resolve { orphanedLeg with validation := validationWithCanonicality orphanedLeg [10, 11] }
          [10, 11] 50 = .invalid := by
  refine ⟨by decide, by rw [show resolve orphanedLeg [10, 11] 50 = .void by decide]; rfl, by decide⟩

/-- R13-5, evidence availability: once validation evidence is available, storage
is resolved and each parent's fate is known, a registered fulfillment is not
Pending. -/
theorem registered_fulfillment_resolves_under_evidence_availability {x : Facts}
    {legs : List Nat} {e : Nat} (hreg : x.registered = true)
    (hev : x.validation ≠ .unavailable) (hsv : x.setupValid ≠ .unavailable)
    (hcf : x.conformance ≠ .unavailable) (hsr : StorageResolved x legs = true)
    (hpar : parentPending x.parent = false)
    (hfate : ∀ R ∈ legs, (x.parentStatus R = .canonical ∧ x.live R = true) ∨ x.parentStatus R = .orphaned
      ∨ x.consumedElsewhere R = true) :
    resolve x legs e ≠ .pending := by
  have h1 : ¬ x.registered = false := by simp [hreg]
  have hp : ¬ parentPending x.parent = true := by simp [hpar]
  unfold resolve
  rw [if_neg h1, if_neg hp]
  by_cases himp : parentImpossible x.parent = true
  · rw [if_pos himp]; decide
  rw [if_neg himp]
  have himpF : parentImpossible x.parent = false := by
    cases h : parentImpossible x.parent
    · rfl
    · exact absurd h himp
  have hcompat : parentCompatible x.parent = true :=
    ((parent_states_are_exclusive x.parent).2.2 hpar).mpr himpF
  by_cases hc3 : x.conformance = .invalid
  · rw [if_pos hc3]; decide
  rw [if_neg hc3]
  have hc4 : ¬ x.conformance = .unavailable := hcf
  rw [if_neg hc4]
  by_cases hcr : ConsumedRoute x legs e = true
  · rw [if_pos hcr]; decide
  · rw [if_neg hcr]
    by_cases hinv : x.routeValidation = .invalid
    · rw [if_pos hinv]; decide
    · rw [if_neg hinv]
      have hv : x.routeValidation = .valid := by
        unfold Facts.routeValidation at hinv ⊢
        cases hs : x.setupValid <;> cases hl : x.validation <;> simp_all [Validation.and]
      have hcv : x.conformance = .valid := by
        cases h : x.conformance
        · rfl
        · exact absurd h hc3
        · exact absurd h hc4
      have hve : VoidEvidence x legs e = true := by
        simp only [StorageResolved, Bool.and_eq_true, Bool.or_eq_true, List.all_eq_true] at hsr
        obtain ⟨_, hall⟩ := hsr
        have hall_ok : ¬ ∀ R ∈ legs, x.parentStatus R = .canonical ∧ x.live R = true ∧ x.cell R = some e := by
          intro hok
          apply hcr
          exact (consumedRoute_iff x legs e).mpr ⟨hreg, hcv, hv, hok, hcompat⟩
        apply Classical.byContradiction
        intro hnot
        apply hall_ok
        intro R hR
        have hnl : legLost x e R = false := by
          cases hl : legLost x e R
          · rfl
          · exfalso; apply hnot
            simp only [VoidEvidence, List.any_eq_true]
            exact ⟨R, hR, hl⟩
        simp only [legLost, cellOther, Bool.or_eq_false_iff] at hnl
        obtain ⟨⟨⟨hd, hco⟩, hce⟩, ho⟩ := hnl
        rcases hfate R hR with ⟨hcan, hlive⟩ | h | h
        · refine ⟨hcan, hlive, ?_⟩
          rcases hall R hR with h | h
          · rw [hd] at h; cases h
          · cases hcell : x.cell R with
            | none => rw [hcell] at h; cases h
            | some y =>
              rw [hcell] at hco
              simp at hco
              rw [hco]
        · rw [h] at ho; simp at ho
        · rw [hce] at h; cases h
      rw [if_pos ⟨hv, hsr, hve⟩]
      decide

/-- Without evidence a registered fulfillment may stay Pending forever. -/
theorem without_evidence_a_registered_fulfillment_stays_pending :
    ∀ x', Evolves unavailableThenVoid x' → x'.validation = .unavailable →
      resolve x' [10] 50 ≠ .realized ∧ resolve x' [10] 50 ≠ .void := by
  intro x' hevx hu
  have hpar : x'.parent = .single := by
    have := hevx.parent (by decide); simpa [unavailableThenVoid] using this
  have hrv : x'.routeValidation ≠ .valid := by
    intro hh; exact absurd ((routeValidation_valid_iff x').mp hh).2 (by rw [hu]; decide)
  have hcr : ConsumedRoute x' [10] 50 = false := by
    have : (x'.routeValidation == .valid) = false := by
      cases hh : x'.routeValidation
      · exact absurd hh hrv
      · rfl
      · rfl
    simp [ConsumedRoute, this]
  constructor
  · intro h; rw [(resolve_realized_iff _ _ _).mp h] at hcr; cases hcr
  · intro h
    unfold resolve at h
    cases hc : x'.conformance <;> cases hh : x'.routeValidation <;>
      simp_all [parentPending, parentImpossible] <;> split at h <;> simp_all

-- ── §8 lineage, the predecessor fence, SofiVoid ───────────────────────────

/-- Validated economic ancestry through position `q`: every earlier position
selected a root. -/
def ValidatedThrough (res : Nat → Resolution) (q : Nat) : Prop :=
  ∀ q' < q, res q' = .realized ∨ res q' = .void

theorem invalid_terminates_lineage {res : Nat → Resolution} {q : Nat} (h : res q = .invalid) :
    ∀ q', q < q' → ¬ ValidatedThrough res q' := by
  intro q' hlt hv
  rcases hv q hlt with h' | h' <;> rw [h] at h' <;> cases h'

theorem descendant_requires_resolved_predecessor {res : Nat → Resolution} {q : Nat}
    (h : ValidatedThrough res (q + 1)) (P : PBody) : selectedRoot (res q) P ≠ none := by
  rcases h q (Nat.lt_succ_self q) with h' | h' <;> rw [h'] <;> simp [selectedRoot]

/-- ADVANCE EXTENDS THE VALIDATED LINEAGE, R13 (`advance_resolved`, stage 10):
a position resolved Realized or Void -- the two answers that select a root --
extends validated ancestry by exactly one position. -/
theorem advance_extends_validated_lineage {res : Nat → Resolution} {q : Nat}
    (h : ValidatedThrough res q) (hq : res q = .realized ∨ res q = .void) :
    ValidatedThrough res (q + 1) := by
  intro q' hlt
  rcases Nat.lt_or_eq_of_le (Nat.le_of_lt_succ hlt) with hl | he
  · exact h q' hl
  · subst he; exact hq

/-- Nothing follows an undecided or terminal position: neither Pending nor
Invalid selects a root, so no validated ancestry reaches past it. Mutation:
let `ValidatedThrough` count `.pending` as validated -- red (with
`descendant_requires_resolved_predecessor`). -/
theorem an_undecided_or_terminal_position_extends_nothing {res : Nat → Resolution} {q : Nat}
    (hq : res q = .pending ∨ res q = .invalid) : ¬ ValidatedThrough res (q + 1) := by
  intro hv
  rcases hv q (Nat.lt_succ_self q) with h | h <;> rcases hq with hq | hq <;> rw [hq] at h <;> cases h

inductive Kind where
  | single
  | conditional
  | setup
  | close
  deriving DecidableEq, Repr

/-- Registered claims of one lineage, and which conditional positions Core has
resolved (Realized, Void or Invalid). Storage resolution is never a
predecessor authority (Section 22). -/
structure Lineage where
  claim : Nat → Option Kind
  resolved : Nat → Bool

def Lineage.put (ln : Lineage) (q : Nat) (k : Kind) : Lineage :=
  { ln with claim := fun p => if p = q then some k else ln.claim p }

inductive LStep : Lineage → Lineage → Prop
  | first (ln : Lineage) (k : Kind) : ln.claim 0 = none → LStep ln (ln.put 0 k)
  /-- ANY claim kind at `p + 1`: a parent exists, and a conditional parent is
  Core-resolved. -/
  | next (ln : Lineage) (p : Nat) (k : Kind) : ln.claim p ≠ none → ln.claim (p + 1) = none →
      (ln.claim p = some .conditional → ln.resolved p = true) → LStep ln (ln.put (p + 1) k)
  | resolve (ln : Lineage) (p : Nat) : ln.claim p = some .conditional →
      LStep ln { ln with resolved := fun r => if r = p then true else ln.resolved r }

inductive LReach : Lineage → Lineage → Prop
  | refl (ln : Lineage) : LReach ln ln
  | tail {a b c : Lineage} : LReach a b → LStep b c → LReach a c

structure FenceInv (ln : Lineage) : Prop where
  no_gap : ∀ p, ln.claim p = none → ln.claim (p + 1) = none
  fenced : ∀ p, ln.claim p = some .conditional → ln.resolved p = false → ln.claim (p + 1) = none

def emptyLineage : Lineage := ⟨fun _ => none, fun _ => false⟩

theorem FenceInv.step {ln ln' : Lineage} (hi : FenceInv ln) (hs : LStep ln ln') : FenceInv ln' := by
  cases hs with
  | first k h0 =>
    constructor
    · intro p hp
      simp only [Lineage.put] at hp ⊢
      by_cases hp0 : p = 0
      · rw [if_pos hp0] at hp; cases hp
      · rw [if_neg hp0] at hp
        rw [if_neg (by omega)]
        exact hi.no_gap p hp
    · intro p hp hr
      simp only [Lineage.put] at hp ⊢
      rw [if_neg (by omega)]
      by_cases hp0 : p = 0
      · subst hp0; exact hi.no_gap 0 h0
      · rw [if_neg hp0] at hp; exact hi.fenced p hp hr
  | next p k hpar hnone hfence =>
    constructor
    · intro r hr
      simp only [Lineage.put] at hr ⊢
      by_cases hrp : r = p + 1
      · rw [if_pos hrp] at hr; cases hr
      · rw [if_neg hrp] at hr
        by_cases hrp' : r + 1 = p + 1
        · have : r = p := by omega
          subst this; exact absurd hr hpar
        · rw [if_neg hrp']; exact hi.no_gap r hr
    · intro r hr hres
      simp only [Lineage.put] at hr ⊢
      by_cases hrp : r = p + 1
      · subst hrp
        rw [if_neg (by omega)]
        exact hi.no_gap (p + 1) hnone
      · rw [if_neg hrp] at hr
        by_cases hrp' : r + 1 = p + 1
        · have : r = p := by omega
          subst this
          have hres' : ln.resolved r = false := hres
          rw [hfence hr] at hres'; cases hres'
        · rw [if_neg hrp']; exact hi.fenced r hr hres
  | resolve p _ =>
    refine ⟨hi.no_gap, fun r hr hres => hi.fenced r hr ?_⟩
    simp only at hres
    by_cases hrp : r = p
    · rw [if_pos hrp] at hres; cases hres
    · rw [if_neg hrp] at hres; exact hres

theorem FenceInv.reach {ln ln' : Lineage} (hi : FenceInv ln) (hr : LReach ln ln') : FenceInv ln' := by
  induction hr with
  | refl => exact hi
  | tail _ hs ih => exact ih.step hs

theorem fenceInv_empty : FenceInv emptyLineage := ⟨fun _ _ => rfl, fun _ h => by cases h⟩

theorem no_gap_above {ln : Lineage} (hi : FenceInv ln) {p : Nat} (h : ln.claim p = none) :
    ∀ d, ln.claim (p + d) = none := by
  intro d
  induction d with
  | zero => exact h
  | succ d ih => exact hi.no_gap (p + d) ih

/-- SPECULATIVE DESCENDANTS ARE NEVER ADMITTED, for every claim kind. -/
theorem speculative_descendants_never_admitted {ln : Lineage} (hr : LReach emptyLineage ln)
    {p : Nat} (hc : ln.claim p = some .conditional) (hu : ln.resolved p = false) :
    ∀ q, p < q → ln.claim q = none := by
  have hi := fenceInv_empty.reach hr
  intro q hq
  have h := no_gap_above hi (hi.fenced p hc hu) (q - (p + 1))
  rwa [show p + 1 + (q - (p + 1)) = q by omega] at h

theorem at_most_one_unresolved_fulfillment_per_lineage {ln : Lineage}
    (hr : LReach emptyLineage ln) {p p' : Nat}
    (h1 : ln.claim p = some .conditional) (h1u : ln.resolved p = false)
    (h2 : ln.claim p' = some .conditional) (h2u : ln.resolved p' = false) : p = p' := by
  rcases Nat.lt_trichotomy p p' with h | h | h
  · rw [speculative_descendants_never_admitted hr h1 h1u p' h] at h2; cases h2
  · exact h
  · rw [speculative_descendants_never_admitted hr h2 h2u p h] at h1; cases h1

/-- The rejected fence: applied to conditional claims only. A single-root claim
then descends from an unresolved conditional position. -/
theorem fence_on_one_kind_admits_a_speculative_descendant :
    let ln : Lineage := ⟨fun p => if p = 0 then some .conditional else none, fun _ => false⟩
    ln.claim 0 ≠ none ∧ ln.claim 1 = none
      ∧ (Kind.single = .conditional → ln.claim 0 = some .conditional → ln.resolved 0 = true)
      ∧ ¬ (ln.claim 0 = some .conditional → ln.resolved 0 = true) := by
  decide

structure Transition where
  pre : Nat
  post : Nat
  mutations : List (Nat × Nat)
  position : Nat

def applyMutations (hm : HashModel) : List (Nat × Nat) → Nat → Nat
  | [], r => r
  | m :: ms, r => applyMutations hm ms (hm.H [r, m.1, m.2])

def ValidSofiVoid (parentRoot parentPos : Nat) (t : Transition) : Prop :=
  t.mutations = [] ∧ t.post = t.pre ∧ t.pre = parentRoot ∧ t.position = parentPos + 1

/-- SOFIVOID HAS ZERO ECONOMIC EFFECT: the root is the parent's, the position
advances by one. -/
theorem sofi_void_has_zero_economic_effect (hm : HashModel) {R p : Nat} {t : Transition}
    (h : ValidSofiVoid R p t) :
    applyMutations hm t.mutations t.pre = R ∧ t.post = R ∧ t.position = p + 1 := by
  obtain ⟨hm0, hpost, hpre, hpos⟩ := h
  exact ⟨by rw [hm0, hpre]; rfl, by rw [hpost, hpre], hpos⟩

theorem applyMutations_grows (hm : HashModel) :
    ∀ (ms : List (Nat × Nat)) (r : Nat), r ≤ applyMutations hm ms r := by
  intro ms
  induction ms with
  | nil => intro r; exact Nat.le_refl r
  | cons m ms ih =>
    intro r
    exact Nat.le_trans (Nat.le_of_lt (hm.dominates _ r (by simp))) (ih _)

/-- Both conjuncts are load-bearing: `post = pre` alone admits a void that carries
a mutation, whose applied root differs from the root it claims. -/
theorem void_gate_needs_the_empty_mutation_set (hm : HashModel) (r k v : Nat) :
    applyMutations hm [(k, v)] r ≠ r := by
  have := hm.dominates [r, k, v] r (by simp)
  simp only [applyMutations]
  omega

-- ── §9 genesis, setup, relationship leaf, network scope, close ────────────

structure Genesis where
  id : Nat
  network : Nat
  stored : Bool
  validatedCreation : Bool

/-- `GenesisStored` is mechanical; `GenesisAccepted` requires validated creation. -/
def GenesisAccepted (g : Genesis) : Prop := g.stored = true ∧ g.validatedCreation = true

/-- The walk starts only from an accepted genesis (or a verified frontier). -/
def WalkStart (g : Genesis) : Prop := GenesisAccepted g

theorem genesis_requires_validated_creation {g : Genesis} (h : WalkStart g) :
    g.validatedCreation = true := h.2

theorem genesis_stored_is_not_accepted :
    ∃ g : Genesis, g.stored = true ∧ ¬ WalkStart g :=
  ⟨⟨1, 1, true, false⟩, rfl, fun h => by cases h.2⟩

/-- Network scope is carried by the committed genesis identities. -/
def networkScope (trader : Genesis) (legs : List Genesis) : Validation :=
  if legs.all (fun g => g.network == trader.network) then .valid else .invalid

theorem Validation.and_invalid_right (a : Validation) : a.and .invalid = .invalid := by
  cases a <;> rfl

theorem cross_network_route_is_invalid (trader : Genesis) (legs : List Genesis) (g : Genesis)
    (hg : g ∈ legs) (hne : g.network ≠ trader.network) (gset : List Nat) (ev : Evidence) :
    routeValidation gset { ev with routeWide := ev.routeWide.and (networkScope trader legs) }
      = .invalid := by
  have hscope : networkScope trader legs = .invalid := by
    have : legs.all (fun g => g.network == trader.network) = false := by
      rw [List.all_eq_false]; exact ⟨g, hg, by simpa using hne⟩
    simp [networkScope, this]
  simp only [routeValidation, hscope, Validation.and_invalid_right]

def TAG_SETUP_REF : Nat := 9

structure SetupBody where
  genesis : Nat
  device : Nat
  p : Nat
  vault : Nat
  claimRef : Nat
  setupRoot : Nat
  key : Nat
  deriving DecidableEq, Repr

def setupRef (hm : HashModel) (b : SetupBody) : Nat :=
  hm.H [TAG_SETUP_REF, b.genesis, b.device, b.p, b.vault, b.claimRef, b.setupRoot, b.key]

def TAG_SETUP_ID : Nat := 11
def TAG_REL_GENESIS : Nat := 12
def TAG_REL_KEY : Nat := 13

/-- `σ = H(setup-id ‖ G ‖ DevID ‖ p ‖ v)`. -/
def setupId (hm : HashModel) (b : SetupBody) : Nat :=
  hm.H [TAG_SETUP_ID, b.genesis, b.device, b.p, b.vault]

/-- `h⁰ = H(rel-genesis ‖ σ)`. -/
def relLeafGenesis (hm : HashModel) (sigma : Nat) : Nat := hm.H [TAG_REL_GENESIS, sigma]

/-- `k_{T,v} = H(rel-key ‖ G ‖ DevID ‖ v)`. -/
def relKey (hm : HashModel) (b : SetupBody) : Nat :=
  hm.H [TAG_REL_KEY, b.genesis, b.device, b.vault]

/-- The P15-6 insertion, as an abstract SMT insert of an ABSENT key.

`smtInsert R k v` is the root after writing `v` at `k` in the tree rooted at
`R`; `absentAt R k` says `k` holds nothing there. Modelled abstractly because
what matters here is that `R_T^setup` is a FUNCTION of `(R_p, k, L⁰)` — not
how the tree computes it. -/
structure SmtModel where
  insert : Nat → Nat → Nat → Nat
  absentAt : Nat → Nat → Prop

/-- `R_T^setup := SMT_Insert(R_p, k_{T,v}, ABSENT → L⁰)`.

Derived, never asserted. The `absentAt` premise is the same insert-from-zero
rule the write set enforces: a root produced by OVERWRITING an existing
relationship leaf is not this value. -/
def SetupPostRoot (hm : HashModel) (sm : SmtModel) (Rp : Nat) (b : SetupBody) (R : Nat) : Prop :=
  sm.absentAt Rp (relKey hm b) ∧
    R = sm.insert Rp (relKey hm b) (relLeafGenesis hm (setupId hm b))

/-- Setup ingress at one member.

Four conjuncts, not two. The first two were already here: the exact root-claim
envelope digest at `K_root(p)`, and the `(G, DevID, v)` index empty or already
`(p, ρ)`.

The last two are what stops the uniqueness theorem below from ranging over an
UNCHECKED field. `setupRoot` is part of `SetupBody` and therefore part of `ρ`,
so without them a correctly signed first setup — index empty — could put any
value there, and the index would pin a `ρ` committing it forever. The theorem
would prove that later ingresses agree on those bytes, never that the bytes
describe the actual trader root.

`parent` gives the root the claim at `p` names; `SetupPostRoot` derives
`R_T^setup` from it by the P15-6 absent→`h⁰` insertion, and the body must
equal that. `b.p` is the position the parent claim names — the ordinary setup
transition lands at `p + 1`. -/
def SetupIngress (hm : HashModel) (sm : SmtModel) (kroot : Nat → Option Nat)
    (parent : Nat → Option Nat) (index : Option (Nat × Nat)) (b : SetupBody) : Prop :=
  kroot b.p = some b.claimRef ∧
    (index = none ∨ index = some (b.p, setupRef hm b)) ∧
    (∃ Rp, parent b.p = some Rp ∧ SetupPostRoot hm sm Rp b b.setupRoot)

/-- `R_T^setup` IS DETERMINED by the parent root and the body's coordinates.

The conjunct's point, stated on its own: two admitted setups that name the same
parent position cannot disagree about the root, because neither of them chose
it. Before the conjunct existed this was false — `setupRoot` was free. -/
theorem setup_root_is_derived_not_chosen {hm : HashModel} {sm : SmtModel}
    {kroot parent : Nat → Option Nat} {index : Option (Nat × Nat)} {b1 b2 : SetupBody}
    (h1 : SetupIngress hm sm kroot parent index b1)
    (h2 : SetupIngress hm sm kroot parent index b2)
    (hp : b1.p = b2.p) (hg : b1.genesis = b2.genesis) (hd : b1.device = b2.device)
    (hv : b1.vault = b2.vault) :
    b1.setupRoot = b2.setupRoot := by
  obtain ⟨R1, hpar1, _, hr1⟩ := h1.2.2
  obtain ⟨R2, hpar2, _, hr2⟩ := h2.2.2
  have hR : R1 = R2 := by
    rw [hp, hpar2] at hpar1; exact (Option.some.inj hpar1).symm
  have hk : relKey hm b1 = relKey hm b2 := by
    simp [relKey, hg, hd, hv]
  have hs : setupId hm b1 = setupId hm b2 := by
    simp [setupId, hg, hd, hp, hv]
  rw [hr1, hr2, hR, hk, hs]

/-- SETUP IS BOUND TO THE EXACT ENVELOPE: two setups admitted at one position
name the same root-claim envelope digest, and an occupied index admits only its
own `ρ` — alternate envelopes of one body are idempotent. -/
theorem setup_bound_to_exact_envelope {hm : HashModel} {sm : SmtModel}
    {kroot parent : Nat → Option Nat} {index : Option (Nat × Nat)} {b1 b2 : SetupBody}
    (h1 : SetupIngress hm sm kroot parent index b1)
    (h2 : SetupIngress hm sm kroot parent index b2) (hp : b1.p = b2.p) :
    b1.claimRef = b2.claimRef ∧ (index ≠ none → setupRef hm b1 = setupRef hm b2) := by
  refine ⟨?_, fun hne => ?_⟩
  · have := h1.1; rw [hp, h2.1] at this; exact (Option.some.inj this).symm
  · rcases h1.2.1 with h | h
    · exact absurd h hne
    · rcases h2.2.1 with h' | h'
      · exact absurd h' hne
      · rw [h] at h'
        exact (Prod.mk.inj (Option.some.inj h')).2

theorem setup_ref_is_signature_independent (hm : HashModel) (a b : Envelope SetupBody)
    (h : a.body = b.body) : setupRef hm a.body = setupRef hm b.body := by rw [h]

def TAG_REL_LEAF : Nat := 10

/-- One relationship: the trader-side leaf, and the DLV-side SMT entry for the
relationship key (none = non-inclusion). -/
structure RelState where
  trader : Nat
  dlv : Option Nat

def leafNext (hm : HashModel) (h e : Nat) : Nat := hm.H [TAG_REL_LEAF, h, e]

/-- The first relationship-gated operation proves the trader leaf `h⁰` and DLV
NON-INCLUSION; both sides become `h¹`. -/
def firstOp (hm : HashModel) (e : Nat) (s : RelState) : Option RelState :=
  if s.dlv = none then some ⟨leafNext hm s.trader e, some (leafNext hm s.trader e)⟩ else none

/-- A later operation requires both sides at `hʲ`. -/
def laterOp (hm : HashModel) (e : Nat) (s : RelState) : Option RelState :=
  if s.dlv = some s.trader then some ⟨leafNext hm s.trader e, some (leafNext hm s.trader e)⟩ else none

/-- LEAF NON-INCLUSION: the first operation is admitted once. After it, the DLV
entry exists and non-inclusion can never be proven again. -/
theorem leaf_non_inclusion_admits_the_first_operation_once (hm : HashModel) {e : Nat}
    {s s' : RelState} (h : firstOp hm e s = some s') :
    s'.dlv = some s'.trader ∧ ∀ e', firstOp hm e' s' = none := by
  unfold firstOp at h
  split at h
  · cases h; exact ⟨rfl, fun _ => by simp [firstOp]⟩
  · cases h

theorem later_operations_keep_both_sides_equal (hm : HashModel) {e : Nat} {s s' : RelState}
    (h : laterOp hm e s = some s') : s'.dlv = some s'.trader ∧ ∀ e', firstOp hm e' s' = none := by
  unfold laterOp at h
  split at h
  · cases h; exact ⟨rfl, fun _ => by simp [firstOp]⟩
  · cases h

/-- The leaf chain binds every E in order: equal successor leaves from one leaf
mean equal operations. -/
theorem leaf_chain_binds_each_operation (hm : HashModel) {h e e' : Nat}
    (heq : leafNext hm h e = leafNext hm h e') : e = e' := by
  have := hm.injective _ _ heq
  simp at this
  exact this

/-- Authority over a vault: the key committed by the latest setup strictly
before `q` (`p_setup < q`), else the creation key. Setups ascend by position. -/
def currentKey : List (Nat × Nat) → Nat → Nat → Nat
  | [], _, k => k
  | (p, k') :: rest, q, k => if p < q then currentKey rest q k' else k

def CloseAuthorized (setups : List (Nat × Nat)) (creationKey q signer : Nat) : Prop :=
  signer = currentKey setups q creationKey

instance (setups : List (Nat × Nat)) (creationKey q signer : Nat) :
    Decidable (CloseAuthorized setups creationKey q signer) :=
  inferInstanceAs (Decidable (signer = currentKey setups q creationKey))

/-- CLOSE BY CURRENT AUTHORITY: after a successor authority at `p_setup = 3`, a
close at 5 signed by the superseded key is refused and one by the successor is
admitted; at 3 itself the successor has no authority yet. -/
theorem close_by_current_authority :
    ¬ CloseAuthorized [(3, 77)] 11 5 11 ∧ CloseAuthorized [(3, 77)] 11 5 77
      ∧ ¬ CloseAuthorized [(3, 77)] 11 3 77 ∧ CloseAuthorized [(3, 77)] 11 3 11 := by
  decide

theorem later_setups_confer_no_authority (p k q k0 : Nat) (rest : List (Nat × Nat)) (h : q ≤ p) :
    currentKey ((p, k) :: rest) q k0 = k0 := by
  simp [currentKey, Nat.not_lt.mpr h]

#print axioms two_pow_mul_odd_inj
#print axioms enc_pos
#print axioms enc_injective
#print axioms enc_dominates
#print axioms identity_is_signature_independent
#print axioms identity_and_signing_digest_are_domain_separated
#print axioms witness_encoding_does_not_change_policy_fulfillment_id
#print axioms gid_depends_only_on_identity_fields
#print axioms policy_fulfillment_identity_canonical_per_leg
#print axioms gid_injective
#print axioms mem_canonSet
#print axioms policy_fulfillment_bound_to_precommit_parent_and_shadow
#print axioms p_g_f_hash_order_acyclic
#print axioms current_e_objects_never_in_closure
#print axioms precommit_in_its_own_closure_is_unconstructible
#print axioms closure_admits_prior_e
#print axioms closure_refuses_current_e_classes
#print axioms structurally_earlier_dependencies
#print axioms fulfillment_requires_complete_policy_fulfillment_set
#print axioms fLegs_conforming
#print axioms conforming_is_signature_bound
#print axioms Validation.and_comm
#print axioms and_refines
#print axioms allV_invalid_iff
#print axioms allV_valid_iff
#print axioms invalid_refines_only_to_invalid
#print axioms valid_refines_only_to_valid
#print axioms allV_map_refines
#print axioms route_validation_refines
#print axioms route_validation_is_static
#print axioms route_impossible_invalid_arm_monotone_without_f_quantification
#print axioms per_f_arm_diverges
#print axioms aux_candidates_are_content_addressed_no_singleton_slot
#print axioms singleton_slot_is_hostile
#print axioms aux_candidate_cannot_establish_invalid
#print axioms budget_exhaustion_never_yields_invalid
#print axioms supplying_the_valid_address_validates
#print axioms garbage_candidates_do_not_consume_fetch_bound
#print axioms counting_garbage_flips_an_honest_route
#print axioms bound_violation_is_invalid_never_unavailable
#print axioms unretrieved_objects_never_establish_a_violation
#print axioms precommit_is_non_economic
#print axioms policy_fulfillment_is_non_economic_and_non_locking
#print axioms gs_persist
#print axioms locking_policy_fulfillment_is_a_free_lock
#print axioms own_conditional_successor_does_not_expire_T0
#print axioms incompatible_trader_transition_refuses_fulfillment
#print axioms a_registered_rival_refuses_fulfillment
#print axioms consumedRoute_iff
#print axioms legLost_false_of_ok
#print axioms realized_excludes_void_evidence
#print axioms resolve_realized_iff
#print axioms parent_states_are_exclusive
#print axioms parent_compatible_is_not_pending
#print axioms conditional_parent_pending_keeps_the_position_pending
#print axioms conditional_parent_on_another_branch_is_invalid
#print axioms terminal_parent_with_no_root_is_invalid_without_evidence
#print axioms the_trader_parent_rungs_are_not_vacuous
#print axioms trader_parent_arm_is_monotone
#print axioms fulfillment_atomic_all_or_none
#print axioms per_leg_consumption_is_partial_execution
#print axioms route_impossible_orphan_and_consumed_elsewhere_arms
#print axioms stranded_e_cell_is_not_partial_execution
#print axioms contended_is_coherent
#print axioms fulfillment_may_void_under_contention
#print axioms consumedRoute_mono
#print axioms storageResolved_mono
#print axioms legLost_mono
#print axioms voidEvidence_mono
#print axioms resolution_is_permanent
#print axioms literal_ladder_is_not_permanent
#print axioms registered_is_not_validated
#print axioms fulfillment_registrable_after_parent_loss_resolves_void
#print axioms at_most_one_candidate_registers_per_position
#print axioms a_candidate_that_never_registers_stays_pending
#print axioms no_guarantee_without_prepare_lock
-- ── §10 FulfillmentConformance over fetched evidence (rebuild step R7) ─────

/-- What a verifier fetched for `FulfillmentConformance(F)` — the twin of
`sofi::conformance::ConformanceEvidence`. A `none` or a `false` storage field
is a read that established nothing, never a refusal. `fSigned` and
`setupNamesLeg` are facts about bytes in hand. -/
structure ConfEvidence where
  /-- Item 1: the exact P, in a copy whose envelope verifies. -/
  precommit : Option PBody
  /-- Item 2: F's own envelope verifies under the key F commits. -/
  fSigned : Bool
  /-- Items 3, 7 and 8: `P(E)` — the preimage that recomputes E — as the
  shadow it commits per `(vault, parent)`. -/
  preimage : Option (Nat → Nat → Nat)
  /-- Item 5: `K^(a)` of vault `v` has a permanent storage resolution. -/
  priorResolved : Nat → Nat → Bool
  /-- Item 6: `Stored(setup body)` under `ρ`. -/
  setupStored : Nat → Bool
  /-- Item 7: the body at `ρ` names this trader and its leg's vault, before
  the operation. Meaningful once the body is in hand. -/
  setupNamesLeg : Nat → Bool
  /-- Item 8: every reference of `𝒞_E^pre` fetched and re-derived. -/
  closureVerified : Bool

/-- A fact about bytes in hand: false is a refusal. -/
def known (b : Bool) : Validation := if b then .valid else .invalid

/-- A storage read: false established nothing. -/
def fetched (b : Bool) : Validation := if b then .valid else .unavailable

/-- Without the exact P nothing but item 2's own-signature half is decidable:
an unsigned F is refused, a signed one waits. -/
def withoutP (ev : ConfEvidence) : Validation := (known ev.fSigned).and .unavailable

/-- Items 1 to 8 of Section 20.2, in order, under the three-valued conjunction.
A fetched P that is not the one F names is no P at all. -/
def conformance (hm : HashModel) (F : FBody) (ev : ConfEvidence) : Validation :=
  match ev.precommit with
  | none => withoutP ev
  | some P =>
    if F.pid = pid hm P then
      allV
        [ known (decide (P.p < U64_MAX ∧ F.q = P.p + 1))
        , known (ev.fSigned && decide (F.key = P.key))
        , (match ev.preimage with
            | none => .unavailable
            | some sh => known (decide (F.gset = canonSet hm sh P)))
        , known (decide (F.attempts.map Prod.fst = P.legs.map Leg.vault))
        , allV (F.attempts.map fun a =>
            if a.2 = 0 then .valid else fetched (ev.priorResolved a.1 (a.2 - 1)))
        , allV (P.legs.map fun l => fetched (ev.setupStored l.setup))
        , allV (P.legs.map fun l =>
            if ev.setupStored l.setup then known (ev.setupNamesLeg l.setup) else .unavailable)
        , (match ev.preimage with
            | none => .unavailable
            | some _ => fetched ev.closureVerified) ]
    else withoutP ev

theorem known_valid_iff (b : Bool) : known b = .valid ↔ b = true := by
  cases b <;> simp [known]

theorem fetched_valid_iff (b : Bool) : fetched b = .valid ↔ b = true := by
  cases b <;> simp [fetched]

theorem fetched_ne_invalid (b : Bool) : fetched b ≠ .invalid := by
  cases b <;> simp [fetched]

theorem withoutP_ne_valid (ev : ConfEvidence) : withoutP ev ≠ .valid := by
  unfold withoutP known
  cases ev.fSigned <;> decide

theorem allV_map_valid_iff {α : Type} (l : List α) (f : α → Validation) :
    allV (l.map f) = .valid ↔ ∀ x ∈ l, f x = .valid := by
  rw [allV_valid_iff]
  exact List.forall_mem_map

theorem item5_valid_iff (z : Prop) [Decidable z] (b : Bool) :
    (if z then Validation.valid else fetched b) = .valid ↔ (¬ z → b = true) := by
  by_cases hz : z <;> simp [hz, fetched_valid_iff]

theorem item7_valid_iff (s n : Bool) :
    (if s = true then known n else Validation.unavailable) = .valid ↔ s = true ∧ n = true := by
  cases s <;> cases n <;> simp [known]

/-- CORRESPONDENCE (the Core test `a_fulfillment_with_everything_in_hand_is_valid`
and the eight `item_n_*` tests): the predicate is Valid exactly when the
structural `Conforming` holds over the exact P and P(E), F is signed, and every
storage fact it depends on is established. -/
theorem conformance_valid_iff (hm : HashModel) (F : FBody) (ev : ConfEvidence) :
    conformance hm F ev = .valid ↔
      ∃ P sh, ev.precommit = some P ∧ ev.preimage = some sh ∧ Conforming hm sh P F
        ∧ ev.fSigned = true
        ∧ (∀ a ∈ F.attempts, a.2 ≠ 0 → ev.priorResolved a.1 (a.2 - 1) = true)
        ∧ (∀ l ∈ P.legs, ev.setupStored l.setup = true ∧ ev.setupNamesLeg l.setup = true)
        ∧ ev.closureVerified = true := by
  cases hp : ev.precommit with
  | none => simp [conformance, hp, withoutP_ne_valid]
  | some P =>
    simp only [conformance, hp]
    by_cases hid : F.pid = pid hm P
    · rw [if_pos hid]
      cases hpre : ev.preimage with
      | none => simp [allV_valid_iff]
      | some sh =>
        simp only [allV_valid_iff, List.forall_mem_cons, List.forall_mem_map, known_valid_iff,
          fetched_valid_iff, item5_valid_iff, item7_valid_iff, decide_eq_true_eq,
          Bool.and_eq_true, Option.some.injEq]
        constructor
        · rintro ⟨⟨h1a, h1b⟩, ⟨h2a, h2b⟩, h3, h4, h5, h6, h7, h8, -⟩
          exact ⟨P, sh, rfl, rfl, ⟨hid, h3, h4, h1a, h1b, h2b⟩, h2a, h5,
            fun l hl => ⟨h6 l hl, (h7 l hl).2⟩, h8⟩
        · rintro ⟨P', sh', hP', hsh', ⟨_, h3, h4, h1a, h1b, h2b⟩, h2a, h5, h67, h8⟩
          cases hP'
          cases hsh'
          exact ⟨⟨h1a, h1b⟩, ⟨h2a, h2b⟩, h3, h4, h5, fun l hl => (h67 l hl).1,
            fun l hl => h67 l hl, h8, by simp⟩
    · rw [if_neg hid]
      simp only [withoutP_ne_valid, false_iff]
      rintro ⟨P', sh', hP', _, ⟨hid', _⟩, _⟩
      cases hP'
      exact hid hid'

/-- `ev'` has everything `ev` has: the same objects where `ev` had them, and
every storage fact `ev` established. What was not read may now be read. -/
def Extends (ev ev' : ConfEvidence) : Prop :=
  (ev.precommit = none ∨ ev'.precommit = ev.precommit)
    ∧ ev'.fSigned = ev.fSigned
    ∧ (ev.preimage = none ∨ ev'.preimage = ev.preimage)
    ∧ (∀ v a, ev.priorResolved v a = true → ev'.priorResolved v a = true)
    ∧ (∀ r, ev.setupStored r = true → ev'.setupStored r = true)
    ∧ (∀ r, ev.setupStored r = true → ev'.setupNamesLeg r = ev.setupNamesLeg r)
    ∧ (ev.closureVerified = true → ev'.closureVerified = true)

theorem Refines.rfl (v : Validation) : Refines v v := by
  cases v <;> simp [Refines]

theorem fetched_refines {b b' : Bool} (h : b = true → b' = true) :
    Refines (fetched b) (fetched b') := by
  cases b <;> cases b' <;> simp_all [fetched, Refines]

theorem allV_map_refines' {α : Type} (xs : List α) {f f' : α → Validation}
    (h : ∀ x ∈ xs, Refines (f x) (f' x)) : Refines (allV (xs.map f)) (allV (xs.map f')) := by
  induction xs with
  | nil => simp [allV, Refines]
  | cons x xs ih =>
    exact and_refines (h x (List.mem_cons_self ..))
      (ih fun y hy => h y (List.mem_cons_of_mem _ hy))

/-- MORE EVIDENCE ONLY REFINES (the Core tests `item_5_*`, `item_6_*`,
`item_8_*` and `invalid_dominates_unavailable_in_item_order`): reading more
turns Unavailable into an answer and never changes one. Invalid is permanent
and is never produced by an unmade read; Valid is never withdrawn. -/
theorem more_evidence_only_refines (hm : HashModel) (F : FBody) {ev ev' : ConfEvidence}
    (h : Extends ev ev') : Refines (conformance hm F ev) (conformance hm F ev') := by
  obtain ⟨hp, hs, hpre, hprior, hstored, hnames, hcl⟩ := h
  cases hev : ev.precommit with
  | none =>
    -- Without P only the own-signature half of item 2 was decided; it is a
    -- fact about F, and ev' carries the same fact.
    simp only [conformance, hev]
    unfold withoutP known
    rw [hs]
    cases hf : ev.fSigned
    · -- an unsigned F is refused whatever else is read
      cases hev' : ev'.precommit with
      | none => simp [Refines, Validation.and]
      | some P' =>
        simp only []
        by_cases hid : F.pid = pid hm P'
        · rw [if_pos hid]
          -- item 2 is Invalid on the same fact, so the whole conjunction is
          show Validation.invalid = allV _
          exact ((allV_invalid_iff _).mpr (by simp)).symm
        · rw [if_neg hid]
          simp [Refines, Validation.and]
    · simp [Refines, Validation.and]
  | some P =>
    have hev' : ev'.precommit = some P := by
      rcases hp with hnone | heq
      · rw [hev] at hnone; exact absurd hnone (by simp)
      · rw [heq, hev]
    simp only [conformance, hev, hev']
    by_cases hid : F.pid = pid hm P
    · rw [if_pos hid, if_pos hid]
      simp only [allV]
      refine and_refines (Refines.rfl _) (and_refines ?_ (and_refines ?_ (and_refines (Refines.rfl _)
        (and_refines ?_ (and_refines ?_ (and_refines ?_ (and_refines ?_ (Refines.rfl _))))))))
      · rw [hs]; exact Refines.rfl _
      · cases hpr : ev.preimage with
        | none => simp [Refines]
        | some sh =>
          have : ev'.preimage = some sh := by
            rcases hpre with hnone | heq
            · rw [hpr] at hnone; exact absurd hnone (by simp)
            · rw [heq, hpr]
          rw [this]; exact Refines.rfl _
      · refine allV_map_refines' _ fun a _ => ?_
        by_cases hz : a.2 = 0
        · simp [hz, Refines]
        · simp only [hz, if_false]
          exact fetched_refines (hprior _ _)
      · exact allV_map_refines' _ fun l _ => fetched_refines (hstored _)
      · refine allV_map_refines' _ fun l _ => ?_
        cases hst : ev.setupStored l.setup
        · simp [Refines]
        · rw [hstored _ hst, hnames _ hst]
          exact Refines.rfl _
      · cases hpr : ev.preimage with
        | none => simp [Refines]
        | some sh =>
          have : ev'.preimage = some sh := by
            rcases hpre with hnone | heq
            · rw [hpr] at hnone; exact absurd hnone (by simp)
            · rw [heq, hpr]
          rw [this]
          exact fetched_refines hcl
    · rw [if_neg hid, if_neg hid]
      unfold withoutP
      rw [hs]
      exact Refines.rfl _

/-- A MISSING P WAITS (the Core test `item_1_*`, and
`invalid_dominates_unavailable_in_item_order`): with the exact P not in hand
nothing about the fulfillment is refused except that it is unsigned. Mutation:
read a missing P as Invalid — this and `more_evidence_only_refines` fail. -/
theorem a_missing_p_waits_and_only_an_unsigned_f_refuses (hm : HashModel) (F : FBody)
    (ev : ConfEvidence) (h : ev.precommit = none) :
    conformance hm F ev = (if ev.fSigned then .unavailable else .invalid) := by
  simp only [conformance, h]
  unfold withoutP known
  cases ev.fSigned <;> rfl

theorem allV_map_ne_invalid {α : Type} (xs : List α) {g : α → Validation}
    (h : ∀ x, g x ≠ .invalid) : allV (xs.map g) ≠ .invalid := by
  intro hi
  rw [allV_invalid_iff, List.mem_map] at hi
  obtain ⟨x, _, hx⟩ := hi
  exact h x hx

theorem allV_eq_unavailable_of {l : List Validation} (hinv : ∀ v ∈ l, v ≠ .invalid)
    (hun : .unavailable ∈ l) : allV l = .unavailable := by
  induction l with
  | nil => simp at hun
  | cons v vs ih =>
    have hv : v ≠ .invalid := hinv v (List.mem_cons_self ..)
    have hvs : ∀ w ∈ vs, w ≠ .invalid := fun w hw => hinv w (List.mem_cons_of_mem _ hw)
    simp only [allV]
    rcases List.mem_cons.mp hun with rfl | hmem
    · cases h : allV vs
      · rfl
      · exact absurd ((allV_invalid_iff vs).mp h) (fun hm => hvs _ hm rfl)
      · rfl
    · rw [ih hvs hmem]
      cases v <;> simp_all [Validation.and]

/-- UNREAD STORAGE IS UNAVAILABLE, NEVER INVALID (the Core tests `item_5_*`,
`item_6_*`, `item_8_*`): a conforming, signed F over its exact P and P(E) whose
storage facts were not read is Unavailable. Mutation: read an unfetched setup
as Invalid (`fetched` → `known` in item 6) — this fails. -/
theorem unread_storage_is_unavailable_never_invalid (hm : HashModel) {sh : Nat → Nat → Nat}
    {P : PBody} {F : FBody} (hc : Conforming hm sh P F) :
    conformance hm F
      ⟨some P, true, some sh, fun _ _ => false, fun _ => false, fun _ => false, false⟩
      = .unavailable := by
  obtain ⟨hid, h3, h4, h1a, h1b, h2b⟩ := hc
  simp only [conformance, if_pos hid]
  apply allV_eq_unavailable_of
  · intro v hv
    simp only [List.mem_cons, List.mem_nil_iff, or_false] at hv
    rcases hv with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
    · simp [known, h1a, h1b]
    · simp [known, h2b]
    · simp [known, h3]
    · simp [known, h4]
    · exact allV_map_ne_invalid _ fun a => by split <;> simp [fetched]
    · exact allV_map_ne_invalid _ fun l => by simp [fetched]
    · exact allV_map_ne_invalid _ fun l => by simp
    · simp [fetched]
  · simp [fetched]

#print axioms position_pair_atomic
#print axioms conformance_valid_iff
#print axioms more_evidence_only_refines
#print axioms a_missing_p_waits_and_only_an_unsigned_f_refuses
#print axioms unread_storage_is_unavailable_never_invalid

#print axioms selected_root_is_committed
#print axioms route_validation_excludes_parent_canonicality
#print axioms registered_fulfillment_resolves_under_evidence_availability
#print axioms without_evidence_a_registered_fulfillment_stays_pending
#print axioms invalid_terminates_lineage
#print axioms orphaned_is_never_canonical
#print axioms an_unestablished_parent_neither_consumes_nor_defeats
#print axioms the_same_route_with_an_orphaned_parent_voids
#print axioms descendant_requires_resolved_predecessor
#print axioms advance_extends_validated_lineage
#print axioms an_undecided_or_terminal_position_extends_nothing
#print axioms FenceInv.step
#print axioms FenceInv.reach
#print axioms fenceInv_empty
#print axioms no_gap_above
#print axioms speculative_descendants_never_admitted
#print axioms at_most_one_unresolved_fulfillment_per_lineage
#print axioms fence_on_one_kind_admits_a_speculative_descendant
#print axioms sofi_void_has_zero_economic_effect
#print axioms applyMutations_grows
#print axioms void_gate_needs_the_empty_mutation_set
#print axioms genesis_requires_validated_creation
#print axioms genesis_stored_is_not_accepted
#print axioms Validation.and_invalid_right
#print axioms cross_network_route_is_invalid
#print axioms setup_bound_to_exact_envelope
#print axioms setup_root_is_derived_not_chosen
#print axioms setup_ref_is_signature_independent
#print axioms leaf_non_inclusion_admits_the_first_operation_once
#print axioms later_operations_keep_both_sides_equal
#print axioms leaf_chain_binds_each_operation
#print axioms close_by_current_authority
#print axioms later_setups_confer_no_authority
#print axioms unreached_generation_is_unavailable
#print axioms unreached_generation_never_refutes
#print axioms named_root_is_canonical
#print axioms refutes_iff_a_different_root_at_that_generation
#print axioms an_empty_chain_refutes_nothing
#print axioms admitted_credits_were_adopted
#print axioms an_unadopted_credit_is_not_admitted
#print axioms a_route_credits_only_its_output
#print axioms a_pass_through_token_is_never_credited
#print axioms an_unadopted_pass_through_still_admits

end DSMSofiAtomicity
