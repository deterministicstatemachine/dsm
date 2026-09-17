/-
  SoFi v8 atomicity: one unilateral trader operation, P → G → F → realization —
  self-contained Lean 4 (no Mathlib, no imports)

  Machine-checks plan revision 10.3 F1–F4 and F9–F10 over content-addressed
  objects:

    - IDENTITY      P, G and F identities ignore signatures and are domain-separated
                    from signing digests; exactly one PolicyFulfillmentId per
                    (P, E, vault, parent, shadow); witness encodings never enter it;
                    a G is bound to its precommit, parent and shadow
    - HASH ORDER    𝒞_E^pre → E → P → G → F → {C_q, K_out(F)} strictly increases:
                    no current-E object can be named in the closure, a prior-E
                    conditional claim can, and conditional references are
                    structurally earlier
    - CONFORMANCE   a conforming F carries the complete canonical policy set, one
                    attempt per leg, q = p + 1 and P's key
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
                    Void, never Invalid; a registered F resolves once evidence is
                    available AND its own trader parent has resolved
    - TRADER PARENT a conditional parent that has not resolved keeps the position
                    Pending and decides nothing; one that selected another root, or
                    none, makes it Invalid with no evidence at all; the arm is
                    monotone (P15-3, R17-3)
    - CANDIDATES    E ↔ F is not one-to-one: many candidate F share one (P, E, q)
                    and one RouteValidation, and at most one of them registers
                    (R15-2)
    - LINEAGE       Invalid terminates the lineage; a descendant needs a selected
                    predecessor root; the storage fence admits no claim of ANY kind
                    above an unresolved fulfillment, so at most one is unresolved
                    per lineage; SofiVoid has zero economic effect
    - CARRIED       genesis acceptance needs validated creation; setup is bound to
                    the exact envelope; the relationship leaf's first operation is
                    admitted once; a cross-network route is Invalid; close needs the
                    current authority

  Modelling premises:

    * `HashModel`: a content address is injective, and no address is an input to
      its own preimage. `encModel` shows the two are jointly satisfiable.
    * Quorum registration is abstracted to registered facts; the quorum layer is
      DSMSofiSuccessorCells.
    * `Coherent` restates the storage and walk facts DSMSofiSuccessorCells proves:
      dead keys hold no final, one outcome value, Abort only on objective evidence,
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
                                                  `at_most_one_storage_unresolved_fulfillment_per_lineage`
    19. SofiVoid without the empty mutation set -> `sofi_void_has_zero_economic_effect`
    20. first leaf operation without non-inclusion
                                               -> `leaf_non_inclusion_admits_the_first_operation_once`
    21. authority from a setup at q itself     -> `close_by_current_authority`
    22. network scope removed                  -> `cross_network_route_is_invalid`
    23. setup without the exact envelope digest -> `setup_bound_to_exact_envelope`
    24. the walk starts from a stored genesis  -> `genesis_requires_validated_creation`
    25. a known bound violation Unavailable    -> `bound_violation_is_invalid_never_unavailable`
    26. an exhausted budget Invalid            -> `budget_exhaustion_never_yields_invalid`
    27. F ingress ignores K_root(q)            -> `incompatible_trader_transition_refuses_fulfillment`
    28. F at the parent position q = p         -> `own_conditional_successor_does_not_expire_T0`
    29. the signature inside PrecommitId       -> `identity_is_signature_independent`
    30. id and signing digest share a tag      -> `identity_and_signing_digest_are_domain_separated`
    31. Invalid counted as validated ancestry  -> `invalid_terminates_lineage`
    32. Void selecting the Realize root        -> `route_validation_excludes_parent_canonicality`
    33. the parent's selected branch unchecked -> `conditional_parent_on_another_branch_is_invalid`
    34. an undecided parent read as terminal   -> `conditional_parent_pending_keeps_the_position_pending`

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
def TAG_ROUTE_OUTCOME : Nat := 8

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


-- ── §3 hash order: 𝒞_E^pre → E → P → G → F → {C_q, K_out(F)} ──────────────

inductive ObjClass where
  | setup
  | precommit
  | policyFulfillment
  | fulfillment
  | resolutionClaim
  | resolutionRecord
  | outcomeCell
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

/-- `K_out(F) = H(route-outcome/v2 ‖ FulfillmentId)`. -/
def outcomeKey (F : FBody) : Nat := hm.H [TAG_ROUTE_OUTCOME, fid hm F]

end Order

/-- THE HASH ORDER IS ACYCLIC. Every closure digest precedes E, E precedes P,
P precedes each G, each G and P precede F, and F precedes `C_q` and `K_out(F)`. -/
theorem p_g_f_hash_order_acyclic (hm : HashModel) (shadowOf : Nat → Nat → Nat)
    (closure : List ValidationRef) (rest : List Nat) (P : PBody) (F : FBody)
    (hE : P.e = extId hm closure rest) (hP : F.pid = pid hm P)
    (hG : F.gset = canonSet hm shadowOf P) :
    (∀ r ∈ closure, refDigest hm r < P.e)
      ∧ P.e < pid hm P
      ∧ (∀ g ∈ canonSet hm shadowOf P, pid hm P < g ∧ P.e < g ∧ g < fid hm F)
      ∧ pid hm P < fid hm F
      ∧ fid hm F < claimId hm P F
      ∧ fid hm F < outcomeKey hm F := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
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
  · exact hm.dominates _ _ (by simp)

/-- Hence no current-E object can be named in the closure: its address is
strictly after E, and every closure digest strictly before. -/
theorem current_e_objects_never_in_closure (hm : HashModel) (shadowOf : Nat → Nat → Nat)
    (closure : List ValidationRef) (rest : List Nat) (P : PBody) (F : FBody)
    (hE : P.e = extId hm closure rest) (hP : F.pid = pid hm P)
    (hG : F.gset = canonSet hm shadowOf P) (r : ValidationRef) (hr : r ∈ closure) :
    refDigest hm r ≠ pid hm P ∧ (∀ g ∈ canonSet hm shadowOf P, refDigest hm r ≠ g)
      ∧ refDigest hm r ≠ fid hm F ∧ refDigest hm r ≠ claimId hm P F := by
  obtain ⟨h1, h2, h3, h4, h5, _⟩ := p_g_f_hash_order_acyclic hm shadowOf closure rest P F hE hP hG
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
registered facts (the quorum layer is DSMSofiSuccessorCells). -/
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

/-- F ingress. It does NOT require any DLV parent to be unconsumed: storage
cannot know that. -/
def FIngress (hm : HashModel) (shadowOf : Nat → Nat → Nat) (s : Sys) (P : PBody) (F : FBody) : Prop :=
  P ∈ s.ps ∧ PIngress s P ∧ Conforming hm shadowOf P F
    ∧ (∀ l ∈ P.legs, gFor hm shadowOf P l ∈ s.gs)
    ∧ (s.kful F.q = none ∨ s.kful F.q = some F)
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
P still conforms and F still passes ingress. -/
theorem own_conditional_successor_does_not_expire_T0 {hm : HashModel}
    {shadowOf : Nat → Nat → Nat} {s : Sys} {P : PBody} {F : FBody}
    (h : FIngress hm shadowOf s P F) :
    PIngress (fulfillStep hm P F s) P ∧ FIngress hm shadowOf (fulfillStep hm P F s) P F := by
  obtain ⟨hmem, hp, hc, hgs, _, _⟩ := h
  have hq : P.p ≠ F.q := by rw [hc.2.2.2.2.1]; omega
  have hp' : PIngress (fulfillStep hm P F s) P := by
    show (if P.p = F.q then some (claimId hm P F) else s.kroot P.p) = some P.parentClaim
    rw [if_neg hq]; exact hp
  exact ⟨hp', hmem, hp', hc, hgs, Or.inr (if_pos rfl), Or.inr (if_pos rfl)⟩

/-- An incompatible trader transition at `q` refuses every fulfillment at `q`. -/
theorem incompatible_trader_transition_refuses_fulfillment {hm : HashModel}
    {shadowOf : Nat → Nat → Nat} {s : Sys} {P : PBody} {F : FBody} {c : Nat}
    (hk : s.kroot F.q = some c) (hne : c ≠ claimId hm P F) : ¬ FIngress hm shadowOf s P F := by
  rintro ⟨_, _, _, _, _, hr⟩
  rcases hr with h | h
  · rw [hk] at h; cases h
  · rw [hk] at h; exact hne (Option.some.inj h)

theorem a_registered_rival_refuses_fulfillment {hm : HashModel} {shadowOf : Nat → Nat → Nat}
    {s : Sys} {P : PBody} {F F' : FBody} (hk : s.kful F.q = some F') (hne : F' ≠ F) :
    ¬ FIngress hm shadowOf s P F := by
  rintro ⟨_, _, _, _, hf, _⟩
  rcases hf with h | h
  · rw [hk] at h; cases h
  · rw [hk] at h; exact hne (Option.some.inj h)

-- ── §7 one operation: consumption, resolution, atomicity ──────────────────

/-- The claim at `p` that P names as its trader parent `T0` (P15-3, R17-3).
A trader may build P on a conditional parent before that parent resolves,
because the storage fence only requires `p` to be storage-resolved: it is
guessing which branch `p` will take. -/
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

/-- What a verifier has established about one fulfillment at one position. A
fulfillment that has not registered is carried with `registered := false`, and
the ladder answers Pending for it — the position's terminal answer comes from
the one fulfillment that does register (R15-2). Keys are DLV parents `R_j`;
per-parent facts are at the fulfillment's own attempt. -/
structure Facts where
  registered : Bool
  validation : Validation
  canonical : Nat → Bool
  live : Nat → Bool
  cell : Nat → Option Nat
  dead : Nat → Bool
  consumedElsewhere : Nat → Bool
  orphan : Nat → Bool
  complete : Bool
  abort : Bool
  /-- The claim at `p` this operation was built on. An ordinary parent is the
  default, which is what every pre-P15-3 fact set means. -/
  parent : ParentState := .single

def legOk (x : Facts) (e R : Nat) : Bool := x.canonical R && x.live R && x.cell R == some e

/-- `ConsumedRoute(F, E)`; a single-vault trade is the one-leg case. The
trader parent must have taken the branch this operation was built on. -/
def ConsumedRoute (x : Facts) (legs : List Nat) (e : Nat) : Bool :=
  x.registered && x.validation == .valid && legs.all (legOk x e)
    && (decide (legs.length < 2) || x.complete) && parentCompatible x.parent

def StorageResolved (x : Facts) (legs : List Nat) : Bool :=
  x.registered && legs.all (fun R => x.dead R || (x.cell R).isSome)
    && (decide (legs.length < 2) || x.complete || x.abort)

def cellOther (x : Facts) (e R : Nat) : Bool :=
  match x.cell R with
  | some y => y != e
  | none => false

def legLost (x : Facts) (e R : Nat) : Bool :=
  x.dead R || cellOther x e R || x.consumedElsewhere R || x.orphan R

def VoidEvidence (x : Facts) (legs : List Nat) (e : Nat) : Bool :=
  legs.any (legLost x e) || x.abort

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
  else if ConsumedRoute x legs e = true then .realized
  else if x.validation = .invalid then .invalid
  else if x.validation = .valid ∧ StorageResolved x legs = true ∧ VoidEvidence x legs e = true then .void
  else .pending

def resolveLiteral (x : Facts) (legs : List Nat) (e : Nat) : Resolution :=
  if x.registered = false then .pending
  else if ConsumedRoute x legs e = true then .realized
  else if x.validation = .invalid then .invalid
  else if StorageResolved x legs = true ∧ VoidEvidence x legs e = true then .void
  else .pending

/-- The storage and walk facts the cell layer proves (DSMSofiSuccessorCells):
dead keys hold no final, one outcome value, Abort only on objective evidence,
one consumer per parent, orphaned parents are not canonical. -/
structure Coherent (x : Facts) (legs : List Nat) (e : Nat) : Prop where
  dead_not_final : ∀ R, x.dead R = true → x.cell R = none
  outcome_unique : ¬ (x.complete = true ∧ x.abort = true)
  abort_objective : x.abort = true → ∃ R ∈ legs, x.dead R = true ∨ cellOther x e R = true
  consumed_route_exclusive : ConsumedRoute x legs e = true → ∀ R ∈ legs, x.consumedElsewhere R = false
  orphan_not_canonical : ∀ R, x.orphan R = true → x.canonical R = false

structure Evolves (x x' : Facts) : Prop where
  registered : x.registered = true → x'.registered = true
  validation : Refines x.validation x'.validation
  canonical : ∀ R, x.canonical R = true → x'.canonical R = true
  live : ∀ R, x.live R = true → x'.live R = true
  cell : ∀ R y, x.cell R = some y → x'.cell R = some y
  dead : ∀ R, x.dead R = true → x'.dead R = true
  consumedElsewhere : ∀ R, x.consumedElsewhere R = true → x'.consumedElsewhere R = true
  orphan : ∀ R, x.orphan R = true → x'.orphan R = true
  complete : x.complete = true → x'.complete = true
  abort : x.abort = true → x'.abort = true
  /-- An open branch may be selected; a terminal one never changes. -/
  parent : x.parent ≠ .openBranch → x'.parent = x.parent := by intro _; rfl

theorem consumedRoute_iff (x : Facts) (legs : List Nat) (e : Nat) :
    ConsumedRoute x legs e = true ↔
      x.registered = true ∧ x.validation = .valid
        ∧ (∀ R ∈ legs, x.canonical R = true ∧ x.live R = true ∧ x.cell R = some e)
        ∧ (legs.length < 2 ∨ x.complete = true)
        ∧ parentCompatible x.parent = true := by
  simp [ConsumedRoute, legOk, and_assoc]

theorem legLost_false_of_ok {x : Facts} {legs : List Nat} {e R : Nat} (hc : Coherent x legs e)
    (hcr : ConsumedRoute x legs e = true) (hR : R ∈ legs) : legLost x e R = false := by
  obtain ⟨_, _, hall, _, _⟩ := (consumedRoute_iff x legs e).mp hcr
  obtain ⟨hcan, _, hcell⟩ := hall R hR
  have hd : x.dead R = false := by
    cases h : x.dead R
    · rfl
    · have := hc.dead_not_final R h; rw [hcell] at this; cases this
  have ho : x.orphan R = false := by
    cases h : x.orphan R
    · rfl
    · have := hc.orphan_not_canonical R h; rw [hcan] at this; cases this
  have hce := hc.consumed_route_exclusive hcr R hR
  simp [legLost, cellOther, hd, ho, hce, hcell]

/-- REALIZED AND VOID ARE EXCLUSIVE. -/
theorem realized_excludes_void_evidence {x : Facts} {legs : List Nat} {e : Nat}
    (hc : Coherent x legs e) (hcr : ConsumedRoute x legs e = true) :
    VoidEvidence x legs e = false := by
  have hany : legs.any (legLost x e) = false := by
    rw [List.any_eq_false]
    intro R hR
    simp [legLost_false_of_ok hc hcr hR]
  have hab : x.abort = false := by
    cases h : x.abort
    · rfl
    · obtain ⟨R, hR, hl⟩ := hc.abort_objective h
      have := legLost_false_of_ok hc hcr hR
      simp [legLost] at this
      rcases hl with hl | hl <;> simp_all
  simp [VoidEvidence, hany, hab]

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
          by_cases h2 : ConsumedRoute x legs e = true
          · exact h2
          · rw [if_neg h2] at h
            by_cases h3 : x.validation = .invalid
            · rw [if_pos h3] at h; cases h
            · rw [if_neg h3] at h
              split at h <;> cases h
  · intro h
    obtain ⟨hreg, _, _, _, hcompat⟩ := (consumedRoute_iff x legs e).mp h
    obtain ⟨hpend, himp⟩ := parent_compatible_is_not_pending hcompat
    have h1 : ¬ x.registered = false := by simp [hreg]
    have hp : ¬ parentPending x.parent = true := by simp [hpend]
    have hi : ¬ parentImpossible x.parent = true := by simp [himp]
    unfold resolve
    rw [if_neg h1, if_neg hp, if_neg hi, if_pos h]

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
  canonical := fun _ => true
  live := fun _ => true
  cell := fun _ => some 50
  dead := fun _ => false
  consumedElsewhere := fun _ => false
  orphan := fun _ => false
  complete := true
  abort := false
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
  canonical := fun _ => true
  live := fun _ => true
  cell := fun R => if R = 10 then some 50 else none
  dead := fun R => R == 11
  consumedElsewhere := fun _ => false
  orphan := fun _ => false
  complete := false
  abort := true

theorem per_leg_consumption_is_partial_execution :
    legConsumedAlone splitFacts 50 10 = true ∧ legConsumedAlone splitFacts 50 11 = false
      ∧ resolve splitFacts [10, 11] 50 = .void := by
  decide

/-- ROUTE IMPOSSIBILITY, arms (ii) and (iii′): once a parent P names is orphaned
or consumed by another E, no fulfillment of P — at any attempt vector — can be
consumed. -/
theorem route_impossible_orphan_and_consumed_elsewhere_arms {x : Facts} {legs : List Nat}
    {e R : Nat} (hc : Coherent x legs e) (hR : R ∈ legs)
    (h : x.orphan R = true ∨ x.consumedElsewhere R = true) : ConsumedRoute x legs e = false := by
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
    (hlost : x.orphan R' = true ∨ x.consumedElsewhere R' = true) :
    (x.cell R = some e ∧ ∀ R'', ConsumedLeg x legs e R'' = false)
      ∧ (x.registered = true → x.validation = .valid → StorageResolved x legs = true →
          parentCompatible x.parent = true → resolve x legs e = .void) := by
  have hno := route_impossible_orphan_and_consumed_elsewhere_arms hc hR' hlost
  refine ⟨⟨hstranded, fun R'' => by simp [ConsumedLeg, hno]⟩, fun hreg hv hsr hcompat => ?_⟩
  obtain ⟨hpend, himp⟩ := parent_compatible_is_not_pending hcompat
  have hve : VoidEvidence x legs e = true := by
    have : legLost x e R' = true := by
      rcases hlost with h | h <;> simp [legLost, h]
    simp only [VoidEvidence, Bool.or_eq_true, List.any_eq_true]
    exact Or.inl ⟨R', hR', this⟩
  simp [resolve, hreg, hno, hv, hsr, hve, hpend, himp]

/-- Contention: a rival consumed `R_A = 10` between the witnesses and F. -/
def contended : Facts where
  registered := true
  validation := .valid
  canonical := fun _ => true
  live := fun R => R == 11
  cell := fun R => if R = 10 then some 99 else if R = 11 then some 50 else none
  dead := fun _ => false
  consumedElsewhere := fun R => R == 10
  orphan := fun _ => false
  complete := false
  abort := true

theorem contended_is_coherent : Coherent contended [10, 11] 50 where
  dead_not_final := fun R h => by simp [contended] at h
  outcome_unique := by simp [contended]
  abort_objective := fun _ => ⟨10, by simp, Or.inr (by decide)⟩
  consumed_route_exclusive := fun h => by simp [ConsumedRoute, contended, legOk] at h
  orphan_not_canonical := fun R h => by simp [contended] at h

/-- A FULFILLMENT MAY VOID UNDER CONTENTION: registered, every witness valid,
and still Void. -/
theorem fulfillment_may_void_under_contention :
    Coherent contended [10, 11] 50 ∧ contended.registered = true
      ∧ contended.validation = .valid ∧ resolve contended [10, 11] 50 = .void :=
  ⟨contended_is_coherent, rfl, rfl, by decide⟩

theorem consumedRoute_mono {x x' : Facts} (hev : Evolves x x') {legs : List Nat} {e : Nat}
    (h : ConsumedRoute x legs e = true) : ConsumedRoute x' legs e = true := by
  obtain ⟨hreg, hv, hall, hlen, hcompat⟩ := (consumedRoute_iff x legs e).mp h
  have hv' : x'.validation = .valid := by
    have := hev.validation; rw [hv] at this; exact valid_refines_only_to_valid this
  refine (consumedRoute_iff x' legs e).mpr ⟨hev.registered hreg, hv', fun R hR => ?_, ?_, ?_⟩
  · obtain ⟨a, b, c⟩ := hall R hR
    exact ⟨hev.canonical R a, hev.live R b, hev.cell R e c⟩
  · rcases hlen with h | h
    · exact Or.inl h
    · exact Or.inr (hev.complete h)
  · have hne : x.parent ≠ .openBranch := by
      intro hq; rw [hq] at hcompat; exact absurd hcompat (by decide)
    rw [hev.parent hne]; exact hcompat

theorem storageResolved_mono {x x' : Facts} (hev : Evolves x x') {legs : List Nat}
    (h : StorageResolved x legs = true) : StorageResolved x' legs = true := by
  simp only [StorageResolved, Bool.and_eq_true, Bool.or_eq_true, List.all_eq_true,
    decide_eq_true_eq] at h ⊢
  obtain ⟨⟨hreg, hall⟩, hlen⟩ := h
  refine ⟨⟨hev.registered hreg, fun R hR => ?_⟩, ?_⟩
  · rcases hall R hR with hd | hs
    · exact Or.inl (hev.dead R hd)
    · right
      cases hcell : x.cell R with
      | none => rw [hcell] at hs; cases hs
      | some y => rw [hev.cell R y hcell]; rfl
  · rcases hlen with (h | h) | h
    · exact Or.inl (Or.inl h)
    · exact Or.inl (Or.inr (hev.complete h))
    · exact Or.inr (hev.abort h)

theorem legLost_mono {x x' : Facts} (hev : Evolves x x') {e R : Nat}
    (h : legLost x e R = true) : legLost x' e R = true := by
  simp only [legLost, Bool.or_eq_true] at h ⊢
  rcases h with ((hd | hco) | hce) | ho
  · exact Or.inl (Or.inl (Or.inl (hev.dead R hd)))
  · left; left; right
    unfold cellOther at hco ⊢
    cases hcell : x.cell R with
    | none => rw [hcell] at hco; cases hco
    | some y => rw [hcell] at hco; rw [hev.cell R y hcell]; exact hco
  · exact Or.inl (Or.inr (hev.consumedElsewhere R hce))
  · exact Or.inr (hev.orphan R ho)

theorem voidEvidence_mono {x x' : Facts} (hev : Evolves x x') {legs : List Nat} {e : Nat}
    (h : VoidEvidence x legs e = true) : VoidEvidence x' legs e = true := by
  simp only [VoidEvidence, Bool.or_eq_true, List.any_eq_true] at h ⊢
  rcases h with ⟨R, hR, hl⟩ | ha
  · exact Or.inl ⟨R, hR, legLost_mono hev hl⟩
  · exact Or.inr (hev.abort ha)

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
    by_cases hcr : ConsumedRoute x legs e = true
    · rw [if_pos hcr, if_pos (consumedRoute_mono hev hcr)]
    · rw [if_neg hcr]
      rw [if_neg hcr] at hnp
      by_cases hinv : x.validation = .invalid
      · have hinv' : x'.validation = .invalid := by
          have := hev.validation; rw [hinv] at this; exact invalid_refines_only_to_invalid this
        have hcr' : ¬ ConsumedRoute x' legs e = true := by simp [ConsumedRoute, hinv']
        rw [if_pos hinv, if_neg hcr', if_pos hinv']
      · rw [if_neg hinv]
        rw [if_neg hinv] at hnp
        by_cases hvoid : x.validation = .valid ∧ StorageResolved x legs = true ∧ VoidEvidence x legs e = true
        · obtain ⟨hv, hsr, hve⟩ := hvoid
          have hv' : x'.validation = .valid := by
            have := hev.validation; rw [hv] at this; exact valid_refines_only_to_valid this
          have hve' := voidEvidence_mono hev hve
          have hcr' : ¬ ConsumedRoute x' legs e = true := by
            intro h
            rw [realized_excludes_void_evidence hc' h] at hve'
            cases hve'
          have hinv' : ¬ x'.validation = .invalid := by rw [hv']; decide
          have hvoid' : x'.validation = .valid ∧ StorageResolved x' legs = true ∧ VoidEvidence x' legs e = true :=
            ⟨hv', storageResolved_mono hev hsr, hve'⟩
          have hvoid : x.validation = .valid ∧ StorageResolved x legs = true ∧ VoidEvidence x legs e = true :=
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
  canonical := fun _ => true
  live := fun _ => true
  cell := fun _ => none
  dead := fun _ => true
  consumedElsewhere := fun _ => false
  orphan := fun _ => false
  complete := false
  abort := false

def laterInvalid : Facts := { unavailableThenVoid with validation := .invalid }

theorem literal_ladder_is_not_permanent :
    Evolves unavailableThenVoid laterInvalid
      ∧ Coherent laterInvalid [10] 50
      ∧ resolveLiteral unavailableThenVoid [10] 50 = .void
      ∧ resolveLiteral laterInvalid [10] 50 = .invalid
      ∧ resolve unavailableThenVoid [10] 50 = .pending := by
  refine ⟨⟨fun h => h, trivial, fun _ h => h, fun _ h => h, fun _ _ h => h, fun _ h => h,
    fun _ h => h, fun _ h => h, fun h => h, fun h => h, fun _ => rfl⟩, ⟨fun _ _ => rfl, (by decide),
    (fun h => by cases h), (fun h => by simp [ConsumedRoute, laterInvalid, unavailableThenVoid] at h),
    (fun _ h => by simp [laterInvalid, unavailableThenVoid] at h)⟩, (by decide), (by decide), (by decide)⟩

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
    (hv : x.validation = .valid) (hsr : StorageResolved x legs = true)
    (hcompat : parentCompatible x.parent = true) :
    (FIngress hm shadowOf (consumeStep R y s) P F ↔ FIngress hm shadowOf s P F)
      ∧ resolve x legs e = .void
      ∧ ∀ x', Evolves x x' → Coherent x' legs e → resolve x' legs e = .void := by
  have hno := route_impossible_orphan_and_consumed_elsewhere_arms hc hR (Or.inr hlost)
  obtain ⟨hpend, himp⟩ := parent_compatible_is_not_pending hcompat
  have hve : VoidEvidence x legs e = true := by
    simp only [VoidEvidence, Bool.or_eq_true, List.any_eq_true]
    exact Or.inl ⟨R, hR, by simp [legLost, hlost]⟩
  have hres : resolve x legs e = .void := by
    simp [resolve, hreg, hno, hv, hsr, hve, hpend, himp]
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
  obtain ⟨_, _, _, _, hk, _⟩ := h2
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
  if legs.any x.orphan then .invalid else x.validation

def orphanedLeg : Facts where
  registered := true
  validation := .valid
  canonical := fun R => R != 10
  live := fun _ => true
  cell := fun R => if R = 10 then some 50 else none
  dead := fun R => R == 11
  consumedElsewhere := fun _ => false
  orphan := fun R => R == 10
  complete := false
  abort := true

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
    (hev : x.validation ≠ .unavailable) (hsr : StorageResolved x legs = true)
    (hpar : parentPending x.parent = false)
    (hfate : ∀ R ∈ legs, (x.canonical R = true ∧ x.live R = true) ∨ x.orphan R = true
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
  by_cases hcr : ConsumedRoute x legs e = true
  · rw [if_pos hcr]; decide
  · rw [if_neg hcr]
    by_cases hinv : x.validation = .invalid
    · rw [if_pos hinv]; decide
    · rw [if_neg hinv]
      have hv : x.validation = .valid := by
        cases h : x.validation
        · rfl
        · exact absurd h hinv
        · exact absurd h hev
      have hve : VoidEvidence x legs e = true := by
        simp only [StorageResolved, Bool.and_eq_true, Bool.or_eq_true, List.all_eq_true,
          decide_eq_true_eq] at hsr
        obtain ⟨⟨_, hall⟩, hlen⟩ := hsr
        by_cases hab : x.abort = true
        · simp [VoidEvidence, hab]
        · have hall_ok : ¬ ∀ R ∈ legs, x.canonical R = true ∧ x.live R = true ∧ x.cell R = some e := by
            intro hok
            apply hcr
            refine (consumedRoute_iff x legs e).mpr ⟨hreg, hv, hok, ?_, hcompat⟩
            rcases hlen with (h | h) | h
            · exact Or.inl h
            · exact Or.inr h
            · exact absurd h hab
          apply Classical.byContradiction
          intro hnot
          apply hall_ok
          intro R hR
          have hnl : legLost x e R = false := by
            cases hl : legLost x e R
            · rfl
            · exfalso; apply hnot
              simp only [VoidEvidence, Bool.or_eq_true, List.any_eq_true]
              exact Or.inl ⟨R, hR, hl⟩
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
          · rw [ho] at h; cases h
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
  have hcr : ConsumedRoute x' [10] 50 = false := by simp [ConsumedRoute, hu]
  constructor
  · intro h; rw [(resolve_realized_iff _ _ _).mp h] at hcr; cases hcr
  · intro h
    unfold resolve at h
    simp [hpar, parentPending, parentImpossible, hcr, hu] at h

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

inductive Kind where
  | single
  | conditional
  | setup
  | close
  deriving DecidableEq, Repr

/-- Registered claims of one lineage, and which conditional positions are
storage-resolved. -/
structure Lineage where
  claim : Nat → Option Kind
  resolved : Nat → Bool

def Lineage.put (ln : Lineage) (q : Nat) (k : Kind) : Lineage :=
  { ln with claim := fun p => if p = q then some k else ln.claim p }

inductive LStep : Lineage → Lineage → Prop
  | first (ln : Lineage) (k : Kind) : ln.claim 0 = none → LStep ln (ln.put 0 k)
  /-- ANY claim kind at `p + 1`: a parent exists, and a conditional parent is
  storage-resolved. -/
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

theorem at_most_one_storage_unresolved_fulfillment_per_lineage {ln : Lineage}
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

/-- Setup ingress at one member: the exact root-claim envelope digest at
`K_root(p)`, and the `(G, DevID, v)` index empty or already `(p, ρ)`. -/
def SetupIngress (hm : HashModel) (kroot : Nat → Option Nat) (index : Option (Nat × Nat))
    (b : SetupBody) : Prop :=
  kroot b.p = some b.claimRef ∧ (index = none ∨ index = some (b.p, setupRef hm b))

/-- SETUP IS BOUND TO THE EXACT ENVELOPE: two setups admitted at one position
name the same root-claim envelope digest, and an occupied index admits only its
own `ρ` — alternate envelopes of one body are idempotent. -/
theorem setup_bound_to_exact_envelope {hm : HashModel} {kroot : Nat → Option Nat}
    {index : Option (Nat × Nat)} {b1 b2 : SetupBody}
    (h1 : SetupIngress hm kroot index b1) (h2 : SetupIngress hm kroot index b2) (hp : b1.p = b2.p) :
    b1.claimRef = b2.claimRef ∧ (index ≠ none → setupRef hm b1 = setupRef hm b2) := by
  refine ⟨?_, fun hne => ?_⟩
  · have := h1.1; rw [hp, h2.1] at this; exact (Option.some.inj this).symm
  · rcases h1.2 with h | h
    · exact absurd h hne
    · rcases h2.2 with h' | h'
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
#print axioms selected_root_is_committed
#print axioms route_validation_excludes_parent_canonicality
#print axioms registered_fulfillment_resolves_under_evidence_availability
#print axioms without_evidence_a_registered_fulfillment_stays_pending
#print axioms invalid_terminates_lineage
#print axioms descendant_requires_resolved_predecessor
#print axioms FenceInv.step
#print axioms FenceInv.reach
#print axioms fenceInv_empty
#print axioms no_gap_above
#print axioms speculative_descendants_never_admitted
#print axioms at_most_one_storage_unresolved_fulfillment_per_lineage
#print axioms fence_on_one_kind_admits_a_speculative_descendant
#print axioms sofi_void_has_zero_economic_effect
#print axioms applyMutations_grows
#print axioms void_gate_needs_the_empty_mutation_set
#print axioms genesis_requires_validated_creation
#print axioms genesis_stored_is_not_accepted
#print axioms Validation.and_invalid_right
#print axioms cross_network_route_is_invalid
#print axioms setup_bound_to_exact_envelope
#print axioms setup_ref_is_signature_independent
#print axioms leaf_non_inclusion_admits_the_first_operation_once
#print axioms later_operations_keep_both_sides_equal
#print axioms leaf_chain_binds_each_operation
#print axioms close_by_current_authority
#print axioms later_setups_confer_no_authority

end DSMSofiAtomicity
