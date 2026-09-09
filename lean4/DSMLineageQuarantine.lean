/-
  DSM lineage quarantine — self-contained Lean 4 (no Mathlib, no imports)

  Machine-checks the statements amendment 2c-C3.1 freezes:

    - ARITHMETIC   one read at the canonical quorum cannot show two chosen
                   values, so the intra-read `Conflict` arm is not the trigger
    - TRIGGER      a root is created by exactly one event: a qualifying
                   finality contradicting a RECORDED qualifying finality at
                   the same key; no other event changes the root set
    - VALUE        the same value at another round is the same binding
    - MONOTONE     no event removes a root -- restart, timeout, a later read
                   that shows Free, a majority change, all included
    - PRESERVE     a contradiction records BOTH finalities and corrects neither
    - DERIVATION   a descendant of a root is quarantined; every descendant is
                   caught by the generation bound; under a linear chain the
                   bound is exact
    - REFUSAL      a quarantined cursor classifies SAFETY_VIOLATION with
                   LINEAGE_QUARANTINED and never INVALID or INCOMPLETE; the
                   walk folds nothing at or beyond a root -- no partial result
    - NO TIE-BREAK a quarantined key resolves to no value

  What this module does NOT claim:

    * It does not model attribution. `holders` counts ATTRIBUTED members
      holding a value; that a non-member's answer is never attributed is
      2c-C2's rule, enforced in `attribute_read`, and is a premise here.
    * It does not model the client database. "Durable" is 2c-C3.1 ruling C's
      requirement on the store. This module proves what the store's transition
      function must satisfy, not that a particular database satisfies it.
    * The linearity hypothesis of `beyond_the_root_by_generation` is stated,
      not proved: it is what a write-once register guarantees below the first
      contradiction, and where it fails an earlier root exists.

  Mutation controls, executed on copies rather than asserted. Each removed
  one frozen rule and each produced the strongest available result -- the
  kernel proving the NEGATION of a named concrete-run theorem, not merely a
  broken proof:

    1. the `q ≤ holders` qualification dropped from `step`
         -> `unqualified_finality_changes_nothing` and
            `only_a_contradiction_creates_a_root` no longer prove
         -> an unqualified second value now creates a root

    2. `resolve` answering on a quarantined key (the tie-break)
         -> `quarantined_key_resolves_to_nothing` no longer proves
         -> `the_key_resolves_to_nothing` is proved FALSE

    3. `fold` returning the prefix below a refused cursor (a partial result)
         -> `nothing_folds_at_or_beyond_a_root` and
            `folded_means_nothing_refused` no longer prove
         -> `the_walk_yields_nothing_after_the_root` is proved FALSE

    4. values compared on the ROUND as well as the value
         -> `same_value_is_not_a_contradiction` no longer proves
         -> `rerun_at_a_higher_round_is_the_same_binding` is proved FALSE:
            a re-acceptance at a higher round would quarantine a sound key

  Zero `axiom`, zero `opaque`, zero `sorry`. `#print axioms` runs on every
  headline result at the bottom and the output is REPORTED, not summarised:
  no result depends on `sorryAx` or `Classical.choice`; several depend on
  `propext` and `Quot.sound`, which are part of Lean's logic; eight results
  depend on no axioms at all.
-/

-- ============================================================
-- ARITHMETIC — one read cannot show two chosen values
-- ============================================================

/-- One read: each attributed member's record at the key, or `none` for an
    explicit absence. A member holds exactly one record per key, which is what
    makes this a list of OPTIONS rather than a list of sets. -/
def holders (v : Nat) : List (Option Nat) → Nat
  | []              => 0
  | some w :: rest  => (if w = v then 1 else 0) + holders v rest
  | none   :: rest  => holders v rest

/-- Two distinct values' holder sets are disjoint, so their counts sum to at
    most the number of answers. -/
theorem holders_disjoint (v₁ v₂ : Nat) (hne : v₁ ≠ v₂) :
    ∀ l : List (Option Nat), holders v₁ l + holders v₂ l ≤ l.length := by
  intro l
  induction l with
  | nil => simp [holders]
  | cons a rest ih =>
    cases a with
    | none => simp only [holders, List.length_cons]; omega
    | some w =>
      simp only [holders, List.length_cons]
      split <;> split <;> omega

/-- **ARITHMETIC.** At the canonical strict majority `q = n/2 + 1`, no single
    read of at most `n` answers can hold two distinct values each at `q`. This
    is why `BindingObservation::Conflict` cannot fire in production, and why
    the trigger is temporal: the duplicate finality Req 6.3 describes is seen
    by one verifier only ACROSS reads. -/
theorem one_read_cannot_show_two_chosen_values
    (answers : List (Option Nat)) (n q v₁ v₂ : Nat)
    (hn : answers.length ≤ n) (hq : q = n / 2 + 1) (hne : v₁ ≠ v₂)
    (h₁ : q ≤ holders v₁ answers) (h₂ : q ≤ holders v₂ answers) : False := by
  have := holders_disjoint v₁ v₂ hne answers
  omega

-- ============================================================
-- The objects
-- ============================================================

/-- A chosen VALUE: what two finalities are compared on. The round is
    deliberately not here (2c-C3.1 ruling A). -/
structure Value where
  txId        : Nat
  valueDigest : Nat
  valueAddr   : Nat
  deriving Repr, DecidableEq

/-- One qualifying binding finality this verifier established at a key --
    an observation at the committed set, or its own committed bind. -/
structure Finality where
  vault   : Nat
  cn      : Nat
  gen     : Nat
  value   : Value
  round   : Nat
  holders : Nat
  deriving Repr, DecidableEq

/-- A quarantine root: the exact parent, and BOTH finalities. -/
structure Root where
  vault  : Nat
  cn     : Nat
  gen    : Nat
  first  : Finality
  second : Finality
  deriving Repr, DecidableEq

/-- The durable store (ruling C): every finality established, write-once per
    `(vault, cn)`; and the roots. -/
structure Store where
  recorded : List Finality
  roots    : List Root
  deriving Repr, DecidableEq

/-- The recorded finality at a key, if any. -/
def lookup (s : Store) (vault cn : Nat) : Option Finality :=
  s.recorded.find? (fun r => r.vault == vault && r.cn == cn)

-- ============================================================
-- The event alphabet — everything the store can be told
-- ============================================================

/-- Every kind of thing the verifier can learn or undergo. The non-finality
    constructors exist so that "changes nothing" is proved over the events
    ruling A excludes and ruling E names, rather than assumed. -/
inductive Event where
  /-- A binding finality established by this verifier, with its attributed
      holder count. Qualifies iff `q ≤ holders`. -/
  | finality (f : Finality)
  | free
  | undetermined
  | unavailable
  /-- A present-but-failing receipt, bundle or signature. -/
  | invalidEvidence
  /-- The economic register's cell conflict: a different key space (2c-C2). -/
  | economicRegisterConflict
  | transportFailure
  | timeout
  | restart
  | majorityChange
  deriving Repr, DecidableEq

/-- **THE TRANSITION FUNCTION.** Ruling A, exactly. -/
def step (q : Nat) (s : Store) : Event → Store
  | .finality f =>
    if f.holders < q then s
    else
      match lookup s f.vault f.cn with
      | none   => { s with recorded := f :: s.recorded }
      | some r =>
        if r.value = f.value then s
        else { s with roots := { vault := f.vault, cn := f.cn, gen := r.gen,
                                 first := r, second := f } :: s.roots }
  | _ => s

-- ============================================================
-- TRIGGER, VALUE, MONOTONE, PRESERVE
-- ============================================================

/-- No non-finality event touches the store. Restart, timeout, a later read
    that shows Free, a majority change, a forged receipt, the economic
    register's conflict: each is `s ↦ s`. -/
theorem non_finality_events_change_nothing (q : Nat) (s : Store) (e : Event)
    (h : ∀ f, e ≠ .finality f) : step q s e = s := by
  cases e with
  | finality f => exact absurd rfl (h f)
  | _ => rfl

/-- **DoS, half one.** A finality below the committed quorum is not
    qualifying and changes nothing -- not the record, not the roots. -/
theorem unqualified_finality_changes_nothing (q : Nat) (s : Store) (f : Finality)
    (h : f.holders < q) : step q s (.finality f) = s := by
  simp [step, h]

/-- **VALUE.** The same value at another round is the same binding: nothing
    is written and no root is created. -/
theorem same_value_is_not_a_contradiction (q : Nat) (s : Store) (f r : Finality)
    (hq : q ≤ f.holders) (hl : lookup s f.vault f.cn = some r)
    (hv : r.value = f.value) : step q s (.finality f) = s := by
  simp [step, hl, hv, Nat.not_lt.mpr hq]

/-- **MONOTONE.** No event removes a root. This is ruling E as a theorem:
    it holds for every constructor of `Event`, including the ones a clearing
    path would have to live on. -/
theorem roots_never_removed (q : Nat) (s : Store) (e : Event) :
    ∀ r ∈ s.roots, r ∈ (step q s e).roots := by
  intro r hr
  cases e with
  | finality f =>
    simp only [step]
    split
    · exact hr
    · split
      · exact hr
      · split
        · exact hr
        · exact List.mem_cons_of_mem _ hr
  | _ => exact hr

/-- **TRIGGER, the only way in.** If the root set changed, the event was a
    qualifying finality whose value contradicts the recorded one at its key.
    Stated as: any root in the new store that was not in the old one was
    built from exactly that pair. -/
theorem only_a_contradiction_creates_a_root (q : Nat) (s : Store) (e : Event)
    (r : Root) (hnew : r ∈ (step q s e).roots) (hold : r ∉ s.roots) :
    ∃ f rec, e = .finality f ∧ q ≤ f.holders ∧
      lookup s f.vault f.cn = some rec ∧ rec.value ≠ f.value ∧
      r.first = rec ∧ r.second = f := by
  cases e with
  | finality f =>
    simp only [step] at hnew
    split at hnew
    · exact absurd hnew hold
    · next hq =>
      split at hnew
      · exact absurd hnew hold
      · next rec hl =>
        split at hnew
        · exact absurd hnew hold
        · next hv =>
          simp only [List.mem_cons] at hnew
          rcases hnew with rfl | hin
          · exact ⟨f, rec, rfl, Nat.not_lt.mp hq, hl, hv, rfl, rfl⟩
          · exact absurd hin hold
  | _ => exact absurd hnew hold

/-- **PRESERVE.** A contradiction writes a root carrying BOTH finalities and
    leaves the earlier record untouched: the first observation is evidence,
    not an error to correct. -/
theorem a_contradiction_records_both (q : Nat) (s : Store) (f r : Finality)
    (hq : q ≤ f.holders) (hl : lookup s f.vault f.cn = some r)
    (hv : r.value ≠ f.value) :
    let s' := step q s (.finality f)
    { vault := f.vault, cn := f.cn, gen := r.gen, first := r, second := f } ∈ s'.roots ∧
    s'.recorded = s.recorded := by
  simp [step, hl, hv, Nat.not_lt.mpr hq]

-- ============================================================
-- DERIVATION — descendants, and the generation bound
-- ============================================================

/-- A vault state as the walk sees it: identity, commitment, generation, and
    the `h_{n+1} = c_n` edge to its parent (field 12). -/
structure Node where
  vault  : Nat
  cn     : Nat
  gen    : Nat
  parent : Nat
  deriving Repr, DecidableEq

/-- `Descends a p`: `p` is `a` or a descendant of `a` along parent edges. -/
inductive Descends : Node → Node → Prop where
  | refl (a : Node) : Descends a a
  | child {a b : Node} (c : Node) (h : Descends a b)
      (hp : c.parent = b.cn) (hg : c.gen = b.gen + 1) (hv : c.vault = b.vault) :
      Descends a c

def IsRoot (s : Store) (a : Node) : Prop :=
  ∃ r ∈ s.roots, r.vault = a.vault ∧ r.cn = a.cn ∧ r.gen = a.gen

/-- Ruling B's normative meaning: a node is quarantined iff its ancestry
    passes through a root. -/
def Quarantined (s : Store) (p : Node) : Prop :=
  ∃ a, IsRoot s a ∧ Descends a p

/-- A child of a quarantined node is quarantined. Nothing was enumerated. -/
theorem child_of_quarantined_is_quarantined (s : Store) (b c : Node)
    (h : Quarantined s b) (hp : c.parent = b.cn) (hg : c.gen = b.gen + 1)
    (hv : c.vault = b.vault) : Quarantined s c := by
  obtain ⟨a, ha, hd⟩ := h
  exact ⟨a, ha, Descends.child c hd hp hg hv⟩

/-- Along parent edges the generation never decreases and the vault never
    changes. -/
theorem descends_gen_le {a p : Node} (h : Descends a p) :
    a.gen ≤ p.gen ∧ a.vault = p.vault := by
  induction h with
  | refl => exact ⟨Nat.le_refl _, rfl⟩
  | child c _ _ hg hv ih => exact ⟨by omega, by rw [hv]; exact ih.2⟩

/-- The decision procedure (ruling B (i)/(ii)): same vault, generation at or
    beyond a root's. Boolean, because it is what the walk runs. -/
def refusedByGeneration (s : Store) (p : Node) : Bool :=
  s.roots.any (fun r => r.vault == p.vault && r.gen ≤ p.gen)

/-- **DERIVATION IS CAUGHT.** Every node quarantined by ancestry is refused by
    the generation bound. This is the soundness direction: the procedure
    never lets a descendant of a root through. -/
theorem quarantined_is_refused (s : Store) (p : Node)
    (h : Quarantined s p) : refusedByGeneration s p = true := by
  obtain ⟨a, ⟨r, hr, hv, _, hg⟩, hd⟩ := h
  obtain ⟨hle, hva⟩ := descends_gen_le hd
  simp only [refusedByGeneration, List.any_eq_true]
  refine ⟨r, hr, ?_⟩
  simp only [Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq]
  exact ⟨by rw [hv, hva], by omega⟩

/-- A linear chain: one state per generation, each the child of the previous.
    What a write-once register guarantees below the first contradiction. -/
structure Linear (st : Nat → Node) : Prop where
  parent : ∀ k, (st (k + 1)).parent = (st k).cn
  gen    : ∀ k, (st k).gen = k
  vault  : ∀ k, (st k).vault = (st 0).vault

/-- **THE GENERATION BOUND IS EXACT ON A LINEAR CHAIN.** Every state at or
    beyond the root's generation descends from the root, so refusing by
    generation refuses exactly the quarantined lineage and nothing else. -/
theorem beyond_the_root_by_generation {st : Nat → Node} (hl : Linear st)
    (g d : Nat) : Descends (st g) (st (g + d)) := by
  induction d with
  | zero => exact Descends.refl _
  | succ d ih =>
    refine Descends.child _ ih (hl.parent _) ?_ ?_
    · simp only [hl.gen]; omega
    · exact (hl.vault _).trans (hl.vault _).symm

theorem refused_is_quarantined_on_a_linear_chain {st : Nat → Node} (hl : Linear st)
    (s : Store) (g g' : Nat) (hroot : IsRoot s (st g)) (hle : g ≤ g') :
    Quarantined s (st g') := by
  obtain ⟨d, hd⟩ : ∃ d, g' = g + d := ⟨g' - g, by omega⟩
  subst hd
  exact ⟨st g, hroot, beyond_the_root_by_generation hl g d⟩

-- ============================================================
-- REFUSAL — the classification, and the walk
-- ============================================================

/-- 2c-C3 ruling E's layer 1, mirrored locally (modules are self-contained). -/
inductive Cls where
  | valid
  | invalid
  | incomplete
  | safetyViolation
  deriving Repr, DecidableEq

/-- The two reasons this amendment touches. `lineageQuarantined` is ruling G:
    a durable root refusing a cursor whose own key may read Free. -/
inductive Reason where
  | duplicateBindingFinality
  | lineageQuarantined
  deriving Repr, DecidableEq

/-- What the walk does at one cursor BEFORE reading the register. -/
def classifyCursor (s : Store) (p : Node) : Cls × Option Reason :=
  if refusedByGeneration s p then (.safetyViolation, some .lineageQuarantined)
  else (.valid, none)

/-- **REFUSAL, the class.** A refused cursor is a safety violation with the
    durable reason -- never INVALID, never INCOMPLETE, never valid. -/
theorem refused_cursor_is_a_safety_violation (s : Store) (p : Node)
    (h : refusedByGeneration s p = true) :
    classifyCursor s p = (.safetyViolation, some .lineageQuarantined) := by
  simp [classifyCursor, h]

theorem cursor_is_never_invalid_or_incomplete (s : Store) (p : Node) :
    (classifyCursor s p).1 ≠ .invalid ∧ (classifyCursor s p).1 ≠ .incomplete := by
  unfold classifyCursor
  split <;> exact ⟨by decide, by decide⟩

/-- The walk over a chain of cursors: folds every cursor, or refuses. It
    returns NOTHING on refusal -- there is no arm that returns the prefix. -/
def fold (s : Store) : List Node → Option (List Node)
  | []      => some []
  | p :: ps =>
    if refusedByGeneration s p then none
    else (fold s ps).map (p :: ·)

/-- **NO PARTIAL RESULT.** If any cursor in the chain is refused, the walk
    yields nothing at all -- not the states below the root, not a frontier. -/
theorem nothing_folds_at_or_beyond_a_root (s : Store) :
    ∀ chain : List Node, (∃ p ∈ chain, refusedByGeneration s p = true) →
      fold s chain = none := by
  intro chain
  induction chain with
  | nil => rintro ⟨_, h, _⟩; simp at h
  | cons p ps ih =>
    rintro ⟨x, hx, hr⟩
    simp only [fold]
    by_cases hp : refusedByGeneration s p = true
    · simp [hp]
    · simp only [List.mem_cons] at hx
      rcases hx with rfl | hin
      · exact absurd hr hp
      · simp [hp, ih ⟨x, hin, hr⟩]

/-- …and a folded chain contains no refused cursor. -/
theorem folded_means_nothing_refused (s : Store) :
    ∀ chain out : List Node, fold s chain = some out →
      ∀ p ∈ chain, refusedByGeneration s p = false := by
  intro chain
  induction chain with
  | nil => intro _ _ _ h; simp at h
  | cons p ps ih =>
    intro out hf x hx
    simp only [fold] at hf
    split at hf
    · exact Option.noConfusion hf
    · next hp =>
      simp only [List.mem_cons] at hx
      rcases hx with rfl | hin
      · exact Bool.eq_false_iff.mpr hp
      · obtain ⟨o, ho, _⟩ := Option.map_eq_some_iff.mp hf
        exact ih o ho x hin

-- ============================================================
-- NO TIE-BREAK — a quarantined key has no value
-- ============================================================

def rootAt (s : Store) (vault cn : Nat) : Bool :=
  s.roots.any (fun r => r.vault == vault && r.cn == cn)

/-- The ONLY way to ask the store for a key's value. It answers nothing on a
    quarantined key, whichever value was recorded first. -/
def resolve (s : Store) (vault cn : Nat) : Option Value :=
  if rootAt s vault cn then none else (lookup s vault cn).map (·.value)

theorem quarantined_key_resolves_to_nothing (s : Store) (vault cn : Nat)
    (h : rootAt s vault cn = true) : resolve s vault cn = none := by
  simp [resolve, h]

/-- After a contradiction, the key resolves to nothing -- the recorded first
    value is NOT returned, and neither is the second. -/
theorem contradiction_leaves_no_resolvable_value (q : Nat) (s : Store) (f r : Finality)
    (hq : q ≤ f.holders) (hl : lookup s f.vault f.cn = some r)
    (hv : r.value ≠ f.value) :
    resolve (step q s (.finality f)) f.vault f.cn = none := by
  apply quarantined_key_resolves_to_nothing
  have hmem := (a_contradiction_records_both q s f r hq hl hv).1
  simp only [rootAt, List.any_eq_true]
  exact ⟨_, hmem, by simp⟩

-- ============================================================
-- A concrete run, so nothing above is vacuous
-- ============================================================

def vA : Value := ⟨1, 2, 3⟩
def vB : Value := ⟨4, 5, 6⟩

/-- First observation: `A` chosen at parent `(vault 7, c_n 100, gen 5)` at
    round 1 by 2 attributed holders under `q = 2`. -/
def obsA : Finality := ⟨7, 100, 5, vA, 1, 2⟩
/-- The SAME value re-accepted at round 3. -/
def obsA' : Finality := ⟨7, 100, 5, vA, 3, 2⟩
/-- A DIFFERENT value at the same key. -/
def obsB : Finality := ⟨7, 100, 5, vB, 2, 2⟩

def s0 : Store := ⟨[], []⟩
def s1 : Store := step 2 s0 (.finality obsA)

theorem first_observation_is_recorded_not_a_root :
    s1.recorded = [obsA] ∧ s1.roots = [] := by decide

theorem rerun_at_a_higher_round_is_the_same_binding :
    step 2 s1 (.finality obsA') = s1 := by decide

theorem a_second_value_creates_the_root :
    (step 2 s1 (.finality obsB)).roots =
      [{ vault := 7, cn := 100, gen := 5, first := obsA, second := obsB }] := by
  decide

/-- **TEETH — an unqualified second value does nothing.** One holder at
    `q = 2`: not finality, not a contradiction, not a root. -/
theorem an_unqualified_second_value_does_nothing :
    step 2 s1 (.finality ⟨7, 100, 5, vB, 2, 1⟩) = s1 := by decide

def s2 : Store := step 2 s1 (.finality obsB)

/-- Both continuations at generation 6 are refused, and so is generation 9;
    generation 4 -- below the root -- is not. -/
theorem both_continuations_are_refused :
    refusedByGeneration s2 ⟨7, 201, 6, 100⟩ = true ∧
    refusedByGeneration s2 ⟨7, 202, 6, 100⟩ = true ∧
    refusedByGeneration s2 ⟨7, 900, 9, 555⟩ = true ∧
    refusedByGeneration s2 ⟨7, 40, 4, 39⟩ = false := by decide

/-- A sibling vault on the same set is untouched. -/
theorem another_vault_is_not_refused :
    refusedByGeneration s2 ⟨8, 100, 5, 99⟩ = false := by decide

theorem the_walk_yields_nothing_after_the_root :
    fold s2 [⟨7, 40, 4, 39⟩, ⟨7, 100, 5, 40⟩, ⟨7, 201, 6, 100⟩] = none := by decide

theorem the_walk_yields_the_chain_below_the_root :
    fold s2 [⟨7, 30, 3, 29⟩, ⟨7, 40, 4, 30⟩] = some [⟨7, 30, 3, 29⟩, ⟨7, 40, 4, 30⟩] := by
  decide

theorem the_key_resolves_to_nothing : resolve s2 7 100 = none := by decide

/-- …whereas before the contradiction it resolved to `A`. -/
theorem the_key_resolved_before : resolve s1 7 100 = some vA := by decide

/-- **MONOTONE, exercised.** A later read showing Free, a restart, a timeout
    and a majority change each leave the root in place. -/
theorem no_ordinary_event_clears_it :
    (step 2 s2 .free).roots = s2.roots ∧
    (step 2 s2 .restart).roots = s2.roots ∧
    (step 2 s2 .timeout).roots = s2.roots ∧
    (step 2 s2 .majorityChange).roots = s2.roots ∧
    (step 2 s2 .invalidEvidence).roots = s2.roots := by decide

-- ============================================================
-- Axiom report (per-theorem, never a blanket claim)
-- ============================================================

#print axioms one_read_cannot_show_two_chosen_values
#print axioms non_finality_events_change_nothing
#print axioms unqualified_finality_changes_nothing
#print axioms same_value_is_not_a_contradiction
#print axioms roots_never_removed
#print axioms only_a_contradiction_creates_a_root
#print axioms a_contradiction_records_both
#print axioms child_of_quarantined_is_quarantined
#print axioms quarantined_is_refused
#print axioms beyond_the_root_by_generation
#print axioms refused_is_quarantined_on_a_linear_chain
#print axioms refused_cursor_is_a_safety_violation
#print axioms cursor_is_never_invalid_or_incomplete
#print axioms nothing_folds_at_or_beyond_a_root
#print axioms folded_means_nothing_refused
#print axioms quarantined_key_resolves_to_nothing
#print axioms contradiction_leaves_no_resolvable_value
#print axioms a_second_value_creates_the_root
#print axioms both_continuations_are_refused
#print axioms no_ordinary_event_clears_it
