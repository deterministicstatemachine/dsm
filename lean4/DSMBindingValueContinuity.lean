/-
  Binding value continuity — self-contained Lean 4 (no Mathlib, no imports)

  Machine-checks the TEMPORAL gap a raw binding-register probe exposed on
  2026-09-15, and states the property a repair must discharge. It proves a
  NEGATIVE result about the shipped rule; it does not propose the repair.

    - SHIPPED RULE     byte-identical replay is idempotent; otherwise the caller
                       must still hold exactly what it claims to have observed
                       AND supersede it with a strictly greater round. The
                       replacement VALUE is then unrestricted.
    - COUNTEREXAMPLE   `A` can be chosen, and a later raw higher-round CAS can
                       make a DIFFERENT `B` chosen at the same key
    - SNAPSHOT         one canonical-majority read still cannot show two
                       distinct chosen identities — the existing snapshot
                       theorem survives, and this module must not contradict it
    - CONTINUITY       once `A` is chosen at a key, every later chosen value
                       there must equal `A`. A later round carrying that SAME
                       value stays available, so recovery is not destroyed.

  The model. `Store` is the ONE-resource-key projection of the member register;
  list position is member identity, and `none` is explicit absence. `expected`
  is a collision-free stand-in for the caller's expected record-set digest:
  `none` means it observed absence, `some r` exactly `r`. That removes hashing
  from the model without touching the rule under test.

  What this module does NOT claim:

    * QuorumBind's prepare / adopt-highest-accepted phase is not modelled. The
      negative result is deliberately at the raw member-CAS layer, because a
      storage safety invariant must not rest on an honest-client convention.
    * Application validity is not modelled. `Value` is opaque register identity
      — tx id, value digest, value address. Storage stays application-blind.
    * Multi-key atomicity is not modelled. One overlapping key suffices to
      falsify temporal value continuity.
    * No repair is selected or proved. `ValueContinuity` is a DEFINITION of the
      obligation, never a stubbed proof: no `sorry`, no `axiom`, no `opaque`.

  Mutation controls, executed rather than asserted — and each produced the
  strongest available result: the kernel proving the NEGATION of a named
  concrete-run theorem, not merely a broken proof.

    1. the higher-round branch of `applyCas` restricted so an already-ACCEPTED
       prior may be replaced only when `prior.value = replacement.value`
         -> `the_higher_round_raw_cas_replaces_every_member` is proved FALSE
         -> `a_higher_round_raw_cas_can_choose_a_different_value` is proved
            FALSE — `afterHostileCas` stays on `A`, so no second value is chosen

  That is the evidence these theorems are about the SHIPPED rule and not an
  artifact of the model: restore the unrestricted branch and they prove again.
  The mutation was reverted from a byte copy; this file is the unmutated model.

  Axioms: `#print axioms` runs per headline theorem below and the output is
  REPORTED, never summarised. The three concrete runs depend on NO axioms; the
  general statements depend only on core `propext` / `Quot.sound` reached
  through `simp`/`omega`. Any `sorryAx` in that output is a failure, including
  the one Lean inserts when it recovers from an elaboration error — which is
  exactly what a missing `Decidable (chosen ..)` instance produced here before
  the instance below was added.
-/

namespace DSMBindingValueContinuity

/-- A binding round. The shipped Rust derives its ordering from this field
order — counter first, proposer second — and calls that ordering load-bearing. -/
structure Round where
  counter : Nat
  proposer : Nat
  deriving DecidableEq, Repr

/-- Strict lexicographic order on rounds. -/
def roundLt (a b : Round) : Bool :=
  if a.counter < b.counter then true
  else if b.counter < a.counter then false
  else decide (a.proposer < b.proposer)

/-- The binding VALUE. The round is deliberately NOT part of it: re-proposing
the same safe value at a higher round is recovery, not a second binding. -/
structure Value where
  txId : Nat
  valueDigest : Nat
  valueAddr : Nat
  deriving DecidableEq, Repr

inductive Status where
  | promised
  | accepted
  deriving DecidableEq, Repr

/-- One member's record at one resource key. -/
structure Record where
  round : Round
  value : Value
  status : Status
  deriving DecidableEq, Repr

/-- One slot per storage member. -/
abbrev Store := List (Option Record)

/-- The SHIPPED member-side acceptance rule, projected to one key:

1. byte-identical replay is idempotent;
2. otherwise the caller must still hold exactly what it expected;
3. a present prior must be superseded by a STRICTLY greater round;
4. and then ANY replacement value is written — there is no comparison against
   a value already accepted below it. That omission is the defect. -/
def applyCas (held expected : Option Record) (replacement : Record) : Option Record :=
  if held = some replacement then held
  else if held ≠ expected then held
  else
    match held with
    | none => some replacement
    | some prior => if roundLt prior.round replacement.round then some replacement else held

/-- Issue the same raw CAS to every member, as a hostile caller would. -/
def applyCasAll (s : Store) (expected : Option Record) (replacement : Record) : Store :=
  s.map (fun held => applyCas held expected replacement)

/-- One exact ACCEPTED identity: the round it was accepted at, and its value. -/
structure ChosenIdentity where
  round : Round
  value : Value
  deriving DecidableEq, Repr

/-- `Bool`, not `Prop`: this is consumed by `if` and by concrete `decide`
proofs, which is the house convention for such predicates. -/
def holds (c : ChosenIdentity) : Option Record → Bool
  | none => false
  | some r => r.status == Status.accepted && r.round == c.round && r.value == c.value

/-- How many members hold this exact ACCEPTED identity. -/
def holders (c : ChosenIdentity) : List (Option Record) → Nat
  | [] => 0
  | x :: xs => (if holds c x then 1 else 0) + holders c xs

/-- `q` members hold ACCEPTED at the same round for the same value. -/
def chosen (q : Nat) (c : ChosenIdentity) (s : Store) : Prop :=
  q ≤ holders c s

/-- Kept as a `Prop` so it reads as a statement in the theorems below, with the
decision procedure supplied explicitly so the concrete runs can be `decide`d.
Without this the `decide` proofs do not merely fail — Lean recovers from the
elaboration error and stubs them, and `#print axioms` then reports `sorryAx`. -/
instance (q : Nat) (c : ChosenIdentity) (s : Store) : Decidable (chosen q c s) :=
  inferInstanceAs (Decidable (q ≤ holders c s))

/-- The canonical strict-majority threshold the observer reads at. -/
def canonicalQuorum (n : Nat) : Nat := n / 2 + 1

-- ─────────────────────────────────────────────────────────────────────────────
-- Snapshot safety — preserved, not contradicted
-- ─────────────────────────────────────────────────────────────────────────────

/-- A member holds at most one record, so it cannot hold two distinct chosen
identities at once. No structure `.ext` lemma is used: the two field equalities
are extracted and the constructors destructured. -/
theorem one_member_cannot_hold_two_distinct_identities
    (a b : ChosenIdentity) (hne : a ≠ b) (x : Option Record)
    (ha : holds a x = true) (hb : holds b x = true) : False := by
  cases x with
  | none => simp [holds] at ha
  | some r =>
    simp [holds] at ha hb
    apply hne
    cases a with
    | mk ar av =>
      cases b with
      | mk br bv =>
        simp_all

/-- Distinct chosen identities have disjoint holder sets within ONE read. -/
theorem holders_disjoint (a b : ChosenIdentity) (hne : a ≠ b) :
    ∀ l : List (Option Record), holders a l + holders b l ≤ l.length := by
  intro l
  induction l with
  | nil => simp [holders]
  | cons x xs ih =>
    cases ha : holds a x with
    | false =>
      cases hb : holds b x with
      | false => simp [holders, ha, hb]; omega
      | true => simp [holders, ha, hb]; omega
    | true =>
      cases hb : holds b x with
      | false => simp [holders, ha, hb]; omega
      | true => exact (one_member_cannot_hold_two_distinct_identities a b hne x ha hb).elim

/-- SNAPSHOT. At the canonical strict majority, one read cannot show two
distinct chosen identities. The temporal counterexample below does not
contradict this — it is a statement about a single read. -/
theorem one_read_cannot_show_two_chosen_values
    (s : Store) (a b : ChosenIdentity) (hne : a ≠ b)
    (ha : chosen (canonicalQuorum s.length) a s)
    (hb : chosen (canonicalQuorum s.length) b s) : False := by
  have hd := holders_disjoint a b hne s
  unfold chosen canonicalQuorum at ha hb
  omega

-- ─────────────────────────────────────────────────────────────────────────────
-- The shipped rule's counterexample, as a concrete run
-- ─────────────────────────────────────────────────────────────────────────────

def roundA : Round := { counter := 3, proposer := 1 }
def roundB : Round := { counter := 4, proposer := 238 }

def valueA : Value := { txId := 101, valueDigest := 22163, valueAddr := 1001 }
def valueB : Value := { txId := 202, valueDigest := 45232, valueAddr := 2002 }

def recordA : Record := { round := roundA, value := valueA, status := Status.accepted }
def recordB : Record := { round := roundB, value := valueB, status := Status.accepted }

def chosenA : ChosenIdentity := { round := roundA, value := valueA }
def chosenB : ChosenIdentity := { round := roundB, value := valueB }

/-- `A` is chosen on all three members. -/
def beforeHostileCas : Store := [some recordA, some recordA, some recordA]

/-- The hostile caller read `A`, so it can name the expectation exactly, and
submits `B` at a strictly greater round directly to every member. -/
def afterHostileCas : Store :=
  applyCasAll beforeHostileCas (some recordA) recordB

theorem the_higher_round_raw_cas_replaces_every_member :
    afterHostileCas = [some recordB, some recordB, some recordB] := by
  decide

/-- COUNTEREXAMPLE. `A` is chosen; one raw higher-round CAS sequence then makes
a DIFFERENT `B` chosen. This is the negative result about the shipped rule. -/
theorem a_higher_round_raw_cas_can_choose_a_different_value :
    chosen 2 chosenA beforeHostileCas
      ∧ valueA ≠ valueB
      ∧ chosen 2 chosenB afterHostileCas := by
  decide

/-- The same run still respects snapshot uniqueness: after the overwrite the
two values are not both chosen in that one read. The defect is temporal. -/
theorem the_counterexample_preserves_snapshot_uniqueness :
    ¬ (chosen 2 chosenA afterHostileCas ∧ chosen 2 chosenB afterHostileCas) := by
  decide

-- ─────────────────────────────────────────────────────────────────────────────
-- The obligation a repair must discharge
-- ─────────────────────────────────────────────────────────────────────────────

/-- BINDING VALUE CONTINUITY.

For one resource key at a fixed quorum: if `A` is chosen at `t₁` and `B` is
chosen later at `t₂`, their VALUES are equal. Their rounds may differ, so a
later ballot carrying the same safe value forward — legitimate recovery —
remains possible.

A DEFINITION, deliberately. Nothing here proves it of `applyCas`, because no
mechanism currently enforces it; the counterexample above is precisely a witness
that the shipped rule does not. -/
def ValueContinuity (q : Nat) (trace : Nat → Store) : Prop :=
  ∀ (A B : ChosenIdentity) (t₁ t₂ : Nat),
    chosen q A (trace t₁) → chosen q B (trace t₂) → t₁ < t₂ → A.value = B.value

-- ─────────────────────────────────────────────────────────────────────────────
-- Axiom report (per-theorem, never a blanket claim)
-- ─────────────────────────────────────────────────────────────────────────────

#print axioms one_member_cannot_hold_two_distinct_identities
#print axioms holders_disjoint
#print axioms one_read_cannot_show_two_chosen_values
#print axioms the_higher_round_raw_cas_replaces_every_member
#print axioms a_higher_round_raw_cas_can_choose_a_different_value
#print axioms the_counterexample_preserves_snapshot_uniqueness

end DSMBindingValueContinuity
