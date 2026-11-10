/-
  DSM Relationship Lifecycle (DSM Amendment A33) — self-contained Lean 4
  (no Mathlib, no imports)

  A relationship's leaf enters a device's tree at `h_0` when the device adds
  the contact: the relationship is OPENED, and nothing moves on it. Its first
  step is ESTABLISH, a step on its chain that moves no value, made by one
  side and countersigned by the other: the relationship is ESTABLISHED on a
  device once that device holds the step. Either side ends it with TERMINATE,
  a step that moves no value: the relationship is ENDED, for good.

  This module is the fold a device's chain applies to its leaf's lifecycle,
  step by step, in the order the device applied the steps
  (`dsm::core::relationship_lifecycle::next_lifecycle`), and what it proves:

    1. `value_step_needs_established` — a value step is admitted only on an
       established relationship: the fold refuses it from Opened and from
       Ended. This is what makes "nothing moves on a relationship that is
       not established" a property of the chain, not of a wallet's gate.
    2. `ended_is_final` — from Ended, the only step admitted is a termination
       (the other side's, crossing this device's), and it leaves the
       relationship Ended. No value step and no establishment follows.
    3. `establish_once` — an establishment is admitted only from Opened: a
       relationship is established once, by its first step.
    4. `fold_value_only_after_establish` — over any sequence of steps the
       fold admits from Opened, every value step comes after an
       establishment and before any termination
       (`fold_allows_value_only_established`: the fold's state says exactly
       when value is allowed).

  Correspondence (Rust ↔ Lean):
    `RelationshipLifecycle`                      ↔ `Lifecycle`
    `LifecycleStep` / any other `Operation`      ↔ `Step`
    `next_lifecycle` (on a bilateral relationship) ↔ `next`
    `DeviceState::advance` folding the tip's lifecycle ↔ `fold`

  A device's own relationship (the self-loop) takes neither step and admits
  every other; it is Established from the device's creation and outside this
  fold, as it is outside `next_lifecycle`'s bilateral arms.

  This module contains zero `axiom`, `opaque` and `sorry` declarations.
-/

namespace DSMRelationshipLifecycle

/-- Where a relationship stands on a device's chain. -/
inductive Lifecycle where
  | opened
  | established
  | ended
  deriving DecidableEq, Repr

/-- A step on the relationship's chain: its establishment, its termination,
or any step that moves value (a transfer). -/
inductive Step where
  | establish
  | terminate
  | value
  deriving DecidableEq, Repr

/-- The fold: the lifecycle after `s` is applied at `l`, or `none` when the
chain refuses the step there (`next_lifecycle`'s `Err`). -/
def next : Lifecycle → Step → Option Lifecycle
  | .opened, .establish => some .established
  | .opened, .terminate => some .ended
  | .opened, .value => none
  | .established, .establish => none
  | .established, .terminate => some .ended
  | .established, .value => some .established
  | .ended, .establish => none
  | .ended, .terminate => some .ended
  | .ended, .value => none

/-- Theorem 1: a value step is admitted only on an established relationship. -/
theorem value_step_needs_established (l l' : Lifecycle) (h : next l .value = some l') :
    l = .established := by
  cases l with
  | opened => simp [next] at h
  | established => rfl
  | ended => simp [next] at h

/-- A value step leaves the relationship established. -/
theorem value_step_keeps_established (l l' : Lifecycle) (h : next l .value = some l') :
    l' = .established := by
  cases l with
  | opened => simp [next] at h
  | established => simp [next] at h; exact h.symm
  | ended => simp [next] at h

/-- Theorem 2: Ended is final. The only step admitted from Ended is a
termination, and it leaves the relationship Ended. -/
theorem ended_is_final (s : Step) (l' : Lifecycle) (h : next .ended s = some l') :
    s = .terminate ∧ l' = .ended := by
  cases s with
  | establish => simp [next] at h
  | terminate => simp [next] at h; exact ⟨rfl, h.symm⟩
  | value => simp [next] at h

/-- Theorem 3: an establishment is admitted only from Opened: a relationship
is established once, by its first step. -/
theorem establish_once (l l' : Lifecycle) (h : next l .establish = some l') :
    l = .opened ∧ l' = .established := by
  cases l with
  | opened => simp [next] at h; exact ⟨rfl, h.symm⟩
  | established => simp [next] at h
  | ended => simp [next] at h

/-- The fold over a sequence of steps, refusing the whole sequence as soon as
one step is refused. -/
def fold : Lifecycle → List Step → Option Lifecycle
  | l, [] => some l
  | l, s :: rest =>
    match next l s with
    | some l' => fold l' rest
    | none => none

/-- Whether every value step in `steps` comes while value is allowed: after
an establishment and before any termination. `allowed` says whether value is
allowed before the first step. -/
def valueOnlyWhenAllowed : Bool → List Step → Bool
  | _, [] => true
  | _, .establish :: rest => valueOnlyWhenAllowed true rest
  | _, .terminate :: rest => valueOnlyWhenAllowed false rest
  | allowed, .value :: rest => allowed && valueOnlyWhenAllowed allowed rest

/-- The fold's state says whether value is allowed: exactly when the
relationship is established. -/
theorem fold_allows_value_only_established (steps : List Step) :
    ∀ (l l' : Lifecycle), fold l steps = some l' →
      valueOnlyWhenAllowed (decide (l = .established)) steps = true := by
  induction steps with
  | nil => intro l l' _; rfl
  | cons s rest ih =>
    intro l l' h
    cases s with
    | establish =>
      cases l with
      | opened =>
        simp [fold, next] at h
        simpa [valueOnlyWhenAllowed] using ih .established l' h
      | established => simp [fold, next] at h
      | ended => simp [fold, next] at h
    | terminate =>
      cases l with
      | opened =>
        simp [fold, next] at h
        simpa [valueOnlyWhenAllowed] using ih .ended l' h
      | established =>
        simp [fold, next] at h
        simpa [valueOnlyWhenAllowed] using ih .ended l' h
      | ended =>
        simp [fold, next] at h
        simpa [valueOnlyWhenAllowed] using ih .ended l' h
    | value =>
      cases l with
      | opened => simp [fold, next] at h
      | established =>
        simp [fold, next] at h
        simpa [valueOnlyWhenAllowed] using ih .established l' h
      | ended => simp [fold, next] at h

/-- Theorem 4: over any sequence the fold admits from Opened, every value
step comes after an establishment and before any termination. -/
theorem fold_value_only_after_establish (steps : List Step) (l' : Lifecycle)
    (h : fold .opened steps = some l') :
    valueOnlyWhenAllowed false steps = true := by
  simpa using fold_allows_value_only_established steps .opened l' h

end DSMRelationshipLifecycle
