/-
  Settlement completion — self-contained Lean 4 (no Mathlib, no imports)

  Machine-checks amendment 2c-D §14 C2-R1 point 4 and determination D-f: the
  ONE completion pass the settle route runs after its advance and D-f's resume
  runs again on the same settlement.

    - ORDERING     the fence is released only after the exact receipt is at
                   quorum, and only in a pass whose certification held
    - HELD         below quorum, or without certification, the fence stays held
    - DURABLE      a receipt already at quorum (a crash after publication,
                   before release) is enough: the pass releases without
                   re-publishing
    - IDEMPOTENT   a second pass changes nothing, and a released fence is never
                   touched again
    - EXACT        a pass never changes the settlement's bundle `b` or its
                   permitted successor: it resumes, it never retries

  What this module does NOT claim:

    * How certification is decided. `certifiable` is the composition walk's
      verdict for exactly `b` on this pass (DSMAcceptedSuccessorWalk,
      DSMBundleAcceptance); here it is an input, re-supplied every pass, and
      never a cached field of the settlement.
    * How quorum is reached. `quorumReachable` is whether a quorum of the
      vault's set accepts the exact frozen bytes on this pass.
    * The binding. The settlement here is already bound (QuorumBind COMMITTED)
      and advanced; nothing in this model binds, advances or admits.

  Mutation controls, executed rather than asserted -- the kernel proving the
  NEGATION of a named sample theorem:

    1. the release no longer waits for publication
         -> `below_quorum_the_sample_holds` is proved FALSE
    2. the certification check dropped from the pass
         -> `an_uncertifiable_sample_never_releases` is proved FALSE

  Both mutations were reverted; this file is the unmutated module.
-/

namespace DSMSettlementCompletion

inductive Fence where
  | held
  | released
  deriving DecidableEq, Repr

/-- One bound, advanced market settlement as its completion sees it. `b` and
`successor` are fixed at binding. -/
structure Settlement where
  b : Nat
  successor : Nat
  /-- The exact receipt is frozen for the vault's set. -/
  receiptFrozen : Bool
  /-- That exact receipt is at quorum. -/
  published : Bool
  fence : Fence
  deriving DecidableEq, Repr

/-- What one pass meets: the walk's certification for exactly `b`, and whether
a quorum accepts the frozen bytes now. -/
structure World where
  certifiable : Bool
  quorumReachable : Bool
  deriving DecidableEq, Repr

/-- **One completion pass** (`complete_settlement`). -/
def pass (w : World) (s : Settlement) : Settlement :=
  match s.fence with
  | .released => s
  | .held =>
    if w.certifiable then
      if s.published || w.quorumReachable then
        { s with receiptFrozen := true, published := true, fence := .released }
      else
        { s with receiptFrozen := true }
    else s

/-- The ordering invariant: a released fence has its receipt at quorum. -/
def ordered (s : Settlement) : Prop := s.fence = .released → s.published = true

-- ─────────────────────────────────────────────────────────────────────────────
-- General statements
-- ─────────────────────────────────────────────────────────────────────────────

/-- **ORDERING is preserved by every pass.** -/
theorem every_pass_keeps_publication_before_release
    (w : World) (s : Settlement) (h : ordered s) : ordered (pass w s) := by
  obtain ⟨b, succ, rf, pub, fence⟩ := s
  obtain ⟨c, q⟩ := w
  cases fence <;> cases pub <;> cases c <;> cases q <;> simp_all [pass, ordered]

/-- A pass that releases a held fence did so under certification, with the
receipt at quorum. -/
theorem a_release_happens_only_certified_and_published
    (w : World) (s : Settlement)
    (hheld : s.fence = .held) (hrel : (pass w s).fence = .released) :
    w.certifiable = true ∧ (pass w s).published = true := by
  obtain ⟨b, succ, rf, pub, fence⟩ := s
  obtain ⟨c, q⟩ := w
  cases fence <;> cases pub <;> cases c <;> cases q <;> simp_all [pass]

/-- **HELD.** Below quorum with no durable receipt, the fence stays held. -/
theorem below_quorum_the_fence_stays_held
    (w : World) (s : Settlement)
    (hheld : s.fence = .held) (hp : s.published = false) (hq : w.quorumReachable = false) :
    (pass w s).fence = .held := by
  obtain ⟨b, succ, rf, pub, fence⟩ := s
  obtain ⟨c, q⟩ := w
  cases fence <;> cases pub <;> cases c <;> cases q <;> simp_all [pass]

/-- **HELD.** Without certification nothing changes — a frozen or even
published receipt releases nothing on its own. -/
theorem an_uncertifiable_pass_changes_nothing
    (w : World) (s : Settlement) (hc : w.certifiable = false) :
    pass w s = s := by
  obtain ⟨b, succ, rf, pub, fence⟩ := s
  obtain ⟨c, q⟩ := w
  cases fence <;> cases pub <;> cases c <;> cases q <;> simp_all [pass]

/-- **DURABLE.** A receipt already at quorum is enough: a certified pass
releases even when no quorum is reachable now. -/
theorem a_durable_receipt_is_verified_not_resent
    (w : World) (s : Settlement)
    (hheld : s.fence = .held) (hp : s.published = true) (hc : w.certifiable = true) :
    (pass w s).fence = .released := by
  obtain ⟨b, succ, rf, pub, fence⟩ := s
  obtain ⟨c, q⟩ := w
  cases fence <;> cases pub <;> cases c <;> cases q <;> simp_all [pass]

/-- **IDEMPOTENT.** A second pass under the same world changes nothing. -/
theorem a_second_pass_changes_nothing (w : World) (s : Settlement) :
    pass w (pass w s) = pass w s := by
  obtain ⟨b, succ, rf, pub, fence⟩ := s
  obtain ⟨c, q⟩ := w
  cases fence <;> cases pub <;> cases c <;> cases q <;> simp_all [pass]

/-- **EXACT.** A pass never changes the bundle or the permitted successor. -/
theorem a_pass_keeps_the_settlement (w : World) (s : Settlement) :
    (pass w s).b = s.b ∧ (pass w s).successor = s.successor := by
  obtain ⟨b, succ, rf, pub, fence⟩ := s
  obtain ⟨c, q⟩ := w
  cases fence <;> cases pub <;> cases c <;> cases q <;> simp_all [pass]

-- ─────────────────────────────────────────────────────────────────────────────
-- Samples — the statements above are not vacuous
-- ─────────────────────────────────────────────────────────────────────────────

def bound : Settlement :=
  { b := 7, successor := 12, receiptFrozen := false, published := false, fence := .held }

def missQuorum : World := { certifiable := true, quorumReachable := false }
def healed : World := { certifiable := true, quorumReachable := true }
def uncertified : World := { certifiable := false, quorumReachable := true }

/-- Below quorum the sample stays held, with its receipt frozen and owed. -/
theorem below_quorum_the_sample_holds :
    pass missQuorum bound
      = { bound with receiptFrozen := true } := by decide

/-- D-f: the SAME settlement, resumed once the fleet heals, is released. -/
theorem the_resume_finishes_what_the_first_pass_could_not :
    (pass healed (pass missQuorum bound)).fence = .released
      ∧ (pass healed (pass missQuorum bound)).b = bound.b := by
  constructor <;> decide

/-- An uncertifiable settlement never releases, whatever quorum offers. -/
theorem an_uncertifiable_sample_never_releases :
    (pass uncertified bound).fence = .held := by decide

-- ─────────────────────────────────────────────────────────────────────────────
-- Axiom report
-- ─────────────────────────────────────────────────────────────────────────────

#print axioms every_pass_keeps_publication_before_release
#print axioms a_release_happens_only_certified_and_published
#print axioms below_quorum_the_fence_stays_held
#print axioms an_uncertifiable_pass_changes_nothing
#print axioms a_durable_receipt_is_verified_not_resent
#print axioms a_second_pass_changes_nothing
#print axioms a_pass_keeps_the_settlement
#print axioms below_quorum_the_sample_holds
#print axioms the_resume_finishes_what_the_first_pass_could_not
#print axioms an_uncertifiable_sample_never_releases

end DSMSettlementCompletion
