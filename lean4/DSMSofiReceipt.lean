/-
  The Def 14.2 SofiReceipt obligation — self-contained Lean 4 (no Mathlib, no imports)

  Machine-checks amendment 2c-F's owner rulings on R6, and the owner's merge
  condition on #859, against C2's completion pass (DSMSettlementCompletion),
  restated here over one record:

    - NEVER A GATE     the fence follows C2's rule alone: certification and V1 at
                       quorum. The receipt's state, its freeze succeeding and its
                       reachability change nothing about the release
    - AFTER CERTIFY    a receipt obligation is created only by a certified pass,
                       or rebuilt only for a released — certified — settlement
    - NEVER LOST       a failed freeze does not hold the fence, and once the fence
                       is released the recovery pass records the obligation
    - RECOVERABLE      recovery and the sweep never move the fence, the bundle,
                       the successor or V1
    - IDEMPOTENT       a second pass, recovery or sweep changes nothing

  What this module does NOT claim:

    * The projection. That the rebuilt receipt is byte-identical to the one the
      completion would have frozen is the SDK's, pinned by its restart test;
      here the receipt is a flag.
    * That `released` means certified. In the implementation, Released is
      reachable only through SuccessorAccepted, recorded only by the certified
      completion; here that is the modelling premise of `recover`.
    * Certification and quorum. Inputs, re-supplied every pass.

  Mutation controls, executed rather than asserted — the kernel proving the
  NEGATION of a named sample theorem:

    1. the release also waits for the receipt at quorum
         -> `the_release_does_not_wait_for_the_receipt` is proved FALSE
    2. the obligation is created without certification
         -> `an_uncertified_settlement_has_no_receipt` is proved FALSE
    3. the recovery pass removed
         -> `a_lost_obligation_is_rebuilt_after_release` is proved FALSE

  All mutations were reverted; this file is the unmutated module.
-/

namespace DSMSofiReceipt

inductive Fence where
  | held
  | released
  deriving DecidableEq, Repr

/-- One bound, advanced market settlement: C2's state, plus the 2c-F
obligation. `b` and `successor` are fixed at binding. -/
structure Settlement where
  b : Nat
  successor : Nat
  /-- V1 at quorum — C2's release condition. -/
  v1Published : Bool
  fence : Fence
  /-- The receipt closure is frozen: the obligation is recorded. -/
  receiptFrozen : Bool
  /-- The receipt closure is at quorum on the vault's set. -/
  receiptPublished : Bool
  deriving DecidableEq, Repr

/-- What one pass meets. -/
structure World where
  certifiable : Bool
  v1QuorumReachable : Bool
  /-- The local freeze of the receipt closure succeeds. -/
  freezeSucceeds : Bool
  receiptQuorumReachable : Bool
  deriving DecidableEq, Repr

/-- **One completion pass** (`complete_settlement`): C2's pass, with the
obligation frozen in the certified branch — when the freeze succeeds — and
swept in the same pass. A released fence is finished; D-f never resumes it. -/
def pass (w : World) (s : Settlement) : Settlement :=
  match s.fence with
  | .released => s
  | .held =>
    if w.certifiable then
      let v1 := s.v1Published || w.v1QuorumReachable
      let frozen := s.receiptFrozen || w.freezeSucceeds
      { s with
        fence := if v1 then .released else .held,
        v1Published := v1,
        receiptFrozen := frozen,
        receiptPublished := s.receiptPublished || (frozen && w.receiptQuorumReachable) }
    else s

/-- **The recovery pass** (`recover_owed_receipts`): a released settlement —
certified, by the only path to `released` — has its obligation recorded;
nothing else changes. A held fence belongs to the completion, not to this. -/
def recover (s : Settlement) : Settlement :=
  match s.fence with
  | .released => { s with receiptFrozen := true }
  | .held => s

/-- **The generic sweep**: replays a frozen obligation, and touches nothing else. -/
def sweep (w : World) (s : Settlement) : Settlement :=
  { s with receiptPublished := s.receiptPublished || (s.receiptFrozen && w.receiptQuorumReachable) }

/-- C2's release rule, stated over C2's inputs only. -/
def c2Releases (w : World) (s : Settlement) : Bool :=
  s.fence == .released || (w.certifiable && (s.v1Published || w.v1QuorumReachable))

-- ─────────────────────────────────────────────────────────────────────────────
-- General statements
-- ─────────────────────────────────────────────────────────────────────────────

/-- **NEVER A GATE.** The fence a pass produces is C2's rule, and nothing else. -/
theorem the_fence_follows_c2s_rule_alone (w : World) (s : Settlement) :
    ((pass w s).fence = .released) ↔ c2Releases w s = true := by
  obtain ⟨b, succ, v1, fence, rf, rp⟩ := s
  obtain ⟨c, q, fz, rq⟩ := w
  cases fence <;> cases v1 <;> cases c <;> cases q <;> simp [pass, c2Releases]

/-- **NEVER A GATE.** Neither the receipt's state, nor whether its freeze
succeeds, nor its reachability moves the fence. -/
theorem the_receipt_never_moves_the_fence
    (w : World) (s : Settlement) (r fz f p : Bool) :
    (pass { w with receiptQuorumReachable := r, freezeSucceeds := fz }
          { s with receiptFrozen := f, receiptPublished := p }).fence
      = (pass w s).fence := by
  obtain ⟨b, succ, v1, fence, rf, rp⟩ := s
  obtain ⟨c, q, fz', rq⟩ := w
  cases fence <;> cases v1 <;> cases c <;> cases q <;> simp [pass]

/-- **AFTER CERTIFY.** A completion pass that creates the obligation was
certified. -/
theorem a_receipt_is_created_only_by_a_certified_pass
    (w : World) (s : Settlement)
    (h0 : s.receiptFrozen = false) (h1 : (pass w s).receiptFrozen = true) :
    w.certifiable = true := by
  obtain ⟨b, succ, v1, fence, rf, rp⟩ := s
  obtain ⟨c, q, fz, rq⟩ := w
  cases fence <;> cases c <;> simp_all [pass]

/-- **AFTER CERTIFY.** Recovery never runs on a held fence. -/
theorem recovery_runs_only_after_release (s : Settlement) (h : s.fence = .held) :
    recover s = s := by
  simp [recover, h]

/-- **NEVER LOST.** Once the fence is released, recovery records the
obligation — whatever the completion's freeze did. -/
theorem the_obligation_is_never_lost (s : Settlement) (h : s.fence = .released) :
    (recover s).receiptFrozen = true := by
  simp [recover, h]

/-- **RECOVERABLE.** Recovery changes the record and nothing else. -/
theorem recovery_changes_nothing_but_the_record (s : Settlement) :
    (recover s).fence = s.fence ∧ (recover s).b = s.b
      ∧ (recover s).successor = s.successor ∧ (recover s).v1Published = s.v1Published
      ∧ (recover s).receiptPublished = s.receiptPublished := by
  obtain ⟨b, succ, v1, fence, rf, rp⟩ := s
  cases fence <;> simp [recover]

/-- **RECOVERABLE.** A frozen obligation is finished by the sweep alone. -/
theorem the_sweep_finishes_a_frozen_obligation
    (w : World) (s : Settlement)
    (hf : s.receiptFrozen = true) (hq : w.receiptQuorumReachable = true) :
    (sweep w s).receiptPublished = true := by
  simp [sweep, hf, hq]

/-- **RECOVERABLE.** The sweep never touches the settlement or its release. -/
theorem the_sweep_changes_nothing_but_publication (w : World) (s : Settlement) :
    (sweep w s).fence = s.fence ∧ (sweep w s).b = s.b
      ∧ (sweep w s).successor = s.successor ∧ (sweep w s).v1Published = s.v1Published
      ∧ (sweep w s).receiptFrozen = s.receiptFrozen := by
  simp [sweep]

/-- **IDEMPOTENT.** -/
theorem a_second_pass_changes_nothing (w : World) (s : Settlement) :
    pass w (pass w s) = pass w s := by
  obtain ⟨b, succ, v1, fence, rf, rp⟩ := s
  obtain ⟨c, q, fz, rq⟩ := w
  cases fence <;> cases v1 <;> cases c <;> cases q <;> cases rf <;> cases rp <;> cases fz
    <;> cases rq <;> simp [pass]

theorem a_second_recovery_changes_nothing (s : Settlement) :
    recover (recover s) = recover s := by
  obtain ⟨b, succ, v1, fence, rf, rp⟩ := s
  cases fence <;> simp [recover]

theorem a_second_sweep_changes_nothing (w : World) (s : Settlement) :
    sweep w (sweep w s) = sweep w s := by
  obtain ⟨b, succ, v1, fence, rf, rp⟩ := s
  obtain ⟨c, q, fz, rq⟩ := w
  cases rf <;> cases rp <;> cases rq <;> simp [sweep]

-- ─────────────────────────────────────────────────────────────────────────────
-- Samples — the statements above are not vacuous
-- ─────────────────────────────────────────────────────────────────────────────

def bound : Settlement :=
  { b := 7, successor := 12, v1Published := false, fence := .held,
    receiptFrozen := false, receiptPublished := false }

/-- Certified, V1 reachable, every receipt PUT refused. -/
def receiptRefused : World :=
  { certifiable := true, v1QuorumReachable := true, freezeSucceeds := true,
    receiptQuorumReachable := false }
/-- Certified, V1 reachable, and the local freeze of the receipt FAILS. -/
def freezeFails : World :=
  { certifiable := true, v1QuorumReachable := true, freezeSucceeds := false,
    receiptQuorumReachable := true }
def healed : World :=
  { certifiable := true, v1QuorumReachable := true, freezeSucceeds := true,
    receiptQuorumReachable := true }
def uncertified : World :=
  { certifiable := false, v1QuorumReachable := true, freezeSucceeds := true,
    receiptQuorumReachable := true }

/-- The release does not wait: released with the receipt still owed. -/
theorem the_release_does_not_wait_for_the_receipt :
    (pass receiptRefused bound).fence = .released
      ∧ (pass receiptRefused bound).receiptFrozen = true
      ∧ (pass receiptRefused bound).receiptPublished = false := by
  decide

/-- …and the sweep alone, once healed, publishes it after the release. -/
theorem the_sweep_publishes_after_the_release :
    (sweep healed (pass receiptRefused bound)).receiptPublished = true
      ∧ (sweep healed (pass receiptRefused bound)).fence = .released := by
  decide

/-- A failed freeze does not hold the fence — and leaves nothing recorded. -/
theorem a_failed_freeze_does_not_hold_the_fence :
    (pass freezeFails bound).fence = .released
      ∧ (pass freezeFails bound).receiptFrozen = false := by
  decide

/-- **The merge condition.** The lost obligation is rebuilt after the release,
and the sweep then publishes it; the fence stays released throughout. -/
theorem a_lost_obligation_is_rebuilt_after_release :
    (recover (pass freezeFails bound)).receiptFrozen = true
      ∧ (sweep healed (recover (pass freezeFails bound))).receiptPublished = true
      ∧ (sweep healed (recover (pass freezeFails bound))).fence = .released := by
  decide

/-- No certification, no receipt — whatever quorum offers, and recovery does
not run on the held fence. -/
theorem an_uncertified_settlement_has_no_receipt :
    (pass uncertified bound).receiptFrozen = false
      ∧ (recover (pass uncertified bound)).receiptFrozen = false := by
  decide

-- ─────────────────────────────────────────────────────────────────────────────
-- Axiom report
-- ─────────────────────────────────────────────────────────────────────────────

#print axioms the_fence_follows_c2s_rule_alone
#print axioms the_receipt_never_moves_the_fence
#print axioms a_receipt_is_created_only_by_a_certified_pass
#print axioms recovery_runs_only_after_release
#print axioms the_obligation_is_never_lost
#print axioms recovery_changes_nothing_but_the_record
#print axioms the_sweep_finishes_a_frozen_obligation
#print axioms the_sweep_changes_nothing_but_publication
#print axioms a_second_pass_changes_nothing
#print axioms a_second_recovery_changes_nothing
#print axioms a_second_sweep_changes_nothing
#print axioms the_release_does_not_wait_for_the_receipt
#print axioms the_sweep_publishes_after_the_release
#print axioms a_failed_freeze_does_not_hold_the_fence
#print axioms a_lost_obligation_is_rebuilt_after_release
#print axioms an_uncertified_settlement_has_no_receipt

end DSMSofiReceipt
