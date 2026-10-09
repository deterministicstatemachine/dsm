/-
  DSM Offline Finality — self-contained Lean 4 proofs (no Mathlib)

  One offline bilateral step between a proposer and a receiver:

      proposer                          receiver
      prepared        -- prepare -->    pendingUser  (its user decides)
                      <-- response --   accepted     (or a signed rejection)
      confirmPending  -- confirm -->    committed    (commits, then answers)
      committed       <--- ack -----

  The receiver commits on the confirm and the proposer on the ack: two
  commits, on two devices, at two moments. The step's atomicity is therefore
  BOTH-OR-NEITHER: the receiver has committed only if the proposer is past its
  confirm (so it can no longer end the step), and the proposer has committed
  only if the receiver has.

  This module proves both-or-neither for every behaviour of one step: frames
  lost, delivered again or delivered late, the link dropping and returning,
  either device restarting, the user accepting or rejecting, the proposer
  cancelling, and either commit refused by its tripwire. It rests on four
  clauses that are inductive on their own (`Inv`): the two halves of
  both-or-neither, and the durable boundary for the two frames that commit —
  a confirm in the air was sent by a proposer whose confirmPending is durable,
  an ack by a receiver whose commit is.

  The rules of the code (dsm_sdk bluetooth/bilateral_ble_handler.rs) are
  switches (`Rules`), as in tla/DSM_OfflineFinality.tla. `code` sets each to
  what the code does, and `both_or_neither` holds for it. Each rule flipped
  alone reaches a state that breaks both-or-neither, and each such state is
  exhibited below as a concrete behaviour:

    framesAfterDurable       false: the confirm leaves before confirmPending is
                             written, the proposer restarts, and — still
                             prepared — cancels; the receiver commits.
    cancelOnlyBeforeConfirm  false: the proposer cancels after its confirm.
    linkLossFailsNothing     false: losing the link fails every step in
                             flight (the removed disconnect handler).

  Scope. One step. A device's state for the step is its durable phase, since
  every transition is written before the frame it owes leaves; a restart
  therefore loses only frames in the air. A frame is modelled as in the air or
  not, and taking one may leave a copy in the air (`keep`), so any number of
  deliveries of it is covered: every handler answers from the durable phase.
  Interactions between steps — one step at a time at both doors, proposals
  that cross, the relationship's tripwire — and liveness are model-checked in
  tla/DSM_OfflineFinality.tla. A device whose head moves through another
  relationship between its confirm and its commit cannot commit (its receipt
  names its whole device root); that is recorded open in
  specs/requirements/CONFORMANCE_GAPS.md §6.28 and is outside this model.
-/

namespace DSMOfflineFinality

/-- The proposer's durable phase for the step. `cancelled`: it signed the
    step's cancellation, which it keeps as its answer. `ended`: the receiver's
    signed rejection ended it. `failed`: ended with no signed end — only the
    removed disconnect handler did this. -/
inductive PPhase where
  | prepared
  | confirmPending
  | cancelled
  | ended
  | committed
  | failed
  deriving DecidableEq, Repr

/-- The receiver's durable phase for the step. `refused`: it signed a
    rejection (its user's, or its door's), which answers the proposal
    delivered again. `ended`: the proposer's signed cancellation ended it. -/
inductive RPhase where
  | none
  | pendingUser
  | accepted
  | refused
  | ended
  | committed
  | failed
  deriving DecidableEq, Repr

/-- The step's frames in the air, by kind. -/
structure Air where
  prepare : Bool
  response : Bool
  reject : Bool
  cancel : Bool
  confirm : Bool
  ack : Bool
  deriving DecidableEq, Repr

def Air.empty : Air := ⟨false, false, false, false, false, false⟩

structure S where
  p : PPhase
  r : RPhase
  air : Air
  link : Bool
  deriving DecidableEq, Repr

/-- The step proposed: the proposal is durable and its prepare is out. -/
def init : S :=
  { p := .prepared, r := .none, air := { Air.empty with prepare := true }, link := true }

/-- The code's rules, as switches. -/
structure Rules where
  framesAfterDurable : Bool
  cancelOnlyBeforeConfirm : Bool
  linkLossFailsNothing : Bool

def code : Rules := ⟨true, true, true⟩

/-- A frame leaves only while the devices are linked. -/
def emit (link b : Bool) : Bool := link || b

def PPhase.inFlight : PPhase → Bool
  | .prepared | .confirmPending => true
  | _ => false

def RPhase.inFlight : RPhase → Bool
  | .pendingUser | .accepted => true
  | _ => false

/-- One transition of the step. Every `recv*` takes a frame from the air while
    linked and may leave a copy of it there (`keep`). -/
inductive Next (cfg : Rules) : S → S → Prop
  -- The receiver's door: a proposal it does not hold is held for its user,
  -- or refused with a signed rejection (another step in flight, or a stale
  -- tip).
  | recvPrepareHold (s : S) (keep : Bool) :
      s.link = true → s.air.prepare = true → s.r = .none →
      Next cfg s { s with r := .pendingUser, air := { s.air with prepare := keep } }
  | recvPrepareRefuse (s : S) (keep : Bool) :
      s.link = true → s.air.prepare = true → s.r = .none →
      Next cfg s { s with r := .refused, air := { s.air with prepare := keep, reject := true } }
  -- A proposal it holds is answered from its phase.
  | recvPrepareAnswerAccepted (s : S) (keep : Bool) :
      s.link = true → s.air.prepare = true → s.r = .accepted →
      Next cfg s { s with air := { s.air with prepare := keep, response := true } }
  | recvPrepareAnswerRefused (s : S) (keep : Bool) :
      s.link = true → s.air.prepare = true → s.r = .refused →
      Next cfg s { s with air := { s.air with prepare := keep, reject := true } }
  | recvPrepareNoAnswer (s : S) (keep : Bool) :
      s.link = true → s.air.prepare = true →
      s.r = .pendingUser ∨ s.r = .ended ∨ s.r = .committed ∨ s.r = .failed →
      Next cfg s { s with air := { s.air with prepare := keep } }
  -- The receiver's user decides.
  | userAccept (s : S) :
      s.r = .pendingUser →
      Next cfg s { s with r := .accepted,
                          air := { s.air with response := emit s.link s.air.response } }
  | userReject (s : S) :
      s.r = .pendingUser →
      Next cfg s { s with r := .refused,
                          air := { s.air with reject := emit s.link s.air.reject } }
  -- The proposer takes the response: from prepared it confirms, and
  -- confirmPending is durable before the confirm leaves.
  | recvResponseConfirm (s : S) (keep : Bool) :
      s.link = true → s.air.response = true → s.p = .prepared →
      Next cfg s { s with p := .confirmPending,
                          air := { s.air with response := keep, confirm := true } }
  | recvResponseFrameFirst (s : S) (keep : Bool) :
      cfg.framesAfterDurable = false →
      s.link = true → s.air.response = true → s.p = .prepared →
      Next cfg s { s with air := { s.air with response := keep, confirm := true } }
  | recvResponseAnswerConfirm (s : S) (keep : Bool) :
      s.link = true → s.air.response = true → s.p = .confirmPending →
      Next cfg s { s with air := { s.air with response := keep, confirm := true } }
  | recvResponseAnswerCancel (s : S) (keep : Bool) :
      s.link = true → s.air.response = true → s.p = .cancelled →
      Next cfg s { s with air := { s.air with response := keep, cancel := true } }
  | recvResponseNoAnswer (s : S) (keep : Bool) :
      s.link = true → s.air.response = true →
      s.p = .ended ∨ s.p = .committed ∨ s.p = .failed →
      Next cfg s { s with air := { s.air with response := keep } }
  -- The receiver's signed rejection ends only a proposal not yet confirmed.
  | recvRejectEnds (s : S) (keep : Bool) :
      s.link = true → s.air.reject = true → s.p = .prepared →
      Next cfg s { s with p := .ended, air := { s.air with reject := keep } }
  | recvRejectIgnored (s : S) (keep : Bool) :
      s.link = true → s.air.reject = true → s.p ≠ .prepared →
      Next cfg s { s with air := { s.air with reject := keep } }
  -- The proposer cancels a proposal it has not confirmed.
  | cancel (s : S) :
      s.p = .prepared →
      Next cfg s { s with p := .cancelled, air := { s.air with cancel := emit s.link s.air.cancel } }
  | cancelAfterConfirm (s : S) :
      cfg.cancelOnlyBeforeConfirm = false → s.p = .confirmPending →
      Next cfg s { s with p := .cancelled, air := { s.air with cancel := emit s.link s.air.cancel } }
  -- The proposer's signed cancellation ends a step the receiver holds and
  -- has not committed.
  | recvCancelEndsHeld (s : S) (keep : Bool) :
      s.link = true → s.air.cancel = true → s.r = .pendingUser →
      Next cfg s { s with r := .ended, air := { s.air with cancel := keep } }
  | recvCancelEndsAccepted (s : S) (keep : Bool) :
      s.link = true → s.air.cancel = true → s.r = .accepted →
      Next cfg s { s with r := .ended, air := { s.air with cancel := keep } }
  | recvCancelIgnored (s : S) (keep : Bool) :
      s.link = true → s.air.cancel = true → s.r ≠ .pendingUser → s.r ≠ .accepted →
      Next cfg s { s with air := { s.air with cancel := keep } }
  -- The receiver takes the confirm: it commits in one transaction and only
  -- then answers with its ack; its tripwire may refuse the commit. A
  -- committed step answers the confirm again with its ack.
  | recvConfirmCommit (s : S) (keep : Bool) :
      s.link = true → s.air.confirm = true → s.r = .accepted →
      Next cfg s { s with r := .committed, air := { s.air with confirm := keep, ack := true } }
  | recvConfirmRefused (s : S) (keep : Bool) :
      s.link = true → s.air.confirm = true → s.r = .accepted →
      Next cfg s { s with air := { s.air with confirm := keep } }
  | recvConfirmAnswerAck (s : S) (keep : Bool) :
      s.link = true → s.air.confirm = true → s.r = .committed →
      Next cfg s { s with air := { s.air with confirm := keep, ack := true } }
  | recvConfirmNoAnswer (s : S) (keep : Bool) :
      s.link = true → s.air.confirm = true → s.r ≠ .accepted → s.r ≠ .committed →
      Next cfg s { s with air := { s.air with confirm := keep } }
  -- The proposer takes the ack: it commits the step its confirm was signed
  -- from; an ack that does not hold against its heads commits nothing.
  | recvAckCommit (s : S) (keep : Bool) :
      s.link = true → s.air.ack = true → s.p = .confirmPending →
      Next cfg s { s with p := .committed, air := { s.air with ack := keep } }
  | recvAckRefused (s : S) (keep : Bool) :
      s.link = true → s.air.ack = true →
      Next cfg s { s with air := { s.air with ack := keep } }
  -- While linked, each device delivers what its phase owes.
  | resendPrepare (s : S) :
      s.link = true → s.p = .prepared →
      Next cfg s { s with air := { s.air with prepare := true } }
  | resendResponse (s : S) :
      s.link = true → s.r = .accepted →
      Next cfg s { s with air := { s.air with response := true } }
  | resendConfirm (s : S) :
      s.link = true → s.p = .confirmPending →
      Next cfg s { s with air := { s.air with confirm := true } }
  -- The link drops (losing the frames in the air) and returns; a restart
  -- loses the frames in the air and nothing durable.
  | linkDown (s : S) :
      s.link = true → cfg.linkLossFailsNothing = true →
      Next cfg s { s with link := false, air := Air.empty }
  | linkDownFails (s : S) :
      s.link = true → cfg.linkLossFailsNothing = false →
      Next cfg s { s with link := false, air := Air.empty,
                          p := if s.p.inFlight then .failed else s.p,
                          r := if s.r.inFlight then .failed else s.r }
  | linkUp (s : S) :
      s.link = false →
      Next cfg s { s with link := true }
  | restart (s : S) :
      Next cfg s { s with air := Air.empty }

/-- The states a step reaches under `cfg`'s rules. -/
inductive Reach (cfg : Rules) : S → Prop
  | init : Reach cfg init
  | step {s s' : S} : Reach cfg s → Next cfg s s' → Reach cfg s'

/-- Both-or-neither: the receiver has committed only if the proposer is past
    its confirm, and the proposer has committed only if the receiver has. -/
def BothOrNeither (s : S) : Prop :=
  (s.r = .committed → s.p = .confirmPending ∨ s.p = .committed) ∧
  (s.p = .committed → s.r = .committed)

/-- Both-or-neither and the durable boundary of the two frames that commit. -/
def Inv (s : S) : Prop :=
  BothOrNeither s ∧
  (s.air.confirm = true → s.p = .confirmPending ∨ s.p = .committed) ∧
  (s.air.ack = true → s.r = .committed)

theorem inv_init : Inv init := by
  simp [Inv, BothOrNeither, init, Air.empty]

/-- `Inv` is inductive under the code's rules. -/
theorem inv_step {s s' : S} (h : Inv s) (hn : Next code s s') : Inv s' := by
  obtain ⟨⟨ha, hb⟩, hc, hd⟩ := h
  cases hn <;> simp_all [Inv, BothOrNeither, code, Air.empty]

/-- Every state of the step under the code's rules satisfies both-or-neither:
    whatever is lost, delivered again or late, whoever restarts, and however
    the link comes and goes. -/
theorem both_or_neither {s : S} (h : Reach code s) : BothOrNeither s := by
  have hinv : Inv s := by
    induction h with
    | init => exact inv_init
    | step _ hn ih => exact inv_step ih hn
  exact hinv.1

-- ============================================================
-- Each rule is load-bearing: flipped alone, it reaches a state where one
-- device has committed the step and the other has ended it.
-- ============================================================

/-- The proposal taken, held, accepted, and the response back at the proposer. -/
private def held : S := { init with r := .pendingUser, air := Air.empty }
private def accepted : S := { held with r := .accepted, air := { Air.empty with response := true } }

/-- framesAfterDurable = false: the confirm leaves while the proposer still
    holds prepared (it restarts before writing confirmPending); still
    prepared, it cancels; the receiver commits on the confirm. -/
theorem frame_before_durable_breaks_both_or_neither :
    ∃ s, Reach { code with framesAfterDurable := false } s ∧ ¬ BothOrNeither s := by
  let cfg : Rules := { code with framesAfterDurable := false }
  let s1 : S := held
  let s2 : S := accepted
  let s3 : S := { accepted with air := { Air.empty with confirm := true } }
  let s4 : S := { s3 with p := .cancelled, air := { s3.air with cancel := true } }
  let s5 : S := { s4 with r := .committed, air := { s4.air with confirm := false, ack := true } }
  have r1 : Reach cfg s1 :=
    .step .init (.recvPrepareHold init false rfl rfl rfl)
  have r2 : Reach cfg s2 := .step r1 (.userAccept s1 rfl)
  have r3 : Reach cfg s3 := .step r2 (.recvResponseFrameFirst s2 false rfl rfl rfl rfl)
  have r4 : Reach cfg s4 := .step r3 (.cancel s3 rfl)
  have r5 : Reach cfg s5 := .step r4 (.recvConfirmCommit s4 false rfl rfl rfl)
  exact ⟨s5, r5, by simp [BothOrNeither, s5, s4]⟩

/-- cancelOnlyBeforeConfirm = false: the proposer confirms, then cancels;
    the receiver commits on the confirm. -/
theorem cancel_after_confirm_breaks_both_or_neither :
    ∃ s, Reach { code with cancelOnlyBeforeConfirm := false } s ∧ ¬ BothOrNeither s := by
  let cfg : Rules := { code with cancelOnlyBeforeConfirm := false }
  let s3 : S := { accepted with p := .confirmPending, air := { Air.empty with confirm := true } }
  let s4 : S := { s3 with p := .cancelled, air := { s3.air with cancel := true } }
  let s5 : S := { s4 with r := .committed, air := { s4.air with confirm := false, ack := true } }
  have r1 : Reach cfg held := .step .init (.recvPrepareHold init false rfl rfl rfl)
  have r2 : Reach cfg accepted := .step r1 (.userAccept held rfl)
  have r3 : Reach cfg s3 := .step r2 (.recvResponseConfirm accepted false rfl rfl rfl)
  have r4 : Reach cfg s4 := .step r3 (.cancelAfterConfirm s3 rfl rfl)
  have r5 : Reach cfg s5 := .step r4 (.recvConfirmCommit s4 false rfl rfl rfl)
  exact ⟨s5, r5, by simp [BothOrNeither, s5, s4]⟩

/-- linkLossFailsNothing = false: the receiver commits, its ack is lost with
    the link, and the lost link fails the proposer's confirmed step. -/
theorem link_loss_failing_steps_breaks_both_or_neither :
    ∃ s, Reach { code with linkLossFailsNothing := false } s ∧ ¬ BothOrNeither s := by
  let cfg : Rules := { code with linkLossFailsNothing := false }
  let s3 : S := { accepted with p := .confirmPending, air := { Air.empty with confirm := true } }
  let s4 : S := { s3 with r := .committed, air := { Air.empty with ack := true } }
  let s5 : S := { s4 with link := false, air := Air.empty, p := .failed }
  have r1 : Reach cfg held := .step .init (.recvPrepareHold init false rfl rfl rfl)
  have r2 : Reach cfg accepted := .step r1 (.userAccept held rfl)
  have r3 : Reach cfg s3 := .step r2 (.recvResponseConfirm accepted false rfl rfl rfl)
  have r4 : Reach cfg s4 := .step r3 (.recvConfirmCommit s3 false rfl rfl rfl)
  have r5 : Reach cfg s5 := by
    have := Next.linkDownFails (cfg := cfg) s4 rfl rfl
    simpa [s5, s4, s3, PPhase.inFlight, RPhase.inFlight] using Reach.step r4 this
  exact ⟨s5, r5, by simp [BothOrNeither, s5, s4]⟩

end DSMOfflineFinality
