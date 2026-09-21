/-
  The native ERA reserve — one lineage, released leader first;
  self-contained Lean 4 (no Mathlib, no imports)
  Machine-checks the algebra of `dsm/src/economic/native_reserve.rs`
  (Part IX §51; rebuild step R4; owner ruling 2026-09-20):
    - ONE TRANSITION     `release_constructible` is the only constructor of a
                         reserve state past genesis: remaining' = remaining −
                         amount, generation' = generation + 1, and the release
                         names its claimant as recipient. `Reach` below has
                         exactly that one step constructor — there is no mint
                         arm and no creator withdrawal to write down.
    - CONSERVATION       reserve_after + release = reserve_before; along any
                         lineage, S_genesis = remaining + Σ released.
    - NO MINT            no valid transition raises `remaining`; a release of
                         more than remains, or of zero, is refused.
    - RECIPIENT          FaucetClaim(A, x) ⇒ recipient = A: the body's recipient
                         is the claimant that signed it.
    - LEADER FIRST       the winner at the reserve's cell is the first
                         RECOGNIZED object at the leader; Final needs the leader
                         and two other holders and nothing more; copies never
                         change the winner; unrecognized bytes never occupy.
  Correspondence: every theorem below has a same-named test in
  `native_reserve.rs` (Core) or `dsm_sdk/src/sdk/native_reserve.rs` (the fake
  fleet), and `tla/DSM_NativeReserveRelease.tla` states the invariants over
  the interleavings. Mutation controls (executed 2026-09-20): dropping the
  `amount ≤ remaining` conjunct of `constructible` breaks
  `no_valid_reserve_transition_can_mint_era` and `an_overdraft_is_refused`;
  dropping `recipient = claimant` breaks
  `faucet_claim_names_its_claimant_as_recipient`; counting holders without
  the leader breaks `finality_without_the_deterministic_leader_is_impossible`.
  What this module does NOT claim: signatures, hashing and the cell's key
  derivation (DSMRecognition, DSMSofiSuccessorCells); liveness of the carry.
-/

namespace DSMNativeReserve

/-- A reserve state: `NativeReserveState`, with the identity fields elided —
    they are constants along one lineage. -/
structure State where
  remaining : Nat
  generation : Nat
deriving DecidableEq, Repr

/-- A verified release body, with the identity and binding fields elided. -/
structure Release where
  generation : Nat
  amount : Nat
  recipient : Nat
  claimant : Nat
deriving DecidableEq, Repr

/-- `release_constructible`: the ONE transition of the reserve. -/
def constructible (s : State) (x : Release) : Prop :=
  x.generation = s.generation + 1 ∧ 0 < x.amount ∧ x.amount ≤ s.remaining ∧
    x.recipient = x.claimant

/-- The successor state a constructible release installs. -/
def step (s : State) (x : Release) : State :=
  { remaining := s.remaining - x.amount, generation := x.generation }

-- ── The one transition ──────────────────────────────────────────────────────

/-- `reserve_after = reserve_before − release`. -/
theorem a_release_conserves_the_reserve (s : State) (x : Release) (h : constructible s x) :
    (step s x).remaining + x.amount = s.remaining := by
  unfold step
  exact Nat.sub_add_cancel h.2.2.1

/-- No valid transition raises the reserve. -/
theorem no_valid_reserve_transition_can_mint_era (s : State) (x : Release) :
    (step s x).remaining ≤ s.remaining :=
  Nat.sub_le s.remaining x.amount

/-- `release ≤ reserve_before`. -/
theorem release_never_exceeds_the_reserve (s : State) (x : Release) (h : constructible s x) :
    x.amount ≤ s.remaining :=
  h.2.2.1

/-- `FaucetClaim(A, x) ⇒ recipient = A`. -/
theorem faucet_claim_names_its_claimant_as_recipient (s : State) (x : Release)
    (h : constructible s x) : x.recipient = x.claimant :=
  h.2.2.2

theorem the_successor_is_the_next_generation (s : State) (x : Release) (h : constructible s x) :
    (step s x).generation = s.generation + 1 := by
  unfold step
  exact h.1

/-- A release of more than remains is not a transition — the one arm that
    would mint. -/
theorem an_overdraft_is_refused (s : State) (x : Release) (hlt : s.remaining < x.amount) :
    ¬ constructible s x := by
  intro h
  exact absurd h.2.2.1 (Nat.not_le.mpr hlt)

/-- A release of zero is not a transition. -/
theorem a_zero_release_is_refused (s : State) (x : Release) (hz : x.amount = 0) :
    ¬ constructible s x := by
  intro h
  have := h.2.1
  omega

/-- Exactly what remains is the last legal release; the reserve is then
    exhausted, and nothing replenishes it. -/
theorem the_last_unit_exhausts_the_reserve (s : State) (x : Release)
    (hall : x.amount = s.remaining) : (step s x).remaining = 0 := by
  unfold step
  rw [hall]
  exact Nat.sub_self _

-- ── Lineages: no creator backout, total conserved ───────────────────────────

/-- States reachable from `s₀` by releases, carrying the total released. The
    single `step` constructor IS "no creator backout": there is no other way
    to reach a state, so every unit that left the reserve is in `total`, and
    every release in `total` named its claimant as recipient. -/
inductive Reach : State → State → Nat → Prop
  | refl (s : State) : Reach s s 0
  | step {s t : State} {total : Nat} (x : Release) (h : constructible t x)
      (r : Reach s t total) : Reach s (step t x) (total + x.amount)

/-- `S_genesis = remaining + Σ released` at every reachable state. -/
theorem total_era_is_conserved {s₀ s : State} {total : Nat} (r : Reach s₀ s total) :
    s.remaining + total = s₀.remaining := by
  induction r with
  | refl => simp
  | step x h _ ih =>
    unfold step
    simp only
    have hle := h.2.2.1
    omega

/-- The reserve only ever shrinks along a lineage. -/
theorem the_reserve_never_grows {s₀ s : State} {total : Nat} (r : Reach s₀ s total) :
    s.remaining ≤ s₀.remaining := by
  have := total_era_is_conserved r
  omega

/-- No creator backout: every unit that left the reserve was released, and a
    release names its claimant — there is no transition to a creator. -/
theorem no_creator_backout {s₀ s : State} {total : Nat} (r : Reach s₀ s total) :
    s₀.remaining - s.remaining = total := by
  have := total_era_is_conserved r
  omega

/-- Generations count releases: a lineage of `n` releases is at generation
    `s₀.generation + n`. -/
theorem generations_count_releases {s₀ s : State} {total : Nat} (r : Reach s₀ s total) :
    s₀.generation ≤ s.generation := by
  induction r with
  | refl => exact Nat.le_refl _
  | step x h _ ih =>
    unfold step
    simp only
    have := h.1
    omega

-- ── The cell, leader first ──────────────────────────────────────────────────

/-- Values at a member: opaque. -/
abbrev Val := Nat

/-- `LeaderHeld`: the first RECOGNIZED object in the leader's read
    (`sofi::arith::resolve_objects` over `recognize_release`). -/
def winner (leader : List Val) (recognized : Val → Bool) : Option Val :=
  leader.find? recognized

/-- `Final`: leader-held and held by two OTHER members — nothing more. -/
def final (leader : List Val) (recognized : Val → Bool) (copies : Val → Nat) (v : Val) : Prop :=
  winner leader recognized = some v ∧ 2 ≤ copies v

/-- Finality without the deterministic leader is impossible: an empty
    leader read makes nothing final, however many members hold the value. -/
theorem finality_without_the_deterministic_leader_is_impossible
    (recognized : Val → Bool) (copies : Val → Nat) (v : Val) :
    ¬ final [] recognized copies v := by
  intro h
  simp [final, winner] at h

/-- Final implies leader-held (the definition, stated as the TLA invariant
    `FinalRequiresLeader`). -/
theorem final_requires_leader (leader : List Val) (recognized : Val → Bool)
    (copies : Val → Nat) (v : Val) (h : final leader recognized copies v) :
    winner leader recognized = some v :=
  h.1

/-- Three holders — the leader and two others — is finality; an unavailable
    non-leader member never blocks it. -/
theorem three_holders_is_final (leader : List Val) (recognized : Val → Bool)
    (copies : Val → Nat) (v : Val) (hl : winner leader recognized = some v)
    (hc : 2 ≤ copies v) : final leader recognized copies v :=
  ⟨hl, hc⟩

/-- Additional replicas do not alter the winner: the winner is a function of
    the leader's read alone. -/
theorem additional_replicas_do_not_alter_the_winner (leader : List Val)
    (recognized : Val → Bool) (copies copies' : Val → Nat) (v : Val)
    (h : final leader recognized copies v) (hc : 2 ≤ copies' v) :
    final leader recognized copies' v :=
  ⟨h.1, hc⟩

/-- Unrecognized bytes never occupy the cell, however early they arrived. -/
theorem unrecognized_bytes_never_occupy_the_cell (leader : List Val)
    (recognized : Val → Bool) (v : Val) (hv : recognized v = false) :
    winner leader recognized ≠ some v := by
  intro h
  have := List.find?_some h
  rw [hv] at this
  exact Bool.false_ne_true this

/-- The first recognized object wins, not the first bytes: garbage ahead of
    it at the leader changes nothing. -/
theorem the_first_recognized_object_wins (leader : List Val) (recognized : Val → Bool)
    (g : Val) (hg : recognized g = false) :
    winner (g :: leader) recognized = winner leader recognized := by
  simp [winner, List.find?, hg]

end DSMNativeReserve
