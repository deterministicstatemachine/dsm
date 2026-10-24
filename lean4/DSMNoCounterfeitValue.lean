/-
  DSM No Counterfeit Value — self-contained Lean 4 (no Mathlib)

  The economic-layer counterpart of the Tripwire. DSMGuardedTripwire.lean and
  DSMOfflineAnchorOrigin.lean prove that a value cannot be spent twice. This
  module proves the other half: value cannot be made. Every unit an honest
  device accepts, online or offline, is a unit of the genesis supply.

  The paper's statement (concise specification, §8, Theorem 4, Global Supply
  Conservation): the debits and credits of every bilateral transaction sum to
  zero, so the total supply is preserved without global synchronization. It
  is stated there as a sketch. Here it is a theorem over every reachable state,
  with the offline tier included.

  The model. A device's software can claim anything about itself; such claims
  are `forged` value and are not checked here. What an honest device ACCEPTS is
  fixed by DSM's acceptance rules, one action each:
    - release      a unit leaves the reserve to a device (a faucet claim)
    - debit        an online transfer out, within the validated balance
    - credit       an online credit, only from a recorded debit naming this
                   device, consumed once (the receiver's walk to the source)
    - load         the online balance moves into the offline account
    - unload       the offline account moves back to the online balance
    - offSpend     an offline transfer, drawn from the offline account only
                   (the account a receiver validated online, stepped by its
                   counter chain)
    - offReceive   an offline receipt, recorded as pending
    - reconcile    a pending receipt becomes balance once it is validated online
    - forge        a device's own unchecked claim; it moves nothing accepted

  Proved:
    - `conserved_on_every_reachable_state`: the reserve, every balance, every
      offline account, every pending receipt and every transfer in flight sum to
      the genesis supply, in every state the accepted actions reach.
    - `honest_holdings_never_exceed_genesis`: no total of accepted holdings
      exceeds the genesis supply. Forged claims never enter them.
    - `device_balance_never_exceeds_genesis`: nor does any one device's.
    - `forged_value_is_never_accepted`: a forge leaves every accepted quantity as
      it was.
    - `respending_offline_receipts_offline_admits_counterfeit`: necessity. If an
      offline receipt could be re-spent offline before it is validated online,
      a two-step history leaves an honest receiver holding value the reserve
      never released: the accepted total exceeds the genesis supply.
    - `offline_payment_reachable`: non-vacuity. A history with a load, an
      offline payment, its receipt and its online reconciliation is reachable.

  Run: `lean DSMNoCounterfeitValue.lean`.
-/

namespace DSMNoCounterfeitValue

/-! ## Sums over devices and over transfers in flight -/

/-- The sum of `f` over the devices `0, …, n-1`. -/
def total (f : Nat → Nat) : Nat → Nat
  | 0 => 0
  | n + 1 => total f n + f n

/-- `f` with device `d` set to `v`. -/
def upd (f : Nat → Nat) (d v : Nat) : Nat → Nat :=
  fun x => if x = d then v else f x

theorem total_upd_of_ge (f : Nat → Nat) (d v : Nat) :
    ∀ n, n ≤ d → total (upd f d v) n = total f n := by
  intro n
  induction n with
  | zero => intro _; rfl
  | succ k ih =>
    intro h
    have hk : k ≤ d := Nat.le_of_succ_le h
    have hne : k ≠ d := Nat.ne_of_lt (Nat.lt_of_succ_le h)
    simp [total, upd, ih hk, hne]

/-- Setting device `d < n` to `v` changes the total by exactly `f d ↦ v`. -/
theorem total_upd (f : Nat → Nat) (d v : Nat) :
    ∀ n, d < n → total (upd f d v) n + f d = total f n + v := by
  intro n
  induction n with
  | zero => intro h; exact absurd h (Nat.not_lt_zero d)
  | succ k ih =>
    intro h
    by_cases hd : d = k
    · subst hd
      have hsame := total_upd_of_ge f d v d (Nat.le_refl d)
      have hv : upd f d v d = v := by simp [upd]
      show total (upd f d v) d + upd f d v d + f d = total f d + f d + v
      rw [hsame, hv]
      omega
    · have hlt : d < k := Nat.lt_of_le_of_ne (Nat.le_of_lt_succ h) hd
      have hne : k ≠ d := fun e => hd e.symm
      have ihk := ih hlt
      have hv : upd f d v k = f k := by simp [upd, hne]
      show total (upd f d v) k + upd f d v k + f d = total f k + f k + v
      rw [hv]
      omega

/-- One transfer in flight: from `src` to `dst`, `amt` units. -/
structure Flow where
  src : Nat
  dst : Nat
  amt : Nat
deriving DecidableEq, Repr

/-- The units in flight on a list of transfers. -/
def flowing : List Flow → Nat
  | [] => 0
  | f :: rest => f.amt + flowing rest

theorem flowing_append (l₁ l₂ : List Flow) :
    flowing (l₁ ++ l₂) = flowing l₁ + flowing l₂ := by
  induction l₁ with
  | nil => simp [flowing]
  | cons f rest ih => simp [flowing, ih]; omega

theorem flowing_mid (l₁ l₂ : List Flow) (f : Flow) :
    flowing (l₁ ++ f :: l₂) = flowing (l₁ ++ l₂) + f.amt := by
  rw [flowing_append, flowing_append]
  simp [flowing]
  omega

/-! ## The state an honest verifier accepts -/

/-- Everything accepted, per device (devices `0, …, n-1`), plus what each
    device's own software claims beyond it. -/
structure St where
  /-- Devices on the network. -/
  n : Nat
  /-- Units still in the native reserve. -/
  reserve : Nat
  /-- Validated online balance. -/
  bal : Nat → Nat
  /-- Offline account, loaded online. -/
  alloc : Nat → Nat
  /-- Offline receipts awaiting online validation. -/
  pend : Nat → Nat
  /-- Online debits whose credit is not yet taken. -/
  inflight : List Flow
  /-- Offline spends whose receipt is not yet taken. -/
  offflight : List Flow
  /-- A device's own unchecked claims. Never accepted by anyone. -/
  forged : Nat → Nat

/-- All accepted value. -/
def accepted (s : St) : Nat :=
  s.reserve + total s.bal s.n + total s.alloc s.n + total s.pend s.n
    + flowing s.inflight + flowing s.offflight

/-- The accepted actions, and the one action a device can take that nobody
    accepts (`forge`). -/
inductive Step : St → St → Prop where
  | release (s : St) (d a : Nat) (hd : d < s.n) (ha : a ≤ s.reserve) :
      Step s { s with reserve := s.reserve - a, bal := upd s.bal d (s.bal d + a) }
  | debit (s : St) (src dst a : Nat) (hs : src < s.n) (ha : a ≤ s.bal src) :
      Step s { s with bal := upd s.bal src (s.bal src - a),
                      inflight := ⟨src, dst, a⟩ :: s.inflight }
  | credit (s : St) (l₁ l₂ : List Flow) (f : Flow)
      (hl : s.inflight = l₁ ++ f :: l₂) (hd : f.dst < s.n) :
      Step s { s with inflight := l₁ ++ l₂,
                      bal := upd s.bal f.dst (s.bal f.dst + f.amt) }
  | load (s : St) (d a : Nat) (hd : d < s.n) (ha : a ≤ s.bal d) :
      Step s { s with bal := upd s.bal d (s.bal d - a),
                      alloc := upd s.alloc d (s.alloc d + a) }
  | unload (s : St) (d a : Nat) (hd : d < s.n) (ha : a ≤ s.alloc d) :
      Step s { s with alloc := upd s.alloc d (s.alloc d - a),
                      bal := upd s.bal d (s.bal d + a) }
  | offSpend (s : St) (src dst a : Nat) (hs : src < s.n) (ha : a ≤ s.alloc src) :
      Step s { s with alloc := upd s.alloc src (s.alloc src - a),
                      offflight := ⟨src, dst, a⟩ :: s.offflight }
  | offReceive (s : St) (l₁ l₂ : List Flow) (f : Flow)
      (hl : s.offflight = l₁ ++ f :: l₂) (hd : f.dst < s.n) :
      Step s { s with offflight := l₁ ++ l₂,
                      pend := upd s.pend f.dst (s.pend f.dst + f.amt) }
  | reconcile (s : St) (d a : Nat) (hd : d < s.n) (ha : a ≤ s.pend d) :
      Step s { s with pend := upd s.pend d (s.pend d - a),
                      bal := upd s.bal d (s.bal d + a) }
  | forge (s : St) (d a : Nat) :
      Step s { s with forged := upd s.forged d (s.forged d + a) }

/-- A genesis state: the whole supply in the reserve, nothing else anywhere. -/
def genesis (n supply : Nat) : St :=
  { n := n, reserve := supply, bal := fun _ => 0, alloc := fun _ => 0,
    pend := fun _ => 0, inflight := [], offflight := [], forged := fun _ => 0 }

/-- States reachable from a genesis by any sequence of steps. -/
inductive Reach (n supply : Nat) : St → Prop where
  | init : Reach n supply (genesis n supply)
  | step {s t : St} : Reach n supply s → Step s t → Reach n supply t

/-! ## Conservation -/

theorem total_zero (n : Nat) : total (fun _ => 0) n = 0 := by
  induction n with
  | zero => rfl
  | succ k ih => simp [total, ih]

theorem accepted_genesis (n supply : Nat) : accepted (genesis n supply) = supply := by
  simp [accepted, genesis, total_zero, flowing]

/-- Every accepted action keeps the accepted total; a forge does too. -/
theorem step_conserves {s t : St} (h : Step s t) : accepted t = accepted s := by
  cases h with
  | release d a hd ha =>
    have := total_upd s.bal d (s.bal d + a) s.n hd
    simp only [accepted]; omega
  | debit src dst a hs ha =>
    have := total_upd s.bal src (s.bal src - a) s.n hs
    simp only [accepted, flowing]; omega
  | credit l₁ l₂ f hl hd =>
    have hb := total_upd s.bal f.dst (s.bal f.dst + f.amt) s.n hd
    have hf := flowing_mid l₁ l₂ f
    simp only [accepted, hl]; omega
  | load d a hd ha =>
    have hb := total_upd s.bal d (s.bal d - a) s.n hd
    have ha' := total_upd s.alloc d (s.alloc d + a) s.n hd
    simp only [accepted]; omega
  | unload d a hd ha =>
    have hb := total_upd s.bal d (s.bal d + a) s.n hd
    have ha' := total_upd s.alloc d (s.alloc d - a) s.n hd
    simp only [accepted]; omega
  | offSpend src dst a hs ha =>
    have := total_upd s.alloc src (s.alloc src - a) s.n hs
    simp only [accepted, flowing]; omega
  | offReceive l₁ l₂ f hl hd =>
    have hp := total_upd s.pend f.dst (s.pend f.dst + f.amt) s.n hd
    have hf := flowing_mid l₁ l₂ f
    simp only [accepted, hl]; omega
  | reconcile d a hd ha =>
    have hp := total_upd s.pend d (s.pend d - a) s.n hd
    have hb := total_upd s.bal d (s.bal d + a) s.n hd
    simp only [accepted]; omega
  | forge d a =>
    simp only [accepted]

/-- In every reachable state, all accepted value is exactly the genesis supply. -/
theorem conserved_on_every_reachable_state {n supply : Nat} {s : St}
    (h : Reach n supply s) : accepted s = supply := by
  induction h with
  | init => exact accepted_genesis n supply
  | step _ hstep ih => rw [step_conserves hstep, ih]

/-- The network size never changes, so "every device" means the same devices. -/
theorem step_keeps_n {s t : St} (h : Step s t) : t.n = s.n := by
  cases h <;> rfl

theorem reach_n {n supply : Nat} {s : St} (h : Reach n supply s) : s.n = n := by
  induction h with
  | init => rfl
  | step _ hstep ih => rw [step_keeps_n hstep, ih]

/-- No total of accepted holdings — balances, offline accounts and pending
    receipts — ever exceeds the genesis supply. -/
theorem honest_holdings_never_exceed_genesis {n supply : Nat} {s : St}
    (h : Reach n supply s) :
    total s.bal s.n + total s.alloc s.n + total s.pend s.n ≤ supply := by
  have := conserved_on_every_reachable_state h
  simp only [accepted] at this
  omega

theorem le_total (f : Nat → Nat) (d : Nat) : ∀ n, d < n → f d ≤ total f n := by
  intro n
  induction n with
  | zero => intro h; exact absurd h (Nat.not_lt_zero d)
  | succ k ih =>
    intro h
    by_cases hd : d = k
    · subst hd; simp [total]
    · have := ih (Nat.lt_of_le_of_ne (Nat.le_of_lt_succ h) hd)
      simp [total]; omega

/-- Any one device's accepted balance is at most the genesis supply. -/
theorem device_balance_never_exceeds_genesis {n supply : Nat} {s : St}
    (h : Reach n supply s) (d : Nat) (hd : d < n) : s.bal d ≤ supply := by
  have hn := reach_n h
  have hb := le_total s.bal d s.n (by rw [hn]; exact hd)
  have := honest_holdings_never_exceed_genesis h
  omega

/-- A forge changes nothing anybody accepts. -/
theorem forged_value_is_never_accepted (s : St) (d a : Nat) :
    let t := { s with forged := upd s.forged d (s.forged d + a) }
    t.bal = s.bal ∧ t.alloc = s.alloc ∧ t.pend = s.pend ∧
      t.inflight = s.inflight ∧ t.offflight = s.offflight ∧ t.reserve = s.reserve := by
  simp

/-! ## Necessity: offline receipts must not be re-spent offline before validation

    The unsafe rule a receiver could be tempted to accept: an offline spend
    drawn from what the payer received offline, which the receiver cannot
    validate offline (it comes from a third party the receiver never saw
    online). The payer's software can claim such receipts freely — they are
    forged — so the rule lets forged value reach an honest receiver. -/

/-- The accepted actions, with one more: an offline spend drawn from the
    payer's own claimed offline receipts. -/
inductive UnsafeStep : St → St → Prop where
  | safe {s t : St} : Step s t → UnsafeStep s t
  | spendClaimedReceipt (s : St) (src dst a : Nat) (hs : src < s.n)
      (ha : a ≤ s.forged src) :
      UnsafeStep s { s with forged := upd s.forged src (s.forged src - a),
                            offflight := ⟨src, dst, a⟩ :: s.offflight }

inductive UnsafeReach (n supply : Nat) : St → Prop where
  | init : UnsafeReach n supply (genesis n supply)
  | step {s t : St} : UnsafeReach n supply s → UnsafeStep s t → UnsafeReach n supply t

/-- Bob (device 0) claims an offline receipt of 5 he never got, from someone
    Alice (device 1) never saw online; Bob spends it to Alice offline; Alice
    takes the receipt. The reserve released nothing, yet Alice holds 5 pending:
    accepted value exceeds the genesis supply of 0. -/
theorem respending_offline_receipts_offline_admits_counterfeit :
    ∃ s : St, UnsafeReach 2 0 s ∧ accepted s > 0 := by
  let g := genesis 2 0
  let s1 : St := { g with forged := upd g.forged 0 (g.forged 0 + 5) }
  let s2 : St := { s1 with forged := upd s1.forged 0 (s1.forged 0 - 5),
                           offflight := ⟨0, 1, 5⟩ :: s1.offflight }
  let s3 : St := { s2 with offflight := [] ++ [],
                           pend := upd s2.pend 1 (s2.pend 1 + 5) }
  have r1 : UnsafeReach 2 0 s1 :=
    UnsafeReach.step UnsafeReach.init (UnsafeStep.safe (Step.forge g 0 5))
  have r2 : UnsafeReach 2 0 s2 :=
    UnsafeReach.step r1
      (UnsafeStep.spendClaimedReceipt s1 0 1 5 (by decide) (by simp [s1, g, upd, genesis]))
  have r3 : UnsafeReach 2 0 s3 :=
    UnsafeReach.step r2
      (UnsafeStep.safe (Step.offReceive s2 [] [] ⟨0, 1, 5⟩ (by simp [s2, s1, g, genesis]) (by decide)))
  refine ⟨s3, r3, ?_⟩
  simp [s3, s2, s1, g, accepted, genesis, total, upd, flowing]

/-! ## Non-vacuity -/

/-- A history with every offline action is reachable: the reserve releases 10
    to Bob (device 0); Bob loads 10 offline; Bob pays Alice (device 1) 4
    offline; Alice receives it pending and reconciles it online. Alice holds 4,
    Bob 6 offline, and the total is the genesis supply. -/
theorem offline_payment_reachable :
    ∃ s : St, Reach 2 10 s ∧ s.bal 1 = 4 ∧ s.alloc 0 = 6 ∧ accepted s = 10 := by
  let g := genesis 2 10
  let s1 : St := { g with reserve := g.reserve - 10, bal := upd g.bal 0 (g.bal 0 + 10) }
  let s2 : St := { s1 with bal := upd s1.bal 0 (s1.bal 0 - 10),
                           alloc := upd s1.alloc 0 (s1.alloc 0 + 10) }
  let s3 : St := { s2 with alloc := upd s2.alloc 0 (s2.alloc 0 - 4),
                           offflight := ⟨0, 1, 4⟩ :: s2.offflight }
  let s4 : St := { s3 with offflight := [] ++ [],
                           pend := upd s3.pend 1 (s3.pend 1 + 4) }
  let s5 : St := { s4 with pend := upd s4.pend 1 (s4.pend 1 - 4),
                           bal := upd s4.bal 1 (s4.bal 1 + 4) }
  have r1 : Reach 2 10 s1 :=
    Reach.step Reach.init (Step.release g 0 10 (by decide) (by simp [g, genesis]))
  have r2 : Reach 2 10 s2 :=
    Reach.step r1 (Step.load s1 0 10 (by decide) (by simp [s1, g, upd, genesis]))
  have r3 : Reach 2 10 s3 :=
    Reach.step r2 (Step.offSpend s2 0 1 4 (by decide) (by simp [s2, s1, g, upd, genesis]))
  have r4 : Reach 2 10 s4 :=
    Reach.step r3 (Step.offReceive s3 [] [] ⟨0, 1, 4⟩ (by simp [s3, s2, s1, g, genesis]) (by decide))
  have r5 : Reach 2 10 s5 :=
    Reach.step r4 (Step.reconcile s4 1 4 (by decide) (by simp [s4, s3, s2, s1, g, upd, genesis]))
  refine ⟨s5, r5, ?_, ?_, ?_⟩
  · simp [s5, s4, s3, s2, s1, g, upd, genesis]
  · simp [s5, s4, s3, s2, s1, g, upd, genesis]
  · exact conserved_on_every_reachable_state r5

end DSMNoCounterfeitValue
