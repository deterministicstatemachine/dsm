-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomOracle

/- ROM role games for the primitive roles the EUF-CMA reduction's events
   stand on. Each is a statement about an arbitrary query tree (adversary and
   challenger together) answered by the lazily sampled random oracle of
   `RomOracle`, with an explicit query budget.

   * Tweak collision (the thash role, SM-TCR-like): an adversary-side keyed
     request collides, in its n-byte answer, with the challenger's request
     under the same key and the same 32-byte address but a different input.
     If the challenger never draws two different requests at one (key,
     address) (tweak single use), the probability is at most q_adv / 256^n.
   * Secret guessing (PRF/KDF keys, PRF_msg key, master seed, hidden chain
     values): a uniformly random secret independent of the run is named by
     one of the adversary's q_adv guesses with probability at most q_adv / K.
   These are idealized-model statements, not properties of BLAKE3. -/
namespace DSM.Rom
open DSM.Sphincs

/-! Counting pairs. -/

theorem sum_append' (l1 l2 : List Nat) : (l1 ++ l2).sum = l1.sum + l2.sum := by
  induction l1 with
  | nil => simp
  | cons a l ih => simp only [List.cons_append, List.sum_cons, ih]; omega

theorem range_succ_sum (L : Nat) (f : Nat → Nat) :
    ((List.range (L+1)).map f).sum = ((List.range L).map f).sum + f L := by
  rw [List.range_succ, List.map_append, sum_append']; simp

/-- Unordered pairs `i < j`, each charged to both orientations, are at most
    all ordered pairs. -/
theorem pairs_le_square (f : Nat → Nat → Nat) : ∀ L : Nat,
    ((List.range L).map (fun j => ((List.range j).map (fun i => f i j + f j i)).sum)).sum ≤
      ((List.range L).map (fun a => ((List.range L).map (fun c => f a c)).sum)).sum
  | 0 => by simp
  | L+1 => by
    rw [range_succ_sum]
    have ih := pairs_le_square f L
    have grow : ((List.range (L+1)).map (fun a => ((List.range (L+1)).map (fun c => f a c)).sum)).sum =
        ((List.range L).map (fun a => ((List.range L).map (fun c => f a c)).sum)).sum +
        ((List.range L).map (fun a => f a L)).sum + ((List.range L).map (fun c => f L c)).sum + f L L := by
      rw [range_succ_sum]
      have : ∀ a, ((List.range (L+1)).map (fun c => f a c)).sum =
          ((List.range L).map (fun c => f a c)).sum + f a L := fun a => range_succ_sum L _
      simp only [this, sum_map_add]
      omega
    have hsplit := sum_map_add (List.range L) (fun i => f i L) (fun i => f L i)
    rw [grow]
    omega

/-- The same-tweak partner relation at output length `n`: one adversary-side
    and one challenger keyed request, same key, same 32-byte address prefix,
    different inputs, both with `n`-byte answers. -/
def tweakPartner (n : Nat) (x y : Draw) : Bool :=
  x.1 != y.1 && x.2.mode == 1 && y.2.mode == 1 && x.2.key == y.2.key &&
  x.2.outLen == n && y.2.outLen == n &&
  x.2.input.take 32 == y.2.input.take 32 && x.2.input != y.2.input

theorem tweakPartner_symm (n : Nat) (x y : Draw) : tweakPartner n x y = tweakPartner n y x := by
  unfold tweakPartner
  apply Bool.eq_iff_iff.mpr
  simp only [Bool.and_eq_true, bne_iff_ne, beq_iff_eq, ne_eq]
  constructor <;> rintro ⟨⟨⟨⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩, h6⟩, h7⟩, h8⟩ <;>
    exact ⟨⟨⟨⟨⟨⟨⟨fun e => h1 e.symm, h3⟩, h2⟩, h4.symm⟩, h6⟩, h5⟩, h7.symm⟩, fun e => h8 e.symm⟩

theorem partner_facts {n : Nat} {x y : Draw} (h : tweakPartner n x y = true) :
    x.1 ≠ y.1 ∧ y.2.mode = 1 ∧ x.2.key = y.2.key ∧ x.2.input.take 32 = y.2.input.take 32 := by
  unfold tweakPartner at h
  simp only [Bool.and_eq_true, bne_iff_ne, ne_eq, beq_iff_eq] at h
  obtain ⟨⟨⟨⟨⟨⟨⟨h1, _⟩, h3⟩, h4⟩, _⟩, _⟩, h7⟩, _⟩ := h
  exact ⟨h1, h3, h4, h7⟩

/-- Tweak single use of the challenger's draws: two challenger keyed draws
    under the same key and address are the same draw (the honest computation
    hashes one canonical input per address). -/
def ChallengerSingleUse (D : List Draw) : Prop :=
  ∀ a c, a < D.length → c < D.length →
    (D.getD a noDraw).1 = false → (D.getD c noDraw).1 = false →
    (D.getD a noDraw).2.mode = 1 → (D.getD c noDraw).2.mode = 1 →
    (D.getD a noDraw).2.key = (D.getD c noDraw).2.key →
    (D.getD a noDraw).2.input.take 32 = (D.getD c noDraw).2.input.take 32 → a = c

/-- The number of adversary-side fresh draws. -/
def advCount (D : List Draw) : Nat :=
  ((List.range D.length).map (fun a => if (D.getD a noDraw).1 then 1 else 0)).sum

theorem len_le_one_of_eq : ∀ (l : List Nat), l.Nodup → (∀ x ∈ l, ∀ y ∈ l, x = y) → l.length ≤ 1
  | [], _, _ => by simp
  | [_], _, _ => by simp
  | x :: y :: _, nd, h => absurd (h x (by simp) y (by simp))
      (fun e => (List.nodup_cons.mp nd).1 (by rw [e]; simp))

/-- With challenger single use, the same-tweak partnered pairs among the
    draws are at most the adversary-side draws. -/
theorem pairs_le_adv (n : Nat) (D : List Draw) (single : ChallengerSingleUse D) :
    ((List.range D.length).map (fun j => (pairsList (tweakPartner n) D j).length)).sum ≤ advCount D := by
  let L := D.length
  let P : Nat → Nat → Bool := fun i j => tweakPartner n (D.getD i noDraw) (D.getD j noDraw)
  let adv : Nat → Nat := fun a => if (D.getD a noDraw).1 then 1 else 0
  let f : Nat → Nat → Nat := fun a c => adv a * (if P a c then 1 else 0)
  have step1 : ∀ j, j < L → (pairsList (tweakPartner n) D j).length ≤
      ((List.range j).map (fun i => f i j + f j i)).sum := by
    intro j hj
    have hj' : j < D.length := hj
    rw [pairsList, if_pos hj', len_filter_eq_sum]
    apply sum_map_le
    intro i _
    simp only [f, adv, P]
    by_cases h : tweakPartner n (D.getD i noDraw) (D.getD j noDraw) = true
    · have hs : tweakPartner n (D.getD j noDraw) (D.getD i noDraw) = true := by
        rw [tweakPartner_symm]; exact h
      have hside := (partner_facts h).1
      rw [if_pos h, if_pos hs]
      cases hi : (D.getD i noDraw).1 <;> cases hj' : (D.getD j noDraw).1 <;> simp_all
    · simp only [h]; simp
  have step2 : ∀ a, a < L → ((List.range L).map (fun c => f a c)).sum ≤ adv a := by
    intro a _
    simp only [f]
    rw [sum_map_mul]
    by_cases hadv : (D.getD a noDraw).1 = true
    · simp only [adv, hadv, if_true, Nat.one_mul]
      rw [← len_filter_eq_sum]
      apply len_le_one_of_eq _ (List.nodup_range.filter _)
      intro c1 hc1 c2 hc2
      have p1 := List.mem_filter.mp hc1
      have p2 := List.mem_filter.mp hc2
      have f1 := partner_facts p1.2
      have f2 := partner_facts p2.2
      apply single c1 c2 (List.mem_range.mp p1.1) (List.mem_range.mp p2.1)
      · have := f1.1; rw [hadv] at this; cases h : (D.getD c1 noDraw).1 <;> simp_all
      · have := f2.1; rw [hadv] at this; cases h : (D.getD c2 noDraw).1 <;> simp_all
      · exact f1.2.1
      · exact f2.2.1
      · rw [← f1.2.2.1, f2.2.2.1]
      · rw [← f1.2.2.2, f2.2.2.2]
    · simp only [adv, hadv]; simp
  calc ((List.range L).map (fun j => (pairsList (tweakPartner n) D j).length)).sum
      ≤ ((List.range L).map (fun j => ((List.range j).map (fun i => f i j + f j i)).sum)).sum :=
        sum_map_le _ (fun j hj => step1 j (List.mem_range.mp hj))
    _ ≤ ((List.range L).map (fun a => ((List.range L).map (fun c => f a c)).sum)).sum :=
        pairs_le_square f L
    _ ≤ ((List.range L).map adv).sum := sum_map_le _ (fun a ha => step2 a (List.mem_range.mp ha))
    _ = advCount D := rfl

#print axioms pairs_le_adv

theorem sum_range_zero_tail (g : Nat → Nat) (len : Nat) (hz : ∀ j, len ≤ j → g j = 0) :
    ∀ N, len ≤ N → ((List.range N).map g).sum = ((List.range len).map g).sum
  | 0, h => by have : len = 0 := by omega
               subst this; rfl
  | N+1, h => by
    by_cases hl : len ≤ N
    · rw [range_succ_sum, hz N hl, sum_range_zero_tail g len hz N hl]; rfl
    · have : len = N + 1 := by omega
      subst this; rfl

theorem be_mod : ∀ (w x : Nat), be w x = be w (x % 256^w)
  | 0, _ => rfl
  | w+1, x => by
    simp only [be]
    rw [Nat.pow_succ', Nat.mod_mul_right_div_self, Nat.mod_mul_right_mod]
    rw [be_mod w (x/256), be_mod w (x/256 % 256^w), Nat.mod_mod]

theorem be_eq_mod {w x y : Nat} (h : be w x = be w y) : x % 256^w = y % 256^w := by
  rw [be_mod w x, be_mod w y] at h
  have hx := be_roundtrip w (x % 256^w) (Nat.mod_lt _ (Nat.pow_pos (by decide : 0 < 256)))
  have hy := be_roundtrip w (y % 256^w) (Nat.mod_lt _ (Nat.pow_pos (by decide : 0 < 256)))
  rw [← hx, ← hy, h]

/-- The answers a run gives its `i`-th and `j`-th fresh draws. -/
def answerOf (D : List Draw) (t : List Nat) (i : Nat) : Bytes :=
  be (D.getD i noDraw).2.outLen (t.getD i 0)

/-- Equal answers on a same-tweak partnered pair is the counted event. -/
theorem collides_of_answers (n : Nat) (D : List Draw) (t : List Nat) (i j : Nat) (hij : i < j)
    (hj : j < D.length) (hp : tweakPartner n (D.getD i noDraw) (D.getD j noDraw) = true)
    (ha : answerOf D t i = answerOf D t j) : collides (tweakPartner n) (256^n) D t = true := by
  obtain ⟨hn1, hn2⟩ : (D.getD i noDraw).2.outLen = n ∧ (D.getD j noDraw).2.outLen = n := by
    have h := hp
    unfold tweakPartner at h
    simp only [Bool.and_eq_true, bne_iff_ne, ne_eq, beq_iff_eq] at h
    obtain ⟨⟨⟨⟨⟨⟨⟨_, _⟩, _⟩, _⟩, h5⟩, h6⟩, _⟩, _⟩ := h
    exact ⟨h5, h6⟩
  unfold answerOf at ha
  rw [hn1, hn2] at ha
  have hm := be_eq_mod ha
  unfold collides
  apply List.any_eq_true.mpr
  refine ⟨j, List.mem_range.mpr hj, List.any_eq_true.mpr ⟨i, ?_, ?_⟩⟩
  · unfold pairsList; rw [if_pos hj]
    exact List.mem_filter.mpr ⟨List.mem_range.mpr hij, hp⟩
  · simp only [beq_iff_eq]; exact hm.symm

/-- ROM tweak-collision bound (thash role). A query tree with at most `N`
    queries, whose challenger side uses each (key, address) for one input and
    whose adversary side makes at most `qa` fresh draws, has a same-tweak
    collision of `n`-byte answers on at most a `qa / 256^n` fraction of tapes.
    Tape entries are uniform in `[0, 256^W)`, `n ≤ W`. -/
theorem rom_tweak_collision {α : Type} (n W N qa : Nat) (hn : n ≤ W) (T : QT α) (hT : T.Within N)
    (hsingle : ∀ t : List Nat, ChallengerSingleUse (run t T []).2)
    (hadv : ∀ t : List Nat, advCount (run t T []).2 ≤ qa) :
    tsum (256^W) N (fun t => if collides (tweakPartner n) (256^n) (run t T []).2 t then 1 else 0) * 256^n
      ≤ (256^W)^N * qa := by
  apply rom_partner_bound (256^W) (256^n) N qa (Nat.pow_pos (by decide : 0 < 256))
    (Nat.pow_dvd_pow 256 hn) T hT
  intro t
  have hlen : (run t T []).2.length ≤ N := by
    have := run_draws_le t T N [] hT; simpa using this
  rw [sum_range_zero_tail _ (run t T []).2.length (fun j hj => by
      simp [pairsList, Nat.not_lt.mpr hj]) N hlen]
  exact Nat.le_trans (pairs_le_adv n _ (hsingle t)) (hadv t)

/-- ROM secret-guessing bound (keys of the PRF/KDF/PRF_msg roles, the master
    seed, hidden chain values). A secret uniform in `[0, K)` and independent
    of the run lies among the run's guesses (at most `qa` on every tape) with
    probability at most `qa / K`. -/
theorem rom_secret_guess {α : Type} (R N K qa : Nat) (T : QT α) (Guess : List Draw → List Nat)
    (hg : ∀ t : List Nat, (Guess (run t T []).2).length ≤ qa) :
    ((List.range K).map (fun s => tsum R N (fun t =>
        if (Guess (run t T []).2).contains s then 1 else 0))).sum ≤ R^N * qa := by
  calc _ ≤ tsum R N (fun t => (Guess (run t T []).2).length) := guess_bound R N K _
    _ ≤ tsum R N (fun _ => qa) := tsum_mono R N hg
    _ = R^N * qa := tsum_const R qa N

#print axioms rom_tweak_collision
#print axioms rom_secret_guess
end DSM.Rom
