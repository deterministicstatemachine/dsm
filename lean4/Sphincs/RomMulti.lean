-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomSeed

/- Reordering lazily sampled computations.

   The single-key theorems (C57–C65) assume the target key's generation is the first
   oracle activity. In a multi-key game it comes after earlier activity `X` (other
   keys, adversary queries), at a point `X` chooses. This file moves the target's
   generation `Y` to the front without revealing it early:

       G  = X >>= fun x => if c x then Y >>= Z x else Z' x
       G' = Y >>= fun y => X >>= fun x => if c x then Z x y else Z' x

   On tapes where the target is created, the two runs give the same result, unless
   `X` alone and `Y` alone draw a common request (`Ov`). The coupling is a bijection
   on the finite tape space: rotate the first `a + b` coordinates, where `a` and `b`
   are the numbers of fresh draws of `X` alone and of `Y` alone (`reorder`). -/
namespace DSM.Rom
open DSM.Sphincs DSM.Sphincs.Security

/-! Tapes as a finite list, and reindexing by a bijection. -/

def allT (R : Nat) : Nat → List (List Nat)
  | 0 => [[]]
  | N+1 => (List.range R).flatMap (fun y => (allT R N).map (fun t => y :: t))

theorem tsum_allT (R : Nat) : ∀ (N : Nat) (F : List Nat → Nat), tsum R N F = ((allT R N).map F).sum
  | 0, F => by simp [tsum, allT]
  | N+1, F => by
    simp only [tsum, allT]
    rw [sum_flatMap]
    congr 1; apply List.map_congr_left; intro y _
    rw [tsum_allT R N, List.map_map]; rfl

/-- A tape of length `N` with entries below `R`. -/
def Valid (R N : Nat) (t : List Nat) : Prop := t.length = N ∧ ∀ x ∈ t, x < R

theorem mem_allT (R : Nat) : ∀ (N : Nat) (t : List Nat), t ∈ allT R N → Valid R N t
  | 0, t, h => by simp [allT] at h; subst h; exact ⟨rfl, by simp⟩
  | N+1, t, h => by
    simp only [allT, List.mem_flatMap, List.mem_range, List.mem_map] at h
    obtain ⟨y, hy, t0, ht0, rfl⟩ := h
    obtain ⟨h1, h2⟩ := mem_allT R N t0 ht0
    refine ⟨by simp [h1], fun x hx => ?_⟩
    simp only [List.mem_cons] at hx
    rcases hx with rfl | hx
    · exact hy
    · exact h2 x hx

def occ (t : List Nat) (L : List (List Nat)) : Nat := (L.map (fun x => if x = t then 1 else 0)).sum

theorem sum_range_single (R y c : Nat) (hy : y < R) (f : Nat → Nat) (h0 : ∀ z, z ≠ y → f z = 0) (hc : f y = c) :
    ((List.range R).map f).sum = c := by
  induction R with
  | zero => omega
  | succ R ih =>
    rw [List.range_succ, List.map_append, sum_append']
    by_cases hR : y < R
    · rw [ih hR]
      simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, h0 R (by omega)]; omega
    · have hyR : y = R := by omega
      subst hyR
      rw [sum_zero_of _ _ (fun z hz => h0 z (by have := List.mem_range.mp hz; omega))]
      simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, hc]; omega

theorem occ_allT (R : Nat) : ∀ (N : Nat) (t : List Nat), Valid R N t → occ t (allT R N) = 1
  | 0, t, ⟨h1, _⟩ => by
    have : t = [] := List.eq_nil_of_length_eq_zero h1
    subst this; simp [occ, allT]
  | N+1, t, ⟨h1, h2⟩ => by
    obtain ⟨y, t0, rfl⟩ : ∃ y t0, t = y :: t0 := by
      cases t with
      | nil => simp at h1
      | cons y t0 => exact ⟨y, t0, rfl⟩
    have hy : y < R := h2 y (by simp)
    have hv : Valid R N t0 := ⟨by simp at h1; exact h1, fun x hx => h2 x (by simp [hx])⟩
    unfold occ
    simp only [allT]
    rw [sum_flatMap]
    refine sum_range_single R y 1 hy _ (fun z hz => ?_) ?_
    · simp only [List.map_map, Function.comp_def]
      exact sum_zero_of _ _ (fun x _ => by simp [hz])
    · simp only [List.map_map, Function.comp_def, List.cons.injEq, true_and]
      exact occ_allT R N t0 hv

/-- Reindexing a tape sum by a bijection of the valid tapes. -/
theorem tsum_bij (R N : Nat) (φ ψ : List Nat → List Nat) (hφ : ∀ t, Valid R N t → Valid R N (φ t))
    (hψ : ∀ t, Valid R N t → Valid R N (ψ t)) (h1 : ∀ t, Valid R N t → ψ (φ t) = t)
    (h2 : ∀ t, Valid R N t → φ (ψ t) = t) (F : List Nat → Nat) :
    tsum R N (fun t => F (φ t)) = tsum R N F := by
  rw [tsum_allT, tsum_allT]
  have e1 : ∀ x ∈ allT R N, F (φ x) = ((allT R N).map (fun y => if φ x = y then F y else 0)).sum := by
    intro x hx
    have hv := hφ x (mem_allT R N x hx)
    have := occ_allT R N (φ x) hv
    unfold occ at this
    have e : ((allT R N).map (fun y => if φ x = y then F y else 0)).sum =
        ((allT R N).map (fun y => F (φ x) * (if y = φ x then 1 else 0))).sum := by
      congr 1; apply List.map_congr_left; intro y _
      by_cases h : φ x = y
      · subst h; simp
      · simp [h, Ne.symm h]
    rw [e, sum_map_mul, this, Nat.mul_one]
  rw [List.map_congr_left e1, sum_comm]
  congr 1; apply List.map_congr_left; intro y hy
  have hv := mem_allT R N y hy
  have := occ_allT R N (ψ y) (hψ y hv)
  unfold occ at this
  have e : ((allT R N).map (fun x => if φ x = y then F y else 0)).sum =
      ((allT R N).map (fun x => F y * (if x = ψ y then 1 else 0))).sum := by
    congr 1; apply List.map_congr_left; intro x hx
    have hxv := mem_allT R N x hx
    by_cases h : φ x = y
    · have : x = ψ y := by rw [← h, h1 x hxv]
      rw [if_pos h, if_pos this, Nat.mul_one]
    · have : x ≠ ψ y := fun hx' => h (by rw [hx', h2 y hv])
      simp [h, this]
  rw [e, sum_map_mul, this, Nat.mul_one]

/-! Runs and tapes. -/

theorem len_le_run {α : Type} (t : List Nat) (T : QT α) (D : List Draw) : D.length ≤ (run t T D).2.length := by
  obtain ⟨e, he⟩ := run_extends t T D; rw [he]; simp

/-- A run reads only the tape coordinates below its final table length. -/
theorem run_prefixR {α : Type} (t t' : List Nat) : ∀ (T : QT α) (D : List Draw),
    (∀ i, i < (run t T D).2.length → t.getD i 0 = t'.getD i 0) → run t T D = run t' T D
  | .done _, _, _ => rfl
  | .ask g r k, D, h => by
    cases hf : findDraw D r with
    | some i =>
      have hr : run t (.ask g r k) D = run t (k (be r.outLen (t.getD i 0))) D := by simp only [run, hf]
      have hr' : run t' (.ask g r k) D = run t' (k (be r.outLen (t'.getD i 0))) D := by simp only [run, hf]
      rw [hr] at h
      rw [hr, hr']
      have hi : t.getD i 0 = t'.getD i 0 :=
        h i (Nat.lt_of_lt_of_le (findDraw_lt D r i hf) (len_le_run _ _ _))
      rw [← hi]
      exact run_prefixR t t' _ D h
    | none =>
      have hr : run t (.ask g r k) D = run t (k (be r.outLen (t.getD D.length 0))) (D ++ [(g, r)]) := by
        simp only [run, hf]
      have hr' : run t' (.ask g r k) D = run t' (k (be r.outLen (t'.getD D.length 0))) (D ++ [(g, r)]) := by
        simp only [run, hf]
      rw [hr] at h
      rw [hr, hr']
      have hi : t.getD D.length 0 = t'.getD D.length 0 :=
        h D.length (Nat.lt_of_lt_of_le (by simp) (len_le_run _ _ _))
      rw [← hi]
      exact run_prefixR t t' _ _ h

/-- A run after a table `D` whose requests it never asks is the run on the shifted tape. -/
theorem run_shift {α : Type} (D : List Draw) (t : List Nat) : ∀ (T : QT α) (E : List Draw),
    (∀ e ∈ (run (t.drop D.length) T E).2, ∀ d ∈ D, e.2 ≠ d.2) →
    run t T (D ++ E) = ((run (t.drop D.length) T E).1, D ++ (run (t.drop D.length) T E).2)
  | .done _, _, _ => rfl
  | .ask g r k, E, h => by
    have hrD : ∀ d ∈ D, d.2 ≠ r := by
      intro d hd hdr
      cases hf : findDraw E r with
      | some j =>
        have hr : run (t.drop D.length) (.ask g r k) E =
            run (t.drop D.length) (k (be r.outLen ((t.drop D.length).getD j 0))) E := by simp only [run, hf]
        rw [hr] at h
        obtain ⟨e, he, her⟩ := findDraw_mem E r j hf
        obtain ⟨x, hx⟩ := run_extends (t.drop D.length) (k (be r.outLen ((t.drop D.length).getD j 0))) E
        exact h e (by rw [hx]; exact List.mem_append_left _ he) d hd (by rw [her, hdr])
      | none =>
        have hr : run (t.drop D.length) (.ask g r k) E =
            run (t.drop D.length) (k (be r.outLen ((t.drop D.length).getD E.length 0))) (E ++ [(g, r)]) := by
          simp only [run, hf]
        rw [hr] at h
        obtain ⟨x, hx⟩ := run_extends (t.drop D.length) (k (be r.outLen ((t.drop D.length).getD E.length 0)))
          (E ++ [(g, r)])
        exact h (g, r) (by rw [hx]; simp) d hd hdr.symm
    have hfd : findDraw (D ++ E) r = (findDraw E r).map (· + D.length) := findDraw_skip D E r hrD
    cases hf : findDraw E r with
    | some j =>
      have hr : run (t.drop D.length) (.ask g r k) E = run (t.drop D.length) (k (be r.outLen ((t.drop D.length).getD j 0))) E := by
        simp only [run, hf]
      rw [hr] at h ⊢
      have hl : run t (.ask g r k) (D ++ E) = run t (k (be r.outLen (t.getD (j + D.length) 0))) (D ++ E) := by
        simp only [run, hfd, hf, Option.map_some]
      rw [hl]
      have hv : t.getD (j + D.length) 0 = (t.drop D.length).getD j 0 := by
        simp only [List.getD_eq_getElem?_getD, List.getElem?_drop]; rw [Nat.add_comm]
      rw [hv]
      exact run_shift D t _ E h
    | none =>
      have hr : run (t.drop D.length) (.ask g r k) E =
          run (t.drop D.length) (k (be r.outLen ((t.drop D.length).getD E.length 0))) (E ++ [(g, r)]) := by
        simp only [run, hf]
      rw [hr] at h ⊢
      have hl : run t (.ask g r k) (D ++ E) = run t (k (be r.outLen (t.getD (D ++ E).length 0))) (D ++ E ++ [(g, r)]) := by
        simp only [run, hfd, hf, Option.map_none]
      rw [hl]
      have hv : t.getD (D ++ E).length 0 = (t.drop D.length).getD E.length 0 := by
        simp only [List.getD_eq_getElem?_getD, List.getElem?_drop, List.length_append]
      rw [hv, List.append_assoc]
      exact run_shift D t _ _ h

/-- The answer a table gives a request. -/
def ans (t : List Nat) (D : List Draw) (r : Request) : Option Bytes :=
  (findDraw D r).map (fun i => be r.outLen (t.getD i 0))

theorem findDraw_none_ne : ∀ (D : List Draw) (r : Request), findDraw D r = none → ∀ e ∈ D, e.2 ≠ r
  | [], _, _, e, he => by simp at he
  | x :: D, r, h, e, he => by
    rw [findDraw_cons] at h
    split at h
    · cases h
    · rename_i hx
      simp only [List.mem_cons] at he
      rcases he with rfl | he
      · exact hx
      · cases hf : findDraw D r with
        | none => exact findDraw_none_ne D r hf e he
        | some j => rw [hf] at h; cases h

theorem findDraw_snoc (D : List Draw) (g : Bool) (r r' : Request) :
    findDraw (D ++ [(g, r)]) r' = match findDraw D r' with
      | some i => some i
      | none => if r = r' then some D.length else none := by
  cases hf : findDraw D r' with
  | some i => exact findDraw_append_some D _ r' i hf
  | none =>
    simp only
    rw [findDraw_skip D [(g, r)] r' (findDraw_none_ne D r' hf)]
    by_cases h : r = r'
    · subst h; simp [findDraw_cons]
    · rw [findDraw_cons, if_neg h]; simp [h, findDraw]

/-- Two runs agree when their tables give every request the same answer and their tapes
    agree past the tables. -/
theorem run_equiv {α : Type} : ∀ (T : QT α) (t u : List Nat) (D1 D2 : List Draw), D1.length = D2.length →
    (∀ r, ans t D1 r = ans u D2 r) → (∀ i, D1.length ≤ i → t.getD i 0 = u.getD i 0) →
    (run t T D1).1 = (run u T D2).1
  | .done _, _, _, _, _, _, _, _ => rfl
  | .ask g r k, t, u, D1, D2, hl, ha, ht => by
    have har := ha r
    unfold ans at har
    cases h1 : findDraw D1 r with
    | some i1 =>
      cases h2 : findDraw D2 r with
      | none => rw [h1, h2] at har; cases har
      | some i2 =>
        rw [h1, h2] at har
        simp only [Option.map_some, Option.some.injEq] at har
        simp only [run, h1, h2]
        rw [har]
        exact run_equiv _ t u D1 D2 hl ha ht
    | none =>
      cases h2 : findDraw D2 r with
      | some i2 => rw [h1, h2] at har; cases har
      | none =>
        simp only [run, h1, h2]
        rw [ht D1.length (Nat.le_refl _), hl]
        refine run_equiv _ t u _ _ (by simp [hl]) (fun r' => ?_) (fun i hi => ht i (by simp at hi; omega))
        have hr' := ha r'
        unfold ans at hr' ⊢
        rw [findDraw_snoc, findDraw_snoc]
        cases f1 : findDraw D1 r' with
        | some j1 =>
          cases f2 : findDraw D2 r' with
          | none => rw [f1, f2] at hr'; cases hr'
          | some j2 => rw [f1, f2] at hr'; simpa using hr'
        | none =>
          cases f2 : findDraw D2 r' with
          | some j2 => rw [f1, f2] at hr'; cases hr'
          | none =>
            simp only
            by_cases hrr : r = r'
            · subst hrr; simp only [if_true, Option.map_some]; rw [ht D1.length (Nat.le_refl _), hl]
            · simp [hrr]

/-! The rotation of the tape. -/

theorem getD_append_lt (l1 l2 : List Nat) (i : Nat) (h : i < l1.length) : (l1 ++ l2).getD i 0 = l1.getD i 0 := by
  simp only [List.getD_eq_getElem?_getD, List.getElem?_append_left h]

theorem getD_append_ge (l1 l2 : List Nat) (i : Nat) (h : l1.length ≤ i) :
    (l1 ++ l2).getD i 0 = l2.getD (i - l1.length) 0 := by
  simp only [List.getD_eq_getElem?_getD, List.getElem?_append_right h]

theorem getD_takeL (l : List Nat) (n i : Nat) (h : i < n) : (l.take n).getD i 0 = l.getD i 0 := by
  simp only [List.getD_eq_getElem?_getD, List.getElem?_take, if_pos h]

theorem getD_drop (l : List Nat) (n i : Nat) : (l.drop n).getD i 0 = l.getD (n + i) 0 := by
  simp only [List.getD_eq_getElem?_getD, List.getElem?_drop]

/-- Rotate `t` so that the block `[a, a+b)` comes first. -/
def rot (a b : Nat) (t : List Nat) : List Nat := (t.drop a).take b ++ t.take a ++ t.drop (a + b)

theorem rot_length (a b : Nat) (t : List Nat) (h : a + b ≤ t.length) : (rot a b t).length = t.length := by
  simp only [rot, List.length_append, List.length_take, List.length_drop]; omega

theorem rot_mem (a b : Nat) (t : List Nat) (x : Nat) (hx : x ∈ rot a b t) : x ∈ t := by
  simp only [rot, List.mem_append] at hx
  rcases hx with (h | h) | h
  · exact List.mem_of_mem_drop (List.mem_of_mem_take h)
  · exact List.mem_of_mem_take h
  · exact List.mem_of_mem_drop h

theorem rot_rot (a b : Nat) (t : List Nat) (h : a + b ≤ t.length) : rot b a (rot a b t) = t := by
  have l1 : ((t.drop a).take b).length = b := by simp; omega
  have l2 : (t.take a).length = a := by simp; omega
  have hd : (rot a b t).drop b = t.take a ++ t.drop (a + b) := by
    simp only [rot]
    rw [List.append_assoc, List.drop_left' l1]
  have ht : (rot a b t).take b = (t.drop a).take b := by
    simp only [rot]; rw [List.append_assoc, List.take_left' l1]
  show ((rot a b t).drop b).take a ++ (rot a b t).take b ++ (rot a b t).drop (b + a) = t
  rw [show (rot a b t).drop (b + a) = ((rot a b t).drop b).drop a by rw [List.drop_drop]]
  rw [hd, ht, List.take_left' l2, List.drop_left' l2, List.append_assoc,
    show t.drop (a + b) = (t.drop a).drop b by rw [List.drop_drop], List.take_append_drop, List.take_append_drop]

section
variable {χ υ : Type} (X : QT χ) (Y : QT υ)

/-- Fresh draws of `X` alone and of `Y` alone. -/
def aX (t : List Nat) : Nat := (run t X []).2.length
def bY (t : List Nat) : Nat := (run t Y []).2.length

/-- The coupling: move the block `Y` alone draws (after `X` alone's) to the front. -/
def phiT (t : List Nat) : List Nat := rot (aX X t) (bY Y (t.drop (aX X t))) t
/-- Its inverse: move the block `X` alone draws (after `Y` alone's) back to the front. -/
def psiT (t : List Nat) : List Nat := rot (bY Y t) (aX X (t.drop (bY Y t))) t

/-- `X` alone and `Y` alone draw a common request. -/
def Ov (t : List Nat) : Prop :=
  ∃ e ∈ (run t X []).2, ∃ e' ∈ (run (t.drop (aX X t)) Y []).2, e.2 = e'.2

variable (A B : Nat) (hA : ∀ t, aX X t ≤ A) (hB : ∀ t, bY Y t ≤ B)
include hA hB

theorem psi_phi (t : List Nat) (hl : A + B ≤ t.length) : psiT X Y (phiT X Y t) = t := by
  have ha := hA t
  have hb := hB (t.drop (aX X t))
  generalize hav : aX X t = a at ha hb
  generalize hbv : bY Y (t.drop a) = b at hb
  have hab : a + b ≤ t.length := by omega
  have hphi : phiT X Y t = rot a b t := by simp only [phiT, hav, hbv]
  rw [hphi]
  have l1 : ((t.drop a).take b).length = b := by simp; omega
  -- Y alone on the rotated tape is Y alone on t.drop a
  have hY : run (t.drop a) Y [] = run (rot a b t) Y [] := by
    refine run_prefixR _ _ Y [] (fun i hi => ?_)
    have hi' : i < b := by rw [← hbv]; exact hi
    simp only [rot]; rw [List.append_assoc, getD_append_lt _ _ i (by omega), getD_takeL _ _ _ hi']
  have hb' : bY Y (rot a b t) = b := by rw [bY, ← hY]; exact hbv
  have hd : (rot a b t).drop b = t.take a ++ t.drop (a + b) := by
    simp only [rot]; rw [List.append_assoc, List.drop_left' l1]
  have hX : run t X [] = run ((rot a b t).drop b) X [] := by
    refine run_prefixR _ _ X [] (fun i hi => ?_)
    have hi' : i < a := by rw [← hav]; exact hi
    rw [hd, getD_append_lt _ _ i (by simp; omega), getD_takeL _ _ _ hi']
  have ha' : aX X ((rot a b t).drop b) = a := by rw [aX, ← hX]; exact hav
  simp only [psiT, hb', ha']
  exact rot_rot a b t hab

theorem phi_psi (t : List Nat) (hl : A + B ≤ t.length) : phiT X Y (psiT X Y t) = t := by
  have hb := hB t
  have ha := hA (t.drop (bY Y t))
  generalize hbv : bY Y t = b at ha hb
  generalize hav : aX X (t.drop b) = a at ha
  have hab : b + a ≤ t.length := by omega
  have hpsi : psiT X Y t = rot b a t := by simp only [psiT, hav, hbv]
  rw [hpsi]
  have l1 : ((t.drop b).take a).length = a := by simp; omega
  have hX : run (t.drop b) X [] = run (rot b a t) X [] := by
    refine run_prefixR _ _ X [] (fun i hi => ?_)
    have hi' : i < a := by rw [← hav]; exact hi
    simp only [rot]; rw [List.append_assoc, getD_append_lt _ _ i (by omega), getD_takeL _ _ _ hi']
  have ha' : aX X (rot b a t) = a := by rw [aX, ← hX]; exact hav
  have hd : (rot b a t).drop a = t.take b ++ t.drop (b + a) := by
    simp only [rot]; rw [List.append_assoc, List.drop_left' l1]
  have hY : run t Y [] = run ((rot b a t).drop a) Y [] := by
    refine run_prefixR _ _ Y [] (fun i hi => ?_)
    have hi' : i < b := by rw [← hbv]; exact hi
    rw [hd, getD_append_lt _ _ i (by simp; omega), getD_takeL _ _ _ hi']
  have hb' : bY Y ((rot b a t).drop a) = b := by rw [bY, ← hY]; exact hbv
  simp only [phiT, ha', hb']
  exact rot_rot b a t hab

theorem phiT_valid (R N : Nat) (hN : A + B ≤ N) (t : List Nat) (ht : Valid R N t) : Valid R N (phiT X Y t) := by
  have ha := hA t
  have hb := hB (t.drop (aX X t))
  refine ⟨?_, fun x hx => ht.2 x (rot_mem _ _ t x hx)⟩
  simp only [phiT]; rw [rot_length _ _ _ (by rw [ht.1]; omega), ht.1]

theorem psiT_valid (R N : Nat) (hN : A + B ≤ N) (t : List Nat) (ht : Valid R N t) : Valid R N (psiT X Y t) := by
  have hb := hB t
  have ha := hA (t.drop (bY Y t))
  refine ⟨?_, fun x hx => ht.2 x (rot_mem _ _ t x hx)⟩
  simp only [psiT]; rw [rot_length _ _ _ (by rw [ht.1]; omega), ht.1]

end

/-! The reordering theorem. -/

theorem tsum_mono_valid (R N : Nat) {F G : List Nat → Nat} (h : ∀ t, Valid R N t → F t ≤ G t) :
    tsum R N F ≤ tsum R N G := by
  rw [tsum_allT, tsum_allT]
  exact sum_map_le _ (fun t ht => h t (mem_allT R N t ht))

section
variable {χ υ α : Type} (X : QT χ) (Y : QT υ) (Z : χ → υ → QT α) (Z' : χ → QT α) (c : χ → Bool)

/-- The game with the target generated at the point `X` selects. -/
def gameOrd : QT α := QT.bind X (fun x => if c x = true then QT.bind Y (Z x) else Z' x)
/-- The game with the target generated first and kept unrevealed until that point. -/
def gameRe : QT α := QT.bind Y (fun y => QT.bind X (fun x => if c x = true then Z x y else Z' x))

theorem reorder_point (t : List Nat) (hl : aX X t + bY Y (t.drop (aX X t)) ≤ t.length)
    (hc : c (run t X []).1 = true) (hov : ¬ Ov X Y t) :
    (run t (gameOrd X Y Z Z' c) []).1 = (run (phiT X Y t) (gameRe X Y Z Z' c) []).1 := by
  generalize hav : aX X t = a at hl
  generalize hbv : bY Y (t.drop a) = b at hl
  have hphi : phiT X Y t = rot a b t := by simp only [phiT, hav, hbv]
  rw [hphi]
  generalize hu : rot a b t = u
  have l1 : ((t.drop a).take b).length = b := by simp; omega
  -- X alone, Y alone
  rcases hXr : run t X [] with ⟨x, DX⟩
  rcases hYr : run (t.drop a) Y [] with ⟨y, EY⟩
  have hDX : DX.length = a := by rw [← hav, aX, hXr]
  have hEY : EY.length = b := by rw [← hbv, bY, hYr]
  have hov' : ∀ e ∈ EY, ∀ d ∈ DX, e.2 ≠ d.2 := by
    intro e he d hd h
    apply hov
    refine ⟨d, by rw [hXr]; exact hd, e, ?_, h.symm⟩
    rw [hav, hYr]; exact he
  have hcx : c x = true := by rw [hXr] at hc; exact hc
  -- the original run
  have hO : (run t (gameOrd X Y Z Z' c) []).1 = (run t (Z x y) (DX ++ EY)).1 := by
    simp only [gameOrd]
    rw [run_bind, hXr]
    simp only [hcx, if_true]
    rw [run_bind]
    have hs := run_shift DX t Y [] (by rw [hDX, hYr]; exact hov')
    rw [List.append_nil, hDX, hYr] at hs
    rw [hs]
  -- the reordered run
  have hYu : run (t.drop a) Y [] = run u Y [] := by
    refine run_prefixR _ _ Y [] (fun i hi => ?_)
    have hi' : i < b := by rw [hYr] at hi; simp only at hi; omega
    rw [← hu]; simp only [rot]; rw [List.append_assoc, getD_append_lt _ _ i (by omega), getD_takeL _ _ _ hi']
  have hd : u.drop b = t.take a ++ t.drop (a + b) := by
    rw [← hu]; simp only [rot]; rw [List.append_assoc, List.drop_left' l1]
  have hXu : run t X [] = run (u.drop b) X [] := by
    refine run_prefixR _ _ X [] (fun i hi => ?_)
    have hi' : i < a := by rw [hXr] at hi; simp only at hi; omega
    rw [hd, getD_append_lt _ _ i (by simp; omega), getD_takeL _ _ _ hi']
  have hR : (run u (gameRe X Y Z Z' c) []).1 = (run u (Z x y) (EY ++ DX)).1 := by
    simp only [gameRe]
    rw [run_bind, ← hYu, hYr]
    simp only
    rw [run_bind]
    have hs := run_shift EY u X [] (by
      rw [hEY, ← hXu, hXr]
      intro e he d hd h; exact hov' d hd e he h.symm)
    rw [List.append_nil, hEY, ← hXu, hXr] at hs
    rw [hs]
    simp only [hcx, if_true]
  rw [hO, hR]
  -- the two tables give the same answers
  have hut : ∀ i, i < a → u.getD (b + i) 0 = t.getD i 0 := by
    intro i hi
    rw [← hu]; simp only [rot]
    rw [List.append_assoc, getD_append_ge _ _ _ (by omega), l1, show b + i - b = i by omega,
      getD_append_lt _ _ i (by simp; omega), getD_takeL _ _ _ hi]
  have hut2 : ∀ j, j < b → u.getD j 0 = t.getD (a + j) 0 := by
    intro j hj
    rw [← hu]; simp only [rot]
    rw [List.append_assoc, getD_append_lt _ _ j (by omega), getD_takeL _ _ _ hj, getD_drop]
  refine run_equiv (Z x y) t u _ _ (by simp; omega) (fun r => ?_) (fun i hi => ?_)
  · unfold ans
    cases h1 : findDraw DX r with
    | some i =>
      have hi := findDraw_lt DX r i h1
      obtain ⟨d, hdi, hdr⟩ := findDraw_get DX r i h1
      have hnE : ∀ e ∈ EY, e.2 ≠ r := fun e he h' => hov' e he d (List.mem_of_getElem? hdi) (by rw [h', hdr])
      rw [findDraw_append_some DX EY r i h1, findDraw_skip EY DX r hnE, h1]
      simp only [Option.map_some, hEY]
      rw [Nat.add_comm i b, hut i (by omega)]
    | none =>
      have hnD := findDraw_none_ne DX r h1
      cases h2 : findDraw EY r with
      | some j =>
        have hj := findDraw_lt EY r j h2
        rw [findDraw_skip DX EY r hnD, findDraw_append_some EY DX r j h2, h2]
        simp only [Option.map_some, hDX]
        rw [hut2 j (by omega), Nat.add_comm a j]
      | none =>
        rw [findDraw_skip DX EY r hnD, findDraw_skip EY DX r (findDraw_none_ne EY r h2), h1, h2]
        rfl
  · simp only [List.length_append, hDX, hEY] at hi
    rw [← hu]; simp only [rot]
    rw [List.append_assoc, getD_append_ge _ _ _ (by simp; omega), l1, getD_append_ge _ _ _ (by simp; omega),
      getD_drop]
    congr 1; simp; omega

variable (A B : Nat) (hA : ∀ t, aX X t ≤ A) (hB : ∀ t, bY Y t ≤ B)
include hA hB

/-- **Reordering.** On tapes of length `N ≥ A + B`, the tapes on which the target is
    created and `P` holds in the original game are at most the tapes on which `P` holds
    in the reordered game, plus the overlap tapes. -/
theorem reorder (R N : Nat) (hN : A + B ≤ N) (P : α → Prop) :
    tsum R N (fun t => ind (c (run t X []).1 = true ∧ P (run t (gameOrd X Y Z Z' c) []).1)) ≤
      tsum R N (fun t => ind (P (run t (gameRe X Y Z Z' c) []).1)) + tsum R N (fun t => ind (Ov X Y t)) := by
  have hbij := tsum_bij R N (phiT X Y) (psiT X Y) (phiT_valid X Y A B hA hB R N hN) (psiT_valid X Y A B hA hB R N hN)
    (fun t ht => psi_phi X Y A B hA hB t (by rw [ht.1]; exact hN))
    (fun t ht => phi_psi X Y A B hA hB t (by rw [ht.1]; exact hN))
    (fun t => ind (P (run t (gameRe X Y Z Z' c) []).1))
  rw [← hbij, ← tsum_add]
  refine tsum_mono_valid R N (fun t ht => ?_)
  by_cases h : c (run t X []).1 = true ∧ P (run t (gameOrd X Y Z Z' c) []).1
  · rw [ind_of h]
    by_cases hov : Ov X Y t
    · rw [ind_of hov]; omega
    · have hl : aX X t + bY Y (t.drop (aX X t)) ≤ t.length := by
        have := hA t; have := hB (t.drop (aX X t)); rw [ht.1]; omega
      have he := reorder_point X Y Z Z' c t hl h.1 hov
      rw [ind_of (show P (run (phiT X Y t) (gameRe X Y Z Z' c) []).1 by rw [← he]; exact h.2)]
      omega
  · rw [ind_of_not h]; exact Nat.zero_le _

end

/-! The target key generation's requests. -/

/-- A request not keyed by `tk` or `pk`. -/
def nk (tk pk : Bytes) (r : Request) : Bool := !(decide (r.key = tk) || decide (r.key = pk))

section
variable (g : Bool) (p : Params) (tk prfKey seed : Bytes)

theorem k_thash (a : Adrs) (x : Bytes) : Cnt (nk tk prfKey) (thash (tagO g) p tk a x) 0 :=
  Cnt.oracle g _ (by simp [nk])

theorem k_chain (a : Adrs) : ∀ (steps : Nat) (x : Bytes) (start : Nat),
    Cnt (nk tk prfKey) (chain (tagO g) p tk a x start steps) 0
  | 0, x, _ => Cnt.pure x
  | steps+1, x, start => by
    simp only [chain]
    exact Cnt.bind0 (k_thash g p tk prfKey _ _) (fun y => k_chain a steps y (start+1))

theorem k_wotsPkgen (a : Adrs) : Cnt (nk tk prfKey) (wotsPkgen (tagO g) p tk prfKey seed a) 0 := by
  simp only [wotsPkgen, wotsCompress]
  refine Cnt.bind0 (Cnt.forIn _ _ ?_ []) (fun tops => k_thash g p tk prfKey _ _)
  intro i _ s
  exact Cnt.bind0 (Cnt.oracle g _ (by simp [nk])) (fun sk => Cnt.bind0 (k_chain g p tk prfKey _ _ _ _)
    (fun top => Cnt.pure _))

theorem k_xmssNode (a : Adrs) : ∀ (height idx : Nat),
    Cnt (nk tk prfKey) (xmssNode (tagO g) p tk prfKey seed a idx height) 0
  | 0, idx => by simp only [xmssNode]; exact k_wotsPkgen g p tk prfKey seed _
  | height+1, idx => by
    simp only [xmssNode]
    exact Cnt.bind0 (k_xmssNode a height (2*idx)) (fun l => Cnt.bind0 (k_xmssNode a height (2*idx+1))
      (fun r => k_thash g p tk prfKey _ _))

end

/-- Entries a run appends satisfy `P = false` when no ask satisfies `P`. -/
theorem run_all (P : Request → Bool) (t : List Nat) {α : Type} : ∀ (T : QT α) (D : List Draw),
    Cnt P T 0 → ∀ e ∈ (run t T D).2, e ∈ D ∨ P e.2 = false
  | .done _, D, _, e, he => Or.inl he
  | .ask g r k, D, h, e, he => by
    simp only [Cnt] at h
    split at h
    · exact absurd h.1 (by omega)
    · rename_i hp
      simp only [run] at he
      cases hf : findDraw D r with
      | some i =>
        rw [hf] at he
        exact run_all P t _ D (h _) e he
      | none =>
        rw [hf] at he
        rcases run_all P t _ _ (h _) e he with h1 | h1
        · rcases List.mem_append.mp h1 with h2 | h2
          · exact Or.inl h2
          · simp at h2; subst h2; right; simpa using hp
        · exact Or.inr h1

theorem qbind_eq {α β : Type} (T : QT α) (f : α → QT β) : (T >>= f) = T.bind f := rfl

/-- The requests the target's key generation draws: the expansion, the two key
    derivations, and requests keyed by the tweak key or the PRF key. -/
theorem gk_shape (v : Variant) (s : Nat) (w : List Nat) :
    ∀ e ∈ (run w (generateKeypair challengerOracle v (seedW s)) []).2,
      e.2 = expReq v s ∨
      e.2 = ⟨0, "DSM/sphincs/v2/thash", [], slice (be (3*(params v).n) (w.getD 0 0)) (2*(params v).n) (params v).n, 32⟩ ∨
      e.2 = ⟨0, "DSM/sphincs/v2/prf", [], (be (3*(params v).n) (w.getD 0 0)).take (params v).n, 32⟩ ∨
      e.2.key = be 32 (w.getD 1 0) ∨ e.2.key = be 32 (w.getD 2 0) := by
  intro e he
  rw [generateKeypair_split, qbind_eq, run_bind] at he
  have h0 : run w (challengerOracle ⟨3, "ChaCha20Rng", [], (seedW s).val, 3*(params v).n⟩) [] =
      (be (3*(params v).n) (w.getD 0 0), [(false, expReq v s)]) := by
    simp [challengerOracle, run, findDraw, expReq, seedW]
  rw [h0] at he
  simp only [kgTail, qbind_eq] at he
  rw [run_bind] at he
  have h1 : run w (deriveKey challengerOracle "DSM/sphincs/v2/thash"
      (slice (be (3*(params v).n) (w.getD 0 0)) (2*(params v).n) (params v).n)) [(false, expReq v s)] =
      (be 32 (w.getD 1 0), [(false, expReq v s), (false, ⟨0, "DSM/sphincs/v2/thash", [],
        slice (be (3*(params v).n) (w.getD 0 0)) (2*(params v).n) (params v).n, 32⟩)]) := by
    simp [deriveKey, challengerOracle, run, findDraw, expReq, req_beq_unfold]
  rw [h1] at he
  simp only at he
  rw [run_bind] at he
  have h2 : run w (deriveKey challengerOracle "DSM/sphincs/v2/prf" ((be (3*(params v).n) (w.getD 0 0)).take (params v).n))
      [(false, expReq v s), (false, ⟨0, "DSM/sphincs/v2/thash", [],
        slice (be (3*(params v).n) (w.getD 0 0)) (2*(params v).n) (params v).n, 32⟩)] =
      (be 32 (w.getD 2 0), [(false, expReq v s), (false, ⟨0, "DSM/sphincs/v2/thash", [],
        slice (be (3*(params v).n) (w.getD 0 0)) (2*(params v).n) (params v).n, 32⟩),
        (false, ⟨0, "DSM/sphincs/v2/prf", [], (be (3*(params v).n) (w.getD 0 0)).take (params v).n, 32⟩)]) := by
    simp [deriveKey, challengerOracle, run, findDraw, expReq, req_beq_unfold]
  rw [h2] at he
  simp only at he
  rw [run_bind] at he
  simp only [run] at he
  rcases run_all (nk (be 32 (w.getD 1 0)) (be 32 (w.getD 2 0))) w _ _
    (k_xmssNode false (params v) (be 32 (w.getD 1 0)) (be 32 (w.getD 2 0))
      (slice (be (3*(params v).n) (w.getD 0 0)) (2*(params v).n) (params v).n)
      { layer := (params v).d - 1 } (params v).hp 0) e he with h | h
  · simp only [List.mem_cons, List.not_mem_nil, or_false] at h
    rcases h with rfl | rfl | rfl
    · exact Or.inl rfl
    · exact Or.inr (Or.inl rfl)
    · exact Or.inr (Or.inr (Or.inl rfl))
  · simp only [nk, Bool.not_eq_false', Bool.or_eq_true, decide_eq_true_eq] at h
    exact Or.inr (Or.inr (Or.inr h))

/-! Hitting a byte-string-valued function of a fresh tape coordinate. -/

/-- Fixed coordinate, general hit function `f`: if every value `k` has at most
    `R / M` preimages under `f` among `0..R-1`, a target that does not depend on
    coordinate `c` is hit on at most a `1/M` fraction of the weight. -/
theorem coord_hitB (R M : Nat) (f : Nat → Bytes)
    (hf : ∀ k, ((List.range R).map (fun y => if f y = k then 1 else 0)).sum * M ≤ R) :
    ∀ (c N : Nat), c < N →
    ∀ (w : List Nat → Nat) (g : List Nat → Bytes), (∀ t y, w (t.set c y) = w t) → (∀ t y, g (t.set c y) = g t) →
    tsum R N (fun t => w t * (if f (t.getD c 0) = g t then 1 else 0)) * M ≤ tsum R N w
  | _, 0, h, _, _, _, _ => absurd h (Nat.not_lt_zero _)
  | 0, N+1, _, w, g, hw, hg => by
    have w0 : ∀ y t, w (y :: t) = w (0 :: t) := fun y t => by
      have := hw (0 :: t) y; rw [set_cons_zero] at this; exact this
    have g0 : ∀ y t, g (y :: t) = g (0 :: t) := fun y t => by
      have := hg (0 :: t) y; rw [set_cons_zero] at this; exact this
    simp only [tsum, List.getD_cons_zero]
    simp only [w0, g0]
    have e := tsum_list R N (List.range R)
      (fun y t => w (0 :: t) * (if f y = g (0 :: t) then 1 else 0))
    rw [← e]
    simp only [sum_map_mul, sum_map_const, List.length_range]
    rw [Nat.mul_comm, ← tsum_mul]
    apply Nat.le_trans (tsum_mono R N (G := fun t => R * w (0 :: t)) _)
    · rw [tsum_mul]; exact Nat.le_refl _
    · intro t
      calc M * (w (0 :: t) * ((List.range R).map (fun y => if f y = g (0 :: t) then 1 else 0)).sum)
          = w (0 :: t) * (((List.range R).map (fun y => if f y = g (0 :: t) then 1 else 0)).sum * M) := by
            ac_rfl
        _ ≤ w (0 :: t) * R := Nat.mul_le_mul_left _ (hf _)
        _ = R * w (0 :: t) := Nat.mul_comm _ _
  | c+1, N+1, h, w, g, hw, hg => by
    simp only [tsum, List.getD_cons_succ]
    rw [Nat.mul_comm, ← sum_map_mul]
    apply sum_map_le
    intro y _
    have ih := coord_hitB R M f hf c N (by omega) (fun t => w (y :: t)) (fun t => g (y :: t))
      (fun t z => by have := hw (y :: t) z; rw [set_cons_succ] at this; exact this)
      (fun t z => by have := hg (y :: t) z; rw [set_cons_succ] at this; exact this)
    rw [Nat.mul_comm]; exact ih

/-- The target need only be invariant where the weight is nonzero. -/
theorem coord_hitB' (R M : Nat) (f : Nat → Bytes)
    (hf : ∀ k, ((List.range R).map (fun y => if f y = k then 1 else 0)).sum * M ≤ R) (c N : Nat) (hc : c < N)
    (w : List Nat → Nat) (g : List Nat → Bytes) (hw : ∀ t y, w (t.set c y) = w t)
    (hg : ∀ t y, w t ≠ 0 → g (t.set c y) = g t) :
    tsum R N (fun t => w t * (if f (t.getD c 0) = g t then 1 else 0)) * M ≤ tsum R N w := by
  have hg' : ∀ t y, (if w (t.set c y) = 0 then [] else g (t.set c y)) = (if w t = 0 then [] else g t) := by
    intro t y
    rw [hw]
    by_cases h : w t = 0
    · simp [h]
    · simp [h, hg t y h]
  have e : (fun t => w t * (if f (t.getD c 0) = g t then 1 else 0)) =
      (fun t => w t * (if f (t.getD c 0) = (if w t = 0 then [] else g t) then 1 else 0)) := by
    funext t
    by_cases h : w t = 0
    · simp [h]
    · simp [h]
  rw [e]
  exact coord_hitB R M f hf c N hc w (fun t => if w t = 0 then [] else g t) hw hg'

/-- A family of such hits, summed. -/
theorem hitsB_sum {ι : Type} (R M N : Nat) (f : Nat → Bytes)
    (hf : ∀ k, ((List.range R).map (fun y => if f y = k then 1 else 0)).sum * M ≤ R) (Ix : List ι)
    (c : ι → Nat) (hc : ∀ i ∈ Ix, c i < N) (w : ι → List Nat → Nat) (g : ι → List Nat → Bytes)
    (hw : ∀ i ∈ Ix, ∀ t y, w i (t.set (c i) y) = w i t)
    (hg : ∀ i ∈ Ix, ∀ t y, w i t ≠ 0 → g i (t.set (c i) y) = g i t) :
    tsum R N (fun t => (Ix.map (fun i => w i t * (if f (t.getD (c i) 0) = g i t then 1 else 0))).sum) * M
      ≤ tsum R N (fun t => (Ix.map (fun i => w i t)).sum) := by
  rw [tsum_list, tsum_list, Nat.mul_comm, ← sum_map_mul]
  apply sum_map_le
  intro i hi
  rw [Nat.mul_comm]
  exact coord_hitB' R M f hf (c i) N (hc i hi) (w i) (g i) (hw i hi) (hg i hi)

/-- `be n` is injective below `256^n`: each byte string has at most one preimage. -/
theorem inj_count (n : Nat) (I : Bytes) :
    ((List.range (256^n)).map (fun c => if be n c = I then 1 else 0)).sum ≤ 1 := by
  by_cases h : ∃ c0, c0 < 256^n ∧ be n c0 = I
  · obtain ⟨c0, hc0, he⟩ := h
    have e : ∀ c ∈ List.range (256^n), (if be n c = I then 1 else 0) = (if (c == c0) = true then 1 else 0) := by
      intro c hc
      have hc' := List.mem_range.mp hc
      by_cases hx : c = c0
      · subst hx; simp [he]
      · have : be n c ≠ I := fun h' => hx (be_injective n c c0 hc' hc0 (h'.trans he.symm))
        simp [this, hx]
    rw [List.map_congr_left e, ← len_filter_eq_sum]
    exact filter_eq_le_one _ List.nodup_range c0
  · have e : ∀ c ∈ List.range (256^n), (if be n c = I then 1 else 0) = 0 := by
      intro c hc; have := List.mem_range.mp hc
      rw [if_neg (fun h' => h ⟨c, this, h'⟩)]
    rw [List.map_congr_left e, sum_map_zero]; omega

/-- A tweak or PRF key `be 32 y` of a fresh coordinate. -/
theorem cnt_key (R : Nat) (hR : 256^32 ∣ R) (I : Bytes) :
    ((List.range R).map (fun y => if be 32 y = I then 1 else 0)).sum * 256^32 ≤ R := by
  obtain ⟨q, hq⟩ := hR
  rw [sum_mod_eq R (256^32) q hq _ (fun x => by rw [be_mod 32 x])]
  have := inj_count 32 I
  rw [hq]
  calc q * ((List.range (256^32)).map (fun y => if be 32 y = I then 1 else 0)).sum * 256^32
      ≤ q * 1 * 256^32 := Nat.mul_le_mul_right _ (Nat.mul_le_mul_left _ this)
    _ = 256^32 * q := by rw [Nat.mul_one, Nat.mul_comm]

/-- The public seed of an expansion output (its last `n` bytes). -/
theorem cnt_pk (n R : Nat) (hR : 256^(3*n) ∣ R) (I : Bytes) :
    ((List.range R).map (fun y => if slice (be (3*n) y) (2*n) n = I then 1 else 0)).sum * 256^n ≤ R := by
  obtain ⟨q, hq⟩ := hR
  rw [sum_mod_eq R (256^(3*n)) q hq _ (fun x => by rw [be_mod (3*n) x])]
  rw [expand_slices_sum n (fun _ _ c => if c = I then 1 else 0)]
  have hin : ∀ a ∈ List.range (256^n), ((List.range (256^n)).map (fun b =>
      ((List.range (256^n)).map (fun c => if be n c = I then 1 else 0)).sum)).sum ≤ 256^n := by
    intro a _
    calc _ ≤ ((List.range (256^n)).map (fun _ => 1)).sum := sum_map_le _ (fun b _ => inj_count n I)
      _ = 256^n := by rw [sum_map_const, List.length_range, Nat.mul_one]
  have h3 : 256^(3*n) = 256^n * 256^n * 256^n := by rw [← Nat.pow_add, ← Nat.pow_add]; congr 1; omega
  calc q * ((List.range (256^n)).map (fun a => ((List.range (256^n)).map (fun b =>
        ((List.range (256^n)).map (fun c => if be n c = I then 1 else 0)).sum)).sum)).sum * 256^n
      ≤ q * ((List.range (256^n)).map (fun _ => 256^n)).sum * 256^n :=
        Nat.mul_le_mul_right _ (Nat.mul_le_mul_left _ (sum_map_le _ hin))
    _ = R := by rw [sum_map_const, List.length_range, hq, h3]; ac_rfl

/-- The secret seed of an expansion output (its first `n` bytes). -/
theorem cnt_sk (n R : Nat) (hR : 256^(3*n) ∣ R) (I : Bytes) :
    ((List.range R).map (fun y => if (be (3*n) y).take n = I then 1 else 0)).sum * 256^n ≤ R := by
  obtain ⟨q, hq⟩ := hR
  rw [sum_mod_eq R (256^(3*n)) q hq _ (fun x => by rw [be_mod (3*n) x])]
  rw [expand_slices_sum n (fun a _ _ => if a = I then 1 else 0)]
  have hin : ∀ a ∈ List.range (256^n), ((List.range (256^n)).map (fun b =>
      ((List.range (256^n)).map (fun c => if be n a = I then 1 else 0)).sum)).sum =
      256^n * 256^n * (if be n a = I then 1 else 0) := by
    intro a _
    rw [sum_map_const, List.length_range, sum_map_const, List.length_range, Nat.mul_assoc]
  rw [List.map_congr_left hin, sum_map_mul]
  have := inj_count n I
  have h3 : 256^(3*n) = 256^n * 256^n * 256^n := by rw [← Nat.pow_add, ← Nat.pow_add]; congr 1; omega
  calc q * (256^n * 256^n * ((List.range (256^n)).map (fun a => if be n a = I then 1 else 0)).sum) * 256^n
      ≤ q * (256^n * 256^n * 1) * 256^n :=
        Nat.mul_le_mul_right _ (Nat.mul_le_mul_left _ (Nat.mul_le_mul_left _ this))
    _ = R := by rw [hq, h3, Nat.mul_one]; ac_rfl

/-! The overlap event of the target's key generation.

   `X` is everything before the target key is created; `Y s` is the target's key
   generation from seed `s`, run on the tape after `X`'s draws. `X` alone and `Y s`
   alone draw a common request only if one of `X`'s requests (a function of the tape
   before position `p = aX X t`) equals one of five values (`gk_shape`):
   the expansion request of the seed `s` (sampled independently of `X`), or a value
   of the fresh coordinates `p`, `p+1`, `p+2`: the public seed and the secret seed
   of the expansion output, and the tweak and PRF keys. Each is a fresh uniform
   value of `256^n` (seeds) or `256^32` (keys) possibilities that `X` never read,
   so `X` hits it with probability at most `1/256^n` or `1/256^32` per request. -/

theorem count_eq_le_one (L : List Nat) (nd : L.Nodup) (x : Nat) :
    (L.map (fun q => if x = q then 1 else 0)).sum ≤ 1 := by
  have e : ∀ q ∈ L, (if x = q then 1 else 0) = (if (q == x) = true then 1 else 0) := by
    intro q _
    by_cases h : x = q
    · subst h; simp
    · simp [h, Ne.symm h]
  rw [List.map_congr_left e, ← len_filter_eq_sum]
  exact filter_eq_le_one _ nd x

section
variable {χ : Type} (X : QT χ)

/-- `X` is unaffected by tape coordinates at or after its draws. -/
theorem runX_set (t : List Nat) (c y : Nat) (h : aX X t ≤ c) : run (t.set c y) X [] = run t X [] := by
  symm
  apply run_prefixR
  intro i hi
  have : i < c := by unfold aX at h; omega
  rw [getD_set_ne t c i y (by omega)]

theorem aX_set (t : List Nat) (c y : Nat) (h : aX X t ≤ c) : aX X (t.set c y) = aX X t := by
  unfold aX; rw [runX_set X t c y h]

/-- Request of `X`'s `j`-th draw. -/
def xReq (j : Nat) (t : List Nat) : Request :=
  (((run t X []).2[j]?).map Prod.snd).getD ⟨0, "", [], [], 0⟩

/-- Weight of the index `(p, j)`: `X` made exactly `p` draws, and `j < p`. -/
def wX (i : Nat × Nat) (t : List Nat) : Nat := if aX X t = i.1 ∧ i.2 < i.1 then 1 else 0

def IxA (A : Nat) : List (Nat × Nat) := (List.range (A+1)).flatMap (fun q => (List.range A).map (fun j => (q, j)))

theorem wX_set (i : Nat × Nat) (t : List Nat) (c y : Nat) (hc : i.1 ≤ c) : wX X i (t.set c y) = wX X i t := by
  unfold wX
  by_cases h : aX X t = i.1
  · rw [aX_set X t c y (by omega)]
  · have h' : aX X (t.set c y) ≠ i.1 := by
      intro h'
      have := aX_set X (t.set c y) c (t.getD c 0) (by omega)
      rw [set_set_back] at this
      exact h (this.trans h')
    rw [if_neg (fun h2 => h' h2.1), if_neg (fun h2 => h h2.1)]

theorem xReq_set (i : Nat × Nat) (t : List Nat) (c y : Nat) (hc : i.1 ≤ c) (hw : wX X i t ≠ 0) :
    xReq X i.2 (t.set c y) = xReq X i.2 t := by
  have h : aX X t = i.1 := by
    unfold wX at hw; by_cases h : aX X t = i.1 ∧ i.2 < i.1
    · exact h.1
    · rw [if_neg h] at hw; exact absurd rfl hw
  unfold xReq; rw [runX_set X t c y (by omega)]

theorem wX_sum (A : Nat) (t : List Nat) : ((IxA A).map (fun i => wX X i t)).sum ≤ A := by
  unfold IxA
  rw [sum_flatMap]
  have h1 : ∀ q ∈ List.range (A+1), (((List.range A).map (fun j => (q, j))).map (fun i => wX X i t)).sum ≤
      A * (if aX X t = q then 1 else 0) := by
    intro q _
    rw [List.map_map]
    calc _ ≤ ((List.range A).map (fun _ => (if aX X t = q then 1 else 0))).sum := by
          apply sum_map_le; intro j _
          simp only [Function.comp, wX]
          by_cases h : aX X t = q
          · rw [if_pos h]; split <;> omega
          · rw [if_neg h, if_neg (fun h2 => h h2.1)]; exact Nat.le_refl 0
      _ = _ := by rw [sum_map_const, List.length_range]
  calc _ ≤ ((List.range (A+1)).map (fun q => A * (if aX X t = q then 1 else 0))).sum := sum_map_le _ h1
    _ = A * ((List.range (A+1)).map (fun q => if aX X t = q then 1 else 0)).sum := sum_map_mul _ _ _
    _ ≤ A * 1 := Nat.mul_le_mul_left _ (count_eq_le_one _ List.nodup_range _)
    _ = A := Nat.mul_one A

variable (v : Variant)

/-- The target's key generation from seed `s`. -/
abbrev Ygen (s : Nat) : QT (Bytes × Bytes) := generateKeypair challengerOracle v (seedW s)

/-- `X` drew the target's expansion request. -/
def seedHitX (s : Nat) (t : List Nat) : Prop := ∃ e ∈ (run t X []).2, e.2 = expReq v s

/-- `X` drew the target's public-seed key derivation (input: the expansion's public seed). -/
def hitPK (A : Nat) (t : List Nat) : Nat := ((IxA A).map (fun i => wX X i t *
  (if slice (be (3*(params v).n) (t.getD i.1 0)) (2*(params v).n) (params v).n = (xReq X i.2 t).input then 1 else 0))).sum
/-- `X` drew the target's secret-seed key derivation (input: the expansion's secret seed). -/
def hitSK (A : Nat) (t : List Nat) : Nat := ((IxA A).map (fun i => wX X i t *
  (if (be (3*(params v).n) (t.getD i.1 0)).take (params v).n = (xReq X i.2 t).input then 1 else 0))).sum
/-- `X` drew a request keyed by the target's tweak key. -/
def hitTK (A : Nat) (t : List Nat) : Nat := ((IxA A).map (fun i => wX X i t *
  (if be 32 (t.getD (i.1+1) 0) = (xReq X i.2 t).key then 1 else 0))).sum
/-- `X` drew a request keyed by the target's PRF key. -/
def hitPF (A : Nat) (t : List Nat) : Nat := ((IxA A).map (fun i => wX X i t *
  (if be 32 (t.getD (i.1+2) 0) = (xReq X i.2 t).key then 1 else 0))).sum

theorem term_le (A : Nat) (F : Nat × Nat → Nat) (i : Nat × Nat) (hi : i ∈ IxA A) : F i ≤ ((IxA A).map F).sum :=
  le_sum_of_mem (List.mem_map.mpr ⟨i, hi, rfl⟩)

/-- **Overlap inclusion.** Every overlap between `X` alone and the target's key
    generation alone is one of the five hits. -/
theorem ov_incl (A : Nat) (hA : ∀ t, aX X t ≤ A) (s : Nat) (t : List Nat) :
    ind (Ov X (Ygen v s) t) ≤ ind (seedHitX X v s t) + hitPK X v A t + hitSK X v A t + hitTK X A t + hitPF X A t := by
  by_cases hov : Ov X (Ygen v s) t
  · obtain ⟨e, he, e', he', heq⟩ := hov
    obtain ⟨j, hj, hje⟩ := List.mem_iff_getElem.mp he
    have hxr : xReq X j t = e.2 := by
      unfold xReq; rw [List.getElem?_eq_getElem hj, hje]; rfl
    have hjA : j < aX X t := hj
    have hi : (aX X t, j) ∈ IxA A := by
      unfold IxA
      refine List.mem_flatMap.mpr ⟨aX X t, List.mem_range.mpr (by have := hA t; omega), ?_⟩
      exact List.mem_map.mpr ⟨j, List.mem_range.mpr (by have := hA t; omega), rfl⟩
    have hw : wX X (aX X t, j) t = 1 := by unfold wX; rw [if_pos ⟨rfl, hjA⟩]
    rw [ind_of ⟨e, he, e', he', heq⟩]
    have g := gk_shape v s (t.drop (aX X t)) e' he'
    simp only [getD_drop, Nat.add_zero] at g
    rw [← heq] at g
    rcases g with g | g | g | g | g
    · rw [ind_of ⟨e, he, g⟩]; omega
    · have := term_le A (fun i => wX X i t *
        (if slice (be (3*(params v).n) (t.getD i.1 0)) (2*(params v).n) (params v).n = (xReq X i.2 t).input
          then 1 else 0)) _ hi
      simp only [hw, hxr, g, if_true, Nat.one_mul] at this
      unfold hitPK; omega
    · have := term_le A (fun i => wX X i t *
        (if (be (3*(params v).n) (t.getD i.1 0)).take (params v).n = (xReq X i.2 t).input then 1 else 0)) _ hi
      simp only [hw, hxr, g, if_true, Nat.one_mul] at this
      unfold hitSK; omega
    · have := term_le A (fun i => wX X i t *
        (if be 32 (t.getD (i.1+1) 0) = (xReq X i.2 t).key then 1 else 0)) _ hi
      simp only [hw, hxr, g, if_true, Nat.one_mul] at this
      unfold hitTK; omega
    · have := term_le A (fun i => wX X i t *
        (if be 32 (t.getD (i.1+2) 0) = (xReq X i.2 t).key then 1 else 0)) _ hi
      simp only [hw, hxr, g, if_true, Nat.one_mul] at this
      unfold hitPF; omega
  · rw [ind_of_not hov]; exact Nat.zero_le _

end

theorem ov_arith (O S P K T F Z u U : Nat) (h1 : O ≤ S + U * (P + K + T + F)) (hS : S ≤ Z) (hP : P * u ≤ Z)
    (hK : K * u ≤ Z) (hT : T * U ≤ Z) (hF : F * U ≤ Z) : O * u ≤ Z * (3 * u + 2 * U) := by
  calc O * u ≤ (S + U * (P + K + T + F)) * u := Nat.mul_le_mul_right _ h1
    _ = S * u + U * (P * u) + U * (K * u) + u * (T * U) + u * (F * U) := by
        simp only [Nat.add_mul, Nat.mul_add]; ac_rfl
    _ ≤ Z * u + U * Z + U * Z + u * Z + u * Z :=
        Nat.add_le_add (Nat.add_le_add (Nat.add_le_add (Nat.add_le_add (Nat.mul_le_mul_right _ hS)
          (Nat.mul_le_mul_left _ hP)) (Nat.mul_le_mul_left _ hK)) (Nat.mul_le_mul_left _ hT))
          (Nat.mul_le_mul_left _ hF)
    _ = Z * (3 * u + 2 * U) := by
        rw [Nat.mul_add, Nat.mul_left_comm Z 3 u, Nat.mul_left_comm Z 2 U, Nat.mul_comm U Z, Nat.mul_comm u Z]
        omega

theorem ixA_mem (A : Nat) (i : Nat × Nat) (h : i ∈ IxA A) : i.1 ≤ A ∧ i.2 < A := by
  unfold IxA at h
  obtain ⟨q, hq, hi⟩ := List.mem_flatMap.mp h
  obtain ⟨j, hj, rfl⟩ := List.mem_map.mp hi
  exact ⟨by have := List.mem_range.mp hq; simp; omega, by simpa using hj⟩

section
variable {χ : Type} (X : QT χ)

/-- One family of hits at offset `k` after `X`'s draws. -/
theorem hit_bound (A N R M : Nat) (f : Nat → Bytes)
    (hf : ∀ k, ((List.range R).map (fun y => if f y = k then 1 else 0)).sum * M ≤ R) (k : Nat) (hN : A + k < N)
    (g : Nat × Nat → List Nat → Bytes)
    (hg : ∀ i t c y, i.1 ≤ c → wX X i t ≠ 0 → g i (t.set c y) = g i t) :
    tsum R N (fun t => ((IxA A).map (fun i => wX X i t * (if f (t.getD (i.1+k) 0) = g i t then 1 else 0))).sum) * M
      ≤ R^N * A := by
  refine Nat.le_trans (hitsB_sum R M N f hf (IxA A) (fun i => i.1 + k)
    (fun i hi => by have := (ixA_mem A i hi).1; show i.1 + k < N; omega) (wX X) g
    (fun i _ t y => wX_set X i t _ y (by show i.1 ≤ i.1 + k; omega))
    (fun i _ t y hw => hg i t _ y (by show i.1 ≤ i.1 + k; omega) hw)) ?_
  rw [← tsum_const]
  exact tsum_mono R N (fun t => wX_sum X A t)

variable (v : Variant)

/-- The seed guesses: `X` names each seed at most once per draw. -/
theorem seed_sum (A N R : Nat) (hA : ∀ t, aX X t ≤ A) :
    ((List.range (256^32)).map (fun s => tsum R N (fun t => ind (seedHitX X v s t)))).sum ≤ R^N * A := by
  let G : List Nat → List Nat := fun t => (run t X []).2.map (fun e => toInt e.2.input)
  calc _ ≤ ((List.range (256^32)).map (fun s => tsum R N (fun t => if (G t).contains s then 1 else 0))).sum := by
        apply sum_map_le; intro s hs
        apply tsum_mono; intro t
        by_cases h : seedHitX X v s t
        · obtain ⟨e, he, heq⟩ := h
          have hm : s ∈ G t := List.mem_map.mpr ⟨e, he, by
            rw [heq]; simp only [expReq]; exact be_roundtrip 32 s (List.mem_range.mp hs)⟩
          rw [ind_of ⟨e, he, heq⟩, if_pos (List.contains_iff_mem.mpr hm)]; exact Nat.le_refl 1
        · rw [ind_of_not h]; exact Nat.zero_le _
    _ ≤ tsum R N (fun t => (G t).length) := guess_bound R N _ G
    _ ≤ tsum R N (fun _ => A) := tsum_mono R N (fun t => by simp only [G, List.length_map]; exact hA t)
    _ = R^N * A := tsum_const R A N

/-- **Overlap bound.** Summed over the target's seed `s` (uniform over `256^32`,
    sampled independently of `X`), the overlap tapes are at most
    `R^N · A · (3/256^n + 2/256^32)` of `256^32 · R^N`: an average overlap
    probability of at most `A/2^256 + 2A/2^(8n) + 2A/2^256`, where `A` bounds the
    draws before the target is created. -/
theorem ov_count (A N R : Nat) (hA : ∀ t, aX X t ≤ A) (hN : A + 3 ≤ N)
    (hR : 256^(3*(params v).n) ∣ R) (hR32 : 256^32 ∣ R) :
    ((List.range (256^32)).map (fun s => tsum R N (fun t => ind (Ov X (Ygen v s) t)))).sum * 256^(params v).n ≤
      R^N * A * (3 * 256^(params v).n + 2 * 256^32) := by
  have hg : ∀ (i : Nat × Nat) t c y, i.1 ≤ c → wX X i t ≠ 0 → xReq X i.2 (t.set c y) = xReq X i.2 t :=
    fun i t c y hc hw => xReq_set X i t c y hc hw
  have hP := hit_bound X A N R (256^(params v).n) _ (cnt_pk (params v).n R hR) 0 (by omega)
    (fun i t => (xReq X i.2 t).input) (fun i t c y hc hw => congrArg Request.input (hg i t c y hc hw))
  have hK := hit_bound X A N R (256^(params v).n) _ (cnt_sk (params v).n R hR) 0 (by omega)
    (fun i t => (xReq X i.2 t).input) (fun i t c y hc hw => congrArg Request.input (hg i t c y hc hw))
  have hT := hit_bound X A N R (256^32) _ (cnt_key R hR32) 1 (by omega)
    (fun i t => (xReq X i.2 t).key) (fun i t c y hc hw => congrArg Request.key (hg i t c y hc hw))
  have hF := hit_bound X A N R (256^32) _ (cnt_key R hR32) 2 (by omega)
    (fun i t => (xReq X i.2 t).key) (fun i t c y hc hw => congrArg Request.key (hg i t c y hc hw))
  have hS := seed_sum X v A N R hA
  have h1 : ((List.range (256^32)).map (fun s => tsum R N (fun t => ind (Ov X (Ygen v s) t)))).sum ≤
      ((List.range (256^32)).map (fun s => tsum R N (fun t => ind (seedHitX X v s t)))).sum +
      256^32 * (tsum R N (hitPK X v A) + tsum R N (hitSK X v A) + tsum R N (hitTK X A) + tsum R N (hitPF X A)) := by
    calc _ ≤ ((List.range (256^32)).map (fun s => tsum R N (fun t => ind (seedHitX X v s t)) +
          (tsum R N (hitPK X v A) + tsum R N (hitSK X v A) + tsum R N (hitTK X A) + tsum R N (hitPF X A)))).sum := by
          apply sum_map_le; intro s _
          calc _ ≤ tsum R N (fun t => ind (seedHitX X v s t) + hitPK X v A t + hitSK X v A t + hitTK X A t +
                hitPF X A t) := tsum_mono R N (fun t => ov_incl X v A hA s t)
            _ = _ := by rw [tsum_add, tsum_add, tsum_add, tsum_add]; omega
      _ = _ := by rw [sum_map_add, sum_map_const, List.length_range]
  exact ov_arith _ _ _ _ _ _ _ _ _ h1 hS hP hK hT hF

end

end DSM.Rom
