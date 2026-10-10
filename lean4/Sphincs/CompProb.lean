-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.MultiKey

/- Modular proof, milestone 2 (part 1): exact algebra of `FiniteExperiment`.

   The computational games of `CompGames` sample several independent values
   (a public parameter, challenger tapes, the adversary's coins). Reductions
   and restatements reorder and regroup that randomness. This file gives the
   exact tools for it, over the existing ticket semantics of
   `SecurityGames.lean`: success counts are sums over tickets (`sum`), a
   product's sum is an iterated sum (`product_sum`), and iterated sums
   commute (`rsum_comm`). It also proves that `uniformBytes (n+m)` is the
   concatenation of independent `uniformBytes n` and `uniformBytes m`
   (`uniform_split_sum`), and the fixed-prefix lemma of the modular map (I3):
   for each fixed `pp` of n bytes, `x ↦ F (pp ++ x)` of a uniformly random
   function `F` on (n+w)-byte inputs is a uniformly random function on w-byte
   inputs (`rf_prefix_sum`, `rf_prefix_joint`).

   No cryptographic assumption, axiom or `sorry`. -/
namespace DSM.Sphincs.Security

/-! ## Sums over a range -/

def rsum (N : Nat) (F : Nat → Nat) : Nat := ((List.range N).map F).sum

theorem rsum_zero (F : Nat → Nat) : rsum 0 F = 0 := rfl

theorem rsum_succ (N : Nat) (F : Nat → Nat) : rsum (N+1) F = rsum N F + F N := by
  simp [rsum, List.range_succ, List.sum_append_nat]

theorem rsum_congr {N : Nat} {F G : Nat → Nat} (h : ∀ i, i < N → F i = G i) :
    rsum N F = rsum N G := by
  induction N with
  | zero => rfl
  | succ N ih => rw [rsum_succ, rsum_succ, ih (fun i hi => h i (by omega)), h N (by omega)]

theorem rsum_add (A : Nat) (F : Nat → Nat) : ∀ B, rsum (A+B) F = rsum A F + rsum B (fun j => F (A+j))
  | 0 => rfl
  | B+1 => by
    show rsum ((A+B)+1) F = _
    rw [rsum_succ, rsum_add A F B, rsum_succ]; omega

theorem rsum_fun_add (N : Nat) (F G : Nat → Nat) :
    rsum N F + rsum N G = rsum N (fun i => F i + G i) := by
  induction N with
  | zero => rfl
  | succ N ih => rw [rsum_succ, rsum_succ, rsum_succ, ← ih]; omega

theorem rsum_const (N k : Nat) : rsum N (fun _ => k) = N * k := by
  induction N with
  | zero => simp [rsum_zero]
  | succ N ih => rw [rsum_succ, ih, Nat.succ_mul]

theorem rsum_mul_left (c N : Nat) (F : Nat → Nat) : c * rsum N F = rsum N (fun i => c * F i) := by
  induction N with
  | zero => simp [rsum_zero]
  | succ N ih => rw [rsum_succ, rsum_succ, Nat.mul_add, ih]

theorem rsum_le {N : Nat} {F G : Nat → Nat} (h : ∀ i, i < N → F i ≤ G i) : rsum N F ≤ rsum N G := by
  induction N with
  | zero => exact Nat.le_refl _
  | succ N ih =>
    rw [rsum_succ, rsum_succ]
    exact Nat.add_le_add (ih (fun i hi => h i (by omega))) (h N (by omega))

/-- Fubini for a range of length `A*B`: ticket `a*B+b`. -/
theorem rsum_mul (B : Nat) (F : Nat → Nat) : ∀ A,
    rsum (A*B) F = rsum A (fun a => rsum B (fun b => F (a*B+b)))
  | 0 => by simp [rsum_zero]
  | A+1 => by rw [Nat.succ_mul, rsum_add, rsum_mul B F A, rsum_succ]

theorem rsum_comm (A B : Nat) (F : Nat → Nat → Nat) :
    rsum A (fun a => rsum B (fun b => F a b)) = rsum B (fun b => rsum A (fun a => F a b)) := by
  induction A with
  | zero => simp [rsum_zero, rsum_const]
  | succ A ih => rw [rsum_succ, ih, rsum_fun_add]; exact rsum_congr (fun b _ => (rsum_succ A _).symm)

/-! ## Sums over a finite experiment -/

/-- The sum of `g` over the experiment's tickets. -/
def FiniteExperiment.sum {α : Type} (S : FiniteExperiment α) (g : α → Nat) : Nat :=
  rsum S.cardinality (fun i => if h : i < S.cardinality then g (S.sample ⟨i, h⟩) else 0)

theorem ofFn_map_sum {α : Type} (g : α → Nat) : ∀ (N : Nat) (s : Fin N → α),
    ((List.ofFn s).map g).sum = rsum N (fun i => if h : i < N then g (s ⟨i, h⟩) else 0)
  | 0, _ => by simp [rsum_zero]
  | N+1, s => by
    rw [List.ofFn_succ_last, List.map_append, List.sum_append_nat, ofFn_map_sum g N, rsum_succ]
    simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, Nat.add_zero,
      Nat.lt_succ_self, dif_pos]
    congr 1
    exact rsum_congr (fun i hi => by simp only [hi, dif_pos, Nat.lt_succ_of_lt hi]; rfl)

theorem eventMass_sum {α : Type} (e : α → Bool) :
    ∀ xs : List α, eventMass xs e = (xs.map (fun x => if e x then 1 else 0)).sum
  | [] => rfl
  | x :: xs => by simp only [eventMass, List.map_cons, List.sum_cons, eventMass_sum e xs]

theorem numerator_sum {α : Type} (S : FiniteExperiment α) (e : α → Bool) :
    (probability S e).numerator = S.sum (fun x => if e x then 1 else 0) := by
  change eventMass (List.ofFn S.sample) e = _
  rw [eventMass_sum, ofFn_map_sum]; rfl

theorem sample_congr {α : Type} (S : FiniteExperiment α) {i j : Nat} (hi : i < S.cardinality)
    (hj : j < S.cardinality) (h : i = j) : S.sample ⟨i, hi⟩ = S.sample ⟨j, hj⟩ := by
  subst h; rfl

theorem sum_congr {α : Type} (S : FiniteExperiment α) {g g' : α → Nat}
    (h : ∀ i : Fin S.cardinality, g (S.sample i) = g' (S.sample i)) : S.sum g = S.sum g' :=
  rsum_congr (fun i hi => by simp only [hi, dif_pos]; exact h ⟨i, hi⟩)

theorem sum_le {α : Type} (S : FiniteExperiment α) {g g' : α → Nat}
    (h : ∀ i : Fin S.cardinality, g (S.sample i) ≤ g' (S.sample i)) : S.sum g ≤ S.sum g' :=
  rsum_le (fun i hi => by simp only [hi, dif_pos]; exact h ⟨i, hi⟩)

theorem map_sum {α β : Type} (S : FiniteExperiment α) (f : α → β) (g : β → Nat) :
    (S.map f).sum g = S.sum (fun x => g (f x)) := rfl

theorem sum_const {α : Type} (S : FiniteExperiment α) (k : Nat) :
    S.sum (fun _ => k) = S.cardinality * k := by
  unfold FiniteExperiment.sum
  rw [← rsum_const]; exact rsum_congr (fun i hi => by simp [hi])

theorem sum_fun_add {α : Type} (S : FiniteExperiment α) (g g' : α → Nat) :
    S.sum g + S.sum g' = S.sum (fun x => g x + g' x) := by
  unfold FiniteExperiment.sum
  rw [rsum_fun_add]; exact rsum_congr (fun i hi => by simp [hi])

theorem sum_mul_left {α : Type} (S : FiniteExperiment α) (c : Nat) (g : α → Nat) :
    c * S.sum g = S.sum (fun x => c * g x) := by
  unfold FiniteExperiment.sum
  rw [rsum_mul_left]; exact rsum_congr (fun i hi => by simp [hi])

/-- Fubini for `independentProduct`. -/
theorem product_sum {α β : Type} (a : FiniteExperiment α) (b : FiniteExperiment β)
    (g : α × β → Nat) :
    (independentProduct a b).sum g = a.sum (fun x => b.sum (fun y => g (x, y))) := by
  unfold FiniteExperiment.sum
  change rsum (a.cardinality * b.cardinality) _ = _
  rw [rsum_mul]
  apply rsum_congr; intro i hi
  simp only [hi, dif_pos]
  apply rsum_congr; intro j hj
  have hb := b.positive
  have lt : i * b.cardinality + j < a.cardinality * b.cardinality := by
    have := Nat.mul_le_mul_right b.cardinality (Nat.succ_le_of_lt hi)
    rw [Nat.succ_mul] at this; omega
  have hdiv : (i * b.cardinality + j) / b.cardinality = i := by
    rw [Nat.add_comm, Nat.add_mul_div_right _ _ hb, Nat.div_eq_of_lt hj, Nat.zero_add]
  have hmod : (i * b.cardinality + j) % b.cardinality = j := by
    rw [Nat.add_comm, Nat.add_mul_mod_self_right, Nat.mod_eq_of_lt hj]
  have lt' : i * b.cardinality + j < (independentProduct a b).cardinality := lt
  rw [dif_pos lt', dif_pos hj]
  show g (a.sample _, b.sample _) = _
  rw [sample_congr a _ hi hdiv, sample_congr b _ hj hmod]

/-- The order of independent samples does not matter. -/
theorem product_comm_sum {α β : Type} (a : FiniteExperiment α) (b : FiniteExperiment β)
    (g : α × β → Nat) :
    (independentProduct a b).sum g = (independentProduct b a).sum (fun p => g (p.2, p.1)) := by
  rw [product_sum, product_sum]
  let G : Nat → Nat → Nat := fun i j => if h : i < a.cardinality then
    if h' : j < b.cardinality then g (a.sample ⟨i, h⟩, b.sample ⟨j, h'⟩) else 0 else 0
  have L : a.sum (fun x => b.sum (fun y => g (x, y))) =
      rsum a.cardinality (fun i => rsum b.cardinality (fun j => G i j)) :=
    rsum_congr (fun i hi => by simp only [G, hi, dif_pos]; rfl)
  have R : b.sum (fun x => a.sum (fun y => g (y, x))) =
      rsum b.cardinality (fun j => rsum a.cardinality (fun i => G i j)) := by
    apply rsum_congr; intro j hj
    simp only [hj, dif_pos]
    apply rsum_congr; intro i hi
    simp only [G, hi, hj, dif_pos]
  rw [L, R, rsum_comm]

theorem product_assoc_sum {α β γ : Type} (a : FiniteExperiment α) (b : FiniteExperiment β)
    (c : FiniteExperiment γ) (g : (α × β) × γ → Nat) :
    (independentProduct (independentProduct a b) c).sum g =
      (independentProduct a (independentProduct b c)).sum (fun p => g ((p.1, p.2.1), p.2.2)) := by
  rw [product_sum, product_sum, product_sum]
  apply sum_congr; intro i
  rw [product_sum]

/-- Two probabilities are equal when their counts and ticket numbers are. -/
theorem probability_ext {p q : Probability} (h1 : p.numerator = q.numerator)
    (h2 : p.denominator = q.denominator) : p = q := by
  cases p; cases q; simp only at h1 h2; subst h1; subst h2; rfl

/-- Equal as rationals: the cross-multiplied form used throughout. -/
def Probability.same (p q : Probability) : Prop := p.numerator * q.denominator = q.numerator * p.denominator

theorem gap_of_same {a a' b b' : Probability} (ha : a.same a') (hb : b.same b') :
    gapNumerator a b * (a'.denominator * b'.denominator) =
      gapNumerator a' b' * (a.denominator * b.denominator) := by
  unfold Probability.same at ha hb
  unfold gapNumerator
  have e1 : a.numerator * b.denominator * (a'.denominator * b'.denominator) =
      a'.numerator * b'.denominator * (a.denominator * b.denominator) := by
    calc a.numerator * b.denominator * (a'.denominator * b'.denominator)
        = (a.numerator * a'.denominator) * (b.denominator * b'.denominator) := by ac_rfl
      _ = (a'.numerator * a.denominator) * (b.denominator * b'.denominator) := by rw [ha]
      _ = a'.numerator * b'.denominator * (a.denominator * b.denominator) := by ac_rfl
  have e2 : b.numerator * a.denominator * (a'.denominator * b'.denominator) =
      b'.numerator * a'.denominator * (a.denominator * b.denominator) := by
    calc b.numerator * a.denominator * (a'.denominator * b'.denominator)
        = (b.numerator * b'.denominator) * (a.denominator * a'.denominator) := by ac_rfl
      _ = (b'.numerator * b.denominator) * (a.denominator * a'.denominator) := by rw [hb]
      _ = b'.numerator * a'.denominator * (a.denominator * b.denominator) := by ac_rfl
  rw [Nat.add_mul, Nat.sub_mul, Nat.sub_mul, e1, e2, Nat.add_mul, Nat.sub_mul, Nat.sub_mul]

/-! ## Byte strings: splitting a uniform string -/

theorem be_split (n : Nat) : ∀ (m i : Nat), be (n+m) i = be n (i / 256^m) ++ be m (i % 256^m)
  | 0, i => by simp [be]
  | m+1, i => by
    show be ((n+m)+1) i = _
    simp only [be]
    rw [be_split n m (i/256), List.append_assoc]
    have p1 : i / 256 / 256^m = i / 256^(m+1) := by
      rw [Nat.div_div_eq_div_mul, Nat.pow_succ, Nat.mul_comm]
    have p2 : i / 256 % 256^m = i % 256^(m+1) / 256 := by
      rw [Nat.pow_succ, Nat.mul_comm, Nat.mod_mul_right_div_self]
    have p3 : i % 256^(m+1) % 256 = i % 256 :=
      Nat.mod_mod_of_dvd _ ⟨256^m, by rw [Nat.pow_succ, Nat.mul_comm]⟩
    rw [p1, p2, p3]

/-- `uniformBytes (n+m)` is `uniformBytes n` and an independent `uniformBytes m`,
    concatenated. -/
theorem uniform_split_sum (n m : Nat) (g : Bytes → Nat) :
    (uniformBytes (n+m)).sum (fun x => g x.val) =
      (independentProduct (uniformBytes n) (uniformBytes m)).sum (fun p => g (p.1.val ++ p.2.val)) := by
  rw [product_sum]
  unfold FiniteExperiment.sum
  change rsum (256^(n+m)) (fun i => if h : i < 256^(n+m) then g (be (n+m) i) else 0) = _
  rw [Nat.pow_add, rsum_mul]
  apply rsum_congr; intro x hx
  change _ = (if h : x < 256^n then rsum (256^m) (fun j => if h : j < 256^m then
    g (be n x ++ be m j) else 0) else 0)
  simp only [hx, dif_pos]
  apply rsum_congr; intro y hy
  have hB : 0 < 256^m := Nat.pow_pos (by decide)
  have lt : x * 256^m + y < 256^n * 256^m := by
    have := Nat.mul_le_mul_right (256^m) (Nat.succ_le_of_lt hx)
    rw [Nat.succ_mul] at this; omega
  have hdiv : (x * 256^m + y) / 256^m = x := by
    rw [Nat.add_comm, Nat.add_mul_div_right _ _ hB, Nat.div_eq_of_lt hy, Nat.zero_add]
  have hmod : (x * 256^m + y) % 256^m = y := by
    rw [Nat.add_comm, Nat.add_mul_mod_self_right, Nat.mod_eq_of_lt hy]
  simp only [lt, hy, dif_pos]
  rw [be_split, hdiv, hmod]

theorem sum_comm {α β : Type} (a : FiniteExperiment α) (b : FiniteExperiment β) (g : α → β → Nat) :
    a.sum (fun x => b.sum (fun y => g x y)) = b.sum (fun y => a.sum (fun x => g x y)) := by
  have h := product_comm_sum a b (fun p => g p.1 p.2)
  rw [product_sum, product_sum] at h
  exact h

theorem sum_map_product {β γ δ : Type} (B : FiniteExperiment β) (C : FiniteExperiment γ)
    (h : β × γ → δ) (g : δ → Nat) :
    ((independentProduct B C).map h).sum g = B.sum (fun b => C.sum (fun c => g (h (b, c)))) :=
  product_sum B C (fun p => g (h p))

/-- Splitting a uniform string into two independent uniform halves. -/
theorem split_sum (n m : Nat) (g : Bytes → Nat) :
    (uniformBytes (n+m)).sum (fun x => g x.val) =
      (uniformBytes n).sum (fun x => (uniformBytes m).sum (fun y => g (x.val ++ y.val))) := by
  rw [uniform_split_sum, product_sum]

/-! ## The fixed-prefix lemma for random functions (map I3) -/

theorem toInt_append (a : Bytes) : ∀ b : Bytes, toInt (a ++ b) = toInt a * 256^b.length + toInt b := by
  intro b
  apply snoc_induction (fun b => toInt (a ++ b) = toInt a * 256^b.length + toInt b) ?_ ?_ b
  · simp [toInt]
  · intro b x ih
    rw [← List.append_assoc, toInt_snoc, toInt_snoc, ih, List.length_append, List.length_singleton,
      Nat.pow_succ, ← Nat.mul_assoc]
    have : toInt a * 256 ^ b.length * 256 = 256 * (toInt a * 256 ^ b.length) := Nat.mul_comm _ _
    rw [this]; omega

/-- Ticket `i` of `randomFunction inLen outLen`, as a function. -/
def rfAt (inLen outLen i : Nat) : Bytes → Nat → Bytes := fun x len =>
  if x.length = inLen ∧ len = outLen then
    be outLen (i / (256^outLen)^(toInt x) % 256^outLen) else []

theorem rf_sum (inLen outLen : Nat) (g : (Bytes → Nat → Bytes) → Nat) :
    (randomFunction inLen outLen).sum g =
      rsum ((256^outLen)^(256^inLen)) (fun i => g (rfAt inLen outLen i)) :=
  rsum_congr (fun i hi => by
    have hi' : i < (256^outLen)^(256^inLen) := hi
    change (if h : i < (256^outLen)^(256^inLen) then _ else 0) = _
    rw [dif_pos hi']; rfl)

/-- `x ↦ F (pp ++ x)`. -/
def restrictPrefix (pp : Bytes) (F : Bytes → Nat → Bytes) : Bytes → Nat → Bytes :=
  fun x len => F (pp ++ x) len

theorem digit_block (B T c t hi mid lo : Nat) (hB : 0 < B) (ht : t < T) (hlo : lo < B^c) :
    ((hi * B^T + mid) * B^c + lo) / B^(c+t) % B = mid / B^t % B := by
  have hc : 0 < B^c := Nat.pow_pos hB
  have htp : 0 < B^t := Nat.pow_pos hB
  have e1 : ((hi * B^T + mid) * B^c + lo) / B^c = hi * B^T + mid := by
    rw [Nat.add_comm, Nat.add_mul_div_right _ _ hc, Nat.div_eq_of_lt hlo, Nat.zero_add]
  rw [Nat.pow_add, ← Nat.div_div_eq_div_mul, e1]
  have hT : B^T = B^(T-t-1) * B * B^t := by
    rw [← Nat.pow_succ, ← Nat.pow_add]; congr 1; omega
  have key : hi * B^T + mid = mid + (hi * B^(T-t-1) * B) * B^t := by rw [hT]; ac_rfl
  rw [key, Nat.add_mul_div_right _ _ htp, Nat.add_mul_mod_self_right]

theorem rf_prefix_point (n w o : Nat) (pp : Bytes) (hpp : pp.length = n) (hi mid lo : Nat)
    (hlo : lo < (256^o)^(toInt pp * 256^w)) :
    restrictPrefix pp (rfAt (n+w) o ((hi * (256^o)^(256^w) + mid) * (256^o)^(toInt pp * 256^w) + lo)) =
      rfAt w o mid := by
  funext x len
  unfold restrictPrefix rfAt
  by_cases hx : x.length = w
  · have hl : (pp ++ x).length = n + w := by simp [hpp, hx]
    by_cases hlen : len = o
    · simp only [hl, hx, hlen, and_self, if_true]
      rw [toInt_append, hx, digit_block _ _ _ _ _ _ _ (Nat.pow_pos (by decide)) _ hlo]
      have := toInt_bound x; rw [hx] at this; exact this
    · simp [hlen]
  · have hl : ¬((pp ++ x).length = n + w ∧ len = o) := by simp [hpp]; omega
    have hl2 : ¬(x.length = w ∧ len = o) := by simp [hx]
    rw [if_neg hl, if_neg hl2]

/-- For a fixed `pp` of `n` bytes, `x ↦ F (pp ++ x)` of a uniformly random
    function on `(n+w)`-byte inputs is a uniformly random function on `w`-byte
    inputs: every ticket of the latter is hit by the same number of tickets. -/
theorem rf_prefix_sum (n w o : Nat) (pp : Bytes) (hpp : pp.length = n)
    (g : (Bytes → Nat → Bytes) → Nat) :
    (randomFunction (n+w) o).sum (fun F => g (restrictPrefix pp F)) =
      (256^o)^(256^(n+w) - 256^w) * (randomFunction w o).sum g := by
  rw [rf_sum, rf_sum]
  have hP : toInt pp < 256^n := by have := toInt_bound pp; rwa [hpp] at this
  have hT : 0 < 256^w := Nat.pow_pos (by decide)
  have hcT : toInt pp * 256^w + 256^w ≤ 256^(n+w) := by
    rw [Nat.pow_add]
    have := Nat.mul_le_mul_right (256^w) (Nat.succ_le_of_lt hP)
    rw [Nat.succ_mul] at this; exact this
  have split : (256^o)^(256^(n+w)) =
      ((256^o)^(256^(n+w) - toInt pp * 256^w - 256^w) * (256^o)^(256^w)) *
        (256^o)^(toInt pp * 256^w) := by
    rw [← Nat.pow_add, ← Nat.pow_add]; congr 1; omega
  have expo : (256^o)^(256^(n+w) - 256^w) =
      (256^o)^(256^(n+w) - toInt pp * 256^w - 256^w) * (256^o)^(toInt pp * 256^w) := by
    rw [← Nat.pow_add]; congr 1; omega
  rw [split, rsum_mul, rsum_mul, expo]
  have inner : ∀ hi mid, rsum ((256^o)^(toInt pp * 256^w)) (fun lo => g (restrictPrefix pp
      (rfAt (n+w) o ((hi * (256^o)^(256^w) + mid) * (256^o)^(toInt pp * 256^w) + lo)))) =
      (256^o)^(toInt pp * 256^w) * g (rfAt w o mid) := by
    intro hi mid
    rw [rsum_congr (G := fun _ => g (rfAt w o mid))
      (fun lo hlo => by rw [rf_prefix_point n w o pp hpp hi mid lo hlo]), rsum_const]
  rw [rsum_congr (G := fun _ => (256^o)^(toInt pp * 256^w) *
      rsum ((256^o)^(256^w)) (fun mid => g (rfAt w o mid)))
    (fun hi _ => by rw [rsum_congr (fun mid _ => inner hi mid)]; exact (rsum_mul_left _ _ _).symm),
    rsum_const, Nat.mul_assoc]

/-- The joint form: a uniform `pp` together with the restriction of a random
    function on `pp ‖ x` is distributed as a uniform `pp` with an independent
    random function on `x`. The two probabilities are equal as rationals. -/
theorem rf_prefix_joint (n w o : Nat) (e : Bytes → (Bytes → Nat → Bytes) → Bool) :
    (probability (independentProduct (uniformBytes n) (randomFunction (n+w) o))
        (fun p => e p.1.val (restrictPrefix p.1.val p.2))).same
      (probability (independentProduct (uniformBytes n) (randomFunction w o))
        (fun p => e p.1.val p.2)) := by
  unfold Probability.same
  have L : (probability (independentProduct (uniformBytes n) (randomFunction (n+w) o))
        (fun p => e p.1.val (restrictPrefix p.1.val p.2))).numerator =
      (256^o)^(256^(n+w) - 256^w) * (probability (independentProduct (uniformBytes n)
        (randomFunction w o)) (fun p => e p.1.val p.2)).numerator := by
    rw [numerator_sum, numerator_sum, product_sum, product_sum, sum_mul_left]
    exact sum_congr _ (fun i => rf_prefix_sum n w o _ ((uniformBytes n).sample i).property
      (fun G => if e ((uniformBytes n).sample i).val G then 1 else 0))
  rw [L]
  change _ * (256^n * (256^o)^(256^w)) = _ * (256^n * (256^o)^(256^(n+w)))
  have : (256^o)^(256^(n+w)) = (256^o)^(256^(n+w) - 256^w) * (256^o)^(256^w) := by
    rw [← Nat.pow_add]; congr 1
    have : 256^w ≤ 256^(n+w) := Nat.pow_le_pow_right (by decide) (by omega)
    omega
  rw [this]; ac_rfl

/-! ## Challenger tapes -/

/-- `q` independent samples of `S`: a challenger's tape of fresh values, one
    per oracle query (EasyCrypt samples them lazily; drawing them up front is
    the same distribution, since each is used at most once). -/
def FiniteExperiment.tape {α : Type} (S : FiniteExperiment α) : Nat → FiniteExperiment (List α)
  | 0 => ⟨1, by decide, fun _ => []⟩
  | q+1 => (independentProduct S (S.tape q)).map (fun p => p.1 :: p.2)

theorem tape_length {α : Type} (S : FiniteExperiment α) :
    ∀ (q : Nat) (i : Fin (S.tape q).cardinality), ((S.tape q).sample i).length = q
  | 0, _ => rfl
  | q+1, i => by
    change (_ :: _).length = q + 1
    rw [List.length_cons]
    exact congrArg (· + 1) (tape_length S q _)

#print axioms toInt_append
#print axioms rf_prefix_sum
#print axioms rf_prefix_joint

#print axioms product_sum
#print axioms product_comm_sum
#print axioms product_assoc_sum
#print axioms uniform_split_sum
#print axioms gap_of_same
end DSM.Sphincs.Security
