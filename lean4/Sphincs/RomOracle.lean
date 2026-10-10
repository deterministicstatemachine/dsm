-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomTape
import Sphincs.Proofs

/- The random-oracle model (ROM) with explicit oracle access and query counts.
   A program with oracle access is a query tree `QT`: every primitive request
   is an explicit `ask`, tagged with who asks (true = the adversary's side,
   including verification of its forgery; false = the honest challenger).
   `Within T q` bounds the number of queries on every path. `run` answers the
   tree from a lazily sampled random oracle: the i-th fresh request is answered
   by tape entry i truncated to its output length, a repeated request by its
   first answer. One oracle answers every request, so requests of different
   roles (keyed BLAKE3 under different keys, derive_key contexts, the h_msg
   XOF, ChaCha expansion) are independent random functions: this is the
   idealization, not a property of BLAKE3. -/
namespace DSM.Rom
open DSM.Sphincs

inductive QT (α : Type) where
  | done (a : α)
  | ask (adv : Bool) (r : Request) (k : Bytes → QT α)

def QT.bind {α β : Type} : QT α → (α → QT β) → QT β
  | .done a, f => f a
  | .ask g r k, f => .ask g r (fun b => QT.bind (k b) f)

instance : Monad QT where
  pure := .done
  bind := QT.bind

/-- Every path asks at most `q` queries. -/
def QT.Within {α : Type} : QT α → Nat → Prop
  | .done _, _ => True
  | .ask _ _ _, 0 => False
  | .ask _ _ k, q+1 => ∀ b, QT.Within (k b) q

abbrev Draw := Bool × Request

def noDraw : Draw := (false, ⟨0, "", [], [], 0⟩)

/-- Index of the first draw of request `r`. -/
def findDraw : List Draw → Request → Option Nat
  | [], _ => none
  | e :: d, r => if e.2 == r then some 0 else (findDraw d r).map (· + 1)

theorem findDraw_lt : ∀ (d : List Draw) (r : Request) (i : Nat), findDraw d r = some i → i < d.length
  | [], _, _, h => by simp [findDraw] at h
  | e :: d, r, i, h => by
    simp only [findDraw] at h
    split at h
    · simp at h; subst h; simp
    · cases h' : findDraw d r with
      | none => rw [h'] at h; simp at h
      | some k =>
        rw [h'] at h; simp at h; subst h
        have := findDraw_lt d r k h'
        simp; omega

/-- Lazy random oracle on tape `tape`; returns the result and every fresh draw. -/
def run {α : Type} (tape : List Nat) : QT α → List Draw → α × List Draw
  | .done a, d => (a, d)
  | .ask g r k, d => match findDraw d r with
    | some i => run tape (k (be r.outLen (tape.getD i 0))) d
    | none => run tape (k (be r.outLen (tape.getD d.length 0))) (d ++ [(g, r)])

theorem run_extends {α : Type} (tape : List Nat) : ∀ (T : QT α) (d : List Draw),
    ∃ e, (run tape T d).2 = d ++ e
  | .done _, d => ⟨[], by simp [run]⟩
  | .ask g r k, d => by
    simp only [run]
    split
    · exact run_extends tape _ d
    · obtain ⟨e, he⟩ := run_extends tape (k (be r.outLen (tape.getD d.length 0))) (d ++ [(g, r)])
      exact ⟨[(g, r)] ++ e, by rw [he]; simp⟩

theorem run_draws_le {α : Type} (tape : List Nat) : ∀ (T : QT α) (q : Nat) (d : List Draw),
    T.Within q → (run tape T d).2.length ≤ d.length + q
  | .done _, q, d, _ => by simp [run]
  | .ask _ _ _, 0, _, h => absurd h (by simp [QT.Within])
  | .ask g r k, q+1, d, h => by
    simp only [run]
    split
    · next i _ =>
      have := run_draws_le tape (k (be r.outLen (tape.getD i 0))) q d (h _); omega
    · have := run_draws_le tape (k (be r.outLen (tape.getD d.length 0))) q (d ++ [(g, r)]) (h _)
      simp only [List.length_append, List.length_singleton] at this; omega

theorem take_extend {d e : List Draw} {j : Nat} (h : j + 1 ≤ d.length) :
    (d ++ e).take (j+1) = d.take (j+1) := List.take_append_of_le_length h

/-- The draws up to index `j` depend only on the first `j` tape entries. -/
theorem run_prefix {α : Type} (t t' : List Nat) (j : Nat) (ht : t.take j = t'.take j) :
    ∀ (T : QT α) (d : List Draw), (run t T d).2.take (j+1) = (run t' T d).2.take (j+1)
  | .done _, d => rfl
  | .ask g r k, d => by
    simp only [run]
    have eq_at : ∀ i, i < j → t.getD i 0 = t'.getD i 0 := by
      intro i hi
      rw [← getD_take hi, ← getD_take (t := t') hi, ht]
    split
    · next i hi =>
      have hlt := findDraw_lt d r i hi
      by_cases hij : i < j
      · rw [eq_at i hij]; exact run_prefix t t' j ht _ d
      · obtain ⟨e, he⟩ := run_extends t (k (be r.outLen (t.getD i 0))) d
        obtain ⟨e', he'⟩ := run_extends t' (k (be r.outLen (t'.getD i 0))) d
        rw [he, he', take_extend (by omega), take_extend (by omega)]
    · by_cases hj : d.length < j
      · rw [eq_at d.length hj]; exact run_prefix t t' j ht _ _
      · obtain ⟨e, he⟩ := run_extends t (k (be r.outLen (t.getD d.length 0))) (d ++ [(g, r)])
        obtain ⟨e', he'⟩ := run_extends t' (k (be r.outLen (t'.getD d.length 0))) (d ++ [(g, r)])
        have hl : j + 1 ≤ (d ++ [(g, r)]).length := by simp; omega
        rw [he, he', take_extend (d := d ++ [(g, r)]) (e := e) hl,
          take_extend (d := d ++ [(g, r)]) (e := e') hl]

/-! Partners: pairs of fresh draws the bad event compares. -/

/-- Earlier draws that `P` pairs with draw `j`. -/
def pairsList (P : Draw → Draw → Bool) (D : List Draw) (j : Nat) : List Nat :=
  if j < D.length then (List.range j).filter (fun i => P (D.getD i noDraw) (D.getD j noDraw)) else []

theorem getD_take_draw {D : List Draw} {i j : Nat} (h : i < j) :
    (D.take j).getD i noDraw = D.getD i noDraw := by
  simp only [List.getD_eq_getElem?_getD, List.getElem?_take, h, if_true]

theorem pairsList_take (P : Draw → Draw → Bool) (D : List Draw) (j : Nat) :
    pairsList P (D.take (j+1)) j = pairsList P D j := by
  unfold pairsList
  have hlen : (j < (D.take (j+1)).length) ↔ j < D.length := by simp; omega
  by_cases h : j < D.length
  · rw [if_pos (hlen.mpr h), if_pos h]
    apply List.filter_congr
    intro i hi
    have hi' : i < j := List.mem_range.mp hi
    rw [getD_take_draw (by omega : i < j+1), getD_take_draw (by omega : j < j+1)]
  · rw [if_neg (fun h' => h (hlen.mp h')), if_neg h]

/-- The collision event: two fresh draws that `P` pairs have equal truncated
    answers mod `M`. -/
def collides (P : Draw → Draw → Bool) (M : Nat) (D : List Draw) (t : List Nat) : Bool :=
  (List.range D.length).any (fun j => (pairsList P D j).any
    (fun i => t.getD j 0 % M == t.getD i 0 % M))

/-- Generic ROM collision bound. For a query tree with at most `N` queries,
    if on every tape the draws contain at most `B` partnered pairs, then a
    partnered pair has answers agreeing mod `M` on at most a `B / M` fraction
    of tapes (`M ∣ R`, tape entries uniform in `[0, R)`). -/
theorem rom_partner_bound {α : Type} (R M N B : Nat) (hM : 0 < M) (hMR : M ∣ R)
    (T : QT α) (hT : T.Within N) (P : Draw → Draw → Bool)
    (hB : ∀ t : List Nat, ((List.range N).map (fun j => (pairsList P (run t T []).2 j).length)).sum ≤ B) :
    tsum R N (fun t => if collides P M (run t T []).2 t then 1 else 0) * M ≤ R^N * B := by
  let S : Nat → List Nat → List Nat := fun j p => pairsList P (run p T []).2 j
  have agree : ∀ (t : List Nat) (j : Nat), S j (t.take j) = pairsList P (run t T []).2 j := by
    intro t j
    have hp := run_prefix (t.take j) t j (by rw [List.take_take, Nat.min_self]) T []
    show pairsList P (run (t.take j) T []).2 j = _
    rw [← pairsList_take, hp, pairsList_take]
  have hS : ∀ j p i, i ∈ S j p → i < j := by
    intro j p i hi
    simp only [S, pairsList] at hi
    split at hi
    · exact List.mem_range.mp (List.mem_filter.mp hi).1
    · simp at hi
  have hB' : ∀ t : List Nat, ((List.range N).map (fun j => (S j (t.take j)).length)).sum ≤ B := by
    intro t; simp only [agree]; exact hB t
  have main := partner_hits R M N B hM hMR S hS hB'
  refine Nat.le_trans (Nat.mul_le_mul_right _ (tsum_mono R N ?_)) main
  intro t
  split
  · next h =>
    have hlen : (run t T []).2.length ≤ N := by
      have := run_draws_le t T N [] hT; simpa using this
    obtain ⟨j, hj, hany⟩ := List.any_eq_true.mp h
    have hjN : j < N := Nat.lt_of_lt_of_le (List.mem_range.mp hj) hlen
    have : (List.range N).any (fun j => (S j (t.take j)).any
        (fun i => t.getD j 0 % M == t.getD i 0 % M)) = true :=
      List.any_eq_true.mpr ⟨j, List.mem_range.mpr hjN, by rw [agree]; exact hany⟩
    rw [if_pos this]
    exact Nat.le_refl 1
  · exact Nat.zero_le _

#print axioms run_prefix
#print axioms rom_partner_bound
end DSM.Rom
