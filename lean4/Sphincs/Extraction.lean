-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.AddressRange

/- Deterministic forgery extraction, stage 1: primitive break events and
   their extraction from Merkle authentication paths and WOTS chains. No
   probability: each lemma says that a verifying value that differs from the
   honest one exhibits, explicitly, two distinct inputs that one tweakable
   hash maps to the same output under one named address. -/
namespace DSM.Sphincs

/-- Two distinct inputs with equal thash output under the tweak `a`. -/
def ThashCollisionAt (o : Oracle Id) (p : Params) (tk : Bytes) (a : Adrs) : Prop :=
  ∃ x y : Bytes, x ≠ y ∧ thash o p tk a x = thash o p tk a y

/-- A thash collision under one in-range tweak. -/
def ThashCollision (o : Oracle Id) (p : Params) (tk : Bytes) : Prop :=
  ∃ (a : Adrs) (x y : Bytes), a.InRange ∧ x ≠ y ∧ thash o p tk a x = thash o p tk a y

theorem ThashCollisionAt.collision {o : Oracle Id} {p : Params} {tk : Bytes} {a : Adrs}
    (ha : a.InRange) (h : ThashCollisionAt o p tk a) : ThashCollision o p tk := by
  obtain ⟨x, y, hne, he⟩ := h
  exact ⟨a, x, y, ha, hne, he⟩

section
variable {o : Oracle Id} {p : Params} {tk : Bytes}

theorem auth_walk_succ (a : Adrs) (li gi : Nat) (node auth : Bytes) (level r : Nat) :
    authWalk o p tk a li gi node auth level (r+1) =
      authWalk o p tk a (li/2) (gi/2)
        (thash o p tk {a with chain := level+1, hash := gi/2}
          (if li%2 = 0 then node ++ slice auth (level*p.n) p.n
           else slice auth (level*p.n) p.n ++ node))
        auth (level+1) r := rfl

theorem half_pow (gi j : Nat) : gi/2/2^(j+1) = gi/2^(j+1+1) := by
  rw [Nat.div_div_eq_div_mul, Nat.pow_succ 2 (j+1), Nat.mul_comm]

/-- Merkle path extraction, general form. Two walks over the same address,
    indices, level and height, from leaves of equal length, that reach the
    same root, where the leaves differ or the sibling slices differ at some
    visited level, contain a thash collision at a visited node address
    `{a with chain := level+j+1, hash := gi/2^(j+1)}`, `j < remaining`. -/
theorem auth_walk_extract_general (widths : OutputWidths o) (a : Adrs) (A B : Bytes)
    (remaining level li gi : Nat) (x y : Bytes) (hlen : x.length = y.length)
    (hroot : authWalk o p tk a li gi x A level remaining =
      authWalk o p tk a li gi y B level remaining)
    (hdiff : x ≠ y ∨ ∃ j, j < remaining ∧
      slice A ((level+j)*p.n) p.n ≠ slice B ((level+j)*p.n) p.n) :
    ∃ j, j < remaining ∧
      ThashCollisionAt o p tk {a with chain := level+j+1, hash := gi/2^(j+1)} := by
  induction remaining generalizing level li gi x y with
  | zero =>
    have hxy : x = y := hroot
    rcases hdiff with h | ⟨j, hj, _⟩
    · exact absurd hxy h
    · omega
  | succ r ih =>
    rw [auth_walk_succ, auth_walk_succ] at hroot
    have shift : ∀ j, ThashCollisionAt o p tk
        {a with chain := level+1+j+1, hash := gi/2/2^(j+1)} →
        ThashCollisionAt o p tk {a with chain := level+(j+1)+1, hash := gi/2^(j+1+1)} := by
      intro j hc
      rw [half_pow, show level+1+j+1 = level+(j+1)+1 by omega] at hc
      exact hc
    by_cases hin : (if li%2 = 0 then x ++ slice A (level*p.n) p.n
        else slice A (level*p.n) p.n ++ x) =
        (if li%2 = 0 then y ++ slice B (level*p.n) p.n
        else slice B (level*p.n) p.n ++ y)
    · have hxy : x = y ∧ slice A (level*p.n) p.n = slice B (level*p.n) p.n := by
        by_cases hp : li%2 = 0
        · rw [if_pos hp, if_pos hp] at hin
          exact List.append_inj hin hlen
        · rw [if_neg hp, if_neg hp] at hin
          obtain ⟨h1, h2⟩ := List.append_inj' hin hlen
          exact ⟨h2, h1⟩
      obtain ⟨j, hj, hd⟩ : ∃ j, j < r+1 ∧
          slice A ((level+j)*p.n) p.n ≠ slice B ((level+j)*p.n) p.n := by
        rcases hdiff with h | h
        · exact absurd hxy.1 h
        · exact h
      cases j with
      | zero => exact absurd hxy.2 (by simpa using hd)
      | succ j =>
        rw [hin] at hroot
        obtain ⟨k, hk, hc⟩ := ih (level+1) (li/2) (gi/2) _ _ rfl hroot
          (Or.inr ⟨j, by omega, by rw [show level+1+j = level+(j+1) by omega]; exact hd⟩)
        exact ⟨k+1, by omega, shift k hc⟩
    · by_cases hn : thash o p tk {a with chain := level+1, hash := gi/2}
          (if li%2 = 0 then x ++ slice A (level*p.n) p.n else slice A (level*p.n) p.n ++ x) =
        thash o p tk {a with chain := level+1, hash := gi/2}
          (if li%2 = 0 then y ++ slice B (level*p.n) p.n else slice B (level*p.n) p.n ++ y)
      · refine ⟨0, by omega, ?_⟩
        simp only [Nat.add_zero, Nat.zero_add, Nat.pow_one]
        exact ⟨_, _, hin, hn⟩
      · obtain ⟨k, hk, hc⟩ := ih (level+1) (li/2) (gi/2) _ _
          (by rw [thash_width o widths, thash_width o widths]) hroot (Or.inl hn)
        exact ⟨k+1, by omega, shift k hc⟩

/-- Merkle path extraction: distinct equal-length leaves, any two
    authentication paths, same root ⇒ a collision at a visited node. -/
theorem auth_walk_extract (widths : OutputWidths o) (a : Adrs) (A B : Bytes)
    (remaining level li gi : Nat) (x y : Bytes) (hlen : x.length = y.length) (hne : x ≠ y)
    (hroot : authWalk o p tk a li gi x A level remaining =
      authWalk o p tk a li gi y B level remaining) :
    ∃ j, j < remaining ∧
      ThashCollisionAt o p tk {a with chain := level+j+1, hash := gi/2^(j+1)} :=
  auth_walk_extract_general widths a A B remaining level li gi x y hlen hroot (Or.inl hne)

/-- The same at the root level (`authRoot` starts at level 0). -/
theorem auth_root_extract_general (widths : OutputWidths o) (a : Adrs) (A B : Bytes)
    (li gi height : Nat) (x y : Bytes) (hlen : x.length = y.length)
    (hroot : authRoot o p tk a li gi x A height = authRoot o p tk a li gi y B height)
    (hdiff : x ≠ y ∨ ∃ j, j < height ∧ slice A (j*p.n) p.n ≠ slice B (j*p.n) p.n) :
    ∃ j, j < height ∧ ThashCollisionAt o p tk {a with chain := j+1, hash := gi/2^(j+1)} := by
  obtain ⟨j, hj, hc⟩ := auth_walk_extract_general widths a A B height 0 li gi x y hlen hroot
    (by simpa using hdiff)
  exact ⟨j, hj, by simpa using hc⟩

/-- Every node address a walk visits is in range when the walk's address
    fields, top level and global index are. -/
theorem visited_inRange (a : Adrs) (level remaining gi j : Nat)
    (hl : a.layer < 256^4) (ht : a.tree < 256^8) (hk : a.kind < 256^4) (hkp : a.keypair < 256^4)
    (hrem : level + remaining < 256^4) (hg : gi < 256^4) (hj : j < remaining) :
    ({a with chain := level+j+1, hash := gi/2^(j+1)} : Adrs).InRange := by
  have hd : gi/2^(j+1) ≤ gi := Nat.div_le_self _ _
  inrange

/-- Merkle path extraction to an in-range collision. -/
theorem auth_walk_collision (widths : OutputWidths o) (a : Adrs) (A B : Bytes)
    (remaining level li gi : Nat) (x y : Bytes) (hlen : x.length = y.length)
    (hl : a.layer < 256^4) (ht : a.tree < 256^8) (hk : a.kind < 256^4) (hkp : a.keypair < 256^4)
    (hrem : level + remaining < 256^4) (hg : gi < 256^4)
    (hroot : authWalk o p tk a li gi x A level remaining =
      authWalk o p tk a li gi y B level remaining)
    (hdiff : x ≠ y ∨ ∃ j, j < remaining ∧
      slice A ((level+j)*p.n) p.n ≠ slice B ((level+j)*p.n) p.n) :
    ThashCollision o p tk := by
  obtain ⟨j, hj, hc⟩ := auth_walk_extract_general widths a A B remaining level li gi x y hlen hroot hdiff
  exact hc.collision (visited_inRange a level remaining gi j hl ht hk hkp hrem hg hj)

/-- Chain extraction: equal chain outputs from distinct starts give a
    collision at one of the hash positions the chain uses. -/
theorem chain_extract (a : Adrs) (x y : Bytes) (s k : Nat) (hne : x ≠ y)
    (h : chain o p tk a x s k = chain o p tk a y s k) :
    ∃ j, s ≤ j ∧ j < s+k ∧ ThashCollisionAt o p tk {a with hash := j} := by
  induction k generalizing x y s with
  | zero => exact absurd h hne
  | succ k ih =>
    change chain o p tk a (thash o p tk {a with hash := s} x) (s+1) k =
      chain o p tk a (thash o p tk {a with hash := s} y) (s+1) k at h
    by_cases hs : thash o p tk {a with hash := s} x = thash o p tk {a with hash := s} y
    · exact ⟨s, Nat.le_refl _, by omega, x, y, hne, hs⟩
    · obtain ⟨j, hj1, hj2, hc⟩ := ih _ _ (s+1) hs h
      exact ⟨j, by omega, by omega, hc⟩

/-- The two-way form used by WOTS extraction. -/
theorem chain_extract_or (a : Adrs) (x y : Bytes) (s k : Nat)
    (h : chain o p tk a x s k = chain o p tk a y s k) :
    x = y ∨ ∃ j, s ≤ j ∧ j < s+k ∧ ThashCollisionAt o p tk {a with hash := j} := by
  by_cases hne : x = y
  · exact Or.inl hne
  · exact Or.inr (chain_extract a x y s k hne h)
end

#print axioms auth_walk_extract_general
#print axioms auth_walk_extract
#print axioms auth_root_extract_general
#print axioms auth_walk_collision
#print axioms chain_extract
#print axioms chain_extract_or
end DSM.Sphincs
