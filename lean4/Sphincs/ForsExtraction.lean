-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.HtExtraction

/- Forgery extraction, stage 2, FORS. A forged FORS signature of `md'` at
   hypertree leaf (tree, leaf) whose reconstructed public key is the honest
   one either exhibits a thash collision at an honest FORS address (root
   compression, a node of FORS tree i, or the leaf of tree i at the forged
   index), or reveals, for every tree i, exactly the honest FORS secret at
   the forged global index i*2^a + idx'_i. -/
namespace DSM.Sphincs

/-- The forged FORS digit for tree `i`. -/
def forsDigit (p : Params) (md : Bytes) (i : Nat) : Nat := (base2b md p.a p.k).getD i 0

/-- Break events in FORS tree `i` of the honest FORS key at (tree, leaf), at
    the forged index. -/
def ForsTreeBreak (o : Oracle Id) (p : Params) (tk : Bytes) (tree leaf : Nat) (md : Bytes)
    (i : Nat) : Prop :=
  (∃ j, j < p.a ∧ ThashCollisionAt o p tk
    {(forsAdrs tree leaf) with chain := j+1, hash := (i*2^p.a + forsDigit p md i)/2^(j+1)}) ∨
  ThashCollisionAt o p tk {(forsAdrs tree leaf) with chain := 0, hash := i*2^p.a + forsDigit p md i}

/-- Break events of the honest FORS key at (tree, leaf) against a forged
    digest `md`. -/
def ForsBreakAt (o : Oracle Id) (p : Params) (tk : Bytes) (tree leaf : Nat) (md : Bytes) : Prop :=
  ThashCollisionAt o p tk {(forsAdrs tree leaf).setType 4 with keypair := (forsAdrs tree leaf).keypair} ∨
  ∃ i, i < p.k ∧ ForsTreeBreak o p tk tree leaf md i

theorem getD_mem_zipIdx (l : List Nat) (i : Nat) (hi : i < l.length) :
    (l.getD i 0, i) ∈ l.zipIdx := by
  refine List.mem_zipIdx_iff_getElem?.mpr ?_
  simp [hi]

section
variable {o : Oracle Id} {p : Params} {tk prfKey seed : Bytes}

theorem slice_take_prefix (x : Bytes) (s step n : Nat) (h : n ≤ step) :
    (slice x s step).take n = slice x s n := by
  simp only [slice, List.take_take, Nat.min_eq_left h]

/-- One FORS tree: a forged tree root equal to the honest one gives a break
    in that tree or the honest secret at the forged index. -/
theorem fors_tree_extract (widths : OutputWidths o) (tree leaf : Nat) (md part : Bytes) (i : Nat)
    (hroot : authRoot o p tk (forsAdrs tree leaf) (forsDigit p md i) (i*2^p.a + forsDigit p md i)
      (thash o p tk {(forsAdrs tree leaf) with chain := 0, hash := i*2^p.a + forsDigit p md i}
        (part.take p.n)) (part.drop p.n) p.a =
      forsNode o p tk prfKey seed (forsAdrs tree leaf) i p.a) :
    ForsTreeBreak o p tk tree leaf md i ∨
      part.take p.n = forsSecret o p prfKey seed (forsAdrs tree leaf) (i*2^p.a + forsDigit p md i) := by
  have hbound : forsDigit p md i < 2^p.a := by
    unfold forsDigit
    by_cases hi : i < (base2b md p.a p.k).length
    · rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hi, Option.getD_some]
      exact base2b_digit_bound md p.a p.k _ (List.getElem_mem hi)
    · rw [List.getD_eq_getElem?_getD, List.getElem?_eq_none (by omega), Option.getD_none]
      exact Nat.pos_of_ne_zero (by simp)
  have honest := fors_signer_tree_path o p tk prfKey seed (forsAdrs tree leaf) i (forsDigit p md i)
    (((List.range p.a).map fun j => (forsNode o p tk prfKey seed (forsAdrs tree leaf)
      (i*2^(p.a-j)+Nat.xor (forsDigit p md i/2^j) 1) j : Bytes)).flatten) hbound
    (fun j hj => by
      have extracted := serialized_map_block (List.range p.a)
        (fun level => (forsNode o p tk prfKey seed (forsAdrs tree leaf)
          (i*2^(p.a-level)+Nat.xor (forsDigit p md i/2^level) 1) level : Bytes)) p.n j
        (fun _ _ => fors_node_width o widths p tk prfKey seed _ _ _) (by simpa using hj)
      simpa [fors_offset_sibling i (forsDigit p md i) p.a j hj] using extracted)
  rw [← honest] at hroot
  by_cases hL : thash o p tk {(forsAdrs tree leaf) with chain := 0, hash := i*2^p.a + forsDigit p md i}
      (part.take p.n) = forsNode o p tk prfKey seed (forsAdrs tree leaf) (i*2^p.a + forsDigit p md i) 0
  · by_cases hs : part.take p.n =
        forsSecret o p prfKey seed (forsAdrs tree leaf) (i*2^p.a + forsDigit p md i)
    · exact Or.inr hs
    · exact Or.inl (Or.inr ⟨_, _, hs, hL⟩)
  · obtain ⟨j, hj, hc⟩ := auth_root_extract_general widths (forsAdrs tree leaf) _ _ _ _ p.a _ _
      (by rw [thash_width o widths, fors_node_width o widths]) hroot (Or.inl hL)
    exact Or.inl (Or.inl ⟨j, hj, hc⟩)

/-- FORS extraction: a forged FORS signature (of any length) of `md` at
    (tree, leaf) reconstructing the honest FORS public key gives a FORS
    break, or for every tree i its forged secret block is the honest secret
    at the forged global index. -/
theorem fors_forgery_extract (widths : OutputWidths o) (tree leaf : Nat) (sig md : Bytes)
    (h : forsPkFromSig o p tk (forsAdrs tree leaf) sig md = honestForsPk o p tk prfKey seed tree leaf) :
    ForsBreakAt o p tk tree leaf md ∨
      ∀ i, i < p.k → slice sig (i*((p.a+1)*p.n)) p.n =
        forsSecret o p prfKey seed (forsAdrs tree leaf) (i*2^p.a + forsDigit p md i) := by
  rw [fors_verify_blocks] at h
  by_cases hr :
    ((base2b md p.a p.k).zipIdx.map fun x =>
        (authRoot o p tk (forsAdrs tree leaf) x.1 (x.2*2^p.a+x.1)
          (thash o p tk {(forsAdrs tree leaf) with chain := 0,hash := x.2*2^p.a+x.1}
            ((slice sig (x.2*((p.a+1)*p.n)) ((p.a+1)*p.n)).take p.n))
          ((slice sig (x.2*((p.a+1)*p.n)) ((p.a+1)*p.n)).drop p.n) p.a : Bytes)).flatten =
    ((List.range p.k).map fun i =>
      (forsNode o p tk prfKey seed (forsAdrs tree leaf) i p.a : Bytes)).flatten
  · have tree_i : ∀ i, i < p.k → ForsTreeBreak o p tk tree leaf md i ∨
        slice sig (i*((p.a+1)*p.n)) p.n =
          forsSecret o p prfKey seed (forsAdrs tree leaf) (i*2^p.a + forsDigit p md i) := by
      intro i hi
      have hlen : i < (base2b md p.a p.k).length := by rw [base2b_length]; exact hi
      have forged := serialized_indexed_block (base2b md p.a p.k)
        (fun x => (authRoot o p tk (forsAdrs tree leaf) x.1 (x.2*2^p.a+x.1)
          (thash o p tk {(forsAdrs tree leaf) with chain := 0,hash := x.2*2^p.a+x.1}
            ((slice sig (x.2*((p.a+1)*p.n)) ((p.a+1)*p.n)).take p.n))
          ((slice sig (x.2*((p.a+1)*p.n)) ((p.a+1)*p.n)).drop p.n) p.a : Bytes))
        p.n _ (getD_mem_zipIdx _ i hlen)
        (fun y _ => authWalk_width widths _ _ _ _ _ _ _ (thash_width o widths p tk _ _))
      have honestRoot := serialized_map_block (List.range p.k)
        (fun i => (forsNode o p tk prfKey seed (forsAdrs tree leaf) i p.a : Bytes))
        p.n i (fun _ _ => fors_node_width o widths p tk prfKey seed _ _ _) (by simpa using hi)
      rw [hr, honestRoot] at forged
      simp only [List.getElem_range] at forged
      rcases fors_tree_extract (prfKey := prfKey) (seed := seed) widths tree leaf md _ i forged.symm
        with b | s
      · exact Or.inl b
      · right
        rw [← s, slice_take_prefix _ _ _ _ (by rw [Nat.add_mul, Nat.one_mul]; omega)]
    by_cases hall : ∀ i, i < p.k → slice sig (i*((p.a+1)*p.n)) p.n =
        forsSecret o p prfKey seed (forsAdrs tree leaf) (i*2^p.a + forsDigit p md i)
    · exact Or.inr hall
    · left; right
      apply Classical.byContradiction
      intro hno
      apply hall
      intro i hi
      rcases tree_i i hi with b | s
      · exact absurd ⟨i, hi, b⟩ hno
      · exact s
  · exact Or.inl (Or.inl ⟨_, _, hr, h⟩)
end

#print axioms fors_tree_extract
#print axioms fors_forgery_extract
end DSM.Sphincs
