-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.Extraction
import Sphincs.WotsChecksum

/- WOTS forgery extraction. The honest WOTS key at address `a` has chain i
   secret `prf(.., {a.setType 5 with keypair, chain := i})` and public top at
   position 15; an honest signature of `m` reveals chain i at position
   d_i = digit_i(m). If a forged signature `sig'` of `m'` (with different
   digits) reconstructs the honest WOTS public key, then one of:
   * a thash collision at the WOTS compression address;
   * a thash collision on some chain i, at hash position j < 15;
   * `WotsPreimage`: for some chain i with d'_i < d_i, the forged block is
     exactly the honest chain value at position d'_i, a position the honest
     signature of `m` did not reveal. -/
namespace DSM.Sphincs

/-- The honest value of WOTS chain `i` after `j` steps. -/
def wotsChainValue (o : Oracle Id) (p : Params) (tk prfKey seed : Bytes) (a : Adrs) (i j : Nat) :
    Bytes :=
  chain o p tk {a with chain := i}
    (prf o p prfKey seed {a.setType 5 with keypair := a.keypair, chain := i}) 0 j

/-- The forged signature of `m'` contains, at some chain whose digit dropped
    below the honestly signed digit of `m`, the honest chain value at the
    lower position. -/
def WotsPreimage (o : Oracle Id) (p : Params) (tk prfKey seed : Bytes) (a : Adrs)
    (m m' sig' : Bytes) : Prop :=
  ∃ i, i < p.len ∧ (wotsDigits p m').getD i 0 < (wotsDigits p m).getD i 0 ∧
    slice sig' (i*p.n) p.n = wotsChainValue o p tk prfKey seed a i ((wotsDigits p m').getD i 0)

section
variable {o : Oracle Id} {p : Params} {tk prfKey seed : Bytes}

theorem digit_mem (m : Bytes) (i : Nat) (hi : i < p.len) :
    ((wotsDigits p m).getD i 0, i) ∈ (wotsDigits p m).zipIdx ∧
      (wotsDigits p m).getD i 0 ≤ 15 := by
  have hl : i < (wotsDigits p m).length := by rw [wots_digit_count]; exact hi
  have hget : (wotsDigits p m).getD i 0 = (wotsDigits p m)[i] := by
    simp [List.getD_eq_getElem?_getD, hl]
  refine ⟨List.mem_zipIdx_iff_getElem?.mpr ?_, ?_⟩
  · simp [hl]
  · rw [hget]; exact wots_digit_bound p m _ (List.getElem_mem hl)

/-- The honest signature of `m` reveals chain `i` at position digit_i(m). -/
theorem wots_sign_reveals (widths : OutputWidths o) (a : Adrs) (m : Bytes) (i : Nat)
    (hi : i < p.len) :
    slice (wotsSign o p tk prfKey seed a m) (i*p.n) p.n =
      wotsChainValue o p tk prfKey seed a i ((wotsDigits p m).getD i 0) :=
  wots_sign_slice widths a m _ (digit_mem m i hi).1

theorem slice_width (x : Bytes) (i n len : Nat) (hx : x.length = len*n) (hi : i < len) :
    (slice x (i*n) n).length = n := by
  have : i*n + n ≤ len*n := by
    have h := Nat.mul_le_mul_right n (show i+1 ≤ len by omega)
    rw [Nat.succ_mul] at h; exact h
  simp only [slice, List.length_take, List.length_drop, hx]
  omega

/-- WOTS forgery extraction (generic parameters whose checksum fits three
    base-16 digits). -/
theorem wots_forgery_extract_of (widths : OutputWidths o) (hn : 2*p.n*15 < 4096)
    (a : Adrs) (m m' sig' : Bytes) (hsig' : sig'.length = p.len*p.n)
    (hd : wotsDigits p m ≠ wotsDigits p m')
    (hpk : wotsPkFromSig o p tk a sig' m' = wotsPkgen o p tk prfKey seed a) :
    ThashCollisionAt o p tk {a.setType 1 with keypair := a.keypair} ∨
    (∃ i j, i < p.len ∧ j < 15 ∧ ThashCollisionAt o p tk {{a with chain := i} with hash := j}) ∨
    WotsPreimage o p tk prfKey seed a m m' sig' := by
  rw [wots_verify_blocks, wots_pkgen_blocks] at hpk
  by_cases ht :
    ((wotsDigits p m').zipIdx.map fun (digit,i) =>
      (chain o p tk {a with chain := i} (slice sig' (i*p.n) p.n) digit (15-digit) : Bytes)).flatten =
    ((List.range p.len).map fun i => (chain o p tk {a with chain := i}
      (prf o p prfKey seed {a.setType 5 with keypair := a.keypair,chain := i}) 0 15 : Bytes)).flatten
  · right
    obtain ⟨i, hi, hlt⟩ := wots_checksum_decreases_of p hn m m' hd
    obtain ⟨hmem, hd15⟩ := digit_mem (p := p) m' i hi
    have forged := serialized_indexed_block (wotsDigits p m')
      (fun (digit,i) => (chain o p tk {a with chain := i} (slice sig' (i*p.n) p.n) digit (15-digit) : Bytes))
      p.n _ hmem (fun y hy => chain_width o widths p tk _ _ _ _
        (slice_width sig' y.2 p.n p.len hsig' (by
          have := (zipIdx_mem hy).2; rw [wots_digit_count] at this; exact this)))
    have honest := serialized_map_block (List.range p.len)
      (fun i => (chain o p tk {a with chain := i}
        (prf o p prfKey seed {a.setType 5 with keypair := a.keypair,chain := i}) 0 15 : Bytes))
      p.n i (fun _ _ => chain_width o widths p tk _ _ 0 15 (prf_width o widths p prfKey seed _))
      (by simpa using hi)
    rw [ht, honest] at forged
    simp only [List.getElem_range] at forged
    rw [← wots_signature_recovers_chain_top o p tk _ _ _ hd15] at forged
    rcases chain_extract_or _ _ _ _ _ forged.symm with e | ⟨j, _, hj2, hc⟩
    · exact Or.inr ⟨i, hi, hlt, e⟩
    · exact Or.inl ⟨i, j, hi, by omega, hc⟩
  · exact Or.inl ⟨_, _, ht, hpk⟩
end

/-- WOTS forgery extraction for every supported variant. -/
theorem wots_forgery_extract (o : Oracle Id) (widths : OutputWidths o) (v : Variant)
    (tk prfKey seed : Bytes) (a : Adrs) (m m' sig' : Bytes)
    (hsig' : sig'.length = (params v).len*(params v).n)
    (hd : wotsDigits (params v) m ≠ wotsDigits (params v) m')
    (hpk : wotsPkFromSig o (params v) tk a sig' m' = wotsPkgen o (params v) tk prfKey seed a) :
    ThashCollisionAt o (params v) tk {a.setType 1 with keypair := a.keypair} ∨
    (∃ i j, i < (params v).len ∧ j < 15 ∧
      ThashCollisionAt o (params v) tk {{a with chain := i} with hash := j}) ∨
    WotsPreimage o (params v) tk prfKey seed a m m' sig' :=
  wots_forgery_extract_of widths (by have := (checksum_width_three v).2; omega) a m m' sig' hsig' hd hpk

/-- The same for distinct n-byte messages. -/
theorem wots_forgery_extract_of_ne (o : Oracle Id) (widths : OutputWidths o) (v : Variant)
    (tk prfKey seed : Bytes) (a : Adrs) (m m' sig' : Bytes)
    (hm : m.length = (params v).n) (hm' : m'.length = (params v).n) (hne : m ≠ m')
    (hsig' : sig'.length = (params v).len*(params v).n)
    (hpk : wotsPkFromSig o (params v) tk a sig' m' = wotsPkgen o (params v) tk prfKey seed a) :
    ThashCollisionAt o (params v) tk {a.setType 1 with keypair := a.keypair} ∨
    (∃ i j, i < (params v).len ∧ j < 15 ∧
      ThashCollisionAt o (params v) tk {{a with chain := i} with hash := j}) ∨
    WotsPreimage o (params v) tk prfKey seed a m m' sig' :=
  wots_forgery_extract o widths v tk prfKey seed a m m' sig' hsig'
    (fun h => hne (wots_digits_injective _ m m' hm hm' h)) hpk

#print axioms wots_sign_reveals
#print axioms wots_forgery_extract_of
#print axioms wots_forgery_extract
#print axioms wots_forgery_extract_of_ne
end DSM.Sphincs
