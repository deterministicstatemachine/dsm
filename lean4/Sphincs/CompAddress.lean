-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.CompGames
import Sphincs.AddressInjective

/- Modular proof, milestone 2 (part 3): EasyCrypt's addresses and DSM's
   (map I6, obligation 3).

   EasyCrypt's SPHINCS+ address is a list of six integers, in the order
   [hash or breadth index, chain or height index, keypair, type, tree, layer],
   with five validity predicates, one per address type (`SPHINCS_PLUS.ec`,
   `valid_idxvalsch` … `valid_idxvalstrco`). DSM's `Adrs` has the same six
   coordinates. `ecIdx`/`ofEc` are the bijection; `EcValid` transcribes the
   EasyCrypt predicates for DSM's parameters (w = 16, l' = 2^h');
   `ec_valid_in_range` shows that every EasyCrypt-valid address is in range
   for DSM's 32-byte encoding, so distinct valid addresses are distinct
   tweaks (`ec_valid_tweak_injective`). The constructor lemmas
   (`ecValid_chain` … `ecValid_trco`) give the converse for each address
   shape, under the index ranges stated in their hypotheses.

   Not proved here: that every address DSM's signer issues meets those
   ranges for its type. C18 (`AddressRange`) proves `InRange` for them, which
   is weaker; the per-type ranges are discharged with the reductions that
   enumerate the honest addresses (map §9, obligations 6 and 9). -/
namespace DSM.Sphincs.Comp
open DSM.Sphincs DSM.Sphincs.Security

/-- EasyCrypt's index list of a DSM address. -/
def ecIdx (a : Adrs) : List Nat := [a.hash, a.chain, a.keypair, a.kind, a.tree, a.layer]

/-- The DSM address of an EasyCrypt index list. -/
def ofEc (l : List Nat) : Adrs :=
  {hash := l.getD 0 0, chain := l.getD 1 0, keypair := l.getD 2 0, kind := l.getD 3 0,
   tree := l.getD 4 0, layer := l.getD 5 0}

theorem ofEc_ecIdx (a : Adrs) : ofEc (ecIdx a) = a := by cases a; rfl

theorem ecIdx_ofEc (l : List Nat) (h : l.length = 6) : ecIdx (ofEc l) = l := by
  match l, h with
  | [_, _, _, _, _, _], _ => rfl

/-- EasyCrypt's address types (`chtype`, `pkcotype`, `trhxtype`, `trhftype`,
    `trcotype`) are DSM's 0–4; its axiom `dist_adrstypes` holds. DSM's PRF
    types 5 and 6 are outside EasyCrypt's address space (map I4). -/
theorem dist_adrstypes : [0, 1, 2, 3, 4].Nodup ∧ 5 ∉ [0, 1, 2, 3, 4] ∧ 6 ∉ [0, 1, 2, 3, 4] := by
  decide

section
variable (p : Params)

/-- `nr_trees`: trees in hypertree layer `layer`. -/
def nrTrees (layer : Nat) : Nat := 2^(p.hp * (p.d - layer - 1))

def ecCh (l : List Nat) : Prop :=
  l.getD 0 0 < 15 ∧ l.getD 1 0 < p.len ∧ l.getD 2 0 < 2^p.hp ∧ l.getD 3 0 = 0 ∧
    l.getD 4 0 < nrTrees p (l.getD 5 0) ∧ l.getD 5 0 < p.d
def ecPkco (l : List Nat) : Prop :=
  l.getD 0 0 = 0 ∧ l.getD 1 0 = 0 ∧ l.getD 2 0 < 2^p.hp ∧ l.getD 3 0 = 1 ∧
    l.getD 4 0 < nrTrees p (l.getD 5 0) ∧ l.getD 5 0 < p.d
def ecTrhx (l : List Nat) : Prop :=
  l.getD 0 0 < 2^(p.hp - l.getD 1 0) ∧ l.getD 1 0 ≤ p.hp ∧ l.getD 2 0 = 0 ∧ l.getD 3 0 = 2 ∧
    l.getD 4 0 < nrTrees p (l.getD 5 0) ∧ l.getD 5 0 < p.d
def ecTrhf (l : List Nat) : Prop :=
  l.getD 0 0 < p.k * 2^(p.a - l.getD 1 0) ∧ l.getD 1 0 ≤ p.a ∧ l.getD 2 0 < 2^p.hp ∧
    l.getD 3 0 = 3 ∧ l.getD 4 0 < nrTrees p (l.getD 5 0) ∧ l.getD 5 0 = 0
def ecTrco (l : List Nat) : Prop :=
  l.getD 0 0 = 0 ∧ l.getD 1 0 = 0 ∧ l.getD 2 0 < 2^p.hp ∧ l.getD 3 0 = 4 ∧
    l.getD 4 0 < nrTrees p (l.getD 5 0) ∧ l.getD 5 0 = 0

/-- EasyCrypt's `valid_adrsidxs` for DSM's parameters. -/
def EcValid (l : List Nat) : Prop :=
  l.length = 6 ∧ (ecCh p l ∨ ecPkco p l ∨ ecTrhx p l ∨ ecTrhf p l ∨ ecTrco p l)
end

/-- The parameter facts the range proof needs, for every DSM variant. -/
theorem variant_ec_bounds (v : Variant) :
    let p := params v
    p.hp * (p.d - 1) ≤ 64 ∧ p.d ≤ 256^4 ∧ 2^p.hp ≤ 256^4 ∧ p.len ≤ 256^4 ∧
      p.hp < 256^4 ∧ p.a < 256^4 ∧ p.k * 2^p.a ≤ 256^4 := by
  cases v <;> decide

theorem tree_in_range (p : Params) (h : p.hp * (p.d - 1) ≤ 64) (layer tree : Nat)
    (ht : tree < nrTrees p layer) : tree < 256^8 := by
  unfold nrTrees at ht
  have e1 : 2^(p.hp * (p.d - layer - 1)) ≤ 2^(p.hp * (p.d - 1)) :=
    Nat.pow_le_pow_right (by decide) (Nat.mul_le_mul_left _ (by omega))
  have e2 : 2^(p.hp * (p.d - 1)) ≤ 2^64 := Nat.pow_le_pow_right (by decide) h
  have e3 : (2:Nat)^64 = 256^8 := by decide
  omega

/-- Every EasyCrypt-valid address is in range for DSM's encoding. -/
theorem ec_valid_in_range (v : Variant) (l : List Nat) (h : EcValid (params v) l) :
    (ofEc l).InRange := by
  obtain ⟨hhd, hdd, hhp, hlen, hhp', ha, hka⟩ := variant_ec_bounds v
  have l2 : 2^((params v).hp - l.getD 1 0) ≤ 2^(params v).hp :=
    Nat.pow_le_pow_right (by decide) (Nat.sub_le _ _)
  have l3 : (params v).k * 2^((params v).a - l.getD 1 0) ≤ (params v).k * 2^(params v).a :=
    Nat.mul_le_mul_left _ (Nat.pow_le_pow_right (by decide) (Nat.sub_le _ _))
  obtain ⟨_, h⟩ := h
  unfold Adrs.InRange ofEc
  simp only
  rcases h with ⟨h0, h1, h2, h3, h4, h5⟩ | ⟨h0, h1, h2, h3, h4, h5⟩ | ⟨h0, h1, h2, h3, h4, h5⟩ |
      ⟨h0, h1, h2, h3, h4, h5⟩ | ⟨h0, h1, h2, h3, h4, h5⟩ <;>
    have ht := tree_in_range _ hhd _ _ h4 <;>
    refine ⟨?_, ht, ?_, ?_, ?_, ?_⟩ <;> omega

/-- Distinct valid EasyCrypt addresses are distinct 32-byte tweaks. -/
theorem ec_valid_tweak_injective (v : Variant) (l l' : List Nat) (h : EcValid (params v) l)
    (h' : EcValid (params v) l') (e : adrsTweak (ofEc l) = adrsTweak (ofEc l')) : l = l' := by
  have := adrs_bytes_injective _ _ (ec_valid_in_range v l h) (ec_valid_in_range v l' h')
    (congrArg Subtype.val e)
  rw [← ecIdx_ofEc l h.1, ← ecIdx_ofEc l' h'.1, this]

/-! The five DSM address shapes, and when they are EasyCrypt-valid. -/

theorem ecValid_chain (p : Params) (layer tree keypair chain hash : Nat) (hh : hash < 15)
    (hc : chain < p.len) (hk : keypair < 2^p.hp) (ht : tree < nrTrees p layer) (hl : layer < p.d) :
    EcValid p (ecIdx ⟨layer, tree, 0, keypair, chain, hash⟩) :=
  ⟨rfl, Or.inl ⟨hh, hc, hk, rfl, ht, hl⟩⟩

theorem ecValid_pkco (p : Params) (layer tree keypair : Nat) (hk : keypair < 2^p.hp)
    (ht : tree < nrTrees p layer) (hl : layer < p.d) :
    EcValid p (ecIdx {layer := layer, tree := tree, kind := 1, keypair := keypair}) :=
  ⟨rfl, Or.inr (Or.inl ⟨rfl, rfl, hk, rfl, ht, hl⟩)⟩

theorem ecValid_trhx (p : Params) (layer tree height index : Nat)
    (hi : index < 2^(p.hp - height)) (hh : height ≤ p.hp) (ht : tree < nrTrees p layer)
    (hl : layer < p.d) :
    EcValid p (ecIdx {layer := layer, tree := tree, kind := 2, chain := height, hash := index}) :=
  ⟨rfl, Or.inr (Or.inr (Or.inl ⟨hi, hh, rfl, rfl, ht, hl⟩))⟩

theorem ecValid_trhf (p : Params) (tree keypair height index : Nat)
    (hi : index < p.k * 2^(p.a - height)) (hh : height ≤ p.a) (hk : keypair < 2^p.hp)
    (ht : tree < nrTrees p 0) :
    EcValid p (ecIdx {tree := tree, kind := 3, keypair := keypair, chain := height, hash := index}) :=
  ⟨rfl, Or.inr (Or.inr (Or.inr (Or.inl ⟨hi, hh, hk, rfl, ht, rfl⟩)))⟩

theorem ecValid_trco (p : Params) (tree keypair : Nat) (hk : keypair < 2^p.hp)
    (ht : tree < nrTrees p 0) :
    EcValid p (ecIdx {tree := tree, kind := 4, keypair := keypair}) :=
  ⟨rfl, Or.inr (Or.inr (Or.inr (Or.inr ⟨rfl, rfl, hk, rfl, ht, rfl⟩)))⟩

/-- Layer-0 trees are exactly the `split_digest` tree indices. -/
theorem nrTrees_zero (v : Variant) : nrTrees (params v) 0 = 2^((params v).h - (params v).hp) := by
  cases v <;> decide

#print axioms ec_valid_in_range
#print axioms ec_valid_tweak_injective
#print axioms nrTrees_zero
end DSM.Sphincs.Comp
