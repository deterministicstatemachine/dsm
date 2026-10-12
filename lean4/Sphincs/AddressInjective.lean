-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.Proofs

/- The full 32-byte address encoding is injective on in-range coordinates:
   two addresses that encode to the same bytes are the same address. This is
   the tweak-separation premise of the tweakable-hash reductions: distinct
   (layer, tree, type, keypair, chain, hash) coordinates never collide as
   ADRS bytes, so distinct positions in the hypertree are distinct tweaks of
   F, H and T_l. It closes the "checked injection" row of the SHA-2/BLAKE3
   boundary for DSM's own (uncompressed) address layout. -/
namespace DSM.Sphincs

/-- Every coordinate fits its field: 4-byte words, and the 8-byte tree index. -/
def Adrs.InRange (a : Adrs) : Prop :=
  a.layer < 256^4 ∧ a.tree < 256^8 ∧ a.kind < 256^4 ∧
  a.keypair < 256^4 ∧ a.chain < 256^4 ∧ a.hash < 256^4

theorem be_injective (w x y : Nat) (hx : x < 256^w) (hy : y < 256^w) (h : be w x = be w y) :
    x = y := by
  have := congrArg toInt h
  rwa [be_roundtrip _ _ hx, be_roundtrip _ _ hy] at this

theorem adrs_bytes_injective (a b : Adrs) (ha : a.InRange) (hb : b.InRange)
    (h : a.bytes = b.bytes) : a = b := by
  obtain ⟨al, at', ak, akp, ac, ah⟩ := ha
  obtain ⟨bl, bt, bk, bkp, bc, bh⟩ := hb
  unfold Adrs.bytes at h
  obtain ⟨h, hHash⟩ := List.append_inj h (by simp [be_width])
  obtain ⟨h, hChain⟩ := List.append_inj h (by simp [be_width])
  obtain ⟨h, hKeypair⟩ := List.append_inj h (by simp [be_width])
  obtain ⟨h, hKind⟩ := List.append_inj h (by simp [be_width])
  obtain ⟨h, hTree⟩ := List.append_inj h (by simp [be_width])
  obtain ⟨hLayer, _⟩ := List.append_inj h (by simp [be_width])
  have e1 := be_injective _ _ _ al bl hLayer
  have e2 := be_injective _ _ _ at' bt hTree
  have e3 := be_injective _ _ _ ak bk hKind
  have e4 := be_injective _ _ _ akp bkp hKeypair
  have e5 := be_injective _ _ _ ac bc hChain
  have e6 := be_injective _ _ _ ah bh hHash
  cases a; cases b
  simp only at e1 e2 e3 e4 e5 e6
  subst e1 e2 e3 e4 e5 e6
  rfl

/-- Distinct in-range addresses are distinct tweaks: their thash requests
    differ for every message, under every key. -/
theorem distinct_addresses_distinct_requests (p : Params) (tk : Bytes)
    (a b : Adrs) (ha : a.InRange) (hb : b.InRange) (ne : a ≠ b) (x y : Bytes) :
    (⟨1,"",tk,a.bytes ++ x,p.n⟩ : Request) ≠ ⟨1,"",tk,b.bytes ++ y,p.n⟩ := by
  intro h
  have hi : a.bytes ++ x = b.bytes ++ y := by injection h
  obtain ⟨hab, _⟩ := List.append_inj hi (by simp [address_width])
  exact ne (adrs_bytes_injective a b ha hb hab)

#print axioms adrs_bytes_injective
#print axioms distinct_addresses_distinct_requests
end DSM.Sphincs
