-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.LogExtraction
import Sphincs.MsgPrfHybrid

/- Full-signature forgery extraction against the key derived from an
   arbitrary 3n-byte expansion (`keypairFromExpansion`), for any oracle that
   gives n-byte answers to the construction's thash requests (under the
   derived thash key) and PRF requests (under the derived PRF key, on
   (n+32)-byte inputs). This is what the hybrid games' routed oracles
   satisfy. The collision case is witnessed by a request in the verifier's
   own log for the forged pair. -/
namespace DSM.Sphincs.Security
open DSM.Sphincs

section
variable (O : Oracle Id) (v : Variant)

def expSeed (e : Bytes) : Bytes := slice e (2*(params v).n) (params v).n
def expTk (e : Bytes) : Bytes := deriveKey O "DSM/sphincs/v2/thash" (expSeed v e)
def expPrf (e : Bytes) : Bytes := deriveKey O "DSM/sphincs/v2/prf" (e.take (params v).n)

/-- The digest `sign` computes for `msg` under secret key `sk`. -/
def signDigest (sk msg : Bytes) : Bytes :=
  hmsg O (params v)
    (keyed O (params v).n (deriveKey O "DSM/sphincs/v2/prf-msg" (slice sk (params v).n (params v).n))
      (slice sk (2*(params v).n) (params v).n ++ msg))
    (slice sk (2*(params v).n) (params v).n) (sk.drop (3*(params v).n)) msg

/-- The digest `verify` computes for (pk, msg, sig). -/
def verifyDigest (pk msg sig : Bytes) : Bytes :=
  hmsg O (params v) (sig.take (params v).n) (pk.take (params v).n) (pk.drop (params v).n) msg

/-- The exact request log of `verify` on (pk, msg, sig). -/
def verifyLog (pk msg sig : Bytes) : List Request :=
  ((verify (logOracle O) v pk msg sig).run []).2

/-- Some message in `signed`, signed under `sk`, selects hypertree leaf
    (tree, leaf) and FORS index `idx` in tree `i`. -/
def RevealedBy (sk : Bytes) (signed : List Bytes) (tree leaf i idx : Nat) : Prop :=
  ∃ msg ∈ signed,
    (splitDigest (params v) (signDigest O v sk msg)).tree = tree ∧
    (splitDigest (params v) (signDigest O v sk msg)).leaf = leaf ∧
    forsDigit (params v) (splitDigest (params v) (signDigest O v sk msg)).md i = idx

/-- ITSR covered: every FORS index of `I` was selected at the same hypertree
    leaf by some message signed under `sk`. -/
def CoveredBy (sk : Bytes) (signed : List Bytes) (I : Indices) : Prop :=
  ∀ i, i < (params v).k →
    RevealedBy O v sk signed I.tree I.leaf i (forsDigit (params v) I.md i)
end

/-- Full-signature extraction for the key of an arbitrary expansion. -/
theorem forgery_extract_exp (O : Oracle Id) (v : Variant) (e : Bytes)
    (he : e.length = 3*(params v).n)
    (tw : ∀ x, (O ⟨1,"",expTk O v e,x,(params v).n⟩).length = (params v).n)
    (pw : ∀ x, x.length = (params v).n+32 →
      (O ⟨1,"",expPrf O v e,x,(params v).n⟩).length = (params v).n)
    (signed : List Bytes) (msg' sig' : Bytes)
    (hv : verify O v (keypairFromExpansion O v e).1 msg' sig' = some true) :
    CanonCollIn O (params v) (expTk O v e) (expPrf O v e) (expSeed v e)
        (verifyLog O v (keypairFromExpansion O v e).1 msg' sig') ∨
    WotsEvent O (params v) (expTk O v e) (expPrf O v e) (expSeed v e)
        (sig'.drop ((params v).n + (params v).forsBytes)) ∨
    (∃ i, i < (params v).k ∧
      ¬ RevealedBy O v (keypairFromExpansion O v e).2 signed
        (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')).tree
        (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')).leaf i
        (forsDigit (params v)
          (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')).md i) ∧
      slice sig' ((params v).n + i*(((params v).a+1)*(params v).n)) (params v).n =
        forsSecret O (params v) (expPrf O v e) (expSeed v e)
          (forsAdrs (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')).tree
            (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')).leaf)
          (i*2^(params v).a + forsDigit (params v)
            (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')).md i)) ∨
    CoveredBy O v (keypairFromExpansion O v e).2 signed
      (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')) := by
  obtain ⟨hpklen, hsiglen⟩ := accepted_requires_exact_lengths O v _ msg' sig' hv
  have hne : msg'.isEmpty = false := by
    cases ee : msg'.isEmpty
    · rfl
    · rw [List.isEmpty_iff.mp ee, verify_empty] at hv; cases hv
  have hseedlen : (expSeed v e).length = (params v).n := by
    simp only [expSeed, slice, List.length_take, List.length_drop, he]; omega
  have hpk : (keypairFromExpansion O v e).1 = List.append (expSeed v e)
      (xmssNode O (params v) (expTk O v e) (expPrf O v e) (expSeed v e)
        {layer := (params v).d-1} 0 (params v).hp) := rfl
  have htake : (keypairFromExpansion O v e).1.take (params v).n = expSeed v e := by
    rw [hpk]; exact List.take_left' hseedlen
  have hdrop : (keypairFromExpansion O v e).1.drop (params v).n =
      xmssNode O (params v) (expTk O v e) (expPrf O v e) (expSeed v e)
        {layer := (params v).d-1} 0 (params v).hp := by
    rw [hpk]; exact List.drop_left' hseedlen
  have htk : deriveKey O "DSM/sphincs/v2/thash" ((keypairFromExpansion O v e).1.take (params v).n) =
      expTk O v e := by rw [htake]; rfl
  have hacc := (verification_structure O v _ msg' sig' hne hpklen hsiglen).mp hv
  dsimp only at hacc
  rw [htk] at hacc
  replace hacc := hacc.trans hdrop
  have hlogs := (verify_exact O v _ msg' sig' hne hpklen hsiglen).run_empty.2
  rw [htk] at hlogs
  have hlogs' : verifyLog O v (keypairFromExpansion O v e).1 msg' sig' = _ := hlogs
  obtain ⟨hlen, hH, hdd, hMA, hA, hT⟩ := variant_bounds v
  obtain ⟨hd2, hexp⟩ := supported_layer_bounds v
  have hn : 2*(params v).n*15 < 4096 := by have := (checksum_width_three v).2; omega
  have htop : 2^((params v).hp*((params v).d-1)) ≤ 256^8 := by rw [hexp]; exact hT
  have hS : (sig'.drop ((params v).n + (params v).forsBytes)).length =
      (params v).d*(params v).layerBytes := by
    simp only [List.length_drop, hsiglen, Params.sigBytes]; omega
  have htree := digest_tree_bounded (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')
  have hleaf := digest_leaf_bounded (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')
  have htree' := htree
  rw [← hexp] at htree'
  have hfw : ∀ (a : Adrs) (s md : Bytes),
      (forsPkFromSig O (params v) (expTk O v e) a s md).length = (params v).n := by
    intro a s md; rw [fors_verify_blocks]; exact thash_w tw _ _
  rcases ht_extract_log tw pw hseedlen hn hlen hH hdd htop (by omega) _ _ _ _ hS
    (hfw _ _ _) htree' hleaf hacc with hf | c | w
  · rcases fors_extract_log (prfKey := expPrf O v e) (seed := expSeed v e) tw _ _ (Nat.lt_of_lt_of_le htree hT)
      (Nat.lt_of_lt_of_le hleaf hH) hMA hA _ _ hf with c | hs
    · left
      exact c.mono (fun r hr => by
        rw [hlogs']; exact List.mem_append_left _ (List.mem_append_right _ hr))
    · right; right
      by_cases hcov : CoveredBy O v (keypairFromExpansion O v e).2 signed
          (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig'))
      · exact Or.inr hcov
      · left
        apply Classical.byContradiction
        intro hno
        apply hcov
        intro i hi
        apply Classical.byContradiction
        intro hrev
        apply hno
        refine ⟨i, hi, hrev, ?_⟩
        have ee := hs i hi
        rw [slice_slice] at ee
        · exact ee
        · have h1 := Nat.mul_le_mul_right (((params v).a+1)*(params v).n) (show i+1 ≤ (params v).k by omega)
          rw [Nat.succ_mul] at h1
          simp only [Params.forsBytes, Nat.mul_assoc] at h1 ⊢
          have h2 : (params v).n ≤ ((params v).a+1)*(params v).n := by
            rw [Nat.add_mul, Nat.one_mul]; omega
          omega
  · left
    exact c.mono (fun r hr => by rw [hlogs']; exact List.mem_append_right _ hr)
  · exact Or.inr (Or.inl w)

#print axioms forgery_extract_exp
end DSM.Sphincs.Security
