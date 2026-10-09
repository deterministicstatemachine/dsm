-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.ForsExtraction

/- Forgery extraction, stage 2, full signature. Against an honestly generated
   key (any seed, any oracle with fixed-width outputs), every accepted
   (message, signature) pair exhibits one of:
   * `HtBreak`: an XMSS break (thash collision at an honest Merkle node, WOTS
     compression or WOTS chain address, or a WOTS preimage of an unrevealed
     honest chain value) at an honest hypertree position;
   * `ForsBreakAt`: a thash collision at an honest FORS address of the
     forged digest's hypertree leaf;
   * a FORS secret at an index no honest signature at that (tree, leaf)
     revealed, equal to the honest secret (a preimage of an unrevealed
     honest value; this includes a (tree, leaf) no honest signature used);
   * `ForsCovered`: every forged FORS index was revealed by an honest
     signature at the same (tree, leaf), stated with the actual h_msg
     outputs (the event the H_msg / ITSR step bounds).
   Deterministic; no probability. -/
namespace DSM.Sphincs

section
variable (o : Oracle Id) (v : Variant) (seed32 : Wire 32)

/-- The honest secret key. -/
def kgSk : Bytes := (generateKeypair o v seed32).2
/-- The honest public key. -/
def kgPk : Bytes := (generateKeypair o v seed32).1
/-- Public seed, thash key and PRF key, exactly as `sign` derives them. -/
def kgSeed : Bytes := slice (kgSk o v seed32) (2*(params v).n) (params v).n
def kgTk : Bytes := deriveKey o "DSM/sphincs/v2/thash" (kgSeed o v seed32)
def kgPrf : Bytes := deriveKey o "DSM/sphincs/v2/prf" ((kgSk o v seed32).take (params v).n)

/-- The digest `sign` computes for `msg` under the honest key. -/
def honestDigest (msg : Bytes) : Bytes :=
  hmsg o (params v)
    (keyed o (params v).n
      (deriveKey o "DSM/sphincs/v2/prf-msg" (slice (kgSk o v seed32) (params v).n (params v).n))
      (kgSeed o v seed32 ++ msg))
    (kgSeed o v seed32) ((kgSk o v seed32).drop (3*(params v).n)) msg

/-- The digest `verify` computes for a forged pair under the honest public key. -/
def forgedDigest (msg sig : Bytes) : Bytes :=
  hmsg o (params v) (sig.take (params v).n) ((kgPk o v seed32).take (params v).n)
    ((kgPk o v seed32).drop (params v).n) msg

/-- Some honestly signed message selects hypertree leaf (tree, leaf) and, in
    FORS tree `i`, index `idx`. -/
def Revealed (signed : List Bytes) (tree leaf i idx : Nat) : Prop :=
  ∃ msg ∈ signed,
    (splitDigest (params v) (honestDigest o v seed32 msg)).tree = tree ∧
    (splitDigest (params v) (honestDigest o v seed32 msg)).leaf = leaf ∧
    forsDigit (params v) (splitDigest (params v) (honestDigest o v seed32 msg)).md i = idx

/-- ITSR "covered": every FORS index of the forged indices was revealed by
    an honest signature at the same hypertree leaf. -/
def ForsCovered (signed : List Bytes) (forged : Indices) : Prop :=
  ∀ i, i < (params v).k →
    Revealed o v seed32 signed forged.tree forged.leaf i (forsDigit (params v) forged.md i)
end

theorem slice_slice (x : Bytes) (s t L n : Nat) (h : t + n ≤ L) :
    slice (slice x s L) t n = slice x (s+t) n := by
  simp only [slice, List.drop_take, List.take_take, List.drop_drop]
  rw [Nat.min_eq_left (by omega)]

theorem forsPkFromSig_width {o : Oracle Id} {p : Params} {tk : Bytes} (widths : OutputWidths o)
    (a : Adrs) (sig md : Bytes) : (forsPkFromSig o p tk a sig md).length = p.n := by
  rw [fors_verify_blocks]
  exact thash_width o widths p tk _ _

/-- Full-signature forgery extraction against an honestly generated key. -/
theorem forgery_extract (o : Oracle Id) (widths : OutputWidths o) (v : Variant) (seed32 : Wire 32)
    (signed : List Bytes) (msg' sig' : Bytes)
    (hv : verify o v (kgPk o v seed32) msg' sig' = some true) :
    HtBreak o (params v) (kgTk o v seed32) (kgPrf o v seed32) (kgSeed o v seed32)
      (sig'.drop ((params v).n + (params v).forsBytes)) ∨
    ForsBreakAt o (params v) (kgTk o v seed32)
      (splitDigest (params v) (forgedDigest o v seed32 msg' sig')).tree
      (splitDigest (params v) (forgedDigest o v seed32 msg' sig')).leaf
      (splitDigest (params v) (forgedDigest o v seed32 msg' sig')).md ∨
    (∃ i, i < (params v).k ∧
      ¬ Revealed o v seed32 signed
        (splitDigest (params v) (forgedDigest o v seed32 msg' sig')).tree
        (splitDigest (params v) (forgedDigest o v seed32 msg' sig')).leaf i
        (forsDigit (params v) (splitDigest (params v) (forgedDigest o v seed32 msg' sig')).md i) ∧
      slice sig' ((params v).n + i*(((params v).a+1)*(params v).n)) (params v).n =
        forsSecret o (params v) (kgPrf o v seed32) (kgSeed o v seed32)
          (forsAdrs (splitDigest (params v) (forgedDigest o v seed32 msg' sig')).tree
            (splitDigest (params v) (forgedDigest o v seed32 msg' sig')).leaf)
          (i*2^(params v).a +
            forsDigit (params v) (splitDigest (params v) (forgedDigest o v seed32 msg' sig')).md i)) ∨
    ForsCovered o v seed32 signed (splitDigest (params v) (forgedDigest o v seed32 msg' sig')) := by
  obtain ⟨valid, hpkeq⟩ := generated_key_valid o widths v seed32
  obtain ⟨hsklen, hskroot⟩ := valid
  obtain ⟨hpklen, hsiglen⟩ := accepted_requires_exact_lengths o v _ msg' sig' hv
  have hne : msg'.isEmpty = false := by
    cases e : msg'.isEmpty
    · rfl
    · rw [List.isEmpty_iff.mp e, verify_empty] at hv; cases hv
  have hacc := (verification_structure o v _ msg' sig' hne hpklen hsiglen).mp hv
  dsimp only at hacc
  have hseedlen : (kgSeed o v seed32).length = (params v).n := by
    simp only [kgSeed, kgSk, slice, List.length_take, List.length_drop, hsklen]
    omega
  have hpk : kgPk o v seed32 = kgSeed o v seed32 ++ (kgSk o v seed32).drop (3*(params v).n) := by
    unfold kgPk kgSeed kgSk; exact hpkeq
  have hroot : (kgSk o v seed32).drop (3*(params v).n) =
      xmssNode o (params v) (kgTk o v seed32) (kgPrf o v seed32) (kgSeed o v seed32)
        {layer := (params v).d-1} 0 (params v).hp := by
    unfold kgTk kgPrf kgSeed kgSk; exact hskroot
  have htake : (kgPk o v seed32).take (params v).n = kgSeed o v seed32 := by
    rw [hpk]; exact List.take_left' hseedlen
  have hdrop : (kgPk o v seed32).drop (params v).n =
      xmssNode o (params v) (kgTk o v seed32) (kgPrf o v seed32) (kgSeed o v seed32)
        {layer := (params v).d-1} 0 (params v).hp := by
    rw [hpk, List.drop_left' hseedlen]; exact hroot
  have htk : deriveKey o "DSM/sphincs/v2/thash" ((kgPk o v seed32).take (params v).n) =
      kgTk o v seed32 := by rw [htake]; unfold kgTk; rfl
  rw [htk] at hacc
  replace hacc := hacc.trans hdrop
  obtain ⟨hd2, hexp⟩ := supported_layer_bounds v
  have hn : 2*(params v).n*15 < 4096 := by have := (checksum_width_three v).2; omega
  have hS : (sig'.drop ((params v).n + (params v).forsBytes)).length =
      (params v).d*(params v).layerBytes := by
    simp only [List.length_drop, hsiglen, Params.sigBytes]; omega
  have htree := digest_tree_bounded (params v) (forgedDigest o v seed32 msg' sig')
  rw [← hexp] at htree
  have hleaf := digest_leaf_bounded (params v) (forgedDigest o v seed32 msg' sig')
  rcases ht_forgery_extract widths hn (by omega) _ _ _ _ hS
    (forsPkFromSig_width widths _ _ _) htree hleaf hacc with hf | hb
  · right
    rcases fors_forgery_extract widths _ _ _ _ hf with fb | hs
    · exact Or.inl fb
    · right
      by_cases hcov : ForsCovered o v seed32 signed
          (splitDigest (params v) (forgedDigest o v seed32 msg' sig'))
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
        have e := hs i hi
        rw [slice_slice] at e
        · exact e
        · have h1 := Nat.mul_le_mul_right (((params v).a+1)*(params v).n) (show i+1 ≤ (params v).k by omega)
          rw [Nat.succ_mul] at h1
          simp only [Params.forsBytes, Nat.mul_assoc] at h1 ⊢
          have h2 : (params v).n ≤ ((params v).a+1)*(params v).n := by
            rw [Nat.add_mul, Nat.one_mul]; omega
          omega
  · exact Or.inl hb

/-- What `Revealed` refers to: an honest signature of `msg` under the
    generated key contains, at FORS tree `i`, the honest FORS secret at the
    index its own digest selects. -/
theorem honest_signature_reveals (o : Oracle Id) (widths : OutputWidths o) (v : Variant)
    (seed32 : Wire 32) (msg sig : Bytes) (h : sign o v (kgSk o v seed32) msg = some sig)
    (i : Nat) (hi : i < (params v).k) :
    slice sig ((params v).n + i*(((params v).a+1)*(params v).n)) (params v).n =
      forsSecret o (params v) (kgPrf o v seed32) (kgSeed o v seed32)
        (forsAdrs (splitDigest (params v) (honestDigest o v seed32 msg)).tree
          (splitDigest (params v) (honestDigest o v seed32 msg)).leaf)
        (i*2^(params v).a + forsDigit (params v) (splitDigest (params v) (honestDigest o v seed32 msg)).md i) := by
  have key : ∀ r fs hs : Bytes, r.length = (params v).n →
      fs = forsSign o (params v) (kgTk o v seed32) (kgPrf o v seed32) (kgSeed o v seed32)
        (forsAdrs (splitDigest (params v) (honestDigest o v seed32 msg)).tree
          (splitDigest (params v) (honestDigest o v seed32 msg)).leaf)
        (splitDigest (params v) (honestDigest o v seed32 msg)).md →
      slice (r ++ fs ++ hs) ((params v).n + i*(((params v).a+1)*(params v).n)) (params v).n =
      forsSecret o (params v) (kgPrf o v seed32) (kgSeed o v seed32)
        (forsAdrs (splitDigest (params v) (honestDigest o v seed32 msg)).tree
          (splitDigest (params v) (honestDigest o v seed32 msg)).leaf)
        (i*2^(params v).a + forsDigit (params v) (splitDigest (params v) (honestDigest o v seed32 msg)).md i) := by
    intro r fs hs hr hfs
    have hstep : i*(((params v).a+1)*(params v).n) + (params v).n ≤ fs.length := by
      rw [hfs, fors_sign_width o widths, Params.forsBytes, Nat.mul_assoc]
      have h1 := Nat.mul_le_mul_right (((params v).a+1)*(params v).n) (show i+1 ≤ (params v).k by omega)
      rw [Nat.succ_mul] at h1
      have h2 : (params v).n ≤ ((params v).a+1)*(params v).n := by rw [Nat.add_mul, Nat.one_mul]; omega
      omega
    have e1 : slice (r ++ fs ++ hs) ((params v).n + i*(((params v).a+1)*(params v).n)) (params v).n =
        slice fs (i*(((params v).a+1)*(params v).n)) (params v).n := by
      unfold slice
      rw [List.append_assoc, List.drop_append, List.drop_eq_nil_of_le (by omega), List.nil_append, hr,
        Nat.add_sub_cancel_left]
      exact slice_append_prefix fs hs _ _ hstep
    rw [e1, ← slice_take_prefix fs _ (((params v).a+1)*(params v).n) _
      (by rw [Nat.add_mul, Nat.one_mul]; omega), hfs,
      fors_sign_part widths _ _ _ (getD_mem_zipIdx _ i (by rw [base2b_length]; exact hi)),
      fors_part_take widths]
    rfl
  simp only [sign] at h
  split at h
  · cases h
  · simp only [id_bind] at h
    split at h
    · cases h
    · rw [← Option.some.inj h]
      exact key _ _ _ (widths _) rfl

#print axioms honest_signature_reveals
#print axioms forgery_extract
end DSM.Sphincs
