-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomDerive

/- DSM key schedule KS1: encodings of every derivation input.

   KS1 (`core::identity::key_schedule`) derives every identity secret by
   HKDF-Expand under one of three pseudorandom keys, each a single Extract
   under a fixed salt, and everything under Smaster by keyed BLAKE3. The
   Expand `info` of a node is `label ‖ 0x00 ‖ fields`. This file proves:

   * the three Extract salts are distinct (`ks_salts_nodup`);
   * the `info` of a node determines the node and its context, among all the
     nodes under the same key (`wnode_info_inj` under the wallet root,
     `snode_info_inj` under `s0`, `akInfo_inj` under the device seed):
     every Expand under one key is a query at a distinct input;
   * the three Smaster-keyed inputs (per-step EK seed, ML-KEM coins, ML-KEM
     identity seed) are pairwise distinct, and the ML-KEM identity input is
     outside the per-step domain (`ekDom_mlkem`), so in C67's game it is one
     more revealed derivation: no auxiliary input is needed
     (`dsm_forge_256f_ks1`). -/
namespace DSM.Rom
open DSM.Sphincs DSM.Sphincs.Security

/-! Integer and length encodings. -/

/-- `x as u32` in little-endian bytes (Rust `to_le_bytes`). -/
def le32 (x : Nat) : Bytes := (be 4 x).reverse

theorem le32_length (x : Nat) : (le32 x).length = 4 := by simp [le32, be_width]

theorem le32_inj {x y : Nat} (hx : x < 2^32) (hy : y < 2^32) (h : le32 x = le32 y) : x = y :=
  be_injective 4 x y (by simpa using hx) (by simpa using hy) (List.reverse_inj.mp h)

theorem le32_split {x y : Nat} {r s : Bytes} (hx : x < 2^32) (hy : y < 2^32)
    (h : le32 x ++ r = le32 y ++ s) : x = y ∧ r = s := by
  obtain ⟨h1, h2⟩ := List.append_inj h (by rw [le32_length, le32_length])
  exact ⟨le32_inj hx hy h1, h2⟩

/-- `len(x) as u32 LE ‖ x`. -/
def lp (x : Bytes) : Bytes := le32 x.length ++ x

theorem lp_split {x y r s : Bytes} (hx : x.length < 2^32) (hy : y.length < 2^32)
    (h : lp x ++ r = lp y ++ s) : x = y ∧ r = s := by
  simp only [lp, List.append_assoc] at h
  obtain ⟨hl, h'⟩ := le32_split hx hy h
  exact List.append_inj h' hl

theorem wire_split {n : Nat} {a b : Wire n} {r s : Bytes} (h : a.val ++ r = b.val ++ s) : a = b ∧ r = s :=
  fixed_head_binding a b r s h

/-! Labels and salts. -/

def lNonce := "DSM/genesis-public-nonce/v3"
def lGrk := "DSM/genesis-root-authority/v2"
def lAtta := "DSM/atta/v3"
def lDevSeed := "DSM/device-seed/v3"
def lS0 := "DSM/s0/v3"
def lSdk := "DSM/sdk-entropy/v3"
def lRecAead := "DSM/recovery-aead/v2"
def lRecAuth := "DSM/recovery-authority/v2"
def lAk := "DSM/device-ak/v3"
def lSmaster := "DSM/Smaster/v3"
def lAtRest := "DSM/chain-head-at-rest/v3"

def ksLabels : List String :=
  [lNonce, lGrk, lAtta, lDevSeed, lS0, lSdk, lRecAead, lRecAuth, lAk, lSmaster, lAtRest]

theorem ksLabels_nul_free : ∀ l ∈ ksLabels, (0 : UInt8) ∉ utf8 l := by decide

theorem ksLabels_nodup : (ksLabels.map utf8).Nodup := by decide

def ksSalts : List String := ["DSM/kdf/wallet-root/v1", "DSM/kdf/device-root/v1", "DSM/kdf/s0-root/v1"]

/-- The three Extract salts are distinct: the three pseudorandom keys come from three
    distinct Extracts. -/
theorem ks_salts_nodup : (ksSalts.map utf8).Nodup := by decide

/-- The Expand `info` of a node: `label ‖ 0x00 ‖ fields`. -/
def ksInfo (label : String) (fields : Bytes) : Bytes := tagged (utf8 label) fields

theorem ksInfo_split {l1 l2 : String} (h1 : l1 ∈ ksLabels) (h2 : l2 ∈ ksLabels) {f1 f2 : Bytes}
    (h : ksInfo l1 f1 = ksInfo l2 f2) : utf8 l1 = utf8 l2 ∧ f1 = f2 :=
  tagged_injective _ _ _ _ (ksLabels_nul_free _ h1) (ksLabels_nul_free _ h2) h

/-! The nodes under the wallet root. -/

/-- An Expand under `PRK_w`, with its context. -/
inductive WNode where
  | nonce (net : Bytes) (idx : Nat)
  | grk (net : Bytes) (idx ver : Nat)
  | atta (g : Wire 32) (slot : Nat)
  | dseed (g : Wire 32) (slot : Nat)
  | s0 (g : Wire 32) (slot : Nat) (aph : Wire 32)
  | sdk (devid g : Wire 32)
  | recAead
  | recAuth

def WNode.label : WNode → String
  | .nonce _ _ => lNonce
  | .grk _ _ _ => lGrk
  | .atta _ _ => lAtta
  | .dseed _ _ => lDevSeed
  | .s0 _ _ _ => lS0
  | .sdk _ _ => lSdk
  | .recAead => lRecAead
  | .recAuth => lRecAuth

def WNode.fields : WNode → Bytes
  | .nonce net idx => lp net ++ le32 idx
  | .grk net idx ver => lp net ++ (le32 idx ++ le32 ver)
  | .atta g slot => g.val ++ le32 slot
  | .dseed g slot => g.val ++ le32 slot
  | .s0 g slot aph => g.val ++ (le32 slot ++ aph.val)
  | .sdk devid g => devid.val ++ g.val
  | .recAead => []
  | .recAuth => []

def WNode.info (n : WNode) : Bytes := ksInfo n.label n.fields

/-- The integer fields fit in `u32`, as the Rust types guarantee. -/
def WNode.ok : WNode → Prop
  | .nonce net idx => net.length < 2^32 ∧ idx < 2^32
  | .grk net idx ver => net.length < 2^32 ∧ idx < 2^32 ∧ ver < 2^32
  | .atta _ slot => slot < 2^32
  | .dseed _ slot => slot < 2^32
  | .s0 _ slot _ => slot < 2^32
  | _ => True

def WNode.tag : WNode → Nat
  | .nonce _ _ => 0 | .grk _ _ _ => 1 | .atta _ _ => 2 | .dseed _ _ => 3 | .s0 _ _ _ => 4
  | .sdk _ _ => 5 | .recAead => 6 | .recAuth => 7

theorem WNode.label_mem (n : WNode) : n.label ∈ ksLabels := by cases n <;> simp only [WNode.label] <;> decide

theorem WNode.tag_of_label (a b : WNode) (h : utf8 a.label = utf8 b.label) : a.tag = b.tag := by
  cases a <;> cases b <;> simp only [WNode.label, WNode.tag] at h ⊢ <;> first | rfl | exact absurd h (by decide)

/-- **Context injectivity under the wallet root.** Two Expands under `PRK_w` with the
    same `info` are the same node with the same context. -/
theorem wnode_info_inj (a b : WNode) (ha : a.ok) (hb : b.ok) (h : a.info = b.info) : a = b := by
  obtain ⟨hl, hf⟩ := ksInfo_split a.label_mem b.label_mem h
  have ht := WNode.tag_of_label a b hl
  cases a <;> cases b <;> (try (simp [WNode.tag] at ht; done)) <;> simp only [WNode.fields] at hf <;>
    simp only [WNode.ok] at ha hb
  · obtain ⟨h1, h2⟩ := lp_split ha.1 hb.1 hf
    rw [h1, le32_inj ha.2 hb.2 h2]
  · obtain ⟨h1, h2⟩ := lp_split ha.1 hb.1 hf
    obtain ⟨h3, h4⟩ := le32_split ha.2.1 hb.2.1 h2
    rw [h1, h3, le32_inj ha.2.2 hb.2.2 h4]
  · obtain ⟨h1, h2⟩ := wire_split hf
    rw [h1, le32_inj ha hb h2]
  · obtain ⟨h1, h2⟩ := wire_split hf
    rw [h1, le32_inj ha hb h2]
  · obtain ⟨h1, h2⟩ := wire_split hf
    obtain ⟨h3, h4⟩ := le32_split ha hb h2
    rw [h1, h3, Subtype.ext h4]
  · obtain ⟨h1, h2⟩ := wire_split hf
    rw [h1, Subtype.ext h2]
  · rfl
  · rfl

/-! The nodes under `s0` and under the device seed. -/

/-- An Expand under `PRK_s0`. -/
inductive SNode where
  | smaster (g devid aph : Wire 32)
  | atRest (g devid : Wire 32)

def SNode.label : SNode → String
  | .smaster _ _ _ => lSmaster
  | .atRest _ _ => lAtRest

def SNode.fields : SNode → Bytes
  | .smaster g devid aph => g.val ++ (devid.val ++ aph.val)
  | .atRest g devid => g.val ++ devid.val

def SNode.info (n : SNode) : Bytes := ksInfo n.label n.fields

/-- **Context injectivity under `s0`**: `Smaster` and the at-rest key are Expands at
    distinct inputs, so exposing the at-rest key reveals an output at another input. -/
theorem snode_info_inj (a b : SNode) (h : a.info = b.info) : a = b := by
  have hm : ∀ n : SNode, n.label ∈ ksLabels := fun n => by cases n <;> simp only [SNode.label] <;> decide
  obtain ⟨hl, hf⟩ := ksInfo_split (hm a) (hm b) h
  cases a <;> cases b <;> simp only [SNode.label, SNode.fields] at hl hf
  · obtain ⟨h1, h2⟩ := wire_split hf
    obtain ⟨h3, h4⟩ := wire_split h2
    rw [h1, h3, Subtype.ext h4]
  · exact absurd hl (by decide)
  · exact absurd hl (by decide)
  · obtain ⟨h1, h2⟩ := wire_split hf
    rw [h1, Subtype.ext h2]

/-- The AK seed's Expand under `PRK_d`. -/
def akInfo (aph : Wire 32) : Bytes := ksInfo lAk aph.val

theorem akInfo_inj (a b : Wire 32) (h : akInfo a = akInfo b) : a = b :=
  Subtype.ext (ksInfo_split (by decide) (by decide) h).2

/-! The keyed-BLAKE3 inputs under Smaster. -/

/-- The ML-KEM identity seed's input: `"DSM/ml-kem-identity/v1" ‖ 0x00 ‖ "ML-KEM-768"`. -/
def mlkemInput : Bytes := domainInput "DSM/ml-kem-identity/v1" (utf8 "ML-KEM-768")

/-- The ML-KEM identity input is outside the per-step domain. -/
theorem ekDom_mlkem : ekDom mlkemInput = false := by
  unfold ekDom mlkemInput domainInput ekPrefix
  rw [toUTF8_toList, toUTF8_toList, List.append_assoc, List.take_append_of_le_length (by decide)]
  decide

/-- The three Smaster-keyed inputs are pairwise distinct. -/
theorem smaster_inputs_distinct (alg kalg : Bytes) (c t p s rh tip pre dev : Wire 32) :
    ekSeedInput alg c t p s ≠ coinsInput kalg rh tip pre dev ∧
    ekSeedInput alg c t p s ≠ mlkemInput ∧ coinsInput kalg rh tip pre dev ≠ mlkemInput := by
  refine ⟨fun h => ?_, fun h => ?_, fun h => ?_⟩
  · have := congrArg ekDom h; rw [ekDom_seed, ekDom_coins] at this; exact absurd this (by decide)
  · have := congrArg ekDom h; rw [ekDom_seed, ekDom_mlkem] at this; exact absurd this (by decide)
  · unfold coinsInput mlkemInput at h
    rw [domainInput_eq_tagged, domainInput_eq_tagged, toUTF8_toList, toUTF8_toList] at h
    have := (tagged_injective _ _ _ _ (by decide) (by decide) h).1
    exact absurd this (by decide)

/-- **C67 under KS1.** With the ML-KEM identity key derived by keyed BLAKE3 under
    Smaster, the adversary obtains its seed with one revealed derivation (`leak` at
    `mlkemInput`, outside the per-step domain) and computes the public key itself, so
    the DSM bound holds with no auxiliary input: `Adv` is the ordinary PRF advantage
    of keyed BLAKE3 under Smaster. -/
theorem dsm_forge_256f_ks1 (limits : Limits) (A : Bytes → DAdv) (qh qn ql qs : Nat)
    (hA : ∀ a, DBudget (A a) qh qn ql qs) (hqs : qs ≤ 2^64) (c : Nat) (hc : 0 < c) :
    let R := c * 256^(3*(params .spx256f).n) * 256^(params .spx256f).m
    let N := (mQ (params .spx256f) qh qn qs + 1704962 * qs + 398862) + 1
    let realW := ((List.range (256^32)).map (fun K => tsum R N
        (fun t => ind ((run t (resF (dsmF K) (dplay .spx256f limits [] [] [] (A []))) []).1.win = true)))).sum
    let idealW := ((List.range (256^32)).map (fun _ => tsum (256^32) (qn + ql) (fun ss => tsum R N
        (fun t => ind ((run t (resL [] ss (dplay .spx256f limits [] [] [] (A []))) []).1.win = true))))).sum
    realW * (256^32)^(qn + ql) * 2^256 ≤
      (realW * (256^32)^(qn + ql) - idealW) * 2^256 +
        256^32 * (256^32)^(qn + ql) * (R ^ N * (qn * (27 * mQ (params .spx256f) qh qn qs + 368023))) :=
  dsm_forge_256f limits (fun _ => []) A qh qn ql qs hA hqs c hc

end DSM.Rom
