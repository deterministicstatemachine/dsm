-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.KeySchedule

/- From key schedule KS1 to C67's uniform Smaster: the hybrid hop.

   C67 bounds forgery in the DSM game for a uniform Smaster. KS1 derives Smaster
   from the wallet seed by an Extract to `PRK_w`, eight Expands under it (seven
   siblings and `s0`), an Extract of `s0` to `PRK_s0`, and two Expands under it
   (Smaster and the chain-head at-rest key). This file

   1. defines HMAC-BLAKE3 and HKDF as DSM computes them (`hmacB3`, `hkdfExtract`,
      `expand32`; `KeyScheduleChecks.lean` reproduces the Rust test vectors with
      these definitions);
   2. writes the Expands under one PRK as a straight-line program of requests to
      a derivation function (`kprog`), whose fields may depend on earlier
      outputs, and proves that against a lazily sampled random function every
      request of a program with distinct KS1 labels is fresh, so its outputs are
      independent uniform values (`resL_kprog`);
   3. defines the hybrids as the real and ideal worlds of named distinguishers:
      the game given `PRK_w` (`fromW`), the Expand distinguisher under `PRK_w`
      (`distW`, eight requests), the game given `PRK_s0` (`fromS0`), and the
      Expand distinguisher under `PRK_s0` (`distS`, two requests). The adversary
      is given any function `pubOf` of the seven siblings and the at-rest key;
   4. proves each ideal world is the next real world (`idealW_eq`, `idealS_eq`):
      after the hybrids, Smaster is uniform and independent of everything the
      adversary is given, which is C67's real game with no auxiliary input;
   5. composes the chain with C67 (`ks1_forge_256f`).

   The four KS1 advantages are defined, not bounded: Extract of the BIP39 seed of
   a uniform 256-bit entropy, Expand under a uniform `PRK_w`, Extract of a
   uniform `s0`, and Expand under a uniform `PRK_s0`, each against its uniform
   counterpart. -/
namespace DSM.Rom
open DSM.Sphincs DSM.Sphincs.Security

/-! HMAC-BLAKE3 (RFC 2104: 64-byte block, 32-byte output) and HKDF (RFC 5869). -/

/-- The HMAC key block: a key longer than the block is hashed, then zero-padded to 64 bytes. -/
def hmacKey (k : Bytes) : Bytes :=
  let k' := if 64 < k.length then Blake3.hash k 32 else k
  k' ++ List.replicate (64 - k'.length) 0

def hmacB3 (k m : Bytes) : Bytes :=
  Blake3.hash ((hmacKey k).map (· ^^^ 0x5c) ++ Blake3.hash ((hmacKey k).map (· ^^^ 0x36) ++ m) 32) 32

/-- HKDF-Extract: the salt is the HMAC key, the input keying material the message. -/
def hkdfExtract (salt ikm : Bytes) : Bytes := hmacB3 salt ikm

/-- HKDF-Expand to 32 bytes: `T(1) = HMAC(PRK, info ‖ 0x01)`. -/
def expand32 (prk info : Bytes) : Bytes := hmacB3 prk (info ++ [1])

/-- An Extract salt: `tag ‖ 0x00`. -/
def ksSalt (s : String) : Bytes := utf8 s ++ [0]
def saltW : Bytes := ksSalt "DSM/kdf/wallet-root/v1"
def saltS0 : Bytes := ksSalt "DSM/kdf/s0-root/v1"

/-! Straight-line derivations: Expand queries whose fields depend on the earlier outputs. -/

structure KStep where
  label : String
  fields : List Bytes → Bytes

def KStep.input (s : KStep) (outs : List Bytes) : Bytes := ksInfo s.label (s.fields outs)

/-- Ask the derivation function for every step in order, then continue with all outputs. -/
def kprog {α : Type} : List KStep → List Bytes → (List Bytes → FQT α) → FQT α
  | [], outs, k => k outs
  | s :: rest, outs, k => .fq (s.input outs) (fun y => kprog rest (outs ++ [y]) k)

/-- The outputs under a fixed function. -/
def kreal (F : Bytes → Bytes) : List KStep → List Bytes → List Bytes
  | [], outs => outs
  | s :: rest, outs => kreal F rest (outs ++ [F (s.input outs)])

/-- The outputs when every request takes the next entry of the vector. -/
def kideal : List KStep → List Bytes → List Nat → List Bytes
  | [], outs, _ => outs
  | _ :: rest, outs, ss => kideal rest (outs ++ [be 32 (ss.headD 0)]) ss.tail

theorem resF_kprog {α : Type} (F : Bytes → Bytes) : ∀ (steps : List KStep) (outs : List Bytes)
    (k : List Bytes → FQT α), resF F (kprog steps outs k) = resF F (k (kreal F steps outs))
  | [], _, _ => rfl
  | _ :: rest, _, k => resF_kprog F rest _ k

theorem resF_lift {α : Type} (F : Bytes → Bytes) : ∀ (T : QT α), resF F (liftQ T) = T
  | .done _ => rfl
  | .ask g r k => by
    simp only [liftQ, resF]; congr 1; funext b; exact resF_lift F (k b)

theorem resL_lift {α : Type} (tab : RTab) (ss : List Nat) : ∀ (T : QT α), resL tab ss (liftQ T) = T
  | .done _ => rfl
  | .ask g r k => by
    simp only [liftQ, resL]; congr 1; funext b; exact resL_lift tab ss (k b)

/-- Every table entry is an Expand input under a label outside `L`. -/
def Outside (L : List String) (tab : RTab) : Prop :=
  ∀ e ∈ tab, ∃ l f, l ∈ ksLabels ∧ utf8 l ∉ L.map utf8 ∧ e.1 = ksInfo l f

/-- **Distinct labels make every request fresh.** Against a lazily sampled random
    function, a straight-line derivation whose labels are distinct KS1 labels takes
    the entries of the vector in order, however its fields depend on earlier outputs. -/
theorem resL_kprog {α : Type} : ∀ (steps : List KStep) (tab : RTab) (ss : List Nat) (outs : List Bytes)
    (Q : List Bytes → QT α), (∀ s ∈ steps, s.label ∈ ksLabels) →
    ((steps.map KStep.label).map utf8).Nodup → Outside (steps.map KStep.label) tab →
    resL tab ss (kprog steps outs (fun o => liftQ (Q o))) = Q (kideal steps outs ss)
  | [], tab, ss, outs, Q, _, _, _ => resL_lift tab ss (Q outs)
  | s :: rest, tab, ss, outs, Q, hm, hnd, hout => by
    have hs : s.label ∈ ksLabels := hm s (List.mem_cons_self ..)
    simp only [List.map_cons] at hnd
    have hnd' := List.nodup_cons.1 hnd
    have hfresh : rlook tab (s.input outs) = none := by
      apply rlook_none
      intro hx
      obtain ⟨e, he, hex⟩ := List.mem_map.1 hx
      obtain ⟨l, f, hl, hlo, hef⟩ := hout e he
      rw [hef] at hex
      have hu := (ksInfo_split hl hs hex).1
      apply hlo
      rw [hu]
      simp
    simp only [kprog, resL, hfresh, kideal]
    apply resL_kprog rest
    · exact fun s' h' => hm s' (List.mem_cons_of_mem _ h')
    · exact hnd'.2
    · intro e he
      rcases List.mem_append.1 he with he | he
      · obtain ⟨l, f, hl, hlo, hef⟩ := hout e he
        refine ⟨l, f, hl, fun h => hlo ?_, hef⟩
        simp only [List.map_cons, List.mem_cons]; exact Or.inr h
      · simp only [List.mem_singleton] at he
        subst he
        exact ⟨s.label, s.fields outs, hs, hnd'.1, rfl⟩

theorem kideal_eq : ∀ (steps : List KStep) (outs : List Bytes) (ss : List Nat),
    ss.length = steps.length → kideal steps outs ss = outs ++ ss.map (be 32)
  | [], outs, [], _ => by simp [kideal]
  | _ :: rest, outs, y :: ys, h => by
    simp only [kideal, List.headD_cons, List.tail_cons]
    rw [kideal_eq rest _ ys (by simpa using h)]
    simp
  | [], _, _ :: _, h => absurd h (by simp)
  | _ :: _, _, [], h => absurd h (by simp)

theorem tsum_append (R : Nat) : ∀ (n m : Nat) (F : List Nat → Nat),
    tsum R (n + m) F = tsum R n (fun a => tsum R m (fun b => F (a ++ b)))
  | 0, m, F => by simp [tsum]
  | n+1, m, F => by
    rw [show n + 1 + m = (n + m) + 1 by omega]
    simp only [tsum]
    apply congrArg List.sum; apply List.map_congr_left; intro y _
    rw [tsum_append R n m]
    rfl

/-! The KS1 derivation of Smaster. -/

/-- A wallet's public context: the network, the indices, the authority policy, and how
    `G` and `DevID` are computed from earlier outputs (`G` from the genesis nonce and the
    GRK seed, through the GRK public key; `DevID` from `G` and the device seed, through
    the AK public key). -/
structure WCtx where
  net : Bytes
  idx : Nat
  ver : Nat
  slot : Nat
  aph : Wire 32
  gOf : Bytes → Bytes → Wire 32
  devOf : Wire 32 → Bytes → Wire 32

def WCtx.g (c : WCtx) (o : List Bytes) : Wire 32 := c.gOf (o.getD 0 []) (o.getD 1 [])
def WCtx.dev (c : WCtx) (o : List Bytes) : Wire 32 := c.devOf (c.g o) (o.getD 3 [])

/-- The eight Expands under `PRK_w`, `s0` last: the first seven are the siblings. -/
def wSteps (c : WCtx) : List KStep :=
  [⟨lNonce, fun _ => lp c.net ++ le32 c.idx⟩,
   ⟨lGrk, fun _ => lp c.net ++ (le32 c.idx ++ le32 c.ver)⟩,
   ⟨lAtta, fun o => (c.g o).val ++ le32 c.slot⟩,
   ⟨lDevSeed, fun o => (c.g o).val ++ le32 c.slot⟩,
   ⟨lSdk, fun o => (c.dev o).val ++ (c.g o).val⟩,
   ⟨lRecAead, fun _ => []⟩,
   ⟨lRecAuth, fun _ => []⟩,
   ⟨lS0, fun o => (c.g o).val ++ (le32 c.slot ++ c.aph.val)⟩]

/-- The two Expands under `PRK_s0`: Smaster, then the at-rest key. -/
def sSteps (c : WCtx) (sib : List Bytes) : List KStep :=
  [⟨lSmaster, fun _ => (c.g sib).val ++ ((c.dev sib).val ++ c.aph.val)⟩,
   ⟨lAtRest, fun _ => (c.g sib).val ++ (c.dev sib).val⟩]

/-- The inputs are exactly C68's nodes. -/
theorem wSteps_info (c : WCtx) (o : List Bytes) : (wSteps c).map (·.input o) =
    [(WNode.nonce c.net c.idx).info, (WNode.grk c.net c.idx c.ver).info, (WNode.atta (c.g o) c.slot).info,
     (WNode.dseed (c.g o) c.slot).info, (WNode.sdk (c.dev o) (c.g o)).info, WNode.recAead.info,
     WNode.recAuth.info, (WNode.s0 (c.g o) c.slot c.aph).info] := rfl

theorem sSteps_info (c : WCtx) (sib o : List Bytes) : (sSteps c sib).map (·.input o) =
    [(SNode.smaster (c.g sib) (c.dev sib) c.aph).info, (SNode.atRest (c.g sib) (c.dev sib)).info] := rfl

theorem labels_ok (steps : List KStep) (L : List String) (h : steps.map KStep.label = L)
    (hL : ∀ l ∈ L, l ∈ ksLabels) : ∀ s ∈ steps, s.label ∈ ksLabels :=
  fun _ hs => hL _ (h ▸ List.mem_map_of_mem hs)

theorem wSteps_labels (c : WCtx) : (wSteps c).map KStep.label =
    [lNonce, lGrk, lAtta, lDevSeed, lSdk, lRecAead, lRecAuth, lS0] := rfl

theorem sSteps_labels (c : WCtx) (sib : List Bytes) : (sSteps c sib).map KStep.label = [lSmaster, lAtRest] := rfl

theorem wSteps_ok (c : WCtx) : ∀ s ∈ wSteps c, s.label ∈ ksLabels :=
  labels_ok _ _ (wSteps_labels c) (by decide)

theorem sSteps_ok (c : WCtx) (sib : List Bytes) : ∀ s ∈ sSteps c sib, s.label ∈ ksLabels :=
  labels_ok _ _ (sSteps_labels c sib) (by decide)

theorem wSteps_nodup (c : WCtx) : (((wSteps c).map KStep.label).map utf8).Nodup := by
  rw [wSteps_labels]; decide

theorem sSteps_nodup (c : WCtx) (sib : List Bytes) : (((sSteps c sib).map KStep.label).map utf8).Nodup := by
  rw [sSteps_labels]; decide

/-! The games. -/

section
variable (limits : Limits) (A : Bytes → DAdv) (pubOf : List Bytes → Bytes) (c : WCtx)

/-- C67's DSM game under Smaster `sm`, the adversary given `pubOf pub`. -/
def dgame (sm : Bytes) (pub : List Bytes) : QT MOut :=
  resF (fun x => Blake3.keyedHash sm x 32) (dplay .spx256f limits [] [] [] (A (pubOf pub)))

/-- Below `PRK_s0`: Smaster keys the game; the at-rest key is disclosed with the siblings. -/
def belowS (sib so : List Bytes) : QT MOut := dgame limits A pubOf (so.getD 0 []) (sib ++ [so.getD 1 []])

/-- The distinguisher against Expand under `PRK_s0` (two requests). -/
def distS (sib : List Bytes) : FQT MOut := kprog (sSteps c sib) [] (fun so => liftQ (belowS limits A pubOf sib so))

/-- The game given `PRK_s0`. -/
def fromS0 (q : Bytes) (sib : List Bytes) : QT MOut := resF (expand32 q) (distS limits A pubOf c sib)

/-- The distinguisher against Expand under `PRK_w` (eight requests): the siblings are
    disclosed, and `s0` is Extracted to `PRK_s0`. -/
def distW : FQT MOut :=
  kprog (wSteps c) [] (fun wo => liftQ (fromS0 limits A pubOf c (hkdfExtract saltS0 (wo.getD 7 [])) (wo.take 7)))

/-- The game given `PRK_w`. -/
def fromW (p : Bytes) : QT MOut := resF (expand32 p) (distW limits A pubOf c)

/-- The game given the wallet seed. -/
def fromWallet (ws : Bytes) : QT MOut := fromW limits A pubOf c (hkdfExtract saltW ws)

/-- The real game, unfolded: Smaster and the disclosed values are KS1's. -/
theorem fromWallet_eq (ws : Bytes) :
    fromWallet limits A pubOf c ws =
      let wo := kreal (expand32 (hkdfExtract saltW ws)) (wSteps c) []
      let so := kreal (expand32 (hkdfExtract saltS0 (wo.getD 7 []))) (sSteps c (wo.take 7)) []
      dgame limits A pubOf (so.getD 0 []) (wo.take 7 ++ [so.getD 1 []]) := by
  simp only [fromWallet, fromW, distW, resF_kprog, resF_lift, fromS0, distS, belowS]

/-- **The ideal world under `PRK_w` is the real world of the Extract of `s0`.** With
    Expand under `PRK_w` a lazily sampled random function, the eight requests are fresh
    (distinct labels), so the siblings and `s0` are independent uniform values; `s0`
    is then only the input of the Extract to `PRK_s0`. -/
theorem idealW_eq (M : Nat) (W : QT MOut → Nat) :
    tsum M 8 (fun ss => W (resL [] ss (distW limits A pubOf c))) =
      tsum M 7 (fun a => ((List.range M).map (fun u =>
        W (fromS0 limits A pubOf c (hkdfExtract saltS0 (be 32 u)) (a.map (be 32))))).sum) := by
  have e : ∀ ss, resL [] ss (distW limits A pubOf c) =
      fromS0 limits A pubOf c (hkdfExtract saltS0 ((kideal (wSteps c) [] ss).getD 7 []))
        ((kideal (wSteps c) [] ss).take 7) :=
    fun ss => resL_kprog (wSteps c) [] ss [] _ (wSteps_ok c) (wSteps_nodup c) (fun _ he => absurd he (by simp))
  have hlen : (wSteps c).length = 8 := rfl
  have hl : ∀ (a : List Nat) (u : Nat), a.length = 7 →
      (kideal (wSteps c) [] (a ++ [u])).getD 7 [] = be 32 u ∧
        (kideal (wSteps c) [] (a ++ [u])).take 7 = a.map (be 32) := by
    intro a u ha
    rw [kideal_eq _ _ _ (by rw [hlen, List.length_append, ha]; rfl)]
    have h7 : (a.map (be 32)).length = 7 := by rw [List.length_map, ha]
    rw [List.nil_append, List.map_append]
    refine ⟨?_, List.take_left' h7⟩
    rw [List.getD_eq_getElem?_getD, List.getElem?_append_right (by omega), h7]
    rfl
  rw [funext (fun ss => congrArg W (e ss))]
  rw [show 8 = 7 + 1 from rfl, tsum_append]
  apply tsum_congr_len; intro a ha
  show ((List.range M).map (fun u => W (fromS0 limits A pubOf c
      (hkdfExtract saltS0 ((kideal (wSteps c) [] (a ++ [u])).getD 7 []))
      ((kideal (wSteps c) [] (a ++ [u])).take 7)))).sum = _
  apply congrArg List.sum; apply List.map_congr_left; intro u _
  rw [(hl a u ha).1, (hl a u ha).2]

/-- **The ideal world under `PRK_s0`.** Smaster and the at-rest key are independent
    uniform values. -/
theorem idealS_eq (M : Nat) (W : QT MOut → Nat) (sib : List Bytes) :
    tsum M 2 (fun ss => W (resL [] ss (distS limits A pubOf c sib))) =
      ((List.range M).map (fun k => ((List.range M).map (fun r =>
        W (dgame limits A pubOf (be 32 k) (sib ++ [be 32 r])))).sum)).sum := by
  have e : ∀ ss, resL [] ss (distS limits A pubOf c sib) = belowS limits A pubOf sib (kideal (sSteps c sib) [] ss) :=
    fun ss => resL_kprog (sSteps c sib) [] ss [] _ (sSteps_ok c sib) (sSteps_nodup c sib) (fun _ he => absurd he (by simp))
  rw [funext (fun ss => congrArg W (e ss))]
  show ((List.range M).map (fun k => ((List.range M).map (fun r =>
      W (belowS limits A pubOf sib (kideal (sSteps c sib) [] [k, r])))).sum)).sum = _
  rfl

end

/-! The bound. -/

theorem range_sum_swap (M : Nat) (f : Nat → Nat → Nat) :
    ((List.range M).map (fun k => ((List.range M).map (fun r => f k r)).sum)).sum =
      ((List.range M).map (fun r => ((List.range M).map (fun k => f k r)).sum)).sum :=
  tsum_comm M M 1 1 (fun a b => f (a.headD 0) (b.headD 0))

theorem pow9 (x y : Nat) : x^7 * (x * (x * y)) = x^9 * y := by
  simp only [Nat.pow_succ, Nat.pow_zero, Nat.one_mul, Nat.mul_assoc]

/-- The hybrid chain, in counts: each step is `x ≤ (x - y) + y`. -/
theorem hop_chain (h0 h1 h2 h3 h4 m k t z : Nat) (hs : h4 * k ≤ t + z) :
    h0 * m^8 * k ≤ ((h0 - h1) * m^8 + (h1 * m^7 - h2) * m + (h2 - h3) * m + (h3 * m - h4)) * k + t + z := by
  have s1 : h0 * m^8 ≤ (h0 - h1) * m^8 + h1 * m^8 := by
    rw [← Nat.add_mul]; exact Nat.mul_le_mul_right _ (by omega)
  have s2 : h1 * m^8 ≤ (h1 * m^7 - h2) * m + h2 * m := by
    rw [← Nat.add_mul, Nat.pow_succ, ← Nat.mul_assoc]; exact Nat.mul_le_mul_right _ (by omega)
  have s3 : h2 * m ≤ (h2 - h3) * m + h3 * m := by
    rw [← Nat.add_mul]; exact Nat.mul_le_mul_right _ (by omega)
  have s4 : h3 * m ≤ (h3 * m - h4) + h4 := by omega
  have a : h0 * m^8 ≤ ((h0 - h1) * m^8 + (h1 * m^7 - h2) * m + (h2 - h3) * m + (h3 * m - h4)) + h4 := by omega
  calc h0 * m^8 * k ≤ (((h0 - h1) * m^8 + (h1 * m^7 - h2) * m + (h2 - h3) * m + (h3 * m - h4)) + h4) * k :=
        Nat.mul_le_mul_right _ a
    _ = ((h0 - h1) * m^8 + (h1 * m^7 - h2) * m + (h2 - h3) * m + (h3 * m - h4)) * k + h4 * k := Nat.add_mul _ _ _
    _ ≤ ((h0 - h1) * m^8 + (h1 * m^7 - h2) * m + (h2 - h3) * m + (h3 * m - h4)) * k + (t + z) :=
        Nat.add_le_add_left hs _
    _ = _ := (Nat.add_assoc _ _ _).symm

/-- **KS1 to C67, SPX256f.** The DSM game with Smaster derived by KS1 from the wallet
    seed `bip e` of a uniform 256-bit entropy `e` (H0), the adversary given any
    function `pubOf` of the seven siblings of `s0` under `PRK_w` and of the at-rest key.
    With `D = R^N` tapes, `M = 2^256` and `L = qn + ql`:

    * `H2 = H2'` and `H4 = Σ realW`: each ideal world is the next real world (the
      requests under one PRK are fresh by their distinct labels, `resL_kprog`);
    * `Pr[H0] ≤ ΔExt_w + ΔPRF_w + ΔExt_s0 + ΔPRF_s0 + E[Adv_C67] + qn·(27Q + 368023)/2^256`,
      where, dividing the bound by `M^9·M^L·D·2^256`:
      `ΔExt_w = (H0 − H1)/(M·D)`, the advantage of `fromW` between `Extract(saltW, bip e)`
      and a uniform PRK; `ΔPRF_w = (H1·M^7 − H2)/(M^8·D)`, that of `distW` (eight
      requests) between Expand under a uniform PRK and a random function;
      `ΔExt_s0 = (H2' − H3)/(M^8·D)`, that of `fromS0 · sib` between
      `Extract(saltS0, u)` for uniform `u` and a uniform PRK, averaged over the
      siblings; `ΔPRF_s0 = (H3·M − H4)/(M^9·D)`, that of `distS` (two requests); and
      `E[Adv_C67]`, C67's PRF advantage for keyed BLAKE3 under a uniform Smaster with
      no auxiliary input, averaged over the disclosed values. None is bounded here. -/
theorem ks1_forge_256f (limits : Limits) (A : Bytes → DAdv) (pubOf : List Bytes → Bytes) (c : WCtx)
    (bip : Nat → Bytes) (qh qn ql qs : Nat)
    (hA : ∀ a, DBudget (A a) qh qn ql qs) (hqs : qs ≤ 2^64) (cc : Nat) (hc : 0 < cc) :
    let R := cc * 256^(3*(params .spx256f).n) * 256^(params .spx256f).m
    let N := (mQ (params .spx256f) qh qn qs + 1704962 * qs + 398862) + 1
    let M := 256^32
    let L := qn + ql
    let W := fun T : QT MOut => tsum R N (fun t => ind ((run t T []).1.win = true))
    let H0 := ((List.range M).map (fun e => W (fromWallet limits A pubOf c (bip e)))).sum
    let H1 := ((List.range M).map (fun p => W (resF (expand32 (be 32 p)) (distW limits A pubOf c)))).sum
    let H2 := tsum M 8 (fun ss => W (resL [] ss (distW limits A pubOf c)))
    let H2' := tsum M 7 (fun a => ((List.range M).map (fun u =>
        W (fromS0 limits A pubOf c (hkdfExtract saltS0 (be 32 u)) (a.map (be 32))))).sum)
    let H3 := tsum M 7 (fun a => ((List.range M).map (fun q =>
        W (resF (expand32 (be 32 q)) (distS limits A pubOf c (a.map (be 32)))))).sum)
    let H4 := tsum M 7 (fun a => tsum M 2 (fun ss => W (resL [] ss (distS limits A pubOf c (a.map (be 32))))))
    let realW := fun (a : List Nat) (r : Nat) => ((List.range M).map (fun K =>
        W (resF (dsmF K) (dplay .spx256f limits [] [] [] (A (pubOf (a.map (be 32) ++ [be 32 r]))))))).sum
    let idealW := fun (a : List Nat) (r : Nat) => ((List.range M).map (fun _ => tsum M L (fun ss =>
        W (resL [] ss (dplay .spx256f limits [] [] [] (A (pubOf (a.map (be 32) ++ [be 32 r])))))))).sum
    H2 = H2' ∧ H4 = tsum M 7 (fun a => ((List.range M).map (fun r => realW a r)).sum) ∧
    H0 * M^8 * M^L * 2^256 ≤
      ((H0 - H1) * M^8 + (H1 * M^7 - H2) * M + (H2' - H3) * M + (H3 * M - H4)) * M^L * 2^256 +
      tsum M 7 (fun a => ((List.range M).map (fun r => realW a r * M^L - idealW a r)).sum) * 2^256 +
      M^9 * M^L * (R^N * (qn * (27 * mQ (params .spx256f) qh qn qs + 368023))) := by
  intro R N M L W H0 H1 H2 H2' H3 H4 realW idealW
  have e2 : H2 = H2' := idealW_eq limits A pubOf c M W
  have e4 : H4 = tsum M 7 (fun a => ((List.range M).map (fun r => realW a r)).sum) := by
    apply tsum_congr_len; intro a _
    rw [idealS_eq limits A pubOf c M W (a.map (be 32)), range_sum_swap]
    rfl
  refine ⟨e2, e4, ?_⟩
  generalize hX : R^N * (qn * (27 * mQ (params .spx256f) qh qn qs + 368023)) = X
  have hC : ∀ a r, realW a r * M^L * 2^256 ≤ (realW a r * M^L - idealW a r) * 2^256 + M * M^L * X := by
    intro a r
    rw [← hX]
    exact dsm_forge_256f limits (fun _ => []) (fun _ => A (pubOf (a.map (be 32) ++ [be 32 r])))
      qh qn ql qs (fun _ => hA _) hqs cc hc
  have per : ∀ a, (M^L * 2^256) * ((List.range M).map (fun r => realW a r)).sum ≤
      2^256 * ((List.range M).map (fun r => realW a r * M^L - idealW a r)).sum + M * (M * M^L * X) := by
    intro a
    rw [← sum_map_mul, ← sum_map_mul]
    calc _ ≤ ((List.range M).map (fun r => 2^256 * (realW a r * M^L - idealW a r) + M * M^L * X)).sum :=
          sum_map_le _ (fun r _ => by
            have h := hC a r
            rw [(Nat.mul_comm _ _).trans (Nat.mul_assoc _ _ _).symm, Nat.mul_comm (2^256)]
            exact h)
      _ = _ := by rw [sum_map_add, sum_map_const, List.length_range]
  have hs : H4 * (M^L * 2^256) ≤
      tsum M 7 (fun a => ((List.range M).map (fun r => realW a r * M^L - idealW a r)).sum) * 2^256 +
        M^9 * M^L * X := by
    rw [e4, Nat.mul_comm, ← tsum_mul]
    calc _ ≤ tsum M 7 (fun a => 2^256 * ((List.range M).map (fun r => realW a r * M^L - idealW a r)).sum +
            M * (M * M^L * X)) := tsum_mono _ _ per
      _ = _ := by
        rw [tsum_add, tsum_mul, tsum_const, Nat.mul_comm (2^256), Nat.mul_assoc M, pow9, Nat.mul_assoc]
  have := hop_chain H0 H1 H2 H3 H4 M (M^L * 2^256) _ _ hs
  rw [← e2]
  simp only [Nat.mul_assoc] at this ⊢
  exact this

end DSM.Rom
