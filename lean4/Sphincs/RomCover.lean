-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomSecGame

/- Coverage read on the extended run's table is coverage on the main run's table:
   the two tables agree on every draw of the main run, and every request the
   covered event reads (the forgery's digest request, and for each signed message
   its PRF-msg key, randomizer and signing requests) was drawn in the main run.
   Then the inclusion of events for H1, summed over tapes. -/
namespace DSM.Rom
open DSM.Sphincs DSM.Sphincs.Security

/-! Requests in the logs of `sign` and `verify`. -/

theorem ext_oracle (o : Oracle Id) (r : Request) : Ext (logOracle o r) :=
  fun s => ⟨[r], by rw [logOracle_run]⟩

/-- The PRF-msg key derivation of a signing run. -/
def dReqB (v : Variant) (sk : Bytes) : Request :=
  ⟨0, "DSM/sphincs/v2/prf-msg", [], slice sk (params v).n (params v).n, 32⟩

/-- The randomizer request of a signing run. -/
def rReqB (o : Oracle Id) (v : Variant) (sk msg : Bytes) : Request :=
  ⟨1, "", o (dReqB v sk), slice sk (2*(params v).n) (params v).n ++ msg, (params v).n⟩

theorem sign_log_dReq (o : Oracle Id) (v : Variant) (sk msg : Bytes) (hne : msg.isEmpty = false)
    (hsk : sk.length = 4*(params v).n) : Mem (dReqB v sk) (sign (logOracle o) v sk msg) := by
  have hc : (msg.isEmpty || sk.length != 4*(params v).n) = false := by simp [hne, hsk]
  simp only [sign, hc, Bool.false_eq_true, if_false]
  refine mem_pure_bind _ _ _ (mem_oracle_bind _ _ _ _ (mem_oracle_bind _ _ _ _ (mem_oracle_here _ _ _ ?_)))
  intro mk
  refine ext_bind (ext_oracle _ _) (fun r => ext_bind (ext_oracle _ _) (fun dg => ?_))
  exact ext_bind (ext_cost (forsSign_cost _ _)) (fun fs => ext_bind (ext_cost (forsPkFromSig_cost _ _ _))
    (fun fpk => ext_bind (ext_cost (htSign_cost _ _ _)) (fun hs => ext_bind (ext_cost (htRoot_cost _ _ _ _))
      (fun ac => ext_ite (ext_pure _) (ext_bind (ext_pure _) (fun _ => ext_pure _))))))

theorem sign_log_rReq (o : Oracle Id) (v : Variant) (sk msg : Bytes) (hne : msg.isEmpty = false)
    (hsk : sk.length = 4*(params v).n) : Mem (rReqB o v sk msg) (sign (logOracle o) v sk msg) := by
  have hc : (msg.isEmpty || sk.length != 4*(params v).n) = false := by simp [hne, hsk]
  simp only [sign, hc, Bool.false_eq_true, if_false]
  refine mem_pure_bind _ _ _ (mem_oracle_bind _ _ _ _ (mem_oracle_bind _ _ _ _ (mem_oracle_bind _ _ _ _
    (mem_oracle_here _ _ _ ?_))))
  intro r
  refine ext_bind (ext_oracle _ _) (fun dg => ?_)
  exact ext_bind (ext_cost (forsSign_cost _ _)) (fun fs => ext_bind (ext_cost (forsPkFromSig_cost _ _ _))
    (fun fpk => ext_bind (ext_cost (htSign_cost _ _ _)) (fun hs => ext_bind (ext_cost (htRoot_cost _ _ _ _))
      (fun ac => ext_ite (ext_pure _) (ext_bind (ext_pure _) (fun _ => ext_pure _))))))

/-- The digest request of an accepting verification. -/
def vReqB (v : Variant) (pk msg sig : Bytes) : Request :=
  ⟨2, "DSM/sphincs/v2/h-msg", [], sig.take (params v).n ++ pk.take (params v).n ++ pk.drop (params v).n ++ msg,
    (params v).m⟩

theorem verify_log_hmsg (o : Oracle Id) (v : Variant) (pk msg sig : Bytes) (hv : verify o v pk msg sig = some true) :
    vReqB v pk msg sig ∈ verifyLog o v pk msg sig := by
  obtain ⟨hpklen, hsiglen⟩ := accepted_requires_exact_lengths o v _ msg sig hv
  have hne : msg.isEmpty = false := by
    cases ee : msg.isEmpty
    · rfl
    · rw [List.isEmpty_iff.mp ee, verify_empty] at hv; cases hv
  have hl : (pk.length != 2*(params v).n || sig.length != (params v).sigBytes) = false := by
    simp [hpklen, hsiglen]
  have hm : Mem (vReqB v pk msg sig) (verify (logOracle o) v pk msg sig) := by
    simp only [verify, hne, hl, Bool.false_eq_true, if_false]
    refine mem_pure_bind _ _ _ (mem_pure_bind _ _ _ (mem_oracle_bind _ _ _ _ (mem_oracle_here _ _ _ ?_)))
    intro dg
    exact ext_bind (ext_cost (forsPkFromSig_cost _ _ _)) (fun fpk => ext_bind (ext_cost (htRoot_cost _ _ _ _))
      (fun ac => ext_pure _))
  exact hm []

/-! Every request of a signing run in the play is drawn in the run. -/

theorem play_signlog (t : List Nat) (v : Variant) (limits : Limits) (pk sk : Bytes) :
    ∀ (A : RAdv) (signed : List Bytes) (d D : List Draw),
    Pre (run t (playQT v limits pk sk A signed) d).2 D →
    ∀ m ∈ (run t (playQT v limits pk sk A signed) d).1.signed, m ∉ signed → m.isEmpty = false ∧
      ∀ r ∈ ((sign (logOracle (oracleOf t D)) v sk m).run []).2,
        ∃ e ∈ (run t (playQT v limits pk sk A signed) d).2, e.2 = r
  | .hq r k, signed, d, D, hD => by
    simp only [playQT, run] at hD ⊢
    cases hf : findDraw d r with
    | some i =>
      simp only [hf] at hD ⊢
      exact play_signlog t v limits pk sk (k _) signed d D hD
    | none =>
      simp only [hf] at hD ⊢
      exact play_signlog t v limits pk sk (k _) signed (d ++ [(true, r)]) D hD
  | .sq m k, signed, d, D, hD => by
    simp only [playQT] at hD ⊢
    split
    · next hl =>
      rw [if_pos hl] at hD
      rw [run_bind] at hD ⊢
      have hq : QL false t (sign challengerOracle v sk m) (fun O => sign (logOracle O) v sk m) := ql_sign false v sk m
      have hpre : Pre (run t (sign challengerOracle v sk m) d).2 D := Pre.trans (pre_run t _ _) hD
      obtain ⟨L, eL, mL, -⟩ := hq d D hpre []
      have ih := play_signlog t v limits pk sk (k _) (signed ++ [m]) _ D hD
      intro x hx hn
      by_cases hxm : x = m
      · subst hxm
        refine ⟨by simp only [legal, Bool.and_eq_true, Bool.not_eq_true'] at hl; exact hl.1, fun r hr => ?_⟩
        rw [eL] at hr
        obtain ⟨e, he, her⟩ := mL r (by simpa using hr)
        obtain ⟨E₂, hE₂⟩ := pre_run t (playQT v limits pk sk (k (run t (sign challengerOracle v sk x) d).1)
          (signed ++ [x])) (run t (sign challengerOracle v sk x) d).2
        exact ⟨e, by rw [hE₂]; exact List.mem_append_left _ he, her⟩
      · exact ih x hx (by simp [hn, hxm])
    · next hl =>
      rw [if_neg hl] at hD
      exact play_signlog t v limits pk sk (k none) signed d D hD
  | .out m s, signed, d, D, hD => by
    simp only [playQT] at hD ⊢
    rw [run_bind] at hD ⊢
    simp only [run] at hD ⊢
    intro x hx hn
    exact absurd hx hn

section
variable (v : Variant) (limits : Limits) (A : Bytes → RAdv)

theorem game_signlog (t : List Nat) :
    ∀ m ∈ (runG v limits A t).1.signed, m.isEmpty = false ∧
      ∀ r ∈ ((sign (logOracle (finO v limits A t)) v (finKey v limits A t).2 m).run []).2,
        ∃ e ∈ (runG v limits A t).2, e.2 = r := by
  have hpl := play_signlog t v limits (finKey v limits A t).1 (finKey v limits A t).2
    (A (finKey v limits A t).1) []
    (run t (kgTail challengerOracle v (sres t (coinEx (params v).n))) (resD t (coinSt (params v).n))).2
    (runG v limits A t).2 (by rw [← runG_play]; exact ⟨[], by simp⟩)
  rw [← runG_play] at hpl
  exact fun m hm => hpl m hm (by simp)

/-- The extended run's table answers every main-run draw as the main run's table. -/
theorem fin_agree (t : List Nat) {r : Request} (h : ∃ e ∈ (runG v limits A t).2, e.2 = r) :
    finO' v limits A t r = finO v limits A t r := by
  obtain ⟨i, hi⟩ := findDraw_of_mem _ _ h
  obtain ⟨X, hX⟩ := pre_ext v limits A t
  have hi' := findDraw_append_some _ X _ _ hi
  rw [← hX] at hi'
  simp only [finO', finO, oracleOf, hi, hi']

/-- Coverage on the extended run's table is coverage on the main run's table. -/
theorem cov_transfer (t : List Nat) (hw : (runG v limits A t).1.win = true)
    (hcov : CoveredBy (finO' v limits A t) v (finKey v limits A t).2 (runG v limits A t).1.signed
      (splitDigest (params v) (verifyDigest (finO' v limits A t) v (finKey v limits A t).1
        (runG v limits A t).1.msg (runG v limits A t).1.sig))) :
    CovG v limits A t := by
  have hp := play_extract t v limits (finKey v limits A t).1 (finKey v limits A t).2
    (A (finKey v limits A t).1) []
    (run t (kgTail challengerOracle v (sres t (coinEx (params v).n))) (resD t (coinSt (params v).n))).2
    (by rw [← runG_play]; exact hw) (runG v limits A t).2 (by rw [← runG_play]; exact ⟨[], by simp⟩)
  rw [← runG_play] at hp
  obtain ⟨hv, -, -, hlog⟩ := hp
  have hvd : verifyDigest (finO' v limits A t) v (finKey v limits A t).1 (runG v limits A t).1.msg
      (runG v limits A t).1.sig = verifyDigest (finO v limits A t) v (finKey v limits A t).1
        (runG v limits A t).1.msg (runG v limits A t).1.sig :=
    fin_agree v limits A t (hlog _ (verify_log_hmsg _ _ _ _ _ hv))
  have hsd : ∀ m ∈ (runG v limits A t).1.signed,
      signDigest (finO' v limits A t) v (finKey v limits A t).2 m =
        signDigest (finO v limits A t) v (finKey v limits A t).2 m := by
    intro m hm
    obtain ⟨hne, hl⟩ := game_signlog v limits A t m hm
    have hsk := finKey_len v limits A t
    have e0 := fin_agree v limits A t (hl _ (sign_log_dReq _ v _ m hne hsk []))
    have e1 := fin_agree v limits A t (hl _ (sign_log_rReq _ v _ m hne hsk []))
    have e2 := fin_agree v limits A t (hl _ (sign_log_mem _ v _ m hne hsk []))
    have hr : hreqOf (finO' v limits A t) v (finKey v limits A t).2 m =
        hreqOf (finO v limits A t) v (finKey v limits A t).2 m := by
      unfold hreqOf keyed deriveKey
      unfold dReqB at e0
      unfold rReqB dReqB at e1
      rw [e0, e1]
    show finO' v limits A t (hreqOf (finO' v limits A t) v (finKey v limits A t).2 m) =
      finO v limits A t (hreqOf (finO v limits A t) v (finKey v limits A t).2 m)
    rw [hr, e2]
  unfold CovG
  rw [hvd] at hcov
  intro i hi
  obtain ⟨m, hm, h1, h2, h3⟩ := hcov i hi
  rw [hsd m hm] at h1 h2 h3
  exact ⟨m, hm, h1, h2, h3⟩

/-- On every tape on which H1 is won: a canonical collision in the verifier's log on
    H1''s table, ITSR coverage on H1's table, or a disagreement step of H1'. -/
theorem rom_win_split (t : List Nat) :
    ind ((runG v limits A t).1.win = true) ≤
      ind (CanonCollIn (finO' v limits A t) (params v) (expTk (finO' v limits A t) v (sres t (coinEx (params v).n)))
        (expPrf (finO' v limits A t) v (sres t (coinEx (params v).n))) (expSeed v (sres t (coinEx (params v).n)))
        (verifyLog (finO' v limits A t) v (finKey v limits A t).1 (runG v limits A t).1.msg
          (runG v limits A t).1.sig)) +
      ind ((runG v limits A t).1.win = true ∧ CovG v limits A t) +
      (if anyDis (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) t then 1 else 0) := by
  by_cases hw : (runG v limits A t).1.win = true
  · rw [ind_of hw]
    rcases rom_extract_sec v limits A t hw with h | h | h
    · rw [ind_of h]; omega
    · rw [ind_of (P := (runG v limits A t).1.win = true ∧ CovG v limits A t) ⟨hw, cov_transfer v limits A t hw h⟩]; omega
    · rw [h]; simp
  · rw [ind_of_not hw]; exact Nat.zero_le _

theorem rom_win_sum (R N : Nat) (B : Nat) :
    tsum R N (fun t => ind ((runG v limits A t).1.win = true)) * B ≤
      tsum R N (fun t => ind (CanonCollIn (finO' v limits A t) (params v)
        (expTk (finO' v limits A t) v (sres t (coinEx (params v).n)))
        (expPrf (finO' v limits A t) v (sres t (coinEx (params v).n))) (expSeed v (sres t (coinEx (params v).n)))
        (verifyLog (finO' v limits A t) v (finKey v limits A t).1 (runG v limits A t).1.msg
          (runG v limits A t).1.sig))) * B +
      tsum R N (fun t => ind ((runG v limits A t).1.win = true ∧ CovG v limits A t)) * B +
      tsum R N (fun t => if anyDis (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) t
        then 1 else 0) * B := by
  rw [← Nat.add_mul, ← Nat.add_mul, ← tsum_add, ← tsum_add]
  exact Nat.mul_le_mul_right _ (tsum_mono R N (rom_win_split v limits A))

theorem anyDis_sum (R N : Nat) :
    tsum R N (fun t => if anyDis (gameS v limits A (coinEx (params v).n)) (coinSt (params v).n) t then 1 else 0) ≤
      tsum R N (fun t => if anyDis (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) t
        then 1 else 0) := by
  apply tsum_mono
  intro t
  cases h : anyDis (gameS v limits A (coinEx (params v).n)) (coinSt (params v).n) t
  · simp
  · rw [anyDis_ext v limits A _ t h]; simp
end

/-- SPHINCS+-128f, H1: the won tapes, against `2^-128`: the canonical collisions on
    H1''s table, `JA` ITSR candidates, and twice the disagreement tapes of H1'.
    Conditional on the three budget hypotheses of the ITSR theorem. -/
theorem rom_win_128f (limits : Limits) (A : Bytes → RAdv) (c N q JA : Nat) (hc : 0 < c) (hq : q ≤ 2^64)
    (hN : ∀ t : List Nat, t.length = N → (runG .spx128f limits A t).2.length ≤ N)
    (hC : ∀ t : List Nat, t.length = N → ((runG .spx128f limits A t).2.filter isC).length ≤ q)
    (hJ : ∀ t : List Nat, t.length = N → ((runG .spx128f limits A t).2.filter isA).length ≤ JA) :
    tsum (c * 256^(params .spx128f).m) N (fun t => ind ((runG .spx128f limits A t).1.win = true)) * 2^128 ≤
      tsum (c * 256^(params .spx128f).m) N (fun t => ind (CanonCollIn (finO' .spx128f limits A t) (params .spx128f)
        (expTk (finO' .spx128f limits A t) .spx128f (sres t (coinEx (params .spx128f).n)))
        (expPrf (finO' .spx128f limits A t) .spx128f (sres t (coinEx (params .spx128f).n)))
        (expSeed .spx128f (sres t (coinEx (params .spx128f).n)))
        (verifyLog (finO' .spx128f limits A t) .spx128f (finKey .spx128f limits A t).1
          (runG .spx128f limits A t).1.msg (runG .spx128f limits A t).1.sig))) * 2^128 +
      JA * (c * 256^(params .spx128f).m)^N +
      2 * (tsum (c * 256^(params .spx128f).m) N (fun t => if anyDis (gameS' .spx128f limits A
        (coinEx (params .spx128f).n)) (coinSt (params .spx128f).n) t then 1 else 0) * 2^128) := by
  have h1 := rom_win_sum .spx128f limits A (c * 256^(params .spx128f).m) N (2^128)
  have h2 := itsr_game_hid_128f limits A c N q JA hc hq hN hC hJ
  have h3 := Nat.mul_le_mul_right (2^128) (anyDis_sum .spx128f limits A (c * 256^(params .spx128f).m) N)
  omega

/-- SPHINCS+-256f, H1: as `rom_win_128f`, against `2^-255`. -/
theorem rom_win_256f (limits : Limits) (A : Bytes → RAdv) (c N q JA : Nat) (hc : 0 < c) (hq : q ≤ 2^64)
    (hN : ∀ t : List Nat, t.length = N → (runG .spx256f limits A t).2.length ≤ N)
    (hC : ∀ t : List Nat, t.length = N → ((runG .spx256f limits A t).2.filter isC).length ≤ q)
    (hJ : ∀ t : List Nat, t.length = N → ((runG .spx256f limits A t).2.filter isA).length ≤ JA) :
    tsum (c * 256^(params .spx256f).m) N (fun t => ind ((runG .spx256f limits A t).1.win = true)) * 2^255 ≤
      tsum (c * 256^(params .spx256f).m) N (fun t => ind (CanonCollIn (finO' .spx256f limits A t) (params .spx256f)
        (expTk (finO' .spx256f limits A t) .spx256f (sres t (coinEx (params .spx256f).n)))
        (expPrf (finO' .spx256f limits A t) .spx256f (sres t (coinEx (params .spx256f).n)))
        (expSeed .spx256f (sres t (coinEx (params .spx256f).n)))
        (verifyLog (finO' .spx256f limits A t) .spx256f (finKey .spx256f limits A t).1
          (runG .spx256f limits A t).1.msg (runG .spx256f limits A t).1.sig))) * 2^255 +
      JA * (c * 256^(params .spx256f).m)^N +
      2 * (tsum (c * 256^(params .spx256f).m) N (fun t => if anyDis (gameS' .spx256f limits A
        (coinEx (params .spx256f).n)) (coinSt (params .spx256f).n) t then 1 else 0) * 2^255) := by
  have h1 := rom_win_sum .spx256f limits A (c * 256^(params .spx256f).m) N (2^255)
  have h2 := itsr_game_hid_256f limits A c N q JA hc hq hN hC hJ
  have h3 := Nat.mul_le_mul_right (2^255) (anyDis_sum .spx256f limits A (c * 256^(params .spx256f).m) N)
  omega


/-! The disagreement count of H1', from the hidden-value bound. -/

theorem rom_ext_hidden (v : Variant) (limits : Limits) (A : Bytes → RAdv) (R N S B : Nat)
    (hR : 256^(params v).n ∣ R)
    (hS : ∀ t s stp, (strace t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n))[s]? = some stp →
      s < S ∧ stp.1.ents.length ≤ S)
    (hB : ∀ t, pairCount (params v).n (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) S t ≤ B) :
    tsum R N (fun t => if anyDis (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) t then 1 else 0) *
        256^(params v).n ≤
      R^N * B + tsum R N (fun t => if wildColl (params v).n (gameS' v limits A (coinEx (params v).n))
        (coinSt (params v).n) N t then 1 else 0) * 256^(params v).n :=
  hidden_bound (params v).n (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) R N S B hR hS hB

/-- SPHINCS+-128f, H1, with the hidden-value bound for H1': the won tapes against
    `2^-128` are the canonical collisions on H1''s table, `JA` ITSR candidates,
    twice the hidden-value budget `B`, and twice the wild-guess/collision tapes of
    H1'. Conditional on the ITSR budget hypotheses and on `hidden_bound`'s step and
    pair-count hypotheses for H1'. -/
theorem rom_win_hidden_128f (limits : Limits) (A : Bytes → RAdv) (c N q JA S B : Nat) (hc : 0 < c)
    (hq : q ≤ 2^64)
    (hN : ∀ t : List Nat, t.length = N → (runG .spx128f limits A t).2.length ≤ N)
    (hC : ∀ t : List Nat, t.length = N → ((runG .spx128f limits A t).2.filter isC).length ≤ q)
    (hJ : ∀ t : List Nat, t.length = N → ((runG .spx128f limits A t).2.filter isA).length ≤ JA)
    (hS : ∀ t s stp, (strace t (gameS' .spx128f limits A (coinEx (params .spx128f).n))
      (coinSt (params .spx128f).n))[s]? = some stp → s < S ∧ stp.1.ents.length ≤ S)
    (hB : ∀ t, pairCount (params .spx128f).n (gameS' .spx128f limits A (coinEx (params .spx128f).n))
      (coinSt (params .spx128f).n) S t ≤ B) :
    tsum (c * 256^(params .spx128f).m) N (fun t => ind ((runG .spx128f limits A t).1.win = true)) * 2^128 ≤
      tsum (c * 256^(params .spx128f).m) N (fun t => ind (CanonCollIn (finO' .spx128f limits A t) (params .spx128f)
        (expTk (finO' .spx128f limits A t) .spx128f (sres t (coinEx (params .spx128f).n)))
        (expPrf (finO' .spx128f limits A t) .spx128f (sres t (coinEx (params .spx128f).n)))
        (expSeed .spx128f (sres t (coinEx (params .spx128f).n)))
        (verifyLog (finO' .spx128f limits A t) .spx128f (finKey .spx128f limits A t).1
          (runG .spx128f limits A t).1.msg (runG .spx128f limits A t).1.sig))) * 2^128 +
      JA * (c * 256^(params .spx128f).m)^N + 2 * ((c * 256^(params .spx128f).m)^N * B) +
      2 * (tsum (c * 256^(params .spx128f).m) N (fun t => if wildColl (params .spx128f).n
        (gameS' .spx128f limits A (coinEx (params .spx128f).n)) (coinSt (params .spx128f).n) N t then 1 else 0)
          * 2^128) := by
  have h1 := rom_win_128f limits A c N q JA hc hq hN hC hJ
  have hR : 256^(params .spx128f).n ∣ c * 256^(params .spx128f).m :=
    Nat.dvd_mul_left_of_dvd (Nat.pow_dvd_pow 256 (by decide)) c
  have h2 := rom_ext_hidden .spx128f limits A _ N S B hR hS hB
  have e : (256 : Nat)^(params .spx128f).n = 2^128 := by decide
  rw [e] at h2
  omega

/-- SPHINCS+-256f, H1: as `rom_win_hidden_128f`, against `2^-256` (twice the
    `2^-255` ITSR term). -/
theorem rom_win_hidden_256f (limits : Limits) (A : Bytes → RAdv) (c N q JA S B : Nat) (hc : 0 < c)
    (hq : q ≤ 2^64)
    (hN : ∀ t : List Nat, t.length = N → (runG .spx256f limits A t).2.length ≤ N)
    (hC : ∀ t : List Nat, t.length = N → ((runG .spx256f limits A t).2.filter isC).length ≤ q)
    (hJ : ∀ t : List Nat, t.length = N → ((runG .spx256f limits A t).2.filter isA).length ≤ JA)
    (hS : ∀ t s stp, (strace t (gameS' .spx256f limits A (coinEx (params .spx256f).n))
      (coinSt (params .spx256f).n))[s]? = some stp → s < S ∧ stp.1.ents.length ≤ S)
    (hB : ∀ t, pairCount (params .spx256f).n (gameS' .spx256f limits A (coinEx (params .spx256f).n))
      (coinSt (params .spx256f).n) S t ≤ B) :
    tsum (c * 256^(params .spx256f).m) N (fun t => ind ((runG .spx256f limits A t).1.win = true)) * 2^256 ≤
      tsum (c * 256^(params .spx256f).m) N (fun t => ind (CanonCollIn (finO' .spx256f limits A t) (params .spx256f)
        (expTk (finO' .spx256f limits A t) .spx256f (sres t (coinEx (params .spx256f).n)))
        (expPrf (finO' .spx256f limits A t) .spx256f (sres t (coinEx (params .spx256f).n)))
        (expSeed .spx256f (sres t (coinEx (params .spx256f).n)))
        (verifyLog (finO' .spx256f limits A t) .spx256f (finKey .spx256f limits A t).1
          (runG .spx256f limits A t).1.msg (runG .spx256f limits A t).1.sig))) * 2^256 +
      2 * (JA * (c * 256^(params .spx256f).m)^N) + 2 * ((c * 256^(params .spx256f).m)^N * B) +
      2 * (tsum (c * 256^(params .spx256f).m) N (fun t => if wildColl (params .spx256f).n
        (gameS' .spx256f limits A (coinEx (params .spx256f).n)) (coinSt (params .spx256f).n) N t then 1 else 0)
          * 2^256) := by
  have h1 := rom_win_256f limits A c N q JA hc hq hN hC hJ
  have hR : 256^(params .spx256f).n ∣ c * 256^(params .spx256f).m :=
    Nat.dvd_mul_left_of_dvd (Nat.pow_dvd_pow 256 (by decide)) c
  have h2 := rom_ext_hidden .spx256f limits A _ N S B hR hS hB
  have e : (256 : Nat)^(params .spx256f).n = 2^256 := by decide
  rw [e] at h2
  omega
end DSM.Rom
