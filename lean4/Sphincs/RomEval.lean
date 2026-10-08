-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomGame
import Sphincs.QueryCost
import Sphincs.ForgeryExtractExp

/- The lazy random oracle's final table as an oracle function, and the
   forgery extraction transported to the ROM game. `oracleOf t D` answers a
   request from the first draw of it in `D` (tape entry, truncated), and
   undrawn requests with zero bytes. `QL t T X`: run from any draws whose
   continuation stays a prefix of `D`, the query tree `T` returns what the
   logging run `X (oracleOf t D)` returns, and every request `X` logs was
   drawn. With the model's own logging lemmas (`verify_sim`, `xmssNode_good`)
   this gives: on every tape on which the H1 game is won, the forgery
   verifies against the honest key under the run's own oracle table, so
   `forgery_extract_exp` applies to that table (`rom_extract`). -/
namespace DSM.Rom
open DSM.Sphincs DSM.Sphincs.Security

/-- The final oracle table of a run. -/
def oracleOf (t : List Nat) (D : List Draw) : Oracle Id := fun r =>
  match findDraw D r with
  | some i => be r.outLen (t.getD i 0)
  | none => List.replicate r.outLen 0

theorem oracleOf_len (t : List Nat) (D : List Draw) (r : Request) : (oracleOf t D r).length = r.outLen := by
  unfold oracleOf; split <;> simp [be_width]

/-- `d` is a prefix of `D`. -/
def Pre (d D : List Draw) : Prop := ∃ e, D = d ++ e

theorem Pre.trans {a b c : List Draw} (h₁ : Pre a b) (h₂ : Pre b c) : Pre a c := by
  obtain ⟨e₁, rfl⟩ := h₁; obtain ⟨e₂, rfl⟩ := h₂; exact ⟨e₁ ++ e₂, by simp⟩

theorem pre_run {α : Type} (t : List Nat) (T : QT α) (d : List Draw) : Pre d (run t T d).2 := by
  obtain ⟨e, he⟩ := run_extends t T d; exact ⟨e, he⟩

theorem findDraw_append_some : ∀ (d e : List Draw) (r : Request) (i : Nat),
    findDraw d r = some i → findDraw (d ++ e) r = some i
  | [], _, _, _, h => by simp [findDraw] at h
  | x :: d, e, r, i, h => by
    simp only [List.cons_append, findDraw] at h ⊢
    split
    · split at h
      · exact h
      · contradiction
    · split at h
      · contradiction
      · cases hd : findDraw d r with
        | none => rw [hd] at h; cases h
        | some j => rw [hd] at h; rw [findDraw_append_some d e r j hd]; exact h

theorem findDraw_append_none : ∀ (d e : List Draw) (g : Bool) (r : Request),
    findDraw d r = none → findDraw (d ++ (g, r) :: e) r = some d.length
  | [], e, g, r, _ => by
    simp only [List.nil_append, findDraw, List.length_nil]
    rw [if_pos ((req_beq_iff r r).mpr rfl)]
  | x :: d, e, g, r, h => by
    simp only [findDraw] at h
    split at h
    · cases h
    · simp only [List.cons_append, findDraw, List.length_cons]
      next hx =>
      rw [if_neg hx]
      cases hd : findDraw d r with
      | some j => rw [hd] at h; cases h
      | none => rw [findDraw_append_none d e g r hd]; rfl

theorem findDraw_mem : ∀ (d : List Draw) (r : Request) (i : Nat), findDraw d r = some i → ∃ e ∈ d, e.2 = r
  | [], _, _, h => by simp [findDraw] at h
  | x :: d, r, i, h => by
    simp only [findDraw] at h
    split at h
    · next hx => exact ⟨x, by simp, (req_beq_iff _ _).mp hx⟩
    · cases hd : findDraw d r with
      | none => rw [hd] at h; cases h
      | some j =>
        obtain ⟨e, he, hr⟩ := findDraw_mem d r j hd
        exact ⟨e, by simp [he], hr⟩

/-- Query tree `T` computes what the logging run `X` computes under the
    final table, and only logs drawn requests. -/
def QL {α : Type} (t : List Nat) (T : QT α) (X : Oracle Id → LogM α) : Prop :=
  ∀ d D, Pre (run t T d).2 D → ∀ s, ∃ L,
    (X (oracleOf t D)).run s = ((run t T d).1, s ++ L) ∧ ∀ r ∈ L, ∃ e ∈ (run t T d).2, e.2 = r

/-- Tagged query-tree oracle. -/
def tagO (g : Bool) : Oracle QT := fun r => .ask g r .done

namespace QL
variable {t : List Nat}

theorem pure' {α : Type} (a : α) : QL t (QT.done a) (fun _ => (pure a : LogM α)) :=
  fun _ _ _ s => ⟨[], by simp [run]; rfl, by simp⟩

theorem bind {α β : Type} {T : QT α} {g : α → QT β} {X : Oracle Id → LogM α}
    {Y : α → Oracle Id → LogM β} (hT : QL t T X) (hg : ∀ a, QL t (g a) (Y a)) :
    QL t (T >>= g) (fun O => X O >>= fun a => Y a O) := by
  intro d D hD s
  change Pre (run t (T.bind g) d).2 D at hD
  show ∃ L, _ = ((run t (T.bind g) d).1, s ++ L) ∧ ∀ r ∈ L, ∃ e ∈ (run t (T.bind g) d).2, e.2 = r
  rw [run_bind] at hD ⊢
  have hD1 : Pre (run t T d).2 D := Pre.trans (pre_run t _ _) hD
  obtain ⟨L₁, e₁, m₁⟩ := hT d D hD1 s
  obtain ⟨L₂, e₂, m₂⟩ := hg (run t T d).1 (run t T d).2 D hD (s ++ L₁)
  refine ⟨L₁ ++ L₂, ?_, ?_⟩
  · rw [logM_run_bind, e₁]; simpa [List.append_assoc] using e₂
  · intro r hr
    rcases List.mem_append.mp hr with h | h
    · obtain ⟨e, he, rfl⟩ := m₁ r h
      obtain ⟨x, hx⟩ := pre_run t (g (run t T d).1) (run t T d).2
      exact ⟨e, by rw [hx]; exact List.mem_append_left _ he, rfl⟩
    · exact m₂ r h

theorem oracle (g : Bool) (r : Request) : QL t (tagO g r) (fun O => logOracle O r) := by
  intro d D hD s
  refine ⟨[r], ?_, ?_⟩
  · rw [logOracle_run]
    simp only [tagO, run] at hD ⊢
    cases hf : findDraw d r with
    | some i =>
      simp only [hf] at hD ⊢
      obtain ⟨e, rfl⟩ := hD
      simp [oracleOf, findDraw_append_some d e r i hf]
    | none =>
      simp only [hf] at hD ⊢
      obtain ⟨e, rfl⟩ := hD
      have := findDraw_append_none d e g r hf
      simp [oracleOf, List.append_assoc, this]
  · intro x hx
    simp only [List.mem_singleton] at hx
    subst hx
    simp only [tagO, run]
    cases hf : findDraw d x with
    | some i => simpa [hf, run] using findDraw_mem d x i hf
    | none => exact ⟨(g, x), by simp, rfl⟩

theorem ite {α : Type} {c : Prop} [Decidable c] {T₁ T₂ : QT α} {X₁ X₂ : Oracle Id → LogM α}
    (h₁ : c → QL t T₁ X₁) (h₂ : ¬c → QL t T₂ X₂) :
    QL t (if c then T₁ else T₂) (fun O => if c then X₁ O else X₂ O) := by
  by_cases h : c
  · simp only [h, if_true]; exact h₁ h
  · simp only [h, if_false]; exact h₂ h

theorem forIn {ι σ : Type} (l : List ι) (G : ι → σ → QT (ForInStep σ))
    (F : ι → σ → Oracle Id → LogM (ForInStep σ)) (h : ∀ i ∈ l, ∀ s, QL t (G i s) (F i s)) :
    ∀ init, QL t (forIn l init G) (fun O => forIn l init (fun i s => F i s O)) := by
  induction l with
  | nil => intro init; exact pure' init
  | cons a l ih =>
    intro init
    simp only [List.forIn_cons]
    refine bind (h a (by simp) init) (fun r => ?_)
    cases r with
    | done b => exact pure' b
    | yield b => exact ih (fun i hi s => h i (by simp [hi]) s) b
end QL

/-! The model functions run as query trees compute what they compute under
    the final table. -/

section
variable {t : List Nat} (g : Bool) (p : Params) (tk : Bytes)

theorem ql_thash (a : Adrs) (x : Bytes) :
    QL t (thash (tagO g) p tk a x) (fun O => thash (logOracle O) p tk a x) := QL.oracle g _

theorem ql_chain (a : Adrs) : ∀ (steps : Nat) (x : Bytes) (start : Nat),
    QL t (chain (tagO g) p tk a x start steps) (fun O => chain (logOracle O) p tk a x start steps)
  | 0, x, _ => QL.pure' x
  | steps+1, x, start => by
    simp only [chain]
    exact QL.bind (ql_thash g p tk _ _) (fun y => ql_chain a steps y (start+1))

theorem ql_authWalk (a : Adrs) (auth : Bytes) : ∀ (remaining li gi level : Nat) (node : Bytes),
    QL t (authWalk (tagO g) p tk a li gi node auth level remaining)
      (fun O => authWalk (logOracle O) p tk a li gi node auth level remaining)
  | 0, _, _, _, node => QL.pure' node
  | remaining+1, li, gi, level, node => by
    simp only [authWalk]
    exact QL.bind (ql_thash g p tk _ _) (fun y => ql_authWalk a auth remaining _ _ _ y)

theorem ql_wotsPkFromSig (a : Adrs) (sig msg : Bytes) :
    QL t (wotsPkFromSig (tagO g) p tk a sig msg) (fun O => wotsPkFromSig (logOracle O) p tk a sig msg) := by
  simp only [wotsPkFromSig, wotsCompress]
  refine QL.bind (QL.forIn _ _ _ ?_ []) (fun tops => ql_thash g p tk _ _)
  intro x _ s
  obtain ⟨digit, i⟩ := x
  exact QL.bind (ql_chain g p tk _ _ _ _) (fun top => QL.pure' _)

theorem ql_xmssPkFromSig (a : Adrs) (idx : Nat) (sig msg : Bytes) :
    QL t (xmssPkFromSig (tagO g) p tk a idx sig msg) (fun O => xmssPkFromSig (logOracle O) p tk a idx sig msg) := by
  simp only [xmssPkFromSig, authRoot]
  exact QL.bind (ql_wotsPkFromSig g p tk _ _ _) (fun node => ql_authWalk g p tk _ _ _ _ _ _ _)

theorem ql_htRootTail : ∀ (remaining layer tree : Nat) (node sig : Bytes),
    QL t (htRootTail (tagO g) p tk layer tree node sig remaining)
      (fun O => htRootTail (logOracle O) p tk layer tree node sig remaining)
  | 0, _, _, node, _ => QL.pure' node
  | remaining+1, layer, tree, node, sig => by
    simp only [htRootTail]
    exact QL.bind (ql_xmssPkFromSig g p tk _ _ _ _) (fun root => ql_htRootTail remaining _ _ root _)

theorem ql_htRoot (sig msg : Bytes) (tree leaf : Nat) :
    QL t (htRoot (tagO g) p tk sig msg tree leaf) (fun O => htRoot (logOracle O) p tk sig msg tree leaf) := by
  simp only [htRoot]
  exact QL.bind (ql_xmssPkFromSig g p tk _ _ _ _) (fun node => ql_htRootTail g p tk _ _ _ node _)

theorem ql_forsPkFromSig (a : Adrs) (sig md : Bytes) :
    QL t (forsPkFromSig (tagO g) p tk a sig md) (fun O => forsPkFromSig (logOracle O) p tk a sig md) := by
  simp only [forsPkFromSig, authRoot]
  refine QL.bind (QL.forIn _ _ _ ?_ []) (fun roots => ql_thash g p tk _ _)
  intro x _ s
  obtain ⟨idx, i⟩ := x
  exact QL.bind (ql_thash g p tk _ _) (fun leaf => QL.bind (ql_authWalk g p tk _ _ _ _ _ _ leaf)
    (fun root => QL.pure' _))

variable (prfKey seed : Bytes)

theorem ql_wotsPkgen (a : Adrs) :
    QL t (wotsPkgen (tagO g) p tk prfKey seed a) (fun O => wotsPkgen (logOracle O) p tk prfKey seed a) := by
  simp only [wotsPkgen, wotsCompress]
  refine QL.bind (QL.forIn _ _ _ ?_ []) (fun tops => ql_thash g p tk _ _)
  intro i _ s
  exact QL.bind (QL.oracle g _) (fun sk => QL.bind (ql_chain g p tk _ _ _ _) (fun top => QL.pure' _))

theorem ql_xmssNode (a : Adrs) : ∀ (height idx : Nat),
    QL t (xmssNode (tagO g) p tk prfKey seed a idx height)
      (fun O => xmssNode (logOracle O) p tk prfKey seed a idx height)
  | 0, idx => by simp only [xmssNode]; exact ql_wotsPkgen g p tk prfKey seed _
  | height+1, idx => by
    simp only [xmssNode]
    exact QL.bind (ql_xmssNode a height (2*idx)) (fun l => QL.bind (ql_xmssNode a height (2*idx+1))
      (fun r => ql_thash g p tk _ _))
end

theorem ql_kgTail {t : List Nat} (g : Bool) (v : Variant) (ex : Bytes) :
    QL t (kgTail (tagO g) v ex) (fun O => kgTail (logOracle O) v ex) := by
  simp only [kgTail]
  exact QL.bind (QL.oracle g _) (fun tk => QL.bind (QL.oracle g _)
    (fun pk => QL.bind (ql_xmssNode g _ tk pk _ _ _ _) (fun root => QL.pure' _)))

theorem ql_verify {t : List Nat} (g : Bool) (v : Variant) (pk msg sig : Bytes) :
    QL t (verify (tagO g) v pk msg sig) (fun O => verify (logOracle O) v pk msg sig) := by
  simp only [verify]
  refine QL.ite (fun _ => QL.pure' _) (fun _ => ?_)
  refine QL.bind (QL.pure' _) (fun _ => ?_)
  refine QL.ite (fun _ => QL.pure' _) (fun _ => ?_)
  refine QL.bind (QL.pure' _) (fun _ => ?_)
  exact QL.bind (QL.oracle g _) (fun tk => QL.bind (QL.oracle g _) (fun dg =>
    QL.bind (ql_forsPkFromSig g _ tk _ _ _) (fun fpk => QL.bind (ql_htRoot g _ tk _ _ _ _)
      (fun ac => QL.pure' _))))

theorem kgTail_good (O : Oracle Id) (v : Variant) (ex : Bytes) :
    Good AnyReq (kgTail (logOracle O) v ex) (keypairFromExpansion O v ex) := by
  obtain ⟨hlen, hH, hd, _, _, _⟩ := variant_bounds v
  refine Good.congr_val (v := kgTail O v ex) ?_ rfl
  simp only [kgTail]
  refine Good.bind_id (Good.oracle O trivial) ?_
  refine Good.bind_id (Good.oracle O trivial) ?_
  apply Good.bind_id (Good.mono (fun _ _ => trivial)
    (xmssNode_good _ (params v).hp hH (by dsimp only; omega) (by show 0 < 256^8; decide) hlen _ 0
      (Nat.le_refl _) (by simp)))
  exact Good.pure' _

/-- The QT run's value and log under the final table, read through `Good`. -/
theorem ql_value {α : Type} {t : List Nat} {T : QT α} {X : Oracle Id → LogM α} (hT : QL t T X)
    (d D : List Draw) (hD : Pre (run t T d).2 D) {w : α} (hw : Good AnyReq (X (oracleOf t D)) w) :
    (run t T d).1 = w ∧ ∀ r ∈ ((X (oracleOf t D)).run []).2, ∃ e ∈ D, e.2 = r := by
  obtain ⟨L, e₁, m₁⟩ := hT d D hD []
  obtain ⟨L', e₂, _⟩ := hw []
  rw [e₁] at e₂
  refine ⟨(Prod.mk.inj e₂).1, ?_⟩
  rw [e₁]
  intro r hr
  obtain ⟨e, he, rfl⟩ := m₁ r (by simpa using hr)
  obtain ⟨x, hx⟩ := hD
  exact ⟨e, by rw [hx]; exact List.mem_append_left _ he, rfl⟩

/-- On a won play, the forgery verifies against `pk` under any table
    extending the run, and the verifier's requests were all drawn. -/
theorem play_extract (t : List Nat) (v : Variant) (limits : Limits) (pk sk : Bytes) :
    ∀ (A : RAdv) (signed : List Bytes) (d : List Draw),
    (run t (playQT v limits pk sk A signed) d).1.win = true →
    ∀ D, Pre (run t (playQT v limits pk sk A signed) d).2 D →
      verify (oracleOf t D) v pk (run t (playQT v limits pk sk A signed) d).1.msg
        (run t (playQT v limits pk sk A signed) d).1.sig = some true ∧
      legal limits (run t (playQT v limits pk sk A signed) d).1.msg = true ∧
      (run t (playQT v limits pk sk A signed) d).1.signed.contains
        (run t (playQT v limits pk sk A signed) d).1.msg = false ∧
      ∀ r ∈ verifyLog (oracleOf t D) v pk (run t (playQT v limits pk sk A signed) d).1.msg
        (run t (playQT v limits pk sk A signed) d).1.sig, ∃ e ∈ D, e.2 = r
  | .hq r k, signed, d => by
    simp only [playQT, run]
    cases findDraw d r with
    | some i => exact play_extract t v limits pk sk (k _) signed d
    | none => exact play_extract t v limits pk sk (k _) signed _
  | .sq m k, signed, d => by
    simp only [playQT]
    split
    · rw [run_bind]; exact play_extract t v limits pk sk (k _) _ _
    · exact play_extract t v limits pk sk (k none) signed d
  | .out m s, signed, d => by
    simp only [playQT]
    rw [run_bind]
    simp only [run]
    intro hw D hD
    have q : QL t (verify advQ v pk m s) (fun O => verify (logOracle O) v pk m s) := ql_verify true v pk m s
    obtain ⟨hval, hlog⟩ := ql_value q d D hD (verify_sim (oracleOf t D) v pk m s)
    rw [hval] at hw
    simp only [Bool.and_eq_true, Bool.not_eq_true'] at hw
    obtain ⟨⟨hl, hc⟩, hv⟩ := hw
    refine ⟨?_, hl, hc, hlog⟩
    revert hv
    cases verify (oracleOf t D) v pk m s with
    | none => intro h; simp at h
    | some b => intro h; simp at h; rw [h]

theorem coinEx_len (t : List Nat) (v : Variant) :
    (sres t (coinEx (params v).n)).length = 3*(params v).n := by
  rw [sres_length t _ _ (coinEx_WN _)]; simp [coinEx]

/-- Extraction transported to the ROM game (H1). On every tape on which the
    model's game is won, the forgery exhibits one of the four extraction
    events against the run's own final oracle table, and every request of
    the verifier's log was drawn in the run. -/
theorem rom_extract (t : List Nat) (v : Variant) (limits : Limits) (A : Bytes → RAdv)
    (hw : (run t (gameQT v limits A (sres t (coinEx (params v).n)))
      (resD t (coinSt (params v).n))).1.win = true) :
    let R := run t (gameQT v limits A (sres t (coinEx (params v).n))) (resD t (coinSt (params v).n))
    let O := oracleOf t R.2
    let e := sres t (coinEx (params v).n)
    (CanonCollIn O (params v) (expTk O v e) (expPrf O v e) (expSeed v e)
        (verifyLog O v (keypairFromExpansion O v e).1 R.1.msg R.1.sig) ∨
      WotsEvent O (params v) (expTk O v e) (expPrf O v e) (expSeed v e)
        (R.1.sig.drop ((params v).n + (params v).forsBytes)) ∨
      (∃ i, i < (params v).k ∧
        ¬ RevealedBy O v (keypairFromExpansion O v e).2 R.1.signed
          (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 R.1.msg R.1.sig)).tree
          (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 R.1.msg R.1.sig)).leaf i
          (forsDigit (params v)
            (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 R.1.msg R.1.sig)).md i) ∧
        slice R.1.sig ((params v).n + i*(((params v).a+1)*(params v).n)) (params v).n =
          forsSecret O (params v) (expPrf O v e) (expSeed v e)
            (forsAdrs (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 R.1.msg R.1.sig)).tree
              (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 R.1.msg R.1.sig)).leaf)
            (i*2^(params v).a + forsDigit (params v)
              (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 R.1.msg R.1.sig)).md i)) ∨
      CoveredBy O v (keypairFromExpansion O v e).2 R.1.signed
        (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 R.1.msg R.1.sig))) ∧
    (∀ r ∈ verifyLog O v (keypairFromExpansion O v e).1 R.1.msg R.1.sig, ∃ x ∈ R.2, x.2 = r) := by
  intro R O e
  have hR : R = run t (playQT v limits
      (run t (kgTail challengerOracle v e) (resD t (coinSt (params v).n))).1.1
      (run t (kgTail challengerOracle v e) (resD t (coinSt (params v).n))).1.2
      (A (run t (kgTail challengerOracle v e) (resD t (coinSt (params v).n))).1.1) [])
      (run t (kgTail challengerOracle v e) (resD t (coinSt (params v).n))).2 := by
    show run t (QT.bind _ _) _ = _
    rw [run_bind]
  have hpre : Pre (run t (kgTail challengerOracle v e) (resD t (coinSt (params v).n))).2 R.2 := by
    rw [hR]; exact pre_run t _ _
  have hk : QL t (kgTail challengerOracle v e) (fun O => kgTail (logOracle O) v e) := ql_kgTail false v e
  have hks := (ql_value hk _ R.2 hpre (kgTail_good O v e)).1
  have hw' : R.1.win = true := hw
  rw [hR] at hw'
  have hp := play_extract t v limits _ _ _ [] _ hw' R.2 (by rw [← hR]; exact ⟨[], by simp⟩)
  rw [← hR, hks] at hp
  obtain ⟨hv, -, -, hlog⟩ := hp
  exact ⟨forgery_extract_exp O v e (coinEx_len t v) (fun x => oracleOf_len t _ _)
      (fun x _ => oracleOf_len t _ _) R.1.signed R.1.msg R.1.sig hv, hlog⟩

#print axioms rom_extract
#print axioms ql_verify
#print axioms ql_kgTail
end DSM.Rom
