-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.CompWots

/- Modular proof, milestone 3, obligation 8 (part 2): the SM-DT-UD-C step of
   WOTS-TW (EasyCrypt `R_SMDTUDC_Game23WOTSTWES`).

   The reduction picks a hybrid index `i < w − 2` with its coins. For every
   signing query and chain with digit `d = e + 1 > i + 1` it submits the
   target tweak at hash position `i`, takes the challenge as the chain value
   at depth `i + 1`, and finishes the chain with the collection oracle; for
   the other chains it draws the value at depth `e` itself. With the real UD
   challenge it plays hybrid `i`, with the ideal one hybrid `i + 1`.

   This file: the reduction (`udRed`, coins `udCoins`); its UD-C game as a
   labelled process (`udRed_run_proc`) whose merged run is hybrid `i` or
   `i + 1` on every tape (`udProc_hyb`); the exact telescoped identity
   (`ud_step`) and the bound Pr[G] ≤ Pr[Hyb_{w−2}] + (w − 2)·Adv^UD-C
   (`ud_step_frac`); and the reduction's query budget (`udRed_queries`).
   No assumption, axiom or `sorry`. -/
namespace DSM.Sphincs.Comp
open DSM.Sphincs DSM.Sphincs.Security

/-- A reduction program's queries: UD-C (target or collection) or an own draw. -/
abbrev UdProgQ (Tw Xc : Type) := (Tw ⊕ (Tw × Xc)) ⊕ Unit

section Interp
variable {PP Tw Xc X α : Type}

/-- The UD-C challenger, run as a labelled process: a target query draws from
    the challenger's tape (`true`) and answers `f(x)` (real, `b = false`) or
    `x` (ideal, `b = true`); a collection query answers `fc`; an own draw reads
    the reduction's tape (`false`). The challenger's log is kept. -/
def udInterp (b : Bool) (f : PP → Tw → X → X) (fc : PP → Tw → Xc → X) (pp : PP) :
    OT (UdProgQ Tw Xc) X α → Log Tw Tw → OT Bool X (α × Log Tw Tw)
  | .done a, L => .done (a, L)
  | .ask (.inl (.inl tw)) k, L => .ask true (fun x =>
      udInterp b f fc pp (k (if b then x else f pp tw x)) ⟨L.tgt ++ [tw], L.col⟩)
  | .ask (.inl (.inr q)) k, L => udInterp b f fc pp (k (fc pp q.1 q.2)) ⟨L.tgt, L.col ++ [q.1]⟩
  | .ask (.inr ()) k, L => .ask false (fun x => udInterp b f fc pp (k x) L)

/-- The UD-C challenger's answer to target `j`. -/
def udAns (b : Bool) (f : PP → Tw → X → X) (x0 : X) (pp : PP) (T : List X) (j : Nat) (tw : Tw) : X :=
  if b then T.getD j x0 else f pp tw (T.getD j x0)

theorem drop_headD (T : List X) (n : Nat) (x0 : X) : (T.drop n).headD x0 = T.getD n x0 := by
  induction T generalizing n with
  | nil => simp
  | cons y T ih => cases n with
    | zero => simp
    | succ n => simp

/-- The UD-C game's run of a reduction with own tape `R` is the labelled
    process's run on the challenger's remaining tape and `R`. -/
theorem udRun_proc (b : Bool) (f : PP → Tw → X → X) (fc : PP → Tw → Xc → X) (x0 : X) (pp : PP)
    (T : List X) : ∀ (P : OT (UdProgQ Tw Xc) X α) (R : List X) (L : Log Tw Tw),
      (resolveS x0 P R).run (udOracle (udAns b f x0 pp T) fc pp) L =
        let r := (udInterp b f fc pp P L).run (tape2 x0) (T.drop L.tgt.length, R)
        ((r.1.1, r.2.2), r.1.2)
  | .done _, _, _ => rfl
  | .ask (.inl (.inl tw)) k, R, L => by
    simp only [resolveS, OT.run, udOracle, udInterp, tape2, udAns]
    rw [udRun_proc b f fc x0 pp T (k _) R ⟨L.tgt ++ [tw], L.col⟩]
    simp only [List.length_append, List.length_singleton, drop_headD, List.tail_drop]
  | .ask (.inl (.inr q)) k, R, L => by
    simp only [resolveS, OT.run, udOracle, colAnswer, udInterp]
    exact udRun_proc b f fc x0 pp T (k _) R _
  | .ask (.inr ()) k, R, L => by
    simp only [resolveS, OT.run, udInterp, tape2]
    exact udRun_proc b f fc x0 pp T (k _) R.tail L

theorem udInterp_tape (b : Bool) (f : PP → Tw → X → X) (fc : PP → Tw → Xc → X) (x0 : X) (pp : PP)
    (T : List X) : ∀ (P : OT (UdProgQ Tw Xc) X α) (R : List X) (L : Log Tw Tw),
      ((udInterp b f fc pp P L).run (tape2 x0) (T.drop L.tgt.length, R)).2.1 =
        T.drop ((udInterp b f fc pp P L).run (tape2 x0) (T.drop L.tgt.length, R)).1.2.tgt.length
  | .done _, _, _ => rfl
  | .ask (.inl (.inl tw)) k, R, L => by
    simp only [udInterp, OT.run, tape2, List.tail_drop]
    have := udInterp_tape b f fc x0 pp T
      (k (if b = true then (T.drop L.tgt.length).headD x0 else f pp tw ((T.drop L.tgt.length).headD x0)))
      R ⟨L.tgt ++ [tw], L.col⟩
    simp only [List.length_append, List.length_singleton] at this
    exact this
  | .ask (.inl (.inr q)) k, R, L => by
    simp only [udInterp]; exact udInterp_tape b f fc x0 pp T (k _) R _
  | .ask (.inr ()) k, R, L => by
    simp only [udInterp, OT.run, tape2]; exact udInterp_tape b f fc x0 pp T (k _) R.tail L
end Interp


section InterpBind
variable {PP Tw Xc X α β : Type}

theorem udInterp_bind (b : Bool) (f : PP → Tw → X → X) (fc : PP → Tw → Xc → X) (pp : PP)
    (k : α → OT (UdProgQ Tw Xc) X β) :
    ∀ (P : OT (UdProgQ Tw Xc) X α) (L : Log Tw Tw),
      udInterp b f fc pp (P.bind k) L = (udInterp b f fc pp P L).bind (fun r => udInterp b f fc pp (k r.1) r.2)
  | .done _, _ => rfl
  | .ask (.inl (.inl tw)) c, L => by
    simp only [OT.bind, udInterp]; congr; funext x; exact udInterp_bind b f fc pp k (c _) _
  | .ask (.inl (.inr q)) c, L => by
    simp only [OT.bind, udInterp]; exact udInterp_bind b f fc pp k (c _) _
  | .ask (.inr ()) c, L => by
    simp only [OT.bind, udInterp]; congr; funext x; exact udInterp_bind b f fc pp k (c x) L
end InterpBind

namespace WotsSetting
variable {PP Tw I M X Xc : Type} (W : WotsSetting PP Tw I M X Xc)

/-! ## The reduction -/

/-- `k` chain steps through the collection oracle. -/
def colChain (a : I) (c : Nat) : X → Nat → Nat → OT (UdProgQ Tw Xc) X X
  | x, _, 0 => .done x
  | x, s, k+1 => .ask (.inl (.inr (W.twk a c s, W.embed x))) (fun y => colChain a c y (s+1) k)

/-- Chain `c` of instance `a` for digit `d`, with hybrid index `i`. -/
def udElem (i : Nat) (a : I) (c : Nat) : Nat → OT (UdProgQ Tw Xc) X (X × X)
  | 0 => .ask (.inr ()) (fun x => (W.colChain a c x 0 (W.w - 1)).bind (fun pk => .done (pk, x)))
  | e+1 =>
    (if i < e then OT.ask (.inl (.inl (W.twk a c i))) (fun y => W.colChain a c y (i+1) (e - (i+1)))
     else OT.ask (.inr ()) (fun v => .done v)).bind (fun v =>
      (W.colChain a c v e 1).bind (fun sig =>
        (W.colChain a c sig (e+1) (W.w - 1 - (e+1))).bind (fun pk => .done (pk, sig))))

/-- The reduction's answer to the adversary's queries. -/
def udHandler (i : Nat) :
    WotsState Tw I M X → WotsQuery Tw I M Xc → OT (UdProgQ Tw Xc) X (WotsAnswer X × WotsState Tw I M X)
  | s, .inl (a, m) => (signFrom (W.udElem i a) 0 (W.enc m)).bind (fun r =>
      .done (.inl r, ⟨s.qs ++ [(a, m, r.1, r.2)], s.cols⟩))
  | s, .inr (tw, x) => .ask (.inl (.inr (tw, x))) (fun y => .done (.inr y, ⟨s.qs, s.cols ++ [tw]⟩))

/-! ## The reduction's chain computations, interpreted -/

/-- Tweaks of `k` chain steps from depth `s`. -/
def colTweaks (a : I) (c s k : Nat) : List Tw := (List.range k).map (fun j => W.twk a c (s + j))

theorem udInterp_colChain (b : Bool) (pp : PP) (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x)
    (a : I) (c : Nat) : ∀ (k : Nat) (x : X) (s : Nat) (L : Log Tw Tw),
      udInterp b W.f W.fc pp (W.colChain a c x s k) L =
        .done (W.chain pp a c x s k, ⟨L.tgt, L.col ++ W.colTweaks a c s k⟩)
  | 0, _, _, L => by simp [colChain, udInterp, chain, colTweaks]
  | k+1, x, s, L => by
    simp only [colChain, udInterp, hc]
    rw [udInterp_colChain b pp hc a c k _ (s+1)]
    simp only [chain]
    congr 2
    simp only [colTweaks, List.range_succ_eq_map, List.map_cons, List.map_map, Nat.add_zero,
      List.append_assoc, List.singleton_append]
    have hm : List.map (fun j => W.twk a c (s + 1 + j)) (List.range k) =
        List.map ((fun j => W.twk a c (s + j)) ∘ Nat.succ) (List.range k) :=
      List.map_congr_left (fun j _ => by simp only [Function.comp]; congr 1; omega)
    rw [hm]

/-- The hybrid the reduction plays: `i` with the real challenge, `i + 1` with
    the ideal one. -/
def hybIndex (b : Bool) (i : Nat) : Nat := if b then i + 1 else i

/-- The challenger's log entries of one chain. -/
def elemTgts (i : Nat) (a : I) (c d : Nat) : List Tw :=
  match d with
  | 0 => []
  | e+1 => if i < e then [W.twk a c i] else []

def elemCols (i : Nat) (a : I) (c d : Nat) : List Tw :=
  match d with
  | 0 => W.colTweaks a c 0 (W.w - 1)
  | e+1 => (if i < e then W.colTweaks a c (i+1) (e - (i+1)) else []) ++ W.colTweaks a c e 1 ++
      W.colTweaks a c (e+1) (W.w - 1 - (e+1))

theorem elem_eq (b : Bool) (pp : PP) (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x)
    (i : Nat) (a : I) (c d : Nat) (L : Log Tw Tw) :
    unlabel (udInterp b W.f W.fc pp (W.udElem i a c d) L) =
      (W.hybElem (hybIndex b i) pp a c d).bind (fun r =>
        .done (r, ⟨L.tgt ++ W.elemTgts i a c d, L.col ++ W.elemCols i a c d⟩)) := by
  cases d with
  | zero =>
    simp only [udElem, udInterp, unlabel, hybElem, OT.bind, elemTgts, elemCols, List.append_nil]
    congr; funext x
    rw [udInterp_bind, udInterp_colChain W b pp hc]
    rfl
  | succ e =>
    by_cases hi : i < e
    · simp only [udElem, if_pos hi, OT.bind, udInterp, unlabel, hybElem, elemTgts, elemCols]
      congr; funext x
      rw [udInterp_bind, udInterp_colChain W b pp hc]
      simp only [OT.bind]
      rw [udInterp_bind, udInterp_colChain W b pp hc]
      simp only [OT.bind]
      rw [udInterp_bind, udInterp_colChain W b pp hc]
      simp only [OT.bind, udInterp, unlabel, List.append_assoc]
      have hmin : min (hybIndex b i) e = hybIndex b i := by
        cases b <;> simp [hybIndex] <;> omega
      rw [hmin]
      congr 3
      · cases b
        · simp only [hybIndex, if_false, Bool.false_eq_true]
          rw [show e - i = 1 + (e - (i + 1)) by omega, chain_add]; rfl
        · simp only [hybIndex, if_true]; rfl
      · cases b
        · simp only [hybIndex, if_false, Bool.false_eq_true]
          rw [show e - i = 1 + (e - (i + 1)) by omega, chain_add]; rfl
        · simp only [hybIndex, if_true]; rfl
    · simp only [udElem, if_neg hi, OT.bind, udInterp, unlabel, hybElem, elemTgts, elemCols,
        List.append_nil, List.nil_append]
      congr; funext x
      rw [udInterp_bind, udInterp_colChain W b pp hc]
      simp only [OT.bind]
      rw [udInterp_bind, udInterp_colChain W b pp hc]
      simp only [OT.bind, udInterp, unlabel, List.append_assoc]
      have hmin : min (hybIndex b i) e = e := by cases b <;> simp [hybIndex] <;> omega
      rw [hmin, Nat.sub_self]
      rfl

/-- The challenger's log entries of one signature. -/
def sigTgts (i : Nat) (a : I) : Nat → List Nat → List Tw
  | _, [] => []
  | c, d :: ds => W.elemTgts i a c d ++ sigTgts i a (c+1) ds

def sigCols (i : Nat) (a : I) : Nat → List Nat → List Tw
  | _, [] => []
  | c, d :: ds => W.elemCols i a c d ++ sigCols i a (c+1) ds

theorem sign_eq (b : Bool) (pp : PP) (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x)
    (i : Nat) (a : I) : ∀ (ds : List Nat) (c : Nat) (L : Log Tw Tw),
      unlabel (udInterp b W.f W.fc pp (signFrom (W.udElem i a) c ds) L) =
        (signFrom (W.hybElem (hybIndex b i) pp a) c ds).bind (fun r =>
          .done (r, ⟨L.tgt ++ W.sigTgts i a c ds, L.col ++ W.sigCols i a c ds⟩))
  | [], c, L => by simp [signFrom, udInterp, unlabel, sigTgts, sigCols, OT.bind]
  | d :: ds, c, L => by
    simp only [signFrom]
    rw [udInterp_bind, unlabel_bind, elem_eq W b pp hc, OT.bind_assoc, OT.bind_assoc]
    apply OT.bind_congr; intro e
    simp only [OT.bind]
    rw [udInterp_bind, unlabel_bind, sign_eq b pp hc i a ds (c+1), OT.bind_assoc, OT.bind_assoc]
    apply OT.bind_congr; intro r
    simp only [OT.bind, udInterp, unlabel, sigTgts, sigCols, List.append_assoc]

/-- The challenger's log after one query. -/
def logUpd (i : Nat) (q : WotsQuery Tw I M Xc) (L : Log Tw Tw) : Log Tw Tw :=
  match q with
  | .inl (a, m) => ⟨L.tgt ++ W.sigTgts i a 0 (W.enc m), L.col ++ W.sigCols i a 0 (W.enc m)⟩
  | .inr (tw, _) => ⟨L.tgt, L.col ++ [tw]⟩

theorem handler_eq (b : Bool) (pp : PP) (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x)
    (i : Nat) (s : WotsState Tw I M X) (q : WotsQuery Tw I M Xc) (L : Log Tw Tw) :
    unlabel (udInterp b W.f W.fc pp (W.udHandler i s q) L) =
      (W.handler (fun pp a => W.hybElem (hybIndex b i) pp a) pp s q).bind (fun r =>
        .done (r, W.logUpd i q L)) := by
  match q with
  | .inl (a, m) =>
    simp only [udHandler, handler, logUpd]
    rw [udInterp_bind, unlabel_bind, sign_eq W b pp hc, OT.bind_assoc, OT.bind_assoc]
    apply OT.bind_congr; intro r
    rfl
  | .inr (tw, x) =>
    simp only [udHandler, handler, logUpd, udInterp, unlabel, OT.bind]



/-! ## What the reduction asks: membership and counts -/

theorem mem_colTweaks {a : I} {c s k : Nat} {tw : Tw} (h : tw ∈ W.colTweaks a c s k) :
    ∃ j, j < k ∧ tw = W.twk a c (s + j) := by
  simp only [colTweaks, List.mem_map, List.mem_range] at h
  obtain ⟨j, hj, rfl⟩ := h
  exact ⟨j, hj, rfl⟩

theorem mem_elemTgts {i : Nat} {a : I} {c d : Nat} {tw : Tw} (h : tw ∈ W.elemTgts i a c d) :
    i + 1 < d ∧ tw = W.twk a c i := by
  cases d with
  | zero => simp [elemTgts] at h
  | succ e =>
    simp only [elemTgts] at h
    split at h
    · simp only [List.mem_singleton] at h; exact ⟨by omega, h⟩
    · simp at h

theorem mem_elemCols {i : Nat} {a : I} {c d : Nat} {tw : Tw} (hd : d ≤ W.w - 1) (h : tw ∈ W.elemCols i a c d) :
    ∃ hh, hh < W.w - 1 ∧ tw = W.twk a c hh ∧ (i + 1 < d → i < hh) := by
  cases d with
  | zero =>
    obtain ⟨j, hj, rfl⟩ := W.mem_colTweaks h
    exact ⟨0 + j, by omega, rfl, by omega⟩
  | succ e =>
    simp only [elemCols, List.mem_append] at h
    rcases h with (h | h) | h
    · split at h
      · obtain ⟨j, hj, rfl⟩ := W.mem_colTweaks h
        exact ⟨i + 1 + j, by omega, rfl, fun _ => by omega⟩
      · simp at h
    · obtain ⟨j, hj, rfl⟩ := W.mem_colTweaks h
      exact ⟨e + j, by omega, rfl, fun _ => by omega⟩
    · obtain ⟨j, hj, rfl⟩ := W.mem_colTweaks h
      exact ⟨e + 1 + j, by omega, rfl, fun _ => by omega⟩

theorem mem_sigTgts {i : Nat} {a : I} : ∀ {ds : List Nat} {c0 : Nat} {tw : Tw},
    tw ∈ W.sigTgts i a c0 ds → ∃ j, j < ds.length ∧ i + 1 < ds.getD j 0 ∧ tw = W.twk a (c0 + j) i
  | [], _, _, h => by simp [sigTgts] at h
  | d :: ds, c0, tw, h => by
    simp only [sigTgts, List.mem_append] at h
    rcases h with h | h
    · obtain ⟨hd, rfl⟩ := W.mem_elemTgts h
      exact ⟨0, by simp, by simpa using hd, by simp⟩
    · obtain ⟨j, hj, hd, rfl⟩ := mem_sigTgts h
      exact ⟨j + 1, by simp; omega, by simpa using hd, by rw [show c0 + 1 + j = c0 + (j + 1) by omega]⟩

theorem mem_sigCols {i : Nat} {a : I} : ∀ {ds : List Nat} {c0 : Nat} {tw : Tw}, (∀ d ∈ ds, d ≤ W.w - 1) →
    tw ∈ W.sigCols i a c0 ds →
      ∃ j hh, j < ds.length ∧ hh < W.w - 1 ∧ tw = W.twk a (c0 + j) hh ∧ (i + 1 < ds.getD j 0 → i < hh)
  | [], _, _, _, h => by simp [sigCols] at h
  | d :: ds, c0, tw, hb, h => by
    simp only [sigCols, List.mem_append] at h
    rcases h with h | h
    · obtain ⟨hh, h1, rfl, h2⟩ := W.mem_elemCols (hb d (List.mem_cons_self ..)) h
      exact ⟨0, hh, by simp, h1, by simp, by simpa using h2⟩
    · obtain ⟨j, hh, hj, h1, rfl, h2⟩ := mem_sigCols (fun d h => hb d (List.mem_cons_of_mem _ h)) h
      exact ⟨j + 1, hh, by simp; omega, h1, by rw [show c0 + 1 + j = c0 + (j + 1) by omega],
        by simpa using h2⟩

theorem length_sigTgts (i : Nat) (a : I) : ∀ (ds : List Nat) (c0 : Nat),
    (W.sigTgts i a c0 ds).length ≤ ds.length
  | [], _ => by simp [sigTgts]
  | d :: ds, c0 => by
    have h1 : (W.elemTgts i a c0 d).length ≤ 1 := by
      cases d with
      | zero => simp [elemTgts]
      | succ e => simp only [elemTgts]; split <;> simp
    have h2 := length_sigTgts i a ds (c0 + 1)
    simp only [sigTgts, List.length_append, List.length_cons]; omega

/-- Distinct chains have distinct targets. -/
theorem nodup_sigTgts (i : Nat) (a : I) (hi : i < W.w)
    (hinj : ∀ a a' j j' h h', j < W.len → j' < W.len → h < W.w → h' < W.w →
      W.twk a j h = W.twk a' j' h' → a = a' ∧ j = j' ∧ h = h') :
    ∀ (ds : List Nat) (c0 : Nat), c0 + ds.length ≤ W.len → (W.sigTgts i a c0 ds).Nodup
  | [], _, _ => by simp [sigTgts]
  | d :: ds, c0, hl => by
    simp only [sigTgts]
    rw [List.nodup_append]
    refine ⟨?_, nodup_sigTgts i a hi hinj ds (c0 + 1) (by simp at hl; omega), ?_⟩
    · cases d with
      | zero => simp [elemTgts]
      | succ e => simp only [elemTgts]; split <;> simp
    · intro x hx y hy hxy
      obtain ⟨_, rfl⟩ := W.mem_elemTgts hx
      obtain ⟨j, hj, _, rfl⟩ := W.mem_sigTgts hy
      have := (hinj a a c0 (c0 + 1 + j) i i (by simp at hl; omega) (by simp at hl; omega) hi hi hxy).2.1
      omega


/-! ## The challenger's log is determined by the reduction's state -/

/-- The UD-C log after the reduction answered the queries recorded in `s`. -/
def Inv (c i : Nat) (s : WotsState Tw I M X) (L : Log Tw Tw) : Prop :=
  L.tgt = ((s.qs.take c).map (fun e => W.sigTgts i e.1 0 (W.enc e.2.1))).flatten ∧
    ∀ tw ∈ L.col, tw ∈ s.cols ∨ ∃ e ∈ s.qs.take c, tw ∈ W.sigCols i e.1 0 (W.enc e.2.1)

/-- The challenger's log after one query to the capped reduction. -/
def capLog (c i : Nat) (s : WotsState Tw I M X) (q : WotsQuery Tw I M Xc) (L : Log Tw Tw) : Log Tw Tw :=
  match q with
  | .inl _ => if s.qs.length < c then W.logUpd i q L else L
  | .inr _ => W.logUpd i q L

theorem inv_step (pp : PP) (c i : Nat) (k : Nat) (s : WotsState Tw I M X) (L : Log Tw Tw)
    (q : WotsQuery Tw I M Xc) (h : W.Inv c i s L) :
    ((capH c (W.handler (fun pp a => W.hybElem k pp a) pp) s q).bind (fun r =>
      (.done (r.1, (r.2, W.capLog c i s q L)) : OT Unit X _))).All (fun r => W.Inv c i r.2.1 r.2.2) := by
  match q with
  | .inl (a, m) =>
    by_cases hlt : s.qs.length < c
    · simp only [capH, if_pos hlt, handler, OT.bind_assoc]
      refine OT.all_bind (fun _ => True) _ _ ?_ _ (OT.all_true _)
      intro r _
      show W.Inv c i ⟨s.qs ++ [(a, m, r.1, r.2)], s.cols⟩ (W.capLog c i s (.inl (a, m)) L)
      obtain ⟨h1, h2⟩ := h
      have ht1 : (s.qs ++ [(a, m, r.1, r.2)]).take c = s.qs ++ [(a, m, r.1, r.2)] :=
        List.take_of_length_le (by simp; omega)
      have ht0 : s.qs.take c = s.qs := List.take_of_length_le (by omega)
      rw [ht0] at h1 h2
      simp only [Inv, capLog, if_pos hlt, logUpd, ht1, List.map_append, List.map_cons, List.map_nil,
        List.flatten_append, List.flatten_cons, List.flatten_nil, List.append_nil]
      refine ⟨by rw [h1], fun tw htw => ?_⟩
      rw [List.mem_append] at htw
      rcases htw with htw | htw
      · rcases h2 tw htw with h | ⟨e, he, h⟩
        · exact Or.inl h
        · exact Or.inr ⟨e, List.mem_append_left _ he, h⟩
      · exact Or.inr ⟨(a, m, r.1, r.2), List.mem_append_right _ (List.mem_singleton_self _), htw⟩
    · simp only [capH, if_neg hlt, OT.bind]
      show W.Inv c i ⟨s.qs ++ [(a, m, [], [])], s.cols⟩ (W.capLog c i s (.inl (a, m)) L)
      have ht : (s.qs ++ [(a, m, [], [])]).take c = s.qs.take c :=
        List.take_append_of_le_length (by omega)
      simp only [Inv, capLog, if_neg hlt, ht]
      exact h
  | .inr (tw, x) =>
    simp only [capH, handler, OT.bind]
    show W.Inv c i ⟨s.qs, s.cols ++ [tw]⟩ (W.capLog c i s (.inr (tw, x)) L)
    obtain ⟨h1, h2⟩ := h
    simp only [Inv, capLog, logUpd]
    refine ⟨h1, fun tw' htw => ?_⟩
    rw [List.mem_append] at htw
    rcases htw with htw | htw
    · rcases h2 tw' htw with h | h
      · exact Or.inl (List.mem_append_left _ h)
      · exact Or.inr h
    · exact Or.inl (List.mem_append_right _ htw)

theorem nodup_map_eq {α β : Type} (f : α → β) : ∀ (l : List α), (l.map f).Nodup →
    ∀ x ∈ l, ∀ y ∈ l, f x = f y → x = y
  | [], _, x, hx, _, _, _ => absurd hx (by simp)
  | a :: l, hn, x, hx, y, hy, he => by
    rw [List.map_cons, List.nodup_cons] at hn
    rcases List.mem_cons.mp hx with rfl | hx' <;> rcases List.mem_cons.mp hy with rfl | hy'
    · rfl
    · exact absurd (List.mem_map.mpr ⟨y, hy', he.symm⟩) hn.1
    · exact absurd (List.mem_map.mpr ⟨x, hx', he⟩) hn.1
    · exact nodup_map_eq f l hn.2 x hx' y hy' he

/-- When the adversary wins, the UD-C challenger's conditions hold: at most
    `c · len` targets, distinct target tweaks, and no collection tweak among
    them. -/
theorem cond_of_win [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M]
    (c t i : Nat) (pp : PP) (s : WotsState Tw I M X) (L : Log Tw Tw) (out : Nat × M × List X)
    (hlen : ∀ m, (W.enc m).length = W.len) (hdig : ∀ m, ∀ d ∈ W.enc m, d ≤ W.w - 1)
    (hinj : ∀ a a' j j' h h', j < W.len → j' < W.len → h < W.w → h' < W.w →
      W.twk a j h = W.twk a' j' h' → a = a' ∧ j = j' ∧ h = h')
    (hinst : ∀ a j h, W.inst (W.twk a j h) = a) (hi : i < W.w) (ht : c * W.len ≤ t)
    (hI : W.Inv c i s L) (hw : W.win c pp s out = true) :
    (decide (L.tgt.length ≤ t) && tweaksOk L.tgt L.col) = true := by
  obtain ⟨h1, h2⟩ := hI
  unfold win at hw
  split at hw
  · exact absurd hw (by simp)
  rename_i a m pk sg _
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, Bool.not_eq_true'] at hw
  obtain ⟨⟨⟨⟨hc, hnd⟩, hdisj⟩, _⟩, _⟩ := hw
  rw [List.take_of_length_le hc] at h1 h2
  have hdisj' : ∀ tw ∈ s.cols, W.inst tw ∉ s.qs.map (·.1) := by
    intro tw htw hm
    have := hdisj tw htw
    rw [Bool.eq_false_iff] at this
    exact this (List.contains_iff_mem.mpr hm)
  simp only [Bool.and_eq_true, decide_eq_true_eq, tweaksOk, List.all_eq_true, Bool.not_eq_true']
  refine ⟨?_, ?_, ?_⟩
  · -- target count
    rw [h1, List.length_flatten]
    have : ((s.qs.map (fun e => W.sigTgts i e.1 0 (W.enc e.2.1))).map List.length).sum ≤
        s.qs.length * W.len := by
      clear h1 h2 hnd hdisj hdisj' hc
      induction s.qs with
      | nil => simp
      | cons e es ih =>
        simp only [List.map_cons, List.sum_cons, List.length_cons, Nat.succ_mul]
        have := W.length_sigTgts i e.1 (W.enc e.2.1) 0
        rw [hlen] at this; omega
    have := Nat.mul_le_mul_right W.len hc
    omega
  · -- distinct targets
    rw [h1]
    clear h1 h2 hc hdisj hdisj'
    generalize s.qs = qs at hnd ⊢
    induction qs with
    | nil => simp
    | cons e es ih =>
      rw [List.map_cons, List.nodup_cons] at hnd
      simp only [List.map_cons, List.flatten_cons]
      rw [List.nodup_append]
      refine ⟨W.nodup_sigTgts i e.1 hi hinj (W.enc e.2.1) 0 (by rw [hlen]; omega), ih hnd.2, ?_⟩
      intro x hx y hy hxy
      obtain ⟨j, hj, _, rfl⟩ := W.mem_sigTgts hx
      rw [List.mem_flatten] at hy
      obtain ⟨l, hl, hyl⟩ := hy
      obtain ⟨e', he', rfl⟩ := List.mem_map.mp hl
      obtain ⟨j', _, _, rfl⟩ := W.mem_sigTgts hyl
      have := congrArg W.inst hxy
      rw [hinst, hinst] at this
      exact hnd.1 (List.mem_map.mpr ⟨e', he', this.symm⟩)
  · -- targets are not collection tweaks
    intro tw htw
    rw [Bool.eq_false_iff]
    intro hcol'
    have hcol := List.contains_iff_mem.mp hcol'
    rw [h1, List.mem_flatten] at htw
    obtain ⟨l, hl, htl⟩ := htw
    obtain ⟨e, he, rfl⟩ := List.mem_map.mp hl
    obtain ⟨j, hj, hd, rfl⟩ := W.mem_sigTgts htl
    rcases h2 _ hcol with hc' | ⟨e', he', hc'⟩
    · apply hdisj' _ hc'
      rw [hinst]; exact List.mem_map.mpr ⟨e, he, rfl⟩
    · obtain ⟨j', hh, hj', hh', heq, himp⟩ := W.mem_sigCols (hdig _) hc'
      rw [hlen] at hj hj'
      obtain ⟨ha, hjj, hhi⟩ := hinj _ _ _ _ _ _ (by omega) (by omega) hi (by omega) heq
      have hee : e = e' := nodup_map_eq _ _ hnd e he e' he' ha
      subst hee
      have hjj' : j = j' := by omega
      subst hjj'
      have := himp hd
      omega

/-! ## The reduction as a UD-C adversary, and its game as a labelled process -/

/-- The reduction's handler (capped at `c` signing queries) with its own tape. -/
def udRedHandler (c i : Nat) (x0 : X) (st : WotsState Tw I M X × List X) (q : WotsQuery Tw I M Xc) :
    OT (Tw ⊕ (Tw × Xc)) X (WotsAnswer X × (WotsState Tw I M X × List X)) :=
  (resolveS x0 (capH c (W.udHandler i) st.1 q) st.2).bind (fun r => .done (r.1.1, (r.1.2, r.2)))

/-- `R_SMDTUDC_Game23WOTSTWES` with hybrid index `i` and own tape `R`. -/
def udRed [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type} (c i : Nat) (x0 : X)
    (A : WotsAdv PP Tw I M X Xc σ) (R : List X) :
    UdAdv PP Tw Xc X (σ × (WotsState Tw I M X × List X)) :=
  ⟨OT.interp (W.udRedHandler c i x0) A.choose (⟨[], []⟩, R),
   fun st pp => W.win c pp st.2.1 (A.forge st.1 pp)⟩

/-- The labelled process's handler. -/
def udProcHandler (b : Bool) (pp : PP) (c i : Nat) (st : WotsState Tw I M X × Log Tw Tw)
    (q : WotsQuery Tw I M Xc) : OT Bool X (WotsAnswer X × (WotsState Tw I M X × Log Tw Tw)) :=
  (udInterp b W.f W.fc pp (capH c (W.udHandler i) st.1 q) st.2).bind (fun r => .done (r.1.1, (r.1.2, r.2)))

/-- The UD-C game of the reduction, as a labelled process. -/
def udProc [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (b : Bool) (c t i : Nat) (pp : PP) (A : WotsAdv PP Tw I M X Xc σ) : OT Bool X Bool :=
  (OT.interp (W.udProcHandler b pp c i) A.choose (⟨[], []⟩, ⟨[], []⟩)).bind (fun r =>
    .done (decide (r.2.2.tgt.length ≤ t) && tweaksOk r.2.2.tgt r.2.2.col && W.win c pp r.2.1 (A.forge r.1 pp)))

theorem udRed_run_proc [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (b : Bool) (c t i : Nat) (x0 : X) (pp : PP) (A : WotsAdv PP Tw I M X Xc σ) (T R : List X) :
    (let B := W.udRed c i x0 A R
     let r := B.pick.run (udOracle (udAns b W.f x0 pp T) W.fc pp) ⟨[], []⟩
     decide (r.2.tgt.length ≤ t) && tweaksOk r.2.tgt r.2.col && B.distinguish r.1 pp) =
      ((W.udProc b c t i pp A).run (tape2 x0) (T, R)).1 := by
  let Rel : ((WotsState Tw I M X × List X) × Log Tw Tw) →
      ((WotsState Tw I M X × Log Tw Tw) × (List X × List X)) → Prop :=
    fun u v => u.1.1 = v.1.1 ∧ u.2 = v.1.2 ∧ u.1.2 = v.2.2 ∧ v.2.1 = T.drop u.2.tgt.length
  have step := OT.run_rel
    (fun (st : (WotsState Tw I M X × List X) × Log Tw Tw) q =>
      let x := (W.udRedHandler c i x0 st.1 q).run (udOracle (udAns b W.f x0 pp T) W.fc pp) st.2
      (x.1.1, (x.1.2, x.2)))
    (fun (st : (WotsState Tw I M X × Log Tw Tw) × (List X × List X)) q =>
      let x := (W.udProcHandler b pp c i st.1 q).run (tape2 x0) st.2
      (x.1.1, (x.1.2, x.2))) Rel (by
      rintro ⟨⟨s1, R1⟩, L1⟩ ⟨⟨s2, L2⟩, ⟨T2, R2⟩⟩ q ⟨h1, h2, h3, h4⟩
      simp only at h1 h2 h3 h4
      subst h1 h2 h3 h4
      have hu := udRun_proc b W.f W.fc x0 pp T (capH c (W.udHandler i) s1 q) R1 L1
      have ht := udInterp_tape b W.f W.fc x0 pp T (capH c (W.udHandler i) s1 q) R1 L1
      simp only [udRedHandler, udProcHandler, OT.run_bind, OT.run, hu]
      refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> first | rfl | trivial | exact ht) A.choose ((⟨[], []⟩, R), ⟨[], []⟩) ((⟨[], []⟩, ⟨[], []⟩), (T, R))
      ⟨rfl, rfl, rfl, rfl⟩
  have hB := OT.run_interp (W.udRedHandler c i x0) (udOracle (udAns b W.f x0 pp T) W.fc pp) A.choose
    (⟨[], []⟩, R) ⟨[], []⟩
  have hL := OT.run_interp (W.udProcHandler b pp c i) (tape2 x0) A.choose (⟨[], []⟩, ⟨[], []⟩) (T, R)
  obtain ⟨he, h1, h2, _, _⟩ := step
  simp only [udRed, udProc, OT.run_bind, OT.run]
  simp only [hB, hL]
  simp only [he, h1, h2]

theorem band_of_imp (a w : Bool) (h : w = true → a = true) : (a && w) = w := by
  cases w <;> simp_all

theorem cap_handler_eq (b : Bool) (pp : PP) (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x)
    (c i : Nat) (s : WotsState Tw I M X) (q : WotsQuery Tw I M Xc) (L : Log Tw Tw) :
    unlabel (udInterp b W.f W.fc pp (capH c (W.udHandler i) s q) L) =
      (capH c (W.handler (fun pp a => W.hybElem (hybIndex b i) pp a) pp) s q).bind (fun r =>
        .done (r, W.capLog c i s q L)) := by
  match q with
  | .inl (a, m) =>
    by_cases hlt : s.qs.length < c
    · simp only [capH, if_pos hlt, capLog]; exact W.handler_eq b pp hc i s _ L
    · simp only [capH, if_neg hlt, capLog, udInterp, unlabel, OT.bind]
  | .inr q => simp only [capH, capLog]; exact W.handler_eq b pp hc i s _ L

theorem procHandler_eq (b : Bool) (pp : PP) (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x)
    (c i : Nat) (st : WotsState Tw I M X × Log Tw Tw) (q : WotsQuery Tw I M Xc) :
    unlabel (W.udProcHandler b pp c i st q) =
      (capH c (W.handler (fun pp a => W.hybElem (hybIndex b i) pp a) pp) st.1 q).bind (fun r =>
        .done (r.1, (r.2, W.capLog c i st.1 q st.2))) := by
  unfold udProcHandler
  rw [unlabel_bind, cap_handler_eq W b pp hc, OT.bind_assoc]
  rfl

/-- With the real (`b = false`) or ideal (`b = true`) challenge, the
    reduction's UD-C game, read on one tape, is hybrid `i` or `i + 1`
    (both capped at `c` signing queries). -/
theorem udProc_hyb [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (b : Bool) (c t i : Nat) (x0 : X) (pp : PP) (A : WotsAdv PP Tw I M X Xc σ)
    (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x)
    (hlen : ∀ m, (W.enc m).length = W.len) (hdig : ∀ m, ∀ d ∈ W.enc m, d ≤ W.w - 1)
    (hinj : ∀ a a' j j' h h', j < W.len → j' < W.len → h < W.w → h' < W.w →
      W.twk a j h = W.twk a' j' h' → a = a' ∧ j = j' ∧ h = h')
    (hinst : ∀ a j h, W.inst (W.twk a j h) = a) (hi : i < W.w) (ht : c * W.len ≤ t) (T : List X) :
    ((unlabel (W.udProc b c t i pp A)).run (tape1 x0) T).1 =
      ((W.proc (capH c (W.handler (fun pp a => W.hybElem (hybIndex b i) pp a) pp)) c pp A).run
        (tape1 x0) T).1 := by
  have hfun : (fun st q => unlabel (W.udProcHandler b pp c i st q)) =
      (fun (st : WotsState Tw I M X × Log Tw Tw) q =>
        (capH c (W.handler (fun pp a => W.hybElem (hybIndex b i) pp a) pp) st.1 q).bind (fun r =>
          (.done (r.1, (r.2, W.capLog c i st.1 q st.2)) : OT Unit X _))) := by
    funext st q; exact procHandler_eq W b pp hc c i st q
  unfold udProc proc
  rw [unlabel_bind, unlabel_interp, hfun, OT.run_bind, OT.run_bind]
  have hinv := OT.all_run (fun r => W.Inv c i r.2.1 r.2.2) (tape1 x0)
    (OT.interp (fun (st : WotsState Tw I M X × Log Tw Tw) q =>
      (capH c (W.handler (fun pp a => W.hybElem (hybIndex b i) pp a) pp) st.1 q).bind (fun r =>
        (.done (r.1, (r.2, W.capLog c i st.1 q st.2)) : OT Unit X _))) A.choose (⟨[], []⟩, ⟨[], []⟩)) T
    (OT.all_interp (fun (st : WotsState Tw I M X × Log Tw Tw) => W.Inv c i st.1 st.2) _
      (fun st q h => W.inv_step pp c i (hybIndex b i) st.1 st.2 q h) A.choose _ ⟨by simp, by simp⟩)
  have step := OT.interp_run_rel
    (fun (st : WotsState Tw I M X × Log Tw Tw) q =>
      (capH c (W.handler (fun pp a => W.hybElem (hybIndex b i) pp a) pp) st.1 q).bind (fun r =>
        (.done (r.1, (r.2, W.capLog c i st.1 q st.2)) : OT Unit X _))) (tape1 x0)
    (capH c (W.handler (fun pp a => W.hybElem (hybIndex b i) pp a) pp)) (tape1 x0)
    (fun u v => u.1.1 = v.1 ∧ u.2 = v.2) (by
      rintro ⟨s1, L1⟩ T1 s2 T2 q ⟨h1, h2⟩
      simp only at h1 h2
      subst h1 h2
      simp only [OT.run_bind, OT.run]
      refine ⟨?_, ?_, ?_⟩ <;> first | rfl | trivial) A.choose (⟨[], []⟩, ⟨[], []⟩) T ⟨[], []⟩ T ⟨rfl, rfl⟩
  obtain ⟨he, h1, _⟩ := step
  simp only at h1 hinv
  simp only [OT.run, unlabel]
  rw [he, h1]
  rw [h1] at hinv
  exact band_of_imp _ _ (fun hw => W.cond_of_win c t i pp _ _ _ hlen hdig hinj hinst hi ht hinv hw)


/-! ## Draw budgets of the reduction's game -/

theorem unlabel_udProc [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (b : Bool) (c t i : Nat) (pp : PP) (A : WotsAdv PP Tw I M X Xc σ)
    (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x) :
    unlabel (W.udProc b c t i pp A) =
      (OT.interp (fun (st : WotsState Tw I M X × Log Tw Tw) q =>
        (capH c (W.handler (fun pp a => W.hybElem (hybIndex b i) pp a) pp) st.1 q).bind (fun r =>
          (.done (r.1, (r.2, W.capLog c i st.1 q st.2)) : OT Unit X _))) A.choose (⟨[], []⟩, ⟨[], []⟩)).bind
        (fun r => .done (decide (r.2.2.tgt.length ≤ t) && tweaksOk r.2.2.tgt r.2.2.col &&
          W.win c pp r.2.1 (A.forge r.1 pp))) := by
  have hfun : (fun st q => unlabel (W.udProcHandler b pp c i st q)) =
      (fun (st : WotsState Tw I M X × Log Tw Tw) q =>
        (capH c (W.handler (fun pp a => W.hybElem (hybIndex b i) pp a) pp) st.1 q).bind (fun r =>
          (.done (r.1, (r.2, W.capLog c i st.1 q st.2)) : OT Unit X _))) := by
    funext st q; exact procHandler_eq W b pp hc c i st q
  unfold udProc
  rw [unlabel_bind, unlabel_interp, hfun]
  rfl

/-- The reduction's game draws at most `c · len` values in all. -/
theorem udProc_within [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (b : Bool) (c t i : Nat) (pp : PP) (A : WotsAdv PP Tw I M X Xc σ)
    (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x) (hlen : ∀ m, (W.enc m).length = W.len) :
    (unlabel (W.udProc b c t i pp A)).Within (c * W.len) := by
  rw [W.unlabel_udProc b c t i pp A hc]
  apply OT.withinP_within (fun _ _ => True)
  exact OT.withinP_bind _ _ _ (fun _ _ _ => by simp [OT.WithinP]) _ _
    (OT.withinP_interp (fun (st : WotsState Tw I M X × Log Tw Tw) n => W.capInv c st.1 n) _
      (fun st q n h => OT.withinP_bind _ _ _ (fun r m hr => by simp only [OT.WithinP]; exact hr) _ n
        (W.capH_withinP _ (fun pp a => W.hyb_oneDraw (hybIndex b i) pp a) hlen pp c st.1 q n h))
      A.choose _ _ (by simp [capInv]))

theorem udProc_withinL [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (b : Bool) (c t i : Nat) (pp : PP) (A : WotsAdv PP Tw I M X Xc σ)
    (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x) (hlen : ∀ m, (W.enc m).length = W.len)
    (ht : c * W.len ≤ t) : WithinL (W.udProc b c t i pp A) t (c * W.len) :=
  withinL_of_unlabel _ (c * W.len) t (c * W.len) (W.udProc_within b c t i pp A hc hlen) ht (Nat.le_refl _)

/-! ## Counting: the UD-C game of the reduction is a pair of hybrids -/

/-- For fixed `pp`, adversary and hybrid index: summing the reduction's game
    over the challenger's `t` values and the reduction's `c · len` own values
    gives `|D|^t` times the capped hybrid's count over `c · len` values. -/
theorem ud_inner [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (b : Bool) (c t i : Nat) (x0 : X) (pp : PP) (A : WotsAdv PP Tw I M X Xc σ) (Din : FiniteExperiment X)
    (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x)
    (hlen : ∀ m, (W.enc m).length = W.len) (hdig : ∀ m, ∀ d ∈ W.enc m, d ≤ W.w - 1)
    (hinj : ∀ a a' j j' h h', j < W.len → j' < W.len → h < W.w → h' < W.w →
      W.twk a j h = W.twk a' j' h' → a = a' ∧ j = j' ∧ h = h')
    (hinst : ∀ a j h, W.inst (W.twk a j h) = a) (hi : i < W.w) (ht : c * W.len ≤ t) :
    (Din.tape t).sum (fun T => (Din.tape (c * W.len)).sum (fun R =>
      if ((W.udProc b c t i pp A).run (tape2 x0) (T, R)).1 then 1 else 0)) =
      Din.cardinality ^ t * (Din.tape (c * W.len)).sum (fun T =>
        if ((W.proc (capH c (W.handler (fun pp a => W.hybElem (hybIndex b i) pp a) pp)) c pp A).run
          (tape1 x0) T).1 then 1 else 0) := by
  have hm := tape_merge x0 Din (fun b => if b then 1 else 0) (W.udProc b c t i pp A) t (c * W.len)
    (W.udProc_withinL b c t i pp A hc hlen ht)
  have hp := tape_pad x0 Din (fun b => if b then 1 else 0)
    (W.proc (capH c (W.handler (fun pp a => W.hybElem (hybIndex b i) pp a) pp)) c pp A) (c * W.len) t
    (W.proc_within _ (fun pp a => W.hyb_oneDraw (hybIndex b i) pp a) hlen c pp A)
  simp only at hm hp
  rw [hm, hp, Nat.add_comm]
  apply sum_congr; intro j
  rw [W.udProc_hyb b c t i x0 pp A hc hlen hdig hinj hinst hi ht]

end WotsSetting

/-- The uniform hybrid index `i < n`. -/
def idxExp (n : Nat) (hn : 0 < n) : FiniteExperiment Nat := ⟨n, hn, fun j => j.val⟩

theorem idx_sum (n : Nat) (hn : 0 < n) (g : Nat → Nat) : (idxExp n hn).sum g = rsum n g := by
  unfold FiniteExperiment.sum
  exact rsum_congr (fun i hi => by have h : i < n := hi; simp [h, idxExp])

/-- Telescoping over the hybrids. -/
theorem rsum_telescope (H : Nat → Nat) : ∀ n, rsum n H + H n = rsum n (fun i => H (i + 1)) + H 0
  | 0 => by simp [rsum_zero]
  | n+1 => by
    rw [rsum_succ, rsum_succ]
    have := rsum_telescope H n
    omega

/-- Exact fraction arithmetic of the UD-C step. -/
theorem frac_step (N0 Nn Dg Dt n R I Dud : Nat) (hD : Dud = n * Dt * Dg)
    (hid : Dt * N0 + I = R + Dt * Nn) :
    fle (N0, Dg) (fadd (Nn, Dg) (n * (R * Dud - I * Dud + (I * Dud - R * Dud)), Dud * Dud)) := by
  unfold fle fadd
  simp only
  have h1 : Dt * N0 ≤ Dt * Nn + (R - I) := by omega
  have h2 : (R - I) * Dud ≤ R * Dud - I * Dud + (I * Dud - R * Dud) := by rw [Nat.sub_mul]; omega
  generalize R * Dud - I * Dud + (I * Dud - R * Dud) = gap at h2 ⊢
  generalize R - I = d at h1 h2
  calc N0 * (Dg * (Dud * Dud)) = (Dt * N0) * (n * Dg * Dud * Dg) := by rw [hD]; ac_rfl
    _ ≤ (Dt * Nn + d) * (n * Dg * Dud * Dg) := Nat.mul_le_mul_right _ h1
    _ = Nn * (Dud * Dud) * Dg + (d * Dud) * (n * Dg * Dg) := by
      rw [Nat.add_mul, hD]; congr 1 <;> ac_rfl
    _ ≤ Nn * (Dud * Dud) * Dg + gap * (n * Dg * Dg) := Nat.add_le_add_left (Nat.mul_le_mul_right _ h2) _
    _ = (Nn * (Dud * Dud) + n * gap * Dg) * Dg := by rw [Nat.add_mul]; congr 1; ac_rfl

namespace WotsSetting
variable {PP Tw I M X Xc : Type} (W : WotsSetting PP Tw I M X Xc)

/-- The reduction's coins: the hybrid index `i < n`, its own `c · len`
    values, and the WOTS adversary's coins. -/
def udCoins [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type} (c : Nat) (x0 : X)
    (Din : FiniteExperiment X) (As : FiniteExperiment (WotsAdv PP Tw I M X Xc σ)) (n : Nat) (hn : 0 < n) :
    FiniteExperiment (UdAdv PP Tw Xc X (σ × (WotsState Tw I M X × List X))) :=
  (independentProduct (idxExp n hn) (independentProduct (Din.tape (c * W.len)) As)).map
    (fun p => W.udRed c p.1 x0 p.2.2 p.2.1)

/-- The UD-C game of the reduction, with challenge answers `udAns b`, counts
    `|D|^t` times the sum of capped hybrids `hybIndex b i` over `i < n`. -/
theorem ud_num [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (b : Bool) (c t n : Nat) (hn : 0 < n) (x0 : X) (P : FiniteExperiment PP) (Din : FiniteExperiment X)
    (As : FiniteExperiment (WotsAdv PP Tw I M X Xc σ)) (ans : PP → List X → Nat → Tw → X)
    (hans : ∀ pp T, ans pp T = udAns b W.f x0 pp T)
    (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x)
    (hlen : ∀ m, (W.enc m).length = W.len) (hdig : ∀ m, ∀ d ∈ W.enc m, d ≤ W.w - 1)
    (hinj : ∀ a a' j j' h h', j < W.len → j' < W.len → h < W.w → h' < W.w →
      W.twk a j h = W.twk a' j' h' → a = a' ∧ j = j' ∧ h = h')
    (hinst : ∀ a j h, W.inst (W.twk a j h) = a) (hnw : n ≤ W.w) (ht : c * W.len ≤ t) :
    (udRun P (Din.tape t) ans W.fc t (W.udCoins c x0 Din As n hn)).numerator =
      Din.cardinality ^ t * rsum n (fun i => W.hybCount x0 c P Din As (hybIndex b i)) := by
  have stepA : (udRun P (Din.tape t) ans W.fc t (W.udCoins c x0 Din As n hn)).numerator =
      P.sum (fun pp => (Din.tape t).sum (fun T => (idxExp n hn).sum (fun i =>
        (Din.tape (c * W.len)).sum (fun R => As.sum (fun A =>
          if ((W.udProc b c t i pp A).run (tape2 x0) (T, R)).1 then 1 else 0))))) := by
    unfold udRun udCoins
    rw [numerator_sum, product_sum, product_sum]
    apply sum_congr; intro i1
    apply sum_congr; intro i2
    rw [sum_map_product]
    apply sum_congr; intro i3
    rw [product_sum]
    apply sum_congr; intro i4
    apply sum_congr; intro i5
    apply ind_of_eq
    rw [hans]
    exact W.udRed_run_proc b c t _ x0 _ _ _ _
  rw [stepA]
  simp only [sum_comm (Din.tape t) (idxExp n hn), sum_comm (Din.tape (c * W.len)) As,
    sum_comm (Din.tape t) As, sum_comm P (idxExp n hn)]
  rw [← idx_sum n hn, sum_mul_left]
  apply sum_congr; intro i
  have hi : (idxExp n hn).sample i < n := i.isLt
  unfold hybCount count
  rw [sum_mul_left]
  apply sum_congr; intro j
  rw [sum_mul_left]
  apply sum_congr; intro k
  exact W.ud_inner b c t _ x0 _ _ Din hc hlen hdig hinj hinst (by omega) ht

theorem ud_den [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (c t n : Nat) (hn : 0 < n) (x0 : X) (P : FiniteExperiment PP) (Din : FiniteExperiment X)
    (As : FiniteExperiment (WotsAdv PP Tw I M X Xc σ)) (ans : PP → List X → Nat → Tw → X) :
    (udRun P (Din.tape t) ans W.fc t (W.udCoins c x0 Din As n hn)).denominator =
      n * Din.cardinality ^ t * (W.hybProb x0 c P Din As 0).denominator := by
  show (P.cardinality * (Din.tape t).cardinality) * (n * ((Din.tape (c * W.len)).cardinality * As.cardinality)) = _
  simp only [hybProb, card_tape]
  ac_rfl


/-- **The UD-C step, exactly.** With `n = w − 2` hybrid indices, the
    reduction's real and ideal UD-C counts telescope:
    `|D|^t · #G + #ideal = #real + |D|^t · #Hyb_{w−2}`, where `G` is the
    M-EUF-GCMA game and `Hyb_{w−2}` the capped Game 3. -/
theorem ud_step [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (c t : Nat) (x0 : X) (P : FiniteExperiment PP) (Din : FiniteExperiment X)
    (As : FiniteExperiment (WotsAdv PP Tw I M X Xc σ)) (hn : 0 < W.w - 2)
    (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x)
    (hlen : ∀ m, (W.enc m).length = W.len) (hdig : ∀ m, ∀ d ∈ W.enc m, d ≤ W.w - 1)
    (hinj : ∀ a a' j j' h h', j < W.len → j' < W.len → h < W.w → h' < W.w →
      W.twk a j h = W.twk a' j' h' → a = a' ∧ j = j' ∧ h = h')
    (hinst : ∀ a j h, W.inst (W.twk a j h) = a) (ht : c * W.len ≤ t) :
    Din.cardinality ^ t * (W.gameProb x0 c P Din As).numerator +
        (udIdealProb P Din x0 W.fc t (W.udCoins c x0 Din As (W.w - 2) hn)).numerator =
      (udRealProb P Din x0 W.f W.fc t (W.udCoins c x0 Din As (W.w - 2) hn)).numerator +
        Din.cardinality ^ t * (W.hybProb x0 c P Din As (W.w - 2)).numerator := by
  have hR := W.ud_num false c t (W.w - 2) hn x0 P Din As (fun pp tape j tw => W.f pp tw (tape.getD j x0))
    (fun pp T => by funext j tw; simp [udAns]) hc hlen hdig hinj hinst (by omega) ht
  have hI := W.ud_num true c t (W.w - 2) hn x0 P Din As (fun _ tape j _ => tape.getD j x0)
    (fun pp T => by funext j tw; simp [udAns]) hc hlen hdig hinj hinst (by omega) ht
  have tel := rsum_telescope (W.hybCount x0 c P Din As) (W.w - 2)
  unfold udRealProb udIdealProb
  rw [hR, hI, W.game_hyb0 x0 c P Din As hdig]
  show _ = _ + Din.cardinality ^ t * W.hybCount x0 c P Din As (W.w - 2)
  simp only [hybIndex, if_true, if_false, Bool.false_eq_true]
  rw [← Nat.mul_add, ← Nat.mul_add, Nat.add_comm (W.hybCount x0 c P Din As 0), tel]

/-- **The UD-C step, as fractions.** `Pr[G] ≤ Pr[Hyb_{w−2}] + (w − 2) · Adv^{UD-C}`
    for the reduction `udCoins` (index guessed uniformly among `w − 2`), with
    the challenger's `t ≥ c · len` targets and inputs and outputs uniform on
    the same space. -/
theorem ud_step_frac [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (c t : Nat) (x0 : X) (P : FiniteExperiment PP) (Din : FiniteExperiment X)
    (As : FiniteExperiment (WotsAdv PP Tw I M X Xc σ)) (hn : 0 < W.w - 2)
    (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x)
    (hlen : ∀ m, (W.enc m).length = W.len) (hdig : ∀ m, ∀ d ∈ W.enc m, d ≤ W.w - 1)
    (hinj : ∀ a a' j j' h h', j < W.len → j' < W.len → h < W.w → h' < W.w →
      W.twk a j h = W.twk a' j' h' → a = a' ∧ j = j' ∧ h = h')
    (hinst : ∀ a j h, W.inst (W.twk a j h) = a) (ht : c * W.len ≤ t) :
    fle (W.gameProb x0 c P Din As).frac
      (fadd (W.hybProb x0 c P Din As (W.w - 2)).frac
        ((W.w - 2) * (udAdv P Din x0 Din x0 W.f W.fc t (W.udCoins c x0 Din As (W.w - 2) hn)).1,
         (udAdv P Din x0 Din x0 W.f W.fc t (W.udCoins c x0 Din As (W.w - 2) hn)).2)) := by
  have hid := W.ud_step c t x0 P Din As hn hc hlen hdig hinj hinst ht
  have hRd := W.ud_den c t (W.w - 2) hn x0 P Din As (fun pp tape j tw => W.f pp tw (tape.getD j x0))
  have hId := W.ud_den c t (W.w - 2) hn x0 P Din As (fun _ tape j _ => tape.getD j x0)
  have key := frac_step _ _ (W.hybProb x0 c P Din As 0).denominator (Din.cardinality ^ t) (W.w - 2) _ _ _ rfl hid
  unfold udAdv advantage gapNumerator Probability.frac
  unfold udRealProb udIdealProb
  rw [hRd, hId]
  exact key


/-! ## Resources of the reduction

Every chain costs the reduction at most `w − 1` UD-C queries (targets and
collection) and one own draw; a signing query costs at most `len · (w − 1)`
queries, a collection query one. -/

theorem colChain_withinI (a : I) (c : Nat) :
    ∀ (k : Nat) (x : X) (s n : Nat), k ≤ n →
      WithinI (fun _ m => n ≤ m + k) (W.colChain a c x s k) n
  | 0, _, _, n, _ => by simp [colChain, WithinI]
  | k+1, x, s, n, hk => by
    cases n with
    | zero => omega
    | succ n =>
      simp only [colChain, WithinI]
      intro y
      exact withinI_mono _ _ (fun _ m h => by omega) _ _ (colChain_withinI a c k y (s+1) n (by omega))

theorem udTail_withinI (a : I) (c e : Nat) (he : e + 1 ≤ W.w - 1) (v : X) (m : Nat)
    (hm : W.w - 1 - e ≤ m) :
    WithinI (fun _ m' => m ≤ m' + (W.w - 1 - e))
      ((W.colChain a c v e 1).bind (fun sig =>
        (W.colChain a c sig (e+1) (W.w - 1 - (e+1))).bind (fun pk => .done (pk, sig)))) m := by
  refine withinI_bind _ _ _ (fun sig m1 h1 => ?_) _ m (W.colChain_withinI a c 1 v e m (by omega))
  refine withinI_bind _ _ _ (fun pk m2 h2 => ?_) _ m1 (W.colChain_withinI a c _ sig (e+1) m1 (by omega))
  simp only [WithinI]
  omega

theorem udElem_withinI (i : Nat) (a : I) (c d : Nat) (hd : d ≤ W.w - 1) (n : Nat) (hn : W.w - 1 ≤ n) :
    WithinI (fun _ m => n ≤ m + (W.w - 1)) (W.udElem i a c d) n := by
  cases d with
  | zero =>
    simp only [udElem, WithinI]
    intro x
    exact withinI_bind _ _ _ (fun _ m h => by simp only [WithinI]; exact h) _ n
      (W.colChain_withinI a c (W.w - 1) x 0 n hn)
  | succ e =>
    by_cases hi : i < e
    · simp only [udElem, if_pos hi, OT.bind]
      cases n with
      | zero => omega
      | succ n =>
        simp only [WithinI]
        intro y
        refine withinI_bind _ _ _ (fun v m hm => ?_) _ n
          (W.colChain_withinI a c (e - (i+1)) y (i+1) n (by omega))
        exact withinI_mono _ _ (fun _ m' h => by omega) _ _ (W.udTail_withinI a c e (by omega) v m (by omega))
    · simp only [udElem, if_neg hi, OT.bind, WithinI]
      intro v
      exact withinI_mono _ _ (fun _ m' h => by omega) _ _ (W.udTail_withinI a c e (by omega) v n (by omega))

theorem signUd_withinI (i : Nat) (a : I) :
    ∀ (ds : List Nat) (c n : Nat), (∀ d ∈ ds, d ≤ W.w - 1) → ds.length * (W.w - 1) ≤ n →
      WithinI (fun _ m => n ≤ m + ds.length * (W.w - 1)) (signFrom (W.udElem i a) c ds) n
  | [], _, n, _, _ => by simp [signFrom, WithinI]
  | d :: ds, c, n, hd, hn => by
    simp only [List.length_cons, Nat.succ_mul] at hn ⊢
    simp only [signFrom]
    refine withinI_bind _ _ _ (fun e m hm => ?_) _ n
      (W.udElem_withinI i a c d (hd d (List.mem_cons_self ..)) n (by omega))
    refine withinI_bind _ _ _ (fun r m' hm' => ?_) _ m
      (signUd_withinI i a ds (c+1) m (fun d h => hd d (List.mem_cons_of_mem _ h)) (by omega))
    simp only [WithinI]
    omega

theorem capUd_withinI (hlen : ∀ m, (W.enc m).length = W.len) (hdig : ∀ m, ∀ d ∈ W.enc m, d ≤ W.w - 1)
    (hK : 1 ≤ W.len * (W.w - 1)) (c i : Nat) (s : WotsState Tw I M X) (q : WotsQuery Tw I M Xc)
    (n : Nat) (hn : W.len * (W.w - 1) ≤ n) :
    WithinI (fun _ m => n ≤ m + W.len * (W.w - 1)) (capH c (W.udHandler i) s q) n := by
  match q with
  | .inl (a, msg) =>
    by_cases hlt : s.qs.length < c
    · simp only [capH, if_pos hlt, udHandler]
      have h := W.signUd_withinI i a (W.enc msg) 0 n (hdig msg) (by rw [hlen]; exact hn)
      rw [hlen] at h
      exact withinI_bind _ _ _ (fun _ m hm => by simp only [WithinI]; exact hm) _ n h
    · simp only [capH, if_neg hlt, WithinI]
      omega
  | .inr (tw, x) =>
    cases n with
    | zero => omega
    | succ n =>
      simp only [capH, udHandler, WithinI]
      intro _
      omega

/-- **Query budget of the reduction.** Against an adversary whose first phase
    makes at most `q` queries (signing and collection together), the
    reduction makes at most `q · len · (w − 1)` UD-C queries (targets and
    collection together). Its own coins are the index `i` and `c · len`
    values (`udCoins`); its targets number at most `c · len` (`cond_of_win`
    for winning runs; the challenger rejects more than `t`). -/
theorem udRed_queries [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (hlen : ∀ m, (W.enc m).length = W.len) (hdig : ∀ m, ∀ d ∈ W.enc m, d ≤ W.w - 1)
    (hK : 1 ≤ W.len * (W.w - 1)) (c i : Nat) (x0 : X) (A : WotsAdv PP Tw I M X Xc σ) (R : List X)
    (q : Nat) (hA : A.choose.Within q) :
    (W.udRed c i x0 A R).pick.Within (q * (W.len * (W.w - 1))) := by
  apply OT.withinP_within (fun _ _ => True)
  refine OT.within_interp_mul _ (W.len * (W.w - 1)) (fun st qq n hn => ?_) A.choose q _ _ hA (Nat.le_refl _)
  unfold udRedHandler
  exact OT.withinP_bind _ _ _ (fun _ m hm => by simp only [OT.WithinP]; exact hm) _ n
    (withinI_resolve x0 _ _ st.2 n (W.capUd_withinI hlen hdig hK c i st.1 qq n hn))

end WotsSetting

#print axioms udRun_proc
#print axioms WotsSetting.ud_num
#print axioms frac_step
#print axioms WotsSetting.ud_step
#print axioms WotsSetting.ud_step_frac
#print axioms WotsSetting.udRed_queries
end DSM.Sphincs.Comp
