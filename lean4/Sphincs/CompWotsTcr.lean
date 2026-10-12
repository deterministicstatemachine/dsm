-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.CompWotsG3

/- Modular proof, milestone 3, obligation 8 (part 5): the SM-DT-TCR-C step
   of WOTS-TW (EasyCrypt `R_SMDTTCRC_Game34WOTSTWES`).

   The reduction plays Game 3 for the adversary with its own uniform values.
   For digit `d = e + 1` it obtains the signature element `F(x)` at depth `e`
   through the collection oracle; then it climbs every chain from its digit
   to depth `w − 1` by submitting each step's input as a TCR-C target (the
   target oracle answers `F` of it). When the forgery climbs onto a value
   different from the signed one (`tcrEv`), the two chains collide at some
   depth, and the honest side of that collision is one of its targets.
   No assumption, axiom or `sorry`. -/
namespace DSM.Sphincs.Comp
open DSM.Sphincs DSM.Sphincs.Security

/-- A TCR reduction program's queries: a target `(tweak, input)`, a
    collection query, or an own draw. -/
abbrev TcrProgQ (Tw X Xc : Type) := ((Tw × X) ⊕ (Tw × Xc)) ⊕ Unit

section TcrInterp
variable {PP Tw Xc X α β : Type}

/-- The TCR-C challenger (deterministic) inside the process; own draws remain. -/
def tcrInterp (f : PP → Tw → X → X) (fc : PP → Tw → Xc → X) (pp : PP) :
    OT (TcrProgQ Tw X Xc) X α → Log (Tw × X) Tw → OT Unit X (α × Log (Tw × X) Tw)
  | .done a, L => .done (a, L)
  | .ask (.inl (.inl q)) k, L => tcrInterp f fc pp (k (f pp q.1 q.2)) ⟨L.tgt ++ [q], L.col⟩
  | .ask (.inl (.inr q)) k, L => tcrInterp f fc pp (k (fc pp q.1 q.2)) ⟨L.tgt, L.col ++ [q.1]⟩
  | .ask (.inr ()) k, L => .ask () (fun x => tcrInterp f fc pp (k x) L)

theorem tcrRun_proc (f : PP → Tw → X → X) (fc : PP → Tw → Xc → X) (x0 : X) (pp : PP) :
    ∀ (P : OT (TcrProgQ Tw X Xc) X α) (R : List X) (L : Log (Tw × X) Tw),
      (resolveS x0 P R).run (tcrOracle f fc pp) L =
        let r := (tcrInterp f fc pp P L).run (tape1 x0) R
        ((r.1.1, r.2), r.1.2)
  | .done _, _, _ => rfl
  | .ask (.inl (.inl q)) k, R, L => by
    simp only [resolveS, OT.run, tcrOracle, tcrInterp]
    exact tcrRun_proc f fc x0 pp (k _) R _
  | .ask (.inl (.inr q)) k, R, L => by
    simp only [resolveS, OT.run, tcrOracle, colAnswer, tcrInterp]
    exact tcrRun_proc f fc x0 pp (k _) R _
  | .ask (.inr ()) k, R, L => by
    simp only [resolveS, OT.run, tcrInterp, tape1]
    exact tcrRun_proc f fc x0 pp (k _) R.tail L

theorem tcrInterp_bind (f : PP → Tw → X → X) (fc : PP → Tw → Xc → X) (pp : PP)
    (k : α → OT (TcrProgQ Tw X Xc) X β) :
    ∀ (P : OT (TcrProgQ Tw X Xc) X α) (L : Log (Tw × X) Tw),
      tcrInterp f fc pp (P.bind k) L = (tcrInterp f fc pp P L).bind (fun r => tcrInterp f fc pp (k r.1) r.2)
  | .done _, _ => rfl
  | .ask (.inl (.inl q)) c, L => by
    simp only [OT.bind, tcrInterp]; exact tcrInterp_bind f fc pp k (c _) _
  | .ask (.inl (.inr q)) c, L => by
    simp only [OT.bind, tcrInterp]; exact tcrInterp_bind f fc pp k (c _) _
  | .ask (.inr ()) c, L => by
    simp only [OT.bind, tcrInterp]; congr; funext x; exact tcrInterp_bind f fc pp k (c x) L
end TcrInterp

namespace WotsSetting
variable {PP Tw I M X Xc : Type} (W : WotsSetting PP Tw I M X Xc)

/-! ## The reduction -/

/-- `k` chain steps, each submitted as a target. -/
def tgtChain (a : I) (c : Nat) : X → Nat → Nat → OT (TcrProgQ Tw X Xc) X X
  | x, _, 0 => .done x
  | x, s, k+1 => .ask (.inl (.inl (W.twk a c s, x))) (fun y => tgtChain a c y (s+1) k)

def tcrElem (a : I) (c : Nat) : Nat → OT (TcrProgQ Tw X Xc) X (X × X)
  | 0 => .ask (.inr ()) (fun x => (W.tgtChain a c x 0 (W.w - 1)).bind (fun pk => .done (pk, x)))
  | e+1 => .ask (.inr ()) (fun x => .ask (.inl (.inr (W.twk a c e, W.embed x))) (fun sig =>
      (W.tgtChain a c sig (e+1) (W.w - 1 - (e+1))).bind (fun pk => .done (pk, sig))))

def tcrHandler :
    WotsState Tw I M X → WotsQuery Tw I M Xc → OT (TcrProgQ Tw X Xc) X (WotsAnswer X × WotsState Tw I M X)
  | s, .inl (a, m) => (signFrom (W.tcrElem a) 0 (W.enc m)).bind (fun r =>
      .done (.inl r, ⟨s.qs ++ [(a, m, r.1, r.2)], s.cols⟩))
  | s, .inr (tw, x) => .ask (.inl (.inr (tw, x))) (fun y => .done (.inr y, ⟨s.qs, s.cols ++ [tw]⟩))

/-- The targets of `k` steps from `x` at depth `s`. -/
def chainTgts (pp : PP) (a : I) (c : Nat) (x : X) (s k : Nat) : List (Tw × X) :=
  (List.range k).map (fun r => (W.twk a c (s + r), W.chain pp a c x s r))

theorem tcrInterp_tgtChain (pp : PP) (a : I) (c : Nat) : ∀ (k : Nat) (x : X) (s : Nat) (L : Log (Tw × X) Tw),
    tcrInterp W.f W.fc pp (W.tgtChain a c x s k) L =
      .done (W.chain pp a c x s k, ⟨L.tgt ++ W.chainTgts pp a c x s k, L.col⟩)
  | 0, _, _, L => by simp [tgtChain, tcrInterp, chain, chainTgts]
  | k+1, x, s, L => by
    simp only [tgtChain, tcrInterp]
    rw [tcrInterp_tgtChain pp a c k _ (s+1)]
    simp only [chain]
    congr 2
    simp only [chainTgts, List.range_succ_eq_map, List.map_cons, List.map_map, Nat.add_zero,
      List.append_assoc, List.singleton_append, chain]
    have hm : List.map (fun r => (W.twk a c (s + 1 + r), W.chain pp a c (W.f pp (W.twk a c s) x) (s + 1) r))
        (List.range k) =
        List.map ((fun r => (W.twk a c (s + r), W.chain pp a c x s r)) ∘ Nat.succ) (List.range k) :=
      List.map_congr_left (fun r _ => by
        simp only [Function.comp]
        rw [show s + (r + 1) = s + 1 + r by omega]
        rfl)
    rw [hm]

def tcrElemTgts (pp : PP) (a : I) (c d : Nat) (sig : X) : List (Tw × X) :=
  W.chainTgts pp a c sig d (W.w - 1 - d)

def tcrElemCols (a : I) (c d : Nat) : List Tw :=
  match d with
  | 0 => []
  | e+1 => [W.twk a c e]

theorem tcrElem_eq (pp : PP) (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x)
    (a : I) (c d : Nat) (L : Log (Tw × X) Tw) :
    tcrInterp W.f W.fc pp (W.tcrElem a c d) L =
      (W.g3Elem pp a c d).bind (fun r =>
        .done (r, ⟨L.tgt ++ W.tcrElemTgts pp a c d r.2, L.col ++ W.tcrElemCols a c d⟩)) := by
  cases d with
  | zero =>
    simp only [tcrElem, tcrInterp, g3Elem, OT.bind, tcrElemTgts, tcrElemCols, List.append_nil, Nat.sub_zero]
    congr; funext x
    rw [tcrInterp_bind, W.tcrInterp_tgtChain pp]
    rfl
  | succ e =>
    simp only [tcrElem, tcrInterp, g3Elem, OT.bind, tcrElemTgts, tcrElemCols, hc]
    congr; funext x
    rw [tcrInterp_bind, W.tcrInterp_tgtChain pp]
    rfl

def tcrSigTgts (pp : PP) (a : I) : Nat → List Nat → List X → List (Tw × X)
  | c, d :: ds, x :: xs => W.tcrElemTgts pp a c d x ++ tcrSigTgts pp a (c+1) ds xs
  | _, _, _ => []

def tcrSigCols (a : I) : Nat → List Nat → List Tw
  | _, [] => []
  | c, d :: ds => W.tcrElemCols a c d ++ tcrSigCols a (c+1) ds

theorem tcrSign_eq (pp : PP) (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x)
    (a : I) : ∀ (ds : List Nat) (c : Nat) (L : Log (Tw × X) Tw),
      tcrInterp W.f W.fc pp (signFrom (W.tcrElem a) c ds) L =
        (signFrom (W.g3Elem pp a) c ds).bind (fun r =>
          .done (r, ⟨L.tgt ++ W.tcrSigTgts pp a c ds r.2, L.col ++ W.tcrSigCols a c ds⟩))
  | [], c, L => by simp [signFrom, tcrInterp, tcrSigTgts, tcrSigCols, OT.bind]
  | d :: ds, c, L => by
    simp only [signFrom]
    rw [tcrInterp_bind, W.tcrElem_eq pp hc, OT.bind_assoc, OT.bind_assoc]
    apply OT.bind_congr; intro e
    simp only [OT.bind]
    rw [tcrInterp_bind, tcrSign_eq pp hc a ds (c+1), OT.bind_assoc, OT.bind_assoc]
    apply OT.bind_congr; intro r
    simp only [OT.bind, tcrInterp, tcrSigTgts, tcrSigCols, List.append_assoc]

def tcrLog (pp : PP) (c : Nat) (s : WotsState Tw I M X) (q : WotsQuery Tw I M Xc) (ans : WotsAnswer X)
    (L : Log (Tw × X) Tw) : Log (Tw × X) Tw :=
  match q, ans with
  | .inl (a, m), .inl (_, sig) =>
    if s.qs.length < c then ⟨L.tgt ++ W.tcrSigTgts pp a 0 (W.enc m) sig, L.col ++ W.tcrSigCols a 0 (W.enc m)⟩
    else L
  | .inr (tw, _), _ => ⟨L.tgt, L.col ++ [tw]⟩
  | .inl _, .inr _ => L

theorem capTcr_eq (pp : PP) (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x)
    (c : Nat) (s : WotsState Tw I M X) (q : WotsQuery Tw I M Xc) (L : Log (Tw × X) Tw) :
    tcrInterp W.f W.fc pp (capH c W.tcrHandler s q) L =
      (capH c (W.handler (fun pp a => W.g3Elem pp a) pp) s q).bind (fun r =>
        .done (r, W.tcrLog pp c s q r.1 L)) := by
  match q with
  | .inl (a, m) =>
    by_cases hlt : s.qs.length < c
    · simp only [capH, if_pos hlt, tcrHandler, handler]
      rw [tcrInterp_bind, W.tcrSign_eq pp hc, OT.bind_assoc, OT.bind_assoc]
      apply OT.bind_congr; intro r
      simp only [OT.bind, tcrInterp, tcrLog, if_pos hlt]
    · simp only [capH, if_neg hlt, tcrInterp, OT.bind, tcrLog]
  | .inr (tw, x) =>
    simp only [capH, tcrHandler, handler, tcrInterp, OT.bind, tcrLog]


/-! ## The challenger's log is determined by the reduction's state -/

def TInv (c : Nat) (pp : PP) (s : WotsState Tw I M X) (L : Log (Tw × X) Tw) : Prop :=
  W.Honest pp c s ∧
    L.tgt = ((s.qs.take c).map (fun e => W.tcrSigTgts pp e.1 0 (W.enc e.2.1) e.2.2.2)).flatten ∧
    ∀ tw ∈ L.col, tw ∈ s.cols ∨ ∃ e ∈ s.qs.take c, tw ∈ W.tcrSigCols e.1 0 (W.enc e.2.1)

theorem tinv_step (hlen : ∀ m, (W.enc m).length = W.len) (pp : PP) (c : Nat)
    (s : WotsState Tw I M X) (L : Log (Tw × X) Tw) (q : WotsQuery Tw I M Xc) (h : W.TInv c pp s L) :
    ((capH c (W.handler (fun pp a => W.g3Elem pp a) pp) s q).bind (fun r =>
      (.done (r.1, (r.2, W.tcrLog pp c s q r.1 L)) : OT Unit X _))).All
        (fun r => W.TInv c pp r.2.1 r.2.2) := by
  have hon := W.honest_step hlen pp c s q h.1
  obtain ⟨_, h1, h2⟩ := h
  match q with
  | .inl (a, m) =>
    by_cases hlt : s.qs.length < c
    · have hsh := W.handler_sign_shape (fun pp a => W.g3Elem pp a) pp s a m
      simp only [capH, if_pos hlt] at hon ⊢
      refine OT.all_bind _ _ _ (fun r hr => ?_) _ (OT.all_and _ _ _ hon hsh)
      obtain ⟨hH, pk, sig, hr1, hr2⟩ := hr
      show W.TInv c pp r.2 (W.tcrLog pp c s (.inl (a, m)) r.1 L)
      rw [hr1]
      simp only [tcrLog, if_pos hlt]
      rw [hr2] at hH ⊢
      have ht1 : (s.qs ++ [(a, m, pk, sig)]).take c = s.qs ++ [(a, m, pk, sig)] :=
        List.take_of_length_le (by simp; omega)
      have ht0 : s.qs.take c = s.qs := List.take_of_length_le (by omega)
      rw [ht0] at h1 h2
      refine ⟨hH, ?_, fun tw htw => ?_⟩
      · simp only [ht1, List.map_append, List.map_cons, List.map_nil, List.flatten_append,
          List.flatten_cons, List.flatten_nil, List.append_nil, h1]
      · simp only [ht1]
        rcases List.mem_append.mp htw with htw | htw
        · rcases h2 tw htw with h | ⟨e, he, h⟩
          · exact Or.inl h
          · exact Or.inr ⟨e, List.mem_append_left _ he, h⟩
        · exact Or.inr ⟨(a, m, pk, sig), List.mem_append_right _ (List.mem_singleton_self _), htw⟩
    · simp only [capH, if_neg hlt, OT.bind, OT.All] at hon ⊢
      show W.TInv c pp ⟨s.qs ++ [(a, m, [], [])], s.cols⟩ (W.tcrLog pp c s (.inl (a, m)) (.inl ([], [])) L)
      simp only [tcrLog, if_neg hlt]
      have ht : (s.qs ++ [(a, m, [], [])]).take c = s.qs.take c :=
        List.take_append_of_le_length (by omega)
      exact ⟨hon, by simp only [ht]; exact h1, by simp only [ht]; exact h2⟩
  | .inr (tw, x) =>
    simp only [capH, handler, OT.bind, OT.All] at hon ⊢
    show W.TInv c pp ⟨s.qs, s.cols ++ [tw]⟩ (W.tcrLog pp c s (.inr (tw, x)) _ L)
    simp only [tcrLog]
    refine ⟨hon, h1, fun tw' htw => ?_⟩
    rcases List.mem_append.mp htw with htw | htw
    · rcases h2 tw' htw with h | h
      · exact Or.inl (List.mem_append_left _ h)
      · exact Or.inr h
    · exact Or.inl (List.mem_append_right _ htw)

/-! ## Membership and counts -/

theorem mem_tcrSigTgts (pp : PP) {a : I} : ∀ {ds : List Nat} {c0 : Nat} {sig : List X} {p : Tw × X},
    p ∈ W.tcrSigTgts pp a c0 ds sig →
      ∃ j h, j < ds.length ∧ ds.getD j 0 ≤ h ∧ h < W.w - 1 ∧ p.1 = W.twk a (c0 + j) h
  | [], _, _, _, h => by simp [tcrSigTgts] at h
  | _ :: _, _, [], _, h => by simp [tcrSigTgts] at h
  | d :: ds, c0, x :: xs, p, h => by
    simp only [tcrSigTgts, List.mem_append] at h
    rcases h with h | h
    · simp only [tcrElemTgts, chainTgts, List.mem_map, List.mem_range] at h
      obtain ⟨r, hr, rfl⟩ := h
      exact ⟨0, d + r, by simp, by simp, by omega, by simp⟩
    · obtain ⟨j, hh, hj, h1, h2, he⟩ := mem_tcrSigTgts pp h
      exact ⟨j + 1, hh, by simp; omega, by simpa using h1, h2, by
        rw [he, show c0 + 1 + j = c0 + (j + 1) by omega]⟩

theorem mem_tcrSigCols {a : I} : ∀ {ds : List Nat} {c0 : Nat} {tw : Tw},
    tw ∈ W.tcrSigCols a c0 ds →
      ∃ j, j < ds.length ∧ 1 ≤ ds.getD j 0 ∧ tw = W.twk a (c0 + j) (ds.getD j 0 - 1)
  | [], _, _, h => by simp [tcrSigCols] at h
  | d :: ds, c0, tw, h => by
    simp only [tcrSigCols, List.mem_append] at h
    rcases h with h | h
    · cases d with
      | zero => simp [tcrElemCols] at h
      | succ e =>
        simp only [tcrElemCols, List.mem_singleton] at h
        subst h
        exact ⟨0, by simp, by simp, by simp⟩
    · obtain ⟨j, hj, hd, rfl⟩ := mem_tcrSigCols h
      exact ⟨j + 1, by simp; omega, by simpa using hd, by
        rw [show c0 + 1 + j = c0 + (j + 1) by omega]; simp⟩

theorem mem_tcrSigTgts_of (pp : PP) (x0 : X) (a : I) : ∀ (ds : List Nat) (sig : List X) (c0 j k : Nat),
    j < ds.length → j < sig.length → ds.getD j 0 ≤ k → k < W.w - 1 →
      (W.twk a (c0 + j) k, W.chain pp a (c0 + j) (sig.getD j x0) (ds.getD j 0) (k - ds.getD j 0)) ∈
        W.tcrSigTgts pp a c0 ds sig
  | [], _, _, _, _, h, _, _, _ => absurd h (by simp)
  | _ :: _, [], _, _, _, _, h, _, _ => absurd h (by simp)
  | d :: ds, x :: xs, c0, 0, k, _, _, h1, h2 => by
    simp only [tcrSigTgts, List.mem_append]
    left
    simp only [tcrElemTgts, chainTgts, List.mem_map, List.mem_range]
    refine ⟨k - d, by simp at h1 h2 ⊢; omega, ?_⟩
    simp at h1 ⊢
    rw [show d + (k - d) = k by omega]
  | d :: ds, x :: xs, c0, j+1, k, h1, h2, h3, h4 => by
    simp only [tcrSigTgts, List.mem_append]
    right
    have := mem_tcrSigTgts_of pp x0 a ds xs (c0 + 1) j k (by simp at h1; omega) (by simp at h2; omega)
      (by simpa using h3) h4
    rw [show c0 + 1 + j = c0 + (j + 1) by omega] at this
    simpa using this

theorem length_tcrSigTgts (pp : PP) (a : I) : ∀ (ds : List Nat) (sig : List X) (c0 : Nat),
    (W.tcrSigTgts pp a c0 ds sig).length ≤ ds.length * (W.w - 1)
  | [], _, _ => by simp [tcrSigTgts]
  | _ :: _, [], _ => by simp [tcrSigTgts]
  | d :: ds, x :: xs, c0 => by
    have h1 : (W.tcrElemTgts pp a c0 d x).length ≤ W.w - 1 := by
      simp only [tcrElemTgts, chainTgts, List.length_map, List.length_range]; omega
    have h2 := length_tcrSigTgts pp a ds xs (c0 + 1)
    simp only [tcrSigTgts, List.length_append, List.length_cons, Nat.succ_mul]; omega

theorem nodup_map_range {β : Type} (g : Nat → β) :
    ∀ (k : Nat), (∀ r r', r < k → r' < k → g r = g r' → r = r') → ((List.range k).map g).Nodup
  | 0, _ => by simp
  | k+1, hg => by
    rw [List.range_succ, List.map_append, List.nodup_append]
    refine ⟨nodup_map_range g k (fun r r' h1 h2 => hg r r' (by omega) (by omega)), by simp, ?_⟩
    intro x hx y hy hxy
    obtain ⟨r, hr, rfl⟩ := List.mem_map.mp hx
    simp only [List.map_cons, List.map_nil, List.mem_singleton] at hy
    subst hy
    rw [List.mem_range] at hr
    have := hg r k (by omega) (by omega) hxy
    omega

theorem nodup_tcrSigTgts (pp : PP) (a : I)
    (hinj : ∀ a a' j j' h h', j < W.len → j' < W.len → h < W.w → h' < W.w →
      W.twk a j h = W.twk a' j' h' → a = a' ∧ j = j' ∧ h = h') :
    ∀ (ds : List Nat) (sig : List X) (c0 : Nat), c0 + ds.length ≤ W.len →
      ((W.tcrSigTgts pp a c0 ds sig).map Prod.fst).Nodup
  | [], _, _, _ => by simp [tcrSigTgts]
  | _ :: _, [], _, _ => by simp [tcrSigTgts]
  | d :: ds, x :: xs, c0, hl => by
    simp only [tcrSigTgts, List.map_append]
    rw [List.nodup_append]
    refine ⟨?_, nodup_tcrSigTgts pp a hinj ds xs (c0 + 1) (by simp at hl; omega), ?_⟩
    · simp only [tcrElemTgts, chainTgts, List.map_map]
      apply nodup_map_range
      intro r r' h1 h2 he
      simp only [Function.comp] at he
      have := (hinj a a c0 c0 (d + r) (d + r') (by simp at hl; omega) (by simp at hl; omega)
        (by omega) (by omega) he).2.2
      omega
    · intro u hu v hv huv
      obtain ⟨p, hp, rfl⟩ := List.mem_map.mp hu
      obtain ⟨p', hp', rfl⟩ := List.mem_map.mp hv
      simp only [tcrElemTgts, chainTgts, List.mem_map, List.mem_range] at hp
      obtain ⟨r, hr, rfl⟩ := hp
      obtain ⟨j, hh, hj, _, h2, he⟩ := W.mem_tcrSigTgts pp hp'
      rw [he] at huv
      have := (hinj a a c0 (c0 + 1 + j) (d + r) hh (by simp at hl; omega)
        (by simp at hl; omega) (by omega) (by omega) huv).2.1
      omega


/-- When the adversary wins, the TCR-C challenger's conditions hold: at most
    `c · len · (w − 1)` targets, distinct target tweaks, none queried to the
    collection oracle. -/
theorem cond_tcr [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M]
    (c t : Nat) (pp : PP) (s : WotsState Tw I M X) (L : Log (Tw × X) Tw) (out : Nat × M × List X)
    (hlen : ∀ m, (W.enc m).length = W.len) (hdig : ∀ m, ∀ d ∈ W.enc m, d ≤ W.w - 1)
    (hinj : ∀ a a' j j' h h', j < W.len → j' < W.len → h < W.w → h' < W.w →
      W.twk a j h = W.twk a' j' h' → a = a' ∧ j = j' ∧ h = h')
    (hinst : ∀ a j h, W.inst (W.twk a j h) = a) (ht : c * (W.len * (W.w - 1)) ≤ t)
    (hI : W.TInv c pp s L) (hw : W.win c pp s out = true) :
    (decide (L.tgt.length ≤ t) && tweaksOk (L.tgt.map Prod.fst) L.col) = true := by
  obtain ⟨_, h1, h2⟩ := hI
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
    have : ((s.qs.map (fun e => W.tcrSigTgts pp e.1 0 (W.enc e.2.1) e.2.2.2)).map List.length).sum ≤
        s.qs.length * (W.len * (W.w - 1)) := by
      clear h1 h2 hnd hdisj hdisj' hc
      induction s.qs with
      | nil => simp
      | cons e es ih =>
        simp only [List.map_cons, List.sum_cons, List.length_cons, Nat.succ_mul]
        have := W.length_tcrSigTgts pp e.1 (W.enc e.2.1) e.2.2.2 0
        rw [hlen] at this; omega
    have := Nat.mul_le_mul_right (W.len * (W.w - 1)) hc
    omega
  · -- distinct targets
    rw [h1, List.map_flatten, List.map_map]
    clear h1 h2 hc hdisj hdisj'
    generalize s.qs = qs at hnd ⊢
    induction qs with
    | nil => simp
    | cons e es ih =>
      rw [List.map_cons, List.nodup_cons] at hnd
      simp only [List.map_cons, List.flatten_cons]
      rw [List.nodup_append]
      refine ⟨W.nodup_tcrSigTgts pp e.1 hinj (W.enc e.2.1) e.2.2.2 0 (by rw [hlen]; omega), ih hnd.2, ?_⟩
      intro x hx y hy hxy
      obtain ⟨p, hp, rfl⟩ := List.mem_map.mp hx
      obtain ⟨j, _, _, _, _, hpe⟩ := W.mem_tcrSigTgts pp hp
      rw [List.mem_flatten] at hy
      obtain ⟨l, hl, hyl⟩ := hy
      obtain ⟨e', he', rfl⟩ := List.mem_map.mp hl
      obtain ⟨p', hp', rfl⟩ := List.mem_map.mp hyl
      obtain ⟨j', _, _, _, _, hpe'⟩ := W.mem_tcrSigTgts pp hp'
      rw [hpe, hpe'] at hxy
      have := congrArg W.inst hxy
      rw [hinst, hinst] at this
      exact hnd.1 (List.mem_map.mpr ⟨e', he', this.symm⟩)
  · -- targets are not collection tweaks
    intro tw htw
    rw [Bool.eq_false_iff]
    intro hcol'
    have hcol := List.contains_iff_mem.mp hcol'
    rw [h1, List.map_flatten, List.map_map, List.mem_flatten] at htw
    obtain ⟨l, hl, htl⟩ := htw
    obtain ⟨e, he, rfl⟩ := List.mem_map.mp hl
    obtain ⟨p, hp, rfl⟩ := List.mem_map.mp htl
    obtain ⟨j, hh, hj, hd, hhw, hpe⟩ := W.mem_tcrSigTgts pp hp
    rw [hpe] at hcol
    rcases h2 _ hcol with hc' | ⟨e', he', hc'⟩
    · apply hdisj' _ hc'
      rw [hinst]; exact List.mem_map.mpr ⟨e, he, rfl⟩
    · obtain ⟨j', hj', hd', heq⟩ := W.mem_tcrSigCols hc'
      rw [hlen] at hj hj'
      have hdj : (W.enc e'.2.1).getD j' 0 ≤ W.w - 1 := hdig _ _ (by
        rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem (by rw [hlen]; exact hj'), Option.getD_some]
        exact List.getElem_mem _)
      obtain ⟨ha, hjj, hhi⟩ := hinj _ _ _ _ _ _ (by omega) (by omega) (by omega) (by omega) heq
      have hee : e = e' := nodup_map_eq _ _ hnd e he e' he' ha
      subst hee
      have hjj' : j = j' := by omega
      subst hjj'
      omega

/-- The reduction's answer: the honest side of the first collision above the
    forged chain, as a target index, and the forgery's side. -/
def tcrFind [DecidableEq Tw] [DecidableEq X] (x0 : X) (c : Nat) (pp : PP) (s : WotsState Tw I M X)
    (out : Nat × M × List X) : Nat × X :=
  match s.qs[out.1]? with
  | none => (0, x0)
  | some (a, m, _, sig) =>
    let j := firstLess (W.enc out.2.1) (W.enc m)
    let d := (W.enc m).getD j 0
    match W.findCol pp a j (W.forgeY x0 pp a m out) (sig.getD j x0) d (W.w - 1 - d) with
    | none => (0, x0)
    | some (k, y1, y2) =>
      ((((s.qs.take c).map (fun e => W.tcrSigTgts pp e.1 0 (W.enc e.2.1) e.2.2.2)).flatten.idxOf
          (W.twk a j k, y2)), y1)

/-- In the TCR case, the reduction finds a collision on one of its targets. -/
theorem tcr_of_ev [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M]
    (x0 : X) (c t : Nat) (pp : PP) (s : WotsState Tw I M X) (L : Log (Tw × X) Tw) (out : Nat × M × List X)
    (hlen : ∀ m, (W.enc m).length = W.len) (hdig : ∀ m, ∀ d ∈ W.enc m, d ≤ W.w - 1)
    (htwo : ∀ m m' : M, m ≠ m' → ∃ j, j < W.len ∧ (W.enc m').getD j 0 < (W.enc m).getD j 0)
    (hinj : ∀ a a' j j' h h', j < W.len → j' < W.len → h < W.w → h' < W.w →
      W.twk a j h = W.twk a' j' h' → a = a' ∧ j = j' ∧ h = h')
    (hinst : ∀ a j h, W.inst (W.twk a j h) = a) (ht : c * (W.len * (W.w - 1)) ≤ t)
    (hI : W.TInv c pp s L) (hw : W.win c pp s out = true) (he : W.tcrEv x0 pp s out = true) :
    tcrWin W.f pp t L (W.tcrFind x0 c pp s out).1 (W.tcrFind x0 c pp s out).2 = true := by
  have hcond := W.cond_tcr c t pp s L out hlen hdig hinj hinst ht hI hw
  unfold tcrEv at he
  unfold tcrFind
  cases hq : s.qs[out.1]? with
  | none => rw [hq] at he; exact absurd he (by simp)
  | some e =>
    obtain ⟨a, m, pk, sig⟩ := e
    rw [hq] at he
    simp only [Bool.not_eq_true', beq_eq_false_iff_ne, ne_eq] at he
    simp only
    obtain ⟨hmem, hc, hjl, hlt, hd, hsl, hl', hch⟩ :=
      W.forge_facts x0 c pp hlen hdig htwo s out hI.1 hw a m pk sig hq _ rfl
    generalize hj : firstLess (W.enc out.2.1) (W.enc m) = j at hjl hlt hd he hch ⊢
    obtain ⟨k, y1, y2, hfc, hk1, hk2, hne, hfeq, hy2⟩ :=
      W.findCol_spec pp a j _ _ _ _ he hch
    rw [hfc]
    simp only
    have hin := W.mem_tcrSigTgts_of pp x0 a (W.enc m) sig 0 j k (by rw [hlen]; exact hjl)
      (by rw [hsl]; exact hjl) hk1 (by omega)
    rw [Nat.zero_add, ← hy2] at hin
    have hin' : (W.twk a j k, y2) ∈
        ((s.qs.take c).map (fun e => W.tcrSigTgts pp e.1 0 (W.enc e.2.1) e.2.2.2)).flatten :=
      List.mem_flatten.mpr ⟨_, List.mem_map.mpr ⟨(a, m, pk, sig),
        by rw [List.take_of_length_le hc]; exact hmem, rfl⟩, hin⟩
    have hget := getElem?_idxOf _ _ hin'
    rw [← hI.2.1] at hget
    unfold tcrWin
    rw [← hI.2.1, hget]
    simp only [Bool.and_eq_true, beq_iff_eq, bne_iff_ne, ne_eq] at hcond ⊢
    exact ⟨⟨hcond, fun h => hne h.symm⟩, hfeq.symm⟩


/-! ## The reduction as a TCR-C adversary, and its game as a process -/

def tcrRedHandler (c : Nat) (x0 : X) (st : WotsState Tw I M X × List X) (q : WotsQuery Tw I M Xc) :
    OT ((Tw × X) ⊕ (Tw × Xc)) X (WotsAnswer X × (WotsState Tw I M X × List X)) :=
  (resolveS x0 (capH c W.tcrHandler st.1 q) st.2).bind (fun r => .done (r.1.1, (r.1.2, r.2)))

/-- `R_SMDTTCRC_Game34WOTSTWES` with own tape `R`. -/
def tcrRed [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type} (c : Nat) (x0 : X)
    (A : WotsAdv PP Tw I M X Xc σ) (R : List X) :
    TcrAdv PP Tw X Xc X (σ × (WotsState Tw I M X × List X)) :=
  ⟨OT.interp (W.tcrRedHandler c x0) A.choose (⟨[], []⟩, R),
   fun st pp => W.tcrFind x0 c pp st.2.1 (A.forge st.1 pp)⟩

def tcrProcHandler (pp : PP) (c : Nat) (st : WotsState Tw I M X × Log (Tw × X) Tw)
    (q : WotsQuery Tw I M Xc) : OT Unit X (WotsAnswer X × (WotsState Tw I M X × Log (Tw × X) Tw)) :=
  (tcrInterp W.f W.fc pp (capH c W.tcrHandler st.1 q) st.2).bind (fun r => .done (r.1.1, (r.1.2, r.2)))

def tcrProc [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (x0 : X) (c t : Nat) (pp : PP) (A : WotsAdv PP Tw I M X Xc σ) : OT Unit X Bool :=
  (OT.interp (W.tcrProcHandler pp c) A.choose (⟨[], []⟩, ⟨[], []⟩)).bind (fun r =>
    .done (tcrWin W.f pp t r.2.2 (W.tcrFind x0 c pp r.2.1 (A.forge r.1 pp)).1
      (W.tcrFind x0 c pp r.2.1 (A.forge r.1 pp)).2))

theorem tcrRed_run_proc [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (c t : Nat) (x0 : X) (pp : PP) (A : WotsAdv PP Tw I M X Xc σ) (R : List X) :
    (let B := W.tcrRed c x0 A R
     let r := B.pick.run (tcrOracle W.f W.fc pp) ⟨[], []⟩
     let ix := B.find r.1 pp
     tcrWin W.f pp t r.2 ix.1 ix.2) =
      ((W.tcrProc x0 c t pp A).run (tape1 x0) R).1 := by
  let Rel : ((WotsState Tw I M X × List X) × Log (Tw × X) Tw) →
      ((WotsState Tw I M X × Log (Tw × X) Tw) × List X) → Prop :=
    fun u v => u.1.1 = v.1.1 ∧ u.2 = v.1.2 ∧ u.1.2 = v.2
  have step := OT.run_rel
    (fun (st : (WotsState Tw I M X × List X) × Log (Tw × X) Tw) q =>
      let x := (W.tcrRedHandler c x0 st.1 q).run (tcrOracle W.f W.fc pp) st.2
      (x.1.1, (x.1.2, x.2)))
    (fun (st : (WotsState Tw I M X × Log (Tw × X) Tw) × List X) q =>
      let x := (W.tcrProcHandler pp c st.1 q).run (tape1 x0) st.2
      (x.1.1, (x.1.2, x.2))) Rel (by
      rintro ⟨⟨s1, R1⟩, L1⟩ ⟨⟨s2, L2⟩, R2⟩ q ⟨h1, h2, h3⟩
      simp only at h1 h2 h3
      subst h1 h2 h3
      have hu := tcrRun_proc W.f W.fc x0 pp (capH c W.tcrHandler s1 q) R1 L1
      simp only [tcrRedHandler, tcrProcHandler, OT.run_bind, OT.run, hu]
      refine ⟨?_, ?_, ?_, ?_⟩ <;> first | rfl | trivial) A.choose ((⟨[], []⟩, R), ⟨[], []⟩)
      ((⟨[], []⟩, ⟨[], []⟩), R) ⟨rfl, rfl, rfl⟩
  have hB := OT.run_interp (W.tcrRedHandler c x0) (tcrOracle W.f W.fc pp) A.choose (⟨[], []⟩, R) ⟨[], []⟩
  have hL := OT.run_interp (W.tcrProcHandler pp c) (tape1 x0) A.choose (⟨[], []⟩, ⟨[], []⟩) R
  obtain ⟨he, h1, h2, _⟩ := step
  simp only [tcrRed, tcrProc, OT.run_bind, OT.run]
  simp only [hB, hL]
  simp only [he, h1, h2]

theorem tcrProc_eq [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (x0 : X) (c t : Nat) (pp : PP) (A : WotsAdv PP Tw I M X Xc σ)
    (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x) :
    W.tcrProc x0 c t pp A =
      (OT.interp (fun (st : WotsState Tw I M X × Log (Tw × X) Tw) q =>
        (capH c (W.handler (fun pp a => W.g3Elem pp a) pp) st.1 q).bind (fun r =>
          (.done (r.1, (r.2, W.tcrLog pp c st.1 q r.1 st.2)) : OT Unit X _))) A.choose (⟨[], []⟩, ⟨[], []⟩)).bind
        (fun r => .done (tcrWin W.f pp t r.2.2 (W.tcrFind x0 c pp r.2.1 (A.forge r.1 pp)).1
          (W.tcrFind x0 c pp r.2.1 (A.forge r.1 pp)).2)) := by
  have hfun : W.tcrProcHandler pp c =
      (fun (st : WotsState Tw I M X × Log (Tw × X) Tw) q =>
        (capH c (W.handler (fun pp a => W.g3Elem pp a) pp) st.1 q).bind (fun r =>
          (.done (r.1, (r.2, W.tcrLog pp c st.1 q r.1 st.2)) : OT Unit X _))) := by
    funext st q
    unfold tcrProcHandler
    rw [W.capTcr_eq pp hc, OT.bind_assoc]
    rfl
  unfold tcrProc
  rw [hfun]

theorem tcrProc_of_g3 [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (x0 : X) (c t : Nat) (pp : PP) (A : WotsAdv PP Tw I M X Xc σ)
    (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x)
    (hlen : ∀ m, (W.enc m).length = W.len) (hdig : ∀ m, ∀ d ∈ W.enc m, d ≤ W.w - 1)
    (htwo : ∀ m m' : M, m ≠ m' → ∃ j, j < W.len ∧ (W.enc m').getD j 0 < (W.enc m).getD j 0)
    (hinj : ∀ a a' j j' h h', j < W.len → j' < W.len → h < W.w → h' < W.w →
      W.twk a j h = W.twk a' j' h' → a = a' ∧ j = j' ∧ h = h')
    (hinst : ∀ a j h, W.inst (W.twk a j h) = a) (ht : c * (W.len * (W.w - 1)) ≤ t) (T : List X)
    (hg : ((W.procEv (capH c (W.handler (fun pp a => W.g3Elem pp a) pp)) c pp A (W.tcrEv x0 pp)).run
      (tape1 x0) T).1 = true) :
    ((W.tcrProc x0 c t pp A).run (tape1 x0) T).1 = true := by
  rw [W.tcrProc_eq x0 c t pp A hc, OT.run_bind]
  unfold procEv at hg
  rw [OT.run_bind] at hg
  have hinv := OT.all_run (fun r => W.TInv c pp r.2.1 r.2.2) (tape1 x0)
    (OT.interp (fun (st : WotsState Tw I M X × Log (Tw × X) Tw) q =>
      (capH c (W.handler (fun pp a => W.g3Elem pp a) pp) st.1 q).bind (fun r =>
        (.done (r.1, (r.2, W.tcrLog pp c st.1 q r.1 st.2)) : OT Unit X _))) A.choose (⟨[], []⟩, ⟨[], []⟩)) T
    (OT.all_interp (fun (st : WotsState Tw I M X × Log (Tw × X) Tw) => W.TInv c pp st.1 st.2) _
      (fun st q h => W.tinv_step hlen pp c st.1 st.2 q h) A.choose _
      ⟨fun e he => by simp at he, by simp, by simp⟩)
  have step := OT.interp_run_rel
    (fun (st : WotsState Tw I M X × Log (Tw × X) Tw) q =>
      (capH c (W.handler (fun pp a => W.g3Elem pp a) pp) st.1 q).bind (fun r =>
        (.done (r.1, (r.2, W.tcrLog pp c st.1 q r.1 st.2)) : OT Unit X _))) (tape1 x0)
    (capH c (W.handler (fun pp a => W.g3Elem pp a) pp)) (tape1 x0)
    (fun u v => u.1.1 = v.1 ∧ u.2 = v.2) (by
      rintro ⟨s1, L1⟩ T1 s2 T2 q ⟨h1, h2⟩
      simp only at h1 h2
      subst h1 h2
      simp only [OT.run_bind, OT.run]
      refine ⟨?_, ?_, ?_⟩ <;> first | rfl | trivial) A.choose (⟨[], []⟩, ⟨[], []⟩) T ⟨[], []⟩ T ⟨rfl, rfl⟩
  obtain ⟨he, h1, _⟩ := step
  simp only at h1 hinv
  simp only [OT.run] at hg ⊢
  rw [he, h1]
  rw [h1] at hinv
  simp only [Bool.and_eq_true] at hg
  exact W.tcr_of_ev x0 c t pp _ _ _ hlen hdig htwo hinj hinst ht hinv hg.1 hg.2

/-! ## Counting: the TCR case of Game 3 is at most the reduction's TCR-C wins -/

def tcrCoins [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type} (c : Nat) (x0 : X)
    (Din : FiniteExperiment X) (As : FiniteExperiment (WotsAdv PP Tw I M X Xc σ)) :
    FiniteExperiment (TcrAdv PP Tw X Xc X (σ × (WotsState Tw I M X × List X))) :=
  (independentProduct (Din.tape (c * W.len)) As).map (fun p => W.tcrRed c x0 p.2 p.1)

/-- `#(Game 3 won in the TCR case) ≤ #TCR-C(B_tcr)`, on the same tickets. -/
theorem tcr_num [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (x0 : X) (c t : Nat) (P : FiniteExperiment PP) (Din : FiniteExperiment X)
    (As : FiniteExperiment (WotsAdv PP Tw I M X Xc σ))
    (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x)
    (hlen : ∀ m, (W.enc m).length = W.len) (hdig : ∀ m, ∀ d ∈ W.enc m, d ≤ W.w - 1)
    (htwo : ∀ m m' : M, m ≠ m' → ∃ j, j < W.len ∧ (W.enc m').getD j 0 < (W.enc m).getD j 0)
    (hinj : ∀ a a' j j' h h', j < W.len → j' < W.len → h < W.w → h' < W.w →
      W.twk a j h = W.twk a' j' h' → a = a' ∧ j = j' ∧ h = h')
    (hinst : ∀ a j h, W.inst (W.twk a j h) = a) (ht : c * (W.len * (W.w - 1)) ≤ t) :
    W.g3EvCount x0 c P Din As (W.tcrEv x0) ≤ (tcrProb P W.f W.fc t (W.tcrCoins c x0 Din As)).numerator := by
  have stepA : (tcrProb P W.f W.fc t (W.tcrCoins c x0 Din As)).numerator =
      P.sum (fun pp => (Din.tape (c * W.len)).sum (fun R => As.sum (fun A =>
        if ((W.tcrProc x0 c t pp A).run (tape1 x0) R).1 then 1 else 0))) := by
    unfold tcrProb tcrCoins
    rw [numerator_sum, product_sum]
    apply sum_congr; intro i1
    rw [sum_map_product]
    apply sum_congr; intro i2
    apply sum_congr; intro i3
    apply ind_of_eq
    exact W.tcrRed_run_proc c t x0 _ _ _
  rw [stepA]
  simp only [sum_comm (Din.tape (c * W.len)) As]
  unfold g3EvCount
  apply sum_le; intro i
  apply sum_le; intro j
  apply sum_le; intro k
  split
  · rename_i hg
    rw [if_pos (W.tcrProc_of_g3 x0 c t _ _ hc hlen hdig htwo hinj hinst ht _ hg)]
    exact Nat.le_refl _
  · exact Nat.zero_le _

theorem tcr_den [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (x0 : X) (c t : Nat) (P : FiniteExperiment PP) (Din : FiniteExperiment X)
    (As : FiniteExperiment (WotsAdv PP Tw I M X Xc σ)) :
    (tcrProb P W.f W.fc t (W.tcrCoins c x0 Din As)).denominator = (W.hybProb x0 c P Din As 0).denominator := by
  show P.cardinality * ((Din.tape (c * W.len)).cardinality * As.cardinality) = _
  simp only [hybProb]
  ac_rfl

/-! ## Resources of the reduction -/

theorem tgtChain_withinI (a : I) (c : Nat) :
    ∀ (k : Nat) (x : X) (s n : Nat), k ≤ n →
      WithinI (fun _ m => n ≤ m + k) (W.tgtChain a c x s k) n
  | 0, _, _, n, _ => by simp [tgtChain, WithinI]
  | k+1, x, s, n, hk => by
    cases n with
    | zero => omega
    | succ n =>
      simp only [tgtChain, WithinI]
      intro y
      exact withinI_mono _ _ (fun _ m h => by omega) _ _ (tgtChain_withinI a c k y (s+1) n (by omega))

theorem tcrElem_withinI (a : I) (c d : Nat) (hd : d ≤ W.w - 1) (n : Nat) (hn : W.w - 1 ≤ n) :
    WithinI (fun _ m => n ≤ m + (W.w - 1)) (W.tcrElem a c d) n := by
  cases d with
  | zero =>
    simp only [tcrElem, WithinI]
    intro x
    exact withinI_bind _ _ _ (fun _ m h => by simp only [WithinI]; exact h) _ n
      (W.tgtChain_withinI a c (W.w - 1) x 0 n hn)
  | succ e =>
    cases n with
    | zero => omega
    | succ n =>
      simp only [tcrElem, WithinI]
      intro x y
      exact withinI_bind _ _ _ (fun _ m h => by simp only [WithinI]; omega) _ n
        (W.tgtChain_withinI a c (W.w - 1 - (e+1)) y (e+1) n (by omega))

theorem signTcr_withinI (a : I) :
    ∀ (ds : List Nat) (c n : Nat), (∀ d ∈ ds, d ≤ W.w - 1) → ds.length * (W.w - 1) ≤ n →
      WithinI (fun _ m => n ≤ m + ds.length * (W.w - 1)) (signFrom (W.tcrElem a) c ds) n
  | [], _, n, _, _ => by simp [signFrom, WithinI]
  | d :: ds, c, n, hd, hn => by
    simp only [List.length_cons, Nat.succ_mul] at hn ⊢
    simp only [signFrom]
    refine withinI_bind _ _ _ (fun e m hm => ?_) _ n
      (W.tcrElem_withinI a c d (hd d (List.mem_cons_self ..)) n (by omega))
    refine withinI_bind _ _ _ (fun r m' hm' => ?_) _ m
      (signTcr_withinI a ds (c+1) m (fun d h => hd d (List.mem_cons_of_mem _ h)) (by omega))
    simp only [WithinI]
    omega

/-- **Query budget of the TCR reduction.** At most `q · len · (w − 1)` TCR-C
    queries (targets and collection) for an adversary of `q` first-phase
    queries; at most `c · len · (w − 1)` targets on winning runs
    (`cond_tcr`); own coins: `c · len` values. -/
theorem tcrRed_queries [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (hlen : ∀ m, (W.enc m).length = W.len) (hdig : ∀ m, ∀ d ∈ W.enc m, d ≤ W.w - 1)
    (hK : 1 ≤ W.len * (W.w - 1)) (c : Nat) (x0 : X) (A : WotsAdv PP Tw I M X Xc σ) (R : List X)
    (q : Nat) (hA : A.choose.Within q) :
    (W.tcrRed c x0 A R).pick.Within (q * (W.len * (W.w - 1))) := by
  apply OT.withinP_within (fun _ _ => True)
  refine OT.within_interp_mul _ (W.len * (W.w - 1)) (fun st qq n hn => ?_) A.choose q _ _ hA (Nat.le_refl _)
  have hI : WithinI (fun _ m => n ≤ m + W.len * (W.w - 1)) (capH c W.tcrHandler st.1 qq) n := by
    match qq with
    | .inl (a, msg) =>
      by_cases hlt : st.1.qs.length < c
      · simp only [capH, if_pos hlt, tcrHandler]
        have h := W.signTcr_withinI a (W.enc msg) 0 n (hdig msg) (by rw [hlen]; exact hn)
        rw [hlen] at h
        exact withinI_bind _ _ _ (fun _ m hm => by simp only [WithinI]; exact hm) _ n h
      · simp only [capH, if_neg hlt, WithinI]
        omega
    | .inr (tw, x) =>
      cases n with
      | zero => omega
      | succ n =>
        simp only [capH, tcrHandler, WithinI]
        intro _
        omega
  unfold tcrRedHandler
  exact OT.withinP_bind _ _ _ (fun _ m hm => by simp only [OT.WithinP]; exact hm) _ n
    (withinI_resolve x0 _ _ st.2 n hI)

end WotsSetting

#print axioms WotsSetting.cond_tcr
#print axioms WotsSetting.tcr_of_ev
#print axioms WotsSetting.tcrRed_run_proc
#print axioms WotsSetting.tcr_num
#print axioms WotsSetting.tcrRed_queries
end DSM.Sphincs.Comp
