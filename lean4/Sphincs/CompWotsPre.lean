-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.CompWotsG3

/- Modular proof, milestone 3, obligation 8 (part 4): the SM-DT-PRE-C step
   of WOTS-TW (EasyCrypt `R_SMDTPREC_Game4WOTSTWES`).

   The reduction plays Game 3 for the adversary. For every chain with digit
   `d = e + 1` it submits the tweak at depth `e` as a PRE-C target and uses
   the challenge `y = F(x)` (x uniform, unknown to it) as the signature
   element; it finishes the chain with the collection oracle. For digit 0 it
   draws the element itself. When the forgery climbs onto a signed value
   (`preEv`), the value one step below is a preimage of that target.
   No assumption, axiom or `sorry`. -/
namespace DSM.Sphincs.Comp
open DSM.Sphincs DSM.Sphincs.Security

section PreInterp
variable {PP Tw Xc X α β : Type}

/-- The PRE-C challenger as a labelled process: a target draws from the
    challenger's tape (`true`), answers `f(x)` and logs `(tw, f(x))`; a
    collection query answers `fc`; an own draw reads the reduction's tape
    (`false`). -/
def preInterp (f : PP → Tw → X → X) (fc : PP → Tw → Xc → X) (pp : PP) :
    OT (UdProgQ Tw Xc) X α → Log (Tw × X) Tw → OT Bool X (α × Log (Tw × X) Tw)
  | .done a, L => .done (a, L)
  | .ask (.inl (.inl tw)) k, L => .ask true (fun x =>
      preInterp f fc pp (k (f pp tw x)) ⟨L.tgt ++ [(tw, f pp tw x)], L.col⟩)
  | .ask (.inl (.inr q)) k, L => preInterp f fc pp (k (fc pp q.1 q.2)) ⟨L.tgt, L.col ++ [q.1]⟩
  | .ask (.inr ()) k, L => .ask false (fun x => preInterp f fc pp (k x) L)

theorem preRun_proc (f : PP → Tw → X → X) (fc : PP → Tw → Xc → X) (x0 : X) (pp : PP)
    (T : List X) : ∀ (P : OT (UdProgQ Tw Xc) X α) (R : List X) (L : Log (Tw × X) Tw),
      (resolveS x0 P R).run (preOracle f fc x0 pp T) L =
        let r := (preInterp f fc pp P L).run (tape2 x0) (T.drop L.tgt.length, R)
        ((r.1.1, r.2.2), r.1.2)
  | .done _, _, _ => rfl
  | .ask (.inl (.inl tw)) k, R, L => by
    simp only [resolveS, OT.run, preOracle, preInterp, tape2]
    rw [preRun_proc f fc x0 pp T (k _) R ⟨L.tgt ++ [_], L.col⟩]
    simp only [List.length_append, List.length_singleton, drop_headD, List.tail_drop]
  | .ask (.inl (.inr q)) k, R, L => by
    simp only [resolveS, OT.run, preOracle, colAnswer, preInterp]
    exact preRun_proc f fc x0 pp T (k _) R _
  | .ask (.inr ()) k, R, L => by
    simp only [resolveS, OT.run, preInterp, tape2]
    exact preRun_proc f fc x0 pp T (k _) R.tail L

theorem preInterp_tape (f : PP → Tw → X → X) (fc : PP → Tw → Xc → X) (x0 : X) (pp : PP)
    (T : List X) : ∀ (P : OT (UdProgQ Tw Xc) X α) (R : List X) (L : Log (Tw × X) Tw),
      ((preInterp f fc pp P L).run (tape2 x0) (T.drop L.tgt.length, R)).2.1 =
        T.drop ((preInterp f fc pp P L).run (tape2 x0) (T.drop L.tgt.length, R)).1.2.tgt.length
  | .done _, _, _ => rfl
  | .ask (.inl (.inl tw)) k, R, L => by
    simp only [preInterp, OT.run, tape2, List.tail_drop]
    have := preInterp_tape f fc x0 pp T (k (f pp tw ((T.drop L.tgt.length).headD x0))) R
      ⟨L.tgt ++ [(tw, f pp tw ((T.drop L.tgt.length).headD x0))], L.col⟩
    simp only [List.length_append, List.length_singleton] at this
    exact this
  | .ask (.inl (.inr q)) k, R, L => by
    simp only [preInterp]; exact preInterp_tape f fc x0 pp T (k _) R _
  | .ask (.inr ()) k, R, L => by
    simp only [preInterp, OT.run, tape2]; exact preInterp_tape f fc x0 pp T (k _) R.tail L

theorem preInterp_bind (f : PP → Tw → X → X) (fc : PP → Tw → Xc → X) (pp : PP)
    (k : α → OT (UdProgQ Tw Xc) X β) :
    ∀ (P : OT (UdProgQ Tw Xc) X α) (L : Log (Tw × X) Tw),
      preInterp f fc pp (P.bind k) L = (preInterp f fc pp P L).bind (fun r => preInterp f fc pp (k r.1) r.2)
  | .done _, _ => rfl
  | .ask (.inl (.inl tw)) c, L => by
    simp only [OT.bind, preInterp]; congr; funext x; exact preInterp_bind f fc pp k (c _) _
  | .ask (.inl (.inr q)) c, L => by
    simp only [OT.bind, preInterp]; exact preInterp_bind f fc pp k (c _) _
  | .ask (.inr ()) c, L => by
    simp only [OT.bind, preInterp]; congr; funext x; exact preInterp_bind f fc pp k (c x) L
end PreInterp

namespace WotsSetting
variable {PP Tw I M X Xc : Type} (W : WotsSetting PP Tw I M X Xc)

/-! ## The reduction -/

/-- Chain `c` of instance `a` for digit `d`. -/
def preElem (a : I) (c : Nat) : Nat → OT (UdProgQ Tw Xc) X (X × X)
  | 0 => .ask (.inr ()) (fun x => (W.colChain a c x 0 (W.w - 1)).bind (fun pk => .done (pk, x)))
  | e+1 => .ask (.inl (.inl (W.twk a c e))) (fun y =>
      (W.colChain a c y (e+1) (W.w - 1 - (e+1))).bind (fun pk => .done (pk, y)))

def preHandler :
    WotsState Tw I M X → WotsQuery Tw I M Xc → OT (UdProgQ Tw Xc) X (WotsAnswer X × WotsState Tw I M X)
  | s, .inl (a, m) => (signFrom (W.preElem a) 0 (W.enc m)).bind (fun r =>
      .done (.inl r, ⟨s.qs ++ [(a, m, r.1, r.2)], s.cols⟩))
  | s, .inr (tw, x) => .ask (.inl (.inr (tw, x))) (fun y => .done (.inr y, ⟨s.qs, s.cols ++ [tw]⟩))

theorem preInterp_colChain (pp : PP) (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x)
    (a : I) (c : Nat) : ∀ (k : Nat) (x : X) (s : Nat) (L : Log (Tw × X) Tw),
      preInterp W.f W.fc pp (W.colChain a c x s k) L =
        .done (W.chain pp a c x s k, ⟨L.tgt, L.col ++ W.colTweaks a c s k⟩)
  | 0, _, _, L => by simp [colChain, preInterp, chain, colTweaks]
  | k+1, x, s, L => by
    simp only [colChain, preInterp, hc]
    rw [preInterp_colChain pp hc a c k _ (s+1)]
    simp only [chain]
    congr 2
    simp only [colTweaks, List.range_succ_eq_map, List.map_cons, List.map_map, Nat.add_zero,
      List.append_assoc, List.singleton_append]
    have hm : List.map (fun j => W.twk a c (s + 1 + j)) (List.range k) =
        List.map ((fun j => W.twk a c (s + j)) ∘ Nat.succ) (List.range k) :=
      List.map_congr_left (fun j _ => by simp only [Function.comp]; congr 1; omega)
    rw [hm]

/-- The challenger's log entries of one chain: the target and its answer. -/
def preElemTgts (a : I) (c d : Nat) (sig : X) : List (Tw × X) :=
  match d with
  | 0 => []
  | e+1 => [(W.twk a c e, sig)]

def preElemCols (a : I) (c d : Nat) : List Tw := W.colTweaks a c d (W.w - 1 - d)

theorem preElem_eq (pp : PP) (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x)
    (a : I) (c d : Nat) (L : Log (Tw × X) Tw) :
    unlabel (preInterp W.f W.fc pp (W.preElem a c d) L) =
      (W.g3Elem pp a c d).bind (fun r =>
        .done (r, ⟨L.tgt ++ W.preElemTgts a c d r.2, L.col ++ W.preElemCols a c d⟩)) := by
  cases d with
  | zero =>
    simp only [preElem, preInterp, unlabel, g3Elem, OT.bind, preElemTgts, preElemCols, List.append_nil,
      Nat.sub_zero]
    congr; funext x
    rw [preInterp_bind, W.preInterp_colChain pp hc]
    rfl
  | succ e =>
    simp only [preElem, preInterp, unlabel, g3Elem, OT.bind, preElemTgts, preElemCols]
    congr; funext x
    rw [preInterp_bind, W.preInterp_colChain pp hc]
    rfl

/-- The challenger's log entries of one signature. -/
def preSigTgts (a : I) : Nat → List Nat → List X → List (Tw × X)
  | c, d :: ds, x :: xs => W.preElemTgts a c d x ++ preSigTgts a (c+1) ds xs
  | _, _, _ => []

def preSigCols (a : I) : Nat → List Nat → List Tw
  | _, [] => []
  | c, d :: ds => W.preElemCols a c d ++ preSigCols a (c+1) ds

theorem preSign_eq (pp : PP) (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x)
    (a : I) : ∀ (ds : List Nat) (c : Nat) (L : Log (Tw × X) Tw),
      unlabel (preInterp W.f W.fc pp (signFrom (W.preElem a) c ds) L) =
        (signFrom (W.g3Elem pp a) c ds).bind (fun r =>
          .done (r, ⟨L.tgt ++ W.preSigTgts a c ds r.2, L.col ++ W.preSigCols a c ds⟩))
  | [], c, L => by simp [signFrom, preInterp, unlabel, preSigTgts, preSigCols, OT.bind]
  | d :: ds, c, L => by
    simp only [signFrom]
    rw [preInterp_bind, unlabel_bind, W.preElem_eq pp hc, OT.bind_assoc, OT.bind_assoc]
    apply OT.bind_congr; intro e
    simp only [OT.bind]
    rw [preInterp_bind, unlabel_bind, preSign_eq pp hc a ds (c+1), OT.bind_assoc, OT.bind_assoc]
    apply OT.bind_congr; intro r
    simp only [OT.bind, preInterp, unlabel, preSigTgts, preSigCols, List.append_assoc]

/-- The challenger's log after one query to the capped reduction. -/
def preLog (c : Nat) (s : WotsState Tw I M X) (q : WotsQuery Tw I M Xc) (ans : WotsAnswer X)
    (L : Log (Tw × X) Tw) : Log (Tw × X) Tw :=
  match q, ans with
  | .inl (a, m), .inl (_, sig) =>
    if s.qs.length < c then ⟨L.tgt ++ W.preSigTgts a 0 (W.enc m) sig, L.col ++ W.preSigCols a 0 (W.enc m)⟩
    else L
  | .inr (tw, _), _ => ⟨L.tgt, L.col ++ [tw]⟩
  | .inl _, .inr _ => L

theorem capPre_eq (pp : PP) (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x)
    (c : Nat) (s : WotsState Tw I M X) (q : WotsQuery Tw I M Xc) (L : Log (Tw × X) Tw) :
    unlabel (preInterp W.f W.fc pp (capH c W.preHandler s q) L) =
      (capH c (W.handler (fun pp a => W.g3Elem pp a) pp) s q).bind (fun r =>
        .done (r, W.preLog c s q r.1 L)) := by
  match q with
  | .inl (a, m) =>
    by_cases hlt : s.qs.length < c
    · simp only [capH, if_pos hlt, preHandler, handler]
      rw [preInterp_bind, unlabel_bind, W.preSign_eq pp hc, OT.bind_assoc, OT.bind_assoc]
      apply OT.bind_congr; intro r
      simp only [OT.bind, preInterp, unlabel, preLog, if_pos hlt]
    · simp only [capH, if_neg hlt, preInterp, unlabel, OT.bind, preLog]
  | .inr (tw, x) =>
    simp only [capH, preHandler, handler, preInterp, unlabel, OT.bind, preLog]

/-! ## The challenger's log is determined by the reduction's state -/

/-- Game 3's entries are honest; the PRE-C log lists, entry by entry, each
    chain's target and its answer (the signature element); collection tweaks
    are the adversary's or the reduction's. -/
def PInv (c : Nat) (pp : PP) (s : WotsState Tw I M X) (L : Log (Tw × X) Tw) : Prop :=
  W.Honest pp c s ∧
    L.tgt = ((s.qs.take c).map (fun e => W.preSigTgts e.1 0 (W.enc e.2.1) e.2.2.2)).flatten ∧
    ∀ tw ∈ L.col, tw ∈ s.cols ∨ ∃ e ∈ s.qs.take c, tw ∈ W.preSigCols e.1 0 (W.enc e.2.1)

theorem pinv_step (hlen : ∀ m, (W.enc m).length = W.len) (pp : PP) (c : Nat)
    (s : WotsState Tw I M X) (L : Log (Tw × X) Tw) (q : WotsQuery Tw I M Xc) (h : W.PInv c pp s L) :
    ((capH c (W.handler (fun pp a => W.g3Elem pp a) pp) s q).bind (fun r =>
      (.done (r.1, (r.2, W.preLog c s q r.1 L)) : OT Unit X _))).All
        (fun r => W.PInv c pp r.2.1 r.2.2) := by
  have hon := W.honest_step hlen pp c s q h.1
  obtain ⟨_, h1, h2⟩ := h
  match q with
  | .inl (a, m) =>
    by_cases hlt : s.qs.length < c
    · have hsh := W.handler_sign_shape (fun pp a => W.g3Elem pp a) pp s a m
      simp only [capH, if_pos hlt] at hon ⊢
      refine OT.all_bind _ _ _ (fun r hr => ?_) _ (OT.all_and _ _ _ hon hsh)
      obtain ⟨hH, pk, sig, hr1, hr2⟩ := hr
      show W.PInv c pp r.2 (W.preLog c s (.inl (a, m)) r.1 L)
      rw [hr1]
      simp only [preLog, if_pos hlt]
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
      show W.PInv c pp ⟨s.qs ++ [(a, m, [], [])], s.cols⟩ (W.preLog c s (.inl (a, m)) (.inl ([], [])) L)
      simp only [preLog, if_neg hlt]
      have ht : (s.qs ++ [(a, m, [], [])]).take c = s.qs.take c :=
        List.take_append_of_le_length (by omega)
      exact ⟨hon, by simp only [ht]; exact h1, by simp only [ht]; exact h2⟩
  | .inr (tw, x) =>
    simp only [capH, handler, OT.bind, OT.All] at hon ⊢
    show W.PInv c pp ⟨s.qs, s.cols ++ [tw]⟩ (W.preLog c s (.inr (tw, x)) _ L)
    simp only [preLog]
    refine ⟨hon, h1, fun tw' htw => ?_⟩
    rcases List.mem_append.mp htw with htw | htw
    · rcases h2 tw' htw with h | h
      · exact Or.inl (List.mem_append_left _ h)
      · exact Or.inr h
    · exact Or.inl (List.mem_append_right _ htw)

/-! ## Membership and counts -/

theorem mem_preSigTgts {a : I} : ∀ {ds : List Nat} {c0 : Nat} {sig : List X} {p : Tw × X},
    p ∈ W.preSigTgts a c0 ds sig →
      ∃ j, j < ds.length ∧ 1 ≤ ds.getD j 0 ∧ p.1 = W.twk a (c0 + j) (ds.getD j 0 - 1)
  | [], _, _, _, h => by simp [preSigTgts] at h
  | _ :: _, _, [], _, h => by simp [preSigTgts] at h
  | d :: ds, c0, x :: xs, p, h => by
    simp only [preSigTgts, List.mem_append] at h
    rcases h with h | h
    · cases d with
      | zero => simp [preElemTgts] at h
      | succ e =>
        simp only [preElemTgts, List.mem_singleton] at h
        subst h
        exact ⟨0, by simp, by simp, by simp⟩
    · obtain ⟨j, hj, hd, he⟩ := mem_preSigTgts h
      exact ⟨j + 1, by simp; omega, by simpa using hd, by
        rw [he, show c0 + 1 + j = c0 + (j + 1) by omega]; simp⟩

theorem mem_preSigCols {a : I} : ∀ {ds : List Nat} {c0 : Nat} {tw : Tw},
    tw ∈ W.preSigCols a c0 ds →
      ∃ j h, j < ds.length ∧ ds.getD j 0 ≤ h ∧ h < W.w - 1 ∧ tw = W.twk a (c0 + j) h
  | [], _, _, h => by simp [preSigCols] at h
  | d :: ds, c0, tw, h => by
    simp only [preSigCols, List.mem_append] at h
    rcases h with h | h
    · obtain ⟨j', hj', rfl⟩ := W.mem_colTweaks h
      exact ⟨0, d + j', by simp, by simp, by omega, by simp⟩
    · obtain ⟨j, hh, hj, h1, h2, rfl⟩ := mem_preSigCols h
      exact ⟨j + 1, hh, by simp; omega, by simpa using h1, h2,
        by rw [show c0 + 1 + j = c0 + (j + 1) by omega]⟩

theorem mem_preSigTgts_of (x0 : X) (a : I) : ∀ (ds : List Nat) (sig : List X) (c0 j : Nat),
    j < ds.length → j < sig.length → 1 ≤ ds.getD j 0 →
      (W.twk a (c0 + j) (ds.getD j 0 - 1), sig.getD j x0) ∈ W.preSigTgts a c0 ds sig
  | [], _, _, _, h, _, _ => absurd h (by simp)
  | _ :: _, [], _, _, _, h, _ => absurd h (by simp)
  | d :: ds, x :: xs, c0, 0, _, _, hd => by
    cases d with
    | zero => simp at hd
    | succ e => simp [preSigTgts, preElemTgts]
  | d :: ds, x :: xs, c0, j+1, h1, h2, hd => by
    simp only [preSigTgts, List.mem_append]
    right
    have := mem_preSigTgts_of x0 a ds xs (c0 + 1) j (by simp at h1; omega) (by simp at h2; omega)
      (by simpa using hd)
    rw [show c0 + 1 + j = c0 + (j + 1) by omega] at this
    simpa using this

theorem length_preSigTgts (a : I) : ∀ (ds : List Nat) (sig : List X) (c0 : Nat),
    (W.preSigTgts a c0 ds sig).length ≤ ds.length
  | [], _, _ => by simp [preSigTgts]
  | _ :: _, [], _ => by simp [preSigTgts]
  | d :: ds, x :: xs, c0 => by
    have h1 : (W.preElemTgts a c0 d x).length ≤ 1 := by
      cases d with
      | zero => simp [preElemTgts]
      | succ e => simp [preElemTgts]
    have h2 := length_preSigTgts a ds xs (c0 + 1)
    simp only [preSigTgts, List.length_append, List.length_cons]; omega

theorem nodup_preSigTgts (a : I)
    (hinj : ∀ a a' j j' h h', j < W.len → j' < W.len → h < W.w → h' < W.w →
      W.twk a j h = W.twk a' j' h' → a = a' ∧ j = j' ∧ h = h') :
    ∀ (ds : List Nat) (sig : List X) (c0 : Nat), c0 + ds.length ≤ W.len → (∀ d ∈ ds, d ≤ W.w - 1) →
      ((W.preSigTgts a c0 ds sig).map Prod.fst).Nodup
  | [], _, _, _, _ => by simp [preSigTgts]
  | _ :: _, [], _, _, _ => by simp [preSigTgts]
  | d :: ds, x :: xs, c0, hl, hb => by
    simp only [preSigTgts, List.map_append]
    rw [List.nodup_append]
    refine ⟨?_, nodup_preSigTgts a hinj ds xs (c0 + 1) (by simp at hl; omega)
      (fun d h => hb d (List.mem_cons_of_mem _ h)), ?_⟩
    · cases d with
      | zero => simp [preElemTgts]
      | succ e => simp [preElemTgts]
    · intro u hu v hv huv
      obtain ⟨p, hp, rfl⟩ := List.mem_map.mp hu
      obtain ⟨p', hp', rfl⟩ := List.mem_map.mp hv
      have hd0 := hb d (List.mem_cons_self ..)
      cases d with
      | zero => simp [preElemTgts] at hp
      | succ e =>
        simp only [preElemTgts, List.mem_singleton] at hp
        subst hp
        obtain ⟨j, hj, hd, he⟩ := W.mem_preSigTgts hp'
        have hdj : ds.getD j 0 ≤ W.w - 1 := hb _ (List.mem_cons_of_mem _ (by
          rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hj, Option.getD_some]
          exact List.getElem_mem _))
        rw [he] at huv
        have := (hinj a a c0 (c0 + 1 + j) e (ds.getD j 0 - 1) (by simp at hl; omega)
          (by simp at hl; omega) (by omega) (by omega) huv).2.1
        omega



/-- When the adversary wins, the PRE-C challenger's conditions hold: at most
    `c · len` targets, distinct target tweaks, none queried to the
    collection oracle. -/
theorem cond_pre [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M]
    (c t : Nat) (pp : PP) (s : WotsState Tw I M X) (L : Log (Tw × X) Tw) (out : Nat × M × List X)
    (hlen : ∀ m, (W.enc m).length = W.len) (hdig : ∀ m, ∀ d ∈ W.enc m, d ≤ W.w - 1)
    (hinj : ∀ a a' j j' h h', j < W.len → j' < W.len → h < W.w → h' < W.w →
      W.twk a j h = W.twk a' j' h' → a = a' ∧ j = j' ∧ h = h')
    (hinst : ∀ a j h, W.inst (W.twk a j h) = a) (ht : c * W.len ≤ t)
    (hI : W.PInv c pp s L) (hw : W.win c pp s out = true) :
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
    have : ((s.qs.map (fun e => W.preSigTgts e.1 0 (W.enc e.2.1) e.2.2.2)).map List.length).sum ≤
        s.qs.length * W.len := by
      clear h1 h2 hnd hdisj hdisj' hc
      induction s.qs with
      | nil => simp
      | cons e es ih =>
        simp only [List.map_cons, List.sum_cons, List.length_cons, Nat.succ_mul]
        have := W.length_preSigTgts e.1 (W.enc e.2.1) e.2.2.2 0
        rw [hlen] at this; omega
    have := Nat.mul_le_mul_right W.len hc
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
      refine ⟨W.nodup_preSigTgts e.1 hinj (W.enc e.2.1) e.2.2.2 0 (by rw [hlen]; omega) (hdig _),
        ih hnd.2, ?_⟩
      intro x hx y hy hxy
      obtain ⟨p, hp, rfl⟩ := List.mem_map.mp hx
      obtain ⟨j, _, _, hpe⟩ := W.mem_preSigTgts hp
      rw [List.mem_flatten] at hy
      obtain ⟨l, hl, hyl⟩ := hy
      obtain ⟨e', he', rfl⟩ := List.mem_map.mp hl
      obtain ⟨p', hp', rfl⟩ := List.mem_map.mp hyl
      obtain ⟨j', _, _, hpe'⟩ := W.mem_preSigTgts hp'
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
    obtain ⟨j, hj, hd, hpe⟩ := W.mem_preSigTgts hp
    rw [hpe] at hcol
    rcases h2 _ hcol with hc' | ⟨e', he', hc'⟩
    · apply hdisj' _ hc'
      rw [hinst]; exact List.mem_map.mpr ⟨e, he, rfl⟩
    · obtain ⟨j', hh, hj', hh1, hh2, heq⟩ := W.mem_preSigCols hc'
      rw [hlen] at hj hj'
      have hdj : (W.enc e.2.1).getD j 0 ≤ W.w - 1 := hdig _ _ (by
        rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem (by rw [hlen]; exact hj), Option.getD_some]
        exact List.getElem_mem _)
      obtain ⟨ha, hjj, hhi⟩ := hinj _ _ _ _ _ _ (by omega) (by omega) (by omega) (by omega) heq
      have hee : e = e' := nodup_map_eq _ _ hnd e he e' he' ha
      subst hee
      have hjj' : j = j' := by omega
      subst hjj'
      omega

/-- The reduction's answer: the target of the forged chain and the value one
    step below the signed element. -/
def preFind (x0 : X) (c : Nat) (pp : PP) (s : WotsState Tw I M X) (out : Nat × M × List X) [DecidableEq Tw]
    [DecidableEq X] : Nat × X :=
  match s.qs[out.1]? with
  | none => (0, x0)
  | some (a, m, _, sig) =>
    let j := firstLess (W.enc out.2.1) (W.enc m)
    let d' := (W.enc out.2.1).getD j 0
    let d := (W.enc m).getD j 0
    ((((s.qs.take c).map (fun e => W.preSigTgts e.1 0 (W.enc e.2.1) e.2.2.2)).flatten.idxOf
        (W.twk a j (d - 1), sig.getD j x0)),
      W.chain pp a j (out.2.2.getD j x0) d' (d - 1 - d'))

/-- In the PRE case, the reduction inverts its target. -/
theorem pre_of_ev [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M]
    (x0 : X) (c t : Nat) (pp : PP) (s : WotsState Tw I M X) (L : Log (Tw × X) Tw) (out : Nat × M × List X)
    (hlen : ∀ m, (W.enc m).length = W.len) (hdig : ∀ m, ∀ d ∈ W.enc m, d ≤ W.w - 1)
    (htwo : ∀ m m' : M, m ≠ m' → ∃ j, j < W.len ∧ (W.enc m').getD j 0 < (W.enc m).getD j 0)
    (hinj : ∀ a a' j j' h h', j < W.len → j' < W.len → h < W.w → h' < W.w →
      W.twk a j h = W.twk a' j' h' → a = a' ∧ j = j' ∧ h = h')
    (hinst : ∀ a j h, W.inst (W.twk a j h) = a) (ht : c * W.len ≤ t)
    (hI : W.PInv c pp s L) (hw : W.win c pp s out = true) (he : W.preEv x0 pp s out = true) :
    preWin W.f pp t L (W.preFind x0 c pp s out).1 (W.preFind x0 c pp s out).2 = true := by
  have hcond := W.cond_pre c t pp s L out hlen hdig hinj hinst ht hI hw
  unfold preEv at he
  unfold preFind
  cases hq : s.qs[out.1]? with
  | none => rw [hq] at he; exact absurd he (by simp)
  | some e =>
    obtain ⟨a, m, pk, sig⟩ := e
    rw [hq] at he
    simp only [beq_iff_eq] at he
    simp only
    obtain ⟨hmem, hc, hjl, hlt, hd, hsl, hl', _⟩ :=
      W.forge_facts x0 c pp hlen hdig htwo s out hI.1 hw a m pk sig hq _ rfl
    generalize hj : firstLess (W.enc out.2.1) (W.enc m) = j at hjl hlt hd he ⊢
    have hin := W.mem_preSigTgts_of x0 a (W.enc m) sig 0 j (by rw [hlen]; exact hjl)
      (by rw [hsl]; exact hjl) (by omega)
    rw [Nat.zero_add] at hin
    have hin' : (W.twk a j ((W.enc m).getD j 0 - 1), sig.getD j x0) ∈
        ((s.qs.take c).map (fun e => W.preSigTgts e.1 0 (W.enc e.2.1) e.2.2.2)).flatten :=
      List.mem_flatten.mpr ⟨_, List.mem_map.mpr ⟨(a, m, pk, sig),
        by rw [List.take_of_length_le hc]; exact hmem, rfl⟩, hin⟩
    have hget := getElem?_idxOf _ _ hin'
    rw [← hI.2.1] at hget
    unfold preWin
    rw [← hI.2.1, hget]
    simp only [Bool.and_eq_true, beq_iff_eq] at hcond ⊢
    refine ⟨hcond, ?_⟩
    rw [← he]
    unfold forgeY
    simp only [hj]
    generalize (W.enc m).getD j 0 = D at hlt hd ⊢
    generalize (W.enc out.2.1).getD j 0 = D' at hlt hd ⊢
    rw [show D - D' = (D - 1 - D') + 1 by omega, chain_succ, show D' + (D - 1 - D') = D - 1 by omega]


/-! ## The reduction as a PRE-C adversary, and its game as a labelled process -/

def preRedHandler (c : Nat) (x0 : X) (st : WotsState Tw I M X × List X) (q : WotsQuery Tw I M Xc) :
    OT (Tw ⊕ (Tw × Xc)) X (WotsAnswer X × (WotsState Tw I M X × List X)) :=
  (resolveS x0 (capH c W.preHandler st.1 q) st.2).bind (fun r => .done (r.1.1, (r.1.2, r.2)))

/-- `R_SMDTPREC_Game4WOTSTWES` with own tape `R`. -/
def preRed [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type} (c : Nat) (x0 : X)
    (A : WotsAdv PP Tw I M X Xc σ) (R : List X) :
    PreAdv PP Tw X Xc X (σ × (WotsState Tw I M X × List X)) :=
  ⟨OT.interp (W.preRedHandler c x0) A.choose (⟨[], []⟩, R),
   fun st pp => W.preFind x0 c pp st.2.1 (A.forge st.1 pp)⟩

def preProcHandler (pp : PP) (c : Nat) (st : WotsState Tw I M X × Log (Tw × X) Tw)
    (q : WotsQuery Tw I M Xc) : OT Bool X (WotsAnswer X × (WotsState Tw I M X × Log (Tw × X) Tw)) :=
  (preInterp W.f W.fc pp (capH c W.preHandler st.1 q) st.2).bind (fun r => .done (r.1.1, (r.1.2, r.2)))

/-- The PRE-C game of the reduction, as a labelled process. -/
def preProc [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (x0 : X) (c t : Nat) (pp : PP) (A : WotsAdv PP Tw I M X Xc σ) : OT Bool X Bool :=
  (OT.interp (W.preProcHandler pp c) A.choose (⟨[], []⟩, ⟨[], []⟩)).bind (fun r =>
    .done (preWin W.f pp t r.2.2 (W.preFind x0 c pp r.2.1 (A.forge r.1 pp)).1
      (W.preFind x0 c pp r.2.1 (A.forge r.1 pp)).2))

theorem preRed_run_proc [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (c t : Nat) (x0 : X) (pp : PP) (A : WotsAdv PP Tw I M X Xc σ) (T R : List X) :
    (let B := W.preRed c x0 A R
     let r := B.pick.run (preOracle W.f W.fc x0 pp T) ⟨[], []⟩
     let ix := B.find r.1 pp
     preWin W.f pp t r.2 ix.1 ix.2) =
      ((W.preProc x0 c t pp A).run (tape2 x0) (T, R)).1 := by
  let Rel : ((WotsState Tw I M X × List X) × Log (Tw × X) Tw) →
      ((WotsState Tw I M X × Log (Tw × X) Tw) × (List X × List X)) → Prop :=
    fun u v => u.1.1 = v.1.1 ∧ u.2 = v.1.2 ∧ u.1.2 = v.2.2 ∧ v.2.1 = T.drop u.2.tgt.length
  have step := OT.run_rel
    (fun (st : (WotsState Tw I M X × List X) × Log (Tw × X) Tw) q =>
      let x := (W.preRedHandler c x0 st.1 q).run (preOracle W.f W.fc x0 pp T) st.2
      (x.1.1, (x.1.2, x.2)))
    (fun (st : (WotsState Tw I M X × Log (Tw × X) Tw) × (List X × List X)) q =>
      let x := (W.preProcHandler pp c st.1 q).run (tape2 x0) st.2
      (x.1.1, (x.1.2, x.2))) Rel (by
      rintro ⟨⟨s1, R1⟩, L1⟩ ⟨⟨s2, L2⟩, ⟨T2, R2⟩⟩ q ⟨h1, h2, h3, h4⟩
      simp only at h1 h2 h3 h4
      subst h1 h2 h3 h4
      have hu := preRun_proc W.f W.fc x0 pp T (capH c W.preHandler s1 q) R1 L1
      have ht := preInterp_tape W.f W.fc x0 pp T (capH c W.preHandler s1 q) R1 L1
      simp only [preRedHandler, preProcHandler, OT.run_bind, OT.run, hu]
      refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> first | rfl | trivial | exact ht) A.choose ((⟨[], []⟩, R), ⟨[], []⟩)
      ((⟨[], []⟩, ⟨[], []⟩), (T, R)) ⟨rfl, rfl, rfl, rfl⟩
  have hB := OT.run_interp (W.preRedHandler c x0) (preOracle W.f W.fc x0 pp T) A.choose (⟨[], []⟩, R) ⟨[], []⟩
  have hL := OT.run_interp (W.preProcHandler pp c) (tape2 x0) A.choose (⟨[], []⟩, ⟨[], []⟩) (T, R)
  obtain ⟨he, h1, h2, _, _⟩ := step
  simp only [preRed, preProc, OT.run_bind, OT.run]
  simp only [hB, hL]
  simp only [he, h1, h2]

theorem preProcHandler_eq (pp : PP) (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x) (c : Nat)
    (st : WotsState Tw I M X × Log (Tw × X) Tw) (q : WotsQuery Tw I M Xc) :
    unlabel (W.preProcHandler pp c st q) =
      (capH c (W.handler (fun pp a => W.g3Elem pp a) pp) st.1 q).bind (fun r =>
        .done (r.1, (r.2, W.preLog c st.1 q r.1 st.2))) := by
  unfold preProcHandler
  rw [unlabel_bind, W.capPre_eq pp hc, OT.bind_assoc]
  rfl

theorem unlabel_preProc [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (x0 : X) (c t : Nat) (pp : PP) (A : WotsAdv PP Tw I M X Xc σ)
    (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x) :
    unlabel (W.preProc x0 c t pp A) =
      (OT.interp (fun (st : WotsState Tw I M X × Log (Tw × X) Tw) q =>
        (capH c (W.handler (fun pp a => W.g3Elem pp a) pp) st.1 q).bind (fun r =>
          (.done (r.1, (r.2, W.preLog c st.1 q r.1 st.2)) : OT Unit X _))) A.choose (⟨[], []⟩, ⟨[], []⟩)).bind
        (fun r => .done (preWin W.f pp t r.2.2 (W.preFind x0 c pp r.2.1 (A.forge r.1 pp)).1
          (W.preFind x0 c pp r.2.1 (A.forge r.1 pp)).2)) := by
  have hfun : (fun st q => unlabel (W.preProcHandler pp c st q)) =
      (fun (st : WotsState Tw I M X × Log (Tw × X) Tw) q =>
        (capH c (W.handler (fun pp a => W.g3Elem pp a) pp) st.1 q).bind (fun r =>
          (.done (r.1, (r.2, W.preLog c st.1 q r.1 st.2)) : OT Unit X _))) := by
    funext st q; exact W.preProcHandler_eq pp hc c st q
  unfold preProc
  rw [unlabel_bind, unlabel_interp, hfun]
  rfl

/-- Whenever Game 3 is won in the PRE case, the reduction wins its PRE-C
    game on the same values. -/
theorem preProc_of_g3 [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (x0 : X) (c t : Nat) (pp : PP) (A : WotsAdv PP Tw I M X Xc σ)
    (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x)
    (hlen : ∀ m, (W.enc m).length = W.len) (hdig : ∀ m, ∀ d ∈ W.enc m, d ≤ W.w - 1)
    (htwo : ∀ m m' : M, m ≠ m' → ∃ j, j < W.len ∧ (W.enc m').getD j 0 < (W.enc m).getD j 0)
    (hinj : ∀ a a' j j' h h', j < W.len → j' < W.len → h < W.w → h' < W.w →
      W.twk a j h = W.twk a' j' h' → a = a' ∧ j = j' ∧ h = h')
    (hinst : ∀ a j h, W.inst (W.twk a j h) = a) (ht : c * W.len ≤ t) (T : List X)
    (hg : ((W.procEv (capH c (W.handler (fun pp a => W.g3Elem pp a) pp)) c pp A (W.preEv x0 pp)).run
      (tape1 x0) T).1 = true) :
    ((unlabel (W.preProc x0 c t pp A)).run (tape1 x0) T).1 = true := by
  rw [W.unlabel_preProc x0 c t pp A hc, OT.run_bind]
  unfold procEv at hg
  rw [OT.run_bind] at hg
  have hinv := OT.all_run (fun r => W.PInv c pp r.2.1 r.2.2) (tape1 x0)
    (OT.interp (fun (st : WotsState Tw I M X × Log (Tw × X) Tw) q =>
      (capH c (W.handler (fun pp a => W.g3Elem pp a) pp) st.1 q).bind (fun r =>
        (.done (r.1, (r.2, W.preLog c st.1 q r.1 st.2)) : OT Unit X _))) A.choose (⟨[], []⟩, ⟨[], []⟩)) T
    (OT.all_interp (fun (st : WotsState Tw I M X × Log (Tw × X) Tw) => W.PInv c pp st.1 st.2) _
      (fun st q h => W.pinv_step hlen pp c st.1 st.2 q h) A.choose _
      ⟨fun e he => by simp at he, by simp, by simp⟩)
  have step := OT.interp_run_rel
    (fun (st : WotsState Tw I M X × Log (Tw × X) Tw) q =>
      (capH c (W.handler (fun pp a => W.g3Elem pp a) pp) st.1 q).bind (fun r =>
        (.done (r.1, (r.2, W.preLog c st.1 q r.1 st.2)) : OT Unit X _))) (tape1 x0)
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
  exact W.pre_of_ev x0 c t pp _ _ _ hlen hdig htwo hinj hinst ht hinv hg.1 hg.2


/-! ## Counting: the PRE case of Game 3 is at most the reduction's PRE-C wins -/

theorem preProc_within [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (x0 : X) (c t : Nat) (pp : PP) (A : WotsAdv PP Tw I M X Xc σ)
    (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x) (hlen : ∀ m, (W.enc m).length = W.len) :
    (unlabel (W.preProc x0 c t pp A)).Within (c * W.len) := by
  rw [W.unlabel_preProc x0 c t pp A hc]
  apply OT.withinP_within (fun _ _ => True)
  exact OT.withinP_bind _ _ _ (fun _ _ _ => by simp [OT.WithinP]) _ _
    (OT.withinP_interp (fun (st : WotsState Tw I M X × Log (Tw × X) Tw) n => W.capInv c st.1 n) _
      (fun st q n h => OT.withinP_bind _ _ _ (fun r m hr => by simp only [OT.WithinP]; exact hr) _ n
        (W.capH_withinP _ (fun pp a => W.g3_oneDraw pp a) hlen pp c st.1 q n h))
      A.choose _ _ (by simp [capInv]))

theorem pre_inner [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (x0 : X) (c t : Nat) (pp : PP) (A : WotsAdv PP Tw I M X Xc σ) (Din : FiniteExperiment X)
    (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x)
    (hlen : ∀ m, (W.enc m).length = W.len) (hdig : ∀ m, ∀ d ∈ W.enc m, d ≤ W.w - 1)
    (htwo : ∀ m m' : M, m ≠ m' → ∃ j, j < W.len ∧ (W.enc m').getD j 0 < (W.enc m).getD j 0)
    (hinj : ∀ a a' j j' h h', j < W.len → j' < W.len → h < W.w → h' < W.w →
      W.twk a j h = W.twk a' j' h' → a = a' ∧ j = j' ∧ h = h')
    (hinst : ∀ a j h, W.inst (W.twk a j h) = a) (ht : c * W.len ≤ t) :
    Din.cardinality ^ t * (Din.tape (c * W.len)).sum (fun T =>
        if ((W.procEv (capH c (W.handler (fun pp a => W.g3Elem pp a) pp)) c pp A (W.preEv x0 pp)).run
          (tape1 x0) T).1 then 1 else 0) ≤
      (Din.tape t).sum (fun T => (Din.tape (c * W.len)).sum (fun R =>
        if ((W.preProc x0 c t pp A).run (tape2 x0) (T, R)).1 then 1 else 0)) := by
  have hm := tape_merge x0 Din (fun b => if b then 1 else 0) (W.preProc x0 c t pp A) t (c * W.len)
    (withinL_of_unlabel _ (c * W.len) t (c * W.len) (W.preProc_within x0 c t pp A hc hlen) ht (Nat.le_refl _))
  have hp := tape_pad x0 Din (fun b => if b then 1 else 0)
    (W.procEv (capH c (W.handler (fun pp a => W.g3Elem pp a) pp)) c pp A (W.preEv x0 pp)) (c * W.len) t
    (W.procEv_within _ (fun pp a => W.g3_oneDraw pp a) hlen c pp A _)
  simp only at hm hp
  rw [hm, hp, Nat.add_comm]
  apply sum_le; intro j
  split
  · rename_i hg
    rw [if_pos (W.preProc_of_g3 x0 c t pp A hc hlen hdig htwo hinj hinst ht _ hg)]
    exact Nat.le_refl _
  · exact Nat.zero_le _

/-- The reduction's coins: its own `c · len` values and A's coins. -/
def preCoins [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type} (c : Nat) (x0 : X)
    (Din : FiniteExperiment X) (As : FiniteExperiment (WotsAdv PP Tw I M X Xc σ)) :
    FiniteExperiment (PreAdv PP Tw X Xc X (σ × (WotsState Tw I M X × List X))) :=
  (independentProduct (Din.tape (c * W.len)) As).map (fun p => W.preRed c x0 p.2 p.1)

/-- `|D|^t · #(Game 3 won in the PRE case) ≤ #PRE-C(B_pre)`. -/
theorem pre_num [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (x0 : X) (c t : Nat) (P : FiniteExperiment PP) (Din : FiniteExperiment X)
    (As : FiniteExperiment (WotsAdv PP Tw I M X Xc σ))
    (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x)
    (hlen : ∀ m, (W.enc m).length = W.len) (hdig : ∀ m, ∀ d ∈ W.enc m, d ≤ W.w - 1)
    (htwo : ∀ m m' : M, m ≠ m' → ∃ j, j < W.len ∧ (W.enc m').getD j 0 < (W.enc m).getD j 0)
    (hinj : ∀ a a' j j' h h', j < W.len → j' < W.len → h < W.w → h' < W.w →
      W.twk a j h = W.twk a' j' h' → a = a' ∧ j = j' ∧ h = h')
    (hinst : ∀ a j h, W.inst (W.twk a j h) = a) (ht : c * W.len ≤ t) :
    Din.cardinality ^ t * W.g3EvCount x0 c P Din As (W.preEv x0) ≤
      (preProb P Din x0 W.f W.fc t (W.preCoins c x0 Din As)).numerator := by
  have stepA : (preProb P Din x0 W.f W.fc t (W.preCoins c x0 Din As)).numerator =
      P.sum (fun pp => (Din.tape t).sum (fun T => (Din.tape (c * W.len)).sum (fun R => As.sum (fun A =>
        if ((W.preProc x0 c t pp A).run (tape2 x0) (T, R)).1 then 1 else 0)))) := by
    unfold preProb preCoins
    rw [numerator_sum, product_sum, product_sum]
    apply sum_congr; intro i1
    apply sum_congr; intro i2
    rw [sum_map_product]
    apply sum_congr; intro i3
    apply sum_congr; intro i4
    apply ind_of_eq
    exact W.preRed_run_proc c t x0 _ _ _ _
  rw [stepA]
  simp only [sum_comm (Din.tape (c * W.len)) As, sum_comm (Din.tape t) As]
  unfold g3EvCount
  rw [sum_mul_left]
  apply sum_le; intro i
  rw [sum_mul_left]
  apply sum_le; intro j
  exact W.pre_inner x0 c t _ _ Din hc hlen hdig htwo hinj hinst ht

theorem pre_den [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (x0 : X) (c t : Nat) (P : FiniteExperiment PP) (Din : FiniteExperiment X)
    (As : FiniteExperiment (WotsAdv PP Tw I M X Xc σ)) :
    (preProb P Din x0 W.f W.fc t (W.preCoins c x0 Din As)).denominator =
      Din.cardinality ^ t * (W.hybProb x0 c P Din As 0).denominator := by
  show (P.cardinality * (Din.tape t).cardinality) * ((Din.tape (c * W.len)).cardinality * As.cardinality) = _
  simp only [hybProb, card_tape]
  ac_rfl

/-! ## Resources of the reduction -/

theorem preElem_withinI (a : I) (c d : Nat) (hd : d ≤ W.w - 1) (n : Nat) (hn : W.w - 1 ≤ n) :
    WithinI (fun _ m => n ≤ m + (W.w - 1)) (W.preElem a c d) n := by
  cases d with
  | zero =>
    simp only [preElem, WithinI]
    intro x
    exact withinI_bind _ _ _ (fun _ m h => by simp only [WithinI]; exact h) _ n
      (W.colChain_withinI a c (W.w - 1) x 0 n hn)
  | succ e =>
    cases n with
    | zero => omega
    | succ n =>
      simp only [preElem, WithinI]
      intro y
      exact withinI_bind _ _ _ (fun _ m h => by simp only [WithinI]; omega) _ n
        (W.colChain_withinI a c (W.w - 1 - (e+1)) y (e+1) n (by omega))

theorem signPre_withinI (a : I) :
    ∀ (ds : List Nat) (c n : Nat), (∀ d ∈ ds, d ≤ W.w - 1) → ds.length * (W.w - 1) ≤ n →
      WithinI (fun _ m => n ≤ m + ds.length * (W.w - 1)) (signFrom (W.preElem a) c ds) n
  | [], _, n, _, _ => by simp [signFrom, WithinI]
  | d :: ds, c, n, hd, hn => by
    simp only [List.length_cons, Nat.succ_mul] at hn ⊢
    simp only [signFrom]
    refine withinI_bind _ _ _ (fun e m hm => ?_) _ n
      (W.preElem_withinI a c d (hd d (List.mem_cons_self ..)) n (by omega))
    refine withinI_bind _ _ _ (fun r m' hm' => ?_) _ m
      (signPre_withinI a ds (c+1) m (fun d h => hd d (List.mem_cons_of_mem _ h)) (by omega))
    simp only [WithinI]
    omega

/-- **Query budget of the PRE reduction.** At most `q · len · (w − 1)` PRE-C
    queries (targets and collection) for an adversary of `q` first-phase
    queries; at most `c · len` targets on winning runs (`cond_pre`); own
    coins: `c · len` values. -/
theorem preRed_queries [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (hlen : ∀ m, (W.enc m).length = W.len) (hdig : ∀ m, ∀ d ∈ W.enc m, d ≤ W.w - 1)
    (hK : 1 ≤ W.len * (W.w - 1)) (c : Nat) (x0 : X) (A : WotsAdv PP Tw I M X Xc σ) (R : List X)
    (q : Nat) (hA : A.choose.Within q) :
    (W.preRed c x0 A R).pick.Within (q * (W.len * (W.w - 1))) := by
  apply OT.withinP_within (fun _ _ => True)
  refine OT.within_interp_mul _ (W.len * (W.w - 1)) (fun st qq n hn => ?_) A.choose q _ _ hA (Nat.le_refl _)
  have hI : WithinI (fun _ m => n ≤ m + W.len * (W.w - 1)) (capH c W.preHandler st.1 qq) n := by
    match qq with
    | .inl (a, msg) =>
      by_cases hlt : st.1.qs.length < c
      · simp only [capH, if_pos hlt, preHandler]
        have h := W.signPre_withinI a (W.enc msg) 0 n (hdig msg) (by rw [hlen]; exact hn)
        rw [hlen] at h
        exact withinI_bind _ _ _ (fun _ m hm => by simp only [WithinI]; exact hm) _ n h
      · simp only [capH, if_neg hlt, WithinI]
        omega
    | .inr (tw, x) =>
      cases n with
      | zero => omega
      | succ n =>
        simp only [capH, preHandler, WithinI]
        intro _
        omega
  unfold preRedHandler
  exact OT.withinP_bind _ _ _ (fun _ m hm => by simp only [OT.WithinP]; exact hm) _ n
    (withinI_resolve x0 _ _ st.2 n hI)

end WotsSetting

#print axioms WotsSetting.cond_pre
#print axioms WotsSetting.pre_of_ev
#print axioms WotsSetting.preRed_run_proc
#print axioms WotsSetting.preProc_of_g3
#print axioms WotsSetting.pre_num
#print axioms WotsSetting.preRed_queries
end DSM.Sphincs.Comp
