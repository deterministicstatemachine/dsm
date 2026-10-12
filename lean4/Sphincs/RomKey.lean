-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomBudget

/- Key collisions.

   The 32-byte collision events of C59 (`collC_key`) and C60 (`canon_split`) are
   collisions between two of the three challenger key-derivation entries (`KeyEnts`):
   the tweak key, the PRF key and the PRF-msg key. Here they are counted as such.

   `KeyColl` is the shared event: a step appends a challenger key entry at an
   unrevealed position whose coordinate agrees, modulo `256^32`, with an existing
   challenger key entry. It is charged at that creation, a fresh coordinate, against
   the earlier key entry, which the prefix fixes. Each key request is appended at most
   once, so a run has at most three such pairs, and
       #KeyColl · 256^32 ≤ 3 · R^N   (`key_count`). -/
namespace DSM.Rom
open DSM.Sphincs DSM.Sphincs.Security

theorem firstIdx_le_of {β : Type} (p : β → Bool) (l : List β) (j : Nat) (b : β) (h : l[j]? = some b)
    (hp : p b = true) : firstIdx p l ≤ j := by
  apply Nat.le_of_not_lt
  intro hlt
  have := fr_before p l j b h hlt
  rw [hp] at this; cases this

/-- The state after a step is a prefix of the end state. -/
theorem post_final (t : List Nat) {α : Type} : ∀ (P : Prog α) (st : St) (s : Nat) (stp : St × Ev),
    (strace t P st)[s]? = some stp → ∃ L, (xrun false t P st).2.ents = (stepPost t stp).ents ++ L
  | .done _, _, _, _, h => by simp [strace] at h
  | .askC r k, st, 0, stp, h => by
    simp [strace] at h; subst h
    obtain ⟨⟨L, hL⟩, _⟩ := xrun_grow t (k (.hid (firstIdx (mC false t st.rev r) st.ents) r.outLen))
      (addC st (firstIdx (mC false t st.rev r) st.ents) r)
    exact ⟨L, by simp only [xrun, stepPost]; exact hL⟩
  | .askC r k, st, s+1, stp, h => by
    simp only [strace, List.getElem?_cons_succ] at h
    simp only [xrun]
    exact post_final t _ _ s stp h
  | .askA q k, st, 0, stp, h => by
    simp [strace] at h; subst h
    obtain ⟨⟨L, hL⟩, _⟩ := xrun_grow t (k (be q.outLen (t.getD (firstIdx (mA false t st.rev q) st.ents) 0)))
      (addA st (firstIdx (mA false t st.rev q) st.ents) q)
    exact ⟨L, by simp only [xrun, stepPost]; exact hL⟩
  | .askA q k, st, s+1, stp, h => by
    simp only [strace, List.getElem?_cons_succ] at h
    simp only [xrun]
    exact post_final t _ _ s stp h
  | .reveal x k, st, 0, stp, h => by
    simp [strace] at h; subst h
    obtain ⟨⟨L, hL⟩, _⟩ := xrun_grow t (k (sres t x)) ⟨st.ents, shids x ++ st.rev⟩
    exact ⟨L, by simp only [xrun, stepPost]; exact hL⟩
  | .reveal x k, st, s+1, stp, h => by
    simp only [strace, List.getElem?_cons_succ] at h
    simp only [xrun]
    exact post_final t _ _ s stp h

/-- A fresh challenger step appends its request at the old length. -/
theorem fresh_post (t : List Nat) {stp : St × Ev} {y : SReq} (hc : stp.2 = .c y)
    (hf : firstIdx (mC false t stp.1.rev y) stp.1.ents = stp.1.ents.length) :
    (stepPost t stp).ents[stp.1.ents.length]? = some (false, y) := by
  obtain ⟨st, ev⟩ := stp
  simp only at hc hf ⊢
  subst hc
  simp [stepPost, hf, addC]

/-- A challenger request already present is not appended again. -/
theorem not_fresh {t : List Nat} {stp : St × Ev} {x : SReq} {a : Nat}
    (ha : stp.1.ents[a]? = some (false, x))
    (hf : firstIdx (mC false t stp.1.rev x) stp.1.ents = stp.1.ents.length) : False := by
  have h1 := firstIdx_le_of (mC false t stp.1.rev x) stp.1.ents a _ ha (by simp [mC])
  have h2 := lt_entry ha
  omega

section
variable {α : Type} (P : Prog α) (st0 : St)

/-- Past the initial entries, a challenger request is an entry at most once. -/
theorem ch_once (t : List Nat) {a1 a2 : Nat} {r : SReq}
    (h1 : (xrun false t P st0).2.ents[a1]? = some (false, r)) (h2 : (xrun false t P st0).2.ents[a2]? = some (false, r))
    (hlt : a1 < a2) (h0 : st0.ents.length ≤ a2) : False := by
  obtain ⟨s, stp, hs, hl, hc⟩ := entry_creation t P st0 a2 _ h2 h0
  rcases hc with ⟨q, _, _, hq⟩ | ⟨r', hr, hf, hq⟩
  · exact absurd (Prod.mk.inj hq).1 (by decide)
  · obtain rfl : r = r' := (Prod.mk.inj hq).2
    obtain ⟨L, hL⟩ := trace_final t P st0 s stp hs
    have hget : stp.1.ents[a1]? = some (false, r) := by
      rw [hL, List.getElem?_append_left (by omega)] at h1; exact h1
    rw [← hl] at hf
    exact not_fresh hget hf

/-- An entry of a step state stays in every later step state. -/
theorem ent_later (t : List Nat) {s1 s2 : Nat} {stp1 stp2 : St × Ev} (hle : s1 ≤ s2)
    (h1 : (strace t P st0)[s1]? = some stp1) (h2 : (strace t P st0)[s2]? = some stp2) {a : Nat}
    {e : Bool × SReq} (ha : stp1.1.ents[a]? = some e) : stp2.1.ents[a]? = some e := by
  rcases Nat.lt_or_eq_of_le hle with hlt | rfl
  · exact grow_get (grow_trans (post_grow t stp1) (trace_grow2 t P st0 _ _ _ _ hlt h1 h2)) ha
  · rw [h1] at h2; obtain rfl := Option.some.inj h2; exact ha

/-- Weight of index `((x, y), (s, b))`: step `s` appends challenger request `y` at the
    unrevealed position `b`, and challenger request `x` is already an entry. -/
def KeyW (t : List Nat) (i : (SReq × SReq) × Nat × Nat) : Prop :=
  ∃ stp, (strace t P st0)[i.2.1]? = some stp ∧ i.2.2 = stp.1.ents.length ∧ i.2.2 ∉ stp.1.rev ∧
    stp.2 = .c i.1.2 ∧ firstIdx (mC false t stp.1.rev i.1.2) stp.1.ents = stp.1.ents.length ∧
    ∃ a : Nat, stp.1.ents[a]? = some (false, i.1.1)

noncomputable def keyW (i : (SReq × SReq) × Nat × Nat) (t : List Nat) : Nat :=
  @ite _ (KeyW P st0 t i) (Classical.propDecidable _) 1 0

/-- The earlier key entry's coordinate. -/
noncomputable def keyTg (i : (SReq × SReq) × Nat × Nat) (t : List Nat) : Nat :=
  match (strace t P st0)[i.2.1]? with
  | some stp => t.getD (firstIdx (fun e => decide (e = (false, i.1.1))) stp.1.ents) 0
  | none => 0

/-- The key-collision event: a step appends a challenger key entry at an unrevealed
    position whose coordinate agrees modulo `256^32` with an existing challenger key entry. -/
def KeyColl (n : Nat) (t : List Nat) : Prop :=
  ∃ (s a : Nat) (stp : St × Ev) (x y : SReq), x ∈ keyReqs n ∧ y ∈ keyReqs n ∧
    (strace t P st0)[s]? = some stp ∧ stp.2 = .c y ∧
    firstIdx (mC false t stp.1.rev y) stp.1.ents = stp.1.ents.length ∧ stp.1.ents.length ∉ stp.1.rev ∧
    stp.1.ents[a]? = some (false, x) ∧ t.getD a 0 % 256^32 = t.getD stp.1.ents.length 0 % 256^32

theorem keyW_set (t : List Nat) (i : (SReq × SReq) × Nat × Nat) (y : Nat) (hp : KeyW P st0 t i) :
    KeyW P st0 (t.set i.2.2 y) i ∧ (strace (t.set i.2.2 y) P st0)[i.2.1]? = (strace t P st0)[i.2.1]? := by
  obtain ⟨stp, h1, hb, hnr, hc, hf, a, ha⟩ := hp
  have hT := strace_inv t i.2.2 y P st0 i.2.1 stp h1 (by rw [hb]; rw [hb] at hnr; exact hnr)
  have e1 : (strace (t.set i.2.2 y) P st0)[i.2.1]? = (strace t P st0)[i.2.1]? := by
    have := congrArg (fun l => l[i.2.1]?) hT
    simpa only [List.getElem?_take, Nat.lt_succ_self, if_true] using this
  refine ⟨⟨stp, by rw [e1]; exact h1, hb, hnr, hc, ?_, a, ha⟩, e1⟩
  rw [← hf]; exact firstIdx_congr _ _ _ (fun e _ => mC_false_set t i.2.2 y stp.1.rev _ e hnr)

theorem keyW_inv (i : (SReq × SReq) × Nat × Nat) (t : List Nat) (y : Nat) :
    keyW P st0 i (t.set i.2.2 y) = keyW P st0 i t := by
  unfold keyW
  by_cases h : KeyW P st0 t i
  · rw [if_pos h, if_pos (keyW_set P st0 t i y h).1]
  · rw [if_neg h, if_neg]
    intro h'
    apply h
    have := (keyW_set P st0 (t.set i.2.2 y) i (t.getD i.2.2 0) h').1
    rwa [set_set_back] at this

theorem keyW_pos {i : (SReq × SReq) × Nat × Nat} {t : List Nat} (hw : keyW P st0 i t ≠ 0) : KeyW P st0 t i := by
  unfold keyW at hw
  by_cases h : KeyW P st0 t i
  · exact h
  · rw [if_neg h] at hw; exact absurd rfl hw

theorem keyW_le (i : (SReq × SReq) × Nat × Nat) (t : List Nat) : keyW P st0 i t ≤ 1 := by
  unfold keyW; split <;> omega

theorem keyTg_inv (i : (SReq × SReq) × Nat × Nat) (t : List Nat) (y : Nat) (hw : keyW P st0 i t ≠ 0) :
    keyTg P st0 i (t.set i.2.2 y) = keyTg P st0 i t := by
  have hp := keyW_pos P st0 hw
  have e1 := (keyW_set P st0 t i y hp).2
  obtain ⟨stp, h1, hb, _, _, _, a, ha⟩ := hp
  unfold keyTg
  rw [e1, h1]
  refine getD_set_ne t i.2.2 _ y ?_
  have hle := firstIdx_le_of (fun e => decide (e = (false, i.1.1))) stp.1.ents a _ ha (by simp)
  have := lt_entry ha
  omega

/-- Two weighted indices of one key pair coincide. -/
theorem keyW_unique (t : List Nat) (xy : SReq × SReq) {s1 b1 s2 b2 : Nat}
    (h1 : KeyW P st0 t (xy, s1, b1)) (h2 : KeyW P st0 t (xy, s2, b2)) : s1 = s2 ∧ b1 = b2 := by
  obtain ⟨stp1, hs1, hb1, _, hc1, hf1, _⟩ := h1
  obtain ⟨stp2, hs2, hb2, _, hc2, hf2, _⟩ := h2
  have key : ∀ {s s' : Nat} {stp stp' : St × Ev}, s < s' → (strace t P st0)[s]? = some stp →
      (strace t P st0)[s']? = some stp' → stp.2 = .c xy.2 →
      firstIdx (mC false t stp.1.rev xy.2) stp.1.ents = stp.1.ents.length → stp'.2 = .c xy.2 →
      firstIdx (mC false t stp'.1.rev xy.2) stp'.1.ents = stp'.1.ents.length → False := by
    intro s s' stp stp' hlt hs hs' hc hf hc' hf'
    have hp := fresh_post t hc hf
    have := grow_get (trace_grow2 t P st0 _ _ _ _ hlt hs hs') hp
    exact not_fresh this hf'
  rcases Nat.lt_trichotomy s1 s2 with hlt | rfl | hgt
  · exact (key hlt hs1 hs2 hc1 hf1 hc2 hf2).elim
  · rw [hs1] at hs2; obtain rfl := Option.some.inj hs2; exact ⟨rfl, by simp only at hb1 hb2; omega⟩
  · exact (key hgt hs2 hs1 hc2 hf2 hc1 hf1).elim

/-- A request is not appended while it is already an entry. -/
theorem keyW_diag (t : List Nat) (x : SReq) (s b : Nat) : ¬ KeyW P st0 t ((x, x), s, b) := by
  rintro ⟨stp, _, _, _, _, hf, a, ha⟩
  exact not_fresh ha hf

/-- Of two key requests, only the later one is charged. -/
theorem keyW_anti (t : List Nat) (x y : SReq) {s1 b1 s2 b2 : Nat}
    (h1 : KeyW P st0 t ((x, y), s1, b1)) (h2 : KeyW P st0 t ((y, x), s2, b2)) : False := by
  obtain ⟨stp1, hs1, _, _, hc1, hf1, a1, ha1⟩ := h1
  obtain ⟨stp2, hs2, _, _, hc2, hf2, a2, ha2⟩ := h2
  rcases Nat.le_total s1 s2 with hle | hle
  · exact not_fresh (ent_later P st0 t hle hs1 hs2 ha1) hf2
  · exact not_fresh (ent_later P st0 t hle hs2 hs1 ha2) hf1

end

theorem sum_zero_of {ι : Type} (l : List ι) (f : ι → Nat) (h : ∀ i ∈ l, f i = 0) : (l.map f).sum = 0 := by
  have := sum_map_le l (g := fun _ => 0) (fun i hi => Nat.le_of_eq (h i hi))
  rw [sum_map_const] at this
  omega

theorem exists_of_sum_ne {ι : Type} (l : List ι) (f : ι → Nat) (h : (l.map f).sum ≠ 0) : ∃ i ∈ l, f i ≠ 0 := by
  apply Classical.byContradiction
  intro hn
  apply h
  exact sum_zero_of l f (fun i hi => Classical.byContradiction (fun hi' => hn ⟨i, hi, hi'⟩))

section
variable {α : Type} (P : Prog α) (st0 : St)

/-- Ordered pairs of key requests. -/
def keyPairs (n : Nat) : List (SReq × SReq) :=
  [(dTk n, dTk n), (dTk n, dPrf n), (dTk n, dReq n), (dPrf n, dTk n), (dPrf n, dPrf n), (dPrf n, dReq n),
   (dReq n, dTk n), (dReq n, dPrf n), (dReq n, dReq n)]

def keyIx (n S N : Nat) : List ((SReq × SReq) × Nat × Nat) :=
  (keyPairs n).flatMap (fun xy => (List.range S).flatMap (fun s => (List.range N).map (fun b => (xy, s, b))))

/-- The charged indices of one key pair. -/
noncomputable def keyG (S N : Nat) (xy : SReq × SReq) (t : List Nat) : Nat :=
  ((List.range S).map (fun s => ((List.range N).map (fun b => keyW P st0 (xy, s, b) t)).sum)).sum

theorem keyG_ex {S N : Nat} {xy : SReq × SReq} {t : List Nat} (h : keyG P st0 S N xy t ≠ 0) :
    ∃ s b, KeyW P st0 t (xy, s, b) := by
  obtain ⟨s, _, hs⟩ := exists_of_sum_ne _ _ h
  obtain ⟨b, _, hb⟩ := exists_of_sum_ne _ _ hs
  exact ⟨s, b, keyW_pos P st0 hb⟩

theorem keyG_le (S N : Nat) (xy : SReq × SReq) (t : List Nat) : keyG P st0 S N xy t ≤ 1 := by
  unfold keyG
  have hin : ∀ s, ((List.range N).map (fun b => keyW P st0 (xy, s, b) t)).sum ≤ 1 := fun s =>
    sum_le_one (fun b => keyW P st0 (xy, s, b) t) (fun b => keyW_le P st0 _ t)
      (fun b1 b2 hlt h1 h2 => by
        have := (keyW_unique P st0 t xy (keyW_pos P st0 h1) (keyW_pos P st0 h2)).2; omega) N
  refine sum_le_one _ hin (fun s1 s2 hlt h1 h2 => ?_) S
  obtain ⟨b1, _, hb1⟩ := exists_of_sum_ne _ _ h1
  obtain ⟨b2, _, hb2⟩ := exists_of_sum_ne _ _ h2
  have := (keyW_unique P st0 t xy (keyW_pos P st0 hb1) (keyW_pos P st0 hb2)).1
  omega

theorem keyG_diag (S N : Nat) (x : SReq) (t : List Nat) : keyG P st0 S N (x, x) t = 0 := by
  apply Classical.byContradiction
  intro h
  obtain ⟨s, b, hk⟩ := keyG_ex P st0 h
  exact keyW_diag P st0 t x s b hk

theorem keyG_anti (S N : Nat) (x y : SReq) (t : List Nat) :
    keyG P st0 S N (x, y) t + keyG P st0 S N (y, x) t ≤ 1 := by
  have h1 := keyG_le P st0 S N (x, y) t
  have h2 := keyG_le P st0 S N (y, x) t
  by_cases hx : keyG P st0 S N (x, y) t = 0
  · omega
  · by_cases hy : keyG P st0 S N (y, x) t = 0
    · omega
    · obtain ⟨s1, b1, k1⟩ := keyG_ex P st0 hx
      obtain ⟨s2, b2, k2⟩ := keyG_ex P st0 hy
      exact (keyW_anti P st0 t x y k1 k2).elim

/-- At most three charged indices per tape. -/
theorem keyW_total (n S N : Nat) (t : List Nat) : ((keyIx n S N).map (fun i => keyW P st0 i t)).sum ≤ 3 := by
  have e : ((keyIx n S N).map (fun i => keyW P st0 i t)).sum = ((keyPairs n).map (fun xy => keyG P st0 S N xy t)).sum := by
    simp only [keyIx, keyG, sum_flatMap, List.map_map, Function.comp_def]
  rw [e]
  simp only [keyPairs, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil]
  have d1 := keyG_diag P st0 S N (dTk n) t
  have d2 := keyG_diag P st0 S N (dPrf n) t
  have d3 := keyG_diag P st0 S N (dReq n) t
  have a1 := keyG_anti P st0 S N (dTk n) (dPrf n) t
  have a2 := keyG_anti P st0 S N (dTk n) (dReq n) t
  have a3 := keyG_anti P st0 S N (dPrf n) (dReq n) t
  omega

/-- The key-collision count: `#KeyColl · 256^32 ≤ 3 · R^N`. -/
theorem key_count (n R N S : Nat) (hR : 256^32 ∣ R)
    (hst0 : ∀ (j : Nat) (x : SReq), x ∈ keyReqs n → st0.ents[j]? ≠ some (false, x))
    (hS : ∀ t s stp, (strace t P st0)[s]? = some stp → s < S ∧ stp.1.ents.length ≤ S) (hSN : S < N) :
    tsum R N (fun t => ind (KeyColl P st0 n t)) * 256^32 ≤ R^N * 3 := by
  have hM : 0 < 256^32 := Nat.pow_pos (by decide)
  have hpt : ∀ t, ind (KeyColl P st0 n t) ≤ ((keyIx n S N).map (fun i => keyW P st0 i t *
      (if t.getD i.2.2 0 % 256^32 == keyTg P st0 i t % 256^32 then 1 else 0))).sum := by
    intro t
    by_cases h : KeyColl P st0 n t
    · rw [ind_of h]
      obtain ⟨s, a, stp, x, y, hx, hy, hs, hc, hf, hnr, ha, hm⟩ := h
      have hSb := hS t s stp hs
      have hmem : ((x, y), s, stp.1.ents.length) ∈ keyIx n S N := by
        simp only [keyIx, List.mem_flatMap, List.mem_map, List.mem_range]
        refine ⟨(x, y), ?_, s, hSb.1, stp.1.ents.length, by omega, rfl⟩
        simp only [keyReqs, List.mem_cons, List.not_mem_nil, or_false] at hx hy
        rcases hx with rfl | rfl | rfl <;> rcases hy with rfl | rfl | rfl <;> simp [keyPairs]
      have hw : keyW P st0 ((x, y), s, stp.1.ents.length) t = 1 := by
        unfold keyW; rw [if_pos ⟨stp, hs, rfl, hnr, hc, hf, a, ha⟩]
      have ha0 : firstIdx (fun e => decide (e = (false, x))) stp.1.ents = a := by
        have hle := firstIdx_le_of (fun e => decide (e = (false, x))) stp.1.ents a _ ha (by simp)
        rcases Nat.lt_or_eq_of_le hle with hlt | heq
        · exfalso
          obtain ⟨e, he, hpe⟩ := fr_hit (fun e => decide (e = (false, x))) stp.1.ents
            (by have := lt_entry ha; omega)
          have hex : e = (false, x) := by simpa using hpe
          subst hex
          obtain ⟨L, hL⟩ := trace_final t P st0 s stp hs
          have g1 : (xrun false t P st0).2.ents[firstIdx (fun e => decide (e = (false, x))) stp.1.ents]? =
              some (false, x) := by
            rw [hL, List.getElem?_append_left (lt_entry he)]; exact he
          have g2 : (xrun false t P st0).2.ents[a]? = some (false, x) := by
            rw [hL, List.getElem?_append_left (lt_entry ha)]; exact ha
          have h0 : st0.ents.length ≤ a := by
            apply Nat.le_of_not_lt
            intro hlt0
            obtain ⟨⟨L0, hL0⟩, _⟩ := trace_grow t P st0 s stp hs
            apply hst0 a x hx
            rw [hL0, List.getElem?_append_left hlt0] at ha; exact ha
          exact ch_once P st0 t g1 g2 hlt h0
        · exact heq
      have htg : keyTg P st0 ((x, y), s, stp.1.ents.length) t = t.getD a 0 := by
        unfold keyTg; rw [hs]; simp only; rw [ha0]
      exact le_sum_of_mem (List.mem_map.mpr ⟨_, hmem, by rw [hw, htg, hm]; simp⟩)
    · rw [ind_of_not h]; exact Nat.zero_le _
  have hix : ∀ i ∈ keyIx n S N, i.2.2 < N := fun i hi => by
    simp only [keyIx, List.mem_flatMap, List.mem_range, List.mem_map] at hi
    obtain ⟨_, _, _, _, b, hb, rfl⟩ := hi
    exact hb
  have hh := hits_sum R (256^32) N hM hR (keyIx n S N) (fun i => i.2.2) hix
    (fun i t => keyW P st0 i t) (keyTg P st0)
    (fun i _ t y => keyW_inv P st0 i t y) (fun i _ t y hw => keyTg_inv P st0 i t y hw)
  have hsum : tsum R N (fun t => ((keyIx n S N).map (fun i => keyW P st0 i t)).sum) ≤ R^N * 3 := by
    rw [← tsum_const]
    exact tsum_mono R N (fun t => keyW_total P st0 n S N t)
  calc tsum R N (fun t => ind (KeyColl P st0 n t)) * 256^32
      ≤ tsum R N (fun t => ((keyIx n S N).map (fun i => keyW P st0 i t *
          (if t.getD i.2.2 0 % 256^32 == keyTg P st0 i t % 256^32 then 1 else 0))).sum) * 256^32 :=
        Nat.mul_le_mul_right _ (tsum_mono R N hpt)
    _ ≤ R^N * 3 := Nat.le_trans hh hsum

end

/-! H1': the C59 and C60 events are key collisions. -/

theorem coin_not_key (n : Nat) (j : Nat) (x : SReq) (hx : x ∈ keyReqs n) : (coinSt n).ents[j]? ≠ some (false, x) := by
  simp only [keyReqs, List.mem_cons, List.not_mem_nil, or_false] at hx
  rcases j with _ | _ | _ | j <;>
    rcases hx with rfl | rfl | rfl <;> simp [coinSt, coin, dTk, dPrf, dReq]

/-- A coordinate collision among the three coins modulo `256^n`. -/
def CoinColl (n : Nat) (t : List Nat) : Prop :=
  ∃ a b, a < b ∧ b < 3 ∧ t.getD a 0 % 256^n = t.getD b 0 % 256^n

theorem coin_count (R N n : Nat) (hn : 256^n ∣ R) (h3 : 3 ≤ N) :
    tsum R N (fun t => ind (CoinColl n t)) * 256^n ≤ R^N * 3 := by
  have hM : 0 < 256^n := Nat.pow_pos (by decide)
  let I1 : List (Nat × Nat) := pairsBelow 3
  have hpt : ∀ t, ind (CoinColl n t) ≤ (I1.map (fun i => 1 * (if t.getD i.2 0 % 256^n == t.getD i.1 0 % 256^n
      then 1 else 0))).sum := by
    intro t
    by_cases h : CoinColl n t
    · rw [ind_of h]
      obtain ⟨a, b, hab, hb, hc⟩ := h
      exact le_sum_of_mem (List.mem_map.mpr ⟨(a, b), mem_pairsBelow.mpr ⟨hab, hb⟩, by
        show 1 * (if (t.getD b 0 % 256^n == t.getD a 0 % 256^n) = true then 1 else 0) = 1
        rw [hc]; simp⟩)
    · rw [ind_of_not h]; exact Nat.zero_le _
  have e1 := hits_sum R (256^n) N hM hn I1 (fun i => i.2)
    (fun i hi => by have := (mem_pairsBelow' hi).2; show i.2 < N; omega)
    (fun _ _ => 1) (fun i t => t.getD i.1 0) (fun _ _ _ _ => rfl)
    (fun i hi t y _ => getD_set_ne t i.2 i.1 y (by have := (mem_pairsBelow' hi).1; omega))
  have c1 : tsum R N (fun t => (I1.map (fun _ => 1)).sum) = R^N * 3 := by
    rw [sum_map_const, tsum_const]; rfl
  rw [c1] at e1
  exact Nat.le_trans (Nat.mul_le_mul_right _ (tsum_mono R N hpt)) e1

section
variable (v : Variant) (limits : Limits) (A : Bytes → RAdv)

/-- Two key entries of the end state of H1' with agreeing coordinates are a `KeyColl`,
    provided the run has no disagreement before the later entry is appended. -/
theorem keyColl_of_fin (t : List Nat) {a b : Nat}
    (hk : KeyEnts (params v).n (xrun false t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)).2 a b)
    (hm : t.getD a 0 % 256^32 = t.getD b 0 % 256^32)
    (hnd : ∀ (s' : Nat) (stp' : St × Ev), (strace t (gameS' v limits A (coinEx (params v).n))
      (coinSt (params v).n))[s']? = some stp' → stp'.1.ents.length = b →
      NoDisTo t (strace t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)) s') :
    KeyColl (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) (params v).n t := by
  obtain ⟨hab, ⟨x, hx, ha⟩, ⟨y, hy, hb⟩⟩ := hk
  have h3 : (coinSt (params v).n).ents.length ≤ b := by
    apply Nat.le_of_not_lt
    intro hlt
    obtain ⟨⟨L, hL⟩, _⟩ := xrun_grow t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)
    rw [hL, List.getElem?_append_left hlt] at hb
    exact coin_not_key _ b y hy hb
  obtain ⟨s, stp, hs, hl, hc⟩ := entry_creation t _ _ b _ hb h3
  rcases hc with ⟨q, _, _, hq⟩ | ⟨r, hr, hf, hq⟩
  · exact absurd (Prod.mk.inj hq).1 (by decide)
  · obtain rfl : y = r := (Prod.mk.inj hq).2
    obtain ⟨hI, -⟩ := game_struct (c := structCtx t v) rfl limits A s stp hs (hnd s stp hs hl)
    have hnr : stp.1.ents.length ∉ stp.1.rev := fun hm' => by
      have := (hI.2.2.1 _ hm').1; omega
    obtain ⟨L, hL⟩ := trace_final t _ _ s stp hs
    have ha' : stp.1.ents[a]? = some (false, x) := by
      rw [hL, List.getElem?_append_left (by omega)] at ha; exact ha
    exact ⟨s, a, stp, x, y, hx, hy, hs, hr, by rw [hf, hl], hnr, ha', by rw [hl]; exact hm⟩

/-- C59 refined: the wild/collision or initial-collision event of H1' is a coin
    collision or a key collision. -/
theorem coll_event_key (N S : Nat) (hS : ∀ t s stp, (strace t (gameS' v limits A (coinEx (params v).n))
      (coinSt (params v).n))[s]? = some stp → s < S ∧ stp.1.ents.length ≤ S) (hSN : S ≤ N) (t : List Nat)
    (h : (wildCollP (params v).n (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) N t ||
      initColl t (coinSt (params v).n)) = true) :
    CoinColl (params v).n t ∨ KeyColl (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) (params v).n t := by
  rcases Bool.or_eq_true_iff.mp h with h | h
  · right
    simp only [wildCollP, List.any_eq_true, List.mem_range] at h
    obtain ⟨s, _, hs⟩ := h
    cases hst : (strace t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n))[s]? with
    | none => rw [hst] at hs; cases hs
    | some stp =>
      rw [hst] at hs
      simp only [Bool.and_eq_true, List.any_eq_true, Bool.or_eq_true] at hs
      obtain ⟨hnd, x, hx, hcw⟩ := hs
      have hnd' : NoDisTo t (strace t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)) s := by
        intro s' stp' hlt hs'
        simp only [noDisB, List.all_eq_true, Bool.not_eq_true'] at hnd
        exact hnd stp' (by
          rw [List.mem_iff_getElem?]
          exact ⟨s', by rw [List.getElem?_take, if_pos hlt]; exact hs'⟩)
      obtain ⟨ρ, hρ⟩ := kg_root_shape t v
      obtain ⟨hI, hSt⟩ := game_struct (c := structCtx t v) rfl limits A s stp hst hnd'
      have hlen := (hS t s stp hst).2
      rcases hcw with hc | hw
      · obtain ⟨st, ev⟩ := stp
        cases ev with
        | c r =>
          obtain ⟨a, b, hk, he⟩ := collC_key (c := structCtx t v) ρ hρ hI hSt hx hc
          obtain ⟨hab, ⟨x1, hx1, ha⟩, ⟨y1, hy1, hb⟩⟩ := hk
          obtain ⟨L, hL⟩ := trace_final t _ _ s _ hst
          have hbl : b < st.ents.length := lt_entry hb
          have hfin : KeyEnts (params v).n (xrun false t (gameS' v limits A (coinEx (params v).n))
              (coinSt (params v).n)).2 a b := by
            refine ⟨hab, ⟨x1, hx1, ?_⟩, ⟨y1, hy1, ?_⟩⟩
            · rw [hL, List.getElem?_append_left (lt_entry ha)]; exact ha
            · rw [hL, List.getElem?_append_left hbl]; exact hb
          refine keyColl_of_fin v limits A t hfin he (fun s' stp' hs' hl' => ?_)
          have hlt : s' < s := by
            apply Nat.lt_of_not_le
            intro hge
            have := len_mono _ _ t hge hst hs'
            simp only at this
            omega
          exact fun s'' stp'' h'' hs'' => hnd' s'' stp'' (by omega) hs''
        | a q => simp [collC] at hc
        | r x => simp [collC] at hc
      · exfalso
        have h0 := wildE_false (c := structCtx t v) ρ hρ hI hSt (params v).n N (Nat.le_refl _)
          (show (params v).n ≤ 32 by cases v <;> decide) (by omega) hx
        have h1 : wildE (params v).n N t stp.1 stp.2 x = false := h0
        rw [h1] at hw; cases hw
  · left
    obtain ⟨a, b, hab, hb, hc⟩ := initColl_coin _ t h
    exact ⟨a, b, hab, hb, hc⟩

/-- C60 refined: a canonical collision outside the disagreement tapes is a pinned pair or
    a key collision. -/
theorem canon_split_key (t : List Nat) (S N : Nat)
    (hS : ∀ (s : Nat) (stp : St × Ev), (strace t (gameS' v limits A (coinEx (params v).n))
      (coinSt (params v).n))[s]? = some stp → s < S ∧ stp.1.ents.length ≤ S) (hSN : S < N) (h3N : 3 ≤ N)
    (hnd : anyDis (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) t = false)
    (hc : CanonCollIn (finO' v limits A t) (params v) (expTk (finO' v limits A t) v (sres t (coinEx (params v).n)))
        (expPrf (finO' v limits A t) v (sres t (coinEx (params v).n))) (expSeed v (sres t (coinEx (params v).n)))
        (verifyLog (finO' v limits A t) v (finKey v limits A t).1 (runG v limits A t).1.msg
          (runG v limits A t).1.sig)) :
    (∃ i ∈ idx S N, pairW (params v).n (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) i t = 1 ∧
      t.getD i.2.2 0 % 256^(params v).n =
        pairTg (params v).n (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) i t % 256^(params v).n) ∨
    KeyColl (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) (params v).n t := by
  rcases canon_split v limits A t S N hS hSN h3N hnd hc with h | ⟨a, b, hk, hm⟩
  · exact Or.inl h
  · right
    refine keyColl_of_fin v limits A t hk hm (fun s' _ _ _ s'' stp'' _ hs'' => ?_)
    simp only [anyDis, List.any_eq_false] at hnd
    simpa using hnd stp'' (List.mem_of_getElem? hs'')

end

/-! The refined counts. -/

section
variable (v : Variant) (limits : Limits) (A : Bytes → RAdv)

/-- C59 refined: the wild/collision or initial-collision tapes of H1'. -/
theorem coll_count_key (R N S : Nat) (hRn : 256^(params v).n ∣ R) (hR : 256^32 ∣ R)
    (hS : ∀ t s stp, (strace t (gameS' v limits A (coinEx (params v).n))
      (coinSt (params v).n))[s]? = some stp → s < S ∧ stp.1.ents.length ≤ S) (hSN : S < N) (h3N : 3 ≤ N) :
    tsum R N (fun t => if wildCollP (params v).n (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) N t ||
        initColl t (coinSt (params v).n) then 1 else 0) * (256^(params v).n * 256^32) ≤
      R^N * 3 * 256^32 + R^N * 3 * 256^(params v).n := by
  have hpt : ∀ t, (if wildCollP (params v).n (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) N t ||
      initColl t (coinSt (params v).n) then 1 else 0) ≤ ind (CoinColl (params v).n t) +
      ind (KeyColl (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) (params v).n t) := by
    intro t
    split
    · rename_i h
      rcases coll_event_key v limits A N S hS (Nat.le_of_lt hSN) t h with h | h
      · rw [ind_of h]; omega
      · rw [ind_of h]; omega
    · exact Nat.zero_le _
  have hT := tsum_mono R N hpt
  rw [tsum_add] at hT
  have h1 := coin_count R N (params v).n hRn h3N
  have h2 := key_count (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) (params v).n R N S hR
    (coin_not_key _) hS hSN
  calc _ ≤ (tsum R N (fun t => ind (CoinColl (params v).n t)) +
        tsum R N (fun t => ind (KeyColl (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) (params v).n t))) *
        (256^(params v).n * 256^32) := Nat.mul_le_mul_right _ hT
    _ = tsum R N (fun t => ind (CoinColl (params v).n t)) * 256^(params v).n * 256^32 +
        tsum R N (fun t => ind (KeyColl (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) (params v).n t)) *
          256^32 * 256^(params v).n := by
        rw [Nat.add_mul, ← Nat.mul_assoc, Nat.mul_comm (256^(params v).n) (256^32), ← Nat.mul_assoc]
    _ ≤ R^N * 3 * 256^32 + R^N * 3 * 256^(params v).n :=
        Nat.add_le_add (Nat.mul_le_mul_right _ h1) (Nat.mul_le_mul_right _ h2)

/-- C60 refined: canonical collisions outside the disagreement tapes of H1'. -/
theorem canon_count_key (R N S AA : Nat) (hRn : 256^(params v).n ∣ R) (hR : 256^32 ∣ R)
    (hS : ∀ t (s : Nat) (stp : St × Ev), (strace t (gameS' v limits A (coinEx (params v).n))
      (coinSt (params v).n))[s]? = some stp → s < S ∧ stp.1.ents.length ≤ S) (hSN : S < N) (h3N : 3 ≤ N)
    (hA : ∀ t, ((strace t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)).filter isAev).length ≤ AA) :
    tsum R N (fun t => ind (CanonCollIn (finO' v limits A t) (params v)
        (expTk (finO' v limits A t) v (sres t (coinEx (params v).n)))
        (expPrf (finO' v limits A t) v (sres t (coinEx (params v).n))) (expSeed v (sres t (coinEx (params v).n)))
        (verifyLog (finO' v limits A t) v (finKey v limits A t).1 (runG v limits A t).1.msg
          (runG v limits A t).1.sig) ∧
        anyDis (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) t = false)) *
      (256^(params v).n * 256^32) ≤
    R^N * AA * 256^32 + R^N * 3 * 256^(params v).n := by
  let H := fun t : List Nat => ((idx S N).map (fun i => pairW (params v).n (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) i t *
    (if t.getD i.2.2 0 % 256^(params v).n == pairTg (params v).n (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) i t % 256^(params v).n then 1 else 0))).sum
  let K := fun t : List Nat => KeyColl (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) (params v).n t
  have hpt : ∀ t, ind (CanonCollIn (finO' v limits A t) (params v)
        (expTk (finO' v limits A t) v (sres t (coinEx (params v).n)))
        (expPrf (finO' v limits A t) v (sres t (coinEx (params v).n))) (expSeed v (sres t (coinEx (params v).n)))
        (verifyLog (finO' v limits A t) v (finKey v limits A t).1 (runG v limits A t).1.msg
          (runG v limits A t).1.sig) ∧
        anyDis (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) t = false) ≤ H t + ind (K t) := by
    intro t
    by_cases hev : CanonCollIn (finO' v limits A t) (params v)
        (expTk (finO' v limits A t) v (sres t (coinEx (params v).n)))
        (expPrf (finO' v limits A t) v (sres t (coinEx (params v).n))) (expSeed v (sres t (coinEx (params v).n)))
        (verifyLog (finO' v limits A t) v (finKey v limits A t).1 (runG v limits A t).1.msg
          (runG v limits A t).1.sig) ∧
        anyDis (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) t = false
    · rw [ind_of hev]
      rcases canon_split_key v limits A t S N (hS t) hSN h3N hev.2 hev.1 with ⟨i, hi, hw, hh⟩ | hk
      · have : 1 ∈ (idx S N).map (fun i => pairW (params v).n (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) i t *
            (if t.getD i.2.2 0 % 256^(params v).n == pairTg (params v).n (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) i t % 256^(params v).n then 1 else 0)) :=
          List.mem_map.mpr ⟨i, hi, by simp only [hw, hh]; simp⟩
        exact Nat.le_trans (le_sum_of_mem this) (Nat.le_add_right _ _)
      · rw [ind_of (P := K t) hk]; omega
    · rw [ind_of_not hev]; exact Nat.zero_le _
  have hMn : 0 < 256^(params v).n := Nat.pow_pos (by decide)
  have hix : ∀ i ∈ idx S N, i.2.2 < N := fun i hi => by
    simp only [idx, List.mem_flatMap, List.mem_range, List.mem_map] at hi
    obtain ⟨_, _, _, _, h, hh, rfl⟩ := hi
    exact hh
  have hh := hits_sum R (256^(params v).n) N hMn hRn (idx S N) (fun i => i.2.2) hix
    (fun i t => pairW (params v).n (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) i t) (pairTg (params v).n (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n))
    (fun i _ t y => pairW_inv (params v).n (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) i t y)
    (fun i _ t y hw => pairTg_inv (params v).n (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) i t y hw)
  have hsum : tsum R N (fun t => ((idx S N).map (fun i => pairW (params v).n (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) i t)).sum) ≤ R^N * AA := by
    rw [← tsum_const]
    exact tsum_mono R N (fun t => Nat.le_trans (pair_count (params v).n (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) S N t) (hA t))
  have hk := key_count (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) (params v).n R N S hR
    (coin_not_key _) hS hSN
  have hT := tsum_mono R N hpt
  rw [tsum_add] at hT
  calc _ ≤ (tsum R N H + tsum R N (fun t => ind (K t))) * (256^(params v).n * 256^32) := Nat.mul_le_mul_right _ hT
    _ = tsum R N H * 256^(params v).n * 256^32 + tsum R N (fun t => ind (K t)) * 256^32 * 256^(params v).n := by
        rw [Nat.add_mul, ← Nat.mul_assoc, Nat.mul_comm (256^(params v).n) (256^32), ← Nat.mul_assoc]
    _ ≤ R^N * AA * 256^32 + R^N * 3 * 256^(params v).n :=
        Nat.add_le_add (Nat.mul_le_mul_right _ (Nat.le_trans hh hsum)) (Nat.mul_le_mul_right _ hk)

end

end DSM.Rom
