-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomSym

/- Symbolic runs: the hidden-value bridge, part 2 (the bound).

   A step of the symbolic run disagrees with the real oracle on an entry in
   one of two ways (`dis_entry`):
   * a guess: a request `X` with an unrevealed handle resolves to bytes `Y`
     the run has already fixed (an adversary request, or the resolution of an
     open request), `cand`;
   * a collision `collC`: two syntactically distinct challenger requests,
     neither open, resolve to the same request.
   A guess pins the tape entry of `X`'s first unrevealed handle `h` (width
   `w`) to the bytes of `Y` at that handle's offset. The run up to that step
   never reads entry `h` (`strace_inv`), so by `hits_sum` the total guess
   weight is at most `B / 256^wmin`, where `B` bounds the number of
   (step, entry) pairs that are compatible guesses (`pairCount`). Guesses at
   a handle narrower than `wmin` or beyond the tape (`wildE`) are kept as a
   separate event. `real_le_sym` turns this into: every event of the real
   run has probability at most its symbolic probability plus the
   disagreement probability. -/
namespace DSM.Rom
open DSM.Sphincs

/-! Handle occurrences and their byte offsets. -/

def occs : List SV → Nat → List (Nat × Nat × Nat)
  | [], _ => []
  | .lit b :: x, o => occs x (o + b.length)
  | .hid i w :: x, o => (i, w, o) :: occs x (o + w)

theorem occ_slice (t : List Nat) : ∀ (x : List SV) (o : Nat) (p : Bytes), p.length = o →
    ∀ e ∈ occs x o, slice (p ++ sres t x) e.2.2 e.2.1 = be e.2.1 (t.getD e.1 0)
  | [], _, _, _, e, he => by simp [occs] at he
  | .lit b :: x, o, p, hp, e, he => by
    simp only [occs] at he
    simp only [sres, SV.res, ← List.append_assoc]
    exact occ_slice t x (o + b.length) (p ++ b) (by simp [hp]) e he
  | .hid i w :: x, o, p, hp, e, he => by
    simp only [occs, List.mem_cons] at he
    rcases he with rfl | he
    · simp only [sres, SV.res, slice]
      rw [List.drop_left' hp]
      exact List.take_left' (be_width w _)
    · simp only [sres, SV.res, ← List.append_assoc]
      exact occ_slice t x (o + w) (p ++ be w (t.getD i 0)) (by simp [hp, be_width]) e he

theorem shids_occs : ∀ (x : List SV) (o : Nat), shids x = (occs x o).map Prod.fst
  | [], _ => rfl
  | .lit b :: x, o => by simp only [shids, occs]; exact shids_occs x _
  | .hid i w :: x, o => by simp only [shids, occs, List.map_cons]; rw [shids_occs x (o+w)]

def firstOut (rev : List Nat) : List (Nat × Nat × Nat) → Option (Nat × Nat × Nat)
  | [] => none
  | e :: l => if e.1 ∈ rev then firstOut rev l else some e

theorem firstOut_some (rev : List Nat) : ∀ (l : List (Nat × Nat × Nat)) (e : Nat × Nat × Nat),
    firstOut rev l = some e → e ∈ l ∧ e.1 ∉ rev
  | [], _, h => by simp [firstOut] at h
  | a :: l, e, h => by
    simp only [firstOut] at h
    split at h
    · have := firstOut_some rev l e h
      exact ⟨List.mem_cons_of_mem _ this.1, this.2⟩
    · next hn =>
      obtain rfl := Option.some.inj h
      exact ⟨by simp, hn⟩

theorem firstOut_none (rev : List Nat) : ∀ (l : List (Nat × Nat × Nat)),
    firstOut rev l = none → ∀ e ∈ l, e.1 ∈ rev
  | [], _, e, he => by simp at he
  | a :: l, h, e, he => by
    simp only [firstOut] at h
    split at h
    · next ha =>
      simp only [List.mem_cons] at he
      rcases he with rfl | he
      · exact ha
      · exact firstOut_none rev l h e he
    · cases h

/-- The first unrevealed handle of a request: (handle, width, in key?, offset). -/
def firstHidden (rev : List Nat) (r : SReq) : Option (Nat × Nat × Bool × Nat) :=
  match firstOut rev (occs r.key 0), firstOut rev (occs r.input 0) with
  | some e, _ => some (e.1, e.2.1, true, e.2.2)
  | none, some e => some (e.1, e.2.1, false, e.2.2)
  | none, none => none

theorem firstHidden_some (rev : List Nat) (r : SReq) (v : Nat × Nat × Bool × Nat)
    (h : firstHidden rev r = some v) :
    v.1 ∉ rev ∧ (v.1, v.2.1, v.2.2.2) ∈ occs (if v.2.2.1 then r.key else r.input) 0 := by
  unfold firstHidden at h
  cases hk : firstOut rev (occs r.key 0) with
  | some e =>
    rw [hk] at h
    obtain rfl := Option.some.inj h
    have := firstOut_some rev _ e hk
    exact ⟨this.2, by simpa using this.1⟩
  | none =>
    cases hi : firstOut rev (occs r.input 0) with
    | some e =>
      rw [hk, hi] at h
      obtain rfl := Option.some.inj h
      have := firstOut_some rev _ e hi
      exact ⟨this.2, by simpa using this.1⟩
    | none => rw [hk, hi] at h; cases h

theorem firstHidden_of_not_open (rev : List Nat) (r : SReq) (h : isOpen rev r = false) :
    ∃ v, firstHidden rev r = some v := by
  cases hf : firstHidden rev r with
  | some v => exact ⟨v, rfl⟩
  | none =>
    exfalso
    unfold firstHidden at hf
    cases hk : firstOut rev (occs r.key 0) with
    | some e => rw [hk] at hf; cases hf
    | none =>
      cases hi : firstOut rev (occs r.input 0) with
      | some e => rw [hk, hi] at hf; cases hf
      | none =>
        have ak := firstOut_none rev _ hk
        have ai := firstOut_none rev _ hi
        have ho : isOpen rev r = true := by
          simp only [isOpen, List.all_eq_true, decide_eq_true_eq, SReq.hids, List.mem_append]
          intro i hi'
          rcases hi' with hk' | hi'
          · rw [shids_occs _ 0] at hk'
            obtain ⟨e, he, rfl⟩ := List.mem_map.mp hk'
            exact ak e he
          · rw [shids_occs _ 0] at hi'
            obtain ⟨e, he, rfl⟩ := List.mem_map.mp hi'
            exact ai e he
        rw [ho] at h; cases h

/-- A guess pins the tape entry of the first unrevealed handle. -/
theorem guess_pins (t rev : List Nat) (X : SReq) (Y : Request) (v : Nat × Nat × Bool × Nat)
    (hXY : X.res t = Y) (hv : firstHidden rev X = some v) :
    t.getD v.1 0 % 256^v.2.1 =
      toInt (slice (if v.2.2.1 then Y.key else Y.input) v.2.2.2 v.2.1) % 256^v.2.1 := by
  have hmem := (firstHidden_some rev X v hv).2
  have hs := occ_slice t _ 0 [] rfl _ hmem
  simp only [List.nil_append] at hs
  have hf : sres t (if v.2.2.1 then X.key else X.input) = (if v.2.2.1 then Y.key else Y.input) := by
    subst hXY; cases v.2.2.1 <;> rfl
  rw [hf] at hs
  rw [hs, be_mod, be_roundtrip _ _ (Nat.mod_lt _ (Nat.pow_pos (by decide : 0 < 256))), Nat.mod_mod]

/-! Compatibility: the literal parts of a request agree with given bytes. -/

def patMatch : List SV → Bytes → Bool
  | [], b => b.isEmpty
  | .lit l :: x, b => decide (b.take l.length = l) && patMatch x (b.drop l.length)
  | .hid _ w :: x, b => decide (w ≤ b.length) && patMatch x (b.drop w)

theorem patMatch_sres (t : List Nat) : ∀ x : List SV, patMatch x (sres t x) = true
  | [] => rfl
  | .lit l :: x => by
    simp only [patMatch, sres, SV.res, List.take_left' rfl, List.drop_left' rfl, patMatch_sres t x]
    simp
  | .hid i w :: x => by
    simp only [patMatch, sres, SV.res]
    rw [List.drop_left' (be_width w _), patMatch_sres t x]
    simp [be_width]

/-- `Y` could be a resolution of `X`. -/
def compat (X : SReq) (Y : Request) : Bool :=
  decide (X.mode = Y.mode) && decide (X.context = Y.context) && decide (X.outLen = Y.outLen) &&
    patMatch X.key Y.key && patMatch X.input Y.input

theorem compat_of_res (t : List Nat) (X : SReq) (Y : Request) (h : X.res t = Y) : compat X Y = true := by
  subst h; simp [compat, SReq.res, patMatch_sres]

/-! Guesses and collisions at a step. -/

/-- The guess a step makes against entry `e`: a request with an unrevealed
    handle and the bytes it is compared with. -/
def cand (t : List Nat) (st : St) (ev : Ev) (e : Bool × SReq) : Option (SReq × Request) :=
  match ev with
  | .a q => if isOpen st.rev e.2 then none else some (e.2, q)
  | .c r =>
    if e.2 = r then none
    else if isOpen st.rev e.2 then (if isOpen st.rev r then none else some (r, e.2.res t))
    else if isOpen st.rev r then some (e.2, r.res t) else none
  | .r _ => none

/-- Two distinct challenger requests, neither open, with equal resolutions. -/
def collC (t : List Nat) (st : St) (ev : Ev) (e : Bool × SReq) : Bool :=
  match ev with
  | .c r => !decide (e.2 = r) && !isOpen st.rev e.2 && !isOpen st.rev r && decide (e.2.res t = r.res t)
  | _ => false

theorem cand_set (t : List Nat) (h y : Nat) (st : St) (ev : Ev) (e : Bool × SReq)
    (hh : h ∉ st.rev) : cand (t.set h y) st ev e = cand t st ev e := by
  cases ev with
  | a q => rfl
  | r x => rfl
  | c r =>
    simp only [cand]
    by_cases h0 : e.2 = r
    · simp [h0]
    · rw [if_neg h0, if_neg h0]
      cases h1 : isOpen st.rev e.2
      · cases h2 : isOpen st.rev r
        · rfl
        · simp [open_res t h y st.rev r h2 hh]
      · cases h2 : isOpen st.rev r
        · simp [open_res t h y st.rev e.2 h1 hh]
        · rfl

theorem cand_not_open (t : List Nat) (st : St) (ev : Ev) (e : Bool × SReq) (XY : SReq × Request)
    (h : cand t st ev e = some XY) : isOpen st.rev XY.1 = false := by
  cases ev with
  | r x => cases h
  | a q =>
    simp only [cand] at h
    split at h
    · cases h
    · next ho => obtain rfl := Option.some.inj h; simpa using ho
  | c r =>
    simp only [cand] at h
    split at h
    · cases h
    · split at h
      · split at h
        · cases h
        · next ho => obtain rfl := Option.some.inj h; simpa using ho
      · next ho =>
        split at h
        · obtain rfl := Option.some.inj h; simpa using ho
        · cases h

/-- Every disagreement is a successful guess or a collision. -/
theorem dis_entry (t : List Nat) (st : St) (ev : Ev) (hd : dis t (st, ev) = true) :
    ∃ e ∈ st.ents, (∃ XY, cand t st ev e = some XY ∧ XY.1.res t = XY.2) ∨ collC t st ev e = true := by
  cases ev with
  | r x => simp [dis] at hd
  | a q =>
    simp only [dis, List.any_eq_true] at hd
    obtain ⟨e, he, hne⟩ := hd
    refine ⟨e, he, Or.inl ?_⟩
    cases ho : isOpen st.rev e.2
    · refine ⟨(e.2, q), by simp [cand, ho], ?_⟩
      simp only [mA, ho] at hne
      simpa using hne
    · simp [mA, ho] at hne
  | c r =>
    simp only [dis, List.any_eq_true] at hd
    obtain ⟨e, he, hne⟩ := hd
    refine ⟨e, he, ?_⟩
    simp only [mC] at hne
    by_cases h0 : e.2 = r
    · simp [h0] at hne
    · have hres : e.2.res t = r.res t := by
        cases h1 : isOpen st.rev e.2 <;> cases h2 : isOpen st.rev r <;> simp_all
      cases h1 : isOpen st.rev e.2
      · cases h2 : isOpen st.rev r
        · exact Or.inr (by simp [collC, h0, h1, h2, hres])
        · exact Or.inl ⟨(e.2, r.res t), by simp [cand, h0, h1, h2], hres⟩
      · cases h2 : isOpen st.rev r
        · exact Or.inl ⟨(r, e.2.res t), by simp [cand, h0, h1, h2], hres.symm⟩
        · simp [h0, h1, h2, hres] at hne

/-! Probes: a compatible guess at step `s` against entry `j`, with the handle
    it pins and the value it pins it to. -/

def probeAt (wmin : Nat) (t : List Nat) (stp : St × Ev) (j : Nat) : Option (Nat × Nat) :=
  match stp.1.ents[j]? with
  | none => none
  | some e => match cand t stp.1 stp.2 e with
    | none => none
    | some XY => match firstHidden stp.1.rev XY.1 with
      | none => none
      | some v => if wmin ≤ v.2.1 ∧ compat XY.1 XY.2 = true then
          some (v.1, toInt (slice (if v.2.2.1 then XY.2.key else XY.2.input) v.2.2.2 v.2.1))
        else none

theorem probeAt_set (wmin : Nat) (t : List Nat) (h y : Nat) (stp : St × Ev) (j : Nat)
    (hh : h ∉ stp.1.rev) : probeAt wmin (t.set h y) stp j = probeAt wmin t stp j := by
  have hc : ∀ e, cand (t.set h y) stp.1 stp.2 e = cand t stp.1 stp.2 e :=
    fun e => cand_set t h y stp.1 stp.2 e hh
  simp only [probeAt, hc]

theorem probeAt_some (wmin : Nat) (t : List Nat) (stp : St × Ev) (j : Nat) (v : Nat × Nat)
    (hp : probeAt wmin t stp j = some v) : v.1 ∉ stp.1.rev := by
  simp only [probeAt] at hp
  split at hp
  · cases hp
  · split at hp
    · cases hp
    · split at hp
      · cases hp
      · next fv hfv =>
        split at hp
        · obtain rfl := Option.some.inj hp
          exact (firstHidden_some _ _ fv hfv).1
        · cases hp

section
variable {α : Type} (wmin : Nat) (P : Prog α) (st0 : St)

def probe (t : List Nat) (s j : Nat) : Option (Nat × Nat) :=
  ((strace t P st0)[s]?).bind (fun stp => probeAt wmin t stp j)

theorem probe_inv (t : List Nat) (s j : Nat) (v : Nat × Nat) (y : Nat)
    (hp : probe wmin P st0 t s j = some v) : probe wmin P st0 (t.set v.1 y) s j = some v := by
  unfold probe at hp ⊢
  cases hs : (strace t P st0)[s]? with
  | none => rw [hs] at hp; cases hp
  | some stp =>
    rw [hs] at hp
    simp only [Option.bind_some] at hp
    have hh := probeAt_some wmin t stp j v hp
    have ht := strace_inv t v.1 y P st0 s stp hs hh
    have hs' : (strace (t.set v.1 y) P st0)[s]? = some stp := by
      have := congrArg (fun l => l[s]?) ht
      simp only [List.getElem?_take, Nat.lt_succ_self, if_true] at this
      rw [this, hs]
    rw [hs']
    simp only [Option.bind_some]
    rw [probeAt_set wmin t v.1 y stp j hh, hp]

theorem probe_back (t : List Nat) (s j h y : Nat) (v : Nat × Nat) (hv : v.1 = h)
    (hp : probe wmin P st0 (t.set h y) s j = some v) : probe wmin P st0 t s j = some v := by
  have := probe_inv wmin P st0 (t.set h y) s j v (t.getD h 0) hp
  rwa [hv, set_set_back] at this

/-- Weight of index (s, j, h): the probe at (s, j) pins handle `h`. -/
def wt (t : List Nat) (i : Nat × Nat × Nat) : Nat :=
  if (probe wmin P st0 t i.1 i.2.1).map Prod.fst = some i.2.2 then 1 else 0
/-- Target of index (s, j, h). -/
def tg (i : Nat × Nat × Nat) (t : List Nat) : Nat :=
  ((probe wmin P st0 t i.1 i.2.1).map Prod.snd).getD 0

theorem wt_inv (i : Nat × Nat × Nat) (t : List Nat) (y : Nat) :
    wt wmin P st0 (t.set i.2.2 y) i = wt wmin P st0 t i := by
  unfold wt
  by_cases ha : (probe wmin P st0 t i.1 i.2.1).map Prod.fst = some i.2.2
  · rw [if_pos ha]
    cases hp : probe wmin P st0 t i.1 i.2.1 with
    | none => rw [hp] at ha; cases ha
    | some v =>
      rw [hp] at ha
      have hv : v.1 = i.2.2 := Option.some.inj ha
      have := probe_inv wmin P st0 t i.1 i.2.1 v y hp
      rw [hv] at this
      rw [this]; simp [hv]
  · rw [if_neg ha, if_neg]
    intro hb
    apply ha
    cases hp : probe wmin P st0 (t.set i.2.2 y) i.1 i.2.1 with
    | none => rw [hp] at hb; cases hb
    | some v =>
      rw [hp] at hb
      have hv : v.1 = i.2.2 := Option.some.inj hb
      rw [probe_back wmin P st0 t i.1 i.2.1 i.2.2 y v hv hp]
      simp [hv]

theorem tg_inv (i : Nat × Nat × Nat) (t : List Nat) (y : Nat) (hw : wt wmin P st0 t i ≠ 0) :
    tg wmin P st0 i (t.set i.2.2 y) = tg wmin P st0 i t := by
  unfold wt at hw
  unfold tg
  cases hp : probe wmin P st0 t i.1 i.2.1 with
  | none => rw [hp] at hw; simp at hw
  | some v =>
    rw [hp] at hw
    have hv : v.1 = i.2.2 := by simpa using hw
    have := probe_inv wmin P st0 t i.1 i.2.1 v y hp
    rw [hv] at this
    rw [this]

/-- The number of (step, entry) pairs below `S` that are compatible guesses. -/
def pairCount (S : Nat) (t : List Nat) : Nat :=
  ((List.range S).map (fun s => ((List.range S).map (fun j =>
    if (probe wmin P st0 t s j).isSome then 1 else 0)).sum)).sum

/-- Guesses at a narrow or out-of-tape handle, and collisions. -/
def wildE (N : Nat) (t : List Nat) (st : St) (ev : Ev) (e : Bool × SReq) : Bool :=
  match cand t st ev e with
  | none => false
  | some XY => match firstHidden st.rev XY.1 with
    | none => false
    | some v => !(decide (wmin ≤ v.2.1) && decide (v.1 < N))

def wildColl (N : Nat) (t : List Nat) : Bool :=
  (strace t P st0).any (fun stp => stp.1.ents.any (fun e =>
    collC t stp.1 stp.2 e || wildE wmin N t stp.1 stp.2 e))

def anyDis (t : List Nat) : Bool := (strace t P st0).any (dis t)

def idx (S N : Nat) : List (Nat × Nat × Nat) :=
  (List.range S).flatMap (fun s => (List.range S).flatMap (fun j => (List.range N).map (fun h => (s, j, h))))
end

theorem sum_flatMap {β γ : Type} (l : List β) (f : β → List γ) (g : γ → Nat) :
    ((l.flatMap f).map g).sum = (l.map (fun a => ((f a).map g).sum)).sum := by
  induction l with
  | nil => rfl
  | cons a l ih => simp only [List.flatMap_cons, List.map_append, sum_append', ih, List.map_cons, List.sum_cons]

theorem sum_pin (N : Nat) (o : Option (Nat × Nat)) :
    ((List.range N).map (fun h => if o.map Prod.fst = some h then 1 else 0)).sum ≤
      if o.isSome then 1 else 0 := by
  cases o with
  | none => simp; exact sum_map_zero _
  | some v =>
    have e : (fun h => if (some v).map Prod.fst = some h then 1 else 0) =
        (fun h => if (h == v.1) = true then 1 else 0) := by
      funext h
      by_cases hh : h = v.1
      · simp [hh]
      · have hh' : v.1 ≠ h := fun e => hh e.symm
        simp [hh, hh']
    rw [e, ← len_filter_eq_sum]
    simpa using filter_eq_le_one (List.range N) List.nodup_range v.1

section
variable {α : Type} (wmin : Nat) (P : Prog α) (st0 : St)

theorem idx_sum_le (S N : Nat) (t : List Nat) :
    ((idx S N).map (fun i => wt wmin P st0 t i)).sum ≤ pairCount wmin P st0 S t := by
  unfold idx pairCount
  rw [sum_flatMap]
  apply sum_map_le; intro s _
  rw [sum_flatMap]
  apply sum_map_le; intro j _
  refine Nat.le_trans (Nat.le_of_eq ?_) (sum_pin N (probe wmin P st0 t s j))
  rw [List.map_map]
  congr 1

/-- Pointwise: a disagreement is a pinned guess at some index, or wild. -/
theorem dis_point (S N : Nat)
    (hS : ∀ t s stp, (strace t P st0)[s]? = some stp → s < S ∧ stp.1.ents.length ≤ S) (t : List Nat) :
    (if anyDis P st0 t then 1 else 0) ≤
      ((idx S N).map (fun i => wt wmin P st0 t i *
        (if t.getD i.2.2 0 % 256^wmin == tg wmin P st0 i t % 256^wmin then 1 else 0))).sum +
      (if wildColl wmin P st0 N t then 1 else 0) := by
  cases had : anyDis P st0 t
  · simp
  · simp only [if_true]
    cases hw : wildColl wmin P st0 N t
    · simp only [Bool.false_eq_true, if_false, Nat.add_zero]
      simp only [anyDis, List.any_eq_true] at had
      obtain ⟨stp, hstp, hd⟩ := had
      obtain ⟨s, hs⟩ := List.mem_iff_getElem?.mp hstp
      obtain ⟨e, he, hk⟩ := dis_entry t stp.1 stp.2 hd
      obtain ⟨j, hj⟩ := List.mem_iff_getElem?.mp he
      simp only [wildColl, List.any_eq_false] at hw
      have hwe := hw stp hstp
      simp only [List.any_eq_true, not_exists, not_and, Bool.or_eq_true] at hwe
      have hwe' := hwe e he
      rcases hk with ⟨XY, hc, hres⟩ | hcoll
      · have hno := cand_not_open t stp.1 stp.2 e XY hc
        obtain ⟨v, hv⟩ := firstHidden_of_not_open _ _ hno
        have hwild : wmin ≤ v.2.1 ∧ v.1 < N := by
          by_cases hn : wmin ≤ v.2.1 ∧ v.1 < N
          · exact hn
          · exfalso
            apply hwe'
            right
            simp only [wildE, hc, hv]
            simp; omega
        have hcompat := compat_of_res t XY.1 XY.2 hres
        have hpa : probeAt wmin t stp j = some (v.1, toInt (slice (if v.2.2.1 then XY.2.key else XY.2.input) v.2.2.2 v.2.1)) := by
          simp only [probeAt, hj, hc, hv, hwild.1, hcompat, and_self, if_true]
        have hp : probe wmin P st0 t s j = some (v.1, toInt (slice (if v.2.2.1 then XY.2.key else XY.2.input) v.2.2.2 v.2.1)) := by
          simp only [probe, hs, Option.bind_some, hpa]
        have hpin := guess_pins t stp.1.rev XY.1 XY.2 v hres hv
        have hdvd : 256^wmin ∣ 256^v.2.1 := Nat.pow_dvd_pow 256 hwild.1
        have hmod : t.getD v.1 0 % 256^wmin = toInt (slice (if v.2.2.1 then XY.2.key else XY.2.input) v.2.2.2 v.2.1) % 256^wmin := by
          rw [← Nat.mod_mod_of_dvd _ hdvd, hpin, Nat.mod_mod_of_dvd _ hdvd]
        have hbound := hS t s stp hs
        have hjlt : j < stp.1.ents.length := (List.getElem?_eq_some_iff.mp hj).1
        have hslt : s < (strace t P st0).length := (List.getElem?_eq_some_iff.mp hs).1
        have hmem : (s, j, v.1) ∈ idx S N := by
          simp only [idx, List.mem_flatMap, List.mem_range, List.mem_map]
          exact ⟨s, hbound.1, j, by omega, v.1, hwild.2, rfl⟩
        have hterm : wt wmin P st0 t (s, j, v.1) *
            (if t.getD (s, j, v.1).2.2 0 % 256^wmin == tg wmin P st0 (s, j, v.1) t % 256^wmin then 1 else 0) = 1 := by
          simp only [wt, tg, hp, Option.map_some, Option.getD_some, if_true, hmod]
          simp
        exact Nat.le_trans (Nat.le_of_eq hterm.symm)
          (le_sum_of_mem (List.mem_map.mpr ⟨(s, j, v.1), hmem, rfl⟩))
      · exfalso; exact hwe' (Or.inl hcoll)
    · rw [if_pos rfl]; exact Nat.le_add_left 1 _

/-- Hidden-value bound: the probability that the real and the symbolic run
    disagree at some step is at most `B / 256^wmin` plus the probability of a
    wild guess or a collision between unopened challenger requests. -/
theorem hidden_bound (R N S B : Nat) (hR : 256^wmin ∣ R)
    (hS : ∀ t s stp, (strace t P st0)[s]? = some stp → s < S ∧ stp.1.ents.length ≤ S)
    (hB : ∀ t, pairCount wmin P st0 S t ≤ B) :
    tsum R N (fun t => if anyDis P st0 t then 1 else 0) * 256^wmin ≤
      R^N * B + tsum R N (fun t => if wildColl wmin P st0 N t then 1 else 0) * 256^wmin := by
  have hM : 0 < 256^wmin := Nat.pow_pos (by decide)
  have hh := hits_sum R (256^wmin) N hM hR (idx S N) (fun i => i.2.2)
    (fun i hi => by
      simp only [idx, List.mem_flatMap, List.mem_range, List.mem_map] at hi
      obtain ⟨_, _, _, _, h, hh, rfl⟩ := hi
      exact hh)
    (fun i t => wt wmin P st0 t i) (tg wmin P st0)
    (fun i _ t y => wt_inv wmin P st0 i t y)
    (fun i _ t y hw => tg_inv wmin P st0 i t y hw)
  calc tsum R N (fun t => if anyDis P st0 t then 1 else 0) * 256^wmin
      ≤ tsum R N (fun t =>
          ((idx S N).map (fun i => wt wmin P st0 t i *
            (if t.getD i.2.2 0 % 256^wmin == tg wmin P st0 i t % 256^wmin then 1 else 0))).sum +
          (if wildColl wmin P st0 N t then 1 else 0)) * 256^wmin :=
        Nat.mul_le_mul_right _ (tsum_mono R N (dis_point wmin P st0 S N hS))
    _ = tsum R N (fun t =>
          ((idx S N).map (fun i => wt wmin P st0 t i *
            (if t.getD i.2.2 0 % 256^wmin == tg wmin P st0 i t % 256^wmin then 1 else 0))).sum) * 256^wmin +
        tsum R N (fun t => if wildColl wmin P st0 N t then 1 else 0) * 256^wmin := by
        rw [tsum_add, Nat.add_mul]
    _ ≤ tsum R N (fun t => ((idx S N).map (fun i => wt wmin P st0 t i)).sum) +
        tsum R N (fun t => if wildColl wmin P st0 N t then 1 else 0) * 256^wmin :=
        Nat.add_le_add_right hh _
    _ ≤ tsum R N (fun _ => B) + tsum R N (fun t => if wildColl wmin P st0 N t then 1 else 0) * 256^wmin :=
        Nat.add_le_add_right (tsum_mono R N (fun t => Nat.le_trans (idx_sum_le wmin P st0 S N t) (hB t))) _
    _ = R^N * B + tsum R N (fun t => if wildColl wmin P st0 N t then 1 else 0) * 256^wmin := by
        rw [tsum_const]

/-- Any event of the real run is at most as likely as in the symbolic run,
    plus the disagreement probability. -/
theorem real_le_sym (R N : Nat) (E : List Nat → α × St → Bool) :
    tsum R N (fun t => if E t (xrun true t P st0) then 1 else 0) ≤
      tsum R N (fun t => if E t (xrun false t P st0) then 1 else 0) +
      tsum R N (fun t => if anyDis P st0 t then 1 else 0) := by
  rw [← tsum_add]
  apply tsum_mono
  intro t
  cases hd : anyDis P st0 t
  · have hc : ∀ s ∈ strace t P st0, dis t s = false := by
      simp only [anyDis, List.any_eq_false] at hd
      intro s hs; simpa using hd s hs
    rw [coupling t P st0 hc]; simp
  · split <;> simp
end

#print axioms hidden_bound
#print axioms real_le_sym
end DSM.Rom
