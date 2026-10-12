-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomCoord
import Sphincs.RomRoles

/- Symbolic runs: the hidden-value bridge, part 1 (semantics and coupling).

   A game is a program `Prog` with three kinds of step: a challenger oracle
   request `askC` whose fields may contain handles `hid i w` (the answer of
   tape entry `i` truncated to `w` bytes), an adversary request `askA` with
   concrete bytes, and `reveal`, which resolves bytes to the adversary (or to
   challenger control flow) and marks their handles revealed.

   `xrun true` is the real lazily sampled random oracle on resolved requests:
   a request is answered from the first entry whose resolution equals it,
   otherwise from the next tape entry. `xrun false` is the symbolic run: a
   challenger request matches an entry only when the two are syntactically
   equal or both are open (every handle revealed) with equal resolutions; an
   adversary request matches only open entries. The symbolic run reads the
   tape only at revealed handles (`strace_inv`), so an unrevealed answer is
   independent of everything the run has done. `coupling`: when no step's
   real and symbolic lookups disagree, the two runs are equal. -/
namespace DSM.Rom
open DSM.Sphincs

inductive SV where
  | lit (b : Bytes)
  | hid (i w : Nat)
  deriving DecidableEq

def SV.res (t : List Nat) : SV → Bytes
  | .lit b => b
  | .hid i w => be w (t.getD i 0)

def sres (t : List Nat) : List SV → Bytes
  | [] => []
  | v :: x => v.res t ++ sres t x

def shids : List SV → List Nat
  | [] => []
  | .lit _ :: x => shids x
  | .hid i _ :: x => i :: shids x

structure SReq where
  mode : Nat
  context : String
  key : List SV
  input : List SV
  outLen : Nat
  deriving DecidableEq

def SReq.res (t : List Nat) (r : SReq) : Request :=
  ⟨r.mode, r.context, sres t r.key, sres t r.input, r.outLen⟩
def SReq.hids (r : SReq) : List Nat := shids r.key ++ shids r.input
/-- An adversary request as a symbolic request without handles. -/
def lift (q : Request) : SReq := ⟨q.mode, q.context, [.lit q.key], [.lit q.input], q.outLen⟩

/-- Every handle of `r` is revealed. -/
def isOpen (rev : List Nat) (r : SReq) : Bool := r.hids.all (fun i => decide (i ∈ rev))

theorem getD_set_ne (t : List Nat) (h i y : Nat) (hne : i ≠ h) :
    (t.set h y).getD i 0 = t.getD i 0 := by
  simp [List.getD_eq_getElem?_getD, Ne.symm hne]

theorem sres_set (t : List Nat) (h y : Nat) : ∀ (x : List SV), (∀ i ∈ shids x, i ≠ h) →
    sres (t.set h y) x = sres t x
  | [], _ => rfl
  | .lit b :: x, hx => by
    simp only [sres, SV.res]
    rw [sres_set t h y x (fun i hi => hx i (by simpa [shids] using hi))]
  | .hid i w :: x, hx => by
    simp only [sres, SV.res]
    rw [getD_set_ne t h i y (hx i (by simp [shids])),
      sres_set t h y x (fun j hj => hx j (by simp [shids, hj]))]

theorem open_res (t : List Nat) (h y : Nat) (rev : List Nat) (r : SReq) (ho : isOpen rev r = true)
    (hh : h ∉ rev) : r.res (t.set h y) = r.res t := by
  simp only [isOpen, List.all_eq_true, decide_eq_true_eq] at ho
  have hk : ∀ i ∈ shids r.key, i ≠ h := fun i hi he => hh (he ▸ ho i (by simp [SReq.hids, hi]))
  have hi : ∀ i ∈ shids r.input, i ≠ h := fun i hi he => hh (he ▸ ho i (by simp [SReq.hids, hi]))
  simp only [SReq.res, sres_set t h y _ hk, sres_set t h y _ hi]

inductive Prog (α : Type) where
  | done (a : α)
  | askC (r : SReq) (k : SV → Prog α)
  | askA (q : Request) (k : Bytes → Prog α)
  | reveal (x : List SV) (k : Bytes → Prog α)

/-- Oracle entries (tag: adversary side) and revealed handles. -/
structure St where
  ents : List (Bool × SReq)
  rev : List Nat

inductive Ev where
  | c (r : SReq)
  | a (q : Request)
  | r (x : List SV)

/-- Does entry `e` answer challenger request `r`? -/
def mC (real : Bool) (t rev : List Nat) (r : SReq) (e : Bool × SReq) : Bool :=
  if real then decide (e.2.res t = r.res t)
  else decide (e.2 = r) || (isOpen rev e.2 && isOpen rev r && decide (e.2.res t = r.res t))

/-- Does entry `e` answer adversary request `q`? -/
def mA (real : Bool) (t rev : List Nat) (q : Request) (e : Bool × SReq) : Bool :=
  if real then decide (e.2.res t = q) else isOpen rev e.2 && decide (e.2.res t = q)

/-- Index of the first entry satisfying `p`, or the length. -/
def firstIdx {β : Type} (p : β → Bool) : List β → Nat
  | [] => 0
  | b :: l => if p b then 0 else firstIdx p l + 1

def addC (st : St) (i : Nat) (r : SReq) : St :=
  if i < st.ents.length then st else ⟨st.ents ++ [(false, r)], st.rev⟩
def addA (st : St) (i : Nat) (q : Request) : St :=
  ⟨if i < st.ents.length then st.ents else st.ents ++ [(true, lift q)], i :: st.rev⟩

theorem addC_rev (st : St) (i : Nat) (r : SReq) : (addC st i r).rev = st.rev := by
  unfold addC; split <;> rfl

/-- Real (`true`) or symbolic (`false`) run. -/
def xrun {α : Type} (real : Bool) (t : List Nat) : Prog α → St → α × St
  | .done a, st => (a, st)
  | .askC r k, st =>
    xrun real t (k (.hid (firstIdx (mC real t st.rev r) st.ents) r.outLen))
      (addC st (firstIdx (mC real t st.rev r) st.ents) r)
  | .askA q k, st =>
    xrun real t (k (be q.outLen (t.getD (firstIdx (mA real t st.rev q) st.ents) 0)))
      (addA st (firstIdx (mA real t st.rev q) st.ents) q)
  | .reveal x k, st => xrun real t (k (sres t x)) ⟨st.ents, shids x ++ st.rev⟩

/-- The symbolic run's steps: the state before each step and the step. -/
def strace {α : Type} (t : List Nat) : Prog α → St → List (St × Ev)
  | .done _, _ => []
  | .askC r k, st =>
    (st, .c r) :: strace t (k (.hid (firstIdx (mC false t st.rev r) st.ents) r.outLen))
      (addC st (firstIdx (mC false t st.rev r) st.ents) r)
  | .askA q k, st =>
    (st, .a q) :: strace t (k (be q.outLen (t.getD (firstIdx (mA false t st.rev q) st.ents) 0)))
      (addA st (firstIdx (mA false t st.rev q) st.ents) q)
  | .reveal x k, st => (st, .r x) :: strace t (k (sres t x)) ⟨st.ents, shids x ++ st.rev⟩

/-- A step at which the real and the symbolic lookup disagree on some entry. -/
def dis (t : List Nat) (s : St × Ev) : Bool :=
  match s.2 with
  | .c r => s.1.ents.any (fun e => mC true t s.1.rev r e != mC false t s.1.rev r e)
  | .a q => s.1.ents.any (fun e => mA true t s.1.rev q e != mA false t s.1.rev q e)
  | .r _ => false

theorem firstIdx_congr {β : Type} (p p' : β → Bool) : ∀ (l : List β), (∀ b ∈ l, p b = p' b) →
    firstIdx p l = firstIdx p' l
  | [], _ => rfl
  | b :: l, h => by
    simp only [firstIdx]
    rw [h b (by simp), firstIdx_congr p p' l (fun c hc => h c (by simp [hc]))]

/-- Coupling: without a disagreeing step the real run equals the symbolic run. -/
theorem coupling {α : Type} (t : List Nat) : ∀ (P : Prog α) (st : St),
    (∀ s ∈ strace t P st, dis t s = false) → xrun true t P st = xrun false t P st
  | .done _, _, _ => rfl
  | .askC r k, st, h => by
    simp only [strace, List.mem_cons, forall_eq_or_imp] at h
    obtain ⟨h0, h⟩ := h
    have hi : firstIdx (mC true t st.rev r) st.ents = firstIdx (mC false t st.rev r) st.ents := by
      apply firstIdx_congr
      intro e he
      simp only [dis, List.any_eq_false] at h0
      simpa using h0 e he
    simp only [xrun]
    rw [hi]
    exact coupling t _ _ h
  | .askA q k, st, h => by
    simp only [strace, List.mem_cons, forall_eq_or_imp] at h
    obtain ⟨h0, h⟩ := h
    have hi : firstIdx (mA true t st.rev q) st.ents = firstIdx (mA false t st.rev q) st.ents := by
      apply firstIdx_congr
      intro e he
      simp only [dis, List.any_eq_false] at h0
      simpa using h0 e he
    simp only [xrun]
    rw [hi]
    exact coupling t _ _ h
  | .reveal x k, st, h => by
    simp only [strace, List.mem_cons, forall_eq_or_imp] at h
    simp only [xrun]
    exact coupling t _ _ h.2

/-- Revealed handles stay revealed. -/
theorem strace_rev_mono {α : Type} (t : List Nat) : ∀ (P : Prog α) (st : St),
    ∀ s ∈ strace t P st, ∀ x ∈ st.rev, x ∈ s.1.rev
  | .done _, _, s, hs, _, _ => by simp [strace] at hs
  | .askC r k, st, s, hs, x, hx => by
    simp only [strace, List.mem_cons] at hs
    rcases hs with rfl | hs
    · exact hx
    · exact strace_rev_mono t _ _ s hs x (by rw [addC_rev]; exact hx)
  | .askA q k, st, s, hs, x, hx => by
    simp only [strace, List.mem_cons] at hs
    rcases hs with rfl | hs
    · exact hx
    · exact strace_rev_mono t _ _ s hs x (by simp [addA, hx])
  | .reveal y k, st, s, hs, x, hx => by
    simp only [strace, List.mem_cons] at hs
    rcases hs with rfl | hs
    · exact hx
    · exact strace_rev_mono t _ _ s hs x (by simp [hx])

theorem mC_false_set (t : List Nat) (h y : Nat) (rev : List Nat) (r : SReq) (e : Bool × SReq)
    (hh : h ∉ rev) : mC false (t.set h y) rev r e = mC false t rev r e := by
  simp only [mC, Bool.false_eq_true, if_false]
  cases h1 : isOpen rev e.2
  · simp
  · cases h2 : isOpen rev r
    · simp
    · simp [open_res t h y rev _ h1 hh, open_res t h y rev _ h2 hh]

theorem mA_false_set (t : List Nat) (h y : Nat) (rev : List Nat) (q : Request) (e : Bool × SReq)
    (hh : h ∉ rev) : mA false (t.set h y) rev q e = mA false t rev q e := by
  simp only [mA, Bool.false_eq_true, if_false]
  cases h1 : isOpen rev e.2
  · simp
  · simp [open_res t h y rev _ h1 hh]

theorem mem_of_getElem? {β : Type} {l : List β} {i : Nat} {a : β} (h : l[i]? = some a) : a ∈ l := by
  obtain ⟨hi, he⟩ := List.getElem?_eq_some_iff.mp h
  exact he ▸ List.getElem_mem hi

/-- Invariance: while handle `h` is unrevealed, the symbolic run does not
    depend on tape entry `h`. -/
theorem strace_inv {α : Type} (t : List Nat) (h y : Nat) : ∀ (P : Prog α) (st : St) (s : Nat)
    (stp : St × Ev), (strace t P st)[s]? = some stp → h ∉ stp.1.rev →
    (strace (t.set h y) P st).take (s+1) = (strace t P st).take (s+1)
  | .done _, _, _, _, hs, _ => by simp [strace] at hs
  | .askC r k, st, 0, _, _, _ => by simp [strace]
  | .askC r k, st, s+1, stp, hs, hh => by
    simp only [strace, List.getElem?_cons_succ] at hs
    have hst : h ∉ st.rev := fun hm =>
      hh (strace_rev_mono t _ _ stp (mem_of_getElem? hs) h (by rw [addC_rev]; exact hm))
    have hi : firstIdx (mC false (t.set h y) st.rev r) st.ents = firstIdx (mC false t st.rev r) st.ents :=
      firstIdx_congr _ _ _ (fun e _ => mC_false_set t h y st.rev r e hst)
    simp only [strace, List.take_succ_cons]
    rw [hi, strace_inv t h y _ _ s stp hs hh]
  | .askA q k, st, 0, _, _, _ => by simp [strace]
  | .askA q k, st, s+1, stp, hs, hh => by
    simp only [strace, List.getElem?_cons_succ] at hs
    have hmono := strace_rev_mono t _ _ stp (mem_of_getElem? hs)
    have hst : h ∉ st.rev := fun hm => hh (hmono h (by simp [addA, hm]))
    have hi : firstIdx (mA false (t.set h y) st.rev q) st.ents = firstIdx (mA false t st.rev q) st.ents :=
      firstIdx_congr _ _ _ (fun e _ => mA_false_set t h y st.rev q e hst)
    have hne : firstIdx (mA false t st.rev q) st.ents ≠ h := fun he =>
      hh (hmono h (by simp [addA, he]))
    simp only [strace, List.take_succ_cons]
    rw [hi, getD_set_ne t h _ y hne, strace_inv t h y _ _ s stp hs hh]
  | .reveal x k, st, 0, _, _, _ => by simp [strace]
  | .reveal x k, st, s+1, stp, hs, hh => by
    simp only [strace, List.getElem?_cons_succ] at hs
    have hmono := strace_rev_mono t _ _ stp (mem_of_getElem? hs)
    have hx : ∀ i ∈ shids x, i ≠ h := fun i hi he => hh (hmono h (by simp [← he, hi]))
    simp only [strace, List.take_succ_cons]
    rw [sres_set t h y x hx, strace_inv t h y _ _ s stp hs hh]

#print axioms coupling
#print axioms strace_inv
end DSM.Rom
