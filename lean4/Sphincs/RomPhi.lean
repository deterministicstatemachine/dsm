-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomStruct

/- The narrow-pin count of H1'.

   From the structural invariant (`game_struct`) a tape-independent predicate
   `Φ` is derived at every step with no earlier disagreement: challenger
   entries have one of DSM's request shapes, the narrow-shaped ones have
   pairwise distinct literal skeletons, and a challenger request's skeleton is
   shared only by its own entry. With `Φ`, every narrow pin (an `n`-byte
   handle) counted by `hidden_bound_split` involves an adversary draw:
   at an adversary step it is charged against at most four entries, and at a
   fresh challenger step it is charged against an adversary entry, at most
   once per adversary entry. -/
namespace DSM.Rom
open DSM.Sphincs DSM.Sphincs.Security

/-! Literal skeletons. -/

def eraseSV : SV → SV
  | .lit b => .lit b
  | .hid _ w => .hid 0 w

/-- A request with its handle indices erased. -/
def skel (r : SReq) : SReq := ⟨r.mode, r.context, r.key.map eraseSV, r.input.map eraseSV, r.outLen⟩

theorem pm_lit {l : Bytes} {x : List SV} {b : Bytes} (h : patMatch (.lit l :: x) b = true) :
    b.take l.length = l ∧ patMatch x (b.drop l.length) = true := by
  simpa [patMatch] using h

theorem pm_hid {i w : Nat} {x : List SV} {b : Bytes} (h : patMatch (.hid i w :: x) b = true) :
    w ≤ b.length ∧ patMatch x (b.drop w) = true := by
  simpa [patMatch] using h

theorem pm_nil {b : Bytes} (h : patMatch [] b = true) : b = [] := by
  simpa [patMatch] using h

/-- Every element is a handle of width `n`. -/
def HidsN (n : Nat) (hs : List SV) : Prop := ∀ v ∈ hs, ∃ h, v = .hid h n

theorem pm_hids (n : Nat) : ∀ (hs : List SV), HidsN n hs → ∀ b, patMatch hs b = true → b.length = hs.length * n
  | [], _, b, h => by rw [pm_nil h]; simp
  | v :: hs, hh, b, h => by
    obtain ⟨i, rfl⟩ := hh v (by simp)
    obtain ⟨h1, h2⟩ := pm_hid h
    have := pm_hids n hs (fun u hu => hh u (by simp [hu])) _ h2
    simp at this ⊢
    rw [Nat.succ_mul]; omega

theorem erase_hids (n : Nat) : ∀ (hs : List SV), HidsN n hs → hs.map eraseSV = List.replicate hs.length (.hid 0 n)
  | [], _ => rfl
  | v :: hs, hh => by
    obtain ⟨i, rfl⟩ := hh v (by simp)
    simp only [List.map_cons, List.length_cons, List.replicate_succ, eraseSV]
    rw [erase_hids n hs (fun u hu => hh u (by simp [hu]))]

theorem compat_parts {X : SReq} {Y : Request} (h : compat X Y = true) :
    X.mode = Y.mode ∧ X.context = Y.context ∧ X.outLen = Y.outLen ∧ patMatch X.key Y.key = true ∧
      patMatch X.input Y.input = true := by
  simp only [compat, Bool.and_eq_true, decide_eq_true_eq] at h
  exact ⟨h.1.1.1.1, h.1.1.1.2, h.1.1.2, h.1.2, h.2⟩

/-! DSM's request shapes (tape-free). -/

section
variable (n pm : Nat)

def IsTh (r : SReq) : Prop :=
  ∃ itk b hs, r = ⟨1, "", [.hid itk 32], .lit b :: hs, n⟩ ∧ b.length = 32 ∧ HidsN n hs
def IsD (r : SReq) : Prop := r = dTk n ∨ r = dPrf n ∨ r = dReq n
def IsHq (r : SReq) : Prop :=
  ∃ iR ρ m, r = ⟨2, "DSM/sphincs/v2/h-msg", [], [.hid iR n, .hid 2 n, .hid ρ n, .lit m], pm⟩
def IsPR (r : SReq) : Prop := ∃ k m, r = ⟨1, "", [.hid k 32], [.hid 2 n, .lit m], n⟩
/-- The shapes whose first hidden handle can be narrow. -/
def LoShape (r : SReq) : Prop := IsTh n r ∨ IsD n r ∨ IsHq n pm r

/-- The skeleton a narrow-shaped request compatible with `Y` must have. -/
def skOf (Y : Request) : SReq :=
  if Y.mode = 1 then ⟨1, "", [.hid 0 32], .lit (Y.input.take 32) :: List.replicate ((Y.input.length - 32) / n) (.hid 0 n), n⟩
  else if Y.mode = 2 then ⟨2, "DSM/sphincs/v2/h-msg", [], [.hid 0 n, .hid 0 n, .hid 0 n, .lit (Y.input.drop (3*n))], pm⟩
  else ⟨0, Y.context, [], [.hid 0 n], 32⟩

end

theorem skel_of_compat {n pm : Nat} (hn : 0 < n) {X : SReq} {Y : Request} (hX : LoShape n pm X)
    (hc : compat X Y = true) : skel X = skOf n pm Y := by
  obtain ⟨hm, hctx, hout, hk, hi⟩ := compat_parts hc
  rcases hX with ⟨itk, b, hs, rfl, hb, hh⟩ | hD | ⟨iR, ρ, m, rfl⟩
  · simp only at hm hctx hout hk hi
    have hY1 : Y.mode = 1 := hm.symm
    obtain ⟨h1, h2⟩ := pm_lit hi
    rw [hb] at h1 h2
    have hl := pm_hids n hs hh _ h2
    simp only [List.length_drop] at hl
    have hq : (Y.input.length - 32) / n = hs.length := by rw [hl, Nat.mul_div_cancel _ hn]
    simp only [skOf, hY1, if_true, skel, List.map_cons, List.map_nil, eraseSV, h1, hq, erase_hids n hs hh]
  · have hY0 : Y.mode = 0 := by rcases hD with rfl | rfl | rfl <;> exact hm.symm
    have hne1 : ¬ Y.mode = 1 := by omega
    have hne2 : ¬ Y.mode = 2 := by omega
    simp only [skOf, hne1, hne2, if_false]
    rcases hD with rfl | rfl | rfl <;> simp only [dTk, dPrf, dReq] at hctx ⊢ <;>
      simp [skel, eraseSV, ← hctx]
  · simp only at hm hctx hout hk hi
    have hY2 : Y.mode = 2 := hm.symm
    obtain ⟨_, h1⟩ := pm_hid hi
    obtain ⟨_, h2⟩ := pm_hid h1
    obtain ⟨_, h3⟩ := pm_hid h2
    obtain ⟨h4, h5⟩ := pm_lit h3
    have h6 := pm_nil h5
    simp only [List.drop_drop] at h4 h6
    have hm' : Y.input.drop (3*n) = m := by
      rw [← List.take_append_drop m.length (Y.input.drop (3*n)), List.drop_drop]
      rw [show 3*n = n + n + n by omega, h4, h6]; simp
    simp only [skOf, hY2, if_true, show ¬ (2:Nat) = 1 by omega, if_false, skel, List.map_cons, List.map_nil,
      eraseSV, hm', hout]

theorem skel_det {n pm : Nat} (hn : 0 < n) {X X' : SReq} {Y : Request} (hX : LoShape n pm X)
    (hX' : LoShape n pm X') (hc : compat X Y = true) (hc' : compat X' Y = true) : skel X = skel X' := by
  rw [skel_of_compat hn hX hc, skel_of_compat hn hX' hc']

/-! The tape-free step predicate `Φ`. -/

section
variable (n pm : Nat)

/-- A request of a DSM shape; a PRF or randomizer request with its key unrevealed. -/
def GoodFam (rev : List Nat) (r : SReq) : Prop :=
  LoShape n pm r ∨ ∃ k m, r = ⟨1, "", [.hid k 32], [.hid 2 n, .lit m], n⟩ ∧ k ∉ rev

end

/-- What the narrow-pin count needs at a step. -/
def PhiP (v : Variant) (stp : St × Ev) : Prop :=
  3 ≤ stp.1.ents.length ∧
  (∀ (j : Nat) (e : Bool × SReq), j < 3 → stp.1.ents[j]? = some e → e.2.mode = 999) ∧
  (∀ (j : Nat) (qa : SReq), stp.1.ents[j]? = some (true, qa) → qa.hids = []) ∧
  (∀ (j : Nat) (r : SReq), 3 ≤ j → stp.1.ents[j]? = some (false, r) →
    GoodFam (params v).n (params v).m stp.1.rev r) ∧
  (∀ (a b : Nat) (ra rb : SReq), 3 ≤ a → 3 ≤ b → a ≠ b → stp.1.ents[a]? = some (false, ra) →
    stp.1.ents[b]? = some (false, rb) → LoShape (params v).n (params v).m ra →
    LoShape (params v).n (params v).m rb → skel ra ≠ skel rb) ∧
  (∀ r, stp.2 = .c r → GoodFam (params v).n (params v).m stp.1.rev r ∧
    (LoShape (params v).n (params v).m r → ∀ (j : Nat) (e : SReq), 3 ≤ j → stp.1.ents[j]? = some (false, e) →
      LoShape (params v).n (params v).m e → skel e = skel r → e = r))

theorem adrs_bytes_len (a : Adrs) : a.bytes.length = 32 := by simp [Adrs.bytes, be_width]

section
variable {c : Ctx}

theorem structReq_shape {st : St} {d : Nat} {r : SReq} {A : Adrs} (h : StructReq c st d r A) :
    ∃ itk hs, r = ⟨1, "", [.hid itk 32], .lit A.bytes :: hs, c.n⟩ ∧ HidsN c.n hs ∧ A.InRange := by
  cases d with
  | zero => exact h.elim
  | succ d =>
    obtain ⟨hA, _, itk, hs, rfl, _, _, hh⟩ := h
    refine ⟨itk, hs, rfl, fun v hv => ?_, hA⟩
    obtain ⟨k, hk⟩ := List.mem_iff_getElem?.mp hv
    obtain ⟨h', hx, _⟩ := hh k (List.getElem?_eq_some_iff.mp hk).1
    rw [hk] at hx
    exact ⟨h', Option.some.inj hx⟩

theorem famOK_good (ρ : Nat) (hroot : c.root = [.hid ρ c.n]) {st : St} (hI : InvS c st) {r : SReq}
    (hF : FamOK c st r) : GoodFam c.n c.pm st.rev r := by
  rcases hF with rfl | rfl | rfl | ⟨ipk, A, rfl, hk, _⟩ | ⟨dk, m, rfl, hk⟩ | ⟨iR, m, rfl, _⟩ | ⟨d, A, hs⟩
  · exact Or.inl (Or.inr (Or.inl (Or.inl rfl)))
  · exact Or.inl (Or.inr (Or.inl (Or.inr (Or.inl rfl))))
  · exact Or.inl (Or.inr (Or.inl (Or.inr (Or.inr rfl))))
  · exact Or.inr ⟨ipk, A.bytes, rfl, notRev_of_prot hI ⟨_, hk, Or.inl (by simp [dPrf, SReq.hids, shids])⟩⟩
  · exact Or.inr ⟨dk, m, rfl, notRev_of_prot hI ⟨_, hk, Or.inr (by simp [dReq, SReq.hids, shids])⟩⟩
  · refine Or.inl (Or.inr (Or.inr ⟨iR, ρ, m, ?_⟩))
    rw [hroot]; simp [hqOf]
  · obtain ⟨itk, hs', rfl, hh, _⟩ := structReq_shape hs
    exact Or.inl (Or.inl ⟨itk, A.bytes, hs', rfl, adrs_bytes_len A, hh⟩)

/-- A narrow-shaped DSM request is structured, a key derivation, or a signing request. -/
theorem famLo_cases {st : St} {r : SReq} (hF : FamOK c st r)
    (hL : LoShape c.n c.pm r) :
    (∃ d A, StructReq c st d r A) ∨ IsD c.n r ∨
    (∃ iR m dk, r = hqOf c.n c.pm c.root iR m ∧ st.ents[iR]? = some (false, rqOf c.n dk m) ∧
      st.ents[dk]? = some (false, dReq c.n)) := by
  rcases hF with h | h | h | ⟨ipk, A, rfl, _⟩ | ⟨dk, m, rfl, _⟩ | ⟨iR, m, rfl, dk, h1, h2, _⟩ | ⟨d, A, hs⟩
  · exact Or.inr (Or.inl (Or.inl h))
  · exact Or.inr (Or.inl (Or.inr (Or.inl h)))
  · exact Or.inr (Or.inl (Or.inr (Or.inr h)))
  · exfalso
    rcases hL with ⟨_, _, _, he, _⟩ | hD | ⟨_, _, _, he⟩
    · simp [prfReq] at he
    · rcases hD with h | h | h <;> simp [prfReq, dTk, dPrf, dReq] at h
    · simp [prfReq] at he
  · exfalso
    rcases hL with ⟨_, _, _, he, _⟩ | hD | ⟨_, _, _, he⟩
    · simp [rqOf] at he
    · rcases hD with h | h | h <;> simp [rqOf, dTk, dPrf, dReq] at h
    · simp [rqOf] at he
  · exact Or.inr (Or.inr ⟨iR, m, dk, rfl, h1, h2⟩)
  · exact Or.inl ⟨d, A, hs⟩

theorem dReq_unique {st : St} (hI : InvS c st) {a b : Nat} (ha : st.ents[a]? = some (false, dReq c.n))
    (hb : st.ents[b]? = some (false, dReq c.n)) : a = b :=
  idx_eq_of_res hI ha hb rfl (by simp [dReq, SReq.res])

theorem skel_mode {r r' : SReq} (h : skel r = skel r') : r.mode = r'.mode := by
  have := congrArg SReq.mode h; simpa [skel] using this

/-- Canonical uniqueness at the skeleton level, for the narrow shapes. -/
theorem famOK_skel_unique (ρ : Nat) (hroot : c.root = [.hid ρ c.n]) {st : St} (hI : InvS c st) {r r' : SReq}
    (hF : FamOK c st r) (hF' : FamOK c st r') (hL : LoShape c.n c.pm r) (hL' : LoShape c.n c.pm r')
    (hs : skel r = skel r') : r = r' := by
  have hm := skel_mode hs
  rcases famLo_cases hF hL with ⟨d, A, hA⟩ | hD | ⟨iR, m, dk, rfl, h1, h2⟩ <;>
  rcases famLo_cases hF' hL' with ⟨d', A', hA'⟩ | hD' | ⟨iR', m', dk', rfl, h1', h2'⟩
  · obtain ⟨itk, hs1, rfl, _, hR⟩ := structReq_shape hA
    obtain ⟨itk', hs2, rfl, _, hR'⟩ := structReq_shape hA'
    have hb : A.bytes = A'.bytes := by
      have := congrArg SReq.input hs
      simp [skel, eraseSV] at this
      exact this.1
    have := adrs_bytes_injective A A' hR hR' hb
    subst this
    exact struct_unique hI d d' _ _ A hA hA'
  · obtain ⟨_, _, rfl, _, _⟩ := structReq_shape hA
    rcases hD' with rfl | rfl | rfl <;> simp [dTk, dPrf, dReq] at hm
  · obtain ⟨_, _, rfl, _, _⟩ := structReq_shape hA
    simp [hqOf] at hm
  · obtain ⟨_, _, rfl, _, _⟩ := structReq_shape hA'
    rcases hD with rfl | rfl | rfl <;> simp [dTk, dPrf, dReq] at hm
  · have hc := congrArg SReq.context hs
    rcases hD with rfl | rfl | rfl <;> rcases hD' with rfl | rfl | rfl <;> simp_all [skel, dTk, dPrf, dReq]
  · rcases hD with rfl | rfl | rfl <;> simp [dTk, dPrf, dReq, hqOf] at hm
  · obtain ⟨_, _, rfl, _, _⟩ := structReq_shape hA'
    simp [hqOf] at hm
  · rcases hD' with rfl | rfl | rfl <;> simp [dTk, dPrf, dReq, hqOf] at hm
  · have hmm : m = m' := by
      have := congrArg SReq.input hs
      rw [hroot] at this
      simp [skel, hqOf, eraseSV] at this
      exact this
    subst hmm
    have hdk := dReq_unique hI h2 h2'
    subst hdk
    have := idx_eq_of_res hI h1 h1' rfl (by simp [rqOf, SReq.res])
    subst this
    rfl

end

section
variable {c : Ctx}

/-- `Φ` from the structural invariant. -/
theorem phi_of (ρ : Nat) (hroot : c.root = [.hid ρ c.n]) {st : St} {ev : Ev} (hI : InvS c st)
    (hS : StepOK c (st, ev)) : PhiP c.v (st, ev) := by
  obtain ⟨hc, hadv, hrev, hfam, hD⟩ := hI
  have hI : InvS c st := ⟨hc, hadv, hrev, hfam, hD⟩
  have hfam3 : ∀ (j : Nat) (r : SReq), 3 ≤ j → st.ents[j]? = some (false, r) → FamOK c st r := by
    intro j r hj he
    rcases hfam j r he with h | h
    · omega
    · exact h
  refine ⟨?_, ?_, hadv, fun j r hj he => famOK_good ρ hroot hI (hfam3 j r hj he), ?_, ?_⟩
  · have := lt_entry hc.2.2; show 3 ≤ st.ents.length; omega
  · intro j e hj he
    rcases j with _ | _ | _ | j
    · rw [hc.1] at he; obtain rfl := Option.some.inj he; rfl
    · rw [hc.2.1] at he; obtain rfl := Option.some.inj he; rfl
    · rw [hc.2.2] at he; obtain rfl := Option.some.inj he; rfl
    · omega
  · intro a b ra rb ha hb hab hea heb hla hlb hsk
    have := famOK_skel_unique ρ hroot hI (hfam3 a ra ha hea) (hfam3 b rb hb heb) hla hlb hsk
    subst this
    rcases Nat.lt_or_gt_of_ne hab with h | h
    · exact hD a b _ _ h hb hea heb rfl
    · exact hD b a _ _ h ha heb hea rfl
  · intro r hr
    subst hr
    have hF : FamOK c st r := hS
    refine ⟨famOK_good ρ hroot hI hF, fun hl j e hj he hle hsk => ?_⟩
    exact famOK_skel_unique ρ hroot hI (hfam3 j e hj he) hF hle hl hsk

/-- The Φ-steps of H1': every step with no earlier disagreement. -/
theorem game_phi (hroot0 : c.root = (xrun false c.t (sKgTail c.v (coinEx c.n)) (coinSt c.n)).1.1.drop 1)
    (ρ : Nat) (hroot : c.root = [.hid ρ c.n]) (limits : Limits) (A : Bytes → RAdv) (s : Nat) (stp : St × Ev)
    (hs : (strace c.t (gameS' c.v limits A (coinEx c.n)) (coinSt c.n))[s]? = some stp)
    (hnd : NoDisTo c.t (strace c.t (gameS' c.v limits A (coinEx c.n)) (coinSt c.n)) s) :
    PhiP c.v stp :=
  let ⟨hI, hS⟩ := game_struct hroot0 limits A s stp hs hnd
  phi_of ρ hroot hI hS

end

/-! Classifying narrow pins at a Φ-step. -/

theorem fh_key {rev : List Nat} {r : SReq} {k : Nat} (hk : r.key = [.hid k 32]) (hr : k ∉ rev) :
    firstHidden rev r = some (k, 32, true, 0) := by
  simp [firstHidden, hk, occs, firstOut, hr]

theorem isOpen_false_of {rev : List Nat} {r : SReq} {k : Nat} (hk : k ∈ r.hids) (hr : k ∉ rev) :
    isOpen rev r = false := by
  cases h : isOpen rev r
  · rfl
  · exact absurd (open_mem h k hk) hr

theorem loShape_mode {n pm : Nat} {r : SReq} (h : LoShape n pm r) : r.mode = 0 ∨ r.mode = 1 ∨ r.mode = 2 := by
  rcases h with ⟨_, _, _, rfl, _⟩ | hD | ⟨_, _, _, rfl⟩
  · exact Or.inr (Or.inl rfl)
  · rcases hD with rfl | rfl | rfl <;> exact Or.inl rfl
  · exact Or.inr (Or.inr rfl)

theorem goodFam_mode {n pm : Nat} {rev : List Nat} {r : SReq} (h : GoodFam n pm rev r) : r.mode ≠ 999 := by
  rcases h with h | ⟨k, m, rfl, _⟩
  · rcases loShape_mode h with h | h | h <;> omega
  · simp

theorem goodFam_narrow {n pm : Nat} {rev : List Nat} {r : SReq} (h : GoodFam n pm rev r) {v : Nat × Nat × Bool × Nat}
    (hv : firstHidden rev r = some v) (hw : v.2.1 < 32) : LoShape n pm r := by
  rcases h with h | ⟨k, m, rfl, hk⟩
  · exact h
  · rw [fh_key rfl hk] at hv
    obtain rfl := Option.some.inj hv
    simp at hw

theorem goodFam_open {n pm : Nat} {rev : List Nat} {r : SReq} (h : GoodFam n pm rev r) (ho : isOpen rev r = true) :
    LoShape n pm r := by
  rcases h with h | ⟨k, m, rfl, hk⟩
  · exact h
  · rw [isOpen_false_of (k := k) (by simp [SReq.hids, shids]) hk] at ho; cases ho

theorem res_mode (t : List Nat) (r : SReq) : (r.res t).mode = r.mode := rfl

/-- A narrow pin at a Φ-step is charged at an adversary step against a challenger entry
    (a coin, or a narrow-shaped entry compatible with the query), or at a challenger step
    against an adversary entry. -/
theorem np_class (v : Variant) (t : List Nat) {stp : St × Ev} (hΦ : PhiP v stp) {j : Nat} {e : Bool × SReq}
    (he : stp.1.ents[j]? = some e) {XY : SReq × Request} (hc : cand t stp.1 stp.2 e = some XY)
    {w : Nat × Nat × Bool × Nat} (hf : firstHidden stp.1.rev XY.1 = some w) (hw : w.2.1 < 32)
    (hcomp : compat XY.1 XY.2 = true) :
    (∃ q, stp.2 = .a q ∧ e.1 = false ∧ (j < 3 ∨ (LoShape (params v).n (params v).m e.2 ∧ compat e.2 q = true))) ∨
    (∃ r, stp.2 = .c r ∧ e.1 = true ∧ LoShape (params v).n (params v).m r ∧ compat r (e.2.res t) = true) := by
  have hn := params_n_pos v
  obtain ⟨st, ev⟩ := stp
  obtain ⟨hlen, hcoin, hadv, hgood, hnd, hstep⟩ := hΦ
  obtain ⟨b, er⟩ := e
  cases ev with
  | r x => cases hc
  | a q =>
    left
    simp only [cand] at hc
    split at hc
    · cases hc
    · next ho =>
      obtain rfl := Option.some.inj hc
      cases b with
      | true =>
        exfalso; apply ho
        simp [isOpen, hadv j er he]
      | false =>
        refine ⟨q, rfl, rfl, ?_⟩
        by_cases hj : j < 3
        · exact Or.inl hj
        · exact Or.inr ⟨goodFam_narrow (hgood j er (by omega) he) hf hw, hcomp⟩
  | c r =>
    right
    obtain ⟨hgr, hfr⟩ := hstep r rfl
    simp only [cand] at hc
    split at hc
    · cases hc
    · next hne =>
      split at hc
      · next hoe =>
        split at hc
        · cases hc
        · obtain rfl := Option.some.inj hc
          have hlr := goodFam_narrow hgr hf hw
          refine ⟨r, rfl, ?_, hlr, hcomp⟩
          cases b with
          | true => rfl
          | false =>
            exfalso
            by_cases hj : j < 3
            · have h1 := hcoin j _ hj he
              have h2 := (compat_parts hcomp).1
              rw [res_mode] at h2
              simp only at h1 h2
              rcases loShape_mode hlr with h | h | h <;> omega
            · have hle := goodFam_open (hgood j er (by omega) he) hoe
              have := hfr hlr j er (by omega) he hle
                (skel_det hn hle hlr (compat_of_res t er _ rfl) hcomp)
              exact hne this
      · next hoe =>
        split at hc
        · next hor =>
          obtain rfl := Option.some.inj hc
          exfalso
          cases b with
          | true => exact hoe (by simp [isOpen, hadv j er he])
          | false =>
            by_cases hj : j < 3
            · have h1 := hcoin j _ hj he
              have h2 := (compat_parts hcomp).1
              rw [res_mode] at h2
              simp only at h1 h2
              exact goodFam_mode hgr (by omega)
            · have hle := goodFam_narrow (hgood j er (by omega) he) hf hw
              have hlr := goodFam_open hgr hor
              have := hfr hlr j er (by omega) he hle
                (skel_det hn hle hlr hcomp (compat_of_res t r _ rfl))
              exact hne this
        · cases hc

/-! Trace facts: states only grow, and a fresh step's entry stays. -/

/-- The state after a step. -/
def stepPost (t : List Nat) : St × Ev → St
  | (st, .c r) => addC st (firstIdx (mC false t st.rev r) st.ents) r
  | (st, .a q) => addA st (firstIdx (mA false t st.rev q) st.ents) q
  | (st, .r x) => ⟨st.ents, shids x ++ st.rev⟩

theorem addC_ext (st : St) (i : Nat) (r : SReq) : ∃ L, (addC st i r).ents = st.ents ++ L := by
  unfold addC; split
  · exact ⟨[], by simp⟩
  · exact ⟨_, rfl⟩

theorem addA_ext (st : St) (i : Nat) (q : Request) : ∃ L, (addA st i q).ents = st.ents ++ L := by
  unfold addA; split
  · exact ⟨[], by simp⟩
  · exact ⟨_, rfl⟩

theorem post_ext (t : List Nat) (stp : St × Ev) : ∃ L, (stepPost t stp).ents = stp.1.ents ++ L := by
  obtain ⟨st, ev⟩ := stp
  cases ev with
  | c r => exact addC_ext _ _ _
  | a q => exact addA_ext _ _ _
  | r x => exact ⟨[], by simp [stepPost]⟩

theorem trace_ext (t : List Nat) {α : Type} : ∀ (P : Prog α) (st : St) (s : Nat) (stp : St × Ev),
    (strace t P st)[s]? = some stp → ∃ L, stp.1.ents = st.ents ++ L
  | .done _, _, _, _, h => by simp [strace] at h
  | .askC r k, st, 0, stp, h => by simp [strace] at h; subst h; exact ⟨[], by simp⟩
  | .askC r k, st, s+1, stp, h => by
    simp only [strace, List.getElem?_cons_succ] at h
    obtain ⟨L1, h1⟩ := addC_ext st (firstIdx (mC false t st.rev r) st.ents) r
    obtain ⟨L2, h2⟩ := trace_ext t _ _ s stp h
    exact ⟨L1 ++ L2, by rw [h2, h1, List.append_assoc]⟩
  | .askA q k, st, 0, stp, h => by simp [strace] at h; subst h; exact ⟨[], by simp⟩
  | .askA q k, st, s+1, stp, h => by
    simp only [strace, List.getElem?_cons_succ] at h
    obtain ⟨L1, h1⟩ := addA_ext st (firstIdx (mA false t st.rev q) st.ents) q
    obtain ⟨L2, h2⟩ := trace_ext t _ _ s stp h
    exact ⟨L1 ++ L2, by rw [h2, h1, List.append_assoc]⟩
  | .reveal x k, st, 0, stp, h => by simp [strace] at h; subst h; exact ⟨[], by simp⟩
  | .reveal x k, st, s+1, stp, h => by
    simp only [strace, List.getElem?_cons_succ] at h
    exact trace_ext t _ ⟨st.ents, shids x ++ st.rev⟩ s stp h

/-- A later pre-step state extends an earlier step's post-state. -/
theorem trace_post (t : List Nat) {α : Type} : ∀ (P : Prog α) (st : St) (s1 s2 : Nat) (stp1 stp2 : St × Ev),
    s1 < s2 → (strace t P st)[s1]? = some stp1 → (strace t P st)[s2]? = some stp2 →
    ∃ L, stp2.1.ents = (stepPost t stp1).ents ++ L
  | .done _, _, _, _, _, _, _, h, _ => by simp [strace] at h
  | .askC r k, st, 0, s2+1, stp1, stp2, _, h1, h2 => by
    simp [strace] at h1; subst h1
    simp only [strace, List.getElem?_cons_succ] at h2
    exact trace_ext t _ _ s2 stp2 h2
  | .askC r k, st, s1+1, s2+1, stp1, stp2, hlt, h1, h2 => by
    simp only [strace, List.getElem?_cons_succ] at h1 h2
    exact trace_post t _ _ s1 s2 stp1 stp2 (by omega) h1 h2
  | .askA q k, st, 0, s2+1, stp1, stp2, _, h1, h2 => by
    simp [strace] at h1; subst h1
    simp only [strace, List.getElem?_cons_succ] at h2
    exact trace_ext t _ _ s2 stp2 h2
  | .askA q k, st, s1+1, s2+1, stp1, stp2, hlt, h1, h2 => by
    simp only [strace, List.getElem?_cons_succ] at h1 h2
    exact trace_post t _ _ s1 s2 stp1 stp2 (by omega) h1 h2
  | .reveal x k, st, 0, s2+1, stp1, stp2, _, h1, h2 => by
    simp [strace] at h1; subst h1
    simp only [strace, List.getElem?_cons_succ] at h2
    exact trace_ext t _ _ s2 stp2 h2
  | .reveal x k, st, s1+1, s2+1, stp1, stp2, hlt, h1, h2 => by
    simp only [strace, List.getElem?_cons_succ] at h1 h2
    exact trace_post t _ _ s1 s2 stp1 stp2 (by omega) h1 h2
  | _, _, _, 0, _, _, hlt, _, _ => absurd hlt (by omega)

/-- Every pre-step state is a prefix of the end state. -/
theorem trace_final (t : List Nat) {α : Type} : ∀ (P : Prog α) (st : St) (s : Nat) (stp : St × Ev),
    (strace t P st)[s]? = some stp → ∃ L, (xrun false t P st).2.ents = stp.1.ents ++ L
  | .done _, _, _, _, h => by simp [strace] at h
  | .askC r k, st, 0, stp, h => by
    simp [strace] at h; subst h
    obtain ⟨⟨L, hL⟩, _⟩ := xrun_grow t (.askC r k) st
    exact ⟨L, hL⟩
  | .askC r k, st, s+1, stp, h => by
    simp only [strace, List.getElem?_cons_succ] at h
    simp only [xrun]
    exact trace_final t _ _ s stp h
  | .askA q k, st, 0, stp, h => by
    simp [strace] at h; subst h
    obtain ⟨⟨L, hL⟩, _⟩ := xrun_grow t (.askA q k) st
    exact ⟨L, hL⟩
  | .askA q k, st, s+1, stp, h => by
    simp only [strace, List.getElem?_cons_succ] at h
    simp only [xrun]
    exact trace_final t _ _ s stp h
  | .reveal x k, st, 0, stp, h => by
    simp [strace] at h; subst h
    obtain ⟨⟨L, hL⟩, _⟩ := xrun_grow t (.reveal x k) st
    exact ⟨L, hL⟩
  | .reveal x k, st, s+1, stp, h => by
    simp only [strace, List.getElem?_cons_succ] at h
    simp only [xrun]
    exact trace_final t _ _ s stp h

/-- A fresh challenger step's request is the entry at the old length in every later state. -/
theorem fresh_entry (t : List Nat) {α : Type} (P : Prog α) (st0 : St) {s1 s2 : Nat} {st1 : St} {r : SReq}
    {stp2 : St × Ev} (hlt : s1 < s2) (h1 : (strace t P st0)[s1]? = some (st1, .c r))
    (hel : elig t (st1, .c r) = true) (h2 : (strace t P st0)[s2]? = some stp2) :
    stp2.1.ents[st1.ents.length]? = some (false, r) := by
  obtain ⟨L, hL⟩ := trace_post t P st0 s1 s2 _ _ hlt h1 h2
  have hfr : st1.ents.length ≤ firstIdx (mC false t st1.rev r) st1.ents := by simpa [elig] using hel
  have hpost : (stepPost t (st1, .c r)).ents = st1.ents ++ [(false, r)] := by
    simp only [stepPost, addC]
    rw [if_neg (by omega)]
  rw [hL, hpost]
  simp

/-! Counting the narrow pins. -/

/-- `Φ` as a Boolean step predicate (classically decided). -/
noncomputable def phiB (v : Variant) (stp : St × Ev) : Bool := @decide (PhiP v stp) (Classical.propDecidable _)

theorem phiB_true {v : Variant} {stp : St × Ev} (h : phiB v stp = true) : PhiP v stp := by
  simpa [phiB] using h

def isAev (stp : St × Ev) : Bool :=
  match stp.2 with
  | .a _ => true
  | _ => false

def cntT (l : List (Bool × SReq)) : Nat := (l.filter (fun e => e.1)).length

theorem sum_idx_filter {β : Type} (p : β → Bool) : ∀ (l : List β) (S : Nat),
    ((List.range S).map (fun j => if (l[j]?.map p) = some true then 1 else 0)).sum ≤ (l.filter p).length
  | [], S => by simp; exact sum_map_zero _
  | x :: l, 0 => by simp
  | x :: l, S+1 => by
    rw [List.range_succ_eq_map, List.map_cons, List.sum_cons, List.map_map]
    have ih := sum_idx_filter p l S
    simp only [Function.comp_def, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.map_some]
    rw [List.filter_cons]
    by_cases hx : p x = true
    · simp only [hx, if_true, List.length_cons]; omega
    · simp only [hx]; simpa using ih

theorem sum_le_one (f : Nat → Nat) (hf : ∀ j, f j ≤ 1) (hu : ∀ a b, a < b → f a ≠ 0 → f b ≠ 0 → False) :
    ∀ S, ((List.range S).map f).sum ≤ 1
  | 0 => by simp
  | S+1 => by
    rw [List.range_succ, List.map_append, sum_append']
    simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, Nat.add_zero]
    by_cases h : f S = 0
    · rw [h]; exact sum_le_one f hf hu S
    · have hz : ((List.range S).map f).sum = 0 := by
        have : ∀ j ∈ List.range S, f j = 0 := by
          intro j hj
          exact Nat.eq_zero_of_not_pos (fun hpos => hu j S (List.mem_range.mp hj) (by omega) h)
        rw [show (List.range S).map f = (List.range S).map (fun _ => 0) from List.map_congr_left this]
        exact sum_map_zero _
      have := hf S; omega

theorem sum_swap (f : Nat → Nat → Nat) (B : Nat) : ∀ A,
    ((List.range A).map (fun a => ((List.range B).map (fun b => f a b)).sum)).sum =
      ((List.range B).map (fun b => ((List.range A).map (fun a => f a b)).sum)).sum
  | 0 => by simp; exact (sum_map_zero _).symm
  | A+1 => by
    rw [List.range_succ, List.map_append, sum_append', sum_swap f B A]
    simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, Nat.add_zero]
    rw [← sum_map_add]
    congr 1
    apply List.map_congr_left
    intro b _
    rw [List.map_append, sum_append']
    simp

theorem sum_lt3 (S : Nat) : ((List.range S).map (fun j => if j < 3 then 1 else 0)).sum ≤ 3 := by
  rcases Nat.le_total S 3 with hS | hS
  · calc _ ≤ ((List.range S).map (fun _ => 1)).sum := sum_map_le _ (fun j _ => by split <;> omega)
      _ = S := by rw [sum_map_const]; simp
      _ ≤ 3 := hS
  · have h := sum_range_zero_tail (fun j => if j < 3 then 1 else 0) 3 (fun j hj => by
      simp only; split <;> omega)
    rw [h S hS]; decide

theorem cnt_run (t : List Nat) {α : Type} : ∀ (P : Prog α) (st : St),
    cntT (xrun false t P st).2.ents ≤ cntT st.ents + ((strace t P st).filter isAev).length
  | .done _, _ => by simp [xrun]
  | .askC r k, st => by
    simp only [xrun, strace, List.filter_cons, isAev, Bool.false_eq_true, if_false]
    have := cnt_run t (k (.hid (firstIdx (mC false t st.rev r) st.ents) r.outLen))
      (addC st (firstIdx (mC false t st.rev r) st.ents) r)
    have e : cntT (addC st (firstIdx (mC false t st.rev r) st.ents) r).ents = cntT st.ents := by
      unfold addC; split
      · rfl
      · simp [cntT, List.filter_append]
    omega
  | .askA q k, st => by
    simp only [xrun, strace, List.filter_cons, isAev, if_true, List.length_cons]
    have := cnt_run t (k (be q.outLen (t.getD (firstIdx (mA false t st.rev q) st.ents) 0)))
      (addA st (firstIdx (mA false t st.rev q) st.ents) q)
    have e : cntT (addA st (firstIdx (mA false t st.rev q) st.ents) q).ents ≤ cntT st.ents + 1 := by
      unfold addA; split
      · simp
      · simp [cntT, List.filter_append]
    omega
  | .reveal x k, st => by
    simp only [xrun, strace, List.filter_cons, isAev, Bool.false_eq_true, if_false]
    exact cnt_run t (k (sres t x)) ⟨st.ents, shids x ++ st.rev⟩

section
variable {α : Type} (v : Variant) (P : Prog α) (st0 : St) (wmin W : Nat)

theorem narrow_of_pin (t : List Nat) (s j : Nat)
    (h : (pinC wmin W (phiB v) P st0 t s j).map Prod.snd = some false) :
    ∃ stp e XY w, (strace t P st0)[s]? = some stp ∧ elig t stp = true ∧ PhiP v stp ∧
      stp.1.ents[j]? = some e ∧ cand t stp.1 stp.2 e = some XY ∧ firstHidden stp.1.rev XY.1 = some w ∧
      w.2.1 < W ∧ compat XY.1 XY.2 = true := by
  unfold pinC at h
  cases hp : probeF wmin (phiB v) P st0 t s j with
  | none => rw [hp] at h; cases h
  | some val =>
    rw [hp] at h
    simp only [Option.map_some, Option.some.injEq, decide_eq_false_iff_not] at h
    unfold probeF at hp
    cases hs : (strace t P st0)[s]? with
    | none => rw [hs] at hp; cases hp
    | some stp =>
      rw [hs] at hp
      simp only [Option.bind_some] at hp
      split at hp
      · rename_i hel
        simp only [Bool.and_eq_true] at hel
        unfold probeAtW at hp
        split at hp
        · cases hp
        · rename_i e he
          split at hp
          · cases hp
          · rename_i XY hXY
            split at hp
            · cases hp
            · rename_i w hw
              split at hp
              · rename_i hcond
                obtain rfl := Option.some.inj hp
                exact ⟨stp, e, XY, w, rfl, hel.1, phiB_true hel.2, he, hXY, hw, by simpa using h, hcond.2⟩
              · cases hp
      · cases hp

end

section
variable {α : Type} (v : Variant) (P : Prog α) (st0 : St) (wmin W : Nat)

/-- At an adversary step, at most four entries carry a narrow pin. -/
theorem adv_step_count (hW : W ≤ 32) (t : List Nat) (s S : Nat) (stp : St × Ev) (q : Request)
    (hs : (strace t P st0)[s]? = some stp) (hq : stp.2 = .a q) :
    ((List.range S).map (fun j => if (pinC wmin W (phiB v) P st0 t s j).map Prod.snd = some false then 1 else 0)).sum ≤ 4 := by
  have hn := params_n_pos v
  let N := fun j => if (pinC wmin W (phiB v) P st0 t s j).map Prod.snd = some false then 1 else 0
  let U := fun j => if 3 ≤ j ∧ N j = 1 then 1 else 0
  have hpt : ∀ j, N j ≤ (if j < 3 then 1 else 0) + U j := by
    intro j
    by_cases h3 : j < 3
    · simp only [N, h3, if_true]; split <;> omega
    · simp only [U, h3, if_false, Nat.zero_add]
      by_cases hN : N j = 1
      · rw [if_pos ⟨by omega, hN⟩]; omega
      · simp only [N] at hN ⊢; split <;> simp_all
  have hU : ((List.range S).map U).sum ≤ 1 := by
    refine sum_le_one U (fun j => by simp only [U]; split <;> omega) (fun a b hab ha hb => ?_) S
    simp only [U] at ha hb
    split at ha
    · rename_i hha
      split at hb
      · rename_i hhb
        have pa : (pinC wmin W (phiB v) P st0 t s a).map Prod.snd = some false := by
          have := hha.2; simp only [N] at this; split at this <;> simp_all
        have pb : (pinC wmin W (phiB v) P st0 t s b).map Prod.snd = some false := by
          have := hhb.2; simp only [N] at this; split at this <;> simp_all
        obtain ⟨stp1, e1, XY1, w1, hs1, _, hΦ, he1, hc1, hf1, hw1, hp1⟩ := narrow_of_pin v P st0 wmin W t s a pa
        obtain ⟨stp2, e2, XY2, w2, hs2, _, _, he2, hc2, hf2, hw2, hp2⟩ := narrow_of_pin v P st0 wmin W t s b pb
        rw [hs] at hs1 hs2
        obtain rfl := Option.some.inj hs1
        obtain rfl := Option.some.inj hs2
        rcases np_class v t hΦ he1 hc1 hf1 (by omega) hp1 with ⟨q1, hq1, ht1, hj1⟩ | ⟨r1, hr1, _⟩
        · rcases np_class v t hΦ he2 hc2 hf2 (by omega) hp2 with ⟨q2, hq2, ht2, hj2⟩ | ⟨r2, hr2, _⟩
          · rw [hq] at hq1 hq2
            cases hq1; cases hq2
            rcases hj1 with h | ⟨hl1, hcp1⟩
            · omega
            rcases hj2 with h | ⟨hl2, hcp2⟩
            · omega
            obtain ⟨b1, r1⟩ := e1
            obtain ⟨b2, r2⟩ := e2
            simp only at ht1 ht2 hl1 hl2 hcp1 hcp2
            subst ht1 ht2
            exact hΦ.2.2.2.2.1 a b r1 r2 hha.1 hhb.1 (by omega) he1 he2 hl1 hl2 (skel_det hn hl1 hl2 hcp1 hcp2)
          · rw [hq] at hr2; cases hr2
        · rw [hq] at hr1; cases hr1
      · cases hb rfl
    · cases ha rfl
  calc ((List.range S).map N).sum ≤ ((List.range S).map (fun j => (if j < 3 then 1 else 0) + U j)).sum :=
        sum_map_le _ (fun j _ => hpt j)
    _ = ((List.range S).map (fun j => if j < 3 then 1 else 0)).sum + ((List.range S).map U).sum := sum_map_add _ _ _
    _ ≤ 3 + 1 := Nat.add_le_add (sum_lt3 S) hU

end

section
variable {α : Type} (v : Variant) (P : Prog α) (st0 : St) (wmin W : Nat)

/-- The narrow pins at challenger steps against entry `j`: at most one, and only if `j`
    is an adversary entry of the end state. -/
theorem chal_entry_count (hW : W ≤ 32) (t : List Nat) (S j : Nat) :
    ((List.range S).map (fun s => if ((strace t P st0)[s]?.map isAev) = some true then 0 else
      if (pinC wmin W (phiB v) P st0 t s j).map Prod.snd = some false then 1 else 0)).sum ≤
    if ((xrun false t P st0).2.ents[j]?.map Prod.fst) = some true then 1 else 0 := by
  have hn := params_n_pos v
  let C := fun s => if ((strace t P st0)[s]?.map isAev) = some true then 0 else
      if (pinC wmin W (phiB v) P st0 t s j).map Prod.snd = some false then 1 else 0
  -- a charged step is a challenger step against an adversary entry
  have key : ∀ s, C s ≠ 0 → ∃ stp r e, (strace t P st0)[s]? = some stp ∧ stp.2 = .c r ∧
      elig t stp = true ∧ PhiP v stp ∧ stp.1.ents[j]? = some e ∧ e.1 = true ∧
      LoShape (params v).n (params v).m r ∧ compat r (e.2.res t) = true := by
    intro s hC
    simp only [C] at hC
    split at hC
    · exact absurd rfl hC
    · rename_i hna
      split at hC
      · rename_i hpin
        obtain ⟨stp, e, XY, w, hs, hel, hΦ, he, hc, hf, hw, hp⟩ := narrow_of_pin v P st0 wmin W t s j hpin
        rcases np_class v t hΦ he hc hf (by omega) hp with ⟨q, hq, _⟩ | ⟨r, hr, ht, hl, hcp⟩
        · exfalso; apply hna; rw [hs]; simp [isAev, hq]
        · exact ⟨stp, r, e, hs, hr, hel, hΦ, he, ht, hl, hcp⟩
      · exact absurd rfl hC
  have hC1 : ∀ s, C s ≤ 1 := fun s => by
    simp only [C]
    split
    · omega
    · split <;> omega
  split
  · rename_i hT
    refine sum_le_one C hC1 (fun s1 s2 hlt h1 h2 => ?_) S
    obtain ⟨stp1, r1, e1, hs1, hr1, hel1, hΦ1, he1, ht1, hl1, hcp1⟩ := key s1 h1
    obtain ⟨stp2, r2, e2, hs2, hr2, hel2, hΦ2, he2, ht2, hl2, hcp2⟩ := key s2 h2
    obtain ⟨st1, ev1⟩ := stp1
    obtain ⟨st2, ev2⟩ := stp2
    simp only at hr1 hr2
    subst hr1 hr2
    -- the same entry at both steps
    obtain ⟨L, hL⟩ := trace_post t P st0 s1 s2 _ _ hlt hs1 hs2
    obtain ⟨L', hL'⟩ := post_ext t (st1, Ev.c r1)
    have he12 : e1 = e2 := by
      have : st2.ents[j]? = some e1 := by
        simp only at he1 hL hL' ⊢
        rw [hL, hL', List.append_assoc, List.getElem?_append_left (lt_entry he1)]; exact he1
      simp only at he2
      rw [he2] at this; exact (Option.some.inj this).symm
    subst he12
    have hsk := skel_det hn hl1 hl2 hcp1 hcp2
    have hfe := fresh_entry t P st0 hlt hs1 hel1 hs2
    simp only at hfe
    have h3 : 3 ≤ st1.ents.length := hΦ1.1
    obtain ⟨-, -, -, -, -, hF2⟩ := hΦ2
    have heq := (hF2 r2 rfl).2 hl2 st1.ents.length r1 h3 hfe hl1 hsk
    subst heq
    -- the second step is not fresh: its own request has an entry
    have hfr : st2.ents.length ≤ firstIdx (mC false t st2.rev r1) st2.ents := by simpa [elig] using hel2
    have hm : mC false t st2.rev r1 (false, r1) = true := by simp [mC]
    have := fr_before (mC false t st2.rev r1) st2.ents st1.ents.length (false, r1) hfe
      (by have := lt_entry hfe; omega)
    rw [hm] at this; cases this
  · rename_i hT
    have hz : ∀ s ∈ List.range S, C s = 0 := by
      intro s _
      cases hc : C s with
      | zero => rfl
      | succ k =>
        exfalso
        obtain ⟨stp, r, e, hs, _, _, _, he, ht, _⟩ := key s (by omega)
        obtain ⟨L, hL⟩ := trace_final t P st0 s stp hs
        apply hT
        rw [hL, List.getElem?_append_left (lt_entry he), he]
        simp [ht]
    rw [List.map_congr_left hz, sum_map_zero]
    exact Nat.le_refl 0

/-- The narrow-pin count of a program whose `Φ`-steps satisfy `PhiP`: at most five per
    adversary step, plus the initial adversary entries. -/
theorem narrow_count (hW : W ≤ 32) (t : List Nat) (S : Nat) :
    pairCountF wmin W (phiB v) P st0 false S t ≤
      5 * ((strace t P st0).filter isAev).length + cntT st0.ents := by
  let NA := ((strace t P st0).filter isAev).length
  let a := fun (s : Nat) => if ((strace t P st0)[s]?.map isAev) = some true then 1 else 0
  let N := fun (s j : Nat) => if (pinC wmin W (phiB v) P st0 t s j).map Prod.snd = some false then 1 else 0
  let C := fun (s j : Nat) => if ((strace t P st0)[s]?.map isAev) = some true then 0 else N s j
  have h1 : ∀ s, ((List.range S).map (N s)).sum ≤ 4 * a s + ((List.range S).map (C s)).sum := by
    intro s
    by_cases ha : ((strace t P st0)[s]?.map isAev) = some true
    · have hC0 : ((List.range S).map (C s)).sum = 0 := by
        simp only [C, ha, if_true]; exact sum_map_zero _
      rw [hC0]
      simp only [a, ha, if_true]
      cases hs : (strace t P st0)[s]? with
      | none => rw [hs] at ha; cases ha
      | some stp =>
        rw [hs] at ha
        obtain ⟨st, ev⟩ := stp
        cases ev with
        | a q => exact adv_step_count v P st0 wmin W hW t s S _ q hs rfl
        | c r => simp [isAev] at ha
        | r x => simp [isAev] at ha
    · simp only [a, C, ha, if_false, Nat.mul_zero, Nat.zero_add]; exact Nat.le_refl _
  have h2 : ((List.range S).map (fun s => ((List.range S).map (C s)).sum)).sum ≤ NA + cntT st0.ents := by
    rw [sum_swap (fun s j => C s j) S S]
    calc _ ≤ ((List.range S).map (fun j =>
            if ((xrun false t P st0).2.ents[j]?.map Prod.fst) = some true then 1 else 0)).sum :=
          sum_map_le _ (fun j _ => chal_entry_count v P st0 wmin W hW t S j)
      _ ≤ ((xrun false t P st0).2.ents.filter Prod.fst).length := sum_idx_filter _ _ _
      _ ≤ cntT st0.ents + NA := cnt_run t P st0
      _ = NA + cntT st0.ents := Nat.add_comm _ _
  have h3 : ((List.range S).map a).sum ≤ NA := sum_idx_filter isAev _ _
  show ((List.range S).map (fun s => ((List.range S).map (N s)).sum)).sum ≤ 5 * NA + cntT st0.ents
  calc _ ≤ ((List.range S).map (fun s => 4 * a s + ((List.range S).map (C s)).sum)).sum := sum_map_le _ (fun s _ => h1 s)
    _ = 4 * ((List.range S).map a).sum + ((List.range S).map (fun s => ((List.range S).map (C s)).sum)).sum := by
        rw [sum_map_add, sum_map_mul]
    _ ≤ 4 * NA + (NA + cntT st0.ents) := Nat.add_le_add (Nat.mul_le_mul_left _ h3) h2
    _ = 5 * NA + cntT st0.ents := by omega

end

/-! H1': the narrow-pin count, and the hidden-value bound with it. -/

theorem xrun_sAsk (t : List Nat) (r : SReq) (st : St) :
    (xrun false t (sAsk r) st).1 = [.hid (firstIdx (mC false t st.rev r) st.ents) r.outLen] := rfl

theorem prog_bind_eq {β γ : Type} (X : Prog β) (g : β → Prog γ) : (X >>= g) = X.bind g := rfl

theorem xmssNode_shape (t : List Nat) (p : Params) (tk pk seed : SB) (a : Adrs) :
    ∀ (height idx : Nat) (st : St), ∃ i, (xrun false t (sXmssNode p tk pk seed a idx height) st).1 = [.hid i p.n]
  | 0, idx, st => by
    simp only [sXmssNode, sWotsPkgen, sWotsCompress, sThash, sKeyed]
    simp only [prog_bind_eq, xrun_bind]
    exact ⟨_, xrun_sAsk t _ _⟩
  | height+1, idx, st => by
    simp only [sXmssNode, sThash, sKeyed]
    simp only [prog_bind_eq, xrun_bind]
    exact ⟨_, xrun_sAsk t _ _⟩

theorem kg_root_shape (t : List Nat) (v : Variant) :
    ∃ ρ, (xrun false t (sKgTail v (coinEx (params v).n)) (coinSt (params v).n)).1.1.drop 1 = [.hid ρ (params v).n] := by
  simp only [sKgTail, sDeriveKey]
  simp only [prog_bind_eq, xrun_bind]
  obtain ⟨i, hi⟩ := xmssNode_shape t (params v) _ _ (sSlice (coinEx (params v).n) 2 1) {layer := (params v).d - 1} (params v).hp 0
    (xrun false t (sAsk ⟨0, "DSM/sphincs/v2/prf", [], (coinEx (params v).n).take 1, 32⟩)
      (xrun false t (sAsk ⟨0, "DSM/sphincs/v2/thash", [], sSlice (coinEx (params v).n) 2 1, 32⟩)
        (coinSt (params v).n)).2).2
  refine ⟨i, ?_⟩
  simp only [xrun]
  rw [hi]; rfl

/-- The run context of H1' on tape `t`, for the structural invariant. -/
def structCtx (t : List Nat) (v : Variant) : Ctx :=
  ⟨t, v, (xrun false t (sKgTail v (coinEx (params v).n)) (coinSt (params v).n)).1.1.drop 1, [], []⟩

/-- `Φ` holds at every step of H1' with no earlier disagreement. -/
theorem game_phiB (v : Variant) (limits : Limits) (A : Bytes → RAdv) (t : List Nat) (s : Nat) (stp : St × Ev)
    (hs : (strace t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n))[s]? = some stp)
    (hnd : ∀ (s' : Nat) (stp' : St × Ev), s' < s →
      (strace t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n))[s']? = some stp' → dis t stp' = false) :
    phiB v stp = true := by
  obtain ⟨ρ, hρ⟩ := kg_root_shape t v
  have h := game_phi (c := structCtx t v) rfl ρ hρ limits A s stp hs hnd
  simpa [phiB] using h

theorem cntT_coin (n : Nat) : cntT (coinSt n).ents = 0 := by simp [cntT, coinSt]

/-- The hidden-value bound for H1' with the narrow-pin count discharged: narrow pins cost
    `5·A` (at most `A` adversary steps) against `256^n`, the 32-byte pins `S^2` against `256^32`. -/
theorem rom_ext_struct (v : Variant) (limits : Limits) (A : Bytes → RAdv) (R N S AA : Nat)
    (hn32 : (params v).n ≤ 32) (hR : 256^32 ∣ R)
    (hS : ∀ t s stp, (strace t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n))[s]? = some stp →
      s < S ∧ stp.1.ents.length ≤ S)
    (hA : ∀ t, ((strace t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)).filter isAev).length ≤ AA) :
    tsum R N (fun t => if anyDis (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) t then 1 else 0) *
        256^32 ≤
      R^N * (5 * AA) * 256^(32 - (params v).n) + R^N * (S * S) +
        tsum R N (fun t => if wildColl (params v).n (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) N t ||
          initColl t (coinSt (params v).n) then 1 else 0) * 256^32 :=
  hidden_bound_split (params v).n 32 (phiB v) (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)
    R N S (5 * AA) (S * S) hn32 hR hS (game_phiB v limits A)
    (fun t => by
      have := narrow_count v (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) (params v).n 32
        (Nat.le_refl _) t S
      rw [cntT_coin, Nat.add_zero] at this
      exact Nat.le_trans this (Nat.mul_le_mul_left _ (hA t)))
    (fun t => pairCountF_le_sq _ _ _ _ _ _ _ _)

/-- SPHINCS+-128f, H1, with the narrow-pin count of H1' discharged. Against `2^-256`:
    the won tapes are the canonical collisions on H1''s table, `JA` ITSR candidates against
    `2^-128`, twice `5·AA` narrow pins against `2^-128` (`AA` adversary steps of H1'),
    twice `S^2` wide pins, and twice the wild-guess/collision or initial-collision tapes of H1'.
    Conditional on the ITSR budget hypotheses, the step bound `S` and the adversary-step
    bound `AA` of H1'. -/
theorem rom_win_struct_128f (limits : Limits) (A : Bytes → RAdv) (c N q JA S AA : Nat) (hc : 0 < c)
    (hq : q ≤ 2^64)
    (hN : ∀ t : List Nat, t.length = N → (runG .spx128f limits A t).2.length ≤ N)
    (hC : ∀ t : List Nat, t.length = N → ((runG .spx128f limits A t).2.filter isC).length ≤ q)
    (hJ : ∀ t : List Nat, t.length = N → ((runG .spx128f limits A t).2.filter isA).length ≤ JA)
    (hS : ∀ t s stp, (strace t (gameS' .spx128f limits A (coinEx (params .spx128f).n))
      (coinSt (params .spx128f).n))[s]? = some stp → s < S ∧ stp.1.ents.length ≤ S)
    (hA : ∀ t, ((strace t (gameS' .spx128f limits A (coinEx (params .spx128f).n))
      (coinSt (params .spx128f).n)).filter isAev).length ≤ AA) :
    tsum (c * 256^(params .spx128f).m) N (fun t => ind ((runG .spx128f limits A t).1.win = true)) * 256^32 ≤
      tsum (c * 256^(params .spx128f).m) N (fun t => ind (CanonCollIn (finO' .spx128f limits A t) (params .spx128f)
        (expTk (finO' .spx128f limits A t) .spx128f (sres t (coinEx (params .spx128f).n)))
        (expPrf (finO' .spx128f limits A t) .spx128f (sres t (coinEx (params .spx128f).n)))
        (expSeed .spx128f (sres t (coinEx (params .spx128f).n)))
        (verifyLog (finO' .spx128f limits A t) .spx128f (finKey .spx128f limits A t).1
          (runG .spx128f limits A t).1.msg (runG .spx128f limits A t).1.sig))) * 256^32 +
      JA * (c * 256^(params .spx128f).m)^N * 256^16 +
      2 * ((c * 256^(params .spx128f).m)^N * (5 * AA) * 256^16) +
      2 * ((c * 256^(params .spx128f).m)^N * (S * S)) +
      2 * (tsum (c * 256^(params .spx128f).m) N (fun t => if wildColl (params .spx128f).n
        (gameS' .spx128f limits A (coinEx (params .spx128f).n)) (coinSt (params .spx128f).n) N t ||
          initColl t (coinSt (params .spx128f).n) then 1 else 0) * 256^32) := by
  have h1 := rom_win_128f limits A c N q JA hc hq hN hC hJ
  have hR : 256^32 ∣ c * 256^(params .spx128f).m :=
    Nat.dvd_mul_left_of_dvd (Nat.pow_dvd_pow 256 (by decide)) c
  have h2 := rom_ext_struct .spx128f limits A (c * 256^(params .spx128f).m) N S AA (by decide) hR hS hA
  rw [show 32 - (params .spx128f).n = 16 by decide] at h2
  rw [show (2:Nat)^128 = 256^16 by decide] at h1
  rw [show (256:Nat)^32 = 256^16 * 256^16 by decide] at h2 ⊢
  generalize (256:Nat)^16 = K at h1 h2 ⊢
  have h3 := Nat.mul_le_mul_right K h1
  rw [Nat.add_mul, Nat.add_mul] at h3
  have a3 : ∀ X : Nat, 2 * (X * K) * K = 2 * (X * (K * K)) := fun X => by rw [Nat.mul_assoc, Nat.mul_assoc]
  rw [Nat.mul_assoc _ K K, Nat.mul_assoc _ K K, a3] at h3
  omega

end DSM.Rom
