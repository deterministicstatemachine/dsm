-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomExt

/- Secrecy of the WOTS chain values and FORS secrets in the extended game H1'.

   A second Hoare-style judgment `J2`, over disagreement-free symbolic runs of
   H1' whose final table is `D`. Its invariant `Inv2` records:
   * origin: coins at entries 0-2, handles refer to existing entries,
     adversary entries carry no handles;
   * distinctness: no two entries resolve to the same request (on a
     disagreement-free run every lookup finds the first entry with the
     request's resolution, so a new entry is never a repeat);
   * protection/disclosure: every revealed handle is `Safe2`. It never names
     an entry mentioning SK.seed or SK.prf (so neither coin nor a key derived
     from them is revealed); it is not a low WOTS chain value (a chain value
     below the digit the honest key signs at that position, `LowChain`); and
     if it is a FORS secret, its index is selected by the digest of a
     challenger signing request;
   * signing requests: every challenger h_msg entry is the signing request of
     a message in `Sg` with its randomizer's PRF-msg entry.
   The honest messages, hence the digits, are those of the final table `D`.

   On a disagreement-free run, the extension's honest successor request at a
   low chain value (or an unselected FORS secret) and the verifier's request
   with the forged value are distinct entries with one resolution unless the
   protected value was revealed, which `Inv2` excludes. -/
namespace DSM.Rom
open DSM.Sphincs DSM.Sphincs.Security

/-! Addresses. -/

def A5 (L T F ci : Nat) : Adrs := {(wA L T F).setType 5 with keypair := (wA L T F).keypair, chain := ci}
def A0 (L T F ci s : Nat) : Adrs := {({wA L T F with chain := ci} : Adrs) with hash := s}
def fsA (tree leaf gi : Nat) : Adrs :=
  {(forsAdrs tree leaf).setType 6 with keypair := (forsAdrs tree leaf).keypair, hash := gi}
def flA (tree leaf gi : Nat) : Adrs := {forsAdrs tree leaf with chain := 0, hash := gi}

theorem adrs_fields (a b : Adrs) (h : a.bytes = b.bytes) :
    be 4 a.layer = be 4 b.layer ∧ be 8 a.tree = be 8 b.tree ∧ be 4 a.kind = be 4 b.kind ∧
      be 4 a.keypair = be 4 b.keypair ∧ be 4 a.chain = be 4 b.chain ∧ be 4 a.hash = be 4 b.hash := by
  unfold Adrs.bytes at h
  obtain ⟨h, hHash⟩ := List.append_inj h (by simp [be_width])
  obtain ⟨h, hChain⟩ := List.append_inj h (by simp [be_width])
  obtain ⟨h, hKeypair⟩ := List.append_inj h (by simp [be_width])
  obtain ⟨h, hKind⟩ := List.append_inj h (by simp [be_width])
  obtain ⟨h, hTree⟩ := List.append_inj h (by simp [be_width])
  obtain ⟨hLayer, _⟩ := List.append_inj h (by simp [be_width])
  exact ⟨hLayer, hTree, hKind, hKeypair, hChain, hHash⟩

theorem adrs_kind (a b : Adrs) (h : a.bytes = b.bytes) (ha : a.kind < 256^4) (hb : b.kind < 256^4) :
    a.kind = b.kind :=
  be_injective _ _ _ ha hb (adrs_fields a b h).2.2.1

/-! Requests. -/

/-- Derivation of the tweak key from PK.seed (coin 2). -/
def dTk (n : Nat) : SReq := ⟨0, "DSM/sphincs/v2/thash", [], [.hid 2 n], 32⟩
/-- A PRF request under the PRF key at entry `pk`, with PK.seed. -/
def prfReq (n pk : Nat) (A : Adrs) : SReq := ⟨1, "", [.hid pk 32], [.hid 2 n, .lit A.bytes], n⟩
/-- A thash request under the tweak key at entry `itk`, on one handle. -/
def chReq (n itk : Nat) (A : Adrs) (h : Nat) : SReq := ⟨1, "", [.hid itk 32], [.lit A.bytes, .hid h n], n⟩

/-- Entry `h` is the honest WOTS chain value at step `s` of chain `ci` of the
    key at (L, T, F), computed from the honest secret through challenger
    entries only. -/
def LowAt (n : Nat) (st : St) (h L T F ci : Nat) : Nat → Prop
  | 0 => ∃ pk, st.ents[h]? = some (false, prfReq n pk (A5 L T F ci)) ∧ st.ents[pk]? = some (false, dPrf n)
  | s+1 => ∃ itk h', st.ents[h]? = some (false, chReq n itk (A0 L T F ci s) h') ∧
      st.ents[itk]? = some (false, dTk n) ∧ LowAt n st h' L T F ci s

def InR (L T F ci s : Nat) : Prop := L < 256^4 ∧ T < 256^8 ∧ F < 256^4 ∧ ci < 256^4 ∧ s < 256^4

/-- Entry `h` is the honest FORS secret at (tree, leaf, gi). -/
def FsAt (n : Nat) (st : St) (h tree leaf gi : Nat) : Prop :=
  ∃ pk, st.ents[h]? = some (false, prfReq n pk (fsA tree leaf gi)) ∧ st.ents[pk]? = some (false, dPrf n)

def InRF (tree leaf gi : Nat) : Prop := tree < 256^8 ∧ leaf < 256^4 ∧ gi < 256^4

/-- The run context: tape, variant, the key's root handle, the final table,
    the messages signed. -/
structure Ctx where
  t : List Nat
  v : Variant
  root : SB
  D : List Draw
  Sg : List Bytes

namespace Ctx
variable (c : Ctx)
abbrev n : Nat := (params c.v).n
abbrev pm : Nat := (params c.v).m
abbrev O : Oracle Id := oracleOf c.t c.D
abbrev e : Bytes := sres c.t (coinEx (params c.v).n)
/-- The honest message signed at hypertree position (L, T, F). -/
def M (L T F : Nat) : Bytes :=
  htMsg c.O (params c.v) (expTk c.O c.v c.e) (expPrf c.O c.v c.e) (expSeed c.v c.e) L T F
/-- Its digit on chain `ci`. -/
def dgt (L T F ci : Nat) : Nat := (wotsDigits (params c.v) (c.M L T F)).getD ci 0
end Ctx

/-- A FORS index selected by digest `dg`. -/
def Sel (v : Variant) (dg : Bytes) (tree leaf gi : Nat) : Prop :=
  (splitDigest (params v) dg).tree = tree ∧ (splitDigest (params v) dg).leaf = leaf ∧
    ∃ j, j < (params v).k ∧ gi = j*2^(params v).a + forsDigit (params v) (splitDigest (params v) dg).md j

section
variable (c : Ctx)

/-- A low chain value: below the digit the honest key signs. -/
def LowChain (st : St) (h : Nat) : Prop :=
  ∃ L T F ci s, InR L T F ci s ∧ s < c.dgt L T F ci ∧ LowAt c.n st h L T F ci s

/-- Entry `k` resolves to the signing request of `m ∈ Sg`, with its randomizer's PRF-msg entry. -/
def SigD (st : St) (k : Nat) (m : Bytes) : Prop :=
  ∃ iR dk e, m ∈ c.Sg ∧ st.ents[iR]? = some (false, rqOf c.n dk m) ∧
    st.ents[dk]? = some (false, dReq c.n) ∧ st.ents[k]? = some e ∧
    e.2.res c.t = (hqOf c.n c.pm c.root iR m).res c.t

/-- A handle that may be disclosed. -/
def Safe2 (st : St) (i : Nat) : Prop :=
  i < st.ents.length ∧ ¬ Prot st i ∧
  (∀ tree leaf gi, InRF tree leaf gi → FsAt c.n st i tree leaf gi →
    ∃ k m, SigD c st k m ∧ Sel c.v (be c.pm (c.t.getD k 0)) tree leaf gi) ∧
  ¬ LowChain c st i

def Gd2 (st : St) (x : SB) : Prop := ∀ i w, SV.hid i w ∈ x → Safe2 c st i

def Inv2 (st : St) : Prop :=
  (st.ents[0]? = some (false, coin c.n 0) ∧ st.ents[1]? = some (false, coin c.n 1) ∧
    st.ents[2]? = some (false, coin c.n 2)) ∧
  (∀ (i : Nat) (e : Bool × SReq), st.ents[i]? = some e → ∀ h ∈ e.2.hids, h < st.ents.length) ∧
  (∀ (a : Nat) (qa : SReq), st.ents[a]? = some (true, qa) → qa.hids = []) ∧
  (∀ (a b : Nat) (ea eb : Bool × SReq), a < b → 3 ≤ b → st.ents[a]? = some ea → st.ents[b]? = some eb →
    ea.2.res c.t ≠ eb.2.res c.t) ∧
  (∀ i ∈ st.rev, Safe2 c st i) ∧
  (∀ (k iR : Nat) (m : Bytes), st.ents[k]? = some (false, hqOf c.n c.pm c.root iR m) →
    m ∈ c.Sg ∧ ∃ dk, st.ents[iR]? = some (false, rqOf c.n dk m) ∧ st.ents[dk]? = some (false, dReq c.n))

/-- Entries and revealed handles only grow. -/
def Grow2 (st st' : St) : Prop := (∃ L, st'.ents = st.ents ++ L) ∧ ∀ x ∈ st.rev, x ∈ st'.rev

def Stable2 (P : St → Prop) : Prop := ∀ st st', Inv2 c st → Grow2 st st' → P st → P st'

/-- Hoare judgment on disagreement-free runs whose final table extends `c.D`'s prefix. -/
def J2 {α : Type} (P : Prog α) (P0 : St → Prop) (Q : α → St → Prop) : Prop :=
  ∀ st, Inv2 c st → P0 st → (∀ s ∈ strace c.t P st, dis c.t s = false) →
    Pre (resD c.t (xrun false c.t P st).2) c.D →
    Inv2 c (xrun false c.t P st).2 ∧ Grow2 st (xrun false c.t P st).2 ∧
      Q (xrun false c.t P st).1 (xrun false c.t P st).2
end

/-! Growth. -/

theorem grow_get {st st' : St} (h : Grow2 st st') {i : Nat} {e : Bool × SReq} (he : st.ents[i]? = some e) :
    st'.ents[i]? = some e := ext_get h.1 he

theorem grow_len {st st' : St} (h : Grow2 st st') : st.ents.length ≤ st'.ents.length := ext_len h.1

theorem grow_refl (st : St) : Grow2 st st := ⟨⟨[], by simp⟩, fun _ h => h⟩

theorem grow_trans {a b d : St} (h1 : Grow2 a b) (h2 : Grow2 b d) : Grow2 a d :=
  ⟨ext_trans h1.1 h2.1, fun x hx => h2.2 x (h1.2 x hx)⟩

theorem grow_back {st st' : St} (h : Grow2 st st') {i : Nat} {e : Bool × SReq} (hi : i < st.ents.length)
    (he : st'.ents[i]? = some e) : st.ents[i]? = some e := by
  obtain ⟨⟨L, hL⟩, _⟩ := h
  rw [hL, List.getElem?_append_left hi] at he; exact he

section
variable {c : Ctx}

theorem lt_entry {st : St} {i : Nat} {e : Bool × SReq} (h : st.ents[i]? = some e) : i < st.ents.length :=
  (List.getElem?_eq_some_iff.mp h).1

theorem hid_lt {st : St} (hI : Inv2 c st) {i : Nat} {e : Bool × SReq} (he : st.ents[i]? = some e)
    {h : Nat} (hm : h ∈ e.2.hids) : h < st.ents.length := hI.2.1 i e he h hm

theorem lowAt_fwd {st st' : St} (hg : Grow2 st st') {h L T F ci : Nat} :
    ∀ s, LowAt c.n st h L T F ci s → LowAt c.n st' h L T F ci s := by
  intro s
  induction s generalizing h with
  | zero => rintro ⟨pk, h1, h2⟩; exact ⟨pk, grow_get hg h1, grow_get hg h2⟩
  | succ s ih => rintro ⟨itk, h', h1, h2, h3⟩; exact ⟨itk, h', grow_get hg h1, grow_get hg h2, ih h3⟩

theorem lowAt_back {st st' : St} (hI : Inv2 c st) (hg : Grow2 st st') {L T F ci : Nat} :
    ∀ s h, h < st.ents.length → LowAt c.n st' h L T F ci s → LowAt c.n st h L T F ci s := by
  intro s
  induction s with
  | zero =>
    rintro h hh ⟨pk, h1, h2⟩
    have h1' := grow_back hg hh h1
    have hpk : pk < st.ents.length := hid_lt hI h1' (by simp [prfReq, SReq.hids, shids])
    exact ⟨pk, h1', grow_back hg hpk h2⟩
  | succ s ih =>
    rintro h hh ⟨itk, h', h1, h2, h3⟩
    have h1' := grow_back hg hh h1
    have hitk : itk < st.ents.length := hid_lt hI h1' (by simp [chReq, SReq.hids, shids])
    have hh' : h' < st.ents.length := hid_lt hI h1' (by simp [chReq, SReq.hids, shids])
    exact ⟨itk, h', h1', grow_back hg hitk h2, ih h' hh' h3⟩

theorem fsAt_back {st st' : St} (hI : Inv2 c st) (hg : Grow2 st st') {h tree leaf gi : Nat}
    (hh : h < st.ents.length) (hf : FsAt c.n st' h tree leaf gi) : FsAt c.n st h tree leaf gi := by
  obtain ⟨pk, h1, h2⟩ := hf
  have h1' := grow_back hg hh h1
  have hpk : pk < st.ents.length := hid_lt hI h1' (by simp [prfReq, SReq.hids, shids])
  exact ⟨pk, h1', grow_back hg hpk h2⟩

theorem safe2_mono {st st' : St} (hI : Inv2 c st) (hg : Grow2 st st') {i : Nat} (h : Safe2 c st i) :
    Safe2 c st' i := by
  obtain ⟨hl, hp, hf, hlow⟩ := h
  obtain ⟨e, he⟩ : ∃ e, st.ents[i]? = some e := ⟨_, List.getElem?_eq_getElem hl⟩
  have he' := grow_get hg he
  refine ⟨Nat.lt_of_lt_of_le hl (grow_len hg), ?_, ?_, ?_⟩
  · rintro ⟨e2, h2, h3⟩
    obtain rfl : e = e2 := Option.some.inj (he'.symm.trans h2)
    exact hp ⟨e, he, h3⟩
  · intro tree leaf gi hr hfs
    obtain ⟨k, m, ⟨iR, dk, e, hm, h1, h2, h3, h4⟩, hsel⟩ := hf tree leaf gi hr (fsAt_back hI hg hl hfs)
    exact ⟨k, m, ⟨iR, dk, e, hm, grow_get hg h1, grow_get hg h2, grow_get hg h3, h4⟩, hsel⟩
  · rintro ⟨L, T, F, ci, s, hr, hs, hlw⟩
    exact hlow ⟨L, T, F, ci, s, hr, hs, lowAt_back hI hg s i hl hlw⟩

theorem gd2_mono {st st' : St} (hI : Inv2 c st) (hg : Grow2 st st') {x : SB} (h : Gd2 c st x) :
    Gd2 c st' x := fun i w hm => safe2_mono hI hg (h i w hm)

theorem prot0 {st : St} (hI : Inv2 c st) : Prot st 0 :=
  ⟨_, hI.1.1, Or.inl (by simp [coin, SReq.hids, shids])⟩

theorem prot1 {st : St} (hI : Inv2 c st) : Prot st 1 :=
  ⟨_, hI.1.2.1, Or.inr (by simp [coin, SReq.hids, shids])⟩

theorem not_rev_unsafe {st : St} (hI : Inv2 c st) {i : Nat} (h : ¬ Safe2 c st i) : i ∉ st.rev :=
  fun hm => h (hI.2.2.2.2.1 i hm)

theorem not_rev_prot2 {st : St} (hI : Inv2 c st) {i : Nat} (hp : Prot st i) : i ∉ st.rev :=
  not_rev_unsafe hI (fun h => h.2.1 hp)

theorem not_rev_low {st : St} (hI : Inv2 c st) {i : Nat} (hl : LowChain c st i) : i ∉ st.rev :=
  not_rev_unsafe hI (fun h => h.2.2.2 hl)

theorem lowAt_inR_pred {L T F ci s : Nat} (h : InR L T F ci (s+1)) : InR L T F ci s := by
  obtain ⟨a, b, d, e, f⟩ := h; exact ⟨a, b, d, e, by omega⟩

/-- An open entry may be disclosed. -/
theorem safe2_of_open {st : St} (hI : Inv2 c st) {i : Nat} {e : Bool × SReq}
    (he : st.ents[i]? = some e) (ho : isOpen st.rev e.2 = true) : Safe2 c st i := by
  have hm := open_mem ho
  refine ⟨lt_entry he, ?_, ?_, ?_⟩
  · rintro ⟨e2, h2, h3⟩
    obtain rfl : e = e2 := Option.some.inj (he.symm.trans h2)
    rcases h3 with h3 | h3
    · exact not_rev_prot2 hI (prot0 hI) (hm 0 h3)
    · exact not_rev_prot2 hI (prot1 hI) (hm 1 h3)
  · intro tree leaf gi _ ⟨pk, h1, h2⟩
    have : e = (false, prfReq c.n pk (fsA tree leaf gi)) := Option.some.inj (he.symm.trans h1)
    subst this
    exact absurd (hm pk (by simp [prfReq, SReq.hids, shids]))
      (not_rev_prot2 hI ⟨_, h2, Or.inl (by simp [dPrf, SReq.hids, shids])⟩)
  · rintro ⟨L, T, F, ci, s, hr, hs, hlw⟩
    cases s with
    | zero =>
      obtain ⟨pk, h1, h2⟩ := hlw
      have : e = (false, prfReq c.n pk (A5 L T F ci)) := Option.some.inj (he.symm.trans h1)
      subst this
      exact absurd (hm pk (by simp [prfReq, SReq.hids, shids]))
        (not_rev_prot2 hI ⟨_, h2, Or.inl (by simp [dPrf, SReq.hids, shids])⟩)
    | succ s =>
      obtain ⟨itk, h', h1, _, h3⟩ := hlw
      have : e = (false, chReq c.n itk (A0 L T F ci s) h') := Option.some.inj (he.symm.trans h1)
      subst this
      exact absurd (hm h' (by simp [chReq, SReq.hids, shids]))
        (not_rev_low hI ⟨L, T, F, ci, s, lowAt_inR_pred hr, by omega, h3⟩)
end

/-! Runs only grow; one step each. -/

theorem xrun_grow (t : List Nat) {α : Type} : ∀ (P : Prog α) (st : St), Grow2 st (xrun false t P st).2
  | .done _, st => grow_refl st
  | .askC r k, st => by
    simp only [xrun]
    refine grow_trans ?_ (xrun_grow t _ _)
    unfold addC
    split
    · exact grow_refl st
    · exact ⟨⟨_, rfl⟩, fun x hx => hx⟩
  | .askA q k, st => by
    simp only [xrun]
    refine grow_trans ?_ (xrun_grow t _ _)
    unfold addA
    split
    · exact ⟨⟨[], by simp⟩, fun x hx => List.mem_cons_of_mem _ hx⟩
    · exact ⟨⟨_, rfl⟩, fun x hx => List.mem_cons_of_mem _ hx⟩
  | .reveal x k, st => by
    simp only [xrun]
    exact grow_trans ⟨⟨[], by simp⟩, fun y hy => List.mem_append_right _ hy⟩ (xrun_grow t _ _)

theorem pre_back (t : List Nat) {st st' : St} (hg : Grow2 st st') {D : List Draw}
    (h : Pre (resD t st') D) : Pre (resD t st) D := by
  obtain ⟨⟨L, hL⟩, _⟩ := hg
  obtain ⟨X, hX⟩ := h
  refine ⟨L.map (fun e => (e.1, e.2.res t)) ++ X, ?_⟩
  rw [hX]; simp [resD, hL]

theorem dis_a {t : List Nat} {st : St} {q : Request} (hd : dis t (st, .a q) = false) :
    ∀ e ∈ st.ents, mA true t st.rev q e = mA false t st.rev q e := by
  intro e he
  simp only [dis, List.any_eq_false] at hd
  have := hd e he
  revert this
  cases mA true t st.rev q e <;> cases mA false t st.rev q e <;> simp

section
variable {c : Ctx}

theorem step_askC2 (st : St) (r : SReq) (hI : Inv2 c st)
    (hh : ∀ h ∈ r.hids, h < st.ents.length)
    (hq : ∀ iR m, r = hqOf c.n c.pm c.root iR m → m ∈ c.Sg ∧
      ∃ dk, st.ents[iR]? = some (false, rqOf c.n dk m) ∧ st.ents[dk]? = some (false, dReq c.n))
    (hd : dis c.t (st, .c r) = false) :
    Inv2 c (addC st (firstIdx (mC false c.t st.rev r) st.ents) r) := by
  generalize hi : firstIdx (mC false c.t st.rev r) st.ents = i
  by_cases hl : i < st.ents.length
  · have : addC st i r = st := by simp [addC, hl]
    rw [this]; exact hI
  · have hi' : i = st.ents.length := Nat.le_antisymm (hi ▸ firstIdx_le _ _) (Nat.le_of_not_lt hl)
    have ha : addC st i r = ⟨st.ents ++ [(false, r)], st.rev⟩ := by simp [addC, hl]
    rw [ha]
    have hx : Grow2 st ⟨st.ents ++ [(false, r)], st.rev⟩ := ⟨⟨_, rfl⟩, fun _ h => h⟩
    have hreal : ∀ (j : Nat) (e : Bool × SReq), st.ents[j]? = some e → mC true c.t st.rev r e = false := by
      intro j e he
      rw [dis_c hd e (mem_of_getElem? he)]
      exact firstIdx_before _ _ j e he (by rw [hi, hi']; exact lt_entry he)
    obtain ⟨hc, hs, hadv, hdist, hrev, hhq⟩ := hI
    refine ⟨⟨grow_get hx hc.1, grow_get hx hc.2.1, grow_get hx hc.2.2⟩, ?_, ?_, ?_, ?_, ?_⟩
    · intro j e he h hm
      simp only [List.length_append, List.length_singleton]
      rcases get_snoc he with ⟨_, he⟩ | ⟨_, rfl⟩
      · exact Nat.lt_succ_of_lt (hs j e he h hm)
      · exact Nat.lt_succ_of_lt (hh h hm)
    · intro a qa he
      rcases get_snoc he with ⟨_, he⟩ | ⟨_, he⟩
      · exact hadv a qa he
      · cases he
    · intro a b ea eb hab hb3 ha hb
      rcases get_snoc ha with ⟨hal, ha0⟩ | ⟨hal, ha0⟩
      · rcases get_snoc hb with ⟨_, hb0⟩ | ⟨_, hb0⟩
        · exact hdist a b ea eb hab hb3 ha0 hb0
        · subst hb0
          have := hreal a ea ha0
          simpa [mC] using this
      · rcases get_snoc hb with ⟨hbl, _⟩ | ⟨hbl, _⟩ <;> omega
    · intro j hj
      exact safe2_mono ⟨hc, hs, hadv, hdist, hrev, hhq⟩ hx (hrev j hj)
    · intro k iR m hk
      rcases get_snoc hk with ⟨_, hk0⟩ | ⟨_, hk0⟩
      · obtain ⟨hm, dk, h1, h2⟩ := hhq k iR m hk0
        exact ⟨hm, dk, grow_get hx h1, grow_get hx h2⟩
      · have hr : r = hqOf c.n c.pm c.root iR m := (Prod.mk.inj hk0).2.symm
        obtain ⟨hm, dk, h1, h2⟩ := hq iR m hr
        exact ⟨hm, dk, grow_get hx h1, grow_get hx h2⟩

theorem step_askA2 (st : St) (q : Request) (hI : Inv2 c st) (hd : dis c.t (st, .a q) = false) :
    Inv2 c (addA st (firstIdx (mA false c.t st.rev q) st.ents) q) := by
  generalize hi : firstIdx (mA false c.t st.rev q) st.ents = i
  obtain ⟨hc, hs, hadv, hdist, hrev, hhq⟩ := hI
  by_cases hl : i < st.ents.length
  · have ha : addA st i q = ⟨st.ents, i :: st.rev⟩ := by simp [addA, hl]
    rw [ha]
    have hx : Grow2 st ⟨st.ents, i :: st.rev⟩ := ⟨⟨[], by simp⟩, fun _ h => List.mem_cons_of_mem _ h⟩
    refine ⟨hc, hs, hadv, hdist, ?_, hhq⟩
    intro j hj
    simp only [List.mem_cons] at hj
    rcases hj with rfl | hj
    · obtain ⟨e, he, hp⟩ := firstIdx_hit _ st.ents (hi ▸ hl)
      rw [hi] at he
      simp only [mA, Bool.false_eq_true, if_false, Bool.and_eq_true] at hp
      exact safe2_mono ⟨hc, hs, hadv, hdist, hrev, hhq⟩ hx (safe2_of_open ⟨hc, hs, hadv, hdist, hrev, hhq⟩ he hp.1)
    · exact safe2_mono ⟨hc, hs, hadv, hdist, hrev, hhq⟩ hx (hrev j hj)
  · have hi' : i = st.ents.length := Nat.le_antisymm (hi ▸ firstIdx_le _ _) (Nat.le_of_not_lt hl)
    have ha : addA st i q = ⟨st.ents ++ [(true, lift q)], st.ents.length :: st.rev⟩ := by
      simp [addA, hi']
    rw [ha]
    have hx : Grow2 st ⟨st.ents ++ [(true, lift q)], st.ents.length :: st.rev⟩ :=
      ⟨⟨_, rfl⟩, fun _ h => List.mem_cons_of_mem _ h⟩
    have hreal : ∀ (j : Nat) (e : Bool × SReq), st.ents[j]? = some e → mA true c.t st.rev q e = false := by
      intro j e he
      rw [dis_a hd e (mem_of_getElem? he)]
      exact firstIdx_before _ _ j e he (by rw [hi, hi']; exact lt_entry he)
    refine ⟨⟨grow_get hx hc.1, grow_get hx hc.2.1, grow_get hx hc.2.2⟩, ?_, ?_, ?_, ?_, ?_⟩
    · intro j e he h hm
      simp only [List.length_append, List.length_singleton]
      rcases get_snoc he with ⟨_, he⟩ | ⟨_, rfl⟩
      · exact Nat.lt_succ_of_lt (hs j e he h hm)
      · rw [lift_hids] at hm; cases hm
    · intro a qa he
      rcases get_snoc he with ⟨_, he⟩ | ⟨_, he⟩
      · exact hadv a qa he
      · rw [(Prod.mk.inj he).2]; exact lift_hids q
    · intro a b ea eb hab hb3 ha hb
      rcases get_snoc ha with ⟨hal, ha0⟩ | ⟨hal, ha0⟩
      · rcases get_snoc hb with ⟨_, hb0⟩ | ⟨_, hb0⟩
        · exact hdist a b ea eb hab hb3 ha0 hb0
        · subst hb0
          have := hreal a ea ha0
          simp only [mA, if_true, decide_eq_false_iff_not] at this
          rw [lift_res]; exact this
      · rcases get_snoc hb with ⟨hbl, _⟩ | ⟨hbl, _⟩ <;> omega
    · intro j hj
      simp only [List.mem_cons] at hj
      rcases hj with rfl | hj
      · refine ⟨by simp, ?_, ?_, ?_⟩
        · rintro ⟨e2, h2, h3⟩
          simp at h2
          subst h2
          rw [lift_hids] at h3; simp at h3
        · intro tree leaf gi _ ⟨pk, h1, _⟩
          simp at h1
        · rintro ⟨L, T, F, ci, s, _, _, hlw⟩
          cases s with
          | zero => obtain ⟨pk, h1, _⟩ := hlw; simp at h1
          | succ s => obtain ⟨itk, h', h1, _⟩ := hlw; simp at h1
      · exact safe2_mono ⟨hc, hs, hadv, hdist, hrev, hhq⟩ hx (hrev j hj)
    · intro k iR m hk
      rcases get_snoc hk with ⟨_, hk0⟩ | ⟨_, hk0⟩
      · obtain ⟨hm, dk, h1, h2⟩ := hhq k iR m hk0
        exact ⟨hm, dk, grow_get hx h1, grow_get hx h2⟩
      · cases hk0

theorem step_reveal2 (st : St) (x : List SV) (hI : Inv2 c st) (hx : Gd2 c st x) :
    Inv2 c ⟨st.ents, shids x ++ st.rev⟩ := by
  have hg : Grow2 st ⟨st.ents, shids x ++ st.rev⟩ := ⟨⟨[], by simp⟩, fun _ h => List.mem_append_right _ h⟩
  obtain ⟨hc, hs, hadv, hdist, hrev, hhq⟩ := hI
  refine ⟨hc, hs, hadv, hdist, ?_, hhq⟩
  intro j hj
  rcases List.mem_append.mp hj with hj | hj
  · obtain ⟨w, hw⟩ := mem_shids x j hj
    exact safe2_mono ⟨hc, hs, hadv, hdist, hrev, hhq⟩ hg (hx j w hw)
  · exact safe2_mono ⟨hc, hs, hadv, hdist, hrev, hhq⟩ hg (hrev j hj)
end

/-! The final table agrees with every entry. -/

theorem findDraw_first (r : Request) : ∀ (l : List Draw) (j : Nat) (e : Draw), l[j]? = some e → e.2 = r →
    (∀ a x, a < j → l[a]? = some x → x.2 ≠ r) → findDraw l r = some j
  | [], _, _, h, _, _ => by simp at h
  | x :: l, 0, e, h, he, _ => by
    simp only [List.getElem?_cons_zero, Option.some.injEq] at h
    subst h
    simp only [findDraw, he, (req_beq_iff r r).mpr rfl, if_true]
  | x :: l, j+1, e, h, he, hb => by
    simp only [List.getElem?_cons_succ] at h
    have hx : x.2 ≠ r := hb 0 x (by omega) rfl
    have hx' : (x.2 == r) = false := by
      cases hq : x.2 == r
      · rfl
      · exact absurd ((req_beq_iff _ _).mp hq) hx
    simp only [findDraw, hx', Bool.false_eq_true, if_false]
    rw [findDraw_first r l j e h he (fun a y ha hy => hb (a+1) y (by omega) (by simpa using hy))]
    rfl

section
variable {c : Ctx}

theorem agree {st : St} (hI : Inv2 c st) (hD : Pre (resD c.t st) c.D) {j : Nat} {e : Bool × SReq}
    (he : st.ents[j]? = some e) : c.O (e.2.res c.t) = be e.2.outLen (c.t.getD j 0) := by
  have hm : ∃ x ∈ resD c.t st, x.2 = e.2.res c.t :=
    ⟨(e.1, e.2.res c.t), List.mem_map.mpr ⟨e, mem_of_getElem? he, rfl⟩, rfl⟩
  obtain ⟨a, hf⟩ := findDraw_of_mem _ _ hm
  have haj : a ≤ j := findDraw_min _ _ a hf j (e.1, e.2.res c.t) (by simp [resD, he]) rfl
  obtain ⟨x, hx, hxr⟩ := findDraw_get _ _ a hf
  simp only [resD, List.getElem?_map, Option.map_eq_some_iff] at hx
  obtain ⟨y, hy, rfl⟩ := hx
  have hval : be e.2.outLen (c.t.getD a 0) = be e.2.outLen (c.t.getD j 0) := by
    rcases Nat.lt_or_eq_of_le haj with hlt | rfl
    · by_cases h3 : 3 ≤ j
      · exact absurd hxr (hI.2.2.2.1 a j y e hlt h3 hy he)
      · -- two coin entries with one resolution carry one value
        have hce : ∀ k f, k < 3 → st.ents[k]? = some f → f = (false, coin c.n k) := by
          intro k f hk hf
          rcases k with _ | _ | _ | k
          · rw [hI.1.1] at hf; exact (Option.some.inj hf).symm
          · rw [hI.1.2.1] at hf; exact (Option.some.inj hf).symm
          · rw [hI.1.2.2] at hf; exact (Option.some.inj hf).symm
          · omega
        rw [hce j e (by omega) he] at hxr ⊢
        rw [hce a y (by omega) hy] at hxr
        have := congrArg Request.input hxr
        simp only [coin, SReq.res, sres, SV.res, List.append_nil] at this
        simp only [coin]
        exact this
    · rfl
  obtain ⟨X, hX⟩ := hD
  have hf' := findDraw_append_some _ X _ _ hf
  rw [← hX] at hf'
  show oracleOf c.t c.D (e.2.res c.t) = _
  simp only [oracleOf, hf']
  exact hval

/-! The judgment's rules. -/

theorem J2.pure' {α : Type} {a : α} {P0 : St → Prop} {Q : α → St → Prop}
    (h : ∀ st, Inv2 c st → P0 st → Q a st) : J2 c (.done a) P0 Q :=
  fun st hI hp _ _ => ⟨hI, grow_refl st, h st hI hp⟩

theorem J2.bind' {α β : Type} {P : Prog α} {f : α → Prog β} {P0 : St → Prop} {Q : α → St → Prop}
    {Q' : β → St → Prop} (hP : J2 c P P0 Q)
    (hf : ∀ a, J2 c (f a) (fun st => P0 st ∧ Q a st) Q') (hs : Stable2 c P0) :
    J2 c (P.bind f) P0 Q' := by
  intro st hI hp hnd hD
  rw [strace_bind] at hnd
  rw [xrun_bind] at hD ⊢
  have hD1 := pre_back c.t (xrun_grow c.t _ _) hD
  obtain ⟨hI1, hx1, hq1⟩ := hP st hI hp (fun s hs' => hnd s (List.mem_append_left _ hs')) hD1
  obtain ⟨hI2, hx2, hq2⟩ := hf _ _ hI1 ⟨hs _ _ hI hx1 hp, hq1⟩
    (fun s hs' => hnd s (List.mem_append_right _ hs')) hD
  exact ⟨hI2, grow_trans hx1 hx2, hq2⟩

theorem J2.bind {α β : Type} {P : Prog α} {f : α → Prog β} {P0 : St → Prop} {Q : α → St → Prop}
    {Q' : β → St → Prop} (hP : J2 c P P0 Q)
    (hf : ∀ a, J2 c (f a) (fun st => P0 st ∧ Q a st) Q') (hs : Stable2 c P0) :
    J2 c (P >>= f) P0 Q' := J2.bind' hP hf hs

theorem J2.conseq {α : Type} {P : Prog α} {P0 P0' : St → Prop} {Q Q' : α → St → Prop}
    (h : J2 c P P0 Q) (h1 : ∀ st, Inv2 c st → P0' st → P0 st)
    (h2 : ∀ a st, Q a st → Q' a st) : J2 c P P0' Q' := fun st hI hp hnd hD =>
  let ⟨a, b, d⟩ := h st hI (h1 st hI hp) hnd hD
  ⟨a, b, h2 _ _ d⟩

theorem J2.ite {α : Type} {b : Prop} [Decidable b] {P₁ P₂ : Prog α} {P0 : St → Prop} {Q : α → St → Prop}
    (h₁ : b → J2 c P₁ P0 Q) (h₂ : ¬b → J2 c P₂ P0 Q) :
    J2 c (if b then P₁ else P₂) P0 Q := by
  by_cases h : b
  · simp only [h, if_true]; exact h₁ h
  · simp only [h, if_false]; exact h₂ h

theorem J2.reveal {α : Type} {x : List SV} {k : Bytes → Prog α} {P0 : St → Prop} {Q : α → St → Prop}
    (hx : ∀ st, Inv2 c st → P0 st → Gd2 c st x)
    (hk : ∀ b, J2 c (k b) P0 Q) (hs : Stable2 c P0) :
    J2 c (.reveal x k) P0 Q := by
  intro st hI hp hnd hD
  simp only [strace, List.mem_cons, forall_eq_or_imp] at hnd
  simp only [xrun] at hD ⊢
  have hI1 := step_reveal2 st x hI (hx st hI hp)
  have hx1 : Grow2 st ⟨st.ents, shids x ++ st.rev⟩ := ⟨⟨[], by simp⟩, fun _ h => List.mem_append_right _ h⟩
  obtain ⟨hI2, hx2, hq⟩ := hk _ _ hI1 (hs _ _ hI hx1 hp) hnd.2 hD
  exact ⟨hI2, grow_trans hx1 hx2, hq⟩

/-- One adversary request, with the step's own facts. -/
theorem J2.askA {α : Type} {q : Request} {k : Bytes → Prog α} {P0 : St → Prop} {Q : α → St → Prop}
    (hk : ∀ st, Inv2 c st → P0 st → dis c.t (st, .a q) = false →
      J2 c (k (be q.outLen (c.t.getD (firstIdx (mA false c.t st.rev q) st.ents) 0)))
        (fun st' => st' = addA st (firstIdx (mA false c.t st.rev q) st.ents) q) Q) :
    J2 c (.askA q k) P0 Q := by
  intro st hI hp hnd hD
  simp only [strace, List.mem_cons, forall_eq_or_imp] at hnd
  simp only [xrun] at hD ⊢
  have hI1 := step_askA2 st q hI hnd.1
  have hx1 : Grow2 st (addA st (firstIdx (mA false c.t st.rev q) st.ents) q) := by
    have := xrun_grow c.t (.askA q (fun _ => .done ())) st
    simpa [xrun] using this
  obtain ⟨hI2, hx2, hq⟩ := hk st hI hp hnd.1 _ hI1 rfl hnd.2 hD
  exact ⟨hI2, grow_trans hx1 hx2, hq⟩

/-- One challenger request, with the step's own facts. -/
theorem J2.ask (r : SReq) {P0 : St → Prop} {Q : SB → St → Prop}
    (hh : ∀ st, Inv2 c st → P0 st → ∀ h ∈ r.hids, h < st.ents.length)
    (hHQ : ∀ st, Inv2 c st → P0 st → ∀ iR m, r = hqOf c.n c.pm c.root iR m → m ∈ c.Sg ∧
      ∃ dk, st.ents[iR]? = some (false, rqOf c.n dk m) ∧ st.ents[dk]? = some (false, dReq c.n))
    (hq : ∀ st, Inv2 c st → P0 st → dis c.t (st, .c r) = false →
      Inv2 c (addC st (firstIdx (mC false c.t st.rev r) st.ents) r) →
      Pre (resD c.t (addC st (firstIdx (mC false c.t st.rev r) st.ents) r)) c.D →
      Q [.hid (firstIdx (mC false c.t st.rev r) st.ents) r.outLen]
        (addC st (firstIdx (mC false c.t st.rev r) st.ents) r)) :
    J2 c (sAsk r) P0 Q := by
  intro st hI hp hnd hD
  simp only [sAsk, strace, List.mem_cons, forall_eq_or_imp] at hnd
  simp only [sAsk, xrun] at hD ⊢
  have hI1 := step_askC2 st r hI (hh st hI hp) (hHQ st hI hp) hnd.1
  have hx1 : Grow2 st (addC st (firstIdx (mC false c.t st.rev r) st.ents) r) := by
    have := xrun_grow c.t (sAsk r) st
    simpa [sAsk, xrun] using this
  exact ⟨hI1, hx1, hq st hI hp hnd.1 hI1 hD⟩

theorem stable2_and {P Q : St → Prop} (hP : Stable2 c P) (hQ : Stable2 c Q) :
    Stable2 c (fun st => P st ∧ Q st) :=
  fun st st' hI hx h => ⟨hP st st' hI hx h.1, hQ st st' hI hx h.2⟩

theorem stable2_true : Stable2 c (fun _ => True) := fun _ _ _ _ _ => trivial

theorem J2.loop {ι σ : Type} (l : List ι) (f : ι → σ → Prog (ForInStep σ)) (P0 : St → Prop)
    (L : σ → St → Prop) (hs : Stable2 c P0) (hL : ∀ s, Stable2 c (L s))
    (hf : ∀ i ∈ l, ∀ s, J2 c (f i s) (fun st => P0 st ∧ L s st) (SL L)) :
    ∀ s, J2 c (forIn l s f) (fun st => P0 st ∧ L s st) L := by
  induction l with
  | nil => intro s; exact J2.pure' (fun st _ h => h.2)
  | cons a l ih =>
    intro s
    rw [List.forIn_cons]
    refine J2.bind (hf a (by simp) s) (fun x => ?_) (stable2_and hs (hL s))
    cases x with
    | done b => exact J2.pure' (fun st _ h => h.2)
    | yield b =>
      exact J2.conseq (ih (fun i hi => hf i (by simp [hi])) b) (fun st _ h => ⟨h.1.1, h.2⟩) (fun _ _ h => h)

theorem J2.loop' {ι σ : Type} (l : List ι) (f : ι → σ → Prog (ForInStep σ)) {P0 : St → Prop}
    (L : σ → St → Prop) (hs : Stable2 c P0) (hL : ∀ s, Stable2 c (L s)) (s : σ)
    (h0 : ∀ st, Inv2 c st → P0 st → L s st)
    (hf : ∀ i ∈ l, ∀ s, J2 c (f i s) (fun st => P0 st ∧ L s st) (SL L)) :
    J2 c (forIn l s f) P0 L :=
  J2.conseq (J2.loop l f P0 L hs hL hf s) (fun st hI h => ⟨h, h0 st hI h⟩) (fun _ _ h => h)

theorem J2.obtain {α : Type} {P : Prog α} {P0 : St → Prop} {Q : α → St → Prop} {v : SB} {w : Nat}
    {X : Nat → St → Prop} (h : ∀ i, v = [.hid i w] → J2 c P (fun st => P0 st ∧ X i st) Q) :
    J2 c P (fun st => P0 st ∧ ∃ i, v = [.hid i w] ∧ X i st) Q :=
  fun st hI ⟨hp, i, hv, hx⟩ hnd hD => h i hv st hI ⟨hp, hx⟩ hnd hD

theorem J2.unit {P0 : St → Prop} : J2 c (pure PUnit.unit : Prog PUnit) P0 (fun _ _ => True) :=
  J2.pure' (fun _ _ _ => trivial)

/-- A stable precondition still holds at the end. -/
theorem J2.frame {α : Type} {P : Prog α} {P0 : St → Prop} {Q : α → St → Prop} (h : J2 c P P0 Q)
    (hs : Stable2 c P0) : J2 c P P0 (fun v st => P0 st ∧ Q v st) := fun st hI hp hnd hD =>
  let ⟨a, b, d⟩ := h st hI hp hnd hD
  ⟨a, b, hs _ _ hI b hp, d⟩
end

/-! What one challenger request returns. -/

section
variable {c : Ctx}

/-- On a disagreement-free run, a lookup returns an entry with the request's resolution. -/
theorem ask_res (st : St) (r : SReq) :
    ∃ e, (addC st (firstIdx (mC false c.t st.rev r) st.ents) r).ents[firstIdx (mC false c.t st.rev r) st.ents]? =
      some e ∧ e.2.res c.t = r.res c.t ∧ (e.2 = r ∨ (isOpen st.rev e.2 = true ∧ isOpen st.rev r = true)) := by
  generalize hi : firstIdx (mC false c.t st.rev r) st.ents = i
  by_cases hl : i < st.ents.length
  · have : addC st i r = st := by simp [addC, hl]
    rw [this]
    obtain ⟨e, he, hp⟩ := firstIdx_hit _ st.ents (hi ▸ hl)
    rw [hi] at he
    simp only [mC, Bool.false_eq_true, if_false, Bool.or_eq_true, decide_eq_true_eq,
      Bool.and_eq_true] at hp
    rcases hp with hp | ⟨⟨ho, hor⟩, hres⟩
    · exact ⟨e, he, by rw [hp], Or.inl hp⟩
    · exact ⟨e, he, hres, Or.inr ⟨ho, hor⟩⟩
  · have hi' : i = st.ents.length := Nat.le_antisymm (hi ▸ firstIdx_le _ _) (Nat.le_of_not_lt hl)
    have ha : addC st i r = ⟨st.ents ++ [(false, r)], st.rev⟩ := by simp [addC, hl]
    rw [ha, hi']
    exact ⟨(false, r), by simp, rfl, Or.inl rfl⟩

theorem res_outLen {t : List Nat} {a b : SReq} (h : a.res t = b.res t) : a.outLen = b.outLen := by
  have := congrArg Request.outLen h
  simpa [SReq.res] using this

/-- The value returned is the final table's answer to the request. -/
theorem ask_val (st : St) (r : SReq) (hI' : Inv2 c (addC st (firstIdx (mC false c.t st.rev r) st.ents) r))
    (hD : Pre (resD c.t (addC st (firstIdx (mC false c.t st.rev r) st.ents) r)) c.D) :
    sres c.t [.hid (firstIdx (mC false c.t st.rev r) st.ents) r.outLen] = c.O (r.res c.t) := by
  obtain ⟨e, he, hres, _⟩ := ask_res (c := c) st r
  have h := agree hI' hD he
  rw [hres, res_outLen hres] at h
  simp [sres, SV.res, h]

theorem ask_closed2 (st : St) (r : SReq) (hI : Inv2 c st) (hc : ∃ h ∈ r.hids, h ∉ st.rev) :
    (addC st (firstIdx (mC false c.t st.rev r) st.ents) r).ents[firstIdx (mC false c.t st.rev r) st.ents]? =
      some (false, r) := by
  obtain ⟨e, he, _, ho⟩ := ask_res (c := c) st r
  obtain ⟨h, hm, hnr⟩ := hc
  rcases ho with ho | ho
  · obtain ⟨g, r'⟩ := e
    simp only at ho
    subst ho
    cases g
    · exact he
    · exfalso
      generalize hi : firstIdx (mC false c.t st.rev r') st.ents = i at he
      by_cases hl : i < st.ents.length
      · have : addC st i r' = st := by simp [addC, hl]
        rw [this] at he
        have := hI.2.2.1 i r' he
        rw [this] at hm; cases hm
      · have ha : addC st i r' = ⟨st.ents ++ [(false, r')], st.rev⟩ := by simp [addC, hl]
        rw [ha] at he
        rcases get_snoc he with ⟨hh, _⟩ | ⟨_, he'⟩
        · exact hl hh
        · cases he'
  · exact absurd (open_mem ho.2 h hm) hnr

/-- A request that is no PRF request and whose thash address (if any) is not a
    WOTS chain address yields a disclosable handle. -/
theorem ask_safe2 (st : St) (r : SReq) (hI' : Inv2 c (addC st (firstIdx (mC false c.t st.rev r) st.ents) r))
    (hG : Grow2 st (addC st (firstIdx (mC false c.t st.rev r) st.ents) r))
    (h01 : ∀ h ∈ r.hids, h ≠ 0 ∧ h ≠ 1)
    (hP : ∀ pk A, r ≠ prfReq c.n pk A)
    (hC : ∀ itk A h', r = chReq c.n itk A h' → A.kind < 256^4 → A.kind ≠ 0) :
    Safe2 c (addC st (firstIdx (mC false c.t st.rev r) st.ents) r) (firstIdx (mC false c.t st.rev r) st.ents) := by
  obtain ⟨e, he, _, ho⟩ := ask_res (c := c) st r
  rcases ho with ho | ho
  · obtain ⟨g, r'⟩ := e
    simp only at ho
    subst ho
    refine ⟨lt_entry he, ?_, ?_, ?_⟩
    · rintro ⟨e2, h2, h3⟩
      obtain rfl : (g, r') = e2 := Option.some.inj (he.symm.trans h2)
      rcases h3 with h3 | h3
      · exact (h01 0 h3).1 rfl
      · exact (h01 1 h3).2 rfl
    · intro tree leaf gi _ ⟨pk, h1, _⟩
      have := Option.some.inj (he.symm.trans h1)
      exact absurd (Prod.mk.inj this).2 (hP pk _)
    · rintro ⟨L, T, F, ci, s, hr, _, hlw⟩
      cases s with
      | zero =>
        obtain ⟨pk, h1, _⟩ := hlw
        exact hP pk _ (Prod.mk.inj (Option.some.inj (he.symm.trans h1))).2
      | succ s =>
        obtain ⟨itk, h', h1, _, _⟩ := hlw
        have hr' := (Prod.mk.inj (Option.some.inj (he.symm.trans h1))).2
        -- r' is a chain request at A0; its own address has kind 0
        exact hC itk (A0 L T F ci s) h' hr' (by simp [A0, wA, Adrs.setType]) (by simp [A0, wA, Adrs.setType])
  · have hrev : ∀ x ∈ st.rev, x ∈ (addC st (firstIdx (mC false c.t st.rev r) st.ents) r).rev := hG.2
    refine safe2_of_open hI' he ?_
    have ho1 := ho.1
    simp only [isOpen, List.all_eq_true, decide_eq_true_eq] at ho1 ⊢
    exact fun x hx => hrev x (ho1 x hx)
end

/-! Relational loops and request-level lemmas. -/

def SLR {σ σ' : Type} (R : σ → σ' → St → Prop) : ForInStep σ → ForInStep σ' → St → Prop
  | .done a, .done b, st => R a b st
  | .yield a, .yield b, st => R a b st
  | _, _, _ => False

section
variable {c : Ctx}

theorem J2.loopR {ι σ σ' : Type} (l : List ι) (f : ι → σ → Prog (ForInStep σ)) (g : ι → σ' → Id (ForInStep σ'))
    (P0 : St → Prop) (R : σ → σ' → St → Prop) (hs : Stable2 c P0) (hR : ∀ a b, Stable2 c (R a b))
    (hf : ∀ i ∈ l, ∀ s s', J2 c (f i s) (fun st => P0 st ∧ R s s' st) (fun r st => SLR R r (g i s') st)) :
    ∀ s s', J2 c (forIn l s f) (fun st => P0 st ∧ R s s' st) (fun r st => R r (forIn (m := Id) l s' g) st) := by
  induction l with
  | nil => intro s s'; exact J2.pure' (fun st _ h => h.2)
  | cons a l ih =>
    intro s s'
    rw [List.forIn_cons, List.forIn_cons]
    refine J2.bind (hf a (by simp) s s') (fun x => ?_) (stable2_and hs (hR s s'))
    cases hx : g a s' with
    | done b =>
      cases x with
      | done a' => exact J2.pure' (fun st _ h => h.2)
      | yield a' => exact fun st _ h => (h.2 : False).elim
    | yield b =>
      cases x with
      | done a' => exact fun st _ h => (h.2 : False).elim
      | yield a' =>
        exact J2.conseq (ih (fun i hi => hf i (by simp [hi])) a' b) (fun st _ h => ⟨h.1.1, h.2⟩)
          (fun _ _ h => h)

theorem J2.loopR' {ι σ σ' : Type} (l : List ι) (f : ι → σ → Prog (ForInStep σ)) (g : ι → σ' → Id (ForInStep σ'))
    {P0 : St → Prop} (R : σ → σ' → St → Prop) (hs : Stable2 c P0) (hR : ∀ a b, Stable2 c (R a b))
    (s : σ) (s' : σ') (h0 : ∀ st, Inv2 c st → P0 st → R s s' st)
    (hf : ∀ i ∈ l, ∀ s s', J2 c (f i s) (fun st => P0 st ∧ R s s' st) (fun r st => SLR R r (g i s') st)) :
    J2 c (forIn l s f) P0 (fun r st => R r (forIn (m := Id) l s' g) st) :=
  J2.conseq (J2.loopR l f g P0 R hs hR hf s s') (fun st hI h => ⟨h, h0 st hI h⟩) (fun _ _ h => h)

theorem grow_addC (st : St) (r : SReq) :
    Grow2 st (addC st (firstIdx (mC false c.t st.rev r) st.ents) r) := by
  have := xrun_grow c.t (sAsk r) st
  simpa [sAsk, xrun] using this

theorem safe2_ne {st : St} (hI : Inv2 c st) {i : Nat} (h : Safe2 c st i) :
    i < st.ents.length ∧ i ≠ 0 ∧ i ≠ 1 :=
  ⟨h.1, fun e => h.2.1 (e ▸ prot0 hI), fun e => h.2.1 (e ▸ prot1 hI)⟩

theorem entry_ne {st : St} (hI : Inv2 c st) {i : Nat} {r : SReq} (h : st.ents[i]? = some (false, r))
    (h0 : r ≠ coin c.n 0) (h1 : r ≠ coin c.n 1) : i < st.ents.length ∧ i ≠ 0 ∧ i ≠ 1 := by
  refine ⟨lt_entry h, fun e => ?_, fun e => ?_⟩
  · subst e; rw [hI.1.1] at h; exact h0 (Prod.mk.inj (Option.some.inj h)).2.symm
  · subst e; rw [hI.1.2.1] at h; exact h1 (Prod.mk.inj (Option.some.inj h)).2.symm

theorem gd2_hids {st : St} (hI : Inv2 c st) {x : SB} (hx : Gd2 c st x) :
    ∀ h ∈ shids x, h < st.ents.length ∧ h ≠ 0 ∧ h ≠ 1 := by
  intro h hm
  obtain ⟨w, hw⟩ := mem_shids x h hm
  exact safe2_ne hI (hx h w hw)

/-- The tweak key's handle. -/
def TKh (c : Ctx) (st : St) (tk : SB) : Prop := ∃ itk, tk = [.hid itk 32] ∧ st.ents[itk]? = some (false, dTk c.n)
/-- The PRF key's handle. -/
def PKh (c : Ctx) (st : St) (pk : SB) : Prop := ∃ ipk, pk = [.hid ipk 32] ∧ st.ents[ipk]? = some (false, dPrf c.n)

theorem stable_tkh (tk : SB) : Stable2 c (fun st => TKh c st tk) :=
  fun _ _ _ hg ⟨i, h1, h2⟩ => ⟨i, h1, grow_get hg h2⟩

theorem stable_pkh (pk : SB) : Stable2 c (fun st => PKh c st pk) :=
  fun _ _ _ hg ⟨i, h1, h2⟩ => ⟨i, h1, grow_get hg h2⟩

theorem stable_gd2 (x : SB) : Stable2 c (fun st => Gd2 c st x) :=
  fun _ _ hI hg h => gd2_mono hI hg h

theorem stable_one2 (w : Nat) (v : SB) : Stable2 c (fun st => ∃ i, v = [.hid i w] ∧ Safe2 c st i) :=
  fun _ _ hI hg ⟨i, hv, h⟩ => ⟨i, hv, safe2_mono hI hg h⟩

theorem stable_pure (P : Prop) : Stable2 c (fun _ => P) := fun _ _ _ _ h => h

theorem tkh_hids {st : St} (hI : Inv2 c st) {tk : SB} (h : TKh c st tk) :
    ∀ y ∈ shids tk, y < st.ents.length ∧ y ≠ 0 ∧ y ≠ 1 := by
  obtain ⟨i, rfl, hi⟩ := h
  intro y hy
  simp only [shids, List.mem_singleton] at hy
  subst hy
  exact entry_ne hI hi (by simp [dTk, coin]) (by simp [dTk, coin])

theorem pkh_hids {st : St} (hI : Inv2 c st) {pk : SB} (h : PKh c st pk) :
    ∀ y ∈ shids pk, y < st.ents.length ∧ y ≠ 0 ∧ y ≠ 1 := by
  obtain ⟨i, rfl, hi⟩ := h
  intro y hy
  simp only [shids, List.mem_singleton] at hy
  subst hy
  exact entry_ne hI hi (by simp [dPrf, coin]) (by simp [dPrf, coin])

/-- A thash request at a non-chain address: a disclosable handle, the table's answer. -/
theorem j2_thash (p : Params) (tk : SB) (a : Adrs) (x : SB) (hk : a.kind ≠ 0) (hkk : a.kind < 256^4)
    {P0 : St → Prop}
    (h : ∀ st, Inv2 c st → P0 st → ∀ y ∈ shids tk ++ shids x, y < st.ents.length ∧ y ≠ 0 ∧ y ≠ 1) :
    J2 c (sThash p tk a x) P0 (fun v st => (∃ i, v = [.hid i p.n] ∧ Safe2 c st i) ∧
      sres c.t v = thash c.O p (sres c.t tk) a (sres c.t x)) := by
  refine J2.ask _ (fun st hI hp y hy => (h st hI hp y (by simpa [SReq.hids, shids] using hy)).1)
    (fun _ _ _ iR m e => by simp [hqOf] at e) (fun st hI hp _ hI' hD => ⟨⟨_, rfl, ?_⟩, ?_⟩)
  · refine ask_safe2 st _ hI' (grow_addC st _) (fun y hy => (h st hI hp y
      (by simpa [SReq.hids, shids] using hy)).2) (fun pk A e => by simp [prfReq] at e) ?_
    intro itk A h' e hA
    have e2 := congrArg SReq.input e
    simp only [chReq] at e2
    have hb : a.bytes = A.bytes := by
      have := congrArg List.head? e2
      simpa using this
    rw [adrs_kind A a hb.symm hA hkk]; exact hk
  · rw [ask_val st _ hI' hD]
    simp [thash, keyed, SReq.res, sres, SV.res]

end

/-! WOTS chain values and FORS secrets. -/

section
variable {c : Ctx}

theorem a5_eq (L T F ci : Nat) : A5 L T F ci = {layer := L, tree := T, kind := 5, keypair := F, chain := ci} := by
  simp [A5, wA, Adrs.setType]

theorem a0_eq (L T F ci s : Nat) :
    A0 L T F ci s = {layer := L, tree := T, kind := 0, keypair := F, chain := ci, hash := s} := by
  simp [A0, wA, Adrs.setType]

theorem fsA_eq (tree leaf gi : Nat) :
    fsA tree leaf gi = {tree := tree, kind := 6, keypair := leaf, hash := gi} := by
  simp [fsA, forsAdrs, Adrs.setType]

theorem prfReq_ne_chReq (n pk itk h : Nat) (A B : Adrs) : prfReq n pk A ≠ chReq n itk B h := by
  intro e
  have := congrArg SReq.input e
  simp [prfReq, chReq] at this

theorem lowAt_unique {st : St} {h : Nat} :
    ∀ {L T F ci s L' T' F' ci' s' : Nat}, InR L T F ci s → InR L' T' F' ci' s' →
    LowAt c.n st h L T F ci s → LowAt c.n st h L' T' F' ci' s' →
    L = L' ∧ T = T' ∧ F = F' ∧ ci = ci' ∧ s = s' := by
  intro L T F ci s L' T' F' ci' s' hr hr' h1 h2
  obtain ⟨r1, r2, r3, r4, r5⟩ := hr
  obtain ⟨r1', r2', r3', r4', r5'⟩ := hr'
  cases s with
  | zero =>
    cases s' with
    | zero =>
      obtain ⟨pk, e1, _⟩ := h1
      obtain ⟨pk', e2, _⟩ := h2
      have e := (Prod.mk.inj (Option.some.inj (e1.symm.trans e2))).2
      have hb := congrArg SReq.input e
      simp only [prfReq, List.cons.injEq, SV.lit.injEq, and_true, true_and] at hb
      have ha := adrs_bytes_injective _ _ (by rw [a5_eq]; simp only [Adrs.InRange]; omega)
        (by rw [a5_eq]; simp only [Adrs.InRange]; omega) hb
      rw [a5_eq, a5_eq] at ha
      simp only [Adrs.mk.injEq] at ha
      omega
    | succ s' =>
      obtain ⟨pk, e1, _⟩ := h1
      obtain ⟨itk, h', e2, _⟩ := h2
      exact absurd (Prod.mk.inj (Option.some.inj (e1.symm.trans e2))).2 (prfReq_ne_chReq _ _ _ _ _ _)
  | succ s =>
    cases s' with
    | zero =>
      obtain ⟨itk, h', e1, _⟩ := h1
      obtain ⟨pk, e2, _⟩ := h2
      exact absurd (Prod.mk.inj (Option.some.inj (e2.symm.trans e1))).2 (prfReq_ne_chReq _ _ _ _ _ _)
    | succ s' =>
      obtain ⟨itk, h', e1, _⟩ := h1
      obtain ⟨itk', h'', e2, _⟩ := h2
      have e := (Prod.mk.inj (Option.some.inj (e1.symm.trans e2))).2
      have hb := congrArg SReq.input e
      simp only [chReq, List.cons.injEq, SV.lit.injEq] at hb
      have ha := adrs_bytes_injective _ _ (by rw [a0_eq]; simp only [Adrs.InRange]; omega)
        (by rw [a0_eq]; simp only [Adrs.InRange]; omega) hb.1
      rw [a0_eq, a0_eq] at ha
      simp only [Adrs.mk.injEq] at ha
      omega

theorem lowAt_entry_ne {st : St} (hI : Inv2 c st) {h L T F ci : Nat} :
    ∀ s, LowAt c.n st h L T F ci s → h < st.ents.length ∧ h ≠ 0 ∧ h ≠ 1
  | 0, ⟨_, e1, _⟩ => entry_ne hI e1 (by simp [prfReq, coin]) (by simp [prfReq, coin])
  | _+1, ⟨_, _, e1, _⟩ => entry_ne hI e1 (by simp [chReq, coin]) (by simp [chReq, coin])

/-- A chain value at or above the digit may be disclosed. -/
theorem lowAt_safe2 {st : St} (hI : Inv2 c st) {h L T F ci s : Nat} (hr : InR L T F ci s)
    (hd : c.dgt L T F ci ≤ s) (hl : LowAt c.n st h L T F ci s) : Safe2 c st h := by
  refine ⟨(lowAt_entry_ne hI s hl).1, ?_, ?_, ?_⟩
  · rintro ⟨e, he, h3⟩
    cases s with
    | zero =>
      obtain ⟨pk, e1, e2⟩ := hl
      rw [e1] at he; obtain rfl := Option.some.inj he
      have hpk := entry_ne hI e2 (by simp [dPrf, coin]) (by simp [dPrf, coin])
      simp [prfReq, SReq.hids, shids] at h3
      omega
    | succ s =>
      obtain ⟨itk, h', e1, e2, e3⟩ := hl
      rw [e1] at he; obtain rfl := Option.some.inj he
      have hi := entry_ne hI e2 (by simp [dTk, coin]) (by simp [dTk, coin])
      have hh := lowAt_entry_ne hI s e3
      simp [chReq, SReq.hids, shids] at h3
      omega
  · intro tree leaf gi hrf ⟨pk, e1, _⟩
    exfalso
    cases s with
    | zero =>
      obtain ⟨pk', e2, _⟩ := hl
      have e := (Prod.mk.inj (Option.some.inj (e1.symm.trans e2))).2
      have hb := congrArg SReq.input e
      simp only [prfReq, List.cons.injEq, SV.lit.injEq, and_true, true_and] at hb
      have := adrs_kind _ _ hb (by rw [fsA_eq]; show (6:Nat) < 256^4; decide) (by rw [a5_eq]; show (5:Nat) < 256^4; decide)
      rw [fsA_eq, a5_eq] at this
      simp at this
    | succ s =>
      obtain ⟨itk, h', e2, _⟩ := hl
      exact prfReq_ne_chReq _ _ _ _ _ _ (Prod.mk.inj (Option.some.inj (e1.symm.trans e2))).2
  · rintro ⟨L', T', F', ci', s', hr', hs', hl'⟩
    obtain ⟨rfl, rfl, rfl, rfl, rfl⟩ := lowAt_unique hr hr' hl hl'
    omega

/-- Chain values: the honest low value, or a disclosable one. -/
def ChainH (c : Ctx) (st : St) (h L T F ci s : Nat) : Prop := LowAt c.n st h L T F ci s ∨ Safe2 c st h

theorem stable_chainH (h L T F ci s : Nat) : Stable2 c (fun st => ChainH c st h L T F ci s) :=
  fun _ _ hI hg hc => hc.elim (fun l => Or.inl (lowAt_fwd hg s l)) (fun sf => Or.inr (safe2_mono hI hg sf))

/-- The WOTS secret: the honest low chain value at step 0. -/
theorem j2_prf5 (pk : SB) (L T F ci : Nat) {P0 : St → Prop}
    (h : ∀ st, Inv2 c st → P0 st → PKh c st pk) :
    J2 c (sPrf (params c.v) pk [.hid 2 c.n] (A5 L T F ci)) P0 (fun v st =>
      (∃ i, v = [.hid i c.n] ∧ LowAt c.n st i L T F ci 0) ∧
      sres c.t v = prf c.O (params c.v) (sres c.t pk) (sres c.t [.hid 2 c.n]) (A5 L T F ci)) := by
  refine J2.ask _ (fun st hI hp y hy => ?_) (fun _ _ _ iR m e => by simp [hqOf] at e)
    (fun st hI hp _ hI' hD => ⟨?_, ?_⟩)
  · simp only [SReq.hids, shids_append, List.mem_append] at hy
    rcases hy with hy | hy | hy
    · exact (pkh_hids hI (h st hI hp) y hy).1
    · simp [shids] at hy; subst hy; exact lt_entry hI.1.2.2
    · simp [shids] at hy
  · obtain ⟨ipk, rfl, hipk⟩ := h st hI hp
    refine ⟨_, rfl, ipk, ?_, grow_get (grow_addC st _) hipk⟩
    exact ask_closed2 st _ hI ⟨ipk, by simp [SReq.hids, shids],
      not_rev_prot2 hI ⟨_, hipk, Or.inl (by simp [dPrf, SReq.hids, shids])⟩⟩
  · rw [ask_val st _ hI' hD]
    simp [prf, keyed, SReq.res, sres, SV.res]

/-- The FORS secret: the honest secret entry. -/
theorem j2_prf6 (pk : SB) (tree leaf gi : Nat) {P0 : St → Prop}
    (h : ∀ st, Inv2 c st → P0 st → PKh c st pk) :
    J2 c (sPrf (params c.v) pk [.hid 2 c.n] (fsA tree leaf gi)) P0 (fun v st =>
      (∃ i, v = [.hid i c.n] ∧ FsAt c.n st i tree leaf gi) ∧
      sres c.t v = prf c.O (params c.v) (sres c.t pk) (sres c.t [.hid 2 c.n]) (fsA tree leaf gi)) := by
  refine J2.ask _ (fun st hI hp y hy => ?_) (fun _ _ _ iR m e => by simp [hqOf] at e)
    (fun st hI hp _ hI' hD => ⟨?_, ?_⟩)
  · simp only [SReq.hids, shids_append, List.mem_append] at hy
    rcases hy with hy | hy | hy
    · exact (pkh_hids hI (h st hI hp) y hy).1
    · simp [shids] at hy; subst hy; exact lt_entry hI.1.2.2
    · simp [shids] at hy
  · obtain ⟨ipk, rfl, hipk⟩ := h st hI hp
    refine ⟨_, rfl, ipk, ?_, grow_get (grow_addC st _) hipk⟩
    exact ask_closed2 st _ hI ⟨ipk, by simp [SReq.hids, shids],
      not_rev_prot2 hI ⟨_, hipk, Or.inl (by simp [dPrf, SReq.hids, shids])⟩⟩
  · rw [ask_val st _ hI' hD]
    simp [prf, keyed, SReq.res, sres, SV.res]
end

/-! The relational judgment: a symbolic program against the Id-model computation on the final table. -/

/-- `P` relates to the `Id`-model value `T` by `Rel`, in the final state. -/
def JR {α β : Type} (c : Ctx) (P : Prog α) (T : Id β) (P0 : St → Prop) (Rel : α → β → St → Prop) : Prop :=
  J2 c P P0 (fun v st => Rel v T st)

namespace JR
variable {c : Ctx}

theorem pure' {α β : Type} {a : α} {b : β} {P0 : St → Prop} {Rel : α → β → St → Prop}
    (h : ∀ st, Inv2 c st → P0 st → Rel a b st) : JR c (.done a) (pure b) P0 Rel :=
  J2.pure' h

theorem bind {α β γ δ : Type} {P : Prog α} {T : Id β} {f : α → Prog γ} {g : β → Id δ} {P0 : St → Prop}
    {R₁ : α → β → St → Prop} {R₂ : γ → δ → St → Prop} (hP : JR c P T P0 R₁)
    (hf : ∀ a b, JR c (f a) (g b) (fun st => P0 st ∧ R₁ a b st) R₂) (hs : Stable2 c P0) :
    JR c (P >>= f) (T >>= g) P0 R₂ :=
  J2.bind hP (fun a => hf a T) hs

theorem conseq {α β : Type} {P : Prog α} {T : Id β} {P0 P0' : St → Prop} {R R' : α → β → St → Prop}
    (h : JR c P T P0 R) (h1 : ∀ st, Inv2 c st → P0' st → P0 st) (h2 : ∀ a b st, R a b st → R' a b st) :
    JR c P T P0' R' :=
  J2.conseq h h1 (fun a st hr => h2 a T st hr)

theorem ite {α β : Type} {b : Prop} [Decidable b] {P₁ P₂ : Prog α} {T₁ T₂ : Id β} {P0 : St → Prop}
    {Rel : α → β → St → Prop} (h₁ : b → JR c P₁ T₁ P0 Rel) (h₂ : ¬b → JR c P₂ T₂ P0 Rel) :
    JR c (if b then P₁ else P₂) (if b then T₁ else T₂) P0 Rel := by
  by_cases h : b
  · simp only [h, if_true]; exact h₁ h
  · simp only [h, if_false]; exact h₂ h

theorem reveal {α β : Type} {x : List SV} {k : Bytes → Prog α} {T : Id β} {P0 : St → Prop}
    {Rel : α → β → St → Prop} (hx : ∀ st, Inv2 c st → P0 st → Gd2 c st x)
    (hk : JR c (k (sres c.t x)) T P0 Rel) (hs : Stable2 c P0) : JR c (.reveal x k) T P0 Rel := by
  intro st hI hp hnd hD
  simp only [strace, List.mem_cons, forall_eq_or_imp] at hnd
  simp only [xrun] at hD ⊢
  have hI1 := step_reveal2 st x hI (hx st hI hp)
  have hx1 : Grow2 st ⟨st.ents, shids x ++ st.rev⟩ := ⟨⟨[], by simp⟩, fun _ h => List.mem_append_right _ h⟩
  obtain ⟨hI2, hx2, hq⟩ := hk _ hI1 (hs _ _ hI hx1 hp) hnd.2 hD
  exact ⟨hI2, grow_trans hx1 hx2, hq⟩

theorem unit {P0 : St → Prop} :
    JR c (pure PUnit.unit : Prog PUnit) (pure PUnit.unit : Id PUnit) P0 (fun _ _ _ => True) :=
  pure' (fun _ _ _ => trivial)

theorem loop {ι σ σ' : Type} (l : List ι) (f : ι → σ → Prog (ForInStep σ)) (g : ι → σ' → Id (ForInStep σ'))
    (P0 : St → Prop) (R : σ → σ' → St → Prop) (hs : Stable2 c P0) (hR : ∀ a b, Stable2 c (R a b))
    (hf : ∀ i ∈ l, ∀ s s', JR c (f i s) (g i s') (fun st => P0 st ∧ R s s' st) (SLR R)) :
    ∀ s s', JR c (forIn l s f) (forIn l s' g) (fun st => P0 st ∧ R s s' st) R :=
  J2.loopR l f g P0 R hs hR hf

theorem loop' {ι σ σ' : Type} (l : List ι) (f : ι → σ → Prog (ForInStep σ)) (g : ι → σ' → Id (ForInStep σ'))
    {P0 : St → Prop} (R : σ → σ' → St → Prop) (hs : Stable2 c P0) (hR : ∀ a b, Stable2 c (R a b))
    (s : σ) (s' : σ') (h0 : ∀ st, Inv2 c st → P0 st → R s s' st)
    (hf : ∀ i ∈ l, ∀ s s', JR c (f i s) (g i s') (fun st => P0 st ∧ R s s' st) (SLR R)) :
    JR c (forIn l s f) (forIn l s' g) P0 R :=
  J2.loopR' l f g R hs hR s s' h0 hf
end JR

/-- All handles of width `n`. -/
def AllHid (n : Nat) (x : SB) : Prop := ∀ v ∈ x, ∃ i, v = .hid i n

/-- Disclosable bytes with their final-table value. -/
def RG (c : Ctx) (v : SB) (b : Bytes) (st : St) : Prop := Gd2 c st v ∧ sres c.t v = b ∧ AllHid c.n v
/-- One disclosable handle with its final-table value. -/
def R1 (c : Ctx) (w : Nat) (v : SB) (b : Bytes) (st : St) : Prop :=
  (∃ i, v = [.hid i w] ∧ Safe2 c st i) ∧ sres c.t v = b

section
variable {c : Ctx}

theorem stable_RG (v : SB) (b : Bytes) : Stable2 c (RG c v b) :=
  fun _ _ hI hg h => ⟨gd2_mono hI hg h.1, h.2.1, h.2.2⟩

theorem stable_R1 (w : Nat) (v : SB) (b : Bytes) : Stable2 c (R1 c w v b) := by
  intro _ _ hI hg h
  obtain ⟨⟨i, hv, hs⟩, hr⟩ := h
  exact ⟨⟨i, hv, safe2_mono hI hg hs⟩, hr⟩

theorem RG_of_R1 {v : SB} {b : Bytes} {st : St} (h : R1 c c.n v b st) : RG c v b st := by
  obtain ⟨⟨i, rfl, hs⟩, hr⟩ := h
  refine ⟨fun j w' hm => ?_, hr, fun y hy => ⟨i, by simpa using hy⟩⟩
  simp only [List.mem_singleton, SV.hid.injEq] at hm
  rw [hm.1]; exact hs

theorem RG_one {i : Nat} {b : Bytes} {st : St} (hs : Safe2 c st i) (hb : sres c.t [.hid i c.n] = b) :
    RG c [.hid i c.n] b st := RG_of_R1 ⟨⟨i, rfl, hs⟩, hb⟩

theorem RG_append {v v' : SB} {b b' : Bytes} {st : St} (h : RG c v b st) (h' : RG c v' b' st) :
    RG c (v ++ v') (b ++ b') st := by
  refine ⟨fun i w hm => ?_, by rw [sres_append, h.2.1, h'.2.1], fun y hy => ?_⟩
  · rcases List.mem_append.mp hm with hm | hm
    · exact h.1 i w hm
    · exact h'.1 i w hm
  · rcases List.mem_append.mp hy with hy | hy
    · exact h.2.2 y hy
    · exact h'.2.2 y hy

theorem RG_nil (st : St) : RG c [] [] st := ⟨fun _ _ h => (by cases h), rfl, fun _ h => (by cases h)⟩

theorem gd2_sub {st : St} {x y : SB} (hx : Gd2 c st x) (h : ∀ v ∈ y, v ∈ x) : Gd2 c st y :=
  fun i w hm => hx i w (h _ hm)
end

/-! Requests, relationally. -/

section
variable {c : Ctx}

theorem jr_thash (p : Params) (tk : SB) (a : Adrs) (x : SB) (tk' x' : Bytes) (hk : a.kind ≠ 0)
    (hkk : a.kind < 256^4) (htk : sres c.t tk = tk') {P0 : St → Prop}
    (hx : ∀ st, Inv2 c st → P0 st → sres c.t x = x')
    (h : ∀ st, Inv2 c st → P0 st → ∀ y ∈ shids tk ++ shids x, y < st.ents.length ∧ y ≠ 0 ∧ y ≠ 1) :
    JR c (sThash p tk a x) (thash c.O p tk' a x') P0 (R1 c p.n) := by
  subst htk
  intro st hI hp hnd hD
  have := j2_thash p tk a x hk hkk h st hI hp hnd hD
  rw [hx st hI hp] at this
  exact this

theorem chain_safe_entry {st : St} (hI : Inv2 c st) {i itk hx L T F ci s : Nat} (hR : InR L T F ci (s+1))
    (he : st.ents[i]? = some (false, chReq c.n itk (A0 L T F ci s) hx))
    (hitk : st.ents[itk]? = some (false, dTk c.n)) (hs : Safe2 c st hx) : Safe2 c st i := by
  refine ⟨lt_entry he, ?_, ?_, ?_⟩
  · rintro ⟨e, he', h3⟩
    rw [he] at he'; obtain rfl := Option.some.inj he'
    have h1 := entry_ne hI hitk (by simp [dTk, coin]) (by simp [dTk, coin])
    have h2 := safe2_ne hI hs
    simp [chReq, SReq.hids, shids] at h3
    omega
  · intro tree leaf gi _ ⟨pk, e1, _⟩
    exact absurd (Prod.mk.inj (Option.some.inj (e1.symm.trans he))).2 (prfReq_ne_chReq _ _ _ _ _ _)
  · rintro ⟨L', T', F', ci', s', hr', hs', hl'⟩
    cases s' with
    | zero =>
      obtain ⟨pk, e1, _⟩ := hl'
      exact prfReq_ne_chReq _ _ _ _ _ _ (Prod.mk.inj (Option.some.inj (e1.symm.trans he))).2
    | succ s' =>
      obtain ⟨itk', h', e1, _, e3⟩ := hl'
      have e := (Prod.mk.inj (Option.some.inj (e1.symm.trans he))).2
      have hb := congrArg SReq.input e
      simp only [chReq, List.cons.injEq, SV.lit.injEq, SV.hid.injEq, and_true] at hb
      obtain ⟨r1, r2, r3, r4, r5⟩ := hR
      obtain ⟨r1', r2', r3', r4', r5'⟩ := hr'
      have ha := adrs_bytes_injective _ _ (by rw [a0_eq]; simp only [Adrs.InRange]; omega)
        (by rw [a0_eq]; simp only [Adrs.InRange]; omega) hb.1
      rw [a0_eq, a0_eq] at ha
      simp only [Adrs.mk.injEq] at ha
      obtain ⟨rfl, rfl, -, rfl, rfl, rfl⟩ := ha
      rw [hb.2] at e3
      exact hs.2.2.2 ⟨L', T', F', ci', s', ⟨r1, r2, r3, r4, by omega⟩, by omega, e3⟩

/-- Chain-step results: the next chain value, honest-low while below the digit. -/
def RCs (c : Ctx) (L T F ci s : Nat) (x : SB) (v : SB) (b : Bytes) (st : St) : Prop :=
  (∃ i, v = [.hid i c.n] ∧ ChainH c st i L T F ci (s+1) ∧
    ∀ hx, x = [.hid hx c.n] → hx < st.ents.length ∧
      (LowAt c.n st hx L T F ci s → s < c.dgt L T F ci → LowAt c.n st i L T F ci (s+1))) ∧
  sres c.t v = b

theorem stable_RCs (L T F ci s : Nat) (x v : SB) (b : Bytes) : Stable2 c (RCs c L T F ci s x v b) := by
  intro st st' hI hg h
  obtain ⟨⟨i, hv, hch, himp⟩, hr⟩ := h
  refine ⟨⟨i, hv, stable_chainH i L T F ci (s+1) st st' hI hg hch, fun hx hxe => ?_⟩, hr⟩
  obtain ⟨hxl, himp'⟩ := himp hx hxe
  refine ⟨Nat.lt_of_lt_of_le hxl (grow_len hg), fun hl hs => ?_⟩
  exact lowAt_fwd hg (s+1) (himp' (lowAt_back hI hg s hx hxl hl) hs)

theorem chainH_lt {st : St} (hI : Inv2 c st) {h L T F ci s : Nat} (hc : ChainH c st h L T F ci s) :
    h < st.ents.length :=
  hc.elim (fun l => (lowAt_entry_ne hI s l).1) (fun sf => sf.1)

/-- One chain step. -/
theorem jr_chainStep (tk : SB) (L T F ci s : Nat) (x : SB) (tk' x' : Bytes) (hR : InR L T F ci (s+1))
    (htk : sres c.t tk = tk') {P0 : St → Prop} (hxv : ∀ st, Inv2 c st → P0 st → sres c.t x = x')
    (h : ∀ st, Inv2 c st → P0 st → TKh c st tk ∧ ∃ hx, x = [.hid hx c.n] ∧ ChainH c st hx L T F ci s) :
    JR c (sThash (params c.v) tk (A0 L T F ci s) x) (thash c.O (params c.v) tk' (A0 L T F ci s) x') P0
      (RCs c L T F ci s x) := by
  subst htk
  refine J2.ask _ (fun st hI hp y hy => ?_) (fun _ _ _ iR m e => by simp [hqOf] at e)
    (fun st hI hp _ hI' hD => ⟨?_, ?_⟩)
  · obtain ⟨⟨itk, rfl, hitk⟩, hx, rfl, hch⟩ := h st hI hp
    simp [SReq.hids, shids] at hy
    rcases hy with rfl | rfl
    · exact lt_entry hitk
    · exact chainH_lt hI hch
  · obtain ⟨⟨itk, rfl, hitk⟩, hx, rfl, hch⟩ := h st hI hp
    have hg := grow_addC (c := c) st ⟨1, "", [.hid itk 32], .lit (A0 L T F ci s).bytes :: [.hid hx c.n], (params c.v).n⟩
    obtain ⟨e, he, _, ho⟩ := ask_res (c := c) st ⟨1, "", [.hid itk 32], .lit (A0 L T F ci s).bytes :: [.hid hx c.n], (params c.v).n⟩
    have hxl := chainH_lt hI hch
    have hitk' := grow_get hg hitk
    refine ⟨_, rfl, ?_, fun hx' hxe => ?_⟩
    · rcases ho with ho | ho
      · obtain ⟨g, r'⟩ := e
        simp only at ho
        subst ho
        cases g with
        | true =>
          exfalso
          have := hI'.2.2.1 _ _ he
          simp [SReq.hids, shids] at this
        | false =>
          rcases hch with hl | hs
          · exact Or.inl ⟨itk, hx, he, hitk', lowAt_fwd hg s hl⟩
          · exact Or.inr (chain_safe_entry hI' hR he hitk' (safe2_mono hI hg hs))
      · refine Or.inr (safe2_of_open hI' he ?_)
        have ho1 := ho.1
        simp only [isOpen, List.all_eq_true, decide_eq_true_eq] at ho1 ⊢
        exact fun y hy => hg.2 y (ho1 y hy)
    · simp only [List.cons.injEq, SV.hid.injEq, and_true] at hxe
      subst hxe
      refine ⟨Nat.lt_of_lt_of_le hxl (grow_len hg), fun hl hs => ?_⟩
      rcases ho with ho | ho
      · obtain ⟨g, r'⟩ := e
        simp only at ho
        subst ho
        cases g with
        | true =>
          exfalso
          have := hI'.2.2.1 _ _ he
          simp [SReq.hids, shids] at this
        | false => exact ⟨itk, hx, he, hitk', hl⟩
      · exfalso
        have hor := open_mem ho.2 hx (by simp [SReq.hids, shids])
        exact not_rev_low hI' ⟨L, T, F, ci, s, lowAt_inR_pred hR, hs, hl⟩ (hg.2 hx hor)
  · rw [ask_val st _ hI' hD, ← hxv st hI hp]
    simp [thash, keyed, SReq.res, sres, SV.res]

/-- Chain results. -/
def RCh (c : Ctx) (L T F ci start steps : Nat) (x : SB) (v : SB) (b : Bytes) (st : St) : Prop :=
  (∃ i, v = [.hid i c.n] ∧ ChainH c st i L T F ci (start+steps)) ∧ sres c.t v = b ∧
  ∀ hx, x = [.hid hx c.n] → hx < st.ents.length ∧ (LowAt c.n st hx L T F ci start →
    ∀ s', start ≤ s' → s' ≤ start+steps → s' ≤ c.dgt L T F ci → ∃ j, LowAt c.n st j L T F ci s')

theorem stable_RCh (L T F ci start steps : Nat) (x v : SB) (b : Bytes) :
    Stable2 c (RCh c L T F ci start steps x v b) := by
  intro st st' hI hg h
  obtain ⟨⟨i, hv, hch⟩, hr, himp⟩ := h
  refine ⟨⟨i, hv, stable_chainH i L T F ci _ st st' hI hg hch⟩, hr, fun hx hxe => ?_⟩
  obtain ⟨hxl, himp'⟩ := himp hx hxe
  refine ⟨Nat.lt_of_lt_of_le hxl (grow_len hg), fun hl s' h1 h2 h3 => ?_⟩
  obtain ⟨j, hj⟩ := himp' (lowAt_back hI hg start hx hxl hl) s' h1 h2 h3
  exact ⟨j, lowAt_fwd hg s' hj⟩

/-- A chain from a chain value. -/
theorem jr_chain (tk : SB) (tk' : Bytes) (L T F ci : Nat) (htk : sres c.t tk = tk') :
    ∀ (steps start : Nat) (x : SB) (x' : Bytes) {P0 : St → Prop}, Stable2 c P0 →
    InR L T F ci (start+steps) → (∀ st, Inv2 c st → P0 st → sres c.t x = x') →
    (∀ st, Inv2 c st → P0 st → TKh c st tk ∧ ∃ hx, x = [.hid hx c.n] ∧ ChainH c st hx L T F ci start) →
    JR c (sChain (params c.v) tk {wA L T F with chain := ci} x start steps)
      (chain c.O (params c.v) tk' {wA L T F with chain := ci} x' start steps) P0 (RCh c L T F ci start steps x)
  | 0, start, x, x', P0, hs, hR, hxv, h => JR.pure' (fun st hI hp => by
      obtain ⟨_, hx, rfl, hch⟩ := h st hI hp
      refine ⟨⟨hx, rfl, by simpa using hch⟩, hxv st hI hp, fun hx' hxe => ?_⟩
      simp only [List.cons.injEq, SV.hid.injEq, and_true] at hxe
      subst hxe
      exact ⟨chainH_lt hI hch, fun hl s' h1 h2 _ => ⟨hx, by rw [show s' = start by omega]; exact hl⟩⟩)
  | steps+1, start, x, x', P0, hs, hR, hxv, h => by
    simp only [sChain, chain]
    have hR1 : InR L T F ci (start+1) := by
      obtain ⟨a, b, d, e, f⟩ := hR; exact ⟨a, b, d, e, by omega⟩
    refine JR.bind (jr_chainStep tk L T F ci start x tk' x' hR1 htk hxv h) (fun y y' => ?_) hs
    have hs' := stable2_and hs (stable_RCs L T F ci start x y y')
    have hrec := J2.frame (jr_chain tk tk' L T F ci htk steps (start+1) y y' hs'
      (by obtain ⟨a, b, d, e, f⟩ := hR; exact ⟨a, b, d, e, by omega⟩) (fun st _ hp => hp.2.2)
      (fun st hI hp => ⟨(h st hI hp.1).1, by
        obtain ⟨⟨i, hv, hch, _⟩, _⟩ := hp.2
        exact ⟨i, hv, hch⟩⟩)) hs'
    refine J2.conseq hrec (fun _ _ h => h) ?_
    intro v st ⟨⟨_, ⟨i, hy, _, himp⟩, _⟩, ⟨⟨j, hv, hch⟩, hr, himp2⟩⟩
    refine ⟨⟨j, hv, by rw [show start + (steps+1) = start + 1 + steps by omega]; exact hch⟩, hr,
      fun hx hxe => ?_⟩
    obtain ⟨hxl, hlow⟩ := himp hx hxe
    refine ⟨hxl, fun hl s' h1 h2 h3 => ?_⟩
    by_cases hs0 : s' = start
    · exact ⟨hx, hs0 ▸ hl⟩
    · have hi := hlow hl (by omega)
      exact ((himp2 i hy).2 hi) s' (by omega) (by omega) h3
end

/-! WOTS. -/

theorem zipIdx_getD {l : List Nat} {x : Nat × Nat} (h : x ∈ l.zipIdx) : l.getD x.2 0 = x.1 := by
  have := List.mem_zipIdx_iff_getElem?.mp h
  simp [List.getD_eq_getElem?_getD, this]

theorem digits_le15 (p : Params) (m : Bytes) (i : Nat) : (wotsDigits p m).getD i 0 ≤ 15 := by
  by_cases hi : i < (wotsDigits p m).length
  · rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hi, Option.getD_some]
    exact wots_digit_bound p m _ (List.getElem_mem hi)
  · rw [List.getD_eq_getElem?_getD, List.getElem?_eq_none (by omega)]; simp

section
variable {c : Ctx}

theorem JR.bindT {α β γ δ : Type} {P : Prog α} {T : Id β} {f : α → Prog γ} {g : β → Id δ} {P0 : St → Prop}
    {R₁ : α → β → St → Prop} {R₂ : γ → δ → St → Prop} (hP : JR c P T P0 R₁)
    (hf : ∀ a, JR c (f a) (g T) (fun st => P0 st ∧ R₁ a T st) R₂) (hs : Stable2 c P0) :
    JR c (P >>= f) (T >>= g) P0 R₂ :=
  J2.bind hP hf hs

theorem chainH_safe {st : St} (hI : Inv2 c st) {h L T F ci s : Nat} (hr : InR L T F ci s)
    (hd : c.dgt L T F ci ≤ s) (hc : ChainH c st h L T F ci s) : Safe2 c st h :=
  hc.elim (lowAt_safe2 hI hr hd) id

theorem dgt_le15 (L T F ci : Nat) : c.dgt L T F ci ≤ 15 := digits_le15 _ _ _

/-- The honest WOTS secret, relationally. -/
def RL0 (c : Ctx) (L T F ci : Nat) (v : SB) (b : Bytes) (st : St) : Prop :=
  (∃ i, v = [.hid i c.n] ∧ LowAt c.n st i L T F ci 0) ∧ sres c.t v = b

theorem stable_RL0 (L T F ci : Nat) (v : SB) (b : Bytes) : Stable2 c (RL0 c L T F ci v b) := by
  intro _ _ _ hg h
  obtain ⟨⟨i, hv, hl⟩, hr⟩ := h
  exact ⟨⟨i, hv, lowAt_fwd hg 0 hl⟩, hr⟩

theorem jr_prf5 (pk : SB) (pk' seed' : Bytes) (L T F ci : Nat) (hpk : sres c.t pk = pk')
    (hseed : sres c.t [.hid 2 c.n] = seed') {P0 : St → Prop} (h : ∀ st, Inv2 c st → P0 st → PKh c st pk) :
    JR c (sPrf (params c.v) pk [.hid 2 c.n] (A5 L T F ci)) (prf c.O (params c.v) pk' seed' (A5 L T F ci)) P0
      (RL0 c L T F ci) := by
  subst hpk hseed
  exact j2_prf5 pk L T F ci h

/-- The honest keys and the public seed. -/
structure Keys (c : Ctx) (tk pk : SB) (tk' pk' : Bytes) : Prop where
  htk : sres c.t tk = tk'
  hpk : sres c.t pk = pk'

variable {tk pk : SB} {tk' pk' : Bytes}

theorem jr_wotsSign (K : Keys c tk pk tk' pk') (L T F : Nat) (msg : Bytes) (hmsg : msg = c.M L T F)
    (hL : L < 256^4) (hT : T < 256^8) (hF : F < 256^4) {P0 : St → Prop} (hs : Stable2 c P0)
    (h : ∀ st, Inv2 c st → P0 st → TKh c st tk ∧ PKh c st pk) :
    JR c (sWotsSign (params c.v) tk pk [.hid 2 c.n] (wA L T F) msg)
      (wotsSign c.O (params c.v) tk' pk' (sres c.t [.hid 2 c.n]) (wA L T F) msg) P0 (RG c) := by
  obtain ⟨hlen, _⟩ := variant_bounds c.v
  simp only [sWotsSign, wotsSign]
  refine JR.bind (JR.loop' _ _ _ (RG c) hs (fun a b => stable_RG a b) [] [] (fun st _ _ => RG_nil st) ?_)
    (fun a b => JR.pure' (fun _ _ h => h.2)) hs
  intro x hx s s'
  obtain ⟨digit, i⟩ := x
  have hi := (zipIdx_mem hx).2
  rw [wots_digit_count] at hi
  have hdig := zipIdx_getD hx
  simp only at hi hdig
  have hd15 : digit ≤ 15 := by rw [← hdig]; exact digits_le15 _ _ _
  refine JR.bind (jr_prf5 pk pk' _ L T F i K.hpk rfl (fun st hI hp => (h st hI hp.1).2)) (fun sk sk' => ?_)
    (stable2_and hs (stable_RG s s'))
  have hs2 := stable2_and (stable2_and hs (stable_RG s s')) (stable_RL0 L T F i sk sk')
  refine JR.bind (jr_chain tk tk' L T F i K.htk digit 0 sk sk' hs2
      (⟨hL, hT, hF, by omega, by omega⟩) (fun st _ hp => hp.2.2)
      (fun st hI hp => ⟨(h st hI hp.1.1).1, by
        obtain ⟨⟨j, hj, hl⟩, _⟩ := hp.2
        exact ⟨j, hj, Or.inl hl⟩⟩)) (fun part part' => ?_) hs2
  refine JR.pure' (fun st hI hp => ?_)
  obtain ⟨⟨⟨_, hrg⟩, _⟩, ⟨⟨j, hj, hch⟩, hres, _⟩⟩ := hp
  have hsafe : Safe2 c st j := chainH_safe hI ⟨hL, hT, hF, by omega, by omega⟩
    (by simp only [Ctx.dgt]; rw [← hmsg, hdig]; omega) hch
  subst hj
  exact RG_append hrg (RG_one hsafe hres)
end

/-! Loops whose body always continues, with a per-item fact. -/

section
variable {c : Ctx}

theorem JR.loopQ {ι σ σ' : Type} (l : List ι) (f : ι → σ → Prog (ForInStep σ)) (g : ι → σ' → Id (ForInStep σ'))
    (R : σ → σ' → St → Prop) (Q : ι → St → Prop) (hR : ∀ a b, Stable2 c (R a b)) (hQ : ∀ i, Stable2 c (Q i)) :
    ∀ (P0 : St → Prop), Stable2 c P0 →
    (∀ i ∈ l, ∀ s s', JR c (f i s) (g i s') (fun st => P0 st ∧ R s s' st)
      (fun r r' st => (∃ a b, r = .yield a ∧ r' = .yield b ∧ R a b st) ∧ Q i st)) →
    ∀ s s', JR c (forIn l s f) (forIn l s' g) (fun st => P0 st ∧ R s s' st)
      (fun r r' st => R r r' st ∧ ∀ i ∈ l, Q i st) := by
  induction l with
  | nil =>
    intro P0 _ _ s s'
    exact JR.pure' (fun st _ h => ⟨h.2, fun i hi => absurd hi (List.not_mem_nil)⟩)
  | cons a l ih =>
    intro P0 hs hf s s'
    rw [List.forIn_cons, List.forIn_cons]
    refine J2.bind (hf a (by simp) s s') (fun x => ?_) (stable2_and hs (hR s s'))
    cases hg : g a s' with
    | done b =>
      intro st _ hp
      obtain ⟨⟨a', b', _, e2, _⟩, _⟩ := hp.2
      cases e2
    | yield b =>
      cases x with
      | done a' =>
        intro st _ hp
        obtain ⟨⟨a'', b', e1, _, _⟩, _⟩ := hp.2
        cases e1
      | yield a' =>
        have hP' : Stable2 c (fun st => P0 st ∧ Q a st) := stable2_and hs (hQ a)
        have hrest := ih (fun st => P0 st ∧ Q a st) hP'
          (fun i hi s s' => J2.conseq (J2.frame (hf i (by simp [hi]) s s')
            (stable2_and hs (hR s s'))) (fun st _ h => ⟨h.1.1, h.2⟩)
            (fun r st h => h.2)) a' b
        refine J2.conseq (J2.frame hrest (stable2_and hP' (hR a' b))) (fun st _ h => ⟨⟨h.1.1, h.2.2⟩, ?_⟩) ?_
        · obtain ⟨⟨a'', b'', e1, e2, hr⟩, _⟩ := h.2
          cases e1; cases e2; exact hr
        · intro r st h
          refine ⟨h.2.1, fun i hi => ?_⟩
          simp only [List.mem_cons] at hi
          rcases hi with rfl | hi
          · exact h.1.1.2
          · exact h.2.2 i hi
end

section
variable {c : Ctx} {tk pk : SB} {tk' pk' : Bytes}

theorem hids_tk_gd {st : St} (hI : Inv2 c st) {x : SB} (htk : TKh c st tk) (hx : Gd2 c st x) :
    ∀ y ∈ shids tk ++ shids x, y < st.ents.length ∧ y ≠ 0 ∧ y ≠ 1 := by
  intro y hy
  rcases List.mem_append.mp hy with hy | hy
  · exact tkh_hids hI htk y hy
  · exact gd2_hids hI hx y hy

/-- WOTS public key generation: a disclosable compressed key; on every chain, the
    honest low chain values up to the digit are entries. -/
theorem jr_wotsPkgen (K : Keys c tk pk tk' pk') (L T F : Nat) (hL : L < 256^4) (hT : T < 256^8)
    (hF : F < 256^4) {P0 : St → Prop} (hs : Stable2 c P0)
    (h : ∀ st, Inv2 c st → P0 st → TKh c st tk ∧ PKh c st pk) :
    JR c (sWotsPkgen (params c.v) tk pk [.hid 2 c.n] (wA L T F))
      (wotsPkgen c.O (params c.v) tk' pk' (sres c.t [.hid 2 c.n]) (wA L T F)) P0
      (fun v b st => R1 c c.n v b st ∧ ∀ ci ∈ List.range (params c.v).len, ∀ s', s' ≤ c.dgt L T F ci →
        ∃ j, LowAt c.n st j L T F ci s') := by
  obtain ⟨hlen, _⟩ := variant_bounds c.v
  simp only [sWotsPkgen, wotsPkgen, sWotsCompress, wotsCompress]
  refine JR.bind (R₁ := fun r r' st => RG c r r' st ∧ ∀ ci ∈ List.range (params c.v).len, ∀ s',
      s' ≤ c.dgt L T F ci → ∃ j, LowAt c.n st j L T F ci s')
    (J2.conseq (JR.loopQ (c := c) _ _ _ (RG c)
    (fun ci st => ∀ s', s' ≤ c.dgt L T F ci → ∃ j, LowAt c.n st j L T F ci s')
    (fun a b => stable_RG a b)
    (fun ci st st' hI hg hq s' hs' => by
      obtain ⟨j, hj⟩ := hq s' hs'
      exact ⟨j, lowAt_fwd hg s' hj⟩) P0 hs ?body [] [])
    (fun st _ hp => ⟨hp, RG_nil st⟩) (fun _ _ h => h)) (fun tops tops' => ?cont) hs
  case cont =>
    refine J2.conseq (J2.frame (jr_thash (params c.v) tk _ tops tk' tops' (by simp [Adrs.setType])
      (by simp [Adrs.setType]) K.htk (fun st _ hp => hp.2.1.2.1)
      (fun st hI hp => hids_tk_gd hI (h st hI hp.1).1 hp.2.1.1)) (stable2_and hs (fun st st' hI hg hp =>
        ⟨stable_RG tops tops' st st' hI hg hp.1, fun ci hci s' hs' => by
          obtain ⟨j, hj⟩ := hp.2 ci hci s' hs'
          exact ⟨j, lowAt_fwd hg s' hj⟩⟩))) (fun _ _ h => h) ?_
    intro v st hv
    exact ⟨hv.2, hv.1.2.2⟩
  case body =>
    intro i hi s s'
    have hi' : i < (params c.v).len := List.mem_range.mp hi
    refine JR.bind (jr_prf5 pk pk' _ L T F i K.hpk rfl (fun st hI hp => (h st hI hp.1).2)) (fun sk sk' => ?_)
      (stable2_and hs (stable_RG s s'))
    have hs2 := stable2_and (stable2_and hs (stable_RG s s')) (stable_RL0 L T F i sk sk')
    refine JR.bind (jr_chain tk tk' L T F i K.htk 15 0 sk sk' hs2
        (⟨hL, hT, hF, by omega, by omega⟩) (fun st _ hp => hp.2.2)
        (fun st hI hp => ⟨(h st hI hp.1.1).1, by
          obtain ⟨⟨j, hj, hl⟩, _⟩ := hp.2
          exact ⟨j, hj, Or.inl hl⟩⟩)) (fun top top' => ?_) hs2
    refine JR.pure' (fun st hI hp => ?_)
    obtain ⟨⟨⟨_, hrg⟩, ⟨⟨j0, hj0, hl0⟩, _⟩⟩, ⟨⟨j, hj, hch⟩, hres, hex⟩⟩ := hp
    have hsafe : Safe2 c st j := chainH_safe hI ⟨hL, hT, hF, by omega, by omega⟩
      (by have := dgt_le15 (c := c) L T F i; omega) hch
    subst hj
    refine ⟨⟨_, _, rfl, rfl, RG_append hrg (RG_one hsafe hres)⟩, fun s' hs' => ?_⟩
    exact (hex j0 hj0).2 hl0 s' (Nat.zero_le _) (by have := dgt_le15 (c := c) L T F i; omega) hs'
end

/-! XMSS. -/

section
variable {c : Ctx} {tk pk : SB} {tk' pk' : Bytes}

theorem allHid_WN {x : SB} (h : AllHid c.n x) : WN c.n x := by
  intro v hv
  obtain ⟨i, rfl⟩ := h v hv
  rfl

theorem RG_sub {v w : SB} {st : St} (hsub : ∀ y ∈ w, y ∈ v) (h : Gd2 c st v ∧ AllHid c.n v) :
    Gd2 c st w ∧ AllHid c.n w :=
  ⟨fun i x hm => h.1 i x (hsub _ hm), fun y hy => h.2 y (hsub _ hy)⟩

theorem RG_take {v : SB} {b : Bytes} {st : St} (h : RG c v b st) (k : Nat) :
    RG c (v.take k) (b.take (k*c.n)) st := by
  obtain ⟨hg, ha⟩ := RG_sub (w := v.take k) (fun y hy => List.mem_of_mem_take hy) ⟨h.1, h.2.2⟩
  exact ⟨hg, by rw [sres_take c.t c.n v k (allHid_WN h.2.2), h.2.1], ha⟩

theorem RG_drop {v : SB} {b : Bytes} {st : St} (h : RG c v b st) (k : Nat) :
    RG c (v.drop k) (b.drop (k*c.n)) st := by
  obtain ⟨hg, ha⟩ := RG_sub (w := v.drop k) (fun y hy => List.mem_of_mem_drop hy) ⟨h.1, h.2.2⟩
  exact ⟨hg, by rw [sres_drop c.t c.n v k (allHid_WN h.2.2), h.2.1], ha⟩

theorem RG_sSlice {v : SB} {b : Bytes} {st : St} (h : RG c v b st) (i k : Nat) :
    RG c (sSlice v i k) (slice b (i*c.n) (k*c.n)) st := by
  obtain ⟨hg, ha⟩ := RG_sub (w := sSlice v i k)
    (fun y hy => List.mem_of_mem_drop (List.mem_of_mem_take hy)) ⟨h.1, h.2.2⟩
  exact ⟨hg, by rw [sres_sSlice c.t c.n v i k (allHid_WN h.2.2), h.2.1], ha⟩

theorem stable_tkRG (tk : SB) (x : SB) (b : Bytes) : Stable2 c (fun st => TKh c st tk ∧ RG c x b st) :=
  stable2_and (stable_tkh tk) (stable_RG x b)

theorem jr_authWalk (K : Keys c tk pk tk' pk') (a : Adrs) (hk : a.kind ≠ 0) (hkk : a.kind < 256^4)
    (auth : SB) (auth' : Bytes) :
    ∀ (remaining li gi level : Nat) (node : SB) (node' : Bytes) {P0 : St → Prop}, Stable2 c P0 →
    (∀ st, Inv2 c st → P0 st → TKh c st tk ∧ RG c auth auth' st ∧ RG c node node' st) →
    JR c (sAuthWalk (params c.v) tk a li gi node auth level remaining)
      (authWalk c.O (params c.v) tk' a li gi node' auth' level remaining) P0 (RG c)
  | 0, _, _, _, _, _, _, _, h => JR.pure' (fun st hI hp => (h st hI hp).2.2)
  | remaining+1, li, gi, level, node, node', P0, hs, h => by
    simp only [sAuthWalk, authWalk]
    have hin : ∀ st, Inv2 c st → P0 st →
        RG c (if li%2 = 0 then node ++ sSlice auth level 1 else sSlice auth level 1 ++ node)
          (if li%2 = 0 then node' ++ slice auth' (level*(params c.v).n) (params c.v).n
            else slice auth' (level*(params c.v).n) (params c.v).n ++ node') st := by
      intro st hI hp
      obtain ⟨_, ha, hn⟩ := h st hI hp
      have hsl := RG_sSlice ha level 1
      rw [Nat.one_mul] at hsl
      split
      · exact RG_append hn hsl
      · exact RG_append hsl hn
    refine JR.bind (jr_thash (params c.v) tk _ _ tk' _ (by simpa using hk) (by simpa using hkk) K.htk
      (fun st hI hp => (hin st hI hp).2.1) (fun st hI hp => hids_tk_gd hI (h st hI hp).1 (hin st hI hp).1))
      (fun y y' => ?_) hs
    exact jr_authWalk K a hk hkk auth auth' remaining _ _ _ y y' (stable2_and hs (stable_R1 _ y y'))
      (fun st hI hp => ⟨(h st hI hp.1).1, (h st hI hp.1).2.1, RG_of_R1 hp.2⟩)

theorem jr_xmssNode (K : Keys c tk pk tk' pk') (L T : Nat) (hL : L < 256^4) (hT : T < 256^8) :
    ∀ (height idx : Nat) {P0 : St → Prop}, Stable2 c P0 → (idx+1)*2^height ≤ 2^(params c.v).hp →
    (∀ st, Inv2 c st → P0 st → TKh c st tk ∧ PKh c st pk) →
    JR c (sXmssNode (params c.v) tk pk [.hid 2 c.n] {layer := L, tree := T} idx height)
      (xmssNode c.O (params c.v) tk' pk' (sres c.t [.hid 2 c.n]) {layer := L, tree := T} idx height) P0
      (R1 c c.n)
  | 0, idx, P0, hs, hb, h => by
    obtain ⟨_, hH, _⟩ := variant_bounds c.v
    simp only [sXmssNode, xmssNode]
    exact J2.conseq (jr_wotsPkgen K L T idx hL hT (by simp at hb; omega) hs h) (fun _ _ h => h)
      (fun _ _ h => h.1)
  | height+1, idx, P0, hs, hb, h => by
    simp only [sXmssNode, xmssNode]
    have e : (idx+1)*2^(height+1) = (2*idx+2)*2^height := by
      rw [Nat.pow_succ, Nat.mul_comm (2^height) 2, ← Nat.mul_assoc]; congr 1; omega
    have hb1 : (2*idx+1)*2^height ≤ 2^(params c.v).hp :=
      Nat.le_trans (Nat.mul_le_mul_right _ (by omega)) (e ▸ hb)
    have hb2 : (2*idx+1+1)*2^height ≤ 2^(params c.v).hp := by
      rw [show 2*idx+1+1 = 2*idx+2 by omega, ← e]; exact hb
    refine JR.bind (jr_xmssNode K L T hL hT height (2*idx) hs hb1 h) (fun l l' => ?_) hs
    have hs1 := stable2_and hs (stable_R1 c.n l l')
    refine JR.bind (jr_xmssNode K L T hL hT height (2*idx+1) hs1 hb2 (fun st hI hp => h st hI hp.1))
      (fun r r' => ?_) hs1
    exact jr_thash (params c.v) tk _ (l ++ r) tk' (l' ++ r') (by simp [Adrs.setType])
      (by simp [Adrs.setType]) K.htk
      (fun st _ hp => (RG_append (RG_of_R1 hp.1.2) (RG_of_R1 hp.2)).2.1)
      (fun st hI hp => hids_tk_gd hI (h st hI hp.1.1).1 (RG_append (RG_of_R1 hp.1.2) (RG_of_R1 hp.2)).1)
end

section
variable {c : Ctx} {tk pk : SB} {tk' pk' : Bytes}

theorem sSlice_one {x : SB} (hx : AllHid c.n x) {i : Nat} (hi : i < x.length) :
    ∃ h, sSlice x i 1 = [.hid h c.n] ∧ SV.hid h c.n ∈ x := by
  obtain ⟨h, hh⟩ := hx (x[i]) (List.getElem_mem hi)
  refine ⟨h, ?_, hh ▸ List.getElem_mem hi⟩
  unfold sSlice
  rw [List.drop_eq_getElem_cons hi]
  simp [hh]

theorem jr_wotsPkFromSig (K : Keys c tk pk tk' pk') (L T F : Nat) (hL : L < 256^4) (hT : T < 256^8)
    (hF : F < 256^4) (sig : SB) (sig' : Bytes) (msg : Bytes) {P0 : St → Prop} (hs : Stable2 c P0)
    (hlen : ∀ st, Inv2 c st → P0 st → sig.length = (params c.v).len)
    (h : ∀ st, Inv2 c st → P0 st → TKh c st tk ∧ RG c sig sig' st) :
    JR c (sWotsPkFromSig (params c.v) tk (wA L T F) sig msg)
      (wotsPkFromSig c.O (params c.v) tk' (wA L T F) sig' msg) P0 (R1 c c.n) := by
  obtain ⟨hlen', _⟩ := variant_bounds c.v
  simp only [sWotsPkFromSig, wotsPkFromSig, sWotsCompress, wotsCompress]
  refine JR.bind (R₁ := RG c) (JR.loop' _ _ _ (RG c) hs (fun a b => stable_RG a b) [] []
    (fun st _ _ => RG_nil st) ?_) (fun tops tops' => ?_) hs
  · intro x hx s s'
    obtain ⟨digit, i⟩ := x
    have hi := (zipIdx_mem hx).2
    rw [wots_digit_count] at hi
    have hdig := zipIdx_getD hx
    simp only at hi hdig
    have hd15 : digit ≤ 15 := by rw [← hdig]; exact digits_le15 _ _ _
    have hs1 := stable2_and hs (stable_RG s s')
    refine JR.bind (jr_chain tk tk' L T F i K.htk (15-digit) digit (sSlice sig i 1)
        (slice sig' (i*(params c.v).n) (params c.v).n) hs1 ⟨hL, hT, hF, by omega, by omega⟩
        (fun st hI hp => by
          have := (RG_sSlice (h st hI hp.1).2 i 1).2.1
          rw [Nat.one_mul] at this; exact this)
        (fun st hI hp => ⟨(h st hI hp.1).1, by
          have hl1 : sig.length = (params c.v).len := hlen st hI hp.1
          obtain ⟨hx', hsl, hmem⟩ := sSlice_one (h st hI hp.1).2.2.2 (show i < sig.length by omega)
          exact ⟨hx', hsl, Or.inr ((h st hI hp.1).2.1 hx' _ hmem)⟩⟩)) (fun top top' => ?_) hs1
    refine JR.pure' (fun st hI hp => ?_)
    obtain ⟨⟨_, hrg⟩, ⟨⟨j, hj, hch⟩, hres, _⟩⟩ := hp
    have hsafe : Safe2 c st j := chainH_safe hI ⟨hL, hT, hF, by omega, by omega⟩
      (by have := dgt_le15 (c := c) L T F i; omega) hch
    subst hj
    exact RG_append hrg (RG_one hsafe hres)
  · exact jr_thash (params c.v) tk _ tops tk' tops' (by simp [Adrs.setType]) (by simp [Adrs.setType]) K.htk
      (fun st _ hp => hp.2.2.1) (fun st hI hp => hids_tk_gd hI (h st hI hp.1).1 hp.2.1)

theorem jr_xmssPkFromSig (K : Keys c tk pk tk' pk') (L T idx : Nat) (hL : L < 256^4) (hT : T < 256^8)
    (hidx : idx < 256^4) (sig : SB) (sig' : Bytes) (msg : Bytes) {P0 : St → Prop} (hs : Stable2 c P0)
    (hlen : ∀ st, Inv2 c st → P0 st → (params c.v).len ≤ sig.length)
    (h : ∀ st, Inv2 c st → P0 st → TKh c st tk ∧ RG c sig sig' st) :
    JR c (sXmssPkFromSig (params c.v) tk {layer := L, tree := T} idx sig msg)
      (xmssPkFromSig c.O (params c.v) tk' {layer := L, tree := T} idx sig' msg) P0 (RG c) := by
  simp only [sXmssPkFromSig, xmssPkFromSig, sAuthRoot, authRoot]
  refine JR.bind (jr_wotsPkFromSig K L T idx hL hT hidx (sig.take (params c.v).len) _ msg hs
    (fun st hI hp => by have := hlen st hI hp; simp; omega)
    (fun st hI hp => ⟨(h st hI hp).1, RG_take (h st hI hp).2 _⟩)) (fun node node' => ?_) hs
  exact jr_authWalk K _ (by simp [Adrs.setType]) (by simp [Adrs.setType]) _ _ _ _ _ _ node node'
    (stable2_and hs (stable_R1 _ node node'))
    (fun st hI hp => ⟨(h st hI hp.1).1, RG_drop (h st hI hp.1).2 _, RG_of_R1 hp.2⟩)

theorem jr_xmssSign (K : Keys c tk pk tk' pk') (L T idx : Nat) (hL : L < 256^4) (hT : T < 256^8)
    (hidx : idx < 2^(params c.v).hp) (msg : Bytes) (hmsg : msg = c.M L T idx) {P0 : St → Prop}
    (hs : Stable2 c P0) (h : ∀ st, Inv2 c st → P0 st → TKh c st tk ∧ PKh c st pk) :
    JR c (sXmssSign (params c.v) tk pk [.hid 2 c.n] {layer := L, tree := T} idx msg)
      (xmssSign c.O (params c.v) tk' pk' (sres c.t [.hid 2 c.n]) {layer := L, tree := T} idx msg) P0 (RG c) := by
  obtain ⟨_, hH, _⟩ := variant_bounds c.v
  simp only [sXmssSign, xmssSign]
  refine JR.bind (R₁ := RG c) (JR.loop' _ _ _ (RG c) hs (fun a b => stable_RG a b) [] []
    (fun st _ _ => RG_nil st) ?_) (fun auth auth' => ?_) hs
  · intro level hl s s'
    have hl' := List.mem_range.mp hl
    have hsib := sibling_bound (params c.v).hp level idx hidx hl'
    have hb : (Nat.xor (idx/2^level) 1 + 1)*2^level ≤ 2^(params c.v).hp := by
      have e : 2^(params c.v).hp = 2^((params c.v).hp-level)*2^level := by
        rw [← Nat.pow_add]; congr 1; omega
      rw [e]; exact Nat.mul_le_mul_right _ hsib
    have hs1 := stable2_and hs (stable_RG s s')
    refine JR.bind (jr_xmssNode K L T hL hT level _ hs1 hb (fun st hI hp => h st hI hp.1))
      (fun node node' => JR.pure' (fun st _ hp => RG_append hp.1.2 (RG_of_R1 hp.2))) hs1
  · have hs1 := stable2_and hs (stable_RG auth auth')
    refine JR.bind (jr_wotsSign K L T idx msg hmsg hL hT (by omega) hs1 (fun st hI hp => h st hI hp.1))
      (fun sg sg' => JR.pure' (fun st _ hp => RG_append hp.2 hp.1.2)) hs1
end

/-! The hypertree signer, with the honest message at every layer. -/

section
variable {c : Ctx}

theorem coin_res (t : List Nat) (n : Nat) :
    sres t (coinEx n) = be n (t.getD 0 0) ++ (be n (t.getD 1 0) ++ (be n (t.getD 2 0) ++ [])) := rfl

theorem seed_res : sres c.t [.hid 2 c.n] = expSeed c.v c.e := by
  have hA := be_width c.n (c.t.getD 0 0)
  have hB := be_width c.n (c.t.getD 1 0)
  have hC := be_width c.n (c.t.getD 2 0)
  simp only [expSeed, Ctx.e, coin_res, slice]
  rw [show 2*(params c.v).n = (params c.v).n + (params c.v).n by omega, ← List.drop_drop,
    List.drop_left' hA, List.drop_left' hB]
  simp only [sres, SV.res, List.append_nil]
  exact (List.take_of_length_le (Nat.le_of_eq hC)).symm

theorem outputWidths_O : OutputWidths c.O := fun r => oracleOf_len c.t c.D r

theorem M_eq (L T F : Nat) : c.M L T F =
    htMsg c.O (params c.v) (expTk c.O c.v c.e) (expPrf c.O c.v c.e) (sres c.t [.hid 2 c.n]) L T F := by
  rw [seed_res]; rfl

variable {tk pk : SB}

theorem xmss_correct_root (layer next leaf : Nat) (hleaf : leaf < 2^(params c.v).hp) (nb : Bytes) :
    xmssPkFromSig c.O (params c.v) (expTk c.O c.v c.e) {layer := layer, tree := next} leaf
      (xmssSign c.O (params c.v) (expTk c.O c.v c.e) (expPrf c.O c.v c.e) (sres c.t [.hid 2 c.n])
        {layer := layer, tree := next} leaf nb) nb =
      c.M (layer+1) (next/2^(params c.v).hp) (next%2^(params c.v).hp) := by
  rw [xmss_sign_correct c.O outputWidths_O, Nat.div_eq_of_lt hleaf, M_eq]
  simp only [htMsg, Nat.add_one_ne_zero, if_false, Nat.add_sub_cancel]
  rw [Nat.mul_comm, Nat.div_add_mod]

theorem jr_htSignTail (K : Keys c tk pk (expTk c.O c.v c.e) (expPrf c.O c.v c.e)) :
    ∀ (remaining layer tree : Nat) (node : SB) (node' : Bytes) {P0 : St → Prop}, Stable2 c P0 →
    layer + remaining ≤ (params c.v).d → tree < 256^8 →
    node' = c.M layer (tree/2^(params c.v).hp) (tree%2^(params c.v).hp) →
    (∀ st, Inv2 c st → P0 st → TKh c st tk ∧ PKh c st pk ∧ RG c node node' st) →
    JR c (sHtSignTail (params c.v) tk pk [.hid 2 c.n] layer tree node remaining)
      (htSignTail c.O (params c.v) (expTk c.O c.v c.e) (expPrf c.O c.v c.e) (sres c.t [.hid 2 c.n])
        layer tree node' remaining) P0 (RG c)
  | 0, _, _, _, _, _, _, _, _, _, _ => JR.pure' (fun st _ _ => RG_nil st)
  | remaining+1, layer, tree, node, node', P0, hs, hl, ht, hnode, h => by
    obtain ⟨_, hH, hd, _⟩ := variant_bounds c.v
    simp only [sHtSignTail, htSignTail]
    refine JR.reveal (fun st hI hp => (h st hI hp).2.2.1) ?_ hs
    have hnb : ∀ st, Inv2 c st → P0 st → sres c.t node = node' := fun st hI hp => (h st hI hp).2.2.2.1
    have hleaf : tree % 2^(params c.v).hp < 2^(params c.v).hp := Nat.mod_lt _ (Nat.pow_pos (by decide))
    have hnext : tree / 2^(params c.v).hp < 256^8 := Nat.lt_of_le_of_lt (Nat.div_le_self _ _) ht
    intro st hI hp hnd hD
    rw [hnb st hI hp] at hnd hD ⊢
    revert st
    refine JR.bindT (jr_xmssSign K layer (tree/2^(params c.v).hp) (tree%2^(params c.v).hp) (by omega) hnext
      hleaf node' hnode hs (fun st hI hp => ⟨(h st hI hp).1, (h st hI hp).2.1⟩)) (fun part => ?_) hs
    have hs1 := stable2_and hs (stable_RG part (xmssSign c.O (params c.v) (expTk c.O c.v c.e)
      (expPrf c.O c.v c.e) (sres c.t [.hid 2 c.n]) {layer := layer, tree := tree/2^(params c.v).hp}
      (tree%2^(params c.v).hp) node'))
    refine JR.ite (fun _ => JR.pure' (fun _ _ hp => hp.2)) (fun hr => ?_)
    refine JR.bind JR.unit (fun _ _ => ?_) hs1
    have hs2 := stable2_and hs1 (stable_pure True)
    refine JR.bindT (jr_xmssPkFromSig K layer (tree/2^(params c.v).hp) (tree%2^(params c.v).hp) (by omega)
      hnext (by omega) part _ node' hs2 (fun st _ hp => by
        have h1 := sres_length c.t c.n part (allHid_WN hp.1.2.2.2)
        rw [hp.1.2.2.1, xmss_sign_width c.O outputWidths_O] at h1
        simp only [Params.layerBytes] at h1
        have hn := params_n_pos c.v
        have : (params c.v).len + (params c.v).hp = part.length :=
          Nat.eq_of_mul_eq_mul_right hn (by rw [← h1, Nat.add_mul])
        omega) (fun st hI hp => ⟨(h st hI hp.1.1).1, hp.1.2⟩)) (fun root => ?_) hs2
    have hs3 := stable2_and hs2 (stable_RG root (xmssPkFromSig c.O (params c.v) (expTk c.O c.v c.e)
      {layer := layer, tree := tree/2^(params c.v).hp} (tree%2^(params c.v).hp)
      (xmssSign c.O (params c.v) (expTk c.O c.v c.e) (expPrf c.O c.v c.e) (sres c.t [.hid 2 c.n])
        {layer := layer, tree := tree/2^(params c.v).hp} (tree%2^(params c.v).hp) node') node'))
    refine JR.bind (jr_htSignTail K remaining (layer+1) (tree/2^(params c.v).hp) root _ hs3 (by omega) hnext
      (xmss_correct_root layer (tree/2^(params c.v).hp) _ hleaf node')
      (fun st hI hp => ⟨(h st hI hp.1.1.1).1, (h st hI hp.1.1.1).2.1, hp.2⟩)) (fun tail tail' => ?_) hs3
    exact JR.pure' (fun st _ hp => RG_append hp.1.1.1.2 hp.2)
end

section
variable {c : Ctx} {tk pk : SB}

theorem jr_htSign (K : Keys c tk pk (expTk c.O c.v c.e) (expPrf c.O c.v c.e)) (msg : SB) (msg' : Bytes)
    (idxTree idxLeaf : Nat) (ht : idxTree < 256^8) (hleaf : idxLeaf < 2^(params c.v).hp)
    (hmsg : msg' = c.M 0 idxTree idxLeaf) {P0 : St → Prop} (hs : Stable2 c P0)
    (h : ∀ st, Inv2 c st → P0 st → TKh c st tk ∧ PKh c st pk ∧ RG c msg msg' st) :
    JR c (sHtSign (params c.v) tk pk [.hid 2 c.n] msg idxTree idxLeaf)
      (htSign c.O (params c.v) (expTk c.O c.v c.e) (expPrf c.O c.v c.e) (sres c.t [.hid 2 c.n])
        msg' idxTree idxLeaf) P0 (RG c) := by
  obtain ⟨_, hH, hd, _⟩ := variant_bounds c.v
  obtain ⟨hd2, _⟩ := supported_layer_bounds c.v
  simp only [sHtSign, htSign]
  refine JR.reveal (fun st hI hp => (h st hI hp).2.2.1) ?_ hs
  intro st hI hp hnd hD
  rw [(h st hI hp).2.2.2.1] at hnd hD ⊢
  revert st
  refine JR.bindT (jr_xmssSign K 0 idxTree idxLeaf (by decide) ht hleaf msg' hmsg hs
    (fun st hI hp => ⟨(h st hI hp).1, (h st hI hp).2.1⟩)) (fun first => ?_) hs
  have hs1 := stable2_and hs (stable_RG first (xmssSign c.O (params c.v) (expTk c.O c.v c.e)
      (expPrf c.O c.v c.e) (sres c.t [.hid 2 c.n]) {tree := idxTree} idxLeaf msg'))
  refine JR.bindT (jr_xmssPkFromSig K 0 idxTree idxLeaf (by decide) ht (by omega) first _ msg' hs1
    (fun st _ hp => by
      have h1 := sres_length c.t c.n first (allHid_WN hp.2.2.2)
      rw [hp.2.2.1, xmss_sign_width c.O outputWidths_O] at h1
      simp only [Params.layerBytes] at h1
      have hn := params_n_pos c.v
      have : (params c.v).len + (params c.v).hp = first.length :=
        Nat.eq_of_mul_eq_mul_right hn (by rw [← h1, Nat.add_mul])
      omega) (fun st hI hp => ⟨(h st hI hp.1).1, hp.2⟩)) (fun root => ?_) hs1
  have hs2 := stable2_and hs1 (stable_RG root (xmssPkFromSig c.O (params c.v) (expTk c.O c.v c.e)
      {tree := idxTree} idxLeaf (xmssSign c.O (params c.v) (expTk c.O c.v c.e) (expPrf c.O c.v c.e)
        (sres c.t [.hid 2 c.n]) {tree := idxTree} idxLeaf msg') msg'))
  refine JR.bind (jr_htSignTail K _ 1 idxTree root _ hs2 (by omega) ht
    (xmss_correct_root 0 idxTree idxLeaf hleaf msg')
    (fun st hI hp => ⟨(h st hI hp.1.1).1, (h st hI hp.1.1).2.1, hp.2⟩)) (fun tail tail' => ?_) hs2
  exact JR.pure' (fun st _ hp => RG_append hp.1.1.2 hp.2)
end

/-! FORS. -/

section
variable {c : Ctx} {tk pk : SB} {tk' pk' : Bytes}

theorem flA_eq (tree leaf gi : Nat) :
    flA tree leaf gi = {tree := tree, kind := 3, keypair := leaf, hash := gi} := by
  simp [flA, forsAdrs]

theorem fsAt_fwd {st st' : St} (hg : Grow2 st st') {h tree leaf gi : Nat} (hf : FsAt c.n st h tree leaf gi) :
    FsAt c.n st' h tree leaf gi := by
  obtain ⟨pk, h1, h2⟩ := hf
  exact ⟨pk, grow_get hg h1, grow_get hg h2⟩

/-- The honest FORS secret, relationally. -/
def RF (c : Ctx) (tree leaf gi : Nat) (v : SB) (b : Bytes) (st : St) : Prop :=
  (∃ i, v = [.hid i c.n] ∧ FsAt c.n st i tree leaf gi) ∧ sres c.t v = b

theorem stable_RF (tree leaf gi : Nat) (v : SB) (b : Bytes) : Stable2 c (RF c tree leaf gi v b) := by
  intro _ _ _ hg h
  obtain ⟨⟨i, hv, hf⟩, hr⟩ := h
  exact ⟨⟨i, hv, fsAt_fwd hg hf⟩, hr⟩

theorem jr_prf6 (pk : SB) (pk' seed' : Bytes) (tree leaf gi : Nat) (hpk : sres c.t pk = pk')
    (hseed : sres c.t [.hid 2 c.n] = seed') {P0 : St → Prop} (h : ∀ st, Inv2 c st → P0 st → PKh c st pk) :
    JR c (sPrf (params c.v) pk [.hid 2 c.n] (fsA tree leaf gi)) (prf c.O (params c.v) pk' seed' (fsA tree leaf gi)) P0
      (RF c tree leaf gi) := by
  subst hpk hseed
  exact j2_prf6 pk tree leaf gi h

theorem fsAt_ne {st : St} (hI : Inv2 c st) {h tree leaf gi : Nat} (hf : FsAt c.n st h tree leaf gi) :
    h < st.ents.length ∧ h ≠ 0 ∧ h ≠ 1 := by
  obtain ⟨_, e1, _⟩ := hf
  exact entry_ne hI e1 (by simp [prfReq, coin]) (by simp [prfReq, coin])

/-- A FORS secret selected by a challenger digest may be disclosed. -/
theorem fsAt_safe2 {st : St} (hI : Inv2 c st) {h tree leaf gi : Nat} (hr : InRF tree leaf gi)
    (hf : FsAt c.n st h tree leaf gi)
    (hsel : ∃ k m, SigD c st k m ∧ Sel c.v (be c.pm (c.t.getD k 0)) tree leaf gi) : Safe2 c st h := by
  obtain ⟨pk, e1, e2⟩ := hf
  obtain ⟨r1, r2, r3⟩ := hr
  refine ⟨lt_entry e1, ?_, ?_, ?_⟩
  · rintro ⟨e, he, h3⟩
    rw [e1] at he; obtain rfl := Option.some.inj he
    have hpk := entry_ne hI e2 (by simp [dPrf, coin]) (by simp [dPrf, coin])
    simp [prfReq, SReq.hids, shids] at h3
    omega
  · intro tree' leaf' gi' hr' ⟨pk', e1', _⟩
    obtain ⟨r1', r2', r3'⟩ := hr'
    have e := (Prod.mk.inj (Option.some.inj (e1.symm.trans e1'))).2
    have hb := congrArg SReq.input e
    simp only [prfReq, List.cons.injEq, SV.lit.injEq, and_true, true_and] at hb
    have ha := adrs_bytes_injective _ _ (by rw [fsA_eq]; simp only [Adrs.InRange]; omega)
      (by rw [fsA_eq]; simp only [Adrs.InRange]; omega) hb
    rw [fsA_eq, fsA_eq] at ha
    simp only [Adrs.mk.injEq] at ha
    obtain ⟨-, rfl, -, rfl, -, rfl⟩ := ha
    exact hsel
  · rintro ⟨L, T, F, ci, s, hr', _, hlw⟩
    cases s with
    | zero =>
      obtain ⟨pk', e1', _⟩ := hlw
      have e := (Prod.mk.inj (Option.some.inj (e1.symm.trans e1'))).2
      have hb := congrArg SReq.input e
      simp only [prfReq, List.cons.injEq, SV.lit.injEq, and_true, true_and] at hb
      have := adrs_kind _ _ hb (by rw [fsA_eq]; show (6:Nat) < 256^4; decide)
        (by rw [a5_eq]; show (5:Nat) < 256^4; decide)
      rw [fsA_eq, a5_eq] at this
      simp at this
    | succ s =>
      obtain ⟨itk, h', e1', _⟩ := hlw
      exact prfReq_ne_chReq _ _ _ _ _ _ (Prod.mk.inj (Option.some.inj (e1.symm.trans e1'))).2

/-- The FORS leaf: a disclosable handle; while its secret is unrevealed, its entry is the
    honest leaf request on the honest secret. -/
def LeafAt (c : Ctx) (st : St) (v : SB) (tree leaf gi : Nat) : Prop :=
  ∃ hl hs itk, v = [.hid hl c.n] ∧ FsAt c.n st hs tree leaf gi ∧ st.ents[itk]? = some (false, dTk c.n) ∧
    (hs ∈ st.rev ∨ st.ents[hl]? = some (false, chReq c.n itk (flA tree leaf gi) hs))

theorem stable_leafAt (v : SB) (tree leaf gi : Nat) : Stable2 c (fun st => LeafAt c st v tree leaf gi) := by
  intro _ _ _ hg ⟨hl, hs, itk, hv, hf, hi, ho⟩
  refine ⟨hl, hs, itk, hv, fsAt_fwd hg hf, grow_get hg hi, ?_⟩
  rcases ho with ho | ho
  · exact Or.inl (hg.2 _ ho)
  · exact Or.inr (grow_get hg ho)

theorem jr_forsLeaf (K : Keys c tk pk tk' pk') (tree leaf gi : Nat) {P0 : St → Prop} (hs : Stable2 c P0)
    (h : ∀ st, Inv2 c st → P0 st → TKh c st tk ∧ PKh c st pk) :
    JR c (sPrf (params c.v) pk [.hid 2 c.n] (fsA tree leaf gi) >>= fun sk => sThash (params c.v) tk (flA tree leaf gi) sk)
      (prf c.O (params c.v) pk' (sres c.t [.hid 2 c.n]) (fsA tree leaf gi) >>= fun sk =>
        thash c.O (params c.v) tk' (flA tree leaf gi) sk) P0
      (fun v b st => R1 c c.n v b st ∧ LeafAt c st v tree leaf gi) := by
  refine JR.bind (jr_prf6 pk pk' _ tree leaf gi K.hpk rfl (fun st hI hp => (h st hI hp).2)) (fun sk sk' => ?_) hs
  refine J2.ask _ (fun st hI hp y hy => ?_) (fun _ _ _ iR m e => by simp [hqOf] at e)
    (fun st hI hp _ hI' hD => ⟨⟨⟨_, rfl, ?_⟩, ?_⟩, ?_⟩)
  · obtain ⟨⟨itk, rfl, hitk⟩, _⟩ := h st hI hp.1
    obtain ⟨⟨hs', rfl, hf⟩, _⟩ := hp.2
    simp [SReq.hids, shids] at hy
    rcases hy with rfl | rfl
    · exact lt_entry hitk
    · exact (fsAt_ne hI hf).1
  · obtain ⟨⟨itk, rfl, hitk⟩, _⟩ := h st hI hp.1
    obtain ⟨⟨hs', rfl, hf⟩, _⟩ := hp.2
    refine ask_safe2 st _ hI' (grow_addC st _) (fun y hy => ?_) (fun pk A e => by simp [prfReq] at e) ?_
    · simp [SReq.hids, shids] at hy
      rcases hy with rfl | rfl
      · exact (entry_ne hI hitk (by simp [dTk, coin]) (by simp [dTk, coin])).2
      · exact (fsAt_ne hI hf).2
    · intro itk' A h' e hA
      have e2 := congrArg SReq.input e
      simp only [chReq] at e2
      have hb : (flA tree leaf gi).bytes = A.bytes := by
        have := congrArg List.head? e2
        simpa using this
      rw [← adrs_kind _ _ hb (by rw [flA_eq]; show (3:Nat) < 256^4; decide) hA, flA_eq]
      show (3:Nat) ≠ 0
      decide
  · rw [ask_val st _ hI' hD, ← hp.2.2, ← K.htk]
    simp [thash, keyed, SReq.res, sres, SV.res]
  · obtain ⟨⟨itk, rfl, hitk⟩, _⟩ := h st hI hp.1
    obtain ⟨⟨hs', rfl, hf⟩, _⟩ := hp.2
    have hg := grow_addC (c := c) st ⟨1, "", [.hid itk 32], .lit (flA tree leaf gi).bytes :: [.hid hs' c.n], (params c.v).n⟩
    refine ⟨_, hs', itk, rfl, fsAt_fwd hg hf, grow_get hg hitk, ?_⟩
    by_cases hr : hs' ∈ st.rev
    · exact Or.inl (hg.2 _ hr)
    · exact Or.inr (ask_closed2 st _ hI ⟨hs', by simp [SReq.hids, shids], hr⟩)
end

section
variable {c : Ctx} {tk pk : SB} {tk' pk' : Bytes}

theorem jr_forsNode (K : Keys c tk pk tk' pk') (tree leaf : Nat) :
    ∀ (height idx : Nat) {P0 : St → Prop}, Stable2 c P0 →
    (∀ st, Inv2 c st → P0 st → TKh c st tk ∧ PKh c st pk) →
    JR c (sForsNode (params c.v) tk pk [.hid 2 c.n] (forsAdrs tree leaf) idx height)
      (forsNode c.O (params c.v) tk' pk' (sres c.t [.hid 2 c.n]) (forsAdrs tree leaf) idx height) P0 (R1 c c.n)
  | 0, idx, P0, hs, h => by
    simp only [sForsNode, sForsSecret, forsNode, forsSecret]
    exact J2.conseq (jr_forsLeaf K tree leaf idx hs h) (fun _ _ h => h) (fun _ _ h => h.1)
  | height+1, idx, P0, hs, h => by
    simp only [sForsNode, forsNode]
    refine JR.bind (jr_forsNode K tree leaf height (2*idx) hs h) (fun l l' => ?_) hs
    have hs1 := stable2_and hs (stable_R1 c.n l l')
    refine JR.bind (jr_forsNode K tree leaf height (2*idx+1) hs1 (fun st hI hp => h st hI hp.1))
      (fun r r' => ?_) hs1
    exact jr_thash (params c.v) tk _ (l ++ r) tk' (l' ++ r') (by simp [forsAdrs])
      (by simp [forsAdrs]) K.htk
      (fun st _ hp => (RG_append (RG_of_R1 hp.1.2) (RG_of_R1 hp.2)).2.1)
      (fun st hI hp => hids_tk_gd hI (h st hI hp.1.1).1 (RG_append (RG_of_R1 hp.1.2) (RG_of_R1 hp.2)).1)

/-- The FORS signature reveals only the secrets its digest selects. -/
theorem jr_forsSign (K : Keys c tk pk tk' pk') (tree leaf : Nat) (ht : tree < 256^8) (hl : leaf < 256^4)
    (md : Bytes) {P0 : St → Prop} (hs : Stable2 c P0)
    (h : ∀ st, Inv2 c st → P0 st → TKh c st tk ∧ PKh c st pk)
    (hsel : ∀ st, Inv2 c st → P0 st → ∃ k m, SigD c st k m ∧
      (splitDigest (params c.v) (be c.pm (c.t.getD k 0))).tree = tree ∧
      (splitDigest (params c.v) (be c.pm (c.t.getD k 0))).leaf = leaf ∧
      (splitDigest (params c.v) (be c.pm (c.t.getD k 0))).md = md) :
    JR c (sForsSign (params c.v) tk pk [.hid 2 c.n] (forsAdrs tree leaf) md)
      (forsSign c.O (params c.v) tk' pk' (sres c.t [.hid 2 c.n]) (forsAdrs tree leaf) md) P0 (RG c) := by
  obtain ⟨_, _, _, hMA, hA, _⟩ := variant_bounds c.v
  simp only [sForsSign, forsSign, sForsSecret, forsSecret]
  refine JR.bind (R₁ := RG c) (JR.loop' _ _ _ (RG c) hs (fun a b => stable_RG a b) [] []
    (fun st _ _ => RG_nil st) ?_) (fun a b => JR.pure' (fun _ _ h => h.2)) hs
  intro x hx s s'
  obtain ⟨idx, i⟩ := x
  have hi := (zipIdx_mem hx).2
  rw [base2b_length] at hi
  have hdig := zipIdx_getD hx
  have hidx := base2b_digit_bound md (params c.v).a (params c.v).k idx (zipIdx_mem hx).1
  simp only at hi hdig
  have hgi : i*2^(params c.v).a + idx < 256^4 := Nat.lt_of_lt_of_le (offset_lt hi hidx) hMA
  have hs1 := stable2_and hs (stable_RG s s')
  refine JR.bind (jr_prf6 pk pk' _ tree leaf (i*2^(params c.v).a+idx) K.hpk rfl
    (fun st hI hp => (h st hI hp.1).2)) (fun sk sk' => ?_) hs1
  have hs2 := stable2_and hs1 (stable_RF tree leaf (i*2^(params c.v).a+idx) sk sk')
  have hsk : ∀ st, Inv2 c st → (P0 st ∧ RG c s s' st) ∧ RF c tree leaf (i*2^(params c.v).a+idx) sk sk' st →
      RG c (s ++ sk) (s' ++ sk') st := by
    intro st hI hp
    obtain ⟨⟨hj, rfl, hf⟩, hres⟩ := hp.2
    obtain ⟨k, m, hk, e1, e2, e3⟩ := hsel st hI hp.1.1
    refine RG_append hp.1.2 (RG_one (fsAt_safe2 hI ⟨ht, hl, hgi⟩ hf ⟨k, m, hk, e1, e2, i, hi, ?_⟩) hres)
    rw [e3]; simp only [forsDigit]; rw [hdig]
  refine JR.bind (R₁ := RG c) (JR.loop' _ _ _ (RG c) hs2 (fun a b => stable_RG a b) _ _
    (fun st hI hp => hsk st hI hp) ?_) (fun b b' => JR.bind JR.unit (fun _ _ => JR.pure' (fun _ _ hp =>
      (show SLR (RG c) (.yield b) (.yield b') _ from hp.1.2))) (stable2_and hs2 (stable_RG b b'))) hs2
  intro level hlv u u'
  have hlv' := List.mem_range.mp hlv
  have hs3 := stable2_and hs2 (stable_RG u u')
  refine JR.bind (jr_forsNode K tree leaf level _ hs3 (fun st hI hp => h st hI hp.1.1.1))
    (fun node node' => JR.bind JR.unit (fun _ _ => JR.pure' (fun _ _ hp =>
      (show SLR (RG c) (.yield (u ++ node)) (.yield (u' ++ node')) _ from
        RG_append hp.1.1.2 (RG_of_R1 hp.1.2)))) (stable2_and hs3 (stable_R1 c.n node node'))) hs3

theorem jr_forsPkFromSig (K : Keys c tk pk tk' pk') (tree leaf : Nat) (sig : SB) (sig' : Bytes) (md : Bytes)
    {P0 : St → Prop} (hs : Stable2 c P0) (h : ∀ st, Inv2 c st → P0 st → TKh c st tk ∧ RG c sig sig' st) :
    JR c (sForsPkFromSig (params c.v) tk (forsAdrs tree leaf) sig md)
      (forsPkFromSig c.O (params c.v) tk' (forsAdrs tree leaf) sig' md) P0 (R1 c c.n) := by
  simp only [sForsPkFromSig, forsPkFromSig, sAuthRoot, authRoot]
  refine JR.bind (R₁ := RG c) (JR.loop' _ _ _ (RG c) hs (fun a b => stable_RG a b) [] []
    (fun st _ _ => RG_nil st) ?_) (fun roots roots' => ?_) hs
  · intro x _ s s'
    obtain ⟨idx, i⟩ := x
    have hs1 := stable2_and hs (stable_RG s s')
    have hpart : ∀ st, Inv2 c st → P0 st → RG c (sSlice sig (i*((params c.v).a+1)) ((params c.v).a+1))
        (slice sig' (i*(((params c.v).a+1)*(params c.v).n)) (((params c.v).a+1)*(params c.v).n)) st := by
      intro st hI hp
      have := RG_sSlice (h st hI hp).2 (i*((params c.v).a+1)) ((params c.v).a+1)
      rw [Nat.mul_assoc] at this; exact this
    refine JR.bind (jr_thash (params c.v) tk _ _ tk' _ (by simp [forsAdrs]) (by simp [forsAdrs]) K.htk
      (fun st hI hp => by have := (RG_take (hpart st hI hp.1) 1).2.1; rw [Nat.one_mul] at this; exact this)
      (fun st hI hp => hids_tk_gd hI (h st hI hp.1).1 (RG_take (hpart st hI hp.1) 1).1))
      (fun lf lf' => ?_) hs1
    have hs2 := stable2_and hs1 (stable_R1 c.n lf lf')
    refine JR.bind (jr_authWalk K _ (by simp [forsAdrs]) (by simp [forsAdrs]) _ _ _ _ _ _ lf lf' hs2
      (fun st hI hp => ⟨(h st hI hp.1.1).1, by
        have := RG_drop (hpart st hI hp.1.1) 1; rw [Nat.one_mul] at this; exact this, RG_of_R1 hp.2⟩))
      (fun r r' => JR.pure' (fun _ _ hp => RG_append hp.1.1.2 hp.2)) hs2
  · exact jr_thash (params c.v) tk _ roots tk' roots' (by simp [forsAdrs, Adrs.setType])
      (by simp [forsAdrs, Adrs.setType]) K.htk (fun st _ hp => hp.2.2.1)
      (fun st hI hp => hids_tk_gd hI (h st hI hp.1).1 hp.2.1)
end

section
variable {c : Ctx} {tk pk : SB} {tk' pk' : Bytes}

theorem jr_htRootTail (K : Keys c tk pk tk' pk') :
    ∀ (remaining layer tree : Nat) (node sig : SB) (node' sig' : Bytes) {P0 : St → Prop}, Stable2 c P0 →
    layer + remaining ≤ (params c.v).d → tree < 256^8 →
    (∀ st, Inv2 c st → P0 st → TKh c st tk ∧ RG c node node' st ∧ RG c sig sig' st ∧
      sig.length = remaining*((params c.v).len+(params c.v).hp)) →
    JR c (sHtRootTail (params c.v) tk layer tree node sig remaining)
      (htRootTail c.O (params c.v) tk' layer tree node' sig' remaining) P0 (RG c)
  | 0, _, _, _, _, _, _, _, _, _, _, h => JR.pure' (fun st hI hp => (h st hI hp).2.1)
  | remaining+1, layer, tree, node, sig, node', sig', P0, hs, hl, ht, h => by
    obtain ⟨_, hH, hd, _⟩ := variant_bounds c.v
    simp only [sHtRootTail, htRootTail]
    have hleaf : tree % 2^(params c.v).hp < 2^(params c.v).hp := Nat.mod_lt _ (Nat.pow_pos (by decide))
    have hnext : tree / 2^(params c.v).hp < 256^8 := Nat.lt_of_le_of_lt (Nat.div_le_self _ _) ht
    refine JR.bind (R₁ := RG c) (JR.reveal (fun st hI hp => (h st hI hp).2.1.1) ?_ hs) (fun root root' => ?_) hs
    · intro st hI hp hnd hD
      rw [(h st hI hp).2.1.2.1] at hnd hD ⊢
      exact jr_xmssPkFromSig K layer (tree/2^(params c.v).hp) (tree%2^(params c.v).hp) (by omega) hnext
        (by omega) (sig.take ((params c.v).len+(params c.v).hp)) _ node' hs
        (fun st hI hp => by have := (h st hI hp).2.2.2; simp; rw [Nat.succ_mul] at this; omega)
        (fun st hI hp => ⟨(h st hI hp).1, RG_take (h st hI hp).2.2.1 _⟩) st hI hp hnd hD
    · exact jr_htRootTail K remaining (layer+1) _ root (sig.drop ((params c.v).len+(params c.v).hp)) root' _
        (stable2_and hs (stable_RG root root')) (by omega) hnext
        (fun st hI hp => ⟨(h st hI hp.1).1, hp.2, RG_drop (h st hI hp.1).2.2.1 _, by
          have := (h st hI hp.1).2.2.2; simp; rw [Nat.succ_mul] at this; omega⟩)

theorem jr_htRoot (K : Keys c tk pk tk' pk') (sig msg : SB) (sig' msg' : Bytes) (tree leaf : Nat)
    (ht : tree < 256^8) (hleaf : leaf < 2^(params c.v).hp) {P0 : St → Prop} (hs : Stable2 c P0)
    (h : ∀ st, Inv2 c st → P0 st → TKh c st tk ∧ RG c sig sig' st ∧ RG c msg msg' st ∧
      sig.length = (params c.v).d*((params c.v).len+(params c.v).hp)) :
    JR c (sHtRoot (params c.v) tk sig msg tree leaf) (htRoot c.O (params c.v) tk' sig' msg' tree leaf) P0 (RG c) := by
  obtain ⟨_, hH, hd, _⟩ := variant_bounds c.v
  obtain ⟨hd2, _⟩ := supported_layer_bounds c.v
  simp only [sHtRoot, htRoot]
  refine JR.bind (R₁ := RG c) (JR.reveal (fun st hI hp => (h st hI hp).2.2.1.1) ?_ hs) (fun node node' => ?_) hs
  · intro st hI hp hnd hD
    rw [(h st hI hp).2.2.1.2.1] at hnd hD ⊢
    exact jr_xmssPkFromSig K 0 tree leaf (by decide) ht (by omega)
      (sig.take ((params c.v).len+(params c.v).hp)) _ msg' hs
      (fun st hI hp => by
        have := (h st hI hp).2.2.2
        have h2 : (params c.v).len + (params c.v).hp ≤ (params c.v).d*((params c.v).len+(params c.v).hp) :=
          Nat.le_mul_of_pos_left _ (by omega)
        simp; omega)
      (fun st hI hp => ⟨(h st hI hp).1, RG_take (h st hI hp).2.1 _⟩) st hI hp hnd hD
  · exact jr_htRootTail K _ 1 tree node (sig.drop ((params c.v).len+(params c.v).hp)) node' _
      (stable2_and hs (stable_RG node node')) (by omega) ht
      (fun st hI hp => ⟨(h st hI hp.1).1, hp.2, RG_drop (h st hI hp.1).2.1 _, by
        have := (h st hI hp.1).2.2.2
        simp; rw [this, Nat.sub_one_mul]⟩)
end

end DSM.Rom
