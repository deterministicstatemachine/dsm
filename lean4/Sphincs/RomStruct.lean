-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomFresh
import Sphincs.RomCover

/- Request-level dataflow of DSM's challenger, on every step of every symbolic run.

   Every challenger request of the extended game H1' belongs to one of DSM's
   request families, and each thash request is *structured*: its address
   literal is in range, its key is the tweak-key entry, and its k-th input
   handle is the challenger entry of the k-th canonical child of its address
   (a structured thash request one level down, or the PRF request at the base
   of a WOTS chain or a FORS leaf), each child having the address as its DSM
   parent. Structure is a statement about the symbolic dataflow (which request
   produced each input handle), not about values, so it holds at every step of
   the symbolic run on every tape: no disagreement-freedom is assumed. The
   judgment `JS` records it for every pre-step state of a trace and for the end
   state; it also records that no protected entry (one mentioning SK.seed or
   SK.prf) is ever revealed, and that every revealed canonical entry has its
   DSM ancestors materialized as structured challenger entries (provenance,
   `AncOK`). Provenance is what makes a structured request's answer its own
   challenger entry (`ask_struct`), never an adversary entry. -/
namespace DSM.Rom
open DSM.Sphincs DSM.Sphincs.Security

/-! Canonical children of an address. -/

/-- A canonical child: a thash request at an address, or a PRF request at an address. -/
inductive Kid where
  | th (A : Adrs)
  | pf (A : Adrs)

/-- The canonical children of a thash address, in input order. -/
def kids (p : Params) (A : Adrs) : List Kid :=
  if A.kind = 0 then
    (if A.hash = 0 then [.pf {A.setType 5 with keypair := A.keypair, chain := A.chain}]
     else [.th {A with hash := A.hash - 1}])
  else if A.kind = 1 then
    (List.range p.len).map (fun ci => .th {A.setType 0 with keypair := A.keypair, chain := ci, hash := 14})
  else if A.kind = 2 then
    (if A.chain = 1 then [.th {A.setType 1 with keypair := 2*A.hash}, .th {A.setType 1 with keypair := 2*A.hash+1}]
     else if 2 ≤ A.chain then
       [.th {A with chain := A.chain - 1, hash := 2*A.hash}, .th {A with chain := A.chain - 1, hash := 2*A.hash+1}]
     else [])
  else if A.kind = 3 then
    (if A.chain = 0 then [.pf {A.setType 6 with keypair := A.keypair, hash := A.hash}]
     else [.th {A with chain := A.chain - 1, hash := 2*A.hash}, .th {A with chain := A.chain - 1, hash := 2*A.hash+1}])
  else if A.kind = 4 then
    (List.range p.k).map (fun i => .th {A.setType 3 with keypair := A.keypair, chain := p.a, hash := i})
  else []

/-- The address a canonical child lives at. -/
def Kid.adr : Kid → Adrs
  | .th A => A
  | .pf A => A

/-- DSM's parent of an address: the thash node whose canonical children include it
    (`none`: a root, i.e. an XMSS tree top or a FORS roots compression). -/
def par (p : Params) (A : Adrs) : Option Adrs :=
  if A.kind = 0 then
    (if A.hash < 14 then some {A with hash := A.hash + 1} else some {A.setType 1 with keypair := A.keypair})
  else if A.kind = 1 then some {A.setType 2 with chain := 1, hash := A.keypair / 2}
  else if A.kind = 2 then
    (if A.chain < p.hp then some {A with chain := A.chain + 1, hash := A.hash / 2} else none)
  else if A.kind = 3 then
    (if A.chain < p.a then some {A with chain := A.chain + 1, hash := A.hash / 2}
     else some {A.setType 4 with keypair := A.keypair})
  else if A.kind = 5 then some {A.setType 0 with keypair := A.keypair, chain := A.chain}
  else if A.kind = 6 then some {A.setType 3 with keypair := A.keypair, hash := A.hash}
  else none

/-- `A`'s canonical children all have `A` as their parent. -/
def DSMOK (p : Params) (A : Adrs) : Prop := ∀ K ∈ kids p A, par p K.adr = some A

/-- `B` is a strict ancestor of `A`. -/
inductive AncOf (p : Params) : Adrs → Adrs → Prop
  | one {A B : Adrs} : par p A = some B → AncOf p A B
  | up {A B C : Adrs} : par p A = some B → AncOf p B C → AncOf p A C

/-- `K` lies below `A` in the canonical-children relation. -/
inductive Reach (p : Params) : Adrs → Kid → Prop
  | kid {A : Adrs} {K : Kid} : K ∈ kids p A → Reach p A K
  | down {A B : Adrs} {K : Kid} : Kid.th B ∈ kids p A → Reach p B K → Reach p A K

section
variable (c : Ctx)

/-- `r` is a structured thash request at `A`, to depth `d`. -/
def StructReq (st : St) : Nat → SReq → Adrs → Prop
  | 0, _, _ => False
  | d+1, r, A => A.InRange ∧ kids (params c.v) A ≠ [] ∧ DSMOK (params c.v) A ∧
      ∃ itk hs, r = ⟨1, "", [.hid itk 32], .lit A.bytes :: hs, c.n⟩ ∧
      st.ents[itk]? = some (false, dTk c.n) ∧ hs.length = (kids (params c.v) A).length ∧
      ∀ k, k < hs.length → ∃ h, hs[k]? = some (.hid h c.n) ∧
        match (kids (params c.v) A)[k]? with
        | some (.th B) => ∃ r', StructReq st d r' B ∧ st.ents[h]? = some (false, r')
        | some (.pf B) => ∃ ipk, st.ents[ipk]? = some (false, dPrf c.n) ∧
            st.ents[h]? = some (false, prfReq c.n ipk B) ∧ B.InRange
        | none => False

/-- Handle `h` is the challenger entry of the canonical child `K`, to depth `d`. -/
def KidAt (st : St) (d : Nat) (h : Nat) : Kid → Prop
  | .th B => ∃ r', StructReq c st d r' B ∧ st.ents[h]? = some (false, r')
  | .pf B => ∃ ipk, st.ents[ipk]? = some (false, dPrf c.n) ∧ st.ents[h]? = some (false, prfReq c.n ipk B) ∧
      B.InRange

/-- Handle `h` resolves to the canonical child `K`. -/
def KidOK (st : St) (h : Nat) (K : Kid) : Prop := ∃ d, KidAt c st d h K

/-- DSM's challenger request families. -/
def FamOK (st : St) (r : SReq) : Prop :=
  r = dTk c.n ∨ r = dPrf c.n ∨ r = dReq c.n ∨
  (∃ ipk A, r = prfReq c.n ipk A ∧ st.ents[ipk]? = some (false, dPrf c.n) ∧ A.InRange ∧ (A.kind = 5 ∨ A.kind = 6)) ∨
  (∃ dk m, r = rqOf c.n dk m ∧ st.ents[dk]? = some (false, dReq c.n)) ∨
  (∃ iR m, r = hqOf c.n c.pm c.root iR m ∧ ∃ dk, st.ents[iR]? = some (false, rqOf c.n dk m) ∧
    st.ents[dk]? = some (false, dReq c.n) ∧ ∀ i ∈ shids c.root, 3 ≤ i ∧ i < st.ents.length) ∨
  (∃ d A, StructReq c st d r A)

/-- A thash request at the address `A` (a statement about its shape only). -/
def ThAt (r : SReq) (A : Adrs) : Prop :=
  A.InRange ∧ ∃ itk hs, r = ⟨1, "", [.hid itk 32], .lit A.bytes :: hs, c.n⟩

/-- Handle `h` is a challenger entry for a thash request at `A`, or for a PRF request
    at `A` under SK.seed. -/
def EntAt (st : St) (h : Nat) (A : Adrs) : Prop :=
  ∃ r, st.ents[h]? = some (false, r) ∧
    (ThAt c r A ∨ (A.InRange ∧ ∃ ipk, r = prfReq c.n ipk A ∧ st.ents[ipk]? = some (false, dPrf c.n)))

/-- A structured challenger entry at `b`. -/
def HasS (st : St) (b : Adrs) : Prop := ∃ (d : Nat) (r : SReq) (j : Nat), StructReq c st d r b ∧ st.ents[j]? = some (false, r)

/-- Every ancestor of `A` has a structured challenger entry. -/
def AncCov (st : St) (A : Adrs) : Prop := ∀ b, AncOf (params c.v) A b → HasS c st b

/-- Provenance of a handle: if it is a canonical challenger entry, every ancestor of its
    address has already been materialized by the challenger. -/
def AncOK (st : St) (h : Nat) : Prop := ∀ A, EntAt c st h A → AncCov c st A

/-- The structural invariant. -/
def InvS (st : St) : Prop :=
  (st.ents[0]? = some (false, coin c.n 0) ∧ st.ents[1]? = some (false, coin c.n 1) ∧
    st.ents[2]? = some (false, coin c.n 2)) ∧
  (∀ (a : Nat) (qa : SReq), st.ents[a]? = some (true, qa) → qa.hids = []) ∧
  (∀ i ∈ st.rev, i < st.ents.length ∧ ¬ Prot st i) ∧
  (∀ (i : Nat) (r : SReq), st.ents[i]? = some (false, r) → i < 3 ∨ FamOK c st r) ∧
  DistK 3 c.t st ∧
  (∀ i ∈ st.rev, AncOK c st i)

/-- What a single step needs. -/
def StepOK (stp : St × Ev) : Prop :=
  match stp.2 with
  | .c r => FamOK c stp.1 r
  | .r x => ∀ h ∈ shids x, h < stp.1.ents.length ∧ ¬ Prot stp.1 h ∧ AncOK c stp.1 h
  | .a _ => True

def StableS (P : St → Prop) : Prop := ∀ st st', InvS c st → Grow2 st st' → P st → P st'

/-- No disagreement among the first `s` steps of a trace. -/
def NoDisTo (t : List Nat) (tr : List (St × Ev)) (s : Nat) : Prop :=
  ∀ (s' : Nat) (stp' : St × Ev), s' < s → tr[s']? = some stp' → dis t stp' = false

/-- The structural judgment: every pre-step state reached without a disagreement
    satisfies `InvS` and the step's obligation; on a disagreement-free run the end
    state satisfies `InvS` and `Q`. -/
def JS {α : Type} (P : Prog α) (P0 : St → Prop) (Q : α → St → Prop) : Prop :=
  ∀ st, InvS c st → P0 st →
    (∀ (s : Nat) (stp : St × Ev), (strace c.t P st)[s]? = some stp → NoDisTo c.t (strace c.t P st) s →
      InvS c stp.1 ∧ Grow2 st stp.1 ∧ StepOK c stp) ∧
    ((∀ s ∈ strace c.t P st, dis c.t s = false) →
      InvS c (xrun false c.t P st).2 ∧ Grow2 st (xrun false c.t P st).2 ∧
        Q (xrun false c.t P st).1 (xrun false c.t P st).2)
end

/-! Monotonicity. -/

section
variable {c : Ctx}

theorem structReq_mono {st st' : St} (hg : Grow2 st st') :
    ∀ (d : Nat) (r : SReq) (A : Adrs), StructReq c st d r A → StructReq c st' d r A
  | 0, _, _, h => h
  | d+1, r, A, ⟨hA, hk, hD, itk, hs, hr, hitk, hl, hh⟩ => by
    refine ⟨hA, hk, hD, itk, hs, hr, grow_get hg hitk, hl, fun k hk' => ?_⟩
    obtain ⟨h, hhk, hK⟩ := hh k hk'
    refine ⟨h, hhk, ?_⟩
    revert hK
    cases (kids (params c.v) A)[k]? with
    | none => exact id
    | some K =>
      cases K with
      | th B =>
        rintro ⟨r', h1, h2⟩
        exact ⟨r', structReq_mono hg d r' B h1, grow_get hg h2⟩
      | pf B =>
        rintro ⟨ipk, h1, h2, h3⟩
        exact ⟨ipk, grow_get hg h1, grow_get hg h2, h3⟩

theorem kidAt_mono {st st' : St} (hg : Grow2 st st') {d h : Nat} {K : Kid} (hk : KidAt c st d h K) :
    KidAt c st' d h K := by
  cases K with
  | th B =>
    obtain ⟨r', h1, h2⟩ := hk
    exact ⟨r', structReq_mono hg d r' B h1, grow_get hg h2⟩
  | pf B =>
    obtain ⟨ipk, h1, h2, h3⟩ := hk
    exact ⟨ipk, grow_get hg h1, grow_get hg h2, h3⟩

theorem kidOK_mono {st st' : St} (hg : Grow2 st st') {h : Nat} {K : Kid} (hk : KidOK c st h K) :
    KidOK c st' h K := let ⟨d, hd⟩ := hk; ⟨d, kidAt_mono hg hd⟩

theorem famOK_mono {st st' : St} (hg : Grow2 st st') {r : SReq} (h : FamOK c st r) : FamOK c st' r := by
  rcases h with h | h | h | ⟨ipk, A, h1, h2, h3⟩ | ⟨dk, m, h1, h2⟩ | ⟨iR, m, h1, dk, h2, h3, h4⟩ | ⟨d, A, h1⟩
  · exact Or.inl h
  · exact Or.inr (Or.inl h)
  · exact Or.inr (Or.inr (Or.inl h))
  · exact Or.inr (Or.inr (Or.inr (Or.inl ⟨ipk, A, h1, grow_get hg h2, h3⟩)))
  · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inl ⟨dk, m, h1, grow_get hg h2⟩))))
  · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inl ⟨iR, m, h1, dk, grow_get hg h2, grow_get hg h3,
      fun i hi => ⟨(h4 i hi).1, by obtain ⟨⟨L, hL⟩, _⟩ := hg; rw [hL]; simp; have := (h4 i hi).2; omega⟩⟩)))))
  · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr ⟨d, A, structReq_mono hg d _ A h1⟩)))))

theorem prot_mono {st st' : St} (hg : Grow2 st st') {i : Nat} (hi : i < st.ents.length) :
    Prot st' i ↔ Prot st i := by
  obtain ⟨⟨L, hL⟩, _⟩ := hg
  have e : st'.ents[i]? = st.ents[i]? := by rw [hL, List.getElem?_append_left hi]
  simp only [Prot, e]

theorem hasS_mono {st st' : St} (hg : Grow2 st st') {b : Adrs} (h : HasS c st b) : HasS c st' b :=
  let ⟨d, r, j, h1, h2⟩ := h; ⟨d, r, j, structReq_mono hg d r b h1, grow_get hg h2⟩

theorem ancCov_mono {st st' : St} (hg : Grow2 st st') {A : Adrs} (h : AncCov c st A) : AncCov c st' A :=
  fun b hb => hasS_mono hg (h b hb)

/-- A PRF-shaped challenger request is keyed by SK.prf's entry or by the message-PRF key's. -/
theorem famOK_prf_key {st : St} {ipk : Nat} {A : Adrs} (hF : FamOK c st (prfReq c.n ipk A)) :
    st.ents[ipk]? = some (false, dPrf c.n) ∨ st.ents[ipk]? = some (false, dReq c.n) := by
  rcases hF with h | h | h | ⟨ipk', A', h1, h2, _⟩ | ⟨dk, m, h1, h2⟩ | ⟨iR, m, h1, _⟩ | ⟨d, B, h1⟩
  · simp [prfReq, dTk] at h
  · simp [prfReq, dPrf] at h
  · simp [prfReq, dReq] at h
  · have := congrArg SReq.key h1
    simp [prfReq] at this
    subst this; exact Or.inl h2
  · have := congrArg SReq.key h1
    simp [prfReq, rqOf] at this
    subst this; exact Or.inr h2
  · simp [prfReq, hqOf] at h1
  · cases d with
    | zero => exact h1.elim
    | succ d =>
      obtain ⟨_, _, _, _, _, hr, _⟩ := h1
      have := congrArg SReq.input hr
      simp [prfReq] at this

/-- Entries below the length keep their address shape. -/
theorem entAt_down {st st' : St} (hI : InvS c st) (hg : Grow2 st st') {h : Nat} (hh : h < st.ents.length)
    {A : Adrs} (he : EntAt c st' h A) : EntAt c st h A := by
  obtain ⟨⟨L, hL⟩, _⟩ := hg
  have e : st'.ents[h]? = st.ents[h]? := by rw [hL, List.getElem?_append_left hh]
  obtain ⟨r, hr, hA⟩ := he
  rw [e] at hr
  refine ⟨r, hr, ?_⟩
  rcases hA with hA | ⟨hA, ipk, rfl, hk⟩
  · exact Or.inl hA
  · refine Or.inr ⟨hA, ipk, rfl, ?_⟩
    rcases hI.2.2.2.1 h _ hr with h3 | hF
    · exfalso
      rcases h with _ | _ | _ | h
      · rw [hI.1.1] at hr; simp [coin, prfReq] at hr
      · rw [hI.1.2.1] at hr; simp [coin, prfReq] at hr
      · rw [hI.1.2.2] at hr; simp [coin, prfReq] at hr
      · omega
    · rcases famOK_prf_key hF with h1 | h1
      · exact h1
      · exfalso
        rw [hL, List.getElem?_append_left (lt_entry h1), h1] at hk
        simp [dReq, dPrf] at hk

theorem ancOK_mono {st st' : St} (hI : InvS c st) (hg : Grow2 st st') {h : Nat} (hh : h < st.ents.length)
    (ha : AncOK c st h) : AncOK c st' h :=
  fun A he => ancCov_mono hg (ha A (entAt_down hI hg hh he))

theorem thAt_of_struct {st : St} : ∀ {d : Nat} {r : SReq} {A : Adrs}, StructReq c st d r A → ThAt c r A
  | 0, _, _, h => h.elim
  | _+1, _, _, ⟨hA, _, _, itk, hs, hr, _⟩ => ⟨hA, itk, hs, hr⟩

theorem entAt_of_kidAt {st : St} {d h : Nat} {K : Kid} (hk : KidAt c st d h K) : EntAt c st h K.adr := by
  cases K with
  | th B => obtain ⟨r', h1, h2⟩ := hk; exact ⟨r', h2, Or.inl (thAt_of_struct h1)⟩
  | pf B => obtain ⟨ipk, h1, h2, h3⟩ := hk; exact ⟨_, h2, Or.inr ⟨h3, ipk, rfl, h1⟩⟩

theorem hid_shids : ∀ {x : List SV} {k h w : Nat}, x[k]? = some (.hid h w) → h ∈ shids x
  | [], _, _, _, hx => by simp at hx
  | v :: x, 0, h, w, hx => by
    simp at hx; subst hx; simp [shids]
  | v :: x, k+1, h, w, hx => by
    simp at hx
    have := hid_shids hx
    cases v <;> simp [shids, this]

/-- An open structured request is covered: its first child is a revealed handle, so by
    provenance the child's ancestors, the request's own address first, are materialized. -/
theorem struct_open_cov {st : St} (hI : InvS c st) {d : Nat} {r : SReq} {A : Adrs}
    (hS : StructReq c st d r A) (hom : ∀ h ∈ r.hids, h ∈ st.rev) : HasS c st A ∧ AncCov c st A := by
  cases d with
  | zero => exact hS.elim
  | succ d =>
  obtain ⟨_, hkn, hD, itk, hs, rfl, _, hl, hh⟩ := hS
  obtain ⟨K, hK0⟩ : ∃ K, (kids (params c.v) A)[0]? = some K := by
    cases hkk : kids (params c.v) A with
    | nil => exact absurd hkk hkn
    | cons K _ => exact ⟨K, rfl⟩
  have hmem : K ∈ kids (params c.v) A := List.mem_of_getElem? hK0
  have h0 : 0 < hs.length := by rw [hl]; exact (List.getElem?_eq_some_iff.mp hK0).1
  obtain ⟨h0', hx0, hK⟩ := hh 0 h0
  rw [hK0] at hK
  have hrev0 : h0' ∈ st.rev := hom h0' (by
    show h0' ∈ shids [SV.hid itk 32] ++ shids (SV.lit A.bytes :: hs)
    simp only [shids, List.mem_append]
    exact Or.inr (hid_shids hx0))
  have hent : EntAt c st h0' K.adr := by
    cases K with
    | th B => obtain ⟨r', h1, h2⟩ := hK; exact ⟨r', h2, Or.inl (thAt_of_struct h1)⟩
    | pf B => obtain ⟨ipk, h1, h2, h3⟩ := hK; exact ⟨_, h2, Or.inr ⟨h3, ipk, rfl, h1⟩⟩
  have hcov := hI.2.2.2.2.2 h0' hrev0 K.adr hent
  have hpar := hD K hmem
  exact ⟨hcov A (AncOf.one hpar), fun b hb => hcov b (AncOf.up hpar hb)⟩

end

/-! Steps. -/

section
variable {c : Ctx}

theorem coin_prot {st : St} (h0 : st.ents[0]? = some (false, coin c.n 0)) : Prot st 0 :=
  ⟨_, h0, Or.inl (by simp [coin, SReq.hids, shids])⟩

theorem coin1_prot {st : St} (h1 : st.ents[1]? = some (false, coin c.n 1)) : Prot st 1 :=
  ⟨_, h1, Or.inr (by simp [coin, SReq.hids, shids])⟩

/-- An adversary lookup that answers from an open challenger entry keeps provenance:
    a thash entry is structured, hence covered (`struct_open_cov`); a PRF entry is never open. -/
theorem ancOK_open {st : St} (hI : InvS c st) {i : Nat} {e : Bool × SReq} (he : st.ents[i]? = some e)
    (ho : isOpen st.rev e.2 = true) : AncOK c st i := by
  intro A ⟨r, hr, hA⟩
  rw [he] at hr
  obtain rfl := Option.some.inj hr
  have hom := open_mem ho
  rcases hA with ⟨hR, itk, hs, rfl⟩ | ⟨_, ipk, rfl, hk⟩
  · rcases hI.2.2.2.1 i _ he with h3 | hF
    · exfalso
      rcases i with _ | _ | _ | i
      · rw [hI.1.1] at he; simp [coin] at he
      · rw [hI.1.2.1] at he; simp [coin] at he
      · rw [hI.1.2.2] at he; simp [coin] at he
      · omega
    rcases hF with h | h | h | ⟨_, _, h, _⟩ | ⟨_, _, h, _⟩ | ⟨_, _, h, _⟩ | ⟨d, A', hS⟩
    · simp [dTk] at h
    · simp [dPrf] at h
    · simp [dReq] at h
    · have := congrArg SReq.input h; simp [prfReq] at this
    · have := congrArg SReq.input h; simp [rqOf] at this
    · simp [hqOf] at h
    have hA' : A' = A := by
      cases d with
      | zero => exact hS.elim
      | succ d =>
        obtain ⟨hA', _, _, itk', hs', hr', _⟩ := hS
        have := congrArg SReq.input hr'
        simp only [List.cons.injEq, SV.lit.injEq] at this
        exact adrs_bytes_injective A' A hA' hR this.1.symm
    subst hA'
    exact (struct_open_cov hI hS hom).2
  · exfalso
    have hP : Prot st ipk := ⟨_, hk, Or.inl (by simp [dPrf, SReq.hids, shids])⟩
    exact (hI.2.2.1 ipk (hom ipk (by simp [prfReq, SReq.hids, shids]))).2 hP

theorem stepS_askC (st : St) (r : SReq) (hI : InvS c st) (hF : FamOK c st r) (hd : dis c.t (st, .c r) = false) :
    InvS c (addC st (firstIdx (mC false c.t st.rev r) st.ents) r) := by
  have hD' := distK_askC hI.2.2.2.2.1 hd
  generalize hi : firstIdx (mC false c.t st.rev r) st.ents = i at hD'
  by_cases hl : i < st.ents.length
  · have : addC st i r = st := by simp [addC, hl]
    rw [this]; exact hI
  · have ha : addC st i r = ⟨st.ents ++ [(false, r)], st.rev⟩ := by simp [addC, hl]
    rw [ha] at hD' ⊢
    have hx : Grow2 st ⟨st.ents ++ [(false, r)], st.rev⟩ := ⟨⟨_, rfl⟩, fun _ h => h⟩
    obtain ⟨hc, hadv, hrev, hfam, -, hanc⟩ := id hI
    refine ⟨⟨grow_get hx hc.1, grow_get hx hc.2.1, grow_get hx hc.2.2⟩, ?_, ?_, ?_, hD',
      fun j hj => ancOK_mono hI hx (hrev j hj).1 (hanc j hj)⟩
    · intro a qa he
      rcases fr_snoc he with ⟨_, he⟩ | ⟨_, he⟩
      · exact hadv a qa he
      · cases he
    · intro j hj
      obtain ⟨h1, h2⟩ := hrev j hj
      refine ⟨by simp; omega, fun hp => h2 ((prot_mono hx h1).mp hp)⟩
    · intro j r' he
      rcases fr_snoc he with ⟨_, he⟩ | ⟨_, he⟩
      · rcases hfam j r' he with h | h
        · exact Or.inl h
        · exact Or.inr (famOK_mono hx h)
      · obtain rfl : r' = r := (Prod.mk.inj he).2
        exact Or.inr (famOK_mono hx hF)

theorem stepS_askA (st : St) (q : Request) (hI : InvS c st) (hd : dis c.t (st, .a q) = false) :
    InvS c (addA st (firstIdx (mA false c.t st.rev q) st.ents) q) := by
  have hD' := distK_askA hI.2.2.2.2.1 hd
  generalize hi : firstIdx (mA false c.t st.rev q) st.ents = i at hD'
  obtain ⟨hc, hadv, hrev, hfam, -, hanc⟩ := id hI
  by_cases hl : i < st.ents.length
  · have ha : addA st i q = ⟨st.ents, i :: st.rev⟩ := by simp [addA, hl]
    rw [ha] at hD' ⊢
    have hx : Grow2 st ⟨st.ents, i :: st.rev⟩ := ⟨⟨[], by simp⟩, fun _ h => List.mem_cons_of_mem _ h⟩
    obtain ⟨e, he, hp⟩ := fr_hit _ st.ents (hi ▸ hl)
    rw [hi] at he
    simp only [mA, Bool.false_eq_true, if_false, Bool.and_eq_true] at hp
    refine ⟨hc, hadv, ?_, fun j r' he => (hfam j r' he).imp id (famOK_mono hx), hD', ?_⟩
    rotate_left
    · intro j hj
      simp only [List.mem_cons] at hj
      rcases hj with rfl | hj
      · exact ancOK_mono hI hx hl (ancOK_open hI he hp.1)
      · exact ancOK_mono hI hx (hrev j hj).1 (hanc j hj)
    intro j hj
    simp only [List.mem_cons] at hj
    rcases hj with rfl | hj
    · refine ⟨hl, ?_⟩
      rintro ⟨e2, h2, h3⟩
      simp only at h2
      obtain rfl : e = e2 := Option.some.inj (he.symm.trans h2)
      have ho := open_mem hp.1
      rcases h3 with h3 | h3
      · exact (hrev 0 (ho 0 h3)).2 (coin_prot hc.1)
      · exact (hrev 1 (ho 1 h3)).2 (coin1_prot hc.2.1)
    · obtain ⟨h1, h2⟩ := hrev j hj
      exact ⟨h1, h2⟩
  · have hi' : i = st.ents.length := Nat.le_antisymm (hi ▸ firstIdx_le _ _) (Nat.le_of_not_lt hl)
    have ha : addA st i q = ⟨st.ents ++ [(true, lift q)], st.ents.length :: st.rev⟩ := by
      simp [addA, hi']
    rw [ha] at hD' ⊢
    have hx : Grow2 st ⟨st.ents ++ [(true, lift q)], st.ents.length :: st.rev⟩ :=
      ⟨⟨_, rfl⟩, fun _ h => List.mem_cons_of_mem _ h⟩
    refine ⟨⟨grow_get hx hc.1, grow_get hx hc.2.1, grow_get hx hc.2.2⟩, ?_, ?_, ?_, hD', ?_⟩
    rotate_left 3
    · intro j hj
      simp only [List.mem_cons] at hj
      rcases hj with rfl | hj
      · rintro A ⟨r, hr, -⟩
        rw [List.getElem?_append_right (Nat.le_refl _)] at hr
        simp at hr
      · exact ancOK_mono hI hx (hrev j hj).1 (hanc j hj)
    · intro a qa he
      rcases fr_snoc he with ⟨_, he⟩ | ⟨_, he⟩
      · exact hadv a qa he
      · rw [(Prod.mk.inj he).2]; exact lift_hids q
    · intro j hj
      simp only [List.mem_cons] at hj
      rcases hj with rfl | hj
      · refine ⟨by simp, ?_⟩
        rintro ⟨e2, h2, h3⟩
        simp at h2
        subst h2
        rw [lift_hids] at h3; simp at h3
      · obtain ⟨h1, h2⟩ := hrev j hj
        exact ⟨by simp; omega, fun hp => h2 ((prot_mono hx h1).mp hp)⟩
    · intro j r' he
      rcases fr_snoc he with ⟨_, he⟩ | ⟨_, he⟩
      · exact (hfam j r' he).imp id (famOK_mono hx)
      · cases (Prod.mk.inj he).1

theorem stepS_reveal (st : St) (x : List SV) (hI : InvS c st)
    (hx : ∀ h ∈ shids x, h < st.ents.length ∧ ¬ Prot st h ∧ AncOK c st h) :
    InvS c ⟨st.ents, shids x ++ st.rev⟩ := by
  obtain ⟨hc, hadv, hrev, hfam, hD, hanc⟩ := id hI
  have hg : Grow2 st ⟨st.ents, shids x ++ st.rev⟩ := ⟨⟨[], by simp⟩, fun _ h => List.mem_append_right _ h⟩
  refine ⟨hc, hadv, ?_, fun j r' he => (hfam j r' he).imp id (famOK_mono hg), hD, ?_⟩
  · intro j hj
    rcases List.mem_append.mp hj with h | h
    · exact ⟨(hx j h).1, (hx j h).2.1⟩
    · exact hrev j h
  · intro j hj
    rcases List.mem_append.mp hj with h | h
    · exact ancOK_mono hI hg (hx j h).1 (hx j h).2.2
    · exact ancOK_mono hI hg (hrev j h).1 (hanc j h)

end



/-! The judgment's rules. -/

section
variable {c : Ctx}

theorem stableS_and {P Q : St → Prop} (hP : StableS c P) (hQ : StableS c Q) :
    StableS c (fun st => P st ∧ Q st) :=
  fun st st' hI hx h => ⟨hP st st' hI hx h.1, hQ st st' hI hx h.2⟩

theorem stableS_true : StableS c (fun _ => True) := fun _ _ _ _ _ => trivial
theorem stableS_pure (P : Prop) : StableS c (fun _ => P) := fun _ _ _ _ h => h
theorem stableS_ent (i : Nat) (e : Bool × SReq) : StableS c (fun st => st.ents[i]? = some e) :=
  fun _ _ _ hg h => grow_get hg h
theorem stableS_kid (h : Nat) (K : Kid) : StableS c (fun st => KidOK c st h K) :=
  fun _ _ _ hg hk => kidOK_mono hg hk

theorem noDis_nil (t : List Nat) (tr : List (St × Ev)) : NoDisTo t tr 0 := fun _ _ h => absurd h (by omega)

theorem noDis_all {t : List Nat} {tr : List (St × Ev)} (h : ∀ s ∈ tr, dis t s = false) (s : Nat) :
    NoDisTo t tr s := fun _ stp _ hs => h stp (mem_of_getElem? hs)

theorem noDis_cons {t : List Nat} {x : St × Ev} {tr : List (St × Ev)} {s : Nat}
    (h : NoDisTo t (x :: tr) (s+1)) : dis t x = false ∧ NoDisTo t tr s :=
  ⟨h 0 x (by omega) rfl, fun s' stp hs' hst => h (s'+1) stp (by omega) (by simpa using hst)⟩

theorem JS.pure' {α : Type} {a : α} {P0 : St → Prop} {Q : α → St → Prop}
    (h : ∀ st, InvS c st → P0 st → Q a st) : JS c (.done a) P0 Q :=
  fun st hI hp => ⟨fun s stp hs => by simp [strace] at hs, fun _ => ⟨hI, grow_refl st, h st hI hp⟩⟩

theorem JS.bind' {α β : Type} {P : Prog α} {f : α → Prog β} {P0 : St → Prop} {Q : α → St → Prop}
    {R : β → St → Prop} (hP : JS c P P0 Q) (hf : ∀ a, JS c (f a) (fun st => P0 st ∧ Q a st) R)
    (hs : StableS c P0) : JS c (P.bind f) P0 R := by
  intro st hI hp
  obtain ⟨hT1, hE1⟩ := hP st hI hp
  refine ⟨fun s stp hsp hnd => ?_, fun hnd => ?_⟩
  · rw [strace_bind] at hsp hnd
    by_cases hlt : s < (strace c.t P st).length
    · rw [List.getElem?_append_left hlt] at hsp
      exact hT1 s stp hsp (fun s' stp' hs' hst => hnd s' stp' hs' (by
        rw [List.getElem?_append_left (by have := (List.getElem?_eq_some_iff.mp hst).1; omega)]; exact hst))
    · have hP1 : ∀ x ∈ strace c.t P st, dis c.t x = false := by
        intro x hx
        obtain ⟨s', hs'⟩ := List.mem_iff_getElem?.mp hx
        have hlt' := (List.getElem?_eq_some_iff.mp hs').1
        exact hnd s' x (by omega) (by rw [List.getElem?_append_left hlt']; exact hs')
      obtain ⟨hI1, hg1, hq1⟩ := hE1 hP1
      rw [List.getElem?_append_right (by omega)] at hsp
      obtain ⟨hT2, -⟩ := hf _ _ hI1 ⟨hs _ _ hI hg1 hp, hq1⟩
      obtain ⟨a1, a2, a3⟩ := hT2 _ stp hsp (fun s' stp' hs' hst => hnd (s' + (strace c.t P st).length) stp'
        (by omega) (by rw [List.getElem?_append_right (by omega)]; simpa using hst))
      exact ⟨a1, grow_trans hg1 a2, a3⟩
  · rw [strace_bind] at hnd
    obtain ⟨hI1, hg1, hq1⟩ := hE1 (fun x hx => hnd x (List.mem_append_left _ hx))
    obtain ⟨-, hE2⟩ := hf _ _ hI1 ⟨hs _ _ hI hg1 hp, hq1⟩
    obtain ⟨hI2, hg2, hq2⟩ := hE2 (fun x hx => hnd x (List.mem_append_right _ hx))
    rw [xrun_bind]
    exact ⟨hI2, grow_trans hg1 hg2, hq2⟩

theorem JS.bind {α β : Type} {P : Prog α} {f : α → Prog β} {P0 : St → Prop} {Q : α → St → Prop}
    {R : β → St → Prop} (hP : JS c P P0 Q) (hf : ∀ a, JS c (f a) (fun st => P0 st ∧ Q a st) R)
    (hs : StableS c P0) : JS c (P >>= f) P0 R := JS.bind' hP hf hs

theorem JS.conseq {α : Type} {P : Prog α} {P0 P0' : St → Prop} {Q Q' : α → St → Prop}
    (h : JS c P P0 Q) (h1 : ∀ st, InvS c st → P0' st → P0 st) (h2 : ∀ a st, Q a st → Q' a st) :
    JS c P P0' Q' := fun st hI hp =>
  let ⟨a, b⟩ := h st hI (h1 st hI hp)
  ⟨a, fun hnd => let ⟨x, y, z⟩ := b hnd; ⟨x, y, h2 _ _ z⟩⟩

theorem JS.ite {α : Type} {b : Prop} [Decidable b] {P₁ P₂ : Prog α} {P0 : St → Prop} {Q : α → St → Prop}
    (h₁ : b → JS c P₁ P0 Q) (h₂ : ¬b → JS c P₂ P0 Q) : JS c (if b then P₁ else P₂) P0 Q := by
  by_cases h : b
  · simp only [h, if_true]; exact h₁ h
  · simp only [h, if_false]; exact h₂ h

theorem JS.reveal {α : Type} {x : List SV} {k : Bytes → Prog α} {P0 : St → Prop} {Q : α → St → Prop}
    (hx : ∀ st, InvS c st → P0 st → ∀ h ∈ shids x, h < st.ents.length ∧ ¬ Prot st h ∧ AncOK c st h)
    (hk : JS c (k (sres c.t x)) P0 Q) (hs : StableS c P0) : JS c (.reveal x k) P0 Q := by
  intro st hI hp
  have hI1 := stepS_reveal st x hI (hx st hI hp)
  have hg : Grow2 st ⟨st.ents, shids x ++ st.rev⟩ := ⟨⟨[], by simp⟩, fun _ h => List.mem_append_right _ h⟩
  obtain ⟨hT, hE⟩ := hk _ hI1 (hs _ _ hI hg hp)
  refine ⟨fun s stp hsp hnd => ?_, fun hnd => ?_⟩
  · cases s with
    | zero =>
      simp only [strace, List.getElem?_cons_zero, Option.some.injEq] at hsp
      subst hsp
      exact ⟨hI, grow_refl st, hx st hI hp⟩
    | succ s =>
      simp only [strace] at hsp hnd
      simp only [List.getElem?_cons_succ] at hsp
      obtain ⟨a1, a2, a3⟩ := hT s stp hsp (noDis_cons hnd).2
      exact ⟨a1, grow_trans hg a2, a3⟩
  · simp only [strace, List.mem_cons, forall_eq_or_imp] at hnd
    obtain ⟨a1, a2, a3⟩ := hE hnd.2
    exact ⟨a1, grow_trans hg a2, a3⟩

theorem JS.askA {α : Type} {q : Request} {k : Bytes → Prog α} {P0 : St → Prop} {Q : α → St → Prop}
    (hk : ∀ st, InvS c st → P0 st →
      JS c (k (be q.outLen (c.t.getD (firstIdx (mA false c.t st.rev q) st.ents) 0)))
        (fun st' => st' = addA st (firstIdx (mA false c.t st.rev q) st.ents) q) Q) :
    JS c (.askA q k) P0 Q := by
  intro st hI hp
  have hx1 : Grow2 st (addA st (firstIdx (mA false c.t st.rev q) st.ents) q) := by
    have := xrun_grow c.t (.askA q (fun _ => .done ())) st
    simpa [xrun] using this
  refine ⟨fun s stp hsp hnd => ?_, fun hnd => ?_⟩
  · cases s with
    | zero =>
      simp only [strace, List.getElem?_cons_zero, Option.some.injEq] at hsp
      subst hsp
      exact ⟨hI, grow_refl st, trivial⟩
    | succ s =>
      simp only [strace] at hsp hnd
      simp only [List.getElem?_cons_succ] at hsp
      obtain ⟨hd0, hnd'⟩ := noDis_cons hnd
      have hI1 := stepS_askA (c := c) st q hI hd0
      obtain ⟨a1, a2, a3⟩ := (hk st hI hp _ hI1 rfl).1 s stp hsp hnd'
      exact ⟨a1, grow_trans hx1 a2, a3⟩
  · simp only [strace, List.mem_cons, forall_eq_or_imp] at hnd
    have hI1 := stepS_askA (c := c) st q hI hnd.1
    obtain ⟨a1, a2, a3⟩ := (hk st hI hp _ hI1 rfl).2 hnd.2
    exact ⟨a1, grow_trans hx1 a2, a3⟩

theorem JS.ask (r : SReq) {P0 : St → Prop} {Q : SB → St → Prop}
    (hF : ∀ st, InvS c st → P0 st → FamOK c st r)
    (hq : ∀ st, InvS c st → P0 st → InvS c (addC st (firstIdx (mC false c.t st.rev r) st.ents) r) →
      Q [.hid (firstIdx (mC false c.t st.rev r) st.ents) r.outLen]
        (addC st (firstIdx (mC false c.t st.rev r) st.ents) r)) :
    JS c (sAsk r) P0 Q := by
  intro st hI hp
  refine ⟨fun s stp hsp _ => ?_, fun hnd => ?_⟩
  · cases s with
    | zero =>
      simp only [sAsk, strace, List.getElem?_cons_zero, Option.some.injEq] at hsp
      subst hsp
      exact ⟨hI, grow_refl st, hF st hI hp⟩
    | succ s => simp [sAsk, strace] at hsp
  · simp only [sAsk, strace, List.mem_cons, forall_eq_or_imp] at hnd
    have hI1 := stepS_askC st r hI (hF st hI hp) hnd.1
    exact ⟨hI1, grow_addC st r, hq st hI hp hI1⟩

theorem JS.loop {ι σ : Type} (l : List ι) (f : ι → σ → Prog (ForInStep σ)) (P0 : St → Prop)
    (L : σ → St → Prop) (hs : StableS c P0) (hL : ∀ s, StableS c (L s))
    (hf : ∀ i ∈ l, ∀ s, JS c (f i s) (fun st => P0 st ∧ L s st) (SL L)) :
    ∀ s, JS c (forIn l s f) (fun st => P0 st ∧ L s st) L := by
  induction l with
  | nil => intro s; exact JS.pure' (fun st _ h => h.2)
  | cons a l ih =>
    intro s
    rw [List.forIn_cons]
    refine JS.bind (hf a (by simp) s) (fun x => ?_) (stableS_and hs (hL s))
    cases x with
    | done b => exact JS.pure' (fun st _ h => h.2)
    | yield b =>
      exact JS.conseq (ih (fun i hi => hf i (by simp [hi])) b) (fun st _ h => ⟨h.1.1, h.2⟩) (fun _ _ h => h)

theorem JS.loop' {ι σ : Type} (l : List ι) (f : ι → σ → Prog (ForInStep σ)) {P0 : St → Prop}
    (L : σ → St → Prop) (hs : StableS c P0) (hL : ∀ s, StableS c (L s)) (s : σ)
    (h0 : ∀ st, InvS c st → P0 st → L s st)
    (hf : ∀ i ∈ l, ∀ s, JS c (f i s) (fun st => P0 st ∧ L s st) (SL L)) :
    JS c (forIn l s f) P0 L :=
  JS.conseq (JS.loop l f P0 L hs hL hf s) (fun st hI h => ⟨h, h0 st hI h⟩) (fun _ _ h => h)

theorem JS.obtain {α : Type} {P : Prog α} {P0 : St → Prop} {Q : α → St → Prop} {v : SB} {w : Nat}
    {X : Nat → St → Prop} (h : ∀ i, v = [.hid i w] → JS c P (fun st => P0 st ∧ X i st) Q) :
    JS c P (fun st => P0 st ∧ ∃ i, v = [.hid i w] ∧ X i st) Q :=
  fun st hI ⟨hp, i, hv, hx⟩ => h i hv st hI ⟨hp, hx⟩

theorem JS.unit {P0 : St → Prop} : JS c (pure PUnit.unit : Prog PUnit) P0 (fun _ _ => True) :=
  JS.pure' (fun _ _ _ => trivial)

theorem JS.frame {α : Type} {P : Prog α} {P0 : St → Prop} {Q : α → St → Prop} (h : JS c P P0 Q)
    (hs : StableS c P0) : JS c P P0 (fun v st => P0 st ∧ Q v st) := fun st hI hp =>
  let ⟨a, b⟩ := h st hI hp
  ⟨a, fun hnd => let ⟨x, y, z⟩ := b hnd; ⟨x, y, hs _ _ hI y hp, z⟩⟩

theorem JS.assume {α : Type} {P : Prog α} {P0 : St → Prop} {Q : α → St → Prop} {X : Prop}
    (hX : ∀ st, InvS c st → P0 st → X) (h : X → JS c P P0 Q) : JS c P P0 Q :=
  fun st hI hp => h (hX st hI hp) st hI hp

end

/-! Fuel and uniqueness. -/

section
variable {c : Ctx}

theorem structReq_fuel {st : St} : ∀ (d d' : Nat) (r : SReq) (A : Adrs), d ≤ d' →
    StructReq c st d r A → StructReq c st d' r A
  | 0, _, _, _, _, h => h.elim
  | d+1, d'+1, r, A, hle, ⟨hA, hk, hD, itk, hs, hr, hitk, hl, hh⟩ => by
    refine ⟨hA, hk, hD, itk, hs, hr, hitk, hl, fun k hk' => ?_⟩
    obtain ⟨h, hhk, hK⟩ := hh k hk'
    refine ⟨h, hhk, ?_⟩
    revert hK
    cases (kids (params c.v) A)[k]? with
    | none => exact id
    | some K =>
      cases K with
      | th B =>
        rintro ⟨r', h1, h2⟩
        exact ⟨r', structReq_fuel d d' r' B (by omega) h1, h2⟩
      | pf B => exact id
  | d+1, 0, _, _, hle, _ => absurd hle (by omega)

theorem kidAt_fuel {st : St} {d d' h : Nat} {K : Kid} (hle : d ≤ d') (hk : KidAt c st d h K) :
    KidAt c st d' h K := by
  cases K with
  | th B =>
    obtain ⟨r', h1, h2⟩ := hk
    exact ⟨r', structReq_fuel d d' r' B hle h1, h2⟩
  | pf B => exact hk

theorem coin_res_mode {st : St} (hI : InvS c st) {i : Nat} {e : Bool × SReq} (hi : i < 3)
    (he : st.ents[i]? = some e) : (e.2.res c.t).mode = 999 := by
  rcases i with _ | _ | _ | i
  · rw [hI.1.1] at he; obtain rfl := Option.some.inj he; rfl
  · rw [hI.1.2.1] at he; obtain rfl := Option.some.inj he; rfl
  · rw [hI.1.2.2] at he; obtain rfl := Option.some.inj he; rfl
  · omega

/-- Two entries with one resolution that is not a coin's are one entry. -/
theorem idx_eq_of_res {st : St} (hI : InvS c st) {a b : Nat} {ea eb : Bool × SReq}
    (ha : st.ents[a]? = some ea) (hb : st.ents[b]? = some eb) (hres : ea.2.res c.t = eb.2.res c.t)
    (hm : (ea.2.res c.t).mode ≠ 999) : a = b := by
  rcases Nat.lt_trichotomy a b with h | h | h
  · by_cases h3 : 3 ≤ b
    · exact absurd hres (hI.2.2.2.2.1 a b ea eb h h3 ha hb)
    · exact absurd (hres ▸ coin_res_mode hI (by omega) hb) hm
  · exact h
  · by_cases h3 : 3 ≤ a
    · exact absurd hres.symm (hI.2.2.2.2.1 b a eb ea h h3 hb ha)
    · exact absurd (coin_res_mode hI (by omega) ha) hm

theorem dTk_unique {st : St} (hI : InvS c st) {a b : Nat} (ha : st.ents[a]? = some (false, dTk c.n))
    (hb : st.ents[b]? = some (false, dTk c.n)) : a = b :=
  idx_eq_of_res hI ha hb rfl (by simp [dTk, SReq.res])

theorem dPrf_unique {st : St} (hI : InvS c st) {a b : Nat} (ha : st.ents[a]? = some (false, dPrf c.n))
    (hb : st.ents[b]? = some (false, dPrf c.n)) : a = b :=
  idx_eq_of_res hI ha hb rfl (by simp [dPrf, SReq.res])

/-- Canonical uniqueness: structured requests at one address are one request. -/
theorem struct_unique {st : St} (hI : InvS c st) : ∀ (d d' : Nat) (r r' : SReq) (A : Adrs),
    StructReq c st d r A → StructReq c st d' r' A → r = r'
  | 0, _, _, _, _, h, _ => h.elim
  | _, 0, _, _, _, _, h => h.elim
  | d+1, d'+1, r, r', A, ⟨_, _, _, itk, hs, hr, hitk, hl, hh⟩, ⟨_, _, _, itk', hs', hr', hitk', hl', hh'⟩ => by
    subst hr hr'
    have hk : itk = itk' := dTk_unique hI hitk hitk'
    subst hk
    have hlen : hs.length = hs'.length := by rw [hl, hl']
    have hseq : hs = hs' := by
      apply List.ext_getElem? 
      intro k
      by_cases hk : k < hs.length
      · obtain ⟨h, hx, hK⟩ := hh k hk
        obtain ⟨h', hx', hK'⟩ := hh' k (by omega)
        rw [hx, hx']
        have hkk : k < (kids (params c.v) A).length := by omega
        revert hK hK'
        cases hkid : (kids (params c.v) A)[k]? with
        | none => intro hK; exact hK.elim
        | some K =>
          cases K with
          | th B =>
            rintro ⟨r1, h1, h2⟩ ⟨r1', h1', h2'⟩
            have := struct_unique hI d d' r1 r1' B h1 h1'
            subst this
            have hm : ((false, r1).2.res c.t).mode ≠ 999 := by
              cases d with
              | zero => exact h1.elim
              | succ d => obtain ⟨_, _, _, _, _, hrr, _⟩ := h1; subst hrr; simp [SReq.res]
            rw [idx_eq_of_res hI h2 h2' rfl hm]
          | pf B =>
            rintro ⟨ipk, h1, h2, _⟩ ⟨ipk', h1', h2', _⟩
            have := dPrf_unique hI h1 h1'
            subst this
            rw [idx_eq_of_res hI h2 h2' rfl (by simp [prfReq, SReq.res])]
      · rw [List.getElem?_eq_none (by omega), List.getElem?_eq_none (by omega)]
    rw [hseq]

end


section
variable {c : Ctx}

theorem ge3_of_res {st : St} (hI : InvS c st) {h : Nat} {e : Bool × SReq} (he : st.ents[h]? = some e)
    (hm : (e.2.res c.t).mode ≠ 999) : 3 ≤ h := by
  by_cases h3 : h < 3
  · exact absurd (coin_res_mode hI h3 he) hm
  · omega

theorem ge3_of_ent {st : St} (hI : InvS c st) {h : Nat} {r : SReq} (he : st.ents[h]? = some (false, r))
    (hm : r.mode ≠ 999) : 3 ≤ h := ge3_of_res hI he hm

theorem askS_closed (st : St) (r : SReq) (hI : InvS c st) (hc : ∃ h ∈ r.hids, h ∉ st.rev) :
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
        have := hI.2.1 i r' he
        rw [this] at hm; cases hm
      · have ha : addC st i r' = ⟨st.ents ++ [(false, r')], st.rev⟩ := by simp [addC, hl]
        rw [ha] at he
        rcases fr_snoc he with ⟨hh, _⟩ | ⟨_, he'⟩
        · exact hl hh
        · cases he'
  · exact absurd (open_mem ho.2 h hm) hnr

theorem askS_known {st : St} (hI : InvS c st) {r : SReq} (hr : r.mode ≠ 999) {j : Nat}
    (hj : st.ents[j]? = some (false, r)) : firstIdx (mC false c.t st.rev r) st.ents = j := by
  have h3 : 3 ≤ j := ge3_of_ent hI hj hr
  have hm : mC false c.t st.rev r (false, r) = true := by simp [mC]
  have hle : firstIdx (mC false c.t st.rev r) st.ents ≤ j := by
    refine Nat.le_of_not_lt (fun hlt => ?_)
    have := fr_before _ _ j _ hj hlt
    rw [hm] at this; cases this
  rcases Nat.lt_or_eq_of_le hle with hlt | heq
  · exfalso
    obtain ⟨e, he, hp⟩ := fr_hit (mC false c.t st.rev r) st.ents (Nat.lt_trans hlt (lt_entry hj))
    exact hI.2.2.2.2.1 _ j e (false, r) hlt h3 he hj (mC_false_true hp)
  · exact heq

end

/-! Requests: thash and PRF. -/

section
variable (c : Ctx)

/-- The inputs `x` are the canonical children of `A`, to depth `d`. -/
def InputAt (st : St) (d : Nat) (A : Adrs) (x : SB) : Prop :=
  A.InRange ∧ kids (params c.v) A ≠ [] ∧ x.length = (kids (params c.v) A).length ∧
  ∀ k, k < x.length → ∃ h, x[k]? = some (.hid h c.n) ∧ ∀ K, (kids (params c.v) A)[k]? = some K → KidAt c st d h K

end

section
variable {c : Ctx}

theorem kidOK_unique_th {st : St} (hI : InvS c st) {h h' : Nat} {A : Adrs}
    (hk : KidOK c st h (.th A)) (hk' : KidOK c st h' (.th A)) : h = h' := by
  obtain ⟨d, r, h1, h2⟩ := hk
  obtain ⟨d', r', h1', h2'⟩ := hk'
  have := struct_unique hI d d' r r' A h1 h1'
  subst this
  have hm : ((false, r).2.res c.t).mode ≠ 999 := by
    cases d with
    | zero => exact h1.elim
    | succ d => obtain ⟨_, _, _, _, _, hrr, _⟩ := h1; subst hrr; simp [SReq.res]
  exact idx_eq_of_res hI h2 h2' rfl hm

/-- A structured request's answer is its own challenger entry. With a closed handle the
    request is new or already held; open, its address is covered (`struct_open_cov`), so the
    challenger already holds a structured request there, which is this one (`struct_unique`). -/
theorem ask_struct {st : St} (hI : InvS c st) {d : Nat} {r : SReq} {A : Adrs} (hS : StructReq c st d r A) :
    (addC st (firstIdx (mC false c.t st.rev r) st.ents) r).ents[firstIdx (mC false c.t st.rev r) st.ents]? =
      some (false, r) := by
  by_cases ho : ∃ h ∈ r.hids, h ∉ st.rev
  · exact askS_closed st r hI ho
  · have hom : ∀ h ∈ r.hids, h ∈ st.rev := fun h hh => Classical.byContradiction (fun hn => ho ⟨h, hh, hn⟩)
    obtain ⟨d', r', j, hS', hj⟩ := (struct_open_cov hI hS hom).1
    obtain rfl := struct_unique hI d' d r' r A hS' hS
    have hm : r'.mode ≠ 999 := by
      cases d' with
      | zero => exact hS'.elim
      | succ d' => obtain ⟨_, _, _, _, _, hrr, _⟩ := hS'; subst hrr; simp
    rw [askS_known hI hm hj]
    have : addC st j r' = st := by simp [addC, lt_entry hj]
    rw [this]; exact hj

theorem js_thash (A : Adrs) (x : SB) (itk : Nat) (hD : DSMOK (params c.v) A) {P0 : St → Prop}
    (h : ∀ st, InvS c st → P0 st → st.ents[itk]? = some (false, dTk c.n) ∧ ∃ d, InputAt c st d A x) :
    JS c (sThash (params c.v) [.hid itk 32] A x) P0 (fun v st => ∃ i, v = [.hid i c.n] ∧ KidOK c st i (.th A)) := by
  have hstruct : ∀ st, InvS c st → P0 st → ∃ d, StructReq c st (d+1) ⟨1, "", [.hid itk 32], .lit A.bytes :: x, c.n⟩ A := by
    intro st hI hp
    obtain ⟨hitk, d, hA, hk, hl, hx⟩ := h st hI hp
    refine ⟨d, hA, hk, hD, itk, x, rfl, hitk, hl, fun k hk' => ?_⟩
    obtain ⟨hh, hxk, hK⟩ := hx k hk'
    refine ⟨hh, hxk, ?_⟩
    have hkk : k < (kids (params c.v) A).length := by omega
    cases hkid : (kids (params c.v) A)[k]? with
    | none => rw [List.getElem?_eq_none_iff] at hkid; omega
    | some K =>
      have := hK K hkid
      cases K with
      | th B => exact this
      | pf B => exact this
  refine JS.ask _ (fun st hI hp => ?_) (fun st hI hp _ => ?_)
  · obtain ⟨d, hd⟩ := hstruct st hI hp
    exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr ⟨d+1, A, hd⟩)))))
  · obtain ⟨d, hd⟩ := hstruct st hI hp
    exact ⟨_, rfl, d+1, _, structReq_mono (grow_addC st _) (d+1) _ A hd, ask_struct hI hd⟩

theorem js_prf (B : Adrs) (hB : B.InRange) (hk : B.kind = 5 ∨ B.kind = 6) (ipk : Nat) {P0 : St → Prop}
    (h : ∀ st, InvS c st → P0 st → st.ents[ipk]? = some (false, dPrf c.n)) :
    JS c (sPrf (params c.v) [.hid ipk 32] [.hid 2 c.n] B) P0
      (fun v st => ∃ i, v = [.hid i c.n] ∧ KidOK c st i (.pf B)) := by
  refine JS.ask (prfReq c.n ipk B) (fun st hI hp => ?_) (fun st hI hp _ => ?_)
  · exact Or.inr (Or.inr (Or.inr (Or.inl ⟨ipk, B, rfl, h st hI hp, hB, hk⟩)))
  · have hk := h st hI hp
    refine ⟨_, rfl, 0, ipk, grow_get (grow_addC st _) hk, askS_closed st _ hI ⟨ipk,
      by simp [prfReq, SReq.hids, shids], fun hr => (hI.2.2.1 ipk hr).2 ⟨_, hk, Or.inl (by simp [dPrf, SReq.hids, shids])⟩⟩, hB⟩

/-! WOTS chains. -/

/-- The canonical producer of the chain value after `j` steps on chain address `a`. -/
def chainKid (a : Adrs) (j : Nat) : Kid :=
  if j = 0 then .pf {a.setType 5 with keypair := a.keypair, chain := a.chain} else .th {a with hash := j - 1}

theorem kids_chain (p : Params) (a : Adrs) (ha : a.kind = 0) (s : Nat) :
    kids p {a with hash := s} = [chainKid a s] := by
  unfold kids chainKid
  cases s with
  | zero => simp [ha, Adrs.setType]
  | succ s => simp [ha]

theorem dsmOK_chain (p : Params) (a : Adrs) (ha : a.kind = 0) (s : Nat) (hs : s < 15) :
    DSMOK p {a with hash := s} := by
  intro K hK
  rw [kids_chain p a ha s] at hK
  simp only [List.mem_singleton] at hK
  subst hK
  unfold chainKid
  cases s with
  | zero => cases a; simp_all [Kid.adr, par, Adrs.setType]
  | succ s =>
    have h14 : s < 14 := by omega
    cases a; simp_all [Kid.adr, par]

/-- Chain-address coordinates in range. -/
def ChainR (a : Adrs) : Prop := a.kind = 0 ∧ a.layer < 256^4 ∧ a.tree < 256^8 ∧ a.keypair < 256^4 ∧ a.chain < 256^4

theorem js_chain (itk : Nat) (a : Adrs) (ha : ChainR a) : ∀ (steps start : Nat) (x : SB) {P0 : St → Prop},
    StableS c P0 → start + steps ≤ 15 →
    (∀ st, InvS c st → P0 st → st.ents[itk]? = some (false, dTk c.n) ∧
      ∃ d xh, x = [.hid xh c.n] ∧ KidAt c st d xh (chainKid a start)) →
    JS c (sChain (params c.v) [.hid itk 32] a x start steps) P0
      (fun y st => ∃ d yh, y = [.hid yh c.n] ∧ KidAt c st d yh (chainKid a (start+steps)))
  | 0, start, x, P0, _, _, h => JS.pure' (fun st hI hp => (h st hI hp).2)
  | steps+1, start, x, P0, hs, hb, h => by
    simp only [sChain]
    obtain ⟨hk0, hl, ht, hkp, hc⟩ := ha
    refine JS.bind (js_thash {a with hash := start} x itk (dsmOK_chain _ a hk0 start (by omega))
      (fun st hI hp => ?_)) (fun y => ?_) hs
    · obtain ⟨hitk, d, xh, hx, hK⟩ := h st hI hp
      refine ⟨hitk, d, ⟨hl, ht, by simp [hk0], hkp, hc, by simp; omega⟩, by simp [kids_chain _ a hk0],
        by simp [hx, kids_chain _ a hk0], fun k hk => ?_⟩
      subst hx
      simp at hk
      subst hk
      refine ⟨xh, rfl, fun K hK' => ?_⟩
      rw [kids_chain _ a hk0] at hK'
      simp at hK'
      subst hK'; exact hK
    · have hs' := stableS_and hs (fun st st' _ hg (h : ∃ i, y = [.hid i c.n] ∧ KidOK c st i (.th {a with hash := start})) =>
        let ⟨i, hi, hk⟩ := h; ⟨i, hi, kidOK_mono hg hk⟩)
      refine JS.conseq (js_chain itk a ⟨hk0, hl, ht, hkp, hc⟩ steps (start+1) y hs' (by omega) (fun st hI hp => ?_))
        (fun _ _ h => h) (fun _ _ h => by rw [show start + (steps+1) = start + 1 + steps by omega]; exact h)
      obtain ⟨i, hi, d, hd⟩ := hp.2
      refine ⟨(h st hI hp.1).1, d, i, hi, ?_⟩
      have : chainKid a (start+1) = .th {a with hash := start} := by simp [chainKid]
      rw [this]; exact hd

end


/-! Indexed loops. -/

section
variable {c : Ctx}

theorem JS.loopI {ι σ : Type} (l : List ι) (f : ι → σ → Prog (ForInStep σ)) {P0 : St → Prop}
    (L : Nat → σ → St → Prop) (hs : StableS c P0) (hL : ∀ k s, StableS c (L k s))
    (hf : ∀ k (hk : k < l.length) s, JS c (f l[k] s) (fun st => P0 st ∧ L k s st)
      (fun r st => ∃ s', r = .yield s' ∧ L (k+1) s' st)) :
    ∀ m k s, k + m = l.length → JS c (forIn (l.drop k) s f) (fun st => P0 st ∧ L k s st) (L l.length)
  | 0, k, s, hk => by
    rw [List.drop_eq_nil_of_le (by omega)]
    exact JS.pure' (fun st _ h => by rw [← show k = l.length by omega]; exact h.2)
  | m+1, k, s, hk => by
    have hlt : k < l.length := by omega
    rw [List.drop_eq_getElem_cons hlt, List.forIn_cons]
    refine JS.bind (hf k hlt s) (fun x => ?_) (stableS_and hs (hL k s))
    cases x with
    | done b => exact JS.pure' (fun st _ h => by obtain ⟨_, he, _⟩ := h.2; cases he)
    | yield b =>
      exact JS.conseq (JS.loopI l f L hs hL hf m (k+1) b (by omega))
        (fun st _ h => ⟨h.1.1, by obtain ⟨s', he, hl⟩ := h.2; cases he; exact hl⟩) (fun _ _ h => h)

theorem JS.loopI' {ι σ : Type} (l : List ι) (f : ι → σ → Prog (ForInStep σ)) {P0 : St → Prop}
    (L : Nat → σ → St → Prop) (hs : StableS c P0) (hL : ∀ k s, StableS c (L k s)) (s : σ)
    (h0 : ∀ st, InvS c st → P0 st → L 0 s st)
    (hf : ∀ k (hk : k < l.length) s, JS c (f l[k] s) (fun st => P0 st ∧ L k s st)
      (fun r st => ∃ s', r = .yield s' ∧ L (k+1) s' st)) :
    JS c (forIn l s f) P0 (L l.length) := by
  have := JS.loopI l f L hs hL hf l.length 0 s (by omega)
  rw [List.drop_zero] at this
  exact JS.conseq this (fun st hI h => ⟨h, h0 st hI h⟩) (fun _ _ h => h)

end


/-! WOTS. -/

section
variable {c : Ctx}

/-- A WOTS key address in range. -/
def WotsR (wa : Adrs) : Prop :=
  wa.kind = 0 ∧ wa.chain = 0 ∧ wa.hash = 0 ∧ wa.layer < 256^4 ∧ wa.tree < 256^8 ∧ wa.keypair < 256^4

/-- The compression address of a WOTS key. -/
def compA (wa : Adrs) : Adrs := {wa.setType 1 with keypair := wa.keypair}

/-- Chain values on positions `[0, k)`: the chain on position `j` after `D j` steps. -/
def ChainsAt (c : Ctx) (wa : Adrs) (D : Nat → Nat) (k : Nat) (v : SB) (st : St) : Prop :=
  ∃ d, v.length = k ∧ ∀ j, j < k → ∃ h, v[j]? = some (.hid h c.n) ∧ KidAt c st d h (chainKid {wa with chain := j} (D j))

theorem stable_chainsAt (wa : Adrs) (D : Nat → Nat) (k : Nat) (v : SB) : StableS c (ChainsAt c wa D k v) :=
  fun _ _ _ hg ⟨d, hl, hv⟩ => ⟨d, hl, fun j hj => let ⟨h, h1, h2⟩ := hv j hj; ⟨h, h1, kidAt_mono hg h2⟩⟩

theorem chainsAt_snoc {wa : Adrs} {D : Nat → Nat} {k : Nat} {v : SB} {st : St} {d yh : Nat}
    (hv : ChainsAt c wa D k v st) (hy : KidAt c st d yh (chainKid {wa with chain := k} (D k))) :
    ChainsAt c wa D (k+1) (v ++ [.hid yh c.n]) st := by
  obtain ⟨d0, hl, hv⟩ := hv
  refine ⟨max d0 d, by simp [hl], fun j hj => ?_⟩
  by_cases hjk : j < k
  · obtain ⟨h, h1, h2⟩ := hv j hjk
    exact ⟨h, by rw [List.getElem?_append_left (by omega)]; exact h1, kidAt_fuel (Nat.le_max_left _ _) h2⟩
  · have hj : j = k := by omega
    subst hj
    exact ⟨yh, by rw [List.getElem?_append_right (by omega)]; simp [hl], kidAt_fuel (Nat.le_max_right _ _) hy⟩

theorem chainR_of_wots {wa : Adrs} (hw : WotsR wa) {j : Nat} (hj : j < 256^4) : ChainR {wa with chain := j} := by
  obtain ⟨h1, _, _, h4, h5, h6⟩ := hw
  exact ⟨h1, h4, h5, h6, hj⟩

theorem js_wotsChains (itk ipk : Nat) (wa : Adrs) (hw : WotsR wa) (D : Nat → Nat) (hD : ∀ j, D j ≤ 15)
    (l : List (Nat × Nat)) (hl : ∀ k (hk : k < l.length), l[k].2 = k ∧ l[k].1 = D k)
    (hlen : l.length ≤ 256^4) {P0 : St → Prop} (hs : StableS c P0)
    (h : ∀ st, InvS c st → P0 st → st.ents[itk]? = some (false, dTk c.n) ∧ st.ents[ipk]? = some (false, dPrf c.n)) :
    JS c (forIn l [] fun x r => do
            let sk ← sPrf (params c.v) [SV.hid ipk 32] [SV.hid 2 c.n]
                  { layer := (wa.setType 5).layer, tree := (wa.setType 5).tree, kind := (wa.setType 5).kind,
                    keypair := wa.keypair, chain := x.snd, hash := (wa.setType 5).hash }
            let part ← sChain (params c.v) [SV.hid itk 32]
                  { layer := wa.layer, tree := wa.tree, kind := wa.kind, keypair := wa.keypair, chain := x.snd,
                    hash := wa.hash } sk 0 x.fst
            pure PUnit.unit
            pure (ForInStep.yield (r ++ part)))
      P0 (ChainsAt c wa D l.length) := by
  refine JS.loopI' l _ (fun k v st => ChainsAt c wa D k v st) hs (fun k v => stable_chainsAt wa D k v) []
    (fun _ _ _ => ⟨0, rfl, fun j hj => absurd hj (by omega)⟩) (fun k hk v => ?_)
  obtain ⟨hk2, hk1⟩ := hl k hk
  have hP := stableS_and hs (stable_chainsAt (c := c) wa D k v)
  have hB : ({wa.setType 5 with keypair := wa.keypair, chain := l[k].snd} : Adrs).InRange := by
    obtain ⟨_, _, _, h4, h5, h6⟩ := hw
    rw [hk2]
    refine ⟨h4, h5, ?_, h6, ?_, ?_⟩ <;> simp [Adrs.setType] <;> omega
  refine JS.bind (js_prf _ hB (Or.inl (by simp [Adrs.setType])) ipk (fun st hI hp => (h st hI hp.1).2))
    (fun sk => ?_) hP
  refine JS.obtain (X := fun i st => KidOK c st i (.pf {wa.setType 5 with keypair := wa.keypair, chain := l[k].snd}))
    (fun i hi => ?_)
  subst hi
  have hP2 := stableS_and hP (stableS_kid (c := c) i (.pf {wa.setType 5 with keypair := wa.keypair, chain := l[k].snd}))
  refine JS.bind (js_chain itk {wa with chain := l[k].snd} (chainR_of_wots hw (by rw [hk2]; omega))
      l[k].fst 0 [.hid i c.n] hP2 (by rw [hk1]; have := hD k; omega)
      (fun st hI hp => ⟨(h st hI hp.1.1).1, ?_⟩)) (fun part => ?_) hP2
  · obtain ⟨d, hd⟩ := hp.2
    exact ⟨d, i, rfl, by simp only [chainKid, if_pos]; exact hd⟩
  · refine JS.bind JS.unit (fun _ => JS.pure' (fun st _ hp => ?_)) (stableS_and hP2 (fun st st' _ hg
      (h : ∃ d yh, part = [.hid yh c.n] ∧ KidAt c st d yh (chainKid {wa with chain := l[k].snd} (0 + l[k].fst))) =>
        let ⟨d, yh, h1, h2⟩ := h; ⟨d, yh, h1, kidAt_mono hg h2⟩))
    obtain ⟨d, yh, hpart, hy⟩ := hp.1.2
    subst hpart
    refine ⟨_, rfl, chainsAt_snoc (d := d) hp.1.1.1.2 ?_⟩
    rw [hk2, hk1, Nat.zero_add] at hy
    exact hy

end


section
variable {c : Ctx}

theorem kids_compA (wa : Adrs) (hw : WotsR wa) (j : Nat) (hj : j < (params c.v).len) :
    (kids (params c.v) (compA wa))[j]? = some (chainKid {wa with chain := j} 15) := by
  obtain ⟨h0, _⟩ := hw
  have hk : (compA wa).kind = 1 := rfl
  unfold kids
  simp only [hk, chainKid]
  simp [List.getElem?_map, List.getElem?_range hj, compA, Adrs.setType]
  cases wa; simp_all

theorem dsmOK_comp (p : Params) (wa : Adrs) : DSMOK p (compA wa) := by
  intro K hK
  simp [kids, compA, Adrs.setType] at hK
  obtain ⟨ci, _, rfl⟩ := hK
  simp [Kid.adr, par, compA, Adrs.setType]

theorem compA_inRange {wa : Adrs} (hw : WotsR wa) : (compA wa).InRange := by
  obtain ⟨_, _, _, h4, h5, h6⟩ := hw
  refine ⟨h4, h5, ?_, h6, ?_, ?_⟩ <;> simp [compA, Adrs.setType]

theorem js_compress (itk : Nat) (wa : Adrs) (hw : WotsR wa) (tops : SB) {P0 : St → Prop}
    (h : ∀ st, InvS c st → P0 st → st.ents[itk]? = some (false, dTk c.n) ∧
      ChainsAt c wa (fun _ => 15) (params c.v).len tops st) :
    JS c (sThash (params c.v) [.hid itk 32] (compA wa) tops) P0
      (fun v st => ∃ i, v = [.hid i c.n] ∧ KidOK c st i (.th (compA wa))) := by
  obtain ⟨hlen, _⟩ := variant_bounds c.v
  have hpos : 0 < (params c.v).len := by cases c.v <;> decide
  refine js_thash (compA wa) tops itk (dsmOK_comp _ wa) (fun st hI hp => ?_)
  obtain ⟨hitk, d, hl, hv⟩ := h st hI hp
  have hkl : (kids (params c.v) (compA wa)).length = (params c.v).len := by
    have : (compA wa).kind = 1 := rfl
    unfold kids; simp [this]
  refine ⟨hitk, d, compA_inRange hw, by rw [← List.length_pos_iff, hkl]; exact hpos, by rw [hl, hkl], fun k hk => ?_⟩
  obtain ⟨hh, h1, h2⟩ := hv k (by omega)
  refine ⟨hh, h1, fun K hK => ?_⟩
  rw [kids_compA wa hw k (by omega)] at hK
  obtain rfl := Option.some.inj hK
  exact h2

theorem js_wotsPkgen (itk ipk : Nat) (wa : Adrs) (hw : WotsR wa) {P0 : St → Prop} (hs : StableS c P0)
    (h : ∀ st, InvS c st → P0 st → st.ents[itk]? = some (false, dTk c.n) ∧ st.ents[ipk]? = some (false, dPrf c.n)) :
    JS c (sWotsPkgen (params c.v) [.hid itk 32] [.hid ipk 32] [.hid 2 c.n] wa) P0
      (fun v st => ∃ i, v = [.hid i c.n] ∧ KidOK c st i (.th (compA wa))) := by
  obtain ⟨hlen, _⟩ := variant_bounds c.v
  simp only [sWotsPkgen, sWotsCompress]
  refine JS.bind (JS.loopI' (List.range (params c.v).len) _ (fun k v st => ChainsAt c wa (fun _ => 15) k v st) hs
    (fun k v => stable_chainsAt wa _ k v) [] (fun _ _ _ => ⟨0, rfl, fun j hj => absurd hj (by omega)⟩)
    (fun k hk v => ?_)) (fun tops => ?_) hs
  · rw [List.getElem_range]
    rw [List.length_range] at hk
    have hP := stableS_and hs (stable_chainsAt (c := c) wa (fun _ => 15) k v)
    have hB : ({wa.setType 5 with keypair := wa.keypair, chain := k} : Adrs).InRange := by
      obtain ⟨_, _, _, h4, h5, h6⟩ := hw
      refine ⟨h4, h5, ?_, h6, ?_, ?_⟩ <;> simp [Adrs.setType] <;> omega
    refine JS.bind (js_prf _ hB (Or.inl (by simp [Adrs.setType])) ipk (fun st hI hp => (h st hI hp.1).2))
      (fun sk => ?_) hP
    refine JS.obtain (X := fun i st => KidOK c st i (.pf {wa.setType 5 with keypair := wa.keypair, chain := k}))
      (fun i hi => ?_)
    subst hi
    have hP2 := stableS_and hP (stableS_kid (c := c) i (.pf {wa.setType 5 with keypair := wa.keypair, chain := k}))
    refine JS.bind (js_chain itk {wa with chain := k} (chainR_of_wots hw (by omega))
        15 0 [.hid i c.n] hP2 (by omega)
        (fun st hI hp => ⟨(h st hI hp.1.1).1, ?_⟩)) (fun part => ?_) hP2
    · obtain ⟨d, hd⟩ := hp.2
      exact ⟨d, i, rfl, by simp only [chainKid, if_pos]; exact hd⟩
    · refine JS.bind JS.unit (fun _ => JS.pure' (fun st _ hp => ?_)) (stableS_and hP2 (fun st st' _ hg
        (h : ∃ d yh, part = [.hid yh c.n] ∧ KidAt c st d yh (chainKid {wa with chain := k} (0 + 15))) =>
          let ⟨d, yh, h1, h2⟩ := h; ⟨d, yh, h1, kidAt_mono hg h2⟩))
      obtain ⟨d, yh, hpart, hy⟩ := hp.1.2
      subst hpart
      exact ⟨_, rfl, chainsAt_snoc (d := d) hp.1.1.1.2 hy⟩
  · rw [List.length_range]
    exact js_compress itk wa hw tops (fun st hI hp => ⟨(h st hI hp.1).1, hp.2⟩)

theorem js_wotsSign (itk ipk : Nat) (wa : Adrs) (hw : WotsR wa) (msg : Bytes) {P0 : St → Prop} (hs : StableS c P0)
    (h : ∀ st, InvS c st → P0 st → st.ents[itk]? = some (false, dTk c.n) ∧ st.ents[ipk]? = some (false, dPrf c.n)) :
    JS c (sWotsSign (params c.v) [.hid itk 32] [.hid ipk 32] [.hid 2 c.n] wa msg) P0
      (fun v st => ChainsAt c wa (fun j => (wotsDigits (params c.v) msg).getD j 0) (params c.v).len v st) := by
  obtain ⟨hlen, _⟩ := variant_bounds c.v
  simp only [sWotsSign]
  have hl : (wotsDigits (params c.v) msg).zipIdx.length = (params c.v).len := by simp [wots_digit_count]
  refine JS.bind (js_wotsChains itk ipk wa hw (fun j => (wotsDigits (params c.v) msg).getD j 0)
    (fun j => digits_le15 _ _ j) _ (fun k hk => ?_) (by omega) hs h) (fun sig => JS.pure' (fun st _ hp => ?_)) hs
  · simp only [List.getElem_zipIdx, true_and, Nat.zero_add]
    have hk' : k < (wotsDigits (params c.v) msg).length := by simpa using hk
    simp only [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hk', Option.getD_some]
  · rw [hl] at hp; exact hp.2

end


section
variable {c : Ctx}

theorem sSlice_one_get {x : SB} {i : Nat} {v : SV} (h : x[i]? = some v) : sSlice x i 1 = [v] := by
  have hi := (List.getElem?_eq_some_iff.mp h).1
  simp only [sSlice]
  rw [List.drop_eq_getElem_cons hi]
  simp [(List.getElem?_eq_some_iff.mp h).2]

theorem js_wotsPkFromSig (itk : Nat) (wa : Adrs) (hw : WotsR wa) (sig : SB) (msg : Bytes) {P0 : St → Prop}
    (hs : StableS c P0)
    (h : ∀ st, InvS c st → P0 st → st.ents[itk]? = some (false, dTk c.n) ∧
      ChainsAt c wa (fun j => (wotsDigits (params c.v) msg).getD j 0) (params c.v).len sig st) :
    JS c (sWotsPkFromSig (params c.v) [.hid itk 32] wa sig msg) P0
      (fun v st => ∃ i, v = [.hid i c.n] ∧ KidOK c st i (.th (compA wa))) := by
  obtain ⟨hlen, _⟩ := variant_bounds c.v
  simp only [sWotsPkFromSig, sWotsCompress]
  have hl : (wotsDigits (params c.v) msg).zipIdx.length = (params c.v).len := by simp [wots_digit_count]
  refine JS.bind (JS.loopI' (wotsDigits (params c.v) msg).zipIdx _ (fun k v st => ChainsAt c wa (fun _ => 15) k v st) hs
    (fun k v => stable_chainsAt wa _ k v) [] (fun _ _ _ => ⟨0, rfl, fun j hj => absurd hj (by omega)⟩)
    (fun k hk v => ?_)) (fun tops => ?_) hs
  · have hk' : k < (wotsDigits (params c.v) msg).length := by simpa using hk
    have hel : (wotsDigits (params c.v) msg).zipIdx[k] = ((wotsDigits (params c.v) msg)[k], k) := by
      simp [List.getElem_zipIdx]
    rw [hel]
    have hdk : (wotsDigits (params c.v) msg)[k] = (wotsDigits (params c.v) msg).getD k 0 := by
      simp only [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hk', Option.getD_some]
    have hP := stableS_and hs (stable_chainsAt (c := c) wa (fun _ => 15) k v)
    have h15 := digits_le15 (params c.v) msg k
    refine JS.assume (X := ∃ hh, sig[k]? = some (.hid hh c.n)) (fun st hI hp => ?_) (fun ⟨hh, hsig⟩ => ?_)
    · obtain ⟨_, _, hv⟩ := (h st hI hp.1).2
      obtain ⟨hh, h1, _⟩ := hv k (by rw [hl] at hk; exact hk)
      exact ⟨hh, h1⟩
    rw [sSlice_one_get hsig]
    refine JS.bind (js_chain itk {wa with chain := k} (chainR_of_wots hw (by rw [hl] at hk; omega))
        (15 - (wotsDigits (params c.v) msg)[k]) _ [.hid hh c.n] hP (by rw [hdk]; omega)
        (fun st hI hp => ⟨(h st hI hp.1).1, ?_⟩)) (fun part => ?_) hP
    · obtain ⟨d, _, hv⟩ := (h st hI hp.1).2
      obtain ⟨hh', h1, h2⟩ := hv k (by rw [hl] at hk; exact hk)
      rw [hsig] at h1
      obtain rfl : hh = hh' := by simpa using h1
      exact ⟨d, hh, rfl, by rw [hdk]; exact h2⟩
    · refine JS.bind JS.unit (fun _ => JS.pure' (fun st _ hp => ?_)) (stableS_and hP (fun st st' _ hg
        (h : ∃ d yh, part = [.hid yh c.n] ∧ KidAt c st d yh (chainKid {wa with chain := k}
          ((wotsDigits (params c.v) msg)[k] + (15 - (wotsDigits (params c.v) msg)[k])))) =>
          let ⟨d, yh, h1, h2⟩ := h; ⟨d, yh, h1, kidAt_mono hg h2⟩))
      obtain ⟨d, yh, hpart, hy⟩ := hp.1.2
      subst hpart
      rw [show (wotsDigits (params c.v) msg)[k] + (15 - (wotsDigits (params c.v) msg)[k]) = 15 by
        rw [hdk]; omega] at hy
      exact ⟨_, rfl, chainsAt_snoc (d := d) hp.1.1.2 hy⟩
  · rw [hl]
    exact js_compress itk wa hw tops (fun st hI hp => ⟨(h st hI hp.1).1, hp.2⟩)

end


/-! XMSS trees and authentication walks. -/

theorem xor_one (j : Nat) : Nat.xor j 1 = if j % 2 = 0 then j + 1 else j - 1 := by
  apply Nat.eq_of_testBit_eq
  intro i
  show (j ^^^ 1).testBit i = _
  rw [Nat.testBit_xor]
  cases i with
  | zero =>
    simp only [Nat.testBit_zero]
    split <;> rename_i h
    · have h1 : (j + 1) % 2 = 1 := by omega
      simp [h, h1]
    · have h1 : (j - 1) % 2 = 0 := by omega
      have h2 : j % 2 = 1 := by omega
      simp [h1, h2]
  | succ i =>
    simp only [Nat.testBit_succ]
    have : (1 : Nat) / 2 = 0 := rfl
    rw [this, Nat.zero_testBit, Bool.xor_false]
    split <;> rename_i h <;> congr 1 <;> omega

theorem lin1 (i X : Nat) : (2*i+1)*X = 2*(i*X) + X := by rw [Nat.add_mul, Nat.one_mul, Nat.mul_assoc]
theorem lin2 (i X : Nat) : (i+1)*(X*2) = 2*(i*X) + 2*X := by
  rw [Nat.add_mul, Nat.one_mul, ← Nat.mul_assoc, Nat.mul_comm (i*X) 2, Nat.mul_comm X 2]
theorem lin3 (i X : Nat) : (2*i+1+1)*X = 2*(i*X) + 2*X := by
  rw [show 2*i+1+1 = 2*i+2 by omega, Nat.add_mul, Nat.mul_assoc]

/-- The XMSS node at height `h`, index `idx`, of the tree at `a` (height 0: a WOTS key). -/
def nodeA (a : Adrs) (h idx : Nat) : Adrs :=
  if h = 0 then compA {a.setType 0 with keypair := idx} else {a.setType 2 with chain := h, hash := idx}

theorem kids_node (p : Params) (a : Adrs) (h idx : Nat) :
    kids p (nodeA a (h+1) idx) = [.th (nodeA a h (2*idx)), .th (nodeA a h (2*idx+1))] := by
  unfold kids nodeA
  cases h with
  | zero => simp [Adrs.setType, compA]
  | succ h => simp [Adrs.setType]

theorem dsmOK_node (p : Params) (a : Adrs) (h idx : Nat) (hh : h + 1 ≤ p.hp) :
    DSMOK p (nodeA a (h+1) idx) := by
  intro K hK
  rw [kids_node] at hK
  simp only [List.mem_cons, List.mem_nil_iff, or_false] at hK
  cases h with
  | zero =>
    rcases hK with rfl | rfl <;> simp [Kid.adr, par, nodeA, compA, Adrs.setType] <;> omega
  | succ h =>
    have hlt : h + 1 < p.hp := by omega
    rcases hK with rfl | rfl <;> simp [Kid.adr, par, nodeA, Adrs.setType, hlt] <;> omega

theorem nodeA_inRange (a : Adrs) (hl : a.layer < 256^4) (ht : a.tree < 256^8) {h idx : Nat}
    (hh : h < 256^4) (hi : idx < 256^4) : (nodeA a h idx).InRange := by
  unfold nodeA
  split
  · refine ⟨hl, ht, ?_, ?_, ?_, ?_⟩ <;> simp [compA, Adrs.setType] <;> omega
  · refine ⟨hl, ht, ?_, ?_, ?_, ?_⟩ <;> simp [Adrs.setType] <;> omega

section
variable {c : Ctx}

theorem wotsR_node (a : Adrs) (hl : a.layer < 256^4) (ht : a.tree < 256^8) {idx : Nat} (hi : idx < 256^4) :
    WotsR {a.setType 0 with keypair := idx} := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩ <;> simp [Adrs.setType] <;> omega

theorem js_xmssNode (itk ipk : Nat) (a : Adrs) (hl : a.layer < 256^4) (ht : a.tree < 256^8) :
    ∀ (height idx : Nat) {P0 : St → Prop}, StableS c P0 → (idx+1)*2^height ≤ 2^(params c.v).hp →
    (∀ st, InvS c st → P0 st → st.ents[itk]? = some (false, dTk c.n) ∧ st.ents[ipk]? = some (false, dPrf c.n)) →
    JS c (sXmssNode (params c.v) [.hid itk 32] [.hid ipk 32] [.hid 2 c.n] a idx height) P0
      (fun v st => ∃ i, v = [.hid i c.n] ∧ KidOK c st i (.th (nodeA a height idx)))
  | 0, idx, P0, hs, hb, h => by
    obtain ⟨_, hH, _⟩ := variant_bounds c.v
    simp only [sXmssNode]
    have : nodeA a 0 idx = compA {a.setType 0 with keypair := idx} := by simp [nodeA]
    rw [this]
    exact js_wotsPkgen itk ipk _ (wotsR_node a hl ht (by simp at hb; omega)) hs h
  | height+1, idx, P0, hs, hb, h => by
    obtain ⟨_, hH, _⟩ := variant_bounds c.v
    have hp1 : 2^height ≤ 2^(params c.v).hp := by
      calc 2^height ≤ (idx+1)*2^(height+1) := by
            rw [Nat.pow_succ]; exact Nat.le_trans (Nat.le_mul_of_pos_right _ (by omega)) (Nat.le_mul_of_pos_left _ (by omega))
        _ ≤ _ := hb
    have hhp : height + 1 ≤ (params c.v).hp := by
      have := Nat.pow_le_pow_iff_right (show 1 < 2 by omega) |>.mp (Nat.le_trans (by
        rw [Nat.pow_succ]; exact Nat.le_mul_of_pos_left _ (by omega)) hb : 2^(height+1) ≤ 2^(params c.v).hp)
      exact this
    have hhp4 : (params c.v).hp < 256^4 := Nat.lt_of_lt_of_le (Nat.lt_two_pow_self) hH
    simp only [sXmssNode]
    refine JS.bind (js_xmssNode itk ipk a hl ht height (2*idx) hs (by
      calc (2*idx+1)*2^height ≤ (idx+1)*2^(height+1) := by rw [Nat.pow_succ, lin1, lin2]; omega
        _ ≤ _ := hb) h) (fun left => ?_) hs
    refine JS.obtain (X := fun i st => KidOK c st i (.th (nodeA a height (2*idx)))) (fun il hil => ?_)
    subst hil
    have hs1 := stableS_and hs (stableS_kid (c := c) il (.th (nodeA a height (2*idx))))
    refine JS.bind (js_xmssNode itk ipk a hl ht height (2*idx+1) hs1 (by
      calc (2*idx+1+1)*2^height = (idx+1)*2^(height+1) := by rw [Nat.pow_succ, lin3, lin2]
        _ ≤ _ := hb) (fun st hI hp => h st hI hp.1)) (fun right => ?_) hs1
    refine JS.obtain (X := fun i st => KidOK c st i (.th (nodeA a height (2*idx+1)))) (fun ir hir => ?_)
    subst hir
    have hA : ({a.setType 2 with chain := height+1, hash := idx} : Adrs) = nodeA a (height+1) idx := by
      simp [nodeA]
    rw [hA]
    refine js_thash _ _ itk (dsmOK_node _ a height idx hhp) (fun st hI hp => ⟨(h st hI hp.1.1).1, ?_⟩)
    obtain ⟨d1, hd1⟩ := hp.1.2
    obtain ⟨d2, hd2⟩ := hp.2
    refine ⟨max d1 d2, nodeA_inRange a hl ht (by omega) ?_, by rw [kids_node]; simp, by rw [kids_node]; rfl,
      fun k hk => ?_⟩
    · have : idx < 2^(params c.v).hp := by
        have := Nat.le_trans (Nat.le_mul_of_pos_right _ (Nat.two_pow_pos (height+1))) hb; omega
      omega
    · rw [kids_node]
      have hk2 : k < 2 := by simpa using hk
      rcases k with _ | _ | k
      · refine ⟨il, rfl, fun K hK => ?_⟩
        simp at hK; subst hK; exact kidAt_fuel (Nat.le_max_left _ _) hd1
      · refine ⟨ir, rfl, fun K hK => ?_⟩
        simp at hK; subst hK; exact kidAt_fuel (Nat.le_max_right _ _) hd2
      · omega

end


section
variable {c : Ctx}

theorem div_pow_succ (x l : Nat) : x / 2^l / 2 = x / 2^(l+1) := by
  rw [Nat.div_div_eq_div_mul, Nat.pow_succ]

/-- Authentication walk from level `level` to `T`, on a tree whose node at level `ℓ`,
    index `j`, is `N ℓ j`; the global index at level 0 is `g0`, the local one `l0`. -/
theorem js_authWalk (itk : Nat) (a2 : Adrs) (N : Nat → Nat → Adrs) (T g0 l0 : Nat)
    (hN : ∀ ℓ j, ({a2 with chain := ℓ+1, hash := j} : Adrs) = N (ℓ+1) j)
    (hK : ∀ ℓ, ℓ < T → kids (params c.v) (N (ℓ+1) (g0 / 2^(ℓ+1))) =
      [.th (N ℓ (2*(g0 / 2^(ℓ+1)))), .th (N ℓ (2*(g0 / 2^(ℓ+1))+1))])
    (hR : ∀ ℓ, ℓ < T → (N (ℓ+1) (g0 / 2^(ℓ+1))).InRange)
    (hD : ∀ ℓ, ℓ < T → DSMOK (params c.v) (N (ℓ+1) (g0 / 2^(ℓ+1))))
    (hpar : ∀ ℓ, ℓ < T → (l0 / 2^ℓ) % 2 = (g0 / 2^ℓ) % 2) (auth : SB) :
    ∀ (r level : Nat) (node : SB) {P0 : St → Prop}, StableS c P0 → level + r = T →
    (∀ st, InvS c st → P0 st → st.ents[itk]? = some (false, dTk c.n) ∧
      (∃ h, node = [.hid h c.n] ∧ KidOK c st h (.th (N level (g0 / 2^level)))) ∧
      ∀ ℓ, level ≤ ℓ → ℓ < T → ∃ h, auth[ℓ]? = some (.hid h c.n) ∧
        KidOK c st h (.th (N ℓ (Nat.xor (g0 / 2^ℓ) 1)))) →
    JS c (sAuthWalk (params c.v) [.hid itk 32] a2 (l0 / 2^level) (g0 / 2^level) node auth level r) P0
      (fun v st => ∃ i, v = [.hid i c.n] ∧ KidOK c st i (.th (N T (g0 / 2^T))))
  | 0, level, node, P0, _, hT, h => by
    simp only [sAuthWalk]
    refine JS.pure' (fun st hI hp => ?_)
    obtain ⟨_, ⟨hh, hn, hk⟩, _⟩ := h st hI hp
    exact ⟨hh, hn, by rw [← show level = T by omega]; exact hk⟩
  | r+1, level, node, P0, hs, hT, h => by
    simp only [sAuthWalk]
    have hlT : level < T := by omega
    rw [hN level (g0 / 2^level / 2), div_pow_succ]
    refine JS.assume (X := ∃ hs' hn, node = [.hid hn c.n] ∧ auth[level]? = some (.hid hs' c.n)) (fun st hI hp => ?_)
      (fun ⟨hs', hn, hnode, hauth⟩ => ?_)
    · obtain ⟨_, ⟨hn, hnode, _⟩, ha⟩ := h st hI hp
      obtain ⟨hs', hauth, _⟩ := ha level (Nat.le_refl _) hlT
      exact ⟨hs', hn, hnode, hauth⟩
    subst hnode
    rw [sSlice_one_get hauth]
    refine JS.bind (js_thash _ _ itk (hD level hlT) (fun st hI hp => ⟨(h st hI hp).1, ?_⟩)) (fun next => ?_) hs
    · obtain ⟨_, ⟨hn', hnode', ⟨d1, hd1⟩⟩, ha⟩ := h st hI hp
      obtain rfl : hn = hn' := by simpa using hnode'
      obtain ⟨hs'', hauth', ⟨d2, hd2⟩⟩ := ha level (Nat.le_refl _) hlT
      rw [hauth] at hauth'
      obtain rfl : hs' = hs'' := by simpa using hauth'
      have hpl := hpar level hlT
      have hpar' : g0 / 2^level = 2 * (g0 / 2^(level+1)) + (g0 / 2^level) % 2 := by
        rw [← div_pow_succ]; omega
      refine ⟨max d1 d2, hR level hlT, by rw [hK level hlT]; simp, ?_, fun k hk => ?_⟩
      · split <;> rw [hK level hlT] <;> rfl
      · rw [hK level hlT]
        have hk2 : k < 2 := by split at hk <;> simpa using hk
        rw [xor_one] at hd2
        by_cases hev : (g0 / 2^level) % 2 = 0
        · have hl0 : (l0 / 2^level) % 2 = 0 := by omega
          simp only [hl0, if_true]
          rw [if_pos hev] at hd2
          rcases k with _ | _ | k
          · refine ⟨hn, rfl, fun K hK => ?_⟩
            simp at hK; subst hK
            have : 2 * (g0 / 2^(level+1)) = g0 / 2^level := by omega
            rw [this]; exact kidAt_fuel (Nat.le_max_left _ _) hd1
          · refine ⟨hs', rfl, fun K hK => ?_⟩
            simp at hK; subst hK
            have : 2 * (g0 / 2^(level+1)) + 1 = g0 / 2^level + 1 := by omega
            rw [this]; exact kidAt_fuel (Nat.le_max_right _ _) hd2
          · omega
        · have hl0 : ¬ (l0 / 2^level) % 2 = 0 := by omega
          simp only [hl0, if_false]
          rw [if_neg hev] at hd2
          rcases k with _ | _ | k
          · refine ⟨hs', rfl, fun K hK => ?_⟩
            simp at hK; subst hK
            have : 2 * (g0 / 2^(level+1)) = g0 / 2^level - 1 := by omega
            rw [this]; exact kidAt_fuel (Nat.le_max_right _ _) hd2
          · refine ⟨hn, rfl, fun K hK => ?_⟩
            simp at hK; subst hK
            have : 2 * (g0 / 2^(level+1)) + 1 = g0 / 2^level := by omega
            rw [this]; exact kidAt_fuel (Nat.le_max_left _ _) hd1
          · omega
    · refine JS.obtain (X := fun i st => KidOK c st i (.th (N (level+1) (g0 / 2^(level+1))))) (fun i hi => ?_)
      subst hi
      have hs1 := stableS_and hs (stableS_kid (c := c) i (.th (N (level+1) (g0 / 2^(level+1)))))
      rw [div_pow_succ l0 level]
      exact js_authWalk itk a2 N T g0 l0 hN hK hR hD hpar auth r (level+1) [.hid i c.n] hs1 (by omega)
        (fun st hI hp => ⟨(h st hI hp.1).1, ⟨i, rfl, hp.2⟩,
          fun ℓ h1 h2 => (h st hI hp.1).2.2 ℓ (by omega) h2⟩)

end


section
variable {c : Ctx}

/-- Authentication path of leaf `idx` in the tree at `a`, levels `[0, k)`. -/
def AuthAt (c : Ctx) (a : Adrs) (idx : Nat) (k : Nat) (v : SB) (st : St) : Prop :=
  ∃ d, v.length = k ∧ ∀ ℓ, ℓ < k → ∃ h, v[ℓ]? = some (.hid h c.n) ∧
    KidAt c st d h (.th (nodeA a ℓ (Nat.xor (idx / 2^ℓ) 1)))

theorem stable_authAt (a : Adrs) (idx k : Nat) (v : SB) : StableS c (AuthAt c a idx k v) :=
  fun _ _ _ hg ⟨d, hl, hv⟩ => ⟨d, hl, fun j hj => let ⟨h, h1, h2⟩ := hv j hj; ⟨h, h1, kidAt_mono hg h2⟩⟩

/-- An XMSS signature of `msg` by leaf `idx` of the tree at `a`. -/
def XSig (c : Ctx) (a : Adrs) (idx : Nat) (msg : Bytes) (v : SB) (st : St) : Prop :=
  ChainsAt c {a.setType 0 with keypair := idx} (fun j => (wotsDigits (params c.v) msg).getD j 0)
    (params c.v).len (v.take (params c.v).len) st ∧
  AuthAt c a idx (params c.v).hp (v.drop (params c.v).len) st

theorem stable_xsig (a : Adrs) (idx : Nat) (msg : Bytes) (v : SB) : StableS c (XSig c a idx msg v) :=
  stableS_and (stable_chainsAt _ _ _ _) (stable_authAt _ _ _ _)

theorem sib_bound (hp idx l : Nat) (hidx : idx < 2^hp) (hl : l < hp) :
    (Nat.xor (idx / 2^l) 1 + 1) * 2^l ≤ 2^hp := by
  have hM : 2^hp = 2^(hp - l) * 2^l := by rw [← Nat.pow_add]; congr 1; omega
  have hpos : 0 < 2^l := Nat.two_pow_pos l
  have hj : idx / 2^l < 2^(hp - l) := (Nat.div_lt_iff_lt_mul hpos).mpr (by rw [← hM]; exact hidx)
  have hev : 2^(hp - l) % 2 = 0 := by
    rw [show hp - l = (hp - l - 1) + 1 by omega, Nat.pow_succ]; simp
  rw [xor_one]
  split
  · have : idx / 2^l + 1 + 1 ≤ 2^(hp - l) := by
      generalize idx / 2^l = j at *
      generalize 2^(hp - l) = M at *
      omega
    rw [hM]; exact Nat.mul_le_mul_right _ this
  · have h1 : idx / 2^l - 1 + 1 = idx / 2^l := by
      generalize idx / 2^l = j at *
      omega
    rw [h1]
    exact Nat.le_of_lt (Nat.lt_of_le_of_lt (Nat.div_mul_le_self idx (2^l)) hidx)

theorem authAt_snoc {a : Adrs} {idx k : Nat} {v : SB} {st : St} {d yh : Nat}
    (hv : AuthAt c a idx k v st) (hy : KidAt c st d yh (.th (nodeA a k (Nat.xor (idx / 2^k) 1)))) :
    AuthAt c a idx (k+1) (v ++ [.hid yh c.n]) st := by
  obtain ⟨d0, hl, hv⟩ := hv
  refine ⟨max d0 d, by simp [hl], fun j hj => ?_⟩
  by_cases hjk : j < k
  · obtain ⟨h, h1, h2⟩ := hv j hjk
    exact ⟨h, by rw [List.getElem?_append_left (by omega)]; exact h1, kidAt_fuel (Nat.le_max_left _ _) h2⟩
  · have hj : j = k := by omega
    subst hj
    exact ⟨yh, by rw [List.getElem?_append_right (by omega)]; simp [hl], kidAt_fuel (Nat.le_max_right _ _) hy⟩

theorem js_xmssSign (itk ipk : Nat) (a : Adrs) (hl : a.layer < 256^4) (ht : a.tree < 256^8) (idx : Nat)
    (hidx : idx < 2^(params c.v).hp) (msg : Bytes) {P0 : St → Prop} (hs : StableS c P0)
    (h : ∀ st, InvS c st → P0 st → st.ents[itk]? = some (false, dTk c.n) ∧ st.ents[ipk]? = some (false, dPrf c.n)) :
    JS c (sXmssSign (params c.v) [.hid itk 32] [.hid ipk 32] [.hid 2 c.n] a idx msg) P0 (XSig c a idx msg) := by
  obtain ⟨_, hH, _⟩ := variant_bounds c.v
  simp only [sXmssSign]
  refine JS.bind (JS.loopI' (List.range (params c.v).hp) _ (fun k v st => AuthAt c a idx k v st) hs
    (fun k v => stable_authAt a idx k v) [] (fun _ _ _ => ⟨0, rfl, fun j hj => absurd hj (by omega)⟩)
    (fun k hk v => ?_)) (fun auth => ?_) hs
  · rw [List.getElem_range]
    rw [List.length_range] at hk
    have hP := stableS_and hs (stable_authAt (c := c) a idx k v)
    refine JS.bind (js_xmssNode itk ipk a hl ht k _ hP (sib_bound _ idx k hidx hk) (fun st hI hp => h st hI hp.1))
      (fun node => ?_) hP
    refine JS.obtain (X := fun i st => KidOK c st i (.th (nodeA a k (Nat.xor (idx / 2^k) 1)))) (fun i hi => ?_)
    subst hi
    refine JS.bind JS.unit (fun _ => JS.pure' (fun st _ hp => ?_)) (stableS_and hP (stableS_kid _ _))
    obtain ⟨d, hd⟩ := hp.1.2
    exact ⟨_, rfl, authAt_snoc hp.1.1.2 hd⟩
  · rw [List.length_range]
    have hs1 := stableS_and hs (stable_authAt (c := c) a idx (params c.v).hp auth)
    have hw : WotsR {a.setType 0 with keypair := idx} :=
      wotsR_node a hl ht (Nat.lt_of_lt_of_le hidx hH)
    refine JS.bind (js_wotsSign itk ipk _ hw msg hs1 (fun st hI hp => h st hI hp.1)) (fun sig => ?_) hs1
    refine JS.pure' (fun st _ hp => ⟨?_, ?_⟩)
    · obtain ⟨d, hl', hv⟩ := hp.2
      rw [List.take_left' hl']
      exact ⟨d, hl', hv⟩
    · obtain ⟨d, hl', _⟩ := hp.2
      rw [List.drop_left' hl']
      exact hp.1.2

theorem js_xmssPkFromSig (itk : Nat) (a : Adrs) (hl : a.layer < 256^4) (ht : a.tree < 256^8) (idx : Nat)
    (hidx : idx < 2^(params c.v).hp) (sig : SB) (msg : Bytes) {P0 : St → Prop} (hs : StableS c P0)
    (h : ∀ st, InvS c st → P0 st → st.ents[itk]? = some (false, dTk c.n) ∧ XSig c a idx msg sig st) :
    JS c (sXmssPkFromSig (params c.v) [.hid itk 32] a idx sig msg) P0
      (fun v st => ∃ i, v = [.hid i c.n] ∧ KidOK c st i (.th (nodeA a (params c.v).hp 0))) := by
  obtain ⟨_, hH, _⟩ := variant_bounds c.v
  have hhp : (params c.v).hp < 256^4 := Nat.lt_of_lt_of_le Nat.lt_two_pow_self hH
  simp only [sXmssPkFromSig, sAuthRoot]
  have hw : WotsR {a.setType 0 with keypair := idx} := wotsR_node a hl ht (Nat.lt_of_lt_of_le hidx hH)
  refine JS.bind (js_wotsPkFromSig itk _ hw _ msg hs (fun st hI hp => ⟨(h st hI hp).1, (h st hI hp).2.1⟩))
    (fun node => ?_) hs
  have hw0 := js_authWalk (c := c) itk (a.setType 2) (nodeA a) (params c.v).hp idx idx
    (fun ℓ j => by simp [nodeA])
    (fun ℓ hℓ => kids_node _ a ℓ _)
    (fun ℓ hℓ => nodeA_inRange a hl ht (by omega)
      (Nat.lt_of_le_of_lt (Nat.div_le_self _ _) (Nat.lt_of_lt_of_le hidx hH)))
    (fun ℓ hℓ => dsmOK_node _ a ℓ _ (by omega))
    (fun _ _ => rfl) (sig.drop (params c.v).len) (params c.v).hp 0 node
    (stableS_and hs (fun st st' _ hg (h : ∃ i, node = [.hid i c.n] ∧ KidOK c st i (.th (compA {a.setType 0 with keypair := idx}))) =>
      let ⟨i, h1, h2⟩ := h; ⟨i, h1, kidOK_mono hg h2⟩)) (by omega)
    (fun st hI hp => ⟨(h st hI hp.1).1, ?_, ?_⟩)
  · simp only [Nat.pow_zero, Nat.div_one] at hw0
    rw [Nat.div_eq_of_lt hidx] at hw0
    exact hw0
  · obtain ⟨i, hi, hk⟩ := hp.2
    refine ⟨i, hi, ?_⟩
    simp only [Nat.pow_zero, Nat.div_one]
    have : nodeA a 0 idx = compA {a.setType 0 with keypair := idx} := by simp [nodeA]
    rw [this]; exact hk
  · intro ℓ _ hℓ
    obtain ⟨d, _, hv⟩ := (h st hI hp.1).2.2
    obtain ⟨hh, h1, h2⟩ := hv ℓ hℓ
    exact ⟨hh, h1, d, h2⟩

end

/-! Revealable handles. -/

section
variable {c : Ctx}

/-- Every handle of `v` exists and is not protected. -/
def RevOK (st : St) (v : List SV) : Prop := ∀ h ∈ shids v, h < st.ents.length ∧ ¬ Prot st h

theorem stable_revOK (v : List SV) : StableS c (fun st => RevOK st v) := by
  intro st st' _ hg h i hi
  obtain ⟨h1, h2⟩ := h i hi
  refine ⟨?_, fun hp => h2 ((prot_mono hg h1).mp hp)⟩
  obtain ⟨⟨L, hL⟩, _⟩ := hg
  rw [hL]; simp; omega

theorem revOK_append {st : St} {x y : List SV} (hx : RevOK st x) (hy : RevOK st y) : RevOK st (x ++ y) := by
  intro i hi
  rw [shids_append, List.mem_append] at hi
  rcases hi with hi | hi
  · exact hx i hi
  · exact hy i hi

theorem revOK_nil {st : St} : RevOK st [] := fun i hi => by simp [shids] at hi

theorem kidAt_mode {st : St} {d h : Nat} {K : Kid} (hk : KidAt c st d h K) :
    ∃ e, st.ents[h]? = some e ∧ (e.2.res c.t).mode = 1 := by
  cases K with
  | th B =>
    obtain ⟨r', h1, h2⟩ := hk
    refine ⟨_, h2, ?_⟩
    cases d with
    | zero => exact h1.elim
    | succ d => obtain ⟨_, _, _, _, _, hrr, _⟩ := h1; subst hrr; rfl
  | pf B =>
    obtain ⟨ipk, _, h2, _⟩ := hk
    exact ⟨_, h2, rfl⟩

theorem famOK_hids {st : St} (hI : InvS c st) {r : SReq} (hF : FamOK c st r) (h0 : r ≠ dPrf c.n)
    (h1 : r ≠ dReq c.n) : ∀ i ∈ r.hids, 2 ≤ i := by
  rcases hF with rfl | rfl | rfl | ⟨ipk, A, rfl, hk, _⟩ | ⟨dk, m, rfl, hk⟩ | ⟨iR, m, rfl, dk, hk, _, hroot⟩ | ⟨d, A, hs⟩
  · intro i hi; simp [dTk, SReq.hids, shids] at hi; omega
  · exact absurd rfl h0
  · exact absurd rfl h1
  · have := ge3_of_ent hI hk (by simp [dPrf])
    intro i hi; simp [prfReq, SReq.hids, shids] at hi; omega
  · have := ge3_of_ent hI hk (by simp [dReq])
    intro i hi; simp [rqOf, SReq.hids, shids] at hi; omega
  · have := ge3_of_ent hI hk (by simp [rqOf])
    intro i hi
    simp [hqOf, SReq.hids, shids, shids_append] at hi
    rcases hi with rfl | rfl | hi
    · omega
    · omega
    · have := (hroot i hi).1; omega
  · cases d with
    | zero => exact hs.elim
    | succ d =>
      obtain ⟨_, _, _, itk, hs', rfl, hitk, hl, hh⟩ := hs
      have h3 := ge3_of_ent hI hitk (by simp [dTk])
      intro i hi
      simp [SReq.hids, shids] at hi
      rcases hi with rfl | hi
      · omega
      · obtain ⟨w, hw⟩ := mem_shids hs' i hi
        obtain ⟨k, hk⟩ := List.mem_iff_getElem?.mp hw
        have hkl := (List.getElem?_eq_some_iff.mp hk).1
        obtain ⟨h', hx, hK⟩ := hh k hkl
        rw [hk] at hx
        obtain rfl : i = h' := by simp at hx; exact hx.1
        revert hK
        cases (kids (params c.v) A)[k]? with
        | none => intro h; exact h.elim
        | some K =>
          intro hK
          have : KidAt c st d i K := by cases K <;> exact hK
          obtain ⟨e, he, hm⟩ := kidAt_mode this
          have := ge3_of_res hI he (by rw [hm]; decide)
          omega

theorem notProt_of_res {st : St} (hI : InvS c st) {h : Nat} {e : Bool × SReq} (he : st.ents[h]? = some e)
    (hm0 : (e.2.res c.t).mode ≠ 0) (hm9 : (e.2.res c.t).mode ≠ 999) : ¬ Prot st h := by
  rintro ⟨e', he', hp⟩
  rw [he] at he'
  obtain rfl := Option.some.inj he'
  obtain ⟨b, r⟩ := e
  cases b with
  | true =>
    rw [hI.2.1 h r he] at hp; simp at hp
  | false =>
    have h3 := ge3_of_res hI he hm9
    rcases hI.2.2.2.1 h r he with hlt | hF
    · omega
    · have hr0 : r ≠ dPrf c.n := by rintro rfl; exact hm0 rfl
      have hr1 : r ≠ dReq c.n := by rintro rfl; exact hm0 rfl
      have := famOK_hids hI hF hr0 hr1
      rcases hp with hp | hp
      · have := this 0 hp; omega
      · have := this 1 hp; omega

theorem kidAt_rev {st : St} (hI : InvS c st) {d h : Nat} {K : Kid} (hk : KidAt c st d h K) :
    h < st.ents.length ∧ ¬ Prot st h := by
  obtain ⟨e, he, hm⟩ := kidAt_mode hk
  exact ⟨(List.getElem?_eq_some_iff.mp he).1, notProt_of_res hI he (by rw [hm]; decide) (by rw [hm]; decide)⟩

theorem revOK_one {st : St} (hI : InvS c st) {d h : Nat} {K : Kid} (hk : KidAt c st d h K) (w : Nat) :
    RevOK st [.hid h w] := by
  intro i hi
  simp [shids] at hi; subst hi
  exact kidAt_rev hI hk

theorem revOK_idx {st : St} {v : List SV}
    (h : ∀ j, j < v.length → ∃ i w, v[j]? = some (.hid i w) ∧ i < st.ents.length ∧ ¬ Prot st i) :
    RevOK st v := by
  intro i hi
  obtain ⟨w, hw⟩ := mem_shids v i hi
  obtain ⟨j, hj⟩ := List.mem_iff_getElem?.mp hw
  obtain ⟨i', w', hj', h1, h2⟩ := h j (List.getElem?_eq_some_iff.mp hj).1
  rw [hj] at hj'
  obtain ⟨rfl, -⟩ := SV.hid.inj (Option.some.inj hj')
  exact ⟨h1, h2⟩

theorem revOK_chainsAt {st : St} (hI : InvS c st) {wa : Adrs} {D : Nat → Nat} {k : Nat} {v : SB}
    (h : ChainsAt c wa D k v st) : RevOK st v := by
  obtain ⟨d, hl, hv⟩ := h
  refine revOK_idx (fun j hj => ?_)
  obtain ⟨i, h1, h2⟩ := hv j (by omega)
  exact ⟨i, c.n, h1, kidAt_rev hI h2⟩

theorem revOK_authAt {st : St} (hI : InvS c st) {a : Adrs} {idx k : Nat} {v : SB}
    (h : AuthAt c a idx k v st) : RevOK st v := by
  obtain ⟨d, hl, hv⟩ := h
  refine revOK_idx (fun j hj => ?_)
  obtain ⟨i, h1, h2⟩ := hv j (by omega)
  exact ⟨i, c.n, h1, kidAt_rev hI h2⟩

theorem revOK_xsig {st : St} (hI : InvS c st) {a : Adrs} {idx : Nat} {msg : Bytes} {v : SB}
    (h : XSig c a idx msg v st) : RevOK st v := by
  have := revOK_append (revOK_chainsAt hI h.1) (revOK_authAt hI h.2)
  rwa [List.take_append_drop] at this

theorem xsig_len {st : St} {a : Adrs} {idx : Nat} {msg : Bytes} {v : SB} (h : XSig c a idx msg v st) :
    v.length = (params c.v).len + (params c.v).hp := by
  obtain ⟨⟨_, h1, _⟩, ⟨_, h2, _⟩⟩ := h
  rw [List.length_take] at h1
  rw [List.length_drop] at h2
  omega

end

/-! Provenance of revealed handles: every revealed canonical entry has its ancestors
    materialized. The signer reveals a signature only after recomputing its root, whose
    structure covers every handle of the signature. -/

/-- Every handle of `v` exists and has its ancestors materialized. -/
def Cov (c : Ctx) (st : St) (v : List SV) : Prop := ∀ h ∈ shids v, h < st.ents.length ∧ AncOK c st h

section
variable {c : Ctx}

theorem stable_cov (v : List SV) : StableS c (fun st => Cov c st v) := by
  intro st st' hI hg h i hi
  obtain ⟨h1, h2⟩ := h i hi
  refine ⟨?_, ancOK_mono hI hg h1 h2⟩
  obtain ⟨⟨L, hL⟩, _⟩ := hg
  rw [hL]; simp; omega

theorem cov_append {st : St} {x y : List SV} (hx : Cov c st x) (hy : Cov c st y) : Cov c st (x ++ y) := by
  intro i hi
  rw [shids_append, List.mem_append] at hi
  rcases hi with hi | hi
  · exact hx i hi
  · exact hy i hi

theorem cov_nil {st : St} : Cov c st [] := fun i hi => by simp [shids] at hi

theorem reveal_ok {st : St} {v : List SV} (h1 : RevOK st v) (h2 : Cov c st v) :
    ∀ h ∈ shids v, h < st.ents.length ∧ ¬ Prot st h ∧ AncOK c st h :=
  fun h hh => ⟨(h1 h hh).1, (h1 h hh).2, (h2 h hh).2⟩

theorem stable_rc (v : List SV) : StableS c (fun st => RevOK st v ∧ Cov c st v) :=
  stableS_and (stable_revOK v) (stable_cov v)

/-- A handle's address shape determines its address. -/
theorem entAt_kid_eq {st : St} {d h : Nat} {K : Kid} (hk : KidAt c st d h K) {A : Adrs}
    (he : EntAt c st h A) : A = K.adr := by
  obtain ⟨r, hr, hA⟩ := he
  cases K with
  | th B =>
    obtain ⟨r', h1, h2⟩ := hk
    rw [h2] at hr
    obtain rfl : r' = r := by simpa using hr
    cases d with
    | zero => exact h1.elim
    | succ d =>
      obtain ⟨hR, _, _, itk, hs, rfl, _⟩ := h1
      rcases hA with ⟨hR', itk', hs', hr'⟩ | ⟨_, ipk, hr', _⟩
      · have := congrArg SReq.input hr'
        simp only [List.cons.injEq, SV.lit.injEq] at this
        exact adrs_bytes_injective A B hR' hR this.1.symm
      · have := congrArg SReq.input hr'
        simp [prfReq] at this
  | pf B =>
    obtain ⟨ipk, _, h2, hB⟩ := hk
    rw [h2] at hr
    obtain rfl : prfReq c.n ipk B = r := by simpa using hr
    rcases hA with ⟨hR', itk', hs', hr'⟩ | ⟨hR', ipk', hr', _⟩
    · have := congrArg SReq.input hr'
      simp [prfReq] at this
    · have := congrArg SReq.input hr'
      simp only [prfReq, List.cons.injEq, SV.lit.injEq, and_true, true_and] at this
      exact adrs_bytes_injective A B hR' hB this.symm

theorem ancOK_kid {st : St} {d h : Nat} {K : Kid} (hk : KidAt c st d h K) (hc : AncCov c st K.adr) :
    AncOK c st h := fun A he => by rw [entAt_kid_eq hk he]; exact hc

theorem ancCov_root {st : St} {A : Adrs} (hA : par (params c.v) A = none) : AncCov c st A := by
  intro b hb
  cases hb with
  | one h => rw [hA] at h; cases h
  | up h _ => rw [hA] at h; cases h

/-- A handle whose entry is not a thash or PRF request is trivially covered. -/
theorem ancOK_mode {st : St} {h : Nat} {e : Bool × SReq} (he : st.ents[h]? = some e)
    (hm : (e.2.res c.t).mode ≠ 1) : AncOK c st h := by
  intro A ⟨r, hr, hA⟩
  rw [he] at hr
  obtain rfl := Option.some.inj hr
  exfalso; apply hm
  rcases hA with ⟨_, itk, hs, rfl⟩ | ⟨_, ipk, rfl, _⟩ <;> rfl

theorem cov_one {st : St} {h w : Nat} (hl : h < st.ents.length) (ha : AncOK c st h) : Cov c st [.hid h w] := by
  intro i hi; simp [shids] at hi; subst hi; exact ⟨hl, ha⟩

/-- The children of a covered structured entry are covered, and its thash children have
    structured entries of their own. -/
theorem ancCov_kid {st : St} {d j : Nat} {T : Adrs} (hk : KidAt c st d j (.th T)) (hc : AncCov c st T)
    {K : Kid} (hK : K ∈ kids (params c.v) T) :
    AncCov c st K.adr ∧ ∀ B, K = .th B → ∃ d' h, KidAt c st d' h (.th B) := by
  obtain ⟨r, hS, hj⟩ := hk
  cases d with
  | zero => exact hS.elim
  | succ d =>
  obtain ⟨_, _, hD, itk, hs, _, _, hl, hh⟩ := id hS
  have hpar := hD K hK
  refine ⟨fun b hb => ?_, fun B hB => ?_⟩
  · cases hb with
    | one h =>
      rw [hpar] at h
      obtain rfl := Option.some.inj h
      exact ⟨d+1, r, j, hS, hj⟩
    | up h h' =>
      rw [hpar] at h
      obtain rfl := Option.some.inj h
      exact hc b h'
  · subst hB
    obtain ⟨k, hk⟩ := List.mem_iff_getElem?.mp hK
    have hkl := (List.getElem?_eq_some_iff.mp hk).1
    obtain ⟨h', _, hm⟩ := hh k (by omega)
    rw [hk] at hm
    obtain ⟨r', h1, h2⟩ := hm
    exact ⟨d, h', r', h1, h2⟩

/-- Coverage descends along the canonical-children relation from a covered structured entry. -/
theorem ancCov_reach {st : St} {T : Adrs} {K : Kid} (hR : Reach (params c.v) T K) :
    ∀ {d j : Nat}, KidAt c st d j (.th T) → AncCov c st T → AncCov c st K.adr := by
  induction hR with
  | kid hK => intro d j hk hc; exact (ancCov_kid hk hc hK).1
  | down hB _ ih =>
    intro d j hk hc
    obtain ⟨d', h', hk'⟩ := (ancCov_kid hk hc hB).2 _ rfl
    exact ih hk' (ancCov_kid hk hc hB).1

theorem cov_idx {st : St} {v : List SV}
    (h : ∀ j, j < v.length → ∃ i w d K, v[j]? = some (.hid i w) ∧ KidAt c st d i K ∧ AncCov c st K.adr) :
    Cov c st v := by
  intro i hi
  obtain ⟨w, hw⟩ := mem_shids v i hi
  obtain ⟨j, hj⟩ := List.mem_iff_getElem?.mp hw
  obtain ⟨i', w', d, K, hj', h1, h2⟩ := h j (List.getElem?_eq_some_iff.mp hj).1
  rw [hj] at hj'
  obtain ⟨rfl, -⟩ := SV.hid.inj (Option.some.inj hj')
  obtain ⟨e, he, _⟩ := kidAt_mode h1
  exact ⟨lt_entry he, ancOK_kid h1 h2⟩

end

/-! Reachability of signature positions from their roots. -/

theorem reach_trans {p : Params} {X Y : Adrs} {K : Kid} (h1 : Reach p X (.th Y)) (h2 : Reach p Y K) :
    Reach p X K := by
  generalize hY : (Kid.th Y) = KY at h1
  induction h1 with
  | kid hK => subst hY; exact Reach.down hK h2
  | down hB _ ih => exact Reach.down hB (ih hY)

theorem xor1_div (x m : Nat) (hm : 1 ≤ m) : Nat.xor x 1 / 2^m = x / 2^m := by
  obtain ⟨m', rfl⟩ : ∃ m', m = m' + 1 := ⟨m - 1, by omega⟩
  rw [Nat.pow_succ', ← Nat.div_div_eq_div_mul, ← Nat.div_div_eq_div_mul, xor_one]
  congr 1
  split <;> omega

theorem mem_kids_node (p : Params) (a : Adrs) (h i : Nat) :
    Kid.th (nodeA a h i) ∈ kids p (nodeA a (h+1) (i/2)) := by
  rw [kids_node]
  rcases Nat.mod_two_eq_zero_or_one i with h0 | h1
  · rw [show 2 * (i/2) = i by omega]; simp
  · rw [show 2 * (i/2) + 1 = i by omega]; simp

theorem reach_node (p : Params) (a : Adrs) :
    ∀ k h i, Reach p (nodeA a (h+k+1) (i / 2^(k+1))) (.th (nodeA a h i))
  | 0, h, i => Reach.kid (by simpa using mem_kids_node p a h i)
  | k+1, h, i => by
    have ih := reach_node p a k (h+1) (i/2)
    rw [Nat.div_div_eq_div_mul, ← Nat.pow_succ', show h + 1 + k + 1 = h + (k+1) + 1 by omega] at ih
    exact reach_trans ih (Reach.kid (mem_kids_node p a h i))

theorem reach_top (p : Params) (a : Adrs) {h i : Nat} (hh : h < p.hp) (hi : i < 2^(p.hp - h)) :
    Reach p (nodeA a p.hp 0) (.th (nodeA a h i)) := by
  have := reach_node p a (p.hp - h - 1) h i
  rwa [show h + (p.hp - h - 1) + 1 = p.hp by omega, show p.hp - h - 1 + 1 = p.hp - h by omega,
    Nat.div_eq_of_lt hi] at this

theorem par_top (p : Params) (a : Adrs) (hp : 1 ≤ p.hp) : par p (nodeA a p.hp 0) = none := by
  unfold nodeA
  rw [if_neg (by omega)]
  simp [par, Adrs.setType]

section
variable {c : Ctx}

theorem reach_chain (wa : Adrs) (hw : WotsR wa) (j : Nat) (hj : j < (params c.v).len) :
    ∀ m D, D + m = 15 → Reach (params c.v) (compA wa) (chainKid {wa with chain := j} D)
  | 0, D, hD => by
    rw [show D = 15 by omega]
    exact Reach.kid (List.mem_of_getElem? (kids_compA (c := c) wa hw j hj))
  | m+1, D, hD => by
    have ih := reach_chain wa hw j hj m (D+1) (by omega)
    have hk : kids (params c.v) {wa with chain := j, hash := D} = [chainKid {wa with chain := j} D] :=
      kids_chain _ {wa with chain := j} hw.1 D
    have e : chainKid {wa with chain := j} (D+1) = .th {wa with chain := j, hash := D} := by
      simp [chainKid]
    rw [e] at ih
    refine reach_trans ih (Reach.kid ?_)
    rw [hk]; simp

/-- Every handle of an XMSS signature lies under the tree's top. -/
theorem cov_xsig {st : St} {a : Adrs} {idx : Nat} {msg : Bytes} {v : SB}
    (hw : WotsR {a.setType 0 with keypair := idx}) (hidx : idx < 2^(params c.v).hp)
    (hx : XSig c a idx msg v st) {j d : Nat} (ht : KidAt c st d j (.th (nodeA a (params c.v).hp 0))) :
    Cov c st v := by
  have hp1 : 1 ≤ (params c.v).hp := by cases c.v <;> decide
  have hc := ancCov_root (c := c) (st := st) (par_top (params c.v) a hp1)
  have hcomp : Reach (params c.v) (nodeA a (params c.v).hp 0) (.th (compA {a.setType 0 with keypair := idx})) := by
    have := reach_top (params c.v) a (h := 0) (i := idx) (by omega) (by simpa using hidx)
    simpa [nodeA] using this
  obtain ⟨⟨d1, hl1, hv1⟩, ⟨d2, hl2, hv2⟩⟩ := hx
  have h1 : Cov c st (v.take (params c.v).len) := by
    refine cov_idx (fun k hk => ?_)
    obtain ⟨i, hi, hki⟩ := hv1 k (by omega)
    have h15 : (fun j => (wotsDigits (params c.v) msg).getD j 0) k ≤ 15 := digits_le15 (params c.v) msg k
    exact ⟨i, c.n, d1, _, hi, hki, ancCov_reach (reach_trans hcomp
      (reach_chain (c := c) _ hw k (by omega) (15 - (fun j => (wotsDigits (params c.v) msg).getD j 0) k) _
        (by omega))) ht hc⟩
  have h2 : Cov c st (v.drop (params c.v).len) := by
    refine cov_idx (fun k hk => ?_)
    obtain ⟨i, hi, hki⟩ := hv2 k (by omega)
    have hkp : k < (params c.v).hp := by omega
    have hsb := sib_bound _ idx k hidx hkp
    have hlt : Nat.xor (idx / 2^k) 1 < 2^((params c.v).hp - k) := by
      have hM : 2^(params c.v).hp = 2^((params c.v).hp - k) * 2^k := by rw [← Nat.pow_add]; congr 1; omega
      rw [hM] at hsb
      exact Nat.lt_of_succ_le (Nat.le_of_mul_le_mul_right hsb (Nat.two_pow_pos k))
    exact ⟨i, c.n, d2, _, hi, hki, ancCov_reach (reach_top (params c.v) a hkp hlt) ht hc⟩
  have := cov_append h1 h2
  rwa [List.take_append_drop] at this

theorem reveal_root {st : St} (hI : InvS c st) {g : Nat} {A : Adrs} (hk : KidOK c st g (.th A))
    (hA : par (params c.v) A = none) (w : Nat) :
    ∀ h ∈ shids [SV.hid g w], h < st.ents.length ∧ ¬ Prot st h ∧ AncOK c st h :=
  let ⟨_, hd⟩ := hk
  reveal_ok (revOK_one hI hd w) (cov_one (kidAt_rev hI hd).1 (ancOK_kid hd (ancCov_root hA)))

/-- `js_xmssPkFromSig`, recording that the recomputed top covers the signature. -/
theorem js_xmssPkFromSigC (itk : Nat) (a : Adrs) (hl : a.layer < 256^4) (ht : a.tree < 256^8) (idx : Nat)
    (hidx : idx < 2^(params c.v).hp) (sig : SB) (msg : Bytes) {P0 : St → Prop} (hs : StableS c P0)
    (h : ∀ st, InvS c st → P0 st → st.ents[itk]? = some (false, dTk c.n) ∧ XSig c a idx msg sig st) :
    JS c (sXmssPkFromSig (params c.v) [.hid itk 32] a idx sig msg) P0
      (fun v st => ∃ i, v = [.hid i c.n] ∧ KidOK c st i (.th (nodeA a (params c.v).hp 0)) ∧ Cov c st sig) := by
  obtain ⟨_, hH, _⟩ := variant_bounds c.v
  have hw : WotsR {a.setType 0 with keypair := idx} := wotsR_node a hl ht (Nat.lt_of_lt_of_le hidx hH)
  have hs' := stableS_and hs (stable_xsig (c := c) a idx msg sig)
  refine JS.conseq (JS.frame (js_xmssPkFromSig itk a hl ht idx hidx sig msg hs' (fun st hI hp => h st hI hp.1)) hs')
    (fun st hI hp => ⟨hp, (h st hI hp).2⟩) (fun v st hq => ?_)
  obtain ⟨⟨_, hx⟩, i, hv, d, hk⟩ := hq
  exact ⟨i, hv, ⟨d, hk⟩, cov_xsig hw hidx hx hk⟩

end

/-! Hypertree. -/

/-- The layer-`layer` tree above tree index `tree`, and the leaf in it. -/
def htA (p : Params) (layer tree : Nat) : Adrs := {layer := layer, tree := tree / 2^p.hp}

/-- Hypertree signature layers `[layer, layer + r)`, the first signing handle `g`. -/
def HTS (c : Ctx) (st : St) : Nat → Nat → Nat → Nat → SB → Prop
  | _, _, _, 0, v => v = []
  | layer, tree, g, r+1, v => ∃ part rest, v = part ++ rest ∧
      XSig c (htA (params c.v) layer tree) (tree % 2^(params c.v).hp) (sres c.t [.hid g c.n]) part st ∧
      (r = 0 → rest = []) ∧
      (r ≠ 0 → ∃ g', KidOK c st g' (.th (nodeA (htA (params c.v) layer tree) (params c.v).hp 0)) ∧
        HTS c st (layer+1) (tree / 2^(params c.v).hp) g' r rest)

section
variable {c : Ctx}

theorem stable_hts : ∀ (r layer tree g : Nat) (v : SB), StableS c (fun st => HTS c st layer tree g r v)
  | 0, _, _, _, _ => fun _ _ _ _ h => h
  | r+1, layer, tree, g, v => by
    intro st st' hI hg ⟨part, rest, h1, h2, h3, h4⟩
    refine ⟨part, rest, h1, stable_xsig _ _ _ _ st st' hI hg h2, h3, fun hr => ?_⟩
    obtain ⟨g', hk, hh⟩ := h4 hr
    exact ⟨g', kidOK_mono hg hk, stable_hts r _ _ g' rest st st' hI hg hh⟩

theorem revOK_hts {st : St} (hI : InvS c st) : ∀ (r layer tree g : Nat) (v : SB),
    HTS c st layer tree g r v → RevOK st v
  | 0, _, _, _, _, h => by simp only [HTS] at h; subst h; exact revOK_nil
  | r+1, layer, tree, g, v, ⟨part, rest, h1, h2, h3, h4⟩ => by
    subst h1
    refine revOK_append (revOK_xsig hI h2) ?_
    by_cases hr : r = 0
    · rw [h3 hr]; exact revOK_nil
    · obtain ⟨g', _, hh⟩ := h4 hr
      exact revOK_hts hI r _ _ g' rest hh

theorem htA_layer (p : Params) (layer tree : Nat) : (htA p layer tree).layer = layer := rfl
theorem htA_tree (p : Params) (layer tree : Nat) : (htA p layer tree).tree = tree / 2^p.hp := rfl

theorem js_htSignTail (itk ipk : Nat) : ∀ (r layer tree : Nat) (node : SB) {P0 : St → Prop},
    StableS c P0 → layer + r ≤ 256^4 → tree < 256^8 →
    (∀ st, InvS c st → P0 st → st.ents[itk]? = some (false, dTk c.n) ∧ st.ents[ipk]? = some (false, dPrf c.n) ∧
      ∃ g A, node = [.hid g c.n] ∧ KidOK c st g (.th A) ∧ par (params c.v) A = none) →
    JS c (sHtSignTail (params c.v) [.hid itk 32] [.hid ipk 32] [.hid 2 c.n] layer tree node r) P0
      (fun v st => ∃ g, node = [.hid g c.n] ∧ HTS c st layer tree g r v)
  | 0, layer, tree, node, P0, _, _, _, h => by
    simp only [sHtSignTail]
    exact JS.pure' (fun st hI hp => let ⟨_, _, g, _, hn, _⟩ := h st hI hp; ⟨g, hn, rfl⟩)
  | r+1, layer, tree, node, P0, hs, hl, ht, h => by
    obtain ⟨_, hH, _⟩ := variant_bounds c.v
    refine JS.assume (X := ∃ g, node = [.hid g c.n]) (fun st hI hp => let ⟨_, _, g, _, hn, _⟩ := h st hI hp; ⟨g, hn⟩)
      (fun ⟨g, hn⟩ => ?_)
    subst hn
    simp only [sHtSignTail]
    refine JS.reveal (fun st hI hp => ?_) ?_ hs
    · obtain ⟨_, _, g', A, hn, hk, hA⟩ := h st hI hp
      obtain rfl : g = g' := by simpa using hn
      exact reveal_root hI hk hA c.n
    have hp1 : 1 ≤ (params c.v).hp := by cases c.v <;> decide
    have hleaf : tree % 2^(params c.v).hp < 2^(params c.v).hp := Nat.mod_lt _ (Nat.two_pow_pos _)
    have htr : tree / 2^(params c.v).hp < 256^8 := Nat.lt_of_le_of_lt (Nat.div_le_self _ _) ht
    have hla : layer < 256^4 := by omega
    show JS c (do
      let part ← sXmssSign (params c.v) [.hid itk 32] [.hid ipk 32] [.hid 2 c.n]
        (htA (params c.v) layer tree) (tree % 2^(params c.v).hp) (sres c.t [.hid g c.n])
      if r = 0 then pure part else do
        pure PUnit.unit
        let root ← sXmssPkFromSig (params c.v) [.hid itk 32] (htA (params c.v) layer tree)
          (tree % 2^(params c.v).hp) part (sres c.t [.hid g c.n])
        let tail ← sHtSignTail (params c.v) [.hid itk 32] [.hid ipk 32] [.hid 2 c.n] (layer+1)
          (tree / 2^(params c.v).hp) root r
        pure (part ++ tail)) P0 _
    have hx := js_xmssSign (c := c) itk ipk (htA (params c.v) layer tree) hla htr (tree % 2^(params c.v).hp) hleaf
      (sres c.t [.hid g c.n]) hs (fun st hI hp => let ⟨h1, h2, _⟩ := h st hI hp; ⟨h1, h2⟩)
    refine JS.bind hx (fun part => ?_) hs
    have hs1 := stableS_and hs (stable_xsig (c := c) (htA (params c.v) layer tree) (tree % 2^(params c.v).hp)
      (sres c.t [.hid g c.n]) part)
    refine JS.ite (fun hr => JS.pure' (fun st _ hp => ⟨g, rfl, part, [], by simp, hp.2, fun _ => rfl,
      fun h' => absurd hr h'⟩)) (fun hr => ?_)
    refine JS.bind JS.unit (fun _ => ?_) hs1
    have hs2 := stableS_and hs1 (stableS_true (c := c))
    refine JS.bind (js_xmssPkFromSig itk (htA (params c.v) layer tree) hla htr _ hleaf part _ hs2
      (fun st hI hp => ⟨(h st hI hp.1.1).1, hp.1.2⟩)) (fun root => ?_) hs2
    refine JS.obtain (X := fun i st => KidOK c st i (.th (nodeA (htA (params c.v) layer tree) (params c.v).hp 0)))
      (fun g' hg' => ?_)
    subst hg'
    have hs3 := stableS_and hs2 (stableS_kid (c := c) g' (.th (nodeA (htA (params c.v) layer tree) (params c.v).hp 0)))
    refine JS.bind (js_htSignTail itk ipk r (layer+1) (tree / 2^(params c.v).hp) [.hid g' c.n] hs3 (by omega) htr
      (fun st hI hp => ⟨(h st hI hp.1.1.1).1, (h st hI hp.1.1.1).2.1, g', _, rfl, hp.2, par_top _ _ hp1⟩))
      (fun tail => ?_) hs3
    refine JS.pure' (fun st _ hp => ⟨g, rfl, part, tail, rfl, hp.1.1.1.2, fun h' => absurd h' hr, fun _ => ?_⟩)
    obtain ⟨g'', hg'', hh⟩ := hp.2
    obtain rfl : g' = g'' := by simpa using hg''
    exact ⟨g', hp.1.2, hh⟩
end

/-- A full hypertree signature of the handle `g` at (`tree`, `leaf`). -/
def HSig (c : Ctx) (st : St) (g tree leaf : Nat) (v : SB) : Prop :=
  ∃ first tail g', v = first ++ tail ∧ XSig c {tree := tree} leaf (sres c.t [.hid g c.n]) first st ∧
    KidOK c st g' (.th (nodeA {tree := tree} (params c.v).hp 0)) ∧ HTS c st 1 tree g' ((params c.v).d - 1) tail

section
variable {c : Ctx}

theorem stable_hsig (g tree leaf : Nat) (v : SB) : StableS c (fun st => HSig c st g tree leaf v) := by
  intro st st' hI hg ⟨first, tail, g', h1, h2, h3, h4⟩
  exact ⟨first, tail, g', h1, stable_xsig _ _ _ _ st st' hI hg h2, kidOK_mono hg h3,
    stable_hts _ _ _ _ _ st st' hI hg h4⟩

theorem revOK_hsig {st : St} (hI : InvS c st) {g tree leaf : Nat} {v : SB} (h : HSig c st g tree leaf v) :
    RevOK st v := by
  obtain ⟨first, tail, g', rfl, h2, _, h4⟩ := h
  exact revOK_append (revOK_xsig hI h2) (revOK_hts hI _ _ _ _ _ h4)

theorem js_htSign (itk ipk : Nat) (msg : SB) (idxTree idxLeaf : Nat) (ht : idxTree < 256^8)
    (hleaf : idxLeaf < 2^(params c.v).hp) {P0 : St → Prop} (hs : StableS c P0)
    (h : ∀ st, InvS c st → P0 st → st.ents[itk]? = some (false, dTk c.n) ∧ st.ents[ipk]? = some (false, dPrf c.n) ∧
      ∃ g A, msg = [.hid g c.n] ∧ KidOK c st g (.th A) ∧ par (params c.v) A = none) :
    JS c (sHtSign (params c.v) [.hid itk 32] [.hid ipk 32] [.hid 2 c.n] msg idxTree idxLeaf) P0
      (fun v st => ∃ g, msg = [.hid g c.n] ∧ HSig c st g idxTree idxLeaf v) := by
  obtain ⟨_, hH, hd, _⟩ := variant_bounds c.v
  refine JS.assume (X := ∃ g, msg = [.hid g c.n]) (fun st hI hp => let ⟨_, _, g, _, hn, _⟩ := h st hI hp; ⟨g, hn⟩)
    (fun ⟨g, hn⟩ => ?_)
  subst hn
  simp only [sHtSign]
  refine JS.reveal (fun st hI hp => ?_) ?_ hs
  · obtain ⟨_, _, g', A, hn, hk, hA⟩ := h st hI hp
    obtain rfl : g = g' := by simpa using hn
    exact reveal_root hI hk hA c.n
  have hp1 : 1 ≤ (params c.v).hp := by cases c.v <;> decide
  have hl0 : ({tree := idxTree} : Adrs).layer < 256^4 := by show 0 < 256^4; decide
  refine JS.bind (js_xmssSign itk ipk {tree := idxTree} hl0 ht idxLeaf hleaf _ hs
    (fun st hI hp => let ⟨h1, h2, _⟩ := h st hI hp; ⟨h1, h2⟩)) (fun first => ?_) hs
  have hs1 := stableS_and hs (stable_xsig (c := c) ({tree := idxTree} : Adrs) idxLeaf (sres c.t [.hid g c.n]) first)
  refine JS.bind (js_xmssPkFromSig itk {tree := idxTree} hl0 ht idxLeaf hleaf first _ hs1
    (fun st hI hp => ⟨(h st hI hp.1).1, hp.2⟩)) (fun root => ?_) hs1
  refine JS.obtain (X := fun i st => KidOK c st i (.th (nodeA {tree := idxTree} (params c.v).hp 0)))
    (fun g' hg' => ?_)
  subst hg'
  have hs2 := stableS_and hs1 (stableS_kid (c := c) g' (.th (nodeA {tree := idxTree} (params c.v).hp 0)))
  refine JS.bind (js_htSignTail itk ipk ((params c.v).d - 1) 1 idxTree [.hid g' c.n] hs2 (by omega) ht
    (fun st hI hp => ⟨(h st hI hp.1.1).1, (h st hI hp.1.1).2.1, g', _, rfl, hp.2, par_top _ _ hp1⟩))
    (fun tail => ?_) hs2
  refine JS.pure' (fun st _ hp => ⟨g, rfl, first, tail, g', rfl, hp.1.1.2, hp.1.2, ?_⟩)
  obtain ⟨g'', hg'', hh⟩ := hp.2
  obtain rfl : g' = g'' := by simpa using hg''
  exact hh

theorem js_htRootTail (itk : Nat) : ∀ (r layer tree g : Nat) (sig : SB) {P0 : St → Prop},
    StableS c P0 → layer + r ≤ 256^4 → tree < 256^8 →
    (∀ st, InvS c st → P0 st → st.ents[itk]? = some (false, dTk c.n) ∧ HTS c st layer tree g r sig ∧
      ∃ A, KidOK c st g (.th A) ∧ par (params c.v) A = none) →
    JS c (sHtRootTail (params c.v) [.hid itk 32] layer tree [.hid g c.n] sig r) P0
      (fun v st => (∃ i A, v = [.hid i c.n] ∧ KidOK c st i (.th A) ∧ par (params c.v) A = none) ∧ Cov c st sig)
  | 0, layer, tree, g, sig, P0, _, _, _, h => by
    simp only [sHtRootTail]
    refine JS.pure' (fun st hI hp => ?_)
    obtain ⟨_, hh, A, hk, hA⟩ := h st hI hp
    simp only [HTS] at hh
    subst hh
    exact ⟨⟨g, A, rfl, hk, hA⟩, cov_nil⟩
  | r+1, layer, tree, g, sig, P0, hs, hl, ht, h => by
    obtain ⟨_, hH, _⟩ := variant_bounds c.v
    have hp1 : 1 ≤ (params c.v).hp := by cases c.v <;> decide
    have hleaf : tree % 2^(params c.v).hp < 2^(params c.v).hp := Nat.mod_lt _ (Nat.two_pow_pos _)
    have htr : tree / 2^(params c.v).hp < 256^8 := Nat.lt_of_le_of_lt (Nat.div_le_self _ _) ht
    have hla : layer < 256^4 := by omega
    have hsplit : ∀ st, InvS c st → P0 st →
        XSig c (htA (params c.v) layer tree) (tree % 2^(params c.v).hp) (sres c.t [.hid g c.n])
          (sig.take ((params c.v).len + (params c.v).hp)) st ∧
        (r = 0 → sig.drop ((params c.v).len + (params c.v).hp) = []) ∧
        (r ≠ 0 → ∃ g', KidOK c st g' (.th (nodeA (htA (params c.v) layer tree) (params c.v).hp 0)) ∧
          HTS c st (layer+1) (tree / 2^(params c.v).hp) g' r (sig.drop ((params c.v).len + (params c.v).hp))) := by
      intro st hI hp
      obtain ⟨_, ⟨part, rest, rfl, h2, h3, h4⟩, _⟩ := h st hI hp
      have hlen := xsig_len h2
      rw [List.take_left' hlen, List.drop_left' hlen]
      exact ⟨h2, h3, h4⟩
    simp only [sHtRootTail]
    show JS c (do
      let root ← Prog.reveal [.hid g c.n] (fun nb => sXmssPkFromSig (params c.v) [.hid itk 32]
        (htA (params c.v) layer tree) (tree % 2^(params c.v).hp)
        (sig.take ((params c.v).len + (params c.v).hp)) nb)
      sHtRootTail (params c.v) [.hid itk 32] (layer+1) (tree / 2^(params c.v).hp) root
        (sig.drop ((params c.v).len + (params c.v).hp)) r) P0 _
    refine JS.bind (Q := fun v st => ∃ i, v = [.hid i c.n] ∧
        (KidOK c st i (.th (nodeA (htA (params c.v) layer tree) (params c.v).hp 0)) ∧
          Cov c st (sig.take ((params c.v).len + (params c.v).hp))))
      (JS.reveal (fun st hI hp => ?_) ?_ hs) (fun root => ?_) hs
    · obtain ⟨_, _, A, hk, hA⟩ := h st hI hp
      exact reveal_root hI hk hA c.n
    · exact js_xmssPkFromSigC itk (htA (params c.v) layer tree) hla htr _ hleaf _ _ hs
        (fun st hI hp => ⟨(h st hI hp).1, (hsplit st hI hp).1⟩)
    refine JS.obtain (X := fun i st => KidOK c st i (.th (nodeA (htA (params c.v) layer tree) (params c.v).hp 0)) ∧
      Cov c st (sig.take ((params c.v).len + (params c.v).hp))) (fun i hi => ?_)
    subst hi
    have hs1 := stableS_and hs (stableS_and (stableS_kid (c := c) i (.th (nodeA (htA (params c.v) layer tree) (params c.v).hp 0)))
      (stable_cov (c := c) (sig.take ((params c.v).len + (params c.v).hp))))
    refine JS.conseq (JS.frame (js_htRootTail itk r (layer+1) _ i _ hs1 (by omega) htr
      (fun st hI hp => ⟨(h st hI hp.1).1, ?_, _, hp.2.1, par_top _ _ hp1⟩)) hs1) (fun _ _ hp => hp)
      (fun v st hq => ⟨hq.2.1, by have := cov_append hq.1.2.2 hq.2.2; rwa [List.take_append_drop] at this⟩)
    obtain ⟨_, h3, h4⟩ := hsplit st hI hp.1
    by_cases hr : r = 0
    · subst hr; exact h3 rfl
    · obtain ⟨g', hk', hh⟩ := h4 hr
      rw [kidOK_unique_th hI hp.2.1 hk']
      exact hh

theorem js_htRoot (itk : Nat) (sig msg : SB) (idxTree idxLeaf : Nat) (ht : idxTree < 256^8)
    (hleaf : idxLeaf < 2^(params c.v).hp) {P0 : St → Prop} (hs : StableS c P0)
    (h : ∀ st, InvS c st → P0 st → st.ents[itk]? = some (false, dTk c.n) ∧
      ∃ g A, msg = [.hid g c.n] ∧ KidOK c st g (.th A) ∧ par (params c.v) A = none ∧
        HSig c st g idxTree idxLeaf sig) :
    JS c (sHtRoot (params c.v) [.hid itk 32] sig msg idxTree idxLeaf) P0
      (fun v st => (∃ i A, v = [.hid i c.n] ∧ KidOK c st i (.th A) ∧ par (params c.v) A = none) ∧
        Cov c st sig) := by
  obtain ⟨_, hH, hd, _⟩ := variant_bounds c.v
  have hp1 : 1 ≤ (params c.v).hp := by cases c.v <;> decide
  refine JS.assume (X := ∃ g, msg = [.hid g c.n]) (fun st hI hp => let ⟨_, g, _, hn, _⟩ := h st hI hp; ⟨g, hn⟩)
    (fun ⟨g, hn⟩ => ?_)
  subst hn
  have hl0 : ({tree := idxTree} : Adrs).layer < 256^4 := by show 0 < 256^4; decide
  have hsplit : ∀ st, InvS c st → P0 st →
      XSig c {tree := idxTree} idxLeaf (sres c.t [.hid g c.n]) (sig.take ((params c.v).len + (params c.v).hp)) st ∧
      ∃ g', KidOK c st g' (.th (nodeA {tree := idxTree} (params c.v).hp 0)) ∧
        HTS c st 1 idxTree g' ((params c.v).d - 1) (sig.drop ((params c.v).len + (params c.v).hp)) := by
    intro st hI hp
    obtain ⟨_, g', A, hn, _, _, first, tail, g'', rfl, h2, h3, h4⟩ := h st hI hp
    obtain rfl : g = g' := by simpa using hn
    have hlen := xsig_len h2
    rw [List.take_left' hlen, List.drop_left' hlen]
    exact ⟨h2, g'', h3, h4⟩
  simp only [sHtRoot]
  refine JS.bind (Q := fun v st => ∃ i, v = [.hid i c.n] ∧
      (KidOK c st i (.th (nodeA {tree := idxTree} (params c.v).hp 0)) ∧
        Cov c st (sig.take ((params c.v).len + (params c.v).hp))))
    (JS.reveal (fun st hI hp => ?_) ?_ hs) (fun node => ?_) hs
  · obtain ⟨_, g', A, hn, hk, hA, _⟩ := h st hI hp
    obtain rfl : g = g' := by simpa using hn
    exact reveal_root hI hk hA c.n
  · exact js_xmssPkFromSigC itk {tree := idxTree} hl0 ht _ hleaf _ _ hs
      (fun st hI hp => ⟨(h st hI hp).1, (hsplit st hI hp).1⟩)
  refine JS.obtain (X := fun i st => KidOK c st i (.th (nodeA {tree := idxTree} (params c.v).hp 0)) ∧
    Cov c st (sig.take ((params c.v).len + (params c.v).hp))) (fun i hi => ?_)
  subst hi
  have hs1 := stableS_and hs (stableS_and (stableS_kid (c := c) i (.th (nodeA {tree := idxTree} (params c.v).hp 0)))
    (stable_cov (c := c) (sig.take ((params c.v).len + (params c.v).hp))))
  refine JS.conseq (JS.frame (js_htRootTail itk _ 1 idxTree i _ hs1 (by omega) ht
    (fun st hI hp => ⟨(h st hI hp.1).1, ?_, _, hp.2.1, par_top _ _ hp1⟩)) hs1) (fun _ _ hp => hp)
    (fun v st hq => ⟨hq.2.1, by have := cov_append hq.1.2.2 hq.2.2; rwa [List.take_append_drop] at this⟩)
  obtain ⟨_, g', hk', hh⟩ := hsplit st hI hp.1
  rw [kidOK_unique_th hI hp.2.1 hk']
  exact hh

end

/-! Slots: a list whose `j`-th handle is the canonical child `K j`. -/

/-- Positions `[0, k)` of `v` hold the canonical children `K j`. -/
def SlotsAt (c : Ctx) (K : Nat → Kid) (k : Nat) (v : SB) (st : St) : Prop :=
  ∃ d, v.length = k ∧ ∀ j, j < k → ∃ h, v[j]? = some (.hid h c.n) ∧ KidAt c st d h (K j)

section
variable {c : Ctx}

theorem stable_slotsAt (K : Nat → Kid) (k : Nat) (v : SB) : StableS c (SlotsAt c K k v) :=
  fun _ _ _ hg ⟨d, hl, hv⟩ => ⟨d, hl, fun j hj => let ⟨h, h1, h2⟩ := hv j hj; ⟨h, h1, kidAt_mono hg h2⟩⟩

theorem slotsAt_nil (K : Nat → Kid) (st : St) : SlotsAt c K 0 [] st := ⟨0, rfl, fun _ hj => absurd hj (by omega)⟩

theorem slotsAt_snoc {K : Nat → Kid} {k : Nat} {v : SB} {st : St} {d yh : Nat}
    (hv : SlotsAt c K k v st) (hy : KidAt c st d yh (K k)) : SlotsAt c K (k+1) (v ++ [.hid yh c.n]) st := by
  obtain ⟨d0, hl, hv⟩ := hv
  refine ⟨max d0 d, by simp [hl], fun j hj => ?_⟩
  by_cases hjk : j < k
  · obtain ⟨h, h1, h2⟩ := hv j hjk
    exact ⟨h, by rw [List.getElem?_append_left (by omega)]; exact h1, kidAt_fuel (Nat.le_max_left _ _) h2⟩
  · have hj : j = k := by omega
    subst hj
    exact ⟨yh, by rw [List.getElem?_append_right (by omega)]; simp [hl], kidAt_fuel (Nat.le_max_right _ _) hy⟩

theorem revOK_slotsAt {st : St} (hI : InvS c st) {K : Nat → Kid} {k : Nat} {v : SB}
    (h : SlotsAt c K k v st) : RevOK st v := by
  obtain ⟨d, hl, hv⟩ := h
  refine revOK_idx (fun j hj => ?_)
  obtain ⟨i, h1, h2⟩ := hv j (by omega)
  exact ⟨i, c.n, h1, kidAt_rev hI h2⟩

end

/-! FORS. -/

/-- FORS node at height `h`, global index `idx`, of the FORS key at `a`. -/
def fA (a : Adrs) (h idx : Nat) : Adrs := {a with chain := h, hash := idx}
/-- FORS secret at global index `idx`. -/
def fkA (a : Adrs) (idx : Nat) : Adrs := {a.setType 6 with keypair := a.keypair, hash := idx}
/-- FORS roots address. -/
def frA (a : Adrs) : Adrs := {a.setType 4 with keypair := a.keypair}

/-- A FORS key address in range. -/
def ForsR (a : Adrs) : Prop := a.kind = 3 ∧ a.layer < 256^4 ∧ a.tree < 256^8 ∧ a.keypair < 256^4

theorem kids_fA_succ (p : Params) (a : Adrs) (ha : a.kind = 3) (h idx : Nat) :
    kids p (fA a (h+1) idx) = [.th (fA a h (2*idx)), .th (fA a h (2*idx+1))] := by
  unfold kids fA; simp [ha]

theorem kids_fA_zero (p : Params) (a : Adrs) (ha : a.kind = 3) (idx : Nat) :
    kids p (fA a 0 idx) = [.pf (fkA a idx)] := by
  unfold kids fA fkA; simp [ha, Adrs.setType]

theorem kids_frA (p : Params) (a : Adrs) (ha : a.kind = 3) :
    kids p (frA a) = (List.range p.k).map (fun i => .th (fA a p.a i)) := by
  unfold kids frA fA
  simp only [Adrs.setType]
  simp
  cases a; simp_all

theorem dsmOK_fA_succ (p : Params) (a : Adrs) (ha : a.kind = 3) (h idx : Nat) (hh : h + 1 ≤ p.a) :
    DSMOK p (fA a (h+1) idx) := by
  intro K hK
  rw [kids_fA_succ p a ha] at hK
  simp only [List.mem_cons, List.mem_nil_iff, or_false] at hK
  have hlt : h < p.a := by omega
  rcases hK with rfl | rfl <;> cases a <;> simp_all [Kid.adr, par, fA] <;> omega

theorem dsmOK_fA_zero (p : Params) (a : Adrs) (ha : a.kind = 3) (idx : Nat) : DSMOK p (fA a 0 idx) := by
  intro K hK
  rw [kids_fA_zero p a ha] at hK
  simp only [List.mem_singleton] at hK
  subst hK
  cases a; simp_all [Kid.adr, par, fkA, fA, Adrs.setType]

theorem dsmOK_frA (p : Params) (a : Adrs) (ha : a.kind = 3) : DSMOK p (frA a) := by
  intro K hK
  rw [kids_frA p a ha] at hK
  simp only [List.mem_map, List.mem_range] at hK
  obtain ⟨i, _, rfl⟩ := hK
  cases a; simp_all [Kid.adr, par, fA, frA, Adrs.setType]

theorem fA_inRange {a : Adrs} (ha : ForsR a) {h idx : Nat} (hh : h < 256^4) (hi : idx < 256^4) :
    (fA a h idx).InRange := by
  obtain ⟨h1, h2, h3, h4⟩ := ha
  exact ⟨h2, h3, by simp [fA, h1], h4, hh, hi⟩

theorem fkA_inRange {a : Adrs} (ha : ForsR a) {idx : Nat} (hi : idx < 256^4) : (fkA a idx).InRange := by
  obtain ⟨_, h2, h3, h4⟩ := ha
  refine ⟨h2, h3, ?_, h4, ?_, hi⟩ <;> simp [fkA, Adrs.setType]

theorem frA_inRange {a : Adrs} (ha : ForsR a) : (frA a).InRange := by
  obtain ⟨_, h2, h3, h4⟩ := ha
  refine ⟨h2, h3, ?_, h4, ?_, ?_⟩ <;> simp [frA, Adrs.setType]

section
variable {c : Ctx}

theorem js_forsNode (itk ipk : Nat) (a : Adrs) (ha : ForsR a) :
    ∀ (height idx : Nat) {P0 : St → Prop}, StableS c P0 → height ≤ (params c.v).a →
    (idx+1)*2^height ≤ (params c.v).k * 2^(params c.v).a →
    (∀ st, InvS c st → P0 st → st.ents[itk]? = some (false, dTk c.n) ∧ st.ents[ipk]? = some (false, dPrf c.n)) →
    JS c (sForsNode (params c.v) [.hid itk 32] [.hid ipk 32] [.hid 2 c.n] a idx height) P0
      (fun v st => ∃ i, v = [.hid i c.n] ∧ KidOK c st i (.th (fA a height idx)))
  | 0, idx, P0, hs, _, hb, h => by
    obtain ⟨_, _, _, hk, ha4, _⟩ := variant_bounds c.v
    have hi : idx < 256^4 := by simp at hb; omega
    show JS c (do
      let sk ← sPrf (params c.v) [.hid ipk 32] [.hid 2 c.n] (fkA a idx)
      sThash (params c.v) [.hid itk 32] (fA a 0 idx) sk) P0 _
    have hB := fkA_inRange ha hi
    refine JS.bind (js_prf (fkA a idx) hB (Or.inr (by simp [fkA, Adrs.setType])) ipk
      (fun st hI hp => (h st hI hp).2)) (fun sk => ?_) hs
    refine JS.obtain (X := fun i st => KidOK c st i (.pf (fkA a idx))) (fun i hi' => ?_)
    subst hi'
    refine js_thash _ _ itk (dsmOK_fA_zero _ a ha.1 idx) (fun st hI hp => ⟨(h st hI hp.1).1, ?_⟩)
    obtain ⟨d, hd⟩ := hp.2
    refine ⟨d, fA_inRange ha (by omega) hi, by rw [kids_fA_zero _ a ha.1]; simp,
      by rw [kids_fA_zero _ a ha.1]; rfl, fun k hk => ?_⟩
    simp at hk; subst hk
    refine ⟨i, rfl, fun K hK => ?_⟩
    rw [kids_fA_zero _ a ha.1] at hK
    simp at hK; subst hK; exact hd
  | height+1, idx, P0, hs, hh, hb, h => by
    obtain ⟨_, _, _, hk, ha4, _⟩ := variant_bounds c.v
    have hi : idx < 256^4 := by
      have := Nat.le_trans (Nat.le_mul_of_pos_right _ (Nat.two_pow_pos (height+1))) hb; omega
    show JS c (do
      let left ← sForsNode (params c.v) [.hid itk 32] [.hid ipk 32] [.hid 2 c.n] a (2*idx) height
      let right ← sForsNode (params c.v) [.hid itk 32] [.hid ipk 32] [.hid 2 c.n] a (2*idx+1) height
      sThash (params c.v) [.hid itk 32] (fA a (height+1) idx) (left++right)) P0 _
    refine JS.bind (js_forsNode itk ipk a ha height (2*idx) hs (by omega) (by
      calc (2*idx+1)*2^height ≤ (idx+1)*2^(height+1) := by rw [Nat.pow_succ, lin1, lin2]; omega
        _ ≤ _ := hb) h) (fun left => ?_) hs
    refine JS.obtain (X := fun i st => KidOK c st i (.th (fA a height (2*idx)))) (fun il hil => ?_)
    subst hil
    have hs1 := stableS_and hs (stableS_kid (c := c) il (.th (fA a height (2*idx))))
    refine JS.bind (js_forsNode itk ipk a ha height (2*idx+1) hs1 (by omega) (by
      calc (2*idx+1+1)*2^height = (idx+1)*2^(height+1) := by rw [Nat.pow_succ, lin3, lin2]
        _ ≤ _ := hb) (fun st hI hp => h st hI hp.1)) (fun right => ?_) hs1
    refine JS.obtain (X := fun i st => KidOK c st i (.th (fA a height (2*idx+1)))) (fun ir hir => ?_)
    subst hir
    refine js_thash _ _ itk (dsmOK_fA_succ _ a ha.1 height idx hh) (fun st hI hp => ⟨(h st hI hp.1.1).1, ?_⟩)
    obtain ⟨d1, hd1⟩ := hp.1.2
    obtain ⟨d2, hd2⟩ := hp.2
    refine ⟨max d1 d2, fA_inRange ha (by omega) hi, by rw [kids_fA_succ _ a ha.1]; simp,
      by rw [kids_fA_succ _ a ha.1]; rfl, fun k hk => ?_⟩
    rw [kids_fA_succ _ a ha.1]
    have hk2 : k < 2 := by simpa using hk
    rcases k with _ | _ | k
    · refine ⟨il, rfl, fun K hK => ?_⟩
      simp at hK; subst hK; exact kidAt_fuel (Nat.le_max_left _ _) hd1
    · refine ⟨ir, rfl, fun K hK => ?_⟩
      simp at hK; subst hK; exact kidAt_fuel (Nat.le_max_right _ _) hd2
    · omega

end

/-- The `i`-th FORS digit. -/
def fdig (p : Params) (md : Bytes) (i : Nat) : Nat := (base2b md p.a p.k).getD i 0
/-- The global leaf index of tree `i`. -/
def fG (p : Params) (md : Bytes) (i : Nat) : Nat := i*2^p.a + fdig p md i
/-- The canonical child at position `q` of a FORS signature. -/
def fslot (p : Params) (a : Adrs) (md : Bytes) (q : Nat) : Kid :=
  if q % (p.a+1) = 0 then .pf (fkA a (fG p md (q / (p.a+1))))
  else .th (fA a (q % (p.a+1) - 1) (Nat.xor (fG p md (q / (p.a+1)) / 2^(q % (p.a+1) - 1)) 1))

theorem slot_mod (A i j : Nat) (hj : j < A + 1) : (i*(A+1)+j) % (A+1) = j ∧ (i*(A+1)+j) / (A+1) = i := by
  rw [show i*(A+1)+j = j + (A+1)*i by rw [Nat.mul_comm]; omega]
  refine ⟨by rw [Nat.add_mul_mod_self_left, Nat.mod_eq_of_lt hj], ?_⟩
  rw [Nat.add_mul_div_left _ _ (by omega), Nat.div_eq_of_lt hj, Nat.zero_add]

theorem fors_sib (A i dig l : Nat) (hl : l < A) :
    i*2^(A-l) + Nat.xor (dig / 2^l) 1 = Nat.xor ((i*2^A + dig) / 2^l) 1 := by
  have hpos : 0 < 2^l := Nat.two_pow_pos l
  have hA : 2^A = 2^(A-l) * 2^l := by rw [← Nat.pow_add]; congr 1; omega
  have hq : (i*2^A + dig) / 2^l = i*2^(A-l) + dig / 2^l := by
    rw [hA, Nat.mul_comm (2^(A-l)) (2^l), Nat.mul_left_comm, Nat.add_comm]
    rw [Nat.add_mul_div_left _ _ hpos]; omega
  have hev : i*2^(A-l) % 2 = 0 := by
    rw [show A - l = (A - l - 1) + 1 by omega, Nat.pow_succ, ← Nat.mul_assoc]; simp
  rw [hq, xor_one, xor_one]
  generalize i*2^(A-l) = E at *
  generalize dig / 2^l = x
  split <;> split <;> omega

theorem fors_sib_bound (A i dig l k : Nat) (hl : l < A) (hd : dig < 2^A) (hi : i < k) :
    (i*2^(A-l) + Nat.xor (dig / 2^l) 1 + 1) * 2^l ≤ k * 2^A := by
  have hs := sib_bound A dig l hd hl
  have hA : 2^A = 2^(A-l) * 2^l := by rw [← Nat.pow_add]; congr 1; omega
  have e1 : (i*2^(A-l) + Nat.xor (dig / 2^l) 1 + 1) * 2^l = i*2^A + (Nat.xor (dig / 2^l) 1 + 1) * 2^l := by
    rw [hA, Nat.add_assoc, Nat.add_mul, Nat.mul_assoc]
  rw [e1]
  calc i*2^A + (Nat.xor (dig / 2^l) 1 + 1) * 2^l ≤ i*2^A + 2^A := Nat.add_le_add_left hs _
    _ = (i+1)*2^A := by rw [Nat.add_mul, Nat.one_mul]
    _ ≤ k*2^A := Nat.mul_le_mul_right _ hi

theorem fdig_lt (p : Params) (md : Bytes) (i : Nat) (hi : i < p.k) : fdig p md i < 2^p.a := by
  unfold fdig
  have hl : i < (base2b md p.a p.k).length := by rw [base2b_length]; exact hi
  rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hl, Option.getD_some]
  exact base2b_digit_bound md p.a p.k _ (List.getElem_mem hl)

theorem fslot_secret (p : Params) (a : Adrs) (md : Bytes) (i : Nat) :
    fslot p a md (i*(p.a+1)) = .pf (fkA a (fG p md i)) := by
  have := slot_mod p.a i 0 (by omega)
  rw [Nat.add_zero] at this
  simp [fslot, this.1, this.2]

theorem fslot_auth (p : Params) (a : Adrs) (md : Bytes) (i l : Nat) (hl : l < p.a) :
    fslot p a md (i*(p.a+1)+1+l) = .th (fA a l (Nat.xor (fG p md i / 2^l) 1)) := by
  have := slot_mod p.a i (1+l) (by omega)
  rw [← Nat.add_assoc] at this
  unfold fslot
  rw [this.1, this.2, if_neg (by omega)]
  simp

section
variable {c : Ctx}

theorem js_forsSign (itk ipk : Nat) (a : Adrs) (ha : ForsR a) (md : Bytes) {P0 : St → Prop} (hs : StableS c P0)
    (h : ∀ st, InvS c st → P0 st → st.ents[itk]? = some (false, dTk c.n) ∧ st.ents[ipk]? = some (false, dPrf c.n)) :
    JS c (sForsSign (params c.v) [.hid itk 32] [.hid ipk 32] [.hid 2 c.n] a md) P0
      (SlotsAt c (fslot (params c.v) a md) ((params c.v).k * ((params c.v).a + 1))) := by
  obtain ⟨_, _, _, hkA, haA, _⟩ := variant_bounds c.v
  simp only [sForsSign]
  have hl : (base2b md (params c.v).a (params c.v).k).zipIdx.length = (params c.v).k := by simp [base2b_length]
  refine JS.bind (JS.loopI' _ _ (fun k v st => SlotsAt c (fslot (params c.v) a md) (k * ((params c.v).a + 1)) v st)
    hs (fun k v => stable_slotsAt _ _ v) [] (fun st _ _ => by simpa using slotsAt_nil (c := c) _ st)
    (fun i hi v => ?_)) (fun r => JS.pure' (fun st _ hp => by rw [hl] at hp; exact hp.2)) hs
  rw [hl] at hi
  have hel : (base2b md (params c.v).a (params c.v).k).zipIdx[i]'(by rw [hl]; exact hi) = (fdig (params c.v) md i, i) := by
    have hi' : i < (base2b md (params c.v).a (params c.v).k).length := by rw [base2b_length]; exact hi
    simp only [List.getElem_zipIdx, Nat.zero_add, fdig]
    rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hi', Option.getD_some]
  simp only [hel]
  have hdig := fdig_lt (params c.v) md i hi
  have hP := stableS_and hs (stable_slotsAt (c := c) (fslot (params c.v) a md) (i * ((params c.v).a + 1)) v)
  have hGi : fG (params c.v) md i < 256^4 := by
    unfold fG
    have : (i+1)*2^(params c.v).a ≤ (params c.v).k*2^(params c.v).a := Nat.mul_le_mul_right _ hi
    rw [Nat.add_mul, Nat.one_mul] at this; omega
  simp only [sForsSecret]
  show JS c (do
    let sk ← sPrf (params c.v) [.hid ipk 32] [.hid 2 c.n] (fkA a (fG (params c.v) md i))
    let r ← forIn (List.range (params c.v).a) (v ++ sk) fun level r => do
      let node ← sForsNode (params c.v) [SV.hid itk 32] [SV.hid ipk 32] [SV.hid 2 c.n] a
        (i * 2 ^ ((params c.v).a - level) + (fdig (params c.v) md i / 2 ^ level).xor 1) level
      pure PUnit.unit
      pure (ForInStep.yield (r ++ node))
    pure PUnit.unit
    pure (ForInStep.yield r)) _ _
  refine JS.bind (js_prf _ (fkA_inRange ha hGi) (Or.inr (by simp [fkA, Adrs.setType])) ipk
    (fun st hI hp => (h st hI hp.1).2)) (fun sk => ?_) hP
  refine JS.obtain (X := fun j st => KidOK c st j (.pf (fkA a (fG (params c.v) md i)))) (fun j hj => ?_)
  subst hj
  have hPj := stableS_and hP (stableS_kid (c := c) j (.pf (fkA a (fG (params c.v) md i))))
  refine JS.bind (JS.loopI' (List.range (params c.v).a) _
    (fun l w st => SlotsAt c (fslot (params c.v) a md) (i * ((params c.v).a + 1) + 1 + l) w st)
    hPj (fun l w => stable_slotsAt _ _ w) _ (fun st _ hp => ?_) (fun l hl' w => ?_))
    (fun r => ?_) hPj
  · obtain ⟨d, hd⟩ := hp.2
    exact slotsAt_snoc (d := d) hp.1.2 (by rw [fslot_secret]; exact hd)
  · rw [List.length_range] at hl'
    rw [List.getElem_range]
    have hP2 := stableS_and hPj (stable_slotsAt (c := c) (fslot (params c.v) a md)
      (i * ((params c.v).a + 1) + 1 + l) w)
    refine JS.bind (js_forsNode itk ipk a ha l _ hP2 (by omega)
      (fors_sib_bound _ i _ l _ hl' hdig hi) (fun st hI hp => h st hI hp.1.1.1)) (fun node => ?_) hP2
    rw [fors_sib _ i _ l hl']
    refine JS.obtain (X := fun j st => KidOK c st j (.th (fA a l (Nat.xor (fG (params c.v) md i / 2^l) 1))))
      (fun j hj => ?_)
    subst hj
    refine JS.bind JS.unit (fun _ => JS.pure' (fun st _ hp => ?_))
      (stableS_and hP2 (stableS_kid (c := c) j _))
    obtain ⟨d, hd⟩ := hp.1.2
    refine ⟨_, rfl, ?_⟩
    have := slotsAt_snoc (d := d) hp.1.1.2 (by rw [fslot_auth _ a md i l hl']; exact hd)
    rwa [show i * ((params c.v).a + 1) + 1 + l + 1 = i * ((params c.v).a + 1) + 1 + (l+1) by omega] at this
  · rw [List.length_range]
    refine JS.bind JS.unit (fun _ => JS.pure' (fun st _ hp => ⟨_, rfl, ?_⟩)) (stableS_and hPj (stable_slotsAt _ _ r))
    rw [show (i+1) * ((params c.v).a + 1) = i * ((params c.v).a + 1) + 1 + (params c.v).a by
      rw [Nat.succ_mul]; omega]
    exact hp.1.2
end

theorem fors_div (A i dig l : Nat) (hl : l < A) :
    (i*2^A + dig) / 2^l = i*2^(A-l) + dig / 2^l ∧ i*2^(A-l) % 2 = 0 := by
  have hpos : 0 < 2^l := Nat.two_pow_pos l
  have hA : 2^A = 2^(A-l) * 2^l := by rw [← Nat.pow_add]; congr 1; omega
  refine ⟨?_, ?_⟩
  · rw [hA, Nat.mul_comm (2^(A-l)) (2^l), Nat.mul_left_comm, Nat.add_comm]
    rw [Nat.add_mul_div_left _ _ hpos]; omega
  · rw [show A - l = (A - l - 1) + 1 by omega, Nat.pow_succ, ← Nat.mul_assoc]; simp

theorem sSlice_get (x : SB) (p m j : Nat) (hj : j < m) : (sSlice x p m)[j]? = x[p+j]? := by
  simp only [sSlice, List.getElem?_take, hj, if_true, List.getElem?_drop]

theorem sSlice_take1 (x : SB) (p m : Nat) (hm : 1 ≤ m) : (sSlice x p m).take 1 = sSlice x p 1 := by
  simp only [sSlice, List.take_take]
  congr 1; omega

section
variable {c : Ctx}

theorem js_forsPkFromSig (itk : Nat) (a : Adrs) (ha : ForsR a) (sig : SB) (md : Bytes) {P0 : St → Prop}
    (hs : StableS c P0)
    (h : ∀ st, InvS c st → P0 st → st.ents[itk]? = some (false, dTk c.n) ∧
      SlotsAt c (fslot (params c.v) a md) ((params c.v).k * ((params c.v).a + 1)) sig st) :
    JS c (sForsPkFromSig (params c.v) [.hid itk 32] a sig md) P0
      (fun v st => ∃ i, v = [.hid i c.n] ∧ KidOK c st i (.th (frA a))) := by
  obtain ⟨_, _, _, hkA, haA, _⟩ := variant_bounds c.v
  have hkpos : 0 < (params c.v).k := by cases c.v <;> decide
  simp only [sForsPkFromSig]
  have hl : (base2b md (params c.v).a (params c.v).k).zipIdx.length = (params c.v).k := by simp [base2b_length]
  refine JS.bind (JS.loopI' _ _ (fun k v st => SlotsAt c (fun i => .th (fA a (params c.v).a i)) k v st)
    hs (fun k v => stable_slotsAt _ _ v) [] (fun st _ _ => slotsAt_nil (c := c) _ st)
    (fun i hi v => ?_)) (fun roots => ?_) hs
  · rw [hl] at hi
    have hel : (base2b md (params c.v).a (params c.v).k).zipIdx[i]'(by rw [hl]; exact hi) =
        (fdig (params c.v) md i, i) := by
      have hi' : i < (base2b md (params c.v).a (params c.v).k).length := by rw [base2b_length]; exact hi
      simp only [List.getElem_zipIdx, Nat.zero_add, fdig]
      rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hi', Option.getD_some]
    simp only [hel]
    have hdig := fdig_lt (params c.v) md i hi
    have hG : fG (params c.v) md i < (params c.v).k * 2^(params c.v).a := by
      unfold fG
      have : (i+1)*2^(params c.v).a ≤ (params c.v).k*2^(params c.v).a := Nat.mul_le_mul_right _ hi
      rw [Nat.add_mul, Nat.one_mul] at this; omega
    have hP := stableS_and hs (stable_slotsAt (c := c) (fun i => .th (fA a (params c.v).a i)) i v)
    have hpos : i * ((params c.v).a + 1) < (params c.v).k * ((params c.v).a + 1) :=
      Nat.mul_lt_mul_of_pos_right hi (by omega)
    refine JS.assume (X := ∃ hs0, sig[i * ((params c.v).a + 1)]? = some (.hid hs0 c.n)) (fun st hI hp => ?_)
      (fun ⟨hs0, hsig⟩ => ?_)
    · obtain ⟨_, _, hv⟩ := (h st hI hp.1).2
      obtain ⟨hh, h1, _⟩ := hv _ hpos
      exact ⟨hh, h1⟩
    show JS c (do
      let leaf ← sThash (params c.v) [.hid itk 32] (fA a 0 (fG (params c.v) md i))
        ((sSlice sig (i * ((params c.v).a + 1)) ((params c.v).a + 1)).take 1)
      let root ← sAuthRoot (params c.v) [.hid itk 32] a (fdig (params c.v) md i) (fG (params c.v) md i) leaf
        ((sSlice sig (i * ((params c.v).a + 1)) ((params c.v).a + 1)).drop 1) (params c.v).a
      pure PUnit.unit
      pure (ForInStep.yield (v ++ root))) _ _
    rw [sSlice_take1 _ _ _ (by omega), sSlice_one_get (by rw [Nat.add_zero] at hsig ⊢; exact hsig)]
    refine JS.bind (js_thash (fA a 0 (fG (params c.v) md i)) [.hid hs0 c.n] itk (dsmOK_fA_zero _ a ha.1 _)
      (fun st hI hp => ⟨(h st hI hp.1).1, ?_⟩))
      (fun leaf => ?_) hP
    · obtain ⟨d, _, hv⟩ := (h st hI hp.1).2
      obtain ⟨hh, h1, h2⟩ := hv _ hpos
      rw [hsig] at h1
      obtain rfl : hs0 = hh := by simpa using h1
      rw [fslot_secret] at h2
      refine ⟨d, fA_inRange ha (by omega) (by omega), by rw [kids_fA_zero _ a ha.1]; simp,
        by rw [kids_fA_zero _ a ha.1]; rfl, fun k hk => ?_⟩
      simp at hk; subst hk
      refine ⟨hs0, rfl, fun K hK => ?_⟩
      rw [kids_fA_zero _ a ha.1] at hK
      simp at hK; subst hK; exact h2
    refine JS.obtain (X := fun j st => KidOK c st j (.th (fA a 0 (fG (params c.v) md i)))) (fun j hj => ?_)
    subst hj
    have hP2 := stableS_and hP (stableS_kid (c := c) j (.th (fA a 0 (fG (params c.v) md i))))
    simp only [sAuthRoot]
    have hw0 := js_authWalk (c := c) itk a (fA a) (params c.v).a (fG (params c.v) md i) (fdig (params c.v) md i)
      (fun ℓ j => rfl)
      (fun ℓ hℓ => kids_fA_succ _ a ha.1 ℓ _)
      (fun ℓ hℓ => fA_inRange ha (by omega) (Nat.lt_of_le_of_lt (Nat.div_le_self _ _) (by omega)))
      (fun ℓ hℓ => dsmOK_fA_succ _ a ha.1 ℓ _ (by omega))
      (fun ℓ hℓ => by
        obtain ⟨e1, e2⟩ := fors_div (params c.v).a i (fdig (params c.v) md i) ℓ hℓ
        unfold fG; rw [e1]; omega)
      ((sSlice sig (i * ((params c.v).a + 1)) ((params c.v).a + 1)).drop 1) (params c.v).a 0 [.hid j c.n]
      hP2 (by omega)
      (fun st hI hp => ⟨(h st hI hp.1.1).1, ⟨j, rfl, by simpa using hp.2⟩, fun ℓ _ hℓ => ?_⟩)
    · simp only [Nat.pow_zero, Nat.div_one] at hw0
      have hdivA : fG (params c.v) md i / 2^(params c.v).a = i := by
        unfold fG
        rw [Nat.add_comm, Nat.mul_comm, Nat.add_mul_div_left _ _ (Nat.two_pow_pos _), Nat.div_eq_of_lt hdig]
        omega
      rw [hdivA] at hw0
      refine JS.bind hw0 (fun root => ?_) hP2
      refine JS.obtain (X := fun j st => KidOK c st j (.th (fA a (params c.v).a i))) (fun r hr => ?_)
      subst hr
      refine JS.bind JS.unit (fun _ => JS.pure' (fun st _ hp => ?_)) (stableS_and hP2 (stableS_kid (c := c) r _))
      obtain ⟨d, hd⟩ := hp.1.2
      exact ⟨_, rfl, slotsAt_snoc (d := d) hp.1.1.1.2 hd⟩
    · obtain ⟨d, _, hv⟩ := (h st hI hp.1.1).2
      have hq : i * ((params c.v).a + 1) + 1 + ℓ < (params c.v).k * ((params c.v).a + 1) := by
        have : (i+1) * ((params c.v).a + 1) ≤ (params c.v).k * ((params c.v).a + 1) := Nat.mul_le_mul_right _ hi
        rw [Nat.succ_mul] at this; omega
      obtain ⟨hh, h1, h2⟩ := hv _ hq
      rw [fslot_auth _ a md i ℓ hℓ] at h2
      refine ⟨hh, ?_, d, h2⟩
      rw [List.getElem?_drop, sSlice_get _ _ _ _ (by omega)]
      rw [show i * ((params c.v).a + 1) + (1 + ℓ) = i * ((params c.v).a + 1) + 1 + ℓ by omega]
      exact h1
  · rw [hl]
    have hfr : ({a.setType 4 with keypair := a.keypair} : Adrs) = frA a := rfl
    rw [hfr]
    refine js_thash (frA a) roots itk (dsmOK_frA _ a ha.1) (fun st hI hp => ⟨(h st hI hp.1).1, ?_⟩)
    obtain ⟨d, hlen, hv⟩ := hp.2
    have hkl : (kids (params c.v) (frA a)).length = (params c.v).k := by rw [kids_frA _ a ha.1]; simp
    refine ⟨d, frA_inRange ha, by rw [← List.length_pos_iff, hkl]; exact hkpos, by rw [hlen, hkl], fun k hk => ?_⟩
    obtain ⟨hh, h1, h2⟩ := hv k (by omega)
    refine ⟨hh, h1, fun K hK => ?_⟩
    rw [kids_frA _ a ha.1, List.getElem?_map, List.getElem?_range (by omega)] at hK
    simp at hK; subst hK; exact h2

end

section
variable {c : Ctx}

theorem mem_kids_fA (p : Params) (a : Adrs) (ha : a.kind = 3) (h i : Nat) :
    Kid.th (fA a h i) ∈ kids p (fA a (h+1) (i/2)) := by
  rw [kids_fA_succ p a ha]
  rcases Nat.mod_two_eq_zero_or_one i with h0 | h1
  · rw [show 2 * (i/2) = i by omega]; simp
  · rw [show 2 * (i/2) + 1 = i by omega]; simp

theorem reach_fA (p : Params) (a : Adrs) (ha : a.kind = 3) :
    ∀ k h i, Reach p (fA a (h+k+1) (i / 2^(k+1))) (.th (fA a h i))
  | 0, h, i => Reach.kid (by simpa using mem_kids_fA p a ha h i)
  | k+1, h, i => by
    have ih := reach_fA p a ha k (h+1) (i/2)
    rw [Nat.div_div_eq_div_mul, ← Nat.pow_succ', show h + 1 + k + 1 = h + (k+1) + 1 by omega] at ih
    exact reach_trans ih (Reach.kid (mem_kids_fA p a ha h i))

/-- Every position of a FORS signature lies under the FORS roots compression. -/
theorem reach_fslot (a : Adrs) (ha : a.kind = 3) (md : Bytes) {q : Nat}
    (hq : q < (params c.v).k * ((params c.v).a + 1)) :
    Reach (params c.v) (frA a) (fslot (params c.v) a md q) := by
  have hA1 : 1 ≤ (params c.v).a := by cases c.v <;> decide
  have hi : q / ((params c.v).a + 1) < (params c.v).k :=
    Nat.div_lt_of_lt_mul (by rw [Nat.mul_comm]; exact hq)
  have hdig := fdig_lt (params c.v) md _ hi
  have hG : fG (params c.v) md (q / ((params c.v).a + 1)) / 2^(params c.v).a = q / ((params c.v).a + 1) := by
    unfold fG
    rw [Nat.add_comm, Nat.mul_comm, Nat.add_mul_div_left _ _ (Nat.two_pow_pos _), Nat.div_eq_of_lt hdig]
    omega
  have hroot : Reach (params c.v) (frA a) (.th (fA a (params c.v).a (q / ((params c.v).a + 1)))) := by
    apply Reach.kid
    rw [kids_frA _ a ha]
    simp only [List.mem_map, List.mem_range]
    exact ⟨_, hi, rfl⟩
  have hdown : ∀ h x, h < (params c.v).a → x / 2^((params c.v).a - h) = q / ((params c.v).a + 1) →
      Reach (params c.v) (frA a) (.th (fA a h x)) := by
    intro h x hh hx
    have := reach_fA (params c.v) a ha ((params c.v).a - h - 1) h x
    rw [show h + ((params c.v).a - h - 1) + 1 = (params c.v).a by omega,
      show (params c.v).a - h - 1 + 1 = (params c.v).a - h by omega, hx] at this
    exact reach_trans hroot this
  unfold fslot
  split
  · have hleaf := hdown 0 (fG (params c.v) md (q / ((params c.v).a + 1))) (by omega) (by simpa using hG)
    exact reach_trans hleaf (Reach.kid (by rw [kids_fA_zero _ a ha]; simp))
  · have hl : q % ((params c.v).a + 1) - 1 < (params c.v).a := by
      have := Nat.mod_lt q (show 0 < (params c.v).a + 1 by omega); omega
    refine hdown _ _ hl ?_
    rw [xor1_div _ _ (by omega), Nat.div_div_eq_div_mul, ← Nat.pow_add,
      show q % ((params c.v).a + 1) - 1 + ((params c.v).a - (q % ((params c.v).a + 1) - 1)) = (params c.v).a by omega]
    exact hG

theorem par_frA (p : Params) (a : Adrs) : par p (frA a) = none := by simp [par, frA, Adrs.setType]

theorem cov_slots {st : St} {a : Adrs} (ha : a.kind = 3) {md : Bytes} {v : SB}
    (hv : SlotsAt c (fslot (params c.v) a md) ((params c.v).k * ((params c.v).a + 1)) v st)
    {j d : Nat} (ht : KidAt c st d j (.th (frA a))) : Cov c st v := by
  have hc := ancCov_root (c := c) (st := st) (par_frA (params c.v) a)
  obtain ⟨d0, hl, hv⟩ := hv
  refine cov_idx (fun k hk => ?_)
  obtain ⟨i, hi, hki⟩ := hv k (by omega)
  exact ⟨i, c.n, d0, _, hi, hki, ancCov_reach (reach_fslot a ha md (by omega)) ht hc⟩

/-- `js_forsPkFromSig`, recording that the recomputed roots compression covers the signature. -/
theorem js_forsPkFromSigC (itk : Nat) (a : Adrs) (ha : ForsR a) (sig : SB) (md : Bytes) {P0 : St → Prop}
    (hs : StableS c P0)
    (h : ∀ st, InvS c st → P0 st → st.ents[itk]? = some (false, dTk c.n) ∧
      SlotsAt c (fslot (params c.v) a md) ((params c.v).k * ((params c.v).a + 1)) sig st) :
    JS c (sForsPkFromSig (params c.v) [.hid itk 32] a sig md) P0
      (fun v st => ∃ i, v = [.hid i c.n] ∧ KidOK c st i (.th (frA a)) ∧ Cov c st sig) := by
  have hs' := stableS_and hs (stable_slotsAt (c := c) (fslot (params c.v) a md)
    ((params c.v).k * ((params c.v).a + 1)) sig)
  refine JS.conseq (JS.frame (js_forsPkFromSig itk a ha sig md hs' (fun st hI hp => h st hI hp.1)) hs')
    (fun st hI hp => ⟨hp, (h st hI hp).2⟩) (fun v st hq => ?_)
  obtain ⟨⟨_, hx⟩, i, hv, d, hk⟩ := hq
  exact ⟨i, hv, ⟨d, hk⟩, cov_slots ha.1 hx hk⟩

theorem ancOK_rq {st : St} {iR dk : Nat} {m : Bytes} (he : st.ents[iR]? = some (false, rqOf c.n dk m))
    (hk : st.ents[dk]? = some (false, dReq c.n)) : AncOK c st iR := by
  intro A ⟨r, hr, hA⟩
  rw [he] at hr
  obtain rfl : rqOf c.n dk m = r := by simpa using hr
  exfalso
  rcases hA with ⟨_, itk, hs, hr'⟩ | ⟨_, ipk, hr', hk'⟩
  · have := congrArg SReq.input hr'; simp [rqOf] at this
  · have := congrArg SReq.key hr'
    simp [rqOf, prfReq] at this
    subst this
    rw [hk] at hk'; simp [dReq, dPrf] at hk'

end

/-! Requests with their own challenger entry. -/

section
variable {c : Ctx}

/-- A challenger request with a closed handle, or with its own entry already: the
    answer is a challenger entry for exactly this request. -/
theorem js_askE (r : SReq) (h999 : r.mode ≠ 999) {P0 : St → Prop}
    (hF : ∀ st, InvS c st → P0 st → FamOK c st r)
    (hk : ∀ st, InvS c st → P0 st → (∃ h ∈ r.hids, h ∉ st.rev) ∨ ∃ j : Nat, st.ents[j]? = some (false, r)) :
    JS c (sAsk r) P0 (fun v st => ∃ i, v = [.hid i r.outLen] ∧ st.ents[i]? = some (false, r)) := by
  refine JS.ask r hF (fun st hI hp _ => ⟨_, rfl, ?_⟩)
  rcases hk st hI hp with hc | ⟨j, hj⟩
  · exact askS_closed st r hI hc
  · rw [askS_known hI h999 hj]
    have : addC st j r = st := by simp [addC, lt_entry hj]
    rw [this]; exact hj

theorem notRev_of_prot {st : St} (hI : InvS c st) {i : Nat} (hp : Prot st i) : i ∉ st.rev :=
  fun hi => (hI.2.2.1 i hi).2 hp

theorem revOK_ent {st : St} (hI : InvS c st) {i : Nat} {r : SReq} (he : st.ents[i]? = some (false, r))
    (h0 : r.mode ≠ 0) (h9 : r.mode ≠ 999) (w : Nat) : RevOK st [.hid i w] := by
  intro j hj
  simp [shids] at hj; subst hj
  exact ⟨lt_entry he, notProt_of_res hI he h0 h9⟩

theorem revOK_kid {st : St} (hI : InvS c st) {i : Nat} {K : Kid} (hk : KidOK c st i K) (w : Nat) :
    RevOK st [.hid i w] := let ⟨_, hd⟩ := hk; revOK_one hI hd w

end

/-! Signing. -/

section
variable {c : Ctx}

theorem js_sign (ρ : Nat) (hroot : c.root = [.hid ρ c.n]) (msg : Bytes) {P0 : St → Prop} (hs : StableS c P0)
    (h : ∀ st, InvS c st → P0 st → (∃ A, KidOK c st ρ (.th A) ∧ par (params c.v) A = none) ∧
      ∃ j : Nat, st.ents[j]? = some (false, dTk c.n)) :
    JS c (sSign c.v (coinEx c.n ++ [.hid ρ c.n]) msg) P0
      (fun res st => ∀ sg, res = some sg → RevOK st sg ∧ Cov c st sg) := by
  obtain ⟨_, hH, hd, _⟩ := variant_bounds c.v
  simp only [sSign, sDeriveKey, sKeyed, sHmsg]
  apply JS.ite
  · intro _; exact JS.pure' (fun _ _ _ sg h => by cases h)
  intro _
  refine JS.bind JS.unit (fun _ => ?_) hs
  have s0 := stableS_and hs (stableS_true (c := c))
  refine JS.bind (js_askE (dTk c.n) (by simp [dTk]) (fun _ _ _ => Or.inl rfl)
    (fun st hI hp => Or.inr (h st hI hp.1).2)) (fun tk => ?_) s0
  refine JS.obtain (X := fun i st => st.ents[i]? = some (false, dTk c.n)) (fun itk htk => ?_)
  subst htk
  have s1 := stableS_and s0 (stableS_ent (c := c) itk (false, dTk c.n))
  refine JS.bind (js_askE (dPrf c.n) (by simp [dPrf]) (fun _ _ _ => Or.inr (Or.inl rfl))
    (fun st hI _ => Or.inl ⟨0, by simp [dPrf, SReq.hids, shids], notRev_of_prot hI (coin_prot hI.1.1)⟩))
    (fun pk => ?_) s1
  refine JS.obtain (X := fun i st => st.ents[i]? = some (false, dPrf c.n)) (fun ipk hpk => ?_)
  subst hpk
  have s2 := stableS_and s1 (stableS_ent (c := c) ipk (false, dPrf c.n))
  refine JS.bind (js_askE (dReq c.n) (by simp [dReq]) (fun _ _ _ => Or.inr (Or.inr (Or.inl rfl)))
    (fun st hI _ => Or.inl ⟨1, by simp [dReq, SReq.hids, shids], notRev_of_prot hI (coin1_prot hI.1.2.1)⟩))
    (fun mk => ?_) s2
  refine JS.obtain (X := fun i st => st.ents[i]? = some (false, dReq c.n)) (fun dk hmk => ?_)
  subst hmk
  have s3 := stableS_and s2 (stableS_ent (c := c) dk (false, dReq c.n))
  refine JS.bind (js_askE (rqOf c.n dk msg) (by simp [rqOf])
    (fun st _ hp => Or.inr (Or.inr (Or.inr (Or.inr (Or.inl ⟨dk, msg, rfl, hp.2⟩)))))
    (fun st hI hp => Or.inl ⟨dk, by simp [rqOf, SReq.hids, shids],
      notRev_of_prot hI ⟨_, hp.2, Or.inr (by simp [dReq, SReq.hids, shids])⟩⟩)) (fun r => ?_) s3
  refine JS.obtain (X := fun i st => st.ents[i]? = some (false, rqOf c.n dk msg)) (fun iR hr => ?_)
  subst hr
  have s4 := stableS_and s3 (stableS_ent (c := c) iR (false, rqOf c.n dk msg))
  have e1 : sSlice (coinEx c.n ++ [SV.hid ρ c.n]) 2 1 = [SV.hid 2 c.n] := rfl
  have e2 : List.drop 3 (coinEx c.n ++ [SV.hid ρ c.n]) = [SV.hid ρ c.n] := rfl
  have e3 : (rqOf c.n dk msg).outLen = c.n := rfl
  have e4 : (dTk c.n).outLen = 32 := rfl
  have e5 : (dPrf c.n).outLen = 32 := rfl
  simp only [e1, e2, e3, e4, e5]
  have hq : (⟨2, "DSM/sphincs/v2/h-msg", [], [SV.hid iR c.n] ++ [SV.hid 2 c.n] ++ [SV.hid ρ c.n] ++ [SV.lit msg],
      (params c.v).m⟩ : SReq) = hqOf c.n c.pm c.root iR msg := by
    rw [hroot]; simp [hqOf]
  rw [hq]
  refine JS.bind (Q := fun v st => ∃ k, v = [.hid k c.pm] ∧ ∃ e, st.ents[k]? = some e ∧ (e.2.res c.t).mode = 2)
    (JS.ask (hqOf c.n c.pm c.root iR msg) (fun st hI hp => ?_) (fun st hI hp _ => ?_)) (fun dg => ?_) s4
  · obtain ⟨A, ⟨d, hk⟩, _⟩ := (h st hI hp.1.1.1.1.1).1
    obtain ⟨e, he, hm⟩ := kidAt_mode hk
    have h3 := ge3_of_res hI he (by rw [hm]; decide)
    refine Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inl ⟨iR, msg, rfl, dk, hp.2, hp.1.2, ?_⟩)))))
    rw [hroot]; intro i hi; simp [shids] at hi; subst hi; exact ⟨h3, lt_entry he⟩
  · obtain ⟨e, he, hres, _⟩ := ask_res (c := c) st (hqOf c.n c.pm c.root iR msg)
    exact ⟨_, rfl, e, he, by rw [hres]; rfl⟩
  refine JS.obtain (X := fun i st => ∃ e, st.ents[i]? = some e ∧ (e.2.res c.t).mode = 2) (fun k hk => ?_)
  subst hk
  have s5 := stableS_and s4 (fun st st' _ hg (h : ∃ e, st.ents[k]? = some e ∧ (e.2.res c.t).mode = 2) =>
    let ⟨e, he, hm⟩ := h; ⟨e, grow_get hg he, hm⟩)
  refine JS.reveal (fun st hI hp => ?_) ?_ s5
  · obtain ⟨e, he, hm⟩ := hp.2
    intro j hj; simp [shids] at hj; subst hj
    exact ⟨lt_entry he, notProt_of_res hI he (by rw [hm]; decide) (by rw [hm]; decide),
      ancOK_mode he (by rw [hm]; decide)⟩
  generalize hI : splitDigest (params c.v) (sres c.t [.hid k c.pm]) = I
  have ht : I.tree < 256^8 := hI ▸ split_tree_lt c.v _
  have hl : I.leaf < 2^(params c.v).hp := hI ▸ split_leaf_lt c.v _
  have hfa : ForsR ({tree := I.tree, kind := 3, keypair := I.leaf} : Adrs) :=
    ⟨rfl, by show 0 < 256^4; decide, ht, Nat.lt_of_lt_of_le hl hH⟩
  refine JS.bind (js_forsSign itk ipk _ hfa I.md s5 (fun st _ hp => ⟨hp.1.1.1.1.2, hp.1.1.1.2⟩)) (fun fs => ?_) s5
  have S1 := stableS_and s5 (stable_slotsAt (c := c) (fslot (params c.v) {tree := I.tree, kind := 3, keypair := I.leaf} I.md)
    ((params c.v).k * ((params c.v).a + 1)) fs)
  refine JS.bind (js_forsPkFromSigC itk _ hfa fs I.md S1 (fun st _ hp => ⟨hp.1.1.1.1.1.2, hp.2⟩)) (fun fpk => ?_) S1
  refine JS.obtain (X := fun i st => KidOK c st i (.th (frA {tree := I.tree, kind := 3, keypair := I.leaf})) ∧
    Cov c st fs) (fun f hf => ?_)
  subst hf
  have S2 := stableS_and S1 (stableS_and (stableS_kid (c := c) f (.th (frA {tree := I.tree, kind := 3, keypair := I.leaf})))
    (stable_cov (c := c) fs))
  refine JS.bind (js_htSign itk ipk [.hid f c.n] I.tree I.leaf ht hl S2
    (fun st _ hp => ⟨hp.1.1.1.1.1.1.2, hp.1.1.1.1.1.2, f, _, rfl, hp.2.1, par_frA _ _⟩)) (fun hsg => ?_) S2
  have S3 := stableS_and S2 (fun st st' hI' hg (h : ∃ g, [SV.hid f c.n] = [.hid g c.n] ∧ HSig c st g I.tree I.leaf hsg) =>
    let ⟨g, h1, h2⟩ := h; ⟨g, h1, stable_hsig g I.tree I.leaf hsg st st' hI' hg h2⟩)
  refine JS.bind (js_htRoot itk hsg [.hid f c.n] I.tree I.leaf ht hl S3 (fun st _ hp => ⟨hp.1.1.1.1.1.1.1.2, ?_⟩))
    (fun actual => ?_) S3
  · obtain ⟨g, hg, hsig⟩ := hp.2
    obtain rfl : f = g := by simpa using hg
    exact ⟨f, _, rfl, hp.1.2.1, par_frA _ _, hsig⟩
  refine JS.assume (X := ∃ i, actual = [.hid i c.n]) (fun st _ hp => let ⟨⟨i, _, h1, _⟩, _⟩ := hp.2; ⟨i, h1⟩)
    (fun ⟨ac, hac⟩ => ?_)
  subst hac
  have S4 := stableS_and S3 (fun st st' hI' hg (h : (∃ i A, [SV.hid ac c.n] = [.hid i c.n] ∧ KidOK c st i (.th A) ∧
      par (params c.v) A = none) ∧ Cov c st hsg) =>
    let ⟨⟨i, A, h1, h2, h3⟩, h4⟩ := h; ⟨⟨i, A, h1, kidOK_mono hg h2, h3⟩, stable_cov hsg st st' hI' hg h4⟩)
  refine JS.reveal (fun st hI hp => ?_) ?_ S4
  · obtain ⟨⟨i, A, h1, h2, hA⟩, _⟩ := hp.2
    obtain rfl : ac = i := by simpa using h1
    exact reveal_root hI h2 hA c.n
  refine JS.reveal (fun st hI hp => ?_) ?_ S4
  · obtain ⟨A, hk, hA⟩ := (h st hI hp.1.1.1.1.1.1.1.1.1.1).1
    exact reveal_root hI hk hA c.n
  apply JS.ite
  · intro _; exact JS.pure' (fun _ _ _ sg h => by cases h)
  intro _
  refine JS.bind JS.unit (fun _ => JS.pure' (fun st hI hp sg hsg' => ?_)) S4
  cases hsg'
  have hp' := hp.1
  refine ⟨revOK_append (revOK_append (revOK_ent hI hp'.1.1.1.1.1.2 (by simp [rqOf]) (by simp [rqOf]) c.n)
    (revOK_slotsAt hI hp'.1.1.1.2)) (let ⟨g, _, hg⟩ := hp'.1.2; revOK_hsig hI hg),
    cov_append (cov_append (cov_one (lt_entry hp'.1.1.1.1.1.2) (ancOK_rq hp'.1.1.1.1.1.2 hp'.1.1.1.1.1.1.2))
      hp'.1.1.2.2) hp'.2.2⟩
end

/-! Adversary-only programs (the forgery's verification). -/

/-- A program that issues adversary requests only. -/
inductive AOnly : {α : Type} → Prog α → Prop
  | done {α : Type} (a : α) : AOnly (.done a)
  | askA {α : Type} (q : Request) (k : Bytes → Prog α) : (∀ b, AOnly (k b)) → AOnly (.askA q k)

theorem AOnly.bind {α β : Type} {P : Prog α} (hP : AOnly P) {f : α → Prog β} (hf : ∀ a, AOnly (f a)) :
    AOnly (P >>= f) := by
  induction hP with
  | done a => exact hf a
  | askA q k _ ih => exact AOnly.askA q _ (fun b => ih b)

theorem AOnly.pure {α : Type} (a : α) : AOnly (pure a : Prog α) := AOnly.done a

theorem AOnly.ask (q : Request) : AOnly (advP q) := AOnly.askA q _ (fun b => AOnly.done b)

theorem AOnly.ite {α : Type} {b : Prop} [Decidable b] {P₁ P₂ : Prog α} (h₁ : b → AOnly P₁) (h₂ : ¬b → AOnly P₂) :
    AOnly (if b then P₁ else P₂) := by
  by_cases h : b
  · simp only [h, if_true]; exact h₁ h
  · simp only [h, if_false]; exact h₂ h

theorem AOnly.loop {ι σ : Type} (l : List ι) (f : ι → σ → Prog (ForInStep σ)) (h : ∀ i ∈ l, ∀ s, AOnly (f i s)) :
    ∀ s, AOnly (forIn l s f) := by
  induction l with
  | nil => intro s; exact AOnly.done s
  | cons a l ih =>
    intro s
    rw [List.forIn_cons]
    refine AOnly.bind (h a (by simp) s) (fun x => ?_)
    cases x with
    | done b => exact AOnly.done b
    | yield b => exact ih (fun i hi => h i (by simp [hi])) b

theorem ao_chain (p : Params) (tk : Bytes) (a : Adrs) : ∀ (steps : Nat) (x : Bytes) (start : Nat),
    AOnly (chain advP p tk a x start steps)
  | 0, _, _ => AOnly.done _
  | steps+1, x, start => by
    simp only [chain]
    exact AOnly.bind (AOnly.ask _) (fun y => ao_chain p tk a steps y (start+1))

theorem ao_authWalk (p : Params) (tk : Bytes) (a : Adrs) (auth : Bytes) :
    ∀ (remaining li gi level : Nat) (node : Bytes), AOnly (authWalk advP p tk a li gi node auth level remaining)
  | 0, _, _, _, _ => AOnly.done _
  | remaining+1, li, gi, level, node => by
    simp only [authWalk]
    exact AOnly.bind (AOnly.ask _) (fun y => ao_authWalk p tk a auth remaining _ _ _ y)

theorem ao_wotsPkFromSig (p : Params) (tk : Bytes) (a : Adrs) (sig msg : Bytes) :
    AOnly (wotsPkFromSig advP p tk a sig msg) := by
  simp only [wotsPkFromSig, wotsCompress]
  refine AOnly.bind (AOnly.loop _ _ ?_ []) (fun tops => AOnly.ask _)
  intro x _ s
  obtain ⟨digit, i⟩ := x
  exact AOnly.bind (ao_chain p tk _ _ _ _) (fun top => AOnly.done _)

theorem ao_xmssPkFromSig (p : Params) (tk : Bytes) (a : Adrs) (idx : Nat) (sig msg : Bytes) :
    AOnly (xmssPkFromSig advP p tk a idx sig msg) := by
  simp only [xmssPkFromSig, authRoot]
  exact AOnly.bind (ao_wotsPkFromSig p tk _ _ _) (fun node => ao_authWalk p tk _ _ _ _ _ _ _)

theorem ao_htRootTail (p : Params) (tk : Bytes) : ∀ (remaining layer tree : Nat) (node sig : Bytes),
    AOnly (htRootTail advP p tk layer tree node sig remaining)
  | 0, _, _, _, _ => AOnly.done _
  | remaining+1, layer, tree, node, sig => by
    simp only [htRootTail]
    exact AOnly.bind (ao_xmssPkFromSig p tk _ _ _ _) (fun root => ao_htRootTail p tk remaining _ _ root _)

theorem ao_htRoot (p : Params) (tk sig msg : Bytes) (tree leaf : Nat) :
    AOnly (htRoot advP p tk sig msg tree leaf) := by
  simp only [htRoot]
  exact AOnly.bind (ao_xmssPkFromSig p tk _ _ _ _) (fun node => ao_htRootTail p tk _ _ _ node _)

theorem ao_forsPkFromSig (p : Params) (tk : Bytes) (a : Adrs) (sig md : Bytes) :
    AOnly (forsPkFromSig advP p tk a sig md) := by
  simp only [forsPkFromSig, authRoot]
  refine AOnly.bind (AOnly.loop _ _ ?_ []) (fun roots => AOnly.ask _)
  intro x _ s
  obtain ⟨idx, i⟩ := x
  exact AOnly.bind (AOnly.ask _) (fun leaf => AOnly.bind (ao_authWalk p tk _ _ _ _ _ _ leaf)
    (fun root => AOnly.done _))

theorem ao_verify (v : Variant) (pk msg sig : Bytes) : AOnly (verify advP v pk msg sig) := by
  simp only [verify]
  refine AOnly.ite (fun _ => AOnly.done _) (fun _ => ?_)
  refine AOnly.bind (AOnly.done _) (fun _ => ?_)
  refine AOnly.ite (fun _ => AOnly.done _) (fun _ => ?_)
  refine AOnly.bind (AOnly.done _) (fun _ => ?_)
  exact AOnly.bind (AOnly.ask _) (fun tk => AOnly.bind (AOnly.ask _) (fun dg =>
    AOnly.bind (ao_forsPkFromSig _ tk _ _ _) (fun fpk => AOnly.bind (ao_htRoot _ tk _ _ _ _)
      (fun ac => AOnly.done _))))

section
variable {c : Ctx}

theorem grow_addA (st : St) (q : Request) :
    Grow2 st (addA st (firstIdx (mA false c.t st.rev q) st.ents) q) := by
  have := xrun_grow c.t (.askA q (fun _ => .done ())) st
  simpa [xrun] using this

theorem JS.askA' {α : Type} {q : Request} {k : Bytes → Prog α} {P0 : St → Prop} {Q : α → St → Prop}
    (hk : ∀ b, JS c (k b) P0 Q) (hs : StableS c P0) : JS c (.askA q k) P0 Q :=
  JS.askA (fun st hI hp => JS.conseq (hk _) (fun st' _ he => by subst he; exact hs _ _ hI (grow_addA st q) hp)
    (fun _ _ h => h))

theorem JS.aonly {α : Type} {P : Prog α} (hP : AOnly P) : ∀ {P0 : St → Prop}, StableS c P0 →
    JS c P P0 (fun _ _ => True) := by
  induction hP with
  | done a => intro P0 _; exact JS.pure' (fun _ _ _ => trivial)
  | askA q k _ ih => intro P0 hs; exact JS.askA' (fun b => ih b hs) hs

end

/-! Play, extension, key generation, and the whole extended game. -/

/-- The signer's standing facts: the root is a canonical node, the tweak key has its entry. -/
def PS (c : Ctx) (ρ : Nat) (st : St) : Prop :=
  (∃ A, KidOK c st ρ (.th A) ∧ par (params c.v) A = none) ∧ ∃ j : Nat, st.ents[j]? = some (false, dTk c.n)

section
variable {c : Ctx}

theorem stable_PS (ρ : Nat) : StableS c (PS c ρ) :=
  fun _ _ _ hg ⟨⟨A, hA, hn⟩, j, hj⟩ => ⟨⟨A, kidOK_mono hg hA, hn⟩, j, grow_get hg hj⟩

theorem js_play (ρ : Nat) (hroot : c.root = [.hid ρ c.n]) (limits : Limits) (pk : Bytes) :
    ∀ (A : RAdv) (signed : List Bytes),
    JS c (playS c.v limits pk (coinEx c.n ++ [.hid ρ c.n]) A signed) (PS c ρ) (fun _ _ => True)
  | .hq r k, signed => by
    simp only [playS]
    exact JS.askA' (fun b => js_play ρ hroot limits pk (k b) signed) (stable_PS ρ)
  | .sq m k, signed => by
    by_cases hl : legal limits m = true
    · simp only [playS, hl, if_true]
      refine JS.bind' (js_sign ρ hroot m (stable_PS ρ) (fun st _ hp => hp)) (fun s => ?_) (stable_PS ρ)
      rcases s with _ | sg
      · exact JS.conseq (P0 := PS c ρ) (js_play ρ hroot limits pk (k none) (signed ++ [m]))
          (fun _ _ hp => hp.1) (fun _ _ h => h)
      · have hs1 : StableS c (fun st => PS c ρ st ∧ ∀ sg', some sg = some sg' → RevOK st sg' ∧ Cov c st sg') :=
          stableS_and (stable_PS ρ) (fun st st' hI hg h sg' e => stable_rc sg' st st' hI hg (h sg' e))
        refine JS.reveal (fun st _ hp => reveal_ok (hp.2 sg rfl).1 (hp.2 sg rfl).2) ?_ hs1
        exact JS.conseq (P0 := PS c ρ) (js_play ρ hroot limits pk (k _) (signed ++ [m]))
          (fun _ _ hp => hp.1) (fun _ _ h => h)
    · have hl' : legal limits m = false := by cases h : legal limits m <;> simp_all
      simp only [playS, hl', Bool.false_eq_true, if_false]
      exact js_play ρ hroot limits pk (k none) signed
  | .out m s, signed => by
    simp only [playS]
    exact JS.bind' (JS.aonly (ao_verify c.v pk m s) (stable_PS ρ)) (fun _ => JS.pure' (fun _ _ _ => trivial))
      (stable_PS ρ)

end

/-- What the extension's tail materializes: the FORS roots compression of the
    digest's FORS key and the root of the XMSS tree at every layer of the path. -/
def ExtS (c : Ctx) (I : Indices) (st : St) : Prop :=
  (∃ i, KidOK c st i (.th (frA (forsAdrs I.tree I.leaf)))) ∧
  ∀ l, l < (params c.v).d → ∃ i, KidOK c st i (.th (nodeA {layer := l, tree := pathT (params c.v) I l}
    (params c.v).hp 0))

/-- What the extension leaves for the canonical-collision argument: the digest the
    extension used is the answer to the verifier's message-hash request, and the
    structures on its path are materialized (`ExtS`). -/
def ExtF (c : Ctx) (ρ : Nat) (msg sig : Bytes) (st : St) : Prop :=
  ∃ (i : Nat) (e : Bool × SReq), st.ents[i]? = some e ∧ e.2.res c.t = extReq c ρ msg sig ∧
    ExtS c (splitDigest (params c.v) (be c.pm (c.t.getD i 0))) st

section
variable {c : Ctx}

theorem stable_extS (I : Indices) : StableS c (ExtS c I) := by
  intro st st' _ hg ⟨⟨i, hi⟩, h2⟩
  exact ⟨⟨i, kidOK_mono hg hi⟩, fun l hl => let ⟨j, hj⟩ := h2 l hl; ⟨j, kidOK_mono hg hj⟩⟩

theorem js_extTail (itk ipk : Nat) (I : Indices) (htI : I.tree < 256^8) (hlI : I.leaf < 2^(params c.v).hp)
    {P0 : St → Prop} (hs : StableS c P0)
    (h : ∀ st, InvS c st → P0 st → st.ents[itk]? = some (false, dTk c.n) ∧ st.ents[ipk]? = some (false, dPrf c.n)) :
    JS c (sExtTail (params c.v) [.hid itk 32] [.hid ipk 32] [.hid 2 c.n] I) P0 (fun _ st => ExtS c I st) := by
  obtain ⟨_, hH, hd, hkA, haA, _⟩ := variant_bounds c.v
  have hkpos : 0 < (params c.v).k := by cases c.v <;> decide
  have hfa : ForsR (forsAdrs I.tree I.leaf) := ⟨rfl, by show 0 < 256^4; decide, htI, Nat.lt_of_lt_of_le hlI hH⟩
  simp only [sExtTail]
  refine JS.bind (JS.loopI' (List.range (params c.v).k) _
    (fun k v st => SlotsAt c (fun i => .th (fA (forsAdrs I.tree I.leaf) (params c.v).a i)) k v st)
    hs (fun k v => stable_slotsAt _ _ v) [] (fun st _ _ => slotsAt_nil (c := c) _ st) (fun i hi v => ?_))
    (fun roots => ?_) hs
  · rw [List.length_range] at hi
    rw [List.getElem_range]
    have hP := stableS_and hs (stable_slotsAt (c := c) (fun i => .th (fA (forsAdrs I.tree I.leaf) (params c.v).a i)) i v)
    refine JS.bind (js_forsNode itk ipk _ hfa (params c.v).a i hP (Nat.le_refl _)
      (Nat.mul_le_mul_right _ hi) (fun st hI hp => h st hI hp.1)) (fun r => ?_) hP
    refine JS.obtain (X := fun j st => KidOK c st j (.th (fA (forsAdrs I.tree I.leaf) (params c.v).a i)))
      (fun j hj => ?_)
    subst hj
    refine JS.bind JS.unit (fun _ => JS.pure' (fun st _ hp => ?_)) (stableS_and hP (stableS_kid (c := c) j _))
    obtain ⟨d, hd'⟩ := hp.1.2
    exact ⟨_, rfl, slotsAt_snoc (d := d) hp.1.1.2 hd'⟩
  rw [List.length_range]
  have hs1 := stableS_and hs (stable_slotsAt (c := c) (fun i => .th (fA (forsAdrs I.tree I.leaf) (params c.v).a i))
    (params c.v).k roots)
  have hfr : ({(forsAdrs I.tree I.leaf).setType 4 with keypair := (forsAdrs I.tree I.leaf).keypair} : Adrs) =
      frA (forsAdrs I.tree I.leaf) := rfl
  rw [hfr]
  refine JS.bind (js_thash (frA (forsAdrs I.tree I.leaf)) roots itk (dsmOK_frA _ _ hfa.1)
    (fun st hI hp => ⟨(h st hI hp.1).1, ?_⟩))
    (fun z => ?_) hs1
  · obtain ⟨d, hlen, hv⟩ := hp.2
    have hkl : (kids (params c.v) (frA (forsAdrs I.tree I.leaf))).length = (params c.v).k := by
      rw [kids_frA _ _ hfa.1]; simp
    refine ⟨d, frA_inRange hfa, by rw [← List.length_pos_iff, hkl]; exact hkpos, by rw [hlen, hkl], fun k hk => ?_⟩
    obtain ⟨hh, h1, h2⟩ := hv k (by omega)
    refine ⟨hh, h1, fun K hK => ?_⟩
    rw [kids_frA _ _ hfa.1, List.getElem?_map, List.getElem?_range (by omega)] at hK
    simp at hK; subst hK; exact h2
  refine JS.obtain (X := fun j st => KidOK c st j (.th (frA (forsAdrs I.tree I.leaf)))) (fun f hf => ?_)
  subst hf
  have hs2 := stableS_and hs1 (stableS_kid (c := c) f (.th (frA (forsAdrs I.tree I.leaf))))
  refine JS.bind (JS.loopI' (List.range (params c.v).d) _
    (fun k _ st => ∀ l, l < k → ∃ i, KidOK c st i (.th (nodeA {layer := l, tree := pathT (params c.v) I l}
      (params c.v).hp 0))) hs2
    (fun k _ st st' _ hg h l hl => let ⟨j, hj⟩ := h l hl; ⟨j, kidOK_mono hg hj⟩) PUnit.unit
    (fun _ _ _ l hl => absurd hl (by omega)) (fun l hl u => ?_)) (fun _ => JS.pure' (fun st _ hp => ?_)) hs2
  · rw [List.length_range] at hl
    rw [List.getElem_range]
    have hP := stableS_and hs2 (fun st st' (_ : InvS c st) hg (h : ∀ l', l' < l → ∃ i, KidOK c st i
      (.th (nodeA {layer := l', tree := pathT (params c.v) I l'} (params c.v).hp 0))) l' hl' =>
        let ⟨j, hj⟩ := h l' hl'; ⟨j, kidOK_mono hg hj⟩)
    refine JS.bind (js_xmssNode itk ipk {layer := l, tree := pathT (params c.v) I l} (by show l < 256^4; omega)
      (Nat.lt_of_le_of_lt (ext_tree_le c.v I.tree I.leaf l hlI) htI) (params c.v).hp 0 hP (by simp)
      (fun st hI hp => h st hI hp.1.1.1)) (fun r => ?_) hP
    refine JS.obtain (X := fun j st => KidOK c st j (.th (nodeA {layer := l, tree := pathT (params c.v) I l}
      (params c.v).hp 0))) (fun j hj => ?_)
    subst hj
    refine JS.bind JS.unit (fun _ => JS.pure' (fun st _ hp => ⟨_, rfl, fun l' hl' => ?_⟩))
      (stableS_and hP (stableS_kid (c := c) j _))
    by_cases he : l' = l
    · subst he; exact ⟨j, hp.1.2⟩
    · exact hp.1.1.2 l' (by omega)
  · rw [List.length_range] at hp
    exact ⟨⟨f, hp.1.2⟩, hp.2⟩

theorem js_ext (ρ : Nat) (msg sig : Bytes) {P0 : St → Prop} (hs : StableS c P0)
    (h : ∀ st, InvS c st → P0 st → PS c ρ st) :
    JS c (sExtW c.v (coinEx c.n ++ [.hid ρ c.n]) msg sig) P0 (fun _ st => ExtF c ρ msg sig st) := by
  obtain ⟨_, hH, hd, hkA, haA, hhb⟩ := variant_bounds c.v
  have e1 : sSlice (coinEx c.n ++ [SV.hid ρ c.n]) 2 1 = [SV.hid 2 c.n] := rfl
  have e2 : List.drop 3 (coinEx c.n ++ [SV.hid ρ c.n]) = [SV.hid ρ c.n] := rfl
  simp only [sExtW, sDeriveKey, e1, e2]
  refine JS.bind (js_askE (dTk c.n) (by simp [dTk]) (fun _ _ _ => Or.inl rfl)
    (fun st hI hp => Or.inr (h st hI hp).2)) (fun tk => ?_) hs
  refine JS.obtain (X := fun i st => st.ents[i]? = some (false, dTk c.n)) (fun itk htk => ?_)
  subst htk
  have s1 := stableS_and hs (stableS_ent (c := c) itk (false, dTk c.n))
  refine JS.bind (js_askE (dPrf c.n) (by simp [dPrf]) (fun _ _ _ => Or.inr (Or.inl rfl))
    (fun st hI _ => Or.inl ⟨0, by simp [dPrf, SReq.hids, shids], notRev_of_prot hI (coin_prot hI.1.1)⟩))
    (fun pk => ?_) s1
  refine JS.obtain (X := fun i st => st.ents[i]? = some (false, dPrf c.n)) (fun ipk hpk => ?_)
  subst hpk
  have s2 := stableS_and s1 (stableS_ent (c := c) ipk (false, dPrf c.n))
  refine JS.bind (Q := fun dg st => ∃ (i : Nat) (e : Bool × SReq), st.ents[i]? = some e ∧ e.2.res c.t = extReq c ρ msg sig ∧
      dg = be c.pm (c.t.getD i 0))
    (JS.reveal (fun st hI hp => ?_) (JS.askA (fun st _ _ => JS.pure' (fun st' _ he => ?_))) s2)
    (fun dg => ?_) s2
  rotate_left
  · subst he
    obtain ⟨e, he, hres, _⟩ := askA_entry (c := c) st
      ⟨2, "DSM/sphincs/v2/h-msg", [], sig.take (params c.v).n ++ sres c.t ([SV.hid 2 c.n] ++ [SV.hid ρ c.n]) ++ msg,
        (params c.v).m⟩
    exact ⟨_, e, he, hres, rfl⟩
  rotate_right
  · intro i hi
    simp [shids] at hi
    rcases hi with rfl | rfl
    · refine ⟨lt_entry hI.1.2.2, ?_, ancOK_mode hI.1.2.2 (by simp [coin, SReq.res])⟩
      rintro ⟨e, he, hp'⟩
      rw [hI.1.2.2] at he
      obtain rfl := Option.some.inj he
      simp [coin, SReq.hids, shids] at hp'
    · obtain ⟨A, hk, hA⟩ := (h st hI hp.1.1).1
      exact reveal_root hI hk hA c.n i (by simp [shids])
  have s3 := stableS_and s2 (fun st st' (_ : InvS c st) hg (h : ∃ (i : Nat) (e : Bool × SReq), st.ents[i]? = some e ∧
      e.2.res c.t = extReq c ρ msg sig ∧ dg = be c.pm (c.t.getD i 0)) =>
    let ⟨i, e, h1, h2, h3⟩ := h; ⟨i, e, grow_get hg h1, h2, h3⟩)
  generalize hI : splitDigest (params c.v) dg = I
  have htI : I.tree < 256^8 := hI ▸ split_tree_lt c.v _
  have hlI : I.leaf < 2^(params c.v).hp := hI ▸ split_leaf_lt c.v _
  have hfa : ForsR (forsAdrs I.tree I.leaf) := ⟨rfl, by show 0 < 256^4; decide, htI, Nat.lt_of_lt_of_le hlI hH⟩
  refine JS.bind (JS.loop' _ _ (fun _ _ => True) s3 (fun _ => stableS_true) PUnit.unit (fun _ _ _ => trivial)
    (fun i hi u => ?_)) (fun _ => ?_) s3
  · have hi' := List.mem_range.mp hi
    have hdig := fors_digit_lt (params c.v) I.md i
    refine JS.bind (js_forsNode itk ipk _ hfa 0 _ (stableS_and s3 stableS_true) (by omega) (by
      have : (i+1)*2^(params c.v).a ≤ (params c.v).k*2^(params c.v).a := Nat.mul_le_mul_right _ hi'
      rw [Nat.add_mul, Nat.one_mul] at this; simp; omega)
      (fun st _ hp => ⟨hp.1.1.1.2, hp.1.1.2⟩)) (fun _ => ?_) (stableS_and s3 stableS_true)
    exact JS.conseq (P0 := fun _ => True) (JS.bind JS.unit (fun _ => JS.pure' (fun _ _ _ => trivial)) stableS_true)
      (fun _ _ _ => trivial) (fun _ _ h => h)
  refine JS.bind (JS.loop' _ _ (fun _ _ => True) (stableS_and s3 stableS_true) (fun _ => stableS_true) PUnit.unit
    (fun _ _ _ => trivial) (fun l hl u => ?_))
    (fun _ => JS.conseq (JS.frame (js_extTail itk ipk I htI hlI (stableS_and (stableS_and s3 stableS_true) stableS_true)
      (fun st _ hp => ⟨hp.1.1.1.1.2, hp.1.1.1.2⟩)) (stableS_and (stableS_and s3 stableS_true) stableS_true))
      (fun _ _ h => h) (fun _ st hq => by
        obtain ⟨i, e, h1, h2, h3⟩ := hq.1.1.1.2
        exact ⟨i, e, h1, h2, by rw [← h3, hI]; exact hq.2⟩))
    (stableS_and s3 stableS_true)
  have hl' := List.mem_range.mp hl
  have hw : WotsR (wA l (((I.tree*2^(params c.v).hp + I.leaf)/2^((params c.v).hp*l)/2^(params c.v).hp))
      (((I.tree*2^(params c.v).hp + I.leaf)/2^((params c.v).hp*l)%2^(params c.v).hp))) := by
    refine ⟨rfl, rfl, rfl, by show l < 256^4; omega,
      Nat.lt_of_le_of_lt (ext_tree_le c.v I.tree I.leaf l hlI) htI,
      Nat.lt_of_lt_of_le (Nat.mod_lt _ (Nat.two_pow_pos _)) hH⟩
  refine JS.bind (js_wotsPkgen itk ipk _ hw (stableS_and (stableS_and s3 stableS_true) stableS_true)
    (fun st _ hp => ⟨hp.1.1.1.1.2, hp.1.1.1.2⟩)) (fun _ => ?_) (stableS_and (stableS_and s3 stableS_true) stableS_true)
  exact JS.conseq (P0 := fun _ => True) (JS.bind JS.unit (fun _ => JS.pure' (fun _ _ _ => trivial)) stableS_true)
    (fun _ _ _ => trivial) (fun _ _ h => h)

end

section
variable {c : Ctx}

/-- Sequencing where the continuation is needed only at the actual intermediate value and state. -/
theorem JS.bindX {α β : Type} {P : Prog α} {f : α → Prog β} {P0 : St → Prop} {Q : α → St → Prop}
    {R : β → St → Prop} (hP : JS c P P0 Q)
    (hf : ∀ st, InvS c st → P0 st → (∀ x ∈ strace c.t P st, dis c.t x = false) →
      JS c (f (xrun false c.t P st).1) (fun st' => st' = (xrun false c.t P st).2) R) :
    JS c (P.bind f) P0 R := by
  intro st hI hp
  obtain ⟨hT1, hE1⟩ := hP st hI hp
  refine ⟨fun s stp hsp hnd => ?_, fun hnd => ?_⟩
  · rw [strace_bind] at hsp hnd
    by_cases hlt : s < (strace c.t P st).length
    · rw [List.getElem?_append_left hlt] at hsp
      exact hT1 s stp hsp (fun s' stp' hs' hst => hnd s' stp' hs' (by
        rw [List.getElem?_append_left (by have := (List.getElem?_eq_some_iff.mp hst).1; omega)]; exact hst))
    · have hP1 : ∀ x ∈ strace c.t P st, dis c.t x = false := by
        intro x hx
        obtain ⟨s', hs'⟩ := List.mem_iff_getElem?.mp hx
        have hlt' := (List.getElem?_eq_some_iff.mp hs').1
        exact hnd s' x (by omega) (by rw [List.getElem?_append_left hlt']; exact hs')
      obtain ⟨hI1, hg1, _⟩ := hE1 hP1
      rw [List.getElem?_append_right (by omega)] at hsp
      obtain ⟨hT2, -⟩ := hf st hI hp hP1 _ hI1 rfl
      obtain ⟨a1, a2, a3⟩ := hT2 _ stp hsp (fun s' stp' hs' hst => hnd (s' + (strace c.t P st).length) stp'
        (by omega) (by rw [List.getElem?_append_right (by omega)]; simpa using hst))
      exact ⟨a1, grow_trans hg1 a2, a3⟩
  · rw [strace_bind] at hnd
    have hP1 : ∀ x ∈ strace c.t P st, dis c.t x = false := fun x hx => hnd x (List.mem_append_left _ hx)
    obtain ⟨hI1, hg1, _⟩ := hE1 hP1
    obtain ⟨-, hE2⟩ := hf st hI hp hP1 _ hI1 rfl
    obtain ⟨hI2, hg2, hq2⟩ := hE2 (fun x hx => hnd x (List.mem_append_right _ hx))
    rw [xrun_bind]
    exact ⟨hI2, grow_trans hg1 hg2, hq2⟩

/-- Sequencing without carrying the precondition. -/
theorem JS.bind0 {α β : Type} {P : Prog α} {f : α → Prog β} {P0 : St → Prop} {Q : α → St → Prop}
    {R : β → St → Prop} (hP : JS c P P0 Q) (hf : ∀ a, JS c (f a) (Q a) R) : JS c (P.bind f) P0 R :=
  JS.bindX hP (fun st hI hp hnd => JS.conseq (hf _) (fun st' _ he => by subst he; exact ((hP st hI hp).2 hnd).2.2)
    (fun _ _ h => h))

theorem js_kgTail :
    JS c (sKgTail c.v (coinEx c.n)) (fun st => 2 ∉ st.rev)
      (fun ks st => ∃ ρ, ks.1 = [.hid 2 c.n, .hid ρ c.n] ∧ ks.2 = coinEx c.n ++ [.hid ρ c.n] ∧ PS c ρ st) := by
  obtain ⟨_, hH, hd, _⟩ := variant_bounds c.v
  have e1 : sSlice (coinEx c.n) 2 1 = [SV.hid 2 c.n] := rfl
  have e2 : List.take 1 (coinEx c.n) = [SV.hid 0 c.n] := rfl
  simp only [sKgTail, sDeriveKey, e1, e2]
  refine JS.bind0 (js_askE (dTk c.n) (by simp [dTk]) (fun _ _ _ => Or.inl rfl)
    (fun st hI hp => Or.inl ⟨2, by simp [dTk, SReq.hids, shids], hp⟩)) (fun tk => ?_)
  refine JS.conseq (P0 := fun st => True ∧ ∃ i, tk = [.hid i 32] ∧ st.ents[i]? = some (false, dTk c.n)) ?_
    (fun _ _ h => ⟨trivial, h⟩) (fun _ _ h => h)
  refine JS.obtain (fun itk htk => ?_)
  subst htk
  have s1 := stableS_and (stableS_true (c := c)) (stableS_ent (c := c) itk (false, dTk c.n))
  refine JS.bind (js_askE (dPrf c.n) (by simp [dPrf]) (fun _ _ _ => Or.inr (Or.inl rfl))
    (fun st hI _ => Or.inl ⟨0, by simp [dPrf, SReq.hids, shids], notRev_of_prot hI (coin_prot hI.1.1)⟩))
    (fun pk => ?_) s1
  refine JS.obtain (X := fun i st => st.ents[i]? = some (false, dPrf c.n)) (fun ipk hpk => ?_)
  subst hpk
  have s2 := stableS_and s1 (stableS_ent (c := c) ipk (false, dPrf c.n))
  have hl : ({layer := (params c.v).d - 1} : Adrs).layer < 256^4 := by show (params c.v).d - 1 < 256^4; omega
  refine JS.bind (js_xmssNode itk ipk {layer := (params c.v).d - 1} hl (by show 0 < 256^8; decide) (params c.v).hp 0 s2
    (by simp) (fun st _ hp => ⟨hp.1.2, hp.2⟩)) (fun root => ?_) s2
  refine JS.pure' (fun st _ hp => ?_)
  obtain ⟨ρ, hρ, hk⟩ := hp.2
  subst hρ
  have hp1 : 1 ≤ (params c.v).hp := by cases c.v <;> decide
  exact ⟨ρ, rfl, rfl, ⟨_, hk, par_top _ _ hp1⟩, itk, hp.1.1.2⟩
end

section
variable {c : Ctx}

theorem invS_coin : InvS c (coinSt c.n) := by
  refine ⟨⟨rfl, rfl, rfl⟩, ?_, ?_, ?_, ?_, fun i hi => by simp [coinSt] at hi⟩
  · intro a qa he; rcases a with _ | _ | _ | a <;> simp [coinSt, coin] at he
  · intro i hi; simp [coinSt] at hi
  · intro i r he
    left
    have := lt_entry he
    simpa [coinSt] using this
  · intro a b ea eb _ hb _ hbe
    have := lt_entry hbe
    simp [coinSt] at this; omega

theorem js_rest (ρ : Nat) (hroot : c.root = [.hid ρ c.n]) (limits : Limits) (A : Bytes → RAdv) :
    JS c (restS c.v limits A ([.hid 2 c.n, .hid ρ c.n], coinEx c.n ++ [.hid ρ c.n])) (PS c ρ)
      (fun out st => ExtF c ρ out.msg out.sig st) := by
  simp only [restS]
  refine JS.reveal (fun st hI hp => ?_) ?_ (stable_PS ρ)
  · intro i hi
    simp [shids] at hi
    rcases hi with rfl | rfl
    · refine ⟨lt_entry hI.1.2.2, ?_, ancOK_mode hI.1.2.2 (by simp [coin, SReq.res])⟩
      rintro ⟨e, he, hp'⟩
      rw [hI.1.2.2] at he
      obtain rfl := Option.some.inj he
      simp [coin, SReq.hids, shids] at hp'
    · obtain ⟨A, hk, hA⟩ := hp.1
      exact reveal_root hI hk hA c.n i (by simp [shids])
  refine JS.bind' (js_play ρ hroot limits _ _ []) (fun out => ?_) (stable_PS ρ)
  refine JS.bind' (js_ext ρ out.msg out.sig (stableS_and (stable_PS ρ) stableS_true) (fun _ _ hp => hp.1))
    (fun _ => JS.pure' (fun _ _ hp => hp.2)) (stableS_and (stable_PS ρ) stableS_true)

/-- The structural judgment for the whole extended game, from the coin state. -/
theorem js_game (hroot : c.root = (xrun false c.t (sKgTail c.v (coinEx c.n)) (coinSt c.n)).1.1.drop 1)
    (limits : Limits) (A : Bytes → RAdv) :
    JS c (gameS' c.v limits A (coinEx c.n)) (fun st => st = coinSt c.n)
      (fun out st => ∃ ρ, c.root = [.hid ρ c.n] ∧ ExtF c ρ out.msg out.sig st) := by
  rw [gameS'_eq]
  refine JS.bindX (JS.conseq js_kgTail (fun st _ h => by subst h; simp [coinSt]) (fun _ _ h => h))
    (fun st hI hp hnd => ?_)
  subst hp
  obtain ⟨_, _, ρ, h1, h2, hPS⟩ := (js_kgTail (c := c) (coinSt c.n) hI (by simp [coinSt])).2 hnd
  have hr : c.root = [.hid ρ c.n] := by rw [hroot, h1]; rfl
  have hks : (xrun false c.t (sKgTail c.v (coinEx c.n)) (coinSt c.n)).1 =
      ([.hid 2 c.n, .hid ρ c.n], coinEx c.n ++ [.hid ρ c.n]) := Prod.ext h1 h2
  rw [hks]
  exact JS.conseq (js_rest ρ hr limits A) (fun st' _ he => by subst he; exact hPS) (fun _ _ h => ⟨ρ, hr, h⟩)

/-- Every pre-step state of the extended game reached without a disagreement satisfies
    the structural invariant, and its step is a DSM family request, an adversary request,
    or a reveal of unprotected handles. -/
theorem game_struct (hroot : c.root = (xrun false c.t (sKgTail c.v (coinEx c.n)) (coinSt c.n)).1.1.drop 1)
    (limits : Limits) (A : Bytes → RAdv) (s : Nat) (stp : St × Ev)
    (hs : (strace c.t (gameS' c.v limits A (coinEx c.n)) (coinSt c.n))[s]? = some stp)
    (hnd : NoDisTo c.t (strace c.t (gameS' c.v limits A (coinEx c.n)) (coinSt c.n)) s) :
    InvS c stp.1 ∧ StepOK c stp :=
  let ⟨a, _, b⟩ := (js_game hroot limits A (coinSt c.n) invS_coin rfl).1 s stp hs hnd
  ⟨a, b⟩

end

end DSM.Rom
