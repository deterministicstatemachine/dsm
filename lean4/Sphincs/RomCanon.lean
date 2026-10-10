-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomColl

/- Canonical collisions in H1'.

   A canonical collision is a verifier request at an address `b` of the forged
   path whose input differs from the honest canonical input `canon b` but whose
   thash output equals the canonical one. In H1' the extension materializes the
   whole honest structure on the forged path, recursively from the honest seeds,
   so on a disagreement-free run:

   * every path address carries a structured challenger entry (`ExtS`, descent);
   * a structured entry's request is the canonical request and its value the
     canonical output (`struct_val`, from `canon_kids`);
   * the verifier's request is an entry too; it is not a challenger entry (a
     challenger thash entry at `b` is the canonical one, `struct_unique`), except
     through a 32-byte key coincidence; so it is an adversary entry.

   The pair (adversary entry, structured challenger entry) at one literal address
   with equal truncated values is charged at the later of the two creations: the
   later entry's value is a fresh tape coordinate and the earlier one's value is
   fixed by the prefix, whatever the earlier visibility of that value. Provenance
   (`AncOK`) guarantees the canonical value is never an adversary entry's. -/
namespace DSM.Rom
open DSM.Sphincs DSM.Sphincs.Security

/-! The canonical input is the concatenation of the canonical children's values. -/

/-- The honest value of a canonical child. -/
def kval (o : Oracle Id) (p : Params) (tk prfKey seed : Bytes) : Kid → Bytes
  | .th B => thash o p tk B (canon o p tk prfKey seed B)
  | .pf B => prf o p prfKey seed B

section
variable (o : Oracle Id) (p : Params) (tk prfKey seed : Bytes)

theorem canon_kids0 (b : Adrs) (hk : b.kind = 0) :
    canon o p tk prfKey seed b = ((kids p b).map (kval o p tk prfKey seed)).flatten := by
  rw [canon_kind0 (o := o) (p := p) (tk := tk) (prfKey := prfKey) (seed := seed) hk]
  cases hh : b.hash with
  | zero =>
    simp [kids, hk, hh, kval, chain, wotsSecretAt]
    rfl
  | succ h =>
    have e : kids p b = [.th {b with hash := h}] := by simp [kids, hk, hh]
    rw [e]
    simp only [List.map_cons, List.map_nil, List.flatten_cons, List.flatten_nil, List.append_nil, kval]
    rw [chain_step, canon_kind0 (o := o) (p := p) (tk := tk) (prfKey := prfKey) (seed := seed)
      (show ({b with hash := h} : Adrs).kind = 0 from hk)]
    congr 1
    show chain o p tk b (wotsSecretAt o p prfKey seed b) 0 h =
      chain o p tk {b with hash := h} (wotsSecretAt o p prfKey seed {b with hash := h}) 0 h
    rw [chain_hash_irrel (o := o) (p := p) (tk := tk) b h]; rfl

theorem canon_kids1 (b : Adrs) (hk : b.kind = 1) :
    canon o p tk prfKey seed b = ((kids p b).map (kval o p tk prfKey seed)).flatten := by
  rw [canon_kind1 (o := o) (p := p) (tk := tk) (prfKey := prfKey) (seed := seed) hk]
  have e : kids p b = (List.range p.len).map
      (fun ci => .th {b.setType 0 with keypair := b.keypair, chain := ci, hash := 14}) := by
    simp [kids, hk]
  rw [e, List.map_map]
  unfold wotsTopsAt
  congr 1

theorem canon_kids2 (b : Adrs) (hk : b.kind = 2) (hc : 1 ≤ b.chain) (hkp : b.keypair = 0) :
    canon o p tk prfKey seed b = ((kids p b).map (kval o p tk prfKey seed)).flatten := by
  obtain ⟨bl, bt, bk, bkp, bc, bh⟩ := b
  simp only at hk hc hkp
  subst hk hkp
  obtain ⟨c, rfl⟩ : ∃ c, bc = c + 1 := ⟨bc - 1, by omega⟩
  cases c with
  | zero =>
    simp [canon, kids, kval, Adrs.setType, xmssNode, wots_pkgen_blocks, wotsCompress, wotsTopsAt]
  | succ c =>
    simp [canon, kids, kval, Adrs.setType, xmssNode]
    rfl

theorem canon_kids3 (b : Adrs) (hk : b.kind = 3) :
    canon o p tk prfKey seed b = ((kids p b).map (kval o p tk prfKey seed)).flatten := by
  obtain ⟨bl, bt, bk, bkp, bc, bh⟩ := b
  simp only at hk
  subst hk
  cases bc with
  | zero => simp [canon, kids, kval, Adrs.setType, forsSecret]
  | succ c =>
    cases c with
    | zero => simp [canon, kids, kval, Adrs.setType, forsNode, forsSecret]; rfl
    | succ c => simp [canon, kids, kval, forsNode]; rfl

theorem canon_kids4 (b : Adrs) (hk : b.kind = 4) (ha : 1 ≤ p.a) :
    canon o p tk prfKey seed b = ((kids p b).map (kval o p tk prfKey seed)).flatten := by
  rw [canon_kind4 (o := o) (p := p) (tk := tk) (prfKey := prfKey) (seed := seed) hk]
  have e : kids p b = (List.range p.k).map
      (fun i => .th {b.setType 3 with keypair := b.keypair, chain := p.a, hash := i}) := by
    simp [kids, hk]
  rw [e, List.map_map]
  congr 1
  apply List.map_congr_left
  intro i _
  obtain ⟨a', ha'⟩ : ∃ a', p.a = a' + 1 := ⟨p.a - 1, by omega⟩
  simp only [Function.comp, kval]
  rw [canon_kind3_node (o := o) (p := p) (tk := tk) (prfKey := prfKey) (seed := seed) a' rfl (by simp [ha'])]
  obtain ⟨bl, bt, bk, bkp, bc, bh⟩ := b
  rw [ha']
  simp [forsNode, Adrs.setType]
  rfl

/-- The canonical input at an address with canonical children is the concatenation of
    the children's honest values (FORS height at least one; XMSS nodes with keypair 0). -/
theorem canon_kids (b : Adrs) (hk : kids p b ≠ []) (h2 : b.kind = 2 → b.keypair = 0) (ha : 1 ≤ p.a) :
    canon o p tk prfKey seed b = ((kids p b).map (kval o p tk prfKey seed)).flatten := by
  by_cases k0 : b.kind = 0
  · exact canon_kids0 o p tk prfKey seed b k0
  by_cases k1 : b.kind = 1
  · exact canon_kids1 o p tk prfKey seed b k1
  by_cases k2 : b.kind = 2
  · have hc : 1 ≤ b.chain := by
      rcases Nat.eq_zero_or_pos b.chain with h0 | h0
      · exact absurd (by simp [kids, k2, h0]) hk
      · exact h0
    exact canon_kids2 o p tk prfKey seed b k2 hc (h2 k2)
  by_cases k3 : b.kind = 3
  · exact canon_kids3 o p tk prfKey seed b k3
  by_cases k4 : b.kind = 4
  · exact canon_kids4 o p tk prfKey seed b k4 ha
  exact absurd (by simp [kids, k0, k1, k2, k3, k4]) hk

end

/-! Structured entries are canonical. -/

section
variable {c : Ctx}

/-- A structured XMSS node has keypair 0 (its height-one descendants are compressions,
    whose parent is a keypair-0 node). -/
theorem struct_kp2 {st : St} : ∀ {d : Nat} {r : SReq} {b : Adrs}, StructReq c st d r b → b.kind = 2 →
    b.keypair = 0
  | 0, _, _, h, _ => h.elim
  | d+1, r, b, hS, hk => by
    obtain ⟨_, hkn, hD, itk, hs, _, _, hl, hh⟩ := hS
    rcases Nat.lt_or_ge b.chain 2 with hc | hc
    · have hc1 : b.chain = 1 := by
        rcases Nat.lt_or_ge b.chain 1 with h0 | h0
        · have h00 : b.chain = 0 := by omega
          exact absurd (by simp [kids, hk, h00]) hkn
        · omega
      have hK : Kid.th {b.setType 1 with keypair := 2*b.hash} ∈ kids (params c.v) b := by simp [kids, hk, hc1]
      have h1 := congrArg (fun o => o.map Adrs.keypair) (hD _ hK)
      simp [par, Kid.adr, Adrs.setType] at h1
      exact h1.symm
    · have hk0 : (kids (params c.v) b)[0]? = some (.th {b with chain := b.chain - 1, hash := 2*b.hash}) := by
        simp [kids, hk, show b.chain ≠ 1 by omega, show 2 ≤ b.chain from hc]
      have h0 : 0 < hs.length := by rw [hl]; exact (List.getElem?_eq_some_iff.mp hk0).1
      obtain ⟨h, _, hm⟩ := hh 0 h0
      rw [hk0] at hm
      obtain ⟨r', h1, _⟩ := hm
      have h2 := struct_kp2 h1 hk
      exact h2

end

theorem sres_kids (t : List Nat) (n : Nat) (f : Kid → Bytes) : ∀ (hs : List SV) (ks : List Kid),
    hs.length = ks.length →
    (∀ k, k < hs.length → ∃ h, hs[k]? = some (.hid h n) ∧ ∀ K, ks[k]? = some K → be n (t.getD h 0) = f K) →
    sres t hs = (ks.map f).flatten
  | [], [], _, _ => rfl
  | [], _ :: _, hl, _ => by simp at hl
  | _ :: _, [], hl, _ => by simp at hl
  | v :: hs, K :: ks, hl, hh => by
    obtain ⟨h, h1, h2⟩ := hh 0 (by simp)
    simp only [List.getElem?_cons_zero, Option.some.injEq] at h1
    subst h1
    simp only [sres, SV.res, List.map_cons, List.flatten_cons]
    rw [h2 K rfl, sres_kids t n f hs ks (by simpa using hl) (fun k hk => by
      obtain ⟨h', h1', h2'⟩ := hh (k+1) (by simp; omega)
      exact ⟨h', by simpa using h1', fun K' hK' => h2' K' (by simpa using hK')⟩)]

section
variable {c : Ctx}

/-- Value canonicity: on the final table, a structured challenger request is the
    canonical request at its address. -/
theorem struct_val {st : St} (hI2 : Inv2 c st) (hD : Pre (resD c.t st) c.D) :
    ∀ (d : Nat) (r : SReq) (b : Adrs), StructReq c st d r b →
      r.res c.t = thashReq (params c.v) (expTk c.O c.v c.e) b
        (canon c.O (params c.v) (expTk c.O c.v c.e) (expPrf c.O c.v c.e) (expSeed c.v c.e) b)
  | 0, _, _, h => h.elim
  | d+1, r, b, hS => by
    have ha : 1 ≤ (params c.v).a := by cases c.v <;> decide
    obtain ⟨_, hkn, _, itk, hs, rfl, hitk, hl, hh⟩ := id hS
    rw [canon_kids _ _ _ _ _ b hkn (fun hk => struct_kp2 hS hk) ha]
    have hin : sres c.t hs = ((kids (params c.v) b).map (kval c.O (params c.v) (expTk c.O c.v c.e)
        (expPrf c.O c.v c.e) (expSeed c.v c.e))).flatten := by
      refine sres_kids c.t c.n _ hs _ hl (fun k hk => ?_)
      obtain ⟨h, hx, hm⟩ := hh k hk
      refine ⟨h, hx, fun K hK => ?_⟩
      rw [hK] at hm
      cases K with
      | th B =>
        obtain ⟨r', h1, h2⟩ := hm
        have ev := entry_val hI2 hD h2
        have hn : r'.outLen = c.n := by
          cases d with
          | zero => exact h1.elim
          | succ d => obtain ⟨_, _, _, _, _, hr, _⟩ := h1; subst hr; rfl
        simp only at ev
        rw [hn, struct_val hI2 hD d r' B h1] at ev
        simpa [sres, SV.res, kval, thash, keyed, thashReq] using ev
      | pf B =>
        obtain ⟨ipk, h1, h2, _⟩ := hm
        have := prf_val hI2 hD h2 h1
        simpa [sres, SV.res, kval] using this
    simp only [SReq.res, thashReq, sres, SV.res, List.append_nil]
    rw [be_tk hI2 hD hitk, hin]

end

/-! Trace facts. -/

theorem addA_rev (st : St) (i : Nat) (q : Request) : (addA st i q).rev = i :: st.rev := by
  unfold addA; rfl

theorem post_grow (t : List Nat) (stp : St × Ev) : Grow2 stp.1 (stepPost t stp) := by
  obtain ⟨st, ev⟩ := stp
  cases ev with
  | c r => exact ⟨addC_ext st _ r, fun x hx => by simp only [stepPost]; rw [addC_rev]; exact hx⟩
  | a q => exact ⟨addA_ext st _ q, fun x hx => by simp only [stepPost]; rw [addA_rev]; exact List.mem_cons_of_mem _ hx⟩
  | r x => exact ⟨⟨[], by simp [stepPost]⟩, fun y hy => by simp only [stepPost]; exact List.mem_append_right _ hy⟩

theorem trace_grow (t : List Nat) {α : Type} : ∀ (P : Prog α) (st : St) (s : Nat) (stp : St × Ev),
    (strace t P st)[s]? = some stp → Grow2 st stp.1
  | .done _, _, _, _, h => by simp [strace] at h
  | .askC r k, st, 0, stp, h => by simp [strace] at h; subst h; exact grow_refl _
  | .askC r k, st, s+1, stp, h => by
    simp only [strace, List.getElem?_cons_succ] at h
    exact grow_trans (post_grow t (st, .c r)) (trace_grow t _ _ s stp h)
  | .askA q k, st, 0, stp, h => by simp [strace] at h; subst h; exact grow_refl _
  | .askA q k, st, s+1, stp, h => by
    simp only [strace, List.getElem?_cons_succ] at h
    exact grow_trans (post_grow t (st, .a q)) (trace_grow t _ _ s stp h)
  | .reveal x k, st, 0, stp, h => by simp [strace] at h; subst h; exact grow_refl _
  | .reveal x k, st, s+1, stp, h => by
    simp only [strace, List.getElem?_cons_succ] at h
    exact grow_trans (post_grow t (st, .r x)) (trace_grow t _ _ s stp h)

/-- A later pre-step state grows from an earlier step's post-state. -/
theorem trace_grow2 (t : List Nat) {α : Type} : ∀ (P : Prog α) (st : St) (s1 s2 : Nat) (stp1 stp2 : St × Ev),
    s1 < s2 → (strace t P st)[s1]? = some stp1 → (strace t P st)[s2]? = some stp2 →
    Grow2 (stepPost t stp1) stp2.1
  | .done _, _, _, _, _, _, _, h, _ => by simp [strace] at h
  | .askC r k, st, 0, s2+1, stp1, stp2, _, h1, h2 => by
    simp [strace] at h1; subst h1
    simp only [strace, List.getElem?_cons_succ] at h2
    exact trace_grow t _ _ s2 stp2 h2
  | .askC r k, st, s1+1, s2+1, stp1, stp2, hlt, h1, h2 => by
    simp only [strace, List.getElem?_cons_succ] at h1 h2
    exact trace_grow2 t _ _ s1 s2 stp1 stp2 (by omega) h1 h2
  | .askA q k, st, 0, s2+1, stp1, stp2, _, h1, h2 => by
    simp [strace] at h1; subst h1
    simp only [strace, List.getElem?_cons_succ] at h2
    exact trace_grow t _ _ s2 stp2 h2
  | .askA q k, st, s1+1, s2+1, stp1, stp2, hlt, h1, h2 => by
    simp only [strace, List.getElem?_cons_succ] at h1 h2
    exact trace_grow2 t _ _ s1 s2 stp1 stp2 (by omega) h1 h2
  | .reveal x k, st, 0, s2+1, stp1, stp2, _, h1, h2 => by
    simp [strace] at h1; subst h1
    simp only [strace, List.getElem?_cons_succ] at h2
    exact trace_grow t _ _ s2 stp2 h2
  | .reveal x k, st, s1+1, s2+1, stp1, stp2, hlt, h1, h2 => by
    simp only [strace, List.getElem?_cons_succ] at h1 h2
    exact trace_grow2 t _ _ s1 s2 stp1 stp2 (by omega) h1 h2
  | _, _, _, 0, _, _, hlt, _, _ => absurd hlt (by omega)

/-- Every entry past the initial ones was appended by a step: an adversary step whose
    lookup failed, or a challenger step whose lookup failed. -/
theorem entry_creation (t : List Nat) {α : Type} : ∀ (P : Prog α) (st : St) (j : Nat) (e : Bool × SReq),
    (xrun false t P st).2.ents[j]? = some e → st.ents.length ≤ j →
    ∃ (s : Nat) (stp : St × Ev), (strace t P st)[s]? = some stp ∧ stp.1.ents.length = j ∧
      ((∃ q, stp.2 = .a q ∧ firstIdx (mA false t stp.1.rev q) stp.1.ents = j ∧ e = (true, lift q)) ∨
       (∃ r, stp.2 = .c r ∧ firstIdx (mC false t stp.1.rev r) stp.1.ents = j ∧ e = (false, r)))
  | .done _, st, j, e, he, hj => by
    simp only [xrun] at he
    have := lt_entry he; omega
  | .askC r k, st, j, e, he, hj => by
    simp only [xrun] at he
    generalize hi : firstIdx (mC false t st.rev r) st.ents = i at he
    by_cases hl : i < st.ents.length
    · have e1 : addC st i r = st := by simp [addC, hl]
      rw [e1] at he
      obtain ⟨s, stp, h1, h2, h3⟩ := entry_creation t _ st j e he hj
      exact ⟨s+1, stp, by simp only [strace, List.getElem?_cons_succ]; rw [hi, e1]; exact h1, h2, h3⟩
    · have e1 : addC st i r = ⟨st.ents ++ [(false, r)], st.rev⟩ := by simp [addC, hl]
      rw [e1] at he
      by_cases hjl : j = st.ents.length
      · subst hjl
        refine ⟨0, (st, .c r), by simp [strace], rfl, Or.inr ⟨r, rfl, ?_, ?_⟩⟩
        · show firstIdx (mC false t st.rev r) st.ents = st.ents.length
          have := firstIdx_le (mC false t st.rev r) st.ents; omega
        · obtain ⟨⟨L, hL⟩, _⟩ := xrun_grow t (k (.hid i r.outLen)) ⟨st.ents ++ [(false, r)], st.rev⟩
          rw [hL] at he
          simp at he
          exact he.symm
      · obtain ⟨s, stp, h1, h2, h3⟩ := entry_creation t _ _ j e he (by simp; omega)
        exact ⟨s+1, stp, by simp only [strace, List.getElem?_cons_succ]; rw [hi, e1]; exact h1, h2, h3⟩
  | .askA q k, st, j, e, he, hj => by
    simp only [xrun] at he
    generalize hi : firstIdx (mA false t st.rev q) st.ents = i at he
    by_cases hl : i < st.ents.length
    · have e1 : addA st i q = ⟨st.ents, i :: st.rev⟩ := by simp [addA, hl]
      rw [e1] at he
      obtain ⟨s, stp, h1, h2, h3⟩ := entry_creation t _ _ j e he hj
      exact ⟨s+1, stp, by simp only [strace, List.getElem?_cons_succ]; rw [hi, e1]; exact h1, h2, h3⟩
    · have hi' : i = st.ents.length := Nat.le_antisymm (hi ▸ firstIdx_le _ _) (Nat.le_of_not_lt hl)
      have e1 : addA st i q = ⟨st.ents ++ [(true, lift q)], i :: st.rev⟩ := by simp [addA, hl]
      rw [e1] at he
      by_cases hjl : j = st.ents.length
      · subst hjl
        refine ⟨0, (st, .a q), by simp [strace], rfl, Or.inl ⟨q, rfl, hi.trans hi', ?_⟩⟩
        obtain ⟨⟨L, hL⟩, _⟩ := xrun_grow t (k (be q.outLen (t.getD i 0))) ⟨st.ents ++ [(true, lift q)], i :: st.rev⟩
        rw [hL] at he
        simp at he
        exact he.symm
      · obtain ⟨s, stp, h1, h2, h3⟩ := entry_creation t _ _ j e he (by simp; omega)
        exact ⟨s+1, stp, by simp only [strace, List.getElem?_cons_succ]; rw [hi, e1]; exact h1, h2, h3⟩
  | .reveal x k, st, j, e, he, hj => by
    simp only [xrun] at he
    obtain ⟨s, stp, h1, h2, h3⟩ := entry_creation t _ _ j e he hj
    exact ⟨s+1, stp, by simp only [strace, List.getElem?_cons_succ]; exact h1, h2, h3⟩

/-! The pair event: an adversary entry and a challenger thash entry at one address
    literal, charged at the later creation. -/

/-- An adversary request at the address literal `L`. -/
def AdvAt (n : Nat) (q : Request) (L : Bytes) : Prop :=
  q.mode = 1 ∧ q.context = "" ∧ q.outLen = n ∧ q.input.take 32 = L

/-- A challenger request of thash shape at the address literal `L`. -/
def ChAt (n : Nat) (r : SReq) (L : Bytes) : Prop :=
  ∃ (itk : Nat) (hs : List SV), r = ⟨1, "", [.hid itk 32], .lit L :: hs, n⟩

/-- A challenger entry of thash shape at `L`. -/
def HasCh (n : Nat) (st : St) (L : Bytes) : Prop :=
  ∃ (j : Nat) (r : SReq), st.ents[j]? = some (false, r) ∧ ChAt n r L

/-- An adversary step at `L` whose lookup fails: it appends a new adversary entry. -/
def AdvNew (n : Nat) (t : List Nat) (stp : St × Ev) (L : Bytes) : Prop :=
  ∃ q, stp.2 = .a q ∧ AdvAt n q L ∧ firstIdx (mA false t stp.1.rev q) stp.1.ents = stp.1.ents.length

/-- A challenger thash step at `L` whose lookup fails: it appends a new challenger entry. -/
def ChNew (n : Nat) (t : List Nat) (stp : St × Ev) (L : Bytes) : Prop :=
  ∃ r, stp.2 = .c r ∧ ChAt n r L ∧ firstIdx (mC false t stp.1.rev r) stp.1.ents = stp.1.ents.length

/-- The first challenger thash entry at `L`. -/
noncomputable def chIdx (n : Nat) (st : St) (L : Bytes) : Nat :=
  firstIdx (fun e => @decide (e.1 = false ∧ ChAt n e.2 L) (Classical.propDecidable _)) st.ents

/-- The address literal of a step's adversary request. -/
def advLit (stp : St × Ev) : Bytes :=
  match stp.2 with
  | .a q => q.input.take 32
  | _ => []

theorem hasCh_mono {n : Nat} {st st' : St} {L : Bytes} (hg : Grow2 st st') (h : HasCh n st L) : HasCh n st' L :=
  let ⟨j, r, h1, h2⟩ := h; ⟨j, r, grow_get hg h1, h2⟩

theorem chIdx_lt {n : Nat} {st : St} {L : Bytes} (h : HasCh n st L) : chIdx n st L < st.ents.length := by
  obtain ⟨j, r, h1, h2⟩ := h
  have hj := lt_entry h1
  refine Nat.lt_of_le_of_lt (Nat.le_of_not_lt (fun hlt => ?_)) hj
  unfold chIdx at hlt
  have := fr_before _ st.ents j _ h1 hlt
  simp at this
  exact this h2

section
variable {α : Type} (n : Nat) (P : Prog α) (st0 : St)

/-- The pair at index `(s, s', h)`: step `s'` appends an adversary entry at `L`, and
    either (`s = s'`) a challenger thash entry at `L` already exists, the pinned
    coordinate `h` being the new adversary entry; or (`s' < s`) step `s` appends the
    first challenger thash entry at `L`, the pinned coordinate being that entry. -/
def PairW (t : List Nat) (i : Nat × Nat × Nat) : Prop :=
  ∃ (stp stp' : St × Ev) (L : Bytes), (strace t P st0)[i.1]? = some stp ∧ (strace t P st0)[i.2.1]? = some stp' ∧
    i.2.2 = stp.1.ents.length ∧ i.2.2 ∉ stp.1.rev ∧ AdvNew n t stp' L ∧
    ((i.1 = i.2.1 ∧ HasCh n stp.1 L) ∨ (i.2.1 < i.1 ∧ ChNew n t stp L ∧ ¬ HasCh n stp.1 L))

noncomputable def pairW (i : Nat × Nat × Nat) (t : List Nat) : Nat :=
  @ite _ (PairW n P st0 t i) (Classical.propDecidable _) 1 0

/-- The earlier entry's value: the first challenger entry at the adversary request's
    literal, or the adversary entry appended at step `s'`. -/
noncomputable def pairTg (i : Nat × Nat × Nat) (t : List Nat) : Nat :=
  match (strace t P st0)[i.1]?, (strace t P st0)[i.2.1]? with
  | some stp, some stp' =>
    if i.1 = i.2.1 then t.getD (chIdx n stp.1 (advLit stp)) 0 else t.getD stp'.1.ents.length 0
  | _, _ => 0

theorem advNew_set {t : List Nat} {h y : Nat} {stp : St × Ev} {L : Bytes} (hh : h ∉ stp.1.rev) :
    AdvNew n (t.set h y) stp L ↔ AdvNew n t stp L := by
  unfold AdvNew
  constructor
  · rintro ⟨q, h1, h2, h3⟩
    refine ⟨q, h1, h2, ?_⟩
    rw [← h3]; exact firstIdx_congr _ _ _ (fun e _ => (mA_false_set t h y stp.1.rev q e hh).symm)
  · rintro ⟨q, h1, h2, h3⟩
    refine ⟨q, h1, h2, ?_⟩
    rw [← h3]; exact firstIdx_congr _ _ _ (fun e _ => mA_false_set t h y stp.1.rev q e hh)

theorem chNew_set {t : List Nat} {h y : Nat} {stp : St × Ev} {L : Bytes} (hh : h ∉ stp.1.rev) :
    ChNew n (t.set h y) stp L ↔ ChNew n t stp L := by
  unfold ChNew
  constructor
  · rintro ⟨r, h1, h2, h3⟩
    refine ⟨r, h1, h2, ?_⟩
    rw [← h3]; exact firstIdx_congr _ _ _ (fun e _ => (mC_set t h y stp.1.rev r e hh).symm)
  · rintro ⟨r, h1, h2, h3⟩
    refine ⟨r, h1, h2, ?_⟩
    rw [← h3]; exact firstIdx_congr _ _ _ (fun e _ => mC_set t h y stp.1.rev r e hh)

/-- The earlier step's handles are unrevealed at the later step if they are there. -/
theorem rev_le {t : List Nat} {s' s : Nat} {stp' stp : St × Ev} (hle : s' ≤ s)
    (h1 : (strace t P st0)[s']? = some stp') (h2 : (strace t P st0)[s]? = some stp) :
    ∀ x ∈ stp'.1.rev, x ∈ stp.1.rev := by
  rcases Nat.lt_or_eq_of_le hle with hlt | rfl
  · intro x hx
    exact (trace_grow2 t P st0 s' s stp' stp hlt h1 h2).2 x ((post_grow t stp').2 x hx)
  · rw [h1] at h2; obtain rfl := Option.some.inj h2; exact fun _ h => h

/-- The pair condition does not depend on the pinned coordinate. -/
theorem pairW_set (t : List Nat) (i : Nat × Nat × Nat) (y : Nat) (hp : PairW n P st0 t i) :
    PairW n P st0 (t.set i.2.2 y) i ∧
      (strace (t.set i.2.2 y) P st0)[i.1]? = (strace t P st0)[i.1]? ∧
      (strace (t.set i.2.2 y) P st0)[i.2.1]? = (strace t P st0)[i.2.1]? := by
  obtain ⟨stp, stp', L, h1, h2, hh, hnr, hA, hcase⟩ := hp
  have hle : i.2.1 ≤ i.1 := by rcases hcase with ⟨he, _⟩ | ⟨hl, _⟩ <;> omega
  have hT := strace_inv t i.2.2 y P st0 i.1 stp h1 hnr
  have e1 : (strace (t.set i.2.2 y) P st0)[i.1]? = (strace t P st0)[i.1]? := by
    have := congrArg (fun l => l[i.1]?) hT
    simpa only [List.getElem?_take, Nat.lt_succ_self, if_true] using this
  have e2 : (strace (t.set i.2.2 y) P st0)[i.2.1]? = (strace t P st0)[i.2.1]? := by
    have := congrArg (fun l => l[i.2.1]?) hT
    simpa only [List.getElem?_take, show i.2.1 < i.1 + 1 by omega, if_true] using this
  have hnr' : i.2.2 ∉ stp'.1.rev := fun hm => hnr (rev_le P st0 hle h2 h1 _ hm)
  refine ⟨⟨stp, stp', L, by rw [e1]; exact h1, by rw [e2]; exact h2, hh, hnr, (advNew_set n hnr').mpr hA, ?_⟩, e1, e2⟩
  rcases hcase with h | ⟨hl, hc, hn⟩
  · exact Or.inl h
  · exact Or.inr ⟨hl, (chNew_set n hnr).mpr hc, hn⟩

theorem pairW_inv (i : Nat × Nat × Nat) (t : List Nat) (y : Nat) :
    pairW n P st0 i (t.set i.2.2 y) = pairW n P st0 i t := by
  unfold pairW
  by_cases h : PairW n P st0 t i
  · rw [if_pos h, if_pos (pairW_set n P st0 t i y h).1]
  · rw [if_neg h, if_neg]
    intro h'
    apply h
    have := (pairW_set n P st0 (t.set i.2.2 y) i (t.getD i.2.2 0) h').1
    rwa [set_set_back] at this

theorem pairTg_inv (i : Nat × Nat × Nat) (t : List Nat) (y : Nat) (hw : pairW n P st0 i t ≠ 0) :
    pairTg n P st0 i (t.set i.2.2 y) = pairTg n P st0 i t := by
  have hp : PairW n P st0 t i := by
    unfold pairW at hw
    by_cases h : PairW n P st0 t i
    · exact h
    · rw [if_neg h] at hw; exact absurd rfl hw
  obtain ⟨_, e1, e2⟩ := pairW_set n P st0 t i y hp
  obtain ⟨stp, stp', L, h1, h2, hh, hnr, ⟨q, hq, hAt, hnew⟩, hcase⟩ := hp
  unfold pairTg
  rw [e1, e2, h1, h2]
  simp only
  rcases hcase with ⟨he, hc⟩ | ⟨hl, hc, _⟩
  · rw [if_pos he, if_pos he]
    have hL : advLit stp = L := by
      rw [he] at h1; rw [h1] at h2; obtain rfl := Option.some.inj h2
      simp only [advLit, hq]; exact hAt.2.2.2
    rw [hL]
    exact getD_set_ne t i.2.2 (chIdx n stp.1 L) y (by have := chIdx_lt hc; omega)
  · rw [if_neg (show ¬ (i.1 = i.2.1) by omega), if_neg (show ¬ (i.1 = i.2.1) by omega)]
    refine getD_set_ne t i.2.2 _ y ?_
    have hg := trace_grow2 t P st0 _ _ _ _ hl h2 h1
    obtain ⟨⟨L', hL'⟩, _⟩ := hg
    have hpost : (stepPost t stp').ents.length = stp'.1.ents.length + 1 := by
      obtain ⟨st', ev'⟩ := stp'
      simp only at hq; subst hq
      simp only [stepPost, addA]
      simp only at hnew
      rw [if_neg (by omega)]; simp
    have := congrArg List.length hL'
    simp at this
    omega

end

section
variable {α : Type} (n : Nat) (P : Prog α) (st0 : St)

theorem chNew_post {t : List Nat} {stp : St × Ev} {L : Bytes} (h : ChNew n t stp L) :
    HasCh n (stepPost t stp) L := by
  obtain ⟨r, hr, hc, hnew⟩ := h
  obtain ⟨st, ev⟩ := stp
  simp only at hr; subst hr
  simp only at hnew
  refine ⟨st.ents.length, r, ?_, hc⟩
  simp only [stepPost, addC, hnew, Nat.lt_irrefl, if_false]
  simp

theorem advAt_lit {q : Request} {L L' : Bytes} (h : AdvAt n q L) (h' : AdvAt n q L') : L = L' :=
  h.2.2.2.symm.trans h'.2.2.2

theorem pairW_le (i : Nat × Nat × Nat) (t : List Nat) : pairW n P st0 i t ≤ 1 := by
  unfold pairW; split <;> omega

theorem pairW_pos {i : Nat × Nat × Nat} {t : List Nat} (h : pairW n P st0 i t ≠ 0) : PairW n P st0 t i := by
  unfold pairW at h
  by_cases hp : PairW n P st0 t i
  · exact hp
  · rw [if_neg hp] at h; exact absurd rfl h

/-- At most one pinned coordinate per pair of steps. -/
theorem pair_h (t : List Nat) (s s' N : Nat) :
    ((List.range N).map (fun h => pairW n P st0 (s, s', h) t)).sum ≤
      @ite _ (∃ h, PairW n P st0 t (s, s', h)) (Classical.propDecidable _) 1 0 := by
  by_cases hx : ∃ h, PairW n P st0 t (s, s', h)
  · rw [if_pos hx]
    refine sum_le_one _ (fun h => pairW_le n P st0 _ t) (fun a b hab ha hb => ?_) N
    obtain ⟨stp, _, _, h1, _, e1, _⟩ := pairW_pos n P st0 ha
    obtain ⟨stp2, _, _, h2, _, e2, _⟩ := pairW_pos n P st0 hb
    simp only at h1 h2 e1 e2
    rw [h1] at h2; obtain rfl := Option.some.inj h2
    omega
  · rw [if_neg hx]
    have : ∀ h ∈ List.range N, pairW n P st0 (s, s', h) t = 0 := by
      intro h _
      unfold pairW
      rw [if_neg (fun hp => hx ⟨h, hp⟩)]
    rw [List.map_congr_left this, sum_map_zero]; exact Nat.le_refl 0

/-- For a fixed adversary step, at most one step carries a pair. -/
theorem pair_s (t : List Nat) (s' S : Nat) :
    ((List.range S).map (fun s => @ite _ (∃ h, PairW n P st0 t (s, s', h)) (Classical.propDecidable _) 1 0)).sum ≤
      if ((strace t P st0)[s']?.map isAev) = some true then 1 else 0 := by
  by_cases hA : ((strace t P st0)[s']?.map isAev) = some true
  · rw [if_pos hA]
    refine sum_le_one _ (fun s => by split <;> omega) (fun s1 s2 hlt ha hb => ?_) S
    have ha' : ∃ h, PairW n P st0 t (s1, s', h) := by
      by_cases hh : ∃ h, PairW n P st0 t (s1, s', h)
      · exact hh
      · rw [if_neg hh] at ha; exact absurd rfl ha
    have hb' : ∃ h, PairW n P st0 t (s2, s', h) := by
      by_cases hh : ∃ h, PairW n P st0 t (s2, s', h)
      · exact hh
      · rw [if_neg hh] at hb; exact absurd rfl hb
    obtain ⟨h1, stp1, stp1', L1, e1, e1', _, _, hA1, hc1⟩ := ha'
    obtain ⟨h2, stp2, stp2', L2, e2, e2', _, _, hA2, hc2⟩ := hb'
    simp only at e1 e1' e2 e2' hc1 hc2
    rw [e1'] at e2'; obtain rfl := Option.some.inj e2'
    have hL : L1 = L2 := by
      obtain ⟨q1, hq1, ha1, _⟩ := hA1
      obtain ⟨q2, hq2, ha2, _⟩ := hA2
      rw [hq1] at hq2; cases hq2
      exact advAt_lit n ha1 ha2
    subst hL
    rcases hc2 with ⟨he, _⟩ | ⟨hl2, _, hno⟩
    · rcases hc1 with ⟨he1, _⟩ | ⟨hl1, _⟩ <;> omega
    · have hg := trace_grow2 t P st0 s1 s2 stp1 stp2 hlt e1 e2
      rcases hc1 with ⟨_, hh⟩ | ⟨_, hc, _⟩
      · exact hno (hasCh_mono (grow_trans (post_grow t stp1) hg) hh)
      · exact hno (hasCh_mono hg (chNew_post n hc))
  · rw [if_neg hA]
    have : ∀ s ∈ List.range S,
        @ite _ (∃ h, PairW n P st0 t (s, s', h)) (Classical.propDecidable _) 1 0 = 0 := by
      intro s _
      rw [if_neg]
      rintro ⟨h, stp, stp', L, _, e', _, _, ⟨q, hq, _⟩, _⟩
      apply hA
      simp only at e'
      rw [e']
      simp [isAev, hq]
    rw [List.map_congr_left this, sum_map_zero]; exact Nat.le_refl 0

/-- The pair count is at most the number of adversary steps. -/
theorem pair_count (S N : Nat) (t : List Nat) :
    ((idx S N).map (fun i => pairW n P st0 i t)).sum ≤ ((strace t P st0).filter isAev).length := by
  unfold idx
  rw [sum_flatMap]
  have e : ∀ s, (((List.range S).flatMap (fun j => (List.range N).map (fun h => (s, j, h)))).map
      (fun i => pairW n P st0 i t)).sum =
      ((List.range S).map (fun j => ((List.range N).map (fun h => pairW n P st0 (s, j, h) t)).sum)).sum := by
    intro s
    rw [sum_flatMap]
    simp only [List.map_map, Function.comp_def]
  simp only [e]
  rw [sum_swap (fun s j => ((List.range N).map (fun h => pairW n P st0 (s, j, h) t)).sum) S S]
  calc _ ≤ ((List.range S).map (fun j => ((List.range S).map (fun s =>
          @ite _ (∃ h, PairW n P st0 t (s, j, h)) (Classical.propDecidable _) 1 0)).sum)).sum :=
        sum_map_le _ (fun j _ => sum_map_le _ (fun s _ => pair_h n P st0 t s j N))
    _ ≤ ((List.range S).map (fun j => if ((strace t P st0)[j]?.map isAev) = some true then 1 else 0)).sum :=
        sum_map_le _ (fun j _ => pair_s n P st0 t j S)
    _ ≤ _ := sum_idx_filter isAev (strace t P st0) S

end

/-! The verifier's thash requests lie on the forged path. -/

section
variable (o : Oracle Id) (p : Params) (tk : Bytes)

theorem chainLog_adr (a : Adrs) : ∀ (x : Bytes) (s k : Nat) (q : Request), q ∈ chainLog o p tk a x s k →
    ∃ j x', s ≤ j ∧ j < s + k ∧ q = thashReq p tk {a with hash := j} x'
  | _, _, 0, _, h => by simp [chainLog] at h
  | x, s, k+1, q, h => by
    simp only [chainLog, List.mem_cons] at h
    rcases h with rfl | h
    · exact ⟨s, x, Nat.le_refl _, by omega, rfl⟩
    · obtain ⟨j, x', h1, h2, h3⟩ := chainLog_adr a _ (s+1) k q h
      exact ⟨j, x', by omega, by omega, h3⟩

theorem authWalkLog_adr (a : Adrs) (auth : Bytes) : ∀ (r li gi : Nat) (node : Bytes) (level : Nat) (q : Request),
    q ∈ authWalkLog o p tk a li gi node auth level r →
    ∃ j x', j < r ∧ q = thashReq p tk {a with chain := level + j + 1, hash := gi / 2^(j+1)} x'
  | 0, _, _, _, _, _, h => by simp [authWalkLog] at h
  | r+1, li, gi, node, level, q, h => by
    simp only [authWalkLog, List.mem_cons] at h
    rcases h with rfl | h
    · exact ⟨0, _, by omega, by rw [show level + 0 + 1 = level + 1 by omega, show (2:Nat)^(0+1) = 2 by rfl]⟩
    · obtain ⟨j, x', h1, h2⟩ := authWalkLog_adr a auth r _ _ _ _ q h
      refine ⟨j+1, x', by omega, ?_⟩
      rw [h2, Nat.div_div_eq_div_mul, ← Nat.pow_succ']
      congr 3
      omega

theorem wotsLog_adr (a : Adrs) (sig msg : Bytes) (q : Request) (h : q ∈ wotsPkFromSigLog o p tk a sig msg) :
    (∃ ci j x', ci < p.len ∧ j < 15 ∧ q = thashReq p tk {{a with chain := ci} with hash := j} x') ∨
    (∃ x', q = thashReq p tk {a.setType 1 with keypair := a.keypair} x') := by
  unfold wotsPkFromSigLog at h
  rcases List.mem_append.mp h with h | h
  · obtain ⟨x, hx, hm⟩ := List.mem_flatMap.mp h
    have hx' := List.mem_zipIdx_iff_getElem?.mp hx
    have hlt : x.2 < (wotsDigits p msg).length := (List.getElem?_eq_some_iff.mp hx').1
    rw [wots_digit_count] at hlt
    have h15 : x.1 ≤ 15 := by
      have := digits_le15 p msg x.2
      rw [List.getD_eq_getElem?_getD, hx'] at this
      simpa using this
    obtain ⟨j, x', h1, h2, h3⟩ := chainLog_adr o p tk _ _ _ _ q hm
    exact Or.inl ⟨x.2, j, x', hlt, by omega, h3⟩
  · simp only [List.mem_singleton] at h
    exact Or.inr ⟨_, h⟩

theorem xmssLog_adr (a : Adrs) (idx : Nat) (sig msg : Bytes) (q : Request)
    (h : q ∈ xmssPkFromSigLog o p tk a idx sig msg) :
    (∃ ci j x', ci < p.len ∧ j < 15 ∧
      q = thashReq p tk {{({a.setType 0 with keypair := idx} : Adrs) with chain := ci} with hash := j} x') ∨
    (∃ x', q = thashReq p tk (compA {a.setType 0 with keypair := idx}) x') ∨
    (∃ j x', j < p.hp ∧ q = thashReq p tk {a.setType 2 with chain := j + 1, hash := idx / 2^(j+1)} x') := by
  unfold xmssPkFromSigLog at h
  rcases List.mem_append.mp h with h | h
  · rcases wotsLog_adr o p tk _ _ _ q h with h | ⟨x', hx⟩
    · exact Or.inl h
    · exact Or.inr (Or.inl ⟨x', hx⟩)
  · obtain ⟨j, x', h1, h2⟩ := authWalkLog_adr o p tk _ _ _ _ _ _ _ q h
    exact Or.inr (Or.inr ⟨j, x', h1, by rw [h2]; congr 3; omega⟩)

theorem htTailLog_adr : ∀ (r layer tree : Nat) (node sig : Bytes) (q : Request),
    q ∈ htRootTailLog o p tk layer tree node sig r →
    ∃ i sg nd, i < r ∧ q ∈ xmssPkFromSigLog o p tk {layer := layer + i, tree := tree / 2^(p.hp*i) / 2^p.hp}
      (tree / 2^(p.hp*i) % 2^p.hp) sg nd
  | 0, _, _, _, _, _, h => by simp [htRootTailLog] at h
  | r+1, layer, tree, node, sig, q, h => by
    simp only [htRootTailLog, List.mem_append] at h
    rcases h with h | h
    · exact ⟨0, _, _, by omega, by simpa [nextLayer] using h⟩
    · obtain ⟨i, sg, nd, h1, h2⟩ := htTailLog_adr r (layer+1) _ _ _ q h
      refine ⟨i+1, sg, nd, by omega, ?_⟩
      have e : (nextLayer p tree).2 / 2^(p.hp*i) = tree / 2^(p.hp*(i+1)) := by
        simp only [nextLayer]
        rw [Nat.div_div_eq_div_mul, ← Nat.pow_add]
        congr 2
        rw [Nat.mul_succ]; omega
      rw [e, show layer + 1 + i = layer + (i+1) by omega] at h2
      exact h2

theorem forsLog_adr (a : Adrs) (sig md : Bytes) (q : Request) (h : q ∈ forsPkFromSigLog o p tk a sig md) :
    (∃ i d x', i < p.k ∧ d < 2^p.a ∧ q = thashReq p tk {a with chain := 0, hash := i*2^p.a + d} x') ∨
    (∃ i d j x', i < p.k ∧ d < 2^p.a ∧ j < p.a ∧
      q = thashReq p tk {a with chain := j + 1, hash := (i*2^p.a + d) / 2^(j+1)} x') ∨
    (∃ x', q = thashReq p tk {a.setType 4 with keypair := a.keypair} x') := by
  unfold forsPkFromSigLog at h
  rcases List.mem_append.mp h with h | h
  · obtain ⟨x, hx, hm⟩ := List.mem_flatMap.mp h
    have hx' := List.mem_zipIdx_iff_getElem?.mp hx
    have hlt : x.2 < (base2b md p.a p.k).length := (List.getElem?_eq_some_iff.mp hx').1
    rw [base2b_length] at hlt
    have hd : x.1 < 2^p.a := base2b_digit_bound md p.a p.k _ (List.mem_of_getElem? hx')
    simp only [List.mem_cons] at hm
    rcases hm with rfl | hm
    · exact Or.inl ⟨x.2, x.1, _, hlt, hd, rfl⟩
    · obtain ⟨j, x', h1, h2⟩ := authWalkLog_adr o p tk _ _ _ _ _ _ _ q hm
      exact Or.inr (Or.inl ⟨x.2, x.1, j, x', hlt, hd, h1, by rw [h2]; congr 3; omega⟩)
  · simp only [List.mem_singleton] at h
    exact Or.inr (Or.inr ⟨_, h⟩)

end

theorem thashReq_bytes {p : Params} {k k' : Bytes} {b b' : Adrs} {x x' : Bytes}
    (h : thashReq p k b x = thashReq p k' b' x') : b.bytes = b'.bytes := by
  have := congrArg Request.input h
  simp only [thashReq] at this
  exact (List.append_inj this (by rw [address_width, address_width])).1

theorem pathT_eq (p : Params) (I : Indices) (l : Nat) (hleaf : I.leaf < 2^p.hp) :
    pathT p I l = I.tree / 2^(p.hp*l) := by
  unfold pathT
  have hp : 0 < 2^p.hp := Nat.two_pow_pos _
  rw [Nat.div_div_eq_div_mul, Nat.mul_comm (2^(p.hp*l)), ← Nat.div_div_eq_div_mul]
  have : (I.tree*2^p.hp + I.leaf)/2^p.hp = I.tree := by
    rw [Nat.add_comm, Nat.add_mul_div_right _ _ hp, Nat.div_eq_of_lt hleaf, Nat.zero_add]
  rw [this]

/-- The address literal `L` is that of an address of the forged path: a root (the FORS
    roots compression, or a layer's tree top) or one of a root's canonical descendants. -/
def PathAt (p : Params) (I : Indices) (L : Bytes) : Prop :=
  ∃ b R, b.bytes = L ∧
    (R = frA (forsAdrs I.tree I.leaf) ∨ ∃ l, l < p.d ∧ R = nodeA {layer := l, tree := pathT p I l} p.hp 0) ∧
    (b = R ∨ Reach p R (.th b))

theorem reach_froot (p : Params) (a : Adrs) (ha : a.kind = 3) {i : Nat} (hi : i < p.k) {h x : Nat}
    (hh : h < p.a) (hx : x / 2^(p.a - h) = i) : Reach p (frA a) (.th (fA a h x)) := by
  have hroot : Reach p (frA a) (.th (fA a p.a i)) := by
    apply Reach.kid
    rw [kids_frA _ a ha]
    simp only [List.mem_map, List.mem_range]
    exact ⟨_, hi, rfl⟩
  have := reach_fA p a ha (p.a - h - 1) h x
  rw [show h + (p.a - h - 1) + 1 = p.a by omega, show p.a - h - 1 + 1 = p.a - h by omega, hx] at this
  exact reach_trans hroot this

section
variable {c : Ctx}

/-- An XMSS verification's thash requests lie under its tree's top. -/
theorem xmss_path (o : Oracle Id) (tk : Bytes) {l T idx : Nat} (hl : l < 256^4) (hT : T < 256^8)
    (hidx : idx < 2^(params c.v).hp) (sg nd : Bytes) {k x : Bytes} {b : Adrs}
    (hm : thashReq (params c.v) k b x ∈ xmssPkFromSigLog o (params c.v) tk {layer := l, tree := T} idx sg nd) :
    ∃ b', b'.bytes = b.bytes ∧ (b' = nodeA {layer := l, tree := T} (params c.v).hp 0 ∨
      Reach (params c.v) (nodeA {layer := l, tree := T} (params c.v).hp 0) (.th b')) := by
  obtain ⟨_, hH, _⟩ := variant_bounds c.v
  have hp1 : 1 ≤ (params c.v).hp := by cases c.v <;> decide
  have hw : WotsR {({layer := l, tree := T} : Adrs).setType 0 with keypair := idx} :=
    wotsR_node _ hl hT (Nat.lt_of_lt_of_le hidx hH)
  have hcomp : Reach (params c.v) (nodeA {layer := l, tree := T} (params c.v).hp 0)
      (.th (compA {({layer := l, tree := T} : Adrs).setType 0 with keypair := idx})) := by
    have := reach_top (params c.v) {layer := l, tree := T} (h := 0) (i := idx) (by omega) (by simpa using hidx)
    simpa [nodeA] using this
  rcases xmssLog_adr o (params c.v) tk _ idx sg nd _ hm with ⟨ci, j, x', hci, hj, he⟩ | ⟨x', he⟩ | ⟨j, x', hj, he⟩
  · refine ⟨_, (thashReq_bytes he).symm, Or.inr (reach_trans hcomp ?_)⟩
    have := reach_chain (c := c) _ hw ci hci (14 - j) (j+1) (by omega)
    have e : chainKid {({({layer := l, tree := T} : Adrs).setType 0 with keypair := idx} : Adrs) with chain := ci} (j+1) =
        .th {{({({layer := l, tree := T} : Adrs).setType 0 with keypair := idx} : Adrs) with chain := ci} with hash := j} := by
      simp [chainKid]
    rwa [e] at this
  · exact ⟨_, (thashReq_bytes he).symm, Or.inr hcomp⟩
  · refine ⟨_, (thashReq_bytes he).symm, ?_⟩
    have hn : ({({layer := l, tree := T} : Adrs).setType 2 with chain := j + 1, hash := idx / 2^(j+1)} : Adrs) =
        nodeA {layer := l, tree := T} (j+1) (idx / 2^(j+1)) := by simp [nodeA]
    rw [hn]
    rcases Nat.lt_or_ge (j+1) (params c.v).hp with hlt | hge
    · refine Or.inr (reach_top (params c.v) _ hlt ?_)
      rw [Nat.div_lt_iff_lt_mul (Nat.two_pow_pos _), ← Nat.pow_add,
        show (params c.v).hp - (j+1) + (j+1) = (params c.v).hp by omega]
      exact hidx
    · have he' : j + 1 = (params c.v).hp := by omega
      left
      rw [he', Nat.div_eq_of_lt hidx]

/-- A FORS verification's thash requests lie under its roots compression. -/
theorem fors_path (o : Oracle Id) (tk : Bytes) (a : Adrs) (ha : a.kind = 3) (sg md : Bytes) {k x : Bytes} {b : Adrs}
    (hm : thashReq (params c.v) k b x ∈ forsPkFromSigLog o (params c.v) tk a sg md) :
    ∃ b', b'.bytes = b.bytes ∧ (b' = frA a ∨ Reach (params c.v) (frA a) (.th b')) := by
  have hA1 : 1 ≤ (params c.v).a := by cases c.v <;> decide
  have hG : ∀ i d, d < 2^(params c.v).a → (i*2^(params c.v).a + d) / 2^(params c.v).a = i := by
    intro i d hd
    rw [Nat.add_comm, Nat.mul_comm, Nat.add_mul_div_left _ _ (Nat.two_pow_pos _), Nat.div_eq_of_lt hd]; omega
  rcases forsLog_adr o (params c.v) tk a sg md _ hm with ⟨i, d, x', hi, hd, he⟩ | ⟨i, d, j, x', hi, hd, hj, he⟩ | ⟨x', he⟩
  · refine ⟨fA a 0 (i*2^(params c.v).a + d), (thashReq_bytes he).symm, Or.inr ?_⟩
    exact reach_froot (params c.v) a ha hi (by omega) (by simpa using hG i d hd)
  · refine ⟨fA a (j+1) ((i*2^(params c.v).a + d) / 2^(j+1)), (thashReq_bytes he).symm, Or.inr ?_⟩
    have hq : (i*2^(params c.v).a + d) / 2^(j+1) / 2^((params c.v).a - (j+1)) = i := by
      rw [Nat.div_div_eq_div_mul, ← Nat.pow_add, show j + 1 + ((params c.v).a - (j+1)) = (params c.v).a by omega]
      exact hG i d hd
    rcases Nat.lt_or_ge (j+1) (params c.v).a with hlt | hge
    · exact reach_froot (params c.v) a ha hi hlt hq
    · have he' : j + 1 = (params c.v).a := by omega
      rw [he', Nat.sub_self, Nat.pow_zero, Nat.div_one] at hq
      rw [he', hq]
      apply Reach.kid
      rw [kids_frA _ a ha]
      simp only [List.mem_map, List.mem_range]
      exact ⟨_, hi, rfl⟩
  · exact ⟨frA a, (thashReq_bytes he).symm, Or.inl rfl⟩

end

section
variable {c : Ctx}

/-- Every thash request of the verifier's log is at an address of the forged path
    its own digest selects. -/
theorem verifyLog_path (O : Oracle Id) (pk msg sig k x : Bytes) (b : Adrs)
    (hm : thashReq (params c.v) k b x ∈ verifyLog O c.v pk msg sig) :
    PathAt (params c.v) (splitDigest (params c.v) (hmsg O (params c.v) (sig.take (params c.v).n)
      (pk.take (params c.v).n) (pk.drop (params c.v).n) msg)) b.bytes := by
  obtain ⟨_, hH, hd, _⟩ := variant_bounds c.v
  unfold verifyLog at hm
  by_cases hne : msg.isEmpty = true
  · simp [verify, hne] at hm
    change thashReq _ k b x ∈ ([] : List Request) at hm
    simp at hm
  have hd1 : 1 ≤ (params c.v).d := by cases c.v <;> decide
  by_cases hl : pk.length = 2*(params c.v).n ∧ sig.length = (params c.v).sigBytes
  · rw [(verify_exact O c.v pk msg sig (by simpa using hne) hl.1 hl.2).run_empty.2] at hm
    have htl : ∀ dg, (splitDigest (params c.v) dg).tree < 256^8 := split_tree_lt c.v
    have hll : ∀ dg, (splitDigest (params c.v) dg).leaf < 2^(params c.v).hp := split_leaf_lt c.v
    generalize hI : splitDigest (params c.v) (hmsg O (params c.v) (sig.take (params c.v).n)
      (pk.take (params c.v).n) (pk.drop (params c.v).n) msg) = I at hm ⊢
    have hIt : I.tree < 256^8 := hI ▸ htl _
    have hIl : I.leaf < 2^(params c.v).hp := hI ▸ hll _
    simp only [List.mem_append, List.mem_cons, List.mem_nil_iff, or_false] at hm
    rcases hm with (((h | h) | h) | h)
    · have := congrArg Request.mode h; simp [thashReq] at this
    · have := congrArg Request.mode h; simp [thashReq] at this
    · obtain ⟨b', hb, hr⟩ := fors_path (c := c) O _ {tree := I.tree, kind := 3, keypair := I.leaf} rfl _ _ h
      exact ⟨b', _, hb, Or.inl rfl, hr⟩
    · unfold htRootLog at h
      rcases List.mem_append.mp h with h | h
      · obtain ⟨b', hb, hr⟩ := xmss_path (c := c) O _ (l := 0) (by decide) hIt hIl _ _ h
        refine ⟨b', _, hb, Or.inr ⟨0, by omega, ?_⟩, hr⟩
        rw [pathT_eq _ _ _ hIl]; simp
      · obtain ⟨i, sg, nd, hi, h⟩ := htTailLog_adr O (params c.v) _ _ 1 I.tree _ _ _ h
        obtain ⟨b', hb, hr⟩ := xmss_path (c := c) O _ (l := 1 + i) (by omega)
          (Nat.lt_of_le_of_lt (Nat.le_trans (Nat.div_le_self _ _) (Nat.div_le_self _ _)) hIt)
          (Nat.mod_lt _ (Nat.two_pow_pos _)) _ _ h
        refine ⟨b', _, hb, Or.inr ⟨1 + i, by omega, ?_⟩, hr⟩
        rw [pathT_eq _ _ _ hIl, Nat.div_div_eq_div_mul, ← Nat.pow_add]
        congr 3
        rw [Nat.mul_add, Nat.mul_one, Nat.add_comm]
  · exfalso
    have hc : (pk.length != 2*(params c.v).n || sig.length != (params c.v).sigBytes) = true := by
      by_cases h1 : pk.length = 2*(params c.v).n
      · have h2 : sig.length ≠ (params c.v).sigBytes := fun h2 => hl ⟨h1, h2⟩
        simp [h2]
      · simp [h1]
    simp [verify, hne, hc] at hm
    change thashReq _ k b x ∈ ([] : List Request) at hm
    simp at hm

end

/-! Descent and uniqueness of challenger thash entries. -/

section
variable {c : Ctx}

theorem kidAt_kid {st : St} {d j : Nat} {T : Adrs} (hk : KidAt c st d j (.th T)) {B : Adrs}
    (hB : Kid.th B ∈ kids (params c.v) T) : ∃ d' h, KidAt c st d' h (.th B) := by
  obtain ⟨r, hS, _⟩ := hk
  cases d with
  | zero => exact hS.elim
  | succ d =>
  obtain ⟨_, _, _, itk, hs, _, _, hl, hh⟩ := hS
  obtain ⟨k, hk⟩ := List.mem_iff_getElem?.mp hB
  have hkl := (List.getElem?_eq_some_iff.mp hk).1
  obtain ⟨h', _, hm⟩ := hh k (by omega)
  rw [hk] at hm
  obtain ⟨r', h1, h2⟩ := hm
  exact ⟨d, h', r', h1, h2⟩

/-- Descent: a structured entry at `T` has structured entries at all its thash descendants. -/
theorem kidAt_reach {st : St} {T : Adrs} {K : Kid} (hR : Reach (params c.v) T K) :
    ∀ {d j : Nat}, KidAt c st d j (.th T) → ∀ B, K = .th B → ∃ d' h, KidAt c st d' h (.th B) := by
  induction hR with
  | kid hK => intro d j hk B hB; subst hB; exact kidAt_kid hk hK
  | down hB _ ih =>
    intro d j hk B' hB'
    obtain ⟨d', h', hk'⟩ := kidAt_kid hk hB
    exact ih hk' B' hB'

/-- A thash-shaped challenger family request is structured. -/
theorem famOK_th {st : St} {r : SReq} {L : Bytes} (hF : FamOK c st r) (hc : ChAt c.n r L) :
    ∃ d b, StructReq c st d r b ∧ b.bytes = L := by
  obtain ⟨itk, hs, rfl⟩ := hc
  rcases hF with h | h | h | ⟨_, _, h, _⟩ | ⟨_, _, h, _⟩ | ⟨_, _, h, _⟩ | ⟨d, b, hS⟩
  · simp [dTk] at h
  · simp [dPrf] at h
  · simp [dReq] at h
  · have := congrArg SReq.input h; simp [prfReq] at this
  · have := congrArg SReq.input h; simp [rqOf] at this
  · simp [hqOf] at h
  refine ⟨d, b, hS, ?_⟩
  cases d with
  | zero => exact hS.elim
  | succ d =>
    obtain ⟨_, _, _, itk', hs', hr', _⟩ := hS
    have := congrArg SReq.input hr'
    simp only [List.cons.injEq, SV.lit.injEq] at this
    exact this.1.symm

theorem chAt_mode {r : SReq} {n : Nat} {L : Bytes} (h : ChAt n r L) : r.mode = 1 := by
  obtain ⟨_, _, rfl⟩ := h; rfl

/-- Challenger thash entries at one literal are one entry. -/
theorem ch_unique {st : St} (hI : InvS c st) {j1 j2 : Nat} {r1 r2 : SReq} {L : Bytes}
    (h1 : st.ents[j1]? = some (false, r1)) (hc1 : ChAt c.n r1 L)
    (h2 : st.ents[j2]? = some (false, r2)) (hc2 : ChAt c.n r2 L) : j1 = j2 ∧ r1 = r2 := by
  have hF : ∀ (j : Nat) (r : SReq), st.ents[j]? = some (false, r) → ChAt c.n r L → FamOK c st r := by
    intro j r hj hc
    rcases hI.2.2.2.1 j r hj with h3 | hF
    · exfalso
      rcases j with _ | _ | _ | j
      · rw [hI.1.1] at hj; obtain ⟨_, _, h⟩ := hc; simp [coin] at hj; rw [← hj] at h; simp at h
      · rw [hI.1.2.1] at hj; obtain ⟨_, _, h⟩ := hc; simp [coin] at hj; rw [← hj] at h; simp at h
      · rw [hI.1.2.2] at hj; obtain ⟨_, _, h⟩ := hc; simp [coin] at hj; rw [← hj] at h; simp at h
      · omega
    · exact hF
  obtain ⟨d1, b1, hS1, hb1⟩ := famOK_th (hF _ _ h1 hc1) hc1
  obtain ⟨d2, b2, hS2, hb2⟩ := famOK_th (hF _ _ h2 hc2) hc2
  have hR1 : b1.InRange := by cases d1 with | zero => exact hS1.elim | succ => exact hS1.1
  have hR2 : b2.InRange := by cases d2 with | zero => exact hS2.elim | succ => exact hS2.1
  obtain rfl := adrs_bytes_injective b1 b2 hR1 hR2 (hb1.trans hb2.symm)
  obtain rfl := struct_unique hI d1 d2 r1 r2 b1 hS1 hS2
  refine ⟨idx_eq_of_res hI h1 h2 rfl (by show r1.mode ≠ 999; rw [chAt_mode hc1]; decide), rfl⟩

end

section
variable {α : Type} (P : Prog α) (st0 : St)

theorem len_mono (t : List Nat) {s1 s2 : Nat} {stp1 stp2 : St × Ev} (hle : s1 ≤ s2)
    (h1 : (strace t P st0)[s1]? = some stp1) (h2 : (strace t P st0)[s2]? = some stp2) :
    stp1.1.ents.length ≤ stp2.1.ents.length := by
  rcases Nat.lt_or_eq_of_le hle with hlt | rfl
  · obtain ⟨⟨L1, hL1⟩, _⟩ := post_grow t stp1
    obtain ⟨⟨L2, hL2⟩, _⟩ := trace_grow2 t P st0 _ _ _ _ hlt h1 h2
    have := congrArg List.length hL2
    have := congrArg List.length hL1
    simp at *; omega
  · rw [h1] at h2; obtain rfl := Option.some.inj h2; exact Nat.le_refl _

end

/-! A canonical pair on a disagreement-free run is a pinned hit. -/

section
variable (v : Variant) (limits : Limits) (A : Bytes → RAdv)

/-- On a disagreement-free run, an adversary entry and a challenger thash entry at one
    address literal with equal truncated values give a hit of the pair count: the later
    of the two creations is a fresh coordinate equal to the earlier entry's value. -/
theorem pair_hit (t : List Nat) (S N : Nat)
    (hS : ∀ (s : Nat) (stp : St × Ev), (strace t (gameS' v limits A (coinEx (params v).n))
      (coinSt (params v).n))[s]? = some stp → s < S ∧ stp.1.ents.length ≤ S) (hSN : S < N)
    (hnd : ∀ s ∈ strace t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n), dis t s = false)
    {ja j : Nat} {q : Request} {r : SReq} {L : Bytes}
    (hja : (xrun false t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)).2.ents[ja]? =
      some (true, lift q)) (hq : AdvAt (params v).n q L)
    (hj : (xrun false t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)).2.ents[j]? =
      some (false, r)) (hr : ChAt (params v).n r L)
    (hv : t.getD ja 0 % 256^(params v).n = t.getD j 0 % 256^(params v).n) :
    ∃ i ∈ idx S N, pairW (params v).n (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) i t = 1 ∧
      t.getD i.2.2 0 % 256^(params v).n =
        pairTg (params v).n (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) i t % 256^(params v).n := by
  -- abbreviations
  generalize hP : gameS' v limits A (coinEx (params v).n) = P at hS hnd hja hj ⊢
  have hst : ∀ (s : Nat) (stp : St × Ev), (strace t P (coinSt (params v).n))[s]? = some stp →
      InvS (structCtx t v) stp.1 ∧
      StepOK (structCtx t v) stp := by
    intro s stp hs
    subst hP
    exact game_struct (c := structCtx t v) rfl limits A s stp hs (noDis_all hnd s)
  have hl3 : (coinSt (params v).n).ents.length = 3 := rfl
  -- the two creations
  have hja3 : 3 ≤ ja := by
    rcases Nat.lt_or_ge ja 3 with h | h
    · exfalso
      obtain ⟨⟨L0, hL0⟩, _⟩ := xrun_grow t P (coinSt (params v).n)
      rw [hL0, List.getElem?_append_left (by rw [hl3]; exact h)] at hja
      rcases ja with _ | _ | _ | ja
      · simp [coinSt] at hja
      · simp [coinSt] at hja
      · simp [coinSt] at hja
      · omega
    · exact h
  have hj3 : 3 ≤ j := by
    rcases Nat.lt_or_ge j 3 with h | h
    · exfalso
      obtain ⟨⟨L0, hL0⟩, _⟩ := xrun_grow t P (coinSt (params v).n)
      rw [hL0, List.getElem?_append_left (by rw [hl3]; exact h)] at hj
      have hm := chAt_mode hr
      rcases j with _ | _ | _ | j
      · simp [coinSt] at hj; rw [← hj] at hm; simp [coin] at hm
      · simp [coinSt] at hj; rw [← hj] at hm; simp [coin] at hm
      · simp [coinSt] at hj; rw [← hj] at hm; simp [coin] at hm
      · omega
    · exact h
  obtain ⟨sa, stpa, hsa, hla, hca⟩ := entry_creation t P _ ja _ hja (by rw [hl3]; exact hja3)
  obtain ⟨sj, stpj, hsj, hlj, hcj⟩ := entry_creation t P _ j _ hj (by rw [hl3]; exact hj3)
  have hqa : stpa.2 = .a q ∧ firstIdx (mA false t stpa.1.rev q) stpa.1.ents = ja := by
    rcases hca with ⟨q', h1, h2, h3⟩ | ⟨r', _, _, h3⟩
    · have : q' = q := by
        have := congrArg (fun e => e.2.res t) h3
        simpa [lift_res] using this.symm
      subst this; exact ⟨h1, h2⟩
    · cases h3
  have hrj : stpj.2 = .c r ∧ firstIdx (mC false t stpj.1.rev r) stpj.1.ents = j := by
    rcases hcj with ⟨q', _, _, h3⟩ | ⟨r', h1, h2, h3⟩
    · cases h3
    · obtain rfl : r' = r := ((Prod.mk.inj h3).2).symm
      exact ⟨h1, h2⟩
  obtain ⟨hIa, _⟩ := hst sa stpa hsa
  obtain ⟨hIj, hSj⟩ := hst sj stpj hsj
  have hFj : FamOK (structCtx t v) stpj.1 r := by
    have := hSj; simp only [StepOK, hrj.1] at this; exact this
  have hnra : ja ∉ stpa.1.rev := fun hm => by have := (hIa.2.2.1 ja hm).1; omega
  have hnrj : j ∉ stpj.1.rev := fun hm => by have := (hIj.2.2.1 j hm).1; omega
  have hadv : AdvNew (params v).n t stpa L := ⟨q, hqa.1, hq, by rw [hqa.2, hla]⟩
  have hbS := hS sa stpa hsa
  have hbJ := hS sj stpj hsj
  rcases Nat.lt_or_gt_of_ne (show ja ≠ j by intro he; subst he; rw [hja] at hj; cases hj) with hlt | hgt
  · -- the challenger entry is later: pinned at its creation, against the adversary entry
    have hs : sa < sj := by
      rcases Nat.lt_or_ge sa sj with h | h
      · exact h
      · have := len_mono P _ t h hsj hsa; omega
    refine ⟨(sj, sa, j), ?_, ?_, ?_⟩
    · simp only [idx, List.mem_flatMap, List.mem_range, List.mem_map]
      exact ⟨sj, hbJ.1, sa, hbS.1, j, by omega, rfl⟩
    · unfold pairW
      rw [if_pos]
      refine ⟨stpj, stpa, L, hsj, hsa, hlj.symm, hnrj, hadv, Or.inr ⟨hs, ⟨r, hrj.1, hr, by rw [hrj.2, hlj]⟩, ?_⟩⟩
      rintro ⟨j2, r2, h2, hc2⟩
      -- the request has its own entry already: its lookup finds it
      obtain ⟨d0, b0, hS0, hb0⟩ := famOK_th hFj hr
      obtain ⟨d2, b2, hS2, hb2⟩ := famOK_th (c := structCtx t v) (by
        rcases hIj.2.2.2.1 j2 r2 h2 with h3 | hF
        · exfalso
          have hm := chAt_mode hc2
          rcases j2 with _ | _ | _ | j2
          · rw [hIj.1.1] at h2; simp [coin] at h2; rw [← h2] at hm; simp at hm
          · rw [hIj.1.2.1] at h2; simp [coin] at h2; rw [← h2] at hm; simp at hm
          · rw [hIj.1.2.2] at h2; simp [coin] at h2; rw [← h2] at hm; simp at hm
          · omega
        · exact hF) hc2
      have hR0 : b0.InRange := by cases d0 with | zero => exact hS0.elim | succ => exact hS0.1
      have hR2 : b2.InRange := by cases d2 with | zero => exact hS2.elim | succ => exact hS2.1
      obtain rfl := adrs_bytes_injective b0 b2 hR0 hR2 (hb0.trans hb2.symm)
      obtain rfl := struct_unique hIj d0 d2 r r2 b0 hS0 hS2
      have := askS_known (c := structCtx t v) hIj (by rw [chAt_mode hr]; decide) h2
      change firstIdx (mC false t stpj.1.rev r) stpj.1.ents = j2 at this
      rw [hrj.2] at this
      have := lt_entry h2
      omega
    · unfold pairTg
      rw [hsj, hsa]
      simp only [show sj ≠ sa by omega, if_false, hla]
      exact hv.symm
  · -- the adversary entry is later: pinned at its creation, against the challenger entry
    have hs : sj < sa := by
      rcases Nat.lt_or_ge sj sa with h | h
      · exact h
      · have := len_mono P _ t h hsa hsj; omega
    have hel : elig t (stpj.1, .c r) = true := by
      simp only [elig, decide_eq_true_eq]; rw [hrj.2, hlj]; exact Nat.le_refl _
    have hent : stpa.1.ents[j]? = some (false, r) := by
      have := fresh_entry t P _ hs (by rw [hsj]; congr; exact Prod.ext rfl hrj.1) hel hsa
      rwa [hlj] at this
    refine ⟨(sa, sa, ja), ?_, ?_, ?_⟩
    · simp only [idx, List.mem_flatMap, List.mem_range, List.mem_map]
      exact ⟨sa, hbS.1, sa, hbS.1, ja, by omega, rfl⟩
    · unfold pairW
      rw [if_pos]
      exact ⟨stpa, stpa, L, hsa, hsa, hla.symm, hnra, hadv, Or.inl ⟨rfl, j, r, hent, hr⟩⟩
    · unfold pairTg
      rw [hsa]
      simp only [if_true]
      have hlit : advLit stpa = L := by simp only [advLit, hqa.1]; exact hq.2.2.2
      rw [hlit]
      have hci : chIdx (params v).n stpa.1 L = j := by
        have hlt' := chIdx_lt (n := (params v).n) ⟨j, r, hent, hr⟩
        obtain ⟨e, he, hp⟩ := fr_hit _ stpa.1.ents hlt'
        simp only [decide_eq_true_eq] at hp
        obtain ⟨b0, r0⟩ := e
        simp only at hp
        obtain ⟨rfl, hc0⟩ := hp
        exact (ch_unique hIa he hc0 hent hr).1
      rw [hci]
      exact hv
end

/-! A canonical collision outside a disagreement step is a pinned hit or a key collision. -/

section
variable (v : Variant) (limits : Limits) (A : Bytes → RAdv)

theorem ent_lt (t : List Nat) (S N : Nat)
    (hS : ∀ (s : Nat) (stp : St × Ev), (strace t (gameS' v limits A (coinEx (params v).n))
      (coinSt (params v).n))[s]? = some stp → s < S ∧ stp.1.ents.length ≤ S) (hSN : S < N) (h3N : 3 ≤ N)
    {x : Nat} {e : Bool × SReq}
    (he : (xrun false t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)).2.ents[x]? = some e) :
    x < N := by
  rcases Nat.lt_or_ge x 3 with h | h
  · omega
  · obtain ⟨s, stp, hs, hl, _⟩ := entry_creation t _ _ x e he (by show x ≥ 3; exact h)
    have := (hS s stp hs).2; omega

theorem canon_split (t : List Nat) (S N : Nat)
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
    (∃ a b, KeyEnts (params v).n (xrun false t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)).2 a b ∧
      t.getD a 0 % 256^32 = t.getD b 0 % 256^32) := by
  have hnd' : ∀ s ∈ strace t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n), dis t s = false := by
    simp only [anyDis, List.any_eq_false] at hnd
    intro s hs; simpa using hnd s hs
  have hcp := coupling t _ _ hnd'
  obtain ⟨hrel, hdr⟩ := sim_game' (t := t) v limits A (coinSt (params v).n)
  rw [hcp] at hrel hdr
  have h1 : (runG v limits A t).1 = (xrun false t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)).1 := by
    rw [← out_ext]; exact hrel.symm
  have hO : finO' v limits A t = (secCtx t v limits A).O := by
    show oracleOf t (runG' v limits A t).2 = _
    rw [show (runG' v limits A t).2 = _ from hdr]; rfl
  obtain ⟨ρ, hroot, hrootv, hI2, hV, -⟩ := sec_game t v limits A hnd'
  have hD : Pre (resD (secCtx t v limits A).t (xrun false t (gameS' v limits A (coinEx (params v).n))
      (coinSt (params v).n)).2) (secCtx t v limits A).D := ⟨[], by simp [secCtx]⟩
  obtain ⟨hIS, -, ρ', hρ', hExt⟩ := (js_game (c := secCtx t v limits A) rfl limits A (coinSt (params v).n)
    invS_coin rfl).2 hnd'
  obtain rfl : ρ = ρ' := by rw [hroot] at hρ'; exact (by simpa using hρ' : ρ = ρ' ∧ _).1
  have hpk := pk_eq (c := secCtx t v limits A) ρ hrootv
  have hfk : (finKey v limits A t).1 = sres t [.hid 2 (params v).n, .hid ρ (params v).n] := by
    rw [← finKey_ext v limits A t, hO]; exact hpk
  rw [hfk, h1, hO] at hc
  have hIS' : InvS (secCtx t v limits A) (xrun false t (gameS' v limits A (coinEx (params v).n))
      (coinSt (params v).n)).2 := hIS
  have hExt' : ExtF (secCtx t v limits A) ρ
      (xrun false t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)).1.msg
      (xrun false t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)).1.sig
      (xrun false t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)).2 := hExt
  clear hIS hExt
  generalize hst : (xrun false t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)) = fin at *
  obtain ⟨out, stF⟩ := fin
  simp only at hI2 hV hD hIS' hExt' hc
  have hent : ∀ {x : Nat} {e : Bool × SReq}, stF.ents[x]? = some e → x < N := by
    intro x e he
    exact ent_lt v limits A t S N hS hSN h3N (e := e) (by rw [hst]; exact he)
  obtain ⟨b, x, hbR, hm, hne, heq⟩ := hc
  obtain ⟨ja, e, hja, hres, _⟩ := hV _ hm
  have hpath : PathAt (params v) (splitDigest (params v) (hmsg (secCtx t v limits A).O (params v)
      (out.sig.take (params v).n) ((sres t [.hid 2 (params v).n, .hid ρ (params v).n]).take (params v).n)
      ((sres t [.hid 2 (params v).n, .hid ρ (params v).n]).drop (params v).n) out.msg)) b.bytes :=
    verifyLog_path (c := secCtx t v limits A) _ _ _ _ _ _ b hm
  have hdg : hmsg (secCtx t v limits A).O (params v) (out.sig.take (params v).n)
      ((sres t [.hid 2 (params v).n, .hid ρ (params v).n]).take (params v).n)
      ((sres t [.hid 2 (params v).n, .hid ρ (params v).n]).drop (params v).n) out.msg =
      (secCtx t v limits A).O (extReq (secCtx t v limits A) ρ out.msg out.sig) := by
    have := dig_eq (c := secCtx t v limits A) ρ hpk out.msg out.sig
    rw [hpk] at this; exact this
  rw [hdg] at hpath
  obtain ⟨i0, e0, he0, hres0, hES⟩ := hExt'
  have hv0 := entry_val hI2 hD he0
  have hout0 : e0.2.outLen = (params v).m := by
    have := congrArg Request.outLen hres0; simpa [SReq.res, extReq] using this
  rw [hres0, hout0] at hv0
  have hbe : be (params v).m (t.getD i0 0) = (secCtx t v limits A).O (extReq (secCtx t v limits A) ρ out.msg out.sig) := by
    simpa [sres, SV.res] using hv0
  have hES' : ExtS (secCtx t v limits A) (splitDigest (params v)
      ((secCtx t v limits A).O (extReq (secCtx t v limits A) ρ out.msg out.sig))) stF := by
    rw [← hbe]; exact hES
  obtain ⟨b', R, hbb, hR, hbr⟩ := hpath
  have hkR : ∃ i, KidOK (secCtx t v limits A) stF i (.th R) := by
    rcases hR with rfl | ⟨l, hl, rfl⟩
    · exact hES'.1
    · exact hES'.2 l hl
  obtain ⟨i, d, hkd⟩ := hkR
  have hkb : ∃ d' h, KidAt (secCtx t v limits A) stF d' h (.th b') := by
    rcases hbr with rfl | hr
    · exact ⟨d, i, hkd⟩
    · exact kidAt_reach hr hkd b' rfl
  obtain ⟨d', j, r, hSr, hj⟩ := hkb
  have hR' : b'.InRange := by cases d' with | zero => exact hSr.elim | succ => exact hSr.1
  obtain rfl := adrs_bytes_injective b' b hR' hbR hbb
  have hval := struct_val hI2 hD d' r b' hSr
  -- the shape of the structured entry
  cases d' with
  | zero => exact hSr.elim
  | succ d0 =>
  obtain ⟨_, _, _, itk, hs, hrr, hitk, _⟩ := id hSr
  have hchr : ChAt (params v).n r b'.bytes := ⟨itk, hs, hrr⟩
  -- the two values agree
  have hvj := entry_val hI2 hD hj
  have hnr : r.outLen = (params v).n := by rw [hrr]; rfl
  simp only at hvj
  rw [hval, hnr] at hvj
  have hva := entry_val hI2 hD hja
  have hne' : e.2.outLen = (params v).n := by
    have := congrArg Request.outLen hres; simpa [SReq.res, thashReq] using this
  rw [hres, hne'] at hva
  have hbeq : be (params v).n (t.getD ja 0) = be (params v).n (t.getD j 0) := by
    have e1 : sres t [.hid ja (params v).n] = be (params v).n (t.getD ja 0) := by simp [sres, SV.res]
    have e2 : sres t [.hid j (params v).n] = be (params v).n (t.getD j 0) := by simp [sres, SV.res]
    rw [← e1, ← e2]
    exact hva.trans (heq.trans hvj.symm)
  have hv := be_eq_mod hbeq
  have hja3 : 3 ≤ ja := by
    rcases Nat.lt_or_ge ja 3 with h | h
    · exfalso
      have hm1 : (e.2.res (secCtx t v limits A).t).mode = 1 := by rw [hres]; rfl
      rcases ja with _ | _ | _ | ja
      · rw [hI2.1.1] at hja; obtain rfl := Option.some.inj hja; simp [coin, SReq.res] at hm1
      · rw [hI2.1.2.1] at hja; obtain rfl := Option.some.inj hja; simp [coin, SReq.res] at hm1
      · rw [hI2.1.2.2] at hja; obtain rfl := Option.some.inj hja; simp [coin, SReq.res] at hm1
      · omega
    · exact h
  obtain ⟨tag, ra⟩ := e
  cases tag with
  | true =>
    obtain ⟨s0, stp0, hs0, _, hc0⟩ := entry_creation t _ _ ja _ (by rw [hst]; exact hja) (by show 3 ≤ ja; exact hja3)
    rcases hc0 with ⟨q, _, _, hq⟩ | ⟨_, _, _, hq⟩
    · obtain rfl : ra = lift q := (Prod.mk.inj hq).2
      have hqe : q = thashReq (params v) (expTk (secCtx t v limits A).O v (sres t (coinEx (params v).n))) b' x := by
        rw [← hres]; exact (lift_res t q).symm
      left
      refine pair_hit v limits A t S N hS hSN hnd' (q := q) (L := b'.bytes) (by rw [hst]; exact hja) ?_
        (by rw [hst]; exact hj) hchr hv
      subst hqe
      exact ⟨rfl, rfl, rfl, List.take_left' (address_width b')⟩
    · cases hq
  | false =>
    right
    rcases hIS'.2.2.2.1 ja ra hja with hlt | hF
    · omega
    have htk := be_tk hI2 hD hitk
    have hmode := congrArg Request.mode hres
    have hkey := congrArg Request.key hres
    rcases hF with h | h | h | ⟨ipk, A0, hrq, hipk, _, _⟩ | ⟨dk, m, hrq, hdk⟩ | ⟨iR, m, hrq, _⟩ | ⟨d2, b2, hS2⟩
    · subst h; simp [dTk, SReq.res, thashReq] at hmode
    · subst h; simp [dPrf, SReq.res, thashReq] at hmode
    · subst h; simp [dReq, SReq.res, thashReq] at hmode
    · subst hrq
      have hk : be 32 (t.getD ipk 0) = be 32 (t.getD itk 0) := by
        simp [prfReq, SReq.res, sres, SV.res, thashReq] at hkey
        have := hkey.trans htk.symm
        simpa [List.getD_eq_getElem?_getD] using this
      have hne2 : ipk ≠ itk := by
        intro he; rw [he] at hipk; rw [hipk] at hitk; simp [dPrf, dTk] at hitk
      have hm := be_eq_mod hk
      rcases Nat.lt_or_gt_of_ne hne2 with hl | hl
      · exact ⟨ipk, itk, ⟨hl, ⟨_, dPrf_key _, hipk⟩, ⟨_, dTk_key _, hitk⟩⟩, hm⟩
      · exact ⟨itk, ipk, ⟨hl, ⟨_, dTk_key _, hitk⟩, ⟨_, dPrf_key _, hipk⟩⟩, hm.symm⟩
    · subst hrq
      have hk : be 32 (t.getD dk 0) = be 32 (t.getD itk 0) := by
        simp [rqOf, SReq.res, sres, SV.res, thashReq] at hkey
        have := hkey.trans htk.symm
        simpa [List.getD_eq_getElem?_getD] using this
      have hne2 : dk ≠ itk := by
        intro he; rw [he] at hdk; rw [hdk] at hitk; simp [dReq, dTk] at hitk
      have hm := be_eq_mod hk
      rcases Nat.lt_or_gt_of_ne hne2 with hl | hl
      · exact ⟨dk, itk, ⟨hl, ⟨_, dReq_key _, hdk⟩, ⟨_, dTk_key _, hitk⟩⟩, hm⟩
      · exact ⟨itk, dk, ⟨hl, ⟨_, dTk_key _, hitk⟩, ⟨_, dReq_key _, hdk⟩⟩, hm.symm⟩
    · subst hrq; simp [hqOf, SReq.res, thashReq] at hmode
    · exfalso
      cases d2 with
      | zero => exact hS2.elim
      | succ d2 =>
      obtain ⟨hR2, _, _, itk2, hs2, hra, _⟩ := id hS2
      have hin := congrArg Request.input hres
      rw [hra] at hin
      simp only [SReq.res, sres, SV.res, thashReq] at hin
      have hbb2 := (List.append_inj hin (by rw [address_width, address_width])).1
      obtain rfl := adrs_bytes_injective b2 b' hR2 hbR hbb2
      have hra' := struct_unique hIS' _ _ _ _ b2 hS2 hSr
      rw [hra', hval] at hres
      have := congrArg Request.input hres
      simp [thashReq] at this
      exact hne this.symm

end

/-! Counting. -/

/-- Coordinate collisions modulo `256^32` among the first `N` tape entries. -/
theorem pair_coll32 (R N : Nat) (hR : 256^32 ∣ R) (E : List Nat → Prop)
    (hE : ∀ t, E t → ∃ a b, a < b ∧ b < N ∧ t.getD a 0 % 256^32 = t.getD b 0 % 256^32) :
    tsum R N (fun t => ind (E t)) * 256^32 ≤ R^N * (N * N) := by
  have hM : 0 < 256^32 := Nat.pow_pos (by decide)
  let I2 : List (Nat × Nat) := pairsBelow N
  let S2 := fun t : List Nat => (I2.map (fun i => 1 * (if t.getD i.2 0 % 256^32 == t.getD i.1 0 % 256^32 then 1 else 0))).sum
  have hpt : ∀ t, ind (E t) ≤ S2 t := by
    intro t
    by_cases he : E t
    · rw [ind_of he]
      obtain ⟨a, b, hab, hb, hc⟩ := hE t he
      have : 1 ∈ I2.map (fun i => 1 * (if t.getD i.2 0 % 256^32 == t.getD i.1 0 % 256^32 then 1 else 0)) :=
        List.mem_map.mpr ⟨(a, b), mem_pairsBelow.mpr ⟨hab, hb⟩, by
          show 1 * (if (t.getD b 0 % 256^32 == t.getD a 0 % 256^32) = true then 1 else 0) = 1
          rw [hc]; simp⟩
      exact le_sum_of_mem this
    · rw [ind_of_not he]; exact Nat.zero_le _
  have e2 := hits_sum R (256^32) N hM hR I2 (fun i => i.2)
    (fun i hi => (mem_pairsBelow' hi).2)
    (fun _ _ => 1) (fun i t => t.getD i.1 0) (fun _ _ _ _ => rfl)
    (fun i hi t y _ => getD_set_ne t i.2 i.1 y (by have := (mem_pairsBelow' hi).1; omega))
  have c2 : tsum R N (fun t => (I2.map (fun _ => 1)).sum) ≤ R^N * (N * N) := by
    rw [sum_map_const, tsum_const, Nat.mul_one]; exact Nat.mul_le_mul_left _ (pairsBelow_len N)
  calc tsum R N (fun t => ind (E t)) * 256^32 ≤ tsum R N S2 * 256^32 :=
        Nat.mul_le_mul_right _ (tsum_mono R N hpt)
    _ ≤ _ := Nat.le_trans e2 c2

section
variable (v : Variant) (limits : Limits) (A : Bytes → RAdv)

/-- Canonical collisions outside the disagreement tapes of H1': at most `AA` pinned pairs
    against `256^n`, plus key coincidences among the first `N` entries against `256^32`. -/
theorem canon_count (R N S AA : Nat) (hRn : 256^(params v).n ∣ R) (hR : 256^32 ∣ R)
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
    R^N * AA * 256^32 + R^N * (N * N) * 256^(params v).n := by
  let H := fun t : List Nat => ((idx S N).map (fun i => pairW (params v).n (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) i t *
    (if t.getD i.2.2 0 % 256^(params v).n == pairTg (params v).n (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) i t % 256^(params v).n then 1 else 0))).sum
  let K := fun t : List Nat => ∃ a b, a < b ∧ b < N ∧ t.getD a 0 % 256^32 = t.getD b 0 % 256^32
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
      rcases canon_split v limits A t S N (hS t) hSN h3N hev.2 hev.1 with ⟨i, hi, hw, hh⟩ | hk
      · have : 1 ∈ (idx S N).map (fun i => pairW (params v).n (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) i t *
            (if t.getD i.2.2 0 % 256^(params v).n == pairTg (params v).n (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) i t % 256^(params v).n then 1 else 0)) :=
          List.mem_map.mpr ⟨i, hi, by simp only [hw, hh]; simp⟩
        exact Nat.le_trans (le_sum_of_mem this) (Nat.le_add_right _ _)
      · obtain ⟨a, b, ⟨hab, -, ⟨_, -, hb⟩⟩, hm⟩ := hk
        rw [ind_of (P := K t) ⟨a, b, hab, ent_lt v limits A t S N (hS t) hSN h3N hb, hm⟩]; omega
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
  have hk := pair_coll32 R N hR K (fun t h => h)
  have hT := tsum_mono R N hpt
  rw [tsum_add] at hT
  calc _ ≤ (tsum R N H + tsum R N (fun t => ind (K t))) * (256^(params v).n * 256^32) := Nat.mul_le_mul_right _ hT
    _ = tsum R N H * 256^(params v).n * 256^32 + tsum R N (fun t => ind (K t)) * 256^32 * 256^(params v).n := by
        rw [Nat.add_mul, ← Nat.mul_assoc, Nat.mul_comm (256^(params v).n) (256^32), ← Nat.mul_assoc]
    _ ≤ R^N * AA * 256^32 + R^N * (N * N) * 256^(params v).n :=
        Nat.add_le_add (Nat.mul_le_mul_right _ (Nat.le_trans hh hsum)) (Nat.mul_le_mul_right _ hk)

end

/-! The won tapes with the canonical-collision term discharged. -/

section
variable (v : Variant) (limits : Limits) (A : Bytes → RAdv)

/-- On every tape on which H1 is won: a canonical collision outside the disagreement
    tapes of H1', ITSR coverage, or a disagreement step of H1'. -/
theorem rom_win_split' (t : List Nat) :
    ind ((runG v limits A t).1.win = true) ≤
      ind (CanonCollIn (finO' v limits A t) (params v) (expTk (finO' v limits A t) v (sres t (coinEx (params v).n)))
        (expPrf (finO' v limits A t) v (sres t (coinEx (params v).n))) (expSeed v (sres t (coinEx (params v).n)))
        (verifyLog (finO' v limits A t) v (finKey v limits A t).1 (runG v limits A t).1.msg
          (runG v limits A t).1.sig) ∧
        anyDis (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) t = false) +
      ind ((runG v limits A t).1.win = true ∧ CovG v limits A t) +
      (if anyDis (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) t then 1 else 0) := by
  by_cases hw : (runG v limits A t).1.win = true
  · rw [ind_of hw]
    rcases rom_extract_sec v limits A t hw with h | h | h
    · by_cases hd : anyDis (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) t = false
      · have hx := ind_of (P := CanonCollIn (finO' v limits A t) (params v)
          (expTk (finO' v limits A t) v (sres t (coinEx (params v).n)))
          (expPrf (finO' v limits A t) v (sres t (coinEx (params v).n))) (expSeed v (sres t (coinEx (params v).n)))
          (verifyLog (finO' v limits A t) v (finKey v limits A t).1 (runG v limits A t).1.msg
            (runG v limits A t).1.sig) ∧
          anyDis (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) t = false) ⟨h, hd⟩
        omega
      · have hd' : anyDis (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) t = true := by
          simpa using hd
        rw [hd']; simp
    · rw [ind_of (P := (runG v limits A t).1.win = true ∧ CovG v limits A t) ⟨hw, cov_transfer v limits A t hw h⟩]
      omega
    · rw [h]; simp
  · rw [ind_of_not hw]; exact Nat.zero_le _

theorem rom_win_sum' (R N : Nat) (B : Nat) :
    tsum R N (fun t => ind ((runG v limits A t).1.win = true)) * B ≤
      tsum R N (fun t => ind (CanonCollIn (finO' v limits A t) (params v)
        (expTk (finO' v limits A t) v (sres t (coinEx (params v).n)))
        (expPrf (finO' v limits A t) v (sres t (coinEx (params v).n))) (expSeed v (sres t (coinEx (params v).n)))
        (verifyLog (finO' v limits A t) v (finKey v limits A t).1 (runG v limits A t).1.msg
          (runG v limits A t).1.sig) ∧
        anyDis (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) t = false)) * B +
      tsum R N (fun t => ind ((runG v limits A t).1.win = true ∧ CovG v limits A t)) * B +
      tsum R N (fun t => if anyDis (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) t
        then 1 else 0) * B := by
  rw [← Nat.add_mul, ← Nat.add_mul, ← tsum_add, ← tsum_add]
  exact Nat.mul_le_mul_right _ (tsum_mono R N (rom_win_split' v limits A))

end

/-- SPHINCS+-128f, H1, with the canonical-collision term discharged. With `K = 2^128`
    and `R^N` tapes:
    `#won·K^3 ≤ JA·R^N·K^2 + 2·5·AA·R^N·K^2 + 2·S^2·R^N·K + 2·(3·R^N·K^2 + N^2·R^N·K) + AA·R^N·K^2 + N^2·R^N·K`,
    i.e. `Pr[won] ≤ (JA + 11·AA + 6)/2^128 + (2·S^2 + 3·N^2)/2^256`.
    Conditional on the ITSR budget hypotheses, the step bound `S < N` of H1' (every
    pre-step state has at most `S` entries and the trace at most `S` steps), and the
    adversary-step bound `AA` of H1'. -/
theorem rom_win_full_128f (limits : Limits) (A : Bytes → RAdv) (c N q JA S AA : Nat) (hc : 0 < c)
    (hq : q ≤ 2^64)
    (hN : ∀ t : List Nat, t.length = N → (runG .spx128f limits A t).2.length ≤ N)
    (hC : ∀ t : List Nat, t.length = N → ((runG .spx128f limits A t).2.filter isC).length ≤ q)
    (hJ : ∀ t : List Nat, t.length = N → ((runG .spx128f limits A t).2.filter isA).length ≤ JA)
    (hS : ∀ t s stp, (strace t (gameS' .spx128f limits A (coinEx (params .spx128f).n))
      (coinSt (params .spx128f).n))[s]? = some stp → s < S ∧ stp.1.ents.length ≤ S)
    (hA : ∀ t, ((strace t (gameS' .spx128f limits A (coinEx (params .spx128f).n))
      (coinSt (params .spx128f).n)).filter isAev).length ≤ AA)
    (hSN : S < N) (h3N : 3 ≤ N) :
    tsum (c * 256^(params .spx128f).m) N (fun t => ind ((runG .spx128f limits A t).1.win = true)) *
        (256^16 * (256^16 * 256^16)) ≤
      JA * (c * 256^(params .spx128f).m)^N * (256^16 * 256^16) +
      2 * ((c * 256^(params .spx128f).m)^N * (5 * AA) * (256^16 * 256^16)) +
      2 * ((c * 256^(params .spx128f).m)^N * (S * S) * 256^16) +
      2 * ((c * 256^(params .spx128f).m)^N * 3 * (256^16 * 256^16) +
        (c * 256^(params .spx128f).m)^N * (N * N) * 256^16) +
      (c * 256^(params .spx128f).m)^N * AA * (256^16 * 256^16) +
      (c * 256^(params .spx128f).m)^N * (N * N) * 256^16 := by
  have h1 := rom_win_sum' .spx128f limits A (c * 256^(params .spx128f).m) N (2^128)
  have h2 := itsr_game_hid_128f limits A c N q JA hc hq hN hC hJ
  have h3 := Nat.mul_le_mul_right (2^128) (anyDis_sum .spx128f limits A (c * 256^(params .spx128f).m) N)
  have hR : 256^32 ∣ c * 256^(params .spx128f).m :=
    Nat.dvd_mul_left_of_dvd (Nat.pow_dvd_pow 256 (by decide)) c
  have hR16 : 256^16 ∣ c * 256^(params .spx128f).m :=
    Nat.dvd_mul_left_of_dvd (Nat.pow_dvd_pow 256 (by decide)) c
  have h4 := rom_ext_structP .spx128f limits A (c * 256^(params .spx128f).m) N S AA (by decide) hR hS hA
  have h5 := tape_coll (c * 256^(params .spx128f).m) N (256^16) (256^32) (Nat.pow_pos (by decide))
    (Nat.pow_pos (by decide)) hR16 hR h3N _ (coll_event .spx128f limits A N S hS (Nat.le_of_lt hSN))
  have h6 := canon_count .spx128f limits A (c * 256^(params .spx128f).m) N S AA hR16 hR hS hSN h3N hA
  rw [show 32 - (params .spx128f).n = 16 by decide] at h4
  rw [show (256:Nat)^(params .spx128f).n = 256^16 by decide] at h6
  rw [show (2:Nat)^128 = 256^16 by decide] at h1 h2 h3
  rw [show (256:Nat)^32 = 256^16 * 256^16 by decide] at h4 h5 h6
  generalize (256:Nat)^16 = K at h1 h2 h3 h4 h5 h6 ⊢
  generalize (c * 256^(params .spx128f).m)^N = RN at h1 h2 h3 h4 h5 h6 ⊢
  generalize tsum (c * 256^(params .spx128f).m) N (fun t => if anyDis (gameS' .spx128f limits A
    (coinEx (params .spx128f).n)) (coinSt (params .spx128f).n) t then 1 else 0) = D at h1 h3 h4
  generalize tsum (c * 256^(params .spx128f).m) N (fun t => if anyDis (gameS .spx128f limits A
    (coinEx (params .spx128f).n)) (coinSt (params .spx128f).n) t then 1 else 0) = D0 at h2 h3
  generalize tsum (c * 256^(params .spx128f).m) N (fun t => ind ((runG .spx128f limits A t).1.win = true ∧
    CovG .spx128f limits A t)) = Cv at h1 h2
  generalize tsum (c * 256^(params .spx128f).m) N (fun t => ind ((runG .spx128f limits A t).1.win = true)) = W
    at h1 ⊢
  generalize tsum (c * 256^(params .spx128f).m) N (fun t => ind (CanonCollIn (finO' .spx128f limits A t)
    (params .spx128f) (expTk (finO' .spx128f limits A t) .spx128f (sres t (coinEx (params .spx128f).n)))
    (expPrf (finO' .spx128f limits A t) .spx128f (sres t (coinEx (params .spx128f).n)))
    (expSeed .spx128f (sres t (coinEx (params .spx128f).n)))
    (verifyLog (finO' .spx128f limits A t) .spx128f (finKey .spx128f limits A t).1
      (runG .spx128f limits A t).1.msg (runG .spx128f limits A t).1.sig) ∧
    anyDis (gameS' .spx128f limits A (coinEx (params .spx128f).n)) (coinSt (params .spx128f).n) t = false)) = Cn
    at h1 h6
  generalize tsum (c * 256^(params .spx128f).m) N (fun t => if wildCollP (params .spx128f).n
    (gameS' .spx128f limits A (coinEx (params .spx128f).n)) (coinSt (params .spx128f).n) N t ||
    initColl t (coinSt (params .spx128f).n) then 1 else 0) = E at h4 h5
  have g1 := Nat.mul_le_mul_right (K * K) h1
  rw [Nat.add_mul, Nat.add_mul] at g1
  have g2 := Nat.mul_le_mul_right (K * K) h2
  rw [Nat.add_mul] at g2
  have g3 := Nat.mul_le_mul_right (K * K) h3
  have g4 := Nat.mul_le_mul_right K h4
  rw [Nat.add_mul, Nat.add_mul] at g4
  have a1 : ∀ X : Nat, X * K * (K * K) = X * (K * (K * K)) := fun X => Nat.mul_assoc _ _ _
  have a3 : ∀ X : Nat, X * (K * K) * K = X * (K * (K * K)) := fun X => by
    rw [Nat.mul_assoc, Nat.mul_comm (K * K) K]
  have a4 : ∀ X : Nat, X * K * K = X * (K * K) := fun X => Nat.mul_assoc _ _ _
  rw [a1, a1, a1, a1] at g1
  rw [a1, a1] at g2
  rw [a1, a1] at g3
  rw [a3, a3, a4] at g4
  omega

end DSM.Rom
