-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.EufCmaReduction

/- Multi-key EUF-CMA for DSM's SPHINCS+ (BLAKE3) keys. DSM signs every step
   with a fresh ephemeral key whose seed is derived from chain state, so the
   deployed setting is many keys with correlated seeds. The adversary sees
   every public key, asks for signatures under any key adaptively, and wins by
   forging a fresh message under any one of them.

   The reduction is the deterministic forgery extraction applied per key:
   whatever the key material is, a forgery under key j exhibits one of the four
   primitive events FOR KEY J (`forgery_extract_exp`). So the multi-key
   forgery probability is at most the sum over keys of each key's event
   probability, for ANY joint distribution of key expansions and adversary
   coins: correlated, derived or independent seeds alike. No hybrid, no
   simulation and no cryptographic premise is used; the events are exactly the
   per-key primitive assumptions of SPHINCS_BLAKE3_ROLE_MAP.md. -/
namespace DSM.Sphincs.Security

structure MReply where
  key : Nat
  reply : Reply

structure MView where
  publicKeys : List Bytes
  replies : List MReply := []

inductive MMove where
  | query (key : Nat) (message : Bytes)
  | forge (key : Nat) (message signature : Bytes)

abbrev MStrategy := MView → MMove

inductive MOutcome where
  | exhausted (view : MView)
  | forgery (view : MView) (key : Nat) (message signature : Bytes)

def MOutcome.view : MOutcome → MView
  | .exhausted v => v
  | .forgery v _ _ _ => v

def madvance (limits : Limits) (sign : Nat → Bytes → Option Bytes) (view : MView)
    (k : Nat) (m : Bytes) : MView :=
  {view with replies := view.replies ++ [⟨k, reply limits (sign k) m⟩]}

/-- Every query attempt, under any key, consumes one unit of the shared budget. -/
def mrun (limits : Limits) (sign : Nat → Bytes → Option Bytes) (A : MStrategy) :
    Nat → MView → MOutcome
  | 0, view => match A view with
    | .forge k m s => .forgery view k m s
    | .query _ _ => .exhausted view
  | fuel+1, view => match A view with
    | .forge k m s => .forgery view k m s
    | .query k m => mrun limits sign A fuel (madvance limits sign view k m)

/-- The legal messages queried under key `k`. -/
def signedOn (limits : Limits) (view : MView) (k : Nat) : List Bytes :=
  (view.replies.filter (fun r => r.key == k && legal limits r.reply.message)).map
    (fun r => r.reply.message)

def mfresh (limits : Limits) (view : MView) (k : Nat) (m : Bytes) : Bool :=
  !view.replies.any (fun r => r.key == k && legal limits r.reply.message && r.reply.message == m)

def mwins (limits : Limits) (verifyK : Nat → Bytes → Bytes → Bool) : MOutcome → Bool
  | .exhausted _ => false
  | .forgery view k m s =>
    decide (k < view.publicKeys.length) && legal limits m && mfresh limits view k m && verifyK k m s

section
variable (v : Variant) (limits : Limits) (O : Oracle Id)

/-- Key `k` is generated from the k-th 3n-byte expansion. -/
def mkey (exps : List Bytes) (k : Nat) : Bytes × Bytes :=
  keypairFromExpansion O v (exps.getD k [])

def msign (exps : List Bytes) (k : Nat) (m : Bytes) : Option Bytes :=
  if k < exps.length then sign O v (mkey v O exps k).2 m else none

def mverify (exps : List Bytes) (k : Nat) (m s : Bytes) : Bool :=
  (verify O v (mkey v O exps k).1 m s).getD false

def mexperiment (exps : List Bytes) (A : MStrategy) : MOutcome :=
  mrun limits (msign v O exps) A limits.signingAttempts
    ⟨exps.map (fun e => (keypairFromExpansion O v e).1), []⟩

def mforgeEvent (exps : List Bytes) (A : MStrategy) : Bool :=
  mwins limits (mverify v O exps) (mexperiment v limits O exps A)

/-- The four per-key primitive events of `forgery_extract_exp`, for the key
    built from expansion `e`, the messages legally signed under it, and the
    forged pair. -/
def KeyBreak (e : Bytes) (signed : List Bytes) (msg' sig' : Bytes) : Prop :=
  CanonCollIn O (params v) (expTk O v e) (expPrf O v e) (expSeed v e)
      (verifyLog O v (keypairFromExpansion O v e).1 msg' sig') ∨
  WotsEvent O (params v) (expTk O v e) (expPrf O v e) (expSeed v e)
      (sig'.drop ((params v).n + (params v).forsBytes)) ∨
  (∃ i, i < (params v).k ∧
    ¬ RevealedBy O v (keypairFromExpansion O v e).2 signed
      (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')).tree
      (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')).leaf i
      (forsDigit (params v)
        (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')).md i) ∧
    slice sig' ((params v).n + i*(((params v).a+1)*(params v).n)) (params v).n =
      forsSecret O (params v) (expPrf O v e) (expSeed v e)
        (forsAdrs (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')).tree
          (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')).leaf)
        (i*2^(params v).a + forsDigit (params v)
          (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')).md i)) ∨
  CoveredBy O v (keypairFromExpansion O v e).2 signed
    (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig'))
end

theorem mrun_preserves_keys (limits : Limits) (sign : Nat → Bytes → Option Bytes) (A : MStrategy) :
    ∀ (fuel : Nat) (view : MView), (mrun limits sign A fuel view).view.publicKeys = view.publicKeys := by
  intro fuel
  induction fuel with
  | zero => intro view; cases h : A view <;> simp [mrun, h, MOutcome.view]
  | succ fuel ih =>
    intro view
    cases h : A view with
    | forge k m s => simp [mrun, h, MOutcome.view]
    | query k m => simp only [mrun, h]; rw [ih]; rfl

theorem mexperiment_keys (v : Variant) (limits : Limits) (O : Oracle Id) (exps : List Bytes)
    (A : MStrategy) :
    (mexperiment v limits O exps A).view.publicKeys = exps.map (fun e => (keypairFromExpansion O v e).1) :=
  mrun_preserves_keys _ _ _ _ _

/-- A multi-key forgery under key k exhibits one of the four primitive events
    for key k. Only `OutputWidths` and the expansion width are assumed. -/
theorem multi_forgery_extract (v : Variant) (limits : Limits) (O : Oracle Id)
    (widths : OutputWidths O) (exps : List Bytes) (A : MStrategy)
    (hlen : ∀ e ∈ exps, e.length = 3*(params v).n)
    (h : mforgeEvent v limits O exps A = true) :
    ∃ view k m s, mexperiment v limits O exps A = .forgery view k m s ∧ k < exps.length ∧
      KeyBreak v O (exps.getD k []) (signedOn limits view k) m s := by
  unfold mforgeEvent at h
  have hk := mexperiment_keys v limits O exps A
  generalize hout : mexperiment v limits O exps A = out at h hk
  cases out with
  | exhausted view => simp [mwins] at h
  | forgery view k m s =>
    simp only [mwins, Bool.and_eq_true, decide_eq_true_eq] at h
    obtain ⟨⟨⟨hk', _⟩, _⟩, hver⟩ := h
    simp only [MOutcome.view] at hk
    rw [hk, List.length_map] at hk'
    refine ⟨view, k, m, s, rfl, hk', ?_⟩
    have hmem : exps.getD k [] ∈ exps := by
      rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hk']
      exact List.getElem_mem hk'
    have hv : verify O v (keypairFromExpansion O v (exps.getD k [])).1 m s = some true := by
      unfold mverify mkey at hver
      revert hver
      generalize (verify O v (keypairFromExpansion O v (exps.getD k [])).1 m s : Option Bool) = r
      intro hver
      cases r with
      | none => simp at hver
      | some b => cases b <;> simp_all
    exact forgery_extract_exp O v _ (hlen _ hmem) (fun _ => widths _) (fun _ _ => widths _) _ m s hv

/-! ## Probability -/

abbrev MWorld := List Bytes × MStrategy

/-- Key j's primitive event in a world: the forgery is under key j and
    exhibits `KeyBreak` for it. -/
noncomputable def keyBreakEvent (v : Variant) (limits : Limits) (O : Oracle Id) (j : Nat)
    (w : MWorld) : Bool :=
  match mexperiment v limits O w.1 w.2 with
  | .forgery view k m s => cdec (k = j ∧ KeyBreak v O (w.1.getD j []) (signedOn limits view j) m s)
  | .exhausted _ => false

theorem multi_forge_events (v : Variant) (limits : Limits) (O : Oracle Id) (widths : OutputWidths O)
    (N : Nat) (w : MWorld) (hlen : ∀ e ∈ w.1, e.length = 3*(params v).n) (hN : w.1.length ≤ N)
    (h : mforgeEvent v limits O w.1 w.2 = true) :
    badUnion ((List.range N).map (keyBreakEvent v limits O)) w = true := by
  obtain ⟨view, k, m, s, hout, hk, hb⟩ := multi_forgery_extract v limits O widths w.1 w.2 hlen h
  simp only [badUnion, List.any_map, List.any_eq_true, List.mem_range, Function.comp]
  refine ⟨k, by omega, ?_⟩
  unfold keyBreakEvent
  rw [hout]
  exact cdec_true ⟨rfl, hb⟩

theorem eventMass_mono_ofFn {α : Type} {n : Nat} (f : Fin n → α) (e₁ e₂ : α → Bool)
    (h : ∀ i, e₁ (f i) = true → e₂ (f i) = true) :
    eventMass (List.ofFn f) e₁ ≤ eventMass (List.ofFn f) e₂ := by
  have gen : ∀ xs : List α, (∀ x ∈ xs, e₁ x = true → e₂ x = true) →
      eventMass xs e₁ ≤ eventMass xs e₂ := by
    intro xs
    induction xs with
    | nil => intro _; simp [eventMass]
    | cons x xs ih =>
      intro hx
      have rest := ih (fun y hy => hx y (List.mem_cons_of_mem _ hy))
      have head := hx x List.mem_cons_self
      cases h1 : e₁ x <;> cases h2 : e₂ x <;> simp_all [eventMass] <;> omega
  apply gen
  intro x hx
  obtain ⟨i, rfl⟩ := List.mem_ofFn.mp hx
  exact h i

/-- MULTI-KEY REDUCTION. For any joint distribution of key expansions and
    adversary coins (with at most N keys, each a 3n-byte expansion), the
    multi-key forgery count is at most the sum over keys of that key's
    primitive-event count, over the same space. -/
theorem multi_key_reduction (v : Variant) (limits : Limits) (O : Oracle Id) (widths : OutputWidths O)
    (N : Nat) (space : FiniteExperiment MWorld)
    (hspace : ∀ i, (∀ e ∈ (space.sample i).1, e.length = 3*(params v).n) ∧
      (space.sample i).1.length ≤ N) :
    (probability space (fun w => mforgeEvent v limits O w.1 w.2)).numerator ≤
      ((List.range N).map (fun j => (probability space (keyBreakEvent v limits O j)).numerator)).sum := by
  change eventMass (List.ofFn space.sample) _ ≤ _
  calc eventMass (List.ofFn space.sample) (fun w => mforgeEvent v limits O w.1 w.2)
      ≤ eventMass (List.ofFn space.sample) (badUnion ((List.range N).map (keyBreakEvent v limits O))) :=
        eventMass_mono_ofFn _ _ _ (fun i hi =>
          multi_forge_events v limits O widths N _ (hspace i).1 (hspace i).2 hi)
    _ ≤ (((List.range N).map (keyBreakEvent v limits O)).map (eventMass (List.ofFn space.sample))).sum :=
        finite_union_bound _ _
    _ = ((List.range N).map (fun j => (probability space (keyBreakEvent v limits O j)).numerator)).sum := by
        rw [List.map_map]; rfl

/-- Relabelling a finite experiment's outcomes. -/
def FiniteExperiment.map {α β : Type} (X : FiniteExperiment α) (f : α → β) : FiniteExperiment β :=
  ⟨X.cardinality, X.positive, fun i => f (X.sample i)⟩

theorem ofFn_comp_map {α β : Type} : ∀ {n : Nat} (g : Fin n → α) (f : α → β),
    List.ofFn (fun i => f (g i)) = (List.ofFn g).map f
  | 0, _, _ => by simp
  | n+1, g, f => by
    rw [List.ofFn_succ, List.ofFn_succ, List.map_cons, ofFn_comp_map (fun i => g i.succ) f]

theorem eventMass_map {α β : Type} (f : α → β) (e : β → Bool) :
    ∀ xs : List α, eventMass (xs.map f) e = eventMass xs (fun x => e (f x))
  | [] => rfl
  | x :: xs => by simp only [List.map_cons, eventMass, eventMass_map f e xs]

theorem probability_map {α β : Type} (X : FiniteExperiment α) (f : α → β) (e : β → Bool) :
    (probability (X.map f) e).numerator = (probability X (fun x => e (f x))).numerator := by
  change eventMass (List.ofFn (fun i => f (X.sample i))) e = eventMass (List.ofFn X.sample) _
  rw [ofFn_comp_map, eventMass_map]

/-! ## DSM's key generation: one ChaCha20 expansion per 32-byte seed

`generate_keypair_from_seed` expands each seed with ChaCha20, so a list of
seeds (each ephemeral key's derived seed, or any other) gives the expansions
below, and key j is exactly `generateKeypair` of seed j. -/

theorem seed_expansions_width (O : Oracle Id) (widths : OutputWidths O) (v : Variant)
    (seeds : List (Wire 32)) : ∀ e ∈ seeds.map (seedExpansion O v), e.length = 3*(params v).n := by
  intro e he
  obtain ⟨s, _, rfl⟩ := List.mem_map.mp he
  exact seed_expansion_width O widths v s

theorem mkey_of_seeds (O : Oracle Id) (v : Variant) (seeds : List (Wire 32)) (j : Nat)
    (hj : j < seeds.length) :
    mkey v O (seeds.map (seedExpansion O v)) j = generateKeypair O v seeds[j] := by
  unfold mkey
  rw [List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_eq_getElem hj]
  exact (keygen_expansion_refines O v _).symm

/-- The multi-key reduction over a distribution of seed lists (any
    correlation) and adversary coins, keys generated as DSM generates them. -/
theorem multi_key_reduction_seeds (v : Variant) (limits : Limits) (O : Oracle Id)
    (widths : OutputWidths O) (N : Nat) (space : FiniteExperiment (List (Wire 32) × MStrategy))
    (hN : ∀ i, (space.sample i).1.length ≤ N) :
    (probability space (fun w => mforgeEvent v limits O (w.1.map (seedExpansion O v)) w.2)).numerator ≤
      ((List.range N).map (fun j => (probability space
        (fun w => keyBreakEvent v limits O j (w.1.map (seedExpansion O v), w.2))).numerator)).sum := by
  have h := multi_key_reduction v limits O widths N (space.map (fun w => (w.1.map (seedExpansion O v), w.2)))
    (fun i => ⟨seed_expansions_width O widths v _, by
      simp only [FiniteExperiment.map, List.length_map]; exact hN i⟩)
  simp only [probability_map] at h
  exact h

#print axioms multi_forgery_extract
#print axioms multi_forge_events
#print axioms multi_key_reduction
#print axioms mkey_of_seeds
#print axioms multi_key_reduction_seeds
end DSM.Sphincs.Security
