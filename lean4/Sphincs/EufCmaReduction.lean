-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.ForgeryExtractExp

/- End-to-end EUF-CMA accounting. In the last hybrid game (both secret seeds
   gone, PRF and PRF_msg replaced by random functions), every forging world
   exhibits one of four events, each read off the forgery and the game's
   transcript: a canonical thash collision witnessed in the verifier's log,
   a WOTS preimage of an unrevealed honest chain value, an honest FORS secret
   at an index no legal signing query revealed, or the ITSR covered event
   (with the actual h_msg outputs). The forging numerator is bounded by the
   sum of the four event numerators over the same space, and the hybrid hops
   chain this into an exact rational bound on the real game. -/
namespace DSM.Sphincs.Security
open DSM.Sphincs

abbrev FinalWorld (v : Variant) :=
  ((Wire (params v).n × (Bytes → Nat → Bytes)) × (Bytes → Nat → Bytes)) × Strategy

def finalSpace (v : Variant) (limits : Limits) (coins : FiniteExperiment Strategy) :
    FiniteExperiment (FinalWorld v) :=
  independentProduct (independentProduct (independentProduct
    (uniformBytes (params v).n) (randomFunctionUpTo ((params v).n + limits.maxMessageBytes) (params v).n))
    (randomFunction ((params v).n+32) (params v).n)) coins

theorem final_probability (v : Variant) (limits : Limits) (o : Oracle Id) (coins : FiniteExperiment Strategy) :
    idealMsgFunctionProbability v limits o coins =
      probability (finalSpace v limits coins)
        (fun (((pkSeed,H),F),strategy) => msgFunctionDistinguisher v limits strategy o F pkSeed.val H) := rfl

section
variable (v : Variant) (limits : Limits) (o : Oracle Id)

def finalOracle (w : FinalWorld v) : Oracle Id := routeMsg (routePrf o w.1.2) w.1.1.2
def finalExp (w : FinalWorld v) : Bytes := zeros (params v).n ++ zeros (params v).n ++ w.1.1.1.val
def finalOutcome (w : FinalWorld v) : Outcome :=
  expandedExperiment v limits w.2 (finalOracle v o w) (finalExp v w)
end

/-- The legal messages the adversary queried (each was answered by `sign`). -/
def signedIn (limits : Limits) (view : View) : List Bytes :=
  (view.replies.filter (fun r => legal limits r.message)).map Reply.message

/-- Classical Boolean reading of a proposition. -/
noncomputable def cdec (P : Prop) : Bool := @decide P (Classical.propDecidable P)

theorem cdec_true {P : Prop} (h : P) : cdec P = true := @decide_eq_true P (Classical.propDecidable P) h

section
variable (v : Variant) (limits : Limits) (o : Oracle Id)

/-- A canonical thash collision in the verifier's log for the forged pair. -/
noncomputable def collisionEvent (w : FinalWorld v) : Bool :=
  match finalOutcome v limits o w with
  | .forgery _ m s => cdec (CanonCollIn (finalOracle v o w) (params v)
      (expTk (finalOracle v o w) v (finalExp v w)) (expPrf (finalOracle v o w) v (finalExp v w))
      (expSeed v (finalExp v w))
      (verifyLog (finalOracle v o w) v (keypairFromExpansion (finalOracle v o w) v (finalExp v w)).1 m s))
  | .exhausted _ => false

/-- A WOTS preimage of an unrevealed honest chain value in the forged pair. -/
noncomputable def wotsPreimageEvent (w : FinalWorld v) : Bool :=
  match finalOutcome v limits o w with
  | .forgery _ _ s => cdec (WotsEvent (finalOracle v o w) (params v)
      (expTk (finalOracle v o w) v (finalExp v w)) (expPrf (finalOracle v o w) v (finalExp v w))
      (expSeed v (finalExp v w)) (s.drop ((params v).n + (params v).forsBytes)))
  | .exhausted _ => false

/-- The forged signature holds an honest FORS secret at an index no legal
    signing query revealed at the forged digest's hypertree leaf. -/
noncomputable def forsSecretEvent (w : FinalWorld v) : Bool :=
  match finalOutcome v limits o w with
  | .forgery view m s => cdec (∃ i, i < (params v).k ∧
      ¬ RevealedBy (finalOracle v o w) v (keypairFromExpansion (finalOracle v o w) v (finalExp v w)).2
        (signedIn limits view)
        (splitDigest (params v) (verifyDigest (finalOracle v o w) v
          (keypairFromExpansion (finalOracle v o w) v (finalExp v w)).1 m s)).tree
        (splitDigest (params v) (verifyDigest (finalOracle v o w) v
          (keypairFromExpansion (finalOracle v o w) v (finalExp v w)).1 m s)).leaf i
        (forsDigit (params v) (splitDigest (params v) (verifyDigest (finalOracle v o w) v
          (keypairFromExpansion (finalOracle v o w) v (finalExp v w)).1 m s)).md i) ∧
      slice s ((params v).n + i*(((params v).a+1)*(params v).n)) (params v).n =
        forsSecret (finalOracle v o w) (params v) (expPrf (finalOracle v o w) v (finalExp v w))
          (expSeed v (finalExp v w))
          (forsAdrs (splitDigest (params v) (verifyDigest (finalOracle v o w) v
              (keypairFromExpansion (finalOracle v o w) v (finalExp v w)).1 m s)).tree
            (splitDigest (params v) (verifyDigest (finalOracle v o w) v
              (keypairFromExpansion (finalOracle v o w) v (finalExp v w)).1 m s)).leaf)
          (i*2^(params v).a + forsDigit (params v) (splitDigest (params v) (verifyDigest (finalOracle v o w) v
            (keypairFromExpansion (finalOracle v o w) v (finalExp v w)).1 m s)).md i))
  | .exhausted _ => false

/-- ITSR covered: every forged FORS index was selected at the forged
    hypertree leaf by some legal signing query's actual h_msg output. -/
noncomputable def forsCoveredEvent (w : FinalWorld v) : Bool :=
  match finalOutcome v limits o w with
  | .forgery view m s => cdec (CoveredBy (finalOracle v o w) v
      (keypairFromExpansion (finalOracle v o w) v (finalExp v w)).2 (signedIn limits view)
      (splitDigest (params v) (verifyDigest (finalOracle v o w) v
        (keypairFromExpansion (finalOracle v o w) v (finalExp v w)).1 m s)))
  | .exhausted _ => false

noncomputable def finalEvents : List (FinalWorld v → Bool) :=
  [collisionEvent v limits o, wotsPreimageEvent v limits o, forsSecretEvent v limits o,
   forsCoveredEvent v limits o]
end

theorem expanded_public_key (v : Variant) (limits : Limits) (strategy : Strategy) (O : Oracle Id)
    (e : Bytes) : (expandedExperiment v limits strategy O e).view.publicKey =
      (keypairFromExpansion O v e).1 := by
  unfold expandedExperiment
  split
  next pk sk heq =>
    rw [run_preserves_public_key, heq]

theorem randomFunction_width (n inLen : Nat) (i : Fin (randomFunction inLen n).cardinality) (x : Bytes)
    (hx : x.length = inLen) : ((randomFunction inLen n).sample i x n).length = n := by
  simp only [randomFunction, hx, and_self, if_true]
  exact be_width _ _

theorem final_widths (v : Variant) (o : Oracle Id) (widths : OutputWidths o) (w : FinalWorld v)
    (hF : ∃ i, w.1.2 = (randomFunction ((params v).n+32) (params v).n).sample i) :
    (∀ x, (finalOracle v o w ⟨1,"",expTk (finalOracle v o w) v (finalExp v w),x,(params v).n⟩).length =
      (params v).n) ∧
    (∀ x, x.length = (params v).n+32 →
      (finalOracle v o w ⟨1,"",expPrf (finalOracle v o w) v (finalExp v w),x,(params v).n⟩).length =
        (params v).n) := by
  obtain ⟨iF, hF⟩ := hF
  have htk : expTk (finalOracle v o w) v (finalExp v w) =
      o ⟨0,"DSM/sphincs/v2/thash",[],expSeed v (finalExp v w),32⟩ := by
    simp only [expTk, deriveKey, finalOracle]
    rw [rm_unkeyed _ _ _ (by decide), msgpatch_other _ _ _ (by decide), route_unkeyed _ _ _ (by decide),
      patch_other _ _ _ (by decide)]
  have htklen : (expTk (finalOracle v o w) v (finalExp v w)).length = 32 := by rw [htk]; exact widths _
  have hprf : expPrf (finalOracle v o w) v (finalExp v w) = MARK := by
    simp only [expPrf, deriveKey, finalOracle]
    rw [rm_unkeyed _ _ _ (by decide), msgpatch_other _ _ _ (by decide), route_unkeyed _ _ _ (by decide),
      patch_prf]
  constructor
  · intro x
    change (routeMsg (routePrf o w.1.2) w.1.1.2
      ⟨1,"",expTk (finalOracle v o w) v (finalExp v w),x,(params v).n⟩).length = _
    rw [rm_keyed _ _ _ _ _ (not_mark2_of_width _ htklen),
      route_keyed _ _ _ _ _ (not_mark_of_width _ htklen)]
    exact widths _
  · intro x hx
    rw [hprf]
    change (routeMsg (routePrf o w.1.2) w.1.1.2 ⟨1,"",MARK,x,(params v).n⟩).length = _
    rw [rm_keyed _ _ _ _ _ mark_ne_mark2, route_mark, hF]
    exact randomFunction_width _ _ _ _ hx

theorem final_exp_width (v : Variant) (w : FinalWorld v) :
    (finalExp v w).length = 3*(params v).n := by
  simp only [finalExp, zeros, List.length_append, List.length_replicate, w.1.1.1.property]
  omega

/-- In every world of the final game whose PRF function is a random-function
    table, a successful forgery exhibits one of the four events. -/
theorem final_forge_events (v : Variant) (limits : Limits) (o : Oracle Id) (widths : OutputWidths o)
    (w : FinalWorld v) (hF : ∃ i, w.1.2 = (randomFunction ((params v).n+32) (params v).n).sample i)
    (h : msgFunctionDistinguisher v limits w.2 o w.1.2 w.1.1.1.val w.1.1.2 = true) :
    badUnion (finalEvents v limits o) w = true := by
  obtain ⟨tw, pw⟩ := final_widths v o widths w hF
  have hpkv := expanded_public_key v limits w.2 (finalOracle v o w) (finalExp v w)
  change wins limits (fun m s => (verify (finalOracle v o w) v
    (finalOutcome v limits o w).view.publicKey m s).getD false) (finalOutcome v limits o w) = true at h
  simp only [badUnion, finalEvents, List.any_cons, List.any_nil, Bool.or_false]
  unfold collisionEvent wotsPreimageEvent forsSecretEvent forsCoveredEvent
  revert h hpkv
  unfold finalOutcome
  cases (expandedExperiment v limits w.2 (finalOracle v o w) (finalExp v w)) with
  | exhausted view => intro _ h; simp [wins] at h
  | forgery view m s =>
    intro hpkv h
    simp only [wins, Outcome.view, Bool.and_eq_true] at h hpkv
    have hv : verify (finalOracle v o w) v (keypairFromExpansion (finalOracle v o w) v (finalExp v w)).1 m s =
        some true := by
      have g := h.2
      rw [hpkv] at g
      revert g
      cases verify (finalOracle v o w) v (keypairFromExpansion (finalOracle v o w) v (finalExp v w)).1 m s with
      | none => intro g; simp at g
      | some b => intro g; simp at g; rw [g]
    rcases forgery_extract_exp (finalOracle v o w) v (finalExp v w) (final_exp_width v w) tw pw
      (signedIn limits view) m s hv with c | c | c | c
    · simp [cdec_true c]
    · simp [cdec_true c]
    · simp [cdec_true c]
    · simp [cdec_true c]

theorem eventMass_mono_on {α : Type} (xs : List α) (e₁ e₂ : α → Bool)
    (h : ∀ x ∈ xs, e₁ x = true → e₂ x = true) : eventMass xs e₁ ≤ eventMass xs e₂ := by
  induction xs with
  | nil => simp [eventMass]
  | cons x xs ih =>
    have hx := h x (by simp)
    have rest := ih (fun y hy => h y (by simp [hy]))
    simp only [eventMass]
    cases h1 : e₁ x <;> cases h2 : e₂ x <;> simp_all <;> omega

theorem final_space_prf (v : Variant) (limits : Limits) (coins : FiniteExperiment Strategy)
    (w : FinalWorld v) (hw : w ∈ List.ofFn (finalSpace v limits coins).sample) :
    ∃ i, w.1.2 = (randomFunction ((params v).n+32) (params v).n).sample i := by
  obtain ⟨j, rfl⟩ := List.mem_ofFn.mp hw
  exact ⟨_, rfl⟩

/-- Final-game accounting: the forging numerator is at most the sum of the
    four event numerators, all over the final game's space. -/
theorem final_event_bound (v : Variant) (limits : Limits) (o : Oracle Id) (widths : OutputWidths o)
    (coins : FiniteExperiment Strategy) :
    (idealMsgFunctionProbability v limits o coins).numerator ≤
      (probability (finalSpace v limits coins) (collisionEvent v limits o)).numerator +
      (probability (finalSpace v limits coins) (wotsPreimageEvent v limits o)).numerator +
      (probability (finalSpace v limits coins) (forsSecretEvent v limits o)).numerator +
      (probability (finalSpace v limits coins) (forsCoveredEvent v limits o)).numerator := by
  rw [final_probability]
  have h1 := eventMass_mono_on (List.ofFn (finalSpace v limits coins).sample)
    (fun (((pkSeed,H),F),strategy) => msgFunctionDistinguisher v limits strategy o F pkSeed.val H)
    (badUnion (finalEvents v limits o)) (fun w hw hf => by
      have hF := final_space_prf v limits coins w hw
      obtain ⟨⟨⟨pkSeed, H⟩, F⟩, strategy⟩ := w
      exact final_forge_events v limits o widths _ hF hf)
  have h2 := finite_union_bound (List.ofFn (finalSpace v limits coins).sample) (finalEvents v limits o)
  unfold finalEvents at h1 h2
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at h2
  show eventMass _ _ ≤ eventMass _ _ + eventMass _ _ + eventMass _ _ + eventMass _ _
  omega

/-! ## Exact rational chaining

A probability is the fraction `(numerator, denominator)`; `fle a b` is
`a.1/a.2 ≤ b.1/b.2` cross-multiplied, and `fadd` is fraction addition. Both
are exact, with no floating point. `advantage R I` is the constructed
distinguisher's exact gap |Pr_R − Pr_I| = gapNumerator R I / (R.den · I.den). -/

def fle (a b : Nat × Nat) : Prop := a.1 * b.2 ≤ b.1 * a.2
def fadd (a b : Nat × Nat) : Nat × Nat := (a.1 * b.2 + b.1 * a.2, a.2 * b.2)
def Probability.frac (P : Probability) : Nat × Nat := (P.numerator, P.denominator)
def advantage (R I : Probability) : Nat × Nat := (gapNumerator R I, R.denominator * I.denominator)

theorem fle_trans {a b c : Nat × Nat} (hb : 0 < b.2) (h1 : fle a b) (h2 : fle b c) : fle a c := by
  unfold fle at *
  apply Nat.le_of_mul_le_mul_right (c := b.2) _ hb
  calc a.1 * c.2 * b.2 = (a.1 * b.2) * c.2 := by ac_rfl
    _ ≤ (b.1 * a.2) * c.2 := Nat.mul_le_mul_right _ h1
    _ = (b.1 * c.2) * a.2 := by ac_rfl
    _ ≤ (c.1 * b.2) * a.2 := Nat.mul_le_mul_right _ h2
    _ = c.1 * a.2 * b.2 := by ac_rfl

theorem fadd_mono {a a' : Nat × Nat} (b : Nat × Nat) (h : fle a a') : fle (fadd a b) (fadd a' b) := by
  unfold fle fadd at *
  dsimp only
  rw [Nat.add_mul, Nat.add_mul]
  apply Nat.add_le_add
  · calc a.1 * b.2 * (a'.2 * b.2) = (a.1 * a'.2) * (b.2 * b.2) := by ac_rfl
      _ ≤ (a'.1 * a.2) * (b.2 * b.2) := Nat.mul_le_mul_right _ h
      _ = a'.1 * b.2 * (a.2 * b.2) := by ac_rfl
  · exact Nat.le_of_eq (by ac_rfl)

theorem fadd_pos {a b : Nat × Nat} (ha : 0 < a.2) (hb : 0 < b.2) : 0 < (fadd a b).2 :=
  Nat.mul_pos ha hb

theorem hop_frac (P R I : Probability) (hR : R = P)
    (hop : P.numerator * I.denominator ≤ I.numerator * P.denominator + gapNumerator R I) :
    fle P.frac (fadd I.frac (advantage R I)) := by
  subst hR
  unfold fle fadd Probability.frac advantage
  dsimp only
  calc R.numerator * (I.denominator * (R.denominator * I.denominator))
      = (R.numerator * I.denominator) * (R.denominator * I.denominator) := by ac_rfl
    _ ≤ (I.numerator * R.denominator + gapNumerator R I) * (R.denominator * I.denominator) :=
        Nat.mul_le_mul_right _ hop
    _ = (I.numerator * (R.denominator * I.denominator) + gapNumerator R I * I.denominator) *
          R.denominator := by
        rw [Nat.add_mul, Nat.add_mul]; ac_rfl

theorem adv_pos (R I : Probability) : 0 < (advantage R I).2 := Nat.mul_pos R.positive I.positive

/-- End-to-end EUF-CMA reduction, exact over the rationals (as fractions):
    Pr[real forgery] ≤ Pr[canonical collision] + Pr[WOTS preimage]
      + Pr[unrevealed FORS secret] + Pr[ForsCovered]          (final game)
      + Adv_msgFunction + Adv_msgKey + Adv_prfFunction + Adv_prfKey + Adv_seed,
    each Adv the exact gap of the corresponding constructed distinguisher.
    Hypothesis: fixed-width outputs of the real oracle. -/
theorem euf_cma_reduction (v : Variant) (limits : Limits) (o : Oracle Id) (widths : OutputWidths o)
    (coins : FiniteExperiment Strategy) :
    fle (eufCmaProbability v limits o coins).frac
      (fadd (fadd (fadd (fadd (fadd
        ((probability (finalSpace v limits coins) (collisionEvent v limits o)).numerator +
         (probability (finalSpace v limits coins) (wotsPreimageEvent v limits o)).numerator +
         (probability (finalSpace v limits coins) (forsSecretEvent v limits o)).numerator +
         (probability (finalSpace v limits coins) (forsCoveredEvent v limits o)).numerator,
         (finalSpace v limits coins).cardinality)
        (advantage (realMsgFunctionProbability v limits o coins) (idealMsgFunctionProbability v limits o coins)))
        (advantage (realMsgKeyProbability v limits o coins) (idealMsgKeyProbability v limits o coins)))
        (advantage (realPrfFunctionProbability v limits o coins) (idealPrfFunctionProbability v limits o coins)))
        (advantage (realPrfKeyProbability v limits o coins) (idealPrfKeyProbability v limits o coins)))
        (advantage (realSeedChallengeProbability v limits o coins) (idealSeedChallengeProbability v limits o coins))) := by
  have h1 := hop_frac _ _ _ (seed_hybrid_real_equivalence v limits o coins).symm
    (seed_prg_hybrid_bound v limits o coins)
  have h2 := hop_frac _ _ _ (prf_key_real_equivalence v limits o coins).symm
    (prf_key_hybrid_bound v limits o coins)
  have h3 := hop_frac _ _ _ (prf_function_real_equivalence v limits o widths coins).symm
    (prf_function_hybrid_bound v limits o widths coins)
  have h4 := hop_frac _ _ _ (msg_key_real_equivalence v limits o coins).symm
    (msg_key_hybrid_bound v limits o coins)
  have h5 := hop_frac _ _ _ (msg_function_real_equivalence v limits o widths coins).symm
    (msg_function_hybrid_bound v limits o widths coins)
  have h6 : fle (idealMsgFunctionProbability v limits o coins).frac
      ((probability (finalSpace v limits coins) (collisionEvent v limits o)).numerator +
         (probability (finalSpace v limits coins) (wotsPreimageEvent v limits o)).numerator +
         (probability (finalSpace v limits coins) (forsSecretEvent v limits o)).numerator +
         (probability (finalSpace v limits coins) (forsCoveredEvent v limits o)).numerator,
         (finalSpace v limits coins).cardinality) := by
    unfold fle Probability.frac
    rw [final_probability]
    exact Nat.mul_le_mul_right _ (by rw [← final_probability]; exact final_event_bound v limits o widths coins)
  have p := fun (P : Probability) => P.positive
  -- chain from the inside out
  refine fle_trans (fadd_pos (p _) (adv_pos _ _)) h1 ?_
  apply fadd_mono
  refine fle_trans (fadd_pos (p _) (adv_pos _ _)) h2 ?_
  apply fadd_mono
  refine fle_trans (fadd_pos (p _) (adv_pos _ _)) h3 ?_
  apply fadd_mono
  refine fle_trans (fadd_pos (p _) (adv_pos _ _)) h4 ?_
  apply fadd_mono
  refine fle_trans (fadd_pos (p _) (adv_pos _ _)) h5 ?_
  apply fadd_mono
  exact h6

#print axioms final_forge_events
#print axioms final_event_bound
#print axioms euf_cma_reduction
end DSM.Sphincs.Security
