-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.SecurityGames

/- The first narrow substitution: actual ChaCha expansion versus uniform 3n
   bytes. The distinguisher runs the existing adaptive signing/forgery game;
   neither deterministic signing nor BLAKE3 calls are changed. No PRG hardness
   premise is added. This does not supply a full adversary time/memory model. -/
namespace DSM.Sphincs.Security

def seedExpansion (o : Oracle Id) (v : Variant) (seed : Wire 32) : Bytes :=
  o ⟨3,"ChaCha20Rng",[],seed.val,3*(params v).n⟩

-- Same post-expansion key generation as Model.generateKeypair; the equality
-- below checks this decomposition against that existing definition.
def keypairFromExpansion (o : Oracle Id) (v : Variant) (expanded : Bytes) : Bytes × Bytes :=
  let p := params v
  let seed := slice expanded (2*p.n) p.n
  let tk : Bytes := deriveKey o "DSM/sphincs/v2/thash" seed
  let prfKey : Bytes := deriveKey o "DSM/sphincs/v2/prf" (expanded.take p.n)
  let root : Bytes := xmssNode o p tk prfKey seed {layer := p.d-1} 0 p.hp
  (seed++root,expanded++root)

theorem keygen_expansion_refines (o : Oracle Id) (v : Variant) (seed : Wire 32) :
    generateKeypair o v seed = keypairFromExpansion o v (seedExpansion o v seed) := by
  rfl

theorem seed_expansion_width (o : Oracle Id) (widths : OutputWidths o)
    (v : Variant) (seed : Wire 32) :
    (seedExpansion o v seed).length = 3*(params v).n := widths _

theorem expansion_field_widths (n : Nat) (expanded : Wire (3*n)) :
    (expanded.val.take n).length = n ∧
    (slice expanded.val n n).length = n ∧
    (slice expanded.val (2*n) n).length = n := by
  simp only [slice,List.length_take,List.length_drop,expanded.property]
  omega

theorem expanded_keypair_widths (o : Oracle Id) (widths : OutputWidths o)
    (v : Variant) (expanded : Wire (3*(params v).n)) :
    (keypairFromExpansion o v expanded.val).1.length = 2*(params v).n ∧
    (keypairFromExpansion o v expanded.val).2.length = 4*(params v).n := by
  simp only [keypairFromExpansion,List.length_append,xmss_node_width o widths,
    expanded.property,slice,List.length_take,List.length_drop]
  omega

def expandedExperiment (v : Variant) (limits : Limits) (strategy : Strategy)
    (o : Oracle Id) (expanded : Bytes) : Outcome :=
  let (pk,sk) := keypairFromExpansion o v expanded
  run limits (fun m => sign o v sk m) strategy limits.signingAttempts ⟨pk,[]⟩

-- This is an explicit challenge distinguisher: its challenge is expanded seed
-- material, not the master seed. It constructs the public key, answers adaptive
-- signing queries and returns whether the final fresh forgery verifies.
def seedDistinguisher (v : Variant) (limits : Limits) (strategy : Strategy)
    (o : Oracle Id) (challenge : Bytes) : Bool :=
  let outcome := expandedExperiment v limits strategy o challenge
  wins limits (fun m s => (verify o v outcome.view.publicKey m s).getD false) outcome

theorem seed_distinguisher_exact (v : Variant) (limits : Limits) (strategy : Strategy)
    (o : Oracle Id) (seed : Wire 32) :
    forgeEvent v limits strategy ⟨seed,o⟩ =
      seedDistinguisher v limits strategy o (seedExpansion o v seed) := by
  rfl

-- Uniform destination is exactly 3n bytes. It is explicitly a hybrid, not the
-- deployed key distribution. Master seed and strategy coins remain independent.
def uniformExpansion (v : Variant) : FiniteExperiment (Wire (3*(params v).n)) :=
  ⟨256^(3*(params v).n),Nat.pow_pos (by decide),
    fun i => ⟨be (3*(params v).n) i.val,be_width _ _⟩⟩

theorem uniform_expansion_ticket_recovers (v : Variant)
    (i : Fin (uniformExpansion v).cardinality) :
    toInt ((uniformExpansion v).sample i).val = i.val :=
  be_roundtrip _ _ i.isLt

theorem uniform_expansion_injective (v : Variant)
    (i j : Fin (uniformExpansion v).cardinality)
    (same : (uniformExpansion v).sample i = (uniformExpansion v).sample j) : i = j := by
  apply Fin.ext
  have h := congrArg (fun x : Wire (3*(params v).n) => toInt x.val) same
  simpa only [uniform_expansion_ticket_recovers] using h

theorem uniform_expansion_surjective (v : Variant) (x : Wire (3*(params v).n)) :
    ∃ i : Fin (uniformExpansion v).cardinality, (uniformExpansion v).sample i = x := by
  have bound := toInt_bound x.val
  rw [x.property] at bound
  refine ⟨⟨toInt x.val,bound⟩,?_⟩
  apply Subtype.ext
  change be (3*(params v).n) (toInt x.val) = x.val
  simpa only [x.property] using be_decoded_bytes x.val

def realSeedChallengeProbability (v : Variant) (limits : Limits) (o : Oracle Id)
    (coins : FiniteExperiment Strategy) : Probability :=
  probability (independentProduct uniformMasterSeed coins)
    (fun (seed,strategy) => seedDistinguisher v limits strategy o (seedExpansion o v seed))

def idealSeedChallengeProbability (v : Variant) (limits : Limits) (o : Oracle Id)
    (coins : FiniteExperiment Strategy) : Probability :=
  probability (independentProduct (uniformExpansion v) coins)
    (fun (expanded,strategy) => seedDistinguisher v limits strategy o expanded.val)

-- The exact real-game success probability is preserved by the constructed
-- PRG distinguisher, including adaptive queries, rejection and self-checks.
theorem seed_hybrid_real_equivalence (v : Variant) (limits : Limits) (o : Oracle Id)
    (coins : FiniteExperiment Strategy) :
    eufCmaProbability v limits o coins = realSeedChallengeProbability v limits o coins := by
  rfl

-- Absolute probability gap is represented by its exact common-denominator
-- numerator. Real and ideal spaces may have different numbers of tickets.
def gapNumerator (a b : Probability) : Nat :=
  a.numerator*b.denominator - b.numerator*a.denominator +
    (b.numerator*a.denominator - a.numerator*b.denominator)

theorem gap_zero_iff (a b : Probability) : gapNumerator a b = 0 ↔
    a.numerator*b.denominator = b.numerator*a.denominator := by
  unfold gapNumerator
  omega

theorem gap_symmetric (a b : Probability) : gapNumerator a b = gapNumerator b a := by
  simp only [gapNumerator,Nat.add_comm]

theorem probability_hybrid_bound (a b : Probability) :
    a.numerator*b.denominator ≤ b.numerator*a.denominator + gapNumerator a b := by
  unfold gapNumerator
  omega

-- Dividing by the positive product of denominators gives:
-- Pr[actual forgery] ≤ Pr[uniform-expansion forgery] + Adv_PRG[D].
-- The advantage is that of D above, not an unexplained bad-event count.
theorem seed_prg_hybrid_bound (v : Variant) (limits : Limits) (o : Oracle Id)
    (coins : FiniteExperiment Strategy) :
    (eufCmaProbability v limits o coins).numerator *
        (idealSeedChallengeProbability v limits o coins).denominator ≤
      (idealSeedChallengeProbability v limits o coins).numerator *
        (eufCmaProbability v limits o coins).denominator +
      gapNumerator (realSeedChallengeProbability v limits o coins)
        (idealSeedChallengeProbability v limits o coins) := by
  rw [seed_hybrid_real_equivalence]
  exact probability_hybrid_bound _ _

theorem seed_distinguisher_query_budget (v : Variant) (limits : Limits)
    (strategy : Strategy) (o : Oracle Id) (challenge : Bytes) :
    (expandedExperiment v limits strategy o challenge).view.replies.length ≤
      limits.signingAttempts := by
  unfold expandedExperiment
  split
  simpa using query_budget limits _ strategy limits.signingAttempts
    (⟨_,[]⟩ : View)

#print axioms keygen_expansion_refines
#print axioms expanded_keypair_widths
#print axioms seed_distinguisher_exact
#print axioms uniform_expansion_surjective
#print axioms seed_hybrid_real_equivalence
#print axioms seed_prg_hybrid_bound
#print axioms gap_zero_iff
#print axioms seed_distinguisher_query_budget
end DSM.Sphincs.Security
