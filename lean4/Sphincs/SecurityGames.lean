-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.Proofs
import Std.Internal.Rat

/- Classical finite experiments for DSM construction v2. No cryptographic
   assumption, ideal-oracle replacement, or forgery-extraction axiom is declared. -/
namespace DSM.Sphincs.Security

structure Limits where
  signingAttempts : Nat
  maxMessageBytes : Nat
  messageLimitPositive : 0 < maxMessageBytes

structure Reply where
  message : Bytes
  signature : Option Bytes
  deriving Repr
structure View where
  publicKey : Bytes
  replies : List Reply := []
  deriving Repr
inductive Move where
  | query (message : Bytes)
  | forge (message signature : Bytes)
  deriving Repr
abbrev Strategy := View → Move
inductive Outcome where
  | exhausted (view : View)
  | forgery (view : View) (message signature : Bytes)
  deriving Repr

def legal (limits : Limits) (message : Bytes) : Bool :=
  !message.isEmpty && message.length ≤ limits.maxMessageBytes

def reply (limits : Limits) (sign : Bytes → Option Bytes) (message : Bytes) : Reply :=
  ⟨message, if legal limits message then sign message else none⟩

def advance (limits : Limits) (sign : Bytes → Option Bytes) (view : View)
    (message : Bytes) : View :=
  {view with replies := view.replies ++ [reply limits sign message]}

-- Every query attempt consumes one unit, even when invalid. At zero fuel a
-- final forgery can be submitted, but another query ends the experiment.
def run (limits : Limits) (sign : Bytes → Option Bytes) (strategy : Strategy) :
    Nat → View → Outcome
  | 0, view => match strategy view with
    | .forge m s => .forgery view m s
    | .query _ => .exhausted view
  | fuel+1, view => match strategy view with
    | .forge m s => .forgery view m s
    | .query m => run limits sign strategy fuel (advance limits sign view m)

def Outcome.view : Outcome → View
  | .exhausted v => v
  | .forgery v _ _ => v

def fresh (limits : Limits) (view : View) (message : Bytes) : Bool :=
  !view.replies.any (fun r => legal limits r.message && r.message == message)

def wins (limits : Limits) (verify : Bytes → Bytes → Bool) : Outcome → Bool
  | .exhausted _ => false
  | .forgery view m s => legal limits m && fresh limits view m && verify m s

-- Exact existing model, including ChaCha request mode 3, typed widths, key
-- layouts, deterministic R and the signer's self-check. A world fixes the
-- primitive function and adversary coins/strategy throughout the experiment.
structure World where
  seed : Wire 32
  oracle : Oracle Id

def experiment (v : Variant) (limits : Limits) (strategy : Strategy) (world : World) : Outcome :=
  let (pk,sk) := generateKeypair world.oracle v world.seed
  run limits (fun m => sign world.oracle v sk m) strategy
    limits.signingAttempts ⟨pk,[]⟩

def forgeEvent (v : Variant) (limits : Limits) (strategy : Strategy) (world : World) : Bool :=
  let outcome := experiment v limits strategy world
  wins limits (fun m s => (verify world.oracle v outcome.view.publicKey m s).getD false)
    outcome

 theorem invalid_query_rejected (limits : Limits) (sign : Bytes → Option Bytes)
    (m : Bytes) (invalid : legal limits m = false) :
    (reply limits sign m).signature = none := by
  simp [reply, invalid]

 theorem query_budget (limits : Limits) (sign : Bytes → Option Bytes)
    (strategy : Strategy) (fuel : Nat) (view : View) :
    (run limits sign strategy fuel view).view.replies.length ≤
      view.replies.length + fuel := by
  induction fuel generalizing view with
  | zero => cases h : strategy view <;> simp [run,h,Outcome.view]
  | succ fuel ih =>
    cases h : strategy view with
    | forge m s => simp [run,h,Outcome.view]
    | query m =>
      have bound := ih (advance limits sign view m)
      simp only [advance,List.length_append,List.length_singleton] at bound
      simp only [run,h]
      change (run limits sign strategy fuel (advance limits sign view m)).view.replies.length ≤ _
      change (run limits sign strategy fuel (advance limits sign view m)).view.replies.length ≤ _ at bound
      omega

 theorem run_preserves_public_key (limits : Limits) (sign : Bytes → Option Bytes)
    (strategy : Strategy) (fuel : Nat) (view : View) :
    (run limits sign strategy fuel view).view.publicKey = view.publicKey := by
  induction fuel generalizing view with
  | zero => cases h : strategy view <;> simp [run,h,Outcome.view]
  | succ fuel ih =>
    cases h : strategy view with
    | forge m s => simp [run,h,Outcome.view]
    | query m => simpa [run,h,advance] using ih (advance limits sign view m)

 theorem fresh_excludes_queried (limits : Limits) (view : View) (m : Bytes)
    (queried : ∃ r ∈ view.replies, legal limits r.message = true ∧ r.message = m) :
    fresh limits view m = false := by
  obtain ⟨r,member,valid,equal⟩ := queried
  have hit : view.replies.any (fun r => legal limits r.message && r.message == m) = true := by
    apply List.any_eq_true.mpr
    exact ⟨r,member,by simpa only [equal,beq_self_eq_true,Bool.and_true] using (equal ▸ valid)⟩
  simp [fresh,hit]

 theorem queried_message_cannot_win (limits : Limits) (verify : Bytes → Bytes → Bool)
    (view : View) (m s : Bytes)
    (queried : ∃ r ∈ view.replies, legal limits r.message = true ∧ r.message = m) :
    wins limits verify (.forgery view m s) = false := by
  simp [wins,fresh_excludes_queried limits view m queried]

 theorem repeated_query_replies (limits : Limits) (sign : Bytes → Option Bytes)
    (view : View) (m : Bytes) :
    (advance limits sign (advance limits sign view m) m).replies =
      view.replies ++ [reply limits sign m,reply limits sign m] := by
  simp [advance,List.append_assoc]

-- Uniform finite tickets can repeat outcomes, representing every rational
-- finite distribution. This is mathematical enumeration, not runtime entropy.
structure FiniteExperiment (α : Type) where
  cardinality : Nat
  positive : 0 < cardinality
  sample : Fin cardinality → α

def eventMass {α : Type} : List α → (α → Bool) → Nat
  | [], _ => 0
  | x::xs, e => (if e x then 1 else 0) + eventMass xs e

 theorem mass_bounded {α : Type} (xs : List α) (e : α → Bool) :
    eventMass xs e ≤ xs.length := by
  induction xs with
  | nil => simp [eventMass]
  | cons x xs ih => cases h : e x <;> simp [eventMass,h] <;> omega

 theorem union_mass_bound {α : Type} (xs : List α) (a b : α → Bool) :
    eventMass xs (fun x => a x || b x) ≤ eventMass xs a + eventMass xs b := by
  induction xs with
  | nil => simp [eventMass]
  | cons x xs ih =>
    cases ha : a x <;> cases hb : b x <;> simp [eventMass,ha,hb] <;> omega

structure Probability where
  numerator : Nat
  denominator : Nat
  positive : 0 < denominator
  bounded : numerator ≤ denominator
  deriving Repr

def Probability.value (p : Probability) : Std.Internal.Rat :=
  Std.Internal.mkRat (Int.ofNat p.numerator) p.denominator

def probability {α : Type} (space : FiniteExperiment α) (event : α → Bool) : Probability :=
  ⟨eventMass (List.ofFn space.sample) event,space.cardinality,space.positive,
    by simpa using mass_bounded (List.ofFn space.sample) event⟩

 theorem probability_denominator {α : Type} (space : FiniteExperiment α)
    (event : α → Bool) : (probability space event).denominator = space.cardinality := rfl

 theorem probability_union_bound {α : Type} (space : FiniteExperiment α)
    (a b : α → Bool) :
    (probability space (fun x => a x || b x)).numerator ≤
      (probability space a).numerator + (probability space b).numerator :=
  union_mass_bound (List.ofFn space.sample) a b

-- The same denominator makes this the exact rational union bound, without
-- floating point. No premise says that forgery implies these events.
def badUnion {α : Type} (events : List (α → Bool)) (x : α) : Bool :=
  events.any (fun e => e x)

 theorem finite_union_bound {α : Type} (xs : List α) (events : List (α → Bool)) :
    eventMass xs (badUnion events) ≤ (events.map (eventMass xs)).sum := by
  induction events with
  | nil =>
    simp only [List.map_nil,List.sum_nil]
    induction xs with
    | nil => simp [eventMass]
    | cons x xs ih => simp_all [eventMass,badUnion]
  | cons e es ih =>
    have bound := union_mass_bound xs e (badUnion es)
    have eqEvent : badUnion (e::es) = (fun x => e x || badUnion es x) := by
      funext x
      simp [badUnion]
    rw [eqEvent]
    simp only [List.map_cons,List.sum_cons]
    omega

 theorem snoc_induction {α : Type} (P : List α → Prop) (empty : P [])
    (snoc : ∀ xs x, P xs → P (xs++[x])) (xs : List α) : P xs := by
  have aux : ∀ ys : List α, P ys.reverse := by
    intro ys
    induction ys with
    | nil => simpa using empty
    | cons y ys ih => simpa using snoc ys.reverse y ih
  simpa using aux xs.reverse
 theorem toInt_snoc (bs : Bytes) (b : UInt8) :
    toInt (bs++[b]) = b.toNat+256*toInt bs := by
  simp [toInt,List.reverse_append]
 theorem toInt_bound (bs : Bytes) : toInt bs < 256^bs.length := by
  apply snoc_induction (fun bs => toInt bs < 256^bs.length) ?_ ?_ bs
  · simp [toInt]
  · intro bs b ih
    have octet : b.toNat < 256 := b.toNat_lt
    rw [toInt_snoc]
    simp only [List.length_append,List.length_singleton,Nat.pow_succ]
    omega
 theorem be_decoded_bytes (bs : Bytes) : be bs.length (toInt bs) = bs := by
  apply snoc_induction (fun bs => be bs.length (toInt bs) = bs) ?_ ?_ bs
  · rfl
  · intro bs b ih
    have octet : b.toNat < 256 := b.toNat_lt
    have quotient : (b.toNat+256*toInt bs)/256 = toInt bs := by omega
    have remainder : (b.toNat+256*toInt bs)%256 = b.toNat := by omega
    simp only [List.length_append,List.length_singleton,toInt_snoc,be,quotient,remainder]
    rw [ih]
    simp

-- The sampler is bijective: exactly 2^256 equally likely 32-byte seeds.
def uniformMasterSeed : FiniteExperiment (Wire 32) :=
  ⟨2^256,by decide,fun i => ⟨be 32 i.val,be_width 32 i.val⟩⟩

 theorem master_seed_ticket_recovers (i : Fin uniformMasterSeed.cardinality) :
    toInt (uniformMasterSeed.sample i).val = i.val := by
  apply be_roundtrip
  have equality : 256^32 = 2^256 := by decide
  have bounded : i.val < 2^256 := i.isLt
  simpa only [equality] using bounded

 theorem master_seed_sampling_injective (i j : Fin uniformMasterSeed.cardinality)
    (equal : uniformMasterSeed.sample i = uniformMasterSeed.sample j) : i = j := by
  apply Fin.ext
  have decoded := congrArg (fun w : Wire 32 => toInt w.val) equal
  simpa only [master_seed_ticket_recovers] using decoded

 theorem master_seed_sampling_surjective (seed : Wire 32) :
    ∃ i : Fin uniformMasterSeed.cardinality, uniformMasterSeed.sample i = seed := by
  have bound : toInt seed.val < 2^256 := by
    have bounded := toInt_bound seed.val
    rw [seed.property] at bounded
    have equality : 256^32 = 2^256 := by decide
    simpa only [equality] using bounded
  refine ⟨⟨toInt seed.val,bound⟩,?_⟩
  apply Subtype.ext
  change be 32 (toInt seed.val) = seed.val
  simpa only [seed.property] using be_decoded_bytes seed.val

-- Product tickets provide independent seed/adversary random tapes. Strategies
-- are chosen by the adversary's tape, not by the secret seed or secret key.
def independentProduct {α β : Type} (a : FiniteExperiment α) (b : FiniteExperiment β) :
    FiniteExperiment (α × β) :=
  ⟨a.cardinality*b.cardinality,Nat.mul_pos a.positive b.positive,
    fun i => (a.sample ⟨i.val / b.cardinality,
      (Nat.div_lt_iff_lt_mul b.positive).mpr i.isLt⟩,
      b.sample ⟨i.val % b.cardinality,Nat.mod_lt _ b.positive⟩)⟩

def eufCmaProbability (v : Variant) (limits : Limits) (oracle : Oracle Id)
    (adversaryCoins : FiniteExperiment Strategy) : Probability :=
  probability (independentProduct uniformMasterSeed adversaryCoins)
    (fun (seed,strategy) => forgeEvent v limits strategy ⟨seed,oracle⟩)

#print axioms master_seed_sampling_surjective
#print axioms master_seed_sampling_injective
#print axioms run_preserves_public_key
#print axioms query_budget
#print axioms queried_message_cannot_win
#print axioms probability_union_bound
#print axioms finite_union_bound
end DSM.Sphincs.Security
