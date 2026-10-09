-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.SecurityGames
namespace DSM.Sphincs.Security

structure Certificate where
  key : Wire 64
  parent : Wire 32
  deriving DecidableEq

def Certificate.preimage (c : Certificate) : Bytes := ekCertInput c.key.val c.parent

 theorem certificate_encoding_injective (a b : Certificate)
    (same : a.preimage = b.preimage) : a = b := by
  have fields := cert_preimage_binding a.key b.key a.parent b.parent same
  cases a; cases b
  simp_all [Certificate.preimage]

inductive Extraction where
  | signatureForgery (message signature : Bytes)
  | collision (left right : Bytes)
  deriving Repr

-- This reduction computes at most one candidate hash plus one hash for each
-- queried object, then either reuses the forged signature or emits byte inputs.
def extractWrapper {Object : Type} (encode : Object → Bytes) (hash : Bytes → Wire 32)
    (queries : List Object) (candidate : Object) (signature : Bytes) : Extraction :=
  let digest := (hash (encode candidate)).val
  match queries.find? (fun q => (hash (encode q)).val == digest) with
  | none => .signatureForgery digest signature
  | some q => .collision (encode candidate) (encode q)

-- Instrumented oracle-query execution, with a refinement theorem to the
-- executable extractor. The trace contains exactly the inputs sent to hash.
def searchDigest {Object : Type} (encode : Object → Bytes) (hash : Bytes → Wire 32)
    (digest : Bytes) : List Object → Option Object × List Bytes
  | [] => (none,[])
  | q::qs =>
    let input := encode q
    if (hash input).val == digest then (some q,[input])
    else
      let tail := searchDigest encode hash digest qs
      (tail.1,input::tail.2)

 theorem search_refines_find {Object : Type} (encode : Object → Bytes)
    (hash : Bytes → Wire 32) (digest : Bytes) (queries : List Object) :
    (searchDigest encode hash digest queries).1 =
      queries.find? (fun q => (hash (encode q)).val == digest) := by
  induction queries with
  | nil => rfl
  | cons q qs ih =>
    simp only [searchDigest,List.find?_cons]
    cases h : ((hash (encode q)).val == digest) <;> simp_all

 theorem search_query_bound {Object : Type} (encode : Object → Bytes)
    (hash : Bytes → Wire 32) (digest : Bytes) (queries : List Object) :
    (searchDigest encode hash digest queries).2.length ≤ queries.length := by
  induction queries with
  | nil => simp [searchDigest]
  | cons q qs ih =>
    simp only [searchDigest]
    split <;> simp_all <;> omega

def extractWithTrace {Object : Type} (encode : Object → Bytes) (hash : Bytes → Wire 32)
    (queries : List Object) (candidate : Object) (signature : Bytes) : Extraction × List Bytes :=
  let input := encode candidate
  let digest := (hash input).val
  let search := searchDigest encode hash digest queries
  let result := match search.1 with
    | none => Extraction.signatureForgery digest signature
    | some q => Extraction.collision input (encode q)
  (result,input::search.2)

 theorem traced_extractor_refines {Object : Type} (encode : Object → Bytes)
    (hash : Bytes → Wire 32) (queries : List Object) (candidate : Object) (signature : Bytes) :
    (extractWithTrace encode hash queries candidate signature).1 =
      extractWrapper encode hash queries candidate signature := by
  simp only [extractWithTrace,extractWrapper,search_refines_find]

 theorem extractor_hash_query_bound {Object : Type} (encode : Object → Bytes)
    (hash : Bytes → Wire 32) (queries : List Object) (candidate : Object) (signature : Bytes) :
    (extractWithTrace encode hash queries candidate signature).2.length ≤ queries.length+1 := by
  have bound := search_query_bound encode hash (hash (encode candidate)).val queries
  simpa only [extractWithTrace,List.length_cons,Nat.add_comm] using Nat.add_le_add_right bound 1

def primitiveForgery (verify : Bytes → Bytes → Prop) (queries : List Bytes) : Extraction → Prop
  | .signatureForgery m s => m ∉ queries ∧ verify m s
  | .collision _ _ => False

def hashCollision (hash : Bytes → Wire 32) : Extraction → Prop
  | .collision a b => a ≠ b ∧ hash a = hash b
  | .signatureForgery _ _ => False

 theorem wrapper_forgery_extraction {Object : Type} (encode : Object → Bytes)
    (injective : ∀ a b, encode a = encode b → a = b)
    (hash : Bytes → Wire 32) (verify : Bytes → Bytes → Prop)
    (queries : List Object) (candidate : Object) (signature : Bytes)
    (fresh : candidate ∉ queries)
    (accepted : verify (hash (encode candidate)).val signature) :
    primitiveForgery verify (queries.map (fun q => (hash (encode q)).val))
      (extractWrapper encode hash queries candidate signature) ∨
    hashCollision hash (extractWrapper encode hash queries candidate signature) := by
  unfold extractWrapper
  dsimp only
  cases found : queries.find? (fun q => (hash (encode q)).val == (hash (encode candidate)).val) with
  | none =>
    simp only [primitiveForgery]
    have missing := found
    left
    constructor
    · intro member
      obtain ⟨q,member,equal⟩ := List.mem_map.mp member
      have noMatch := List.find?_eq_none.mp missing q member
      simp [equal] at noMatch
    · exact accepted
  | some q =>
    simp only [hashCollision]
    right
    have matched := List.find?_some found
    have member := List.mem_of_find?_eq_some found
    constructor
    · intro same
      exact fresh ((injective candidate q same) ▸ member)
    · apply Subtype.ext
      exact (beq_iff_eq.mp matched).symm

 theorem certificate_forgery_extraction (hash : Bytes → Wire 32)
    (o : Oracle Id) (v : Variant) (pk : Bytes) (queries : List Certificate)
    (candidate : Certificate) (signature : Bytes)
    (fresh : candidate ∉ queries)
    (accepted : verify o v pk (hash candidate.preimage).val signature = some true) :
    primitiveForgery (fun m s => verify o v pk m s = some true)
      (queries.map (fun q => (hash q.preimage).val))
      (extractWrapper Certificate.preimage hash queries candidate signature) ∨
    hashCollision hash (extractWrapper Certificate.preimage hash queries candidate signature) :=
  wrapper_forgery_extraction Certificate.preimage certificate_encoding_injective
    hash _ queries candidate signature fresh accepted

-- Actual event implication is proved by the extractor above, not supplied as
-- an assumption. Worlds can contain any adaptive transcript; no independence
-- between query objects and the candidate is needed for this classification.
structure WrapperTrial (Object : Type) where
  queries : List Object
  candidate : Object
  signature : Bytes

def wrapperSuccess {Object : Type} [DecidableEq Object] (encode : Object → Bytes)
    (hash : Bytes → Wire 32) (verify : Bytes → Bytes → Bool) (trial : WrapperTrial Object) : Bool :=
  decide (trial.candidate ∉ trial.queries) && verify (hash (encode trial.candidate)).val trial.signature

def signatureBreak (verify : Bytes → Bytes → Bool) (messages : List Bytes) : Extraction → Bool
  | .signatureForgery m s => decide (m ∉ messages) && verify m s
  | .collision _ _ => false

def collisionBreak (hash : Bytes → Wire 32) : Extraction → Bool
  | .signatureForgery _ _ => false
  | .collision a b => decide (a ≠ b) && decide (hash a = hash b)

 theorem extraction_event_implication {Object : Type} [DecidableEq Object]
    (encode : Object → Bytes) (injective : ∀ a b, encode a = encode b → a = b)
    (hash : Bytes → Wire 32) (verify : Bytes → Bytes → Bool) (trial : WrapperTrial Object)
    (won : wrapperSuccess encode hash verify trial = true) :
    signatureBreak verify (trial.queries.map (fun q => (hash (encode q)).val))
      (extractWrapper encode hash trial.queries trial.candidate trial.signature) = true ∨
    collisionBreak hash
      (extractWrapper encode hash trial.queries trial.candidate trial.signature) = true := by
  have parts := Bool.and_eq_true_iff.mp won
  have classified := wrapper_forgery_extraction encode injective hash
    (fun m s => verify m s = true) trial.queries trial.candidate trial.signature
    (of_decide_eq_true parts.1) parts.2
  cases result : extractWrapper encode hash trial.queries trial.candidate trial.signature with
  | signatureForgery m s =>
    simp only [result,primitiveForgery,hashCollision,or_false] at classified
    left
    simp [signatureBreak,classified.1,classified.2]
  | collision a b =>
    simp only [result,primitiveForgery,hashCollision,false_or] at classified
    right
    simp [collisionBreak,classified.1,classified.2]

 theorem event_mass_monotone {α : Type} (xs : List α) (a b : α → Bool)
    (covered : ∀ x, a x = true → b x = true) : eventMass xs a ≤ eventMass xs b := by
  induction xs with
  | nil => simp [eventMass]
  | cons x xs ih =>
    have cover := covered x
    cases ha : a x <;> cases hb : b x <;> simp_all [eventMass] <;> omega

 theorem wrapper_advantage_reduction {Object : Type} [DecidableEq Object]
    (encode : Object → Bytes) (injective : ∀ a b, encode a = encode b → a = b)
    (hash : Bytes → Wire 32) (verify : Bytes → Bytes → Bool)
    (space : FiniteExperiment (WrapperTrial Object)) :
    (probability space (wrapperSuccess encode hash verify)).numerator ≤
    (probability space (fun trial => signatureBreak verify
      (trial.queries.map (fun q => (hash (encode q)).val))
      (extractWrapper encode hash trial.queries trial.candidate trial.signature))).numerator +
    (probability space (fun trial => collisionBreak hash
      (extractWrapper encode hash trial.queries trial.candidate trial.signature))).numerator := by
  let a := fun trial : WrapperTrial Object => signatureBreak verify
    (trial.queries.map (fun q => (hash (encode q)).val))
    (extractWrapper encode hash trial.queries trial.candidate trial.signature)
  let b := fun trial : WrapperTrial Object => collisionBreak hash
    (extractWrapper encode hash trial.queries trial.candidate trial.signature)
  have subset := event_mass_monotone (List.ofFn space.sample) (wrapperSuccess encode hash verify)
    (fun trial => a trial || b trial) (by
      intro trial won
      have implication := extraction_event_implication encode injective hash verify trial won
      rcases implication with left | right
      · simp [a,left]
      · simp [b,right])
  have union := union_mass_bound (List.ofFn space.sample) a b
  exact Nat.le_trans subset union

#print axioms traced_extractor_refines
#print axioms extractor_hash_query_bound
#print axioms wrapper_forgery_extraction
#print axioms certificate_forgery_extraction
#print axioms wrapper_advantage_reduction
end DSM.Sphincs.Security
