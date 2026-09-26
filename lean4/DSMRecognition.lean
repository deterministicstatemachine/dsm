/-
  The recognition boundary — DSM's foundational theorem — self-contained
  Lean 4 (no Mathlib, no imports)

    ConstructibleDSM(x)  ⇒  RecognizedDSM(x)  ⇒  ValidDSM(x)

  Everything else DSM proves — conservation, the tripwire, SoFi atomicity,
  leader finality — is a refinement of this: a statement about what a valid
  construction preserves, what an incompatible lineage does, what a recognized
  multilateral operation must contain, how a recognizable object becomes
  durably observable. None of them rescues DSM from an invalid state after
  the fact, because no invalid state is admissible in the first place. This
  module is where "if it exists, it is valid" (Read this first) stops being
  an architectural assertion and becomes a theorem about the state machine's
  admissible state space.

  THE TWO UNIVERSES
      raw bytes from anyone  --recognition-->  protocol object  --> state
  An adversary supplies arbitrary bytes: malformed objects, conflicting
  objects, wrong signatures, wrong ancestry, wrong coordinates, wrong proofs,
  consumed sources. Storage keeps all of it. Recognition is Core's ONE
  deterministic function from bytes to objects: it rebuilds the candidate,
  verifies the signature under the owner key the state names, and keeps the
  candidate only if every recomputation agrees. The adversary is not assumed
  away; the theorem is that nothing it can produce crosses the boundary
  unless every construction constraint holds.

  TWO STATEMENTS, KEPT APART
    the producer ladder             Core's canonical producer
                                        ↓  `constructible_implies_recognized`
                                    Constructible
                                        ↓  `recognized_implies_valid`
                                    Recognized by deterministic rules
                                        ↓
                                    Valid
    the security statement          adversarial bytes
                                        ↓  verification + recognition
                                    cannot become recognized state unless
                                    all DSM predicates hold
                                    (`recognized_implies_valid`,
                                     `hostile_bytes_never_become_state`)

  WHAT IS PROVED
    - CONSTRUCTIBLE ⇒ RECOGNIZED   `constructible_implies_recognized`: what
      Core's constructor emits, Core recognizes (round-trip soundness and the
      canonical codec). The non-vacuity witness for `Recognized`.
    - RECOGNIZED ⇒ VALID           `recognized_implies_valid`: whatever bytes
      arrived, if Core recognizes them then every field but the signature is
      Core's own derivation from the state — encoding, parent, coordinate,
      proof — the source is available, the amount is within the balance, and
      the signature VERIFIES under the lineage owner's key. `Valid` is stated
      on its own terms (authority, ancestry, naming, availability,
      conservation, proof soundness), never as "recognized".
    - CONSTRUCTIBLE ⇒ VALID        `constructible_implies_valid`, the chain.
    - HOSTILE BYTES ARE NOT STATE  `hostile_bytes_never_become_state`: an
      adversary that holds no seed of the lineage owner's key can get an
      object recognized on that lineage only by re-presenting an honest
      signature over exactly that object's message — never a new object
      (`replayed_signature_pins_the_fields`); and one witness per
      construction constraint: a forged signature, a wrong parent, a wrong
      coordinate, a non-canonical encoding, a wrong proof, a consumed source,
      an overdraft — each is not recognized.
    - NOT A TAUTOLOGY              `valid_is_not_recognized_by_definition`:
      `Valid` is stated over the operation the bytes encode and the state,
      `Recognized` over the decoder and recomputed derivations; the two are
      proved equivalent, not defined equal.

  WHAT IS NOT CLAIMED. Recognized ⇒ Constructible is NOT a theorem here.
  It would need "every signature that verifies under pk on m is byte for
  byte the deterministic signer's output on m", which is stronger than
  EUF-CMA and stronger than DSM's verifier: `verify` receives (pk, m, sig)
  only, has no `sk_prf`, and cannot recompute the deterministic
  `R = H(sk_prf ∥ m)` to demand that the supplied signature be the exact
  output of `sign`. Deterministic `R` is a signer construction rule, not a
  verifier check. So the recognized object is Core's shape with a verifying
  signature; whether the signature bytes equal Core's own is neither
  assumed nor needed for any theorem below.

  CRYPTOGRAPHIC ASSUMPTIONS — the model of DSMCertChain.lean, stated as
  fields of `Crypto` so the theorems are parametric in them:
    * `H_inj`: BLAKE3 domain-hash collision resistance, as the protocol-level
      consequence (distinct inputs, distinct digests). The same axiom as
      `domain_hash_injective` in DSMCertChain / DSMCryptoBinding.
    * `keyGen`, `sign`, `verify`: a SPHINCS+ keypair from a seed, DETERMINISTIC
      signing (whitepaper §11: the Cat-5 'f' deterministic variant), and a
      verification predicate. Nothing is assumed about `sign` as a function
      of its key, and a public key tells nothing about its seed.
    * `sign_verify_round_trip`: a signature produced with the secret half of
      a keypair verifies under its public half (soundness). Exactly
      `sphincs_sign_verify_round_trip` in DSMCertChain.
    * `signature_message_binding`: for a fixed (pk, sig) at most one message
      verifies. Exactly `sphincs_signature_message_binding` in DSMCertChain.
    * `Adversary.euf`: existential unforgeability, phrased over what the
      adversary can OUTPUT. Any signature it presents that verifies under pk
      on some message was made with a seed it holds whose public half is
      pk, or was observed on the wire as an honest signature under pk. This
      is EUF-CMA with replay allowed: the adversary may copy any signature it
      has seen and attach it to any fields it likes. We do NOT prove
      SPHINCS+ security; we state its consequence for the adversary.
    * The canonical codec decodes only what it encoded (`decode_sound`,
      proved from `H_inj`). The Rust encoders are injective by the Phase B
      vectors.
    * One lineage per operation, one balance per lineage, one source leaf per
      operation: the smallest state on which every construction constraint
      has something to bind. Widening the state adds constraints, not shape.

  MUTATION CONTROLS, executed rather than asserted. Each removes one
  recomputation from `Recognized` (the constraint stays in `Valid`, which is
  the point) and the named theorems rest on `sorryAx`;
  `constructible_implies_recognized` stays green under every one of them,
  which is why it is the witness and not a control:
     1. signature binding dropped         -> `recognized_implies_valid`,
                                             `forged_signature_is_not_recognized`,
                                             `hostile_bytes_never_become_state`
     2. ancestry binding dropped          -> `recognized_implies_valid`,
                                             `wrong_parent_is_not_recognized`
     3. coordinate derivation dropped     -> `recognized_implies_valid`,
                                             `wrong_coordinate_is_not_recognized`
     4. canonical encoding dropped        -> `recognized_implies_valid`,
        (executed as `∃ o : Op, True`, keeping o typed)
                                             `non_canonical_encoding_is_not_recognized`
     5. proof verification dropped        -> `recognized_implies_valid`,
                                             `wrong_proof_is_not_recognized`
     6. consumed-key exclusion dropped    -> `recognized_implies_valid`,
                                             `consumed_source_is_not_recognized`
     7. the bound dropped                 -> `recognized_implies_valid`,
                                             `overdraft_is_not_recognized`
  Run: `lean -DwarningAsError=true DSMRecognition.lean`
-/

namespace DSMRecognition

/-- The primitives and their assumptions: BLAKE3 as an injective
domain-separated hash; deterministic SPHINCS+ as (keyGen, sign, verify) with
round-trip soundness and message binding — the DSMCertChain model, nothing
more. Unforgeability is a statement about the adversary (`Adversary.euf`),
not about `verify`. `H` is domain-separated by its leading tag. -/
structure Crypto where
  H : List Nat → Nat
  /-- Collision resistance, as its protocol-level consequence. -/
  H_inj : ∀ a b, H a = H b → a = b
  /-- `keyGen seed = (pk, sk)`. -/
  keyGen : Nat → Nat × Nat
  /-- Deterministic signing: `sign sk m`. -/
  sign : Nat → Nat → Nat
  /-- Verification: `verify pk m sig`. -/
  verify : Nat → Nat → Nat → Prop
  /-- Round-trip soundness. -/
  sign_verify_round_trip :
    ∀ seed m, verify (keyGen seed).1 m (sign (keyGen seed).2 m)
  /-- Message binding: one verifying message per (pk, sig). -/
  signature_message_binding :
    ∀ pk m₁ m₂ sig, verify pk m₁ sig → verify pk m₂ sig → m₁ = m₂

/-- An operation as its author intends it. -/
structure Op where
  lineage : Nat
  amount : Nat
  source : Nat
  nonce : Nat
  deriving DecidableEq, Repr

/-- The state every party holds and recomputes against. `owner` is the
public key that authorizes a lineage. -/
structure St where
  tip : Nat → Nat
  owner : Nat → Nat
  balance : Nat → Nat
  consumed : Nat → Bool

/-- The wire object. ANYONE can craft one with any fields: this is what raw
bytes decode to before recognition. -/
structure Obj where
  payload : Nat
  parent : Nat
  coord : Nat
  sig : Nat
  proof : Nat
  deriving DecidableEq, Repr

variable (c : Crypto)

-- ── the derivations Core recomputes ────────────────────────────────────────

/-- Canonical encoding of an operation (domain 1). -/
def encode (o : Op) : Nat := c.H [1, o.lineage, o.amount, o.source, o.nonce]

/-- The coordinate an operation names: derived from its lineage and the tip
it extends (domain 2). -/
def deriveCoord (lineage parent : Nat) : Nat := c.H [2, lineage, parent]

/-- The proof of the source leaf under the parent (domain 3). -/
def prove (parent source : Nat) : Nat := c.H [3, parent, source]

/-- What a signature covers (domain 4). -/
def msgOf (payload parent coord : Nat) : Nat := c.H [4, payload, parent, coord]

theorem msgOf_inj {p₁ a₁ k₁ p₂ a₂ k₂ : Nat}
    (h : msgOf c p₁ a₁ k₁ = msgOf c p₂ a₂ k₂) : p₁ = p₂ ∧ a₁ = a₂ ∧ k₁ = k₂ := by
  unfold msgOf at h
  have hl := c.H_inj _ _ h
  simp only [List.cons.injEq] at hl
  exact ⟨hl.2.1, hl.2.2.1, hl.2.2.2.1⟩

/-- The canonical encoding is injective: two operations with one encoding
are one operation (the hash is injective on its input list). -/
theorem encode_inj {a b : Op} (h : encode c a = encode c b) : a = b := by
  unfold encode at h
  have hl := c.H_inj _ _ h
  cases a; cases b
  simp only [List.cons.injEq] at hl
  obtain ⟨_, h1, h2, h3, h4⟩ := hl
  simp [h1, h2, h3, h4]

open Classical in
/-- The canonical decoder: the bytes are an encoding, or nothing. -/
noncomputable def decode (p : Nat) : Option Op :=
  if h : ∃ o : Op, encode c o = p then some (Classical.choose h) else none

theorem decode_encode (o : Op) : decode c (encode c o) = some o := by
  unfold decode
  have h : ∃ o' : Op, encode c o' = encode c o := ⟨o, rfl⟩
  rw [dif_pos h]
  congr 1
  exact encode_inj c (Classical.choose_spec h)

theorem decode_sound {p : Nat} {o : Op} (h : decode c p = some o) : encode c o = p := by
  unfold decode at h
  split at h
  · rename_i hex
    have hs := Classical.choose_spec hex
    injection h with h
    rw [← h]; exact hs
  · cases h

-- ── Core's constructor: the ONLY way a DSM object is made ─────────────────

/-- `construct s seed o`: Core builds the object for `o` on state `s`, signing
with the keypair of `seed`, or refuses. The guard is the semantic
precondition; the fields are the derivations. -/
def construct (s : St) (seed : Nat) (o : Op) : Option Obj :=
  if (c.keyGen seed).1 = s.owner o.lineage ∧ o.amount ≤ s.balance o.lineage
      ∧ s.consumed o.source = false then
    let payload := encode c o
    let parent := s.tip o.lineage
    let coord := deriveCoord c o.lineage parent
    some { payload := payload, parent := parent, coord := coord,
           sig := c.sign (c.keyGen seed).2 (msgOf c payload parent coord),
           proof := prove c parent o.source }
  else none

/-- ConstructibleDSM: Core's canonical producer emitted exactly x — some seed
and some operation make `construct` produce it, signature bytes included. -/
def Constructible (s : St) (x : Obj) : Prop :=
  ∃ seed o, construct c s seed o = some x

-- ── ValidDSM: the semantic predicates, on their own terms ─────────────────

/-- The lineage's owner authorized this object: its signature verifies under
the owner key the state names, over this object's own message. Signature
validity IS the verification relation; that no one without the owner's seed
can produce a new verifying pair is `Adversary.euf`, stated where it
belongs. -/
def Authorized (s : St) (o : Op) (x : Obj) : Prop :=
  c.verify (s.owner o.lineage) (msgOf c x.payload x.parent x.coord) x.sig

/-- The object extends the lineage's current head, not some other state. -/
def ExtendsHead (s : St) (o : Op) (x : Obj) : Prop := x.parent = s.tip o.lineage

/-- The object names the coordinate its lineage and parent derive. -/
def NamesItsCoordinate (o : Op) (x : Obj) : Prop :=
  x.coord = deriveCoord c o.lineage x.parent

/-- The source it consumes is still available: no double consumption. -/
def SourceAvailable (s : St) (o : Op) : Prop := s.consumed o.source = false

/-- Conservation: it moves no more than the lineage holds. -/
def Conserves (s : St) (o : Op) : Prop := o.amount ≤ s.balance o.lineage

/-- Its proof is the proof of its source under its parent. -/
def ProofSound (o : Op) (x : Obj) : Prop := x.proof = prove c x.parent o.source

/-- ValidDSM: stated over the operation the bytes ENCODE and the state.
Nothing here mentions recognition or decoding. -/
def Valid (s : St) (x : Obj) : Prop :=
  ∃ o, x.payload = encode c o
    ∧ Authorized c s o x ∧ ExtendsHead s o x ∧ NamesItsCoordinate c o x
    ∧ SourceAvailable s o ∧ Conserves s o ∧ ProofSound c o x

-- ── RecognizedDSM: Core rebuilds the candidate and compares ───────────────

/-- Recognition: decode the bytes, recompute every derivation from the state
the reader holds, verify the signature under the owner key the state names,
and accept only if all agree. Each conjunct is one construction constraint;
the mutation controls remove them one at a time. -/
def Recognized (s : St) (x : Obj) : Prop :=
  ∃ o, decode c x.payload = some o                                   -- canonical encoding
    ∧ x.parent = s.tip o.lineage                                       -- ancestry binding
    ∧ x.coord = deriveCoord c o.lineage x.parent                       -- coordinate derivation
    ∧ c.verify (s.owner o.lineage) (msgOf c x.payload x.parent x.coord) x.sig  -- signature binding
    ∧ x.proof = prove c x.parent o.source                              -- proof verification
    ∧ s.consumed o.source = false                                      -- consumed-key exclusion
    ∧ o.amount ≤ s.balance o.lineage                                   -- the bound

-- ── THE THEOREM ─────────────────────────────────────────────────────────────

/-- RECOGNIZED ⇒ VALID. Whatever bytes arrived, if Core recognizes them then
every field but the signature is Core's own derivation from the state —
encoding, parent, coordinate, proof — the source is available, the amount is
within the balance, and the signature verifies under the owner's key. This
is the security half of the boundary: it holds over the verification
relation alone. -/
theorem recognized_implies_valid {s : St} {x : Obj} (h : Recognized c s x) : Valid c s x := by
  obtain ⟨o, hdec, hpar, hcoord, hver, hproof, hcons, hamt⟩ := h
  exact ⟨o, (decode_sound c hdec).symm, hver, hpar, hcoord, hcons, hamt, hproof⟩

/-- CONSTRUCTIBLE ⇒ RECOGNIZED. What Core's constructor emits, Core
recognizes: the codec decodes what it encoded and the owner's signature
verifies by round-trip soundness. The producer half of the boundary, and the
non-vacuity witness for `Recognized`. -/
theorem constructible_implies_recognized {s : St} {x : Obj} (h : Constructible c s x) :
    Recognized c s x := by
  obtain ⟨seed, o, hc⟩ := h
  unfold construct at hc
  split at hc
  · rename_i hg
    obtain ⟨hpk, hamt, hcons⟩ := hg
    injection hc with hx
    subst hx
    -- Not a fixed-arity tuple on purpose: removing any conjunct from
    -- `Recognized` (the mutation controls) must leave this witness green.
    refine ⟨o, ?_⟩
    simp only [decode_encode, hcons, hamt, and_true, true_and]
    all_goals (rw [← hpk]; exact c.sign_verify_round_trip seed _)
  · cases hc

/-- CONSTRUCTIBLE ⇒ VALID: the chain. -/
theorem constructible_implies_valid {s : St} {x : Obj} (h : Constructible c s x) :
    Valid c s x :=
  recognized_implies_valid c (constructible_implies_recognized c h)

-- ── THE ADVERSARY ───────────────────────────────────────────────────────────

/-- What an adversary is and can do. It holds the seeds in `seeds`; it has
observed the honest signatures `seen pk m sig` on the wire (each verifying
under pk on m); it can output the objects in `outputs`, with any fields at
all. `euf` is existential unforgeability phrased over its outputs: a
signature it presents that verifies under pk on some message was made with a
seed it holds for pk, or is one it observed under pk — replayed, possibly
onto other fields. -/
structure Adversary where
  seeds : Nat → Prop
  seen : Nat → Nat → Nat → Prop
  seen_verifies : ∀ pk m sig, seen pk m sig → c.verify pk m sig
  outputs : Obj → Prop
  euf : ∀ x, outputs x → ∀ pk m, c.verify pk m x.sig →
    (∃ seed, seeds seed ∧ (c.keyGen seed).1 = pk) ∨ (∃ m₀, seen pk m₀ x.sig)

/-- HOSTILE BYTES ARE NOT STATE. An adversary that holds no seed for a
lineage's owner key can get an object recognized on that lineage only by
re-presenting an honest signature that the owner made over EXACTLY this
object's message (message binding). Whatever else it crafts — wrong
ancestry, coordinate, encoding, proof, source, amount, or all of them right —
the signature binding stops it. -/
theorem hostile_bytes_never_become_state {a : Adversary c} {s : St} {x : Obj} {o : Op}
    (hout : a.outputs x) (hdec : decode c x.payload = some o)
    (hnokey : ∀ seed, a.seeds seed → (c.keyGen seed).1 ≠ s.owner o.lineage)
    (hrec : Recognized c s x) :
    a.seen (s.owner o.lineage) (msgOf c x.payload x.parent x.coord) x.sig := by
  obtain ⟨o', hdec', _, _, hver, _, _, _⟩ := hrec
  have ho : o' = o := by rw [hdec] at hdec'; exact (Option.some.inj hdec').symm
  subst ho
  rcases a.euf x hout _ _ hver with ⟨seed, hheld, hpk⟩ | ⟨m₀, hseen⟩
  · exact absurd hpk (hnokey seed hheld)
  · have hver₀ := a.seen_verifies _ _ _ hseen
    have hm := c.signature_message_binding _ _ _ _ hver₀ hver
    rw [hm] at hseen
    exact hseen

/-- The replay is the honest object, field for field: an honest signature
observed on (payload₀, parent₀, coord₀) that verifies for x pins x's own
payload, parent and coordinate to those (message binding, then hash
injectivity); recognition then fixes the proof from them. -/
theorem replayed_signature_pins_the_fields {s : St} {x : Obj} {o : Op}
    {p₀ a₀ k₀ : Nat}
    (hrec : Recognized c s x) (hdec : decode c x.payload = some o)
    (hver₀ : c.verify (s.owner o.lineage) (msgOf c p₀ a₀ k₀) x.sig) :
    x.payload = p₀ ∧ x.parent = a₀ ∧ x.coord = k₀ := by
  obtain ⟨o', hdec', _, _, hver, _, _, _⟩ := hrec
  have ho : o' = o := by rw [hdec] at hdec'; exact (Option.some.inj hdec').symm
  subst ho
  have hm := c.signature_message_binding _ _ _ _ hver hver₀
  exact msgOf_inj c hm

-- ── one witness per construction constraint ────────────────────────────────

theorem forged_signature_is_not_recognized {s : St} {x : Obj} {o : Op}
    (hdec : decode c x.payload = some o)
    (hforged : ¬ c.verify (s.owner o.lineage) (msgOf c x.payload x.parent x.coord) x.sig) :
    ¬ Recognized c s x := by
  intro hrec
  obtain ⟨o', hdec', _, _, hver, _, _, _⟩ := hrec
  have ho : o' = o := by rw [hdec] at hdec'; exact (Option.some.inj hdec').symm
  subst ho
  exact hforged hver

theorem wrong_parent_is_not_recognized {s : St} {x : Obj} {o : Op}
    (hdec : decode c x.payload = some o) (h : x.parent ≠ s.tip o.lineage) :
    ¬ Recognized c s x := by
  intro hrec
  obtain ⟨o', hdec', hpar, _⟩ := hrec
  have ho : o' = o := by rw [hdec] at hdec'; exact (Option.some.inj hdec').symm
  subst ho
  exact h hpar

theorem wrong_coordinate_is_not_recognized {s : St} {x : Obj} {o : Op}
    (hdec : decode c x.payload = some o) (h : x.coord ≠ deriveCoord c o.lineage x.parent) :
    ¬ Recognized c s x := by
  intro hrec
  obtain ⟨o', hdec', _, hcoord, _⟩ := hrec
  have ho : o' = o := by rw [hdec] at hdec'; exact (Option.some.inj hdec').symm
  subst ho
  exact h hcoord

/-- Bytes that are not the canonical encoding of any operation are not an
object at all: recognition has nothing to rebuild. -/
theorem non_canonical_encoding_is_not_recognized {s : St} {x : Obj}
    (h : decode c x.payload = none) : ¬ Recognized c s x := by
  intro hrec
  obtain ⟨o, hdec, _⟩ := hrec
  rw [h] at hdec
  cases hdec

theorem wrong_proof_is_not_recognized {s : St} {x : Obj} {o : Op}
    (hdec : decode c x.payload = some o) (h : x.proof ≠ prove c x.parent o.source) :
    ¬ Recognized c s x := by
  intro hrec
  obtain ⟨o', hdec', _, _, _, hproof, _⟩ := hrec
  have ho : o' = o := by rw [hdec] at hdec'; exact (Option.some.inj hdec').symm
  subst ho
  exact h hproof

theorem consumed_source_is_not_recognized {s : St} {x : Obj} {o : Op}
    (hdec : decode c x.payload = some o) (h : s.consumed o.source = true) :
    ¬ Recognized c s x := by
  intro hrec
  obtain ⟨o', hdec', _, _, _, _, hcons, _⟩ := hrec
  have ho : o' = o := by rw [hdec] at hdec'; exact (Option.some.inj hdec').symm
  subst ho
  rw [h] at hcons
  cases hcons

theorem overdraft_is_not_recognized {s : St} {x : Obj} {o : Op}
    (hdec : decode c x.payload = some o) (h : s.balance o.lineage < o.amount) :
    ¬ Recognized c s x := by
  intro hrec
  obtain ⟨o', hdec', _, _, _, _, _, hamt⟩ := hrec
  have ho : o' = o := by rw [hdec] at hdec'; exact (Option.some.inj hdec').symm
  subst ho
  exact absurd hamt (Nat.not_le.mpr h)

-- ── not a tautology ───────────────────────────────────────────────────────

/-- VALID ⇒ RECOGNIZED: a valid object's bytes decode to its operation and
its recomputations agree. Its own content, separate from the chain above. -/
theorem valid_implies_recognized {s : St} {x : Obj} (h : Valid c s x) : Recognized c s x := by
  obtain ⟨o, hpay, hver, hpar, hcoord, hcons, hamt, hproof⟩ := h
  refine ⟨o, ?_, hpar, hcoord, hver, hproof, hcons, hamt⟩
  rw [hpay]; exact decode_encode c o

/-- `Valid` and `Recognized` are different predicates that agree on every
object: `Valid` is stated over the operation the bytes encode, `Recognized`
over the decoder; each direction has its own proof. The two are proved
equivalent here, not defined equal. -/
theorem valid_is_not_recognized_by_definition {s : St} {x : Obj} :
    Valid c s x ↔ Recognized c s x :=
  ⟨valid_implies_recognized c, recognized_implies_valid c⟩

#print axioms constructible_implies_recognized
#print axioms recognized_implies_valid
#print axioms constructible_implies_valid
#print axioms hostile_bytes_never_become_state
#print axioms replayed_signature_pins_the_fields
#print axioms forged_signature_is_not_recognized
#print axioms wrong_parent_is_not_recognized
#print axioms wrong_coordinate_is_not_recognized
#print axioms non_canonical_encoding_is_not_recognized
#print axioms wrong_proof_is_not_recognized
#print axioms consumed_source_is_not_recognized
#print axioms overdraft_is_not_recognized
#print axioms valid_implies_recognized
#print axioms valid_is_not_recognized_by_definition

end DSMRecognition
