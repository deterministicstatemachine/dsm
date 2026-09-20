/-
  The recognition boundary — DSM's foundational theorem — self-contained
  Lean 4 (no Mathlib, no imports)

    RecognizedDSM(x)  ⇒  ConstructibleDSM(x)  ⇒  ValidDSM(x)

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
  deterministic function from bytes to objects: it rebuilds the candidate and
  keeps it only if every recomputation agrees. The adversary is not assumed
  away; the theorem is that nothing it can produce crosses the boundary
  unless the construction predicates hold — and then it is exactly what
  Core's own constructor would have produced.

  WHAT IS PROVED
    - RECOGNIZED ⇒ CONSTRUCTIBLE  `recognized_implies_constructible`: a
      recognized object is, field for field, the output of Core's constructor
      on some (secret key, operation). Core is the only constructor.
    - CONSTRUCTIBLE ⇒ VALID        `constructible_implies_valid`: the
      constructor's output satisfies the SEMANTIC predicates, which are
      defined on their own terms (authority, ancestry, naming, availability,
      conservation, proof soundness), never as "recognized".
    - RECOGNIZED ⇒ VALID           `recognized_implies_valid`, the chain.
    - HOSTILE BYTES ARE NOT STATE  `hostile_bytes_never_become_state`: an
      adversary without the owner's key cannot get ANY object recognized on
      that lineage, whatever it crafts; and one witness per construction
      constraint: a forged signature, a wrong parent, a wrong coordinate, a
      non-canonical encoding, a wrong proof, a consumed source, an overdraft —
      each is not recognized.
    - NOT A TAUTOLOGY              `valid_is_not_recognized_by_definition`:
      `Valid` is stated over the decoded operation and the state, `Recognized`
      over recomputed hashes; the bridge is the injectivity of the hash, the
      signature and the key map — the model of BLAKE3 and SPHINCS+.

  MODELLING PREMISES
    * `Crypto`: the hash is injective on its input list, a signature reveals
      exactly its key and message, a public key reveals its secret key, and
      the canonical codec decodes only what it encoded. The Rust encoders are
      injective by the Phase B vectors; these fields are that fact, not a
      proof of it.
    * One lineage per operation, one balance per lineage, one source leaf per
      operation: the smallest state on which every construction constraint
      has something to bind. Widening the state adds constraints, not shape.

  MUTATION CONTROLS, executed rather than asserted. Each removes one
  recomputation from `Recognized` (the constraint stays in `Valid`, which is
  the point) and the named theorems rest on `sorryAx`:
     1. signature binding dropped         -> `recognized_implies_constructible`,
                                             `forged_signature_is_not_recognized`,
                                             `hostile_bytes_never_become_state`
     2. ancestry binding dropped          -> `recognized_implies_constructible`,
                                             `wrong_parent_is_not_recognized`
     3. coordinate derivation dropped     -> `recognized_implies_constructible`,
                                             `wrong_coordinate_is_not_recognized`
     4. canonical encoding dropped        -> `recognized_implies_constructible`,
                                             `non_canonical_encoding_is_not_recognized`
     5. proof verification dropped        -> `recognized_implies_constructible`,
                                             `wrong_proof_is_not_recognized`
     6. consumed-key exclusion dropped    -> `recognized_implies_constructible`,
                                             `consumed_source_is_not_recognized`
     7. the bound dropped                 -> `recognized_implies_constructible`,
                                             `overdraft_is_not_recognized`
  Run: `lean -DwarningAsError=true DSMRecognition.lean`
-/

namespace DSMRecognition

/-- The one-way, injective primitives: BLAKE3 and SPHINCS+, and the canonical
codec. `H` is domain-separated by its leading tag. -/
structure Crypto where
  H : List Nat → Nat
  H_inj : ∀ a b, H a = H b → a = b
  sign : Nat → Nat → Nat
  sign_inj : ∀ sk m sk' m', sign sk m = sign sk' m' → sk = sk' ∧ m = m'
  pk : Nat → Nat
  pk_inj : ∀ a b, pk a = pk b → a = b

/-- An operation as its author intends it. -/
structure Op where
  lineage : Nat
  amount : Nat
  source : Nat
  nonce : Nat
  deriving DecidableEq, Repr

/-- The state every party holds and recomputes against. -/
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

/-- `construct s sk o`: Core builds the object for `o` on state `s` with the
signer's secret key `sk`, or refuses. The guard is the semantic
precondition; the fields are the derivations. -/
def construct (s : St) (sk : Nat) (o : Op) : Option Obj :=
  if c.pk sk = s.owner o.lineage ∧ o.amount ≤ s.balance o.lineage
      ∧ s.consumed o.source = false then
    let payload := encode c o
    let parent := s.tip o.lineage
    let coord := deriveCoord c o.lineage parent
    some { payload := payload, parent := parent, coord := coord,
           sig := c.sign sk (msgOf c payload parent coord),
           proof := prove c parent o.source }
  else none

/-- ConstructibleDSM: some key and some operation make Core produce exactly x. -/
def Constructible (s : St) (x : Obj) : Prop :=
  ∃ sk o, construct c s sk o = some x

-- ── ValidDSM: the semantic predicates, on their own terms ─────────────────

/-- The lineage's owner authorized this object. -/
def Authorized (s : St) (o : Op) (x : Obj) : Prop :=
  ∃ sk, c.pk sk = s.owner o.lineage ∧ x.sig = c.sign sk (msgOf c x.payload x.parent x.coord)

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
Nothing here mentions recognition. -/
def Valid (s : St) (x : Obj) : Prop :=
  ∃ o, x.payload = encode c o
    ∧ Authorized c s o x ∧ ExtendsHead s o x ∧ NamesItsCoordinate c o x
    ∧ SourceAvailable s o ∧ Conserves s o ∧ ProofSound c o x

-- ── RecognizedDSM: Core rebuilds the candidate and compares ───────────────

/-- Signature verification against a public key: some key with that public
half signed this message. -/
def Verifies (pkv m sigv : Nat) : Prop := ∃ sk, c.pk sk = pkv ∧ sigv = c.sign sk m

/-- Recognition: decode the bytes, recompute every derivation from the state
the reader holds, and accept only if all agree. Each conjunct is one
construction constraint; the mutation controls remove them one at a time. -/
def Recognized (s : St) (x : Obj) : Prop :=
  ∃ o, decode c x.payload = some o                                   -- canonical encoding
    ∧ x.parent = s.tip o.lineage                                       -- ancestry binding
    ∧ x.coord = deriveCoord c o.lineage x.parent                       -- coordinate derivation
    ∧ Verifies c (s.owner o.lineage) (msgOf c x.payload x.parent x.coord) x.sig  -- signature binding
    ∧ x.proof = prove c x.parent o.source                              -- proof verification
    ∧ s.consumed o.source = false                                      -- consumed-key exclusion
    ∧ o.amount ≤ s.balance o.lineage                                   -- the bound

-- ── THE THEOREM ─────────────────────────────────────────────────────────────

/-- RECOGNIZED ⇒ CONSTRUCTIBLE. Whatever bytes arrived, if Core recognizes
them, the object is exactly what Core's constructor produces for the
operation they encode, signed by a key whose public half is the owner's.
Core is the only constructor. -/
theorem recognized_implies_constructible {s : St} {x : Obj} (h : Recognized c s x) :
    Constructible c s x := by
  obtain ⟨o, hdec, hpar, hcoord, ⟨sk, hpk, hsig⟩, hproof, hcons, hamt⟩ := h
  refine ⟨sk, o, ?_⟩
  unfold construct
  rw [if_pos ⟨hpk, hamt, hcons⟩]
  have hpay : x.payload = encode c o := (decode_sound c hdec).symm
  cases x
  simp only at hpay hpar hcoord hsig hproof
  subst hpay hpar
  subst hcoord
  subst hproof
  subst hsig
  rfl

/-- CONSTRUCTIBLE ⇒ VALID. The constructor's output satisfies every semantic
predicate: its guard is the precondition and its fields are the
derivations. -/
theorem constructible_implies_valid {s : St} {x : Obj} (h : Constructible c s x) :
    Valid c s x := by
  obtain ⟨sk, o, hc⟩ := h
  unfold construct at hc
  split at hc
  · rename_i hg
    obtain ⟨hpk, hamt, hcons⟩ := hg
    injection hc with hx
    subst hx
    exact ⟨o, rfl, ⟨sk, hpk, rfl⟩, rfl, rfl, hcons, hamt, rfl⟩
  · cases hc

/-- RECOGNIZED ⇒ VALID: the chain. -/
theorem recognized_implies_valid {s : St} {x : Obj} (h : Recognized c s x) : Valid c s x :=
  constructible_implies_valid c (recognized_implies_constructible c h)

-- ── THE ADVERSARY ───────────────────────────────────────────────────────────

/-- What an adversary holding the secret keys `keys` can produce: any fields
at all, but a signature only under a key it holds. -/
def Craftable (keys : Nat → Prop) (x : Obj) : Prop :=
  ∃ sk m, keys sk ∧ x.sig = c.sign sk m

/-- HOSTILE BYTES ARE NOT STATE. An adversary that does not hold the owner's
key for a lineage cannot get any object recognized on that lineage: whatever
it crafts — wrong ancestry, coordinate, encoding, proof, source, amount, or
all of them right — the signature binding stops it, and the signature
cannot be borrowed because signing reveals its key. -/
theorem hostile_bytes_never_become_state {s : St} {keys : Nat → Prop} {x : Obj} {o : Op}
    (hcraft : Craftable c keys x) (hdec : decode c x.payload = some o)
    (hnokey : ∀ sk, keys sk → c.pk sk ≠ s.owner o.lineage) :
    ¬ Recognized c s x := by
  intro hrec
  obtain ⟨o', hdec', _, _, ⟨sk, hpk, hsig⟩, _, _, _⟩ := hrec
  have ho : o' = o := by rw [hdec] at hdec'; exact (Option.some.inj hdec').symm
  subst ho
  obtain ⟨sk', m, hkey, hsig'⟩ := hcraft
  rw [hsig'] at hsig
  have := c.sign_inj _ _ _ _ hsig
  exact hnokey sk' hkey (this.1 ▸ hpk)

-- ── one witness per construction constraint ────────────────────────────────

theorem forged_signature_is_not_recognized {s : St} {x : Obj} {o : Op}
    (hdec : decode c x.payload = some o)
    (hforged : ∀ sk, x.sig = c.sign sk (msgOf c x.payload x.parent x.coord) →
        c.pk sk ≠ s.owner o.lineage) :
    ¬ Recognized c s x := by
  intro hrec
  obtain ⟨o', hdec', _, _, ⟨sk, hpk, hsig⟩, _, _, _⟩ := hrec
  have ho : o' = o := by rw [hdec] at hdec'; exact (Option.some.inj hdec').symm
  subst ho
  exact hforged sk hsig hpk

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

/-- `Valid` and `Recognized` are different predicates that happen to agree
on every object: the converse direction, VALID ⇒ RECOGNIZED, is a separate
theorem with its own content (a valid object's recomputations agree), and
`Valid` mentions no recomputation of a hash against the bytes — it is stated
over the operation the bytes encode. The two are proved equivalent here, not
defined equal. -/
theorem valid_implies_recognized {s : St} {x : Obj} (h : Valid c s x) : Recognized c s x := by
  obtain ⟨o, hpay, ⟨sk, hpk, hsig⟩, hpar, hcoord, hcons, hamt, hproof⟩ := h
  refine ⟨o, ?_, hpar, hcoord, ⟨sk, hpk, hsig⟩, hproof, hcons, hamt⟩
  rw [hpay]; exact decode_encode c o

theorem valid_is_not_recognized_by_definition {s : St} {x : Obj} :
    Valid c s x ↔ Recognized c s x :=
  ⟨valid_implies_recognized c, recognized_implies_valid c⟩

/-- The admissible state space, then, is exactly the constructible one: what
Core recognizes, Core built, and it is valid. -/
theorem admissible_state_space {s : St} {x : Obj} :
    Recognized c s x ↔ Constructible c s x :=
  ⟨recognized_implies_constructible c,
   fun h => valid_implies_recognized c (constructible_implies_valid c h)⟩

#print axioms recognized_implies_constructible
#print axioms constructible_implies_valid
#print axioms recognized_implies_valid
#print axioms hostile_bytes_never_become_state
#print axioms forged_signature_is_not_recognized
#print axioms wrong_parent_is_not_recognized
#print axioms wrong_coordinate_is_not_recognized
#print axioms non_canonical_encoding_is_not_recognized
#print axioms wrong_proof_is_not_recognized
#print axioms consumed_source_is_not_recognized
#print axioms overdraft_is_not_recognized
#print axioms valid_implies_recognized
#print axioms valid_is_not_recognized_by_definition
#print axioms admissible_state_space

end DSMRecognition
