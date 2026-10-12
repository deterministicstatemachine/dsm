/-
  DSM Crypto Binding Lemmas — self-contained Lean 4 proofs, axiom-free

  This module does not claim to prove cryptographic security of BLAKE3 or
  SPHINCS+. It proves that each protocol-level binding DSM relies on can only
  fail by producing an explicit break of a primitive:

  * a collision of the domain-separated hash on distinct inputs, or
  * an EUF-CMA forgery: a signature verifying a message that was never signed.

  Both primitives are parameters (`H`, `S`), not axioms. The only property of
  the signature scheme taken as a hypothesis is functional correctness
  (`SigScheme.correct`), which the deployed construction has as a proved
  theorem in lean4/Sphincs/Signer.lean. Every theorem here therefore rests on
  Lean's core axioms only; scripts/lean_axiom_audit.py checks this.

  History (audit-prep, 2026-10-07): an earlier version declared the bindings
  as global axioms. Two of them are false of any real 256-bit hash or
  hash-based signature (injectivity into a fixed width; "one signature
  verifies at most one message"), and `claim_key_material_binding` was
  inconsistent with the module's own definitions: `[1] ++ [2,3]` and
  `[1,2] ++ [3]` are the same bytes, so the kernel derived `False` from it.
  The deployed derivation fixes `hash_lock` at 32 bytes
  (dsm_sdk::sdk::bitcoin_tx_builder::derive_claim_keypair), which is what makes
  the split unique; the restated theorem carries that premise.
-/

/-- An abstract signature scheme. Correctness is a hypothesis carried by the
    value, never a global axiom. -/
structure SigScheme where
  pkOf    : Nat → Nat
  sign    : Nat → Nat → Nat
  verify  : Nat → Nat → Nat → Prop
  correct : ∀ sk msg, verify (pkOf sk) msg (sign sk msg)

/-- A domain-separated hash: `H tag msg`. -/
abbrev DomainHash := String → List UInt8 → Nat

/-- EUF-CMA forgery event: `sig` verifies `msg` under `pk`, and `msg` is not
    among the messages the key holder signed. -/
def Forgery (S : SigScheme) (pk : Nat) (signed : List Nat) (msg sig : Nat) : Prop :=
  S.verify pk msg sig ∧ msg ∉ signed

/-- A collision of the domain-separated hash on distinct inputs. -/
def DomainCollision (H : DomainHash)
    (tag₁ : String) (msg₁ : List UInt8) (tag₂ : String) (msg₂ : List UInt8) : Prop :=
  (tag₁ ≠ tag₂ ∨ msg₁ ≠ msg₂) ∧ H tag₁ msg₁ = H tag₂ msg₂

theorem signed_digest_verifies (S : SigScheme) (sk msg : Nat) :
    S.verify (S.pkOf sk) msg (S.sign sk msg) :=
  S.correct sk msg

/-- An honest signature on `msg₁` that also verifies `msg₂` either is the
    same message or is an EUF-CMA forgery on `msg₂`. -/
theorem signature_retargeting_requires_same_digest
    (S : SigScheme) (sk msg₁ msg₂ : Nat)
    (h₂ : S.verify (S.pkOf sk) msg₂ (S.sign sk msg₁)) :
    msg₁ = msg₂ ∨ Forgery S (S.pkOf sk) [msg₁] msg₂ (S.sign sk msg₁) := by
  by_cases h : msg₁ = msg₂
  · exact Or.inl h
  · refine Or.inr ⟨h₂, ?_⟩
    intro hm
    exact h (List.mem_singleton.mp hm).symm

/-- Retargeting an honest signature over one domain-separated digest to a
    different domain or payload yields a hash collision or a forgery. -/
theorem cross_domain_signature_retargeting_impossible
    (S : SigScheme) (H : DomainHash)
    (sk : Nat) (tag₁ tag₂ : String) (msg₁ msg₂ : List UInt8)
    (hRetarget : S.verify (S.pkOf sk) (H tag₂ msg₂) (S.sign sk (H tag₁ msg₁))) :
    (tag₁ = tag₂ ∧ msg₁ = msg₂)
    ∨ DomainCollision H tag₁ msg₁ tag₂ msg₂
    ∨ Forgery S (S.pkOf sk) [H tag₁ msg₁] (H tag₂ msg₂) (S.sign sk (H tag₁ msg₁)) := by
  by_cases hd : H tag₁ msg₁ = H tag₂ msg₂
  · by_cases hs : tag₁ = tag₂ ∧ msg₁ = msg₂
    · exact Or.inl hs
    · refine Or.inr (Or.inl ⟨?_, hd⟩)
      by_cases ht : tag₁ = tag₂
      · exact Or.inr (fun hm => hs ⟨ht, hm⟩)
      · exact Or.inl ht
  · refine Or.inr (Or.inr ⟨hRetarget, ?_⟩)
    intro hm
    exact hd (List.mem_singleton.mp hm).symm

/-- The math-owned claim key: `H("DSM/dbtc-claim", preimage ‖ hash_lock)`. -/
def deriveClaimKey (H : DomainHash) (preimage hashLock : List UInt8) : Nat :=
  H "DSM/dbtc-claim" (preimage ++ hashLock)

/-- Without a fixed-width suffix the split is ambiguous: the reason the claim
    binding below needs `hash_lock` to be exactly 32 bytes. -/
theorem claim_split_ambiguous_without_fixed_lock :
    ([1] ++ [2, 3] : List UInt8) = [1, 2] ++ [3] ∧ ([1] : List UInt8) ≠ [1, 2] := by
  decide

/-- Splitting at a suffix of known length is unique. -/
theorem append_fixed_suffix_inj {α : Type} {p₁ p₂ s₁ s₂ : List α}
    (hl : s₁.length = s₂.length) (h : p₁ ++ s₁ = p₂ ++ s₂) :
    p₁ = p₂ ∧ s₁ = s₂ := by
  have hlen := congrArg List.length h
  simp only [List.length_append] at hlen
  have hp : p₁.length = p₂.length := by omega
  exact List.append_inj h hp

/-- Two 32-byte hash locks giving the same claim key name the same
    `(preimage, hash_lock)`, unless the hash collides. -/
theorem math_owned_claim_retargeting_impossible
    (H : DomainHash) (pre₁ lock₁ pre₂ lock₂ : List UInt8)
    (hLock₁ : lock₁.length = 32) (hLock₂ : lock₂.length = 32)
    (hEq : deriveClaimKey H pre₁ lock₁ = deriveClaimKey H pre₂ lock₂) :
    (pre₁ = pre₂ ∧ lock₁ = lock₂)
    ∨ DomainCollision H "DSM/dbtc-claim" (pre₁ ++ lock₁) "DSM/dbtc-claim" (pre₂ ++ lock₂) := by
  by_cases hc : pre₁ ++ lock₁ = pre₂ ++ lock₂
  · exact Or.inl (append_fixed_suffix_inj (by rw [hLock₁, hLock₂]) hc)
  · exact Or.inr ⟨Or.inr hc, hEq⟩
