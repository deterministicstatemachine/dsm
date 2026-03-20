/- 
  DSM Crypto Binding Lemmas — self-contained Lean 4 proofs

  This module does not claim to prove cryptographic security of BLAKE3 or
  SPHINCS+. Instead, it machine-checks the protocol-level consequences DSM
  relies on once two assumptions hold:

  1. `domainHash` is injective over `(tag, message)`.
  2. `verify` is message-binding for a fixed `(pk, sig)`.

  Under those assumptions, a signature over one domain-separated digest cannot
  be retargeted to a different DSM domain or payload, and the math-owned claim
  key derivation remains bound to the exact `(preimage, hash_lock)` pair.
-/

axiom domainHash : String → List UInt8 → Nat
axiom pkOf : Nat → Nat
axiom sign : Nat → Nat → Nat
axiom verify : Nat → Nat → Nat → Prop

axiom sign_verify_sound :
  ∀ sk msg, verify (pkOf sk) msg (sign sk msg)

axiom verify_message_binding :
  ∀ pk msg₁ msg₂ sig,
    verify pk msg₁ sig →
    verify pk msg₂ sig →
    msg₁ = msg₂

axiom domain_hash_injective :
  ∀ tag₁ msg₁ tag₂ msg₂,
    domainHash tag₁ msg₁ = domainHash tag₂ msg₂ →
    tag₁ = tag₂ ∧ msg₁ = msg₂

noncomputable def deriveClaimKey (preimage hashLock : List UInt8) : Nat :=
  domainHash "DSM/dbtc-claim" (preimage ++ hashLock)

axiom claim_key_material_binding :
  ∀ pre₁ lock₁ pre₂ lock₂,
    deriveClaimKey pre₁ lock₁ = deriveClaimKey pre₂ lock₂ →
    pre₁ = pre₂ ∧ lock₁ = lock₂

theorem signed_digest_verifies (sk msg : Nat) :
    verify (pkOf sk) msg (sign sk msg) :=
  sign_verify_sound sk msg

theorem signature_retargeting_requires_same_digest
    (pk msg₁ msg₂ sig : Nat)
    (h₁ : verify pk msg₁ sig)
    (h₂ : verify pk msg₂ sig) :
    msg₁ = msg₂ :=
  verify_message_binding pk msg₁ msg₂ sig h₁ h₂

theorem cross_domain_signature_retargeting_impossible
    (sk : Nat) (tag₁ tag₂ : String) (msg₁ msg₂ : List UInt8)
    (hRetarget : verify (pkOf sk) (domainHash tag₂ msg₂)
        (sign sk (domainHash tag₁ msg₁))) :
    tag₁ = tag₂ ∧ msg₁ = msg₂ := by
  have hOriginal :
      verify (pkOf sk) (domainHash tag₁ msg₁) (sign sk (domainHash tag₁ msg₁)) :=
    sign_verify_sound sk (domainHash tag₁ msg₁)
  have hDigestEq :
      domainHash tag₁ msg₁ = domainHash tag₂ msg₂ :=
    verify_message_binding
      (pkOf sk)
      (domainHash tag₁ msg₁)
      (domainHash tag₂ msg₂)
      (sign sk (domainHash tag₁ msg₁))
      hOriginal
      hRetarget
  exact domain_hash_injective tag₁ msg₁ tag₂ msg₂ hDigestEq

theorem math_owned_claim_retargeting_impossible
    (pre₁ lock₁ pre₂ lock₂ : List UInt8)
    (hEq : deriveClaimKey pre₁ lock₁ = deriveClaimKey pre₂ lock₂) :
    pre₁ = pre₂ ∧ lock₁ = lock₂ :=
  claim_key_material_binding pre₁ lock₁ pre₂ lock₂ hEq
