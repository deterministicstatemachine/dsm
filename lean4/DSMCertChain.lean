/-
  DSM Per-Step EK Certificate Chain — fully-discharged Lean 4 proofs (no Mathlib)

  Machine-checks the structural invariants of the per-step ephemeral key
  certificate chain introduced in commits 50bd182, 5dc8eb6, f5a5415, and
  d8a6b1b (whitepaper §11.1). All theorems are fully discharged — no
  `sorry`, and no axioms beyond Lean core: the signature scheme and the
  domain hash are parameters, and the scheme's correctness is a field of
  the parameter (proved for the deployed construction in
  lean4/Sphincs/Signer.lean). scripts/lean_axiom_audit.py checks this.

  Theorems (all DISCHARGED):
    1. extend_chain_length_strictly_grows: extending a chain adds exactly
       one step.
    2. empty_chain_valid: an empty chain is trivially valid.
    3. empty_chain_head_is_ak: the chain head of an empty chain is AK_pk.
    4. extend_empty_chain_valid: extending an empty chain with a cert
       signed by AK's secret key produces a valid 1-step chain.
    5. cert_substitution_attack_resistant: an honest cert for EK_pk that
       also verifies for a different EK_pk' under the same parent tip is a
       hash collision or an EUF-CMA forgery. (An earlier version concluded
       outright non-verification from an axiom that one signature verifies
       at most one message; no hash-based scheme has that property, and the
       security charter rules it out: see SPHINCS_SECURITY_CHARTER.md.)
    6. cert_chain_first_step_anchored: a non-empty valid chain's first
       step has a cert verifying under AK_pk.
    7. extendChain_preserves_validity: extending a valid chain with a
       cert signed by the current chain head produces another valid
       chain. (The inductive step of cert-chain extension.)

  Helper lemma:
    - certHash_injective_in_ekPk: equal cert hashes for a fixed hN name
      the same ekPk, or exhibit a domain-hash collision. Uses the
      length-encoding of ekPk in the preimage.

  Paper anchoring (Ramsay, "Statelessness Reframed", Oct 2025):
    - §11.1 (Ephemeral certification, normative):
        cert_{n+1} = Sign_{SK_n}(BLAKE3("DSM/ek-cert\0" || EK_pk_{n+1} || h_n))
        Verification replays the chain back to AK_pk.

  Code correspondence:
    - sign_ek_cert(), verify_ek_cert(): crypto/ephemeral_key.rs.
    - sign_receipt_with_per_step_ek(): sdk/receipts.rs.
    - per_step_signing_chain_property_invariants test (sdk/receipts.rs)
      empirically exercises P1-P5 over chain lengths {1,3,5,8}; this
      module proves the corresponding invariants formally.

  Refines: DSM_Tripwire.tla `CountersignedByBoth` predicate. Tripwire
  fork-exclusion remains unchanged because cert validity does not affect
  adjacency reasoning.

  k_step source (Phase F real-Kyber migration):
    The per-step EK derivation context includes a `k_step` input. This
    module abstracts `k_step` as an arbitrary 32-byte input; in the
    implementation `k_step` is derived from a fresh per-step Kyber-768
    encapsulation between the bilateral parties:
      coins  = BLAKE3-256("DSM/kyber-coins\0" || h_n || C_pre
                          || DevID_sender)
      (ct, ss) = KyberEncDet(recipient_kyber_pk, coins)
      k_step = BLAKE3-256("DSM/kyber-ss\0" || ss)
    The recipient decapsulates `ct` with their Kyber sk to recover the
    same `ss` and `k_step`. The Kyber ciphertext travels in the receipt's
    `kyber_ct_a/b` envelope fields (proto 18/19). Code helpers:
    `derive_kyber_k_step_for_send` / `_for_verify` in sdk/receipts.rs.
    The cert chain proofs in this module are agnostic to where `k_step`
    came from — they reason about cert verification given EK_pk values,
    regardless of the derivation pathway. Real Kyber per-step BINDS the
    EK derivation to a specific recipient (a receipt encapsulated to one
    recipient cannot be replayed against another — Kyber binds to
    recipient_kyber_pk), strengthening the security model the cert chain
    proofs rest on.
-/

-- ============================================================
-- Primitives (parameters, not axioms)
-- ============================================================

/-- A signature scheme with key generation. `round_trip` is functional
    correctness; it is a hypothesis carried by the value, never an axiom. -/
structure SigScheme where
  keyGen     : Nat → Nat × Nat
  sign       : Nat → Nat → Nat
  verify     : Nat → Nat → Nat → Prop
  round_trip : ∀ (seed m : Nat), verify (keyGen seed).1 m (sign (keyGen seed).2 m)

/-- Domain-separated BLAKE3 hash, `H tag msg`. -/
abbrev DomainHash := String → List UInt8 → Nat

/-- A collision of the domain hash on distinct inputs. -/
def DomainCollision (H : DomainHash)
    (tag₁ : String) (msg₁ : List UInt8) (tag₂ : String) (msg₂ : List UInt8) : Prop :=
  (tag₁ ≠ tag₂ ∨ msg₁ ≠ msg₂) ∧ H tag₁ msg₁ = H tag₂ msg₂

/-- EUF-CMA forgery event: `sig` verifies `msg` under `pk`, and `msg` is not
    among the messages the key holder signed. -/
def Forgery (S : SigScheme) (pk : Nat) (signed : List Nat) (msg sig : Nat) : Prop :=
  S.verify pk msg sig ∧ msg ∉ signed

-- ============================================================
-- EK cert hash (whitepaper §11.1 normative form)
-- ============================================================

/-- The preimage of the cert hash. The Nat arguments stand in for
    byte-encoded values: `ekPk` zeros then `hN` ones, which makes the
    encoding length-injective in `ekPk` for a fixed `hN`. -/
def certPreimage (ekPk hN : Nat) : List UInt8 :=
  List.replicate ekPk 0 ++ List.replicate hN 1

/-- The cert hash that gets signed:
    H_ek-cert(EK_pk, h_n) = BLAKE3("DSM/ek-cert\0" || EK_pk || h_n)
    Code: derive_ek_cert_hash() in crypto/ephemeral_key.rs. -/
def certHash (H : DomainHash) (ekPk hN : Nat) : Nat :=
  H "DSM/ek-cert" (certPreimage ekPk hN)

/-- cert = Sign_{prevSk}(certHash(EK_pk, h_n)) -/
def certFor (S : SigScheme) (H : DomainHash) (prevSk ekPk hN : Nat) : Nat :=
  S.sign prevSk (certHash H ekPk hN)

/-- Whitepaper §11.1 verification predicate. -/
def certValid (S : SigScheme) (H : DomainHash) (prevPk ekPk hN cert : Nat) : Prop :=
  S.verify prevPk (certHash H ekPk hN) cert

/-- Equal cert hashes for a fixed `hN` name the same `ekPk`, or exhibit a
    collision of the domain hash. -/
theorem certHash_injective_in_ekPk (H : DomainHash) (ekPk1 ekPk2 hN : Nat)
    (h : certHash H ekPk1 hN = certHash H ekPk2 hN) :
    ekPk1 = ekPk2
    ∨ DomainCollision H "DSM/ek-cert" (certPreimage ekPk1 hN) "DSM/ek-cert" (certPreimage ekPk2 hN) := by
  by_cases hm : certPreimage ekPk1 hN = certPreimage ekPk2 hN
  · left
    have h_len := congrArg List.length hm
    simp [certPreimage, List.length_append, List.length_replicate] at h_len
    exact h_len
  · exact Or.inr ⟨Or.inr hm, h⟩

-- ============================================================
-- Cert chain
-- ============================================================

/-- A single chain step records the new EK pubkey, the parent tip h_n it
    was certified under, and the cert that authorizes it. -/
structure ChainStep where
  ekPk : Nat
  hN   : Nat
  cert : Nat

/-- A cert chain: an attestation root pubkey AK_pk plus an ordered list
    of steps. Step 0's cert is signed by AK_sk; step i+1's cert is signed
    by step i's EK_sk. -/
structure CertChain where
  akPk  : Nat
  steps : List ChainStep

/-- The current chain head pubkey: AK_pk if no steps, else the last step's
    EK_pk. This is what signs the next step's cert. -/
def currentHead (c : CertChain) : Nat :=
  match c.steps.getLast? with
  | none      => c.akPk
  | some step => step.ekPk

/-- Validity of a step list anchored at `akPk`. -/
def chainValidAux (S : SigScheme) (H : DomainHash) (akPk : Nat) : List ChainStep → Prop
  | [] => True
  | step :: rest =>
      certValid S H akPk step.ekPk step.hN step.cert ∧
      chainValidAux S H step.ekPk rest

/-- Each cert verifies under its predecessor's pubkey. Empty chain is
    vacuously valid. -/
@[reducible] def chainValid (S : SigScheme) (H : DomainHash) (c : CertChain) : Prop :=
  chainValidAux S H c.akPk c.steps

theorem chainValidAux_nil (S : SigScheme) (H : DomainHash) (akPk : Nat) :
    chainValidAux S H akPk [] = True := rfl

theorem chainValidAux_cons (S : SigScheme) (H : DomainHash) (akPk : Nat)
    (step : ChainStep) (rest : List ChainStep) :
    chainValidAux S H akPk (step :: rest) =
      (certValid S H akPk step.ekPk step.hN step.cert ∧ chainValidAux S H step.ekPk rest) :=
  rfl

theorem chainValid_mk (S : SigScheme) (H : DomainHash) (akPk : Nat) (steps : List ChainStep) :
    chainValid S H ⟨akPk, steps⟩ = chainValidAux S H akPk steps := rfl

/-- Extend a chain with a freshly-signed step. -/
def extendChain (S : SigScheme) (H : DomainHash)
    (chain : CertChain) (newEkPk newHN prevSk : Nat) : CertChain :=
  ⟨chain.akPk, chain.steps ++ [⟨newEkPk, newHN, certFor S H prevSk newEkPk newHN⟩]⟩

-- ============================================================
-- Theorems (all DISCHARGED)
-- ============================================================

/-- Theorem 1 (Chain Length Monotonicity). -/
theorem extend_chain_length_strictly_grows (S : SigScheme) (H : DomainHash)
    (c : CertChain) (newEkPk newHN prevSk : Nat) :
    (extendChain S H c newEkPk newHN prevSk).steps.length = c.steps.length + 1 := by
  simp [extendChain]

/-- Theorem 2 (Empty Chain Validity). -/
theorem empty_chain_valid (S : SigScheme) (H : DomainHash) (akPk : Nat) :
    chainValid S H ⟨akPk, []⟩ := by
  rw [chainValid_mk, chainValidAux_nil]
  trivial

/-- Theorem 3 (Empty Chain Head). -/
theorem empty_chain_head_is_ak (akPk : Nat) :
    currentHead ⟨akPk, []⟩ = akPk := by
  simp [currentHead]

/-- Theorem 4 (Step-0 Soundness): extending an empty chain with a cert
    signed by AK's secret key produces a valid 1-step chain. -/
theorem extend_empty_chain_valid (S : SigScheme) (H : DomainHash)
    (akPk akSk newEkPk newHN : Nat)
    (h_keypair : (S.keyGen akSk).1 = akPk ∧ (S.keyGen akSk).2 = akSk) :
    chainValid S H (extendChain S H ⟨akPk, []⟩ newEkPk newHN akSk) := by
  show chainValidAux S H akPk [⟨newEkPk, newHN, certFor S H akSk newEkPk newHN⟩]
  rw [chainValidAux_cons]
  refine ⟨?_, ?_⟩
  · show S.verify akPk (certHash H newEkPk newHN) (S.sign akSk (certHash H newEkPk newHN))
    have rt := S.round_trip akSk (certHash H newEkPk newHN)
    rw [h_keypair.1, h_keypair.2] at rt
    exact rt
  · rw [chainValidAux_nil]
    trivial

/-- Theorem 5 (Substitution Attack Resistance): an honest cert for `ekPk1`
    that also verifies for a different `ekPk2` under the same parent tip is
    a domain-hash collision or an EUF-CMA forgery on the second cert hash. -/
theorem cert_substitution_attack_resistant (S : SigScheme) (H : DomainHash)
    (prevPk prevSk ekPk1 ekPk2 hN : Nat)
    (h_distinct : ekPk1 ≠ ekPk2)
    (h_valid_for_2 : certValid S H prevPk ekPk2 hN (certFor S H prevSk ekPk1 hN)) :
    DomainCollision H "DSM/ek-cert" (certPreimage ekPk1 hN) "DSM/ek-cert" (certPreimage ekPk2 hN)
    ∨ Forgery S prevPk [certHash H ekPk1 hN] (certHash H ekPk2 hN) (certFor S H prevSk ekPk1 hN) := by
  by_cases hd : certHash H ekPk1 hN = certHash H ekPk2 hN
  · left
    rcases certHash_injective_in_ekPk H ekPk1 ekPk2 hN hd with he | hc
    · exact absurd he h_distinct
    · exact hc
  · right
    exact ⟨h_valid_for_2, fun hm => hd (List.mem_singleton.mp hm).symm⟩

/-- Theorem 6 (AK-Rooted First Step). -/
theorem cert_chain_first_step_anchored (S : SigScheme) (H : DomainHash)
    (c : CertChain) (h_valid : chainValid S H c) (h_nonempty : c.steps ≠ []) :
    ∃ (firstStep : ChainStep),
        c.steps.head? = some firstStep ∧
        certValid S H c.akPk firstStep.ekPk firstStep.hN firstStep.cert := by
  obtain ⟨akPk, steps⟩ := c
  cases steps with
  | nil => exact absurd rfl h_nonempty
  | cons step rest =>
      rw [chainValid_mk, chainValidAux_cons] at h_valid
      exact ⟨step, rfl, h_valid.1⟩

/-- chainValidAux is preserved when appending a step whose cert was signed
    by the SK matching the last pubkey of the chain. -/
theorem chainValidAux_extend (S : SigScheme) (H : DomainHash)
    (akPk : Nat) (steps : List ChainStep)
    (h_valid : chainValidAux S H akPk steps)
    (newEkPk newHN prevSk : Nat)
    (newStep : ChainStep)
    (h_newStep : newStep = ⟨newEkPk, newHN, certFor S H prevSk newEkPk newHN⟩)
    (h_lastPk : (S.keyGen prevSk).1 =
                  match steps.getLast? with
                  | none => akPk
                  | some step => step.ekPk)
    (h_sk : (S.keyGen prevSk).2 = prevSk) :
    chainValidAux S H akPk (steps ++ [newStep]) := by
  induction steps generalizing akPk with
  | nil =>
      simp at h_lastPk
      rw [List.nil_append, chainValidAux_cons]
      refine ⟨?_, ?_⟩
      · subst h_newStep
        show S.verify akPk (certHash H newEkPk newHN) (S.sign prevSk (certHash H newEkPk newHN))
        have rt := S.round_trip prevSk (certHash H newEkPk newHN)
        rw [h_lastPk, h_sk] at rt
        exact rt
      · subst h_newStep
        rw [chainValidAux_nil]
        trivial
  | cons step rest ih =>
      rw [chainValidAux_cons] at h_valid
      have h_first : certValid S H akPk step.ekPk step.hN step.cert := h_valid.1
      have h_rest_valid : chainValidAux S H step.ekPk rest := h_valid.2
      have h_lastPk_rest :
          (S.keyGen prevSk).1 =
            match rest.getLast? with
            | none => step.ekPk
            | some s => s.ekPk := by
        cases rest with
        | nil => simp; simp at h_lastPk; exact h_lastPk
        | cons r1 rs =>
            simp at h_lastPk ⊢
            exact h_lastPk
      have h_rest_extended := ih step.ekPk h_rest_valid h_lastPk_rest
      rw [List.cons_append, chainValidAux_cons]
      exact ⟨h_first, h_rest_extended⟩

/-- Theorem 7: extending a valid chain with a cert signed by the current
    chain head produces another valid chain. -/
theorem extendChain_preserves_validity (S : SigScheme) (H : DomainHash)
    (c : CertChain) (h_valid : chainValid S H c)
    (newEkPk newHN prevSk : Nat)
    (h_keypair : (S.keyGen prevSk).1 = currentHead c ∧
                 (S.keyGen prevSk).2 = prevSk) :
    chainValid S H (extendChain S H c newEkPk newHN prevSk) := by
  obtain ⟨akPk, steps⟩ := c
  show chainValidAux S H akPk (steps ++ [⟨newEkPk, newHN, certFor S H prevSk newEkPk newHN⟩])
  have h_lastPk : (S.keyGen prevSk).1 =
                    match steps.getLast? with
                    | none => akPk
                    | some step => step.ekPk := by
    have := h_keypair.1
    simp [currentHead] at this
    exact this
  exact chainValidAux_extend S H akPk steps h_valid newEkPk newHN prevSk
    ⟨newEkPk, newHN, certFor S H prevSk newEkPk newHN⟩ rfl h_lastPk h_keypair.2
