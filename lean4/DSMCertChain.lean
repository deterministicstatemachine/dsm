/-
  DSM Per-Step EK Certificate Chain — fully-discharged Lean 4 proofs (no Mathlib)

  Machine-checks the structural invariants of the per-step ephemeral key
  certificate chain introduced in commits 50bd182, 5dc8eb6, f5a5415, and
  d8a6b1b (whitepaper §11.1). All theorems are fully discharged — no
  `sorry` placeholders. Self-contained: relies only on Lean 4 core stdlib.

  Theorems (all DISCHARGED):
    1. extend_chain_length_strictly_grows: extending a chain adds exactly
       one step.
    2. empty_chain_valid: an empty chain is trivially valid.
    3. empty_chain_head_is_ak: the chain head of an empty chain is AK_pk.
    4. extend_empty_chain_valid: extending an empty chain with a cert
       signed by AK's secret key produces a valid 1-step chain.
    5. cert_substitution_attack_resistant: a cert valid for EK_pk does
       NOT verify for any different EK_pk' under the same parent tip.
    6. cert_chain_first_step_anchored: a non-empty valid chain's first
       step has a cert verifying under AK_pk.
    7. extendChain_preserves_validity: extending a valid chain with a
       cert signed by the current chain head produces another valid
       chain. (The inductive step of cert-chain extension.)

  Helper lemma:
    - certHash_injective_in_ekPk: certHash is injective in ekPk for
      fixed hN. Follows from BLAKE3 domain-hash injectivity and the
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
                          || DevID_sender || K_DBRW)
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
-- Crypto axioms
-- ============================================================

/-- Domain-separated BLAKE3 hash. -/
axiom domainHash : String → List UInt8 → Nat

/-- BLAKE3 domain-hash collision resistance: distinct (tag, message) pairs
    produce distinct hashes. We do NOT prove BLAKE3 security; we state
    the protocol-level consequence. Consistent with the same axiom in
    DSMOfflineFinality.lean / DSMCryptoBinding.lean. -/
axiom domain_hash_injective :
  ∀ (tag₁ : String) (msg₁ : List UInt8) (tag₂ : String) (msg₂ : List UInt8),
    domainHash tag₁ msg₁ = domainHash tag₂ msg₂ →
    tag₁ = tag₂ ∧ msg₁ = msg₂

/-- SPHINCS+ keypair derivation from a seed.
    Returns `(pk, sk)` such that signatures by sk verify under pk. -/
opaque sphincsKeyGen : Nat → Nat × Nat

/-- SPHINCS+ signature: produces a signature for a message under a
    secret key. -/
opaque sphincsSign : Nat → Nat → Nat

/-- SPHINCS+ verification predicate. -/
opaque sphincsVerify : Nat → Nat → Nat → Prop

/-- Signature soundness: a signature produced by `sphincsSign` on the
    secret-key half of a keypair verifies under the corresponding pubkey.
    This is the round-trip property. -/
axiom sphincs_sign_verify_round_trip :
  ∀ (seed m : Nat),
    sphincsVerify (sphincsKeyGen seed).1 m (sphincsSign (sphincsKeyGen seed).2 m)

/-- Deterministic SPHINCS+ message binding (whitepaper §11 SPHINCS+ Cat-5
    'f' is deterministic): for fixed (pk, sig), at most one message
    verifies. Two distinct messages cannot share a verifying signature
    under the same public key.

    Justification: §11.1 specifies the deterministic SPHINCS+ variant.
    Under deterministic signing, a fixed (sk, m) produces a unique sig,
    and verification cryptographically binds (pk, m, sig) — so a
    single sig that verifies under pk uniquely determines m. -/
axiom sphincs_signature_message_binding :
  ∀ (pk m1 m2 sig : Nat),
    sphincsVerify pk m1 sig →
    sphincsVerify pk m2 sig →
    m1 = m2

-- ============================================================
-- EK cert hash (whitepaper §11.1 normative form)
-- ============================================================

/-- The cert hash that gets signed:
    H_ek-cert(EK_pk, h_n) = BLAKE3("DSM/ek-cert\0" || EK_pk || h_n)
    Code: derive_ek_cert_hash() in crypto/ephemeral_key.rs. The Nat
    arguments stand in for byte-encoded values; the preimage encodes
    `ekPk` in its first `ekPk` bytes (zeros) and `hN` in the next
    `hN` bytes (ones), which makes the encoding length-injective. -/
noncomputable def certHash (ekPk hN : Nat) : Nat :=
  domainHash "DSM/ek-cert" (List.replicate ekPk 0 ++ List.replicate hN 1)

/-- A cert for (EK_pk, h_n) signed under prior-signer secret key prevSk:
    cert = Sign_{prevSk}(certHash(EK_pk, h_n)) -/
noncomputable def certFor (prevSk ekPk hN : Nat) : Nat :=
  sphincsSign prevSk (certHash ekPk hN)

/-- A cert is valid under prior-signer's pubkey prevPk. Whitepaper §11.1
    verification predicate. -/
def certValid (prevPk ekPk hN cert : Nat) : Prop :=
  sphincsVerify prevPk (certHash ekPk hN) cert

/-- The cert hash is injective in `ekPk` for a fixed `hN`: if two cert
    hashes are equal, the EK pubkeys are equal. Follows from BLAKE3
    domain-hash injectivity + the unique-decoding property of the
    `replicate ekPk 0 ++ replicate hN 1` preimage (which carries `ekPk`
    in its length). -/
theorem certHash_injective_in_ekPk (ekPk1 ekPk2 hN : Nat)
    (h : certHash ekPk1 hN = certHash ekPk2 hN) :
    ekPk1 = ekPk2 := by
  -- Step 1: domain_hash_injective gives us message equality.
  unfold certHash at h
  have h_pair := domain_hash_injective _ _ _ _ h
  have h_msg : List.replicate ekPk1 (0 : UInt8) ++ List.replicate hN 1 =
               List.replicate ekPk2 (0 : UInt8) ++ List.replicate hN 1 := h_pair.2
  -- Step 2: take the length of both sides of the message equality.
  --   length (replicate ekPk1 0 ++ replicate hN 1) = ekPk1 + hN
  --   length (replicate ekPk2 0 ++ replicate hN 1) = ekPk2 + hN
  -- Equality of lengths gives ekPk1 = ekPk2.
  have h_len := congrArg List.length h_msg
  simp [List.length_append, List.length_replicate] at h_len
  exact h_len

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

/-- Helper: validity of a step list anchored at `akPk`. Recurses on the
    list directly so pattern-matching reduction works cleanly inside
    proofs. -/
def chainValidAux (akPk : Nat) : List ChainStep → Prop
  | [] => True
  | step :: rest =>
      certValid akPk step.ekPk step.hN step.cert ∧
      chainValidAux step.ekPk rest

/-- Inductive validity predicate for the chain. Walks through the steps
    checking each cert verifies under its predecessor's pubkey. Empty
    chain is vacuously valid. -/
@[reducible] def chainValid (c : CertChain) : Prop := chainValidAux c.akPk c.steps

-- Useful unfolding lemmas (provable by definitional rewriting on chainValidAux):

theorem chainValidAux_nil (akPk : Nat) :
    chainValidAux akPk [] = True := rfl

theorem chainValidAux_cons (akPk : Nat) (step : ChainStep) (rest : List ChainStep) :
    chainValidAux akPk (step :: rest) =
      (certValid akPk step.ekPk step.hN step.cert ∧ chainValidAux step.ekPk rest) :=
  rfl

theorem chainValid_mk (akPk : Nat) (steps : List ChainStep) :
    chainValid ⟨akPk, steps⟩ = chainValidAux akPk steps := rfl

/-- Extend a chain with a freshly-signed step. Caller provides the new
    EK pubkey, its parent tip h_n, and the prior chain-head's secret key
    used to sign the cert. -/
noncomputable def extendChain
    (chain : CertChain)
    (newEkPk newHN prevSk : Nat)
    : CertChain :=
  ⟨chain.akPk, chain.steps ++ [⟨newEkPk, newHN, certFor prevSk newEkPk newHN⟩]⟩

-- ============================================================
-- Theorems (all DISCHARGED)
-- ============================================================

/-- Theorem 1 (Chain Length Monotonicity): extending a chain strictly
    increases its step count by exactly one. -/
theorem extend_chain_length_strictly_grows
    (c : CertChain) (newEkPk newHN prevSk : Nat) :
    (extendChain c newEkPk newHN prevSk).steps.length = c.steps.length + 1 := by
  simp [extendChain]

/-- Theorem 2 (Empty Chain Validity): an empty chain is trivially valid
    by the base case of `chainValidAux`. -/
theorem empty_chain_valid (akPk : Nat) : chainValid ⟨akPk, []⟩ := by
  rw [chainValid_mk, chainValidAux_nil]
  trivial

/-- Theorem 3 (Empty Chain Head): the chain head of an empty chain is
    AK_pk, which is what signs the first cert (step 0 → step 1). -/
theorem empty_chain_head_is_ak (akPk : Nat) :
    currentHead ⟨akPk, []⟩ = akPk := by
  simp [currentHead]

/-- Theorem 4 (Step-0 Soundness): extending an empty chain with a cert
    signed by AK's secret key produces a valid 1-step chain.

    Proof: extendChain ⟨akPk, []⟩ newEkPk newHN akSk reduces to
    ⟨akPk, [⟨newEkPk, newHN, certFor akSk newEkPk newHN⟩]⟩. By the
    [step] case of chainValid, this requires
      certValid akPk newEkPk newHN (certFor akSk newEkPk newHN)
    = sphincsVerify akPk (certHash newEkPk newHN) (sphincsSign akSk (certHash newEkPk newHN)).
    By sphincs_sign_verify_round_trip applied to seed akSk and message
    certHash newEkPk newHN, we get sphincsVerify with (sphincsKeyGen akSk).1
    and (sphincsKeyGen akSk).2 in place of akPk and akSk. The hypothesis
    h_keypair rewrites these to akPk and akSk respectively. -/
theorem extend_empty_chain_valid
    (akPk akSk newEkPk newHN : Nat)
    (h_keypair : (sphincsKeyGen akSk).1 = akPk ∧ (sphincsKeyGen akSk).2 = akSk) :
    chainValid (extendChain ⟨akPk, []⟩ newEkPk newHN akSk) := by
  -- extendChain ⟨akPk, []⟩ ... = ⟨akPk, [newStep]⟩ where newStep =
  -- ⟨newEkPk, newHN, certFor akSk newEkPk newHN⟩.
  show chainValidAux akPk [⟨newEkPk, newHN, certFor akSk newEkPk newHN⟩]
  rw [chainValidAux_cons]
  refine ⟨?_, ?_⟩
  · -- certValid akPk newEkPk newHN (certFor akSk newEkPk newHN)
    --   = sphincsVerify akPk (certHash newEkPk newHN)
    --                  (sphincsSign akSk (certHash newEkPk newHN))
    show sphincsVerify akPk (certHash newEkPk newHN)
                       (sphincsSign akSk (certHash newEkPk newHN))
    -- Apply round_trip and forward-rewrite the keypair components into
    -- the standalone (akPk, akSk) form using h_keypair.
    have rt := sphincs_sign_verify_round_trip akSk (certHash newEkPk newHN)
    rw [h_keypair.1, h_keypair.2] at rt
    exact rt
  · -- chainValidAux newEkPk [] = True
    rw [chainValidAux_nil]
    trivial

/-- Theorem 5 (Substitution Attack Resistance): a cert that verifies for
    one (EK_pk_1, h_n) does NOT verify for any different EK_pk_2 under
    the same h_n.

    This prevents an attacker from "swapping" an authorized EK_pk in a
    receipt for a different one and reusing the cert.

    Proof: assume `certValid prevPk ekPk2 hN cert` for contradiction.
    Both certValids unfold to `sphincsVerify prevPk (certHash _ hN) cert`.
    By sphincs_signature_message_binding (deterministic SPHINCS+), a
    single (pk, sig) pair binds at most one message — so
    certHash ekPk1 hN = certHash ekPk2 hN. By certHash_injective_in_ekPk,
    ekPk1 = ekPk2, contradicting h_distinct. -/
theorem cert_substitution_attack_resistant
    (prevPk ekPk1 ekPk2 hN cert : Nat)
    (h_distinct : ekPk1 ≠ ekPk2)
    (h_valid_for_1 : certValid prevPk ekPk1 hN cert) :
    ¬ certValid prevPk ekPk2 hN cert := by
  intro h_valid_for_2
  unfold certValid at h_valid_for_1 h_valid_for_2
  have h_msg_eq : certHash ekPk1 hN = certHash ekPk2 hN :=
    sphincs_signature_message_binding prevPk _ _ _ h_valid_for_1 h_valid_for_2
  exact h_distinct (certHash_injective_in_ekPk _ _ _ h_msg_eq)

/-- Theorem 6 (AK-Rooted First Step): a non-empty valid chain has a
    first step whose cert verifies under AK_pk.

    Proof: case-split on c.steps.
    - Empty: contradicts h_nonempty.
    - [step]: chainValid unfolds to certValid akPk step.ekPk step.hN step.cert.
    - step :: next :: rest: chainValid unfolds to a conjunction whose
      first conjunct is certValid akPk step.ekPk step.hN step.cert. -/
theorem cert_chain_first_step_anchored
    (c : CertChain) (h_valid : chainValid c) (h_nonempty : c.steps ≠ []) :
    ∃ (firstStep : ChainStep),
        c.steps.head? = some firstStep ∧
        certValid c.akPk firstStep.ekPk firstStep.hN firstStep.cert := by
  obtain ⟨akPk, steps⟩ := c
  cases steps with
  | nil => exact absurd rfl h_nonempty
  | cons step rest =>
      -- h_valid : chainValid ⟨akPk, step :: rest⟩
      --   = chainValidAux akPk (step :: rest)
      --   = certValid akPk step.ekPk step.hN step.cert ∧ chainValidAux step.ekPk rest
      rw [chainValid_mk, chainValidAux_cons] at h_valid
      exact ⟨step, rfl, h_valid.1⟩

/-- Helper: chainValidAux is preserved when appending a step whose cert
    was signed by the SK matching the *last* pubkey of the chain.

    This is the inductive workhorse for Theorem 7
    (extendChain_preserves_validity): chain validity propagates through
    extensions where the new cert is signed by the chain head. -/
theorem chainValidAux_extend
    (akPk : Nat) (steps : List ChainStep)
    (h_valid : chainValidAux akPk steps)
    (newEkPk newHN prevSk : Nat)
    (newStep : ChainStep)
    (h_newStep : newStep = ⟨newEkPk, newHN, certFor prevSk newEkPk newHN⟩)
    (h_lastPk : (sphincsKeyGen prevSk).1 =
                  match steps.getLast? with
                  | none => akPk
                  | some step => step.ekPk)
    (h_sk : (sphincsKeyGen prevSk).2 = prevSk) :
    chainValidAux akPk (steps ++ [newStep]) := by
  induction steps generalizing akPk with
  | nil =>
      -- steps.getLast? = none → akPk = (sphincsKeyGen prevSk).1
      simp at h_lastPk
      -- chainValidAux akPk ([] ++ [newStep]) = chainValidAux akPk [newStep]
      -- = certValid akPk newStep.ekPk newStep.hN newStep.cert ∧ chainValidAux newStep.ekPk []
      rw [List.nil_append, chainValidAux_cons]
      refine ⟨?_, ?_⟩
      · subst h_newStep
        show sphincsVerify akPk (certHash newEkPk newHN)
                           (sphincsSign prevSk (certHash newEkPk newHN))
        -- Forward-rewrite the round_trip output using h_lastPk and h_sk.
        have rt := sphincs_sign_verify_round_trip prevSk (certHash newEkPk newHN)
        rw [h_lastPk, h_sk] at rt
        exact rt
      · subst h_newStep
        rw [chainValidAux_nil]
        trivial
  | cons step rest ih =>
      -- h_valid : chainValidAux akPk (step :: rest)
      rw [chainValidAux_cons] at h_valid
      have h_first : certValid akPk step.ekPk step.hN step.cert := h_valid.1
      have h_rest_valid : chainValidAux step.ekPk rest := h_valid.2
      -- (step :: rest).getLast? equals rest.getLast? when rest ≠ [], else some step.
      -- Either way it's also the lastPk for the recursive call (with akPk = step.ekPk).
      have h_lastPk_rest :
          (sphincsKeyGen prevSk).1 =
            match rest.getLast? with
            | none => step.ekPk
            | some s => s.ekPk := by
        cases rest with
        | nil => simp; simp at h_lastPk; exact h_lastPk
        | cons r1 rs =>
            simp at h_lastPk ⊢
            exact h_lastPk
      have h_rest_extended :=
        ih step.ekPk h_rest_valid h_lastPk_rest
      -- (step :: rest) ++ [newStep] = step :: (rest ++ [newStep])
      rw [List.cons_append, chainValidAux_cons]
      exact ⟨h_first, h_rest_extended⟩

theorem extendChain_preserves_validity
    (c : CertChain) (h_valid : chainValid c)
    (newEkPk newHN prevSk : Nat)
    (h_keypair : (sphincsKeyGen prevSk).1 = currentHead c ∧
                 (sphincsKeyGen prevSk).2 = prevSk) :
    chainValid (extendChain c newEkPk newHN prevSk) := by
  obtain ⟨akPk, steps⟩ := c
  -- unfold extendChain and chainValid down to chainValidAux
  show chainValidAux akPk (steps ++ [⟨newEkPk, newHN, certFor prevSk newEkPk newHN⟩])
  -- bridge currentHead ⟨akPk, steps⟩ to the match-form expected by the helper
  have h_lastPk : (sphincsKeyGen prevSk).1 =
                    match steps.getLast? with
                    | none => akPk
                    | some step => step.ekPk := by
    have := h_keypair.1
    simp [currentHead] at this
    exact this
  exact chainValidAux_extend akPk steps h_valid newEkPk newHN prevSk
    ⟨newEkPk, newHN, certFor prevSk newEkPk newHN⟩ rfl h_lastPk h_keypair.2
