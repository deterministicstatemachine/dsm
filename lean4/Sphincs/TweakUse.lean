-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.AddressRange

/- Tweak single use. Under fixed-width oracle outputs (`OutputWidths o`, the
   functional contract BLAKE3 meets), every keyed thash request issued by key
   generation or by signing hashes, at its in-range address `a`, exactly
   `canon o p tk prfKey seed a`: a value fixed by the key material and the
   address alone, independent of the message. Hence an address never tweaks
   two different inputs: not within one key generation, not within one
   signing run, not across signing runs with the same key, and not between
   key generation and a later signature under the generated key.

   The raw-log corollaries identify thash requests by their key `tk`; they
   assume `tk` differs from the PRF key and the message-PRF key (outputs of
   distinct derive_key contexts). Without that, a PRF request could carry the
   same key and the classification theorems (`*_inputs_canonical`), which need
   no key assumption, are the exact statement. -/
namespace DSM.Sphincs

/-- Two canonical thash requests under one key with the same 32-byte address
    prefix are the same request. -/
theorem canonical_requests_agree (C : Adrs → Bytes) (tk : Bytes) (n : Nat) {r₁ r₂ : Request}
    (h₁ : ∃ a : Adrs, a.InRange ∧ r₁ = ⟨1,"",tk,a.bytes ++ C a,n⟩)
    (h₂ : ∃ a : Adrs, a.InRange ∧ r₂ = ⟨1,"",tk,a.bytes ++ C a,n⟩)
    (same : r₁.input.take 32 = r₂.input.take 32) : r₁ = r₂ := by
  obtain ⟨a₁, ha₁, rfl⟩ := h₁
  obtain ⟨a₂, ha₂, rfl⟩ := h₂
  have t₁ : (a₁.bytes ++ C a₁).take 32 = a₁.bytes := by
    rw [← address_width a₁]; exact List.take_left
  have t₂ : (a₂.bytes ++ C a₂).take 32 = a₂.bytes := by
    rw [← address_width a₂]; exact List.take_left
  have hb : a₁.bytes = a₂.bytes := by
    have e := same
    simp only at e
    rw [t₁, t₂] at e
    exact e
  rw [adrs_bytes_injective a₁ a₂ ha₁ ha₂ hb]

/-- Signing: under fixed-width outputs, every keyed request is the
    message-PRF request, an in-range PRF request, or an in-range thash request
    whose hashed value is the canonical value of its address. No key
    distinctness is assumed. -/
theorem sign_thash_inputs_canonical (o : Oracle Id) (widths : OutputWidths o)
    (v : Variant) (sk msg : Bytes) :
    let p := params v
    let seed := slice sk (2*p.n) p.n
    let tk := deriveKey o "DSM/sphincs/v2/thash" seed
    let prfKey := deriveKey o "DSM/sphincs/v2/prf" (sk.take p.n)
    let msgKey := deriveKey o "DSM/sphincs/v2/prf-msg" (slice sk p.n p.n)
    ∀ r ∈ ((sign (logOracle o) v sk msg).run []).2, r.mode = 1 →
      r = ⟨1,"",msgKey,seed ++ msg,p.n⟩ ∨
      (∃ a : Adrs, a.InRange ∧ r = ⟨1,"",tk,a.bytes ++ canon o p tk prfKey seed a,p.n⟩) ∨
      (∃ a : Adrs, a.InRange ∧ r = ⟨1,"",prfKey,seed ++ a.bytes,p.n⟩) := by
  intro p seed tk prfKey msgKey r hr hm
  rcases (sign_good o v sk msg).run_empty.2 r hr with h | h | h | h
  · exact absurd hm h
  · exact Or.inl h
  · obtain ⟨a, x, ha, e, hc⟩ := h
    rw [hc widths] at e
    exact Or.inr (Or.inl ⟨a, ha, e⟩)
  · exact Or.inr (Or.inr h)

/-- Key generation: under fixed-width outputs, every keyed request is an
    in-range PRF request or an in-range thash request whose hashed value is
    the canonical value of its address. No key distinctness is assumed. -/
theorem keygen_thash_inputs_canonical (o : Oracle Id) (widths : OutputWidths o)
    (v : Variant) (seed32 : Wire 32) :
    let p := params v
    let expanded := o ⟨3,"ChaCha20Rng",[],seed32.val,3*p.n⟩
    let seed := slice expanded (2*p.n) p.n
    let tk := deriveKey o "DSM/sphincs/v2/thash" seed
    let prfKey := deriveKey o "DSM/sphincs/v2/prf" (expanded.take p.n)
    ∀ r ∈ ((generateKeypair (logOracle o) v seed32).run []).2, r.mode = 1 →
      (∃ a : Adrs, a.InRange ∧ r = ⟨1,"",tk,a.bytes ++ canon o p tk prfKey seed a,p.n⟩) ∨
      (∃ a : Adrs, a.InRange ∧ r = ⟨1,"",prfKey,seed ++ a.bytes,p.n⟩) := by
  intro p expanded seed tk prfKey r hr hm
  rcases (keygen_good o v seed32).run_empty.2 r hr with h | h | h
  · exact absurd hm h
  · obtain ⟨a, x, ha, e, hc⟩ := h
    rw [hc widths] at e
    exact Or.inl ⟨a, ha, e⟩
  · exact Or.inr h

/-- In a signing log, a keyed request under the thash key is canonical,
    provided that key differs from the PRF and message-PRF keys. -/
theorem sign_thash_key_canonical (o : Oracle Id) (widths : OutputWidths o)
    (v : Variant) (sk msg : Bytes)
    (hp : deriveKey o "DSM/sphincs/v2/thash" (slice sk (2*(params v).n) (params v).n) ≠
      deriveKey o "DSM/sphincs/v2/prf" (sk.take (params v).n))
    (hm : deriveKey o "DSM/sphincs/v2/thash" (slice sk (2*(params v).n) (params v).n) ≠
      deriveKey o "DSM/sphincs/v2/prf-msg" (slice sk (params v).n (params v).n))
    (r : Request) (hr : r ∈ ((sign (logOracle o) v sk msg).run []).2) (mode : r.mode = 1)
    (key : r.key = deriveKey o "DSM/sphincs/v2/thash" (slice sk (2*(params v).n) (params v).n)) :
    ∃ a : Adrs, a.InRange ∧ r = ⟨1,"",deriveKey o "DSM/sphincs/v2/thash"
      (slice sk (2*(params v).n) (params v).n),
      a.bytes ++ canon o (params v) (deriveKey o "DSM/sphincs/v2/thash"
        (slice sk (2*(params v).n) (params v).n))
        (deriveKey o "DSM/sphincs/v2/prf" (sk.take (params v).n))
        (slice sk (2*(params v).n) (params v).n) a,(params v).n⟩ := by
  rcases sign_thash_inputs_canonical o widths v sk msg r hr mode with h | h | h
  · subst h; exact absurd key.symm hm
  · exact h
  · obtain ⟨a, _, e⟩ := h
    subst e; exact absurd key.symm hp

theorem keygen_thash_key_canonical (o : Oracle Id) (widths : OutputWidths o)
    (v : Variant) (seed32 : Wire 32)
    (hp : deriveKey o "DSM/sphincs/v2/thash"
        (slice (o ⟨3,"ChaCha20Rng",[],seed32.val,3*(params v).n⟩) (2*(params v).n) (params v).n) ≠
      deriveKey o "DSM/sphincs/v2/prf"
        ((o ⟨3,"ChaCha20Rng",[],seed32.val,3*(params v).n⟩).take (params v).n))
    (r : Request) (hr : r ∈ ((generateKeypair (logOracle o) v seed32).run []).2) (mode : r.mode = 1)
    (key : r.key = deriveKey o "DSM/sphincs/v2/thash"
        (slice (o ⟨3,"ChaCha20Rng",[],seed32.val,3*(params v).n⟩) (2*(params v).n) (params v).n)) :
    ∃ a : Adrs, a.InRange ∧ r = ⟨1,"",deriveKey o "DSM/sphincs/v2/thash"
        (slice (o ⟨3,"ChaCha20Rng",[],seed32.val,3*(params v).n⟩) (2*(params v).n) (params v).n),
      a.bytes ++ canon o (params v) (deriveKey o "DSM/sphincs/v2/thash"
        (slice (o ⟨3,"ChaCha20Rng",[],seed32.val,3*(params v).n⟩) (2*(params v).n) (params v).n))
        (deriveKey o "DSM/sphincs/v2/prf"
          ((o ⟨3,"ChaCha20Rng",[],seed32.val,3*(params v).n⟩).take (params v).n))
        (slice (o ⟨3,"ChaCha20Rng",[],seed32.val,3*(params v).n⟩) (2*(params v).n) (params v).n) a,
      (params v).n⟩ := by
  rcases keygen_thash_inputs_canonical o widths v seed32 r hr mode with h | h
  · exact h
  · obtain ⟨a, _, e⟩ := h
    subst e; exact absurd key.symm hp

/-- Tweak single use across signing runs under one secret key: two keyed
    thash-key requests, from signing any two messages (possibly the same),
    whose inputs share the 32-byte address prefix are identical. -/
theorem sign_tweak_single_use_across (o : Oracle Id) (widths : OutputWidths o)
    (v : Variant) (sk msg₁ msg₂ : Bytes)
    (hp : deriveKey o "DSM/sphincs/v2/thash" (slice sk (2*(params v).n) (params v).n) ≠
      deriveKey o "DSM/sphincs/v2/prf" (sk.take (params v).n))
    (hm : deriveKey o "DSM/sphincs/v2/thash" (slice sk (2*(params v).n) (params v).n) ≠
      deriveKey o "DSM/sphincs/v2/prf-msg" (slice sk (params v).n (params v).n))
    (r₁ r₂ : Request)
    (h₁ : r₁ ∈ ((sign (logOracle o) v sk msg₁).run []).2)
    (h₂ : r₂ ∈ ((sign (logOracle o) v sk msg₂).run []).2)
    (m₁ : r₁.mode = 1) (m₂ : r₂.mode = 1)
    (k₁ : r₁.key = deriveKey o "DSM/sphincs/v2/thash" (slice sk (2*(params v).n) (params v).n))
    (k₂ : r₂.key = deriveKey o "DSM/sphincs/v2/thash" (slice sk (2*(params v).n) (params v).n))
    (same : r₁.input.take 32 = r₂.input.take 32) : r₁ = r₂ :=
  canonical_requests_agree _ _ _
    (sign_thash_key_canonical o widths v sk msg₁ hp hm r₁ h₁ m₁ k₁)
    (sign_thash_key_canonical o widths v sk msg₂ hp hm r₂ h₂ m₂ k₂) same

/-- Tweak single use within one signing run. -/
theorem sign_tweak_single_use (o : Oracle Id) (widths : OutputWidths o)
    (v : Variant) (sk msg : Bytes)
    (hp : deriveKey o "DSM/sphincs/v2/thash" (slice sk (2*(params v).n) (params v).n) ≠
      deriveKey o "DSM/sphincs/v2/prf" (sk.take (params v).n))
    (hm : deriveKey o "DSM/sphincs/v2/thash" (slice sk (2*(params v).n) (params v).n) ≠
      deriveKey o "DSM/sphincs/v2/prf-msg" (slice sk (params v).n (params v).n))
    (r₁ r₂ : Request)
    (h₁ : r₁ ∈ ((sign (logOracle o) v sk msg).run []).2)
    (h₂ : r₂ ∈ ((sign (logOracle o) v sk msg).run []).2)
    (m₁ : r₁.mode = 1) (m₂ : r₂.mode = 1)
    (k₁ : r₁.key = deriveKey o "DSM/sphincs/v2/thash" (slice sk (2*(params v).n) (params v).n))
    (k₂ : r₂.key = deriveKey o "DSM/sphincs/v2/thash" (slice sk (2*(params v).n) (params v).n))
    (same : r₁.input.take 32 = r₂.input.take 32) : r₁ = r₂ :=
  sign_tweak_single_use_across o widths v sk msg msg hp hm r₁ r₂ h₁ h₂ m₁ m₂ k₁ k₂ same

/-- Tweak single use within one key generation run. -/
theorem keygen_tweak_single_use (o : Oracle Id) (widths : OutputWidths o)
    (v : Variant) (seed32 : Wire 32)
    (hp : deriveKey o "DSM/sphincs/v2/thash"
        (slice (o ⟨3,"ChaCha20Rng",[],seed32.val,3*(params v).n⟩) (2*(params v).n) (params v).n) ≠
      deriveKey o "DSM/sphincs/v2/prf"
        ((o ⟨3,"ChaCha20Rng",[],seed32.val,3*(params v).n⟩).take (params v).n))
    (r₁ r₂ : Request)
    (h₁ : r₁ ∈ ((generateKeypair (logOracle o) v seed32).run []).2)
    (h₂ : r₂ ∈ ((generateKeypair (logOracle o) v seed32).run []).2)
    (m₁ : r₁.mode = 1) (m₂ : r₂.mode = 1)
    (k₁ : r₁.key = deriveKey o "DSM/sphincs/v2/thash"
        (slice (o ⟨3,"ChaCha20Rng",[],seed32.val,3*(params v).n⟩) (2*(params v).n) (params v).n))
    (k₂ : r₂.key = deriveKey o "DSM/sphincs/v2/thash"
        (slice (o ⟨3,"ChaCha20Rng",[],seed32.val,3*(params v).n⟩) (2*(params v).n) (params v).n))
    (same : r₁.input.take 32 = r₂.input.take 32) : r₁ = r₂ :=
  canonical_requests_agree _ _ _
    (keygen_thash_key_canonical o widths v seed32 hp r₁ h₁ m₁ k₁)
    (keygen_thash_key_canonical o widths v seed32 hp r₂ h₂ m₂ k₂) same

/-- Under fixed-width outputs, signing with a generated secret key uses the
    same seed, thash key and PRF key as the key generation that produced it. -/
theorem generated_key_material (o : Oracle Id) (widths : OutputWidths o) (v : Variant)
    (seed32 : Wire 32) :
    slice (generateKeypair o v seed32).2 (2*(params v).n) (params v).n =
      slice (o ⟨3,"ChaCha20Rng",[],seed32.val,3*(params v).n⟩) (2*(params v).n) (params v).n ∧
    (generateKeypair o v seed32).2.take (params v).n =
      (o ⟨3,"ChaCha20Rng",[],seed32.val,3*(params v).n⟩).take (params v).n := by
  have expandedLen : (o ⟨3,"ChaCha20Rng",[],seed32.val,3*(params v).n⟩).length = 3*(params v).n :=
    widths _
  constructor
  · exact slice_append_prefix _ _ _ _ (by rw [expandedLen]; omega)
  · exact List.take_append_of_le_length (by rw [expandedLen]; omega)

/-- Tweak single use between key generation and a later signature under the
    generated secret key. -/
theorem keygen_sign_tweak_single_use (o : Oracle Id) (widths : OutputWidths o)
    (v : Variant) (seed32 : Wire 32) (msg : Bytes)
    (hp : deriveKey o "DSM/sphincs/v2/thash"
        (slice (o ⟨3,"ChaCha20Rng",[],seed32.val,3*(params v).n⟩) (2*(params v).n) (params v).n) ≠
      deriveKey o "DSM/sphincs/v2/prf"
        ((o ⟨3,"ChaCha20Rng",[],seed32.val,3*(params v).n⟩).take (params v).n))
    (hm : deriveKey o "DSM/sphincs/v2/thash"
        (slice (o ⟨3,"ChaCha20Rng",[],seed32.val,3*(params v).n⟩) (2*(params v).n) (params v).n) ≠
      deriveKey o "DSM/sphincs/v2/prf-msg"
        (slice (generateKeypair o v seed32).2 (params v).n (params v).n))
    (r₁ r₂ : Request)
    (h₁ : r₁ ∈ ((generateKeypair (logOracle o) v seed32).run []).2)
    (h₂ : r₂ ∈ ((sign (logOracle o) v (generateKeypair o v seed32).2 msg).run []).2)
    (m₁ : r₁.mode = 1) (m₂ : r₂.mode = 1)
    (k₁ : r₁.key = deriveKey o "DSM/sphincs/v2/thash"
        (slice (o ⟨3,"ChaCha20Rng",[],seed32.val,3*(params v).n⟩) (2*(params v).n) (params v).n))
    (k₂ : r₂.key = deriveKey o "DSM/sphincs/v2/thash"
        (slice (o ⟨3,"ChaCha20Rng",[],seed32.val,3*(params v).n⟩) (2*(params v).n) (params v).n))
    (same : r₁.input.take 32 = r₂.input.take 32) : r₁ = r₂ := by
  obtain ⟨hs, ht⟩ := generated_key_material o widths v seed32
  have c₂ := sign_thash_key_canonical o widths v (generateKeypair o v seed32).2 msg
    (by rw [hs, ht]; exact hp) (by rw [hs]; exact hm) r₂ h₂ m₂ (by rw [hs]; exact k₂)
  rw [hs, ht] at c₂
  exact canonical_requests_agree _ _ _
    (keygen_thash_key_canonical o widths v seed32 hp r₁ h₁ m₁ k₁) c₂ same

#print axioms keygen_sign_tweak_single_use
#print axioms canonical_requests_agree
#print axioms sign_thash_inputs_canonical
#print axioms keygen_thash_inputs_canonical
#print axioms sign_tweak_single_use_across
#print axioms sign_tweak_single_use
#print axioms keygen_tweak_single_use
end DSM.Sphincs
