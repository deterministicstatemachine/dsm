-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.MultiKey
import Sphincs.WrapperInjective

/- Object-level forgery. DSM never signs raw bytes: an honest key signs the
   digest H(enc obj) of a wrapper object (EK certificate, DevID, Connect
   object, escrow statement, SoFi claim, ...). The attack that matters is a
   signature that verifies, under an honest key, on the digest of an object
   the key never signed. This composes the multi-key reduction with an
   injective object encoding (WrapperInjective.lean): such a signature is
   either one of that key's four primitive events, or a collision of H on the
   encodings of two different objects. -/
namespace DSM.Sphincs.Security

theorem not_fresh_signed (limits : Limits) (view : MView) (k : Nat) (m : Bytes)
    (h : mfresh limits view k m = false) : m ∈ signedOn limits view k := by
  unfold mfresh at h
  simp only [Bool.not_eq_false', List.any_eq_true, Bool.and_eq_true, beq_iff_eq] at h
  obtain ⟨r, hr, ⟨hk, hl⟩, hm⟩ := h
  unfold signedOn
  rw [List.mem_map]
  refine ⟨r, ?_, hm⟩
  rw [List.mem_filter]
  exact ⟨hr, by simp [hk, hl]⟩

theorem mforge_of_parts (v : Variant) (limits : Limits) (O : Oracle Id) (exps : List Bytes)
    (A : MStrategy) (view : MView) (k : Nat) (m s : Bytes)
    (hout : mexperiment v limits O exps A = .forgery view k m s) (hk : k < exps.length)
    (hlegal : legal limits m = true) (hfresh : mfresh limits view k m = true)
    (hver : mverify v O exps k m s = true) : mforgeEvent v limits O exps A = true := by
  have hkeys := mexperiment_keys v limits O exps A
  rw [hout] at hkeys
  simp only [MOutcome.view] at hkeys
  unfold mforgeEvent
  rw [hout]
  simp only [mwins, hkeys, List.length_map, hk, decide_true, hlegal, hfresh, hver, Bool.and_self]

/-- OBJECT-LEVEL FORGERY EXTRACTION. Suppose every message legally signed under
    key k is the digest `H (enc q)` of some object `q ∈ Q`, and the adversary's
    final signature verifies under key k on `H (enc obj)` for an object
    `obj ∉ Q`. Then key k's primitive events occurred, or `H` collides on the
    encodings of two different objects. -/
theorem wrapper_forgery_extract (v : Variant) (limits : Limits) (O : Oracle Id)
    (widths : OutputWidths O) (exps : List Bytes) (A : MStrategy)
    (hlen : ∀ e ∈ exps, e.length = 3*(params v).n)
    {Obj : Type} (H : Bytes → Bytes) (enc : Obj → Bytes)
    (enc_inj : ∀ a b, enc a = enc b → a = b) (Q : List Obj)
    (view : MView) (k : Nat) (m s : Bytes)
    (hout : mexperiment v limits O exps A = .forgery view k m s) (hk : k < exps.length)
    (hlegal : legal limits m = true) (hver : mverify v O exps k m s = true)
    (hQ : ∀ x ∈ signedOn limits view k, ∃ q ∈ Q, x = H (enc q))
    (obj : Obj) (hobj : obj ∉ Q) (hm : m = H (enc obj)) :
    KeyBreak v O (exps.getD k []) (signedOn limits view k) m s ∨
      ∃ q ∈ Q, enc q ≠ enc obj ∧ H (enc q) = H (enc obj) := by
  cases hf : mfresh limits view k m with
  | true =>
    left
    have hwin := mforge_of_parts v limits O exps A view k m s hout hk hlegal hf hver
    obtain ⟨view', k', m', s', hout', _, hb⟩ := multi_forgery_extract v limits O widths exps A hlen hwin
    rw [hout] at hout'
    injection hout' with e1 e2 e3 e4
    subst e1; subst e2; subst e3; subst e4
    exact hb
  | false =>
    right
    obtain ⟨q, hq, hx⟩ := hQ m (not_fresh_signed limits view k m hf)
    refine ⟨q, hq, ?_, by rw [← hx, hm]⟩
    intro he
    exact hobj (enc_inj q obj he ▸ hq)

/-- The DSM Connect instance: objects are (kind, body) pairs signed as
    `H(tag(kind) ‖ 0 ‖ body)`. -/
theorem connect_forgery_extract (v : Variant) (limits : Limits) (O : Oracle Id)
    (widths : OutputWidths O) (exps : List Bytes) (A : MStrategy)
    (hlen : ∀ e ∈ exps, e.length = 3*(params v).n) (H : Bytes → Bytes)
    (Q : List (ConnectKind × Bytes)) (view : MView) (k : Nat) (m s : Bytes)
    (hout : mexperiment v limits O exps A = .forgery view k m s) (hk : k < exps.length)
    (hlegal : legal limits m = true) (hver : mverify v O exps k m s = true)
    (hQ : ∀ x ∈ signedOn limits view k, ∃ q ∈ Q, x = H (connectSigningInput q.1 q.2))
    (obj : ConnectKind × Bytes) (hobj : obj ∉ Q) (hm : m = H (connectSigningInput obj.1 obj.2)) :
    KeyBreak v O (exps.getD k []) (signedOn limits view k) m s ∨
      ∃ q ∈ Q, connectSigningInput q.1 q.2 ≠ connectSigningInput obj.1 obj.2 ∧
        H (connectSigningInput q.1 q.2) = H (connectSigningInput obj.1 obj.2) :=
  wrapper_forgery_extract v limits O widths exps A hlen H (fun q => connectSigningInput q.1 q.2)
    (fun a b h => by
      obtain ⟨hk, hb⟩ := connect_signing_injective a.1 b.1 a.2 b.2 h
      exact Prod.ext hk hb)
    Q view k m s hout hk hlegal hver hQ obj hobj hm

/-- The escrow-statement instance: objects are (verdict cell, outcome). -/
theorem escrow_forgery_extract (v : Variant) (limits : Limits) (O : Oracle Id)
    (widths : OutputWidths O) (exps : List Bytes) (A : MStrategy)
    (hlen : ∀ e ∈ exps, e.length = 3*(params v).n) (H : Bytes → Bytes)
    (Q : List (Wire 32 × Bytes)) (view : MView) (k : Nat) (m s : Bytes)
    (hout : mexperiment v limits O exps A = .forgery view k m s) (hk : k < exps.length)
    (hlegal : legal limits m = true) (hver : mverify v O exps k m s = true)
    (hQ : ∀ x ∈ signedOn limits view k, ∃ q ∈ Q, x = H (escrowStatementInput q.1 q.2))
    (obj : Wire 32 × Bytes) (hobj : obj ∉ Q) (hm : m = H (escrowStatementInput obj.1 obj.2)) :
    KeyBreak v O (exps.getD k []) (signedOn limits view k) m s ∨
      ∃ q ∈ Q, escrowStatementInput q.1 q.2 ≠ escrowStatementInput obj.1 obj.2 ∧
        H (escrowStatementInput q.1 q.2) = H (escrowStatementInput obj.1 obj.2) :=
  wrapper_forgery_extract v limits O widths exps A hlen H (fun q => escrowStatementInput q.1 q.2)
    (fun a b h => by
      obtain ⟨hk, hb⟩ := escrow_statement_injective a.1 b.1 a.2 b.2 h
      exact Prod.ext hk hb)
    Q view k m s hout hk hlegal hver hQ obj hobj hm

/-- The EK-certificate instance: objects are (next EK public key, parent tip),
    signed as `H(DSM/ek-cert ‖ 0 ‖ EK_pk ‖ h_n)` (`derive_ek_cert_hash`). A
    certificate that verifies under an honest key for a (key, tip) pair it
    never certified is that key's primitive event or a collision of H. -/
theorem ek_cert_forgery_extract (v : Variant) (limits : Limits) (O : Oracle Id)
    (widths : OutputWidths O) (exps : List Bytes) (A : MStrategy)
    (hlen : ∀ e ∈ exps, e.length = 3*(params v).n) (H : Bytes → Bytes)
    (Q : List (Wire 64 × Wire 32)) (view : MView) (k : Nat) (m s : Bytes)
    (hout : mexperiment v limits O exps A = .forgery view k m s) (hk : k < exps.length)
    (hlegal : legal limits m = true) (hver : mverify v O exps k m s = true)
    (hQ : ∀ x ∈ signedOn limits view k, ∃ q ∈ Q, x = H (ekCertInput q.1.val q.2))
    (obj : Wire 64 × Wire 32) (hobj : obj ∉ Q) (hm : m = H (ekCertInput obj.1.val obj.2)) :
    KeyBreak v O (exps.getD k []) (signedOn limits view k) m s ∨
      ∃ q ∈ Q, ekCertInput q.1.val q.2 ≠ ekCertInput obj.1.val obj.2 ∧
        H (ekCertInput q.1.val q.2) = H (ekCertInput obj.1.val obj.2) :=
  wrapper_forgery_extract v limits O widths exps A hlen H (fun q => ekCertInput q.1.val q.2)
    (fun a b h => by
      obtain ⟨hk, hb⟩ := cert_preimage_binding a.1 b.1 a.2 b.2 h
      exact Prod.ext hk hb)
    Q view k m s hout hk hlegal hver hQ obj hobj hm

#print axioms wrapper_forgery_extract
#print axioms connect_forgery_extract
#print axioms escrow_forgery_extract
#print axioms ek_cert_forgery_extract
end DSM.Sphincs.Security
