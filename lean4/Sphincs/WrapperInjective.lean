-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.Proofs

/- Canonical-byte injectivity of DSM's signed wrappers (SPHINCS security
   charter, "Wrapper targets"). Every signed digest is
   H(tag ‖ 0x00 ‖ body) (dsm::crypto::blake3::domain_hash). TaggedHashDomain
   rejects an empty or NUL-bearing tag at compile time, so the NUL ends the tag
   and the encoding determines (tag, body). Each wrapper body below is then
   shown to determine its fields. With these, two distinct signed objects never
   share a preimage, so equal digests are an explicit hash collision
   (domain_binding_or_collision). No cryptographic premise is used. -/
namespace DSM.Sphincs

/-- The domain encoding, over the tag's bytes. -/
def tagged (tag body : Bytes) : Bytes := tag ++ [0] ++ body

theorem tagged_nil (d : Bytes) : tagged [] d = 0 :: d := rfl
theorem tagged_cons (c : UInt8) (cs d : Bytes) : tagged (c :: cs) d = c :: tagged cs d := rfl

/-- A NUL-free tag is recovered from the encoding, and so is the body. -/
theorem tagged_injective : ∀ (t₁ t₂ d₁ d₂ : Bytes), (0 : UInt8) ∉ t₁ → (0 : UInt8) ∉ t₂ →
    tagged t₁ d₁ = tagged t₂ d₂ → t₁ = t₂ ∧ d₁ = d₂
  | [], [], d₁, d₂, _, _, h => by
      rw [tagged_nil, tagged_nil] at h
      exact ⟨rfl, (List.cons.inj h).2⟩
  | [], c :: cs, d₁, d₂, _, n₂, h => by
      rw [tagged_nil, tagged_cons] at h
      have hc := (List.cons.inj h).1
      subst hc
      simp at n₂
  | c :: cs, [], d₁, d₂, n₁, _, h => by
      rw [tagged_cons, tagged_nil] at h
      have hc := (List.cons.inj h).1
      subst hc
      simp at n₁
  | c :: cs, c' :: cs', d₁, d₂, n₁, n₂, h => by
      rw [tagged_cons, tagged_cons] at h
      obtain ⟨hc, ht⟩ := List.cons.inj h
      have ih := tagged_injective cs cs' d₁ d₂ (fun m => n₁ (List.mem_cons_of_mem _ m))
        (fun m => n₂ (List.mem_cons_of_mem _ m)) ht
      exact ⟨by rw [hc, ih.1], ih.2⟩

theorem domainInput_eq_tagged (tag : String) (body : Bytes) :
    domainInput tag body = tagged tag.toUTF8.toList body := rfl

/-! ## The signing domains, as the Rust names them -/

def tagEkCert := "DSM/ek-cert"
def tagDevid := "DSM/devid"
def tagIdentityBinding := "DSM/kyber-identity-binding"
def tagResolutionClaim := "DSM/sofi/resolution-claim-sign/v1"
def tagEscrowStatement := "DSM/escrow/statement/v1"
def tagConnectOffer := "DSM/connect/offer"
def tagConnectAccept := "DSM/connect/accept"
def tagConnectRequest := "DSM/connect/request"
def tagConnectResponse := "DSM/connect/response"

def signingTags : List String :=
  [tagEkCert, tagDevid, tagIdentityBinding, tagResolutionClaim, tagEscrowStatement,
   tagConnectOffer, tagConnectAccept, tagConnectRequest, tagConnectResponse]

/-! `ByteArray.toList` is defined by well-founded recursion, which the kernel
does not evaluate. It is the underlying list. -/

theorem bytearray_toList_loop (bs : ByteArray) :
    ∀ n i (r : List UInt8), bs.size - i = n →
      ByteArray.toList.loop bs i r = r.reverse ++ bs.data.toList.drop i := by
  intro n
  induction n with
  | zero =>
    intro i r hn
    unfold ByteArray.toList.loop
    have hi : ¬ i < bs.size := by omega
    have hd : bs.data.toList.drop i = [] := by
      apply List.drop_eq_nil_of_le
      simp only [Array.length_toList]
      exact Nat.le_of_not_lt hi
    simp [hi, hd]
  | succ n ih =>
    intro i r hn
    unfold ByteArray.toList.loop
    have hi : i < bs.size := by omega
    have hl : i < bs.data.toList.length := by simpa [Array.length_toList] using hi
    rw [if_pos hi, ih (i+1) _ (by omega), List.drop_eq_getElem_cons hl]
    have hs : i < bs.data.size := hi
    have hg : bs.get! i = bs.data.toList[i] := by
      obtain ⟨d⟩ := bs
      show d[i]! = d.toList[i]
      rw [getElem!_pos d i hs, Array.getElem_toList]
    rw [hg]
    simp

theorem bytearray_toList (bs : ByteArray) : bs.toList = bs.data.toList := by
  unfold ByteArray.toList
  rw [bytearray_toList_loop bs _ 0 [] rfl]
  simp

/-- A string's UTF-8 bytes, in a form the kernel evaluates. -/
def utf8 (s : String) : Bytes := s.data.flatMap String.utf8EncodeChar

theorem toUTF8_toList (s : String) : s.toUTF8.toList = utf8 s := by
  rw [bytearray_toList]; rfl

theorem signing_tags_nul_free : ∀ t ∈ signingTags, (0 : UInt8) ∉ t.toUTF8.toList := by
  intro t ht
  rw [toUTF8_toList]
  revert t
  decide

theorem signing_tags_distinct : (signingTags.map utf8).Nodup := by
  decide

/-- Domain separation: a preimage under one signing domain is never a
    preimage under another, and within one domain it fixes the body. -/
theorem signing_domain_separation (t₁ t₂ : String) (h₁ : t₁ ∈ signingTags) (h₂ : t₂ ∈ signingTags)
    (b₁ b₂ : Bytes) (h : domainInput t₁ b₁ = domainInput t₂ b₂) :
    t₁.toUTF8.toList = t₂.toUTF8.toList ∧ b₁ = b₂ :=
  tagged_injective _ _ _ _ (signing_tags_nul_free _ h₁) (signing_tags_nul_free _ h₂) h

/-! ## Escrow verdict statements (SoFi Amendment S21)

`statement(K, o) = H(DSM/escrow/statement/v1 ‖ K(32) ‖ u32be(|o|) ‖ o)`,
`dsm::sofi::escrow::statement`. -/

def escrowStatementInput (cell : Wire 32) (outcome : Bytes) : Bytes :=
  domainInput tagEscrowStatement (cell.val ++ be 4 outcome.length ++ outcome)

theorem escrow_statement_injective (k₁ k₂ : Wire 32) (o₁ o₂ : Bytes)
    (h : escrowStatementInput k₁ o₁ = escrowStatementInput k₂ o₂) : k₁ = k₂ ∧ o₁ = o₂ := by
  have body := List.append_cancel_left h
  simp only [List.append_assoc] at body
  obtain ⟨hk, rest⟩ := List.append_inj body (by rw [k₁.property, k₂.property])
  obtain ⟨_, ho⟩ := List.append_inj rest (by simp [be_width])
  exact ⟨Subtype.ext hk, ho⟩

/-! ## DSM Connect signed objects (DSM Amendment A11)

`signing_digest(kind, body) = H(<kind tag> ‖ body)`,
`dsm_sdk::sdk::connect::signed::signing_digest`. -/

inductive ConnectKind where
  | offer | accept | request | response
  deriving DecidableEq, Repr

def ConnectKind.tag : ConnectKind → String
  | .offer => tagConnectOffer
  | .accept => tagConnectAccept
  | .request => tagConnectRequest
  | .response => tagConnectResponse

theorem ConnectKind.tag_mem (k : ConnectKind) : k.tag ∈ signingTags := by
  cases k <;> decide

theorem ConnectKind.tag_injective (k₁ k₂ : ConnectKind)
    (h : k₁.tag.toUTF8.toList = k₂.tag.toUTF8.toList) : k₁ = k₂ := by
  rw [toUTF8_toList, toUTF8_toList] at h
  cases k₁ <;> cases k₂ <;> first | rfl | (exfalso; revert h; decide)

def connectSigningInput (kind : ConnectKind) (body : Bytes) : Bytes :=
  domainInput kind.tag body

theorem connect_signing_injective (k₁ k₂ : ConnectKind) (b₁ b₂ : Bytes)
    (h : connectSigningInput k₁ b₁ = connectSigningInput k₂ b₂) : k₁ = k₂ ∧ b₁ = b₂ := by
  obtain ⟨ht, hb⟩ := signing_domain_separation _ _ k₁.tag_mem k₂.tag_mem _ _ h
  exact ⟨ConnectKind.tag_injective _ _ ht, hb⟩

/-! ## SoFi resolution claims (SoFi Amendment S20)

`resolution_claim_signing_digest = H(DSM/sofi/resolution-claim-sign/v1 ‖
CCB(claim) ‖ u16be(alg) ‖ u32be(|pk|) ‖ pk ‖ AttA)`, and CCB of a
SofiResolutionClaim is the fixed-width
`u16be(class) ‖ u16be(schema) ‖ genesis ‖ device ‖ u64be(position) ‖ fulfillment ‖ realize ‖ void`
(`SofiResolutionClaim::encode`). -/

structure ResolutionClaim where
  genesis : Wire 32
  device : Wire 32
  position : Nat
  fulfillment : Wire 32
  realize : Wire 32
  void : Wire 32

def ResolutionClaim.ccb (cls schema : Nat) (c : ResolutionClaim) : Bytes :=
  be 2 cls ++ be 2 schema ++ c.genesis.val ++ c.device.val ++ be 8 c.position ++
    c.fulfillment.val ++ c.realize.val ++ c.void.val

theorem resolution_claim_ccb_width (cls schema : Nat) (c : ResolutionClaim) :
    (c.ccb cls schema).length = 172 := by
  simp [ResolutionClaim.ccb, be_width, c.genesis.property, c.device.property,
    c.fulfillment.property, c.realize.property, c.void.property]

theorem wire_head {w : Nat} {a b : Wire w} {x y : Bytes} (h : a.val ++ x = b.val ++ y) :
    a = b ∧ x = y := by
  obtain ⟨h1, h2⟩ := List.append_inj h (by rw [a.property, b.property])
  exact ⟨Subtype.ext h1, h2⟩

theorem be_head {w x₁ x₂ : Nat} {s t : Bytes} (b₁ : x₁ < 256^w) (b₂ : x₂ < 256^w)
    (h : be w x₁ ++ s = be w x₂ ++ t) : x₁ = x₂ ∧ s = t := by
  obtain ⟨h1, h2⟩ := List.append_inj h (by simp [be_width])
  have := congrArg toInt h1
  rw [be_roundtrip _ _ b₁, be_roundtrip _ _ b₂] at this
  exact ⟨this, h2⟩

/-- The claim's canonical bytes determine every field. -/
theorem resolution_claim_ccb_injective (cls schema : Nat) (c₁ c₂ : ResolutionClaim)
    (p₁ : c₁.position < 256^8) (p₂ : c₂.position < 256^8)
    (h : c₁.ccb cls schema = c₂.ccb cls schema) : c₁ = c₂ := by
  simp only [ResolutionClaim.ccb, List.append_assoc] at h
  obtain ⟨_, h⟩ := List.append_inj h (by simp [be_width])
  obtain ⟨_, h⟩ := List.append_inj h (by simp [be_width])
  obtain ⟨g, h⟩ := wire_head h
  obtain ⟨d, h⟩ := wire_head h
  obtain ⟨pos, h⟩ := be_head p₁ p₂ h
  obtain ⟨f, h⟩ := wire_head h
  obtain ⟨r, v⟩ := wire_head h
  have v' : c₁.void = c₂.void := Subtype.ext v
  cases c₁; cases c₂
  simp only at g d pos f r v'
  subst g d pos f r v'
  rfl

def resolutionClaimSigningInput (cls schema : Nat) (c : ResolutionClaim) (alg : Nat)
    (pk : Bytes) (att : Wire 32) : Bytes :=
  resolutionClaimInput (c.ccb cls schema) alg pk att

/-- The signed resolution-claim preimage determines the claim, the algorithm,
    the claimant key and AttA. -/
theorem resolution_claim_signing_injective (cls schema : Nat) (c₁ c₂ : ResolutionClaim)
    (alg₁ alg₂ : Nat) (pk₁ pk₂ : Bytes) (att₁ att₂ : Wire 32)
    (p₁ : c₁.position < 256^8) (p₂ : c₂.position < 256^8)
    (a₁ : alg₁ < 256^2) (a₂ : alg₂ < 256^2)
    (h : resolutionClaimSigningInput cls schema c₁ alg₁ pk₁ att₁ =
      resolutionClaimSigningInput cls schema c₂ alg₂ pk₂ att₂) :
    c₁ = c₂ ∧ alg₁ = alg₂ ∧ pk₁ = pk₂ ∧ att₁ = att₂ := by
  have body := List.append_cancel_left h
  simp only [List.append_assoc] at body
  obtain ⟨hc, rest⟩ := List.append_inj body (by
    rw [resolution_claim_ccb_width, resolution_claim_ccb_width])
  have hc' : c₁.ccb cls schema = c₂.ccb cls schema := by
    simpa only [List.append_assoc] using hc
  obtain ⟨ha, rest⟩ := be_head a₁ a₂ rest
  obtain ⟨_, rest⟩ := List.append_inj rest (by simp [be_width])
  have lens := congrArg List.length rest
  simp only [List.length_append, att₁.property, att₂.property] at lens
  obtain ⟨hpk, hatt⟩ := List.append_inj rest (by omega)
  exact ⟨resolution_claim_ccb_injective cls schema c₁ c₂ p₁ p₂ hc', ha, hpk, Subtype.ext hatt⟩

#print axioms tagged_injective
#print axioms signing_tags_nul_free
#print axioms signing_tags_distinct
#print axioms signing_domain_separation
#print axioms escrow_statement_injective
#print axioms connect_signing_injective
#print axioms resolution_claim_ccb_injective
#print axioms resolution_claim_signing_injective
end DSM.Sphincs
