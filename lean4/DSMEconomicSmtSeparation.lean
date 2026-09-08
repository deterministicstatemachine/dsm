/-
  DSM Economic SMT Domain Separation — self-contained Lean 4 (no Mathlib)

  Discharges the non-aliasing obligations named in amendment 2c-C2 ruling G for
  the `R_econ` economic sparse Merkle tree — a THIRD tree, neither the
  relationship SMT nor the device SMT, which no existing Lean or TLA module
  covered.

  What is proved:
    1. The tagged encoder `H_dom(T, m) = BLAKE3(T ‖ 0x00 ‖ m)` admits exactly
       one (tag, message) split when T is NUL-free — for ARBITRARY m.
    2. Each economic key's INPUT ENCODING is injective at the byte layer, from
       fixed-width fields alone.
    3. The eight economic domains are pairwise non-aliasing.
    4. ABSENT_LEAF is not a populated leaf commitment.
    5. Independently keyed economic leaves do not interfere, at map, tree and
       root level, with anti-vacuity witnesses.
    6. Qualifying quorums intersect when 2q > n, and canonical_quorum(3) = 2.

  ── ON NAMING: THIS IS NOT "PREFIX-FREEDOM" ─────────────────────────────────
  The delimiter gives INJECTIVITY IN (tag, message) and hence DISJOINT PREIMAGE
  SPACES for distinct tags. It does not give prefix-freedom, in either
  direction: `DSM/x‖00‖a` IS a prefix of `DSM/x‖00‖ab`, and NUL-freedom does not
  make the tag strings prefix-free either — `DSM/foo` and `DSM/foo/bar` are both
  NUL-free and one is a prefix of the other. Literal tag-string prefix-freedom
  is a SEPARATE hygiene property, enforced in Rust by
  `no_domain_tag_is_a_prefix_of_another_as_the_hasher_sees_it`. Keep the two
  named apart.

  ── PROVED vs ASSUMED — read this before quoting any theorem ─────────────────
  §1-§2 are theorems about REAL byte lists and REAL tag literals. They assume
  nothing.

  §3-§10 are theorems about a SYMBOLIC model: `Digest` is the free term algebra
  over the tagged encoder, so distinct preimages give distinct digests BY
  CONSTRUCTION. That is the abstraction ruling G explicitly asks for — "stated
  under the symbolic abstraction, not as theorems about BLAKE3" — and it is the
  only assumption those sections make. It does not appear in `#print axioms`
  because it is structural, so it is stated here instead. A reader who quotes
  `econ_balance_key_injective` as a fact about BLAKE3 is misquoting it.

  §11 is the bridge, and the only place cryptography appears. Its assumptions
  are LOCAL to the preimages each statement is about, and deliberately SPLIT:

      digest_width      definitional; PROVED (encodeDigs_length), not assumed
      h_collision_xy    for the CONCRETE preimages x, y of a statement:
                            x ≠ y → H(x) ≠ H(y)
      h_not_absent_x    for a CONCRETE populated preimage x:  H(x) ≠ 0^256

  Neither hash hypothesis is a global claim. A universal "distinct canonical
  preimages produce distinct 256-bit outputs" would be FALSE, not merely
  unproven: over an unbounded input space and a 256-bit codomain, collisions
  necessarily exist. And "no populated economic preimage produces 0^256" is not
  implied by preimage resistance, which says only that FINDING one is
  computationally infeasible.

      Concrete interpretation. An adversary violating h_collision_xy supplies a
      collision for the specific canonical economic preimages under
      consideration. An adversary violating h_not_absent_x supplies a populated
      economic preimage whose digest is the reserved zero sentinel. DSM's
      concrete security rests on the computational infeasibility of producing
      such witnesses — NOT on the mathematical non-existence of BLAKE3
      collisions or zero-digest preimages.

  `global_injectivity_would_smuggle_in_the_zero_claim` exhibits why the two are
  kept apart: a single global injectivity hypothesis would also prove the
  zero-sentinel exclusion, which is a preimage claim wearing a
  collision-resistance name.

  This module contains zero `axiom` and zero `opaque` declarations.

  ── THREE CORRECTIONS TO RULING G AS WRITTEN ────────────────────────────────
  * Obligation 4 says "node/root domains cannot alias leaf domains". There is no
    separate ROOT domain: `empty_economic_root() = default_node(256)` and every
    non-empty root is an `econ_node` output, so node and root are ONE domain.
    `root_lives_in_the_node_domain` proves that rather than asserting it; a
    model separating them would prove something false.
  * The leaf-state domain (`DSM/economic-leaf-state/v1`) is absent from ruling
    G's list but is step 2 of the frozen five-step chain, so it is included in
    the disjointness set here.
  * Obligation 1's input domain is not closed for the settlement-receipt and
    consumed-source keys: `receipt_id` is itself a domain hash
    (economic/state.rs:168) and `source_id` comes from six SourceId domains.
    Injectivity is stated RELATIVE TO the declared 32-byte inputs; the nested
    derivations are a recorded dependency, not part of this chain.

  Paper anchoring: docs/papers/amendment-2c-c2-verification-substrate.md,
  ruling G and "The economic SMT — frozen".

  Code correspondence:
    - encoder, the single 0x00           crypto/blake3.rs:167-177
    - NUL-free-by-type tag               crypto/domain.rs:78, 102-118
    - the eight tag literals             common/domain_tags/dsm/misc/economic.rs
    - the four leaf keys                 economic/keys.rs:40-91
    - ABSENT_LEAF, econ_leaf/econ_node   economic/tree.rs:41-60
    - default_node, empty_economic_root  economic/tree.rs:75-96
    - root_from_path                     economic/tree.rs:104-119
    - economic_leaf_value                economic/state.rs:271-277
    - K_root                             economic/register.rs:76-86
    - canonical_quorum                   economic/cell_observation.rs:70-75
    - SOFI_BETA_MEMBERS / _QUORUM        dlv/beta_storage_profile.rs:47-50

  A source-tree note. `economic/tree.rs:29` states "Since every present leaf is
  a BLAKE3 output, all-zero is unreachable as a present value." The conclusion
  does not follow from the premise — being a BLAKE3 output is exactly what makes
  all-zero POSSIBLE; what makes it unreachable in practice is preimage
  resistance. The construction is fine; the comment asserts a theorem where an
  assumption belongs, the same failure mode as peer_lineage.rs:61-62 which
  2c-C2 already records.

  What this module deliberately does NOT cover:
    - the 256-level get_bit descent and the leaf-to-root sibling ordering. Those
      are ruling-D conformance-vector facts, not non-aliasing facts, and
      modelling them here would smuggle an encoding claim into a separation
      proof. The fold is proved over a path of arbitrary length instead.
    - authenticated retrieval (the re-hash-on-fetch obligation), a consume-path
      property of peer_lineage.rs and not a property of the tree.

  Run: `lean -DwarningAsError=true DSMEconomicSmtSeparation.lean`
-/

-- §1 BYTE LAYER
def ascii (s : String) : List UInt8 := s.data.map (fun c => UInt8.ofNat c.toNat)

def NulFree (bs : List UInt8) : Prop := ∀ b ∈ bs, b ≠ 0

instance (bs : List UInt8) : Decidable (NulFree bs) := by
  unfold NulFree; infer_instance

def taggedEncode (tag msg : List UInt8) : List UInt8 := tag ++ (0 :: msg)

theorem tagged_encoding_unique_split :
    ∀ (t₁ m₁ t₂ m₂ : List UInt8),
      NulFree t₁ → NulFree t₂ →
      taggedEncode t₁ m₁ = taggedEncode t₂ m₂ → t₁ = t₂ ∧ m₁ = m₂ := by
  intro t₁
  induction t₁ with
  | nil =>
    intro m₁ t₂ m₂ _h₁ h₂ heq
    cases t₂ with
    | nil => simp only [taggedEncode, List.nil_append, List.cons.injEq, true_and] at heq
             exact ⟨rfl, heq⟩
    | cons b t =>
      exfalso
      simp only [taggedEncode, List.nil_append, List.cons_append, List.cons.injEq] at heq
      exact (h₂ b (by simp)) heq.1.symm
  | cons a t ih =>
    intro m₁ t₂ m₂ h₁ h₂ heq
    cases t₂ with
    | nil =>
      exfalso
      simp only [taggedEncode, List.nil_append, List.cons_append, List.cons.injEq] at heq
      exact (h₁ a (by simp)) heq.1
    | cons b t2 =>
      simp only [taggedEncode, List.cons_append, List.cons.injEq] at heq
      obtain ⟨hab, hrest⟩ := heq
      have hnf₁ : NulFree t := fun x hx => h₁ x (by simp [hx])
      have hnf₂ : NulFree t2 := fun x hx => h₂ x (by simp [hx])
      obtain ⟨ht, hm⟩ := ih m₁ t2 m₂ hnf₁ hnf₂ hrest
      exact ⟨by simp [hab, ht], hm⟩

theorem distinct_tags_have_disjoint_preimages
    (t₁ m₁ t₂ m₂ : List UInt8) (h₁ : NulFree t₁) (h₂ : NulFree t₂) (hne : t₁ ≠ t₂) :
    taggedEncode t₁ m₁ ≠ taggedEncode t₂ m₂ := by
  intro heq
  exact hne (tagged_encoding_unique_split t₁ m₁ t₂ m₂ h₁ h₂ heq).1

theorem nul_freedom_is_load_bearing :
    ∃ (t₁ m₁ t₂ m₂ : List UInt8),
      taggedEncode t₁ m₁ = taggedEncode t₂ m₂ ∧ t₁ ≠ t₂ :=
  ⟨[], [0], [0], [], by decide, by decide⟩

-- §2 FIXED-WIDTH FIELD CONCATENATION
theorem fixed_width_pair_injective
    (a₁ b₁ a₂ b₂ : List UInt8) (hw : a₁.length = a₂.length)
    (h : a₁ ++ b₁ = a₂ ++ b₂) : a₁ = a₂ ∧ b₁ = b₂ :=
  List.append_inj h hw

theorem fixed_width_triple_injective
    (a₁ b₁ c₁ a₂ b₂ c₂ : List UInt8)
    (ha : a₁.length = a₂.length) (hb : b₁.length = b₂.length)
    (h : a₁ ++ b₁ ++ c₁ = a₂ ++ b₂ ++ c₂) :
    a₁ = a₂ ∧ b₁ = b₂ ∧ c₁ = c₂ := by
  simp only [List.append_assoc] at h
  obtain ⟨h1, hrest⟩ := List.append_inj h ha
  obtain ⟨h2, h3⟩ := List.append_inj hrest hb
  exact ⟨h1, h2, h3⟩

theorem fixed_width_quad_injective
    (a₁ b₁ c₁ d₁ a₂ b₂ c₂ d₂ : List UInt8)
    (ha : a₁.length = a₂.length) (hb : b₁.length = b₂.length)
    (hc : c₁.length = c₂.length)
    (h : a₁ ++ b₁ ++ c₁ ++ d₁ = a₂ ++ b₂ ++ c₂ ++ d₂) :
    a₁ = a₂ ∧ b₁ = b₂ ∧ c₁ = c₂ ∧ d₁ = d₂ := by
  simp only [List.append_assoc] at h
  obtain ⟨h1, hrest⟩ := List.append_inj h ha
  obtain ⟨h2, hrest2⟩ := List.append_inj hrest hb
  obtain ⟨h3, h4⟩ := List.append_inj hrest2 hc
  exact ⟨h1, h2, h3, h4⟩

-- The four economic leaf-key input encodings, at the BYTE layer.
def encodeBalanceKeyInputs (g d pc : List UInt8) : List UInt8 := g ++ d ++ pc
def encodeVaultReserveKeyInputs (g d v pc : List UInt8) : List UInt8 := g ++ d ++ v ++ pc
def encodeSettlementReceiptKeyInputs (g d v r : List UInt8) : List UInt8 := g ++ d ++ v ++ r
def encodeConsumedSourceKeyInputs (g d s : List UInt8) : List UInt8 := g ++ d ++ s

def Is32 (x : List UInt8) : Prop := x.length = 32

theorem encode_balance_key_inputs_injective
    (g₁ d₁ p₁ g₂ d₂ p₂ : List UInt8)
    (_h1 : Is32 g₁) (_h2 : Is32 d₁) (h3 : Is32 g₂) (h4 : Is32 d₂)
    (heq : encodeBalanceKeyInputs g₁ d₁ p₁ = encodeBalanceKeyInputs g₂ d₂ p₂) :
    g₁ = g₂ ∧ d₁ = d₂ ∧ p₁ = p₂ := by
  unfold encodeBalanceKeyInputs at heq
  exact fixed_width_triple_injective g₁ d₁ p₁ g₂ d₂ p₂
    (by rw [_h1, h3]) (by rw [_h2, h4]) heq

theorem encode_vault_reserve_key_inputs_injective
    (g₁ d₁ v₁ p₁ g₂ d₂ v₂ p₂ : List UInt8)
    (a1 : Is32 g₁) (a2 : Is32 d₁) (a3 : Is32 v₁)
    (b1 : Is32 g₂) (b2 : Is32 d₂) (b3 : Is32 v₂)
    (heq : encodeVaultReserveKeyInputs g₁ d₁ v₁ p₁ = encodeVaultReserveKeyInputs g₂ d₂ v₂ p₂) :
    g₁ = g₂ ∧ d₁ = d₂ ∧ v₁ = v₂ ∧ p₁ = p₂ := by
  unfold encodeVaultReserveKeyInputs at heq
  exact fixed_width_quad_injective g₁ d₁ v₁ p₁ g₂ d₂ v₂ p₂
    (by rw [a1, b1]) (by rw [a2, b2]) (by rw [a3, b3]) heq

theorem encode_settlement_receipt_key_inputs_injective
    (g₁ d₁ v₁ r₁ g₂ d₂ v₂ r₂ : List UInt8)
    (a1 : Is32 g₁) (a2 : Is32 d₁) (a3 : Is32 v₁)
    (b1 : Is32 g₂) (b2 : Is32 d₂) (b3 : Is32 v₂)
    (heq : encodeSettlementReceiptKeyInputs g₁ d₁ v₁ r₁
         = encodeSettlementReceiptKeyInputs g₂ d₂ v₂ r₂) :
    g₁ = g₂ ∧ d₁ = d₂ ∧ v₁ = v₂ ∧ r₁ = r₂ := by
  unfold encodeSettlementReceiptKeyInputs at heq
  exact fixed_width_quad_injective g₁ d₁ v₁ r₁ g₂ d₂ v₂ r₂
    (by rw [a1, b1]) (by rw [a2, b2]) (by rw [a3, b3]) heq

theorem encode_consumed_source_key_inputs_injective
    (g₁ d₁ s₁ g₂ d₂ s₂ : List UInt8)
    (a1 : Is32 g₁) (a2 : Is32 d₁) (b1 : Is32 g₂) (b2 : Is32 d₂)
    (heq : encodeConsumedSourceKeyInputs g₁ d₁ s₁ = encodeConsumedSourceKeyInputs g₂ d₂ s₂) :
    g₁ = g₂ ∧ d₁ = d₂ ∧ s₁ = s₂ := by
  unfold encodeConsumedSourceKeyInputs at heq
  exact fixed_width_triple_injective g₁ d₁ s₁ g₂ d₂ s₂
    (by rw [a1, b1]) (by rw [a2, b2]) heq

-- §3 THE EIGHT FROZEN DOMAINS
inductive EconDomain where
  | balanceKey | vaultReserveKey | settlementReceiptKey | consumedSourceKey
  | smtLeaf | smtNode | leafState | rootRegisterKey
deriving DecidableEq, Repr

def EconDomain.tag : EconDomain → List UInt8
  | .balanceKey           => ascii "DSM/economic-balance-key/v1"
  | .vaultReserveKey      => ascii "DSM/economic-vault-reserve-key/v1"
  | .settlementReceiptKey => ascii "DSM/economic-settlement-receipt-key/v1"
  | .consumedSourceKey    => ascii "DSM/economic-consumed-source-key/v1"
  | .smtLeaf              => ascii "DSM/economic-smt-leaf/v1"
  | .smtNode              => ascii "DSM/economic-smt-node/v1"
  | .leafState            => ascii "DSM/economic-leaf-state/v1"
  | .rootRegisterKey      => ascii "DSM/trader-economic-root-register-key/v1"

theorem econ_domain_tag_injective (D E : EconDomain) (h : D.tag = E.tag) : D = E := by
  cases D <;> cases E <;> first | rfl | (exact absurd h (by decide))

theorem econ_domain_tag_nul_free (D : EconDomain) : NulFree D.tag := by
  cases D <;> decide

def EconDomain.all : List EconDomain :=
  [.balanceKey, .vaultReserveKey, .settlementReceiptKey, .consumedSourceKey,
   .smtLeaf, .smtNode, .leafState, .rootRegisterKey]

theorem econ_domain_table_complete (D : EconDomain) : D ∈ EconDomain.all := by
  cases D <;> decide

theorem econ_domain_count : EconDomain.all.length = 8 := rfl

-- §4 THE SYMBOLIC DIGEST ALGEBRA
inductive Digest where
  | absent : Digest
  | hashed (tag : List UInt8) (digs : List Digest)
           (pos : Option Nat) (tail : List UInt8) : Digest

def mkHash (D : EconDomain) (ds : List Digest) (p : Option Nat) (s : List UInt8) : Digest :=
  .hashed D.tag ds p s

def absentLeaf : Digest := .absent

def econBalanceKey (g d pc : Digest) : Digest := mkHash .balanceKey [g, d, pc] none []
def econVaultReserveKey (g d v pc : Digest) : Digest :=
  mkHash .vaultReserveKey [g, d, v, pc] none []
def econSettlementRcptKey (g d v r : Digest) : Digest :=
  mkHash .settlementReceiptKey [g, d, v, r] none []
def econConsumedSourceKey (g d s : Digest) : Digest := mkHash .consumedSourceKey [g, d, s] none []
def econLeaf (k v : Digest) : Digest := mkHash .smtLeaf [k, v] none []
def econNode (l r : Digest) : Digest := mkHash .smtNode [l, r] none []
def econLeafValue (ccb : List UInt8) : Digest := mkHash .leafState [] none ccb
def econRootRegisterKey (g d : Digest) (p : Nat) : Digest :=
  mkHash .rootRegisterKey [g, d] (some p) []

def defaultNode : Nat → Digest
  | 0     => .absent
  | h + 1 => econNode (defaultNode h) (defaultNode h)

def economicSmtHeight : Nat := 256
def emptyEconomicRoot : Digest := defaultNode economicSmtHeight

def leafNode (k : Digest) : Option Digest → Digest
  | none   => absentLeaf
  | some v => econLeaf k v

-- §5 OBLIGATION 1 (symbolic layer): per-derivation injectivity
theorem econ_balance_key_injective (g d pc g' d' pc' : Digest)
    (h : econBalanceKey g d pc = econBalanceKey g' d' pc') :
    g = g' ∧ d = d' ∧ pc = pc' := by
  unfold econBalanceKey mkHash at h
  injection h with _ hargs _ _
  simp only [List.cons.injEq, and_true] at hargs
  exact ⟨hargs.1, hargs.2.1, hargs.2.2⟩

theorem econ_root_register_key_injective (g d g' d' : Digest) (p q : Nat)
    (h : econRootRegisterKey g d p = econRootRegisterKey g' d' q) :
    g = g' ∧ d = d' ∧ p = q := by
  unfold econRootRegisterKey mkHash at h
  injection h with _ hargs hpos _
  simp only [List.cons.injEq, and_true] at hargs
  simp only [Option.some.injEq] at hpos
  exact ⟨hargs.1, hargs.2, hpos⟩

theorem econ_leaf_injective (k v k' v' : Digest) (h : econLeaf k v = econLeaf k' v') :
    k = k' ∧ v = v' := by
  unfold econLeaf mkHash at h
  injection h with _ hargs _ _
  simp only [List.cons.injEq, and_true] at hargs
  exact hargs

theorem econ_node_injective (l r l' r' : Digest) (h : econNode l r = econNode l' r') :
    l = l' ∧ r = r' := by
  unfold econNode mkHash at h
  injection h with _ hargs _ _
  simp only [List.cons.injEq, and_true] at hargs
  exact hargs

theorem econ_leaf_value_injective (a b : List UInt8)
    (h : econLeafValue a = econLeafValue b) : a = b := by
  unfold econLeafValue mkHash at h
  injection h with _ _ _ htail

-- §6 OBLIGATIONS 2, 3, 4: cross-domain non-aliasing
theorem econ_domains_pairwise_disjoint
    (D E : EconDomain) (hDE : D ≠ E)
    (a b : List Digest) (p q : Option Nat) (s t : List UInt8) :
    mkHash D a p s ≠ mkHash E b q t := by
  intro h
  unfold mkHash at h
  injection h with ht _ _ _
  exact hDE (econ_domain_tag_injective D E ht)

theorem k_root_aliases_no_leaf_key_domain
    (E : EconDomain) (hE : E ≠ EconDomain.rootRegisterKey)
    (g d : Digest) (p : Nat) (b : List Digest) (q : Option Nat) (t : List UInt8) :
    econRootRegisterKey g d p ≠ mkHash E b q t := by
  unfold econRootRegisterKey
  intro h
  exact econ_domains_pairwise_disjoint .rootRegisterKey E (fun hc => hE hc.symm) _ _ _ _ _ _ h

theorem econ_leaf_never_a_node (k v l r : Digest) : econLeaf k v ≠ econNode l r :=
  econ_domains_pairwise_disjoint .smtLeaf .smtNode (by decide) _ _ _ _ _ _

theorem econ_leaf_value_never_a_leaf (ccb : List UInt8) (k v : Digest) :
    econLeafValue ccb ≠ econLeaf k v :=
  econ_domains_pairwise_disjoint .leafState .smtLeaf (by decide) _ _ _ _ _ _

theorem econ_leaf_value_never_a_node (ccb : List UInt8) (l r : Digest) :
    econLeafValue ccb ≠ econNode l r :=
  econ_domains_pairwise_disjoint .leafState .smtNode (by decide) _ _ _ _ _ _

-- OBLIGATION 4, AS CORRECTED. There is no separate root domain to separate
-- from: every root at positive height IS a node digest. A model that tried to
-- separate them would be proving something false.
theorem root_lives_in_the_node_domain (h : Nat) :
    ∃ l r, defaultNode (h + 1) = econNode l r :=
  ⟨defaultNode h, defaultNode h, rfl⟩

theorem empty_economic_root_is_a_node : ∃ l r, emptyEconomicRoot = econNode l r :=
  root_lives_in_the_node_domain 255

-- §7 OBLIGATION 5: ABSENT_LEAF, symbolic form
theorem absent_leaf_is_not_a_hash (t : List UInt8) (ds : List Digest)
    (p : Option Nat) (s : List UInt8) : absentLeaf ≠ Digest.hashed t ds p s := by
  intro h; exact Digest.noConfusion h

theorem absent_leaf_is_not_a_populated_leaf (k v : Digest) : absentLeaf ≠ econLeaf k v :=
  absent_leaf_is_not_a_hash _ _ _ _

theorem absent_leaf_is_not_a_node (l r : Digest) : absentLeaf ≠ econNode l r :=
  absent_leaf_is_not_a_hash _ _ _ _

theorem default_node_is_never_a_populated_leaf (h : Nat) (k v : Digest) :
    defaultNode h ≠ econLeaf k v := by
  cases h with
  | zero => exact absent_leaf_is_not_a_populated_leaf k v
  | succ n => exact econ_domains_pairwise_disjoint .smtNode .smtLeaf (by decide) _ _ _ _ _ _

theorem leaf_node_absent_iff_empty (k : Digest) (o : Option Digest) :
    leafNode k o = absentLeaf ↔ o = none := by
  cases o with
  | none => simp only [leafNode]
  | some v =>
    simp only [leafNode, reduceCtorEq, iff_false]
    exact fun h => absent_leaf_is_not_a_populated_leaf k v h.symm

theorem default_node_zero_is_absent : defaultNode 0 = absentLeaf := rfl
theorem node_of_two_absent_is_default_one : econNode absentLeaf absentLeaf = defaultNode 1 := rfl

-- §8 THE TREE FOLD
def foldStep (cur : Digest) (step : Bool × Digest) : Digest :=
  if step.1 then econNode step.2 cur else econNode cur step.2

def foldPath (leaf : Digest) : List (Bool × Digest) → Digest
  | []        => leaf
  | s :: rest => foldPath (foldStep leaf s) rest

theorem foldStep_injective (c c' : Digest) (s t : Bool × Digest)
    (hb : s.1 = t.1) (h : foldStep c s = foldStep c' t) : c = c' ∧ s.2 = t.2 := by
  obtain ⟨b, d⟩ := s
  obtain ⟨b2, d2⟩ := t
  simp only at hb
  subst hb
  unfold foldStep at h
  cases b <;>
    · simp only [Bool.false_eq_true, if_false, if_true] at h
      obtain ⟨h1, h2⟩ := econ_node_injective _ _ _ _ h
      exact ⟨by first | exact h1 | exact h2, by first | exact h2 | exact h1⟩

/-- TREE LEVEL. The root, together with the direction bits, determines BOTH the
    leaf node and every off-path sibling. Two readings:
      * a proof for one leaf cannot be replayed at another position;
      * off-path nodes are exactly the siblings, so "nodes not on path(k) are
        unchanged" is the statement that they are recoverable from the root. -/
theorem fold_path_injective :
    ∀ (p q : List (Bool × Digest)) (a b : Digest),
      p.map Prod.fst = q.map Prod.fst →
      foldPath a p = foldPath b q → a = b ∧ p = q := by
  intro p
  induction p with
  | nil =>
    intro q a b hbits heq
    cases q with
    | nil => exact ⟨heq, rfl⟩
    | cons _ _ => exact absurd hbits (by simp)
  | cons s rest ih =>
    intro q a b hbits heq
    cases q with
    | nil => exact absurd hbits (by simp)
    | cons t qrest =>
      simp only [List.map_cons, List.cons.injEq] at hbits
      simp only [foldPath] at heq
      obtain ⟨hacc, hrest⟩ := ih qrest (foldStep a s) (foldStep b t) hbits.2 heq
      obtain ⟨hab, hsib⟩ := foldStep_injective a b s t hbits.1 hacc
      refine ⟨hab, ?_⟩
      have hst : s = t := Prod.ext hbits.1 hsib
      rw [hst, hrest]

/-- CANONICALITY: the same leaf and the same off-path siblings give the same
    root. Congruence, stated so the composition is on the record. -/
theorem same_leaf_and_path_same_root (a : Digest) (p : List (Bool × Digest)) :
    foldPath a p = foldPath a p := rfl

/-- ANTI-VACUITY (tree level): a valid update CHANGES the resulting root. -/
theorem distinct_leaves_give_distinct_roots
    (a b : Digest) (p : List (Bool × Digest)) (hne : a ≠ b) :
    foldPath a p ≠ foldPath b p := by
  intro h
  exact hne (fold_path_injective p p a b rfl h).1

theorem econ_node_argument_order_matters (l r : Digest) (hne : l ≠ r) :
    econNode l r ≠ econNode r l := by
  intro h
  exact hne (econ_node_injective _ _ _ _ h).1

theorem econ_leaf_binds_key_and_value (k v : Digest) (hne : k ≠ v) :
    econLeaf k v ≠ econLeaf v k := by
  intro h
  exact hne (econ_leaf_injective _ _ _ _ h).1

theorem fold_path_inhabited :
    ∃ (a b : Digest) (p : List (Bool × Digest)), a ≠ b ∧ foldPath a p ≠ foldPath b p := by
  refine ⟨absentLeaf, econNode absentLeaf absentLeaf, [], ?_, ?_⟩
  · exact absent_leaf_is_not_a_node _ _
  · simp only [foldPath]
    exact absent_leaf_is_not_a_node _ _

-- §9 OBLIGATION 6: NON-INTERFERENCE
abbrev Cell := Option Digest
abbrev EconStore := Digest → Cell

structure IsUpdate (s : EconStore) (k : Digest) (v : Cell) (s' : EconStore) : Prop where
  hit   : s' k = v
  frame : ∀ k', k' ≠ k → s' k' = s k'

theorem update_frame {s s' : EconStore} {k : Digest} {v : Cell}
    (hu : IsUpdate s k v s') (k' : Digest) (hne : k' ≠ k) : s' k' = s k' :=
  hu.frame k' hne

theorem update_hits_its_own_key {s s' : EconStore} {k : Digest} {v : Cell}
    (hu : IsUpdate s k v s') : s' k = v := hu.hit

/-- A write to a BALANCE leaf cannot change what is observed at ANY
    vault-reserve leaf, for any identities and any inputs. This is where the
    cross-domain disjointness of §6 becomes operational. -/
theorem class_non_interference
    {s s' : EconStore} {v : Cell} {g d pc g' d' vid pc' : Digest}
    (hu : IsUpdate s (econBalanceKey g d pc) v s') :
    s' (econVaultReserveKey g' d' vid pc') = s (econVaultReserveKey g' d' vid pc') := by
  refine update_frame hu _ ?_
  unfold econVaultReserveKey econBalanceKey
  exact econ_domains_pairwise_disjoint .vaultReserveKey .balanceKey (by decide) _ _ _ _ _ _

/-- The general form: a write in domain D never disturbs an observation in any
    other domain E. One statement, every cross-domain pair. -/
theorem cross_domain_non_interference
    {s s' : EconStore} {v : Cell}
    (D E : EconDomain) (hDE : E ≠ D)
    (a b : List Digest) (p q : Option Nat) (x y : List UInt8)
    (hu : IsUpdate s (mkHash D a p x) v s') :
    s' (mkHash E b q y) = s (mkHash E b q y) :=
  update_frame hu _ (econ_domains_pairwise_disjoint E D hDE _ _ _ _ _ _)

/-- Within one class, distinct declared inputs are distinct positions. -/
theorem intra_class_non_interference
    {s s' : EconStore} {v : Cell} {g d pc pc' : Digest}
    (hpc : pc' ≠ pc)
    (hu : IsUpdate s (econBalanceKey g d pc) v s') :
    s' (econBalanceKey g d pc') = s (econBalanceKey g d pc') := by
  refine update_frame hu _ ?_
  intro hc
  exact hpc (econ_balance_key_injective _ _ _ _ _ _ hc).2.2

/-- ROOT LEVEL. After an update elsewhere the root changes, but the value
    authenticated at a position does not: for a given root and direction bits,
    the only leaf node folding to it is the true one. -/
theorem authenticated_value_unaffected
    (bits : List Bool) (ln ln' : Digest) (sibs sibs' : List (Bool × Digest))
    (hb : sibs.map Prod.fst = bits) (hb' : sibs'.map Prod.fst = bits)
    (hroot : foldPath ln sibs = foldPath ln' sibs') : ln = ln' := by
  refine (fold_path_injective sibs sibs' ln ln' ?_ hroot).1
  rw [hb, hb']

def emptyStore : EconStore := fun _ => none

def witnessStore : EconStore := fun k =>
  match k with
  | .absent         => some .absent
  | .hashed _ _ _ _ => none

theorem update_inhabited :
    ∃ (s s' : EconStore) (k : Digest) (v : Cell), IsUpdate s k v s' ∧ s' ≠ s := by
  refine ⟨emptyStore, witnessStore, Digest.absent, some Digest.absent, ⟨rfl, ?_⟩, ?_⟩
  · intro k2 hne
    cases k2 with
    | absent => exact absurd rfl hne
    | hashed _ _ _ _ => rfl
  · intro hc
    have := congrFun hc Digest.absent
    exact Option.noConfusion this

/-- TEETH: the key-distinctness hypothesis in `update_frame` is load-bearing.
    A frame condition that survives deleting it is the vacuity this module was
    written to avoid — see DSMNonInterference.lean's repaired
    `operation_locality`. -/
theorem update_frame_needs_key_distinctness :
    ∃ (s s' : EconStore) (k : Digest) (v : Cell), IsUpdate s k v s' ∧ s' k ≠ s k := by
  refine ⟨emptyStore, witnessStore, Digest.absent, some Digest.absent, ⟨rfl, ?_⟩, ?_⟩
  · intro k2 hne
    cases k2 with
    | absent => exact absurd rfl hne
    | hashed _ _ _ _ => rfl
  · intro hc
    exact Option.noConfusion hc

-- §10 OBLIGATION 7: QUORUM INTERSECTION
theorem count_inclusion_exclusion {α : Type} (l : List α) (A B : α → Bool) :
    (l.filter (fun x => A x && B x)).length + (l.filter (fun x => A x || B x)).length
      = (l.filter A).length + (l.filter B).length := by
  induction l with
  | nil => rfl
  | cons a t ih => cases hA : A a <;> cases hB : B a <;> simp [hA, hB] <;> omega

/-- The positional pigeonhole. `A` and `B` are PREDICATES over the member
    universe, not independently chosen sublists, so neither can inflate its own
    cardinality and the proof needs no `Nodup`.

    `_hnodup` is `_`-prefixed by the house convention for a hypothesis that is
    not load-bearing IN THE PROOF — and it is carried anyway, because it is what
    licenses reading `S.length` as *the number of distinct storage members*.
    Without it the lemma stays true and `n` stops denoting membership, which is
    the quantity obligation 7 is about. -/
theorem quorum_intersection {α : Type} (members : List α) (A B : α → Bool)
    (_hnodup : members.Nodup)
    (h : members.length < (members.filter A).length + (members.filter B).length) :
    ∃ x, x ∈ members ∧ A x = true ∧ B x = true := by
  have hie := count_inclusion_exclusion members A B
  have hub := List.length_filter_le (fun x => A x || B x) members
  have hpos : 0 < (members.filter (fun x => A x && B x)).length := by omega
  obtain ⟨x, hx⟩ := List.exists_mem_of_length_pos hpos
  rw [List.mem_filter] at hx
  exact ⟨x, hx.1, by simpa using hx.2⟩

/-- THE OBLIGATION, over QUALIFYING quorums: response sets satisfying AT LEAST
    `q`, which is what the protocol actually deals with. -/
theorem qualifying_quorums_intersect {α : Type}
    (members : List α) (n q : Nat) (A B : α → Bool)
    (hnodup : members.Nodup)
    (hn : members.length = n)
    (hA : q ≤ (members.filter A).length)
    (hB : q ≤ (members.filter B).length)
    (h2q : n < 2 * q) :
    ∃ x, x ∈ members ∧ A x = true ∧ B x = true := by
  refine quorum_intersection members A B hnodup ?_
  omega

/-- The exact-`q` form, kept as the underlying lemma. -/
theorem quorum_intersection_of_two_q {α : Type}
    (members : List α) (n q : Nat) (A B : α → Bool)
    (hnodup : members.Nodup)
    (hn : members.length = n)
    (hA : (members.filter A).length = q)
    (hB : (members.filter B).length = q)
    (h2q : n < 2 * q) :
    ∃ x, x ∈ members ∧ A x = true ∧ B x = true :=
  qualifying_quorums_intersect members n q A B hnodup hn (by omega) (by omega) h2q

/-- `canonical_quorum(n) = n/2 + 1` — economic/cell_observation.rs:70-75.
    DERIVED, never chosen. -/
def canonicalQuorum (n : Nat) : Nat := n / 2 + 1

theorem canonical_quorum_intersects (n : Nat) : n < 2 * canonicalQuorum n := by
  unfold canonicalQuorum; omega

/-- ...and it is the SMALLEST such threshold, which is why
    `require_canonical_quorum` demands exact equality in both directions. -/
theorem canonical_quorum_is_minimal (n q : Nat) (h : n < 2 * q) : canonicalQuorum n ≤ q := by
  unfold canonicalQuorum; omega

/-- THE BETA COROLLARY. `SOFI_BETA_QUORUM = 2` over `SOFI_BETA_MEMBERS = 3` is
    exactly `canonical_quorum(3)` — an identity, not an arithmetic coincidence.
    Mirrors dlv/beta_storage_profile.rs:152-160. -/
theorem beta_quorum_is_canonical : canonicalQuorum 3 = 2 := rfl

theorem beta_quorums_intersect {α : Type} (members : List α) (A B : α → Bool)
    (hnodup : members.Nodup)
    (hn : members.length = 3)
    (hA : 2 ≤ (members.filter A).length)
    (hB : 2 ≤ (members.filter B).length) :
    ∃ x, x ∈ members ∧ A x = true ∧ B x = true :=
  qualifying_quorums_intersect members 3 2 A B hnodup hn hA hB (by decide)

/-- TEETH: a sub-canonical `q` admits two DISJOINT quorums and therefore two
    winners. n = 4, q = 2 (canonical is 3). The safety failure
    `require_canonical_quorum` exists to refuse. -/
theorem subcanonical_quorum_admits_disjoint_quorums :
    ∃ (members : List Nat) (A B : Nat → Bool) (n q : Nat),
      members.Nodup ∧ members.length = n ∧ (members.filter A).length = q ∧
      (members.filter B).length = q ∧ q < canonicalQuorum n ∧
      ¬ ∃ x, x ∈ members ∧ A x = true ∧ B x = true := by
  refine ⟨[0, 1, 2, 3], (fun x => decide (x < 2)), (fun x => decide (2 ≤ x)), 4, 2, ?_⟩
  refine ⟨by decide, by decide, by decide, by decide, by decide, by decide⟩

/-- TEETH: a zero threshold carries no intersection at all. Reachable, because
    `canonical_quorum(0) = 0` in the Rust and `quorum_for(0) == 0` — the
    "emptiness manufactured from no members at all" the amendment requires
    `observe_cell` to refuse. -/
theorem zero_threshold_carries_no_intersection :
    ¬ ∀ (members : List Nat) (A B : Nat → Bool),
        0 ≤ (members.filter A).length → 0 ≤ (members.filter B).length →
        ∃ x, x ∈ members ∧ A x = true ∧ B x = true := by
  intro h
  obtain ⟨x, hx, _, _⟩ := h [] (fun _ => true) (fun _ => true) (by omega) (by omega)
  exact absurd hx (by simp)

-- §11 ADEQUACY BRIDGE — the only place cryptography appears
def encodeDigs (bytesOf : Digest → List UInt8) : List Digest → List UInt8
  | []      => []
  | d :: ds => bytesOf d ++ encodeDigs bytesOf ds

def encodePos : Option Nat → List UInt8
  | none   => []
  | some n => [UInt8.ofNat (n % 256)]

/-- The exact byte string the encoder consumes for a model digest. -/
def preimageBytes (bytesOf : Digest → List UInt8)
    (D : EconDomain) (ds : List Digest) (p : Option Nat) (s : List UInt8) : List UInt8 :=
  taggedEncode D.tag (encodeDigs bytesOf ds ++ encodePos p ++ s)

/-- `digest_width` is DEFINITIONAL and therefore PROVED here for the encoder's
    own output shape, not assumed: it is what licenses the no-length-prefix
    concatenation the economic derivations rely on. -/
theorem encodeDigs_length (bytesOf : Digest → List UInt8)
    (hwidth : ∀ d, (bytesOf d).length = 32) (ds : List Digest) :
    (encodeDigs bytesOf ds).length = 32 * ds.length := by
  induction ds with
  | nil => rfl
  | cons d t ih =>
    simp only [encodeDigs, List.length_append, List.length_cons, ih, hwidth]
    omega

/-- CROSS-DOMAIN PREIMAGES DIFFER — proved, no cryptographic assumption.
    This is the real content of the bridge: whatever the hash does, the two
    byte strings it is applied to are already distinct. -/
theorem econ_preimages_differ_across_domains
    (bytesOf : Digest → List UInt8)
    (D E : EconDomain) (hDE : D ≠ E)
    (a b : List Digest) (p q : Option Nat) (s t : List UInt8) :
    preimageBytes bytesOf D a p s ≠ preimageBytes bytesOf E b q t := by
  unfold preimageBytes
  refine distinct_tags_have_disjoint_preimages _ _ _ _
    (econ_domain_tag_nul_free D) (econ_domain_tag_nul_free E) ?_
  intro hc
  exact hDE (econ_domain_tag_injective D E hc)

/-- THE BRIDGE, with the collision assumption LOCAL to the two preimages this
    statement is about.
    
    `h_collision_xy` is NOT a global claim that the hash is injective — over an
    unbounded input space and a 256-bit codomain, collisions necessarily EXIST,
    so a universal version would be false rather than merely unproven. It says
    only: for THESE two canonical economic preimages, an adversary who makes
    their digests coincide has supplied a collision for them. -/
theorem econ_digests_differ_across_domains
    (bytesOf : Digest → List UInt8) (H : List UInt8 → Digest)
    (D E : EconDomain) (hDE : D ≠ E)
    (a b : List Digest) (p q : Option Nat) (s t : List UInt8)
    (h_collision_xy :
      preimageBytes bytesOf D a p s ≠ preimageBytes bytesOf E b q t →
      H (preimageBytes bytesOf D a p s) ≠ H (preimageBytes bytesOf E b q t)) :
    H (preimageBytes bytesOf D a p s) ≠ H (preimageBytes bytesOf E b q t) :=
  h_collision_xy (econ_preimages_differ_across_domains bytesOf D E hDE a b p q s t)

/-- OBLIGATION 5 at the byte layer, with its assumption named and LOCAL.

    `h_not_absent_x` is not a consequence of preimage resistance: preimage
    resistance says FINDING such an input is computationally infeasible, not
    that none exists. An adversary violating it supplies a populated economic
    preimage whose digest is the reserved zero sentinel. -/
theorem populated_leaf_is_not_the_zero_sentinel
    (H : List UInt8 → Digest) (zero : Digest) (x : List UInt8)
    (h_not_absent_x : H x ≠ zero) : H x ≠ zero := h_not_absent_x

/-- TEETH — why the two assumptions are kept apart.

    A single global "injective `Digest → bytes`" hypothesis would ALSO prove the
    zero-sentinel exclusion, because `absent` maps to the zero word. That is a
    fixed-target preimage claim smuggled in under a collision-resistance name.
    Exhibited here so the decision to split them is visible rather than
    accidental. -/
theorem global_injectivity_would_smuggle_in_the_zero_claim
    (bytesOf : Digest → List UInt8)
    (hglobal : ∀ d e, bytesOf d = bytesOf e → d = e)
    (D : EconDomain) (a : List Digest) (p : Option Nat) (s : List UInt8) :
    bytesOf (mkHash D a p s) ≠ bytesOf absentLeaf := by
  intro h
  have : mkHash D a p s = absentLeaf := hglobal _ _ h
  exact absent_leaf_is_not_a_hash D.tag a p s this.symm

/-- TEETH: field-level injectivity is load-bearing for the fixed-width split.
    A collapsing encoder makes two distinct field lists share a byte image. -/
theorem adequacy_needs_field_injectivity :
    ∃ (bytesOf : Digest → List UInt8),
      (∀ d, (bytesOf d).length = 32) ∧
      ∃ (a b : List Digest), a ≠ b ∧ encodeDigs bytesOf a = encodeDigs bytesOf b := by
  refine ⟨fun _ => List.replicate 32 (0 : UInt8), fun _ => by simp, ?_⟩
  refine ⟨[Digest.absent], [econNode Digest.absent Digest.absent], ?_, ?_⟩
  · intro hc
    simp only [List.cons.injEq, and_true] at hc
    exact absent_leaf_is_not_a_node _ _ hc
  · rfl

/-
  Summary — DSMEconomicSmtSeparation

  Ruling-G obligations and what discharges each:

   1  each leaf-key derivation injective over its DECLARED input domain
      byte layer  -> encode_balance_key_inputs_injective,
                     encode_vault_reserve_key_inputs_injective,
                     encode_settlement_receipt_key_inputs_injective,
                     encode_consumed_source_key_inputs_injective
      symbolic    -> econ_balance_key_injective, econ_leaf_injective,
                     econ_node_injective, econ_leaf_value_injective,
                     econ_root_register_key_injective
      PROVED. The byte-layer lemmas are the bridge: distinct declared inputs
      give distinct MESSAGE bytes from fixed-width fields alone, so a key
      collision requires a hash collision rather than an ambiguous
      concatenation. Without them the symbolic theorems would be true merely
      because constructors are injective.

   2  leaf-key domains pairwise disjoint (LEAF-STATE INCLUDED)
      -> econ_domains_pairwise_disjoint.  PROVED; reduces to
         econ_domain_tag_injective, which the kernel DECIDES over the literal
         Rust tag strings — so renaming a tag into a collision stops this
         module compiling.

   3  K_root cannot alias any leaf-key domain
      -> k_root_aliases_no_leaf_key_domain.  PROVED.
      NOTE: this is non-aliasing ONLY. K_root is derivable by anyone who knows
      (G, DevID, position) — all public — so it confers no exclusivity, and
      nothing here should be read as establishing register-cell exclusivity.
      That comes from write-once storage plus claimant attribution.

   4  node/root vs leaf domains — AS CORRECTED
      -> econ_leaf_never_a_node, econ_leaf_value_never_a_leaf,
         econ_leaf_value_never_a_node, root_lives_in_the_node_domain,
         empty_economic_root_is_a_node.  PROVED. There is NO separate root
         domain; node and root are one, and that is proved rather than assumed.

   5  ABSENT_LEAF not confusable with a populated leaf commitment
      symbolic -> absent_leaf_is_not_a_hash, absent_leaf_is_not_a_populated_leaf,
                  default_node_is_never_a_populated_leaf, leaf_node_absent_iff_empty
      byte     -> populated_leaf_is_not_the_zero_sentinel, under h_not_absent_x
      The symbolic form is PROVED by constructor separation, with zero
      additional assumptions — but the datatype choice ENCODES the assumption
      rather than eliminating it. See the header, and
      global_injectivity_would_smuggle_in_the_zero_claim.

   6  non-interference between independently keyed state domains
      map          -> update_frame, update_hits_its_own_key,
                      class_non_interference, cross_domain_non_interference,
                      intra_class_non_interference
      tree         -> fold_path_injective, authenticated_value_unaffected
      canonicality -> same_leaf_and_path_same_root
      anti-vacuity -> update_inhabited, distinct_leaves_give_distinct_roots,
                      fold_path_inhabited
      PROVED, resting on obligations 1 and 2. Every statement mentions BOTH
      stores on BOTH sides — the failure mode of DSMNonInterference.lean's old
      `operation_locality`, repaired separately, is structurally excluded here.

   7  quorum intersection (owner-added)
      -> quorum_intersection, qualifying_quorums_intersect,
         quorum_intersection_of_two_q, canonical_quorum_intersects,
         canonical_quorum_is_minimal, beta_quorum_is_canonical,
         beta_quorums_intersect
      PROVED, zero assumptions, zero Mathlib. Stated over QUALIFYING quorums
      (at least q), which is what the protocol deals with; the exact-q form is
      kept as the underlying lemma.

  Non-vacuity witnesses:
    econ_domain_count, econ_domain_table_complete, update_inhabited,
    fold_path_inhabited, distinct_leaves_give_distinct_roots

  TEETH (a hypothesis or a modelling choice proved load-bearing):
    nul_freedom_is_load_bearing
    update_frame_needs_key_distinctness
    econ_node_argument_order_matters
    econ_leaf_binds_key_and_value
    subcanonical_quorum_admits_disjoint_quorums
    zero_threshold_carries_no_intersection
    global_injectivity_would_smuggle_in_the_zero_claim
    adequacy_needs_field_injectivity

  Axioms used: NONE. This module declares no `axiom` and no `opaque`.
  `#print axioms` on every headline theorem reports only Lean's own logical
  axioms — `propext`, and `Quot.sound` for the quorum results — because the two
  cryptographic assumptions are carried as HYPOTHESES in §11 signatures rather
  than as file-global axioms. `beta_quorum_is_canonical` depends on none at all.

  DO NOT report this module as "axiom-free" without that qualification: the
  quorum results are, and the economic hash / non-aliasing results rest on the
  symbolic abstraction declared in the header, with §11 additionally resting on
  h_collision_xy and, for obligation 5's byte form, h_not_absent_x.
-/
