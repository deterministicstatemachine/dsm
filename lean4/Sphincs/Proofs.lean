import Sphincs.Model
namespace DSM.Sphincs

 theorem be_width (width x : Nat) : (be width x).length = width := by
  induction width generalizing x with
  | zero => rfl
  | succ width ih => simp [be,ih]

 theorem be_roundtrip (width x : Nat) (bound : x < 256^width) : toInt (be width x) = x := by
  induction width generalizing x with
  | zero => simp [be,toInt]; omega
  | succ width ih =>
    have smaller : x/256 < 256^width := by
      apply (Nat.div_lt_iff_lt_mul (by decide)).2
      simpa [Nat.pow_succ] using bound
    simp only [be,toInt,List.reverse_append,List.reverse_cons,List.reverse_nil,
      List.nil_append,List.foldr_append,List.foldr_cons,List.foldr_nil]
    have hx := ih (x/256) smaller
    unfold toInt at hx
    rw [hx]
    simp only [UInt8.toNat_ofNat']
    have hmod : x%256 < 256 := Nat.mod_lt _ (by decide)
    have octet : (x%256) % 2^8 = x%256 := Nat.mod_eq_of_lt hmod
    rw [octet]
    exact Nat.mod_add_div x 256

 theorem parse_encode {width : Nat} (w : Wire width) : parse width (encode w) = some w := by
  simp [parse, encode, w.property]
 theorem encode_parse {width : Nat} {bs : Bytes} {w : Wire width}
    (h : parse width bs = some w) : encode w = bs := by
  unfold parse at h
  split at h
  · cases Option.some.inj h
    rfl
  · contradiction
 theorem wrong_length_rejected {width : Nat} {bs : Bytes} (h : bs.length ≠ width) :
    parse width bs = none := by simp [parse,h]
 theorem canonical_unique {width : Nat} (a b : Wire width)
    (h : encode a = encode b) : a = b := Subtype.ext h
 theorem signature_split_rejoins (p : Params) (sig : Bytes) :
    sig.take p.n ++ (sig.drop p.n).take p.forsBytes ++
      (sig.drop p.n).drop p.forsBytes = sig := by
  rw [List.append_assoc, List.take_append_drop, List.take_append_drop]
 theorem type_clears (a : Adrs) (t : Nat) :
    (a.setType t).keypair = 0 ∧ (a.setType t).chain = 0 ∧ (a.setType t).hash = 0 := by
  simp [Adrs.setType]
 theorem type_preserves_tree (a : Adrs) (t : Nat) :
    (a.setType t).layer = a.layer ∧ (a.setType t).tree = a.tree := by simp [Adrs.setType]
 theorem address_width (a : Adrs) : a.bytes.length = 32 := by
  simp [Adrs.bytes, be_width]
 theorem next_layer_leaf_bounded (p : Params) (tree : Nat) :
    (nextLayer p tree).1 < 2^p.hp := by
  exact Nat.mod_lt _ (Nat.pow_pos (by decide))
 theorem next_layer_reconstructs (p : Params) (tree : Nat) :
    (nextLayer p tree).1 + 2^p.hp * (nextLayer p tree).2 = tree :=
  Nat.mod_add_div _ _
 theorem digest_tree_bounded (p : Params) (digest : Bytes) :
    (splitDigest p digest).tree < 2^(p.h-p.hp) :=
  Nat.mod_lt _ (Nat.pow_pos (by decide))
 theorem digest_leaf_bounded (p : Params) (digest : Bytes) :
    (splitDigest p digest).leaf < 2^p.hp :=
  Nat.mod_lt _ (Nat.pow_pos (by decide))

-- Composition holds for any deterministic hash oracle; no injectivity,
-- collision-resistance or signature-security premise is used.
 theorem chain_composes (o : Oracle Id) (p : Params) (tk : Bytes) (a : Adrs)
    (x : Bytes) (start left right : Nat) :
    chain o p tk a x start (left+right) =
      chain o p tk a (chain o p tk a x start left) (start+left) right := by
  induction left generalizing x start with
  | zero => simp [chain, Id.instMonad]
  | succ left ih =>
    simp only [Nat.succ_add, chain, Id.instMonad, bind]
    rw [ih]
    congr 1
    omega

 theorem verify_empty (o : Oracle Id) (v : Variant) (pk sig : Bytes) :
    verify o v pk [] sig = none := by simp [Id.instMonad, verify]
 theorem verify_bad_pk (o : Oracle Id) (v : Variant) (pk msg sig : Bytes)
    (hne : msg.isEmpty = false) (hbad : pk.length ≠ 2*(params v).n) :
    verify o v pk msg sig = some false := by simp [Id.instMonad, verify,hne,hbad]
 theorem verify_bad_signature (o : Oracle Id) (v : Variant) (pk msg sig : Bytes)
    (hne : msg.isEmpty = false) (hbad : sig.length ≠ (params v).sigBytes) :
    verify o v pk msg sig = some false := by simp [Id.instMonad, verify,hne,hbad]

-- Parameters: all supported variants have len2=3, d*hp=h, bounded tree
-- and leaf indices, and the exact implemented signature byte counts.
 theorem parameter_layout (v : Variant) :
    (params v).d*(params v).hp = (params v).h ∧
    (params v).h-(params v).hp ≤ 64 ∧ (params v).hp ≤ 9 := by
  cases v <;> decide
 theorem signature_sizes :
    (params .spx128s).sigBytes = 7856 ∧ (params .spx128f).sigBytes = 17088 ∧
    (params .spx192s).sigBytes = 16224 ∧ (params .spx192f).sigBytes = 35664 ∧
    (params .spx256s).sigBytes = 29792 ∧ (params .spx256f).sigBytes = 49856 := by decide

-- Correct finite-width framing means an equal cert preimage binds both
-- the next key and parent tip, before any hashing assumption is made.
 theorem cert_preimage_binding (pk₁ pk₂ : Wire 64) (tip₁ tip₂ : Wire 32)
    (h : ekCertInput pk₁.val tip₁ = ekCertInput pk₂.val tip₂) :
    pk₁ = pk₂ ∧ tip₁ = tip₂ := by
  simp only [ekCertInput,domainInput] at h
  have body : pk₁.val ++ tip₁.val = pk₂.val ++ tip₂.val := List.append_cancel_left h
  have keys := congrArg (List.take 64) body
  have tips := congrArg (List.drop 64) body
  simp [pk₁.property,pk₂.property] at keys
  simp [pk₁.property,pk₂.property] at tips
  exact ⟨Subtype.ext keys,Subtype.ext tips⟩

-- This is a concrete collision witness formulation, not the false axiom
-- that a finite-output hash is globally injective on all byte strings.
 theorem domain_binding_or_collision (hash : Bytes → Bytes)
    (tag₁ tag₂ : String) (body₁ body₂ : Bytes)
    (heq : hash (domainInput tag₁ body₁) = hash (domainInput tag₂ body₂)) :
    domainInput tag₁ body₁ = domainInput tag₂ body₂ ∨
      (domainInput tag₁ body₁ ≠ domainInput tag₂ body₂ ∧
       hash (domainInput tag₁ body₁) = hash (domainInput tag₂ body₂)) := by
  by_cases h : domainInput tag₁ body₁ = domainInput tag₂ body₂
  · exact Or.inl h
  · exact Or.inr ⟨h,heq⟩

 theorem wots_signature_recovers_chain_top (o : Oracle Id) (p : Params)
    (tk : Bytes) (a : Adrs) (secret : Bytes) (digit : Nat) (hd : digit ≤ 15) :
    chain o p tk a (chain o p tk a secret 0 digit) digit (15-digit) =
      chain o p tk a secret 0 15 := by
  have h := chain_composes o p tk a secret 0 digit (15-digit)
  simp only [Nat.zero_add] at h
  have total : digit+(15-digit) = 15 := by omega
  rw [total] at h
  exact h.symm

 theorem wots_digit_count (p : Params) (msg : Bytes) :
    (wotsDigits p msg).length = p.len := by
  simp [wotsDigits, base2b, Params.len, Id.run, Id.instMonad]

 theorem accepted_requires_exact_lengths (o : Oracle Id) (v : Variant) (pk msg sig : Bytes)
    (h : verify o v pk msg sig = some true) :
    pk.length = 2*(params v).n ∧ sig.length = (params v).sigBytes := by
  by_cases empty : msg.isEmpty = true
  · simp [verify,empty,Id.instMonad] at h
  · have nonempty : msg.isEmpty = false := by cases e : msg.isEmpty <;> simp_all
    by_cases keySize : pk.length = 2*(params v).n
    · by_cases sigSize : sig.length = (params v).sigBytes
      · exact ⟨keySize,sigSize⟩
      · rw [verify_bad_signature o v pk msg sig nonempty sigSize] at h
        have bad : (false : Bool) = true := Option.some.inj h
        cases bad
    · rw [verify_bad_pk o v pk msg sig nonempty keySize] at h
      have bad : (false : Bool) = true := Option.some.inj h
      cases bad

-- The verifier acceptance equation includes the concrete FORS and hypertree
-- reconstruction functions. It is conditional on the selected primitive
-- oracle; it does not assert EUF-CMA or signer correctness.
 theorem verification_structure (o : Oracle Id) (v : Variant) (pk msg sig : Bytes)
    (hne : msg.isEmpty = false) (hpk : pk.length = 2*(params v).n)
    (hsig : sig.length = (params v).sigBytes) :
    verify o v pk msg sig = some true ↔
      let p := params v
      let seed := pk.take p.n
      let tk := deriveKey o "DSM/sphincs/v2/thash" seed
      let indices := splitDigest p (hmsg o p (sig.take p.n) seed (pk.drop p.n) msg)
      let fpk := forsPkFromSig o p tk
        {tree := indices.tree,kind := 3,keypair := indices.leaf}
        (slice sig p.n p.forsBytes) indices.md
      htRoot o p tk (sig.drop (p.n+p.forsBytes)) fpk indices.tree indices.leaf = pk.drop p.n := by
  simp [verify,hne,hpk,hsig,Id.instMonad]
  constructor
  · intro h
    exact (@beq_iff_eq Bytes _ _ _ _).mp (Option.some.inj h)
  · intro h
    apply congrArg some
    exact (@beq_iff_eq Bytes _ _ _ _).mpr h

 theorem fixed_pair_binding {left right : Nat} (a₁ a₂ : Wire left) (b₁ b₂ : Wire right)
    (h : a₁.val++b₁.val = a₂.val++b₂.val) : a₁ = a₂ ∧ b₁ = b₂ := by
  have ha : a₁.val = a₂.val := List.append_inj_left h (by rw [a₁.property,a₂.property])
  have hb : b₁.val = b₂.val := by rw [ha] at h; exact List.append_cancel_left h
  exact ⟨Subtype.ext ha,Subtype.ext hb⟩

 theorem devid_preimage_binding (pk₁ pk₂ : Wire 64) (att₁ att₂ : Wire 32)
    (h : devidInput pk₁.val att₁ = devidInput pk₂.val att₂) : pk₁ = pk₂ ∧ att₁ = att₂ := by
  exact fixed_pair_binding pk₁ pk₂ att₁ att₂ (List.append_cancel_left h)

 theorem identity_preimage_binding (dev₁ dev₂ gen₁ gen₂ : Wire 32)
    (kem₁ kem₂ : Wire 1184)
    (h : identityBindingInput dev₁ gen₁ kem₁.val = identityBindingInput dev₂ gen₂ kem₂.val) :
    dev₁ = dev₂ ∧ gen₁ = gen₂ ∧ kem₁ = kem₂ := by
  have body : dev₁.val++gen₁.val++kem₁.val = dev₂.val++gen₂.val++kem₂.val :=
    List.append_cancel_left h
  rw [List.append_assoc,List.append_assoc] at body
  have devs : dev₁.val = dev₂.val := List.append_inj_left body (by rw [dev₁.property,dev₂.property])
  rw [devs] at body
  have tail := List.append_cancel_left body
  have rest := fixed_pair_binding gen₁ gen₂ kem₁ kem₂ tail
  exact ⟨Subtype.ext devs,rest⟩

-- Altering a bound cert field while retaining its digest gives an explicit
-- pair of distinct byte strings with equal hash outputs. No global hash
-- injectivity assumption is introduced.
 theorem changed_cert_fields_same_digest_is_collision (hash : Bytes → Bytes)
    (pk₁ pk₂ : Wire 64) (tip₁ tip₂ : Wire 32)
    (changed : pk₁ ≠ pk₂ ∨ tip₁ ≠ tip₂)
    (sameDigest : hash (ekCertInput pk₁.val tip₁) = hash (ekCertInput pk₂.val tip₂)) :
    ekCertInput pk₁.val tip₁ ≠ ekCertInput pk₂.val tip₂ ∧
      hash (ekCertInput pk₁.val tip₁) = hash (ekCertInput pk₂.val tip₂) := by
  refine ⟨?_,sameDigest⟩
  intro sameInput
  have bindings := cert_preimage_binding pk₁ pk₂ tip₁ tip₂ sameInput
  rcases changed with h | h
  · exact h bindings.1
  · exact h bindings.2

-- Authentication paths recover a tree root under an explicit tree-parent
-- recurrence, correct sibling nodes, and localLeaf/global orientation agreement.
-- This is a universal structural statement, not a hash-security assumption.
 theorem auth_walk_recovers_tree (o : Oracle Id) (p : Params) (tk : Bytes) (a : Adrs)
    (nodes : Nat → Nat → Bytes)
    (parents : ∀ level index,
      thash o p tk {a with chain := level+1,hash := index}
        (nodes level (2*index) ++ nodes level (2*index+1)) = nodes (level+1) index)
    (remaining level localIndex globalIndex : Nat) (auth : Bytes)
    (orientation : ∀ j, j < remaining → (localIndex/2^j)%2 = (globalIndex/2^j)%2)
    (siblings : ∀ j, j < remaining →
      slice auth ((level+j)*p.n) p.n = nodes (level+j) (siblingIndex (globalIndex/2^j))) :
    authWalk o p tk a localIndex globalIndex (nodes level globalIndex) auth level remaining =
      nodes (level+remaining) (globalIndex/2^remaining) := by
  induction remaining generalizing level localIndex globalIndex with
  | zero => simp [authWalk,Id.instMonad]
  | succ remaining ih =>
    have parity : localIndex%2 = globalIndex%2 := by simpa using orientation 0 (by omega)
    have sibling := siblings 0 (by omega)
    simp only [Nat.pow_zero,Nat.div_one,Nat.add_zero] at sibling
    have step :
      thash o p tk {a with chain := level+1,hash := globalIndex/2}
        (if localIndex%2 = 0 then
          nodes level globalIndex ++ slice auth (level*p.n) p.n
        else slice auth (level*p.n) p.n ++ nodes level globalIndex) =
        nodes (level+1) (globalIndex/2) := by
      rw [sibling,parity]
      by_cases even : globalIndex%2 = 0
      · have left : globalIndex = 2*(globalIndex/2) := by omega
        have right : siblingIndex globalIndex = 2*(globalIndex/2)+1 := by simp [siblingIndex,even]; omega
        simp only [even,if_true]
        have input : nodes level globalIndex ++ nodes level (siblingIndex globalIndex) =
            nodes level (2*(globalIndex/2)) ++ nodes level (2*(globalIndex/2)+1) := by
          exact congr (congrArg List.append (congrArg (nodes level) left)) (congrArg (nodes level) right)
        rw [input]
        exact parents level (globalIndex/2)
      · have right : globalIndex = 2*(globalIndex/2)+1 := by omega
        have left : siblingIndex globalIndex = 2*(globalIndex/2) := by simp [siblingIndex,even]; omega
        simp only [even,if_false]
        have input : nodes level (siblingIndex globalIndex) ++ nodes level globalIndex =
            nodes level (2*(globalIndex/2)) ++ nodes level (2*(globalIndex/2)+1) := by
          exact congr (congrArg List.append (congrArg (nodes level) left)) (congrArg (nodes level) right)
        rw [input]
        exact parents level (globalIndex/2)
    simp only [authWalk,Id.instMonad,bind]
    rw [step]
    have orientation' : ∀ j, j < remaining →
        ((localIndex/2)/2^j)%2 = ((globalIndex/2)/2^j)%2 := by
      intro j hj
      have h := orientation (j+1) (by omega)
      simpa [Nat.pow_succ,Nat.div_div_eq_div_mul,Nat.mul_comm] using h
    have siblings' : ∀ j, j < remaining →
        slice auth ((level+1+j)*p.n) p.n =
          nodes (level+1+j) (siblingIndex ((globalIndex/2)/2^j)) := by
      intro j hj
      have h := siblings (j+1) (by omega)
      simpa [Nat.pow_succ,Nat.div_div_eq_div_mul,Nat.mul_comm,Nat.add_assoc,Nat.add_comm,Nat.add_left_comm] using h
    rw [ih (level+1) (localIndex/2) (globalIndex/2) orientation' siblings']
    simp [Nat.pow_succ,Nat.div_div_eq_div_mul,Nat.mul_comm,Nat.add_comm,Nat.add_left_comm]

 theorem fors_orientation (offset localLeaf height j : Nat) (bound : j < height) :
    (localLeaf/2^j)%2 = ((offset*2^height+localLeaf)/2^j)%2 := by
  induction j generalizing localLeaf height with
  | zero =>
    cases height with
    | zero => omega
    | succ h => simp [Nat.pow_succ,Nat.add_mod,Nat.mul_mod]
  | succ j ih =>
    cases height with
    | zero => omega
    | succ h =>
      have reduced : (offset*2^(h+1)+localLeaf)/2 = offset*2^h+localLeaf/2 := by
        rw [Nat.pow_succ,←Nat.mul_assoc,Nat.add_comm]
        rw [Nat.add_mul_div_right _ _ (by decide)]
        exact Nat.add_comm _ _
      have result := ih (localLeaf/2) h (by omega)
      rw [←reduced] at result
      simpa [Nat.pow_succ,Nat.div_div_eq_div_mul,Nat.mul_comm] using result

 theorem xmss_authentication_path_recovers_tree (o : Oracle Id) (p : Params) (tk : Bytes)
    (a : Adrs) (nodes : Nat → Nat → Bytes) (index : Nat) (auth : Bytes)
    (parents : ∀ level idx,
      thash o p tk {a with chain := level+1,hash := idx}
        (nodes level (2*idx) ++ nodes level (2*idx+1)) = nodes (level+1) idx)
    (siblings : ∀ j, j < p.hp →
      slice auth (j*p.n) p.n = nodes j (siblingIndex (index/2^j))) :
    authRoot o p tk a index index (nodes 0 index) auth p.hp = nodes p.hp (index/2^p.hp) := by
  simpa [authRoot] using auth_walk_recovers_tree o p tk a nodes parents p.hp 0 index index auth
    (fun _ _ => rfl) (by simpa using siblings)

 theorem fors_authentication_path_recovers_tree (o : Oracle Id) (p : Params) (tk : Bytes)
    (a : Adrs) (nodes : Nat → Nat → Bytes) (treeIndex leaf : Nat) (auth : Bytes)
    (leafBound : leaf < 2^p.a)
    (parents : ∀ level idx,
      thash o p tk {a with chain := level+1,hash := idx}
        (nodes level (2*idx) ++ nodes level (2*idx+1)) = nodes (level+1) idx)
    (siblings : ∀ j, j < p.a →
      slice auth (j*p.n) p.n = nodes j (siblingIndex ((treeIndex*2^p.a+leaf)/2^j))) :
    authRoot o p tk a leaf (treeIndex*2^p.a+leaf)
      (nodes 0 (treeIndex*2^p.a+leaf)) auth p.a = nodes p.a treeIndex := by
  have walk := auth_walk_recovers_tree o p tk a nodes parents p.a 0 leaf
    (treeIndex*2^p.a+leaf) auth
    (fun j hj => fors_orientation treeIndex leaf p.a j hj) (by simpa using siblings)
  have index : (treeIndex*2^p.a+leaf)/2^p.a = treeIndex := by
    rw [Nat.add_comm,Nat.add_mul_div_right _ _ (Nat.pow_pos (by decide))]
    rw [Nat.div_eq_of_lt leafBound]
    simp
  simpa [authRoot,index] using walk

 theorem fixed_head_binding {width : Nat} (a₁ a₂ : Wire width) (tail₁ tail₂ : Bytes)
    (h : a₁.val++tail₁ = a₂.val++tail₂) : a₁ = a₂ ∧ tail₁ = tail₂ := by
  have head : a₁.val = a₂.val := List.append_inj_left h (by rw [a₁.property,a₂.property])
  have tail : tail₁ = tail₂ := by rw [head] at h; exact List.append_cancel_left h
  exact ⟨Subtype.ext head,tail⟩

 theorem ek_seed_preimage_binding (alg₁ alg₂ : Wire 7)
    (chain₁ chain₂ tip₁ tip₂ pre₁ pre₂ step₁ step₂ : Wire 32)
    (h : ekSeedInput alg₁.val chain₁ tip₁ pre₁ step₁ =
      ekSeedInput alg₂.val chain₂ tip₂ pre₂ step₂) :
    alg₁ = alg₂ ∧ chain₁ = chain₂ ∧ tip₁ = tip₂ ∧ pre₁ = pre₂ ∧ step₁ = step₂ := by
  have body : alg₁.val++chain₁.val++tip₁.val++pre₁.val++step₁.val =
      alg₂.val++chain₂.val++tip₂.val++pre₂.val++step₂.val := List.append_cancel_left h
  simp only [List.append_assoc] at body
  obtain ⟨alg,body⟩ := fixed_head_binding alg₁ alg₂ _ _ body
  obtain ⟨chain,body⟩ := fixed_head_binding chain₁ chain₂ _ _ body
  obtain ⟨tip,body⟩ := fixed_head_binding tip₁ tip₂ _ _ body
  obtain ⟨pre,step⟩ := fixed_pair_binding pre₁ pre₂ step₁ step₂ body
  exact ⟨alg,chain,tip,pre,step⟩

 theorem verify_bad_signature_no_hash_calls [Monad m] [LawfulMonad m] (o : Oracle m) (v : Variant)
    (pk msg sig : Bytes) (hne : msg.isEmpty = false)
    (bad : sig.length ≠ (params v).sigBytes) :
    verify o v pk msg sig = pure (some false) := by
  simp [verify,hne,bad]

 theorem checksum_width_three (v : Variant) :
    16^(3-1) ≤ 2*(params v).n*15 ∧ 2*(params v).n*15 < 16^3 := by
  cases v <;> decide

 theorem xor_one_is_sibling (index : Nat) : Nat.xor index 1 = siblingIndex index := by
  change (index ^^^ 1) = siblingIndex index
  have quotient : (index ^^^ 1)/2 = index/2 := by rw [Nat.xor_div_two]; simp
  have parity : ((index ^^^ 1)%2 = 1) ↔ index%2 ≠ 1 := by
    simp
  have arithmetic : ∀ x y : Nat, y/2 = x/2 →
      (y%2 = 1 ↔ x%2 ≠ 1) → y = siblingIndex x := by
    intro x y sameDiv opposite
    by_cases even : x%2 = 0
    · simp [siblingIndex,even]
      omega
    · simp [siblingIndex,even]
      omega
  exact arithmetic index (index ^^^ 1) quotient parity

 theorem fixed_block_slice (headBytes block tailBytes : Bytes) (width : Nat)
    (blockWidth : block.length = width) :
    slice (headBytes++block++tailBytes) headBytes.length width = block := by
  simp [slice,List.append_assoc,blockWidth]

#print axioms xor_one_is_sibling
#print axioms fixed_block_slice
 theorem bit_fold_bound (bits : List Nat) (bit : Nat → Nat)
    (bounded : ∀ j, bit j < 2) (acc width : Nat) (initial : acc < 2^width) :
    bits.foldl (fun value j => value*2+bit j) acc < 2^(width+bits.length) := by
  induction bits generalizing acc width with
  | nil => simpa using initial
  | cons j rest ih =>
    have next : acc*2+bit j < 2^(width+1) := by
      rw [Nat.pow_succ]
      have hb := bounded j
      omega
    have result := ih (acc*2+bit j) (width+1) next
    simpa [Nat.add_assoc,Nat.add_comm,Nat.add_left_comm] using result

 theorem base2b_digit_bound (input : Bytes) (b count digit : Nat)
    (member : digit ∈ base2b input b count) : digit < 2^b := by
  obtain ⟨i,_,rfl⟩ := List.mem_map.mp member
  have result := bit_fold_bound (List.range b)
    (fun j => ((input[(i*b+j)/8]?.getD 0).toNat / 2^(7-(i*b+j)%8))%2)
    (fun j => Nat.mod_lt _ (by decide)) 0 0 (by decide)
  simpa using result

 theorem wots_digit_bound (p : Params) (msg : Bytes) (digit : Nat)
    (member : digit ∈ wotsDigits p msg) : digit ≤ 15 := by
  simp only [wotsDigits,Id.run,pure,List.mem_append] at member
  rcases member with first | checksum
  · have bound := base2b_digit_bound msg 4 (2*p.n) digit first
    omega
  · have bound := base2b_digit_bound _ 4 3 digit checksum
    omega

#print axioms base2b_digit_bound
#print axioms wots_digit_bound
 theorem wots_generated_digit_recovers (o : Oracle Id) (p : Params)
    (tk : Bytes) (a : Adrs) (secret msg : Bytes) (digit : Nat)
    (member : digit ∈ wotsDigits p msg) :
    chain o p tk a (chain o p tk a secret 0 digit) digit (15-digit) =
      chain o p tk a secret 0 15 := by
  exact wots_signature_recovers_chain_top o p tk a secret digit
    (wots_digit_bound p msg digit member)

#print axioms wots_generated_digit_recovers
-- This contract describes fixed-width primitive output, not hash security.
def OutputWidths (o : Oracle Id) : Prop := ∀ request, (o request).length = request.outLen

 theorem thash_width (o : Oracle Id) (widths : OutputWidths o)
    (p : Params) (tk : Bytes) (a : Adrs) (input : Bytes) :
    (thash o p tk a input).length = p.n := by
  exact widths _

 theorem prf_width (o : Oracle Id) (widths : OutputWidths o)
    (p : Params) (key seed : Bytes) (a : Adrs) :
    (prf o p key seed a).length = p.n := by
  exact widths _

 theorem chain_width (o : Oracle Id) (widths : OutputWidths o)
    (p : Params) (tk : Bytes) (a : Adrs) (x : Bytes) (start steps : Nat)
    (initial : x.length = p.n) :
    (chain o p tk a x start steps).length = p.n := by
  induction steps generalizing x start with
  | zero => exact initial
  | succ steps ih =>
    exact ih (thash o p tk {a with hash := start} x) (start+1)
      (thash_width o widths p tk _ x)

 theorem wots_pkgen_width (o : Oracle Id) (widths : OutputWidths o)
    (p : Params) (tk prfKey seed : Bytes) (a : Adrs) :
    (wotsPkgen o p tk prfKey seed a).length = p.n := by
  unfold wotsPkgen
  exact thash_width o widths p tk _ _

 theorem xmss_node_width (o : Oracle Id) (widths : OutputWidths o)
    (p : Params) (tk prfKey seed : Bytes) (a : Adrs) (index height : Nat) :
    (xmssNode o p tk prfKey seed a index height).length = p.n := by
  cases height with
  | zero => exact wots_pkgen_width o widths p tk prfKey seed _
  | succ height => exact thash_width o widths p tk _ _

#print axioms wots_pkgen_width
#print axioms xmss_node_width
 theorem xmss_node_parent (o : Oracle Id) (p : Params) (tk prfKey seed : Bytes)
    (a : Adrs) (level index : Nat) :
    thash o p tk {a.setType 2 with chain := level+1, hash := index}
      (List.append (xmssNode o p tk prfKey seed a (2*index) level)
       (xmssNode o p tk prfKey seed a (2*index+1) level)) =
    xmssNode o p tk prfKey seed a index (level+1) := by
  rfl

 theorem fors_node_parent (o : Oracle Id) (p : Params) (tk prfKey seed : Bytes)
    (a : Adrs) (level index : Nat) :
    thash o p tk {a with chain := level+1, hash := index}
      (List.append (forsNode o p tk prfKey seed a (2*index) level)
       (forsNode o p tk prfKey seed a (2*index+1) level)) =
    forsNode o p tk prfKey seed a index (level+1) := by
  rfl

 theorem fors_node_width (o : Oracle Id) (widths : OutputWidths o)
    (p : Params) (tk prfKey seed : Bytes) (a : Adrs) (index height : Nat) :
    (forsNode o p tk prfKey seed a index height).length = p.n := by
  cases height with
  | zero => exact thash_width o widths p tk _ _
  | succ height => exact thash_width o widths p tk _ _

-- Parent recurrence is discharged using the signer itself. Only the leaf
-- and authentication-byte correspondence remain premises here.
 theorem xmss_signer_tree_path (o : Oracle Id) (p : Params) (tk prfKey seed : Bytes)
    (a : Adrs) (index : Nat) (auth : Bytes)
    (siblings : ∀ j, j < p.hp → slice auth (j*p.n) p.n =
      xmssNode o p tk prfKey seed a (siblingIndex (index/2^j)) j) :
    authRoot o p tk (a.setType 2) index index
      (xmssNode o p tk prfKey seed a index 0) auth p.hp =
      xmssNode o p tk prfKey seed a (index/2^p.hp) p.hp := by
  apply xmss_authentication_path_recovers_tree o p tk (a.setType 2)
    (fun level idx => xmssNode o p tk prfKey seed a idx level) index auth
  · intro level idx
    simpa [Adrs.setType] using xmss_node_parent o p tk prfKey seed a level idx
  · exact siblings

 theorem fors_signer_tree_path (o : Oracle Id) (p : Params) (tk prfKey seed : Bytes)
    (a : Adrs) (treeIndex leaf : Nat) (auth : Bytes) (bound : leaf < 2^p.a)
    (siblings : ∀ j, j < p.a → slice auth (j*p.n) p.n =
      forsNode o p tk prfKey seed a (siblingIndex ((treeIndex*2^p.a+leaf)/2^j)) j) :
    authRoot o p tk a leaf (treeIndex*2^p.a+leaf)
      (forsNode o p tk prfKey seed a (treeIndex*2^p.a+leaf) 0) auth p.a =
      forsNode o p tk prfKey seed a treeIndex p.a := by
  exact fors_authentication_path_recovers_tree o p tk a
    (fun level idx => forsNode o p tk prfKey seed a idx level) treeIndex leaf auth bound
    (fors_node_parent o p tk prfKey seed a) siblings

#print axioms chain_width
#print axioms fors_node_width
#print axioms xmss_signer_tree_path
#print axioms fors_signer_tree_path
#print axioms verify_bad_signature_no_hash_calls
#print axioms checksum_width_three
#print axioms ek_seed_preimage_binding
#print axioms fors_orientation
#print axioms xmss_authentication_path_recovers_tree
#print axioms fors_authentication_path_recovers_tree
#print axioms auth_walk_recovers_tree
#print axioms be_roundtrip
#print axioms devid_preimage_binding
#print axioms identity_preimage_binding
#print axioms changed_cert_fields_same_digest_is_collision
#print axioms wots_signature_recovers_chain_top
#print axioms accepted_requires_exact_lengths
#print axioms verification_structure
#print axioms parse_encode
#print axioms encode_parse
#print axioms chain_composes
#print axioms cert_preimage_binding
#print axioms verify_bad_signature
#print axioms next_layer_reconstructs
#print axioms parameter_layout
end DSM.Sphincs
