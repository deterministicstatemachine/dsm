-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.PrfHybrid

/- The PRF_msg hybrids, after the PRF hybrids (PrfHybrid.lean). Hop 3a
   replaces L = derive_key("DSM/sphincs/v2/prf-msg", SK.prf) by a uniform
   32-byte key; hop 3b replaces keyed BLAKE3 under it, which computes the
   randomizer R from PK.seed ‖ M, by a uniformly random function. After hop 3b
   neither secret seed appears in the game: every WOTS/FORS secret and every R
   is a random-function output. Distinguishers are explicit and proved exact;
   no PRF, KDF or BLAKE3 premise is declared. -/
namespace DSM.Sphincs.Security

/-- `sign_congr` with the message keys allowed to differ: the second secret-key
    field (SK.prf) may differ, provided the two worlds answer the R request
    alike under their own message keys. -/
theorem sign_congr_msg (v : Variant) (o₁ o₂ : Oracle Id) (M K L₁ L₂ sk₁ sk₂ : Bytes)
    (agreeAt : ∀ x, KeyedAgreeAt o₁ o₂ (o₂ ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩) M K)
    (dThash : ∀ x, o₁ ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩ = o₂ ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩)
    (hMsg : ∀ x len, o₁ ⟨2,"DSM/sphincs/v2/h-msg",[],x,len⟩ = o₂ ⟨2,"DSM/sphincs/v2/h-msg",[],x,len⟩)
    (dMsg₁ : o₁ ⟨0,"DSM/sphincs/v2/prf-msg",[],slice sk₁ (params v).n (params v).n,32⟩ = L₁)
    (dMsg₂ : o₂ ⟨0,"DSM/sphincs/v2/prf-msg",[],slice sk₂ (params v).n (params v).n,32⟩ = L₂)
    (rAgree : ∀ input len, o₁ ⟨1,"",L₁,input,len⟩ = o₂ ⟨1,"",L₂,input,len⟩)
    (dPrf₁ : o₁ ⟨0,"DSM/sphincs/v2/prf",[],sk₁.take (params v).n,32⟩ = M)
    (dPrf₂ : o₂ ⟨0,"DSM/sphincs/v2/prf",[],sk₂.take (params v).n,32⟩ = K)
    (len : sk₁.length = sk₂.length)
    (seedEq : slice sk₁ (2*(params v).n) (params v).n = slice sk₂ (2*(params v).n) (params v).n)
    (rootEq : sk₁.drop (3*(params v).n) = sk₂.drop (3*(params v).n))
    (m : Bytes) : sign o₁ v sk₁ m = sign o₂ v sk₂ m := by
  have htk := agreeAt (slice sk₂ (2*(params v).n) (params v).n)
  simp only [sign, deriveKey, keyed, hmsg, id_bind, id_pure, len, seedEq, rootEq,
    dThash, dMsg₁, dMsg₂, rAgree, hMsg, dPrf₁, dPrf₂,
    forsSign_agree htk, forsPkFromSig_agree htk,
    htSign_agree htk, htRoot_agree htk]

/-- Two expansions that share PK.seed (the last n of 3n bytes). -/
theorem shared_seed_layout (n : Nat) (X Y R : Bytes) (xl : X.length = 3*n) (yl : Y.length = 3*n)
    (same : X.drop (2*n) = Y.drop (2*n)) :
    (X ++ R).length = (Y ++ R).length ∧
    slice (X ++ R) (2*n) n = slice (Y ++ R) (2*n) n ∧
    (X ++ R).drop (3*n) = (Y ++ R).drop (3*n) ∧
    slice X (2*n) n = slice Y (2*n) n := by
  have base : (X ++ R).drop (2*n) = (Y ++ R).drop (2*n) := by
    rw [List.drop_append_of_le_length (by omega), List.drop_append_of_le_length (by omega), same]
  refine ⟨by simp [xl, yl], ?_, drop_after _ _ (2*n) (3*n) (by omega) base, ?_⟩
  · simp only [slice]; rw [base]
  · simp only [slice]; rw [same]

/-! ## Hop 3a: the derived message key becomes a uniform key -/

def patchMsgKey (o : Oracle Id) (L : Bytes) : Oracle Id :=
  fun r => if r.mode = 0 ∧ r.context = "DSM/sphincs/v2/prf-msg" then L else o r

theorem msgpatch_keyed (o : Oracle Id) (L key input : Bytes) (len : Nat) :
    patchMsgKey o L ⟨1,"",key,input,len⟩ = o ⟨1,"",key,input,len⟩ := by
  simp [patchMsgKey]

theorem msgpatch_other (o : Oracle Id) (L : Bytes) (c : String) (ne : c ≠ "DSM/sphincs/v2/prf-msg")
    (mode : Nat) (key input : Bytes) (len : Nat) :
    patchMsgKey o L ⟨mode,c,key,input,len⟩ = o ⟨mode,c,key,input,len⟩ := by
  simp [patchMsgKey, ne]

theorem msgpatch_msg (o : Oracle Id) (L input : Bytes) :
    patchMsgKey o L ⟨0,"DSM/sphincs/v2/prf-msg",[],input,32⟩ = L := by
  simp [patchMsgKey]

theorem msgpatch_agree (o : Oracle Id) (L M : Bytes) : KeyedAgree (patchMsgKey o L) o M M :=
  ⟨fun _ _ _ _ => msgpatch_keyed _ _ _ _ _, fun _ _ => msgpatch_keyed _ _ _ _ _⟩

/-- Hop 3a's distinguisher, in hop 2b's world (PRF answered by `F`). Its
    challenge is PK.seed and a message key `L`; SK.seed and SK.prf are zeros. -/
def msgKeyDistinguisher (v : Variant) (limits : Limits) (strategy : Strategy) (o : Oracle Id)
    (F : Bytes → Nat → Bytes) (pkSeed L : Bytes) : Bool :=
  seedDistinguisher v limits strategy (patchMsgKey (routePrf o F) L)
    (zeros (params v).n ++ zeros (params v).n ++ pkSeed)

theorem msg_key_distinguisher_exact (v : Variant) (limits : Limits) (strategy : Strategy)
    (o : Oracle Id) (F : Bytes → Nat → Bytes) (rest : Wire (2*(params v).n)) :
    msgKeyDistinguisher v limits strategy o F (rest.val.drop (params v).n)
        (deriveKey o "DSM/sphincs/v2/prf-msg" (rest.val.take (params v).n)) =
      functionDistinguisher v limits strategy o rest.val F := by
  generalize hL : deriveKey o "DSM/sphincs/v2/prf-msg" (rest.val.take (params v).n) = L
  have hL' : o ⟨0,"DSM/sphincs/v2/prf-msg",[],rest.val.take (params v).n,32⟩ = L := hL
  have rl := rest.property
  have e₁l : (zeros (params v).n ++ zeros (params v).n ++ rest.val.drop (params v).n).length =
      3*(params v).n := by simp only [zeros, List.length_append, List.length_replicate,
        List.length_drop, rl]; omega
  have e₂l : (zeros (params v).n ++ rest.val).length = 3*(params v).n := by
    simp only [zeros, List.length_append, List.length_replicate, rl]; omega
  have same : (zeros (params v).n ++ zeros (params v).n ++ rest.val.drop (params v).n).drop
      (2*(params v).n) = (zeros (params v).n ++ rest.val).drop (2*(params v).n) := by
    have lhs : (zeros (params v).n ++ zeros (params v).n ++ rest.val.drop (params v).n).drop
        (2*(params v).n) = rest.val.drop (params v).n := List.drop_left' (by simp [zeros]; omega)
    have gen : ∀ X : Bytes, (zeros (params v).n ++ X).drop (2*(params v).n) = X.drop (params v).n := by
      intro X
      rw [show 2*(params v).n = (zeros (params v).n).length + (params v).n by simp [zeros]; omega,
        List.drop_append]
      simp [zeros]
    have rhs := gen rest.val
    rw [lhs, rhs]
  have dThash : ∀ x, patchMsgKey (routePrf o F) L ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩ =
      routePrf o F ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩ := fun x => msgpatch_other _ _ _ (by decide) _ _ _ _
  have hMsg : ∀ x len, patchMsgKey (routePrf o F) L ⟨2,"DSM/sphincs/v2/h-msg",[],x,len⟩ =
      routePrf o F ⟨2,"DSM/sphincs/v2/h-msg",[],x,len⟩ := fun x len =>
    msgpatch_other _ _ _ (by decide) _ _ _ _
  have dPrf₁ : ∀ x, patchMsgKey (routePrf o F) L ⟨0,"DSM/sphincs/v2/prf",[],x,32⟩ = MARK := fun x => by
    rw [msgpatch_other _ _ _ (by decide), route_unkeyed _ _ _ (by decide), patch_prf]
  have dPrf₂ : ∀ x, routePrf o F ⟨0,"DSM/sphincs/v2/prf",[],x,32⟩ = MARK := fun x => by
    rw [route_unkeyed _ _ _ (by decide), patch_prf]
  have root : ∀ seed tk, xmssNode (patchMsgKey (routePrf o F) L) (params v) tk MARK seed
      {layer := (params v).d-1} 0 (params v).hp =
      xmssNode (routePrf o F) (params v) tk MARK seed {layer := (params v).d-1} 0 (params v).hp :=
    fun seed tk => xmssNode_agree ((msgpatch_agree _ L MARK).at (fun _ => rfl)) _ _ _ _
  obtain ⟨_, _, _, seedS⟩ := shared_seed_layout (params v).n _ _ [] e₁l e₂l same
  have kp1 : (keypairFromExpansion (patchMsgKey (routePrf o F) L) v
        (zeros (params v).n ++ zeros (params v).n ++ rest.val.drop (params v).n)).1 =
      (keypairFromExpansion (routePrf o F) v (zeros (params v).n ++ rest.val)).1 := by
    simp only [keypairFromExpansion, deriveKey, dThash, dPrf₁, dPrf₂, seedS, root]
  unfold msgKeyDistinguisher functionDistinguisher
  apply seedDistinguisher_congr
  · exact kp1
  · intro m
    rw [kp_shape _ v _ e₁l, kp_shape _ v _ e₂l, kp1]
    obtain ⟨l1, l2, l3, _⟩ := shared_seed_layout (params v).n _ _
      ((keypairFromExpansion (routePrf o F) v (zeros (params v).n ++ rest.val)).1.drop (params v).n)
      e₁l e₂l same
    apply sign_congr_msg v _ _ MARK MARK L L _ _ (fun x => (msgpatch_agree _ L MARK).at (fun _ => rfl)) dThash
      hMsg _ _ (fun _ _ => msgpatch_keyed _ _ _ _ _) (dPrf₁ _) (dPrf₂ _) l1 l2 l3
    · exact msgpatch_msg _ _ _
    · simp only [slice]
      rw [List.drop_append_of_le_length (by simp [zeros, rl] <;> omega),
        List.take_append_of_le_length (by simp [zeros, rl] <;> omega)]
      simp only [zeros]
      rw [List.drop_left' (by simp), route_unkeyed _ _ _ (by decide), patch_other _ _ _ (by decide)]
      exact hL'
  · exact verify_congr v _ _ MARK MARK (fun x => (msgpatch_agree _ L MARK).at (fun _ => rfl)) dThash hMsg

/-! ## Hop 3a, probabilities -/

/-- Hop 2b's ideal game, written as hop 3a's distinguisher on the real message
    key derived from SK.prf. -/
def realMsgKeyProbability (v : Variant) (limits : Limits) (o : Oracle Id)
    (coins : FiniteExperiment Strategy) : Probability :=
  probability (independentProduct (independentProduct (uniformBytes (2*(params v).n))
      (randomFunction ((params v).n+32) (params v).n)) coins)
    (fun ((rest,F),strategy) => msgKeyDistinguisher v limits strategy o F
      (rest.val.drop (params v).n) (deriveKey o "DSM/sphincs/v2/prf-msg" (rest.val.take (params v).n)))

def idealMsgKeyProbability (v : Variant) (limits : Limits) (o : Oracle Id)
    (coins : FiniteExperiment Strategy) : Probability :=
  probability (independentProduct (independentProduct (independentProduct
      (uniformBytes (params v).n) uniformMasterSeed)
      (randomFunction ((params v).n+32) (params v).n)) coins)
    (fun (((pkSeed,L),F),strategy) => msgKeyDistinguisher v limits strategy o F pkSeed.val L.val)

theorem msg_key_real_equivalence (v : Variant) (limits : Limits) (o : Oracle Id)
    (coins : FiniteExperiment Strategy) :
    idealPrfFunctionProbability v limits o coins = realMsgKeyProbability v limits o coins :=
  probability_congr _ _ _ (fun ⟨⟨rest,F⟩,strategy⟩ =>
    (msg_key_distinguisher_exact v limits strategy o F rest).symm)

/-- Pr[random-PRF forgery] ≤ Pr[uniform-message-key forgery] + Adv_KDF[D],
    D = msgKeyDistinguisher. -/
theorem msg_key_hybrid_bound (v : Variant) (limits : Limits) (o : Oracle Id)
    (coins : FiniteExperiment Strategy) :
    (idealPrfFunctionProbability v limits o coins).numerator *
        (idealMsgKeyProbability v limits o coins).denominator ≤
      (idealMsgKeyProbability v limits o coins).numerator *
        (idealPrfFunctionProbability v limits o coins).denominator +
      gapNumerator (realMsgKeyProbability v limits o coins)
        (idealMsgKeyProbability v limits o coins) := by
  rw [msg_key_real_equivalence]
  exact probability_hybrid_bound _ _

/-! ## Hop 3b: keyed BLAKE3 computing R becomes a random function -/

/-- A 34-byte marker: no derived key (32 bytes) and not the PRF marker (33). -/
def MARK2 : Bytes := List.replicate 34 0

def routeMsg (o : Oracle Id) (H : Bytes → Nat → Bytes) : Oracle Id :=
  fun r => if r.mode = 1 ∧ r.key = MARK2 then H r.input r.outLen else patchMsgKey o MARK2 r

def msgFunctionDistinguisher (v : Variant) (limits : Limits) (strategy : Strategy)
    (o : Oracle Id) (F : Bytes → Nat → Bytes) (pkSeed : Bytes) (H : Bytes → Nat → Bytes) : Bool :=
  seedDistinguisher v limits strategy (routeMsg (routePrf o F) H)
    (zeros (params v).n ++ zeros (params v).n ++ pkSeed)

theorem rm_keyed (o : Oracle Id) (H : Bytes → Nat → Bytes) (key input : Bytes) (len : Nat)
    (ne : key ≠ MARK2) : routeMsg o H ⟨1,"",key,input,len⟩ = o ⟨1,"",key,input,len⟩ := by
  simp [routeMsg, ne, patchMsgKey]

theorem rm_mark (o : Oracle Id) (H : Bytes → Nat → Bytes) (input : Bytes) (len : Nat) :
    routeMsg o H ⟨1,"",MARK2,input,len⟩ = H input len := by
  simp [routeMsg]

theorem rm_unkeyed (o : Oracle Id) (H : Bytes → Nat → Bytes) (mode : Nat) (ne : mode ≠ 1)
    (c : String) (key input : Bytes) (len : Nat) :
    routeMsg o H ⟨mode,c,key,input,len⟩ = patchMsgKey o MARK2 ⟨mode,c,key,input,len⟩ := by
  simp [routeMsg, ne]

theorem not_mark2_of_width (b : Bytes) (w : b.length = 32) : b ≠ MARK2 := by
  intro h; rw [h] at w; simp [MARK2] at w

theorem mark_ne_mark2 : MARK ≠ MARK2 := by decide

theorem msg_function_distinguisher_exact (v : Variant) (limits : Limits) (strategy : Strategy)
    (o : Oracle Id) (widths : OutputWidths o) (F : Bytes → Nat → Bytes)
    (pkSeed : Wire (params v).n) (L : Wire 32) :
    msgFunctionDistinguisher v limits strategy o F pkSeed.val (fun x len => o ⟨1,"",L.val,x,len⟩) =
      msgKeyDistinguisher v limits strategy o F pkSeed.val L.val := by
  have toO : ∀ mode c key input len, mode ≠ 1 → c ≠ "DSM/sphincs/v2/prf" →
      c ≠ "DSM/sphincs/v2/prf-msg" →
      routeMsg (routePrf o F) (fun x len => o ⟨1,"",L.val,x,len⟩) ⟨mode,c,key,input,len⟩ =
        o ⟨mode,c,key,input,len⟩ ∧
      patchMsgKey (routePrf o F) L.val ⟨mode,c,key,input,len⟩ = o ⟨mode,c,key,input,len⟩ := by
    intro mode c key input len hm hp hq
    refine ⟨?_, ?_⟩
    · rw [rm_unkeyed _ _ _ hm, msgpatch_other _ _ _ hq, route_unkeyed _ _ _ hm, patch_other _ _ _ hp]
    · rw [msgpatch_other _ _ _ hq, route_unkeyed _ _ _ hm, patch_other _ _ _ hp]
  have dThash : ∀ x, routeMsg (routePrf o F) (fun x len => o ⟨1,"",L.val,x,len⟩)
      ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩ =
      patchMsgKey (routePrf o F) L.val ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩ := fun x => by
    rw [(toO _ _ _ _ _ (by decide) (by decide) (by decide)).1,
      (toO _ _ _ _ _ (by decide) (by decide) (by decide)).2]
  have hMsg : ∀ x len, routeMsg (routePrf o F) (fun x len => o ⟨1,"",L.val,x,len⟩)
      ⟨2,"DSM/sphincs/v2/h-msg",[],x,len⟩ =
      patchMsgKey (routePrf o F) L.val ⟨2,"DSM/sphincs/v2/h-msg",[],x,len⟩ := fun x len => by
    rw [(toO _ _ _ _ _ (by decide) (by decide) (by decide)).1,
      (toO _ _ _ _ _ (by decide) (by decide) (by decide)).2]
  have tkW : ∀ x, (patchMsgKey (routePrf o F) L.val ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩).length = 32 :=
    fun x => by rw [(toO _ _ _ _ _ (by decide) (by decide) (by decide)).2]; exact widths _
  have agreeAt : ∀ x, KeyedAgreeAt (routeMsg (routePrf o F) (fun x len => o ⟨1,"",L.val,x,len⟩))
      (patchMsgKey (routePrf o F) L.val)
      (patchMsgKey (routePrf o F) L.val ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩) MARK MARK := fun x =>
    ⟨fun input len => by rw [rm_keyed _ _ _ _ _ (not_mark2_of_width _ (tkW x)), msgpatch_keyed],
     fun input len => by rw [rm_keyed _ _ _ _ _ mark_ne_mark2, msgpatch_keyed]⟩
  have dMsg₁ : ∀ x, routeMsg (routePrf o F) (fun x len => o ⟨1,"",L.val,x,len⟩)
      ⟨0,"DSM/sphincs/v2/prf-msg",[],x,32⟩ = MARK2 := fun x => by
    rw [rm_unkeyed _ _ _ (by decide), msgpatch_msg]
  have dPrf₁ : ∀ x, routeMsg (routePrf o F) (fun x len => o ⟨1,"",L.val,x,len⟩)
      ⟨0,"DSM/sphincs/v2/prf",[],x,32⟩ = MARK := fun x => by
    rw [rm_unkeyed _ _ _ (by decide), msgpatch_other _ _ _ (by decide), route_unkeyed _ _ _ (by decide),
      patch_prf]
  have dPrf₂ : ∀ x, patchMsgKey (routePrf o F) L.val ⟨0,"DSM/sphincs/v2/prf",[],x,32⟩ = MARK :=
    fun x => by rw [msgpatch_other _ _ _ (by decide), route_unkeyed _ _ _ (by decide), patch_prf]
  have rAgree : ∀ input len, routeMsg (routePrf o F) (fun x len => o ⟨1,"",L.val,x,len⟩)
      ⟨1,"",MARK2,input,len⟩ = patchMsgKey (routePrf o F) L.val ⟨1,"",L.val,input,len⟩ := by
    intro input len
    rw [rm_mark, msgpatch_keyed, route_keyed _ _ _ _ _ (not_mark_of_width _ L.property)]
  have root : ∀ seed, xmssNode (routeMsg (routePrf o F) (fun x len => o ⟨1,"",L.val,x,len⟩)) (params v)
      (patchMsgKey (routePrf o F) L.val ⟨0,"DSM/sphincs/v2/thash",[],seed,32⟩) MARK seed
      {layer := (params v).d-1} 0 (params v).hp = xmssNode (patchMsgKey (routePrf o F) L.val) (params v)
      (patchMsgKey (routePrf o F) L.val ⟨0,"DSM/sphincs/v2/thash",[],seed,32⟩) MARK seed
      {layer := (params v).d-1} 0 (params v).hp := fun seed => xmssNode_agree (agreeAt seed) _ _ _ _
  have el : (zeros (params v).n ++ zeros (params v).n ++ pkSeed.val).length = 3*(params v).n := by
    simp only [zeros, List.length_append, List.length_replicate, pkSeed.property]; omega
  have kp1 : (keypairFromExpansion (routeMsg (routePrf o F) (fun x len => o ⟨1,"",L.val,x,len⟩)) v
        (zeros (params v).n ++ zeros (params v).n ++ pkSeed.val)).1 =
      (keypairFromExpansion (patchMsgKey (routePrf o F) L.val) v
        (zeros (params v).n ++ zeros (params v).n ++ pkSeed.val)).1 := by
    simp only [keypairFromExpansion, deriveKey, dThash, dPrf₁, dPrf₂, root]
  unfold msgFunctionDistinguisher msgKeyDistinguisher
  apply seedDistinguisher_congr
  · exact kp1
  · intro m
    rw [kp_shape _ v _ el, kp_shape (patchMsgKey (routePrf o F) L.val) v _ el, kp1]
    exact sign_congr_msg v _ _ MARK MARK MARK2 L.val _ _ agreeAt dThash hMsg (dMsg₁ _)
      (msgpatch_msg _ _ _) rAgree (dPrf₁ _) (dPrf₂ _) rfl rfl rfl m
  · exact verify_congr v _ _ MARK MARK agreeAt dThash hMsg

/-! ## Hop 3b, probabilities -/

/-- A uniformly random function on inputs of at most `maxLen` bytes. Inputs of
    different lengths are kept apart by indexing the table with the value of
    `1 :: x`. R's input is PK.seed ‖ M, at most n + maxMessageBytes bytes. -/
def randomFunctionUpTo (maxLen outLen : Nat) : FiniteExperiment (Bytes → Nat → Bytes) :=
  ⟨(256^outLen)^(256^(maxLen+1)), Nat.pow_pos (Nat.pow_pos (by decide)), fun i x len =>
    if x.length ≤ maxLen ∧ len = outLen then
      be outLen (i.val / (256^outLen)^(toInt (1 :: x)) % 256^outLen) else []⟩

def realMsgFunctionProbability (v : Variant) (limits : Limits) (o : Oracle Id)
    (coins : FiniteExperiment Strategy) : Probability :=
  probability (independentProduct (independentProduct (independentProduct
      (uniformBytes (params v).n) uniformMasterSeed)
      (randomFunction ((params v).n+32) (params v).n)) coins)
    (fun (((pkSeed,L),F),strategy) => msgFunctionDistinguisher v limits strategy o F pkSeed.val
      (fun x len => o ⟨1,"",L.val,x,len⟩))

def idealMsgFunctionProbability (v : Variant) (limits : Limits) (o : Oracle Id)
    (coins : FiniteExperiment Strategy) : Probability :=
  probability (independentProduct (independentProduct (independentProduct
      (uniformBytes (params v).n) (randomFunctionUpTo ((params v).n + limits.maxMessageBytes) (params v).n))
      (randomFunction ((params v).n+32) (params v).n)) coins)
    (fun (((pkSeed,H),F),strategy) => msgFunctionDistinguisher v limits strategy o F pkSeed.val H)

theorem msg_function_real_equivalence (v : Variant) (limits : Limits) (o : Oracle Id)
    (widths : OutputWidths o) (coins : FiniteExperiment Strategy) :
    idealMsgKeyProbability v limits o coins = realMsgFunctionProbability v limits o coins :=
  probability_congr _ _ _ (fun ⟨⟨⟨pkSeed,L⟩,F⟩,strategy⟩ =>
    (msg_function_distinguisher_exact v limits strategy o widths F pkSeed L).symm)

/-- Pr[uniform-message-key forgery] ≤ Pr[random-R forgery] + Adv_PRF[D],
    D = msgFunctionDistinguisher. After this hop neither SK.seed nor SK.prf
    appears in the game. -/
theorem msg_function_hybrid_bound (v : Variant) (limits : Limits) (o : Oracle Id)
    (widths : OutputWidths o) (coins : FiniteExperiment Strategy) :
    (idealMsgKeyProbability v limits o coins).numerator *
        (idealMsgFunctionProbability v limits o coins).denominator ≤
      (idealMsgFunctionProbability v limits o coins).numerator *
        (idealMsgKeyProbability v limits o coins).denominator +
      gapNumerator (realMsgFunctionProbability v limits o coins)
        (idealMsgFunctionProbability v limits o coins) := by
  rw [msg_function_real_equivalence v limits o widths]
  exact probability_hybrid_bound _ _

#print axioms sign_congr_msg
#print axioms msg_key_distinguisher_exact
#print axioms msg_key_hybrid_bound
#print axioms msg_function_distinguisher_exact
#print axioms msg_function_hybrid_bound
end DSM.Sphincs.Security
