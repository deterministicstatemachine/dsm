-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.MsgPrfHybrid

/- Modular proof, milestone 2 (part 4): C15/C16's function distinguishers
   query their challenge function only on its PRF domain.

   C15 hop 2b and C16 hop 3b compare the signer run with keyed BLAKE3 against
   the run with a random function that is defined only on the PRF domain
   (`randomFunction`: PK.seed ‖ ADRS, n+32 bytes; `randomFunctionUpTo`:
   PK.seed ‖ M). For those hops to be advantages in a PRF game whose real
   oracle is also restricted to that domain, the distinguisher's output must
   not depend on the challenge outside the domain. This file proves that:

   * `function_distinguisher_dom`: hop 2b's distinguisher reads `G` only at
     (x, n) with |x| = n + 32;
   * `msg_function_distinguisher_dom`: hop 3b's distinguisher reads `H` only
     at (PK.seed ‖ M, n) for legal messages M, so |x| ≤ n + maxMessageBytes.

   The proofs restrict `OracleAgree`'s agreement to the PRF calls of one
   seed (`KeyedAgreeOn`) and the signing oracle to legal messages
   (`run_congr_legal`). No new assumption. -/
namespace DSM.Sphincs
open DSM.Sphincs.Security

/-- Agreement on the thash key, and on PRF calls under one seed. -/
structure KeyedAgreeOn (o₁ o₂ : Oracle Id) (p : Params) (tk M K seed : Bytes) : Prop where
  thash : ∀ input len, o₁ ⟨1,"",tk,input,len⟩ = o₂ ⟨1,"",tk,input,len⟩
  renamed : ∀ a : Adrs, prf o₁ p M seed a = prf o₂ p K seed a

section
variable {o₁ o₂ : Oracle Id} {p : Params} {tk M K seed : Bytes} (h : KeyedAgreeOn o₁ o₂ p tk M K seed)
include h

theorem KeyedAgreeOn.th : KeyedAgreeAt o₁ o₂ tk tk tk := ⟨h.thash, h.thash⟩

theorem wotsSign_on (a : Adrs) (msg : Bytes) :
    wotsSign o₁ p tk M seed a msg = wotsSign o₂ p tk K seed a msg := by
  simp only [wotsSign, h.renamed, chain_agree h.th]

theorem wotsPkgen_on (a : Adrs) : wotsPkgen o₁ p tk M seed a = wotsPkgen o₂ p tk K seed a := by
  simp only [wotsPkgen, h.renamed, chain_agree h.th, wotsCompress_agree h.th]

theorem xmssNode_on (a : Adrs) (idx height : Nat) :
    xmssNode o₁ p tk M seed a idx height = xmssNode o₂ p tk K seed a idx height := by
  induction height generalizing idx with
  | zero => simp only [xmssNode, wotsPkgen_on h]
  | succ r ih => simp only [xmssNode, ih, thash_agree h.th]

theorem xmssSign_on (a : Adrs) (idx : Nat) (msg : Bytes) :
    xmssSign o₁ p tk M seed a idx msg = xmssSign o₂ p tk K seed a idx msg := by
  simp only [xmssSign, xmssNode_on h, wotsSign_on h]

theorem htSignTail_on (layer tree : Nat) (node : Bytes) (remaining : Nat) :
    htSignTail o₁ p tk M seed layer tree node remaining =
      htSignTail o₂ p tk K seed layer tree node remaining := by
  induction remaining generalizing layer tree node with
  | zero => rfl
  | succ r ih => simp only [htSignTail, xmssSign_on h, xmssPkFromSig_agree h.th, ih]

theorem htSign_on (msg : Bytes) (idxTree idxLeaf : Nat) :
    htSign o₁ p tk M seed msg idxTree idxLeaf = htSign o₂ p tk K seed msg idxTree idxLeaf := by
  simp only [htSign, xmssSign_on h, xmssPkFromSig_agree h.th, htSignTail_on h]

theorem forsSecret_on (a : Adrs) (idx : Nat) :
    forsSecret o₁ p M seed a idx = forsSecret o₂ p K seed a idx := by
  simp only [forsSecret, h.renamed]

theorem forsNode_on (a : Adrs) (idx height : Nat) :
    forsNode o₁ p tk M seed a idx height = forsNode o₂ p tk K seed a idx height := by
  induction height generalizing idx with
  | zero => simp only [forsNode, forsSecret_on h, thash_agree h.th]
  | succ r ih => simp only [forsNode, ih, thash_agree h.th]

theorem forsSign_on (a : Adrs) (md : Bytes) :
    forsSign o₁ p tk M seed a md = forsSign o₂ p tk K seed a md := by
  simp only [forsSign, forsSecret_on h, forsNode_on h]
end

/-- `sign_congr` with agreement only on the PRF calls of the key's seed, and
    on the one R request of message `m`. -/
theorem sign_congr_on (v : Variant) (o₁ o₂ : Oracle Id) (M K sk₁ sk₂ m : Bytes)
    (htk : KeyedAgreeOn o₁ o₂ (params v)
      (o₂ ⟨0,"DSM/sphincs/v2/thash",[],slice sk₂ (2*(params v).n) (params v).n,32⟩) M K
      (slice sk₂ (2*(params v).n) (params v).n))
    (dThash : ∀ x, o₁ ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩ = o₂ ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩)
    (hMsg : ∀ x len, o₁ ⟨2,"DSM/sphincs/v2/h-msg",[],x,len⟩ = o₂ ⟨2,"DSM/sphincs/v2/h-msg",[],x,len⟩)
    (dMsgKey : ∀ x, o₁ ⟨0,"DSM/sphincs/v2/prf-msg",[],x,32⟩ =
      o₂ ⟨0,"DSM/sphincs/v2/prf-msg",[],x,32⟩)
    (rAgree : o₁ ⟨1,"",o₂ ⟨0,"DSM/sphincs/v2/prf-msg",[],slice sk₂ (params v).n (params v).n,32⟩,
        slice sk₂ (2*(params v).n) (params v).n ++ m,(params v).n⟩ =
      o₂ ⟨1,"",o₂ ⟨0,"DSM/sphincs/v2/prf-msg",[],slice sk₂ (params v).n (params v).n,32⟩,
        slice sk₂ (2*(params v).n) (params v).n ++ m,(params v).n⟩)
    (dPrf₁ : o₁ ⟨0,"DSM/sphincs/v2/prf",[],sk₁.take (params v).n,32⟩ = M)
    (dPrf₂ : o₂ ⟨0,"DSM/sphincs/v2/prf",[],sk₂.take (params v).n,32⟩ = K)
    (len : sk₁.length = sk₂.length)
    (seedEq : slice sk₁ (2*(params v).n) (params v).n = slice sk₂ (2*(params v).n) (params v).n)
    (prfEq : slice sk₁ (params v).n (params v).n = slice sk₂ (params v).n (params v).n)
    (rootEq : sk₁.drop (3*(params v).n) = sk₂.drop (3*(params v).n)) :
    sign o₁ v sk₁ m = sign o₂ v sk₂ m := by
  simp only [sign, deriveKey, keyed, hmsg, id_bind, id_pure, len, seedEq, prfEq, rootEq,
    dThash, dMsgKey, rAgree, hMsg, dPrf₁, dPrf₂,
    forsSign_on htk, forsPkFromSig_agree htk.th,
    htSign_on htk, htRoot_agree htk.th]

namespace Security

/-- The signing oracle is consulted on legal messages only. -/
theorem run_congr_legal (limits : Limits) (s₁ s₂ : Bytes → Option Bytes)
    (h : ∀ m, legal limits m = true → s₁ m = s₂ m) (strategy : Strategy) :
    ∀ fuel view, run limits s₁ strategy fuel view = run limits s₂ strategy fuel view
  | 0, _ => rfl
  | fuel+1, view => by
    simp only [run]
    cases strategy view with
    | forge m s => rfl
    | query m =>
      have : advance limits s₁ view m = advance limits s₂ view m := by
        simp only [advance, reply]
        by_cases hl : legal limits m = true
        · rw [h m hl]
        · simp [hl]
      show run limits s₁ strategy fuel (advance limits s₁ view m) =
        run limits s₂ strategy fuel (advance limits s₂ view m)
      rw [this]; exact run_congr_legal limits s₁ s₂ h strategy fuel _

theorem seedDistinguisher_congr_legal (v : Variant) (limits : Limits) (strategy : Strategy)
    (o₁ o₂ : Oracle Id) (e₁ e₂ : Bytes)
    (hpk : (keypairFromExpansion o₁ v e₁).1 = (keypairFromExpansion o₂ v e₂).1)
    (hsign : ∀ m, legal limits m = true → sign o₁ v (keypairFromExpansion o₁ v e₁).2 m =
      sign o₂ v (keypairFromExpansion o₂ v e₂).2 m)
    (hver : ∀ pk m s, verify o₁ v pk m s = verify o₂ v pk m s) :
    seedDistinguisher v limits strategy o₁ e₁ = seedDistinguisher v limits strategy o₂ e₂ := by
  have hv : verify o₁ v = verify o₂ v := by
    funext pk m s; exact hver pk m s
  have hrun := run_congr_legal limits (fun m => sign o₁ v (keypairFromExpansion o₁ v e₁).2 m)
    (fun m => sign o₂ v (keypairFromExpansion o₂ v e₂).2 m) hsign strategy limits.signingAttempts
    ⟨(keypairFromExpansion o₂ v e₂).1, []⟩
  unfold seedDistinguisher expandedExperiment
  revert hpk hrun
  cases keypairFromExpansion o₁ v e₁
  cases keypairFromExpansion o₂ v e₂
  intro hpk hrun
  simp only at hpk hrun ⊢
  rw [hpk, hrun, hv]

/-- Hop 2b's distinguisher reads its challenge only on the SKG domain. -/
theorem function_distinguisher_dom (v : Variant) (limits : Limits) (strategy : Strategy)
    (o : Oracle Id) (widths : OutputWidths o) (rest : Bytes) (hr : rest.length = 2*(params v).n)
    (G G' : Bytes → Nat → Bytes)
    (hG : ∀ x, x.length = (params v).n + 32 → G x (params v).n = G' x (params v).n) :
    functionDistinguisher v limits strategy o rest G = functionDistinguisher v limits strategy o rest G' := by
  have same : ∀ r : Request, ¬(r.mode = 1 ∧ r.key = MARK) → routePrf o G r = routePrf o G' r := by
    intro r h; simp only [routePrf, h, if_false]
  have dThash : ∀ x, routePrf o G ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩ =
      routePrf o G' ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩ := fun x => same _ (by simp)
  have hMsg : ∀ x len, routePrf o G ⟨2,"DSM/sphincs/v2/h-msg",[],x,len⟩ =
      routePrf o G' ⟨2,"DSM/sphincs/v2/h-msg",[],x,len⟩ := fun x len => same _ (by simp)
  have dMsgKey : ∀ x, routePrf o G ⟨0,"DSM/sphincs/v2/prf-msg",[],x,32⟩ =
      routePrf o G' ⟨0,"DSM/sphincs/v2/prf-msg",[],x,32⟩ := fun x => same _ (by simp)
  have keyedOther : ∀ key input len, key ≠ MARK →
      routePrf o G ⟨1,"",key,input,len⟩ = routePrf o G' ⟨1,"",key,input,len⟩ :=
    fun key input len ne => same _ (by simp [ne])
  have tkW : ∀ x, (routePrf o G' ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩).length = 32 := fun x => by
    rw [route_unkeyed _ _ _ (by decide), patch_other _ _ _ (by decide)]; exact widths _
  have mkW : ∀ x, (routePrf o G' ⟨0,"DSM/sphincs/v2/prf-msg",[],x,32⟩).length = 32 := fun x => by
    rw [route_unkeyed _ _ _ (by decide), patch_other _ _ _ (by decide)]; exact widths _
  have on : ∀ seed : Bytes, seed.length = (params v).n → KeyedAgreeOn (routePrf o G) (routePrf o G')
      (params v) (routePrf o G' ⟨0,"DSM/sphincs/v2/thash",[],seed,32⟩) MARK MARK seed :=
    fun seed hs => ⟨fun input len => keyedOther _ _ _ (not_mark_of_width _ (tkW seed)), fun a => by
      change routePrf o G ⟨1,"",MARK,seed ++ a.bytes,(params v).n⟩ =
        routePrf o G' ⟨1,"",MARK,seed ++ a.bytes,(params v).n⟩
      rw [route_mark, route_mark]
      exact hG _ (by simp [hs, address_width])⟩
  have dPrf : ∀ (H : Bytes → Nat → Bytes) x, routePrf o H ⟨0,"DSM/sphincs/v2/prf",[],x,32⟩ = MARK :=
    fun H x => by rw [route_unkeyed _ _ _ (by decide), patch_prf]
  have el : (zeros (params v).n ++ rest).length = 3*(params v).n := by
    simp only [zeros, List.length_append, List.length_replicate, hr]; omega
  have sl : (slice (zeros (params v).n ++ rest) (2*(params v).n) (params v).n).length = (params v).n := by
    simp only [slice, List.length_take, List.length_drop, el]; omega
  have root := xmssNode_on (on _ sl) {layer := (params v).d-1} 0 (params v).hp
  have kp1 : (keypairFromExpansion (routePrf o G) v (zeros (params v).n ++ rest)).1 =
      (keypairFromExpansion (routePrf o G') v (zeros (params v).n ++ rest)).1 := by
    simp only [keypairFromExpansion, deriveKey, dThash, dPrf, root]
  unfold functionDistinguisher
  apply seedDistinguisher_congr
  · exact kp1
  · intro m
    rw [kp_shape _ v _ el, kp_shape (routePrf o G') v _ el, kp1]
    have sl' : (slice (zeros (params v).n ++ rest ++ (keypairFromExpansion (routePrf o G') v
        (zeros (params v).n ++ rest)).1.drop (params v).n) (2*(params v).n) (params v).n).length =
        (params v).n := by
      simp only [slice, List.length_take, List.length_drop, List.length_append, el]; omega
    exact sign_congr_on v _ _ MARK MARK _ _ m (on _ sl') dThash hMsg dMsgKey
      (keyedOther _ _ _ (not_mark_of_width _ (mkW _))) (dPrf _ _) (dPrf _ _) rfl rfl rfl rfl
  · exact verify_congr v _ _ [] [] (fun x => ⟨fun input len =>
      keyedOther _ _ _ (not_mark_of_width _ (tkW x)), fun input len => keyedOther _ _ _ (by decide)⟩)
      dThash hMsg

/-- Hop 3b's distinguisher reads its challenge only at `PK.seed ‖ M` for legal
    `M`, with n-byte outputs. -/
theorem msg_function_distinguisher_dom (v : Variant) (limits : Limits) (strategy : Strategy)
    (o : Oracle Id) (widths : OutputWidths o) (F : Bytes → Nat → Bytes) (pkSeed : Bytes)
    (hp : pkSeed.length = (params v).n) (H H' : Bytes → Nat → Bytes)
    (hH : ∀ x, x.length ≤ (params v).n + limits.maxMessageBytes →
      H x (params v).n = H' x (params v).n) :
    msgFunctionDistinguisher v limits strategy o F pkSeed H =
      msgFunctionDistinguisher v limits strategy o F pkSeed H' := by
  have same : ∀ r : Request, ¬(r.mode = 1 ∧ r.key = MARK2) →
      routeMsg (routePrf o F) H r = routeMsg (routePrf o F) H' r := by
    intro r h; simp only [routeMsg, h, if_false]
  have dThash : ∀ x, routeMsg (routePrf o F) H ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩ =
      routeMsg (routePrf o F) H' ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩ := fun x => same _ (by simp)
  have hMsg : ∀ x len, routeMsg (routePrf o F) H ⟨2,"DSM/sphincs/v2/h-msg",[],x,len⟩ =
      routeMsg (routePrf o F) H' ⟨2,"DSM/sphincs/v2/h-msg",[],x,len⟩ := fun x len => same _ (by simp)
  have dMsgKey : ∀ x, routeMsg (routePrf o F) H ⟨0,"DSM/sphincs/v2/prf-msg",[],x,32⟩ =
      routeMsg (routePrf o F) H' ⟨0,"DSM/sphincs/v2/prf-msg",[],x,32⟩ := fun x => same _ (by simp)
  have keyedOther : ∀ key input len, key ≠ MARK2 →
      routeMsg (routePrf o F) H ⟨1,"",key,input,len⟩ = routeMsg (routePrf o F) H' ⟨1,"",key,input,len⟩ :=
    fun key input len ne => same _ (by simp [ne])
  have tkW : ∀ x, (routeMsg (routePrf o F) H' ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩).length = 32 :=
    fun x => by
      rw [rm_unkeyed _ _ _ (by decide), msgpatch_other _ _ _ (by decide), route_unkeyed _ _ _ (by decide),
        patch_other _ _ _ (by decide)]
      exact widths _
  have agree : ∀ x, KeyedAgreeAt (routeMsg (routePrf o F) H) (routeMsg (routePrf o F) H')
      (routeMsg (routePrf o F) H' ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩) MARK MARK := fun x =>
    ⟨fun input len => keyedOther _ _ _ (not_mark2_of_width _ (tkW x)),
     fun input len => keyedOther _ _ _ mark_ne_mark2⟩
  have on : ∀ seed : Bytes, KeyedAgreeOn (routeMsg (routePrf o F) H) (routeMsg (routePrf o F) H')
      (params v) (routeMsg (routePrf o F) H' ⟨0,"DSM/sphincs/v2/thash",[],seed,32⟩) MARK MARK seed :=
    fun seed => ⟨(agree seed).thash, fun a => (agree seed).renamed _ _⟩
  have dPrf : ∀ (H : Bytes → Nat → Bytes) x,
      routeMsg (routePrf o F) H ⟨0,"DSM/sphincs/v2/prf",[],x,32⟩ = MARK := fun H x => by
    rw [rm_unkeyed _ _ _ (by decide), msgpatch_other _ _ _ (by decide), route_unkeyed _ _ _ (by decide),
      patch_prf]
  have dMsg : ∀ (H : Bytes → Nat → Bytes) x,
      routeMsg (routePrf o F) H ⟨0,"DSM/sphincs/v2/prf-msg",[],x,32⟩ = MARK2 := fun H x => by
    rw [rm_unkeyed _ _ _ (by decide), msgpatch_msg]
  have el : (zeros (params v).n ++ zeros (params v).n ++ pkSeed).length = 3*(params v).n := by
    simp only [zeros, List.length_append, List.length_replicate, hp]; omega
  have root := xmssNode_agree (p := params v) (agree (slice (zeros (params v).n ++ zeros (params v).n ++ pkSeed)
    (2*(params v).n) (params v).n)) (slice (zeros (params v).n ++ zeros (params v).n ++ pkSeed)
    (2*(params v).n) (params v).n) {layer := (params v).d-1} 0 (params v).hp
  have kp1 : (keypairFromExpansion (routeMsg (routePrf o F) H) v
        (zeros (params v).n ++ zeros (params v).n ++ pkSeed)).1 =
      (keypairFromExpansion (routeMsg (routePrf o F) H') v
        (zeros (params v).n ++ zeros (params v).n ++ pkSeed)).1 := by
    simp only [keypairFromExpansion, deriveKey, dThash, dPrf, root]
  unfold msgFunctionDistinguisher
  apply seedDistinguisher_congr_legal
  · exact kp1
  · intro m hm
    rw [kp_shape _ v _ el, kp_shape (routeMsg (routePrf o F) H') v _ el, kp1]
    have hm' : m.length ≤ limits.maxMessageBytes := by
      simp only [legal, Bool.and_eq_true, decide_eq_true_eq] at hm; exact hm.2
    have sl : (slice (zeros (params v).n ++ zeros (params v).n ++ pkSeed ++
        (keypairFromExpansion (routeMsg (routePrf o F) H') v
          (zeros (params v).n ++ zeros (params v).n ++ pkSeed)).1.drop (params v).n)
          (2*(params v).n) (params v).n).length = (params v).n := by
      simp only [slice, List.length_take, List.length_drop, List.length_append, el]; omega
    refine sign_congr_on v _ _ MARK MARK _ _ m (on _) dThash hMsg dMsgKey ?_ (dPrf _ _) (dPrf _ _)
      rfl rfl rfl rfl
    rw [dMsg, rm_mark, rm_mark]
    exact hH _ (by simp only [List.length_append, sl]; omega)
  · exact verify_congr v _ _ MARK MARK agree dThash hMsg

#print axioms sign_congr_on
#print axioms function_distinguisher_dom
#print axioms msg_function_distinguisher_dom
end Security
end DSM.Sphincs
