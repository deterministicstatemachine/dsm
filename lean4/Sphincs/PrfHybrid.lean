-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.SeedHybrid
import Sphincs.OracleAgree

/- The PRF hybrids for DSM construction v2, after the seed hybrid
   (SeedHybrid.lean). Hop 2a replaces the derived PRF key
   K = derive_key("DSM/sphincs/v2/prf", SK.seed) by a uniform 32-byte key; hop
   2b replaces keyed BLAKE3 under that key by a uniformly random function on
   PRF inputs (PK.seed ‖ ADRS, n+32 bytes). Each hop has an explicit
   distinguisher that never reads SK.seed, proved to reproduce the previous
   game exactly; the bound is the exact rational gap. No PRF, KDF or BLAKE3
   hardness premise is declared: the advantage terms are those of the
   constructed distinguishers. -/
namespace DSM.Sphincs.Security

/-! ## Congruence: equal requests give equal games -/

theorem id_bind {α β : Type} (x : Id α) (f : α → Id β) : x >>= f = f x := rfl
theorem id_pure {α : Type} (a : α) : (pure a : Id α) = a := rfl

theorem probability_congr {α : Type} (space : FiniteExperiment α) (e₁ e₂ : α → Bool)
    (same : ∀ x, e₁ x = e₂ x) : probability space e₁ = probability space e₂ := by
  have : e₁ = e₂ := funext same
  subst this; rfl

theorem seedDistinguisher_congr (v : Variant) (limits : Limits) (strategy : Strategy)
    (o₁ o₂ : Oracle Id) (e₁ e₂ : Bytes)
    (hpk : (keypairFromExpansion o₁ v e₁).1 = (keypairFromExpansion o₂ v e₂).1)
    (hsign : ∀ m, sign o₁ v (keypairFromExpansion o₁ v e₁).2 m =
      sign o₂ v (keypairFromExpansion o₂ v e₂).2 m)
    (hver : ∀ pk m s, verify o₁ v pk m s = verify o₂ v pk m s) :
    seedDistinguisher v limits strategy o₁ e₁ = seedDistinguisher v limits strategy o₂ e₂ := by
  have hv : verify o₁ v = verify o₂ v := by
    funext pk m s; exact hver pk m s
  have hs : (fun m => sign o₁ v (keypairFromExpansion o₁ v e₁).2 m) =
      (fun m => sign o₂ v (keypairFromExpansion o₂ v e₂).2 m) := funext hsign
  unfold seedDistinguisher expandedExperiment
  revert hpk hs
  cases keypairFromExpansion o₁ v e₁
  cases keypairFromExpansion o₂ v e₂
  intro hpk hs
  simp only at hpk hs ⊢
  rw [hpk, hs, hv]

/-- What a world must agree on for verification to agree: the public-seed key
    derivation, the message hash, and every keyed request under the public key
    (`M` never equals a derived public key). -/
theorem verify_congr (v : Variant) (o₁ o₂ : Oracle Id) (M K : Bytes)
    (agree : KeyedAgree o₁ o₂ M K)
    (dThash : ∀ x, o₁ ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩ = o₂ ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩)
    (tkNotM : ∀ x, o₂ ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩ = M → M = K)
    (hMsg : ∀ x len, o₁ ⟨2,"DSM/sphincs/v2/h-msg",[],x,len⟩ = o₂ ⟨2,"DSM/sphincs/v2/h-msg",[],x,len⟩)
    (pk m s : Bytes) : verify o₁ v pk m s = verify o₂ v pk m s := by
  have htk := tkNotM (pk.take (params v).n)
  simp only [verify, deriveKey, hmsg, dThash, hMsg, id_bind, id_pure,
    forsPkFromSig_agree agree htk, htRoot_agree agree htk]


/-- What a world must agree on for signing to agree. Besides the verification
    requests: the message-key derivation and the keyed request computing R, and
    the PRF key derivation, which yields `M` in the first world and `K` in the
    second. The two secret keys may differ only in SK.seed. -/
theorem sign_congr (v : Variant) (o₁ o₂ : Oracle Id) (M K sk₁ sk₂ : Bytes)
    (agree : KeyedAgree o₁ o₂ M K)
    (dThash : ∀ x, o₁ ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩ = o₂ ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩)
    (tkNotM : ∀ x, o₂ ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩ = M → M = K)
    (hMsg : ∀ x len, o₁ ⟨2,"DSM/sphincs/v2/h-msg",[],x,len⟩ = o₂ ⟨2,"DSM/sphincs/v2/h-msg",[],x,len⟩)
    (dMsgKey : ∀ x, o₁ ⟨0,"DSM/sphincs/v2/prf-msg",[],x,32⟩ =
      o₂ ⟨0,"DSM/sphincs/v2/prf-msg",[],x,32⟩)
    (rAgree : ∀ x input len, o₁ ⟨1,"",o₂ ⟨0,"DSM/sphincs/v2/prf-msg",[],x,32⟩,input,len⟩ =
      o₂ ⟨1,"",o₂ ⟨0,"DSM/sphincs/v2/prf-msg",[],x,32⟩,input,len⟩)
    (dPrf₁ : o₁ ⟨0,"DSM/sphincs/v2/prf",[],sk₁.take (params v).n,32⟩ = M)
    (dPrf₂ : o₂ ⟨0,"DSM/sphincs/v2/prf",[],sk₂.take (params v).n,32⟩ = K)
    (len : sk₁.length = sk₂.length)
    (seedEq : slice sk₁ (2*(params v).n) (params v).n = slice sk₂ (2*(params v).n) (params v).n)
    (prfEq : slice sk₁ (params v).n (params v).n = slice sk₂ (params v).n (params v).n)
    (rootEq : sk₁.drop (3*(params v).n) = sk₂.drop (3*(params v).n))
    (m : Bytes) : sign o₁ v sk₁ m = sign o₂ v sk₂ m := by
  have htk := tkNotM (slice sk₂ (2*(params v).n) (params v).n)
  simp only [sign, deriveKey, keyed, hmsg, id_bind, id_pure, len, seedEq, prfEq, rootEq,
    dThash, dMsgKey, rAgree, hMsg, dPrf₁, dPrf₂,
    forsSign_agree agree htk, forsPkFromSig_agree agree htk,
    htSign_agree agree htk, htRoot_agree agree htk]

/-! ## Secret-key layout -/

def zeros (n : Nat) : Bytes := List.replicate n 0

theorem drop_after {α : Type} (X Y : List α) (n k : Nat) (le : n ≤ k)
    (same : X.drop n = Y.drop n) : X.drop k = Y.drop k := by
  obtain ⟨j, rfl⟩ : ∃ j, k = n + j := ⟨k - n, by omega⟩
  have hx : X.drop (n + j) = (X.drop n).drop j := by simp [List.drop_drop]
  have hy : Y.drop (n + j) = (Y.drop n).drop j := by simp [List.drop_drop]
  rw [hx, hy, same]

/-- SK.seed replaced by zeros: every layout fact the signer reads, apart from
    SK.seed itself, is unchanged. -/
theorem zeroed_layout (n : Nat) (e r : Bytes) (elen : e.length = 3*n) :
    let z := zeros n ++ e.drop n
    (z ++ r).length = (e ++ r).length ∧
    slice (z ++ r) (2*n) n = slice (e ++ r) (2*n) n ∧
    slice (z ++ r) n n = slice (e ++ r) n n ∧
    (z ++ r).drop (3*n) = (e ++ r).drop (3*n) ∧
    slice z (2*n) n = slice e (2*n) n ∧
    (e ++ r).take n = e.take n := by
  intro z
  have zlen : z.length = 3*n := by
    show (zeros n ++ e.drop n).length = 3*n
    simp only [zeros, List.length_append, List.length_replicate, List.length_drop, elen]; omega
  have h1 : (z ++ r).drop n = e.drop n ++ r := by
    simp only [z, zeros, List.append_assoc]
    exact List.drop_left' (by simp)
  have h2 : (e ++ r).drop n = e.drop n ++ r := List.drop_append_of_le_length (by omega)
  have base : (z ++ r).drop n = (e ++ r).drop n := by rw [h1, h2]
  have baseZ : z.drop n = e.drop n := by
    simp only [z, zeros]
    exact List.drop_left' (by simp)
  refine ⟨by simp [zlen, elen], ?_, ?_, ?_, ?_, ?_⟩
  · simp only [slice]; rw [drop_after _ _ n (2*n) (by omega) base]
  · simp only [slice]; rw [base]
  · exact drop_after _ _ n (3*n) (by omega) base
  · simp only [slice]; rw [drop_after _ _ n (2*n) (by omega) baseZ]
  · exact List.take_append_of_le_length (by omega)

/-- The secret key is the expansion followed by the root the public key ends in. -/
theorem kp_shape (o : Oracle Id) (v : Variant) (x : Bytes) (xlen : x.length = 3*(params v).n) :
    (keypairFromExpansion o v x).2 = x ++ (keypairFromExpansion o v x).1.drop (params v).n := by
  simp only [keypairFromExpansion]
  rw [List.drop_left' (by simp [slice, xlen]; omega)]

/-! ## Hop 2a: the derived PRF key becomes a uniform key -/

def patchPrfKey (o : Oracle Id) (K : Bytes) : Oracle Id :=
  fun r => if r.mode = 0 ∧ r.context = "DSM/sphincs/v2/prf" then K else o r

theorem patch_keyed (o : Oracle Id) (K key input : Bytes) (len : Nat) :
    patchPrfKey o K ⟨1,"",key,input,len⟩ = o ⟨1,"",key,input,len⟩ := by
  simp [patchPrfKey]

theorem patch_other (o : Oracle Id) (K : Bytes) (c : String) (ne : c ≠ "DSM/sphincs/v2/prf")
    (mode : Nat) (key input : Bytes) (len : Nat) :
    patchPrfKey o K ⟨mode,c,key,input,len⟩ = o ⟨mode,c,key,input,len⟩ := by
  simp [patchPrfKey, ne]

theorem patch_prf (o : Oracle Id) (K input : Bytes) :
    patchPrfKey o K ⟨0,"DSM/sphincs/v2/prf",[],input,32⟩ = K := by
  simp [patchPrfKey]

theorem patch_agree (o : Oracle Id) (K : Bytes) : KeyedAgree (patchPrfKey o K) o K K :=
  ⟨fun _ _ _ _ => patch_keyed _ _ _ _ _, fun _ _ => patch_keyed _ _ _ _ _⟩

/-- Hop 2a's distinguisher. Its challenge is `rest` = SK.prf ‖ PK.seed and a PRF
    key `K`. It never sees SK.seed and puts zeros in its place. -/
def keyDistinguisher (v : Variant) (limits : Limits) (strategy : Strategy) (o : Oracle Id)
    (rest K : Bytes) : Bool :=
  seedDistinguisher v limits strategy (patchPrfKey o K) (zeros (params v).n ++ rest)

theorem key_distinguisher_exact (v : Variant) (limits : Limits) (strategy : Strategy)
    (o : Oracle Id) (e : Wire (3*(params v).n)) :
    keyDistinguisher v limits strategy o (e.val.drop (params v).n)
        (deriveKey o "DSM/sphincs/v2/prf" (e.val.take (params v).n)) =
      seedDistinguisher v limits strategy o e.val := by
  generalize hK : deriveKey o "DSM/sphincs/v2/prf" (e.val.take (params v).n) = K
  have hK' : o ⟨0,"DSM/sphincs/v2/prf",[],e.val.take (params v).n,32⟩ = K := hK
  have dThash : ∀ x, patchPrfKey o K ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩ =
      o ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩ := fun x => patch_other _ _ _ (by decide) _ _ _ _
  have dMsg : ∀ x, patchPrfKey o K ⟨0,"DSM/sphincs/v2/prf-msg",[],x,32⟩ =
      o ⟨0,"DSM/sphincs/v2/prf-msg",[],x,32⟩ := fun x => patch_other _ _ _ (by decide) _ _ _ _
  have hMsg : ∀ x len, patchPrfKey o K ⟨2,"DSM/sphincs/v2/h-msg",[],x,len⟩ =
      o ⟨2,"DSM/sphincs/v2/h-msg",[],x,len⟩ := fun x len => patch_other _ _ _ (by decide) _ _ _ _
  have htk : ∀ x, o ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩ = K → K = K := fun _ _ => rfl
  have root : ∀ seed tk, xmssNode (patchPrfKey o K) (params v) tk K seed {layer := (params v).d-1} 0
      (params v).hp = xmssNode o (params v) tk K seed {layer := (params v).d-1} 0 (params v).hp :=
    fun seed tk => xmssNode_agree (patch_agree o K) (fun _ => rfl) _ _ _ _
  have elen := e.property
  have zlen : (zeros (params v).n ++ e.val.drop (params v).n).length = 3*(params v).n := by
    simp [zeros, elen]; omega
  obtain ⟨_, _, _, _, seedZ, _⟩ := zeroed_layout (params v).n e.val [] elen
  have kp1 : (keypairFromExpansion (patchPrfKey o K) v (zeros (params v).n ++ e.val.drop (params v).n)).1 =
      (keypairFromExpansion o v e.val).1 := by
    simp only [keypairFromExpansion, deriveKey, dThash, patch_prf, seedZ, hK', root]
  unfold keyDistinguisher
  apply seedDistinguisher_congr
  · exact kp1
  · intro m
    rw [kp_shape _ v _ zlen, kp_shape o v _ elen, kp1]
    obtain ⟨l1, l2, l3, l4, _, l6⟩ :=
      zeroed_layout (params v).n e.val ((keypairFromExpansion o v e.val).1.drop (params v).n) elen
    apply sign_congr v (patchPrfKey o K) o K K _ _ (patch_agree o K) dThash htk hMsg dMsg
      (fun _ _ _ => patch_keyed _ _ _ _ _) (patch_prf _ _ _) _ l1 l2 l3 l4
    rw [l6]; exact hK'
  · exact verify_congr v _ _ K K (patch_agree o K) dThash htk hMsg

/-! ## Hop 2a, probabilities -/

def uniformBytes (w : Nat) : FiniteExperiment (Wire w) :=
  ⟨256^w, Nat.pow_pos (by decide), fun i => ⟨be w i.val, be_width w i.val⟩⟩

/-- The previous game (uniform expansion), written as the distinguisher run on
    the real key: the rest of the expansion and the key derived from SK.seed. -/
def realPrfKeyProbability (v : Variant) (limits : Limits) (o : Oracle Id)
    (coins : FiniteExperiment Strategy) : Probability :=
  probability (independentProduct (uniformExpansion v) coins)
    (fun (e,strategy) => keyDistinguisher v limits strategy o (e.val.drop (params v).n)
      (deriveKey o "DSM/sphincs/v2/prf" (e.val.take (params v).n)))

/-- The same distinguisher with an independent uniform 32-byte PRF key. -/
def idealPrfKeyProbability (v : Variant) (limits : Limits) (o : Oracle Id)
    (coins : FiniteExperiment Strategy) : Probability :=
  probability (independentProduct (independentProduct (uniformBytes (2*(params v).n))
      uniformMasterSeed) coins)
    (fun ((rest,K),strategy) => keyDistinguisher v limits strategy o rest.val K.val)

theorem prf_key_real_equivalence (v : Variant) (limits : Limits) (o : Oracle Id)
    (coins : FiniteExperiment Strategy) :
    idealSeedChallengeProbability v limits o coins = realPrfKeyProbability v limits o coins :=
  probability_congr _ _ _ (fun ⟨e,strategy⟩ => (key_distinguisher_exact v limits strategy o e).symm)

/-- Pr[uniform-expansion forgery] ≤ Pr[uniform-PRF-key forgery] + Adv_KDF[D],
    with D = keyDistinguisher: the advantage of telling derive_key("prf", s),
    s uniform, from a uniform key. -/
theorem prf_key_hybrid_bound (v : Variant) (limits : Limits) (o : Oracle Id)
    (coins : FiniteExperiment Strategy) :
    (idealSeedChallengeProbability v limits o coins).numerator *
        (idealPrfKeyProbability v limits o coins).denominator ≤
      (idealPrfKeyProbability v limits o coins).numerator *
        (idealSeedChallengeProbability v limits o coins).denominator +
      gapNumerator (realPrfKeyProbability v limits o coins)
        (idealPrfKeyProbability v limits o coins) := by
  rw [prf_key_real_equivalence]
  exact probability_hybrid_bound _ _

/-! ## Hop 2b: keyed BLAKE3 under the uniform key becomes a random function -/

/-- A 33-byte marker key. Every key the construction derives is 32 bytes, so
    no derived key equals it. -/
def MARK : Bytes := List.replicate 33 0

/-- The distinguisher's world: the PRF key derivation yields MARK, and keyed
    requests under MARK are answered by the challenge function `G`. -/
def routePrf (o : Oracle Id) (G : Bytes → Nat → Bytes) : Oracle Id :=
  fun r => if r.mode = 1 ∧ r.key = MARK then G r.input r.outLen else patchPrfKey o MARK r

def functionDistinguisher (v : Variant) (limits : Limits) (strategy : Strategy) (o : Oracle Id)
    (rest : Bytes) (G : Bytes → Nat → Bytes) : Bool :=
  seedDistinguisher v limits strategy (routePrf o G) (zeros (params v).n ++ rest)

theorem route_keyed (o : Oracle Id) (G : Bytes → Nat → Bytes) (key input : Bytes) (len : Nat)
    (ne : key ≠ MARK) : routePrf o G ⟨1,"",key,input,len⟩ = o ⟨1,"",key,input,len⟩ := by
  simp [routePrf, ne, patchPrfKey]

theorem route_mark (o : Oracle Id) (G : Bytes → Nat → Bytes) (input : Bytes) (len : Nat) :
    routePrf o G ⟨1,"",MARK,input,len⟩ = G input len := by
  simp [routePrf]

theorem route_unkeyed (o : Oracle Id) (G : Bytes → Nat → Bytes) (mode : Nat) (ne : mode ≠ 1)
    (c : String) (key input : Bytes) (len : Nat) :
    routePrf o G ⟨mode,c,key,input,len⟩ = patchPrfKey o MARK ⟨mode,c,key,input,len⟩ := by
  simp [routePrf, ne]

theorem not_mark_of_width (b : Bytes) (w : b.length = 32) : b ≠ MARK := by
  intro h; rw [h] at w; simp [MARK] at w

theorem function_distinguisher_exact (v : Variant) (limits : Limits) (strategy : Strategy)
    (o : Oracle Id) (widths : OutputWidths o) (rest : Wire (2*(params v).n)) (K : Bytes) :
    functionDistinguisher v limits strategy o rest.val (fun x len => o ⟨1,"",K,x,len⟩) =
      keyDistinguisher v limits strategy o rest.val K := by
  have agree : KeyedAgree (routePrf o (fun x len => o ⟨1,"",K,x,len⟩)) (patchPrfKey o K) MARK K :=
    ⟨fun key input len ne => by rw [route_keyed _ _ _ _ _ ne, patch_keyed],
     fun input len => by rw [route_mark, patch_keyed]⟩
  have dThash : ∀ x, routePrf o (fun x len => o ⟨1,"",K,x,len⟩) ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩ =
      patchPrfKey o K ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩ := fun x => by
    rw [route_unkeyed _ _ _ (by decide), patch_other _ _ _ (by decide), patch_other _ _ _ (by decide)]
  have dMsg : ∀ x, routePrf o (fun x len => o ⟨1,"",K,x,len⟩) ⟨0,"DSM/sphincs/v2/prf-msg",[],x,32⟩ =
      patchPrfKey o K ⟨0,"DSM/sphincs/v2/prf-msg",[],x,32⟩ := fun x => by
    rw [route_unkeyed _ _ _ (by decide), patch_other _ _ _ (by decide), patch_other _ _ _ (by decide)]
  have hMsg : ∀ x len, routePrf o (fun x len => o ⟨1,"",K,x,len⟩) ⟨2,"DSM/sphincs/v2/h-msg",[],x,len⟩ =
      patchPrfKey o K ⟨2,"DSM/sphincs/v2/h-msg",[],x,len⟩ := fun x len => by
    rw [route_unkeyed _ _ _ (by decide), patch_other _ _ _ (by decide), patch_other _ _ _ (by decide)]
  have tkNotM : ∀ x, patchPrfKey o K ⟨0,"DSM/sphincs/v2/thash",[],x,32⟩ = MARK → MARK = K := by
    intro x h
    exact absurd h (not_mark_of_width _ (by rw [patch_other _ _ _ (by decide)]; exact widths _))
  have rAgree : ∀ x input len,
      routePrf o (fun x len => o ⟨1,"",K,x,len⟩)
        ⟨1,"",patchPrfKey o K ⟨0,"DSM/sphincs/v2/prf-msg",[],x,32⟩,input,len⟩ =
      patchPrfKey o K ⟨1,"",patchPrfKey o K ⟨0,"DSM/sphincs/v2/prf-msg",[],x,32⟩,input,len⟩ := by
    intro x input len
    rw [route_keyed _ _ _ _ _ (not_mark_of_width _ (by rw [patch_other _ _ _ (by decide)]; exact widths _)),
      patch_keyed]
  have dPrf₁ : ∀ x, routePrf o (fun x len => o ⟨1,"",K,x,len⟩) ⟨0,"DSM/sphincs/v2/prf",[],x,32⟩ = MARK :=
    fun x => by rw [route_unkeyed _ _ _ (by decide), patch_prf]
  have root : ∀ seed, xmssNode (routePrf o (fun x len => o ⟨1,"",K,x,len⟩)) (params v)
      (patchPrfKey o K ⟨0,"DSM/sphincs/v2/thash",[],seed,32⟩) MARK seed {layer := (params v).d-1} 0
      (params v).hp = xmssNode (patchPrfKey o K) (params v)
      (patchPrfKey o K ⟨0,"DSM/sphincs/v2/thash",[],seed,32⟩) K seed {layer := (params v).d-1} 0
      (params v).hp := fun seed => xmssNode_agree agree (tkNotM seed) _ _ _ _
  have zlen : (zeros (params v).n ++ rest.val).length = 3*(params v).n := by
    simp only [zeros, List.length_append, List.length_replicate, rest.property]; omega
  have kp1 : (keypairFromExpansion (routePrf o (fun x len => o ⟨1,"",K,x,len⟩)) v
        (zeros (params v).n ++ rest.val)).1 =
      (keypairFromExpansion (patchPrfKey o K) v (zeros (params v).n ++ rest.val)).1 := by
    simp only [keypairFromExpansion, deriveKey, dThash, dPrf₁, patch_prf, root]
  unfold functionDistinguisher keyDistinguisher
  apply seedDistinguisher_congr
  · exact kp1
  · intro m
    rw [kp_shape _ v _ zlen, kp_shape (patchPrfKey o K) v _ zlen, kp1]
    exact sign_congr v _ _ MARK K _ _ agree dThash tkNotM hMsg dMsg rAgree (dPrf₁ _)
      (patch_prf _ _ _) rfl rfl rfl rfl m
  · exact verify_congr v _ _ MARK K agree dThash tkNotM hMsg

/-! ## Hop 2b, probabilities -/

/-- A uniformly random function on `inLen`-byte inputs with `outLen`-byte
    outputs: ticket `i` lists one output per input, in base 256^outLen digits
    indexed by the input's value. Other shapes answer `[]`; the signer never
    asks them (PRF inputs are PK.seed ‖ ADRS, n+32 bytes, n-byte outputs). -/
def randomFunction (inLen outLen : Nat) : FiniteExperiment (Bytes → Nat → Bytes) :=
  ⟨(256^outLen)^(256^inLen), Nat.pow_pos (Nat.pow_pos (by decide)), fun i x len =>
    if x.length = inLen ∧ len = outLen then
      be outLen (i.val / (256^outLen)^(toInt x) % 256^outLen) else []⟩

def realPrfFunctionProbability (v : Variant) (limits : Limits) (o : Oracle Id)
    (coins : FiniteExperiment Strategy) : Probability :=
  probability (independentProduct (independentProduct (uniformBytes (2*(params v).n))
      uniformMasterSeed) coins)
    (fun ((rest,K),strategy) => functionDistinguisher v limits strategy o rest.val
      (fun x len => o ⟨1,"",K.val,x,len⟩))

def idealPrfFunctionProbability (v : Variant) (limits : Limits) (o : Oracle Id)
    (coins : FiniteExperiment Strategy) : Probability :=
  probability (independentProduct (independentProduct (uniformBytes (2*(params v).n))
      (randomFunction ((params v).n+32) (params v).n)) coins)
    (fun ((rest,F),strategy) => functionDistinguisher v limits strategy o rest.val F)

theorem prf_function_real_equivalence (v : Variant) (limits : Limits) (o : Oracle Id)
    (widths : OutputWidths o) (coins : FiniteExperiment Strategy) :
    idealPrfKeyProbability v limits o coins = realPrfFunctionProbability v limits o coins :=
  probability_congr _ _ _ (fun ⟨⟨rest,K⟩,strategy⟩ =>
    (function_distinguisher_exact v limits strategy o widths rest K.val).symm)

/-- Pr[uniform-PRF-key forgery] ≤ Pr[random-PRF forgery] + Adv_PRF[D], with
    D = functionDistinguisher: the advantage of telling keyed BLAKE3 under a
    uniform key from a random function, on PRF-shaped queries. -/
theorem prf_function_hybrid_bound (v : Variant) (limits : Limits) (o : Oracle Id)
    (widths : OutputWidths o) (coins : FiniteExperiment Strategy) :
    (idealPrfKeyProbability v limits o coins).numerator *
        (idealPrfFunctionProbability v limits o coins).denominator ≤
      (idealPrfFunctionProbability v limits o coins).numerator *
        (idealPrfKeyProbability v limits o coins).denominator +
      gapNumerator (realPrfFunctionProbability v limits o coins)
        (idealPrfFunctionProbability v limits o coins) := by
  rw [prf_function_real_equivalence v limits o widths]
  exact probability_hybrid_bound _ _

#print axioms seedDistinguisher_congr
#print axioms verify_congr
#print axioms sign_congr
#print axioms zeroed_layout
#print axioms key_distinguisher_exact
#print axioms prf_key_hybrid_bound
#print axioms function_distinguisher_exact
#print axioms prf_function_hybrid_bound
end DSM.Sphincs.Security
