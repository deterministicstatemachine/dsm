-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.ExtractionLog

/- Log-aware forgery extraction. A collision event is now witnessed by the
   forgery itself: a request the verifier issued (a member of its exact log)
   at an in-range address whose input differs from the honest key's
   canonical input `canon` there but has the same thash output. Width facts
   are assumed only for the requests the construction makes under the thash
   key and the PRF key (`tw`, `pw`), which the hybrid games' routed oracles
   satisfy; no global `OutputWidths` is required. -/
namespace DSM.Sphincs

/-- The verifier's log `L` contains a thash request at an in-range address
    whose input differs from the honest canonical input but collides with it. -/
def CanonCollIn (o : Oracle Id) (p : Params) (tk prfKey seed : Bytes) (L : List Request) : Prop :=
  ∃ (b : Adrs) (x : Bytes), b.InRange ∧ thashReq p tk b x ∈ L ∧
    x ≠ canon o p tk prfKey seed b ∧
    thash o p tk b x = thash o p tk b (canon o p tk prfKey seed b)

theorem CanonCollIn.mono {o : Oracle Id} {p : Params} {tk prfKey seed : Bytes} {L L' : List Request}
    (h : CanonCollIn o p tk prfKey seed L) (sub : ∀ r, r ∈ L → r ∈ L') :
    CanonCollIn o p tk prfKey seed L' := by
  obtain ⟨b, x, hb, hm, hne, he⟩ := h
  exact ⟨b, x, hb, sub _ hm, hne, he⟩

section
variable {o : Oracle Id} {p : Params} {tk prfKey seed : Bytes}

theorem thash_w (tw : ∀ x, (o ⟨1,"",tk,x,p.n⟩).length = p.n) (a : Adrs) (x : Bytes) :
    (thash o p tk a x).length = p.n := tw _

theorem chain_w (tw : ∀ x, (o ⟨1,"",tk,x,p.n⟩).length = p.n) (a : Adrs) (x : Bytes) (s k : Nat)
    (hx : x.length = p.n) : (chain o p tk a x s k).length = p.n := by
  induction k generalizing x s with
  | zero => exact hx
  | succ k ih => exact ih _ _ (thash_w tw _ _)

theorem authWalk_w (tw : ∀ x, (o ⟨1,"",tk,x,p.n⟩).length = p.n) (a : Adrs) (li gi : Nat)
    (node auth : Bytes) (level r : Nat) (hn : node.length = p.n) :
    (authWalk o p tk a li gi node auth level r).length = p.n := by
  induction r generalizing li gi node level with
  | zero => exact hn
  | succ r ih => exact ih _ _ _ _ (thash_w tw _ _)

theorem prf_w (pw : ∀ x, x.length = p.n+32 → (o ⟨1,"",prfKey,x,p.n⟩).length = p.n)
    (hseed : seed.length = p.n) (a : Adrs) : (prf o p prfKey seed a).length = p.n :=
  pw _ (by rw [List.length_append, hseed, address_width])

theorem xmssNode_w (tw : ∀ x, (o ⟨1,"",tk,x,p.n⟩).length = p.n) (a : Adrs) (i h : Nat) :
    (xmssNode o p tk prfKey seed a i h).length = p.n := by
  cases h with
  | zero => show (wotsPkgen o p tk prfKey seed _).length = p.n
            rw [wots_pkgen_blocks]; exact thash_w tw _ _
  | succ h => exact thash_w tw _ _

theorem forsNode_w (tw : ∀ x, (o ⟨1,"",tk,x,p.n⟩).length = p.n) (a : Adrs) (i h : Nat) :
    (forsNode o p tk prfKey seed a i h).length = p.n := by
  cases h with
  | zero => exact thash_w tw _ _
  | succ h => exact thash_w tw _ _

/-- Chain extraction with the forged input located in the chain's log. -/
theorem chain_extract_log (a : Adrs) (hv : Nat → Bytes)
    (hstep : ∀ j, thash o p tk {a with hash := j} (hv j) = hv (j+1))
    (x : Bytes) (s k : Nat) (h : chain o p tk a x s k = hv (s+k)) (hne : x ≠ hv s) :
    ∃ j inp, s ≤ j ∧ j < s+k ∧ thashReq p tk {a with hash := j} inp ∈ chainLog o p tk a x s k ∧
      inp ≠ hv j ∧ thash o p tk {a with hash := j} inp = thash o p tk {a with hash := j} (hv j) := by
  induction k generalizing x s with
  | zero => exact absurd h hne
  | succ k ih =>
    change chain o p tk a (thash o p tk {a with hash := s} x) (s+1) k = hv (s+(k+1)) at h
    by_cases hn : thash o p tk {a with hash := s} x = hv (s+1)
    · exact ⟨s, x, Nat.le_refl _, by omega, List.mem_cons_self .., hne, by rw [hn, hstep]⟩
    · obtain ⟨j, inp, h1, h2, hm, hne', he⟩ :=
        ih _ (s+1) (by rw [show s+1+k = s+(k+1) by omega]; exact h) hn
      exact ⟨j, inp, by omega, by omega, List.mem_cons_of_mem _ hm, hne', he⟩

/-- Merkle-path extraction against an honest tree `N`, with the forged input
    located in the walk's log and the honest input the honest children. -/
theorem auth_walk_extract_log (tw : ∀ x, (o ⟨1,"",tk,x,p.n⟩).length = p.n)
    (a : Adrs) (N : Nat → Nat → Bytes) (hN : ∀ lv i, (N lv i).length = p.n)
    (hpar : ∀ lv i, thash o p tk {a with chain := lv+1, hash := i}
      (List.append (N lv (2*i)) (N lv (2*i+1))) = N (lv+1) i)
    (A : Bytes) (r level li gi : Nat) (x : Bytes) (hx : x.length = p.n)
    (orient : ∀ j, j < r → (li/2^j)%2 = (gi/2^j)%2)
    (hroot : authWalk o p tk a li gi x A level r = N (level+r) (gi/2^r)) (hne : x ≠ N level gi) :
    ∃ j inp, j < r ∧
      thashReq p tk {a with chain := level+j+1, hash := gi/2^(j+1)} inp ∈
        authWalkLog o p tk a li gi x A level r ∧
      inp ≠ List.append (N (level+j) (2*(gi/2^(j+1)))) (N (level+j) (2*(gi/2^(j+1))+1)) ∧
      thash o p tk {a with chain := level+j+1, hash := gi/2^(j+1)} inp =
        thash o p tk {a with chain := level+j+1, hash := gi/2^(j+1)}
          (List.append (N (level+j) (2*(gi/2^(j+1)))) (N (level+j) (2*(gi/2^(j+1))+1))) := by
  induction r generalizing level li gi x with
  | zero =>
    simp only [Nat.add_zero, Nat.pow_zero, Nat.div_one] at hroot
    exact absurd hroot hne
  | succ r ih =>
    rw [auth_walk_succ] at hroot
    have parity : li%2 = gi%2 := by simpa using orient 0 (by omega)
    by_cases hn : thash o p tk {a with chain := level+1, hash := gi/2}
        (if li%2 = 0 then x ++ slice A (level*p.n) p.n else slice A (level*p.n) p.n ++ x) =
        N (level+1) (gi/2)
    · by_cases hin : (if li%2 = 0 then x ++ slice A (level*p.n) p.n else slice A (level*p.n) p.n ++ x) =
          List.append (N level (2*(gi/2))) (N level (2*(gi/2)+1))
      · exfalso
        apply hne
        by_cases hp : li%2 = 0
        · rw [if_pos hp] at hin
          have e := (List.append_inj hin (by rw [hx, hN])).1
          rw [e]; congr 1; omega
        · rw [if_neg hp] at hin
          have e := (List.append_inj' hin (by rw [hx, hN])).2
          rw [e]; congr 1; omega
      · refine ⟨0, (if li%2 = 0 then x ++ slice A (level*p.n) p.n else slice A (level*p.n) p.n ++ x),
          by omega, ?_, ?_, ?_⟩
        · simp only [Nat.add_zero, Nat.zero_add, Nat.pow_one]
          exact List.mem_cons_self ..
        · simpa using hin
        · simp only [Nat.add_zero, Nat.zero_add, Nat.pow_one]
          rw [hn, hpar]
    · obtain ⟨j, inp, hj, hm, hne', he⟩ := ih (level+1) (li/2) (gi/2) _ (thash_w tw _ _)
        (fun j hj => by
          have h := orient (j+1) (by omega)
          simpa [Nat.pow_succ,Nat.div_div_eq_div_mul,Nat.mul_comm] using h)
        (by rw [show level+1+r = level+(r+1) by omega, Nat.div_div_eq_div_mul,
              show 2*2^r = 2^(r+1) by rw [Nat.pow_succ, Nat.mul_comm]]
            exact hroot) hn
      refine ⟨j+1, inp, by omega, ?_, ?_, ?_⟩
      · rw [show level+(j+1) = level+1+j by omega, ← half_pow]
        exact List.mem_cons_of_mem _ hm
      · rw [show level+(j+1) = level+1+j by omega, ← half_pow]
        exact hne'
      · rw [show level+(j+1) = level+1+j by omega, ← half_pow]
        exact he

/-- WOTS extraction with logs: a forged WOTS signature of `m'` (digits
    different from the honestly signed `M`) reconstructing the honest WOTS
    public key gives a canonical collision in the verifier's WOTS log, or
    the forged block is an honest chain value below the revealed position. -/
theorem wots_extract_log (tw : ∀ x, (o ⟨1,"",tk,x,p.n⟩).length = p.n)
    (pw : ∀ x, x.length = p.n+32 → (o ⟨1,"",prfKey,x,p.n⟩).length = p.n)
    (hseed : seed.length = p.n) (hn : 2*p.n*15 < 4096)
    (b : Adrs) (idx : Nat) (hl : b.layer < 256^4) (ht : b.tree < 256^8) (hidx : idx < 256^4)
    (hlen : p.len ≤ 256^4) (M m' sig' : Bytes) (hsig' : sig'.length = p.len*p.n)
    (hd : wotsDigits p M ≠ wotsDigits p m')
    (hpk : wotsPkFromSig o p tk {b.setType 0 with keypair := idx} sig' m' =
      wotsPkgen o p tk prfKey seed {b.setType 0 with keypair := idx}) :
    CanonCollIn o p tk prfKey seed (wotsPkFromSigLog o p tk {b.setType 0 with keypair := idx} sig' m') ∨
      WotsPreimage o p tk prfKey seed {b.setType 0 with keypair := idx} M m' sig' := by
  rw [wots_verify_blocks, wots_pkgen_blocks] at hpk
  have hform : ((wotsDigits p m').zipIdx.map fun (digit,i) =>
      (chain o p tk {({b.setType 0 with keypair := idx} : Adrs) with chain := i}
        (slice sig' (i*p.n) p.n) digit (15-digit) : Bytes)) =
      ((wotsDigits p m').zipIdx.map fun x =>
      (chain o p tk {({b.setType 0 with keypair := idx} : Adrs) with chain := x.2}
        (slice sig' (x.2*p.n) p.n) x.1 (15-x.1) : Bytes)) := by
    apply List.map_congr_left; intro x _; obtain ⟨d, i⟩ := x; rfl
  have hpk' : thash o p tk {({b.setType 0 with keypair := idx} : Adrs).setType 1 with keypair := idx}
      (((wotsDigits p m').zipIdx.map fun x =>
        (chain o p tk {({b.setType 0 with keypair := idx} : Adrs) with chain := x.2}
          (slice sig' (x.2*p.n) p.n) x.1 (15-x.1) : Bytes)).flatten) =
      thash o p tk {({b.setType 0 with keypair := idx} : Adrs).setType 1 with keypair := idx}
      (((List.range p.len).map fun i => (chain o p tk {({b.setType 0 with keypair := idx} : Adrs) with chain := i}
        (prf o p prfKey seed {({b.setType 0 with keypair := idx} : Adrs).setType 5 with
          keypair := idx, chain := i}) 0 15 : Bytes)).flatten) := by
    rw [← hform]; exact hpk
  by_cases ht' : ((wotsDigits p m').zipIdx.map fun x =>
        (chain o p tk {({b.setType 0 with keypair := idx} : Adrs) with chain := x.2}
          (slice sig' (x.2*p.n) p.n) x.1 (15-x.1) : Bytes)).flatten =
      ((List.range p.len).map fun i => (chain o p tk {({b.setType 0 with keypair := idx} : Adrs) with chain := i}
        (prf o p prfKey seed {({b.setType 0 with keypair := idx} : Adrs).setType 5 with
          keypair := idx, chain := i}) 0 15 : Bytes)).flatten
  · obtain ⟨i, hi, hlt⟩ := wots_checksum_decreases_of p hn M m' hd
    obtain ⟨hmem, hd15⟩ := digit_mem (p := p) m' i hi
    have forged := serialized_indexed_block (wotsDigits p m')
      (fun x => (chain o p tk {({b.setType 0 with keypair := idx} : Adrs) with chain := x.2}
        (slice sig' (x.2*p.n) p.n) x.1 (15-x.1) : Bytes))
      p.n _ hmem (fun y hy => chain_w tw _ _ _ _
        (slice_width sig' y.2 p.n p.len hsig' (by
          have := (zipIdx_mem hy).2; rw [wots_digit_count] at this; exact this)))
    have honest := serialized_map_block (List.range p.len)
      (fun i => (chain o p tk {({b.setType 0 with keypair := idx} : Adrs) with chain := i}
        (prf o p prfKey seed {({b.setType 0 with keypair := idx} : Adrs).setType 5 with
          keypair := idx, chain := i}) 0 15 : Bytes))
      p.n i (fun _ _ => chain_w tw _ _ 0 15 (prf_w pw hseed _)) (by simpa using hi)
    rw [ht', honest] at forged
    simp only [List.getElem_range] at forged
    have hstep : ∀ j, thash o p tk {({({b.setType 0 with keypair := idx} : Adrs) with chain := i} : Adrs)
        with hash := j} (wotsChainValue o p tk prfKey seed {b.setType 0 with keypair := idx} i j) =
        wotsChainValue o p tk prfKey seed {b.setType 0 with keypair := idx} i (j+1) :=
      fun j => (chain_step _ _ j).symm
    have h : chain o p tk {({b.setType 0 with keypair := idx} : Adrs) with chain := i}
        (slice sig' (i*p.n) p.n) ((wotsDigits p m').getD i 0) (15 - (wotsDigits p m').getD i 0) =
        wotsChainValue o p tk prfKey seed {b.setType 0 with keypair := idx} i
          ((wotsDigits p m').getD i 0 + (15 - (wotsDigits p m').getD i 0)) := by
      rw [show (wotsDigits p m').getD i 0 + (15 - (wotsDigits p m').getD i 0) = 15 by omega]
      exact forged.symm
    by_cases hs : slice sig' (i*p.n) p.n =
        wotsChainValue o p tk prfKey seed {b.setType 0 with keypair := idx} i ((wotsDigits p m').getD i 0)
    · exact Or.inr ⟨i, hi, hlt, hs⟩
    · obtain ⟨j, inp, _, hj2, hm, hne, he⟩ := chain_extract_log _ _ hstep _ _ _ h hs
      have hc : canon o p tk prfKey seed {({({b.setType 0 with keypair := idx} : Adrs) with chain := i} : Adrs)
          with hash := j} = wotsChainValue o p tk prfKey seed {b.setType 0 with keypair := idx} i j := by
        rw [canon_kind0 (a := {({({b.setType 0 with keypair := idx} : Adrs) with chain := i} : Adrs)
          with hash := j}) rfl, chain_hash_irrel]
        rfl
      left
      refine ⟨{({({b.setType 0 with keypair := idx} : Adrs) with chain := i} : Adrs) with hash := j},
        inp, ?_, ?_, by rw [hc]; exact hne, by rw [hc]; exact he⟩
      · simp only [Adrs.InRange, Adrs.setType]; omega
      exact List.mem_append_left _ (List.mem_flatMap.mpr ⟨_, hmem, hm⟩)
  · left
    have hc : canon o p tk prfKey seed {({b.setType 0 with keypair := idx} : Adrs).setType 1 with
        keypair := idx} =
        ((List.range p.len).map fun i => (chain o p tk {({b.setType 0 with keypair := idx} : Adrs) with chain := i}
          (prf o p prfKey seed {({b.setType 0 with keypair := idx} : Adrs).setType 5 with
            keypair := idx, chain := i}) 0 15 : Bytes)).flatten := by
      rw [canon_kind1 rfl]; rfl
    refine ⟨{({b.setType 0 with keypair := idx} : Adrs).setType 1 with keypair := idx}, _, ?_, ?_,
      by rw [hc]; exact ht', by rw [hc]; exact hpk'⟩
    · simp only [Adrs.InRange, Adrs.setType]; omega
    exact List.mem_append_right _ (List.mem_singleton_self _)

theorem xmssPkFromSig_width' (tw : ∀ x, (o ⟨1,"",tk,x,p.n⟩).length = p.n) (a : Adrs) (idx : Nat)
    (sig msg : Bytes) : (xmssPkFromSig o p tk a idx sig msg).length = p.n := by
  apply authWalk_w tw
  rw [wots_verify_blocks]; exact thash_w tw _ _

theorem wotsPkFromSig_w (tw : ∀ x, (o ⟨1,"",tk,x,p.n⟩).length = p.n) (a : Adrs) (sig msg : Bytes) :
    (wotsPkFromSig o p tk a sig msg).length = p.n := by
  rw [wots_verify_blocks]; exact thash_w tw _ _

/-- XMSS layer extraction with logs. -/
theorem xmss_extract_log (tw : ∀ x, (o ⟨1,"",tk,x,p.n⟩).length = p.n)
    (pw : ∀ x, x.length = p.n+32 → (o ⟨1,"",prfKey,x,p.n⟩).length = p.n)
    (hseed : seed.length = p.n) (hn : 2*p.n*15 < 4096)
    (a : Adrs) (hl : a.layer < 256^4) (ht : a.tree < 256^8) (hlen : p.len ≤ 256^4)
    (hH : 2^p.hp ≤ 256^4) (idx : Nat) (hidx : idx < 2^p.hp) (M m' sig' : Bytes)
    (hM : M.length = p.n) (hm' : m'.length = p.n) (hsig : sig'.length = p.layerBytes)
    (hroot : xmssPkFromSig o p tk a idx sig' m' = xmssNode o p tk prfKey seed a 0 p.hp) :
    m' = M ∨ CanonCollIn o p tk prfKey seed (xmssPkFromSigLog o p tk a idx sig' m') ∨
      WotsPreimageAt o p tk prfKey seed {a.setType 0 with keypair := idx} M (sig'.take (p.len*p.n)) := by
  have hhp : p.hp < 2^p.hp := Nat.lt_two_pow_self
  have hwalk : authWalk o p tk (a.setType 2) idx idx
      (wotsPkFromSig o p tk {a.setType 0 with keypair := idx} (sig'.take (p.len*p.n)) m')
      (sig'.drop (p.len*p.n)) 0 p.hp =
      (fun lv i => xmssNode o p tk prfKey seed a i lv) (0+p.hp) (idx/2^p.hp) := by
    rw [Nat.zero_add, Nat.div_eq_of_lt hidx]; exact hroot
  by_cases hL : wotsPkFromSig o p tk {a.setType 0 with keypair := idx} (sig'.take (p.len*p.n)) m' =
      xmssNode o p tk prfKey seed a idx 0
  · by_cases hmM : m' = M
    · exact Or.inl hmM
    · have hd : wotsDigits p M ≠ wotsDigits p m' :=
        fun h => hmM (wots_digits_injective p M m' hM hm' h).symm
      rcases wots_extract_log tw pw hseed hn a idx hl ht (by omega) hlen M m' _
        (layer_take_width sig' hsig) hd hL with c | w
      · exact Or.inr (Or.inl (c.mono (fun r hr => List.mem_append_left _ hr)))
      · obtain ⟨i, hi, hlt, e⟩ := w
        exact Or.inr (Or.inr ⟨i, _, hi, hlt, e⟩)
  · obtain ⟨j, inp, hj, hm, hne, he⟩ := auth_walk_extract_log tw (a.setType 2)
      (fun lv i => xmssNode o p tk prfKey seed a i lv) (fun lv i => xmssNode_w tw a i lv)
      (fun lv i => xmss_node_parent o p tk prfKey seed a lv i) _ p.hp 0 idx idx _
      (wotsPkFromSig_w tw _ _ _) (fun _ _ => rfl) hwalk hL
    have hc : canon o p tk prfKey seed {a.setType 2 with chain := 0+j+1, hash := idx/2^(j+1)} =
        List.append (xmssNode (m := Id) o p tk prfKey seed a (2*(idx/2^(j+1))) (0+j))
          (xmssNode (m := Id) o p tk prfKey seed a (2*(idx/2^(j+1))+1) (0+j)) := by
      rw [canon_kind2 (a := {a.setType 2 with chain := 0+j+1, hash := idx/2^(j+1)}) rfl]
      dsimp only [Adrs.setType]
      rw [Nat.add_sub_cancel, ← xmssNode_base, ← xmssNode_base]
    have hd : idx/2^(j+1) ≤ idx := Nat.div_le_self _ _
    refine Or.inr (Or.inl ⟨{a.setType 2 with chain := 0+j+1, hash := idx/2^(j+1)}, inp, ?_,
      List.mem_append_right _ hm, by rw [hc]; exact hne, by rw [hc]; exact he⟩)
    simp only [Adrs.InRange, Adrs.setType]; omega
end

/-- A WOTS preimage at an honest hypertree position, against the forged
    hypertree signature `S`. -/
def WotsEvent (o : Oracle Id) (p : Params) (tk prfKey seed : Bytes) (S : Bytes) : Prop :=
  ∃ layer tree leaf, layer < p.d ∧ tree < 2^(p.hp*(p.d-1-layer)) ∧ leaf < 2^p.hp ∧
    WotsPreimageAt o p tk prfKey seed {({layer := layer, tree := tree} : Adrs).setType 0 with keypair := leaf}
      (htMsg o p tk prfKey seed layer tree leaf)
      (((S.drop (layer*p.layerBytes)).take p.layerBytes).take (p.len*p.n))

section
variable {o : Oracle Id} {p : Params} {tk prfKey seed : Bytes}

theorem htMsg_w (tw : ∀ x, (o ⟨1,"",tk,x,p.n⟩).length = p.n) (layer tree leaf : Nat) :
    (htMsg o p tk prfKey seed layer tree leaf).length = p.n := by
  unfold htMsg
  split
  · exact thash_w tw _ _
  · exact xmssNode_w tw _ _ _

theorem tree_inRange (htop : 2^(p.hp*(p.d-1)) ≤ 256^8) (layer t : Nat)
    (h : t < 2^(p.hp*(p.d-1-layer))) : t < 256^8 := by
  have h1 : 2^(p.hp*(p.d-1-layer)) ≤ 2^(p.hp*(p.d-1)) :=
    Nat.pow_le_pow_right (by decide) (Nat.mul_le_mul_left _ (by omega))
  omega

/-- Hypertree extraction with logs, over layers `layer` … d-1. -/
theorem ht_tail_extract_log (tw : ∀ x, (o ⟨1,"",tk,x,p.n⟩).length = p.n)
    (pw : ∀ x, x.length = p.n+32 → (o ⟨1,"",prfKey,x,p.n⟩).length = p.n)
    (hseed : seed.length = p.n) (hn : 2*p.n*15 < 4096) (hlen : p.len ≤ 256^4)
    (hH : 2^p.hp ≤ 256^4) (hdd : p.d ≤ 256^4) (htop : 2^(p.hp*(p.d-1)) ≤ 256^8)
    (S : Bytes) (hS : S.length = p.d*p.layerBytes) :
    ∀ r layer tree (node : Bytes), layer + r + 1 = p.d → tree < 2^(p.hp*(r+1)) →
      node.length = p.n →
      htRootTail o p tk layer tree node (S.drop (layer*p.layerBytes)) (r+1) =
        xmssNode o p tk prfKey seed {layer := p.d-1} 0 p.hp →
      node = htMsg o p tk prfKey seed layer (tree/2^p.hp) (tree%2^p.hp) ∨
        CanonCollIn o p tk prfKey seed (htRootTailLog o p tk layer tree node (S.drop (layer*p.layerBytes)) (r+1)) ∨
        WotsEvent o p tk prfKey seed S := by
  intro r
  induction r with
  | zero =>
    intro layer tree node hl ht hnode h
    rw [ht_root_tail_succ] at h
    have hnext : (nextLayer p tree).2 = 0 := Nat.div_eq_of_lt (by simpa using ht)
    have top : ({layer := p.d-1} : Adrs) = {layer := layer, tree := (nextLayer p tree).2} := by
      rw [hnext, show p.d-1 = layer by omega]
    rw [top] at h
    have hleaf := next_layer_leaf_bounded p tree
    rcases xmss_extract_log tw pw hseed hn _ (by dsimp only; omega)
      (by dsimp only; rw [hnext]; exact Nat.pos_of_ne_zero (by simp)) hlen hH _ hleaf _ _ _
      (htMsg_w tw _ _ _) hnode (layer_part_width S hS layer (by omega)) h with e | c | w
    · exact Or.inl e
    · exact Or.inr (Or.inl (c.mono (fun r hr => by
        simp only [htRootTailLog]; exact List.mem_append_left _ hr)))
    · refine Or.inr (Or.inr ⟨layer, _, _, by omega, ?_, hleaf, w⟩)
      rw [hnext]; exact Nat.pos_of_ne_zero (by simp)
  | succ r ih =>
    intro layer tree node hl ht hnode h
    rw [ht_root_tail_succ, List.drop_drop, show layer*p.layerBytes+p.layerBytes =
      (layer+1)*p.layerBytes by rw [Nat.succ_mul]] at h
    have split : 2^(p.hp*(r+1+1)) = 2^(p.hp*(r+1))*2^p.hp := by
      rw [← Nat.pow_add]; congr 1
    have hnext : (nextLayer p tree).2 < 2^(p.hp*(r+1)) :=
      (Nat.div_lt_iff_lt_mul (Nat.pow_pos (by decide))).2 (by rw [← split]; exact ht)
    have hnext' : (nextLayer p tree).2 < 256^8 :=
      tree_inRange htop layer _ (by rw [show p.d-1-layer = r+1 by omega]; exact hnext)
    have hleaf := next_layer_leaf_bounded p tree
    have hlog : htRootTailLog o p tk layer tree node (S.drop (layer*p.layerBytes)) (r+1+1) =
        xmssPkFromSigLog o p tk {layer := layer, tree := (nextLayer p tree).2} (nextLayer p tree).1
          ((S.drop (layer*p.layerBytes)).take p.layerBytes) node ++
        htRootTailLog o p tk (layer+1) (nextLayer p tree).2
          (xmssPkFromSig o p tk {layer := layer, tree := (nextLayer p tree).2} (nextLayer p tree).1
            ((S.drop (layer*p.layerBytes)).take p.layerBytes) node)
          (S.drop ((layer+1)*p.layerBytes)) (r+1) := by
      rw [htRootTailLog, List.drop_drop, show layer*p.layerBytes+p.layerBytes =
        (layer+1)*p.layerBytes by rw [Nat.succ_mul]]
    rw [hlog]
    rcases ih (layer+1) _ _ (by omega) hnext (xmssPkFromSig_width' tw _ _ _ _) h with e | c | w
    · have root : htMsg o p tk prfKey seed (layer+1) ((nextLayer p tree).2/2^p.hp)
          ((nextLayer p tree).2%2^p.hp) =
          xmssNode o p tk prfKey seed {layer := layer, tree := (nextLayer p tree).2} 0 p.hp := by
        simp only [htMsg, Nat.add_one_ne_zero, if_false, Nat.add_sub_cancel]
        rw [Nat.mul_comm, Nat.div_add_mod]
      rw [root] at e
      rcases xmss_extract_log tw pw hseed hn _ (by dsimp only; omega) (by dsimp only; exact hnext')
        hlen hH _ hleaf _ _ _ (htMsg_w tw _ _ _) hnode (layer_part_width S hS layer (by omega)) e
        with e' | c' | w'
      · exact Or.inl e'
      · exact Or.inr (Or.inl (c'.mono (fun r hr => List.mem_append_left _ hr)))
      · refine Or.inr (Or.inr ⟨layer, _, _, by omega, ?_, hleaf, w'⟩)
        rw [show p.d-1-layer = r+1 by omega]; exact hnext
    · exact Or.inr (Or.inl (c.mono (fun r hr => List.mem_append_right _ hr)))
    · exact Or.inr (Or.inr w)

theorem nextLayer_split (tree leaf : Nat) (hleaf : leaf < 2^p.hp) :
    nextLayer p (tree*2^p.hp+leaf) = (leaf, tree) := by
  simp only [nextLayer, Prod.mk.injEq]
  constructor
  · rw [Nat.add_comm, Nat.add_mul_mod_self_right, Nat.mod_eq_of_lt hleaf]
  · rw [Nat.add_comm, Nat.add_mul_div_right _ _ (Nat.pow_pos (by decide)),
      Nat.div_eq_of_lt hleaf, Nat.zero_add]

theorem ht_root_log_as_tail (S msg : Bytes) (tree leaf : Nat) (hleaf : leaf < 2^p.hp) :
    htRootLog o p tk S msg tree leaf =
      htRootTailLog o p tk 0 (tree*2^p.hp+leaf) msg (S.drop (0*p.layerBytes)) (p.d-1+1) := by
  rw [Nat.zero_mul, List.drop_zero, htRootTailLog, nextLayer_split tree leaf hleaf]
  rfl

/-- Hypertree extraction with logs: a forged hypertree signature reaching the
    honest public root signs the honest FORS public key, or yields a
    canonical collision in the verifier's hypertree log, or a WOTS preimage. -/
theorem ht_extract_log (tw : ∀ x, (o ⟨1,"",tk,x,p.n⟩).length = p.n)
    (pw : ∀ x, x.length = p.n+32 → (o ⟨1,"",prfKey,x,p.n⟩).length = p.n)
    (hseed : seed.length = p.n) (hn : 2*p.n*15 < 4096) (hlen : p.len ≤ 256^4)
    (hH : 2^p.hp ≤ 256^4) (hdd : p.d ≤ 256^4) (htop : 2^(p.hp*(p.d-1)) ≤ 256^8) (hd : 1 ≤ p.d)
    (S msg : Bytes) (tree leaf : Nat) (hS : S.length = p.d*p.layerBytes)
    (hmsg : msg.length = p.n) (htree : tree < 2^(p.hp*(p.d-1))) (hleaf : leaf < 2^p.hp)
    (h : htRoot o p tk S msg tree leaf = xmssNode o p tk prfKey seed {layer := p.d-1} 0 p.hp) :
    msg = honestForsPk o p tk prfKey seed tree leaf ∨
      CanonCollIn o p tk prfKey seed (htRootLog o p tk S msg tree leaf) ∨
      WotsEvent o p tk prfKey seed S := by
  rw [ht_root_as_tail S msg tree leaf hd hleaf] at h
  have hT : tree*2^p.hp+leaf < 2^(p.hp*(p.d-1+1)) := by
    have e : 2^(p.hp*(p.d-1+1)) = 2^(p.hp*(p.d-1))*2^p.hp := by
      rw [← Nat.pow_add]; congr 1
    rw [e]
    have := Nat.mul_le_mul_right (2^p.hp) (show tree+1 ≤ 2^(p.hp*(p.d-1)) by omega)
    rw [Nat.succ_mul] at this
    omega
  have h' : htRootTail o p tk 0 (tree*2^p.hp+leaf) msg (S.drop (0*p.layerBytes)) (p.d-1+1) =
      xmssNode o p tk prfKey seed {layer := p.d-1} 0 p.hp := by
    rw [Nat.zero_mul, List.drop_zero, show p.d-1+1 = p.d by omega]; exact h
  rw [ht_root_log_as_tail S msg tree leaf hleaf]
  rcases ht_tail_extract_log tw pw hseed hn hlen hH hdd htop S hS (p.d-1) 0 _ msg (by omega) hT hmsg h'
    with e | c | w
  · left
    have hq : (tree*2^p.hp+leaf)/2^p.hp = tree := by
      rw [Nat.add_comm, Nat.add_mul_div_right _ _ (Nat.pow_pos (by decide)),
        Nat.div_eq_of_lt hleaf, Nat.zero_add]
    have hr : (tree*2^p.hp+leaf)%2^p.hp = leaf := by
      rw [Nat.add_comm, Nat.add_mul_mod_self_right, Nat.mod_eq_of_lt hleaf]
    rw [e, hq, hr]
    simp only [htMsg, if_true]
  · exact Or.inr (Or.inl c)
  · exact Or.inr (Or.inr w)

/-- FORS extraction with logs. -/
theorem fors_extract_log (tw : ∀ x, (o ⟨1,"",tk,x,p.n⟩).length = p.n)
    (tree leaf : Nat) (ht : tree < 256^8) (hleaf : leaf < 256^4)
    (hMA : p.k*2^p.a ≤ 256^4) (hA : p.a < 256^4) (sig md : Bytes)
    (h : forsPkFromSig o p tk (forsAdrs tree leaf) sig md = honestForsPk o p tk prfKey seed tree leaf) :
    CanonCollIn o p tk prfKey seed (forsPkFromSigLog o p tk (forsAdrs tree leaf) sig md) ∨
      ∀ i, i < p.k → slice sig (i*((p.a+1)*p.n)) p.n =
        forsSecret o p prfKey seed (forsAdrs tree leaf) (i*2^p.a + forsDigit p md i) := by
  rw [fors_verify_blocks] at h
  by_cases hr :
    ((base2b md p.a p.k).zipIdx.map fun x =>
        (authRoot o p tk (forsAdrs tree leaf) x.1 (x.2*2^p.a+x.1)
          (thash o p tk {(forsAdrs tree leaf) with chain := 0,hash := x.2*2^p.a+x.1}
            ((slice sig (x.2*((p.a+1)*p.n)) ((p.a+1)*p.n)).take p.n))
          ((slice sig (x.2*((p.a+1)*p.n)) ((p.a+1)*p.n)).drop p.n) p.a : Bytes)).flatten =
    ((List.range p.k).map fun i =>
      (forsNode o p tk prfKey seed (forsAdrs tree leaf) i p.a : Bytes)).flatten
  · have tree_i : ∀ i, i < p.k →
        CanonCollIn o p tk prfKey seed (forsPkFromSigLog o p tk (forsAdrs tree leaf) sig md) ∨
        slice sig (i*((p.a+1)*p.n)) p.n =
          forsSecret o p prfKey seed (forsAdrs tree leaf) (i*2^p.a + forsDigit p md i) := by
      intro i hi
      have hlen : i < (base2b md p.a p.k).length := by rw [base2b_length]; exact hi
      have hmem := getD_mem_zipIdx _ i hlen
      have hdig : forsDigit p md i < 2^p.a := by
        unfold forsDigit
        rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hlen, Option.getD_some]
        exact base2b_digit_bound md _ _ _ (List.getElem_mem _)
      have hg := Nat.lt_of_lt_of_le (offset_lt hi hdig) hMA
      have forged := serialized_indexed_block (base2b md p.a p.k)
        (fun x => (authRoot o p tk (forsAdrs tree leaf) x.1 (x.2*2^p.a+x.1)
          (thash o p tk {(forsAdrs tree leaf) with chain := 0,hash := x.2*2^p.a+x.1}
            ((slice sig (x.2*((p.a+1)*p.n)) ((p.a+1)*p.n)).take p.n))
          ((slice sig (x.2*((p.a+1)*p.n)) ((p.a+1)*p.n)).drop p.n) p.a : Bytes))
        p.n _ hmem (fun y _ => authWalk_w tw _ _ _ _ _ _ _ (thash_w tw _ _))
      have honestRoot := serialized_map_block (List.range p.k)
        (fun i => (forsNode o p tk prfKey seed (forsAdrs tree leaf) i p.a : Bytes))
        p.n i (fun _ _ => forsNode_w tw _ _ _) (by simpa using hi)
      rw [hr, honestRoot] at forged
      simp only [List.getElem_range] at forged
      have hq : (i*2^p.a + forsDigit p md i)/2^p.a = i := by
        rw [Nat.add_comm, Nat.add_mul_div_right _ _ (Nat.pow_pos (by decide)),
          Nat.div_eq_of_lt hdig, Nat.zero_add]
      by_cases hL : thash o p tk {(forsAdrs tree leaf) with chain := 0, hash := i*2^p.a + forsDigit p md i}
          ((slice sig (i*((p.a+1)*p.n)) ((p.a+1)*p.n)).take p.n) =
          forsNode o p tk prfKey seed (forsAdrs tree leaf) (i*2^p.a + forsDigit p md i) 0
      · by_cases hs : (slice sig (i*((p.a+1)*p.n)) ((p.a+1)*p.n)).take p.n =
            forsSecret o p prfKey seed (forsAdrs tree leaf) (i*2^p.a + forsDigit p md i)
        · right
          rw [← hs, slice_take_prefix _ _ _ _ (by rw [Nat.add_mul, Nat.one_mul]; omega)]
        · left
          have hc : canon o p tk prfKey seed
              {(forsAdrs tree leaf) with chain := 0, hash := i*2^p.a + forsDigit p md i} =
              forsSecret o p prfKey seed (forsAdrs tree leaf) (i*2^p.a + forsDigit p md i) := by
            rw [canon_kind3_leaf rfl rfl]; rfl
          refine ⟨{(forsAdrs tree leaf) with chain := 0, hash := i*2^p.a + forsDigit p md i}, _, ?_, ?_,
            by rw [hc]; exact hs, by rw [hc]; exact hL⟩
          · unfold forsAdrs; simp only [Adrs.InRange]; omega
          · exact List.mem_append_left _ (List.mem_flatMap.mpr ⟨_, hmem, List.mem_cons_self ..⟩)
      · left
        have hroot : authWalk o p tk (forsAdrs tree leaf) (forsDigit p md i) (i*2^p.a + forsDigit p md i)
            (thash o p tk {(forsAdrs tree leaf) with chain := 0, hash := i*2^p.a + forsDigit p md i}
              ((slice sig (i*((p.a+1)*p.n)) ((p.a+1)*p.n)).take p.n))
            ((slice sig (i*((p.a+1)*p.n)) ((p.a+1)*p.n)).drop p.n) 0 p.a =
            (fun lv j => forsNode o p tk prfKey seed (forsAdrs tree leaf) j lv) (0+p.a)
              ((i*2^p.a + forsDigit p md i)/2^p.a) := by
          rw [Nat.zero_add, hq]; exact forged.symm
        obtain ⟨j, inp, hj, hm, hne, he⟩ := auth_walk_extract_log tw (forsAdrs tree leaf)
          (fun lv j => forsNode o p tk prfKey seed (forsAdrs tree leaf) j lv)
          (fun lv j => forsNode_w tw _ _ _) (fun lv j => fors_node_parent o p tk prfKey seed _ lv j)
          _ p.a 0 _ _ _ (thash_w tw _ _) (fun j hj => fors_orientation i _ p.a j hj) hroot hL
        have hc : canon o p tk prfKey seed
            {(forsAdrs tree leaf) with chain := 0+j+1, hash := (i*2^p.a + forsDigit p md i)/2^(j+1)} =
            List.append (forsNode (m := Id) o p tk prfKey seed (forsAdrs tree leaf)
                (2*((i*2^p.a + forsDigit p md i)/2^(j+1))) (0+j))
              (forsNode (m := Id) o p tk prfKey seed (forsAdrs tree leaf)
                (2*((i*2^p.a + forsDigit p md i)/2^(j+1))+1) (0+j)) := by
          rw [canon_kind3_node (0+j) rfl rfl, forsNode_base (forsAdrs tree leaf),
            forsNode_base (forsAdrs tree leaf)]
        have hdv : (i*2^p.a + forsDigit p md i)/2^(j+1) ≤ i*2^p.a + forsDigit p md i :=
          Nat.div_le_self _ _
        refine ⟨{(forsAdrs tree leaf) with chain := 0+j+1, hash := (i*2^p.a + forsDigit p md i)/2^(j+1)},
          inp, ?_, ?_, by rw [hc]; exact hne, by rw [hc]; exact he⟩
        · unfold forsAdrs; simp only [Adrs.InRange]; omega
        · exact List.mem_append_left _ (List.mem_flatMap.mpr ⟨_, hmem, List.mem_cons_of_mem _ hm⟩)
    by_cases hall : ∀ i, i < p.k → slice sig (i*((p.a+1)*p.n)) p.n =
        forsSecret o p prfKey seed (forsAdrs tree leaf) (i*2^p.a + forsDigit p md i)
    · exact Or.inr hall
    · left
      apply Classical.byContradiction
      intro hno
      apply hall
      intro i hi
      rcases tree_i i hi with c | s
      · exact absurd c hno
      · exact s
  · left
    have hc : canon o p tk prfKey seed {(forsAdrs tree leaf).setType 4 with keypair := leaf} =
        ((List.range p.k).map fun i =>
          (forsNode o p tk prfKey seed (forsAdrs tree leaf) i p.a : Bytes)).flatten := by
      rw [canon_kind4 rfl]; rfl
    refine ⟨{(forsAdrs tree leaf).setType 4 with keypair := leaf}, _, ?_,
      List.mem_append_right _ (List.mem_singleton_self _), by rw [hc]; exact hr, by rw [hc]; exact h⟩
    unfold forsAdrs; simp only [Adrs.InRange, Adrs.setType]; omega
end
#print axioms chain_extract_log
#print axioms auth_walk_extract_log
#print axioms wots_extract_log
#print axioms xmss_extract_log
#print axioms ht_extract_log
#print axioms fors_extract_log
end DSM.Sphincs
