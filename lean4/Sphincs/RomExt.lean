-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomProv
import Sphincs.RomPath

/- The post-verification extension (game H1'). After the adversary's output,
   the challenger draws the honest WOTS chains on the verifier's hypertree
   path and the honest FORS leaves at the verifier's FORS indices; the
   digest locating them is recomputed from public data with the adversary's
   oracle. The extension reveals nothing and runs after the adversary has
   halted, so the adversary's view and the game's output are unchanged
   (`gameQT'` returns the main game's output), the main run's draws are a
   prefix of the extended run's (distribution), and extraction applies to
   the extended table (`rom_extract_ext`), where the honest values the
   events refer to are drawn rather than defaulted. -/
namespace DSM.Rom
open DSM.Sphincs DSM.Sphincs.Security

/-- The tree index at layer `l` of the hypertree path selected by digest indices `I`. -/
def pathT (p : Params) (I : Indices) (l : Nat) : Nat := (I.tree*2^p.hp + I.leaf)/2^(p.hp*l)/2^p.hp

/-- The extension's tail: the complete honest FORS key (all trees and the roots
    compression) and the complete XMSS tree at every layer of the forged path,
    computed recursively from the honest seeds. -/
def extTail {m : Type → Type} [Monad m] (oc : Oracle m) (p : Params) (tk prfKey seed : Bytes) (I : Indices) :
    m Unit := do
  let fa := forsAdrs I.tree I.leaf
  let mut roots : Bytes := []
  for i in List.range p.k do
    let r ← forsNode oc p tk prfKey seed fa i p.a
    roots := roots ++ r
  let _ ← thash oc p tk {fa.setType 4 with keypair := fa.keypair} roots
  for l in List.range p.d do
    let _ ← xmssNode oc p tk prfKey seed {layer := l, tree := pathT p I l} 0 p.hp
    pure ()

/-- The extension's tail, symbolically. -/
def sExtTail (p : Params) (tk prfKey seed : SB) (I : Indices) : Prog Unit := do
  let fa := forsAdrs I.tree I.leaf
  let mut roots : SB := []
  for i in List.range p.k do
    let r ← sForsNode p tk prfKey seed fa i p.a
    roots := roots ++ r
  let _ ← sThash p tk {fa.setType 4 with keypair := fa.keypair} roots
  for l in List.range p.d do
    let _ ← sXmssNode p tk prfKey seed {layer := l, tree := pathT p I l} 0 p.hp
    pure ()

/-- The extension. `oc` is the challenger's oracle, `oa` the adversary's. -/
def extW {m : Type → Type} [Monad m] (oc oa : Oracle m) (v : Variant) (sk msg sig : Bytes) : m Unit := do
  let p := params v
  let seed := slice sk (2*p.n) p.n
  let tk ← deriveKey oc "DSM/sphincs/v2/thash" seed
  let prfKey ← deriveKey oc "DSM/sphincs/v2/prf" (sk.take p.n)
  let dg ← oa ⟨2, "DSM/sphincs/v2/h-msg", [], sig.take p.n ++ (seed ++ sk.drop (3*p.n)) ++ msg, p.m⟩
  for i in List.range p.k do
    let _ ← forsNode oc p tk prfKey seed (forsAdrs (splitDigest p dg).tree (splitDigest p dg).leaf)
      (i*2^p.a + forsDigit p (splitDigest p dg).md i) 0
    pure ()
  for l in List.range p.d do
    let _ ← wotsPkgen oc p tk prfKey seed
      (wA l (((splitDigest p dg).tree*2^p.hp + (splitDigest p dg).leaf)/2^(p.hp*l)/2^p.hp)
        (((splitDigest p dg).tree*2^p.hp + (splitDigest p dg).leaf)/2^(p.hp*l)%2^p.hp))
    pure ()
  extTail oc p tk prfKey seed (splitDigest p dg)

/-- The extension, symbolically. -/
def sExtW (v : Variant) (sk : SB) (msg sig : Bytes) : Prog Unit := do
  let p := params v
  let seed := sSlice sk 2 1
  let tk ← sDeriveKey "DSM/sphincs/v2/thash" seed
  let prfKey ← sDeriveKey "DSM/sphincs/v2/prf" (sk.take 1)
  let dg ← Prog.reveal (seed ++ sk.drop 3) (fun sr =>
    advP ⟨2, "DSM/sphincs/v2/h-msg", [], sig.take p.n ++ sr ++ msg, p.m⟩)
  for i in List.range p.k do
    let _ ← sForsNode p tk prfKey seed (forsAdrs (splitDigest p dg).tree (splitDigest p dg).leaf)
      (i*2^p.a + forsDigit p (splitDigest p dg).md i) 0
    pure ()
  for l in List.range p.d do
    let _ ← sWotsPkgen p tk prfKey seed
      (wA l (((splitDigest p dg).tree*2^p.hp + (splitDigest p dg).leaf)/2^(p.hp*l)/2^p.hp)
        (((splitDigest p dg).tree*2^p.hp + (splitDigest p dg).leaf)/2^(p.hp*l)%2^p.hp))
    pure ()
  sExtTail p tk prfKey seed (splitDigest p dg)

/-- The extended game H1' as a query tree. -/
def gameQT' (v : Variant) (limits : Limits) (A : Bytes → RAdv) (ex : Bytes) : QT Out :=
  QT.bind (kgTail challengerOracle v ex) (fun ks =>
    QT.bind (playQT v limits ks.1 ks.2 (A ks.1) []) (fun out =>
      QT.bind (extW challengerOracle advQ v ks.2 out.msg out.sig) (fun _ => .done out)))

/-- The extended game H1', symbolically. -/
def gameS' (v : Variant) (limits : Limits) (A : Bytes → RAdv) (ex : SB) : Prog Out :=
  Prog.bind (sKgTail v ex) (fun ks => .reveal ks.1 (fun pk =>
    Prog.bind (playS v limits pk ks.2 (A pk) []) (fun out =>
      Prog.bind (sExtW v ks.2 out.msg out.sig) (fun _ => .done out))))

section
variable {t : List Nat}

theorem sim_extTail (p : Params) (tk pk seed : SB) (tk' pk' seed' : Bytes) (htk : RB t tk tk')
    (hpk : RB t pk pk') (hsd : RB t seed seed') (I : Indices) :
    Sim t (sExtTail p tk pk seed I) (extTail challengerOracle p tk' pk' seed' I) (fun _ _ => True) := by
  simp only [sExtTail, extTail]
  refine Sim.bind (Sim.forIn _ _ _ (RBn t p.n) ?_ [] [] ⟨rfl, WN_nil _⟩) (fun roots roots' hr => ?_)
  · intro i _ s s' hss
    exact Sim.bind (sim_forsNode p tk tk' htk pk seed pk' seed' hpk hsd _ _ _)
      (fun r r' hr => Sim.bind Sim.unit (fun _ _ _ => Sim.pure'
        (show Sim.StepRel (RBn t p.n) (.yield (s ++ r)) (.yield (s' ++ r')) from RBn_append hss hr)))
  refine Sim.bind (sim_thash p tk tk' _ roots roots' htk hr.1) (fun _ _ _ => ?_)
  refine Sim.bind (Sim.forIn _ _ _ (fun _ _ => True) ?_ _ _ trivial) (fun _ _ _ => Sim.pure' trivial)
  intro l _ u u' _
  exact Sim.bind (sim_xmssNode p tk tk' htk pk seed pk' seed' hpk hsd _ _ _)
    (fun _ _ _ => Sim.bind Sim.unit (fun _ _ _ => Sim.pure'
      (show Sim.StepRel (fun _ _ => True) (.yield PUnit.unit) (.yield PUnit.unit) from trivial)))

theorem sim_extW (v : Variant) (sk : SB) (sk' : Bytes) (hsk : RBn t (params v).n sk sk') (msg sig : Bytes) :
    Sim t (sExtW v sk msg sig) (extW challengerOracle advQ v sk' msg sig) (fun _ _ => True) := by
  have hseed := RBn_sSlice hsk 2 1
  rw [Nat.one_mul] at hseed
  have hroot := RBn_drop hsk 3
  have hpre := RBn_take hsk 1
  rw [Nat.one_mul] at hpre
  simp only [sExtW, extW]
  refine Sim.bind (sim_deriveKey _ _ _ hseed.1) (fun tk tk' htk => ?_)
  refine Sim.bind (sim_deriveKey _ _ _ hpre.1) (fun pk pk' hpk => ?_)
  refine Sim.bind (R₁ := Eq) (Sim.reveal _ _ _ ?_) (fun dg dg' hdg => ?_)
  · rw [sres_append, hseed.1, hroot.1]; exact simA _
  · subst hdg
    refine Sim.bind (Sim.forIn _ _ _ (fun _ _ => True) ?_ _ _ trivial) (fun _ _ _ => ?_)
    · intro i _ s s' _
      exact Sim.bind (sim_forsNode _ tk tk' htk.1 pk _ pk' _ hpk.1 hseed.1 _ _ _)
        (fun _ _ _ => Sim.bind Sim.unit (fun _ _ _ => Sim.pure'
          (show Sim.StepRel (fun _ _ => True) (.yield PUnit.unit) (.yield PUnit.unit) from trivial)))
    · refine Sim.bind (Sim.forIn _ _ _ (fun _ _ => True) ?_ _ _ trivial)
        (fun _ _ _ => sim_extTail _ tk pk _ tk' pk' _ htk.1 hpk.1 hseed.1 _)
      intro l _ s s' _
      exact Sim.bind (sim_wotsPkgen _ tk tk' htk.1 pk _ pk' _ hpk.1 hseed.1 _)
        (fun _ _ _ => Sim.bind Sim.unit (fun _ _ _ => Sim.pure'
          (show Sim.StepRel (fun _ _ => True) (.yield PUnit.unit) (.yield PUnit.unit) from trivial)))

theorem sim_game' (v : Variant) (limits : Limits) (A : Bytes → RAdv) :
    Sim t (gameS' v limits A (coinEx (params v).n))
      (gameQT' v limits A (sres t (coinEx (params v).n))) Eq := by
  unfold gameS' gameQT'
  refine Sim.bind' (sim_kgTail v _ _ ⟨rfl, coinEx_WN _⟩) (fun ks ks' h => ?_)
  apply Sim.reveal
  rw [h.1.1]
  refine Sim.bind' (sim_play v limits _ ks.2 ks'.2 h.2 _ []) (fun out out' ho => ?_)
  subst ho
  exact Sim.bind' (sim_extW v ks.2 ks'.2 h.2 _ _) (fun _ _ _ => Sim.pure' rfl)
end

/-- The main game's trace is a prefix of the extended game's: a disagreement
    in H1 is one in H1'. -/
theorem anyDis_ext (v : Variant) (limits : Limits) (A : Bytes → RAdv) (st0 : St) (t : List Nat)
    (h : anyDis (gameS v limits A (coinEx (params v).n)) st0 t = true) :
    anyDis (gameS' v limits A (coinEx (params v).n)) st0 t = true := by
  simp only [anyDis, List.any_eq_true] at h ⊢
  obtain ⟨s, hs, hd⟩ := h
  refine ⟨s, ?_, hd⟩
  unfold gameS at hs
  unfold gameS'
  rw [strace_bind] at hs ⊢
  rcases List.mem_append.mp hs with hs | hs
  · exact List.mem_append_left _ hs
  · refine List.mem_append_right _ ?_
    simp only [strace, List.mem_cons] at hs ⊢
    rcases hs with hs | hs
    · exact Or.inl hs
    · right
      rw [strace_bind]
      exact List.mem_append_left _ hs

/-! The extended run: same output, extended draws; extraction on the extended table. -/

section
variable (v : Variant) (limits : Limits) (A : Bytes → RAdv)

/-- The extended game H1' on tape `t`. -/
def runG' (t : List Nat) : Out × List Draw :=
  run t (gameQT' v limits A (sres t (coinEx (params v).n))) (resD t (coinSt (params v).n))

/-- The extended run's final table. -/
def finO' (t : List Nat) : Oracle Id := oracleOf t (runG' v limits A t).2

theorem runG'_eq (t : List Nat) :
    runG' v limits A t = ((runG v limits A t).1,
      (run t (extW challengerOracle advQ v (finKey v limits A t).2 (runG v limits A t).1.msg
        (runG v limits A t).1.sig) (runG v limits A t).2).2) := by
  have h := runG_play v limits A t
  unfold runG' gameQT'
  simp only [run_bind, kg_value v limits A t]
  rw [← h]
  simp [run]

/-- View and distribution: the main run's draws are a prefix of the extended run's. -/
theorem pre_ext (t : List Nat) : Pre (runG v limits A t).2 (runG' v limits A t).2 := by
  rw [runG'_eq]; exact pre_run t _ _

/-- The output is the main game's. -/
theorem out_ext (t : List Nat) : (runG' v limits A t).1 = (runG v limits A t).1 := by
  rw [runG'_eq]

theorem finKey_ext (t : List Nat) :
    keypairFromExpansion (finO' v limits A t) v (sres t (coinEx (params v).n)) = finKey v limits A t := by
  have hk : QL false t (kgTail challengerOracle v (sres t (coinEx (params v).n)))
      (fun O => kgTail (logOracle O) v (sres t (coinEx (params v).n))) := ql_kgTail false v _
  rw [← (ql_value hk _ _ (Pre.trans (kg_pre v limits A t) (pre_ext v limits A t))
    (kgTail_good (finO' v limits A t) v _)).1, kg_value]

/-- Extension conservativity: the extended run has the main game's output (transcript,
    win bit, signed messages), the main game's draws as a prefix of its own, and the
    same honest key. -/
theorem ext_conservative (t : List Nat) :
    (runG' v limits A t).1 = (runG v limits A t).1 ∧ Pre (runG v limits A t).2 (runG' v limits A t).2 ∧
      keypairFromExpansion (finO' v limits A t) v (sres t (coinEx (params v).n)) = finKey v limits A t :=
  ⟨out_ext v limits A t, pre_ext v limits A t, finKey_ext v limits A t⟩

/-- Event preservation: on every won tape, the forgery exhibits one of the
    path-located extraction events on the extended table. -/
theorem rom_extract_ext (t : List Nat) (hw : (runG v limits A t).1.win = true) :
    CanonCollIn (finO' v limits A t) (params v) (expTk (finO' v limits A t) v (sres t (coinEx (params v).n)))
        (expPrf (finO' v limits A t) v (sres t (coinEx (params v).n))) (expSeed v (sres t (coinEx (params v).n)))
        (verifyLog (finO' v limits A t) v (finKey v limits A t).1 (runG v limits A t).1.msg
          (runG v limits A t).1.sig) ∨
      WotsPath (finO' v limits A t) v (sres t (coinEx (params v).n)) (runG v limits A t).1.msg
        (runG v limits A t).1.sig ∨
      ForsPath (finO' v limits A t) v (sres t (coinEx (params v).n)) (runG v limits A t).1.msg
        (runG v limits A t).1.sig (runG v limits A t).1.signed ∨
      CoveredBy (finO' v limits A t) v (finKey v limits A t).2 (runG v limits A t).1.signed
        (splitDigest (params v) (verifyDigest (finO' v limits A t) v (finKey v limits A t).1
          (runG v limits A t).1.msg (runG v limits A t).1.sig)) := by
  have hp := play_extract t v limits (finKey v limits A t).1 (finKey v limits A t).2
    (A (finKey v limits A t).1) []
    (run t (kgTail challengerOracle v (sres t (coinEx (params v).n))) (resD t (coinSt (params v).n))).2
    (by rw [← runG_play]; exact hw) (runG' v limits A t).2 (by rw [← runG_play]; exact pre_ext v limits A t)
  rw [← runG_play] at hp
  obtain ⟨hv, -, -, -⟩ := hp
  have := forgery_extract_path (finO' v limits A t) v (sres t (coinEx (params v).n)) (coinEx_len t v)
    (fun x => oracleOf_len t _ _) (fun x _ => oracleOf_len t _ _) (runG v limits A t).1.signed _ _
    (by rw [finKey_ext]; exact hv)
  rw [finKey_ext] at this
  exact this
end

end DSM.Rom
