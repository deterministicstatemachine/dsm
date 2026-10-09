-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.CompAddress
import Sphincs.CompOpenPre
import Sphincs.CompWotsUd
open DSM.Sphincs DSM.Sphincs.Security DSM.Sphincs.Comp

/- Controls for the computational games (milestone 2). Each game is run on a
   deliberately insecure toy function, small enough to enumerate exactly: a
   positive control must win with the exact expected probability, and each
   negative control must lose because of the restriction it violates
   (distinct tweaks, collection disjointness, target bound, freshness,
   opened targets, query budget). The DSM instances are exercised on an
   insecure oracle at fixed points, since their spaces are 2^256 tickets. -/

private def single {α : Type} (a : α) : FiniteExperiment α := ⟨1, by decide, fun _ => a⟩
private def coin : FiniteExperiment Bool := ⟨2, by decide, fun i => i.val == 1⟩
private def bools : FiniteExperiment (Bool → Bool) :=
  ⟨4, by decide, fun i b => if b then i.val / 2 == 1 else i.val % 2 == 1⟩


-- Toy WOTS-TW: w = 4, two chains, digits (m mod 4, 3 − m mod 4) (a checksum),
-- one-bit chain values, tweak = (instance, chain, depth).
private def wset (f : Bool → Nat × Nat × Nat → Bool → Bool) :
    WotsSetting Bool (Nat × Nat × Nat) Nat Nat Bool Bool :=
  { w := 4, len := 2, enc := fun m => [m % 4, 3 - m % 4], twk := fun a c h => (a, c, h),
    inst := fun tw => tw.1, f := f, fc := f, embed := id }
private def fConst : Bool → Nat × Nat × Nat → Bool → Bool := fun _ _ _ => false
private def fXor : Bool → Nat × Nat × Nat → Bool → Bool := fun pp _ x => x != pp
private def sigOf : WotsAnswer Bool → List Bool × List Bool
  | .inl r => r
  | .inr _ => ([], [])
/-- Signs message 0 on instance 0, forges message 1: one step up chain 0, a
    brute-force preimage on chain 1. -/
private def wForge (f : Bool → Nat × Nat × Nat → Bool → Bool) (qs : List (WotsQuery (Nat × Nat × Nat) Nat Nat Bool))
    (msg : Nat) : WotsAdv Bool (Nat × Nat × Nat) Nat Nat Bool Bool (List Bool × List Bool) :=
  ⟨qs.foldr (fun q k => .ask q (fun _ => k)) (.ask (.inl (0, 0)) (fun r => .done (sigOf r))),
   fun st pp =>
    let s0 := st.2.getD 0 false
    let pk1 := st.1.getD 1 false
    if msg == 1 then (0, 1, [f pp (0, 0, 0) s0, if f pp (0, 1, 2) false == pk1 then false else true])
    else (0, msg, st.2)⟩

private def check (ok : Bool) (msg : String) : IO Unit :=
  unless ok do throw (IO.userError msg)

private def frac (p : Probability) : Nat × Nat := (p.numerator, p.denominator)

-- Toy tweakable hash: parity of the input, shifted by pp.
private def tf (pp : Bool) (_ : Nat) (x : Nat) : Nat := (x + (if pp then 1 else 0)) % 2

private def colN (_ : Bool) (_ : Nat) (x : Nat) : Nat := x % 7
private def tcr1 : TcrAdv Bool Nat Nat Nat Nat Unit :=
  ⟨.ask (.inl (0, 0)) (fun _ => .done ()), fun _ _ => (0, 2)⟩
private def tcrDup : TcrAdv Bool Nat Nat Nat Nat Unit :=
  ⟨.ask (.inl (0, 0)) (fun _ => .ask (.inl (0, 1)) (fun _ => .done ())), fun _ _ => (0, 2)⟩
private def tcrCol : TcrAdv Bool Nat Nat Nat Nat Unit :=
  ⟨.ask (.inl (0, 0)) (fun _ => .ask (.inr (0, 5)) (fun _ => .done ())), fun _ _ => (0, 2)⟩
private def tcrTwo : TcrAdv Bool Nat Nat Nat Nat Unit :=
  ⟨.ask (.inl (0, 0)) (fun _ => .ask (.inl (1, 1)) (fun _ => .done ())), fun _ _ => (0, 2)⟩
private def tcrSame : TcrAdv Bool Nat Nat Nat Nat Unit :=
  ⟨.ask (.inl (0, 0)) (fun _ => .done ()), fun _ _ => (0, 0)⟩

-- ITSR toy: key k selects the key set, the input's parity the secret.
private def hix (k : Bool) (x : Nat) : List (Nat × Nat × Nat) := [(if k then 1 else 0, 0, x % 2)]
private def itsr1 : OT Nat Bool (Bool × Nat) := .ask 0 (fun k => .done (k, 2))
private def itsrOld : OT Nat Bool (Bool × Nat) := .ask 0 (fun k => .done (k, 0))
private def itsrOver : OT Nat Bool (Bool × Nat) := .ask 0 (fun _ => .ask 1 (fun k => .done (k, 2)))

-- PRE / OpenPRE / UD / DSPR toys.
private def idf (_ : Bool) (_ : Nat) (x : Bool) : Bool := x
private def constf (_ : Bool) (_ : Nat) (_ : Bool) : Bool := false
private def pre1 : PreAdv Bool Nat Bool Empty Bool Bool :=
  ⟨.ask (.inl 0) (fun y => .done y), fun y _ => (0, y)⟩
private def open1 : OpenPreAdv Bool Nat Bool Empty Bool Unit :=
  ⟨.done ((), [0, 1]), fun _ _ ys => .done (1, ys.getD 1 false)⟩
private def openOpened : OpenPreAdv Bool Nat Bool Empty Bool Unit :=
  ⟨.done ((), [0, 1]), fun _ _ _ => .ask 0 (fun x => .done (0, x))⟩
private def ud1 : UdAdv Bool Nat Empty Bool Bool :=
  ⟨.ask (.inl 0) (fun y => .done y), fun y _ => !y⟩
private def dsprYes : DsprAdv Bool Nat Bool Empty Bool Unit :=
  ⟨.ask (.inl (0, false)) (fun _ => .done ()), fun _ _ => (0, true)⟩
private def dsprNo : DsprAdv Bool Nat Bool Empty Bool Unit :=
  ⟨.ask (.inl (0, false)) (fun _ => .done ()), fun _ _ => (0, false)⟩
private def spConst (_ : Bool) (_ : Nat) (_ : Bool) : Bool := true
private def spId (_ : Bool) (_ : Nat) (_ : Bool) : Bool := false

-- Insecure oracle: every request answers zeros.
private def zeroOracle : Oracle Id := fun r => List.replicate r.outLen 0

def main : IO Unit := do
  -- TCR(-C)
  check (frac (tcrProb coin tf colN 4 (single tcr1)) == (2, 2)) "TCR positive control"
  check ((tcrProb coin tf colN 4 (single tcrDup)).numerator == 0) "TCR accepted repeated tweaks"
  check ((tcrProb coin tf colN 4 (single tcrCol)).numerator == 0)
    "TCR-C accepted a collection tweak equal to a target tweak"
  check ((tcrProb coin tf colN 1 (single tcrTwo)).numerator == 0) "TCR exceeded the target bound"
  check ((tcrProb coin tf colN 4 (single tcrSame)).numerator == 0) "TCR accepted x' = x"
  -- ITSR
  check (frac (itsrProb coin false 1 hix (single itsr1)) == (2, 2)) "ITSR positive control"
  check ((itsrProb coin false 1 hix (single itsrOld)).numerator == 0) "ITSR accepted a queried pair"
  check ((itsrProb coin false 1 hix (single itsrOver)).numerator == 0) "ITSR exceeded the query budget"
  -- PRF: F k x = k xor x is distinguishable (F k false ≠ F k true always).
  let prfD : FiniteExperiment ((Bool → Bool) → Bool) := single (fun f => f false != f true)
  let adv := prfAdvFn coin (fun k x => xor k x) (fun _ => true) false bools prfD
  check (adv == (4, 8)) "PRF advantage of the xor control is not 1/2"
  -- The mask: outside the domain both worlds answer the default.
  let maskD : FiniteExperiment ((Bool → Bool) → Bool) := single (fun f => f true)
  let ideal0 : FiniteExperiment (Bool → Bool) := ⟨2, by decide, fun i b => if b then false else i.val == 1⟩
  check (prfAdvFn coin (fun k x => xor k x) (fun b => !b) false ideal0 maskD == (0, 4))
    "a query outside the PRF domain distinguished the worlds"
  -- PRE: the identity is invertible; OpenPRE: opened targets do not count.
  check (frac (preProb coin coin false idf noCol 1 (single pre1)) == (4, 4)) "PRE positive control"
  check (frac (openPreProb coin coin false idf noCol 2 (single open1)) == (8, 8))
    "OpenPRE positive control"
  check ((openPreProb coin coin false idf noCol 2 (single openOpened)).numerator == 0)
    "OpenPRE accepted an opened target"
  check ((openPreProb coin coin false idf noCol 1 (single open1)).numerator == 0)
    "OpenPRE kept targets beyond the bound"
  -- UD: a constant function is distinguishable from uniform outputs (1/2).
  let ud := udAdv coin coin false coin false constf noCol 1 (single ud1)
  check (ud.1 * 2 == ud.2) "UD advantage of the constant control is not 1/2"
  -- DSPR: constant f has second preimages everywhere (advantage 0 with SPprob 1);
  -- the identity has none (advantage 1).
  let a1 := dsprAdv coin constf noCol spConst 1 (single dsprYes)
  let a2 := dsprAdv coin idf noCol spId 1 (single dsprNo)
  check (a1.1 == 0 && a2.1 == a2.2) "DSPR accounting"
  check ((spProb coin constf noCol spConst 1 (single dsprYes)).numerator == 2) "SPprob control"
  -- DSM instances, on the insecure oracle at fixed points.
  let v := Variant.spx256f
  let p := params v
  let pp : Bytes := List.replicate p.n 3
  let tw := adrsTweak {kind := 3}
  let x1 : Wire p.n := ⟨be p.n 1, be_width _ _⟩
  let x2 : Wire p.n := ⟨be p.n 2, be_width _ _⟩
  check (thf zeroOracle v p.n pp tw x1 == thf zeroOracle v p.n pp tw x2 &&
    (thf zeroOracle v p.n pp tw x1).length == p.n) "insecure DSM thash control"
  check (tcrWin (thf zeroOracle v p.n) pp 1 ⟨[(tw, x1)], []⟩ 0 x2) "DSM TCR win on the insecure oracle"
  check (!tcrWin (thf zeroOracle v p.n) pp 1 ⟨[(tw, x1)], [tw]⟩ 0 x2) "DSM TCR-C disjointness"
  let ix := mco zeroOracle v (List.replicate p.n 0) (List.replicate (2*p.n) 0) [1]
  check ((itsrG v ix).length == p.k && (itsrG v ix).all (fun t => t.1 == instanceIndex v ix))
    "DSM ITSR index map shape"
  -- EasyCrypt address map round trip.
  let a : Adrs := {layer := 3, tree := 5, kind := 2, chain := 1, hash := 4}
  check (ofEc (ecIdx a) == a && ecIdx a == [4, 1, 0, 2, 5, 3]) "EasyCrypt address map"
  -- Theorem 2 on toys: counts satisfy #OpenPRE + #SPprob ≤ #DSPR + 3·#TCR, and
  -- the TCR reduction wins whenever A inverts a constant function with x' ≠ x.
  let guess0 : OpenPreAdv Bool Nat Bool Empty Bool Unit := ⟨.done ((), [0, 1]), fun _ _ _ => .done (0, false)⟩
  for (fn, spn, name) in [(constf, spConst, "constant"), (idf, spId, "identity")] do
    let op := (openPreProb coin coin false fn noCol 2 (single guess0)).numerator
    let d := (dsprProb coin fn noCol spn 2 (dsprRedCoins 2 false (single guess0) coin)).numerator
    let sp := (spProb coin fn noCol spn 2 (dsprRedCoins 2 false (single guess0) coin)).numerator
    let tc := (tcrProb coin fn noCol 2 (tcrRedCoins 2 false (single guess0) coin)).numerator
    check (op + sp ≤ d + 3 * tc) s!"Theorem 2 count inequality fails on the {name} control"
    if name == "constant" then
      check (op == 8 && tc == 4) s!"Theorem 2 constant control: op={op} tc={tc}"
  -- WOTS-TW on toys: the forger wins every ticket (8 = 2 pp × 4 tapes); a
  -- replayed message, a second signing query (c = 1) and a collection query
  -- in the signed instance each lose; the UD-C step's exact identity
  -- |D|^t·#G + #ideal = #real + |D|^t·#Hyb_{w−2} holds on both toys.
  for (fn, name) in [(fConst, "constant"), (fXor, "xor")] do
    let W := wset fn
    let g := fun (A : WotsAdv Bool (Nat × Nat × Nat) Nat Nat Bool Bool (List Bool × List Bool)) =>
      (W.gameProb false 1 coin coin (single A)).numerator
    check (g (wForge fn [] 1) == 8) s!"WOTS forger control ({name})"
    check (g (wForge fn [] 0) == 0) s!"WOTS replayed message control ({name})"
    check (g (wForge fn [.inl (1, 2)] 1) == 0) s!"WOTS signing budget control ({name})"
    check (g (wForge fn [.inr ((0, 1, 2), true)] 1) == 0) s!"WOTS collection disjointness control ({name})"
    let co := W.udCoins 1 false coin (single (wForge fn [] 1)) 2 (by decide)
    let re := (udRealProb coin coin false W.f W.fc 2 co).numerator
    let id := (udIdealProb coin coin false W.fc 2 co).numerator
    let h2 := (W.hybProb false 1 coin coin (single (wForge fn [] 1)) 2).numerator
    check (4 * g (wForge fn [] 1) + id == re + 4 * h2) s!"WOTS UD-C identity ({name}): re={re} id={id} h2={h2}"
  IO.println "Computational game controls passed: TCR(-C), ITSR, PRF (with domain mask), PRE, OpenPRE, UD, DSPR/SPprob, Theorem 2's reductions, the WOTS-TW game and its UD-C step, and the DSM instances on an insecure oracle."
