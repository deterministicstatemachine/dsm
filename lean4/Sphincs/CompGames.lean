-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.CompProb

/- Modular proof, milestone 2 (part 2): the computational security games of
   the EasyCrypt SPHINCS+ proof (MM45/FV-SPHINCSPLUS-EC @ a28e4c5), on DSM's
   finite-experiment framework, and their instances with DSM's actual
   functions. See `specs/requirements/DSM_MODULAR_PROOF_MAP.md` §4 and §9.

   * `OT`: oracle interaction trees. An adversary is a deterministic tree of
     oracle queries, drawn from its coins (a `FiniteExperiment`); `Within q`
     bounds its queries on every path.
   * PRG and PRF (`KeyedHashFunctions.eca`, theory PRF), with a domain mask:
     outside its domain the real oracle answers the same default as the ideal
     one, so the game is not trivially lost by a query of the wrong shape.
   * ITSR (`KeyedHashFunctions.eca`, theory ITSR): a fresh key per query.
   * SM-DT-TCR, -PRE, -OpenPRE, -DSPR / -SPprob, -UD, each with the
     collection oracle (`-C`); the plain games are the `-C` games with no
     collection queries (`Empty`). As in `TweakableHashFunctions.eca`, `pp`
     is sampled first, the target and collection oracles answer with it, and
     the adversary receives it only in its second phase.

   This file defines games and states what they are; it proves no bound and
   no reduction. Nothing here asserts that a DSM function has any of these
   properties: those are the assumptions of the modular theorem. -/
namespace DSM.Sphincs.Comp
open DSM.Sphincs DSM.Sphincs.Security

/-! ## Oracle interaction trees -/

inductive OT (Q A α : Type) where
  | done (a : α)
  | ask (q : Q) (k : A → OT Q A α)

namespace OT
variable {Q A α σ : Type}

/-- Run against a stateful oracle. -/
def run (o : σ → Q → A × σ) : OT Q A α → σ → α × σ
  | .done a, s => (a, s)
  | .ask q k, s => run o (k (o s q).1) (o s q).2

/-- Run against a fixed function. -/
def eval (f : Q → A) : OT Q A α → α
  | .done a => a
  | .ask q k => eval f (k (f q))

/-- The queries asked when answered by `f`. -/
def trace (f : Q → A) : OT Q A α → List Q
  | .done _ => []
  | .ask q k => q :: trace f (k (f q))

/-- At most `q` queries on every path. -/
def Within : OT Q A α → Nat → Prop
  | .done _, _ => True
  | .ask _ _, 0 => False
  | .ask _ k, q+1 => ∀ a, Within (k a) q

theorem trace_length (f : Q → A) : ∀ (T : OT Q A α) (q : Nat), T.Within q → (T.trace f).length ≤ q
  | .done _, _, _ => Nat.zero_le _
  | .ask _ _, 0, h => absurd h (by simp [Within])
  | .ask q k, n+1, h => by
    simp only [trace, List.length_cons]
    exact Nat.succ_le_succ (trace_length f (k (f q)) n (h _))

/-- A stateful run with a stateless answer and a log of the queries. -/
theorem run_log (f : Q → A) : ∀ (T : OT Q A α) (l : List Q),
    T.run (fun s q => (f q, s ++ [q])) l = (T.eval f, l ++ T.trace f)
  | .done _, l => by simp [run, eval, trace]
  | .ask q k, l => by
    simp only [run, eval, trace]
    rw [run_log f (k (f q)) (l ++ [q])]
    simp
end OT

/-! ## Distinguishing games: PRG and PRF -/

/-- `D` sees `G k` for a key from `K`. -/
def realP {κ Y : Type} (K : FiniteExperiment κ) (G : κ → Y) (D : FiniteExperiment (Y → Bool)) :
    Probability :=
  probability (independentProduct K D) (fun p => p.2 (G p.1))

/-- `D` sees a sample of `U`. -/
def idealP {Y : Type} (U : FiniteExperiment Y) (D : FiniteExperiment (Y → Bool)) : Probability :=
  probability (independentProduct U D) (fun p => p.2 p.1)

/-- PRG advantage `|Pr[D(G s) = 1] − Pr[D(u) = 1]|`, as an exact fraction. -/
def prgAdv {κ Y : Type} (S : FiniteExperiment κ) (G : κ → Y) (U : FiniteExperiment Y)
    (D : FiniteExperiment (Y → Bool)) : Nat × Nat :=
  advantage (realP S G D) (idealP U D)

/-- The oracle restricted to its domain; elsewhere the default `d0`. -/
def mask {I O : Type} (dom : I → Bool) (d0 : O) (f : I → O) : I → O :=
  fun x => if dom x then f x else d0

/-- PRF advantage of a function-access distinguisher: the oracle is
    `F k` (masked to the domain) for a key from `K`, or a sample of `RF`.
    EasyCrypt's PRF game samples the ideal function lazily on its domain;
    `RF` is the same uniform function, drawn up front. -/
def prfAdvFn {κ I O : Type} (K : FiniteExperiment κ) (F : κ → I → O) (dom : I → Bool) (d0 : O)
    (RF : FiniteExperiment (I → O)) (D : FiniteExperiment ((I → O) → Bool)) : Nat × Nat :=
  advantage (realP K (fun k => mask dom d0 (F k)) D) (idealP RF D)

/-- PRF advantage of an oracle adversary (a query tree). -/
def prfAdv {κ I O : Type} (K : FiniteExperiment κ) (F : κ → I → O) (dom : I → Bool) (d0 : O)
    (RF : FiniteExperiment (I → O)) (A : FiniteExperiment (OT I O Bool)) : Nat × Nat :=
  prfAdvFn K F dom d0 RF (A.map (fun T f => T.eval f))

/-- A function-access distinguisher that is a `q`-query tree. Query budgets of
    the distinguishers C15/C16 construct are stated with this. -/
def QueryBounded {I O : Type} (q : Nat) (d : (I → O) → Bool) : Prop :=
  ∃ T : OT I O Bool, T.Within q ∧ ∀ f, d f = T.eval f

theorem prfAdv_queryBounded {I O : Type} (q : Nat) (A : FiniteExperiment (OT I O Bool))
    (h : ∀ i, (A.sample i).Within q) (i : Fin (A.map (fun T f => T.eval f)).cardinality) :
    QueryBounded q ((A.map (fun T (f : I → O) => T.eval f)).sample i) :=
  ⟨A.sample i, h i, fun _ => rfl⟩

/-- The ideal function is defined on the domain only. -/
def DomainOnly {I O : Type} (dom : I → Bool) (d0 : O) (RF : FiniteExperiment (I → O)) : Prop :=
  ∀ i, mask dom d0 (RF.sample i) = RF.sample i

/-! ## ITSR (interleaved target subset resilience) -/

section Itsr
variable {κ X : Type} [DecidableEq κ] [DecidableEq X]

/-- Each query `x` is answered by the next fresh key `k` from the tape, and
    `(k, x)` is recorded. -/
def itsrOracle (k0 : κ) (tape : List κ) (log : List (κ × X)) (x : X) : κ × List (κ × X) :=
  let k := tape.getD log.length k0
  (k, log ++ [(k, x)])

/-- EasyCrypt's winning condition: every index triple of `hix k x` is in the
    union of the queried pairs' triples, and `(k, x)` was not queried. The
    query budget `q` is the tape length. -/
def itsrWin (hix : κ → X → List (Nat × Nat × Nat)) (q : Nat) (log : List (κ × X)) (k : κ) (x : X) :
    Bool :=
  decide (log.length ≤ q) &&
    (hix k x).all (fun t => log.any (fun kx => (hix kx.1 kx.2).contains t)) &&
    !log.contains (k, x)

/-- ITSR success probability; `hix k x = g (mco k x)`. -/
def itsrProb (Keys : FiniteExperiment κ) (k0 : κ) (q : Nat) (hix : κ → X → List (Nat × Nat × Nat))
    (A : FiniteExperiment (OT X κ (κ × X))) : Probability :=
  probability (independentProduct (Keys.tape q) A) (fun p =>
    let r := p.2.run (itsrOracle k0 p.1) []
    itsrWin hix q r.2 r.1.1 r.1.2)
end Itsr

/-! ## Single-function, multi-target, distinct-tweak games, with a collection -/

section SmDt
variable {PP Tw X Xc Y σ : Type} [DecidableEq Tw] [DecidableEq X] [DecidableEq Y]

/-- Targets and collection-oracle tweaks recorded by the challenger. -/
structure Log (T Tw : Type) where
  tgt : List T
  col : List Tw

/-- Distinct target tweaks, disjoint from the collection oracle's
    (EasyCrypt's `dist` and `disj_lists`). -/
def tweaksOk (tws cols : List Tw) : Bool :=
  decide tws.Nodup && tws.all (fun tw => !cols.contains tw)

/-- The collection oracle: `fc pp tw x`, where `fc` evaluates the member of
    the collection selected by the input (EasyCrypt's `fc (get_diff x)`). -/
def colAnswer (fc : PP → Tw → Xc → Y) (pp : PP) {T : Type} (s : Log T Tw) (q : Tw × Xc) :
    Y × Log T Tw :=
  (fc pp q.1 q.2, ⟨s.tgt, s.col ++ [q.1]⟩)

/-- No collection: the plain games. -/
def noCol {PP Tw Y : Type} : PP → Tw → Empty → Y := fun _ _ e => nomatch e

/-! ### SM-DT-TCR(-C) -/

structure TcrAdv (PP Tw X Xc Y σ : Type) where
  pick : OT ((Tw × X) ⊕ (Tw × Xc)) Y σ
  find : σ → PP → Nat × X

def tcrOracle (f : PP → Tw → X → Y) (fc : PP → Tw → Xc → Y) (pp : PP) :
    Log (Tw × X) Tw → (Tw × X) ⊕ (Tw × Xc) → Y × Log (Tw × X) Tw
  | s, .inl q => (f pp q.1 q.2, ⟨s.tgt ++ [q], s.col⟩)
  | s, .inr q => colAnswer fc pp s q

def tcrWin (f : PP → Tw → X → Y) (pp : PP) (t : Nat) (s : Log (Tw × X) Tw) (i : Nat) (x' : X) : Bool :=
  match s.tgt[i]? with
  | none => false
  | some (tw, x) => decide (s.tgt.length ≤ t) && tweaksOk (s.tgt.map Prod.fst) s.col &&
      x != x' && f pp tw x == f pp tw x'

def tcrProb (P : FiniteExperiment PP) (f : PP → Tw → X → Y) (fc : PP → Tw → Xc → Y) (t : Nat)
    (A : FiniteExperiment (TcrAdv PP Tw X Xc Y σ)) : Probability :=
  probability (independentProduct P A) (fun p =>
    let r := p.2.pick.run (tcrOracle f fc p.1) ⟨[], []⟩
    let ix := p.2.find r.1 p.1
    tcrWin f p.1 t r.2 ix.1 ix.2)

/-! ### SM-DT-PRE(-C): targets are images of fresh uniform inputs -/

structure PreAdv (PP Tw X Xc Y σ : Type) where
  pick : OT (Tw ⊕ (Tw × Xc)) Y σ
  find : σ → PP → Nat × X

def preOracle (f : PP → Tw → X → Y) (fc : PP → Tw → Xc → Y) (x0 : X) (pp : PP) (tape : List X) :
    Log (Tw × Y) Tw → Tw ⊕ (Tw × Xc) → Y × Log (Tw × Y) Tw
  | s, .inl tw => let y := f pp tw (tape.getD s.tgt.length x0); (y, ⟨s.tgt ++ [(tw, y)], s.col⟩)
  | s, .inr q => colAnswer fc pp s q

def preWin (f : PP → Tw → X → Y) (pp : PP) (t : Nat) (s : Log (Tw × Y) Tw) (i : Nat) (x : X) : Bool :=
  match s.tgt[i]? with
  | none => false
  | some (tw, y) => decide (s.tgt.length ≤ t) && tweaksOk (s.tgt.map Prod.fst) s.col && f pp tw x == y

def preProb (P : FiniteExperiment PP) (Din : FiniteExperiment X) (x0 : X) (f : PP → Tw → X → Y)
    (fc : PP → Tw → Xc → Y) (t : Nat) (A : FiniteExperiment (PreAdv PP Tw X Xc Y σ)) : Probability :=
  probability (independentProduct (independentProduct P (Din.tape t)) A) (fun p =>
    let r := p.2.pick.run (preOracle f fc x0 p.1.1 p.1.2) ⟨[], []⟩
    let ix := p.2.find r.1 p.1.1
    preWin f p.1.1 t r.2 ix.1 ix.2)

/-! ### SM-DT-OpenPRE(-C): the adversary names the target tweaks, may open
    targets, and must invert an unopened one -/

structure OpenPreAdv (PP Tw X Xc Y σ : Type) where
  pick : OT (Tw × Xc) Y (σ × List Tw)
  find : σ → PP → List Y → OT Nat X (Nat × X)

def openPreProb (P : FiniteExperiment PP) (Din : FiniteExperiment X) (x0 : X)
    (f : PP → Tw → X → Y) (fc : PP → Tw → Xc → Y) (t : Nat)
    (A : FiniteExperiment (OpenPreAdv PP Tw X Xc Y σ)) : Probability :=
  probability (independentProduct (independentProduct P (Din.tape t)) A) (fun p =>
    let pp := p.1.1
    let r := p.2.pick.run (fun (cols : List Tw) q => (fc pp q.1 q.2, cols ++ [q.1])) []
    let tws := r.1.2.take t
    let xs := p.1.2.take tws.length
    let ys := (tws.zip xs).map (fun q => f pp q.1 q.2)
    let fr := (p.2.find r.1.1 pp ys).run (fun (opened : List Nat) i => (xs.getD i x0, opened ++ [i])) []
    match tws[fr.1.1]?, ys[fr.1.1]? with
    | some tw, some y => !fr.2.contains fr.1.1 && tweaksOk tws r.2 && f pp tw fr.1.2 == y
    | _, _ => false)

/-! ### SM-DT-DSPR(-C) and SM-DT-SPprob(-C) -/

structure DsprAdv (PP Tw X Xc Y σ : Type) where
  pick : OT ((Tw × X) ⊕ (Tw × Xc)) Y σ
  guess : σ → PP → Nat × Bool

/-- `sp` decides EasyCrypt's `spexists`: a second preimage exists. -/
def SpDecides (f : PP → Tw → X → Y) (sp : PP → Tw → X → Bool) : Prop :=
  ∀ pp tw x, sp pp tw x = true ↔ ∃ x', x' ≠ x ∧ f pp tw x' = f pp tw x

def dsprRun (P : FiniteExperiment PP) (f : PP → Tw → X → Y) (fc : PP → Tw → Xc → Y) (t : Nat)
    (A : FiniteExperiment (DsprAdv PP Tw X Xc Y σ))
    (win : PP → Tw → X → Bool → Bool) : Probability :=
  probability (independentProduct P A) (fun p =>
    let r := p.2.pick.run (tcrOracle f fc p.1) ⟨[], []⟩
    let ib := p.2.guess r.1 p.1
    match r.2.tgt[ib.1]? with
    | none => false
    | some (tw, x) => decide (r.2.tgt.length ≤ t) && tweaksOk (r.2.tgt.map Prod.fst) r.2.col &&
        win p.1 tw x ib.2)

/-- DSPR: the guess equals whether a second preimage exists. -/
def dsprProb (P : FiniteExperiment PP) (f : PP → Tw → X → Y) (fc : PP → Tw → Xc → Y)
    (sp : PP → Tw → X → Bool) (t : Nat) (A : FiniteExperiment (DsprAdv PP Tw X Xc Y σ)) : Probability :=
  dsprRun P f fc t A (fun pp tw x b => sp pp tw x == b)

/-- SPprob: a second preimage exists at the chosen target (the trivial bound). -/
def spProb (P : FiniteExperiment PP) (f : PP → Tw → X → Y) (fc : PP → Tw → Xc → Y)
    (sp : PP → Tw → X → Bool) (t : Nat) (A : FiniteExperiment (DsprAdv PP Tw X Xc Y σ)) : Probability :=
  dsprRun P f fc t A (fun pp tw x _ => sp pp tw x)

/-- `Adv^DSPR = max(0, Pr[DSPR] − Pr[SPprob])`, an exact fraction. -/
def dsprAdv (P : FiniteExperiment PP) (f : PP → Tw → X → Y) (fc : PP → Tw → Xc → Y)
    (sp : PP → Tw → X → Bool) (t : Nat) (A : FiniteExperiment (DsprAdv PP Tw X Xc Y σ)) : Nat × Nat :=
  let d := dsprProb P f fc sp t A
  let s := spProb P f fc sp t A
  (d.numerator * s.denominator - s.numerator * d.denominator, d.denominator * s.denominator)

/-! ### SM-DT-UD(-C): targets are images of fresh inputs, or fresh uniform outputs -/

structure UdAdv (PP Tw Xc Y σ : Type) where
  pick : OT (Tw ⊕ (Tw × Xc)) Y σ
  distinguish : σ → PP → Bool

def udOracle (answer : Nat → Tw → Y) (fc : PP → Tw → Xc → Y) (pp : PP) :
    Log Tw Tw → Tw ⊕ (Tw × Xc) → Y × Log Tw Tw
  | s, .inl tw => (answer s.tgt.length tw, ⟨s.tgt ++ [tw], s.col⟩)
  | s, .inr q => colAnswer fc pp s q

def udRun {R : Type} (P : FiniteExperiment PP) (Tape : FiniteExperiment R)
    (answer : PP → R → Nat → Tw → Y) (fc : PP → Tw → Xc → Y) (t : Nat)
    (A : FiniteExperiment (UdAdv PP Tw Xc Y σ)) : Probability :=
  probability (independentProduct (independentProduct P Tape) A) (fun p =>
    let r := p.2.pick.run (udOracle (answer p.1.1 p.1.2) fc p.1.1) ⟨[], []⟩
    decide (r.2.tgt.length ≤ t) && tweaksOk r.2.tgt r.2.col && p.2.distinguish r.1 p.1.1)

/-- `b = 0`: target `j` is `f pp tw x_j` for a fresh uniform input `x_j`. -/
def udRealProb (P : FiniteExperiment PP) (Din : FiniteExperiment X) (x0 : X) (f : PP → Tw → X → Y)
    (fc : PP → Tw → Xc → Y) (t : Nat) (A : FiniteExperiment (UdAdv PP Tw Xc Y σ)) : Probability :=
  udRun P (Din.tape t) (fun pp tape j tw => f pp tw (tape.getD j x0)) fc t A

/-- `b = 1`: target `j` is a fresh uniform output. -/
def udIdealProb (P : FiniteExperiment PP) (Dout : FiniteExperiment Y) (y0 : Y)
    (fc : PP → Tw → Xc → Y) (t : Nat) (A : FiniteExperiment (UdAdv PP Tw Xc Y σ)) : Probability :=
  udRun P (Dout.tape t) (fun _ tape j _ => tape.getD j y0) fc t A

def udAdv (P : FiniteExperiment PP) (Din : FiniteExperiment X) (x0 : X) (Dout : FiniteExperiment Y)
    (y0 : Y) (f : PP → Tw → X → Y) (fc : PP → Tw → Xc → Y) (t : Nat)
    (A : FiniteExperiment (UdAdv PP Tw Xc Y σ)) : Nat × Nat :=
  advantage (udRealProb P Din x0 f fc t A) (udIdealProb P Dout y0 fc t A)

end SmDt

/-! ## DSM instances -/

section Dsm
variable (o : Oracle Id) (v : Variant)

/-- Uniform `w`-byte strings, as bytes. -/
def ub (w : Nat) : FiniteExperiment Bytes := (uniformBytes w).map Subtype.val

/-- A tweak is the 32 ADRS bytes. -/
abbrev Tweak := Wire 32

def adrsTweak (a : Adrs) : Tweak := ⟨a.bytes, address_width a⟩

/-- DSM's tweakable-hash collection: keyed BLAKE3 under
    `derive_key("DSM/sphincs/v2/thash", pp)` on `ADRS ‖ x`, first n bytes.
    One function for every input length (EasyCrypt's `diff = |x|`). -/
def thc (pp : Bytes) (tw : Tweak) (x : Bytes) : Bytes :=
  keyed o (params v).n (deriveKey o "DSM/sphincs/v2/thash" pp) (tw.val ++ x)

/-- It is the model's `thash`, at every address and input. -/
theorem thc_thash (pp : Bytes) (a : Adrs) (x : Bytes) :
    thash o (params v) (deriveKey o "DSM/sphincs/v2/thash" pp) a x = thc o v pp (adrsTweak a) x := rfl

/-- The member on `ℓ`-byte inputs: F (ℓ = n), TRH (2n), PKCO (len·n), TRCO (k·n). -/
def thf (ℓ : Nat) (pp : Bytes) (tw : Tweak) (x : Wire ℓ) : Bytes := thc o v pp tw x.val

/-- EasyCrypt's `in_collection` axiom, here a definition. -/
theorem in_collection (ℓ : Nat) : thf o v ℓ = fun pp tw x => thc o v pp tw x.val := rfl

/-- Public parameters: PK.seed, uniform on n bytes. -/
def ppSpace : FiniteExperiment Bytes := ub (params v).n

/-- A decision procedure for `spexists` on `ℓ`-byte inputs, by enumeration. -/
def thfSp (ℓ : Nat) (pp : Bytes) (tw : Tweak) (x : Wire ℓ) : Bool :=
  (List.range (256^ℓ)).any (fun j => be ℓ j != x.val && thc o v pp tw (be ℓ j) == thc o v pp tw x.val)

theorem thfSp_decides (ℓ : Nat) : SpDecides (thf o v ℓ) (thfSp o v ℓ) := by
  intro pp tw x
  unfold thfSp thf
  constructor
  · intro h
    obtain ⟨j, _, hj⟩ := List.any_eq_true.mp h
    simp only [Bool.and_eq_true, bne_iff_ne, ne_eq, beq_iff_eq] at hj
    refine ⟨⟨be ℓ j, be_width ℓ j⟩, fun e => hj.1 (congrArg Subtype.val e), hj.2⟩
  · intro ⟨x', hne, heq⟩
    apply List.any_eq_true.mpr
    have hb : toInt x'.val < 256^ℓ := by have := toInt_bound x'.val; rwa [x'.property] at this
    have hd : be ℓ (toInt x'.val) = x'.val := by
      have := be_decoded_bytes x'.val; rwa [x'.property] at this
    refine ⟨toInt x'.val, List.mem_range.mpr hb, ?_⟩
    simp only [hd, Bool.and_eq_true, bne_iff_ne, ne_eq, beq_iff_eq]
    exact ⟨fun e => hne (Subtype.ext e), heq⟩

/-! ### Message compression and ITSR (map §5a) -/

/-- `MCO_DSM(R, ctx, M)`, `ctx = PK.seed ‖ PK.root`. -/
def mco (R ctx M : Bytes) : Indices :=
  splitDigest (params v) (hmsg o (params v) R (ctx.take (params v).n) (ctx.drop (params v).n) M)

/-- It is what the verifier computes from `R = sig[0, n)` and `pk`. -/
theorem mco_verifier (pk msg sig : Bytes) :
    splitDigest (params v) (hmsg o (params v) (sig.take (params v).n) (pk.take (params v).n)
      (pk.drop (params v).n) msg) = mco o v (sig.take (params v).n) pk msg := rfl

/-- The FORS instance `idx = tree · 2^h' + leaf`. -/
def instanceIndex (ix : Indices) : Nat := ix.tree * 2^(params v).hp + ix.leaf

/-- EasyCrypt's `g`: for tree `i < k`, `(idx, i, md_i)`. -/
def itsrG (ix : Indices) : List (Nat × Nat × Nat) :=
  (List.range (params v).k).map (fun i =>
    (instanceIndex v ix, i, (base2b ix.md (params v).a (params v).k).getD i 0))

/-- `h k x = g (mco k x)` with input `x = (ctx, M)`. -/
def itsrH (R : Bytes) (x : Bytes × Bytes) : List (Nat × Nat × Nat) := itsrG v (mco o v R x.1 x.2)

/-- DSM's ITSR game: `R` uniform on n bytes, input `(ctx, M)`, `q` queries. -/
def dsmItsrProb (q : Nat) (A : FiniteExperiment (OT (Bytes × Bytes) Bytes (Bytes × (Bytes × Bytes)))) :
    Probability :=
  itsrProb (ub (params v).n) [] q (itsrH o v) A

/-! The shape of `g` (EasyCrypt's commented ITSR axioms `size_g`, `eqiks_g`,
    `neqisvs_g`, `rng_iks`, `rng_sv`), proved for DSM. -/

theorem itsrG_size (ix : Indices) : (itsrG v ix).length = (params v).k := by
  simp [itsrG]

theorem itsrG_eqiks (ix : Indices) (x y : Nat × Nat × Nat) (hx : x ∈ itsrG v ix)
    (hy : y ∈ itsrG v ix) : x.1 = y.1 := by
  simp only [itsrG, List.mem_map] at hx hy
  obtain ⟨_, _, rfl⟩ := hx
  obtain ⟨_, _, rfl⟩ := hy
  rfl

theorem itsrG_neqisvs (ix : Indices) (x y : Nat × Nat × Nat) (hx : x ∈ itsrG v ix)
    (hy : y ∈ itsrG v ix) (ne : x ≠ y) : x.2.1 ≠ y.2.1 := by
  simp only [itsrG, List.mem_map] at hx hy
  obtain ⟨i, _, rfl⟩ := hx
  obtain ⟨j, _, rfl⟩ := hy
  intro e
  simp only at e
  subst e
  exact ne rfl

theorem itsrG_rng_sv (ix : Indices) (x : Nat × Nat × Nat) (hx : x ∈ itsrG v ix) :
    x.2.1 < (params v).k ∧ x.2.2 < 2^(params v).a := by
  simp only [itsrG, List.mem_map, List.mem_range] at hx
  obtain ⟨i, hi, rfl⟩ := hx
  refine ⟨hi, ?_⟩
  have hl : i < (base2b ix.md (params v).a (params v).k).length := by simp [base2b, hi]
  rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hl]
  exact base2b_digit_bound _ _ _ _ (List.getElem_mem hl)

theorem itsrG_rng_iks (ix : Indices) (ht : ix.tree < 2^((params v).h - (params v).hp)) (hl : ix.leaf < 2^(params v).hp)
    (x : Nat × Nat × Nat) (hx : x ∈ itsrG v ix) : x.1 < 2^(params v).h := by
  simp only [itsrG, List.mem_map] at hx
  obtain ⟨_, _, rfl⟩ := hx
  unfold instanceIndex
  have hp : (params v).hp ≤ (params v).h := Nat.div_le_self _ _
  have : 2^(params v).h = 2^((params v).h - (params v).hp) * 2^(params v).hp := by
    rw [← Nat.pow_add]; congr 1; omega
  rw [this]
  have := Nat.mul_le_mul_right (2^(params v).hp) (Nat.succ_le_of_lt ht)
  rw [Nat.succ_mul] at this
  omega

/-- `split_digest` always yields indices in range. -/
theorem splitDigest_ranges (d : Bytes) :
    (splitDigest (params v) d).tree < 2^((params v).h - (params v).hp) ∧
      (splitDigest (params v) d).leaf < 2^(params v).hp :=
  ⟨Nat.mod_lt _ (Nat.pow_pos (by decide)), Nat.mod_lt _ (Nat.pow_pos (by decide))⟩

/-! ### PRG and PRF instances (C11, C15, C16) -/

/-- ChaCha20Rng seed expansion, 32 bytes → 3n bytes. -/
def dsmPrgAdv (D : FiniteExperiment (Bytes → Bool)) : Nat × Nat :=
  prgAdv uniformMasterSeed (seedExpansion o v) ((uniformExpansion v).map Subtype.val) D

/-- `derive_key(ctx, ·)` on an n-byte secret seed, as a PRG to 32 bytes
    (C15 hop 2a with `ctx = "DSM/sphincs/v2/prf"`, C16 hop 3a with
    `"DSM/sphincs/v2/prf-msg"`). -/
def dsmKdfAdv (ctx : String) (D : FiniteExperiment (Bytes → Bool)) : Nat × Nat :=
  prgAdv (ub (params v).n) (deriveKey o ctx) (uniformMasterSeed.map Subtype.val) D

/-- Keyed BLAKE3 under a uniform 32-byte key, queried at `(input, outLen)`. -/
def keyedFn (K : Bytes) (q : Bytes × Nat) : Bytes := o ⟨1, "", K, q.1, q.2⟩

/-- SKG's domain: `PK.seed ‖ ADRS` (n+32 bytes), n-byte outputs. -/
def skgDom (q : Bytes × Nat) : Bool := q.1.length == (params v).n + 32 && q.2 == (params v).n

/-- MKG's domain: `PK.seed ‖ M` for a legal `M` (at most n + maxMessageBytes
    bytes), n-byte outputs. -/
def mkgDom (maxMsg : Nat) (q : Bytes × Nat) : Bool :=
  decide (q.1.length ≤ (params v).n + maxMsg) && q.2 == (params v).n

def uncurried (S : FiniteExperiment (Bytes → Nat → Bytes)) : FiniteExperiment (Bytes × Nat → Bytes) :=
  S.map (fun F q => F q.1 q.2)

def dsmSkgPrfAdv (D : FiniteExperiment ((Bytes × Nat → Bytes) → Bool)) : Nat × Nat :=
  prfAdvFn (uniformMasterSeed.map Subtype.val) (keyedFn o) (skgDom v) []
    (uncurried (randomFunction ((params v).n + 32) (params v).n)) D

def dsmMkgPrfAdv (maxMsg : Nat) (D : FiniteExperiment ((Bytes × Nat → Bytes) → Bool)) : Nat × Nat :=
  prfAdvFn (uniformMasterSeed.map Subtype.val) (keyedFn o) (mkgDom v maxMsg) []
    (uncurried (randomFunctionUpTo ((params v).n + maxMsg) (params v).n)) D

theorem skg_domain_only : DomainOnly (skgDom v) []
    (uncurried (randomFunction ((params v).n + 32) (params v).n)) := by
  intro i; funext q
  unfold mask skgDom
  by_cases h : q.1.length = (params v).n + 32 ∧ q.2 = (params v).n
  · simp [h.1, h.2]
  · have : (q.1.length == (params v).n + 32 && q.2 == (params v).n) = false := by
      simp only [Bool.and_eq_false_iff, beq_eq_false_iff_ne]; omega
    rw [if_neg (by simp [this])]
    show [] = (if q.1.length = (params v).n + 32 ∧ q.2 = (params v).n then _ else [])
    rw [if_neg h]

theorem mkg_domain_only (maxMsg : Nat) : DomainOnly (mkgDom v maxMsg) []
    (uncurried (randomFunctionUpTo ((params v).n + maxMsg) (params v).n)) := by
  intro i; funext q
  unfold mask mkgDom
  by_cases h : q.1.length ≤ (params v).n + maxMsg ∧ q.2 = (params v).n
  · simp [h.1, h.2]
  · have : (decide (q.1.length ≤ (params v).n + maxMsg) && q.2 == (params v).n) = false := by
      simp only [Bool.and_eq_false_iff, beq_eq_false_iff_ne, decide_eq_false_iff_not]; omega
    rw [if_neg (by simp [this])]
    show [] = (if q.1.length ≤ (params v).n + maxMsg ∧ q.2 = (params v).n then _ else [])
    rw [if_neg h]

/-! ### The tweakable-hash games for DSM's roles -/

/-- SM-DT-TCR-C for the member on `ℓ`-byte inputs, `t` targets. -/
def dsmTcrC {σ : Type} (ℓ t : Nat) (A : FiniteExperiment (TcrAdv Bytes Tweak (Wire ℓ) Bytes Bytes σ)) :
    Probability :=
  tcrProb (ppSpace v) (thf o v ℓ) (thc o v) t A

/-- SM-DT-PRE-C for F (n-byte inputs). -/
def dsmPreC {σ : Type} (t : Nat) (A : FiniteExperiment (PreAdv Bytes Tweak (Wire (params v).n) Bytes Bytes σ)) :
    Probability :=
  preProb (ppSpace v) (uniformBytes (params v).n) ⟨be (params v).n 0, be_width _ _⟩ (thf o v (params v).n)
    (thc o v) t A

/-- SM-DT-OpenPRE for F (no collection; EasyCrypt's Theorem 1 uses the plain game). -/
def dsmOpenPre {σ : Type} (t : Nat)
    (A : FiniteExperiment (OpenPreAdv Bytes Tweak (Wire (params v).n) Empty Bytes σ)) : Probability :=
  openPreProb (ppSpace v) (uniformBytes (params v).n) ⟨be (params v).n 0, be_width _ _⟩
    (thf o v (params v).n) noCol t A

/-- SM-DT-DSPR for F, against SM-DT-SPprob. -/
def dsmDsprAdv {σ : Type} (t : Nat)
    (A : FiniteExperiment (DsprAdv Bytes Tweak (Wire (params v).n) Empty Bytes σ)) : Nat × Nat :=
  dsprAdv (ppSpace v) (thf o v (params v).n) noCol (thfSp o v (params v).n) t A

/-- SM-DT-TCR for F (no collection; used inside Theorem 2). -/
def dsmTcrF {σ : Type} (t : Nat) (A : FiniteExperiment (TcrAdv Bytes Tweak (Wire (params v).n) Empty Bytes σ)) :
    Probability :=
  tcrProb (ppSpace v) (thf o v (params v).n) noCol t A

/-- SM-DT-UD-C for F: fresh n-byte inputs against fresh n-byte outputs. -/
def dsmUdCAdv {σ : Type} (t : Nat) (A : FiniteExperiment (UdAdv Bytes Tweak Bytes Bytes σ)) : Nat × Nat :=
  udAdv (ppSpace v) (uniformBytes (params v).n) ⟨be (params v).n 0, be_width _ _⟩ (ub (params v).n) []
    (thf o v (params v).n) (thc o v) t A

end Dsm

#print axioms OT.trace_length
#print axioms OT.run_log
#print axioms thfSp_decides
#print axioms itsrG_neqisvs
#print axioms itsrG_rng_sv
#print axioms itsrG_rng_iks
#print axioms skg_domain_only
#print axioms mkg_domain_only
end DSM.Sphincs.Comp
