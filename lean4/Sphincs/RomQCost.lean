-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomSeed

/- Oracle-request counts of the honest routines as query trees.

   `Cnt allR T n`: every path of `T` asks at most `n` requests. These are the
   costs a reduction pays when it simulates another key's key generation,
   signing or verification through its own hash queries. The bounds use the
   step formulas of `RomBudget` (`kgC`, `signC`, `verC`), which count the
   symbolic routines' requests and reveals, so they bound the query trees'
   requests. -/
namespace DSM.Rom
open DSM.Sphincs DSM.Sphincs.Security

def allR (_ : Request) : Bool := true

namespace Cnt
variable {P : Request → Bool}

theorem bindm {α β : Type} {T : QT α} {f : α → QT β} {n1 n2 n : Nat} (hT : Cnt P T n1)
    (hf : ∀ a, Cnt P (f a) n2) (h : n1 + n2 ≤ n) : Cnt P (T >>= f) n := mono (bind hT hf) h

theorem pureN {α : Type} (a : α) (n : Nat) : Cnt P (Pure.pure a : QT α) n := trivial

theorem forInN {ι σ : Type} (l : List ι) (G : ι → σ → QT (ForInStep σ)) (c : Nat)
    (h : ∀ i ∈ l, ∀ s, Cnt P (G i s) c) : ∀ init, Cnt P (ForIn.forIn l init G) (l.length * c) := by
  induction l with
  | nil => intro init; exact pureN (P := P) init _
  | cons a l ih =>
    intro init
    simp only [List.forIn_cons]
    refine bindm (h a (by simp) init) (n2 := l.length * c) (fun r => ?_) (by simp [Nat.succ_mul]; omega)
    cases r with
    | done b => exact pureN b _
    | yield b => exact ih (fun i hi s => h i (by simp [hi]) s) b

end Cnt

section
variable (g : Bool) (p : Params) (tk : Bytes)

theorem a_thash (a : Adrs) (x : Bytes) : Cnt allR (thash (tagO g) p tk a x) 1 := Cnt.ask1 g _

theorem a_chain (a : Adrs) : ∀ (steps : Nat) (x : Bytes) (start : Nat),
    Cnt allR (chain (tagO g) p tk a x start steps) steps
  | 0, x, _ => Cnt.pure x
  | steps+1, x, start => by
    simp only [chain]
    exact Cnt.bindm (a_thash g p tk _ _) (fun y => a_chain a steps y (start+1)) (by omega)

theorem a_authWalk (a : Adrs) (auth : Bytes) : ∀ (remaining li gi level : Nat) (node : Bytes),
    Cnt allR (authWalk (tagO g) p tk a li gi node auth level remaining) remaining
  | 0, _, _, _, node => Cnt.pure node
  | remaining+1, li, gi, level, node => by
    simp only [authWalk]
    exact Cnt.bindm (a_thash g p tk _ _) (fun y => a_authWalk a auth remaining _ _ _ y) (by omega)

theorem a_wotsPkFromSig (a : Adrs) (sig msg : Bytes) :
    Cnt allR (wotsPkFromSig (tagO g) p tk a sig msg) (15 * p.len + 1) := by
  simp only [wotsPkFromSig, wotsCompress]
  refine Cnt.bindm (Cnt.forInN _ _ 15 ?_ []) (fun tops => a_thash g p tk _ _) (by simp [wots_digit_count]; omega)
  intro x _ s
  obtain ⟨digit, i⟩ := x
  exact Cnt.bindm (a_chain g p tk _ _ _ _) (fun top => Cnt.pure _) (by omega)

theorem a_xmssPkFromSig (a : Adrs) (idx : Nat) (sig msg : Bytes) :
    Cnt allR (xmssPkFromSig (tagO g) p tk a idx sig msg) (xpC p) := by
  simp only [xmssPkFromSig, authRoot, xpC]
  exact Cnt.bindm (a_wotsPkFromSig g p tk _ _ _) (fun node => a_authWalk g p tk _ _ _ _ _ _ _) (Nat.le_refl _)

theorem a_htRootTail : ∀ (remaining layer tree : Nat) (node sig : Bytes),
    Cnt allR (htRootTail (tagO g) p tk layer tree node sig remaining) (remaining * xpC p)
  | 0, _, _, node, _ => Cnt.pureN (P := allR) node _
  | remaining+1, layer, tree, node, sig => by
    simp only [htRootTail]
    exact Cnt.bindm (a_xmssPkFromSig g p tk _ _ _ _) (fun root => a_htRootTail remaining _ _ root _)
      (by rw [Nat.succ_mul]; omega)

theorem a_htRoot (sig msg : Bytes) (tree leaf : Nat) (hd : 1 ≤ p.d) :
    Cnt allR (htRoot (tagO g) p tk sig msg tree leaf) (p.d * xpC p) := by
  simp only [htRoot]
  refine Cnt.bindm (a_xmssPkFromSig g p tk _ _ _ _) (fun node => a_htRootTail g p tk (p.d - 1) _ _ node _) ?_
  obtain ⟨d', hd'⟩ : ∃ d', p.d = d' + 1 := ⟨p.d - 1, by omega⟩
  rw [hd', Nat.add_sub_cancel, Nat.succ_mul]; omega

theorem a_forsPkFromSig (a : Adrs) (sig md : Bytes) :
    Cnt allR (forsPkFromSig (tagO g) p tk a sig md) (p.k * (1 + p.a) + 1) := by
  simp only [forsPkFromSig, authRoot]
  refine Cnt.bindm (Cnt.forInN _ _ (1 + p.a) ?_ []) (fun roots => a_thash g p tk _ _) (by simp [base2b_length])
  intro x _ s
  obtain ⟨idx, i⟩ := x
  exact Cnt.bindm (a_thash g p tk _ _) (fun leaf => Cnt.bindm (a_authWalk g p tk _ _ _ _ _ _ leaf)
    (fun root => Cnt.pure _) (Nat.le_refl _)) (by omega)

variable (prfKey seed : Bytes)

theorem a_wotsPkgen (a : Adrs) : Cnt allR (wotsPkgen (tagO g) p tk prfKey seed a) (16 * p.len + 1) := by
  simp only [wotsPkgen, wotsCompress]
  refine Cnt.bindm (Cnt.forInN _ _ 16 ?_ []) (fun tops => a_thash g p tk _ _) (by simp; omega)
  intro i _ s
  exact Cnt.bindm (Cnt.ask1 g _) (fun sk => Cnt.bindm (a_chain g p tk _ _ _ _) (fun top => Cnt.pure _)
    (Nat.le_refl _)) (by omega)

theorem a_xmssNode (a : Adrs) : ∀ (height idx : Nat),
    Cnt allR (xmssNode (tagO g) p tk prfKey seed a idx height) (xC p height)
  | 0, idx => by simp only [xmssNode, xC]; exact a_wotsPkgen g p tk prfKey seed _
  | height+1, idx => by
    simp only [xmssNode, xC]
    exact Cnt.bindm (a_xmssNode a height (2*idx)) (fun l => Cnt.bindm (a_xmssNode a height (2*idx+1))
      (fun r => a_thash g p tk _ _) (Nat.le_refl _)) (by omega)

theorem a_wotsSign (a : Adrs) (msg : Bytes) : Cnt allR (wotsSign (tagO g) p tk prfKey seed a msg) (16 * p.len) := by
  simp only [wotsSign]
  refine Cnt.bindm (Cnt.forInN _ _ 16 ?_ []) (fun sig => Cnt.pure _) (by simp [wots_digit_count]; omega)
  intro x hx s
  have := digit_le p hx
  obtain ⟨digit, i⟩ := x
  exact Cnt.bindm (Cnt.ask1 g _) (fun sk => Cnt.bindm (a_chain g p tk _ _ _ _) (fun part => Cnt.pure _)
    (Nat.le_refl _)) (by simp only at this; omega)

theorem a_xmssSign (a : Adrs) (idx : Nat) (msg : Bytes) :
    Cnt allR (xmssSign (tagO g) p tk prfKey seed a idx msg) (xsC p) := by
  simp only [xmssSign, xsC]
  refine Cnt.bindm (Cnt.forInN _ _ (xC p p.hp) ?_ []) (fun auth => Cnt.bindm (a_wotsSign g p tk prfKey seed _ _)
    (fun sig => Cnt.pure _) (Nat.le_refl _)) (by simp)
  intro level hl s
  have hl' := List.mem_range.mp hl
  exact Cnt.bindm (a_xmssNode g p tk prfKey seed _ _ _) (fun node => Cnt.pure _)
    (by have := xC_mono p (show level ≤ p.hp by omega); omega)

theorem a_htSignTail : ∀ (remaining layer tree : Nat) (node : Bytes),
    Cnt allR (htSignTail (tagO g) p tk prfKey seed layer tree node remaining) (remaining * (xsC p + xpC p))
  | 0, _, _, _ => Cnt.pureN (P := allR) _ _
  | remaining+1, layer, tree, node => by
    simp only [htSignTail]
    refine Cnt.bindm (a_xmssSign g p tk prfKey seed _ _ _) (n2 := xpC p + remaining * (xsC p + xpC p))
      (fun part => ?_) (by rw [Nat.succ_mul]; omega)
    refine Cnt.ite (fun _ => Cnt.pureN _ _) (fun _ => ?_)
    exact Cnt.bindm (Cnt.pure _) (fun _ => Cnt.bindm (a_xmssPkFromSig g p tk _ _ _ _)
      (fun root => Cnt.bindm (a_htSignTail remaining _ _ root) (fun tail => Cnt.pure _) (Nat.le_refl _))
      (Nat.le_refl _)) (by omega)

theorem a_htSign (msg : Bytes) (tree leaf : Nat) (hd : 1 ≤ p.d) :
    Cnt allR (htSign (tagO g) p tk prfKey seed msg tree leaf) (p.d * (xsC p + xpC p)) := by
  simp only [htSign]
  refine Cnt.bindm (a_xmssSign g p tk prfKey seed _ _ _) (fun first => Cnt.bindm (a_xmssPkFromSig g p tk _ _ _ _)
    (fun root => Cnt.bindm (a_htSignTail g p tk prfKey seed (p.d - 1) _ _ root) (fun tail => Cnt.pure _)
      (Nat.le_refl _)) (Nat.le_refl _)) ?_
  obtain ⟨d', hd'⟩ : ∃ d', p.d = d' + 1 := ⟨p.d - 1, by omega⟩
  rw [hd', Nat.add_sub_cancel, Nat.succ_mul]; omega

theorem a_forsNode (a : Adrs) : ∀ (height idx : Nat), Cnt allR (forsNode (tagO g) p tk prfKey seed a idx height) (fC height)
  | 0, idx => by
    simp only [forsNode, forsSecret, fC]
    exact Cnt.bindm (Cnt.ask1 g _) (fun sk => a_thash g p tk _ _) (by omega)
  | height+1, idx => by
    simp only [forsNode, fC]
    exact Cnt.bindm (a_forsNode a height (2*idx)) (fun l => Cnt.bindm (a_forsNode a height (2*idx+1))
      (fun r => a_thash g p tk _ _) (Nat.le_refl _)) (by omega)

theorem a_forsSign (a : Adrs) (md : Bytes) :
    Cnt allR (forsSign (tagO g) p tk prfKey seed a md) (p.k * (1 + p.a * fC p.a)) := by
  simp only [forsSign, forsSecret]
  refine Cnt.bindm (Cnt.forInN _ _ (1 + p.a * fC p.a) ?_ []) (fun sig => Cnt.pure _) (by simp [base2b_length])
  intro x _ s
  obtain ⟨idx, i⟩ := x
  refine Cnt.bindm (Cnt.ask1 g _) (n2 := p.a * fC p.a) (fun sk => ?_) (by omega)
  refine Cnt.bindm (Cnt.forInN _ _ (fC p.a) ?_ _) (fun r => Cnt.bindm (Cnt.pure _) (fun _ => Cnt.pure _)
    (Nat.le_refl _)) (by simp)
  intro level hl u
  have hl' := List.mem_range.mp hl
  exact Cnt.bindm (a_forsNode g p tk prfKey seed _ _ _) (fun node => Cnt.bindm (Cnt.pure _)
    (fun _ => Cnt.pure _) (Nat.le_refl _)) (by have := fC_mono (show level ≤ p.a by omega); omega)

end

/-- Signing asks at most `signC` requests. -/
theorem a_sign (g : Bool) (v : Variant) (sk msg : Bytes) : Cnt allR (sign (tagO g) v sk msg) (signC (params v)) := by
  have hd : 1 ≤ (params v).d := by cases v <;> decide
  simp only [sign, signC]
  refine Cnt.ite (fun _ => Cnt.pureN _ _) (fun _ => ?_)
  have h1 := Nat.mul_le_mul_left (params v).d (show xsC (params v) + xpC (params v) ≤ 1 + xsC (params v) + xpC (params v) by omega)
  have h2 := Nat.mul_le_mul_left (params v).d (show xpC (params v) ≤ 1 + xpC (params v) by omega)
  exact Cnt.mono (Cnt.bind (Cnt.pure _) (fun _ => Cnt.bind (Cnt.ask1 g _) (fun tk => Cnt.bind (Cnt.ask1 g _) (fun pk =>
    Cnt.bind (Cnt.ask1 g _) (fun mk => Cnt.bind (Cnt.ask1 g _) (fun r => Cnt.bind (Cnt.ask1 g _) (fun dg =>
    Cnt.bind (a_forsSign g _ tk pk _ _ _) (fun fs => Cnt.bind (a_forsPkFromSig g _ tk _ _ _) (fun fpk =>
    Cnt.bind (a_htSign g _ tk pk _ _ _ _ hd) (fun hs => Cnt.bind (a_htRoot g _ tk _ _ _ _ hd) (fun ac =>
    Cnt.ite (fun _ => Cnt.pureN _ 0) (fun _ => Cnt.bind (Cnt.pure _) (fun _ => Cnt.pure _))))))))))))) (by omega)

theorem a_kgTail (g : Bool) (v : Variant) (ex : Bytes) : Cnt allR (kgTail (tagO g) v ex) (kgC (params v)) := by
  simp only [kgTail, kgC]
  exact Cnt.bindm (Cnt.ask1 g _) (fun tk => Cnt.bindm (Cnt.ask1 g _)
    (fun pk => Cnt.bindm (a_xmssNode g _ tk pk _ _ _ _) (fun root => Cnt.pure _) (Nat.le_refl _)) (Nat.le_refl _))
    (by omega)

/-- Key generation asks at most `kgC + 1` requests (the expansion and `kgTail`). -/
theorem a_keygen (g : Bool) (v : Variant) (seed : Wire 32) :
    Cnt allR (generateKeypair (tagO g) v seed) (kgC (params v) + 1) := by
  rw [generateKeypair_split]
  exact Cnt.bindm (Cnt.ask1 g _) (fun ex => a_kgTail g v ex) (by omega)

/-- Verification asks at most `verC` requests. -/
theorem a_verify (g : Bool) (v : Variant) (pk msg sig : Bytes) :
    Cnt allR (verify (tagO g) v pk msg sig) (verC (params v)) := by
  have hd : 1 ≤ (params v).d := by cases v <;> decide
  simp only [verify, verC]
  refine Cnt.ite (fun _ => Cnt.pureN _ _) (fun _ => ?_)
  exact Cnt.mono (Cnt.bind (Cnt.pure _) (fun _ => Cnt.ite (fun _ => Cnt.pureN _ _) (fun _ =>
    Cnt.bind (Cnt.pure _) (fun _ => Cnt.bind (Cnt.ask1 g _) (fun tk => Cnt.bind (Cnt.ask1 g _) (fun dg =>
    Cnt.bind (a_forsPkFromSig g _ tk _ _ _) (fun fpk => Cnt.bind (a_htRoot g _ tk _ _ _ _ hd)
      (fun ac => Cnt.pure _)))))))) (by omega)

end DSM.Rom
