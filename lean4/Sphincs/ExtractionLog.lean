-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.ExtractionRange

/- Exact request logs of the verifier. `Exact x v L`: run in the logging
   monad, `x` returns the `Id`-model value `v` and appends exactly `L`. The
   verifier's components get explicit log functions (`chainLog`,
   `authWalkLog`, …, `htRootLog`, `forsPkFromSigLog`), proved exact, and an
   accepting `verify` run logs both the FORS and the hypertree logs. These
   identify the inputs the verifier hashes for a forged signature. -/
namespace DSM.Sphincs

def Exact {α : Type} (x : LogM α) (v : α) (L : List Request) : Prop :=
  ∀ s, x.run s = (v, s ++ L)

namespace Exact

theorem pure' {α : Type} (a : α) : Exact (pure a : LogM α) a [] :=
  fun s => by rw [List.append_nil]; rfl

theorem bind_id {α β : Type} {x : LogM α} {f : α → LogM β} {v : Id α} {g : α → Id β}
    {L₁ L₂ : List Request} (hx : Exact x v L₁) (hf : Exact (f v) (g v) L₂) :
    Exact (x >>= f) (v >>= g) (L₁ ++ L₂) := by
  intro s
  rw [logM_run_bind, hx s, hf (s ++ L₁), List.append_assoc]
  rfl

theorem oracle (o : Oracle Id) (r : Request) : Exact (logOracle o r) (o r) [r] :=
  logOracle_run o r

theorem congr_log {α : Type} {x : LogM α} {v : α} {L L' : List Request} (h : Exact x v L)
    (e : L = L') : Exact x v L' := e ▸ h

theorem forIn' {α β : Type} (l : List α) (init : β) {f : α → β → LogM (ForInStep β)}
    {g : α → β → Id (ForInStep β)} (B : α → List Request)
    (hf : ∀ a ∈ l, ∀ b, Exact (f a b) (g a b) (B a))
    (hy : ∀ a ∈ l, ∀ b, ∃ b', g a b = .yield b') :
    Exact (forIn l init f) (forIn l init g) (l.flatMap B) := by
  induction l generalizing init with
  | nil => exact pure' init
  | cons a l ih =>
    rw [List.forIn_cons, List.forIn_cons, List.flatMap_cons]
    obtain ⟨b', hb⟩ := hy a (by simp) init
    have hfa := hf a (by simp) init
    rw [hb] at hfa ⊢
    exact bind_id hfa (ih b' (fun a' h b => hf a' (by simp [h]) b) (fun a' h b => hy a' (by simp [h]) b))

theorem run_empty {α : Type} {x : LogM α} {v : α} {L : List Request} (h : Exact x v L) :
    (x.run []).1 = v ∧ (x.run []).2 = L := by
  rw [h []]; exact ⟨rfl, rfl⟩
end Exact

def thashReq (p : Params) (tk : Bytes) (a : Adrs) (x : Bytes) : Request := ⟨1,"",tk,a.bytes ++ x,p.n⟩

section
variable (o : Oracle Id) (p : Params) (tk : Bytes)

def chainLog (a : Adrs) : Bytes → Nat → Nat → List Request
  | _, _, 0 => []
  | x, s, k+1 => thashReq p tk {a with hash := s} x ::
      chainLog a (thash o p tk {a with hash := s} x) (s+1) k

def authWalkLog (a : Adrs) (li gi : Nat) (node auth : Bytes) (level : Nat) : Nat → List Request
  | 0 => []
  | r+1 => thashReq p tk {a with chain := level+1, hash := gi/2}
        (if li%2 = 0 then node ++ slice auth (level*p.n) p.n else slice auth (level*p.n) p.n ++ node) ::
      authWalkLog a (li/2) (gi/2)
        (thash o p tk {a with chain := level+1, hash := gi/2}
          (if li%2 = 0 then node ++ slice auth (level*p.n) p.n else slice auth (level*p.n) p.n ++ node))
        auth (level+1) r
end

section
variable {o : Oracle Id} {p : Params} {tk : Bytes}

theorem chain_exact (a : Adrs) (x : Bytes) (s k : Nat) :
    Exact (chain (logOracle o) p tk a x s k) (chain o p tk a x s k) (chainLog o p tk a x s k) := by
  induction k generalizing x s with
  | zero => exact Exact.pure' x
  | succ k ih =>
    simp only [chain, chainLog]
    exact Exact.bind_id (Exact.oracle o _) (ih _ _)

theorem authWalk_exact (a : Adrs) (li gi : Nat) (node auth : Bytes) (level r : Nat) :
    Exact (authWalk (logOracle o) p tk a li gi node auth level r)
      (authWalk o p tk a li gi node auth level r) (authWalkLog o p tk a li gi node auth level r) := by
  induction r generalizing li gi node level with
  | zero => exact Exact.pure' _
  | succ r ih =>
    simp only [authWalk, authWalkLog]
    exact Exact.bind_id (Exact.oracle o _) (ih _ _ _ _)
end

section
variable (o : Oracle Id) (p : Params) (tk : Bytes)

def wotsPkFromSigLog (a : Adrs) (sig msg : Bytes) : List Request :=
  ((wotsDigits p msg).zipIdx.flatMap fun x =>
    chainLog o p tk {a with chain := x.2} (slice sig (x.2*p.n) p.n) x.1 (15-x.1)) ++
  [thashReq p tk {a.setType 1 with keypair := a.keypair}
    (((wotsDigits p msg).zipIdx.map fun x =>
      (chain o p tk {a with chain := x.2} (slice sig (x.2*p.n) p.n) x.1 (15-x.1) : Bytes)).flatten)]

def xmssPkFromSigLog (a : Adrs) (idx : Nat) (sig msg : Bytes) : List Request :=
  wotsPkFromSigLog o p tk {a.setType 0 with keypair := idx} (sig.take (p.len*p.n)) msg ++
  authWalkLog o p tk (a.setType 2) idx idx
    (wotsPkFromSig o p tk {a.setType 0 with keypair := idx} (sig.take (p.len*p.n)) msg)
    (sig.drop (p.len*p.n)) 0 p.hp

def htRootTailLog (layer tree : Nat) (node sig : Bytes) : Nat → List Request
  | 0 => []
  | r+1 => xmssPkFromSigLog o p tk {layer := layer, tree := (nextLayer p tree).2} (nextLayer p tree).1
        (sig.take p.layerBytes) node ++
      htRootTailLog (layer+1) (nextLayer p tree).2
        (xmssPkFromSig o p tk {layer := layer, tree := (nextLayer p tree).2} (nextLayer p tree).1
          (sig.take p.layerBytes) node) (sig.drop p.layerBytes) r

def htRootLog (sig msg : Bytes) (tree leaf : Nat) : List Request :=
  xmssPkFromSigLog o p tk {tree := tree} leaf (sig.take p.layerBytes) msg ++
  htRootTailLog o p tk 1 tree
    (xmssPkFromSig o p tk {tree := tree} leaf (sig.take p.layerBytes) msg)
    (sig.drop p.layerBytes) (p.d-1)

def forsPart' (sig : Bytes) (x : Nat × Nat) : Bytes :=
  slice sig (x.2*((p.a+1)*p.n)) ((p.a+1)*p.n)

def forsPkFromSigLog (a : Adrs) (sig md : Bytes) : List Request :=
  ((base2b md p.a p.k).zipIdx.flatMap fun x =>
    thashReq p tk {a with chain := 0, hash := x.2*2^p.a+x.1} ((forsPart' p sig x).take p.n) ::
    authWalkLog o p tk a x.1 (x.2*2^p.a+x.1)
      (thash o p tk {a with chain := 0, hash := x.2*2^p.a+x.1} ((forsPart' p sig x).take p.n))
      ((forsPart' p sig x).drop p.n) 0 p.a) ++
  [thashReq p tk {a.setType 4 with keypair := a.keypair}
    (((base2b md p.a p.k).zipIdx.map fun x =>
        (authRoot o p tk a x.1 (x.2*2^p.a+x.1)
          (thash o p tk {a with chain := 0, hash := x.2*2^p.a+x.1} ((forsPart' p sig x).take p.n))
          ((forsPart' p sig x).drop p.n) p.a : Bytes)).flatten)]
end

section
variable {o : Oracle Id} {p : Params} {tk : Bytes}

theorem wotsPkFromSig_exact (a : Adrs) (sig msg : Bytes) :
    Exact (wotsPkFromSig (logOracle o) p tk a sig msg) (wotsPkFromSig o p tk a sig msg)
      (wotsPkFromSigLog o p tk a sig msg) := by
  simp only [wotsPkFromSig]
  refine Exact.congr_log (Exact.bind_id (Exact.forIn' _ _
    (fun x => chainLog o p tk {a with chain := x.2} (slice sig (x.2*p.n) p.n) x.1 (15-x.1)) ?_ ?_)
    (Exact.oracle o _)) ?_
  · intro x _ b
    obtain ⟨d, i⟩ := x
    exact Exact.congr_log (Exact.bind_id (chain_exact _ _ _ _)
      (Exact.bind_id (Exact.pure' _) (Exact.pure' _))) (by simp)
  · intro x _ b
    obtain ⟨d, i⟩ := x
    exact ⟨_, rfl⟩
  · simp only [wotsPkFromSigLog, List.append_cancel_left_eq, List.cons.injEq, and_true]
    simp only [thashReq, Request.mk.injEq, true_and, Id.instMonad, bind, pure]
    rw [gather_raw]
    simp

theorem xmssPkFromSig_exact (a : Adrs) (idx : Nat) (sig msg : Bytes) :
    Exact (xmssPkFromSig (logOracle o) p tk a idx sig msg) (xmssPkFromSig o p tk a idx sig msg)
      (xmssPkFromSigLog o p tk a idx sig msg) := by
  simp only [xmssPkFromSig, authRoot]
  exact Exact.bind_id (wotsPkFromSig_exact _ _ _) (authWalk_exact _ _ _ _ _ _ _)

theorem htRootTail_exact (layer tree : Nat) (node sig : Bytes) (r : Nat) :
    Exact (htRootTail (logOracle o) p tk layer tree node sig r) (htRootTail o p tk layer tree node sig r)
      (htRootTailLog o p tk layer tree node sig r) := by
  induction r generalizing layer tree node sig with
  | zero => exact Exact.pure' _
  | succ r ih =>
    simp only [htRootTail, htRootTailLog]
    exact Exact.bind_id (xmssPkFromSig_exact _ _ _ _) (ih _ _ _ _)

theorem htRoot_exact (sig msg : Bytes) (tree leaf : Nat) :
    Exact (htRoot (logOracle o) p tk sig msg tree leaf) (htRoot o p tk sig msg tree leaf)
      (htRootLog o p tk sig msg tree leaf) := by
  simp only [htRoot]
  exact Exact.bind_id (xmssPkFromSig_exact _ _ _ _) (htRootTail_exact _ _ _ _ _)

theorem forsPkFromSig_exact (a : Adrs) (sig md : Bytes) :
    Exact (forsPkFromSig (logOracle o) p tk a sig md) (forsPkFromSig o p tk a sig md)
      (forsPkFromSigLog o p tk a sig md) := by
  simp only [forsPkFromSig]
  refine Exact.congr_log (Exact.bind_id (Exact.forIn' _ _
    (fun x => thashReq p tk {a with chain := 0, hash := x.2*2^p.a+x.1} ((forsPart' p sig x).take p.n) ::
      authWalkLog o p tk a x.1 (x.2*2^p.a+x.1)
        (thash o p tk {a with chain := 0, hash := x.2*2^p.a+x.1} ((forsPart' p sig x).take p.n))
        ((forsPart' p sig x).drop p.n) 0 p.a) ?_ ?_)
    (Exact.oracle o _)) ?_
  · intro x _ b
    obtain ⟨d, i⟩ := x
    exact Exact.congr_log (Exact.bind_id (Exact.oracle o _) (Exact.bind_id (authWalk_exact _ _ _ _ _ _ _)
      (Exact.bind_id (Exact.pure' _) (Exact.pure' _)))) (by simp [forsPart', thashReq])
  · intro x _ b
    obtain ⟨d, i⟩ := x
    exact ⟨_, rfl⟩
  · simp only [forsPkFromSigLog, List.append_cancel_left_eq, List.cons.injEq, and_true]
    simp only [thashReq, Request.mk.injEq, true_and, Id.instMonad, bind, pure]
    rw [gather_raw]
    simp [forsPart', authRoot]
end

theorem verify_exact (o : Oracle Id) (v : Variant) (pk msg sig : Bytes)
    (hne : msg.isEmpty = false) (hpk : pk.length = 2*(params v).n)
    (hsig : sig.length = (params v).sigBytes) :
    Exact (verify (logOracle o) v pk msg sig) (verify o v pk msg sig)
      ([⟨0,"DSM/sphincs/v2/thash",[],pk.take (params v).n,32⟩,
        ⟨2,"DSM/sphincs/v2/h-msg",[],sig.take (params v).n ++ pk.take (params v).n ++
          pk.drop (params v).n ++ msg,(params v).m⟩] ++
       forsPkFromSigLog o (params v) (deriveKey o "DSM/sphincs/v2/thash" (pk.take (params v).n))
         {tree := (splitDigest (params v) (hmsg o (params v) (sig.take (params v).n)
            (pk.take (params v).n) (pk.drop (params v).n) msg)).tree, kind := 3,
          keypair := (splitDigest (params v) (hmsg o (params v) (sig.take (params v).n)
            (pk.take (params v).n) (pk.drop (params v).n) msg)).leaf}
         (slice sig (params v).n (params v).forsBytes)
         (splitDigest (params v) (hmsg o (params v) (sig.take (params v).n)
            (pk.take (params v).n) (pk.drop (params v).n) msg)).md ++
       htRootLog o (params v) (deriveKey o "DSM/sphincs/v2/thash" (pk.take (params v).n))
         (sig.drop ((params v).n + (params v).forsBytes))
         (forsPkFromSig o (params v) (deriveKey o "DSM/sphincs/v2/thash" (pk.take (params v).n))
           {tree := (splitDigest (params v) (hmsg o (params v) (sig.take (params v).n)
              (pk.take (params v).n) (pk.drop (params v).n) msg)).tree, kind := 3,
            keypair := (splitDigest (params v) (hmsg o (params v) (sig.take (params v).n)
              (pk.take (params v).n) (pk.drop (params v).n) msg)).leaf}
           (slice sig (params v).n (params v).forsBytes)
           (splitDigest (params v) (hmsg o (params v) (sig.take (params v).n)
              (pk.take (params v).n) (pk.drop (params v).n) msg)).md)
         (splitDigest (params v) (hmsg o (params v) (sig.take (params v).n)
            (pk.take (params v).n) (pk.drop (params v).n) msg)).tree
         (splitDigest (params v) (hmsg o (params v) (sig.take (params v).n)
            (pk.take (params v).n) (pk.drop (params v).n) msg)).leaf) := by
  simp only [verify, hne, hpk, hsig, Bool.false_eq_true, if_false, bne_self_eq_false, Bool.or_self]
  refine Exact.congr_log (Exact.bind_id (Exact.pure' _) (Exact.bind_id (Exact.pure' _)
    (Exact.bind_id (Exact.oracle o _) (Exact.bind_id (Exact.oracle o _)
    (Exact.bind_id (forsPkFromSig_exact _ _ _) (Exact.bind_id (htRoot_exact _ _ _ _)
    (Exact.pure' _))))))) ?_
  simp [hmsg, deriveKey]
#print axioms chain_exact
#print axioms authWalk_exact
#print axioms wotsPkFromSig_exact
#print axioms xmssPkFromSig_exact
#print axioms htRoot_exact
#print axioms forsPkFromSig_exact
#print axioms verify_exact
end DSM.Sphincs
