/-
  LeanVM.Prover.Ring

  The executable ring switching makes the specification's moves and returns the data of its
  claim.
-/

module

public import Statement.Prover.Whir
public import LeanVM.Prover.Corr
public import LeanVM.Protocol.EndToEnd.Complete.Ring
public import LeanVM.Protocol.RingVerifier

/-!
# Ring switching

`corr_ringFast`: `ringFast claims` makes the moves of the specification's `hRing claims` (a
grind and sixteen challenges, nothing sent; research build: a list of claims, `q_keccak`'s and
`q_flock`'s), and each of the specification's results is the target with the weight
`ringWeight point · (ringCoefficients f g)` of the
executable's result.
-/

namespace LeanVM.Prover

open LeanVM.Parameters LeanVM.Protocol.Verifier LeanVM.Protocol.EndToEnd.Complete

@[expose] public section

/-- Receiving `n` challenges gives `n` challenges. -/
theorem corr_sampleN : ∀ n : ℕ,
    Corr (fun a b ↦ a = b ∧ a.length = n) (Script.sampleN n) (Script.sampleN n)
  | 0 => ⟨rfl, rfl⟩
  | n + 1 => by
    simp only [Script.sampleN, Script.sampleE, Script.bind_eq, Script.pure_eq]
    intro c
    simp only [Script.bind]
    refine Corr.bind (fun a b h ↦ ?_) _ _ (corr_sampleN n)
    obtain ⟨rfl, hl⟩ := h
    exact ⟨rfl, by simp [hl]⟩

/-- What the specification's ring switching returns for the executable's result. -/
def RingOut.spec (r : RingOut) : E × (List E → E) :=
  (r.target, fun rPrime ↦ ringWeight r.point rPrime (Protocol.Ring.ringCoefficients r.f r.g))

attribute [local irreducible] Corr in
/-- **The executable ring switching makes the specification's moves** on every claim list, and the
specification's results are the executable's targets with the weights of their points and the
challenges. -/
theorem corr_ringFast (claims : List (List E × List E)) :
    Corr (fun a b ↦ b = a.map RingOut.spec ∧ a.map RingOut.point = claims.map Prod.fst)
      (ringFast claims) (hRing claims) := by
  simp only [ringFast, hRing, Script.bind_eq, Script.pure_eq, show ringMapWidth = 8 from rfl]
  refine Corr.bind_same _ fun _ ↦ ?_
  refine Corr.bind (fun a b h ↦ ?_) _ _ (corr_sampleN _)
  obtain ⟨rfl, hl⟩ := h
  refine Corr.ret_ret ⟨?_, ?_⟩
  · rw [List.map_map]
    refine List.map_congr_left fun c _ ↦ ?_
    obtain ⟨p, sl⟩ := c
    simp only [Function.comp_apply, RingOut.spec, Prod.mk.injEq, and_true]
    rw [Protocol.Ring.verifier_ringTarget]
  · rw [List.map_map]
    refine List.map_congr_left fun c _ ↦ ?_
    obtain ⟨p, sl⟩ := c
    rfl

end
end LeanVM.Prover
