/-
  LeanVM.Protocol.EndToEnd.Complete.Flock

  Flock's phase in the honest run (research build): the honest script, the Statement's Flock
  prover beside the verifier's phase, and its acceptance, `FlockComplete`, a named hypothesis that
  is NOT proved.
-/

module

public import LeanVM.Protocol.EndToEnd.Front.FlockPhase
public import LeanVM.Protocol.EndToEnd.Complete.Claims
public import LeanVM.Protocol.Whir.Complete.Script
public import Statement.Prover.Flock
public import LeanVM.Protocol.LeanIsa.Complete

/-!
# Flock's phase in the honest run

The honest script of Flock's phase is the Statement's Flock prover (`LeanVM.Prover.Flock.prove`,
`Statement/Prover/Flock.lean`) beside the verifier's phase (`Script.alongside`), as the Statement's
honest script runs it (`LeanVM.Prover.honestScript`), on the instances of the `BLAKE3` rows the
stack carries (`blake3RowsOf`, the rows `flockWitness` reads off a witness).

**Not proved: `FlockComplete`.** It states that, at admissible sizes, on a stack whose `q_flock`
region is the honest Flock prover's column of its own `BLAKE3` rows (`FlockColumnHonest`; the
stack of a witness has it), the honest script follows `flockPhase` at the verifier's layout from
any commitments, every `require` passing whatever the challenges, and returns `q_flock`'s true
point and slices (`KeccakGkr.slicesTrue` on region `QFLOCK`, `τ_BLAKE3 + 2` rows of sixty-four
bits at the region's offset), which ring switching takes. This is the honest Flock prover's
acceptance. The completeness theorems take it as a hypothesis in their statements.

`FlockColumnHonest` is needed because Flock's predicate on the stack (`flockAux`) fixes only an
instance's input and output cells: the walk's other words of a stack satisfying the relation are
free, and the honest prover commits the walk it computes.
-/

namespace LeanVM.Protocol.EndToEnd.Complete

open LeanVM.Prover (Script)

open LeanVM.Parameters LeanVM.Semantics LeanVM.Protocol.Compile LeanVM.Protocol.Verifier
open LeanVM.Protocol.LeanIsa LeanVM.Protocol.Whir.Complete LeanVM.Arithmetization

@[expose] public section

section Script

variable (prog : LeanIsaProgram) (s : Sizes) (q : Column (leanIsaμ prog s))

/-- The `BLAKE3` rows a stack carries, as `flockWitness` reads them off a witness. -/
def blake3RowsOf : Array (Array K) :=
  ((tableAt (witnessOf prog s q) 6).table.take (s.rows 6)).toArray

/-- Flock's instances of the stack's `BLAKE3` rows at the height `2^τ_BLAKE3`. -/
def flockInstancesOf : Array LeanVM.Prover.Flock.Instance :=
  LeanVM.Prover.Flock.instancesOf (blake3RowsOf prog s q) (s.τ 6)

/-- **The honest script of Flock's phase**: the Statement's Flock prover on the stack's instances,
beside the verifier's phase. -/
def hFlock : Script (List E × List E) :=
  Script.alongside (flockPhase (Front.verifierLayout prog s))
    (LeanVM.Prover.Flock.prove (flockInstancesOf prog s q) (s.τ 6))

/-- **The stack's `q_flock` region is the honest Flock prover's column** of its own instances. -/
def FlockColumnHonest : Prop :=
  ∀ i < 2 ^ (s.τ 6 + 8), Front.qkAt (Front.qfOff prog s) q i =
    (LeanVM.Prover.Flock.qflockColumn (flockInstancesOf prog s q) (s.τ 6)).getD i 0

end Script

/-- **Flock's completeness, a named hypothesis (NOT proved).** At admissible sizes, on a stack
whose `q_flock` region is the honest Flock prover's column, the honest script `hFlock` follows
`flockPhase` from any commitments and returns `q_flock`'s true point and slices. -/
def FlockComplete : Prop :=
  ∀ (prog : LeanIsaProgram) (s : Sizes), s.Admissible prog →
    ∀ q : Column (leanIsaμ prog s), FlockColumnHonest prog s q → ∀ cs : Commits,
      Follows (fun cs' a b ↦ cs' = cs ∧ a = b ∧
          KeccakGkr.slicesTrue (s.τ 6 + 2) (Front.qkAt (Front.qfOff prog s) q) b.1 b.2)
        (hFlock prog s q) (flockPhase (Front.verifierLayout prog s)) cs

/-! ## The stack of a witness -/

section Stack

variable {prog : LeanIsaProgram} {s : Sizes} {κ : ℕ}
  {w : Air.Flat.EnsembleWitness (leanIsaEnsemble prog κ)}

/-- The `BLAKE3` table read off the stack of a witness holds the witness's rows. -/
theorem blake3Table_stackOf (hF : Flock.FlockWalk) {input : PublicInput}
    (h : SatisfiedBy prog input w) (hsz : Sizes.ofWitness w = some s) :
    (tableAt (witnessOf prog s (stackOf prog s w)) 6).table.take (s.rows 6) =
      (tableAt w 6).table.take (s.rows 6) := by
  obtain ⟨hcells, -⟩ := witnessOf_stackOf hF h hsz
  obtain ⟨hp, rfl⟩ := eq_of_ofWitness hsz
  have hr : ∀ j, (witnessSizes w hp).rows j ≤ UInt64.size := fun j ↦ (opTable w j).length_le
  have hlen : (tableAt (witnessOf prog (witnessSizes w hp) (stackOf prog (witnessSizes w hp) w))
      6).table.length = (witnessSizes w hp).rows 6 := by
    rw [witnessOf_table]
    show (opTableOf prog (witnessSizes w hp) (stackOf prog (witnessSizes w hp) w) 6).table.length = _
    rw [opTableOf_table prog _ _ (hr 6), opcodeRows, List.length_ofFn]
  have hlen₂ : (tableAt w 6).table.length = (witnessSizes w hp).rows 6 := rfl
  have hw₁ := (tableAt (witnessOf prog (witnessSizes w hp) (stackOf prog (witnessSizes w hp) w))
    6).uniform_width
  have hw₂ := (tableAt w 6).uniform_width
  have hc₁ := opTable_component (witnessOf prog (witnessSizes w hp)
    (stackOf prog (witnessSizes w hp) w)) 6
  have hc₂ := opTable_component w 6
  apply List.ext_getElem (by simp [hlen, hlen₂])
  intro j h1 h2
  simp only [List.length_take, hlen, min_self] at h1
  rw [List.getElem_take, List.getElem_take]
  have hs₁ := hw₁ _ (List.getElem_mem (Nat.lt_of_lt_of_le h1 hlen.ge))
  have hs₂ := hw₂ _ (List.getElem_mem (Nat.lt_of_lt_of_le h1 hlen₂.ge))
  refine Array.ext (by rw [hs₁, hs₂]; exact congrArg Air.Flat.Component.width (hc₁.trans hc₂.symm))
    fun i hi₁ hi₂ ↦ ?_
  have hc₁' : (tableAt (witnessOf prog (witnessSizes w hp) (stackOf prog (witnessSizes w hp) w))
      6).component = opcodeComponent 6 := hc₁
  have hi : i < (opcodeComponent 6).width := by
    have := hi₁
    rw [hs₁, hc₁'] at this
    exact this
  have := hcells 6 ⟨j, h1⟩ ⟨i, hi⟩
  simp only [cellOf, LeanIsa.opTable] at this
  change ((((tableAt (witnessOf prog (witnessSizes w hp) (stackOf prog (witnessSizes w hp) w))
    6).table[j]?).bind (·[i]?)).getD 0 = (((tableAt w 6).table[j]?).bind (·[i]?)).getD 0) at this
  rw [List.getElem?_eq_getElem (Nat.lt_of_lt_of_le h1 hlen.ge),
    List.getElem?_eq_getElem (Nat.lt_of_lt_of_le h1 hlen₂.ge), Option.bind_some,
    Option.bind_some, Array.getElem?_eq_getElem hi₁, Array.getElem?_eq_getElem hi₂,
    Option.getD_some, Option.getD_some] at this
  exact this

/-- Flock's instances of the stack of a witness are the witness's. -/
theorem flockInstancesOf_stackOf (hF : Flock.FlockWalk) {input : PublicInput}
    (h : SatisfiedBy prog input w) (hsz : Sizes.ofWitness w = some s) :
    flockInstancesOf prog s (stackOf prog s w) = flockInsts prog s w := by
  unfold flockInstancesOf blake3RowsOf
  rw [blake3Table_stackOf hF h hsz]

/-- **The stack of a witness has the honest `q_flock`**: its region is the honest Flock prover's
column of its instances (`flockWitness`). -/
theorem flockColumnHonest_stackOf (hF : Flock.FlockWalk) {input : PublicInput}
    (h : SatisfiedBy prog input w) (hsz : Sizes.ofWitness w = some s) :
    FlockColumnHonest prog s (stackOf prog s w) := by
  intro i hi
  rw [flockInstancesOf_stackOf hF h hsz]
  have hp : 0 < 2 ^ s.τ 6 := Nat.two_pow_pos _
  have hx : i % 2 ^ s.τ 6 < 2 ^ s.τ 6 := Nat.mod_lt _ hp
  have hslot : i / 2 ^ s.τ 6 < 256 := by
    rw [Nat.div_lt_iff_lt_mul hp]
    rw [pow_add] at hi
    simpa [mul_comm] using hi
  have hi' : i = i % 2 ^ s.τ 6 + 2 ^ s.τ 6 * (i / 2 ^ s.τ 6) := (Nat.mod_add_div i _).symm
  have hR : (LeanVM.Prover.Flock.qflockColumn (flockInsts prog s w) (s.τ 6)).getD i 0 =
      K.ofLane (((flockInsts prog s w).getD (i % 2 ^ s.τ 6) default).z.getD
        (i / 2 ^ s.τ 6) 0) := by
    unfold LeanVM.Prover.Flock.qflockColumn
    rw [Array.getD_eq_getD_getElem?, Array.getElem?_ofFn]
    simp only [show i < 2 ^ (s.τ 6 + qflockSlotBits) from hi, ↓reduceDIte, Option.getD_some]
  rw [hR, ← flockWord_stackOf prog s w (i / 2 ^ s.τ 6) hslot ⟨_, hx⟩,
    word_flockColumn prog s _ _ hslot ⟨_, hx⟩]
  unfold Front.qkAt Front.qfOff
  rw [Array.getD_eq_getD_getElem?, Array.getElem?_eq_getElem, Option.getD_some,
    Vector.getElem_toArray]
  · congr 1
    dsimp only
    omega
  · rw [Vector.size_toArray]
    have h1 := (blocks prog s).offset_add_pow_le_total (flockBlock prog s)
    have h2 := blocks_fits prog s
    rw [size_flockBlock] at h1
    have : 2 ^ (s.τ 6 + 8) ≤ 2 ^ leanIsaμ prog s := by omega
    omega

end Stack

end
end LeanVM.Protocol.EndToEnd.Complete
