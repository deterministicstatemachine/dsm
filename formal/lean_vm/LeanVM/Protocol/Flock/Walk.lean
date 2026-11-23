/-
  LeanVM.Protocol.Flock.Walk

  What the honest prover's Flock instances are (research build): the forward walk of the BLAKE3
  circuit keeps its input words and computes the compression into its output words. Stated here as
  the propositions the completeness side of the protocol needs; their proofs are open.
-/

module

public import Statement.Prover.Flock
public import LeanVM.Protocol.Spine.Instance

/-!
# The Flock circuit's forward walk

The honest prover commits, per `BLAKE3` row, the instance `instanceOf` builds (`Prover/Flock.lean`,
`Statement`): the inputs placed as bits, then the circuit walked forward over bits (`bitWalk`), each
row's slot set to its product. `QFLOCK` holds its `256` words. The Flock predicate (`FlockRegion.Holds`)
reads the thirteen input cells and the two output cells of an instance off its words. Two facts
about the walk connect the two:

* `WalkComputes`: on every instance `instanceOf` builds, whatever its inputs, the output cells
  are the compression of the input cells (`Blake3CellsRelation`). This is the correctness of the
  circuit as an evaluator: its ripple-carry and majority adders against `UInt32` addition, its
  rotations and sums, round by round.
* `WalkKeepsInputs`: the input words an instance's word slots hold are the inputs it was built
  from: the walk sets an input bit only through its identity row, which keeps it.

`FlockWalk` is both. Neither is proved here yet: the completeness theorems that need them take
`FlockWalk` as a hypothesis, named, so that what is open is in their statements. Nothing here is
assumed by a soundness theorem.
-/

namespace LeanVM.Protocol.Flock

open LeanVM.Parameters LeanVM.Semantics LeanVM.Prover.Flock

@[expose] public section

/-- The cell an instance's words `lo, lo + 1` hold. -/
def instCell (I : Instance) (lo : ℕ) : E :=
  E.ofLimbs (K.ofLane (I.z.getD lo 0)) (K.ofLane (I.z.getD (lo + 1) 0))

/-- The thirteen cells an instance reads, as the Flock predicate reads them (`flockInSlots`). -/
def instInputs (I : Instance) : Fin 13 → E := fun k ↦ instCell I (flockInSlots k)

/-- The two cells an instance writes, zero past them. -/
def instOutputs (I : Instance) : Fin 13 → E :=
  fun k ↦ if k.val < 2 then instCell I (4 + 2 * k.val) else 0

/-- **The walk computes the compression**: every instance the honest prover builds has its output
cells the compression of its input cells. -/
def WalkComputes : Prop :=
  ∀ (cv msg : List ℕ) (counter blockLen flags : ℕ) (xyw : List ℕ),
    Blake3CellsRelation (instInputs (instanceOf cv msg counter blockLen flags xyw))
      (instOutputs (instanceOf cv msg counter blockLen flags xyw))

/-- The 64-bit word of two 32-bit words, the first low. -/
def pairWord (lo hi : ℕ) : UInt64 := UInt64.ofNat (lo % 2 ^ 32 + 2 ^ 32 * (hi % 2 ^ 32))

/-- **The walk keeps its inputs**: an instance's input word slots hold the words it was built from:
the chaining value at `0 … 4`, the message at `10 … 18`, the counter at `18`, the block length
and flags at `19`, `X ‖ Y ‖ W` at `181 … 193`, each two 32-bit words a 64-bit word. -/
def WalkKeepsInputs : Prop :=
  ∀ (cv msg : List ℕ) (counter blockLen flags : ℕ) (xyw : List ℕ),
    cv.length = 8 → msg.length = 16 → xyw.length = 24 →
      let I := instanceOf cv msg counter blockLen flags xyw
      (∀ k < 4, I.z.getD k 0 = pairWord (cv.getD (2 * k) 0) (cv.getD (2 * k + 1) 0)) ∧
      (∀ k < 8, I.z.getD (10 + k) 0 = pairWord (msg.getD (2 * k) 0) (msg.getD (2 * k + 1) 0)) ∧
      I.z.getD 18 0 = UInt64.ofNat counter ∧
      I.z.getD 19 0 = pairWord blockLen flags ∧
      (∀ k < 12, I.z.getD (181 + k) 0 = pairWord (xyw.getD (2 * k) 0) (xyw.getD (2 * k + 1) 0))

/-- **The honest Flock instances**: the walk computes the compression and keeps its inputs. Open:
a hypothesis of the completeness theorems that read the honest `QFLOCK`. -/
def FlockWalk : Prop := WalkComputes ∧ WalkKeepsInputs

/-! ## Rows as instances -/

/-- A limb's low 32-bit word. -/
def lo32 (a : K) : ℕ := LeanVM.Protocol.Verifier.kToNat a % 2 ^ 32

/-- A limb's high 32-bit word. -/
def hi32 (a : K) : ℕ := LeanVM.Protocol.Verifier.kToNat a / 2 ^ 32

/-- **A `BLAKE3` row's instance**, its arguments spelled out by column (`BLAKE3_COLUMNS`): the
chaining value from columns `24 … 27`, the message from `12 … 19`, the metadata from `28`, `29`,
`X ‖ Y ‖ W` from `30 … 41`, each limb two 32-bit words. -/
theorem instanceOfRow_eq (r : ℕ → K) :
    instanceOfRow r = instanceOf
      ([24, 25, 26, 27].flatMap fun c ↦ [lo32 (r c), hi32 (r c)])
      ([12, 13, 14, 15, 16, 17, 18, 19].flatMap fun c ↦ [lo32 (r c), hi32 (r c)])
      (LeanVM.Protocol.Verifier.kToNat (r 28)) (lo32 (r 29)) (hi32 (r 29))
      ([30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41].flatMap fun c ↦ [lo32 (r c), hi32 (r c)]) := rfl

/-- A limb's two 32-bit words make its 64-bit lane. -/
theorem pairWord_lo32_hi32 (a : K) : pairWord (lo32 a) (hi32 a) = K.lane a := by
  unfold pairWord lo32 hi32
  have h64 : LeanVM.Protocol.Verifier.kToNat a < 2 ^ 64 := a.toBitVec.isLt
  rw [Nat.mod_mod, Nat.mod_eq_of_lt (Nat.div_lt_of_lt_mul (by omega)), Nat.mod_add_div]
  apply UInt64.toBitVec_inj.mp
  simp [K.lane, LeanVM.Protocol.Verifier.kToNat]

/-- A limb's lane, as a natural number, is the limb. -/
theorem ofNat_kToNat (a : K) : UInt64.ofNat (LeanVM.Protocol.Verifier.kToNat a) = K.lane a := by
  apply UInt64.toBitVec_inj.mp
  simp [K.lane, LeanVM.Protocol.Verifier.kToNat]

/-- The low limb column of each cell a `BLAKE3` row reads, in the predicate's order
(`BLAKE3_COLUMNS`). -/
def rowInLo : Fin 13 → ℕ := ![12, 14, 16, 18, 24, 26, 28, 30, 32, 34, 36, 38, 40]

/-- The thirteen cells a row's limbs make, in the predicate's order. -/
def rowInputs (r : ℕ → K) : Fin 13 → E := fun k ↦ E.ofLimbs (r (rowInLo k)) (r (rowInLo k + 1))

/-- The two output cells a row's limbs make (columns `20 … 23`), zero past them. -/
def rowOutputs (r : ℕ → K) : Fin 13 → E :=
  fun k ↦ if k.val < 2 then E.ofLimbs (r (20 + 2 * k.val)) (r (20 + 2 * k.val + 1)) else 0

/-- Two cells of lanes. -/
private theorem ofLimbs_lanes {w₀ w₁ : UInt64} {a b : K} (h₀ : w₀ = K.lane a) (h₁ : w₁ = K.lane b) :
    E.ofLimbs (K.ofLane w₀) (K.ofLane w₁) = E.ofLimbs a b := by
  rw [h₀, h₁]
  rfl

/-- **A row's instance reads the row's input cells**, when the walk keeps its inputs. -/
theorem instInputs_instanceOfRow (hK : WalkKeepsInputs) (r : ℕ → K) :
    instInputs (instanceOfRow r) = rowInputs r := by
  obtain ⟨hc, hm, h18, h19, hx⟩ := hK
      ([24, 25, 26, 27].flatMap fun c ↦ [lo32 (r c), hi32 (r c)])
      ([12, 13, 14, 15, 16, 17, 18, 19].flatMap fun c ↦ [lo32 (r c), hi32 (r c)])
      (LeanVM.Protocol.Verifier.kToNat (r 28)) (lo32 (r 29)) (hi32 (r 29))
      ([30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41].flatMap fun c ↦ [lo32 (r c), hi32 (r c)])
      (by simp) (by simp) (by simp)
  rw [instanceOfRow_eq]
  funext k
  unfold instInputs instCell rowInputs
  fin_cases k <;> simp only [flockInSlots, rowInLo] <;>
    simp only [Fin.reduceFinMk, Matrix.cons_val_zero, Matrix.cons_val_one, Matrix.cons_val_two,
      Nat.reduceAdd]
  · exact ofLimbs_lanes (by simpa [pairWord_lo32_hi32] using hm 0 (by norm_num))
      (by simpa [pairWord_lo32_hi32] using hm 1 (by norm_num))
  · exact ofLimbs_lanes (by simpa [pairWord_lo32_hi32] using hm 2 (by norm_num))
      (by simpa [pairWord_lo32_hi32] using hm 3 (by norm_num))
  · exact ofLimbs_lanes (by simpa [pairWord_lo32_hi32] using hm 4 (by norm_num))
      (by simpa [pairWord_lo32_hi32] using hm 5 (by norm_num))
  · exact ofLimbs_lanes (by simpa [pairWord_lo32_hi32] using hm 6 (by norm_num))
      (by simpa [pairWord_lo32_hi32] using hm 7 (by norm_num))
  · exact ofLimbs_lanes (by simpa [pairWord_lo32_hi32] using hc 0 (by norm_num))
      (by simpa [pairWord_lo32_hi32] using hc 1 (by norm_num))
  · exact ofLimbs_lanes (by simpa [pairWord_lo32_hi32] using hc 2 (by norm_num))
      (by simpa [pairWord_lo32_hi32] using hc 3 (by norm_num))
  · exact ofLimbs_lanes (by simpa [ofNat_kToNat] using h18)
      (by simpa [pairWord_lo32_hi32] using h19)
  · exact ofLimbs_lanes (by simpa [pairWord_lo32_hi32] using hx 0 (by norm_num))
      (by simpa [pairWord_lo32_hi32] using hx 1 (by norm_num))
  · exact ofLimbs_lanes (by simpa [pairWord_lo32_hi32] using hx 2 (by norm_num))
      (by simpa [pairWord_lo32_hi32] using hx 3 (by norm_num))
  · exact ofLimbs_lanes (by simpa [pairWord_lo32_hi32] using hx 4 (by norm_num))
      (by simpa [pairWord_lo32_hi32] using hx 5 (by norm_num))
  · exact ofLimbs_lanes (by simpa [pairWord_lo32_hi32] using hx 6 (by norm_num))
      (by simpa [pairWord_lo32_hi32] using hx 7 (by norm_num))
  · exact ofLimbs_lanes (by simpa [pairWord_lo32_hi32] using hx 8 (by norm_num))
      (by simpa [pairWord_lo32_hi32] using hx 9 (by norm_num))
  · exact ofLimbs_lanes (by simpa [pairWord_lo32_hi32] using hx 10 (by norm_num))
      (by simpa [pairWord_lo32_hi32] using hx 11 (by norm_num))

/-- Two cells are equal limb by limb. -/
theorem ofLimbs_inj {a b c d : K} (h : E.ofLimbs a b = E.ofLimbs c d) : a = c ∧ b = d :=
  ⟨by simpa using congrArg (·.limb 0) h, by simpa using congrArg (·.limb 1) h⟩

/-- **A valid row's instance writes the row's output cells**, when the walk computes the
compression and keeps its inputs: both are the compression of the row's input cells. -/
theorem instOutputs_instanceOfRow (hF : FlockWalk) (r : ℕ → K)
    (hv : Blake3CellsRelation (rowInputs r) (rowOutputs r)) :
    instOutputs (instanceOfRow r) = rowOutputs r := by
  have hc := hF.1
  have h := hc ([24, 25, 26, 27].flatMap fun c ↦ [lo32 (r c), hi32 (r c)])
    ([12, 13, 14, 15, 16, 17, 18, 19].flatMap fun c ↦ [lo32 (r c), hi32 (r c)])
    (LeanVM.Protocol.Verifier.kToNat (r 28)) (lo32 (r 29)) (hi32 (r 29))
    ([30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41].flatMap fun c ↦ [lo32 (r c), hi32 (r c)])
  rw [← instanceOfRow_eq, instInputs_instanceOfRow hF.2] at h
  funext k
  by_cases hk : k.val < 2
  · obtain ⟨k, hk'⟩ := k
    interval_cases k
    · exact h.1.trans hv.1.symm
    · exact h.2.trans hv.2.symm
  · simp only [instOutputs, rowOutputs, hk, ↓reduceIte]

end

end LeanVM.Protocol.Flock
