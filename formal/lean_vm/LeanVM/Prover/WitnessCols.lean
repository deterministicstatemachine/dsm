/-
  LeanVM.Prover.WitnessCols

  Every executable column of a valid execution is the instance's column of the stack of its
  specification witness, at the verifier's global column number.
-/

module

public import LeanVM.Prover.WitnessColumns

/-!
# Every column

`cols_trace`: on a valid execution, `colsOf` at `refCol c` is the instance's column `c` read off
`stackOf` of the specification witness, for every column `c`: the memory's (its limbs and its
finalize counts), `BYTECODE_FINAL_COUNTERS`, `QKECCAK` (`qkeccak_trace`), `QFLOCK`
(`qflock_trace`), the opcode tables' columns, the `KECCAK` input lanes and spare columns among
them, the `KECCAK` output lanes, which the instance derives (`column_toArray_out`), and the
`BLAKE3` value limbs, which it reads off `QFLOCK` (`column_toArray_limb`; research build: under
`hF : Flock.FlockWalk`, a named hypothesis).
-/

namespace LeanVM.Prover

open LeanVM.Parameters LeanVM.Semantics LeanVM.Arithmetization LeanVM.Extraction
open LeanVM.Protocol LeanVM.Protocol.LeanIsa LeanVM.Protocol.EndToEnd.Front
open LeanVM.Protocol.EndToEnd.Complete LeanVM.Protocol.Verifier
open Air.Flat (EnsembleWitness)

@[expose] public section

/-! ## The executable dispatch -/

/-- Each opcode table's width. -/
def tableWidth : ℕ → ℕ
  | 0 => 13
  | 1 => 13
  | 2 => 7
  | 3 => 14
  | 4 => 14
  | 5 => 92
  | 6 => 58
  | _ => 58

/-- The instance's opcode tables have these widths. -/
theorem width_opIdx_eq : ∀ j : Fin 7, width (opIdx j) = tableWidth j := by decide +kernel

/-- Each opcode table's first global column (`GLOBAL_COLUMN_BASES`), as numbers. -/
def tableBase : ℕ → ℕ
  | 0 => 6
  | 1 => 19
  | 2 => 32
  | 3 => 39
  | 4 => 53
  | 5 => 67
  | 6 => 159
  | _ => 159

/-- The verifier's table bases are `tableBase`. -/
theorem globalColumnBases_getD : ∀ j : Fin 7, globalColumnBases.getD j 0 = tableBase j := by
  decide +kernel

/-- The columns, by number. -/
theorem colsOf_getD {κ : ℕ} (img : MemoryImage κ) (acc : Rows) (logs : List ℕ)
    (instances : Array Flock.Instance) (n : ℕ) (hn : n < 217) :
    (colsOf img acc logs instances).getD n #[] =
      columnAt img acc logs (midStates (acc.tabs.getD 5 #[]) (logs.getD 5 0))
        (outStates (acc.tabs.getD 5 #[]) (midStates (acc.tabs.getD 5 #[]) (logs.getD 5 0)))
        instances n := by
  have hc : n < columnCount := lt_of_lt_of_eq hn (by decide)
  simp only [colsOf, Array.getD_eq_getD_getElem?, Array.getElem?_ofFn, hc, dite_true,
    Option.getD_some]

/-- Each opcode table's columns fall in it. -/
theorem tableIndexOf_base : ∀ (j : Fin 7) (i : Fin (tableWidth j)), tableIndexOf (tableBase j + i) = j := by
  decide +kernel

/-- The column of an opcode table's column number: an output lane derived, a `BLAKE3` value limb
padded with the padding instance's word, the table's column otherwise. -/
theorem columnAt_base {κ : ℕ} (img : MemoryImage κ) (acc : Rows) (logs : List ℕ)
    (mids outs : Array KeccakState) (instances : Array Flock.Instance) (j : ℕ) (hj : j < 7) (i : ℕ)
    (hi : i < tableWidth j) :
    columnAt img acc logs mids outs instances (tableBase j + i) =
      if j = 5 ∧ 40 ≤ i ∧ i < 65 then
        Array.ofFn (n := 2 ^ logs.getD 5 0) fun x ↦ laneK (outs.getD x.val zeroState) (i - 40)
      else if j = 6 then
        match blake3Slot (blake3Columns.getD i "") with
        | some slot => blake3ValueColumn (acc.tabs.getD 6 #[]) (logs.getD 6 0) i slot
        | none => tableColumn (acc.tabs.getD j #[]) (logs.getD j 0) i
      else tableColumn (acc.tabs.getD j #[]) (logs.getD j 0) i := by
  have hb : 6 ≤ tableBase j := by interval_cases j <;> decide
  have hidx : tableIndexOf (tableBase j + i) = j := tableIndexOf_base ⟨j, hj⟩ ⟨i, hi⟩
  have hg : globalColumnBases.getD j 0 = tableBase j := globalColumnBases_getD ⟨j, hj⟩
  unfold columnAt
  rw [ite_eq_right (by omega), ite_eq_right (by omega), ite_eq_right (by omega),
    ite_eq_right (by omega), ite_eq_right (by omega), ite_eq_right (by omega)]
  simp only [hidx, hg, Nat.add_sub_cancel_left]
  rfl

/-- The memory's columns are committed. -/
theorem not_isVirtual_memCol' (i : Fin 3) : ¬ IsVirtual (memCol i) := by revert i; decide

/-- The memory's limb columns, by number. -/
theorem columnAt_limb {κ : ℕ} (img : MemoryImage κ) (acc : Rows) (logs : List ℕ)
    (mids outs : Array KeccakState) (instances : Array Flock.Instance) (k : ℕ) (hk : k < 2) :
    columnAt img acc logs mids outs instances k = Array.ofFn (n := 2 ^ κ) fun x ↦ (img x).limb ⟨k, hk⟩ := by
  interval_cases k <;> rfl

theorem columnAt_two {κ : ℕ} (img : MemoryImage κ) (acc : Rows) (logs : List ℕ)
    (mids outs : Array KeccakState) (instances : Array Flock.Instance) :
    columnAt img acc logs mids outs instances 2 = acc.mem := rfl

theorem columnAt_three {κ : ℕ} (img : MemoryImage κ) (acc : Rows) (logs : List ℕ)
    (mids outs : Array KeccakState) (instances : Array Flock.Instance) :
    columnAt img acc logs mids outs instances 3 = acc.bc := rfl

theorem columnAt_four {κ : ℕ} (img : MemoryImage κ) (acc : Rows) (logs : List ℕ)
    (mids outs : Array KeccakState) (instances : Array Flock.Instance) :
    columnAt img acc logs mids outs instances 4 =
      qkeccakColumn (acc.tabs.getD 5 #[]) (logs.getD 5 0) mids :=
  rfl

theorem columnAt_five {κ : ℕ} (img : MemoryImage κ) (acc : Rows) (logs : List ℕ)
    (mids outs : Array KeccakState) (instances : Array Flock.Instance) :
    columnAt img acc logs mids outs instances 5 = Flock.qflockColumn instances (logs.getD 6 0) :=
  rfl

/-- **The `BLAKE3` value limbs**: exactly the columns `12 … 41` have a `q_flock` slot. -/
theorem blake3Slot_isSome : ∀ i : Fin 58,
    (blake3Slot (blake3Columns.getD i "")).isSome = decide (12 ≤ i.val ∧ i.val < 42) := by
  decide +kernel

/-- The padding instance's word at a value limb's slot is the verifier's padding row's cell. -/
theorem blake3Slot_pad : ∀ i : Fin 58,
    (blake3Slot (blake3Columns.getD i "")).all
      (fun slot ↦ decide (K.ofBits (blake3PaddingWord slot) = padR i)) = true := by
  decide +kernel

/-! ## The output lanes -/

section Out

variable {prog : LeanIsaProgram} {κ : ℕ} (w : EnsembleWitness (leanIsaEnsemble prog κ))
  (hp : 0 < (imageOf w.data).1)

/-- **An output lane of the stack**, as an array: the last twelve rounds of the first twelve of
each row's input lanes. -/
theorem column_toArray_out (c : Col) (h : IsOut c) :
    ((leanIsaInstance prog (witnessSizes w hp)).column (stackOf prog (witnessSizes w hp) w)
        c).values.toArray =
      Array.ofFn (n := 2 ^ (witnessSizes w hp).τ 5) fun x ↦
        stateLanes (keccakSegment 1 (keccakSegment 0
          (laneState fun l : Fin 25 ↦ cellOf (tableAt w 5) x (15 + l.val))))
          ⟨c.2.val - 40, by have := h.2.2; omega⟩ := by
  obtain ⟨j, i⟩ := c
  obtain ⟨hj, h38, h63⟩ := h
  change j = opIdx 5 at hj
  subst hj
  refine (congrArg (fun c : Col ↦ ((leanIsaInstance prog (witnessSizes w hp)).column
    (stackOf prog (witnessSizes w hp) w) c).values.toArray) (eq_outCol (i := i) h38 h63)).trans ?_
  refine Array.ext (by simp only [Vector.size_toArray, Array.size_ofFn]; rfl) fun x h1 h2 ↦ ?_
  have hx : x < 2 ^ (witnessSizes w hp).τ 5 := by simpa using h2
  rw [Vector.getElem_toArray, Array.getElem_ofFn]
  exact column_getElem_out w hp _ x hx

end Out

/-! ## Every column of an execution -/

variable {prog : LeanIsaProgram} {input : PublicInput} {t : Execution prog}

/-- The pass's tables, by number. -/
theorem tabs_trace' (hv : ValidExecution prog input t) (hb : TraceBounds t) (j : ℕ) (hj : j < 7) :
    ((traceRows t).tabs.getD j #[]).toList =
      (tableAt (traceWitness prog input t) ⟨j, by omega⟩).table :=
  tabs_trace hv hb ⟨j, hj⟩

/-- **The memory columns**, computed: the image's limbs and the finalize counts. -/
theorem memColumn_trace (hv : ValidExecution prog input t) (hb : TraceBounds t) (logs : List ℕ)
    (mids outs : Array KeccakState) (instances : Array Flock.Instance) (k : Fin 3) :
    columnAt t.memory (traceRows t) logs mids outs instances k =
      (witnessColumn prog (witnessSizes (traceWitness prog input t) (traceWitness_pos hv hb))
        (traceWitness prog input t) (memCol k)).toArray := by
  have hlog := traceWitness_logSize (input := input) hb
  have hI := rowsInv_trace (input := input) hv
  apply Array.ext_getElem?
  intro x
  have hR : (witnessColumn prog (witnessSizes (traceWitness prog input t) (traceWitness_pos hv hb))
      (traceWitness prog input t) (memCol k)).toArray[x]? =
      if x < 2 ^ t.logMemorySize then some (cellOf (tableAt (traceWitness prog input t) 7) x (memRowCell k))
      else none := by
    rw [Vector.getElem?_toArray]
    show (Vector.ofFn fun y : Fin (2 ^ (imageOf (traceWitness prog input t).data).1) ↦
      cellOf (tableAt (traceWitness prog input t) 7) y (memRowCell k))[x]? = _
    rw [Vector.getElem?_ofFn]
    by_cases hx : x < 2 ^ t.logMemorySize
    · rw [dite_eq_left_of_eq_true (eq_true (by rw [hlog]; exact hx)), ite_eq_left hx]
    · rw [dite_eq_right_of_eq_false (eq_false (by rw [hlog]; exact hx)), ite_eq_right hx]
  rw [hR]
  obtain ⟨k, hk⟩ := k
  by_cases hx : x < 2 ^ t.logMemorySize
  · rw [ite_eq_left hx, memCell_trace hb x hx]
    by_cases hk2 : k < 2
    · rw [columnAt_limb _ _ _ _ _ _ k hk2, Array.getElem?_ofFn, dite_eq_left_of_eq_true (eq_true hx)]
      interval_cases k <;> simp [memRowCell]
    · obtain rfl : k = 2 := by omega
      rw [columnAt_two, Array.getElem?_eq_getElem (by rw [hI.mem.1]; exact hx), hI.mem.2]
      simp [memRowCell, skelMemFin]
  · rw [ite_eq_right hx]
    by_cases hk2 : k < 2
    · rw [columnAt_limb _ _ _ _ _ _ k hk2, Array.getElem?_ofFn, dite_eq_right_of_eq_false (eq_false hx)]
    · obtain rfl : k = 2 := by omega
      rw [columnAt_two, Array.getElem?_eq_none (by rw [hI.mem.1]; omega)]

/-- **The bytecode's finalize counts**, computed. -/
theorem bfcntColumn_trace (hv : ValidExecution prog input t) (hb : TraceBounds t) (logs : List ℕ)
    (mids outs : Array KeccakState) (instances : Array Flock.Instance) :
    columnAt t.memory (traceRows t) logs mids outs instances 3 =
      (witnessColumn prog (witnessSizes (traceWitness prog input t) (traceWitness_pos hv hb))
        (traceWitness prog input t) bfcntCol).toArray := by
  have hI := rowsInv_trace (input := input) hv
  rw [columnAt_three]
  apply Array.ext_getElem?
  intro x
  rw [Vector.getElem?_toArray]
  show _ = (Vector.ofFn fun y : Fin (2 ^ prog.logSize) ↦
    cellOf (tableAt (traceWitness prog input t) 8) y 1)[x]?
  rw [Vector.getElem?_ofFn]
  by_cases hx : x < 2 ^ prog.logSize
  · rw [dite_eq_left_of_eq_true (eq_true hx), bcCell_trace (input := input) hb x hx,
      Array.getElem?_eq_getElem (by rw [hI.bc.1]; exact hx), hI.bc.2]
    rfl
  · rw [dite_eq_right_of_eq_false (eq_false hx), Array.getElem?_eq_none (by rw [hI.bc.1]; omega)]

/-- **`QKECCAK`**, computed once per step: the witness's. -/
theorem qkeccak_trace (hv : ValidExecution prog input t) (hb : TraceBounds t) {logs : List ℕ}
    (hl : logs.getD 5 0 =
      (witnessSizes (traceWitness prog input t) (traceWitness_pos hv hb)).τ 5) :
    qkeccakColumn ((traceRows t).tabs.getD 5 #[]) (logs.getD 5 0)
        (midStates ((traceRows t).tabs.getD 5 #[]) (logs.getD 5 0)) =
      (keccakWitness prog (witnessSizes (traceWitness prog input t) (traceWitness_pos hv hb))
        (traceWitness prog input t)).toArray := by
  have hR : ((traceRows t).tabs.getD 5 #[]).toList =
      (tableAt (traceWitness prog input t) 5).table := tabs_trace' hv hb 5 (by omega)
  rw [hl]
  unfold qkeccakColumn keccakWitness
  rw [Vector.toArray_ofFn]
  dsimp only
  refine congrArg Array.ofFn (funext fun i ↦ ?_)
  have hx : i.val % 2 ^ (witnessSizes (traceWitness prog input t) (traceWitness_pos hv hb)).τ 5 <
      2 ^ (witnessSizes (traceWitness prog input t) (traceWitness_pos hv hb)).τ 5 :=
    Nat.mod_lt _ (Nat.two_pow_pos _)
  split_ifs with h1 h2
  · rw [inLaneOf_eq _ (traceWitness_pos hv hb)]
    exact cellAt_eq hR _ _
  · rw [midStates_getD _ _ _ hx]
    have hin : (fun l : Fin 25 ↦ cellAt ((traceRows t).tabs.getD 5 #[])
        (i.val % 2 ^ (witnessSizes (traceWitness prog input t) (traceWitness_pos hv hb)).τ 5)
        (15 + l.val)) = inLaneOf prog (witnessSizes (traceWitness prog input t) (traceWitness_pos hv hb))
          (traceWitness prog input t)
          (i.val % 2 ^ (witnessSizes (traceWitness prog input t) (traceWitness_pos hv hb)).τ 5) :=
      funext fun l ↦ by rw [inLaneOf_eq _ (traceWitness_pos hv hb)]; exact cellAt_eq hR _ _
    exact congrArg (fun L ↦ laneK (keccakSegment 0 (laneState L))
      (i.val / 2 ^ (witnessSizes (traceWitness prog input t) (traceWitness_pos hv hb)).τ 5 - 25)) hin
  · exact cellAt_eq hR _ _

/-- **`QFLOCK`**, Flock's instances once per `BLAKE3` row: the witness's. -/
theorem qflock_trace (hv : ValidExecution prog input t) (hb : TraceBounds t) {logs : List ℕ}
    (hl : logs.getD 6 0 =
      (witnessSizes (traceWitness prog input t) (traceWitness_pos hv hb)).τ 6) :
    Flock.qflockColumn (Flock.instancesOf ((traceRows t).tabs.getD 6 #[]) (logs.getD 6 0))
        (logs.getD 6 0) =
      (flockWitness prog (witnessSizes (traceWitness prog input t) (traceWitness_pos hv hb))
        (traceWitness prog input t)).toArray := by
  have hR : (traceRows t).tabs.getD 6 #[] =
      ((tableAt (traceWitness prog input t) 6).table.take
        ((witnessSizes (traceWitness prog input t) (traceWitness_pos hv hb)).rows 6)).toArray := by
    apply Array.toList_inj.mp
    rw [tabs_trace' hv hb 6 (by omega), List.toList_toArray]
    exact (List.take_of_length_le (le_of_eq rfl)).symm
  rw [hl, hR]
  unfold flockWitness
  dsimp only
  rw [Vector.toArray_ofFn]
  refine Array.ext (by simp [Flock.qflockColumn, qflockSlotBits, blake3R1csLogSize, flockKSkip])
    fun i h1 h2 ↦ ?_
  rw [Array.getElem_ofFn, Array.getD_eq_getD_getElem?, Array.getElem?_eq_getElem h1,
    Option.getD_some]

/-- **Every column of an execution.** On a valid execution, the executable columns at the
verifier's number of an instance column are that column of the stack of the specification witness
at its sizes: the committed columns, the `KECCAK` input lanes and spare columns, the derived
`KECCAK` output lanes, `QFLOCK`, and the `BLAKE3` value limbs, which need the witness to satisfy
the constraint system and Flock's walk to compute and keep its inputs (`hF`, a named hypothesis). -/
theorem cols_trace (hF : Flock.FlockWalk) (hv : ValidExecution prog input t) (hb : TraceBounds t)
    (hw : SatisfiedBy prog input (traceWitness prog input t))
    (hs : Sizes.ofWitness (traceWitness prog input t) = some (traceSizes prog input t)) (c : Col) :
    (colsOf t.memory (traceRows t) (tableLogs (traceSizes prog input t))
        (Flock.instancesOf ((traceRows t).tabs.getD 6 #[])
          ((tableLogs (traceSizes prog input t)).getD 6 0))).getD (refCol c) #[] =
      ((inst prog (traceSizes prog input t)).column
        (stackOf prog (traceSizes prog input t) (traceWitness prog input t)) c).values.toArray := by
  rw [colsOf_getD _ _ _ _ _ (refCol_lt c), traceSizes_eq hv hb]
  rw [traceSizes_eq hv hb] at hs
  have hl : ∀ j (hj : j < 7),
      (tableLogs (witnessSizes (traceWitness prog input t) (traceWitness_pos hv hb))).getD j 0 =
        (witnessSizes (traceWitness prog input t) (traceWitness_pos hv hb)).τ ⟨j, hj⟩ := by
    intro j hj
    rw [tableLogs, List.getD_eq_getElem?_getD, List.getElem?_ofFn]
    simp [hj]
  generalize tableLogs (witnessSizes (traceWitness prog input t) (traceWitness_pos hv hb)) = logs at hl
  have hI := rowsInv_trace hv
  rcases c with ⟨⟨j, hj⟩, i⟩
  match j, hj, i with
  | 0, _, i =>
    have hnv : ¬ IsVirtual (memCol i) := not_isVirtual_memCol' i
    exact (congrArg (columnAt t.memory (traceRows t) logs _ _ _) (refCol_memCol i)).trans
      ((memColumn_trace hv hb _ _ _ _ i).trans (column_toArray_committed _ _ _ hnv).symm)
  | 1, _, i =>
    obtain ⟨i, hi1⟩ := i
    obtain rfl : i = 0 := by change i < 1 at hi1; omega
    exact (congrArg (columnAt t.memory (traceRows t) logs _ _ _) refCol_bfcntCol).trans
      ((bfcntColumn_trace hv hb _ _ _ _).trans
        (column_toArray_committed _ _ bfcntCol (by decide)).symm)
  | 2, _, i =>
    obtain ⟨i, hi1⟩ := i
    obtain rfl : i = 0 := by change i < 1 at hi1; omega
    exact (congrArg (columnAt t.memory (traceRows t) logs _ _ _) refCol_keccakCol).trans
      ((columnAt_four _ _ _ _ _ _).trans ((qkeccak_trace hv hb (hl 5 (by omega))).trans
        (column_toArray_committed _ _ keccakCol not_isVirtual_keccakCol).symm))
  | 3, _, i =>
    obtain ⟨i, hi1⟩ := i
    obtain rfl : i = 0 := by change i < 1 at hi1; omega
    exact (congrArg (columnAt t.memory (traceRows t) logs _ _ _) refCol_flockCol).trans
      ((columnAt_five _ _ _ _ _ _).trans ((qflock_trace hv hb (hl 6 (by omega))).trans
        (column_toArray_committed _ _ flockCol not_isVirtual_flockCol).symm))
  | j + 4, hj, i =>
    have hj7 : j < 7 := by omega
    obtain ⟨i, hi⟩ := i
    have hiw : i < tableWidth j :=
      calc i < width (opIdx ⟨j, hj7⟩) := hi
        _ = tableWidth j := width_opIdx_eq ⟨j, hj7⟩
    have hpy : refCol ⟨⟨j + 4, hj⟩, ⟨i, hi⟩⟩ = tableBase j + i :=
      (refCol_opIdx ⟨j, hj7⟩ ⟨i, hi⟩).trans (congrArg (· + i) (globalColumnBases_getD ⟨j, hj7⟩))
    refine (congrArg (columnAt t.memory (traceRows t) logs _ _ _) hpy).trans
      ((columnAt_base _ _ _ _ _ _ j hj7 i hiw).trans ?_)
    by_cases hout : j = 5 ∧ 40 ≤ i ∧ i < 65
    · rw [ite_eq_left hout]
      obtain ⟨rfl, h38, h63⟩ := hout
      have hO : IsOut ⟨opIdx 5, ⟨i, hi⟩⟩ := ⟨rfl, h38, h63⟩
      have hl5 : logs.getD 5 0 =
          (witnessSizes (traceWitness prog input t) (traceWitness_pos hv hb)).τ 5 := hl 5 (by omega)
      refine Eq.trans ?_ (column_toArray_out _ _ _ hO).symm
      rw [hl5]
      refine congrArg Array.ofFn (funext fun x ↦ ?_)
      rw [outStates_getD _ _ _ x.isLt]
      have hin : (fun l : Fin 25 ↦ cellAt ((traceRows t).tabs.getD 5 #[]) x.val (15 + l.val)) =
          fun l : Fin 25 ↦ cellOf (tableAt (traceWitness prog input t) 5) x (15 + l.val) :=
        funext fun l ↦ cellAt_eq (tabs_trace' hv hb 5 (by omega)) _ _
      exact congrArg (fun L ↦ laneK (keccakSegment 1 (keccakSegment 0 (laneState L)))
        (i - 40)) hin
    rw [ite_eq_right hout]
    have hO : ¬ IsOut ⟨opIdx ⟨j, hj7⟩, ⟨i, hi⟩⟩ := fun h ↦ hout ⟨by
      have := congrArg Fin.val h.1; simp [opIdx] at this; omega, h.2⟩
    by_cases hj6 : j = 6
    · subst hj6
      rw [ite_eq_left rfl]
      have hi58 : i < 58 := by simpa [tableWidth] using hiw
      have hl6 : logs.getD 6 0 =
          (witnessSizes (traceWitness prog input t) (traceWitness_pos hv hb)).τ 6 := hl 6 (by omega)
      split
      · rename_i slot hslot
        have hpad : K.ofBits (blake3PaddingWord slot) = padR i := by
          have := blake3Slot_pad ⟨i, hi58⟩
          simp only [hslot, Option.all_some, decide_eq_true_eq] at this
          exact this
        refine Eq.trans ?_ (column_toArray_limb _ _ hF hw hs ⟨i, hi⟩).symm
        rw [hl6]
        unfold blake3ValueColumn
        refine congrArg Array.ofFn (funext fun x ↦ ?_)
        have hsz : ((traceRows t).tabs.getD 6 #[]).size =
            (witnessSizes (traceWitness prog input t) (traceWitness_pos hv hb)).rows 6 := by
          rw [← Array.length_toList, tabs_trace' hv hb 6 (by omega)]
          rfl
        rw [hsz]
        split_ifs
        · exact cellAt_eq (tabs_trace' hv hb 6 (by omega)) _ _
        · exact hpad
      · rename_i hslot
        have hS : ¬ (12 ≤ i ∧ i < 42) := by
          have := blake3Slot_isSome ⟨i, hi58⟩
          simp only [hslot, Option.isSome_none] at this
          exact of_decide_eq_false this.symm
        have hlimb : ¬ IsLimb ⟨opIdx 6, ⟨i, hi⟩⟩ := fun h ↦ hS ⟨h.2.1, h.2.2⟩
        refine Eq.trans ?_ (column_toArray_table _ _ 6 ⟨i, hi⟩ hO hlimb).symm
        rw [hl6]
        unfold tableColumn
        refine congrArg Array.ofFn (funext fun x ↦ ?_)
        exact cellAt_eq (tabs_trace' hv hb 6 (by omega)) _ _
    · rw [ite_eq_right hj6]
      have hlimb : ¬ IsLimb ⟨opIdx ⟨j, hj7⟩, ⟨i, hi⟩⟩ := fun h ↦ hj6 (by
        have := congrArg Fin.val h.1; simp [opIdx] at this; omega)
      refine Eq.trans ?_ (column_toArray_table _ _ ⟨j, hj7⟩ ⟨i, hi⟩ hO hlimb).symm
      rw [← hl j hj7]
      unfold tableColumn
      congr 1
      funext x
      exact cellAt_eq (tabs_trace' hv hb j hj7) _ _

end

end LeanVM.Prover
