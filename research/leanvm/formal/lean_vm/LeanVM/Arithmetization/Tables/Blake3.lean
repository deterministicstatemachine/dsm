/-
  LeanVM.Arithmetization.Tables.Blake3

  The `BLAKE3` table (research build): one Clean component per row, sound and complete for the
  relation the row refines, its bindings to an image together with `execute` of the instruction
  it names, under the named assumption that Flock's reduction proves the compression on the row's
  limbs.
-/

module

public import LeanVM.Arithmetization.Tables.Basic
public import LeanVM.Semantics.Blake3Cells
public import Clean.Circuit.Formal
public import Clean.Utils.Tactics.CircuitProofStart

@[expose] public section

/-!
# The `BLAKE3` table

The columns are `BLAKE3_COLUMNS` (`crates/verifier/src/layout.rs`) and the flushes
`flushes_blake3` (`layout.rs`; `crates/lean_vm_core/src/tables.rs`, `Blake3Table`). There is no
table constraint: the compression is proved by Flock's reduction (`verify_flock`) on the value
limbs, which are `q_flock`'s words.

**The row** `Blake3Row` is the column list: `pc, fp`; the operands `o_m₀, …, o_m₃` (`om`), `o_cv`,
`o_out`, `o_md`, `o_x`, `o_y`, `o_w`; the fifteen cells as limb pairs, in the columns' order (the
message's four, the output's two, the chaining value's two, the metadata, `X`'s, `Y`'s and `W`'s
two); one memory count per cell, in flush order (the message's, the chaining value's, the output's,
the metadata's, `X`'s, `Y`'s, `W`'s); the bytecode count `r_bc`.

**The relation.** `Blake3Bindings mem r` binds the row to an image: the thirteen cells read and the
two written hold the row's limbs. `Blake3Refines mem r next` adds that the machine executes
`BLAKE3` with the row's operands to `next`; `blake3_refines_of` is its converse given
`Blake3Relation r` (the output is the compression of the input), the table's `Assumptions`, which
Flock's reduction discharges for the composed system.
-/

namespace LeanVM.Arithmetization

open LeanVM.Parameters LeanVM.Semantics

/-! ## The row -/

/-- The `BLAKE3` columns, in the order of `BLAKE3_COLUMNS` (`layout.rs`). -/
structure Blake3Row (F : Type) where
  /-- The program counter. -/
  pc : F
  /-- The frame pointer. -/
  fp : F
  /-- The operands of the four message cells. -/
  om : Vector F 4
  /-- The operand `o_v`, the chaining value's two cells. -/
  ocv : F
  /-- The operand `o_out`, the output's two cells. -/
  oout : F
  /-- The operand `o_md`, the metadata cell. -/
  omd : F
  /-- The operand `o_x`, `X`'s two cells. -/
  ox : F
  /-- The operand `o_y`, `Y`'s two cells. -/
  oy : F
  /-- The operand `o_w`, `W`'s two cells. -/
  ow : F
  /-- Message cell `0`, as limbs. -/
  m0 : Vector F 2
  /-- Message cell `1`. -/
  m1 : Vector F 2
  /-- Message cell `2`. -/
  m2 : Vector F 2
  /-- Message cell `3`. -/
  m3 : Vector F 2
  /-- Output cell `0`. -/
  out0 : Vector F 2
  /-- Output cell `1`. -/
  out1 : Vector F 2
  /-- Chaining-value cell `0`. -/
  cv0 : Vector F 2
  /-- Chaining-value cell `1`. -/
  cv1 : Vector F 2
  /-- The metadata cell. -/
  md : Vector F 2
  /-- `X`'s cell `0`. -/
  x0 : Vector F 2
  /-- `X`'s cell `1`. -/
  x1 : Vector F 2
  /-- `Y`'s cell `0`. -/
  y0 : Vector F 2
  /-- `Y`'s cell `1`. -/
  y1 : Vector F 2
  /-- `W`'s cell `0`. -/
  w0 : Vector F 2
  /-- `W`'s cell `1`. -/
  w1 : Vector F 2
  /-- The read counts, in flush order. -/
  cnt : Vector F 15
  /-- The read count of the bytecode entry at `pc`. -/
  rbc : F
  deriving ProvableStruct

/-- A limb pair's word. -/
abbrev Blake3Row.word (v : Vector K 2) : E := E.ofLimbs v[0] v[1]

/-- The four message operands of a row. -/
def Blake3Row.oms (r : Blake3Row K) : Fin 4 → K := fun i ↦ r.om[i]

/-- The thirteen cells a row reads, in `blake3InputCellOffset`'s order. -/
def Blake3Row.inCells (r : Blake3Row K) : Fin 13 → E :=
  ![Blake3Row.word r.m0, Blake3Row.word r.m1, Blake3Row.word r.m2, Blake3Row.word r.m3,
    Blake3Row.word r.cv0, Blake3Row.word r.cv1, Blake3Row.word r.md, Blake3Row.word r.x0,
    Blake3Row.word r.x1, Blake3Row.word r.y0, Blake3Row.word r.y1, Blake3Row.word r.w0,
    Blake3Row.word r.w1]

/-- The two cells a row writes, zero past them. -/
def Blake3Row.outCells (r : Blake3Row K) : Fin 13 → E :=
  ![Blake3Row.word r.out0, Blake3Row.word r.out1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

/-- The compression on a row's limbs, as Flock's reduction proves it: the output is the new
chaining value of the input. The named assumption of the table. -/
def Blake3Relation (r : Blake3Row K) : Prop := Blake3CellsRelation r.inCells r.outCells

/-! ## The relation -/

/-- The thirteen offsets, spelled out. -/
theorem blake3InputCellOffset_eq (om : Fin 4 → K) (ocv omd ox oy ow : K) :
    blake3InputCellOffset om ocv omd ox oy ow =
      ![om 0, om 1, om 2, om 3, ocv, g * ocv, omd, ox, g * ox, oy, g * oy, ow, g * ow] := by
  funext c; fin_cases c <;> rfl

/-- The row's bindings to an image: the cells read and written hold the row's limbs. -/
structure Blake3Bindings {κ : ℕ} (mem : MemoryImage κ) (r : Blake3Row K) : Prop where
  /-- Cell `c` read holds the row's `c`-th input cell. -/
  in_eq : ∀ c : Fin 13,
    mem.read (r.fp * blake3InputCellOffset r.oms r.ocv r.omd r.ox r.oy r.ow c) = some (r.inCells c)
  /-- Output cell `c < 2` holds the row's `c`-th output cell. -/
  out_eq : ∀ c : Fin 13, c.val < 2 → mem.read (r.fp * (g ^ c.val * r.oout)) = some (r.outCells c)

/-- The relation a `BLAKE3` row refines: it is bound to the image, and from its registers the
machine executes the instruction it names to `next`. -/
def Blake3Refines {κ : ℕ} (mem : MemoryImage κ) (r : Blake3Row K) (next : Registers K) : Prop :=
  Blake3Bindings mem r ∧
    execute mem ⟨r.pc, r.fp⟩ (.blake3 r.oms r.ocv r.oout r.omd r.ox r.oy r.ow) = some next

/-- **A bound row whose limbs compress refines `BLAKE3`**, to the successor `(g·pc, fp)`. -/
theorem blake3_refines_of {κ : ℕ} {mem : MemoryImage κ} {r : Blake3Row K}
    (hb : Blake3Bindings mem r) (hrel : Blake3Relation r) :
    Blake3Refines mem r (Registers.next ⟨r.pc, r.fp⟩) :=
  ⟨hb, (execute_blake3_eq_some_iff _ _ _ _ _ _ _ _ _ _).mpr
    ⟨r.inCells, r.outCells, hb.in_eq, hb.out_eq, hrel, rfl⟩⟩

/-! ## The adapter to the prover data -/

/-- The table's `Spec`: the row refines `Blake3Refines` over the image the prover data names. -/
def Blake3Spec (r : Blake3Row K) (next : Registers K) (data : ProverData K) : Prop :=
  Blake3Refines (imageOf data).2 r next

/-- The bytecode tuple of a row, its operands spelled out, is `entry` of the instruction it names. -/
private theorem blake3_entry' (a0 a1 a2 a3 ocv oout omd ox oy ow : K) :
    #v[Opcode.blake3.busCode] ++ #v[a0, a1, a2, a3, ocv, oout, omd, ox, oy, ow, 0, 0] =
      busEntry (.blake3 ![a0, a1, a2, a3] ocv oout omd ox oy ow) := rfl

/-! ## The table -/

set_option maxHeartbeats 16000000 in
/-- The `BLAKE3` table (`flushes_blake3`, `layout.rs`): state step, bytecode read of
`(BLAKE3, o_m₀, …, o_m₃, o_v, o_out, o_md, o_x, o_y, o_w)`, then the fifteen cells, each as its
two limbs, in flush order. Returns the pushed successor `(g·pc, fp)`; sound under
`Blake3Relation`. -/
def blake3Table : GeneralFormalCircuit K Blake3Row Registers where
  name := "BLAKE3"
  main r := do
    let next : Var Registers K := ⟨Expression.const g * r.pc, r.fp⟩
    StatePull.pull ⟨r.pc, r.fp⟩
    StatePush.push next
    bytecodeRead r.pc r.rbc (Expression.const Opcode.blake3.busCode)
      #v[r.om[0], r.om[1], r.om[2], r.om[3], r.ocv, r.oout, r.omd, r.ox, r.oy, r.ow, 0, 0]
    memRead (r.fp * r.om[0]) r.cnt[0] r.m0
    memRead (r.fp * r.om[1]) r.cnt[1] r.m1
    memRead (r.fp * r.om[2]) r.cnt[2] r.m2
    memRead (r.fp * r.om[3]) r.cnt[3] r.m3
    memRead (r.fp * r.ocv) r.cnt[4] r.cv0
    memRead (r.fp * (Expression.const g * r.ocv)) r.cnt[5] r.cv1
    memRead (r.fp * (Expression.const (g ^ 0) * r.oout)) r.cnt[6] r.out0
    memRead (r.fp * (Expression.const (g ^ 1) * r.oout)) r.cnt[7] r.out1
    memRead (r.fp * r.omd) r.cnt[8] r.md
    memRead (r.fp * r.ox) r.cnt[9] r.x0
    memRead (r.fp * (Expression.const g * r.ox)) r.cnt[10] r.x1
    memRead (r.fp * r.oy) r.cnt[11] r.y0
    memRead (r.fp * (Expression.const g * r.oy)) r.cnt[12] r.y1
    memRead (r.fp * r.ow) r.cnt[13] r.w0
    memRead (r.fp * (Expression.const g * r.ow)) r.cnt[14] r.w1
    pure next
  channelsWithRequirements := [StatePush.toRaw, MemPush.toRaw, BytecodePush.toRaw]
  requirementsChannelsLawful input offset := by
    simp only [circuit_norm, memRead, bytecodeRead, -BitVec.reduceNeg]
    tauto
  -- The named assumption: Flock's proof of the compression on the row's limbs.
  Assumptions r _ := Blake3Relation r
  Spec := Blake3Spec
  ProverAssumptions r data _ := Blake3Bindings (imageOf data).2 r
  soundness := by
    circuit_proof_start [StatePull, StatePush, MemPull, MemPush, BytecodePull, BytecodePush,
      memRead, bytecodeRead]
    obtain ⟨-, h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14⟩ := h_holds
    obtain ⟨_, _, hom, _, _, _, _, _, _, hm0, hm1, hm2, hm3, ho0, ho1, hc0, hc1, hmd, hx0, hx1, hy0,
      hy1, hw0, hw1, _, _⟩ := h_input
    subst hom hm0 hm1 hm2 hm3 ho0 ho1 hc0 hc1 hmd hx0 hx1 hy0 hy1 hw0 hw1
    refine blake3_refines_of ⟨fun c ↦ ?_, fun c hc ↦ ?_⟩ h_assumptions
    · fin_cases c
      · simp [Blake3Row.inCells, Blake3Row.oms, blake3InputCellOffset_eq, Blake3Row.word, Vector.getElem_map] at h0 ⊢; exact h0
      · simp [Blake3Row.inCells, Blake3Row.oms, blake3InputCellOffset_eq, Blake3Row.word, Vector.getElem_map] at h1 ⊢; exact h1
      · simp [Blake3Row.inCells, Blake3Row.oms, blake3InputCellOffset_eq, Blake3Row.word, Vector.getElem_map] at h2 ⊢; exact h2
      · simp [Blake3Row.inCells, Blake3Row.oms, blake3InputCellOffset_eq, Blake3Row.word, Vector.getElem_map] at h3 ⊢; exact h3
      · simp [Blake3Row.inCells, Blake3Row.oms, blake3InputCellOffset_eq, Blake3Row.word, Vector.getElem_map] at h4 ⊢; exact h4
      · simp [Blake3Row.inCells, Blake3Row.oms, blake3InputCellOffset_eq, Blake3Row.word, Vector.getElem_map] at h5 ⊢; exact h5
      · simp [Blake3Row.inCells, Blake3Row.oms, blake3InputCellOffset_eq, Blake3Row.word, Vector.getElem_map] at h8 ⊢; exact h8
      · simp [Blake3Row.inCells, Blake3Row.oms, blake3InputCellOffset_eq, Blake3Row.word, Vector.getElem_map] at h9 ⊢; exact h9
      · simp [Blake3Row.inCells, Blake3Row.oms, blake3InputCellOffset_eq, Blake3Row.word, Vector.getElem_map] at h10 ⊢; exact h10
      · simp [Blake3Row.inCells, Blake3Row.oms, blake3InputCellOffset_eq, Blake3Row.word, Vector.getElem_map] at h11 ⊢; exact h11
      · simp [Blake3Row.inCells, Blake3Row.oms, blake3InputCellOffset_eq, Blake3Row.word, Vector.getElem_map] at h12 ⊢; exact h12
      · simp [Blake3Row.inCells, Blake3Row.oms, blake3InputCellOffset_eq, Blake3Row.word, Vector.getElem_map] at h13 ⊢; exact h13
      · simp [Blake3Row.inCells, Blake3Row.oms, blake3InputCellOffset_eq, Blake3Row.word, Vector.getElem_map] at h14 ⊢; exact h14
    · fin_cases c
      · simp [Blake3Row.outCells, Blake3Row.word, Vector.getElem_map] at h6 ⊢; exact h6
      · simp [Blake3Row.outCells, Blake3Row.word, Vector.getElem_map] at h7 ⊢; exact h7
      all_goals simp at hc
  completeness := by
    circuit_proof_start [StatePull, StatePush, MemPull, MemPush, BytecodePull, BytecodePush,
      memRead, bytecodeRead]
    obtain ⟨hin, hout⟩ := h_assumptions
    obtain ⟨_, _, hom, _, _, _, _, _, _, hm0, hm1, hm2, hm3, ho0, ho1, hc0, hc1, hmd, hx0, hx1, hy0,
      hy1, hw0, hw1, _, _⟩ := h_input
    subst hom hm0 hm1 hm2 hm3 ho0 ho1 hc0 hc1 hmd hx0 hx1 hy0 hy1 hw0 hw1
    refine ⟨⟨_, by rw [blake3_entry']; exact decode_entry _⟩, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
      ?_, ?_, ?_, ?_, ?_, ?_⟩
    · have h := hin 0
      simp [Blake3Row.inCells, Blake3Row.oms, blake3InputCellOffset_eq, Blake3Row.word, Vector.getElem_map] at h ⊢; exact h
    · have h := hin 1
      simp [Blake3Row.inCells, Blake3Row.oms, blake3InputCellOffset_eq, Blake3Row.word, Vector.getElem_map] at h ⊢; exact h
    · have h := hin 2
      simp [Blake3Row.inCells, Blake3Row.oms, blake3InputCellOffset_eq, Blake3Row.word, Vector.getElem_map] at h ⊢; exact h
    · have h := hin 3
      simp [Blake3Row.inCells, Blake3Row.oms, blake3InputCellOffset_eq, Blake3Row.word, Vector.getElem_map] at h ⊢; exact h
    · have h := hin 4
      simp [Blake3Row.inCells, Blake3Row.oms, blake3InputCellOffset_eq, Blake3Row.word, Vector.getElem_map] at h ⊢; exact h
    · have h := hin 5
      simp [Blake3Row.inCells, Blake3Row.oms, blake3InputCellOffset_eq, Blake3Row.word, Vector.getElem_map] at h ⊢; exact h
    · have h := hout 0 (by decide)
      simp [Blake3Row.outCells, Blake3Row.word, Vector.getElem_map] at h ⊢; exact h
    · have h := hout 1 (by decide)
      simp [Blake3Row.outCells, Blake3Row.word, Vector.getElem_map] at h ⊢; exact h
    · have h := hin 6
      simp [Blake3Row.inCells, Blake3Row.oms, blake3InputCellOffset_eq, Blake3Row.word, Vector.getElem_map] at h ⊢; exact h
    · have h := hin 7
      simp [Blake3Row.inCells, Blake3Row.oms, blake3InputCellOffset_eq, Blake3Row.word, Vector.getElem_map] at h ⊢; exact h
    · have h := hin 8
      simp [Blake3Row.inCells, Blake3Row.oms, blake3InputCellOffset_eq, Blake3Row.word, Vector.getElem_map] at h ⊢; exact h
    · have h := hin 9
      simp [Blake3Row.inCells, Blake3Row.oms, blake3InputCellOffset_eq, Blake3Row.word, Vector.getElem_map] at h ⊢; exact h
    · have h := hin 10
      simp [Blake3Row.inCells, Blake3Row.oms, blake3InputCellOffset_eq, Blake3Row.word, Vector.getElem_map] at h ⊢; exact h
    · have h := hin 11
      simp [Blake3Row.inCells, Blake3Row.oms, blake3InputCellOffset_eq, Blake3Row.word, Vector.getElem_map] at h ⊢; exact h
    · have h := hin 12
      simp [Blake3Row.inCells, Blake3Row.oms, blake3InputCellOffset_eq, Blake3Row.word, Vector.getElem_map] at h ⊢; exact h

/-! ## Rows from executions -/

/-- The row of an execution of `BLAKE3` from `(pc, fp)` over the image `mem`: the registers, the
operands, the fifteen cells read back from the image as limbs, and the counts as parameters. -/
noncomputable def blake3RowOf {κ : ℕ} (mem : MemoryImage κ) (pc fp : K) (om : Fin 4 → K)
    (ocv oout omd ox oy ow : K) (cnt : Vector K 15) (rbc : K) : Blake3Row K :=
  let L := fun (a : K) ↦ mem.limbsAt (fp * a)
  ⟨pc, fp, #v[om 0, om 1, om 2, om 3], ocv, oout, omd, ox, oy, ow, L (om 0), L (om 1), L (om 2),
    L (om 3), L (g ^ 0 * oout), L (g ^ 1 * oout), L ocv, L (g * ocv), L omd, L ox, L (g * ox),
    L oy, L (g * oy), L ow, L (g * ow), cnt, rbc⟩

/-- The operands of `blake3RowOf` are the instruction's. -/
theorem blake3RowOf_oms {κ : ℕ} (mem : MemoryImage κ) (pc fp : K) (om : Fin 4 → K)
    (ocv oout omd ox oy ow : K) (cnt : Vector K 15) (rbc : K) :
    (blake3RowOf mem pc fp om ocv oout omd ox oy ow cnt rbc).oms = om := by
  funext i; fin_cases i <;> rfl

/-- The input cells of `blake3RowOf` are the image's words at the offsets. -/
theorem blake3RowOf_inCells {κ : ℕ} (mem : MemoryImage κ) (pc fp : K) (om : Fin 4 → K)
    (ocv oout omd ox oy ow : K) (cnt : Vector K 15) (rbc : K) (c : Fin 13) :
    (blake3RowOf mem pc fp om ocv oout omd ox oy ow cnt rbc).inCells c =
      Blake3Row.word (mem.limbsAt (fp * blake3InputCellOffset om ocv omd ox oy ow c)) := by
  fin_cases c <;> rfl

/-- The output cells of `blake3RowOf`, the first two, are the image's words at the offsets. -/
theorem blake3RowOf_outCells {κ : ℕ} (mem : MemoryImage κ) (pc fp : K) (om : Fin 4 → K)
    (ocv oout omd ox oy ow : K) (cnt : Vector K 15) (rbc : K) (c : Fin 13) (hc : c.val < 2) :
    (blake3RowOf mem pc fp om ocv oout omd ox oy ow cnt rbc).outCells c =
      Blake3Row.word (mem.limbsAt (fp * (g ^ c.val * oout))) := by
  fin_cases c
  · rfl
  · rfl
  all_goals simp at hc

/-- A valid execution of `BLAKE3` is represented by `blake3RowOf`, with any counts. -/
theorem blake3RowOf_refines {κ : ℕ} {mem : MemoryImage κ} {pc fp : K} {om : Fin 4 → K}
    {ocv oout omd ox oy ow : K} {next : Registers K}
    (hexec : execute mem ⟨pc, fp⟩ (.blake3 om ocv oout omd ox oy ow) = some next)
    (cnt : Vector K 15) (rbc : K) :
    Blake3Refines mem (blake3RowOf mem pc fp om ocv oout omd ox oy ow cnt rbc) next := by
  obtain ⟨input, output, hin, hout, -, -⟩ :=
    (execute_blake3_eq_some_iff _ _ _ _ _ _ _ _ _ _).mp hexec
  refine ⟨⟨fun c ↦ ?_, fun c hc ↦ ?_⟩, by rw [blake3RowOf_oms]; exact hexec⟩
  · have h := hin c
    have e : Blake3Row.word (mem.limbsAt (fp * blake3InputCellOffset om ocv omd ox oy ow c)) =
        input c := MemoryImage.ofLimbs_limbsAt (hin c)
    rw [← e] at h
    rw [blake3RowOf_oms, blake3RowOf_inCells]
    exact h
  · have h := hout c hc
    have e : Blake3Row.word (mem.limbsAt (fp * (g ^ c.val * oout))) = output c :=
      MemoryImage.ofLimbs_limbsAt (hout c hc)
    rw [← e] at h
    rw [blake3RowOf_outCells _ _ _ _ _ _ _ _ _ _ _ _ _ hc]
    exact h

/-- The row of a valid `BLAKE3` execution compresses: its input cells are the cells read, and its
output cells the cells written, which the execution checks. -/
theorem blake3RowOf_relation {κ : ℕ} {mem : MemoryImage κ} {pc fp : K} {om : Fin 4 → K}
    {ocv oout omd ox oy ow : K} {next : Registers K}
    (hexec : execute mem ⟨pc, fp⟩ (.blake3 om ocv oout omd ox oy ow) = some next)
    (cnt : Vector K 15) (rbc : K) :
    Blake3Relation (blake3RowOf mem pc fp om ocv oout omd ox oy ow cnt rbc) := by
  obtain ⟨input, output, hin, hout, ⟨h0, h1⟩, -⟩ :=
    (execute_blake3_eq_some_iff _ _ _ _ _ _ _ _ _ _).mp hexec
  have hi : (blake3RowOf mem pc fp om ocv oout omd ox oy ow cnt rbc).inCells = input := by
    funext c
    rw [blake3RowOf_inCells]
    exact MemoryImage.ofLimbs_limbsAt (hin c)
  have ho : ∀ c : Fin 13, c.val < 2 →
      (blake3RowOf mem pc fp om ocv oout omd ox oy ow cnt rbc).outCells c = output c :=
    fun c hc ↦ by
      rw [blake3RowOf_outCells _ _ _ _ _ _ _ _ _ _ _ _ _ hc]
      exact MemoryImage.ofLimbs_limbsAt (hout c hc)
  unfold Blake3Relation Blake3CellsRelation
  rw [hi]
  exact ⟨(ho 0 (by decide)).trans h0, (ho 1 (by decide)).trans h1⟩

/-- Every valid `BLAKE3` execution has a satisfying row, from the execution alone. -/
theorem blake3_exec_complete {data : ProverData K} {pc fp : K} {om : Fin 4 → K}
    {ocv oout omd ox oy ow : K} {next : Registers K}
    (hexec : execute (imageOf data).2 ⟨pc, fp⟩ (.blake3 om ocv oout omd ox oy ow) = some next)
    (cnt : Vector K 15) (rbc : K) :
    ConstraintsHold.Completeness (rowEnv data)
      ((blake3Table.main (const (blake3RowOf (imageOf data).2 pc fp om ocv oout omd ox oy ow cnt
        rbc))).operations 0) :=
  (blake3Table.completeness 0 (rowEnv data) (const _)
    (by simp only [circuit_norm, blake3Table, memRead, bytecodeRead, -BitVec.reduceNeg]) _
    ProvableType.eval_const_prover (blake3RowOf_refines hexec cnt rbc).1).1

end LeanVM.Arithmetization
