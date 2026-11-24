/-
  LeanVM.Semantics.Blake3Cells

  What `execute` of a `BLAKE3` asks of the image (research build): its thirteen input cells and two
  output cells read, the compression relation between them, the fall-through successor.
-/

module

public import LeanVM.Semantics.KeccakCells

namespace LeanVM.Semantics

open LeanVM.Parameters

@[expose] public section

/-- **`BLAKE3`'s execution**: the thirteen cells read hold `input`, the two written `output`, the
compression relation holds, and the successor is `(g·pc, fp)`. -/
theorem execute_blake3_eq_some_iff {κ : ℕ} (mem : MemoryImage κ) (r : Registers K)
    (om : Fin 4 → K) (ocv oout omd ox oy ow : K) (next : Registers K) :
    execute mem r (.blake3 om ocv oout omd ox oy ow) = some next ↔
      ∃ input output : Fin 13 → E,
        (∀ c, mem.read (r.fp * blake3InputCellOffset om ocv omd ox oy ow c) = some (input c)) ∧
        (∀ c : Fin 13, c.val < 2 → mem.read (r.fp * (g ^ c.val * oout)) = some (output c)) ∧
        Blake3CellsRelation input output ∧ next = r.next := by
  simp only [execute, executeWith, Option.bind_eq_bind, Option.bind_eq_some_iff]
  constructor
  · rintro ⟨input, hin, output, hout, u, hu, hn⟩
    unfold guard at hu
    split_ifs at hu with hc
    simp only [Option.pure_def, Option.some.injEq] at hn
    exact ⟨input, output, (readCells_eq_some_iff _ _ _ _).mp hin,
      ((readFirstCells_eq_some_iff _ _ _ _ _).mp hout).1, hc, hn.symm⟩
  · rintro ⟨input, output, hin, hout, hc, rfl⟩
    let output' : Fin 13 → E := fun c ↦ if c.val < 2 then output c else 0
    have hc' : Blake3CellsRelation input output' := by
      obtain ⟨h0, h1⟩ := hc
      exact ⟨by simpa [output'] using h0, by simpa [output'] using h1⟩
    refine ⟨input, (readCells_eq_some_iff _ _ _ _).mpr hin, output',
      (readFirstCells_eq_some_iff _ _ _ _ _).mpr ⟨fun c h ↦ ?_, fun c h ↦ ?_⟩, (), ?_, rfl⟩
    · simp only [output', h, ↓reduceIte]; exact hout c h
    · simp only [output']; split_ifs <;> first | omega | rfl
    · simp [guard, hc']

end

end LeanVM.Semantics
