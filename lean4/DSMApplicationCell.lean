/-
  An application cell and the one write that holds it; self-contained Lean 4
  (no Mathlib, no imports). DSM Amendment A35; storage spec §9;
  `dsm/src/app_cell.rs`.

    - CELL          K_app = H(cell ‖ application ‖ ω ‖ name), ω = H(writers ‖ W):
                    the key commits the application, the name and the exact
                    writer set.
    - WRITE         carries the application, the name, the writer set, the
                    writer that signed, a payload and a signature over
                    m(p) = H(write ‖ K_app ‖ p).
    - RECOGNITION   from the write's own fields and the cell's key alone: its
                    fields derive the key, its signer is one of its writers,
                    and the signature verifies under that signer.
    - OCCUPANT      the first recognized write in the leader's arrival log
                    (storage §9). The other seats' logs are not an input.
    - STEP          H(step ‖ K_app ‖ the occupant's fields): what an
                    application's next cell name commits.

  The hash is an uninterpreted function. Where a theorem needs it to separate
  two inputs it takes `Injective H` as a premise: an idealization of
  collision resistance, not a fact about BLAKE3 (CONFORMANCE_GAPS, "Lean
  premises"). Signature verification is an uninterpreted relation.

  Proved here (MR-DSM-0368 to MR-DSM-0370):
    - one cell has one application, one name and one writer set, so a write
      recognized at a cell was signed by a key that cell's own set names;
    - the occupant is a function of the leader's log, the same for every
      reader and whatever the other seats hold;
    - bytes that are not recognized ahead of a recognized write take no place;
    - an occupant, once read, is the occupant on every later read (a node only
      appends), and a later write never is, even one recognized at the cell;
    - the step commits the occupant: two different occupants give two steps,
      whether or not an application accepts either.

  Mutation controls (executed 2026-11-12): taking the last recognized write
  for the occupant breaks `unrecognized_values_are_passed_over` and
  `occupant_is_stable`; a step over the payload alone breaks
  `step_commits_the_occupant`; recognition without the signer's membership
  breaks `recognized_iff`.
-/

namespace DSMApplicationCell

/-- A write as its own fields. Keys, digests and payloads are numbers. -/
structure Write where
  application : Nat
  name        : Nat
  writers     : List Nat
  signer      : Nat
  payload     : Nat
  signature   : Nat
deriving DecidableEq

/-- The hash and the signature check, uninterpreted. -/
structure Crypto where
  H      : List Nat → Nat
  verify : Nat → Nat → Nat → Bool

/-- A function that sends different inputs to different outputs. -/
def Injective {α β : Type} (f : α → β) : Prop := ∀ a b, f a = f b → a = b

variable (c : Crypto)

/-- ω, the digest of a writer set. -/
def writersDigest (ws : List Nat) : Nat := c.H (1 :: ws)

/-- K_app. -/
def cellKey (application : Nat) (ws : List Nat) (name : Nat) : Nat :=
  c.H [2, application, writersDigest c ws, name]

/-- The cell a write's own fields name. -/
def cellOf (w : Write) : Nat := cellKey c w.application w.writers w.name

/-- m(p): what a writer signs to write payload p at the cell. -/
def statement (cell payload : Nat) : Nat := c.H [3, cell, payload]

/-- A write's fields in one order, as the step hashes them. -/
def fields (w : Write) : List Nat :=
  [w.application, w.name, w.signer, w.payload, w.signature] ++ w.writers

/-- The step of a cell and the write holding it. -/
def step (cell : Nat) (w : Write) : Nat := c.H (4 :: cell :: fields w)

/-- Recognition at `cell`, from the write's own fields and the key. -/
def recognized (cell : Nat) (w : Write) : Bool :=
  decide (cellOf c w = cell) && w.writers.contains w.signer
    && c.verify w.signer (statement c cell w.payload) w.signature

/-- The canonical occupant: the first recognized write in the leader's log. -/
def occupant (cell : Nat) (leader : List Write) : Option Write :=
  leader.find? (recognized c cell)

/-- A cell as a reader holds it: the leader's log and the other seats' logs. -/
structure Seats where
  leader : List Write
  others : Fin 4 → List Write

/-- What a reader reads at a cell. -/
def read (cell : Nat) (s : Seats) : Option Write := occupant c cell s.leader

-- ── recognition ───────────────────────────────────────────────────────────

/-- A recognized write names the cell, is signed by one of its own writers,
    and its signature verifies over the statement for that cell. -/
theorem recognized_iff (cell : Nat) (w : Write) :
    recognized c cell w = true ↔
      cellOf c w = cell ∧ w.writers.contains w.signer = true
        ∧ c.verify w.signer (statement c cell w.payload) w.signature = true := by
  simp [recognized, Bool.and_eq_true, and_assoc]

/-- A write whose signature does not verify is not recognized. -/
theorem unverified_is_not_recognized (cell : Nat) (w : Write)
    (h : c.verify w.signer (statement c cell w.payload) w.signature = false) :
    recognized c cell w = false := by
  cases hr : recognized c cell w with
  | false => rfl
  | true =>
    have hv := ((recognized_iff c cell w).mp hr).2.2
    rw [h] at hv
    cases hv

/-- A write signed by a key outside its own writer set is not recognized. -/
theorem outsider_is_not_recognized (cell : Nat) (w : Write)
    (h : w.writers.contains w.signer = false) : recognized c cell w = false := by
  cases hr : recognized c cell w with
  | false => rfl
  | true =>
    have hm := ((recognized_iff c cell w).mp hr).2.1
    rw [h] at hm
    cases hm

/-- A write for another cell is not recognized at this one. -/
theorem other_cell_is_not_recognized (cell : Nat) (w : Write)
    (h : cellOf c w ≠ cell) : recognized c cell w = false := by
  cases hr : recognized c cell w with
  | false => rfl
  | true => exact absurd ((recognized_iff c cell w).mp hr).1 h

/-- Under an injective hash a cell has one application, one name and one
    writer set: two writes that name one cell carry the same three. -/
theorem one_cell_one_writer_set (hH : Injective c.H) (w w' : Write)
    (h : cellOf c w = cellOf c w') :
    w.application = w'.application ∧ w.name = w'.name ∧ w.writers = w'.writers := by
  unfold cellOf cellKey at h
  have h1 := hH _ _ h
  injection h1 with _ h1
  injection h1 with ha h1
  injection h1 with hw h1
  injection h1 with hn _
  unfold writersDigest at hw
  have h2 := hH _ _ hw
  injection h2 with _ h2
  exact ⟨ha, hn, h2⟩

/-- So a write recognized at the cell of `w` was signed by a key `w`'s own
    writer set names: adding a key to the set is another cell. -/
theorem recognized_signer_is_a_writer_of_the_cell (hH : Injective c.H)
    (w w' : Write) (h : recognized c (cellOf c w) w' = true) :
    w.writers.contains w'.signer = true := by
  have h' := (recognized_iff c (cellOf c w) w').mp h
  have hs := one_cell_one_writer_set c hH w' w h'.1
  rw [← hs.2.2]
  exact h'.2.1

-- ── the occupant ──────────────────────────────────────────────────────────

/-- The occupant is recognized at the cell. -/
theorem occupant_is_recognized (cell : Nat) (leader : List Write) (w : Write)
    (h : occupant c cell leader = some w) : recognized c cell w = true :=
  List.find?_some h

/-- Every reader of one leader log reads one occupant, whatever the other
    seats hold: first arrival anywhere else decides nothing. -/
theorem read_ignores_the_other_seats (cell : Nat) (s s' : Seats)
    (h : s.leader = s'.leader) : read c cell s = read c cell s' := by
  unfold read
  rw [h]

/-- Values that are not recognized ahead of a recognized write take no
    place: the write holds the cell. -/
theorem unrecognized_values_are_passed_over (cell : Nat) (pre post : List Write) (w : Write)
    (hpre : ∀ x, x ∈ pre → recognized c cell x = false) (hw : recognized c cell w = true) :
    occupant c cell (pre ++ w :: post) = some w := by
  unfold occupant
  induction pre with
  | nil => simp only [List.nil_append, List.find?_cons, hw]
  | cons x xs ih =>
    have hx : recognized c cell x = false := hpre x (List.mem_cons_self ..)
    have hxs : ∀ y, y ∈ xs → recognized c cell y = false :=
      fun y hy => hpre y (List.mem_cons_of_mem _ hy)
    simp only [List.cons_append, List.find?_cons, hx]
    exact ih hxs

/-- A node only appends: an occupant, once read, is the occupant on every
    later read of the leader. -/
theorem occupant_is_stable (cell : Nat) (leader later : List Write) (w : Write)
    (h : occupant c cell leader = some w) :
    occupant c cell (leader ++ later) = some w := by
  unfold occupant at *
  induction leader with
  | nil => cases h
  | cons x xs ih =>
    cases hx : recognized c cell x with
    | true =>
      simp only [List.find?_cons, hx] at h
      simp only [List.cons_append, List.find?_cons, hx]
      exact h
    | false =>
      simp only [List.find?_cons, hx] at h
      simp only [List.cons_append, List.find?_cons, hx]
      exact ih h

/-- A second write never holds the cell, even one validly signed by another
    writer of the set: the first recognized write stays the occupant. -/
theorem a_later_write_never_holds_the_cell (cell : Nat) (leader later : List Write)
    (w w' : Write) (h : occupant c cell leader = some w) (hne : w' ≠ w) :
    occupant c cell (leader ++ later) ≠ some w' := by
  rw [occupant_is_stable c cell leader later w h]
  intro heq
  exact hne (Option.some.inj heq).symm

-- ── the step ──────────────────────────────────────────────────────────────

/-- A write is its fields. -/
theorem fields_inj {w w' : Write} (h : fields w = fields w') : w = w' := by
  cases w
  cases w'
  simp [fields] at h
  simp [h]

/-- Under an injective hash the step commits the cell and the occupant: two
    different occupants give two steps. Nothing about what an application
    makes of the payload enters it, so its lineage records an occupant it
    accepts and one it passes over alike. -/
theorem step_commits_the_occupant (hH : Injective c.H) (cell cell' : Nat)
    (w w' : Write) (h : step c cell w = step c cell' w') : cell = cell' ∧ w = w' := by
  unfold step at h
  have h1 := hH _ _ h
  injection h1 with _ h1
  injection h1 with hc hf
  exact ⟨hc, fields_inj hf⟩

end DSMApplicationCell
