/-
  SoFi storage facts for objects and indexes — Part II §10, §11, §13 —
  rebuild steps R1, R5 and R6 — self-contained Lean 4 (no Mathlib, no imports)

  A member stores bytes under the hash of the bytes and appends content
  addresses under locators; it interprets nothing. Core turns raw member
  answers into two facts and uses nothing else from storage:

    Stored(o)   ⟺  three members return the exact bytes of o
    Kept(L, o)  ⟺  o is the first candidate under L whose recomputed
                   identity is L; every other candidate is nothing

  RUST CORRESPONDENCE  `dsm/src/sofi/storage.rs`: `stored`, `merge_index_reads`,
  `keep_verifying`. Every theorem below has a Rust test of the same name in
  that module. The address model is `storage_object::immutable_addr`:
  `addr(ns, p) = H(storage-object; ns ‖ H(ns; p))`, here `H [0, ns, H [1, ns, p]]`.

  WHAT IS PROVED
    - stored_returns_exact_bytes     the fact's bytes re-hash to the address
                                     read; never a member's word
    - counting_reads_agree           any two counted answers carry the same
                                     payload (the address is injective in it)
    - wrong_bytes_never_count        bytes that do not derive the address are
                                     nothing, whoever returned them
    - a_wrong_namespace_never_counts the address binds the namespace too
    - two_members_is_not_stored      the threshold is three, exactly
    - silence_never_counts           an unreachable or absent answer is not bytes
    - kept_verifies                  what is kept recomputes to the locator and
                                     is a candidate
    - garbage_is_never_kept          nothing under the locator verifies ⇒
                                     nothing is kept
    - over_budget_is_unavailable_never_none
                                     running out of budget before a verifying
                                     candidate is Unavailable, never None
    - within_budget_exhausted_is_none
                                     every candidate examined, none verifies ⇒ None
    - acquired_bytes_are_stored      (R5) acquisition holds only Stored bytes,
                                     at the addresses the preimage needs
    - nothing_is_defaulted           (R5) nothing needed, or nothing read ⇒ the
      silence_acquires_nothing       evidence holds nothing; never filled in
    - missing_evidence_is_unavailable_never_invalid
                                     (R5) a check over an unfetched item is
                                     Unavailable; acquisition_decides_nothing
    - unavailable_stops_the_producer (R6) rule T5: no conjunction holding an
      the_producer_proceeds_only_on_valid
                                     Unavailable is Valid; the producer moves
                                     on Valid alone; Invalid dominates

  MUTATION CONTROLS, executed against the Rust module (each turns the named
  Rust test red) and against this file (each puts the named theorem on
  `sorryAx`):
    1. admit bytes without the address check   -> wrong_bytes_never_count,
       (`| some (ns, p) => let _ := addr h ns p;   a_wrong_namespace_never_counts,
        some p`, keeping `h` in scope)             counting_reads_agree
    2. threshold 2                              -> two_members_is_not_stored
    3. keep a candidate without recomputing     -> kept_verifies,
       its identity                                garbage_is_never_kept
    4. over budget reported as None             -> over_budget_is_unavailable_never_none
    5. (R5) acquire defaults an unread address  -> acquired_bytes_are_stored,
       (`| none => some 0` in `acquire`)           silence_acquires_nothing
    6. (R6) `and` reads Unavailable as Valid     -> unavailable_stops_the_producer,
       (`| .unavailable, v => v` in `Verdict.and`)  the_producer_proceeds_only_on_valid
  Run: `lean -DwarningAsError=true DSMSofiStorage.lean`
-/

namespace DSMSofiStorage

/-- The hash: injective on its input list (collision resistance as its
protocol-level consequence; the same axiom as `domain_hash_injective`
elsewhere). -/
structure Hash where
  H : List Nat → Nat
  H_inj : ∀ a b, H a = H b → a = b

variable (h : Hash)

/-- `inner(ns, p) = H(ns; p)` and `addr(ns, p) = H(storage-object; ns ‖ inner)`. -/
def inner (ns p : Nat) : Nat := h.H [1, ns, p]
def addr (ns p : Nat) : Nat := h.H [0, ns, inner h ns p]

theorem addr_inj {ns₁ p₁ ns₂ p₂ : Nat} (e : addr h ns₁ p₁ = addr h ns₂ p₂) :
    ns₁ = ns₂ ∧ p₁ = p₂ := by
  unfold addr at e
  have o := h.H_inj _ _ e
  simp only [List.cons.injEq] at o
  obtain ⟨_, hns, hin, _⟩ := o
  unfold inner at hin
  have i := h.H_inj _ _ hin
  simp only [List.cons.injEq] at i
  exact ⟨hns, i.2.2.1⟩

-- ── §10 Stored ─────────────────────────────────────────────────────────────

/-- What one member answered: a `(namespace, payload)` tuple, or nothing
(absent, unreachable, malformed — all the same to the fact). -/
def Read := Option (Nat × Nat)

/-- The payload of an answer that re-hashes to `a`, or nothing. The only
admission of a member's answer. -/
def counts (a : Nat) : Read → Option Nat
  | some (ns, p) => if addr h ns p = a then some p else none
  | none => none

/-- The counted payloads of a read list. -/
def counted (a : Nat) : List Read → List Nat
  | [] => []
  | r :: rs => match counts h a r with
    | some p => p :: counted a rs
    | none => counted a rs

/-- `Stored`: at least three members returned bytes that re-hash to `a`; the
fact carries the first counted payload. -/
def stored (a : Nat) (reads : List Read) : Option Nat :=
  match counted h a reads with
  | p :: rest => if 3 ≤ (p :: rest).length then some p else none
  | [] => none

theorem counts_some {a : Nat} {r : Read} {p : Nat} (hc : counts h a r = some p) :
    ∃ ns, r = some (ns, p) ∧ addr h ns p = a := by
  match r with
  | none => simp [counts] at hc
  | some (ns, q) =>
    simp only [counts] at hc
    split at hc
    · rename_i he
      exact ⟨ns, by simp_all, by simp_all⟩
    · cases hc

theorem counted_mem {a : Nat} : ∀ {reads : List Read} {p : Nat},
    p ∈ counted h a reads → ∃ r ∈ reads, counts h a r = some p := by
  intro reads
  induction reads with
  | nil => intro p hp; simp [counted] at hp
  | cons r rs ih =>
    intro p hp
    simp only [counted] at hp
    split at hp
    · rename_i q hq
      cases hp with
      | head => exact ⟨r, List.mem_cons_self .., hq⟩
      | tail _ hm =>
        obtain ⟨r', hr', hc⟩ := ih hm
        exact ⟨r', List.mem_cons_of_mem _ hr', hc⟩
    · obtain ⟨r', hr', hc⟩ := ih hp
      exact ⟨r', List.mem_cons_of_mem _ hr', hc⟩

/-- The fact's bytes re-hash to the address that was read. -/
theorem stored_returns_exact_bytes {a : Nat} {reads : List Read} {p : Nat}
    (hs : stored h a reads = some p) : ∃ ns, addr h ns p = a := by
  unfold stored at hs
  split at hs
  · rename_i q rest hq
    split at hs
    · have hp : q = p := Option.some.inj hs
      have hm : q ∈ counted h a reads := by rw [hq]; exact List.mem_cons_self ..
      obtain ⟨_, _, hc⟩ := counted_mem h hm
      obtain ⟨ns, _, ha⟩ := counts_some h hc
      exact ⟨ns, hp ▸ ha⟩
    · cases hs
  · cases hs

/-- Any two counted answers carry the same payload. -/
theorem counting_reads_agree {a : Nat} {r₁ r₂ : Read} {p₁ p₂ : Nat}
    (h₁ : counts h a r₁ = some p₁) (h₂ : counts h a r₂ = some p₂) : p₁ = p₂ := by
  obtain ⟨ns₁, _, e₁⟩ := counts_some h h₁
  obtain ⟨ns₂, _, e₂⟩ := counts_some h h₂
  exact (addr_inj h (e₁.trans e₂.symm)).2

/-- Bytes that do not derive the address are nothing. -/
theorem wrong_bytes_never_count {a ns p : Nat} (hne : addr h ns p ≠ a) :
    counts h a (some (ns, p)) = none := by
  simp [counts, hne]

/-- The address binds the namespace: the same payload under another
namespace is another address, so it is nothing under this one. -/
theorem a_wrong_namespace_never_counts {ns ns' p : Nat} (hne : ns' ≠ ns) :
    counts h (addr h ns p) (some (ns', p)) = none := by
  apply wrong_bytes_never_count
  intro e
  exact hne (addr_inj h e).1

/-- Fewer than three counted answers is not `Stored`. -/
theorem two_members_is_not_stored {a : Nat} {reads : List Read}
    (hlt : (counted h a reads).length < 3) : stored h a reads = none := by
  unfold stored
  split
  · rename_i q rest hq
    rw [hq] at hlt
    rw [if_neg (Nat.not_le.mpr hlt)]
  · rfl

/-- An unreachable or absent answer is not bytes. -/
theorem silence_never_counts {a : Nat} : counts h a none = none := rfl

-- ── §11 the index ──────────────────────────────────────────────────────────

/-- What a scan established. -/
inductive Resolved (α : Type) where
  | kept (o : α)
  | none
  | unavailable
  deriving DecidableEq

/-- Recognition: from bytes, the object and the identity Core recomputes
from them — or nothing. -/
structure Recognizer (α : Type) where
  recognize : Nat → Option (Nat × α)

/-- Keep the first candidate whose bytes are Stored (`some`) and whose
recomputed identity is the locator; examining a candidate spends one unit of
budget; running out of budget is Unavailable. -/
def keep {α : Type} (R : Recognizer α) (L : Nat) :
    List (Option Nat) → Nat → Resolved α
  | [], _ => .none
  | _ :: _, 0 => .unavailable
  | none :: cs, b + 1 => keep R L cs b
  | some bytes :: cs, b + 1 =>
    match R.recognize bytes with
    | some (id, o) => if id = L then .kept o else keep R L cs b
    | none => keep R L cs b

/-- What is kept recomputes to the locator and is one of the candidates. -/
theorem kept_verifies {α : Type} (R : Recognizer α) (L : Nat) :
    ∀ (cs : List (Option Nat)) (b : Nat) (o : α), keep R L cs b = .kept o →
      ∃ bytes, some bytes ∈ cs ∧ R.recognize bytes = some (L, o) := by
  intro cs
  induction cs with
  | nil => intro b o hk; cases b <;> simp [keep] at hk
  | cons c cs ih =>
    intro b o hk
    cases b with
    | zero => simp [keep] at hk
    | succ b =>
      match c with
      | none =>
        obtain ⟨bytes, hm, hr⟩ := ih b o (by simpa [keep] using hk)
        exact ⟨bytes, List.mem_cons_of_mem _ hm, hr⟩
      | some bytes =>
        simp only [keep] at hk
        split at hk
        · rename_i id o' hrec
          split at hk
          · rename_i hid
            have ho : o' = o := by cases hk; rfl
            subst ho; subst hid
            exact ⟨bytes, List.mem_cons_self .., hrec⟩
          · obtain ⟨bytes', hm, hr⟩ := ih b o hk
            exact ⟨bytes', List.mem_cons_of_mem _ hm, hr⟩
        · obtain ⟨bytes', hm, hr⟩ := ih b o hk
          exact ⟨bytes', List.mem_cons_of_mem _ hm, hr⟩

/-- Nothing under the locator verifies ⇒ nothing is kept. -/
theorem garbage_is_never_kept {α : Type} (R : Recognizer α) (L : Nat)
    (cs : List (Option Nat)) (b : Nat)
    (hg : ∀ bytes o, some bytes ∈ cs → R.recognize bytes ≠ some (L, o)) :
    ∀ o, keep R L cs b ≠ .kept o := by
  intro o hk
  obtain ⟨bytes, hm, hr⟩ := kept_verifies R L cs b o hk
  exact hg bytes o hm hr

/-- Running out of budget before a verifying candidate is Unavailable, never
None: with no budget and a candidate left, the scan says so. -/
theorem over_budget_is_unavailable_never_none {α : Type} (R : Recognizer α) (L : Nat)
    (c : Option Nat) (cs : List (Option Nat)) :
    keep R L (c :: cs) 0 = .unavailable := by
  simp [keep]

/-- Every candidate examined within the budget, none verifying, is None. -/
theorem within_budget_exhausted_is_none {α : Type} (R : Recognizer α) (L : Nat) :
    ∀ (cs : List (Option Nat)) (b : Nat), cs.length ≤ b →
      (∀ bytes o, some bytes ∈ cs → R.recognize bytes ≠ some (L, o)) →
      keep R L cs b = .none := by
  intro cs
  induction cs with
  | nil => intro b _ _; cases b <;> rfl
  | cons c cs ih =>
    intro b hlen hg
    cases b with
    | zero => simp at hlen
    | succ b =>
      have hlen' : cs.length ≤ b := Nat.le_of_succ_le_succ hlen
      have hg' : ∀ bytes o, some bytes ∈ cs → R.recognize bytes ≠ some (L, o) :=
        fun bytes o hm => hg bytes o (List.mem_cons_of_mem _ hm)
      match c with
      | none => simpa [keep] using ih b hlen' hg'
      | some bytes =>
        simp only [keep]
        split
        · rename_i id o hrec
          split
          · rename_i hid
            subst hid
            exact absurd hrec (hg bytes o (List.mem_cons_self ..))
          · exact ih b hlen' hg'
        · exact ih b hlen' hg'


-- ── §13 acquisition — rebuild step R5 ─────────────────────────────────────

/-- Evidence, as Core holds it: bytes by address, or nothing. Production code
builds it only by acquisition (`Evidence::acquired` at the end of
`sdk::sofi_evidence::acquire_evidence`); `Default` exists only under
`cfg(test)` (gate G2). -/
def Evidence := Nat → Option Nat

/-- Acquisition: for every address a preimage needs, the Stored bytes at that
address, and nothing else. An address that is not needed, or whose bytes are
not Stored, is absent — never filled in. -/
def acquire (needs : List Nat) (reads : Nat → List Read) : Evidence :=
  fun a => if a ∈ needs then stored h a (reads a) else none

/-- What a check needs, three-valued: an absent item is Unavailable, never
Invalid, and never a value. -/
inductive Verdict where
  | valid
  | invalid
  | unavailable
  deriving DecidableEq

def need (item : Option Nat) (check : Nat → Verdict) : Verdict :=
  match item with
  | some p => check p
  | none => .unavailable

/-- Every acquired item is Stored at its address: acquisition adds nothing a
member did not return three times over. -/
theorem acquired_bytes_are_stored {needs : List Nat} {reads : Nat → List Read} {a p : Nat}
    (hq : acquire h needs reads a = some p) : stored h a (reads a) = some p := by
  unfold acquire at hq
  split at hq
  · exact hq
  · exact Option.noConfusion hq

/-- Nothing is defaulted: with nothing needed, or nothing read, the evidence
holds nothing. -/
theorem nothing_is_defaulted (reads : Nat → List Read) (a : Nat) :
    acquire h [] reads a = none := by
  simp [acquire]

theorem silence_acquires_nothing (needs : List Nat) (a : Nat) :
    acquire h needs (fun _ => []) a = none := by
  unfold acquire
  split
  · rfl
  · rfl

/-- Missing evidence is Unavailable, never Invalid: a check over an item the
acquisition did not fetch cannot refuse the operation. -/
theorem missing_evidence_is_unavailable_never_invalid (ev : Evidence) (a : Nat)
    (check : Nat → Verdict) (hm : ev a = none) : need (ev a) check = .unavailable := by
  simp [need, hm]

/-- And a fetched item is judged by its check alone: acquisition decides
nothing. -/
theorem acquisition_decides_nothing (ev : Evidence) (a p : Nat) (check : Nat → Verdict)
    (hp : ev a = some p) : need (ev a) check = check p := by
  simp [need, hp]


-- ── §13 the producer, rebuild step R6 ──────────────────────────────────────

/-- The three-valued conjunction of `sofi::conformance::Validation::and`: any
Invalid is Invalid; otherwise any Unavailable is Unavailable; otherwise
Valid. -/
def Verdict.and : Verdict → Verdict → Verdict
  | .invalid, _ => .invalid
  | _, .invalid => .invalid
  | .unavailable, _ => .unavailable
  | _, .unavailable => .unavailable
  | .valid, .valid => .valid

/-- Rule T5: a producer proceeds on Valid and on nothing else. -/
def proceeds : Verdict → Bool
  | .valid => true
  | _ => false

/-- `invalid_dominates_and_unavailable_never_becomes_invalid` (Rust,
`sofi::conformance`): missing evidence never masks a refusal, and is never
read as one. -/
theorem invalid_dominates_and_unavailable_never_becomes_invalid :
    Verdict.and .unavailable .invalid = .invalid ∧
    Verdict.and .invalid .unavailable = .invalid ∧
    Verdict.and .valid .unavailable = .unavailable ∧
    Verdict.and .unavailable .valid = .unavailable := by
  refine ⟨rfl, rfl, rfl, rfl⟩

/-- Unavailable stops the producer: no conjunction containing it is Valid,
whatever the other conjuncts say. -/
theorem unavailable_stops_the_producer (v : Verdict) :
    proceeds (Verdict.and .unavailable v) = false ∧
    proceeds (Verdict.and v .unavailable) = false := by
  cases v <;> exact ⟨rfl, rfl⟩

/-- Missing evidence never hides a refusal: with an item unfetched, a check
that is Invalid keeps the whole verdict Invalid — the producer refuses for the
reason, not for the gap. -/
theorem missing_evidence_never_hides_a_refusal (ev : Evidence) (a : Nat)
    (check : Nat → Verdict) (hm : ev a = none) :
    Verdict.and (need (ev a) check) .invalid = .invalid := by
  simp [need, hm, Verdict.and]

/-- And only a conjunction of Valid verdicts lets the producer proceed. -/
theorem the_producer_proceeds_only_on_valid (u v : Verdict) :
    proceeds (Verdict.and u v) = true ↔ u = .valid ∧ v = .valid := by
  cases u <;> cases v <;> simp [Verdict.and, proceeds]

#print axioms stored_returns_exact_bytes
#print axioms counting_reads_agree
#print axioms wrong_bytes_never_count
#print axioms a_wrong_namespace_never_counts
#print axioms two_members_is_not_stored
#print axioms silence_never_counts
#print axioms kept_verifies
#print axioms garbage_is_never_kept
#print axioms over_budget_is_unavailable_never_none
#print axioms within_budget_exhausted_is_none
#print axioms acquired_bytes_are_stored
#print axioms nothing_is_defaulted
#print axioms missing_evidence_is_unavailable_never_invalid
#print axioms unavailable_stops_the_producer
#print axioms the_producer_proceeds_only_on_valid

end DSMSofiStorage
