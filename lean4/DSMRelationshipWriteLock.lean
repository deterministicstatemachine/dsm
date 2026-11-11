/-
  DSM Relationship Write Lock (DSM Amendment A34) — self-contained Lean 4
  (no Mathlib, no imports)

  Every write a storage node takes into an inbox carries a proof: the lock
  the inbox is bound to, the lock's grant of a write key, and the write key's
  signature over the address, the message id and the envelope. Every node
  runs the same check on it (`dsm::core::relationship_write_grant::
  verify_spool_write`, then the node's store), and nothing else:

  * A relationship's FIRST inbox is the open address of its route. The first
    write there fixes its key, the writer's own (lock and write key at once);
    every later write there must be under that key. A fixed key never moves.
  * Every LATER inbox is the route bound to the recipient's lock. A write is
    taken there only when the address IS that route bound to the write's
    lock, the lock signed the grant, and the granted key signed the write.
    The node keeps no state for it: the check is derivation alone.

  This module is that check, and what it proves:

    1. `locked_write_is_granted` — a write taken at the inbox bound to lock
       `L` is signed by a key `L` granted; with `granted_keys_only`, by a key
       the recipient issued a grant to.
    2. `locked_check_is_stateless` — at a lock-bound inbox every node decides
       the same, whatever it holds: no arrival order, no node's state, no
       node's discretion.
    3. `locked_address_binds_its_lock` — a write under any other lock is
       refused at the inbox bound to `L`, however it is signed.
    4. `open_first_write_fixes` and `open_refuses_another_key` — the first
       write at an open inbox fixes its key; a write under another key is
       refused there from then on.
    5. `fixed_key_never_moves` — over any sequence of writes, a key fixed at
       an open inbox stays fixed: "The key cannot be removed or moved."
    6. `open_and_locked_never_meet` — no address is both a first inbox and a
       lock-bound one, and two lock-bound inboxes of different locks or
       routes are different addresses.
    7. `ended_relationship_takes_nothing_in` — once a relationship has ended
       and nothing on it is awaited, its recipient reads none of its inboxes,
       so a write a node takes there under a grant still held reaches no one.

  Assumptions, as the model states them (the CLAIM_TRACE row names them):
  addresses are domain-separated BLAKE3 digests, modeled as distinct
  constructors (collision resistance); a grant names the lock that signed it
  and a write the key that signed it only if those keys signed them (SPHINCS+
  EUF-CMA), modeled by a write's `grantSigner` and `signer` fields being the
  keys that verified.

  Correspondence (Rust ↔ Lean):
    `open_inbox_address` / `locked_inbox_address`  ↔ `Addr.first` / `Addr.locked`
    `SpoolWriteV1` as `verify_spool_write` reads it ↔ `Write`
    `verify_spool_write` + the node's `spool_key`  ↔ `accept`
    `spool_insert_locked` fixing the key           ↔ `apply`
    `reads_nothing_more_from` (the wallet's poll)  ↔ `reads`

  This module contains zero `axiom`, `opaque` and `sorry` declarations.
-/

namespace DSMRelationshipWriteLock

/-- A public key (a lock, or a write key). -/
abbrev Key := Nat

/-- An inbox route: the recipient's genesis, device and the relationship's tip. -/
abbrev Route := Nat

/-- An inbox address: the open address of a route (a relationship's first
inbox), or a route bound to a lock (every later one). -/
inductive Addr where
  | first (route : Route)
  | locked (route : Route) (lock : Key)
  deriving DecidableEq, Repr

/-- A write as a node reads it: the route it claims, the lock it carries, the
key the lock's grant names and the key that signed that grant, and the key
that signed the write. -/
structure Write where
  route : Route
  lock : Key
  grantedKey : Key
  grantSigner : Key
  signer : Key
  deriving DecidableEq, Repr

/-- What a node holds: the key fixed at each first inbox, if any. -/
abbrev Fixed := Route → Option Key

/-- The node's check of `w` at `a`. -/
def accept (fixed : Fixed) (a : Addr) (w : Write) : Bool :=
  match a with
  | .locked r l =>
      decide (r = w.route) && decide (l = w.lock) && decide (w.grantSigner = w.lock)
        && decide (w.signer = w.grantedKey)
  | .first r =>
      decide (r = w.route) && decide (w.grantSigner = w.lock)
        && decide (w.grantedKey = w.lock) && decide (w.signer = w.lock)
        && (match fixed r with
            | none => true
            | some k => decide (k = w.lock))

/-- What a node holds after taking `w` at `a`: a first inbox's key is fixed
by its first write; nothing else changes. -/
def apply (fixed : Fixed) (a : Addr) (w : Write) : Fixed :=
  match a with
  | .locked _ _ => fixed
  | .first r =>
      if accept fixed a w then
        fun r' => if r' = r then (match fixed r with
                                  | none => some w.lock
                                  | some k => some k)
                  else fixed r'
      else fixed

/-- Theorem 1: a write taken at the inbox bound to lock `l` is signed by a
key `l` granted. -/
theorem locked_write_is_granted (fixed : Fixed) (r : Route) (l : Key) (w : Write)
    (h : accept fixed (.locked r l) w = true) :
    w.lock = l ∧ w.grantSigner = l ∧ w.signer = w.grantedKey := by
  simp [accept] at h
  obtain ⟨⟨⟨_, hl⟩, hg⟩, hs⟩ := h
  exact ⟨hl.symm, hg.trans hl.symm, hs⟩

/-- Theorem 1, with the recipient's grants: when the only grants lock `l`
ever signed are of keys in `issued` (EUF-CMA: nobody else can sign one),
every write taken at the inbox bound to `l` is signed by an issued key. -/
theorem granted_keys_only (issued : Key → Prop) (fixed : Fixed) (r : Route) (l : Key)
    (w : Write)
    (unforgeable : w.grantSigner = l → issued w.grantedKey)
    (h : accept fixed (.locked r l) w = true) :
    issued w.signer := by
  obtain ⟨_, hg, hs⟩ := locked_write_is_granted fixed r l w h
  rw [hs]
  exact unforgeable hg

/-- Theorem 2: at a lock-bound inbox every node decides the same, whatever it
holds. -/
theorem locked_check_is_stateless (f₁ f₂ : Fixed) (r : Route) (l : Key) (w : Write) :
    accept f₁ (.locked r l) w = accept f₂ (.locked r l) w := by
  simp [accept]

/-- Taking a write at a lock-bound inbox changes nothing a node holds. -/
theorem locked_write_keeps_state (fixed : Fixed) (r : Route) (l : Key) (w : Write) :
    apply fixed (.locked r l) w = fixed := by
  simp [apply]

/-- Theorem 3: a write under any other lock is refused at the inbox bound to
`l`, however it is signed. -/
theorem locked_address_binds_its_lock (fixed : Fixed) (r : Route) (l : Key) (w : Write)
    (other : w.lock ≠ l) :
    accept fixed (.locked r l) w = false := by
  cases h : accept fixed (.locked r l) w with
  | false => rfl
  | true => exact absurd (locked_write_is_granted fixed r l w h).1 other

/-- Theorem 4a: the first write taken at an open inbox fixes its key. -/
theorem open_first_write_fixes (fixed : Fixed) (r : Route) (w : Write)
    (empty : fixed r = none) (h : accept fixed (.first r) w = true) :
    apply fixed (.first r) w r = some w.lock := by
  simp [apply, h, empty]

/-- Theorem 4b: once a key is fixed at an open inbox, a write under another
key is refused there. -/
theorem open_refuses_another_key (fixed : Fixed) (r : Route) (k : Key) (w : Write)
    (held : fixed r = some k) (other : w.lock ≠ k) :
    accept fixed (.first r) w = false := by
  cases h : accept fixed (.first r) w with
  | false => rfl
  | true =>
    simp [accept, held] at h
    exact absurd h.2.symm other

/-- One write's effect keeps a fixed key where it is. -/
theorem apply_keeps_fixed (fixed : Fixed) (a : Addr) (w : Write) (r : Route) (k : Key)
    (held : fixed r = some k) :
    apply fixed a w r = some k := by
  cases a with
  | locked _ _ => simpa [apply] using held
  | first r₀ =>
    unfold apply
    split
    · by_cases hr : r = r₀
      · subst hr; simp [held]
      · simp [hr, held]
    · exact held

/-- A sequence of writes, each at its address, applied in order. -/
def applyAll : Fixed → List (Addr × Write) → Fixed
  | fixed, [] => fixed
  | fixed, (a, w) :: rest => applyAll (apply fixed a w) rest

/-- Theorem 5: a key fixed at an open inbox never moves, over any sequence of
writes. -/
theorem fixed_key_never_moves (writes : List (Addr × Write)) :
    ∀ (fixed : Fixed) (r : Route) (k : Key), fixed r = some k →
      applyAll fixed writes r = some k := by
  induction writes with
  | nil => intro fixed r k h; exact h
  | cons aw rest ih =>
    intro fixed r k h
    obtain ⟨a, w⟩ := aw
    exact ih (apply fixed a w) r k (apply_keeps_fixed fixed a w r k h)

/-- Theorem 6: no first inbox is a lock-bound one, and lock-bound inboxes of
different routes or locks are different addresses. -/
theorem open_and_locked_never_meet (r r' : Route) (l l' : Key) :
    Addr.first r ≠ Addr.locked r' l' ∧
      (Addr.locked r l = Addr.locked r' l' → r = r' ∧ l = l') := by
  refine ⟨fun h => Addr.noConfusion h, fun h => ?_⟩
  cases h
  exact ⟨rfl, rfl⟩

/-- Whether a recipient reads a relationship's inboxes: always, until the
relationship has ended with nothing on it awaited. -/
def reads (ended awaited : Bool) : Bool :=
  !ended || awaited

/-- A write is taken in when a node accepts it and its recipient reads the
inbox. -/
def takenIn (fixed : Fixed) (a : Addr) (w : Write) (ended awaited : Bool) : Bool :=
  accept fixed a w && reads ended awaited

/-- Theorem 7: once a relationship has ended and nothing on it is awaited, no
write at any of its inboxes is taken in, whatever a node accepts. -/
theorem ended_relationship_takes_nothing_in (fixed : Fixed) (a : Addr) (w : Write) :
    takenIn fixed a w true false = false := by
  simp [takenIn, reads]

/-- And while it is live, or something on it is awaited, a write a node
accepts is read: the rule takes nothing from a live relationship. -/
theorem live_relationship_reads_what_is_accepted (fixed : Fixed) (a : Addr) (w : Write)
    (ended awaited : Bool) (live : ended = false ∨ awaited = true)
    (h : accept fixed a w = true) :
    takenIn fixed a w ended awaited = true := by
  cases live with
  | inl e => simp [takenIn, reads, e, h]
  | inr aw => simp [takenIn, reads, aw, h]

/-! Non-vacuity: each check takes a write that meets it, so no theorem above
holds only because nothing is ever accepted. -/

/-- A write under lock 7, granted and signed by key 9, at route 3. -/
def grantedWrite : Write := { route := 3, lock := 7, grantedKey := 9, grantSigner := 7, signer := 9 }

/-- A writer's own key 5, lock and write key at once, at route 3. -/
def firstWrite : Write := { route := 3, lock := 5, grantedKey := 5, grantSigner := 5, signer := 5 }

theorem a_granted_write_is_taken : accept (fun _ => none) (.locked 3 7) grantedWrite = true := by
  decide

theorem a_first_write_is_taken : accept (fun _ => none) (.first 3) firstWrite = true := by
  decide

theorem the_same_key_is_taken_again :
    accept (apply (fun _ => none) (.first 3) firstWrite) (.first 3) firstWrite = true := by
  decide

theorem another_key_is_refused_after_the_first :
    accept (apply (fun _ => none) (.first 3) firstWrite) (.first 3)
      { firstWrite with lock := 6, grantedKey := 6, grantSigner := 6, signer := 6 } = false := by
  decide

end DSMRelationshipWriteLock
