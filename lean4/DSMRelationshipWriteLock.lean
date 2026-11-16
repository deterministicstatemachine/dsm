/-
  DSM Relationship Write Lock (DSM Amendments A34 and A37) — self-contained
  Lean 4 (no Mathlib, no imports)

  Every write a storage node takes into an inbox carries a proof: the lock
  the inbox is bound to, the lock's grant of a write key, and the write key's
  signature over the address, the message id and the envelope. Every node
  runs the same check on it (`dsm::core::relationship_write_grant::
  verify_spool_write`, then the node's append), and nothing else:

  * Every inbox is a route bound to one lock. A write is taken there only
    when the address IS that route bound to the write's lock, the lock signed
    the grant, and the granted key signed the write. The node keeps no state
    for any inbox: the check is derivation alone.
  * A relationship's FIRST inbox is its route bound to the writer's
    first-inbox lock, the key the writer's directory entry publishes, lock
    and write key at once (DSM Amendment A37). Every LATER inbox is its route
    bound to the recipient's write lock (DSM Amendment A34).

  This module is that check, and what it proves:

    1. `write_is_granted` — a write taken at the inbox bound to lock `L` is
       signed by a key `L` granted; with `granted_keys_only`, by a key `L`'s
       holder issued a grant to.
    2. `address_binds_its_lock` — a write under any other lock is refused at
       the inbox bound to `L`, however it is signed.
    3. `first_inbox_takes_only_its_writer` — at a first inbox, bound to the
       writer's first-inbox lock `F`, a write is taken only when `F` signed
       it; a third party who computes the address from public bytes and signs
       with a key of its own is refused.
    4. `no_write_closes_an_inbox` — whatever any sequence of writes did
       before, the writer's own write at its first inbox is taken: no write
       of anyone's, arriving first or not, fixes or moves anything.
    5. `addresses_bind_route_and_lock` — two inboxes of different routes or
       locks are different addresses.
    6. `ended_relationship_takes_nothing_in` — once a relationship has ended
       and nothing on it is awaited, its recipient reads none of its inboxes,
       so a write a node takes there under a grant still held reaches no one.

  Assumptions, as the model states them (the CLAIM_TRACE row names them):
  addresses are domain-separated BLAKE3 digests, modeled as an injective
  constructor (collision resistance); a grant names the lock that signed it
  and a write the key that signed it only if those keys signed them (SPHINCS+
  EUF-CMA), modeled by a write's `grantSigner` and `signer` fields being the
  keys that verified.

  Correspondence (Rust ↔ Lean):
    `locked_inbox_address`                         ↔ `Addr.mk`
    `SpoolWriteV1` as `verify_spool_write` reads it ↔ `Write`
    `verify_spool_write`                           ↔ `accept`
    `self_granted_spool_write` under the lock      ↔ `ownWrite`
    `reads_nothing_more_from` (the wallet's poll)  ↔ `reads`

  This module contains zero `axiom`, `opaque` and `sorry` declarations.
-/

namespace DSMRelationshipWriteLock

/-- A public key (a lock, or a write key). -/
abbrev Key := Nat

/-- An inbox route: the recipient's genesis, device and the relationship's tip. -/
abbrev Route := Nat

/-- An inbox address: a route bound to a lock. -/
structure Addr where
  route : Route
  lock : Key
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

/-- The node's check of `w` at `a`. It reads nothing but the two. -/
def accept (a : Addr) (w : Write) : Bool :=
  decide (a.route = w.route) && decide (a.lock = w.lock) && decide (w.grantSigner = w.lock)
    && decide (w.signer = w.grantedKey)

/-- Theorem 1: a write taken at the inbox bound to lock `l` is signed by a
key `l` granted. -/
theorem write_is_granted (r : Route) (l : Key) (w : Write)
    (h : accept ⟨r, l⟩ w = true) :
    w.lock = l ∧ w.grantSigner = l ∧ w.signer = w.grantedKey := by
  simp [accept] at h
  obtain ⟨⟨⟨_, hl⟩, hg⟩, hs⟩ := h
  exact ⟨hl.symm, hg.trans hl.symm, hs⟩

/-- Theorem 1, with the lock holder's grants: when the only grants lock `l`
ever signed are of keys in `issued` (EUF-CMA: nobody else can sign one),
every write taken at the inbox bound to `l` is signed by an issued key. -/
theorem granted_keys_only (issued : Key → Prop) (r : Route) (l : Key) (w : Write)
    (unforgeable : w.grantSigner = l → issued w.grantedKey)
    (h : accept ⟨r, l⟩ w = true) :
    issued w.signer := by
  obtain ⟨_, hg, hs⟩ := write_is_granted r l w h
  rw [hs]
  exact unforgeable hg

/-- Theorem 2: a write under any other lock is refused at the inbox bound to
`l`, however it is signed. -/
theorem address_binds_its_lock (r : Route) (l : Key) (w : Write) (other : w.lock ≠ l) :
    accept ⟨r, l⟩ w = false := by
  cases h : accept ⟨r, l⟩ w with
  | false => rfl
  | true => exact absurd (write_is_granted r l w h).1 other

/-- The writer's own write at route `r` under its first-inbox lock `f`: lock
and write key at once, granting itself. -/
def ownWrite (r : Route) (f : Key) : Write :=
  { route := r, lock := f, grantedKey := f, grantSigner := f, signer := f }

/-- Theorem 3: at a first inbox, bound to the writer's first-inbox lock `f`,
a write is taken only when `f` signed it, when `f`'s holder issued no grant
but its own (a first-inbox lock grants only itself). -/
theorem first_inbox_takes_only_its_writer (r : Route) (f : Key) (w : Write)
    (selfOnly : w.grantSigner = f → w.grantedKey = f)
    (h : accept ⟨r, f⟩ w = true) :
    w.signer = f := by
  obtain ⟨_, hg, hs⟩ := write_is_granted r f w h
  rw [hs]
  exact selfOnly hg

/-- What a node did with a sequence of writes, each at its address: the
writes it took, in order. -/
def takeAll : List (Addr × Write) → List (Addr × Write)
  | [] => []
  | (a, w) :: rest => if accept a w then (a, w) :: takeAll rest else takeAll rest

/-- Theorem 4: whatever any sequence of writes did before, the writer's own
write at its first inbox is taken. The check reads no history, so no write,
first or not, closes an inbox to the key it is bound to. -/
theorem no_write_closes_an_inbox (before : List (Addr × Write)) (r : Route) (f : Key) :
    takeAll (before ++ [(⟨r, f⟩, ownWrite r f)]) = takeAll before ++ [(⟨r, f⟩, ownWrite r f)] := by
  induction before with
  | nil => simp [takeAll, accept, ownWrite]
  | cons aw rest ih =>
    obtain ⟨a, w⟩ := aw
    by_cases h : accept a w = true
    · simp [takeAll, h, ih]
    · simp [takeAll, h, ih]

/-- Theorem 5: inboxes of different routes or locks are different addresses. -/
theorem addresses_bind_route_and_lock (r r' : Route) (l l' : Key)
    (h : (⟨r, l⟩ : Addr) = ⟨r', l'⟩) : r = r' ∧ l = l' := by
  cases h
  exact ⟨rfl, rfl⟩

/-- Whether a recipient reads a relationship's inboxes: always, until the
relationship has ended with nothing on it awaited. -/
def reads (ended awaited : Bool) : Bool :=
  !ended || awaited

/-- A write is taken in when a node accepts it and its recipient reads the
inbox. -/
def takenIn (a : Addr) (w : Write) (ended awaited : Bool) : Bool :=
  accept a w && reads ended awaited

/-- Theorem 6: once a relationship has ended and nothing on it is awaited, no
write at any of its inboxes is taken in, whatever a node accepts. -/
theorem ended_relationship_takes_nothing_in (a : Addr) (w : Write) :
    takenIn a w true false = false := by
  simp [takenIn, reads]

/-- And while it is live, or something on it is awaited, a write a node
accepts is read: the rule takes nothing from a live relationship. -/
theorem live_relationship_reads_what_is_accepted (a : Addr) (w : Write)
    (ended awaited : Bool) (live : ended = false ∨ awaited = true)
    (h : accept a w = true) :
    takenIn a w ended awaited = true := by
  cases live with
  | inl e => simp [takenIn, reads, e, h]
  | inr aw => simp [takenIn, reads, aw, h]

/-! Non-vacuity: each check takes a write that meets it, so no theorem above
holds only because nothing is ever accepted. -/

/-- A write under lock 7, granted and signed by key 9, at route 3. -/
def grantedWrite : Write := { route := 3, lock := 7, grantedKey := 9, grantSigner := 7, signer := 9 }

theorem a_granted_write_is_taken : accept ⟨3, 7⟩ grantedWrite = true := by
  decide

theorem a_first_write_is_taken : accept ⟨3, 5⟩ (ownWrite 3 5) = true := by
  decide

/-- A third party's own key 6, self-granted, at the first inbox bound to 5. -/
theorem a_third_party_is_refused_at_a_first_inbox : accept ⟨3, 5⟩ (ownWrite 3 6) = false := by
  decide

/-- The writer's write is still taken after the third party's came first. -/
theorem the_writer_is_taken_after_a_third_party :
    takeAll [(⟨3, 5⟩, ownWrite 3 6), (⟨3, 5⟩, ownWrite 3 5)] = [(⟨3, 5⟩, ownWrite 3 5)] := by
  decide

end DSMRelationshipWriteLock
