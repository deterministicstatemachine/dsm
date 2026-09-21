/-
  SoFi successor cells — leader-first resolution — and the attempt walk;
  self-contained Lean 4 (no Mathlib, no imports)
  Machine-checks the storage and walk layer of the market settlement
  (Part II §7/§8, `sofi::arith::resolve`; §23, `sofi::resolution`) and its
  fault model:
    - KEEPS EVERYTHING  a member keeps every value it is given for a key, in
                        arrival order; a put never refuses, replaces or compares.
                        What a member holds is a prefix of what it holds later.
    - LEADER FIRST      the writer computed the key's leader from the committed
                        set and a validated root and wrote there first, so the
                        race ends at the leader: LeaderHeld(K, x) iff x is the
                        first object naming K in the leader's read; Final(K, x)
                        iff LeaderHeld(K, x) and two other members hold x.
    - FINAL PERSISTS    a value final on a (partial) read is final on every
                        later, fuller read; one final value per key, ever.
    - LEADER-HELD       once the leader's first object is x, no other value is
      SETTLES           ever final — or leader-held — at the key: loss is
                        settled before any copy arrives.
    - NO KEY IS DEAD    an empty leader leaves the key open (one put makes any
                        value leader-held); a leader-held value becomes final
                        with two more puts. Nothing else closes a key, and
                        counting cannot: three non-leaders agreeing is not final.
    - UNKNOWN           an unread, timed-out or malformed member reply is
                        Unknown; it is never read as empty and never counts as
                        a copy — the resolution is the same as if that member
                        held nothing.
    - THE WALK          one consumer per parent across all attempts, with
                        AttemptLive load-bearing; a final leg of an impossible route
                        is skippable with no Complete premise (R7-17), and gating it
                        on Complete wedges a withheld leg; Unavailable never
                        establishes impossibility; skips are permanent; a chunked
                        walk equals one walk
    - ORDERING          no numeric holes in attempt indices; counters never wrap
    - STORAGEREACHABLE  a noncanonical DAG whose producer is (parent, E) — never the
                        attempt; reachable is not canonical
    - REGISTRATION      (R10) FulfillmentRegistered is both cells final with the root
                        on this F's own claim — a conclusion from reads, never a
                        record; a rival first at the leader settles loss; the root
                        final on another claim never registers
  Modelling premises:
    * Members are positions of the frozen five-member set; a store is the
      members' lists at ONE key. Members are read truthfully or not at all:
      an answered member reports a prefix of what it holds (F0: crash and
      omission only; no equivocation, no loss).
    * The leader is an input: the caller derives it from the seed and the
      committed set, never from availability. Nothing here says which member
      it is, only what its read decides.
    * Values (E, FulfillmentId, claims) are opaque naturals. Hashing and object
      identity are DSMSofiAtomicity's. Which values in a member's list are
      objects naming the key is the caller's question; the model is handed the
      classified digests in arrival order, as `resolve` is.
    * The walk's per-key facts (final value, validation, orphan, rival
      consumption, route outcome, the trader parent's branch) are inputs;
      `Coherent` restates what the cell layer above proves about them.
  What this module does NOT claim:
    * Semantic validity of any E, or the resolution of a trader position
      (DSMSofiAtomicity). Arm (iv) enters here as the input
      `traderParentImpossible`; WHY a trader parent is terminal is the ladder's
      business, not this module's.
    * Any member-side rule: a member decides nothing. The coupling of the
      fulfillment register `K_ful(q)` to the root register `K_root(q)` is the
      writer's rule, exercised leader first, and is not a property of the store.
    * Liveness: nothing here says a put ever lands; NO KEY IS DEAD says a key
      CAN still be closed, not that it will be.
  Mutation controls, executed rather than asserted. Each gate was removed and the
  named theorem went red — its proof rejected by the kernel:
     1. a put replaces instead of appending     -> `put_keeps_prefix`
     1b. a put refuses (leaves the store as it   -> `put_holds_what_it_was_given` (R2);
         was)                                       `put_keeps_prefix` also reddens, on its
                                                    proof's `split` over the `if` — the
                                                    prefix statement itself survives refusal
     2. finality at one copy                    -> `one_copy_is_not_final`
     3. the leader counted as its own copy      -> `one_copy_is_not_final`
     4. the leader's LAST object instead of     -> `a_later_value_at_the_leader_never_becomes_final`
        its first
     5. Unknown read as holding the value       -> `unknown_is_not_a_copy`
     6. `AttemptLive` dropped from Consumed     -> `walk_consumes_at_most_once`
        (replaced by True)                       (`attempt_live_is_load_bearing` is the
                                                  witness of what that admits and stays green)
     7. (R10) `registered` accepting a leader-  -> `registration_needs_both_finals`
        held F at K_ful
  Run: `lean -DwarningAsError=true DSMSofiSuccessorCells.lean`
-/

namespace DSMSofiSuccessorCells

abbrev Val := Nat

/-- What one member holds at one key: every object naming it, in arrival
order. A member keeps what it is given; nothing is refused, replaced or
compared. -/
abbrev Held := List Val

/-- A store: the committed members' lists at ONE key, by position in the
committed set. -/
abbrev Store := Nat → Held

def MEMBERS : Nat := 5
def FINALITY : Nat := 3

-- ── the store: puts append, nothing is ever removed ──────────────────────

/-- Put: member `i` keeps `v` after everything it already holds. -/
def putAt (i : Nat) (v : Val) (s : Store) : Store :=
  fun j => if j = i then s j ++ [v] else s j

inductive Reach : Store → Store → Prop
  | refl (s : Store) : Reach s s
  | put {s s' : Store} (i : Nat) (v : Val) : Reach s s' → Reach s (putAt i v s')

theorem Reach.trans {a b c : Store} (h1 : Reach a b) (h2 : Reach b c) : Reach a c := by
  induction h2 with
  | refl => exact h1
  | put i v _ ih => exact Reach.put i v ih

theorem prefix_refl (l : Held) : l <+: l := ⟨[], List.append_nil l⟩

theorem prefix_trans {a b c : Held} (h1 : a <+: b) (h2 : b <+: c) : a <+: c := by
  obtain ⟨t1, rfl⟩ := h1
  obtain ⟨t2, rfl⟩ := h2
  exact ⟨t1 ++ t2, by rw [List.append_assoc]⟩

/-- KEEPS EVERYTHING: what a member holds is a prefix of what it holds after
any put, anywhere. -/
theorem put_keeps_prefix (i : Nat) (v : Val) (s : Store) (j : Nat) :
    s j <+: putAt i v s j := by
  unfold putAt
  split
  · exact ⟨[v], rfl⟩
  · exact prefix_refl _

theorem reach_keeps_prefix {s s' : Store} (h : Reach s s') (j : Nat) : s j <+: s' j := by
  induction h with
  | refl => exact prefix_refl _
  | put i v _ ih => exact prefix_trans ih (put_keeps_prefix i v _ j)

/-- NEVER REFUSES (R2, Part II §12): after a put, the member holds the value it
was given — it is the last thing in its list. With `put_keeps_prefix`, what a
member holds is exactly everything it was given, in arrival order. -/
theorem put_holds_what_it_was_given (i : Nat) (v : Val) (s : Store) :
    (putAt i v s i).getLast? = some v := by
  simp [putAt]

theorem first_stable {l l' : Held} {v : Val} (hp : l <+: l') (hv : l.head? = some v) :
    l'.head? = some v := by
  obtain ⟨t, rfl⟩ := hp
  cases l with
  | nil => cases hv
  | cons x xs => simp at hv; simp [hv]

theorem mem_of_prefix {l l' : Held} {v : Val} (hp : l <+: l') (hv : v ∈ l) : v ∈ l' := by
  obtain ⟨t, rfl⟩ := hp
  exact List.mem_append_left t hv

-- ── observations: what a read of the five members establishes ────────────

/-- One member's answer at one key: the objects naming the key it holds, in
arrival order — or nothing usable. `Unknown` covers an unread member, a
timeout, and any reply that is not a well-formed list. -/
inductive Obs where
  | holds (vs : Held)
  | unknown

def holdsVal (o : Obs) (v : Val) : Bool :=
  match o with
  | .holds vs => decide (v ∈ vs)
  | .unknown => false

theorem holdsVal_holds (vs : Held) (v : Val) : holdsVal (.holds vs) v = true ↔ v ∈ vs := by
  simp [holdsVal]

/-- The first object naming the key in the leader's read, if the leader
answered and holds one. -/
def leaderFirst (obs : Nat → Obs) (leader : Nat) : Option Val :=
  match obs leader with
  | .holds vs => vs.head?
  | .unknown => none

/-- Whether member `i` counts as a copy of `v`: a member other than the
leader that holds `v`. -/
def copyAt (obs : Nat → Obs) (leader : Nat) (v : Val) (i : Nat) : Nat :=
  if i ≠ leader ∧ holdsVal (obs i) v = true then 1 else 0

/-- Members other than the leader holding `v`, over the committed set. -/
def copies (obs : Nat → Obs) (leader : Nat) (v : Val) : Nat :=
  copyAt obs leader v 0 + copyAt obs leader v 1 + copyAt obs leader v 2
    + copyAt obs leader v 3 + copyAt obs leader v 4

inductive Res where
  | final (v : Val)
  | leaderHeld (v : Val)
  | unresolved
  deriving DecidableEq, Repr

/-- `sofi::arith::resolve`. -/
def resolve (obs : Nat → Obs) (leader : Nat) : Res :=
  match leaderFirst obs leader with
  | none => .unresolved
  | some v => if FINALITY ≤ copies obs leader v + 1 then .final v else .leaderHeld v

/-- A truthful, complete read of a store. -/
def observe (s : Store) : Nat → Obs := fun i => .holds (s i)

def compatAt (o : Obs) (l : Held) : Prop :=
  match o with
  | .holds vs => vs <+: l
  | .unknown => True

/-- A read of `s`, possibly partial: every answered member reports a prefix
of what it holds. -/
def Compatible (obs : Nat → Obs) (s : Store) : Prop := ∀ i, compatAt (obs i) (s i)

theorem compatible_observe (s : Store) : Compatible (observe s) s :=
  fun i => prefix_refl (s i)

theorem compatible_reach {obs : Nat → Obs} {s s' : Store} (hc : Compatible obs s)
    (hr : Reach s s') : Compatible obs s' := by
  intro i
  have hi := hc i
  unfold compatAt at hi ⊢
  cases hobs : obs i with
  | holds vs => rw [hobs] at hi; exact prefix_trans hi (reach_keeps_prefix hr i)
  | unknown => trivial

theorem holdsVal_of_compatible {obs : Nat → Obs} {s : Store} (hc : Compatible obs s)
    (i : Nat) (v : Val) (h : holdsVal (obs i) v = true) : holdsVal (observe s i) v = true := by
  have hi := hc i
  unfold compatAt at hi
  unfold observe
  rw [holdsVal_holds]
  cases hobs : obs i with
  | holds vs =>
    rw [hobs] at h hi
    rw [holdsVal_holds] at h
    exact mem_of_prefix hi h
  | unknown => rw [hobs] at h; cases h

theorem leaderFirst_of_compatible {obs : Nat → Obs} {s : Store} (hc : Compatible obs s)
    {leader : Nat} {v : Val} (h : leaderFirst obs leader = some v) :
    leaderFirst (observe s) leader = some v := by
  unfold leaderFirst at h ⊢
  unfold observe
  cases hobs : obs leader with
  | holds vs =>
    rw [hobs] at h
    have hp : vs <+: s leader := by
      have := hc leader
      unfold compatAt at this
      rw [hobs] at this
      exact this
    exact first_stable hp h
  | unknown => rw [hobs] at h; cases h

theorem copyAt_mono {obs obs' : Nat → Obs} {leader : Nat} {v : Val}
    (h : ∀ i, holdsVal (obs i) v = true → holdsVal (obs' i) v = true) (i : Nat) :
    copyAt obs leader v i ≤ copyAt obs' leader v i := by
  unfold copyAt
  by_cases hc : i ≠ leader ∧ holdsVal (obs i) v = true
  · rw [if_pos hc, if_pos ⟨hc.1, h i hc.2⟩]; exact Nat.le_refl _
  · rw [if_neg hc]; exact Nat.zero_le _

theorem copies_mono {obs obs' : Nat → Obs} {leader : Nat} {v : Val}
    (h : ∀ i, holdsVal (obs i) v = true → holdsVal (obs' i) v = true) :
    copies obs leader v ≤ copies obs' leader v := by
  unfold copies
  have h0 := copyAt_mono (leader := leader) h 0
  have h1 := copyAt_mono (leader := leader) h 1
  have h2 := copyAt_mono (leader := leader) h 2
  have h3 := copyAt_mono (leader := leader) h 3
  have h4 := copyAt_mono (leader := leader) h 4
  omega

theorem resolve_names_leader_first {obs : Nat → Obs} {leader : Nat} {v : Val}
    (h : resolve obs leader = .final v ∨ resolve obs leader = .leaderHeld v) :
    leaderFirst obs leader = some v := by
  unfold resolve at h
  cases hlf : leaderFirst obs leader with
  | none => rw [hlf] at h; rcases h with h | h <;> cases h
  | some u =>
    rw [hlf] at h
    dsimp only at h
    by_cases hge : FINALITY ≤ copies obs leader u + 1
    · rw [if_pos hge] at h; rcases h with h | h <;> cases h; rfl
    · rw [if_neg hge] at h; rcases h with h | h <;> cases h; rfl

theorem resolve_of_leaderFirst {obs : Nat → Obs} {leader : Nat} {v : Val}
    (h : leaderFirst obs leader = some v) :
    resolve obs leader = .final v ∨ resolve obs leader = .leaderHeld v := by
  unfold resolve
  rw [h]
  dsimp only
  by_cases hge : FINALITY ≤ copies obs leader v + 1
  · rw [if_pos hge]; exact Or.inl rfl
  · rw [if_neg hge]; exact Or.inr rfl

-- ── the properties ────────────────────────────────────────────────────────

/-- FINAL PERSISTS: a value final on a (partial) read of `s` is final on the
complete read of every store reachable from `s`. -/
theorem final_persists {obs : Nat → Obs} {s s' : Store} {leader : Nat} {v : Val}
    (hc : Compatible obs s) (hr : Reach s s') (h : resolve obs leader = .final v) :
    resolve (observe s') leader = .final v := by
  have hc' := compatible_reach hc hr
  have hlf : leaderFirst obs leader = some v := resolve_names_leader_first (Or.inl h)
  have hlf' := leaderFirst_of_compatible hc' hlf
  have hmono : copies obs leader v ≤ copies (observe s') leader v :=
    copies_mono (fun i => holdsVal_of_compatible hc' i v)
  unfold resolve at h ⊢
  rw [hlf] at h
  rw [hlf']
  dsimp only at h ⊢
  by_cases hge : FINALITY ≤ copies obs leader v + 1
  · rw [if_pos (Nat.le_trans hge (Nat.add_le_add_right hmono 1))]
  · rw [if_neg hge] at h; cases h

/-- ONE FINAL VALUE, EVER: two finals at one key, however far apart in time,
agree. -/
theorem final_unique_across_time {s s' : Store} {leader : Nat} {v u : Val}
    (h1 : resolve (observe s) leader = .final v) (hr : Reach s s')
    (h2 : resolve (observe s') leader = .final u) : u = v := by
  have := final_persists (compatible_observe s) hr h1
  rw [h2] at this
  exact Res.final.inj this

/-- LEADER-HELD SETTLES: once the leader's first object is `v`, no other value
is ever final — or leader-held — at the key, whatever the other members hold
now or later. -/
theorem leader_held_excludes_others {obs : Nat → Obs} {s s' : Store} {leader : Nat} {v : Val}
    (hc : Compatible obs s) (hr : Reach s s') (h : resolve obs leader = .leaderHeld v)
    (u : Val) (hne : u ≠ v) :
    resolve (observe s') leader ≠ .final u ∧ resolve (observe s') leader ≠ .leaderHeld u := by
  have hlf : leaderFirst obs leader = some v := resolve_names_leader_first (Or.inr h)
  have hlf' := leaderFirst_of_compatible (compatible_reach hc hr) hlf
  rcases resolve_of_leaderFirst hlf' with hres | hres
  · rw [hres]; exact ⟨fun h => hne (Res.final.inj h).symm, fun h => Res.noConfusion h⟩
  · rw [hres]; exact ⟨fun h => Res.noConfusion h, fun h => hne (Res.leaderHeld.inj h).symm⟩

/-- NO KEY IS DEAD (i): an empty leader leaves the key open — one put at the
leader makes any value leader-held (or final). -/
theorem open_key_becomes_leader_held (s : Store) (leader : Nat) (hempty : s leader = [])
    (v : Val) :
    resolve (observe (putAt leader v s)) leader = .final v
      ∨ resolve (observe (putAt leader v s)) leader = .leaderHeld v := by
  apply resolve_of_leaderFirst
  simp [leaderFirst, observe, putAt, hempty]

theorem holds_after_put_self (i : Nat) (v : Val) (s : Store) :
    holdsVal (observe (putAt i v s) i) v = true := by
  unfold observe
  rw [holdsVal_holds]
  simp [putAt]

theorem holds_after_put_other {i j : Nat} (v : Val) (s : Store) (u : Val)
    (h : holdsVal (observe s j) u = true) : holdsVal (observe (putAt i v s) j) u = true := by
  unfold observe at h ⊢
  rw [holdsVal_holds] at h ⊢
  exact mem_of_prefix (put_keeps_prefix i v s j) h

/-- NO KEY IS DEAD (ii): a value the leader holds first becomes final once two
other members hold it — and among members 0, 1 and 2, two are always not the
leader. Nothing but puts is needed; nothing else can close the key. -/
theorem leader_held_becomes_final (s : Store) (leader : Nat) (v : Val)
    (h : leaderFirst (observe s) leader = some v) :
    ∃ s', Reach s s' ∧ resolve (observe s') leader = .final v := by
  let s'' := putAt 2 v (putAt 1 v (putAt 0 v s))
  have hr : Reach s s'' :=
    Reach.put 2 v (Reach.put 1 v (Reach.put 0 v (Reach.refl s)))
  refine ⟨s'', hr, ?_⟩
  have hlf : leaderFirst (observe s'') leader = some v :=
    leaderFirst_of_compatible (compatible_reach (compatible_observe s) hr) h
  have hh0 : holdsVal (observe s'' 0) v = true :=
    holds_after_put_other v _ v (holds_after_put_other v _ v (holds_after_put_self 0 v s))
  have hh1 : holdsVal (observe s'' 1) v = true :=
    holds_after_put_other v _ v (holds_after_put_self 1 v _)
  have hh2 : holdsVal (observe s'' 2) v = true := holds_after_put_self 2 v _
  have c0 : (leader = 0 ∧ copyAt (observe s'') leader v 0 = 0)
      ∨ (leader ≠ 0 ∧ copyAt (observe s'') leader v 0 = 1) := by
    unfold copyAt
    by_cases hl : leader = 0
    · left; exact ⟨hl, by rw [if_neg (fun hc => hc.1 hl.symm)]⟩
    · right; exact ⟨hl, by rw [if_pos ⟨fun hc => hl hc.symm, hh0⟩]⟩
  have c1 : (leader = 1 ∧ copyAt (observe s'') leader v 1 = 0)
      ∨ (leader ≠ 1 ∧ copyAt (observe s'') leader v 1 = 1) := by
    unfold copyAt
    by_cases hl : leader = 1
    · left; exact ⟨hl, by rw [if_neg (fun hc => hc.1 hl.symm)]⟩
    · right; exact ⟨hl, by rw [if_pos ⟨fun hc => hl hc.symm, hh1⟩]⟩
  have c2 : (leader = 2 ∧ copyAt (observe s'') leader v 2 = 0)
      ∨ (leader ≠ 2 ∧ copyAt (observe s'') leader v 2 = 1) := by
    unfold copyAt
    by_cases hl : leader = 2
    · left; exact ⟨hl, by rw [if_neg (fun hc => hc.1 hl.symm)]⟩
    · right; exact ⟨hl, by rw [if_pos ⟨fun hc => hl hc.symm, hh2⟩]⟩
  have hge : FINALITY ≤ copies (observe s'') leader v + 1 := by
    unfold copies FINALITY
    omega
  unfold resolve
  rw [hlf]
  dsimp only
  rw [if_pos hge]

/-- UNKNOWN NEVER COUNTS: an unread member contributes nothing; the resolution
is the same as if that member held nothing. -/
theorem unknown_never_counts (obs : Nat → Obs) (leader i : Nat) (hi : i ≠ leader)
    (hu : obs i = .unknown) :
    resolve obs leader = resolve (fun j => if j = i then .holds [] else obs j) leader := by
  have hlf : leaderFirst (fun j => if j = i then .holds [] else obs j) leader
      = leaderFirst obs leader := by
    unfold leaderFirst
    dsimp only
    rw [if_neg (fun h => hi h.symm)]
  have hca : ∀ v j, copyAt (fun j => if j = i then .holds [] else obs j) leader v j
      = copyAt obs leader v j := by
    intro v j
    unfold copyAt
    dsimp only
    by_cases hj : j = i
    · rw [if_pos hj, hj, hu]; simp [holdsVal]
    · rw [if_neg hj]
  unfold resolve copies
  rw [hlf]
  cases leaderFirst obs leader with
  | none => rfl
  | some v => dsimp only; rw [hca, hca, hca, hca, hca]

-- ── the four cases of `sofi::arith`, decided ──────────────────────────────

def ofList (l : List Obs) : Nat → Obs := fun i => l.getD i .unknown

def A : Val := 10
def B : Val := 11

theorem the_leaders_first_value_held_by_two_others_is_final :
    resolve (ofList [.holds [A], .holds [A], .holds [A], .holds [], .unknown]) 0 = .final A := by
  decide

/-- What replaces counting: the leader holds nothing, so whatever the others
hold, the race has not ended. -/
theorem three_non_leaders_agreeing_is_not_final :
    resolve (ofList [.holds [], .holds [A], .holds [A], .holds [A], .holds [A]]) 0
      = .unresolved := by
  decide

/-- B arrived at the leader after A. Four members hold B; A is the winner
because it got to the leader first. -/
theorem a_later_value_at_the_leader_never_becomes_final :
    resolve (ofList [.holds [A, B], .holds [B], .holds [B], .holds [B], .holds [B]]) 0
      = .leaderHeld A := by
  decide

theorem leader_held_settles_the_race_before_finality :
    resolve (ofList [.holds [A], .holds [], .unknown, .holds [], .holds []]) 0
      = .leaderHeld A := by
  decide

theorem one_copy_is_not_final :
    resolve (ofList [.holds [A], .holds [A], .holds [], .holds [], .holds []]) 0
      = .leaderHeld A := by
  decide

theorem unknown_is_not_a_copy :
    resolve (ofList [.holds [A], .holds [A], .unknown, .unknown, .unknown]) 0 = .leaderHeld A
      ∧ resolve (ofList [.holds [A], .holds [A], .holds [A], .unknown, .unknown]) 0 = .final A := by
  decide

-- ── the attempt walk ──────────────────────────────────────────────────────

inductive Validation where
  | valid
  | invalid
  | unavailable
  deriving DecidableEq, Repr

/-- The facts about ONE vault parent's attempt chain that a verifier has
established. Storage facts (`keyFinal`, outcomes) and semantic facts
(`validation`, `orphanLeg`, `consumedElsewhere`) are separate fields; nothing
here is a clock. -/
structure World where
  keyFinal : Nat → Option Val
  isRoute : Val → Bool
  validation : Val → Validation
  orphanLeg : Val → Bool
  consumedElsewhere : Val → Bool
  outcomeComplete : Val → Bool
  outcomeAbort : Val → Bool
  /-- Arm (iv), P15-3/R17-3: the operation's own TRADER parent at `p` is
  terminal on another branch, or on none. It is a fact about the trader's
  lineage, not about this vault, and it reads no validation evidence. -/
  traderParentImpossible : Val → Bool := fun _ => false
  canonicalParent : Bool

/-- Storage coherence the cell layer proves: an outcome register holds at most
one final value. A key lost to another exercise is `keyFinal = none` here and
that exercise's question (`classify_attempt`: Unresolved), never a skip. -/
structure Coherent (w : World) : Prop where
  outcome_unique : ∀ e, ¬ (w.outcomeComplete e = true ∧ w.outcomeAbort e = true)

/-- R7-17 / P9-2: permanent proof that a route can never be consumed.
Only Invalid counts; Unavailable never does. Arm (iv) is the trader parent
(P15-3), which likewise needs no evidence. -/
def RouteImpossible (w : World) (e : Val) : Bool :=
  w.validation e == .invalid || w.orphanLeg e || w.consumedElsewhere e
    || w.traderParentImpossible e

/-- A storage-final E at a DLV key is skippable only on objective evidence. -/
def finalSkippable (w : World) (e : Val) : Bool :=
  if w.isRoute e then RouteImpossible w e || w.outcomeAbort e
  else w.validation e == .invalid

def Skipped (w : World) (a : Nat) : Bool :=
  (w.keyFinal a).any (finalSkippable w)

def AttemptLive (w : World) (a : Nat) : Prop := ∀ b, b < a → Skipped w b = true

def Consumed (w : World) (a : Nat) (e : Val) : Prop :=
  w.canonicalParent = true ∧ AttemptLive w a ∧ w.keyFinal a = some e
    ∧ w.validation e = .valid
    ∧ (w.isRoute e = true →
        w.outcomeComplete e = true ∧ w.orphanLeg e = false ∧ w.consumedElsewhere e = false
          ∧ w.traderParentImpossible e = false)

theorem consumed_not_skipped {w : World} (hc : Coherent w) {a : Nat} {e : Val}
    (h : Consumed w a e) : Skipped w a = false := by
  obtain ⟨_, _, hf, hv, hr⟩ := h
  have hfs : finalSkippable w e = false := by
    unfold finalSkippable
    by_cases hroute : w.isRoute e = true
    · obtain ⟨hcomp, horph, hce, htp⟩ := hr hroute
      have hab : w.outcomeAbort e = false := by
        cases hx : w.outcomeAbort e
        · rfl
        · exact absurd ⟨hcomp, hx⟩ (hc.outcome_unique e)
      rw [if_pos hroute]
      simp [RouteImpossible, hv, horph, hce, hab, htp]
    · rw [if_neg hroute, hv]
      decide
  show ((w.keyFinal a).any (finalSkippable w)) = false
  rw [hf]
  exact hfs

/-- ONE CONSUMER PER PARENT across the whole attempt chain. -/
theorem walk_consumes_at_most_once {w : World} (hc : Coherent w) {a1 a2 : Nat} {e1 e2 : Val}
    (h1 : Consumed w a1 e1) (h2 : Consumed w a2 e2) : a1 = a2 ∧ e1 = e2 := by
  have hlt : ∀ {x y ex ey}, Consumed w x ex → Consumed w y ey → ¬ x < y := by
    intro x y ex ey hx hy hxy
    have hs := hy.2.1 x hxy
    rw [consumed_not_skipped hc hx] at hs
    exact Bool.false_ne_true hs
  have ha : a1 = a2 := by
    rcases Nat.lt_trichotomy a1 a2 with h | h | h
    · exact absurd h (hlt h1 h2)
    · exact h
    · exact absurd h (hlt h2 h1)
  subst ha
  have := h1.2.2.1.symm.trans h2.2.2.1
  exact ⟨rfl, Option.some.inj this⟩

theorem consumed_requires_attempt_live {w : World} {a : Nat} {e : Val}
    (h : Consumed w a e) : AttemptLive w a := h.2.1

/-- The same predicate without `AttemptLive` consumes one parent twice: a valid
final at attempt 0 and another final at attempt 1. -/
def ConsumedNoLive (w : World) (a : Nat) (e : Val) : Prop :=
  w.canonicalParent = true ∧ w.keyFinal a = some e ∧ w.validation e = .valid ∧ w.isRoute e = false

def twoFinals : World where
  keyFinal := fun a => if a = 0 then some 10 else if a = 1 then some 11 else none
  isRoute := fun _ => false
  validation := fun _ => .valid
  orphanLeg := fun _ => false
  consumedElsewhere := fun _ => false
  outcomeComplete := fun _ => false
  outcomeAbort := fun _ => false
  canonicalParent := true

theorem attempt_live_is_load_bearing :
    ConsumedNoLive twoFinals 0 10 ∧ ConsumedNoLive twoFinals 1 11 ∧ (10 : Val) ≠ 11 := by
  simp [ConsumedNoLive, twoFinals]

theorem objective_rejection_implies_skipped (w : World) (a : Nat) (e : Val)
    (hf : w.keyFinal a = some e)
    (hobj : (w.isRoute e = false ∧ w.validation e = .invalid)
      ∨ (w.isRoute e = true ∧ RouteImpossible w e = true)) :
    Skipped w a = true := by
  have hfs : finalSkippable w e = true := by
    unfold finalSkippable
    rcases hobj with ⟨hr, hv⟩ | ⟨hr, hi⟩
    · rw [if_neg (by rw [hr]; decide), hv]
      decide
    · rw [if_pos hr, hi]
      rfl
  show ((w.keyFinal a).any (finalSkippable w)) = true
  rw [hf]
  show finalSkippable w e = true
  exact hfs

/-- R7-17: a finalized leg of an impossible route is skippable with NO
Complete premise. -/
theorem route_impossible_final_leg_is_skippable (w : World) (a : Nat) (e : Val)
    (hf : w.keyFinal a = some e) (hroute : w.isRoute e = true)
    (himp : RouteImpossible w e = true) : Skipped w a = true :=
  objective_rejection_implies_skipped w a e hf (Or.inr ⟨hroute, himp⟩)

/-- ARM (iv) (P15-3, R17-3): a storage-final route cell whose TRADER parent is
terminal on another branch — or on none — is skippable, with NO validation
evidence and no Complete premise. Nothing rolls back: the cell was never an
execution of its own, and the trader position is Invalid by the ladder's rung 2
rather than Void. -/
theorem trader_parent_impossible_makes_a_final_route_skippable (w : World) (a : Nat) (e : Val)
    (hf : w.keyFinal a = some e) (hroute : w.isRoute e = true)
    (htp : w.traderParentImpossible e = true)
    -- Deliberately unused: the arm decides with the evidence still missing.
    (_hun : w.validation e = .unavailable) : Skipped w a = true :=
  route_impossible_final_leg_is_skippable w a e hf hroute (by simp [RouteImpossible, htp])

/-- The rejected alternative: gating route skip on Complete. -/
def SkippedGated (w : World) (a : Nat) : Bool :=
  (w.keyFinal a).any (fun e =>
    if w.isRoute e then (RouteImpossible w e && w.outcomeComplete e) || w.outcomeAbort e
    else w.validation e == .invalid)

/-- A withheld leg: attempt 0 holds route E whose other leg's parent was consumed
elsewhere, and whose outcome never resolves. -/
def withheld : World where
  keyFinal := fun a => if a = 0 then some 20 else if a = 1 then some 21 else none
  isRoute := fun e => e == 20
  validation := fun _ => .valid
  orphanLeg := fun _ => false
  consumedElsewhere := fun e => e == 20
  outcomeComplete := fun _ => false
  outcomeAbort := fun _ => false
  canonicalParent := true

theorem withheld_leg_recovers_under_R7_17 :
    Skipped withheld 0 = true ∧ Consumed withheld 1 21 := by
  refine ⟨by decide, ?_⟩
  refine ⟨rfl, ?_, rfl, rfl, ?_⟩
  · intro b hb
    have : b = 0 := by omega
    subst this; decide
  · intro h; simp [withheld] at h

theorem withheld_leg_wedges_if_gated_on_complete :
    SkippedGated withheld 0 = false := by decide

-- ── evolution: facts only become more resolved ────────────────────────────

def ValidationRefines : Validation → Validation → Prop
  | .unavailable, _ => True
  | v, v' => v = v'

structure Evolves (w w' : World) : Prop where
  final_stays : ∀ a e, w.keyFinal a = some e → w'.keyFinal a = some e
  route_fixed : ∀ e, w'.isRoute e = w.isRoute e
  validation_refines : ∀ e, ValidationRefines (w.validation e) (w'.validation e)
  orphan_stays : ∀ e, w.orphanLeg e = true → w'.orphanLeg e = true
  consumed_elsewhere_stays : ∀ e, w.consumedElsewhere e = true → w'.consumedElsewhere e = true
  abort_stays : ∀ e, w.outcomeAbort e = true → w'.outcomeAbort e = true
  /-- A terminal trader parent never retracts. -/
  trader_parent_stays : ∀ e, w.traderParentImpossible e = true →
    w'.traderParentImpossible e = true := by intro _ h; exact h

theorem invalid_stays {w w' : World} (hev : Evolves w w') {e : Val}
    (h : w.validation e = .invalid) : w'.validation e = .invalid := by
  have := hev.validation_refines e
  rw [h] at this
  exact this.symm

theorem route_impossibility_is_permanent {w w' : World} (hev : Evolves w w') {e : Val}
    (h : RouteImpossible w e = true) : RouteImpossible w' e = true := by
  unfold RouteImpossible at *
  simp only [Bool.or_eq_true, beq_iff_eq] at *
  rcases h with ((h | h) | h) | h
  · exact Or.inl (Or.inl (Or.inl (invalid_stays hev h)))
  · exact Or.inl (Or.inl (Or.inr (hev.orphan_stays e h)))
  · exact Or.inl (Or.inr (hev.consumed_elsewhere_stays e h))
  · exact Or.inr (hev.trader_parent_stays e h)

theorem final_skippable_is_monotone {w w' : World} (hev : Evolves w w') {e : Val}
    (h : finalSkippable w e = true) : finalSkippable w' e = true := by
  unfold finalSkippable at *
  rw [hev.route_fixed e]
  by_cases hr : w.isRoute e = true
  · rw [if_pos hr] at h ⊢
    rcases Bool.or_eq_true_iff.mp h with hi | ha
    · rw [route_impossibility_is_permanent hev hi, Bool.true_or]
    · rw [hev.abort_stays e ha, Bool.or_true]
  · rw [if_neg hr] at h ⊢
    exact beq_iff_eq.mpr (invalid_stays hev (beq_iff_eq.mp h))

theorem rejected_final_is_monotone {w w' : World} (hev : Evolves w w') {a : Nat}
    (h : Skipped w a = true) : Skipped w' a = true := by
  unfold Skipped at *
  cases hf : w.keyFinal a with
  | none => rw [hf] at h; exact absurd h Bool.false_ne_true
  | some e =>
    rw [hf] at h
    rw [hev.final_stays a e hf]
    show finalSkippable w' e = true
    exact final_skippable_is_monotone hev h

theorem unavailable_never_establishes_route_impossibility (w : World) (e : Val)
    (hu : w.validation e = .unavailable) (ho : w.orphanLeg e = false)
    (hc : w.consumedElsewhere e = false) (htp : w.traderParentImpossible e = false) :
    RouteImpossible w e = false := by
  simp [RouteImpossible, hu, ho, hc, htp]

theorem validation_unavailable_never_implies_rejection (w : World) (a : Nat) (e : Val)
    (hf : w.keyFinal a = some e) (hsingle : w.isRoute e = false)
    (hu : w.validation e = .unavailable) :
    Skipped w a = false := by
  show ((w.keyFinal a).any (finalSkippable w)) = false
  rw [hf]
  show finalSkippable w e = false
  unfold finalSkippable
  rw [if_neg (by rw [hsingle]; decide), hu]
  decide

-- ── the walk and its computational budget ─────────────────────────────────

inductive WalkResult where
  | consumed (a : Nat)
  | unresolved (a : Nat)
  | continueAt (a : Nat)
  deriving DecidableEq, Repr

def walkFrom (consumable skipped : Nat → Bool) : Nat → Nat → WalkResult
  | 0, a => .continueAt a
  | fuel + 1, a =>
    if consumable a then .consumed a
    else if skipped a then walkFrom consumable skipped fuel (a + 1)
    else .unresolved a

def resume (consumable skipped : Nat → Bool) (m : Nat) : WalkResult → WalkResult
  | .continueAt c => walkFrom consumable skipped m c
  | r => r

/-- WALK_MAX_ATTEMPTS is a budget only: two chunks of `n` and `m` equal one walk
of `n + m`. -/
theorem walk_chunking_preserves_result (consumable skipped : Nat → Bool) :
    ∀ n m a, resume consumable skipped m (walkFrom consumable skipped n a)
      = walkFrom consumable skipped (n + m) a := by
  intro n
  induction n with
  | zero => intro m a; simp [walkFrom, resume]
  | succ n ih =>
    intro m a
    rw [Nat.succ_add]
    simp only [walkFrom]
    split
    · rfl
    · split
      · exact ih m (a + 1)
      · rfl

-- ── storage ordering projection: no numeric holes ─────────────────────────

/-- Storage admits a cell at attempt `a > 0` only when it holds a resolution
record for `a - 1`, and a record exists only where cells were written. -/
structure StorageOrdering (written record : Nat → Bool) : Prop where
  admit : ∀ a, written (a + 1) = true → record a = true
  record_needs_cells : ∀ a, record a = true → written a = true

theorem storage_forbids_numeric_holes {written record : Nat → Bool}
    (h : StorageOrdering written record) :
    ∀ a, written a = true → ∀ b, b ≤ a → written b = true := by
  intro a
  induction a with
  | zero => intro hw b hb; have : b = 0 := by omega
            subst this; exact hw
  | succ a ih =>
    intro hw b hb
    rcases Nat.lt_or_eq_of_le hb with hlt | heq
    · exact ih (h.record_needs_cells a (h.admit a hw)) b (by omega)
    · subst heq; exact hw

/-- Without the projection, a write at a huge attempt index exists with nothing
before it. -/
theorem index_skip_without_projection :
    ∃ written : Nat → Bool, written 500000 = true ∧ written 0 = false :=
  ⟨fun a => a == 500000, by decide, by decide⟩

-- ── checked counters ──────────────────────────────────────────────────────

def U64_MAX : Nat := 2 ^ 64 - 1

def checkedNext (p : Nat) : Option Nat := if p < U64_MAX then some (p + 1) else none

theorem checked_counters_never_wrap :
    (∀ p q, checkedNext p = some q → q = p + 1 ∧ q ≤ U64_MAX) ∧ checkedNext U64_MAX = none := by
  refine ⟨?_, by simp [checkedNext]⟩
  intro p q h
  unfold checkedNext at h
  split at h
  · cases h; constructor
    · rfl
    · omega
  · cases h

-- ── StorageReachable: a noncanonical DAG, never authority ─────────────────

/-- Roots as terms. A child root is determined by its parent and E; the attempt
index is routing metadata and is not an input. -/
inductive Root where
  | genesis (vault : Nat)
  | child (parent : Root) (e : Val)
  deriving DecidableEq, Repr

def generation : Root → Nat
  | .genesis _ => 0
  | .child p _ => generation p + 1

inductive StorageReachable (finalAt : Root → Val → Prop) : Root → Prop
  | genesis (v : Nat) : StorageReachable finalAt (.genesis v)
  | child {r : Root} {e : Val} : StorageReachable finalAt r → finalAt r e →
      StorageReachable finalAt (.child r e)

/-- The producer of a root, from `(parent, E)` only. -/
def produce (parent : Root) (_attempt : Nat) (e : Val) : Root := .child parent e

theorem storage_reachable_producer_identity_excludes_attempt (r : Root) (e : Val) (a a' : Nat) :
    produce r a e = produce r a' e := rfl

theorem storage_reachable_producer_unique {r r' : Root} {e e' : Val}
    (h : Root.child r e = Root.child r' e') : r = r' ∧ e = e' := by
  cases h; exact ⟨rfl, rfl⟩

theorem storage_reachable_generation_acyclic (r : Root) (e : Val) :
    generation (.child r e) = generation r + 1 ∧ Root.child r e ≠ r := by
  refine ⟨rfl, ?_⟩
  intro h
  have := congrArg generation h
  simp [generation] at this

/-- Two storage-final candidates at one parent both produce StorageReachable
roots; at most one of them is canonical. -/
theorem storage_reachable_does_not_imply_canonical :
    let finalAt : Root → Val → Prop := fun r e => r = .genesis 0 ∧ (e = 1 ∨ e = 2)
    StorageReachable finalAt (.child (.genesis 0) 1)
      ∧ StorageReachable finalAt (.child (.genesis 0) 2)
      ∧ Root.child (.genesis 0) 1 ≠ Root.child (.genesis 0) 2 := by
  refine ⟨.child (.genesis 0) ⟨rfl, Or.inl rfl⟩, .child (.genesis 0) ⟨rfl, Or.inr rfl⟩, ?_⟩
  decide

#print axioms Reach.trans
#print axioms prefix_refl
#print axioms prefix_trans
#print axioms put_keeps_prefix
#print axioms put_holds_what_it_was_given
#print axioms reach_keeps_prefix
#print axioms first_stable
#print axioms mem_of_prefix
#print axioms holdsVal_holds
#print axioms compatible_observe
#print axioms compatible_reach
#print axioms holdsVal_of_compatible
#print axioms leaderFirst_of_compatible
#print axioms copyAt_mono
#print axioms copies_mono
#print axioms resolve_names_leader_first
#print axioms resolve_of_leaderFirst
#print axioms final_persists
#print axioms final_unique_across_time
#print axioms leader_held_excludes_others
#print axioms open_key_becomes_leader_held
#print axioms holds_after_put_self
#print axioms holds_after_put_other
#print axioms leader_held_becomes_final
#print axioms unknown_never_counts
#print axioms the_leaders_first_value_held_by_two_others_is_final
#print axioms three_non_leaders_agreeing_is_not_final
#print axioms a_later_value_at_the_leader_never_becomes_final
#print axioms leader_held_settles_the_race_before_finality
#print axioms one_copy_is_not_final
#print axioms unknown_is_not_a_copy
#print axioms consumed_not_skipped
#print axioms walk_consumes_at_most_once
#print axioms consumed_requires_attempt_live
#print axioms attempt_live_is_load_bearing
#print axioms objective_rejection_implies_skipped
#print axioms route_impossible_final_leg_is_skippable
#print axioms trader_parent_impossible_makes_a_final_route_skippable
#print axioms withheld_leg_recovers_under_R7_17
#print axioms withheld_leg_wedges_if_gated_on_complete
#print axioms invalid_stays
#print axioms route_impossibility_is_permanent
#print axioms final_skippable_is_monotone
#print axioms rejected_final_is_monotone
#print axioms unavailable_never_establishes_route_impossibility
#print axioms validation_unavailable_never_implies_rejection
#print axioms walk_chunking_preserves_result
#print axioms storage_forbids_numeric_holes
#print axioms index_skip_without_projection
#print axioms checked_counters_never_wrap
#print axioms storage_reachable_producer_identity_excludes_attempt
-- ── registration: the two position cells (rebuild step R10) ──────────────

/-- `FulfillmentRegistered(F)` (`sofi::registration::fulfillment_registered`):
`F` final at `K_ful(q)` and, at `K_root(q)`, this `F`'s own claim final —
`claimOf` is `resolution_claim(P, F)`. Nothing else: no member's word, no
record. -/
def registered (ful root : Res) (f : Val) (claimOf : Val → Val) : Bool :=
  match ful, root with
  | .final f', .final c => f' == f && c == claimOf f
  | _, _ => false

/-- REGISTRATION NEEDS BOTH FINALS
(`registration_needs_both_cells_final_and_the_root_on_this_claim`): a pair
held at the leader but not copied is not registered, and neither is a final
`F` beside a root cell that is not final on its claim. Mutation: `registered`
accepting `.leaderHeld f` at `K_ful` — this fails. -/
theorem registration_needs_both_finals (ful root : Res) (f : Val) (claimOf : Val → Val)
    (h : registered ful root f claimOf = true) : ful = .final f ∧ root = .final (claimOf f) := by
  cases ful <;> cases root <;> simp [registered] at h
  rename_i f' c
  obtain ⟨hf, hc⟩ := h
  subst hf; subst hc
  exact ⟨rfl, rfl⟩

/-- A RIVAL FIRST AT THE LEADER SETTLES LOSS
(`a_claim_first_at_the_root_cell_settles_that_the_fulfillment_never_registers`,
`held_at_the_leader_but_not_copied_is_not_registered`): once the leader's
first object at `K_ful(q)` is some `u ≠ f`, no read — partial or full —
registers `f`, because `resolve` names the leader's first value and only it
can be final (`resolve_names_leader_first`). -/
theorem a_rival_first_at_the_leader_settles_loss (obs : Nat → Obs) (leader : Nat) (u f : Val)
    (hu : leaderFirst obs leader = some u) (hne : u ≠ f) (root : Res) (claimOf : Val → Val) :
    registered (resolve obs leader) root f claimOf = false := by
  unfold resolve
  simp only [hu]
  split
  · cases root with
    | final c => simp [registered, hne]
    | leaderHeld _ => rfl
    | unresolved => rfl
  · cases root <;> rfl

/-- THE ROOT CELL FINAL ON ANOTHER CLAIM NEVER REGISTERS (PairMutualExclusion): with
`K_root(q)` final on `c ≠ claimOf f`, `f` is not registered whatever
`K_ful(q)` holds. -/
theorem root_final_on_another_claim_never_registers (ful : Res) (c f : Val) (claimOf : Val → Val)
    (hne : c ≠ claimOf f) : registered ful (.final c) f claimOf = false := by
  cases ful with
  | final f' => simp [registered, hne]
  | leaderHeld _ => rfl
  | unresolved => rfl

#print axioms registration_needs_both_finals
#print axioms a_rival_first_at_the_leader_settles_loss
#print axioms root_final_on_another_claim_never_registers
#print axioms storage_reachable_producer_unique
#print axioms storage_reachable_generation_acyclic
#print axioms storage_reachable_does_not_imply_canonical

end DSMSofiSuccessorCells
