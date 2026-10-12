/-
  DSM Step Transition — the batch fold of a write set, self-contained Lean 4
  (no Mathlib)

  A step's receipt carries every leaf the step writes, each with its path
  against ONE pre-root, and the verifier folds them together
  (`dsm::merkle::batch_fold`). This module is that fold over a symbolic sparse
  Merkle tree of depth `d`, and what it proves about it.

  What is proved:
    1. `fold_sound` — if the fold of a write set yields `(P, Q)` and `P` is the
       root of the tree `m`, then every entry's pre-value is the value `m`
       holds at its key, and `Q` is the root of `m` with every write applied.
       No key outside the write set moves (`upd_off`).
    2. `fold_complete` — an honest write set (distinct keys, each entry's
       pre-value and path the tree's own) folds to the tree's root before and
       its root after the writes: the verifier refuses no honest step.
    3. `fold_canonical` — if the fold yields `(P, Q)` with `P` the root of
       `m`, every path the write set carries is the tree's own path at its
       key. This is the job of the sibling-consistency checks, and only this:
    4. `lax_fold_sound` and `lax_fold_is_not_canonical` (anti-vacuity) — the
       fold with the consistency checks deleted still satisfies (1), but
       accepts a write set carrying a sibling that is not the tree's, so the
       same move has more than one encoding.

  So the pre-root check (`verify_batch`: the fold's pre-root equals the
  claimed one) is what makes the post-root right; the consistency checks are
  what make the proof canonical. A sibling the fold never uses would otherwise
  be free, and a receipt carrying the move would be malleable.

  ── PROVED vs ASSUMED ────────────────────────────────────────────────────────
  `Dig` is the free term algebra over the leaf and node hashes, so distinct
  preimages give distinct digests BY CONSTRUCTION: equal roots have equal
  children. That symbolic abstraction is the only assumption, as in
  `DSMEconomicSmtSeparation`; it is structural and so does not appear in
  `#print axioms`. Concretely, an adversary breaking these theorems for the
  real tree supplies a BLAKE3 collision between two leaf or node preimages.

  Correspondence (Rust ↔ Lean):
    `batch_fold::subtree`                   ↔ `fold`
    `FoldError::InconsistentPath`           ↔ the `agree` checks in `fold`
    `verify_batch` (pre-root equality)      ↔ the hypothesis `P = root d m`
    `SparseMerkleTree::apply_writes`        ↔ `upd`
    `SparseMerkleTree::get_inclusion_proof` ↔ `path`
  Paths here are root-first; the Rust path is leaf-to-root (`sibling_at`
  reads `path[FOLD_HEIGHT - 1 - depth]`), the same siblings in reverse.

  This module contains zero `axiom`, `opaque` and `sorry` declarations.
-/

namespace DSMStepTransition

/-- A symbolic digest: a leaf over its value (`none` is a leaf holding
nothing), or a node over its two children. -/
inductive Dig where
  | leaf : Option Nat → Dig
  | node : Dig → Dig → Dig
  deriving DecidableEq, Repr

/-- The tree below one child: `m` restricted to the keys that go `b` first. -/
def sub (m : List Bool → Option Nat) (b : Bool) : List Bool → Option Nat :=
  fun k => m (b :: k)

/-- The root of the depth-`d` tree holding `m`. -/
def root : Nat → (List Bool → Option Nat) → Dig
  | 0, m => .leaf (m [])
  | d + 1, m => .node (root d (sub m false)) (root d (sub m true))

/-- The tree's own path at `k`, root-first: at each level, the root of the
side `k` does not take. -/
def path : Nat → (List Bool → Option Nat) → List Bool → List Dig
  | 0, _, _ => []
  | _ + 1, _, [] => []
  | d + 1, m, b :: k => root d (sub m (!b)) :: path d (sub m b) k

/-- One key's contribution to a write set. -/
structure Entry where
  key : List Bool
  pre : Option Nat
  post : Option Nat
  path : List Dig

/-- The entry as the subtree below its first step sees it. -/
def Entry.down (e : Entry) : Entry :=
  { e with key := e.key.tail, path := e.path.tail }

/-- Whether the entry's key goes `b` first. -/
def goes (b : Bool) (e : Entry) : Bool := e.key.head? == some b

/-- The entries on side `b`, as the subtree on that side sees them. -/
def side (b : Bool) : List Entry → List Entry
  | [] => []
  | e :: rest => if goes b e then e.down :: side b rest else side b rest

/-- Whether every entry going `b` names `s` as its first sibling. -/
def agree (b : Bool) (s : Dig) : List Entry → Bool
  | [] => true
  | e :: rest => (!goes b e || e.path.head? == some s) && agree b s rest

/-- The first sibling the write set names. -/
def firstSibling (es : List Entry) : Option Dig :=
  es.head?.bind (fun e => e.path.head?)

/-- The batch fold: both roots of the subtree of depth `d` over the entries,
or `none`. Where the keys do not separate, every path must name the same
sibling; where they separate, each side's paths must name the other side as
the entries compute it. -/
def fold : Nat → List Entry → Option (Dig × Dig)
  | 0, [e] => some (.leaf e.pre, .leaf e.post)
  | 0, _ => none
  | d + 1, es =>
    if (side true es).isEmpty then
      if (side false es).isEmpty then none
      else match firstSibling es with
        | none => none
        | some s =>
          if agree false s es then
            (fold d (side false es)).map (fun pq => (.node pq.1 s, .node pq.2 s))
          else none
    else if (side false es).isEmpty then
      match firstSibling es with
      | none => none
      | some s =>
        if agree true s es then
          (fold d (side true es)).map (fun pq => (.node s pq.1, .node s pq.2))
        else none
    else
      match fold d (side false es), fold d (side true es) with
      | some (lp, lq), some (hp, hq) =>
        if agree false hp es && agree true lp es then
          some (.node lp hp, .node lq hq)
        else none
      | _, _ => none

/-- The fold with the consistency checks deleted: where the keys do not
separate the sibling is the first entry's, and where they separate nothing is
compared. -/
def laxFold : Nat → List Entry → Option (Dig × Dig)
  | 0, [e] => some (.leaf e.pre, .leaf e.post)
  | 0, _ => none
  | d + 1, es =>
    if (side true es).isEmpty then
      if (side false es).isEmpty then none
      else match firstSibling es with
        | none => none
        | some s => (laxFold d (side false es)).map (fun pq => (.node pq.1 s, .node pq.2 s))
    else if (side false es).isEmpty then
      match firstSibling es with
      | none => none
      | some s => (laxFold d (side true es)).map (fun pq => (.node s pq.1, .node s pq.2))
    else
      match laxFold d (side false es), laxFold d (side true es) with
      | some (lp, lq), some (hp, hq) => some (.node lp hp, .node lq hq)
      | _, _ => none

/-- `m` with every entry's post-value written at its key (the first entry
naming a key wins; the fold refuses a key named twice). -/
def upd (m : List Bool → Option Nat) : List Entry → List Bool → Option Nat
  | [], k => m k
  | e :: rest, k => if e.key = k then e.post else upd m rest k

/-! ## Lemmas about sides and writes -/

theorem mem_side {b : Bool} {es : List Entry} {e' : Entry} :
    e' ∈ side b es ↔ ∃ e ∈ es, goes b e = true ∧ e' = e.down := by
  induction es with
  | nil => simp [side]
  | cons e rest ih =>
    cases hg : goes b e <;> simp [side, hg, ih]

theorem goes_key {b : Bool} {e : Entry} (h : goes b e = true) :
    ∃ k, e.key = b :: k := by
  unfold goes at h
  cases hk : e.key with
  | nil => rw [hk] at h; simp at h
  | cons c k =>
    rw [hk] at h
    simp at h
    exact ⟨k, by rw [h]⟩

theorem side_lengths {b : Bool} {d : Nat} {es : List Entry}
    (hl : ∀ e ∈ es, e.key.length = d + 1) : ∀ e ∈ side b es, e.key.length = d := by
  intro e' he'
  obtain ⟨e, he, hg, rfl⟩ := mem_side.mp he'
  obtain ⟨k, hk⟩ := goes_key hg
  have := hl e he
  rw [hk] at this
  simp [Entry.down, hk] at this ⊢
  exact this

/-- Every entry of positive depth goes one way or the other. -/
theorem goes_cases {d : Nat} {e : Entry} (hl : e.key.length = d + 1) :
    goes false e = true ∨ goes true e = true := by
  cases hk : e.key with
  | nil => rw [hk] at hl; simp at hl
  | cons c k => cases c <;> simp [goes, hk]

theorem side_empty_all {b : Bool} {es : List Entry} (h : (side b es).isEmpty = true) :
    ∀ e ∈ es, goes b e = false := by
  intro e he
  cases hg : goes b e
  · rfl
  · have hm : e.down ∈ side b es := mem_side.mpr ⟨e, he, hg, rfl⟩
    rw [List.isEmpty_iff] at h
    rw [h] at hm; simp at hm

theorem down_mem {b : Bool} {es : List Entry} {e : Entry} (he : e ∈ es)
    (hg : goes b e = true) : e.down ∈ side b es :=
  mem_side.mpr ⟨e, he, hg, rfl⟩

theorem upd_nil (m : List Bool → Option Nat) : upd m [] = m := by
  funext k; simp [upd]

/-- Written keys read back as written, below one child. -/
theorem upd_sub {d : Nat} (m : List Bool → Option Nat) (b : Bool) :
    ∀ (es : List Entry), (∀ e ∈ es, e.key.length = d + 1) →
    sub (upd m es) b = upd (sub m b) (side b es) := by
  intro es
  induction es with
  | nil => intro _; funext k; simp [sub, upd, side]
  | cons e rest ih =>
    intro hl
    have hrest : ∀ x ∈ rest, x.key.length = d + 1 :=
      fun x hx => hl x (List.mem_cons_of_mem e hx)
    have ih := ih hrest
    have hle := hl e List.mem_cons_self
    funext k
    have hk_eq := congrFun ih k
    cases hek : e.key with
    | nil => rw [hek] at hle; simp at hle
    | cons c k' =>
      by_cases hc : c = b
      · subst hc
        have hg : goes c e = true := by simp [goes, hek]
        by_cases hkk : k' = k
        · subst hkk
          simp [sub, upd, side, hg, hek, Entry.down]
        · have h1 : ¬ (c :: k' = c :: k) := by simp [hkk]
          simp only [sub] at hk_eq
          simp [sub, upd, side, hg, hek, h1, Entry.down, hkk, hk_eq]
      · have hg : goes b e = false := by simp [goes, hek, hc]
        have h1 : ¬ (c :: k' = b :: k) := by simp [hc]
        simp only [sub] at hk_eq
        simp [sub, upd, side, hg, hek, h1, hk_eq]

/-- A key no entry names holds what it held. -/
theorem upd_off (m : List Bool → Option Nat) (es : List Entry) (k : List Bool)
    (h : ∀ e ∈ es, e.key ≠ k) : upd m es k = m k := by
  induction es with
  | nil => rfl
  | cons e rest ih =>
    simp only [upd, h e List.mem_cons_self, if_false]
    exact ih (fun x hx => h x (List.mem_cons_of_mem e hx))

/-- An entry below a child reads its pre-value from that child. -/
theorem pre_down {b : Bool} {m : List Bool → Option Nat} {e : Entry}
    (hg : goes b e = true) (h : e.down.pre = sub m b e.down.key) : e.pre = m e.key := by
  obtain ⟨k, hk⟩ := goes_key hg
  simp [Entry.down, hk, sub] at h ⊢
  exact h

/-! ## Soundness: the post-root is the tree after the writes -/

theorem fold_sound : ∀ (d : Nat) (m : List Bool → Option Nat) (es : List Entry)
    (P Q : Dig), (∀ e ∈ es, e.key.length = d) → fold d es = some (P, Q) →
    P = root d m → (∀ e ∈ es, e.pre = m e.key) ∧ Q = root d (upd m es) := by
  intro d
  induction d with
  | zero =>
    intro m es P Q hl hf hP
    match es, hf with
    | [e], hf =>
      simp [fold] at hf
      obtain ⟨rfl, rfl⟩ := hf
      have hk : e.key = [] := List.eq_nil_of_length_eq_zero (hl e (List.mem_singleton_self e))
      simp [root] at hP
      refine ⟨?_, ?_⟩
      · intro x hx; simp at hx; subst hx; rw [hk]; exact hP
      · simp [root, upd, hk]
  | succ d ih =>
    intro m es P Q hl hf hP
    have hlo := side_lengths (b := false) hl
    have hhi := side_lengths (b := true) hl
    simp only [fold] at hf
    split at hf
    · -- no key goes true
      rename_i hT
      split at hf
      · simp at hf
      · split at hf
        · simp at hf
        · rename_i s _
          split at hf
          · obtain ⟨⟨lp, lq⟩, hfl, hpq⟩ := Option.map_eq_some_iff.mp hf
            simp at hpq; obtain ⟨rfl, rfl⟩ := hpq
            simp only [root, Dig.node.injEq] at hP
            obtain ⟨hP1, hP2⟩ := hP
            obtain ⟨hpre, hq⟩ := ih (sub m false) _ lp lq hlo hfl hP1
            refine ⟨?_, ?_⟩
            · intro x hx
              rcases goes_cases (hl x hx) with hg | hg
              · exact pre_down hg (hpre _ (down_mem hx hg))
              · have := side_empty_all hT x hx; rw [hg] at this; simp at this
            · simp only [root]
              rw [upd_sub m false es hl, upd_sub m true es hl, ← hq,
                List.isEmpty_iff.mp hT, upd_nil, ← hP2]
          · simp at hf
    · split at hf
      · -- no key goes false
        rename_i _ hF
        split at hf
        · simp at hf
        · rename_i s _
          split at hf
          · obtain ⟨⟨hp, hq⟩, hfh, hpq⟩ := Option.map_eq_some_iff.mp hf
            simp at hpq; obtain ⟨rfl, rfl⟩ := hpq
            simp only [root, Dig.node.injEq] at hP
            obtain ⟨hP1, hP2⟩ := hP
            obtain ⟨hpre, hq'⟩ := ih (sub m true) _ hp hq hhi hfh hP2
            refine ⟨?_, ?_⟩
            · intro x hx
              rcases goes_cases (hl x hx) with hg | hg
              · have := side_empty_all hF x hx; rw [hg] at this; simp at this
              · exact pre_down hg (hpre _ (down_mem hx hg))
            · simp only [root]
              rw [upd_sub m false es hl, upd_sub m true es hl, ← hq',
                List.isEmpty_iff.mp hF, upd_nil, ← hP1]
          · simp at hf
      · -- the keys separate
        split at hf
        · rename_i lp lq hp hq hfl hfh
          split at hf
          · simp at hf; obtain ⟨rfl, rfl⟩ := hf
            simp only [root, Dig.node.injEq] at hP
            obtain ⟨hP1, hP2⟩ := hP
            obtain ⟨hpreL, hqL⟩ := ih (sub m false) _ lp lq hlo hfl hP1
            obtain ⟨hpreH, hqH⟩ := ih (sub m true) _ hp hq hhi hfh hP2
            refine ⟨?_, ?_⟩
            · intro x hx
              rcases goes_cases (hl x hx) with hg | hg
              · exact pre_down hg (hpreL _ (down_mem hx hg))
              · exact pre_down hg (hpreH _ (down_mem hx hg))
            · simp only [root]
              rw [upd_sub m false es hl, upd_sub m true es hl, ← hqL, ← hqH]
          · simp at hf
        · simp at hf

/-! ## Canonicity: every carried path is the tree's own -/

theorem agree_spec {b : Bool} {s : Dig} {es : List Entry} :
    agree b s es = true ↔ ∀ e ∈ es, goes b e = true → e.path.head? = some s := by
  induction es with
  | nil => simp [agree]
  | cons e rest ih =>
    cases hg : goes b e <;> simp [agree, hg, ih]

theorem side_path_lengths {b : Bool} {d : Nat} {es : List Entry}
    (hp : ∀ e ∈ es, e.path.length = d + 1) : ∀ e ∈ side b es, e.path.length = d := by
  intro e' he'
  obtain ⟨e, he, _, rfl⟩ := mem_side.mp he'
  simp [Entry.down, hp e he]

/-- The tree's path at a key of positive depth: its head, and its tail below
the child the key takes. -/
theorem path_cons {d : Nat} {m : List Bool → Option Nat} {b : Bool} {e : Entry}
    (hg : goes b e = true) :
    path (d + 1) m e.key = root d (sub m (!b)) :: path d (sub m b) e.down.key := by
  obtain ⟨k, hk⟩ := goes_key hg
  simp [Entry.down, hk, path]

/-- An entry whose first sibling and whose path below it are the tree's
carries the tree's path. -/
theorem path_down {d : Nat} {m : List Bool → Option Nat} {b : Bool} {e : Entry}
    (hg : goes b e = true) (hhead : e.path.head? = some (root d (sub m (!b))))
    (hdown : e.down.path = path d (sub m b) e.down.key) :
    e.path = path (d + 1) m e.key := by
  rw [path_cons hg]
  cases hp : e.path with
  | nil => rw [hp] at hhead; simp at hhead
  | cons x xs =>
    rw [hp] at hhead
    simp at hhead
    simp [Entry.down, hp] at hdown
    rw [hhead, hdown]; rfl

theorem fold_canonical : ∀ (d : Nat) (m : List Bool → Option Nat) (es : List Entry)
    (P Q : Dig), (∀ e ∈ es, e.key.length = d) → (∀ e ∈ es, e.path.length = d) →
    fold d es = some (P, Q) → P = root d m → ∀ e ∈ es, e.path = path d m e.key := by
  intro d
  induction d with
  | zero =>
    intro m es P Q _ hp _ _ e he
    simp [path]
    exact List.eq_nil_of_length_eq_zero (hp e he)
  | succ d ih =>
    intro m es P Q hl hp hf hP e he
    have hlo := side_lengths (b := false) hl
    have hhi := side_lengths (b := true) hl
    have hplo := side_path_lengths (b := false) hp
    have hphi := side_path_lengths (b := true) hp
    simp only [fold] at hf
    split at hf
    · rename_i hT
      split at hf
      · simp at hf
      · split at hf
        · simp at hf
        · rename_i s _
          split at hf
          · rename_i hag
            obtain ⟨⟨lp, lq⟩, hfl, hpq⟩ := Option.map_eq_some_iff.mp hf
            simp at hpq; obtain ⟨rfl, rfl⟩ := hpq
            simp only [root, Dig.node.injEq] at hP
            obtain ⟨hP1, hP2⟩ := hP
            have hc := ih (sub m false) _ lp lq hlo hplo hfl hP1
            rcases goes_cases (hl e he) with hg | hg
            · refine path_down hg ?_ (hc _ (down_mem he hg))
              rw [agree_spec.mp hag e he hg, hP2]; rfl
            · have := side_empty_all hT e he; rw [hg] at this; simp at this
          · simp at hf
    · split at hf
      · rename_i _ hF
        split at hf
        · simp at hf
        · rename_i s _
          split at hf
          · rename_i hag
            obtain ⟨⟨hp', hq⟩, hfh, hpq⟩ := Option.map_eq_some_iff.mp hf
            simp at hpq; obtain ⟨rfl, rfl⟩ := hpq
            simp only [root, Dig.node.injEq] at hP
            obtain ⟨hP1, hP2⟩ := hP
            have hc := ih (sub m true) _ hp' hq hhi hphi hfh hP2
            rcases goes_cases (hl e he) with hg | hg
            · have := side_empty_all hF e he; rw [hg] at this; simp at this
            · refine path_down hg ?_ (hc _ (down_mem he hg))
              rw [agree_spec.mp hag e he hg, hP1]; rfl
          · simp at hf
      · split at hf
        · rename_i lp lq hp' hq hfl hfh
          split at hf
          · rename_i hag
            simp at hf; obtain ⟨rfl, rfl⟩ := hf
            simp only [root, Dig.node.injEq] at hP
            obtain ⟨hP1, hP2⟩ := hP
            simp only [Bool.and_eq_true] at hag
            obtain ⟨hagF, hagT⟩ := hag
            have hcL := ih (sub m false) _ lp lq hlo hplo hfl hP1
            have hcH := ih (sub m true) _ hp' hq hhi hphi hfh hP2
            rcases goes_cases (hl e he) with hg | hg
            · refine path_down hg ?_ (hcL _ (down_mem he hg))
              rw [agree_spec.mp hagF e he hg, hP2]; rfl
            · refine path_down hg ?_ (hcH _ (down_mem he hg))
              rw [agree_spec.mp hagT e he hg, hP1]; rfl
          · simp at hf
        · simp at hf

/-! ## Completeness: the verifier refuses no honest step -/

/-- Distinct keys: a write set names each key once. -/
def Distinct (es : List Entry) : Prop := es.Pairwise (fun a b => a.key ≠ b.key)

theorem side_distinct {b : Bool} {es : List Entry} (h : Distinct es) :
    Distinct (side b es) := by
  induction es with
  | nil => simp [side, Distinct]
  | cons e rest ih =>
    unfold Distinct at h
    rw [List.pairwise_cons] at h
    obtain ⟨hne, hrest⟩ := h
    have ih := ih hrest
    cases hg : goes b e
    · simp [side, hg]; exact ih
    · simp only [side, hg, if_true, Distinct, List.pairwise_cons]
      refine ⟨?_, ih⟩
      intro x hx
      obtain ⟨y, hy, hgy, rfl⟩ := mem_side.mp hx
      obtain ⟨k1, hk1⟩ := goes_key hg
      obtain ⟨k2, hk2⟩ := goes_key hgy
      have := hne y hy
      rw [hk1, hk2] at this
      simp [Entry.down, hk1, hk2]
      intro h12; exact this (by rw [h12])

/-- An honest entry below a child is honest there. -/
theorem honest_down {d : Nat} {m : List Bool → Option Nat} {b : Bool} {e : Entry}
    (hg : goes b e = true) (h : e.pre = m e.key ∧ e.path = path (d + 1) m e.key) :
    e.down.pre = sub m b e.down.key ∧ e.down.path = path d (sub m b) e.down.key := by
  obtain ⟨k, hk⟩ := goes_key hg
  obtain ⟨hpre, hpath⟩ := h
  rw [hk] at hpre hpath
  simp [Entry.down, hk, sub, hpre, hpath, path]

/-- An honest entry's first sibling is the root of the side it does not take. -/
theorem honest_head {d : Nat} {m : List Bool → Option Nat} {b : Bool} {e : Entry}
    (hg : goes b e = true) (h : e.path = path (d + 1) m e.key) :
    e.path.head? = some (root d (sub m (!b))) := by
  rw [h, path_cons hg]; rfl

theorem side_nonempty {b : Bool} {es : List Entry} {e : Entry} (he : e ∈ es)
    (hg : goes b e = true) : (side b es).isEmpty = false := by
  cases h : (side b es).isEmpty
  · rfl
  · have := side_empty_all h e he; rw [hg] at this; simp at this

theorem fold_complete : ∀ (d : Nat) (m : List Bool → Option Nat) (es : List Entry),
    es ≠ [] → (∀ e ∈ es, e.key.length = d) → Distinct es →
    (∀ e ∈ es, e.pre = m e.key ∧ e.path = path d m e.key) →
    fold d es = some (root d m, root d (upd m es)) := by
  intro d
  induction d with
  | zero =>
    intro m es hne hl hd hh
    match es, hne with
    | [e], _ =>
      have hk : e.key = [] := List.eq_nil_of_length_eq_zero (hl e (List.mem_singleton_self e))
      have hpre := (hh e (List.mem_singleton_self e)).1
      rw [hk] at hpre
      simp [fold, root, upd, hk, hpre]
    | e :: f :: rest, _ =>
      have hke : e.key = [] := List.eq_nil_of_length_eq_zero (hl e (by simp))
      have hkf : f.key = [] := List.eq_nil_of_length_eq_zero (hl f (by simp))
      unfold Distinct at hd
      rw [List.pairwise_cons] at hd
      exact absurd (by rw [hke, hkf]) (hd.1 f (by simp))
  | succ d ih =>
    intro m es hne hl hd hh
    have hlo := side_lengths (b := false) hl
    have hhi := side_lengths (b := true) hl
    have hdlo := side_distinct (b := false) hd
    have hdhi := side_distinct (b := true) hd
    have hhlo : ∀ x ∈ side false es, x.pre = sub m false x.key ∧ x.path = path d (sub m false) x.key := by
      intro x hx
      obtain ⟨y, hy, hgy, rfl⟩ := mem_side.mp hx
      exact honest_down hgy (hh y hy)
    have hhhi : ∀ x ∈ side true es, x.pre = sub m true x.key ∧ x.path = path d (sub m true) x.key := by
      intro x hx
      obtain ⟨y, hy, hgy, rfl⟩ := mem_side.mp hx
      exact honest_down hgy (hh y hy)
    have hagree : ∀ b, agree b (root d (sub m (!b))) es = true := by
      intro b
      rw [agree_spec]
      intro e he hg
      exact honest_head hg (hh e he).2
    obtain ⟨e, rest, rfl⟩ : ∃ e rest, es = e :: rest := by
      cases es with
      | nil => exact absurd rfl hne
      | cons e rest => exact ⟨e, rest, rfl⟩
    have hupd : root (d + 1) (upd m (e :: rest)) =
        .node (root d (upd (sub m false) (side false (e :: rest))))
              (root d (upd (sub m true) (side true (e :: rest)))) := by
      simp only [root]; rw [upd_sub m false _ hl, upd_sub m true _ hl]
    have he : e ∈ e :: rest := by simp
    -- A side any entry goes to is nonempty, and folds by the induction.
    have nonempty_of {b : Bool} {x : Entry} (hx : x ∈ e :: rest) (hg : goes b x = true) :
        side b (e :: rest) ≠ [] := List.ne_nil_of_mem (down_mem hx hg)
    have witness {b : Bool} (h : (side b (e :: rest)).isEmpty = false) :
        ∃ x ∈ e :: rest, goes b x = true := by
      cases hs : side b (e :: rest) with
      | nil => rw [hs] at h; simp at h
      | cons y _ =>
        have hy : y ∈ side b (e :: rest) := by rw [hs]; simp
        obtain ⟨x, hx, hgx, _⟩ := mem_side.mp hy
        exact ⟨x, hx, hgx⟩
    rcases goes_cases (hl e he) with hge | hge
    · -- the first entry goes false
      have hFne := side_nonempty he hge
      have hs : firstSibling (e :: rest) = some (root d (sub m true)) := by
        simp only [firstSibling, List.head?_cons, Option.bind_some]
        exact honest_head hge (hh e he).2
      have hsubF := ih (sub m false) _ (nonempty_of he hge) hlo hdlo hhlo
      cases hT : (side true (e :: rest)).isEmpty
      · -- the keys separate
        obtain ⟨x, hx, hgx⟩ := witness hT
        have hsubT := ih (sub m true) _ (nonempty_of hx hgx) hhi hdhi hhhi
        simp only [fold, hT, hFne, if_false, Bool.false_eq_true, hsubF, hsubT]
        rw [show agree false (root d (sub m true)) (e :: rest) = true from hagree false,
          show agree true (root d (sub m false)) (e :: rest) = true from hagree true]
        rw [hupd]; simp [root]
      · simp only [fold, hT, hFne, if_true, if_false, Bool.false_eq_true, hs,
          show agree false (root d (sub m true)) (e :: rest) = true from hagree false,
          hsubF, Option.map_some]
        rw [hupd, List.isEmpty_iff.mp hT, upd_nil]; simp [root]
    · -- the first entry goes true
      have hTne := side_nonempty he hge
      have hs : firstSibling (e :: rest) = some (root d (sub m false)) := by
        simp only [firstSibling, List.head?_cons, Option.bind_some]
        exact honest_head hge (hh e he).2
      have hsubT := ih (sub m true) _ (nonempty_of he hge) hhi hdhi hhhi
      cases hF : (side false (e :: rest)).isEmpty
      · obtain ⟨x, hx, hgx⟩ := witness hF
        have hsubF := ih (sub m false) _ (nonempty_of hx hgx) hlo hdlo hhlo
        simp only [fold, hTne, hF, if_false, Bool.false_eq_true, hsubF, hsubT]
        rw [show agree false (root d (sub m true)) (e :: rest) = true from hagree false,
          show agree true (root d (sub m false)) (e :: rest) = true from hagree true]
        rw [hupd]; simp [root]
      · simp only [fold, hTne, hF, if_true, if_false, Bool.false_eq_true, hs,
          show agree true (root d (sub m false)) (e :: rest) = true from hagree true,
          hsubT, Option.map_some]
        rw [hupd, List.isEmpty_iff.mp hF, upd_nil]; simp [root]

/-! ## Anti-vacuity: without the checks the fold is sound but not canonical -/

theorem lax_fold_sound : ∀ (d : Nat) (m : List Bool → Option Nat) (es : List Entry)
    (P Q : Dig), (∀ e ∈ es, e.key.length = d) → laxFold d es = some (P, Q) →
    P = root d m → (∀ e ∈ es, e.pre = m e.key) ∧ Q = root d (upd m es) := by
  intro d
  induction d with
  | zero =>
    intro m es P Q hl hf hP
    match es, hf with
    | [e], hf =>
      simp [laxFold] at hf
      obtain ⟨rfl, rfl⟩ := hf
      have hk : e.key = [] := List.eq_nil_of_length_eq_zero (hl e (List.mem_singleton_self e))
      simp [root] at hP
      refine ⟨?_, ?_⟩
      · intro x hx; simp at hx; subst hx; rw [hk]; exact hP
      · simp [root, upd, hk]
  | succ d ih =>
    intro m es P Q hl hf hP
    have hlo := side_lengths (b := false) hl
    have hhi := side_lengths (b := true) hl
    simp only [laxFold] at hf
    split at hf
    · rename_i hT
      split at hf
      · simp at hf
      · split at hf
        · simp at hf
        · obtain ⟨⟨lp, lq⟩, hfl, hpq⟩ := Option.map_eq_some_iff.mp hf
          simp at hpq; obtain ⟨rfl, rfl⟩ := hpq
          simp only [root, Dig.node.injEq] at hP
          obtain ⟨hP1, hP2⟩ := hP
          obtain ⟨hpre, hq⟩ := ih (sub m false) _ lp lq hlo hfl hP1
          refine ⟨?_, ?_⟩
          · intro x hx
            rcases goes_cases (hl x hx) with hg | hg
            · exact pre_down hg (hpre _ (down_mem hx hg))
            · have := side_empty_all hT x hx; rw [hg] at this; simp at this
          · simp only [root]
            rw [upd_sub m false es hl, upd_sub m true es hl, ← hq,
              List.isEmpty_iff.mp hT, upd_nil, ← hP2]
    · split at hf
      · rename_i _ hF
        split at hf
        · simp at hf
        · obtain ⟨⟨hp, hq⟩, hfh, hpq⟩ := Option.map_eq_some_iff.mp hf
          simp at hpq; obtain ⟨rfl, rfl⟩ := hpq
          simp only [root, Dig.node.injEq] at hP
          obtain ⟨hP1, hP2⟩ := hP
          obtain ⟨hpre, hq'⟩ := ih (sub m true) _ hp hq hhi hfh hP2
          refine ⟨?_, ?_⟩
          · intro x hx
            rcases goes_cases (hl x hx) with hg | hg
            · have := side_empty_all hF x hx; rw [hg] at this; simp at this
            · exact pre_down hg (hpre _ (down_mem hx hg))
          · simp only [root]
            rw [upd_sub m false es hl, upd_sub m true es hl, ← hq',
              List.isEmpty_iff.mp hF, upd_nil, ← hP1]
      · split at hf
        · rename_i lp lq hp hq hfl hfh
          simp at hf; obtain ⟨rfl, rfl⟩ := hf
          simp only [root, Dig.node.injEq] at hP
          obtain ⟨hP1, hP2⟩ := hP
          obtain ⟨hpreL, hqL⟩ := ih (sub m false) _ lp lq hlo hfl hP1
          obtain ⟨hpreH, hqH⟩ := ih (sub m true) _ hp hq hhi hfh hP2
          refine ⟨?_, ?_⟩
          · intro x hx
            rcases goes_cases (hl x hx) with hg | hg
            · exact pre_down hg (hpreL _ (down_mem hx hg))
            · exact pre_down hg (hpreH _ (down_mem hx hg))
          · simp only [root]
            rw [upd_sub m false es hl, upd_sub m true es hl, ← hqL, ← hqH]
        · simp at hf

/-- The empty depth-1 tree, and a write set over its two leaves in which one
entry carries a sibling the tree does not hold. -/
def emptyTree : List Bool → Option Nat := fun _ => none

/-- The entry at `[false]`: its first sibling is not the tree's. -/
def bentEntry : Entry :=
  { key := [false], pre := none, post := some 1, path := [.leaf (some 7)] }

def bentWrites : List Entry :=
  [ bentEntry, { key := [true], pre := none, post := none, path := [.leaf none] } ]

/-- Without the checks, a write set carrying a sibling that is not the tree's
folds from the tree's own root — the same move has another encoding — and the
checked fold refuses it. -/
theorem lax_fold_is_not_canonical :
    (∃ Q, laxFold 1 bentWrites = some (root 1 emptyTree, Q)) ∧
    (bentEntry ∈ bentWrites ∧ bentEntry.path ≠ path 1 emptyTree bentEntry.key) ∧
    fold 1 bentWrites = none := by
  refine ⟨⟨.node (.leaf (some 1)) (.leaf none), ?_⟩, ⟨by simp [bentWrites], ?_⟩, ?_⟩
  · decide
  · decide
  · decide

#print axioms fold_sound
#print axioms fold_complete
#print axioms fold_canonical
#print axioms lax_fold_sound
#print axioms lax_fold_is_not_canonical

end DSMStepTransition
