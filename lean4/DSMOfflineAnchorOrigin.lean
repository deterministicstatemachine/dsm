/-
  DSM Offline Anchor Origin Uniqueness — self-contained Lean 4 (no Mathlib)

  v2 ("Software Authority, Hardware Identity", July 2026) offline instantiation
  of the general key-scoped uniqueness theorem in lean4/DSMGuardedTripwire.lean
  (`realized_unique_at_key`, paper Theorem 2 of "DSM as Guarded Linear Constraint
  Systems"). The abstract resource-consumption key is instantiated by the SMT
  ANCHOR ORIGIN (R_i, h_i, u_i): parentRoot = R_i (device SMT root), descriptor =
  (h_i, u_i) (offline frontier root + committed SMT anchor counter). Because the
  anchor origin embeds injectively into that key space (`keyOf_inj`), the general
  key-scoped uniqueness result specializes to origin uniqueness proved here.

  The result proved DIRECTLY, structurally, axiom-free:
    a correct enrolled appliance emits AT MOST ONE committed package per anchor
    origin. Not "two collide later", not "detected on reconciliation" — the
    second one cannot be constructed inside the appliance discipline.

  This is the v2 REPLACEMENT for the boot-fenced lean4/DSMGuardedOffline.lean.
  It uses NO fused anchor head, NO boot head, and NO boot ticket (all removed by
  the correction). Uniqueness is a software property of the SMT counter leaf and
  the single-prepared-record / atomic-counter-advance discipline; no hardware
  term appears in any proof (Corollary 1 / Hardware Independence).

  Paper map ("Software Authority, Hardware Identity"):
    - Def 6 (Whole State Consumption) + Def 7 (Offline Origin)  -> AnchorOrigin
    - Def 5 (Counter Synchronized State), atomic advance u_i+1  -> WellFormedCommit
    - Theorem 1 (Adopted Frontier Software Exclusion),
        appliance-producer form                                -> offline_anchor_origin_unique
                                                                  committed_record_unique_per_anchor_origin
    - general Theorem 2 (DSMGuardedTripwire.realized_unique_at_key) via keyOf_inj

  Companion model-check: tla/DSM_OfflineAnchorSingleAppliance.tla.
  Run: `lean DSMOfflineAnchorOrigin.lean`.
-/

-- ============================================================
-- Anchor origin (R_i, h_i, u_i) and its embedding into the general key
-- ============================================================

/-- The offline origin of a transfer (paper Def 7): device SMT root `R_i`, the
    offline frontier root `h_i`, and the committed SMT anchor counter `u_i`. -/
structure AnchorOrigin where
  root     : Nat   -- R_i
  frontier : Nat   -- h_i
  counter  : Nat   -- u_i
deriving DecidableEq, Repr

/-- The general resource-consumption key of DSMGuardedTripwire.lean, specialized
    to the anchor origin: parentRoot = `R_i`; descriptor = the pair `(h_i, u_i)`.
    The bilateral instantiation maps parentRoot ↦ device root and descriptor ↦
    (relationship, tip); here it maps to (frontier, counter). -/
def keyOf (o : AnchorOrigin) : Nat × Nat × Nat := (o.root, o.frontier, o.counter)

/-- The anchor origin embeds INJECTIVELY into the general resource-consumption
    key space: same key ⇔ same origin. Hence the general key-scoped uniqueness
    theorem `realized_unique_at_key` (paper Theorem 2), instantiated at key
    `keyOf o`, specializes to the anchor-origin uniqueness proved below — the
    offline anchor origin is a legitimate consumption key. -/
theorem keyOf_inj (o o' : AnchorOrigin) (h : keyOf o = keyOf o') : o = o' := by
  cases o with
  | mk r f c =>
    cases o' with
    | mk r' f' c' =>
      injection h with hr hrest
      injection hrest with hf hc
      subst hr; subst hf; subst hc; rfl

-- ============================================================
-- The offline-bearer appliance step (v2: no boot head / anchor head)
-- ============================================================

/-- Forward-only offline frontier advance h_{i+1} = H(tag ‖ h_i ‖ D_{i+1})
    (paper Def, Offline Frontier Root). A pure function of the frontier and the
    transition digest `content`; its concrete shape is immaterial, only that it
    is a function. -/
def nextFrontier (h content : Nat) : Nat := h * 8 + content

/-- Successor device SMT root R_{i+1} recomputed from the bound fields (the SDK
    computes the real root; here a pure function witnessing determinism). -/
def nextRoot (R h u content : Nat) : Nat := R * 100 + h * 10 + u + content * 1000

/-- A committed offline-bearer package: the origin it consumes, the transition
    digest `content` (D_{i+1}), and the successor coordinates. -/
structure Package where
  origin  : AnchorOrigin
  content : Nat            -- D_{i+1}
  nextU   : Nat            -- u_{i+1}
  nextH   : Nat            -- h_{i+1}
  nextR   : Nat            -- R_{i+1}
deriving DecidableEq, Repr

/-- A well-formed committed package from origin `o` with transition digest
    `content`. Captures the load-bearing discipline of the v2 appliance:
      * AtomicCounterAdvance  — `nextU = u_i + 1` (the SMT counter leaf advances
        by exactly one, atomically with the transfer);
      * SMTAnchorLeafAdvance  — `nextH` / `nextR` recompute forward-only from the
        bound fields. -/
def WellFormedCommit (o : AnchorOrigin) (p : Package) : Prop :=
  p.origin = o
  ∧ p.nextU = o.counter + 1
  ∧ p.nextH = nextFrontier o.frontier p.content
  ∧ p.nextR = nextRoot o.root o.frontier o.counter p.content

-- ============================================================
-- committed_record_unique_per_anchor_origin (mechanical form)
-- ============================================================

/-- Given the appliance discipline — a single prepared record per origin (both
    commits carry the SAME `content`, `hc`), atomic counter advance and SMT-leaf
    advance (`h₁`, `h₂`) — two committed packages from the SAME anchor origin are
    identical. PROVED structurally, axiom-free. -/
theorem committed_record_unique_per_anchor_origin
    (o : AnchorOrigin) (p₁ p₂ : Package)
    (hc : p₁.content = p₂.content)       -- SinglePreparedRecordDiscipline
    (h₁ : WellFormedCommit o p₁)         -- AtomicCounterAdvance ∧ SMTAnchorLeafAdvance
    (h₂ : WellFormedCommit o p₂) :
    p₁ = p₂ := by
  have horigin : p₁.origin = p₂.origin := by rw [h₁.1, h₂.1]
  have hu : p₁.nextU = p₂.nextU := by rw [h₁.2.1, h₂.2.1]
  have hh : p₁.nextH = p₂.nextH := by rw [h₁.2.2.1, h₂.2.2.1, hc]
  have hr : p₁.nextR = p₂.nextR := by rw [h₁.2.2.2, h₂.2.2.2, hc]
  calc p₁ = ⟨p₁.origin, p₁.content, p₁.nextU, p₁.nextH, p₁.nextR⟩ := rfl
    _ = ⟨p₂.origin, p₂.content, p₂.nextU, p₂.nextH, p₂.nextR⟩ := by
          rw [horigin, hc, hu, hh, hr]
    _ = p₂ := rfl

-- ============================================================
-- offline_anchor_origin_unique (appliance form)
-- ============================================================

/-- A correct enrolled appliance, as a partial function from an anchor origin to
    the SINGLE transition digest it prepared there (if any). The functionality of
    `Appliance` IS the single-prepared-record discipline (paper §13.1: "exactly
    one prepared record may exist per frontier"). -/
abbrev Appliance := AnchorOrigin → Option Nat

/-- `CommitFrom a o p`: appliance `a` commits package `p` from anchor origin `o`
    — `p`'s digest is the one `a` prepared at `o`, and `p` is well formed. -/
def CommitFrom (a : Appliance) (o : AnchorOrigin) (p : Package) : Prop :=
  a o = some p.content ∧ WellFormedCommit o p

/-- MAIN RESULT (appliance-producer form of Theorem 1). A correct appliance emits
    at most one committed package per anchor origin: two commits from the SAME
    origin are equal. The single prepared digest per origin (`a o`) forces equal
    `content`; atomic counter advance and SMT-leaf recompute then force every
    successor field equal. Axiom-free; no hardware term. -/
theorem offline_anchor_origin_unique
    (a : Appliance) (o : AnchorOrigin) (p₁ p₂ : Package)
    (h₁ : CommitFrom a o p₁) (h₂ : CommitFrom a o p₂) : p₁ = p₂ := by
  have hc : p₁.content = p₂.content := by
    have e1 : a o = some p₁.content := h₁.1
    have e2 : a o = some p₂.content := h₂.1
    have hsome : some p₁.content = some p₂.content := by rw [← e1, e2]
    exact Option.some.inj hsome
  exact committed_record_unique_per_anchor_origin o p₁ p₂ hc h₁.2 h₂.2

-- ============================================================
-- Non-vacuity + teeth
-- ============================================================

/-- Non-vacuity: a genuine well-formed commit from any origin exists. -/
theorem commit_inhabited (o : AnchorOrigin) (content : Nat) :
    ∃ p : Package, WellFormedCommit o p := by
  refine ⟨⟨o, content, o.counter + 1, nextFrontier o.frontier content,
           nextRoot o.root o.frontier o.counter content⟩, ?_⟩
  exact ⟨rfl, rfl, rfl, rfl⟩

/-- TEETH: the single-prepared-record discipline is LOAD-BEARING. Two DISTINCT
    transition digests from the SAME origin yield two DISTINCT well-formed
    packages (a genuine fork). Uniqueness therefore rests on the appliance
    committing one digest per origin — not on structural recompute alone. This
    proves `offline_anchor_origin_unique` is not vacuously true. -/
theorem distinct_content_forks (o : AnchorOrigin) (c₁ c₂ : Nat) (hne : c₁ ≠ c₂) :
    ∃ p₁ p₂ : Package,
      WellFormedCommit o p₁ ∧ WellFormedCommit o p₂ ∧ p₁ ≠ p₂ := by
  refine ⟨⟨o, c₁, o.counter + 1, nextFrontier o.frontier c₁,
           nextRoot o.root o.frontier o.counter c₁⟩,
          ⟨o, c₂, o.counter + 1, nextFrontier o.frontier c₂,
           nextRoot o.root o.frontier o.counter c₂⟩,
          ⟨rfl, rfl, rfl, rfl⟩, ⟨rfl, rfl, rfl, rfl⟩, ?_⟩
  intro h
  have hcc : c₁ = c₂ := congrArg Package.content h
  exact hne hcc

-- ============================================================
-- Summary
-- ============================================================
-- Discharged, zero `sorry` / `admit`, zero axioms:
--   keyOf_inj                                 (origin embeds injectively into
--                                              the general resource key)
--   committed_record_unique_per_anchor_origin (mechanical uniqueness)
--   offline_anchor_origin_unique              (appliance-producer form of Thm 1)
--   commit_inhabited                          (non-vacuity)
--   distinct_content_forks                    (teeth: discipline is load-bearing)
-- No boot head / anchor head / boot ticket; no hardware term in any proof.
