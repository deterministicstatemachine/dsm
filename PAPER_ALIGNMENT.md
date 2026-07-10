# Paper alignment: "DSM as Guarded Linear Constraint Systems" (June 2026 PDF)

Edits required to bring the paper text into exact agreement with the
machine-checked artifacts now in this repo. The PDF source is not in this
workspace, so this file is the authoritative edit list until the LaTeX is
updated and recompiled. Repo state as of this file: all five guarded TLC
configs behave as documented in `tla/README.md`, both guarded Lean files check
with exit 0, and the Rust reference passes 8/8.

## 1. Root self-reference in the definitions (spec text bug)

G6 commits the guard family under `rho_s`, while G1 and Def 14(1) require every
guard descriptor to contain the canonical digest of parent state s. If that
digest is `rho_s`, the cycle `rho -> Gamma -> g -> rho` is unconstructible as a
hash DAG. The same cycle runs through candidates: P(s) commits
`d_i = H(enc(s_i))` (Def 11, Def 36(2)), `enc(s_i)` covers
`Sigma_{s_i} = Sigma_s u K_b` (Def 31(2)), and `K_b` contains
`kappa_res(s, x) = H(tag || rho_s || x)` (Def 27), so
`rho_s -> P -> d_i -> Sigma_{s_i} -> kappa_res -> rho_s`.

Fix, pick one and state it explicitly:

- Layered root: `rho_core = SMT(R, u, Sigma, Pi, Omega)`; guards, keys, and
  candidate digests bind `rho_core`; the full root is
  `H(rho_core || digest(P) || digest(Gamma))`.
- Precommitment as its own realized step: candidates bind the root of the state
  being extended, so the family committed at step n constrains step n+1.

The Lean model already reflects the acyclic reading: `ResKey` is the pair
(parent root, resource descriptor) the digest commits to, and the successor is
a pure function of (parent, branch). No artifact change needed; paper text only.

## 2. Theorems 2, 4, 11 (and the cut restatement, Thm 7): static form needs its
##    hypothesis stated; trace form should be added

As written, Theorem 2 quantifies over the stateless Step predicate. For a
family whose conflict class relies on G7 alone (same derived key set, different
successors, multiple guards simultaneously fulfilled, the Section 19 case), two
distinct candidates can both satisfy every conjunct of Step at the same parent:
LinearityOK checks the key against the same unconsumed `Sigma_s` for both. What
excludes co-realization there is the ledger update, which is temporal. The
paper's own proofs of Prop 10 and Thm 1 say this ("once one branch realizes,
that key set is recorded").

The artifacts now check both readings, so the paper should state both:

- Static form (keep Thms 2 and 4, add the hypothesis): "for a guard family that
  is well formed in the sense that any two fulfilled branches sharing a resource
  key resolve to the same canonical successor (G5, or G7 with shared canonical
  successor recomputation), Step_K(s, s1) and Step_K(s, s2) imply s1 = s2."
  Machine checked: `realized_unique_at_key` in `lean4/DSMGuardedTripwire.lean`
  (no axioms) and invariant `Safety` in `tla/DSM_Guarded.tla`
  (`DSM_GuardedMC_WF.cfg`, No error). The hypothesis is load bearing:
  `malformed_family_admits_fork` (Lean) and `DSM_GuardedMC_Fork.cfg` (TLC,
  violated at depth 0) falsify the statement without it.
- Trace form (add as the operational theorem): "the realized history of a
  verifier never contains two accepted receipts consuming the same
  (parent, key) with different successors." Machine checked: invariant
  `RealizedHistoryUnique` in `tla/DSM_Guarded.tla`; it holds at a single honest
  verifier EVEN for a key-split family (`DSM_GuardedMC_Fork_Ledger.cfg`,
  No error), which is exactly Prop 11. Theorem 11 and the Thm 7 cut-freeness
  restatement should be reworded the same way: invariants of reachable realized
  histories, not of the stateless predicate.

Also add a remark after Remark 5 or in Sec 23: the "different receivers accept
conflicting packages" shape of Definition 1 cannot arise for online
relationship resources, for two structural reasons. The derived consumption
key embeds the relationship identity (Def 27, Def 33, Rule 2), so every
relationship is its own straight hash chain and a parent under relationship r
is not replayable under q (Sec 6). And the topology is bilateral: the acceptor
of a relationship step is exactly that relationship's counterparty, so there
is no second independent receiver of the same relationship parent in online
operation. Machine checked: `tla/DSM_GuardedMC_BilateralWF.tla` deliberately
includes an attempted same-parent conflict in the committed family and TLC
proves no same-parent fork anywhere in the system in every interleaving;
`tla/DSM_GuardedMC_BilateralFork.tla` is the structure-removed contrast, where
the fork appears only after deleting derived keys and the single-receiver
topology, neither of which exists in online DSM. Multi-receiver presentation
of one spendable object exists only in offline bearer mode and is governed
there by the fused anchor, the Def 56 pending lock, the offline anchor
design's co-signed precommit, and reconciliation (Sec 29, Thm 14).

## 3. K is overloaded across steps (Def 53, Thms 5, 6, 10)

`kappa_res` binds `rho_s`, so the key consumed at step n cannot literally equal
the key at step n+1, yet Def 53 and Thms 5, 6, 10 write
`s0 ->K s1 ->K s2 ...` with fixed K. Introduce a lineage identifier (the
resource descriptor family modulo generation index) for those statements, and
reserve K for the per-step key as in Defs 42 and 44. The Lean `ResKey`
structure makes the per-step reading explicit already.

## 4. Appendix A (Lean skeleton): replace with the artifact

Replace the skeleton with a pointer to `lean4/DSMGuardedTripwire.lean` and
`lean4/DSMOfflineAnchorOrigin.lean` (the offline-anchor instantiation). Two
defects of the printed skeleton, both fixed in the artifact:

- `deriving DecidableEq` on a structure with function-typed fields
  (`relHead : String -> Nat`, `consumed : String -> Bool`) does not elaborate.
- The load-bearing claim was `axiom structural_linearity_unique_at_key`. It is
  now the proved theorem `realized_unique_at_key`; `#print axioms` confirms the
  uniqueness/tripwire core depends on no axioms.

## 5. Appendix B (TLA+ skeleton): replace with the artifact

Replace the skeleton with a pointer to `tla/DSM_Guarded.tla`,
`tla/DSM_GuardedBilateral.tla`, and the five configs listed in `tla/README.md`.
Defects of the printed skeleton, fixed in the artifact:

- `DisjointProgressAllowed` applied `Step(s, s1)` but the skeleton's `Step` is
  unary over candidates, and `ConsumptionKeys` was undefined. The module states
  `DisjointProgressPossible` over two candidates sharing a parent with distinct
  keys and successors, plus the App B form over `StepAtKey`.
- The skeleton had no realized-history state, so the trace-level theorem was
  not checkable. The module carries a `ledger` and checks
  `RealizedHistoryUnique`.

## 6. Claim boundary sentence (Sec 31 or Sec 36)

Add: "The general key-scoped theorems of Sections 10 through 16 are machine
checked in Lean 4 over the abstract guarded model, TLC model checks concrete
well-formed and deliberately malformed instances of both the static and the
trace-level statements, the relationship-scoped bilateral model verifies that
same-parent multi-receiver forks are unconstructible in online DSM, and the
bilateral-tip instantiation is separately TLC-checked in the concrete protocol
model (`DSM_Tripwire.tla`). TLAPS mechanization of the guarded kernel, the
category-theoretic layer, and the Section 19 multi-party composition remain
future work."

## 7. Housekeeping

The June 30 `DSM_GuardedMC_Fork_TTrace_*.bin` files in `tla/` were produced by
the pre-merge falsification harness and are superseded; safe to delete. TLC
regenerates `*_TTrace_*` artifacts on every expected-violation run.
