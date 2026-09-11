# Amendment 2c-G — owner catch-up and owner-side economic admission: survey and rulings draft

> **STATUS: DRAFT FOR OWNER RULING. Nothing in this document is frozen, and it changes no code.**
>
> Base: `main` at `5133eaa2` (2c-F, #859 and #860).

**Sources.** Revision 15 is quoted from `.github/instructions/sofispecs.instructions.md` as `spec:N`.
Code paths are relative to `dsm_client/deterministic_state_machine/`.

---

## 1. Existing normative state

- **Req 4.5** (spec:552, "DLV exception to pending and owner catch-up"): if the LP returns while the
  DLV remains active, *"it must deterministically catch that relationship state up through the DLV
  market successors that were already realized. Catch-up records the DLV market history into a fresh
  owner-authenticated baseline; it neither moves the reserve value a second time nor constitutes a
  new approval, veto, rollback, or ordering step."*
- **Req 6.31** (spec:1236, "Owner catch-up baseline"): the caught-up owner state *"must commit a fresh
  DLV baseline/anchor. Later market composition may begin from that baseline."* It records the current
  reserves, re-transfers nothing to or from the owner's balance, and sets no limit on how long the
  owner may be absent. A terminal close under Req 6.30 needs no separate catch-up.
- **2c-D §14, C2-R1 point 6.** The owner apply acts only on the exact fold the walk certified.
- **2c-D §14, the owner-apply boundary.** Owner apply's bypass of economic admission *"may remain
  separately owed only if C2 proves it cannot invent or modify economics"*. The test
  `an_owner_apply_applies_only_the_exact_certified_fold` pins that.
- **2c-D §14, D-g.** The composed-state rule is *latest authenticated owner baseline + every later
  realized successor*. Owner backing is read at one baseline generation. Catch-up is
  *"optional synchronization of already-realized history; it authorizes nothing."*
- **Core write sets** (3.6 PR1–PR4, `dsm/src/economic/write_set.rs`):
  - `DlvOwnerApply`: the input reserve gains the input amount, the output reserve loses the output
    amount, and both reserves must exist **at exactly the parent generation**.
  - `DlvWithdraw`: the close. One generation step, and it leaves a terminal zero leaf.
  - The apply's input credit is funded by the `0x0027` settlement-payment arm (`provenance.rs:1438+`).
    Its evidence (`dsm/src/economic/settlement_payment_evidence.rs`) is the trader's `0x0021`
    settlement-receipt leaf and its 256 siblings, proven into the independently derived
    `ValidatedEconomicRoot(trader_economic_position)`.

## 2. Shipped behaviour at `5133eaa2`

| Route | Economic admission | What moves |
|---|---|---|
| `dlv.create` (funded) | **yes** — `admitted_dlv_create_funded` (`economic_admission_flow.rs:658`) | the owner's `R_econ` gains the vault-reserve leaves at generation 0 |
| market settle | **yes** — `admitted_dlv_settle` (`:822`) | the trader's `R_econ` |
| `dlv.reconcile` (owner apply) | **no** — `execute_on_relationship_with_reserve_mutation` (`dlv_routes.rs:1966`) | device reserve leaves only; the owner's `R_econ` reserve leaf never moves |
| `dlv.close` | **no** | device balance only; the `R_econ` reserve leaf is never withdrawn |

Further facts:

- **Composition's baseline is the owner's birth `AnchorPresentationV3`.** It is built by
  `build_vault_publication_artifacts` (`dlv_routes.rs:4375`), which birth and close call. Nothing
  re-anchors after an apply.
- **There is no SDK producer for the `0x0027` evidence.** Core has only the decoder and the verifier
  arm.
- **`unapplied_settlements_for_vault`** (`sdk/vault_rehydration.rs:294`) already lists certified,
  unapplied folds in generation order. Only the owner display uses it.
- **Closed since the 2026-08-31 route-wiring note:**
  - the admission pre-state carries reserve leaves (`economic_admission_flow.rs:169`, `:212`);
  - the `immutable_addr` misuse in provenance is fixed;
  - the admitted advance exists (`core_sdk.rs:1714`) and create and settle use it.

## 3. Consequences — why this is on the critical path

The owner's `R_econ` reserve leaf stays at the birth generation. After K market trades:

1. **An owner apply for generation n cannot be admitted until applies 0…n−1 are**, because the write
   set requires the reserve leaf at exactly the parent generation.
2. **A close cannot be admitted until all K applies are.**
3. **Close proceeds never reach `R_econ`.** The owner therefore cannot spend them in any admitted
   operation; a new `dlv.create`, for example, funds only from `R_econ`. The roadmap line *live DLV
   create/close + settle/apply → fresh-identity two-asset E2E* cannot close today.
4. **Owner backing stays at generation 0**, so every settle's provenance composes the whole history
   from birth. That is correct, but the walk grows without bound.

**This is not a safety defect.** Nothing unadmitted is counted as admitted. It is a completeness gap
on the owner's side of the lifecycle.

## 4. Proposed rulings (smallest)

- **G1 — admit the owner apply.** `dlv.reconcile` runs economic admission of `DlvOwnerApplyV2` through
  the existing admitted advance. The `0x0027` evidence is built from the certified fold's own
  Req 21.16 material: the trader's `0x0021` receipt leaf and its path under `R_T^+`, which the walk
  already fetched and verified. That needs no new transport, to be confirmed at implementation. The
  apply still acts only on the exact certified fold, and consume-once is unchanged.
- **G2 — catch-up is the ordered sequence of admitted applies.** Req 4.5's deterministic catch-up
  applies every certified, unapplied fold, oldest generation first. It runs automatically when the
  owner is online (`storage.sync`) and on explicit request. It stops at the first generation the walk
  has not certified, is idempotent, and gates nothing.
- **G3 — a fresh owner baseline after catch-up** (Req 6.31). Once caught up, the owner publishes an
  `AnchorPresentationV3` over the caught-up `c_n` through the same `build_vault_publication_artifacts`
  path birth and close use, and composition may begin from the latest owner baseline. It authorizes
  nothing: backing comes from `R_econ`, which G1 advances.
- **G4 — admit the close.** `dlv.close` runs admission of `DlvClose` (`DlvWithdraw`). Today's "close
  refused while a settlement is unreconciled" gate becomes the admission's own precondition — the
  owner's reserve leaf at the close's parent generation — the same condition, now enforced
  economically.

## 5. Alternatives where a real choice exists

| Choice | Recommended | Alternative | Why |
|---|---|---|---|
| Catch-up form | G2: one admitted `DlvOwnerApplyV2` per settlement | a single collapsing catch-up transition | per-settlement reuses a frozen operation, its write set and its credit arm; a collapsing transition needs a new operation, write set and provenance arm |
| Trigger | automatic on `storage.sync`, plus explicit | explicit only | Req 4.5 says *must* |
| Baseline | publish after every catch-up (G3) | only on demand, or defer | composition from birth stays correct, so deferral costs walk length, not safety |
| Close before catch-up | refuse (as today) | catch up automatically inside `dlv.close` | keeps one route doing one thing |
| Delivery | three sequential PRs: (1) G1 + G2, (2) G4, (3) G3 | one PR | G4 depends on G1; G3 is independent of both |

## 6. Boundaries these rulings keep

These are C2's and 2c-F's, unchanged:

- C2 realization stays authoritative.
- Catch-up creates no second realization boundary and no owner approval in market settlement.
- The composed-state / offline-LP rule is unchanged: catch-up is synchronization, never
  authorization.
- No bypass of `validated_root_or_activate`, and nothing admitted without its write set and credit
  arms.

## 7. Work these rulings would unlock (not started)

1. **`0x0027` producer** (SDK). Build `SettlementPaymentEvidenceV1` from the certified fold's
   Req 21.16 material. Verify that the fold retains the trader's receipt leaf and siblings; if not,
   carry them the way `certified_acceptance` was carried for 2c-F.
2. **`admitted_dlv_owner_apply`** in `economic_admission_flow.rs`, and the route swap in
   `dlv.reconcile`.
3. **The catch-up pass**, beside D-f and the receipt recovery in `storage.sync`, applying folds in
   generation order.
4. **`admitted_dlv_close`**, and the route swap in `dlv.close`.
5. **The re-anchor**: a third caller of `build_vault_publication_artifacts`, plus composition
   starting from the latest owner baseline.
6. **Tests and controls**:
   - an LP offline for K trades returns, catches up and closes, with every step admitted;
   - catch-up stops at an uncertified generation;
   - an apply out of order is refused;
   - close proceeds are spendable by a subsequent admitted `dlv.create`;
   - mutation controls on the ordering, the certified-only rule and the consume-once rule;
   - a Lean model of catch-up as ordered application that authorizes nothing.
