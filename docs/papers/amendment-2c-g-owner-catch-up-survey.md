# Amendment 2c-G — owner catch-up and owner-side economic admission: survey and rulings

> **STATUS: FROZEN — owner rulings of 2026-09-11, recorded verbatim in §0.** §1–§7 are the survey as
> it was put for ruling; where they differ from §0, §0 governs. Delivery is three sequential PRs,
> each cut from updated `main` after its predecessor merges: PR 1 = G1 + G2, PR 2 = G4, PR 3 = G3.
>
> Base: `main` at `5133eaa2` (2c-F, #859 and #860).

**Sources.** Revision 15 is quoted from `.github/instructions/sofispecs.instructions.md` as `spec:N`.
Code paths are relative to `dsm_client/deterministic_state_machine/`.

---

## 0. Owner rulings (2026-09-11), verbatim

### G1 + G2 — ordered admitted applies, as materialization only

```text
G1 + G2 RULING

Choose option 1: Ordered admitted applies.

Implement owner catch-up by applying the already-certified settlements in causal
order, oldest generation first, using the existing DlvOwnerApplyV2 machinery.

Do NOT introduce a new collapsing wire transition.

However, freeze the semantics explicitly:

- DlvOwnerApplyV2 during catch-up is a MATERIALIZATION / SYNCHRONIZATION step.
- It does not authorize the underlying market transition.
- It does not move value a second time.
- It does not re-certify the settlement.
- It does not create a new realization boundary.
- It does not give the owner a veto over an already-realized market successor.
- It does not change ordering; ordering comes from the already-certified DLV
  history.
- It does not make future trader admission depend on owner catch-up.
- It cannot manufacture authority from an uncertified settlement.

For a catch-up from owner baseline V_g to composed frontier V_n:

1. Start from the owner's last authenticated baseline.
2. Enumerate exactly the already-certified realized successors
   V_(g+1) ... V_n in causal order.
3. For each one, materialize the existing certified economic effect through the
   existing owner-apply write-set machinery.
4. Each step must be derived from the exact certified fold / Req 21.16 evidence
   already accepted for that settlement.
5. No fresh market choice, route choice, reserve choice, amount choice, fee
   choice, successor choice, or storage-set choice is permitted.
6. The terminal owner state must equal the current composed DLV frontier exactly.
7. After completion, that terminal owner state becomes the new authenticated
   owner baseline, collapsing the already-verified history for future reads.

Failure partway through catch-up is local/recoverable:
- resume from the last successfully materialized certified generation;
- never replay an already-applied generation as new value movement;
- never roll back the composed DLV frontier;
- never affect trader settlement finality.

Required invariant:

    owner catch-up consumes certified history;
    it never creates certified history.

Add tests proving:
- multiple generations can accumulate while LP is offline;
- catch-up later applies them oldest-first;
- final owner baseline equals composed frontier;
- no owner action existed between those trades;
- an uncertified generation cannot be materialized;
- altered reserves / parent / generation / receipt evidence are refused;
- partial catch-up resumes idempotently;
- catch-up never changes the already-realized trader-visible frontier.
```

### G2 — when catch-up runs

```text
G2 RULING — WHEN OWNER CATCH-UP RUNS

Choose option 1: Auto on sync + explicit.

Use one shared idempotent catch-up core, reachable from:

1. storage.sync / normal online synchronization; and
2. an explicit owner-triggered catch-up operation/API.

Automatic catch-up semantics:

- When the owner is online and storage.sync discovers certified DLV generations
  beyond the owner's current authenticated baseline, it should attempt catch-up.
- Apply only already-certified realized successors, oldest generation first.
- Stop at the current composed frontier that is actually available and certified.
- A successful partial pass may advance the owner baseline through the generations
  that were materialized successfully.
- A later sync resumes from that new baseline.
- Running sync repeatedly with nothing new is a no-op.

Explicit catch-up semantics:

- The explicit path invokes the exact same catch-up engine.
- It does not have stronger authority than automatic sync.
- It cannot choose different history, reserves, ordering, or successors.
- It is useful for manual repair, diagnostics, and forcing synchronization now.

CRITICAL AUTHORITY BOUNDARIES

Catch-up must never gate:

- trader settlement;
- market realization;
- composition;
- future trader admission;
- QuorumBind;
- fence release;
- close finality.

Owner absence therefore remains harmless to continued delegated trading.

Catch-up failure is LOCAL synchronization failure only.

If automatic catch-up fails:
- report/log the failure;
- retain the last successfully materialized owner baseline;
- do not roll back composed state;
- do not invalidate already-realized settlements;
- retry on a later sync or explicit request.

Do not make "owner is online" a protocol precondition for anything.

The automatic path must not create an infinite/re-entrant sync loop.
storage.sync may invoke catch-up, but catch-up must not recursively invoke the
same sync entrypoint.

Use tests for:
- owner offline through multiple trades, then sync catches up automatically;
- explicit catch-up reaches the same exact state;
- repeated automatic/explicit calls are idempotent;
- partial failure resumes from the last applied generation;
- catch-up failure does not affect trader-visible frontier;
- nothing to catch up => no writes;
- automatic and explicit paths produce byte-identical terminal owner state.
```

### G3 — a fresh owner baseline after every catch-up

```text
G3 RULING — FRESH OWNER BASELINE

Choose option 1: publish a fresh owner baseline after every successful catch-up.

After owner catch-up has materialized certified history through V_n:

1. Construct a fresh AnchorPresentationV3 using the SAME canonical owner-anchor
   machinery already used for the birth/owner baseline path.

2. The new anchor MUST commit to exactly the terminal caught-up state V_n.

3. Publish it only after the catch-up through V_n has completed successfully.

4. Once authenticated and published, V_n becomes the new owner baseline for
   future composition.

5. Future composition may begin from that newest authenticated baseline rather
   than replaying certified history from birth.

CRITICAL SEMANTICS

The new anchor is a baseline-collapse / synchronization artifact only.

It does NOT:

- authorize any of the settlements it summarizes;
- re-certify them;
- move value;
- change their order;
- create a second realization boundary;
- permit rollback of the already-composed frontier;
- give the owner a veto;
- alter trader settlement finality.

The authority chain remains:

    old authenticated owner baseline
        + ordered certified realized successors
        -> exact caught-up V_n
        -> fresh owner-authenticated baseline for V_n

The fresh anchor may summarize that already-established history, but it may not
change it.

PARTIAL FAILURE

If catch-up stops at V_k before reaching V_n:

- publish a fresh baseline only for V_k if V_k was fully and successfully
  materialized;
- never anchor a partially applied generation;
- later catch-up resumes from authenticated V_k;
- the trader-visible composed frontier may remain ahead at V_n.

Do not require the owner baseline to equal the current trader-visible frontier
at every moment.

ANCHOR VALIDITY

Before accepting the new baseline:

- exact vault identity must match;
- generation must equal the successfully materialized generation;
- parent/history linkage must correspond to the certified chain just consumed;
- reserves and all canonical vault fields must equal the caught-up terminal state;
- storage-set coordinates must be the authenticated ones for that state;
- owner authentication/signature must verify under the existing owner identity;
- canonical encoding and address/CCB checks must pass.

No caller-supplied replacement reserves, generation, parent, or storage set.

IDEMPOTENCE

Re-running catch-up when the owner is already anchored at V_n:

- performs no economic writes;
- does not create a semantically different anchor;
- does not move the baseline backwards;
- does not replay settlements as value movement.

TESTS

Prove:

- owner starts at V0;
- several certified trades realize while owner remains offline;
- catch-up materializes V1...Vn in order;
- fresh anchor is published for exactly Vn;
- subsequent composition starts from Vn rather than birth;
- resulting composed frontier is identical either way;
- partial catch-up anchors only the last fully applied generation;
- stale/altered anchor data is refused;
- an uncertified successor can never be absorbed into a fresh baseline;
- repeated catch-up/re-anchor is idempotent.
```

### G4 and delivery — three sequential PRs

```text
G4 / DELIVERY RULING

Choose option 1: three sequential PRs.

PR 1 — G1 + G2
Owner catch-up execution.

Implement:
- admitted ordered DlvOwnerApplyV2 catch-up;
- automatic-on-sync + explicit catch-up entrypoints;
- oldest-first consumption of already-certified realized successors;
- idempotent partial-progress/restart behavior.

This PR owns the executable catch-up semantics.

Merge PR 1 before beginning the dependent G4 implementation.

PR 2 — G4
Admitted terminal close.

Cut this branch from updated main AFTER PR 1 merges.

Close must use the same corrected economic-admission foundation established by
PR 1. Do not duplicate or bypass that machinery.

Critical close boundaries:

- close authority remains owner authority;
- close cannot operate from a stale owner-materialized baseline while a newer
  certified composed DLV frontier exists;
- any required catch-up consumes the already-certified frontier and is not
  owner approval of those settlements;
- close admission must correspond to the exact current authoritative/composed
  vault state;
- no skipped realized generations;
- no caller-selected reserves, generation, parent or storage set;
- no close may erase, replace or roll back a realized market successor;
- terminal close remains distinct from market realization;
- existing QuorumBind / accepted-successor / close-auth rules remain intact.

Add negative tests for stale-baseline close, skipped generation, altered
reserves, wrong parent, uncertified predecessor and attempted close against a
frontier that has not been correctly caught up/admitted.

PR 3 — G3
Fresh owner re-anchor / baseline collapse.

Cut this branch from updated main AFTER PR 2 merges.

Implement the fresh AnchorPresentationV3 baseline publication using the
already-working catch-up path.

This PR owns:
- publishing the exact caught-up V_n as the new owner baseline;
- restarting composition from that baseline;
- partial catch-up anchoring only the last fully materialized generation;
- idempotent re-anchor behavior.

Do not make re-anchoring a prerequisite for trader execution or settlement.

DELIVERY RULE

These are sequential dependencies, not stacked review branches:

    main
      -> PR1 merge
      -> updated main
      -> PR2 merge
      -> updated main
      -> PR3 merge

Each PR must independently pass its full tests, mutations, lint, safety checks
and head-sync gate before merge.

Do not start the next implementation against an unmerged predecessor branch.
```

### G3 implementation rulings (2026-09-11), verbatim

Asked while PR 3 was being designed: when the fresh baseline is built, whether the advertisement
(strangers) moves in this PR, and when the owner's record switches.

```text
G3: when should the fresh owner baseline be built and frozen?

Choose "Once, after the run (Recommended)" — option 1.

That matches the frozen G3 ruling exactly. The fresh owner baseline is a
post-catch-up baseline collapse, not something that should be rebuilt after
every individual owner-apply.

The semantics should be:

* Catch up through the certified generations in order.
* When that catch-up pass finishes, take the last fully materialized
  generation V_k.
* Build/freeze the fresh AnchorPresentationV3 for exactly V_k.
* If catch-up only gets partway, it is valid to anchor that last fully
  completed V_k; never anchor a partially applied generation.
* Re-running it for the same V_k must be idempotent.
* The anchor does not authorize, re-certify, or re-realize any trade. It just
  creates a new authenticated owner baseline so future composition doesn't
  have to replay everything from the older baseline.

So do not choose "Inside every apply." That would unnecessarily make every
individual catch-up application also perform baseline construction/publication
and would couple two things we deliberately separated.
```

```text
G3: should this PR also move strangers, i.e. the routing advertisement traders
compose from?

Choose Option 1: "Yes, anchor + proof together (Recommended)."

This is the piece we were just talking about: how a stranger/trader learns
where the new authenticated baseline is and can actually compose forward from
it.

If G3 only updates the owner locally, then the owner gets the benefit of
baseline collapse, but everybody else still has to start from the original
birth state and replay an ever-growing history. That defeats a major purpose of
creating the fresh baseline.

The important part is that the advertisement must move the anchor and the
corresponding economic proof locator together. Not just the anchor.

The intended flow becomes:

old advertised baseline → owner catches up through V_k → fresh
owner-authenticated baseline for V_k is created and durably published →
corresponding proof/economic state is available → advertisement atomically
points strangers at that new baseline + proof → new traders start composing
from V_k.

Until that new advertisement is safely published, the old advertisement
remains valid, so there is no trading interruption.

And make sure Claude preserves this distinction:

The advertisement is discovery/routing information, not authority. A stranger
does not trust the advertisement because it says "this is the latest state."
They use it to find the candidate baseline and its proof material, then
independently authenticate the owner anchor and verify the state/evidence
before composing from it.

So yes: move strangers too, in this PR. Anchor + proof together. That makes G3
an actual system-wide baseline collapse instead of merely an owner-local
optimization.
```

```text
G3: when should the owner's vault record switch to the new baseline?

Choose Option 1: "Same tx as the freeze (Recommended)."

That is the cleaner crash-consistent design, with one important semantic
guard:

The owner's local vault record may switch to the newly frozen baseline in the
same atomic transaction, but that does not make the baseline publicly usable or
authoritative for strangers until the anchor + proof are durably published to
the required quorum.

So the sequence is:

catch-up completes through V_k → freeze fresh anchor/proof for V_k + update
owner's local vault record atomically → mark it publication-pending → publish
anchor/proof → once quorum durability is established, republish the
advertisement so strangers begin composing from V_k.

Until that final publication/advertisement step, strangers keep using the old
already-published baseline. Trading therefore keeps working and there is no
discovery gap.

Why I prefer option 1 over "Only after quorum" is recovery simplicity.
Option 2 creates another intermediate state:

new anchor exists and is published, but owner record still points at old
baseline

and then you need a second crash-recoverable transition just to switch the
local record. Option 1 keeps the owner-side state transition atomic with
creation of the new baseline object.

The invariant I would give Claude is:

> Switching the owner record at freeze is local bookkeeping, not publication
> authority. A pending baseline MUST NOT become the stranger/composition
> discovery baseline until its required objects are quorum-durable and the
> advertisement is moved. The old published baseline remains valid until then.

So: Option 1.
```

### G3 blocker ruling (2026-09-11), verbatim

Raised while PR 3 was being tested. Moving the advertisement's anchor made earlier settles impossible to
re-validate: lineage validation re-runs each past trader settle's reserve-provenance check, and that
check composes history from the advertisement's CURRENT anchor, so it can no longer reach an older
owner proof's generation (`HistoryMissesBaseline`).

```text
G3 BLOCKER RULING

Choose: Keep birth anchor in the advertisement.

Add the immutable vault birth-anchor digest as transport/discovery metadata.
It is set once for the vault and never changes.

Semantics:

1. The current advertised anchor remains the preferred composition baseline
   for new quotes, trades and verification at or after its generation.

2. The birth anchor is only the immutable historical fallback when the
   current baseline is newer than the generation that must be reconstructed.

3. The birth-anchor field is discovery/provenance metadata, not authority.
   A verifier must still fetch and authenticate the referenced anchor through
   the existing anchor-validation machinery.

4. Do not allow callers to substitute an arbitrary historical anchor.

5. Moving the current advertisement to V_k must not invalidate the ability to
   revalidate settlements from generations before V_k.

6. Do not introduce an anchor chain unless the immutable birth fallback proves
   insufficient. It adds unnecessary wire/history-resolution machinery.

7. Keep the G3 stranger-facing baseline move. Do not revert to owner-local-only.

8. The current anchor + economic-proof locator still move together only after
   their required publication durability is established. The birth anchor
   remains unchanged forever.

This is a transport/discovery wire extension, not a new economic authority
object and not a new settlement rule.
```

The owner's framing: **birth anchor = permanent historical root; current advertised anchor = efficient
modern starting point.**

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
