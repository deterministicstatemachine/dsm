# Amendment 2c-C3.1 — Lineage quarantine

Governs the containment consequence of duplicate binding finality at a DLV parent: Req 6.3's
obligations 2, 3 and 4, which 2c-C3 attached to `SAFETY_VIOLATION` and which no mechanism in the
repository implements.

Status: **SPECIFICATION FROZEN.** The trigger, the scope, the persistence, the five effects, the
absence of any clearing path and the denial-of-service boundary are normative here. Lean statements
and production Rust follow this document; neither precedes it.

Prior: 2c-C3 (`ValidDlvSuccessorCore`). Next: the adopting change under C3's closure sequence, then
2c-C4, which **consumes** quarantine state and does not redefine it.

---

# What this amendment decides

2c-C3 ruling E froze `SAFETY_VIOLATION` as the class of a proven substrate contradiction, named
duplicate binding finality at one DLV parent as its defined case, and quoted Req 6.3's five
obligations. It did not say how a verifier quarantines a lineage, because at the time there was
nothing to reconcile: the classification existed and the containment did not.

```text
C3.1 DECIDES      when a lineage quarantine is created            (Ruling A)
                  what it covers, and how descendants are covered  (Ruling B)
                  where it lives and how long                      (Ruling C)
                  what it does — the five Req 6.3 effects           (Ruling D)
                  that nothing clears it                            (Ruling E)
                  that no remote party can create one               (Ruling F)
                  the reason code a durable quarantine reports      (Ruling G)
                  what an evidence object is                        (Ruling H)

C3.1 DOES NOT     the SAFETY_VIOLATION classification itself       (C3 rulings E, J — consumed unchanged)
                  the ordered evidence walk                         (C4)
                  any register, wire object or shared state         (Ruling C forbids it)
                  a recovery or clearing authority                  (Ruling E declares it absent)
```

---

# Why this is a separate amendment

C3's Phase E owed an integration control proving all five Req 6.3 effects individually. Writing it
established that three of the five are not present behaviour waiting to be tested:

```text
1. report STORAGE_SAFETY_VIOLATION      structural  CompositionError::SafetyViolation
2. quarantine parent + descendants      ABSENT
3. refuse market execution on lineage   ABSENT
4. preserve BOTH evidence objects       ABSENT      Conflict carries a COUNT
5. never tie-break                      structural  Conflict yields no chosen value
```

Every `quarantine` in the tree is something else. `network.rs` quarantines a storage **endpoint** on
transport failure, with a tick-based expiry — the opposite of every property below. The economic
register's `RegisterError::Conflict` becomes `PrevalidationRefusal::Quarantined`, a classification
that refuses one admission and persists nothing. `canonical_rebuild.rs` returns `Ambiguous` and
"leaves the caller quarantined" by declining to install a head. `CasHeadOutcome::Conflict` is a
local compare-and-swap vocabulary. None is keyed by a lineage, none survives a restart as a refusal,
and none refuses execution.

So effects 2–4 are a **new durable safety subsystem** with a denial-of-service surface, not wiring.
The owner's ordering rule for this programme stops implementation at exactly that point: a mechanism
whose persistence, descendant scope and clearing semantics are undefined must be frozen before Rust
chooses them. This document is that freeze.

---

# The finding that shapes the trigger

`BindingObservation::Conflict` is the arm every Req 6.3 discussion in the repository points at. It
fires when one read of `k_v` at the vault's committed set finds two distinct chosen values. Its own
doc comment states the arithmetic: a member holds exactly one record per key, so two chosen sets
are disjoint, and two disjoint sets cannot both exceed `n/2`.

That arithmetic is not a caveat; it is a proof that **the arm cannot fire in production.** The
composition walk refuses to read at any quorum other than the canonical strict majority
(`require_canonical_quorum`, `vault_state_composition.rs`), and under `q = ⌊n/2⌋ + 1` two disjoint
quorums need `2q ≤ n`, which never holds. The Lean module proves this
(`one_read_cannot_show_two_chosen_values`). The arm is reachable only at a wrong `q`, which the
observer must refuse before reading rather than after.

The contradiction Req 6.3 describes is therefore observable by a single verifier **only across
reads**: this verifier established that `k_v` was binding-final to value `A`, and a later read
establishes binding finality to value `B ≠ A`. That is precisely the fault a write-once register
must never exhibit, and a member that exhibits it has broken its register. **Nothing in the
repository records the earlier read.** The walk holds its folded parents in memory and discards them;
no durable row says what this device once observed chosen at a key.

Two consequences, both normative below:

1. the trigger is **temporal** — a qualifying finality that contradicts a *recorded* qualifying
   finality at the same key — and needs a durable record of every qualifying finality this verifier
   establishes;
2. the intra-read arm stays, as the refusal it already is, but is not the trigger's definition, and
   an implementation that only wires that arm has implemented nothing.

---

# Ruling A — the trigger

> A lineage quarantine is created by exactly one fact: **duplicate contradictory qualifying binding
> finality at one binding parent**, positively established by this verifier. Nothing else creates
> one.

**Definitions.** Let `V` be a vault with committed storage set `S` (field 14) and committed quorum
`q` (field 15). Let `P` be a parent state of `V` with commitment `c_n` and generation `g`, established
under C3's input contract (`ParentAuth.established`). The binding key is
`k_v = H(DSM/binding-keyset ‖ c_n)`.

A **qualifying binding finality** at `k_v` is a value `(tx_id, value_digest, value_addr)` for which
`q` members of `S`, each attributed under the two-axis rule — member id **and** register incarnation
both echoed (Req 15.8; 2c-C2 ruling B) — hold an `ACCEPTED` record naming that value at one round
(Def 6.21). It qualifies whether or not the bound bundle has been fetched, resolves, or names this
parent: occupancy is independent of bundle content (`binding_occupancy.rs` header), and a finality
that turns out to bind a foreign bundle is still a finality.

A **contradiction** is two qualifying finalities at one `k_v` whose **values** differ. Values are
compared on `(tx_id, value_digest, value_addr)` and **never on the round**: a value re-accepted at a
higher round is the same binding, and the proposer's own recovery path (`ReadEvidence` in
`quorum_bind.rs`) carries a foreign chosen value forward rather than overwriting it, so a later round
with the same value is expected behaviour, not a fork.

**Sources of established finality.** This verifier establishes a qualifying finality by either of:

```text
(a) OBSERVATION   BindingObservation::BoundFinal at S under canonical q
(b) OWN COMMIT    this device's QuorumBind driver reached COMMITTED at k_v,
                  as the Req 6.23 fence records (permitted_successor)
```

Every such fact is recorded durably (Ruling C) at the moment it is established, before any use is
made of it. The trigger compares a newly established finality against the recorded one at the same
`(V, c_n)`.

**Trigger, exactly.** A quarantine root `(V, c_n, g)` is created iff a qualifying finality with value
`B` is established at `k_v` and the durable record holds a qualifying finality with value `A ≠ B` at
the same `k_v` — or iff one read at canonical `q` returns `Conflict`, which Ruling F shows is
unreachable and which is retained as a refusal only.

**What MUST NOT create a quarantine.** Each of these is a real path in the code today and each is
excluded by name:

```text
Unavailable                    fewer than q attributed answers           INCOMPLETE
Undetermined                   attributed, nothing chosen, not free      INCOMPLETE
Free                           q explicit absences                       INVALID (no binding)
a bundle that fails to resolve, decode or hash                           INVALID
a bundle naming another vault or parent (BundleForeignToVault)           INVALID
a successor or receipt signature that fails                              INVALID
RealizationEvidenceInvalid (a forged receipt)                            INVALID
a Conflict at a NON-canonical q                                          refused before reading
the economic register's RegisterError::Conflict                          a different key space (C2)
CasHeadOutcome::Conflict, VaultGenerationConsumeOutcome::Conflict        local CAS vocabulary
canonical_rebuild's Ambiguous                                            a local rebuild stop
a transport failure, timeout, or endpoint quarantine (network.rs)        not evidence
```

`RealizationEvidenceInvalid` is listed although C3 already excludes it, because it is the case an
attacker can manufacture at will: anyone holding a keypair can build a receipt that fails
verification, and a quarantine on it would be a remotely triggerable freeze.

---

# Ruling B — scope: the root, and descendants by derivation

> The quarantined root is the exact binding parent `(V, c_n, g)`. Every state of `V` whose ancestry
> passes through the root is quarantined **by derivation**. Nothing is enumerated at write time.

**Ancestry** is the `h_{n+1} = c_n` edge: field 12 of `V_{n+1}` names its parent's commitment
(`mkSuccessor_binds_parent` in the C3 model). A candidate parent `P'` of `V` is quarantined iff there
is a root `(V, r, g)` with `P'.c_n = r`, or with `r` on `P'`'s parent-commitment chain.

**The decision procedure is normative, because the obvious one is unsound.** "Walk from the vault's
baseline and refuse when the cursor reaches a root" would be exact if the baseline were the birth
state. It is not: `amm_vault_records::update_baseline_with_conn` advances the baseline to the close's
terminal state, and a restored or imported record may begin anywhere. A walk that starts below the
root never crosses it. So two checks, both required:

```text
(i)   AT EVERY CURSOR of the composition walk — the baseline included, BEFORE its
      first register read — refuse if the cursor's (V, c_n) is a root, or if
      the cursor's generation is >= g for any root of V.

(ii)  AT MARKET-EXECUTION ADMISSION — the parent an execution names must be the
      c_n of a composition that passed (i) (today: enforce_parent_binding against
      composed.c_n), and must independently satisfy the generation bound.
```

**Why the generation bound is a derivation and not an approximation.** A vault's chain below any
root is linear: one parent has one successor, because binding finality is exclusive (Def 6.21) and
the register is write-once. So the only state of `V` at generation `g` is `r` itself, and every
state of `V` at generation `> g` descends from `r`. Where that linearity fails, an *earlier*
generation carries two finalities — itself a root under Ruling A — and refusing everything at or
beyond `g` is the fail-closed reading of a substrate already proven unsound. The Lean module states
the lemma (`beyond_the_root_by_generation`) under an explicit linearity hypothesis, so the assumption
is visible rather than buried in "obviously".

**Both continuations are covered.** The two conflicting successors sit at generation `g + 1 ≥ g`.
Neither is composable; neither is executable; neither is selected.

**Per vault, never wider.** A root of `V` quarantines nothing of any other vault, even one sharing
the storage set. This bounds the damage a broken member can do to the lineages it actually served
two values for.

---

# Ruling C — persistence

> Quarantine is durable, client-local safety state. It survives restart. It is not a register value,
> not a CCB object, and not shared.

```text
WHERE     the client database, beside the Req 6.23 fence and the frozen slot-claim
          envelopes — the two existing rows whose discipline this one copies
KEY       (vault_id, root c_n)
FIELDS    root generation g, storage_set_id, committed quorum q,
          the evidence object (Ruling H) — both finalities, in full
WRITE     write-once: INSERT OR IGNORE. The first evidence written IS the evidence.
          No UPDATE statement exists. No DELETE statement exists.
WHEN      BEFORE the SAFETY_VIOLATION is returned to any caller.
CLOCK     none. No timestamp column; ordering is the insertion ordinal.
```

A second durable row is required by Ruling A's temporal trigger: the record of every qualifying
finality this verifier has established, keyed `(vault_id, c_n)`, holding the value and its evidence.
It is also write-once. On a contradiction the *new* evidence is written into the quarantine row
beside the *recorded* evidence, and the finality record is left as it was — the earlier observation
is part of the evidence, not something to be corrected.

**Not a register value.** The row is never published, never read by a peer, never carried in any
object of §3, and allocates no class; the registry's §4 counts do not move. Req 6.3's containment is
a property of a verifier's own conduct, and a shared quarantine object would be a new consensus
artefact this programme has not designed.

**The limit this implies, stated rather than hidden.** Durability is that of the client database. A
verifier that never observed the contradiction is not quarantined until it does; a verifier whose
database is destroyed forgets. If the substrate later stops exhibiting the contradiction — a member
repaired to one value — a fresh verifier composes past a fork this one refuses. That is the boundary
of client-local containment, it is why 2c-C4's walk must consume quarantine state rather than
re-derive it, and it is recorded as a residual under closure status.

**If the write fails.** The outcome is still `SAFETY_VIOLATION` — it is never downgraded because a
row could not be written — and the write failure is reported with it. The lineage is then not
durably contained until a later observation succeeds in writing the row. An implementation that
silently proceeds on a failed write has implemented Ruling D's refusal without Ruling C's memory.

---

# Ruling D — the five effects

Each effect names the observable an integration control asserts. Each is independent: removing one
must turn a named test red while the other four stay green.

**1. Report.** The refusal carries class `SAFETY_VIOLATION`. At the observation that creates the
root the reason is `DUPLICATE_BINDING_FINALITY`; at every later cursor or admission refused by the
durable row the reason is `LINEAGE_QUARANTINED` (Ruling G). Neither is ever `INVALID`, `INCOMPLETE`
or an absence, and no caller may map either to a retryable or a "not found" outcome.

**2. Preserve.** Both evidence objects are in the row, immutable, and readable by the owner's query
surface. A preserved evidence object is lossless (Ruling H): a reader recomputes each finality from
it and reproduces the contradiction.

**3. Refuse composition.** `compose_vault_state` on a quarantined lineage returns
`SafetyViolation` at the first quarantined cursor and produces **no** `ComposedVaultState` — no
partial fold, no folded-parent list, no frontier. A partial result "up to below the root" is
forbidden because it would be read as a frontier.

**4. Refuse execution.** Every execution path that consumes a composed parent refuses: market
execution (`dlv.unlockRouted`), the owner close, reconcile, and the compose query. The close is
included deliberately — a close publishes a terminal state and *advances the baseline*, which is the
one operation that could carry a verifier past its own root.

**5. Never tie-break.** No path reads two finalities and selects one. The observation returns no
chosen value on `Conflict`; the trigger records both values symmetrically with no "primary"; and
nothing downstream may resolve a quarantined key to a value. A `resolve` that answers on a
quarantined key is the fork Req 6.3 forbids, whichever value it picks.

**Not convertible.** A quarantined outcome may not be mapped to `INVALID` (as if the candidate were
merely bad), to `INCOMPLETE` (as if retrying could help), or to any deployment-status arm of
`C3Verdict` (as if the containment were a deployment gap). C3's `C3Verdict` has no arm that admits
it, and none is added.

> **Corrected 2026-09-09 by the 2c-A.1 adopting change (#799).** The third clause named
> `PartialPendingEncoderCut` by type. 2c-A.1 ruling 12 deleted that arm, and the deployment-status
> arm is now `PartialPendingRealization` — which carries a market fold pending 2c-C4's realization
> fact. The RULE is unchanged and now reads by role rather than by type name, so it binds whatever
> deployment-status arm exists: a quarantine is a `SAFETY_VIOLATION` and is convertible to nothing.

---

# Ruling E — nothing clears it

> No timeout, retry, later read, majority change, set or quorum change, restart, re-basing,
> re-installation of the vault record, or ordinary successful operation clears a quarantine. No
> administrative clearing is defined, and therefore none is implemented.

The last sentence is the ruling's point. A clearing path has an authority (who may invoke it), a
discharge condition (what evidence resolves the contradiction), and a disposition (what becomes of
each continuation and of anything that relied on either). None of the three is designed here, and an
operator "escape hatch" written in Rust ahead of that design would be exactly the tie-break Ruling D
forbids, deferred to a human. The module exposes no delete and no update; a future amendment that
freezes recovery semantics may add one, and until it does, quarantine is terminal for this verifier's
view of the vault.

**The cost is liveness, and it is accepted.** A quarantined vault cannot be composed, closed or
traded on this device. That is the same trade the composition walk already makes for a bound-but-
unsettled frontier — *"an adversary who wins a slot and never settles can hold a vault here
indefinitely … strictly preferable to manufacturing a maximality claim the network did not
support"* — and here the alternative is worse than a manufactured claim: it is a blessed fork.

**A later read that shows one value does not clear it.** A member that served two values and now
serves one has not un-broken its register; it has hidden the break from readers who arrive later.
The recorded contradiction is the fact.

---

# Ruling F — the denial-of-service boundary

> No party outside the vault's committed set can create a quarantine, by any input.

The trigger requires two qualifying finalities. Each is `q` attributed `ACCEPTED` records from
distinct committed members; attribution requires the member's id and its committed register
incarnation both echoed (Req 15.8), so an answer from a non-member, a reincarnated member, or an
unauthenticated endpoint is `Unavailable` and counts toward nothing (`attribute_read`,
`quorum_bind_runner.rs`). A record that does not decode is not an answer. A forged bundle, a forged
receipt, a malformed record, a contradictory-*looking* pair of bundles that were never bound, and a
flood of any of these produce `INVALID` or `INCOMPLETE` outcomes and no quarantine.

Within one read the bound is arithmetic (Ruling A's finding): two values at canonical `q` cannot both
be held by disjoint quorums of one set, so an intra-read `Conflict` at canonical `q` is impossible
from any answers whatever. The Lean module proves it. Across reads, producing a contradiction needs
at least one committed member to have served two distinct `ACCEPTED` values at one key to attributed
readers — a member that broke its write-once register. That is the substrate fault Req 6.3 exists to
contain, and it is not available to an outside party.

**Two local preconditions, named because they are the only false-positive routes.** The committed
set's members are distinct — an observer must refuse to read at a set listing one member identity
twice, since a duplicate entry would count one answer twice. And the local catalog maps the vault's
`storage_set_id` to the membership the owner committed; a catalog that maps it elsewhere yields
`Unavailable` under attribution, not `Conflict`, but it is a local integrity precondition and is
stated as one.

**The observer refuses a non-canonical quorum itself.** Composition already enforces
`q = ⌊|S|/2⌋ + 1` before reading; the observer enforces it too, so a caller that passes a weaker
`q` cannot make the `Conflict` arm reachable and thereby create a root. Belt and braces, because the
consequence of one wrong caller is a frozen vault.

---

# Ruling G — the reason code

A durable root refusing a cursor whose own key may read `BoundFinal` or `Free` cannot truthfully
report `DUPLICATE_BINDING_FINALITY`: no duplicate exists at that key. C3's taxonomy demands an exact
reason, so a second code is added, in the same class:

```text
LINEAGE_QUARANTINED      class SAFETY_VIOLATION
                         a durable root of this vault refuses this cursor or
                         this execution; the root's own c_n and generation are
                         named in the detail
```

Added to the Lean reason inventory **first**, then mirrored in Rust, under the same rule the three
clause-table codes followed. It refines `SAFETY_VIOLATION` and never competes with it: the class is
what a caller routes on, the reason is what a caller shows.

---

# Ruling H — the evidence object

> An evidence object is the complete attributed read that established one qualifying finality, or
> the device's own commit record — never a count, never a digest of the read.

For an observed finality at `k_v` under `(S, q)`:

```text
for each member of S, in set order:
    NOT ATTRIBUTED                                  (no usable answer), or
    ATTRIBUTED with  member id
                     register incarnation
                     the record at k_v as BindingRecordWireV1 bytes (§2.10),
                        or EXPLICIT ABSENCE
plus the derived chosen value:
    (tx_id, value_digest, value_addr, round, holders)
```

For the device's own commit: the Req 6.23 fence row at `COMMITTED`, which names the permitted
successor, the ballot and the value address.

**Lossless is the requirement, and it is testable.** From the object alone a reader recomputes the
tally under `q` and obtains the same chosen value; from two objects at one key it reproduces the
contradiction. `Conflict { distinct: usize }` fails this — a count of two says nothing about which
two — and the observation type is changed to carry the read. The core observation function already
holds every field above at the point it classifies; it discards them.

The row's byte layout is client-local and defined by the module, not by this document: it is not
wire, and the registry allocates nothing for it. The module owes a round-trip test.

---

# Verification obligations

The adopting change owes these, and C3's Phase E is not complete until they are green and the
mutation controls have been **run**, not asserted.

**Integration control, five named assertions, deterministic in-process fleet.** Establish
`BoundFinal(A)` at `k_v`; have the fleet serve `BoundFinal(B ≠ A)` at the same key; compose.

```text
E1  compose returns SafetyViolation { DuplicateBindingFinality }
E2  the quarantine row exists, holds both evidence objects, and each recomputes
    to its finality under q
E3  a second compose returns SafetyViolation { LineageQuarantined } with NO
    ComposedVaultState — and does so after the fleet is switched back to A,
    after a restart of the client database connection, and with the register
    reading Free
E4  dlv.unlockRouted, dlv.close and dlv.reconcile each refuse on that vault;
    a sibling vault on the same set composes and executes
E5  no resolution of k_v to a value is obtainable from any query surface
```

**Mutation controls, one effect at a time.** Remove the durable write → `E2` and `E3` red. Remove the
cursor check → `E3` red. Remove the admission check while leaving the cursor check → a test that
names a quarantined parent directly is red. Remove the evidence from the row → `E2` red. Add a
`resolve` that returns the recorded value → `E5` red. Each mutation is performed, its named test
observed red, and the control restored; a mutation that stays green is a finding about the test.

**Negative controls.** Each row of Ruling A's exclusion table has a test that performs the excluded
input and asserts that no quarantine row was written. `RealizationEvidenceInvalid` and `Unavailable`
are mandatory; the rest may share a harness.

**The arithmetic control.** A test that constructs the strongest adversarial single read the fleet
double can express at canonical `q` and asserts the observation is never `Conflict`; and the Lean
theorem is `#print axioms`-reported.

---

# Registry and cross-document edits

- **2c-C3.** After Req 6.3's five obligations under ruling E, one sentence pointing here; and the
  closure-status block gains a line for Req 6.3 containment.
- **Registry §3 / §7.** Record that C3.1 adds no class, no encoding and no field table — the
  quarantine is client-local — and add the ledger bullet.
- **No new §2 primitives.** The evidence object reuses `BindingRecordWireV1` (§2.10) unchanged.

---

# Closure status

```text
Trigger, scope, persistence, effects, clearing, DoS boundary     FROZEN
LINEAGE_QUARANTINED                                              FROZEN (Lean first)
Lean model of the trigger, monotonicity, derivation, refusal     PROVED AS CLAIMED
Production mechanism                                             IMPLEMENTED (client-local)
Req 6.3 effects 2, 3, 4                                          IMPLEMENTED, controls E1–E5 green,
                                                                 six mutation controls red
Recovery / clearing                                              DECLARED ABSENT, NOT DESIGNED
```

**Residual — client-local containment.** Recorded under Ruling C. A verifier that has not observed
the contradiction is not bound by another's quarantine; the substrate fault is contained per
verifier, not per network. C4 consumes this state and must not present its walk as closing that gap.

**Residual — the write can fail.** The refusal stands; the memory may not. Named under Ruling C.

**Implementation record.** The adopting change landed the mechanism as frozen: two write-once
client-database tables (`dlv_binding_finality_observed`, `dlv_lineage_quarantine`) with no update
and no delete statement; the observer validates the canonical quorum itself (`CanonicalQuorum`) and
returns the read behind every verdict; a finality is recorded the moment it is established, by
observation and by this device's own commit, and compared on value; the cursor check runs in the
observer ahead of its read, and each execution route (`dlv.unlockRouted`, `dlv.close`,
`dlv.reconcile`) checks again on its own; `dlv.lineageQuarantine` lists the roots with both evidence
objects. The `Conflict` arm now carries the read; the probe reports `LINEAGE_QUARANTINED` and names
no value. One deviation from the verification obligations is recorded rather than hidden: E3's
"after a restart of the client database connection" is not exercised in-process, because the test
database is shared in-memory and cannot be closed without being lost; restart-survival is the
durability of the on-disk table.

---

# Scope

**Documentation and Lean only. No Rust.** The adopting change implements Rulings A–H under C3's
existing closure sequence and carries the controls above.

---

# Verification of this document

1. **The Conflict arm's unreachability was derived, not assumed.** `observe_key` tallies one record
   per attributed member under the full record identity; `chosen` filters at `≥ quorum`; composition
   enforces the canonical quorum before any read. Two chosen identities therefore need
   `2q ≤ attributed ≤ n`, which `q = ⌊n/2⌋ + 1` refutes. Stated as a Lean theorem so that a change to
   any of the three premises fails a kernel check rather than a reader.
2. **The baseline's mobility was read at source** (`update_baseline_with_conn`), which is what
   disqualified "walk from the baseline" as the derivation and forced the generation bound.
3. **The value-not-round comparison was checked against the proposer.** `ReadEvidence` in
   `quorum_bind.rs` treats a foreign chosen value as something to carry, not to overwrite, so a
   higher round with the same value is expected.
4. **Every existing `quarantine` in the tree was enumerated** and each excluded by name in Ruling A,
   so that none can be mistaken for an implementation of this amendment.
5. **The attribution rule was read, not cited.** `attribute_read` requires both echoes; an
   unattributed answer is `Unavailable`, not an empty read.
6. **Self-contradiction sweep** for `never / only / every / always`, and specifically that no sentence
   claims quarantine is shared state, that no sentence claims a clearing path exists, and that no
   sentence claims effects 2–4 are implemented.
