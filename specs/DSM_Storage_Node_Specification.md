---
title: DSM Storage Node Specification
document_role: engineering-source
status: accepted by the owner on 2026-09-22; items marked Open remain undecided
supersedes: .github/instructions/storagenodes.instructions.md (Envelope v3, Schema 2.4.0, 27 Oct 2025)
---

# DSM Storage Node Specification

<!-- spec-section: STOR-PREAMBLE -->
## Read this first

A storage node is bytes in, bytes out. It holds no key, signs nothing, and decides nothing. The reader checks every byte a node returns against its hash and the signatures it carries, and every fact the protocol draws from storage is derived by the verifier from raw reads.

This document is the single statement of the storage contract. It refines the storage rules of `DSM_High_Level_Explainer.md` (§9, §11, §80) and states the contract that `SoFi_Settlement_Specification.md` (Part II) and `dBTC_Native_Specification.md` (§24) rely on. It adds what those documents leave open: how a storage set survives the replacement or loss of a member without changing the meaning of any historical cell.

### Authority

- `DSM_High_Level_Explainer.md` governs. This document refines it and must not silently redefine it.
- This document does not redefine SoFi or dBTC. Where it appears to conflict with either, the conflict is listed in §23 for the owner to resolve before code changes.
- `.github/instructions/storagenodes.instructions.md` is superseded. Its mechanisms that are compatible with the corpus are adopted here and marked as such; the rest are listed in §23.2 as not adopted.

### Status markers

Every rule carries one of these:

| Marker | Meaning |
|---|---|
| **Imported** | Restates a rule already normative in DSM, SoFi or dBTC. The citation governs. |
| **Owner decision** | Decided by the owner (2026-09-22). Normative. |
| **Adopted** | Taken from the superseded October 2025 storage specification, compatible with the corpus. Normative. |
| **Open** | A decision this document needs and does not make. |

### Normative words

MUST and MUST NOT state requirements an implementation cannot relax. SHOULD states a requirement that may be departed from only with a written reason. MAY states a permission. Statements without these words are explanatory unless labelled Rule, Invariant, Property or Proof Obligation.

### Notation

| Symbol | Meaning |
|---|---|
| `H(tag; x)` | Domain-separated BLAKE3, as in SoFi §1.4. |
| `S` | A committed storage set: five member ids, sorted by raw bytes (SoFi §6). |
| `r` | A role: one member id of a committed set (§11). |
| `op(r)` | The operator currently bound to role `r` (§12). |
| `K` | A cell key, derived by Core from committed state. |
| `L(K)` | The leader of `K`: `FisherYates(s, S)[0]` (SoFi §7). |
| `Final(K, x)` | The finality rule of SoFi §8. |
| `Reg` | The active operator registry (§13). |

---

## Part I — Role and fault model

<!-- spec-section: STOR-001 -->
### 1 What a storage node is

**Rule (Imported: DSM §11; SoFi §2, Part II, §12)**

1. A node MUST hold no key and MUST sign nothing.
2. A node MUST NOT validate a protocol rule, evaluate a guard, compute a balance, compute a leader, compare one value with another, or decide whether a transition is valid.
3. Economic and protocol payloads MUST be opaque to the node apart from content addressing. The node MUST NOT vary what it stores by what a payload would parse as.
4. No protocol-relevant path in the node MAY read a clock. Ordering inside the node uses logical ticks.
5. Inter-node gossip is state synchronisation only. There is no leader election, no Raft, no Paxos, and no vote between nodes.

**Rule — the layer test (Imported: SoFi §2.2)**

Every addition to the node answers one question before it is written: does storage need to know what this means? If yes, the addition is in the wrong layer.

<!-- spec-section: STOR-002 -->
### 2 What a node never does

**Rule (Imported: dBTC Requirement 24.1; DSM §64 "Storage, again")**

A node MUST NOT decide who owns an asset, validate a burn as an economic authority, possess a mint key, possess a plaintext reusable Bitcoin vault key, sign a Bitcoin exit, convert an invalid DSM transition into a valid one, or choose a successor on behalf of the protocol. A malicious or unavailable node may degrade availability. It MUST NOT gain authority from the bytes it stores.

<!-- spec-section: STOR-003 -->
### 3 Fault model

**Rule (Imported: SoFi §5.1; DSM §11, §80.11)**

1. A node may crash and may omit messages.
2. A node never equivocates, never alters content it holds, never reorders what it holds for a key, and never permanently loses stored bytes, including across restart, restoration, and storage migration.
3. Restoring a node from a snapshot that predates a value it held is a safety violation, not an availability event.
4. Misresponses about immutable objects are detectable by hash and affect availability only.
5. A store that falls outside this model fails closed.

**Rule — safety and liveness (Imported: DSM §80)**

Failure to reach a cell's leader, or two further seats of its route, is a liveness failure: the cell waits. Violation of durable memory is a safety failure.

**Rule — the fault model binds roles (Owner decision)**

Items 2 and 3 bind a *role* (§11), not a machine. A role's memory survives the machine that serves it through handover (§12.5). The loss of every copy of a role's memory is handled by §12.6, never by treating a new machine's empty memory as the role's history.

<!-- spec-section: STOR-004 -->
### 4 What storage facts are

**Rule (Imported: SoFi §13, §2.3)**

Core derives exactly three storage facts from raw reads: `LeaderHeld(K, x)`, `Final(K, x)`, and `Stored(o)`, with `LeaderHeld` and `Final` defined by route chains (§9). It uses nothing else from storage, except that the loss rule (§12.6) also reads `Preserved` (§9). Registered is not Validated, and a storage fact implies nothing about semantic validity.

**Rule — nothing negative is recorded (Owner decision; DSM Amendment A1)**

A storage fact is either established from the reads in hand or not established, and a fact that is not established is never read as its negation. A verifier records nothing for a presentation it does not accept. Nothing a node returns is a verdict.

---

## Part II — Objects and operations

<!-- spec-section: STOR-005 -->
### 5 Immutable objects

**Rule (Imported: DSM §11; SoFi §10)**

1. A payload `P` in namespace `N` is stored at `addr = H(DSM/storage-object ∥ N ∥ H(N ∥ P))`, computed by the node from the input.
2. A caller-supplied address is checked against the computed one and never used as the key.
3. There is no update path and no overwrite path. The path is absent, not a path that refuses.
4. Replaying identical bytes re-acknowledges. Different bytes at the same address are reported as corruption.
5. On read, the node recomputes the address before serving. The client re-hashes regardless.
6. `Stored(o)` holds when three members of `S` return the exact bytes of `o`.

<!-- spec-section: STOR-006 -->
### 6 Keyed cells

**Rule (Imported: SoFi §8, §12; DSM §11)**

1. Put at a key stores the bytes a writer sends for that key after everything already held there.
2. Get returns everything held at the key, in the order it arrived, or that it holds none.
3. No member refuses, replaces or compares anything held at a key, except that a node MAY refuse a write addressed to an account that has not met the spend-gate (§16, §17). There is no write authorization: a signed object carries its signer's authority, and a derived object is recomputed by whoever reads it.
4. Any party MAY carry bytes to members not yet reached.
5. A put to a keyed cell returns the entry's **arrival record**: the member id, the key, the entry's per-key arrival index, and the member's running hash for that key after the entry (§14). The record is bytes, not a signature. It becomes checkable when the member's ByteCommit that commits it closes (Owner decision, 2026-09-22).

<!-- spec-section: STOR-007 -->
### 7 Indexes

**Rule (Imported: SoFi §11)**

Anyone MAY append the content address of an object the member already holds under any locator. Appends are never removed. A read returns addresses in append order, paged. The member interprets nothing.

<!-- spec-section: STOR-008 -->
### 8 Mirror, spool, and identity storage

**Rule (Imported: DSM §11)**

1. **Tip mirror.** A public head and encrypted per-relationship leaves, keyed by device and relationship.
2. **Inbox spool.** Unilateral delivery to an offline counterparty. Envelopes are strictly versioned, ordered by insertion, acknowledged per routing key, and never opened by the node.
3. **Identity and recovery.** Genesis anchoring, device-tree indexing, and recovery capsules, stored as bytes under derived keys. Recovery is out of scope for this round; this document imports it as substrate only.

**Rule — routing exists only through a pre-established contact (Owner decision; Imported: DSM §9, §13)**

Nothing can be sent to a party that has not pre-established the sender as a contact. A relationship is created by mutual pre-add from committed state, never by first contact (DSM §9, §13), and the same rule governs token policies.

1. A message is sent to a relationship, never to a genesis account. The relationship is addressed by its chain id, the hash of the two device ids.
2. **Sender side.** The sender's device sends only over a relationship it has pre-added. With no relationship there is nothing to address, so nothing is sent.
3. **Recipient side.** The recipient's device reads only relationships it has pre-added, and accepts a message only if it is signed by the other device of that relationship.
4. The checks listed in DSM §11 (canonical encoding, device authentication, replay-protected message id, recipient key) are performed by the devices at both ends.

**Rule — the node never checks the writer (Owner decision)**

The node does not verify who is writing, not even that the writer is one of the relationship's two devices. A node that can check can block, and blocking is an authority the node must not have. Software that skips the sender-side check can still compute a relationship id and write bytes under it; those bytes are never read by the recipient and change nothing. That is accepted.

<!-- spec-section: STOR-009 -->
### 9 Route, leader and finality

**Rule — the route and the leader (Imported: SoFi §7, §7.1; DSM §80.12. Route: Owner decision, 2026-09-22)**

1. The writer and Core compute a cell's **route** as `R(K) = FisherYates(s, S) = [r0, r1, r2, r3, r4]`, with the shuffle of SoFi §7.1. The **leader** is `L(K) = r0`. A node never computes a route or a leader and does not know which cells it leads.
2. The seed `s` is derived from committed state only. Availability, the caller's identity, and node ids never enter a seed.
3. `S` is the storage set committed in the state that seeds the cell. A member that is offline is still in `S`, and keeps its position in the route.
4. A verifier reads a cell only after every check it can decide from evidence already in hand has passed. A transition that is Invalid on what the verifier holds never causes a storage read (Imported: DSM Amendment A4).

**Rule — route chains (Owner decision, 2026-09-22)**

1. A writer writes a value `x` to the route's seats in route order, leader first. Each copy after the leader carries the chain built so far. The chain is built live, as the write goes; it is never reconstructed afterwards from copies.
2. A **link** at seat `ri` is the arrival record that seat returned for `x` (§6). It names the cell, the seat and its route position `i`, and it commits the previous link.
3. The **leader link** is valid only if `x` is the first recognized object naming `K` in the leader's arrival log. Bytes that are not a recognized object naming `K` never count, so junk written to the leader blocks nothing.
4. A later link is valid only if the entry it records carries a valid chain beginning with the leader link, its position is higher than every earlier link's, and its seat's own mirror of the leader's ByteCommits (§14) covers the leader link.
5. Where a seat yields no link, the writer records an **empty** for that position, so the route never shortens or reorders. An empty is either **taken** (another value's valid chain is already first at that seat, provable from that seat's arrival record) or **no response** (recorded, and proving nothing, because nobody can prove that a seat failed). An empty never counts as a link.
6. A node verifies nothing about a chain. It stores the bytes it receives, in arrival order, and returns their arrival record. Verifiers evaluate chains.
7. Links are carried forward at once; the writer does not wait for ByteCommits between seats. A link becomes verifiable when the ByteCommit that commits its arrival record has closed (§14).
8. Normal operation writes to all five seats. Any party MAY continue a chain along the remaining route.

**Rule — finality (Owner decision, 2026-09-22; replaces "first at the leader and held by two other members"; applied to SoFi §8 as Amendment S4 and to DSM §3, §9, §11, §63 and §80 as Amendment A6)**

- `LeaderHeld(K, x) ⇔ x has a valid leader link at K`.
- `Preserved(K, x) ⇔ x's chain has a valid leader link and at least one further valid link`.
- `Final(K, x) ⇔ x's chain has a valid leader link and at least two further valid links`.

1. Core evaluates these from raw reads and the carried chain. No node evaluates them.
2. At most one value has a valid leader link at a cell, so at most one value is preserved or final.
3. A receiver relies only on `Final`. A preserved value is not final and is never spendable; preservation matters only for loss (§12.6). Stopping a chain at two links gains a writer nothing, and any party can complete it.
4. If the leader is unreachable, the cell waits. No other member stands in.
5. Three links are not a quorum and do not vote. They are three positions of one route: the leader fixes the order, and the two later links carry the proof of that order to seats that survive the leader.

**Invariant — historical routes are fixed (Owner decision)**

A cell's route, and so its leader, is a function of the set committed when the cell was seeded. It MUST NOT be re-derived over any later set, registry, or binding. Changing who serves a role (§12) never changes which role holds which position of a cell's route.

<!-- spec-section: STOR-009-1 -->
#### 9.1 Pending challenges counted in the leader's ByteCommits

**Rule (Owner decision)**

1. When a result is pending on one party, any party MAY write a challenge to the pending cell's leader.
2. The challenged party answers by supplying what is missing. The alternative is a drop claim.
3. The answer and the drop claim race to the cell's leader, like every race: the first to reach the leader wins.
4. A drop claim counts only if the leader's own ByteCommit chain shows at least X ByteCommits closed after the first of the leader's ByteCommits whose root includes the challenge. A drop claim that arrives before that counts as nothing.
5. Once a drop claim wins, the pending result is dropped for every verifier, and later evidence for it is ignored. In SoFi, a dropped trade is Void: it never executes and moves no balance.
6. If the leader is unreachable, its chain does not advance and the deadline does not arrive. The cell waits, as it always does.
7. A challenge applies only where the missing piece can come from the challenged party alone. Anything a relayer can complete is completed by relaying.

**Why it resists gaming**

The leader's cadence is driven by all of its customers' traffic, and a node does not know which cells it leads (§9), so it cannot target one challenge. Speeding up its whole chain is visible to every customer and is scored (§13). Operators that underperform are never admitted and are cut, and parties may opt out of members of their own sets.

**Open:** the value of X; the wire form of a challenge and a drop claim; and the SoFi rule that consumes a dropped result (SoFi §24 has no rung for it).

---

## Part III — Storage sets, roles, and succession

<!-- spec-section: STOR-010 -->
### 10 Storage sets

**Rule (Imported: SoFi §6, §19.8)**

1. A storage set is five member ids committed in state, identified by `storage_set_id`, which covers member ids only and never endpoints.
2. A vault's set is the network's pinned set. Vault genesis is accepted only if `storage_set_id` equals it.

**Rule — party sets (Owner decision)**

1. Every party has its own storage set for its own objects and cells. Traders' objects and cells go to the trader's set; an owner's objects and cells go to the owner's set.
2. A party's set is assigned from the active registry by Fisher–Yates. The party never chooses a member.
3. A party MAY opt out of a member. The replacement is drawn by Fisher–Yates (§12.4). The party may draw another poor performer; that is accepted.
4. A party pays for storage with credits (§17).

**Open — device register set.** DSM §9 and §80.12 require the economic-root register's set to be "owner-committed". Where that set is committed in device state is not specified.

<!-- spec-section: STOR-011 -->
### 11 Member ids are seats

**Rule (Owner decision)**

1. A member id in a committed set names a **seat**: a stable logical position together with that seat's ordered memory (every key's arrival log and every immutable object stored under it). This document also calls a seat a *role*.
2. A seat is served by one operator at a time, `op(r)`. Which operator occupies a seat is not committed in any party's state.
3. Once `S` is committed, it never changes. The leader of every cell is a seat, so it is fixed forever (§9), whichever machine later occupies that seat.
4. Operator endpoints are resolved outside committed state. Whether endpoint resolution is network configuration or a committed object is Open.

**Why**

SoFi §6 already separates member ids from endpoints, and nodes hold no keys, so a member id is not bound to hardware. Treating the id as a role lets the machine change while every historical cell keeps its meaning. No party's state has to change, so succession never depends on an owner who is offline, lapsed, or dead.

<!-- spec-section: STOR-011-1 -->
#### 11.1 Two separate Fisher–Yates selections

**Rule (Owner decision)**

Fisher–Yates is used for two unrelated purposes. They share the primitive and nothing else.

| | Seat assignment | Leader selection |
|---|---|---|
| Question it answers | Which operator occupies a seat | Which seat leads a cell |
| Drawn from | The active registry, excluding operators already seated in the set | The five seats of the committed set |
| When | At set creation (§12.1) and on replacement (§12.4) | For every cell (§9) |
| Seed tags | `DSM/storage/seat-bind/v1` at creation; `DSM/storage/rebind/v1` on replacement | SoFi §7.2 (`storage-seed/v4` for vault cells; `DSM/economic/position-seed/v1` for positions) |
| Draw function | Its own tag, `DSM/storage/seat-fy-prf/v1` | SoFi §7.1 (`fy-prf/v1`), unchanged |

1. The two selections MUST use distinct domain tags for their seeds and for their draw functions, so that no input to one can influence the other.
2. Seat assignment never changes a leader: replacing the operator in seat 3 leaves seat 3 as seat 3, and every cell seat 3 led it still leads.
3. Leader selection never reads which operator occupies a seat.

```text
Seat assignment                        Leader selection
chooses WHO occupies seat 3            chooses WHICH SEAT leads cell K
        |                                      |
seat 3 remains seat 3                  historically chose seat 3
        |                                      |
        +---------- replacement does not alter that result
```

**Why**

Without seats, replacing machine A with machine B would change the membership input to every historical leader derivation, and two observers could derive different winners for the same past race. With seats, leader selection refers only to the stable position, and the separate assignment mechanism decides which machine currently serves it.

<!-- spec-section: STOR-012 -->
### 12 Binding and succession

<!-- spec-section: STOR-012-1 -->
#### 12.1 Initial binding

**Rule (Owner decision)**

When a set is created, each seat is bound to an operator drawn from the active registry by the seat-assignment selection (§11.1), with seed `H(DSM/storage/seat-bind/v1; creating state commitment ∥ seat)`. Operators already seated in the same set are excluded from the draw.

<!-- spec-section: STOR-012-2 -->
#### 12.2 Retirement triggers

**Rule (Owner decision)**

An operator's binding to a role ends only by:

1. **Opt-out.** The party that owns a party set retires one of its members. This applies to party sets only, never to a vault's network-pinned set.
2. **Network cut.** The registry process (§13) removes an operator for under-performance. Every role bound to that operator is retired.

No owner action is ever required for a network cut. There is no other trigger.

<!-- spec-section: STOR-012-3 -->
#### 12.3 Retirement records

**Rule (Owner decision)**

1. A retirement is recorded as an immutable object naming **one or two** seats of a set and, for each seat, whether it is a handover (§12.5) or a loss (§12.6). A network cut's record is the registry successor that removes the operator (§13).
2. The **survivors** of a record are the seats it does not name. A record is **effective** once every survivor's current operator holds it. This is every survivor, not a count.
3. **Simultaneous or unreachable members.** A record never waits on a seat it names. If a survivor of a pending record is itself unreachable and is to be replaced, a new record naming both seats is issued; its survivors are the remaining three, and it becomes effective without the unreachable seat. Records only add: a seat is retired once any effective record names it, and a pending record that names the same seat is superseded.
4. **Verifier rule.**
   - A verifier that finds a record at none of the members it read proceeds as though no such record is effective.
   - A verifier that finds a record at any member MUST either confirm it at every survivor, and then treat it as effective, or wait. It MUST NOT proceed as though the record were not effective.
5. **More than two seats out at once is outside the model.** Finality already needs three live seats, the leader and two further seats of the route (§9), so a set with three or more seats out cannot advance any cell. It waits. No rule here resolves it, and safety is unaffected.

**Property — retirement convergence (Owner decision)**

Every finality read touches three seats: the leader and two further seats of the route. A record names at most two seats, so every finality read touches at least one survivor. If a record is effective, every survivor holds it, so every verifier that can read a cell sees it. A verifier that sees it nowhere among the members it read is therefore right that it is not effective. A verifier that sees it but cannot confirm it waits rather than acting on the old occupant, so no two verifiers act on different occupants of one seat. This is full replication among the survivors, not quorum overlap.

**Why not a quorum**

A quorum rule (say, three of four) would let a record become effective while one survivor has never seen it. A verifier reading that survivor and two named seats could then act on the old occupant while another verifier acts on the new one. Naming the unreachable seat in the record, instead of counting past it, keeps every survivor informed.

<!-- spec-section: STOR-012-4 -->
#### 12.4 Rebinding

**Rule (Owner decision)**

1. The replacement operator is drawn by the seat-assignment selection (§11.1) from the active registry, excluding operators already seated in the set.
2. The seed MUST NOT be computable by the party before the retirement is effective. Construction: `s_rebind = H(DSM/storage/rebind/v1; role ∥ H(record) ∥ D)`, where `D` is the sorted list of digests of the first ByteCommit (§14) of each surviving operator whose root includes the record. `D` depends on everything those operators hold, so the party cannot predict it or steer it by repeating opt-outs.
3. Under per-write credits, opting out carries no payment. The unpredictable seed (item 2) is the defence against steering a seat by repeated opt-outs. Whether opting out should carry a cost is Open (§24).

<!-- spec-section: STOR-012-5 -->
#### 12.5 Handover

**Rule (Owner decision)**

1. When a retiring operator is live, it MUST transfer the role's memory to the new operator: every key's full arrival log in order, and every immutable object.
2. The new operator's commitments for the role MUST continue from the retiring operator's last ByteCommit that covers the role, so that peers holding the mirrored chain can detect any reordering during handover.
3. Until handover completes, the role is served by the retiring operator.
4. A retiring operator's stake cannot be released until it has handed over every role it served (§15).

**Rule — replicate before counting (Owner decision)**

An operator MUST durably replicate a role's memory before a write to that role is acknowledged. Permanent loss of a role then requires the loss of every replica, not one machine.

<!-- spec-section: STOR-012-6 -->
#### 12.6 Loss

**Rule (Owner decision; route chains 2026-09-22, finding GPT-4)**

1. If a role's memory is lost with no handover, the retirement record carries a loss marker.
2. Each surviving operator records the loss marker at a point in its own ordered memory. For each survivor, material it held before that point is **pre-loss** material.
3. For a cell `K` whose leader role was lost, the verifier looks in the survivors' pre-loss material for valid chains of `K` (§9) and resolves `K` as follows:

| Pre-loss chains at survivors | Result |
|---|---|
| Valid chains for exactly one value `x` | `x` is the winner at `K`. If its chain has fewer than three links, any party MAY continue it along the remaining route. |
| No valid chain | No value was final at `K` before the loss. The role's new operator serves the leader position for `K` from here, and `K` is written afresh. |
| Valid chains for two different values | `Frozen(K)`: no winner. Two valid leader links for one cell mean the leader recorded two values first, which §3 excludes; the chains are evidence that it did. |

4. Only pre-loss material identifies the winner. A chain first presented after the loss marker counts as nothing for `K`, even if its leader link verifies. Otherwise a value that never reached a second seat could appear after `K` had been written afresh.
5. For a cell with a valid pre-loss chain, the new operator's arrival log MUST NOT be used as the leader's order.

**Property — loss never reverses or loses a final value (Owner decision)**

If `Final(K, x)` held before the loss, `x`'s chain was held by the leader and two further seats, and each of those seats' links counted only once that seat's own mirror covered the leader link (§9). A record names at most two seats, so at least one of those two further seats survives, holding the chain and the means to verify it: `x` is the winner. Only one value can have a valid leader link (§3), so no other value is ever selected. If no survivor holds a valid chain, no value was final, so writing `K` afresh creates no second final value. The rule freezes a cell only if the leader equivocated.

**Open — consequences of `Frozen(K)`.** What a frozen cell means for DSM acceptance, SoFi resolution, and dBTC, and whether it triggers the DSM tripwire (§53), is not decided here. Under route chains a frozen cell requires a leader that equivocated, which §3 excludes.

---

<!-- spec-section: STOR-013 -->
### 13 The operator registry

**Rule (Adopted: October 2025 spec §9; succession mechanism by Owner decision)**

1. The active registry `Reg` is the sorted list of operator ids, stored as an immutable object.
2. The registry advances by a pure function of the prior registry and input objects referenced by hash: capacity and performance evidence (Up/Down signals, §14), and applicant packs.
3. Each registry successor is a keyed cell on the network's pinned set, keyed by the prior registry's address. Any party MAY write a candidate successor. A verifier recomputes a candidate from the inputs it references; an object that does not recompute is not a candidate. The winner is the first candidate at the cell's leader, and it is final under the ordinary rule (§9). This settles which of several valid candidates (built from different discovered inputs) becomes the registry, without a vote.
4. Pruning MUST be computed from committed evidence only (ByteCommit chains and signals that reference them). Measurements a node makes locally, such as latency or uptime, MUST NOT enter the rule, because different nodes observe different values.
5. Growth selects new operators by the salted applicant ranking of the October 2025 spec §9, which is anchored in the genesis commit-reveal (§5 of that spec), so no party can bias selection.
6. A new operator is protected from pruning for a grace period counted in ByteCommit cycles, never in time (October 2025 spec §10).
7. **Owner decision:** an operator that does not meet the performance bar is never admitted, and one that falls below it is cut. Cadence regularity, meaning the size and spacing of an operator's ByteCommit cycles compared with its own history and its peers, is part of the performance score.

**Open — the performance criterion.** The October 2025 spec prunes by lowest utilisation. The owner's intent is to prune under-performers. Which performance measures are expressible over committed evidence is not decided here.

<!-- spec-section: STOR-014 -->
### 14 ByteCommit

**Rule (Imported: DSM §11; format Adopted: October 2025 spec §7)**

1. Each cycle, a node emits an unsigned ByteCommit containing: its node id, a cycle index (a counter, never time), the SMT root over what it holds, the bytes used, and the digest of its previous ByteCommit.
2. A ByteCommit is stored as an ordinary object under a deterministic address and mirrored by peers.
3. A verifier checks the chain link and the root itself. A ByteCommit is **not** accepted by counting how many mirrors hold it; the October 2025 mirror-count rule is not adopted.
4. Up and Down capacity signals reference windows of accepted ByteCommits and are checked against them (October 2025 spec §8).

**Rule — arrival order is committed (Owner decision)**

Each keyed-cell entry is committed with its per-key arrival index and the member's running hash for that key, `hi = H(running hash of the key before the entry ∥ digest of the entry)`, so that arrival records (§6), route links (§9), handover (§12.5) and pre-loss partitioning (§12.6) are checkable against mirrored commitments.

**Rule — mirror provenance (Owner decision, 2026-09-22)**

1. A node mirrors the ByteCommits of every node it shares a storage set with, by fetching them from that node itself.
2. The mirror is its own namespace. No third-party write enters it: bytes someone else presents as another node's ByteCommit never populate a node's mirror of that node.
3. A verifier treats a member's mirror of another node's ByteCommits under the same fault model as the member's own memory (§3). ByteCommits stay unsigned, and nodes hold no key.

<!-- spec-section: STOR-015 -->
### 15 Stake and exit

**Rule (Adopted: October 2025 spec §15; DSM §11)**

1. An operator stakes through a stake DLV.
2. The stake unlocks only when a DrainProof is mirrored: two consecutive accepted ByteCommits with bytes used equal to zero.

**Property — exit implies handover (Owner decision)**

Retention never depends on payment (§19), so an operator's memory empties only when every role it served has been handed over (§12.5). A DrainProof therefore proves completed handover, and an operator that refuses handover never recovers its stake.

---

## Part IV — Economics at the storage boundary

<!-- spec-section: STOR-016 -->
### 16 The PaidK spend-gate

**Rule (Imported: DSM §11; Adopted: October 2025 spec §16; enforcement by Owner decision)**

1. A device is receive-only after genesis until it has paid a flat rate to K = 3 distinct storage operators. On first satisfaction, spending is enabled permanently, with no renewal.
2. Payment receipts are device-signed objects stored like any other object.
3. A node enforces the gate itself: it stores the receipts, counts distinct operators, and MAY refuse writes addressed to a device that has not met the gate (§17, enforcement bounds).
4. `PaidK` is also the join event that drives DJTE, which verifiers evaluate over the same receipts. Emissions are out of scope for this round; this document imports the gate as substrate only.

<!-- spec-section: STOR-017 -->
### 17 Storage credits

**Rule (Owner decision)**

1. Storage is paid on-chain with credits. A party's credit balance is a leaf in its own committed state.
2. The credit price is fixed in token units as a committed network parameter and is charged by the storage a write actually uses. Operators do not set prices; they compete on performance (§13). The real-world cost of storage follows the token's exchange value.
3. A sender-authored, state-advancing transition consumes the credits for the storage it uses, inside that transition. The receiver checks the debit as part of acceptance, like any balance debit. Receiving never debits.
4. Credits are refilled by paying operators. The payment receipts are the evidence for the refill, through the same path as the spend-gate (§16).
5. Credits are counted in storage used, never in time, so no clock enters any protocol path.
6. A party whose credits are exhausted cannot act. That is a liveness consequence only, never an invalidity. Before acting, the client checks its own credit balance.
7. Paying and getting through are separate: a write goes through at a cell once its route chain has three links, the leader's and two more (§9).

**Rule — node refusal is bounded (Owner decision)**

1. A node MAY refuse a write addressed to an account that has not met the spend-gate (§16). Whether nodes also refuse writes from an account whose credits are exhausted, or only receivers enforce credits, is Open (§24).
2. Any refusal is keyed on the account the write is addressed to, never on who is connected. A relayer carrying a party's bytes is admitted, and the node still never checks the writer (§8).
3. Refusal never applies to DLVs (§18), and never depends on a payload's content or on what else is held at a key.
4. To the protocol, a refusal is indistinguishable from unavailability: liveness only, never validity.
5. A node is one of five in a party's set, and the others carry a write it refuses. A refusal can only stall the cells that node leads, and only until the party opts it out (§10) or it is cut (§13).

<!-- spec-section: STOR-018 -->
### 18 DLV exemption

**Rule (Owner decision)**

1. Creating a DLV consumes the creator's credits like any write.
2. After creation, a DLV's objects and cells, and writes to them, never depend on anyone's credits or payment, the owner's included, because everyone depends on them.
3. A lapse in payment never removes or cancels a DLV.
4. A DLV's storage set is the network-pinned set (§10); its succession is driven by the network (§12.2), never by the owner.

<!-- spec-section: STOR-019 -->
### 19 Retention

**Rule (Owner decision)**

1. A node MUST NOT delete, expire, or age out held bytes because of lapsed payment, owner inactivity, or owner death.
2. The only path by which an operator's memory for a role empties is handover (§12.5).
3. Reads for verification cost no credits. Receiving value, and verifying provenance, MUST NOT cost the reader anything.
4. **Pruning (Owner direction; Open).** Data past a certain age is to be pruned by a sliding window, with age measured in logical units (positions, generations or ByteCommit cycles), never time. Until the window and its exemptions are specified, nothing is pruned. Whatever rule is adopted MUST NOT make a slot that held a claim read as empty, and MUST NOT prune live DLV or dBTC backing material.

<!-- spec-section: STOR-020 -->
### 20 Owner independence

**Rule (Owner decision)**

No safety property, and no party's liveness other than the owner's own, may depend on the owner continuing to exist. In particular:

1. Retention is never tied to owner activity (§19).
2. Operator exit is by handover, never by dropping held memory (§15).
3. Retirement effectiveness, the survivor rule, and any consequence of `Frozen(K)` are verifier rules, never owner actions.

---

## Part V — Repair

<!-- spec-section: STOR-021 -->
### 21 Repair

**Rule (Adopted: October 2025 spec §11)**

1. After a prune or an exit, any client MAY restore missing replicas of immutable objects. Acceptance is by hash only, so a client's repair is equivalent to an operator's.
2. Keyed-cell arrival order is not repairable by clients. It moves only by handover (§12.5). If it is lost, the cell is resolved by §12.6.

---

## Part VI — Obligations, conflicts, and open items

<!-- spec-section: STOR-022 -->
### 22 Proof obligations

| # | Obligation |
|---|---|
| 22.1 | History invariance: a handover changes no `LeaderHeld`, `Preserved` or `Final` fact for any cell. |
| 22.2 | Loss soundness: under §3, with at most two seats lost, the rule of §12.6 selects the pre-loss final value whenever one existed, never selects another value, and freezes only if the leader equivocated. |
| 22.3 | Retirement convergence: with at most two seats named per record, no two verifiers act on different occupants of one seat. |
| 22.4 | Registry determinism: any two verifiers holding the same winning registry candidate and its referenced inputs compute the same registry. |
| 22.5 | Rebind unpredictability: the party cannot compute `s_rebind` before its retirement is effective. |
| 22.6 | Route immutability: no binding, registry, or retirement event changes `R(K)`, and so `L(K)`, for any committed cell. |
| 22.7 | Chain uniqueness: at most one value has a valid leader link at a cell, so at most one value is preserved or final. |
| 22.8 | Mirror soundness: bytes a third party presents as a node's ByteCommit never enter another node's mirror of that node (§14). |

<!-- spec-section: STOR-023 -->
### 23 Conflicts for the owner

<!-- spec-section: STOR-023-1 -->
#### 23.1 With the pinned corpus

| # | Conflict | Resolution |
|---|---|---|
| 1 | DSM §11 says the node "stores the payment receipts and counts distinct operators" before permitting writes. | **Owner ruling:** nodes enforce their own payment (§16, §17). Applied as DSM Amendment A2. |
| 2 | DSM §11 says a node never refuses a value, yet gives the spool admission gates. | **Owner ruling:** routing exists only through a pre-established contact, so a non-contact has nowhere to send; the node refuses nothing on protocol grounds and the checks are done by the devices at both ends (§8). Applied as DSM Amendment A3. |
| 3 | SoFi §40.4 (Part VIII, a historical implementation plan) keeps a gate requiring the root register to decode and verify signed single root claims and check attribution. SoFi §12 says a member never checks, decodes, or decides anything, and DSM §11 agrees. | **Owner ruling (by §8's reasoning):** a node that checks the writer can block, so the root register must not verify caller signatures. SoFi §12 governs and the Part VIII gate is retired. Applied as SoFi Amendment S2. |
| 4 | SoFi §6 says membership is frozen per vault and replacement is unspecified; SoFi §46 reserves `DSM/sofi/membership-handover/v1`. | Part III of this document; the reserved tag becomes SoFi's encoding of §12.5. |
| 5 | DSM §62 prices storage traffic with prepaid credits, while an earlier decision priced storage by monthly subscription. | **Owner ruling:** credits adopted, at a fixed network price per storage used (§17); the subscription is removed. |
| 6 | DSM §63 calls a vault's storage set owner-chosen, while SoFi §6 and §10 here make it the network-pinned set. | **Owner ruling:** the set is assigned, never chosen. Applied as DSM Amendment A5. |
| 7 | SoFi §8 and DSM §9, §11 define finality as first at the leader and held by two other members, which cannot recover a lost leader soundly (finding GPT-4). | **Owner ruling (2026-09-22):** finality is the route chain of §9. Applied as SoFi Amendment S4 and DSM Amendment A6. |

<!-- spec-section: STOR-023-2 -->
#### 23.2 From the October 2025 specification, not adopted

| Item | Why not |
|---|---|
| "No validators, sequencers, or leaders" | Every keyed cell has a leader (DSM §9, §11; SoFi §7). |
| Nodes MUST reject on partition, address, or capacity mismatch | A node refuses nothing on protocol grounds (DSM §11); the only refusal it may make is for its own payment (§17). Address checking on immutable objects is kept (§5). |
| Redundancy N = 6 per object, reads succeed with any K = 3 | Five members per committed set; finality is a three-link route chain, the leader first (§9; SoFi §6, §8 as amended by S4). |
| Per-object placement over the whole registry | Committed sets per vault or party (§10). |
| ByteCommit accepted by mirror count | "Nobody counts toward a threshold" (DSM §3); §14 here. |
| Its keyed Fisher–Yates variant | SoFi §7.1 governs. |
| `DLVCreateV3` / `DLVOpenV3` | Superseded by the SoFi DLV model. |
| Storage in an `.instructions.md` file with `applyTo: '**'` | Protocol text belongs in `specs/` (specs README). |

<!-- spec-section: STOR-024 -->
### 24 Open items

| # | Item |
|---|---|
| 1 | Where the device register's committed set lives in device state (§10). |
| 2 | Endpoint resolution for roles: network configuration or a committed object (§11). |
| 3 | Consequences of `Frozen(K)`, and whether it triggers the tripwire (§12.6). |
| 4 | The performance criterion for pruning, expressible over committed evidence (§13). Cadence regularity (§9.1, §13.7) is one criterion; the rest are undecided. |
| 5 | Whether vaults keep a single network-pinned set as the network grows (§10). |
| 6 | Wire formats and domain tags for retirement, loss, handover, and registry-successor objects, and for arrival records, route links, empties and the per-key running hash (§6, §9, §14). |
| 7 | The challenge deadline X, the wire form of challenges and drop claims, and SoFi's rule for a dropped pending result (§9.1). |
| 8 | The credit price, its token, and how a price change is made (§17). |
| 9 | How a credit payment is split among the five operators that store a write (§17). |
| 10 | Whether nodes also refuse writes from accounts whose credits are exhausted, or only receivers enforce credits (§17). |
| 11 | The pruning window and its exemptions (§19). |
| 12 | The minimum network size: a set needs five distinct operators, and replacements need more to draw from (§12). |
| 13 | Whether opting out of a member should carry a cost (§12.4). |
