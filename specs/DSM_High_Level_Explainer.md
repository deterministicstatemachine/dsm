---
title: Deterministic State Machines Explained Mathematically
document_role: engineering-source
source_format: PDF
conversion_policy: faithful
normative_note: The source PDF controls if conversion layout is ambiguous.
amendments: Owner amendments of 2026-09-22 are marked "Amendment" in the text. Where marked, this Markdown governs over the source PDF.
---

# Deterministic State Machines Explained Mathematically

> **Engineering-source conversion.** Original wording and section numbering are preserved. `Source PDF page` markers provide publication traceability. Formatting added by this Markdown edition (stable section anchors, Markdown tables, and conversion notes) is non-normative. Where a diagram's spatial layout matters, the source PDF graphic controls.


<!-- Source PDF page 1 -->

**Subtitle:** Bilateral State, Sparse Merkle Trees, Determinism, Precommitment, Linear Resources, Canonical State Chaining, and Conflict-Local Finality

**Author:** Brandon Ramsay
**Organization:** Irrefutable Labs Inc.


## Abstract
The Deterministic State Machine (DSM) is a guarded, linear, forward-only, constraint-based state
architecture. Its purpose is to make state validity derivable from canonical cryptographically committed
state rather than from a global ordering authority.
DSM does not require a blockchain, validator set, sequencer, mempool, gas market, clock-based
transaction ordering, or global consensus mechanism for ordinary state evolution. Instead, validity
is established locally from canonical bytes, bilateral relationship chains, Sparse Merkle Tree (SMT)
commitments, cryptographic precommitment of candidate futures, deterministic guards, explicit
linear-resource consumption keys, signatures, policies, and proofs.
The important architectural change is not merely that DSM orders fewer things. DSM removes
global ordering from the state-validity mechanism. Where an application itself requires an ordering
relation, that relation can be represented explicitly and deterministically inside committed state or
policy rather than being supplied by a universal external transaction-ordering system.
Multiple possible futures may be precommitted from one parent state. However, conflicting futures
over the same linear resource are forced to derive the same authoritative resource-consumption key.
Once one such resource is consumed in a realized state lineage, a second conflicting consumption
contradicts the validity rules.
The mathematics needed to understand the construction is intentionally elementary. Functions,
sets, Boolean logic, hashes, trees, algebra, and proof by contradiction are sufficient to understand the
principal safety theorem.
Throughout the paper, shaded comparison boxes explain how Bitcoin solves the corresponding
problem and where DSM differs architecturally. These comparisons do not rely on claiming that
Bitcoin is defective. Bitcoin deliberately solves global decentralized monetary ordering with proof of
work and UTXOs. DSM solves the state-transition problem differently: by making conflict, linearity,
authority, and admissible futures properties of authenticated state itself.


<!-- Source PDF page 6 -->

## Part I — What Is Claimed, and Who Decides
The reader’s objections, answered in the order they occur. The mathematical claims used here are
constructed and proved in Part II. Operational claims about storage, position binding, leader selection,
and offline identity are stated explicitly as protocol assumptions and implementation obligations, and are
revisited in Parts IV and V.


<!-- spec-section: DSM-HL-001 -->
### 1 The Central Question
A distributed system must answer a basic question:

If several machines can propose changes to state, how does a verifier know which changes are
valid?

A common answer is to construct a universally ordered history.
For example,

T1 < T2 < T3 < T4 < T5 .
If everybody accepts the same ordering, then a conflict can be resolved by asking which transaction
came first in the accepted history.
DSM takes a fundamentally different approach.
It asks:

Can the validity and conflict rules be represented directly inside cryptographically committed
state so that a verifier does not need a global ordering service at all?

DSM’s answer is yes.
The core safety objective is:

For one committed linear resource, two conflicting consumptions
cannot both occur in one valid realized history.

This does not require every operation in the entire system to be placed into one total order.
Instead, each transition carries enough canonical structure for a verifier to determine whether it is a
valid continuation of the state it claims to extend.

<!-- spec-section: DSM-HL-001-1 -->
#### 1.1 Candidate Futures Versus Realized Futures
DSM permits multiple candidate futures.
Suppose state s has candidates

P (s) = {c1 , c2 , c3 }.
All three candidates may be legitimate possibilities.
But possibility is not realization.

candidate future ≠ realized future
The safety property concerns which candidates can become part of one valid realized state lineage.


<!-- Source PDF page 7 -->

#### Bitcoin Comparison

Bitcoin solves double-spend prevention by maintaining a shared proof-of-work blockchain from which
the accepted UTXO state is derived.
Conflicting transactions may exist, but the accepted chain history determines which spend survives.
DSM does not use a global chain-selection rule as the state-validity mechanism.
Instead, a conflicting set of DSM branches is tied to a common linear resource. The shared resource
is consumed once, and the canonical successor state records that fact.
#### Architectural consequence
DSM removes the requirement that unrelated state transitions participate in one common ordering
contest.
The conflict rule travels with the state resource itself.


<!-- spec-section: DSM-HL-002 -->
### 2 The Entire DSM Idea in One Diagram

Canonical parent state


Precommitted candidate futures


the successor becomes the next parent
Deterministic guards


Canonical linear-resource descriptors


Derived shared resource-consumption keys


Consumed-resource set Σ


Canonical successor state


Next precommitted future space

Colour key used in every diagram:

parent state        candidate          resource / key      realized   rejected                                           evidence


The system therefore forms a repeating cycle:

state → candidate space → guarded realization → resource consumption → new state


<!-- spec-section: DSM-HL-003 -->
### 3 Six Answers Before the Mathematics
A reader coming from Bitcoin or Ethereum will not read this document in the order its mathematics
is built. They will read it with a list of objections, and each time an objection is not answered on the


<!-- Source PDF page 8 -->

page where it occurs they will fill the gap themselves, usually with “validator set,” “hidden consensus,”
“payment channel,” or “trusted database.” The rest of the document would then be spent undoing a
misconception it allowed to form.
So the answers come first, in one table, with the section that earns each one. Everything after this
section is explanation, not suspense.

| The question the reader has | The answer, and where it is earned |
|---|---|
| What replaces global chain ordering? | Deterministic derivability from committed state. A verifier recomputes validity from the parent, the candidate, and proofs; it never asks which transaction came first in a shared history. (Sections 6, 52) |
| What stops two branches consuming one resource? | They derive the same consumption key K from the same committed parent and the same resource descriptor. Realization adds K to a monotonic consumed set Σ; the second branch fails the check K ∉ Σ. This is a theorem, not a policy. (Sections 7–8, 52) |
| What if Bob and Charlie see different branches? | Alice’s balance is one resource in Alice’s own device root, and that root carries a position. Each position has one cell, and one member of the storage set, its leader, is derived from the position and the committed root. Alice writes her signed root claim there first. The first claim that names the cell at the leader is the one that counts; only Alice can sign one. Charlie reads the next cell before accepting. Two phones do not help her. (Section 9) |
| Who determines whether a transition is valid? | The recipient. Bob verifies what Alice presents against his own copy of the frontier and the committed policies. No third party is consulted for validity, and no third party could be. (Sections 5, 11, 12) |
| What does storage determine? | Persistence and availability, nothing else. A storage node holds no key and signs nothing, never evaluates a guard, never computes a balance, never refuses a value and never compares one with another. It keeps what it is given, in the order it arrived, and returns it. Every byte it returns proves itself. (Section 11) |
| Is there a quorum? | No. For each cell, one member of the owner-committed storage set is the leader, computed by a deterministic shuffle seeded from committed state; no node id and no availability view enters the seed, and no node knows which cells it leads. The writer writes to the leader first, then to the other members. The first object naming the cell at the leader is the winner; the value is final once the leader and two other members hold it. The verifier reads the members raw and derives both facts itself. Nobody votes, nobody counts toward a threshold, and the other members are copies. (Sections 9, 11, 63) |

The reader who holds those six answers can read the rest of this document as a proof that they are
true, rather than as a search for whether they will be.


<!-- spec-section: DSM-HL-004 -->
### 4 The Two Halves of an Agreement
One more frame before the mathematics, because it is the frame the whole system is easiest to hold in.
Every agreement between two parties has two halves, and DSM settles them in different ways.

Truth. Given the prior state, is this a possible and truthful outcome? The state machine settles that
by construction. A transition that is not a valid successor of the state it claims to extend cannot be
built: it fails the realization predicate of Part II and therefore never exists as a state. So a malformed or


<!-- Source PDF page 9 -->

malicious transition is not something a verifier has to discover and discard; it is not producible in the
first place. This is what lets a local operation be trustworthy at global scale without global coordination.
Two parties settle between themselves, and the result is true for everyone, because everyone who holds
the bytes recomputes the same answer.

Consent. Out of the outcomes that are possible and true, which ones do the parties actually agree
to? Truth alone does not settle that. An outcome can be true and still not be one the other side would
accept, because the other side may have terms. Consent is the parties’ own, and it is captured in one of
two ways depending on whether the other party is present.

- Offline, both parties are present. They decide on the spot what their terms are, and if both
agree, both sign. Liveness is there, so consent is gathered live (Part IV).

- Online, movement is unilateral (Section 12) and the other party need not be present, so its
consent has to exist already. That is what a Deterministic Limbo Vault is: one party’s terms, stated
ahead of time and committed into its own state, so that anyone who meets them completes an
agreement the owner already consented to, without the owner being there (Sections 58 and 63). A
bilateral chain converges to global consistency without global coordination, and the vault is how
one side of an agreement is supplied in advance.

#### Key Idea

Truth is never negotiated, on any path: the transition predicate settles it. Consent is always the
parties’ own: gathered live when both are present, and posted in advance as a vault when one is not.

Both halves are recomputable by anyone who holds the bytes. The difference is only where the second
half comes from: two live signatures, or one committed set of conditions and one transition that meets
them.

#### Just enough notation to read Part I
Part I uses the following symbols before they are formally constructed in Part II. The constructions are
exact there; here they are only named.

State s, root ρ. A device’s core state is committed by ρcore , the root of a Sparse Merkle Tree over the
device’s leaves; the full state commitment ρ additionally binds the digests of the precommitted
candidate space and the guard family. Changing any of them changes ρ.

Position u. In online mode, u is a committed integer position that increments on every value-moving
advance. More generally, u is the mode’s monotonic progression object. A root is always presented
together with its position, (ρ, u).

Candidate, realized. A candidate is a successor a device is allowed to construct from s; many candidates
may exist at once. A successor is realized when a counterparty accepts it and it becomes part of
the lineage. At most one conflicting consumption of a linear resource can occur in one valid realized
lineage; showing why is the job of Part II.

Guard g. A deterministic predicate a candidate must satisfy to be accepted: a signature, a hash preimage,
a threshold, an arithmetic bound. Some guards are static (their family is written G5 ); some depend
on what has already been realized (G7 ).


<!-- Source PDF page 10 -->

Resource descriptor x, key K. A descriptor names the thing being consumed: a balance, a vault
generation, a recovery generation. The consumption key is derived as K = κres (s, x) from the parent
state and the descriptor, and only from those, so two candidates that consume the same thing from
the same parent derive the same K whatever else they differ in.

Consumed set Σ. The set of keys already consumed in a lineage. It only grows. The realization rule
includes K ∉ Σ.

Relationship chain. Every pair of parties A ↔ B has its own hash chain with its own leaf in each
device’s tree. Chains never share a parent, key, or counterparty.

Mirror, register. Storage nodes hold copies of committed roots and receipts (the mirror) and a set of
keyed cells, one per (genesis, device, position) (the register), each with one leader member derived
from committed state. Neither validates anything, and a member never refuses a value.

That is all Part I needs. Where a section in Part I relies on a claim that Part II proves, it says so and
gives the reference.


<!-- spec-section: DSM-HL-005 -->
### 5 The Six Questions Every Transition Must Answer
Given parent state s, candidate successor s′ , and witness w, DSM asks:

1. Was s′ actually precommitted by s?

2. Has the correct deterministic guard been fulfilled?

3. Does s′ preserve the required state structure?

4. Are the linear resources required by the branch still unconsumed?

5. Does the transition obey committed deterministic policy?

6. Does it satisfy any mode-specific requirements?

The full acceptance predicate is

Accept(s, s′ , w) = CandidateOK(s, s′ )
∧ GuardOK(s, s′ , w)
∧ StructuralOK(s, s′ )
∧ LinearityOK(s, s′ )
∧ PolicyOK(s, s′ )
∧ ModeOK(s, s′ ).

Every term is Boolean.
Therefore,

Accept(s, s′ , w) ∈ {True, False}.

> **Amendment A1 (owner, 2026-09-22) — acceptance stays binary.** A transition either satisfies the full acceptance predicate or it does not execute. There is no third kind of protocol truth. Everything that can be decided from evidence already in hand is evaluated first, and a transition found Invalid there never reaches the network layer (Amendment A4).
>
> - **Evidence that cannot be obtained yet is not a verdict.** If the network evidence the predicate needs is not currently in hand, Accept has not been evaluated. The attempt does not execute and can be retried. Fetching and retrying belong to the network layer beneath the protocol, and Unavailable is never a value of any protocol predicate. Software may report it through an API status such as Pending or Unavailable, so that it retries rather than reporting the transition as invalid. Both layers can end in Invalid. Evidence obtained from the network is checked like anything else and can show the transition Invalid, for example a register cell holding a different root. And when retrying ends without the evidence, the transition does not execute: Accept is False, nothing moves, and nothing is recorded. Where other parties depend on the outcome, retrying ends only through the challenge rule of `DSM_Storage_Node_Specification.md` §9.1, so every verifier reaches the same result at the same point.
> - **Nothing negative is recorded.** A transition that does not execute changes no state, and nothing negative is recorded anywhere. Bytes written while it was attempted (a losing attempt, a challenge, a chain that never completed) stay in storage as raw material, and are never a verdict.
>
> Where something else waits on the outcome, the subsystem derives for itself, from raw reads, whether a transition that has not executed can still execute. SoFi does this for a vault's attempt slots (SoFi §23, §24). The next trade against a vault needs a reliable available balance, so it proceeds only once the trade ahead of it has either realized or can provably never realize. Treating "not yet" as "never" there would let two trades spend the same reserves; treating "never" as "not yet" would stall the vault. A pending outcome can be brought to an end by the challenge rule of `DSM_Storage_Node_Specification.md` §9.1.


<!-- Source PDF page 11 -->

<!-- spec-section: DSM-HL-006 -->
### 6 DSM Does Not Need Global Ordering
This point deserves explicit wording.
DSM does not merely reduce global ordering.
It removes global ordering from the validity mechanism.
The system’s validity rules are expressed through:

- canonical parent state;

- explicit dependencies;

- bilateral chain adjacency;

- authenticated roots;

- precommitted successor space;

- deterministic guards;

- linear-resource consumption;

- policy.

If an application requires a sequence relation, that relation can be encoded as part of state.
For example, if an application needs:

x1 ≺ x2 ≺ x3 ,
that dependency can be represented explicitly in the canonical state machine.
It does not require the entire network to globally order unrelated operations alongside it.

#### Bitcoin Comparison

Bitcoin intentionally constructs a global proof-of-work ordering for monetary transactions.
DSM does not use a universal transaction-ordering system.
#### Architectural consequence
Ordering becomes an explicit state constraint only when the application semantics require it.
It is not an infrastructure requirement imposed on all state.
Therefore DSM sacrifices neither deterministic validity nor linear-resource safety by removing global
ordering from the architecture.


<!-- spec-section: DSM-HL-007 -->
### 7 Concrete Double-Spend Example
Suppose Alice controls one 10-unit resource xA .
Two candidates are precommitted:

cB : 10 → Bob,


cC : 10 → Charlie.
Both consume the same source generation.
Therefore:


<!-- Source PDF page 12 -->

KB = κres (s, xA )
and:

KC = κres (s, xA ).
Hence:

KB = KC = K.
Initially:

K ∉ Σs .
Suppose Bob’s branch realizes.
Then:

ΣB = Σs ∪ {K}.
Charlie’s branch would now require:

K ∉ ΣB .
But:

K ∈ ΣB .
Therefore the second conflicting realization is invalid.


<!-- spec-section: DSM-HL-008 -->
### 8 Both Candidates Can Look Valid
A careful reader will notice something about the example above.
Charlie’s branch is rejected after Bob’s branch has been folded into the lineage. Before that, against
Σs alone, both branches pass every check: both are precommitted, both guards can be satisfied, both
derive K, and K ∈ / Σs .
That is not a flaw. It is the same situation as Bitcoin, and it is worth saying so plainly.
Two Bitcoin transactions spending the same UTXO are each individually valid. The scripts verify,
the signatures verify, the input exists. What decides between them is not validity; it is which one the
chain includes.
DSM has the same two-valid-candidates moment. What differs is what settles it.

#### So who picks?
In Bitcoin, the chain picks, and the chain is a global object that many parties contend to extend.
In DSM, nobody picks, because there is nothing to pick between at the point where it matters. A
resource has one acceptor, and that acceptor’s accept step is atomic: the successor root and the updated
Σ are adopted together or not at all. Whichever candidate the acceptor folds in first has consumed K by
the time the second is evaluated. There is no window in which two candidates are both accepted and
awaiting resolution.

Bitcoin: two valid candidates → ordering contest → one survives
DSM: two valid candidates → one atomic accept → the other is no longer valid


<!-- Source PDF page 13 -->

#### Bitcoin Comparison

Bitcoin readers already know that “valid” and “confirmed” are different words. DSM keeps that
distinction and renames the second half: a candidate is valid against a parent, and it is realized once
the one acceptor has folded it into the lineage.
#### Architectural consequence
The step from valid to realized is a local, atomic accept at one party, not a global contest. There is
no interval during which two conflicting candidates are both “accepted but unresolved.”
#### Tradeoff / boundary
The static form of the theorem, where at most one candidate even passes the predicate, is a property
of selector families only. The explainer’s uniqueness theorem in Section 52 is the realized-history
form, which is the one that covers every family.


Bitcoin                                        DSM

Parent state s
Spendable UTXO U
linear resource x


Transaction TB        Transaction TC          Candidate cB          Candidate cC


Accepted proof-of-work                        Shared consumption key
chain history                                  K = κres (s, x)

conflict resolved by ordering         conflict excluded by one key, consumed once


<!-- figure-note: Figure 1; nearby loose-layout text was extracted from the source graphic; use the PDF for spatial relationships -->
Figure 1: Different double-spend exclusion structures. Bitcoin resolves conflicting spends through the accepted
proof-of-work chain. DSM binds conflicting candidates to the same canonical linear-resource consumption key.

#### Bitcoin Comparison

#### Architectural consequence
DSM does not need a globally ordered chain to establish the exclusivity of the resource.
The exclusion condition is already committed into the resource state.
#### Tradeoff / boundary
This is a state-safety theorem about one parent and one verifier. The harder case, one payer and
two verifiers who never speak, is the subject of the next section.


<!-- spec-section: DSM-HL-009 -->
### 9 Same Balance, Two Counterparties
The sections above showed two candidates from one parent state.
A Bitcoin reader will immediately ask a harder question.
Suppose Alice does not present two candidates to one verifier. Suppose she presents one candidate to
Bob and a different candidate to Charlie, and Bob and Charlie never speak to each other.
This is the unconfirmed double spend: pay two merchants with the same coin and hope neither learns
about the other before the goods change hands.
Set it up in DSM terms.


<!-- Source PDF page 14 -->

Alice holds a balance of 10. She has a relationship with Bob and a relationship with Charlie:

rAB ,        rAC .
Step one. Alice constructs and presents a transfer of 10 to Bob over rAB . Her device state advances:

s0 → s1 ,        ρ0 → ρ1 .
Two words matter here and will be kept apart throughout: the transfer is constructed and presented
by Alice; it is accepted and realized only when Bob’s verifier says so. What Bob requires before saying so
is the subject of this section.
Step two. Alice constructs a second transfer of 10, this time to Charlie over rAC , and builds it from
s0 as if step one had never happened.

#### Why the relationship chains alone do not catch it
The two relationship parents are different resources:

xAB = (relationship, kAB , hAB,n ),         xAC = (relationship, kAC , hAC,m ).
They derive different keys. Neither chain knows about the other. Relationship linearity is not what
stops this case, and neither is the non-crossability of Section 10: Alice is not replaying a Bob transition
to Charlie, she is building a fresh, correctly addressed A ↔ C transition from a stale root.

#### Where the balance lives
Alice’s balance is not stored inside either relationship chain. It is a leaf in Alice’s device SMT, committed
by her core root ρcore .
Its resource descriptor is holder-scoped:

xbal = (cpta-balance, GT , PT , Alice).
Both transfers consume the balance. Both therefore derive the same key from the same parent:

Kbal = κres (s0 , xbal ).
After step one:

Kbal ∈ Σ1 .
The transfer to Charlie is a second child of s0 consuming a key that s1 already records as consumed.
By the uniqueness theorem it cannot join the lineage that contains s1 .
But Charlie has never seen s1 . Against s0 alone, the transfer to Charlie looks perfect: the rAC leaf is
present, the balance leaf reads 10, and Kbal ∉ Σ0 .
So the remaining question is exactly the Bitcoin reader’s question:

How does Charlie know that s0 already has a child?


<!-- Source PDF page 15 -->

#### The committed position counter
Every DSM device root carries a committed progression object u (see the state object in Section 29). In
online mode it is a position counter. Every root advance increments it:

(ρ0 , n) → (ρ1 , n + 1).
The counter is inside the root, so the root cannot advance without the counter and the counter cannot
advance without the root.

#### What Charlie holds
A relationship is not created by first contact. It is created by both sides taking the counterparty’s
committed device state from the storage-node mirror and verifying it. From that moment Charlie holds
Alice’s committed position:

(ρA , uA ).
Charlie does not trust the mirror. He verifies the signed root chain that produced (ρA , uA ). The
mirror supplies bytes; Charlie supplies the verdict.

#### The check at acceptance
When Alice presents a transfer to Charlie, the presented parent carries a position. Once he has
checked everything he can from what he already holds (Amendment A4), Charlie asks one question: what root does Alice’s device hold at the next position?
He can ask it because every value-moving advance of a device root has to be registered. The storage
set keeps an economic-root register : a cell for each

(G, DevID, position),

where G is the genesis and DevID the device. The cell’s key is derived from those three values, so anyone
can compute it. So is the cell’s leader : one member of the storage set, chosen by a deterministic shuffle
seeded from G, DevID, the position and Alice’s validated root at the previous position. No node id and
no availability view enters the seed, so nobody, Alice included, can choose the leader, and no node knows
which cells it leads.
What Alice writes there is a signed root claim, and only Alice can sign one. She writes it to the leader
first, then the same bytes to the other members. A member keeps everything it is given, in arrival order;
it authorizes nothing, refuses nothing and compares nothing (Section 11). The rule that decides the cell
is Charlie’s to evaluate, from raw reads: the root at position n + 1 is the first claim naming that cell at
the leader, and it is final once the leader and two other members hold it. A claim the leader does not
hold is never final, and if the leader is unreachable the cell waits; no other member stands in, because a
fallback chosen by who is reachable would let two writers settle at two different nodes. There are exactly
three outcomes:

- The cell holds a root that is not the one Alice is presenting. Alice’s device has already moved past
n; the presented parent is superseded. Reject.

- The cell is empty. Charlie will accept only once Alice has registered the Charlie-transfer root at
n + 1 and Charlie has derived it final from his own reads. If Alice will not register, Charlie does not
accept.

- The cell holds exactly the presented root. Accept.

> **Amendment A4 (owner, 2026-09-22) — order of checks at acceptance.** The receiver first evaluates everything it can decide from what it already holds: it decodes the presentation, verifies its signatures and the payer's signed root chain, and runs the precommitment, guard, linearity and policy checks as far as the evidence in hand allows. If any of these is Invalid, the transition is Invalid and the network is never touched. Only then does it read the register cell and fetch any other evidence it still needs. This supersedes the order drawn in Figure 2 (§12), which places the register read before the precommitment and guard checks.
>
> - **Why checks on what is in hand come first.** A transition that is invalid on what the receiver already holds never reaches the network part: no storage read is spent on it, and no one's cell is read on its behalf.
> - **Why authentication comes before the register read.** The cell's leader is derived from the payer's validated root at the previous position, so the receiver cannot even compute which member to ask until that root is verified.
> - **The verdict does not depend on the order.** Accept is a conjunction, so every order gives the same result. The order binds only what the receiver does on the way: nothing is fetched from the network for a transition that is already Invalid on what the receiver holds.


<!-- Source PDF page 16 -->

In the story above, Alice presented a transfer to Bob at n + 1. Bob, being an honest acceptor, applied
the same rule: he treated the transfer as realized only once the cell at n + 1 held ρ1 . So either Alice
registered ρ1 , in which case Bob accepted and Charlie’s read returns ρ1 ≠ ρ′0 and he rejects; or she
never registered it, in which case Bob never accepted, holds candidate and receipt material rather than a
realized transfer, and Charlie’s acceptance is what forces ρ′0 into the cell. She cannot have both.
Bob’s own copy of the receipt is still on the mirror, and it is still useful: it is a second witness to the
same fact. But it is not what the argument rests on.

register cell
Alice s0     spend 10 to Bob       Alice s1           Alice registers
(G, DevA , n + 1)
(ρ0 , n)                          (ρ1 , n + 1)
first claim at its leader: ρ1

verified, not trusted


spend 10 to Charlie                    presents ρ′0 at n + 1                     Charlie reads cell n + 1
built from s0
at the leader and two others
(ρ0 , n) → (ρ′0 , n + 1)


rejected: cell holds ρ1 ≠ ρ′0
before any guard runs
Only Alice’s device can write Alice’s cells,
and it can write each one once.


#### Two wallets, one owner
The obvious way to try to defeat a check that relies on a counterparty is to be the counterparty. Alice
runs two wallets, W1 and W2 . She pays W2 from W1 at position n + 1 and tells nobody: no push to any
mirror, no receipt anywhere. Then W1 pays Bob from the same balance, also at n + 1.
If the position check were “ask the previous counterparty,” this would work, because the previous
counterparty is Alice. Bob would see W1 at n, accept, and Alice would hold the value in W2 while Bob
believed he held it too.
Against the register it fails in the same way as before, because the cell for (G, DevW1 , n + 1) belongs
to W1 , not to whoever W1 paid. Bob’s acceptance requires that cell to hold the Bob-transfer root. Either
it already holds the W2 -transfer root, and Bob rejects; or it is empty, Bob requires W1 to fill it with
ρBob , and from then on W2 ’s incoming receipt names a root at n + 1 that the register contradicts. The
next time W2 tries to spend that value to an honest acceptor who walks provenance back one hop, the
equivocation is a comparison of two leaves.
The register does not care who the counterparty was. It cares that a device can name one root per
position, and that the device is the only party who can do the naming.

#### Two roots at one position
Suppose instead that Alice tries to present a root at position n + 1 that differs from ρ1 . Then two distinct
roots claim the same position under the same device. That is a fork, and it is decidable on sight: any
party holding both compares two leaves and is done. The register exists so that the second leaf can never
be acknowledged anywhere honest; the fork is refused at the cell, not discovered afterward.

#### What this does and does not depend on
It depends on the leader keeping what it holds, in the order it arrived, across restarts and restores, and
never altering or losing it. That is the storage fault model, stated as such in Section 11 and listed in


<!-- Source PDF page 17 -->

Section 80. It does not depend on the storage node validating anything, ranking anything, refusing
anything, or signing anything; a node will store a nonsense claim perfectly consistently, and whether the
root inside it is the result of a valid transition is Charlie’s question. Storage remains outside the authority
path.
If the leader is unreachable, Charlie is not a weaker online verifier. He is, by definition, an offline
receiver. That case has its own machinery: the committed anchor counter, commit-time identity witnesses,
and the measurement gate of Sections 66–71.

#### Key Idea

Online, a device names one root per position: the first signed claim that reaches the cell’s leader,
and only the device can sign one. The double spend is not resolved later by a chain. It is refused at
acceptance by reading one cell.


#### Bitcoin Comparison

A Bitcoin merchant who accepts an unconfirmed transaction is exposed until the transaction is
mined, because a conflicting transaction may be mined first. The merchant cannot know, at the
counter, whether the coin has already been spent elsewhere. Confirmation depth is the remedy, and
it is a waiting period.
DSM requires no confirmation-depth waiting period for this case; acceptance still requires the cell’s
leader and two other members to respond. The payer’s committed position is part of the payer’s
state, the payer’s root at each position is the first claim its own device got to the cell’s leader, and
the receiver reads the next cell at the moment of acceptance.
#### Architectural consequence
The information a Bitcoin merchant is waiting for is exactly the information a DSM receiver already
has: whether the payer’s state has moved past the parent being presented. DSM commits that fact
as a counter inside the payer’s root and binds each position to one root: the first claim at the cell’s
leader, which nobody but the payer can sign and which no later write can displace.
#### Tradeoff / boundary
This is an online property. It relies on reaching the cell’s leader and two other members, and on the
leader keeping what it holds in arrival order, which is an availability and storage-integrity question,
not a validity one. A payer who withholds does not gain a second spend; the receiver simply cannot
accept, which is a liveness failure. When the leader is unreachable at the moment of exchange, the
cell waits and the receiver is in offline mode, where the offline machinery applies.


<!-- spec-section: DSM-HL-010 -->
### 10 A Transition Cannot Cross Relationships
There is a second exclusion in DSM that is easy to miss because it never needs a theorem. It is built into
the addressing.
Every relationship is its own hash chain. A ↔ B and A ↔ C do not share a parent, a leaf, a key, or a
counterparty. A transition that happened between Alice and Bob is not an object that can be picked up
and replayed between Alice and Charlie.
Look at what a transition on A ↔ B actually carries:
- its parent hAB,n , which is a node of the A ↔ B chain and of no other chain;
- its SMT leaf key kA↔B , which embeds both device identifiers;
- its resource descriptor xAB = (relationship, kAB , hAB,n ), and therefore its consumption key KAB =
κres (s, xAB );


<!-- Source PDF page 18 -->

- Bob’s signature, over canonical bytes that name Bob’s device.

Now try to present that transition to Charlie as a step on A ↔ C. It fails four separate times.

parent hAB,n              is not adjacent to hAC,m
leaf key kAB              ≠ kAC
consumption key KAB        ≠ KAC
signature by B              is not a signature by C
Any one of these is fatal. There is no reframing, re-keying, or re-signing that turns a A ↔ B object
into a valid A ↔ C object, because the relationship identity is hashed into every layer.

A ↔ B chain                  receipt for hAB,n → hAB,n+1
· · · → hAB,n → hAB,n+1                   kAB , KAB , sigB


replay into A ↔ C?


A ↔ C chain                     not adjacent / wrong leaf key
· · · → hAC,m               wrong consumption key / wrong signer

the relationship identity is hashed into every layer


This gives DSM three orthogonal exclusions, and it helps to keep them apart:

1. Within a relationship: the parent is a linear resource. Two successors of hAB,n cannot both be
realized (Section 52).

2. Across relationships: nothing transfers. A step on A ↔ B is not a candidate on A ↔ C at all.
This section.

3. Across relationships, same balance: the balance is a holder-scoped resource in Alice’s device
root, and the root register, read at its leader, is how the second counterparty learns the root has
moved (Section 9).

The first is a theorem. The second is addressing. The third is the register.

#### Bitcoin Comparison

In Bitcoin a signed transaction is a free-standing object. Anyone who holds the bytes can relay
them anywhere, and the network will accept them from any source, because the transaction names
a UTXO rather than a counterparty.
A DSM transition is not free-standing. It names its relationship in its parent, its leaf key, its
consumption key, and its co-signature, and it is valid only against that relationship’s frontier.
#### Architectural consequence
There is no “relay it somewhere else” attack surface. A transition that exists for one relationship is
meaningless bytes to every other relationship, and the verifier does not need a rule to reject it; it
simply fails to verify.
#### Tradeoff / boundary
This is scoping, not secrecy. Charlie can be shown the A ↔ B receipt as evidence of something (for
example, as a stitched proof in a multi-party workflow). What he cannot do is accept it as a step on
his own chain.


<!-- Source PDF page 19 -->

<!-- spec-section: DSM-HL-011 -->
### 11 Storage Nodes
This document will say “storage is not authority” many times. A Bitcoin reader will want to know what
a storage node actually is, because in their world the thing that stores the chain is also the thing that
validates it, and separating the two sounds like a trick.
The description below is of the shipping node: a Rust service in front of a PostgreSQL database,
speaking protobuf over TLS. The production set is six nodes across three cloud regions at roughly ninety
dollars a month. That number is worth holding in mind against what Bitcoin’s storage-and-ordering layer
costs.

#### The rule the code enforces
A storage node holds no key and signs nothing, ever. It never validates a protocol rule, never evaluates
a guard, never computes a balance, never refuses a value on protocol grounds (Amendment A2), never
compares one value with another, and
never decides whether a transition is valid. Economic and protocol payloads are opaque to it apart from
content addressing: it stores bytes under the hash of the bytes, keeps what it is given for a key in the
order it arrived, and returns what it holds. The node does not vary acceptance by what a payload would
parse as; an earlier store did, and it was replaced because a generic substrate cannot. Nothing in any
protocol-relevant path reads a clock; ordering inside the node uses logical ticks.
Inter-node gossip exists, and it is state synchronisation only: no leader election, no Raft, no Paxos
between nodes, no vote.

> **Amendment A2 (owner, 2026-09-22) — payment is the one refusal.** A node may refuse a write addressed to an account that has not met the one-time spend-gate below. It refuses nothing else, and nothing on protocol grounds. It may also refuse a write addressed to an account whose storage credits are exhausted: the spend-gate is the first payment and credits are the continuing one, so an account keeps paying for its storage (owner, 2026-09-23). Both refusals are keyed on the account written to, and both are outside beta.
>
> - **Paying and getting through are separate.** A party pays for storage with credits (storage spec §17); how a payment is split among the five members of its set is open (storage spec §24, item 9). A write goes through once its route chain has three links (Amendment A6), so the other seats carry what one member refuses.
> - **The one exception is a leader.** No member stands in for a cell's leader, so if a member refuses a cell it happens to lead, that cell waits until the party opts the member out or the network cuts it. That is a stall, never a change in validity.
> - **No further protection is needed.** A node is one of five. Refusing a paying customer loses that customer and counts against the node's performance score, for a negligible gain.
> - **Enforcement is keyed on the account the write is addressed to, never on who is writing.** Anyone may still carry a paid-up party's bytes, and the node never checks the writer (Amendment A3).
> - **It never applies to DLVs.** Creating a vault consumes its creator's credits like any write; after that, a vault's storage never depends on anyone's payment, because everyone depends on it.
> - **Storage is paid on-chain with credits.** Credits are charged by storage used at a fixed network price, counted in storage and never in time, and checked by the receiver like any debit (storage spec §17). Before acting, a client checks its own credit balance.
>
> Details: `DSM_Storage_Node_Specification.md` §16–§19.

#### What it stores
Immutable objects. A payload P in namespace N is stored at

addr = H(DSM/storage-object ∥ N ∥ H(N ∥P )),

computed by the node from the input. A caller-supplied address is checked, never used as the
key. There is no update path and no overwrite path in the code, not an update path that refuses.
Replaying identical bytes re-acknowledges; different bytes at the same address are reported as
corruption. On read the node recomputes the address before serving. The client re-hashes anyway,
because a check performed by the party being verified is not a check.

Per-device tip mirror. A public head and encrypted per-relationship leaves, keyed by device and
relationship. This is where a counterparty’s copy of a receipt lives: a second witness to a device’s
frontier, alongside the register below.

Inbox spool. Unilateral delivery for the offline counterparty. Envelopes are strictly versioned, ordered
by insertion, and read from a position; nothing is marked, hidden, expired or removed after a write. The
node never opens the envelope and checks nothing about it (Amendment A3), and every payload it holds is
ciphertext (Amendment A7).

> **Amendment A3 (owner, 2026-09-22) — routing exists only through a pre-established contact, and the node never checks the writer.** This replaces the admission gates the source placed at the node (canonical encoding, device authentication, a replay-protected message id, and a recipient key).
>
> - **A message goes to a relationship, never to a genesis account.** The relationship is the address: Its inbox address is per relationship and changes every step: the hash of the recipient's genesis, the recipient's device id and the relationship's current chain tip (owner, 2026-09-23). Nobody can send to a party it has not pre-added: with no relationship there is nothing to address.
> - **Both ends check.** The sender's device sends only over relationships it has pre-added. The recipient's device reads only relationships it has pre-added, and accepts only messages signed by the other device of that relationship. The checks the source listed are performed by the devices at both ends.
> - **The node does not check who is writing,** not even whether the writer is one of the relationship's two devices. A node that can check can block, and blocking is an authority a node must not have.
> - **What that leaves is worthless to an attacker.** Software that skips the sender-side check can compute a relationship id and write bytes under it, but nothing changes: writing into someone else's relationship needs two victims' ids and fails the recipient's signature check, and writing under one's own id and a victim's is never read, because the victim never pre-added it.

> **Amendment A7 (owner, 2026-09-23) — the spool is append-only and its payloads are sealed.**
>
> - **Append-only.** A node never marks, hides, expires or removes a spool envelope after it is written, and serves a spool from a position. Which messages a device has consumed is the device's own state, kept on the device; no node holds read state, and no one can change another party's. This replaces "acknowledged per routing key".
> - **Sealed.** Every spool payload — a transfer body, a reply, a message — is encrypted end to end between the two parties of its relationship. Each step's Kyber encapsulation, which already yields the step's shared secret, also yields a message key under its own domain tag, never reused for another step, and the payload is sealed under an authenticated cipher. A node holds ciphertext only. This is what makes "only the parties to a relationship hold its bytes" true of the spool.
> - **Not SoFi.** SoFi's objects and cells are public verification material by design — any trader walks a vault's head, any verifier checks a route, any relayer completes a registered fulfillment — and stay unencrypted.

Identity and recovery. Genesis anchoring, device-tree indexing, and recovery capsules, all stored as
bytes under derived keys.

The node’s own commitments. Each cycle a node emits an unsigned ByteCommit: a Sparse Merkle
root over what it holds, linked to the previous cycle’s digest, stored as an ordinary object under a
deterministic address and mirrored by peers. Capacity is regulated against it, and an operator exits
by proving two consecutive empty cycles. Verifiers check the chain link and the root themselves;
the node’s word is not part of it.


<!-- Source PDF page 20 -->

#### The spend-gate
Writes are not free. A device may write only once it has paid a flat rate to K = 3 distinct operators; the
node stores the payment receipts and counts distinct operators, and once the threshold is met the device
is enabled permanently. This is the join event that drives DJTE (Section 62) and it is the floor under the
spam argument: an identity costs three receipts before it can store a byte. The node enforces this gate
itself (Amendment A2).

#### The keyed cells, and where a race ends
The registers are where an honest description used to carry an exception: earlier versions of the node
refused a second value for a key, checked who was writing, and echoed a member id so that a client
could count answers toward a threshold. None of that survives, because each of those is a decision, and a
member that decides is an authority. The cells now follow one rule.
A keyed cell is a place, derived from committed state, where competing objects meet: a device’s
root claim at a position, or the successor of a vault parent in SoFi (Section 63). For each cell the writer
and the verifier compute one leader : the first member of a Fisher–Yates shuffle of the owner-committed
storage set, seeded from committed state (a device’s genesis, id, position and validated root; a vault id
and parent root). Node ids, availability and the caller’s identity never enter a seed, so the leader of a cell
never depends on who is online, nobody can choose it, and no node knows which cells it leads.

- The writer writes to the leader first, then the same bytes to the other members. Any party may
carry the bytes to members not yet reached.

- Every member keeps everything it is given for a key, in arrival order. Nothing is refused, replaced
or compared. There is no write authorization: a signed object carries its signer’s authority, and a
derived object is recomputed by whoever reads it.

- The winner at a cell is the first object naming that cell at the leader. The value is final once the
leader and two other members hold it. A value the leader does not hold is never final, so the race
ends at the leader.

- The verifier derives both facts from raw reads. No node evaluates them; the other members are
copies.

- If the leader is unreachable, the cell waits. No other member stands in, because a fallback chosen
from who is reachable would let two writers settle at two different nodes.

> **Amendment A6 (owner, 2026-09-22) — finality is a route chain.** Wherever this document says a value is final once the leader and two other members hold it (here, and in §3, §9, §63 and §80), read the rule of `DSM_Storage_Node_Specification.md` §9. The cell's Fisher–Yates shuffle fixes a route through all five seats, and its first seat is the leader. The writer writes to the seats in route order, and each copy after the leader carries the chain of arrival records returned so far, proving the value was first at the leader. A value is final when its chain has the leader's link and two further links. Three links are not a vote: the leader fixes the order, and the two later links carry the proof of that order to seats that survive the leader, so a lost leader is recovered without guessing (storage spec §12.6). Nodes still check nothing, sign nothing and decide nothing; verifiers evaluate the chain.

Registered is not validated. A malicious device can register an arbitrary claim perfectly consistently
and the leader will store it; whether the root inside it is the result of a valid transition is the verifier’s
question and nothing the node says bears on it. What the node contributes is memory: the leader keeps
what arrived, in the order it arrived, and that fact survives restart and restore. Restoring a member from
a snapshot that predates a held value is a safety violation, not an availability event.
That is a real assumption and it should be read as one, and it is narrower than a crash-versus-
Byzantine label. Immutable-object misresponses are detectable by hash and affect availability only. The
safety-critical assumption is that a member never alters, reorders or loses what it holds. No intersection
arithmetic is needed: at most one value is final at a cell because exactly one member is the place the race
ends.


<!-- Source PDF page 21 -->

immutable objects
device                           addr = H(· · · ), no overwrite

ByteCommit
lea                           tip mirror
de               public head, encrypted leaves
SMT root, parent link,
r fi
rst                                                     unsigned
,t
he
n              inbox spool
co
pie envelopes, per-key ack
s

keyed cells
everything kept, in arrival order

every row is content-blind;
the verifier derives the winner of a cell from what the leader holds


#### Bitcoin Comparison

A Bitcoin full node stores the chain and validates every block and transaction in it; storage and
validation are one program. It cannot be trusted for anything, and it does not need to be, because
every other node re-validates.
A DSM storage node stores bytes and does not validate anything; validation happens on the two
devices at the ends of a relationship. It cannot be trusted for content either, and it does not need to
be, because the recipient re-hashes and re-verifies. What it is trusted for is narrower: to keep bytes
available, and to keep what it holds for a key in the order it arrived.
#### Architectural consequence
The entire storage tier for the network is six small instances, none of which runs a consensus protocol,
holds a DSM validation or consensus authority key, or knows what a transaction is. There is no
miner or validator role to capture because there is no role that semantically validates or globally
orders transitions.
#### Tradeoff / boundary
The keyed cells carry a durable memory assumption: a member never alters, reorders or loses what
it holds for a key, and that survives restarts and restores. And the leader of a cell must be reachable
for the cell to advance; while it is not, the cell waits, which is a liveness cost and nothing else.


<!-- spec-section: DSM-HL-012 -->
### 12 Online DSM
Ordinary online DSM does not require hardware to determine transition uniqueness.
A verifier may receive:

- canonical state bytes;

- relationship proof;

- signatures;

- Merkle proofs;

- precommitment information;

- guard witness;

- resource-consumption proof;

- policy information.


<!-- Source PDF page 22 -->

Then it performs local verification.

Receive canonical bytes and proofs


Canonical decode
authenticate
Recompute hashes and Merkle roots


Verify signatures


Read sender’s register cell at next position;
position
must be empty or hold exactly this root


Verify candidate precommitment
candidate
Verify deterministic guard


linearity       Verify resource key is unconsumed


Recompute successor state
commit
no ordering
Accept or reject locally
service consulted


<!-- figure-note: Figure 2; nearby loose-layout text was extracted from the source graphic; use the PDF for spatial relationships -->
Figure 2: Online Verification Path


<!-- spec-section: DSM-HL-013 -->
### 13 DSM Is Not a Payment Channel
A Bitcoin reader who has followed this far will have a name ready: Lightning.
Two parties, a private chain of signed states, no on-chain transaction for the ordinary case. The
resemblance is real and it stops early.
A payment channel is bilateral off chain, but its safety is rooted on chain. The channel exists because
a funding transaction was mined. It closes by broadcasting the latest signed state. If a counterparty
broadcasts a stale state, the honest party must notice within a timeout and publish a penalty transaction,
which is why watchtowers exist. Every dispute reduces to one question: which state does the global ledger
accept?
DSM has no ledger to reduce to.
There is no funding transaction, because there is no chain to fund on. There is no channel close,
because the bilateral chain is not a temporary detour from a canonical record; it is the canonical record
for that relationship. And there is no stale-state attack, because a stale state is not a thing that can
be broadcast anywhere. The only party who accepts a step on A ↔ B is the counterparty, and the
counterparty holds the frontier. A stale parent presented to the party who already advanced past it is
simply not adjacent.


<!-- Source PDF page 23 -->

| Property | Lightning channel | DSM bilateral chain |
|---|---|---|
| Opened by | on-chain funding transaction | mutual pre-add from committed state |
| Safety rooted in | the global ledger | the consumed resource itself |
| Stale state | broadcastable, penalised on chain | not adjacent, never accepted |
| Dispute window | timeout, must be watched | none |
| Watchtower | needed if offline | no role |
| Hostile counterparty | can force a close | can only refuse to advance |
| Court of last resort | the chain | none on the common path |

The last two rows are the honest trade.
In Lightning a hostile counterparty can hurt you, but the chain will eventually settle what you are
owed, provided the honest party or its watchtower acts within the relevant protocol window. In DSM a
hostile counterparty cannot take anything from you and cannot forge a state you did not sign, but they
can decline to continue, and no third party will continue on their behalf. DSM classifies that as a liveness
failure and keeps it out of the safety theorem entirely.

#### Bitcoin Comparison

Lightning moves the common case off chain and keeps the chain as the arbiter for the uncommon
case.
DSM removes the arbiter. Conflicting successors of one consumed resource are excluded by resource
linearity at the one acceptor who holds the frontier, not selected among by whichever history a
network eventually agrees on.
#### Architectural consequence
No timeouts, no penalty transactions, no watchtowers, and no requirement that the counterparty be
live within a deadline. Safety does not depend on anyone broadcasting anything in time.
#### Tradeoff / boundary
Lightning buys something DSM does not offer: a stranger who has never held your frontier can still
be made whole by the chain. In DSM, the party who holds your frontier is the party who can accept
your next step. That is the design, not a gap, and the position check of Section 9 is how the frontier
reaches a counterparty who was not present for your last step.


## Part II — The Construction
The primitives, built in order, ending in the uniqueness theorem that Part I relied on.


<!-- spec-section: DSM-HL-014 -->
### 14 Determinism
The word deterministic is not decorative. It is the foundation of the architecture.
#### Mathematical primer — optional for technical readers

Consider the elementary function f (x) = 2x + 3. For x = 5 the answer is f (5) = 13. Alice obtains
13, Bob obtains 13, Charlie obtains 13. The answer does not depend on which person evaluates the
function. DSM imposes exactly that property on state verification.

Let


<!-- Source PDF page 24 -->

V(s, c, w)
be the verifier.
Then for identical canonical inputs,

VA (s, c, w) = VB (s, c, w).
No verifier gets to interpret the bytes according to preference.
No storage node gets to declare an invalid object valid.
No ordering service gets to decide which mathematical rule applies.
The rule is already fixed.

#### Key Idea

Determinism allows authority to reside in the transition predicate rather than in the identity of
whoever announces the result.
A conforming verifier should be able to reproduce the decision from the canonical inputs alone.


<!-- spec-section: DSM-HL-014-1 -->
#### 14.1 Determinism Is Broader Than Arithmetic
DSM requires deterministic:

- serialization;

- hashing;

- relationship identifiers;

- candidate digests;

- guard evaluation;

- resource descriptors;

- resource-consumption keys;

- SMT updates;

- policy evaluation;

- successor construction;

- root recomputation.

Thus determinism is distributed throughout the architecture.

#### Bitcoin Comparison

Bitcoin is deterministic at the level of consensus validation as well. Conforming nodes should agree
whether the same block or transaction is valid.
The architectural difference is that Bitcoin still uses a shared proof-of-work chain to establish the
accepted global transaction history from which the current UTXO state follows.
DSM removes global transaction ordering from the validity model.
Given a committed parent and a proposed transition, DSM attempts to make the answer derive


<!-- Source PDF page 25 -->

entirely from canonical state, precommitments, guards, consumption state, policy, and proofs.
#### Architectural consequence
DSM does not require another system to decide which state-transition rule wins. The same canonical
state produces the same validity answer locally.


<!-- spec-section: DSM-HL-015 -->
### 15 Canonical Encoding
Deterministic logic is useless if machines encode the same object differently.
Suppose two programs represent the same balances as:

Alice=10,Bob=20
and

Bob=20,Alice=10.
A human may say they mean the same thing.
Cryptographically, they are different byte strings.
Normally,

H(Alice=10,Bob=20) ≠ H(Bob=20,Alice=10).
DSM therefore requires canonical encoding.
For logical object x,

enc(x)
means its unique protocol-defined byte representation.
Then

dx = H(enc(x)).
Every correct implementation must generate exactly the same bytes.

<!-- spec-section: DSM-HL-015-1 -->
#### 15.1 Canonical Equality
DSM attempts to convert logical equality into byte equality.
If

x=y
as protocol objects, then a canonical encoder must satisfy

enc(x) = enc(y).
If two implementations produce different encodings for the same logical state, they have not implemented the same protocol object.


<!-- Source PDF page 26 -->

<!-- spec-section: DSM-HL-015-2 -->
#### 15.2 Why This Matters Everywhere
Canonical encoding affects:

- signatures;

- hashes;

- state roots;

- relationship heads;

- candidate commitments;

- guards;

- SMT leaves;

- resource keys;

- policy;

- proofs.

A serialization disagreement becomes a state disagreement.

#### Bitcoin Comparison

Bitcoin also uses consensus-critical canonical structures and exact byte interpretation.
The difference is how widely DSM relies on committed canonical state.
In DSM, not only transactions but also current relationship heads, precommitted successor spaces,
guards, resource descriptors, consumed-state sets, and policies participate in the deterministic
commitment structure.
#### Architectural consequence
A verifier does not need to ask a database operator what an object was supposed to mean. It
reproduces the canonical object byte-for-byte.


<!-- spec-section: DSM-HL-016 -->
### 16 Domain Separation
A cryptographic hash should also know what kind of object it is hashing.
For example,

H(DSM/consume resource/v1 ∥ x)
should not be confused with

H(DSM/smt-key/v1 ∥ x).
The prefixes are called domain separators.
They make semantically different hash operations live in cryptographically different namespaces.
Thus the same raw field cannot accidentally be interpreted as two different protocol object types.


<!-- Source PDF page 27 -->

<!-- spec-section: DSM-HL-017 -->
### 17 Cryptographic Hashes
A hash function maps arbitrary input to a fixed-size digest.

H(x) = h.
For a 256-bit digest,

h ∈ {0, 1}256 .
A useful intuitive analogy is a cryptographic fingerprint.
Changing the input changes the fingerprint.
If

x ≠ y,
then, under the collision-resistance assumption,

H(x) ≠ H(y)
except with negligible probability.
Hashes allow DSM to commit to large state objects using compact fixed-size identifiers.


<!-- spec-section: DSM-HL-018 -->
### 18 Forward-Only Hash Chaining
Suppose states evolve as

S0 , S1 , S2 , S3 .
Define

hn = H(enc(Sn )).
A successor binds its predecessor:

Sn+1 ⊃ hn .
Thus:

S0 → S1 → S2 → S3 .
If somebody changes S1 , then

h1 → h′1 .
But S2 was committed to the original h1 .
The chain no longer verifies.


<!-- Source PDF page 28 -->

<!-- spec-section: DSM-HL-019 -->
### 19 Bilateral Relationships
A DSM bilateral relationship is an independently evolving state chain between two identified participants
or devices.
Let the devices be

A, B, C, D.
The relationship between A and B is

rAB .
The relationship between A and C is

rAC .
These are not the same state resource:

rAB ≠ rAC .
Each relationship has its own forward-only chain.
For A ↔ B:

hAB,0 → hAB,1 → hAB,2 → hAB,3 .
For A ↔ C:

hAC,0 → hAC,1 .
For A ↔ D:

hAD,0 → hAD,1 → hAD,2 .


A↔B       0         1          2            3       current head hAB,3


A↔C       0         1      current head hAC,1


A↔D       0         1          2        current head hAD,2


genesis

<!-- figure-note: Figure 3; nearby loose-layout text was extracted from the source graphic; use the PDF for spatial relationships -->
Figure 3: Independent Bilateral Chains

The important point is that these are distinct chains.
An update to one does not imply an update to the others.


<!-- Source PDF page 29 -->

<!-- spec-section: DSM-HL-020 -->
### 20 Relationship State as a Vector
Alice’s current relationship state can be written as a vector:

RA = (hAB,3 , hAC,1 , hAD,2 ).
Suppose Alice and Bob advance.
Then

′
RA = (hAB,4 , hAC,1 , hAD,2 ).
Only one coordinate changed.
This is mathematically similar to changing one component of a vector while leaving the others fixed.


<!-- spec-section: DSM-HL-021 -->
### 21 Relationship Projections
Let the total state space be

S.
For relationship r, define projection

πr : S → Sr .
The projection extracts the state belonging to r.
If

s = (x, y, z),
then

π1 (s) = x,       π2 (s) = y,        π3 (s) = z.
Suppose transition fAB touches only A ↔ B.
Then:

πAB (s′ ) = fAB (πAB (s)).
For an unrelated relationship:

πAC (s′ ) = πAC (s).
This means that any valid DSM state transition involving a relationship must agree exactly with the
deterministic transition defined for that relationship, while leaving unrelated relationship projections
unchanged.


<!-- Source PDF page 30 -->

s                               fAB                           s′
(hAB,3 , hAC,1 , hAD,2 )                                      (hAB,4 , hAC,1 , hAD,2 )

πAB                                                                  πAB


πAB (s) = hAB,3
fAB
πAB (s′ ) = hAB,4

Only the A ↔ B coordinate changes; the square commutes.

<!-- figure-note: Figure 4; nearby loose-layout text was extracted from the source graphic; use the PDF for spatial relationships -->
Figure 4: Projection-Preserving Update


<!-- spec-section: DSM-HL-022 -->
### 22 Why Bilateral State Matters
Bilateral relationships allow local state to advance independently.
DSM does not need a global statement such as

hAB,4 < hCD,7
unless some explicit state rule actually creates a dependency between those operations.
The validity of A ↔ B is determined from the state relevant to A ↔ B, together with any named
shared resources or policy.

#### Bitcoin Comparison

Bitcoin does not maintain a separate canonical state chain for every pair of participants.
Bitcoin transactions consume globally recognizable UTXOs and eventually participate in the same
proof-of-work blockchain history.
DSM uses explicit bilateral chains and authenticated projections.
#### Architectural consequence
A relationship can progress without requiring unrelated relationships to be placed before or after it
in one global history.
DSM replaces global ordering entirely as a validity mechanism rather than merely trying to reduce
how often it is used.
If an application needs an ordering relation, that relation can itself be represented deterministically
in committed state.


<!-- spec-section: DSM-HL-023 -->
### 23 Why a Device Needs a Compact Commitment
A device may have a large number of relationships:

r1 , r2 , . . . , rn .
One could store a giant ordered list:

(h1 , h2 , . . . , hn ).
But proving one relationship would be inefficient if the verifier had to receive the entire list.
DSM therefore uses authenticated tree commitments.
The important structure is the Sparse Merkle Tree.


<!-- Source PDF page 31 -->

<!-- spec-section: DSM-HL-024 -->
### 24 Ordinary Merkle Trees
Suppose there are four leaves:

L1 , L2 , L3 , L4 .
Hash each leaf:

a = H(L1 ),     b = H(L2 ),        c = H(L3 ),    d = H(L4 ).
Then:

u = H(a ∥ b),


v = H(c ∥ d),
and finally:

ρ = H(u ∥ v).


ρ = H(u∥v)                recomputed when L2 → L′2


u = H(a∥b)                            v = H(c∥d)


a = H(L1 )     b = H(L2 )           c = H(L3 )        d = H(L4 )

<!-- figure-note: Figure 5; nearby loose-layout text was extracted from the source graphic; use the PDF for spatial relationships -->
Figure 5: Ordinary Merkle Tree

Change one leaf:

L2 → L′2 .
Then:

H(L2 ) → H(L′2 ),
which changes u, which changes ρ.
Therefore one small change creates a new root commitment.


<!-- spec-section: DSM-HL-025 -->
### 25 Sparse Merkle Trees
A Sparse Merkle Tree uses a fixed logical key space.
For a 256-bit key:

k ∈ {0, 1}256 .
The logical tree has

possible leaf positions.


<!-- Source PDF page 32 -->

That does not mean the implementation stores 2256 leaves.
Almost all positions are empty.
Empty subtrees have deterministic default hashes.
Only populated paths and necessary nodes need to be represented.
Thus a sparse tree can logically address an enormous namespace while physically storing a tiny subset
of it.

ρA


N0                                                     N1


default                   N01                        N10                            N11


kAB                        kAC                                        kAD
default                    default        default
hAB                        hAC                                        hAD


dashed nodes are empty subtrees with deterministic default hashes: addressed logically, never stored


<!-- figure-note: Figure 6; nearby loose-layout text was extracted from the source graphic; use the PDF for spatial relationships -->
Figure 6: Sparse Merkle Tree Concept

This miniature diagram shows only a few levels.
A real 256-bit SMT has a logical depth of 256.


<!-- spec-section: DSM-HL-026 -->
### 26 Relationship Keys
DSM can derive a bilateral relationship key deterministically.
For devices A and B:

kA↔B = H(DSM/smt-key/v1 ∥ min(DevIDA , DevIDB ) ∥ max(DevIDA , DevIDB )).
Because the device IDs are canonically sorted:

kA↔B = kB↔A .
The relationship leaf stores its current head:

SMTA [kAB ] = hAB,n .
Likewise:

SMTA [kAC ] = hAC,m ,


SMTA [kAD ] = hAD,q .


<!-- Source PDF page 33 -->

A↔B                            A↔C                        A↔D
chains
hAB,0 → hAB,1 → hAB,2              hAC,0 → hAC,1          hAD,0 → hAD,1 → hAD,2

head                             head                        head


SMT leaves       kAB ↦ hAB,2                     kAC ↦ hAC,1               kAD ↦ hAD,2


Device authenticated state commitment
SMT root
ρA

<!-- figure-note: Figure 7; nearby loose-layout text was extracted from the source graphic; use the PDF for spatial relationships -->
Figure 7: Bilateral Chains Into One Device SMT

The relationship chains remain independent.
The SMT commits their current heads.


<!-- spec-section: DSM-HL-027 -->
### 27 Updating One SMT Leaf
Suppose Alice and Bob advance:

hAB,n → hAB,n+1 .
Before:

SMTA [kAB ] = hAB,n .
After:

SMT′A [kAB ] = hAB,n+1 .
All unrelated leaves remain unchanged.
The root changes:

ρA → ρ′A .

root advance
ρA                                         ρ′A


all other leaves
old path hash              unchanged
new path hash


kAB                                           kAB
hAB,n              relationship advance      hAB,n+1

<!-- figure-note: Figure 8; nearby loose-layout text was extracted from the source graphic; use the PDF for spatial relationships -->
Figure 8: One Leaf Changes the Root


<!-- Source PDF page 34 -->

<!-- spec-section: DSM-HL-028 -->
### 28 Merkle Proofs
A Merkle proof proves that one leaf belongs to one committed root without sending every leaf.
Suppose the verifier wants to prove:

kAB ↦ hAB,n .
The proof supplies the sibling hashes needed to recompute the path.
At each level, the verifier performs:

pi+1 = H(pi ∥ siblingi )
or

pi+1 = H(siblingi ∥ pi )
depending on whether the path goes left or right.
After the final level, the verifier obtains:

p256 .
The proof is valid if

p256 = ρA .

p256        =?
3                               committed ρA

···


2        p2 = H(· ∥ ·)                  sibling s2


1        p1 = H(· ∥ ·)                  sibling s1


kAB ↦ hAB                     sibling s0

prover supplies the leaf and the siblings; verifier recomputes upward and compares

<!-- figure-note: Figure 9; nearby loose-layout text was extracted from the source graphic; use the PDF for spatial relationships -->
Figure 9: Merkle Inclusion Proof

In a 256-bit SMT, the logical proof path has depth 256, although default subtrees may be represented
compactly by implementation-specific proof compression.

#### Bitcoin Comparison

Bitcoin also uses Merkle trees.
A Bitcoin block’s transaction Merkle root commits the transactions contained in that block.
DSM uses authenticated tree structures as part of current state itself.
For example:


<!-- Source PDF page 35 -->

kAB ↦ hAB
represents the presently committed bilateral relationship head.
#### Architectural consequence
The tree is not merely a proof that an event occurred in an historical block. It participates directly
in authenticated state evolution.
#### Tradeoff / boundary
The important distinction is not “Bitcoin has no Merkle trees.” Both use Merkle commitments. The
difference is what the tree commits and how the root participates in the state model.


<!-- spec-section: DSM-HL-029 -->
### 29 The DSM State Object
A complete abstract DSM state can be represented as:

s = (R, u, P, Γ, Σ, Π, Ω, ρ).
Each component has a distinct function.

#### R: Relationship Map
R : R → H.
For relationship identifier r,

R(r) = hr .
It records the current authenticated relationship head.

#### u: Progression Object
The object u represents monotonic progression.
Depending on the protocol mode, it may be:

- a sequence digest;

- a local progression coordinate;

- a receipt frontier;

- a committed offline anchor counter.

#### P : Candidate Precommitment Space
P = {c1 , c2 , . . . , cn }.
It commits the currently permitted future candidates.

#### Γ: Guard Family
Γ = {(bi , gi , Ki )}ni=1 .
It associates candidate branches with deterministic fulfillment rules and resource sets.


<!-- Source PDF page 36 -->

#### Σ: Consumed Resource Set
Σ
contains resource-consumption keys already consumed in the realized lineage.

#### Π: Policy
Π
contains deterministic policy and authority data.

#### Ω: Mode Evidence
Ω
contains mode-specific evidence. In an ordinary online state it may be empty.

#### ρ: State Commitment
ρ
is the canonical state root.


<!-- spec-section: DSM-HL-030 -->
### 30 The Layered Root
There is a subtle dependency problem.
Candidates need to bind the parent state.
But if the parent root includes candidate commitments, then naively defining the candidates in terms
of the full root could produce a cycle.
DSM avoids this using a core root.
First:

ρcore = SMT(R, u, Σ, Π, Ω).
Candidates and guards may safely bind:

ρcore .
Then the full root is:

ρ = H(ρcore ∥ digest(P ) ∥ digest(Γ)).


<!-- Source PDF page 37 -->

R            u             Σ          Π           Ω

core layer
(no candidates)


ρcore = SMT(R, u, Σ, Π, Ω)

bind                                bind


future layer
(binds ρcore )
digest(P )                                                 digest(Γ)


ρ = H(ρcore ∥ digest(P )∥ digest(Γ))

<!-- figure-note: Figure 10; nearby loose-layout text was extracted from the source graphic; use the PDF for spatial relationships -->
Figure 10: Layered Canonical Commitment

The dependency graph is acyclic.

(R, u, Σ, Π, Ω) → ρcore → (P, Γ) → ρ.


<!-- spec-section: DSM-HL-031 -->
### 31 Canonical State Chaining
The complete state itself advances forward.

s0 → s1 → s2 → s3 .
At the root level:

ρ0 → ρ1 → ρ2 → ρ3 .
The arrow means derivability.
It does not mean:

“A global network placed these states in chronological order.”

It means:

“The successor is a valid deterministic transformation of the committed parent.”


s0        derives       s1           derives       s2     derives      s3
ρ0                      ρ1                         ρ2                  ρ3

commits                commits                    commits               commits
P 0 , Γ0               P1 , Γ1                    P2 , Γ2               P3 , Γ3

<!-- figure-note: Figure 11; nearby loose-layout text was extracted from the source graphic; use the PDF for spatial relationships -->
Figure 11: Canonical DSM state derivation. Each successor is a valid deterministic derivation of its committed
parent.

Every state commits both current facts and its permitted transition structure.


<!-- Source PDF page 38 -->

<!-- spec-section: DSM-HL-032 -->
### 32 Bitcoin Chain Versus DSM State Chain
#### Bitcoin Comparison

Bitcoin chains blocks:

B0 → B1 → B2 → B3 .
Each block contributes to one shared proof-of-work history.
DSM chains authenticated state derivations:

s0 → s1 → s2 → s3 .
The DSM state already commits current relationship heads, consumed resources, policy, progression,
mode evidence, precommitments, and guards.
#### Architectural consequence
DSM does not need a global event history to define whether an unrelated local transition is valid.
The authenticated state and derivation rule are themselves sufficient for the transition-validity test.


<!-- spec-section: DSM-HL-033 -->
### 33 Logical Generations
DSM uses logical generations.
A generation is not a wall-clock timestamp.
Suppose:

V0 → V1 → V2 .
Then V2 is later because it is derivable from V1 , not because a universal clock says it happened later.
This distinction is important.
DSM state progression is ordered by dependency.
It is not ordered by universal time.


<!-- spec-section: DSM-HL-034 -->
### 34 Precommitment
Precommitment means the parent state commits its allowed candidate future space before one of those
futures becomes realized.
Given parent s:

P (s) = {c1 , c2 , . . . , cn }.
For example:

P (s) = {crelease , crefund , crecovery }.
The three candidates are not three completed transitions.
They are three cryptographically committed possibilities.


<!-- spec-section: DSM-HL-035 -->
### 35 Candidate Structure
A candidate may be written as:


<!-- Source PDF page 39 -->

ci = (si , bi , gi , Ki , di ).
where:

- si is the candidate successor;

- bi is the branch identifier;

- gi is the guard descriptor;

- Ki is the required resource-key set;

- di is the candidate digest.

The digest is:

di = H(enc(si )).
The candidate must be bound to the parent.
An arbitrary future state that was never committed cannot simply be inserted later.


Candidate c1
release
ted
mit
com
pre


Parent state      precommitted             Candidate c2
P (sn )
sn                                       refund

pre
one realized        com
mit
parent                    ted

Candidate c3
recovery


three committed possibilities, none realized

<!-- figure-note: Figure 12; nearby loose-layout text was extracted from the source graphic; use the PDF for spatial relationships -->
Figure 12: Precommitted Future Space


<!-- spec-section: DSM-HL-036 -->
### 36 Candidate Forks Are Allowed
DSM permits:

|P (s)| > 1.
Therefore:

c1 , c2 , c3
may all coexist as candidate branches.


<!-- Source PDF page 40 -->

This is intentional.
Candidate branching is not itself a double execution.
The safety theorem applies to realized conflicting branches.

Many candidates may exist.

One linear resource may be consumed once in a valid realized lineage.


<!-- spec-section: DSM-HL-037 -->
### 37 Precommitment Chaining
Precommitment is not temporary metadata.
It is part of canonical state evolution.
State sn commits:

Pn ,          Γn .
Suppose candidate ci ∈ Pn realizes and creates:

sn+1 .
That new state commits a new future space:

Pn+1 ,              Γn+1 .
Thus:

(sn , Pn , Γn ) → (sn+1 , Pn+1 , Γn+1 ) → (sn+2 , Pn+2 , Γn+2 ).

realize ci ∈ Pn                         realize cj ∈ Pn+1
sn                                sn+1                                 sn+2

commits                         commits                               commits

Pn , Γn                      Pn+1 , Γn+1                              Pn+2 , Γn+2

<!-- figure-note: Figure 13; nearby loose-layout text was extracted from the source graphic; use the PDF for spatial relationships -->
Figure 13: Chained Precommitment

Each realized successor becomes the parent of the next precommitted future space.

#### Bitcoin Comparison

Bitcoin outputs can encode spending conditions, and advanced Bitcoin constructions can commit
alternative paths.
DSM makes the candidate successor set itself a first-class component of the general state model.

P (s) = {c1 , . . . , cn }.
#### Architectural consequence
The verifier does not ask:

“What arbitrary new state is somebody trying to execute?”

It asks:


<!-- Source PDF page 41 -->

“Is this successor one of the futures already committed by the parent?”

That sharply constrains the valid state-transition space.


<!-- spec-section: DSM-HL-038 -->
### 38 Guards
A precommitted candidate does not automatically realize.
It must satisfy a deterministic guard.
For branch bi :

gi (s, w) ∈ {True, False}.
Here w is witness material.
A witness may be:

- a signature;

- a cryptographic preimage;

- a completion certificate;

- a receipt;

- a recovery proof;

- a mode-specific evidence bundle.

A guard should bind:

- the parent;

- the branch identifier;

- the required resource keys;

- the accepted witness type;

- the deterministic witness predicate;

- the conflict class.


<!-- spec-section: DSM-HL-039 -->
### 39 Guard Families
For state s:

Γs = {(bi , gi , Ki )}ni=1 .
Each branch has a guard and a resource set.
A well-formed guard family requires deterministic verification and correct binding to the state and
branch.


<!-- Source PDF page 42 -->

witness w


ci ∈ P (s)                                              True
Parent s                 Candidate ci              gi (s, w)?             Realized si


False


Reject

<!-- figure-note: Figure 14; nearby loose-layout text was extracted from the source graphic; use the PDF for spatial relationships -->
Figure 14: Guarded Candidate Realization


<!-- spec-section: DSM-HL-040 -->
### 40 Guards Alone Are Not the Exclusion Mechanism
Suppose two conflicting guards are both satisfiable:

g1 (s, w1 ) = True,


g2 (s, w2 ) = True.
DSM must still remain safe.
Therefore the safety theorem cannot rely only on assuming that every pair of conflicting guards is
logically exclusive.
The load-bearing mechanism is shared resource consumption.

Conflicting branches must contend for the same authoritative linear-resource key.

#### Bitcoin Comparison

Bitcoin Script also provides deterministic spending conditions.
DSM’s guard is integrated with a precommitted candidate successor and an explicit conflict-resource
set.
Thus:

candidate → guard → resource consumption → successor
forms one deterministic transition structure.
#### Architectural consequence
Even overlapping successful guards do not imply that two conflicting successors can both become
realized state, because shared linear-resource consumption remains independently enforced.


<!-- spec-section: DSM-HL-041 -->
### 41 Linear Resources
A linear resource is an object whose committed generation can produce at most one realized successor
inside its conflict class.
Examples include:

- a bilateral relationship parent;


<!-- Source PDF page 43 -->

- a spendable balance object;

- a vault generation;

- a recovery generation;

- an emission-source generation;

- an offline anchor step;

- another canonically defined single-consumption state object.


<!-- spec-section: DSM-HL-042 -->
### 42 Resource Descriptors
Let x be the canonical description of a resource.
For a relationship:

xrel = (relationship, kA↔B , hn ).
The descriptor is derived from committed state.
A branch is not free to invent a different descriptor merely to evade conflict.


<!-- spec-section: DSM-HL-043 -->
### 43 Resource-Consumption Keys
DSM derives the authoritative consumption key as:

κres (s, x) = H(DSM/consume resource/v1 ∥ ρcore,s ∥ x).
Let:

K = κres (s, x).
If two branches consume the same resource x, then both derive the same:

K.
That equality is the point.

Branch b1
release
co
nsu
me
s


derive
Parent state s                       Same resource x             K = κres (s, x)
es
m


one key,
nsu


not two
co


Branch b2
refund

<!-- figure-note: Figure 15; nearby loose-layout text was extracted from the source graphic; use the PDF for spatial relationships -->
Figure 15: Two Branches, One Resource Key

The branches are different.


<!-- Source PDF page 44 -->

The consumed resource is the same.
Therefore the authoritative key is the same.


<!-- spec-section: DSM-HL-044 -->
### 44 Why Branch-Specific Exclusion Keys Would Be Wrong
Suppose exclusion were defined as:

K1 = H(s ∥ x ∥ b1 )
and

K2 = H(s ∥ x ∥ b2 ).
Then:

K1 ≠ K2 .
Both could appear unconsumed.
That would fail to represent the fact that both branches consume one parent resource.
DSM therefore derives the exclusion key from the resource, not from the choice of conflicting branch.
Branch-local identifiers may still exist for audit or indexing, but they are not the authoritative
exclusion mechanism.


<!-- spec-section: DSM-HL-045 -->
### 45 Conflict Classes
Define the conflict class for key K:

CK (s) = {bi : K ∈ Ki }.
The branches inside CK (s) are mutually conflicting with respect to the same linear resource.
This allows conflict to be explicitly scoped.
Not every branch in DSM conflicts with every other branch.
Only branches sharing relevant linear state need exclusion.


<!-- spec-section: DSM-HL-046 -->
### 46 The Consumed Set
DSM records consumed resource keys in:

Σs .
Initially:

K ∉ Σs .
After a valid transition consuming K:

Σs′ = Σs ∪ {K}.
Therefore:

K ∈ Σs′ .
Consumption is monotonic:


<!-- Source PDF page 45 -->

Σ s ⊆ Σ s′ .

Σn ⊆ Σn+1

sn                                                 sn+1
Σn = {K1 , K2 }             consume K3           Σn+1 = {K1 , K2 , K3 }


no path removes K3

<!-- figure-note: Figure 16; nearby loose-layout text was extracted from the source graphic; use the PDF for spatial relationships -->
Figure 16: Monotonic Consumption


<!-- spec-section: DSM-HL-047 -->
### 47 The Consumed Set Can Also Be an SMT
The consumed set may itself be represented as an authenticated sparse map.
For example:
(
0, not consumed,
Σ[K] =
1, consumed.
A proof can demonstrate:

K ∉ Σs
before execution and:

K ∈ Σs′
after execution.
This ties linearity directly into authenticated state.


<!-- spec-section: DSM-HL-048 -->
### 48 Bitcoin UTXOs Versus DSM Linear Resources
#### Bitcoin Comparison

Bitcoin’s UTXO model already contains an important linear concept.
A UTXO can be consumed once.
Once spent in the accepted chain state:

U ∉ UTXOSet.
DSM generalizes this idea from monetary outputs to arbitrary committed state resources.
A DSM linear resource can be:

- a monetary balance generation;

- a relationship parent;

- a vault generation;

- a recovery generation;


<!-- Source PDF page 46 -->

- a policy-controlled object;

- an offline anchor step.

#### Architectural consequence
DSM promotes single-consumption semantics to a general state-machine primitive.
Instead of only asserting:

“this coin output cannot be spent twice”,
DSM can assert:

“this committed state resource cannot produce two conflicting realized successors.”
#### Tradeoff / boundary
Bitcoin’s narrower UTXO model is deliberately simple and is well suited to its purpose as a global
monetary system.


<!-- spec-section: DSM-HL-049 -->
### 49 The Complete Realization Predicate
A potential transition:

fi : s → si
becomes realized only if:

Realize(s, si , w) = CandidateOK(s, si )
∧ GuardOK(s, si , w)
∧ StructuralOK(s, si )
∧ LinearityOK(s, si )
∧ PolicyOK(s, si )
∧ ModeOK(s, si ).


<!-- spec-section: DSM-HL-050 -->
### 50 Potential and Realized Morphisms
A mathematically useful interpretation is:

fi : s → si
is a potential morphism.
It represents a possible structure-preserving transformation.
When all required predicates become true, the potential morphism becomes a realized morphism.
Therefore DSM can be understood as:


a deterministic detector of which precommitted state morphisms are currently realizable.


<!-- Source PDF page 47 -->

<!-- spec-section: DSM-HL-051 -->
### 51 Realized Histories
A realized history is:

s0 → s1 → s2 → · · · → sn
such that every edge is a valid DSM realization.
The consumed set threads forward:

Σ0 ⊆ Σ1 ⊆ Σ2 ⊆ · · · ⊆ Σn .
This is essential.
A branch is not repeatedly evaluated against an old snapshot while ignoring the state created by
earlier realized transitions.


<!-- spec-section: DSM-HL-052 -->
### 52 The Core Uniqueness Theorem
Theorem 1 (Conflict-Local Realized Uniqueness). Let b1 and b2 be two conflicting branches over the
same committed linear resource x.
Let:

K = κres (s, x).
Then b1 and b2 cannot both consume K as separate realized transitions in one valid DSM history.

Proof. Assume the opposite.
Initially:

K ∉ Σs .
Suppose b1 realizes first.
Validity requires:

Σ1 = Σs ∪ {K}.
Therefore:

K ∈ Σ1 .
Now suppose b2 also realizes as another consumption of the same resource.
Linearity requires:

K ∉ Σ1 .
But we already established:

K ∈ Σ1 .
Thus both statements would have to be true:

K ∈ Σ1
and

K ∉ Σ1 .


<!-- Source PDF page 48 -->

Contradiction.
Therefore both conflicting branches cannot be co-realized as separate consumptions of the same
resource in one valid history.


#### Two forms of the theorem
The formal paper states uniqueness in two forms, because guard families come in two kinds.
Selector families. Some conflict classes carry a deterministic selector: a vault decision function, a
recovery decision object. At most one branch can ever be fulfilled, so at most one candidate passes the
predicate even against the untouched parent. For these families the theorem holds statically, at the level
of the predicate.
Shared-key families. Other conflict classes let several guards be true at once. Release, refund, and
recovery witnesses may all be available. Every branch passes the predicate against Σs . For these families
the theorem holds in its realized-history form: the first acceptance updates Σ, and every later conflicting
candidate fails linearity against the updated set.
The realized-history form is the operational safety statement. It holds for every well-formed family,
and it is the form that is machine checked as an invariant (Section 81).

consume K       s1
Branch b1                  K ∈ Σ1
t
firs
l i zes
rea

s                                                                      Σ1 threads forward
into the second attempt
K ∉ Σs


second consumption needs K ∉ Σ1
attempt b2
Branch b2                               but K ∈ Σ1
⊥

<!-- figure-note: Figure 17; nearby loose-layout text was extracted from the source graphic; use the PDF for spatial relationships -->
Figure 17: The Contradiction


<!-- spec-section: DSM-HL-053 -->
### 53 Tripwire
DSM refers to the same-parent conflict exclusion property as Tripwire.
Tripwire does not mean malicious bytes cannot exist.
An attacker can construct:

c1
and:

c2 .
The attacker can transmit both.
The theorem is not:

“conflicting bytes cannot be created.”
The theorem is:


<!-- Source PDF page 49 -->

conflicting same-resource branches cannot both be derived as realized state in one valid lineage.
This distinction is important.
Anyone may write:

1=2
on a sheet of paper.
That does not mean the equation is derivable from ordinary arithmetic.
Likewise, anyone may manufacture conflicting serialized objects.
That does not make them jointly derivable DSM state.

one valid
Conflicting bytes c1                                  realized branch

DSM deterministic
verification

Conflicting bytes c2                                 conflicting branch
non-derivable
anyone can write both
only one can be derived

<!-- figure-note: Figure 18; nearby loose-layout text was extracted from the source graphic; use the PDF for spatial relationships -->
Figure 18: Conflicting byte strings may exist and may be transmitted, but deterministic DSM verification does
not permit conflicting same-resource branches to coexist as realized state in one valid lineage.


<!-- spec-section: DSM-HL-054 -->
### 54 Safety and Liveness
DSM safety does not imply guaranteed progress.
A valid candidate may fail to realize because:

- a counterparty refuses;
- required data is unavailable;
- a witness is never produced;
- storage is temporarily unreachable;
- policy conditions are not met;
- an offline proof cannot be produced.

Therefore:

safety ≠ liveness.
Safety answers:

Can two conflicting realizations both become valid?

Liveness answers:

Will some valid transition eventually occur?

These are different properties.


<!-- Source PDF page 50 -->

<!-- spec-section: DSM-HL-055 -->
### 55 Concurrency Without Global Ordering
Suppose transition f touches resource set X.
Suppose transition g touches resource set Y .
If:

X ∩ Y = ∅
and neither transition depends on state modified by the other, then they may commute:

f (g(s)) = g(f (s)).
Their relative order is unnecessary.

X ∩ Y = ∅
AB0             AB1             AB2          independent resources


no relation ABi ≶ CDj is ever defined


f (g(s)) = g(f (s))
CD0              CD1             CD2
order is irrelevant

<!-- figure-note: Figure 19; nearby loose-layout text was extracted from the source graphic; use the PDF for spatial relationships -->
Figure 19: Independent Concurrent State

There is no need to define:

AB1 < CD1
or:

CD1 < AB1 .
Both can be valid independently.


<!-- spec-section: DSM-HL-056 -->
### 56 Token Conservation
Suppose Alice has balance:

BA
and Bob has:

BB .
Alice transfers amount:

α.
Then:

′
BA = BA − α,

′
BB = BB + α.


<!-- Source PDF page 51 -->

Therefore:

′    ′
BA + BB = (BA − α) + (BB + α).
The transfer terms cancel:

′    ′
BA + BB = BA + BB .
So ordinary transfer is zero-sum.

Alice         transfer α = 20       Bob
BA = 100                            BB = 50


−α                                      +α


Alice                               Bob
′                                  ′
BA = 80                            BB = 70
100 + 50 = 80 + 70 = 150     the transfer terms cancel

<!-- figure-note: Figure 20; nearby loose-layout text was extracted from the source graphic; use the PDF for spatial relationships -->
Figure 20: Conservation


<!-- spec-section: DSM-HL-057 -->
### 57 Why Conservation Is Not Enough
Suppose Alice has 10.
Branch one:

A : 10 → 0,        B : 0 → 10.
Branch two:

A : 10 → 0,        C : 0 → 10.
Each branch individually conserves value.
But if both consumed the same source parent independently, the source would have effectively produced
20 units.
Therefore:

conservation + linearity
are both required.


## Part III — What Is Built on It
Vaults, smart commitments, multi-party workflows, asset policy, emissions, and markets, each a precommitted branch family over linear resources.


<!-- Source PDF page 52 -->

<!-- spec-section: DSM-HL-058 -->
### 58 Deterministic Limbo Vaults
A Deterministic Limbo Vault illustrates precommitted alternative outcomes.
Suppose vault generation Vn allows:

P (Vn ) = {crelease , crefund , crecovery , cabort }.
Each branch has a distinct guard.
But all terminal branches consume:

x Vn .
Therefore:

KVn = κres (s, xVn ).

four precommitted branches


Release


Refund
Vault generation                                               shared resource key          at most one
Vn                                                             KVn                     realizes
Recovery
each branch has its own guard,
but all consume xVn

Abort

<!-- figure-note: Figure 21; nearby loose-layout text was extracted from the source graphic; use the PDF for spatial relationships -->
Figure 21: Deterministic Limbo Vault

Once one terminal branch consumes:

KVn ,
another terminal branch cannot consume the same generation in that lineage.

#### Bitcoin Comparison

Bitcoin can encode alternative spending conditions.
DSM explicitly models the alternatives as precommitted successor branches over one shared linear
vault generation.
#### Architectural consequence
The exclusivity of release, refund, recovery, and abort does not depend on a global transaction-ordering decision.
They are mathematically recognized as alternative consumers of one committed state resource.


<!-- spec-section: DSM-HL-059 -->
### 59 Smart Commitments
An Ethereum reader will have been waiting for this section.
DSM has no contract virtual machine. That is a design decision, not a limitation discovered later, and
the reasoning is worth stating in full because the obvious objection is “then it cannot do what Ethereum
does.”


<!-- Source PDF page 53 -->

#### What a contract is
An Ethereum contract is code plus mutable storage, executed by every node in a globally agreed order.
Any transaction can call any function; the function may loop, recurse, call other contracts, and modify
storage arbitrarily. The global order is what makes the result well-defined, and the gas market is what
keeps execution finite.
Everything that makes Ethereum powerful comes from that general-purpose programmable execution
and dynamic composition. So does most of what makes it dangerous: reentrancy, unbounded recursion,
dynamic call-stack behaviour, gas-budget execution failure, and the difficulty of knowing in advance what
a transaction will do once it starts calling other contracts.

#### What a smart commitment is
A smart commitment is a bounded deterministic predicate over committed inputs:


C = {∆in , ∆out , invariants, external commitments, encumbrances, intent bounds, budget}.

It is not code that runs. It is a guard family (Section 38) attached to a precommitted candidate space
(Section 34) over linear resources (Section 41). The reader has already seen the whole mechanism; this
section only names it.
A smart commitment can use:

- checked integer arithmetic and comparison;

- Boolean composition;

- hashing and signature verification;

- Sparse Merkle inclusion and non-inclusion;

- membership in committed bounded sets;

- iteration with a cardinality fixed at commit time.

It cannot use recursion, dynamic dispatch, or unbounded loops, and every predicate family declares a
static evaluation budget.

#### Why the restriction costs less than it looks
The things people build on Ethereum are not, for the most part, unbounded computations. They are
conditional transfers: move this value if that condition holds. The unbounded VM is the delivery
mechanism, not the product.
DSM keeps the product and drops the mechanism. Every application below is a precommitted branch
family with guards over linear resources, verified by the counterparty who accepts the step.


<!-- Source PDF page 54 -->

| Ethereum pattern | DSM smart commitment | Where in |
|---|---|---|
| ERC-20 token | CPTA fungible policy | Section 61 |
| ERC-721 / soulbound | CPTA NFT / SBT with allowlist proofs | Section 61 |
| Multisig wallet | multi-party authority branches | Section 60 |
| Escrow, HTLC | DLV with hash-fulfillment guard | Section 58 |
| Airdrop, emission schedule | DJTE join-triggered emission from a source vault | Section 62 |
| Oracle | external commitment, co-signed reference window | Section 60 |
| AMM / DEX | DLV with committed market policy | Section 63 |
| Perpetuals, liquidation | precommitted liquidation branch, activity-based funding | Section 63 |
| Social recovery | recovery generation | Section 65 |
| Wrapped or bridged Bitcoin | dBTC: a sovereign tap, Bitcoin origin, DSM lineage, consumption-gated withdrawal | Section 64 |
| Time-lock | iteration budget on the local chain | below |

#### What is genuinely different

#### What is genuinely different
Two things do not carry across unchanged, and the honest version of this section says so.
No clocks. Ethereum has block timestamps and heights. DSM has neither, by design. Where a
contract would say “after time t,” a smart commitment says “after n accepted transitions on this chain”
using an iteration budget β that decrements only on accepted local steps. This is strictly weaker for
wall-clock deadlines and strictly stronger for determinism: no verifier ever disagrees about whether the
condition holds.
No open-ended composition. On Ethereum any contract can call any other. In DSM a commitment
can only reference what was committed when it was created: the candidate space, the guards, the external
commitments by hash. Composition across parties is done by bilateral composition and shared external
commitments (Section 60), not by a call stack.
Those are the two costs. In exchange, reentrancy, unbounded recursion, dynamic call-stack behaviour,
and gas-budget execution failure are structurally excluded, and every outcome of a commitment is
bounded by the committed candidate space and the static evaluation budget, so it can be enumerated
before acceptance.

#### Ethereum Comparison

Bitcoin Script is deliberately not Turing complete. Ethereum’s founding argument was that this
was too restrictive to build applications on.
DSM takes Bitcoin’s side of that argument and then shows the applications can be built anyway,
because a precommitted candidate space with guards is expressive enough for conditional transfer,
and conditional transfer is what the applications are.
#### Architectural consequence
Bounded predicates over committed inputs mean a verifier can enumerate every possible outcome of
a commitment before accepting it. There is no reentrancy, no gas griefing, and no “what does this
contract actually do” question.
#### Tradeoff / boundary
“Everything Ethereum does” means every application pattern in the table. It does not mean arbitrary
computation. A workload that genuinely needs unbounded on-chain computation, rather than
conditional transfer, is not a DSM workload.


<!-- spec-section: DSM-HL-060 -->
### 60 Multi-Party Workflows Through External Commitments
DSM is bilateral at the protocol layer. A reader will reasonably ask how three or more parties agree on
anything if every chain has exactly two ends.


<!-- Source PDF page 55 -->

The answer is that they do not agree on a chain. They agree on a hash.

#### External commitments
An external commitment is a digest of data that lives outside the DSM core:

Y = H(DSM/external/v1 ∥ X).
DSM never executes X. It verifies only equality, inclusion, signature, or proof predicates bound to Y .
A guard can say “this branch is fulfilled if a witness proves H(·) = Y ,” and nothing more is asked of X.
That one rule is enough to bind any number of bilateral chains to the same external fact, because two
chains that both name Y refer to that fact without sharing a parent.

#### Three parties, two chains, one commitment
Carol is to be paid by both Alice and Bob if she delivers service Y = H(DSM/external/v1 ∥ delivery proof).
There is no three-party ledger and no contract account. There are two relationships and one hash.
1. Alice funds a vault VA on A ↔ C whose release guard requires Y and Alice’s acknowledgement.
2. Bob funds a vault VB on B ↔ C whose release guard requires the same Y and Bob’s acknowledgement.
3. Carol presents the delivery proof in each relationship. Each release realizes independently as an
ordinary bilateral step.

A↔C           vault VA
Alice                guard: Y ∧ sigA
rele
ase
external commitment
Y = H(· · · )                                                                 Carol
e
eas
reltwo   bilateral releases,
B↔C           vault VB               no shared parent
Bob                  guard: Y ∧ sigB

If Bob disputes and refuses to acknowledge, Alice’s vault still releases or refunds under her own
precommitted branches. Bob’s refusal is a liveness failure on B ↔ C; it cannot touch A ↔ C.

#### Authority does not multiply the parent
Multi-party guards can be thresholds or Boolean formulas over signatures:

grelease = sig(A),     gcancel = sig(B),   grecover = sig(C) ∧ sig(D).
Suppose every witness for every branch is available at once. Release, cancel, and recover are all
fulfilled. This is the shared-key situation of Section 8: all three branches consume the same derived key
for the resource they share, so the first one folded into the lineage marks it consumed and the other two
fail linearity.

authority chooses an eligible branch; it cannot multiply the consumed parent.
This is why DSM does not need a contract account to referee between authorised parties. Overlapping
authority does not multiply the resource: authority changes branch eligibility, and it does not permit
more than one consumption of the parent.


<!-- Source PDF page 56 -->

#### Bitcoin Comparison

Bitcoin multisig puts all signers on one output and settles the result on one chain. Ethereum puts
all parties into one contract’s storage.
DSM keeps every party on their own bilateral chains and binds them through a shared hash. No
party ever writes to another party’s chain.
#### Architectural consequence
There is no shared mutable object for the parties to contend over, so there is no ordering question
between them. Each bilateral step is accepted by its own counterparty against its own frontier; the
external commitment is what makes those independent steps refer to the same fact.
#### Tradeoff / boundary
Atomicity across the bilateral legs is not automatic. If Alice’s leg releases and Bob’s does not, that
is the outcome, and each vault’s precommitted refund or abort branch is the remedy. Workflows
that require all-or-none across several parties’ resources use the one-bundle settlement of Section 63.


<!-- spec-section: DSM-HL-061 -->
### 61 CPTA and Deterministic Policy
DSM can place authority and policy inside committed state.
Let Π represent a deterministic policy. Possible operations might include:

transfer,   claim,   emission,   burn,   recovery.
An authorized actor may satisfy a policy condition. That does not exempt the actor from linearity.
Even an authorized branch must obey K ∈ / Σ. Therefore:

authority determines eligibility; it does not override single-consumption state.

#### A token is an asset with a policy, not a contract with an API
The Ethereum reader will map CPTA onto ERC-20 and get it slightly wrong, so it is worth being exact
about the difference.
ERC-20 is not a boundary on what a token can be. It is a standard interface: balances, transfers,
approvals, total supply, allowances. A token contract implements that interface and may put any logic
it likes behind it. Interoperability comes from every application calling the same function names. The
token’s rules live in the token contract, and once a token is handed to another contract, a pool, a lending
market, a bridge, it is that contract’s code that decides what happens to it next.
A CPTA token is the other way round. The asset is bound to a committed policy describing which
state transitions involving that asset are valid: who may issue it, whether further issuance exists, what
conditions a transfer must meet, what authority each operation requires, which operations exist at all.
The policy is a hash-committed input to every verifier that ever touches the asset. It does not have a
function interface, and nothing implements it; it is checked.
The consequence is that the rules travel with the asset. When a CPTA token enters a limbo vault,
the vault has its own policy and the token keeps its own. A market swap of A for B is valid only if every
one of the following holds:

PDLV ∧ ΠA ∧ ΠB ∧ reserve arithmetic ∧ economic-root admission.
There is no operation that lets an application bypass a token’s policy by wrapping it, because validity
is the intersection of the operation’s rules and each asset’s rules. If ΠA says a movement is invalid,
putting A in a vault does not make it valid.


<!-- Source PDF page 57 -->

The last term deserves one sentence so it is not misread. Economic validity is decided by the predicates;
a valid transition produces an exact economic write set; that write set is admitted into the device’s
economic root, which DSM’s implementation calls Recon ; and the keyed cell of Section 11, read at its
leader, then makes the admitted root durable and conflict-detectable. The order is


economic validity → exact write set → economic-root admission → register: anti-equivocation.

The register is the last step and only the last step. It is not a policy engine and it decides nothing
about whether the transition was valid.
So DSM is simultaneously more customisable and more restrictive than ERC-20. The creator has
considerable freedom in defining the policy. Once committed, no later transfer, vault, or application can
route around it.

#### What the combination enables
The intersection rule is easy to state and easy to underrate. Here is what it actually buys once a CPTA
asset is inside a limbo vault.
A market cannot validly move a token in a way its committed policy forbids. On Ethereum
a token’s safety inside a pool depends on the pool contract. If the pool is upgradeable, buggy, or malicious,
the token’s own rules do not help; they ended at the contract boundary. In DSM the vault’s policy PM
can only narrow what ΠA already permits. A vault that tried to move A in a way ΠA forbids produces
an invalid successor, and the trader’s own verifier rejects it. There is no “audit the pool to know if the
token is safe there” step, because the token is checking.
Compliance-scoped assets can trade in open markets. A token whose policy says “only to
holders of credential c” can be placed in a public vault. Anyone can read the vault; only a credentialed
trader can produce a valid fulfilment, because ΠA is evaluated on the market successor like on any other
transfer. The issuer did not have to build a permissioned exchange, and the market did not have to know
the rule existed.
Supply commitments survive every hop. If ΠA fixes issuance, no vault, route, or emission
mechanism can mint more A, because each of them is just a transition over A and each is checked against
ΠA . A Bitcoin reader will recognise this: the twenty-one-million cap holds in every context because every
context is a transaction. CPTA gives an arbitrary asset the same property.
Multi-asset routes check themselves. A route through several vaults touching A, B, and C
satisfies each asset’s policy on each leg automatically, since every leg is a transition and every asset carries
its own predicate. The route constructor does not assemble a special safety argument; the intersection
does it.
Issuer, vault, and trader are three independent authors. The issuer committed ΠA once.
The liquidity provider committed PM and PR once. The trader supplies the live side. None of the three
can override the other two, none needs to be online for the other two’s rules to hold, and none had to
coordinate with the others when writing them.
That last point is the one worth sitting with. Three parties wrote three predicates at three different
times without talking to each other, and any market transition must satisfy all three. That is composability
without a shared contract, and it falls out of nothing more than “validity is an intersection.”

#### What a token policy should not say
A natural next question: does every token then need a rule saying which other tokens it may be exchanged
for? No, and it would be a mistake to design it that way.
A token’s policy says what makes a transfer of that token valid. It does not enumerate trading pairs.
The exchange relationship between A and B is the vault’s business, in PDLV . For a swap, ΠA asks whether


<!-- Source PDF page 58 -->

this movement of A is permitted under A’s rules; ΠB asks the same for B; the vault policy asks whether
this A-for-B exchange is permitted under this vault’s rules.
A more restrictive token can certainly say “only against approved assets,” “only through approved
vault policies,” or “only with counterparties who hold this credential.” That is an optional capability,
and it is how soulbound and compliance-scoped assets are built. It is not the default, because a default
that required editing the token’s committed policy every time someone opened a legitimate new pair
would defeat the purpose of having a stable committed policy at all.

#### Ethereum Comparison

An ERC-20 token’s rules live in its contract and stop at the contract’s boundary; once the token is
inside a pool or a bridge, that application’s code decides its fate.
A CPTA token’s rules are a committed policy that every verifier evaluates on every transition the
asset is part of, including transitions inside vaults and markets.
#### Architectural consequence
Asset-level invariants hold across every financial operation, not only inside the token’s own contract.
The token’s policy, the vault’s policy, and the arithmetic must all pass; there is no wrapping trick.
#### Tradeoff / boundary
This is a claim about enforcing asset-level invariants, not a claim that DSM is universally more secure
than Ethereum, which has a mature and well-studied security model of its own. And the flexibility
cuts both ways: a badly written policy is committed just as firmly as a good one. Cryptographic
commitment guarantees faithful enforcement of the policy, not that the policy was well designed.


<!-- spec-section: DSM-HL-062 -->
### 62 Deterministic Emissions (DJTE)
A Bitcoin reader has a specific question about any token system: where do the units come from, who
decides who gets them, and what stops that party from printing more.
Bitcoin’s answer is mining: a coinbase per block, a fixed schedule, halvings, and proof-of-work as the
lottery. That answer needs a chain, a block cadence, and a clock. DSM has none of those, so it needs a
different one.

#### Emission is a vault transition, not minting
All units exist from the start inside a locked source vault under a CPTA policy. Nothing is ever created;
the vault reveals units by moving them out. The vault state at emission index e carries the remaining
supply, and every emission transition must prove

remaininge+1 = remaininge − amounte ,         amounte ≤ remaininge .
That is the entire supply-cap argument. The remaining counter starts at the total and can only
decrease; when it reaches zero the vault emits zero forever. The schedule is halving-shaped: sixteen
epochs, each with twice the emission count and half the per-emission amount of the last. It will look
familiar.
Two things sit here and they should not be confused. The token policy designates the supply: how
many units can ever exist and the schedule on which they are released. The vault holds the units
themselves and the authority to release them, under that policy. A native token therefore has no minting
path at all: the full supply is created once, at the beginning, and everything afterwards is subtraction
from a reserve. That is a security decision, not a bookkeeping one. There is no transition anywhere in
the system that makes a native unit which was not there at genesis.


<!-- Source PDF page 59 -->

External assets are the one exception, and they are logically different. dBTC (Section 64) does mint
on admission and burn on withdrawal, because its supply is not fixed by a DSM policy; it is whatever
is locked on the chain it came from, and outstanding units can never exceed what is provably locked.
DSM secures the units while they are on DSM. The backing rests on the security of the chain that holds
it, and that is the holder’s risk to weigh: DSM’s post-quantum primitives do not extend to an external
backing chain that lacks them.

#### What triggers an emission
There is no block to trigger it, so DJTE is join-triggered. When a device passes the spend-gate (it has
paid for its genesis storage replicas), it produces a Join Activation Proof. Each valid proof is consumed
exactly once to drive one emission, by the same mechanism the reader has now seen several times: the
proof’s hash must be proved absent from a spent-set Sparse Merkle Tree before, and present after.
So the emission rate is set by how many devices join, and nothing else. No timer, no difficulty
adjustment, no miner.

#### Who receives it
The recipient is drawn uniformly over every activated identity, and the draw is proof-carrying: the
transition must carry evidence that the selection was computed correctly, and any verifier can check it
offline.

1. Seed: R0 = H(DJTE.SEED ∥ tip ∥ e ∥ jap hash). Nothing in it is choosable after the fact.

2. Total: a proof from a count tree that there are N activated identities.

3. Rank: k = UniformIndex(R0 , N ), exact rejection sampling, no modulo bias.

4. Descent: walk the count tree from the root. At each level, if k is less than the left child’s count go
left; otherwise subtract it and go right. After b levels you are at one shard with a local index.

5. Inclusion: a proof that the leaf at that index in that shard is the winner.

root
N =12
k=9 ≥ 5: subtract, go right

0: 5                                         1: 7
k=4 ≥ 4: go right
00: 2                          01: 3
10: 4                       11: 3

every step is an SMT opening a verifier recomputes

shard 11, index 0
SMT inclusion ⇒ winner


Because ranks are routed by counts, a shard with more identities gets proportionally more draws and
an empty shard gets none. That is not a skew; it is exactly what uniform-over-individuals means. The
paper proves the sharded descent is equivalent to sampling the concatenated global list, and that the O(b)
descent cost is information-theoretically minimal: choosing one of 2b shards needs b bits, so no cheaper
proof-carrying scheme exists.


<!-- Source PDF page 60 -->

#### No coordinator
Nobody runs the lottery. The seed is a hash of committed state, the count tree and shard accumulators
are committed roots, and the emission transition is verified by whoever receives it. Storage nodes mirror
the objects and are not asked to sign, order, or count anything. Two verifiers holding the same committed
state compute the same winner, and the source vault’s generation is a linear resource exactly like every
other, so two competing emissions from one De collide on the same key.

#### Bitcoin Comparison

Bitcoin’s issuance is a lottery weighted by hashpower, run by block cadence, capped by a schedule
every node enforces.
DJTE’s issuance is a lottery weighted uniformly over activated identities, run by device joins, capped
by a decreasing counter inside a vault every verifier enforces.
#### Architectural consequence
The lottery is a deterministic function of committed roots and a consumed join proof. There is no
miner to bribe, no timing to manipulate, and no party who could emit more than the counter allows.
#### Tradeoff / boundary
Uniform-over-identities is only as fair as identity creation is expensive. DJTE is mechanically correct
under Sybil behaviour, but the social fairness depends on the spend-gate making identity grinding
cost more than an emission is worth. That is DSM’s spend-gate property, not DJTE’s.


#### Aside: spam resistance without a global mempool
The DJTE paper also answers a question a Bitcoin reader will ask about any system with no mempool
and no fee market: what stops flooding?
Most of the answer is structural. A transition must bind to a receiver’s committed context (the
expected parent, index, and policy anchors), so random bytes cannot be represented as a valid candidate
at all and fail the cheapest check first. Inboxes are contact-gated: a device processes objects only from
relationships it has established, so a victim can stay fully online while declining to ingest a hostile sender.
And a zero-effect transition is not a transition, so “send nothing a million times” is not representable.
The residual case, valid high-volume traffic against storage capacity, is priced by prepaid credit
bundles: a sender-authored, state-advancing, accepted transition costs one credit, and refills go through
the spend-gate. Receiving never debits, so a victim’s credits cannot be drained remotely. There is no
time window in any of this. Bitcoin’s fee market solves congestion with a clock and a global queue; DSM
removes the global queue and prices only the sender’s own accepted steps.

> **Note (2026-09-22).** Credits are the storage payment mechanism: charged by storage used, at a fixed network price in token units (storage spec §17).


<!-- spec-section: DSM-HL-063 -->
### 63 Sovereign Finance (SoFi)
The hardest test of “you can build the applications” is a market. A decentralised exchange needs liquidity
that trades while its owner is asleep, prices that are deterministic, and no operator who can reorder
trades. On Ethereum that is a pool contract plus the global order.
SoFi is DSM’s answer. It is built entirely from pieces this document has already introduced, plus one
scoped mechanism it introduces honestly.

#### A vault holds the liquidity
A liquidity provider funds a Deterministic Limbo Vault by moving value out of ordinary spendable balance
and into encumbered vault reserves:


<!-- Source PDF page 61 -->

fund
BLP −−−−→ RDLV .
There is no second spendable copy. The LP owns and controls the vault by committing its policies at
creation:

- PM : the bounded market policy (the invariant, fees, and a per-transition size ceiling);

- PR : the release/close policy under which reserves may come back to ordinary balance.

Once funded, the LP is bound by those policies exactly as a trader is. The owner cannot reach into
the vault and take the reserves out; a release is a governed DLV transition like any other.

#### Why an absent LP can trade
In an ordinary DSM relationship, a present party can send its own value toward an absent one but cannot
make the absent party’s value move outward. There is no fresh authority for that.
A funded vault is the authority, committed in advance. The value is already inside an executable
state object and the conditions under which it may be exchanged were fixed before any trader existed. A
live trader supplies consideration and receives the corresponding reserve output while the LP is absent.
The trader is online; only the LP is away.

LP absent


reserve output
LP spendable          fund          DLV reserves                                   Trader
balance                         PM , PR committed                               (online)
consideration

release under PR


LP spendable
balance

reserves move only through committed policy, in either direction


#### The one new problem, and where it is settled
Everything above is bilateral DSM. But a public vault is executable by anyone, and two unrelated traders
can read the same vault parent and each construct a valid fulfilment before either sees the other. Within
one trader’s own chain, Tripwire handles it. Across two strangers’ chains there is no shared history to be
linear in.
A cell with a leader. The LP commits a storage-member set S when the vault is created. Every
vault parent Rn has a successor cell, and that cell has one leader: the first member of a deterministic
shuffle of S seeded from the vault id and Rn (Section 11). A trader who exercises writes one object to
that cell, the exercise: its signed fulfilment, its signed precommit, the settlement preimage and the policy
witnesses, all bound together by hash. It writes to the leader first, then the same bytes to the other
members, and any party may finish the copies. Members keep everything they are given in arrival order;
none authorizes, refuses, compares or signs anything.
The rule that decides the cell is the trader’s own device’s to evaluate, and anyone else’s, from raw
reads: the winner is the first exercise at the leader naming that cell, and it is final once the leader and
two other members hold it. Everything else at the cell counts as nothing. A losing attempt is dropped


<!-- Source PDF page 62 -->

and never becomes a state, so there is nothing to order; the next attempt key for that parent goes live,
and the loser builds again from the parent that was actually selected.
A reader may still want to call this consensus. Call it that, then, and ask the question that actually
matters: where is the bottleneck? A blockchain’s consensus is a bottleneck because every transaction in
the system passes through one ordering decision. Here there is no such decision. The cell of vault V1 and
the cell of vault V2 have different leaders derived from different roots, are read by different traders, and
never wait for each other. Ten thousand vaults trading at once are ten thousand independent cells, and
adding a vault adds a key, not a load on anything shared. Nobody votes and nobody counts toward a
threshold; the other members are copies. What the model achieves is that there is no shared sequencer
whose throughput caps the system, and that is the property the label was supposed to be about.

#### Winning the cell is not realization
Reaching the leader first settles who may consume the parent. It does not move the reserves. Reserves
move only when the trader’s position resolves: its fulfilment is registered at its own position cell, the
fulfilment conforms to the precommit, the route validates against the exact vault parents it names, and
every leg’s cell is final on this operation with a live attempt and a canonical parent. Then the trader’s
own bilateral successor is accepted under ordinary DSM and the vault’s successor follows from the same
operation. If any leg cannot resolve that way, the position resolves Void : no leg is consumed, nothing
rolls back, and the trader’s balance is untouched.


exercise written → first at the leader → every leg final → trader accepts own step → reserves advance

A trader who registers and walks away leaves nothing locked. There is no write authorization, so any
party can carry the remaining copies, and a registered fulfilment either completes or resolves Void on
what the cells hold. Losing attempts strand nothing: a skipped cell moves the parent’s attempt chain
forward.

#### What this gives you
- Independent vaults, atomic aggregation. A large trade may draw from several LPs’ vaults at
once. The route binds all of their parents in one settlement bundle; it executes fully or not at all.
The vaults remain independently owned. There is no pooled custody.

- Deterministic pricing. Allocation and pricing are checked integer arithmetic; two conforming
SDKs given the same vault states produce byte-identical routes.

- No global mempool or validator-reordering MEV surface. There is no global pending queue
and no validator with a reordering surface. A settlement bundle is visible to its storage set before
binding, but visibility grants no priority.

- Perpetuals and liquidation. Funding is denominated in trade activity rather than elapsed time,
and liquidation is a precommitted branch the position holder committed at open. No clock, no
oracle feed as authority; reference prices are co-signed windows over verified trade digests.

- Clockless. No timestamp, height, or duration appears in any validity rule.

#### Ethereum Comparison

On Ethereum a DEX is a pool contract: pooled custody, global ordering, priority-fee auctions, and
a well-documented MEV industry built on watching the mempool.


<!-- Source PDF page 63 -->

SoFi has sovereign vaults inside each LP’s own state, local verification, horizontal aggregation
without pooling, and no ordering surface to extract from.
#### Architectural consequence
Liquidity trades while its owner is absent without handing custody to a contract. The vault is the
owner’s consent, posted in advance (Section 4); the only shared place in the whole system is one cell
per vault parent, decided by which exercise reached its leader first, and read by the trader from an
owner-chosen storage set.
#### Tradeoff / boundary
Two costs are explicit in the specification. First, a market trade is online: it needs the vault’s storage
set reachable, so SoFi does not inherit DSM’s offline-bearer path. Second, the leader of a cell must
be reachable for that cell to advance; while it is not, the cell waits, and no other member stands in.
Both are liveness properties. Neither lets reserves move without a completed bilateral exchange.

> **Amendment A5 (owner, 2026-09-22) — a vault's storage set is assigned, never chosen.** A vault's storage set is the network's pinned set (SoFi §6; storage spec §10). No owner, liquidity provider or trader chooses storage members. Where this section says the LP commits a storage-member set or calls it owner-chosen, read: the vault commits the network's pinned set.


<!-- spec-section: DSM-HL-064 -->
### 64 dBTC: Bitcoin as a DSM Asset
#### The keg and tap model
DSM does not bridge Bitcoin. It taps it.
A bridge is one shared piece of infrastructure that every unit of the asset passes through: a custodian,
a federation, a multisig, a contract, a committee. Everyone’s Bitcoin sits behind the same door, and one
party or one quorum decides when the door opens. The bridge exists because the system on the far side
needs a single agreed answer to “what is backed and what may be released,” and a single agreed answer
is exactly what a consensus system produces. So the bridge is the consensus, and it carries consensus’s
failure modes: it is the thing that gets captured, and when it fails it fails for everyone at once.
Bitcoin itself is the keg. A tap is an HTLC: a depositor locks Bitcoin in a hash time-locked contract
under a dBTC vault profile, and that lock is their own sovereign tap into the keg. Anyone can put a
tap anywhere in the keg; there is no single spot, and no tap is shared. Nothing routes through a tap
but the units locked behind it. There is no shared operator, no shared key, no shared decision, and no
shared failure. One tap being drained, abandoned or misconfigured touches no other tap. The HTLC is
an ordinary Bitcoin construction; the tap is the shape of how it is used.
DSM is the first system able to do this, and the reason is the reason for everything else in this
document: it has no consensus. Where validity is local, “is this unit backed and may it be released” is a
question one verifier answers from one tap’s committed state, so there is nothing for a bridge to decide.
The shared structure is not removed by engineering; it was never required.
This is also not a Bitcoin-only arrangement. It is how value from any external system enters DSM:
that system is the keg, each lock into it is a sovereign tap, and nothing is bridged over. The rest of this
section is the Bitcoin instance of that rule.

#### dBTC is not a BitVM bridge
The Lightning reader had a name ready in Section 13; the bridge reader has one here. The least-trusting
design the rest of the field has produced is the BitVM2 bridge, in production as Citrea’s Clementine since
January 2026. It deserves the comparison because it is a real improvement on everything before it, and
because it is still a bridge.
A BitVM2 bridge locks all deposits behind one covenant emulated by an n-of-n signer committee that
pre-signs the whole transaction graph at setup. Safety rests on existential honesty: one honest signer at
setup (who is supposed to delete their key) and one honest watchtower during operation, drawn from
a permissioned set, plus a challenger willing to pay for an on-chain dispute. Withdrawals go through
operators who front the Bitcoin and later post a kickoff transaction to be reimbursed; the kickoff opens a


<!-- Source PDF page 64 -->

window in which watchtowers can challenge and, if the operator lied, a fraud proof is executed in Bitcoin
Script. In deployed practice the signers keep their keys so that they can sign an optimistic payout when
all are online, which the designers argue changes nothing because a compromised n-of-n can forge deposits
either way.
That is the shape: one shared door, a committee behind it, operators in front of it, and a challenge
game to keep the operators honest. It is 1-of-n instead of majority-of-n, and that is the whole advance.

| Property | BitVM2 bridge | dBTC tap |
|---|---|---|
| What holds the Bitcoin | one covenant for every deposit | one HTLC per depositor |
| Set up by | an n-of-n signer committee | the depositor alone |
| Safety needs | one honest signer and one honest watchtower | the holder’s own live state |
| Withdrawal path | an operator fronts funds, then claims | the holder burns, then signs Tn |
| Who must watch | a watchtower set, continuously | nobody |
| Dispute | a challenge game in Bitcoin Script | none; an invalid burn is not producible |
| Failure scope | the bridge, for everyone | one tap, for its holders |
| Anyone with copies of everything | is a signer or an operator, or nothing | has nothing |

The last row is the one to hold onto. In a BitVM2 bridge the parties who hold the bridge’s bytes
are exactly the parties whose honesty the design depends on. In dBTC, holding every byte of a vault,
including the sealed key, is worth nothing, because release begins with the consumption of live DSM state
that the holder of copies does not have.

#### Bitcoin Comparison

BitVM2 makes the committee small and the assumption thin, and it does so without changing
Bitcoin, which is a serious achievement.
dBTC has no committee to make small. Each depositor locks their own HTLC, each holder withdraws
against their own state, and no third party authorises, fronts, watches or challenges anything.
#### Architectural consequence
No signer set, no operator, no watchtower, no permissioned role, no dispute window, and no way for
one failure to touch another depositor’s Bitcoin. The trust assumption is not reduced to one honest
party; there is no party.
#### Tradeoff / boundary
A BitVM2 bridge delivers Bitcoin into a general execution environment with its own applications. A
dBTC tap delivers it into DSM, where what can be built is what Section 59 allows. Both inherit
Bitcoin’s own settlement assumptions at the boundary. And the ordinary caveat applies in both
directions: the deployed BitVM2 bridges are new and lightly used, and so is this.


#### What a holder holds
Every design that puts Bitcoin somewhere else has to answer one question: what exactly must a holder
hold to get the Bitcoin back, and what stops someone else who holds bytes from getting it instead?
Most answers name an authority: a custodian’s database, a mint’s signature, a federation’s threshold, a
statechain entity’s key share. In every case the thing that decides ownership is not the thing the holder
holds.
dBTC answers with the machinery this document has already built. The asset is live DSM state. The
Bitcoin key is settlement machinery, sealed, and useless to anyone who merely has a copy of it.


<!-- Source PDF page 65 -->

#### Two authorities, never conflated
Economic authority is ownership of live dBTC state in a device root: it is what transfers, what is
proved, what is consumed. It is the asset. Execution authority is the narrowly scoped Bitcoin material
needed to realise one authorised withdrawal. It is not evidence of ownership, it is not bearer state, and it
is not what anyone holds between transfers. The rule everything follows from is

Bitcoin bytes ⇏ dBTC ownership.
A party may know the vault identifier, the whole lineage, every public receipt, the ciphertext of the
execution capsule, the public execution key, the fulfilment hash, and hold a copy of every storage record.
None of that is ownership and none of it produces a withdrawal, because a withdrawal begins with the
consumption of real dBTC state, and there is nothing valid to consume.

#### Origin, transfer, withdrawal
Origin. A real Bitcoin output is locked in an HTLC under a dBTC vault profile. The admitting device
verifies the transaction, its inclusion, the exact script and amount, the network and the confirmation
depth the profile chose, the way a full node would. Exactly that quantity enters DSM as dBTC,
bound to its origin lineage v. After admission the depositor has no continuing role: it signs nothing
later, approves nothing, and need not exist.

Transfer. A dBTC transfer is an ordinary DSM economic transition (Section 9): the sender’s balance leaf
is consumed, the recipient is credited, provenance is preserved. It carries nothing Bitcoin-specific:
no pre-signed spend, no key, no vault material. There is no Bitcoin transaction per transfer, no
confirmation, no fee per hop, and no dust floor on what can be sent. dBTC adds no second
double-spend system; the same theorem that protects every other asset protects it.

Withdrawal. The holder constructs an exact intent W (amount, destination, fee, successor) and commits
cW . Live dBTC is verified and consumed in a burn bound to cW : spendable state becomes a
non-spendable completion object, and completion evidence σ exists for that consumption only. The
vault’s fulfilment secret is derived from the lock, the committed parameters and that evidence,

skVn = H(DSM/dlv-unlock ∥ Ln ∥ Cn ∥ σ),           SHA256(skVn ) = hf,n ,

and it opens a sealed execution capsule that signs exactly the committed transaction Tn and no
other.

The order is the whole design. The intuitive order, get the key, spend the Bitcoin, then burn the dBTC
you promised to burn, requires trusting the promise, and that is how a bridge acquires a custodian. Here
the burn is a completed DSM transition that the verifier checks, and the Bitcoin secret is a consequence
of its evidence. The hash equality is the last check, not the first, and it is never independently sufficient.


<!-- Source PDF page 66 -->

Bitcoin output paid under a vault profile, verified at depth
origin

exactly that quantity enters DSM as dBTC, bound to origin v


the wide middle   dBTC moves as ordinary DSM transitions, online or offline, touching no Bitcoin


the successor becomes the backing
holder commits exact intent W : amount, destination, fee, successor


live dBTC verified and consumed: S → S ′ , bound to cW

withdrawal
one way only            completion evidence σ exists for this consumption only


skVn = H(DSM/dlv-unlock ∥ Ln ∥ Cn ∥ σ) opens the sealed capsule


exactly Tn is signed: full exit, or payout plus successor vault


The middle band is wide and touches nothing. The bottom band runs one way: every arrow from the
intent to the signature is a consequence of the one above it, and there is no path to the signature that
does not begin with a consumed dBTC state.

#### Knowledge is not possession
Suppose an adversary has all of it: the complete vault descriptor, the complete lineage, every receipt, the
entire Bitcoin history, the encrypted capsule, the public execution key, the fulfilment hash, and a copy of
every storage replica. None of it creates a valid burn, and the withdrawal relation is conjunctive:


Withdrawable = LiveState ∧ StateAuthority ∧ ValidBurn ∧ ValidCompletion ∧ Preimage.

The secret is derived from one specific burn’s evidence. Substituting the lock, the parameters or the
evidence changes the derivation except with negligible probability, so there is no value an adversary can
compute, copy or replay that stands in for a consumption that never happened. Because the asset is
state rather than a secret, copying does not steal it, publishing does not weaken it, and storing the vault
material publicly is safe enough to be the default. That is what lets a holder withdraw years later without
ever meeting the depositor.

#### Partial withdrawal
If the holder wants only part out, the committed transaction pays the destination and, in the same
transaction, creates a successor vault holding the remainder under fresh execution authority, in the same
origin lineage. The spent parent is terminal; parent and successor are never both live backing. A successor
cannot be left at dust: the floor is fixed in the vault profile and enforced by the burn predicate, so a split
that would leave less than the floor is refused as a DSM transition and nothing downstream happens.
The remainder is never trimmed into fee, because the successor is collateral for outstanding dBTC the
withdrawer may not hold.


<!-- Source PDF page 67 -->

#### Storage, again
Storage exists here for one reason: so that a holder years from now can retrieve the vault material
although the depositor is gone. A node may hold the descriptor, the sealed capsule, proofs and indexes.
It decides nothing: it does not determine who owns dBTC, validate a burn, hold a mint key or a plaintext
vault key, sign an exit, or choose a successor. Holding the ciphertext is worth nothing, exactly as in
Section 11. A withheld or unreachable node delays retrieval and creates no authority; holders keep their
own copies.

#### Bitcoin Comparison

A wrapped-Bitcoin custodian’s database is the ledger, a federation’s signers are the authority, a
statechain entity holds a key share, and Lightning needs a responsive counterparty or an awake
watchtower. In each, the infrastructure holds something that matters.
In dBTC there is no shared infrastructure to hold anything. Each HTLC is its own tap into the
Bitcoin keg, and what storage holds for it is ciphertext and proofs. “Not your keys, not your coins”
is exactly right on Bitcoin, where the key is the asset. On dBTC the sentence is “not your live state,
not your coins.”
#### Architectural consequence
A bearer asset that moves offline, in any amount, with no third party in a transfer, and where the
set of parties who could steal it by being compromised includes only the holder. The depositor never
comes back, and nobody has to be online but the withdrawer.
#### Tradeoff / boundary
Withdrawal is online by design and inherits Bitcoin’s own settlement assumptions: the confirmation
depth the profile chose, and no claim that a deeper reorganisation is impossible. And the converse
of “knowledge is not possession” is that possession is whatever DSM says it is: an attacker who
compromises enough of a holder’s DSM authority to produce a transition the verifier accepts has
that dBTC, and the vault will not save them. dBTC is exactly as safe as the holder’s chain, and no
safer.


<!-- spec-section: DSM-HL-065 -->
### 65 Recovery as a Linear Generation
Suppose recovery generation Rn permits:

P (Rn ) = {csuccession , ccancel , cfailure }.
All three terminal alternatives consume:

x Rn .
Therefore:

KR = κres (s, xRn ).
Once one terminal outcome realizes:

KR ∈ Σ.
The same recovery generation cannot terminate a second conflicting way.


<!-- Source PDF page 68 -->

## Part IV — Offline DSM and Conflict-Local Finality
The offline operating mode, what it depends on, what a two-recipient attack looks like there, and what
finality means when there is no chain to wait for.


<!-- spec-section: DSM-HL-066 -->
### 66 Offline Bearer DSM
Offline operation creates a physical-state problem.
If two devices cannot consult online infrastructure, there are two separate questions:

1. Is the state transition mathematically unique under DSM?

2. Did the transition originate from the intended physical device?

DSM keeps these questions separate.
Software linearity answers the first.
Hardware identity evidence can strengthen the second.


<!-- spec-section: DSM-HL-067 -->
### 67 Offline Origin
An offline origin may be committed by coordinates such as:

(Ri , hi , ui ),
where:

- Ri identifies the authenticated device/root state;

- hi identifies the relevant frontier;

- ui is the committed progression coordinate.

All candidates originating from the same anchor step consume the same offline resource:

xoffline .
Therefore:

Koffline = κres (s, xoffline ).


<!-- Source PDF page 69 -->

Candidate c1


Offline origin                                   one commit   Next anchor state
Koffline
(Ri , hi , ui )                                               ui+1 = ui + 1

same origin ⇒ same key


Candidate c2

<!-- figure-note: Figure 22; nearby loose-layout text was extracted from the source graphic; use the PDF for spatial relationships -->
Figure 22: Offline Anchor Step


<!-- spec-section: DSM-HL-068 -->
### 68 The Committed Software Counter
Suppose:

ui = n.
A valid next anchor generation requires:

ui+1 = n + 1.
The new value is committed into authenticated state.
Thus logical monotonicity belongs to the software state machine.


<!-- spec-section: DSM-HL-069 -->
### 69 Hardware Counter Versus Software Authority
A hardware counter may be useful for:

- anti-rewind evidence;

- clone resistance;

- stale-state detection;

- physical-device exposure limits.

But the hardware counter is not the transaction authority.
The uniqueness theorem remains:

K ∉ Σ
before consumption and:

K ∈ Σ′
after consumption.


<!-- Source PDF page 70 -->

<!-- spec-section: DSM-HL-070 -->
### 70 The Observer Model, Inverted
Anyone who has looked at offline digital cash will recognise the shape of a secure element that co-signs
payments.
Chaum and Pedersen proposed it in 1992 as the wallet with observer : a tamper-resistant chip inside
the user’s wallet that co-signs every payment and refuses to sign the same value twice. Brands’ cash sits
in the same model. Fielded smartcard purses used it, and most recent offline CBDC and secure-element
payment designs still do.
In that model the hardware is the double-spend authority. It is trusted to enforce uniqueness. That
means the protocol inherits the hardware’s entire attack surface as its own: extract the key, break the
counter, or emulate the chip, and double spending follows.
DSM refuses that assignment.
Transfer uniqueness, offline included, is a software theorem of the guarded linear kernel (Sections 52
and 67). It holds with the anchor hardware deleted. The proof mentions no chip, no counter read, and
no measurement.
What software cannot do is tell an enrolled device from a perfect copy of its host-readable bytes.
That is the one job left, and it is the only job the hardware is given.


| Property | Observer model | DSM offline bearer |
|---|---|---|
| Who enforces uniqueness? | the chip | the state predicate |
| What does the chip prove? | “this value was not spent” | “this is the enrolled device” |
| Break the chip and… | double spend | forge a device, not a transfer |

The last row is the inversion. In the observer model a hardware compromise is a protocol compromise.
In DSM a hardware compromise lets an attacker impersonate a device; it does not let two successors of
one origin both become realized state, because that exclusion never lived in the hardware.

#### Bitcoin Comparison

Bitcoin readers know hardware wallets, and know that a hardware wallet protects a key, not the
ledger. If the wallet is compromised the coins can be stolen, but the UTXO set does not become
inconsistent.
DSM holds the same line one layer deeper. The offline anchor protects the identity of the physical
device, not the uniqueness of the transfer. Uniqueness comes from the same resource-consumption
theorem that runs online.
#### Architectural consequence
The security argument for offline transfer does not reduce to “trust the chip.” The chip answers one
narrow question, and the answer to that question cannot create a second valid consumption of a
consumed resource.
#### Tradeoff / boundary
A perfect live clone of every non-exportable factor is indistinguishable from the original by any
offline-only protocol. That is the stated boundary of the identity claim. It is a boundary on who the
device is, not on whether a transfer is unique.


<!-- spec-section: DSM-HL-071 -->
### 71 Three-Factor Offline Identity
An offline release may be supported by multiple signatures over the same state-advance message.
Conceptually:

1. seed-rooted DSM signature;


<!-- Source PDF page 71 -->

2. chip-rooted non-exportable signature;
3. measurement-gated host/partition signature.
These witnesses answer:
Did this state advance come from the enrolled physical execution environment?
They do not replace the software state theorem.

software establishes state uniqueness;

hardware strengthens physical-instance authenticity.


Software DSM state                               Physical identity evidence
K, Σ, ρ                                  chip / measurement / counter

theorem                                                        witness


State-transition uniqueness                         Physical-instance assurance

answers: unique?                            answers: enrolled device?

Accepted offline release

different questions; neither mechanism answers the other’s

<!-- figure-note: Figure 23; nearby loose-layout text was extracted from the source graphic; use the PDF for spatial relationships -->
Figure 23: Software and Hardware Roles

#### Bitcoin Comparison

Bitcoin transactions can be signed offline, but ordinary settlement requires eventual reconciliation
with the Bitcoin network’s accepted chain state.
DSM’s offline mode is designed around an explicit authenticated state origin and locally verifiable
linear-resource progression.
#### Architectural consequence
Offline uniqueness still comes from the same software resource-consumption theorem used online.
Hardware adds identity and anti-clone evidence without becoming the canonical transaction register.


<!-- spec-section: DSM-HL-072 -->
### 72 Two Offline Recipients
Part I traced the online double spend to its refusal at the register. The offline case deserves the same
treatment, because it is where every offline-cash design in history has failed, and because the previous
sections have described the machinery abstractly.

#### The setup
Alice’s device holds an offline origin at coordinates (Ri , hi , ui ) with ui = n. She is in a place with no
connectivity, and so are Bob and Carol. She pays Bob from that origin, then walks across the room and
pays Carol from the same origin.
Neither recipient can reach the register. Neither can reach the other. Each sees only what Alice hands
them.


<!-- Source PDF page 72 -->

#### What each recipient sees
Bob receives a state advance from (Ri , hi , n) to (Ri+1 , hi+1 , n + 1), consuming Koffline = κres (s, xoffline ),
carried by the three-factor witness of Section 71: the seed-rooted DSM signature, the chip-rooted non-exportable signature, and the measurement-gated partition signature, all over the same state-advance
message. Bob verifies the software predicate against the origin, verifies each witness against the enrolled
device’s committed identity, and accepts.
Carol is handed something that claims to be the same thing: an advance from (Ri , hi , n), consuming
the same Koffline , with a three-factor witness. She has no way to ask whether n has already been consumed.
So the question is not what she can observe about Alice’s history. It is whether Alice can produce that
object at all.

#### What the genuine device can and cannot do
After paying Bob, the enrolled device’s committed progression coordinate is n + 1. The software state
machine will only construct the next advance from n + 1. To pay Carol from n, Alice needs a state-advance
message from the stale coordinate, signed by all three factors.
The seed-rooted signature she can produce: it is software, she holds the seed, she can run modified
code. The other two she cannot. The chip-rooted signature is issued only inside the measured execution
environment, and the measurement gate binds that signature to the enrolled partition running the enrolled
code. Modified code that would sign a stale coordinate is not the measured code, so the partition witness
fails, and the chip does not co-sign an advance the partition did not attest. Carol’s verifier sees a witness
with one valid factor of three and refuses.
This is the whole content of Section 71 made concrete. The software theorem says two consumptions
of Koffline cannot both be realized in one lineage. The hardware does not repeat that theorem. It answers
the only question the theorem leaves open offline: did this advance come from the enrolled device running
the code that respects the theorem?

#### The clone
Now suppose Alice has done the expensive thing: extracted every non-exportable factor and built a
second device that is, at the moment of use, indistinguishable from the enrolled one. Both devices hold
the origin at n. Device one pays Bob; device two pays Carol. Both witnesses verify. Both recipients
accept.
This is the stated boundary, and the document does not pretend otherwise: a perfect live clone of
every factor is indistinguishable from the original by any offline-only protocol. That was true of the
Chaum–Pedersen observer, of every smartcard purse, and of every offline CBDC design, and it is true
here. What differs is what happens next.

#### What happens later
Both advances name position n + 1 under the same device identity. The first of Bob or Carol to reconnect
registers Alice’s root at n + 1. The second finds the cell already holding a different root. The register
refuses the second write and returns the held digest.
At that moment the loser holds something no observer-model system provides: two witnessed state
advances from one committed origin, each signed by the same chip-rooted identity, naming the same
position with different roots. That is not a suspicion. It is a proof of equivocation, attributable to a
physical device identity rather than to an anonymous key, and it is verifiable by anyone who holds both
objects.
What the protocol does with that proof is policy: the device identity is burned, the losing recipient
has an attributable claim, and the value at stake was bounded in advance by the physical-device exposure


<!-- Source PDF page 73 -->

limits that the offline policy committed. What the protocol does not do is let both advances become
realized state. Only one root occupies n + 1; only one consumption of Koffline is in any lineage.

#### The two questions, answered separately
Section 66 said offline operation poses two questions and that DSM keeps them apart. The trace shows
why that separation is the whole design.
Is the transition unique? Yes, by the software theorem, with the hardware deleted: two consumptions
of one Koffline cannot both realize, and the register makes that fact durable the moment either recipient
reconnects.
Did it come from the enrolled device? Yes if the witness verifies and the device was not perfectly
cloned; and if it was, the clone is detected and attributed at reconnection, with the loss bounded by
committed exposure policy.

#### Bitcoin Comparison

An unconfirmed Bitcoin payment accepted offline is exposed until the transaction reaches the chain,
and if a conflicting transaction is mined first, the merchant holds nothing and can prove nothing
about who defrauded them.
An offline DSM payment is exposed only to a perfect live clone of the payer’s enrolled device, and if
that clone is used, the defrauded recipient holds a verifiable, device-attributable proof of equivocation
the moment either party reconnects.
#### Architectural consequence
The offline double spend requires hardware extraction rather than a race, is detected at first
reconnection rather than never, and produces attributable evidence rather than a silent loss.
#### Tradeoff / boundary
Detection is not recovery. Whether the defrauded recipient is made whole is a question for the
exposure policy and the issuer, not for the state machine. And the clone boundary is real: no
offline-only protocol distinguishes a perfect clone, and DSM does not claim to.


<!-- spec-section: DSM-HL-073 -->
### 73 Conflict-Local Finality as a State Property
DSM uses finality in a specific sense.
It does not mean:

Every machine in the world has observed the transition.

It means:

The consumed committed resource cannot produce another conflicting realized successor inside
the same valid state lineage.

Suppose:

K = κres (s, x).
After realization:

K ∈ Σs′ .
A second consumption requires:


<!-- Source PDF page 74 -->

K ∉ Σs′ .
That fails.
Therefore the exclusion follows from the state itself.


<!-- spec-section: DSM-HL-074 -->
### 74 Bitcoin Confirmation Versus DSM Finality
#### Bitcoin Comparison

Bitcoin confirmation confidence increases as additional proof-of-work blocks extend the chain
containing a transaction.
DSM does not use confirmation depth as the core validity mechanism.
Its question is:

Accept(s, s′ , w) = True?
and:

K ∉ Σs ?
#### Architectural consequence
A resource’s single-consumption property does not become mathematically stronger merely because
unrelated future blocks are produced.
Once the canonical DSM successor consumes the resource, a conflicting second consumption is
non-derivable under the same realized lineage.


<!-- spec-section: DSM-HL-075 -->
### 75 End-to-End Worked Example
Suppose Alice’s device A has a bilateral relationship with Bob’s device B.
Current relationship head:

hAB,n .
Relationship key:

kAB .
Current relationship mapping:

Rn (kAB ) = hAB,n .
Current consumed set:

Σn .
Current core root:

ρcore,n = SMT(Rn , un , Σn , Πn , Ωn ).
Current future candidates:

Pn .


<!-- Source PDF page 75 -->

Suppose candidate:

cB = (sn+1 , bB , gB , KB , dB ).
The candidate digest is:

dB = H(enc(sn+1 )).
The relationship-parent descriptor is:

xAB,n = (relationship, kAB , hAB,n ).
The resource-consumption key is:

KAB,n = H(DSM/consume resource/v1 ∥ ρcore,n ∥ xAB,n ).
The current state must prove:

KAB,n ∉ Σn .
The guard must verify:

gB (sn , w) = True.
The relationship advances:

hAB,n → hAB,n+1 .
Thus:

Rn+1 (kAB ) = hAB,n+1 .
The resource is consumed:

Σn+1 = Σn ∪ {KAB,n }.
The next core root is:

ρcore,n+1 = SMT(Rn+1 , un+1 , Σn+1 , Πn+1 , Ωn+1 ).
The next state commits its future space:

Pn+1 ,        Γn+1 .
Then:

ρn+1 = H(ρcore,n+1 ∥ digest(Pn+1 ) ∥ digest(Γn+1 )).
The result is:

sn → sn+1 .
The old relationship parent is consumed.
The new relationship head becomes current.
The new root becomes canonical for that lineage.
The next candidate future space is already cryptographically bound to the new state.


<!-- Source PDF page 76 -->

This is the core realization pipeline, common to every mode. Online acceptance additionally applies
the register step of Section 12: before the candidate is evaluated, the sender’s cell at the next position
must be empty or hold exactly the presented root.


Canonical parent state sn
parent

Recompute ρcore,n


Verify ci ∈ Pn
candidate
& guard
Evaluate gi (sn , w)


Derive canonical resource descriptor xi


linearity                Derive Ki = κres (sn , xi )


Verify Ki ∉ Σn


Apply named relationship/state projections


apply                   Set Σn+1 = Σn ∪ {Ki }


Apply deterministic policy/mode updates


Recompute ρcore,n+1


commit                   Commit Pn+1 and Γn+1


Canonical successor state sn+1


<!-- figure-note: Figure 24; nearby loose-layout text was extracted from the source graphic; use the PDF for spatial relationships -->
Figure 24: Core DSM Realization Pipeline


## Part V — Assessment
Why every piece is necessary, what is assumed, what is proved, and the whole system in one picture.


<!-- Source PDF page 77 -->

<!-- spec-section: DSM-HL-076 -->
### 76 Why Every Piece Is Necessary
No individual DSM mechanism is sufficient by itself.

#### Hash chaining alone
Hash chains establish ancestry.
They do not by themselves prevent two successors from referencing the same parent.

#### SMTs alone
SMTs authenticate state.
They do not define which transitions are legal.

#### Precommitment alone
Precommitment constrains possible futures.
It does not by itself stop two conflicting committed futures from both trying to realize.

#### Guards alone
Guards determine fulfillment.
They do not provide the strongest exclusion rule if multiple guards can be satisfied.

#### Resource keys alone
Resource keys work only if conflicting branches are forced to derive the same key.

#### Consumed state alone
The consumed set is useful only if it is cryptographically authenticated and carried forward monotonically.
Therefore:

canonical encoding
+ determinism
+ bilateral hash chains
+ SMT authentication
+ precommitment
+ guards
+ canonical resource derivation
+ shared consumption keys
+ monotonic consumed state


=⇒ guarded-linear-kernel realized-history safety.

That conclusion is the kernel’s: within one valid realized lineage, no linear resource is consumed twice.
The full online story of Part I, in which two counterparties who never speak must both be protected from
a stale root, requires one more piece on top of the kernel: the economic-root register, one cell per position
with one leader, where the first signed claim to arrive is the root at that position (Sections 9 and 11).


<!-- Source PDF page 78 -->

The kernel makes the second consumption invalid; the register makes the stale parent undeniable to an
independent recipient.


<!-- spec-section: DSM-HL-077 -->
### 77 Architecture Comparison

| Property | Bitcoin | DSM |
|---|---|---|
| Primary model | UTXO monetary state derived from a globally accepted proof-of-work blockchain | General guarded linear state derived from authenticated state transitions |
| Global ordering | Fundamental to accepted chain history | Not part of the state-validity mechanism |
| State progression | Blocks and transactions advance a shared public history | Canonical state generations advance by deterministic derivation |
| Pairwise state | Not fundamentally organized as bilateral chains | Explicit bilateral forward-only relationship chains |
| Merkle role | Transaction inclusion commitment in blocks | Authenticated current-state relationships, resources, and other state components |
| Future state | Spending conditions constrain valid spends | Exact candidate successor spaces may be precommitted |
| Conditional execution | Script/witness conditions | Deterministic guard families over candidate branches |
| Single consumption | UTXO outputs | General linear state resources |
| Conflict handling | Accepted blockchain history determines the surviving spend | Conflicting candidates share a resource key that can be consumed once |
| Invalid transactions | Can be produced, propagated and mined; found and discarded after the fact | Not producible: a transition that breaks a rule fails the predicate and never exists as a state |
| Guarantee | Probabilistic: confirmation depth makes reversal expensive, never impossible | By construction, exactly as strong as the predicate being the only door; a bug that lets a step be skipped breaks it, and no step can be skipped once it holds |
| Consent of an absent party | Script conditions on an output | A vault: the party’s terms committed in its own state in advance, met by the other party’s transition |
| The middleman | Replaced by a network that decides what stands | Removed: storage keeps bytes and decides nothing; validity is recomputed by the parties |
| Finality | Proof-of-work confirmation depth and accepted chain | Conflict-local non-derivability after canonical resource consumption |
| Independent state | Still ultimately represented relative to one blockchain history | Independent bilateral/resource state can advance without universal ordering |
| Availability | Peer-to-peer block/transaction propagation | Storage and routing are separated from state authority |
| Offline bearer model | Offline signing possible; ordinary settlement requires later chain reconciliation | Optional authenticated offline origin plus software linearity and physical-device evidence |
| Bitcoin held elsewhere | Wrapped or federated: a custodian’s database or a signer set is the authority | dBTC: tapped, not bridged; Bitcoin is the keg, each HTLC is a sovereign tap, live DSM state is the asset, and the Bitcoin key is sealed machinery released only by a consumed burn |

<!-- spec-section: DSM-HL-078 -->
### 78 Produced and Discarded, or Never Producible
The rows above reduce to one difference, and it is the difference every other comparison in this Part
descends from.
A blockchain lets malicious and malformed transactions be produced. They are broadcast, they sit in
mempools, and the network’s job is to find them and discard them after the fact. That is why it needs a
global machine to agree on what stands, and why, even with that machine, its answer is probabilistic:
a high probability that a transaction is settled, never a guarantee, because a deeper reorganisation is
expensive rather than impossible.
In DSM a transition that breaks a rule is never producible. The realization predicate of Part II is the
only way a state comes into existence, and it produces nothing unless every rule holds. There is nothing
to find and nothing to discard. That is the sense in which the guarantee is unconditional, and it is worth
stating its condition precisely: the guarantee is exactly as strong as the predicate being the only door. A
bug that lets a step be skipped breaks it. Once no step can be skipped, it holds. That is what the formal
work of Section 81 exists for: to show that the predicate as written has the property, and to bind the
predicate as written to the code that runs.

Zero knowledge proofs. The comparison a cryptographer will reach for is not the blockchain but the
proof system bolted onto it. Both identify attributes of an object. A zero knowledge proof uses them
to convince a verifier that something is correct without disclosing the object. DSM is a linear object
consumption system: it uses the same attributes to make incorrectness impossible to construct. The
privacy that results is structural rather than added. There is no global ledger; only the parties to a
relationship hold its bytes; and nothing heavy has to be computed to prove what the construction already
guarantees. A zero knowledge proof is expensive precisely because it proves correctness on top of an
architecture that admits incorrect things. Here the problem is solved one level down, so there is no such
proof to build.

The middleman. A bank is a middleman. A blockchain replaces the middleman with a network that
plays the same role: it decides what stands. DSM has no such role. Storage nodes hold bytes and decide
nothing (Section 11); the two parties to a relationship recompute validity themselves; and a party that is


<!-- Source PDF page 80 -->

absent has already committed its consent in a vault (Section 4). Nothing sits in the middle, so there is
nothing to capture, bribe, or wait for.

#### Key Idea

Blockchain replaces the middleman. DSM removes it. Blockchain produces the bad transaction and
discards it later, with high probability. DSM cannot produce it.

DSM’s architectural advantage is not merely speed.
It changes what must be coordinated.
Suppose there are one million independent state relationships.
If none shares a resource with another, then their relative ordering is not a state-validity question.
DSM permits them to remain mathematically independent.
The governing rule is:

dependencies are explicit state relationships, not a global ordering requirement.
Where ordering is semantically required, DSM can encode that ordering as state.
Where ordering is not semantically required, DSM does not invent one.
Therefore the validity architecture remains deterministic without a global sequencing layer.

#### What this looks like at scale: a game
Take the most demanding consumer economy there is: a game with a hundred million players, hundreds
of millions of items, and a match running at sixty frames a second.
The blockchain answer to “put this economy on-chain” has been tried, on Ethereum first and then on
faster and object-oriented chains. It runs into the same wall each time: the chain is a shared execution
environment, so every economic action becomes work for the whole network. Faster chains raise the
ceiling. None removes it, because each still asks a shared network to order and validate every state
change.
DSM’s proposition is the inverse. Do not globally execute what does not need global agreement.
The game keeps running on the studio’s servers and the players’ devices, at game speed. Movement,
physics, shooting, matchmaking are not economic events and never touch DSM. Underneath, the things
that actually represent scarce value, a rare skin, a currency, a crafting input, a tournament prize, are
CPTA assets with committed policies in the players’ own device state. When Alice gives Bob the skin,
Bob verifies its lineage and policy himself, at acceptance, against Alice’s economic root. Nobody else ran
anything.

not the game on a chain; sovereign ownership underneath the game.
This is why DSM is horizontally scalable in the ordinary sense of the term. Adding a player adds that
player’s device and its relationships. It does not add that player’s actions to every other participant’s
workload, because there is no every-other-participant role. A hundred million players are a hundred
million concurrent verifiers of their own state, and the only shared surfaces are the storage set’s keyed
cells, which are per-device, per-position, content-blind, and decided by which object reached the cell’s
leader first.
The caveat belongs in the same paragraph. Horizontal scalability is a property of the architecture:
no global execution, no global ordering, per-device economic roots. How close the implementation gets
to it at a hundred million devices is an empirical question about verification cost, storage throughput,
anti-equivocation under load, and recovery. Those are benchmarks to run, not theorems, and this
document does not claim them.


<!-- Source PDF page 81 -->

<!-- spec-section: DSM-HL-079 -->
### 79 What Bitcoin Optimizes For
Bitcoin’s design solves a different primary problem.
It provides one highly replicated, proof-of-work-secured monetary history.
That makes the question:
What is the accepted Bitcoin chain?
fundamental to its operation.
DSM does not attempt to reproduce a global ledger under a different name.
It changes the state model itself.
The core question becomes:
Is this successor deterministically derivable from this committed parent, under the exact
guards, resources, policies, and proofs already bound to that state?


<!-- spec-section: DSM-HL-080 -->
### 80 Security Assumptions
DSM’s guarantees depend on explicit assumptions.
These include:
1. cryptographic hash collision resistance;
2. signature unforgeability;
3. canonical serialization correctness;
4. correct relationship-key derivation;
5. correct resource-descriptor derivation;
6. conflicting branches deriving the same authoritative resource key;
7. correct SMT proof verification;
8. correct monotonic consumed-state updates;
9. faithful implementation of the deterministic transition predicate;
10. for offline physical claims, security of the relevant fused hardware and measurement boundary;
11. durable member memory: a storage member never alters, reorders or loses what it holds for a
key, including after restart, restoration, or storage migration, so the first object to reach a cell’s
leader stays first;
12. leader derivation: the writer and the verifier compute a cell’s leader from the owner-committed
member set and committed state only, so no availability view, node id or caller choice can move a
cell to a different member.
Failure to reach a cell’s leader, or two other members, is a liveness failure: the cell waits. Violation of
durable member memory is a safety failure.

> **Note (2026-09-22).** How member replacement and storage migration preserve assumption 11 is specified in `DSM_Storage_Node_Specification.md` Part III.
The concrete primitives behind the first two assumptions are post-quantum: BLAKE3 for hashing,
SPHINCS+ for signatures, and Kyber for key encapsulation. The safety theorem itself is scheme-agnostic;
any collision-resistant hash and unforgeable signature will do, and the choice of post-quantum primitives
means the assumptions do not weaken when large quantum computers arrive.
No cryptographic protocol eliminates assumptions.
The important requirement is that the safety theorem follows from clearly stated assumptions rather
than from informal trust.


<!-- Source PDF page 82 -->

<!-- spec-section: DSM-HL-081 -->
### 81 Formal Verification
The safety theorems in this document are not only stated. They are supported by machine-checked
artifacts, and the scope of those artifacts is stated precisely so that the reader can see what is covered
and what is not.

#### What has been proved
Lean 4. The key-scoped uniqueness theorem and Tripwire are proved over an abstract guarded model:

- an abstract type of states and an abstract type of resource keys;

- a step relation scoped by consumed keys;

- a history fold that threads the consumed set forward;

- the theorem that no valid realized history contains a key-scoped realized fork.

The uniqueness and Tripwire core depends on no axioms. The desired result is not assumed anywhere
and then rediscovered; it follows from resource-key uniqueness, consumed-set threading, and the absence
check before each accepted step.
TLA+ . A companion model checks the same statements on concrete guard families, in both the
per-state form and the realized-history form of Section 8. Three checks are worth naming:

- a well-formed family, in which one conflict class resolves to a single successor and a disjoint branch
consumes a second key, satisfies both safety and realized-history uniqueness;

- a deliberately malformed family, in which conflicting branches are given different keys for a shared
resource, is shown to violate uniqueness. This is the falsification that confirms guard-family
well-formedness is load-bearing rather than decorative;

- a relationship-scoped model, in which keys embed the relationship identity and each relationship
has one acceptance locus, confirms that same-parent multi-receiver forks are unconstructible in
online DSM;

- a storage-cell model, in which members keep every value in arrival order and one leader per cell is
derived from committed state, checks that a value is final only if the leader holds it, that at most
one value is final per cell, that the leader is a function of the seed and the committed set only, and
that bytes which are not a recognized object never occupy, finalize or consume a cell. Each property
has a companion configuration that weakens one rule and fails on exactly that property.

The recognition boundary. A second Lean module proves the statement that the two halves of
Section 4 and the whole of Section 78 rest on: for arbitrary bytes from an adversary, constructible implies
recognized implies valid. Whatever bytes arrive, if the canonical constructor recognizes them, then every
field but the signature is the constructor’s own derivation from committed state and every rule holds; and
hostile bytes never become state. The converse, that a recognized object is byte for byte the constructor’s
own output, is deliberately not claimed, because a verifier holds only the public key, the message and the
signature and cannot recompute a deterministic signer’s randomizer. Seven mutation controls each delete
one hypothesis and turn the named theorem red while a non-vacuity witness stays green.


<!-- Source PDF page 83 -->

#### What the artifacts do not cover
The TLA+ module treats resource keys as given inputs and guard well-formedness as an opaque flag. It
exercises the consumed-set threading and the linearity layer. It does not exercise resource-key derivation
or descriptor injectivity; those are discharged by the derived-keys-only rule and the implementation
enforcement skeleton of the formal paper, not by the model checker.
The Lean development does not attempt to prove hardware behaviour, firmware correctness, secure-element behaviour, or transport liveness. Those appear in this document as assumptions or implementation
obligations.
No offline-specific uniqueness artifact is required: offline steps are accepted through the same realized-history fold the artifacts already check.
The storage-cell model covers the rule that decides a cell; it does not cover the members’ durable
memory, which is a fault-model obligation stated as an assumption in Section 80, not a theorem of the
kernel.

#### The standing caveat
proved model property ≠ automatically proved implementation.
A production implementation must faithfully refine the abstract model. The artifacts prove that the
model is safe; conformance testing and the enforcement skeleton are what tie the code to the model.

#### Bitcoin Comparison

Bitcoin’s safety argument is empirical and economic: the chain has held under adversarial conditions
for a long time, and the cost of rewriting it is public.
DSM’s core safety argument is a proof over an abstract model, with the model’s boundaries written
down.
#### Architectural consequence
The claim “two conflicting consumptions cannot both be realized” is a theorem with a machine-checked proof, not a track record. A reader can inspect exactly which assumptions it rests on.
#### Tradeoff / boundary
A proof about a model says nothing about a bug in the code that implements it. Bitcoin’s decade
of adversarial uptime is evidence of a kind no proof supplies. The two arguments are different in
nature, and the honest position is to want both.


<!-- spec-section: DSM-HL-082 -->
### 82 One Mathematical Picture of DSM
Start with:

sn = (Rn , un , Pn , Γn , Σn , Πn , Ωn , ρn ).
Compute:

ρcore,n = SMT(Rn , un , Σn , Πn , Ωn ).
Select candidate:

ci ∈ Pn .
Verify guard:

gi (sn , w) = True.


<!-- Source PDF page 84 -->

Derive resource descriptor:

xi .
Derive resource key:

Ki = κres (sn , xi ).
Verify:

Ki ∉ Σn .
Apply the named state transformation:

Rn → Rn+1 .
Consume the resource:

Σn+1 = Σn ∪ {Ki }.
Update:

un → un+1 ,


Πn → Πn+1 ,


Ωn → Ωn+1 .
Recompute:

ρcore,n+1 .
Commit:

Pn+1 ,          Γn+1 .
Then:

ρn+1 = H(ρcore,n+1 ∥ digest(Pn+1 ) ∥ digest(Γn+1 )).
Thus:

sn → sn+1 .
And because:

Ki ∈ Σn+1 ,
the consumed parent cannot be used again as a second conflicting consumption inside that valid
lineage.


<!-- Source PDF page 85 -->

<!-- spec-section: DSM-HL-083 -->
### 83 Intuitive Analogy
Imagine a sealed mathematical workbook.
Each page contains:

1. the current state;

2. a fingerprint of the previous state;

3. the current bilateral relationship heads;

4. a compact authenticated tree root;

5. a list of one-use resources already crossed out;

6. the exact possible next pages;

7. the conditions that would permit each next page;

8. deterministic policy.

A valid next page must have been listed in advance.
It must satisfy the correct condition.
It must consume a resource that has not already been crossed out.
When that resource is used, the next page permanently commits the fact that it was consumed.
The new page then commits its own possible successors.
Two unrelated sections of the workbook may progress independently.
But two pages that claim to consume the same one-use resource cannot both belong to one valid
derivation.
That is the intuitive DSM construction.


<!-- spec-section: DSM-HL-084 -->
### 84 Final Summary
DSM is built from several mechanisms that reinforce one another.

#### 1. Canonical deterministic state
x → enc(x) → H(enc(x)).
The same logical state must produce the same bytes and commitment.

#### 2. Bilateral relationship chains
hr,0 → hr,1 → hr,2 .
Relationships progress independently.

#### 3. Sparse Merkle authentication
kr ↦ hr
is committed into a compact authenticated root.


<!-- Source PDF page 86 -->

#### 4. Canonical state chaining
sn → sn+1
means the successor is deterministically derivable from its parent.

#### 5. Precommitment
P (s) = {c1 , . . . , cn }.
The future state space is constrained before realization.

#### 6. Guards
gi (s, w) = True
determines whether one candidate’s fulfillment condition has been met.

#### 7. Linear resources
K = κres (s, x).
All conflicting branches consuming resource x derive the same authoritative key.

#### 8. Monotonic consumption
K ∉ Σs
before realization and:

K ∈ Σs′
after realization.

#### 9. Conflict-local uniqueness
Two conflicting branches cannot both consume the same linear resource in one valid realized history.

#### 10. No global ordering requirement
State validity is determined from explicit committed dependencies.
A universal transaction ordering layer is not required.
If an application requires an ordering relation, that relation can be encoded as deterministic state
rather than supplied by global consensus.


<!-- spec-section: DSM-HL-085 -->
### 85 The Core DSM Statement
The entire construction can be summarized as:


<!-- Source PDF page 87 -->

canonical bytes
+ deterministic verification
+ bilateral state chains
+ Sparse Merkle commitments
+ canonical state roots
+ precommitted candidate futures
+ deterministic guards
+ linear-resource descriptors
+ shared consumption keys
+ monotonic consumed state


=⇒ conflict-local realized-state uniqueness without global ordering.
Bitcoin solves double spending by placing monetary transactions into a globally accepted proof-of-work
history and deriving the valid UTXO state from that history.
DSM removes global ordering from the validity architecture entirely.
It does not replace one global ordering system with a smaller global ordering system. Applications
with genuinely shared public resources use one keyed cell per resource, with one leader derived from
committed state, where the first object to arrive is the one that counts; that establishes exclusivity for
the named resource without constructing a universal transaction order.
It replaces ordering authority with explicit authenticated state constraints.
The verifier asks:

Is this successor mathematically derivable from the committed parent?
The decisive facts are already present in or cryptographically bound to the state:
- the current relationship heads;
- the canonical state root;
- the candidate successor set;
- the deterministic guard family;
- the exact linear resources involved;
- the consumed-resource state;
- the deterministic policy;
- the required signatures and proofs.
Many futures may be precommitted.
Many independent relationships may progress concurrently.
Many machines may store and relay the data.
But for one committed linear resource:

one valid realized lineage cannot contain
two conflicting consumptions of the same resource.
That is the central mathematical idea of DSM.
