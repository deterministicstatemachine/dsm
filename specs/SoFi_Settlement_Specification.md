---
title: Sovereign Finance (SoFi) Settlement Specification
document_role: subsystem-normative-specification
parent_spec: DSM_High_Level_Explainer.md
source_format: PDF
conversion_policy: faithful
normative_note: The source PDF controls if conversion layout is ambiguous.
amendments: Owner amendments of 2026-09-22 are marked "Amendment" in the text. Where marked, this Markdown governs over the source PDF.
---

# Sovereign Finance (SoFi) Settlement Specification

> **Engineering-source conversion.** Original wording, section numbering, normative labels, code references, and source-page locations are preserved. `Source PDF page` markers provide publication traceability. Stable `SOFI-...` section anchors and Markdown formatting are non-normative. Where a table, equation, or diagram is ambiguous in extracted text, the source PDF controls.

<!-- Source PDF page 1 -->

Objects, predicates, the storage contract and the build order,
with every rule tied to the code that implements it

This document specifies Sovereign Finance (SoFi), the DSM settlement layer for trades against DLVs, completely
enough to build it: vault creation, setup, single vault trades, multihop routes across several vaults as one all or none
operation, and closing a vault. It states every object a trader constructs, every derivation and identity, every predicate
Core evaluates, the contract a storage node follows, how every piece is wired from the app to the resulting state, and
the order in which it is built. Each rule names the code that implements it, or the code that changes so that it holds.
The whole design rests on one idea, explained first under Read this first: a state that breaks a rule cannot be built,
so anything that exists is valid, and nothing outside Core ever checks anything. Storage follows from it. A node holds
bytes and returns them; one node, selected deterministically from the state root, takes the first write, and the value
is final once it is held by that node and two others.


<!-- Source PDF page 5 -->


<!-- spec-section: SOFI-PREAMBLE -->
## Read this first: if it exists, it is valid
Everything in this document rests on one idea. It is the part people find hardest to accept, because every system
they have used works the other way, so it is explained here from the ground up, assuming no knowledge of DSM,
blockchains or cryptography. Read it before anything else. Come back to it whenever something seems to call for a
check, a validator, a server that decides, or a second opinion. None of those exist in this design, and this part explains
why none can be needed.
**Rule — the idea**
A state change that breaks a rule cannot be made. It is not rejected afterwards; it never comes into existence.
Therefore anything that exists is valid, and nothing anywhere else has to check it.

**Rule — storage nodes sign nothing**

A storage node holds no key and signs nothing, ever. The client signs its own transitions, because movement
is unilateral: the sender advances its own state and signs it. Everything else is bound by hashed preimages:
every object is identified by the hash of its exact bytes, and every object names what it depends on by hash. So
every byte a node returns proves itself, and a node’s word adds nothing. No node attests who got there first, and
nothing needs to: the client establishes it, because it signs its state and carries a proof that only a signed state
can give, like a receipt. Attempts that lose are dropped and never become states, so there is nothing to order;
the canonical chain is the only order.

**Do not**
Giving a storage node a key of any kind, including an identity key, a signature, a certificate of what it holds, or
any attestation role; inventing an ordering problem between attempts; or designing any rule that needs to know
which node returned something. If a design seems to need a node’s signature, it is missing a hash or a client
signature: add that instead.

**Why**
A node’s signature would be something to trust, and the node would become an authority. DSM needs neither.
The client’s signature says who made a transition; the hashes say what it contains and what it extends.


### What it accomplishes
Most systems that move value work by inspection. Someone makes a change, and then someone else (a bank, a
clearing house, a network of miners or validators) looks at it and decides whether it stands. Safety depends on the
inspector being honest, online and correct, and on everyone agreeing with the inspector.
DSM moves the rules into the construction itself. That accomplishes the following.
1. Invalid states cannot exist. A change that breaks a rule cannot be built, so there is never an invalid state to
catch, reject or roll back.
2. Anything that exists proves itself. Whoever holds the bytes of a state can confirm it is valid by recomputing
it, and gets the same answer as everyone else, without asking anyone.
3. Nobody in the middle decides anything. There are no validators, miners, consensus rounds, ordering services,
trusted servers or approvers. A trade against a vault needs nobody’s permission at the moment it happens.
4. Double spends are excluded by structure. Two attempts to spend the same thing are forced to name the same
derived key, and a history can record that key as spent only once.
5. Infrastructure carries bytes and nothing more. Storage and networks cannot forge, alter, reorder or approve
anything. The worst they can do is fail to deliver, which delays; it never corrupts.
6. It is true for everyone at once. A transition that exists is true for the storage node holding it, for every other
client, and for anyone on the network, because each of them recomputes the same bytes and gets the same answer.
Nobody has to be told it is true.


<!-- Source PDF page 6 -->


7. A fake cannot be made. Something presented as a transition that is not one does not match what everyone
recomputes, so it is not a transition at all. Nobody needs to be watching for it to fail.
8. You know what to expect. Given a state and an operation, the only valid successor is already determined.
Anyone can compute it before it arrives.
9. Every reachable state can be checked. Because nothing outside committed state enters validity, the whole
state space of the protocol can be enumerated and checked by a model checker (Why the whole state space can
be checked, below).
10. Online and offline behave the same. The guarantees come from the bytes, not from the path the bytes travel,
so they hold over a network or however else the bytes are handed across.

### How it is done
Nine building blocks, each simple on its own. Together they make it impossible to build a state that breaks a rule.

1. A state is a sealed page
Every state is a data object written in exactly one way: one canonical byte encoding, so the same content always
produces the same bytes. Each state is identified by its fingerprint, a cryptographic hash of those bytes. A hash has
four properties that matter here. The same bytes always give the same fingerprint. Changing any single bit gives a
completely different fingerprint. Nobody can find two different byte strings with the same fingerprint. Nobody can
work backwards from a fingerprint to bytes that produce it. So a fingerprint names exactly one object, and anyone
can check that a given object is the one named.

2. Each page names the page before it
A new state contains the fingerprint of the state it came from, its parent. Each page therefore seals the one before it,
which sealed the one before that, back to the start. Changing any old page changes its fingerprint, which breaks the
link from every later page. History can only be extended forward; it cannot be edited.

3. The next page is computed, not chosen
The next state is produced by a fixed function of three things: the parent, the operation, and entropy derived from
the parent itself. No clock is read. No randomness comes from outside. Nobody else contributes a choice. Given the
same parent and the same operation, every correct implementation produces the same bytes, down to the last bit.

4. Only the owner can turn the page
Every identity starts at a genesis, and its signing keys are derived from it. A transition is signed by its owner over its
exact bytes. A signature cannot be moved to different bytes, and nobody without the key can produce one. So only
the owner can extend the owner’s own history, and every page shows who extended it.

5. What can be spent is named by the parent
To spend something, a transition must consume that thing’s key. The key is not chosen by whoever is spending; it is
computed from the parent’s committed root and a canonical description of the thing being spent. Two attempts to
spend the same thing from the same parent therefore compute the same key, whether they like it or not. Conflicts
identify themselves.

6. The page remembers what was spent
Every state carries the set of keys already consumed in its history, committed inside its fingerprint. A transition that
consumes a key must show the key absent before and present after. A second attempt to spend the same thing in
that history finds the key already present and cannot be built. The record of what was spent lives in the state itself,
not in any server or ledger outside it.

7. The rules are written down before anyone acts
What is allowed to happen next is committed in the state before anyone acts: policies, guards, the conditions under
which something may be taken. A vault is the plainest example. Its owner stocks it and writes into its state the exact
conditions that unlock it. Anyone may take from it, but only by meeting those conditions inside their own transition.
At that moment there is nothing left to decide: the conditions are either met by the committed bytes or not.


<!-- Source PDF page 7 -->


8. The builder is the rulebook
The code that builds a transition, Core, is not something that runs after the fact to check the rules. It is the rules.
It takes committed state and an operation, evaluates every rule, and produces a successor only if every rule holds.
There is no other way to make a state. What comes out of it is its own proof, because it could not have come out
otherwise.

9. Checking is recomputing
Anyone holding the bytes can recompute every fingerprint, root, key and signature, and evaluate every rule again,
and gets exactly the answer everyone else gets. There is no interpreting and no judging. That is why no party needs
to be trusted to say whether something is valid: anyone can know.

### The exact attributes, object by object
The building blocks above hold only because every object carries the fields that make it impossible to fake, misplace
or orphan. These are the fields, from CORE/sofi/wire/objects.rs, grouped by what they rule out.

| Angle | Fields that carry it | Ruled out |
|---|---|---|
| Authorship | setup, P and F carry `genesis`, `device_id` (through P for F) and `claimant_public_key` inside the body; the signature covers the canonical body in a `SignedSofiObject`; identities are computed over the canonical body, never the envelope, so a second valid envelope over one body is the same object (§14.3) | forgery (EUF-CMA), misattribution, a second version of the same object |
| Lineage | P: `parent_claim_ref`, `position`; trader core: `pre_root = Rp`; every leg: `parent_root`; every vault core: `pre_root`; setup: `claim_ref`, `position` | attaching to another parent or position; replay later |
| Placement | every key is computed from fields the object carries: K(0) from `(v, Rn)` in P’s legs; Kful(q) and Kroot(q) from `(G, DevID, q)` in P and F; `F.attempts` names each `(v, a)`; the vault id itself is `H(Go ∥ DevIDo ∥ pcreate)` | counting at a key the object does not name |
| Uniqueness | consumption keys derived from the parent; one constructor per parent; the same inputs give the same bytes; each Gj is a function of P, one per `(P, E, vault, exact parent, exact shadow)` | alternative witnesses, alternative successors, choice |
| Parts bound together | E commits every leg’s `(v, Rn, ρ)`, cT◦, every cV◦, b◦, Xroute (and H(Γ) with every shadow core for a route); Gj binds `precommit_id`, E, vault, parent, `shadow_core`; F binds `precommit_id`, the complete witness set and the attempts; Cq is computed from F and P | swapping any leg, amount, core, witness or outcome; a claim that does not match its fulfillment |
| Rules bound in | the vault state commits `market_policy`, `fee_policy` and `release_policy` by content address, and the market policy names both tokens by their policy commits; a token’s identity is the hash of its whole policy (Part IX) | trading under other rules, or against another token |
| Self proof | core entries carry all 256 siblings against their pre roots; hop amounts are recomputed from committed reserves and the fee policy; `realize_root` and `void_root` are fixed in P | needing anyone’s word to judge it |
| No free input | entropy from the parent; no clock; no outside randomness; canonical encoding; one tag per object type; checked arithmetic | grinding, malleable encodings, type confusion, tricks with time |


<!-- Source PDF page 8 -->


### What these attributes settle
- No write authorization exists. Authority is inside the signed objects, and derived objects need none. Whoever
carries the bytes does not matter, so nothing about a write needs to be checked by anyone.
- The position cells cannot disagree. Kful (q) holds the signed F and Kroot (q) holds Cq . Because Cq is computed
from F and P , a claim that does not match is not F ’s claim. The only other thing that can exist at q is a second
signed successor of the same parent, which only a device that bypassed its own constructor could make, and it
loses the race like anything else.
- Other values never matter. Only an object that names a key can count there. Bytes that are not such an object
are nothing, and a competing object never counts toward the winner. Members keep what they are given and
never refuse anything.
- No key is ever dead. A key is open until an object that names it reaches its leader; nothing else can close it.
- Nothing unclassifiable can occupy a key. The value written to a vault’s successor key is the exercise (Sec-
tion 17.5): the signed F and all of its evidence, bound together by hashed preimages. It cannot exist unless the
trader exercised, it names its own attempt, and it proves itself from its own bytes. No storage node signs anything;
the client signs, and the hashes bind the rest.

### What it has to be like
The guarantee is a property of the construction, so it holds in code only if the code keeps the construction intact.
**Rule — the conditions**
1. The constructor is the only door. One transition function in Core makes every state. Nothing else creates,
repairs, completes or adjusts a state.
2. Every input comes from committed state and passes through Core. No state is built from roots, keys,
entropy or results that some other layer computed or supplied. No evidence is defaulted or filled in.
3. Everything is deterministic and canonical. One byte encoding per object, domain separated hashes, no
clock, no outside randomness, checked arithmetic.
4. Every module on the path is used, and every piece of evidence is consumed by the constructor
(Part VI).
5. Nothing downstream checks what construction guarantees. Not the SDK, not storage, not the app.

**Do not**
Adding a validity check anywhere outside the constructor. If a check seems necessary somewhere else, there is
a hole in the constructor: a path that can build a state without every rule holding. Find it and close it in Core.
A check downstream hides the hole; it does not close it.

**Why**
One side door, such as a function that installs a root the SDK computed, or a path that runs with evidence it never
fetched, would let a state exist that the rules never produced. From that moment the idea above is false, and
every layer downstream would need its own checks, its own trust and its own authority. The strictness in the
rest of this document (one transition function, traced evidence, no bypass) is what keeps that from happening.


### Why it works
- Validity is produced, not inspected. A state exists only because the constructor built it from committed state
with every rule satisfied, and anyone can confirm that by recomputing. So the question “is this valid?” never
needs someone trusted to answer it.
- Conflicts need no referee. Competing spends of one thing must derive the same key from the same parent, and
a history records that key as spent once. Exclusion comes from the history’s own record, not from a coordinator.
- There is no ordering to hand out. Nothing depends on the clock or on which message arrived first at some
server. What counts is what derives from what. In other systems, ordering is exactly the job that turns infras-
tructure into an authority; here there is no such job.
- Bytes vouch for themselves. Every identity is a fingerprint the reader computes. Whoever carries bytes adds
nothing to them and can take away only their availability.


<!-- Source PDF page 9 -->


In a blockchain, the network checks every change after it is made and agrees on one global order, and validity means
“the network accepted it.” In DSM, validity is a property of how the object was built, order is the chain of parents,
and there is nothing left for a network to accept or refuse.
In SoFi the same holds. A trade is the trader’s own transition, and it can only be built if the vault’s committed
conditions are met. Once built, it is valid. When several valid trades compete for the same vault state, they derive
the same key and at most one is recorded; Part II describes where that happens.

### Why the whole state space can be checked
A model checker such as TLC, the checker for TLA+, explores every state a system can reach from its start states
under its rules, and checks every property in every one of them. That only works when the rules are the whole story:
when the next state depends on nothing but the current state and the operation.
In DSM they are. Nothing outside committed state enters validity: no clock, no arrival order at some server, no
miner’s or validator’s choice of what goes first, no gas price, no arbitrary program. So for any bounded model, every
reachable state of the protocol can be enumerated and every safety property checked in all of them. That is what the
formal models in this repository do (Section 42).
A blockchain cannot be checked this way as a whole. Which transaction lands first is chosen by whoever produces
the block; finality depends on the network’s future; and on a general purpose chain any contract can hold any state.
Those inputs are outside the rules, so the reachable states cannot be enumerated from the rules alone. Parts of such
systems can be modeled; the system as a whole cannot be.

### Therefore
1. Every state is a canonical byte object named by its fingerprint.
2. Every state names its parent, so history is fixed.
3. Every successor is computed by the one constructor from committed parent state, and the constructor produces
nothing unless every rule holds.
4. So a state that breaks a rule cannot exist, and a state that exists is valid: for the storage node, for every other
client, and for anyone on the network.
5. So a fake cannot be made. What is not the real transition does not match what everyone recomputes.
6. So nobody downstream checks anything. Anyone who needs to know recomputes, and gets the same answer.
7. So storage is bytes in, bytes out. It cannot make anything valid or invalid; it can only make bytes available or not.
8. So the whole state space can be checked, because nothing but committed state and fixed rules decides it.
9. So the entire burden sits on the constructor being the only door, and that is why this document is strict about
one transition function, traced evidence and no bypass.
**Rule**
If it exists, it is valid. If it is not valid, it does not exist. The code keeps it that way by keeping the constructor
the only door.


## Part I — Ground rules
<!-- spec-section: SOFI-001 -->
### 1 How to read this document
<!-- spec-section: SOFI-001-1 -->
#### 1.1 Code references
Every code reference points at commit 817123c of https://github.com/deterministicstatemachine/dsm. A ref-
erence has the form path:line. Three roots are abbreviated throughout:


<!-- Source PDF page 10 -->


| Abbreviation | Directory |
|---|---|
| CORE | `dsm_client/deterministic_state_machine/dsm/src` |
| SDK | `dsm_client/deterministic_state_machine/dsm_sdk/src` |
| NODE | `dsm_storage_node/src` |

A line number identifies where a definition starts at that commit. When the code moves, the symbol name is the
stable reference and the line number is a convenience.

<!-- spec-section: SOFI-001-2 -->
#### 1.2 Normative words
MUST and MUST NOT state requirements an implementation cannot relax. MAY states a permission. Nothing in
this document is optional unless it says MAY.

<!-- spec-section: SOFI-001-3 -->
#### 1.3 Boxes

| Box | Meaning |
|---|---|
| Rule | Normative text. An implementation that violates it is wrong. |
| Code | Where the rule lives in the tree, or which lines change so that it holds. |
| Gate | A check that must pass before a step is complete, stated as a command or a test. |
| Why | The reason behind a rule, so that it is not removed by someone who does not see what it protects. |
| Do not | A specific wrong move that looks reasonable. |

<!-- spec-section: SOFI-001-4 -->
#### 1.4 Notation


| Symbol | Meaning |
|---|---|
| `H(tag; x)` | BLAKE3(tag ∥ 0x00 ∥ x), the domain hash of `CORE/crypto/blake3.rs:167` (`dsm_domain_hasher`). Every SoFi tag starts with `DSM/sofi/`; formulas write only the part after that prefix. |
| `x1 ∥ x2` | Concatenation. Every part is either fixed width (32-byte digests, 8-byte integers) or a single canonical encoding, so no length prefixes are added (`CORE/sofi/derive.rs:42`). |
| `u64be(n)`, `u32be(n)` | Big-endian encodings of n in 8 and 4 bytes. |
| `CCB(x)` | The canonical binary encoding of object x under its class number (`CORE/ccb/`). Two distinct well-formed objects never share an encoding. |
| `G`, `DevID` | Genesis digest and device id of an identity. |
| `p`, `q` | Economic positions of a trader; q = p + 1 with checked arithmetic. |
| `v`, `Rn` | A vault id and a DLV state root (the vault’s parent state for the next operation). |
| `S` | The committed storage set of a vault: five member ids, sorted (Section II). |
| `L(K)` | The leader of coordinate K: the one node selected from the state root (Section 7). |
| `E` | The external commitment that binds one whole operation (Section 18). |
| `T◦`, `Vj◦`, `B◦` | The trader core, the DLV core of leg j, and the settlement body. |
| `P`, `Gj`, `F` | Trader precommit, DLV policy fulfillment witness for leg j, trader fulfillment. |
| `Valid`, `Invalid`, `Unavailable` | The three values of a Core predicate (Section 1.5). |


<!-- spec-section: SOFI-001-5 -->
#### 1.5 Three valued predicates
A Core predicate returns Valid, Invalid or Unavailable. Unavailable means the evidence needed to decide is not in
hand; it is never read as Invalid. A conjunction of three valued predicates is:
**Rule**
Any conjunct Invalid gives Invalid. Otherwise any conjunct Unavailable gives Unavailable. Otherwise the con-
junction is Valid.

> **Amendment S3 (owner, 2026-09-22) — Unavailable is not a predicate value.** Core predicates are binary: Valid or Invalid, evaluated only over evidence Core has in hand. Obtaining that evidence, including retrying when it cannot be fetched, belongs to the network layer beneath Core. "Unavailable" is that layer's report that it is still fetching; it never sits beside Valid and Invalid, and nothing is marked Invalid while it is still being retried.
>
> - Core first evaluates every conjunct it can decide from evidence already in hand. If any is Invalid, the conjunction is Invalid and the network layer is never asked for anything. Only an operation that nothing in hand shows to be Invalid goes on to the network layer for the evidence it still needs, and the conjunction is Valid only once every conjunct has been evaluated Valid.
> - The rule above, and the rows of Section 24 that name Unavailable (rungs 4 and 6), are read in that sense: Unavailable there means the network layer is still fetching. It is not a result.
> - Evidence obtained from the network is evaluated like any other and can make the conjunction Invalid. When fetching ends without the evidence, which for a trader position happens only through the challenge rule of `DSM_Storage_Node_Specification.md` §9.1, the position resolves Void (Amendment S1).


<!-- Source PDF page 11 -->


**Code**
Validation is defined at CORE/sofi/conformance.rs:19; the static route check that returns it is route_
validation at CORE/sofi/validation.rs:338.


<!-- spec-section: SOFI-002 -->
### 2 The layer rule
**Rule**
There are no validators. A state transition becomes admissible only by satisfying the complete deterministic
predicate that constructs it. Storage does not establish validity. Storage preserves artifacts that are already
established and enforces only generic, authenticated storage mechanics.

<!-- spec-section: SOFI-002-1 -->
#### 2.1 Who owns what


| Layer | Code | Owns, and never does |
|---|---|---|
| Core SoFi | `CORE/sofi/` | Constructs and validates P, Gj, F and E; computes BindExt; folds T◦ and every Vj◦; produces the exact accepted economic result. Never reads a storage verdict as a truth value. |
| Core state machine | `CORE/core/state_machine/` | Entropy evolution, random walk material, generic transition construction, canonical successor machinery. Never names a SoFi type. |
| SDK adapter | `SDK/sdk/` | Packages a result Core already accepted into Core’s generic transition input. Never validates a second time, never computes a second root, never supplies its own entropy. |
| Storage node | `NODE/` | Holds bytes and returns them. It signs nothing: every object proves itself by its hashed preimages and by the signature of the client that made it. Never checks, interprets or decides anything. |


Core SoFi                            publish bytes
constructs and validates P , Gj , F , E


SDK adapter                                             Storage nodes
packages the accepted result                                   bytes in, bytes out


Core state machine
entropy, walk, successor                 raw reads, attributed


<!-- spec-section: SOFI-002-2 -->
#### 2.2 The storage question
Every addition to the implementation answers one question before it is written: does storage need to know what this
means? If the answer is yes, the addition is in the wrong layer.

<!-- spec-section: SOFI-002-3 -->
#### 2.3 Distinct facts
The following facts are different from each other. Code that treats one as another is wrong.

StorageFinal ≠ StorageReachable ≠ Canonical ≠ Consumed ≠ TraderRealized
StoragePredecessorResolved ≠ Skipped
GenesisStored ≠ GenesisAccepted, Registered ≠ Validated
SemanticValidity ≠ Canonicality ≠ AttemptLiveness ≠ StorageFinality
Precommit ≠ PolicyFulfillment ≠ TraderFulfillment


<!-- Source PDF page 12 -->


| Term | Meaning |
|---|---|
| Trader precommit P | Signed by the trader. Noneconomic: publishing or storing it is never exercise, and abandoning it has no effect. |
| Policy fulfillment Gj | A noneconomic, deterministic witness that the operation fulfills the precommitted policy of one referenced DLV state. It is never consent, approval, acceptance or a lock. It has no issuer. |
| Trader fulfillment F | Signed by the trader. References P and the complete policy fulfillment set. The exercise. |
| FulfillmentRegistered(F) | F is final at its fulfillment coordinate (Section 8). The one irreversible exercise boundary. |
| StorageFinalE(K, E) | An exercise carrying E is final at coordinate K (Section 17.5). A storage fact only: it implies nothing about exercise, conformance or consumption. |
| Consumed | Canonical DLV economic ancestry. |
| Validation | Semantic validity only: Valid, Invalid or Unavailable. |
| Realized, Void, Invalid | The verifier-local result of a trader position (Section 24). There is no fourth result: an attempt that cannot complete its reads fails on the network (Amendment S7). |


<!-- spec-section: SOFI-003 -->
### 3 How value moves
Relationships are bilateral. Movement online is unilateral. A sender advances its own state and delivers the result
to the recipient’s storage nodes; the recipient applies it on its own schedule and does not need to be online when it
is sent. An ordinary token transfer works this way, and so does every DLV operation.
A DLV belongs to its owner. The owner funds it, decides what it holds, and commits in its state the criteria that unlock
it: the market, fee and release policies in the vault state leaf (VaultStateLeaf, CORE/sofi/wire/objects.rs:1224).
It works like a locked lending box its owner stocks and leaves out: anyone may take from it, but only with the key,
and the key is meeting the committed criteria inside one’s own state advancement. Nobody approves anything at
trade time. The owner is not asked, and no other party is consulted.
**Rule**
A trader unlocks a DLV by carrying, in its own transition, the evidence that the vault’s committed criteria are met.
Core checks that evidence deterministically. The trader’s state advances, and the vault’s committed successor
follows from the same operation. No party other than the trader signs.

**Code**
Online delivery to a recipient’s storage nodes: SDK/sdk/b0x_sdk.rs. The recipient applies an incoming transfer
with apply_incoming_transfer_full_state, SDK/sdk/core_sdk.rs:3577.

<!-- spec-section: SOFI-004 -->
### 4 What SoFi settles
SoFi settles five operations, all online. An owner creates a vault and, later, closes it. A trader sets up a relationship
with a vault once, and then trades. A trade is a route: one hop against one vault, or a multihop route through distinct
vaults in which each hop’s output token is the next hop’s input token. A multihop route is one operation with one
external commitment E binding every hop, and it is all or none: either every hop is consumed or none is. Each hop
lands at its own vault’s successor cell under that vault’s own leader, so no vault coordinates with another. Part V
follows every operation from the app to the state it produces.

<!-- spec-section: SOFI-005 -->
### 5 Fault model
<!-- spec-section: SOFI-005-1 -->
#### 5.1 Storage nodes

**Rule**
A storage node may crash and may omit messages. It never equivocates, never alters content it holds, and never
permanently loses stored bytes. A store that falls outside this model fails closed.


<!-- Source PDF page 13 -->


<!-- spec-section: SOFI-005-2 -->
#### 5.2 Traders and other callers
Traders are arbitrary. Any caller may speak raw HTTP to a node, send malformed bytes, relay other people’s objects,
or try to occupy coordinates with useless values. Nothing in the safety argument assumes a well behaved caller.

<!-- spec-section: SOFI-005-3 -->
#### 5.3 Safety and liveness
Safety is deterministic and assumes none of the liveness conditions below. Liveness, meaning that a registered ful-
fillment eventually resolves, assumes all of the following:
1. the evidence needed for validation eventually becomes available;
2. the storage nodes needed for finality are eventually reachable and messages are eventually delivered; in partic-
ular the leader of a coordinate (Section 7) is eventually reachable, because no other node can stand in for it;
3. an enabled, conforming completion write has a fair chance to reach some live attempt coordinate;
4. recursively, the same holds for any predecessor position that has to resolve first.
No liveness is claimed against an adversary who wins every future write forever. If required evidence never appears,
a registered fulfillment MAY stay unresolved forever: every attempt to resolve it fails on the network, and unresolved is
not a result (Amendment S7).

> **Note (2026-09-22).** An unresolved position can now be ended by the challenge rule (Amendment S1; storage spec §9.1). It then resolves Void.

<!-- spec-section: SOFI-005-4 -->
#### 5.4 Boundaries that remain
- An identity can split its own registers (self split).
- A registered route with a leg that cannot be written stays unresolved until that leg’s vault acts.
- A position may stay unresolved after its DLV keys become skippable.
- A fulfillment may resolve Void under contention. Policy fulfillment witnesses do not lock parents, so success
after F is never guaranteed. A guarantee would need a prepare lock, and without a clock or an abort authority
an abandoned prepare blocks forever. The design declines it.

<!-- spec-section: SOFI-005-5 -->
#### 5.5 Checked arithmetic
The position q, the attempt index a and the vault generation use checked arithmetic. Overflow is an error, never a
wrap.


## Part II — The storage contract
This part states everything a storage node does and everything a client does when it writes. A node is bytes in, bytes
out. It does not check whether anything is valid, because anything that exists already is (Read this first). It knows
nothing about SoFi, never computes a leader, never compares values and never decides anything. The writer and
Core do all of that.
**Rule — storage nodes sign nothing**

A node holds no key and signs nothing. The client signs; hashed preimages bind the rest; every byte a node
returns proves itself. No node attests who got there first, and nothing needs to: the client establishes it, because
it signs its state and carries a proof that only a signed state can give, like a receipt. Attempts that lose are dropped
and never become states, so there is nothing to order; the canonical chain is the only order. (Read this first.)


<!-- spec-section: SOFI-006 -->
### 6 The committed set
**Rule**
Every vault commits its storage set in its own state. The set is the sorted list of member ids S = (m1 < m2 <
· · · < m5 ), compared as raw bytes. A member that is offline is still in S. The set is identified by one hash,
storage_set_id, which covers the member ids only, never endpoints. A node knows the member list of every
set it belongs to.

> **Amendment S6 (owner, 2026-09-23) — incarnations in the set identity.** Each member of S is committed as its member id paired with the register incarnation it serves, and storage_set_id covers those pairs, still never endpoints. Members stay sorted and compared by member id alone, so one member cannot appear twice under two incarnations. A member rebuilt under the same id has a new incarnation and is therefore not the committed member: it cannot answer for cells its lost register held. The incarnation may be revisited once members run enrolled appliances that carry this continuity in hardware.


<!-- Source PDF page 14 -->


**Code**
- storage_set_id is a field of the vault state leaf VaultStateLeaf, CORE/sofi/wire/objects.rs:1224, so
every DLV state root Rn commits it.
- The set identity and the rule that endpoints are never hashed: module comment of SDK/sdk/storage_set.
rs.

- Set size: STORAGE_MEMBER_COUNT = 5; members that must hold a value for finality: STORAGE_FINALITY_
COUNT = 3, CORE/sofi/wire/mod.rs:174 and :176.

- The set is pinned per network: vault genesis is accepted only if storage_set_id equals the network’s pinned
set (Section 19.8).

Membership is frozen per vault. Replacing a member is not specified here.

> **Note (2026-09-22).** Member replacement is specified in `DSM_Storage_Node_Specification.md` Part III. Under that draft the committed set never changes: member ids are roles, and only the operator serving a role changes, so the leader of every cell stays fixed.

<!-- spec-section: SOFI-007 -->
### 7 The leader of a cell
A cell is the place at a key K, derived by Core, where competing objects meet (Part III). For every cell, the writer
computes one leader from a seed:
L = FisherYates(s, S)[0].

**Rule**
The writer and Core compute the leader. A storage node never does: it does not know which cells it leads, and
it never compares its value with anyone else’s. Availability, the caller’s identity and node ids never enter a seed,
and an offline member stays in S, so the leader of a cell never depends on who is online.

<!-- spec-section: SOFI-007-1 -->
#### 7.1 The shuffle
The algorithm is the one frozen by vectors in CORE/sofi/fisher_yates.rs (permute at line 67, first_member at line
88).
1. Sort S ascending by raw bytes. A duplicate member id is refused.
2. For i from n − 1 down to 1: draw j uniformly from 0 . . . i and swap positions i and j.

3. A draw for range = i + 1 reads words w = u64be first 8 bytes of H(fy-prf/v1; s ∥ u32be(i) ∥ u32be(ctr)) for
ctr = 0, 1, . . . and accepts the first w ≥ 2^64 mod range, returning w mod range. The rejection makes the draw
unbiased.
4. ctr is 32 bits. Exhausting it is a defined error, never a wrap.
5. The leader is position 0 of the result.

<!-- spec-section: SOFI-007-2 -->
#### 7.2 The two SoFi seeds


| Cells | Seed | Keys |
|---|---|---|
| DLV successor cells of vault v at parent Rn | `sv = H(storage-seed/v4; v ∥ Rn)`, `storage_seed`, `CORE/sofi/derive.rs:230` | K(a) for every attempt a |
| the trader’s position q = p + 1 | s(q), below | Kful(q) and Kroot(q) |

s(q) = H(DSM/economic/position-seed/v1; G ∥ DevID ∥ u64be(q) ∥ Rp ),

s(q) = H(DSM/economic/position-seed/v1; G ∥ DevID ∥ u64be(q) ∥ Rp ),
where Rp is the validated economic root at p, or the genesis root when q is the first position.
**Why**
Both seeds consume a state root, so a writer cannot choose its leader. Ordinary economic claims and SoFi fulfill-
ments race for the same position at the same leader, so one seed serves both. G and DevID are in the position seed
so that devices whose roots coincide, such as empty genesis trees, do not share one node. A verifier computes
the leader from the root it validated, never from a root carried in the value it reads.


<!-- Source PDF page 15 -->


<!-- spec-section: SOFI-008 -->
### 8 Writing a cell

later, carried by anyone

member


member
writer         1. write first             leader
value x for K                          keeps the first value
member

2. same bytes
member
final at K once the leader
and two others hold x

**Rule — the write procedure**

1. Compute K and its leader.
2. Write x to the leader. Like every member, it keeps everything it is given, in the order it arrives. The winner
at K is the first object at the leader that names K; if another one got there first, this writer lost the race.
3. Write the same bytes x to the other members of S.
4. Once the leader and two other members hold x, the value is final at K.
5. Members not reached get x later. Any party MAY carry the bytes to them.

**Rule — finality**


Final(K, x) ⇐⇒ x is the first object naming K at the leader ∧ { m ∈ S \ {leader} : m holds x } ≥ 2.

Core evaluates this from raw reads. No node evaluates it.
Four consequences follow from the rule and the fault model.
1. A value the leader does not hold is never final. The race ends at the leader.
2. At most one value is final at a cell.
3. LeaderHeld(K, y) with y ≠ x, where y is the first object naming K at the leader, already settles that x is never
final at K. A verifier MAY classify the loss from the leader’s cell alone.
4. If the leader is unreachable, the cell waits for it. No other member stands in, because a fallback chosen by who
is reachable would let two writers settle at two different nodes.

> **Amendment S4 (owner, 2026-09-22) — finality is a route chain.** `Final(K, x)` above, and every use of it in this document, is replaced by the rule of `DSM_Storage_Node_Specification.md` §9: `x` is final when its route chain has a valid leader link and two further valid links along the cell's Fisher–Yates route. Write-procedure steps 3 and 4 read accordingly: after the leader, the writer writes `x` to the route's seats in route order, each copy carrying the chain so far, and `x` is final at three links. Consequences 1 to 4 above still hold, with `LeaderHeld(K, y)` meaning that `y` has the valid leader link; it still settles that no other value is final at `K`.
> **Amendment S10 (owner, 2026-09-23) — completion proofs.** Every `Final` a DLV unlock relies on is shown by a completion proof (`DSM_Storage_Node_Specification.md` §9): `FulfillmentRegistered(F)` by the proofs at `K_ful(q)` and `K_root(q)`, and each `StorageFinalE(K(F.a_j), E)` in `ConsumedRoute` by the proof at that successor key. The client keeps the proof of each `Final` it relies on. Core checks each proof against its own reads of the seats, which hold everything the proof is made of; an unlock whose proofs do not check does not unlock. The completion digest is the proof's consistent identity: every verifier of the same proof computes the same digest.

**Rule — members keep what they are given**

No member refuses, replaces or compares anything. A value another member already holds for K can therefore
never keep the winner from being copied there.

**Why**
Finality is synchronization, not agreement. The leader is the first place a writer goes, and the first object there
that names the key is where the race ends; the other members are copies. No node votes, compares or decides.
Bytes that are not an object naming the key count as nothing anywhere, because only objects exist (Read this
first).

<!-- spec-section: SOFI-009 -->
### 9 Who may write
Anyone. There is no write authorization, because every object carries its own authority (Read this first): signed
objects carry their signer’s signature over their exact bytes, and derived objects are recomputed by whoever reads
them. The trader’s two position cells, Kful (q) and Kroot (q), are written together at their leader.


<!-- Source PDF page 16 -->


<!-- spec-section: SOFI-010 -->
### 10 Content addressed objects
Precommits, fulfillments, policy fulfillment witnesses, setup bodies, settlement preimages, vault genesis preimages
and auxiliary evidence are stored as their exact canonical bytes in the immutable store, under the store’s own content
address of those bytes. The reader recomputes that address; the member interprets nothing. Protocol identities such
as PrecommitId are recomputed by Core from the bytes; they are never storage addresses.
**Rule**
Stored(o) holds when three members of S return the exact bytes of o.

**Code**
The immutable store: NODE/api/objects/immutable.rs.

<!-- spec-section: SOFI-011 -->
### 11 Indexes
A protocol object is found by its protocol identity, which is not its storage address. An index maps a locator to the
content addresses appended under it.
**Rule**
Anyone MAY append the content address of an object the member already holds under any locator. Appends
are never removed. A read returns the addresses in append order, paged. The member interprets nothing: Core
fetches each candidate, recomputes its identity, and keeps the one that verifies. A scan that exceeds its budget
is Unavailable, never Invalid.


| Locator | Object |
|---|---|
| PrecommitId | P |
| `preimage_locator(E)` | P(E) |
| `vault_genesis_locator(v)` | the vault genesis preimage |
| `vault_token_locator(t)` | the genesis preimage of each vault whose market pairs token `t` (Amendment S16) |
| `escrow_cell_locator(K)` | the genesis preimage of each escrow vault whose terms derive verdict cell `K` (Amendment S21) |
| `escrow_statement_locator(K, o)` | gathered signatures deciding outcome `o` at verdict cell `K` (Amendment S21) |
| `lineage_epoch_locator(k, id, e)` | the generation hints and checkpoints of epoch `e` of shared lineage `(k, id)` (Amendment S23) |
| `vault_baseline_locator(v, g)` | the owner baselines of vault `v` at generation `g`: each its presentation, `OwnerBaselineAuthV1` and `VaultFrontierV1` (Amendment S24) |
| `history_locator(v, R)` | the history leaf `v ‖ u64be(g) ‖ R` of vault `v` naming root `R`, a candidate generation; it stands only as a proof under an authenticated history root (Amendment S26) |
| ρ | the setup body |
| PolicyFulfillmentIdj | Gj |
| the auxiliary reference | auxiliary evidence candidates |



<!-- spec-section: SOFI-012 -->
### 12 Everything a member does

| Operation | What the member does |
|---|---|
| Put object | Store the bytes under the hash of the bytes. The reader recomputes the hash. |
| Put at a key | Store the bytes a writer sends for a key, after anything already held there. |
| Append to index | Add a content address under a locator. |
| Get | Return everything held at the key, in the order it arrived, or that it holds none. The member signs nothing; what it returns proves itself. |

A member never checks, decodes, compares, derives or decides anything.

A member never checks, decodes, compares, derives or decides anything. It is bytes in, bytes out.

<!-- spec-section: SOFI-013 -->
### 13 How Core reads storage
Core turns raw member reads into three storage facts and uses nothing else from storage. A member signs nothing;
Core relies only on what the bytes prove, their hashed preimages and the signatures of the clients that made them.

Storage fact                           Meaning
LeaderHeld(K, x)                       x is the first object naming K in the leader’s read
Final(K, x)                            the finality rule holds for x


<!-- Source PDF page 17 -->


Storage fact                            Meaning
Stored(o)                               three members return the exact bytes of o


Core derives the SoFi facts from them:

SoFi fact                               Derived as
FulfillmentRegistered(F )               Final(Kful (q), F ) and Final(Kroot (q), Cq )
EconomicRootRegistered(q, C)            Final(Kroot (q), C)
SetupRegistered(σ)                      Stored of the setup body
StorageFinalE(K, E)                     Final(K, X) for an exercise X whose P carries E (Section 17.5)


## Part III — Objects and derivations
<!-- spec-section: SOFI-014 -->
### 14 Registries
<!-- spec-section: SOFI-014-1 -->
#### 14.1 Domain tags
Every tag below is a constant in CORE/common/domain_tags/dsm/misc/sofi.rs. The string is exact; formulas in this
document drop the DSM/sofi/ prefix.

Constant                                      String                                    Used for

TAG_DSM_SOFI_REL_KEY                          DSM/sofi/rel-key/v1                       kT,v
TAG_DSM_SOFI_SETUP_ID                         DSM/sofi/setup-id/v1                      σ
TAG_DSM_SOFI_REL_GENESIS                      DSM/sofi/rel-genesis/v1                   h0
TAG_DSM_SOFI_REL_LEAF                         DSM/sofi/rel-leaf/v1                      hj+1
TAG_DSM_SOFI_REL_INDEX                        DSM/sofi/rel-index/v1                     relationship index key
TAG_DSM_SOFI_SETUP_REF                        DSM/sofi/setup-ref/v1                     ρ
TAG_DSM_SOFI_SETUP_SIGN                       DSM/sofi/setup-sign/v1                    msetup
TAG_DSM_SOFI_TRADER_PRECOMMIT_ID              DSM/sofi/trader-precommit-id/v1           PrecommitId
TAG_DSM_SOFI_TRADER_PRECOMMIT_SIGN            DSM/sofi/trader-precommit-sign/v1         mP
TAG_DSM_SOFI_DLV_POLICY_FULFILLMENT           DSM/sofi/dlv-policy-fulfillment/v1        PolicyFulfillmentId
TAG_DSM_SOFI_FULFILLMENT_ID                   DSM/sofi/fulfillment-id/v1                FulfillmentId
TAG_DSM_SOFI_FULFILLMENT_SIGN                 DSM/sofi/fulfillment-sign/v1              mF
TAG_DSM_SOFI_FULFILLMENT                      DSM/sofi/fulfillment/v1                   Kful (q)
TAG_DSM_SOFI_SUCC_CELL_V2                     DSM/sofi/succ-cell/v2                     K (0)
TAG_DSM_SOFI_SUCC_ATTEMPT                     DSM/sofi/succ-attempt/v1                  K (a) , a > 0
TAG_DSM_SOFI_STORAGE_SEED_V4                  DSM/sofi/storage-seed/v4                  sv , the seed of a DLV parent
TAG_DSM_SOFI_FY_PRF                           DSM/sofi/fy-prf/v1                        shuffle draws
TAG_DSM_SOFI_TRADER_CORE_V3                   DSM/sofi/trader-core/v3                   cT ◦
TAG_DSM_SOFI_DLV_CORE_V3                      DSM/sofi/dlv-core/v3                      cV ◦
TAG_DSM_SOFI_SETTLEMENT_CORE_V3               DSM/sofi/settlement-core/v3               b◦
TAG_DSM_SOFI_ATOMIC_EXT_V4                    DSM/sofi/atomic-ext/v4                    E, single leg
TAG_DSM_SOFI_ATOMIC_EXT_MULTIVAULT_V5         DSM/sofi/atomic-ext/multivault/v5         E, two or more legs
TAG_DSM_SOFI_ROUTE_LEG_SET                    DSM/sofi/route-leg-set/v1                 H(Γ)
TAG_DSM_SOFI_ROUTE_DIGEST                     DSM/sofi/route-digest/v1                  Xroute
TAG_DSM_SOFI_PREIMAGE_LOCATOR                 DSM/sofi/preimage-locator/v1              locator of P (E)
TAG_DSM_SOFI_VAULT_ID                         DSM/sofi/vault-id/v1                      v
TAG_DSM_SOFI_VAULT_GENESIS_LOCATOR            DSM/sofi/vault-genesis-locator/v1         locator of vault genesis
TAG_DSM_SOFI_VAULT_TOKEN_LOCATOR              DSM/sofi/vault-token-locator/v1           locator of the vaults of a token (Amendment S16)
TAG_DSM_SOFI_VAULT_CREATION_KEY               DSM/sofi/vault-creation-key/v1            key of the creation leaf
TAG_DSM_SOFI_VAULT_STATE_KEY                  DSM/sofi/vault-state-key/v1               key of the vault state leaf
TAG_DSM_SOFI_VAULT_LEAF_STATE                 DSM/sofi/vault-leaf-state/v1              DLV leaf values
TAG_DSM_SOFI_TRADER_PRE_BALANCE_OBJECT        DSM/sofi/trader-pre-balance-object/v1     address of a TraderPreBalance (Amendment S12)


<!-- Source PDF page 18 -->


Constant                                    String                                    Used for

Reserved, never used for anything else
TAG_DSM_SOFI_MEMBERSHIP_HANDOVER            DSM/sofi/membership-handover/v1           reserved
TAG_DSM_SOFI_TRADE_DIGEST                   DSM/sofi/trade-digest/v1                  reserved
TAG_DSM_SOFI_REF_WINDOW                     DSM/sofi/ref-window/v1                    reserved

Shared tags outside the SoFi prefix
TAG_DSM_TRADER_ECONOMIC_ROOT_REGISTER_KEY   DSM/trader-economic-root-register-        Kroot (q)
key/v1
TAG_DSM_ECONOMIC_POSITION_SEED              DSM/economic/position-seed/v1             s(q), the seed of a trader position
TAG_DSM_ECONOMIC_LEAF_STATE                 DSM/economic-leaf-state/v1                trader relationship leaf value

Retired, never reused
DSM/sofi/route-outcome/v2

Escrow vaults (Amendment S21), constants in CORE/common/domain_tags/dsm/misc/escrow.rs
TAG_DSM_EXTERNAL                            DSM/external/v1                           Y = H(DSM/external/v1 ∥ X) (Explainer §60)
TAG_DSM_ESCROW_TERMS_OBJECT                 DSM/escrow/terms-object/v1                A_T, address of EscrowTerms
TAG_DSM_ESCROW_OUTCOME_TABLE                DSM/escrow/outcome-table/v1               τ
TAG_DSM_ESCROW_VERDICT_CELL                 DSM/escrow/verdict-cell/v1                K_verdict
TAG_DSM_ESCROW_VERDICT_SEED                 DSM/escrow/verdict-seed/v1                s_verdict, the seed of the verdict cell
TAG_DSM_ESCROW_STATEMENT                    DSM/escrow/statement/v1                   m(o)
TAG_DSM_ESCROW_VERDICT_OBJECT               DSM/escrow/verdict-object/v1              address of a gathered EscrowVerdict
TAG_DSM_ESCROW_CELL_LOCATOR                 DSM/escrow/cell-locator/v1                locator of the escrow vaults bound to K_verdict
TAG_DSM_ESCROW_STATEMENT_LOCATOR            DSM/escrow/statement-locator/v1           locator of gathered signatures for (K_verdict, o)

Computed escrow vaults (Amendment S22), constants in CORE/common/domain_tags/dsm/misc/escrow.rs.
TAG_DSM_ESCROW_TERMS_OBJECT also addresses ComputedEscrowTerms, and TAG_DSM_ESCROW_CELL_LOCATOR also locates the vaults bound to K_match.
TAG_DSM_ESCROW_COMPUTED_TABLE               DSM/escrow/computed-table/v1              τ_c
TAG_DSM_ESCROW_COMPUTED_MATCH               DSM/escrow/computed-match/v1              K_match

Shared lineages (Amendment S23), constants in CORE/common/domain_tags/dsm/misc/shared_lineage.rs
TAG_DSM_SHARED_LINEAGE_GENESIS              DSM/shared-lineage/genesis/v1             d_0
TAG_DSM_SHARED_LINEAGE_GENERATION           DSM/shared-lineage/generation/v1          d_g
TAG_DSM_SHARED_LINEAGE_VAULT_STEP           DSM/shared-lineage/vault-step/v1          a vault generation's step_digest
TAG_DSM_SHARED_LINEAGE_CHECKPOINT           DSM/shared-lineage/checkpoint/v1          checkpoint_digest
TAG_DSM_SHARED_LINEAGE_EPOCH_LOCATOR        DSM/shared-lineage/epoch-locator/v1       locator of an epoch's hints and checkpoints
TAG_DSM_SHARED_LINEAGE_OBJECT               DSM/shared-lineage/object/v1              address of a hint, checkpoint or bundle
TAG_DSM_SOFI_ROUTE_LANE                     DSM/sofi/route-lane/v1                    a trader's order over near-equal routes (client policy, §31 note)
TAG_DSM_SOFI_VAULT_FRONTIER                 DSM/sofi/vault-frontier/v1                c_f of a VaultFrontierV1 (Amendment S24)
TAG_DSM_SOFI_VAULT_BASELINE                 DSM/sofi/vault-baseline/v1                c_n of an OwnerBaselineAuthV1, which the owner's anchor signs (Amendment S24)
TAG_DSM_SOFI_VAULT_BASELINE_LOCATOR         DSM/sofi/vault-baseline-locator/v1        locator of a vault's owner baselines at one generation (Amendment S24)
TAG_DSM_SOFI_VAULT_FRONTIER_OBJECT          DSM/sofi/vault-frontier-object/v1         address of a VaultFrontierV1, an OwnerBaselineAuthV1 or a VaultFrontierWitnessV1 (Amendment S24)
TAG_DSM_SOFI_VAULT_HISTORY_LEAF             DSM/sofi/vault-history-leaf/v1            a history leaf's hash, and the namespace of its 72 bytes (Amendment S26)
TAG_DSM_SOFI_VAULT_HISTORY_NODE             DSM/sofi/vault-history-node/v1            a history node's hash, and the namespace of its 64 bytes (Amendment S26)
TAG_DSM_SOFI_VAULT_HISTORY_HEAD             DSM/sofi/vault-history-head/v1            H_n of a VaultHistoryHeadV1, and its namespace (Amendment S26)
TAG_DSM_SOFI_VAULT_HISTORY_LOCATOR          DSM/sofi/vault-history-locator/v1         locator of the history leaf naming a root (Amendment S26)
TAG_DSM_ESCROW_COMPUTED_MATCH_SEED          DSM/escrow/computed-match-seed/v1         s_match, the seed of the match cell
TAG_DSM_ESCROW_COMPUTED_START               DSM/escrow/computed-start/v1              K_start
TAG_DSM_ESCROW_COMPUTED_START_SEED          DSM/escrow/computed-start-seed/v1         s_start, the seed of the start cell
TAG_DSM_ESCROW_COMPUTED_START_STATEMENT     DSM/escrow/computed-start-statement/v1    m_withdraw
TAG_DSM_ESCROW_COMPUTED_READY               DSM/escrow/computed-ready/v1              m_ready, a side's ready statement
TAG_DSM_ESCROW_COMPUTED_SETUP               DSM/escrow/computed-setup/v1              the setup digest
TAG_DSM_ESCROW_COMPUTED_OCCUPANT            DSM/escrow/computed-occupant/v1           a reader's name for the occupant of K_match or K_start
TAG_DSM_ESCROW_TRANSCRIPT                   DSM/escrow/transcript/v1                  h_0
TAG_DSM_ESCROW_TRANSCRIPT_STEP              DSM/escrow/transcript-step/v1             h_i
TAG_DSM_ESCROW_TRANSCRIPT_HEAD              DSM/escrow/transcript-head/v1             m_head(i, h_i)
TAG_DSM_ESCROW_MOVE_COMMIT                  DSM/escrow/move-commit/v1                 a Commit's commitment
The wallet's session-key derivation (§19.10), constant in SDK/sdk/computed_flow.rs.
TAG_SESSION_KEY                             DSM/escrow/session-key/v1                 the HKDF salt of a match session key


<!-- spec-section: SOFI-014-2 -->
#### 14.2 Object classes
Class numbers are constants in CORE/ccb/mod.rs (lines 204 to 290). A class number is never reassigned.

Class            Constant                                      Object
0x0036           SOFI_SETUP_BODY                               setup body
0x0037           SOFI_TRADER_PRECOMMIT_BODY                    P
0x0038           SOFI_DLV_POLICY_FULFILLMENT_BODY              Gj
0x0039           SOFI_TRADER_FULFILLMENT_BODY                  F
0x003A           SOFI_RESOLUTION_CLAIM                         Cq
0x003B           SOFI_PARENT_SINGLE_ROOT_CLAIM                 parent claim reference, single root
0x003C           SOFI_PARENT_CONDITIONAL_CLAIM                 parent claim reference, conditional
0x003D           SOFI_REF_CONTENT_ADDR                         validation reference, content address
0x003E           SOFI_REF_SINGLE_ROOT_CLAIM                    validation reference, single root claim
0x003F           SOFI_REF_CONDITIONAL_CLAIM                    validation reference, conditional claim
0x0040           SOFI_REF_SETUP                                validation reference, setup
pre
0x0041           SOFI_PRE_E_CLOSURE_INDEX                      CE
0x0042           SOFI_POLICY_FULFILLMENT_AUX_REF               auxiliary evidence reference
0x0043     to    burned                                        never assigned to any object
0x0049
0x004A           SOFI_ROUTE_LEG_SET                            Γ
0x004B           SOFI_VAULT_STATE_LEAF                         vault state leaf
0x004C           SOFI_VAULT_RELATIONSHIP_LEAF                  vault side relationship leaf
0x004D           SOFI_TRADER_RELATIONSHIP_LEAF                 trader side relationship leaf
0x004E           SOFI_CORE_ENTRY_MUTATION                      core entry, mutation
0x004F           SOFI_CORE_ENTRY_READ                          core entry, read
0x0050           SOFI_CORE_ENTRY_RELATIONSHIP                  core entry, relationship
0x0051           SOFI_TRADER_CORE                              T◦
0x0052           SOFI_DLV_CORE                                 Vj◦
0x0053           SOFI_SETTLEMENT_SWAP                          B ◦ , Swap branch
0x0054           SOFI_SETTLEMENT_CLOSE                         B ◦ , Close branch
0x0055           SOFI_OWNER_AUTHORITY_ORIGIN                   owner authority, origin owner
0x0056           SOFI_OWNER_AUTHORITY_DSM_SUCCESSOR            owner authority, successor (always refused)
0x0057           SOFI_ROUTE_DIGEST_SWAP                        route digest preimage, Swap
0x0058           SOFI_ROUTE_DIGEST_CLOSE                       route digest preimage, Close
0x0059           SOFI_SETTLEMENT_PREIMAGE                      P (E)
0x005A           SOFI_VAULT_GENESIS_PREIMAGE                   vault genesis preimage
0x005B           SOFI_VAULT_CREATION                           vault creation leaf
0x0061           SOFI_TRADER_PRE_BALANCE                       a trader's balance before the trade (Amendment S12)
0x0063           ESCROW_TERMS                                  an escrow vault's terms (Amendment S21)
0x0064           ESCROW_VERDICT                                a verdict on an external commitment (Amendment S21)
0x0065           SOFI_SETTLEMENT_RELEASE                       B ◦ , Release branch (Amendment S21)
0x0066           SOFI_ROUTE_DIGEST_RELEASE                     route digest preimage, Release (Amendment S21)
0x0067           ESCROW_COMPUTED_TERMS                         a computed escrow vault's terms (Amendment S22)
0x0068           ESCROW_TRANSCRIPT_ENTRY                       one entry of a match transcript (Amendment S22)
0x0069           ESCROW_TRANSCRIPT_OUTCOME                     a transcript occupying a match cell (Amendment S22)
0x006A           ESCROW_EQUIVOCATION_PROOF                     two heads one session key signed at one index (Amendment S22)
0x006B           ESCROW_MATCH_START                            Start (both readies) or Withdraw at a start cell (Amendment S22)
0x006C           SHARED_LINEAGE_GENESIS                        a shared lineage's genesis (Amendment S23)
0x006D           SHARED_LINEAGE_GENERATION                     a shared lineage's generation (Amendment S23)
0x006E           SHARED_LINEAGE_GENERATION_HINT                a generation hint, discovery only (Amendment S23)
0x006F           SHARED_LINEAGE_CHECKPOINT                     a 32-generation checkpoint, discovery only (Amendment S23)
0x0070           SHARED_LINEAGE_TRANSITION_BUNDLE              a segment's read plan, discovery only (Amendment S23)
0x0071           SOFI_VAULT_FRONTIER                           a vault's frontier (vault, generation, root) (Amendment S24)
0x0072           SOFI_VAULT_FRONTIER_WITNESS                   the state leaf and a relationship proof under a frontier root (Amendment S24)
0x0073           SOFI_OWNER_BASELINE_AUTH                      a frontier commitment and the owner-authority position its signer is proven at (Amendment S24)
0x0074           SOFI_VAULT_HISTORY_HEAD                       a vault's history at one generation: its peaks (Amendment S26)


<!-- Source PDF page 19 -->


<!-- spec-section: SOFI-014-3 -->
#### 14.3 Signed objects
A signed SoFi body travels in SignedSofiObject = (body_class, body_ccb, signature_alg, signature), CORE/sofi/
wire/objects.rs:638. Identities are always computed over the canonical body bytes, never over the envelope, so a
second valid signature over the same body is the same object. Signing is deterministic (the SPHINCS+ randomizer is
derived from SK.prf and the message, `dsm_sphincs::sign`), so an honest signer produces one envelope per body. That is
a property of the signer, not something a verifier can check: a second, different envelope verifying for the same body
would be a strong-unforgeability break, which SPHINCS+ is not proved to resist, so no rule may depend on envelope
uniqueness (SPHINCS_SECURITY_CHARTER.md). Whether every cell comparison is by body identity rather than by envelope
bytes is open (MASTER_REQUIREMENTS GPT-11).

<!-- spec-section: SOFI-015 -->
### 15 Derivations
Every function below is in CORE/sofi/derive.rs unless another file is named.

Symbol                  Definition                                                                      Code
v                       H(vault-id/v1; Go ∥ DevIDo ∥ u64be(pcreate ))                                   vault_id :50
vault state key         H(vault-state-key/v1; v)                                                        :63
vault state value       H(vault-leaf-state/v1; CCB(VaultStateLeaf))                                     :68
vault    relationship   H(vault-leaf-state/v1; CCB(VaultRelationshipLeaf))                              :75
value
trader relationship     under DSM/economic-leaf-state/v1 over the trader relationship leaf              :82
value
Xroute                  H(route-digest/v1; CCB(RouteDigestPreimage))                                    :89
vault genesis locator   H(vault-genesis-locator/v1; v)                                                  :94
vault token locator     H(vault-token-locator/v1; t), t a token's policy commit (Amendment S16)          vault_token_locator
vault creation key      H(vault-creation-key/v1; Go ∥ DevIDo ∥ v)                                       :104
kT,v                    H(rel-key/v1; G ∥ DevID ∥ v)                                                    :112
σ                       H(setup-id/v1; G ∥ DevID ∥ u64be(p) ∥ v)                                        :118
h0                      H(rel-genesis/v1; σ)                                                            :126
hj+1                    H(rel-leaf/v1; hj ∥ E)                                                          :131
relationship index      H(rel-index/v1; G ∥ DevID ∥ v)                                                  :136
key
ρ                       H(setup-ref/v1; CCB(SetupBody))                                                 :141
msetup                  H(setup-sign/v1; CCB(SetupBody))                                                :146
ClaimRefp               digest of the exact economic root claim envelope                                :152,            and
CORE/economic/
claim_envelope.
rs:219
PrecommitId             H(trader-precommit-id/v1; CCB(P ))                                              :159
mP                      H(trader-precommit-sign/v1; CCB(P ))                                            :164
PolicyFulfillmentIdj    H(dlv-policy-fulfillment/v1; CCB(Gj ))                                          :169
FulfillmentId           H(fulfillment-id/v1; CCB(F ))                                                   :174
mF                      H(fulfillment-sign/v1; CCB(F ))                                                 :179
s(q)                    H(DSM/economic/position-seed/v1; G ∥ DevID ∥ u64be(q) ∥ Rp )                    step R9
Kful (q)                H(fulfillment/v1; G ∥ DevID ∥ u64be(q))                                         :184
Cq                      (G, DevID, q, FulfillmentId, Rrealize , Rvoid ), class 0x003A                   :193
Kroot (q)               H(DSM/trader-economic-root-register-key/v1; G ∥ DevID ∥                         CORE/economic/
u64be(q))                                                                       register.rs:76
K (0)                   H(succ-cell/v2; v ∥ Rn )                                                        :215
K (a) , a > 0           H(succ-attempt/v1; K (0) ∥ u64be(a))                                            :221
sv (leader seed)        H(storage-seed/v4; v ∥ Rn )                                                     :230
c T ◦ , c V ◦ , b◦      H(trader-core/v3;        CCB(T ◦ )),        H(dlv-core/v3;    CCB(V ◦ )),       :237, :242, :247
◦
H(settlement-core/v3; CCB(B ))
E, single leg           H(atomic-ext/v4; v ∥ Rn ∥ ρ ∥ cT ◦ ∥ cV ◦ ∥ b◦ ∥ Xroute )                       :256
H(Γ)                    H(route-leg-set/v1; CCB(Γ))                                                     :280
E, two or more legs     H(atomic-ext/multivault/v5; cT ◦ ∥ b◦ ∥ Xroute ∥ H(Γ))                          :285
E recomputed            recompute_e over P (E); legs via canonical_legs                                 :389, :325


<!-- Source PDF page 20 -->


Symbol                      Definition                                                                      Code
preimage locator            H(preimage-locator/v1; E)                                                       :424


No attempt index, availability view, routing order, member identity or witness enters E.

The escrow derivations (`A_T`, `τ`, `K_verdict`, `s_verdict`, `m(o)` and the two escrow locators) are defined in §19.9
(Amendment S21). A Release's E takes the single-leg form above, and its verdict is not an input of E.

<!-- spec-section: SOFI-016 -->
### 16 Setup
A trader sets up once per vault before its first operation against that vault.

Field of SofiSetupBody         Symbol               Meaning
genesis                        G                    trader genesis
device_id                      DevID                trader device
position                       p                    the trader’s economic position at setup
vault_id                       v                    the vault
claim_ref                      ClaimRefp            digest of the exact registered claim envelope at p
setup_root                     RTsetup              the trader root the setup inserts
signature_alg,                                      the key that signs msetup
claimant_public_
key


**Code**
Body:  CORE/sofi/wire/objects.rs:121, class 0x0036.     Signature              check:     verify_setup, CORE/sofi/
signature.rs:172. Builder: build_setup, SDK/sdk/sofi_sdk.rs:210.

Equality of setups is equality of ρ. Alternative valid envelopes over one body are the same setup. The setup body is
published as a content addressed object (Section II); Core recomputes ρ from the fetched bytes.
**Rule — two predicates, not one**

SetupValid(setup) is semantic and belongs to Core: canonical body encoding, ρ, the signature over msetup ,
ClaimRef, and the identity and vault relationship rules.

> **Amendment S9 (owner, 2026-09-23) — ClaimRef is checked against the verifier's own lineage.** `SetupValid` compares the setup's `claim_ref` with the digest of the claim this verifier accepted at the setup's position `p` when it validated the trader's lineage: the registered root claim of an ordinary position, or `C_p` of a resolved SoFi position. RouteValidation's evidence carries that accepted claim as a value only lineage validation produces (or the device's own admitted store, for its own positions), so RouteValidation reads no storage for it. A setup naming any other claim is Invalid. Until the accepted claim is in hand, the setup is not evaluated.

> **Amendment S13 (owner, 2026-09-29) — a lineage known invalid makes the setup Invalid.** This supersedes the last sentence of Amendment S9, which let two different states read alike: a lineage whose verdict is not known yet, and a lineage known to be invalid, which can never yield an accepted claim. Under S9's wording the second left its trade holding a vault key forever. `SetupValid` compares the setup's `claim_ref` with the claim accepted at position `p` by validation of the trader's lineage, and there are three cases:
>
> - **Not established.** Lineage validation has not reached a verdict, or evidence it needs is not in hand: `SetupValid` is not evaluated yet, and the verifier waits (Amendment S3).
> - **Valid.** The accepted claim is in hand, and the setup's `claim_ref` must equal its digest. A setup naming any other claim is Invalid.
> - **Invalid.** Lineage validation establishes the trader's lineage Invalid at or before `p`: `SetupValid` is Invalid, so RouteValidation is Invalid. A divergent write-once register cell of the trader, which the walk quarantines, is such a verdict. No accepted claim is required, and none is synthesized: the negative fact is the lineage verdict itself.
>
> No trade whose trader's lineage is known invalid can occupy a vault key indefinitely because that lineage can never yield an accepted claim.
SetupRegistered(setup) is a durability fact that Core derives from storage reads.
Accept(E) requires both. Storage establishes neither.

**Rule — SetupRegistered**

SetupRegistered(σ) ⇐⇒ Stored(the setup body): three members of S return its exact bytes (Section 13).

**Rule — relationship leaf**

On the first relationship gated DLV operation, the operation proves the trader leaf h0 and the DLV side non
inclusion, and both sides become h1 . On every later operation both sides advance hj → H(rel-leaf/v1; hj ∥
E).


<!-- spec-section: SOFI-017 -->
### 17 The operation
A route is one unilateral trader operation with deterministic effects across the one or more DLV states it references. It
is not a set of bilateral transactions. The trader signs P and F and nothing else signs anything. Each Gj has no issuer:
anyone may compute it, and it records that the operation fulfills the policy the referenced DLV state committed to.

exact parent          pre
CE          B◦          E          P         G1 . . . G n          F             Cq
claim

**Rule — hash dependency order**
pre
ExactRegisteredParentClaim → CE     → B ◦ → E → P → G1 . . . Gn → F → Cq . Nothing depends back on
E, and E does not depend on any attempt index.


<!-- Source PDF page 21 -->


<!-- spec-section: SOFI-017-1 -->
#### 17.1 Stage 1: the trader precommit P


Field                      of    Symbol               Meaning
TraderPrecommitBody

genesis, device_id               G, DevID             the trader
position                         p                    the trader position the operation extends
parent_claim_ref                                      SingleRoot{claim_ref} or Conditional{fulfillment_id}
(CORE/sofi/wire/objects.rs:217)
external_commitment              E                    fixes the route, the amounts, the outputs and every successor
core through its preimage
legs                             (vj , Rj , ρj )      canonical list of PrecommitLeg{vault_id, parent_root,
setup_ref}
realize_root                     Rrealize             Root(BindExt(T ◦ , E))
void_root                        Rvoid                T ◦ .pre_economic_root
storage_set_id                                        the committed set S
signature_alg,    claimant_                           the trader key that signs mP
public_key


**Code**
Body: CORE/sofi/wire/objects.rs:278, class 0x0037. Signature check: verify_precommit, CORE/sofi/
signature.rs:215.

P is published as a content addressed object and anyone MAY relay it. P occupies no economic position: it installs
nothing at Kroot , many precommits may exist from one parent, and abandoning one has no effect. Publishing or
storing P is never exercise.
**Rule — P conformance, established by Core before publication**

1. G, DevID and p equal those of T ◦ .
2. ParentClaimRef resolves to the exact registered predecessor claim at p that Core has accepted, and matches
pre
the typed parent reference in CE   . One member’s copy of a register cell is never the source of truth.
3. The parent root. An unresolved conditional position has selected no root and is not a predecessor. Ex-
actly two parents are admissible, and T ◦ .pre_economic_root equals the one root that parent selected: a
SingleRoot parent gives its exact registered root; a resolved conditional parent gives the root its route actu-
ally selected.
4. E recomputes from P (E).
5. The legs equal those derived from P (E) and Γ.
6. Rrealize and Rvoid recompute.
7. storage_set_id equals S.
8. The key binds to the parent claim.

**Do not**
Core MUST NOT construct, sign, publish, fulfill, register or admit a child of an unresolved conditional position.

**Why**
Only the first fulfillment at the leader of Kful (q) counts, and an Invalid position ends the lineage. A child built
on a guessed branch of an unresolved parent therefore ends the device’s economic lineage when the guess is
wrong, and a rival who forces the parent’s branch chooses that outcome.

<!-- spec-section: SOFI-017-2 -->
#### 17.2 Stage 2: policy fulfillment Gj


<!-- Source PDF page 22 -->


Field                        of   Symbol              Meaning
DlvPolicyFulfillmentBody

precommit_id                      PrecommitId         the precommit
external_commitment               E                   the operation
vault_id                          vj                  leg j’s vault
parent_root                       Rj                  the exact DLV parent state P names
shadow_core                       c◦V,j               names the resulting conditional successor; its preimage Vj◦ is
fetched by content address


**Code**
Body: CORE/sofi/wire/objects.rs:428, class 0x0038. The canonical set is derived from P by derive_policy_
fulfillments, CORE/sofi/conformance.rs:67.

The body holds identity fields only. There is exactly one policy fulfillment per (P, E, vault, exact parent, exact shadow),
so PolicyFulfillmentIdj is a deterministic function of leg j of P . Gj means: for exactly this P and E, the operation
fulfills the precommitted policy of the DLV state Rj , and Vj◦ is the conditional successor that policy requires. It is
not a transition and not a lock: Rj stays consumable by other operations.
**Rule — authority of Gj**

Gj has no issuer signature. Its authority comes from deterministic validation against the exact DLV parent
state named by P and the policy that parent committed. Whether that parent is canonical or live belongs to
consumption (Section 23), never to static validation. Hash binding establishes integrity and correspondence; it
is not issuer authentication.

pre
Auxiliary evidence. Proof material never enters PolicyFulfillmentId. Material independent of E lives in CE         . Ma-
terial that depends on E is referenced as PolicyFulfillmentAuxRef = (PolicyFulfillmentId, class, content address),
CORE/sofi/wire/objects.rs:944. Several candidate objects may exist for one (PolicyFulfillmentId, class); each is
stored by its content address, and there is no single slot per (PolicyFulfillmentId, class) that someone could fill first
with junk. Core accepts whichever candidate verifies.
**Rule — what candidates decide**
1. A verifying candidate establishes that one validity step holds.
2. No candidate, or only nonverifying candidates, gives Unavailable, never Invalid.
3. Only a class with one uniquely derived canonical encoding can establish a negative result, because only then
is there exactly one candidate.
4. A per class candidate budget (MAX_POLICY_FULFILLMENT_AUX_CANDIDATES) and a local budget on bytes,
memory and verification work bound hostile input. Both are computational, never semantic: exhausting
either gives Unavailable, never Invalid.
5. Nonverifying candidates never count toward the normative fetch bound MAX_VALIDATION_FETCH_BYTES;
only verifying objects used by the validation do.

<!-- spec-section: SOFI-017-3 -->
#### 17.3 Stage 3: the trader fulfillment F


Field                        of   Symbol              Meaning
TraderFulfillmentBody

precommit_id                      PrecommitId         the precommit exercised
policy_fulfillment_set                                canonical list of PolicyFulfillmentIdj for every leg
attempts                          (vj , aj )          canonical list of AttemptEntry{vault_id, attempt}, fixed at
exercise time against keys live then
position                          q                   P.p + 1


<!-- Source PDF page 23 -->


Field                          of     Symbol              Meaning
TraderFulfillmentBody

signature_alg,         claimant_                          the trader key that signs mF
public_key


**Code**
Body: CORE/sofi/wire/objects.rs:473, class 0x0039. Signature check: verify_fulfillment, CORE/
sofi/signature.rs:192. Conformance against P : check_fulfillment_against_precommit, CORE/sofi/
conformance.rs:100.

F restates no field of P , so there is no second place for the two to disagree.

<!-- spec-section: SOFI-017-4 -->
#### 17.4 Fulfillment ingress

**Rule**
Any     caller       MAY    relay    F.           The       writer   putsF    at Kful (q) and Cq              =
SofiResolutionClaim(G, DevID, q, FulfillmentId, P.Rrealize , P.Rvoid )    at Kroot (q) in one local transaction
at the leader of s(q), both or neither, then puts the same bytes on the other members. The member stores bytes;
it establishes nothing about the conformance of F or the route, and nothing about it has to be established
anywhere but Core. Kful (q) holds the signed envelope of F and Kroot (q) holds CCB(Cq ). Because Cq is
computed from F and P , no claim that disagrees with F can be F ’s claim.

**Code**
Cq is SofiResolutionClaim, CORE/sofi/wire/objects.rs:580, class 0x003A.

> **Amendment S20 (owner, 2026-10-01) — the position pair proves its own authority.** This applies DSM Amendment A10 to the position pair. The ruling, from the 2026-10-01 security pre-audit: "If an object can win/occupy a root position, the object itself proves authority for that position." Before it, anyone could write an unsigned `C_q`, or an `F` under its own key, at another trader's `K_root(q)` and `K_ful(q)`, and take or wedge that position.
>
> - **`C_q` is signed by the trader.** `K_root(q)` holds the trader-signed `C_q`, class `0x0062` (`SignedSofiResolutionClaim`), never a bare `CCB(C_q)`. It carries the six fields of `C_q`, then `signature_alg`, the claimant key, the trader device's `AttA`, and a signature over `H(DSM/sofi/resolution-claim-sign/v1 ‖ CCB(C_q) ‖ u16be(alg) ‖ u32be(|key|) ‖ key ‖ AttA)`.
>   - It occupies the cell only when that signature verifies and `derive_devid(key, AttA)` is the trader's `DevID`. A bare `C_q` is refused by name.
>   - `C_q` is still computed from `P` and `F`. The cell's claim is identified by the entry digest of the body, the pair is matched by the body's `fulfillment_id`, and the body is compared with `derive(P, F)` wherever `P` is in hand (below; §19.6, §36).
> - **`F` carries the trader device's `AttA`**, after its key. `F` names `K_ful(q)` only when `derive_devid(F.key, F.AttA)` is the trader's `DevID`. That is decided from `F`'s bytes alone (below), so a foreign-key `F` neither holds the cell nor makes a reader wait on a `P` it names. With `F.key = P.key` (P conformance 8), it binds `P`'s key too.
> - **The exercise carries the trader's signed `C_q`.** Recognition requires that its body is the `C_q` of the exercise's `P` and `F`, under the same bound key, and that `derive_devid(F.key, F.AttA)` is `P`'s `DevID`. Anything that can hold a vault key therefore carries everything needed to register its own `F`.
> - **A relayer never authors `C_q`.** "Any caller MAY relay F" (above) stands, but the relayer carries the trader's signed `C_q` from the exercise, or from the cell, exactly as signed. It does not recompute it.
> - **Relaying a withheld pair (owner, 2026-10-01).** Pre-audit 12e. Choosing which device relays a pair whose trader withheld it, the owner ruled "Next trader": "If a vault key is held by an exercise whose pair is not yet registered, the relayer MUST use the signed C_q carried by that exercise to register the trader's missing pair before advancing past that held key. The relayer does not author or modify C_q. It only republishes the exact trader-signed bytes already committed in the exercise. After successful pair registration, the relayer retries progression. If the embedded signed C_q is missing, malformed, does not match the exercise, or fails trader/device binding, fail closed for that exercise." So the next operation at a vault, a trade, a route or a close, registers such a pair from the exercise before its walk goes past the key, and walks again. An exercise whose `C_q` fails recognition is no exercise at the key (§17.5). A pair already registered or lost is not written.
> - **`K_ful(q)` is decided from `F`'s bytes alone.** An object names `K_ful(q)` when it is a fulfillment envelope that recognizes under its own key (R8), its position is `q`, and `derive_devid(F.key, F.AttA)` is the trader's `DevID`. `P` is never read to decide it. `F` carries no genesis: the cell's key is derived from `(G, DevID, q)`, and only the holder of `DevID`'s key can write an `F` that passes, so whatever holds the trader's `K_ful(q)` is the trader's own act. Before this, a reader passed over an `F` whose `P` it did not hold yet. A trader could write `F_a`, naming a `P_a` it had not published, ahead of the `F_b` it traded with: a verifier reading before `P_a` appeared saw `F_b` registered and the trade realized, and one reading after saw `F_a` holding the cell and `F_b` neither registered nor lost.
> - **Registration is matched by `F`'s id.** `FulfillmentRegistered(F)` holds when `K_ful(q)` is final on `F` and `K_root(q)` is final on a trader-signed `C_q` whose `fulfillment_id` is `FulfillmentId(F)`. The pair is matched from the two cells' bytes, so registration is the same for every verifier at every time.
> - **Lost.** `F` is lost at `q` when another `F` holds `K_ful(q)`'s leader link in any state, leader-held, preserved or final (§23.1: once the leader keeps a value, no other value is final at that cell), or when `K_root(q)`'s leader link is held by a claim other than one naming `FulfillmentId(F)`, another fulfillment's or an ordinary transition's. A lost `F` is what S14's skip frees: its exception for `F`'s own `C_q`, "whose fulfillment may still be relayed", holds only while no other `F` holds `K_ful(q)`'s leader link.
> - **The body is checked where `P` is in hand.** In an exercise's facts (`P` comes with the exercise) and in a position's resolution (Amendment S15), the `C_q` at `K_root(q)` is compared with `derive(P, F)`. A difference means `K_root(q)` holds a claim that is not `F`'s `C_q`: `F` is lost there, by S14's skip with no Void, and the position resolves Invalid for the trader's lineage. The vault and the lineage therefore agree on the one operation. `P`'s genesis, `DevID` and key are checked against the position and `F` in the same place (conformance). A trader that withholds the `P` its winning `F` names wedges only its own lineage, the same way for every verifier, and the vault keys held by its other fulfillments' exercises are freed by the skip.
>
> This amends this section (`K_root(q)` holds the signed `C_q`, class `0x0062`), "What it accomplishes", the class registries of §14.2 and §15 (the occupant at `K_root(q)` is `0x0062`), §17.5 (the exercise carries the trader's signed `C_q`, after `fulfillment`), §19.6, the crash table of §25, stages 7 and 8 of §31, §33 (the next operation at a vault relays a withheld pair, above), §36, and conditions 4 and 8 of §44: wherever a relayer or another caller "completes the cells", it does so with the trader's signed `C_q`. It also amends §23.6 (the pair is matched by `FulfillmentId(F)` from the two cells' bytes) and Amendment S14's skip (a fulfillment whose `K_ful(q)` another fulfillment holds is lost, as is one whose `C_q` body differs from `derive(P, F)`). Bytes written in the previous format occupy nothing, and nothing written before this amendment carries over (a clean cut).

**Rule — registration**

FulfillmentRegistered(F ) ⇐⇒ Final(Kful (q), F ) ∧ Final(Kroot (q), Cq ). It is a conclusion Core draws from raw
reads. No member computes it and no member writes a registration record. Because the leader of s(q) keeps
one value at Kful (q), at most one fulfillment is registered per position q.

<!-- spec-section: SOFI-017-5 -->
#### 17.5 The exercise
The value written to each successor key of a route is the exercise: one canonical object, class 0x005D (SOFI_EXERCISE,
added in rebuild step R11), that carries everything needed to judge it.

Field                        Content
fulfillment                  the signed envelope of F
precommit                    the signed envelope of P
preimage                     P (E)
witnesses                    every Gj , in leg order
pre
closure                      every object CE     references

**Rule**
At a successor key K = K (a) of vault v at parent Rn , the value that counts is the first exercise at the leader
of K whose F names (v, a) in attempts and whose P names (v, Rn ) in legs. Everything else at K counts as
nothing.

**Why**
An exercise cannot exist unless the trader exercised, because it carries F , which only the trader can sign; every-
thing else in it is bound to F by hashed preimages. It names its own attempt, so it cannot count at another key.
It proves itself from its own bytes and state the reader already holds, so it can always be classified: its route is
realized, or impossible and skipped. A value that names nothing Core can classify cannot occupy a successor
key.

> **Amendment S12 (owner, 2026-09-29) — the exercise carries the trader's balances before the trade.** `T°` states each balance leaf it writes only by the hash of its value, and `TraderSideValid` recomputes the balance after the trade from the balance before it. Only the trader held that value, so no other reader could judge the exercise: once one trader had traded through a vault, the next reader of that vault, its owner closing it included, could not classify the trade (CONFORMANCE §6.39). The exercise now carries those values.
>
> - **The object.** `TraderPreBalance`, class `0x0061`, schema 1: `trader_genesis` (digest32), `trader_device_id` (digest32), `policy_commit` (digest32), `amount` (u64, strictly positive). A zero balance is an absent leaf, and an absent balance needs no object. Its address is `immutable_addr(DSM/sofi/trader-pre-balance-object/v1, CCB bytes)`. `𝒞_E^pre` references it as `ContentAddr{0x0061, addr}`, so `E` commits it, and the exercise carries it with the other closure objects.
> - **Exactly one for each balance the core states.** For every entry of `T°` whose balance before the trade is present, `𝒞_E^pre` names exactly one such object. Its `trader_genesis` and `trader_device_id` are `P`'s trader; `balance_key(G, DevID, policy_commit)` is the entry's key; and `H(DSM/economic-leaf-state/v1; CCB(Balance{policy_commit, amount}))` is the value the entry states before the trade. `𝒞_E^pre` names no other object of this class.
> - **A missing number is Invalid.** An entry with no object in `𝒞_E^pre`, an object that disagrees with its entry, and an object that matches no entry are each Invalid, known from the committed bytes alone. An object `𝒞_E^pre` names whose bytes are not in hand, or whose bytes do not re-derive its address, is not evaluated yet (Amendment S3): bytes that do not authenticate prove nothing.
> - **One source for every verifier.** Every verifier, the trader included, reads the trader's balances before the trade from these objects and from nothing else. An entry that states its balance as absent before the trade is absent. A relationship entry's leaf before the trade is the one its `base` names, and the fold against `T°.pre_root` proves it. The rest of `TraderSideValid` is unchanged.
> - **Not authority.** A value counts only because it hashes to the leaf the core states, and the fold proves that leaf against the trader's root. Storage holds the bytes and decides nothing.
> - **What it shows.** Anyone who reads the exercise sees the trader's balance of each token the trade moves, as it stood before the trade. SoFi's objects are public by design; the trader's other balances and history are not in the exercise.


<!-- Source PDF page 24 -->


<!-- spec-section: SOFI-018 -->
### 18 Settlement preimage and E
<!-- spec-section: SOFI-018-1 -->
#### 18.1 The preimage


Object                      Content (code)
P (E)                       SettlementPreimage{settlement, trader_core, dlv_cores},                     CORE/sofi/wire/
objects.rs:2042, class 0x0059, with a strict decoder.
B ◦ , Swap                  token_in, amount_in, token_out, exact_out, hop ordered hops, cT ◦ , the cV ◦ sorted by
pre
vault_id, closure CE (CORE/sofi/wire/objects.rs:1874).
B ◦ , Close                 vault_id, parent_root, setup_ref, owner_authority, reserve_a, reserve_b, cT ◦ , cV ◦ ,
pre
closure CE   .
hop                         SwapHop{vault_id, parent_root, setup_ref, token_in, amount_in, token_out,
amount_out}, CORE/sofi/wire/objects.rs:1741.
pre
CE                          PreEClosureIndex{refs}, CORE/sofi/wire/objects.rs:886, class 0x0041: objects in-
dependent of E only.
validation reference        ContentAddr{object_class, addr}      |     SingleRootClaim{claim_ref}                            |
ConditionalClaim{genesis, device_id, position, fulfillment_id}                                   |
Setup{setup_ref}, CORE/sofi/wire/objects.rs:759.


pre
P and every Gj contain E, so neither can ever appear in CE   . The classes of B ◦ , T ◦ , V ◦ and P (E) are forbidden
pre
inside CE .

<!-- spec-section: SOFI-018-2 -->
#### 18.2 Inputs after E
These are inputs to validation and are never committed by E: P by PrecommitId; the canonical policy fulfillment
set; auxiliary evidence as content addressed PolicyFulfillmentAuxRef candidates; F from Kful (q); and Cq .

<!-- spec-section: SOFI-018-3 -->
#### 18.3 Choosing the form of E

**Rule**
A Swap with one leg and every Close use the single leg form (atomic-ext/v4). A Swap with two or more legs
uses the route form (atomic-ext/multivault/v5). BindExt inserts the external commitment and hj+1 into
the relationship posts.

<!-- spec-section: SOFI-018-4 -->
#### 18.4 Bounds
A known bound violation is Invalid, never Unavailable.

| Bound | Value | Constant in `CORE/sofi/wire/mod.rs` |
|---|---:|---|
| references in a closure | 64 | `MAX_CLOSURE_REFS :211` |
| canonical bytes per object | 256 KiB | `MAX_CLOSURE_OBJECT_BYTES :213` |
| signed envelopes (P, F, parent envelopes) | 16 | `MAX_AUTH_ENVELOPES :215` |
| aggregate unique fetch | 4 MiB | `MAX_VALIDATION_FETCH_BYTES :218` |
| direct provenance fanout per transition | 16 | `MAX_PROVENANCE_FANOUT :221` |
| P(E) | 256 KiB | `MAX_SETTLEMENT_PREIMAGE_BYTES :223` |



<!-- spec-section: SOFI-019 -->
### 19 The DLV data model
<!-- spec-section: SOFI-019-1 -->
#### 19.1 Leaves


<!-- Source PDF page 25 -->


| Leaf | Key, value and fields |
|---|---|
| vault state | Key `H(vault-state-key/v1; v)`. Fields of `VaultStateLeaf` (`CORE/sofi/wire/objects.rs:1224`): `owner_genesis`, `owner_device_id`, `create_position`, `market_policy`, `fee_policy`, `release_policy`, `storage_set_id`, `generation`, `reserve_a`, `reserve_b`, `status`. Active means both reserves positive; Retired means both zero, and Retired is terminal. |
| vault relationship | Key kT,v. Fields of `VaultRelationshipLeaf` (`:1288`): `trader_genesis`, `trader_device_id`, `leaf = hj`. The key material is explicit, so the tree can be rebuilt by replay. |
| trader relationship | In the trader’s economic tree as `EconomicLeafState::Relationship` (`CORE/economic/state.rs:308`); `TraderRelationshipLeaf{vault_id, leaf}` (`:1320`). A setup inserts exactly one, with no prior value and `h0 = H(rel-genesis/v1; σ)`. Only resolution advances it. |

Not stored: vault_id

Not stored: vault_id (derived and checked), a parent root (the generation keeps roots unique), and the owner
authority position. The whole input of a trade, fee included, stays in reserve_in. There is no add liquidity operation:
an owner closes and creates again.

<!-- spec-section: SOFI-019-2 -->
#### 19.2 Cores and the batch fold
T ◦ (TraderCore{genesis, device_id, position, pre_root, entries}, :1510) and each Vj◦ (DlvCore{vault_
id, pre_root, trader_genesis, trader_device_id, relationship_base, entries}, :1585) list per key entries
against the pre root: Mutation{key, pre, post, path}, Read{key, value, path} or Relationship{genesis,
device_id, vault_id, base, path} (:1357). Every path carries all 256 siblings. One batch fold computes the post
root (batch_fold and verify_batch, CORE/sofi/smt/fold.rs:178 and :197). A single batch is required because
sequential ascending paths (CORE/economic/witness.rs:325) would make any core with a leaf that depends on E
followed by another leaf depend on E throughout.

<!-- spec-section: SOFI-019-3 -->
#### 19.3 Closed write sets
No entry outside these sets is permitted in either branch.

Branch        Entries
Swap          T ◦ : debit token_in, credit token_out, one relationship advance per leg. Each Vj◦ : VaultState Active
to Active with the priced reserves and generation plus one, and one relationship advance.
Close         token_a and token_b come from the referenced vault’s market policy. T ◦ : credit token_a by reserve_
a, credit token_b by reserve_b, the owner vault relationship advance, and no debit. V ◦ : VaultState
Active with exactly the committed reserves to Retired with both reserves zero and generation plus
one, and the matching relationship advance.


<!-- spec-section: SOFI-019-4 -->
#### 19.4 Route digest and leg rules
Xroute hashes a variant discriminated union, RouteDigestPreimage (:1804): Swap{hops} or Close{vault_id,
parent_root, setup_ref, reserve_a, reserve_b}. recompute_e takes the variant from B ◦ ’s own branch, so it
cannot read it any other way.
**Rule**
1. The canonical codec, decoder and recompute_e accept any number of legs from one upward for Swap (two up-
ward for Γ), bounded only by the object byte bound (CANONICAL_MAX_LEGS, CORE/sofi/wire/mod.rs:193).
2. The route cap ROUTE_MAX_LEGS = 2 (:184) is admission and builder policy only (admissible, CORE/sofi/
admission.rs:58, check at :60). It never appears in a canonical constructor or decoder.

3. Vault ids within one route are pairwise distinct: each DLV parent is referenced at most once.

<!-- spec-section: SOFI-019-5 -->
#### 19.5 Static economics
Swap. Per leg, amount_out equals constant_product_output(amount_in, reserve_in, reserve_out, fee_bps)
(CORE/dlv/route_commit.rs:151), with checked reserve updates; hops chain; the intent endpoints match; the Swap
write sets hold; every token, including an intermediate one, passes token policy; per token conservation holds. Any
overflow is static Invalid.


<!-- Source PDF page 26 -->


Close. No constant product pricing applies. The Close write sets hold; VaultState goes from Active to Retired with
exactly the committed reserves, both zero after, generation plus one; trader credits equal reserve_a and reserve_
b; per token conservation holds across the two reductions and the two credits; the release policy is OWNER_LOCAL_
FULL_CLOSE; owner authority holds; token policy holds for both tokens.

**Rule — static validity is not credit**

A static Valid proves pricing, conservation and the legitimacy of the proposed result. It creates no canonical
or spendable credit. Trader output becomes canonical only when the position resolves Realized and advance_
resolved installs P.Rrealize . Void installs the previous validated root and creates no credit. No new credit source
arm exists for SoFi, and a validated peer debit refuses a SoFi position.

<!-- spec-section: SOFI-019-6 -->
#### 19.6 Advancing the lineage
advance_resolved (CORE/sofi/lineage.rs:114) is the only constructor of a validated economic root at q for a SoFi
position. It checks q = P.p + 1 = previous +1; recomputes Cq from P and F and never reads it from a regis-
ter; checks that the claim at Kroot (p) matches P.parent_claim_ref; checks P.Rvoid = T ◦ .pre_root and P.Rrealize =
Fold(T ◦ , E) statically, and T ◦ .pre_root = ValidatedEconomicRoot(p) at advance. Realized installs P.Rrealize , Void
installs the previous root, and Invalid is terminal.

<!-- spec-section: SOFI-019-7 -->
#### 19.7 Close authority
OwnerAuthority (:1676) is Origin or DsmSuccessor{authority_class, authority_addr}. Origin is the only live
branch. A Close is authorized if and only if: P.G equals owner_genesis and P.DevID equals owner_device_id; P
and F are signed under the key proven for that identity at p; that identity holds its own setup and relationship with
the vault; and the release policy is OWNER_LOCAL_FULL_CLOSE. Mnemonic recovery derives the same (G, DevID) and
key, so a recovered owner closes through Origin.
**Rule**
DsmSuccessor decodes and encodes canonically and is always refused by semantic validation as Invalid, never
Unavailable. No builder or producer emits it. vault_id never changes.

<!-- spec-section: SOFI-019-8 -->
#### 19.8 Vault genesis
The owner’s ordinary transition at pcreate debits the funding and inserts VaultCreation{vault_id, genesis_
root, amount_a, amount_b} (:2167), insert only. VaultGenesisPreimage is {owner_genesis, owner_device_id,
create_position, state} (:2124).

**Rule — GenesisAccepted**

All of the following hold: R0 recomputes and V0 holds exactly the initial vault state (generation zero, Active, no
relationship leaves); reserves equal the funded amounts and the debits; v = vault_id(Go , DevIDo , pcreate ) with
pcreate the inserting position; token_a < token_b; the storage set is the network’s pinned set; the owner’s root
at p is validated. Locator writes are attributed to the owner. GenesisStored is only a storage fact.

An owner MAY trade against its own vault; no special case applies, and the fee stays in the reserves.

<!-- spec-section: SOFI-019-9 -->
#### 19.9 Escrow vaults (Amendment S21)

> **Amendment S21 (owner, 2026-10-04 and 2026-10-05) — escrow vaults: a vault released by the canonical verdict on an external commitment.** An application needed two parties to lock equal stakes against one agreed match, with the application as referee deciding who takes both. Owner rulings, 2026-10-04: "The wager should be expressed by composing existing DSM primitives, not by teaching Core what a “PvP wager” or “battle winner” is", "Do not add wager-specific or battle-specific logic to Core", and "You need to make the generic escrow vaults, and then we just use that, but that's one of the primitives we have. We haven't finished yet." 2026-10-05, on two vaults bound to one commitment: "make the verdict for a given external commitment Y a canonical first-commit-wins object. Both linked escrow vaults must settle against that same canonical verdict. Do not rely only on the app host's persisted compare-and-set to prevent the referee from signing conflicting outcomes. The protocol itself should make one Y have one admissible verdict."

An escrow vault is Explainer §59's escrow: a DLV with precommitted branches (§58), each guarded by signatures (§59) over a statement about an external commitment (§60). It is built on the vault machinery of this specification: a vault holds the value, one exercise per generation consumes it (§23), and the payout lands in the recipient's own transition (§19.6). Nothing in it knows what an application's commitment means. No rule for a vault whose terms are a market changes.

**What an escrow vault is**

- An escrow vault holds one amount of one token. It releases that whole amount once, along one of its precommitted branches, to that branch's recipient, when the canonical verdict on its external commitment names that branch's outcome. It has no market, no owner close and no partial release.
- **The slot rule.** `VaultStateLeaf` is unchanged byte for byte. In an escrow vault, `market_policy`, `fee_policy` and `release_policy` all hold `A_T`, the address of the vault's `EscrowTerms` bytes. `reserve_a` is the held amount and `reserve_b` is 0. The vault is Active while `reserve_a > 0` and `reserve_b = 0`. It is Retired when both are zero, and Retired is terminal, as for every vault. A vault's terms are resolved from the bytes its slots address: three slots naming one object of class `0x0063` make an escrow vault. Any other combination that includes such an object is neither a market nor an escrow, and its genesis is refused.

**`EscrowTerms`**, class `0x0063`, schema 1. Its address is `A_T = immutable_addr(DSM/escrow/terms-object/v1, CCB bytes)`.

| Field | Content |
|---|---|
| `token` | digest32: the policy commit of the held token |
| `external_commitment` | digest32: `Y = H(DSM/external/v1 ∥ X)` (Explainer §60). DSM never reads `X`. |
| `branches` | 1 to 16 branches, strictly ascending by `outcome` bytes |

| Branch field | Content |
|---|---|
| `outcome` | 1 to 64 bytes: the label a verdict names |
| `signers` | 1 to 4 signers, strictly ascending: the exact set whose signatures decide this outcome. A signer is `(signature_alg, public_key)`, ordered by `u16be(alg) ∥ u32be(|key|) ∥ key`. |
| `recipient_genesis`, `recipient_device_id` | digest32 each: the identity the branch pays |

- A branch is decided by all of its signers. No duplicate signer, no empty set and no threshold can be expressed. Labels are unique, so a verdict names at most one branch.
- The amount is always the whole held amount. Nothing is chosen at release.
- **The outcome table** `O` is the branches with their recipients removed: the list of `(outcome, signers)` in branch order. Its digest is `τ = H(DSM/escrow/outcome-table/v1; u8(|O|) ∥ ⨁ entries)`, each entry `u32be(|o|) ∥ o ∥ u8(|signers|) ∥ ⨁ (u16be(alg) ∥ u32be(|key|) ∥ key)`. The table is the verdict authority: each outcome's signer set. There is no other authority object. Which vaults share a verdict cell is fixed under "Linked vaults", below.

**The verdict cell: one admissible verdict**

- **The key.** Every escrow vault whose terms name `Y` and whose table hashes to `τ` is bound to one cell, `K_verdict = H(DSM/escrow/verdict-cell/v1; Y ∥ τ)`. Its leader is `FisherYates(s_verdict, S)[0]` (§7) over the network's pinned set, with `s_verdict = H(DSM/escrow/verdict-seed/v1; K_verdict)`, so a reader that knows only the key finds its leader. The cell is written by the procedure of §8 with route-chain finality (Amendment S4), and anyone may write it (§9).
- **The statement.** A signer decides outcome `o` for the cell by signing `m(o) = H(DSM/escrow/statement/v1; K_verdict ∥ u32be(|o|) ∥ o)`. The statement names the cell, so a signature decides nothing anywhere else: not another commitment, and not another table over the same commitment. It names no vault, so one signature serves every vault bound to the cell.
- **`EscrowVerdict`**, class `0x0064`, schema 1: `external_commitment` (`Y`), `table` (`O`, with the bounds of the terms' branches), `outcome` (1 to 64 bytes), and `signatures`: 1 to 4 entries `(signature_alg, public_key, signature)`, strictly ascending by signer. With four SPHINCS+ signatures it is within a cell's value bound (`route_chain::MAX_VALUE_LEN`).
- **What occupies the cell.** The value that counts at `K_verdict` is the first object at its leader that is an `EscrowVerdict` recognized there. Everything else at the cell counts as nothing. A verdict is recognized at `K` when, from its own bytes alone:
  1. `H(DSM/escrow/verdict-cell/v1; Y ∥ τ(table)) = K`;
  2. `outcome` is a label of `table`;
  3. its signers are exactly the signers `table` assigns to `outcome`;
  4. every signature verifies over `m(outcome)` under its key (SPHINCS+, §14.3).

  The verdict proves its own authority for the cell, as Amendment S20 requires of every occupant. No vault, member or reader's position enters the decision.
- **The facts.** `VerdictHeld(K, o)` holds when the cell's leader link is held by a recognized verdict on `o`, in any state: leader-held, preserved or final. `VerdictFinal(K, o)` holds when that verdict is final at `K` (Amendment S4), shown by a completion proof (Amendment S10). By §8, consequences 2 and 3, the cell holds at most one outcome, ever. A second verdict, even one validly signed by the same signers for another outcome, never becomes the cell's value: conflicting adjudications contend for one deterministic key (Explainer §40, §58), and the first at the leader wins.
- **Why the table is in the key.** If the key were `Y` alone, the first object at the cell would have to be judged against signers the cell does not know. Anyone could occupy it first with a verdict signed under keys of its own choosing, and freeze every stake bound to `Y`. With `τ` in the key, only the agreed signers can occupy it. Parties that link vaults agree on `Y` and on the table. A vault with another table is another agreement, with its own cell, and it never touches theirs.
- **The leader.** The parties agree on `Y` and `τ`. A party that proposes `X` can influence which member leads by its choice of `X`. A member never equivocates (§5.1), so that touches liveness only (§5.3, condition 2), never which verdict is canonical.
- **Gathering signatures.** A branch with more than one signer needs each signer's signature. A signer MAY put an `EscrowVerdict` holding the signatures it has as an object, under `immutable_addr(DSM/escrow/verdict-object/v1, CCB bytes)`, and index it under `escrow_statement_locator(K, o) = H(DSM/escrow/statement-locator/v1; K ∥ u32be(|o|) ∥ o)`. A reader keeps each signature that verifies over `m(o)` under a signer the table assigns to `o`, and nothing else. The index carries no authority (§11). Only a recognized verdict at the cell decides anything.

**Linked vaults: same commitment, same table, same cell**

- **One table, one encoding.** The table has exactly one encoding: branches strictly ascending by outcome, each signer set strictly ascending, and every length prefixed. Bytes in any other order do not decode. So parties that agree on the same outcomes, and on the same signer set for each outcome, derive byte-identical tables and the same `τ`.
- **The rule.** Two escrow vaults are linked exactly when their terms name the same `Y` and byte-identical tables. Since the table is the verdict authority, these are also the same authority. Linked vaults have the same `K_verdict`. Conversely, a vault whose `Y` or table differs in any byte is bound to another cell. It is not linked, and a verdict at its cell decides nothing for the others.
- **Linking is derived, never asserted.** Two vaults are linked only when the `K_verdict` derived from each one's accepted terms is the same. A match id, an index entry or an application's word never links them.
- **Checked by whoever relies on it.**
  - A party that locks against a counterpart vault creates its own vault only when the counterpart is GenesisAccepted, Active, and derives the same `K_verdict` as the terms it is about to commit (`escrow.create`, below).
  - A reader that relies on two vaults being linked, such as an application waiting for both stakes before it starts, checks the same derivation on both.
  - Discovery is by cell (`escrow_cell_locator(K)`, under Publication), so a vault bound to another cell is never found among the linked ones.
- **Each genesis stands on its own terms.** Core accepts a vault's genesis without comparing it with any other vault. A creation that named its counterpart would make one vault's acceptance depend on another vault's evidence, and it would protect only the party that can already check before it locks. The party that locks first is protected by what it committed: no verdict at its cell can pay any branch other than its own table's, decided by any signers other than its own table's.

**Creation**

- `EscrowVaultCreate`, variant 38 of `Operation`, carries the vault genesis preimage, the `VaultCreation` leaf and the exact `EscrowTerms` bytes, signed by the owner, as `SofiVaultCreate` carries its market policy (§28). The owner's transition debits the held amount of `terms.token` once and inserts `VaultCreation{vault_id, genesis_root, amount_a, amount_b = 0}`, with `amount_a` the held amount. The record is insert only. The verifier admits exactly one debit and one creation record.
- **GenesisAccepted, escrow form** (§19.8). All of the following hold:
  - `R0` recomputes, and `V0` holds exactly the initial state: generation zero, Active, no relationship leaves;
  - the three policy slots hold `A_T`, and the carried bytes decode as `EscrowTerms` and re-derive `A_T`;
  - `reserve_a` equals the funded amount and the debit, and `reserve_b = 0`;
  - `v = vault_id(Go, DevIDo, pcreate)`, with `pcreate` the inserting position;
  - the storage set is the network's pinned set;
  - the owner's root at `p` is validated;
  - `terms.token` passes its token policy for a transfer (§49).
- **Publication.** The terms are put as an object under `A_T`. The genesis preimage is indexed under `vault_genesis_locator(v)` (§28) and under `escrow_cell_locator(K_verdict) = H(DSM/escrow/cell-locator/v1; K_verdict)`, so a counterparty finds exactly the vaults bound to its own cell. It is not indexed under `vault_token_locator` (Amendment S16), because an escrow vault is not a market. Discovery carries no authority: a candidate counts only when it is GenesisAccepted and its terms derive that `K_verdict`.

**Release**

- **The branch.** `B°` gains a third branch: `Release{vault_id, parent_root, setup_ref, verdict_cell, outcome, amount, trader_core, dlv_core, closure}`, class `0x0065`. It has one leg, and `E` takes its single-leg form (§15). Its route digest preimage is `Release{vault_id, parent_root, setup_ref, verdict_cell, outcome, amount}`, class `0x0066`. The trader is the branch's recipient. A release is the recipient's own position, set up with the vault like any other (§16, Amendment S16), and its credit is the recipient's realized root (§19.6). No verdict enters `E` (§15): `B°` names the outcome and the cell, and the verdict is a fact resolution reads (below).
- **Closed write set** (§19.3). `T°` credits `terms.token` by `amount`, advances the trader's relationship with the vault, and debits nothing. `V°` takes `VaultState` from Active, with exactly `reserve_a = amount` and `reserve_b = 0`, to Retired, with both reserves zero and generation plus one, and makes the matching relationship advance. No other entry is permitted.
- **Static validity** (RouteValidation for a Release, §19.5). Each of the following must hold; a failure of any is Invalid:
  - there is one leg;
  - the vault's terms resolve to `EscrowTerms` by the slot rule;
  - `verdict_cell = K_verdict(terms.external_commitment, τ(terms))`;
  - `outcome` names a branch of the terms;
  - `P`'s trader `(G, DevID)` is that branch's recipient;
  - `amount = reserve_a` and `reserve_b = 0` at the parent;
  - the write set above holds;
  - per-token conservation holds;
  - `terms.token` passes its token policy for a transfer.

  The static budget is at most 16 label comparisons. No signature is verified here; the verdict's signatures are verified where it occupies its cell.
- **Close and Swap need a market.** A Close needs the release policy `OWNER_LOCAL_FULL_CLOSE` (§19.5), and a Swap is priced by the market and fee policies. An escrow vault's slots hold `A_T`, which is neither. So a Close or a Swap against an escrow vault is Invalid, and so is a Release against a market vault. An escrow vault has no owner close: its owner gets the stake back only through a branch that names the owner as recipient, decided by that branch's signers.

**Resolution**

- **The facts** (§13): `VerdictHeld(K, o)` and `VerdictFinal(K, o)`, above.
- **Consumed route** (§23.2): for a Release leg, `ConsumedRoute` also requires `VerdictFinal(B°.verdict_cell, B°.outcome)`.
- **Impossibility** (§23.5): `RouteImpossible(P, E)` gains arm (v): `B°` is a Release, and `VerdictHeld(B°.verdict_cell, o)` for some `o ≠ B°.outcome`.
  - Like arms (ii) to (iv), it needs no validation evidence: only the cell's raw read and the verdict's own bytes.
  - It is permanent, because the cell's leader never holds another value.
  - A release exercise that lost the verdict is skipped, and the vault's next attempt goes live for the branch that won.
- **The ladder** (§24). Rung 7 is Realized through `ConsumedRoute` as amended. Rung 8 (Void, both predicates Valid) also holds when `B°` is a Release whose verdict cell holds another outcome. A Void release moves nothing, and the vault stays Active at its parent. Until the cell's verdict is final on the release's outcome, or held on another, a release has no result (rung 9) and the SDK waits.
- **Linked vaults settle on one outcome.** Every vault bound to `K` settles only on the outcome the cell holds: a release naming another outcome is Void and its key is skipped, whichever vault it is in. The vaults are still independent DLVs with no shared parent (Explainer §60). Each is released by its own recipient's position, and one vault's release does not release the other. What the cell adds is that they cannot release on different outcomes. This refines Explainer §60, whose guards verify predicates bound to `Y`: the canonical verdict is one such predicate, a storage-finality fact keyed by `Y` and the agreed table.
- **Another trader's position** (Amendment S15). The public objects that resolve a Release position include the verdict at its cell, with its finality evidence.

**Liveness, with no clock**

- A stake is released only by a verdict. If no recognized verdict ever reaches the cell, the stake stays locked. That is a stated boundary (§5.4), not a failure.
- An application that wants a way out commits one as a branch: for example a cancel outcome decided by both parties together. It contends for the same cell as every other outcome, so a cancel and a result never both settle.
- A refund after a deadline needs an iteration budget (Explainer §59) and is not part of this amendment.
- A release written before the verdict holds its vault key until the cell holds a verdict, and is then Realized or skipped. Only a branch's recipient can write a release that is not Invalid. Any other release is Invalid, and its key is skipped once final (§23.5). So no third party holds an escrow vault's key past the verdict.

**Routes** (§27). The app reaches escrow vaults only through these routes, in `SDK/handlers/escrow_routes.rs`:

| Route | What it does |
|---|---|
| `escrow.party` | this device's genesis, device id and signing key, for naming in terms |
| `escrow.create` | derives `Y` from `X`, puts the terms and admits `EscrowVaultCreate`. Given a counterpart vault, it locks only once that vault is accepted, Active and bound to the same `K_verdict`. |
| `escrow.sign` | signs `m(o)` for a cell and indexes the signatures under `escrow_statement_locator(K, o)` |
| `escrow.adjudicate` | assembles a recognized verdict from the signatures under the locator and its own, and writes it to `K_verdict` by §8. It returns the verdict the cell holds, which may be another verdict that got there first. |
| `escrow.verdict` | reads `K_verdict` and returns the verdict it holds, or that none is held yet |
| `escrow.release` | builds a release only once the cell's verdict is final on the outcome of a branch that pays this device. It sets up with the vault if needed (Amendment S16), walks the head (§30), drafts the Release, and runs §31 stages 2 to 10. |
| `escrow.locked` | the vaults bound to a verdict cell, read from `escrow_cell_locator(K)`, each accepted, checked to derive `K`, and walked to its head |
| `escrow.vaults` | the escrow vaults this device created, each walked to its head |

This amends §4 (SoFi also creates and releases escrow vaults), §11 (two indexes), §13 (the verdict facts), §14.1 and §14.2 (the escrow tags and classes `0x0063` to `0x0066`), §15, §19.1 (the slot rule and escrow status), §19.3 to §19.5 (the Release branch), §19.7 (an escrow vault has no close authority), §19.8 (the escrow form of GenesisAccepted), §23.2, §23.5 (arm (v)), §24 (rungs 7 and 8), §27 (the escrow routes), §28 (`EscrowVaultCreate`, variant 38 of `Operation`), §32 (a Close against an escrow vault is Invalid) and Amendment S15 (the verdict is among a Release position's public objects).

<!-- spec-section: SOFI-019-10 -->
#### 19.10 Computed escrow vaults (Amendment S22)

> **Amendment S22 (owner, 2026-10-06) — computed escrow vaults: a vault released by what a pinned program computes from a committed transcript.** This applies DSM Amendment A13 to S21's escrow vaults. Under S21 a match's stakes were released by a verdict its referee signed, so the referee decided who was paid. The owner's ruling, 2026-10-06: "the outcome is computed, not decided." The owner ruled the same day: a computed outcome is a generic primitive and no game logic enters Core (S21's ruling stands in spirit); no clock and no deadline enters it; the application relays the players' moves, a residual trust the owner accepted; and whether a match can end level is the program's concern.

A computed escrow vault is an S21 escrow vault whose outcome is computed. Everything §19.9 says of an escrow vault holds for it: one held amount of one token, released whole and once along a precommitted branch by the recipient's own Release position, with no market, no owner close and no partial release. The slot rule, the Release branch, its closed write set and its static budget are §19.9's. Two things differ. The authority is a program and two session keys, not a signer set per outcome. And the release stands on what a match cell computes, not on a verdict cell.

**The kind is the class**

- The three slots of an escrow vault name `A_T = immutable_addr(DSM/escrow/terms-object/v1, CCB bytes)` (§19.9). The class of those bytes decides the kind: `0x0063 EscrowTerms` is a signed escrow vault and `0x0067 ComputedEscrowTerms` a computed one. Bytes of any other class are no escrow terms, and the genesis is refused.
- The signed kind is unchanged byte for byte: its terms, verdict, cell, statement and release are §19.9's.

**`ComputedEscrowTerms`**, class `0x0067`, schema 1.

| Field | Content |
|---|---|
| `token` | digest32: the policy commit of the held token |
| `external_commitment` | digest32: `Y = H(DSM/external/v1 ∥ X)` (Explainer §60). DSM never reads `X`. |
| `table` | the computed table `T_c`, below |
| `branches` | exactly three, in this order: `a-wins`, `b-wins`, `void`. Each is the label (`u32be(|o|) ∥ o`), `recipient_genesis` and `recipient_device_id`. |

| Table field | Content |
|---|---|
| `program` | digest32: `P`, the hash that pins the outcome program |
| `setup_digest` | digest32: `H(DSM/escrow/computed-setup/v1; setup)`, the program's input fixed at lock. DSM never interprets `setup`. |
| `session_a`, `session_b` | `(signature_alg, public_key)` each: side A's and side B's session keys (SPHINCS+, §14.3). The two keys differ. |

- `a-wins` is side A's win, `b-wins` side B's, and `void` is the outcome a Withdraw gives (below). A program may also compute `void`.
- The table's bytes are `P ∥ setup_digest ∥ u16be(alg_a) ∥ u32be(|key_a|) ∥ key_a ∥ u16be(alg_b) ∥ u32be(|key_b|) ∥ key_b`. Its digest is `τ_c = H(DSM/escrow/computed-table/v1; table bytes)`.

**The cells**

- **The match cell.** `K_match = H(DSM/escrow/computed-match/v1; Y ∥ τ_c)`, with seed `s_match = H(DSM/escrow/computed-match-seed/v1; K_match)`. It holds the outcome.
- **The start cell.** `K_start = H(DSM/escrow/computed-start/v1; K_match)`, with seed `s_start = H(DSM/escrow/computed-start-seed/v1; K_start)`. It holds whether the match started.
- Each cell's leader is `FisherYates(s, S)[0]` (§7) over the network's pinned set, and each is written by the procedure of §8 with route-chain finality (Amendment S4). Anyone may write either (§9). A reader names the occupant of either cell by `H(DSM/escrow/computed-occupant/v1; K ∥ u32be(|o|) ∥ o)`, where `o` is the occupant's label (`start` and `withdraw` at the start cell).
- **Linked vaults.** Two computed escrow vaults are linked exactly when their terms name the same `Y` and byte-identical tables; they then have the same `K_match` and `K_start`. The two players' terms differ only in their recipients, which the table does not contain. Linking is derived from each vault's accepted terms, as in §19.9.

**The transcript**

- **An entry.** `TranscriptEntry`, class `0x0068`, schema 1: `index` (`u32be`, from 1), `side` (`u8`: 1 is A, 2 is B) and `kind`, one of:
  - `Commit` (`u8` 1): `commitment`, digest32, `H(DSM/escrow/move-commit/v1; salt ∥ u32be(|move|) ∥ move)`;
  - `Reveal` (`u8` 2): `salt`, digest32, and `move`, 1 to 64 bytes;
  - `Resign` (`u8` 3): nothing.

  An entry carries no signature; the signature over it travels beside it.
- **The head chain.** `h_0 = H(DSM/escrow/transcript/v1; K_match ∥ setup_digest)`, and `h_i = H(DSM/escrow/transcript-step/v1; h_{i−1} ∥ CCB(entry_i))`.
- **The head statement.** A side signs the head of its own entry `i` as `m_head(i, h_i) = H(DSM/escrow/transcript-head/v1; K_match ∥ u32be(i) ∥ h_i)`, under its session key. Since `h_i` commits every entry before it, that signature covers the whole transcript up to `i`.
- **Commit, then reveal.** A move is committed first and revealed later, so a side that moves second in a turn learns nothing of the first move until both are committed.
- **The canonical transcript.** Entries `entry_1 … entry_n` are a canonical transcript for a table and a setup exactly when:
  1. every entry's bytes decode as a `TranscriptEntry` and re-encode to exactly those bytes. An entry that does not round-trip is no entry, and nothing after it counts;
  2. `entry_i` names index `i`, and side 1 or 2;
  3. a `Commit` is made only by a side with no unopened commitment; a `Reveal` opens its side's unopened commitment, and only when it hashes to it; a `Resign` is the last entry;
  4. `H(DSM/escrow/computed-setup/v1; setup)` is the table's `setup_digest`, and `h_0 … h_n` recompute.

  The order of the checks is fixed: decode, re-encode, require byte equality, recompute the chain, then verify signatures.
- **What the program sees.** The opened entries, in order: each `Reveal`, with its side, its own index, the index of the `Commit` it opened and its move; and a `Resign`, with its side and index. An unopened commitment is not shown.

**The program**

- `P(setup, opened)` returns `Done(o)`, `Incomplete`, or a fault. It is deterministic and total over the bounds above. It keeps no state, calls nothing, reads no clock and fetches nothing (Explainer Amendment A13).
- A verifier evaluates `P` only when `P` is registered with it under the hash the table pins. An unregistered `P` leaves every fact of the match cell not established. It is never Invalid, and no other program is tried in its place.
- Core keys its registry by the hash a registered program reports. The binding of code to that hash is the registrar's (owner, 2026-10-06): the SDK registers a program only after the program passes its own frozen conformance vectors, and refuses one that fails them.
- Core does the canonical, chain and signature checks before `P` sees anything. `P`'s answer counts only when `o` is a label of the branches.

**What occupies the match cell**

The value that counts at `K_match` is the first object at its leader that is recognized there. Everything else at the cell counts as nothing. Two kinds of object are recognized, each from its own bytes alone (Amendment S20).

- **`TranscriptOutcome`**, class `0x0069`, schema 1: `external_commitment` (`Y`), `table` (`T_c`), `setup` (1 to 16384 bytes), `entries` (1 to 1024, each `u32be(|entry|) ∥ entry`), and `signatures`: 1 or 2 entries `(side, signature)`, strictly ascending by side. It is recognized at `K` when:
  1. `H(DSM/escrow/computed-match/v1; Y ∥ τ_c(table)) = K`;
  2. the entries are a canonical transcript for the table and the setup;
  3. the sides holding a signature are exactly the sides that made an entry. Each side's signature verifies, under that side's session key, over `m_head(i, h_i)` for the last entry `i` that side made;
  4. the last entry is a `Reveal` or a `Resign`;
  5. `P` is registered, `P(setup, opened)` is `Done(o)` with `o` a label of the branches, and `P` over the opened entries without the last is `Incomplete`.

  Its outcome is `o`. A truncated transcript is never recognized: `P` gives it `Incomplete`. Condition 5 makes the occupant exactly the transcript at the entry that ended the match.
- **`EquivocationProof`**, class `0x006A`, schema 1: `external_commitment` (`Y`), `table` (`T_c`), `side`, `index`, and two `(head, signature)` pairs with the heads strictly ascending. It is recognized at `K` when `Y` and the table derive `K`, and both signatures verify, under the session key of `side`, over `m_head(index, head)` for their own heads. Its outcome is the other side's win: `b-wins` when side A equivocated, `a-wins` when side B did.
  - A side signs one head per index of its own entries, ever. Two different heads signed at one index are proof that the key's holder cheated.
- The first recognized occupant holds the cell for good (§8, consequences 2 and 3), whatever arrives after it.

**The session keys: a wallet obligation**

A session key is the authority of everything its side does in a match: its ready, its Withdraw and every head it signs. Core reads only the public halves the table commits. How a key is made and kept is the wallet's obligation, and every wallet meets it the same way.

- **Derivation.** A wallet derives its session key for a match from its own wallet seed, its own genesis and the match's 32-byte nonce: `k = HKDF(salt = DSM/escrow/session-key/v1 ∥ 0x00; ikm = wallet seed; info = genesis ∥ match_nonce)`, 32 bytes of HKDF over BLAKE3 (RFC 5869, HMAC-BLAKE3). The key pair is the SPHINCS+ key pair (§14.3) whose deterministic key generation takes `k` as its entropy. The nonce is the one the setup carries; the program reads it, and DSM never does.
- **The secret stays in the wallet.** The wallet answers with the public half only. The secret half is derived when it is used, from the seed the wallet holds while unlocked, and is never stored, exported or shown. A locked wallet derives nothing and signs nothing.
- **One key per match.** Two matches with different nonces have different keys, and a key signs only for the match whose setup names it. A wallet locks a stake only when the setup's session key for its side is exactly the one it derives for the setup's nonce.
- **Restoring.** The derivation reads nothing but the seed, the genesis and the nonce, so a wallet restored from its seed derives the same key and can still ready, withdraw, play or settle a match it staked in.

**The start cell: a ready handshake, or a Withdraw** (owner ruling, 2026-10-06)

- **Ready.** A side is ready when its session key signs `m_ready = H(DSM/escrow/computed-ready/v1; K_match)`. Both sides sign the same statement; the key tells them apart.
- **What a wallet checks before it signs its ready.** Its own vault and the opponent's vault are both GenesisAccepted and Active, and both bind to this `K_match`. They hold the same token and the same amount. Each is owned by the side its terms say: the recipient of `a-wins` owns side A's vault, the recipient of `b-wins` owns side B's. The branches mirror: `a-wins` and `b-wins` pay the same identities in both vaults, and each vault's `void` pays its own owner. This is the check side B makes against side A's vault under DSM Amendment A12, made by both sides.
- **`MatchStart`**, class `0x006B`, schema 1: `external_commitment` (`Y`), `table` (`T_c`), `kind` (`u8`) and a body:
  - **Start** (`kind` 1): `ready_a` and `ready_b`, each `u32be(|sig|) ∥ sig`: side A's and side B's signatures over `m_ready`. Whichever side readies second assembles the Start from both signatures and writes it.
  - **Withdraw** (`kind` 2): `side` (`u8`, 1 or 2) and a `signature`, `u32be(|sig|) ∥ sig`, by that side's session key over `m_withdraw = H(DSM/escrow/computed-start-statement/v1; K_start ∥ u8(2))`. Either side may withdraw.
- **Recognition**, from the object's own bytes (Amendment S20). A `MatchStart` is recognized at `K` when `Y` and the table derive `K_start = K` and:
  - for a Start, `ready_a` verifies under `session_a` and `ready_b` under `session_b`, both over `m_ready` for the `K_match` the object derives. A Start holding one side's ready is not a Start;
  - for a Withdraw, its signature verifies under the session key of the side it names, over `m_withdraw`.
- Whichever is first at the start cell's leader holds it for good. The match begins at once and for both sides when a Start holds the start cell. A Withdraw counts only if it reaches the leader before any Start, and a Withdraw that arrives after a Start counts for nothing. No clock is involved.
- **The ready timeout is the application's, outside DSM.** DSM has no clock and no deadline. An application that wants a real-world limit on how long a ready may wait asks the waiting wallet to Withdraw. Nothing in DSM reads the time, and nothing in DSM withdraws on its own.

**The facts** (§13), for a computed escrow vault:

- `VerdictHeld(K_match, void)` holds when a Withdraw holds `K_start`, in any state. `VerdictFinal(K_match, void)` holds when that Withdraw is final there.
- `VerdictHeld(K_match, o)` holds when a Start holds `K_start` and a recognized occupant on `o` holds `K_match`, each in any state. `VerdictFinal(K_match, o)` holds when both are final, each shown by a completion proof (Amendment S10).
- Nothing else holds. Until a Start holds `K_start`, the match cell is not read and counts for nothing. Once a Withdraw holds `K_start`, the match cell never counts.

With these facts, the resolution of §19.9 is unchanged: `ConsumedRoute` (§23.2), arm (v) of `RouteImpossible` (§23.5), and rungs 7 and 8 (§24) read `VerdictHeld` and `VerdictFinal` at `B°.verdict_cell` as they do for a signed escrow vault. Every vault bound to `K_match` settles only on the one outcome those facts give.

**Creation and release**

- **Creation.** `EscrowVaultCreate` (§19.9) carries the exact `ComputedEscrowTerms` bytes in place of `EscrowTerms`. Its debit, record and write set are §19.9's, with `terms.token` the held token.
- **GenesisAccepted** takes §19.9's escrow form, except that the carried bytes decode as `ComputedEscrowTerms` and re-derive `A_T`.
- **Publication.** The genesis preimage is indexed under `vault_genesis_locator(v)` and under `escrow_cell_locator(K_match)`. Discovery by cell finds exactly the vaults linked to it, and carries no authority.
- **Static validity of a Release** against a computed vault is §19.9's, with `verdict_cell = K_match(terms.external_commitment, τ_c(terms.table))` in place of `K_verdict`. The outcome names one of the three branches, and the trader is its recipient.

**Liveness, with no clock**

- A match that is not finished waits. A side that stops playing holds both stakes until it returns. It cannot gain by stopping: a transcript with no end computes no outcome, and the other side's stake stays locked with its own.
- `Resign` is always open to a side that wants out, and its outcome is the program's.
- Before Start holds, either side's Withdraw voids the match and each stake returns to its owner. A side whose opponent never locks, or never readies, withdraws, so neither stake can be held by the other side's silence before the match begins. A wallet signs its ready only after the check above, and signs no entry until Start is final at `K_start`, so no move is ever made in a match that can still be withdrawn.
- **Residual trust (owner, 2026-10-06).** The application relays the moves between the players' wallets. It can delay or withhold a move, which only stalls the match. It cannot forge a move, because every entry is covered by its side's session key.

**Bounds.** At most 1024 entries, a move of at most 64 bytes, a setup of at most 16384 bytes, and two SPHINCS+ signatures. With these bounds, the largest `TranscriptOutcome` fits within a cell's value bound (`route_chain::MAX_VALUE_LEN`), and so does an `EquivocationProof`.

This amends §13 (the verdict facts of a computed vault), §14.1 and §14.2 (the computed escrow tags and classes `0x0067` to `0x006B`), §19.8 (the computed form of GenesisAccepted), and §19.9 (an escrow vault's kind is the class of its terms; a Release against a computed vault names `K_match`).


## Part IV — Predicates and resolution
<!-- spec-section: SOFI-020 -->
### 20 Validation predicates
Two Core predicates decide semantic validity. Both are three valued, and they are evaluated independently.


<!-- Source PDF page 27 -->


<!-- spec-section: SOFI-020-1 -->
#### 20.1 RouteValidation

**Rule — definition**
^
RouteValidation(P, G, E) =       PolicyFulfillmentValid(P, Gj , E)
j

∧ TraderSideValid(P, E) ∧ RouteWideValid(P, E)
under the three valued conjunction of Section 1.5. PolicyFulfillmentValid(P, Gj , E) holds when the exact DLV
parent state Rj named by P , the policy it committed, P , E and the exact proposed shadow satisfy that policy
deterministically. Whether Rj is canonical or live is not checked here.

It covers, for every required leg: SetupValid of that leg’s setup; policy fulfillment; arithmetic and reserves; the exact
effects of the branch (exact constant product output for Swap, exact reserve return and retirement for Close); con-
servation; relationship correspondence; network scope; exact shadows (Vj◦ hashes to the c◦V,j that E commits); the
trader core against the validated parent; the signature on P and its key binding; and the canonicality of the policy
fulfillment witnesses.
**Rule — static**
RouteValidation never depends on attempt indices, storage finality, canonicality, attempt liveness or any out-
come. Missing evidence gives Unavailable. A known bound violation gives Invalid.

**Why**
Setup semantics sit inside this predicate, not only in prose about Accept(E). FulfillmentConformance carries
only the durability half (SetupRegistered); without SetupValid here, setup validity would drop out of the con-
junction that realization depends on. The formal floor names this realized_requires_valid_setup, and re-
moving SetupValid from the predicate must make it fail.

**Code**
route_validation, CORE/sofi/validation.rs:338; validate, :355; Evidence, :228; Refusal, :194.


<!-- spec-section: SOFI-020-2 -->
#### 20.2 FulfillmentConformance

**Rule — definition**
FulfillmentConformance(F ) is Valid when every item below holds, Invalid when any item is known false, and
Unavailable when evidence needed to decide an item is missing:
1. the exact referenced P is available and verifies, and q = P.p + 1 with checked arithmetic;
2. F is signed, and its key equals the key P committed;
3. the policy fulfillment set is complete and canonical: it equals Canon[PolicyFulfillmentIdj (P, j)] over every
leg of P ; a subset, an extra entry or an id not derived from P is malformed;
4. the attempts cover exactly the legs of P , with no numeric holes;
5. for every aj > 0, the earlier attempt K (aj −1) has a permanent storage resolution;
6. SetupRegistered holds for every leg (Section 13);
7. identities and bounds hold;
pre
8. the exact P (E) and CE   are available and verify.

Registration supplies no truth value for this predicate. A registered F injected by an arbitrary caller may be Invalid.
A producer MUST obtain Valid before it publishes F .
**Code**
The structural subset is check_fulfillment_against_precommit, CORE/sofi/conformance.rs:100, with er-
rors at :45.


<!-- Source PDF page 28 -->


<!-- spec-section: SOFI-021 -->
### 21 Exercise and atomicity
**Rule — the exercise boundary**

FulfillmentRegistered(F ) is the exercise. Publishing P is not, and no policy fulfillment witness is. After regis-
tration the trader has no remaining discretion: any caller MAY relay F , publish closure objects and write E into
the successor keys F reserved.

1. No outcome register. Nothing stores a route outcome. Core derives completion or permanent defeat from the
leg reads.
2. Occupancy is not admissibility. A value in a successor cell carries no economic authority by being stored, and
a storage node does not know F and cannot gate on it.
3. All or none. A route is realized only by the all leg predicate of Section 23. If any required leg cannot resolve to
E, the position resolves Void and no DLV leg is consumed by F . F is an irreversible attempt, never a guarantee.
4. No prepare lock. Policy fulfillment witnesses do not lock parents, and success after F is never claimed.

<!-- spec-section: SOFI-021-1 -->
#### 21.1 Registration and realizability are separate
P , G and F are realizable only while the trader parent T0 has not been consumed by an incompatible trader transi-
tion, and while every named DLV parent remains available to E. F ’s own conditional successor Cq does not expire
T0 . A fulfillment MAY register after one of its DLV parents was lost; it can then never be realized.
**Rule — combining the two predicates**

If either predicate is Invalid, the position is Invalid. Only when both are Valid and the route is permanently defeated
is the position Void. No route becomes Void while its conformance is unknown: a predicate is evaluated only over
complete evidence, and an attempt that cannot obtain it within its retry budget fails on the network, which is not a
resolution (Amendment S7).
Registration establishes only that bytes are held at the fulfillment coordinate. It establishes no conformance and
does not require every Rj to be unconsumed. A different registered claim at q makes a later F at q inadmissible,
because the leader of the pair holds one value. Two fulfillments from one T0 compete at the same leader, and at most
one registers. There is no clock anywhere in this.
**Rule — storage facts stay independent**

StorageFinalE(K, E) and FulfillmentRegistered(F ) are independent: a writer can make E final at a successor
key before F is registered. ConsumedRoute requires both, and storage finality never manufactures exercise.


<!-- spec-section: SOFI-022 -->
### 22 The predecessor rule
A child needs an exact selected predecessor root. A conditional predecessor becomes usable only when resolution
has selected exactly one root.

| Predecessor resolution | Selected root | Child |
|---|---|---|
| Realized | P.Rrealize | May be constructed against exactly that root |
| Void | P.Rvoid, the prior validated root | May be constructed against exactly that root |
| Not yet resolved | none yet | none until it resolves |
| Invalid | none, terminal | none |

At most one fulfillment per lineage is unresolved in storage at a time. StorageResolved survives only as an input in-
ternal to Core’s resolution, telling it whether a valid but defeated route is permanently Void. It is never a predecessor
authority and gates no descendant.
**Rule — the local fence**
Core blocks any descendant economic root while a conditional predecessor is unresolved for the verifier.

**Code**
descendant_fence, CORE/sofi/lineage.rs:244; FenceError, :191. The SDK persists fences in SDK/storage/
client_db/trader_parent_fence.rs (place_fence :99, get_fence :186).


<!-- Source PDF page 29 -->


<!-- spec-section: SOFI-023 -->
### 23 Consumption and the walk
<!-- spec-section: SOFI-023-1 -->
#### 23.1 Successor resolution

**Rule**
For a successor key K, Core derives SuccessorResolution(K) from raw reads: Unresolved, or Final(x) when
Final(K, x) holds for an exercise x (Sections 8 and 17.5). No key is ever dead: a key is open until an exercise that
names it reaches its leader. LeaderHeld(K, x) settles early that no other value will be final at K. A cache never
establishes this fact. For a > 0, the key K (a) is usable only once K (a−1) is skipped.

<!-- spec-section: SOFI-023-2 -->
#### 23.2 Consumed route
AttemptLive(v, R, a) ⇐⇒ ∀b < a. Skipped(K (b) )

**Rule — ConsumedRoute**


ConsumedRoute(F, E) ⇐⇒ FulfillmentRegistered(F )
∧ FulfillmentConformance(F ) = Valid
∧ RouteValidation(P, G, E) = Valid
∧ TraderParentCompatible(P )
∧ ⋀j (CanonicalParentj ∧ AttemptLivej(F.aj) ∧ StorageFinalE(K(F.aj), E))

A single vault trade is the case with one leg. Route completion is exactly the conjunction over the legs; there is
no separate outcome.

**Code**
consumed_route, CORE/sofi/resolution.rs:216, over RouteFacts.


<!-- spec-section: SOFI-023-3 -->
#### 23.3 Trader parent compatibility
TraderParentCompatible(P ) holds when T0 is a single root claim, or when T0 = Cp and position p selected exactly
T ◦ .pre_root. TraderParentImpossible(P ) holds when T0 = Cp is terminal and p selected either no root or a root
different from T ◦ .pre_root. Both are objective and monotone. While p is unresolved both are false, so that parent
neither consumes nor skips anything; Core resolves q only once p has resolved (Amendment S7).
**Code**
trader_parent_compatible, CORE/sofi/resolution.rs:188; trader_parent_impossible, :201.


<!-- spec-section: SOFI-023-4 -->
#### 23.4 Routes with more than one leg
Every DLV state P references is a deterministic consequence of one trader operation bound to one E. One final E
cell is evidence associated with the operation, not one executed swap. The whole operation is Realized when every
required leg satisfies the conjunction above. If any required parent becomes permanently incompatible, the opera-
tion can never be realized, and it resolves Void once storage has resolved and RouteValidation is Valid. A stranded E
cell is skipped once route impossibility is established. Nothing rolls back, because that cell was never consumed as
an independent execution.

<!-- spec-section: SOFI-023-5 -->
#### 23.5 Impossibility and skips

**Rule**
FulfillmentImpossible(F, E) ⇐⇒ FulfillmentConformance(F ) = Invalid ∨ RouteImpossible(P (F ), E).
Unavailable is never a ground for impossibility; it waits.

RouteImpossible(P, E) is scoped to P and E only and takes no F , because several candidate fulfillments can refer-
ence one P , E and q before the fulfillment coordinate admits one. It holds when any arm holds:
(i) RouteValidation(P, G, E) = Invalid. Static, monotone and a function of P alone, since the canonical witness set
is derived from P .
(ii) Some parent Rj named in P is permanently orphaned.


<!-- Source PDF page 30 -->


(iii) Some parent Rj named in P is Consumed(X ≠ E). Every realization of P requires Rj consumed by E, and the
walk consumes a parent once.
(iv) TraderParentImpossible(P ).
Arms (ii) to (iv) need no validation evidence, so a stranded DLV cell of an impossible operation is skippable even
while other evidence is Unavailable. Arm (iv) creates no Void: the position becomes Invalid through the predecessor
rung of the ladder, and the arm exists only so that an impossible operation cannot strand a DLV successor key.

Skip                                    Holds when
RejectedFinalSingleLeg(K, F, E)         StorageFinalE(K, E) ∧ CanonicalParent ∧ AttemptLive ∧
FulfillmentImpossible(F, E)
RejectedFinalRoute(Kj , F, E)           StorageFinalE(Kj , E) ∧ FulfillmentImpossible(F, E), where F is
the registered fulfillment whose leg is Kj
Skipped(K)                              RejectedFinalSingleLeg ∨ RejectedFinalRoute

**Code**
route_impossible, CORE/sofi/resolution.rs:253, returning ImpossibleArm from the same file.

> **Amendment S14 (owner, 2026-09-30) — a final cell whose fulfillment can never register is skipped.** One trader's fulfillments for one position can each win a DLV key: the exercise for attempt 0 goes final at `K^(0)` while the fulfillment naming attempt 1 registers at `q`. The fulfillment that `K^(0)`'s exercise carries can then never register, because a different claim at `q` makes it inadmissible (Section 21.1). `K^(0)` holds a final value that no registered fulfillment names, none of the skips above applies to it, and the walk over the DLV parent's attempts would stop there forever.
>
> - **The skip.** `RejectedFinalInadmissible(K, F, E)` holds when `StorageFinalE(K, E)`, the exercise final at `K` carries `F`, and `K_root(q)` for `F`'s position `q` is final on a claim other than `F`'s own `C_q`: another fulfillment's claim, or an ordinary transition. `Skipped(K)` is `RejectedFinalSingleLeg ∨ RejectedFinalRoute ∨ RejectedFinalInadmissible`.
> - **Not an arm of `RouteImpossible`.** Which fulfillment lost the position is a fact about `F`, and `RouteImpossible(P, E)` stays scoped to `P` and `E`, with its four arms.
> - **No validation evidence.** Registration at `q` is a storage fact; the skip needs neither `RouteValidation` nor `FulfillmentConformance`.
> - **No Void and no Invalid.** The skip only frees the DLV key. Position `q` resolves through the claim that holds it, never through `F`.
> - **Permanent.** A position that went to another claim never comes back (PairMutualExclusion), so once the skip holds it holds forever.


> **Amendment S25 (owner, 2026-10-07) — a position's exercise is a function of its public objects.** Phone finding, 2026-10-07: two wallets traded on one vault head and both exercises named the vault's first key there. The faster took it. The slower position's exercise never landed anywhere, and every resolver read "the exercise" back from its first leg's key, where it found the winner's. The loser's own wallet, and every peer resolving the loser's lineage, stood unresolved forever. The loser's next trade named that position as its parent, so every walk of the vault stopped at it. The owner ruled the same day that Void must be provable from public facts, without a shortcut: the ladder ranks `Invalid` above `Void`, so deciding Void without the evidence a full verifier holds would split verdicts, and would let a trader escape a terminal Invalid by losing its key on purpose. This amends §23.5, §24 and Amendment S15.
>
> - **The exercise is determined by public objects.** A position `q`'s exercise is `(F, C_q, P, P(E), W, 𝒞)` where `F` is the fulfillment registered at `K_ful(q)`; `C_q` is the exact bytes final at `K_root(q)`; `P` is the precommit `F` names; `P(E)` is the preimage published under `preimage_locator(E)`; `W` is the canonical witness set derived from `P` and the shadows `P(E)` commits; and `𝒞` is the closure, each object in reference order: a content-addressed object from the store, a setup at `ρ`, and a parent claim — the bytes final at the trader's `K_root(p)`, routed by the root its lineage holds at `p − 1` — checked by its `claim_ref` or fulfillment id as §19.5 checks it.
> - **Rebuilding.** A verifier resolving `q` whose first leg's key holds no exercise carrying `q`'s registered `F` — another exercise holds it, or none yet — rebuilds `q`'s exercise from those objects and establishes the facts over it. The ladder (§24) runs unchanged over the same facts, so its verdict is the one it reaches with the exercise in hand: a lost key is Void when `F` conforms and the route is valid, and Invalid when either fails. An object not yet in hand leaves `q` unresolved; it never decides anything.
> - **One rule for everyone.** The trader resolving its own position and any peer resolving it follow the same rule from the same public objects. What the trader carries is never needed: a position resolvable by its trader is resolvable by anyone.

<!-- spec-section: SOFI-023-6 -->
#### 23.6 The walk
For one DLV parent, the walk visits K (0) , K (1) , . . . in order: a skipped key moves to the next attempt, a consumed key
stops the walk, anything else is unresolved. The walk is budgeted and returns Continue(cursor) when the budget
ends; running it in chunks gives the same result as running it at once.
**Code**
walk, CORE/sofi/resolution.rs:412; classify_attempt, :351.

Dependencies that are structurally earlier are fixed by the constructors: p < q, and P before G before F . A single or
route parent is orphaned once its canonical successor at g + 1 resolves to something else. A producer tuple (v, R, E)
is storage reachable when the objects needed to rebuild it can be fetched; this is required for the legs of P , the legs
of F and every cell.

<!-- spec-section: SOFI-024 -->
### 24 Resolution of a trader position
Resolution is local to the verifier, deterministic, and permanent. The first matching row decides. Core resolves only over
complete facts (Amendment S7): a row whose result is "not a result" names what the SDK must still obtain, and when its
retries are exhausted the attempt fails on the network.

| Step | Result | Condition |
|---:|---|---|
| 0 | not a result (S7) | ¬FulfillmentRegistered(q, F) |
| 1 | not a result (S7) | Defensive: an object supplied from outside names an unresolved conditional predecessor |
| 2 | Invalid | The predecessor is terminal, or selected a root different from P.Rvoid; terminal |
| 3 | Invalid | FulfillmentConformance(F) = Invalid; terminal |
| 3a | Void | A drop claim for this position won under the challenge rule (storage spec §9.1), and RouteValidation(P, G, E) is not Invalid on the evidence in hand (Amendment S5) |
| 4 | not a result (S7) | FulfillmentConformance(F) not yet evaluated |
| 5 | Invalid | RouteValidation(P, G, E) = Invalid; terminal |
| 6 | not a result (S7) | RouteValidation(P, G, E) not yet evaluated |
| 7 | Realized | ConsumedRoute(F, E) |
| 8 | Void | Both predicates Valid and the route is permanently defeated: a reserved key’s leader holds another exercise first, or StorageFinalE(K, X ≠ E); a leg parent is Consumed(X ≠ E); a leg parent is orphaned |
| 9 | not a result (S7) | Otherwise: the facts are not complete |

**Rule**
No shortcut from registration to conformance exists. Rungs 1 and 2 are defensive: a conforming producer never
builds on an unresolved predecessor, so these rungs only classify malformed, historical or externally supplied
objects. For an ordinary single root parent, the parent check is T ◦ .pre_root = ValidatedEconomicRoot(p) at


<!-- Source PDF page 31 -->


advance.
Invalid means the operation never satisfied the rules. Void means a valid operation could not execute. Validity is
established before Void is declared, so no position ever moves from Void to Invalid. A Void position performs zero
mutations. Mutual exclusion holds: FulfillmentRegistered(q) ∧ EconomicRootRegistered(q, C) ⇒ C = Cq .
**Code**
resolve_position, CORE/sofi/resolution.rs:284; effect_of, :92.

> **Amendment S1 (owner, 2026-09-22) — nothing negative is recorded, and Pending can end.** Realized, Void, Invalid and Pending are computed by each verifier from raw reads and are never recorded (DSM Amendment A1). Their job is to tell the next trade against a vault whether the balance ahead of it is settled. A position that stays Pending on one party may be challenged under `DSM_Storage_Node_Specification.md` §9.1: if the challenged party does not answer before the cell's leader has closed X ByteCommits, a drop claim wins at the leader and the position resolves Void. It never executes and moves no balance. The value of X is still open (storage §9.1). (Wording superseded by Amendment S7: Pending is not a result; a position is unresolved, and an attempt to resolve it fails on the network.)

> **Amendment S5 (owner, 2026-09-22) — the drop rung.** Step 3a places a dropped position in the ladder. A position that is shown Invalid on evidence in hand (steps 2 and 3, or RouteValidation) stays Invalid; otherwise a won drop claim resolves it Void: nothing executes, no balance moves, and the trader's lineage continues from the previous root. A dropped position is the one Void declared without both predicates established, and because later evidence for it is ignored (storage spec §9.1), it can never move to Invalid.

> **Amendment S7 (owner, 2026-09-23) — no Pending.** A predicate has two values, Valid and Invalid, and network status is separate (Amendment S3). A trader position resolves Realized, Void or Invalid, and nothing else. Core resolves only over complete facts: F registered at q, both predicates evaluated, every required storage fact final, and the predecessor resolved. Until the facts are complete the SDK keeps reading, relaying and retrying within its budget; when the retries are exhausted the attempt fails on the network. That failure is not a resolution: it is never recorded, never becomes Invalid or Void, and a later attempt may succeed. A position whose evidence never appears stays unresolved, which is a fact about the world, not a result. Wherever this specification says Pending or Unavailable of a position or a predicate, read it this way. Amendments S1 and S5 stand; the challenge rule that ends an unresolved position is outside beta.


> **Amendment S15 (owner, 2026-09-30) — a trader's position resolved from public objects.** A verifier that meets another trader's conditional position `q` (DSM Amendment A8: inside its frontier-to-parent segment of that trader's root chain) derives the root `q` selected from SoFi's public proof-carrying objects for `q` alone: the claim final at `K_root(q)`, the registration pair, `P` and `F`, the exercise read back from the first leg's cell, and the vault cells and canonical chains the facts need, with the finality evidence of each. The ladder runs over the facts Core establishes from them, exactly as for the trader's own position.
>
> - **The result.** The one root `q` selected — `P.realize_root` when Realized, the root authenticated at `q − 1` when Void — or Invalid, or not established yet (Amendment S3).
> - **The claim at `K_root(q)`.** It counts only as the claim `(P, F)` derive: its two roots are the ones the resolution chooses between.
> - **What it reads.** No private object of the trader's, and no position of the trader's outside the verifier's frontier-to-parent segment. Within that segment, resolution may read position `q`, the authenticated predecessor root at `q − 1`, and the accepted claim at each setup position explicitly named by `P`'s legs, each authenticated through DSM Amendment A8. It reads no unrelated trader position and has no fallback lineage walk (owner ruling, 2026-09-30).
> - **SetupValid.** The trader's accepted claim at a setup's position (Amendments S9 and S13) is read by frontier-relative verification of the trader's lineage (DSM Amendment A8), never by replaying the trader's history to genesis; a credit's source on the way is held to account through its own segment to a frontier the verifier holds (DSM Amendment A8, credit sources, 2026-10-01).
> - **Adoption.** Where the trader's own transition requires that a realized position credit only tokens its device adopted before, that is a construction predicate of the trader's own state transition, enforced when the trader installs the realized position. Adoption is not part of frontier-relative resolution of a historical position: a later verifier resolving which root `q` selected does not re-run the trader's adoption check, and this resolution requires no adoption leaf or other private trader state.

<!-- spec-section: SOFI-025 -->
### 25 Crash and recovery

| Durable point | What recovery does | Verifier result |
|---|---|---|
| P signed or stored, witnesses computed, no F | nothing economic; the trader may abandon | nothing |
| F signed, never published | not exercised; the trader may discard it | nothing |
| F held by members, but not by the leader of Kful(q) | not exercised; a different F at the leader wins q | not resolved yet, or F never registers |
| F held by the leader of Kful(q), fewer than two copies | the race at q is settled for F; relayers complete the copies | not resolved yet |
| F registered | irreversible exercise; any party writes E into F’s keys and publishes closure objects | not resolved until both predicates are evaluated |
| a leg lost its parent before E reached it | drive storage resolution | either predicate Invalid: Invalid; evidence not obtained within the retry budget: the attempt fails on the network (S7); both Valid and defeated: Void |
| another exercise is first at a reserved key’s leader | storage resolved; if Void, a new P and F from the predecessor’s selected root | as in the row above |
| every required cell final | Core evaluates the full ConsumedRoute; storage finality alone gives no result | Realized only if the whole conjunction holds |
| evidence missing | retry within the budget | the attempt fails on the network when the retries are exhausted (S7) |

## Part V — The final wiring

## Part V — The final wiring
This part connects every piece. It follows each SoFi operation from the user’s action to the state it produces and
names the function at every step. Every Core SoFi function appears here on a production path; a function this part
does not name is deleted (rule T1, Part VI).

<!-- spec-section: SOFI-026 -->
### 26 The stack
app                        SoFi routes                   SoFi producers            decide            Core SoFi
user action            handlers/sofi_routes.rs              sdk/sofi_sdk.rs                            every decision
ds


write, read                              prepared input
a
re
raw


storage client                          Core transition
storage nodes
leader first,                            one function
bytes, cells, indexes
then the others


<!-- Source PDF page 32 -->


**Rule**
Producers assemble and publish; Core decides. A producer never interprets a storage read, never skips a Core
check, and never advances state except through the Core transition with Core’s result unchanged.


<!-- spec-section: SOFI-027 -->
### 27 Routes
The app reaches SoFi only through these routes in SDK/handlers/sofi_routes.rs.

| Route | Producer | Result |
|---|---|---|
| `sofi.createVault` | `build_vault_create`, `SDK/sdk/sofi_sdk.rs:275` | `Operation::SofiVaultCreate` in the owner’s transition; genesis preimage published |
| `sofi.setup` | `build_setup`, `:210` | `Operation::SofiSetup` in the trader’s transition; setup body published |
| `sofi.findRoute` | Path search over walked vault heads | A hop list; carries no authority |
| `sofi.trade` | `draft_trade`, `:387`, then `build_fulfillment`, `:495` | `Operation::SofiFulfill` |
| `sofi.route` | `draft_route`, `:400`, then `build_fulfillment` | `Operation::SofiFulfill` |
| `sofi.close` | `draft_close`, `:452`, then `build_fulfillment` | `Operation::SofiFulfill` |
| `sofi.relay` | Completion of a registered fulfillment | Copies and hop cells written |
| `sofi.resolve` | Resolution and advance of the device’s pending position | The validated root at q |


The three SoFi operations are variants 34, 35 and 36 of Operation (CORE/types/operations.rs:971, :983, :1015).

<!-- spec-section: SOFI-028 -->
### 28 Creating a vault
1. The owner chooses the pair, the reserves, the market, fee and release policies, and the network’s pinned storage
set.
2. build_vault_create builds the signed SofiVaultCreate, the vault genesis preimage and the VaultCreation
leaf.
3. The owner’s transition carries SofiVaultCreate through the Core transition: verify_operation (CORE/sofi/
signature.rs:232) checks it, the funding is debited and the VaultCreation leaf inserted, and the owner installs
position q with its ordinary claim (Part II).
4. The genesis preimage is put as an object and indexed under vault_genesis_locator(v) (CORE/sofi/derive.rs:
94).

5. Any trader accepts the vault with genesis_accepted (CORE/sofi/lineage.rs:451), which binds the signed op-
eration to the accepted owner transition, and genesis_root (:575), which gives R0 .

<!-- spec-section: SOFI-029 -->
### 29 Setting up with a vault
1. build_setup builds the signed setup body; Core derives ρ with setup_ref (CORE/sofi/derive.rs:141) and the
setup id with setup_id (:118).
2. The setup body is put as an object and indexed under ρ. SetupRegistered holds once it is Stored.
3. The trader’s transition carries SofiSetup: verify_operation checks it, and the relationship leaf h0 from
relationship_leaf_genesis (:126) is inserted at relationship_index_key(G, DevID, v) (:136).


<!-- spec-section: SOFI-030 -->
### 30 Finding the head of a vault
Anyone finds a vault’s current parent the same way, and path search uses nothing else.
1. Fetch the genesis preimage through its index, accept it, and start at R0 .


<!-- Source PDF page 33 -->


2. At parent Rn : compute sv with storage_seed (CORE/sofi/derive.rs:230), its leader with first_
member (CORE/sofi/fisher_yates.rs:88), and read the cells K (a) from successor_attempt_key (:221)
for a = 0, 1, . . . . walk (CORE/sofi/resolution.rs:412) classifies each attempt with classify_attempt (:351).
3. A consumed attempt names its fulfillment; the consumed route’s Vj◦ post root is Rn+1 . A skipped attempt moves
to the next. An unresolved attempt ends the walk: the head is Rn and that attempt is live.
4. The head’s vault state leaf gives the reserves and policies that price the next hop.

> **Amendment S16 (owner, 2026-10-01) — a vault is found by its tokens, and its setup is the first step of the first trade through it.** Phone-rig finding, 2026-10-01: `sofi.findRoute` searched only the vaults the trader had already set up with, so a trader could not find a vault without being told it, and the rig's first trade went through only because the trader set up by hand. This amends §11, §14.1, §15, §27, §28, §29, §30, §31 and §32.
>
> - **The token index.** Creating a vault also indexes its genesis preimage under `vault_token_locator(t) = H(vault-token-locator/v1; t)` for each of the two tokens `t` of its market pair, where `t` is the token's policy commit (§28 step 4). It is an index like every other (§11): public and append-only, anyone may append, a read returns the addresses in append order, and the member interprets nothing.
> - **Discovery carries no authority.** A reader keeps a candidate only when the preimage is accepted as the vault's genesis, bound to the owner's validated creation by `genesis_accepted` (§28 step 5), and the market policy that acceptance resolves pairs `t`. Anything else under the locator is not a vault of `t`, and is passed over. A candidate whose bytes, or whose owner's lineage, the reads do not establish leaves the discovery partial, never Invalid. The vaults the reads did establish are found all the same.
> - **Path search.** `sofi.findRoute` reads the token index of the input token and of the output token. It takes the vaults that pair them directly and, for two hops (`ROUTE_MAX_LEGS`), a vault of the input token and a vault of the output token that share their other token. It walks each one's head by §30 and prices each hop there. Path search finds its vaults by these two indexes and their heads by §30, and uses nothing else. It is not limited to the vaults the trader has set up with, and a quote needs no setup. A route found over a partial discovery says so. A quote carries no authority: the trade walks and prices each head again (§31 stage 2), and the trader's minimum output bounds what it accepts.
> - **The setup is still a transaction.** §16 and §29 stand: a trader sets up once per vault before its first operation against that vault, the setup body is published and `Stored`, and the trader's transition carries `SofiSetup` as a position of its own, which every later leg through that vault names by `ρ`. What changes is who starts it. When the trader has no setup with a vault on the route, the first trade or route through that vault admits the setup transaction first, one per such vault in hop order, and then builds the trade on the position after the last of them. Later trades reuse the setup. The owner's first Close of its own vault does the same (§32).
> - **Routes (§27).** `sofi.setup` is no longer a route of its own: the setup is the first step of the operation that needs it, run by the producer of `sofi.trade`, `sofi.route` and `sofi.close`. In its place, `sofi.vaults` lists the vaults the device created — the creation records its own validated root commits — each walked to its head by §30, so the owner sees the live reserves without closing (owner ruling, 2026-10-01). The app still reaches SoFi through eight routes.
> - **Another trader's conditional parent.** A walk that meets an exercise whose `P` names its trader's conditional position as its parent resolves that position from SoFi's public objects through frontier-relative verification of the trader's lineage (DSM Amendment A8, Amendment S15), exactly as it resolves one inside a lineage it verifies; it does not wait on the trader. Without it, any trader's second trade through a vault stalls every other device's walk of that vault.
> - **What it does not change.** The vault side, the walk, the resolution and every predicate are unchanged. Setting up is an ordinary admitted transition, so a setup admitted ahead of a trade that then fails, or is never built, stands as the trader's position. The next trade through that vault reuses it.

> **Amendment S23 (owner, 2026-10-07) — vault and reserve checkpoints: discovery without authority.** Phone finding, 2026-10-07: a fresh wallet found a 24-generation vault's head by the walk above in ~60 s and a 90-generation reserve's head (§51) in ~16 s, because each generation's cell is computed from the root the generation before it established, so every read waited on the one before. The owner ruled the same day that shared lineages carry their history as proof-carrying generations, in phases: (A) checkpoints and generation hints that let a reader fetch a lineage's evidence in parallel, (B) a proof tree over checkpoints, (C) a recursive validity proof (DSM Amendment A15). This amendment specifies phase A. It amends §11, §14.1, §14.2, §30 and §51.
>
> - **Nothing here establishes anything.** A discovered root tells a reader where to look; it never tells the reader what the state is. The head is still found by the walk in steps 1–3, from the accepted genesis, one consumption at a time, and every generation is established by Core exactly as before. Hints, checkpoints and bundles only decide which cells and objects are read, and when.
> - **The consumption key is unchanged.** A generation's successor is still found at `K(a)` derived from its parent root `R_n` (§23), never at a key derived from the generation number: a key computed before its parent exists would let anyone pre-position bytes at it, and would contradict DSM §43.
> - **Objects** (CCB, §14.2; tags §14.1). For a lineage of kind `k` (1 a vault, 2 the native reserve of §51) and identity `id` (the vault id `v`, or the reserve id):
>   - `SharedGenesisV1 {kind, lineage_id, state_root, genesis_preimage_digest}`, with `d_0 = H(shared-lineage/genesis/v1; CCB(·))`; `genesis_preimage_digest` is a vault's genesis preimage address, or the reserve's policy commit.
>   - `SharedGenerationV1 {kind, lineage_id, generation, parent_generation_digest, state_root, step_digest}`, with `d_g = H(shared-lineage/generation/v1; CCB(·))`; `parent_generation_digest` is `d_{g−1}`, and generation 1 names `d_0`. `step_digest` identifies the canonical transition: for a vault `H(shared-lineage/vault-step/v1; E)`, where `E` commits the exercise's legs and so the parent it consumed; for the reserve the release's evidence address. A reader computes `d_g` only from generations it established.
>   - `GenerationHintV1 {kind, lineage_id, generation, state_root, generation_digest, step_digest}`: one per realized generation.
>   - `CheckpointV1 {kind, lineage_id, start_generation, end_generation, start_generation_digest, end_generation_digest, roots[33], transition_bundle_digest, checkpoint_digest}`, with `end_generation = start_generation + 32`, `roots[i]` the claimed root of generation `start_generation + i`, and `checkpoint_digest = H(shared-lineage/checkpoint/v1; CCB(every other field))`.
>   - `TransitionBundleV1`: the addresses a reader needs to read a segment's generations, for a vault per generation the attempt that consumed the parent, `E`, the trader's coordinates `(G, DevID, q)` and the route's other legs `(vault, parent root)` — the exercise and everything it names are read from the attempt cells; for the reserve the release envelope's address. `transition_bundle_digest` is the bundle's address: retrieval integrity only, never a transition's identity.
> - **The epoch index.** `lineage_epoch_locator(k, id, e) = H(shared-lineage/epoch-locator/v1; u8 k ∥ id ∥ u64be(e))`, an index like every other (§11): it lists the hints and checkpoints of generations `32e … 32e + 31`. Anyone may append to it, so it may hold anything.
> - **Who writes.** The trader whose position resolves Realized at generation `g` of a vault (§24), and the claimant whose release is final at generation `g` of the reserve, append a hint for `g` after their own state is committed; when `g` is a multiple of 32 and greater than 0, they also publish the bundle and the checkpoint of the segment that ends at `g`. Any reader that established a generation whose hint, or a segment whose checkpoint, it does not find MAY publish it. Publishing is never on the path of an admission, and its absence costs only speed.
> - **A fresh reader.** From the accepted genesis, the reader:
>   1. probes the epoch index at `e = 1, 2, 4, …` and then by bisection, and reads every epoch up to the highest populated one, all at once;
>   2. takes a checkpoint for the segment starting at the generation `s` it has established only when its kind and lineage are the lineage's, `start_generation = s`, `start_generation_digest = d_s` as the reader computed it, `roots[0] = R_s`, `end_generation = s + 32`, its encoding round-trips and `checkpoint_digest` recomputes; it fetches that checkpoint's bundle;
>   3. derives from the claimed roots every cell and object the walk will need — the attempt cells and their routes, the trader positions, the sibling legs, the reserve cells — and reads them all at once, re-hashing each object to its address;
>   4. runs the walk of steps 1–3 over what it read, establishing each generation by Core exactly as before; after the segment it compares the `d` and root it computed with the checkpoint's end; a mismatch discards the checkpoint and nothing else;
>   5. reads the generations after the last checkpoint the same way, from their hints.
>
>   Anything a hint, checkpoint or bundle names that the reads do not bear out is passed over, and the walk reads that generation as steps 1–3 describe.
> - **Flooding.** The epoch index is predictable and anyone may append to it. A reader reads a bounded number of candidates per epoch. Exhausting that bound means discovery is unavailable for that epoch: the reader walks it as steps 1–3 describe. It never means the lineage is invalid, and it never means no later generation exists. No hint's generation is evidence of anything: a hint naming generation 1,000,000 is a place to look.
> - **What phase A costs.** The reads a reader waits on, one after another, are logarithmic in the lineage's age; the evidence it reads, the bytes it moves and the work Core does are still proportional to the age. Only phase C makes them independent of it (DSM Amendment A15).

> **Amendment S24 (owner, 2026-10-07) — the owner baseline, and the authenticated-root mode.** Phone finding, 2026-10-07: after Amendment S23 a fresh wallet still established every generation of a 27-generation vault before its first swap (~18–25 s), and the cost grows with every trade. The owner ruled the same day, from the SoFi paper (Def 6.1, Req 6.2, Req 6.3, the composition-depth boundary): a party that holds nothing of a vault starts from the latest authenticated owner baseline; every generation after it is authenticated by its own transition evidence; a trader's signature is never the anchor; no zero-knowledge, recursive proof, server proving or history replay. The proof material is constant in size: the root, the state leaf with its path, and the reader's own relationship proof, never the vault's leaves. This amends §11, §14.1, §14.2, §16 and §30, and refines DSM Amendment A15 for owned lineages.
>
> - **The frontier.** `VaultFrontierV1 {vault_id, generation, root}` (CCB, §14.2; Amendment S26 adds `history_root`), and `c_f = H(vault-frontier/v1; CCB(VaultFrontierV1))`. It states economic state only: nothing about the owner's authority is in it, so a change in the owner's authority lineage changes no frontier, no root and no parent identity.
> - **The owner baseline.** `OwnerBaselineAuthV1 {frontier_commitment, owner_authority_transition_digest}` (CCB, §14.2), `c_n = H(vault-baseline/v1; CCB(OwnerBaselineAuthV1))`, and an `AnchorPresentationV3` whose `state_commitment` is `c_n`, by the vault's owner: `frontier_commitment` is `c_f` of the frontier presented with it; P0–P6 run at `owner_authority_transition_digest`, the position the signer committed, as they run at a `V_n`'s own; the identity they prove is the accepted genesis's `(owner_genesis, owner_device_id)`; `K_cand = K_proven`; and the frontier's `vault_id` is the vault's. Published with the frontier and baseline bytes, and indexed under `vault_baseline_locator(v, g) = H(vault-baseline-locator/v1; v ‖ u64be(g))` (§11), discovery only — one locator per generation, so what a reader reads to check a baseline does not grow with the vault's age.
> - **Verifying a baseline**, in this order: (1) the anchor's candidate key signed `c_n`, and the `OwnerBaselineAuthV1` bytes re-hash to `c_n`; (2) P0–P6 at its `owner_authority_transition_digest` prove the accepted genesis's owner, and `K_cand = K_proven`; (3) `frontier_commitment` is `c_f` of the presented frontier bytes, and the frontier's `vault_id` is the vault's. Only then is the frontier's root accepted, as the verified frontier. (4) A witness is checked against that root before anything is read from it. Authority and economic state meet only at `frontier_commitment`.
> - **The frontier witness.** `VaultFrontierWitnessV1 {state_leaf, state_path[256], relationship}`, where `relationship` is `Present {leaf: VaultRelationshipLeaf, path[256]}` or `Absent {path[256]}`. Against an authenticated frontier: `root_from_path(vault_state_key(v), econ_leaf(·, vault_state_leaf_value(state_leaf)), state_path) = root`; `state_leaf.generation = generation`; its owner fields are the proven owner's; and at `k_T,v` the path folds to `root` from the absent leaf, or from the present leaf whose trader fields are `(G_T, DevID_T)`. The state part is the same for every reader; the relationship part is the querying trader's own.
> - **Composed state.** The latest valid baseline, followed by every successor whose transition evidence verifies from it (§23, §30 steps 2–3). In the authenticated-root mode a successor's leaves are proven by the paths its `DlvCore` carries against the authenticated `pre_root`, the vault state preimage is carried forward from the generation before, and a relationship entry's stated base is decided by the fold: present or absent, only one folds to `pre_root`. No other leaf is held.
> - **Witness advancement.** A held witness is specific to its root. Through each successor, the reader advances its state witness (to the receipt's post state) and its own relationship witness (its value advanced by `relationship_leaf_next` when its leaf was the one written, unchanged otherwise) from `R_n` to `R_n+1`, recomputing each sibling whose subtree the receipt wrote from the receipt's own paths; every recomputed sibling must agree with the receipt on the pre side, and the advanced witness must fold to `R_n+1`, or the successor is refused.
> - **Failure classes.** No baseline, or a witness not available: the reader composes from the genesis as §30 describes. A locator candidate that does not decode or does not authenticate: passed over. Two authenticated baselines of one vault at one generation whose frontiers differ (different `c_f`): `STORAGE_SAFETY_VIOLATION`, the vault is quarantined for this reader, and nothing is chosen (Req 6.3). Two that bind the same frontier and differ only in their authority material are not a fork: they authenticate one frontier, and either stands. An authenticated baseline whose witness contradicts it: refused. Neither of the last two falls back to composing from the genesis.
> - **The owner's duty.** Catch-up is synchronization, never a condition of market realization (Def 6.1). A continuously online owner publishes a baseline after each realized generation, and answers a trader's request for its relationship witness against the current baseline's root; the answer carries no authority, since the trader checks it against `root`.
> - **What it costs.** A fresh reader reads the locator, one presentation, the frontier, one witness, and the generations after the baseline: constant in the vault's age and in the number of its traders when the owner is current; growing with the generations since the last baseline when it is not.


> **Amendment S26 (owner, 2026-10-08) — a vault's history, and no replay below a baseline.** Host finding, 2026-10-08: a wallet that started at an owner baseline (Amendment S24) judged another trader's trade above it. Rung 1 asks for that trader's root at its parent, and the trader's lineage held a SoFi position built on a vault root below the reader's baseline. A chain from a baseline names nothing below it, so the reader's walk asked for that root by extending the chain it was already extending, recursed, and overflowed its stack. Composing the vault from its genesis down there would have answered, and would have put back the history-linear cost Amendment S24 removed. The owner ruled the same day: **a baseline MUST be sufficient, together with bounded authenticated proofs, to validate every historical root that later public evidence may reference. No conforming verifier may recover such a root by replaying vault history.** This amends §11, §14.1, §14.2, §30 and Amendment S24.
>
> - **The history.** Per vault, never across vaults: an append-only binary Merkle tree whose leaf at position `g` is `R_g`, for every generation `g` from 0 to `n`. Leaf hash `H(vault-history-leaf/v1; v ‖ u64be(g) ‖ R_g)`, node hash `H(vault-history-node/v1; left ‖ right)`. Its head `VaultHistoryHeadV1 {vault_id, generation n, peaks}` (CCB class `0x0074`) lists the peaks of the complete subtrees left to right, one per set bit of `n + 1`, highest first, and its root is `H_n = H(vault-history-head/v1; CCB(head))`. It is keyed by generation, which is unique within the vault's lineage, and it is a separate tree from the economic one, so nothing in it refers to itself.
> - **The frontier commits it.** `VaultFrontierV1` becomes `{vault_id, generation, root, history_root}`, `history_root = H_n` at the frontier's generation, so `c_f` binds the economic root and the history together. Two baselines at one generation that differ in their history differ in `c_f`, and are quarantined as Amendment S24 says.
> - **Published once, read by hash.** The owner publishes, before it signs a baseline at `n`, every history object up to `n` it has not published: each leaf's 72 bytes under the leaf tag, indexed under `history_locator(v, R_g) = H(vault-history-locator/v1; v ‖ R_g)`; each interior node a new leaf completes, its 64 bytes under the node tag; the vault's state leaf at each `R_g`, under its leaf-value tag; and the head under the head tag. Each namespace is the hash's own tag, so an object's store digest is its hash and a reader fetches a node, a head or a state leaf by the hash it holds. A completed subtree never changes, so every node is published once and serves every later head. Storage only stores; the owner is never in a reader's path.
> - **Proving a root below a baseline.** A reader whose chain starts at a baseline at `b` and needs a root `R` it does not name: reads the head by the frontier's `history_root` and checks its hash and generation; reads the leaves under `history_locator(v, R)`, each naming a candidate `g < b`; and for a candidate, reads the nodes from the peak covering `g` down to the leaf by their hashes, checking each, until the leaf `(v, g, R)`. A path that ends there proves `R_g = R`, and the chain holds `R` at `g`; one that ends elsewhere proves nothing for that candidate. The path is the peak's height, at most 64 and `log2` of the vault's age in practice. Anything not in hand leaves the root unestablished, never refuted.
> - **The state at that root.** An operation built on a proven root reads the vault's state leaf there by the value its own core states at the state key, whose path validation folds to that root; the bytes must re-derive that value.
> - **Records made before.** A baseline signed before this amendment carries the old frontier, which no longer decodes. A reader drops a record it started at one, whole, and adopts a current baseline; an owner drops what it signed and signs again. No other record changes.
> - **What it costs.** A root below a reader's baseline costs one head, the candidates under one locator and one path of nodes; nothing grows with the vault's age except a path's `log2`. No conforming verifier walks from the genesis to reach it.
<!-- spec-section: SOFI-031 -->
### 31 A trade and a multihop route
A single vault trade is a route with one hop. A multihop route is one operation whose hops run through distinct vaults,
where the output token of hop j is the input token of hop j +1. ROUTE_MAX_LEGS = 2 (CORE/sofi/wire/mod.rs:184)
bounds the hops.

| Stage | What happens, and the function that does it |
|---:|---|
| 0 — parent resolved | The trader’s position p must be resolved: `descendant_fence` (`CORE/sofi/lineage.rs:244`) refuses while it is pending. The trader holds the validated root Rp. |
| 1 — path | `sofi.findRoute` proposes hops v1, …, vn from walked heads R1, …, Rn (Section 30). |
| 2 — draft | `draft_trade` or `draft_route` builds B◦ = `Swap{hops}` with each hop’s output from `constant_product_output` (`CORE/dlv/route_commit.rs:151`) at that head’s reserves and fee policy; each vault core Vj◦ against Rj; the trader core T◦ against Rp; E with `external_commitment_single` or `external_commitment_route` (`CORE/sofi/derive.rs:256, :285`), the second binding every hop through H(Γ) (`:280`); Rrealize = Fold(T◦, E) by `batch_fold` (`CORE/sofi/smt/fold.rs:178`), with hj+1 from `relationship_leaf_next` (`CORE/sofi/derive.rs:131`); the preimage P(E); and P with Rvoid = Rp, signed. |
| 3 — validate | `preimage_admissible` (`CORE/sofi/admission.rs:78`); evidence acquired from storage (rebuild step R5); `route_validation` (`CORE/sofi/validation.rs:338`) must return Valid, verifying each core with `verify_batch` (`CORE/sofi/smt/fold.rs:197`) and each leaf pre value with `verify` (`CORE/sofi/smt/tree.rs:402`); `verify_precommit` (`CORE/sofi/signature.rs:215`). Any other result stops the producer. |
| 4 — publish | P indexed under PrecommitId, P(E) under `preimage_locator(E)` (`CORE/sofi/derive.rs:424`), and every closure object, each put and Stored. |
| 5 — witnesses | `derive_policy_fulfillments` (`CORE/sofi/conformance.rs:67`) yields Gj for every hop, indexed under `policy_fulfillment_id` (`CORE/sofi/derive.rs:169`), with any auxiliary evidence. |
| 6 — exercise | `build_fulfillment` picks each hop’s live attempt aj from the walk, advancing with `next_attempt` (`CORE/sofi/wire/mod.rs:341`), builds and signs F; `check_fulfillment_against_precommit` (`CORE/sofi/conformance.rs:100`) must return Valid; Cq comes from `resolution_claim` (`CORE/sofi/derive.rs:193`). The trader’s transition carries `SofiFulfill` through the Core transition, where `verify_operation` checks it. This is the state advancement that holds the key. |
| 7 — install | The trader writes F at Kful(q) (`fulfillment_register_key`, `CORE/sofi/derive.rs:184`) and Cq at Kroot(q) in one local transaction at the leader of s(q), then the same bytes on the other members. FulfillmentRegistered(F) once final. |
| 8 — complete | For every hop, the trader or any relayer writes the exercise (Section 17.5) to that vault’s cell K(aj) at the leader of svj, then the same bytes on the other members. StorageFinalE per hop once final. |
| 9 — resolve | Core reads the cells raw, builds the facts per hop, and evaluates `consumed_route` (`CORE/sofi/resolution.rs:216`) and `route_impossible` (`:253`) inside `resolve_position` (`:284`); `effect_of` (`:92`) gives the effect. |
| 10 — advance | `advance_resolved` (`CORE/sofi/lineage.rs:114`) produces the validated root at q: Rrealize if Realized, Rp if Void. The fence on p releases and position q + 1 can be built. |

<!-- Source PDF page 34 -->


**Rule — multihop is all or none**

Every hop lands at its own vault’s cell under that vault’s own leader, and no vault waits for another. The route
realizes only when every hop’s cell is final on E with a canonical parent and a live attempt. One permanently
defeated hop voids the whole route; every other hop’s final cell is then skipped as RejectedFinalRoute, so each
of those vaults’ next attempt goes live. There is no partial route and no coordination between vaults.

The vault side needs no action. Once a hop is consumed, that vault’s head is its Vj◦ post root, and the owner and
every later trader find it by walking.

> **Amendment S19 (owner, 2026-10-01) — a route chains or splits.** Owner ruling during the phone-rig run, on two vaults of one pair filling one order: "It should be no different. It just happens to be the same token," and "It should work either way." Two vaults of the same token pair are no different from two vaults of different pairs, and one order may be filled through both. This amends §19.5 and §31, and changes only what a Swap route's hops may be.
>
> - **Two shapes.** A Swap route's hops either chain — the output token and amount of hop j are the input token and amount of hop j + 1, as §19.5 states — or split: every hop trades the route's one pair, from the intent's input token to its output token, through distinct vaults. A route of one hop is both.
> - **A split's endpoints.** The hops' inputs sum to the intent's `amount_in`, and their outputs sum to its `exact_out`, in checked arithmetic. Each hop is priced by its own vault's constant product at its own head, exactly as a chained hop is (§19.5), and each vault takes its own fee.
> - **Everything else is unchanged.** The trader's core moves the intent's two endpoints only (one debit of `amount_in`, one credit of `exact_out`) and advances one relationship per vault. The route is one operation: every hop lands at its own vault's cell, the route realizes only when every hop does, and one defeated hop voids it all ("multihop is all or none", above). `ROUTE_MAX_LEGS` bounds both shapes.
> - **Who chooses the split.** The producer: `sofi.findRoute` weighs a split across two vaults of the pair beside every single hop and chain, and proposes whichever gives the trader the most. The trade prices the same split again at the heads it walks. Neither carries authority; RouteValidation checks the hops as stated.

> **Recommendation (owner, 2026-09-23) — not a rule.** Every vault must honour the policy of each of its tokens; that is a rule, not a choice (§49, MR-SOFI-0311). Within those policies, owners are encouraged to set up their vaults for a token in line with the rest of the market for that token, with only minor differences, so that their liquidity is usable by multihop routes and other traders' paths. Nothing enforces this, and no check depends on it.

> **Note (owner, 2026-10-07) — client routing and retry policy; nothing here is validity.** A pair's liquidity may be split across several vaults so that trades on different vaults never contend (a vault's next key is the conflict domain, §23). A route search keeps the best output as its reference and treats a route within `ROUTE_TOLERANCE_BPS` (300 at beta, tunable) of it as near-equal; among near-equal routes it takes the fewest legs, then the order `H(route-lane/v1; G ‖ DevID ‖ sorted vault ids)` gives the trader, then the lowest vault ids, so small trades spread across a pair's vaults and a split is taken only when it is better by more than the tolerance. A trade whose vault moves under its draft before anything is published plans again at the new head; a swap whose position resolves Void (its key lost to another trade, provable by anyone under Amendment S25) is quoted and traded again; an Invalid or pending position is never retried. None of this changes what any verifier accepts. This refines Amendment S19's "proposes whichever gives the trader the most": the most within the tolerance band, then the fewest legs.

<!-- spec-section: SOFI-032 -->
### 32 Closing a vault
draft_close builds B ◦ = Close{vault_id, parent_root, setup_ref, reserve_a, reserve_b} as a one hop route against
the owner’s own vault under its release policy. Stages 0 and 2 to 10 then run unchanged: the owner’s T ◦ credits the
released reserves and the vault has no successor.

<!-- spec-section: SOFI-033 -->
### 33 Relaying
sofi.relay completes any registered fulfillment whose hops are not all final: it reads F at the position, recomputes
each hop key, and writes the missing exercises and copies. It needs nothing else from the trader.

<!-- spec-section: SOFI-034 -->
### 34 Every Core SoFi function, placed

Function                                  Where it runs
genesis_accepted, genesis_root,           creating a vault; finding a head
vault_genesis_locator
setup_ref,                   setup_id,    setup
relationship_leaf_genesis,
relationship_index_key
storage_seed,       first_member,         finding a head; stages 6 and 8
successor_attempt_key,      walk,
classify_attempt, next_attempt
fulfillment_register_key                  stage 7
descendant_fence                          stage 0
external_commitment_single,               stage 2
external_commitment_route,
route_leg_set_digest,    batch_
fold, relationship_leaf_next
preimage_admissible,      route_          stage 3, and again in stage 9
validation, verify_batch, verify,
verify_precommit
preimage_locator,      policy_            stages 4 and 5
fulfillment_id, derive_policy_
fulfillments
check_fulfillment_against_                stage 6, and again in stage 9
precommit,     resolution_claim,
verify_operation
consumed_route,           route_          stage 9
impossible,     resolve_position,
effect_of
advance_resolved                          stage 10
validate_staged_frontier,                 the trader’s tree store: staged post trees are validated before stage 7, and
reachable                                 nodes not reachable from a validated root are dropped after stage 10
route_outcome_key,                next_   deleted: used by no stage
generation


<!-- Source PDF page 35 -->


## Part VI — Traceability
Nothing in this design is trusted because it exists. A module counts only if production code calls it. A piece of evidence
counts only if Core consumes it on the path that produces the transition, and its effect can be followed from the bytes
that came in to the state that went out. This part states the rules and the gates that enforce them. They apply to every
subsystem, not only to SoFi.

<!-- spec-section: SOFI-035 -->
### 35 Rules
Rule T1: every module is used

Every public item under CORE/sofi/ is called from production code, or it is test support and lives under
#[cfg(test)]. A function with no production caller is wired or deleted. Nothing is kept for later.


Rule T2: all evidence is real
Every evidence item Core consumes is bytes that were fetched from storage by content address or coordinate, or
bytes the trader supplied and published, decoded by a strict canonical decoder after its address is recomputed.
Evidence is never defaulted, synthesized, filled in by the SDK, or replaced by a cached verdict.

Rule T3: all evidence is used
Every evidence item in the unlock preimage is consumed by a named Core check, and that check’s verdict is a
conjunct of RouteValidation, FulfillmentConformance or ConsumedRoute. An item that no check consumes is
refused by the strict decoders as malformed; it is never ignored.

Rule T4: traced from input to output through Core

The values Core verified are the values the transition installs. E recomputes from the verified preimage. The
installed post root is exactly Fold(T ◦ , E) over the verified cores. Cq is recomputed from the verified P and F .
The SDK passes Core’s result into the transition unchanged (Part VII).

Rule T5: Unavailable is never admissible
A producer that receives Unavailable stops. It never publishes, exercises or advances on Unavailable.


<!-- spec-section: SOFI-036 -->
### 36 The unlock preimage, traced
Each row names one evidence item, where it comes from, the Core check that consumes it, the verdict that check feeds,
and where its effect lands in the output. Evidence (CORE/sofi/validation.rs:228) carries two of the items as
maps: objects (policy objects and the trader's TraderPreBalance objects, by address) and vault_leaves (vault
leaf pre values by vault and key). The trader's leaf pre values are derived from T° and those objects
(Amendment S12).

Evidence            Comes from                  Consumed by                        Feeds                           Lands in

P                   content addressed object,   verify_precommit (CORE/sofi/       FulfillmentConformance 1,       Rrealize and Rvoid in Cq
any relayer                 signature.rs:215); P confor-       2; RouteValidation
mance
P (E)               content addressed, class    recompute_e       (CORE/sofi/      RouteValidation                 E
0x0059, found by the        derive.rs:389) equals P.E; size
preimage locator of E       bound
B◦                  inside P (E)                hop chaining, intent endpoints,    RouteValidation: branch ef-     b◦ and Xroute in E
constant_product_output per        fects, conservation
leg (CORE/dlv/route_commit.rs:
151); Close reserves and release
policy


<!-- Source PDF page 36 -->


Evidence                Comes from                  Consumed by                          Feeds                           Lands in

T◦                      inside P (E)                verify_batch (CORE/sofi/smt/         TraderSideValid                 cT ◦ in E; the installed
fold.rs:197) from the validated                                      root Fold(T ◦ , E)
root at p; closed write set
Vj◦                     inside P (E)                verify_batch from Rj ; closed        PolicyFulfillmentValid          cV ◦ in E; the vault’s suc-
write set; hashes to c◦V,j                                           cessor
policy objects          Evidence.objects,           policy checks in validate            PolicyFulfillmentValid          pricing and release deci-
address recomputed                                                                               sions in Vj◦
trader leaf pre         TraderPreBalance ob-        compared with the entries of T ◦     TraderSideValid                 pre root of T ◦
values                  jects CE names (S12)
vault leaf pre val-     Evidence.vault_leaves       vault state and relationship         PolicyFulfillmentValid          pre root of Vj◦
ues                                                 checks
pre
closure      refer-     PreEClosureIndex       in   setup, parent claim and content      RouteValidation; P confor-      CE inside b◦
ences                   B ◦ , each fetched by its   checks                               mance
reference
setup body per          content addressed; ρ re-    verify_setup      (CORE/sofi/        RouteValidation;   Fulfill-     h0 through σ
leg                     computed                    signature.rs:172); SetupValid        mentConformance 6
parent claim            read at Kroot (p)           P conformance 2 and 3; trader_       P conformance; Consume-         T ◦ .pre_root; advance_
parent_compatible                    dRoute                          resolved parent check
witness set Gj          derived from P (CORE/       equality with F ’s set               FulfillmentConformance 3        identity of F
sofi/conformance.rs:
67)
auxiliary        evi-   content addressed candi-    candidate    verification   within   PolicyFulfillmentValid          a validation step only
dence                   dates                       budgets
F                       read at Kful (q)            verify_fulfillment                   FulfillmentConformance          FulfillmentId in Cq ; at-
(CORE/sofi/signature.rs:192);                                        tempts select successor
check_fulfillment_against_                                           keys
precommit
Cq                      recomputed from P and       advance_resolved     (CORE/sofi/     the ladder; mutual exclu-       the root installed at q
F                           lineage.rs:114)                      sion
storage facts           raw member reads            LeaderHeld and Final                 FulfillmentRegistered; Stor-    ConsumedRoute; the lad-
ageFinalE                       der


<!-- spec-section: SOFI-037 -->
### 37 Gates
Gate G1: reachability

A CI script fails if any pub fn under CORE/sofi/ has no caller in production code. Production code is every .rs
file under CORE, SDK and NODE, excluding tests/ directories and everything after the first #[cfg(test)] in a file.
The check prints each unused function by name. Wire it into ci/production_safety_checks.sh.
#!/usr/bin/env python3
# ci/sofi_reachability.py: every public SoFi function has a production caller.
import glob, os, re, sys
roots = ["dsm_client/deterministic_state_machine/dsm/src",
"dsm_client/deterministic_state_machine/dsm_sdk/src", "dsm_storage_node/src"]
def prod(path):
t = open(path, encoding="utf-8").read()
i = t.find("#[cfg(test)]")
return t if i < 0 else t[:i]
files = [f for r in roots for f in glob.glob(r + "/**/*.rs", recursive=True)
if "/tests/" not in f and not f.endswith("_tests.rs")]
text = {f: prod(f) for f in files}
unused = []
for f in sorted(g for g in files if "/dsm/src/sofi/" in g):
for m in re.finditer(r"^pub fn (\w+)", text[f], re.M):
call = re.compile(r"\b" + m.group(1) + r"\s*(::<[^>]*>)?\(")
n = sum(len(call.findall(t)) for g, t in text.items()) - 1
if n == 0:
unused.append(f"{f}:{text[f][:m.start()].count(chr(10)) + 1} {m.group(1)}")
for u in unused: print("[FAIL] no production caller:", u)
sys.exit(1 if unused else 0)


Gate G2: no default evidence
Evidence derives Default only under #[cfg(test)] (#[cfg_attr(test, derive(Default))]), so production
code cannot construct it empty. It is built only by the acquisition step of rebuild step R5. A static check fails on
any Evidence::default() outside test code.


<!-- Source PDF page 37 -->


Gate G3: every evidence item is load bearing

For every row of the table above there is a named test that removes the item and asserts Unavailable, and a
named test that corrupts it and asserts the specific Invalid refusal. Deleting the Core check that consumes the
item turns its test red.

Gate G4: output binding

For an accepted operation, a test asserts that the installed root equals Fold(T ◦ , E) computed from the verified
cores, that Cq recomputed from P and F equals the one at Kroot (q), and that changing any single byte of any
evidence item either changes E or produces a refusal.

Gate G5: Unavailable stops the producer

On the production path, a test withholds each evidence item in turn and asserts that nothing is published,
exercised or advanced.


## Part VII — SoFi in the Core transition
A SoFi operation changes canonical state only through the one Core transition function that every DSM transition
uses. SoFi adds no second path into state.

<!-- spec-section: SOFI-038 -->
### 38 What enters the transition

Operation                    Carried bytes                       Core result it installs
SofiVaultCreate (35)         the signed creation                 the funding debit and the VaultCreation leaf
SofiSetup (34)               the signed setup body               the relationship leaf h0
SofiFulfill (36)             the signed fulfillment F            the conditional claim Cq at position q; after resolu-
tion, the root advance_resolved selects


**Rule — order inside the transition**
1. verify_operation (CORE/sofi/signature.rs:232) checks the operation against the key of the device
whose state advances.
2. The Core checks of Part V for that operation run and return Valid; any other result stops the transition.
3. Core derives the entropy en+1 = H(DSM/state-entropy; en ∥ op ∥ hn ) from the relationship tip.
4. The state advances with Core’s result unchanged.


<!-- spec-section: SOFI-039 -->
### 39 Requirements
1. One function prepares every transition. No SoFi producer calls a lower level advance.
2. The SDK supplies no entropy. The value derived in step 3 is the only entropy of the transition.
3. That same value goes into the relationship tip and into both receipt hashes, Cpre and the symmetric tip.
4. A transfer nonce, where an operation has one, stays in the operation bytes, where it is already hashed.
5. The SDK passes Core’s result into the transition unchanged (rule T4).
**Gate**
For each of the three SoFi operations: applying it twice from the same state gives byte identical results; changing
any carried byte changes the result or refuses it; and a test asserts that the tip and both receipt hashes contain
the one derived value.


<!-- Source PDF page 38 -->


## Part VIII — Build order

> **Engineering classification:** Part VIII is a tree/commit-specific implementation plan tied to commit `817123c`. Preserve it as historical implementation provenance, but do not treat its PR sequencing or migration procedure as an architectural requirement when deriving the current master requirements checklist. Protocol rules stated elsewhere in the document remain normative.

This part is the work that takes the tree at 817123c to the design in Parts I to VI. When it is done, nothing it removes
remains anywhere to reference: no code, no comment, no test, no migration, no compatibility path.

2          formal floor
1                                              seam             5                6
stop and
demolition                                       frozen         rebuild          cutover
inspect           4
Core seam

**Rule — process**

1. One pull request at a time, each from an updated origin/main in a fresh worktree with its own CARGO_
TARGET_DIR. No stacking.

2. Toolchain for every gate: export PATH="$HOME/.cargo/bin:$PATH" and RUSTUP_TOOLCHAIN=1.98.0.
3. Before every merge: ./scripts/check-pr-head-sync.sh <pr>. Before every push: make lint and bash
ci/production_safety_checks.sh.

4. Descriptive branch names. No Co-Authored-By. Files that belong to other work are left untouched.
5. Steps 3 and 4 are independent of each other; both are complete before step 5 starts, and neither starts before
step 2 is complete.
6. No step writes a data migration. Replaced paths are deleted, never migrated, and a fresh database is expected.
7. Nothing is built on the branch feat/conditional-admitted-rows (f97737d2).

**Do not**
A compile error caused by a deletion is information: a surviving component depended on something this design
removes. Trace it. Never fix it by recreating the deleted rule somewhere else.


<!-- spec-section: SOFI-040 -->
### 40 Step 1: demolition
One pull request that only deletes. It adds no replacement mechanism of any kind: no new storage primitive, no capa-
bility format, no publication, no SoFi route, no SoFi table, no registration, no signed storage receipt, no compatibility
layer. After it, SoFi does not execute; that is the intended state.

<!-- spec-section: SOFI-040-1 -->
#### 40.1 Why the node code goes, verified at 817123c
- Registration can never succeed: the node builds its answer list from itself alone (NODE/api/sofi/mod.rs:555
to 578) and requires HOLDER_QUORUM = 3 holders (NODE/api/sofi/registration.rs:27), so it always answers
409 holders-below-quorum (:580).

- post_cell (:634) requires registration (:652), so no route can ever complete.
- The node performs semantic checks that Part II forbids.
- No client calls any SoFi node route: SDK/sdk/storage_node_sdk.rs contains no SoFi API call.

<!-- spec-section: SOFI-040-2 -->
#### 40.2 Storage node


<!-- Source PDF page 39 -->


Delete                                  Detail
NODE/api/sofi/                          the whole directory: mod.rs (836 lines) and registration.rs (166
lines). Every node side helper (conformance_outcome, canonical_legs_
for, recompute_e, check_fulfillment_against_precommit, verify_
signed_object, holders_establish_registration) lives here and goes
with it.
NODE/api/mod.rs:23                      pub mod sofi;
NODE/lib.rs:178, :211                   the merges of api::sofi::create_write_router and create_read_
router; afterwards no /api/v2/sofi/* route exists
NODE/db/pg.rs                           tables sofi_successor_cells, sofi_fulfillment_registrations,
sofi_fulfillments, sofi_settlement_preimages, sofi_precommits,
sofi_policy_fulfillments (lines 904 to 935); ObjectPutOutcome,
put/get_sofi_precommit,             put/get_sofi_policy_fulfillment,
FulfillmentRegistration,            register_fulfillment_with_claim,
get_sofi_fulfillment,                 record_fulfillment_registered,
is_fulfillment_registered,                get_sofi_fulfillment_by_id,
SuccessorCellPutOutcome, put/get_sofi_successor_cell, put/get_
sofi_settlement_preimage (lines 2832 to 3160)
NODE/db/sqlite.rs                       the same tables (lines 593 to 624) and the same items (lines 3019 to 3416)
dsm_storage_node/tests/                 sofi_object_stores.rs (7 tests), sofi_fulfillment_register.rs
(7), sofi_registration_record.rs (4), sofi_successor_cells.rs (8),
sofi_witness_authority.rs (5). Deleted outright, never rewritten,
never ignored.
NODE/db/write_once_properties.rs        the successor cell adaptation (lines 102 to 119) and its property entry
(lines 321 to 330)
NODE/api/economic/root_register.        is_conditional_claim_class (lines 72 to 80), its use in post_claim,
rs                                      the comment block that explains it, and the test fixture built on
SofiResolutionClaim (line 442). The ordinary single root path stays: its
decoder already refuses anything that is not a signed single root claim.
comments                                NODE/api/storage/binding.rs:3, NODE/api/storage/mod.rs:2, NODE/
db/binding.rs:5, NODE/db/binding_properties.rs:4: rewritten to de-
scribe the generic primitive without naming SoFi


economic_register_conformance.rs depends only on the signature of the economic register router and survives.

<!-- spec-section: SOFI-040-3 -->
#### 40.3 Core wire material


Delete                                  Detail
ResolutionRecord                        the      enum       and       its    implementation        (CORE/sofi/
wire/objects.rs:977    and        :997):        all   five     variants,
RecordFulfillmentRegistered,                    RecordSuccessorDead,
RecordSuccessorFinal, RecordOutcomeComplete, RecordOutcomeAbort
OutcomeCell                             CORE/sofi/wire/objects.rs:1080, both variants
class constants                         SOFI_RECORD_* and SOFI_OUTCOME_CELL_*, 0x0043 to 0x0049 (CORE/
ccb/mod.rs:233 to 245); each number moves into burned_class::ALL
(CORE/ccb/mod.rs:383 to 409)
tag                                     TAG_DSM_SOFI_ROUTE_OUTCOME_V2         (CORE/common/domain_tags/dsm/
misc/sofi.rs:79) and every list that names it
derivation                              route_outcome_key (CORE/sofi/derive.rs:208)
documentation                           the class dispatch comments in CORE/sofi/wire/mod.rs that name the
removed classes (lines 79 and 80 and the other mentions)


<!-- Source PDF page 40 -->


Delete                                             Detail
resolution inputs                                  in CORE/sofi/resolution.rs: the import (line 35), the outcome field of
RouteFacts (159), the clause that reads it in consumed_route (225), the
Abort arms at 312 and 370, and the tests that set it (664, 747, 829, 994,
1074, 1143). Completion is the per leg conjunction that remains.
vectors                                            every vector and test in dsm_client/deterministic_state_machine/
dsm/tests/sofi_v8_independent.rs whose only purpose is the re-
moved family
comment                                            the doc comment on resolution_claim (CORE/sofi/derive.rs:190),
which says a member derives Cq ; it is rewritten to say Core computes
it


<!-- spec-section: SOFI-040-4 -->
#### 40.4 Gates

**Gate:** static
git grep dsm::sofi dsm_storage_node/src         # nothing
git grep '/api/v2/sofi' dsm_storage_node/src    # nothing
git grep -ni 'sofi' dsm_storage_node/src        # nothing, comments included


The storage node must be understandable without knowing that SoFi exists.

**Gate:** ci/storage_is_dumb.sh, new, wired into ci/production_safety_checks.sh
#!/usr/bin/env bash
# CI gate: the storage node holds bytes and knows nothing about SoFi.
set -euo pipefail
root="dsm_storage_node/src"
banned=( 'dsm::sofi' 'SOFI_' 'ConditionalSofi' 'SofiResolutionClaim' 'TraderPrecommit'
'TraderFulfillment' 'DlvPolicyFulfillment' 'FulfillmentRegistered' 'RouteValidation'
'ConsumedRoute' 'verify_signed_object' 'check_fulfillment_against_precommit'
'canonical_legs' 'recompute_e' 'resolution_claim' '/api/v2/sofi' )
fail=0
for tok in "${banned[@]}"; do
if hits=$(git grep -n -F -- "$tok" -- "$root"); then
echo "[FAIL] storage node references '$tok':"; echo "$hits"; fail=1
fi
done
if hits=$(git grep -n -i -- 'sofi' -- "$root"); then
echo "[FAIL] storage node mentions SoFi:"; echo "$hits"; fail=1
fi
[[ $fail -eq 0 ]] && echo "[OK] the storage node is application blind"
exit $fail


Mutation proof: add any one banned token to a node file and the gate fails, naming it.

**Gate:** the root register gate is rewritten

ci/root_register_refuses_posted_cq.sh argues from the conditional class check that step 1 deletes, so it
is replaced by ci/root_register_accepts_signed_claims_only.sh, and line 66 of ci/production_safety_
checks.sh points at the new file:
#!/usr/bin/env bash
# CI gate: the root register accepts only single root claims signed by the caller.
set -euo pipefail
node=dsm_storage_node/src/api/economic/root_register.rs
h=$(awk '/^pub async fn post_claim\(/{f=1} f{print} f&&/^\}/{exit}' "$node")
[[ -n "$h" ]] || { echo "[FAIL] post_claim not found"; exit 1; }
grep -q 'decode_and_verify_economic_root_claim' <<<"$h" \
|| { echo "[FAIL] post_claim no longer uses the signed single root decoder"; exit 1; }
if grep -q 'decode_registered_economic_claim' <<<"$h"; then
echo "[FAIL] post_claim decodes a claim kind that carries no caller signature"; exit 1
fi
grep -q 'verify_claim_attribution' "$node" || { echo "[FAIL] attribution check missing"; exit 1; }
echo "[OK] the root register accepts only caller signed single root claims"

> **Amendment S2 (owner, 2026-09-22) — this gate is retired.** The root register must not decode or verify caller signatures or check attribution. A node that can check the writer can block, and blocking is an authority a node must not have (§12; DSM Amendment A3). A root claim that is not signed by its device is not a claim; the reader verifies the signature in Core and ignores it.


**Gate:** build and tests
cargo clippy --workspace --all-features -- -D warnings.                          Dead imports are the expected failures; fix
them by deleting, never by adding a caller.


<!-- Source PDF page 41 -->


cargo test -p dsm_storage_node --release --no-default-features --features local-dev,strict:
surviving suites green, deleted suites gone from disk.
Positive control: bytes put into the immutable store come back byte identical.


<!-- spec-section: SOFI-041 -->
### 41 Step 2: stop and inspect
SoFi does not execute. Before anything is built, every remaining component is pointed at and justified.

Survivor                         Code                                  Kept because
immutable content addressed      NODE/api/objects/immutable.           stores and returns opaque bytes by hash, re-
store                            rs                                    computes the address on write and read, in-
terprets nothing
member and set identity          storage_set_id;         SDK/sdk/      needed to know which members hold a
storage_set.rs; register incarna-     vault’s cells
tion
raw register reads               read_register_cell,      SDK/sdk/     exact held bytes, absence or unavailable; the
storage_node_sdk.rs:1679; ob-         bytes prove themselves
servation types in CORE/economic/
cell_observation.rs
keyed cells                      NODE/db/write_once_                   rebuilt in step R2 to keep every value in ar-
properties.rs,         application    rival order; nothing is refused
blind entries only
atomic multi key transaction     NODE/db/binding.rs                    locking mechanics only, not their round re-
mechanics                                                              placement protocol
Core SoFi                        CORE/sofi/                            only what Parts III and IV define; anything
else is a demolition target
formal models                    tla/, lean4/                          corrected in step 3


<!-- spec-section: SOFI-041-1 -->
#### 41.1 Reachability at 817123c
Gate G1 (Section 37) run against the tree reports these public functions in CORE/sofi/ with no production caller
anywhere. Each is wired by a rebuild step or deleted.

File                           Functions with no production caller
admission.rs                   preimage_admissible
conformance.rs                 check_fulfillment_against_precommit
derive.rs                      vault_genesis_locator, setup_id, relationship_leaf_genesis, relationship_
index_key, setup_ref, policy_fulfillment_id, fulfillment_register_key,
route_outcome_key, successor_attempt_key, storage_seed, preimage_locator
fisher_yates.rs                first_member
lineage.rs                     advance_resolved, descendant_fence, genesis_accepted
resolution.rs                  effect_of, resolve_position
signature.rs                   verify_precommit, verify_operation
smt/fold.rs                    verify_batch
smt/store.rs                   validate_staged_frontier
smt/tree.rs                    verify, reachable
validation.rs                  route_validation
wire/mod.rs                    next_attempt, next_generation


Twenty five further functions are called only from inside CORE/sofi/, and consumed_route and validate have
callers that decide nothing (validate runs once, at SDK/sdk/sofi_sdk.rs:376, with Evidence::default(), and
discards Unavailable). Step 5 closes every entry; G1 passes before the lifecycle test runs.


<!-- Source PDF page 42 -->


<!-- spec-section: SOFI-042 -->
### 42 Step 3: the formal floor
TLA+ and Lean are corrected on the stripped design before any production code is rebuilt.

<!-- spec-section: SOFI-042-1 -->
#### 42.1 Delete first
Model state that exists only for what step 1 removed goes, and is not annotated: a registration record created by a
member; an authoritative outcome cell or Kout ; semantic node ingress; “a final cell implies registration”; any stor-
age prohibition on early cells; speculative producer behavior on unresolved parents; and any treatment of the five
members as peers whose answers are counted. Audit in particular every assumption of the form stored implies con-
forming or registered implies conforming. Outcome is derived Core state, never a stored register. Early cell occupancy
must be reachable in the model; early cell consumption must not be.

<!-- spec-section: SOFI-042-2 -->
#### 42.2 Then the invariants
- an unresolved conditional position is never a predecessor;
- stored is not valid; registered is not valid; an invalid stored artifact is never admitted;
- Realized requires every Core predicate;
- PositionPairAtomic: whenever a position is installed, no reachable state contains only one of Kful (q) and Kroot (q);
this is safety, with no liveness attached;
- FinalRequiresLeader: Final(K, x) implies LeaderHeld(K, x);
- AtMostOneFinalPerCoordinate;
- LeaderFromCommittedSet: the leader is a function of the seed and S only.


Mutation                                              What must fail, by name
producer builds on an unresolved predecessor          the producer invariant
SetupValid removed from RouteValidation               realized_requires_valid_setup
FulfillmentConformance dropped from Consume-          realized_requires_conformance
dRoute
registration treated as conformance                   registration_is_not_conformance
storage occupancy treated as validity                 early_cell_cannot_cause_consumption
the two halves of a position committed separately     PositionPairAtomic
finality counted without the leader                   FinalRequiresLeader, AtMostOneFinalPerCoordinate
leader chosen from an availability view               LeaderFromCommittedSet, AtMostOneFinalPerCoordinate


<!-- spec-section: SOFI-042-3 -->
#### 42.3 Two properties the floor must prove
Under the storage contract of Part II, bytes that are not an exercise naming the key count as nothing (Section 8),
and no key is ever dead. The formal floor models exactly that contract, not a store where arbitrary bytes can win a
coordinate, and proves the two properties below on it. A model in which a value that names no recoverable F or P
can become final at K (0) is a model of the wrong contract and is not used.
P1, OnlyExercisesCount. At every successor key, the only value that can be Final is an exercise (Section 17.5) whose F
names that key’s (v, a) and whose P names (v, Rn ); every other value at the key has no effect on SuccessorResolution,
and K (a+1) becomes live exactly when K (a) is skipped. In particular, no ladder can be stranded by a value Core
cannot classify.
P2, RegisteredFulfillmentCanBeCompletedByAnyone. Once F is registered, any party can write the exercise to every
remaining successor key; completion needs nothing from the trader, because there is no write authorization.
Both are proved on the floor in step 3 and checked as named tests in step 5: P1 in rebuild step R11, where nothing but
an exercise naming the key counts, and P2 in step R2, where no write carries an authorization.


<!-- Source PDF page 43 -->


<!-- spec-section: SOFI-042-4 -->
#### 42.4 Files and counts

**Code**
TLA+: tla/DSM_SofiSuccessorCells.tla (313 lines) and tla/DSM_SofiFulfillment.tla (585 lines) with
their configurations; every configuration whose premise is counting member answers is removed or rewritten.
Lean: lean4/DSMSofiAtomicity.lean, lean4/DSMSofiSuccessorCells.lean, lean4/DSMSofiReceipt.lean.
The registry count EXPECTED_STANDARD_SPECS = 58 (tools/vertical_validation/src/tla_runner.rs:34)
and the Lean module count expected=26 (.github/workflows/ci.yml:718) change with every file added or
removed.

**Gate**
Each invariant holds, and each falsification configuration violates exactly its named property. lean
-DwarningAsError=true on every module, no sorryAx; a proof free of sorry is not evidence on its own, the
mutation is.

<!-- spec-section: SOFI-043 -->
### 43 Step 4: the Core seam
This change is generic and is not built inside the SoFi rebuild. It implements Part VII.

<!-- spec-section: SOFI-043-1 -->
#### 43.1 Starting point in the tree
- The canonical preparation step is prepare_advance_relationship (CORE/core/state_machine/mod.rs:190).
It derives
en+1 = H(DSM/state-entropy; en ∥ op ∥ hn )
from the relationship tip, with en = H(DSM/genesis-entropy; root) and hn = root for a relationship with no
tip, then calls DeviceState::advance (CORE/types/device_state.rs:1812).
- DeviceState::advance takes entropy as a parameter, so a caller can pass its own.
- On the online path the receipt hash space takes the transfer nonce instead of the derived value (SDK/handlers/
app_router_impl.rs:1273, SDK/sdk/core_sdk.rs:3713).

The seam change removes the entropy parameter, puts the one derived value into the relationship tip and both receipt
hashes, keeps the transfer nonce in the operation bytes, and meets Section 39. Then the seam is frozen.

<!-- spec-section: SOFI-044 -->
### 44 Step 5: rebuild
Each step is its own pull request, in this order. Each answers the storage question, runs gates G1 to G5 for what it
touches, and mutation tests every binding it adds: coordinate, value digest, namespace, set id and entitlement each
turn a distinct named test red.

Step     Adds                             Code and gates
R1       objects and indexes            NODE/api/objects/immutable.rs and the index; address recomputation
on every write and read; Core keeps only candidates that verify
R2       storage keeps what it is given no write authorization anywhere; members never refuse, replace or com-
pare; every value kept in arrival order; a node that refuses a second value
fails a named test
R3       leader selection over the com- rewrites the module comment of CORE/sofi/fisher_yates.rs (lines 4 to
mitted set                     7), which calls the input a caller’s availability view; every caller passes S
from the vault state; the writer and Core compute the leader, never a node;
vectors; a test that availability never changes the leader
R4       Core       read       adapter: the winner at a key is the first object naming it at the leader; bytes that
LeaderHeld and Final           are not one count as nothing. Replaces the counting code: resolve (CORE/
sofi/arith.rs:48), observe_cell (CORE/economic/cell_observation.
rs:122), read_cell_quorum and claim counting (SDK/sdk/economic_
registers.rs:222), quorum (SDK/sdk/storage_set.rs:149), quorum_
for (SDK/storage/client_db/publication.rs:75), answer_counts_for
(SDK/sdk/storage_node_sdk.rs:733). Mutation: finality without the
leader fails a named test.


<!-- Source PDF page 44 -->


Step     Adds                              Code and gates
R5       real evidence acquisition         Evidence built only from fetched bytes; Default test only (G2); G3
R6       the producer fails closed         SDK/sdk/sofi_sdk.rs:376 validates with real evidence and stops on
Unavailable (T5, G5)
R7       Core FulfillmentConformance       the full predicate of Part IV, one named test per item
R8       publication of P , G, F and       build_setup (SDK/sdk/sofi_sdk.rs:210) publishes and indexes the
the setup body                    setup body, which it does not at 817123c (line 266)
R9       the two position cells            Kful (q) and Kroot (q) written together at the leader of s(q); Cq computed
from F and P ; PositionPairAtomic as a test
R10      Core derived FulfillmentRegis-    Final at Kful (q); no member writes a registration
tered
R11      the exercise                 class 0x005D, SOFI_EXERCISE (Section 17.5), written to every successor key;
nothing but an exercise naming the key counts; discharges P1
R12      Core consumption and resolu- adds the FulfillmentConformance conjunct to consumed_route
tion                         (CORE/sofi/resolution.rs:216); wires consumed_route and resolve_
position (:284) into production; realized_requires_conformance as a
Rust test
R13      advance_resolved through CORE/sofi/lineage.rs:114; G4
the frozen seam
R14      the lifecycle end to end     the device scenarios below; G1 passes with no exceptions


<!-- spec-section: SOFI-044-1 -->
#### 44.1 Device scenarios for R14
1. P published, witnesses computed, never fulfilled: no economic effect; parents stay usable.
2. A rival consumes RA after the witnesses and before F ; F registers anyway and resolves Void with RouteValida-
tion Valid; no leg is consumed.
3. F missing one witness: the bytes may be stored; FulfillmentConformance is Invalid; it never realizes.
4. F registered, trader offline: a relayer completes the cells and the position resolves.
5. Two fulfillments from one T0 : the leader of the pair holds one; at most one registers.
6. A witness for P reused in a fulfillment of P ′ : Core refuses it; storing it proves nothing.
7. Two traders against one DLV parent: exactly one realizes, the other resolves Void, no partial route.
8. F reaches the leader, the trader crashes, no rival: relayers finish the copies and Core derives registration.
9. F on members other than the leader while a rival F ′ reaches the leader: F ′ is the exercise; F never registers.
10. A flood of malformed auxiliary candidates: the valid one still stores and verifies; budgets give Unavailable, never
Invalid.
11. A registered route loses a parent while evidence is withheld: the position is not resolved, and each attempt fails on
the network when its retries are exhausted, never Void; published
valid evidence gives Void, invalid gives Invalid.
12. The leader of a coordinate is offline: the coordinate waits; no other member stands in.

<!-- spec-section: SOFI-045 -->
### 45 Step 6: cutover
The market settlement machinery that SoFi replaces is mapped by reverse dependency and every item is deleted or
replaced; nothing is kept for compatibility. Known members of that map: SDK/sdk/quorum_bind_runner.rs,
SDK/sdk/settlement_bind.rs,         SDK/sdk/binding_occupancy.rs,        SDK/sdk/binding_http_transport.rs,
SDK/sdk/binding_fleet_double.rs, SDK/sdk/settlement_resume.rs, SDK/storage/client_db/dlv_lineage_
quarantine.rs, their callers in SDK/handlers/dlv_routes.rs and SDK/handlers/storage_routes.rs, and lean4/
DSMBindingValueContinuity.lean; the old SoFi app surface: sofi.launch in SDK/handlers/sofi_routes.rs,
route.findAndBindBestPath and dlv.unlockRouted in SDK/handlers/route_routes.rs, the routing profile
SDK/sdk/sofi_profile.rs, the receipt publication SDK/sdk/sofi_receipt_publication.rs, and path search over
advertisements ranked by state number in SDK/sdk/routing_path_sdk.rs. Class numbers they free are burned.
Operational cutover is blue and green, with the handshake.


<!-- Source PDF page 45 -->


<!-- spec-section: SOFI-046 -->
### 46 Not in this work
Coordinate burn surfaces outside SoFi that accept unauthenticated writes are triaged separately: dlv/{dlv}/slot,
recovery/authority-anchor, tips/*, devtree/root, bytecommit/publish, device/register. Storage member re-
placement is not specified; DSM/sofi/membership-handover/v1 is reserved for it.

> **Note (2026-09-22).** Member replacement is now specified in `DSM_Storage_Node_Specification.md` §12; the reserved tag becomes SoFi's encoding of its handover (§12.5).


## Part IX — Token policy
A token’s policy is part of what makes a transition impossible to fake. The policy is the token’s identity: every balance,
every issuance and every vault names a token by the hash of its whole policy, so a transition can never move a token
under rules other than its own.
**Rule — a token policy and a DLV are two different things**

A token policy creates a tokenized asset. It defines the token, its supply and its rules. It is anchored to its
creator’s state, but the creator does not own it; by the standard policy, the creator locks itself out completely.
A DLV is one owner and what that owner holds and puts up as liquidity, under the owner’s own conditions,
such as fees, which will often be the same common terms everyone uses. A DLV needs no token policy of its own:
its market policy points to the anchors of the tokens it trades, their policy commits. An owner has a token policy
of their own only if they created the token they provide liquidity for, which is rarely the case.


<!-- spec-section: SOFI-047 -->
### 47 What a token policy is
Rust packs one canonical blob, the only packer for the format (build_policy_v3_bytes, SDK/handlers/token_
routes.rs). All integers are big endian.


Field                                 Meaning
version, kind                         3, and 0 for fungible
supply class                          native, or externally backed (Section 48)
flags                                 transferable; recipient allowlist present
release rule                          native tokens only: the conditions, committed in the policy, under which units
not yet released come out. The standard policy locks the issuer out completely
signer set and threshold              the k of n keys, 1 ≤ n ≤ 16; they authorize only what the policy’s own rules
name, and the standard release rule names none
ticker, alias                         2 to 8 characters; a display name
decimals                              0 to 18
genesis supply                        native tokens only: Sgenesis , the whole supply that will ever exist, in base units
backing rule                          externally backed tokens only: what must be proven locked for issuance to be
admissible, and what a redemption releases
description, icon                     display
recipient allowlist                   none, or an inline list of device ids that may receive issuance


**Rule**
The token’s identity is policy_commit, the hash of the whole blob. Any field that differs makes a different token.
The ticker is display only; two tokens may share one.

> **Amendment S8 (owner, 2026-09-23) — the policy names its creator, and a token is created once.** The policy blob also commits the creator: the genesis `G` and device id `DevID` of the device that creates the token, placed after the release rule. A native token's genesis release is admissible only in a `CreateToken` of that device, so anyone else holding the same policy bytes releases nothing. The creating transition also inserts a creation record for the policy commit into the creator's economic tree, from zero (class `0x0060`, key `H(DSM/economic-token-creation-key/v1; G ∥ DevID ∥ policy_commit)`). Its presence under a validated root proves the creation, and a second creation of the same commit on that lineage cannot build its write set. The economic-root register keeps the lineage unforked, so the genesis supply is released exactly once.

> **Amendment S11 (owner, 2026-09-26) — a network-anchored native token names no creator and no signer set; ERA's policy.** A native token whose releases are anchored to the network rather than to a creating device names no creator and no signer set: its blob omits the creator of Amendment S8 and the signer set and threshold of the table above, going from the release rule straight to the ticker, and its release rule alone governs every release. Exactly one such policy exists, ERA's, fixed in Core and checked by its commitment; any other network-anchored blob has no reserve and releases nothing, and it is never registered, adopted or published. The creator and the signer set belong to device-created tokens (release rule all-at-creation), whose layout is unchanged.
>
> ERA's policy: version 3, fungible, native; transferable and burnable; no recipient allowlist; release rule the beta faucet, under which units come out of the network's reserve by faucet claims; ticker and alias `ERA`; decimals 0; genesis supply 80,000,000,000 (owner, 2026-09-26); no description and no icon. Every device holds these bytes by construction. Their commitment, `BLAKE3(DSM/policy ‖ 0x00 ‖ TokenPolicyV3 bytes)`, is `JXPMPGJH45HDTE0ARWE2CTB9E9BWTQZ3T78CE5RFF1RXMR9VKK80` (Crockford base32). The faucet's per-claim payout is fixed by Core's beta claim policy and is not committed in the blob. The reserve's accounting is: the reserve starts at the genesis supply, every release is counted against it, the reserve is exhausted exactly when all of it has been released, and at exhaustion a claim is refused before anything is signed or written. ERA's previous commitment was the hash of empty input and committed to no policy; it is replaced.
>
> **Amendment S18 (owner, 2026-10-01) — ERA has two decimals.** ERA is divisible to hundredths: its policy's decimals are 2, and every ERA amount is held in base units of 0.01 ERA. The amounts people know are unchanged: the genesis supply is 80,000,000,000.00 ERA, which the policy states in base units as 8,000,000,000,000; one beta faucet claim releases 100.00 ERA (10,000 base units); the token creation fee is 10.00 ERA (1,000 base units). The rest of S11's policy is unchanged. ERA's commitment changes with its bytes, to `NNG176RZ6ACTWCDPRNYHXZK2DCZ72SPA9Q6XWGRGQ9JGKZYTESG0` (Crockford base32), and replaces S11's; by S11's rule this is a different ERA identity, so no balance under the old commitment carries over (a clean cut). Amounts are entered and shown in whole tokens with the token's decimals after a point, `100.00` for ERA, never as base units.
>
> Open: join-triggered emission (DJTE) replaces the faucet after beta. That is a different release rule, so a different blob, and by the rule above that any differing field makes a different token, a different ERA identity.

**Code**
Balances are keyed by policy_commit (the economic balance leaf; CORE/sofi/validation.rs:553). Issuance
binds it. A vault’s market policy names its two tokens by token_a_policy_commit and token_b_policy_commit
(MarketPolicy, CORE/ccb/state.rs), and the vault state commits the market policy by content address.


<!-- Source PDF page 46 -->


<!-- spec-section: SOFI-048 -->
### 48 Two kinds of supply
Every token belongs to exactly one supply class, fixed in its policy. The two classes bound supply in different ways,
and neither has an unlimited option.

Symbol                  Meaning
Sgenesis                a native token’s whole supply, fixed in its policy
R                       the units not yet released under a native token’s policy
P
B                    the sum of every balance holding the token, vaults included
D                       for a native token, the units destroyed by burns; for an externally backed token, the units out-
standing
Lproven                 the external value an externally backed token’s policy accepts as proven locked, net of what has
been redeemed


**Rule — native tokens**
X
Sgenesis = R +       B+D        at every state.
There is no minting after genesis. Emission is a release under the token’s own committed policy. The policy is
anchored to the issuer’s state, but the issuer does not own it.

**Rule — externally backed tokens**

Doutstanding ≤ Lproven ,
and for dBTC, one for one under its intended construction,

Doutstanding = Leligible BTC ,

subject to the exact lock and redeem state DSM commits. The policy fixes the issuance rule, not a reserve: there
is no pre-existing pool holding all future units. Additional units become admissible only because corresponding
value has been locked and proven.


<!-- spec-section: SOFI-049 -->
### 49 What each rule governs

Rule                           Governs                                           Checked by the constructor on
supply class                   which of the two supply rules applies             token creation, and every issuance
genesis supply (native)        the total that can ever exist                     token creation, which fixes it in the policy
release rule (native)          when units not yet released come out              every release
backing rule (externally       when issuance is admissible, and what a           every issuance and every redemption
backed)                        redemption releases
signer set and threshold       only what the policy’s own rules name             every operation those rules name
transferable                   whether the token may move between                every transfer, online and offline; vault
holders                                           creation; every SoFi leg for both tokens
of its vault (check_market_leg_permitted,
CORE/economic/issuance.rs:359)
recipient allowlist            who may receive issuance; it has no mar-          every issuance
ket meaning, and a token trades freely
once issued
decimals, ticker, alias, de-   identity and display                              nothing beyond identity
scription, icon


<!-- Source PDF page 47 -->


<!-- spec-section: SOFI-050 -->
### 50 The mandatory baseline
**Rule**
Every token policy states: its version and kind; its supply class; its decimals; whether it is transferable; and its
recipient allowlist, or that it has none. A native token’s policy also states its genesis supply and its release rule.
An externally backed token’s policy also states its backing rule. The constructor refuses to create a token whose
policy omits any of these. Neither class has unlimited supply: a native token is bounded by its genesis supply,
an externally backed token by what is proven locked.


<!-- spec-section: SOFI-051 -->
### 51 Native supply
**Rule — supply under a locked policy**

1. The genesis supply is fixed in the token’s policy, and so in its identity.
2. The policy is anchored to the issuer’s state when the token is created, but the issuer does not own it. By
the standard policy the issuer locks itself out completely: it cannot change the policy and cannot take units
outside its rules.
3. Units not yet released come out only when the conditions committed in the policy are met, and anyone can
verify them by recomputing. For ERA, the conditions are its emission schedule (after beta; in beta, the faucet — Amendment S11).
4. A burn destroys the units it burns. They never return to the unreleased supply, so the total ever released
only grows.

**Rule — read each policy individually**

Every token’s rules are the ones committed in its own policy. A verifier reads that policy and recomputes what
it says. It trusts the policy because the policy is committed and verified, never because of what policies usually
say: no rule is assumed from another token, from a default, or from the standard.

**Why**
- Supply cannot exceed genesis. Every release is a transition the constructor builds under the policy’s rules,
so a release the policy does not allow cannot exist, and the identity above holds at every state.
- The issuer cannot drain it. The issuer is locked out, so a stolen issuer key releases nothing.
- Holders know their worst case. The genesis supply and the release rule are part of the token’s identity, so
anyone accepting the token knows the most that can ever exist and how it can come out.
- Nothing needs to track circulating supply. Because burns never return units to the unreleased supply,
the only number that matters is what remains unreleased.

**Code**
ERA is native: its policy (Amendment S11) fixes its genesis supply, and every release, the beta faucet's and later emission's, comes out of the network's reserve.

> **Amendment S23 (owner, 2026-10-07).** The reserve is a shared lineage of kind 2: its generations are found from its genesis by the same discovery as a vault's (§30, Amendment S23), and each is established by `release_constructible` from the generation before it, as before. Its hints and checkpoints carry no authority.

<!-- spec-section: SOFI-052 -->
### 52 Externally backed supply
**Rule**
1. Issuance is admissible only against a lock that the policy’s backing rule accepts as proven, for exactly the
amount proven.
2. Each proven lock admits its amount once. The lock is a consumed resource: its consumption key is derived
from the lock itself, so two issuances against one lock collide and only one is recorded.
3. A redemption burns units in the same transition that releases the matching backing. Backing is never re-
leased without the burn, and units are never burned without the release.


<!-- Source PDF page 48 -->


**Why**
Outstanding units can never exceed what is proven locked, because every unit entered against a proven lock
and every exit burns what it releases. No reserve of future units exists to be stolen, and the policy never has to
predict how much will be locked.

**Code**
dBTC is externally backed.          Its backing parameters are frozen into its policy through
PolicyCondition::BitcoinTapConstraint     (CORE/types/policy_types.rs): maximum successor depth,
minimum vault balance, dust floor and minimum confirmations.

<!-- spec-section: SOFI-053 -->
### 53 Raising supply
This applies to native tokens; an externally backed token grows only with its backing. A native token’s genesis supply
never changes, so a token that needs more supply is a new token.
**Rule**
1. Create the new token, with its own policy and its own genesis supply.
2. The new token’s policy commits a conversion rule: it releases the new token for the old one, one for one, and
the old units it takes in are locked for good.
3. The conversion rule is part of the new token’s policy, so it is anchored and locked like the rest of the policy.
It is not a DLV: a DLV’s owner could close it and take the old units back.
4. The new token’s policy names the old token’s policy_commit; that is the only link between them.

**Why**
Nobody is diluted without choosing to convert. Old balances and old vaults keep working unchanged, because
nothing about the old token changed. Each conversion consumes the old units for good in the same transition
that releases the new ones, so the same value never circulates twice.

<!-- spec-section: SOFI-054 -->
### 54 What changes in the tree
- The policy blob gains the supply class. The unlimited flag and the unlimited branch of SupplyCap are deleted.
- Native tokens:        issuance stops refusing a finite supply (IssuancePolicyRefusal::FiniteSupplyCap,
CORE/economic/issuance.rs:130).          Token creation anchors the policy, with its whole genesis supply, to
the issuer’s state in the same transition that creates the token, and issuance becomes a release under the policy’s
release rule. The issuer’s signer set no longer authorizes issuance. There is no mint operation after genesis, and
no DLV is involved.
- Externally backed tokens: issuance stays tied to proven locks under the policy’s backing rule, with each lock
consumed once, and redemption burns in the same transition as its release.
- The mint and burn flag governs burns only.
- check_market_leg_permitted runs for both tokens of every vault on every SoFi leg, and on vault creation.
- Each change lands with a named test that fails when the rule is removed.

A What remains open
Nothing. Every question this design raises is settled by the attributes of its objects (Read this first). Storage member
replacement is not part of this work; DSM/sofi/membership-handover/v1 is reserved for it.

> **Note (2026-09-22).** Superseded. Open items are listed in `DSM_Storage_Node_Specification.md` §24, and member replacement is specified there (Part III).
