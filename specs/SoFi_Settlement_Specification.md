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
| Authorship | setup, P and F carry `genesis`, `device_id` (through P for F) and `claimant_public_key` inside the body; the signature covers the canonical body in a `SignedSofiObject`; signing is deterministic (randomizer `H(sk_prf ∥ m)`, `CORE/crypto/sphincs.rs:889`), so one body has exactly one valid envelope | forgery, misattribution, a second version of the same object |
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
TAG_DSM_SOFI_VAULT_CREATION_KEY               DSM/sofi/vault-creation-key/v1            key of the creation leaf
TAG_DSM_SOFI_VAULT_STATE_KEY                  DSM/sofi/vault-state-key/v1               key of the vault state leaf
TAG_DSM_SOFI_VAULT_LEAF_STATE                 DSM/sofi/vault-leaf-state/v1              DLV leaf values


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


<!-- Source PDF page 19 -->


<!-- spec-section: SOFI-014-3 -->
#### 14.3 Signed objects
A signed SoFi body travels in SignedSofiObject = (body_class, body_ccb, signature_alg, signature), CORE/sofi/
wire/objects.rs:638. Identities are always computed over the canonical body bytes, never over the envelope, so a
second valid signature over the same body is the same object. Signing is deterministic: the SPHINCS+ randomizer is
H(sk_prf ∥ m) (CORE/crypto/sphincs.rs:889), so at most one valid envelope exists per body.

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

> **Recommendation (owner, 2026-09-23) — not a rule.** Every vault must honour the policy of each of its tokens; that is a rule, not a choice (§49, MR-SOFI-0311). Within those policies, owners are encouraged to set up their vaults for a token in line with the rest of the market for that token, with only minor differences, so that their liquidity is usable by multihop routes and other traders' paths. Nothing enforces this, and no check depends on it.

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
and where its effect lands in the output. Evidence (CORE/sofi/validation.rs:228) carries three of the items as
maps: objects (policy objects by address), trader_leaves (trader leaf pre values by key) and vault_leaves (vault
leaf pre values by vault and key).

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
trader leaf pre         Evidence.trader_            compared with the entries of T ◦     TraderSideValid                 pre root of T ◦
values                  leaves
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
routes.rs:129). All integers are big endian.


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
verify them by recomputing. For ERA, the conditions are its emission schedule.
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
ERA is native: its emission schedule fixes its total (EmissionsSchedule.total_supply), and emission is release.

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
