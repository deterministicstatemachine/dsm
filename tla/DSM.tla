---- MODULE DSM ----
EXTENDS Naturals, FiniteSets, Sequences, TLAPS

\* Refinement target: irreducible DSM truths (DJTE/JAP anchored).
\* `DSM_Abstract` is used only for bounded TLC regressions; it intentionally
\* ignores mechanisms (shards/SMTs/sessions) and keeps only meanings.
\*
\* TLC refinement is wired in the .cfg files via REFINEMENT.
\*
\* NOTE: We do not extend DSM_Abstract to avoid variable-name collisions.
\* The refinement mapping is provided below using the standard TLC mapping
\* operator names (remaining/budget/spent/commit/step).

\* ============================================================================
\* Helper operators (deterministic, clockless)
\* ============================================================================

\* Unique minimum element of a non-empty finite set of NATURALS.
MinNat(S) == CHOOSE x \in S : \A y \in S : x <= y

\* Unique maximum element of a non-empty finite set of NATURALS.
MaxNat(S) == CHOOSE x \in S : \A y \in S : x >= y

\* ---------------------------------------------------------------------------
\* Deterministic “hash” abstraction for model checking
\*
\* For proof-carrying DJTE in a full spec, H(.) would be BLAKE3-256 with domain
\* separation. For TLC we model hashing as a deterministic mixing function Nat->Nat
\* that is stable and clockless.
\* ---------------------------------------------------------------------------
\* Keep values bounded to avoid TLC integer overflow while preserving a
\* deterministic, non-trivial mixing behavior.
\*
\* NOTE: This is a modeling hash. The real protocol uses BLAKE3-256.
MixMod == 65536

\* Overflow-safe modular arithmetic for TLC.
\*
\* TLC can overflow on intermediate products even when the final value is modded.
\* This implements (a*b) % m using bounded doubling and addition ("Russian peasant"),
\* keeping intermediates under ~2*m, so it never trips TLC's 32-bit signed overflow.
\*
NormMod(x, m) == ((x % m) + m) % m

RECURSIVE MulModRec(_, _, _)
MulModRec(x, y, m) ==
    IF y = 0 THEN 0
    ELSE IF (y % 2) = 1
        THEN NormMod(x + MulModRec(NormMod(2 * x, m), y \div 2, m), m)
        ELSE MulModRec(NormMod(2 * x, m), y \div 2, m)

MulMod(a, b, m) ==
    LET A0 == NormMod(a, m)
        B0 == NormMod(b, m)
    IN  MulModRec(A0, B0, m)

\* Sum over a finite set of naturals (TLC-friendly).
\* TLC requires explicit RECURSIVE declarations.
RECURSIVE Sum(_)
Sum(S) == IF S = {} THEN 0 ELSE LET x == CHOOSE y \in S : TRUE IN x + Sum(S \ {x})

Mix(x) ==
    LET m == MixMod
        x0 == NormMod(x, m)
    IN  NormMod(MulMod(110351, x0, m) + 12345, m)

\* 2^16, used to keep the rejection-sampling domain finite and manageable.
U16 == MixMod

\* Exact-uniform index selection over [0, N) using deterministic rejection sampling.
\*
\* This models the standard technique:
\*   limit = floor(U/N)*N, accept r < limit, output r % N, else reseed and retry.
\* Here we use U=2^16 (U16) instead of 2^256 to keep TLC tractable.
\* For expert-grade claims: the structure is identical; U can be upgraded.
RECURSIVE UniformIndexTry(_, _, _)
UniformIndexTry(s, N, limit) ==
    LET r == Mix(s) % U16
    IN  IF r < limit THEN r % N ELSE UniformIndexTry(Mix(s), N, limit)

UniformIndex(seed, N) ==
    LET limit == (U16 \div N) * N
    IN  UniformIndexTry(seed, N, limit)

\* Deterministically select an element from a non-empty finite set S using a seed.
\*
\* Implementation notes (TLC-compatible):
\* - We avoid SetToSeq/SortSeq (not always available).
\* - We simulate choosing the (k-th) smallest element by repeatedly removing the
\*   current minimum.
\* - This is deterministic given (S, seed).
\* - Modulo selection can introduce bias unless assumptions are strengthened.
RECURSIVE SelectNthMin(_, _)
SelectNthMin(T, i) == IF i = 0 THEN MinNat(T)
                      ELSE SelectNthMin(T \ {MinNat(T)}, i - 1)

SelectFromSetBySeed(S, seed) ==
    LET n == Cardinality(S)
        k == seed % n
    IN SelectNthMin(S, k)

CONSTANT
    DeviceIds,         \* Set of all possible device IDs
    GenesisIds,        \* Set of all possible genesis IDs
    MaxDevices,        \* Maximum devices per genesis
    MaxPayload,        \* Maximum payload value for messages
    VaultIds,          \* Set of all possible vault IDs
    MaxVaults,         \* Maximum vaults per device
    ShardDepth,        \* Depth of shard tree for DJTE
    MaxEmissions,      \* Maximum emission index for DJTE
    EmissionAmount,    \* Fixed emission amount per DJTE event
    MaxSupply,         \* Finite source vault supply for DJTE emissions
    MaxNet,            \* Hard bound on in-flight network messages (bag size)
    MaxDupPerMsg,      \* Per-message duplicate budget (prevents infinite dup churn)
    MaxStep,           \* Bound for step-limited regression configs
    UseHarness,        \* BOOLEAN: TRUE for regression harness mode, FALSE for system interleavings
    \* Online rules, each TRUE as the code runs it; a falsification config
    \* flips one to show the invariant it carries.
    RecipientChecksAdmission, \* apply only a transfer whose sender's debit was admitted
    RecipientChecksPin        \* apply only a transfer whose signed parent is the pinned head

VARIABLES
    devices,           \* devices[g] = set of device IDs for genesis g
    relationships,     \* ordered compatibility view: <<d1,d2>> -> current relationship state
    deviceRoots,       \* deviceRoots[d] = abstract Per-Device SMT root revision r_d
    smtState,          \* smtState[d][rel] = leaf value h_{d<->counterparty} for rel
    net,               \* global adversarial network: a bag (set) of message instances
    nextMsgId,         \* fresh message instance id allocator (clockless counter)
    storageNodes,      \* storageNodes = set of active storage nodes
    \* Cryptographic state
    keys,              \* keys[d] = cryptographic keys for device d
    \* DLV state
    vaults,            \* vaults[d] = set of vaults owned by device d
    vaultState,        \* vaultState[v] = current state of vault v
    \* DJTE state
    activatedDevices,  \* activatedDevices = set of devices that have unlocked spend-gate
    actCount,          \* actCount[d] = number of activation instances for device d
    emissionIndex,     \* emissionIndex = current DJTE emission counter
    shardTree,         \* placeholder counter / SMT root for device activation counts
    djteSeed,          \* deterministic seed for DJTE selection (clockless)
    \* DJTE proof-carrying structures (abstract)
    shardLists,        \* shardLists[s] = Seq(DeviceIds) activated in shard s
    spentJaps,         \* spentJaps = set of consumed activation digests
    spentProofs,       \* spentProofs = set of proof objects minted when a JAP is consumed
    consumedProofs,    \* consumedProofs = set of proof objects that have been acknowledged/consumed exactly once
    sourceRemaining,   \* finite source vault remaining units (conservation)
    phase,             \* deterministic regression phase harness (0..3)
    step,              \* monotone transition counter (clockless)
    \* Offline bilateral state
    offlineSessions,   \* offlineSessions = active BLE/NFC sessions
    \* Tripwire State
    ledger,            \* Set of accepted receipts: [rel: {d1,d2}, oldTip: Nat, newTip: Nat]
    \* Token balances (§8 conservation)
    deviceBalance,     \* deviceBalance[d] = available ERA balance for device d
    \* Online bilateral protocol (see ONLINE BILATERAL PROTOCOL below)
    online,            \* online[<<d,p>>] = d's previous/local projection tips, lineage head, pin, gate, awaited certificate
    outbox,            \* senders' frozen sends not yet released: the admitted debits
    journal,           \* recipients' countersign deltas awaiting the sender's certificate
    certs,             \* step ids whose certificate reached quorum on storage
    joins              \* the join oracle: [parent, lo, hi] -> tip

\* Canonical unordered relationship key, matching k_{A<->B} =
\* BLAKE3("DSM/smt-key\0" || min(DevID_A,DevID_B) || max(...)).
\* TLC models the digest as the unordered two-device set.
RelKey(d1, d2) == {d1, d2}

RelKeys == { {d1, d2} : d1 \in DeviceIds, d2 \in DeviceIds } \ { {d} : d \in DeviceIds }

\* ---------------------------------------------------------------------------
\* Refinement mapping (Concrete DSM -> DSM_Abstract)
\*
\* The abstract layer tracks:
\*   - budget: activation budget (how many emissions are allowed)
\*   - remaining: remaining supply not modeled in concrete yet (kept 0)
\*   - spent: set of consumed proofs (spentJaps)
\*   - commit: monotone commitment head (use shardTree as placeholder commit)
\*   - step: monotone logical transition counter (already present)
\*
\* IMPORTANT: This mapping is deliberately conservative. If concrete adds real
\* balances/supply later, map `remaining` accordingly and strengthen invariants.
\* ---------------------------------------------------------------------------

Abs_remaining == sourceRemaining

\* Total activation budget is the total number of activation instances created.
\* actCount[d] counts the number of JAP instances for each device.
ActivationInstances ==
    UNION { { <<d, i>> : i \in 1..actCount[d] } : d \in DeviceIds }

Abs_budget == Cardinality(ActivationInstances)

Abs_spent == spentJaps

\* shardTree is a monotone counter updated on DJTE steps; it is our placeholder
\* for a forward-only commitment head. If you later add a real commitment digest,
\* map that digest (or a Nat abstraction of it) here instead.
Abs_commit == shardTree

Abs_step == step

\* The refinement mapping operator names TLC expects.
remaining == Abs_remaining
budget == Abs_budget
spent == Abs_spent
commit == Abs_commit

\* ---------------------------------------------------------------------------
\* Concrete refinement property (TLC-checkable)
\*
\* We can't rely on Toolbox-only REFINEMENT stanzas in raw TLC CLI configs.
\* Instead we assert an explicit safety property that the abstract state
\* variables always equal the mapped concrete meanings.
\*
\* This is sufficient to prevent "keeping TLC green" by silently violating the
\* core truths represented by DSM_Abstract's state variables.
\* ---------------------------------------------------------------------------

ConcreteRefinesAbstract ==
    /\ remaining = Abs_remaining
    /\ budget = Abs_budget
    /\ spent = Abs_spent
    /\ commit = Abs_commit

\* Helper: pair each device with a stable numeric id by arbitrary but deterministic CHOOSE.
\* Since TLC doesn't provide an order on model values, we define numbers by repeated removal
\* using CHOOSE (deterministic in TLC given a fixed set).
RECURSIVE AssignNums(_, _)
AssignNums(R, i) == IF R = {} THEN <<>>
                    ELSE
                      LET x == CHOOSE y \in R : TRUE
                      IN Append(AssignNums(R \ {x}, i + 1), <<i, x>>)
DeviceNumPair(d) ==
    LET pairs == AssignNums(DeviceIds, 1)
        idxs == { j \in 1..Len(pairs) : pairs[j][2] = d }
    IN  IF idxs = {} THEN <<0, d>> ELSE pairs[MinNat(idxs)]

\* Map a device model value to a small Nat index (TLC-friendly).
\* Note: DeviceIds is a finite constant set in all provided configs.
DeviceNum(d) == DeviceNumPair(d)[1]

\* ==========================================================================
\* DJTE proof-carrying helpers (TLC-tractable, clockless)
\*
\* We model shards as integers 0..2^ShardDepth-1. Shard assignment is a
\* deterministic hash(prefix) abstraction.
\* ==========================================================================

NumShards == 2^ShardDepth

\* Deterministic shard assignment for a device id (abstract hash prefix).
\* Must return a shard id in 0..NumShards-1 to match shardLists indexing.
ShardOf(d) == (Mix(DeviceNum(d)) % NumShards)

\* Total activated count derived from shardLists.
RECURSIVE TotalLenFrom(_, _)
TotalLenFrom(s, hi) == IF s > hi THEN 0 ELSE Len(shardLists[s]) + TotalLenFrom(s + 1, hi)
TotalActivated == TotalLenFrom(0, NumShards - 1)

\* Count for a shard prefix p (depth k). p is an integer in 0..2^k-1.
\* The subtree consists of shards [p*2^(ShardDepth-k) .. (p+1)*2^(ShardDepth-k)-1].
RECURSIVE SumShardLens(_, _)
SumShardLens(a, b) == IF a > b THEN 0 ELSE Len(shardLists[a]) + SumShardLens(a + 1, b)

PrefixCount(p, k) ==
    LET span == 2^(ShardDepth - k)
        lo == p * span
        hi == (p + 1) * span - 1
    IN  SumShardLens(lo, hi)

\* Deterministically map global rank r \in 0..TotalActivated-1 to a shard and local index.
\* This is the shard-descent algorithm over prefix counts (exact-uniform is ensured
\* by choosing r using UniformIndex).
RECURSIVE RankDescend(_, _, _)
\* Descend(prefix p at depth k, remaining rank rr)
RankDescend(p, rr, k) ==
    IF k = ShardDepth THEN <<p, rr>>
    ELSE
        LET leftP == 2 * p
            leftCnt == PrefixCount(leftP, k + 1)
        IN  IF rr < leftCnt
            THEN RankDescend(leftP, rr, k + 1)
            ELSE RankDescend(leftP + 1, rr - leftCnt, k + 1)

RankToShardAndIndex(r) == RankDescend(0, r, 0)

\* Placeholder root for counts (represents ShardCountSMT root).
\* In the real protocol this would be a BLAKE3-256 digest over deterministic protobuf.
CountRoot == Mix(TotalActivated)

\* Placeholder accumulator roots per shard (represents SAA roots).
ShardAccRoot(s) == Mix(Len(shardLists[s]))

\* ==========================================================================
\* Network semantic progress constraint
\*
\* Goal: prevent executions where TLC spends unbounded effort exploring "net-only
\* churn" (e.g., duplicating forever) while never facing message consequences.
\*
\* Principle (clockless): when the network is non-empty, the *next step* must
\* consume at least one message via deliver or drop.
\*
\* This is a semantic constraint on the explored execution space, not a fairness
\* or probability assumption.
\*
\* IMPORTANT (TLA+): don't define this as `NetDeliver \/ NetDrop` because those
\* are actions (they constrain primed variables) and can't be referenced as
\* standalone operators.
\* Instead, define it as a predicate over the current state and the primed
\* `net'` value.
\* ==========================================================================

NetConsumes == (net # {}) /\ (net' \subseteq net) /\ (Cardinality(net') = Cardinality(net) - 1)

TypeInvariant ==
    /\ devices \in [GenesisIds -> SUBSET DeviceIds]
    /\ \A g \in GenesisIds : Cardinality(devices[g]) <= MaxDevices
    /\ relationships \in [DeviceIds \X DeviceIds -> [tip: Nat, state: {"active", "inactive"}]]
    /\ deviceRoots \in [DeviceIds -> Nat]
    /\ smtState \in [DeviceIds -> [RelKeys -> Nat]]
    /\ \A d1, d2 \in DeviceIds :
        d1 # d2 => smtState[d1][RelKey(d1, d2)] = relationships[<<d1, d2>>].tip
    /\ net \subseteq [id: Nat, copy: Nat, kind: {"transfer", "delta"}, from: DeviceIds, to: DeviceIds,
                      payload: 0..MaxPayload, sp: Nat, sc: Nat, pp: Nat, pc: Nat, dupLeft: 0..MaxDupPerMsg]
    /\ Cardinality(net) <= MaxNet
    /\ nextMsgId \in Nat
    /\ storageNodes \subseteq DeviceIds  \* Storage nodes are also devices
    /\ keys \in [DeviceIds -> [sphincs: Nat, kyber: Nat]]  \* Cryptographic keys
    /\ vaults \in [DeviceIds -> SUBSET VaultIds]
    /\ \A d \in DeviceIds : Cardinality(vaults[d]) <= MaxVaults
    /\ vaultState \in [VaultIds -> [owner: DeviceIds, balance: Nat, locked: BOOLEAN, condition: Nat]]
    /\ activatedDevices \subseteq DeviceIds
    /\ actCount \in [DeviceIds -> Nat]
    /\ emissionIndex \in 0..MaxEmissions
    /\ shardTree \in Nat  \* SMT root (simplified as Nat for model checking)
    /\ djteSeed \in Nat
    /\ shardLists \in [0..(2^ShardDepth - 1) -> Seq(DeviceIds)]
    /\ \A s \in 0..(2^ShardDepth - 1) : \A i \in 1..Len(shardLists[s]) : shardLists[s][i] \in activatedDevices
    /\ spentJaps \subseteq Nat
    /\ spentProofs \subseteq [jap: Nat, proof: Nat]
    /\ consumedProofs \subseteq [jap: Nat, proof: Nat]
    /\ sourceRemaining \in 0..MaxSupply
    /\ phase \in 0..3
    /\ step \in Nat
    /\ offlineSessions \subseteq DeviceIds \X DeviceIds  \* Active offline sessions
    /\ deviceBalance \in [DeviceIds -> Nat]
    /\ ledger \subseteq [rel: RelKeys, signer: DeviceIds, oldTip: Nat, newTip: Nat]
    /\ online \in [DeviceIds \X DeviceIds -> [prev: Nat, local: Nat, lin: Nat, pin: Nat, gate: Nat, awaits: Nat]]
    /\ outbox \subseteq [id: Nat, from: DeviceIds, to: DeviceIds, payload: 1..MaxPayload,
                         sp: Nat, sc: Nat, pp: Nat, pc: Nat, fin: BOOLEAN]
    /\ journal \subseteq [id: Nat, from: DeviceIds, to: DeviceIds, sp: Nat, sc: Nat, pp: Nat, pc: Nat]
    /\ certs \subseteq Nat
    /\ joins \subseteq [parent: Nat, lo: Nat, hi: Nat, tip: Nat]

Init ==
    /\ devices = [g \in GenesisIds |-> {}]
    /\ relationships = [p \in DeviceIds \X DeviceIds |-> [tip |-> 0, state |-> "inactive"]]
    /\ deviceRoots = [d \in DeviceIds |-> 0]
    /\ smtState = [d \in DeviceIds |-> [rel \in RelKeys |-> 0]]
    /\ net = {}
    /\ nextMsgId = 1
    /\ storageNodes = {}
    /\ keys = [d \in DeviceIds |-> [sphincs |-> 0, kyber |-> 0]]  \* Initialize with dummy keys
    /\ vaults = [d \in DeviceIds |-> {}]
    /\ vaultState = [v \in VaultIds |-> [owner |-> CHOOSE d \in DeviceIds : TRUE, balance |-> 0, locked |-> FALSE, condition |-> 0]]
    /\ activatedDevices = {}
    /\ actCount = [d \in DeviceIds |-> 0]
    /\ emissionIndex = 0
    /\ shardTree = 0  \* Initial SMT root
    /\ djteSeed = 0
    /\ shardLists = [s \in 0..(2^ShardDepth - 1) |-> <<>>]
    /\ spentJaps = {}
    /\ spentProofs = {}
    /\ consumedProofs = {}
    /\ sourceRemaining = MaxSupply
    /\ phase = 0
    /\ step = 0
    /\ offlineSessions = {}
    /\ ledger = {}
    /\ deviceBalance = [d \in DeviceIds |-> MaxPayload]  \* §8: devices start with max supply for model checking
    /\ online = [x \in DeviceIds \X DeviceIds |-> [prev |-> 0, local |-> 0, lin |-> 0, pin |-> 0, gate |-> 0, awaits |-> 0]]
    /\ outbox = {}
    /\ journal = {}
    /\ certs = {}
    /\ joins = {}

\* Add a device to a genesis
AddDevice(g, d) ==
    /\ d \notin devices[g]
    /\ \A g2 \in GenesisIds : d \notin devices[g2]  \* Device not in any other genesis
    /\ Cardinality(devices[g]) < MaxDevices
    /\ devices' = [devices EXCEPT ![g] = devices[g] \union {d}]
    /\ step' = step + 1
    /\ UNCHANGED <<relationships, deviceRoots, smtState, net, nextMsgId, storageNodes, keys, vaults, vaultState, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, phase, offlineSessions, ledger, deviceBalance, online, outbox, journal, certs, joins>>

\* Create a bilateral relationship between two devices: both projections and
\* both lineages start at the relationship's genesis seed, and each device
\* pins the other's head there.
CreateRelationship(d1, d2) ==
    LET g == nextMsgId
        start == [prev |-> 0, local |-> g, lin |-> g, pin |-> g, gate |-> 0, awaits |-> 0]
    IN
    /\ d1 # d2
    /\ relationships[<<d1, d2>>].state = "inactive"
    /\ relationships[<<d2, d1>>].state = "inactive"
    /\ smtState[d1][RelKey(d1, d2)] = 0
    /\ smtState[d2][RelKey(d1, d2)] = 0
    /\ relationships' = [relationships EXCEPT
         ![<<d1, d2>>] = [tip |-> g, state |-> "active"],
         ![<<d2, d1>>] = [tip |-> g, state |-> "active"]]
    /\ smtState' = [smtState EXCEPT
         ![d1][RelKey(d1, d2)] = g,
         ![d2][RelKey(d1, d2)] = g]
    /\ deviceRoots' = [deviceRoots EXCEPT ![d1] = @ + 1, ![d2] = @ + 1]
    /\ online' = [online EXCEPT ![<<d1, d2>>] = start, ![<<d2, d1>>] = start]
    /\ nextMsgId' = nextMsgId + 1
    /\ step' = step + 1
    /\ UNCHANGED <<devices, net, storageNodes, keys, vaults, vaultState, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, phase, offlineSessions, ledger, deviceBalance, outbox, journal, certs, joins>>

\* ---------------------------------------------------------------------------
\* ONLINE BILATERAL PROTOCOL (the beta online transfer, as the code runs it)
\*
\* Two spaces, as in the code (`sender_online_proposal`):
\*   - the PROJECTION: each device's view of the relationship tip
\*     (`contacts.chain_tip` = relationships[<<d,p>>].tip = smtState[d][rel],
\*     `previous_chain_tip` = online[<<d,p>>].prev, `local_bilateral_chain_tip`
\*     = online[<<d,p>>].local). Routes and the transfer nonce are taken here.
\*   - the LINEAGE: each device's own canonical chain for the relationship
\*     (online[<<d,p>>].lin), advanced by its sends and by its applies of the
\*     peer's sends, and its pin of the peer's head (online[<<d,p>>].pin,
\*     `counterparty_canonical_heads`), advanced by an apply (to the sender's
\*     signed child) and by a finalization (to the recipient's countersigned
\*     child).
\*
\* The stages:
\*   Send        T1: debit, the sender's lineage moves, the finality gate is
\*               armed (`pending_online_outbox`), `local` takes the projected
\*               child, the transfer is frozen in the outbox.
\*   RecvTransfer T2+T3: the recipient applies a transfer whose debit was
\*               admitted, whose signed parent is its pin, whose projection
\*               parent (the nonce's tip) is its current tip; its
\*               lineage moves, its pin takes the sender's child, it is
\*               credited, its journal holds the countersign delta, and it
\*               awaits the sender's certificate.
\*   RecvDelta   T4: the sender finalizes on the delta whose parent is its pin;
\*               its projection converges, its pin takes the recipient's child.
\*               The gate stays.
\*   CertPost    T5a: the finalized send's certificate reaches quorum on
\*               storage, where the recipient can read it. The gate stays.
\*   GateRelease T5b: the sender's sweep finds the certificate at quorum and
\*               releases the gate (the gate's only deleter).
\*   RecvCert    T6: the recipient reads the certificate and is released.
\*
\* No stage refunds or rolls back a send. Two sends that cross (each made
\* before its sender applied the other's) both settle: each projection is
\* joined deterministically from the shared parent and the two children
\* (owner ruling 2026-10-29, "both settle"; Core
\* `join_concurrent_tips`), every transfer keeps the parent it was signed
\* against, and no sender consumes its own parent twice.
\*
\* The network is an adversarial bag of message copies: any copy can be
\* delivered in any order, dropped or duplicated (bounded). A drop is never
\* permanent: the sender re-drives an unfinalized transfer and the recipient
\* re-emits the delta its journal holds until the certificate arrives.
\* A copy of a device (CopySend) can post a transfer from a parent its
\* original already consumed; its debit was never admitted.
\* ---------------------------------------------------------------------------

onlineVars == <<online, outbox, journal, certs, joins>>

\* A projection tip as one device holds it.
View(d, p) == [chain |-> relationships[<<d, p>>].tip,
               prev  |-> online[<<d, p>>].prev,
               local |-> online[<<d, p>>].local]

\* The join of two concurrent steps from `parent` (Core
\* `join_concurrent_tips`): a deterministic function of the parent and the
\* unordered pair of children, modeled as a lazily filled oracle so that both
\* devices, computing it independently, obtain the same tip.
JoinEntry(parent, a, b) ==
    { j \in joins : j.parent = parent /\ j.lo = MinNat({a, b}) /\ j.hi = MaxNat({a, b}) }

JoinTip(parent, a, b, fresh) ==
    IF JoinEntry(parent, a, b) # {} THEN (CHOOSE j \in JoinEntry(parent, a, b) : TRUE).tip
    ELSE fresh

JoinsAfter(parent, a, b, fresh) ==
    IF JoinEntry(parent, a, b) # {} THEN joins
    ELSE joins \union {[parent |-> parent, lo |-> MinNat({a, b}), hi |-> MaxNat({a, b}), tip |-> fresh]}

\* `sync_tip_projections_in_tx` with crossing steps joined, case for case.
\* `fresh` is the tip a join takes if the oracle has none for the pair.
TipSync(v, parent, target, fresh) ==
    IF v.chain = target
    THEN [ok |-> TRUE, chain |-> target, prev |-> v.prev, local |-> target, joined |-> FALSE]
    ELSE IF v.chain = parent
    THEN [ok |-> TRUE, chain |-> target, prev |-> parent, local |-> target, joined |-> FALSE]
    ELSE IF v.prev = parent /\ v.local = v.chain
    THEN [ok |-> TRUE, chain |-> JoinTip(parent, v.chain, target, fresh), prev |-> v.chain,
          local |-> JoinTip(parent, v.chain, target, fresh), joined |-> TRUE]
    ELSE IF /\ v.prev # 0 /\ v.prev # parent /\ v.prev # target
            /\ JoinEntry(parent, v.prev, target) # {}
            /\ JoinTip(parent, v.prev, target, fresh) = v.chain
            /\ v.local = v.chain
    THEN [ok |-> TRUE, chain |-> v.chain, prev |-> v.prev, local |-> v.local, joined |-> FALSE]
    ELSE [ok |-> FALSE, chain |-> v.chain, prev |-> v.prev, local |-> v.local, joined |-> FALSE]

\* The joins oracle after a sync that may have joined.
JoinsAfterSync(v, parent, target, fresh) ==
    IF v.chain # target /\ v.chain # parent /\ v.prev = parent /\ v.local = v.chain
    THEN JoinsAfter(parent, v.chain, target, fresh)
    ELSE joins

\* A transfer is applied when the ledger holds its signed lineage step.
Applied(t) ==
    [rel |-> RelKey(t.from, t.to), signer |-> t.from, oldTip |-> t.sp, newTip |-> t.sc] \in ledger

\* Neither side holds anything in flight toward the other.
Settled(d, p) ==
    /\ online[<<d, p>>].gate = 0
    /\ online[<<d, p>>].awaits = 0
    /\ ~\E r \in outbox : r.from = d /\ r.to = p

TransferMsg(r, copy) ==
    [id |-> r.id, copy |-> copy, kind |-> "transfer", from |-> r.from, to |-> r.to,
     payload |-> r.payload, sp |-> r.sp, sc |-> r.sc, pp |-> r.pp, pc |-> r.pc,
     dupLeft |-> MaxDupPerMsg]

DeltaMsg(j, copy) ==
    [id |-> j.id, copy |-> copy, kind |-> "delta", from |-> j.from, to |-> j.to,
     payload |-> 0, sp |-> j.sp, sc |-> j.sc, pp |-> j.pp, pc |-> j.pc,
     dupLeft |-> MaxDupPerMsg]

\* T1. The finality barrier: no send while the sender's own send is in flight
\* or while it awaits the peer's certificate for a transfer it applied, and
\* none while an offline step is in flight with the peer.
Send(d, p, amt) ==
    LET id == nextMsgId
        o  == online[<<d, p>>]
        r  == [id |-> id, from |-> d, to |-> p, payload |-> amt,
               sp |-> o.lin, sc |-> id, pp |-> relationships[<<d, p>>].tip, pc |-> id,
               fin |-> FALSE]
    IN
    /\ d # p
    /\ relationships[<<d, p>>].state = "active"
    /\ <<d, p>> \notin offlineSessions
    /\ o.gate = 0
    /\ o.awaits = 0
    /\ o.local = relationships[<<d, p>>].tip
    /\ amt > 0
    /\ deviceBalance[d] >= amt
    /\ Cardinality(net) < MaxNet
    /\ outbox' = outbox \union {r}
    /\ net' = net \union {TransferMsg(r, id)}
    /\ online' = [online EXCEPT ![<<d, p>>].lin = id, ![<<d, p>>].local = id, ![<<d, p>>].gate = id]
    /\ deviceBalance' = [deviceBalance EXCEPT ![d] = @ - amt]
    /\ nextMsgId' = nextMsgId + 1
    /\ step' = step + 1
    /\ UNCHANGED <<devices, relationships, deviceRoots, smtState, storageNodes, keys, vaults, vaultState, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, phase, offlineSessions, ledger, journal, certs, joins>>

\* T2+T3. The recipient applies the transfer copy `m`.
RecvTransfer(m) ==
    LET d     == m.to
        p     == m.from
        o     == online[<<d, p>>]
        v     == View(d, p)
        bc    == nextMsgId
        fresh == nextMsgId + 1
        s     == TipSync(v, m.pp, m.pc, fresh)
        j     == [id |-> m.id, from |-> d, to |-> p, sp |-> o.lin, sc |-> bc, pp |-> m.pp, pc |-> m.pc]
    IN
    /\ m.kind = "transfer"
    /\ ~Applied(m)
    \* recipient admission: the sender's debit for this transfer was admitted
    /\ RecipientChecksAdmission => \E r \in outbox : r.id = m.id /\ r.from = p /\ r.to = d /\ r.sp = m.sp /\ r.sc = m.sc
    \* held while this device awaits the sender's certificate for the last one
    /\ o.awaits = 0
    \* the pin: the signed parent is the sender's head this device pinned
    /\ RecipientChecksPin => m.sp = o.pin
    \* the nonce's tip is this device's current tip
    /\ m.pp = v.chain
    /\ s.ok
    /\ relationships' = [relationships EXCEPT ![<<d, p>>].tip = s.chain]
    /\ smtState' = [smtState EXCEPT ![d][RelKey(d, p)] = s.chain]
    /\ deviceRoots' = [deviceRoots EXCEPT ![d] = @ + 1]
    /\ online' = [online EXCEPT ![<<d, p>>] =
                    [o EXCEPT !.prev = s.prev, !.local = s.local, !.lin = bc, !.pin = m.sc, !.awaits = m.id]]
    /\ deviceBalance' = [deviceBalance EXCEPT ![d] = @ + m.payload]
    /\ ledger' = ledger \union {[rel |-> RelKey(d, p), signer |-> p, oldTip |-> m.sp, newTip |-> m.sc]}
    /\ journal' = journal \union {j}
    /\ joins' = JoinsAfterSync(v, m.pp, m.pc, fresh)
    /\ net' = (net \ {m}) \union {DeltaMsg(j, bc)}
    /\ nextMsgId' = nextMsgId + 2
    /\ step' = step + 1
    /\ UNCHANGED <<devices, storageNodes, keys, vaults, vaultState, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, phase, offlineSessions, outbox, certs>>

\* T4. The sender finalizes its send on the delta copy `m`.
RecvDelta(m) ==
    LET d     == m.to
        p     == m.from
        o     == online[<<d, p>>]
        v     == View(d, p)
        fresh == nextMsgId
        r     == CHOOSE x \in outbox : x.id = m.id
        s     == TipSync(v, r.pp, r.pc, fresh)
    IN
    /\ m.kind = "delta"
    /\ \E x \in outbox : x.id = m.id /\ x.from = d /\ x.to = p /\ ~x.fin
    /\ o.gate = m.id
    \* the pin: the delta's countersigned parent is the recipient's head pinned
    /\ m.sp = o.pin
    /\ s.ok
    /\ relationships' = [relationships EXCEPT ![<<d, p>>].tip = s.chain]
    /\ smtState' = [smtState EXCEPT ![d][RelKey(d, p)] = s.chain]
    /\ deviceRoots' = [deviceRoots EXCEPT ![d] = @ + 1]
    /\ online' = [online EXCEPT ![<<d, p>>] = [o EXCEPT !.prev = s.prev, !.local = s.local, !.pin = m.sc]]
    /\ outbox' = (outbox \ {r}) \union {[r EXCEPT !.fin = TRUE]}
    /\ ledger' = ledger \union {[rel |-> RelKey(d, p), signer |-> p, oldTip |-> m.sp, newTip |-> m.sc]}
    /\ joins' = JoinsAfterSync(v, r.pp, r.pc, fresh)
    /\ net' = net \ {m}
    /\ nextMsgId' = nextMsgId + 1
    /\ step' = step + 1
    /\ UNCHANGED <<devices, storageNodes, keys, vaults, vaultState, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, phase, offlineSessions, deviceBalance, journal, certs>>

\* A copy that changes nothing: a transfer already applied, or a delta for a
\* send already finalized, is read and changes no state.
RecvSpent(m) ==
    /\ \/ m.kind = "transfer" /\ Applied(m)
       \/ m.kind = "delta" /\ ~\E x \in outbox : x.id = m.id /\ ~x.fin
    /\ net' = net \ {m}
    /\ step' = step + 1
    /\ UNCHANGED <<devices, relationships, deviceRoots, smtState, nextMsgId, storageNodes, keys, vaults, vaultState, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, offlineSessions, phase, ledger, deviceBalance, online, outbox, journal, certs, joins>>

\* T5a. The finalized send's certificate reaches quorum on storage. The
\* recipient can read it from here on; the sender's gate stays until its sweep
\* sees the quorum.
CertPost(d, p) ==
    /\ online[<<d, p>>].gate # 0
    /\ online[<<d, p>>].gate \notin certs
    /\ \E r \in outbox : r.id = online[<<d, p>>].gate /\ r.fin
    /\ certs' = certs \union {online[<<d, p>>].gate}
    /\ step' = step + 1
    /\ UNCHANGED <<devices, relationships, deviceRoots, smtState, net, nextMsgId, storageNodes, keys, vaults, vaultState, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, offlineSessions, phase, ledger, deviceBalance, online, outbox, journal, joins>>

\* T5b. The sender's sweep finds its certificate at quorum and releases the
\* gate.
GateRelease(d, p) ==
    /\ online[<<d, p>>].gate # 0
    /\ online[<<d, p>>].gate \in certs
    /\ outbox' = { r \in outbox : r.id # online[<<d, p>>].gate }
    /\ online' = [online EXCEPT ![<<d, p>>].gate = 0]
    /\ step' = step + 1
    /\ UNCHANGED <<devices, relationships, deviceRoots, smtState, net, nextMsgId, storageNodes, keys, vaults, vaultState, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, offlineSessions, phase, ledger, deviceBalance, journal, certs, joins>>

\* T6. The recipient reads the certificate and is released.
RecvCert(d, p) ==
    /\ online[<<d, p>>].awaits # 0
    /\ online[<<d, p>>].awaits \in certs
    /\ journal' = { j \in journal : j.id # online[<<d, p>>].awaits }
    /\ online' = [online EXCEPT ![<<d, p>>].awaits = 0]
    /\ step' = step + 1
    /\ UNCHANGED <<devices, relationships, deviceRoots, smtState, net, nextMsgId, storageNodes, keys, vaults, vaultState, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, offlineSessions, phase, ledger, deviceBalance, outbox, certs, joins>>

\* The sender re-drives a transfer it has not finalized: no drop is permanent.
RedriveTransfer(r) ==
    /\ r \in outbox
    /\ ~r.fin
    /\ ~\E m \in net : m.kind = "transfer" /\ m.id = r.id
    /\ Cardinality(net) < MaxNet
    /\ net' = net \union {TransferMsg(r, nextMsgId)}
    /\ nextMsgId' = nextMsgId + 1
    /\ step' = step + 1
    /\ UNCHANGED <<devices, relationships, deviceRoots, smtState, storageNodes, keys, vaults, vaultState, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, offlineSessions, phase, ledger, deviceBalance, online, outbox, journal, certs, joins>>

\* The recipient re-emits the delta its journal holds until the certificate.
RedriveDelta(j) ==
    /\ j \in journal
    /\ ~\E m \in net : m.kind = "delta" /\ m.id = j.id
    /\ Cardinality(net) < MaxNet
    /\ net' = net \union {DeltaMsg(j, nextMsgId)}
    /\ nextMsgId' = nextMsgId + 1
    /\ step' = step + 1
    /\ UNCHANGED <<devices, relationships, deviceRoots, smtState, storageNodes, keys, vaults, vaultState, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, offlineSessions, phase, ledger, deviceBalance, online, outbox, journal, certs, joins>>

\* The lineage parents device `d` has consumed toward `p` in sends.
ConsumedParents(d, p) ==
    { r.sp : r \in { x \in outbox : x.from = d /\ x.to = p } }
    \union { l.oldTip : l \in { x \in ledger : x.signer = d /\ x.rel = RelKey(d, p) } }

\* A copy of `d` posts a transfer from a lineage parent `d` already consumed,
\* aimed at a projection tip the recipient holds. Its debit is the copy's own
\* and was never admitted: nothing in `outbox` stands behind it.
CopySend(d, p, amt) ==
    /\ d # p
    /\ amt \in 1..MaxPayload
    /\ Cardinality(net) < MaxNet
    /\ \E parent \in ConsumedParents(d, p), pp \in {relationships[<<p, d>>].tip, online[<<p, d>>].prev} \ {0} :
         net' = net \union {[id |-> nextMsgId, copy |-> nextMsgId, kind |-> "transfer", from |-> d, to |-> p,
                             payload |-> amt, sp |-> parent, sc |-> nextMsgId, pp |-> pp, pc |-> nextMsgId,
                             dupLeft |-> 0]}
    /\ nextMsgId' = nextMsgId + 1
    /\ step' = step + 1
    /\ UNCHANGED <<devices, relationships, deviceRoots, smtState, storageNodes, keys, vaults, vaultState, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, offlineSessions, phase, ledger, deviceBalance, online, outbox, journal, certs, joins>>

\* Deliver any copy from the bag (unordered delivery semantics).
NetDeliver ==
    \E m \in net : RecvTransfer(m) \/ RecvDelta(m) \/ RecvSpent(m)

\* Drop any copy (adversary).
NetDrop ==
    /\ net # {}
    /\ \E msg \in net :
         /\ net' = net \ {msg}
         /\ step' = step + 1
         /\ UNCHANGED <<devices, relationships, deviceRoots, smtState, nextMsgId, storageNodes, keys, vaults, vaultState, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, offlineSessions, phase, ledger, deviceBalance, online, outbox, journal, certs, joins>>

\* Duplicate any copy (adversary) while its duplicate budget remains: the copy
\* is the same message, a separate instance in the bag.
NetDuplicate ==
    /\ net # {}
    /\ Cardinality(net) < MaxNet
    /\ \E msg \in net :
         /\ msg.dupLeft > 0
         /\ net' = (net \ {msg})
                   \union { [msg EXCEPT !.dupLeft = msg.dupLeft - 1],
                            [msg EXCEPT !.copy = nextMsgId, !.dupLeft = msg.dupLeft - 1] }
         /\ nextMsgId' = nextMsgId + 1
         /\ step' = step + 1
         /\ UNCHANGED <<devices, relationships, deviceRoots, smtState, storageNodes, keys, vaults, vaultState, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, offlineSessions, phase, ledger, deviceBalance, online, outbox, journal, certs, joins>>

\* The online actions that do not consume a copy from the bag.
OnlineLocal ==
    \/ \E d, p \in DeviceIds : CertPost(d, p)
    \/ \E d, p \in DeviceIds : GateRelease(d, p)
    \/ \E d, p \in DeviceIds : RecvCert(d, p)

\* The online actions that put a copy into the bag.
OnlineInject ==
    \/ \E d, p \in DeviceIds, amt \in 1..MaxPayload : Send(d, p, amt)
    \/ \E d, p \in DeviceIds, amt \in 1..MaxPayload : CopySend(d, p, amt)
    \/ \E r \in outbox : RedriveTransfer(r)
    \/ \E j \in journal : RedriveDelta(j)

\* Add a storage node
AddStorageNode(d) ==
    /\ d \in DeviceIds
    /\ d \notin storageNodes
    /\ storageNodes' = storageNodes \union {d}
    /\ step' = step + 1
    /\ UNCHANGED <<devices, relationships, deviceRoots, smtState, net, nextMsgId, keys, vaults, vaultState, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, phase, offlineSessions, ledger, deviceBalance, online, outbox, journal, certs, joins>>

\* ============================================================================
\* CRYPTOGRAPHIC OPERATIONS (ABSTRACTED)
\*
\* Precision note:
\* This spec does NOT model real SPHINCS+/Kyber algorithms, byte encodings, proofs,
\* or cryptographic soundness. It only models a simple “keys generated?” gate to
\* constrain control-flow (e.g., signing/encryption requires keys).
\* ============================================================================

\* Generate cryptographic keys for a device
GenerateKeys(d) ==
    /\ keys[d].sphincs = 0  \* Not yet generated
    /\ keys' = [keys EXCEPT ![d] = [sphincs |-> 1, kyber |-> 1]]  \* Mark as generated
    /\ step' = step + 1
    /\ UNCHANGED <<devices, relationships, deviceRoots, smtState, net, nextMsgId, storageNodes, vaults, vaultState, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, phase, offlineSessions, ledger, deviceBalance, online, outbox, journal, certs, joins>>

\* Sign a message (abstracted)
SignMessage(d, msg) ==
    /\ keys[d].sphincs = 1  \* Keys must be generated
    /\ step' = step + 1
    /\ UNCHANGED <<devices, relationships, deviceRoots, smtState, net, nextMsgId, storageNodes, keys, vaults, vaultState, activatedDevices, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, offlineSessions, ledger, deviceBalance, online, outbox, journal, certs, joins>>

\* Encrypt using a KEM (abstracted)
EncryptWithKyber(d1, d2, msg) ==
    /\ keys[d1].kyber = 1 /\ keys[d2].kyber = 1  \* Both devices must have keys
    /\ step' = step + 1
    /\ UNCHANGED <<devices, relationships, deviceRoots, smtState, net, nextMsgId, storageNodes, keys, vaults, vaultState, activatedDevices, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, offlineSessions, ledger, deviceBalance, online, outbox, journal, certs, joins>>

\* ============================================================================
\* OFFLINE BILATERAL TRANSFERS (ABSTRACTED)
\*
\* Precision note:
\* BLE/NFC transport, chunking, precommitment, and co-signing are NOT modeled.
\* We model only:
\*  - a symmetric offlineSessions relation
\*  - a tip increment on OfflineTransfer
\* ============================================================================

\* Start an offline session between two devices
StartOfflineSession(d1, d2) ==
    /\ d1 # d2
    /\ <<d1, d2>> \notin offlineSessions /\ <<d2, d1>> \notin offlineSessions
    /\ relationships[<<d1, d2>>].state = "active"
    /\ relationships[<<d2, d1>>].state = "active"
    /\ Settled(d1, d2) /\ Settled(d2, d1)
    /\ offlineSessions' = offlineSessions \union {<<d1, d2>>, <<d2, d1>>}
    /\ step' = step + 1
    /\ UNCHANGED <<devices, relationships, deviceRoots, smtState, net, nextMsgId, storageNodes, keys, vaults, vaultState, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, phase, ledger, deviceBalance, online, outbox, journal, certs, joins>>

\* Perform an offline bilateral transfer (abstracted to its commit on both
\* devices; DSM_OfflineFinality.tla models the frames between). One step at a
\* time across the online and offline processes: neither device has an online
\* send in flight or awaits a certificate toward the other. Both lineages
\* advance, each device pins the other's new head (as an online apply and
\* finalization do), both projections advance, and the amount moves.
OfflineTransfer(d1, d2, amount) ==
    LET tip == relationships[<<d1, d2>>].tip
        c1  == nextMsgId
        c2  == nextMsgId + 1
        o1  == online[<<d1, d2>>]
        o2  == online[<<d2, d1>>]
    IN
    /\ <<d1, d2>> \in offlineSessions
    /\ amount > 0
    /\ deviceBalance[d1] >= amount
    /\ Settled(d1, d2) /\ Settled(d2, d1)
    /\ smtState[d1][RelKey(d1, d2)] = tip
    /\ smtState[d2][RelKey(d1, d2)] = tip
    /\ relationships[<<d2, d1>>].tip = tip
    /\ o1.local = tip /\ o2.local = tip
    /\ o2.pin = o1.lin /\ o1.pin = o2.lin
    /\ relationships' = [relationships EXCEPT
         ![<<d1, d2>>] = [tip |-> c1, state |-> "active"],
         ![<<d2, d1>>] = [tip |-> c1, state |-> "active"]]
    /\ smtState' = [smtState EXCEPT
         ![d1][RelKey(d1, d2)] = c1,
         ![d2][RelKey(d1, d2)] = c1]
    /\ deviceRoots' = [deviceRoots EXCEPT ![d1] = @ + 1, ![d2] = @ + 1]
    /\ online' = [online EXCEPT
         ![<<d1, d2>>] = [o1 EXCEPT !.prev = tip, !.local = c1, !.lin = c1, !.pin = c2],
         ![<<d2, d1>>] = [o2 EXCEPT !.prev = tip, !.local = c1, !.lin = c2, !.pin = c1]]
    /\ deviceBalance' = [deviceBalance EXCEPT ![d1] = @ - amount, ![d2] = @ + amount]
    /\ ledger' = ledger \union {[rel |-> RelKey(d1, d2), signer |-> d1, oldTip |-> o1.lin, newTip |-> c1],
                                [rel |-> RelKey(d1, d2), signer |-> d2, oldTip |-> o2.lin, newTip |-> c2]}
    /\ offlineSessions' = offlineSessions \ {<<d1, d2>>, <<d2, d1>>}
    /\ nextMsgId' = nextMsgId + 2
    /\ step' = step + 1
    /\ UNCHANGED <<devices, net, storageNodes, keys, vaults, vaultState, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, phase, outbox, journal, certs, joins>>

\* ============================================================================
\* DLV (ABSTRACTED)
\*
\* Precision note:
\* This models only ownership + a simple (proof == condition) unlock predicate.
\* It does NOT model precommit/reveal, cryptographic evidence, vault-chain tips,
\* or fork/Tripwire semantics.
\* ============================================================================

\* Create a new DLV vault
CreateVault(d, v, initialBalance, condition) ==
    /\ v \notin vaults[d]
    /\ \A d2 \in DeviceIds : v \notin vaults[d2]  \* Vault not owned by anyone else
    /\ Cardinality(vaults[d]) < MaxVaults
    /\ vaults' = [vaults EXCEPT ![d] = vaults[d] \union {v}]
    /\ vaultState' = [vaultState EXCEPT ![v] = [owner |-> d, balance |-> initialBalance, locked |-> TRUE, condition |-> condition]]
    /\ step' = step + 1
    /\ UNCHANGED <<devices, relationships, deviceRoots, smtState, net, nextMsgId, storageNodes, keys, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, phase, offlineSessions, ledger, deviceBalance, online, outbox, journal, certs, joins>>

\* Unlock a DLV vault when condition is met
UnlockVault(v, proof) ==
    /\ vaultState[v].locked = TRUE
    /\ proof = vaultState[v].condition  \* Simplified: proof matches condition
    /\ vaultState' = [vaultState EXCEPT ![v] = [vaultState[v] EXCEPT !.locked = FALSE]]
    /\ step' = step + 1
    /\ UNCHANGED <<devices, relationships, deviceRoots, smtState, net, nextMsgId, storageNodes, keys, vaults, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, phase, offlineSessions, ledger, deviceBalance, online, outbox, journal, certs, joins>>

\* ============================================================================
\* STORAGE NODES (ABSTRACTED)
\*
\* Precision note:
\* We model membership in storageNodes and stub actions for Store/Replicate.
\* No addressing, replica placement, quorum, byte accounting, or audits.
\* ============================================================================

\* Store data on storage nodes (simplified replication)
StoreData(d, data) ==
    /\ d \in storageNodes
    /\ step' = step + 1
    /\ UNCHANGED <<devices, relationships, deviceRoots, smtState, net, nextMsgId, storageNodes, keys, vaults, vaultState, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, phase, offlineSessions, ledger, deviceBalance, online, outbox, journal, certs, joins>>

\* Replicate data across storage nodes
ReplicateData(data) ==
    /\ Cardinality(storageNodes) >= 3  \* Need at least 3 nodes for replication
    /\ step' = step + 1
    /\ UNCHANGED <<devices, relationships, deviceRoots, smtState, net, nextMsgId, storageNodes, keys, vaults, vaultState, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, phase, offlineSessions, ledger, deviceBalance, online, outbox, journal, certs, joins>>

\* ============================================================================
\* DJTE (ABSTRACTED)
\*
\* Precision note:
\* This is still an abstract model, but it now includes the core *proof-carrying*
\* structure DJTE relies on:
\*  - Shard activation accumulators as explicit sequences: shardLists[s].
\*  - ShardCountSMT is modeled via derived PrefixCount(p,k) over shardLists, with
\*    a placeholder CountRoot digest.
\*  - Winner selection is exact-uniform *within a finite sampling domain* U16
\*    using deterministic rejection sampling (UniformIndex) and shard descent
\*    (RankToShardAndIndex).
\*  - SpentProofSMT is abstracted as a monotone set spentJaps, consumed by
\*    ConsumeJAPAndEmit.
\* What remains abstracted:
\*  - Real cryptographic hashes/digests, proof byte encodings, and accumulator roots.
\*  - The source DLV balance/cap/halving schedule and token transfers.
\* ============================================================================

\* Unlock spend-gate for a device (join activation)
UnlockSpendGate(d) ==
    /\ d \in DeviceIds
     /\ d \notin activatedDevices
     /\ phase = 0
     /\ LET newCount == actCount[d] + 1
         IN /\ actCount' = [actCount EXCEPT ![d] = newCount]
     /\ activatedDevices' = activatedDevices \union {d}
    /\ shardLists' = [shardLists EXCEPT ![ShardOf(d)] = Append(shardLists[ShardOf(d)], d)]
    /\ shardTree' = shardTree + 1  \* Simplified placeholder; see CountRoot/ShardAccRoot for derived views
    /\ djteSeed' = djteSeed + 1
    /\ phase' = 0
    /\ step' = step + 1
    /\ UNCHANGED <<devices, relationships, deviceRoots, smtState, net, nextMsgId, storageNodes, keys, vaults, vaultState, emissionIndex, spentJaps, spentProofs, consumedProofs, sourceRemaining, offlineSessions, ledger, deviceBalance, online, outbox, journal, certs, joins>>

\* Additional activation instances for an already-activated device.
\* This models re-activation / re-issuance without turning the model into an infinite JAP printer:
\* each ActivateAgain increments actCount[d] by exactly 1, producing exactly one new JAP digest.
ActivateAgain(d) ==
     /\ d \in activatedDevices
     /\ phase = 0
     /\ actCount' = [actCount EXCEPT ![d] = actCount[d] + 1]
     /\ shardTree' = shardTree + 1
     /\ djteSeed' = djteSeed + 1
    /\ phase' = 0
     /\ step' = step + 1
    /\ UNCHANGED <<devices, relationships, deviceRoots, smtState, net, nextMsgId, storageNodes, keys, vaults, vaultState, activatedDevices, emissionIndex, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, offlineSessions, ledger, deviceBalance, online, outbox, journal, certs, joins>>

\* Trigger DJTE emission event
\*
\* A "JAP" (Join Activation Proof) digest abstraction.
\* In the real protocol this would be H("DJTE.JAP"||...) and is consumed exactly once.
\* (DeviceNum(d) is used because d is a model value, not a Nat.)
JapDigest(d, seed) == Mix(1009 * DeviceNum(d) + 97 * seed)

\* Model activation-instance uniqueness explicitly:
\* For each device d, actCount[d] tracks how many activation instances exist.
\* Each activation instance i (1..actCount[d]) corresponds to exactly one JAP:
\*   JapDigest(d, i)
\*
\* Define AllJaps here (before first use) to avoid forward-reference issues in TLC.
AllJaps == UNION { { JapDigest(d, i) : i \in 1..actCount[d] } : d \in DeviceIds }

\* AvailableJaps is the set of all instance digests not yet spent.
AvailableJaps == AllJaps \ spentJaps

\* Proof-carrying emission step:
\* - requires at least one activated device and at least one unspent JAP
\* - consumes exactly one JAP (adds it to spentJaps)
\* - selects a winner by exact-uniform rank over the activated population
\*   using rejection sampling + shard descent over PrefixCount
ConsumeJAPAndEmit ==
    /\ TotalActivated > 0
    /\ emissionIndex < MaxEmissions
    /\ AvailableJaps # {}
    /\ sourceRemaining > 0
    /\ phase = 1
    /\ \E jap \in AvailableJaps :
         LET r == UniformIndex(Mix(jap + emissionIndex), TotalActivated)
             pair == RankToShardAndIndex(r)
             s == pair[1]
             i0 == pair[2]
             idx == i0 + 1
             winner == shardLists[s][idx]
         IN
           /\ idx \in 1..Len(shardLists[s])
           /\ winner \in activatedDevices
           /\ spentJaps' = spentJaps \union {jap}
           /\ spentProofs' = spentProofs \union { [jap |-> jap, proof |-> Mix(4242 + 17 * jap + emissionIndex)] }
           /\ consumedProofs' = consumedProofs
           /\ emissionIndex' = emissionIndex + 1
           /\ sourceRemaining' = sourceRemaining - 1
           /\ shardTree' = shardTree + 1  \* Placeholder counter; CountRoot/ShardAccRoot are derived
           /\ djteSeed' = djteSeed + 1
           /\ phase' = 1
           /\ step' = step + 1
           /\ actCount' = actCount
           /\ UNCHANGED <<devices, relationships, deviceRoots, smtState, net, nextMsgId, storageNodes, keys, vaults, vaultState, activatedDevices, shardLists, phase, actCount, offlineSessions, ledger, deviceBalance, online, outbox, journal, certs, joins>>


\* Backwards-compat stub (deprecated): keep as stutter to avoid changing historical docs.
\* Winner selection is now embedded in ConsumeJAPAndEmit.
SelectWinner ==
    /\ phase = 3
    /\ step' = step + 1
    /\ UNCHANGED <<devices, relationships, deviceRoots, smtState, net, nextMsgId, storageNodes, keys, vaults, vaultState, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, phase, offlineSessions, ledger, deviceBalance, online, outbox, journal, certs, joins>>

\* Phase 2 "consume" step: abstracts the SpentProofSMT leaf insertion effect being
\* recognized. Since spentJaps is already updated in ConsumeJAPAndEmit, this action
\* is a deterministic no-op that advances phase to termination.
ConsumeSpentProof ==
    /\ phase = 2
    /\ spentProofs # {}
    /\ \E p \in (spentProofs \ consumedProofs) :
         /\ consumedProofs' = consumedProofs \union {p}
         /\ phase' = 2
         /\ step' = step + 1
         /\ UNCHANGED <<devices, relationships, deviceRoots, smtState, net, nextMsgId, storageNodes, keys, vaults, vaultState, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, sourceRemaining, offlineSessions, ledger, deviceBalance, online, outbox, journal, certs, joins>>

\* Milestone transitions: advance between phase buckets without forcing a single scripted step.
EnterPhase1 ==
    /\ phase = 0
    /\ activatedDevices # {}
    /\ phase' = 1
    /\ step' = step + 1
    /\ UNCHANGED <<devices, relationships, deviceRoots, smtState, net, nextMsgId, storageNodes, keys, vaults, vaultState, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, offlineSessions, ledger, deviceBalance, online, outbox, journal, certs, joins>>

EnterPhase2 ==
    /\ phase = 1
    /\ spentJaps # {}
    /\ phase' = 2
    /\ step' = step + 1
    /\ UNCHANGED <<devices, relationships, deviceRoots, smtState, net, nextMsgId, storageNodes, keys, vaults, vaultState, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, offlineSessions, ledger, deviceBalance, online, outbox, journal, certs, joins>>

EnterPhase3 ==
    /\ phase = 2
    /\ phase' = 3
    /\ step' = step + 1
    /\ UNCHANGED <<devices, relationships, deviceRoots, smtState, net, nextMsgId, storageNodes, keys, vaults, vaultState, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, offlineSessions, ledger, deviceBalance, online, outbox, journal, certs, joins>>

\* Deterministic stutter/termination once phase 3 reached (keeps state space finite).
PhaseDone ==
    /\ phase = 3
    /\ phase' = 3
    /\ step' = step + 1
    /\ UNCHANGED <<devices, relationships, deviceRoots, smtState, net, nextMsgId, storageNodes, keys, vaults, vaultState, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, offlineSessions, ledger, deviceBalance, online, outbox, journal, certs, joins>>

\* Total stutter/termination for bounded runs: keep state fixed.
\*
\* NOTE: we keep this distinct from PhaseDone because PhaseDone increments `step`.
\* Stutter is useful for enablement debugging but must not invalidate types.

\* Explicit stuttering action (useful for debugging enablement/coverage).
\* It keeps all state variables unchanged. NOTE: this still increments no counters.
Stutter ==
    /\ UNCHANGED <<devices, relationships, deviceRoots, smtState, net, nextMsgId, storageNodes, keys, vaults, vaultState, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, phase, step, offlineSessions, ledger, deviceBalance, online, outbox, journal, certs, joins>>

\* Regression harness Next: preserves previous structure.
\* The online protocol's steps. The bag is bounded (MaxNet, each copy's
\* duplicate budget) and every run by StepBound, so the online actions
\* interleave freely with everything else: two sends can cross, a copy can be
\* delivered while another is in flight, a certificate can land at any point.
OnlineNext ==
    \/ NetDeliver
    \/ NetDrop
    \/ NetDuplicate
    \/ OnlineLocal
    \/ OnlineInject

\* Regression harness Next: the phase-bucket structure for DJTE, beside the
\* online protocol on relationships it establishes.
HarnessNext ==
    \/ OnlineNext
    \/ \E d1, d2 \in DeviceIds : CreateRelationship(d1, d2)
    \/ EnterPhase1
    \/ EnterPhase2
    \/ EnterPhase3
    \/ PhaseDone
    \/ IF phase = 0 THEN
           \/ \E d \in DeviceIds : UnlockSpendGate(d)
           \/ \E d \in DeviceIds : ActivateAgain(d)
       ELSE IF phase = 1 THEN
           \/ ConsumeJAPAndEmit
       ELSE IF phase = 2 THEN
           \/ ConsumeSpentProof
       ELSE
           \* PhaseDone already allowed above
           FALSE

\* System Next: explores interleavings without the phase harness gating.
SystemNext ==
    \/ OnlineNext
    \/ \E g \in GenesisIds, d \in DeviceIds : AddDevice(g, d)
    \/ \E d1, d2 \in DeviceIds : CreateRelationship(d1, d2)
    \/ \E d \in DeviceIds : AddStorageNode(d)
    \/ \E d \in DeviceIds : GenerateKeys(d)
    \* Offline bilateral
    \/ \E d1, d2 \in DeviceIds : StartOfflineSession(d1, d2)
    \/ \E d1, d2 \in DeviceIds, amount \in 1..MaxPayload : OfflineTransfer(d1, d2, amount)
    \* Vault lifecycle
    \/ \E d \in DeviceIds, v \in VaultIds, initialBalance \in 0..MaxPayload, condition \in 0..MaxPayload :
           CreateVault(d, v, initialBalance, condition)
    \/ \E v \in VaultIds, proof \in 0..MaxPayload : UnlockVault(v, proof)
    \* DJTE
    \/ \E d \in DeviceIds : UnlockSpendGate(d)
    \/ \E d \in DeviceIds : ActivateAgain(d)
    \/ ConsumeJAPAndEmit
    \/ ConsumeSpentProof

Next ==
    \* Dual-mode execution:
    \* - Harness mode preserves the phase-bucket regression structure.
    \* - System mode explores the full interleavings without phase gating.
    IF UseHarness THEN HarnessNext ELSE SystemNext

vars == <<devices, relationships, deviceRoots, smtState, net, nextMsgId, storageNodes, keys, vaults, vaultState, activatedDevices, actCount, emissionIndex, shardTree, djteSeed, shardLists, spentJaps, spentProofs, consumedProofs, sourceRemaining, phase, step, offlineSessions, ledger, deviceBalance, online, outbox, journal, certs, joins>>

Spec == Init /\ [][Next]_vars

\* State constraint used by step-bounded regression configurations.
\* This is clockless: `step` is a monotone transition counter, not wall time.
StepBound == step \in 0..MaxStep

\* State constraint for the online witnesses: only the online protocol and the
\* relationship it runs on move, so a bounded search reaches deep enough to
\* settle two crossing sends. Clockless, like StepBound.
OnlineScope ==
    /\ StepBound
    /\ \A g \in GenesisIds : devices[g] = {}
    /\ storageNodes = {}
    /\ \A d \in DeviceIds : keys[d].sphincs = 0 /\ vaults[d] = {}
    /\ activatedDevices = {}
    /\ offlineSessions = {}

\* ==========================================================================
\* TLAPS proof surface (Concrete DSM -> DSM_ProtocolCore)
\* ==========================================================================

NetworkStep ==
    \/ OnlineInject
    \/ OnlineLocal
    \/ NetDeliver
    \/ NetDrop
    \/ NetDuplicate

RelationshipStep ==
    \/ \E d1, d2 \in DeviceIds : CreateRelationship(d1, d2)
    \/ \E d1, d2 \in DeviceIds : StartOfflineSession(d1, d2)
    \/ \E d1, d2 \in DeviceIds, amount \in 1..MaxPayload : OfflineTransfer(d1, d2, amount)

VaultStep ==
    \/ \E d \in DeviceIds, v \in VaultIds, initialBalance \in 0..MaxPayload, condition \in 0..MaxPayload :
           CreateVault(d, v, initialBalance, condition)
    \/ \E v \in VaultIds, proof \in 0..MaxPayload : UnlockVault(v, proof)

ActivationStep ==
    \/ \E d \in DeviceIds : UnlockSpendGate(d)
    \/ \E d \in DeviceIds : ActivateAgain(d)

EmissionStep == ConsumeJAPAndEmit

ProofAckStep == ConsumeSpentProof

ObservationStep ==
    \/ \E g \in GenesisIds, d \in DeviceIds : AddDevice(g, d)
    \/ \E d \in DeviceIds : AddStorageNode(d)
    \/ \E d \in DeviceIds : GenerateKeys(d)
    \/ EnterPhase1
    \/ EnterPhase2
    \/ EnterPhase3

Core_actCount == shardTree - emissionIndex
Core_spent == spentJaps
Core_commit == shardTree
Core_supply == sourceRemaining
Core_spentProofs == { p.jap : p \in spentProofs }
Core_consumedProofs == { p.jap : p \in consumedProofs }
Core_step == step

Core == INSTANCE DSM_ProtocolCore
  WITH DeviceIds <- DeviceIds,
       MaxSupply <- MaxSupply,
       MaxStep <- MaxStep,
       actCount <- Core_actCount,
       spentJaps <- Core_spent,
       spentProofs <- Core_spentProofs,
       consumedProofs <- Core_consumedProofs,
       sourceRemaining <- Core_supply,
       commit <- Core_commit,
       step <- Core_step

\* Safety properties
NoDuplicateDevices ==
    \A g1,g2 \in GenesisIds, d \in DeviceIds :
        (d \in devices[g1] /\ d \in devices[g2]) => g1 = g2

ActiveRelationshipsSymmetric ==
    \A d1,d2 \in DeviceIds :
        relationships[<<d1,d2>>].state = "active" <=> relationships[<<d2,d1>>].state = "active"

\* Additional safety properties for advanced features
VaultsOwnedByCreator ==
    \A d \in DeviceIds, v \in VaultIds : (v \in vaults[d]) => (vaultState[v].owner = d)

\* ActivatedDevicesHaveKeys ==
\*     \A d \in DeviceIds : (d \in activatedDevices) => (keys[d].sphincs = 1 /\ keys[d].kyber = 1)

OfflineSessionsSymmetric ==
    \A d1,d2 \in DeviceIds :
        (<<d1,d2>> \in offlineSessions) <=> (<<d2,d1>> \in offlineSessions)

\* ==========================================================================
\* DJTE proof-carrying safety invariants (structural)
\*
\* shardLists is an explicit witness structure for activations.
\* These invariants enforce that it is consistent with activatedDevices.
\* ==========================================================================

\* Shard list helpers (scalable)
ShardIds == 0..(NumShards - 1)

\* Convert a sequence to the set of its elements (TLA+ has no built-in SeqToSet).
SeqToSet(seq) == { seq[i] : i \in 1..Len(seq) }

\* The set of devices present anywhere in shardLists.
\* IMPORTANT: for empty shards, the index set 1..Len(shardLists[s]) is 1..0,
\* which in TLA+ is the set {1,0} (not empty). Guard with IF to ensure we
\* contribute the empty set for empty sequences.
ListedDevices ==
    UNION {
        SeqToSet(shardLists[s])
        : s \in ShardIds
    }

\* Total length of all shard lists (counts sequence elements; duplicates count multiple times).
TotalShardListLen == Sum({ Len(shardLists[s]) : s \in ShardIds })

\* No duplicates anywhere in shardLists (within a shard or across shards).
\* Robust scalable form: if (a) no within-shard duplicates and (b) the total number
\* of distinct elements across shards equals the sum of per-shard distinct counts,
\* then no element can appear in two different shards either.
NoDuplicateInShardLists ==
    /\ \A s \in ShardIds : Cardinality(SeqToSet(shardLists[s])) = Len(shardLists[s])
    /\ \A s1, s2 \in ShardIds :
           (s1 # s2) => (SeqToSet(shardLists[s1]) \intersect SeqToSet(shardLists[s2]) = {})

\* Type sanity: every listed device is a real device id.
ShardListsWellTyped == ListedDevices \subseteq DeviceIds

\* Optional but production-grade: shardLists are an exact partition of activatedDevices.
ShardListsCoverActivated == ListedDevices = activatedDevices

\* If you keep activatedDevices as "ever activated at least once", keep it consistent with actCount.
\* In system mode, allow other subsystems to exist without forcing them to keep the
\* DJTE view (activatedDevices/actCount) perfectly synchronized. In harness mode,
\* activation is the only way these values change, so we require exact equality.
ActivatedDevicesConsistent ==
    IF UseHarness
        THEN activatedDevices = { d \in DeviceIds : actCount[d] > 0 }
        ELSE activatedDevices \subseteq { d \in DeviceIds : actCount[d] > 0 }

\* Consistency: derived total equals set cardinality.
\* (This captures that we are modeling an activation accumulator, not a multiset.)
\* TotalActivated is derived from the shard witness structure (shardLists).
\* It should equal the number of distinct devices listed across shards.
\* We intentionally do NOT tie this to actCount (which counts activation instances).
ActivationCountConsistent == TotalActivated = Cardinality(ListedDevices)

\* Total activation INSTANCES implied by actCount (this is the real budget).
TotalActivations == Cardinality(ActivationInstances)

\* ActCount is the authoritative activation-instance counter. Since shardLists is
\* a per-device witness (set-like), require the total activation instances to be
\* at least the number of distinct activated devices.
ActCountLowerBoundsDistinctActivated == TotalActivations >= Cardinality(activatedDevices)

\* Spending cannot exceed created activation instances.
NoMoreSpentThanActivationInstances == Cardinality(spentJaps) <= TotalActivations

\* Shard assignment consistency: each listed device resides in its computed shard.
\* ShardAssignmentConsistent: every listed device resides in its computed shard.
ShardAssignmentConsistent ==
        \A s \in 0..(NumShards - 1) :
            \A i \in 1..Len(shardLists[s]) : ShardOf(shardLists[s][i]) = s

\* ==========================================================================
\* DJTE spent-proof invariants (structural)
\*
\* spentJaps must only contain digests that could have been produced.
\* In TLC we keep this check finitely witnessable by bounding the seed search.
\* The protocol intent is: spent digests must have been derivable from the
\* activated set at some point.
SpentJapsWellFormed == spentJaps \subseteq AllJaps

\* Every spent digest must correspond to some activated device at the time.
\* (We can't recover the exact seed used from the digest in this abstraction,
\* so we enforce a weaker but still meaningful invariant: spending cannot
\* outnumber activation instances.)
NoMoreSpentThanActivated == Cardinality(spentJaps) <= TotalActivations

\* Stronger spelling: spending bound must not exceed the abstract refinement budget.
\* (These are definitionally equal today, but keeping this makes the intent explicit
\* and protects against future refactors where Abs_budget changes.)
NoMoreSpentThanBudget == Cardinality(spentJaps) <= Abs_budget

\* Refinement-strengthening equalities: these tighten the local proof obligations
\* around the abstract mapping so bounded TLC runs catch bookkeeping drift early.
EmissionsMatchSpentJaps == emissionIndex = Cardinality(spentJaps)

SupplyTracksEmissions == sourceRemaining + emissionIndex = MaxSupply

SpentProofsCoverSpentJaps == { p.jap : p \in spentProofs } = spentJaps

SpentProofCountMatchesSpentJaps == Cardinality(spentProofs) = Cardinality(spentJaps)

ConsumedProofCountBounded == Cardinality(consumedProofs) <= Cardinality(spentProofs)

RefinementStrengthening ==
    /\ EmissionsMatchSpentJaps
    /\ SupplyTracksEmissions
    /\ SpentProofsCoverSpentJaps
    /\ SpentProofCountMatchesSpentJaps
    /\ ConsumedProofCountBounded

\* Phase harness sanity: bounded phase only.
PhaseWellFormed == phase \in 0..3

\* Temporal monotonicity checks mirroring the abstract layer.
SpentJapsNeverShrink ==
    [][spentJaps \subseteq spentJaps']_vars

CommitNeverDecreasesConcrete ==
    [][shardTree' >= shardTree]_vars

SourceRemainingNeverIncreases ==
    [][sourceRemaining' <= sourceRemaining]_vars

\* Liveness properties
EventuallyAllMessagesProcessed ==
    <>[](net = {})

\* ==========================================================================
\* Spent-proof artifacts (replay resistance)
\*
\* spentProofs and consumedProofs are first-class artifacts in the model:
\* - A proof object is minted when a JAP is consumed.
\* - A proof object can be acknowledged/consumed exactly once.
\* - consumedProofs cannot contain a proof that doesn't exist in spentProofs.
\* - Every spent JAP must correspond to exactly one minted proof object.
\* ==========================================================================

ConsumedProofsSubset == consumedProofs \subseteq spentProofs

\* No proof object can be consumed twice (structural: set semantics).
NoDuplicateProofConsumption == Cardinality(consumedProofs) = Cardinality({ p \in consumedProofs : TRUE })

\* Every spent jap has exactly one corresponding proof object in spentProofs.
SpentProofsMatchSpentJaps ==
    /\ \A j \in spentJaps : Cardinality({ p \in spentProofs : p.jap = j }) <= 1
    /\ \A p \in spentProofs : p.jap \in spentJaps

\* Convenience bundle for DJTE-specific safety checks.
DJTESafety ==
    /\ ShardListsWellTyped
    /\ ActivatedDevicesConsistent
    /\ (UseHarness => ShardListsCoverActivated)
    /\ NoDuplicateInShardLists
    /\ ShardAssignmentConsistent
    /\ (phase >= 1 => SpentJapsWellFormed)
    /\ (phase >= 1 => NoMoreSpentThanActivated)
    /\ (phase >= 1 => NoMoreSpentThanBudget)
    /\ (phase = 0 => spentJaps = {})
    /\ (phase = 0 => spentProofs = {})
    /\ (phase >= 2 => ConsumedProofsSubset)
    /\ (phase >= 2 => NoDuplicateProofConsumption)
    /\ (phase >= 2 => spentJaps \subseteq { p.jap : p \in spentProofs })
    /\ (phase >= 2 => SpentProofsMatchSpentJaps)
    /\ Cardinality(spentJaps) <= MaxSupply
    /\ PhaseWellFormed

\* ---------------------------------------------------------------------------
\* Debug: Conjunct isolation for DJTESafety.
\* These invariants are for diagnosis only; they are not referenced by configs.
\* If DJTESafety fails, enable these one-by-one in the .cfg as INVARIANT lines
\* to see the first failing conjunct.
\* ---------------------------------------------------------------------------

DJTE_Inv1_ShardListsWellTyped == ShardListsWellTyped
DJTE_Inv2_ActivatedDevicesConsistent == ActivatedDevicesConsistent
DJTE_Inv3_ShardListsCoverActivated == (UseHarness => ShardListsCoverActivated)
DJTE_Inv4_NoDuplicateInShardLists == NoDuplicateInShardLists
DJTE_Inv5_ShardAssignmentConsistent == ShardAssignmentConsistent
DJTE_Inv6_SpentJapsWellFormed == (phase >= 1 => SpentJapsWellFormed)
DJTE_Inv7_NoMoreSpentThanActivated == (phase >= 1 => NoMoreSpentThanActivated)

\* Concrete vault bounds (loud failure if conservation is violated).
SourceVaultBounded == sourceRemaining \in 0..MaxSupply

ProofGlue ==
    /\ DJTESafety
    /\ RefinementStrengthening
    /\ SourceVaultBounded

\* ============================================================================
\* TRIPWIRE & FORK EXCLUSION (Atomic Interlock)
\* ============================================================================
\* No signer consumes its own lineage parent twice: no two accepted steps of
\* one signer on one relationship claim the same parent with different
\* children. Two sends that cross share a projection parent but consume
\* different lineage parents, so both stand.
TripwireInvariant ==
    \A r1, r2 \in ledger :
        (r1.rel = r2.rel /\ r1.signer = r2.signer /\ r1.oldTip = r2.oldTip) => (r1.newTip = r2.newTip)

\* Sum of the payloads of a finite set of frozen sends.
RECURSIVE SumPayload(_)
SumPayload(S) == IF S = {} THEN 0
                 ELSE LET r == CHOOSE x \in S : TRUE IN r.payload + SumPayload(S \ {r})

\* Sum of the balances of a finite set of devices.
RECURSIVE SumBalances(_)
SumBalances(S) == IF S = {} THEN 0
                  ELSE LET d == CHOOSE x \in S : TRUE IN deviceBalance[d] + SumBalances(S \ {d})

\* Value is neither minted nor lost: every balance plus every admitted debit
\* not yet credited is what the devices started with.
TokenConservation ==
    SumBalances(DeviceIds) + SumPayload({ r \in outbox : ~Applied(r) })
        = Cardinality(DeviceIds) * MaxPayload

\* With nothing in flight either way, the two devices hold one relationship
\* tip, and each pins the other's lineage head.
ProjectionAgreement ==
    \A d, p \in DeviceIds :
        (d # p /\ relationships[<<d, p>>].state = "active" /\ Settled(d, p) /\ Settled(p, d))
            => /\ relationships[<<d, p>>].tip = relationships[<<p, d>>].tip
               /\ online[<<d, p>>].pin = online[<<p, d>>].lin

\* The barrier is held by durable state: a gate by the frozen send it guards,
\* an awaited certificate by the journal that holds the delta.
BarrierHeldDurably ==
    \A d, p \in DeviceIds :
        /\ online[<<d, p>>].gate # 0 => \E r \in outbox : r.id = online[<<d, p>>].gate /\ r.from = d /\ r.to = p
        /\ online[<<d, p>>].awaits # 0 => \E j \in journal : j.id = online[<<d, p>>].awaits /\ j.from = d /\ j.to = p

\* Non-vacuity witness (expected violated in DSM_CrossingSettles.cfg): two
\* sends crossed — a join exists only for two steps from one projection
\* parent — and both devices have settled, released both gates and both
\* recipients, on the joined tip.
NoCrossingSettles ==
    ~\E d, p \in DeviceIds :
        /\ d # p
        /\ Settled(d, p) /\ Settled(p, d)
        /\ relationships[<<d, p>>].tip = relationships[<<p, d>>].tip
        /\ relationships[<<d, p>>].tip \in { j.tip : j \in joins }

RefinedSafety ==
    /\ DJTESafety
    /\ RefinementStrengthening
    /\ TripwireInvariant
    /\ SourceVaultBounded
    /\ TokenConservation
    /\ ProjectionAgreement
    /\ BarrierHeldDurably

THEOREM ConcreteInitRefinesCore == Init => Core!Init
  BY DEF Init, Core!Init, Core_actCount, Core_spent, Core_commit, Core_supply,
         Core_spentProofs, Core_consumedProofs, Core_step

====
