SoFi: Sovereign Deterministic Finance
A Normative Specification for Deterministic Limbo Vaults,
Encumbrance Accounting, Multi-Vault Routing, and Non-Authoritative Storage
Infrastructure
Brandon “Cryptskii” Ramsay
Version 2.0 – August 20, 2026
Abstract
SoFi extends DSM’s ordinary bilateral transaction model by making one counterparty state
object executable while its owner is absent. A liquidity provider funds a Deterministic Limbo
Vault (DLV) by moving value out of ordinary spendable owner balance and into encumbered
DLV reserve state. The DLV therefore holds the liquidity mathematically; the LP does not
retain a second spendable copy. The LP controls the DLV by committing the policies that
govern its state transitions, but while value remains encumbered the LP is also bound by those
policies. Market transitions may move DLV reserves only through successors permitted by the
owner-committed DLV fulfillment policy, the applicable token policy, the remaining reserves,
and the committed per-transition size bound. Returning reserves from the DLV to ordinary
owner balance is a separate governed release transition and requires satisfaction of the vault’s
committed release/close policy.
This is the practical difference from an ordinary DSM transaction initiated online while the
remote counterparty is absent. The present party may send its own value toward the absent party,
but cannot cause value already controlled by the absent party to move outward without authority
that was committed before the absent party left. A funded DLV is that authority embodied as
encumbered executable state: the value is already inside the DLV, and the conditions under
which the DLV may exchange it were fixed in advance. A live trader may therefore buy from the
DLV while the LP is absent. The market transaction itself is online; only the LP may be absent.
The DLV does not replace DSM bilateral state. The initiating trader still advances under
ordinary DSM parent, signature, conservation, pending, and Tripwire rules. The LP still
maintains its bilateral relationship state against an active DLV. While the LP is absent, that
owner-side relationship state may lag the DLV’s realized market history; if the LP returns while
the DLV remains active, it deterministically catches up and publishes a fresh authenticated
baseline. Catch-up is synchronization of already-realized DLV state, not a new approval, veto, or
value movement. If a terminal owner close has already become binding-final and folded, that
close is itself the final owner/DLV state update and no separate catch-up step exists for the
retired DLV.
Because a public DLV may be targeted concurrently by unrelated traders, more than one
constructor can derive a valid bounded fulfillment from the same DLV parent before either
learns of the other. SoFi adds a scoped client-driven quorum-binding procedure for the DLV
resource keys. A quorum COMMIT makes one candidate binding-final for those DLV parents: no
competing candidate may consume them. What binding Finality means economically depends on
the successor kind. For a market bundle, binding does not by itself move the DLV reserve cursor:
the exact trader bilateral successor must also be accepted under ordinary DSM and produce
a verifiable trader-acceptance witness carrying the ordinary accepted-successor commitment
C+
T , its successor-state authentication σ+
T , and inclusion evidence under the root committed by
C+
T . Only a binding-final market bundle with that witness is a realized DLV settlement eligible
1
SoFi: Sovereign Deterministic Finance Revision 15
for composition. A binding-final market bundle whose trader leg never completes can lock the
DLV parent, but it cannot skew advertised reserves or create a half-completed exchange. Owner
release/close is intentionally different after the same binding race: in the beta profile PR is
owner-local by construction, and the exact owner-signed release successor plus every fact needed
to verify it exist before binding begins. If that release/close candidate reaches binding Finality
first, the release successor is realized immediately at the DLV, the released reserves are credited
exactly once according to that successor, and a terminal close retires the vault. No owner-side
acceptance artifact or post-binding materialization step exists. For any one unchanged DLV
parent, at most one binding-final unresolved market candidate can occupy that parent at a time.
Storage members do not form or announce the quorum and do not understand the trade. Class
K contacts the owner-committed storage set, verifies canonical responses, and computes the fixed
threshold locally. Storage members remain application-blind opaque-byte persistence plus generic
conditional-storage machinery. Canonical protocol objects are immutable content-addressed
bytes; logical paths are discovery indexes only. SoFi market settlement is online, no wall-clock
timeout changes validity, and there is no global ledger, global mempool, validator ordering
market, or shared global sequence.
2
SoFi: Sovereign Deterministic Finance Revision 15
The Core Mental Model
A DLV Holds the Liquidity; the LP Commits the Rules
The shortest correct way to think about SoFi is that a DLV is actual encumbered reserve state
owned and controlled by the LP but no longer available as the LP’s ordinary spendable balance.
Funding is a state move, not a promise:
fund DLV
BLP
−−−−−−→ RDLV
.
⏞ ⏟⏟ ⏞
⏞ ⏟⏟ ⏞
ordinary spendable balance
encumbered DLV reserves
There is no second spendable copy on the LP side. Once funded, the market trades against the
DLV’s reserves themselves.
Ordinary DSM transaction with an absent counterparty. Suppose Alice is online and Bob
is not presently participating. Alice may originate a transfer of Alice’s own value toward Bob under
ordinary DSM bilateral machinery. What Alice cannot do is cause value already controlled by Bob
to move outward toward Alice, because Bob is absent and has supplied no fresh authority for that
outbound transition. A bilateral step requiring Bob to send value therefore waits under the ordinary
pending/participation rules.
DLV transaction with an absent LP. Now suppose Bob previously moved liquidity into a
DLV. That value is already inside an executable state object whose market-transition rules Bob
committed before Alice appeared. The DLV policy defines the admissible fulfillment family, the
token policy constrains what the token permits, the remaining DLV reserves bound what exists to
be exchanged, and BM supplies the committed per-transition size ceiling. Alice may provide the
required consideration and receive the corresponding DLV reserve output while Bob is absent. Alice
is not spending Bob’s ordinary balance and no storage node is granting permission; she is exercising
a transition the funded DLV was already allowed to make.
ordinary absent counterparty
⏞ ⏟⏟ ⏞
may receive; cannot newly send value out
−→ funded DLV
⏞ ⏟⏟ ⏞
holds value and may exchange it under committed rules
The owner controls the DLV but is also bound by it. Ownership does not mean the LP
can directly spend the encumbered reserves. While the value remains inside the DLV, every market
movement must satisfy the DLV market policy and token policy. Moving the remaining reserves
back to ordinary owner balance is itself a DLV state transition. The vault birth state therefore
commits a release/close policy PR; withdrawal or close is valid only when that condition and the
ordinary parent, conservation, signature, and contention rules are satisfied. The reverse move is:
valid release/close successor under PR
−−−−−−−−−−−−−−−−−−−−−−−→BLP.
RDLV
The LP cannot bypass that transition merely because it owns the DLV. Release/close also contends
for the current DLV parent, but it has no trader-like second leg. In the beta profile PR is owner-local
by construction, and the exact owner-signed release successor is complete before the first mutating
binding step. If the close candidate wins binding first, competing market candidates lose that parent
and the same binding-final result makes the already-authorized release successor composable. The
reserve debit from the DLV and credit to ordinary owner balance are one conservation-preserving
owner/DLV state transition. A terminal close retires the DLV; there is no owner-side acceptance
artifact, no post-binding owner action, and no owner-bound-but-unrealized state.
3
SoFi: Sovereign Deterministic Finance Revision 15
The LP still has bilateral state. The LP’s bilateral relationship state against an active DLV
still exists. If the LP is absent while the DLV trades, that owner-side relationship state may lag the
DLV’s realized market-successor history. If the LP returns while the DLV remains active, it catches
up deterministically to those already-realized market successors and publishes a fresh authenticated
DLV baseline. Catch-up is synchronization; it does not move value a second time and is not a
new authorization step. If a terminal close has already folded, the DLV is retired and no separate
catch-up transition is required for that closed vault.
Why SoFi needs a quorum at all. The DLV is publicly executable under the policy the owner
committed. Two unrelated traders can therefore read the same DLV parent and independently
construct valid candidate successors before either observes the other. Tripwire protects each trader’s
own bilateral history, but those unrelated traders do not share one trader history. The client-driven
quorum procedure exists only to bind the shared DLV parent to at most one candidate bundle.
That binding is deliberately not the economic reserve fold. A quorum COMMIT makes the
selected bundle binding-final for the consumed DLV parent set. The DLV reserve successor becomes
realized only after the initiating trader’s exact bilateral successor is accepted under ordinary DSM
and a verifiable trader-acceptance witness proves that fact by authenticating the accepted post-
advance root and the settlement inclusion under it. A binding-final but unaccepted trade blocks
the DLV parent; it does not change the DLV’s reserves. This distinction prevents a trader from
distorting the vault’s advertised reserves merely by winning the DLV contention race and then
refusing to complete its own bilateral leg.
What is and is not “offline.” A SoFi market trade is an online transaction. The LP may be
absent. That is different from DSM’s separate offline/bearer transaction capability. Nothing in SoFi
requires DLV market acquisition, quorum recovery, trader-acceptance verification, or independent
binding-Finality verification to work while the device itself is disconnected.
4
SoFi: Sovereign Deterministic Finance Revision 15
Contents
The Core Mental Model 3
1 Scope, Status, and Normative Language 8
1.1 1.2 1.3 1.4 Status and substantive changes . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 8
Normative language . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 10
Conformance classes . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 10
Clocklessness rule . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 11
2 DSM Substrate Assumptions 11
3 Notation, Canonical Encoding, and Commit Bytes 12
3.1 Domain separation . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 12
3.2 Canonical commit bytes . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 12
3.3 Transport and display encoding . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 13
3.4 Fixed-point arithmetic . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 13
4 Deterministic Limbo Vaults 13
4.1 4.2 4.3 Definition . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 13
Reserve ownership and custody . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 14
Predicate bounds . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 14
5 Authority: Public Data Does Not Grant Reserve Control 15
5.1 5.2 Owner authority . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 15
Completion witness . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 16
6 DLV Bilateral Advancement and Quorum Settlement 16
6.1 Composed vault state . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 16
6.2 History-bound parent anchors . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 18
6.3 Stale construction . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 18
6.4 Committed storage set and fixed quorum . . . . . . . . . . . . . . . . . . . . . . . . 18
6.5 Complete SettlementBundle . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 19
6.6 Settlement resource keys . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 20
6.7 Generic storage records and immutable bytes . . . . . . . . . . . . . . . . . . . . . . 20
6.8 Client-driven quorum binding transaction . . . . . . . . . . . . . . . . . . . . . . . . 21
6.9 DLV binding Finality, trader acceptance, realization, and evidence . . . . . . . . . . 22
6.10 Loser behavior and reroute . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 25
6.11 Owner close . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 25
7 Smart Commitments and Atomic Composition 26
7.1 Token conservation . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 26
7.2 External commitments . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 26
8 Deterministic Encumbrance Accounting 27
5
SoFi: Sovereign Deterministic Finance Revision 15
9 Trade Intent, Multi-Vault Routes, and SDK-Resident Routing 27
9.1 Trade intent . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 27
9.2 Allocation bundles . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 27
9.3 Routes and route sets . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 28
9.4 Select, verify, build, bind . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 28
9.5 Deterministic reroute . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 29
9.6 Partial execution is forbidden . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 29
10 Trade Digests: Unordered Evidence 29
10.1 Reference windows . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 30
10.2 Bilateral agreement . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 30
11 Admissibility Filters and Unilateral References 30
12 Perpetual Instruments 30
12.1 Activity-denominated funding . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 30
12.2 Liquidation . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 31
13 Clockless Liveness 31
14 Receipts 31
15 Storage Node Specification 32
15.1 Three separate storage concepts . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 32
15.2 Hard constraints . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 33
15.3 Canonical immutable objects . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 34
15.4 Discovery indexes . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 34
15.5 Generic conditional-binding interface . . . . . . . . . . . . . . . . . . . . . . . . . . . 34
15.6 Client-driven quorum transaction . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 35
15.7 Query completeness and non-selective serving . . . . . . . . . . . . . . . . . . . . . . 36
15.8 Object and index classes . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 36
15.9 Ordinary publication and frozen exact bytes . . . . . . . . . . . . . . . . . . . . . . . 37
15.10Resource accounting . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 37
16 SDK Conformance 37
16.1 Route-set construction . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 37
16.2 Verification, quorum binding, and materialization . . . . . . . . . . . . . . . . . . . . 38
16.3 Deterministic failure taxonomy . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 39
16.4 User contract . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 40
17 Online SoFi Market Boundary, LP Absence, and DSM Offline Transfers 40
18 Security Model 41
18.1 Storage member compromise and availability . . . . . . . . . . . . . . . . . . . . . . 41
18.2 Concurrent same-parent safety . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 41
18.3 Bilateral seam: trader Tripwire, DLV quorum, LP catch-up . . . . . . . . . . . . . . 42
18.4 Multi-vault atomicity . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 42
18.5 Constructor crash and ambiguous outcomes . . . . . . . . . . . . . . . . . . . . . . . 42
18.6 Liveness, overlapping transactions, and the FLP boundary . . . . . . . . . . . . . . . 44
6
SoFi: Sovereign Deterministic Finance Revision 15
18.7 Front running and ordering . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 44
18.8 Router compromise . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 44
18.9 Vault owner compromise . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 44
19 Economic Model 45
19.1 Liquidity providers . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 45
19.2 Storage nodes . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 45
19.3 Traders . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 45
20 Architectural Comparison 45
21 Conformance Test Vectors 46
22 Implementation Rules for Beta 51
23 Security and Liveness Claims in Plain Language 53
24 Conclusion 55
7
SoFi: Sovereign Deterministic Finance Revision 15
1 Scope, Status, and Normative Language
1.1 Status and substantive changes
This revision is a clean statement of the intended SoFi architecture and the storage boundary
required to implement it without assigning financial authority to storage members.
The substantive rules are:
1. SoFi remains DSM bilateral finance. A DLV is not a replacement transaction model.
It is funded encumbered reserve state that can serve as the absent LP’s executable bilateral
counterparty under rules committed before the trader exists.
2. The DLV actually holds the liquidity. Funding moves value out of ordinary spendable
owner balance and into DLV reserve state. The LP owns and controls the DLV but does not
retain a second spendable copy of those reserves.
3. The DLV is an exception to the ordinary absent-counterparty pending rule. In an
ordinary DSM transaction initiated while the counterparty is absent, the present party can send
its own value toward the absent party but cannot cause value controlled by that absent party to
move outward without previously committed authority. A funded DLV already contains both
the encumbered value and the committed market-transition rules, so a live trader may buy from
the DLV while the LP is absent.
4. DLV reserve movement is policy-bounded. A market successor must satisfy the owner-
committed market policy PM , the applicable token policy, the actual remaining reserves, the
per-transition size ceiling committed in BM , conservation, and ordinary DSM validity. There is
no separate economic quota variable in Vn.
5. Owner withdrawal is also a governed DLV transition, but beta close has no second
acceptance leg. The vault birth state commits a release/close policy PR. The LP cannot
directly reclaim encumbered reserves; a release, withdrawal, or close must consume the current
DLV parent, satisfy owner-local PR, token policy, conservation, and exact owner authority, and
win the same parent contention as a market transition. Because the complete owner-signed
release successor is already verifiable before binding, a binding-final release/close folds that
exact successor immediately. A terminal close returns the committed reserves exactly once and
retires the DLV.
6. The LP still catches up bilaterally while the DLV remains active. The LP’s bilateral
relationship state against an active DLV may lag while the LP is absent. On return to an active
DLV, the LP deterministically folds the already-realized market history and produces a new
authenticated baseline. Catch-up is synchronization, not authorization. A terminal close is
already the final owner/DLV update and requires no separate catch-up step.
7. Stale-state rejection and concurrent DLV origination are different mechanisms.
Parent binding rejects a constructor that learns the DLV has already advanced. It does not
prevent two unrelated traders that both read the same DLV parent before either advancement is
visible. The client-driven quorum binding transaction covers that shared-DLV contention case.
8. The trader side still uses ordinary DSM and Tripwire. The quorum does not finalize
the trader’s sovereign chain. The exact trader bilateral parent/successor bound into the
SettlementBundle remains subject to ordinary DSM parent, signature, conservation, pending,
and Tripwire rules.
8
SoFi: Sovereign Deterministic Finance Revision 15
9. The owner fixes the storage domain. Vault creation commits both the storage-member
set S and the settlement threshold q. Endpoints merely resolve committed member identities.
Current reachability cannot change S or q.
10. The quorum is computed client-side. Class K contacts the members of S, authenticates
distinct member responses, verifies returned canonical bytes, and locally evaluates whether at
least q qualifying members agree. A Class N member does not know whether a quorum exists
and does not count other members.
11. Storage nodes understand no SoFi economics. They store and serve opaque bytes and
enforce only generic storage-engine rules such as content addressing, compare-and-exchange,
monotonic transaction rounds, and atomic local multi-key updates. They do not parse a
SettlementBundle, DLV, route, AMM invariant, fee, output, or user intent.
12. Canonical bytes and discovery aliases are different objects. Immutable protocol bytes
live under deterministic content addresses. Logical paths are indexes from names to content
addresses. A moving latest pointer is never canonical state and may not be used as a settlement
or parent-authority input.
13. A client-driven quorum transaction may have recoverable intermediate state. An
interrupted operation is not required to leave zero bytes everywhere. Intermediate generic
bindingrecordsarenon-Final, protocol-recoverable, andmustconvergetooneterminalCOMMIT
or ABORT under the stated liveness assumptions. A caller that loses the outcome treats it as
INDETERMINATE, not as failure.
14. Multi-vault acquisition is one transaction. A route consuming several DLV parents binds
all of those parents to one complete SettlementBundle. Per-vault acquisition followed by rollback
is non-conforming.
15. The committed payload is complete. Before quorum binding begins, the SettlementBundle
contains every DLV successor, exact initiating-trader bilateral transition, signature, proof, and
recovery object needed to verify the selected route without fresh private material from the
original constructor.
16. An unresolved settlement fences the initiating trader parent. Before the first mutating
DLV quorum-binding step, Class K durably binds the attempt to the exact trader bilateral
parent. While the DLV transaction is RECOVERING or INDETERMINATE, no different successor may
advance from that parent, even under a new intent or nonce. Tripwire remains the underlying
one-successor state rule.
17. Reroute requires a terminal prior outcome. A route that is explicitly ABORTED or
conflicts with a previously binding-final DLV settlement may fall through to the next route
already committed by the same intent. The broader trader-parent fence remains in force until
the unresolved attempt becomes terminal.
18. SoFi market settlement is online. The LP may be absent; the market transaction itself
is not an offline protocol. DSM may support separate offline/bearer execution, but SoFi does
not require DLV market acquisition, recovery, or independent beta binding-Finality verification
while disconnected.
9
SoFi: Sovereign Deterministic Finance Revision 15
19. Multi-vault horizontal allocation is first-class. One logical pair leg may allocate across
several independent DLVs. The vaults remain independently owned; one route-wide Settlement-
Bundle supplies all-or-none DLV-side settlement.
20. Binding Finality, realization, and availability are different. Once the quorum transaction
chooses a candidate for the DLV resource keys, later node unavailability does not revoke that
historical binding fact. For a market candidate, the DLV reserves still do not advance until
the exact trader successor is proven accepted. For an owner-local beta release/close candidate,
binding Finality satisfies the completion gate and the exact pre-authorized release successor folds
immediately. A router that cannot obtain the binding evidence required to establish a discovered
candidate DLV’s current composed state reports DLV_BINDING_EVIDENCE_UNAVAILABLE and
excludes that candidate from the route set; it must not assume the advertised parent is still
active or unchanged.
21. Permanent market unresolution has real liveness costs. An unresolved market binding
can indefinitely fence the initiating trader parent and block owner close. Beta defines no
timeout-based escape for that market-side seam. A binding-final owner release/close is not
another unresolved state: under the beta owner-local PR profile it realizes and folds immediately.
For any one current DLV parent, at most one binding-final unresolved market candidate can
occupy that parent, although one multi-vault route may block several distinct DLVs.
22. Owner-offline composition depth is not magically bounded. While a DLV remains
active, composition work between authenticated owner catch-up baselines grows with the number
of realized market successors, and beta may also require live evidence for their underlying
binding decisions. Owner catch-up collapses that active-market history into a new baseline;
an LP absent indefinitely can leave a progressively more expensive active DLV to compose. A
terminal close ends that lineage rather than creating another catch-up segment.
23. A double binding-Final DLV observation is catastrophic. If two distinct binding-final
bundles consume one DLV parent, no tie-break is permitted. The affected lineage is quarantined
and the deployment is treated as having violated its storage safety assumptions.
1.2 Normative language
The key words must, must not, should, should not, and may are conformance requirements. A
statement without one of these words is explanatory and carries no conformance weight.
1.3 Conformance classes
Class C (Core). arithmetic.
The deterministic state machine and predicate evaluator. It emits canonical
commit bytes, verifies state transitions, evaluates bounded predicates, and performs deterministic
Class K (SDK/STK). Discovery, route construction, route-set binding, complete settlement-
bundle construction, client-driven quorum binding, local verification, deterministic materialization,
publication, reroute, and user-facing execution semantics. Class K embeds Class C.
10
SoFi: Sovereign Deterministic Finance Revision 15
Class N (Node). Non-authoritative persistence, indexing, and generic conditional storage. Class
N stores and serves opaque canonical bytes. It may enforce storage-generic rules required by a crash-
recoverable quorum transaction—for example immutable content addressing, compare-and-exchange
against a canonical key, monotonic transaction-round metadata, and one local atomic update over
a sorted key set. It must not parse or validate SoFi economic payloads, determine q, count other
members, select a route, or decide financial validity.
1.4 Clocklessness rule
Requirement 1.1. No protocol object, predicate, commitment, settlement rule, or validity decision
defined by SoFi may depend on wall-clock time, elapsed duration, a timestamp, a global height, or
a shared sequence across independent parties. Local state counters scoped to one DSM chain or one
DLV are permitted because they do not require a shared global ordering.
Operational service measurements may use wall-clock units, but they have no effect on protocol
validity.
2 DSM Substrate Assumptions
SoFi does not restate DSM. It assumes the following substrate properties.
Assumption 2.1 (Relationship-local state). Each participant maintains hash-adjacent state
under its own authenticated state structure. A realized successor consumes an identified parent
state and produces one local successor.
Assumption 2.2 (Precommit). Before a conditional successor family is exercised, the relevant
admissible branch family is committed. The commitment is consumed according to DSM rules.
Assumption 2.3 (Whole-state consumption). Value represented by a DLV is moved only by
a successor consuming the entire committed DLV state required by that transition. Partial hidden
consumption is not representable.
Assumption 2.4 (Tripwire). Within one DSM history, conflicting successors to one consumed
parent are rejected by the local deterministic state machinery.
Assumption 2.5 (Authenticated sparse state). DLV reserve leaves, encumbrance state, and
related proofs are bound under authenticated sparse Merkle roots and verified locally.
Assumption 2.6 (Single hash TCB). domain-separation tag.
H denotes BLAKE3 with a 32-byte output and an explicit
Assumption 2.7 (Signatures). DSM signatures are post-quantum EUF-CMA-secure signatures
over Core-emitted canonical commit bytes. SoFi assumes SPHINCS+ as the shipping signature
scheme.
11
SoFi: Sovereign Deterministic Finance Revision 15
Remark 2.8. The DLV does not weaken Tripwire. The initiating trader still advances one ordinary
DSM bilateral history, so conflicting trader successors from one trader parent remain a Tripwire
violation. The extra settlement rule exists because a funded public DLV holds encumbered reserves
that are executable under a bounded market policy while its LP is absent, and multiple unrelated
traders do not share one trader history with each other. Parent-state composition rejects a stale
constructor after a DLV advancement is known, but it does not prevent two unrelated constructors
that both read the same DLV parent before either advancement is visible. The client-driven quorum
binding transaction supplies the missing consume-once decision for that shared DLV parent.
3 Notation, Canonical Encoding, and Commit Bytes
3.1 Domain separation
Every commitment must be computed as
H(tag ∥Canon(x)).
The reserved tags in this revision are:
Tag Purpose
DSM/vault vault identity
DSM/vault-state vault state
DSM/precommit branch-family precommit
DSM/fulfillment owner-committed fulfillment mechanism
DSM/enc encumbrance set
DSM/enc-claim encumbrance claim identifier
DSM/intent trade intent
DSM/route-set route-set external commitment
DSM/allocation canonical same-pair allocation bundle
DSM/ext external commitment
DSM/digest trade digest
DSM/ref-window reference window
DSM/ref-rule unilateral reference rule
DSM/receipt stitched receipt
DSM/settlement-bundle complete signed settlement bundle
DSM/trader-settlement-acceptance/v2 canonical trader post-advance acceptance artifact
DSM/binding-tx client-driven opaque quorum transaction identifier
DSM/binding-keyset sorted settlement-resource key-set commitment
DSM/vault-state-anchor/v2 history-bound vault-state anchor
DSM/storage-object immutable content-addressed storage object
DSM/storage-set committed storage-set identity
DSM/unlock-tag receipt identifier only
3.2 Canonical commit bytes
Requirement 3.1. Class C must emit canonical commit bytes (CCB) for every hashed or signed
object. CCB is a Core format and is not protobuf serialization.
CCB rules:
12
SoFi: Sovereign Deterministic Finance Revision 15
1. fixed-width integers, big-endian;
2. byte strings length-prefixed by a 4-byte big-endian length;
3. fields emitted in ascending declared field-number order;
4. absent optional fields emitted with an explicit absence marker;
5. sets sorted lexicographically by element CCB;
6. maps emitted as sorted key-value pairs;
7. floating point forbidden;
8. every CCB blob begins with an object-class discriminant and CCB schema version.
Requirement 3.2. No two logical objects may map to one CCB encoding and no one logical
object may map to two CCB encodings.
3.3 Transport and display encoding
1. Transport is protobuf only.
2. Production JSON is forbidden.
3. Binary identifiers remain binary in Core and SDK internals.
4. Base32 Crockford is the permitted human-display encoding at UI, QR, and log boundaries.
5. Hexadecimal is not a protocol or UI encoding.
3.4 Fixed-point arithmetic
All prices, fees, ratios, and invariant calculations use checked integer arithmetic at scale 232 unless a
token’s base-unit arithmetic is exact without fixed-point conversion. Division uses floor semantics
with documented payer-adverse rounding. Overflow is predicate failure.
Exact rational representations. A protocol object may instead define an exact versioned rational
representation with a fixed denominator, where this specification states that denominator
explicitly. Such a representation is not converted to scale 232 . Its products are evaluated in
checked integer arithmetic wide enough not to overflow before any division, and the division floors
exactly once, adverse to the party who would otherwise gain from the truncation. Beta FeePolicyV1
of §5.1 uses this allowance with denominator 10 000.
The allowance exists because converting an exact rational such as f/10 000 to scale 232 introduces
a rounding stage with no protocol meaning. Two implementations that rounded at different points
would disagree on outputs while both claiming conformance.
4 Deterministic Limbo Vaults
4.1 Definition
Definition 4.1 (DLV). A Deterministic Limbo Vault is an encumbered state object inside its
owner’s DSM state that holds actual reserve value and acts as a precommitted executable bilateral
endpoint. Funding the DLV moves value from ordinary spendable owner balance into the DLV
reserve state. The LP retains ownership/control of the vault but not direct spendability of the
encumbered reserves. Market reserve movement occurs only through a valid DLV successor satisfying
the owner-committed market policy and applicable token policy. Returning reserve value to ordinary
owner balance occurs only through a valid release/close successor satisfying the committed release
policy. The DLV does not create a second copy of the reserves and does not replace DSM bilateral
relationship semantics.
A market DLV state is represented abstractly as
Vn = (go,do,vault
_
id,n,RA,RB ,PM ,PR,Φ,E,β,hn,ro,S,q),
13
SoFi: Sovereign Deterministic Finance Revision 15
wherego anddo bindowneridentity,nisthevault-localgeneration,RA,RB aretheactualencumbered
reserves, PM is the bounded market-fulfillment policy, PR is the bounded release/withdraw/close
policy, Φ the fee policy, E the encumbrance set, β an optional iteration budget, hn the local
parent commitment, ro the authenticated owner root, S the committed storage set, and q the fixed
settlement threshold for that set.
The canonical state commitment is
cn = H(DSM/vault-state ∥Canon(Vn)).
The vault identity is fixed at creation and never changes.
The local parent commitment hn is the lineage edge into Vn, and is defined by the recurrence
h0 = H(DSM/vault-state-parent/genesis/v2 ∥vault
_
id),
hn = cn−1 for n > 0.
The genesis value commits the vault identity and nothing else. Birth reserves, the committed
storage set S, and the fixed threshold q are already fields of V0 and of the generation-0
VaultStateAnchorV2, and duplicating them into h0 would blur a field whose only role is the
predecessor edge. An untyped all-zero sentinel is not used: a domain-separated genesis value is
a value no other construction produces, and it makes "this is generation zero" a derivation
rather than a magic-constant comparison.
Because hn commits cn−1, and cn−1 commits the whole canonical prior state rather than its
reserve amounts alone, two histories that arrive at identical reserves still differ in every
later parent binding whenever any preceding canonical DLV state differed. This is the property
Requirement 6.5 requires of the parent anchor, and Definition 6.4 carries hn as
parent_
state
_
commitment.
4.2 Reserve ownership and custody
Requirement 4.2 (Reserve location and no duplicate custody). DLV reserves must not
simultaneously remain available as ordinary spendable owner balance. Funding a DLV must debit
the owner’s ordinary spendable state and credit the corresponding DLV reserve state in one valid
conservation-preserving transition. After funding, the reserve value is represented by the DLV. A
market trade never asks the LP to send from a separate balance; it consumes a DLV parent and
derives a valid DLV successor. Owner absence therefore does not imply that the reserves themselves
are absent.
Consequence. The LP may be absent from the live market interaction while the funded DLV
continues to trade. The LP’s absence changes availability only where an owner-specific transition
is required, such as a policy-governed release/close or policy replacement. It does not make the
market transaction offline and does not move the reserve value back into the LP’s ordinary balance.
4.3 Predicate bounds
Requirement 4.3. Every predicate family must declare a static evaluation budget. Permitted
operations are checked integer arithmetic, comparison, boolean composition, hashing, signature
verification, sparse Merkle inclusion, membership over committed bounded sets, and iteration with
compile-time bounded cardinality. Dynamic dispatch, recursion, and unbounded loops are forbidden.
Requirement 4.4 (Precommitted executable market state). Consider an ordinary DSM
transaction initiated online while the remote counterparty is absent. The present party may authorize
movement of its own value toward that remote party, but it cannot cause value controlled by the
absent party to move outward without authority committed by that absent party. A funded DLV
supplies that authority by placing the value itself inside an encumbered executable state object
before a particular trader exists. The owner commits PM and BM ; a later trader may exercise only
a concrete DLV successor that satisfies those commitments, the applicable token policy, the actual
remaining reserves, the per-transition size ceiling in BM , conservation, and ordinary DSM validity.
Requirement 4.5 (DLV exception to pending and owner catch-up). The DLV is an
exception only to the need for a fresh owner participation step before the DLV’s already-encumbered
reserves may execute a permitted market transition. It is not an exception to parent binding,
conservation, signatures required from the live trader, Tripwire, token policy, or DLV policy. The
LP’s bilateral relationship state against an active DLV may lag while the LP is absent. If the LP
returns while the DLV remains active, it must deterministically catch that relationship state up
through the DLV market successors that were already realized. Catch-up records the DLV market
history into a fresh owner-authenticated baseline; it neither moves the reserve value a second time
nor constitutes a new approval, veto, rollback, or ordering step. If a terminal owner release/close
14
SoFi: Sovereign Deterministic Finance Revision 15
has already become binding-final and folded under Requirement 6.30, the DLV is retired and no
separate catch-up step is required for that closed vault.
Requirement 4.6 (Governed reverse encumbrance; owner-local beta profile). The LP
must not be able to move DLV reserves directly back into ordinary spendable owner balance merely
by virtue of ownership. The vault birth state commits a release/withdraw/close policy PR. Any
transition that reverses the encumbrance must consume the current DLV parent, satisfy PR, satisfy
the applicable token policy, preserve conservation, carry concrete owner authority over the exact
release successor, and obey the same parent-contention rules as another transition competing for
that DLV parent. Only the resulting valid successor may credit the released value back to ordinary
owner balance.
In the beta profile, PR is owner-local by construction. Its truth value must be decidable from the
authenticated current DLV parent, the exact owner-signed release/close successor, the applicable
token policy, and canonical proof/bundle bytes that are complete before the first mutating binding
step. Beta PR must not require a post-binding owner action, an external counterparty or co-
signature, a reference-window outcome, a liquidation/oracle branch, or any other external fact whose
acceptance would have to be proved after DLV binding. Therefore the owner release/close path has
no trader-like second completion leg. A future profile that admits externally conditioned release
policies is outside this one-phase beta rule and must define its own completion evidence before such
a successor may be folded.
5 Authority: Public Data Does Not Grant Reserve Control
5.1 Owner authority
Authority is not a secret derived from public values. It is a signature over either a concrete successor
or a bounded successor family.
Definition 5.1 (Owner authority). A successor Vn+1 carries owner authority if either:
(a) the witness contains Signowner(CCB(Vn+1)); or
(b) the witness contains an owner-signed fulfillment mechanism committed before Vn+1 existed,
plus a proof that Vn+1 satisfies every bound of that mechanism.
Definition 5.2 (Market fulfillment mechanism).
M= H(DSM/fulfillment ∥vault
_
id ∥c0 ∥CCB(BM )),
where BM commits the additional owner-committed bounds on market exercise that do not already
have a home in the vault state or in the predicate family: the per-transition size ceiling and the
authorized encumbrance purposes.
Single value source. PM , the fee policy Φ, the committed storage set S, and the fixed threshold
q are members of V0 under Definition 4.1, and c0 commits the complete canonical V0. The
owner-signed mechanism therefore already commits their birth values transitively, and BM does not
repeat them. This is a deliberate structural choice rather than an omission: two authoritative
copies of one fact create states that encode validly while disagreeing internally, and no equality
rule can be enforced by a verifier that holds only one of the two objects. Any future BM field
concerning fees or storage must express a semantically distinct bound or profile constraint, never
another copy of a V0 value.
The layering is therefore: PM is which bounded predicate family may execute, BM is the additional
owner-committed bounds on its exercise, the Smart Commitment C of Definition 7.1 is the concrete
transaction-time instance over ∆in, ∆out, external commitments, encumbrances and intent bounds,
and Vn is the actual reserve state being consumed. PM is committed at vault birth, before any
trader exists, so it is not structurally equal to C.
Shape of PM . PM is a birth-time, versioned predicate-family descriptor:
PM = (family
_
id,family
_version,evaluation
_budget,family
_parameters),
naming which bounded deterministic predicate family may execute and carrying only the static
parameters needed to instantiate and evaluate it, together with the static evaluation budget
Requirement 4.3 demands. It is not a predicate instance: ∆in, ∆out, the external commitments, the
encumbrances and the intent bounds of Definition 7.1 are transaction-time values that do not exist
when PM is committed, which Requirement 4.4 already implies by having the owner commit PM
before any particular trader exists.
Beta market family. Beta declares exactly one admissible family: family_id =
CONSTANT_PRODUCT_EXACT_INPUT, family_version = 1, and family_parameters =
(token_a_policy_commit, token_b_policy_commit), where both commitments are exactly 32 bytes and
token_a_policy_commit is strictly less than token_b_policy_commit under unsigned lexicographic
byte comparison. The canonical pair belongs to PM because the predicate must know which two
reserve legs it governs. The fee does not belong here: Φ is the single authoritative fee policy,
and it is a member of Vn .
Pricing rule. Let a be the exact input amount, x the input-leg reserve and y the output-leg
reserve of the parent Vn , let D = 10 000 be the fixed denominator of §3.4, and let f = fee_bps
from Φ with 0 ≤ f < D. Then
effective_num = a · (D − f),
output = floor( (y · effective_num) / (x · D + effective_num) ).
Every product is evaluated in checked integer arithmetic wide enough not to overflow, and the
single floor division above is the only rounding in the rule. An implementation must not compute a
rounded fee-adjusted input first: flooring a · (D − f)/D before applying the curve is a second
rounding stage, and two implementations that disagree about whether it happens produce different
outputs from identical inputs. The divergence is not a corner case that needs contrived values:
at a = 1, x = 1, y = 3 and any fee_bps in the legal range, the fused rule yields 1 while the
doubly-rounded variant yields 0, because flooring the fee-adjusted input first collapses a
sub-unit input to zero and takes the whole output with it. Small reserves and small inputs are
where the two rules part company most often, which is exactly the region a low-liquidity vault
operates in.
Reserve successor. The valid successor is R'_in = R_in + a and R'_out = R_out − output,
crediting the FULL input to the reserve. The fee is not withheld, not routed elsewhere, and not
represented anywhere in the successor: it remains inside the DLV reserves as liquidity-provider
yield. That is precisely why R'_in is R_in + a and not R_in + floor(a · (D − f)/D).
Admissibility. The transition is inadmissible, and no successor exists, if a = 0, if x = 0, if
y = 0, if f ≥ D, if output = 0, if output > R_out, or if any checked product overflows.
Acceptance predicate. A verifier recomputes output from the exact parent, direction, input, fee
and bounds, and requires the proposed reserve successor to equal the values above exactly. The
acceptance condition is equality with the recomputed successor. It is not an inequality over the
product.
Consequence, not predicate. Under a valid beta transition R'_in · R'_out ≥ R_in · R_out, with
strict increase possible from the retained fee and from integer truncation. This is a theorem about
the family and a useful sanity property, and it must never serve as the acceptance condition on its
own: many successors far worse for the trader also satisfy it.
Evaluation budget. evaluation_budget is a constant of the family version, not an
owner-configurable field. A per-owner budget would let two implementations agree on every byte
while disagreeing about whether evaluation exhausted its allowance, which is the same class of
divergence canonical bytes exist to prevent. The beta family performs a fixed, bounded sequence of
checked multiplications, one comparison chain and one division, with no iteration, so its budget is
a constant declared by family_version = 1.
Because family_id now names the invariant, BM carries no invariant field. The invariant is the
semantics of the predicate family itself, and a second representation of it would be another alias.
BM retains only the per-transition size ceiling and the authorized encumbrance purposes.
Beta fee policy. Φ is FeePolicyV1, a single unsigned 32-bit field fee_bps with
0 ≤ fee_bps < 10 000, interpreted as the exact rational fee_bps/10 000 under the allowance of
§3.4. A value of 10 000 or above is invalid rather than meaningful: it would make the fee at
least the whole input and leave the pricing rule with a zero or negative effective numerator.
The width is 32 bits because that is the representation already in use throughout, and widening
or re-scaling it would change every committed fee without changing any fee.
Beta release family. PR has the same descriptor shape as PM , and beta declares exactly one
admissible family: family_id = OWNER_LOCAL_FULL_CLOSE, family_version = 1, with no family
parameters. Its evaluation_budget is likewise a constant of the family version.
The family admits exactly one successor shape. A valid release consumes the current DLV parent
and drains BOTH reserve legs to zero in one transition, crediting each leg's exact remaining
amount to ordinary owner balance and retiring the vault, so that no later successor may compose
from the retired parent. There is no partial release in beta: a family that released part of a
leg would need a released amount per leg, and that amount is exactly the parameter this family
does not have.
The family carries no parameters because there is nothing left to parameterise. The amounts are
the parent's reserves, the destination is ordinary owner balance, the authority is the owner
signature over the exact successor required by Definition 5.1(a), and the timing is governed by
Requirement 6.30 rather than by the policy. A parameter here would be a value some verifier
could read differently from the parent state, which is precisely what Requirement 4.6's
decidability condition forbids.
PR is therefore decidable exactly as Requirement 4.6 demands: from the authenticated current
DLV parent, the exact owner-signed release successor, the applicable token policy, and canonical
bytes complete before the first mutating binding step. It requires no post-binding owner action,
no external counterparty or co-signature, no reference-window outcome, and no liquidation or
oracle branch.
The owner signs CCB(M) at vault creation. M commits a mechanism, not a preferred trader.
Market size bound. The beta DLV state has no separate economic “quota” variable. The phrase
market size bound means the per-transition size ceiling committed in BM together with the actual
remaining reserves in Vn. A later profile may add a distinct cumulative quota only by committing it
explicitly into the DLV state and its transition predicates.
15
SoFi: Sovereign Deterministic Finance Revision 15
5.2 Completion witness
A market completion witness contains at minimum:
1. the advancing party signature over the concrete successor CCB;
2. owner authority per Definition 5.1;
3. the parent-state binding;
4. consumed encumbrance proofs;
5. route-set membership proof;
6. external-commitment binding;
7. sparse Merkle inclusion proofs required by the state transition.
Theorem 5.3 (Authorization confinement). Producing a successor outside the owner-
authorized concrete or fulfillment family requires forging owner authority. Producing a successor
inside the fulfillment family still requires satisfying every committed bound, conservation, parent-
state binding, and the advancing party’s signature.
Theorem 5.4 (No general reserve release). A valid successor authorizes exactly the deltas
committed in that successor. It does not create a general withdrawal capability over the vault.
Interpretation. Definition 5.1(b) is authority over transitions of value that is already encumbered
inside the DLV. It is not a standing instruction against a separate LP balance. The LP committed
the executable successor family when funding the vault; the trader supplies the live side of the
bilateral exchange, while PM , BM , the token policy, and the actual DLV reserves determine whether
the concrete market successor is exercisable. A reverse transition from DLV reserves back to owner
spendable balance is separately governed by PR under Requirement 4.6.
6 DLV Bilateral Advancement and Quorum Settlement
6.1 Composed vault state
Definition 6.1 (Composed DLV state). The composed state of a DLV is the latest authenticated
owner catch-up baseline followed by every verified DLV successor that names the current composed
parent. The completion gate is successor-kind-specific:
(a) a market successor is composable only when its complete SettlementBundle is binding-final
under Definition 6.24 and the exact initiating trader successor has a verified acceptance artifact
AB under Definition 6.26;
(b) an owner release/close successor is composable when its exact release/close candidate is binding-
final for the current DLV parent and the exact successor already verifies under Requirement 4.6,
the applicable token policy, conservation, and concrete owner authority under Definition 5.1(a).
It requires no trader-acceptance witness and no owner-side post-binding acceptance artifact.
For either successor kind, Class K must verify the exact vault ID, parent generation, parent
state commitment, parent reserves digest, storage-set identity, committed threshold, applicable
encumbrance proofs, deterministic state arithmetic, conservation, and byte identity of the successor
16
SoFi: Sovereign Deterministic Finance Revision 15
and proof material selected by the binding decision. Market successors additionally require the
route/allocation membership and X checks of the SettlementBundle and the live trader signatures
required by ordinary DSM. Release/close successors additionally require owner-local PR and the
concrete owner signature over the exact release successor. For a terminal close, the verified successor
must credit the released DLV reserves to ordinary owner balance exactly once and mark the DLV
terminal/retired so no later market successor may compose from the retired parent.
This verified successor sequence is the same DLV history the LP’s bilateral relationship state
must reflect. Composition is a local deterministic derivation. It is not an authority object, a second
settlement decision, or an owner approval step.
Requirement 6.2. A market DLV successor must not be folded unless the corresponding
SettlementBundle is both binding-final and realized by a valid trader-acceptance witness. An owner
release/close successor must not be folded unless the exact owner-authorized release candidate is
binding-final and satisfies Requirement 4.6; no AB is required for that successor kind. An immutable
object copy, a discovery-index entry, a locally prepared successor, a recovery-visible binding record,
a market quorum COMMIT without trader acceptance, or an acceptance artifact without the
matching market binding decision has no effect on the reserve cursor. Once a valid terminal close
is binding-final, its exact release successor is folded and any advertisement that still presents the
pre-close DLV as active is stale and must not be accepted for routing.
Composition-depth boundary. Beta defines no synthetic checkpoint, timeout, or storage-node-
created baseline. If the LP remains absent through d realized market DLV advances after its
last authenticated owner baseline, fresh composition requires folding those d market successors
in order, verifying their trader-acceptance witnesses, and establishing any beta binding-Finality
evidence required for the underlying DLV decisions. The verification cost therefore grows with
unanchored market activity. When the LP returns and catches its bilateral relationship state up
through the realized market history, the resulting authenticated owner state is a fresh baseline from
which later composition may begin. A binding-final terminal owner close instead folds its terminal
successor directly and ends further market composition for that DLV. An LP absent indefinitely
may therefore leave an active DLV progressively more expensive to compose; this is a stated beta
liveness/performance property, not hidden constant-time behavior.
Requirement 6.3 (Catastrophic duplicate binding Finality). At one DLV parent
there must be zero or one binding-final bundle. If a verifier establishes two distinct binding-final
SettlementBundles consuming the same DLV parent, it must:
1. report STORAGE_SAFETY_VIOLATION;
2. quarantine that parent and every descendant whose validity depends upon either continuation;
3. refuse new market execution involving the affected lineage;
4. preserve both conflicting evidence objects; and
5. never select one continuation by hash order, route rank, arrival order, node order, or another
tie-break.
SoFi defines no automatic rollback because either continuation may already have been used as an
input to later sovereign state. Deployment repair after this event is an explicit operator/recovery
action outside ordinary settlement.
17
SoFi: Sovereign Deterministic Finance Revision 15
6.2 History-bound parent anchors
Definition 6.4 (Parent binding). The parent binding carried by every route allocation is
pv = H(DSM/vault-state-anchor/v2 ∥vault
_
id∥generation
∥parent_
state
_
commitment∥reserves
_digest
∥storage_
set
_
id∥q).
Requirement 6.5. A parent anchor must bind the history commitment that produced the
advertised reserves, not only the vault identifier, local generation, and reserves digest. Two distinct
histories that happen to produce identical reserve amounts must therefore produce different parent
bindings whenever their parent state commitments differ.
The parent state commitment carried here is exactly the local parent commitment hn of
Definition 4.1: hn = cn−1 for n > 0, and the domain-separated genesis value at n = 0. It is
the canonical prior DLV state, not a chain over anchor serializations and not the trader's
ordinary DSM relationship root — the trader's parent and successor are bound separately by
the SettlementBundle and by the initiating-trader fence of Requirement 6.23.
Requirement 6.6 (Clean anchor cut). The history-bound VaultStateAnchorV2 defined
here uses a new domain/schema and must not be silently accepted as the legacy anchor format or
vice versa. Beta deployment uses a schema bump and clean reprovision rather than a dual-read or
fallback path.
6.3 Stale construction
Theorem 6.7 (Stale-state rejection). If a constructor learns a realized successor has advanced a
vault from parent p to p′, any route still bound to p fails parent binding before value moves.
Requirement 6.8. A stale route is HOP_UNAVAILABLE, not a completed trade that later failed.
Class K must recompose and evaluate the already-committed alternatives in the route set. If none
remains admissible, the trade does not execute.
Boundary of this theorem. Stale-state rejection covers the sequential case. It does not by itself
prevent two constructors that both read p before either sees an advancement. The client-driven
quorum transaction below covers that concurrent case. Neither mechanism substitutes for the other.
6.4 Committed storage set and fixed quorum
Definition 6.9 (Committed storage set). A DLV commits at creation to
S= {m1,...,mn}
of distinct storage-member identities and to a fixed settlement threshold q. The set identity is
storage_
set
_
id= H(DSM/storage-set ∥Canon(S)).
Transport endpoints are resolution metadata and are not member identity.
Requirement 6.10 (Owner-committed threshold). The vault birth state must commit
either the explicit integer q or a versioned quorum rule whose output for the committed S is unique.
Class K must derive the same q from authenticated vault data. Local configuration must not
substitute a different threshold.
Requirement 6.11 (Fixed denominator). Class K evaluates q against the committed n.
Neither Class K nor Class N may lower the threshold because a member is offline, slow, unreachable,
quota-limited, or otherwise unavailable.
Requirement 6.12 (Client-side quorum). A quorum is a Class K result. Class K:
1. resolves the exact committed storage_
set
_
id to member endpoints;
18
SoFi: Sovereign Deterministic Finance Revision 15
2. contacts those members;
3. verifies distinct member identity for every response that it intends to count;
4. verifies the canonical bytes and storage-generic transaction metadata returned by each counted
member; and
5. locally evaluates whether at least q qualifying members support the same transaction fact.
A Class N member does not count other members, does not know whether the caller has reached q,
and does not announce “quorum reached.”
Requirement 6.13 (Five-member beta profile). For the five-member beta storage set,
q = 4. If one member is unavailable, all four remaining members are required. If two or more
members are unavailable, a new settlement decision cannot be established until the fixed threshold
is again reachable.
Durability rationale. With n= 5 and q= 4,
|Q1 ∩Q2|≥4 + 4−5 = 3.
If one record from a previously chosen quorum is later unavailable, at least two surviving members
of that choice still intersect every later four-member quorum. This is a durability margin; it does
not authorize nodes to vote on economic validity.
6.5 Complete SettlementBundle
Definition 6.14 (SettlementBundle). A SettlementBundle B is the complete immutable object
that Class K proposes as the one route result. It binds at minimum:
B = (version,storage_
set
_id,q,I,X,selected_route,
trader
_parent,trader_successor,
{Tv }v∈selected
route,{Pv }v∈selected
route,
_
_
bundle
_signatures,recovery_
material).
For the initiating trader, trader
_parent binds the exact ordinary DSM bilateral parent state
commitmentandgenerationfromwhichthemarkettransactionisconstructed, andtrader
successor
_
contains the exact already-signed bilateral successor CCB that represents the trader’s side of the
exchange. That trader transition remains governed by ordinary DSM parent, pending, signature,
conservation, and Tripwire rules; the storage quorum does not become authority over the trader’s
chain. For every consumed DLV v, Tv contains the exact vault identifier, parent generation, parent
state commitment, parent reserves digest, complete DLV successor CCB, exact reserve deltas, and
every witness required to verify that successor. Pv contains proof material required to verify and later
compose that DLV continuation. The bundle binds every allocation in every horizontal allocation
bundle so the ordinary trader-side transition and the selected DLV fulfillment are cryptographically
one economic exchange.
The immutable bundle identifier is
b= H(DSM/settlement-bundle ∥Canon(B)).
Requirement 6.15 (No post-decision private dependency). Before any quorum-binding
mutation begins, B must already contain every signature, DLV successor, initiating-trader bilateral
19
SoFi: Sovereign Deterministic Finance Revision 15
successor, witness, and proof object required to verify the selected route and recover the DLV-side
decision. Recovery of the DLV decision must not require a new owner signature, trader signature,
nonce, private route-construction state, or another object available only to the original constructor.
This requirement does not authorize a recovery client to write another sovereign party’s local chain;
each party’s bilateral state still advances under ordinary DSM rules.
Requirement6.16(Singlesettlementdomainforonetransaction). EveryDLVconsumed
by one atomic SettlementBundle must be admissible to one client-driven quorum transaction. In
the beta profile every consumed DLV therefore has the same storage_
set
_
id and the same fixed q.
Cross-storage-set atomic settlement is not specified by this revision.
6.6 Settlement resource keys
Definition 6.17 (Resource key). A settlement resource key is
kv = H(DSM/binding-keyset ∥vault
_
idv ∥parent_
state
_
commitmentv ).
A SettlementBundle consumes the sorted set
K(B) = {kv : v∈B}.
The resource key is opaque storage metadata. A node need not know that it represents a vault
parent.
Requirement 6.18. A route-wide binding operation must name the complete sorted K(B). A
conforming Class K must not acquire A, then B, then C as separate settlement decisions for one
atomic route.
6.7 Generic storage records and immutable bytes
Definition 6.19 (Canonical immutable object). Storage of the complete bundle uses a
deterministic content address
addr(B) = H(DSM/storage-object ∥namespace∥H(DSM/settlement-bundle ∥Canon(B))).
The address names exact bytes. Different bytes necessarily produce a different content address.
Re-putting identical bytes is idempotent.
Definition 6.20 (Opaque binding record). For storage-engine coordination only, each
member may hold a generic record
G= (schema,round,tx_id,keyset_digest,value_digest,value_addr,status).
The node may interpret only the generic storage fields needed to enforce compare-and-exchange and
monotonic-round rules. It must not decode the SettlementBundle at value
addr or attach SoFi
_
meaning to any field.
A transaction round is
round= (counter,proposer_
id)
ordered lexicographically. The counter is a persisted proposer-local monotonic integer; not a
timestamp. A recovering proposer chooses a round strictly greater than every round it is required
to supersede.
20
SoFi: Sovereign Deterministic Finance Revision 15
6.8 Client-driven quorum binding transaction
Definition 6.21 (QuorumBind). QuorumBind(B) is the Class K procedure that drives a crash-
recoverable quorum transaction over the exact S, q, and K(B) committed by B. Nodes do not call
one another and do not determine the quorum.
For each contacted member, Class K uses a storage-generic atomic conditional operation over
the complete sorted key set. At one member, the operation updates all keys in K(B) in one local
database transaction or updates none. The payload is the opaque binding record plus the immutable
value address/digest.
The procedure has the following protocol-visible terminal outcomes:
1. COMMITTED(B). At least q distinct members have accepted the same safe transaction value for
the complete DLV resource set K(B). The bundle is chosen as the binding-final candidate for
those DLV parent(s). This outcome excludes competing DLV candidates but does not itself
advance the DLV reserve cursor, the initiating trader’s bilateral chain, or the LP’s local catch-up
state.
2. ABORTED(B). A recovery round has safely decided that this proposal will not become binding-final
for the named DLV parent(s). No DLV successor from B may be folded as realized settlement
state.
3. CONFLICT_FINAL(B’) where B′ ̸= B. Recovery establishes that an overlapping resource key
already belongs to a different binding-final transaction. B cannot commit.
4. INVALID. Canonical or storage-domain checks fail before the transaction is allowed to choose a
value.
A caller may also receive non-terminal RECOVERING or lose connectivity with the outcome
INDETERMINATE. Neither is equivalent to ABORT.
Requirement 6.22 (Safe recovery). Any Class K implementation holding or retrieving the
immutable transaction bytes may recover an interrupted transaction. Recovery must:
1. read a qualifying quorum of generic binding records for every overlapping resource it must
resolve;
2. enter a strictly higher transaction round;
3. obey the safe-value rule: if the quorum evidence proves that a value was already chosen, or
that a prior accepted value must be preserved to avoid contradicting a possible chosen value,
recovery must carry that exact transaction value forward;
4. otherwise decide either the caller’s complete bundle or ABORT according to the canonical
recovery rule;
5. drive the resulting value to a qualifying quorum; and
6. never require the original constructor’s private signing context.
Timeouts may trigger another recovery attempt but must never determine which value is valid.
21
SoFi: Sovereign Deterministic Finance Revision 15
Implementation class. In distributed-systems terminology this is a scoped, client-driven quorum
consensus/atomic-commit problem over opaque storage keys. An implementation may use Paxos-
style prepare/accept rounds, an equivalent crash-recoverable quorum-register transaction, or another
protocol that satisfies the normative safety and recovery properties. This does not make DSM a
consensus system: there is no global ledger, no global log, no validator ordering, and no protocol
order between disjoint key sets.
Requirement6.23(Initiating-traderparentfence). BeforeClassKissuesthefirstmutating
binding operation for B, it must durably record a local settlement fence
FB = (trader
chain
_
_id,trader_parent_
state
_commitment,b,tx_
id).
The fence is a Class K/Class C advancement invariant over the initiating trader’s sovereign chain,
not a storage-node authority object. The fence obeys all of the following:
1. if the fence cannot be durably persisted, QuorumBind(B) must not begin;
2. while B is RECOVERING or INDETERMINATE, no different successor may be created, accepted,
or used as a later parent from trader
_parent, regardless of intent identifier, route set, nonce,
application operation, or user action;
3. ABORTED(B) or CONFLICT_FINAL releases the fence without advancing the trader chain;
4. COMMITTED(B) fixes the permitted continuation to the exact trader
_
successor already commit-
ted inside B; the quorum result alone does not consume the fence, and Class K releases/consumes
it only when that exact successor is accepted through ordinary DSM bilateral state advancement;
and
5. restart or sovereign-state recovery must restore unresolved fences before the recovered trader
chain is allowed to advance. An implementation that can restore the trader parent while
forgetting an unresolved fence does not conform.
A new intent or nonce therefore cannot escape an unresolved market settlement. The protected
resource is the trader’s bilateral chain parent, not the intent object. The fence is an operational
prevention rule for the unresolved window; Tripwire remains the underlying DSM safety rule that
forbids two valid successors from one trader parent. The quorum neither replaces Tripwire nor
grants storage members authority over the trader’s bilateral history.
6.9 DLV binding Finality, trader acceptance, realization, and evidence
Definition 6.24 (DLV binding Finality). A candidate is binding-final with respect to its
consumed DLV parent resource set when the client-driven quorum transaction has chosen that exact
candidate over the complete key set. Binding Finality is a consume-once selection fact: no different
candidate may later consume an overlapping DLV parent under conforming recovery. Its completion
consequence is successor-kind-specific. For a market SettlementBundle B, binding Finality does
not by itself advance the DLV reserve cursor and does not finalize the initiating trader’s ordinary
DSM bilateral chain; market realization still requires Definition 6.26. For an owner-local beta
release/close candidate satisfying Requirement 4.6, every completion fact and the concrete owner
authority already exist before binding, so binding Finality also satisfies that successor’s completion
gate and makes the exact release successor immediately foldable under Requirement 6.30. This does
not make storage authoritative over the release economics; Class K verifies the already-complete
owner-authorized successor locally.
22
SoFi: Sovereign Deterministic Finance Revision 15
Binding Finality is an objective historical property. Later storage-member unavailability does
not revoke it.
Requirement 6.25 (Evidence of DLV binding Finality; online beta profile). Candidate
validity and DLV binding Finality are different questions:
1. for a market SettlementBundle B, one immutable copy is sufficient to verify its signatures,
proofs, arithmetic, route commitment, trader bilateral parent/successor binding, and DLV
parent/successor bindings; for an owner release/close candidate, the exact canonical candidate
bytes are sufficient to verify owner-local PR, token policy, conservation, and concrete owner
authority over the exact release successor;
2. neither candidate’s canonical bytes alone prove that the quorum transaction chose that candidate
for the named DLV parent resource(s); in the beta profile, independently establishing binding
Finality may require live authenticated binding evidence from the DLV’s committed storage set.
If the canonical candidate is valid but current storage availability is insufficient to establish the
historical quorum choice, the verifier returns DLV_BINDING_EVIDENCE_UNAVAILABLE. It must not
call the candidate unchosen merely because members are unavailable. Routing is fail-closed on
this condition: if Class K cannot obtain the binding evidence required to establish the current
composed state of a discovered DLV candidate—including evidence needed to determine whether a
binding-final terminal owner close retired the advertised parent—that candidate must be excluded
from R for the current route construction. Class K must not assume that an evidence-unavailable
candidate is active, unbound, unchanged, or retired. Exclusion is an availability decision, not a
contrary Finality claim.
A future profile may define a portable cryptographic quorum certificate or equivalent witness
to reduce live storage dependencies or to admit market-derived state into an offline/bearer path.
Such a certificate is not required for beta correctness because SoFi market settlement is online by
construction.
Definition 6.26 (Trader-acceptance witness and realized DLV settlement). Let AB be a
canonical, immutable acceptance artifact proving that the initiating trader’s exact trader
successor
_
from trader
_parent was accepted under ordinary DSM bilateral rules. Let C+
T denote the ordinary
DSM canonical accepted-successor commitment produced by that advancement. C+
T must commit,
under the ordinary DSM state format, the trader relationship/chain identity, the exact accepted
trader
_parent→trader
_
successor transition, and the post-advance authenticated state root R+
T.
Let σ+
T be the ordinary DSM successor-state authentication over C+
T itself:
Verify(KT ,C+
T ,σ+
T ) = 1.
SoFi does not define a second acceptance payload around C+
T and does not re-sign it. At minimum
AB binds:
1. the exact ordinary DSM accepted-successor commitment C+
T ;
2. the ordinary DSM successor-state authentication σ+
T over C+
T ;
3. the exact route commitment X and bundle identifier b;
4. a deterministic settlement/acceptance leaf LB , or equivalent state commitment, under the R+
T
committed inside C+
T ; and
5. the inclusion proof πB proving LB under that R+
T.
23
SoFi: Sovereign Deterministic Finance Revision 15
A conforming verifier parses and verifies C+
T under ordinary DSM rules, requires that it commits
the exact trader relationship, trader
_parent, and trader
_
successor already carried by B, verifies
σ+
T directly over C+
T , extracts the committed R+
T , verifies πB under that authenticated root, and
verifies that LB binds the exact (trader
_parent,trader_successor,b,X) committed by B.
The signature or authorization already carried by the preconstructed trader
successor inside
_
B is not sufficient to authenticate R+
T , because R+
T exists only as part of the accepted ordinary
DSM successor state. A Merkle proof authenticates membership relative to a root; it does not
authenticate the provenance of that root. AB introduces no additional SoFi authorization and
no additional SoFi signing round. It packages the ordinary DSM accepted-successor commitment
and its ordinary successor-state authentication from the same hash-adjacent state advancement
whose acceptance it proves. The ordering asserted here is causal only: parent state →accepted
successor state →derived acceptance evidence. No timestamp, duration, wall-clock ordering, or
global sequence is introduced. A constructor that merely possesses B can construct an arbitrary
Merkle tree and inclusion path, but cannot satisfy Definition 6.26 without the valid ordinary DSM
authentication σ+
T over the exact C+
T that commits the post-advance root.
A conforming verifier must be able to verify AB without write authority over the trader’s chain.
A SettlementBundle is a realized DLV settlement only when both (a) B is binding-final under
Definition 6.24 and (b) AB verifies and matches the exact trader parent/successor committed inside
B.
Requirement 6.27 (Completion gate and deterministic DLV composition). Class K
must not expose the market output as spendable, publish a successful settlement receipt, display
the route as successful, or fold any DLV successor from B until B is a realized DLV settlement
under Definition 6.26. When realization is established, Class K folds exactly the DLV successor(s)
already committed in B; it must not rebuild, reprice, reroute, or alter the selected economics.
A market DLV parent is bound-but-unrealized when one market SettlementBundle has reached
binding Finality for that exact parent but the initiating trader’s ordinary DSM advancement has
not yet produced the valid AB required by Definition 6.26. In that state:
1. the DLV reserve amounts and generation remain at the current composed parent;
2. no proposed trader output is spendable;
3. no different bundle may consume the bound DLV parent;
4. a later quote or settlement attempt must treat that parent as blocked rather than price against
a fictitious successor;
5. owner release/close over the same parent remains blocked; and
6. Class K reports the market transaction as unresolved and continues/restarts recovery of the
exact trader successor when possible.
A malicious or non-conforming trader that wins DLV binding and then refuses to accept its own
exact successor can therefore cause an availability lock, but it cannot move the vault reserve cursor,
fabricate input reserves, remove output reserves, or induce a price change without a valid trader-
acceptance witness. This bound-but-unrealized state is specific to the market seam. Requirement
6.30 defines owner release/close as a one-phase DLV successor after binding because beta PR is
owner-local and the exact owner-authorized successor is complete before binding.
For an active DLV, the LP’s owner-side bilateral relationship state catches up later, when the LP
is present, by folding realized market DLV history. Catch-up must never fold a bound-but-unrealized
24
SoFi: Sovereign Deterministic Finance Revision 15
market candidate. A terminal owner close is already the final owner/DLV state update and has no
separate catch-up leg.
Requirement 6.28 (Constructor crash and recovery boundary). If the original construc-
tor disappears:
1. before any binding mutation, the proposal is ordinary uncommitted data and may be abandoned;
2. after binding mutation but before a terminal DLV binding outcome, the DLV decision is
recoverable; the initiating trader parent remains fenced and must not advance through any
different successor;
3. after COMMITTED(B) but before a valid AB exists, any conforming recovery client with the
immutable bundle and sufficient storage access may establish the binding-final DLV decision,
but must not fold the DLV successor or fabricate trader acceptance;
4. onlythetrader’sordinaryDSMstate/recoverypathcanaccepttheexactboundtrader
_
successor,
produce C+
T and its DSM successor-state authentication σ+
T , and thereby produce AB ; and
5. after AB verifies, any conforming verifier may establish realization and compose the exact market
DLV successors, while an active DLV’s LP relationship state still catches up only through its
own DSM state/recovery path; a terminally closed DLV has no separate catch-up step.
6.10 Loser behavior and reroute
Requirement 6.29. A route may fall through to the next admissible route already bound
by the same intent only after the prior route has a terminal non-commit outcome: ABORTED,
CONFLICT_FINAL, stale parent before binding mutation, or another pre-binding failure. A route in
RECOVERING or INDETERMINATE is not a loser yet. Requirement 6.23 is broader than reroute: while
its fence exists, the initiating trader parent may not advance through a different successor under
any intent.
6.11 Owner close
Owner close consumes the same DLV parent resource as market advancement.
Requirement 6.30 (Owner release/close and market-first contention). Owner re-
lease/close is a reverse-encumbrance DLV transition governed by the owner-local beta policy PR
under Requirement 4.6 and is a contender for the same exact DLV parent resource as market
advancement. It must use the same client-driven quorum-binding machinery. Whichever valid candi-
date reaches binding Finality first for that parent excludes every competing market or release/close
candidate from consuming the same parent.
If a market candidate is already indeterminate or binding-final for the current parent, owner
close is not an escape hatch: Class K must recover that prior market binding outcome and must not
bypass it. A binding-final but unrealized market candidate continues to block release/close exactly
as stated in Requirement 6.27.
If the owner’s valid release/close candidate reaches binding Finality first, the result is different.
Because beta PR is decidable entirely from the current owner/DLV state and the canonical candidate
bytes, and because the exact concrete owner signature over the exact release successor is already
present before binding begins, there is no sovereign second leg left to accept. Binding Finality
therefore realizes that release/close successor at the DLV. Any conforming verifier with the canonical
candidate and sufficient binding evidence can verify and fold the exact release transition without
25
SoFi: Sovereign Deterministic Finance Revision 15
obtaining new owner material. The DLV reserve debit and the credit to ordinary owner balance
are one conservation-preserving state update; for a terminal close, all released reserves are credited
exactly once and the DLV becomes terminal/retired.
This asymmetry is intentional. A market trade has a second sovereign trader chain whose
acceptance the DLV cannot infer from DLV binding alone, so market realization requires AB . Owner
release/close has no such remote leg in the beta profile: the DLV is inside the owner’s state, PR
is owner-local, and the exact owner-authorized release successor is the state transition selected by
binding. There is therefore no owner acceptance artifact, no owner-side analogue of the Requirement
6.23 trader-parent fence, and no owner-bound-but-unrealized state. A future release policy that
depends on an external party or externally accepted condition would not satisfy Requirement 4.6
and would require an explicitly specified completion mechanism before entering a future profile.
Permanent unresolution remains possible on the market-first path or while a quorum-binding
transaction itself has not reached a recoverable terminal decision. Beta defines no timeout, automatic
eviction, direct-owner withdrawal bypass, or override that discards a market candidate whose DLV
parent may already be bound.
Requirement 6.31 (Owner catch-up baseline). When the LP returns to an active DLV and
catches its bilateral relationship state against the DLV up through all then-known realized market
successors, the resulting authenticated owner state must commit a fresh DLV baseline/anchor. Later
market composition may begin from that baseline. The new baseline records the current DLV reserve
state; it does not re-transfer value from or to the owner’s ordinary balance. Catch-up collapses
already-verified market history when the owner participates, but it does not impose a maximum
time or maximum number of market advances for which the owner may remain absent. A terminal
owner close under Requirement 6.30 is itself the final owner/DLV state update and does not require
a separate catch-up step.
7 Smart Commitments and Atomic Composition
Definition 7.1 (Smart Commitment). A bounded deterministic predicate over committed
inputs:
C= {∆in,∆out,invariants,external commitments,encumbrances,intent bounds,budget}.
7.1 Token conservation
For each token t touched by one atomic execution,
∑︂
i
R(n+1)
i,t + ∑︂ outt = ∑︂
R(n)
i,t + ∑︂ int−feet.
i
Checked unsigned arithmetic is used throughout.
7.2 External commitments
ExtCommit(X) = H(DSM/ext ∥Canon(X)).
X binds the entire user intent, route set, allocation bundles, every distinct vault parent binding,
and every required encumbrance commitment. A participating vault must reject a hop not bound
by the same X.
Requirement 7.2. Multi-vault execution is all-or-none. No Class C verifier may accept a subset
as successful execution of the original route, and no Class K implementation may invoke separate
26
SoFi: Sovereign Deterministic Finance Revision 15
settlement commits for individual vaults of one atomic route. The selected route is finalized only
through the one SettlementBundle that binds all of its vault transitions.
8 Deterministic Encumbrance Accounting
For a claim ej against vault parent p:
ej= H(DSM/enc-claim ∥vault
_
id ∥p∥claim
_seq ∥amount ∥token ∥purpose).
The encumbrance commitment is
E= H(DSM/enc ∥vault
_
id ∥Canon({ej })).
Naming. E is the encumbrance SET, as Definition 4.1 lists it among the members of Vn , and
Requirement 8.2 below iterates it. The digest above is a distinct object and is written ECv
for vault v:
ECv = H(DSM/enc ∥vault
_
id ∥Canon(E)).
The set and its commitment previously shared the symbol E, which made "E" mean a set in
Definition 4.1 and Requirement 8.2 and a digest here. Only the set is a member of Vn ; ECv is
derived from it.
Type of e. The e carried by an allocation in Definition 9.1 is a single encumbrance CLAIM —
one ej of this section — namely the claim that allocation consumes. It is not ECv . The two
are different facts: e names what one allocation spends, while ECv commits the whole
encumbrance state of a vault. An allocation that had to consume several claims would carry a
set rather than a single e, which is outside the beta shape.
Requirement 8.1 (Uniqueness). A claim is consumed at most once and its exact removal
must be visible in the successor state.
Requirement 8.2 (Solvency). For every token,
∑︂
e∈Et
amount(e) ≤Rt.
Requirement 8.3 (Priority). Priority applies only when one transition must choose among
multiple internally valid claims, such as partial liquidation. It is not the settlement-commit winner
rule.
9 Trade Intent, Multi-Vault Routes, and SDK-Resident Routing
9.1 Trade intent
TradeIntent = {tokenin,amountin,tokenout,minout,maxf ee,maxhops,maxf anout,k,nonce}.
I= H(DSM/intent ∥Canon(TradeIntent)).
No expiry, timestamp, or duration is permitted.
Requirement 9.1 (Independent complexity bounds). k bounds the number of alternative
routes retained in R. maxf anout bounds the number of independent DLVs that may participate
inside one same-pair allocation leg. These are independent bounds. An implementation must not
use k as the fanout limit, and increasing same-pair fanout must not implicitly increase the number
of route alternatives. Both bounds must be finite and committed before execution.
9.2 Allocation bundles
A single logical pair conversion may draw from more than one independent DLV.
Definition 9.1 (Allocation).
a= (vault
_id,parent_binding,∆in,∆out,e,Φ).
Definition 9.2 (Allocation bundle). For one ordered token pair (A,B),
AB = {a1,...,af }, 1 ≤f ≤maxf anout,
where every ai converts the same input token to the same output token and names a distinct DLV.
The bundle is canonicalized by vault identifier and commits the exact integer input and output
assigned to every DLV.
27
SoFi: Sovereign Deterministic Finance Revision 15
Bundle conservation requires
∑︂
i
∆(i)
in = ∆bundle
in , ∑︂
∆(i)
out = ∆bundle
out.
i
Requirement 9.2. Class K must determine allocation with deterministic checked integer AMM
arithmetic. Given the same verified candidate DLVs, the same composed parent states, and the same
intent, conforming implementations must produce the same canonical allocation bundle. Rounding
sites and allocation tie-breaks must be fixed by the CCB specification, not discovery order.
Meaning. This is horizontal liquidity composition, not pooled custody. Independent DLVs remain
independent even when one trade atomically consumes several of them.
9.3 Routes and route sets
A route is a sequence of logical legs, each leg being either a one-vault allocation or a same-pair
allocation bundle:
ri = ⟨Ai,1,Ai,2,...,Ai,h⟩, h≤maxhops.
The route set is
R= {r1,...,rk},
canonicalized by route CCB ascending.
The route commitment is
X= H(DSM/route-set ∥CCB(Q)),
where Q is the canonical RouteCommitmentBody carrying the trade intent I, the route set R,
the per-vault encumbrance commitments {ECv }v∈R , and nonceX . X is always a 32-byte digest;
there is no Canon(X), because a digest is already a primitive, and §7.2's external commitment
is ExtCommit(X) = H(DSM/ext ∥X) over that digest.
Why {ECv } is carried and is not an alias. Every allocation already names its parent binding
pv , and pv commits the vault identifier, the generation, the PARENT state commitment hn , the
reserves digest, the storage set and q. It does not commit the CURRENT generation's
encumbrance set, which lives in Vn . So {ECv } binds a fact no other operand of X binds, and
it is distinct from the per-allocation e of Definition 9.1, which names a single consumed
claim. A plain set suffices rather than a keyed map: vault
_
id is inside each ECv preimage, so
two vaults cannot collide, and a verifier recomputes ECv for each vault named in R and tests
membership.
Requirement 9.3. Route canonicalization and allocation canonicalization must not depend
on node response order, request arrival order, local map iteration, wall-clock information, or the
identity of the node that served an object.
Requirement 9.4 (Settlement-domain admissibility). In the beta profile, every DLV
consumed by one selected route must bind the same storage_
set
_
id and the same fixed q. A route
that does not satisfy this property must be excluded before it enters R. Cross-storage-set atomic
settlement is not specified by this revision.
9.4 Select, verify, build, bind
For one selected r∈R, Class K proceeds in this exact order:
1. compose every DLV named anywhere in r;
2. reject r if any history-bound parent binding is stale;
3. verify every proof, owner-authority form, signature, encumbrance, and predicate input;
4. deterministically re-simulate every allocation and leg;
5. enforce route-wide conservation, minout, and maxf ee;
6. construct every exact signed successor and every proof required for recovery;
7. construct one complete canonical SettlementBundle for the entire selected route;
8. store or confirm the immutable exact bytes of B under its canonical content address;
28
SoFi: Sovereign Deterministic Finance Revision 15
9. invoke exactly one client-driven QuorumBind(B) transaction over the complete K(B);
10. if the terminal outcome is COMMITTED(B), establish DLV binding Finality for the exact bundle
and complete the initiating trader’s exact bound successor through ordinary DSM bilateral
rules;
11. if the terminal outcome is ABORTED or CONFLICT_FINAL, materialize nothing and select the next
admissible route in R; and
12. if the outcome is RECOVERING or INDETERMINATE, keep the initiating trader parent fenced and
recover that transaction to a terminal outcome before permitting any different successor from
that parent.
Requirement 9.5. Steps 1–8 must complete for the entire route before the first mutating
binding step begins. A per-leg “verify then bind” loop is non-conforming.
9.5 Deterministic reroute
Requirement 9.6. Pre-binding stale state, exhausted reserves, failed proof, or another hop-
level precheck may cause immediate selection of the next admissible route already in R. After a
binding mutation has begun, reroute is permitted only after a terminal non-commit outcome under
Requirement 6.23. Class K does not renegotiate I and does not search outside R during execution.
A route outside R fails membership. A route inside R that no longer satisfies minout or maxf ee
is skipped because it violates the user’s already-committed bounds.
9.6 Partial execution is forbidden
Requirement 9.7. A route executes fully or not at all. Horizontal allocations, multi-hop legs, and
every market DLV successor of the selected route are one SettlementBundle and one route-wide DLV
quorum transaction. No market DLV successor is folded from that trade bundle unless it is both
binding-final and realized under Requirements 6.24–6.27, and the trader output is not spendable
before that market realization gate. This requirement governs routed market execution; owner-local
release/close successors follow the distinct one-phase fold rule in Definition 6.1(b), Requirement 6.2,
and Requirement 6.30.
Requirement 9.8. An ABORTED route requires no financial refund because no successor
from that route was materialized. Intermediate storage transaction records are not value movement
and are resolved by storage recovery, not by a financial compensation transaction.
A transaction that remains RECOVERING or INDETERMINATE is neither success nor failure. Class
K must expose an explicit user-visible unresolved state such as SETTLEMENT_UNRESOLVED. While
unresolved, no proposed output is spendable, the initiating trader parent remains fenced under
Requirement 6.23, and the SDK continues or resumes recovery when a qualifying quorum is reachable.
Beta defines no timeout-based escape that converts this state into ABORT or authorizes a different
successor from the fenced parent.
10 Trade Digests: Unordered Evidence
For each verified execution, a trade digest commits the pair, executed amounts, participating vault
identifiers, parent bindings, fees, and X:
d= H(DSM/digest ∥Canon(TradeDigest)).
29
SoFi: Sovereign Deterministic Finance Revision 15
Requirement 10.1. A TradeDigest must not contain a global height, predecessor digest, shared
sequence position, or “latest” claim. The digest collection for a pair is a set.
10.1 Reference windows
A reference window is a finite canonical set of admissible digests:
W= H(DSM/ref-window ∥pair_
id∥Canon({di})).
For an odd admissible member count w≥m,
Π(W) = median(p1,...,pw).
If the window is undersized or any member fails the required filter, Π(W) is undefined and any
consuming predicate fails closed.
10.2 Bilateral agreement
A bilateral reference-consuming transition commits W and Π(W) in its successor. The counterparty
independently verifies the named window and signs or refuses. No global convergence rule is required.
11 Admissibility Filters and Unilateral References
Adigestisadmissibleforaunilateralreferenceonlyifeverycommittedfilterholds. Adeploymentmay
use counterparty distinctness, size floor, reserve-ratio bound, positive-fee reality, and capital/depth
constraints, provided every filter is deterministic and committed in the unilateral branch rule.
Requirement 11.1. A unilateral branch commits the filter rule before execution. The advancing
party supplies the window and proofs; Class C recomputes the rule from those inputs.
Security scope. Reference-manipulation analysis applies only where a party is absent and cannot
co-sign the concrete window. Ordinary spot market routing does not require an external oracle and
does not acquire validity from a reference feed.
12 Perpetual Instruments
Perpetual instruments are DLV predicate families layered on the same settlement machinery. They
introduce no protocol clock or epoch.
12.1 Activity-denominated funding
Funding may be expressed as a deterministic function of co-signed changes in admissible trade
evidence rather than elapsed time. Let D(W) denote the digest-member set of window W. The
activity delta is
δW = |D(Wn+1) \D(Wn)|.
A per-transition clamp prevents unbounded work or one-shot accumulation.
30
SoFi: Sovereign Deterministic Finance Revision 15
12.2 Liquidation
Liquidation is a bounded fulfillment branch committed by the position holder at open. A liquidator
supplies the required reference evidence and proves the branch predicate. The holder need not be
online at liquidation.
Liquidation of any market DLV reserve leg still obeys the same parent-state, encumbrance,
conservation, and DLV quorum-binding rules when the LP is absent and a precommitted DLV
fulfillment is being exercised.
13 Clockless Liveness
SoFi uses state-local iteration budgets where a branch requires timeout-like behavior:
βn+1 = βn−1
only on accepted transitions in the relevant local chain.
Requirement 13.1. Failed verification, node retries, unavailable routes, and failed settlement
acquisition must not consume a protocol iteration budget.
Market liveness. Ordinary spot validity does not depend on a timer. A stale parent discovered
before binding mutation may cause immediate reroute. Once a client-driven quorum transaction has
mutated storage state, the initiating trader parent is fenced until the transaction reaches a terminal
COMMIT, ABORT, or CONFLICT result. Recovery may use operational retry timers or backoff,
but elapsed time never changes a protocol decision. Under permanent asynchrony or permanent loss
of the fixed quorum, termination is not guaranteed; the interface remains SETTLEMENT_UNRESOLVED
and safety remains fail-closed.
14 Receipts
Definition 14.1 (Trader acceptance artifact). For each completed route, Class K publishes the
canonical immutable bytes of the trader-acceptance artifact AB required by Definition 6.26. Its
content digest is
aB = H(DSM/trader-settlement-acceptance/v2 ∥Canon(AB )).
The artifact is not a statement by storage and it is not a second trader authorization. It carries the
ordinary DSM accepted-successor commitment C+
T , the ordinary DSM successor-state authentication
σ+
T over that exact commitment, and the settlement inclusion evidence under the post-advance
root R+
T committed inside C+
T. C+
T must itself commit the exact accepted trader
_parent →
trader
_
successor transition. The preconstructed successor authorization already present in B
does not authenticate R+
T and cannot substitute for σ+
T. AB therefore adds no market-specific
authorization payload or signing round; it packages the ordinary DSM authenticated successor-state
evidence and binds it to the exact (b,X) market execution.
Definition 14.2 (Settlement receipt). A successful SoFi receipt is a compact content-
addressed projection of one realized SettlementBundle:
Receipt= H(DSM/receipt ∥b∥X ∥aB ∥Canon({successor
_
hashv ,witness_
hashv }v∈B )).
31
SoFi: Sovereign Deterministic Finance Revision 15
The publication set for a successful receipt must include the immutable bytes of B, the immutable
bytes of AB , and the DLV successor/witness objects needed by the verifier. A digest without
retrievable acceptance bytes is insufficient evidence of bilateral completion.
A receipt is evidence and an index object. It does not create DLV binding Finality, trader
acceptance, or realization. A verifier that needs the full settlement follows the receipt to b and aB ,
verifies the bundle, establishes the DLV binding decision, verifies AB against the exact bundled
trader parent/successor, and only then treats the DLV successor as realized.
Requirement 14.3. A receipt must not contain a timestamp, global sequence position, or
node-order claim. It must bind the exact SettlementBundle identifier, route commitment, trader-
acceptance artifact digest, and DLV successor/witness commitments.
Requirement14.4. AsuccessfulreceiptmaybepublishedonlyaftertheexactSettlementBundle
is binding-final and the exact initiating trader successor has produced a valid AB . Publishing
a receipt for an unchosen DLV candidate, a bound-but-unrealized bundle, a mismatched trader
successor, an unauthenticated post-advance root, or an acceptance artifact whose σ+
T or inclusion
proof does not verify is non-conforming.
Requirement 14.5 (Third-party verifier form). From the successful receipt publication
set, a third party with no write authority over the LP, trader, or storage members must be able to
establish all of the following independently: (a) the exact bundle economics and signatures, (b) the
DLV binding-final choice for the consumed parents, (c) acceptance of the exact initiating trader
successor by verifying that C+
T commits the exact bundled trader
_parent →trader
successor
_
transition and post-advance root R+
T , verifying σ+
T directly over C+
T , and verifying the settlement
inclusion proof under that authenticated root, and (d) equality between the trader exchange proved
by AB and the DLV reserve deltas committed by B. If any of these facts cannot be established, the
verifier must not report a completed trade.
15 Storage Node Specification
Storage nodes are non-authoritative byte persistence, byte retrieval, and generic storage-engine
state. They do not validate market economics, construct routes, calculate a quorum, or choose a
financial winner. Every SoFi-specific decision is made and verified in Class K and Class C.
15.1 Three separate storage concepts
The storage model has three distinct namespaces.
Canonical immutable object store. A canonical object is stored under a deterministic content
address derived from its exact bytes. The same bytes may be replayed idempotently. Different bytes
necessarily obtain a different content address. Canonical objects are the only storage objects whose
bytes may be committed by hashes and signatures.
Discovery index. A logical path is an index from a client-defined name to one or more content
addresses. A path such as .../latest may move as newer immutable objects are published. The
path entry is not another canonical copy of the payload and must not be used as a state commitment,
signature preimage, parent binding, settlement key, or Finality fact.
Generic binding state. The storage engine may maintain opaque conditional-binding records
used by the client-driven quorum transaction. Those records contain generic transaction metadata
32
SoFi: Sovereign Deterministic Finance Revision 15
and content digests/addresses. They are not SettlementBundles, are not Final successors, and are
not exposed through ordinary market discovery as if they were committed trade state.
Requirement 15.1 (No duplicate mutable payload alias). The implementation must
physically separate the immutable object store from logical path indexing. A mutable path index
must contain content addresses or canonical index metadata, not a second mutable payload row
whose key can overwrite an authoritative-looking object.
15.2 Hard constraints
A Class N member must not:
1. compute AMM prices, route outputs, slippage, fees, or allocation decisions;
2. evaluate user intent bounds, owner fulfillment predicates, or vault economic validity;
3. parse a SettlementBundle in order to decide whether storage should accept it;
4. determine the threshold q or count responses from other members;
5. select a route, candidate, successor, or winner using hash order, arrival order, fee, or any
economic property;
6. sign a DSM state transition or SettlementBundle with financial authority;
7. treat a mutable discovery path as canonical object identity;
8. return fabricated bytes under a content address; or
9. report a successful complete query while intentionally omitting matching canonical data it
claims to serve.
A Class N member may:
1. compute and verify deterministic storage addresses;
2. enforce immutable content-addressed storage;
3. maintain discovery indexes over content addresses;
4. perform a generic local compare-and-exchange over opaque keys;
5. maintain monotonic transaction-round metadata;
6. update a sorted opaque key set atomically inside one local database transaction;
7. return the exact current generic binding bytes to a recovery query; and
8. return its authenticated member identity so Class K can count distinct members.
These are storage semantics, not SoFi economic semantics.
33
SoFi: Sovereign Deterministic Finance Revision 15
15.3 Canonical immutable objects
For an immutable payload P in namespace N,
addr(P) = H(DSM/storage-object ∥N ∥H(N ∥P)).
Requirement 15.2. PutImmutable(P) must be idempotent for identical bytes. It must not
overwrite a different payload at the same canonical address. A hash/address mismatch is a storage
error.
Requirement 15.3. Every Class K consumer must re-hash returned bytes and compare the
result with the requested canonical address before decoding or verifying higher-level protocol content.
15.4 Discovery indexes
A discovery index maps a logical path to content addresses:
path−→{addr1,...,addrj }.
Requirement 15.4. Index mutation may add, remove, or advance pointers according to the
index’s declared discovery semantics, but it must not mutate the immutable objects themselves.
Requirement 15.5. A protocol validity rule must never say “the bytes currently under logical
path p are authoritative.” It must say “resolve p to one or more content addresses, fetch the
immutable bytes, and verify them.”
15.5 Generic conditional-binding interface
The node-side binding interface is application-blind. A logical form is:
service CanonicalStorage {
rpc PutImmutable(PutImmutableRequest) returns (PutImmutableResponse);
rpc GetImmutable(GetImmutableRequest) returns (GetImmutableResponse);
rpc IndexAdd(IndexAddRequest) returns (IndexAddResponse);
rpc IndexResolve(IndexResolveRequest) returns (IndexResolveResponse);
rpc ReadBinding(ReadBindingRequest) returns (ReadBindingResponse);
rpc CompareExchangeMany(CompareExchangeManyRequest)
returns (CompareExchangeManyResponse);
}
message CompareExchangeManyRequest {
repeated bytes keys = 1; bytes expected_digest = 2; bytes replacement = 3; // strictly sorted opaque resource keys
// digest of the exact prior generic record set
// opaque generic transaction record bytes
}
message CompareExchangeManyResponse {
enum Outcome {
APPLIED = 0;
EXPECTATION_MISMATCH = 1;
UNAVAILABLE = 2;
INVALID_STORAGE_ENCODING = 3;
}
34
SoFi: Sovereign Deterministic Finance Revision 15
Outcome outcome = 1;
bytes resulting_digest = 2;
bytes member_id = 3;
}
Requirement 15.6. CompareExchangeMany is atomic only within one member: all named local
keys change to the replacement record or none do. It does not know q, does not contact peers, and
does not decide whether the caller has committed a SoFi trade.
Requirement 15.7. The replacement record is canonical storage metadata. The node may
inspect only fields necessary to enforce the generic storage protocol, such as schema version, round
ordering, exact expected digest, and key-set equality. The value payload addressed by the record
remains opaque.
15.6 Client-driven quorum transaction
Class K, not Class N, executes Definition 6.21.
Requirement 15.8. Class K must count only distinct authenticated members of the exact
owner-committed S. A successful response from a member outside S, a duplicate identity, or a
response whose bytes do not verify is not countable.
Requirement 15.9. A pending or accepted generic binding record may remain durable after
a constructor crash. This is required for crash recovery and is not Finality. Ordinary market
composition must ignore it.
Requirement 15.10. Recovery queries must be able to retrieve the exact generic binding
records and the immutable transaction/value address required to continue a prior transaction. A
storage member must not require the original constructor to be online.
Requirement 15.11. Safety never depends on a timeout. A member may use local timeouts
to close sockets, retry I/O, or trigger operational recovery work, but elapsed time must not
authorize replacing a value, lowering a round, lowering q, or treating an indeterminate transaction
as ABORTED.
Distributed-systems classification. The quorum transaction is a scoped replicated decision
over the specific opaque resources named by one route. It is consensus/atomic-commit in the narrow
distributed-systems sense, driven entirely by clients. It is not a DSM global-consensus layer: disjoint
DLV resource sets need not be ordered, there is no global log, and storage members do not validate
economic state.
Liveness boundary. Under unbounded asynchrony or permanent loss of the fixed quorum,
deterministic termination cannot be guaranteed. Conformance therefore claims unconditional safety
and recovery liveness only when a qualifying quorum eventually communicates and the recovery
procedure eventually obtains an interval of proposer quiescence sufficient to finish a safe round.
Operational retry timing affects liveness only.
Overlapping key-set contention. the same key set. For example,
The hard multi-key case is not only two transactions over
K(T1) = {A,B}, K(T2) = {B,C}.
Neither transaction need be chosen when their recovery drivers first collide. Atomic member-local
updates and the safe-value rule preserve safety, but independently increasing recovery rounds can
35
SoFi: Sovereign Deterministic Finance Revision 15
livelock. The beta SDK therefore must run at most one recovery worker per unresolved transaction
on one device and should use randomized operational backoff after a higher conflicting round is
observed. Backoff values are not protocol objects, are not signed, are not shared ordering, and
must not be used as a financial priority or winner rule. Liveness still requires that, eventually,
one recovery attempt across the connected overlap component proceeds long enough to complete
without perpetual higher-round interference.
15.7 Query completeness and non-selective serving
Requirement 15.12. A synchronized member answering an immutable-object query must return
the exact requested bytes or an explicit availability/not-found result.
Requirement 15.13. A query returning a set must be exhaustive for the member’s synchronized
canonical/index state. Deterministic pagination is permitted, but a client following every returned
cursor must obtain the complete matching set represented by that member.
Requirement 15.14. A member must not expose “preferred successor”, “winning route”,
“latest trade”, or another SoFi selector. Settlement Finality is established by Class K from quorum
binding evidence; it is not a node-selected field.
15.8 Object and index classes
Canonical immutable object classes include:
1. VaultAdvertisement;
2. VaultStateAnchorV2;
3. ExternalCommitment;
4. RouteSet;
5. AllocationBundle;
6. SettlementBundle;
7. Successor;
8. TraderSettlementAcceptanceV2;
9. Receipt;
10. TradeDigest;
11. ReferenceWindow;
12. ProofBundle.
Permitted discovery indexes include:
1. pair identity →set of vault-advertisement addresses;
2. vault ID →owner-advertised address history or current discovery pointer;
3. receipt lookup key →set of receipt addresses;
4. pair ID →unordered set of TradeDigest addresses;
36
SoFi: Sovereign Deterministic Finance Revision 15
5. logical path →content address or bounded set of content addresses.
No discovery index is an authority object.
15.9 Ordinary publication and frozen exact bytes
Ordinary immutable-object publication means storing exact canonical bytes and recording their
content address. It does not establish DLV binding Finality, trader acceptance, or settlement
realization.
A conforming SDK may freeze exact publication bytes in its local durable database before fan-out
and replay those identical bytes until the desired delivery quorum is observed. That publication
quorum is a client-side delivery fact, not a settlement decision. The same exact-byte pattern may
be reused to ensure a SettlementBundle and its supporting objects remain recoverable, but DLV
binding Finality still comes from the binding transaction over K(B) and realization still requires
the trader-acceptance artifact.
15.10 Resource accounting
Storage subscriptions, quota accounting, and rate limits are node-local commercial policy. They
may make a member unavailable, but they cannot change S, q, a parent binding, a transaction
round, or the economic validity of a SettlementBundle.
16 SDK Conformance
16.1 Route-set construction
function findRouteSet(intent):
1. query discovery indexes for candidate DLV addresses
2. fetch canonical immutable bytes by content address
3. verify every candidate locally:
content address
owner signature
history-bound parent anchor
reserve proof
state proof
predicate identity
encumbrance binding
storage_set_id and q
4. compose every surviving candidate using the successor-kind completion gates;
if required DLV binding evidence is unavailable, exclude that candidate from R
5. build the liquidity graph only from candidates whose current composed state is
established
6. allow deterministic same-pair AllocationBundles across independent DLVs
7. enumerate routes with hops <= intent.max_hops
8. reject routes whose consumed DLVs do not share one beta settlement domain
9. keep bounded best alternatives inside min_out and max_fee
10. canonicalize allocations by vault_id and routes by route CCB
11. bind I, R, parent bindings, and encumbrance commitments into X
12. return (R, X, proof_skeletons)
37
SoFi: Sovereign Deterministic Finance Revision 15
16.2 Verification, quorum binding, and materialization
function verifyBindAndMaterialize(route, X, intent):
1. compose ALL DLVs in the selected route
2. verify ALL history-bound state/proof/anchor bindings
3. verify ALL owner-authority forms and concrete successor signatures
4. verify ALL encumbrance availability, solvency, and exact consumption
5. verify Member(route, R) and ExtCommit(X)
6. deterministically re-simulate EVERY allocation and hop
7. verify route-wide conservation
8. enforce total_out >= intent.min_out and total_fee <= intent.max_fee
9. construct EVERY exact signed successor and recovery proof
10. construct ONE complete canonical SettlementBundle B for the route
11. assert no private signing/construction material is needed after B
12. PutImmutable(B); verify returned content address
13. start ONE QuorumBind(B) transaction over the complete K(B)
14. if COMMITTED(B):
establish DLV binding Finality for the exact B
accept exact B.trader_successor from B.trader_parent
through ordinary DSM bilateral rules
obtain ordinary DSM accepted-successor commitment C_T^+
and its successor-state authentication sigma_T^+
construct and verify canonical trader-acceptance artifact A_B
clear trader-parent fence only after that authenticated acceptance
only then mark B realized and make its exact DLV successors composable
publish/index receipt, A_B, and supporting immutable objects
return SUCCESS
15. if ABORTED(B) or CONFLICT_FINAL(other):
fold NO DLV successor from B
release the trader-parent fence without bilateral advancement
choose the next admissible route already in R
retry from step 1
16. if RECOVERING or INDETERMINATE:
recover THIS transaction to a terminal outcome
keep trader_parent fenced; do NOT permit any different successor from it
17. if R is exhausted:
return NO_ADMISSIBLE_ROUTE
Requirement 16.1. Steps 1–12 are a hard gate for the complete route. Class K must not begin
a mutating quorum-binding step after checking only a prefix, one leg, or one allocation.
Requirement 16.2. One selected route maps to one route-wide binding transaction. Class K
must not emulate route atomicity by completing separate settlement decisions per DLV.
Requirement 16.3. Class K must not display the route as successful, expose its output as
spendable, publish a successful settlement receipt, or fold the DLV successor until it has both
established DLV binding Finality for the exact SettlementBundle and verified the canonical trader-
acceptance artifact for the exact initiating trader successor, as required by Requirements 6.26–6.27.
Requirement16.4(Indeterminate-outcomediscipline). Atransport erroraftera mutating
binding request is not a non-commit result. Class K records the attempt as INDETERMINATE, keeps
the initiating trader parent fenced, and starts recovery. It must not silently discard the transaction
or permit a different successor from that parent.
Requirement 16.5 (Restart recovery). On restart, Class K restores every unresolved
initiating-trader parent fence before ordinary chain advancement is enabled. It then loads every
38
SoFi: Sovereign Deterministic Finance Revision 15
locally frozen transaction whose terminal outcome was not recorded, retrieves the immutable
bundle bytes and current generic binding records from the committed storage set, and drives each
transaction to COMMIT, ABORT, or CONFLICT before permitting a different successor from the
fenced parent.
16.3 Deterministic failure taxonomy
The protocol-visible set is:
• NO_ADMISSIBLE_ROUTE
• HOP_UNAVAILABLE
• SETTLEMENT_CONFLICT
• SETTLEMENT_RECOVERING
• SETTLEMENT_INDETERMINATE
• SETTLEMENT_UNRESOLVED
• DLV_BINDING_EVIDENCE_UNAVAILABLE
• ENCUMBRANCE_CONFLICT
• PREDICATE_REJECTED
• STALE_STATE
• BUDGET_EXHAUSTED
• PROOF_INVALID
• REFERENCE_UNDEFINED
• WINDOW_REJECTED
• SIZE_BOUND_EXCEEDED
• STORAGE_SAFETY_VIOLATION
CONFLICT_FINAL maps to SETTLEMENT_CONFLICT and may trigger reroute after the prior trans-
action is terminal. RECOVERING and INDETERMINATE are protocol recovery states; for the market
path the user-facing umbrella state is SETTLEMENT_UNRESOLVED. It means neither market success
nor market failure, carries no spendable trader output, and keeps the initiating trader parent
fenced. A verifier that has a valid bundle but cannot currently obtain sufficient storage evidence
to establish historical DLV binding Finality reports DLV_BINDING_EVIDENCE_UNAVAILABLE. During
route construction that condition excludes the affected DLV candidate from R until its current
composed state can be established; Class K must not fail open by treating an evidence-unavailable
advertisement as active or unchanged. Two different established binding-final bundles for one par-
ent produce STORAGE_SAFETY_VIOLATION and quarantine. A binding-final market bundle without
a valid trader-acceptance artifact remains SETTLEMENT_UNRESOLVED and leaves the DLV parent
blocked without changing its reserves. A valid owner release/close that is already binding-final
does not enter SETTLEMENT_UNRESOLVED; under Requirement 6.30 it is a completed DLV release
transition. A release/close binding attempt that has not yet reached a terminal binding outcome
remains ordinary quorum-transaction recovery, not an owner-side post-Finality completion state.
39
SoFi: Sovereign Deterministic Finance Revision 15
16.4 User contract
The user commits input token, amount, output token, minimum output, fee ceiling, and bounded
route complexity. The user guarantee is:
At most one route for the committed intent may satisfy the market completion gate.
A successful market route has one binding-final DLV decision for its complete DLV
parent set, a verified trader-acceptance artifact for the exact initiating bilateral successor,
realized market DLV successors for every DLV parent consumed by that trade, at least
the committed minimum output, and no more than the committed fee ceiling. If no
market route satisfies the realization gate, no route output becomes spendable and no
market DLV reserve cursor advances.
Class K must not present a protocol settlement-time estimate. Operational storage latency
and retry timing are not protocol time. If a started binding transaction cannot presently reach a
terminal outcome, the interface must remain explicitly unresolved rather than reporting success or
failure. During route discovery, DLV_BINDING_EVIDENCE_UNAVAILABLE is fail-closed: the affected
DLV is excluded from R until its current composed state can be established, rather than being
routed as though a possibly stale advertisement were active.
17 Online SoFi Market Boundary, LP Absence, and DSM Offline
Transfers
A SoFi market trade is an online transaction. The fact that the LP may be absent is not the same
thing as the transaction being offline.
In ordinary DSM bilateral activity initiated while the remote party is absent, the present party
may send its own value toward that remote party but cannot cause value controlled by the remote
party to move outward without previously committed authority. A funded DLV embodies that
authority as actual encumbered reserve state: the LP has already moved liquidity into the DLV and
committed PM , the applicable token policy constraints, and the per-transition size bound in BM , so
a live trader may buy from the DLV while the LP is absent.
SoFi market settlement still depends on communication with the DLV owner’s committed storage
set to establish new DLV binding decisions and, in the beta profile, may require that set again
when an independent verifier needs historical binding-Finality evidence. Trader realization is proven
separately by the canonical acceptance artifact from the initiating trader’s ordinary DSM state.
Requirement 17.1. A conforming implementation must not advertise an offline SoFi market-
settlement guarantee. New DLV market acquisition, recovery of an unresolved DLV quorum
transaction, and independent establishment of beta DLV binding-Finality evidence may require
network access to the relevant committed storage set.
Requirement 17.2. LP absence must not be described as offline market execution. The
LP may be absent while the trader, Class K, and the required storage members are online. The
funded DLV’s encumbered reserves and precommitted market policy are what make that absent LP
executable within PM , the token policy, the actual reserves, and the committed per-transition size
bound.
Requirement 17.3. DSM’s separate offline/bearer paths remain governed by their own DSM
rules. SoFi does not redefine or remove those paths, and beta does not require a portable DLV
quorum certificate. If a later profile deliberately permits a market-derived state or instrument to be
accepted while disconnected without live access to required DLV binding-Finality evidence, that
profile must define a portable witness or another complete verification mechanism.
40
SoFi: Sovereign Deterministic Finance Revision 15
Requirement 17.4. Disconnecting does not resolve an unresolved market transaction. If the
initiating trader parent is fenced when connectivity is lost, the fence remains in force after reconnect
or restart until the DLV transaction reaches a terminal outcome under Requirement 6.23.
Requirement 17.5. When the LP reconnects to an active DLV, its bilateral relationship state
against that DLV must catch up through the already-realized market-successor history according
to Requirements 4.5 and 6.31. That synchronization does not reopen those trades for approval or
move the DLV reserves again. If the DLV was already terminally closed under Requirement 6.30,
the close is itself the final owner/DLV state update and reconnect requires no separate catch-up
step for that retired vault.
18 Security Model
18.1 Storage member compromise and availability
A storage member does not possess financial authority. It cannot make an invalid SettlementBundle
valid, alter a DLV invariant, forge an owner or trader signature, or choose a route. It stores opaque
bytes and generic transaction metadata.
The beta safety model for the quorum transaction is crash/asynchrony safety under protocol-
conforming Class K implementations and authenticated distinct member identities. A malicious
node may lie, selectively fail, or return wrong bytes; Class K detects wrong canonical content and
treats missing/invalid responses as unavailable. A public adversarial-node profile requires stronger
authenticated storage receipts or Byzantine quorum rules and is not silently claimed by this revision.
A response claiming successful synchronized service must be complete for the query. Selec-
tive omission of matching canonical data is non-conforming and is operationally equivalent to
unavailability.
18.2 Concurrent same-parent safety
Theorem 18.1 (At most one binding-final overlapping bundle). Assume:
1. q>n/2 for the committed storage set;
2. each member’s generic compare-and-exchange and local multi-key update are atomic and
durable;
3. Class K recovery obeys the safe-value rule of Requirement 6.22; and
4. counted member identities are distinct and authenticated.
Then two different SettlementBundles with overlapping K(B) cannot both be chosen binding-final
for the same DLV resource by conforming quorum transactions.
The proof obligation is quorum intersection plus preservation of a value that may already have
been chosen. A strict majority, including 3/5, is sufficient for this uniqueness theorem under the
theorem’s assumption that accepted member records remain atomic and durable. The beta 4/5
profile is intentionally stricter: it supplies an additional durability margin when a previously accepted
record or member later becomes unavailable. Requirement 6.13 therefore does not contradict this
theorem or imply that 3/5 lacks intersection safety under perfect durability.
This is the concurrent DLV case. History-bound parent composition handles the sequential
case in which a constructor observes a prior realized DLV settlement before attempting a new
transaction.
41
SoFi: Sovereign Deterministic Finance Revision 15
18.3 Bilateral seam: trader Tripwire, DLV quorum, LP catch-up
The three mechanisms protect different state surfaces and must not be conflated.
1. The initiating trader’s exact bilateral successor is governed by ordinary DSM parent binding
and Tripwire. The DLV storage quorum does not make a conflicting trader branch valid and
does not write the trader’s chain.
2. The DLV quorum resolves concurrent origination by unrelated traders against the same public,
pre-authorized DLV parent. That is the only reason a shared quorum decision is needed.
3. The LP’s bilateral relationship state against an active DLV may lag while the LP is absent
and catches up later to the already-realized market history. That catch-up neither creates nor
changes the earlier DLV binding decision or trader acceptance. A terminal owner close is already
the final owner/DLV state update and has no separate catch-up leg.
Theorem 18.2 (No replacement of bilateral safety). Under Assumption 2.4, the initiating
trader cannot have two valid realized successors from the same bilateral parent inside one DSM
history. A DLV settlement bundle that binds trader
_parent and trader
successor therefore
_
does not need a storage-node rule to enforce trader-side non-equivocation. The trader-parent
fence prevents a conforming client from accidentally advancing the parent while the DLV result is
unresolved; Tripwire remains the underlying state safety rule.
18.4 Multi-vault atomicity
Theorem 18.3 (One route-wide binding decision). One member applies a transaction record
to the complete sorted K(B) atomically or not at all. Class K establishes one quorum decision
for the route-wide transaction. Therefore a binding-final route cannot contain a binding-final DLV
selection for A but no corresponding selection for B when both are members of the same K(B).
Realization still requires the one exact initiating trader-acceptance witness bound to that complete
route.
Intermediate generic records may exist on fewer than q members during recovery. They do not
materialize value and are not binding-final. Recovery resolves the transaction rather than treating
those records as partial financial execution.
18.5 Constructor crash and ambiguous outcomes
Theorem 18.4 (Crash recoverability). For a market SettlementBundle, a crash before the first
mutating binding step leaves only ordinary immutable proposal bytes. A crash after a mutating
step may leave recoverable generic transaction records. A crash after the market DLV value is
chosen leaves a binding-final DLV selection for the exact SettlementBundle even if the original
constructor never observed the success response. That market binding fact alone does not advance
reserves; realization still requires the exact trader-acceptance witness. Owner-local release/close
follows Requirement 6.30 instead: once a valid release/close candidate is binding-final, the exact
release successor is already complete and immediately foldable.
Therefore “the caller did not receive COMMITTED” is not evidence of ABORT. An ambiguous
outcome is recovered by another Class K process using the exact immutable bundle and binding
records.
Theorem 18.5 (No phantom reserve advancement). Assume Definition 6.26 and Require-
ment 6.27. A binding-final SettlementBundle whose initiating trader successor has not produced a
42
SoFi: Sovereign Deterministic Finance Revision 15
valid AB cannot change the composed DLV reserves or generation. Therefore a trader cannot obtain
a free price-manipulation primitive merely by binding a DLV parent and refusing its own bilateral
advance. The remaining adversarial effect is liveness: that bound parent may remain unavailable
to later traders and to owner release/close until the exact settlement completes or the protocol
provides a future safe resolution mechanism.
This theorem covers the zero-successor side of the bilateral seam. Theorem 18.2 prevents two
valid trader successors from one parent; Theorem 18.5 states that no trader successor means no
economic DLV reserve fold.
Corollary 18.5.1 (Binding-withholding capital denial and exposure bounds). Theorem
18.5 converts the half-completed-exchange problem into an availability attack; it does not make
that attack economically costly for the attacker. Under the beta bind-before-trader-accept ordering,
a malicious trader may obtain DLV binding Finality for B and then refuse the ordinary DSM
advancement required to produce C+
T , σ+
T , and AB . No reserve value moves, but every distinct DLV
parent in K(B) remains blocked for market advancement and owner release/close.
There are two different exposure bounds and they must not be conflated. First, the per-route
cross-vault blast radius: if a selected route contains h≤maxhops logical legs and each leg uses at
most maxf anout distinct DLVs, then one binding-final route can block at most
Nroute ≤
h
∑︂
j=1
fj ≤maxhops·maxf anout
distinct DLV parents, with a smaller number when the route reuses a DLV. Second, the per-DLV
market-lock multiplicity: becausemarketbindingconsumesoneexactcurrentparent_
state
commitment
_
and a bound-but-unrealized market settlement does not advance to a new parent, a particular DLV
can have at most
Nunresolved
market(v, parentv ) ≤1
_
binding-final unresolved market candidate for its current parent. Additional trader identities cannot
stack additional binding-final market locks on that same unchanged parent; they can only contend
and lose, or target other DLVs. Thus one route may fan the denial out across several distinct
vaults, but one vault does not accumulate an unbounded number of simultaneous unresolved market
bindings against the same reserves. A binding-final owner close is not counted in this unresolved
multiplicity because Requirement 6.30 makes it immediately composable.
The current beta ordering still does not impose an economic cost proportional to the LP capital
madeunavailable: beforetraderacceptance, theattacker’stradeinputhasnotbeenrealizedasadebit.
The attacker’s protocol-visible cost is the fenced/abandoned trader parent plus storage, computation,
and identity-management cost. Disposable identities therefore make binding withholding a real
capital-denial exposure, but the LP-facing concurrency exposure for any one DLV is one unresolved
binding-final market lock at a time. LP funding policy and beta deployment limits should reason
separately about market-lock duration and capital per DLV, per-DLV unresolved market-lock
multiplicity of one, and the cross-vault blast radius of one route.
Non-normative mitigation experiment: pre-binding conditional trader advancement.
Assumption 2.2 suggests a possible future ordering in which the trader first advances into a
precommitted conditional branch family that encumbers the exact trade input, and the later DLV
binding outcome deterministically resolves that already-authenticated trader state to the success
or non-commit branch. The intended property would be that no live trader action remains to be
withheld after DLV binding and that abandonment locks or consumes attacker value rather than only
43
SoFi: Sovereign Deterministic Finance Revision 15
a disposable parent. This revision does not adopt that ordering. Before it can become normative,
tests must show that: (a) COMMIT and terminal non-commit outcomes select only branches
committed before the conditional advance; (b) resolution is driven solely by authenticated state and
binding evidence, never elapsed time; (c) crash/restart recovery can complete from deterministic
evidence without requiring the trader to return; (d) Tripwire admits no continuation outside the
committed family; (e) one route-wide result resolves every horizontal allocation and hop atomically;
and (f) the attacker cost is materially tied to encumbered value rather than merely to identity
creation.
18.6 Liveness, overlapping transactions, and the FLP boundary
Safety does not depend on elapsed time. Under unbounded asynchronous delay or permanent loss
of the fixed quorum, the protocol may fail to terminate. The explicit overlapping-key case
K(T1) = {A,B}, K(T2) = {B,C}
can also fail to terminate while independent recovery drivers repeatedly supersede one another’s
rounds even though neither transaction is yet chosen.
The beta implementation uses client-side recovery serialization within one device and randomized
operational backoff after observed higher-round contention to reduce dueling-proposer livelock. This
mechanism changes only retry scheduling. It is not committed protocol state, not a route ranking,
and not a financial winner rule. Termination still requires eventual communication with a qualifying
quorum and an interval in which one safe recovery attempt across the connected overlap component
proceeds without perpetual higher-round interference.
Operational timeouts or backoff may decide when to retry or which connection to attempt
next. They never decide COMMIT versus ABORT, never lower q, and never release the initiating
trader-parent fence. If termination is not presently possible, the correct user-visible result is
SETTLEMENT_UNRESOLVED.
18.7 Front running and ordering
There is no global mempool, validator ordering authority, or global public pending queue. A
complete SettlementBundle may become visible to members of its committed storage set before
binding Finality because its immutable bytes and recovery metadata must be retrievable. That
visibility does not create validity, trader acceptance, realization, or priority.
Storage members define no fee auction and no global order between disjoint resource sets. No
Fisher–Yates shuffle, hash ranking, route digest, or node arrival order is a financial winner rule.
18.8 Router compromise
An external router may suggest a suboptimal candidate route. It cannot bypass intent bounds,
route membership, deterministic re-simulation, complete-bundle construction, the history-bound
parent anchor, quorum binding, or conservation. Default routing is SDK-resident.
18.9 Vault owner compromise
Compromise of an owner’s signing authority is outside SoFi’s cryptographic protection. Recovery
can limit future damage but cannot rewrite a binding-final DLV selection or realized history.
44
SoFi: Sovereign Deterministic Finance Revision 15
19 Economic Model
19.1 Liquidity providers
An LP funds one or more independent DLVs and earns the fee policy committed by each vault.
Funding debits ordinary spendable owner balance and places that value into the DLV reserve state;
the LP does not retain a second spendable copy and does not custody trader balances. The LP
does not approve each swap live because PM , the token policy, the remaining reserves, and the
per-transition size bound in BM already define the permitted market successor family. The LP may
be absent while those DLV reserves execute permitted exchanges. Returning reserves to ordinary
owner balance is a separate reverse-encumbrance transition governed by owner-local beta PR; once
the exact owner-authorized release/close candidate wins the DLV-parent binding, that release
successor folds without a second acceptance artifact. The LP’s bilateral relationship state against
an active DLV catches up to realized market history when it returns. Vaults remain independently
owned even when a trade atomically allocates across several of them.
19.2 Storage nodes
Storage members are paid for persistence, bandwidth, availability, immutable-object storage, discov-
ery indexing, and generic conditional-storage service. They are not paid for trade ordering, route
inclusion, AMM computation, or economic validation. There is no protocol priority fee and no
node-side financial choice.
A member’s operational failure may reduce availability, but it does not change the owner-
committed threshold or grant another member authority to reinterpret it. Storage-set replacement
or membership handover is outside the beta settlement path unless explicitly specified by a later
authenticated handover protocol.
19.3 Traders
Trader costs are vault fees, storage/data-availability costs, and any optional compute service the
trader voluntarily uses. There is no protocol gas auction, validator tip, or global priority fee.
20 Architectural Comparison
Property Consensus-chain application
layer
SoFi
Custody pooled or contract-controlled sovereign DLV reserves inside
owner state
Execution globally ordered locally verified deterministic tran-
sitions
Liquidity shared pools independent DLVs with atomic ag-
gregation
Large same-pair trade one pool or external aggregator deterministic horizontal allocation
across DLVs
Finality consensus/probabilistic or
chain-specific
client-verified scoped quorum de-
cision over a complete Settlement-
Bundle
45
SoFi: Sovereign Deterministic Finance Revision 15
Property Consensus-chain application
layer
SoFi
Ordering extraction validator/sequencer surface no global ordering surface
Routing external service often privi-
SDK-resident and intent-bound
leged
Fees gas / priority markets LP fees + data availability
Programming general contracts bounded deterministic predicates
Cross-margin safety policy/risk engine committed encumbrance account-
ing
Reference governed feed/oracle co-signed windows over verified di-
gests where needed
Liveness block/time based recovery + bounded reroute, no
protocol clock
21 Conformance Test Vectors
An implementation claiming conformance must pass at least the following groups.
Group Required assertions
ccb/ tags/ anchor-v2/ predicate/ rounding/ enc/ compose/ bilateral-dlv/ dlv-custody/ byte-exact canonical encoding, absence markers, sorted sets, no
protobuf-as-signature-preimage
every commitment reproduces the specified domain-separated hash
parent anchor changes when parent state commitment changes
even if vault id, generation, and reserves digest are identical
identical verdict and step count across implementations
every rounding site and payer-adverse direction
claim uniqueness, solvency, exact consumption
market successors fold only after binding Finality plus a valid
trader-acceptance witness; binding-final market settlement with-
out trader acceptance leaves reserves unchanged and the parent
blocked; a binding-final valid owner-local release/close folds im-
mediately under the release arm and a terminal close retires the
DLV; stale parent rejected; duplicate binding-Final candidates
quarantine rather than tie-break
ordinary online initiation with an absent counterparty cannot take
value controlled by that absent party; the same exchange succeeds
against a funded DLV because the value is already encumbered
in executable DLV state and the market successor satisfies PM ,
token policy, actual reserves, the BM size bound, and ordinary
DSM rules
funding removes exact value from owner spendable balance and
places one non-duplicated copy in DLV reserve state; market trades
mutate DLV reserves; owner catch-up moves no value
46
SoFi: Sovereign Deterministic Finance Revision 15
Group Required assertions
release-policy/ owner cannot withdraw encumbered reserves directly; beta PR
is owner-local, release/close is a same-parent contender, and a
binding-final valid close folds the exact owner-authorized release
successor, credits reserves exactly once, and retires the DLV with
no second acceptance artifact
half-completion/ binding-final without trader acceptance leaves reserves and gener-
ation unchanged, output unspendable, parent blocked, and owner
close blocked; exact valid AB realizes and folds once
acceptance-root-auth/ a constructor with valid B, valid preconstructed successor autho-
rization, and a self-built accepted-state commitment/Merkle root
cannot realize the settlement without a valid ordinary DSM σ+
T
over the exact C+
T that commits that root
receipt-verifier/ successfulreceiptbindsimmutableAB ; independentverifierverifies
σ+
T directly over C+
T , extracts the authenticated post-root from
that commitment, verifies settlement inclusion, binds the exact
trader parent/successor, and matches the trader exchange to DLV
reserve deltas
binding-withhold-cost/ route blast radius ≤maxhops·maxf anout distinct DLV parents; one
current DLV parent admits at most one binding-final unresolved
market candidate; no reserve movement occurs and bind-before-
accept imposes no LP-capital-proportional attacker cost
composition-depth/ drealized market successors on an active DLV after the last owner
baseline require ordered composition of depth d; owner catch-up
publishes a fresh baseline; a terminal close ends the lineage and
needs no separate catch-up; no hidden storage-created checkpoint
exists
immutable-store/ same bytes replay idempotently; different bytes cannot overwrite
one canonical address
path-index/ mutable logical-path updates alter only address/index metadata,
never canonical payload bytes
quorum-fixed/ five-member beta uses owner-committed four-of-five; one unavail-
able member still requires all four remaining; threshold never falls
back to strict majority
quorum-margin/ three-of-five satisfies the uniqueness theorem when accepted
records remain durable; four-of-five beta preserves the stated
intersection margin after one accepted record/member becomes
unavailable
quorum-client/ no node computes quorum; Class K counts distinct authenticated
responses from the exact committed set
binding-race/ two complete bundles sharing one parent cannot both become
binding-final under adversarial scheduling
binding-crash/ kill the constructor after every mutating binding boundary; an-
other Class K recovers to one terminal COMMIT or ABORT
without original private signing context
47
SoFi: Sovereign Deterministic Finance Revision 15
Group Required assertions
binding-split/ bind-indeterminate/ trader-parent-fence/ overlap-liveness/ online-boundary/ multi-vault-atomic/ close-race/ reroute/ allocation/ settlement-domain/ binding-evidence/ node-opaque/ node-complete-serve/ routeset/ window/ divergent intermediate member records are recoverable and cannot
produce two binding-final values; safety holds without timeout-
based release
lost success response is recorded as INDETERMINATE; initiat-
ing trader parent stays fenced until recovery reaches a terminal
outcome
new intent, new nonce, unrelated application action, and restart
all fail to advance a fenced trader parent while the DLV decision is
unresolved; after COMMIT the fence clears only through ordinary
DSM acceptance of the exact bundled trader successor; Tripwire
remains the underlying one-successor rule; storage quorum never
writes the trader chain
concurrent {A,B}and {B,C}transactions preserve safety under
dueling recovery rounds; randomized backoff affects scheduling
only; unresolved state remains explicit if proposer quiescence never
occurs
SoFi market settlement has no offline guarantee; DSM bilateral of-
flinebehaviorisseparate; disconnectdoesnotreleaseanunresolved
trader-parent fence
one route over A,B,C uses one transaction over the complete sorted
key set; no successor is materialized from an intermediate subset
owner release/close and a market candidate over the same parent
cannot both become binding-final; market-first blocks close, while
close-first immediately folds the owner-authorized release successor
and retires the DLV with no further owner evidence
only terminal ABORT/CONFLICT or pre-binding failure permits
the next route in the already-committed route set
one same-pair trade splits across multiple independent DLVs;
canonical allocation independent of discovery order
beta rejects one atomic route whose DLVs do not share the same
storage_set_id and fixed q
one bundle copy verifies economics but does not by itself
prove quorum binding Finality; unavailable evidence returns
DLV_BINDING_EVIDENCE_UNAVAILABLE, excludes the
candidate from R, and never permits routing by assuming a stale
advertisement is still active
storage member behavior is identical for SettlementBundle bytes
and arbitrary opaque payload bytes of the same storage shape
synchronized member returns exact requested canonical bytes or
explicit unavailability; no successful selective-subset behavior
identical Canon(R) from identical candidates in arbitrary input
order
filter application, median computation, undefined reference fail-
closed
48
SoFi: Sovereign Deterministic Finance Revision 15
Group Required assertions
noclock/ CIrejectsprotocoltimestamps, durations, globalheights, orshared
sequence fields; transaction rounds are monotonic counters, not
time
Requirement 21.1. binding-race/, binding-split/, and multi-vault-atomic/ must exe-
cute the actual generic conditional-storage and Class K recovery path under concurrent scheduling.
Unit-testing quorum arithmetic alone is insufficient.
Requirement21.2. binding-crash/ mustterminatetheconstructoraftereverystate-mutating
boundary and prove that a replacement client can recover the transaction from stored canonical bytes
and generic binding records. The test must not require pending state to disappear automatically
after a crash.
Requirement 21.3. bind-indeterminate/ must simulate a COMMIT response lost after the
DLV quorum value was already chosen and prove that the initiating trader parent remains fenced.
A fresh intent, fresh nonce, and unrelated application transition must all be unable to advance
that parent while the DLV outcome is unresolved. Recovery must discover the chosen DLV value;
completion of the exact bundled trader successor must occur through ordinary DSM bilateral state
advancement, not through storage quorum authority.
Requirement 21.4. multi-vault-atomic/ must include horizontal fanout and a multi-hop
route. The node-local conditional update must cover the complete sorted key set in one local
transaction, and Class K must establish one route-wide quorum decision.
Requirement 21.5. allocation/ must include a requested amount larger than the executable
capacity of every individual candidate DLV but satisfiable by their aggregate, proving the route
succeeds without pooled custody.
Requirement 21.6. trader-parent-fence/ must prove that the fence is persisted before the
first mutating DLV binding call, restored before post-restart bilateral advancement, released by
terminal ABORT/CONFLICT, and after COMMIT cleared only when the exact trader successor
contained in B is accepted through ordinary DSM bilateral state rules. A storage quorum response
alone must not write or advance the trader chain.
Requirement 21.7. overlap-liveness/ must exercise K(T1) = {A,B}against K(T2) =
{B,C}with both recovery drivers active. The test must prove safety under arbitrary interleaving
and prove that backoff or local worker serialization changes only scheduling, never validity.
Requirement 21.8. online-boundary/ must ensure the product does not claim an offline
SoFi market-settlement guarantee and that disconnecting an unresolved transaction does not release
its trader-parent fence.
Requirement 21.9. path-index/ must prove that replacing a latest discovery pointer cannot
change, delete, or overwrite any canonical object address already committed into a signature, state
root, SettlementBundle, or parent anchor.
Requirement 21.10. bilateral-dlv/ must exercise the same token pair with the remote
party absent in two cases: ordinary bilateral state without a funded executable DLV and a funded
DLV with valid PM , token policy, actual reserves, and per-transition size bound. The first case
must not permit the live party to take value controlled by the absent party; the second may succeed
only by consuming and advancing the DLV reserve state inside its committed bounds.
Requirement 21.11. composition-depth/ must build an active DLV history of at least several
realized market successors while the LP remains absent, prove that composition cost grows with
the number of unanchored market successors, then perform owner catch-up and prove that later
composition begins from the new authenticated baseline without changing the realized history or
49
SoFi: Sovereign Deterministic Finance Revision 15
moving value again. A separate terminal-close case must prove that once the binding-final close
folds and retires the DLV, no additional owner catch-up transition or baseline is required for that
closed vault.
Requirement 21.12. close-race/ must test both contention orders over the same DLV
parent. In the market-first case, a market candidate that is indeterminate or binding-final prevents
owner close from bypassing that parent; a binding-final but unrealized market candidate continues
to leave reserves unchanged and close blocked. In the close-first case, the exact owner-signed
release/close successor must already be complete and valid under owner-local PR before binding;
once that candidate becomes binding-final, the test must prove that the release successor folds
immediately, the released reserves are credited to ordinary owner balance exactly once, the DLV
becomes terminal/retired, every competing market candidate is rejected as stale/conflicting, and
no additional owner acceptance artifact, successor-state witness, signature round, or post-binding
owner action is required.
Requirement 21.13. dlv-custody/ must prove conservation across funding: the exact funded
amount leaves ordinary owner spendable balance and appears once in DLV reserve state, with no
second spendable copy. Subsequent market composition must mutate only the DLV reserve cursor;
owner catch-up must not debit or credit the same trade amounts again.
Requirement 21.14. release-policy/ must prove that direct owner withdrawal of DLV
reserves is impossible and that beta PR is owner-local by construction. A valid release/close must
consume the current parent, satisfy PR, token policy, conservation, and concrete owner authority
over the exact successor, and win the same DLV-parent contention used by market advancement.
The exact owner-signed successor and all verification inputs must exist before the first mutating
binding step. Binding Finality for that valid release/close candidate must then fold the exact release
successor and credit the released reserves back to ordinary owner balance exactly once; a terminal
close must retire the DLV. The vector must also prove that adding a post-binding co-signature,
reference-window outcome, liquidation/oracle branch, or other external completion dependency is
rejected as outside the beta PR profile.
Requirement 21.15. half-completion/ must force a bundle to become binding-final and then
withhold the trader-acceptance artifact. The expected state is unchanged DLV reserves/generation,
unspendable trader output, blocked DLV parent, and blocked owner close. The test must prove
that a second identity cannot quote or settle from a fictitious post-trade reserve state. Supplying
the exact valid AB whose σ+
T verifies directly over the ordinary DSM C+
T committing the accepted
post-advance root must then realize and fold the committed successor exactly once.
Requirement 21.16. receipt-verifier/ must start from the published receipt set alone
and prove that an independent verifier can retrieve and verify AB , parse C+
T and prove that it
commits the exact bundled trader parent/successor and R+
T , verify the ordinary DSM successor-state
authentication σ+
T directly over C+
T , verify the settlement inclusion proof under that authenticated
root, match (b,X), and reproduce the DLV reserve deltas. Removing or substituting AB , C+
T , σ+
T ,
or the inclusion proof must make completed-trade verification fail closed.
Requirement 21.17. acceptance-root-auth/ must construct a forged acceptance artifact
using the exact valid B, the exact preconstructed trader
_
successor authorization already present
in B, an attacker-chosen C+
T that names an attacker-chosen post-root, and a valid inclusion path for
the expected settlement leaf under that root. Verification must still fail because no valid ordinary
DSM successor-state authentication σ+
T verifies directly over that forged C+
T . Replacing the forged
commitment with the actual ordinary DSM C+
T from the accepted successor state and its valid
σ+
T must make the same inclusion evidence eligible to pass all remaining checks. This vector is
mandatory because a Merkle proof authenticates membership relative to a root, not the provenance
of the root itself.
50
SoFi: Sovereign Deterministic Finance Revision 15
Requirement 21.18. binding-withhold-cost/ must construct a maximum-shape admissible
route and stop the malicious trader after DLV binding Finality but before ordinary DSM trader
acceptance. It must prove that (a) no DLV reserve or generation advances, (b) every distinct DLV
parent named by the binding remains blocked, (c) owner release/close over those parents remains
blocked, (d) the route-wide number of distinct blocked parents is bounded by maxhops·maxf anout,
(e) for each particular blocked DLV, repeated attempts by additional identities cannot create a
second binding-final unresolved market candidate for the same unchanged current parent, so per-DLV
unresolved market-lock multiplicity is exactly bounded by one, and (f) no trade-input debit has
been realized merely by DLV binding. This is an exposure-characterization vector, not a claim that
beta prevents the attack.
Requirement 21.19. quorum-margin/ must distinguish uniqueness from durability margin: it
must demonstrate the strict-majority intersection argument with three-of-five under durable records
and the beta four-of-five surviving-intersection claim after one previously accepted record/member
becomes unavailable.
Requirement 21.20. binding-evidence/ must prove fail-closed route construction. Present
a discovery advertisement for a DLV whose current parent cannot be established because required
binding evidence is unavailable. The candidate must be excluded from R, and Class K must report
DLV_BINDING_EVIDENCE_UNAVAILABLE rather than assume that the advertised parent is active,
unbound, unchanged, or retired. The vector must include a stale pre-close advertisement whose
terminal close can be established only after the missing binding evidence becomes available: before
that evidence is restored the candidate is excluded, and after restoration the binding-final close is
folded and the stale advertisement is rejected as retired.
Non-normative research vector. A future conditional-prebind/ experiment may evaluate
the Assumption 2.2 mitigation described after Corollary 18.5.1. Passing that experiment does not
change beta conformance. It must demonstrate clockless branch resolution, deterministic crash
recovery, Tripwire confinement to the precommitted family, route-wide atomic resolution, and actual
pre-binding encumbrance of trader value before any claim that it improves the capital-denial ratio.
22 Implementation Rules for Beta
The beta profile is intentionally strict.
1. The DLV market path extends the ordinary DSM bilateral path; it does not introduce a second
trader-side state machine. The live trader uses ordinary bilateral parent/Tripwire semantics,
while the funded DLV holds the absent LP’s encumbered reserve value and exposes only the
market successors permitted by PM , token policy, actual reserves, and BM.
2. One canonical protocol path. Superseded wire, database, or settlement-register paths are
removed rather than retained as fallbacks.
3. Schema changes use a schema bump and clean reprovision unless an explicit migration protocol
is designed.
4. No dual-read, dual-write, silent fallback, or version auto-upgrade path.
5. Protobuf on wire; CCB for hashing/signing; Base32 Crockford only at display boundaries.
6. BLAKE3 commitments are domain separated.
51
SoFi: Sovereign Deterministic Finance Revision 15
7. SPHINCS+ is the signing primitive for SoFi protocol authority.
8. Frontend code renders state and invokes typed SDK operations; protocol business logic remains
below the render layer.
9. The immutable object table and the mutable discovery-index table are distinct schemas. A path
index stores content addresses, not duplicate mutable payload bytes.
10. The owner-committed q is carried in authenticated vault birth/anchor data. A generic helper
that silently derives strict majority must not override that committed value.
11. VaultStateAnchorV2 binds the parent state commitment and uses a clean new schema/domain;
the legacy anchor format is not retained as a compatibility fallback.
12. Settlement-specific node endpoints that parse claims, vault ids, routes, or economic payloads
are removed. The node exposes only generic immutable-object, index, binding-read, and
conditional-storage primitives.
13. Class K owns quorum calculation, transaction rounds, safe-value recovery, terminal-outcome
recording, and reroute discipline.
14. The initiating-trader parent fence is persisted before the first mutating DLV binding request
and is restored before a recovered trader bilateral chain may advance. A fresh intent or nonce
does not bypass it. The fence is not a replacement for Tripwire and storage nodes do not write
the trader chain.
15. SoFi market settlement is online in beta. LP absence must not be described as offline execution.
No portable quorum certificate is required, and the product must not imply an offline market-
settlement or market-derived bearer guarantee.
16. Recovery workers use at most one active worker per unresolved transaction per device; ran-
domized operational backoff may be used for overlapping-key contention but must never enter
signed or hashed protocol state.
17. An indeterminate binding transaction is durable client state. It is never silently converted to
ABORT by restart, timeout, UI dismissal, or route search.
18. Owner close remains blocked by an overlapping unresolved market DLV decision. Separately,
permanent quorum loss can prevent a close binding attempt from reaching any terminal
binding outcome at all. That pre-Finality recovery condition may keep the current DLV parent
unavailable while recovery is unresolved, but it is not an owner-bound-but-unrealized state: if a
valid owner-local close reaches binding Finality first, its exact release successor folds immediately
under Requirement 6.30. Beta invents no timeout escape for either unresolved quorum recovery
or an already-bound market parent.
19. After the LP returns to an active DLV and catches its bilateral state up through realized market
successors, the authenticated owner state emits a fresh DLV baseline/anchor. Beta provides no
node-created checkpoint while the LP remains absent. A terminally closed DLV requires no
separate catch-up baseline because the close itself is the final owner/DLV state update.
20. A gate failure is diagnostic. The implementation fixes the cause rather than bypassing the gate.
21. Changed settlement paths are exercised in deterministic tests before device or hardware builds.
52
SoFi: Sovereign Deterministic Finance Revision 15
22. No TODO, FIXME, HACK, compatibility residue, or dead superseded settlement path ships in
the beta cut.
23 Security and Liveness Claims in Plain Language
The core mental model is:
SoFi does not make a market transaction “offline.” The trader is online; the LP may be
absent. Funding a DLV moves value out of the LP’s ordinary spendable balance and
into encumbered DLV reserve state. The DLV itself holds the liquidity. The LP controls
the vault by committing PM , PR, the fee and size bounds, and the relevant token-policy
constraints, but cannot directly spend the encumbered reserves outside those rules. A
trader can buy from the DLV while the LP is absent because the value and the permitted
market-transition family are already inside that executable state. Returning reserves to
the LP is a separate policy-governed release transition. The trader still uses ordinary
DSM bilateral state and Tripwire. If the LP returns while the DLV is active, its bilateral
state catches up to realized market history without moving the value again; if the DLV
was terminally closed, that close is already the final owner/DLV update and there is no
separate catch-up step.
The settlement-specific claim is narrower:
Because unrelated online traders can concurrently construct valid fulfillments from the
same publicly executable DLV parent, Class K uses the owner-committed storage set
only to obtain one consume-once decision for that DLV parent set. The SDK verifies
the complete route, builds one immutable SettlementBundle, contacts the committed
members itself, verifies canonical responses, and computes the fixed quorum locally.
Storage nodes do not calculate quorum and do not understand the trade. A COM-
MITTED result makes the selected bundle binding-final for the named DLV parents.
It does not move the DLV reserve cursor. The exact trader successor must then be
accepted under ordinary DSM and produce a verifiable acceptance artifact carrying the
ordinary successor-state authentication of the accepted post-advance root before the
DLV successor becomes realized and composable.
The mechanisms are intentionally separate:
• ordinary DSM bilateral state + Tripwire governs the initiating trader’s exact relationship
parent and successor;
• DLV funding + precommit moves liquidity into encumbered DLV reserve state and commits
the market and release transition families;
• PM + token policy + actual reserves + the BM size bound define which market reserve
successor may execute;
• PR defines when encumbrance may be reversed and reserves returned to ordinary owner balance;
• owner catch-up advances the LP’s bilateral relationship state to already-realized DLV history
when the LP returns;
53
SoFi: Sovereign Deterministic Finance Revision 15
• vault math determines whether each proposed DLV successor satisfies its invariant and com-
mitted bounds;
• history-bound parent anchors reject stale constructions and bind reserves to the actual state
history that produced them;
• encumbrance accounting prevents double pledge inside deterministic state;
• canonical immutable storage ensures protocol bytes cannot be overwritten under the same
content identity;
• discovery indexing finds immutable object addresses but carries no authority;
• the client-driven quorum transaction supplies one consume-once decision for overlapping
DLV parents without assigning economic semantics to storage nodes;
• the trader-acceptance artifact proves the exact ordinary DSM trader successor entered
authenticated trader state by carrying the ordinary accepted-successor commitment C+
T , its
successor-state authentication σ+
T , and settlement inclusion evidence under the root committed
inside C+
T ; only quorum binding plus that proof realizes the DLV successor;
• transaction recovery prevents a lost response or constructor crash from being mistaken for
failure;
• the initiating-trader parent fence prevents a conforming client from advancing the ordinary
bilateral parent while the DLV decision is unresolved; Tripwire remains the underlying state rule;
• the complete SettlementBundle cryptographically binds the ordinary trader-side exchange
to every selected DLV fulfillment;
• the route set supplies bounded fallback only after the prior DLV route is terminally non-
committed; and
• storage serving supplies bytes and generic conditional persistence, not pricing, routing, validity,
or global ordering.
Safety is independent of elapsed time. Liveness is conditional on eventual communication
with the fixed quorum and an interval of recovery-proposer quiescence. Permanent asynchrony or
perpetual overlapping recovery may leave a market DLV transaction unresolved. A market-side
unresolved state keeps the initiating trader parent fenced and may block owner close; its reserves
remain at the unchanged current parent until the exact trader acceptance evidence exists. A valid
close that reaches binding Finality first is not another unresolved state: under owner-local beta
PR, the exact owner-authorized release successor folds immediately and a terminal close retires
the DLV. Permanent quorum loss can still prevent a market or close binding attempt that has not
reached binding Finality from reaching any terminal binding outcome; that is unresolved quorum
recovery, not a post-Finality owner materialization state. An LP that stays absent while an active
DLV accumulates many realized market advances also leaves a longer composition chain until it
returns and publishes a new catch-up baseline. These are explicit beta costs; no timeout or hidden
checkpoint erases them.
54
SoFi: Sovereign Deterministic Finance Revision 15
24 Conclusion
The simplest correct description of SoFi is bilateral, but the reserve location matters. A market
trade is an online DSM transaction in which the LP may be absent. Before trading, the LP funds a
DLV by moving value out of ordinary spendable owner balance and into encumbered DLV reserve
state. The DLV itself holds that liquidity mathematically. The LP owns and controls the vault
through the policies committed at creation, but there is no second spendable copy on the LP side
and ownership does not provide a bypass around those policies.
That is what makes an absent LP executable. In an ordinary DSM relationship, a present party
may send its own value toward an absent counterparty but cannot cause value controlled by that
absent counterparty to move outward without prior authority. A funded DLV already contains
both the value and the market-transition authority. PM , the token policy, the actual remaining
reserves, the per-transition size ceiling in BM , parent state, and deterministic predicates define
which exchange successors are permitted. The trader can therefore buy from the DLV while the LP
is absent without giving the trader, router, or storage nodes general control over the LP’s other
state.
The reverse direction is equally constrained, but it is not a mirror-image two-phase exchange.
Returning value from the DLV to the LP is not a direct owner withdrawal from a separate balance.
It is a reverse-encumbrance DLV transition governed by the committed release/close policy PR. In
the beta profile PR is owner-local by construction: a release must consume the current DLV parent,
satisfy PR, token policy, conservation, and concrete owner authority, and the exact owner-signed
successor plus every verification input must be complete before binding. If the close candidate
becomes binding-final first, no market candidate may consume that parent and the exact release
successor is immediately composable. The DLV reserve debit and owner spendable-balance credit
are one state update; a terminal close credits the released reserves exactly once and retires the DLV.
No owner-side acceptance artifact or post-binding owner materialization step exists.
Nothing about that replaces ordinary bilateral state. The initiating trader remains governed by
DSM parent binding, signatures, conservation, pending semantics, and Tripwire. The LP still has
bilateral relationship state against an active DLV. If the LP is absent while the DLV trades, the
owner-authenticated baseline may lag the DLV’s realized market history; if the LP returns while
the DLV remains active, it deterministically catches up and emits a fresh authenticated baseline.
Catch-up records the already-realized DLV reserve state. It does not transfer the trade amounts
again and is not authorization, veto, or settlement. If a terminal close has already folded, the DLV
is retired and there is no separate post-close catch-up step.
SoFi’s additional shared-state machinery exists because the funded DLV is publicly executable
under its precommit. Multiple unrelated traders can read the same DLV parent and independently
construct valid bounded fulfillments before either sees the other. The client-driven quorum transac-
tion supplies a consume-once binding decision for those shared DLV resource keys. It does not finalize
the trader’s sovereign chain, does not itself move the DLV reserve cursor, and does not turn storage
nodes into validators. Class K resolves the owner-committed member set, contacts those members,
verifies canonical storage responses, and computes the fixed threshold locally. Storage members
remain application-blind opaque-byte persistence plus generic conditional-storage machinery.
Theeconomicrealizationboundaryisdeliberatelylater. AquorumCOMMITmakesonecomplete
SettlementBundle binding-final for its DLV parent set. The exact initiating trader successor must
then be accepted through ordinary DSM and produce the canonical trader-acceptance artifact AB ,
including the ordinary accepted-successor commitment C+
T , the successor-state authentication σ+
T
over that commitment, and settlement inclusion evidence under the root committed inside C+
T . Only
binding Finality plus a valid AB makes the DLV settlement realized and eligible for composition. A
55
SoFi: Sovereign Deterministic Finance Revision 15
binding-final bundle with no trader acceptance may lock the DLV parent indefinitely, but it leaves
the DLV generation and reserves unchanged. It therefore creates an availability exposure, not a
phantom reserve exchange or a free reserve-ratio manipulation primitive.
A successful settlement receipt binds both sides of that statement. It identifies the exact
SettlementBundle and DLV successors and also commits the immutable trader-acceptance artifact.
An independent verifier can therefore establish the DLV quorum choice, verify σ+
T directly over the
ordinary accepted-successor commitment C+
T and thereby authenticate its committed post-advance
root, verify the settlement inclusion evidence under that root, and reproduce the reserve deltas. A
receipt that merely asserts that bilateral completion occurred without carrying or resolving to this
evidence is non-conforming.
Canonical protocol objects and discovery names remain separate. Exact protocol bytes live
under immutable deterministic content addresses. Logical paths are indexes to those addresses
and may move without rewriting history. Settlement and parent-state commitments never bind a
mutable path alias.
The beta profile makes its liveness costs explicit. An unresolved market quorum transaction can
indefinitely fence the trader parent. A binding-final market bundle whose trader acceptance never
materializes can indefinitely block that DLV parent and owner release/close. Beta defines no timeout
that safely releases that already-bound market parent. For any one DLV, this is a single-current-
parent market lock rather than an accumulating stack: because a bound-but-unrealized market
settlement does not advance the DLV, at most one binding-final unresolved market candidate can
occupy that current parent. A route can nevertheless fan that denial out across several distinct
DLVs up to the committed route/fanout bounds. A valid owner close that wins binding first does
not create the same second-phase exposure; it folds the exact pre-authorized release successor
immediately. Permanent quorum loss can still prevent a not-yet-terminal market or close binding
transaction from reaching a terminal binding outcome at all; this is unresolved quorum recovery,
not a post-Finality owner materialization state. Likewise, an LP that remains absent through many
realized market DLV advances leaves an increasingly deep composition chain. If the LP returns
while the DLV remains active, deterministic catch-up produces a new authenticated baseline and
collapses that verified history for future composition; a terminally closed DLV needs no separate
catch-up.
Thefive-memberbetastorageprofileusesanowner-committedthresholdoffour. Astrictmajority
is sufficient for the basic uniqueness theorem when accepted member records remain durable; four-of-
five is deliberately stronger to preserve the stated intersection margin after one previously accepted
record/member becomes unavailable. This is a scoped DLV contention mechanism, not a global
consensus layer: there is no global ledger, validator ordering market, global mempool, shared global
sequence, or required order between disjoint DLV resource sets.
If two distinct binding-final SettlementBundles are ever established for one DLV parent, the
storage safety assumptions have failed. SoFi does not retroactively pick a winner. The affected
lineage is quarantined and operator-level recovery is required.
The resulting separation is precise: Core enforces deterministic bilateral and DLV state validity;
funding places value into the DLV reserve state; PM governs market execution while the LP is
absent; PR governs reversal of the encumbrance back to owner spendable state; Class K constructs
and verifies routes, drives the DLV binding decision, fences unresolved trader parents, verifies trader
acceptance, and composes only successor-kind-valid DLV successors; the LP catches its bilateral
state up when it returns to an active DLV, while a terminal close is already the final owner/DLV
update; and storage nodes persist and serve canonical bytes under generic storage rules. No layer is
assigned authority it does not need.
56