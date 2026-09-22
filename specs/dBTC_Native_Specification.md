# dBTC: Bitcoin-Backed DSM State

*A Normative Specification for Consumption-Gated DLV Fulfillment, Constrained Bitcoin Release, and Successor Vaults*

**DSM-NATIVE dBTC V1**

*The dBTC is the bearer asset. The Bitcoin key is settlement machinery.*

Brandon “Cryptskii” Ramsay  
Irrefutable Labs Inc.  
Ontario, Canada  
September 2026

<!--
Engineering-source Markdown conversion of the DSM-NATIVE dBTC V1 normative specification.
Protocol content is normative except where the specification itself marks material informative.
Stable DBTC-* anchors are navigation/traceability metadata and do not change protocol semantics.
-->

<a id="DBTC-SPEC-01"></a>
# 1 Scope, Status, and Normative Language

<a id="DBTC-SPEC-01-01"></a>
## 1.1 Scope

This specification defines the protocol boundary between:

1.  Bitcoin collateral;

2.  DSM-native dBTC state;

3.  DLV fulfillment;

4.  dBTC consumption at withdrawal;

5.  Bitcoin release;

6.  partial-release successor vaults; and

7.  storage and verification infrastructure.

It does not redefine DSM identity, DSM bilateral state progression, the Per-Device Sparse Merkle Tree, the online economic-root register, the offline anti-cloning profile, SoFi market arithmetic, or Bitcoin consensus.

Those systems are imported as substrate.

<a id="DBTC-SPEC-01-02"></a>
## 1.2 Normative language

The words **must**, **must not**, **should**, **should not**, and **may** are conformance requirements.

Statements not using those terms are explanatory unless explicitly identified as an invariant, property, or proof obligation.

<a id="DBTC-SPEC-01-03"></a>
## 1.3 Specification status

This document specifies the intended normative dBTC architecture.

Implementation references in Section 37 are informative. Where an existing implementation path differs from this document, conformance requires the implementation to be brought to this specification rather than silently weakening the specification.

> **Key Principle**
>
> The protocol does not ask Bitcoin to determine who owns dBTC.
>
> DSM determines whether the claimant owns live dBTC and whether that dBTC was validly consumed. The DLV converts that verified consumption into the corresponding Bitcoin release authority.

<a id="DBTC-SPEC-02"></a>
# 2 Architectural Principle

dBTC has two distinct layers of authority:

1.  **economic authority**: ownership of live DSM dBTC state; and

2.  **execution authority**: the narrowly scoped Bitcoin material required to realize an authorized withdrawal.

These must never be conflated.

<a id="DBTC-DEF-02-01"></a>
#### Definition 2.1 — dBTC ownership
A party owns a quantity of dBTC only if that quantity exists in a currently valid DSM economic state under authority the party can satisfy.

<a id="DBTC-DEF-02-02"></a>
#### Definition 2.2 — Bitcoin execution material
Bitcoin execution material is cryptographic material used to spend a Bitcoin backing output after a valid dBTC consumption. It is settlement machinery and is not itself evidence of dBTC ownership.

Therefore:

$$\boxed{
\text{Bitcoin bytes}
\not\Rightarrow
\text{dBTC ownership}
}$$

and:

$$\boxed{
\text{live dBTC}
+
\text{valid authority}
+
\text{valid consumption}
+
\text{DLV fulfillment}
\Rightarrow
\text{authorized Bitcoin release}
}$$

<a id="DBTC-REQ-02-03"></a>
#### Requirement 2.3
No implementation may treat knowledge of a vault identifier, lineage, ciphertext, public key, hash lock, preimage commitment, storage record, or Bitcoin transaction template as sufficient evidence of dBTC ownership.

<a id="DBTC-SPEC-03"></a>
# 3 Relationship to DSM and Sovereign Finance

<a id="DBTC-SPEC-03-01"></a>
## 3.1 DSM substrate

This specification assumes the following existing DSM properties.

<a id="DBTC-ASM-03-01"></a>
#### Assumption 3.1 — Hash adjacency
Accepted DSM state is linked to its predecessor by canonical cryptographic commitment rather than by a global transaction sequence.

<a id="DBTC-ASM-03-02"></a>
#### Assumption 3.2 — Consumed parent
A realized state transition consumes the identified parent state and produces only the successor or successor set permitted by the transition.

<a id="DBTC-ASM-03-03"></a>
#### Assumption 3.3 — Canonical state
Economically relevant state is committed into the applicable authenticated DSM state structure. Unauthenticated caches are not authority.

<a id="DBTC-ASM-03-04"></a>
#### Assumption 3.4 — Tripwire
Conflicting accepted successors to the same consumed state are excluded under the cryptographic assumptions of DSM’s Tripwire construction.

<a id="DBTC-ASM-03-05"></a>
#### Assumption 3.5 — Conservation
Token debits, credits, burns, reserve movements, and provenance are accepted only through canonical DSM economic transitions satisfying the applicable conservation predicate.

<a id="DBTC-SPEC-03-02"></a>
## 3.2 Sovereign Finance boundary

SoFi operates on independently verifiable *online* economic state.

The canonical online economic root is denoted:

$$R_{\mathrm{econ}}.$$

An offline allocation is a separate DSM accounting domain. It is not made SoFi-spendable merely because the asset is dBTC.

<a id="DBTC-REQ-03-06"></a>
#### Requirement 3.6
A dBTC implementation must preserve the existing separation between:

$$\text{online admitted dBTC}
\qquad\text{and}\qquad
\text{offline allocated dBTC}.$$

No dBTC-specific bridge may silently merge those domains.

A user may move value between supported DSM custody domains only through the existing canonical DSM transition defined for that movement.

<a id="DBTC-SPEC-03-03"></a>
## 3.3 DLV compatibility

A dBTC backing vault is a specialization of the existing DLV idea:

> Value is encumbered into a state object and can leave only through a successor or fulfillment satisfying the condition family committed at creation.

The Bitcoin-specific DLV therefore inherits the same principle:

$$\boxed{
\text{public vault data is not reserve authority}
}$$

<a id="DBTC-SPEC-04"></a>
# 4 Conformance Classes

This specification uses the same conformance split as SoFi.

<a id="DBTC-DEF-04-01"></a>
#### Definition 4.1 — Class C: Core
Class C is the deterministic protocol verifier. It:

- *emits canonical commit bytes;*

- *verifies DSM state and provenance;*

- *verifies token conservation;*

- *verifies dBTC burn transitions;*

- *evaluates DLV fulfillment predicates;*

- *verifies successor-vault arithmetic; and*

- *rejects any mismatch deterministically.*

<a id="DBTC-DEF-04-02"></a>
#### Definition 4.2 — Class K: SDK/STK
Class K performs construction and orchestration. It:

- *discovers DLV data;*

- *obtains Bitcoin and DSM proofs;*

- *constructs withdrawal candidates;*

- *invokes Class C verification;*

- *invokes constrained vault execution only after successful verification;*

- *constructs successor vaults;*

- *broadcasts Bitcoin transactions;*

- *publishes resulting artifacts; and*

- *exposes user-facing execution semantics.*

Class K embeds Class C.

<a id="DBTC-DEF-04-03"></a>
#### Definition 4.3 — Class N: Storage node
Class N is non-authoritative persistence and indexing.

It may store and serve:

- *public DLV descriptors;*

- *encrypted vault execution capsules;*

- *successor-vault records;*

- *Bitcoin inclusion proofs;*

- *DSM proof material;*

- *content-addressed canonical objects; and*

- *existing DSM write-once facts where required by the surrounding protocol.*

Class N does not determine economic validity.

<a id="DBTC-REQ-04-04"></a>
#### Requirement 4.4 — No signing federation
Class N must not become a Bitcoin signing committee, threshold signer, custodian, mint, or validator set merely because encrypted vault bytes are stored there.

If SoFi uses a storage-set write-once origination barrier for a market DLV, that mechanism remains a persistence/exclusivity primitive. It is not Bitcoin signing authority and must not be interpreted as such.

<a id="DBTC-SPEC-05"></a>
# 5 Clocklessness and External Bitcoin Finality

DSM protocol validity is clockless.

<a id="DBTC-REQ-05-01"></a>
#### Requirement 5.1
No dBTC ownership predicate, burn predicate, DLV unlock predicate, or successor validity predicate may depend on wall-clock time, elapsed duration, or a globally shared DSM sequence.

Bitcoin block depth is different. Bitcoin confirmation depth is an external settlement observation, not a DSM ordering primitive.

Let:

$$d_{\min}$$

denote the minimum Bitcoin confirmation depth required by the selected dBTC Bitcoin-network profile.

<a id="DBTC-REQ-05-02"></a>
#### Requirement 5.2
The Bitcoin network identifier and $d_{\min}$ policy must be committed into the vault profile or resolved from an immutable network profile.

A reorganization deeper than the accepted Bitcoin depth is an external Bitcoin assumption and is not claimed to be impossible by DSM.

<a id="DBTC-SPEC-06"></a>
# 6 Canonical Encoding and Domain Separation

All security-critical structured objects are converted to canonical commit bytes before hashing or signing.

Write:

$$\mathsf{CCB}(X)$$

for DSM Canonical Commit Bytes.

At minimum, CCB must preserve the existing DSM rules:

1.  fixed-width integer fields use the canonical byte order;

2.  variable byte strings are length-delimited;

3.  fields are emitted in canonical declared order;

4.  optional absence is explicit;

5.  sets and maps have deterministic ordering;

6.  floating-point values are forbidden from protocol predicates;

7.  every object has a class discriminant and schema version.

Transport is Protobuf.

Binary identifiers remain binary internally.

Base32 Crockford is the human-display encoding for identifiers.

Hexadecimal text is not a protocol encoding.

<a id="DBTC-SPEC-06-01"></a>
## 6.1 Required domains

The existing DLV unlock domain is retained:

$$\text{\texttt{DSM/dlv-unlock}}.$$

This document additionally uses conceptual domains:

$$\begin{aligned}
D_{\mathrm{origin}}
&=
\text{\texttt{DSM/dbtc-origin/v1}},
\\
D_{\mathrm{burn}}
&=
\text{\texttt{DSM/dbtc-burn/v1}},
\\
D_{\mathrm{exit}}
&=
\text{\texttt{DSM/dbtc-exit/v1}},
\\
D_{\mathrm{succ}}
&=
\text{\texttt{DSM/dbtc-successor/v1}},
\\
D_{\mathrm{capsule}}
&=
\text{\texttt{DSM/dbtc-vault-capsule/v1}}.
\end{aligned}$$

If equivalent registered DSM domains already exist in the implementation, the registered domain is authoritative and duplicate domains must not be created.

<a id="DBTC-SPEC-07"></a>
# 7 The dBTC Asset

<a id="DBTC-DEF-07-01"></a>
#### Definition 7.1 — dBTC
One dBTC base unit represents one satoshi-equivalent unit of DSM economic state whose positive issuance traces to accepted Bitcoin backing.

The asset identifier is not enough to establish value.

A valid quantity requires provenance.

Conceptually, a holder’s dBTC state contains origin allocation:

$$A =
\left\{
(v_i,q_i)
\right\}_{i=1}^{m}$$

where:

- $v_i$ is a Bitcoin-backed dBTC origin lineage; and

- $q_i$ is the outstanding dBTC quantity attributable to that origin.

The total user-visible balance is:

$$Q = \sum_{i=1}^{m} q_i.$$

The wallet may display $Q$ as one fungible balance, while the protocol retains the provenance needed to reconcile withdrawals with actual Bitcoin backing.

<a id="DBTC-INV-07-02"></a>
#### Invariant 7.2 — No synthetic dBTC
A positive dBTC credit must have a canonical source accepted by DSM. No generic self-asserted mint or custom credit source may manufacture dBTC.

> **Key Principle**
>
> You cannot manufacture withdrawal authority by fabricating a Bitcoin proof, vault record, or preimage because the withdrawal begins with actual dBTC state.
>
> If the dBTC does not exist in live DSM state, there is nothing valid to burn.

<a id="DBTC-SPEC-08"></a>
# 8 Bitcoin-Backed Origin DLV

<a id="DBTC-SPEC-08-01"></a>
## 8.1 Origin output

A dBTC origin begins with a real Bitcoin output:

$$o_0 = (\mathrm{txid}_0,\mathrm{vout}_0)$$

with backing amount:

$$B_0.$$

The output is committed to a dBTC DLV profile.

<a id="DBTC-DEF-08-01"></a>
#### Definition 8.1 — Origin DLV
A dBTC origin DLV is represented abstractly as:

$$V_0 =
(
v,
0,
o_0,
B_0,
L_0,
C_0,
P_0,
h_{f,0},
\Pi_{\mathrm{btc}},
\Pi_{\mathrm{policy}}
)$$

where:

- *$v$ is the stable vault/origin identifier;*

- *$0$ is the backing generation;*

- *$o_0$ is the Bitcoin outpoint;*

- *$B_0$ is the backing quantity;*

- *$L_0$ is the DLV fulfillment condition;*

- *$C_0$ is the DLV parameter commitment;*

- *$P_0$ is the Bitcoin execution public key;*

- *$h_{f,0}$ is the fulfillment hash commitment;*

- *$\Pi_{\mathrm{btc}}$ identifies the Bitcoin network and confirmation profile; and*

- *$\Pi_{\mathrm{policy}}$ commits the dBTC policy, successor rules, and any lineage-wide successor minimum backing $B_{\min}$ used by the selected dBTC profile.*

The vault identifier remains stable across partial-withdrawal successors:

$$v_{n+1}=v_n=v.$$

The generation and Bitcoin outpoint change.

<a id="DBTC-SPEC-09"></a>
# 9 Origin Admission and dBTC Issuance

A Bitcoin output does not create dBTC merely because a client says it exists.

Class C must verify the origin.

<a id="DBTC-DEF-09-01"></a>
#### Definition 9.1 — Valid origin
$$\mathop{\mathrm{ValidOrigin}}(V_0,\pi_{\mathrm{btc}})$$

holds only if:

1.  *the Bitcoin funding transaction is valid under the configured Bitcoin-network verifier;*

2.  *the claimed outpoint exists in that transaction;*

3.  *the amount equals $B_0$;*

4.  *the output script matches the committed DLV profile;*

5.  *the transaction is proven included in an accepted Bitcoin chain;*

6.  *the required confirmation depth is met;*

7.  *the origin identifier recomputes from canonical origin material;*

8.  *the exact Bitcoin origin is bound to one canonical DSM issuance position; and*

9.  *the dBTC policy commitment matches the canonical dBTC asset.*

<a id="DBTC-REQ-09-02"></a>
#### Requirement 9.2 — Mint gate
Positive dBTC issuance must satisfy:

$$\Delta \mathrm{Supply}_{\mathrm{dBTC}} > 0
\quad\Longrightarrow\quad
\mathop{\mathrm{ValidOrigin}}(V_0,\pi_{\mathrm{btc}}).$$

Thus the Bitcoin deposit is the provenance source of newly issued dBTC.

<a id="DBTC-SPEC-10"></a>
# 10 What Moves During an Ordinary dBTC Transfer

Ordinary dBTC ownership transfer is a DSM operation.

Bitcoin is not the ownership ledger.

Suppose Alice owns:

$$q\;\mathrm{dBTC}.$$

Alice transfers $p$ to Bob, with:

$$0 < p \le q.$$

The DSM transition consumes Alice’s old economic state and produces the exact authorized successor state:

$$q
\longrightarrow
p_{\mathrm{Bob}}
+
(q-p)_{\mathrm{Alice}}.$$

The existing DSM transfer verifier proves:

1.  Alice’s source quantity exists;

2.  Alice has authority over the source state;

3.  the source state is current;

4.  the debit is exact;

5.  Bob’s credit has a canonical source;

6.  any Alice remainder is exact;

7.  provenance is preserved;

8.  the source cannot remain simultaneously spendable.

<a id="DBTC-REQ-10-01"></a>
#### Requirement 10.1 — Transfer purity
An ordinary dBTC transfer must not require:

- *a Bitcoin confirmation;*

- *the original depositor;*

- *a Bitcoin custodian;*

- *a Bitcoin signing quorum;*

- *a mint;*

- *a global dBTC ledger; or*

- *a storage-node economic verdict.*

A transfer may be performed through the applicable DSM online or offline custody mechanism.

> **Bitcoin Boundary**
>
> A successor *Bitcoin* vault is not created merely because ordinary DSM ownership changed.
>
> The Bitcoin backing generation advances when the backing Bitcoin outpoint is actually consumed, most importantly during a partial withdrawal.

<a id="DBTC-SPEC-11"></a>
# 11 Withdrawal Is a DSM Consumption First

This is the critical boundary.

A holder does not first obtain a Bitcoin key and then promise to burn dBTC.

The order is reversed.

$$\boxed{
\text{verify live dBTC}
\rightarrow
\text{consume dBTC}
\rightarrow
\text{prove consumption}
\rightarrow
\text{fulfill DLV}
\rightarrow
\text{exercise Bitcoin authority}
}$$

<a id="DBTC-SPEC-11-01"></a>
## 11.1 Withdrawal intent

Before the vault execution authority is usable, Class K constructs a canonical withdrawal intent:

$$W =
(
v,
a,
p,
f,
D,
g,
o_n,
S,
\Pi_{\mathrm{succ}}
)$$

where:

- $v$ is the origin vault;

- $a$ is the dBTC quantity consumed;

- $p$ is the external Bitcoin payout;

- $f$ is the Bitcoin fee charged against this backing;

- $D$ is the Bitcoin destination;

- $g=n$ is the backing generation;

- $o_n$ is the current backing outpoint;

- $S$ identifies the live DSM source state; and

- $\Pi_{\mathrm{succ}}$ commits the successor rule if the withdrawal is partial.

Define:

$$c_W =
\mathsf{H}(
D_{\mathrm{exit}}
\,\|\,
\mathsf{CCB}(W)
).$$

<a id="DBTC-REQ-11-01"></a>
#### Requirement 11.1 — Exact intent
The burn proof must bind the exact withdrawal intent.

Changing the amount, destination, origin, Bitcoin outpoint, fee treatment, or successor construction must change $c_W$.

<a id="DBTC-SPEC-12"></a>
# 12 The dBTC Burn

<a id="DBTC-DEF-12-01"></a>
#### Definition 12.1 — Withdrawal burn
A withdrawal burn is a canonical DSM transition consuming an actual spendable dBTC quantity and producing a non-spendable withdrawal-completion object.

Write:

$$S
\xrightarrow{\mathop{\mathrm{Burn}}(W)}
S'$$

for that transition.

The consumed dBTC is no longer ordinary spendable dBTC after the transition.

<a id="DBTC-REQ-12-02"></a>
#### Requirement 12.2 — Possession
Class C must reject $\mathop{\mathrm{Burn}}(W)$ unless the claimant possesses the live dBTC state identified by $S$ and satisfies the authority required by that state.

<a id="DBTC-REQ-12-03"></a>
#### Requirement 12.3 — No counterfeit burn
A burn proof must not be accepted merely because its bytes are well formed.

Class C must verify the actual state transition, including source inclusion, freshness, authority, provenance, exact debit, and successor root.

Conceptually:

$$\mathop{\mathrm{ValidBurn}}(W,\sigma)$$

requires:

$$\begin{aligned}
&
\mathop{\mathrm{Live}}(S)
\\
{}\land{}&
\mathop{\mathrm{Own}}(\mathrm{claimant},S)
\\
{}\land{}&
\mathop{\mathrm{Origin}}(S,a)=v
\\
{}\land{}&
\mathop{\mathrm{Valid}}(S \rightarrow S')
\\
{}\land{}&
\mathop{\mathrm{Consume}}_{\mathrm{dBTC}}(S,a)
\\
{}\land{}&
\mathop{\mathrm{IntentCommit}}(S\rightarrow S')=c_W
\\
{}\land{}&
\mathop{\mathrm{VerifyCompletion}}(\sigma,S\rightarrow S').
\end{aligned}$$

> **Key Principle**
>
> The scarce object is the live dBTC state.
>
> The preimage does not create the burn. The burn creates the completion evidence from which the correct DLV fulfillment secret can be obtained.

<a id="DBTC-SPEC-13"></a>
# 13 DLV Completion Evidence

Let:

$$\sigma$$

be the canonical DSM proof-of-completion commitment associated with the valid burn transition.

It must cryptographically commit to the state transition that consumed the dBTC and to the exact withdrawal intent.

The existing DLV construction derives its unlock value from:

$$L_n,
\qquad
C_n,
\qquad
\sigma.$$

Define:

$$\boxed{
sk_{V_n}
=
\operatorname{BLAKE3\text{-}256}
\left(
\text{\texttt{DSM/dlv-unlock}}
\,\|\,
\mathsf{CCB}(L_n)
\,\|\,
C_n
\,\|\,
\sigma
\right)
}$$

and:

$$h_{f,n}
=
\operatorname{SHA256}(sk_{V_n}).$$

<a id="DBTC-REQ-13-01"></a>
#### Requirement 13.1 — DLV alignment
A candidate $sk_{V_n}$ is valid only if all of the following align:

1.  *the live dBTC state;*

2.  *the claimant authority;*

3.  *the consumed dBTC quantity;*

4.  *the dBTC origin lineage;*

5.  *the withdrawal intent;*

6.  *the DLV lock $L_n$;*

7.  *the DLV parameter commitment $C_n$;*

8.  *the completion commitment $\sigma$; and*

9.  *the committed Bitcoin fulfillment hash $h_{f,n}$.*

Therefore:

$$\operatorname{SHA256}(sk_{V_n})=h_{f,n}$$

is necessary but not independently sufficient at the DSM layer.

It is the final cryptographic equality of an already-verified state relation.

<a id="DBTC-SPEC-14"></a>
# 14 Knowledge Is Not Possession

This distinction is normative.

A party may possess:

- the complete DLV;

- the complete dBTC lineage;

- every public DSM receipt;

- the Bitcoin transaction history;

- the encrypted execution capsule;

- the public Bitcoin execution key;

- the fulfillment hash; and

- every storage-node replica.

None of those facts create a valid burn.

The withdrawal relation is conjunctive:

$$\boxed{
\mathrm{Withdrawable}
=
\mathrm{LiveState}
\land
\mathrm{StateAuthority}
\land
\mathop{\mathrm{ValidBurn}}
\land
\mathrm{ValidCompletion}
\land
\mathrm{DLVPreimage}
}$$

A copied lineage with no live dBTC is inert.

A copied preimage commitment with no live dBTC is inert.

A stale dBTC state is inert.

A signature key not matching the live state’s authority is inert.

A completion proof from a different state is inert.

A preimage from another vault or another generation is inert.

<a id="DBTC-SPEC-15"></a>
# 15 Encrypted Bitcoin Execution Authority

<a id="DBTC-SPEC-15-01"></a>
## 15.1 Purpose

The Bitcoin execution key is not the bearer asset and should not reside as an ordinary reusable secret in the transferable dBTC state.

Let:

$$x_n$$

be the Bitcoin private execution scalar for backing generation $n$, with:

$$P_n=x_nG.$$

The scalar is represented outside ordinary dBTC state as a sealed vault execution capsule:

$$E_n =
\mathsf{SealVaultAuthority}
(
x_n;
v,n,L_n,C_n,P_n
).$$

Storage nodes may persist $E_n$.

<a id="DBTC-REQ-15-01"></a>
#### Requirement 15.1 — Ciphertext is not authority
Possession of $E_n$ alone must provide no usable Bitcoin signing authority.

<a id="DBTC-SPEC-15-02"></a>
## 15.2 Fulfillment-gated opening

The abstract opening interface is:

$$\mathsf{OpenVaultAuthority}
(
E_n,
sk_{V_n},
\sigma,
W
)
\rightarrow
\mathcal{A}_n$$

only if:

$$\mathop{\mathrm{ValidBurn}}(W,\sigma)$$

and:

$$\operatorname{SHA256}(sk_{V_n})=h_{f,n}.$$

Here $\mathcal{A}_n$ is the constrained Bitcoin execution authority for the current backing generation.

<a id="DBTC-REQ-15-02"></a>
#### Requirement 15.2 — No general-purpose key export
A conforming high-assurance implementation must not expose $x_n$ through a general-purpose signing or export API after DLV fulfillment.

The authority must be usable only by the dBTC vault execution path bound to the verified withdrawal intent.

This requirement prevents a valid partial dBTC burn from becoming an unrestricted ability to sweep the remainder of the Bitcoin vault.

> **Security Boundary**
>
> The protocol is not “preimage means unrestricted Bitcoin key.”
>
> It is:
>
> $$\text{valid DSM burn}
> \rightarrow
> \text{valid DLV completion}
> \rightarrow
> \text{matching preimage}
> \rightarrow
> \text{constrained execution of the committed Bitcoin transition}.$$
>
> The Bitcoin secret remains subordinate to the DSM state transition.

<a id="DBTC-SPEC-16"></a>
# 16 Current Bitcoin Fulfillment Script Profile

The current dBTC Bitcoin profile may use the existing dual-hashlock DLV script shape:

    OP_IF
        OP_SHA256 <fulfill_hash> OP_EQUALVERIFY
        <claim_pubkey> OP_CHECKSIG
    OP_ELSE
        OP_SHA256 <refund_hash> OP_EQUALVERIFY
        <refund_pubkey> OP_CHECKSIG
    OP_ENDIF

The normal dBTC withdrawal path is the fulfill branch.

It requires:

$$\operatorname{SHA256}(sk_{V_n})=h_{f,n}$$

plus a valid signature under $P_n$.

<a id="DBTC-REQ-16-01"></a>
#### Requirement 16.1 — Two aligned conditions
The hashlock witness and Bitcoin signature must correspond to the same DLV generation and the same committed withdrawal execution.

A valid preimage from one generation must not be paired with execution authority from another generation.

<a id="DBTC-SPEC-16-01"></a>
## 16.1 Refund branch

If a refund branch exists, it must not be a discretionary depositor backdoor.

<a id="DBTC-REQ-16-02"></a>
#### Requirement 16.2 — Refund safety
A live dBTC-backed vault must not expose a refund secret merely because a wall clock expired or because the depositor requests one.

Any refund secret must derive from a mutually exclusive DSM condition proving that the refund branch is valid under the committed DLV policy.

A refund path must never allow Bitcoin backing to leave while corresponding live dBTC remains outstanding.

<a id="DBTC-SPEC-17"></a>
# 17 Constructing the Bitcoin Withdrawal

Class K constructs the Bitcoin transaction body before constrained vault execution.

Let:

$$T_n$$

be the exact candidate transaction spending backing outpoint $o_n$.

The transaction commitment is:

$$c_T =
\mathsf{H}(
\text{\texttt{DSM/dbtc-bitcoin-tx/v1}}
\,\|\,
\mathsf{CCB}(T_n^{\mathrm{unsigned}})
).$$

The withdrawal intent must bind $c_T$, or must contain sufficient canonical fields from which Class C deterministically recomputes the same transaction body.

<a id="DBTC-REQ-17-01"></a>
#### Requirement 17.1 — Transaction binding
The DLV execution authority released by one burn must not authorize an arbitrary Bitcoin destination or amount.

The vault execution routine must verify that the candidate transaction equals the transaction committed by the burn.

<a id="DBTC-SPEC-18"></a>
# 18 Full Withdrawal

A full withdrawal consumes all dBTC backed by the claimant’s selected vault quantity and leaves no dBTC successor for that consumed backing.

For a simple one-vault full withdrawal:

$$B_n = p + f$$

when the Bitcoin fee is paid from the backing.

The DSM side performs:

$$\mathop{\mathrm{Spendable}}_{\mathrm{dBTC}}(B_n)
\rightarrow
\mathop{\mathrm{Burned}}_{\mathrm{dBTC}}(B_n).$$

The Bitcoin side performs:

$$V_n(B_n)
\rightarrow
\mathrm{BTC}_{\mathrm{destination}}(p)
+
\mathrm{fee}(f).$$

No successor vault is created.

<a id="DBTC-PROP-18-01"></a>
#### Property 18.1 — Full-withdrawal terminality
After a valid full withdrawal consumes the backing outpoint, the corresponding DLV generation is terminal and must not advertise a live successor.

<a id="DBTC-SPEC-19"></a>
# 19 Partial Withdrawal and Successor Vault

Partial withdrawal is the important split case.

Suppose:

$$V_n(B_n)$$

backs $B_n$ satoshis and the authorized exit removes:

$$a = p+f$$

from that backing, where $p$ is the external payout and $f$ is the fee charged to that backing.

Then:

$$0<a<B_n.$$

The Bitcoin transaction is:

$$\boxed{
V_n(B_n)
\rightarrow
\mathrm{BTC}_{\mathrm{destination}}(p)
+
V_{n+1}(B_{n+1})
+
\mathrm{fee}(f)
}$$

with:

$$B_{n+1}=B_n-p-f.$$

If the fee is funded by a separate Bitcoin input, the accounting equation is adjusted accordingly and that external fee source must be explicit.

<a id="DBTC-REQ-19-01"></a>
#### Requirement 19.1 — Successor minimum backing
The origin policy $\Pi_{\mathrm{policy}}$ must commit a successor minimum backing $B_{\min}$ for any profile that permits partial withdrawal. That value is a lineage property and must remain immutable across successor generations.

After applying the declared fee and anchor treatment, every partial-withdrawal successor must satisfy:

$$\boxed{
B_{n+1} \ge B_{\min}
}$$

For the common one-input profile in which an explicitly retained anchor value $\delta_A$ is paid from the backing, this is equivalent to:

$$B_{n+1}
=
B_n-p-f-\delta_A
\ge
B_{\min}.$$

Class C must enforce this condition as part of burn acceptance, not merely as a Class K construction-time check. If it fails, the burn is invalid and no completion evidence $\sigma$, DLV unlock value, Bitcoin signature, or successor activation may follow from that attempt.

<a id="DBTC-SPEC-19-01"></a>
## 19.1 Successor identity

The successor retains the same stable origin:

$$v_{n+1}=v_n.$$

Its backing generation advances:

$$n\rightarrow n+1.$$

Its Bitcoin outpoint is new:

$$o_{n+1}
=
(
\mathrm{txid}(T_n),
\mathrm{vout}_{\mathrm{successor}}
).$$

<a id="DBTC-SPEC-19-02"></a>
## 19.2 Fresh successor authority

The successor must use fresh Bitcoin execution authority:

$$x_{n+1}\neq x_n$$

and:

$$P_{n+1}=x_{n+1}G.$$

It also receives fresh generation-specific DLV fulfillment material:

$$L_{n+1},
\qquad
C_{n+1},
\qquad
h_{f,n+1},
\qquad
E_{n+1}.$$

<a id="DBTC-REQ-19-02"></a>
#### Requirement 19.2 — Fresh successor
A partial withdrawal must not return the remainder to the spent parent execution key.

The successor output must be committed to fresh generation-specific Bitcoin authority.

<a id="DBTC-REQ-19-03"></a>
#### Requirement 19.3 — Successor derivation
The exact successor-key derivation must be canonical, domain-separated, and pinned by known-answer test vectors.

It must bind at minimum:

- *stable vault identifier $v$;*

- *successor generation $n+1$;*

- *parent outpoint $o_n$;*

- *exact Bitcoin transaction commitment $c_T$;*

- *successor DLV parameters; and*

- *fresh successor derivation material.*

The parent scalar alone must not constitute an unrestricted reusable successor credential outside the constrained vault transition.

<a id="DBTC-SPEC-19-03"></a>
## 19.3 Successor activation

The successor DLV is constructed as part of the same authorized split.

Before the Bitcoin transaction reaches the confirmation policy required for redeemability, the successor may be represented as:

$$\mathsf{PendingSuccessor}.$$

After the successor output is proven in the accepted Bitcoin chain at the required depth:

$$\mathsf{PendingSuccessor}
\rightarrow
\mathsf{Active}.$$

<a id="DBTC-PROP-19-04"></a>
#### Property 19.4 — Successor continuity
Activation changes the Bitcoin backing generation, not the economic origin.

The remaining live dBTC continues to trace to stable origin $v$, now backed by $V_{n+1}$.

<a id="DBTC-SPEC-20"></a>
# 20 Why the Parent Cannot Remain the Authority

A partial withdrawal consumes:

$$o_n.$$

Therefore $o_n$ is not the backing object after the split.

The old generation is terminal:

$$V_n
\rightarrow
\mathsf{Spent}.$$

The remainder is represented only by:

$$V_{n+1}.$$

The protocol must not represent both as active backing.

<a id="DBTC-INV-20-01"></a>
#### Invariant 20.1 — Single live backing generation
For one realized branch of a dBTC vault lineage, a spent parent Bitcoin generation and its confirmed successor must not both be classified as live backing.

This is the Bitcoin-side analogue of ordinary DSM parent consumption.

<a id="DBTC-SPEC-21"></a>
# 21 No Separate dBTC Double-Spend System

dBTC does not need a second ownership consensus mechanism layered on top of DSM.

The withdrawal verifier asks the same fundamental question DSM already asks:

> Does this party possess a valid current state, under valid authority, and does the proposed transition consume that state according to the committed rules?

If the answer is no, no valid burn exists.

If no valid burn exists, no valid completion evidence $\sigma$ exists.

If no valid $\sigma$ exists, the correct DLV unlock value does not exist.

Thus:

$$\neg\mathop{\mathrm{ValidBurn}}(W,\sigma)
\Rightarrow
\neg\mathop{\mathrm{VerifyCompletion}}(\sigma)
\Rightarrow
\neg sk_{V_n}
\Rightarrow
\neg\mathop{\mathrm{Unlock}}(V_n).$$

<a id="DBTC-PROP-21-01"></a>
#### Property 21.1 — No synthetic withdrawal
Producing arbitrary dBTC-looking bytes cannot authorize Bitcoin release because the claimant must prove actual state inclusion, current-state validity, authority, provenance, and consumption.

<a id="DBTC-PROP-21-02"></a>
#### Property 21.2 — Stale-state rejection
A prior owner who retains an old dBTC state does not regain withdrawal authority after that state has been consumed by an accepted DSM successor.

> **Key Principle**
>
> The DLV does not solve double spending again.
>
> DSM has already answered whether the economic state exists and whether it may be consumed.
>
> The DLV only makes Bitcoin release conditional on that answer.

<a id="DBTC-SPEC-22"></a>
# 22 Online dBTC

Online dBTC is governed by the existing independently verifiable economic state.

A withdrawal from online dBTC must prove the burn against the canonical economic root:

$$R_{\mathrm{econ}}.$$

The proof must establish:

1.  the dBTC balance/provenance leaf existed in the predecessor root;

2.  the claimant had authority;

3.  the exact quantity was removed;

4.  the resulting root is canonical;

5.  the applicable economic position is admitted under the online root machinery; and

6.  the completion evidence binds the withdrawal intent.

<a id="DBTC-REQ-22-01"></a>
#### Requirement 22.1
A local wallet cache must not substitute for proof of the canonical $R_{\mathrm{econ}}$ state.

<a id="DBTC-SPEC-23"></a>
# 23 Offline dBTC

Offline dBTC remains a separately allocated DSM bearer domain.

An offline transfer uses the existing enrolled-appliance and protected-state machinery.

A Bitcoin withdrawal from an offline allocation may use an $\mathsf{OfflineBurnProof}$ only if the existing offline verifier proves:

1.  the allocation is live;

2.  the appliance authority is genuine under the applicable profile;

3.  the protected state/counter relation is current;

4.  the dBTC amount is consumed exactly once;

5.  the successor protected state recomputes; and

6.  the withdrawal intent is bound into the completion evidence.

<a id="DBTC-REQ-23-01"></a>
#### Requirement 23.1 — No cross-domain shortcut
An offline burn proof must not be treated as an admitted SoFi $R_{\mathrm{econ}}$ root merely because both carry dBTC.

Likewise, an online balance proof must not impersonate an offline protected allocation.

This preserves the existing SoFi rule that offline allocation is not ordinary SoFi-spendable liquidity.

<a id="DBTC-SPEC-24"></a>
# 24 Storage Nodes

Storage nodes are librarians, not judges.

They may be used so that a future dBTC holder can retrieve the vault material even if the original depositor is permanently offline.

For each vault generation they may store:

$$\{
V_n,
E_n,
\Pi_n,
\mathrm{proofs}_n,
\mathrm{metadata}_n
\}.$$

<a id="DBTC-REQ-24-01"></a>
#### Requirement 24.1 — No storage authority
A storage node must not:

- *decide who owns dBTC;*

- *validate a burn as an economic authority;*

- *possess a dBTC mint key;*

- *possess plaintext reusable Bitcoin vault keys;*

- *sign a Bitcoin exit;*

- *convert an invalid DSM transition into a valid one; or*

- *choose a successor on behalf of the protocol.*

A malicious or unavailable storage service may degrade availability.

It must not gain economic authority from the bytes it stores.

<a id="DBTC-SPEC-25"></a>
# 25 Original Depositor Independence

After valid origin admission, the original depositor has no continuing authorization role in ordinary dBTC circulation.

A later bearer may obtain:

- the dBTC lineage;

- the current DLV generation;

- the encrypted execution capsule;

- the Bitcoin inclusion proof;

- the required public parameters; and

- the relevant DSM proof material

from any available source.

The depositor need not sign the withdrawal.

<a id="DBTC-PROP-25-01"></a>
#### Property 25.1 — Issuer non-liveness
A valid current dBTC holder’s ability to exercise an ordinary withdrawal must not require the origin depositor to return online.

<a id="DBTC-SPEC-26"></a>
# 26 Multi-Origin Balances

A wallet may hold dBTC originating from several Bitcoin-backed DLVs.

For example:

$$A =
\{
(v_A,7000),
(v_B,3000)
\}.$$

A 10,000-satoshi-equivalent withdrawal may consume both provenance lots.

Its Bitcoin transaction may therefore contain multiple backing inputs:

$$o_{A,n},
\qquad
o_{B,m}.$$

Each input must be independently justified by dBTC consumed from the corresponding origin.

<a id="DBTC-INV-26-01"></a>
#### Invariant 26.1 — Origin conservation
For every origin $v_i$:

$$\mathrm{BurnFrom}(v_i)
\le
\mathrm{LiveDbtcFrom}(v_i)$$

before the burn.

<a id="DBTC-REQ-26-02"></a>
#### Requirement 26.2
A holder must not redeem dBTC attributed to origin $v_A$ against unrelated origin $v_B$ unless an explicit canonical protocol transition has changed the provenance relationship.

<a id="DBTC-SPEC-27"></a>
# 27 Fee Accounting

Bitcoin fees consume value and therefore must appear in conservation arithmetic.

For a one-input partial withdrawal paid entirely from backing:

$$B_n = p + B_{n+1} + f + \delta_A$$

where $\delta_A$ is any explicitly retained anchor value.

If the anchor remains part of the continuing backing policy, it must be accounted accordingly.

If a separate external input pays the fee, then the dBTC burn need not consume that externally supplied fee value.

<a id="DBTC-REQ-27-01"></a>
#### Requirement 27.1 — No invisible fee
No implementation may silently increase the Bitcoin fee after the DSM burn if the increase changes how much backing leaves the dBTC system.

Any economically relevant fee change requires a transition whose accounting recomputes exactly.

<a id="DBTC-SPEC-28"></a>
# 28 Conservation

For one origin lineage $v$, define:

- $B_v$: currently accepted Bitcoin backing remaining in the lineage;

- $S_v$: live spendable dBTC attributed to $v$;

- $X_v$: already consumed dBTC with an outstanding Bitcoin execution claim, if the implementation separates burn from observed confirmation; and

- $R_v$: dBTC permanently removed after completed redemption.

The exact state labels are implementation-specific, but the economic conservation relation is not.

Before any backing leaves:

$$B_v
=
S_v + X_v.$$

After a completed payout $p$ and backing-paid fee $f$:

$$B_v'
=
B_v-p-f.$$

The outstanding redeemable dBTC attributed to that lineage must fall by the same backing reduction:

$$S_v'+X_v'
=
S_v+X_v-p-f.$$

<a id="DBTC-INV-28-01"></a>
#### Invariant 28.1 — Backing/supply correspondence
No accepted protocol sequence may leave more redeemable dBTC attributed to an origin than the Bitcoin backing retained by that origin under the committed fee and reserve policy.

<a id="DBTC-SPEC-29"></a>
# 29 Crash Safety and Replay

Withdrawal crosses two systems and must be crash-safe.

The critical stages are:

1.  construct canonical withdrawal intent;

2.  construct exact Bitcoin transaction candidate;

3.  consume/burn dBTC;

4.  durably retain burn completion evidence;

5.  derive DLV fulfillment material;

6.  open constrained Bitcoin execution authority;

7.  sign the exact committed Bitcoin transaction;

8.  durably retain the signed transaction;

9.  broadcast;

10. observe settlement; and

11. publish successor DLV if partial.

<a id="DBTC-REQ-29-01"></a>
#### Requirement 29.1 — No second candidate after burn
Once the burn commits an exact Bitcoin transaction body, crash recovery must either:

1.  *resume or re-emit the identical committed transaction; or*

2.  *fail closed.*

Recovery must not use the same burn to construct a different destination, amount, or successor.

<a id="DBTC-REQ-29-02"></a>
#### Requirement 29.2 — No unsafe remint
Failure to observe a Bitcoin transaction immediately must not automatically recreate spendable dBTC if a Bitcoin-valid signed transaction may still exist.

Any recovery/refund transition must prove a mutually exclusive state under which the original Bitcoin release can no longer validly take effect.

<a id="DBTC-SPEC-30"></a>
# 30 Concurrent Local Invocation

An implementation must prevent two local execution threads from attempting to open the same vault generation concurrently.

For local execution:

$$(v,n)$$

is a unique active vault-generation key.

<a id="DBTC-REQ-30-01"></a>
#### Requirement 30.1
Class K must serialize local execution of one $(v,n)$ generation or use an equivalent atomic compare-and-set guard.

A second local execution request against an already committed generation must fail closed.

This is implementation concurrency control. It is not a new economic authority and does not replace DSM state validity.

<a id="DBTC-SPEC-31"></a>
# 31 Security Properties

<a id="DBTC-PROP-31-01"></a>
#### Property 31.1 — Burn-gated release
If a Bitcoin vault authority is opened through the conforming dBTC path, then there exists a valid DSM consumption of the dBTC quantity bound to that withdrawal.

<a id="DBTC-PROP-31-02"></a>
#### Property 31.2 — No dBTC from vault metadata
Public or replicated DLV metadata cannot create a positive dBTC balance.

<a id="DBTC-PROP-31-03"></a>
#### Property 31.3 — No withdrawal from stale ownership
A state already consumed by a valid DSM successor cannot independently satisfy the current-state requirement for another withdrawal.

<a id="DBTC-PROP-31-04"></a>
#### Property 31.4 — Preimage binding
For a fixed vault generation, substituting any of:

$$L_n,\quad
C_n,\quad
\sigma$$

changes the DLV unlock derivation except with negligible probability under the hash assumptions.

<a id="DBTC-PROP-31-05"></a>
#### Property 31.5 — Partial conservation
A partial withdrawal cannot validly create a successor whose retained Bitcoin value exceeds:

$$B_n-p-f$$

under the declared fee treatment.

<a id="DBTC-PROP-31-06"></a>
#### Property 31.6 — Successor minimum backing
A partial withdrawal cannot validly create or activate a successor whose retained Bitcoin backing is below the lineage-wide $B_{\min}$ committed by the origin policy, under the declared fee and anchor treatment.

<a id="DBTC-PROP-31-07"></a>
#### Property 31.7 — Fresh successor authority
A spent parent generation does not remain the Bitcoin execution authority for the confirmed successor generation.

<a id="DBTC-PROP-31-08"></a>
#### Property 31.8 — Storage non-authority
Compromise of Class N storage alone does not create a valid dBTC burn or a valid constrained Bitcoin withdrawal.

<a id="DBTC-PROP-31-09"></a>
#### Property 31.9 — Original depositor non-liveness
After origin admission, ordinary transfer and valid bearer withdrawal do not require the original depositor’s approval.

<a id="DBTC-SPEC-32"></a>
# 32 What a Device Compromise Means

dBTC inherits the security boundary of the DSM custody profile actually used.

If an attacker compromises enough of the claimant’s DSM authority to produce a transition that the applicable DSM verifier accepts as a valid burn, then the attacker has compromised that dBTC.

The dBTC vault must not pretend otherwise.

Conversely, compromise of unrelated storage infrastructure or unrelated vault metadata does not create a valid burn.

> **Security Boundary**
>
> dBTC does not become safer than DSM by adding Bitcoin.
>
> Nor should Bitcoin weaken DSM by becoming an independent bearer-authority system.
>
> The intended relationship is inheritance:
>
> $$\text{dBTC ownership security}
> =
> \text{DSM ownership security}$$
>
> with Bitcoin adding only the external collateral and settlement boundary.

<a id="DBTC-SPEC-33"></a>
# 33 What Is Deliberately Not Introduced

This protocol introduces none of the following:

1.  a Bitcoin threshold-signing federation;

2.  a vault custodian committee;

3.  a dBTC validator set;

4.  a global dBTC ledger;

5.  a mint that approves withdrawals;

6.  storage-node economic voting;

7.  a second double-spend database;

8.  a requirement that the original depositor remain online;

9.  wall-clock settlement validity;

10. a special dBTC-only ownership model replacing DSM;

11. a special dBTC-only hardware appliance; or

12. a rule that mere knowledge of a preimage constitutes ownership.

<a id="DBTC-SPEC-34"></a>
# 34 What Is Deliberately Not Claimed

The following are not claimed:

1.  that DSM can prevent a Bitcoin reorganization deeper than the chosen confirmation assumption;

2.  that dBTC remains secure after compromise of the DSM authority needed to produce a valid burn;

3.  that storage unavailability cannot delay retrieval of vault material;

4.  that arbitrary malformed Bitcoin transactions can be made safe by application convention alone;

5.  that a reusable raw parent Bitcoin scalar may be exported after a partial burn without constraining what it signs;

6.  that a depositor refund path may coexist with outstanding live dBTC without a mutually exclusive protocol condition;

7.  that testnet or Signet confirmation shortcuts imply mainnet security; or

8.  that implementation conformance follows merely because the required primitives exist in the repository.

<a id="DBTC-SPEC-35"></a>
# 35 End-to-End Protocol

<a id="DBTC-SPEC-35-01"></a>
## 35.1 Deposit: BTC to dBTC

1.  The depositor constructs Bitcoin backing output $o_0$.

2.  The origin DLV $V_0$ commits its Bitcoin and DSM policy.

3.  The funding transaction is broadcast.

4.  Class K acquires the Bitcoin inclusion evidence.

5.  Class C verifies the funding transaction, output, amount, script, network, and required confirmation depth.

6.  The origin position is bound to the DSM issuance transition.

7.  Exactly the accepted backing quantity becomes eligible for dBTC issuance.

8.  The resulting dBTC enters canonical DSM economic state.

9.  Public DLV material and permitted encrypted execution material are published for future holders.

<a id="DBTC-SPEC-35-02"></a>
## 35.2 Transfer: dBTC to dBTC

1.  Alice proves the applicable live DSM dBTC source state.

2.  Alice authorizes the transfer.

3.  DSM consumes Alice’s predecessor economic state.

4.  Bob receives the exact canonical credit.

5.  Alice receives any exact remainder.

6.  Provenance is preserved.

7.  No Bitcoin release occurs.

<a id="DBTC-SPEC-35-03"></a>
## 35.3 Full withdrawal: dBTC to BTC

1.  The holder resolves the backing DLV generation.

2.  Class K constructs the exact full-withdrawal Bitcoin transaction.

3.  The transaction body is bound into the dBTC burn intent.

4.  Class C verifies ownership, provenance, current state, amount, and exact consumption.

5.  The burn commits.

6.  The completion commitment $\sigma$ becomes valid.

7.  The DLV unlock secret $sk_{V_n}$ is derived.

8.  The matching vault execution authority is opened inside the constrained execution path.

9.  The exact committed Bitcoin transaction is signed.

10. The parent backing outpoint is broadcast as fully spent.

11. Bitcoin settlement is verified under the configured chain policy.

12. The DLV generation is terminal.

<a id="DBTC-SPEC-35-04"></a>
## 35.4 Partial withdrawal: dBTC to BTC plus successor vault

1.  The holder resolves the current backing DLV $V_n$.

2.  Class K chooses payout $p$ and exact fee treatment $f$.

3.  Class K generates or derives fresh successor execution authority.

4.  Class K constructs successor descriptor $V_{n+1}$ using the lineage-wide $B_{\min}$ committed by the origin policy.

5.  Class K constructs the Bitcoin split: $$V_n
        \rightarrow
        \mathrm{BTC}(p)
        +
        V_{n+1}(B_{n+1})
        +
        \mathrm{fee}(f).$$

6.  The entire split body is committed into the DSM burn intent.

7.  Class C verifies that actual live dBTC covering $p+f$ exists under the selected origin and that the resulting successor backing satisfies the origin-committed $B_{\min}$ under the declared fee and anchor treatment.

8.  The dBTC is consumed.

9.  Completion evidence $\sigma$ is produced.

10. The DLV fulfillment preimage recomputes.

11. The current vault execution authority is opened only for the committed split.

12. The split is signed and broadcast.

13. The parent generation becomes spent.

14. The successor Bitcoin output reaches the required acceptance depth.

15. $V_{n+1}$ becomes the active backing generation.

16. Remaining dBTC provenance continues under stable origin $v$.

<a id="DBTC-SPEC-36"></a>
# 36 Complete Causal Architecture

```text
Real Bitcoin output funded under a dBTC DLV profile
    ↓
Bitcoin proof + DLV origin binding verified
    ↓
dBTC admitted into canonical DSM economic state
    ↓
dBTC moves through ordinary DSM online/offline state transitions
    ↓
Current holder constructs exact withdrawal and successor intent
    ↓
Actual live dBTC is verified and consumed
    ↓
Valid completion evidence σ exists only for that consumption
    ↓
sk_V = BLAKE3-256(DSM/dlv-unlock || CCB(L) || C || σ)
    ↓
Matching encrypted Bitcoin authority opens only in the constrained vault path
    ↓
Full exit: release BTC
    OR
Partial exit: BTC payout + fresh successor vault
    ↓
Successor confirms and becomes the active backing generation
```


<a id="DBTC-SPEC-37"></a>
# 37 Implementation Mapping

This section is informative and maps the normative construction to existing DSM components.

<a id="DBTC-SPEC-37-01"></a>
## 37.1 Existing DLV fulfillment machinery

The DSM implementation already defines DLV fulfillment mechanisms, including:

    FulfillmentMechanism::BitcoinHTLC

with a fulfillment hash derived from the DLV unlock preimage.

The existing code documents:

$$sk_V =
\operatorname{BLAKE3\text{-}256}
\left(
\text{\texttt{DSM/dlv-unlock}}
\,\|\,
\mathsf{CCB}(L)
\,\|\,
C
\,\|\,
\sigma
\right).$$

This primitive should be reused rather than creating a dBTC-specific authorization system.

<a id="DBTC-SPEC-37-02"></a>
## 37.2 Existing Bitcoin HTLC machinery

The Bitcoin module already contains:

    build_htlc_script(...)
    verify_htlc_script(...)
    sha256_hash_lock(...)

for the dual-hashlock DLV profile.

The fulfill path already combines:

1.  a hash-preimage requirement; and

2.  a Bitcoin signature requirement.

<a id="DBTC-SPEC-37-03"></a>
## 37.3 Existing DLV state model

The DLV implementation already distinguishes an active Bitcoin-backed vault from an unlocked or claimed state.

The active-state documentation places the unlock after a dBTC Burn transition.

That ordering is normative in this document.

<a id="DBTC-SPEC-37-04"></a>
## 37.4 Existing proof carrier

The implementation already defines a Bitcoin HTLC fulfillment proof carrying Bitcoin transaction evidence, preimage material, SPV evidence, and a completion or transition commitment.

The dBTC profile should tighten that carrier so the accepted completion commitment is exactly the canonical burn proof defined by this specification.

<a id="DBTC-SPEC-37-05"></a>
## 37.5 Existing successor machinery

The Bitcoin Tap SDK already contains fractional-exit and successor-generation logic, including generation-specific successor preimage and hash-lock construction.

That machinery should be retained and reconciled with the canonical successor rules in this document.

<a id="DBTC-SPEC-37-06"></a>
## 37.6 Narrow implementation change

The principal architectural adjustment is not a new consensus or custody system.

It is to ensure that:

1.  the actual live dBTC burn is the sole source of valid withdrawal completion evidence;

2.  the DLV preimage derives only from that verified completion;

3.  Bitcoin execution authority is not ordinary bearer state;

4.  the vault execution material is stored only in encrypted or sealed form;

5.  opening that material is downstream of Class C verification;

6.  a partial burn can sign only the exact successor-producing split committed by the burn;

7.  the old parent authority is consumed after use; and

8.  the successor uses fresh sealed authority.

No new external authority is required.

<a id="DBTC-SPEC-38"></a>
# 38 Required Conformance Tests

A conforming implementation must include deterministic tests covering at least the following cases.

<a id="DBTC-SPEC-38-01"></a>
## 38.1 Origin admission

1.  Valid confirmed Bitcoin backing admits exactly matching dBTC.

2.  Wrong amount rejects.

3.  Wrong script rejects.

4.  Wrong Bitcoin network rejects.

5.  Insufficient confirmation depth rejects.

6.  Reusing one origin proof for a second independent dBTC issuance rejects.

<a id="DBTC-SPEC-38-02"></a>
## 38.2 DSM ownership

1.  Valid live dBTC can enter a withdrawal burn.

2.  Nonexistent dBTC cannot.

3.  Stale consumed state cannot.

4.  Wrong claimant authority cannot.

5.  Wrong origin allocation cannot.

6.  A forged positive dBTC balance cannot pass provenance verification.

<a id="DBTC-SPEC-38-03"></a>
## 38.3 DLV fulfillment

1.  Correct $L,C,\sigma$ derives the expected $sk_V$.

2.  Mutating $L$ changes the result.

3.  Mutating $C$ changes the result.

4.  Mutating $\sigma$ changes the result.

5.  Wrong preimage fails the Bitcoin hash lock.

6.  Burn proof from another vault fails.

7.  Burn proof from another generation fails.

8.  Completion evidence that does not bind the exact withdrawal intent fails.

<a id="DBTC-SPEC-38-04"></a>
## 38.4 Full withdrawal

1.  Full burn signs only the committed full withdrawal.

2.  Changing destination after burn fails.

3.  Changing amount after burn fails.

4.  Changing fee treatment after burn fails.

5.  Full withdrawal creates no successor vault.

6.  Parent vault becomes terminal after confirmed full spend.

<a id="DBTC-SPEC-38-05"></a>
## 38.5 Partial withdrawal

1.  Partial burn creates exactly one canonical successor output.

2.  Successor amount satisfies conservation.

3.  Successor generation increments exactly once.

4.  Successor outpoint matches the actual Bitcoin transaction.

5.  Successor authority differs from parent authority.

6.  Successor DLV retains the stable origin identifier.

7.  Parent authority cannot be reused as successor authority.

8.  Mutating successor key or script after burn fails.

9.  Mutating successor amount after burn fails.

10. A partial withdrawal whose successor backing would fall below the origin-committed $B_{\min}$ rejects before completion evidence is produced.

11. A successor generation cannot alter the lineage-wide $B_{\min}$.

<a id="DBTC-SPEC-38-06"></a>
## 38.6 Storage

1.  Public DLV data alone cannot produce a burn.

2.  Encrypted vault capsule alone cannot produce a valid withdrawal.

3.  Copying all Class N records to another host does not create dBTC.

4.  Storage omission causes availability failure, not value creation.

5.  Storage nodes never invoke a Bitcoin signing authority.

<a id="DBTC-SPEC-38-07"></a>
## 38.7 Crash and recovery

1.  Crash before burn leaves no valid unlock proof.

2.  Crash after burn but before signing resumes the same withdrawal only.

3.  Crash after signing but before broadcast retains the exact signed transaction.

4.  Crash after broadcast does not remint dBTC.

5.  Recovery cannot change destination.

6.  Recovery cannot change successor.

7.  Replaying a completed burn cannot generate a second independent dBTC debit or credit.

<a id="DBTC-SPEC-38-08"></a>
## 38.8 Online/offline separation

1.  Online burn verifies against admitted $R_{\mathrm{econ}}$.

2.  An unauthenticated online wallet cache is rejected.

3.  Offline burn verifies through the existing protected-state path.

4.  Offline allocation cannot be used directly as SoFi online liquidity.

5.  Online and offline proofs cannot substitute for one another.

<a id="DBTC-SPEC-39"></a>
# 39 Proof Obligations

The following obligations should be discharged in the existing DSM formal verification stack where their substrate lemmas already exist.

<a id="DBTC-PO-39-01"></a>
#### Proof Obligation 39.1 — Burn uniqueness
For one canonical spendable dBTC source state, two different accepted burns cannot both consume the same economic quantity.

<a id="DBTC-PO-39-02"></a>
#### Proof Obligation 39.2 — Burn/unlock implication
For any accepted dBTC vault unlock:

$$\mathop{\mathrm{Unlock}}(V_n)
\Rightarrow
\exists W,\sigma:
\mathop{\mathrm{ValidBurn}}(W,\sigma).$$

<a id="DBTC-PO-39-03"></a>
#### Proof Obligation 39.3 — Intent binding
For any valid burn proof $\sigma$, changing the withdrawal amount, destination, backing generation, or successor commitment causes the associated vault execution check to fail.

<a id="DBTC-PO-39-04"></a>
#### Proof Obligation 39.4 — Successor conservation
For a partial withdrawal:

$$B_n
=
p+f+B_{n+1}+\delta_A$$

under the declared transaction profile.

<a id="DBTC-PO-39-05"></a>
#### Proof Obligation 39.5 — No hidden duplicate reserve
After a partial withdrawal confirms, the parent backing output is not simultaneously represented as live backing beside its successor.

<a id="DBTC-PO-39-06"></a>
#### Proof Obligation 39.6 — Successor minimum backing
For every accepted partial withdrawal under a lineage with committed $B_{\min}$, the resulting successor backing satisfies:

$$B_{n+1} \ge B_{\min}.$$

No valid burn may produce completion evidence for a split that violates this bound.

<a id="DBTC-PO-39-07"></a>
#### Proof Obligation 39.7 — Provenance conservation
Transfer, split, merge, and burn operations preserve the total origin-attributed dBTC quantity except for explicit valid issuance and explicit withdrawal burn.

<a id="DBTC-SPEC-40"></a>
# 40 Comparison of Authority Models

| **Question**                     | **Incorrect mental model**           | **DSM-native dBTC**                                                 |
|:---------------------------------|:-------------------------------------|:--------------------------------------------------------------------|
| What is the asset?               | Bitcoin private key or redeem script | Live dBTC state under DSM authority                                 |
| What proves ownership?           | Knowledge of a Bitcoin secret        | Current canonical DSM state plus valid authority                    |
| What authorizes withdrawal?      | Possession of vault key              | Valid dBTC consumption followed by DLV fulfillment                  |
| What is the preimage?            | Bearer money                         | A fulfillment value derived from valid completion evidence          |
| What is the Bitcoin key?         | Economic ownership                   | Constrained settlement machinery                                    |
| Can storage decide?              | Possibly                             | No                                                                  |
| Is a federation required?        | Possibly                             | No                                                                  |
| What happens on partial exit?    | Reuse parent key                     | Spend parent into payout plus fresh successor vault                 |
| What happens on full exit?       | Unknown                              | Burn dBTC and terminate the backing generation                      |
| What stops fake dBTC redemption? | Separate bridge database             | Existing DSM state validity, provenance, authority, and consumption |


<a id="DBTC-SPEC-41"></a>
# 41 Final Protocol Invariant

The complete dBTC safety relation can be written compactly as:

$$\boxed{
\begin{aligned}
\mathop{\mathrm{BitcoinRelease}}(V_n,W)
\Rightarrow\;&
\mathop{\mathrm{LiveDbtcBefore}}(W)
\\
&\land\mathop{\mathrm{ValidAuthority}}(W)
\\
&\land\mathop{\mathrm{ValidOrigin}}(W,V_n)
\\
&\land\mathop{\mathrm{ValidBurn}}(W,\sigma)
\\
&\land
sk_{V_n}
=
\operatorname{BLAKE3\text{-}256}
\left(
\text{\texttt{DSM/dlv-unlock}}
\,\|\,
\mathsf{CCB}(L_n)
\,\|\,
C_n
\,\|\,
\sigma
\right)
\\
&\land
\operatorname{SHA256}(sk_{V_n})=h_{f,n}
\\
&\land
\mathop{\mathrm{BitcoinBody}}(W)=T_n
\\
&\land
\mathop{\mathrm{ValueConserved}}(T_n).
\end{aligned}
}$$

For a full withdrawal:

$$V_n
\rightarrow
\mathrm{BTC}$$

and the vault lineage terminates for that backing.

For a partial withdrawal:

$$V_n
\rightarrow
\mathrm{BTC}
+
V_{n+1}$$

where $V_{n+1}$ carries the remaining backing under fresh execution authority and additionally satisfies the lineage-wide floor:

$$B_{n+1} \ge B_{\min}.$$

The dBTC is never the Bitcoin key.

The Bitcoin key is never the ownership proof.

The preimage is never sufficient by itself.

The authoritative sequence is:

$$\boxed{
\text{state}
\rightarrow
\text{verification}
\rightarrow
\text{consumption}
\rightarrow
\text{completion proof}
\rightarrow
\text{DLV fulfillment}
\rightarrow
\text{Bitcoin execution}
}$$

This is the same architectural rule DSM applies elsewhere:

> Authority is established by valid state and a valid transition, not by possession of detached mutable bookkeeping.

<a id="DBTC-SPEC-42"></a>
# 42 Conclusion

dBTC does not require a separate distributed authority to prevent its own double spending.

The value already exists inside DSM’s state machine. A holder who wishes to withdraw must prove possession of that real state and irreversibly consume the required dBTC quantity under the same validity machinery that governs every other DSM economic transition.

That consumption produces the completion evidence needed by the DLV. The DLV’s domain-separated fulfillment relation derives the matching preimage only from the correct lock, parameters, and completion commitment. The resulting Bitcoin authority is settlement machinery for the exact authorized withdrawal.

A partial withdrawal spends the current Bitcoin vault into an external payout and a fresh successor vault. A full withdrawal terminates the backing generation. In neither case does the storage layer become a custodian, signer, mint, or validator.

The construction therefore preserves the architecture shared by DSM and Sovereign Finance:

**state is authority;  
validity is independently verified;  
consumed state does not remain spendable;  
storage is non-authoritative;  
and external execution occurs only after the deterministic predicate holds.**


# References

1. B. Ramsay, *Deterministic State Machine: A Concise, Post-Quantum Specification*, Irrefutable Labs Inc.
2. B. Ramsay, *Software Authority, Hardware Identity*, Irrefutable Labs Inc., 2026.
3. B. Ramsay, *Deterministic State Machines as Guarded Linear Constraint Systems*, Irrefutable Labs Inc., 2026.
4. B. Ramsay, *SoFi: Sovereign Deterministic Finance — A Normative Specification for Deterministic Limbo Vaults, Encumbrance Accounting, Multi-Vault Routing, and Non-Authoritative Storage Infrastructure*, Revision 5, Irrefutable Labs Inc., August 2026.
5. B. Ramsay, *Bitcoin Native, Off-Chain, and Offline — dBTC: A High-Level Explainer for Bitcoin Readers — LINEAGE BOUND V1*, Irrefutable Labs Inc., September 2026.
6. S. Nakamoto, *Bitcoin: A Peer-to-Peer Electronic Cash System*, 2008.
