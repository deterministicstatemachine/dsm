# Amendment 2c-F — the Def 14.2 settlement receipt: survey and rulings

> **STATUS: FROZEN — owner rulings of 2026-09-11, recorded verbatim below, and IMPLEMENTED by the
> change that carries this text (§7).** §1–§5 are the survey as it was put for ruling. Where they
> differ from the rulings, the rulings govern; the two corrections the rulings forced are applied in
> place and marked *(ruled)*. §6 is the text as frozen; the spec, the registry and 2c-D now carry it.
>
> The draft merged as #858 (`b2271d7a`) as a draft. Merging it was not a ruling; the rulings below are.

## Owner rulings (2026-09-11)

Put to the owner as four questions; the answers, verbatim:

- **R1 — X:** ratify the shipped X.
- **FB-4 — publication timing:** *"Pre-bind B durability stays pre-bind. B, including the embedded
  RouteCommit, must already satisfy the existing quorum durability requirement before mutating
  QuorumBind. The “after certification” requirement applies to the new Def. 14.2 SofiReceipt, not to
  B's pre-bind availability. These are two different publication obligations."*
- **R6 — fence ordering:** *"The Def. 14.2 SofiReceipt does not gate trader-fence release. C2's
  existing completion/fence-release ordering remains untouched. Construct the public SofiReceipt
  only after full certification; it may be published after the existing C2 fence-release boundary.
  Publication failure creates an idempotent recoverable publication obligation, but does not undo
  realization, re-fence the trader, re-bind, re-admit, or re-certify."*
- **R3/R5 — TA_B and witness:** *"TA_B must satisfy publication durability over the authenticated
  committed vault storage set S_v and threshold q_v established by the DLV state/lineage—not a set
  chosen merely because B names it. Existing B durability can count if already sufficient. For
  schema 1, witness_hash_v is always absent. Do not reject an otherwise certified settlement merely
  because optional proof material exists. The public receipt must not create a new witness-validity
  rule."*

**Two corrections to the draft follow, and are applied below.**
- `S_v` is the authenticated consumed parent's committed set, established by the DLV state and
  lineage. It is never the set `B`'s proposed successor names; the draft's "derivable from `B`
  alone" is withdrawn. Registry §5.19 already said the proposed successor is never authoritative for
  its own quorum.
- Proof material never refuses a receipt. The draft's "`P_v` present makes the receipt
  unconstructible" is withdrawn.

**Not separately put:** R2 (the fresh tag), R4 (class `0x0034`) and R7 (non-authority) had no
competing option in the draft. They are adopted as proposed and remain open to the owner's
objection before this change merges.

**Sources.** Revision 15 is quoted from `.github/instructions/sofispecs.instructions.md` as
`spec:N` (line numbers). The registry is `docs/papers/ccb-object-registry.md` (`reg §N`). Code is
cited as `path:line` at `e58340cf`, relative to `dsm_client/deterministic_state_machine/` unless it
starts with `proto/`.

---

## 0. Preliminaries

### 0.1 The frozen boundaries this draft is written against

```text
FB-1   C2 realization remains authoritative exactly as implemented.
FB-2   Receipt publication never becomes settlement authority.
FB-3   Receipt existence never substitutes for certification.
FB-4   Q publication occurs only after the settlement has passed the full certification boundary.
FB-5   Publication failure stays fail-closed and recoverable, and never creates a new settlement.
FB-6   QuorumBind semantics unchanged.
FB-7   Accepted-successor rules unchanged.
FB-8   CORR.1–5, Tier-1 SAT, §7 BundleAcceptance, Req 21.16 and IndependentRealization not weakened.
FB-9   No owner approval in market settlement.
FB-10  The composed-state / offline-LP rule fixed in C2 unchanged.
FB-11  No second realization or finality boundary.
```

§4 checks every proposed ruling against every boundary.

### 0.2 Two different things are called "Q"

| Symbol | Meaning | Normative source |
|---|---|---|
| **`Q`** (upper case) | `RouteCommitmentBody`, the preimage of `X` | spec:1356–1358; reg §5.12, class `0x0017` |
| **`q`** (lower case) | the settlement threshold the vault commits at birth | Def 6.9, Req 6.10 (spec:830–842); `V_n` field 15 |

2c-D ruling C2-R1 point 9 (*"The Def 14.2 receipt and Q publication remain separately owed"*) uses
the **first** sense: 2c-A Ruling 2 placed `Q` in the Def 14.2 publication set. The brief's Q
questions (*the storage set over which Q is measured*, *attributable successful publication*) are
about the **second** sense, i.e. quorum publication. This draft answers both, and from here on keeps
the letters apart: `Q` always means the route-commitment body; durability is always "at quorum `q`
over `S`". Ruling R5 proposes making that usage normative.

---

## 1. Existing normative state

### 1.1 Def 14.2 and its requirements

Def 14.2 (spec:1513–1515):

```text
Receipt = H(DSM/receipt ∥ b ∥ X ∥ aB ∥ Canon({successor_hash_v, witness_hash_v} v∈B))
```

- **Publication set** (spec:1521–1523): *"must include the immutable bytes of B, the immutable bytes
  of A_B, and the DLV successor/witness objects needed by the verifier."*
- **Status** (spec:1524–1527): *"A receipt is evidence and an index object. It does not create DLV
  binding Finality, trader acceptance, or realization."*
- **Req 14.3** (spec:1528–1530): no timestamp, global sequence position or node-order claim. Binds
  *"the exact SettlementBundle identifier, route commitment, trader-acceptance artifact digest, and
  DLV successor/witness commitments."*
- **Req 14.4** (spec:1531–1536): publish only after the exact bundle is binding-final and the exact
  initiating trader successor has produced a valid `A_B`.
- **Req 14.5** (spec:1537–1549): a third party must be able to establish (a) bundle economics and
  signatures, (b) the DLV binding-final choice, (c) acceptance of the exact trader successor
  (`σ_T^+` over `C_T^+`, and inclusion under `R_T^+`), and (d) equality of the trader exchange with
  the DLV reserve deltas.
- **Def 14.1** (spec:1491–1494): `aB = H(DSM/trader-settlement-acceptance/v2 ∥ Canon(A_B))`.
- **§16.2 step 14** (spec:1780–1789) gives this order: *"clear trader-parent fence only after that
  authenticated acceptance / only then mark B realized … / publish/index receipt, A_B, and
  supporting immutable objects"*. **Req 16.3** (spec:1805–1808): no successful receipt is
  published before both binding finality and verified trader acceptance.
- **Req 21.16** (spec:2356): *"receipt-verifier/ must start from the published receipt set alone"*.

### 1.2 `X`

- **§9.3** (spec:1355–1360): *"X = H(DSM/route-set ∥ CCB(Q)), where Q is the canonical
  RouteCommitmentBody carrying the trade intent I, the route set R, and nonceX … §7.2's external
  commitment is ExtCommit(X) = H(DSM/ext ∥ X)."* `R = {r_1,…,r_k}` is a set of alternative routes
  (spec:1352–1354). §16.2 step 15 retries *"the next admissible route already in R"*
  (spec:1791–1795).
- **§7.2** (spec:1258–1262): `ExtCommit(X) = H(DSM/ext ∥ X)`.
- **Tag table** (spec:422, 424): `DSM/route-set` is the route-set external commitment; `DSM/ext` is
  the external commitment.
- **reg §5.12**: `0x0017` schema 2 `{intent I, route_set R, nonce_x}`. **reg §5.14**: `0x000C` schema 2,
  a set of `0x000D`. **reg §6a Finding 3** resolved an earlier `X` overload into this body model and
  burned `0x0014`.
- **reg §5.20** `MarketTerms` field 2 `route_set_commitment (X)`: *"`H_dom(DSM/route-set, CCB(Q))`"*.
- **2c-A Ruling 2** (`amendment-2c-a-bundle-and-transition.md:186–199`): *"`B` proves exactly which
  route was executed. The receipt/evidence set proves that route came from the exact committed
  choice set and intent."*
- **2c-A.1** (`amendment-2c-a-1-encoder-cut-rulings.md:125–128`): the cut ships `0x0017`'s encoder
  *"only if the producer of `X` needs it … otherwise `X` is carried as the digest the producer
  already holds, and `0x0017` stays a later ship."* **This deferral is how the divergence in §2.1
  entered `b`.**
- **2c-C4 CORR.2** (`amendment-2c-c4-accepted-successor-closure.md:269`): the accepted DlvSettle's
  `external_commitment_x == B.market_terms.route_set_commitment`.

### 1.3 `DSM/receipt`

- Tag table (spec:428): `DSM/receipt` = **stitched receipt**.
- Def 14.2 (spec:1515) uses `DSM/receipt` for the SoFi settlement receipt.

### 1.4 Storage and publication

- **Def 6.19** (spec:940–944) and **§15.3** (spec:1603–1604): `addr(P) = H(DSM/storage-object ∥ N ∥ H(N ∥ P))`.
  reg §2.11 freezes the injective form: `inner = H_dom(N, P)`,
  `addr = H_dom(DSM/storage-object, N ‖ inner)` (`dsm/src/storage_object.rs:43–66`).
- **Req 15.2**: `PutImmutable` is idempotent for identical bytes. **Req 15.3**: re-hash before
  decoding. **Req 15.8**: *"count only distinct authenticated members of the exact owner-committed
  S"*. **Req 15.12**: exact bytes, or explicit not-found.
- **Def 6.9 / Req 6.10**: `S` and `q` are committed at vault creation. *"Current reachability cannot
  change S or q"* (spec:288).
- **§15.8** (spec:1701–1722): the canonical immutable classes include *"9. Receipt"*. The permitted
  indexes include *"3. receipt lookup key → set of receipt addresses"*.

### 1.5 Registry framework and neighbouring classes

- §2.1 envelope `u16 class ‖ u16 schema ‖ fields`; §2.3 optional = presence marker; §2.4 sets sorted
  by `enc(e)`, duplicates invalid, count in the preimage; §5.2 declares a tuple's `enc(entry)`
  **inline** without allocating a class (precedent).
- §2.8: an allocated `(class, schema)` is frozen; changed semantics need a new schema; retired
  numbers are burned. *"Promoting … must ship with the corresponding code change and collision
  test."*
- §3: highest allocated class `0x0033`; reserved `0x002A`–`0x002F`; burned `0x0003`, `0x0014`.
- §5.19 `SettlementBundle`: field 1 optional `MarketTerms` (the shape discriminator), field 2 `{T_v}`
  (beta: exactly 1). §5.21 `T_v`: 1 `c_n`; 2 complete `V_{n+1}`; 3 optional `P_v` (*"absent
  throughout the beta profile"*); 4 `close_authorization`, present **iff** owner close.
- §5.40 `TA_B`: *"There is **no `ta_B` field and no receipt field** — the Def 14.2 public Receipt
  binds `ta_B`, so a reciprocal field would be circular."*
- §5.23 `0x0031` field 4 `operation_bytes` is a `DlvSettleOperationPreimageV1`. Its fields 9
  `route_commit_bytes` and 10 `external_commitment_x` are listed in the 2c-B preimage table
  (`amendment-2c-b-accepted-successor-and-recovery.md:334–356`).

### 1.6 C2 rulings in force

- **C2-R1**: `TraderSettlementReceiptV1` (V1) is Req 21.16 evidence, **not** the Def 14.2 receipt.
  The walk is the only certifier. V1 reaches quorum **before** fence release (point 4). Point 9: the
  Def 14.2 receipt and Q publication remain owed.
- **D-f**: `resume_settlement_completion` finishes the **same** settlement: re-certify, bring the
  exact receipt to quorum, release the exact fence. Nothing re-binds.

---

## 2. Conflicts / missing definitions

### Blocker 1 — `X` has two definitions

**A. Normative.** `X_spec = H(DSM/route-set ∥ CCB(Q))` with `Q = {I, R, nonce_X}`, and a separate
`ExtCommit(X) = H(DSM/ext ∥ X)` (§1.2). `R` is a choice set of alternatives.

**B. Shipped.** `X_code = H_dom(DSM/ext, prost(RouteCommitV1 v2 with initiator_signature cleared))`
(`dsm/src/dlv/route_commit.rs:27–37`; tag at `dsm/src/common/domain_tags/dsm/misc/protocol.rs:48`).

- No `DSM/route-set` tag exists in code. No second `ExtCommit(X)` hash exists anywhere:
  **`X_code` is the external commitment** (`proto/dsm_app.proto:1546`, `ExternalCommitmentV1.x`).
- `Q` (`0x0017`) and `R` (`0x000C`) are `declared_unencoded` (`dsm/src/ccb/mod.rs:238–261`), so the
  shipped code cannot compute `X_spec` at all.
- **Semantics.** RouteCommitV1 v2 binds exactly one route: *"one route, one anchored state, one
  exact output, one signature"*, with the fallback fields reserved (`proto/dsm_app.proto:1497–1531`).
  TradeIntent schema 2 burned `k`, `max_hops` and `max_fanout` (reg §5.5, 2c-E). The shipped choice
  set is therefore always the selected route alone; a retry is a fresh quote and a fresh signature.
- **The shipped `Q` preimage is already inside `b`.** `route_commit_bytes` (the signed RouteCommitV1,
  including the initiator's SPHINCS+ signature) and `X` are fields 9–10 of the DlvSettle canonical
  bytes (`dsm/src/types/operations.rs:1603–1623`). That grammar is `DlvSettleOperationPreimageV1`,
  which `0x0031` field 4 carries inside `MarketTerms` field 6. A verifier holding `B` recomputes `X`.
- **The walk already relates RC to `B`.** Provenance step 7 (`dsm/src/economic/provenance.rs:1245–1275`)
  verifies RC's initiator signature and the hop's `vault_id`/`c_n`, recomputes `X`, and requires the
  hop's tokens, amounts and fee to equal the settle's. Tier-1 SAT
  (`dsm_sdk/src/sdk/vault_state_composition.rs:1030–1047`, 2c-E §6) consumes `MarketTerms.intent`,
  `MarketTerms.selected_route` and the verified RC bytes together.

**Every object, signature and hash that commits to `X_code`.** Word-matched occurrences in
`dsm/src` and `dsm_sdk/src`, tests included: `external_commitment_x` 44, `route_set_commitment` 33,
`compute_external_commitment` 45, `derive_receipt_id` 22, `vault_receipt_key` 15,
`external_commitment_rc_key` 3, `pending_pointer_x` 19.

| Site | How it commits `X` | Kind |
|---|---|---|
| `compute_external_commitment` (`route_commit.rs:35`) | the preimage | hash |
| DlvSettle field `external_commitment_x` (`operations.rs:681`, serialized `:1608`) | settler's canonical operation bytes | **signed** |
| DlvSettle field `route_commit_bytes` (`:1607`) | the RC itself, including the initiator signature | **signed**, and inside `b` via `0x0031` f4 |
| `MarketTerms` field 2 (reg §5.20) | CCB field | **inside `b`** |
| `settlement_receipt_id = derive_receipt_id(vault_id, X)` (`dlv/settlement_receipt_leaf.rs:209`, tag `DSM/settlement-receipt-id/v1`) | DlvSettle field 17 | **signed** |
| `0x0021` fields 2 `receipt_id` and 3 `x` (reg §5.30) | trader economic SMT leaf value | **committed under `R_T^+`**, so in `TA_B` paths |
| `DlvOwnerApplyV2.pending_pointer_x`, `.settlement_receipt_id` (`operations.rs:1674–1693`) | owner canonical operation bytes | **signed** |
| `sofi/extcommit/{x}`, `sofi/extcommit-rc/{x}`, `sofi/vault-receipt/{vault}/{x}` (`sdk/route_commit_sdk.rs:40,96–99`; `sdk/settlement_receipt_codec.rs:29–37`) | storage keys | discovery |
| `ExternalCommitmentV1.x` (`proto/dsm_app.proto:1544–1547`) | anchor record | stored bytes |
| provenance step 7 (`provenance.rs:1256`), CORR.2 (2c-C4) | recompute / equality | verification |
| bind retry "same `X`" (`handlers/dlv_routes.rs:3298–3303`) | occupancy recognition | control |

**C. Change class.** This depends on the option chosen (§3, §5.1).
**D. Compatibility.** See §3.
**E. Smallest ruling.** **Ratify the shipped `X`** (R1). No byte changes, and the multi-route `R` is
already contradicted by shipped design and an owner ruling (*no pre-signed fallbacks*).

### Blocker 2 — `DSM/receipt` names two different objects

**A. Normative.** spec:428 assigns `DSM/receipt` to the stitched receipt. spec:1515 reuses it for
Def 14.2.

**B. Shipped.** `TAG_DSM_RECEIPT = "DSM/receipt"` (`protocol.rs:32`) has exactly one production use,
and it matches the tag table's meaning:

```text
recovery_sdk.rs:2114-2117   receipt_hash = H_dom(DSM/receipt, bilateral receipt proof bytes)
  -> update_rollup -> ReceiptRollup
  -> sealed into the encrypted recovery capsule (persist_capsule, recovery_sdk.rs:2130)
  -> stored as recovery pref `capsule_rollup_hash`
       (handlers/recovery_routes.rs:328, 875, 1089; handlers/recovery_impl.rs:75)
  -> old_rollup_hash in the activation context (recovery_sdk.rs:1315, 1381-1385, 1416)
  -> create_tombstone(.., old_rollup_hash, ..) (handlers/recovery_impl.rs:514-520)
       whose tombstone_hash covers it and is SPHINCS+-signed (dsm/src/recovery/tombstone.rs)
```

So **persisted bytes** (capsules, prefs) and **signed bytes** (tombstone receipts) already depend
on this tag, transitively. The conflict is Def 14.2's reuse of it, not the code's use.

Receipt-family tags already in use, none of which the new tag may resemble:

| Tag | Meaning | Site |
|---|---|---|
| `DSM/receipt-commit` | bilateral receipt commitment | `domain_tags/dsm/core.rs:10` |
| `DSM/receipt-bind-session`, `DSM/receipt-evidence/A/v1`, `/B/v1`, `DSM/receipt-b-canonical/v1` | bilateral receipt session and evidence | `misc/protocol.rs:34,171–180` |
| `DSM/settlement-receipt/v1`, `-state/v1`, `-sign`, `-commit/v1`, `-id/v1` | V1 / economic receipt leaf family | `core.rs:73–103` |
| `DSM/economic-settlement-receipt-key/v1` | economic receipt key | `misc/economic.rs:47` |

**C. Change class.** Domain separation, confined to the new class.
**D. Compatibility.** Reusing `DSM/receipt` would put stitched-receipt proof hashes and SoFi receipt
digests in one domain. Moving the recovery use off it would change persisted capsules and signed
tombstones, which means a recovery reprovision. A fresh tag for the new class needs no migration.
**E. Smallest ruling.** A fresh tag, **`DSM/sofi-receipt/v1`**, for Def 14.2 only (R2).

### Blocker 3 — the set members are undefined

**A. Normative.** `successor_hash_v` and `witness_hash_v` are defined nowhere; their only occurrence
is Def 14.2. `v ∈ B` does not say which members of `B`. `Canon({…})` of a set of **pairs** names no
element encoding. *"The DLV successor/witness objects needed by the verifier"* (spec:1522),
*"DLV successor/witness commitments"* (spec:1530) and *"the published receipt set"* (spec:2356) are
not enumerated anywhere.

**B. Shipped.** Nothing computes any of them. The relevant shipped facts:

- **Def 14.2 applies to the Market shape only.** It binds `a_B`, and an owner close carries no
  trader-acceptance witness (spec:731–735). In every bundle that can carry a receipt, `T_v`
  field 4 is therefore absent (reg §5.19 shape rule), and in beta field 3 is absent too (reg §5.21).
- `V_{n+1}` and RC are **inside `CCB(B)`** by value.
- `CCB(B)` is `PutImmutable`'d to the vault's committed `S`, counted against the vault's `q`
  (Req 15.8 echo rule), **before any fence or binding round** (`sdk/settlement_bind.rs:93–120,161`).
  The market bind set is `catalog.resolve(settle.storage_set_id)` (`handlers/dlv_routes.rs` above
  `:3599`).
- `CCB(TA_B)` is frozen in the ADMIT transaction for `canonical_set(network_id)`, the network's
  root-register set, and then swept (`sdk/economic_admission_flow.rs:1316–1352`).
- V1 is frozen for the vault's `composed.storage_set_id` in `complete_settlement`
  (`handlers/dlv_routes.rs:3944–3960`).
- **Retrieval is not durability.** `fetch_immutable_payload` reads any mirror of the configured
  fleet and re-hashes (`sdk/storage_io.rs`). One honest copy suffices to *read*; `q` is what makes
  bytes *durable*.

**C. Change class.** Definitional and semantic (plus registry, because the entry encoding must be
declared). **D. Compatibility.** No shipped bytes are affected. **E. Smallest ruling.** R3.

### Blocker 4 — no registered canonical layout

**A. Normative.** §15.8 lists Receipt as a canonical immutable class (spec:1711). reg §3: every
canonical object feeding a hash or a storage address appears there. The receipt does not. reg §2.8:
allocation ships with code and a collision test.

**B. Shipped.** No class and no encoder. V1 is protobuf (`sdk/settlement_receipt_codec.rs`) and is
not this object (C2-R1). `0x0034` is referenced nowhere in `dsm/src`.
**C. Change class.** Registry change: a new class; nothing burned.
**D. Compatibility.** None; this is a first allocation. **E. Smallest ruling.** `0x0034` schema 1 (R4).

### Incidental findings (recorded here, not ruled)

- **I-1.** reg §5.13 says `max_hops` *"is authoritative in `TradeIntent` field 6"*, and reg §5.14 says
  `R`'s cardinality *"is checked against `TradeIntent` field 8"*. Under TradeIntent schema 2
  (reg §5.5) field 6 is `nonce` and there is no field 8. Both sentences are stale. R1 retires §5.14;
  §5.13's sentence needs correcting against 2c-E §5 either way.
- **I-2.** The headings of reg §5.19 and §5.20 still say schema 1; §3 says schema 2 (2c-E's
  transitive bump).
- **I-3.** 2c-D (the status table near line 784) says *"the Rev 15 text is not in-repo"*. It is:
  `.github/instructions/sofispecs.instructions.md` carries Revision 15, and every quotation here
  comes from it.
- **I-4.** Rev 15 §16.2 publishes the receipt **after** fence clear. C2-R1 point 4 reversed that
  for V1, for a reason specific to V1: foreign composers need V1 to certify. The Def 14.2 receipt
  has no such role (R6), so the Rev 15 order can stand for it.
- **I-5.** Frozen-artifact rows are keyed `(object_key, content_digest)` and each binds **one**
  `storage_set_id`; a second freeze of the same key and digest is a no-op
  (`storage/client_db/frozen_publication_artifact.rs:31–40,112–118`). Freezing the same `TA_B` bytes
  for a second set is therefore not expressible today. This is an implementation concern (§7), not
  a protocol one.

---

## 3. Compatibility analysis

| Decision | Wire / persisted bytes | Registry | Domain separation | Semantic | Docs / formal | Migration |
|---|---|---|---|---|---|---|
| **R1 = X-1** ratify shipped `X` | **none** | `0x000C`, `0x0017` retired (burned); §5.20 f2 note; §2.10 named grammar | `DSM/route-set` retired | `R` is the singleton selected route; `ExtCommit ≡ X`; §16.2 step 15 re-quotes | spec §7.2, §9.3, §16.2; reg §6a F3 | **none** |
| X-2 implement Rev 15 `X` | **every `X`** | encoders for `0x000C`, `0x0017` | `DSM/route-set` enters code | new signing object for `Q`; multi-route `R` returns | all of the above | **reprovision**: every signed DlvSettle (f10, f17), every `b`, every `0x0021` leaf, so every `R_T^+`, every `TA_B`, every owner apply, every storage key |
| R2 fresh tag | none | — | new tag only | — | spec Def 14.2 formula, tag table | none |
| R3 set members | none | inline tuple inside `0x0034` | — | definitions | spec Def 14.2 | none |
| R4 class `0x0034` | new bytes only | new row and table | — | — | registry | none |
| R5 publication | none | — | — | none new: reuses frozen artifacts and Req 15.8 | spec Req 14.6 | none |
| R6 ordering (O2) | none | — | — | none to C2 | new Lean module (owed with code) | none |
| R7 non-authority | none | — | — | forbids new consumers | spec Req 14.10 | none |

**X-2 collides with FB-4 and FB-8.** The walk verifies `X` **before** certification (provenance
step 7 recomputes it from RC). Under X-2 the walk would need `CCB(Q)` before certification. Either
`Q`'s bytes ride in `B`, which is published at quorum before binding by §16.2 step 12, or `X` goes
unverified until after certification, which weakens the walk (FB-8). X-1 has the same property for
RC, which already rides in `B`. **FB-4 therefore has to be read as governing the *successful-receipt
publication*, not the availability of bytes §16.2 step 12 requires before binding.** R5 states that
reading for the owner to confirm.

---

## 4. Proposed rulings

**R1 — `X` (take X-1: ratify the shipped `X`).**
`X := H(DSM/ext ∥ RC*)`, where `RC*` is the signature-cleared commitment form of the trader-signed
RouteCommitV1 v2. `X` **is** the external commitment; §7.2's second digest is deleted and
`DSM/route-set` is retired. The committed choice set is the selected route alone; a different route
is a fresh quote. Classes `0x0017` and `0x000C` are retired and burned; `0x000D` stays, because
`MarketTerms` field 3 uses it. 2c-A Ruling 2's *"Q lives in the receipt publication set"* is
satisfied by `CCB(B)`, which carries RC. `RC*` is registered as a named foreign grammar in
reg §2.10.
*Boundary check:* no bytes change, so nothing C2, QuorumBind, the accepted-successor rules, CORR,
SAT, §7 or Req 21.16 compute moves (FB-1, 6, 7, 8). No owner action is added (FB-9).
*Why smallest:* it is the only option that leaves every signed and committed value in the table in
§2 untouched.

**R2 — tag.** Def 14.2 uses `DSM/sofi-receipt/v1`. `DSM/receipt` keeps its tag-table meaning
(stitched receipt), and its recovery use is unchanged.
*Boundary check:* none are touched. *Why smallest:* no persisted or signed byte changes.

**R3 — the set and the publication set, enumerated.**
- `v` ranges over the elements of `B.transitions` (reg §5.19 field 2). Beta: exactly one.
- `successor_hash_v := c_{v,n+1} = H(DSM/vault-state ∥ CCB(T_v.successor))`. This is the successor's
  existing registered identity; no new tag.
- `witness_hash_v` is an optional `digest32` and is **always absent** in schema 1. *(ruled)* Proof
  material in `B` never makes a receipt unconstructible: the receipt does not commit to it and adds
  no witness-validity rule. Giving `P_v` a receipt commitment would need a new schema.
- Entry encoding is inline (reg §5.2 precedent): `enc(entry) = successor_hash ‖ opt(witness_hash)`.
  Entries are sorted by `enc(entry)` per §2.4; duplicates are invalid; the count equals
  `|B.transitions|`.
- **Publication set** `P(ρ_B) := { CCB(SofiReceipt), CCB(B), CCB(TA_B) }`: exactly three immutable
  objects, each under its own namespace. There is no separate successor object, witness object or
  `Q` object: `V_{n+1}`, `P_v` (absent) and RC are inside `CCB(B)` by value.
- **Lineage set** `Λ(TA_B)` := exactly the objects 2c-D §7 step 3 dereferences for
  `(G, economic_position)`. It is defined by that frozen walk and **not** re-enumerated or
  republished here. Its durability belongs to the admission that created each object. If a verifier
  cannot retrieve `Λ`, the result is INCOMPLETE (2c-D §7), never success. Req 21.16's *"published
  receipt set alone"* is read as `P` plus the objects `P`'s members address.

*Boundary check:* no predicate changes (FB-8). *Why smallest:* no new tag, no new class for the
tuple, and no invented witness value.

**R4 — class.** Allocate `0x0034` `SofiReceipt`, schema 1 (§6.5–§6.6). The name follows Def 14.2's
*"successful SoFi receipt"*, so that neither `TraderSettlementReceiptV1` nor
`EconomicSettlementReceiptState` (`0x0021`) shares a stem with it. **Its digest `ρ_B` is not
`settlement_receipt_id`**: that value is `derive_receipt_id(vault_id, X)` and names the V1 /
economic family.

**R5 — `Q` and quorum publication.**
- *What `Q` means:* the route-commitment body. Under R1 it is RC, carried in `CCB(B)`; there is no
  separate `Q` object and no separate `Q` publication act.
- *Storage set:* *(ruled)* for each `v`, `S_v` and `q_v` are the committed storage set and
  threshold of the **authenticated consumed parent** `V_n`, established by the DLV state and lineage
  — the composed `V_n` that `c_n` names. They are never the set `B`'s proposed successor names, and
  never local fleet configuration. `B`'s existing pre-bind durability counts when it was achieved over
  that same `S_v`.
- *Attributable successful publication of `p`:* at least `q_v` distinct authenticated members of
  exactly `S_v`, each echoing its own member identity, have accepted the exact bytes of `p` at
  `addr(N_p, p)` (Req 15.8, 15.2). This is the existing `put_immutable_to_all_members` and
  frozen-artifact sweep; no new quorum system.
- *Object or set:* **both.** `SofiReceipt` is one canonical object. *Published* means every member
  of `P(ρ_B)` is at quorum on every `S_v`.
- *How a verifier establishes it:* by re-observing the same way Class K does: query `S_v`, re-hash
  (Req 15.3), and count qualifying members (Req 15.8, 15.12). **There is no quorum certificate
  object.** Publication state is an observation, and it enters no validity predicate (R7).
- *Reading of FB-4:* a successful-receipt publication begins only after certification. `CCB(B)`
  being at quorum before binding (§16.2 step 12) is bundle publication, not Q publication.

**R6 — ordering, determinism, idempotence, recovery.**
- **Determinism.** `SofiReceipt` is a pure function of `(CCB(B), CCB(TA_B))`: no signature, no
  entropy, no clock, no node order. Every honest party produces identical bytes.
- **After certification.** It may be constructed only in a completion pass where `may_certify()`
  holds for exactly `b`, from that pass's certified fold. It is never constructed otherwise.
- **Independent of fence release (O2).** Receipt construction and publication are neither a
  precondition nor a consequence of fence release. C2's pass is unchanged: certify, V1 at quorum,
  release. *(ruled)* The receipt closure is frozen in that same certified pass, before the release
  step, so the obligation is durable before anything is released. A failure to project or freeze it
  is logged and never holds the fence, and publication may land after the release. This restores
  Rev 15 §16.2's order for this object (I-4).
- **Duplicates.** Identical bytes: `PutImmutable` and freeze are idempotent. Different bytes for the
  same `b` can differ only in field 3. A different `a_B` that does not certify `b` makes an invalid
  receipt: it is refused, and is **never** a `SAFETY_VIOLATION` or a quarantine trigger, so forged
  evidence cannot be used for denial of service.
- **Recovery.** *(ruled)* Certification creates the obligation once, as frozen bytes. Recovery is
  the generic sweep replaying exactly those bytes until a quorum of `S_v` holds each. If recording
  the obligation itself failed — the freeze does not hold the fence — it is **rediscovered** from
  the released trader fence and rebuilt byte-identically from durable facts (§7.3). Recovery never
  re-certifies, re-binds, re-advances, re-admits, re-fences or alters `b`, and it never undoes
  realization. Below quorum, the receipt stays pending and is retried. The settlement is unaffected
  throughout.

**R7 — non-authority.** No composition, admission, realization, fence, certification or
reserve-provenance predicate may take a `0x0034` object, its address, its presence or its
publication state as input. *This keeps FB-2, FB-3 and FB-11 structural rather than conventional.*

---

## 5. Alternative rulings where a real choice exists

### 5.1 `X`

| | **X-1 ratify shipped (recommended)** | X-2 implement Rev 15 | X-3 dual digest | X-4 derived spec-`X` in receipt only |
|---|---|---|---|---|
| Bytes | unchanged | every `X` and everything downstream | unchanged, plus a second digest | unchanged, plus a receipt-only digest |
| Choice set `R` | singleton (matches the no-fallbacks ruling) | multi-route returns | both | singleton |
| Signed by anyone | yes (settler; initiator over RC*) | needs a new signing object | the second digest is unsigned | unsigned |
| Registry | burn `0x000C`, `0x0017`; §2.10 grammar | ship both encoders | both live | both live |
| Verdict | **take** | reject: reprovision, and collides with FB-4/FB-8 (§3) | **reject**: two independently encodable commitments to one route, the alias class the registry removes | **reject**: binds a value no signature covers, and a receipt `X` ≠ `b`'s `X` breaks Req 14.3 |

reg §6a Finding 3 warned that preserving a preimage *"only to avoid a preimage change would make the
registry ceremonial"*. X-1 does not preserve the old four-operand concatenation that finding
replaced. It ratifies a single-body preimage that shipped, is signed by two parties, and is carried
in `b`.

### 5.2 `witness_hash`

- **W-A (recommended):** optional `digest32`, **must be absent** in schema 1; `P_v` present means a
  refusal. It keeps Def 14.2's pair shape and binds the absence explicitly.
- **W-B:** omit `witness_hash` from schema 1 and amend the Def 14.2 formula. This is equally small;
  it loses the explicit "no witness" statement.
- **W-C (reject):** hash `T_v` fields 3–4 under a new tag. That gives a constant for every beta
  receipt, plus a tag that commits nothing variable.

### 5.3 Entry encoding

The inline tuple (reg §5.2 precedent) is recommended. A nested class `0x0035` for a two-field tuple
used nowhere else is rejected.

### 5.4 Ordering relative to fence release

- **O2 (recommended):** independent of release. C2's release condition is untouched (FB-1), and
  Rev 15 §16.2's order is restored for this object.
- **O1:** release waits for V1 **and** `P(ρ_B)` at quorum. This is equally safe, but it changes
  C2's release condition and `DSMSettlementCompletion.lean`'s `published`. C2-R1 point 4's argument
  does not transfer, because nothing certifies from this receipt.

### 5.5 Where `TA_B`'s durability is measured

- **L-1 (recommended, and ruled):** every member of `P` is at quorum on `S_v`, including `TA_B`.
  *(ruled)* `S_v` is the authenticated consumed parent's committed set, not one read off `B`. Cost:
  `TA_B` needs a row bound to `S_v` when its admission froze it for a different set (I-5). Until
  per-set rows exist, that case is reported as not published and never counted.
- **L-2:** accept `TA_B`'s admission durability on the network root-register set. This is smaller
  in code, but the verifier must learn a second set that `B` does not name.
- **L-3 (reject):** replicate `Λ` to `S_v`. It is unbounded (the whole trader lineage).

### 5.6 Tag name

`DSM/sofi-receipt/v1` is recommended. `DSM/settlement-receipt/v2` is rejected: it reads as the
successor of the V1 leaf tag `DSM/settlement-receipt/v1`, which is a different object.
`DSM/receipt/v2` is rejected: it versions the stitched-receipt namespace for an unrelated object.

### 5.7 Who publishes

The settling trader **must**; any holder of `(B, TA_B)` **may**, because the bytes are identical
(recommended). The alternative, settling trader only, adds nothing: nobody can publish different
valid bytes.

### 5.8 Not proposed: canonical re-encode equality for `route_commit_bytes`

`X` is computed over the re-encoding of the decoded RC, so RC bytes carrying unknown or
non-canonically encoded fields yield the same `X`. `b` still fixes the exact bytes, and the
settler's signature covers them, so receipt determinism is unaffected. Requiring
`encode(decode(rc)) == rc` would be a new walk conjunct. It is recorded as a possible hardening and
deliberately left out of the smallest ruling.

---

## 6. Recommended frozen amendment text (PROPOSED, not frozen)

### 6.1 Rev 15 §9.3 / §7.2 (R1)

> The route commitment is `X = H(DSM/ext ∥ RC*)`, where `RC` is the initiating trader's signed
> `RouteCommitV1` (version 2) and `RC*` is its commitment form (registry §2.10): `RC` with
> `initiator_signature` cleared. `RC` binds exactly one route. The committed route set of this
> profile is the singleton `{selected_route}`. A different route is a fresh quote under a fresh
> `RC`, never a pre-committed alternative. `X` is the external commitment: there is no second
> `ExtCommit(X)` digest, and `DSM/route-set` is retired. `X` is carried in `B` as
> `MarketTerms.route_set_commitment`. `RC` is carried in `B` as field 9 of the
> `DlvSettleOperationPreimageV1` in `MarketTerms.recovery_material.operation_bytes`, so a verifier
> recomputes `X` from `B` alone.
>
> §16.2 step 15 then reads: *"if ABORTED(B) or CONFLICT_FINAL(other): fold NO DLV successor from B,
> release the trader-parent fence without bilateral advancement, and return NO_ADMISSIBLE_ROUTE; a
> new route requires a fresh quote."*

### 6.2 Tag table

```text
DSM/route-set           RETIRED by 2c-F R1 — never reused
DSM/ext                 external commitment X = H(DSM/ext ∥ RC*)
DSM/receipt             stitched receipt (unchanged)
DSM/sofi-receipt/v1     Def 14.2 SofiReceipt identity ρ_B
```

### 6.3 Def 14.2 (replacement)

> **Definition 14.2 (Settlement receipt).** A successful SoFi receipt is the canonical object
> `SofiReceipt` (CCB class `0x0034`) projecting one realized **Market-shape** SettlementBundle `B`:
>
> ```text
> SofiReceipt = ( b, X, a_B, { (successor_hash_v, witness_hash_v) : T_v ∈ B.transitions } )
> ρ_B         = H(DSM/sofi-receipt/v1 ∥ CCB(SofiReceipt))
> ```
>
> where `b = H(DSM/settlement-bundle ∥ CCB(B))`; `X = B.market_terms.route_set_commitment`; `a_B`
> is Def 14.1's; `successor_hash_v = H(DSM/vault-state ∥ CCB(T_v.successor))`; and `witness_hash_v`
> is absent in this profile. Its publication set is exactly
> `P(ρ_B) = {CCB(SofiReceipt), CCB(B), CCB(TA_B)}`. A receipt is evidence and an index object. It
> does not create DLV binding Finality, trader acceptance or realization, and no validity predicate
> takes it as input.

### 6.4 New requirements

> **Req 14.6 (Quorum publication).** `ρ_B` is *published* iff every member of `P(ρ_B)` has been
> accepted, at its canonical content address, by at least `q_v` distinct authenticated members of
> exactly `S_v`, for every `T_v ∈ B.transitions`. Here `S_v` and `q_v` are the committed storage
> set and threshold of the authenticated consumed parent `V_n`, established by the DLV state and
> lineage. Counting follows Req 15.8. `B`'s pre-bind durability counts when it was achieved over
> that `S_v`. No quorum certificate exists; publication is re-observable, never carried.
>
> **Req 14.7 (Ordering).** `SofiReceipt` is constructed only after the composition walk certifies
> exactly `b`, and only from that certified fold. Its construction and publication are neither a
> precondition nor a consequence of fence release, realization or admission.
>
> **Req 14.8 (Determinism and duplicates).** `SofiReceipt` is a pure function of `(CCB(B),
> CCB(TA_B))`. Any holder may publish it. Re-publication of identical bytes is idempotent. A
> receipt whose fields do not re-derive from `B` and a certifying `TA_B` is invalid evidence: it is
> refused, and never a safety violation.
>
> **Req 14.9 (Recovery).** Certification creates the publication obligation once, as frozen bytes;
> recovery replays exactly those bytes. Once a settlement has certified, a failure to construct,
> freeze or publish its receipt may delay evidence availability but never loses the obligation: a
> released trader fence — the durable record that certification happened — lets it be rebuilt
> byte-identically from `B`, the trader's own acceptance artifact and the fence's committed set. A
> publication failure never undoes realization, re-fences the trader, re-binds, re-admits or
> re-certifies.
>
> **Req 14.10 (Non-authority).** No composition, admission, realization, fence, certification or
> reserve-provenance rule may take a `SofiReceipt`, its address, its presence or its publication
> state as input.

### 6.5 Registry §3 rows (NOT applied)

```text
| 0x0034 | SofiReceipt (Def 14.2 Receipt) | 1 | ρ_B = H_dom(DSM/sofi-receipt/v1, CCB) | §5.42 defined by 2c-F |
| 0x000C | ~~RouteSet~~                   | — | —  | BURNED by 2c-F R1 (schemas 1 and 2; schema 2 never encoded) |
| 0x0017 | ~~RouteCommitmentBody~~        | — | —  | BURNED by 2c-F R1 (schemas 1 and 2; schema 2 never encoded) |
```

### 6.6 Registry §5.42 `SofiReceipt`, class `0x0034`, schema 1 (NOT applied)

`ρ_B = H_dom(DSM/sofi-receipt/v1, CCB(SofiReceipt))`; the storage address is
`immutable_addr(DSM/sofi-receipt/v1, CCB)` per §2.11. At beta cardinality it is **137 bytes**:
4 envelope + 3×32 + 4 count + 33 entry.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `bundle` (`b`) | `digest32` | `H_dom(DSM/settlement-bundle, CCB(B))`; `B` must be Market shape |
| 2 | `route_commitment` (`X`) | `digest32` | must equal `B.market_terms.route_set_commitment` |
| 3 | `trader_acceptance` (`a_B`) | `digest32` | `H_dom(DSM/trader-settlement-acceptance/v2, CCB(TA_B))`: the **inner identity**, never the storage address |
| 4 | `transitions` | set of inline `enc(entry)` | `enc(entry) = successor_hash: digest32 ‖ witness_hash: optional digest32` (§2.3); one entry per `T_v`; §2.4 order; count `== |B.transitions|` |

- **Deliberately not fields.** No `vault_id` or parent `c_n`: `V_{n+1}` commits both. No
  `economic_operation_id`: bound through `a_B` (`TA_B` field 3 → `0x0032` field 2), and 2c-D D3's
  three-way equality is the check. No `settlement_receipt_id`: a different family. No `storage_set_id`
  or `q`: `V_{n+1}` fields 14–15. No signature, so §2.9 applies vacuously. No timestamp, sequence
  or node order (Req 14.3).
- **Validity, as rejections.** A wrong class or schema. A count of 0, or a count `≠ |B.transitions|`.
  A `witness_hash` marker `0x01`. Misordered or duplicate entries. Trailing bytes. Any field `≠` its
  re-derivation from `(B, TA_B)`. `B` not Market shape. `TA_B` not certifying `b`.
- **Decode.** The strict decoder refuses all of the above, then requires canonical re-encode
  equality. §2.11 re-hash comes **before** any field is read.

### 6.7 Registry §2.10: second named foreign grammar (NOT applied)

> **`RC*` — the RouteCommitV1 commitment form.** The proto3 binary encoding of `RouteCommitV1`
> (`proto/dsm_app.proto`, version 2) with `initiator_signature` empty. Fields are emitted in
> ascending field number; implicit-presence scalars equal to their default are omitted; `hops` are
> emitted in carried order with each `RouteCommitHopV1` encoded likewise; no unknown fields are
> emitted. It is computed over the re-encoding of the decoded message. It is the preimage of `X`
> and of the initiator signature, and it is never a CCB blob.

### 6.8 2c-A Ruling 2 (annotation)

> *Amended by 2c-F R1.* `Q` is `RC`, carried in `B`. The receipt/evidence set's proof that the
> executed route came from the committed choice is the `B`-internal chain: RC signature and hop
> (provenance step 7), `X` recomputation, CORR.2, and Tier-1 SAT over `MarketTerms.intent`,
> `MarketTerms.selected_route` and RC. No separate `Q` object is published.

---

## 7. Implementation

### 7.1 What the adopting change implements

| Ruling | Where | What |
|---|---|---|
| R2 | `dsm/src/common/domain_tags/dsm/core.rs` | `TAG_DSM_SOFI_RECEIPT_V1 = "DSM/sofi-receipt/v1"`, registered, so the uniqueness and prefix-freedom checks cover it |
| R1, R4 | `dsm/src/ccb/mod.rs` | class `0x0034` allocated; `0x000C` and `0x0017` moved from `declared_unencoded` to `burned_class` |
| R3, R4, R7 | `dsm/src/dlv/sofi_receipt.rs` | `SofiReceipt::project(B, a_B)`, a strict decoder, and `verify`, which re-derives and compares field by field. There is no `P_v` refusal *(ruled)*. Nothing returned can serve as authority |
| R1, R4 | `dsm/tests/settlement_bundle_conformance.rs`, `dsm/tests/route_commitment_x_conformance.rs` | class-1 vectors: the 137-byte receipt of the pinned market bundle, and `RC*` → `X` from hand-written protobuf bytes |
| R6 | `dsm_sdk/src/sdk/vault_state_composition.rs` | a certified market fold carries the exact `TA_B` §7 accepted, so the receipt is built from what certified |
| R5, R6 | `dsm_sdk/src/sdk/sofi_receipt_publication.rs`, `handlers/dlv_routes.rs` | `complete_settlement` projects the closure from the certified fold and freezes it for the composed `V_n`'s set, before the release and never gating it; the generic sweep publishes it. `publication()` reports `BoundToAnotherSet` rather than counting another set's quorum |
| R6, merge condition | `sofi_receipt_publication.rs` (`recover_owed_receipts`), `trader_parent_fence.rs` (`list_released_fences`), `frozen_publication_artifact.rs`, `storage_routes.rs` | a lost obligation is rediscovered from the released fence and rebuilt byte-identically after a restart, from `storage.sync`, beside D-f (§7.3). The three-row freeze is atomic, so a receipt row always means all three are recorded |
| R6 | `lean4/DSMSofiReceipt.lean` (19th module) | the fence follows C2's rule alone, whether or not the freeze succeeds; a receipt exists only after certification; once released, recovery records a lost obligation; the sweep alone finishes it; idempotence |
| — | spec, registry, 2c-D | §6 applied: Def 14.2, Req 14.6–14.10, §7.2, §9.3, §16.2; registry §2.10 exception 2, §3, §4, §5.12–§5.14, §5.20, §5.42, §6a F3; I-1, I-2 and I-3 corrected |

**Mutation controls — executed.** Each removes or weakens one property. A **named** test then goes
red by performing the forbidden action. Each source was restored from a byte copy and checked with
`cmp`.

| # | Mutation | Named test red |
|---|---|---|
| MS1 | the release waits for the receipt closure at quorum | `the_def_14_2_receipt_never_gates_the_release_and_publishes_after_it` |
| MS2 | the closure is frozen for a set the vault does not commit | `a_realized_settlement_publishes_its_def_14_2_receipt_on_the_vaults_set` |
| MS3 | the receipt binds an `a_B` other than the certified acceptance's | the same, at `verify`; and `a_closure_is_a_pure_projection_of_its_inputs` |
| L1 | Lean: the release also waits for the receipt | `the_release_does_not_wait_for_the_receipt` proved **false**, and both never-gate theorems fail |
| L2 | Lean: the obligation is created without certification | `an_uncertified_settlement_has_no_receipt` proved **false** |
| L3 | Lean: the recovery pass removed | `a_lost_obligation_is_rebuilt_after_release` proved **false**, and `the_obligation_is_never_lost` fails |
| MR1 | the rediscovery hook removed (the pass returns 0) | `a_receipt_whose_freeze_failed_is_recovered_after_release_and_restart`: "exactly the one lost obligation is rebuilt" |
| MR2 | recovery no longer requires the acceptance to accept exactly `b` | `a_recovered_receipt_cannot_be_rebuilt_from_substituted_facts`, at the substituted-locator case |
| MR3 | recovery no longer requires the fence's set to be the one `B` commits | the same test, at the other-storage-set case |
| MR4 | recovery no longer requires `B` to sit at the fence's `addr(B)` | the same test, at the other-bundle-address case |

That the receipt is built only from a certified fold is also **structural**. The acceptance it binds
exists only on a certified market fold (`FoldedParent::certified_acceptance`), so there is nothing
to build it from otherwise. `an_uncertified_settlement_cannot_be_resumed_into_a_release` asserts that
no receipt row exists.

**Settlements completed before this change** carry no receipt. Beta is a clean cut, so nothing is
backfilled.

**Owed, not done here:** per-set frozen rows (I-5). They matter only when a vault's committed set
differs from the network set `TA_B` was admitted under. That cannot happen in beta, and outside
beta it is reported, never counted.

### 7.3 The merge condition on #859 — a lost obligation is never lost

The owner's condition: *"Once a settlement has certified, failure to construct/freeze/publish the
Def 14.2 receipt may delay evidence availability, but may never permanently lose the publication
obligation."* It was put as one question, answered here from source before any code changed.

> *After certification succeeds and the receipt write fails, the fence releases and the process
> crashes: what durable object lets the next process discover that this settlement still owes a
> SofiReceipt publication?*

**The durable facts already existed. Nothing read them for this purpose.**

| Fact that survives the crash | Why it is authoritative enough |
|---|---|
| A `trader_parent_fence` row on this device's own market chain, keyed `(chain, trader parent, tx_id = b)`, in state `released` | `Released` is reachable only from `CommittedAwaitingAcceptance` through `SuccessorAccepted` carrying the exact permitted successor (`dsm::dlv::trader_fence::next_state`). The one production caller is `complete_settlement`'s release step, reached only after `may_certify()` for exactly `b`. Rows are never deleted. It carries `value_addr = addr(B)` and `storage_set_id`, the bind set resolved from the composed `V_n`'s committed set. |
| `CCB(B)` at quorum on that set | pre-bind durability (FB-4); fetched by `b` and re-hashed |
| This device's `TA_B` bytes and its locator for `b` | frozen as local rows in the ADMIT transaction, before completion runs |

Before this change, `resume_settlement_completions` listed only `committed_awaiting_acceptance`
fences, `resume_settlement_completion` stopped at `AlreadyReleased`, and the sweep replayed only rows
already frozen. **A failed freeze followed by a release and a crash lost the obligation.**

**The mechanism.** `recover_owed_receipts` runs from `storage.sync`, beside D-f. It takes every
`released` fence on the device's own market chain whose receipt row, looked up by purpose and
`bound_root = b`, is absent. For each, it rebuilds the closure from the durable facts alone, with
every input checked against the others:

```text
B      fetched by b, re-hashed, and at the fence's addr(B)
S_v    the fence's set, and equal to the set B's successor commits
TA_B   this device's own locator for b -> its own frozen bytes at ta_B,
       re-hashed, and accepting exactly b
```

It never composes, walks, binds, advances, admits or touches a fence. The freeze of the three rows
is **atomic**, via a savepoint, so a receipt row is a sound marker that all three are recorded. No
signing authority is needed.

**Tests (the owner's list).**

| | Where it is shown |
|---|---|
| A–C | `a_receipt_whose_freeze_failed_is_recovered_after_release_and_restart`: certification succeeds, the injected freeze failure is consumed by the completion, and the fence is `Released` with no receipt row |
| D | a second router over the same database (`economic_fixtures::restart_router`) runs the pass |
| E | the pass rebuilds the one lost obligation. It cannot re-certify: the recovery module has no path into composition |
| F | the recovered receipt row equals, byte for byte, the closure the certified fold projects |
| G | after the sweep, `{SofiReceipt, B, TA_B}` are published on the composed `V_n`'s set |
| H | a second pass finds the row and sends nothing |
| I | `a_recovered_receipt_cannot_be_rebuilt_from_substituted_facts`: a fence naming another `addr(B)`, another storage set, or a locator naming an acceptance of another bundle is refused, and nothing is frozen |
| J | fence, composed frontier, trader head and binding log are identical before and after |
| atomicity | `a_closure_that_fails_part_way_freezes_nothing` |

### 7.2 The plan as drafted (superseded where §7.1 differs)

**Core (`dsm`).**
1. `TAG_DSM_SOFI_RECEIPT_V1 = "DSM/sofi-receipt/v1"`, covered by
   `common/domain_tags/mod.rs::all_tags_are_unique`.
2. `ccb` class `0x0034` `SofiReceipt`: encoder, strict decoder, and an independent conformance
   parser. Update `tests/settlement_bundle_conformance.rs::every_registry_number_is_in_exactly_one_namespace_set`.
   R1: move `0x000C` and `0x0017` from `declared_unencoded` to `burned_class`.
3. `dlv::sofi_receipt::derive(B, TA_B) -> Result<SofiReceipt, Refusal>`, sans-IO. It refuses a
   non-Market shape and `P_v` present. `verify(receipt_bytes, B, TA_B)` does re-derivation and
   equality only, and returns nothing a predicate can consume (R7).
4. Class-1 conformance vectors, with expected bytes produced without the production encoder: one
   for `SofiReceipt`, and one for `RC*` → `X` (R1).

**SDK (`dsm_sdk`).**
5. `complete_settlement`, after C2's existing steps, which stay unchanged: derive from the
   certified fold, then freeze `P(ρ_B)` for `S_v`. This includes `TA_B` for `S_v` under L-1, which
   needs the I-5 per-set freeze. Then sweep. The same logic runs in `resume_settlement_completion`
   and `resume_settlement_completions` (the D-f pass and its sync hook).
6. A decision owed at implementation, which does not affect settlement: backfill receipts for
   settlements completed before the adopting change (each has a frozen V1 row naming `(vault, X)`),
   or leave them receipt-less.

**Tests and mutation controls.** Each control is a named test that goes red by performing the
forbidden action; each gate is restored from a byte copy.
7. A receipt constructed before certification → refused. Receipt publication state wired into
   release or the walk → red (R7). Wrong `a_B`, wrong `X`, wrong successor, `witness_hash` present,
   extra entry → refused. Identical bytes re-published → no-op. Recovery after a crash at each of
   the three freeze points → the same `ρ_B`. A second, differently-positioned `TA_B` for the same
   `b` → refused (this verifies the uniqueness premise of R6, which rests on Def 14.1 pinning
   `R_T^+` to `C_T^+`).

**Formal.**
8. A new Lean module, `DSMSettlementReceipt`: the receipt is a function of `(B, TA_B)`, publication
   never changes certification or the fence, and publication is idempotent. It needs the mutation
   controls above. The CI module pin moves by one.

**Docs.**
9. Apply §6 to the spec and registry. Correct I-1, I-2 and I-3.

**Still owed after all of the above, and not unlocked here:** owner catch-up (Req 4.5/6.31);
`TradeDigest` `0x0012`; and a `P_v` identity (which W-A defers to schema 2).
