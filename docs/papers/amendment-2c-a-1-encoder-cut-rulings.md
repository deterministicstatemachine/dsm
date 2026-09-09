# Amendment 2c-A.1 — The encoder cut: rulings, and the reconciliation of 2c-A after 2c-B

Governs the implementation of the canonical settlement-bundle encoding that 2c-A froze and 2c-B
completed: the first-ship encoders and decoders for `0x000E`, `0x000F`, `0x0010`, `0x0033` and the
nested classes a conformant market bundle requires, the deletion of the protobuf bundle identity,
and the wiring of `VDS.COMMON.10.a`.

Status: **RULINGS FROZEN.** 2026-09-09. Normative and encoder-free: this document authorizes an
encoder as the implementation of already-frozen field tables; it defines no field and changes no
encoding.

Prior: 2c-A (`B` and `T_v` frozen at A-stage), 2c-B (field 6 closed; the two foreign grammars),
2c-C3 / 2c-C3.1 (the predicate the operand feeds). Next: the adopting change, then 2c-C4.

---

# Why this document exists

2c-A ends with a sequencing rule: *"2c-A → 2c-B → ONLY THEN encoder work may begin."* 2c-B has
landed and the registry records the consequence — *"Encoding closure ACHIEVED for both shapes"*
(§5.19, §5.20), *"A conformant market `b` is constructible"* (§6) — but 2c-A's own text was
corrected in one place only (§5.19's owner-close note). Its status header, its §5.20 A-stage
blockquote, its §3 status block, its §6 instruction, its closure status and its final boundary
still say the market encoding is blocked and that no encoder may follow. Read literally, the
encoder PR would contradict the amendment it implements.

Two further things were established since 2c-A was written and change what the cut must do:

- **2c-C3 froze the predicate the encoder's output feeds.** `VDS.COMMON.10.a` compares canonical
  bytes: `Canon(expected) = Canon(supplied)`. Under 2c-A the supplied operand is exactly `0x000F`
  field 2 — the complete nested `0x0001` schema 4 successor — and `c_{n+1}` is *derived* from it,
  never carried beside it. Today there is no such operand on the wire; the cut creates it. C3's
  closure status reads `CLOSED EXCEPT 10.a` for that reason alone.
- **The read-only survey that preceded this document** (four readers over the amendment, the Rust
  surface, the registry and the C3 seam; every reader proved the tree clean before and after) found
  thirteen decisions the frozen texts leave open and an implementation would otherwise make
  silently. They are ruled below. Three are the owner's; the rest are defaults ruled here so the
  implementation cannot choose them.

---

# Ruling 1 — 2c-A is reconciled in place, and its sequencing rule is satisfied

2c-A's stale passages receive dated correction notes at the passage, not rewrites: the header, the
§5.20 blockquote, the §3 status block, the §6 instruction, the closure status, the "No encoder"
list and the final boundary. The registry's §6 lead-in (*"two are frozen only to A-stage"*) and §7
header (*"2c-A is written"*) are corrected the same way.

The sequencing rule is **satisfied**: 2c-B closed the mandatory recovery class, so per 2c-A's own
words encoder work may begin. This document is that authorization. 2c-A's *"No Rust. No proto. No
tests. No encoder."* described the A-stage boundary; it is not a standing prohibition.

---

# Ruling 2 — scope: both shapes, one atomic PR (owner)

> SELECT OPTION 1 — BOTH SHAPES, ONE ATOMIC PR. 2c-A is a clean canonical-identity cut, not a
> staged producer migration.
>
> 1. Both bundle shapes become canonical `CCB(0x000E)`.
> 2. Add the required nested canonical encoders / class identities for the MARKET shape, including
>    the frozen 2c-A / 2c-B structures: `MarketTerms`, `DsmSuccessorEvidence`, `TradeIntent`,
>    `Route` s2 and required nested classes — plus the already-required close structures.
> 3. Delete the prost-produced settlement-bundle identity in the same cut.
> 4. Add independent class-1 vectors for BOTH shapes. The MARKET vector is mandatory because it
>    exercises the A+B closure and gives `COMMON.10.a` its actual second operand for the market
>    path.
> 5. No production path may emit a non-conformant settlement bundle after this PR lands.
> 6. Do not create an intentional intermediate state where owner-close is on canonical CCB while
>    market is merely disabled pending another encoder PR.
>
> The larger PR is acceptable here because atomicity is the security property: after this cut,
> "settlement bundle identity" has exactly one canonical meaning for every supported beta bundle
> shape.

**Amended the same day, on a source finding.** The premise above — that both producer paths can
emit a conformant canonical bundle at this cut — is false for MARKET today. `dlv.unlockRouted`
binds first and advances the trader's DSM chain after, so at bind time there is no prepared
`C_dsm+` and no signed `DsmSuccessorEvidence` (`sign_dsm_successor_evidence` is reached only from
the economic-admission flow, after acceptance); no `TradeIntent` or `0x000D` producer exists
anywhere; and the shipped market bundle carries the vault's `c_n` as `trader_parent` and `X` as
`trader_successor`. The 5c-2 plan already sequences the fix: *"Build and bind `B` is not safe until
`I`, the trader coordinates, the recovery material, the DLV successor and the proof semantics are
all real"* — its Step 2. The owner amended the ruling:

> AMEND the prior "both shapes atomic cutover" ruling as follows. The 2c-A encoder SURFACE remains
> complete for BOTH supported shapes: OWNER CLOSE, MARKET. But producer CUTOVER is not atomic
> across both shapes because the current MARKET producer cannot construct the frozen canonical
> bundle at bind time without 5c-2 Step 2 changing the ordering. Therefore:
>
> 1. Implement canonical encoders/decoders and class-1 vectors for BOTH shapes in 2c-A.
> 2. Cut OWNER CLOSE over to canonical CCB immediately.
> 3. MARKET production MUST FAIL CLOSED after 2c-A until 5c-2 Step 2 lands.
> 4. Do not fabricate `trader_successor` / `DsmSuccessorEvidence` before they exist.
> 5. Do not preserve the prost bundle as a fallback market identity.
> 6. Do not fold 5c-2 Steps 2+3 into 2c-A merely to make the market path compile.
> 7. 5c-2 Step 2 changes the ordering so the trader successor/evidence exists before binding; at
>    that point MARKET may be cut over to the already-frozen canonical encoder surface.
> 8. `COMMON.10.a` for OWNER CLOSE can become live with 2c-A. `COMMON.10.a` for MARKET remains
>    deployment-blocked until the 5c-2 ordering prerequisite is satisfied.
>
> One canonical format for both shapes now; only the shape that can actually produce valid
> evidence is allowed to emit it now.

Consequences the adopting change carries: `dlv.unlockRouted` refuses to bind with a refusal that
names 5c-2 Step 2 — today it binds a placeholder bundle the 5c-2 plan calls unsafe to bind live, so
the intermediate state removes an unsafe path rather than disabling a safe one; the market
composition arm and the market decoder are implemented and vector-pinned against the frozen shape,
with no live producer until 5c-2; the market rig proof is re-run when 5c-2 lands.

The encoder surface the cut ships, all first ships at the schema the registry names:

```text
0x000E  SettlementBundle          schema 1     §5.19
0x000F  ConsumedDlvTransition     schema 1     §5.21
0x0010  DlvProofMaterial          schema 1     §5.22   zero fields
0x0033  MarketTerms               schema 1     §5.20
0x0031  DsmSuccessorEvidence      schema 1     §5.23   substrate (2c-B)
0x000B  TradeIntent               schema 1     §5.5
0x000D  Route                     schema 2     §5.13   schema 1 burned
0x0015  Allocation                schema 2     §5.10   schema 1 burned   nested in 0x000D
0x0016  AllocationBundle          schema 2     §5.11   schema 1 burned   nested in 0x000D
```

`0x0017 RouteCommitmentBody` (`Q`) is **not** in the bundle (2c-A ruling 2: `Q` lives in the
receipt publication set; `X = H(DSM/route-set ‖ CCB(Q))` is carried as `MarketTerms` field 2). The
cut ships its encoder only if the producer of `X` needs it to compute `X` canonically; otherwise
`X` is carried as the digest the producer already holds, and `0x0017` stays a later ship.

---

# Ruling 3 — the owner close's permitted continuation is `c_{n+1}` (owner)

> For OWNER CLOSE after the 2c-A canonical encoder cut, the fence's permitted continuation is the
> canonical commitment of the exact drained successor carried in `ConsumedDlvTransition` field 2:
>
>     c_{n+1} = H_dom(DSM/vault-state, CCB(V_{n+1}))
>
> The fence must be tied to the exact successor state the owner authorized, not to the legacy
> `x_close` / `close_slot_commitment` derivation. Therefore: remove `close_slot_commitment` as the
> authoritative permitted-continuation key; do not preserve `x_close` merely to keep the old fence
> shape alive; recovery compares against the exact canonical `c_{n+1}`; a different successor, even
> if it satisfies the same close intent, is not the permitted continuation.

`close_slot_commitment` is deleted, together with its re-export and every consumer. The close
intent's expected identity is `c_{n+1}`; the Req 6.23 fence's `permitted_successor` for a close is
`c_{n+1}`; `settlement_resume` re-derives `c_{n+1}` from the fetched bundle's field-2 bytes and
compares.

---

# Ruling 4 — identity-scoped full reprovision (owner)

> 2c-A is a clean beta identity cut with no migration, dual resolver, or compatibility path. After
> the cut, every prost-era settlement-bundle-derived identity is non-conformant and MUST NOT
> coexist with the new canonical CCB identity space.
>
> Wipe/reprovision: (1) Class-N binding-register rows whose keys/values derive from the old
> settlement-bundle identity; (2) immutable settlement-bundle objects stored under the old
> `DSM/settlement-bundle` identity/address scheme; (3) client-local persisted state that refers to
> those old identities — fence `tx_id` / `value_digest` state, stored bundle addresses, quarantine
> records keyed to the old bundle/binding identity, pending/recovery rows derived from the old
> `b`; (4) re-create beta DLVs/vault state under the new canonical identity regime rather than
> attempting migration.
>
> Do NOT: decode old prost bundles and re-encode them into new identities; maintain an old-`b` →
> new-`b` compatibility map; keep old binding rows and rely on permanent natural refusal;
> dual-resolve both identity schemes.
>
> Don't interpret "full reprovision" as wiping unrelated DSM state indiscriminately. The wipe
> scope is everything transitively keyed by or committing to the old settlement-bundle identity,
> plus the beta DLV instances that depend on it. Device identity, signing keys, unrelated
> relationships, and unrelated DSM state survive unless their canonical identity also changes in
> this cut.

The exact client-side tables in scope, by name: `trader_parent_fence`, `dlv_close_intent`,
`dlv_binding_finality_observed`, `dlv_lineage_quarantine`, `settlement_slot_claim_local`, and the
AMM vault records of every beta DLV. Fleet side: the binding register and the immutable namespace
`DSM/settlement-bundle`. The namespace string itself does not change; the objects under it are
wiped, not re-addressed. The storage node's **code** does not change — it derives an address from
opaque bytes and does nothing else with a bundle.

---

# Ruling 5 — the `0x000F` decoder refuses a `close_authorization` of any length but 49,856

2c-A types field 4 as optional `bytes` and states no length; 2c-B fixes what it signs — a
`SPHINCS_PLUS_SPX256F` signature over `CloseAuthorizationPreimageV1` — and `0x0031` field 7 already
says *"schema 1 refuses any other length"* for the same primitive. The same discipline applies:
schema 1 refuses a present field 4 whose length is not exactly 49,856. The refusal is structural
(the bundle is non-canonical), so a malformed-length bundle can never be "canonical but
unverifiable", and the owner-close fixture's 50,330 bytes is a property of the shape, not of the
fixture.

# Ruling 6 — the `0x000F` decoder refuses a present `proof_material`

Beta's only pricing family carries nothing irreducible; `0x0010` has zero fields and 2c-A says
beta always encodes it absent. A present field 3 — even the bare envelope `00 10 00 01` — is
refused by schema 1, mirroring `0x0031` field 6. Accepting it would let a producer emit bytes that
no verifier interprets, which is exactly the "proof data that proves nothing" 2c-A refuses to
invent.

# Ruling 7 — locating the transition, and the vault-identity conjunct after the cut

`0x000F` carries no vault identifier. The transition that names the vault under verification is the
one whose `parent_binding` equals the cursor's `c_n` — the verifier holds `c_n`, and it is the
resource key's own preimage. Under beta's `|{T_v}| = 1` this is a check, not a search.

```text
no transition with parent_binding == c_n      INVALID  STALE_PARENT
T_v.successor.vault_id != V_n.vault_id        INVALID  VAULT_MISMATCH      (VDS.COMMON.1.a)
```

Both are decidable from bytes in hand and keep their C3 codes. The quarantine's finality record
takes `vault_id` and `generation` from the authenticated `V_n`, never from the bundle.

# Ruling 8 — strict decoders; the whole bundle round-trips under the frozen encoder

Every class the cut ships decodes strictly: set members out of canonical order are refused,
duplicates are refused, trailing bytes are refused, an absent-optional marker other than `0x00` /
`0x01` is refused. `decode_canonical(B)` requires `encode(decode(B)) == B` over the **whole**
bundle, nested successor included, so a non-canonical `V_{n+1}` inside a bundle makes the bundle
`BUNDLE_NOT_CANONICAL` before `10.a` is reached. `10.a` itself compares the **recorded field-2 byte
span** of the fetched bundle against `Canon(expected)`; nothing re-encodes the supplied side. The
normalizing behaviour of `decode_vault_state` outside a bundle is C3's recorded debt and is not
widened here.

# Ruling 9 — in-bundle structural checks are the decoder's; `V_n`-relative facts are C3's

At decode, from the bundle alone (`BUNDLE_NOT_CANONICAL` on failure):

```text
T_v.successor.parent_state_commitment == T_v.parent_binding
market_terms present  <=>  every T_v.close_authorization absent
market_terms absent   <=>  |{T_v}| == 1 and its close_authorization present
close shape           =>   T_v.successor.reserve_a == 0 and reserve_b == 0
```

Everything that needs `V_n` — generation `+1`, storage set and quorum preserved, the field
dispositions — is derived from `10.a` by C3 ruling B and is not re-checked beside it.

# Ruling 10 — the route-family schema-1 burns enter `schema::BURNED`

The registry burns schema 1 of `0x000C`, `0x000D`, `0x0015`, `0x0016` and `0x0017`. The cut ships
schema 2 of three of them; a schema-1 envelope must classify as `BurnedSchema`, not
`UnknownSchema`. All five pairs are recorded in the same change.

# Ruling 11 — namespace enforcement closes with this cut

Every class number the registry defines gets a constant in `ccb::class`. Numbers the registry
defines but the cut does not encode are listed under a protected `declared_unencoded` set and
guarded by the same test that guards `reserved`: an encoder that reaches for one of them fails a
named test. 2c-A assigned this gap to 2c-C; it is closed here because the cut is the change that
touches the namespace.

# Ruling 12 — the verdict a market fold carries once `10.a` is evaluable

`PartialPendingEncoderCut` and `EstablishedChecks` are **deleted** — the conjunct they recorded as
blocked is no longer blocked, and C3 forbids a deployment status from surviving as a fallback. In
their place:

```text
CorrespondenceWitness              core, private fields, no public constructor:
                                   expected, parent_commitment, c_next derived from the
                                   SUPPLIED bytes; exists only because
                                   Canon(expected) == supplied span held

C3Verdict::Valid(CompleteValidity)         close path, from a CorrespondenceWitness
C3Verdict::PartialPendingRealization(CorrespondenceWitness)
                                           market path: every conjunct held INCLUDING 10.a,
                                           and the realization fact is 2c-C4's
```

`CompleteValidity` gains exactly one constructor, in core, taking a close witness. A market witness
reaches `Valid` only through a constructor that also takes an `IndependentRealization`, which has
no constructor — so `2c-A + 10.a = market valid` stays a compile error. `may_fold()` is true for
`Valid` and `PartialPendingRealization`; `may_certify()` for `Valid` only. The `compile_fail`
pins move with the types.

# Ruling 13 — the protobuf bundle is deleted

`SettlementBundleV1` and `VaultTransitionV1` leave `dsm_app.proto`; the frontend's generated file
is regenerated (no hand-written consumer exists); Android references none. Their false comments
about `successor_ccb` and `parent_reserves_digest` — C3's last open documentation debt — die with
them. `SettleTerms.parent_reserves_digest`, which has zero semantic readers, goes too.

# Ruling 14 — the producer and the verifier share one derivation

The producer builds field 2 by the frozen predicate: `derive_close_successor` for a close,
`derive_market_successor` for a market, from the composed state it is standing on. A verifier
derives the same object and compares bytes. There is no second successor construction anywhere.

---

# The `10.a` wiring point

On the `Derived(e)` arm and only there: `check_correspondence(&e, supplied_span) -> Result<
CorrespondenceWitness, Reason>` in core, sans-IO: `e.encode() == supplied_span`, else
`CORRESPONDENCE_MISMATCH`. The walk takes `c_{n+1}` from the witness (derived from the supplied
bytes; equal to the commitment of `e` by injectivity, `canonVault_injective`), never from the
local state. A mismatch refuses the fold with C3's code; the lineage seam (`verdict: None`, C4's)
is untouched.

# Sizes

Owner close: 50,330 bytes (2c-A's worked layout). Market: the `0x0031` object alone is ~150 KB, so
a market bundle is ~151 KB. Both sit under the storage node's 512 KiB ingress cap; the adopting
change pins the close vector's length in a named test and asserts the market vector's length is
under the cap.

---

# Verification obligations

- **Class-1 vectors, both shapes** (C2 ruling D): the independent encoder gains every class above;
  the owner-close vector reproduces 2c-A's worked byte layout at 50,330 bytes; the market vector
  is the A+B closure test — the first complete market byte vector, with `b` and `addr(B)` computed
  without the production helpers and `c_{n+1}` from the field-2 span without
  `vault_state_commitment`. Byte arrays, never hex.
- **Correspondence vectors**: accept (field-2 bytes equal the independent encoding of the derived
  successor); reject — one preserved field changed, an encumbrance claim added, the budget marker
  flipped, a semantically equal but non-canonical successor.
- **Mutation controls**, each red on a named test: field-1 shape check skipped; a
  `close_authorization` accepted in a market bundle; the `parent_binding == c_n` check dropped;
  `verify_close_authorization` skipped; the supplied span replaced by a producer-derived
  re-encoding; the comparison skipped.
- **Targeted tests per edited module**, then CI is the board.

# Closure status

```text
2c-A status text                    RECONCILED (this document)
Rulings 1-14                        FROZEN
Encoder surface (both shapes)       NOT IMPLEMENTED — the adopting change
Owner-close producer cutover        NOT IMPLEMENTED — the adopting change
Market producer                     FAIL-CLOSED after the cut until 5c-2 Step 2
VDS.COMMON.10.a, owner close        WIRABLE once the surface lands; C3 owner-close
                                    completion then needs nothing else
VDS.COMMON.10.a, market             DEPLOYMENT-BLOCKED on the 5c-2 ordering; then C4
```
