# Amendment 2c-E — `TradeIntent` under the exact-output market model

> **Status.** FROZEN 2026-09-09 by owner ruling. This is 5c-2 Step 1's fourth document — *"the
> canonical `TradeIntent` commitment `I` and what 'the route satisfies `I`' means to a verifier"* —
> the one item of that step that never landed. It sits in the 2c series because it amends `0x000B`,
> a class the 2c settlement and evidence profile froze.
>
> **It is a prerequisite, not a follow-up.** The owner's ruling is explicit: *"Do not write the
> producer against the stale nine-field `TradeIntent` and repair the specification afterward."*
> No part of the 5c-2 market producer may be written until this amendment and its transcriptions
> land.

---

## §1 — The mismatch, and how it surfaced

The 5c-2 market producer must emit a canonical `SettlementBundle`. `MarketTerms` field 1 is a nested
`0x000B TradeIntent`, carried complete, from which `I = H_dom(DSM/intent, CCB(field 1))` is
**derived, never carried**. `TradeIntent` schema 1 has nine members:

```text
token_in  amount_in  token_out  min_out  max_fee  max_hops  max_fanout  k  nonce
```

`RouteCommitV1` — the only artifact the trader signs before settlement — is pinned at **version 2**
and carries: `nonce`, `input_token`, `output_token`, `input_amount_u128`,
`expected_final_output_amount_u128`, `total_fee_bps` (a **rate**, not base units), `hops`,
`initiator_public_key`, `initiator_signature`.

**Four of the nine members have no source.** `min_out`, `max_fee`, `max_fanout` and `k` are nowhere
on the wire, and their absence is deliberate, not an oversight. The schema's own banner records the
cut:

> Version 1 carried a pre-signed multi-route fallback (`fallbacks`) and slippage floors
> (`floor_final_output_amount_u128`, per-hop `min_output_amount_u128`) — a second settlement model
> where a trade could execute against a changed state as long as it stayed above a floor. That is
> removed: **one route, one anchored state, one exact output, one signature.**

Fields 11 and 12 are `reserved`. A fifth member, `max_hops`, is *apparently* derivable as the signed
hop count — but only by inverting the authority direction the registry states: `max_hops` is
*"authoritative in `TradeIntent` `0x000B` field 6; `Route` validity checks `len(legs) ≤ max_hops`"*.
Deriving a bound from the thing it bounds is not a derivation.

So the producer cannot construct a faithful schema-1 `TradeIntent`. Inventing the absent members
would hash invented values into `I`, a canonical commitment no verifier could re-derive.

**This was already known and left as prose.** Amendment 2c records it: *"§5 correctly says `I != X`
but leaves 'the selected route satisfies that exact `I`' as prose."* It is still prose. That
sentence is what this amendment replaces.

**There is no production producer of `TradeIntent` or of `ccb::settlement::MarketTerms` anywhere in
the tree.** Every construction is a fixture or the decoder. Nothing is being broken here; something
that was never constructible is being made constructible. (Note for implementers:
`dlv::successor_validity` declares a *different, unrelated* four-field `MarketTerms`. They are not
the same type.)

---

## §2 — Reconciliation: what the trader genuinely possesses and signs

The ruling requires the field table be reconciled against the actual producer inputs rather than
chosen. The trader signs the canonical `RouteCommit` bytes with `initiator_signature` zeroed, and
the same canonical bytes are the preimage of `X = H(DSM/ext ‖ canonical(RouteCommit))` — sign and
commit once. Everything inside that signature is a genuine trader commitment; nothing outside it is.

```text
SIGNED BY THE TRADER, USABLE AS INTENT
    nonce                              replay binding
    input_token                        the input policy commit
    output_token                       the output policy commit
    input_amount_u128                  exact input
    expected_final_output_amount_u128  the exact output the trader accepted
    total_fee_bps                      the fee rate the trader accepted
    hops[]                             the one route
    initiator_public_key               who committed

NOT PRESENT ANYWHERE, AND DELIBERATELY SO
    min_out  max_fee  max_fanout  k
```

Both amount fields are 16 bytes on the wire and `u64` in CCB. The narrowing is **checked** in the
shipping verifier and a value exceeding `u64` is a refusal, never a truncation. Schema 2 keeps `u64`
and inherits that refusal; it does not widen the class to accommodate a value the market model
cannot price.

---

## §3 — Owner ruling (2026-09-09)

> The frozen `TradeIntent` shape is stale relative to the shipped exact-output market model and MUST
> be amended before the 5c-2 producer is implemented. The trader intent MUST commit only to values
> the trader actually possesses and signs before settlement construction.
>
> Do NOT invent `min_out`, `max_fee`, `max_fanout` or `k_v`; do NOT derive those fields from the
> already-selected route merely to populate the old shape; do NOT restore them to `RouteCommit`
> simply to preserve an obsolete schema. That would either make `I` unverifiable or turn the intent
> predicate into a self-attestation of the selected route.
>
> `k_v` is not to be invented as trader intent material merely because binding later derives or uses
> it.
>
> The selected route must still be checked against `I` using **independent facts**. Do not define an
> intent field as a function of the selected route and then claim that the route satisfies the
> resulting intent.
>
> Because this changes a previously frozen canonical class, treat it as a normative amendment:
> amend the registry and amendment text first; update the exact CCB field table; update the formal
> predicate that consumes `TradeIntent`; regenerate the affected MARKET class-1 vector **exactly
> once** from the genuine 5c-2 producer; run mutation controls proving a changed signed intent
> changes `I` and that route correspondence actually rejects disagreement.

---

## §4 — `TradeIntent`, class `0x000B`, **schema 2**

`TradeIntent = {token_in, amount_in, token_out, exact_out, fee_bps, nonce}`. No expiry, timestamp or
duration is permitted, unchanged from schema 1 and for the same reason.

| # | Field | Type | Source, and why it is genuine |
|---|---|---|---|
| 1 | `token_in` | `digest32` | the input policy commit the trader signed. A ticker is not an identity |
| 2 | `amount_in` | `u64` | exact input, base units; checked narrowing from the signed 16-byte value |
| 3 | `token_out` | `digest32` | the output policy commit the trader signed |
| 4 | `exact_out` | `u64` | the exact output the trader signed and accepted. NOT a floor |
| 5 | `fee_bps` | `u32` | the fee **rate** the trader signed. Base units are not carried: the fee in base units is a function of the amount and the rate, and restating it would create a field that can disagree with its own inputs |
| 6 | `nonce` | `digest32` | the trader's replay binding, signed |

No field 7. Adding one, or adding any time-like field, is forbidden by the same rules that forbade it
for schema 1.

**Schema 1 is BURNED.** Recorded so the number is never re-assigned; no production path decodes,
accepts, emits or falls back to it. This is a clean cut, not a coexistence plan.

---

## §5 — What each dropped member's job becomes

Dropping a member is only sound if the property it protected is still protected. Each is accounted
for, and none of the replacements lives inside `I`.

| dropped | what it protected | what protects it now |
|---|---|---|
| `min_out` | the trade cannot execute below a floor | there is no floor. `exact_out` is exact, and the re-simulation against the authenticated `V_n` must reproduce it exactly or the settle is refused |
| `max_fee` | the fee cannot exceed a cap | `fee_bps` is the exact signed rate, and the vault's own `Φ` in `V_n` is the authority the settle is checked against. A cap over an exact value is dead weight |
| `max_hops` | `Route` validity bounds the leg count | `Route` validity now requires the legs to **correspond exactly to the signed `RouteCommit` hops** — a stronger check against a signed fact, and one that does not read the bound out of the intent it bounds |
| `max_fanout` | bounds DLVs inside one same-pair allocation leg | beta emits one, and the bound had no wire source. If a later release needs it, it belongs where the topology is signed, not in the trader's intent |
| `k` | bounds alternative routes retained in `R` | `R` (`0x000C`) is `declared_unencoded` and beta retains no alternatives. Per the ruling, `k_v` is **not** trader intent material merely because binding later uses it |

---

## §6 — "The selected route satisfies `I`", stated normatively

This replaces the prose amendment 2c flagged. A verifier holding `B` establishes satisfaction with
facts it derives itself; it never accepts the route's own account of the trade.

```text
SAT.1  The bundle's MarketTerms field 1 decodes as 0x000B schema 2, and I is recomputed
       as H_dom(DSM/intent, CCB(field 1)) from those exact bytes. I is never carried.
SAT.2  The trader's signature over the canonical RouteCommit verifies under the proven
       authority key, so every operand below is a signed trader commitment.
SAT.3  token_in, token_out, amount_in, exact_out and fee_bps equal the corresponding
       signed RouteCommit values, under the same checked narrowing. Any mismatch is a
       refusal, never a repair.
SAT.4  The selected Route's legs correspond exactly to the signed RouteCommit hops.
SAT.5  Re-simulating the market policy against the AUTHENTICATED V_n that `c_n` names
       reproduces exact_out EXACTLY, at fee rate Φ(V_n). This is the independent fact:
       it is derived from authenticated state, never read from the route or the intent.
SAT.6  fee_bps equals Φ(V_n)'s rate. The vault's fee is the authority; the signed rate
       is the trader's acknowledgement of it, and the two must agree.
```

**SAT.5 is what makes the predicate non-tautological.** `exact_out` is a signed trader commitment;
the value it is checked against comes from the authenticated vault state. If instead `exact_out` were
computed from the selected route and then compared to that route, the check would prove nothing —
the failure mode the ruling names.

---

## §7 — The transitive schema cascade

§2.8 makes changed semantics a new schema version, and §2.7 nests by complete CCB including class and
schema, so the cut propagates upward mechanically rather than by judgement:

```text
0x000B TradeIntent  1→2 ───► 0x0033 MarketTerms       1→2   (field 1)
                              └───► 0x000E SettlementBundle 1→2   (the market arm)
```

Consequences, all mechanical: `b = H_dom(DSM/settlement-bundle, CCB(B))` changes for every market
bundle, and so does `addr = H_dom(DSM/storage-object, N ‖ b)`. **The owner-close arm is unaffected in
substance but shares the enclosing class**, so a close bundle's bytes move with the `0x000E` bump
even though nothing in the close changed. Schemas `0x0033` 1 and `0x000E` 1 are burned by the same
cut.

---

## §8 — What the adopting change owes

1. **Registry transcription.** §5.5 replaced with the schema-2 table; `0x000B` schema 1 added to the
   burned-schema list; the `0x0033` and `0x000E` bumps and their burns recorded; the §2.8
   propagation block extended with the cascade in §7; the `max_hops` row of the cross-object table
   retargeted to the `Route`/`RouteCommit` correspondence of §5.
2. **The CCB field table in code** — encoder, strict decoder and the schema constants — cut to
   schema 2, with schema-1 bytes refused as **burned** rather than merely unknown.
3. **The formal predicate that consumes `TradeIntent`.** *(Corrected: there was none to update.)*
   No Lean module and no TLA+ specification referenced `TradeIntent` or any of the four retired
   members — the search returns zero hits across `lean4/` and `tla/`. So the obligation is to
   AUTHOR the predicate, not to reconcile one, and "remove every formal dependency on the retired
   members" is discharged vacuously and recorded as such rather than silently skipped. Landed as
   `lean4/DSMTradeIntentCorrespondence.lean`, the fifteenth module, machine-checking `SAT.1`-`SAT.6`
   with the market policy as a parameter so the model fixes no pricing rule. Its load-bearing
   result is `the_tautological_form_accepts_the_forgery`: SAT.5 compared against the route's own
   claim accepts a trade the authenticated-state comparison refuses, so the forbidden shape is
   provably a different predicate rather than a stylistic preference.
4. **The MARKET class-1 vector.** *(Corrected 2026-09-09 by owner ruling — the original wording was
   self-contradictory and is preserved at the end of this item.)* Two different acts are involved
   and only one of them is the one-time act:

   ```text
   A. schema changes              -> canonical bytes / digest / address may move
   B. fake operands -> genuine    -> happens EXACTLY ONCE
      producer operands
   ```

   **"Exactly once, from the genuine producer" governs B — making the MARKET operands genuine.** It
   does NOT prohibit regenerating `MARKET_B` / `MARKET_ADDR` / `MARKET_LEN` when an independent
   canonical envelope or schema cut necessarily changes their bytes. Therefore:

   1. The schema-2 encoder and decoder cut **may land independently**.
   2. Any class-1 vector constant whose canonical bytes necessarily change because the envelope
      itself changed MUST be regenerated **immediately and remain asserted**. Market byte assertions
      are never deleted or disabled, not even briefly.
   3. That schema-driven regeneration does **not** consume the one-time genuine-producer
      regeneration.
   4. When the real 5c-2 producer lands, the fabricated MARKET operands are replaced **exactly
      once** by genuine producer output.
   5. The affected market vector constants are then regenerated from that genuine output and frozen.
   6. After the genuine-producer cutover, **no further operand regeneration is permitted** absent
      another explicit normative protocol change.

   Explicitly forbidden: combining the entire encoder cut, producer, economic-admission path and
   vector replacement into one giant change merely to preserve the mistaken sentence; removing
   market byte assertions temporarily; and pretending a schema-number change leaves the canonical
   vector identity unchanged.

   > **Original wording, preserved.** *"The MARKET class-1 vector regenerated EXACTLY ONCE, from the
   > genuine 5c-2 producer, never from a hand-built stand-in. It must not be regenerated before that
   > producer exists."* Its last sentence contradicted item 2: the CCB envelope encodes class then
   > schema, so the schema-2 cut necessarily moves `MARKET_B`, `MARKET_ADDR` and `MARKET_LEN`, and
   > `CLOSE_B` / `CLOSE_ADDR` with them. Item 2 therefore forced item 4, and the rule as written
   > could only have been honoured by never touching the encoding in between — which the cut it sits
   > beside does. Found by starting the implementation, which is the check the document itself
   > should have run.
5. **Mutation controls, executed and reported by the named failing test:** a changed signed intent
   changes `I`; route correspondence rejects a route that disagrees with the intent; and SAT.5
   rejects an `exact_out` the authenticated `V_n` does not reproduce.

---

## §9 — Scope

**In:** `0x000B`'s field table and schema, the satisfaction predicate, and the transitive bumps §7
forces.

**Out, and deliberately:** `TA_B` `0x0011` and the bundle-acceptance leaf remain **2c-D's**. Market
realization, fence release and receipt publication remain unreachable until 2c-D (2c-C4 Ruling V3),
and nothing here changes that. This amendment does not lift the market emission refusal; it removes
the reason the producer that lifts it could not be written.

`RouteCommit` is **not** amended. Its exact-output model is the thing being conformed to, not the
thing being changed.

---

## §10 — Verification

The adopting change is complete when: the registry transcribes §4, §5 and §7; the encoder and
decoder emit and refuse schema 2 with schema 1 burned; the formal predicate names the schema-2
object; the class-1 market vector is regenerated once from the real producer; and the three mutation
controls in §8.5 each turn a **named** test red by performing the forbidden action, and are restored.

**Closure status (2026-09-09).** Normative content FROZEN. Adopting change IN PROGRESS:

```text
§8.1  registry transcription            DONE
§8.2  encoder / decoder cut to schema 2 DONE — landed alone, per §8.4 as corrected
§8.3  formal predicate                  DONE — authored, not updated; nothing referenced it
§8.4  genuine-operand regeneration      owed, and lands WITH the producer, not before
§8.5  mutation controls                 owed
```

The 5c-2 market producer is no longer blocked by this amendment: §8.1-§8.3 are complete. The market emission refusal is untouched
by any of this and stays fail-closed until the producer exists.
