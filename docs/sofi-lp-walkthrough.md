# SoFi LP Walkthrough — Alice's Journey

A side-by-side narrative for liquidity providers transitioning from
pool-AMM mental models (Uniswap, Curve, Balancer) to DSM's sovereign-
vault model. Companion to the two-device playbook; this one is about
*concepts*, not click-paths.

---

## Why this doc

The technical specs cover deterministic limbo vaults, constant-product
fulfillment, route commits, and external commitments. None of that
explains how Alice's *experience* as a liquidity provider differs from
what she's used to. The mechanics are well-defined; the narrative isn't.
This fills that gap.

---

## The traditional path (Alice on Uniswap)

What Alice does today:

1. Approves the ERC-20 contract to spend her tokens.
2. Calls `addLiquidity(tokenA, tokenB, amountA, amountB)`. Funds move
   into the pool contract.
3. Receives an LP token representing her pro-rata share of the pool.
4. Other traders swap against the pool. Fees accrue to the pool itself,
   diluting into the LP-token redemption value.
5. To exit, Alice burns the LP token and receives back her share of the
   reserves at withdraw-time prices (i.e., possibly with impermanent loss).

What this means structurally:

- **Custody transfers to the contract.** From the moment she calls
  `addLiquidity`, the contract is the legal owner of her tokens. If the
  contract has a bug, her funds are gone. If governance upgrades the
  contract, her funds may behave differently.
- **One global price per pair.** The pool's reserves *are* the price.
  Anyone trading anywhere on that DEX hits the same curve.
- **Fee structure is set by the protocol.** Uniswap v3 hard-codes 100,
  500, 3000, and 10000 bps tiers. Alice cannot create a 17-bp pool.
- **Pro-rata anonymous share.** Anyone with the LP token has the share.
  Possession is the right.

---

## The DSM path (Alice on a sovereign vault)

What Alice does:

1. Wallet bootstrap derives her SPHINCS+ signing key and Kyber pk from
   DBRW. No external KYC, no contract approval — the keys are a property
   of the device.
2. Opens **AMM VAULT (DEV)** in the wallet. Fills in `token_a`,
   `token_b`, `reserve_a`, `reserve_b`, `fee_bps`, `policy_anchor`.
   Taps **Create AMM vault**. The wallet builds a `DlvSpecV1` with an
   `AmmConstantProduct` fulfillment, signs it with her SPHINCS+ key, and
   the vault id is committed locally.
3. Taps **Publish routing ad**. The advertisement is encrypted and
   stored on the storage node under the canonical pair keyspace.
   Discoverable, but the storage node sees an opaque blob — never the
   reserves themselves except through the published commitment.
4. Other traders quote against her vault, sign route commits, settle
   trades. Each settled trade advances reserves *inside her vault* and
   re-publishes the ad with a bumped `state_number` so the next
   trader's quote sees fresh state.
5. To exit, Alice unlocks the vault under her policy. The fee that
   accrued is already in `reserve_a` and `reserve_b` — there's no
   "claim my fees" step because there's nothing for the protocol to
   skim.

What this means structurally:

- **Custody never transfers.** The vault's funds are encumbered by the
  unlock predicate (the vault won't release them except under the
  policy's conditions), but they aren't owned by a contract or pool.
  Alice's SPHINCS+ key is the gating authority. Lose the key, lose the
  vault — same as any sovereign wallet.
- **Each vault is its own market.** No global price tape per pair.
  If five LPs publish DEMO_AAA/DEMO_BBB vaults at five different
  reserves, traders see five vaults during discovery. The route picks
  one. The other four are unaffected by that trade.
- **Fee structure is Alice's choice.** `fee_bps` is a free parameter
  in the vault spec, 0..9999. No protocol minimum. No protocol skim.
  100% of the fee accrues to the vault Alice owns.
- **Identity-anchored share.** No LP token. The vault's creator
  public key is in the spec. Only signatures over Alice's SPHINCS+
  key can unlock it.

---

## A trade, both sides

Bob holds 10000 DEMO_AAA. He wants DEMO_BBB. Alice has a vault.

### Bob's side

1. Open **AMM TRADE (DEV)**. Enter input token, output token, amount.
2. Tap **Quote**. The wallet runs path search over discovered routing
   ads, finds Alice's vault, computes the constant-product output.
3. Bob inspects the discovered-vaults panel. Alice's vault appears
   with reserves and fee. He confirms.
4. Tap **Execute trade**. The wallet runs the chunks #1–#7 pipeline:
   - Sync local DLVManager from routing keyspace.
   - Bind the best path into an unsigned `RouteCommitV1`.
   - Sign the route commit with Bob's SPHINCS+ key.
   - Compute the external commitment digest.
   - Publish the anchor at `defi/extcommit/{X}`.
   - Run `dlv.unlockRouted` against Alice's vault. The chunk #7 gate
     re-simulates the constant-product math against current reserves;
     if reserves haven't moved since Bob's quote, the unlock proceeds.
5. Bob's wallet shows the credit. The discovered-vaults panel
   re-renders with post-trade reserves.

### Alice's side

Nothing manual. Alice doesn't approve the trade — her vault's policy
already encoded what trades are acceptable when she created it.

What changes locally:

- The vault's reserves advance: input token went up by Bob's input,
  output token went down by the constant-product output (minus fee
  retained in the input token side).
- Republish-on-settled fires. Alice's wallet automatically re-publishes
  the routing ad with `state_number` bumped, so the next trader's quote
  reads fresh reserves.

What Alice sees on **AMM VAULT MONITOR (DEV)**: the row updates with
new reserves and `state_number=2`. The fee Bob paid is sitting in the
vault as part of `reserve_a`. No claim flow.

---

## What failure looks like from the LP side

**Stale quote (chunk #7 OutputMismatch).** Another trader settled
against Alice's vault between Bob's quote and his execute. Bob's route
commit references stale reserves; the gate rejects with
`OutputMismatch`. From Alice's side: nothing — the unlock didn't fire,
reserves are unchanged. Bob re-quotes and tries again.

**Network partition mid-trade.** Bob's anchor publish fails. From
Alice's side: nothing — the unlock predicate hasn't been satisfied.
Vault state is unchanged. Bob re-tries when connectivity returns.

**Wash-trading attempt.** A wash-trader could ping-pong against Alice's
shallow vault. The constant-product fee accrues to Alice on every
round-trip, so the wash-trader pays Alice for the privilege. The local
price moves only inside Alice's vault — there is no global tape that
external systems read, so the distortion has no leverage outside the
vault itself. (See `docs/book/15-security-model.md` for the formal
manipulation bound.)

**Encumbrance — when Tier 2 lands.** Once the per-vault state registry
+ encumbrance work ships, a vault won't accept a new claim while a
prior claim is in flight. This prevents stitched-receipt double-claim
in the multi-trader concurrency model. From Alice's side: a brief
"claim pending" period during which the next quote may show
"reserved" instead of clean reserves.

---

## Where Alice runs this

The wallet ships as Android because mobile is the dominant surface for
*casual signers* — traders who run one trade at a time. LPs are not
casual signers; they're operating an always-on liquidity service.

The DSM SDK is the same Rust crate regardless of frontend. LPs have
options:

- **Desktop wallet.** Any frontend over the same `dsm_sdk` crate.
  Manages the same vault keys, talks to the same storage nodes, runs
  the same chunks #1–#7 pipeline.
- **Headless daemon.** No UI; scripted vault creation and republish
  flow. Suitable for a Linux box or VPS sitting next to a storage node.
- **Server cluster.** Multiple vaults under one signing key,
  `dlv.listOwnedAmmVaults` query for monitoring. Higher uptime than a
  single phone.

There's no architectural reason for an LP to manage liquidity from a
phone. Mobile-first means the *trader experience* is mobile-first.
Liquidity provision is a service; LPs run it on whatever hardware
makes sense for service operations.

---

## What Alice owns at end of day

When Alice creates an AMM vault, she holds:

- The vault's SPHINCS+ signing authority (her wallet key).
- The vault's unlock predicate (encoded in `policy_anchor`).
- 100% of fee accrual (no protocol skim).
- Lifecycle control — when to publish the ad, when to unwind.

The storage node holds:

- The encrypted advertisement blob (opaque without the pair anchor).
- The published state-number commitment (so traders can detect staleness).
- Anchor digests for settled commitments (never raw state).

Nothing the storage node holds lets it sign on Alice's behalf, gate
her trades, censor her vault, or skim fees. The storage node is index-
only — exactly the same role it plays for non-SoFi DSM operations.

---

## What's coming (Tier 2)

The current implementation gives Alice a working sovereign AMM vault
with single-trader concurrency safety. Multi-trader concurrency
hardening is the next workstream:

- Per-vault state registry — Alice's vault publishes a committed
  state anchor after every accepted unlock; traders verify against it.
- SMT inclusion proofs of vault state — traders can prove their quote
  matches a specific committed state.
- Encumbrance + claim availability — pending-claim deferral prevents
  double-claim across stitched receipts.
- Route-set membership proofs — Alice publishes the set of routes
  she's willing to accept; traders prove membership.
- Intent bounds — slippage envelope (`min_out`), expiry, max-input.

None of these change Alice's UX in the typical case. They harden the
edge cases when multiple traders race against the same vault.
