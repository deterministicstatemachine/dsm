# 5c-1 — Split binding occupancy from realized composition

Status: COMPLETE — C1 `89c3e5fc`, C2 `989e787c`, C3 `9461cf9f`, gitignore fix `87fda1fc`,
all on `feat/quorumbind-settle-cutover` (unmerged by design until 5c-2 + old-register excision).

> **SUPERSEDED IN PART BY AMENDMENT 2c-A — read this as a historical record, not an instruction.**
> The wire shape described throughout — `bundle_signatures`, `successor_ccb`, `reserve_deltas`,
> and `close_slot_commitment` as the close/market discriminator — is **replaced** by
> [`docs/papers/amendment-2c-a-bundle-and-transition.md`](../papers/amendment-2c-a-bundle-and-transition.md).
> Under 2c-A the bundle is `{market_terms?, transitions}`, a transition carries the complete
> nested `V_{n+1}`, and the shape discriminator is `market_terms` presence. Read this document to
> understand why the shipped code looks the way it does. **Where the two disagree, 2c-A governs.**

Paths below are relative to `dsm_client/deterministic_state_machine/` unless stated.

---

## Context

We are replacing the one-shot settlement-slot register with conformant Rev-15 QuorumBind. PRs #772–#777 landed the pieces: the Class N generic binding primitive, the sans-IO Class K engine, the trader-parent fence, the HTTP transport and restart driver, the canonical `SettlementBundle`, and the resume reconstruction. 5c is the live cutover.

Wiring the close write path revealed the real obstacle. The settlement-slot register is not only *written* by settle — it is *read* by the frontier walk that decides which vault generation is current, and by the core economic-provenance arm that decides whether a trader's swap output is a spendable credit. That read encodes a single conflated idea: **"consumed" means "composed."** With a write-once register those coincided. With QuorumBind they must not.

The governing correction (recorded in `project_binding_vs_realized_frontier`):

```
binding occupancy = which DLV parent is no longer available to a competing candidate
realized frontier = which DLV successor actually became economic state
```

Four rules this plan implements:

1. **Binding occupancy** comes from authenticated QuorumBind evidence for the exact parent resource key `k_v = H(DSM/binding-keyset ‖ c_n)`. A binding-final chosen bundle makes that parent unavailable to every competing candidate. **The old settlement-slot claim stops determining occupancy.**
2. **Local unresolved protection** is separate and client-side. If *this* Class K holds an unresolved trader-parent fence for that parent, it stays blocked locally until recovery terminates. `RECOVERING`/`INDETERMINATE` are fence states, **never** modelled as register evidence.
3. **Realized frontier** advances only when the successor actually becomes economic state. **Close:** immediately on binding Finality — its successor is pre-authorized and complete (Req 6.30). **Market:** binding-final alone never realizes.
4. **Ambiguous or unavailable evidence fails closed** for routing and composition. Uncertainty is never read as "the parent is free."

### The market decision, and its expiry date

In 5c-1 the market path binds for occupancy but **keeps its existing realization gate** — verified receipt + published RouteCommit + curve re-simulation — so successful trades keep advancing reserves while 5c-2 is unfinished. This gate is **temporary scaffolding, not architecture.** 5c-2 replaces it wholesale with the Rev-15 rule: *the exact bundled trader successor accepted under ordinary DSM plus `A_B` verified ⇒ market successor realized.* Every temporary construct introduced here must be marked so 5c-2 removes it rather than inherits it.

## What the code actually does today (verified)

**The frontier walk** is `compose_vault_state` (`dsm_sdk/src/sdk/vault_state_composition.rs:244-634`). Per generation it calls `economic_registers::observe_settlement_slot_cell` (`:277`) → four-valued `CellObservation`, then:

- `EmptyAtQuorum` → `break`; that generation is the frontier.
- `Unavailable` | `Conflict` → `BindingEvidenceUnavailable` (fail closed).
- `Claimed(bytes)` → decode/verify the claim, then classify by recomputing `close_slot_commitment`:
  - **close** → require claimant is the owner, then `next_state{gen+1, reserve_a=0, reserve_b=0}`. **No receipt, no witness** — an owner occupancy claim *is* the realized terminal state. This is the purest instance of the conflation, and it is exactly the behaviour rule 3 keeps for close.
  - **market** → require receipt + published RouteCommit (X recomputed) + routed-unlock eligibility + `hop.parent_binding == cursor_c_n` + exact constant-product re-simulation, and only then move reserves. Here the two concepts are already structurally distinct.

It returns one `ComposedVaultState { sequence, reserves_a, reserves_b, c_n, state, folded_parents, … }` that fuses both answers behind one failure mode.

**The market settle path advances no vault reserves at all.** `dlv_unlock_routed` calls `execute_on_relationship` with only the trader's two balance deltas; the "post-advance reserve update" comment at `dlv_routes.rs:3145-3153` has no code beneath it. Market reserves are re-derived *by the walk* (`:592-604`) and, for the owner's own leaves, by `dlv_reconcile`'s `ApplySettlement`.

**Provenance inverts the same value.** `dsm/src/economic/provenance.rs:1241-1300` requires `Claimed` to fund a `DlvReserveConsumption` credit; `EmptyAtQuorum` there is *Invalid/forgery* — the opposite of its meaning in the walk. It reads the cell directly, bypassing composition, via the core trait methods `PeerEvidenceFetcher::settlement_slot_observation` (`dsm/src/economic/peer_lineage.rs:82`) and `ProvenanceResolver::settlement_slot_observation` (`provenance.rs:198`), with ~10 stub impls across `dsm/tests`.

**Read and write must move together.** If the writes move to QuorumBind while the cell reads stay, every settled generation composes as `EmptyAtQuorum` and provenance rejects every settle. This is not follow-on work; it is inside 5c-1.

## Status carried in

Branch `feat/quorumbind-settle-cutover`, uncommitted, local only:

- `sdk/settlement_bind.rs` — `bind_settlement` (canon `B` → `PutImmutable` → `run_fenced`), `close_bundle`, `local_proposer_id`. 2 driver tests pass, including two bundles over one vault parent conflicting.
- `sdk/binding_fleet_double.rs` — deterministic in-process fleet with byte-for-byte parity to the node's `decide_compare_exchange`; `reset_all`, `ensure_registered`, `fail_member`, `heal_member`, `refuse_writes`, `set_echo`.
- Close **write** path rewired to `bind_settlement`; its `frozen_claim_envelope` removed. **39/41 close tests pass.**

The 2 failures are precisely the remaining coupling, and confirm the half-migrated state: `dlv_close` fences via QuorumBind and never writes the old cell, so composers see `EmptyAtQuorum` at the closed generation; and `resume_close_intents` loads a `FrozenClaimEnvelope` the live close never persists, so it abandons.

## Scope boundary

- **In 5c-1:** the binding-occupancy query; the walk split; close write + close-resume on QuorumBind; close realizing on binding Finality; the provenance arm and core trait moved to binding evidence; market bound for occupancy with its realization gate kept as marked-temporary; test migration to the binding fleet double; removal of every old settlement-slot call path 5c-1 supersedes.
- **Not in 5c-1:** the `A_B` acceptance artifact and the real market realization gate (5c-2); the `dsm_storage_node` endpoint/table excision (separate crate, after 5c-2).
- **Merge discipline:** the branch stays unmerged until 5c-2 and the old-register excision complete. No merge with both mechanisms live.

## A blocker found while designing this, and the fix

**Realizing a close on binding Finality alone is a vault-drain today.** The old walk knew why: `close_slot_commitment` is a public derivation anyone can recompute, so the `x` is a *discriminator*, never an authorization. What a stranger cannot forge is the claim on it **signed by the owner's P0–P6-proven authority key** — `claim.body.claimant_public_key != owner.ak_pk` at `vault_state_composition.rs:449`. `settlement_slot_claim.rs:172-180` says so in as many words.

Under QuorumBind that authentication has no counterpart: the register is application-blind by design (§22 #12) and never inspects the value; `BindingRecord.proposer_id` is 32 self-asserted bytes; `close_bundle` leaves `bundle_signatures` **empty** (`settlement_bind.rs:157`), and `settlement_bundle::validate` (`settlement_bundle.rs:86-108`) never reads that field — the proto defines no semantics for it either (`proto/dsm_app.proto:1764`). So any party could bind a bundle naming a victim vault at its current `c_n` with `successor_ccb = close_slot_commitment(...)`, and every composer would fold that vault to zero reserves.

**Fix — `bundle_signatures[0]` carries the owner's signature over the exact canonical `Operation::DlvClose`.** Not a new authorization over `x_close` plus coordinates: Rev-15 requires the concrete owner signature over the exact release successor, and DSM already has one. `Operation::DlvClose` (`operations.rs:750`) binds the *whole* transition — vault, both legs with their amounts, `parent_sequence`, `new_sequence`, `fee_bps` — and its doc comment states the property that makes reuse work: *every field is DERIVED by the handler from the owner's verified frontier, never supplied* (`operations.rs:747-749`). The walk stands on exactly that frontier.

So the walk **reconstructs** the operation rather than carrying it:

- Rebuild `Operation::DlvClose` from the transition and `cursor_state` — `vault_id`, both leg policy commits and amounts, `parent_sequence`, `new_sequence = parent + 1`, `fee_bps`, `mode: Unilateral` (fixed at the single construction site, `dlv_routes.rs:2540`).
- Verify `bundle_signatures[0]` over `op.with_cleared_signature().to_bytes()` under `owner.ak_pk` — the repo's existing signing preimage (`device_state.rs:3554`), via `crypto::sphincs::sphincs_verify`.
- `close_bundle` takes the owner secret key and populates `bundle_signatures[0]` with that same signature.

This needs **no new domain tag, no new message, and no second canonical form** of the close successor — the operation encoding already is one, and introducing a parallel commitment is exactly the "two statements that can disagree" failure. If the reconstruction ever ceases to be deterministic (a `mode` that can vary, a field the walk cannot derive), the bundle must carry the canonical operation bytes instead; the reconstruction must not be loosened.

**And `validate` forbids mixed bundles.** A `SettlementBundleV1` is one of exactly two shapes:

```
market bundle       : one or more market transitions, no close transition
owner-close bundle  : exactly one transition, and it is a close
```

Without this rule `bundle_signatures[0]` is inadequate for a mixed bundle — there is no deterministic signature-to-transition mapping — and rather than invent one, remove the class. Nothing in the current normative text requires atomic mixed market/close bundles, and `close_bundle` already emits the single-transition shape (`settlement_bind.rs:137-159`). Enforcing it in `settlement_bundle::validate` deletes a whole family of ambiguous authorization semantics, and it makes the close/market discriminator a **bundle-level** fact rather than a per-transition one.

The market side needs no equivalent signature: a market bundle is self-authenticating through `route_set_commitment == X → RouteCommit → initiator SPHINCS+ signature`. That asymmetry is principled and is documented at the call site. This is parity with the path being replaced, not new architecture — it must land **before** anything folds on binding evidence.

## Design

### 1. One definition of "chosen" — `dsm/src/dlv/binding_observation.rs` (new, pure)

`cell_observation::observe_cell` cannot express this: it tallies byte-identical *values*, whereas a binding key holds a `BindingRecord` with a round and a status, and "chosen" is *q members holding an `ACCEPTED` record at the same round* (`quorum_bind.rs:559-572`). A `PROMISED` record is a fifth state — neither empty nor bound — and routing records through an opaque-bytes tally would silently count a promise as a claim. The *shape* is reused verbatim: four-valued answer, tally completes before anything is selected, an error is never evidence of emptiness. `MemberRead` (`quorum_bind.rs:120`) is reused as the input type.

```rust
pub struct ChosenBinding { tx_id, value_digest, value_addr, round, holders }

pub enum BindingObservation {
    Free,                              // q attributed members explicitly hold NOTHING (≙ EmptyAtQuorum)
    BoundFinal(ChosenBinding),         // q hold one bundle's ACCEPTED record at one round
    Conflict { distinct },             // two chosen values on one key — reported, never resolved
    Undetermined { attributed, highest_round },  // THE NEW ANSWER: at least q responses are
                                       // attributable, but the evidence establishes NEITHER a
                                       // chosen value NOR a quorum of explicit absences.
                                       // Not empty, not a forgery.
    Unavailable { attributed, required },
}

pub fn tally_key(reads, key_ix, key_count) -> KeyTally;   // EXTRACTED from QuorumBind::fold_reads
pub fn observe_key(reads, key_ix, key_count, quorum) -> BindingObservation;
pub fn observe_single_key(reads, quorum) -> BindingObservation;
```

Classification order mirrors `observe_cell`: `attributed < q` → `Unavailable`; unique value at `q` → `BoundFinal`; two at `q` → `Conflict`; `absent >= q` → `Free`; else `Undetermined`.

**A sub-quorum ACCEPTED record does not by itself defeat `Free`, and must not.** `absent >= q` is decisive on its own: if a value were chosen, `q` members hold it, and any `q`-subset intersects them — so a quorum of authenticated explicit absences proves nothing is chosen, whatever a minority also holds. Treating any stray minority record as blocking would let one lagging member permanently freeze a vault. Two cases pinned as tests at `n=3, q=2`:

```
Accepted, Absent, Absent       -> Free           (absence quorum is decisive)
Accepted, Absent, Unavailable  -> Undetermined   (attributed, but neither quorum exists)
```

The minority record may still win later; that is the same "NOW" semantics `EmptyAtQuorum` already documents, and the loser of that race gets `ConflictFinal` at bind time — the register serializes, the observer does not have to.

`QuorumBind::fold_reads` (`quorum_bind.rs:530-586`) is refactored onto `tally_key` and adds only `highest_is_ours`, so the proposer and the observer cannot drift on what "chosen" means. No behaviour change.

### 2. The occupancy query — `dsm_sdk/src/sdk/binding_occupancy.rs` (new)

Two layers. The register layer answers occupancy with no bundle fetch:

```rust
pub(crate) async fn observe_parent_key(set, parent_c_n, committed_quorum) -> BindingObservation
```

`k = settlement_bundle::resource_key(parent_c_n)`, one `ReadBinding([k])` fan-out, attributed by the runner's own rule. It returns the observation, **never a `Result`** — a transport failure *is* `Unavailable`, so there is no error channel a caller could collapse into emptiness.

`resource_key` derives from `c_n` alone, and `c_n` already commits `vault_id`, `generation`, reserves, pair and authority position. So the walk's three separate coordinate checks (`vault_state_composition.rs:410`, `:418`, `:427`) collapse into "we read the right key" — they can no longer disagree. The query needs no `vault_id` or `generation` parameter at all.

Two small enabling extractions, both removing duplication rather than adding surface:
- `quorum_bind_runner::read_binding_attributed(members, keys, transport)` — the read+attribute half of `run`'s `MemberOp::Read` arm, so attribution lives in one place.
- `quorum_bind_runner::binding_transport(set)` — promote `settlement_bind::transport` (`settlement_bind.rs:83`, private) to shared. Side benefit: `settlement_resume::live` hard-codes `HttpBindingTransport`, so restart resume is currently untestable under the fleet double; this fixes that.

The resolved layer fetches the bundle and checks it against *this* parent:

```rust
pub(crate) enum ParentOccupancy { Free, BoundBy(Box<BoundParent>), Unresolvable(String) }
pub(crate) enum TransitionKind { OwnerClose, Market }
```

After `BoundFinal`: the record's two identity fields must agree (`immutable_addr_from_inner(TAG_DSM_SETTLEMENT_BUNDLE, value_digest) == value_addr`); fetch via `storage_io::fetch_immutable_payload` (which already re-hashes, `storage_io.rs:200`); then the same four identities `settlement_resume::reconstruct` checks. Then bundle ↔ this parent: `storage_set_id` equal (the port of the cross-set refusal at `:418`), `b.q == committed_quorum` (`V_n` is authoritative — require equality, never consume the bundle's value), exactly one transition naming this `vault_id`, and `t.parent_state_commitment == c_n` + `t.parent_generation == generation`. That last pair is **load-bearing**: the register is application-blind, so a proposer can bind a bundle that does not contain this `c_n` at this key.

`kind` is a **bundle-level** fact, because `validate` now forbids mixing: a bundle with exactly one transition whose `successor_ccb == close_slot_commitment(vault_id, parent_generation)` is an owner-close candidate; anything else is a market bundle. No new proto `kind` field — it would be a second statement of what `successor_ccb` already determines, and two statements can disagree.

### 3. `ComposedVaultState` — two added fields, both total functions of the walk

The newly expressible state is *"the realized frontier is `g` AND `g` is bound by an unrealized market bundle."* It must be on the struct: a caller that stamps that `c_n` as a `HopParentBinding` is guaranteed to lose at bind time.

```rust
pub(crate) enum FrontierBinding {
    Free,                                        // available to a competing candidate right now
    // Bound; this walk did not realize its successor. Carries the X the walk
    // ALREADY verified, so the settle consumer can tell "my own trade's bundle"
    // from "someone else's" without a second fetch of bytes we just read.
    BoundUnrealized { bundle_digest: [u8; 32], route_set_commitment: [u8; 32] },
    LocallyFenced { tx_id: [u8; 32] },           // CLIENT-LOCAL, never register evidence, never
                                                 // published: THIS device holds an unresolved
                                                 // transaction over this exact parent
}
pub(crate) struct ComposedVaultState { /* unchanged */ , frontier_binding: FrontierBinding }
pub(crate) struct FoldedParent    { /* unchanged */ , bound_by: [u8;32], bound_kind: TransitionKind }
```

Only three `FrontierBinding` values are reachable — `Conflict`/`Undetermined`/`Unavailable` never return a composition at all, they fail closed as `BindingEvidenceUnavailable`. One struct, not two entry points: occupancy and realization come from the same walk over the same cursor, so splitting them would double the network cost and let two answers about one vault disagree. `compose_discovered_vault` / `compose_own_vault` signatures are unchanged; both types are `pub(crate)` with a single construction site (`:620`).

### 4. Local unresolved protection

`trader_parent_fence::active_verdict(chain, parent)` is keyed on `(trader_chain_id, parent)`, and `dlv_close` passes `trader_chain_id = vault_id`, `parent = composed.c_n` (`dlv_routes.rs:2640`) — so for the owner's own close the fence is keyed exactly on the vault parent the walk stands on. Market bundles fence the *trader's* chain, so the walk cannot see those; the doc comment states that limit rather than implying generality.

- Consulted **only when the register answered `Free`** — i.e. only where the walk breaks.
- `BlocksAllSuccessors` / `PermitsOnly(_)` → `LocallyFenced { tx_id }`. Deliberately **not** a fail-closed: `dlv_reconcile` and `finish_prepared_close` legitimately compose while this device's own close is in flight, and refusing there would deadlock the recovery paths.
- A register `BoundBy` **wins over** any local verdict — strictly stronger evidence.
- `RECOVERING` / `INDETERMINATE` are never modelled as register states. They are `FenceState::Fenced` rows in local SQLite, surfaced as `LocallyFenced`, never published, never counted toward a quorum.

Enabling change: add `active_fence(...) -> Option<TraderFence>` in `client_db/trader_parent_fence.rs` (the query already loads the whole row) and make `active_verdict` a wrapper — the walk needs the `tx_id`.

### 5. The walk (`vault_state_composition.rs:350-618`)

Everything above `:350` (baseline, pair, set, `require_canonical_quorum`) is untouched. Per generation:

- `Free` → overlay the local fence, set `frontier_binding`, **break**. The only termination that establishes a frontier.
- `Unresolvable(why)` → `BindingEvidenceUnavailable` (fail closed).
- `BoundBy(b)`, `OwnerClose` → `verify_close_authorization` against `owner.ak_pk`, then fold `{gen+1, reserve_a: 0, reserve_b: 0}` and continue. Req 6.30's one-phase fold: the successor is fully determined, so there is no amount to witness and no second artifact to wait for.
- `BoundBy(b)`, `Market` → the **temporary** gate, called out in a block comment naming 5c-1 and its replacement, with a three-way outcome:
  - agrees → fold and continue;
  - **absent** → `frontier_binding = BoundUnrealized`, **break**. This is the load-bearing new distinction: today every market failure is `BindingEvidenceUnavailable` because a claimed slot with no receipt is indistinguishable from anything else. "Bound but not yet settled" becomes a fact the walk can report;
  - **contradicts** (re-sim disagrees, hop binds another parent, X does not recompute) → fail closed. A divergence is never an absence.

The temporary block keeps the existing evidence verbatim — receipt witnessing this generation step, published RouteCommit whose X recomputes from its own bytes, routed-unlock eligibility, `hop.parent_binding == cursor_c_n`, exact constant-product re-simulation — and is marked for wholesale deletion in 5c-2.

### 6. Consumers (8 sites)

| Site | Needs | Change |
|---|---|---|
| `dlv_routes.rs:336` `dlv_compose_vault` | realized | none (optionally surface `frontier_binding` in the response string) |
| `route_routes.rs:1231` route find/bind | **both** | drop the vault from candidates unless `Free` — it stamps `HopParentBinding{parent_binding: composed.c_n}`, so a bound parent manufactures an unsettleable quote. Reuse the existing `warn!` + `continue` shape |
| `route_commit_sdk.rs:466` publish pointers | occupancy | add `Free` else the **existing** `HopParentNotCurrent` — an occupied parent is precisely "not current", no new variant |
| `dlv_routes.rs:2869` market settle | **both** | accept `Free`, or `BoundUnrealized` **only** when that bundle's `route_set_commitment == X` of this settle (this trade's own bundle — the 5c-2 shape). Reject other `BoundUnrealized`, reject `LocallyFenced` |
| `dlv_routes.rs:1696` `dlv_reconcile` | realized | none — it names a historical parent, and this is the consumer that most benefits from the walk no longer failing closed at a bound frontier |
| `dlv_routes.rs:2459` `dlv_close` gate | **both** | accept `Free` or own-`LocallyFenced`; refuse `BoundUnrealized` **before** driving `bind_settlement` rather than discovering it as `ConflictFinal` after a full Paxos round-trip |
| `dlv_routes.rs:2178` `resume_close_intents` | occupancy | replace the flat `sequence != parent_sequence → abandon` with a three-way (re-drive / already-folded → straight to `finish_prepared_close` / abandon). Fixes an existing inconsistency: `finish_prepared_close` tolerates `parent+1`, this guard does not. Also drops the `FrozenClaimEnvelope::load` + `claim_settlement_slot` block |
| `dlv_routes.rs:2331` `finish_prepared_close` | occupancy | shape unchanged; assert `bound_kind == OwnerClose` and `bound_by == this intent's digest`, so a market settle folding at that generation cannot be mistaken for the resumed close |

`reserve_consumption_producer.rs:47` needs no change (realized only). Fixture constructors at `dlv_routes.rs:5027`, `:7087`, `route_routes.rs:1375` are mechanical.

### 7. The core trait and the provenance arm

Both `PeerEvidenceFetcher` (`peer_lineage.rs:82`) and `ProvenanceResolver` (`provenance.rs:198`) replace `settlement_slot_observation` with:

```rust
fn parent_binding_observation(&self, parent_state_commitment: &[u8;32],
                              storage_set: &StorageSetMembers, quorum: u32) -> BindingObservation;
```

`c_n` is the only coordinate — supplying `vault_id`/`generation` separately would admit a disagreeing triple. It returns the observation, not an `Option` or `Result`: the five answers carry five different verdicts and there is deliberately no adapter that could turn one into another. It returns the record's value identity, never bundle bytes — the verifier fetches those through `immutable_evidence` and re-hashes them itself, so the resolver supplies bytes and never verdicts.

`provenance.rs:1241` §8 (`CreditSource::DlvReserveConsumption`), sections 0–7 unchanged:

- `Conflict` → `Quarantined`; `Unavailable` → `Incomplete`; **`Undetermined` → `Incomplete`, not `Invalid`** — the arm that is easy to get backwards. An accepted value below this reader's quorum is not a forgery, and mapping it to `Invalid` would make every concurrent settle permanently invalid.
- `Free` → `Invalid` ("no binding was established for this parent") — replaces the `EmptyAtQuorum` arm with the same verdict.
- `BoundFinal` → fetch by `value_digest` through `immutable_evidence`, re-hash to both identities, require the bundle's `storage_set_id`/`q` to equal the vault's, find the transition for this vault, require `parent_state_commitment` + `parent_generation` to match, then `route_set_commitment == external_commitment_x` (replaces `claim.body.x == d.x`).
- Authorship replaces `claim.body.claimant_public_key == hop.initiator_public_key == ctx.proven_ak` with a **content chain**, which is strictly stronger than a claimant field: the bundle commits X; X is recomputed from the RouteCommit bytes in section 7; the RouteCommit carries the initiator's SPHINCS+ signature; section 1 already established the settler *is* `ctx.proven_ak`. Who pushed the bytes into the register is therefore irrelevant — a third party binding this bundle binds *this* trade.

Net: one deleted dependency on `settlement_slot_claim`, one added on `settlement_bundle`. `dlv_reserve_consumption_source_id` unchanged. `RecordingResolver`'s comment stays true for the register read, and the bundle fetch it now performs *does* flow through `immutable` — an improvement, since the q-durable closure grows to cover the bundle.

The ~10 stub impls in `dsm/tests` keep identical variant field names, so eight are one-line path renames. Two need real work, both in `economic_dlv_settle_provenance.rs`: `:516`'s three-way fixture match becomes `(bundle, coords)` and must also serve the bundle bytes from `immutable_evidence`; `:676`'s observation-injecting wrapper gains an **`Undetermined` case asserting `Incomplete`, not `Invalid`** — the one new semantic, and it deserves a pinned test.

### Other flags

- **Two quorum functions.** `quorum_bind::strict_majority` and `cell_observation::canonical_quorum` are both `n/2 + 1` on two layers and agree today. Make one call the other, or the split eventually becomes a place discretion lives.
- **Read amplification.** One `GetImmutable` per bound generation that the old walk did not need (the slot read carried the claim inline). Bounded by `MAX_PENDING_CHAIN_DEPTH = 64`; cache resolved bundles by `value_digest` within a walk, since a multi-vault bundle would otherwise be fetched once per vault.
- **`compose_own_vault` after a close.** Once a close folds, it reports `parent+1` with zero reserves, while `dlv_close`'s "already closed" guard reads `live` (leaves). The two diverge for a window — worth a test.
- **5d leftovers.** After this change `observe_settlement_slot_cell` (`economic_registers.rs:277`), `read_settlement_slot_cell` (`storage_io.rs:734`), `sdk/settlement_slot.rs` and the claim half of `settlement_slot_claim.rs` have no callers except `close_slot_commitment`, which stays as the discriminator. They are removed in 5d with the node endpoint, not here.

### Three more verified findings that change the work

- **`bind_settlement` reuses ballots on resume.** It hardcodes `base_ballot: 0` (`settlement_bind.rs:196`), while `settlement_resume::reconstruct` deliberately seeds from `fence.ballot` (`settlement_resume.rs:110`) for exactly this reason. `place_fence` is `INSERT OR IGNORE`, so the persisted ballot survives — but close-resume re-derives the same deterministic bundle and calls `bind_settlement` again, restarting from 0. Fix: seed `base_ballot` from `get_fence`.
- **There are five old-register test injections in `dlv_routes.rs`, not four.** The fifth (`:6766`/`:6775`, inside `a_trader_builds_a_reserve_consumption_bundle_the_production_verifier_accepts` at `:6581`) uses the *production* `frozen_claim_envelope` + `claim_settlement_slot` and then runs the **core** verifier — the SDK-side twin of the `dsm/tests` fixtures. It breaks the moment `provenance.rs` §8 moves.
- **`active_verdict` has zero production consumers today** — every caller is a test (`quorum_bind_runner.rs:577+`, `settlement_bind.rs:299`). The walk's `LocallyFenced` arm makes it the fence's *first* production reader. Corollary: every committed settle leaves a `committed_awaiting_acceptance` row that nothing releases, and `list_unresolved_fences` counts it unresolved. `recover_all` is `cfg(not(test))`, so it will not flake the board — a 5c-2 item, recorded, not a 5c-1 bug.

### Two naming choices, deliberately

`Free` rather than `EmptyAtQuorum`: it names the occupancy answer, not the cell shape, and cannot be confused with `CellObservation::EmptyAtQuorum` while both types briefly coexist during migration. `Undetermined` rather than `Pending`: "pending" reads as a client-side transaction state, and the owner's ruling is that `RECOVERING`/`INDETERMINATE` must never be modelled as register states. `Undetermined` is a word about evidence.

## Commit order

The invariant at every boundary: **occupancy is answered by exactly one register, and by the same one on the write and read side.** The trait rename couples `dsm` and `dsm_sdk` at compile time and the walk/provenance coupling is semantic, so the switch is genuinely atomic. Everything else is arranged around it as additive-then-subtractive.

**C1 — core, pure, additive.** `dsm/src/dlv/binding_observation.rs` (the five-valued observation, `tally_key` lifted verbatim from `QuorumBind::fold_reads`, the two pinned `Free`/`Undetermined` cases, unit tests only); `fold_reads` refactored onto it; the mixed-bundle ban in `settlement_bundle::validate` plus the close-successor reconstruct/verify pair. **Also move `close_slot_commitment` out of `settlement_slot_claim.rs:180` into `settlement_bundle.rs`**, updating its three callers (`dlv_routes.rs:2279`, `:2515`, `vault_state_composition.rs:445`) — doing the rescue now means C4 deletes `settlement_slot_claim.rs` whole, with no carve-out to get wrong later.

The mixed-bundle ban is a **narrowing of an already-frozen format** (5a, #776), not a field change: no message, field, or tag moves, and every bundle the tree constructs today already satisfies it. It needs its own refusal test and a note in the 5a format doc.

**C2 — SDK, additive, nothing production-reachable.** `read_binding_attributed` + the shared `binding_transport` factory; `binding_occupancy.rs`; `active_fence`; the `base_ballot` fix; and the fleet double's new controls — member-id-keyed sugar (§ test migration), `plant_committed` (writes canonical ACCEPTED records directly, for negative paths the driver structurally cannot produce), and `cas_log`.

**C3 — THE SWITCH. One atomic commit.** The current uncommitted working tree is folded in here, not committed separately: it is already the forbidden split-brain (close writes the binding register at `dlv_routes.rs:2616-2690` while `vault_state_composition.rs:359` still reads the old cell). Contents: the walk rewrite + `ComposedVaultState` fields; the market write path (`dlv_routes.rs:3050`) building a market bundle and calling `bind_settlement`; the close-resume rewrite (`:2188-2262`, dropping `FrozenClaimEnvelope::load`); the trait rename across both traits and all impls; the provenance §8 arm; the eight consumers; and all test migration.

There is no safe intermediate here and splitting it would create one: (a) without (d)/(e) makes every settled generation compose as `Free` and the vault double-spendable; (d)/(e) without (a) makes provenance reject every settle. Reviewability comes from the commit message and the suite, not from smaller commits.

**C4a / C4b — pure subtraction, compiler-proved.** SDK/client: `sdk/settlement_slot.rs` whole, `client_db/settlement_slot_claim_local.rs` + its DDL, `storage_io.rs:734/751/1058`, `economic_registers.rs:277/808`, `storage_node_sdk.rs:1092/1637`, and the `fake_fleet` slot half — **leaving the object-store half (`stores`, `echo_override`, `put_log`, `put`, `fail_member`, …) intact**, since 19 sites in `artifact_republish.rs` plus four other suites depend on it, and `echo_override` is shared by `put` and `read_slot`. Core: `settlement_slot_claim.rs` whole, the two `TAG_DSM_SETTLEMENT_SLOT_CLAIM_*` tags and their registry entries. The proto messages (`dsm_app.proto:1637`/`:1651`) only if `ci/bridge_contracts_gate.sh` tolerates the `dsm_schema_semver` move — an unreferenced proto message is dead data, not a coexisting mechanism, so deferring that one does not violate the no-coexistence rule.

**C5 — prose sweep.** Module headers are load-bearing documentation here and several now describe a register that no longer exists: `vault_state_composition.rs:22-63`, `economic_registers.rs:16-23`, provenance §8, `dlv_routes.rs:8002`, `route_routes.rs:367/1199`.

## Test migration

**The composition suite funnels through one helper.** `win_slot` (`vault_state_composition.rs:777-798`) is the only register touch for all 14 tests; re-point it at `bind_settlement` and the signature barely moves. Two consequences: `claimant_sk` becomes unused on the market path (which authenticates through the RouteCommit's signature, not a claim) and is repurposed for the close variant's `bundle_signatures`; and `local_proposer_id()` reads `AppState::get_genesis_hash()`, which these tests do not set — derive a deterministic per-claimant proposer inside the helper, since two claimants sharing a proposer would collide rounds. `fleet()` (`:756`) gains `binding_fleet_double::reset_all()`.

**Member-id vs endpoint.** Add id-keyed sugar to the double (`fail_member_id`, `heal_member_id`, `refuse_writes_id`, `set_echo_id`) via a three-line reverse lookup over the `echo` map it already keeps. Every call site then becomes a literal 1:1 substitution, and `vault_storage_members` stays untouched — preserving its "resolve the vault's BIRTH set, never the configured fleet" discipline. Keep the raw endpoint-keyed `set_echo`: it is the only way to exercise the **register-incarnation** arm of `counts_for`, which `fake_fleet` never had.

**One injection changes materially, not cosmetically.** `a_contested_parent_refuses_the_close_and_moves_nothing` (`:7817`) plants a rival claim with a bogus `parent_binding_c_n: [0x9A; 32]`. Under the old `(vault_id, parent_sequence)` key that still hit the right cell and the walk rejected it as "binds a different parent state". Under `k_v = H(binding-keyset ‖ c_n)` a bogus `c_n` lands on a **different key** and the walk sees nothing. The rival bundle must now name the vault's real `c_0`. The asserted error still holds — a rival market bundle has no receipt, so the walk fails closed.

**The `put_log("slot:")` digest assertion gets stronger, not weaker.** The property is *"every attempt before and after the outage carried one envelope, and it is the frozen one."* Under QuorumBind the frozen bytes are the bundle, put through the surviving `fake_fleet::put` under `immutable::DSM/settlement-bundle::{addr}` — so one distinct key proves one content identity, cross-checkable against the fence's `value_addr`. Add a `cas_log()` assertion on top, projected onto `(tx_id, value_digest, value_addr)` and **not** the whole record: rounds and ballots legitimately differ across a recovery, and digesting the full record would fail spuriously.

**Two composition tests need `plant_committed`.** `a_divergent_write_once_cell_fails_closed` (`:1189`) cannot be reproduced through the driver — at `n=3, q=2`, failing two members means no quorum, so a single-member claim is unreachable. Its honest restatement is `Undetermined`: plant one ACCEPTED record and assert the walk refuses rather than reporting a frontier — same verdict, more accurate premise, rename accordingly. `a_winner_binding_a_different_parent_state_fails_closed` (`:1402`) likewise: `K(B)` is *derived* from `parent_state_commitment`, so only a hostile hand-built key set can produce that state, and the application-blind node would accept one. These two are why `plant_committed` exists.

**The ~11 stub impls: bulk mechanical rename.** Not a default method — one returning `Unavailable` would let a future production resolver forget the occupancy question and silently fail closed instead of failing to *compile*, which is the quiet-fallback shape the no-coexistence rule bans, in the one trait whose doc comment explains at length why it has no `Option` and no `Result` to collapse. Not an adapter either — a `CellObservation ⇄ BindingObservation` conversion is a live mechanism-bridge in the tree, and `Undetermined` has no `CellObservation` image, so it would have to collapse into exactly the wrong arm. Seven are byte-identical boilerplate and become one-line changes; the real work is `economic_dlv_settle_provenance.rs:516`/`:676` plus its six `sign_settlement_slot_claim` fixtures, each becoming a canonical bundle plus the `BindingRecord` naming it, with the fixture also serving those bytes through `immutable_evidence`. A shared bundle-fixture builder is worth it for those six; not for the seven boilerplate stubs.

**Test runtime.** `MAX_BALLOTS = 8` with a 2000 ms-capped jittered backoff means each deliberately-failed bind burns ~4–8 s, on a board already at `--test-threads=1`. Add `bind_settlement_with(..., backoff, max_ballots)` and have tests pass a 1–2 ms backoff. Cheap now, painful later.

## Verification

Per commit, from `dsm_client/deterministic_state_machine`: `-p dsm` targeted runs for C1 (`dlv::binding_observation`, `dlv::settlement_bundle`), `-p dsm_sdk` for C2 (`sdk::settlement_bind`, `sdk::quorum_bind_runner`, `storage::client_db::trader_parent_fence`).

**C3 runs the full close/composition surface, not the two driver tests** — the owner's step 5. In order, cheapest signal first:

```bash
cargo test --locked -p dsm_sdk --release sdk::vault_state_composition -- --nocapture --test-threads=1
```

then every `dsm` integration suite carrying a stub impl (`economic_dlv_settle_provenance`, `economic_dlv_owner_apply_provenance`, `economic_provenance_semantics`, `economic_admission_lifecycle`, `economic_peer_evidence`, `economic_authorized_issuance`, `era_faucet_wire`, `quorum_bind_conformance`), then `handlers::dlv_routes` and `handlers::route_routes::stamping_tests` whole.

Nineteen `funded_creation_tests` traverse the walk, settle, or close path and all must be re-run, not just the two known failures. **`lp_offline_market_advances_three_generations_and_lp_reconciles_each_once` (`:7162`) is the highest-value regression test in the cut** — it drives three consecutive generations through both the settle path and the walk, so it is the one test that would catch an `Undetermined`/`Free` confusion a single-generation test cannot.

**Mutation controls** (repo rule: every security gate is mutation-tested, and a mutation that stays green is a finding about the test). Three are mandatory here, and each must reproduce the forbidden *state*, not merely break liveness:

1. **Close authorization.** Drop the `DlvClose` signature verification from the walk, have a non-owner bind a close-shaped bundle over a funded vault, and watch a named test observe reserves folded to zero. Restore. A second control on the same gate: keep the verification but let the reconstruction ignore one bound field (e.g. `leg_b_amount`), then replay a genuine owner signature from a *different* close onto this transition — it must still be refused.
2. **`Undetermined` is not `Free`.** Map `Undetermined → Free` in the walk and watch a named test compose past a generation whose bind is mid-flight. Restore.
3. **The mixed-bundle ban is load-bearing.** Remove the `validate` refusal, construct a bundle carrying a genuine owner-signed close of V1 alongside a market transition on V2, and watch a named test fold V2 on a signature that never authorized it. Restore.

**After C4:** `cargo build -p dsm -p dsm_sdk` is the deletion-completeness proof, followed by the negative grep, which must return zero outside `dsm_storage_node/`:

```bash
grep -rn "settlement_slot\|SettlementSlotClaim\|FrozenClaimEnvelope\|SlotClaimError" dsm/src dsm/tests dsm_sdk/src proto/
```

**Boards, both halves, before claiming anything.** From `dsm_client/deterministic_state_machine`:

```bash
cargo test --locked --workspace --exclude dsm_storage_node --release -- --nocapture --test-threads=1
```

and from the repo root, `make lint` (pinned 1.98.0, `fmt --check` + `clippy --all-targets`) and `ci/production_safety_checks.sh`. Two traps this cut walks straight into: the safety script runs `--all-features`, which turns on `test-utils` and compiles `binding_fleet_double` under `-D warnings` with `unwrap`/`expect`/`panic` lints — every new helper must stay inside that module's existing `#![allow]` or carry its own; and `make lint` covers the whole workspace including `dsm_storage_node`, whose old-register code is untouched here and must keep compiling. Report crates and counts, never "the board is green".

## Merge discipline

The branch stays unmerged until 5c-2 lands and the old register is excised. The pre-merge condition, stated now so it is not renegotiated later: `grep -rn "settlement_slot" dsm/ dsm_sdk/ dsm_storage_node/ proto/` returns **zero**. Two things stand between C5 and that — the `dsm_storage_node` endpoint/table excision (server side; a node dropping the endpoint while a peer still speaks it breaks that peer, so it is sequenced after 5c-2) and the conditional proto removal.

Deliberately carried into 5c-2, each marked in-code with an unmissable `5c-2:` comment so scaffolding cannot be mistaken for settled design: the market realization evidence gate; the market bundle's placeholder `trader_successor`; and the fence's unreleased `committed_awaiting_acceptance` rows, whose release is the acceptance gate 5c-2 builds.

---

# C3 amendments from the adversarial map (post-approval, verified from source)

> **LANDED, and superseded in part by 2c-A — same footing as the section above.** This is a
> top-level heading, so the banner at the head of this document does not reach it. Item 5 below
> describes a close bundle whose `route_set_commitment` is 32 zero bytes and whose only X is its
> transition's `successor_ccb`. **2c-A abolishes both:** an owner close carries no `market_terms`,
> hence no `X` at all, and there is no `successor_ccb` field. Where the two disagree, 2c-A governs.

A 5-agent map plus an adversarial critic swept the whole repo — not just the four files the
plan named. It found eleven things the plan got wrong or missed. Three change scope.

## Corrections to the approved plan

**1. `settlement_slot_claim.rs` must SURVIVE C3 and C4b.** `dsm_storage_node/src/api/vault/settlement_slot.rs:60`
imports `decode_and_verify_settlement_slot_claim` + `ClaimError` as its production endpoint
verifier, and its tests use `sign_settlement_slot_claim`, `claim_envelope_digest` and
`SettlementSlotClaimBody`. The plan said C4b deletes the file whole; that would stop
`dsm_storage_node` compiling. The C1 re-export shim therefore stays until a single coordinated
cut across `dsm` + `dsm_sdk` + `dsm_storage_node` + the router mounts.

**2. THE FAIL-CLOSED LANDMINE — the close signing key.** `dlv_close` signs via
`sign_operation_sphincs`, which uses `signing_authority`'s CURRENT device AK
(derived from the wallet seed). `verify_close_authorization` verifies under `owner.ak_pk`,
which is `presentation.ak_public_key` from the vault's BIRTH presentation
(`identity_presentation.rs:381`). If those ever differ, the close **binds** — taking
occupancy — and can **never realize**: the vault is permanently unclosable, bound forever.
C3 adds an explicit equality gate in `dlv_close`, checked **before** `bind_settlement`, so a
mismatch is a clean refusal instead of a bricked vault. The reconstruction must likewise use
the COMPOSED parent's reserves/pair/fee, not `live.*` — `dlv_close` currently builds the op
from local leaves.

**3. `dlv.composeVault` keeps FOUR fields.** The plan floated appending `frontier_binding`.
`scripts/rig_compose_verdict.py:38-45` does not parse the string — it compares two devices'
answers for **byte-identity**. Two devices reading the binding register at different instants
can honestly disagree about `frontier_binding` for one `c_n`, so appending it makes a live
two-device gate flaky while proving nothing. The response stays a statement about composed
STATE. (`dsm_sdk/tests/vault_funding_routes.rs:462-500` also enumerates every route.)

**4. `scripts/dlv_market_rig_proof.sh:157-176` is a live gate this commit breaks.** It reads
`/api/v2/settlement-slot/{vault}/{seq}` per consumed generation and asserts one claim at
quorum with no rival. Moving the market write path turns every read into nothing. Under the
repo's own "a change that REMOVES a capability owes a dependent sweep" rule this is the
sweep's first target, ported to ReadBinding at `resource_key(c_n)` in the SAME commit.

**5. Discriminate on `shape` FIRST.** A close bundle's `route_set_commitment` is 32 zero
bytes (`settlement_bind.rs`), so any shared path reading X before the shape check computes an
all-zero X. A close's only X is its transition's `successor_ccb`.

**6. FOUR test harnesses must reset the binding double**, not one: `install_identity`
(already done), `economic_fixtures::empty_router_with`, `faucet_flow_tests::setup`, and
`test_support/two_device.rs:400-409`. The board runs `--test-threads=1`, so leakage is
order-dependent and reproducible.

**7. Four `pub` slot transport fns are invisible to dead-code lint** and will silently survive
the cut unless deleted deliberately: `storage_io::submit_settlement_slot_claim` (:751),
`submit_settlement_slot_claim_live` (:1058), `storage_node_sdk::post_settlement_slot_claim`
(:1092), `submit_settlement_slot_claim` (:1637).

**8. `MemberClaimResult` / `MemberClaimOutcome` / `ClaimFanout` / `classify_one_shot_response`
MUST SURVIVE** — they are the shared one-shot-register vocabulary used by the faucet-ticket
and economic-root registers, not slot-specific. Only their doc wording changes.

**9. Evidence locality.** `fetch_immutable_payload` resolves through the LOCALLY configured
fleet, while `put_bundle` wrote the bundle to the VAULT's committed set. In beta these are the
same three nodes; that is an assumption to STATE in the §8 comment, and the not-found case
must be `Incomplete` (retryable), never `Invalid`.

**10. The market settle discards the proven owner key.** `dlv_routes.rs:2965-2966` feeds
`SettleTerms` from `vault.creator_public_key` — a row in the settler's own local records —
while `composed.owner_public_key` (the P0–P6-proven key) is in scope and thrown away. A
settler with no local record is exactly why that path composes the DISCOVERED vault.

**11. `FrontierBinding` derives `Debug, Clone, PartialEq, Eq`** (assert_eq! in migrated tests;
`ComposedVaultState` derives Debug+Clone). Delete `CompositionError::StorageListFailed` and
`PointerDecodeFailed` — never constructed anywhere, dead since the pointer-prefix fold.

## Board scope, pinned before starting

The two halves have DIFFERENT crate scopes: the test command carries
`--exclude dsm_storage_node`, but `make lint` runs `cargo clippy --all-targets` with no
exclusion. So an API break in `dsm` reaches the node through LINT only, and the node's own
tests never execute on the board at all. "The board is green" cannot be claimed for a
node-visible change from the test half alone.

Nothing owed in `tla/`, `lean4/`, `tools/`, `crates/`, Kotlin, or the frontend beyond one
`amm.ts:389-398` doc sentence — all verified as zero-hit by explicit grep.

## Open question for the owner

`settlement_resume::recover_all` / `resume_one` have **zero callers in the workspace**, yet
`dlv_routes.rs:2682-2686` already tells the user an unresolved close "stays fenced and
recovery will resume it." That promise is currently false. Either wire `recover_all` into cold
boot in this commit, or correct the message — but not both, and not neither.

## Owner decisions on the amendments (2026-09-06)

**Restart recovery — wire it in C3.** `recover_all()` goes into the cold-boot sequence *after*
the client DB, device identity, storage-set catalog and transport config are available, and
*before* normal settlement/routing is allowed to treat fenced parents as usable.
`resume_close_intents` **stops being a second binding-recovery driver** — it keeps whatever
close-specific post-binding finalization it still needs, but there is exactly ONE mechanism
that re-drives QuorumBind: `recover_all → resume_one → run_fenced`. If startup recovery cannot
complete because the fleet is unreachable, the fence stays intact and a later sync/recovery
trigger retries. **That is never turned into "free."**

**Rig gate — port in C3, sharing the production observer.** A live proof reading a mechanism
production no longer uses proves a dead mechanism. Do NOT reimplement a simplified
"count matching digests" in shell: the rig calls a helper that shares the **production
observer**, so the hardware gate cannot drift from Class K semantics. Per consumed parent:

```
derive c_n -> k_v = H(DSM/binding-keyset || c_n) -> read committed members
-> authenticate member + incarnation -> same BindingObservation semantics
-> require BoundFinal -> verify value_digest / value_addr -> fetch B
-> verify B names that exact parent -> prove no second binding-final value
```

5c-2 extends the same gate with the `A_B` market-realization proof. The settlement-slot check
is removed from the rig, not kept beside it.

**The AK mismatch — stronger than a key comparison.** A close must not become binding-final
unless the complete close candidate **already verifies under the owner authority committed by
that exact DLV parent**. Rev-15 allows the one-phase owner close precisely because the concrete
owner signature over the exact release successor exists and verifies *before* binding begins.
So: resolve the authority committed by `V_n`, and **preflight `verify_close_authorization`
before the first mutating QuorumBind operation**. If the current signer cannot satisfy the
parent-committed authority, **reject before occupancy** — never bind first and discover
afterward that realization is impossible. Signing with "whatever AK is current" and verifying
against the parent-committed key later is exactly the ordering that bricks a vault.

**C3's definition is therefore:** production write, production read, restart recovery,
provenance, routing consumers, and the live hardware proof all switch authority together. No
component is left believing the old register is authoritative.

---
---

