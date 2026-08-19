# DLV vault close (withdrawal) + narrow quorum-publication primitive for vault birth and death

Status: design approved by owner 2026-08-18 (Steps 1–4 as written; Step 6 gated on
Step 5). Not yet implemented. Branch: `feat/dlv-close-and-quorum-publication-primitive`;
Step 5 is its own PR. Companion to `finding_dlv_reserve_authority_invariant_map` and
`.claude/traces/sessions/TRACE-2026-08-18-001.json`. Rust paths relative to
`dsm_client/deterministic_state_machine/` (`dsm/src/…`, `dsm_sdk/src/…`); storage node
paths relative to `dsm_storage_node/src/`. `docs/plans/` is gitignored by default
(`.gitignore:250`); commit this file with `git add -f` on the branch, as
`2026-08-16-bilateral-finality-barrier.md` was.

## Context

The DLV reserve-authority pass has hardware-proven three of five invariants (2026-08-18,
`scripts/dlv_market_rig_proof.sh` 17/17): funding atomically encumbers (inv 1), the market
advances a vault across generations with the LP dead (inv 2, #672), and each generation is
consumed exactly once (inv 3, #670). The last lifecycle piece is missing: **there is no way
to get liquidity back out of a vault** — `VaultReserveMutation` has only `Fund` and
`ApplySettlement`.

Designing a *safe* close surfaced two base-layer defects the owner directed be fixed at the
base layer first, not worked around in DLV:

1. **Two root moves after the point of no return.** `dlv.create` commits its funding advance
   (root R1), then `publish_vault_state_inclusion_proof` calls `install_vault_state_leaf` — a
   *separate advance* (own lock, own tx) → root R2 — and signs the reserve proof against R2.
   It takes `state_machine.lock()`, so it cannot run inside `pre_write`/`in_tx_extra`
   (deadlock). No owner-published proof can be frozen from "the exact state that freed the
   reserves." The vault-state leaf must ride the staged advance.
2. **DLV publication has zero durable intent, and a single-replica write counts as
   published.** Every SoFi artifact is a remote key only; `put_to_all_replicas` succeeds at
   `success_count > 0`; every failure branch in create's publish is `log::warn!`-and-continue.
   The bilateral `sender_outbox` cannot be reused (proposal-keyed FK, closed role CHECK, b0x
   transport, finality-barrier check) and shouldn't be: bilateral "pending" is
   peer-directed; DLV publication is a fact broadcast to a storage quorum. The
   identity-publication path is the right shape.

**Owner decisions (binding; also in memory `project_dlv_close_withdrawal_design`):**
three separated concerns — canonical state authority (the staged advance) / publication
durability (frozen bytes replayed until quorum) / market semantics (create, trade,
reconcile, close). The publication layer stays ignorant of DLV. **Narrow primitive:**
publish-frozen-object-to-quorum — no recipient, no routing address, no acceptance, no
ACK-driven GC, no countersign, no peer-progress. Same transaction as the canonical advance
(construction failure ⇒ no commit). One generic sweep (startup + sync), byte-identical
replay, never regenerate/re-sign. Quorum = delivery complete, not authority. Birth and death
on equal footing, now. **Boundary:** trader pointers/receipts stay on their current path.
Create lifecycle explicit: funded-locally / publication-pending is NOT market-active until
the seq-0 set reaches quorum. Close pre-claim intent durable *before* the slot claim is
published; recovery orchestration only, never a second authority. Close correctness: pair-
complete drain (refuse when already zero); frontier = sequence AND reserve-digest equality;
slot claim on parent N (prefix derives N+1); crash-freeze. Schema v4 → v5, no shim.

## Step 0 — prerequisites (not on this branch)

Land #673 (SoFi UI ports) and #675 (rig proof + driver). At plan time runs `32167090857`
(#673: Coverage, Embedded) and `32168011621` (#675: Rust, Embedded) had jobs stuck
`in_progress` ~3h — including `Embedded`, a ~90 s job — a stalled Actions runner set, not
our code. On approval: `gh run cancel <id>` + `gh run rerun <id>` for both; merge each on
a fully terminal green board (`gh pr merge N --merge --admin --delete-branch`, the pattern
used for #670–#674). Branch off the resulting `main`.

## Build order (each step its own commit; TDD; one mutation per gate)

Order is **1 → 2 (with schema v5) → 3 (sweep) → 4 (create) → 5 (hard quorum
settlement-slot claim, its own PR) → 6 (close)**. Create lands before close so the
primitive + sweep are proven on the simple lifecycle first and close's frontier gate has
published birth artifacts to compose from. **Close is blocked on step 5:** the current
slot claim is a storage *listing*; under partition a trader and the close can both believe
they own parent K, and a trader settlement final on its own chain plus an owner release of
the same reserves is value duplication — the exact boundary this work exists to prevent.
Same-transaction persistence is not a separate step — it is how 4 and 6 are built.

**Owner approval status (2026-08-18/19, six reviews):** Steps 1–4 **APPROVED** as
written. Step 5 **REQUEST CHANGES → addressed below**: 2nd review — circular signature
preimage; quorum over local config instead of a canonical member set; rollback in the
threat model; griefing classification; `DeviceContext` key injection; naming. 3rd review —
fully canonical `storage_set_id` encoding (count + length-prefixed, sorted); **vault↔set
binding must be cryptographic and public** (in the signed anchor, not only a local
record); `amm_vault_records.storage_set_id` moved into the v5 DDL (step 2) and populated
in step 4. 4th review — step 2 re-keyed by canonical **member id** (URL = transport
metadata; ONE definition of "2 of 3"); **set→endpoint resolution via a catalog that must
re-hash to the anchor's id** (the anchor chooses the set, config only resolves it);
**lineage immutability** of `storage_set_id` (birth-fixed, callers never supply S,
compose rejects a differing later generation; needs the seq-pinned birth anchor → birth
and terminal sets are FIVE objects); **client model stated: protocol-conforming-client
safety for beta**, Byzantine-client safety named as the follow-up boundary. 5th review —
**every frozen artifact binds its `storage_set_id`** (NOT NULL column; `freeze` takes it;
the sweep resolves the frozen S through the catalog and never substitutes); **hardware
register oracle corrected** (exactly one digest with quorum per consumed parent, no
conflicting digest with quorum; minority conflicting rows legal and permanent);
**"distinct members" made executable** (catalog: unique ids, injective endpoints; count
only when the echoed `node_id` equals the contacted member); "immutable birth reference"
softened to birth-pinned / canonical-protocol-immutable. 6th review (final) — **Step 6
requires `amm_vault_records.storage_set_id == composed.storage_set_id` after
composition; the composed/birth-bound S is authoritative for claim-set resolution and
terminal freezing, the record is a cache**; `quorum_required` column DELETED (quorum is
always `quorum_for(|S|)` from the frozen set); member-table key intent stated (single
current observation per `(object_key, member_id)`, `accepted_digest` selects the
generation); `VaultStatePair` fields renamed `policy_commit_a/b` with `a()/b()`.
7th review (textual, final) — canonical `Operation::DlvClose { vault_id, legs,
parent_sequence, new_sequence, pair, signature }` defined so `Withdraw == op` is
implementable (app request stays `DlvCloseV1 { vault_id }`; handler derives + signs;
`pair` inside the signed op); recovery re-establishes the three-way S equality
(`claim.body.S == composed.S == record.S`) before any resumed claim/terminal step;
"ONE atomic SQLite write transaction" wording. **Final disposition: Steps 1–5 APPROVED;
Step 6 APPROVED; Step 6 implementation gated on Step 5 landing. No further design review —
implement.**

### Step 1 — the vault-state leaf rides the staged advance (ONE canonical root)

**Files:** `dsm/src/types/device_state.rs`, `dsm/src/core/state_machine/mod.rs`,
`dsm_sdk/src/sdk/core_sdk.rs`, `dsm_sdk/src/handlers/dlv_routes.rs`, tests.

- **Shape:** attach the vault's pair + fee to the reserve mutations —
  `Fund { …, pair: VaultStatePair }`, `ApplySettlement { …, pair }`, (step 6) `Withdraw {
  …, pair }`; `VaultStatePair { policy_commit_a: [u8;32], policy_commit_b: [u8;32],
  fee_bps: u32 }` with accessors `a()`/`b()` — the two values are 32-byte POLICY
  COMMITMENTS (the keys the reserve legs are stored under), not token labels; the plan's
  `pair.a`/`pair.b` shorthand means these accessors. Every
  reserve mutation updates the vault-state leaf in the SAME SMT batch; a vault-state leaf
  can never exist without the reserve move it describes (derive-don't-accept doctrine,
  `device_state.rs:731-735`, `:1501-1510`). Three construction sites change instead of ~60.
- **Pair completeness on ALL arms (reviewer #5):** `Fund` legs must be exactly
  `[pair.a, pair.b]` (today only non-empty/ascending/distinct, `:1300-1319`);
  `ApplySettlement` `{input,output}` must equal `{pair.a, pair.b}` (today it admits a
  first-time third asset, `:1456-1466`, which the derived digest would silently omit).
- **Inside `advance`:** after the reserve arm, derive `sequence` (from the mutation),
  `ra/rb` from `new_vault_reserves` at the two pair keys, `reserves_digest =
  dsm::dlv::vault_state_anchor::compute_reserves_digest(a,b,ra,rb,fee)` (same crate); push
  `(compute_vault_smt_key(vault_id), compute_vault_smt_value(sequence, digest))` into one
  `batch_leaves` (fold `funding_leaves` into it) used by the fast-path guard (`:1595`), all
  manual arms (`:1615/:1651/:1699`) and the `extra_leaves` replay (`:1766-1768`) —
  mandatory or `restore` recomputes a different root (`:912-914`). `post_root` is taken
  after all `update_leaf`s in every arm ⇒ same `child_r_a` for relationship, anchor,
  receipt, reserve and vault-state leaves.
- **`AdvanceOutcome` gains** `vault_state_proof: Option<VaultStateLeafProof { vault_id,
  sequence, reserves_digest (as DERIVED), siblings (256) }>`, `Some` iff a reserve mutation
  ran, populated after `post_root`, so `pre_write` signs the leaf that landed.
- **Delete** the second advance outright: `DeviceState::with_vault_state_leaf`,
  `VaultLeafOutcome`, `StateMachine::{prepare,commit,install}_vault_state_leaf`,
  `CoreSDK::install_vault_state_leaf`, and the mutation inside
  `publish_vault_state_inclusion_proof` (`dlv_routes.rs:2241-2306`) — that helper becomes
  a pure byte builder over an `AdvanceOutcome`. Since create's inclusion proof can no longer
  be built after the fact, create's `pre_write` build (step 4) lands together with this
  step (or a transitional post-advance build from the single-root head inside this commit).
  Tests that planted a leaf via `with_vault_state_leaf` (`dlv_owner_apply_preservation.rs:117`,
  `device_state.rs`) plant it via a real reserve mutation. `simulate_advance_for_confirm`
  (`core_sdk.rs:1560-1590`) passes `None` for reserve mutations and stays byte-identical.
- **`dlv_reconcile` call site (reviewer #6):** it builds `ApplySettlement` from the receipt
  only (`dlv_routes.rs:1459-1467`); it must read `get_amm_vault_record` for
  `policy_commit_a/b, fee_bps` and fail closed if no record.
- **New wrapper** in `core_sdk.rs`: `execute_on_relationship_staged_with_reserve_mutation<A>`
  = `execute_on_relationship_staged` (build-once `RefCell`, `:1228-1253`) with
  `reserve_funding` parameterized. Constraints (reviewer #7): `pre_write` runs under the
  `state_machine` lock — read ONLY `outcome.new_device_state`
  (`inclusion_siblings`, `vault_reserve_leg_proofs` are pure); never call
  `core_sdk.device_head()/get_current_state()` (re-lock → deadlock); capture pair/fee/keys
  before the staged call; signing is lock-free and sync; no `.await`. `in_tx_extra` may not
  `get_connection()`.
- **Hygiene (reviewer #13):** `DeviceState::withdraw_vault_reserves` (`:2240-2247`) is a
  `pub` unsigned withdrawal path (test callers only) — `cfg(test)`-gate it so `DlvClose` is
  the sole door.
- **RED:** create's anchor/state-inclusion/reserve proofs verify against ONE root equal to
  the committed head root; `bcr_device_heads` written once; reconcile keeps the vault-state
  leaf in lockstep with the legs; Fund with a leg not in the pair refused; ApplySettlement
  naming a third asset refused. Mutation: drop the leaf from the batch → inclusion proof
  fails against `child_r_a` → RED.

### Step 2 — base-layer `frozen_publication_artifact` + schema v5

**Files:** `dsm_sdk/src/storage/client_db/mod.rs`, new
`dsm_sdk/src/storage/client_db/frozen_publication_artifact.rs`,
`dsm_sdk/src/sdk/storage_io.rs` / `storage_node_sdk.rs` (keyed per-node PUT).

- **Model:** `identity_publication` + `_nodes` (`client_db/mod.rs:455-472`, `publication.rs`):
  quorum re-derived from the node table, `quorum_required = 0` sentinel, forward-only,
  `quorum_for(n) = n/2+1`.
- **DDL — keyed by `(object_key, content_digest)`, NOT `object_key` alone (owner-decided;
  reviewer #1, blocking):** the anchor and inclusion proof publish under `…/latest` mirror keys
  (`vault_state_anchor_codec.rs:76-78`, `vault_smt_inclusion_codec.rs:40,135`), so birth
  and close both freeze `sofi/vault-state/{v}/latest`; the storage node upserts by path
  (`objects/store.rs:237-262`; there is no keyed 409). Freezing a new digest for an
  existing key marks that key's prior rows `superseded` (terminal; never swept) in the same
  tx; `is_artifact_published(key)` reads the latest row.
  `frozen_publication_artifact(insertion_ordinal INTEGER PRIMARY KEY AUTOINCREMENT,
  object_key TEXT, content_digest BLOB, payload BLOB, bound_root BLOB, purpose TEXT,
  storage_set_id BLOB NOT NULL, state TEXT CHECK IN
  ('frozen','publication_pending','published','superseded'),
  last_error TEXT DEFAULT '', UNIQUE(object_key, content_digest))` — **no `quorum_required`
  column (owner, sixth review):** quorum is ALWAYS derived as `quorum_for(|S|)` from the
  row's frozen `storage_set_id` resolved through the catalog; a stored quorum would only
  invite drift from the derived one (the identity table's `quorum_required = 0` sentinel
  is that table's own convention and is not carried over). **Every frozen
  artifact binds the canonical set it was frozen FOR (owner, fifth review):** the sweep
  needs an exact S to fan out to, and after restart / config replacement / a multi-set
  catalog "the currently configured fleet" is exactly the local-config authority step 5
  removed. Publication gets the same crash-stable membership semantics as its crash-stable
  bytes. For birth and terminal artifacts the frozen S must equal the vault's birth-bound
  S. — and
  `frozen_publication_artifact_members(object_key, member_id, accepted_digest BLOB,
  PK(object_key, member_id))` — **keyed by canonical member id, never URL (owner, fourth
  review):** protocol membership is by distinct node identity (step 5); a URL is transport
  metadata resolved from the storage-set catalog at send time. **Intent of this key (owner,
  sixth review — do not "fix" it to `(object_key, content_digest, member_id)`):** member
  acceptance is a single CURRENT observation per `(object_key, member_id)`;
  `accepted_digest` identifies which artifact generation that observation applies to.
  Only one non-superseded digest exists per object key, so this is sufficient.
  Superseding an artifact does NOT copy old acceptances forward, and
  `count_accepting_members(key, digest)` counts only rows whose `accepted_digest` exactly
  equals that digest. **No clock columns anywhere in logic (owner):** ordering of
  unpublished work is by the local monotonic `insertion_ordinal`, never by a timestamp;
  `created_at`/`last_attempt_at`/`accepted_at` are dropped (a `tick`-stamped diagnostic
  column may exist but nothing reads it). Quorum counted per `(key, digest)`. Forward-only
  in SQL (`ON CONFLICT … DO UPDATE … WHERE state NOT IN ('published','superseded')`;
  immutable columns absent from SET). No recipient/route/acceptance/ACK/GC columns.
- **Schema v5** here, with the DDL (the version is the authority — v4 doc, `mod.rs:369-375`).
  **v5 also adds `amm_vault_records.storage_set_id BLOB NOT NULL`** (owner, third review:
  the column belongs with the version bump, not in step 5 — step 4 populates it, step 5
  consumes it; no v6). SDK config gains the **storage-set catalog** (`storage_sets:
  [{members: [{member_id, endpoint}]}]`; beta = exactly one entry) from which
  `StorageSet { id, members }` is built (id encoding + resolution rule defined in step 5).
- **Module** (`pub mod`, namespaced like `publication`): `freeze_artifact_with_conn(conn,
  storage_set_id, key, payload, bound_root, purpose) -> [u8;32]` — **derives the domain-separated content
  digest from `payload` internally and returns it (owner correction #4: derive, don't
  accept)**; there is no API that takes a caller-supplied digest, so mismatched bytes/digest
  is structurally impossible; in-tx; supersedes prior rows for the key; a second freeze of
  the same `(key, digest)` is an idempotent no-op, and there is no "same key, same digest,
  different bytes" case because the digest IS a function of the bytes. `record_accepting_member`,
  `clear_accepting_member`, `count_accepting_members(key, digest)`,
  `upsert_artifact_publication_state`, `get_artifact`, `list_unpublished_artifacts(limit)`
  (ORDER BY `insertion_ordinal`, excludes `superseded`), `is_artifact_published(key)`.
- **Per-member keyed PUT (new):** `put_bytes_to_all_members(set: &StorageSet, key, payload)
  -> KeyedPutFanout { outcomes: Vec<{member_id, endpoint, accepted_digest, error}>,
  accepted, total = |set| }` on `StorageNodeSDK` (its `clients` are private,
  `storage_node_sdk.rs:875`; per-node auth via `with_per_node_auth`); iterates the
  canonical member set (endpoint resolved per member from the catalog), never
  short-circuits; returns `Ok` even at zero acceptances (K is the caller's decision);
  **denominator = `|canonical set|`, never `config.node_urls.len()` or `clients.len()`**
  (reviewer #8: `new` silently drops unconstructible nodes, so `clients.len()` could make
  1-of-3 read as 1/1; and URLs are not identity). Optional read-back verify per member
  hashing the returned bytes against `content_digest` before `record_accepting_member`.
  There is exactly ONE definition of "2 of 3" in the codebase — this one, shared with the
  step-5 register (`quorum_for(|S|)`); publication quorum is delivery, but birth
  activation depends on it, so it must not drift from the register's.
  **"Distinct members" is executable, not administrative (owner, fifth review):** the
  catalog is validated on load — member ids unique, endpoints injective within a set —
  and every PUT/claim response carries the node's configured `node_id`; an acceptance is
  counted ONLY when the echoed `node_id` equals the catalog member id being contacted.
  Two catalog members pointing at one physical node therefore yield one countable
  acceptance, not two. (Crash-fault node model — no node-identity PKI needed for beta.)
- **RED:** freeze inside a failing tx leaves no row; the stored digest always equals the
  domain-separated hash of the stored payload (no API can make them disagree — mutation:
  add a caller-supplied digest path → RED); freezing new bytes under an existing key
  supersedes the old row and the sweep never replays superseded bytes; quorum counts only
  nodes that accepted these exact bytes
  (SQL-layer test with a stale-digest node row — the cfg(test) storage seam is single-node,
  reviewer #10); state never regresses from `published`; **every frozen row carries a
  `storage_set_id` (NOT NULL; freeze without one is a compile-time impossibility)**;
  **catalog with duplicate member ids or a shared endpoint is refused on load; a member
  whose echoed `node_id` ≠ the contacted member id is not counted**. Mutations: count
  members regardless of digest → RED; count an acceptance whose echoed `node_id`
  mismatches → two catalog members on one node reach "quorum" → RED.

### Step 3 — ONE generic recovery sweep

**Files:** `dsm_sdk/src/handlers/storage_routes.rs`, `dsm_sdk/src/init.rs`.

- `republish_unpublished_artifacts() -> Result<u32, String>` (free fn beside
  `deliver_pending_finalization_checkpoints`, `:886`): per artifact
  (`list_unpublished_artifacts(ARTIFACT_REPUBLISH_ROWS_PER_POLL = 8)`) → **resolve the
  row's frozen `storage_set_id` through the catalog (re-hash the entry's member ids,
  require exact equality; no match → the row stays pending with `last_error`, fail closed
  — never substitute another set, never "the configured fleet")** →
  `put_bytes_to_all_members(S, …)` → `record_accepting_member` per accept →
  `count_accepting_members(key,digest) >= quorum_for(|S|)` ⇒
  `published` (same member set as step 5's register — one definition of "the fleet";
  never `clients.len()`, which silently drops unconstructible nodes), else
  `publication_pending` + joined error. Purpose opaque; no per-purpose branching; never
  signs.
- **Placements:** cold boot — `spawn_frozen_artifact_republish("cold-boot"/"warm-swap")` in
  `init.rs` beside `spawn_acceptance_recovery_sweep` (`:608`, `:220`) — **not** gated on the
  wallet seed (payloads are plain bytes; only AppState + auth tokens needed, reviewer #9);
  steady state — appended inside `if push_pending` at `storage_routes.rs:2551`, after
  `deliver_pending_finalization_checkpoints`, OUTSIDE `if pull_inbox`. Keep the DB
  `MutexGuard` out of any `.await` (spawned future must be `Send`).
- **Decision (recommend, flag):** do NOT widen `has_pending_settlement_work`
  (`inbox_poller.rs:129-154`; scoped to money in flight). Safety never depends on
  publication liveness (create is not market-active pre-quorum; close's claim blocks K).
- **RED:** freeze N, fail all puts, restart → sweep replays exact bytes (digest of the PUT
  bytes == frozen digest) **to the frozen row's own S**, state advances only at quorum,
  nothing re-signed; **a frozen row whose S is not in the catalog (or whose catalog entry
  re-hashes differently) stays pending and is never sent to any other set**. Mutations:
  make the sweep rebuild from the current head → PUT digest ≠ frozen digest → RED; make
  the sweep use the configured fleet instead of the frozen S → the unresolvable row gets
  published somewhere → RED.

### Step 4 — vault birth through the primitive (`dlv.create`)

**Files:** `dsm_sdk/src/handlers/dlv_routes.rs` (`dlv_create` `:879-1020`, helpers
`:2132-2306`), `dsm_sdk/src/handlers/route_routes.rs` (`publishRoutingAdvertisement`
`:453-485`, `findAndBindBestPath` `:817-826`), `proto/dsm_app.proto`, frontend.

- `pre_write` builds + signs the seq-0 proof set from `outcome.new_device_state`.
  **Three logical proofs are FIVE durable objects (owner corrections, 2nd + 4th review)** —
  the primitive is keyed by object key, so each key is its own frozen row with its own
  quorum: (1) anchor → **seq-pinned `sofi/vault-state/{v}/seq-{b32(seq)}`** (NEW: today
  the anchor has only a `latest` key, `vault_state_anchor_codec.rs:76-78`; the seq-0
  pinned anchor is the **birth-pinned, canonical-protocol-immutable** reference the lineage
  rule in step 5 needs — not storage-immutable: the object path is overwrite-style, so a
  modified owner client could republish another signed seq-0 anchor; that is an
  equivocating-signer / Byzantine-client case, excluded by the beta model — and it
  makes the anchor consistent with the inclusion-proof key pattern); (2) the same anchor
  bytes → `sofi/vault-state/{v}/latest`; (3) inclusion proof → seq-pinned key; (4) the
  same inclusion-proof bytes → `sofi/vault-state-inclusion/{v}/latest`; (5) reserve proof
  → `sofi/vault-reserve/{v}/{seq}`. `in_tx_extra` freezes all five (purpose `dlv-birth`,
  **`storage_set_id` = the vault's birth S — the same value written into the anchor and
  `amm_vault_records`**) beside the `amm_vault_records` insert; publish after; sweep retries;
  `publication_state == published` iff all five are. The terminal set in step 6 is
  likewise five keys.
  Delete every `log::warn!`-and-continue branch and silent `()` return
  (`:938/:945/:1002/:1009/:1013/:2201-2294`). Freeze the five birth objects for **every**
  AMM vault regardless of `anchor_enforcement` (today `Unspecified` publishes nothing, `:887-892`;
  enforcement is a gate policy, not a publication policy — reviewer #14; flag).
- **funded ≠ published:** `AmmVaultSummaryV1.publication_state` (field 21; 19 = `pending_x`
  post-#673, 20 reserved for `closed`), DERIVED = all five birth keys `is_artifact_published`
  (no second copy in `amm_vault_records`).
  `route.publishRoutingAdvertisement` refuses while pending (right after the
  reserve-encumbrance check, `route_routes.rs:453-485`); `findAndBindBestPath`'s
  no-anchor fall-through (`:817-826`, also on storage `Err`) becomes `continue` (drop) —
  dead legacy once ads are quorum-gated (reviewer #11). LiquidityScreen: "Publication
  pending" badge (`:311-314`), `Publish` suppressed until published, reword the
  `handleCreate` catch string (`:224-230`).
- **Decided (owner):** the reserve-proof key becomes Base32 Crockford seq (matching the
  inclusion-proof key) in this PR — producer (`vault_reserve_proof_codec.rs:29-36`) and
  fetcher move together; the `{seq:016x}` hex key is a repo hard-invariant violation. Beta
  reprovision (v5) covers it. **Decided (owner):** every AMM vault freezes + publishes its
  five birth objects regardless of `anchor_enforcement`.
- **Vault↔storage-set binding lands HERE (owner, third review):** `VaultStateAnchorV1`
  gains `storage_set_id` inside the signed preimage (`vault_state_anchor.rs:77-81`,
  `vault_state_anchor_codec.rs`; strict codec: fixed 32 bytes, required); `dlv_create`
  computes it from the SDK's configured storage-set catalog (beta: the one fleet), writes
  it into the seq-0 anchor (published seq-pinned AND `latest`) AND
  `amm_vault_records.storage_set_id` in the same tx; `compose_vault_state` fetches the
  seq-0 pinned anchor alongside `latest`, requires the same `owner_public_key` on both,
  verifies S against both signatures, requires `latest.S == birth.S`, and exposes
  `ComposedVaultState.storage_set_id`. Step 5's register consumes it; nothing in step 4
  branches on it yet. RED: an anchor with a tampered `storage_set_id` fails signature
  verification; create's record equals the anchor's value; a `latest` anchor whose S
  differs from the seq-0 anchor's S is rejected by composition.
- **RED:** all five birth objects frozen in the same tx as the funding; kill before publish → restart
  replays exact bytes, funds stay encumbered, nothing rolled back/fabricated; not
  advertisable until quorum; after quorum the keys hold exactly the frozen bytes and
  `compose_vault_state` succeeds from them; ad gate refuses pending. Mutation: skip
  freezing any one of the five → create commits with a hole → RED.

### Step 5 — hard quorum first-writer claim for a vault parent (PREREQUISITE, own PR)

**Files:** `dsm_storage_node/src/api/…` (new conditional-accept endpoint + table),
**`dsm_storage_node/src/auth/mod.rs`** (`DeviceContext` gains the authenticated public
key — today it holds only `device_id`, `:24-26`, and the middleware discards the key it
already loaded: `let (_pubkey, token_hash, revoked) = lookup_device(...)`, `:186`; inject
it, no second lookup), `dsm_storage_node` config (`storage_set` membership),
`dsm_sdk/src/sdk/settlement_slot.rs` (replace the listing-based claim),
`dsm_sdk/src/sdk/storage_node_sdk.rs` (canonical member set), `dsm_sdk/src/handlers/dlv_routes.rs`
(trader claim call at `:1937-1941`), `proto/dsm_app.proto` (`SettlementSlotClaimBodyV1`,
`SettlementSlotClaimV1`), storage-node docs, fleet redeploy.

- **What it IS (say so in the docs, don't minimize it — owner):** a **distributed,
  crash-fault-tolerant, one-shot quorum register** keyed `(vault_id, parent_sequence)`
  whose non-equivocation becomes part of DLV's no-double-consumption safety argument. It is
  NOT DSM transaction consensus — nodes never decide whether a settlement or close is
  valid — but for this endpoint the "dumb indexer" description of storage nodes is no
  longer accurate and the storage-node docs / `storage-guide` must say exactly that.

- **Why:** the current `claim_settlement_slot` is a storage *listing* (`settlement_slot.rs:146-197`;
  its own doc: "storage is not a consensus system and this is a read"). Under partition a
  trader and the close can each observe an exclusive slot at K. A trader's `DlvSettle` is
  final on its own chain at its advance; if the owner simultaneously releases the same
  reserves, value is duplicated. The in-process race RED cannot show this; the storage
  node's delete-without-ownership makes it worse.
- **What (owner design):** each storage node performs **write-once conditional
  acceptance** for `(vault_id, parent_sequence)`: the first claim bytes for a key are
  stored and acknowledged; identical bytes re-acknowledged (idempotent); different bytes →
  refused with the held claim. A claimant **wins only when a quorum of the CANONICAL member
  set has accepted the SAME claim bytes.** Because quorums over one canonical set
  intersect and a member holds one value per slot, two conflicting claimants cannot both
  reach quorum. Failure to reach quorum (partition, split acceptances) = NOT claimed for
  everyone — liveness cost, safety kept, matching the module's existing "contention fails
  everyone, deliberately" doctrine.
- **Canonical quorum membership (owner blocker #2 — the largest missing piece):** the
  intersection theorem only holds if every contestant counts over the SAME stable set of
  DISTINCT nodes. `config.node_urls.len()` is not protocol identity, and fleet
  reconfiguration creates the same hole over time. Therefore:
  - **Canonical encoding (owner, third review):** `storage_set_id = BLAKE3(
    "DSM/storage-set/v1\0" ‖ u32_be(count) ‖ for each member in lexicographic byte order:
    u32_be(len(member_id)) ‖ member_id)`. Length-prefixed and counted so variable-length
    ids cannot be re-split (`"ab","c"` vs `"a","bc"`); duplicates refused before hashing.
    Member identities are node ids, **not URLs** (today a node's identity is its configured
    `node.node_id`, `dsm_storage_node/src/main.rs:148-150`; a per-node identity KEY is the
    longer-term form — stated as a beta limitation, acceptable because nodes are
    operator-provisioned).
  - **Vault↔set binding is CRYPTOGRAPHIC and PUBLIC, not a local record (owner, third
    review — the per-vault-set model):** a node checking "claim set == my own set" only
    proves the node's own membership; it does not tie vault V to set S (members D,E
    honestly running set CDE would accept a CDE claim for V). So the vault itself must say
    "I belong to S": **`VaultStateAnchorV1` gains `storage_set_id`, inside the owner's
    signed preimage** (`BLAKE3("DSM/vault-state-anchor\0" ‖ vault_id ‖ seq ‖ reserves_digest
    ‖ storage_set_id)`, `vault_state_anchor.rs:77-81`), present in EVERY generation of the
    anchor incl. the terminal one, and exposed as `ComposedVaultState.storage_set_id`.
    A trader/close therefore learns S from the vault's verified birth identity — never from
    its own config — and targets S's members with `quorum_for(|S|)`. The owner's
    `amm_vault_records.storage_set_id` is a local copy that must equal the anchor's.
  - Each member node knows its own set (config `storage_set.members` → derived id, and
    asserts its own id ∈ set) and **refuses a claim whose `body.storage_set_id` ≠ its own**;
    with the vault binding above, S's members are the only members whose acceptance
    counts for V, so a claim on any other set confers no authority over V.
  - **How S resolves to endpoints (owner, fourth review):** `storage_set_id` is a 32-byte
    digest; a trader cannot derive members from it. Rule: *resolve the signed
    `storage_set_id` against a locally available **storage-set catalog** (SDK config
    `storage_sets: [{members: [{member_id, endpoint}]}]`). A catalog entry is usable only
    if canonical re-encoding + hashing of its distinct member ids reproduces the anchor's
    exact `storage_set_id`; otherwise fail closed (vault unquotable/unclosable on this
    device — never fall back to "my fleet").* For beta the catalog holds exactly the one
    immutable configured fleet. **The anchor chooses the set; configuration only resolves
    that authenticated identifier into endpoints.** `StorageSet { id, members }` is the
    type both the register and the publication primitive take.
  - **Lineage immutability (owner, fourth review — load-bearing):** `storage_set_id` is
    **birth-fixed** for vault V. Every generation K+1 derives S from the verified birth
    state — the seq-0 pinned anchor (step 4's object #1) — and **callers never supply S**:
    the owner's close takes S from its own verified composition (`composed.storage_set_id`,
    birth-bound), cross-checks it against `amm_vault_records` (a cache, fail closed on
    mismatch), and stamps that exact S into the terminal K+1 anchor; `compose_vault_state` fetches the seq-0
    anchor as well as `latest`, requires the same `owner_public_key` on both, and
    **rejects any generation whose S differs from the birth-bound S** (a validly signed
    later anchor with a different S is not caught by its own signature — only by lineage).
    The pinned birth anchor is canonical-protocol-immutable, not storage-immutable (the
    object path is overwrite-style; a modified owner client republishing a different
    signed seq-0 anchor is an equivocating-signer case outside the beta client model — a
    genuinely write-once storage key for it is a later hardening). This turns "V belongs
    to S" into a lineage property, not a per-snapshot field.
  - **Beta rule: the three-node claim set is immutable for the lifetime of every vault born
    under it.** Membership change requires an explicit handover protocol that preserves
    outstanding write-once registers AND the vault↔set binding — out of scope, named as
    the follow-up.
  - Publication quorum (steps 2–3) uses the same canonical set for one definition of "the
    fleet", but only the claim register's safety depends on it (publication quorum is
    delivery, not authority).
  - **The theorem, as stated for the docs:** one vault parent K → one canonical set S bound
    in the vault's signed birth anchor and immutable across the lineage → intersecting
    quorums within S → each member durably writes one value → at most one claimant can
    acquire the right to consume K.
  - **Client model — stated, not implied (owner, fourth review; DECISION, flag):** the
    register is a **route-layer prerequisite**: trader and close call
    `claim_settlement_slot` and then the canonical transition proceeds; nodes do not judge
    transition validity. That proves exclusivity for **protocol-conforming clients**. It
    does NOT prove exclusivity against a modified authenticated client that skips the
    claim and constructs an otherwise-valid `DlvSettle` at K on its own chain — such a
    client can still double-consume against an honest close or trader (the same shape the
    listing model has today). **Beta boundary chosen: protocol-conforming-client safety.**
    Stated in the theorem: *authenticated devices may contend and may grief, but execute
    the canonical client path and cannot bypass the claim prerequisite.* **Byzantine-client
    safety** — verifiable evidence of having won S's register (e.g. the member acceptances
    over the frozen claim envelope) becoming an INPUT to settlement/close validity (carried
    in the receipt, checked at the LP's fold and by any downstream verifier of the trader's
    chain), not merely SDK control flow — is the named follow-up and the one boundary that
    could materially change this design. Recorded so the theorem never sounds stronger
    than the implementation.
- **Per-node atomicity is the load-bearing property (owner correction #1):** the
  storage-node operation is **ONE atomic SQLite write transaction** over the unique key —
  e.g. `INSERT … ON CONFLICT (vault_id, parent_sequence) DO NOTHING` then read the held row
  in the same tx, or `INSERT … RETURNING`: first bytes win, identical bytes re-ack,
  different bytes refuse. The safety property is transaction atomicity + the unique key,
  not the statement count — never a check outside the write tx. Storage-node tests:
  **concurrent requests** (N tasks racing the same slot with different bytes → exactly one
  accepted, all others refused with the held digest) and **restart persistence** (node
  accepts A, process restarts, B is still refused, A re-acks). Without these the 2-of-3
  argument rests on an unproven local race.
- **Threat-model paragraph (goes in `settlement_slot.rs` module doc AND the storage-node
  endpoint doc, verbatim in spirit):** *the quorum safety argument assumes member nodes are
  durably non-equivocating for a slot — a member cannot acknowledge two different values
  for the same `(vault_id, parent_sequence)`, and that fact survives process restart AND
  storage lifecycle: **restoring a member's database from a snapshot that predates a held
  claim, replacing a member without preserving its register, or any rollback of the
  register is a SAFETY violation, not an availability event** (A wins on members 1+2, their
  DBs are restored from before A, B later wins the same K — the theorem silently
  disappears). This is not DSM consensus and it does not determine transaction validity;
  quorum intersection over the canonical member set only serializes mutually-unknown
  claimants under these assumptions.* Operational invariants that follow (owner #3): the
  register table is written with `PRAGMA synchronous=FULL` (durable before ack); the
  fleet recipe **never restores a node DB from snapshot** — a member that loses its
  register is retired and the set handed over (follow-up protocol), never re-seated empty;
  recorded in the fleet-redeploy memory.
- **Non-circular signature (owner blocker #1):** the claim is a signed envelope over an
  unsigned canonical body — you cannot sign bytes that contain the signature:
  `SettlementSlotClaimBodyV1 { vault_id, parent_sequence, x, claimant_public_key,
  storage_set_id }` (canonical encoding, required fields, no unknown/duplicate fields,
  decode→re-encode equality); `signature = SPHINCS+_sign(sk,
  BLAKE3("DSM/settlement-slot-claim/v1\0" ‖ canonical_body_bytes))`; envelope
  `SettlementSlotClaimV1 { body, signature }`, canonically encoded — **those envelope bytes
  are what is frozen, PUT, compared byte-for-byte by nodes, and replayed byte-identically.**
  Nodes decode the envelope, re-encode the body, verify the signature under
  `body.claimant_public_key`, and refuse on any mismatch.
- **Explicit boundary:** storage provides *concurrency serialization* for mutually-unknown
  actors consuming one public parent — NOT validity. The canonical DSM transition still
  decides whether the settlement/close is valid.
- **Claim signature semantics — attribution, not theater (owner):** the node **verifies
  claimant attribution, not settlement validity**: `body.claimant_public_key` must equal
  the authenticated storage caller's public key — injected into `DeviceContext` by the
  auth middleware from the row it already loads (`auth/mod.rs:186`; no redundant lookup)
  — and `signature` must verify over the body preimage under that key, so an authenticated
  caller cannot claim as somebody else. The node still never judges whether the
  settlement/close is valid.
- **Canonical, frozen claim bytes for BOTH contestants (owner):** the envelope gets the
  strict signed-protocol-object treatment used elsewhere; the client encodes the body ONCE,
  signs, encodes the envelope ONCE, and **retains those exact envelope bytes** — retries
  and recovery replay them verbatim (a semantically-equal re-encode that differs by a byte
  reads as a *different* claimant at the node). Trader path (`dlv_unlock_routed`) retains
  its claim bytes for the duration of the settle + any retry; close retains them in
  `dlv_close_intent`.
- **Client:** `claim_settlement_slot(vault, parent_sequence, frozen_claim_bytes) ->
  Result<SettlementSlotClaim, SlotClaimError>` keeps its semantics (parent-indexed) but is
  now: PUT-claim to every member of the vault's canonical set → count acceptances of OUR
  bytes → `Ok` iff ≥ `quorum_for(|set|)`; `Contested` if any member holds a different
  value AND we cannot reach quorum; `StorageUnavailable` if we cannot reach quorum for
  transport reasons. **The listing-based implementation is deleted**, not kept beside.
  Pending pointers remain composition discovery only.
- **Both contestants use it:** the trader path (`dlv_unlock_routed`, `:1937-1941`) and
  step 6's close call the same function with the same key. Hardening one contestant is
  no protection.
- **Storage node:** new table `settlement_slot_claims(vault_id, parent_sequence, claim_bytes,
  claim_digest, claimant_public_key, storage_set_id, PK(vault_id, parent_sequence))`
  (`synchronous=FULL`) + endpoint on the device-auth router (same auth as object writes;
  verifies set id + attribution as above; **no delete, no overwrite path at all**).
  Deployed to the 3-node fleet with the checksum-verified-tar recipe (never
  `--skip-build`), canary node first; the register is born empty ONCE and never restored.
- **Griefing — named for what it is (owner #4):** because nodes verify attribution, not
  validity, ANY authenticated device can submit a well-formed claim for a known
  `(vault_id, K)`, win 2/3, and never settle — a cheap authenticated request becomes
  **permanent AMM denial-of-service** for that vault (K is wedged; and unlike today, no
  delete exists). **Explicitly accepted for the controlled beta fleet** (operator-provisioned
  devices). **For a public market this is a LAUNCH BLOCKER, not a follow-up liveness
  note.** A safe expiry/reclamation rule in a clockless system is hard (canonical
  progression-based expiry, or claimant-bonded claims, are the candidate shapes) and must
  be solved before public exposure. Close mitigates its own orphan case with durable
  pre-claim intent (step 6).
- **RED (SDK against an N-node in-process store; storage-node tests for the register):**
  storage node — concurrent racers on one slot → exactly one accepted, others refused with
  the held digest; **restart persistence** (accept A, restart, B refused, A re-acks); a
  claim whose `claimant_public_key` ≠ the authenticated caller, or whose signature fails,
  is refused; **a claim whose `storage_set_id` ≠ the node's own set is refused**; the
  signature verifies over the BODY preimage only (flip one body byte → refused; the
  envelope's own bytes are not in the preimage — asserted by construction test);
  `storage_set_id` encoding: `["ab","c"]` ≠ `["a","bc"]`, order-independent, duplicate
  refused; SDK — two claimants, 3 members: at most one reaches quorum; partition split (m1
  accepts A, m2 accepts B, m3 accepts A) → A wins 2/3, B refused; **vault↔set binding:**
  the trader/close derive S from `ComposedVaultState.storage_set_id` (the vault's signed
  anchor), NOT from local config — a contestant whose local config names a different set
  cannot produce a claim S's members accept, and its acceptances elsewhere confer nothing
  over V (assert: S-members hold exactly one claim for K; the foreign-set contestant's
  claim is absent from every S member); retry replays the SAME frozen envelope bytes and
  re-acks (a re-encoded byte-different claim would be refused as foreign — asserted);
  storage error → not claimed; **lineage immutability: birth S1 → an otherwise-valid,
  correctly signed generation-K anchor carrying S2 → `compose_vault_state` rejects it
  (and close cannot stamp S2: it never takes S as input)**; **catalog resolution: an
  anchor whose S matches no catalog entry (or a catalog entry whose members re-hash to a
  different id) → fail closed, never "my fleet"**; the trader-vs-close race for K (moved
  here from step 6) → exactly one wins. Mutations: let a node overwrite → both reach
  quorum → RED; compose skips the birth-anchor S comparison → the S2 generation composes
  → RED; make the
  node's accept a two-statement check-then-insert and race it → RED; count non-identical
  acceptances → RED; skip attribution verification → a caller claims under another key →
  RED; derive S from local config instead of the vault anchor → the binding test's
  foreign-set contestant "wins" → RED.

### Step 6 — `dlv.close`: canonical close + terminal set, crash-safe (gated on step 5)

**Files:** `dsm/src/types/operations.rs` (`DlvClose`, tag 28; every exhaustive match:
`sign_operation_sphincs` `core_sdk.rs:372-387`, `relationship.rs:290`,
`parameter_comparison.rs:589`, `with_cleared_signature/with_signature/get_signature`,
egress class, the `advance` signature gate `device_state.rs:1199-1209`),
`device_state.rs` (`Withdraw` arm), `dlv_routes.rs` (`dlv_close`), new
`client_db/dlv_close_intent.rs`, `proto` (`DlvCloseV1 { vault_id }`,
`AmmVaultSummaryV1.closed = 20`), frontend (`Withdraw`, `amm.ts closeVault`).

- **Canonical operation shape (owner, seventh review — the signed op must bind the whole
  transition):** the app request is `DlvCloseV1 { vault_id }` ONLY. The handler derives
  the close from the verified local frontier (sub-steps 1–2 below) and constructs + signs
  **`Operation::DlvClose { vault_id, legs: [(policy_commit, amount); 2], parent_sequence,
  new_sequence, pair: VaultStatePair, signature }`** (wire tag 28); callers never supply
  any derived field. `pair` IS inside the signed operation (derive-don't-accept: derived
  by the handler from `composed`/the birth-bound record, then signed), so the signature
  binds vault, legs, generation AND the pair/fee that determine the terminal digest —
  unsigned mutation metadata never decides what moves. Core requires
  **`Withdraw == op` field-for-field** (`vault_id`, `legs`, `parent_sequence`,
  `new_sequence`, `pair`); any mismatch is refused before the SMT batch. `pair` is
  carried on the mutation only so `advance` can derive the vault-state digest, and it is
  validated against the op, never trusted from the mutation alone.
- **Core arm `Withdraw { vault_id, legs, parent_sequence, new_sequence, pair }`** mirroring
  `ApplySettlement`: only `DlvClose`; **mutation legs == op legs** (ApplySettlement never
  cross-checked op vs mutation — don't repeat that); legs == exactly `[pair.a, pair.b]`,
  lex-ascending, no dupes; every leaf EXISTS (never `unwrap_or_default`) at exactly
  `parent_sequence`; `new_sequence == parent+1`; `leaf.amount == leg.amount` both;
  **refuse if both leaves already zero**; `checked_add` into `new_balances`; leaves kept
  at `0 @ N+1`; vault-state leaf derives `digest(a,b,0,0,fee)` at N+1 in the batch.
  Consequence to state: `Fund` refuses a closed vault forever (`:1333-1338`) — a vault id is
  single-use.
- **`x_close` deterministic (reviewer #3):** `H("DSM/dlv-close-x\0" ‖ vault_id ‖ K ‖
  owner_devid)`, so retries are byte-idempotent. Close commitment for the consume-once row:
  `H("DSM/dlv-close-commit\0" ‖ vault_id ‖ K)`.
- **Route `dlv_close`, in order:**
  1. decode; head present; `amm_vault_records` + rehydrate legs → owner `(K, ra, rb)`.
  2. **Frontier gate:** `fetch_latest_signed_anchor` (`Ok(None)`/`Err` → refuse) →
     `compose_vault_state` (any `Err` → refuse) → require `composed.sequence == K` **AND**
     `digest(a,b,composed.ra,composed.rb,fee) == digest(a,b,ra,rb,fee)` **AND
     `amm_vault_records.storage_set_id == composed.storage_set_id`** (owner, sixth review:
     the composed / birth-bound value is the authority; the record is a cache — a stale
     or corrupted record must never let the close claim or freeze against a different set;
     mismatch → refuse). Do NOT gate on `blocked_by_unreceipted_pointer_at_parent` (our
     own prior pointer would refuse the owner forever); contention is decided by the
     Step-5 register in sub-step 4 below.
  3. **Durable pre-claim intent BEFORE any publish:** `dlv_close_intent(vault_id,
     parent_sequence, state CHECK IN ('prepared_close','claim_published',
     'canonical_close_committed','abandoned'), op_bytes (signed DlvClose), x_close,
     claim_bytes (the frozen canonical `SettlementSlotClaimV1`), pointer_key, pointer_bytes,
     insertion_ordinal INTEGER (local monotonic; no clock column),
     PK(vault_id,parent_sequence))` — the one DLV-specific row; it holds *intent + the exact
     bytes it will publish/claim/advance*, never authority. **Pointer and claim bytes live
     ONLY here** (reviewer #4: neither is bound to a canonical advance, and a
     purpose-agnostic sweep would republish an abandoned one forever). Terminal `published`
     is DERIVED from the five terminal artifacts, not a state here.
  4. **Claim parent K with the hardened register (step 5):** publish the discovery pointer
     (`VaultPendingPointerV1` signed by the owner, `expected_receipt_hash` = close
     commitment) at `sofi/vault-pending/{v}/{K+1}/{x_close}` — composition discovery only —
     then `claim_settlement_slot(vault, K, frozen_envelope_bytes)` (**parent-indexed**;
     the same one-shot quorum register the trader path uses at `dlv_routes.rs:1937-1941`,
     over `composed.storage_set_id` — the birth-bound S verified in sub-step 2, never the
     local record alone).
     `Ok` (quorum accepted OUR bytes) → intent → `claim_published`; `Contested` →
     **abandon** (mark `abandoned` + best-effort delete of our discovery pointer);
     `StorageUnavailable`/no quorum → refuse now, retry later (intent stays
     `prepared_close`). Only a quorum-won claim may proceed to release reserves.
  5. **Canonical close** via the step-1 wrapper: `pre_write` builds + signs the terminal
     proof set from `outcome.new_device_state`; `in_tx_extra`: consume-once row for K
     (`cas_consume_vault_generation_with_conn`, source = close commitment), freeze the
     **five** terminal objects (anchor seq-pinned + `/latest`, inclusion seq-pinned + `/latest`,
     reserve proof; purpose `dlv-terminal`; **frozen with `storage_set_id` =
     `composed.storage_set_id` (the birth-bound S verified in sub-step 2 and confirmed
     equal to the record), never a caller value and never the record alone**; the `latest`
     keys supersede birth's rows),
     intent → `canonical_close_committed`. **Value is spendable at this commit; durable, replayable
     terminal evidence exists locally at that instant.** If the advance is refused (owner
     reconciled at K meanwhile → parent mismatch / CAS `Conflict`) → abandon (reviewer #2).
  6. Best-effort publish of the frozen bytes; the generic sweep owns retry.
- **Recovery (own resume in the same cold-boot/sync sites; gated on wallet unlock because
  it signs — reviewer #9):** `prepared_close`/`claim_published` → **first re-establish the
  S invariant** (owner, seventh review): re-compose the vault and require the three-way
  equality **`claim.body.storage_set_id == composed.storage_set_id ==
  amm_vault_records.storage_set_id`** before anything else — the frozen claim bytes
  preserve the originally selected S, and this proves durable intent still agrees with
  the birth-bound lineage after restart; mismatch → abandon (fail closed, no external
  effect). Then **re-run the hardened claim with the same frozen claim bytes**
  (idempotent at nodes that already hold them): `Ok` (quorum) → 5→6; `Contested` →
  abandon; no quorum → wait. `canonical_close_committed` → nothing (artifact sweep
  finishes). Never infer closure from the pointer or the claim; the canonical state
  decides.
- **Terminal market state (verified, reviewer #12):** the owner's pointer at K sets the
  blocked flag until the K+1 baseline lands; after it, compose starts at K+1 and skips the
  pointer; settle at K+1 → `constant_product_output` None → `InsufficientReservesOrOverflow`;
  hop ≤ K → "already consumed". `unapplied_settlements_for_vault` skips receiptless pointers,
  so `x_close` never shows as a phantom pending trade (Withdraw button not self-disabled).
  Best-effort ad retract on close (`lifecycle_state`) is UI hygiene, optional.
- **Observability:** `AmmVaultSummaryV1.closed = 20` derived from leaves at 0;
  LiquidityScreen `Withdraw` (confirm modal; disabled while `pendingUnapplied > 0` — hint).
- **RED (core):** full-drain conserves exactly once (leaves `0@N+1`); one-leg / extra-leg /
  unordered / duplicate / op≠mutation legs refused; amount≠leaf refused; already-zero
  refused; stale generation refused; second close refused (N and N+1); close after a
  settlement withdraws post-trade reserves; unsigned/wrong-op/non-empty-deltas refused;
  preservation of unowned fields; persistence round-trip;
  **`a_closed_vault_id_is_single_use_by_lineage`** (owner): after close leaves both legs at
  `0@N+1`, a `Fund` for the same vault id is refused because the reserve *leaves exist*
  (`device_state.rs:1333-1338`, existence-based) — NOT because an amount is non-zero;
  mutation: make the refusal amount-based → a zero-leaf vault becomes re-fundable → RED.
  **RED (route):** owner closes a reconciled vault → **the correct oracle is post-trade,
  not funding-time (owner #6):** `post_close_wallet[a] == pre_close_wallet[a] +
  reserve_a@K` and `post_close_wallet[b] == pre_close_wallet[b] + reserve_b@K`, with both
  vault leaves at `0@K+1`, exactly once ("back to funding-time" is only true when no trade
  changed the composition — never encode that as the assertion); terminal proofs
  verifiable at K+1, second close refused, subsequent trader quote finds zero reserves /
  settle refused; **close before reconciling unfolded receipts refused**
  (LP-offline test at "THE LP RETURNS"); **compose behind the owner (K−1) refused**;
  **same sequence + wrong digest refused**; **`amm_vault_records.storage_set_id` ≠
  `composed.storage_set_id` (stale/corrupted local record) → close refused before any
  claim or freeze; mutation: take S from the record → the close claims against S2 → RED**;
  **recovery three-way S check:** an intent whose frozen `claim.body.storage_set_id`
  disagrees with the re-composed birth-bound S (or with the record) is abandoned on
  resume before any claim/terminal construction; mutation: skip the recovery check → a
  resumed intent proceeds against a mismatched set → RED; **`Withdraw ≠ op` on any of
  `vault_id`/`legs`/`parent_sequence`/`new_sequence`/`pair` → refused before the SMT
  batch** (mutation: drop the `pair` comparison → a mutation with a different fee_bps
  yields a terminal digest the signed op never authorized → RED); **race:** trader-vs-close for K → exactly one
  wins — driven through the step-5 quorum register on an N-node store (the in-process
  single-store version proves nothing about partition and is not the evidence);
  **recovery `Contested` → abandon, holdings still encumbered, pointer removed**; **kill after canonical close before quorum**
  → restart replays exact bytes, no second credit, never quotable again; **kill after claim
  before canonical close** → restart re-claims and completes (or abandons); **partial
  terminal publication** (anchor@K+1 landed, others not) → compose fails closed, K stays
  blocked; **reconcile after close** (receipt at K → consume-once `Conflict`; at K+1 → arm
  refuses); **`latest` supersession** — birth-then-close on `sofi/vault-state/{v}/latest`
  supersedes, sweep never replays superseded bytes.
  Mutations: drop the digest half of the frontier gate → RED; pass K+1 to the claim → race
  lets both win → RED; drop pair-completeness → one-leg close strands the other asset → RED.

## Out of scope (explicit)

Trader pointer/receipt durability (separate seam); claim-register **griefing / orphan
expiry** (accepted for the controlled beta; **public-market launch blocker** — see step 5);
**storage-set membership change / handover protocol** that preserves outstanding
write-once registers (beta: the set is immutable for the lifetime of vaults born under it);
per-node identity KEYS in place of configured node ids; the storage node's
object-delete-without-ownership (`sqlite.rs:1297-1315`, pre-existing; the step-5 register
has no delete); widening `has_pending_settlement_work`; any change to bilateral
outbox/finality code.

## Verification

- Core: `cargo test -p dsm --lib types::device_state`;
  `cargo test -p dsm_sdk --test dlv_owner_apply_preservation --test dlv_value_op_signing`.
- SDK: `cargo test -p dsm_sdk --lib 'handlers::dlv_routes' -- --test-threads=1`,
  `'storage::client_db::frozen_publication_artifact'`, `'sdk::settlement_slot'` (N-node
  in-process store for the quorum register), `'vault_state_composition'`, `'route_routes'`,
  `'vault_rehydration'`.
- Storage node (step 5): `cargo test -p dsm_storage_node --no-default-features --features
  local-dev,strict` for the write-once register; fleet redeploy per the recorded recipe
  (checksum-verified tar per node, canary node 1 first) before any hardware run.
- Every guard mutation-tested red then restored (per layer), as in #670/#672.
- Real gates: `make lint` (fmt + `clippy --all-targets -D warnings` + npm lint), proto
  guards + `codegen_enforce.sh` (regenerate TS), `ci/no_clock_and_no_json.sh`,
  `ci/production_safety_checks.sh` (prod clippy + TLA+), root `cargo audit`.
- Frontend: jest on `LiquidityScreen`, `amm`.
- Hardware (after merge, own run, v5 reprovision + fleet redeploy for the register): LP
  create → the **five** birth keys hold the frozen bytes on ≥2/3 members and
  `publication_state=published` before the ad publish; market run as #675 (traders now
  claim through the quorum register); LP `Withdraw` → the LP wallet increases by exactly
  `reserve_a@K` and `reserve_b@K` (the post-trade leaves, decoded from the pulled head —
  not "back to funding-time"), both leaves `0@K+1`, the **five** terminal objects on the
  fleet, a trader quote finds no liquidity; kill LP
  between close-commit and quorum → relaunch → sweep completes byte-identically. Extend
  `scripts/dlv_market_rig_proof.sh` with the register invariant stated correctly (owner,
  fifth review — the allowed partition race legitimately leaves a losing value write-once
  on a minority member, e.g. m1=A, m2=B, m3=A): **for every consumed `(vault, K)`, exactly
  one claim digest has quorum in S, and no conflicting digest has quorum; minority
  conflicting rows are legal and permanent — never assert "identical bytes on every
  member"**, and never let a proof script motivate overwriting minority claims to go
  green. Additionally prove the quorum-winning envelope is the claimant that actually
  proceeded to consumption (its `x` == the settled/closed generation's `x`); every held
  claim carries the vault's birth `storage_set_id`; a claim submitted from a device whose
  catalog names a foreign set is refused by all three members.
